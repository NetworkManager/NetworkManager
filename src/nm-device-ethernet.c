/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include <glib.h>
#include <glib/gi18n.h>
#include <netinet/in.h>
#include <string.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <linux/types.h>
#include <linux/sockios.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if.h>
#include <errno.h>

#define G_UDEV_API_IS_SUBJECT_TO_CHANGE
#include <gudev/gudev.h>

#include <netlink/route/addr.h>

#include "nm-glib-compat.h"
#include "nm-device-ethernet.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-activation-request.h"
#include "NetworkManagerUtils.h"
#include "nm-supplicant-manager.h"
#include "nm-supplicant-interface.h"
#include "nm-supplicant-config.h"
#include "nm-netlink-monitor.h"
#include "nm-system.h"
#include "nm-setting-connection.h"
#include "nm-setting-wired.h"
#include "nm-setting-8021x.h"
#include "nm-setting-pppoe.h"
#include "ppp-manager/nm-ppp-manager.h"
#include "nm-logging.h"
#include "nm-properties-changed-signal.h"
#include "nm-dhcp-manager.h"

#include "nm-device-ethernet-glue.h"


G_DEFINE_TYPE (NMDeviceEthernet, nm_device_ethernet, NM_TYPE_DEVICE)

#define NM_DEVICE_ETHERNET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetPrivate))

#define WIRED_SECRETS_TRIES "wired-secrets-tries"

typedef enum
{
	NM_ETHERNET_ERROR_CONNECTION_NOT_WIRED = 0,
	NM_ETHERNET_ERROR_CONNECTION_INVALID,
	NM_ETHERNET_ERROR_CONNECTION_INCOMPATIBLE,
} NMEthernetError;

#define NM_ETHERNET_ERROR (nm_ethernet_error_quark ())
#define NM_TYPE_ETHERNET_ERROR (nm_ethernet_error_get_type ()) 

typedef struct SupplicantStateTask {
	NMDeviceEthernet *self;
	guint32 new_state;
	guint32 old_state;
	gboolean mgr_task;
	guint source_id;
} SupplicantStateTask;

typedef struct Supplicant {
	NMSupplicantManager *mgr;
	NMSupplicantInterface *iface;

	/* signal handler ids */
	guint mgr_state_id;
	guint iface_error_id;
	guint iface_state_id;
	guint iface_con_state_id;

	/* Timeouts and idles */
	guint iface_con_error_cb_id;
	guint con_timeout_id;

	GSList *iface_tasks;
	GSList *mgr_tasks;
} Supplicant;

typedef struct {
	gboolean            disposed;

	guint8              hw_addr[ETH_ALEN];      /* Currently set MAC address */
	guint8              perm_hw_addr[ETH_ALEN]; /* Currently set MAC address */
	gboolean            carrier;

	NMNetlinkMonitor *  monitor;
	gulong              link_connected_id;
	gulong              link_disconnected_id;
	guint               carrier_action_defer_id;

	Supplicant          supplicant;
	guint               supplicant_timeout_id;

	/* s390 */
	char *              subchan1;
	char *              subchan2;
	char *              subchan3;
	char *              subchannels; /* Composite used for checking unmanaged specs */

	/* PPPoE */
	NMPPPManager *ppp_manager;
	NMIP4Config  *pending_ip4_config;
} NMDeviceEthernetPrivate;

enum {
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_PERM_HW_ADDRESS,
	PROP_SPEED,
	PROP_CARRIER,

	LAST_PROP
};


static gboolean supports_mii_carrier_detect (NMDeviceEthernet *dev);
static gboolean supports_ethtool_carrier_detect (NMDeviceEthernet *dev);

static GQuark
nm_ethernet_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-ethernet-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_ethernet_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Connection was not a wired connection. */
			ENUM_ENTRY (NM_ETHERNET_ERROR_CONNECTION_NOT_WIRED, "ConnectionNotWired"),
			/* Connection was not a valid wired connection. */
			ENUM_ENTRY (NM_ETHERNET_ERROR_CONNECTION_INVALID, "ConnectionInvalid"),
			/* Connection does not apply to this device. */
			ENUM_ENTRY (NM_ETHERNET_ERROR_CONNECTION_INCOMPATIBLE, "ConnectionIncompatible"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMEthernetError", values);
	}
	return etype;
}

static void
carrier_action_defer_clear (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	if (priv->carrier_action_defer_id) {
		g_source_remove (priv->carrier_action_defer_id);
		priv->carrier_action_defer_id = 0;
	}
}

static gboolean
carrier_action_defer_cb (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMDeviceState state;

	priv->carrier_action_defer_id = 0;

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (self));
	if (state == NM_DEVICE_STATE_UNAVAILABLE) {
		if (priv->carrier)
			nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_CARRIER);
	} else if (state >= NM_DEVICE_STATE_DISCONNECTED) {
		if (!priv->carrier)
			nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_UNAVAILABLE, NM_DEVICE_STATE_REASON_CARRIER);
	}

	return FALSE;
}

static void
set_carrier (NMDeviceEthernet *self,
             const gboolean carrier,
             const gboolean defer_action)
{
	NMDeviceEthernetPrivate *priv;
	NMDeviceState state;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	if (priv->carrier == carrier)
		return;

	/* Clear any previous deferred action */
	carrier_action_defer_clear (self);

	priv->carrier = carrier;
	g_object_notify (G_OBJECT (self), NM_DEVICE_ETHERNET_CARRIER);

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (self));
	nm_log_info (LOGD_HW | LOGD_ETHER, "(%s): carrier now %s (device state %d%s)",
	             nm_device_get_iface (NM_DEVICE (self)),
	             carrier ? "ON" : "OFF",
	             state,
	             defer_action ? ", deferring action for 4 seconds" : "");

	if (defer_action)
		priv->carrier_action_defer_id = g_timeout_add_seconds (4, carrier_action_defer_cb, self);
	else
		carrier_action_defer_cb (self);
}

static void
carrier_on (NMNetlinkMonitor *monitor,
            int idx,
            gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	guint32 caps;

	/* Make sure signal is for us */
	if (idx == nm_device_get_ifindex (device)) {
		/* Ignore spurious netlink messages */
		caps = nm_device_get_capabilities (device);
		if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT))
			return;

		set_carrier (self, TRUE, FALSE);
	}
}

static void
carrier_off (NMNetlinkMonitor *monitor,
             int idx,
             gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	guint32 caps;

	/* Make sure signal is for us */
	if (idx == nm_device_get_ifindex (device)) {
		NMDeviceState state;
		gboolean defer = FALSE;

		/* Ignore spurious netlink messages */
		caps = nm_device_get_capabilities (device);
		if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT))
			return;

		/* Defer carrier-off event actions while connected by a few seconds
		 * so that tripping over a cable, power-cycling a switch, or breaking
		 * off the RJ45 locking tab isn't so catastrophic.
		 */
		state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (self));
		if (state > NM_DEVICE_STATE_DISCONNECTED)
			defer = TRUE;

		set_carrier (self, FALSE, defer);
	}
}

static void
_update_s390_subchannels (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	const char *iface;
	GUdevClient *client;
	GUdevDevice *dev;
	GUdevDevice *parent;
	const char *parent_path, *item, *driver;
	const char *subsystems[] = { "net", NULL };
	GDir *dir;
	GError *error = NULL;

	iface = nm_device_get_iface (NM_DEVICE (self));

	client = g_udev_client_new (subsystems);
	if (!client) {
		nm_log_warn (LOGD_DEVICE | LOGD_HW, "(%s): failed to initialize GUdev client", iface);
		return;
	}

	dev = g_udev_client_query_by_subsystem_and_name (client, "net", iface);
	if (!dev) {
		nm_log_warn (LOGD_DEVICE | LOGD_HW, "(%s): failed to find device with udev", iface);
		goto out;
	}

	/* Try for the "ccwgroup" parent */
	parent = g_udev_device_get_parent_with_subsystem (dev, "ccwgroup", NULL);
	if (!parent) {
		/* FIXME: whatever 'lcs' devices' subsystem is here... */
		if (!parent) {
			/* Not an s390 device */
			goto out;
		}
	}

	parent_path = g_udev_device_get_sysfs_path (parent);
	dir = g_dir_open (parent_path, 0, &error);
	if (!dir) {
		nm_log_warn (LOGD_DEVICE | LOGD_HW, "(%s): failed to open directory '%s': %s",
		             iface, parent_path,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		goto out;
	}

	/* FIXME: we probably care about ordering here to ensure that we map
	 * cdev0 -> subchan1, cdev1 -> subchan2, etc.
	 */
	while ((item = g_dir_read_name (dir))) {
		char buf[50];
		char *cdev_path;

		if (strncmp (item, "cdev", 4))
			continue;  /* Not a subchannel link */

		cdev_path = g_strdup_printf ("%s/%s", parent_path, item);

		memset (buf, 0, sizeof (buf));
		errno = 0;
		if (readlink (cdev_path, &buf[0], sizeof (buf) - 1) >= 0) {
			if (!priv->subchan1)
				priv->subchan1 = g_path_get_basename (buf);
			else if (!priv->subchan2)
				priv->subchan2 = g_path_get_basename (buf);
			else if (!priv->subchan3)
				priv->subchan3 = g_path_get_basename (buf);
		} else {
			nm_log_warn (LOGD_DEVICE | LOGD_HW,
			             "(%s): failed to read cdev link '%s': %s",
			             iface, cdev_path, errno);
		}
		g_free (cdev_path);
	};

	g_dir_close (dir);

	if (priv->subchan3) {
		priv->subchannels = g_strdup_printf ("%s,%s,%s",
		                                     priv->subchan1,
		                                     priv->subchan2,
		                                     priv->subchan3);
	} else if (priv->subchan2) {
		priv->subchannels = g_strdup_printf ("%s,%s",
		                                     priv->subchan1,
		                                     priv->subchan2);
	} else
		priv->subchannels = g_strdup (priv->subchan1);

	driver = nm_device_get_driver (NM_DEVICE (self));
	nm_log_info (LOGD_DEVICE | LOGD_HW,
	             "(%s): found s390 '%s' subchannels [%s]",
	             iface, driver ? driver : "(unknown driver)", priv->subchannels);

out:
	if (parent)
		g_object_unref (parent);
	if (dev)
		g_object_unref (dev);
	g_object_unref (client);
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDeviceEthernetPrivate *priv;
	NMDevice *self;
	guint32 caps;

	object = G_OBJECT_CLASS (nm_device_ethernet_parent_class)->constructor (type,
	                                                                        n_construct_params,
	                                                                        construct_params);
	if (!object)
		return NULL;

	self = NM_DEVICE (object);
	priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	nm_log_dbg (LOGD_HW | LOGD_OLPC_MESH, "(%s): kernel ifindex %d",
	            nm_device_get_iface (NM_DEVICE (self)),
	            nm_device_get_ifindex (NM_DEVICE (self)));

	/* s390 stuff */
	_update_s390_subchannels (NM_DEVICE_ETHERNET (self));

	caps = nm_device_get_capabilities (self);
	if (caps & NM_DEVICE_CAP_CARRIER_DETECT) {
		GError *error = NULL;
		guint32 ifflags = 0;

		/* Only listen to netlink for cards that support carrier detect */
		priv->monitor = nm_netlink_monitor_get ();

		priv->link_connected_id = g_signal_connect (priv->monitor, "carrier-on",
		                                            G_CALLBACK (carrier_on),
		                                            self);
		priv->link_disconnected_id = g_signal_connect (priv->monitor, "carrier-off",
		                                               G_CALLBACK (carrier_off),
		                                               self);

		/* Get initial link state */
		if (!nm_netlink_monitor_get_flags_sync (priv->monitor,
		                                        nm_device_get_ifindex (NM_DEVICE (self)),
		                                        &ifflags,
		                                        &error)) {
			nm_log_warn (LOGD_HW | LOGD_ETHER,
			             "(%s): couldn't get initial carrier state: (%d) %s",
			             nm_device_get_iface (NM_DEVICE (self)),
			             error ? error->code : -1,
			             (error && error->message) ? error->message : "unknown");
			g_clear_error (&error);
		} else
			priv->carrier = !!(ifflags & IFF_LOWER_UP);

		nm_log_info (LOGD_HW | LOGD_ETHER,
		             "(%s): carrier is %s",
		             nm_device_get_iface (NM_DEVICE (self)),
		             priv->carrier ? "ON" : "OFF");

		/* Request link state again just in case an error occurred getting the
		 * initial link state.
		 */
		if (!nm_netlink_monitor_request_status (priv->monitor, &error)) {
			nm_log_warn (LOGD_HW | LOGD_ETHER,
			             "(%s): couldn't request carrier state: (%d) %s",
			             nm_device_get_iface (NM_DEVICE (self)),
			             error ? error->code : -1,
			             (error && error->message) ? error->message : "unknown");
			g_clear_error (&error);
		}
	} else {
		nm_log_info (LOGD_HW | LOGD_ETHER,
		             "(%s): driver '%s' does not support carrier detection.",
		             nm_device_get_iface (self),
		             nm_device_get_driver (self));
		priv->carrier = TRUE;
	}

	return object;
}

static void
nm_device_ethernet_init (NMDeviceEthernet * self)
{
}

static gboolean
real_is_up (NMDevice *device)
{
	if (!NM_DEVICE_ETHERNET_GET_PRIVATE (device)->supplicant.mgr)
		return FALSE;

	return TRUE;
}

static gboolean
real_bring_up (NMDevice *dev)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (dev);

	priv->supplicant.mgr = nm_supplicant_manager_get ();

	return priv->supplicant.mgr ? TRUE : FALSE;
}

static void
real_take_down (NMDevice *dev)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (dev);

	if (priv->supplicant.mgr) {
		g_object_unref (priv->supplicant.mgr);
		priv->supplicant.mgr = NULL;
	}
}

static gboolean
real_hw_is_up (NMDevice *device)
{
	return nm_system_device_is_up (device);
}

static gboolean
real_hw_bring_up (NMDevice *dev, gboolean *no_firmware)
{
	return nm_system_device_set_up_down (dev, TRUE, no_firmware);
}

static void
real_hw_take_down (NMDevice *dev)
{
	nm_system_device_set_up_down (dev, FALSE, NULL);
}

NMDevice *
nm_device_ethernet_new (const char *udi,
						const char *iface,
						const char *driver)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_ETHERNET,
	                                  NM_DEVICE_INTERFACE_UDI, udi,
	                                  NM_DEVICE_INTERFACE_IFACE, iface,
	                                  NM_DEVICE_INTERFACE_DRIVER, driver,
	                                  NM_DEVICE_INTERFACE_TYPE_DESC, "Ethernet",
	                                  NM_DEVICE_INTERFACE_DEVICE_TYPE, NM_DEVICE_TYPE_ETHERNET,
	                                  NULL);
}


/*
 * nm_device_ethernet_get_address
 *
 * Get a device's hardware address
 *
 */
void
nm_device_ethernet_get_address (NMDeviceEthernet *self, struct ether_addr *addr)
{
	NMDeviceEthernetPrivate *priv;

	g_return_if_fail (self != NULL);
	g_return_if_fail (addr != NULL);

	priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	memcpy (addr, &priv->hw_addr, sizeof (priv->hw_addr));
}

/* Returns speed in Mb/s */
static guint32
nm_device_ethernet_get_speed (NMDeviceEthernet *self)
{
	int fd;
	struct ifreq ifr;
	struct ethtool_cmd edata = {
		.cmd = ETHTOOL_GSET,
	};
	guint32 speed = 0;

	g_return_val_if_fail (self != NULL, 0);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_warn (LOGD_HW, "couldn't open control socket.");
		return 0;
	}

	memset (&ifr, 0, sizeof (struct ifreq));
	strncpy (ifr.ifr_name, nm_device_get_iface (NM_DEVICE (self)), IFNAMSIZ);
	ifr.ifr_data = (char *) &edata;

	if (ioctl (fd, SIOCETHTOOL, &ifr) < 0)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	speed = edata.speed;
#else
	speed = ethtool_cmd_speed (&edata);
#endif

	if (speed == G_MAXUINT16 || speed == G_MAXUINT32)
		speed = 0;

out:
	close (fd);
	return speed;
}

static void
_update_hw_addr (NMDeviceEthernet *self, const guint8 *addr)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	g_return_if_fail (addr != NULL);

	if (memcmp (&priv->hw_addr, addr, ETH_ALEN)) {
		memcpy (&priv->hw_addr, addr, ETH_ALEN);
		g_object_notify (G_OBJECT (self), NM_DEVICE_ETHERNET_HW_ADDRESS);
	}
}

static gboolean
_set_hw_addr (NMDeviceEthernet *self, const guint8 *addr, const char *detail)
{
	NMDevice *dev = NM_DEVICE (self);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	const char *iface;
	char *mac_str = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (addr != NULL, FALSE);

	iface = nm_device_get_iface (dev);

	mac_str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
	                           addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	/* Do nothing if current MAC is same */
	if (!memcmp (&priv->hw_addr, addr, ETH_ALEN)) {
		nm_log_dbg (LOGD_DEVICE | LOGD_ETHER, "(%s): no MAC address change needed",
		            iface, detail, mac_str);
		g_free (mac_str);
		return TRUE;
	}

	/* Can't change MAC address while device is up */
	real_hw_take_down (dev);

	success = nm_system_device_set_mac (iface, (struct ether_addr *) addr);
	if (success) {
		/* MAC address succesfully changed; update the current MAC to match */
		_update_hw_addr (self, addr);
		nm_log_info (LOGD_DEVICE | LOGD_ETHER, "(%s): %s MAC address to %s",
		             iface, detail, mac_str);
	} else {
		nm_log_warn (LOGD_DEVICE | LOGD_ETHER, "(%s): failed to %s MAC address to %s",
		             iface, detail, mac_str);
	}
	real_hw_bring_up (dev, NULL);
	g_free (mac_str);

	return success;
}

static void
real_update_hw_address (NMDevice *dev)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (dev);
	struct ifreq req;
	int fd;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_warn (LOGD_HW, "couldn't open control socket.");
		return;
	}

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), IFNAMSIZ);

	errno = 0;
	if (ioctl (fd, SIOCGIFHWADDR, &req) < 0) {
		nm_log_err (LOGD_HW | LOGD_ETHER,
		            "(%s) failed to read hardware address (error %d)",
		            nm_device_get_iface (dev), errno);
	} else
		_update_hw_addr (self, (const guint8 *) &req.ifr_hwaddr.sa_data);

	close (fd);
}

static void
real_update_permanent_hw_address (NMDevice *dev)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (dev);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	struct ifreq req;
	struct ethtool_perm_addr *epaddr = NULL;
	int fd, ret;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_warn (LOGD_HW, "couldn't open control socket.");
		return;
	}

	/* Get permanent MAC address */
	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), IFNAMSIZ);

	epaddr = g_malloc0 (sizeof (struct ethtool_perm_addr) + ETH_ALEN);
	epaddr->cmd = ETHTOOL_GPERMADDR;
	epaddr->size = ETH_ALEN;
	req.ifr_data = (void *) epaddr;

	errno = 0;
	ret = ioctl (fd, SIOCETHTOOL, &req);
	if ((ret < 0) || !nm_ethernet_address_is_valid ((struct ether_addr *) epaddr->data)) {
		nm_log_err (LOGD_HW | LOGD_ETHER, "(%s): unable to read permanent MAC address (error %d)",
		            nm_device_get_iface (dev), errno);
		/* Fall back to current address */
		memcpy (epaddr->data, &priv->hw_addr, ETH_ALEN);
	}

	if (memcmp (&priv->perm_hw_addr, epaddr->data, ETH_ALEN)) {
		memcpy (&priv->perm_hw_addr, epaddr->data, ETH_ALEN);
		g_object_notify (G_OBJECT (dev), NM_DEVICE_ETHERNET_PERMANENT_HW_ADDRESS);
	}

	close (fd);
}

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (dev);
	guint32	caps = NM_DEVICE_CAP_NONE;

	/* cipsec devices are also explicitly unsupported at this time */
	if (strstr (nm_device_get_iface (dev), "cipsec"))
		return NM_DEVICE_CAP_NONE;

	if (supports_ethtool_carrier_detect (self) || supports_mii_carrier_detect (self))
		caps |= NM_DEVICE_CAP_CARRIER_DETECT;

	caps |= NM_DEVICE_CAP_NM_SUPPORTED;

	return caps;
}

static gboolean
real_can_interrupt_activation (NMDevice *dev)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (dev);
	gboolean interrupt = FALSE;

	/* Devices that support carrier detect can interrupt activation
	 * if the link becomes inactive.
	 */
	if (nm_device_get_capabilities (dev) & NM_DEVICE_CAP_CARRIER_DETECT) {
		if (NM_DEVICE_ETHERNET_GET_PRIVATE (self)->carrier == FALSE)
			interrupt = TRUE;
	}
	return interrupt;
}

static gboolean
real_is_available (NMDevice *dev)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (dev);

	/* Can't do anything if there isn't a carrier */
	if (!NM_DEVICE_ETHERNET_GET_PRIVATE (self)->carrier)
		return FALSE;

	return TRUE;
}

static gboolean
match_subchans (NMDeviceEthernet *self, NMSettingWired *s_wired, gboolean *try_mac)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	const GPtrArray *subchans;
	int i;

	*try_mac = TRUE;

	subchans = nm_setting_wired_get_s390_subchannels (s_wired);
	if (!subchans)
		return TRUE;

	/* connection requires subchannels but the device has none */
	if (!priv->subchannels)
		return FALSE;

	/* Make sure each subchannel in the connection is a subchannel of this device */
	for (i = 0; i < subchans->len; i++) {
		const char *candidate = g_ptr_array_index (subchans, i);

		if (   (priv->subchan1 && !strcmp (priv->subchan1, candidate))
		    || (priv->subchan2 && !strcmp (priv->subchan2, candidate))
		    || (priv->subchan3 && !strcmp (priv->subchan3, candidate)))
			continue;

		return FALSE;  /* a subchannel was not found */
	}

	*try_mac = FALSE;
	return TRUE;
}

static NMConnection *
real_get_best_auto_connection (NMDevice *dev,
                               GSList *connections,
                               char **specific_object)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (dev);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;
		NMSettingWired *s_wired;
		const char *connection_type;
		gboolean is_pppoe = FALSE;

		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);

		connection_type = nm_setting_connection_get_connection_type (s_con);
		if (!strcmp (connection_type, NM_SETTING_PPPOE_SETTING_NAME))
			is_pppoe = TRUE;

		if (!is_pppoe && strcmp (connection_type, NM_SETTING_WIRED_SETTING_NAME))
			continue;
		if (!nm_setting_connection_get_autoconnect (s_con))
			continue;

		s_wired = (NMSettingWired *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED);
		/* Wired setting optional for PPPoE */
		if (!is_pppoe && !s_wired)
			continue;

		if (s_wired) {
			const GByteArray *mac;
			gboolean try_mac = TRUE;

			if (!match_subchans (self, s_wired, &try_mac))
				continue;

			mac = nm_setting_wired_get_mac_address (s_wired);
			if (try_mac && mac && memcmp (mac->data, &priv->perm_hw_addr, ETH_ALEN))
				continue;
		}

		return connection;
	}
	return NULL;
}

static void
real_connection_secrets_updated (NMDevice *dev,
                                 NMConnection *connection,
                                 GSList *updated_settings,
                                 RequestSecretsCaller caller)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (dev);
	NMActRequest *req;
	gboolean valid = FALSE;
	GSList *iter;

	g_return_if_fail (IS_ACTIVATING_STATE (nm_device_get_state (dev)));

	/* PPPoE? */
	if (caller == SECRETS_CALLER_PPP) {
		NMSettingPPPOE *s_pppoe;

		g_assert (priv->ppp_manager);

		s_pppoe = (NMSettingPPPOE *) nm_connection_get_setting (connection, NM_TYPE_SETTING_PPPOE);
		if (!s_pppoe) {
			nm_ppp_manager_update_secrets (priv->ppp_manager,
			                               nm_device_get_iface (dev),
			                               NULL,
			                               NULL,
			                               "missing PPPoE setting; no secrets could be found.");
		} else {
			const char *pppoe_username = nm_setting_pppoe_get_username (s_pppoe);
			const char *pppoe_password = nm_setting_pppoe_get_password (s_pppoe);

			nm_ppp_manager_update_secrets (priv->ppp_manager,
			                               nm_device_get_iface (dev),
			                               pppoe_username ? pppoe_username : "",
			                               pppoe_password ? pppoe_password : "",
			                               NULL);
		}
		return;
	}

	/* Only caller could be ourselves for 802.1x */
	g_return_if_fail (caller == SECRETS_CALLER_ETHERNET);
	g_return_if_fail (nm_device_get_state (dev) == NM_DEVICE_STATE_NEED_AUTH);

	for (iter = updated_settings; iter; iter = g_slist_next (iter)) {
		const char *setting_name = (const char *) iter->data;

		if (!strcmp (setting_name, NM_SETTING_802_1X_SETTING_NAME)) {
			valid = TRUE;
		} else {
			nm_log_warn (LOGD_DEVICE, "Ignoring updated secrets for setting '%s'.",
			             setting_name);
		}
	}

	req = nm_device_get_act_request (dev);
	g_assert (req);

	g_return_if_fail (nm_act_request_get_connection (req) == connection);
	nm_device_activate_schedule_stage1_device_prepare (dev);
}

/* FIXME: Move it to nm-device.c and then get rid of all foo_device_get_setting() all around.
   It's here now to keep the patch short. */
static NMSetting *
device_get_setting (NMDevice *device, GType setting_type)
{
	NMActRequest *req;
	NMSetting *setting = NULL;

	req = nm_device_get_act_request (device);
	if (req) {
		NMConnection *connection;

		connection = nm_act_request_get_connection (req);
		if (connection)
			setting = nm_connection_get_setting (connection, setting_type);
	}

	return setting;
}

/*****************************************************************************/
/* 802.1X */

static void
remove_supplicant_timeouts (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	if (priv->supplicant.con_timeout_id) {
		g_source_remove (priv->supplicant.con_timeout_id);
		priv->supplicant.con_timeout_id = 0;
	}

	if (priv->supplicant_timeout_id) {
		g_source_remove (priv->supplicant_timeout_id);
		priv->supplicant_timeout_id = 0;
	}
}

static void
finish_supplicant_task (SupplicantStateTask *task, gboolean remove_source)
{
	NMDeviceEthernet *self = task->self;
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	/* idle/timeout handlers should pass FALSE for remove_source, since they
	 * will tell glib to remove their source from the mainloop by returning
	 * FALSE when they exit.  When called from this NMDevice's dispose handler,
	 * remove_source should be TRUE to cancel all outstanding idle/timeout
	 * handlers asynchronously.
	 */
	if (task->source_id && remove_source)
		g_source_remove (task->source_id);

	if (task->mgr_task)
		priv->supplicant.mgr_tasks = g_slist_remove (priv->supplicant.mgr_tasks, task);
	else
		priv->supplicant.iface_tasks = g_slist_remove (priv->supplicant.iface_tasks, task);

	memset (task, 0, sizeof (SupplicantStateTask));
	g_slice_free (SupplicantStateTask, task);
}

static void
remove_supplicant_interface_error_handler (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	if (priv->supplicant.iface_error_id != 0) {
		g_signal_handler_disconnect (priv->supplicant.iface, priv->supplicant.iface_error_id);
		priv->supplicant.iface_error_id = 0;
	}

	if (priv->supplicant.iface_con_error_cb_id > 0) {
		g_source_remove (priv->supplicant.iface_con_error_cb_id);
		priv->supplicant.iface_con_error_cb_id = 0;
	}
}

static void
supplicant_interface_release (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	remove_supplicant_timeouts (self);
	remove_supplicant_interface_error_handler (self);

	/* Clean up all pending supplicant interface state idle tasks */
	while (priv->supplicant.iface_tasks)
		finish_supplicant_task ((SupplicantStateTask *) priv->supplicant.iface_tasks->data, TRUE);

	if (priv->supplicant.iface_con_state_id) {
		g_signal_handler_disconnect (priv->supplicant.iface, priv->supplicant.iface_con_state_id);
		priv->supplicant.iface_con_state_id = 0;
	}

	if (priv->supplicant.iface_state_id > 0) {
		g_signal_handler_disconnect (priv->supplicant.iface, priv->supplicant.iface_state_id);
		priv->supplicant.iface_state_id = 0;
	}

	if (priv->supplicant.mgr_state_id) {
		g_signal_handler_disconnect (priv->supplicant.mgr, priv->supplicant.mgr_state_id);
		priv->supplicant.mgr_state_id = 0;
	}

	if (priv->supplicant.iface) {
		nm_supplicant_interface_disconnect (priv->supplicant.iface);
		nm_supplicant_manager_release_iface (priv->supplicant.mgr, priv->supplicant.iface);
		priv->supplicant.iface = NULL;
	}
}

static gboolean
link_timeout_cb (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMDevice *dev = NM_DEVICE (self);
	NMActRequest *req;
	NMConnection *connection;
	const char *setting_name;

	priv->supplicant_timeout_id = 0;

	req = nm_device_get_act_request (dev);

	if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED) {
		nm_device_state_changed (dev, NM_DEVICE_STATE_DISCONNECTED,
		                         NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
		return FALSE;
	}

	/* Disconnect event during initial authentication and credentials
	 * ARE checked - we are likely to have wrong key.  Ask the user for
	 * another one.
	 */
	if (nm_device_get_state (dev) != NM_DEVICE_STATE_CONFIG)
		goto time_out;

	connection = nm_act_request_get_connection (req);
	nm_connection_clear_secrets (connection);
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (!setting_name)
		goto time_out;

	nm_log_info (LOGD_DEVICE | LOGD_ETHER,
	             "Activation (%s/wired): disconnected during authentication,"
	             " asking for new key.",
	             nm_device_get_iface (dev));
	supplicant_interface_release (self);

	nm_device_state_changed (dev, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
	nm_act_request_get_secrets (req,
	                            setting_name,
	                            TRUE,
	                            SECRETS_CALLER_ETHERNET,
	                            NULL,
	                            NULL);

	return FALSE;

time_out:
	nm_log_warn (LOGD_DEVICE | LOGD_ETHER,
	             "(%s): link timed out.", nm_device_get_iface (dev));
	nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);

	return FALSE;
}

static gboolean
schedule_state_handler (NMDeviceEthernet *self,
                        GSourceFunc handler,
                        guint32 new_state,
                        guint32 old_state,
                        gboolean mgr_task)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	SupplicantStateTask *task;

	if (new_state == old_state)
		return TRUE;

	task = g_slice_new0 (SupplicantStateTask);
	if (!task) {
		nm_log_err (LOGD_DEVICE, "Not enough memory to process supplicant manager state change.");
		return FALSE;
	}

	task->self = self;
	task->new_state = new_state;
	task->old_state = old_state;
	task->mgr_task = mgr_task;

	task->source_id = g_idle_add (handler, task);
	if (mgr_task)
		priv->supplicant.mgr_tasks = g_slist_append (priv->supplicant.mgr_tasks, task);
	else
		priv->supplicant.iface_tasks = g_slist_append (priv->supplicant.iface_tasks, task);
	return TRUE;
}

static gboolean
supplicant_mgr_state_cb_handler (gpointer user_data)
{
	SupplicantStateTask *task = (SupplicantStateTask *) user_data;
	NMDevice *device = NM_DEVICE (task->self);

	/* If the supplicant went away, release the supplicant interface */
	if (task->new_state == NM_SUPPLICANT_MANAGER_STATE_DOWN) {
		supplicant_interface_release (task->self);

		if (nm_device_get_state (device) > NM_DEVICE_STATE_UNAVAILABLE) {
			nm_device_state_changed (device, NM_DEVICE_STATE_UNAVAILABLE,
			                         NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		}
	}

	finish_supplicant_task (task, FALSE);
	return FALSE;
}

static void
supplicant_mgr_state_cb (NMSupplicantInterface * iface,
                         guint32 new_state,
                         guint32 old_state,
                         gpointer user_data)
{
	nm_log_info (LOGD_DEVICE | LOGD_ETHER,
	             "(%s): supplicant manager state:  %s -> %s",
	             nm_device_get_iface (NM_DEVICE (user_data)),
	             nm_supplicant_manager_state_to_string (old_state),
	             nm_supplicant_manager_state_to_string (new_state));

	schedule_state_handler (NM_DEVICE_ETHERNET (user_data),
	                        supplicant_mgr_state_cb_handler,
	                        new_state,
	                        old_state,
	                        TRUE);
}

static NMSupplicantConfig *
build_supplicant_config (NMDeviceEthernet *self)
{
	const char *con_path;
	NMSupplicantConfig *config = NULL;
	NMSetting8021x *security;
	NMConnection *connection;

	connection = nm_act_request_get_connection (nm_device_get_act_request (NM_DEVICE (self)));
	g_return_val_if_fail (connection, NULL);
	con_path = nm_connection_get_path (connection);

	config = nm_supplicant_config_new ();
	if (!config)
		return NULL;

	security = NM_SETTING_802_1X (nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X));
	if (!nm_supplicant_config_add_setting_8021x (config, security, con_path, TRUE)) {
		nm_log_warn (LOGD_DEVICE, "Couldn't add 802.1X security setting to supplicant config.");
		g_object_unref (config);
		config = NULL;
	}

	return config;
}

static gboolean
supplicant_iface_state_cb_handler (gpointer user_data)
{
	SupplicantStateTask *task = (SupplicantStateTask *) user_data;
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (task->self);
	NMDevice *device = NM_DEVICE (task->self);

	if (task->new_state == NM_SUPPLICANT_INTERFACE_STATE_READY) {
		NMSupplicantConfig *config;
		const char *iface;
		gboolean success = FALSE;

		iface = nm_device_get_iface (device);
		config = build_supplicant_config (task->self);
		if (config) {
			success = nm_supplicant_interface_set_config (priv->supplicant.iface, config);
			g_object_unref (config);

			if (!success) {
				nm_log_err (LOGD_DEVICE | LOGD_ETHER,
				            "Activation (%s/wired): couldn't send security "
						    "configuration to the supplicant.",
						    iface);
			}
		} else {
			nm_log_warn (LOGD_DEVICE | LOGD_ETHER,
			             "Activation (%s/wired): couldn't build security configuration.",
			             iface);
		}

		if (!success)
			nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED);
	} else if (task->new_state == NM_SUPPLICANT_INTERFACE_STATE_DOWN) {
		NMDeviceState state = nm_device_get_state (device);

		supplicant_interface_release (task->self);

		if (nm_device_is_activating (device) || state == NM_DEVICE_STATE_ACTIVATED)
			nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
	}

	finish_supplicant_task (task, FALSE);
	return FALSE;
}

static void
supplicant_iface_state_cb (NMSupplicantInterface * iface,
                           guint32 new_state,
                           guint32 old_state,
                           gpointer user_data)
{

	nm_log_info (LOGD_DEVICE | LOGD_ETHER,
	             "(%s): supplicant interface state:  %s -> %s",
	             nm_device_get_iface (NM_DEVICE (user_data)),
	             nm_supplicant_interface_state_to_string (old_state),
	             nm_supplicant_interface_state_to_string (new_state));

	schedule_state_handler (NM_DEVICE_ETHERNET (user_data),
	                        supplicant_iface_state_cb_handler,
	                        new_state,
	                        old_state,
	                        FALSE);
}

static gboolean
supplicant_iface_connection_state_cb_handler (gpointer user_data)
{
	SupplicantStateTask *task = (SupplicantStateTask *) user_data;
	NMDevice *dev = NM_DEVICE (task->self);

	if (task->new_state == NM_SUPPLICANT_INTERFACE_CON_STATE_COMPLETED) {
		remove_supplicant_interface_error_handler (task->self);
		remove_supplicant_timeouts (task->self);

		/* If this is the initial association during device activation,
		 * schedule the next activation stage.
		 */
		if (nm_device_get_state (dev) == NM_DEVICE_STATE_CONFIG) {
			nm_log_info (LOGD_DEVICE | LOGD_ETHER,
			             "Activation (%s/wired) Stage 2 of 5 (Device Configure) successful.",
				         nm_device_get_iface (dev));
			nm_device_activate_schedule_stage3_ip_config_start (dev);
		}
	} else if (task->new_state == NM_SUPPLICANT_INTERFACE_CON_STATE_DISCONNECTED) {
		if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED || nm_device_is_activating (dev)) {
			NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (task->self);

			/* Start the link timeout so we allow some time for reauthentication */
			if (!priv->supplicant_timeout_id)
				priv->supplicant_timeout_id = g_timeout_add_seconds (15, link_timeout_cb, dev);
		}
	}

	finish_supplicant_task (task, FALSE);
	return FALSE;
}

static void
supplicant_iface_connection_state_cb (NMSupplicantInterface * iface,
                                      guint32 new_state,
                                      guint32 old_state,
                                      gpointer user_data)
{
	nm_log_info (LOGD_DEVICE | LOGD_ETHER,
	             "(%s) supplicant connection state:  %s -> %s",
	             nm_device_get_iface (NM_DEVICE (user_data)),
	             nm_supplicant_interface_connection_state_to_string (old_state),
	             nm_supplicant_interface_connection_state_to_string (new_state));

	schedule_state_handler (NM_DEVICE_ETHERNET (user_data),
	                        supplicant_iface_connection_state_cb_handler,
	                        new_state,
	                        old_state,
	                        FALSE);
}

static gboolean
supplicant_iface_connection_error_cb_handler (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	supplicant_interface_release (self);
	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED);

	priv->supplicant.iface_con_error_cb_id = 0;
	return FALSE;
}

static void
supplicant_iface_connection_error_cb (NMSupplicantInterface *iface,
                                      const char *name,
                                      const char *message,
                                      gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	guint id;

	nm_log_warn (LOGD_DEVICE | LOGD_ETHER,
	             "Activation (%s/wired): association request to the supplicant failed: %s - %s",
	             nm_device_get_iface (NM_DEVICE (self)), name, message);

	if (priv->supplicant.iface_con_error_cb_id)
		g_source_remove (priv->supplicant.iface_con_error_cb_id);

	id = g_idle_add (supplicant_iface_connection_error_cb_handler, self);
	priv->supplicant.iface_con_error_cb_id = id;
}

static NMActStageReturn
handle_auth_or_fail (NMDeviceEthernet *self,
                     NMActRequest *req,
                     gboolean new_secrets)
{
	const char *setting_name;
	guint32 tries;
	NMConnection *connection;

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	tries = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), WIRED_SECRETS_TRIES));
	if (tries > 3)
		return NM_ACT_STAGE_RETURN_FAILURE;

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);

	nm_connection_clear_secrets (connection);
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		gboolean get_new;

		/* If the caller doesn't necessarily want completely new secrets,
		 * only ask for new secrets after the first failure.
		 */
		get_new = new_secrets ? TRUE : (tries ? TRUE : FALSE);
		nm_act_request_get_secrets (req,
		                            setting_name,
		                            get_new,
		                            SECRETS_CALLER_ETHERNET,
		                            NULL,
		                            NULL);

		g_object_set_data (G_OBJECT (connection), WIRED_SECRETS_TRIES, GUINT_TO_POINTER (++tries));
	} else {
		nm_log_info (LOGD_DEVICE, "Cleared secrets, but setting didn't need any secrets.");
	}

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static gboolean
supplicant_connection_timeout_cb (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	NMActRequest *req;
	const char *iface;

	priv->supplicant.con_timeout_id = 0;

	iface = nm_device_get_iface (device);

	/* Authentication failed, encryption key is probably bad */
	nm_log_warn (LOGD_DEVICE | LOGD_ETHER,
	             "Activation (%s/wired): association took too long.", iface);

	supplicant_interface_release (self);
	req = nm_device_get_act_request (device);
	g_assert (req);

	if (handle_auth_or_fail (self, req, TRUE) == NM_ACT_STAGE_RETURN_POSTPONE) {
		nm_log_info (LOGD_DEVICE | LOGD_ETHER,
		             "Activation (%s/wired): asking for new secrets", iface);
	} else
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NO_SECRETS);

	return FALSE;
}

static gboolean
supplicant_interface_init (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	const char *iface;

	iface = nm_device_get_iface (NM_DEVICE (self));

	/* Create supplicant interface */
	priv->supplicant.iface = nm_supplicant_manager_get_iface (priv->supplicant.mgr, iface, FALSE);
	if (!priv->supplicant.iface) {
		nm_log_err (LOGD_DEVICE | LOGD_ETHER,
		            "Couldn't initialize supplicant interface for %s.",
		            iface);
		supplicant_interface_release (self);

		return FALSE;
	}

	/* Listen for it's state signals */
	priv->supplicant.iface_state_id = g_signal_connect (priv->supplicant.iface,
											  "state",
											  G_CALLBACK (supplicant_iface_state_cb),
											  self);

	/* Hook up error signal handler to capture association errors */
	priv->supplicant.iface_error_id = g_signal_connect (priv->supplicant.iface,
											  "connection-error",
											  G_CALLBACK (supplicant_iface_connection_error_cb),
											  self);

	priv->supplicant.iface_con_state_id = g_signal_connect (priv->supplicant.iface,
												 "connection-state",
												 G_CALLBACK (supplicant_iface_connection_state_cb),
												 self);

	/* Listen for supplicant manager state changes */
	priv->supplicant.mgr_state_id = g_signal_connect (priv->supplicant.mgr,
											"state",
											G_CALLBACK (supplicant_mgr_state_cb),
											self);

	/* Set up a timeout on the connection attempt to fail it after 25 seconds */
	priv->supplicant.con_timeout_id = g_timeout_add_seconds (25, supplicant_connection_timeout_cb, self);

	return TRUE;
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (dev);
	NMActRequest *req;
	NMSettingWired *s_wired;
	const GByteArray *cloned_mac;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_val_if_fail (req != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	s_wired = NM_SETTING_WIRED (device_get_setting (dev, NM_TYPE_SETTING_WIRED));
	g_assert (s_wired);

	/* Set device MAC address if the connection wants to change it */
	cloned_mac = nm_setting_wired_get_cloned_mac_address (s_wired);
	if (cloned_mac && (cloned_mac->len == ETH_ALEN))
		_set_hw_addr (self, (const guint8 *) cloned_mac->data, "set");

	return ret;
}

static NMActStageReturn
nm_8021x_stage2_config (NMDeviceEthernet *self, NMDeviceStateReason *reason)
{
	NMConnection *connection;
	NMSetting8021x *security;
	NMSettingConnection *s_connection;
	const char *setting_name;
	const char *iface;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	connection = nm_act_request_get_connection (nm_device_get_act_request (NM_DEVICE (self)));
	security = NM_SETTING_802_1X (nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X));
	if (!security) {
		nm_log_err (LOGD_DEVICE, "Invalid or missing 802.1X security");
		*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		return ret;
	}

	iface = nm_device_get_iface (NM_DEVICE (self));
	s_connection = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));

	/* If we need secrets, get them */
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		NMActRequest *req = nm_device_get_act_request (NM_DEVICE (self));

		nm_log_info (LOGD_DEVICE | LOGD_ETHER,
		             "Activation (%s/wired): connection '%s' has security, but secrets are required.",
				     iface, nm_setting_connection_get_id (s_connection));

		ret = handle_auth_or_fail (self, req, FALSE);
		if (ret != NM_ACT_STAGE_RETURN_POSTPONE)
			*reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
	} else {
		nm_log_info (LOGD_DEVICE | LOGD_ETHER,
		             "Activation (%s/wired): connection '%s' requires no security. No secrets needed.",
				     iface, nm_setting_connection_get_id (s_connection));

		if (supplicant_interface_init (self))
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
		else
			*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
	}

	return ret;
}

/*****************************************************************************/
/* PPPoE */

static void
ppp_state_changed (NMPPPManager *ppp_manager, NMPPPStatus status, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	switch (status) {
	case NM_PPP_STATUS_DISCONNECT:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_DISCONNECT);
		break;
	case NM_PPP_STATUS_DEAD:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_FAILED);
		break;
	default:
		break;
	}
}

static void
ppp_ip4_config (NMPPPManager *ppp_manager,
			 const char *iface,
			 NMIP4Config *config,
			 gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	/* Ignore PPP IP4 events that come in after initial configuration */
	if (nm_device_get_state (device) != NM_DEVICE_STATE_IP_CONFIG)
		return;

	nm_device_set_ip_iface (device, iface);
	NM_DEVICE_ETHERNET_GET_PRIVATE (device)->pending_ip4_config = g_object_ref (config);
	nm_device_activate_schedule_stage4_ip4_config_get (device);
}

static NMActStageReturn
pppoe_stage3_ip4_config_start (NMDeviceEthernet *self, NMDeviceStateReason *reason)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingPPPOE *s_pppoe;
	NMActRequest *req;
	GError *err = NULL;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_assert (req);

	connection = nm_act_request_get_connection (req);
	g_assert (req);

	s_pppoe = (NMSettingPPPOE *) nm_connection_get_setting (connection, NM_TYPE_SETTING_PPPOE);
	g_assert (s_pppoe);

	priv->ppp_manager = nm_ppp_manager_new (nm_device_get_iface (NM_DEVICE (self)));
	if (nm_ppp_manager_start (priv->ppp_manager, req, nm_setting_pppoe_get_username (s_pppoe), 30, &err)) {
		g_signal_connect (priv->ppp_manager, "state-changed",
					   G_CALLBACK (ppp_state_changed),
					   self);
		g_signal_connect (priv->ppp_manager, "ip4-config",
					   G_CALLBACK (ppp_ip4_config),
					   self);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		nm_log_warn (LOGD_DEVICE, "(%s): PPPoE failed to start: %s",
		             nm_device_get_iface (NM_DEVICE (self)), err->message);
		g_error_free (err);

		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;

		*reason = NM_DEVICE_STATE_REASON_PPP_START_FAILED;
	}

	return ret;
}

static NMActStageReturn
real_act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMSettingConnection *s_con;
	const char *connection_type;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	s_con = NM_SETTING_CONNECTION (device_get_setting (device, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	/* 802.1x has to run before any IP configuration since the 802.1x auth
	 * process opens the port up for normal traffic.
	 */
	connection_type = nm_setting_connection_get_connection_type (s_con);
	if (!strcmp (connection_type, NM_SETTING_WIRED_SETTING_NAME)) {
		NMSetting8021x *security;

		security = (NMSetting8021x *) device_get_setting (device, NM_TYPE_SETTING_802_1X);
		if (security)
			ret = nm_8021x_stage2_config (NM_DEVICE_ETHERNET (device), reason);
	}

	return ret;
}

static NMActStageReturn
real_act_stage3_ip4_config_start (NMDevice *device, NMDeviceStateReason *reason)
{
	NMSettingConnection *s_con;
	const char *connection_type;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	s_con = NM_SETTING_CONNECTION (device_get_setting (device, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	connection_type = nm_setting_connection_get_connection_type (s_con);
	if (!strcmp (connection_type, NM_SETTING_PPPOE_SETTING_NAME))
		return pppoe_stage3_ip4_config_start (NM_DEVICE_ETHERNET (device), reason);

	return NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->act_stage3_ip4_config_start (device, reason);
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *device,
                                NMIP4Config **config,
                                NMDeviceStateReason *reason)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMActStageReturn ret;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	if (!priv->ppp_manager) {
		/* Regular ethernet connection. */

		/* Chain up to parent */
		ret = NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->act_stage4_get_ip4_config (device, config, reason);

		if (ret == NM_ACT_STAGE_RETURN_SUCCESS) {
			NMConnection *connection;
			NMSettingWired *s_wired;
			guint32 mtu;

			connection = nm_act_request_get_connection (nm_device_get_act_request (device));
			g_assert (connection);
			s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
			g_assert (s_wired);

			/* MTU override */
			mtu = nm_setting_wired_get_mtu (s_wired);
			if (mtu)
				nm_ip4_config_set_mtu (*config, mtu);
		}
	} else {
		NMConnection *connection;
		NMSettingIP4Config *s_ip4;

		/* PPPoE */
		*config = priv->pending_ip4_config;
		priv->pending_ip4_config = NULL;

		/* Merge user-defined overrides into the IP4Config to be applied */
		connection = nm_act_request_get_connection (nm_device_get_act_request (device));
		g_assert (connection);
		s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
		nm_utils_merge_ip4_config (*config, s_ip4);

		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	}

	return ret;
}

static void
real_deactivate_quickly (NMDevice *device)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	if (priv->pending_ip4_config) {
		g_object_unref (priv->pending_ip4_config);
		priv->pending_ip4_config = NULL;
	}

	if (priv->ppp_manager) {
		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;
	}

	supplicant_interface_release (self);

	/* Reset MAC address back to permanent address */
	_set_hw_addr (self, priv->perm_hw_addr, "reset");
}

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	const char *connection_type;
	gboolean is_pppoe = FALSE;
	const GByteArray *mac;
	gboolean try_mac = TRUE;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	connection_type = nm_setting_connection_get_connection_type (s_con);
	if (   strcmp (connection_type, NM_SETTING_WIRED_SETTING_NAME)
	    && strcmp (connection_type, NM_SETTING_PPPOE_SETTING_NAME)) {
		g_set_error (error,
		             NM_ETHERNET_ERROR, NM_ETHERNET_ERROR_CONNECTION_NOT_WIRED,
		             "The connection was not a wired or PPPoE connection.");
		return FALSE;
	}

	if (!strcmp (connection_type, NM_SETTING_PPPOE_SETTING_NAME))
		is_pppoe = TRUE;

	s_wired = (NMSettingWired *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED);
	/* Wired setting is optional for PPPoE */
	if (!is_pppoe && !s_wired) {
		g_set_error (error,
		             NM_ETHERNET_ERROR, NM_ETHERNET_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid wired connection.");
		return FALSE;
	}

	if (s_wired) {
		if (!match_subchans (self, s_wired, &try_mac)) {
			g_set_error (error,
			             NM_ETHERNET_ERROR, NM_ETHERNET_ERROR_CONNECTION_INCOMPATIBLE,
			             "The connection's s390 subchannels did not match this device.");
			return FALSE;
		}

		mac = nm_setting_wired_get_mac_address (s_wired);
		if (try_mac && mac && memcmp (mac->data, &priv->perm_hw_addr, ETH_ALEN)) {
			g_set_error (error,
			             NM_ETHERNET_ERROR, NM_ETHERNET_ERROR_CONNECTION_INCOMPATIBLE,
			             "The connection's MAC address did not match this device.");
			return FALSE;
		}
	}

	// FIXME: check bitrate against device capabilities

	return TRUE;
}

static gboolean
spec_match_list (NMDevice *device, const GSList *specs)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);
	char *hwaddr;
	gboolean matched;

	hwaddr = nm_ether_ntop ((struct ether_addr *) &priv->perm_hw_addr);
	matched = nm_match_spec_hwaddr (specs, hwaddr);
	g_free (hwaddr);

	if (!matched && priv->subchannels)
		matched = nm_match_spec_s390_subchannels (specs, priv->subchannels);

	return matched;
}

static gboolean
wired_match_config (NMDevice *self, NMConnection *connection)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMSettingWired *s_wired;
	const GByteArray *s_ether;
	gboolean try_mac = TRUE;

	s_wired = (NMSettingWired *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED);
	if (!s_wired)
		return FALSE;

	if (!match_subchans (NM_DEVICE_ETHERNET (self), s_wired, &try_mac))
		return FALSE;

	/* MAC address check */
	s_ether = nm_setting_wired_get_mac_address (s_wired);
	if (try_mac && s_ether && memcmp (s_ether->data, priv->perm_hw_addr, ETH_ALEN))
		return FALSE;

	return TRUE;
}

typedef struct {
	int ifindex;
	NMIP4Address *addr;
	gboolean found;
} AddrData;

static void
check_one_address (struct nl_object *object, void *user_data)
{
	AddrData *data = user_data;
	struct rtnl_addr *addr = (struct rtnl_addr *) object;
	struct nl_addr *local;
	struct in_addr tmp;

	if (rtnl_addr_get_ifindex (addr) != data->ifindex)
		return;
	if (rtnl_addr_get_family (addr) != AF_INET)
		return;

	if (nm_ip4_address_get_prefix (data->addr) != rtnl_addr_get_prefixlen (addr))
		return;

	local = rtnl_addr_get_local (addr);
	if (nl_addr_get_family (local) != AF_INET)
		return;
	if (nl_addr_get_len (local) != sizeof (struct in_addr))
		return;
	if (!nl_addr_get_binary_addr (local))
		return;

	memcpy (&tmp, nl_addr_get_binary_addr (local), nl_addr_get_len (local));
	if (tmp.s_addr != nm_ip4_address_get_address (data->addr))
		return;

	/* Yay, found it */
	data->found = TRUE;
}

static gboolean
ip4_match_config (NMDevice *self, NMConnection *connection)
{
	NMSettingIP4Config *s_ip4;
	NMSettingConnection *s_con;
	struct nl_handle *nlh = NULL;
	struct nl_cache *addr_cache = NULL;
	int i, num;
	GSList *leases, *iter;
	NMDHCPManager *dhcp_mgr;
	const char *method;
	int ifindex;
	AddrData check_data;

	ifindex = nm_device_get_ifindex (self);

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);
	g_assert (nm_setting_connection_get_uuid (s_con));

	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (!s_ip4)
		return FALSE;

	/* Read all the device's IP addresses */
	nlh = nm_netlink_get_default_handle ();
	if (!nlh)
		return FALSE;

	addr_cache = rtnl_addr_alloc_cache (nlh);
	if (!addr_cache)
		return FALSE;
	nl_cache_mngt_provide (addr_cache);

	/* Get any saved leases that apply to this connection */
	dhcp_mgr = nm_dhcp_manager_get ();
	leases = nm_dhcp_manager_get_lease_config (dhcp_mgr,
	                                           nm_device_get_iface (self),
	                                           nm_setting_connection_get_uuid (s_con));
	g_object_unref (dhcp_mgr);

	method = nm_setting_ip4_config_get_method (s_ip4);
	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		gboolean found = FALSE;

		/* Find at least one lease's address on the device */
		for (iter = leases; iter; iter = g_slist_next (iter)) {
			NMIP4Config *addr = iter->data;

			memset (&check_data, 0, sizeof (check_data));
			check_data.ifindex = ifindex;
			check_data.found = FALSE;
			check_data.addr = nm_ip4_config_get_address (addr, 0);

			nl_cache_foreach (addr_cache, check_one_address, &check_data);
			if (check_data.found) {
				found = TRUE; /* Yay, device has same address as a lease */
				break;
			}
		}
		g_slist_foreach (leases, (GFunc) g_object_unref, NULL);
		g_slist_free (leases);
		return found;
	} else {
		/* Maybe the connection used to be DHCP and there are stale leases; ignore them */
		g_slist_foreach (leases, (GFunc) g_object_unref, NULL);
		g_slist_free (leases);
	}

	/* 'shared' and 'link-local' aren't supported methods because 'shared'
	 * requires too much iptables and dnsmasq state to be reclaimed, and
	 * avahi-autoipd isn't smart enough to allow the link-local address to be
	 * determined at any point other than when it was first assigned.
	 */
	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL))
		return FALSE;

	/* Everything below for static addressing */

	/* Find all IP4 addresses of this connection in the device's address list */
	num = nm_setting_ip4_config_get_num_addresses (s_ip4);
	for (i = 0; i < num; i++) {
		memset (&check_data, 0, sizeof (check_data));
		check_data.ifindex = ifindex;
		check_data.found = FALSE;
		check_data.addr = nm_setting_ip4_config_get_address (s_ip4, i);

		nl_cache_foreach (addr_cache, check_one_address, &check_data);
		if (!check_data.found)
			return FALSE;
	}

	/* Success; all the connection's static IP addresses are assigned to the device */
	return TRUE;
}

static NMConnection *
connection_match_config (NMDevice *self, const GSList *connections)
{
	GSList *iter;
	NMSettingConnection *s_con;

	for (iter = (GSList *) connections; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		s_con = (NMSettingConnection *) nm_connection_get_setting (candidate, NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);
		if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_WIRED_SETTING_NAME))
			continue;

		/* Can't assume 802.1x or PPPoE connections; they have too much state
		 * that's impossible to get on-the-fly from PPPoE or the supplicant.
		 */
		if (   nm_connection_get_setting (candidate, NM_TYPE_SETTING_802_1X)
		    || nm_connection_get_setting (candidate, NM_TYPE_SETTING_PPPOE))
			continue;

		if (!wired_match_config (self, candidate))
			continue;

		if (!ip4_match_config (self, candidate))
			continue;

		return candidate;
	}

	return NULL;
}

static void
dispose (GObject *object)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (object);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_ethernet_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	/* Clean up all pending supplicant tasks */
	while (priv->supplicant.iface_tasks)
		finish_supplicant_task ((SupplicantStateTask *) priv->supplicant.iface_tasks->data, TRUE);
	while (priv->supplicant.mgr_tasks)
		finish_supplicant_task ((SupplicantStateTask *) priv->supplicant.mgr_tasks->data, TRUE);

	if (priv->link_connected_id) {
		g_signal_handler_disconnect (priv->monitor, priv->link_connected_id);
		priv->link_connected_id = 0;
	}
	if (priv->link_disconnected_id) {
		g_signal_handler_disconnect (priv->monitor, priv->link_disconnected_id);
		priv->link_disconnected_id = 0;
	}

	carrier_action_defer_clear (self);

	if (priv->monitor) {
		g_object_unref (priv->monitor);
		priv->monitor = NULL;
	}

	g_free (priv->subchan1);
	g_free (priv->subchan2);
	g_free (priv->subchan3);
	g_free (priv->subchannels);

	G_OBJECT_CLASS (nm_device_ethernet_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (object);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_take_string (value, nm_ether_ntop ((struct ether_addr *) &priv->hw_addr));
		break;
	case PROP_PERM_HW_ADDRESS:
		g_value_take_string (value, nm_ether_ntop ((struct ether_addr *) &priv->perm_hw_addr));
		break;
	case PROP_SPEED:
		g_value_set_uint (value, nm_device_ethernet_get_speed (self));
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, priv->carrier);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_ethernet_class_init (NMDeviceEthernetClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceEthernetPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->hw_is_up = real_hw_is_up;
	parent_class->hw_bring_up = real_hw_bring_up;
	parent_class->hw_take_down = real_hw_take_down;
	parent_class->is_up = real_is_up;
	parent_class->bring_up = real_bring_up;
	parent_class->take_down = real_take_down;
	parent_class->can_interrupt_activation = real_can_interrupt_activation;
	parent_class->update_hw_address = real_update_hw_address;
	parent_class->update_permanent_hw_address = real_update_permanent_hw_address;
	parent_class->get_best_auto_connection = real_get_best_auto_connection;
	parent_class->is_available = real_is_available;
	parent_class->connection_secrets_updated = real_connection_secrets_updated;
	parent_class->check_connection_compatible = real_check_connection_compatible;

	parent_class->act_stage1_prepare = real_act_stage1_prepare;
	parent_class->act_stage2_config = real_act_stage2_config;
	parent_class->act_stage3_ip4_config_start = real_act_stage3_ip4_config_start;
	parent_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	parent_class->deactivate_quickly = real_deactivate_quickly;
	parent_class->spec_match_list = spec_match_list;
	parent_class->connection_match_config = connection_match_config;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_ETHERNET_HW_ADDRESS,
							  "Active MAC Address",
							  "Currently set hardware MAC address",
							  NULL,
							  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_PERM_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_ETHERNET_PERMANENT_HW_ADDRESS,
							  "Permanent MAC Address",
							  "Permanent hardware MAC address",
							  NULL,
							  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_SPEED,
		 g_param_spec_uint (NM_DEVICE_ETHERNET_SPEED,
						   "Speed",
						   "Speed",
						   0, G_MAXUINT32, 0,
						   G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_ETHERNET_CARRIER,
							   "Carrier",
							   "Carrier",
							   FALSE,
							   G_PARAM_READABLE));

	/* Signals */
	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class,
								    G_STRUCT_OFFSET (NMDeviceEthernetClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_device_ethernet_object_info);

	dbus_g_error_domain_register (NM_ETHERNET_ERROR, NULL, NM_TYPE_ETHERNET_ERROR);
}


/**************************************/
/*    Ethtool capability detection    */
/**************************************/

static gboolean
supports_ethtool_carrier_detect (NMDeviceEthernet *self)
{
	int fd;
	struct ifreq ifr;
	gboolean supports_ethtool = FALSE;
	struct ethtool_cmd edata;

	g_return_val_if_fail (self != NULL, FALSE);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_err (LOGD_HW, "couldn't open control socket.");
		return FALSE;
	}

	memset (&ifr, 0, sizeof (struct ifreq));
	strncpy (ifr.ifr_name, nm_device_get_iface (NM_DEVICE (self)), IFNAMSIZ);

	edata.cmd = ETHTOOL_GLINK;
	ifr.ifr_data = (char *) &edata;

	errno = 0;
	if (ioctl (fd, SIOCETHTOOL, &ifr) < 0) {
		nm_log_dbg (LOGD_HW | LOGD_ETHER, "SIOCETHTOOL failed: %d", errno);
		goto out;
	}

	supports_ethtool = TRUE;

out:
	close (fd);
	nm_log_dbg (LOGD_HW | LOGD_ETHER, "ethtool %s supported",
	            supports_ethtool ? "is" : "not");
	return supports_ethtool;
}


/**************************************/
/*    MII capability detection        */
/**************************************/
#define _LINUX_IF_H
#include <linux/mii.h>
#undef _LINUX_IF_H

static int
mdio_read (NMDeviceEthernet *self, int fd, struct ifreq *ifr, int location)
{
	struct mii_ioctl_data *mii;
	int val = -1;

	g_return_val_if_fail (fd >= 0, -1);
	g_return_val_if_fail (ifr != NULL, -1);

	mii = (struct mii_ioctl_data *) &ifr->ifr_ifru;
	mii->reg_num = location;

	errno = 0;
	if (ioctl (fd, SIOCGMIIREG, ifr) == 0) {
		nm_log_dbg (LOGD_HW | LOGD_ETHER, "SIOCGMIIREG result 0x%X", mii->val_out);
		val = mii->val_out;
	} else {
		nm_log_dbg (LOGD_HW | LOGD_ETHER, "SIOCGMIIREG failed: %d", errno);
	}

	return val;
}

static gboolean
supports_mii_carrier_detect (NMDeviceEthernet *self)
{
	int fd, bmsr;
	struct ifreq ifr;
	gboolean supports_mii = FALSE;

	g_return_val_if_fail (self != NULL, FALSE);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_err (LOGD_HW, "couldn't open control socket.");
		return 0;
	}

	memset (&ifr, 0, sizeof (struct ifreq));
	strncpy (ifr.ifr_name, nm_device_get_iface (NM_DEVICE (self)), IFNAMSIZ);

	errno = 0;
	if (ioctl (fd, SIOCGMIIPHY, &ifr) < 0) {
		nm_log_dbg (LOGD_HW | LOGD_ETHER, "SIOCGMIIPHY failed: %d", errno);
		goto out;
	}

	/* If we can read the BMSR register, we assume that the card supports MII link detection */
	bmsr = mdio_read (self, fd, &ifr, MII_BMSR);
	supports_mii = (bmsr != -1) ? TRUE : FALSE;
	nm_log_dbg (LOGD_HW | LOGD_ETHER, "MII %s supported",
	            supports_mii ? "is" : "not");

out:
	close (fd);
	return supports_mii;	
}
