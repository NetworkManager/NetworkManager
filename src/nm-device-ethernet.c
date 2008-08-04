/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <glib/gi18n.h>
#include <netinet/in.h>
#include <string.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include <errno.h>

#include "nm-device-ethernet.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-activation-request.h"
#include "NetworkManagerUtils.h"
#include "nm-supplicant-manager.h"
#include "nm-supplicant-interface.h"
#include "nm-supplicant-config.h"
#include "nm-netlink.h"
#include "nm-netlink-monitor.h"
#include "NetworkManagerSystem.h"
#include "nm-setting-connection.h"
#include "nm-setting-wired.h"
#include "nm-setting-8021x.h"
#include "nm-setting-pppoe.h"
#include "ppp-manager/nm-ppp-manager.h"
#include "nm-utils.h"
#include "nm-properties-changed-signal.h"

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

typedef struct Supplicant {
	NMSupplicantManager *mgr;
	NMSupplicantInterface *iface;

	/* signal handler ids */
	guint                   mgr_state_id;
	guint                   iface_error_id;
	guint                   iface_state_id;
	guint                   iface_con_state_id;

	guint                   con_timeout_id;
} Supplicant;

typedef struct {
	gboolean	dispose_has_run;

	struct ether_addr	hw_addr;
	gboolean			carrier;
	guint				state_to_disconnected_id;

	char *			carrier_file_path;
	gulong			link_connected_id;
	gulong			link_disconnected_id;

	Supplicant          supplicant;
	guint               link_timeout_id;

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
set_carrier (NMDeviceEthernet *self, const gboolean carrier)
{
	NMDeviceEthernetPrivate *priv;
	NMDeviceState state;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	if (priv->carrier == carrier)
		return;

	priv->carrier = carrier;
	g_object_notify (G_OBJECT (self), NM_DEVICE_ETHERNET_CARRIER);

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (self));
nm_info ("(%s): carrier now %s (device state %d)", nm_device_get_iface (NM_DEVICE (self)), carrier ? "ON" : "OFF", state);
	if (state == NM_DEVICE_STATE_UNAVAILABLE) {
		if (carrier)
			nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_NONE);
	} else if (state >= NM_DEVICE_STATE_DISCONNECTED) {
		if (!carrier)
			nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_UNAVAILABLE, NM_DEVICE_STATE_REASON_NONE);
	}
}

static void
nm_device_ethernet_carrier_on (NMNetlinkMonitor *monitor,
                                     int idx,
                                     gpointer user_data)
{
	NMDevice *dev = NM_DEVICE (user_data);
	guint32 caps;

	/* Make sure signal is for us */
	if (nm_netlink_iface_to_index (nm_device_get_iface (dev)) == idx) {
		/* Ignore spurious netlink messages */
		caps = nm_device_get_capabilities (dev);
		if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT))
			return;

		set_carrier (NM_DEVICE_ETHERNET (dev), TRUE);
	}
}

static void
nm_device_ethernet_carrier_off (NMNetlinkMonitor *monitor,
                                      int idx,
                                      gpointer user_data)
{
	NMDevice *dev = NM_DEVICE (user_data);
	guint32 caps;

	/* Make sure signal is for us */
	if (nm_netlink_iface_to_index (nm_device_get_iface (dev)) == idx) {
		/* Ignore spurious netlink messages */
		caps = nm_device_get_capabilities (dev);
		if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT))
			return;

		set_carrier (NM_DEVICE_ETHERNET (dev), FALSE);
	}
}

static gboolean
unavailable_to_disconnected (gpointer user_data)
{
	nm_device_state_changed (NM_DEVICE (user_data), NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_NONE);
	return FALSE;
}

static void
device_state_changed (NMDeviceInterface *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	/* Remove any previous delayed transition to disconnected */
	if (priv->state_to_disconnected_id) {
		g_source_remove (priv->state_to_disconnected_id);
		priv->state_to_disconnected_id = 0;
	}

	/* If transitioning to UNAVAILBLE and we have a carrier, transition to
	 * DISCONNECTED because the device is ready to use.  Otherwise the carrier-on
	 * handler will handle the transition to DISCONNECTED when the carrier is detected.
	 */
	if ((new_state == NM_DEVICE_STATE_UNAVAILABLE) && priv->carrier) {
		priv->state_to_disconnected_id = g_idle_add (unavailable_to_disconnected, self);
		return;
	}
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDeviceEthernetPrivate * priv;
	NMDevice * dev;
	guint32 caps;

	object = G_OBJECT_CLASS (nm_device_ethernet_parent_class)->constructor (type,
																   n_construct_params,
																   construct_params);
	if (!object)
		return NULL;

	dev = NM_DEVICE (object);
	priv = NM_DEVICE_ETHERNET_GET_PRIVATE (dev);

	priv->carrier_file_path = g_strdup_printf ("/sys/class/net/%s/carrier",
	                                           nm_device_get_iface (dev));

	caps = nm_device_get_capabilities (dev);
	if (caps & NM_DEVICE_CAP_CARRIER_DETECT) {
		GError *error = NULL;

		/* Only listen to netlink for cards that support carrier detect */
		NMNetlinkMonitor * monitor = nm_netlink_monitor_get ();

		priv->link_connected_id = g_signal_connect (monitor, "carrier-on",
										    G_CALLBACK (nm_device_ethernet_carrier_on),
										    dev);
		priv->link_disconnected_id = g_signal_connect (monitor, "carrier-off",
											  G_CALLBACK (nm_device_ethernet_carrier_off),
											  dev);

		if (!nm_netlink_monitor_request_status (monitor, &error)) {
			nm_warning ("couldn't request carrier state: %s", error->message);
			g_error_free (error);
		}

		g_object_unref (monitor);
	} else {
		priv->link_connected_id = 0;
		priv->link_disconnected_id = 0;
		priv->carrier = TRUE;
	}

	g_signal_connect (dev, "state-changed", G_CALLBACK (device_state_changed), dev);

	return object;
}

static void
nm_device_ethernet_init (NMDeviceEthernet * self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	priv->dispose_has_run = FALSE;

	memset (&(priv->hw_addr), 0, sizeof (struct ether_addr));
	priv->carrier = FALSE;

	nm_device_set_device_type (NM_DEVICE (self), NM_DEVICE_TYPE_ETHERNET);
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
real_hw_bring_up (NMDevice *dev)
{
	return nm_system_device_set_up_down (dev, TRUE);
}

static void
real_hw_take_down (NMDevice *dev)
{
	nm_system_device_set_up_down (dev, FALSE);
}

NMDeviceEthernet *
nm_device_ethernet_new (const char *udi,
						const char *iface,
						const char *driver,
						gboolean managed)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMDeviceEthernet *) g_object_new (NM_TYPE_DEVICE_ETHERNET,
										 NM_DEVICE_INTERFACE_UDI, udi,
										 NM_DEVICE_INTERFACE_IFACE, iface,
										 NM_DEVICE_INTERFACE_DRIVER, driver,
										 NM_DEVICE_INTERFACE_MANAGED, managed,
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
	g_return_if_fail (self != NULL);
	g_return_if_fail (addr != NULL);

	memcpy (addr, &(NM_DEVICE_ETHERNET_GET_PRIVATE (self)->hw_addr), sizeof (struct ether_addr));
}

/*
 * Get/set functions for carrier
 */
gboolean
nm_device_ethernet_get_carrier (NMDeviceEthernet *self)
{
	g_return_val_if_fail (self != NULL, FALSE);

	return NM_DEVICE_ETHERNET_GET_PRIVATE (self)->carrier;
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
		nm_warning ("couldn't open control socket.");
		return 0;
	}

	memset (&ifr, 0, sizeof (struct ifreq));
	strncpy (ifr.ifr_name, nm_device_get_iface (NM_DEVICE (self)), IFNAMSIZ);
	ifr.ifr_data = (char *) &edata;

	if (ioctl (fd, SIOCETHTOOL, &ifr) == -1)
		goto out;

	speed = edata.speed != G_MAXUINT16 ? edata.speed : 0;

out:
	close (fd);
	return speed;
}

static void
real_update_hw_address (NMDevice *dev)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (dev);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	struct ifreq req;
	int ret, fd;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_warning ("couldn't open control socket.");
		return;
	}

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), IFNAMSIZ);
	ret = ioctl (fd, SIOCGIFHWADDR, &req);
	if (ret) {
		nm_warning ("%s: (%s) error getting hardware address: %d",
		            __func__, nm_device_get_iface (dev), errno);
		goto out;
	}

	if (memcmp (&priv->hw_addr, &req.ifr_hwaddr.sa_data, sizeof (struct ether_addr))) {
		memcpy (&priv->hw_addr, &req.ifr_hwaddr.sa_data, sizeof (struct ether_addr));
		g_object_notify (G_OBJECT (dev), NM_DEVICE_ETHERNET_HW_ADDRESS);
	}

out:
	close (fd);
}

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	NMDeviceEthernet *	self = NM_DEVICE_ETHERNET (dev);
	guint32		caps = NM_DEVICE_CAP_NONE;

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
		if (nm_device_ethernet_get_carrier (self) == FALSE)
			interrupt = TRUE;
	}
	return interrupt;
}

static gboolean
real_can_activate (NMDevice *dev)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (dev);

	/* Can't do anything if there isn't a carrier */
	if (!nm_device_ethernet_get_carrier (self))
		return FALSE;

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
		gboolean is_pppoe = FALSE;

		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);

		if (!strcmp (s_con->type, NM_SETTING_PPPOE_SETTING_NAME))
			is_pppoe = TRUE;

		if (!is_pppoe && strcmp (s_con->type, NM_SETTING_WIRED_SETTING_NAME))
			continue;
		if (!s_con->autoconnect)
			continue;

		s_wired = (NMSettingWired *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED);
		/* Wired setting optional for PPPoE */
		if (!is_pppoe && !s_wired)
			continue;

		if (s_wired) {
			if (   s_wired->mac_address
				&& memcmp (s_wired->mac_address->data, priv->hw_addr.ether_addr_octet, ETH_ALEN))
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

	if (nm_device_get_state (dev) != NM_DEVICE_STATE_NEED_AUTH)
		return;

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
			nm_ppp_manager_update_secrets (priv->ppp_manager,
			                               nm_device_get_iface (dev),
			                               s_pppoe->username ? s_pppoe->username : "",
			                               s_pppoe->password ? s_pppoe->password : "",
			                               NULL);
		}
		return;
	}

	/* Only caller could be ourselves for 802.1x */
	g_return_if_fail (caller == SECRETS_CALLER_ETHERNET);

	for (iter = updated_settings; iter; iter = g_slist_next (iter)) {
		const char *setting_name = (const char *) iter->data;

		if (!strcmp (setting_name, NM_SETTING_802_1X_SETTING_NAME)) {
			valid = TRUE;
		} else {
			nm_warning ("Ignoring updated secrets for setting '%s'.", setting_name);
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

	if (priv->link_timeout_id) {
		g_source_remove (priv->link_timeout_id);
		priv->link_timeout_id = 0;
	}
}

static void
remove_supplicant_interface_connection_error_handler (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	if (priv->supplicant.iface_error_id != 0) {
		g_signal_handler_disconnect (priv->supplicant.iface, priv->supplicant.iface_error_id);
		priv->supplicant.iface_error_id = 0;
	}
}

static void
supplicant_interface_clean (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	remove_supplicant_timeouts (self);
	remove_supplicant_interface_connection_error_handler (self);

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

	priv->link_timeout_id = 0;

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

	nm_info ("Activation (%s/wired): disconnected during authentication,"
	         " asking for new key.", nm_device_get_iface (dev));
	supplicant_interface_clean (self);

	nm_device_state_changed (dev, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
	nm_act_request_request_connection_secrets (req, setting_name, TRUE,
	                                           SECRETS_CALLER_ETHERNET, NULL, NULL);

	return FALSE;

time_out:
	nm_info ("%s: link timed out.", nm_device_get_iface (dev));
	nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);

	return FALSE;
}

struct state_cb_data {
	NMDeviceEthernet *self;
	guint32 new_state;
	guint32 old_state;
};

static gboolean
schedule_state_handler (NMDeviceEthernet *self,
                        GSourceFunc handler,
                        guint32 new_state,
                        guint32 old_state)
{
	struct state_cb_data * cb_data;

	if (new_state == old_state)
		return TRUE;

	cb_data = g_slice_new0 (struct state_cb_data);
	cb_data->self = self;
	cb_data->new_state = new_state;
	cb_data->old_state = old_state;

	g_idle_add (handler, cb_data);

	return TRUE;
}

static gboolean
supplicant_mgr_state_cb_handler (gpointer user_data)
{
	struct state_cb_data *info = (struct state_cb_data *) user_data;
	NMDevice *device = NM_DEVICE (info->self);

	/* If the supplicant went away, release the supplicant interface */
	if (info->new_state == NM_SUPPLICANT_MANAGER_STATE_DOWN) {
		supplicant_interface_clean (info->self);

		if (nm_device_get_state (device) > NM_DEVICE_STATE_UNAVAILABLE) {
			nm_device_state_changed (device, NM_DEVICE_STATE_UNAVAILABLE,
			                         NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		}
	}

	g_slice_free (struct state_cb_data, info);

	return FALSE;
}

static void
supplicant_mgr_state_cb (NMSupplicantInterface * iface,
                         guint32 new_state,
                         guint32 old_state,
                         gpointer user_data)
{
	nm_info ("(%s) supplicant manager is now in state %d (from %d).",
		    nm_device_get_iface (NM_DEVICE (user_data)),
		    new_state,
		    old_state);

	schedule_state_handler (NM_DEVICE_ETHERNET (user_data),
					    supplicant_mgr_state_cb_handler,
					    new_state, old_state);
}

static NMSupplicantConfig *
build_supplicant_config (NMDeviceEthernet *self)
{
	DBusGProxy *proxy;
	const char *con_path;
	NMSupplicantConfig *config = NULL;
	NMSetting8021x *security;
	NMConnection *connection;

	connection = nm_act_request_get_connection (nm_device_get_act_request (NM_DEVICE (self)));
	proxy = g_object_get_data (G_OBJECT (connection), "dbus-proxy");
	con_path = dbus_g_proxy_get_path (proxy);

	config = nm_supplicant_config_new ();
	if (!config)
		return NULL;

	security = NM_SETTING_802_1X (nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X));
	if (!nm_supplicant_config_add_setting_8021x (config, security, con_path, TRUE)) {
		nm_warning ("Couldn't add 802.1X security setting to supplicant config.");
		g_object_unref (config);
		config = NULL;
	}

	return config;
}

static gboolean
supplicant_iface_state_cb_handler (gpointer user_data)
{
	struct state_cb_data *info = (struct state_cb_data *) user_data;
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (info->self);
	NMDevice *device = NM_DEVICE (info->self);

	if (info->new_state == NM_SUPPLICANT_INTERFACE_STATE_READY) {
		NMSupplicantConfig *config;
		const char *iface;
		gboolean success = FALSE;

		iface = nm_device_get_iface (device);
		config = build_supplicant_config (info->self);
		if (config) {
			success = nm_supplicant_interface_set_config (priv->supplicant.iface, config);
			g_object_unref (config);

			if (!success)
				nm_warning ("Activation (%s/wired): couldn't send security "
						  "configuration to the supplicant.", iface);
		} else
			nm_warning ("Activation (%s/wired): couldn't build security configuration.", iface);

		if (!success)
			nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED);
	} else if (info->new_state == NM_SUPPLICANT_INTERFACE_STATE_DOWN) {
		NMDeviceState state = nm_device_get_state (device);

		supplicant_interface_clean (info->self);

		if (nm_device_is_activating (device) || state == NM_DEVICE_STATE_ACTIVATED)
			nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
	}

	g_slice_free (struct state_cb_data, info);

	return FALSE;
}

static void
supplicant_iface_state_cb (NMSupplicantInterface * iface,
                           guint32 new_state,
                           guint32 old_state,
                           gpointer user_data)
{

	nm_info ("(%s) supplicant interface is now in state %d (from %d).",
		    nm_device_get_iface (NM_DEVICE (user_data)),
		    new_state,
		    old_state);

	schedule_state_handler (NM_DEVICE_ETHERNET (user_data),
	                        supplicant_iface_state_cb_handler,
	                        new_state,
	                        old_state);
}

static gboolean
supplicant_iface_connection_state_cb_handler (gpointer user_data)
{
	struct state_cb_data *info = (struct state_cb_data *) user_data;
	NMDevice *dev = NM_DEVICE (info->self);

	if (info->new_state == NM_SUPPLICANT_INTERFACE_CON_STATE_COMPLETED) {
		remove_supplicant_interface_connection_error_handler (info->self);
		remove_supplicant_timeouts (info->self);

		/* If this is the initial association during device activation,
		 * schedule the next activation stage.
		 */
		if (nm_device_get_state (dev) == NM_DEVICE_STATE_CONFIG) {
			nm_info ("Activation (%s/wired) Stage 2 of 5 (Device Configure) successful.",
				    nm_device_get_iface (dev));
			nm_device_activate_schedule_stage3_ip_config_start (dev);
		}
	} else if (info->new_state == NM_SUPPLICANT_INTERFACE_CON_STATE_DISCONNECTED) {
		if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED || nm_device_is_activating (dev)) {
			NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (info->self);

			/* Start the link timeout so we allow some time for reauthentication */
			if (!priv->link_timeout_id)
				priv->link_timeout_id = g_timeout_add (15000, link_timeout_cb, dev);
		}
	}

	g_slice_free (struct state_cb_data, info);

	return FALSE;
}

static void
supplicant_iface_connection_state_cb (NMSupplicantInterface * iface,
                                      guint32 new_state,
                                      guint32 old_state,
                                      gpointer user_data)
{
	nm_info ("(%s) Supplicant interface state change: %d -> %d",
	         nm_device_get_iface (NM_DEVICE (user_data)), old_state, new_state);

	schedule_state_handler (NM_DEVICE_ETHERNET (user_data),
	                        supplicant_iface_connection_state_cb_handler,
	                        new_state,
	                        old_state);
}

static gboolean
supplicant_iface_connection_error_cb_handler (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);

	supplicant_interface_clean (self);
	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED);

	return FALSE;
}

static void
supplicant_iface_connection_error_cb (NMSupplicantInterface *iface,
                                      const char *name,
                                      const char *message,
                                      gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	nm_info ("Activation (%s/wired): association request to the supplicant failed: %s - %s",
	         nm_device_get_iface (device), name, message);

	g_idle_add (supplicant_iface_connection_error_cb_handler, device);
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
		nm_act_request_request_connection_secrets (req, setting_name, get_new,
		                                           SECRETS_CALLER_ETHERNET, NULL, NULL);

		g_object_set_data (G_OBJECT (connection), WIRED_SECRETS_TRIES, GUINT_TO_POINTER (++tries));
	} else
		nm_warning ("Cleared secrets, but setting didn't need any secrets.");

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static gboolean
supplicant_connection_timeout_cb (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDevice *device = NM_DEVICE (self);
	NMActRequest *req;
	const char *iface;

	iface = nm_device_get_iface (device);

	/* Authentication failed, encryption key is probably bad */
	nm_info ("Activation (%s/wired): association took too long.", iface);

	supplicant_interface_clean (self);
	req = nm_device_get_act_request (device);
	g_assert (req);

	if (handle_auth_or_fail (self, req, TRUE) == NM_ACT_STAGE_RETURN_POSTPONE)
		nm_info ("Activation (%s/wired): asking for new secrets", iface);
	else
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
		nm_warning ("Couldn't initialize supplicant interface for %s.", iface);
		supplicant_interface_clean (self);

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
	priv->supplicant.con_timeout_id = g_timeout_add (25000, supplicant_connection_timeout_cb, self);

	return TRUE;
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
		nm_warning ("Invalid or missing 802.1X security");
		*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		return ret;
	}

	iface = nm_device_get_iface (NM_DEVICE (self));
	s_connection = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));

	/* If we need secrets, get them */
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		NMActRequest *req = nm_device_get_act_request (NM_DEVICE (self));

		nm_info ("Activation (%s/wired): connection '%s' has security, but secrets are required.",
			    iface, s_connection->id);

		ret = handle_auth_or_fail (self, req, FALSE);
		if (ret != NM_ACT_STAGE_RETURN_POSTPONE)
			*reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
	} else {
		nm_info ("Activation (%s/wired): connection '%s' requires no security. No secrets needed.",
			    iface, s_connection->id);

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
	case NM_PPP_STATUS_NETWORK:
		nm_device_state_changed (device, NM_DEVICE_STATE_IP_CONFIG, NM_DEVICE_STATE_REASON_NONE);
		break;
	case NM_PPP_STATUS_DISCONNECT:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_DISCONNECT);
		break;
	case NM_PPP_STATUS_DEAD:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_FAILED);
		break;
	case NM_PPP_STATUS_AUTHENTICATE:
		nm_device_state_changed (device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);
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

	nm_device_set_ip_iface (device, iface);
	NM_DEVICE_ETHERNET_GET_PRIVATE (device)->pending_ip4_config = g_object_ref (config);
	nm_device_activate_schedule_stage4_ip_config_get (device);
}

static NMActStageReturn
pppoe_stage2_config (NMDeviceEthernet *self, NMDeviceStateReason *reason)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMActRequest *req;
	GError *err = NULL;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_assert (req);

	priv->ppp_manager = nm_ppp_manager_new (nm_device_get_iface (NM_DEVICE (self)));
	if (nm_ppp_manager_start (priv->ppp_manager, req, &err)) {
		g_signal_connect (priv->ppp_manager, "state-changed",
					   G_CALLBACK (ppp_state_changed),
					   self);
		g_signal_connect (priv->ppp_manager, "ip4-config",
					   G_CALLBACK (ppp_ip4_config),
					   self);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		nm_warning ("(%s): PPPoE failed to start: %s",
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
	NMSettingConnection *s_connection;
	NMActStageReturn ret;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	s_connection = NM_SETTING_CONNECTION (device_get_setting (device, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_connection);

	if (!strcmp (s_connection->type, NM_SETTING_WIRED_SETTING_NAME)) {
		NMSetting8021x *security;

		security = (NMSetting8021x *) device_get_setting (device, NM_TYPE_SETTING_802_1X);
		if (security)
			ret = nm_8021x_stage2_config (NM_DEVICE_ETHERNET (device), reason);
		else
			ret = NM_ACT_STAGE_RETURN_SUCCESS;
	} else if (!strcmp (s_connection->type, NM_SETTING_PPPOE_SETTING_NAME))
		ret = pppoe_stage2_config (NM_DEVICE_ETHERNET (device), reason);
	else {
		nm_warning ("Invalid connection type '%s' for ethernet device", s_connection->type);
		*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	return ret;
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

	if (!priv->ppp_manager) {
		/* Regular ethernet connection. */

		/* Chain up to parent */
		ret = NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->act_stage4_get_ip4_config (device, config, reason);

		if (ret == NM_ACT_STAGE_RETURN_SUCCESS) {
			NMConnection *connection;
			NMSettingWired *s_wired;

			connection = nm_act_request_get_connection (nm_device_get_act_request (device));
			g_assert (connection);
			s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
			g_assert (s_wired);

			/* MTU override */
			if (s_wired->mtu)
				nm_ip4_config_set_mtu (*config, s_wired->mtu);
		}
	} else {
		/* PPPoE */
		*config = priv->pending_ip4_config;
		priv->pending_ip4_config = NULL;
		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	}

	return ret;
}

static void
real_deactivate_quickly (NMDevice *device)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);

	nm_device_set_ip_iface (device, NULL);

	if (priv->pending_ip4_config) {
		g_object_unref (priv->pending_ip4_config);
		priv->pending_ip4_config = NULL;
	}

	if (priv->ppp_manager) {
		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;
	}

	supplicant_interface_clean (NM_DEVICE_ETHERNET (device));
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
	gboolean is_pppoe = FALSE;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (   strcmp (s_con->type, NM_SETTING_WIRED_SETTING_NAME)
	    && strcmp (s_con->type, NM_SETTING_PPPOE_SETTING_NAME)) {
		g_set_error (error,
		             NM_ETHERNET_ERROR, NM_ETHERNET_ERROR_CONNECTION_NOT_WIRED,
		             "The connection was not a wired or PPPoE connection.");
		return FALSE;
	}

	if (!strcmp (s_con->type, NM_SETTING_PPPOE_SETTING_NAME))
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
		if (   s_wired->mac_address
			&& memcmp (s_wired->mac_address->data, &(priv->hw_addr.ether_addr_octet), ETH_ALEN)) {
			g_set_error (error,
			             NM_ETHERNET_ERROR, NM_ETHERNET_ERROR_CONNECTION_INCOMPATIBLE,
			             "The connection's MAC address did not match this device.");
			return FALSE;
		}
	}

	// FIXME: check bitrate against device capabilities

	return TRUE;
}

static void
nm_device_ethernet_dispose (GObject *object)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (object);
	NMNetlinkMonitor *monitor;

	if (priv->dispose_has_run) {
		G_OBJECT_CLASS (nm_device_ethernet_parent_class)->dispose (object);
		return;
	}

	priv->dispose_has_run = TRUE;

	monitor = nm_netlink_monitor_get ();
	if (priv->link_connected_id) {
		g_signal_handler_disconnect (monitor, priv->link_connected_id);
		priv->link_connected_id = 0;
	}
	if (priv->link_disconnected_id) {
		g_signal_handler_disconnect (monitor, priv->link_disconnected_id);
		priv->link_disconnected_id = 0;
	}
	g_object_unref (monitor);

	if (priv->state_to_disconnected_id) {
		g_source_remove (priv->state_to_disconnected_id);
		priv->state_to_disconnected_id = 0;
	}

	G_OBJECT_CLASS (nm_device_ethernet_parent_class)->dispose (object);
}

static void
nm_device_ethernet_finalize (GObject *object)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (object);

	g_free (priv->carrier_file_path);

	G_OBJECT_CLASS (nm_device_ethernet_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMDeviceEthernet *device = NM_DEVICE_ETHERNET (object);
	struct ether_addr hw_addr;

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		nm_device_ethernet_get_address (device, &hw_addr);
		g_value_take_string (value, nm_ether_ntop (&hw_addr));
		break;
	case PROP_SPEED:
		g_value_set_uint (value, nm_device_ethernet_get_speed (device));
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_ethernet_get_carrier (device));
		break;
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
	object_class->dispose = nm_device_ethernet_dispose;
	object_class->get_property = get_property;
	object_class->finalize = nm_device_ethernet_finalize;

	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->hw_is_up = real_hw_is_up;
	parent_class->hw_bring_up = real_hw_bring_up;
	parent_class->hw_take_down = real_hw_take_down;
	parent_class->is_up = real_is_up;
	parent_class->bring_up = real_bring_up;
	parent_class->take_down = real_take_down;
	parent_class->can_interrupt_activation = real_can_interrupt_activation;
	parent_class->update_hw_address = real_update_hw_address;
	parent_class->get_best_auto_connection = real_get_best_auto_connection;
	parent_class->can_activate = real_can_activate;
	parent_class->connection_secrets_updated = real_connection_secrets_updated;
	parent_class->check_connection_compatible = real_check_connection_compatible;

	parent_class->act_stage2_config = real_act_stage2_config;
	parent_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	parent_class->deactivate_quickly = real_deactivate_quickly;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_ETHERNET_HW_ADDRESS,
							  "MAC Address",
							  "Hardware MAC address",
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
		nm_warning ("couldn't open control socket.");
		return FALSE;
	}

	memset (&ifr, 0, sizeof (struct ifreq));
	strncpy (ifr.ifr_name, nm_device_get_iface (NM_DEVICE (self)), IFNAMSIZ);

	edata.cmd = ETHTOOL_GLINK;
	ifr.ifr_data = (char *) &edata;

	if (ioctl (fd, SIOCETHTOOL, &ifr) == -1)
		goto out;

	supports_ethtool = TRUE;

out:
	close (fd);
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
	const char *	iface;

	g_return_val_if_fail (fd >= 0, -1);
	g_return_val_if_fail (ifr != NULL, -1);

	iface = nm_device_get_iface (NM_DEVICE (self));

	mii = (struct mii_ioctl_data *) &ifr->ifr_ifru;
	mii->reg_num = location;

	if (ioctl (fd, SIOCGMIIREG, ifr) >= 0)
		val = mii->val_out;

	return val;
}

static gboolean
supports_mii_carrier_detect (NMDeviceEthernet *self)
{
	int err, fd, bmsr;
	struct ifreq ifr;
	gboolean supports_mii = FALSE;

	g_return_val_if_fail (self != NULL, FALSE);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_warning ("couldn't open control socket.");
		return 0;
	}

	memset (&ifr, 0, sizeof (struct ifreq));
	strncpy (ifr.ifr_name, nm_device_get_iface (NM_DEVICE (self)), IFNAMSIZ);

	err = ioctl (fd, SIOCGMIIPHY, &ifr);
	if (err < 0)
		goto out;

	/* If we can read the BMSR register, we assume that the card supports MII link detection */
	bmsr = mdio_read (self, fd, &ifr, MII_BMSR);
	supports_mii = (bmsr != -1) ? TRUE : FALSE;

out:
	close (fd);
	return supports_mii;	
}
