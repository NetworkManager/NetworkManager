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
 * Copyright (C) 2005 - 2012 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "config.h"
#include <glib.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_infiniband.h>
#include <netinet/ether.h>
#include <linux/sockios.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "nm-device-wired.h"
#include "nm-device-private.h"
#include "nm-dhcp-manager.h"
#include "nm-logging.h"
#include "nm-netlink-monitor.h"
#include "nm-netlink-utils.h"
#include "nm-system.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"


G_DEFINE_TYPE (NMDeviceWired, nm_device_wired, NM_TYPE_DEVICE)

#define NM_DEVICE_WIRED_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_WIRED, NMDeviceWiredPrivate))

#define NM_DEVICE_WIRED_LOG_LEVEL(dev) ((nm_device_get_device_type (dev) == NM_DEVICE_TYPE_INFINIBAND) ? LOGD_INFINIBAND : LOGD_ETHER)

typedef struct {
	guint8              hw_addr[NM_UTILS_HWADDR_LEN_MAX];         /* Currently set MAC address */
	guint               hw_addr_type;
	guint               hw_addr_len;
	gboolean            carrier;
	guint32             speed;

	NMNetlinkMonitor *  monitor;
	gulong              link_connected_id;
	gulong              link_disconnected_id;
	guint               carrier_action_defer_id;

} NMDeviceWiredPrivate;


/* Returns speed in Mb/s */
static guint32
ethtool_get_speed (NMDeviceWired *self)
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
set_speed (NMDeviceWired *self, const guint32 speed)
{
	NMDeviceWiredPrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_WIRED_GET_PRIVATE (self);
	if (priv->speed == speed)
		return;

	priv->speed = speed;
	g_object_notify (G_OBJECT (self), "speed");

	nm_log_dbg (LOGD_HW | NM_DEVICE_WIRED_LOG_LEVEL (NM_DEVICE (self)),
	             "(%s): speed is now %d Mb/s",
	             nm_device_get_iface (NM_DEVICE (self)),
	             speed);
}

static void
carrier_action_defer_clear (NMDeviceWired *self)
{
	NMDeviceWiredPrivate *priv = NM_DEVICE_WIRED_GET_PRIVATE (self);

	if (priv->carrier_action_defer_id) {
		g_source_remove (priv->carrier_action_defer_id);
		priv->carrier_action_defer_id = 0;
	}
}

static gboolean
carrier_action_defer_cb (gpointer user_data)
{
	NMDeviceWired *self = NM_DEVICE_WIRED (user_data);
	NMDeviceWiredPrivate *priv = NM_DEVICE_WIRED_GET_PRIVATE (self);
	NMDeviceState state;

	priv->carrier_action_defer_id = 0;

	state = nm_device_get_state (NM_DEVICE (self));
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
set_carrier (NMDeviceWired *self,
             const gboolean carrier,
             const gboolean defer_action)
{
	NMDeviceWiredPrivate *priv;
	NMDeviceState state;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_WIRED_GET_PRIVATE (self);
	if (priv->carrier == carrier)
		return;

	/* Clear any previous deferred action */
	carrier_action_defer_clear (self);

	priv->carrier = carrier;
	g_object_notify (G_OBJECT (self), "carrier");

	state = nm_device_get_state (NM_DEVICE (self));
	nm_log_info (LOGD_HW | NM_DEVICE_WIRED_LOG_LEVEL (NM_DEVICE (self)),
	             "(%s): carrier now %s (device state %d%s)",
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
	NMDeviceWired *self = NM_DEVICE_WIRED (device);
	guint32 caps;

	/* Make sure signal is for us */
	if (idx == nm_device_get_ifindex (device)) {
		/* Ignore spurious netlink messages */
		caps = nm_device_get_capabilities (device);
		if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT))
			return;

		set_carrier (self, TRUE, FALSE);
		set_speed (self, ethtool_get_speed (self));
	}
}

static void
carrier_off (NMNetlinkMonitor *monitor,
             int idx,
             gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceWired *self = NM_DEVICE_WIRED (device);
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
		state = nm_device_get_state (device);
		if (state > NM_DEVICE_STATE_DISCONNECTED)
			defer = TRUE;

		set_carrier (self, FALSE, defer);
	}
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDeviceWiredPrivate *priv;
	NMDevice *self;
	guint32 caps;

	object = G_OBJECT_CLASS (nm_device_wired_parent_class)->constructor (type,
	                                                                     n_construct_params,
	                                                                     construct_params);
	if (!object)
		return NULL;

	self = NM_DEVICE (object);
	priv = NM_DEVICE_WIRED_GET_PRIVATE (self);

	nm_log_dbg (LOGD_HW | NM_DEVICE_WIRED_LOG_LEVEL (NM_DEVICE (self)),
	            "(%s): kernel ifindex %d",
	            nm_device_get_iface (NM_DEVICE (self)),
	            nm_device_get_ifindex (NM_DEVICE (self)));

	if (nm_device_get_device_type (self) == NM_DEVICE_TYPE_ETHERNET) {
		priv->hw_addr_type = ARPHRD_ETHER;
		priv->hw_addr_len = ETH_ALEN;
	} else if (nm_device_get_device_type (self) == NM_DEVICE_TYPE_INFINIBAND) {
		priv->hw_addr_type = ARPHRD_INFINIBAND;
		priv->hw_addr_len = INFINIBAND_ALEN;
	} else
		g_assert_not_reached ();

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
			nm_log_warn (LOGD_HW | NM_DEVICE_WIRED_LOG_LEVEL (NM_DEVICE (self)),
			             "(%s): couldn't get initial carrier state: (%d) %s",
			             nm_device_get_iface (NM_DEVICE (self)),
			             error ? error->code : -1,
			             (error && error->message) ? error->message : "unknown");
			g_clear_error (&error);
		} else
			priv->carrier = !!(ifflags & IFF_LOWER_UP);

		nm_log_info (LOGD_HW | NM_DEVICE_WIRED_LOG_LEVEL (NM_DEVICE (self)),
		             "(%s): carrier is %s",
		             nm_device_get_iface (NM_DEVICE (self)),
		             priv->carrier ? "ON" : "OFF");

		/* Request link state again just in case an error occurred getting the
		 * initial link state.
		 */
		nm_netlink_monitor_request_status (priv->monitor);
	} else {
		nm_log_info (LOGD_HW | NM_DEVICE_WIRED_LOG_LEVEL (NM_DEVICE (self)),
		             "(%s): driver '%s' does not support carrier detection.",
		             nm_device_get_iface (self),
		             nm_device_get_driver (self));
		priv->carrier = TRUE;
	}

	return object;
}

static void
nm_device_wired_init (NMDeviceWired * self)
{
}

static gboolean
real_hw_is_up (NMDevice *device)
{
	return nm_system_iface_is_up (nm_device_get_ip_ifindex (device));
}

static gboolean
real_hw_bring_up (NMDevice *dev, gboolean *no_firmware)
{
	return nm_system_iface_set_up (nm_device_get_ip_ifindex (dev), TRUE, no_firmware);
}

static void
real_hw_take_down (NMDevice *dev)
{
	nm_system_iface_set_up (nm_device_get_ip_ifindex (dev), FALSE, NULL);
}

static void
real_update_hw_address (NMDevice *dev)
{
	NMDeviceWired *self = NM_DEVICE_WIRED (dev);
	NMDeviceWiredPrivate *priv = NM_DEVICE_WIRED_GET_PRIVATE (self);
	struct rtnl_link *rtnl;
	struct nl_addr *addr;

	rtnl = nm_netlink_index_to_rtnl_link (nm_device_get_ip_ifindex (dev));
	if (!rtnl) {
		nm_log_err (LOGD_HW | NM_DEVICE_WIRED_LOG_LEVEL (dev),
		            "(%s) failed to read hardware address (error %d)",
		            nm_device_get_iface (dev), errno);
		return;
	}

	addr = rtnl_link_get_addr (rtnl);
	if (!addr) {
		nm_log_err (LOGD_HW | NM_DEVICE_WIRED_LOG_LEVEL (dev),
		            "(%s) no hardware address?",
		            nm_device_get_iface (dev));
		rtnl_link_put (rtnl);
		return;
	}

	if (nl_addr_get_len (addr) != priv->hw_addr_len) {
		nm_log_err (LOGD_HW | NM_DEVICE_WIRED_LOG_LEVEL (dev),
		            "(%s) hardware address is wrong length (expected %d got %d)",
		            nm_device_get_iface (dev),
		            priv->hw_addr_len, nl_addr_get_len (addr));
	} else {
		memcpy (&priv->hw_addr, nl_addr_get_binary_addr (addr),
				priv->hw_addr_len);
	}

	rtnl_link_put (rtnl);
}

static gboolean
real_can_interrupt_activation (NMDevice *dev)
{
	NMDeviceWired *self = NM_DEVICE_WIRED (dev);
	gboolean interrupt = FALSE;

	/* Devices that support carrier detect can interrupt activation
	 * if the link becomes inactive.
	 */
	if (nm_device_get_capabilities (dev) & NM_DEVICE_CAP_CARRIER_DETECT) {
		if (NM_DEVICE_WIRED_GET_PRIVATE (self)->carrier == FALSE)
			interrupt = TRUE;
	}
	return interrupt;
}

static gboolean
real_is_available (NMDevice *dev)
{
	NMDeviceWired *self = NM_DEVICE_WIRED (dev);

	/* Can't do anything if there isn't a carrier */
	if (!NM_DEVICE_WIRED_GET_PRIVATE (self)->carrier)
		return FALSE;

	return TRUE;
}

static gboolean
ip4_match_config (NMDevice *self, NMConnection *connection)
{
	NMSettingIP4Config *s_ip4;
	int i, num;
	GSList *leases, *iter;
	NMDHCPManager *dhcp_mgr;
	const char *method;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4)
		return FALSE;

	/* Get any saved leases that apply to this connection */
	dhcp_mgr = nm_dhcp_manager_get ();
	leases = nm_dhcp_manager_get_lease_config (dhcp_mgr,
	                                           nm_device_get_iface (self),
	                                           nm_connection_get_uuid (connection));
	g_object_unref (dhcp_mgr);

	method = nm_setting_ip4_config_get_method (s_ip4);
	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		gboolean found = FALSE;

		/* Find at least one lease's address on the device */
		for (iter = leases; iter; iter = g_slist_next (iter)) {
			NMIP4Config *ip4_config = iter->data;
			NMIP4Address *addr = nm_ip4_config_get_address (ip4_config, 0);
			struct in_addr tmp = { .s_addr = nm_ip4_address_get_address (addr) };

			if (addr && nm_netlink_find_address (nm_device_get_ip_ifindex (self),
			                                     AF_INET,
			                                     &tmp,
			                                     nm_ip4_address_get_prefix (addr))) {
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

	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
		// FIXME: Enforce no ipv4 addresses?
		return TRUE;
	}

	/* 'shared' and 'link-local' aren't supported methods because 'shared'
	 * requires too much iptables and dnsmasq state to be reclaimed, and
	 * avahi-autoipd isn't smart enough to allow the link-local address to be
	 * determined at any point other than when it was first assigned.
	 */
	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL))
		return FALSE;

	/* Everything below for static addressing */

	/* Find all IP4 addresses of this connection on the device */
	num = nm_setting_ip4_config_get_num_addresses (s_ip4);
	for (i = 0; i < num; i++) {
		NMIP4Address *addr = nm_setting_ip4_config_get_address (s_ip4, i);
		struct in_addr tmp = { .s_addr = nm_ip4_address_get_address (addr) };

		if (!nm_netlink_find_address (nm_device_get_ip_ifindex (self),
		                              AF_INET,
		                              &tmp,
		                              nm_ip4_address_get_prefix (addr)))
			return FALSE;
	}

	/* Success; all the connection's static IP addresses are assigned to the device */
	return TRUE;
}

static NMConnection *
connection_match_config (NMDevice *self, const GSList *connections)
{
	const GSList *iter;

	for (iter = connections; iter; iter = iter->next) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		if (!ip4_match_config (self, candidate))
			continue;

		return candidate;
	}

	return NULL;
}

static void
dispose (GObject *object)
{
	NMDeviceWired *self = NM_DEVICE_WIRED (object);
	NMDeviceWiredPrivate *priv = NM_DEVICE_WIRED_GET_PRIVATE (self);

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

	G_OBJECT_CLASS (nm_device_wired_parent_class)->dispose (object);
}

static void
nm_device_wired_class_init (NMDeviceWiredClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceWiredPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;

	parent_class->hw_is_up = real_hw_is_up;
	parent_class->hw_bring_up = real_hw_bring_up;
	parent_class->hw_take_down = real_hw_take_down;
	parent_class->can_interrupt_activation = real_can_interrupt_activation;
	parent_class->update_hw_address = real_update_hw_address;
	parent_class->is_available = real_is_available;
	parent_class->connection_match_config = connection_match_config;
}

/**
 * nm_device_wired_get_hwaddr:
 * @dev: an #NMDeviceWired
 *
 * Get a device's hardware address
 *
 * Return value: (transfer none): @dev's hardware address
 */
guint8 *
nm_device_wired_get_hwaddr (NMDeviceWired *dev)
{
	NMDeviceWiredPrivate *priv;

	g_return_val_if_fail (dev != NULL, NULL);

	priv = NM_DEVICE_WIRED_GET_PRIVATE (dev);
	return priv->hw_addr;
}

/**
 * nm_device_wired_get_hwaddr_type:
 * @dev: an #NMDeviceWired
 *
 * Get the type of a device's hardware address
 *
 * Return value: the type of @dev's hardware address
 */
int
nm_device_wired_get_hwaddr_type (NMDeviceWired *dev)
{
	NMDeviceWiredPrivate *priv;

	g_return_val_if_fail (dev != NULL, -1);

	priv = NM_DEVICE_WIRED_GET_PRIVATE (dev);
	return priv->hw_addr_type;
}

/**
 * nm_device_wired_get_carrier:
 * @dev: an #NMDeviceWired
 *
 * Get @dev's carrier status
 *
 * Return value: @dev's carrier
 */
gboolean
nm_device_wired_get_carrier (NMDeviceWired *dev)
{
	NMDeviceWiredPrivate *priv;

	g_return_val_if_fail (dev != NULL, FALSE);

	priv = NM_DEVICE_WIRED_GET_PRIVATE (dev);
	return priv->carrier;
}

/**
 * nm_device_wired_get_speed:
 * @dev: an #NMDeviceWired
 *
 * Get @dev's speed
 *
 * Return value: @dev's speed in Mb/s
 */
guint32
nm_device_wired_get_speed (NMDeviceWired *dev)
{
	NMDeviceWiredPrivate *priv;

	g_return_val_if_fail (dev != NULL, 0);

	priv = NM_DEVICE_WIRED_GET_PRIVATE (dev);
	return priv->speed;
}
