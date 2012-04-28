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
			nm_device_queue_state (NM_DEVICE (self), NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_CARRIER);
	} else if (state >= NM_DEVICE_STATE_DISCONNECTED) {
		if (!priv->carrier)
			nm_device_queue_state (NM_DEVICE (self), NM_DEVICE_STATE_UNAVAILABLE, NM_DEVICE_STATE_REASON_CARRIER);
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
	guint32 caps;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_WIRED_GET_PRIVATE (self);
	if (priv->carrier == carrier)
		return;

	/* Clear any previous deferred action */
	carrier_action_defer_clear (self);

	/* Warn if we try to set carrier down on a device that
	 * doesn't support carrier detect.  These devices assume
	 * the carrier is always up.
	 */
	caps = nm_device_get_capabilities (NM_DEVICE (self));
	g_return_if_fail (caps & NM_DEVICE_CAP_CARRIER_DETECT);

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
		caps = nm_device_get_capabilities (device);
		g_return_if_fail (caps & NM_DEVICE_CAP_CARRIER_DETECT);

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

		caps = nm_device_get_capabilities (device);
		g_return_if_fail (caps & NM_DEVICE_CAP_CARRIER_DETECT);

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

static gboolean
get_carrier_sync (NMDeviceWired *self)
{
	NMDeviceWiredPrivate *priv = NM_DEVICE_WIRED_GET_PRIVATE (self);
	GError *error = NULL;
	guint32 ifflags = 0;

	/* Get initial link state */
	if (!nm_netlink_monitor_get_flags_sync (priv->monitor,
	                                        nm_device_get_ip_ifindex (NM_DEVICE (self)),
	                                        &ifflags,
	                                        &error)) {
		nm_log_warn (LOGD_HW | NM_DEVICE_WIRED_LOG_LEVEL (NM_DEVICE (self)),
		             "(%s): couldn't get carrier state: (%d) %s",
		             nm_device_get_ip_iface (NM_DEVICE (self)),
		             error ? error->code : -1,
		             (error && error->message) ? error->message : "unknown");
		g_clear_error (&error);
	}

	return !!(ifflags & IFF_LOWER_UP);
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
	} else if (nm_device_get_device_type (self) == NM_DEVICE_TYPE_BOND) {
		/* We may not know the hardware address type until a slave is added */
		priv->hw_addr_type = ARPHRD_ETHER;
		priv->hw_addr_len = ETH_ALEN;
	} else
		g_assert_not_reached ();

	caps = nm_device_get_capabilities (self);
	if (caps & NM_DEVICE_CAP_CARRIER_DETECT) {
		/* Only listen to netlink for cards that support carrier detect */
		priv->monitor = nm_netlink_monitor_get ();

		priv->link_connected_id = g_signal_connect (priv->monitor, "carrier-on",
		                                            G_CALLBACK (carrier_on),
		                                            self);
		priv->link_disconnected_id = g_signal_connect (priv->monitor, "carrier-off",
		                                               G_CALLBACK (carrier_off),
		                                               self);

		priv->carrier = get_carrier_sync (NM_DEVICE_WIRED (self));

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
	gboolean success, carrier;
	guint32 caps;

	success = nm_system_iface_set_up (nm_device_get_ip_ifindex (dev), TRUE, no_firmware);
	if (success) {
		caps = nm_device_get_capabilities (dev);
		if (caps & NM_DEVICE_CAP_CARRIER_DETECT) {
			carrier = get_carrier_sync (NM_DEVICE_WIRED (dev));
			set_carrier (NM_DEVICE_WIRED (dev), carrier, carrier ? FALSE : TRUE);
		}
	}
	return success;
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

static NMConnection *
connection_match_config (NMDevice *self, const GSList *connections)
{
	const GSList *iter;

	for (iter = connections; iter; iter = iter->next) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		if (!nm_device_match_ip_config (self, candidate))
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
 * Returns: (transfer none): @dev's hardware address
 */
const guint8 *
nm_device_wired_get_hwaddr (NMDeviceWired *dev)
{
	NMDeviceWiredPrivate *priv;

	g_return_val_if_fail (dev != NULL, NULL);

	priv = NM_DEVICE_WIRED_GET_PRIVATE (dev);
	return priv->hw_addr;
}

/**
 * nm_device_wired_set_hwaddr:
 * @dev: an #NMDeviceWired
 * @addr: the new hardware address, @addrlen bytes in length
 * @addrlen: the length in bytes of @addr
 *
 * Sets the device's hardware address.
 */
void
nm_device_wired_set_hwaddr (NMDeviceWired *dev,
                            const guint8 *addr,
                            guint addrlen)
{
	NMDeviceWiredPrivate *priv;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (addr != NULL);

	priv = NM_DEVICE_WIRED_GET_PRIVATE (dev);
	g_return_if_fail (addrlen == priv->hw_addr_len);

	memcpy (priv->hw_addr, addr, priv->hw_addr_len);
}

/**
 * nm_device_wired_get_hwaddr_type:
 * @dev: an #NMDeviceWired
 *
 * Get the type of a device's hardware address
 *
 * Returns: the type of @dev's hardware address
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
