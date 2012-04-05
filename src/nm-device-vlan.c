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
 * Copyright 2011 - 2012 Red Hat, Inc.
 */

#include "config.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/ether.h>

#include "nm-device-vlan.h"
#include "nm-logging.h"
#include "nm-properties-changed-signal.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-netlink-monitor.h"
#include "nm-enum-types.h"
#include "nm-system.h"

#include "nm-device-vlan-glue.h"


G_DEFINE_TYPE (NMDeviceVlan, nm_device_vlan, NM_TYPE_DEVICE)

#define NM_DEVICE_VLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_VLAN, NMDeviceVlanPrivate))

#define NM_VLAN_ERROR (nm_vlan_error_quark ())

typedef struct {
	gboolean disposed;

	NMDevice *parent;
	guint parent_state_id;

	guint vlan_id;

	guint8 hw_addr[NM_UTILS_HWADDR_LEN_MAX];
	guint hw_addr_len;

	gboolean          carrier;
	NMNetlinkMonitor *monitor;
	gulong            link_connected_id;
	gulong            link_disconnected_id;
	guint             carrier_action_defer_id;
} NMDeviceVlanPrivate;

enum {
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_CARRIER,
	PROP_VLAN_ID,

	LAST_PROP
};

static void
set_carrier (NMDeviceVlan *self,
             const gboolean carrier,
             const gboolean defer_action);

/******************************************************************/

static GQuark
nm_vlan_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-vlan-error");
	return quark;
}

/******************************************************************/

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	/* We assume VLAN interfaces always support carrier detect */
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_NM_SUPPORTED;
}

static gboolean
get_carrier_sync (NMDeviceVlan *self)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);
	GError *error = NULL;
	guint32 ifflags = 0;

	/* Get initial link state */
	if (!nm_netlink_monitor_get_flags_sync (priv->monitor,
	                                        nm_device_get_ip_ifindex (NM_DEVICE (self)),
	                                        &ifflags,
	                                        &error)) {
		nm_log_warn (LOGD_HW | LOGD_DEVICE,
		             "(%s): couldn't get carrier state: (%d) %s",
		             nm_device_get_ip_iface (NM_DEVICE (self)),
		             error ? error->code : -1,
		             (error && error->message) ? error->message : "unknown");
		g_clear_error (&error);
	}

	return !!(ifflags & IFF_LOWER_UP);
}

static gboolean
real_hw_is_up (NMDevice *device)
{
	return nm_system_iface_is_up (nm_device_get_ip_ifindex (device));
}

static gboolean
real_hw_bring_up (NMDevice *dev, gboolean *no_firmware)
{
	gboolean success = FALSE, carrier;
	guint i = 20;

	while (i-- > 0 && !success) {
		success = nm_system_iface_set_up (nm_device_get_ip_ifindex (dev), TRUE, no_firmware);
		g_usleep (50);
	}

	if (success) {
		/* Block a bit to make sure the carrier comes on; it's delayed a bit
		 * after setting the interface up.
		 */
		i = 20;
		while (i-- > 0) {
			carrier = get_carrier_sync (NM_DEVICE_VLAN (dev));
			set_carrier (NM_DEVICE_VLAN (dev), carrier, carrier ? FALSE : TRUE);
			if (carrier)
				break;
			g_usleep (100);
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
	NMDeviceVlan *self = NM_DEVICE_VLAN (dev);
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);
	struct rtnl_link *rtnl;
	struct nl_addr *addr;

	rtnl = nm_netlink_index_to_rtnl_link (nm_device_get_ip_ifindex (dev));
	if (!rtnl) {
		nm_log_err (LOGD_HW | LOGD_DEVICE,
		            "(%s) failed to read hardware address (error %d)",
		            nm_device_get_iface (dev), errno);
		return;
	}

	addr = rtnl_link_get_addr (rtnl);
	if (!addr) {
		nm_log_err (LOGD_HW | LOGD_DEVICE,
		            "(%s) no hardware address?",
		            nm_device_get_iface (dev));
		goto out;
	}

	if (nl_addr_get_len (addr) > sizeof (priv->hw_addr)) {
		nm_log_err (LOGD_HW | LOGD_DEVICE,
		            "(%s) hardware address is wrong length (got %d max %zd)",
		            nm_device_get_iface (dev),
		            nl_addr_get_len (addr),
		            sizeof (priv->hw_addr));
	} else {
		priv->hw_addr_len = nl_addr_get_len (addr);
		memcpy (&priv->hw_addr, nl_addr_get_binary_addr (addr), priv->hw_addr_len);
		g_object_notify (G_OBJECT (self), NM_DEVICE_VLAN_HW_ADDRESS);
	}

out:
	rtnl_link_put (rtnl);
}

static gboolean
real_can_interrupt_activation (NMDevice *dev)
{
	/* Can interrupt activation if the carrier drops while activating */
	return NM_DEVICE_VLAN_GET_PRIVATE (dev)->carrier ? FALSE : TRUE;
}

static gboolean
real_is_available (NMDevice *dev)
{
	return NM_DEVICE_VLAN_GET_PRIVATE (dev)->carrier ? TRUE : FALSE;
}

/******************************************************************/

static gboolean
match_parent (NMDeviceVlan *self, const char *parent, GError **error)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);

	g_return_val_if_fail (parent != NULL, FALSE);

	if (nm_utils_is_uuid (parent)) {
		NMActRequest *parent_req;
		NMConnection *parent_connection;

		/* If the parent is a UUID, the connection matches if our parent
		 * device has that connection activated.
		 */

		parent_req = nm_device_get_act_request (priv->parent);
		if (!parent_req) {
			g_set_error_literal (error, NM_VLAN_ERROR, NM_VLAN_ERROR_CONNECTION_INVALID,
			                     "Parent interface not active; could not match UUID");
			return FALSE;
		}

		parent_connection = nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (parent_req));
		if (!parent_connection) {
			g_set_error_literal (error, NM_VLAN_ERROR, NM_VLAN_ERROR_CONNECTION_INVALID,
			                     "Parent interface had no connection; could not match UUID");
			return FALSE;
		}
		if (g_strcmp0 (parent, nm_connection_get_uuid (parent_connection)) != 0) {
			g_set_error_literal (error, NM_VLAN_ERROR, NM_VLAN_ERROR_CONNECTION_INVALID,
			                     "Parent interface UUID did not match connection UUID");
			return FALSE;
		}
	} else {
		/* interface name */
		if (g_strcmp0 (parent, nm_device_get_ip_iface (priv->parent)) != 0) {
			g_set_error_literal (error, NM_VLAN_ERROR, NM_VLAN_ERROR_CONNECTION_INVALID,
			                     "Parent interface name did not match connection");
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
match_vlan_connection (NMDeviceVlan *self, NMConnection *connection, GError **error)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);
	NMSettingVlan *s_vlan;
	const char *parent, *iface = NULL;

	s_vlan = nm_connection_get_setting_vlan (connection);
	if (!s_vlan) {
		g_set_error (error, NM_VLAN_ERROR, NM_VLAN_ERROR_CONNECTION_INVALID,
				     "The connection was not a VLAN connection.");
		return FALSE;
	}

	if (nm_setting_vlan_get_id (s_vlan) != priv->vlan_id) {
		g_set_error (error, NM_VLAN_ERROR, NM_VLAN_ERROR_CONNECTION_INVALID,
		             "The connection's VLAN ID did not match the device's VLAN ID.");
		return FALSE;
	}

	/* Check parent interface; could be an interface name or a UUID */
	parent = nm_setting_vlan_get_parent (s_vlan);
	if (parent) {
		if (!match_parent (self, parent, error))
			return FALSE;
	} else {
		/* Parent could be a MAC address in a hardware-specific setting */
		if (!nm_device_hwaddr_matches (priv->parent, connection, NULL, 0, TRUE)) {
			g_set_error (error, NM_VLAN_ERROR, NM_VLAN_ERROR_CONNECTION_INVALID,
					     "Failed to match the VLAN parent interface via hardware address.");
			return FALSE;
		}
	}

	/* Ensure the interface name matches.  If not specified we assume a match
	 * since both the parent interface and the VLAN ID matched by the time we
	 * get here.
	 */
	iface = nm_connection_get_virtual_iface_name (connection);
	if (iface) {
		if (g_strcmp0 (nm_device_get_ip_iface (NM_DEVICE (self)), iface) != 0) {
			g_set_error (error, NM_VLAN_ERROR, NM_VLAN_ERROR_CONNECTION_INVALID,
					     "The VLAN connection virtual interface name did not match.");
			return FALSE;
		}
	}

	return TRUE;
}

static NMConnection *
real_get_best_auto_connection (NMDevice *dev,
                               GSList *connections,
                               char **specific_object)
{
	GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;

		s_con = nm_connection_get_setting_connection (connection);
		g_assert (s_con);
		if (   nm_setting_connection_get_autoconnect (s_con)
		    && match_vlan_connection (NM_DEVICE_VLAN (dev), connection, NULL))
			return connection;
	}
	return NULL;
}

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	return match_vlan_connection (NM_DEVICE_VLAN (device), connection, error);
}

static gboolean
real_complete_connection (NMDevice *device,
                          NMConnection *connection,
                          const char *specific_object,
                          const GSList *existing_connections,
                          GError **error)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (device);
	NMSettingVlan *s_vlan;

	nm_utils_complete_generic (connection,
	                           NM_SETTING_VLAN_SETTING_NAME,
	                           existing_connections,
	                           _("VLAN connection %d"),
	                           NULL,
	                           TRUE);

	s_vlan = nm_connection_get_setting_vlan (connection);
	if (!s_vlan) {
		g_set_error_literal (error, NM_VLAN_ERROR, NM_VLAN_ERROR_CONNECTION_INVALID,
		                     "A 'vlan' setting is required.");
		return FALSE;
	}

	/* If there's no VLAN interface, no parent, and no hardware address in the
	 * settings, then there's not enough information to complete the setting.
	 */
	if (!nm_setting_vlan_get_parent (s_vlan)) {
		if (!nm_device_hwaddr_matches (priv->parent, connection, NULL, 0, TRUE)) {
			/* FIXME: put priv->hw_addr into the connection in the appropriate
			 * hardware-specific setting.
			 */
			g_set_error_literal (error, NM_VLAN_ERROR, NM_VLAN_ERROR_CONNECTION_INVALID,
				                 "The 'vlan' setting had no interface name, parent, or hardware address.");
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
spec_match_list (NMDevice *device, const GSList *specs)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (device);
	char *hwaddr;
	gboolean matched;
	int itype = nm_utils_hwaddr_type (priv->hw_addr_len);

	hwaddr = nm_utils_hwaddr_ntoa (priv->hw_addr, itype);
	matched = nm_match_spec_hwaddr (specs, hwaddr);
	g_free (hwaddr);

	return matched;
}

static gboolean
vlan_match_config (NMDevice *device, NMConnection *connection)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (device);
	NMSettingVlan *s_vlan;
	const char *ifname, *parent;
	gboolean fail_if_no_hwaddr = FALSE;

	s_vlan = nm_connection_get_setting_vlan (connection);
	if (!s_vlan)
		return FALSE;

	/* Interface name */
	ifname = nm_setting_vlan_get_interface_name (s_vlan);
	if (g_strcmp0 (ifname, nm_device_get_ip_iface (device)) != 0)
		return FALSE;

	if (nm_setting_vlan_get_id (s_vlan) != priv->vlan_id)
		return FALSE;

	parent = nm_setting_vlan_get_parent (s_vlan);
	if (parent) {
		if (!match_parent (NM_DEVICE_VLAN (device), parent, NULL))
			return FALSE;
	} else {
		/* If there's no parent and no interface name given, then the only way
		 * we have to identify the VLAN interface the connection matches is
		 * a hardware-specific setting's hardware address property, so we want
		 * to fail the match below if we there is none.
		 */
		 if (ifname == NULL)
		 	fail_if_no_hwaddr = TRUE;
	}

	/* MAC address check; we ask the parent to check our own MAC address,
	 * because only the parent knows what kind of NMSetting the MAC
	 * address will be in.  The VLAN device shouldn't have to know what kind
	 * of interface the parent is.
	 */
	if (!nm_device_hwaddr_matches (priv->parent, connection, priv->hw_addr, priv->hw_addr_len, fail_if_no_hwaddr))
		return FALSE;

	return TRUE;
}

static NMConnection *
connection_match_config (NMDevice *self, const GSList *connections)
{
	const GSList *iter;

	/* First narrow @connections down to those that match in their
	 * NMSettingVlan configuration.
	 */
	for (iter = connections; iter; iter = iter->next) {
		NMConnection *candidate = iter->data;

		if (!nm_connection_is_type (candidate, NM_SETTING_VLAN_SETTING_NAME))
			continue;
		if (!vlan_match_config (self, candidate))
			continue;
		if (!nm_device_match_ip_config (self, candidate))
			continue;

		return candidate;
	}
	return NULL;
}

/******************************************************************/

static void
carrier_action_defer_clear (NMDeviceVlan *self)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);

	if (priv->carrier_action_defer_id) {
		g_source_remove (priv->carrier_action_defer_id);
		priv->carrier_action_defer_id = 0;
	}
}

static gboolean
carrier_action_defer_cb (gpointer user_data)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (user_data);
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);
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
set_carrier (NMDeviceVlan *self,
             const gboolean carrier,
             const gboolean defer_action)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);
	NMDeviceState state;

	if (priv->carrier == carrier)
		return;

	/* Clear any previous deferred action */
	carrier_action_defer_clear (self);

	priv->carrier = carrier;
	g_object_notify (G_OBJECT (self), NM_DEVICE_VLAN_CARRIER);

	state = nm_device_get_state (NM_DEVICE (self));
	nm_log_info (LOGD_HW | LOGD_DEVICE,
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
carrier_on (NMNetlinkMonitor *monitor, int idx, NMDevice *device)
{
	/* Make sure signal is for us */
	if (idx == nm_device_get_ifindex (device))
		set_carrier (NM_DEVICE_VLAN (device), TRUE, FALSE);
}

static void
carrier_off (NMNetlinkMonitor *monitor, int idx, NMDevice *device)
{
	NMDeviceState state;
	gboolean defer = FALSE;

	/* Make sure signal is for us */
	if (idx == nm_device_get_ifindex (device)) {
		/* Defer carrier-off event actions while connected by a few seconds
		 * so that tripping over a cable, power-cycling a switch, or breaking
		 * off the RJ45 locking tab isn't so catastrophic.
		 */
		state = nm_device_get_state (device);
		if (state > NM_DEVICE_STATE_DISCONNECTED)
			defer = TRUE;

		set_carrier (NM_DEVICE_VLAN (device), FALSE, defer);
	}
}

static void
carrier_watch_init (NMDeviceVlan *self)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);

	priv->monitor = nm_netlink_monitor_get ();
	priv->link_connected_id = g_signal_connect (priv->monitor, "carrier-on",
	                                            G_CALLBACK (carrier_on),
	                                            self);
	priv->link_disconnected_id = g_signal_connect (priv->monitor, "carrier-off",
	                                               G_CALLBACK (carrier_off),
	                                               self);

	priv->carrier = get_carrier_sync (NM_DEVICE_VLAN (self));

	nm_log_info (LOGD_HW | LOGD_DEVICE, "(%s): carrier is %s",
	             nm_device_get_iface (NM_DEVICE (self)),
	             priv->carrier ? "ON" : "OFF");

	/* Request link state again just in case an error occurred getting the
	 * initial link state.
	 */
	nm_netlink_monitor_request_status (priv->monitor);
}

/******************************************************************/

static void
parent_state_changed (NMDevice *parent,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (user_data);

	if (new_state < NM_DEVICE_STATE_DISCONNECTED) {
		/* If the parent becomes unavailable or unmanaged so does the VLAN */
		nm_device_state_changed (NM_DEVICE (self), new_state, reason);
	} else if (   new_state == NM_DEVICE_STATE_DISCONNECTED
	           && old_state < NM_DEVICE_STATE_DISCONNECTED) {
		/* Mark VLAN interface as available/disconnected when the parent
		 * becomes available as a result of carrier changes or becoming
		 * initialized.
		 */
		nm_device_state_changed (NM_DEVICE (self), new_state, reason);
	}
}

/******************************************************************/

NMDevice *
nm_device_vlan_new (const char *udi, const char *iface, NMDevice *parent)
{
	NMDevice *device;

	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (parent != NULL, NULL);

	device = (NMDevice *) g_object_new (NM_TYPE_DEVICE_VLAN,
	                                    NM_DEVICE_UDI, udi,
	                                    NM_DEVICE_IFACE, iface,
	                                    NM_DEVICE_DRIVER, "8021q",
	                                    NM_DEVICE_TYPE_DESC, "VLAN",
	                                    NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_VLAN,
	                                    NULL);
	if (device) {
		NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (device);
		int ifindex = nm_device_get_ifindex (device);
		int parent_ifindex = -1, itype;
		int vlan_id;

		itype = nm_system_get_iface_type (ifindex, iface);
		g_assert (itype == NM_IFACE_TYPE_VLAN);

		if (!nm_system_get_iface_vlan_info (ifindex, &parent_ifindex, &vlan_id)) {
			nm_log_warn (LOGD_DEVICE, "(%s): failed to get VLAN interface info.", iface);
			g_object_unref (device);
			return NULL;
		}

		if (   parent_ifindex < 0
		    || parent_ifindex != nm_device_get_ip_ifindex (parent)
		    || vlan_id < 0) {
			nm_log_warn (LOGD_DEVICE, "(%s): VLAN parent ifindex (%d) or VLAN ID (%d) invalid.",
			             iface, parent_ifindex, priv->vlan_id);
			g_object_unref (device);
			return NULL;
		}

		priv->vlan_id = vlan_id;
		priv->parent = g_object_ref (parent);
		priv->parent_state_id = g_signal_connect (priv->parent,
		                                          "state-changed",
		                                          G_CALLBACK (parent_state_changed),
		                                          device);

		carrier_watch_init (NM_DEVICE_VLAN (device));

		nm_log_dbg (LOGD_HW | LOGD_ETHER, "(%s): kernel ifindex %d", iface, ifindex);
		nm_log_info (LOGD_HW | LOGD_ETHER, "(%s): VLAN ID %d with parent %s",
		             iface, priv->vlan_id, nm_device_get_iface (parent));
	}

	return device;
}

static void
nm_device_vlan_init (NMDeviceVlan * self)
{
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (object);
	char *hwaddr;

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		hwaddr = nm_utils_hwaddr_ntoa (priv->hw_addr, nm_utils_hwaddr_type (priv->hw_addr_len));
		g_value_take_string (value, hwaddr);
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, priv->carrier);
		break;
	case PROP_VLAN_ID:
		g_value_set_uint (value, priv->vlan_id);
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
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_VLAN_ID:
		priv->vlan_id = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (object);
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_vlan_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	if (priv->link_connected_id)
		g_signal_handler_disconnect (priv->monitor, priv->link_connected_id);
	if (priv->link_disconnected_id)
		g_signal_handler_disconnect (priv->monitor, priv->link_disconnected_id);
	carrier_action_defer_clear (self);

	g_object_unref (priv->monitor);

	g_signal_handler_disconnect (priv->parent, priv->parent_state_id);
	g_object_unref (priv->parent);
}

static void
nm_device_vlan_class_init (NMDeviceVlanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceVlanPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;

	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->update_hw_address = real_update_hw_address;
	parent_class->hw_is_up = real_hw_is_up;
	parent_class->hw_bring_up = real_hw_bring_up;
	parent_class->hw_take_down = real_hw_take_down;
	parent_class->can_interrupt_activation = real_can_interrupt_activation;
	parent_class->is_available = real_is_available;

	parent_class->get_best_auto_connection = real_get_best_auto_connection;
	parent_class->check_connection_compatible = real_check_connection_compatible;
	parent_class->complete_connection = real_complete_connection;
	parent_class->spec_match_list = spec_match_list;
	parent_class->connection_match_config = connection_match_config;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_VLAN_HW_ADDRESS,
							  "Active MAC Address",
							  "Currently set hardware MAC address",
							  NULL,
							  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_VLAN_CARRIER,
							   "Carrier",
							   "Carrier",
							   FALSE,
							   G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_VLAN_ID,
		 g_param_spec_uint (NM_DEVICE_VLAN_ID,
		                    "VLAN ID",
		                    "VLAN ID",
		                    0, 4095, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* Signals */
	signals[PROPERTIES_CHANGED] =
		nm_properties_changed_signal_new (object_class,
										  G_STRUCT_OFFSET (NMDeviceVlanClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_device_vlan_object_info);

	dbus_g_error_domain_register (NM_VLAN_ERROR, NULL, NM_TYPE_VLAN_ERROR);
}
