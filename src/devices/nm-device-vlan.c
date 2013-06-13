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
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-enum-types.h"
#include "nm-system.h"
#include "nm-dbus-manager.h"
#include "nm-platform.h"

#include "nm-device-vlan-glue.h"


G_DEFINE_TYPE (NMDeviceVlan, nm_device_vlan, NM_TYPE_DEVICE)

#define NM_DEVICE_VLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_VLAN, NMDeviceVlanPrivate))

#define NM_VLAN_ERROR (nm_vlan_error_quark ())

typedef struct {
	gboolean disposed;

	NMDevice *parent;
	guint parent_state_id;

	guint vlan_id;
} NMDeviceVlanPrivate;

enum {
	PROP_0,
	PROP_VLAN_ID,

	LAST_PROP
};

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
get_generic_capabilities (NMDevice *dev)
{
	/* We assume VLAN interfaces always support carrier detect */
	return NM_DEVICE_CAP_CARRIER_DETECT;
}

static gboolean
bring_up (NMDevice *dev, gboolean *no_firmware)
{
	gboolean success = FALSE;
	guint i = 20;

	while (i-- > 0 && !success) {
		success = NM_DEVICE_CLASS (nm_device_vlan_parent_class)->bring_up (dev, no_firmware);
		g_usleep (50);
	}

	return success;
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
check_connection_compatible (NMDevice *device,
                             NMConnection *connection,
                             GError **error)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (device);
	NMSettingVlan *s_vlan;
	const char *parent, *iface = NULL;

	if (!NM_DEVICE_CLASS (nm_device_vlan_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

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
		if (!match_parent (NM_DEVICE_VLAN (device), parent, error))
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
		if (g_strcmp0 (nm_device_get_ip_iface (device), iface) != 0) {
			g_set_error (error, NM_VLAN_ERROR, NM_VLAN_ERROR_CONNECTION_INVALID,
					     "The VLAN connection virtual interface name did not match.");
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
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
			/* FIXME: put hw_addr into the connection in the appropriate
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
match_l2_config (NMDevice *device, NMConnection *connection)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (device);
	NMSettingVlan *s_vlan;
	gboolean fail_if_no_hwaddr = FALSE;
	const guint8 *hw_addr;
	guint hw_addr_len;

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	if (   !nm_setting_vlan_get_parent (s_vlan)
	    && !nm_setting_vlan_get_interface_name (s_vlan)) {
		/* If there's no parent and no interface name given, then the only way
		 * we have to identify the VLAN interface the connection matches is
		 * a hardware-specific setting's hardware address property, so we want
		 * to fail the match below if we there is none.
		 */
		fail_if_no_hwaddr = TRUE;
	}

	/* MAC address check; we ask the parent to check our own MAC address,
	 * because only the parent knows what kind of NMSetting the MAC
	 * address will be in.  The VLAN device shouldn't have to know what kind
	 * of interface the parent is.
	 */
	hw_addr = nm_device_get_hw_address (device, &hw_addr_len);
	if (!nm_device_hwaddr_matches (priv->parent, connection, hw_addr, hw_addr_len, fail_if_no_hwaddr))
		return FALSE;

	/* FIXME: any more L2 checks? */
	return TRUE;
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

	/* We'll react to our own carrier state notifications. Ignore the parent's. */
	if (reason == NM_DEVICE_STATE_REASON_CARRIER)
		return;

	if (new_state < NM_DEVICE_STATE_DISCONNECTED) {
		/* If the parent becomes unavailable or unmanaged so does the VLAN */
		nm_device_state_changed (NM_DEVICE (self), new_state, reason);
	} else if (   new_state == NM_DEVICE_STATE_DISCONNECTED
	           && old_state < NM_DEVICE_STATE_DISCONNECTED) {
		/* Mark VLAN interface as available/disconnected when the parent
		 * becomes available as a result of becoming initialized.
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

		itype = nm_platform_link_get_type (ifindex);
		if (itype != NM_LINK_TYPE_VLAN) {
			nm_log_err (LOGD_VLAN, "(%s): failed to get VLAN interface type.", iface);
			g_object_unref (device);
			return NULL;
		}

		if (!nm_platform_vlan_get_info (ifindex, &parent_ifindex, &vlan_id)) {
			nm_log_warn (LOGD_VLAN, "(%s): failed to get VLAN interface info.", iface);
			g_object_unref (device);
			return NULL;
		}

		if (   parent_ifindex < 0
		    || parent_ifindex != nm_device_get_ip_ifindex (parent)
		    || vlan_id < 0) {
			nm_log_warn (LOGD_VLAN, "(%s): VLAN parent ifindex (%d) or VLAN ID (%d) invalid.",
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

	switch (prop_id) {
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

	g_signal_handler_disconnect (priv->parent, priv->parent_state_id);
	g_object_unref (priv->parent);

	G_OBJECT_CLASS (nm_device_vlan_parent_class)->dispose (object);
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

	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->bring_up = bring_up;

	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->complete_connection = complete_connection;
	parent_class->match_l2_config = match_l2_config;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_VLAN_ID,
		 g_param_spec_uint (NM_DEVICE_VLAN_ID,
		                    "VLAN ID",
		                    "VLAN ID",
		                    0, 4095, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_device_vlan_object_info);

	dbus_g_error_domain_register (NM_VLAN_ERROR, NULL, NM_TYPE_VLAN_ERROR);
}
