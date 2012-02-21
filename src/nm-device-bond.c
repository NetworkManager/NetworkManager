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

#include <netinet/ether.h>

#include "nm-device-bond.h"
#include "nm-logging.h"
#include "nm-properties-changed-signal.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-netlink-monitor.h"
#include "nm-enum-types.h"

#include "nm-device-bond-glue.h"


G_DEFINE_TYPE (NMDeviceBond, nm_device_bond, NM_TYPE_DEVICE_WIRED)

#define NM_DEVICE_BOND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_BOND, NMDeviceBondPrivate))

#define NM_BOND_ERROR (nm_bond_error_quark ())

typedef struct {
	int dummy;
} NMDeviceBondPrivate;

enum {
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_CARRIER,

	LAST_PROP
};

/******************************************************************/

static GQuark
nm_bond_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-bond-error");
	return quark;
}

/******************************************************************/

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	if (new_state == NM_DEVICE_STATE_UNAVAILABLE) {
		/* Use NM_DEVICE_STATE_REASON_CARRIER to make sure num retries is reset */
		nm_device_queue_state (device, NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_CARRIER);
	}
}

static void
real_update_hw_address (NMDevice *dev)
{
	const guint8 *hw_addr;
	guint8 old_addr[NM_UTILS_HWADDR_LEN_MAX];
	int addrtype, addrlen;

	addrtype = nm_device_wired_get_hwaddr_type (NM_DEVICE_WIRED (dev));
	g_assert (addrtype >= 0);
	addrlen = nm_utils_hwaddr_len (addrtype);
	g_assert (addrlen > 0);

	hw_addr = nm_device_wired_get_hwaddr (NM_DEVICE_WIRED (dev));
	memcpy (old_addr, hw_addr, addrlen);

	NM_DEVICE_CLASS (nm_device_bond_parent_class)->update_hw_address (dev);

	hw_addr = nm_device_wired_get_hwaddr (NM_DEVICE_WIRED (dev));
	if (memcmp (old_addr, hw_addr, addrlen))
		g_object_notify (G_OBJECT (dev), NM_DEVICE_BOND_HW_ADDRESS);
}

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_NM_SUPPORTED;
}

static gboolean
match_bond_connection (NMDevice *device, NMConnection *connection, GError **error)
{
	const char *iface;
	NMSettingBond *s_bond;

	s_bond = nm_connection_get_setting_bond (connection);
	if (!s_bond || !nm_connection_is_type (connection, NM_SETTING_BOND_SETTING_NAME)) {
		g_set_error (error, NM_BOND_ERROR, NM_BOND_ERROR_CONNECTION_NOT_BOND,
		             "The connection was not a bond connection.");
		return FALSE;
	}

	/* Bond connections must specify the virtual interface name */
	iface = nm_connection_get_virtual_iface_name (connection);
	if (!iface || strcmp (nm_device_get_iface (device), iface)) {
		g_set_error (error, NM_BOND_ERROR, NM_BOND_ERROR_CONNECTION_NOT_BOND,
		             "The bond connection virtual interface name did not match.");
		return FALSE;
	}

	/* FIXME: match bond properties like mode, etc? */

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
		    && match_bond_connection (dev, connection, NULL))
			return connection;
	}
	return NULL;
}

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	return match_bond_connection (device, connection, error);
}

static gboolean
real_complete_connection (NMDevice *device,
                          NMConnection *connection,
                          const char *specific_object,
                          const GSList *existing_connections,
                          GError **error)
{
	NMSettingBond *s_bond, *tmp;
	guint32 i = 0;
	char *name;
	const GSList *iter;
	gboolean found;

	nm_utils_complete_generic (connection,
	                           NM_SETTING_BOND_SETTING_NAME,
	                           existing_connections,
	                           _("Bond connection %d"),
	                           NULL,
	                           TRUE);

	s_bond = nm_connection_get_setting_bond (connection);
	if (!s_bond) {
		s_bond = (NMSettingBond *) nm_setting_bond_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bond));
	}

	/* Grab the first name that doesn't exist in either our connections
	 * or a device on the system.
	 */
	while (i < 500 && !nm_setting_bond_get_interface_name (s_bond)) {
		name = g_strdup_printf ("bond%u", i);
		/* check interface names */
		if (nm_netlink_iface_to_index (name) < 0) {
			/* check existing bond connections */
			for (iter = existing_connections, found = FALSE; iter; iter = g_slist_next (iter)) {
				NMConnection *candidate = iter->data;

				tmp = nm_connection_get_setting_bond (candidate);
				if (tmp && nm_connection_is_type (candidate, NM_SETTING_BOND_SETTING_NAME)) {
					if (g_strcmp0 (nm_setting_bond_get_interface_name (tmp), name) == 0) {
						found = TRUE;
						break;
					}
				}
			}

			if (!found)
				g_object_set (G_OBJECT (s_bond), NM_SETTING_BOND_INTERFACE_NAME, name, NULL);
		}

		g_free (name);
		i++;
	}

	return TRUE;
}

static gboolean
spec_match_list (NMDevice *device, const GSList *specs)
{
	char *hwaddr;
	gboolean matched;

	hwaddr = nm_utils_hwaddr_ntoa (nm_device_wired_get_hwaddr (NM_DEVICE_WIRED (device)), ARPHRD_ETHER);
	matched = nm_match_spec_hwaddr (specs, hwaddr);
	g_free (hwaddr);

	return matched;
}

static gboolean
bond_match_config (NMDevice *self, NMConnection *connection)
{
	NMSettingBond *s_bond;
	const char *ifname;

	s_bond = nm_connection_get_setting_bond (connection);
	if (!s_bond)
		return FALSE;

	/* Interface name */
	ifname = nm_setting_bond_get_interface_name (s_bond);
	if (g_strcmp0 (ifname, nm_device_get_ip_iface (self)) != 0)
		return FALSE;

	/* MAC address check */
	if (!nm_device_hwaddr_matches (self, connection, FALSE))
		return FALSE;

	return TRUE;
}

static NMConnection *
connection_match_config (NMDevice *self, const GSList *connections)
{
	const GSList *iter;
	GSList *bond_matches;
	NMConnection *match;

	/* First narrow @connections down to those that match in their
	 * NMSettingBond configuration.
	 */
	bond_matches = NULL;
	for (iter = connections; iter; iter = iter->next) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		if (!nm_connection_is_type (candidate, NM_SETTING_BOND_SETTING_NAME))
			continue;
		if (!bond_match_config (self, candidate))
			continue;

		bond_matches = g_slist_prepend (bond_matches, candidate);
	}

	/* Now pass those to the super method, which will check IP config */
	bond_matches = g_slist_reverse (bond_matches);
	match = NM_DEVICE_CLASS (nm_device_bond_parent_class)->connection_match_config (self, bond_matches);
	g_slist_free (bond_matches);

	return match;
}

/******************************************************************/

NMDevice *
nm_device_bond_new (const char *udi, const char *iface)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_BOND,
	                                  NM_DEVICE_UDI, udi,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, "bonding",
	                                  NM_DEVICE_TYPE_DESC, "Bond",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_BOND,
	                                  NULL);
}

static void
constructed (GObject *object)
{
	G_OBJECT_CLASS (nm_device_bond_parent_class)->constructed (object);

	nm_log_dbg (LOGD_HW | LOGD_DEVICE, "(%s): kernel ifindex %d",
	            nm_device_get_iface (NM_DEVICE (object)),
	            nm_device_get_ifindex (NM_DEVICE (object)));
}

static void
nm_device_bond_init (NMDeviceBond * self)
{
	g_signal_connect (self, "state-changed", G_CALLBACK (device_state_changed), NULL);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	const guint8 *current_addr;

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		current_addr = nm_device_wired_get_hwaddr (NM_DEVICE_WIRED (object));
		g_value_take_string (value, nm_utils_hwaddr_ntoa (current_addr, ARPHRD_ETHER));
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_wired_get_carrier (NM_DEVICE_WIRED (object)));
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
nm_device_bond_class_init (NMDeviceBondClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceBondPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->update_hw_address = real_update_hw_address;
	parent_class->get_best_auto_connection = real_get_best_auto_connection;
	parent_class->check_connection_compatible = real_check_connection_compatible;
	parent_class->complete_connection = real_complete_connection;

	parent_class->spec_match_list = spec_match_list;
	parent_class->connection_match_config = connection_match_config;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_BOND_HW_ADDRESS,
							  "Active MAC Address",
							  "Currently set hardware MAC address",
							  NULL,
							  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_BOND_CARRIER,
							   "Carrier",
							   "Carrier",
							   FALSE,
							   G_PARAM_READABLE));

	/* Signals */
	signals[PROPERTIES_CHANGED] =
		nm_properties_changed_signal_new (object_class,
										  G_STRUCT_OFFSET (NMDeviceBondClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_device_bond_object_info);

	dbus_g_error_domain_register (NM_BOND_ERROR, NULL, NM_TYPE_BOND_ERROR);
}
