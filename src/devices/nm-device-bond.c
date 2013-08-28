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

#include "gsystem-local-alloc.h"
#include "nm-device-bond.h"
#include "nm-logging.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-platform.h"
#include "nm-dbus-glib-types.h"
#include "nm-dbus-manager.h"
#include "nm-enum-types.h"

#include "nm-device-bond-glue.h"


G_DEFINE_TYPE (NMDeviceBond, nm_device_bond, NM_TYPE_DEVICE)

#define NM_DEVICE_BOND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_BOND, NMDeviceBondPrivate))

#define NM_BOND_ERROR (nm_bond_error_quark ())

typedef struct {
	int dummy;
} NMDeviceBondPrivate;

enum {
	PROP_0,
	PROP_SLAVES,

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

static guint32
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_CARRIER_DETECT;
}

static gboolean
is_available (NMDevice *dev)
{
	if (NM_DEVICE_GET_CLASS (dev)->is_up)
		return NM_DEVICE_GET_CLASS (dev)->is_up (dev);
	return FALSE;
}

static gboolean
check_connection_compatible (NMDevice *device,
                             NMConnection *connection,
                             GError **error)
{
	const char *iface;
	NMSettingBond *s_bond;

	if (!NM_DEVICE_CLASS (nm_device_bond_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

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

static gboolean
complete_connection (NMDevice *device,
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
		if (!nm_platform_link_exists (name)) {
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
match_l2_config (NMDevice *self, NMConnection *connection)
{
	/* FIXME */
	return TRUE;
}

/******************************************************************/

typedef struct {
	const char *name;
	const char *default_value;
} Option;

static const Option master_options[] = {
	{ "mode", "balance-rr" },
	{ "arp_interval", "0" },
	{ "miimon", "0" },

	{ "ad_select", "stable" },
	{ "arp_validate", "none" },
	{ "downdelay", "0" },
	{ "fail_over_mac", "none" },
	{ "lacp_rate", "slow" },
	{ "min_links", "0" },
	{ "num_grat_arp", "1" },
	{ "num_unsol_na", "1" },
	{ "primary", "" },
	{ "primary_reselect", "always" },
	{ "resend_igmp", "1" },
	{ "updelay", "0" },
	{ "use_carrier", "1" },
	{ "xmit_hash_policy", "layer2" },
	{ NULL, NULL }
};

static gboolean
option_valid_for_nm_setting (NMSettingBond *s_bond, const Option *option)
{
	const char **valid_opts = nm_setting_bond_get_valid_options (s_bond);

	for (; *valid_opts; valid_opts++)
		if (!strcmp (option->name, *valid_opts))
			return TRUE;

	return FALSE;
}

static void
remove_bonding_entries (NMDevice *device, const char *option)
{
	int ifindex = nm_device_get_ifindex (device);
	const char *ifname = nm_device_get_iface (device);
	gs_free char *value = nm_platform_master_get_option (ifindex, option);
	char **entries, **entry;
	char cmd[20];

	g_return_if_fail (value);

	entries = g_strsplit (value, " ", -1);
	for (entry = entries; *entry; entry++) {
		snprintf (cmd, sizeof (cmd), "-%s", g_strstrip (*entry));
		if (!nm_platform_master_set_option (ifindex, option, cmd))
			nm_log_warn (LOGD_HW, "(%s): failed to remove entry '%s' from '%s'",
			             ifname, *entry, option);
	}
	g_strfreev (entries);
}

static gboolean
apply_bonding_config (NMDevice *device, NMSettingBond *s_bond)
{
	int ifindex = nm_device_get_ifindex (device);
	const char *ifname = nm_device_get_iface (device);
	static const Option *option;
	const char *value;

	g_return_val_if_fail (ifindex, FALSE);

	/* Remove old slaves and arp_ip_targets */
	remove_bonding_entries (device, "arp_ip_target");
	remove_bonding_entries (device, "slaves");

	/* Apply config/defaults */
	for (option = master_options; option->name; option++) {
		gs_free char *old_value = NULL;
		char *space;

		value = NULL;
		if (option_valid_for_nm_setting (s_bond, option))
			value = nm_setting_bond_get_option_by_name (s_bond, option->name);
		if (!value)
			value = option->default_value;

		old_value = nm_platform_master_get_option (ifindex, option->name);
		/* FIXME: This could be handled in nm-platform. */
		space = strchr (old_value, ' ');
		if (space)
			*space = '\0';

		if (g_strcmp0 (value, old_value)) {
			if (!nm_platform_master_set_option (ifindex, option->name, value))
				nm_log_warn (LOGD_HW, "(%s): failed to set bonding attribute "
				             "'%s' to '%s'", ifname, option->name, value);
		}
	}

	/* Handle arp_ip_target */
	value = nm_setting_bond_get_option_by_name (s_bond, "arp_ip_target");
	if (value) {
		char **addresses, **address;

		addresses = g_strsplit (value, ",", -1);
		for (address = addresses; *address; address++) {
			char cmd[20];

			snprintf (cmd, sizeof (cmd), "+%s", g_strstrip (*address));
			if (!nm_platform_master_set_option (ifindex, "arp_ip_target", cmd)){
				nm_log_warn (LOGD_HW, "(%s): failed to add arp_ip_target '%s'",
				             ifname, *address);
			}
		}
		g_strfreev (addresses);
	}

	return TRUE;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;
	NMConnection *connection;
	NMSettingBond *s_bond;
	gboolean no_firmware = FALSE;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ret = NM_DEVICE_CLASS (nm_device_bond_parent_class)->act_stage1_prepare (dev, reason);
	if (ret == NM_ACT_STAGE_RETURN_SUCCESS) {
		connection = nm_device_get_connection (dev);
		g_assert (connection);
		s_bond = nm_connection_get_setting_bond (connection);
		g_assert (s_bond);

		/* Interface must be down to set bond options */
		nm_device_take_down (dev, TRUE);

		if (!apply_bonding_config (dev, s_bond))
			ret = NM_ACT_STAGE_RETURN_FAILURE;

		nm_device_bring_up (dev, TRUE, &no_firmware);
	}
	return ret;
}

static gboolean
enslave_slave (NMDevice *device, NMDevice *slave, NMConnection *connection)
{
	gboolean success, no_firmware = FALSE;
	const char *iface = nm_device_get_ip_iface (device);
	const char *slave_iface = nm_device_get_ip_iface (slave);

	nm_device_take_down (slave, TRUE);

	success = nm_platform_link_enslave (nm_device_get_ip_ifindex (device),
	                                    nm_device_get_ip_ifindex (slave));

	nm_device_bring_up (slave, TRUE, &no_firmware);

	if (success) {
		nm_log_info (LOGD_BOND, "(%s): enslaved bond slave %s", iface, slave_iface);
		g_object_notify (G_OBJECT (device), "slaves");
	}

	return success;
}

static gboolean
release_slave (NMDevice *device, NMDevice *slave)
{
	gboolean success, no_firmware = FALSE;

	success = nm_platform_link_release (nm_device_get_ip_ifindex (device),
	                                    nm_device_get_ip_ifindex (slave));

	nm_log_info (LOGD_BOND, "(%s): released bond slave %s (success %d)",
	             nm_device_get_ip_iface (device),
	             nm_device_get_ip_iface (slave),
	             success);
	g_object_notify (G_OBJECT (device), "slaves");

	/* Kernel bonding code "closes" the slave when releasing it, (which clears
	 * IFF_UP), so we must bring it back up here to ensure carrier changes and
	 * other state is noticed by the now-released slave.
	 */
	if (!nm_device_bring_up (slave, TRUE, &no_firmware)) {
		nm_log_warn (LOGD_BOND, "(%s): released bond slave could not be brought up.",
		             nm_device_get_iface (slave));
	}

	return success;
}

/******************************************************************/

NMDevice *
nm_device_bond_new (const char *iface)
{
	g_return_val_if_fail (iface != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_BOND,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, "bonding",
	                                  NM_DEVICE_TYPE_DESC, "Bond",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_BOND,
	                                  NM_DEVICE_IS_MASTER, TRUE,
	                                  NULL);
}

static void
constructed (GObject *object)
{
	G_OBJECT_CLASS (nm_device_bond_parent_class)->constructed (object);

	nm_log_dbg (LOGD_HW | LOGD_BOND, "(%s): kernel ifindex %d",
	            nm_device_get_iface (NM_DEVICE (object)),
	            nm_device_get_ifindex (NM_DEVICE (object)));
}

static void
nm_device_bond_init (NMDeviceBond * self)
{
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	GPtrArray *slaves;
	GSList *list, *iter;

	switch (prop_id) {
		break;
	case PROP_SLAVES:
		slaves = g_ptr_array_new ();
		list = nm_device_master_get_slaves (NM_DEVICE (object));
		for (iter = list; iter; iter = iter->next)
			g_ptr_array_add (slaves, g_strdup (nm_device_get_path (NM_DEVICE (iter->data))));
		g_slist_free (list);
		g_value_take_boxed (value, slaves);
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

	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->is_available = is_available;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->complete_connection = complete_connection;

	parent_class->match_l2_config = match_l2_config;

	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->enslave_slave = enslave_slave;
	parent_class->release_slave = release_slave;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_SLAVES,
		 g_param_spec_boxed (NM_DEVICE_BOND_SLAVES,
		                     "Slaves",
		                     "Slaves",
		                     DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
		                     G_PARAM_READABLE));

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_device_bond_object_info);

	dbus_g_error_domain_register (NM_BOND_ERROR, NULL, NM_TYPE_BOND_ERROR);
}
