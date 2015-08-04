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

#include <errno.h>
#include <stdlib.h>

#include "nm-default.h"
#include "nm-device-bond.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-platform.h"
#include "nm-dbus-glib-types.h"
#include "nm-enum-types.h"
#include "nm-device-factory.h"
#include "nm-core-internal.h"
#include "nm-ip4-config.h"

#include "nm-device-bond-glue.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceBond);

G_DEFINE_TYPE (NMDeviceBond, nm_device_bond, NM_TYPE_DEVICE)

#define NM_DEVICE_BOND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_BOND, NMDeviceBondPrivate))

typedef struct {
	int dummy;
} NMDeviceBondPrivate;

enum {
	PROP_0,
	PROP_SLAVES,

	LAST_PROP
};

/******************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
is_available (NMDevice *dev, NMDeviceCheckDevAvailableFlags flags)
{
	return TRUE;
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object)
{
	/* Connections are always available because the carrier state is determined
	 * by the slave carrier states, not the bonds's state.
	 */
	return TRUE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	const char *iface;
	NMSettingBond *s_bond;

	if (!NM_DEVICE_CLASS (nm_device_bond_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_bond = nm_connection_get_setting_bond (connection);
	if (!s_bond || !nm_connection_is_type (connection, NM_SETTING_BOND_SETTING_NAME))
		return FALSE;

	/* Bond connections must specify the virtual interface name */
	iface = nm_connection_get_interface_name (connection);
	if (!iface || strcmp (nm_device_get_iface (device), iface))
		return FALSE;

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
	NMSettingBond *s_bond;

	nm_utils_complete_generic (connection,
	                           NM_SETTING_BOND_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("Bond connection"),
	                           "bond",
	                           TRUE);

	s_bond = nm_connection_get_setting_bond (connection);
	if (!s_bond) {
		s_bond = (NMSettingBond *) nm_setting_bond_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bond));
	}

	return TRUE;
}

/******************************************************************/

static gboolean
set_bond_attr (NMDevice *device, const char *attr, const char *value)
{
	NMDeviceBond *self = NM_DEVICE_BOND (device);
	gboolean ret;
	int ifindex = nm_device_get_ifindex (device);

	ret = nm_platform_master_set_option (NM_PLATFORM_GET, ifindex, attr, value);
	if (!ret)
		_LOGW (LOGD_HW, "failed to set bonding attribute '%s' to '%s'", attr, value);
	return ret;
}

/* Ignore certain bond options if they are zero (off/disabled) */
static gboolean
ignore_if_zero (const char *option, const char *value)
{
	if (strcmp (option, "arp_interval") &&
	    strcmp (option, "miimon") &&
	    strcmp (option, "downdelay") &&
	    strcmp (option, "updelay"))
		return FALSE;

	return g_strcmp0 (value, "0") == 0 ? TRUE : FALSE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMSettingBond *s_bond = nm_connection_get_setting_bond (connection);
	int ifindex = nm_device_get_ifindex (device);
	const char **options;

	if (!s_bond) {
		s_bond = (NMSettingBond *) nm_setting_bond_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_bond);
	}

	/* Read bond options from sysfs and update the Bond setting to match */
	options = nm_setting_bond_get_valid_options (s_bond);
	while (options && *options) {
		gs_free char *value = nm_platform_master_get_option (NM_PLATFORM_GET, ifindex, *options);
		const char *defvalue = nm_setting_bond_get_option_default (s_bond, *options);

		if (value && !ignore_if_zero (*options, value) && (g_strcmp0 (value, defvalue) != 0)) {
			/* Replace " " with "," for arp_ip_targets from the kernel */
			if (strcmp (*options, "arp_ip_target") == 0) {
				char *p = value;

				while (p && *p) {
					if (*p == ' ')
						*p = ',';
					p++;
				}
			}

			nm_setting_bond_add_option (s_bond, *options, value);
		}
		options++;
	}
}

static gboolean
master_update_slave_connection (NMDevice *self,
                                NMDevice *slave,
                                NMConnection *connection,
                                GError **error)
{
	g_object_set (nm_connection_get_setting_connection (connection),
	              NM_SETTING_CONNECTION_MASTER, nm_device_get_iface (self),
	              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BOND_SETTING_NAME,
	              NULL);
	return TRUE;
}

static void
set_arp_targets (NMDevice *device,
                 const char *value,
                 const char *delim,
                 const char *prefix)
{
	char **items, **iter, *tmp;

	if (!value || !*value)
		return;

	items = g_strsplit_set (value, delim, 0);
	for (iter = items; iter && *iter; iter++) {
		if (*iter[0]) {
			tmp = g_strdup_printf ("%s%s", prefix, *iter);
			set_bond_attr (device, "arp_ip_target", tmp);
			g_free (tmp);
		}
	}
	g_strfreev (items);
}

static void
set_simple_option (NMDevice *device,
                   const char *attr,
                   NMSettingBond *s_bond,
                   const char *opt)
{
	const char *value;

	value = nm_setting_bond_get_option_by_name (s_bond, opt);
	if (!value)
		value = nm_setting_bond_get_option_default (s_bond, opt);
	set_bond_attr (device, attr, value);
}

static NMActStageReturn
apply_bonding_config (NMDevice *device)
{
	NMConnection *connection;
	NMSettingBond *s_bond;
	int ifindex = nm_device_get_ifindex (device);
	const char *mode, *value;
	char *contents;
	gboolean set_arp_interval = TRUE;

	/* Option restrictions:
	 *
	 * arp_interval conflicts miimon > 0
	 * arp_interval conflicts [ alb, tlb ]
	 * arp_validate needs [ active-backup ]
	 * downdelay needs miimon
	 * updelay needs miimon
	 * primary needs [ active-backup, tlb, alb ]
	 *
	 * clearing miimon requires that arp_interval be 0, but clearing
	 *     arp_interval doesn't require miimon to be 0
	 */

	connection = nm_device_get_connection (device);
	g_assert (connection);
	s_bond = nm_connection_get_setting_bond (connection);
	g_assert (s_bond);

	mode = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MODE);
	if (mode == NULL)
		mode = "balance-rr";

	value = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MIIMON);
	if (value && atoi (value)) {
		/* clear arp interval */
		set_bond_attr (device, "arp_interval", "0");
		set_arp_interval = FALSE;

		set_bond_attr (device, "miimon", value);
		set_simple_option (device, "updelay", s_bond, NM_SETTING_BOND_OPTION_UPDELAY);
		set_simple_option (device, "downdelay", s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY);
	} else if (!value) {
		/* If not given, and arp_interval is not given, default to 100 */
		long int val_int;
		char *end;

		value = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL);
		errno = 0;
		val_int = strtol (value ? value : "0", &end, 10);
		if (!value || (val_int == 0 && errno == 0 && *end == '\0'))
			set_bond_attr (device, "miimon", "100");
	}

	/* The stuff after 'mode' requires the given mode or doesn't care */
	set_bond_attr (device, "mode", mode);

	/* arp_interval not compatible with ALB, TLB */
	if (g_strcmp0 (mode, "balance-alb") == 0 || g_strcmp0 (mode, "balance-tlb") == 0)
		set_arp_interval = FALSE;

	if (set_arp_interval) {
		set_simple_option (device, "arp_interval", s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL);

		/* Just let miimon get cleared automatically; even setting miimon to
		 * 0 (disabled) clears arp_interval.
		 */
	}

	value = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_ARP_VALIDATE);
	/* arp_validate > 0 only valid in active-backup mode */
	if (   value
	    && g_strcmp0 (value, "0") != 0
	    && g_strcmp0 (value, "none") != 0
	    && g_strcmp0 (mode, "active-backup") == 0)
		set_bond_attr (device, "arp_validate", value);
	else
		set_bond_attr (device, "arp_validate", "0");

	if (   g_strcmp0 (mode, "active-backup") == 0
	    || g_strcmp0 (mode, "balance-alb") == 0
	    || g_strcmp0 (mode, "balance-tlb") == 0) {
		value = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_PRIMARY);
		set_bond_attr (device, "primary", value ? value : "");
	}

	/* Clear ARP targets */
	contents = nm_platform_master_get_option (NM_PLATFORM_GET, ifindex, "arp_ip_target");
	set_arp_targets (device, contents, " \n", "-");
	g_free (contents);

	/* Add new ARP targets */
	value = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET);
	set_arp_targets (device, value, ",", "+");

	set_simple_option (device, "primary_reselect", s_bond, NM_SETTING_BOND_OPTION_PRIMARY_RESELECT);
	set_simple_option (device, "fail_over_mac", s_bond, NM_SETTING_BOND_OPTION_FAIL_OVER_MAC);
	set_simple_option (device, "use_carrier", s_bond, NM_SETTING_BOND_OPTION_USE_CARRIER);
	set_simple_option (device, "ad_select", s_bond, NM_SETTING_BOND_OPTION_AD_SELECT);
	set_simple_option (device, "xmit_hash_policy", s_bond, NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY);
	set_simple_option (device, "resend_igmp", s_bond, NM_SETTING_BOND_OPTION_RESEND_IGMP);

	if (   g_strcmp0 (mode, "4") == 0
	    || g_strcmp0 (mode, "802.3ad") == 0)
		set_simple_option (device, "lacp_rate", s_bond, NM_SETTING_BOND_OPTION_LACP_RATE);

	return NM_ACT_STAGE_RETURN_SUCCESS;
}


static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;
	gboolean no_firmware = FALSE;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ret = NM_DEVICE_CLASS (nm_device_bond_parent_class)->act_stage1_prepare (dev, reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	/* Interface must be down to set bond options */
	nm_device_take_down (dev, TRUE);
	ret = apply_bonding_config (dev);
	nm_device_bring_up (dev, TRUE, &no_firmware);

	return ret;
}

static void
ip4_config_pre_commit (NMDevice *self, NMIP4Config *config)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	guint32 mtu;

	connection = nm_device_get_connection (self);
	g_assert (connection);
	s_wired = nm_connection_get_setting_wired (connection);

	if (s_wired) {
		/* MTU override */
		mtu = nm_setting_wired_get_mtu (s_wired);
		if (mtu)
			nm_ip4_config_set_mtu (config, mtu, NM_IP_CONFIG_SOURCE_USER);
	}
}

static gboolean
enslave_slave (NMDevice *device,
               NMDevice *slave,
               NMConnection *connection,
               gboolean configure)
{
	NMDeviceBond *self = NM_DEVICE_BOND (device);
	gboolean success = TRUE, no_firmware = FALSE;
	const char *slave_iface = nm_device_get_ip_iface (slave);

	nm_device_master_check_slave_physical_port (device, slave, LOGD_BOND);

	if (configure) {
		nm_device_take_down (slave, TRUE);
		success = nm_platform_link_enslave (NM_PLATFORM_GET,
		                                    nm_device_get_ip_ifindex (device),
		                                    nm_device_get_ip_ifindex (slave));
		nm_device_bring_up (slave, TRUE, &no_firmware);

		if (!success)
			return FALSE;

		_LOGI (LOGD_BOND, "enslaved bond slave %s", slave_iface);
	} else
		_LOGI (LOGD_BOND, "bond slave %s was enslaved", slave_iface);

	g_object_notify (G_OBJECT (device), NM_DEVICE_BOND_SLAVES);
	return TRUE;
}

static gboolean
release_slave (NMDevice *device,
               NMDevice *slave,
               gboolean configure)
{
	NMDeviceBond *self = NM_DEVICE_BOND (device);
	gboolean success = TRUE, no_firmware = FALSE;

	if (configure) {
		success = nm_platform_link_release (NM_PLATFORM_GET,
		                                    nm_device_get_ip_ifindex (device),
		                                    nm_device_get_ip_ifindex (slave));

		if (success) {
			_LOGI (LOGD_BOND, "released bond slave %s",
			       nm_device_get_ip_iface (slave));
		} else {
			_LOGW (LOGD_BOND, "failed to release bond slave %s",
			       nm_device_get_ip_iface (slave));
		}
	} else {
		_LOGI (LOGD_BOND, "bond slave %s was released",
		             nm_device_get_ip_iface (slave));
	}

	if (success)
		g_object_notify (G_OBJECT (device), NM_DEVICE_BOND_SLAVES);

	if (configure) {
		/* Kernel bonding code "closes" the slave when releasing it, (which clears
		 * IFF_UP), so we must bring it back up here to ensure carrier changes and
		 * other state is noticed by the now-released slave.
		 */
		if (!nm_device_bring_up (slave, TRUE, &no_firmware))
			_LOGW (LOGD_BOND, "released bond slave could not be brought up.");
	}

	return success;
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    NMPlatformLink *out_plink,
                    GError **error)
{
	const char *iface = nm_device_get_iface (device);
	NMPlatformError plerr;

	g_assert (iface);
	g_assert (nm_device_get_ifindex (device) <= 0);
	g_assert (out_plink);

	plerr = nm_platform_bond_add (NM_PLATFORM_GET, iface, out_plink);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS && plerr != NM_PLATFORM_ERROR_EXISTS) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create bond interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_platform_error_to_string (plerr));
		return FALSE;
	}
	return TRUE;
}

/******************************************************************/

static void
nm_device_bond_init (NMDeviceBond * self)
{
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	GSList *list;

	switch (prop_id) {
		break;
	case PROP_SLAVES:
		list = nm_device_master_get_slaves (NM_DEVICE (object));
		nm_utils_g_value_set_object_path_array (value, list);
		g_slist_free (list);
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

	parent_class->connection_type = NM_SETTING_BOND_SETTING_NAME;

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->is_available = is_available;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->check_connection_available = check_connection_available;
	parent_class->complete_connection = complete_connection;

	parent_class->update_connection = update_connection;
	parent_class->master_update_slave_connection = master_update_slave_connection;

	parent_class->create_and_realize = create_and_realize;
	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->ip4_config_pre_commit = ip4_config_pre_commit;
	parent_class->enslave_slave = enslave_slave;
	parent_class->release_slave = release_slave;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_SLAVES,
		 g_param_spec_boxed (NM_DEVICE_BOND_SLAVES, "", "",
		                     DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        &dbus_glib_nm_device_bond_object_info);
}

/*************************************************************/

#define NM_TYPE_BOND_FACTORY (nm_bond_factory_get_type ())
#define NM_BOND_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BOND_FACTORY, NMBondFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_BOND,
		                              NM_DEVICE_IFACE, iface,
		                              NM_DEVICE_DRIVER, "bonding",
		                              NM_DEVICE_TYPE_DESC, "Bond",
		                              NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_BOND,
		                              NM_DEVICE_IS_MASTER, TRUE,
		                              NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (BOND, Bond, bond,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_BOND)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_BOND_SETTING_NAME),
	factory_iface->create_device = create_device;
	)

