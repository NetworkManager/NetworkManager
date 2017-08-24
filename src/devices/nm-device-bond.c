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
 * Copyright 2011 - 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-bond.h"

#include <errno.h>
#include <stdlib.h>

#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-core-internal.h"
#include "nm-ip4-config.h"

#include "introspection/org.freedesktop.NetworkManager.Device.Bond.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceBond);

/*****************************************************************************/

struct _NMDeviceBond {
	NMDevice parent;
};

struct _NMDeviceBondClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceBond, nm_device_bond, NM_TYPE_DEVICE)

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMSettingBond *s_bond;

	if (!NM_DEVICE_CLASS (nm_device_bond_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_bond = nm_connection_get_setting_bond (connection);
	if (!s_bond || !nm_connection_is_type (connection, NM_SETTING_BOND_SETTING_NAME))
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

	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
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

/*****************************************************************************/

static gboolean
set_bond_attr (NMDevice *device, NMBondMode mode, const char *attr, const char *value)
{
	NMDeviceBond *self = NM_DEVICE_BOND (device);
	gboolean ret;
	int ifindex = nm_device_get_ifindex (device);

	if (!_nm_setting_bond_option_supported (attr, mode))
		return FALSE;

	ret = nm_platform_sysctl_master_set_option (nm_device_get_platform (device), ifindex, attr, value);
	if (!ret)
		_LOGW (LOGD_PLATFORM, "failed to set bonding attribute '%s' to '%s'", attr, value);
	return ret;
}

static gboolean
ignore_option (NMSettingBond *s_bond, const char *option, const char *value)
{
	const char *defvalue;

	if (nm_streq0 (option, NM_SETTING_BOND_OPTION_MIIMON)) {
		/* The default value for miimon, when missing in the setting, is
		 * 0 if arp_interval is != 0, and 100 otherwise. So, let's ignore
		 * miimon=0 (which means that miimon is disabled) and accept any
		 * other value. Adding miimon=100 does not cause any harm.
		 */
		defvalue = "0";
	} else
		defvalue = nm_setting_bond_get_option_default (s_bond, option);

	return nm_streq0 (value, defvalue);
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMSettingBond *s_bond = nm_connection_get_setting_bond (connection);
	int ifindex = nm_device_get_ifindex (device);
	NMBondMode mode = NM_BOND_MODE_UNKNOWN;
	const char **options;

	if (!s_bond) {
		s_bond = (NMSettingBond *) nm_setting_bond_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_bond);
	}

	/* Read bond options from sysfs and update the Bond setting to match */
	options = nm_setting_bond_get_valid_options (s_bond);
	for (; *options; options++) {
		gs_free char *value = nm_platform_sysctl_master_get_option (nm_device_get_platform (device), ifindex, *options);
		char *p;

		if (   value
		    && _nm_setting_bond_get_option_type (s_bond, *options) == NM_BOND_OPTION_TYPE_BOTH) {
			p = strchr (value, ' ');
			if (p)
				*p = '\0';
		}

		if (value && nm_streq (*options, NM_SETTING_BOND_OPTION_MODE))
			mode = _nm_setting_bond_mode_from_string (value);

		if (!_nm_setting_bond_option_supported (*options, mode))
			continue;

		if (   value
		    && value[0]
		    && !ignore_option (s_bond, *options, value)) {
			/* Replace " " with "," for arp_ip_targets from the kernel */
			if (strcmp (*options, NM_SETTING_BOND_OPTION_ARP_IP_TARGET) == 0) {
				for (p = value; *p; p++) {
					if (*p == ' ')
						*p = ',';
				}
			}

			nm_setting_bond_add_option (s_bond, *options, value);
		}
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
                 NMBondMode mode,
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
			set_bond_attr (device, mode, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, tmp);
			g_free (tmp);
		}
	}
	g_strfreev (items);
}

static void
set_simple_option (NMDevice *device,
                   NMBondMode mode,
                   NMSettingBond *s_bond,
                   const char *opt)
{
	const char *value;

	value = nm_setting_bond_get_option_by_name (s_bond, opt);
	if (!value)
		value = nm_setting_bond_get_option_default (s_bond, opt);
	set_bond_attr (device, mode, opt, value);
}

static NMActStageReturn
apply_bonding_config (NMDevice *device)
{
	NMDeviceBond *self = NM_DEVICE_BOND (device);
	NMConnection *connection;
	NMSettingBond *s_bond;
	int ifindex = nm_device_get_ifindex (device);
	const char *mode_str, *value;
	char *contents;
	gboolean set_arp_interval = TRUE;
	NMBondMode mode;

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

	connection = nm_device_get_applied_connection (device);
	g_assert (connection);
	s_bond = nm_connection_get_setting_bond (connection);
	g_assert (s_bond);

	mode_str = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MODE);
	if (!mode_str)
		mode_str = "balance-rr";

	mode = _nm_setting_bond_mode_from_string (mode_str);
	if (mode == NM_BOND_MODE_UNKNOWN) {
		_LOGW (LOGD_BOND, "unknown bond mode '%s'", mode_str);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	/* Set mode first, as some other options (e.g. arp_interval) are valid
	 * only for certain modes.
	 */

	set_bond_attr (device, mode, NM_SETTING_BOND_OPTION_MODE, mode_str);

	value = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MIIMON);
	if (value && atoi (value)) {
		/* clear arp interval */
		set_bond_attr (device, mode, NM_SETTING_BOND_OPTION_ARP_INTERVAL, "0");
		set_arp_interval = FALSE;

		set_bond_attr (device, mode, NM_SETTING_BOND_OPTION_MIIMON, value);
		set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_UPDELAY);
		set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY);
	} else if (!value) {
		/* If not given, and arp_interval is not given or disabled, default to 100 */
		value = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL);
		if (_nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXUINT32, 0) == 0)
			set_bond_attr (device, mode, NM_SETTING_BOND_OPTION_MIIMON, "100");
	}

	if (set_arp_interval) {
		set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL);
		/* Just let miimon get cleared automatically; even setting miimon to
		 * 0 (disabled) clears arp_interval.
		 */
	}

	/* ARP validate: value > 0 only valid in active-backup mode */
	value = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_ARP_VALIDATE);
	if (   value
	    && !nm_streq (value, "0")
	    && !nm_streq (value, "none")
	    && mode == NM_BOND_MODE_ACTIVEBACKUP)
		set_bond_attr (device, mode, NM_SETTING_BOND_OPTION_ARP_VALIDATE, value);
	else
		set_bond_attr (device, mode, NM_SETTING_BOND_OPTION_ARP_VALIDATE, "0");

	/* Primary */
	value = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_PRIMARY);
	set_bond_attr (device, mode, NM_SETTING_BOND_OPTION_PRIMARY, value ? value : "");

	/* ARP targets: clear and initialize the list */
	contents = nm_platform_sysctl_master_get_option (nm_device_get_platform (device), ifindex,
	                                                 NM_SETTING_BOND_OPTION_ARP_IP_TARGET);
	set_arp_targets (device, mode, contents, " \n", "-");
	value = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET);
	set_arp_targets (device, mode, value, ",", "+");
	g_free (contents);

	/* AD actor system: don't set if empty */
	value = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM);
	if (value)
		set_bond_attr (device, mode, NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM, value);

	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_ACTIVE_SLAVE);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_AD_SELECT);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_AD_USER_PORT_KEY);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_ARP_ALL_TARGETS);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_FAIL_OVER_MAC);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_LACP_RATE);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_LP_INTERVAL);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_NUM_GRAT_ARP);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_NUM_UNSOL_NA);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_MIN_LINKS);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_PRIMARY_RESELECT);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_RESEND_IGMP);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_TLB_DYNAMIC_LB);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_USE_CARRIER);
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY);

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *out_failure_reason)
{
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;
	gboolean no_firmware = FALSE;

	ret = NM_DEVICE_CLASS (nm_device_bond_parent_class)->act_stage1_prepare (dev, out_failure_reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	/* Interface must be down to set bond options */
	nm_device_take_down (dev, TRUE);
	ret = apply_bonding_config (dev);
	if (ret != NM_ACT_STAGE_RETURN_FAILURE)
		ret = nm_device_hw_addr_set_cloned (dev, nm_device_get_applied_connection (dev), FALSE);
	nm_device_bring_up (dev, TRUE, &no_firmware);

	return ret;
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
	NMConnection *master_con;

	nm_device_master_check_slave_physical_port (device, slave, LOGD_BOND);

	if (configure) {
		nm_device_take_down (slave, TRUE);
		success = nm_platform_link_enslave (nm_device_get_platform (device),
		                                    nm_device_get_ip_ifindex (device),
		                                    nm_device_get_ip_ifindex (slave));
		nm_device_bring_up (slave, TRUE, &no_firmware);

		if (!success)
			return FALSE;

		_LOGI (LOGD_BOND, "enslaved bond slave %s", slave_iface);

		/* The active_slave option can be set only after the interface is enslaved */
		master_con = nm_device_get_applied_connection (device);
		if (master_con) {
			NMSettingBond *s_bond = nm_connection_get_setting_bond (master_con);
			const char *active;

			if (s_bond) {
				active = nm_setting_bond_get_option_by_name (s_bond, "active_slave");
				if (active && nm_streq0 (active, nm_device_get_iface (slave))) {
					nm_platform_sysctl_master_set_option (nm_device_get_platform (device),
					                                      nm_device_get_ifindex (device),
					                                      "active_slave",
					                                      active);
					_LOGD (LOGD_BOND, "setting slave %s as active one for master %s",
					       active, nm_device_get_iface (device));
				}
			}
		}
	} else
		_LOGI (LOGD_BOND, "bond slave %s was enslaved", slave_iface);

	return TRUE;
}

static void
release_slave (NMDevice *device,
               NMDevice *slave,
               gboolean configure)
{
	NMDeviceBond *self = NM_DEVICE_BOND (device);
	gboolean success, no_firmware = FALSE;
	gs_free char *address = NULL;

	if (configure) {
		/* When the last slave is released the bond MAC will be set to a random
		 * value by kernel; remember the current one and restore it afterwards.
		 */
		address = g_strdup (nm_device_get_hw_address (device));

		success = nm_platform_link_release (nm_device_get_platform (device),
		                                    nm_device_get_ip_ifindex (device),
		                                    nm_device_get_ip_ifindex (slave));

		if (success) {
			_LOGI (LOGD_BOND, "released bond slave %s",
			       nm_device_get_ip_iface (slave));
		} else {
			_LOGW (LOGD_BOND, "failed to release bond slave %s",
			       nm_device_get_ip_iface (slave));
		}

		nm_platform_process_events (nm_device_get_platform (device));
		if (nm_device_update_hw_address (device))
			nm_device_hw_addr_set (device, address, "restore", FALSE);

		/* Kernel bonding code "closes" the slave when releasing it, (which clears
		 * IFF_UP), so we must bring it back up here to ensure carrier changes and
		 * other state is noticed by the now-released slave.
		 */
		if (!nm_device_bring_up (slave, TRUE, &no_firmware))
			_LOGW (LOGD_BOND, "released bond slave could not be brought up.");
	} else {
		_LOGI (LOGD_BOND, "bond slave %s was released",
		       nm_device_get_ip_iface (slave));
	}
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	const char *iface = nm_device_get_iface (device);
	NMPlatformError plerr;

	g_assert (iface);

	plerr = nm_platform_link_bond_add (nm_device_get_platform (device), iface, out_plink);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create bond interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_platform_error_to_string_a (plerr));
		return FALSE;
	}
	return TRUE;
}

static gboolean
check_changed_options (NMSettingBond *s_a, NMSettingBond *s_b, GError **error)
{
	guint i, num;
	const char *name = NULL, *value_a = NULL, *value_b = NULL;

	/* Check that options in @s_a have compatible changes in @s_b */

	num = nm_setting_bond_get_num_options (s_a);
	for (i = 0; i < num; i++) {
		nm_setting_bond_get_option (s_a, i, &name, &value_a);

		/* We support changes to these */
		if (NM_IN_STRSET (name,
		                  NM_SETTING_BOND_OPTION_ACTIVE_SLAVE,
		                  NM_SETTING_BOND_OPTION_PRIMARY)) {
			continue;
		}

		/* Missing in @s_b, but has a default value in @s_a */
		value_b = nm_setting_bond_get_option_by_name (s_b, name);
		if (   !value_b
		    && nm_streq0 (value_a, nm_setting_bond_get_option_default (s_a, name))) {
			continue;
		}

		/* Reject any other changes */
		if (!nm_streq0 (value_a, value_b)) {
			g_set_error (error,
			             NM_DEVICE_ERROR,
			             NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			             "Can't reapply '%s' bond option",
			             name);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
can_reapply_change (NMDevice *device,
                    const char *setting_name,
                    NMSetting *s_old,
                    NMSetting *s_new,
                    GHashTable *diffs,
                    GError **error)
{
	NMDeviceClass *device_class;
	NMSettingBond *s_bond_old, *s_bond_new;

	/* Only handle bond setting here, delegate other settings to parent class */
	if (nm_streq (setting_name, NM_SETTING_BOND_SETTING_NAME)) {
		if (!nm_device_hash_check_invalid_keys (diffs,
		                                        NM_SETTING_BOND_SETTING_NAME,
		                                        error,
		                                        NM_SETTING_BOND_OPTIONS))
			return FALSE;

		s_bond_old = NM_SETTING_BOND (s_old);
		s_bond_new = NM_SETTING_BOND (s_new);

		if (   !check_changed_options (s_bond_old, s_bond_new, error)
		    || !check_changed_options (s_bond_new, s_bond_old, error)) {
			return FALSE;
		}

		return TRUE;
	}

	device_class = NM_DEVICE_CLASS (nm_device_bond_parent_class);
	return device_class->can_reapply_change (device,
	                                         setting_name,
	                                         s_old,
	                                         s_new,
	                                         diffs,
	                                         error);
}

static void
reapply_connection (NMDevice *device, NMConnection *con_old, NMConnection *con_new)
{
	NMDeviceBond *self = NM_DEVICE_BOND (device);
	const char *value;
	NMSettingBond *s_bond;
	NMBondMode mode;

	NM_DEVICE_CLASS (nm_device_bond_parent_class)->reapply_connection (device,
	                                                                   con_old,
	                                                                   con_new);

	_LOGD (LOGD_BOND, "reapplying bond settings");
	s_bond = nm_connection_get_setting_bond (con_new);
	g_return_if_fail (s_bond);

	value = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MODE);
	if (!value)
		value = "balance-rr";

	mode = _nm_setting_bond_mode_from_string (value);
	g_return_if_fail (mode != NM_BOND_MODE_UNKNOWN);

	/* Primary */
	value = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_PRIMARY);
	set_bond_attr (device, mode, NM_SETTING_BOND_OPTION_PRIMARY, value ? value : "");

	/* Active slave */
	set_simple_option (device, mode, s_bond, NM_SETTING_BOND_OPTION_ACTIVE_SLAVE);
}

/*****************************************************************************/

static void
nm_device_bond_init (NMDeviceBond * self)
{
	nm_assert (nm_device_is_master (NM_DEVICE (self)));
}

static void
nm_device_bond_class_init (NMDeviceBondClass *klass)
{
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NM_SETTING_BOND_SETTING_NAME, NM_LINK_TYPE_BOND)

	parent_class->is_master = TRUE;
	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->complete_connection = complete_connection;

	parent_class->update_connection = update_connection;
	parent_class->master_update_slave_connection = master_update_slave_connection;

	parent_class->create_and_realize = create_and_realize;
	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->get_configured_mtu = nm_device_get_configured_mtu_for_wired;
	parent_class->enslave_slave = enslave_slave;
	parent_class->release_slave = release_slave;
	parent_class->can_reapply_change = can_reapply_change;
	parent_class->reapply_connection = reapply_connection;

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_BOND_SKELETON,
	                                        NULL);
}

/*****************************************************************************/

#define NM_TYPE_BOND_DEVICE_FACTORY (nm_bond_device_factory_get_type ())
#define NM_BOND_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BOND_DEVICE_FACTORY, NMBondDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_BOND,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, "bonding",
	                                  NM_DEVICE_TYPE_DESC, "Bond",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_BOND,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_BOND,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (BOND, Bond, bond,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_BOND)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_BOND_SETTING_NAME),
	factory_class->create_device = create_device;
);
