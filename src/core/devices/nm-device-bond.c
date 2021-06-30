/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2011 - 2018 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-bond.h"

#include <stdlib.h>
#include <net/if.h>

#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-core-internal.h"
#include "nm-ip4-config.h"

#define _NMLOG_DEVICE_TYPE NMDeviceBond
#include "nm-device-logging.h"

/*****************************************************************************/

#define OPTIONS_APPLY_SUBSET                                                               \
    NM_SETTING_BOND_OPTION_MIIMON, NM_SETTING_BOND_OPTION_UPDELAY,                         \
        NM_SETTING_BOND_OPTION_DOWNDELAY, NM_SETTING_BOND_OPTION_ARP_INTERVAL,             \
        NM_SETTING_BOND_OPTION_ARP_VALIDATE, NM_SETTING_BOND_OPTION_PRIMARY,               \
        NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM, NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO,  \
        NM_SETTING_BOND_OPTION_AD_SELECT, NM_SETTING_BOND_OPTION_AD_USER_PORT_KEY,         \
        NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE, NM_SETTING_BOND_OPTION_ARP_ALL_TARGETS,  \
        NM_SETTING_BOND_OPTION_FAIL_OVER_MAC, NM_SETTING_BOND_OPTION_LACP_RATE,            \
        NM_SETTING_BOND_OPTION_LP_INTERVAL, NM_SETTING_BOND_OPTION_MIN_LINKS,              \
        NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE, NM_SETTING_BOND_OPTION_PRIMARY_RESELECT, \
        NM_SETTING_BOND_OPTION_RESEND_IGMP, NM_SETTING_BOND_OPTION_TLB_DYNAMIC_LB,         \
        NM_SETTING_BOND_OPTION_USE_CARRIER, NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY,       \
        NM_SETTING_BOND_OPTION_NUM_GRAT_ARP, NM_SETTING_BOND_OPTION_PEER_NOTIF_DELAY

#define OPTIONS_REAPPLY_SUBSET                                                            \
    NM_SETTING_BOND_OPTION_MIIMON, NM_SETTING_BOND_OPTION_UPDELAY,                        \
        NM_SETTING_BOND_OPTION_DOWNDELAY, NM_SETTING_BOND_OPTION_ARP_INTERVAL,            \
        NM_SETTING_BOND_OPTION_ARP_VALIDATE, NM_SETTING_BOND_OPTION_PRIMARY,              \
        NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM, NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO, \
        NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE, NM_SETTING_BOND_OPTION_ARP_ALL_TARGETS, \
        NM_SETTING_BOND_OPTION_FAIL_OVER_MAC, NM_SETTING_BOND_OPTION_LP_INTERVAL,         \
        NM_SETTING_BOND_OPTION_MIN_LINKS, NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE,       \
        NM_SETTING_BOND_OPTION_PRIMARY_RESELECT, NM_SETTING_BOND_OPTION_RESEND_IGMP,      \
        NM_SETTING_BOND_OPTION_USE_CARRIER, NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY,      \
        NM_SETTING_BOND_OPTION_NUM_GRAT_ARP, NM_SETTING_BOND_OPTION_PEER_NOTIF_DELAY

#define OPTIONS_REAPPLY_FULL                                     \
    OPTIONS_REAPPLY_SUBSET, NM_SETTING_BOND_OPTION_ACTIVE_SLAVE, \
        NM_SETTING_BOND_OPTION_ARP_IP_TARGET

/*****************************************************************************/

struct _NMDeviceBond {
    NMDevice parent;
};

struct _NMDeviceBondClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceBond, nm_device_bond, NM_TYPE_DEVICE)

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *dev)
{
    return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
complete_connection(NMDevice *           device,
                    NMConnection *       connection,
                    const char *         specific_object,
                    NMConnection *const *existing_connections,
                    GError **            error)
{
    NMSettingBond *s_bond;

    nm_utils_complete_generic(nm_device_get_platform(device),
                              connection,
                              NM_SETTING_BOND_SETTING_NAME,
                              existing_connections,
                              NULL,
                              _("Bond connection"),
                              "bond",
                              NULL,
                              TRUE);

    s_bond = nm_connection_get_setting_bond(connection);
    if (!s_bond) {
        s_bond = (NMSettingBond *) nm_setting_bond_new();
        nm_connection_add_setting(connection, NM_SETTING(s_bond));
    }

    return TRUE;
}

/*****************************************************************************/

static gboolean
_set_bond_attr(NMDevice *device, const char *attr, const char *value)
{
    NMDeviceBond *self    = NM_DEVICE_BOND(device);
    int           ifindex = nm_device_get_ifindex(device);
    gboolean      ret;

    nm_assert(attr && attr[0]);
    nm_assert(value);

    if (nm_streq(value, NM_BOND_AD_ACTOR_SYSTEM_DEFAULT)
        && nm_streq(attr, NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM)) {
        gs_free char *cur_val = NULL;

        /* kernel does not allow setting ad_actor_system to "00:00:00:00:00:00". We would thus
         * log an EINVAL error. Avoid that... at least, if the value is already "00:00:00:00:00:00". */
        cur_val =
            nm_platform_sysctl_master_get_option(nm_device_get_platform(device), ifindex, attr);
        if (nm_streq0(cur_val, NM_BOND_AD_ACTOR_SYSTEM_DEFAULT))
            return TRUE;

        /* OK, the current value is different, and we will proceed setting "00:00:00:00:00:00".
         * That will fail, and we will log a warning. There is nothing else to do. */
    }

    ret =
        nm_platform_sysctl_master_set_option(nm_device_get_platform(device), ifindex, attr, value);
    if (!ret)
        _LOGW(LOGD_PLATFORM, "failed to set bonding attribute '%s' to '%s'", attr, value);
    return ret;
}

#define _set_bond_attr_take(device, attr, value)                            \
    G_STMT_START                                                            \
    {                                                                       \
        gs_free char *_tmp = (value);                                       \
                                                                            \
        _set_bond_attr(device, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, _tmp); \
    }                                                                       \
    G_STMT_END

#define _set_bond_attr_printf(device, attr, fmt, ...) \
    _set_bond_attr_take((device), (attr), g_strdup_printf(fmt, __VA_ARGS__))

static gboolean
ignore_option(NMSettingBond *s_bond, const char *option, const char *value)
{
    const char *defvalue;

    if (nm_streq0(option, NM_SETTING_BOND_OPTION_MIIMON)) {
        /* The default value for miimon, when missing in the setting, is
         * 0 if arp_interval is != 0, and 100 otherwise. So, let's ignore
         * miimon=0 (which means that miimon is disabled) and accept any
         * other value. Adding miimon=100 does not cause any harm.
         */
        defvalue = "0";
    } else
        defvalue = nm_setting_bond_get_option_default(s_bond, option);

    return nm_streq0(value, defvalue);
}

static void
update_connection(NMDevice *device, NMConnection *connection)
{
    NMDeviceBond * self    = NM_DEVICE_BOND(device);
    NMSettingBond *s_bond  = nm_connection_get_setting_bond(connection);
    int            ifindex = nm_device_get_ifindex(device);
    NMBondMode     mode    = NM_BOND_MODE_UNKNOWN;
    const char **  options;

    if (!s_bond) {
        s_bond = (NMSettingBond *) nm_setting_bond_new();
        nm_connection_add_setting(connection, (NMSetting *) s_bond);
    }

    /* Read bond options from sysfs and update the Bond setting to match */
    options = nm_setting_bond_get_valid_options(NULL);
    for (; options[0]; options++) {
        const char *  option = options[0];
        gs_free char *value  = NULL;
        char *        p;

        if (NM_IN_STRSET(option, NM_SETTING_BOND_OPTION_ACTIVE_SLAVE))
            continue;

        value =
            nm_platform_sysctl_master_get_option(nm_device_get_platform(device), ifindex, option);

        if (value && _nm_setting_bond_get_option_type(s_bond, option) == NM_BOND_OPTION_TYPE_BOTH) {
            p = strchr(value, ' ');
            if (p)
                *p = '\0';
        }

        if (mode == NM_BOND_MODE_UNKNOWN) {
            if (value && nm_streq(option, NM_SETTING_BOND_OPTION_MODE))
                mode = _nm_setting_bond_mode_from_string(value);
            if (mode == NM_BOND_MODE_UNKNOWN)
                continue;
        }

        if (!_nm_setting_bond_option_supported(option, mode))
            continue;

        if (value && value[0] && !ignore_option(s_bond, option, value)) {
            /* Replace " " with "," for arp_ip_targets from the kernel */
            if (nm_streq(option, NM_SETTING_BOND_OPTION_ARP_IP_TARGET)) {
                for (p = value; *p; p++) {
                    if (*p == ' ')
                        *p = ',';
                }
            }

            if (!_nm_setting_bond_validate_option(option, value, NULL))
                _LOGT(LOGD_BOND, "cannot set invalid bond option '%s' = '%s'", option, value);
            else
                nm_setting_bond_add_option(s_bond, option, value);
        }
    }
}

static gboolean
master_update_slave_connection(NMDevice *    self,
                               NMDevice *    slave,
                               NMConnection *connection,
                               GError **     error)
{
    g_object_set(nm_connection_get_setting_connection(connection),
                 NM_SETTING_CONNECTION_MASTER,
                 nm_device_get_iface(self),
                 NM_SETTING_CONNECTION_SLAVE_TYPE,
                 NM_SETTING_BOND_SETTING_NAME,
                 NULL);
    return TRUE;
}

static void
set_arp_targets(NMDevice *device, const char *cur_arp_ip_target, const char *new_arp_ip_target)
{
    gs_unref_ptrarray GPtrArray *free_list = NULL;
    gs_free const char **        cur_strv  = NULL;
    gs_free const char **        new_strv  = NULL;
    gsize                        cur_len;
    gsize                        new_len;
    gsize                        i;
    gsize                        j;

    cur_strv = nm_utils_strsplit_set_full(cur_arp_ip_target,
                                          NM_ASCII_SPACES,
                                          NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP);
    new_strv = nm_utils_bond_option_arp_ip_targets_split(new_arp_ip_target);

    cur_len = NM_PTRARRAY_LEN(cur_strv);
    new_len = NM_PTRARRAY_LEN(new_strv);

    if (new_len > 0) {
        for (j = 0, i = 0; i < new_len; i++) {
            const char *s;
            in_addr_t   a4;

            s = new_strv[i];
            if (nm_utils_parse_inaddr_bin(AF_INET, s, NULL, &a4)) {
                char sbuf[INET_ADDRSTRLEN];

                _nm_utils_inet4_ntop(a4, sbuf);
                if (!nm_streq(s, sbuf)) {
                    if (!free_list)
                        free_list = g_ptr_array_new_with_free_func(g_free);
                    s = g_strdup(sbuf);
                    g_ptr_array_add(free_list, (gpointer) s);
                }
            }

            if (nm_utils_strv_find_first((char **) new_strv, i, s) < 0)
                new_strv[j++] = s;
        }
        new_strv[j] = NULL;
        new_len     = j;
    }

    if (cur_len == 0 && new_len == 0)
        return;

    if (nm_utils_strv_equal(cur_strv, new_strv))
        return;

    for (i = 0; i < cur_len; i++)
        _set_bond_attr_printf(device, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, "-%s", cur_strv[i]);
    for (i = 0; i < new_len; i++)
        _set_bond_attr_printf(device, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, "+%s", new_strv[i]);
}

/*
 * Sets bond attribute stored in the option hashtable or
 * the default value if no value was set.
 */
static void
set_bond_attr_or_default(NMDevice *device, NMSettingBond *s_bond, const char *opt)
{
    NMDeviceBond *self = NM_DEVICE_BOND(device);
    const char *  value;

    value = nm_setting_bond_get_option_or_default(s_bond, opt);
    if (!value) {
        if (_LOGT_ENABLED(LOGD_BOND) && nm_setting_bond_get_option_by_name(s_bond, opt))
            _LOGT(LOGD_BOND, "bond option '%s' not set as it conflicts with other options", opt);
        return;
    }

    _set_bond_attr(device, opt, value);
}

static void
set_bond_attrs_or_default(NMDevice *device, NMSettingBond *s_bond, const char *const *attr_v)
{
    nm_assert(NM_IS_DEVICE(device));
    nm_assert(s_bond);
    nm_assert(attr_v);

    for (; *attr_v; ++attr_v)
        set_bond_attr_or_default(device, s_bond, *attr_v);
}

static void
set_bond_arp_ip_targets(NMDevice *device, NMSettingBond *s_bond)
{
    int           ifindex           = nm_device_get_ifindex(device);
    gs_free char *cur_arp_ip_target = NULL;

    /* ARP targets: clear and initialize the list */
    cur_arp_ip_target = nm_platform_sysctl_master_get_option(nm_device_get_platform(device),
                                                             ifindex,
                                                             NM_SETTING_BOND_OPTION_ARP_IP_TARGET);
    set_arp_targets(
        device,
        cur_arp_ip_target,
        nm_setting_bond_get_option_or_default(s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET));
}

static gboolean
apply_bonding_config(NMDeviceBond *self)
{
    NMDevice *     device = NM_DEVICE(self);
    NMSettingBond *s_bond;
    NMBondMode     mode;
    const char *   mode_str;
    gs_free char * device_bond_mode = NULL;

    s_bond = nm_device_get_applied_setting(device, NM_TYPE_SETTING_BOND);
    g_return_val_if_fail(s_bond, FALSE);

    mode_str = nm_setting_bond_get_option_or_default(s_bond, NM_SETTING_BOND_OPTION_MODE);
    mode     = _nm_setting_bond_mode_from_string(mode_str);
    g_return_val_if_fail(mode != NM_BOND_MODE_UNKNOWN, FALSE);

    /* Set mode first, as some other options (e.g. arp_interval) are valid
     * only for certain modes.
     */
    device_bond_mode = nm_platform_sysctl_master_get_option(nm_device_get_platform(device),
                                                            nm_device_get_ifindex(device),
                                                            NM_SETTING_BOND_OPTION_MODE);
    /* Need to release all slaves before we can change bond mode */
    if (!nm_streq0(device_bond_mode, mode_str))
        nm_device_master_release_slaves(device);

    set_bond_attr_or_default(device, s_bond, NM_SETTING_BOND_OPTION_MODE);

    set_bond_arp_ip_targets(device, s_bond);

    set_bond_attrs_or_default(device, s_bond, NM_MAKE_STRV(OPTIONS_APPLY_SUBSET));
    return TRUE;
}

static NMActStageReturn
act_stage1_prepare(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMDeviceBond *   self = NM_DEVICE_BOND(device);
    NMActStageReturn ret  = NM_ACT_STAGE_RETURN_SUCCESS;

    /* Interface must be down to set bond options */
    nm_device_take_down(device, TRUE);
    if (!apply_bonding_config(self))
        ret = NM_ACT_STAGE_RETURN_FAILURE;
    else {
        if (!nm_device_hw_addr_set_cloned(device, nm_device_get_applied_connection(device), FALSE))
            ret = NM_ACT_STAGE_RETURN_FAILURE;
    }
    nm_device_bring_up(device, TRUE, NULL);

    return ret;
}

static gboolean
enslave_slave(NMDevice *device, NMDevice *slave, NMConnection *connection, gboolean configure)
{
    NMDeviceBond *self = NM_DEVICE_BOND(device);

    nm_device_master_check_slave_physical_port(device, slave, LOGD_BOND);

    if (configure) {
        gboolean success;

        nm_device_take_down(slave, TRUE);
        success = nm_platform_link_enslave(nm_device_get_platform(device),
                                           nm_device_get_ip_ifindex(device),
                                           nm_device_get_ip_ifindex(slave));
        nm_device_bring_up(slave, TRUE, NULL);

        if (!success) {
            _LOGI(LOGD_BOND, "enslaved bond slave %s: failed", nm_device_get_ip_iface(slave));
            return FALSE;
        }

        _LOGI(LOGD_BOND, "enslaved bond slave %s", nm_device_get_ip_iface(slave));
    } else
        _LOGI(LOGD_BOND, "bond slave %s was enslaved", nm_device_get_ip_iface(slave));

    return TRUE;
}

static void
release_slave(NMDevice *device, NMDevice *slave, gboolean configure)
{
    NMDeviceBond *self = NM_DEVICE_BOND(device);
    gboolean      success;
    gs_free char *address = NULL;
    int           ifindex_slave;
    int           ifindex;

    if (configure) {
        ifindex = nm_device_get_ifindex(device);
        if (ifindex <= 0 || !nm_platform_link_get(nm_device_get_platform(device), ifindex))
            configure = FALSE;
    }

    ifindex_slave = nm_device_get_ip_ifindex(slave);

    if (ifindex_slave <= 0)
        _LOGD(LOGD_BOND, "bond slave %s is already released", nm_device_get_ip_iface(slave));

    if (configure) {
        NMConnection *  applied;
        NMSettingWired *s_wired;
        const char *    cloned_mac;

        address = g_strdup(nm_device_get_hw_address(device));

        if (ifindex_slave > 0) {
            success = nm_platform_link_release(nm_device_get_platform(device),
                                               nm_device_get_ip_ifindex(device),
                                               ifindex_slave);

            if (success) {
                _LOGI(LOGD_BOND, "released bond slave %s", nm_device_get_ip_iface(slave));
            } else {
                _LOGW(LOGD_BOND, "failed to release bond slave %s", nm_device_get_ip_iface(slave));
            }
        }

        if ((applied = nm_device_get_applied_connection(device))
            && ((s_wired = nm_connection_get_setting_wired(applied)))
            && ((cloned_mac = nm_setting_wired_get_cloned_mac_address(s_wired)))) {
            /* When the last slave is released the bond MAC will be set to a random
             * value by kernel; if we have set a cloned-mac-address, we need to
             * restore it to the previous value. */
            nm_platform_process_events(nm_device_get_platform(device));
            if (nm_device_update_hw_address(device))
                nm_device_hw_addr_set(device, address, "restore", FALSE);
        }

        /* Kernel bonding code "closes" the slave when releasing it, (which clears
         * IFF_UP), so we must bring it back up here to ensure carrier changes and
         * other state is noticed by the now-released slave.
         */
        if (ifindex_slave > 0) {
            if (!nm_device_bring_up(slave, TRUE, NULL))
                _LOGW(LOGD_BOND, "released bond slave could not be brought up.");
        }
    } else {
        if (ifindex_slave > 0) {
            _LOGI(LOGD_BOND, "bond slave %s was released", nm_device_get_ip_iface(slave));
        }
    }
}

static gboolean
create_and_realize(NMDevice *             device,
                   NMConnection *         connection,
                   NMDevice *             parent,
                   const NMPlatformLink **out_plink,
                   GError **              error)
{
    const char *iface = nm_device_get_iface(device);
    int         r;

    g_assert(iface);

    r = nm_platform_link_bond_add(nm_device_get_platform(device), iface, out_plink);
    if (r < 0) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_CREATION_FAILED,
                    "Failed to create bond interface '%s' for '%s': %s",
                    iface,
                    nm_connection_get_id(connection),
                    nm_strerror(r));
        return FALSE;
    }
    return TRUE;
}

static gboolean
can_reapply_change(NMDevice *  device,
                   const char *setting_name,
                   NMSetting * s_old,
                   NMSetting * s_new,
                   GHashTable *diffs,
                   GError **   error)
{
    NMDeviceClass *device_class;

    /* Only handle bond setting here, delegate other settings to parent class */
    if (nm_streq(setting_name, NM_SETTING_BOND_SETTING_NAME)) {
        NMSettingBond *s_a = NM_SETTING_BOND(s_old);
        NMSettingBond *s_b = NM_SETTING_BOND(s_new);
        const char **  option_list;

        if (!nm_device_hash_check_invalid_keys(diffs,
                                               NM_SETTING_BOND_SETTING_NAME,
                                               error,
                                               NM_SETTING_BOND_OPTIONS))
            return FALSE;

        option_list = nm_setting_bond_get_valid_options(NULL);

        for (; *option_list; ++option_list) {
            const char *name = *option_list;

            /* We support changes to these */
            if (NM_IN_STRSET(name, OPTIONS_REAPPLY_FULL))
                continue;

            /* Reject any other changes */
            if (!nm_streq0(nm_setting_bond_get_option_normalized(s_a, name),
                           nm_setting_bond_get_option_normalized(s_b, name))) {
                g_set_error(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
                            "Can't reapply '%s' bond option",
                            name);
                return FALSE;
            }
        }

        return TRUE;
    }

    device_class = NM_DEVICE_CLASS(nm_device_bond_parent_class);
    return device_class->can_reapply_change(device, setting_name, s_old, s_new, diffs, error);
}

static void
reapply_connection(NMDevice *device, NMConnection *con_old, NMConnection *con_new)
{
    NMDeviceBond * self = NM_DEVICE_BOND(device);
    NMSettingBond *s_bond;
    const char *   value;
    NMBondMode     mode;

    NM_DEVICE_CLASS(nm_device_bond_parent_class)->reapply_connection(device, con_old, con_new);

    _LOGD(LOGD_BOND, "reapplying bond settings");
    s_bond = nm_connection_get_setting_bond(con_new);
    g_return_if_fail(s_bond);

    value = nm_setting_bond_get_option_or_default(s_bond, NM_SETTING_BOND_OPTION_MODE);
    mode  = _nm_setting_bond_mode_from_string(value);
    g_return_if_fail(mode != NM_BOND_MODE_UNKNOWN);

    /* Below we set only the bond options that kernel allows to modify
     * while keeping the bond interface up */

    set_bond_arp_ip_targets(device, s_bond);

    set_bond_attrs_or_default(device, s_bond, NM_MAKE_STRV(OPTIONS_REAPPLY_SUBSET));
}

/*****************************************************************************/

static void
nm_device_bond_init(NMDeviceBond *self)
{
    nm_assert(nm_device_is_master(NM_DEVICE(self)));
}

static const NMDBusInterfaceInfoExtended interface_info_device_bond = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_BOND,
        .signals    = NM_DEFINE_GDBUS_SIGNAL_INFOS(&nm_signal_info_property_changed_legacy, ),
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L("HwAddress",
                                                             "s",
                                                             NM_DEVICE_HW_ADDRESS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L("Carrier", "b", NM_DEVICE_CARRIER),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L("Slaves",
                                                             "ao",
                                                             NM_DEVICE_SLAVES), ), ),
    .legacy_property_changed = TRUE,
};

static void
nm_device_bond_class_init(NMDeviceBondClass *klass)
{
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass *    device_class      = NM_DEVICE_CLASS(klass);

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_bond);

    device_class->connection_type_supported        = NM_SETTING_BOND_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_BOND_SETTING_NAME;
    device_class->link_types                       = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_BOND);

    device_class->is_master                = TRUE;
    device_class->get_generic_capabilities = get_generic_capabilities;
    device_class->complete_connection      = complete_connection;

    device_class->update_connection              = update_connection;
    device_class->master_update_slave_connection = master_update_slave_connection;

    device_class->create_and_realize = create_and_realize;
    device_class->act_stage1_prepare = act_stage1_prepare;
    device_class->get_configured_mtu = nm_device_get_configured_mtu_for_wired;
    device_class->enslave_slave      = enslave_slave;
    device_class->release_slave      = release_slave;
    device_class->can_reapply_change = can_reapply_change;
    device_class->reapply_connection = reapply_connection;
}

/*****************************************************************************/

#define NM_TYPE_BOND_DEVICE_FACTORY (nm_bond_device_factory_get_type())
#define NM_BOND_DEVICE_FACTORY(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_BOND_DEVICE_FACTORY, NMBondDeviceFactory))

static NMDevice *
create_device(NMDeviceFactory *     factory,
              const char *          iface,
              const NMPlatformLink *plink,
              NMConnection *        connection,
              gboolean *            out_ignore)
{
    return g_object_new(NM_TYPE_DEVICE_BOND,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_DRIVER,
                        "bonding",
                        NM_DEVICE_TYPE_DESC,
                        "Bond",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_BOND,
                        NM_DEVICE_LINK_TYPE,
                        NM_LINK_TYPE_BOND,
                        NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL(
    BOND,
    Bond,
    bond,
    NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(NM_LINK_TYPE_BOND)
        NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_BOND_SETTING_NAME),
    factory_class->create_device = create_device;);
