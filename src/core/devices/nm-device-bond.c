/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2011 - 2018 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-bond.h"

#include <stdlib.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>

#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "libnm-platform/nm-platform.h"
#include "nm-device-factory.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-manager.h"
#include "nm-setting-bond-port.h"
#include "nm-bond-manager.h"

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
        NM_SETTING_BOND_OPTION_NUM_GRAT_ARP, NM_SETTING_BOND_OPTION_PEER_NOTIF_DELAY,      \
        NM_SETTING_BOND_OPTION_ARP_MISSED_MAX, NM_SETTING_BOND_OPTION_LACP_ACTIVE

#define OPTIONS_REAPPLY_SUBSET                                                             \
    NM_SETTING_BOND_OPTION_MIIMON, NM_SETTING_BOND_OPTION_UPDELAY,                         \
        NM_SETTING_BOND_OPTION_DOWNDELAY, NM_SETTING_BOND_OPTION_ARP_INTERVAL,             \
        NM_SETTING_BOND_OPTION_ARP_VALIDATE, NM_SETTING_BOND_OPTION_PRIMARY,               \
        NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM, NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO,  \
        NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE, NM_SETTING_BOND_OPTION_ARP_ALL_TARGETS,  \
        NM_SETTING_BOND_OPTION_LP_INTERVAL, NM_SETTING_BOND_OPTION_MIN_LINKS,              \
        NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE, NM_SETTING_BOND_OPTION_PRIMARY_RESELECT, \
        NM_SETTING_BOND_OPTION_RESEND_IGMP, NM_SETTING_BOND_OPTION_USE_CARRIER,            \
        NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY, NM_SETTING_BOND_OPTION_NUM_GRAT_ARP,      \
        NM_SETTING_BOND_OPTION_PEER_NOTIF_DELAY, NM_SETTING_BOND_OPTION_ARP_MISSED_MAX,    \
        NM_SETTING_BOND_OPTION_LACP_ACTIVE

#define OPTIONS_REAPPLY_FULL                                     \
    OPTIONS_REAPPLY_SUBSET, NM_SETTING_BOND_OPTION_ACTIVE_SLAVE, \
        NM_SETTING_BOND_OPTION_ARP_IP_TARGET, NM_SETTING_BOND_OPTION_NS_IP6_TARGET

/*****************************************************************************/

struct _NMDeviceBond {
    NMDevice       parent;
    NMBondManager *bond_manager;
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
complete_connection(NMDevice            *device,
                    NMConnection        *connection,
                    const char          *specific_object,
                    NMConnection *const *existing_connections,
                    GError             **error)
{
    nm_utils_complete_generic(nm_device_get_platform(device),
                              connection,
                              NM_SETTING_BOND_SETTING_NAME,
                              existing_connections,
                              NULL,
                              _("Bond connection"),
                              "bond",
                              NULL,
                              TRUE);

    _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_BOND);

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
    NMDeviceBond  *self    = NM_DEVICE_BOND(device);
    NMSettingBond *s_bond  = _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_BOND);
    int            ifindex = nm_device_get_ifindex(device);
    NMBondMode     mode    = NM_BOND_MODE_UNKNOWN;
    const char   **options;

    /* Read bond options from sysfs and update the Bond setting to match */
    options = nm_setting_bond_get_valid_options(NULL);
    for (; options[0]; options++) {
        const char   *option = options[0];
        gs_free char *value  = NULL;
        char         *p;

        if (NM_IN_STRSET(option,
                         NM_SETTING_BOND_OPTION_ACTIVE_SLAVE,
                         NM_SETTING_BOND_OPTION_BALANCE_SLB))
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
controller_update_port_connection(NMDevice     *self,
                                  NMDevice     *port,
                                  NMConnection *connection,
                                  GError      **error)
{
    NMSettingBondPort    *s_port;
    int                   ifindex_port       = nm_device_get_ifindex(port);
    NMConnection         *applied_connection = nm_device_get_applied_connection(self);
    const NMPlatformLink *pllink;

    g_return_val_if_fail(ifindex_port > 0, FALSE);

    s_port = _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_BOND_PORT);
    pllink = nm_platform_link_get(nm_device_get_platform(port), ifindex_port);

    if (pllink && pllink->port_kind == NM_PORT_KIND_BOND)
        g_object_set(s_port,
                     NM_SETTING_BOND_PORT_QUEUE_ID,
                     pllink->port_data.bond.queue_id,
                     NM_SETTING_BOND_PORT_PRIO,
                     pllink->port_data.bond.prio,
                     NULL);

    g_object_set(nm_connection_get_setting_connection(connection),
                 NM_SETTING_CONNECTION_MASTER,
                 nm_connection_get_uuid(applied_connection),
                 NM_SETTING_CONNECTION_SLAVE_TYPE,
                 NM_SETTING_BOND_SETTING_NAME,
                 NULL);
    return TRUE;
}

static void
set_arp_targets(NMDevice *device, const char *cur_arp_ip_target, const char *new_arp_ip_target)
{
    gs_unref_ptrarray GPtrArray *free_list = NULL;
    gs_free const char         **cur_strv  = NULL;
    gs_free const char         **new_strv  = NULL;
    gsize                        cur_len;
    gsize                        new_len;
    gsize                        i;
    gsize                        j;

    cur_strv =
        nm_strsplit_set_full(cur_arp_ip_target, NM_ASCII_SPACES, NM_STRSPLIT_SET_FLAGS_STRSTRIP);
    new_strv = nm_utils_bond_option_ip_split(new_arp_ip_target);

    cur_len = NM_PTRARRAY_LEN(cur_strv);
    new_len = NM_PTRARRAY_LEN(new_strv);

    if (new_len > 0) {
        for (j = 0, i = 0; i < new_len; i++) {
            const char *s;
            in_addr_t   a4;

            s = new_strv[i];
            if (nm_inet_parse_bin(AF_INET, s, NULL, &a4)) {
                char sbuf[INET_ADDRSTRLEN];

                nm_inet4_ntop(a4, sbuf);
                if (!nm_streq(s, sbuf)) {
                    if (!free_list)
                        free_list = g_ptr_array_new_with_free_func(g_free);
                    s = g_strdup(sbuf);
                    g_ptr_array_add(free_list, (gpointer) s);
                }
            }

            if (nm_strv_find_first(new_strv, i, s) < 0)
                new_strv[j++] = s;
        }
        new_strv[j] = NULL;
        new_len     = j;
    }

    if (cur_len == 0 && new_len == 0)
        return;

    if (nm_strv_equal(cur_strv, new_strv))
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
    const char   *value;

    value = nm_setting_bond_get_option_normalized(s_bond, opt);
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
        nm_setting_bond_get_option_normalized(s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET));
}

static guint8
_bond_arp_ip_target_to_platform(const char *value, in_addr_t out[static NM_BOND_MAX_ARP_TARGETS])
{
    gs_free const char **ip = NULL;
    in_addr_t            in_a;
    int                  i;
    int                  added = 0;

    ip = nm_utils_bond_option_ip_split(value);

    if (!ip)
        return added;

    for (i = 0; ip[i]; i++) {
        if (added > NM_BOND_MAX_ARP_TARGETS - 1)
            break;
        if (!nm_inet_parse_bin(AF_INET, ip[i], NULL, &in_a))
            nm_assert_not_reached(); /* verify() already validated the IP addresses */

        out[added++] = in_a;
    }
    return added;
}

static guint8
_bond_ns_ip6_target_to_platform(const char     *value,
                                struct in6_addr out[static NM_BOND_MAX_ARP_TARGETS])
{
    gs_free const char **ip = NULL;
    struct in6_addr      in6_a;
    int                  i;
    int                  added = 0;

    ip = nm_utils_bond_option_ip_split(value);

    if (!ip)
        return added;

    for (i = 0; ip[i]; i++) {
        if (added > NM_BOND_MAX_ARP_TARGETS - 1)
            break;
        if (!nm_inet_parse_bin(AF_INET6, ip[i], NULL, &in6_a))
            nm_assert_not_reached(); /* verify() already validated the IP addresses */

        out[added++] = in6_a;
    }
    return added;
}

static int
_setting_bond_primary_opt_as_ifindex(NMSettingBond *s_bond)
{
    const char *primary_str;
    int         ifindex = 0;

    primary_str = nm_setting_bond_get_option_normalized(s_bond, NM_SETTING_BOND_OPTION_PRIMARY);

    if (primary_str != NULL)
        ifindex = nm_platform_link_get_ifindex(NM_PLATFORM_GET, primary_str);

    return ifindex;
}

static void
_platform_lnk_bond_init_from_setting(NMSettingBond *s_bond, NMPlatformLnkBond *props)
{
    const char *opt_value;

#define _v_fcn(fcn, s_bond, opt) (fcn(nm_setting_bond_get_option_normalized((s_bond), (opt))))
#define _v_u8(s_bond, opt)       _nm_setting_bond_opt_value_as_u8((s_bond), (opt))
#define _v_u16(s_bond, opt)      _nm_setting_bond_opt_value_as_u16((s_bond), (opt))
#define _v_u32(s_bond, opt)      _nm_setting_bond_opt_value_as_u32((s_bond), (opt))
#define _v_intbool(s_bond, opt)  _nm_setting_bond_opt_value_as_intbool((s_bond), (opt))

    *props = (NMPlatformLnkBond){
        .mode      = _v_fcn(_nm_setting_bond_mode_from_string, s_bond, NM_SETTING_BOND_OPTION_MODE),
        .primary   = _setting_bond_primary_opt_as_ifindex(s_bond),
        .miimon    = _v_u32(s_bond, NM_SETTING_BOND_OPTION_MIIMON),
        .updelay   = _v_u32(s_bond, NM_SETTING_BOND_OPTION_UPDELAY),
        .downdelay = _v_u32(s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY),
        .arp_interval      = _v_u32(s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL),
        .resend_igmp       = _v_u32(s_bond, NM_SETTING_BOND_OPTION_RESEND_IGMP),
        .min_links         = _v_u32(s_bond, NM_SETTING_BOND_OPTION_MIN_LINKS),
        .lp_interval       = _v_u32(s_bond, NM_SETTING_BOND_OPTION_LP_INTERVAL),
        .packets_per_port  = _v_u32(s_bond, NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE),
        .peer_notif_delay  = _v_u32(s_bond, NM_SETTING_BOND_OPTION_PEER_NOTIF_DELAY),
        .arp_all_targets   = _v_fcn(_nm_setting_bond_arp_all_targets_from_string,
                                  s_bond,
                                  NM_SETTING_BOND_OPTION_ARP_ALL_TARGETS),
        .arp_validate      = _v_fcn(_nm_setting_bond_arp_validate_from_string,
                               s_bond,
                               NM_SETTING_BOND_OPTION_ARP_VALIDATE),
        .ad_actor_sys_prio = _v_u16(s_bond, NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO),
        .ad_user_port_key  = _v_u16(s_bond, NM_SETTING_BOND_OPTION_AD_USER_PORT_KEY),
        .primary_reselect  = _v_fcn(_nm_setting_bond_primary_reselect_from_string,
                                   s_bond,
                                   NM_SETTING_BOND_OPTION_PRIMARY_RESELECT),
        .fail_over_mac     = _v_fcn(_nm_setting_bond_fail_over_mac_from_string,
                                s_bond,
                                NM_SETTING_BOND_OPTION_FAIL_OVER_MAC),
        .xmit_hash_policy  = _v_fcn(_nm_setting_bond_xmit_hash_policy_from_string,
                                   s_bond,
                                   NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY),
        .num_grat_arp      = _v_u8(s_bond, NM_SETTING_BOND_OPTION_NUM_GRAT_ARP),
        .all_ports_active  = _v_u8(s_bond, NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE),
        .arp_missed_max    = _v_u8(s_bond, NM_SETTING_BOND_OPTION_ARP_MISSED_MAX),
        .lacp_active       = _v_fcn(_nm_setting_bond_lacp_active_from_string,
                              s_bond,
                              NM_SETTING_BOND_OPTION_LACP_ACTIVE),
        .lacp_rate         = _v_fcn(_nm_setting_bond_lacp_rate_from_string,
                            s_bond,
                            NM_SETTING_BOND_OPTION_LACP_RATE),
        .ad_select         = _v_fcn(_nm_setting_bond_ad_select_from_string,
                            s_bond,
                            NM_SETTING_BOND_OPTION_AD_SELECT),
        .use_carrier       = _v_intbool(s_bond, NM_SETTING_BOND_OPTION_USE_CARRIER),
        .tlb_dynamic_lb    = _v_intbool(s_bond, NM_SETTING_BOND_OPTION_TLB_DYNAMIC_LB),
    };

    nm_ether_addr_from_string(
        &props->ad_actor_system,
        nm_setting_bond_get_option_normalized(s_bond, NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM));

    opt_value = nm_setting_bond_get_option_normalized(s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET);
    if (opt_value != NULL)
        props->arp_ip_targets_num =
            _bond_arp_ip_target_to_platform(opt_value, props->arp_ip_target);

    opt_value = nm_setting_bond_get_option_normalized(s_bond, NM_SETTING_BOND_OPTION_NS_IP6_TARGET);
    if (opt_value != NULL)
        props->ns_ip6_targets_num =
            _bond_ns_ip6_target_to_platform(opt_value, props->ns_ip6_target);

    props->miimon_has           = !props->arp_interval && !props->arp_validate;
    props->updelay_has          = props->miimon_has && props->miimon;
    props->downdelay_has        = props->miimon_has && props->miimon;
    props->peer_notif_delay_has = (props->miimon || props->arp_interval) && props->peer_notif_delay;
    props->resend_igmp_has      = props->resend_igmp != 1;
    props->lp_interval_has      = props->lp_interval != 1;
    props->tlb_dynamic_lb_has   = NM_IN_SET(props->mode, NM_BOND_MODE_TLB, NM_BOND_MODE_ALB);
    props->lacp_active_has      = NM_IN_SET(props->mode, NM_BOND_MODE_8023AD);
}

static void
_balance_slb_cb(NMBondManager *bond_manager, NMBondManagerEventType event_type, gpointer user_data)
{
    NMDevice     *device = user_data;
    NMDeviceBond *self   = NM_DEVICE_BOND(device);

    nm_assert(NM_IS_DEVICE_BOND(self));
    nm_assert(self->bond_manager == bond_manager);

    switch (event_type) {
    case NM_BOND_MANAGER_EVENT_TYPE_STATE:
        switch (nm_bond_manager_get_state(bond_manager)) {
        case NM_OPTION_BOOL_FALSE:
            if (nm_device_get_state(device) <= NM_DEVICE_STATE_ACTIVATED) {
                _LOGD(LOGD_BOND, "balance-slb: failed");
                nm_device_state_changed(device,
                                        NM_DEVICE_STATE_FAILED,
                                        NM_DEVICE_STATE_REASON_CONFIG_FAILED);
            }
            return;
        case NM_OPTION_BOOL_TRUE:
            if (nm_device_get_state(device) <= NM_DEVICE_STATE_ACTIVATED
                && nm_device_devip_get_state(device, AF_UNSPEC) <= NM_DEVICE_IP_STATE_PENDING) {
                nm_device_devip_set_state(device, AF_UNSPEC, NM_DEVICE_IP_STATE_READY, NULL);
            }
            return;
        case NM_OPTION_BOOL_DEFAULT:
            if (nm_device_get_state(device) <= NM_DEVICE_STATE_ACTIVATED
                && nm_device_devip_get_state(device, AF_UNSPEC) == NM_DEVICE_IP_STATE_READY) {
                /* We are again busy. We can also go back to "pending" from "ready".
                 * If ip-config state is not yet complete, this will further delay it.
                 * Otherwise, it should have no effect. */
                nm_device_devip_set_state(device, AF_UNSPEC, NM_DEVICE_IP_STATE_PENDING, NULL);
            }
            return;
        }
        nm_assert_not_reached();
        return;
    }

    nm_assert_not_reached();
}

static void
_balance_slb_setup(NMDeviceBond *self, NMConnection *connection)
{
    int            ifindex     = nm_device_get_ifindex(NM_DEVICE(self));
    gboolean       balance_slb = FALSE;
    const char    *uuid;
    NMSettingBond *s_bond;

    if (ifindex > 0 && connection && (s_bond = nm_connection_get_setting_bond(connection)))
        balance_slb = _v_intbool(s_bond, NM_SETTING_BOND_OPTION_BALANCE_SLB);

    if (!balance_slb) {
        if (nm_clear_pointer(&self->bond_manager, nm_bond_manager_destroy)) {
            _LOGD(LOGD_BOND, "balance-slb: stopped");
            nm_device_devip_set_state(NM_DEVICE(self), AF_UNSPEC, NM_DEVICE_IP_STATE_NONE, NULL);
        }
        return;
    }

    uuid = nm_connection_get_uuid(connection);

    if (self->bond_manager) {
        if (nm_bond_manager_get_ifindex(self->bond_manager) == ifindex
            && nm_streq0(nm_bond_manager_get_connection_uuid(self->bond_manager), uuid)) {
            _LOGD(LOGD_BOND, "balance-slb: reapply");
            nm_bond_manager_reapply(self->bond_manager);
            return;
        }
        nm_clear_pointer(&self->bond_manager, nm_bond_manager_destroy);
        _LOGD(LOGD_BOND, "balance-slb: restart");
    }

    _LOGD(LOGD_BOND, "balance-slb: start");
    if (nm_device_devip_get_state(NM_DEVICE(self), AF_UNSPEC) < NM_DEVICE_IP_STATE_PENDING)
        nm_device_devip_set_state(NM_DEVICE(self), AF_UNSPEC, NM_DEVICE_IP_STATE_PENDING, NULL);
    self->bond_manager = nm_bond_manager_new(nm_device_get_platform(NM_DEVICE(self)),
                                             ifindex,
                                             uuid,
                                             _balance_slb_cb,
                                             self);
    nm_assert(nm_bond_manager_get_state(self->bond_manager) == NM_OPTION_BOOL_DEFAULT);
}

static NMActStageReturn
act_stage1_prepare(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMDeviceBond     *self = NM_DEVICE_BOND(device);
    NMActStageReturn  ret  = NM_ACT_STAGE_RETURN_SUCCESS;
    NMConnection     *connection;
    NMSettingBond    *s_bond;
    NMPlatformLnkBond props;
    int               r;
    int               ifindex = nm_device_get_ifindex(device);

    connection = nm_device_get_applied_connection(device);
    g_return_val_if_fail(connection, NM_ACT_STAGE_RETURN_FAILURE);

    s_bond = nm_connection_get_setting_bond(connection);
    g_return_val_if_fail(s_bond, NM_ACT_STAGE_RETURN_FAILURE);

    if (nm_device_sys_iface_state_is_external(device))
        return NM_ACT_STAGE_RETURN_SUCCESS;

    _balance_slb_setup(self, connection);

    if (nm_device_sys_iface_state_is_external_or_assume(device))
        return NM_ACT_STAGE_RETURN_SUCCESS;

    _platform_lnk_bond_init_from_setting(s_bond, &props);

    /* Interface must be down to set bond options */
    nm_device_take_down(device, TRUE);
    r = nm_platform_link_bond_change(nm_device_get_platform(device), ifindex, &props);
    if (r < 0) {
        ret = NM_ACT_STAGE_RETURN_FAILURE;
        NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
    } else {
        if (!nm_device_hw_addr_set_cloned(device, nm_device_get_applied_connection(device), FALSE))
            ret = NM_ACT_STAGE_RETURN_FAILURE;
    }

    /* This is a workaround because netlink do not support ifname as primary */
    set_bond_attr_or_default(device, s_bond, NM_SETTING_BOND_OPTION_PRIMARY);

    nm_device_bring_up(device);

    return ret;
}

static void
commit_port_options(NMDevice *bond_device, NMDevice *port, NMSettingBondPort *s_port)
{
    NMBondMode     mode = NM_BOND_MODE_UNKNOWN;
    const char    *value;
    NMSettingBond *s_bond;
    gint32         prio;
    gboolean       prio_has;

    s_bond = nm_device_get_applied_setting(bond_device, NM_TYPE_SETTING_BOND);
    if (s_bond) {
        value = nm_setting_bond_get_option_normalized(s_bond, NM_SETTING_BOND_OPTION_MODE);
        mode  = _nm_setting_bond_mode_from_string(value);
    }

    prio = s_port ? nm_setting_bond_port_get_prio(s_port) : NM_BOND_PORT_PRIO_DEF;

    if (prio != 0) {
        /* The profile explicitly sets the priority. No matter what, we try to set it
         * in netlink. */
        prio_has = TRUE;
    } else if (!NM_IN_SET(mode, NM_BOND_MODE_ACTIVEBACKUP, NM_BOND_MODE_TLB, NM_BOND_MODE_ALB)) {
        /* The priority only is configurable with certain modes. If we don't have
         * one of those modes, don't try to set the priority explicitly to zero. */
        prio_has = FALSE;
    } else if (nm_platform_kernel_support_get_full(
                   NM_PLATFORM_KERNEL_SUPPORT_TYPE_IFLA_BOND_SLAVE_PRIO,
                   FALSE)
               == NM_OPTION_BOOL_TRUE) {
        /* We can only detect support if we have it. We cannot detect lack of support if
         * we don't have it.
         *
         * But we did explicitly detect support, so explicitly set the prio to zero. */
        prio_has = TRUE;
    } else {
        /* We either have an unsuitable mode or didn't detect kernel support for the
         * priority. Don't explicitly set priority to zero. It is already the default,
         * so it shouldn't be necessary. */
        prio_has = FALSE;
    }

    nm_platform_link_change(nm_device_get_platform(port),
                            nm_device_get_ifindex(port),
                            NULL,
                            &((NMPlatformLinkBondPort){
                                .queue_id = s_port ? nm_setting_bond_port_get_queue_id(s_port)
                                                   : NM_BOND_PORT_QUEUE_ID_DEF,
                                .prio     = prio_has ? prio : 0,
                                .prio_has = prio_has,
                            }),
                            0);
}

static NMTernary
attach_port(NMDevice                  *device,
            NMDevice                  *port,
            NMConnection              *connection,
            gboolean                   configure,
            GCancellable              *cancellable,
            NMDeviceAttachPortCallback callback,
            gpointer                   user_data)
{
    NMDeviceBond      *self = NM_DEVICE_BOND(device);
    NMSettingBondPort *s_port;

    nm_device_master_check_slave_physical_port(device, port, LOGD_BOND);

    if (configure) {
        gboolean success;

        nm_device_take_down(port, TRUE);
        success = nm_platform_link_enslave(nm_device_get_platform(device),
                                           nm_device_get_ip_ifindex(device),
                                           nm_device_get_ip_ifindex(port));
        nm_device_bring_up(port);

        if (!success) {
            _LOGI(LOGD_BOND, "attaching bond port %s: failed", nm_device_get_ip_iface(port));
            return FALSE;
        }

        s_port = _nm_connection_get_setting(connection, NM_TYPE_SETTING_BOND_PORT);

        commit_port_options(device, port, s_port);

        _LOGI(LOGD_BOND, "attached bond port %s", nm_device_get_ip_iface(port));
    } else
        _LOGI(LOGD_BOND, "bond port %s was attached", nm_device_get_ip_iface(port));

    return TRUE;
}

static NMTernary
detach_port(NMDevice                  *device,
            NMDevice                  *port,
            gboolean                   configure,
            GCancellable              *cancellable,
            NMDeviceAttachPortCallback callback,
            gpointer                   user_data)
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

    ifindex_slave = nm_device_get_ip_ifindex(port);

    if (ifindex_slave <= 0)
        _LOGD(LOGD_BOND, "bond port %s is already detached", nm_device_get_ip_iface(port));

    if (configure) {
        NMConnection   *applied;
        NMSettingWired *s_wired;
        const char     *cloned_mac;

        address = g_strdup(nm_device_get_hw_address(device));

        if (ifindex_slave > 0) {
            success = nm_platform_link_release(nm_device_get_platform(device),
                                               nm_device_get_ip_ifindex(device),
                                               ifindex_slave);

            if (success) {
                _LOGI(LOGD_BOND, "detached bond port %s", nm_device_get_ip_iface(port));
            } else {
                _LOGW(LOGD_BOND, "failed to detach bond port %s", nm_device_get_ip_iface(port));
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
            if (!nm_device_bring_up(port))
                _LOGW(LOGD_BOND, "detached bond port could not be brought up.");
        }
    } else {
        if (ifindex_slave > 0) {
            _LOGI(LOGD_BOND, "bond port %s was detached", nm_device_get_ip_iface(port));
        }
    }

    return TRUE;
}

static gboolean
create_and_realize(NMDevice              *device,
                   NMConnection          *connection,
                   NMDevice              *parent,
                   const NMPlatformLink **out_plink,
                   GError               **error)
{
    const char       *iface = nm_device_get_iface(device);
    NMSettingBond    *s_bond;
    NMPlatformLnkBond props;
    int               r;

    g_assert(iface);

    s_bond = nm_connection_get_setting_bond(connection);
    nm_assert(s_bond);

    _platform_lnk_bond_init_from_setting(s_bond, &props);

    r = nm_platform_link_bond_add(nm_device_get_platform(device), iface, &props, out_plink);
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
can_reapply_change(NMDevice   *device,
                   const char *setting_name,
                   NMSetting  *s_old,
                   NMSetting  *s_new,
                   GHashTable *diffs,
                   GError    **error)
{
    NMDeviceClass *device_class;

    /* Only handle bond setting here, delegate other settings to parent class */
    if (nm_streq(setting_name, NM_SETTING_BOND_SETTING_NAME)) {
        NMSettingBond *s_a = NM_SETTING_BOND(s_old);
        NMSettingBond *s_b = NM_SETTING_BOND(s_new);
        const char   **option_list;

        if (!nm_device_hash_check_invalid_keys(diffs,
                                               NM_SETTING_BOND_SETTING_NAME,
                                               error,
                                               NM_SETTING_BOND_OPTIONS))
            return FALSE;

        option_list = nm_setting_bond_get_valid_options(NULL);

        for (; *option_list; ++option_list) {
            const char *name = *option_list;

            /* We support changes to these */
            if (NM_IN_STRSET(name, OPTIONS_REAPPLY_FULL, NM_SETTING_BOND_OPTION_BALANCE_SLB))
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
    NMDeviceBond  *self = NM_DEVICE_BOND(device);
    NMSettingBond *s_bond;
    const char    *value;
    NMBondMode     mode;

    NM_DEVICE_CLASS(nm_device_bond_parent_class)->reapply_connection(device, con_old, con_new);

    _LOGD(LOGD_BOND, "reapplying bond settings");
    s_bond = nm_connection_get_setting_bond(con_new);
    g_return_if_fail(s_bond);

    value = nm_setting_bond_get_option_normalized(s_bond, NM_SETTING_BOND_OPTION_MODE);
    mode  = _nm_setting_bond_mode_from_string(value);
    g_return_if_fail(mode != NM_BOND_MODE_UNKNOWN);

    /* Below we set only the bond options that kernel allows to modify
     * while keeping the bond interface up */

    set_bond_arp_ip_targets(device, s_bond);

    set_bond_attrs_or_default(device, s_bond, NM_MAKE_STRV(OPTIONS_REAPPLY_SUBSET));

    _balance_slb_setup(self, con_new);
}

static void
deactivate(NMDevice *device)
{
    NMDeviceBond *self = NM_DEVICE_BOND(device);

    _balance_slb_setup(self, NULL);
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
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("HwAddress", "s", NM_DEVICE_HW_ADDRESS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Carrier", "b", NM_DEVICE_CARRIER),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Slaves", "ao", NM_DEVICE_SLAVES), ), ),
};

static void
nm_device_bond_class_init(NMDeviceBondClass *klass)
{
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_bond);

    device_class->connection_type_supported        = NM_SETTING_BOND_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_BOND_SETTING_NAME;
    device_class->link_types                       = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_BOND);

    device_class->is_master                = TRUE;
    device_class->get_generic_capabilities = get_generic_capabilities;
    device_class->complete_connection      = complete_connection;

    device_class->update_connection              = update_connection;
    device_class->master_update_slave_connection = controller_update_port_connection;

    device_class->create_and_realize                             = create_and_realize;
    device_class->act_stage1_prepare                             = act_stage1_prepare;
    device_class->act_stage1_prepare_also_for_external_or_assume = TRUE;
    device_class->get_configured_mtu = nm_device_get_configured_mtu_for_wired;
    device_class->attach_port        = attach_port;
    device_class->detach_port        = detach_port;
    device_class->can_reapply_change = can_reapply_change;
    device_class->reapply_connection = reapply_connection;
    device_class->deactivate         = deactivate;
}

/*****************************************************************************/

#define NM_TYPE_BOND_DEVICE_FACTORY (nm_bond_device_factory_get_type())
#define NM_BOND_DEVICE_FACTORY(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_BOND_DEVICE_FACTORY, NMBondDeviceFactory))

static NMDevice *
create_device(NMDeviceFactory      *factory,
              const char           *iface,
              const NMPlatformLink *plink,
              NMConnection         *connection,
              gboolean             *out_ignore)
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
