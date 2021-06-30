/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 - 2013 Red Hat, Inc.
 */

#include "libnm-core/nm-default-libnm-core.h"

#include "nm-setting-bond.h"

#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "nm-libnm-core-intern/nm-libnm-core-utils.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-connection-private.h"
#include "nm-setting-infiniband.h"
#include "nm-core-internal.h"

/*****************************************************************************/

/**
 * SECTION:nm-setting-bond
 * @short_description: Describes connection properties for bonds
 *
 * The #NMSettingBond object is a #NMSetting subclass that describes properties
 * necessary for bond connections.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingBond, PROP_OPTIONS, );

typedef struct {
    GHashTable *       options;
    NMUtilsNamedValue *options_idx_cache;
} NMSettingBondPrivate;

G_DEFINE_TYPE(NMSettingBond, nm_setting_bond, NM_TYPE_SETTING)

#define NM_SETTING_BOND_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_BOND, NMSettingBondPrivate))

/*****************************************************************************/

static const char *const valid_options_lst[] = {
    /* mode must be the first element. nm-device-bond.c relies on that. */
    NM_SETTING_BOND_OPTION_MODE,
    NM_SETTING_BOND_OPTION_MIIMON,
    NM_SETTING_BOND_OPTION_DOWNDELAY,
    NM_SETTING_BOND_OPTION_UPDELAY,
    NM_SETTING_BOND_OPTION_ARP_INTERVAL,
    NM_SETTING_BOND_OPTION_ARP_IP_TARGET,
    NM_SETTING_BOND_OPTION_ARP_VALIDATE,
    NM_SETTING_BOND_OPTION_PRIMARY,
    NM_SETTING_BOND_OPTION_PRIMARY_RESELECT,
    NM_SETTING_BOND_OPTION_FAIL_OVER_MAC,
    NM_SETTING_BOND_OPTION_USE_CARRIER,
    NM_SETTING_BOND_OPTION_AD_SELECT,
    NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY,
    NM_SETTING_BOND_OPTION_RESEND_IGMP,
    NM_SETTING_BOND_OPTION_LACP_RATE,
    NM_SETTING_BOND_OPTION_ACTIVE_SLAVE,
    NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO,
    NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM,
    NM_SETTING_BOND_OPTION_AD_USER_PORT_KEY,
    NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE,
    NM_SETTING_BOND_OPTION_ARP_ALL_TARGETS,
    NM_SETTING_BOND_OPTION_MIN_LINKS,
    NM_SETTING_BOND_OPTION_NUM_GRAT_ARP,
    NM_SETTING_BOND_OPTION_NUM_UNSOL_NA,
    NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE,
    NM_SETTING_BOND_OPTION_TLB_DYNAMIC_LB,
    NM_SETTING_BOND_OPTION_LP_INTERVAL,
    NM_SETTING_BOND_OPTION_PEER_NOTIF_DELAY,
    NULL,
};

typedef struct {
    const char *       val;
    NMBondOptionType   opt_type;
    guint              min;
    guint              max;
    const char *const *list;
} OptionMeta;

static gboolean
_nm_assert_bond_meta(const OptionMeta *option_meta)
{
    nm_assert(option_meta);

    switch (option_meta->opt_type) {
    case NM_BOND_OPTION_TYPE_BOTH:
        nm_assert(option_meta->val);
        nm_assert(option_meta->list);
        nm_assert(option_meta->list[0]);
        nm_assert(option_meta->min == 0);
        nm_assert(option_meta->max == NM_PTRARRAY_LEN(option_meta->list) - 1);
        nm_assert(g_strv_contains(option_meta->list, option_meta->val));
        return TRUE;
    case NM_BOND_OPTION_TYPE_INT:
        nm_assert(option_meta->val);
        nm_assert(!option_meta->list);
        nm_assert(option_meta->min < option_meta->max);
        nm_assert(NM_STRCHAR_ALL(option_meta->val, ch, g_ascii_isdigit(ch)));
        nm_assert(NM_STRCHAR_ALL(option_meta->val, ch, g_ascii_isdigit(ch)));
        nm_assert(({
            _nm_utils_ascii_str_to_uint64(option_meta->val,
                                          10,
                                          option_meta->min,
                                          option_meta->max,
                                          0);
            errno == 0;
        }));
        return TRUE;
    case NM_BOND_OPTION_TYPE_IP:
        nm_assert(option_meta->val);
        /* fall-through */
    case NM_BOND_OPTION_TYPE_IFNAME:
    case NM_BOND_OPTION_TYPE_MAC:
        nm_assert(!option_meta->list);
        nm_assert(option_meta->min == 0);
        nm_assert(option_meta->max == 0);
        return TRUE;
    }

    nm_assert_not_reached();
    return FALSE;
}

static char const *const _option_default_strv_ad_select[] =
    NM_MAKE_STRV("stable", "bandwidth", "count");
static char const *const _option_default_strv_arp_all_targets[] = NM_MAKE_STRV("any", "all");
static char const *const _option_default_strv_arp_validate[] =
    NM_MAKE_STRV("none", "active", "backup", "all", "filter", "filter_active", "filter_backup");
static char const *const _option_default_strv_fail_over_mac[] =
    NM_MAKE_STRV("none", "active", "follow");
static char const *const _option_default_strv_lacp_rate[] = NM_MAKE_STRV("slow", "fast");
static char const *const _option_default_strv_mode[]      = NM_MAKE_STRV("balance-rr",
                                                                    "active-backup",
                                                                    "balance-xor",
                                                                    "broadcast",
                                                                    "802.3ad",
                                                                    "balance-tlb",
                                                                    "balance-alb");
static char const *const _option_default_strv_primary_reselect[] =
    NM_MAKE_STRV("always", "better", "failure");
static char const *const _option_default_strv_xmit_hash_policy[] =
    NM_MAKE_STRV("layer2", "layer3+4", "layer2+3", "encap2+3", "encap3+4", "vlan+srcmac");

static NM_UTILS_STRING_TABLE_LOOKUP_STRUCT_DEFINE(
    _get_option_meta,
    OptionMeta,
    {
        G_STATIC_ASSERT_EXPR(G_N_ELEMENTS(LIST) == G_N_ELEMENTS(valid_options_lst) - 1);

        if (NM_MORE_ASSERT_ONCE(5)) {
            int i;

            nm_assert(G_N_ELEMENTS(LIST) == NM_PTRARRAY_LEN(valid_options_lst));
            for (i = 0; i < G_N_ELEMENTS(LIST); i++)
                _nm_assert_bond_meta(&LIST[i].value);
            nm_assert(nm_streq(valid_options_lst[0], NM_SETTING_BOND_OPTION_MODE));
        }
    },
    { return NULL; },
    {NM_SETTING_BOND_OPTION_ACTIVE_SLAVE, {NULL, NM_BOND_OPTION_TYPE_IFNAME}},
    {NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO, {"65535", NM_BOND_OPTION_TYPE_INT, 1, 65535}},
    {NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM, {NULL, NM_BOND_OPTION_TYPE_MAC}},
    {NM_SETTING_BOND_OPTION_AD_SELECT,
     {"stable", NM_BOND_OPTION_TYPE_BOTH, 0, 2, _option_default_strv_ad_select}},
    {NM_SETTING_BOND_OPTION_AD_USER_PORT_KEY, {"0", NM_BOND_OPTION_TYPE_INT, 0, 1023}},
    {NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE, {"0", NM_BOND_OPTION_TYPE_INT, 0, 1}},
    {NM_SETTING_BOND_OPTION_ARP_ALL_TARGETS,
     {"any", NM_BOND_OPTION_TYPE_BOTH, 0, 1, _option_default_strv_arp_all_targets}},
    {NM_SETTING_BOND_OPTION_ARP_INTERVAL, {"0", NM_BOND_OPTION_TYPE_INT, 0, G_MAXINT}},
    {NM_SETTING_BOND_OPTION_ARP_IP_TARGET, {"", NM_BOND_OPTION_TYPE_IP}},
    {NM_SETTING_BOND_OPTION_ARP_VALIDATE,
     {"none", NM_BOND_OPTION_TYPE_BOTH, 0, 6, _option_default_strv_arp_validate}},
    {NM_SETTING_BOND_OPTION_DOWNDELAY, {"0", NM_BOND_OPTION_TYPE_INT, 0, G_MAXINT}},
    {NM_SETTING_BOND_OPTION_FAIL_OVER_MAC,
     {"none", NM_BOND_OPTION_TYPE_BOTH, 0, 2, _option_default_strv_fail_over_mac}},
    {NM_SETTING_BOND_OPTION_LACP_RATE,
     {"slow", NM_BOND_OPTION_TYPE_BOTH, 0, 1, _option_default_strv_lacp_rate}},
    {NM_SETTING_BOND_OPTION_LP_INTERVAL, {"1", NM_BOND_OPTION_TYPE_INT, 1, G_MAXINT}},
    {NM_SETTING_BOND_OPTION_MIIMON, {"100", NM_BOND_OPTION_TYPE_INT, 0, G_MAXINT}},
    {NM_SETTING_BOND_OPTION_MIN_LINKS, {"0", NM_BOND_OPTION_TYPE_INT, 0, G_MAXINT}},
    {NM_SETTING_BOND_OPTION_MODE,
     {"balance-rr", NM_BOND_OPTION_TYPE_BOTH, 0, 6, _option_default_strv_mode}},
    {NM_SETTING_BOND_OPTION_NUM_GRAT_ARP, {"1", NM_BOND_OPTION_TYPE_INT, 0, 255}},
    {NM_SETTING_BOND_OPTION_NUM_UNSOL_NA, {"1", NM_BOND_OPTION_TYPE_INT, 0, 255}},
    {NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE, {"1", NM_BOND_OPTION_TYPE_INT, 0, 65535}},
    {NM_SETTING_BOND_OPTION_PEER_NOTIF_DELAY, {"0", NM_BOND_OPTION_TYPE_INT, 0, G_MAXINT}},
    {NM_SETTING_BOND_OPTION_PRIMARY, {"", NM_BOND_OPTION_TYPE_IFNAME}},
    {NM_SETTING_BOND_OPTION_PRIMARY_RESELECT,
     {"always", NM_BOND_OPTION_TYPE_BOTH, 0, 2, _option_default_strv_primary_reselect}},
    {NM_SETTING_BOND_OPTION_RESEND_IGMP, {"1", NM_BOND_OPTION_TYPE_INT, 0, 255}},
    {NM_SETTING_BOND_OPTION_TLB_DYNAMIC_LB, {"1", NM_BOND_OPTION_TYPE_INT, 0, 1}},
    {NM_SETTING_BOND_OPTION_UPDELAY, {"0", NM_BOND_OPTION_TYPE_INT, 0, G_MAXINT}},
    {NM_SETTING_BOND_OPTION_USE_CARRIER, {"1", NM_BOND_OPTION_TYPE_INT, 0, 1}},
    {NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY,
     {"layer2", NM_BOND_OPTION_TYPE_BOTH, 0, 5, _option_default_strv_xmit_hash_policy}}, );

/*****************************************************************************/

#define BIT(x) (((guint32) 1) << (x))

static NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    _bond_option_unsupp_mode,
    guint32,
    { ; },
    { return 0; },
    {NM_SETTING_BOND_OPTION_ACTIVE_SLAVE,
     ~(BIT(NM_BOND_MODE_ACTIVEBACKUP) | BIT(NM_BOND_MODE_TLB) | BIT(NM_BOND_MODE_ALB))},
    {NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO, ~(BIT(NM_BOND_MODE_8023AD))},
    {NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM, ~(BIT(NM_BOND_MODE_8023AD))},
    {NM_SETTING_BOND_OPTION_AD_USER_PORT_KEY, ~(BIT(NM_BOND_MODE_8023AD))},
    {NM_SETTING_BOND_OPTION_ARP_INTERVAL,
     (BIT(NM_BOND_MODE_8023AD) | BIT(NM_BOND_MODE_TLB) | BIT(NM_BOND_MODE_ALB))},
    {NM_SETTING_BOND_OPTION_ARP_IP_TARGET,
     (BIT(NM_BOND_MODE_8023AD) | BIT(NM_BOND_MODE_TLB) | BIT(NM_BOND_MODE_ALB))},
    {NM_SETTING_BOND_OPTION_ARP_VALIDATE,
     (BIT(NM_BOND_MODE_8023AD) | BIT(NM_BOND_MODE_TLB) | BIT(NM_BOND_MODE_ALB))},
    {NM_SETTING_BOND_OPTION_LACP_RATE, ~(BIT(NM_BOND_MODE_8023AD))},
    {NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE, ~(BIT(NM_BOND_MODE_ROUNDROBIN))},
    {NM_SETTING_BOND_OPTION_PRIMARY,
     ~(BIT(NM_BOND_MODE_ACTIVEBACKUP) | BIT(NM_BOND_MODE_TLB) | BIT(NM_BOND_MODE_ALB))},
    {NM_SETTING_BOND_OPTION_TLB_DYNAMIC_LB, ~(BIT(NM_BOND_MODE_TLB) | BIT(NM_BOND_MODE_ALB))}, );

gboolean
_nm_setting_bond_option_supported(const char *option, NMBondMode mode)
{
    nm_assert(option);
    nm_assert(mode != NM_BOND_MODE_UNKNOWN);
    nm_assert(_NM_INT_NOT_NEGATIVE(mode) && mode < 32);

    return !NM_FLAGS_ANY(_bond_option_unsupp_mode(option), BIT(mode));
}

static const char *
_bond_get_option(NMSettingBond *self, const char *option)
{
    g_return_val_if_fail(NM_IS_SETTING_BOND(self), NULL);
    g_return_val_if_fail(option, NULL);

    return g_hash_table_lookup(NM_SETTING_BOND_GET_PRIVATE(self)->options, option);
}

static const char *
_bond_get_option_default(NMSettingBond *self, const char *option)
{
    const OptionMeta *option_meta;

    g_return_val_if_fail(NM_IS_SETTING_BOND(self), NULL);

    option_meta = _get_option_meta(option);

    g_return_val_if_fail(option_meta, NULL);

    return option_meta->val;
}

static const char *
_bond_get_option_or_default(NMSettingBond *self, const char *option)
{
    return _bond_get_option(self, option) ?: _bond_get_option_default(self, option);
}

static const char *
_bond_get_option_normalized(NMSettingBond *self, const char *option, gboolean get_default_only)
{
    const char *mode_str;
    NMBondMode  mode;
    const char *value = NULL;

    g_return_val_if_fail(NM_IS_SETTING_BOND(self), NULL);
    g_return_val_if_fail(option, NULL);

    mode_str = _bond_get_option_or_default(self, NM_SETTING_BOND_OPTION_MODE);
    mode     = _nm_setting_bond_mode_from_string(mode_str);

    if (mode == NM_BOND_MODE_UNKNOWN) {
        /* the mode is unknown, consequently, there is no normalized/default
         * value either. */
        return NULL;
    }

    if (!_nm_setting_bond_option_supported(option, mode))
        return NULL;

    /* Apply custom NetworkManager policies here */
    if (!get_default_only) {
        if (NM_IN_STRSET(option,
                         NM_SETTING_BOND_OPTION_ARP_INTERVAL,
                         NM_SETTING_BOND_OPTION_ARP_IP_TARGET)) {
            int miimon;

            /* if arp_interval is explicitly set and miimon is not, then disable miimon
             * (and related updelay and downdelay) as recommended by the kernel docs */
            miimon =
                _nm_utils_ascii_str_to_int64(_bond_get_option(self, NM_SETTING_BOND_OPTION_MIIMON),
                                             10,
                                             0,
                                             G_MAXINT,
                                             0);
            if (miimon != 0) {
                /* miimon is enabled. arp_interval values are unset. */
                if (nm_streq(option, NM_SETTING_BOND_OPTION_ARP_INTERVAL))
                    return "0";
                return "";
            }
            value = _bond_get_option(self, option);
        } else if (NM_IN_STRSET(option,
                                NM_SETTING_BOND_OPTION_NUM_GRAT_ARP,
                                NM_SETTING_BOND_OPTION_NUM_UNSOL_NA)) {
            /* just get one of the 2, at kernel level they're the same bond option */
            value = _bond_get_option(self, NM_SETTING_BOND_OPTION_NUM_GRAT_ARP);
            if (!value)
                value = _bond_get_option(self, NM_SETTING_BOND_OPTION_NUM_UNSOL_NA);
        } else if (NM_IN_STRSET(option, NM_SETTING_BOND_OPTION_ACTIVE_SLAVE)) {
            /* "active_slave" is deprecated, and an alias for "primary". The property
             * itself always normalizes to %NULL. */
            value = NULL;
        } else if (NM_IN_STRSET(option, NM_SETTING_BOND_OPTION_PRIMARY)) {
            /* "active_slave" is deprecated, and an alias for "primary". */
            value = _bond_get_option(self, NM_SETTING_BOND_OPTION_PRIMARY);
            if (!value)
                value = _bond_get_option(self, NM_SETTING_BOND_OPTION_ACTIVE_SLAVE);
        } else
            value = _bond_get_option(self, option);

        if (value)
            return value;
    }

    /* Apply rules that change the default value of an option */
    if (nm_streq(option, NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM)) {
        /* The default value depends on the current mode */
        if (mode == NM_BOND_MODE_8023AD)
            return NM_BOND_AD_ACTOR_SYSTEM_DEFAULT;
        return "";
    }

    return _bond_get_option_or_default(self, option);
}

const char *
nm_setting_bond_get_option_or_default(NMSettingBond *self, const char *option)
{
    g_return_val_if_fail(NM_IS_SETTING_BOND(self), NULL);
    g_return_val_if_fail(option, NULL);

    return _bond_get_option_normalized(self, option, FALSE);
}

static int
_atoi(const char *value)
{
    int v;

    v = _nm_utils_ascii_str_to_int64(value, 10, 0, G_MAXINT, -1);
    nm_assert(v >= 0);
    return v;
};

/**
 * nm_setting_bond_get_num_options:
 * @setting: the #NMSettingBond
 *
 * Returns the number of options that should be set for this bond when it
 * is activated. This can be used to retrieve each option individually
 * using nm_setting_bond_get_option().
 *
 * Returns: the number of bonding options
 **/
guint32
nm_setting_bond_get_num_options(NMSettingBond *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BOND(setting), 0);

    return g_hash_table_size(NM_SETTING_BOND_GET_PRIVATE(setting)->options);
}

static int
_get_option_sort(gconstpointer p_a, gconstpointer p_b, gpointer _unused)
{
    const char *a = *((const char *const *) p_a);
    const char *b = *((const char *const *) p_b);

    NM_CMP_DIRECT(nm_streq(b, NM_SETTING_BOND_OPTION_MODE),
                  nm_streq(a, NM_SETTING_BOND_OPTION_MODE));
    NM_CMP_DIRECT_STRCMP(a, b);
    nm_assert_not_reached();
    return 0;
}

static void
_ensure_options_idx_cache(NMSettingBondPrivate *priv)
{
    if (!G_UNLIKELY(priv->options_idx_cache))
        priv->options_idx_cache = nm_utils_named_values_from_strdict_full(priv->options,
                                                                          NULL,
                                                                          _get_option_sort,
                                                                          NULL,
                                                                          NULL,
                                                                          0,
                                                                          NULL);
}

/**
 * nm_setting_bond_get_option:
 * @setting: the #NMSettingBond
 * @idx: index of the desired option, from 0 to
 * nm_setting_bond_get_num_options() - 1
 * @out_name: (out) (transfer none): on return, the name of the bonding option;
 *   this value is owned by the setting and should not be modified
 * @out_value: (out) (transfer none): on return, the value of the name of the
 *   bonding option; this value is owned by the setting and should not be
 *   modified
 *
 * Given an index, return the value of the bonding option at that index.  Indexes
 * are *not* guaranteed to be static across modifications to options done by
 * nm_setting_bond_add_option() and nm_setting_bond_remove_option(),
 * and should not be used to refer to options except for short periods of time
 * such as during option iteration.
 *
 * Returns: %TRUE on success if the index was valid and an option was found,
 * %FALSE if the index was invalid (ie, greater than the number of options
 * currently held by the setting)
 **/
gboolean
nm_setting_bond_get_option(NMSettingBond *setting,
                           guint32        idx,
                           const char **  out_name,
                           const char **  out_value)
{
    NMSettingBondPrivate *priv;
    guint                 len;

    g_return_val_if_fail(NM_IS_SETTING_BOND(setting), FALSE);

    priv = NM_SETTING_BOND_GET_PRIVATE(setting);

    len = g_hash_table_size(priv->options);
    if (idx >= len)
        return FALSE;

    _ensure_options_idx_cache(priv);

    NM_SET_OUT(out_name, priv->options_idx_cache[idx].name);
    NM_SET_OUT(out_value, priv->options_idx_cache[idx].value_str);
    return TRUE;
}

static gboolean
validate_int(const char *name, const char *value, const OptionMeta *option_meta)
{
    guint64 num;

    if (!NM_STRCHAR_ALL(value, ch, g_ascii_isdigit(ch)))
        return FALSE;

    num = _nm_utils_ascii_str_to_uint64(value, 10, option_meta->min, option_meta->max, G_MAXUINT64);
    if (num == G_MAXUINT64 && errno != 0)
        return FALSE;

    return TRUE;
}

static gboolean
validate_list(const char *name, const char *value, const OptionMeta *option_meta)
{
    int i;

    nm_assert(option_meta->list);

    for (i = 0; option_meta->list[i]; i++) {
        if (nm_streq(option_meta->list[i], value))
            return TRUE;
    }
    return FALSE;
}

static gboolean
validate_ip(const char *name, const char *value, GError **error)
{
    gs_free const char **addrs = NULL;
    gsize                i;

    addrs = nm_utils_bond_option_arp_ip_targets_split(value);
    if (!addrs) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' option is empty"),
                    name);
        return FALSE;
    }
    for (i = 0; addrs[i]; i++) {
        if (!nm_utils_parse_inaddr_bin(AF_INET, addrs[i], NULL, NULL)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' is not a valid IPv4 address for '%s' option"),
                        addrs[i],
                        name);
            return FALSE;
        }
    }
    return TRUE;
}

static gboolean
validate_ifname(const char *name, const char *value)
{
    return nm_utils_ifname_valid_kernel(value, NULL);
}

gboolean
_nm_setting_bond_validate_option(const char *name, const char *value, GError **error)
{
    const OptionMeta *option_meta;
    gboolean          success;

    option_meta = _get_option_meta(name);
    if (!option_meta) {
        if (!name) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("missing option name"));
        } else {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("invalid option '%s'"),
                        name);
        }
        return FALSE;
    }

    if (!value)
        return TRUE;

    switch (option_meta->opt_type) {
    case NM_BOND_OPTION_TYPE_INT:
        success = validate_int(name, value, option_meta);
        goto handle_error;
    case NM_BOND_OPTION_TYPE_BOTH:
        success =
            (validate_int(name, value, option_meta) || validate_list(name, value, option_meta));
        goto handle_error;
    case NM_BOND_OPTION_TYPE_IP:
        nm_assert(nm_streq0(name, NM_SETTING_BOND_OPTION_ARP_IP_TARGET));
        return validate_ip(name, value, error);
    case NM_BOND_OPTION_TYPE_MAC:
        success = nm_utils_hwaddr_valid(value, ETH_ALEN);
        goto handle_error;
    case NM_BOND_OPTION_TYPE_IFNAME:
        success = validate_ifname(name, value);
        goto handle_error;
    }

    nm_assert_not_reached();
    success = FALSE;

handle_error:
    if (!success) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("invalid value '%s' for option '%s'"),
                    value,
                    name);
    }
    return success;
}

/**
 * nm_setting_bond_validate_option:
 * @name: the name of the option to validate
 * @value (allow-none): the value of the option to validate.
 *
 * Checks whether @name is a valid bond option and @value is a valid value for
 * the @name. If @value is %NULL, the function only validates the option name.
 *
 * Returns: %TRUE, if the @value is valid for the given name.
 * If the @name is not a valid option, %FALSE will be returned.
 **/
gboolean
nm_setting_bond_validate_option(const char *name, const char *value)
{
    return _nm_setting_bond_validate_option(name, value, NULL);
}

/**
 * nm_setting_bond_get_option_by_name:
 * @setting: the #NMSettingBond
 * @name: the option name for which to retrieve the value
 *
 * Returns the value associated with the bonding option specified by
 * @name, if it exists.
 *
 * Returns: the value, or %NULL if the key/value pair was never added to the
 * setting; the value is owned by the setting and must not be modified
 **/
const char *
nm_setting_bond_get_option_by_name(NMSettingBond *setting, const char *name)
{
    g_return_val_if_fail(NM_IS_SETTING_BOND(setting), NULL);

    return _bond_get_option(setting, name);
}

/**
 * nm_setting_bond_add_option:
 * @setting: the #NMSettingBond
 * @name: name for the option
 * @value: value for the option
 *
 * Add an option to the table. Adding a new name replaces any existing name/value pair
 * that may already exist.
 *
 * Returns: returns %FALSE if either @name or @value is %NULL, in that case
 * the option is not set. Otherwise, the function does not fail and does not validate
 * the arguments. All validation happens via nm_connection_verify() or do basic validation
 * yourself with nm_setting_bond_validate_option().
 *
 * Note: Before 1.30, libnm would perform basic validation of the name and the value
 * via nm_setting_bond_validate_option() and reject the request by returning FALSE.
 * Since 1.30, libnm no longer rejects any values as the setter is not supposed
 * to perform validation.
 **/
gboolean
nm_setting_bond_add_option(NMSettingBond *setting, const char *name, const char *value)
{
    NMSettingBondPrivate *priv;

    g_return_val_if_fail(NM_IS_SETTING_BOND(setting), FALSE);

    if (!name)
        return FALSE;
    if (!value)
        return FALSE;

    priv = NM_SETTING_BOND_GET_PRIVATE(setting);

    nm_clear_g_free(&priv->options_idx_cache);
    g_hash_table_insert(priv->options, g_strdup(name), g_strdup(value));
    _notify(setting, PROP_OPTIONS);
    return TRUE;
}

/**
 * nm_setting_bond_remove_option:
 * @setting: the #NMSettingBond
 * @name: name of the option to remove
 *
 * Remove the bonding option referenced by @name from the internal option
 * list.
 *
 * Returns: %TRUE if the option was found and removed from the internal option
 * list, %FALSE if it was not.
 **/
gboolean
nm_setting_bond_remove_option(NMSettingBond *setting, const char *name)
{
    NMSettingBondPrivate *priv;

    g_return_val_if_fail(NM_IS_SETTING_BOND(setting), FALSE);

    priv = NM_SETTING_BOND_GET_PRIVATE(setting);

    if (!g_hash_table_remove(priv->options, name))
        return FALSE;

    nm_clear_g_free(&priv->options_idx_cache);
    _notify(setting, PROP_OPTIONS);
    return TRUE;
}

/**
 * nm_setting_bond_get_valid_options:
 * @setting: (allow-none): the #NMSettingBond
 *
 * Returns a list of valid bond options.
 *
 * The @setting argument is unused and may be passed as %NULL.
 *
 * Returns: (transfer none): a %NULL-terminated array of strings of valid bond options.
 **/
const char **
nm_setting_bond_get_valid_options(NMSettingBond *setting)
{
    return (const char **) valid_options_lst;
}

/**
 * nm_setting_bond_get_option_default:
 * @setting: the #NMSettingBond
 * @name: the name of the option
 *
 * Returns: the value of the bond option if not overridden by an entry in
 *   the #NMSettingBond:options property.
 **/
const char *
nm_setting_bond_get_option_default(NMSettingBond *setting, const char *name)
{
    g_return_val_if_fail(NM_IS_SETTING_BOND(setting), NULL);

    if (!name)
        return NULL;

    return _bond_get_option_normalized(setting, name, TRUE);
}

/**
 * nm_setting_bond_get_option_normalized:
 * @setting: the #NMSettingBond
 * @name: the name of the option
 *
 * Since: 1.24
 *
 * Returns: the value of the bond option after normalization, which is what NetworkManager
 *   will actually apply when activating the connection. %NULL if the option won't be applied
 *   to the connection.
 **/
const char *
nm_setting_bond_get_option_normalized(NMSettingBond *setting, const char *name)
{
    g_return_val_if_fail(NM_IS_SETTING_BOND(setting), NULL);
    g_return_val_if_fail(name, NULL);

    return _bond_get_option_normalized(setting, name, FALSE);
}

/**
 * nm_setting_bond_get_option_type:
 * @setting: the #NMSettingBond
 * @name: the name of the option
 *
 * Returns: the type of the bond option.
 **/
NMBondOptionType
_nm_setting_bond_get_option_type(NMSettingBond *setting, const char *name)
{
    const OptionMeta *option_meta;

    g_return_val_if_fail(NM_IS_SETTING_BOND(setting), NM_BOND_OPTION_TYPE_INT);

    option_meta = _get_option_meta(name);

    g_return_val_if_fail(option_meta, NM_BOND_OPTION_TYPE_INT);

    return option_meta->opt_type;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingBond *          self = NM_SETTING_BOND(setting);
    NMSettingBondPrivate *   priv = NM_SETTING_BOND_GET_PRIVATE(setting);
    int                      miimon;
    int                      arp_interval;
    int                      num_grat_arp;
    int                      num_unsol_na;
    int                      peer_notif_delay;
    const char *             mode_str;
    const char *             arp_ip_target = NULL;
    const char *             lacp_rate;
    const char *             primary;
    NMBondMode               bond_mode;
    guint                    i;
    const NMUtilsNamedValue *n;

    _ensure_options_idx_cache(priv);

    if (priv->options_idx_cache) {
        for (i = 0; priv->options_idx_cache[i].name; i++) {
            n = &priv->options_idx_cache[i];

            if (!n->value_str || !_nm_setting_bond_validate_option(n->name, n->value_str, error)) {
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_BOND_SETTING_NAME,
                               NM_SETTING_BOND_OPTIONS);
                return FALSE;
            }
        }
    }

    miimon       = _atoi(_bond_get_option_or_default(self, NM_SETTING_BOND_OPTION_MIIMON));
    arp_interval = _atoi(_bond_get_option_or_default(self, NM_SETTING_BOND_OPTION_ARP_INTERVAL));
    num_grat_arp = _atoi(_bond_get_option_or_default(self, NM_SETTING_BOND_OPTION_NUM_GRAT_ARP));
    num_unsol_na = _atoi(_bond_get_option_or_default(self, NM_SETTING_BOND_OPTION_NUM_UNSOL_NA));
    peer_notif_delay =
        _atoi(_bond_get_option_or_default(self, NM_SETTING_BOND_OPTION_PEER_NOTIF_DELAY));

    /* Option restrictions:
     *
     * arp_interval conflicts [ alb, tlb ]
     * arp_interval needs arp_ip_target
     * arp_validate does not work with [ BOND_MODE_8023AD, BOND_MODE_TLB, BOND_MODE_ALB ]
     * downdelay needs miimon
     * updelay needs miimon
     * peer_notif_delay needs miimon enabled
     * peer_notif_delay must be a miimon multiple
     * primary needs [ active-backup, tlb, alb ]
     */

    /* Verify bond mode */
    mode_str = _bond_get_option(self, NM_SETTING_BOND_OPTION_MODE);
    if (!mode_str) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("mandatory option '%s' is missing"),
                    NM_SETTING_BOND_OPTION_MODE);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
        return FALSE;
    }
    bond_mode = _nm_setting_bond_mode_from_string(mode_str);
    if (bond_mode == NM_BOND_MODE_UNKNOWN) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid value for '%s'"),
                    mode_str,
                    NM_SETTING_BOND_OPTION_MODE);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
        return FALSE;
    }

    /* Make sure mode is compatible with other settings */
    if (NM_IN_SET(bond_mode, NM_BOND_MODE_TLB, NM_BOND_MODE_ALB)) {
        if (arp_interval > 0) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s=%s' is incompatible with '%s > 0'"),
                        NM_SETTING_BOND_OPTION_MODE,
                        mode_str,
                        NM_SETTING_BOND_OPTION_ARP_INTERVAL);
            g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
            return FALSE;
        }
    }

    primary = _bond_get_option(self, NM_SETTING_BOND_OPTION_PRIMARY);
    if (NM_IN_SET(bond_mode, NM_BOND_MODE_ACTIVEBACKUP, NM_BOND_MODE_TLB, NM_BOND_MODE_ALB)) {
        GError *tmp_error = NULL;

        if (primary && !nm_utils_ifname_valid_kernel(primary, &tmp_error)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' is not valid for the '%s' option: %s"),
                        primary,
                        NM_SETTING_BOND_OPTION_PRIMARY,
                        tmp_error->message);
            g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
            g_error_free(tmp_error);
            return FALSE;
        }
    } else if (primary) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' option is only valid for '%s=%s'"),
                    NM_SETTING_BOND_OPTION_PRIMARY,
                    NM_SETTING_BOND_OPTION_MODE,
                    "active-backup");
        g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
        return FALSE;
    }

    if (connection && nm_connection_get_setting_infiniband(connection)) {
        if (bond_mode != NM_BOND_MODE_ACTIVEBACKUP) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s=%s' is not a valid configuration for '%s'"),
                        NM_SETTING_BOND_OPTION_MODE,
                        mode_str,
                        NM_SETTING_INFINIBAND_SETTING_NAME);
            g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
            return FALSE;
        }
    }

    if (miimon == 0) {
        /* updelay and downdelay need miimon to be enabled to be valid */
        if (_atoi(_bond_get_option_or_default(self, NM_SETTING_BOND_OPTION_UPDELAY))) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' option requires '%s' option to be enabled"),
                        NM_SETTING_BOND_OPTION_UPDELAY,
                        NM_SETTING_BOND_OPTION_MIIMON);
            g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
            return FALSE;
        }

        if (_atoi(_bond_get_option_or_default(self, NM_SETTING_BOND_OPTION_DOWNDELAY))) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' option requires '%s' option to be enabled"),
                        NM_SETTING_BOND_OPTION_DOWNDELAY,
                        NM_SETTING_BOND_OPTION_MIIMON);
            g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
            return FALSE;
        }
    }

    if (peer_notif_delay) {
        if (miimon == 0) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' option requires '%s' option to be enabled"),
                        NM_SETTING_BOND_OPTION_PEER_NOTIF_DELAY,
                        NM_SETTING_BOND_OPTION_MIIMON);
            g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
            return FALSE;
        }

        /* The code disables miimon when arp is set, so they never occur together.
         * But this occurs after this verification, so this check can occur in
         * an invalid state, when both arp and miimon are enabled. To assure not
         * dealing with an invalid state, this arp_interval == 0 condition,
         * that is implicit, was made explicit.
         */
        if ((peer_notif_delay % miimon) && (arp_interval == 0)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' option needs to be a value multiple of '%s' value"),
                        NM_SETTING_BOND_OPTION_PEER_NOTIF_DELAY,
                        NM_SETTING_BOND_OPTION_MIIMON);
            g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
            return FALSE;
        }
    }

    /* arp_ip_target can only be used with arp_interval, and must
     * contain a comma-separated list of IPv4 addresses.
     */
    arp_ip_target = _bond_get_option(self, NM_SETTING_BOND_OPTION_ARP_IP_TARGET);
    if (arp_interval > 0) {
        if (!arp_ip_target) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' option requires '%s' option to be set"),
                        NM_SETTING_BOND_OPTION_ARP_INTERVAL,
                        NM_SETTING_BOND_OPTION_ARP_IP_TARGET);
            g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
            return FALSE;
        }
    } else {
        if (arp_ip_target) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' option requires '%s' option to be set"),
                        NM_SETTING_BOND_OPTION_ARP_IP_TARGET,
                        NM_SETTING_BOND_OPTION_ARP_INTERVAL);
            g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
            return FALSE;
        }
    }

    lacp_rate = _bond_get_option(self, NM_SETTING_BOND_OPTION_LACP_RATE);
    if (lacp_rate && bond_mode != NM_BOND_MODE_8023AD && !NM_IN_STRSET(lacp_rate, "0", "slow")) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' option is only valid with mode '%s'"),
                    NM_SETTING_BOND_OPTION_LACP_RATE,
                    "802.3ad");
        g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
        return FALSE;
    }

    if (_bond_get_option(self, NM_SETTING_BOND_OPTION_NUM_GRAT_ARP)
        && _bond_get_option(self, NM_SETTING_BOND_OPTION_NUM_UNSOL_NA)
        && num_grat_arp != num_unsol_na) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' and '%s' cannot have different values"),
                    NM_SETTING_BOND_OPTION_NUM_GRAT_ARP,
                    NM_SETTING_BOND_OPTION_NUM_UNSOL_NA);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
        return FALSE;
    }

    if (!_nm_connection_verify_required_interface_name(connection, error))
        return FALSE;

    /* *** errors above here should be always fatal, below NORMALIZABLE_ERROR *** */

    if (!NM_IN_STRSET(mode_str,
                      "802.3ad",
                      "active-backup",
                      "balance-rr",
                      "balance-alb",
                      "balance-tlb",
                      "balance-xor",
                      "broadcast")) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' option should be string"),
                    NM_SETTING_BOND_OPTION_MODE);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
        return NM_SETTING_VERIFY_NORMALIZABLE;
    }

    /* normalize unsupported options for the current mode */
    for (i = 0; priv->options_idx_cache[i].name; i++) {
        n = &priv->options_idx_cache[i];
        if (!_nm_setting_bond_option_supported(n->name, bond_mode)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' option is not valid with mode '%s'"),
                        n->name,
                        mode_str);
            g_prefix_error(error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS);
            return NM_SETTING_VERIFY_NORMALIZABLE;
        }
    }

    return TRUE;
}

/*****************************************************************************/

static gboolean
options_equal_asym(NMSettingBond *s_bond, NMSettingBond *s_bond2, NMSettingCompareFlags flags)
{
    GHashTableIter iter;
    const char *   key, *value;

    g_hash_table_iter_init(&iter, NM_SETTING_BOND_GET_PRIVATE(s_bond)->options);
    while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &value)) {
        if (NM_FLAGS_HAS(flags, NM_SETTING_COMPARE_FLAG_INFERRABLE)) {
            /* when doing an inferrable match, the active-slave should be ignored
             * as it might be differ from the setting in the connection.
             *
             * Also, the fail_over_mac setting can change, see for example
             * https://bugzilla.redhat.com/show_bug.cgi?id=1375558#c8 */
            if (NM_IN_STRSET(key, "fail_over_mac", "active_slave"))
                continue;
        }

        if (!nm_streq0(value, _bond_get_option(s_bond2, key)))
            return FALSE;
    }

    return TRUE;
}

static gboolean
options_equal(NMSettingBond *s_bond, NMSettingBond *s_bond2, NMSettingCompareFlags flags)
{
    return options_equal_asym(s_bond, s_bond2, flags) && options_equal_asym(s_bond2, s_bond, flags);
}

static NMTernary
compare_property(const NMSettInfoSetting *sett_info,
                 guint                    property_idx,
                 NMConnection *           con_a,
                 NMSetting *              set_a,
                 NMConnection *           con_b,
                 NMSetting *              set_b,
                 NMSettingCompareFlags    flags)
{
    if (nm_streq(sett_info->property_infos[property_idx].name, NM_SETTING_BOND_OPTIONS)) {
        return (!set_b || options_equal(NM_SETTING_BOND(set_a), NM_SETTING_BOND(set_b), flags));
    }

    return NM_SETTING_CLASS(nm_setting_bond_parent_class)
        ->compare_property(sett_info, property_idx, con_a, set_a, con_b, set_b, flags);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingBondPrivate *priv = NM_SETTING_BOND_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_OPTIONS:
        g_value_take_boxed(value, _nm_utils_copy_strdict(priv->options));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingBondPrivate *priv = NM_SETTING_BOND_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_OPTIONS:
        nm_clear_g_free(&priv->options_idx_cache);
        g_hash_table_unref(priv->options);
        priv->options = _nm_utils_copy_strdict(g_value_get_boxed(value));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_setting_bond_init(NMSettingBond *setting)
{
    NMSettingBondPrivate *priv = NM_SETTING_BOND_GET_PRIVATE(setting);

    priv->options = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, g_free);

    /* Default values: */
    nm_setting_bond_add_option(setting, NM_SETTING_BOND_OPTION_MODE, "balance-rr");
}

/**
 * nm_setting_bond_new:
 *
 * Creates a new #NMSettingBond object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingBond object
 **/
NMSetting *
nm_setting_bond_new(void)
{
    return g_object_new(NM_TYPE_SETTING_BOND, NULL);
}

static void
finalize(GObject *object)
{
    NMSettingBondPrivate *priv = NM_SETTING_BOND_GET_PRIVATE(object);

    nm_clear_g_free(&priv->options_idx_cache);
    g_hash_table_destroy(priv->options);

    G_OBJECT_CLASS(nm_setting_bond_parent_class)->finalize(object);
}

static void
nm_setting_bond_class_init(NMSettingBondClass *klass)
{
    GObjectClass *  object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray *        properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingBondPrivate));

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    setting_class->verify           = verify;
    setting_class->compare_property = compare_property;

    /**
     * NMSettingBond:options: (type GHashTable(utf8,utf8)):
     *
     * Dictionary of key/value pairs of bonding options.  Both keys and values
     * must be strings. Option names must contain only alphanumeric characters
     * (ie, [a-zA-Z0-9]).
     **/
    /* ---ifcfg-rh---
     * property: options
     * variable: BONDING_OPTS
     * description: Bonding options.
     * example: BONDING_OPTS="miimon=100 mode=broadcast"
     * ---end---
     */
    obj_properties[PROP_OPTIONS] = g_param_spec_boxed(
        NM_SETTING_BOND_OPTIONS,
        "",
        "",
        G_TYPE_HASH_TABLE,
        G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);
    _nm_properties_override_gobj(properties_override,
                                 obj_properties[PROP_OPTIONS],
                                 &nm_sett_info_propert_type_strdict);

    /* ---dbus---
     * property: interface-name
     * format: string
     * description: Deprecated in favor of connection.interface-name, but can
     *   be used for backward-compatibility with older daemons, to set the
     *   bond's interface name.
     * ---end---
     */
    _nm_properties_override_dbus(properties_override,
                                 "interface-name",
                                 &nm_sett_info_propert_type_deprecated_interface_name);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit_full(setting_class,
                                  NM_META_SETTING_TYPE_BOND,
                                  NULL,
                                  properties_override);
}
