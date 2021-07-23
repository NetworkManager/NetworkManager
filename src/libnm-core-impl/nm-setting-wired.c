/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-wired.h"

#include <net/ethernet.h>

#include "nm-utils.h"
#include "libnm-core-aux-intern/nm-common-macros.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-wired
 * @short_description: Describes connection properties for Ethernet-based networks
 *
 * The #NMSettingWired object is a #NMSetting subclass that describes properties
 * necessary for connection to Ethernet networks.
 **/

/*****************************************************************************/

G_STATIC_ASSERT(NM_SETTING_WIRED_WAKE_ON_LAN_EXCLUSIVE_FLAGS
                == (NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT | NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE));

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingWired,
                             PROP_PORT,
                             PROP_SPEED,
                             PROP_DUPLEX,
                             PROP_AUTO_NEGOTIATE,
                             PROP_MAC_ADDRESS,
                             PROP_CLONED_MAC_ADDRESS,
                             PROP_GENERATE_MAC_ADDRESS_MASK,
                             PROP_MAC_ADDRESS_BLACKLIST,
                             PROP_MTU,
                             PROP_S390_SUBCHANNELS,
                             PROP_S390_NETTYPE,
                             PROP_S390_OPTIONS,
                             PROP_WAKE_ON_LAN,
                             PROP_WAKE_ON_LAN_PASSWORD,
                             PROP_ACCEPT_ALL_MAC_ADDRESSES, );

typedef struct {
    struct {
        NMUtilsNamedValue *arr;
        guint              len;
        guint              n_alloc;
    } s390_options;
    GArray *                mac_address_blacklist;
    char **                 s390_subchannels;
    char *                  port;
    char *                  duplex;
    char *                  device_mac_address;
    char *                  cloned_mac_address;
    char *                  generate_mac_address_mask;
    char *                  s390_nettype;
    char *                  wol_password;
    NMSettingWiredWakeOnLan wol;
    NMTernary               accept_all_mac_addresses;
    guint32                 speed;
    guint32                 mtu;
    bool                    auto_negotiate;
} NMSettingWiredPrivate;

/**
 * NMSettingWired:
 *
 * Wired Ethernet Settings
 */
struct _NMSettingWired {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingWiredClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingWired, nm_setting_wired, NM_TYPE_SETTING)

#define NM_SETTING_WIRED_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_WIRED, NMSettingWiredPrivate))

/*****************************************************************************/

static const char *const valid_s390_opts[] = {
    "bridge_role",
    "broadcast_mode",
    "buffer_count",
    "canonical_macaddr",
    "checksumming",
    "ctcprot",
    "fake_broadcast",
    "inter",
    "inter_jumbo",
    "ipato_add4",
    "ipato_add6",
    "ipato_enable",
    "ipato_invert4",
    "ipato_invert6",
    "isolation",
    "lancmd_timeout",
    "large_send",
    "layer2",
    "portname",
    "portno",
    "priority_queueing",
    "protocol",
    "route4",
    "route6",
    "rxip_add4",
    "rxip_add6",
    "sniffer",
    "total",
    "vipa_add4",
    "vipa_add6",
    NULL,
};

gboolean
_nm_setting_wired_is_valid_s390_option(const char *option)
{
    if (NM_MORE_ASSERT_ONCE(10)) {
        gsize i;

        nm_assert(NM_PTRARRAY_LEN(valid_s390_opts) + 1u == G_N_ELEMENTS(valid_s390_opts));

        for (i = 0; i < G_N_ELEMENTS(valid_s390_opts); i++) {
            if (i == G_N_ELEMENTS(valid_s390_opts) - 1u)
                nm_assert(!valid_s390_opts[i]);
            else {
                nm_assert(valid_s390_opts[i]);
                nm_assert(valid_s390_opts[i][0] != '\0');
                if (i > 0)
                    nm_assert(strcmp(valid_s390_opts[i - 1], valid_s390_opts[i]) < 0);
            }
        }
    }

    return option
           && (nm_utils_strv_find_binary_search(valid_s390_opts,
                                                G_N_ELEMENTS(valid_s390_opts) - 1,
                                                option)
               >= 0);
}

gboolean
_nm_setting_wired_is_valid_s390_option_value(const char *name, const char *option)
{
    nm_assert(name);

    if (!option)
        return FALSE;

    /* For historic reasons, the s390-options values were not validated beyond
     * simple length check (below).
     *
     * Here, for certain (recently added) options we add strict validation.
     * As this is only done for a few hand picked options, do it right here.
     *
     * Maybe we should find a backward compatible way to validate all options.
     * In that case, the validation should become more elaborate, like we do
     * for bond options. */

    if (nm_streq(name, "bridge_role")) {
        return NM_IN_STRSET(option, "primary", "secondary", "none");
    }

    return option[0] != '\0' && strlen(option) <= NM_SETTING_WIRED_S390_OPTION_MAX_LEN;
}

/**
 * nm_setting_wired_get_port:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:port property of the setting
 **/
const char *
nm_setting_wired_get_port(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), NULL);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->port;
}

/**
 * nm_setting_wired_get_speed:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:speed property of the setting
 **/
guint32
nm_setting_wired_get_speed(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), 0);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->speed;
}

/**
 * nm_setting_wired_get_duplex:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:duplex property of the setting
 **/
const char *
nm_setting_wired_get_duplex(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), NULL);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->duplex;
}

/**
 * nm_setting_wired_get_auto_negotiate:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:auto-negotiate property of the setting
 **/
gboolean
nm_setting_wired_get_auto_negotiate(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), FALSE);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->auto_negotiate;
}

/**
 * nm_setting_wired_get_mac_address:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:mac-address property of the setting
 **/
const char *
nm_setting_wired_get_mac_address(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), NULL);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->device_mac_address;
}

/**
 * nm_setting_wired_get_cloned_mac_address:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:cloned-mac-address property of the setting
 **/
const char *
nm_setting_wired_get_cloned_mac_address(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), NULL);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->cloned_mac_address;
}

/**
 * nm_setting_wired_get_generate_mac_address_mask:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:generate-mac-address-mask property of the setting
 *
 * Since: 1.4
 **/
const char *
nm_setting_wired_get_generate_mac_address_mask(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), NULL);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->generate_mac_address_mask;
}

/**
 * nm_setting_wired_get_mac_address_blacklist:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:mac-address-blacklist property of the setting
 **/
const char *const *
nm_setting_wired_get_mac_address_blacklist(NMSettingWired *setting)
{
    NMSettingWiredPrivate *priv;

    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), NULL);

    priv = NM_SETTING_WIRED_GET_PRIVATE(setting);
    return (const char *const *) priv->mac_address_blacklist->data;
}

/**
 * nm_setting_wired_get_num_mac_blacklist_items:
 * @setting: the #NMSettingWired
 *
 * Returns: the number of blacklisted MAC addresses
 **/
guint32
nm_setting_wired_get_num_mac_blacklist_items(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), 0);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->mac_address_blacklist->len;
}

/**
 * nm_setting_wired_get_mac_blacklist_item:
 * @setting: the #NMSettingWired
 * @idx: the zero-based index of the MAC address entry
 *
 * Returns: the blacklisted MAC address string (hex-digits-and-colons notation)
 * at index @idx
 **/
const char *
nm_setting_wired_get_mac_blacklist_item(NMSettingWired *setting, guint32 idx)
{
    NMSettingWiredPrivate *priv;

    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), NULL);

    priv = NM_SETTING_WIRED_GET_PRIVATE(setting);
    g_return_val_if_fail(idx <= priv->mac_address_blacklist->len, NULL);

    return g_array_index(priv->mac_address_blacklist, const char *, idx);
}

/**
 * nm_setting_wired_add_mac_blacklist_item:
 * @setting: the #NMSettingWired
 * @mac: the MAC address string (hex-digits-and-colons notation) to blacklist
 *
 * Adds a new MAC address to the #NMSettingWired:mac-address-blacklist property.
 *
 * Returns: %TRUE if the MAC address was added; %FALSE if the MAC address
 * is invalid or was already present
 **/
gboolean
nm_setting_wired_add_mac_blacklist_item(NMSettingWired *setting, const char *mac)
{
    NMSettingWiredPrivate *priv;
    const char *           candidate;
    int                    i;

    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), FALSE);
    g_return_val_if_fail(mac != NULL, FALSE);

    if (!nm_utils_hwaddr_valid(mac, ETH_ALEN))
        return FALSE;

    priv = NM_SETTING_WIRED_GET_PRIVATE(setting);
    for (i = 0; i < priv->mac_address_blacklist->len; i++) {
        candidate = g_array_index(priv->mac_address_blacklist, char *, i);
        if (nm_utils_hwaddr_matches(mac, -1, candidate, -1))
            return FALSE;
    }

    mac = nm_utils_hwaddr_canonical(mac, ETH_ALEN);
    g_array_append_val(priv->mac_address_blacklist, mac);
    _notify(setting, PROP_MAC_ADDRESS_BLACKLIST);
    return TRUE;
}

/**
 * nm_setting_wired_remove_mac_blacklist_item:
 * @setting: the #NMSettingWired
 * @idx: index number of the MAC address
 *
 * Removes the MAC address at index @idx from the blacklist.
 **/
void
nm_setting_wired_remove_mac_blacklist_item(NMSettingWired *setting, guint32 idx)
{
    NMSettingWiredPrivate *priv;

    g_return_if_fail(NM_IS_SETTING_WIRED(setting));

    priv = NM_SETTING_WIRED_GET_PRIVATE(setting);
    g_return_if_fail(idx < priv->mac_address_blacklist->len);

    g_array_remove_index(priv->mac_address_blacklist, idx);
    _notify(setting, PROP_MAC_ADDRESS_BLACKLIST);
}

/**
 * nm_setting_wired_remove_mac_blacklist_item_by_value:
 * @setting: the #NMSettingWired
 * @mac: the MAC address string (hex-digits-and-colons notation) to remove from
 * the blacklist
 *
 * Removes the MAC address @mac from the blacklist.
 *
 * Returns: %TRUE if the MAC address was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_wired_remove_mac_blacklist_item_by_value(NMSettingWired *setting, const char *mac)
{
    NMSettingWiredPrivate *priv;
    const char *           candidate;
    int                    i;

    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), FALSE);
    g_return_val_if_fail(mac != NULL, FALSE);

    priv = NM_SETTING_WIRED_GET_PRIVATE(setting);
    for (i = 0; i < priv->mac_address_blacklist->len; i++) {
        candidate = g_array_index(priv->mac_address_blacklist, char *, i);
        if (!nm_utils_hwaddr_matches(mac, -1, candidate, -1)) {
            g_array_remove_index(priv->mac_address_blacklist, i);
            _notify(setting, PROP_MAC_ADDRESS_BLACKLIST);
            return TRUE;
        }
    }
    return FALSE;
}

/**
 * nm_setting_wired_clear_mac_blacklist_items:
 * @setting: the #NMSettingWired
 *
 * Removes all blacklisted MAC addresses.
 **/
void
nm_setting_wired_clear_mac_blacklist_items(NMSettingWired *setting)
{
    g_return_if_fail(NM_IS_SETTING_WIRED(setting));

    g_array_set_size(NM_SETTING_WIRED_GET_PRIVATE(setting)->mac_address_blacklist, 0);
    _notify(setting, PROP_MAC_ADDRESS_BLACKLIST);
}

/**
 * nm_setting_wired_get_mtu:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:mtu property of the setting
 **/
guint32
nm_setting_wired_get_mtu(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), 0);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->mtu;
}

/**
 * nm_setting_wired_get_s390_subchannels:
 * @setting: the #NMSettingWired
 *
 * Return the list of s390 subchannels that identify the device that this
 * connection is applicable to.  The connection should only be used in
 * conjunction with that device.
 *
 * Returns: (transfer none) (element-type utf8): array of strings, each specifying
 *   one subchannel the s390 device uses to communicate to the host.
 **/
const char *const *
nm_setting_wired_get_s390_subchannels(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), NULL);

    return (const char *const *) NM_SETTING_WIRED_GET_PRIVATE(setting)->s390_subchannels;
}

/**
 * nm_setting_wired_get_s390_nettype:
 * @setting: the #NMSettingWired
 *
 * Returns the s390 device type this connection should apply to.  Will be one
 * of 'qeth', 'lcs', or 'ctc'.
 *
 * Returns: the s390 device type
 **/
const char *
nm_setting_wired_get_s390_nettype(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), NULL);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->s390_nettype;
}

/**
 * nm_setting_wired_get_num_s390_options:
 * @setting: the #NMSettingWired
 *
 * Returns the number of s390-specific options that should be set for this
 * device when it is activated.  This can be used to retrieve each s390
 * option individually using nm_setting_wired_get_s390_option().
 *
 * Returns: the number of s390-specific device options
 **/
guint32
nm_setting_wired_get_num_s390_options(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), 0);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->s390_options.len;
}

/**
 * nm_setting_wired_get_s390_option:
 * @setting: the #NMSettingWired
 * @idx: index of the desired option, from 0 to
 * nm_setting_wired_get_num_s390_options() - 1
 * @out_key: (allow-none) (out) (transfer none): on return, the key name of the s390 specific
 *   option; this value is owned by the setting and should not be modified
 * @out_value: (allow-none) (out) (transfer none): on return, the value of the key of the
 *   s390 specific option; this value is owned by the setting and should not be
 *   modified
 *
 * Given an index, return the value of the s390 option at that index.  indexes
 * are *not* guaranteed to be static across modifications to options done by
 * nm_setting_wired_add_s390_option() and nm_setting_wired_remove_s390_option(),
 * and should not be used to refer to options except for short periods of time
 * such as during option iteration.
 *
 * Returns: %TRUE on success if the index was valid and an option was found,
 * %FALSE if the index was invalid (ie, greater than the number of options
 * currently held by the setting)
 **/
gboolean
nm_setting_wired_get_s390_option(NMSettingWired *setting,
                                 guint32         idx,
                                 const char **   out_key,
                                 const char **   out_value)
{
    NMSettingWiredPrivate *priv;

    /* with LTO and optimization, the compiler complains that the
     * output variables are not initialized. In practice, the function
     * only sets the output on success. But make the compiler happy.
     */
    NM_SET_OUT(out_key, NULL);
    NM_SET_OUT(out_value, NULL);

    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), FALSE);

    priv = NM_SETTING_WIRED_GET_PRIVATE(setting);

    g_return_val_if_fail(idx < priv->s390_options.len, FALSE);

    NM_SET_OUT(out_key, priv->s390_options.arr[idx].name);
    NM_SET_OUT(out_value, priv->s390_options.arr[idx].value_str);
    return TRUE;
}

/**
 * nm_setting_wired_get_s390_option_by_key:
 * @setting: the #NMSettingWired
 * @key: the key for which to retrieve the value
 *
 * Returns the value associated with the s390-specific option specified by
 * @key, if it exists.
 *
 * Returns: the value, or %NULL if the key/value pair was never added to the
 * setting; the value is owned by the setting and must not be modified
 **/
const char *
nm_setting_wired_get_s390_option_by_key(NMSettingWired *setting, const char *key)
{
    NMSettingWiredPrivate *priv;
    gssize                 idx;

    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), NULL);
    g_return_val_if_fail(key, NULL);

    priv = NM_SETTING_WIRED_GET_PRIVATE(setting);

    idx = nm_utils_named_value_list_find(priv->s390_options.arr, priv->s390_options.len, key, TRUE);
    if (idx < 0)
        return NULL;
    return priv->s390_options.arr[idx].value_str;
}

/**
 * nm_setting_wired_add_s390_option:
 * @setting: the #NMSettingWired
 * @key: key name for the option
 * @value: value for the option
 *
 * Add an option to the table. If the key already exists, the value gets
 * replaced.
 *
 * Before 1.32, the function would assert that the key is valid. Since then,
 * an invalid key gets silently added but renders the profile as invalid.
 *
 * Returns: since 1.32 this always returns %TRUE.
 **/
gboolean
nm_setting_wired_add_s390_option(NMSettingWired *setting, const char *key, const char *value)
{
    NMSettingWiredPrivate *priv;
    gssize                 idx;

    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), FALSE);
    g_return_val_if_fail(key, FALSE);
    g_return_val_if_fail(value, FALSE);

    priv = NM_SETTING_WIRED_GET_PRIVATE(setting);

    idx = nm_utils_named_value_list_find(priv->s390_options.arr, priv->s390_options.len, key, TRUE);
    if (idx < 0) {
        gsize dst_idx = ~idx;

        g_return_val_if_fail(priv->s390_options.len < G_MAXUINT32 - 1u, FALSE);

        if (priv->s390_options.n_alloc < ((gsize) priv->s390_options.len) + 1u) {
            priv->s390_options.n_alloc = NM_MAX(4u, (((gsize) priv->s390_options.len) + 1u) * 2u);
            priv->s390_options.arr =
                g_realloc(priv->s390_options.arr,
                          priv->s390_options.n_alloc * sizeof(NMUtilsNamedValue));
        }
        if (dst_idx < priv->s390_options.len) {
            memmove(&priv->s390_options.arr[dst_idx + 1u],
                    &priv->s390_options.arr[dst_idx],
                    (priv->s390_options.len - dst_idx) * sizeof(NMUtilsNamedValue));
        }
        priv->s390_options.arr[dst_idx] = (NMUtilsNamedValue){
            .name      = g_strdup(key),
            .value_str = g_strdup(value),
        };
        priv->s390_options.len++;
    } else {
        if (!nm_utils_strdup_reset(&priv->s390_options.arr[idx].value_str_mutable, value))
            return TRUE;
    }

    _notify(setting, PROP_S390_OPTIONS);
    return TRUE;
}

/**
 * nm_setting_wired_remove_s390_option:
 * @setting: the #NMSettingWired
 * @key: key name for the option to remove
 *
 * Remove the s390-specific option referenced by @key from the internal option
 * list.
 *
 * Returns: %TRUE if the option was found and removed from the internal option
 * list, %FALSE if it was not.
 **/
gboolean
nm_setting_wired_remove_s390_option(NMSettingWired *setting, const char *key)
{
    NMSettingWiredPrivate *priv;
    gsize                  dst_idx;
    gssize                 idx;

    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), FALSE);
    g_return_val_if_fail(key, FALSE);

    priv = NM_SETTING_WIRED_GET_PRIVATE(setting);

    idx = nm_utils_named_value_list_find(priv->s390_options.arr, priv->s390_options.len, key, TRUE);
    if (idx < 0)
        return FALSE;

    dst_idx = idx;

    g_free((char *) priv->s390_options.arr[dst_idx].name);
    g_free((char *) priv->s390_options.arr[dst_idx].value_str);
    if (dst_idx + 1u != priv->s390_options.len) {
        memmove(&priv->s390_options.arr[dst_idx],
                &priv->s390_options.arr[dst_idx + 1u],
                (priv->s390_options.len - dst_idx - 1u) * sizeof(NMUtilsNamedValue));
    }

    priv->s390_options.len--;

    _notify(setting, PROP_S390_OPTIONS);
    return TRUE;
}

static void
_s390_options_clear(NMSettingWiredPrivate *priv)
{
    guint i;

    for (i = 0; i < priv->s390_options.len; i++) {
        g_free((char *) priv->s390_options.arr[i].name);
        g_free((char *) priv->s390_options.arr[i].value_str);
    }
    nm_clear_g_free(&priv->s390_options.arr);
    priv->s390_options.len     = 0;
    priv->s390_options.n_alloc = 0;
}

void
_nm_setting_wired_clear_s390_options(NMSettingWired *setting)
{
    g_return_if_fail(NM_IS_SETTING_WIRED(setting));

    _s390_options_clear(NM_SETTING_WIRED_GET_PRIVATE(setting));
}

/**
 * nm_setting_wired_get_valid_s390_options:
 * @setting: (allow-none): the #NMSettingWired. This argument is unused
 *   and you may pass %NULL.
 *
 * Returns a list of valid s390 options.
 *
 * The @setting argument is unused and %NULL may be passed instead.
 *
 * Returns: (transfer none): a %NULL-terminated array of strings of valid s390 options.
 **/
const char **
nm_setting_wired_get_valid_s390_options(NMSettingWired *setting)
{
    return (const char **) valid_s390_opts;
}

/**
 * nm_setting_wired_get_wake_on_lan:
 * @setting: the #NMSettingWired
 *
 * Returns the Wake-on-LAN options enabled for the connection
 *
 * Returns: the Wake-on-LAN options
 *
 * Since: 1.2
 */
NMSettingWiredWakeOnLan
nm_setting_wired_get_wake_on_lan(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), NM_SETTING_WIRED_WAKE_ON_LAN_NONE);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->wol;
}

/**
 * nm_setting_wired_get_wake_on_lan_password:
 * @setting: the #NMSettingWired
 *
 * Returns the Wake-on-LAN password. This only applies to
 * %NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC.
 *
 * Returns: the Wake-on-LAN setting password, or %NULL if there is no password.
 *
 * Since: 1.2
 */
const char *
nm_setting_wired_get_wake_on_lan_password(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), NULL);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->wol_password;
}

/**
 * nm_setting_wired_get_accept_all_mac_addresses:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:accept-all-mac-addresses property of the setting
 *
 * Since: 1.32
 **/
NMTernary
nm_setting_wired_get_accept_all_mac_addresses(NMSettingWired *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRED(setting), NM_TERNARY_DEFAULT);

    return NM_SETTING_WIRED_GET_PRIVATE(setting)->accept_all_mac_addresses;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingWiredPrivate *priv  = NM_SETTING_WIRED_GET_PRIVATE(setting);
    GError *               local = NULL;
    guint                  i;

    if (!NM_IN_STRSET(priv->port, NULL, "tp", "aui", "bnc", "mii")) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid Ethernet port value"),
                    priv->port);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_PORT);
        return FALSE;
    }

    if (!NM_IN_STRSET(priv->duplex, NULL, "half", "full")) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid duplex value"),
                    priv->duplex);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_DUPLEX);
        return FALSE;
    }

    if (priv->device_mac_address && !nm_utils_hwaddr_valid(priv->device_mac_address, ETH_ALEN)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid MAC address"),
                    priv->device_mac_address);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRED_SETTING_NAME,
                       NM_SETTING_WIRED_MAC_ADDRESS);
        return FALSE;
    }

    for (i = 0; i < priv->mac_address_blacklist->len; i++) {
        const char *mac = g_array_index(priv->mac_address_blacklist, const char *, i);

        if (!nm_utils_hwaddr_valid(mac, ETH_ALEN)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' is not a valid MAC address"),
                        mac);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRED_SETTING_NAME,
                           NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST);
            return FALSE;
        }
    }

    if (priv->s390_subchannels) {
        guint len = g_strv_length(priv->s390_subchannels);

        if (len != 2 && len != 3) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("property is invalid"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRED_SETTING_NAME,
                           NM_SETTING_WIRED_S390_SUBCHANNELS);
            return FALSE;
        }
    }

    if (!NM_IN_STRSET(priv->s390_nettype, NULL, "qeth", "lcs", "ctc")) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is invalid"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRED_SETTING_NAME,
                       NM_SETTING_WIRED_S390_NETTYPE);
        return FALSE;
    }

    for (i = 0; i < priv->s390_options.len; i++) {
        const NMUtilsNamedValue *v = &priv->s390_options.arr[i];

        nm_assert(v->name);

        if (!_nm_setting_wired_is_valid_s390_option(v->name)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("invalid key '%s'"),
                        v->name);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRED_SETTING_NAME,
                           NM_SETTING_WIRED_S390_OPTIONS);
            return FALSE;
        }
        if (!_nm_setting_wired_is_valid_s390_option_value(v->name, v->value_str)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("invalid value for key '%s'"),
                        v->name);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRED_SETTING_NAME,
                           NM_SETTING_WIRED_S390_OPTIONS);
            return FALSE;
        }
    }

    if (priv->cloned_mac_address && !NM_CLONED_MAC_IS_SPECIAL(priv->cloned_mac_address)
        && !nm_utils_hwaddr_valid(priv->cloned_mac_address, ETH_ALEN)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid MAC address"),
                    priv->cloned_mac_address);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRED_SETTING_NAME,
                       NM_SETTING_WIRED_CLONED_MAC_ADDRESS);
        return FALSE;
    }

    /* generate-mac-address-mask only makes sense with cloned-mac-address "random" or
     * "stable". Still, let's not be so strict about that and accept the value
     * even if it is unused. */
    if (!_nm_utils_generate_mac_address_mask_parse(priv->generate_mac_address_mask,
                                                   NULL,
                                                   NULL,
                                                   NULL,
                                                   &local)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            local->message);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRED_SETTING_NAME,
                       NM_SETTING_WIRED_GENERATE_MAC_ADDRESS_MASK);
        g_error_free(local);
        return FALSE;
    }

    if (NM_FLAGS_ANY(priv->wol, NM_SETTING_WIRED_WAKE_ON_LAN_EXCLUSIVE_FLAGS)
        && !nm_utils_is_power_of_two(priv->wol)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("Wake-on-LAN mode 'default' and 'ignore' are exclusive flags"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRED_SETTING_NAME,
                       NM_SETTING_WIRED_WAKE_ON_LAN);
        return FALSE;
    }

    if (priv->wol_password && !NM_FLAGS_HAS(priv->wol, NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("Wake-on-LAN password can only be used with magic packet mode"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRED_SETTING_NAME,
                       NM_SETTING_WIRED_WAKE_ON_LAN_PASSWORD);
        return FALSE;
    }

    if (priv->wol_password && !nm_utils_hwaddr_valid(priv->wol_password, ETH_ALEN)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid MAC address"),
                    priv->wol_password);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRED_SETTING_NAME,
                       NM_SETTING_WIRED_WAKE_ON_LAN_PASSWORD);
        return FALSE;
    }

    /* Normalizable properties - just return NM_SETTING_VERIFY_NORMALIZABLE for compatibility
     * with legacy nm-connection-editor which used to save "full" duplex connection as default
     */

    if (((priv->speed) && (!priv->duplex)) || ((!priv->speed) && (priv->duplex))) {
        g_set_error_literal(
            error,
            NM_CONNECTION_ERROR,
            NM_CONNECTION_ERROR_INVALID_PROPERTY,
            priv->auto_negotiate
                ? _("both speed and duplex should have a valid value or both should be unset")
                : _("both speed and duplex are required for static link configuration"));
        return NM_SETTING_VERIFY_NORMALIZABLE;
    }

    return TRUE;
}

static NMTernary
compare_fcn_cloned_mac_address(const NMSettInfoSetting * sett_info,
                               const NMSettInfoProperty *property_info,
                               NMConnection *            con_a,
                               NMSetting *               set_a,
                               NMConnection *            con_b,
                               NMSetting *               set_b,
                               NMSettingCompareFlags     flags)
{
    return !set_b
           || nm_streq0(NM_SETTING_WIRED_GET_PRIVATE(set_a)->cloned_mac_address,
                        NM_SETTING_WIRED_GET_PRIVATE(set_b)->cloned_mac_address);
}

/*****************************************************************************/

static void
clear_blacklist_item(char **item_p)
{
    g_free(*item_p);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingWired *       setting = NM_SETTING_WIRED(object);
    NMSettingWiredPrivate *priv    = NM_SETTING_WIRED_GET_PRIVATE(setting);
    GHashTable *           hash;
    guint                  i;

    switch (prop_id) {
    case PROP_PORT:
        g_value_set_string(value, nm_setting_wired_get_port(setting));
        break;
    case PROP_SPEED:
        g_value_set_uint(value, nm_setting_wired_get_speed(setting));
        break;
    case PROP_DUPLEX:
        g_value_set_string(value, nm_setting_wired_get_duplex(setting));
        break;
    case PROP_AUTO_NEGOTIATE:
        g_value_set_boolean(value, nm_setting_wired_get_auto_negotiate(setting));
        break;
    case PROP_MAC_ADDRESS:
        g_value_set_string(value, nm_setting_wired_get_mac_address(setting));
        break;
    case PROP_CLONED_MAC_ADDRESS:
        g_value_set_string(value, nm_setting_wired_get_cloned_mac_address(setting));
        break;
    case PROP_GENERATE_MAC_ADDRESS_MASK:
        g_value_set_string(value, nm_setting_wired_get_generate_mac_address_mask(setting));
        break;
    case PROP_MAC_ADDRESS_BLACKLIST:
        g_value_set_boxed(value, (char **) priv->mac_address_blacklist->data);
        break;
    case PROP_MTU:
        g_value_set_uint(value, nm_setting_wired_get_mtu(setting));
        break;
    case PROP_S390_SUBCHANNELS:
        g_value_set_boxed(value, priv->s390_subchannels);
        break;
    case PROP_S390_NETTYPE:
        g_value_set_string(value, nm_setting_wired_get_s390_nettype(setting));
        break;
    case PROP_S390_OPTIONS:
        hash = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, g_free);
        for (i = 0; i < priv->s390_options.len; i++) {
            g_hash_table_insert(hash,
                                g_strdup(priv->s390_options.arr[i].name),
                                g_strdup(priv->s390_options.arr[i].value_str));
        }
        g_value_take_boxed(value, hash);
        break;
    case PROP_WAKE_ON_LAN:
        g_value_set_uint(value, priv->wol);
        break;
    case PROP_WAKE_ON_LAN_PASSWORD:
        g_value_set_string(value, priv->wol_password);
        break;
    case PROP_ACCEPT_ALL_MAC_ADDRESSES:
        g_value_set_enum(value, priv->accept_all_mac_addresses);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE(object);
    const char *const *    blacklist;
    const char *           mac;

    switch (prop_id) {
    case PROP_PORT:
        g_free(priv->port);
        priv->port = g_value_dup_string(value);
        break;
    case PROP_SPEED:
        priv->speed = g_value_get_uint(value);
        break;
    case PROP_DUPLEX:
        g_free(priv->duplex);
        priv->duplex = g_value_dup_string(value);
        break;
    case PROP_AUTO_NEGOTIATE:
        priv->auto_negotiate = g_value_get_boolean(value);
        break;
    case PROP_MAC_ADDRESS:
        g_free(priv->device_mac_address);
        priv->device_mac_address =
            _nm_utils_hwaddr_canonical_or_invalid(g_value_get_string(value), ETH_ALEN);
        break;
    case PROP_CLONED_MAC_ADDRESS:
        g_free(priv->cloned_mac_address);
        priv->cloned_mac_address =
            _nm_utils_hwaddr_canonical_or_invalid(g_value_get_string(value), ETH_ALEN);
        break;
    case PROP_GENERATE_MAC_ADDRESS_MASK:
        g_free(priv->generate_mac_address_mask);
        priv->generate_mac_address_mask = g_value_dup_string(value);
        break;
    case PROP_MAC_ADDRESS_BLACKLIST:
        blacklist = g_value_get_boxed(value);
        g_array_set_size(priv->mac_address_blacklist, 0);
        if (blacklist && *blacklist) {
            guint i;

            for (i = 0; blacklist[i]; i++) {
                mac = _nm_utils_hwaddr_canonical_or_invalid(blacklist[i], ETH_ALEN);
                g_array_append_val(priv->mac_address_blacklist, mac);
            }
        }
        break;
    case PROP_MTU:
        priv->mtu = g_value_get_uint(value);
        break;
    case PROP_S390_SUBCHANNELS:
        if (priv->s390_subchannels)
            g_strfreev(priv->s390_subchannels);
        priv->s390_subchannels = g_value_dup_boxed(value);
        break;
    case PROP_S390_NETTYPE:
        g_free(priv->s390_nettype);
        priv->s390_nettype = g_value_dup_string(value);
        break;
    case PROP_S390_OPTIONS:
    {
        GHashTable *hash;

        _s390_options_clear(priv);

        hash = g_value_get_boxed(value);

        priv->s390_options.n_alloc = nm_g_hash_table_size(hash);

        if (priv->s390_options.n_alloc > 0u) {
            gboolean       invalid_content = FALSE;
            GHashTableIter iter;
            const char *   key;
            const char *   val;
            guint          j;
            guint          i;

            priv->s390_options.arr = g_new(NMUtilsNamedValue, priv->s390_options.n_alloc);

            g_hash_table_iter_init(&iter, hash);
            while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val)) {
                if (!key || !val) {
                    invalid_content = TRUE;
                    continue;
                }

                nm_assert(priv->s390_options.len < priv->s390_options.n_alloc);

                priv->s390_options.arr[priv->s390_options.len] = (NMUtilsNamedValue){
                    .name      = g_strdup(key),
                    .value_str = g_strdup(val),
                };
                priv->s390_options.len++;
            }
            if (priv->s390_options.len > 1) {
                nm_utils_named_value_list_sort(priv->s390_options.arr,
                                               priv->s390_options.len,
                                               NULL,
                                               NULL);
                /* prune duplicate keys. This is only possible if @hash does not use
                 * g_str_equal() as compare function (which would be a bug).
                 * Still, handle this, because we use later binary sort and rely
                 * on unique names. One bug here, should not bork the remainder
                 * of the program. */
                j = 1;
                for (i = 1; i < priv->s390_options.len; i++) {
                    if (nm_streq(priv->s390_options.arr[j - 1].name,
                                 priv->s390_options.arr[i].name)) {
                        g_free((char *) priv->s390_options.arr[i].name);
                        g_free((char *) priv->s390_options.arr[i].value_str);
                        invalid_content = TRUE;
                        continue;
                    }
                    priv->s390_options.arr[j++] = priv->s390_options.arr[i];
                }
                priv->s390_options.len = j;
            }

            g_return_if_fail(!invalid_content);
        }
    } break;
    case PROP_WAKE_ON_LAN:
        priv->wol = g_value_get_uint(value);
        break;
    case PROP_WAKE_ON_LAN_PASSWORD:
        g_free(priv->wol_password);
        priv->wol_password = g_value_dup_string(value);
        break;
    case PROP_ACCEPT_ALL_MAC_ADDRESSES:
        priv->accept_all_mac_addresses = g_value_get_enum(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_setting_wired_init(NMSettingWired *setting)
{
    NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE(setting);

    /* We use GArray rather than GPtrArray so it will automatically be NULL-terminated */
    priv->mac_address_blacklist = g_array_new(TRUE, FALSE, sizeof(char *));
    g_array_set_clear_func(priv->mac_address_blacklist, (GDestroyNotify) clear_blacklist_item);

    priv->wol                      = NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT;
    priv->accept_all_mac_addresses = NM_TERNARY_DEFAULT;
}

/**
 * nm_setting_wired_new:
 *
 * Creates a new #NMSettingWired object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingWired object
 **/
NMSetting *
nm_setting_wired_new(void)
{
    return g_object_new(NM_TYPE_SETTING_WIRED, NULL);
}

static void
finalize(GObject *object)
{
    NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE(object);

    g_free(priv->port);
    g_free(priv->duplex);
    g_free(priv->s390_nettype);

    _s390_options_clear(priv);

    g_free(priv->device_mac_address);
    g_free(priv->cloned_mac_address);
    g_free(priv->generate_mac_address_mask);
    g_array_unref(priv->mac_address_blacklist);

    if (priv->s390_subchannels)
        g_strfreev(priv->s390_subchannels);

    g_free(priv->wol_password);

    G_OBJECT_CLASS(nm_setting_wired_parent_class)->finalize(object);
}

static void
nm_setting_wired_class_init(NMSettingWiredClass *klass)
{
    GObjectClass *  object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray *        properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingWiredPrivate));

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    setting_class->verify = verify;

    /**
     * NMSettingWired:port:
     *
     * Specific port type to use if the device supports multiple
     * attachment methods.  One of "tp" (Twisted Pair), "aui" (Attachment Unit
     * Interface), "bnc" (Thin Ethernet) or "mii" (Media Independent Interface).
     * If the device supports only one port type, this setting is ignored.
     **/
    /* ---ifcfg-rh---
     * property: port
     * variable: (none)
     * description: The property is not saved by the plugin.
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRED_PORT,
                                              PROP_PORT,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWiredPrivate,
                                              port);

    /**
     * NMSettingWired:speed:
     *
     * When a value greater than 0 is set, configures the device to use
     * the specified speed. If "auto-negotiate" is "yes" the specified
     * speed will be the only one advertised during link negotiation:
     * this works only for BASE-T 802.3 specifications and is useful for
     * enforcing gigabit speeds, as in this case link negotiation is
     * mandatory.
     * If the value is unset (0, the default), the link configuration will be
     * either skipped (if "auto-negotiate" is "no", the default) or will
     * be auto-negotiated (if "auto-negotiate" is "yes") and the local device
     * will advertise all the supported speeds.
     * In Mbit/s, ie 100 == 100Mbit/s.
     * Must be set together with the "duplex" property when non-zero.
     * Before specifying a speed value be sure your device supports it.
     **/
    /* ---ifcfg-rh---
     * property: speed
     * variable: ETHTOOL_OPTS
     * description: Fixed speed for the ethernet link. It is added as "speed"
     *    parameter in the ETHTOOL_OPTS variable.
     * ---end---
     */
    obj_properties[PROP_SPEED] = g_param_spec_uint(NM_SETTING_WIRED_SPEED,
                                                   "",
                                                   "",
                                                   0,
                                                   G_MAXUINT32,
                                                   0,
                                                   G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingWired:duplex:
     *
     * When a value is set, either "half" or "full", configures the device
     * to use the specified duplex mode. If "auto-negotiate" is "yes" the
     * specified duplex mode will be the only one advertised during link
     * negotiation: this works only for BASE-T 802.3 specifications and is
     * useful for enforcing gigabits modes, as in these cases link negotiation
     * is mandatory.
     * If the value is unset (the default), the link configuration will be
     * either skipped (if "auto-negotiate" is "no", the default) or will
     * be auto-negotiated (if "auto-negotiate" is "yes") and the local device
     * will advertise all the supported duplex modes.
     * Must be set together with the "speed" property if specified.
     * Before specifying a duplex mode be sure your device supports it.
     **/
    /* ---ifcfg-rh---
     * property: duplex
     * variable: ETHTOOL_OPTS
     * description: Fixed duplex mode for the ethernet link. It is added as
     *    "duplex" parameter in the ETHOOL_OPTS variable.
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRED_DUPLEX,
                                              PROP_DUPLEX,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWiredPrivate,
                                              duplex);

    /**
     * NMSettingWired:auto-negotiate:
     *
     * When %TRUE, enforce auto-negotiation of speed and duplex mode.
     * If "speed" and "duplex" properties are both specified, only that
     * single mode will be advertised and accepted during the link
     * auto-negotiation process: this works only for BASE-T 802.3 specifications
     * and is useful for enforcing gigabits modes, as in these cases link
     * negotiation is mandatory.
     * When %FALSE, "speed" and "duplex" properties should be both set or
     * link configuration will be skipped.
     **/
    /* ---ifcfg-rh---
     * property: auto-negotiate
     * variable: ETHTOOL_OPTS
     * description: Whether link speed and duplex autonegotiation is enabled.
     *    It is not saved only if disabled and no values are provided for the
     *    "speed" and "duplex" parameters (skips link configuration).
     * ---end---
     */
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_WIRED_AUTO_NEGOTIATE,
                                               PROP_AUTO_NEGOTIATE,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingWiredPrivate,
                                               auto_negotiate,
                                               .to_dbus_including_default = TRUE);

    /**
     * NMSettingWired:mac-address:
     *
     * If specified, this connection will only apply to the Ethernet device
     * whose permanent MAC address matches. This property does not change the
     * MAC address of the device (i.e. MAC spoofing).
     **/
    /* ---keyfile---
     * property: mac-address
     * format: usual hex-digits-and-colons notation
     * description: MAC address in traditional hex-digits-and-colons notation
     *   (e.g. 00:22:68:12:79:A2), or semicolon separated list of 6 bytes (obsolete)
     *   (e.g. 0;34;104;18;121;162)
     * ---end---
     * ---ifcfg-rh---
     * property: mac-address
     * variable: HWADDR
     * description: Hardware address of the device in traditional hex-digits-and-colons
     *    notation (e.g. 00:22:68:14:5A:05).
     *    Note that for initscripts this is the current MAC address of the device as found
     *    during ifup. For NetworkManager this is the permanent MAC address. Or in case no
     *    permanent MAC address exists, the MAC address initially configured on the device.
     * ---end---
     */
    _nm_setting_property_define_direct_mac_address(properties_override,
                                                   obj_properties,
                                                   NM_SETTING_WIRED_MAC_ADDRESS,
                                                   PROP_MAC_ADDRESS,
                                                   NM_SETTING_PARAM_INFERRABLE,
                                                   NMSettingWiredPrivate,
                                                   device_mac_address,
                                                   .direct_set_string_mac_address_len = ETH_ALEN);

    /**
     * NMSettingWired:cloned-mac-address:
     *
     * If specified, request that the device use this MAC address instead.
     * This is known as MAC cloning or spoofing.
     *
     * Beside explicitly specifying a MAC address, the special values "preserve", "permanent",
     * "random" and "stable" are supported.
     * "preserve" means not to touch the MAC address on activation.
     * "permanent" means to use the permanent hardware address if the device
     * has one (otherwise this is treated as "preserve").
     * "random" creates a random MAC address on each connect.
     * "stable" creates a hashed MAC address based on connection.stable-id and a
     * machine dependent key.
     *
     * If unspecified, the value can be overwritten via global defaults, see manual
     * of NetworkManager.conf. If still unspecified, it defaults to "preserve"
     * (older versions of NetworkManager may use a different default value).
     *
     * On D-Bus, this field is expressed as "assigned-mac-address" or the deprecated
     * "cloned-mac-address".
     **/
    /* ---keyfile---
     * property: cloned-mac-address
     * format: usual hex-digits-and-colons notation
     * description: Cloned MAC address in traditional hex-digits-and-colons notation
     *   (e.g. 00:22:68:12:79:B2), or semicolon separated list of 6 bytes (obsolete)
     *   (e.g. 0;34;104;18;121;178).
     * ---end---
     * ---ifcfg-rh---
     * property: cloned-mac-address
     * variable: MACADDR
     * description: Cloned (spoofed) MAC address in traditional hex-digits-and-colons
     *    notation (e.g. 00:22:68:14:5A:99).
     * ---end---
     * ---dbus---
     * property: cloned-mac-address
     * format: byte array
     * description: This D-Bus field is deprecated in favor of "assigned-mac-address"
     *    which is more flexible and allows specifying special variants like "random".
     *    For libnm and nmcli, this field is called "cloned-mac-address".
     * ---end---
     */
    obj_properties[PROP_CLONED_MAC_ADDRESS] = g_param_spec_string(
        NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
        "",
        "",
        NULL,
        G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);
    _nm_properties_override_gobj(
        properties_override,
        obj_properties[PROP_CLONED_MAC_ADDRESS],
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_BYTESTRING,
                                       .compare_fcn           = compare_fcn_cloned_mac_address,
                                       .to_dbus_fcn           = _nm_utils_hwaddr_cloned_get,
                                       .from_dbus_fcn         = _nm_utils_hwaddr_cloned_set,
                                       .missing_from_dbus_fcn = _nm_utils_hwaddr_cloned_not_set, ));

    /* ---dbus---
     * property: assigned-mac-address
     * format: string
     * description: The new field for the cloned MAC address. It can be either
     *   a hardware address in ASCII representation, or one of the special values
     *   "preserve", "permanent", "random" or "stable".
     *   This field replaces the deprecated "cloned-mac-address" on D-Bus, which
     *   can only contain explicit hardware addresses. Note that this property
     *   only exists in D-Bus API. libnm and nmcli continue to call this property
     *   "cloned-mac-address".
     * ---end---
     */
    _nm_properties_override_dbus(properties_override,
                                 "assigned-mac-address",
                                 &nm_sett_info_propert_type_assigned_mac_address);

    /**
     * NMSettingWired:generate-mac-address-mask:
     *
     * With #NMSettingWired:cloned-mac-address setting "random" or "stable",
     * by default all bits of the MAC address are scrambled and a locally-administered,
     * unicast MAC address is created. This property allows to specify that certain bits
     * are fixed. Note that the least significant bit of the first MAC address will
     * always be unset to create a unicast MAC address.
     *
     * If the property is %NULL, it is eligible to be overwritten by a default
     * connection setting. If the value is still %NULL or an empty string, the
     * default is to create a locally-administered, unicast MAC address.
     *
     * If the value contains one MAC address, this address is used as mask. The set
     * bits of the mask are to be filled with the current MAC address of the device,
     * while the unset bits are subject to randomization.
     * Setting "FE:FF:FF:00:00:00" means to preserve the OUI of the current MAC address
     * and only randomize the lower 3 bytes using the "random" or "stable" algorithm.
     *
     * If the value contains one additional MAC address after the mask,
     * this address is used instead of the current MAC address to fill the bits
     * that shall not be randomized. For example, a value of
     * "FE:FF:FF:00:00:00 68:F7:28:00:00:00" will set the OUI of the MAC address
     * to 68:F7:28, while the lower bits are randomized. A value of
     * "02:00:00:00:00:00 00:00:00:00:00:00" will create a fully scrambled
     * globally-administered, burned-in MAC address.
     *
     * If the value contains more than one additional MAC addresses, one of
     * them is chosen randomly. For example, "02:00:00:00:00:00 00:00:00:00:00:00 02:00:00:00:00:00"
     * will create a fully scrambled MAC address, randomly locally or globally
     * administered.
     **/
    /* ---ifcfg-rh---
     * property: generate-mac-address-mask
     * variable: GENERATE_MAC_ADDRESS_MASK(+)
     * description: the MAC address mask for generating randomized and stable
     *   cloned-mac-address.
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRED_GENERATE_MAC_ADDRESS_MASK,
                                              PROP_GENERATE_MAC_ADDRESS_MASK,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingWiredPrivate,
                                              generate_mac_address_mask);

    /**
     * NMSettingWired:mac-address-blacklist:
     *
     * If specified, this connection will never apply to the Ethernet device
     * whose permanent MAC address matches an address in the list.  Each MAC
     * address is in the standard hex-digits-and-colons notation
     * (00:11:22:33:44:55).
     **/
    /* ---keyfile---
     * property: mac-address-blacklist
     * format: list of MACs (separated with semicolons)
     * description: MAC address blacklist.
     * example: mac-address-blacklist= 00:22:68:12:79:A6;00:22:68:12:79:78
     * ---end---
     * ---ifcfg-rh---
     * property: mac-address-blacklist
     * variable: HWADDR_BLACKLIST(+)
     * description: It denies usage of the connection for any device whose address
     *   is listed.
     * example: HWADDR_BLACKLIST="00:22:68:11:69:08 00:11:22:11:44:55"
     * ---end---
     */
    obj_properties[PROP_MAC_ADDRESS_BLACKLIST] = g_param_spec_boxed(
        NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST,
        "",
        "",
        G_TYPE_STRV,
        G_PARAM_READWRITE | NM_SETTING_PARAM_FUZZY_IGNORE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingWired:mtu:
     *
     * If non-zero, only transmit packets of the specified size or smaller,
     * breaking larger packets up into multiple Ethernet frames.
     **/
    /* ---ifcfg-rh---
     * property: mtu
     * variable: MTU
     * description: MTU of the interface.
     * ---end---
     */
    obj_properties[PROP_MTU] = g_param_spec_uint(NM_SETTING_WIRED_MTU,
                                                 "",
                                                 "",
                                                 0,
                                                 G_MAXUINT32,
                                                 0,
                                                 G_PARAM_READWRITE | NM_SETTING_PARAM_FUZZY_IGNORE
                                                     | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingWired:s390-subchannels:
     *
     * Identifies specific subchannels that this network device uses for
     * communication with z/VM or s390 host.  Like the
     * #NMSettingWired:mac-address property for non-z/VM devices, this property
     * can be used to ensure this connection only applies to the network device
     * that uses these subchannels.  The list should contain exactly 3 strings,
     * and each string may only be composed of hexadecimal characters and the
     * period (.) character.
     **/
    /* ---ifcfg-rh---
     * property: s390-subchannels
     * variable: SUBCHANNELS
     * description: Subchannels for IBM S390 hosts.
     * example: SUBCHANNELS=0.0.b00a,0.0.b00b,0.0.b00c
     * ---end---
     */
    obj_properties[PROP_S390_SUBCHANNELS] = g_param_spec_boxed(
        NM_SETTING_WIRED_S390_SUBCHANNELS,
        "",
        "",
        G_TYPE_STRV,
        G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingWired:s390-nettype:
     *
     * s390 network device type; one of "qeth", "lcs", or "ctc", representing
     * the different types of virtual network devices available on s390 systems.
     **/
    /* ---ifcfg-rh---
     * property: s390-nettype
     * variable: NETTYPE
     * values: "qeth", "lcs" or "ctc"
     * description: Network type of the S390 host.
     * example: NETTYPE=qeth
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRED_S390_NETTYPE,
                                              PROP_S390_NETTYPE,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingWiredPrivate,
                                              s390_nettype);

    /**
     * NMSettingWired:s390-options: (type GHashTable(utf8,utf8)):
     *
     * Dictionary of key/value pairs of s390-specific device options.  Both keys
     * and values must be strings.  Allowed keys include "portno", "layer2",
     * "portname", "protocol", among others.  Key names must contain only
     * alphanumeric characters (ie, [a-zA-Z0-9]).
     *
     * Currently, NetworkManager itself does nothing with this information.
     * However, s390utils ships a udev rule which parses this information
     * and applies it to the interface.
     **/
    /* ---ifcfg-rh---
     * property: s390-options
     * variable: OPTIONS and PORTNAME, CTCPROTO,
     * description: S390 device options. All options go to OPTIONS, except for
     *   "portname" and "ctcprot" that have their own variables.
     * ---end---
     */
    obj_properties[PROP_S390_OPTIONS] = g_param_spec_boxed(
        NM_SETTING_WIRED_S390_OPTIONS,
        "",
        "",
        G_TYPE_HASH_TABLE,
        G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);
    _nm_properties_override_gobj(properties_override,
                                 obj_properties[PROP_S390_OPTIONS],
                                 &nm_sett_info_propert_type_strdict);

    /**
     * NMSettingWired:wake-on-lan:
     *
     * The #NMSettingWiredWakeOnLan options to enable. Not all devices support all options.
     * May be any combination of %NM_SETTING_WIRED_WAKE_ON_LAN_PHY,
     * %NM_SETTING_WIRED_WAKE_ON_LAN_UNICAST, %NM_SETTING_WIRED_WAKE_ON_LAN_MULTICAST,
     * %NM_SETTING_WIRED_WAKE_ON_LAN_BROADCAST, %NM_SETTING_WIRED_WAKE_ON_LAN_ARP,
     * %NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC or the special values
     * %NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT (to use global settings) and
     * %NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE (to disable management of Wake-on-LAN in
     * NetworkManager).
     *
     * Since: 1.2
     **/
    /* ---ifcfg-rh---
     * property: wake-on-lan
     * variable: ETHTOOL_OPTS, ETHTOOL_WAKE_ON_LAN
     * description: Wake on Lan mode for ethernet. The setting "ignore" is expressed
     * with "ETHTOOL_WAKE_ON_LAN=ignore". Otherwise, the "ETHTOOL_OPTS" variable is set
     * with the value "wol" and several of the characters "p|u|m|b|a|g|s|f|d" as explained
     * in the ethtool manual page.
     * ---end---
     */
    obj_properties[PROP_WAKE_ON_LAN] =
        g_param_spec_uint(NM_SETTING_WIRED_WAKE_ON_LAN,
                          "",
                          "",
                          0,
                          G_MAXUINT32,
                          NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT,
                          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingWired:wake-on-lan-password:
     *
     * If specified, the password used with magic-packet-based
     * Wake-on-LAN, represented as an Ethernet MAC address.  If %NULL,
     * no password will be required.
     *
     * Since: 1.2
     **/
    /* ---ifcfg-rh---
     * property: wake-on-lan-password
     * variable: ETHTOOL_OPTS
     * description: Password for secure-on based Wake-on-Lan. It is added as "sopass"
     *    parameter in the ETHTOOL_OPTS variable.
     * example: ETHTOOL_OPTS="wol gs sopass 00:11:22:33:44:55"
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRED_WAKE_ON_LAN_PASSWORD,
                                              PROP_WAKE_ON_LAN_PASSWORD,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWiredPrivate,
                                              wol_password);

    /**
     * NMSettingWired:accept-all-mac-addresses:
     *
     * When %TRUE, setup the interface to accept packets for all MAC addresses.
     * This is enabling the kernel interface flag IFF_PROMISC.
     * When %FALSE, the interface will only accept the packets with the
     * interface destination mac address or broadcast.
     *
     * Since: 1.32
     **/
    /* ---ifcfg-rh---
     * property: accept-all-mac-addresses
     * variable: ACCEPT_ALL_MAC_ADDRESSES
     * description: Enforce the interface to accept all the packets.
     * ---end---
     */
    obj_properties[PROP_ACCEPT_ALL_MAC_ADDRESSES] =
        g_param_spec_enum(NM_SETTING_WIRED_ACCEPT_ALL_MAC_ADDRESSES,
                          "",
                          "",
                          NM_TYPE_TERNARY,
                          NM_TERNARY_DEFAULT,
                          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_WIRED,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
