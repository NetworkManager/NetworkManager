/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-wireless.h"

#include <net/ethernet.h>

#include "nm-utils.h"
#include "libnm-core-aux-intern/nm-common-macros.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-wireless
 * @short_description: Describes connection properties for 802.11 Wi-Fi networks
 *
 * The #NMSettingWireless object is a #NMSetting subclass that describes properties
 * necessary for connection to 802.11 Wi-Fi networks.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingWireless,
                             PROP_SSID,
                             PROP_MODE,
                             PROP_BAND,
                             PROP_CHANNEL,
                             PROP_BSSID,
                             PROP_RATE,
                             PROP_TX_POWER,
                             PROP_MAC_ADDRESS,
                             PROP_CLONED_MAC_ADDRESS,
                             PROP_GENERATE_MAC_ADDRESS_MASK,
                             PROP_MAC_ADDRESS_BLACKLIST,
                             PROP_MAC_ADDRESS_DENYLIST,
                             PROP_MTU,
                             PROP_SEEN_BSSIDS,
                             PROP_HIDDEN,
                             PROP_POWERSAVE,
                             PROP_MAC_ADDRESS_RANDOMIZATION,
                             PROP_WAKE_ON_WLAN,
                             PROP_AP_ISOLATION,
                             PROP_CHANNEL_WIDTH, );

typedef struct {
    GBytes     *ssid;
    GPtrArray  *seen_bssids;
    char       *mode;
    char       *band;
    char       *bssid;
    char       *device_mac_address;
    char       *cloned_mac_address;
    char       *generate_mac_address_mask;
    NMValueStrv mac_address_denylist;
    int         ap_isolation;
    int         channel_width;
    guint32     mac_address_randomization;
    guint32     channel;
    guint32     rate;
    guint32     tx_power;
    guint32     mtu;
    guint32     powersave;
    guint32     wake_on_wlan;
    bool        hidden;
} NMSettingWirelessPrivate;

/**
 * NMSettingWireless:
 *
 * Wi-Fi Settings
 */
struct _NMSettingWireless {
    NMSetting                parent;
    NMSettingWirelessPrivate _priv;
};

struct _NMSettingWirelessClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingWireless, nm_setting_wireless, NM_TYPE_SETTING)

#define NM_SETTING_WIRELESS_GET_PRIVATE(o) \
    _NM_GET_PRIVATE(o, NMSettingWireless, NM_IS_SETTING_WIRELESS, NMSetting)

/*****************************************************************************/

static gboolean
match_cipher(const char *cipher,
             const char *expected,
             guint32     wpa_flags,
             guint32     rsn_flags,
             guint32     flag)
{
    if (strcmp(cipher, expected) != 0)
        return FALSE;

    if (!(wpa_flags & flag) && !(rsn_flags & flag))
        return FALSE;

    return TRUE;
}

/**
 * nm_setting_wireless_ap_security_compatible:
 * @s_wireless: a #NMSettingWireless
 * @s_wireless_sec: a #NMSettingWirelessSecurity or %NULL
 * @ap_flags: the %NM80211ApFlags of the given access point
 * @ap_wpa: the %NM80211ApSecurityFlags of the given access point's WPA
 * capabilities
 * @ap_rsn: the %NM80211ApSecurityFlags of the given access point's WPA2/RSN
 * capabilities
 * @ap_mode: the 802.11 mode of the AP, either Ad-Hoc or Infrastructure
 *
 * Given a #NMSettingWireless and an optional #NMSettingWirelessSecurity,
 * determine if the configuration given by the settings is compatible with
 * the security of an access point using that access point's capability flags
 * and mode.  Useful for clients that wish to filter a set of connections
 * against a set of access points and determine which connections are
 * compatible with which access points.
 *
 * Returns: %TRUE if the given settings are compatible with the access point's
 * security flags and mode, %FALSE if they are not.
 */
gboolean
nm_setting_wireless_ap_security_compatible(NMSettingWireless         *s_wireless,
                                           NMSettingWirelessSecurity *s_wireless_sec,
                                           NM80211ApFlags             ap_flags,
                                           NM80211ApSecurityFlags     ap_wpa,
                                           NM80211ApSecurityFlags     ap_rsn,
                                           NM80211Mode                ap_mode)
{
    const char *key_mgmt = NULL, *cipher;
    guint32     num, i;
    gboolean    found = FALSE;

    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(s_wireless), FALSE);

    if (!s_wireless_sec) {
        /* A OWE-TM network can be used w/o security */
        if (ap_wpa == NM_802_11_AP_SEC_KEY_MGMT_OWE_TM
            || (ap_rsn == NM_802_11_AP_SEC_KEY_MGMT_OWE_TM))
            return TRUE;
        if ((ap_flags & NM_802_11_AP_FLAGS_PRIVACY) || (ap_wpa != NM_802_11_AP_SEC_NONE)
            || (ap_rsn != NM_802_11_AP_SEC_NONE))
            return FALSE;
        return TRUE;
    }

    key_mgmt = nm_setting_wireless_security_get_key_mgmt(s_wireless_sec);
    if (!key_mgmt)
        return FALSE;

    /* Static WEP */
    if (!strcmp(key_mgmt, "none")) {
        if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY) || (ap_wpa != NM_802_11_AP_SEC_NONE)
            || (ap_rsn != NM_802_11_AP_SEC_NONE))
            return FALSE;
        return TRUE;
    }

    /* Adhoc WPA2 (ie, RSN IBSS) */
    if (ap_mode == NM_802_11_MODE_ADHOC) {
        if (strcmp(key_mgmt, "wpa-psk"))
            return FALSE;

        /* Ensure the AP has RSN PSK capability */
        if (!(ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_PSK))
            return FALSE;

        /* Fall through and check ciphers in generic WPA-PSK code */
    }

    /* Dynamic WEP or LEAP */
    if (!strcmp(key_mgmt, "ieee8021x")) {
        if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
            return FALSE;

        /* If the AP is advertising a WPA IE, make sure it supports WEP ciphers */
        if (ap_wpa != NM_802_11_AP_SEC_NONE) {
            if (!(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
                return FALSE;

            /* quick check; can't use AP if it doesn't support at least one
             * WEP cipher in both pairwise and group suites.
             */
            if (!(ap_wpa & (NM_802_11_AP_SEC_PAIR_WEP40 | NM_802_11_AP_SEC_PAIR_WEP104))
                || !(ap_wpa & (NM_802_11_AP_SEC_GROUP_WEP40 | NM_802_11_AP_SEC_GROUP_WEP104)))
                return FALSE;

            /* Match at least one pairwise cipher with AP's capability if the
             * wireless-security setting explicitly lists pairwise ciphers
             */
            num = nm_setting_wireless_security_get_num_pairwise(s_wireless_sec);
            for (i = 0, found = FALSE; i < num; i++) {
                cipher = nm_setting_wireless_security_get_pairwise(s_wireless_sec, i);
                if ((found = match_cipher(cipher,
                                          "wep40",
                                          ap_wpa,
                                          ap_wpa,
                                          NM_802_11_AP_SEC_PAIR_WEP40)))
                    break;
                if ((found = match_cipher(cipher,
                                          "wep104",
                                          ap_wpa,
                                          ap_wpa,
                                          NM_802_11_AP_SEC_PAIR_WEP104)))
                    break;
            }
            if (!found && num)
                return FALSE;

            /* Match at least one group cipher with AP's capability if the
             * wireless-security setting explicitly lists group ciphers
             */
            num = nm_setting_wireless_security_get_num_groups(s_wireless_sec);
            for (i = 0, found = FALSE; i < num; i++) {
                cipher = nm_setting_wireless_security_get_group(s_wireless_sec, i);
                if ((found = match_cipher(cipher,
                                          "wep40",
                                          ap_wpa,
                                          ap_wpa,
                                          NM_802_11_AP_SEC_GROUP_WEP40)))
                    break;
                if ((found = match_cipher(cipher,
                                          "wep104",
                                          ap_wpa,
                                          ap_wpa,
                                          NM_802_11_AP_SEC_GROUP_WEP104)))
                    break;
            }
            if (!found && num)
                return FALSE;
        }
        return TRUE;
    }

    /* WPA[2]-PSK and WPA[2] Enterprise */
    if (!strcmp(key_mgmt, "wpa-psk") || !strcmp(key_mgmt, "wpa-eap") || !strcmp(key_mgmt, "sae")
        || !strcmp(key_mgmt, "owe")) {
        if (!strcmp(key_mgmt, "wpa-psk")) {
            if (!(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_PSK)
                && !(ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_PSK))
                return FALSE;
        } else if (!strcmp(key_mgmt, "wpa-eap")) {
            if (!(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
                && !(ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
                return FALSE;
        } else if (!strcmp(key_mgmt, "sae")) {
            if (!(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_SAE)
                && !(ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_SAE))
                return FALSE;
        } else if (!strcmp(key_mgmt, "owe")) {
            if (!NM_FLAGS_ANY(ap_wpa,
                              NM_802_11_AP_SEC_KEY_MGMT_OWE | NM_802_11_AP_SEC_KEY_MGMT_OWE_TM)
                && !NM_FLAGS_ANY(ap_rsn,
                                 NM_802_11_AP_SEC_KEY_MGMT_OWE | NM_802_11_AP_SEC_KEY_MGMT_OWE_TM))
                return FALSE;
        }

        // FIXME: should handle WPA and RSN separately here to ensure that
        // if the Connection only uses WPA we don't match a cipher against
        // the AP's RSN IE instead

        /* Match at least one pairwise cipher with AP's capability if the
         * wireless-security setting explicitly lists pairwise ciphers
         */
        num = nm_setting_wireless_security_get_num_pairwise(s_wireless_sec);
        for (i = 0, found = FALSE; i < num; i++) {
            cipher = nm_setting_wireless_security_get_pairwise(s_wireless_sec, i);
            if ((found = match_cipher(cipher, "tkip", ap_wpa, ap_rsn, NM_802_11_AP_SEC_PAIR_TKIP)))
                break;
            if ((found = match_cipher(cipher, "ccmp", ap_wpa, ap_rsn, NM_802_11_AP_SEC_PAIR_CCMP)))
                break;
        }
        if (!found && num)
            return FALSE;

        /* Match at least one group cipher with AP's capability if the
         * wireless-security setting explicitly lists group ciphers
         */
        num = nm_setting_wireless_security_get_num_groups(s_wireless_sec);
        for (i = 0, found = FALSE; i < num; i++) {
            cipher = nm_setting_wireless_security_get_group(s_wireless_sec, i);

            if ((found =
                     match_cipher(cipher, "wep40", ap_wpa, ap_rsn, NM_802_11_AP_SEC_GROUP_WEP40)))
                break;
            if ((found =
                     match_cipher(cipher, "wep104", ap_wpa, ap_rsn, NM_802_11_AP_SEC_GROUP_WEP104)))
                break;
            if ((found = match_cipher(cipher, "tkip", ap_wpa, ap_rsn, NM_802_11_AP_SEC_GROUP_TKIP)))
                break;
            if ((found = match_cipher(cipher, "ccmp", ap_wpa, ap_rsn, NM_802_11_AP_SEC_GROUP_CCMP)))
                break;
        }
        if (!found && num)
            return FALSE;

        return TRUE;
    }

    /* WPA3 Enterprise Suite B 192 */
    if (!strcmp(key_mgmt, "wpa-eap-suite-b-192")) {
        if (!(ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_EAP_SUITE_B_192)) {
            return FALSE;
        }

        /* Since NetworkManager doesn't handle GCMP-256 directly, cipher check can be skipped */
        return TRUE;
    }

    return FALSE;
}

/**
 * nm_setting_wireless_get_ssid:
 * @setting: the #NMSettingWireless
 *
 * Returns: (transfer none): the #NMSettingWireless:ssid property of the setting
 **/
GBytes *
nm_setting_wireless_get_ssid(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), NULL);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->ssid;
}

/**
 * nm_setting_wireless_get_mode:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:mode property of the setting
 **/
const char *
nm_setting_wireless_get_mode(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), NULL);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->mode;
}

/**
 * nm_setting_wireless_get_band:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:band property of the setting
 **/
const char *
nm_setting_wireless_get_band(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), NULL);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->band;
}

/**
 * nm_setting_wireless_get_channel:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:channel property of the setting
 **/
guint32
nm_setting_wireless_get_channel(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), 0);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->channel;
}

/**
 * nm_setting_wireless_get_bssid:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:bssid property of the setting
 **/
const char *
nm_setting_wireless_get_bssid(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), NULL);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->bssid;
}

/**
 * nm_setting_wireless_get_rate:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:rate property of the setting
 *
 * Deprecated: 1.44: This setting is not implemented and has no effect.
 **/
guint32
nm_setting_wireless_get_rate(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), 0);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->rate;
}

/**
 * nm_setting_wireless_get_tx_power:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:tx-power property of the setting
 *
 * Deprecated: 1.44: This setting is not implemented and has no effect.
 **/
guint32
nm_setting_wireless_get_tx_power(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), 0);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->tx_power;
}

/**
 * nm_setting_wireless_get_mac_address:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:mac-address property of the setting
 **/
const char *
nm_setting_wireless_get_mac_address(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), NULL);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->device_mac_address;
}

/**
 * nm_setting_wireless_get_cloned_mac_address:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:cloned-mac-address property of the setting
 **/
const char *
nm_setting_wireless_get_cloned_mac_address(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), NULL);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->cloned_mac_address;
}

/**
 * nm_setting_wireless_get_generate_mac_address_mask:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:generate-mac-address-mask property of the setting
 *
 * Since: 1.4
 **/
const char *
nm_setting_wireless_get_generate_mac_address_mask(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), NULL);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->generate_mac_address_mask;
}

/**
 * nm_setting_wireless_get_mac_address_denylist:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:mac-address-denylist property of the setting
 *
 * Since: 1.48
 **/
const char *const *
nm_setting_wireless_get_mac_address_denylist(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), NULL);

    return nm_strvarray_get_strv_notnull(
        NM_SETTING_WIRELESS_GET_PRIVATE(setting)->mac_address_denylist.arr,
        NULL);
}

/**
 * nm_setting_wireless_get_num_mac_denylist_items:
 * @setting: the #NMSettingWireless
 *
 * Returns: the number of denylisted MAC addresses
 *
 * Since: 1.48
 **/
guint
nm_setting_wireless_get_num_mac_denylist_items(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), 0);

    return nm_g_array_len(NM_SETTING_WIRELESS_GET_PRIVATE(setting)->mac_address_denylist.arr);
}

/**
 * nm_setting_wireless_get_mac_denylist_item:
 * @setting: the #NMSettingWireless
 * @idx: the zero-based index of the MAC address entry
 *
 * Returns: the denylisted MAC address string (hex-digits-and-colons notation)
 * at index @idx
 *
 * Since: 1.48
 **/
const char *
nm_setting_wireless_get_mac_denylist_item(NMSettingWireless *setting, guint32 idx)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), NULL);

    return nm_strvarray_get_idxnull_or_greturn(
        NM_SETTING_WIRELESS_GET_PRIVATE(setting)->mac_address_denylist.arr,
        idx);
}

/**
 * nm_setting_wireless_add_mac_denylist_item:
 * @setting: the #NMSettingWireless
 * @mac: the MAC address string (hex-digits-and-colons notation) to denylist
 *
 * Adds a new MAC address to the #NMSettingWireless:mac-address-denylist property.
 *
 * Returns: %TRUE if the MAC address was added; %FALSE if the MAC address
 * is invalid or was already present
 *
 * Since: 1.48
 **/
gboolean
nm_setting_wireless_add_mac_denylist_item(NMSettingWireless *setting, const char *mac)
{
    NMSettingWirelessPrivate *priv;
    guint8                    mac_bin[ETH_ALEN];
    const char               *candidate;
    guint                     i;
    guint                     len;

    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), FALSE);
    g_return_val_if_fail(mac != NULL, FALSE);

    if (!_nm_utils_hwaddr_aton_exact(mac, mac_bin, ETH_ALEN))
        return FALSE;

    priv = NM_SETTING_WIRELESS_GET_PRIVATE(setting);
    len  = nm_g_array_len(priv->mac_address_denylist.arr);
    for (i = 0; i < len; i++) {
        candidate = nm_g_array_index(priv->mac_address_denylist.arr, char *, i);
        if (nm_utils_hwaddr_matches(mac_bin, ETH_ALEN, candidate, -1))
            return FALSE;
    }

    nm_g_array_append_simple(nm_strvarray_ensure(&priv->mac_address_denylist.arr),
                             nm_utils_hwaddr_ntoa(mac_bin, ETH_ALEN));
    _notify(setting, PROP_MAC_ADDRESS_DENYLIST);
    return TRUE;
}

/**
 * nm_setting_wireless_remove_mac_denylist_item:
 * @setting: the #NMSettingWireless
 * @idx: index number of the MAC address
 *
 * Removes the MAC address at index @idx from the denylist.
 *
 * Since: 1.48
 **/
void
nm_setting_wireless_remove_mac_denylist_item(NMSettingWireless *setting, guint idx)
{
    NMSettingWirelessPrivate *priv;

    g_return_if_fail(NM_IS_SETTING_WIRELESS(setting));

    priv = NM_SETTING_WIRELESS_GET_PRIVATE(setting);
    if (!priv->mac_address_denylist.arr) {
        return;
    }

    g_return_if_fail(idx < priv->mac_address_denylist.arr->len);

    g_array_remove_index(priv->mac_address_denylist.arr, idx);
    _notify(setting, PROP_MAC_ADDRESS_DENYLIST);
}

/**
 * nm_setting_wireless_remove_mac_denylist_item_by_value:
 * @setting: the #NMSettingWireless
 * @mac: the MAC address string (hex-digits-and-colons notation) to remove from
 * the denylist
 *
 * Removes the MAC address @mac from the denylist.
 *
 * Returns: %TRUE if the MAC address was found and removed; %FALSE if it was not.
 *
 * Since: 1.48
 **/
gboolean
nm_setting_wireless_remove_mac_denylist_item_by_value(NMSettingWireless *setting, const char *mac)
{
    NMSettingWirelessPrivate *priv;
    guint8                    mac_bin[ETH_ALEN];
    const char               *candidate;
    guint                     i;

    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), FALSE);
    g_return_val_if_fail(mac != NULL, FALSE);

    if (!_nm_utils_hwaddr_aton_exact(mac, mac_bin, ETH_ALEN))
        return FALSE;

    priv = NM_SETTING_WIRELESS_GET_PRIVATE(setting);

    if (priv->mac_address_denylist.arr) {
        for (i = 0; i < priv->mac_address_denylist.arr->len; i++) {
            candidate = nm_g_array_index(priv->mac_address_denylist.arr, char *, i);
            if (nm_utils_hwaddr_matches(mac_bin, ETH_ALEN, candidate, -1)) {
                g_array_remove_index(priv->mac_address_denylist.arr, i);
                _notify(setting, PROP_MAC_ADDRESS_DENYLIST);
                return TRUE;
            }
        }
    }

    return FALSE;
}

/**
 * nm_setting_wireless_clear_mac_denylist_items:
 * @setting: the #NMSettingWireless
 *
 * Removes all denylisted MAC addresses.
 *
 * Since: 1.48
 **/
void
nm_setting_wireless_clear_mac_denylist_items(NMSettingWireless *setting)
{
    g_return_if_fail(NM_IS_SETTING_WIRELESS(setting));

    if (nm_strvarray_clear(&NM_SETTING_WIRELESS_GET_PRIVATE(setting)->mac_address_denylist.arr))
        _notify(setting, PROP_MAC_ADDRESS_DENYLIST);
}

/**
 * nm_setting_wireless_get_mac_address_blacklist:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:mac-address-blacklist property of the setting
 *
 * Deprecated: 1.48. Use nm_setting_wireless_get_mac_address_denylist() instead.
 **/
const char *const *
nm_setting_wireless_get_mac_address_blacklist(NMSettingWireless *setting)
{
    return nm_setting_wireless_get_mac_address_denylist(setting);
}

/**
 * nm_setting_wireless_get_num_mac_blacklist_items:
 * @setting: the #NMSettingWireless
 *
 * Returns: the number of blacklist MAC addresses
 *
 * Deprecated: 1.48. Use nm_setting_wireless_get_num_mac_denylist_items() instead.
 **/
guint32
nm_setting_wireless_get_num_mac_blacklist_items(NMSettingWireless *setting)
{
    return nm_setting_wireless_get_num_mac_denylist_items(setting);
}

/**
 * nm_setting_wireless_get_mac_blacklist_item:
 * @setting: the #NMSettingWireless
 * @idx: the zero-based index of the MAC address entry
 *
 * Since 1.46, access at index "len" is allowed and returns NULL.
 *
 * Returns: the denylisted MAC address string (hex-digits-and-colons notation)
 * at index @idx
 *
 * Deprecated: 1.48. Use nm_setting_wireless_get_mac_denylist_item() instead.
 **/
const char *
nm_setting_wireless_get_mac_blacklist_item(NMSettingWireless *setting, guint32 idx)
{
    return nm_setting_wireless_get_mac_denylist_item(setting, idx);
}

/**
 * nm_setting_wireless_add_mac_blacklist_item:
 * @setting: the #NMSettingWireless
 * @mac: the MAC address string (hex-digits-and-colons notation) to denylist
 *
 * Adds a new MAC address to the #NMSettingWireless:mac-address-denylist property.
 *
 * Returns: %TRUE if the MAC address was added; %FALSE if the MAC address
 * is invalid or was already present
 *
 * Deprecated: 1.48. Use nm_setting_wireless_add_mac_denylist_item() instead.
 **/
gboolean
nm_setting_wireless_add_mac_blacklist_item(NMSettingWireless *setting, const char *mac)
{
    return nm_setting_wireless_add_mac_denylist_item(setting, mac);
}

/**
 * nm_setting_wireless_remove_mac_blacklist_item:
 * @setting: the #NMSettingWireless
 * @idx: index number of the MAC address
 *
 * Removes the MAC address at index @idx from the denylist.
 *
 * Deprecated: 1.48. Use nm_setting_wireless_remove_mac_denylist_item() instead.
 **/
void
nm_setting_wireless_remove_mac_blacklist_item(NMSettingWireless *setting, guint32 idx)
{
    return nm_setting_wireless_remove_mac_denylist_item(setting, idx);
}

/**
 * nm_setting_wireless_remove_mac_blacklist_item_by_value:
 * @setting: the #NMSettingWireless
 * @mac: the MAC address string (hex-digits-and-colons notation) to remove from
 * the denylist
 *
 * Removes the MAC address @mac from the denylist.
 *
 * Returns: %TRUE if the MAC address was found and removed; %FALSE if it was not.
 *
 * Deprecated: 1.48. Use nm_setting_wireless_remove_mac_denylist_item_by_value() instead.
 **/
gboolean
nm_setting_wireless_remove_mac_blacklist_item_by_value(NMSettingWireless *setting, const char *mac)
{
    return nm_setting_wireless_remove_mac_denylist_item_by_value(setting, mac);
}

/**
 * nm_setting_wireless_clear_mac_blacklist_items:
 * @setting: the #NMSettingWireless
 *
 * Removes all denylisted MAC addresses.
 *
 * Deprecated: 1.48. Use nm_setting_wireless_clear_mac_denylist_items() instead.
 **/
void
nm_setting_wireless_clear_mac_blacklist_items(NMSettingWireless *setting)
{
    return nm_setting_wireless_clear_mac_denylist_items(setting);
}

/**
 * nm_setting_wireless_get_mtu:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:mtu property of the setting
 **/
guint32
nm_setting_wireless_get_mtu(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), 0);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->mtu;
}

/**
 * nm_setting_wireless_get_hidden:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:hidden property of the setting
 **/
gboolean
nm_setting_wireless_get_hidden(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), FALSE);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->hidden;
}

/**
 * nm_setting_wireless_get_powersave:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:powersave property of the setting
 *
 * Since: 1.2
 **/
guint32
nm_setting_wireless_get_powersave(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), 0);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->powersave;
}

/**
 * nm_setting_wireless_get_mac_address_randomization:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:mac-address-randomization property of the
 * setting
 *
 * Since: 1.2
 **/
NMSettingMacRandomization
nm_setting_wireless_get_mac_address_randomization(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), 0);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->mac_address_randomization;
}

/**
 * nm_setting_wireless_add_seen_bssid:
 * @setting: the #NMSettingWireless
 * @bssid: the new BSSID to add to the list
 *
 * Adds a new Wi-Fi AP's BSSID to the previously seen BSSID list of the setting.
 * NetworkManager now tracks previously seen BSSIDs internally so this function
 * no longer has much use. Actually, changes you make using this function will
 * not be preserved.
 *
 * Returns: %TRUE if @bssid was already known, %FALSE if not
 **/
gboolean
nm_setting_wireless_add_seen_bssid(NMSettingWireless *setting, const char *bssid)
{
    NMSettingWirelessPrivate *priv;
    gs_free char             *lower_bssid = NULL;

    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), FALSE);
    g_return_val_if_fail(bssid != NULL, FALSE);

    priv = NM_SETTING_WIRELESS_GET_PRIVATE(setting);

    lower_bssid = g_ascii_strdown(bssid, -1);

    if (!priv->seen_bssids) {
        priv->seen_bssids = g_ptr_array_new_with_free_func(g_free);
    } else {
        if (nm_strv_ptrarray_find_first(priv->seen_bssids, lower_bssid) >= 0)
            return FALSE;
    }

    g_ptr_array_add(priv->seen_bssids, g_steal_pointer(&lower_bssid));
    _notify(setting, PROP_SEEN_BSSIDS);
    return TRUE;
}

/**
 * nm_setting_wireless_get_num_seen_bssids:
 * @setting: the #NMSettingWireless
 *
 * Returns: the number of BSSIDs in the previously seen BSSID list
 **/
guint32
nm_setting_wireless_get_num_seen_bssids(NMSettingWireless *setting)
{
    NMSettingWirelessPrivate *priv;

    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), 0);

    priv = NM_SETTING_WIRELESS_GET_PRIVATE(setting);

    return priv->seen_bssids ? priv->seen_bssids->len : 0u;
}

/**
 * nm_setting_wireless_get_seen_bssid:
 * @setting: the #NMSettingWireless
 * @i: index of a BSSID in the previously seen BSSID list
 *
 * Returns: the BSSID at index @i
 **/
const char *
nm_setting_wireless_get_seen_bssid(NMSettingWireless *setting, guint32 i)
{
    NMSettingWirelessPrivate *priv;

    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), 0);

    priv = NM_SETTING_WIRELESS_GET_PRIVATE(setting);

    if (!priv->seen_bssids || i >= priv->seen_bssids->len)
        return NULL;

    return priv->seen_bssids->pdata[i];
}

static GVariant *
_to_dbus_fcn_seen_bssids(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    if (options && options->seen_bssids)
        return options->seen_bssids[0] ? g_variant_new_strv(options->seen_bssids, -1) : NULL;

    /* The seen-bssid property is special. It cannot be converted to D-Bus
     * like regular properties, only via the "options".
     *
     * This basically means, that only the daemon can provide seen-bssids as GVariant,
     * while when a client converts the property to GVariant, it gets lost.
     *
     * This has the odd effect, that when the client converts the setting to GVariant
     * and back, the seen-bssids gets lost. That is kinda desired here, because the to_dbus_fcn()
     * and from_dbus_fcn() have the meaning of how a setting gets transferred via D-Bus,
     * and not necessarily a loss-less conversion into another format and back. And when
     * transferring via D-Bus, then the option makes only sense when sending it from
     * the daemon to the client, not otherwise. */
    return NULL;
}

gboolean
_nm_setting_wireless_mac_blacklist_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    const gchar **mac_blacklist;

    if (!_nm_setting_use_legacy_property(setting,
                                         connection_dict,
                                         NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST,
                                         NM_SETTING_WIRELESS_MAC_ADDRESS_DENYLIST)) {
        *out_is_modified = FALSE;
        return TRUE;
    }
    mac_blacklist = g_variant_get_strv(value, NULL);

    g_object_set(setting, NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST, mac_blacklist, NULL);
    return TRUE;
}

gboolean
_nm_setting_wireless_mac_denylist_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    const gchar **mac_blacklist;

    if (!_nm_setting_use_legacy_property(setting,
                                         connection_dict,
                                         NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST,
                                         NM_SETTING_WIRELESS_MAC_ADDRESS_DENYLIST)) {
        *out_is_modified = FALSE;
        return TRUE;
    }
    mac_blacklist = g_variant_get_strv(value, NULL);

    g_object_set(setting, NM_SETTING_WIRELESS_MAC_ADDRESS_DENYLIST, mac_blacklist, NULL);
    return TRUE;
}

GVariant *
_nm_setting_wireless_mac_denylist_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    const char *const *mac_denylist;
    /* FIXME: `mac-address-denylist` is an alias of `mac-address-blacklist` property.
     * Serializing the property to the clients would break them as they won't
     * be able to drop it if they are not aware of the existance of
     * `mac-address-denylist`. In order to give them time to adapt their code,
     * NetworkManager is not serializing `mac-address-denylist` on DBus.
     */
    if (_nm_utils_is_manager_process) {
        return NULL;
    }

    mac_denylist = nm_setting_wireless_get_mac_address_denylist(NM_SETTING_WIRELESS(setting));

    return g_variant_new_strv(mac_denylist, -1);
}

static gboolean
_from_dbus_fcn_seen_bssids(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    NMSettingWirelessPrivate *priv;
    gs_free const char      **s = NULL;
    gsize                     len;
    gsize                     i;

    if (_nm_utils_is_manager_process) {
        /* in the manager process, we don't accept seen-bssid from the client.
         * Do nothing.  */
        *out_is_modified = FALSE;
        return TRUE;
    }

    priv = NM_SETTING_WIRELESS_GET_PRIVATE(setting);

    nm_clear_pointer(&priv->seen_bssids, g_ptr_array_unref);

    s = g_variant_get_strv(value, &len);
    if (len > 0) {
        priv->seen_bssids = g_ptr_array_new_full(len, g_free);
        for (i = 0; i < len; i++)
            g_ptr_array_add(priv->seen_bssids, g_strdup(s[i]));
    }
    return TRUE;
}

/**
 * nm_setting_wireless_get_ap_isolation:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:ap-isolation property of the setting
 *
 * Since: 1.28
 */
NMTernary
nm_setting_wireless_get_ap_isolation(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), NM_TERNARY_DEFAULT);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->ap_isolation;
}

/**
 * nm_setting_wireless_get_channel_width:
 * @setting: the #NMSettingWireless
 *
 * Returns the #NMSettingWireless:channel-width property.
 *
 * Returns: the channel width
 *
 * Since: 1.50
 */
NMSettingWirelessChannelWidth
nm_setting_wireless_get_channel_width(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), NM_SETTING_WIRELESS_CHANNEL_WIDTH_AUTO);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->channel_width;
}

/*****************************************************************************/

void
_nm_setting_wireless_normalize_mac_address_randomization(
    NMSettingWireless         *s_wifi,
    const char               **out_cloned_mac_address,
    NMSettingMacRandomization *out_mac_address_randomization)
{
    NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE(s_wifi);
    guint32                   mac_address_randomization;
    const char               *cloned_mac_address;

    mac_address_randomization = priv->mac_address_randomization;
    cloned_mac_address        = priv->cloned_mac_address;

    if (cloned_mac_address) {
        /* If cloned_mac_address is set, it takes precedence and determines
         * mac_address_randomization. */
        if (nm_streq(cloned_mac_address, "random"))
            mac_address_randomization = NM_SETTING_MAC_RANDOMIZATION_ALWAYS;
        else if (nm_streq(cloned_mac_address, "permanent"))
            mac_address_randomization = NM_SETTING_MAC_RANDOMIZATION_NEVER;
        else
            mac_address_randomization = NM_SETTING_MAC_RANDOMIZATION_DEFAULT;
    } else if (!NM_IN_SET(mac_address_randomization,
                          NM_SETTING_MAC_RANDOMIZATION_DEFAULT,
                          NM_SETTING_MAC_RANDOMIZATION_NEVER,
                          NM_SETTING_MAC_RANDOMIZATION_ALWAYS)) {
        /* cloned_mac_address is NULL and mac_address_randomization is invalid. Normalize
         * mac_address_randomization to the default. */
        mac_address_randomization = NM_SETTING_MAC_RANDOMIZATION_DEFAULT;
    } else if (mac_address_randomization != NM_SETTING_MAC_RANDOMIZATION_DEFAULT) {
        /* mac_address_randomization is not (guint32)set to the default. cloned_mac_address gets
         * overwritten. */
        cloned_mac_address = mac_address_randomization == NM_SETTING_MAC_RANDOMIZATION_ALWAYS
                                 ? "random"
                                 : "permanent";
    }

    *out_cloned_mac_address        = cloned_mac_address;
    *out_mac_address_randomization = mac_address_randomization;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingWirelessPrivate *priv          = NM_SETTING_WIRELESS_GET_PRIVATE(setting);
    const char               *valid_modes[] = {NM_SETTING_WIRELESS_MODE_INFRA,
                                               NM_SETTING_WIRELESS_MODE_ADHOC,
                                               NM_SETTING_WIRELESS_MODE_AP,
                                               NM_SETTING_WIRELESS_MODE_MESH,
                                               NULL};
    const char               *valid_bands[] = {"a", "bg", "6GHz", NULL};
    guint                     i;
    gsize                     length;
    GError                   *local = NULL;
    const char               *desired_cloned_mac_address;
    NMSettingMacRandomization desired_mac_address_randomization;

    if (!priv->ssid) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            _("property is missing"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_SSID);
        return FALSE;
    }

    length = g_bytes_get_size(priv->ssid);
    if (length == 0 || length > 32) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("SSID length is out of range <1-32> bytes"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_SSID);
        return FALSE;
    }

    if (priv->mode && !g_strv_contains(valid_modes, priv->mode)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid Wi-Fi mode"),
                    priv->mode);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_MODE);
        return FALSE;
    }

    if (priv->band && !g_strv_contains(valid_bands, priv->band)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid band"),
                    priv->band);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_BAND);
        return FALSE;
    }

    if (priv->channel && !priv->band) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_MISSING_PROPERTY,
                    _("'%s' requires setting '%s' property"),
                    NM_SETTING_WIRELESS_CHANNEL,
                    NM_SETTING_WIRELESS_BAND);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_BAND);
        return FALSE;
    }

    if (priv->channel) {
        if (!nm_utils_wifi_is_channel_valid(priv->channel, priv->band)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%d' is not a valid channel"),
                        priv->channel);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SETTING_NAME,
                           NM_SETTING_WIRELESS_CHANNEL);
            return FALSE;
        }
    }

    if ((g_strcmp0(priv->mode, NM_SETTING_WIRELESS_MODE_MESH) == 0)
        && !(priv->channel && priv->band)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_MISSING_PROPERTY,
                    _("'%s' requires '%s' and '%s' property"),
                    priv->mode,
                    NM_SETTING_WIRELESS_BAND,
                    NM_SETTING_WIRELESS_CHANNEL);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_MODE);
        return FALSE;
    }

    if (priv->bssid && !nm_utils_hwaddr_valid(priv->bssid, ETH_ALEN)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is invalid"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_BSSID);
        return FALSE;
    }

    if (priv->device_mac_address && !nm_utils_hwaddr_valid(priv->device_mac_address, ETH_ALEN)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is invalid"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_MAC_ADDRESS);
        return FALSE;
    }

    if (priv->cloned_mac_address && !NM_CLONED_MAC_IS_SPECIAL(priv->cloned_mac_address, TRUE)
        && !nm_utils_hwaddr_valid(priv->cloned_mac_address, ETH_ALEN)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is invalid"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS);
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
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_GENERATE_MAC_ADDRESS_MASK);
        g_error_free(local);
        return FALSE;
    }

    if (priv->mac_address_denylist.arr) {
        for (i = 0; i < priv->mac_address_denylist.arr->len; i++) {
            const char *mac = nm_g_array_index(priv->mac_address_denylist.arr, const char *, i);

            if (!nm_utils_hwaddr_valid(mac, ETH_ALEN)) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("'%s' is not a valid MAC address"),
                            mac);
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_WIRELESS_SETTING_NAME,
                               NM_SETTING_WIRELESS_MAC_ADDRESS_DENYLIST);
                return FALSE;
            }
        }
    }

    if (priv->seen_bssids) {
        for (i = 0; i < priv->seen_bssids->len; i++) {
            const char *b;

            b = priv->seen_bssids->pdata[i];
            if (!nm_utils_hwaddr_valid(b, ETH_ALEN)) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("'%s' is not a valid MAC address"),
                            b);
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_WIRELESS_SETTING_NAME,
                               NM_SETTING_WIRELESS_SEEN_BSSIDS);
                return FALSE;
            }
        }
    }

    if (!NM_IN_SET(priv->mac_address_randomization,
                   NM_SETTING_MAC_RANDOMIZATION_DEFAULT,
                   NM_SETTING_MAC_RANDOMIZATION_NEVER,
                   NM_SETTING_MAC_RANDOMIZATION_ALWAYS)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("invalid value"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION);
        return FALSE;
    }

    if (NM_FLAGS_ANY(priv->wake_on_wlan, NM_SETTING_WIRELESS_WAKE_ON_WLAN_EXCLUSIVE_FLAGS)) {
        if (!nm_utils_is_power_of_two(priv->wake_on_wlan)) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("Wake-on-WLAN mode 'default' and 'ignore' are exclusive flags"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SETTING_NAME,
                           NM_SETTING_WIRELESS_WAKE_ON_WLAN);
            return FALSE;
        }
    } else if (NM_FLAGS_ANY(priv->wake_on_wlan, ~NM_SETTING_WIRELESS_WAKE_ON_WLAN_ALL)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("Wake-on-WLAN trying to set unknown flag"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_WAKE_ON_WLAN);
        return FALSE;
    }

    if (priv->ap_isolation != NM_TERNARY_DEFAULT
        && !nm_streq0(priv->mode, NM_SETTING_WIRELESS_MODE_AP)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("AP isolation can be set only in AP mode"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_AP_ISOLATION);
        return FALSE;
    }

    if (priv->channel_width != NM_SETTING_WIRELESS_CHANNEL_WIDTH_AUTO) {
        if (!nm_streq0(priv->mode, NM_SETTING_WIRELESS_MODE_AP)) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("a specific channel width can be set only in AP mode"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SETTING_NAME,
                           NM_SETTING_WIRELESS_CHANNEL_WIDTH);
            return FALSE;
        }
        if (!priv->channel) {
            g_set_error_literal(
                error,
                NM_CONNECTION_ERROR,
                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                _("a specific channel width can be set only together with a fixed channel"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SETTING_NAME,
                           NM_SETTING_WIRELESS_CHANNEL_WIDTH);
            return FALSE;
        }

        if (priv->channel_width == NM_SETTING_WIRELESS_CHANNEL_WIDTH_80MHZ
            && !NM_IN_STRSET(priv->band, "a", "6GHz")) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("80MHz channels are only supported in the 5GHz and 6GHz bands"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SETTING_NAME,
                           NM_SETTING_WIRELESS_CHANNEL_WIDTH);
            return FALSE;
        }
    }

    /* from here on, check for NM_SETTING_VERIFY_NORMALIZABLE conditions. */

    _nm_setting_wireless_normalize_mac_address_randomization(NM_SETTING_WIRELESS(setting),
                                                             &desired_cloned_mac_address,
                                                             &desired_mac_address_randomization);
    if (desired_mac_address_randomization != priv->mac_address_randomization
        || !nm_streq0(desired_cloned_mac_address, priv->cloned_mac_address)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("conflicting value of mac-address-randomization and cloned-mac-address"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS);
        return NM_SETTING_VERIFY_NORMALIZABLE;
    }

    if (priv->tx_power != 0 || priv->rate != 0) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("property is deprecated and not implemented"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       priv->tx_power != 0 ? NM_SETTING_WIRELESS_TX_POWER
                                           : NM_SETTING_WIRELESS_RATE);
        return NM_SETTING_VERIFY_NORMALIZABLE;
    }

    return TRUE;
}

static NMTernary
compare_fcn_cloned_mac_address(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil)
{
    return !set_b
           || nm_streq0(NM_SETTING_WIRELESS_GET_PRIVATE(set_a)->cloned_mac_address,
                        NM_SETTING_WIRELESS_GET_PRIVATE(set_b)->cloned_mac_address);
}

static NMTernary
compare_fcn_seen_bssids(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil)
{
    return !set_b
           || (nm_strv_ptrarray_cmp(NM_SETTING_WIRELESS_GET_PRIVATE(set_a)->seen_bssids,
                                    NM_SETTING_WIRELESS_GET_PRIVATE(set_b)->seen_bssids)
               == 0);
}

/*****************************************************************************/

static GVariant *
security_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    if (!_nm_connection_serialize_non_secret(flags))
        return NULL;

    if (!connection)
        return NULL;

    if (!nm_connection_get_setting_wireless_security(connection))
        return NULL;

    return g_variant_new_string(NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
}

/**
 * nm_setting_wireless_get_wake_on_wlan:
 * @setting: the #NMSettingWireless
 *
 * Returns the Wake-on-WLAN options enabled for the connection
 *
 * Returns: the Wake-on-WLAN options
 *
 * Since: 1.12
 */
NMSettingWirelessWakeOnWLan
nm_setting_wireless_get_wake_on_wlan(NMSettingWireless *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WIRELESS(setting), NM_SETTING_WIRELESS_WAKE_ON_WLAN_NONE);

    return NM_SETTING_WIRELESS_GET_PRIVATE(setting)->wake_on_wlan;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingWireless        *setting = NM_SETTING_WIRELESS(object);
    NMSettingWirelessPrivate *priv    = NM_SETTING_WIRELESS_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_CLONED_MAC_ADDRESS:
        g_value_set_string(value, nm_setting_wireless_get_cloned_mac_address(setting));
        break;
    case PROP_SEEN_BSSIDS:
        g_value_take_boxed(
            value,
            priv->seen_bssids
                ? nm_strv_dup((char **) priv->seen_bssids->pdata, priv->seen_bssids->len, TRUE)
                : NULL);
        break;
    default:
        _nm_setting_property_get_property_direct(object, prop_id, value, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingWireless        *self = NM_SETTING_WIRELESS(object);
    NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE(self);
    gboolean                  bool_val;
    _PropertyEnums            prop1 = PROP_0;
    _PropertyEnums            prop2 = PROP_0;

    switch (prop_id) {
    case PROP_CLONED_MAC_ADDRESS:
        bool_val = !!priv->cloned_mac_address;

        if (nm_strdup_reset_take(
                &priv->cloned_mac_address,
                _nm_utils_hwaddr_canonical_or_invalid(g_value_get_string(value), ETH_ALEN)))
            prop1 = prop_id;

        if (bool_val && !priv->cloned_mac_address) {
            /* cloned-mac-address was set before but was now explicitly cleared.
             * In this case, we also clear mac-address-randomization flag */
            if (priv->mac_address_randomization != NM_SETTING_MAC_RANDOMIZATION_DEFAULT) {
                priv->mac_address_randomization = NM_SETTING_MAC_RANDOMIZATION_DEFAULT;
                prop2                           = PROP_MAC_ADDRESS_RANDOMIZATION;
            }
        }

        nm_gobject_notify_together(self, prop1, prop2);
        break;
    case PROP_SEEN_BSSIDS:
    {
        gs_unref_ptrarray GPtrArray *arr_old = NULL;
        const char *const           *strv;

        arr_old = g_steal_pointer(&priv->seen_bssids);

        strv = g_value_get_boxed(value);
        if (strv && strv[0]) {
            gsize i, l;

            l                 = NM_PTRARRAY_LEN(strv);
            priv->seen_bssids = g_ptr_array_new_full(l, g_free);
            for (i = 0; i < l; i++)
                g_ptr_array_add(priv->seen_bssids, g_strdup(strv[i]));
        }
        break;
    }
    default:
        _nm_setting_property_set_property_direct(object, prop_id, value, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_setting_wireless_init(NMSettingWireless *setting)
{}

/**
 * nm_setting_wireless_new:
 *
 * Creates a new #NMSettingWireless object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingWireless object
 **/
NMSetting *
nm_setting_wireless_new(void)
{
    return g_object_new(NM_TYPE_SETTING_WIRELESS, NULL);
}

static void
finalize(GObject *object)
{
    NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE(object);

    g_free(priv->cloned_mac_address);
    nm_g_ptr_array_unref(priv->seen_bssids);

    G_OBJECT_CLASS(nm_setting_wireless_parent_class)->finalize(object);
}

static void
nm_setting_wireless_class_init(NMSettingWirelessClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array_sized(25);
    guint           prop_idx;

    object_class->set_property = set_property;
    object_class->get_property = get_property;
    object_class->finalize     = finalize;

    setting_class->verify = verify;

    /**
     * NMSettingWireless:ssid:
     *
     * SSID of the Wi-Fi network. Must be specified.
     **/
    /* ---keyfile---
     * property: ssid
     * format: string (or decimal-byte list - obsolete)
     * description: SSID of Wi-Fi network.
     * example: ssid=Quick Net
     * ---end---
     */
    /* ---ifcfg-rh---
     * property: ssid
     * variable: ESSID
     * description: SSID of Wi-Fi network.
     * example: ESSID="Quick Net"
     * ---end---
     */
    _nm_setting_property_define_direct_bytes(properties_override,
                                             obj_properties,
                                             NM_SETTING_WIRELESS_SSID,
                                             PROP_SSID,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingWirelessPrivate,
                                             ssid);

    /**
     * NMSettingWireless:mode:
     *
     * Wi-Fi network mode; one of "infrastructure", "mesh", "adhoc" or "ap".  If blank,
     * infrastructure is assumed.
     **/
    /* ---ifcfg-rh---
     * property: mode
     * variable: MODE
     * values: Ad-Hoc, Managed (Auto)  [case insensitive]
     * description: Wi-Fi network mode.
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRELESS_MODE,
                                              PROP_MODE,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWirelessPrivate,
                                              mode,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingWireless:band:
     *
     * 802.11 frequency band of the network.  One of "a" for 5GHz,
     * "bg" for 2.4GHz or "6GHz".  This will lock associations to the
     * Wi-Fi network to the specific band, i.e. if "a" is specified,
     * the device will not associate with the same network in the
     * 2.4GHz (bg) or 6GHz bands even if the network's settings are
     * compatible.  This setting depends on specific driver capability
     * and may not work with all drivers.
     **/
    /* ---ifcfg-rh---
     * property: band
     * variable: BAND(+)
     * values: a, bg, 6GHz
     * description: BAND alone is honored, but CHANNEL overrides BAND since it
     *   implies a band.
     * example: BAND=bg
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRELESS_BAND,
                                              PROP_BAND,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWirelessPrivate,
                                              band,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingWireless:channel:
     *
     * Wireless channel to use for the Wi-Fi connection.  The device will only
     * join (or create for Ad-Hoc networks) a Wi-Fi network on the specified
     * channel.  Because channel numbers overlap between bands, this property
     * also requires the "band" property to be set.
     **/
    /* ---ifcfg-rh---
     * property: channel
     * variable: CHANNEL
     * description: Channel used for the Wi-Fi communication.
     * example: CHANNEL=6
     * ---end---
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRELESS_CHANNEL,
                                              PROP_CHANNEL,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWirelessPrivate,
                                              channel);

    /**
     * NMSettingWireless:bssid:
     *
     * If specified, directs the device to only associate with the given access
     * point.  This capability is highly driver dependent and not supported by
     * all devices.  Note: this property does not control the BSSID used when
     * creating an Ad-Hoc network and is unlikely to in the future.
     *
     * Locking a client profile to a certain BSSID will prevent roaming and also
     * disable background scanning. That can be useful, if there is only one access
     * point for the SSID.
     **/
    /* ---ifcfg-rh---
     * property: bssid
     * variable: BSSID(+)
     * description: Restricts association only to a single AP.
     * example: BSSID=00:1E:BD:64:83:21
     * ---end---
     */
    _nm_setting_property_define_direct_mac_address(properties_override,
                                                   obj_properties,
                                                   NM_SETTING_WIRELESS_BSSID,
                                                   PROP_BSSID,
                                                   NM_SETTING_PARAM_NONE,
                                                   NMSettingWirelessPrivate,
                                                   bssid,
                                                   .direct_set_string_mac_address_len = ETH_ALEN);

    /**
     * NMSettingWireless:rate:
     *
     * This property is not implemented and has no effect.
     *
     * Deprecated: 1.44: This property is not implemented and has no effect.
     **/
    /* ---ifcfg-rh---
     * property: rate
     * variable: (none)
     * description: This property is deprecated and not handled by ifcfg-rh plugin.
     * ---end---
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRELESS_RATE,
                                              PROP_RATE,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingWirelessPrivate,
                                              rate,
                                              .is_deprecated = TRUE, );

    /**
     * NMSettingWireless:tx-power:
     *
     * This property is not implemented and has no effect.
     *
     * Deprecated: 1.44: This property is not implemented and has no effect.
     **/
    /* ---ifcfg-rh---
     * property: tx-power
     * variable: (none)
     * description: This property is deprecated and not handled by ifcfg-rh plugin.
     * ---end---
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRELESS_TX_POWER,
                                              PROP_TX_POWER,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingWirelessPrivate,
                                              tx_power,
                                              .is_deprecated = TRUE, );

    /**
     * NMSettingWireless:mac-address:
     *
     * If specified, this connection will only apply to the Wi-Fi device whose
     * permanent MAC address matches. This property does not change the MAC
     * address of the device (i.e. MAC spoofing).
     **/
    /* ---keyfile---
     * property: mac-address
     * format: usual hex-digits-and-colons notation
     * description: MAC address in traditional hex-digits-and-colons notation
     *   (e.g. 00:22:68:12:79:A2), or semicolon separated list of 6 bytes (obsolete)
     *   (e.g. 0;34;104;18;121;162).
     * ---end---
     */
    /* ---ifcfg-rh---
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
                                                   NM_SETTING_WIRELESS_MAC_ADDRESS,
                                                   PROP_MAC_ADDRESS,
                                                   NM_SETTING_PARAM_NONE,
                                                   NMSettingWirelessPrivate,
                                                   device_mac_address,
                                                   .direct_set_string_mac_address_len = ETH_ALEN);

    /**
     * NMSettingWireless:cloned-mac-address:
     *
     * If specified, request that the device use this MAC address instead.
     * This is known as MAC cloning or spoofing.
     *
     * Beside explicitly specifying a MAC address, the special values "preserve", "permanent",
     * "random", "stable" and "stable-ssid" are supported.
     * "preserve" means not to touch the MAC address on activation.
     * "permanent" means to use the permanent hardware address of the device.
     * "random" creates a random MAC address on each connect.
     * "stable" creates a hashed MAC address based on connection.stable-id and a
     * machine dependent key.
     * "stable-ssid" creates a hashed MAC address based on the SSID, the same as setting the
     * stable-id to "${NETWORK_SSID}".
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
     */
    /* ---ifcfg-rh---
     * property: cloned-mac-address
     * variable: MACADDR
     * description: Cloned (spoofed) MAC address in traditional hex-digits-and-colons
     *    notation (e.g. 00:22:68:14:5A:99).
     * ---end---
     */
    /* ---dbus---
     * property: cloned-mac-address
     * format: byte array
     * description: This D-Bus field is deprecated in favor of "assigned-mac-address"
     *    which is more flexible and allows specifying special variants like "random".
     *    For libnm and nmcli, this field is called "cloned-mac-address".
     * ---end---
     */
    obj_properties[PROP_CLONED_MAC_ADDRESS] =
        g_param_spec_string(NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_EXPLICIT_NOTIFY
                                | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);
    _nm_properties_override_gobj(
        properties_override,
        obj_properties[PROP_CLONED_MAC_ADDRESS],
        NM_SETT_INFO_PROPERT_TYPE_DBUS(
            G_VARIANT_TYPE_BYTESTRING,
            .compare_fcn           = compare_fcn_cloned_mac_address,
            .to_dbus_fcn           = _nm_sett_info_prop_to_dbus_fcn_cloned_mac_address,
            .from_dbus_fcn         = _nm_sett_info_prop_from_dbus_fcn_cloned_mac_address,
            .missing_from_dbus_fcn = _nm_sett_info_prop_missing_from_dbus_fcn_cloned_mac_address, ),
        .dbus_deprecated = TRUE, );

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
     * NMSettingWireless:generate-mac-address-mask:
     *
     * With #NMSettingWireless:cloned-mac-address setting "random" or "stable",
     * by default all bits of the MAC address are scrambled and a locally-administered,
     * unicast MAC address is created. This property allows one to specify that certain bits
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
                                              NM_SETTING_WIRELESS_GENERATE_MAC_ADDRESS_MASK,
                                              PROP_GENERATE_MAC_ADDRESS_MASK,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingWirelessPrivate,
                                              generate_mac_address_mask,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingWireless:mac-address-blacklist:
     *
     * A list of permanent MAC addresses of Wi-Fi devices to which this
     * connection should never apply.  Each MAC address should be given in the
     * standard hex-digits-and-colons notation (eg "00:11:22:33:44:55").
     **/
    /* ---keyfile---
     * property: mac-address-blacklist
     * format: list of MACs (separated with semicolons)
     * description: MAC address blacklist.
     * example: mac-address-blacklist= 00:22:68:12:79:A6;00:22:68:12:79:78
     * ---end---
     */
    /* ---ifcfg-rh---
     * property: mac-address-blacklist
     * variable: HWADDR_BLACKLIST(+)
     * description: It denies usage of the connection for any device whose address
     *   is listed.
     * ---end---
     */
    prop_idx = _nm_setting_property_define_direct_strv(
        properties_override,
        obj_properties,
        NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST,
        PROP_MAC_ADDRESS_BLACKLIST,
        NM_SETTING_PARAM_FUZZY_IGNORE,
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_STRING_ARRAY,
                                       .direct_type = NM_VALUE_TYPE_STRV,
                                       .compare_fcn = _nm_setting_property_compare_fcn_direct,
                                       .to_dbus_fcn = _nm_setting_property_to_dbus_fcn_direct,
                                       .from_dbus_fcn =
                                           _nm_setting_wireless_mac_blacklist_from_dbus, ),
        NMSettingWirelessPrivate,
        mac_address_denylist,
        .direct_set_strv_normalize_hwaddr = TRUE,
        .direct_strv_not_null             = TRUE,
        .direct_is_aliased_field          = TRUE,
        .is_deprecated                    = TRUE);

    /**
     * NMSettingWireless:mac-address-denylist:
     *
     * A list of permanent MAC addresses of Wi-Fi devices to which this
     * connection should never apply.  Each MAC address should be given in the
     * standard hex-digits-and-colons notation (eg "00:11:22:33:44:55").
     **/
    /* ---keyfile---
     * property: mac-address-denylist
     * format: list of MACs (separated with semicolons)
     * description: MAC address denylist.
     * example: mac-address-denylist= 00:22:68:12:79:A6;00:22:68:12:79:78
     * ---end---
     */
    /* ---ifcfg-rh---
     * property: mac-address-denylist
     * variable: HWADDR_BLACKLIST(+)
     * description: It denies usage of the connection for any device whose address
     *   is listed.
     * ---end---
     */
    _nm_setting_property_define_direct_strv(
        properties_override,
        obj_properties,
        NM_SETTING_WIRELESS_MAC_ADDRESS_DENYLIST,
        PROP_MAC_ADDRESS_DENYLIST,
        NM_SETTING_PARAM_FUZZY_IGNORE,
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_STRING_ARRAY,
                                       .direct_type = NM_VALUE_TYPE_STRV,
                                       .compare_fcn = _nm_setting_property_compare_fcn_direct,
                                       .to_dbus_fcn = _nm_setting_wireless_mac_denylist_to_dbus,
                                       .from_dbus_fcn =
                                           _nm_setting_wireless_mac_denylist_from_dbus, ),
        NMSettingWirelessPrivate,
        mac_address_denylist,
        .direct_set_strv_normalize_hwaddr = TRUE,
        .direct_strv_not_null             = TRUE,
        .direct_also_notify               = obj_properties[PROP_MAC_ADDRESS_BLACKLIST], );

    nm_g_array_index(properties_override, NMSettInfoProperty, prop_idx).direct_also_notify =
        obj_properties[PROP_MAC_ADDRESS_DENYLIST];

    /**
     * NMSettingWireless:seen-bssids:
     *
     * A list of BSSIDs (each BSSID formatted as a MAC address like
     * "00:11:22:33:44:55") that have been detected as part of the Wi-Fi
     * network.  NetworkManager internally tracks previously seen BSSIDs. The
     * property is only meant for reading and reflects the BSSID list of
     * NetworkManager. The changes you make to this property will not be
     * preserved.
     *
     * This is not a regular property that the user would configure. Instead,
     * NetworkManager automatically sets the seen BSSIDs and tracks them internally
     * in "/var/lib/NetworkManager/seen-bssids" file.
     **/
    /* ---ifcfg-rh---
     * property: seen-bssids
     * variable: (none)
     * description: This is not a regular property that would be configured by the
     *   user. It is not handled by ifcfg-rh plugin.
     * ---end---
     */
    obj_properties[PROP_SEEN_BSSIDS] = g_param_spec_boxed(
        NM_SETTING_WIRELESS_SEEN_BSSIDS,
        "",
        "",
        G_TYPE_STRV,
        G_PARAM_READWRITE | NM_SETTING_PARAM_FUZZY_IGNORE | G_PARAM_STATIC_STRINGS);
    _nm_properties_override_gobj(
        properties_override,
        obj_properties[PROP_SEEN_BSSIDS],
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_STRING_ARRAY,
                                       .to_dbus_fcn   = _to_dbus_fcn_seen_bssids,
                                       .from_dbus_fcn = _from_dbus_fcn_seen_bssids,
                                       .compare_fcn   = compare_fcn_seen_bssids, ));

    /**
     * NMSettingWireless:mtu:
     *
     * If non-zero, only transmit packets of the specified size or smaller,
     * breaking larger packets up into multiple Ethernet frames.
     **/
    /* ---ifcfg-rh---
     * property: mtu
     * variable: MTU
     * description: MTU of the wireless interface.
     * ---end---
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRELESS_MTU,
                                              PROP_MTU,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingWirelessPrivate,
                                              mtu);

    /**
     * NMSettingWireless:hidden:
     *
     * If %TRUE, indicates that the network is a non-broadcasting network that
     * hides its SSID. This works both in infrastructure and AP mode.
     *
     * In infrastructure mode, various workarounds are used for a more reliable
     * discovery of hidden networks, such as probe-scanning the SSID.  However,
     * these workarounds expose inherent insecurities with hidden SSID networks,
     * and thus hidden SSID networks should be used with caution.
     *
     * In AP mode, the created network does not broadcast its SSID.
     *
     * Note that marking the network as hidden may be a privacy issue for you
     * (in infrastructure mode) or client stations (in AP mode), as the explicit
     * probe-scans are distinctly recognizable on the air.
     *
     **/
    /* ---ifcfg-rh---
     * property: hidden
     * variable: SSID_HIDDEN(+)
     * description: Whether the network hides the SSID.
     * ---end---
     */
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_WIRELESS_HIDDEN,
                                               PROP_HIDDEN,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingWirelessPrivate,
                                               hidden);

    /**
     * NMSettingWireless:powersave:
     *
     * One of %NM_SETTING_WIRELESS_POWERSAVE_DISABLE (disable Wi-Fi power
     * saving), %NM_SETTING_WIRELESS_POWERSAVE_ENABLE (enable Wi-Fi power
     * saving), %NM_SETTING_WIRELESS_POWERSAVE_IGNORE (don't touch currently
     * configure setting) or %NM_SETTING_WIRELESS_POWERSAVE_DEFAULT (use the
     * globally configured value). All other values are reserved.
     *
     * Since: 1.2
     **/
    /* ---ifcfg-rh---
     * property: powersave
     * variable: POWERSAVE(+)
     * values: default, ignore, enable, disable
     * description: Enables or disables Wi-Fi power saving.
     * example: POWERSAVE=enable
     * ---end---
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRELESS_POWERSAVE,
                                              PROP_POWERSAVE,
                                              0,
                                              G_MAXUINT32,
                                              NM_SETTING_WIRELESS_POWERSAVE_DEFAULT,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWirelessPrivate,
                                              powersave);

    /**
     * NMSettingWireless:mac-address-randomization:
     *
     * One of %NM_SETTING_MAC_RANDOMIZATION_DEFAULT (never randomize unless
     * the user has set a global default to randomize and the supplicant
     * supports randomization),  %NM_SETTING_MAC_RANDOMIZATION_NEVER (never
     * randomize the MAC address), or %NM_SETTING_MAC_RANDOMIZATION_ALWAYS
     * (always randomize the MAC address).
     *
     * Since: 1.2
     * Deprecated: 1.4: Use the #NMSettingWireless:cloned-mac-address property instead.
     **/
    /* ---ifcfg-rh---
     * property: mac-address-randomization
     * variable: MAC_ADDRESS_RANDOMIZATION(+)
     * values: default, never, always
     * description: Enables or disables Wi-Fi MAC address randomization.
     * example: MAC_ADDRESS_RANDOMIZATION=always
     * ---end---
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION,
                                              PROP_MAC_ADDRESS_RANDOMIZATION,
                                              0,
                                              G_MAXUINT32,
                                              NM_SETTING_MAC_RANDOMIZATION_DEFAULT,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWirelessPrivate,
                                              mac_address_randomization,
                                              .is_deprecated = TRUE, );

    /* ---dbus---
     * property: security
     * description: This property is deprecated and has no effect.
     * For backwards compatibility, it can be set to "802-11-wireless-security"
     * if the profile has a wireless security setting.
     * ---end---
     */
    _nm_properties_override_dbus(
        properties_override,
        "security",
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_STRING,
                                       .to_dbus_fcn = security_to_dbus,
                                       .compare_fcn = _nm_setting_property_compare_fcn_ignore, ),
        .dbus_deprecated = TRUE, );

    /**
     * NMSettingWireless:wake-on-wlan:
     *
     * The #NMSettingWirelessWakeOnWLan options to enable. Not all devices support all options.
     * May be any combination of %NM_SETTING_WIRELESS_WAKE_ON_WLAN_ANY,
     * %NM_SETTING_WIRELESS_WAKE_ON_WLAN_DISCONNECT,
     * %NM_SETTING_WIRELESS_WAKE_ON_WLAN_MAGIC,
     * %NM_SETTING_WIRELESS_WAKE_ON_WLAN_GTK_REKEY_FAILURE,
     * %NM_SETTING_WIRELESS_WAKE_ON_WLAN_EAP_IDENTITY_REQUEST,
     * %NM_SETTING_WIRELESS_WAKE_ON_WLAN_4WAY_HANDSHAKE,
     * %NM_SETTING_WIRELESS_WAKE_ON_WLAN_RFKILL_RELEASE,
     * %NM_SETTING_WIRELESS_WAKE_ON_WLAN_TCP or the special values
     * %NM_SETTING_WIRELESS_WAKE_ON_WLAN_DEFAULT (to use global settings) and
     * %NM_SETTING_WIRELESS_WAKE_ON_WLAN_IGNORE (to disable management of Wake-on-LAN in
     * NetworkManager).
     *
     * Since: 1.12
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_WIRELESS_WAKE_ON_WLAN,
                                              PROP_WAKE_ON_WLAN,
                                              0,
                                              G_MAXUINT32,
                                              NM_SETTING_WIRELESS_WAKE_ON_WLAN_DEFAULT,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWirelessPrivate,
                                              wake_on_wlan);

    /**
     * NMSettingWireless:ap-isolation
     *
     * Configures AP isolation, which prevents communication between
     * wireless devices connected to this AP. This property can be set
     * to a value different from %NM_TERNARY_DEFAULT only when the
     * interface is configured in AP mode.
     *
     * If set to %NM_TERNARY_TRUE, devices are not able to communicate
     * with each other. This increases security because it protects
     * devices against attacks from other clients in the network. At
     * the same time, it prevents devices to access resources on the
     * same wireless networks as file shares, printers, etc.
     *
     * If set to %NM_TERNARY_FALSE, devices can talk to each other.
     *
     * When set to %NM_TERNARY_DEFAULT, the global default is used; in
     * case the global default is unspecified it is assumed to be
     * %NM_TERNARY_FALSE.
     *
     * Since: 1.28
     **/
    /* ---ifcfg-rh---
     * property: ap-isolation
     * variable: AP_ISOLATION(+)
     * values: "yes", "no"
     * default: missing variable means global default
     * description: Whether AP isolation is enabled
     * ---end---
     */
    _nm_setting_property_define_direct_ternary_enum(properties_override,
                                                    obj_properties,
                                                    NM_SETTING_WIRELESS_AP_ISOLATION,
                                                    PROP_AP_ISOLATION,
                                                    NM_SETTING_PARAM_FUZZY_IGNORE,
                                                    NMSettingWirelessPrivate,
                                                    ap_isolation);

    /**
     * NMSettingWireless:channel-width:
     *
     * Specifies width of the wireless channel in Access Point (AP) mode.
     *
     * When set to %NM_SETTING_WIRELESS_CHANNEL_WIDTH_AUTO (the default), the
     * channel width is automatically determined. At the moment, this means that
     * the safest (smallest) width is chosen.
     *
     * If the value is not %NM_SETTING_WIRELESS_CHANNEL_WIDTH_AUTO, then the
     * 'channel' property must also be set. When using the 2.4GHz band, the width
     * can be at most 40MHz.
     *
     * This property can be set to a value different from
     * %NM_SETTING_WIRELESS_CHANNEL_WIDTH_AUTO only when the interface is configured
     * in AP mode.
     *
     * Since: 1.50
     **/
    _nm_setting_property_define_direct_enum(properties_override,
                                            obj_properties,
                                            NM_SETTING_WIRELESS_CHANNEL_WIDTH,
                                            PROP_CHANNEL_WIDTH,
                                            NM_TYPE_SETTING_WIRELESS_CHANNEL_WIDTH,
                                            NM_SETTING_WIRELESS_CHANNEL_WIDTH_AUTO,
                                            NM_SETTING_PARAM_NONE,
                                            NULL,
                                            NMSettingWirelessPrivate,
                                            channel_width);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_WIRELESS,
                             NULL,
                             properties_override,
                             G_STRUCT_OFFSET(NMSettingWireless, _priv));
}
