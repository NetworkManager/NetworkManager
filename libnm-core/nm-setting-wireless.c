/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2014 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include "config.h"

#include <string.h>
#include <net/ethernet.h>

#include "nm-setting-wireless.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-wireless
 * @short_description: Describes connection properties for 802.11 Wi-Fi networks
 *
 * The #NMSettingWireless object is a #NMSetting subclass that describes properties
 * necessary for connection to 802.11 Wi-Fi networks.
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingWireless, nm_setting_wireless, NM_TYPE_SETTING,
                         _nm_register_setting (WIRELESS, 1))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_WIRELESS)

#define NM_SETTING_WIRELESS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_WIRELESS, NMSettingWirelessPrivate))

typedef struct {
	GBytes *ssid;
	char *mode;
	char *band;
	guint32 channel;
	char *bssid;
	guint32 rate;
	guint32 tx_power;
	char *device_mac_address;
	char *cloned_mac_address;
	GArray *mac_address_blacklist;
	guint32 mtu;
	GSList *seen_bssids;
	gboolean hidden;
	guint32 powersave;
} NMSettingWirelessPrivate;

enum {
	PROP_0,
	PROP_SSID,
	PROP_MODE,
	PROP_BAND,
	PROP_CHANNEL,
	PROP_BSSID,
	PROP_RATE,
	PROP_TX_POWER,
	PROP_MAC_ADDRESS,
	PROP_CLONED_MAC_ADDRESS,
	PROP_MAC_ADDRESS_BLACKLIST,
	PROP_MTU,
	PROP_SEEN_BSSIDS,
	PROP_HIDDEN,
	PROP_POWERSAVE,

	LAST_PROP
};

static gboolean
match_cipher (const char *cipher,
              const char *expected,
              guint32 wpa_flags,
              guint32 rsn_flags,
              guint32 flag)
{
	if (strcmp (cipher, expected) != 0)
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
nm_setting_wireless_ap_security_compatible (NMSettingWireless *s_wireless,
                                            NMSettingWirelessSecurity *s_wireless_sec,
                                            NM80211ApFlags ap_flags,
                                            NM80211ApSecurityFlags ap_wpa,
                                            NM80211ApSecurityFlags ap_rsn,
                                            NM80211Mode ap_mode)
{
	const char *key_mgmt = NULL, *cipher;
	guint32 num, i;
	gboolean found = FALSE;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (s_wireless), FALSE);

	if (!s_wireless_sec) {
		if (   (ap_flags & NM_802_11_AP_FLAGS_PRIVACY)
		    || (ap_wpa != NM_802_11_AP_SEC_NONE)
		    || (ap_rsn != NM_802_11_AP_SEC_NONE))
			return FALSE;
		return TRUE;
	}

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wireless_sec);
	if (!key_mgmt)
		return FALSE;

	/* Static WEP */
	if (!strcmp (key_mgmt, "none")) {
		if (   !(ap_flags & NM_802_11_AP_FLAGS_PRIVACY)
		    || (ap_wpa != NM_802_11_AP_SEC_NONE)
		    || (ap_rsn != NM_802_11_AP_SEC_NONE))
			return FALSE;
		return TRUE;
	}

	/* Adhoc WPA */
	if (!strcmp (key_mgmt, "wpa-none")) {
		if (ap_mode != NM_802_11_MODE_ADHOC)
			return FALSE;
		/* FIXME: validate ciphers if they're in the beacon */
		return TRUE;
	}

	/* Adhoc WPA2 (ie, RSN IBSS) */
	if (ap_mode == NM_802_11_MODE_ADHOC) {
		if (strcmp (key_mgmt, "wpa-psk"))
			return FALSE;

		/* Ensure the AP has RSN PSK capability */
		if (!(ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_PSK))
			return FALSE;

		/* Fall through and check ciphers in generic WPA-PSK code */
	}

	/* Dynamic WEP or LEAP */
	if (!strcmp (key_mgmt, "ieee8021x")) {
		if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
			return FALSE;

		/* If the AP is advertising a WPA IE, make sure it supports WEP ciphers */
		if (ap_wpa != NM_802_11_AP_SEC_NONE) {
			if (!(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
				return FALSE;

			/* quick check; can't use AP if it doesn't support at least one
			 * WEP cipher in both pairwise and group suites.
			 */
			if (   !(ap_wpa & (NM_802_11_AP_SEC_PAIR_WEP40 | NM_802_11_AP_SEC_PAIR_WEP104))
			    || !(ap_wpa & (NM_802_11_AP_SEC_GROUP_WEP40 | NM_802_11_AP_SEC_GROUP_WEP104)))
				return FALSE;

			/* Match at least one pairwise cipher with AP's capability if the
			 * wireless-security setting explicitly lists pairwise ciphers
			 */
			num = nm_setting_wireless_security_get_num_pairwise (s_wireless_sec);
			for (i = 0, found = FALSE; i < num; i++) {
				cipher = nm_setting_wireless_security_get_pairwise (s_wireless_sec, i);
				if ((found = match_cipher (cipher, "wep40", ap_wpa, ap_wpa, NM_802_11_AP_SEC_PAIR_WEP40)))
					break;
				if ((found = match_cipher (cipher, "wep104", ap_wpa, ap_wpa, NM_802_11_AP_SEC_PAIR_WEP104)))
					break;
			}
			if (!found && num)
				return FALSE;

			/* Match at least one group cipher with AP's capability if the
			 * wireless-security setting explicitly lists group ciphers
			 */
			num = nm_setting_wireless_security_get_num_groups (s_wireless_sec);
			for (i = 0, found = FALSE; i < num; i++) {
				cipher = nm_setting_wireless_security_get_group (s_wireless_sec, i);
				if ((found = match_cipher (cipher, "wep40", ap_wpa, ap_wpa, NM_802_11_AP_SEC_GROUP_WEP40)))
					break;
				if ((found = match_cipher (cipher, "wep104", ap_wpa, ap_wpa, NM_802_11_AP_SEC_GROUP_WEP104)))
					break;
			}
			if (!found && num)
				return FALSE;
		}
		return TRUE;
	}

	/* WPA[2]-PSK and WPA[2] Enterprise */
	if (   !strcmp (key_mgmt, "wpa-psk")
	    || !strcmp (key_mgmt, "wpa-eap")) {

		if (!strcmp (key_mgmt, "wpa-psk")) {
			if (   !(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_PSK)
			    && !(ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_PSK))
				return FALSE;
		} else if (!strcmp (key_mgmt, "wpa-eap")) {
			if (   !(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
			    && !(ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
				return FALSE;
		}

		// FIXME: should handle WPA and RSN separately here to ensure that
		// if the Connection only uses WPA we don't match a cipher against
		// the AP's RSN IE instead

		/* Match at least one pairwise cipher with AP's capability if the
		 * wireless-security setting explicitly lists pairwise ciphers
		 */
		num = nm_setting_wireless_security_get_num_pairwise (s_wireless_sec);
		for (i = 0, found = FALSE; i < num; i++) {
			cipher = nm_setting_wireless_security_get_pairwise (s_wireless_sec, i);
			if ((found = match_cipher (cipher, "tkip", ap_wpa, ap_rsn, NM_802_11_AP_SEC_PAIR_TKIP)))
				break;
			if ((found = match_cipher (cipher, "ccmp", ap_wpa, ap_rsn, NM_802_11_AP_SEC_PAIR_CCMP)))
				break;
		}
		if (!found && num)
			return FALSE;

		/* Match at least one group cipher with AP's capability if the
		 * wireless-security setting explicitly lists group ciphers
		 */
		num = nm_setting_wireless_security_get_num_groups (s_wireless_sec);
		for (i = 0, found = FALSE; i < num; i++) {
			cipher = nm_setting_wireless_security_get_group (s_wireless_sec, i);

			if ((found = match_cipher (cipher, "wep40", ap_wpa, ap_rsn, NM_802_11_AP_SEC_GROUP_WEP40)))
				break;
			if ((found = match_cipher (cipher, "wep104", ap_wpa, ap_rsn, NM_802_11_AP_SEC_GROUP_WEP104)))
				break;
			if ((found = match_cipher (cipher, "tkip", ap_wpa, ap_rsn, NM_802_11_AP_SEC_GROUP_TKIP)))
				break;
			if ((found = match_cipher (cipher, "ccmp", ap_wpa, ap_rsn, NM_802_11_AP_SEC_GROUP_CCMP)))
				break;
		}
		if (!found && num)
			return FALSE;

		return TRUE;
	}

	return FALSE;
}

/**
 * nm_setting_wireless_new:
 *
 * Creates a new #NMSettingWireless object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingWireless object
 **/
NMSetting *
nm_setting_wireless_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_WIRELESS, NULL);
}

/**
 * nm_setting_wireless_get_ssid:
 * @setting: the #NMSettingWireless
 *
 * Returns: (transfer none): the #NMSettingWireless:ssid property of the setting
 **/
GBytes *
nm_setting_wireless_get_ssid (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->ssid;
}

/**
 * nm_setting_wireless_get_mode:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:mode property of the setting
 **/
const char *
nm_setting_wireless_get_mode (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->mode;
}

/**
 * nm_setting_wireless_get_band:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:band property of the setting
 **/
const char *
nm_setting_wireless_get_band (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->band;
}

/**
 * nm_setting_wireless_get_channel:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:channel property of the setting
 **/
guint32
nm_setting_wireless_get_channel (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), 0);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->channel;
}

/**
 * nm_setting_wireless_get_bssid:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:bssid property of the setting
 **/
const char *
nm_setting_wireless_get_bssid (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->bssid;
}

/**
 * nm_setting_wireless_get_rate:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:rate property of the setting
 **/
guint32
nm_setting_wireless_get_rate (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), 0);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->rate;
}

/**
 * nm_setting_wireless_get_tx_power:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:tx-power property of the setting
 **/
guint32
nm_setting_wireless_get_tx_power (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), 0);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->tx_power;
}

/**
 * nm_setting_wireless_get_mac_address:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:mac-address property of the setting
 **/
const char *
nm_setting_wireless_get_mac_address (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->device_mac_address;
}

/**
 * nm_setting_wireless_get_cloned_mac_address:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:cloned-mac-address property of the setting
 **/
const char *
nm_setting_wireless_get_cloned_mac_address (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->cloned_mac_address;
}

/**
 * nm_setting_wireless_get_mac_address_blacklist:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:mac-address-blacklist property of the setting
 **/
const char * const *
nm_setting_wireless_get_mac_address_blacklist (NMSettingWireless *setting)
{
	NMSettingWirelessPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);
	return (const char * const *) priv->mac_address_blacklist->data;
}

/**
 * nm_setting_wireless_get_num_mac_blacklist_items:
 * @setting: the #NMSettingWireless
 *
 * Returns: the number of blacklisted MAC addresses
 **/
guint32
nm_setting_wireless_get_num_mac_blacklist_items (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), 0);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->mac_address_blacklist->len;
}

/**
 * nm_setting_wireless_get_mac_blacklist_item:
 * @setting: the #NMSettingWireless
 * @idx: the zero-based index of the MAC address entry
 *
 * Returns: the blacklisted MAC address string (hex-digits-and-colons notation)
 * at index @idx
 **/
const char *
nm_setting_wireless_get_mac_blacklist_item (NMSettingWireless *setting, guint32 idx)
{
	NMSettingWirelessPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);
	g_return_val_if_fail (idx <= priv->mac_address_blacklist->len, NULL);

	return g_array_index (priv->mac_address_blacklist, const char *, idx);
}

/**
 * nm_setting_wireless_add_mac_blacklist_item:
 * @setting: the #NMSettingWireless
 * @mac: the MAC address string (hex-digits-and-colons notation) to blacklist
 *
 * Adds a new MAC address to the #NMSettingWireless:mac-address-blacklist property.
 *
 * Returns: %TRUE if the MAC address was added; %FALSE if the MAC address
 * is invalid or was already present
 **/
gboolean
nm_setting_wireless_add_mac_blacklist_item (NMSettingWireless *setting, const char *mac)
{
	NMSettingWirelessPrivate *priv;
	const char *candidate;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), FALSE);
	g_return_val_if_fail (mac != NULL, FALSE);

	if (!nm_utils_hwaddr_valid (mac, ETH_ALEN))
		return FALSE;

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);
	for (i = 0; i < priv->mac_address_blacklist->len; i++) {
		candidate = g_array_index (priv->mac_address_blacklist, char *, i);
		if (nm_utils_hwaddr_matches (mac, -1, candidate, -1))
			return FALSE;
	}

	mac = nm_utils_hwaddr_canonical (mac, ETH_ALEN);
	g_array_append_val (priv->mac_address_blacklist, mac);
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST);
	return TRUE;
}

/**
 * nm_setting_wireless_remove_mac_blacklist_item:
 * @setting: the #NMSettingWireless
 * @idx: index number of the MAC address
 *
 * Removes the MAC address at index @idx from the blacklist.
 **/
void
nm_setting_wireless_remove_mac_blacklist_item (NMSettingWireless *setting, guint32 idx)
{
	NMSettingWirelessPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_WIRELESS (setting));

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);
	g_return_if_fail (idx < priv->mac_address_blacklist->len);

	g_array_remove_index (priv->mac_address_blacklist, idx);
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST);
}

/**
 * nm_setting_wireless_remove_mac_blacklist_item_by_value:
 * @setting: the #NMSettingWireless
 * @mac: the MAC address string (hex-digits-and-colons notation) to remove from
 * the blacklist
 *
 * Removes the MAC address @mac from the blacklist.
 *
 * Returns: %TRUE if the MAC address was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_wireless_remove_mac_blacklist_item_by_value (NMSettingWireless *setting, const char *mac)
{
	NMSettingWirelessPrivate *priv;
	const char *candidate;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), FALSE);
	g_return_val_if_fail (mac != NULL, FALSE);

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);
	for (i = 0; i < priv->mac_address_blacklist->len; i++) {
		candidate = g_array_index (priv->mac_address_blacklist, char *, i);
		if (!nm_utils_hwaddr_matches (mac, -1, candidate, -1)) {
			g_array_remove_index (priv->mac_address_blacklist, i);
			g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_wireless_clear_mac_blacklist_items:
 * @setting: the #NMSettingWireless
 *
 * Removes all blacklisted MAC addresses.
 **/
void
nm_setting_wireless_clear_mac_blacklist_items (NMSettingWireless *setting)
{
	g_return_if_fail (NM_IS_SETTING_WIRELESS (setting));

	g_array_set_size (NM_SETTING_WIRELESS_GET_PRIVATE (setting)->mac_address_blacklist, 0);
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST);
}

/**
 * nm_setting_wireless_get_mtu:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:mtu property of the setting
 **/
guint32
nm_setting_wireless_get_mtu (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), 0);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->mtu;
}

/**
 * nm_setting_wireless_get_hidden:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:hidden property of the setting
 **/
gboolean
nm_setting_wireless_get_hidden (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), FALSE);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->hidden;
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
nm_setting_wireless_get_powersave (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), 0);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->powersave;
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
nm_setting_wireless_add_seen_bssid (NMSettingWireless *setting,
                                    const char *bssid)
{
	NMSettingWirelessPrivate *priv;
	char *lower_bssid;
	GSList *iter;
	gboolean found = FALSE;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), FALSE);
	g_return_val_if_fail (bssid != NULL, FALSE);

	lower_bssid = g_ascii_strdown (bssid, -1);
	if (!lower_bssid)
		return FALSE;

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);

	for (iter = priv->seen_bssids; iter; iter = iter->next) {
		if (!strcmp ((char *) iter->data, lower_bssid)) {
			found = TRUE;
			break;
		}
	}

	if (!found) {
		priv->seen_bssids = g_slist_prepend (priv->seen_bssids, lower_bssid);
		g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SEEN_BSSIDS);
	} else
		g_free (lower_bssid);

	return !found;
}

/**
 * nm_setting_wireless_get_num_seen_bssids:
 * @setting: the #NMSettingWireless
 *
 * Returns: the number of BSSIDs in the previously seen BSSID list
 **/
guint32
nm_setting_wireless_get_num_seen_bssids (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), 0);

	return g_slist_length (NM_SETTING_WIRELESS_GET_PRIVATE (setting)->seen_bssids);
}

/**
 * nm_setting_wireless_get_seen_bssid:
 * @setting: the #NMSettingWireless
 * @i: index of a BSSID in the previously seen BSSID list
 *
 * Returns: the BSSID at index @i
 **/
const char *
nm_setting_wireless_get_seen_bssid (NMSettingWireless *setting,
                                    guint32 i)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	return (const char *) g_slist_nth_data (NM_SETTING_WIRELESS_GET_PRIVATE (setting)->seen_bssids, i);
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);
	const char *valid_modes[] = { NM_SETTING_WIRELESS_MODE_INFRA, NM_SETTING_WIRELESS_MODE_ADHOC, NM_SETTING_WIRELESS_MODE_AP, NULL };
	const char *valid_bands[] = { "a", "bg", NULL };
	GSList *iter;
	int i;
	gsize length;

	if (!priv->ssid) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_SSID);
		return FALSE;
	}

	length = g_bytes_get_size (priv->ssid);
	if (length == 0 || length > 32) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("SSID length is out of range <1-32> bytes"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_SSID);
		return FALSE;
	}

	if (priv->mode && !_nm_utils_string_in_list (priv->mode, valid_modes)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid Wi-Fi mode"),
		             priv->mode);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_MODE);
		return FALSE;
	}

	if (priv->band && !_nm_utils_string_in_list (priv->band, valid_bands)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid band"),
		             priv->band);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_BAND);
		return FALSE;
	}

	if (priv->channel && !priv->band) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_MISSING_PROPERTY,
		             _("'%s' requires setting '%s' property"),
		             NM_SETTING_WIRELESS_CHANNEL, NM_SETTING_WIRELESS_BAND);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_BAND);
		return FALSE;
	}

	if (priv->channel) {
		if (!nm_utils_wifi_is_channel_valid (priv->channel, priv->band)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%d' is not a valid channel"),
			             priv->channel);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_CHANNEL);
			return FALSE;
		}
	}

	if (priv->bssid && !nm_utils_hwaddr_valid (priv->bssid, ETH_ALEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_BSSID);
		return FALSE;
	}

	if (priv->device_mac_address && !nm_utils_hwaddr_valid (priv->device_mac_address, ETH_ALEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_MAC_ADDRESS);
		return FALSE;
	}

	if (priv->cloned_mac_address && !nm_utils_hwaddr_valid (priv->cloned_mac_address, ETH_ALEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS);
		return FALSE;
	}

	for (i = 0; i < priv->mac_address_blacklist->len; i++) {
		const char *mac = g_array_index (priv->mac_address_blacklist, const char *, i);

		if (!nm_utils_hwaddr_valid (mac, ETH_ALEN)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' is not a valid MAC address"),
			             mac);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST);
			return FALSE;
		}
	}

	for (iter = priv->seen_bssids; iter; iter = iter->next) {
		if (!nm_utils_hwaddr_valid (iter->data, ETH_ALEN)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' is not a valid MAC address"),
			             (const char *) iter->data);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_SEEN_BSSIDS);
			return FALSE;
		}
	}

	return TRUE;
}

static GVariant *
nm_setting_wireless_get_security (NMSetting    *setting,
                                  NMConnection *connection,
                                  const char   *property_name)
{
	if (nm_connection_get_setting_wireless_security (connection))
		return g_variant_new_string (NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
	else
		return NULL;
}

static void
clear_blacklist_item (char **item_p)
{
	g_free (*item_p);
}

static void
nm_setting_wireless_init (NMSettingWireless *setting)
{
	NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);

	/* We use GArray rather than GPtrArray so it will automatically be NULL-terminated */
	priv->mac_address_blacklist = g_array_new (TRUE, FALSE, sizeof (char *));
	g_array_set_clear_func (priv->mac_address_blacklist, (GDestroyNotify) clear_blacklist_item);
}

static void
finalize (GObject *object)
{
	NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE (object);

	g_free (priv->mode);
	g_free (priv->band);

	if (priv->ssid)
		g_bytes_unref (priv->ssid);
	g_free (priv->bssid);
	g_free (priv->device_mac_address);
	g_free (priv->cloned_mac_address);
	g_array_unref (priv->mac_address_blacklist);
	g_slist_free_full (priv->seen_bssids, g_free);

	G_OBJECT_CLASS (nm_setting_wireless_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE (object);
	const char * const *blacklist;
	const char *mac;
	int i;

	switch (prop_id) {
	case PROP_SSID:
		if (priv->ssid)
			g_bytes_unref (priv->ssid);
		priv->ssid = g_value_dup_boxed (value);
		break;
	case PROP_MODE:
		g_free (priv->mode);
		priv->mode = g_value_dup_string (value);
		break;
	case PROP_BAND:
		g_free (priv->band);
		priv->band = g_value_dup_string (value);
		break;
	case PROP_CHANNEL:
		priv->channel = g_value_get_uint (value);
		break;
	case PROP_BSSID:
		g_free (priv->bssid);
		priv->bssid = g_value_dup_string (value);
		break;
	case PROP_RATE:
		priv->rate = g_value_get_uint (value);
		break;
	case PROP_TX_POWER:
		priv->tx_power = g_value_get_uint (value);
		break;
	case PROP_MAC_ADDRESS:
		g_free (priv->device_mac_address);
		priv->device_mac_address = _nm_utils_hwaddr_canonical_or_invalid (g_value_get_string (value),
		                                                                  ETH_ALEN);
		break;
	case PROP_CLONED_MAC_ADDRESS:
		g_free (priv->cloned_mac_address);
		priv->cloned_mac_address = _nm_utils_hwaddr_canonical_or_invalid (g_value_get_string (value),
		                                                                  ETH_ALEN);
		break;
	case PROP_MAC_ADDRESS_BLACKLIST:
		blacklist = g_value_get_boxed (value);
		g_array_set_size (priv->mac_address_blacklist, 0);
		if (blacklist && *blacklist) {
			for (i = 0; blacklist[i]; i++) {
				mac = _nm_utils_hwaddr_canonical_or_invalid (blacklist[i], ETH_ALEN);
				g_array_append_val (priv->mac_address_blacklist, mac);
			}
		}
		break;
	case PROP_MTU:
		priv->mtu = g_value_get_uint (value);
		break;
	case PROP_SEEN_BSSIDS:
		g_slist_free_full (priv->seen_bssids, g_free);
		priv->seen_bssids = _nm_utils_strv_to_slist (g_value_get_boxed (value), TRUE);
		break;
	case PROP_HIDDEN:
		priv->hidden = g_value_get_boolean (value);
		break;
	case PROP_POWERSAVE:
		priv->powersave = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingWireless *setting = NM_SETTING_WIRELESS (object);
	NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SSID:
		g_value_set_boxed (value, nm_setting_wireless_get_ssid (setting));
		break;
	case PROP_MODE:
		g_value_set_string (value, nm_setting_wireless_get_mode (setting));
		break;
	case PROP_BAND:
		g_value_set_string (value, nm_setting_wireless_get_band (setting));
		break;
	case PROP_CHANNEL:
		g_value_set_uint (value, nm_setting_wireless_get_channel (setting));
		break;
	case PROP_BSSID:
		g_value_set_string (value, nm_setting_wireless_get_bssid (setting));
		break;
	case PROP_RATE:
		g_value_set_uint (value, nm_setting_wireless_get_rate (setting));
		break;
	case PROP_TX_POWER:
		g_value_set_uint (value, nm_setting_wireless_get_tx_power (setting));
		break;
	case PROP_MAC_ADDRESS:
		g_value_set_string (value, nm_setting_wireless_get_mac_address (setting));
		break;
	case PROP_CLONED_MAC_ADDRESS:
		g_value_set_string (value, nm_setting_wireless_get_cloned_mac_address (setting));
		break;
	case PROP_MAC_ADDRESS_BLACKLIST:
		g_value_set_boxed (value, (char **) priv->mac_address_blacklist->data);
		break;
	case PROP_MTU:
		g_value_set_uint (value, nm_setting_wireless_get_mtu (setting));
		break;
	case PROP_SEEN_BSSIDS:
		g_value_take_boxed (value, _nm_utils_slist_to_strv (priv->seen_bssids, TRUE));
		break;
	case PROP_HIDDEN:
		g_value_set_boolean (value, nm_setting_wireless_get_hidden (setting));
		break;
	case PROP_POWERSAVE:
		g_value_set_uint (value, nm_setting_wireless_get_powersave (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_wireless_class_init (NMSettingWirelessClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingWirelessPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
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
	 * ---ifcfg-rh---
	 * property: ssid
	 * variable: ESSID
	 * description: SSID of Wi-Fi network.
	 * example: ESSID="Quick Net"
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_SSID,
		 g_param_spec_boxed (NM_SETTING_WIRELESS_SSID, "", "",
		                     G_TYPE_BYTES,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWireless:mode:
	 *
	 * Wi-Fi network mode; one of "infrastructure", "adhoc" or "ap".  If blank,
	 * infrastructure is assumed.
	 **/
	/* ---ifcfg-rh---
	 * property: mode
	 * variable: MODE
	 * values: Ad-Hoc, Managed (Auto)  [case insensitive]
	 * description: Wi-Fi network mode.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_string (NM_SETTING_WIRELESS_MODE, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWireless:band:
	 *
	 * 802.11 frequency band of the network.  One of "a" for 5GHz 802.11a or
	 * "bg" for 2.4GHz 802.11.  This will lock associations to the Wi-Fi network
	 * to the specific band, i.e. if "a" is specified, the device will not
	 * associate with the same network in the 2.4GHz band even if the network's
	 * settings are compatible.  This setting depends on specific driver
	 * capability and may not work with all drivers.
	 **/
	/* ---ifcfg-rh---
	 * property: band
	 * variable: BAND(+)
	 * values: a, bg
	 * description: BAND alone is honored, but CHANNEL overrides BAND since it
	 *   implies a band.
	 * example: BAND=bg
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_BAND,
		 g_param_spec_string (NM_SETTING_WIRELESS_BAND, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

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
	 *   Channels greater than 14 mean "a" band, otherwise the
	 *   band is "bg".
	 * example: CHANNEL=6
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_CHANNEL,
		 g_param_spec_uint (NM_SETTING_WIRELESS_CHANNEL, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWireless:bssid:
	 *
	 * If specified, directs the device to only associate with the given access
	 * point.  This capability is highly driver dependent and not supported by
	 * all devices.  Note: this property does not control the BSSID used when
	 * creating an Ad-Hoc network and is unlikely to in the future.
	 **/
	/* ---ifcfg-rh---
	 * property: bssid
	 * variable: BSSID(+)
	 * description: Restricts association only to a single AP.
	 * example: BSSID=00:1E:BD:64:83:21
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_BSSID,
		 g_param_spec_string (NM_SETTING_WIRELESS_BSSID, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_WIRELESS_BSSID,
	                                      G_VARIANT_TYPE_BYTESTRING,
	                                      _nm_utils_hwaddr_to_dbus,
	                                      _nm_utils_hwaddr_from_dbus);

	/**
	 * NMSettingWireless:rate:
	 *
	 * If non-zero, directs the device to only use the specified bitrate for
	 * communication with the access point.  Units are in Kb/s, ie 5500 = 5.5
	 * Mbit/s.  This property is highly driver dependent and not all devices
	 * support setting a static bitrate.
	 **/
	/* ---ifcfg-rh---
	 * property: rate
	 * variable: (none)
	 * description: This property is not handled by ifcfg-rh plugin.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_RATE,
		 g_param_spec_uint (NM_SETTING_WIRELESS_RATE, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_FUZZY_IGNORE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWireless:tx-power:
	 *
	 * If non-zero, directs the device to use the specified transmit power.
	 * Units are dBm.  This property is highly driver dependent and not all
	 * devices support setting a static transmit power.
	 **/
	/* ---ifcfg-rh---
	 * property: tx-power
	 * variable: (none)
	 * description: This property is not handled by ifcfg-rh plugin.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_TX_POWER,
		 g_param_spec_uint (NM_SETTING_WIRELESS_TX_POWER, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_FUZZY_IGNORE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWireless:mac-address:
	 *
	 * If specified, this connection will only apply to the Wi-Fi device whose
	 * permanent MAC address matches. This property does not change the MAC
	 * address of the device (i.e. MAC spoofing).
	 **/
	/* ---keyfile---
	 * property: mac-address
	 * format: ususal hex-digits-and-colons notation
	 * description: MAC address in traditional hex-digits-and-colons notation
	 *   (e.g. 00:22:68:12:79:A2), or semicolon separated list of 6 bytes (obsolete)
	 *   (e.g. 0;34;104;18;121;162).
	 * ---end---
	 * ---ifcfg-rh---
	 * property: mac-address
	 * variable: HWADDR
	 * description: Hardware address of the device in traditional hex-digits-and-colons
	 *    notation (e.g. 00:22:68:14:5A:05).
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS,
		 g_param_spec_string (NM_SETTING_WIRELESS_MAC_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_WIRELESS_MAC_ADDRESS,
	                                      G_VARIANT_TYPE_BYTESTRING,
	                                      _nm_utils_hwaddr_to_dbus,
	                                      _nm_utils_hwaddr_from_dbus);

	/**
	 * NMSettingWireless:cloned-mac-address:
	 *
	 * If specified, request that the Wi-Fi device use this MAC address instead
	 * of its permanent MAC address.  This is known as MAC cloning or spoofing.
	 **/
	/* ---keyfile---
	 * property: cloned-mac-address
	 * format: ususal hex-digits-and-colons notation
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
	 */
	g_object_class_install_property
		(object_class, PROP_CLONED_MAC_ADDRESS,
		 g_param_spec_string (NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS,
	                                      G_VARIANT_TYPE_BYTESTRING,
	                                      _nm_utils_hwaddr_to_dbus,
	                                      _nm_utils_hwaddr_from_dbus);

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
	 * ---ifcfg-rh---
	 * property: mac-address-blacklist
	 * variable: HWADDR_BLACKLIST(+)
	 * description: It denies usage of the connection for any device whose address
	 *   is listed.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS_BLACKLIST,
		 g_param_spec_boxed (NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_FUZZY_IGNORE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWireless:seen-bssids:
	 *
	 * A list of BSSIDs (each BSSID formatted as a MAC address like
	 * "00:11:22:33:44:55") that have been detected as part of the Wi-Fi
	 * network.  NetworkManager internally tracks previously seen BSSIDs. The
	 * property is only meant for reading and reflects the BSSID list of
	 * NetworkManager. The changes you make to this property will not be
	 * preserved.
	 **/
	/* ---ifcfg-rh---
	 * property: seen-bssids
	 * variable: (none)
	 * description: This property is not handled by ifcfg-rh plugin.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_SEEN_BSSIDS,
		 g_param_spec_boxed (NM_SETTING_WIRELESS_SEEN_BSSIDS, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_FUZZY_IGNORE |
		                     G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_SETTING_WIRELESS_MTU, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_FUZZY_IGNORE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWireless:hidden:
	 *
	 * If %TRUE, indicates this network is a non-broadcasting network that hides
	 * its SSID.  In this case various workarounds may take place, such as
	 * probe-scanning the SSID for more reliable network discovery.  However,
	 * these workarounds expose inherent insecurities with hidden SSID networks,
	 * and thus hidden SSID networks should be used with caution.
	 **/
	/* ---ifcfg-rh---
	 * property: hidden
	 * variable: SSID_HIDDEN(+)
	 * description: Whether the network hides the SSID.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_HIDDEN,
		 g_param_spec_boolean (NM_SETTING_WIRELESS_HIDDEN, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWireless:powersave:
	 *
	 * If set to %FALSE, Wi-Fi power saving behavior is disabled.  If set to
	 * %TRUE, Wi-Fi power saving behavior is enabled.  All other values are
	 * reserved.  Note that even though only boolean values are allowed, the
	 * property type is an unsigned integer to allow for future expansion.
	 *
	 * Since: 1.2
	 **/
	/* ---ifcfg-rh---
	 * property: powersave
	 * variable: POWERSAVE(+)
	 * default: no
	 * description: Enables or disables Wi-Fi power saving.
	 * example: POWERSAVE=yes
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_POWERSAVE,
		 g_param_spec_uint (NM_SETTING_WIRELESS_POWERSAVE, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));

	/* Compatibility for deprecated property */
	/* ---ifcfg-rh---
	 * property: security
	 * variable: (none)
	 * description: This property is deprecated and not handled by ifcfg-rh-plugin.
	 * ---end---
	 * ---dbus---
	 * property: security
	 * description: This property is deprecated, but can be set to the value
	 *   '802-11-wireless-security' when a wireless security setting is also
	 *   present in the connection dictionary, for compatibility with very old
	 *   NetworkManager daemons.
	 * ---end---
	 */
	_nm_setting_class_add_dbus_only_property (parent_class, "security",
	                                          G_VARIANT_TYPE_STRING,
	                                          nm_setting_wireless_get_security, NULL);
}
