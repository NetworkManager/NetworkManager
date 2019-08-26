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

#include "nm-default.h"

#include "nm-setting-wireless.h"

#include <net/ethernet.h>

#include "nm-utils.h"
#include "nm-libnm-core-intern/nm-common-macros.h"
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

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingWireless,
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
	PROP_MTU,
	PROP_SEEN_BSSIDS,
	PROP_HIDDEN,
	PROP_POWERSAVE,
	PROP_MAC_ADDRESS_RANDOMIZATION,
	PROP_WAKE_ON_WLAN,
);

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
	char *generate_mac_address_mask;
	GArray *mac_address_blacklist;
	GPtrArray *seen_bssids;
	guint32 mtu;
	gboolean hidden;
	guint32 powersave;
	NMSettingMacRandomization mac_address_randomization;
	guint32 wowl;
} NMSettingWirelessPrivate;

G_DEFINE_TYPE (NMSettingWireless, nm_setting_wireless, NM_TYPE_SETTING)

#define NM_SETTING_WIRELESS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_WIRELESS, NMSettingWirelessPrivate))

/*****************************************************************************/

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
 * nm_setting_wireless_get_generate_mac_address_mask:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:generate-mac-address-mask property of the setting
 *
 * Since: 1.4
 **/
const char *
nm_setting_wireless_get_generate_mac_address_mask (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->generate_mac_address_mask;
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
	_notify (setting, PROP_MAC_ADDRESS_BLACKLIST);
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
	_notify (setting, PROP_MAC_ADDRESS_BLACKLIST);
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
			_notify (setting, PROP_MAC_ADDRESS_BLACKLIST);
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
	_notify (setting, PROP_MAC_ADDRESS_BLACKLIST);
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
 * nm_setting_wireless_get_mac_address_randomization:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:mac-address-randomization property of the
 * setting
 *
 * Since: 1.2
 **/
NMSettingMacRandomization
nm_setting_wireless_get_mac_address_randomization (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), 0);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->mac_address_randomization;
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
	gs_free char *lower_bssid = NULL;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), FALSE);
	g_return_val_if_fail (bssid != NULL, FALSE);

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);

	lower_bssid = g_ascii_strdown (bssid, -1);

	if (!priv->seen_bssids) {
		priv->seen_bssids = g_ptr_array_new_with_free_func (g_free);
	} else {
		if (nm_utils_strv_find_first ((char **) priv->seen_bssids->pdata,
		                              priv->seen_bssids->len,
		                              lower_bssid) >= 0)
			return FALSE;
	}

	g_ptr_array_add (priv->seen_bssids, g_steal_pointer (&lower_bssid));
	_notify (setting, PROP_SEEN_BSSIDS);
	return TRUE;
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
	NMSettingWirelessPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), 0);

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);

	return   priv->seen_bssids
	       ? priv->seen_bssids->len
	       : 0u;
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
	NMSettingWirelessPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), 0);

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);

	if (   !priv->seen_bssids
	    || i >= priv->seen_bssids->len)
		return NULL;

	return priv->seen_bssids->pdata[i];
}

static GVariant *
_to_dbus_fcn_seen_bssids (const NMSettInfoSetting *sett_info,
                          guint property_idx,
                          NMConnection *connection,
                          NMSetting *setting,
                          NMConnectionSerializationFlags flags,
                          const NMConnectionSerializationOptions *options)
{
	NMSettingWirelessPrivate *priv;

	if (   options
	    && options->seen_bssids) {
		return   options->seen_bssids[0]
		       ? g_variant_new_strv (options->seen_bssids, -1)
		       : NULL;
	}

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);

	if (   !priv->seen_bssids
	    || priv->seen_bssids->len == 0)
		return NULL;

	return g_variant_new_strv ((const char *const*) priv->seen_bssids->pdata, priv->seen_bssids->len);
}

/*****************************************************************************/

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);
	const char *valid_modes[] = {
		NM_SETTING_WIRELESS_MODE_INFRA,
		NM_SETTING_WIRELESS_MODE_ADHOC,
		NM_SETTING_WIRELESS_MODE_AP,
		NM_SETTING_WIRELESS_MODE_MESH,
		NULL
	};
	const char *valid_bands[] = { "a", "bg", NULL };
	guint i;
	gsize length;
	GError *local = NULL;

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

	if (priv->mode && !g_strv_contains (valid_modes, priv->mode)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid Wi-Fi mode"),
		             priv->mode);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_MODE);
		return FALSE;
	}

	if (priv->band && !g_strv_contains (valid_bands, priv->band)) {
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

	if ((g_strcmp0 (priv->mode, NM_SETTING_WIRELESS_MODE_MESH) == 0) && !(priv->channel && priv->band)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_MISSING_PROPERTY,
		             _("'%s' requires '%s' and '%s' property"),
		             priv->mode, NM_SETTING_WIRELESS_BAND, NM_SETTING_WIRELESS_CHANNEL);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_MODE);
		return FALSE;
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

	if (   priv->cloned_mac_address
	    && !NM_CLONED_MAC_IS_SPECIAL (priv->cloned_mac_address)
	    && !nm_utils_hwaddr_valid (priv->cloned_mac_address, ETH_ALEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS);
		return FALSE;
	}

	/* generate-mac-address-mask only makes sense with cloned-mac-address "random" or
	 * "stable". Still, let's not be so strict about that and accept the value
	 * even if it is unused. */
	if (!_nm_utils_generate_mac_address_mask_parse (priv->generate_mac_address_mask,
	                                                NULL, NULL, NULL, &local)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     local->message);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_GENERATE_MAC_ADDRESS_MASK);
		g_error_free (local);
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

	if (priv->seen_bssids) {
		for (i = 0; i < priv->seen_bssids->len; i++) {
			const char *b;

			b = priv->seen_bssids->pdata[i];
			if (!nm_utils_hwaddr_valid (b, ETH_ALEN)) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("'%s' is not a valid MAC address"),
				             b);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_SEEN_BSSIDS);
				return FALSE;
			}
		}
	}

	if (!NM_IN_SET (priv->mac_address_randomization,
	                NM_SETTING_MAC_RANDOMIZATION_DEFAULT,
	                NM_SETTING_MAC_RANDOMIZATION_NEVER,
	                NM_SETTING_MAC_RANDOMIZATION_ALWAYS)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("invalid value"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION);
		return FALSE;
	}

	if (NM_FLAGS_ANY (priv->wowl, NM_SETTING_WIRELESS_WAKE_ON_WLAN_EXCLUSIVE_FLAGS)) {
		if (!nm_utils_is_power_of_two (priv->wowl)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("Wake-on-WLAN mode 'default' and 'ignore' are exclusive flags"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME,
			                NM_SETTING_WIRELESS_WAKE_ON_WLAN);
			return FALSE;
		}
	} else if (NM_FLAGS_ANY (priv->wowl, ~NM_SETTING_WIRELESS_WAKE_ON_WLAN_ALL)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("Wake-on-WLAN trying to set unknown flag"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME,
		                NM_SETTING_WIRELESS_WAKE_ON_WLAN);
		return FALSE;
	}

	/* from here on, check for NM_SETTING_VERIFY_NORMALIZABLE conditions. */

	if (priv->cloned_mac_address) {
		if (   priv->mac_address_randomization == NM_SETTING_MAC_RANDOMIZATION_ALWAYS
		    && nm_streq (priv->cloned_mac_address, "random"))
			goto mac_addr_rand_ok;
		if (   priv->mac_address_randomization == NM_SETTING_MAC_RANDOMIZATION_NEVER
		    && nm_streq (priv->cloned_mac_address, "permanent"))
			goto mac_addr_rand_ok;
		if (priv->mac_address_randomization == NM_SETTING_MAC_RANDOMIZATION_DEFAULT)
			goto mac_addr_rand_ok;
	} else if (priv->mac_address_randomization == NM_SETTING_MAC_RANDOMIZATION_DEFAULT)
		goto mac_addr_rand_ok;
	g_set_error (error,
	             NM_CONNECTION_ERROR,
	             NM_CONNECTION_ERROR_INVALID_PROPERTY,
	             _("conflicting value of mac-address-randomization and cloned-mac-address"));
	g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS);
	return NM_SETTING_VERIFY_NORMALIZABLE;
mac_addr_rand_ok:

	return TRUE;
}

static NMTernary
compare_property (const NMSettInfoSetting *sett_info,
                  guint property_idx,
                  NMConnection *con_a,
                  NMSetting *set_a,
                  NMConnection *con_b,
                  NMSetting *set_b,
                  NMSettingCompareFlags flags)
{
	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS)) {
		return    !set_b
		       || nm_streq0 (NM_SETTING_WIRELESS_GET_PRIVATE (set_a)->cloned_mac_address,
		                     NM_SETTING_WIRELESS_GET_PRIVATE (set_b)->cloned_mac_address);
	}

	return NM_SETTING_CLASS (nm_setting_wireless_parent_class)->compare_property (sett_info,
	                                                                              property_idx,
	                                                                              con_a,
	                                                                              set_a,
	                                                                              con_b,
	                                                                              set_b,
	                                                                              flags);
}

/*****************************************************************************/

static GVariant *
nm_setting_wireless_get_security (const NMSettInfoSetting *sett_info,
                                  guint property_idx,
                                  NMConnection *connection,
                                  NMSetting *setting,
                                  NMConnectionSerializationFlags flags,
                                  const NMConnectionSerializationOptions *options)
{
	if (flags & NM_CONNECTION_SERIALIZE_ONLY_SECRETS)
		return NULL;

	if (!connection)
		return NULL;

	if (!nm_connection_get_setting_wireless_security (connection))
		return NULL;

	return g_variant_new_string (NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
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
nm_setting_wireless_get_wake_on_wlan (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NM_SETTING_WIRELESS_WAKE_ON_WLAN_NONE);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->wowl;
}

static void
clear_blacklist_item (char **item_p)
{
	g_free (*item_p);
}

/*****************************************************************************/

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
	case PROP_GENERATE_MAC_ADDRESS_MASK:
		g_value_set_string (value, nm_setting_wireless_get_generate_mac_address_mask (setting));
		break;
	case PROP_MAC_ADDRESS_BLACKLIST:
		g_value_set_boxed (value, (char **) priv->mac_address_blacklist->data);
		break;
	case PROP_MTU:
		g_value_set_uint (value, nm_setting_wireless_get_mtu (setting));
		break;
	case PROP_SEEN_BSSIDS:
		g_value_take_boxed (value,
		                      priv->seen_bssids
		                    ? nm_utils_strv_dup (priv->seen_bssids->pdata,
		                                         priv->seen_bssids->len)
		                    : NULL);
		break;
	case PROP_HIDDEN:
		g_value_set_boolean (value, nm_setting_wireless_get_hidden (setting));
		break;
	case PROP_POWERSAVE:
		g_value_set_uint (value, nm_setting_wireless_get_powersave (setting));
		break;
	case PROP_MAC_ADDRESS_RANDOMIZATION:
		g_value_set_uint (value, nm_setting_wireless_get_mac_address_randomization (setting));
		break;
	case PROP_WAKE_ON_WLAN:
		g_value_set_uint (value, nm_setting_wireless_get_wake_on_wlan (setting));
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
	NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE (object);
	const char * const *blacklist;
	const char *mac;
	gboolean bool_val;

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
		bool_val = !!priv->cloned_mac_address;
		g_free (priv->cloned_mac_address);
		priv->cloned_mac_address = _nm_utils_hwaddr_canonical_or_invalid (g_value_get_string (value),
		                                                                  ETH_ALEN);
		if (bool_val && !priv->cloned_mac_address) {
			/* cloned-mac-address was set before but was now explicitly cleared.
			 * In this case, we also clear mac-address-randomization flag */
			if (priv->mac_address_randomization != NM_SETTING_MAC_RANDOMIZATION_DEFAULT) {
				priv->mac_address_randomization = NM_SETTING_MAC_RANDOMIZATION_DEFAULT;
				_notify (NM_SETTING_WIRELESS (object), PROP_MAC_ADDRESS_RANDOMIZATION);
			}
		}
		break;
	case PROP_GENERATE_MAC_ADDRESS_MASK:
		g_free (priv->generate_mac_address_mask);
		priv->generate_mac_address_mask = g_value_dup_string (value);
		break;
	case PROP_MAC_ADDRESS_BLACKLIST:
		blacklist = g_value_get_boxed (value);
		g_array_set_size (priv->mac_address_blacklist, 0);
		if (blacklist && blacklist[0]) {
			gsize i;

			for (i = 0; blacklist[i]; i++) {
				mac = _nm_utils_hwaddr_canonical_or_invalid (blacklist[i], ETH_ALEN);
				g_array_append_val (priv->mac_address_blacklist, mac);
			}
		}
		break;
	case PROP_MTU:
		priv->mtu = g_value_get_uint (value);
		break;
	case PROP_SEEN_BSSIDS: {
		gs_unref_ptrarray GPtrArray *arr_old = NULL;
		const char *const*strv;

		arr_old = g_steal_pointer (&priv->seen_bssids);

		strv = g_value_get_boxed (value);
		if (strv && strv[0]) {
			gsize i, l;

			l = NM_PTRARRAY_LEN (strv);
			priv->seen_bssids = g_ptr_array_new_full (l, g_free);
			for (i = 0; i < l; i++)
				g_ptr_array_add (priv->seen_bssids, g_strdup (strv[i]));
		}
		break;
	}
	case PROP_HIDDEN:
		priv->hidden = g_value_get_boolean (value);
		break;
	case PROP_POWERSAVE:
		priv->powersave = g_value_get_uint (value);
		break;
	case PROP_MAC_ADDRESS_RANDOMIZATION:
		priv->mac_address_randomization = g_value_get_uint (value);
		break;
	case PROP_WAKE_ON_WLAN:
		priv->wowl = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_wireless_init (NMSettingWireless *setting)
{
	NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);

	/* We use GArray rather than GPtrArray so it will automatically be NULL-terminated */
	priv->mac_address_blacklist = g_array_new (TRUE, FALSE, sizeof (char *));
	g_array_set_clear_func (priv->mac_address_blacklist, (GDestroyNotify) clear_blacklist_item);
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
	g_free (priv->generate_mac_address_mask);
	g_array_unref (priv->mac_address_blacklist);
	nm_clear_pointer (&priv->seen_bssids, g_ptr_array_unref);

	G_OBJECT_CLASS (nm_setting_wireless_parent_class)->finalize (object);
}

static void
nm_setting_wireless_class_init (NMSettingWirelessClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	g_type_class_add_private (klass, sizeof (NMSettingWirelessPrivate));

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	setting_class->verify           = verify;
	setting_class->compare_property = compare_property;

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
	obj_properties[PROP_SSID] =
	    g_param_spec_boxed (NM_SETTING_WIRELESS_SSID, "", "",
	                        G_TYPE_BYTES,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_MODE] =
	    g_param_spec_string (NM_SETTING_WIRELESS_MODE, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_BAND] =
	    g_param_spec_string (NM_SETTING_WIRELESS_BAND, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_CHANNEL] =
	    g_param_spec_uint (NM_SETTING_WIRELESS_CHANNEL, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_BSSID] =
	    g_param_spec_string (NM_SETTING_WIRELESS_BSSID, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	_properties_override_add_transform (properties_override,
	                                    obj_properties[PROP_BSSID],
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
	obj_properties[PROP_RATE] =
	    g_param_spec_uint (NM_SETTING_WIRELESS_RATE, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_TX_POWER] =
	    g_param_spec_uint (NM_SETTING_WIRELESS_TX_POWER, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_MAC_ADDRESS] =
	    g_param_spec_string (NM_SETTING_WIRELESS_MAC_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	_properties_override_add_transform (properties_override,
	                                    obj_properties[PROP_MAC_ADDRESS],
	                                    G_VARIANT_TYPE_BYTESTRING,
	                                    _nm_utils_hwaddr_to_dbus,
	                                    _nm_utils_hwaddr_from_dbus);

	/**
	 * NMSettingWireless:cloned-mac-address:
	 *
	 * If specified, request that the device use this MAC address instead.
	 * This is known as MAC cloning or spoofing.
	 *
	 * Beside explicitly specifying a MAC address, the special values "preserve", "permanent",
	 * "random" and "stable" are supported.
	 * "preserve" means not to touch the MAC address on activation.
	 * "permanent" means to use the permanent hardware address of the device.
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
	obj_properties[PROP_CLONED_MAC_ADDRESS] =
	    g_param_spec_string (NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	_properties_override_add_override (properties_override,
	                                   obj_properties[PROP_CLONED_MAC_ADDRESS],
	                                   G_VARIANT_TYPE_BYTESTRING,
	                                   _nm_utils_hwaddr_cloned_get,
	                                   _nm_utils_hwaddr_cloned_set,
	                                   _nm_utils_hwaddr_cloned_not_set);

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
	_properties_override_add_dbus_only (properties_override,
	                                    "assigned-mac-address",
	                                    G_VARIANT_TYPE_STRING,
	                                    _nm_utils_hwaddr_cloned_data_synth,
	                                    _nm_utils_hwaddr_cloned_data_set);

	/**
	 * NMSettingWireless:generate-mac-address-mask:
	 *
	 * With #NMSettingWireless:cloned-mac-address setting "random" or "stable",
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
	obj_properties[PROP_GENERATE_MAC_ADDRESS_MASK] =
	     g_param_spec_string (NM_SETTING_WIRELESS_GENERATE_MAC_ADDRESS_MASK, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          NM_SETTING_PARAM_FUZZY_IGNORE |
	                          G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_MAC_ADDRESS_BLACKLIST] =
	    g_param_spec_boxed (NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_FUZZY_IGNORE |
	                        G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_SEEN_BSSIDS] =
	    g_param_spec_boxed (NM_SETTING_WIRELESS_SEEN_BSSIDS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_FUZZY_IGNORE |
	                        G_PARAM_STATIC_STRINGS);

	_properties_override_add_override (properties_override,
	                                   obj_properties[PROP_SEEN_BSSIDS],
	                                   G_VARIANT_TYPE_STRING_ARRAY,
	                                   _to_dbus_fcn_seen_bssids,
	                                   NULL,
	                                   NULL);

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
	obj_properties[PROP_MTU] =
	    g_param_spec_uint (NM_SETTING_WIRELESS_MTU, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_HIDDEN] =
	    g_param_spec_boolean (NM_SETTING_WIRELESS_HIDDEN, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_POWERSAVE] =
	    g_param_spec_uint (NM_SETTING_WIRELESS_POWERSAVE, "", "",
	                       0, G_MAXUINT32, NM_SETTING_WIRELESS_POWERSAVE_DEFAULT,
	                       G_PARAM_READWRITE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWireless:mac-address-randomization:
	 *
	 * One of %NM_SETTING_MAC_RANDOMIZATION_DEFAULT (never randomize unless
	 * the user has set a global default to randomize and the supplicant
	 * supports randomization),  %NM_SETTING_MAC_RANDOMIZATION_NEVER (never
	 * randomize the MAC address), or %NM_SETTING_MAC_RANDOMIZATION_ALWAYS
	 * (always randomize the MAC address). This property is deprecated for
	 * 'cloned-mac-address'.
	 *
	 * Since: 1.2
	 * Deprecated: 1.4: Deprecated by NMSettingWireless:cloned-mac-address property
	 **/
	/* ---ifcfg-rh---
	 * property: mac-address-randomization
	 * variable: MAC_ADDRESS_RANDOMIZATION(+)
	 * values: default, never, always
	 * description: Enables or disables Wi-Fi MAC address randomization.
	 * example: MAC_ADDRESS_RANDOMIZATION=always
	 * ---end---
	 */
	obj_properties[PROP_MAC_ADDRESS_RANDOMIZATION] =
	    g_param_spec_uint (NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION, "", "",
	                       0, G_MAXUINT32, NM_SETTING_MAC_RANDOMIZATION_DEFAULT,
	                       G_PARAM_READWRITE |
	                       G_PARAM_STATIC_STRINGS);

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
	_properties_override_add_dbus_only (properties_override,
	                                    "security",
	                                    G_VARIANT_TYPE_STRING,
	                                    nm_setting_wireless_get_security,
	                                    NULL);

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
	obj_properties[PROP_WAKE_ON_WLAN] =
	    g_param_spec_uint (NM_SETTING_WIRELESS_WAKE_ON_WLAN, "", "",
	                       0, G_MAXUINT32, NM_SETTING_WIRELESS_WAKE_ON_WLAN_DEFAULT,
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_READWRITE |
	                       G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_WIRELESS,
	                               NULL, properties_override);
}
