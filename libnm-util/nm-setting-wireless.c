/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
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
 * (C) Copyright 2007 - 2014 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <dbus/dbus-glib.h>
#include <glib/gi18n.h>

#include "NetworkManager.h"
#include "nm-setting-wireless.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-wireless
 * @short_description: Describes connection properties for 802.11 Wi-Fi networks
 * @include: nm-setting-wireless.h
 *
 * The #NMSettingWireless object is a #NMSetting subclass that describes properties
 * necessary for connection to 802.11 Wi-Fi networks.
 **/

/**
 * nm_setting_wireless_error_quark:
 *
 * Registers an error quark for #NMSettingWireless if necessary.
 *
 * Returns: the error quark used for #NMSettingWireless errors.
 **/
GQuark
nm_setting_wireless_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-wireless-error-quark");
	return quark;
}


G_DEFINE_TYPE_WITH_CODE (NMSettingWireless, nm_setting_wireless, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_WIRELESS_SETTING_NAME,
                                               g_define_type_id,
                                               1,
                                               NM_SETTING_WIRELESS_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_WIRELESS)

#define NM_SETTING_WIRELESS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_WIRELESS, NMSettingWirelessPrivate))

typedef struct {
	GByteArray *ssid;
	char *mode;
	char *band;
	guint32 channel;
	GByteArray *bssid;
	guint32 rate;
	guint32 tx_power;
	GByteArray *device_mac_address;
	GByteArray *cloned_mac_address;
	GSList *mac_address_blacklist;
	guint32 mtu;
	GSList *seen_bssids;
	char *security;
	gboolean hidden;
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
	PROP_SEC,
	PROP_HIDDEN,

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
 * Returns: the #NMSettingWireless:ssid property of the setting
 **/
const GByteArray *
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
const GByteArray *
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
const GByteArray *
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
const GByteArray *
nm_setting_wireless_get_cloned_mac_address (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->cloned_mac_address;
}

/**
 * nm_setting_wireless_get_mac_address_blacklist:
 * @setting: the #NMSettingWireless
 *
 * Returns: (element-type GLib.ByteArray): the
 * #NMSettingWireless:mac-address-blacklist property of the setting
 **/
const GSList *
nm_setting_wireless_get_mac_address_blacklist (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->mac_address_blacklist;
}

/**
 * nm_setting_wireless_get_num_mac_blacklist_items:
 * @setting: the #NMSettingWireless
 *
 * Returns: the number of blacklisted MAC addresses
 *
 * Since: 0.9.10
 **/
guint32
nm_setting_wireless_get_num_mac_blacklist_items (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), 0);

	return g_slist_length (NM_SETTING_WIRELESS_GET_PRIVATE (setting)->mac_address_blacklist);
}

/**
 * nm_setting_wireless_get_mac_blacklist_item:
 * @setting: the #NMSettingWireless
 * @idx: the zero-based index of the MAC address entry
 *
 * Returns: the blacklisted MAC address string (hex-digits-and-colons notation)
 * at index @idx
 *
 * Since: 0.9.10
 **/
const char *
nm_setting_wireless_get_mac_blacklist_item (NMSettingWireless *setting, guint32 idx)
{
	NMSettingWirelessPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);
	g_return_val_if_fail (idx <= g_slist_length (priv->mac_address_blacklist), NULL);

	return (const char *) g_slist_nth_data (priv->mac_address_blacklist, idx);
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
 *
 * Since: 0.9.10
 **/
gboolean
nm_setting_wireless_add_mac_blacklist_item (NMSettingWireless *setting, const char *mac)
{
	NMSettingWirelessPrivate *priv;
	GSList *iter;
	guint8 buf[32];

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), FALSE);
	g_return_val_if_fail (mac != NULL, FALSE);

	if (!nm_utils_hwaddr_aton (mac, ARPHRD_ETHER, buf))
		return FALSE;

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);
	for (iter = priv->mac_address_blacklist; iter; iter = g_slist_next (iter)) {
		if (!strcasecmp (mac, (char *) iter->data))
			return FALSE;
	}

	priv->mac_address_blacklist = g_slist_append (priv->mac_address_blacklist,
	                                              g_ascii_strup (mac, -1));
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST);
	return TRUE;
}

/**
 * nm_setting_wireless_remove_mac_blacklist_item:
 * @setting: the #NMSettingWireless
 * @idx: index number of the MAC address
 *
 * Removes the MAC address at index @idx from the blacklist.
 *
 * Since: 0.9.10
 **/
void
nm_setting_wireless_remove_mac_blacklist_item (NMSettingWireless *setting, guint32 idx)
{
	NMSettingWirelessPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_WIRELESS (setting));

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->mac_address_blacklist, idx);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->mac_address_blacklist = g_slist_delete_link (priv->mac_address_blacklist, elt);
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
 *
 * Since: 0.9.10
 **/
gboolean
nm_setting_wireless_remove_mac_blacklist_item_by_value (NMSettingWireless *setting, const char *mac)
{
	NMSettingWirelessPrivate *priv;
	GSList *iter;
	guint8 buf[32];

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), FALSE);
	g_return_val_if_fail (mac != NULL, FALSE);

	if (!nm_utils_hwaddr_aton (mac, ARPHRD_ETHER, buf))
		return FALSE;

	priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);
	for (iter = priv->mac_address_blacklist; iter; iter = g_slist_next (iter)) {
		if (!strcasecmp (mac, (char *) iter->data)) {
			priv->mac_address_blacklist = g_slist_delete_link (priv->mac_address_blacklist, iter);
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
 *
 * Since: 0.9.10
 **/
void
nm_setting_wireless_clear_mac_blacklist_items (NMSettingWireless *setting)
{
	g_return_if_fail (NM_IS_SETTING_WIRELESS (setting));

	g_slist_free_full (NM_SETTING_WIRELESS_GET_PRIVATE (setting)->mac_address_blacklist, g_free);
	NM_SETTING_WIRELESS_GET_PRIVATE (setting)->mac_address_blacklist = NULL;
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
 * nm_setting_wireless_get_security:
 * @setting: the #NMSettingWireless
 *
 * Returns: the #NMSettingWireless:security property of the setting
 *
 * Deprecated: 0.9.10: No longer used. Security rescrictions are recognized by
 * the presence of NM_SETTING_WIRELESS_SECURITY_SETTING_NAME in the connection.
 **/
const char *
nm_setting_wireless_get_security (NMSettingWireless *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), NULL);

	return NM_SETTING_WIRELESS_GET_PRIVATE (setting)->security;
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
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE (setting);
	const char *valid_modes[] = { NM_SETTING_WIRELESS_MODE_INFRA, NM_SETTING_WIRELESS_MODE_ADHOC, NM_SETTING_WIRELESS_MODE_AP, NULL };
	const char *valid_bands[] = { "a", "bg", NULL };
	GSList *iter;

	if (!priv->ssid) {
		g_set_error_literal (error,
		                     NM_SETTING_WIRELESS_ERROR,
		                     NM_SETTING_WIRELESS_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_SSID);
		return FALSE;
	}

	if (!priv->ssid->len || priv->ssid->len > 32) {
		g_set_error_literal (error,
		                     NM_SETTING_WIRELESS_ERROR,
		                     NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
		                     _("SSID length is out of range <1-32> bytes"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_SSID);
		return FALSE;
	}

	if (priv->mode && !_nm_utils_string_in_list (priv->mode, valid_modes)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_ERROR,
		             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid Wi-Fi mode"),
		             priv->mode);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_MODE);
		return FALSE;
	}

	if (priv->band && !_nm_utils_string_in_list (priv->band, valid_bands)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_ERROR,
		             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid band"),
		             priv->band);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_BAND);
		return FALSE;
	}

	if (priv->channel && !priv->band) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_ERROR,
		             NM_SETTING_WIRELESS_ERROR_CHANNEL_REQUIRES_BAND,
		             _("requires setting '%s' property"),
		             NM_SETTING_WIRELESS_BAND);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_CHANNEL);
		return FALSE;
	}

	if (priv->channel) {
		if (!nm_utils_wifi_is_channel_valid (priv->channel, priv->band)) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_ERROR,
			             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
			             _("'%d' is not a valid channel"),
			             priv->channel);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_CHANNEL);
			return FALSE;
		}
	}

	if (priv->bssid && priv->bssid->len != ETH_ALEN) {
		g_set_error_literal (error,
		                     NM_SETTING_WIRELESS_ERROR,
		                     NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_BSSID);
		return FALSE;
	}

	if (priv->device_mac_address && priv->device_mac_address->len != ETH_ALEN) {
		g_set_error_literal (error,
		                     NM_SETTING_WIRELESS_ERROR,
		                     NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_MAC_ADDRESS);
		return FALSE;
	}

	if (priv->cloned_mac_address && priv->cloned_mac_address->len != ETH_ALEN) {
		g_set_error_literal (error,
		                     NM_SETTING_WIRELESS_ERROR,
		                     NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS);
		return FALSE;
	}

	for (iter = priv->mac_address_blacklist; iter; iter = iter->next) {
		struct ether_addr addr;

		if (!ether_aton_r (iter->data, &addr)) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_ERROR,
			             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
			             _("'%s' is not a valid MAC address"),
			             (const char *) iter->data);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST);
			return FALSE;
		}
	}

	for (iter = priv->seen_bssids; iter; iter = iter->next) {
		struct ether_addr addr;

		if (!ether_aton_r (iter->data, &addr)) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_ERROR,
			             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
			             _("'%s' is not a valid MAC address"),
			             (const char *) iter->data);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_SEEN_BSSIDS);
			return FALSE;
		}
	}

	return TRUE;
}

static void
nm_setting_wireless_init (NMSettingWireless *setting)
{
}

static void
finalize (GObject *object)
{
	NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE (object);

	g_free (priv->mode);
	g_free (priv->band);
	g_free (priv->security);

	if (priv->ssid)
		g_byte_array_free (priv->ssid, TRUE);
	if (priv->bssid)
		g_byte_array_free (priv->bssid, TRUE);
	if (priv->device_mac_address)
		g_byte_array_free (priv->device_mac_address, TRUE);
	if (priv->cloned_mac_address)
		g_byte_array_free (priv->cloned_mac_address, TRUE);
	g_slist_free_full (priv->mac_address_blacklist, g_free);
	g_slist_free_full (priv->seen_bssids, g_free);

	G_OBJECT_CLASS (nm_setting_wireless_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingWirelessPrivate *priv = NM_SETTING_WIRELESS_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SSID:
		if (priv->ssid)
			g_byte_array_free (priv->ssid, TRUE);
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
		if (priv->bssid)
			g_byte_array_free (priv->bssid, TRUE);
		priv->bssid = g_value_dup_boxed (value);
		break;
	case PROP_RATE:
		priv->rate = g_value_get_uint (value);
		break;
	case PROP_TX_POWER:
		priv->tx_power = g_value_get_uint (value);
		break;
	case PROP_MAC_ADDRESS:
		if (priv->device_mac_address)
			g_byte_array_free (priv->device_mac_address, TRUE);
		priv->device_mac_address = g_value_dup_boxed (value);
		break;
	case PROP_CLONED_MAC_ADDRESS:
		if (priv->cloned_mac_address)
			g_byte_array_free (priv->cloned_mac_address, TRUE);
		priv->cloned_mac_address = g_value_dup_boxed (value);
		break;
	case PROP_MAC_ADDRESS_BLACKLIST:
		g_slist_free_full (priv->mac_address_blacklist, g_free);
		priv->mac_address_blacklist = g_value_dup_boxed (value);
		break;
	case PROP_MTU:
		priv->mtu = g_value_get_uint (value);
		break;
	case PROP_SEEN_BSSIDS:
		g_slist_free_full (priv->seen_bssids, g_free);
		priv->seen_bssids = g_value_dup_boxed (value);
		break;
	case PROP_SEC:
		g_free (priv->security);
		priv->security = g_value_dup_string (value);
		break;
	case PROP_HIDDEN:
		priv->hidden = g_value_get_boolean (value);
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
		g_value_set_boxed (value, nm_setting_wireless_get_bssid (setting));
		break;
	case PROP_RATE:
		g_value_set_uint (value, nm_setting_wireless_get_rate (setting));
		break;
	case PROP_TX_POWER:
		g_value_set_uint (value, nm_setting_wireless_get_tx_power (setting));
		break;
	case PROP_MAC_ADDRESS:
		g_value_set_boxed (value, nm_setting_wireless_get_mac_address (setting));
		break;
	case PROP_CLONED_MAC_ADDRESS:
		g_value_set_boxed (value, nm_setting_wireless_get_cloned_mac_address (setting));
		break;
	case PROP_MAC_ADDRESS_BLACKLIST:
		g_value_set_boxed (value, nm_setting_wireless_get_mac_address_blacklist (setting));
		break;
	case PROP_MTU:
		g_value_set_uint (value, nm_setting_wireless_get_mtu (setting));
		break;
	case PROP_SEEN_BSSIDS:
		g_value_set_boxed (value, NM_SETTING_WIRELESS_GET_PRIVATE (setting)->seen_bssids);
		break;
	case PROP_SEC:
		g_value_set_string (value, NM_SETTING_WIRELESS_GET_PRIVATE (setting)->security);
		break;
	case PROP_HIDDEN:
		g_value_set_boolean (value, nm_setting_wireless_get_hidden (setting));
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
	g_object_class_install_property
		(object_class, PROP_SSID,
		 _nm_param_spec_specialized (NM_SETTING_WIRELESS_SSID,
							   "SSID",
							   "SSID of the Wi-Fi network.  Must be specified.",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE));

	/**
	 * NMSettingWireless:mode:
	 *
	 * Wi-Fi network mode; one of "infrastructure", "adhoc" or "ap".  If blank,
	 * infrastructure is assumed.
	 **/
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_string (NM_SETTING_WIRELESS_MODE,
						  "Mode",
						  "Wi-Fi network mode; one of 'infrastructure', "
						  "'adhoc' or 'ap'.  If blank, infrastructure is assumed.",
						  NULL,
						  G_PARAM_READWRITE));

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
	g_object_class_install_property
		(object_class, PROP_BAND,
		 g_param_spec_string (NM_SETTING_WIRELESS_BAND,
						  "Band",
						  "802.11 frequency band of the network.  One of 'a' "
						  "for 5GHz 802.11a or 'bg' for 2.4GHz 802.11.  This "
						  "will lock associations to the Wi-Fi network to the "
						  "specific band, i.e. if 'a' is specified, the device "
						  "will not associate with the same network in the "
						  "2.4GHz band even if the network's settings are "
						  "compatible.  This setting depends on specific driver "
						  "capability and may not work with all drivers.",
						  NULL,
						  G_PARAM_READWRITE));

	/**
	 * NMSettingWireless:channel:
	 *
	 * Wireless channel to use for the Wi-Fi connection.  The device will only
	 * join (or create for Ad-Hoc networks) a Wi-Fi network on the specified
	 * channel.  Because channel numbers overlap between bands, this property
	 * also requires the "band" property to be set.
	 **/
	g_object_class_install_property
		(object_class, PROP_CHANNEL,
		 g_param_spec_uint (NM_SETTING_WIRELESS_CHANNEL,
						"Channel",
						"Wireless channel to use for the Wi-Fi connection.  The "
						"device will only join (or create for Ad-Hoc networks) "
						"a Wi-Fi network on the specified channel.  Because "
						"channel numbers overlap between bands, this property "
						"also requires the 'band' property to be set.",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

	/**
	 * NMSettingWireless:bssid:
	 *
	 * If specified, directs the device to only associate with the given access
	 * point.  This capability is highly driver dependent and not supported by
	 * all devices.  Note: this property does not control the BSSID used when
	 * creating an Ad-Hoc network and is unlikely to in the future.
	 **/
	g_object_class_install_property
		(object_class, PROP_BSSID,
		 _nm_param_spec_specialized (NM_SETTING_WIRELESS_BSSID,
							   "BSSID",
							   "If specified, directs the device to only associate "
							   "with the given access point.  This capability is "
							   "highly driver dependent and not supported by all "
							   "devices.  Note: this property does not control "
							   "the BSSID used when creating an Ad-Hoc network "
							   "and is unlikely to in the future.",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE));

	/**
	 * NMSettingWireless:rate:
	 *
	 * If non-zero, directs the device to only use the specified bitrate for
	 * communication with the access point.  Units are in Kb/s, ie 5500 = 5.5
	 * Mbit/s.  This property is highly driver dependent and not all devices
	 * support setting a static bitrate.
	 **/
	g_object_class_install_property
		(object_class, PROP_RATE,
		 g_param_spec_uint (NM_SETTING_WIRELESS_RATE,
						"Rate",
						"If non-zero, directs the device to only use the "
						"specified bitrate for communication with the access "
						"point.  Units are in Kb/s, ie 5500 = 5.5 Mbit/s.  This "
						"property is highly driver dependent and not all devices "
						"support setting a static bitrate.",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_FUZZY_IGNORE));

	/**
	 * NMSettingWireless:tx-power:
	 *
	 * If non-zero, directs the device to use the specified transmit power.
	 * Units are dBm.  This property is highly driver dependent and not all
	 * devices support setting a static transmit power.
	 **/
	g_object_class_install_property
		(object_class, PROP_TX_POWER,
		 g_param_spec_uint (NM_SETTING_WIRELESS_TX_POWER,
						"TX Power",
						"If non-zero, directs the device to use the specified "
						"transmit power.  Units are dBm.  This property is highly "
						"driver dependent and not all devices support setting a "
						"static transmit power.",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_FUZZY_IGNORE));

	/**
	 * NMSettingWireless:mac-address:
	 *
	 * If specified, this connection will only apply to the Wi-Fi device whose
	 * permanent MAC address matches. This property does not change the MAC
	 * address of the device (i.e. MAC spoofing).
	 **/
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS,
		 _nm_param_spec_specialized (NM_SETTING_WIRELESS_MAC_ADDRESS,
							   "Device MAC Address",
							   "If specified, this connection will only apply to "
							   "the Wi-Fi device whose permanent MAC address matches.  "
							   "This property does not change the MAC address "
							   "of the device (i.e. MAC spoofing).",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE));

	/**
	 * NMSettingWireless:cloned-mac-address:
	 *
	 * If specified, request that the Wi-Fi device use this MAC address instead
	 * of its permanent MAC address.  This is known as MAC cloning or spoofing.
	 **/
	g_object_class_install_property
		(object_class, PROP_CLONED_MAC_ADDRESS,
		 _nm_param_spec_specialized (NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS,
	                                     "Spoof MAC Address",
	                                     "If specified, request that the Wi-Fi device use "
	                                     "this MAC address instead of its permanent MAC address.  "
	                                     "This is known as MAC cloning or spoofing.",
	                                     DBUS_TYPE_G_UCHAR_ARRAY,
	                                     G_PARAM_READWRITE));

	/**
	 * NMSettingWireless:mac-address-blacklist:
	 *
	 * A list of permanent MAC addresses of Wi-Fi devices to which this
	 * connection should never apply.  Each MAC address should be given in the
	 * standard hex-digits-and-colons notation (eg "00:11:22:33:44:55").
	 **/
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS_BLACKLIST,
		 _nm_param_spec_specialized (NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST,
		                             "MAC Address Blacklist",
		                             "A list of permanent MAC addresses of Wi-Fi "
		                             "devices to which this connection should "
		                             "never apply.  Each MAC address should be "
		                             "given in the standard hex-digits-and-colons "
		                             "notation (eg '00:11:22:33:44:55').",
		                             DBUS_TYPE_G_LIST_OF_STRING,
		                             G_PARAM_READWRITE | NM_SETTING_PARAM_FUZZY_IGNORE));

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
	g_object_class_install_property
		(object_class, PROP_SEEN_BSSIDS,
		 _nm_param_spec_specialized (NM_SETTING_WIRELESS_SEEN_BSSIDS,
		                             "Seen BSSIDS",
		                             "A list of BSSIDs (each BSSID formatted as a MAC "
		                             "address like 00:11:22:33:44:55') that have been "
		                             "detected as part of the Wi-Fi network. "
		                             "NetworkManager internally tracks previously seen "
		                             "BSSIDs. The property is only meant for reading "
		                             "and reflects the BSSID list of NetworkManager. "
		                             "The changes you make to this property will not be "
		                             "preserved.",
		                             DBUS_TYPE_G_LIST_OF_STRING,
		                             G_PARAM_READWRITE | NM_SETTING_PARAM_FUZZY_IGNORE));

	/**
	 * NMSettingWireless:mtu:
	 *
	 * If non-zero, only transmit packets of the specified size or smaller,
	 * breaking larger packets up into multiple Ethernet frames.
	 **/
	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_SETTING_WIRELESS_MTU,
						"MTU",
						"If non-zero, only transmit packets of the specified "
						"size or smaller, breaking larger packets up into "
						"multiple Ethernet frames.",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_FUZZY_IGNORE));

	/**
	 * NMSettingWireless:security:
	 *
	 * If the wireless connection has any security restrictions, like 802.1x,
	 * WEP, or WPA, set this property to
	 * %NM_SETTING_WIRELESS_SECURITY_SETTING_NAME and ensure the connection
	 * contains a valid #NMSettingWirelessSecurity setting.
	 *
	 * Deprecated: 0.9.10: No longer used. Security restrictions are recognized
	 * by the presence of a #NMSettingWirelessSecurity setting in the
	 * connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_SEC,
		 g_param_spec_string (NM_SETTING_WIRELESS_SEC,
						  "Security",
						  "If the wireless connection has any security "
						  "restrictions, like 802.1x, WEP, or WPA, set this "
						  "property to '" NM_SETTING_WIRELESS_SECURITY_SETTING_NAME "' "
						  "and ensure the connection contains a valid "
						  NM_SETTING_WIRELESS_SECURITY_SETTING_NAME " setting.",
						  NULL,
						  G_PARAM_READWRITE));

	/**
	 * NMSettingWireless:hidden:
	 *
	 * If %TRUE, indicates this network is a non-broadcasting network that hides
	 * its SSID.  In this case various workarounds may take place, such as
	 * probe-scanning the SSID for more reliable network discovery.  However,
	 * these workarounds expose inherent insecurities with hidden SSID networks,
	 * and thus hidden SSID networks should be used with caution.
	 **/
	g_object_class_install_property
		(object_class, PROP_HIDDEN,
		 g_param_spec_boolean (NM_SETTING_WIRELESS_HIDDEN,
		                       "Hidden",
		                       "If TRUE, indicates this network is a non-broadcasting "
		                       "network that hides its SSID.  In this case various "
		                       "workarounds may take place, such as probe-scanning "
		                       "the SSID for more reliable network discovery.  "
		                       "However, these workarounds expose inherent "
		                       "insecurities with hidden SSID networks, and thus "
		                       "hidden SSID networks should be used with caution.",
		                       FALSE,
		                       G_PARAM_READWRITE));
}
