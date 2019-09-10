// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright 2007 - 2017 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-setting-wireless-security.h"

#include "nm-setting-8021x.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"
#include "nm-setting-wireless.h"

/**
 * SECTION:nm-setting-wireless-security
 * @short_description: Describes connection properties for Wi-Fi networks that
 * use WEP, LEAP, WPA or WPA2/RSN security
 *
 * The #NMSettingWirelessSecurity object is a #NMSetting subclass that describes
 * properties necessary for connection to encrypted Wi-Fi networks.
 *
 * It's a good idea to read up on wpa_supplicant configuration before using this
 * setting extensively, since most of the options here correspond closely with
 * the relevant wpa_supplicant configuration options.  To get a better overview
 * of how Wi-Fi security works, you may want to get copies of the following books.
 *
 *  802.11 Wireless Networks: The Definitive Guide, Second Edition
 *       Author: Matthew Gast
 *       ISBN: 978-0596100520
 *
 *  Cisco Wireless LAN Security
 *       Authors: Krishna Sankar, Sri Sundaralingam, Darrin Miller, and Andrew Balinsky
 *       ISBN: 978-1587051548
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingWirelessSecurity,
	PROP_KEY_MGMT,
	PROP_WEP_TX_KEYIDX,
	PROP_AUTH_ALG,
	PROP_PROTO,
	PROP_PAIRWISE,
	PROP_GROUP,
	PROP_PMF,
	PROP_LEAP_USERNAME,
	PROP_WEP_KEY0,
	PROP_WEP_KEY1,
	PROP_WEP_KEY2,
	PROP_WEP_KEY3,
	PROP_WEP_KEY_FLAGS,
	PROP_WEP_KEY_TYPE,
	PROP_PSK,
	PROP_PSK_FLAGS,
	PROP_LEAP_PASSWORD,
	PROP_LEAP_PASSWORD_FLAGS,
	PROP_WPS_METHOD,
	PROP_FILS,
);

typedef struct {
	char *key_mgmt;
	char *auth_alg;
	GSList *proto; /* GSList of strings */
	GSList *pairwise; /* GSList of strings */
	GSList *group; /* GSList of strings */
	NMSettingWirelessSecurityPmf pmf;

	/* LEAP */
	char *leap_username;
	char *leap_password;
	NMSettingSecretFlags leap_password_flags;

	/* WEP */
	char *wep_key0;
	char *wep_key1;
	char *wep_key2;
	char *wep_key3;
	NMSettingSecretFlags wep_key_flags;
	NMWepKeyType wep_key_type;
	guint32 wep_tx_keyidx;

	/* WPA-PSK */
	char *psk;
	NMSettingSecretFlags psk_flags;

	/* WPS */
	NMSettingWirelessSecurityWpsMethod wps_method;

	/* FILS */
	NMSettingWirelessSecurityFils fils;
} NMSettingWirelessSecurityPrivate;

G_DEFINE_TYPE (NMSettingWirelessSecurity, nm_setting_wireless_security, NM_TYPE_SETTING)

#define NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_WIRELESS_SECURITY, NMSettingWirelessSecurityPrivate))

/*****************************************************************************/

/**
 * nm_setting_wireless_security_get_key_mgmt:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the #NMSettingWirelessSecurity:key-mgmt property of the setting
 **/
const char *
nm_setting_wireless_security_get_key_mgmt (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->key_mgmt;
}

/**
 * nm_setting_wireless_security_get_num_protos:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the number of security protocols this connection allows when
 * connecting to secure Wi-Fi networks
 **/
guint32
nm_setting_wireless_security_get_num_protos (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), 0);

	return g_slist_length (NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->proto);
}

/**
 * nm_setting_wireless_security_get_proto:
 * @setting: the #NMSettingWirelessSecurity
 * @i: an index into the protocol list
 *
 * Returns: the protocol at index @i
 **/
const char *
nm_setting_wireless_security_get_proto (NMSettingWirelessSecurity *setting, guint32 i)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->proto), NULL);

	return (const char *) g_slist_nth_data (priv->proto, i);
}

/**
 * nm_setting_wireless_security_add_proto:
 * @setting: the #NMSettingWirelessSecurity
 * @proto: the protocol to add, one of "wpa" or "rsn"
 *
 * Adds a Wi-Fi security protocol (one of "wpa" or "rsn") to the allowed list;
 * only protocols in this list will be used when finding and connecting to
 * the Wi-Fi network specified by this connection.  For example, if the
 * protocol list contains only "wpa" but the access point for the SSID specified
 * by this connection only supports WPA2/RSN, the connection cannot be used
 * with the access point.
 *
 * Returns: %TRUE if the protocol was new and was added to the allowed
 * protocol list, or %FALSE if it was already in the list
 **/
gboolean
nm_setting_wireless_security_add_proto (NMSettingWirelessSecurity *setting, const char *proto)
{
	NMSettingWirelessSecurityPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), FALSE);
	g_return_val_if_fail (proto != NULL, FALSE);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	for (iter = priv->proto; iter; iter = g_slist_next (iter)) {
		if (strcasecmp (proto, (char *) iter->data) == 0)
			return FALSE;
	}

	priv->proto = g_slist_append (priv->proto, g_ascii_strdown (proto, -1));
	_notify (setting, PROP_PROTO);
	return TRUE;
}

/**
 * nm_setting_wireless_security_remove_proto:
 * @setting: the #NMSettingWirelessSecurity
 * @i: index of the protocol to remove
 *
 * Removes a protocol from the allowed protocol list.
 **/
void
nm_setting_wireless_security_remove_proto (NMSettingWirelessSecurity *setting, guint32 i)
{
	NMSettingWirelessSecurityPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting));

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->proto, i);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->proto = g_slist_delete_link (priv->proto, elt);
	_notify (setting, PROP_PROTO);
}

/**
 * nm_setting_wireless_security_remove_proto_by_value:
 * @setting: the #NMSettingWirelessSecurity
 * @proto: the protocol to remove, one of "wpa" or "rsn"
 *
 * Removes a protocol from the allowed protocol list.
 *
 * Returns: %TRUE if the protocol was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_wireless_security_remove_proto_by_value (NMSettingWirelessSecurity *setting,
                                                    const char *proto)
{
	NMSettingWirelessSecurityPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), FALSE);
	g_return_val_if_fail (proto != NULL, FALSE);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	for (iter = priv->proto; iter; iter = g_slist_next (iter)) {
		if (strcasecmp (proto, (char *) iter->data) == 0) {
			priv->proto = g_slist_delete_link (priv->proto, iter);
			_notify (setting, PROP_PROTO);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_wireless_security_clear_protos:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Removes all protocols from the allowed list.  If there are no protocols
 * specified then all protocols are allowed.
 **/
void
nm_setting_wireless_security_clear_protos (NMSettingWirelessSecurity *setting)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting));

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	g_slist_free_full (priv->proto, g_free);
	priv->proto = NULL;
	_notify (setting, PROP_PROTO);
}

/**
 * nm_setting_wireless_security_get_num_pairwise:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the number of pairwise encryption algorithms in the allowed list
 **/
guint32
nm_setting_wireless_security_get_num_pairwise (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), 0);

	return g_slist_length (NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->pairwise);
}

/**
 * nm_setting_wireless_security_get_pairwise:
 * @setting: the #NMSettingWirelessSecurity
 * @i: index of an item in the allowed pairwise encryption algorithm list
 *
 * Returns the allowed pairwise encryption algorithm from allowed algorithm
 * list.
 *
 * Returns: the pairwise encryption algorithm at index @i
 **/
const char *
nm_setting_wireless_security_get_pairwise (NMSettingWirelessSecurity *setting, guint32 i)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->pairwise), NULL);

	return (const char *) g_slist_nth_data (priv->pairwise, i);
}

/**
 * nm_setting_wireless_security_add_pairwise:
 * @setting: the #NMSettingWirelessSecurity
 * @pairwise: the encryption algorithm to add, one of "tkip" or "ccmp"
 *
 * Adds an encryption algorithm to the list of allowed pairwise encryption
 * algorithms.  If the list is not empty, then only access points that support
 * one or more of the encryption algorithms in the list will be considered
 * compatible with this connection.
 *
 * Returns: %TRUE if the algorithm was added to the list, %FALSE if it was
 * already in the list
 **/
gboolean
nm_setting_wireless_security_add_pairwise (NMSettingWirelessSecurity *setting, const char *pairwise)
{
	NMSettingWirelessSecurityPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), FALSE);
	g_return_val_if_fail (pairwise != NULL, FALSE);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	for (iter = priv->pairwise; iter; iter = g_slist_next (iter)) {
		if (strcasecmp (pairwise, (char *) iter->data) == 0)
			return FALSE;
	}

	priv->pairwise = g_slist_append (priv->pairwise, g_ascii_strdown (pairwise, -1));
	_notify (setting, PROP_PAIRWISE);
	return TRUE;
}

/**
 * nm_setting_wireless_security_remove_pairwise:
 * @setting: the #NMSettingWirelessSecurity
 * @i: the index of an item in the allowed pairwise encryption algorithm list
 *
 * Removes an encryption algorithm from the allowed pairwise encryption
 * algorithm list.
 **/
void
nm_setting_wireless_security_remove_pairwise (NMSettingWirelessSecurity *setting, guint32 i)
{
	NMSettingWirelessSecurityPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting));

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->pairwise, i);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->pairwise = g_slist_delete_link (priv->pairwise, elt);
	_notify (setting, PROP_PAIRWISE);
}

/**
 * nm_setting_wireless_security_remove_pairwise_by_value:
 * @setting: the #NMSettingWirelessSecurity
 * @pairwise: the encryption algorithm to remove, one of "tkip" or "ccmp"
 *
 * Removes an encryption algorithm from the allowed pairwise encryption
 * algorithm list.
 *
 * Returns: %TRUE if the encryption algorithm was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_wireless_security_remove_pairwise_by_value (NMSettingWirelessSecurity *setting,
                                                       const char *pairwise)
{
	NMSettingWirelessSecurityPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), FALSE);
	g_return_val_if_fail (pairwise != NULL, FALSE);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	for (iter = priv->pairwise; iter; iter = g_slist_next (iter)) {
		if (strcasecmp (pairwise, (char *) iter->data) == 0) {
			priv->pairwise = g_slist_delete_link (priv->pairwise, iter);
			_notify (setting, PROP_PAIRWISE);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_wireless_security_clear_pairwise:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Removes all algorithms from the allowed list.  If there are no algorithms
 * specified then all pairwise encryption algorithms are allowed.
 **/
void
nm_setting_wireless_security_clear_pairwise (NMSettingWirelessSecurity *setting)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting));

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	g_slist_free_full (priv->pairwise, g_free);
	priv->pairwise = NULL;
	_notify (setting, PROP_PAIRWISE);
}

/**
 * nm_setting_wireless_security_get_num_groups:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the number of groupwise encryption algorithms in the allowed list
 **/
guint32
nm_setting_wireless_security_get_num_groups (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), 0);

	return g_slist_length (NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->group);
}

/**
 * nm_setting_wireless_security_get_group:
 * @setting: the #NMSettingWirelessSecurity
 * @i: index of an item in the allowed groupwise encryption algorithm list
 *
 * Returns the allowed groupwise encryption algorithm from allowed algorithm
 * list.
 *
 * Returns: the groupwise encryption algorithm at index @i
 **/
const char *
nm_setting_wireless_security_get_group (NMSettingWirelessSecurity *setting, guint32 i)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->group), NULL);

	return (const char *) g_slist_nth_data (priv->group, i);
}

/**
 * nm_setting_wireless_security_add_group:
 * @setting: the #NMSettingWirelessSecurity
 * @group: the encryption algorithm to add, one of "wep40", "wep104",
 * "tkip", or "ccmp"
 *
 * Adds an encryption algorithm to the list of allowed groupwise encryption
 * algorithms.  If the list is not empty, then only access points that support
 * one or more of the encryption algorithms in the list will be considered
 * compatible with this connection.
 *
 * Returns: %TRUE if the algorithm was added to the list, %FALSE if it was
 * already in the list
 **/
gboolean
nm_setting_wireless_security_add_group (NMSettingWirelessSecurity *setting, const char *group)
{
	NMSettingWirelessSecurityPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), FALSE);
	g_return_val_if_fail (group != NULL, FALSE);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	for (iter = priv->group; iter; iter = g_slist_next (iter)) {
		if (strcasecmp (group, (char *) iter->data) == 0)
			return FALSE;
	}

	priv->group = g_slist_append (priv->group, g_ascii_strdown (group, -1));
	_notify (setting, PROP_GROUP);
	return TRUE;
}

/**
 * nm_setting_wireless_security_remove_group:
 * @setting: the #NMSettingWirelessSecurity
 * @i: the index of an item in the allowed groupwise encryption algorithm list
 *
 * Removes an encryption algorithm from the allowed groupwise encryption
 * algorithm list.
 **/
void
nm_setting_wireless_security_remove_group (NMSettingWirelessSecurity *setting, guint32 i)
{
	NMSettingWirelessSecurityPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting));

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->group, i);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->group = g_slist_delete_link (priv->group, elt);
	_notify (setting, PROP_GROUP);
}

/**
 * nm_setting_wireless_security_remove_group_by_value:
 * @setting: the #NMSettingWirelessSecurity
 * @group: the encryption algorithm to remove, one of "wep40", "wep104",
 * "tkip", or "ccmp"
 *
 * Removes an encryption algorithm from the allowed groupwise encryption
 * algorithm list.
 *
 * Returns: %TRUE if the algorithm was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_wireless_security_remove_group_by_value (NMSettingWirelessSecurity *setting,
                                                    const char *group)
{
	NMSettingWirelessSecurityPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), FALSE);
	g_return_val_if_fail (group != NULL, FALSE);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	for (iter = priv->group; iter; iter = g_slist_next (iter)) {
		if (strcasecmp (group, (char *) iter->data) == 0) {
			priv->group = g_slist_delete_link (priv->group, iter);
			_notify (setting, PROP_GROUP);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_wireless_security_clear_groups:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Removes all algorithms from the allowed list.  If there are no algorithms
 * specified then all groupwise encryption algorithms are allowed.
 **/
void
nm_setting_wireless_security_clear_groups (NMSettingWirelessSecurity *setting)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting));

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	g_slist_free_full (priv->group, g_free);
	priv->group = NULL;
	_notify (setting, PROP_GROUP);
}

/*
 * nm_setting_wireless_security_get_pmf:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the #NMSettingWirelessSecurity:pmf property of the setting
 *
 * Since: 1.10
 **/
NMSettingWirelessSecurityPmf
nm_setting_wireless_security_get_pmf (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), 0);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->pmf;
}

/**
 * nm_setting_wireless_security_get_psk:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the #NMSettingWirelessSecurity:psk property of the setting
 **/
const char *
nm_setting_wireless_security_get_psk (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->psk;
}

/**
 * nm_setting_wireless_security_get_psk_flags:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the #NMSettingSecretFlags pertaining to the
 * #NMSettingWirelessSecurity:psk
 **/
NMSettingSecretFlags
nm_setting_wireless_security_get_psk_flags (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->psk_flags;
}

/**
 * nm_setting_wireless_security_get_leap_username:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the #NMSettingWirelessSecurity:leap-username property of the setting
 **/
const char *
nm_setting_wireless_security_get_leap_username (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->leap_username;
}

/**
 * nm_setting_wireless_security_get_leap_password:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the #NMSettingWirelessSecurity:leap-password property of the setting
 **/
const char *
nm_setting_wireless_security_get_leap_password (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->leap_password;
}

/**
 * nm_setting_wireless_security_get_leap_password_flags:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the #NMSettingSecretFlags pertaining to the
 * #NMSettingWirelessSecurity:leap-password
 **/
NMSettingSecretFlags
nm_setting_wireless_security_get_leap_password_flags (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->leap_password_flags;
}

/**
 * nm_setting_wireless_security_get_wep_key:
 * @setting: the #NMSettingWirelessSecurity
 * @idx: the WEP key index (0..3 inclusive)
 *
 * Returns: the WEP key at the given index
 **/
const char *
nm_setting_wireless_security_get_wep_key (NMSettingWirelessSecurity *setting, guint32 idx)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);
	g_return_val_if_fail (idx < 4, NULL);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	if (idx == 0)
		return priv->wep_key0;
	else if (idx == 1)
		return priv->wep_key1;
	else if (idx == 2)
		return priv->wep_key2;
	else if (idx == 3)
		return priv->wep_key3;

	g_assert_not_reached ();
	return NULL;
}

/**
 * nm_setting_wireless_security_set_wep_key:
 * @setting: the #NMSettingWirelessSecurity
 * @idx: the index of the key (0..3 inclusive)
 * @key: the WEP key as a string, in either hexadecimal, ASCII, or passphrase
 * form as determiend by the value of the #NMSettingWirelessSecurity:wep-key-type
 * property.
 *
 * Sets a WEP key in the given index.
 **/
void
nm_setting_wireless_security_set_wep_key (NMSettingWirelessSecurity *setting, guint32 idx, const char *key)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting));
	g_return_if_fail (idx < 4);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	switch (idx) {
	case 0:
		g_free (priv->wep_key0);
		priv->wep_key0 = g_strdup (key);
		_notify (setting, PROP_WEP_KEY0);
		break;
	case 1:
		g_free (priv->wep_key1);
		priv->wep_key1 = g_strdup (key);
		_notify (setting, PROP_WEP_KEY1);
		break;
	case 2:
		g_free (priv->wep_key2);
		priv->wep_key2 = g_strdup (key);
		_notify (setting, PROP_WEP_KEY2);
		break;
	case 3:
		g_free (priv->wep_key3);
		priv->wep_key3 = g_strdup (key);
		_notify (setting, PROP_WEP_KEY3);
		break;
	default:
		g_assert_not_reached ();
	}
}

/**
 * nm_setting_wireless_security_get_wep_tx_keyidx:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the #NMSettingWirelessSecurity:wep-tx-keyidx property of the setting
 **/
guint32
nm_setting_wireless_security_get_wep_tx_keyidx (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), 0);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->wep_tx_keyidx;
}

/**
 * nm_setting_wireless_security_get_auth_alg:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the #NMSettingWirelessSecurity:auth-alg property of the setting
 **/
const char *
nm_setting_wireless_security_get_auth_alg (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->auth_alg;
}

/**
 * nm_setting_wireless_security_get_wep_key_flags:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the #NMSettingSecretFlags pertaining to the all WEP keys
 **/
NMSettingSecretFlags
nm_setting_wireless_security_get_wep_key_flags (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->wep_key_flags;
}

/**
 * nm_setting_wireless_security_get_wep_key_type:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the #NMSettingWirelessSecurity:wep-key-type property of the setting
 **/
NMWepKeyType
nm_setting_wireless_security_get_wep_key_type (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), 0);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->wep_key_type;
}

/**
 * nm_setting_wireless_security_get_wps_method:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the #NMSettingWirelessSecurity:wps-method property of the setting
 *
 * Since: 1.10
 **/
NMSettingWirelessSecurityWpsMethod
nm_setting_wireless_security_get_wps_method (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting),
	                      NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DISABLED);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->wps_method;
}

/*
 * nm_setting_wireless_security_get_fils:
 * @setting: the #NMSettingWirelessSecurity
 *
 * Returns: the #NMSettingWirelessSecurity:fils property of the setting
 *
 * Since: 1.12
 **/
NMSettingWirelessSecurityFils
nm_setting_wireless_security_get_fils (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), 0);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->fils;
}

static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSettingWirelessSecurity *self = NM_SETTING_WIRELESS_SECURITY (setting);
	NMSettingWirelessSecurityPrivate *priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (self);
	GPtrArray *secrets;

	secrets = g_ptr_array_sized_new (4);

	g_assert (priv->key_mgmt);

	/* Static WEP */
	if (strcmp (priv->key_mgmt, "none") == 0) {
		if ((priv->wep_tx_keyidx == 0) && !nm_utils_wep_key_valid (priv->wep_key0, priv->wep_key_type)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);
			return secrets;
		}
		if ((priv->wep_tx_keyidx == 1) && !nm_utils_wep_key_valid (priv->wep_key1, priv->wep_key_type)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_WEP_KEY1);
			return secrets;
		}
		if ((priv->wep_tx_keyidx == 2) && !nm_utils_wep_key_valid (priv->wep_key2, priv->wep_key_type)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_WEP_KEY2);
			return secrets;
		}
		if ((priv->wep_tx_keyidx == 3) && !nm_utils_wep_key_valid (priv->wep_key3, priv->wep_key_type)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_WEP_KEY3);
			return secrets;
		}
		goto no_secrets;
	}

	/* WPA-PSK infrastructure */
	if (strcmp (priv->key_mgmt, "wpa-psk") == 0) {
		if (!nm_utils_wpa_psk_valid (priv->psk)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_PSK);
			return secrets;
		}
		goto no_secrets;
	}

	/* SAE, used in MESH and WPA3-Personal */
	if (strcmp (priv->key_mgmt, "sae") == 0) {
		if (!priv->psk || !*priv->psk) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_PSK);
			return secrets;
		}
		goto no_secrets;
	}

	/* LEAP */
	if (   priv->auth_alg
	    && !strcmp (priv->auth_alg, "leap")
	    && !strcmp (priv->key_mgmt, "ieee8021x")) {
		if (!priv->leap_password || !*priv->leap_password) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD);
			return secrets;
		}
		goto no_secrets;
	}

	if (   (strcmp (priv->key_mgmt, "ieee8021x") == 0)
	    || (strcmp (priv->key_mgmt, "wpa-eap") == 0)) {
		/* Let caller check the 802.1x setting for secrets */
		goto no_secrets;
	}

	g_assert_not_reached ();
	return secrets;

no_secrets:
	if (secrets)
		g_ptr_array_free (secrets, TRUE);
	return NULL;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingWirelessSecurity *self = NM_SETTING_WIRELESS_SECURITY (setting);
	NMSettingWirelessSecurityPrivate *priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (self);
	const char *valid_key_mgmt[] = { "none", "ieee8021x", "wpa-psk", "wpa-eap", "sae", NULL };
	const char *valid_auth_algs[] = { "open", "shared", "leap", NULL };
	const char *valid_protos[] = { "wpa", "rsn", NULL };
	const char *valid_pairwise[] = { "tkip", "ccmp", NULL };
	const char *valid_groups[] = { "wep40", "wep104", "tkip", "ccmp", NULL };
	NMSettingWireless *s_wifi;
	const char *wifi_mode;

	s_wifi = connection ? nm_connection_get_setting_wireless (connection) : NULL;
	wifi_mode = s_wifi ? nm_setting_wireless_get_mode (s_wifi) : NULL;

	if (!priv->key_mgmt) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
		return FALSE;
	}

	if (g_strcmp0 (wifi_mode, NM_SETTING_WIRELESS_MODE_MESH) == 0) {
		if (   (strcmp (priv->key_mgmt, "none") == 0)
		    || (strcmp (priv->key_mgmt, "sae") == 0)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' is not a valid value for '%s' mode connections"),
			             priv->key_mgmt, NM_SETTING_WIRELESS_MODE_MESH);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
			return FALSE;
		}
	} else {
		if (!g_strv_contains (valid_key_mgmt, priv->key_mgmt)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' is not a valid value for the property"),
			             priv->key_mgmt);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
			return FALSE;
		}
	}

	if (priv->auth_alg && !strcmp (priv->auth_alg, "leap")) {
		/* LEAP must use ieee8021x key management */
		if (strcmp (priv->key_mgmt, "ieee8021x")) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' security requires '%s=%s'"),
			             "leap", NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x");
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
			return FALSE;
		}
		if (!priv->leap_username) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
			return FALSE;
		}
	} else {
		if (   (strcmp (priv->key_mgmt, "ieee8021x") == 0)
		    || (strcmp (priv->key_mgmt, "wpa-eap") == 0)) {
			/* Need an 802.1x setting too */
			if (connection && !nm_connection_get_setting_802_1x (connection)) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_MISSING_SETTING,
				             _("'%s' security requires '%s' setting presence"),
				             priv->key_mgmt, NM_SETTING_802_1X_SETTING_NAME);
				g_prefix_error (error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
				return FALSE;
			}
		}
	}

	if (priv->leap_username && !strlen (priv->leap_username)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
		return FALSE;
	}

	if (priv->wep_tx_keyidx > 3) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%d' value is out of range <0-3>"),
		             priv->wep_tx_keyidx);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX);
		return FALSE;
	}

	if (priv->wep_key_type > NM_WEP_KEY_TYPE_LAST) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE);
		return FALSE;
	}

	if (priv->auth_alg && !g_strv_contains (valid_auth_algs, priv->auth_alg)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
		return FALSE;
	}

	if (priv->proto && !_nm_utils_string_slist_validate (priv->proto, valid_protos)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_PROTO);
		return FALSE;
	}

	if (priv->pairwise) {
		if (!_nm_utils_string_slist_validate (priv->pairwise, valid_pairwise)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("property is invalid"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
			return FALSE;
		}
	}

	if (priv->group && !_nm_utils_string_slist_validate (priv->group, valid_groups)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_GROUP);
		return FALSE;
	}

	/* Shared Key auth can only be used with WEP */
	if (priv->auth_alg && !strcmp (priv->auth_alg, "shared")) {
		if (priv->key_mgmt && strcmp (priv->key_mgmt, "none")) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' can only be used with '%s=%s' (WEP)"),
			             "shared", NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none");
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
			return FALSE;
		}
	}

	G_STATIC_ASSERT_EXPR (((NMSettingWirelessSecurityPmf) -1) > 0);
	if (priv->pmf > NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_PMF);
		return FALSE;
	}

	if (   NM_IN_SET (priv->pmf,
	                  NM_SETTING_WIRELESS_SECURITY_PMF_OPTIONAL,
	                  NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED)
	    && !NM_IN_STRSET (priv->key_mgmt, "wpa-eap", "wpa-psk", "sae")) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' can only be used with 'wpa-eap', 'wpa-psk' or 'sae' key management "),
		             priv->pmf == NM_SETTING_WIRELESS_SECURITY_PMF_OPTIONAL ? "optional" : "required");
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_PMF);
		return FALSE;
	}

	if (!_nm_utils_wps_method_validate (priv->wps_method,
	                                    NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	                                    NM_SETTING_WIRELESS_SECURITY_WPS_METHOD,
	                                    FALSE,
	                                    error))
		return FALSE;

	return TRUE;
}

static gboolean
_verify_wep_key (const char *wep_key,
                 NMWepKeyType wep_key_type,
                 const char *property,
                 GError **error)
{
	if (wep_key && !nm_utils_wep_key_valid (wep_key, wep_key_type)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, property);
		return FALSE;
	}
	return TRUE;
}

static gboolean
verify_secrets (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingWirelessSecurity *self = NM_SETTING_WIRELESS_SECURITY (setting);
	NMSettingWirelessSecurityPrivate *priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (self);

	/* LEAP */
	if (   priv->auth_alg
	    && !strcmp (priv->auth_alg, "leap")
	    && !strcmp (priv->key_mgmt, "ieee8021x")) {
		if (!_nm_setting_verify_secret_string (priv->leap_password,
		                                       NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
		                                       NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
		                                       error))
			return FALSE;
	}

	/* WEP */
	if (!_verify_wep_key (priv->wep_key0, priv->wep_key_type, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0, error))
		return FALSE;
	if (!_verify_wep_key (priv->wep_key1, priv->wep_key_type, NM_SETTING_WIRELESS_SECURITY_WEP_KEY1, error))
		return FALSE;
	if (!_verify_wep_key (priv->wep_key2, priv->wep_key_type, NM_SETTING_WIRELESS_SECURITY_WEP_KEY2, error))
		return FALSE;
	if (!_verify_wep_key (priv->wep_key3, priv->wep_key_type, NM_SETTING_WIRELESS_SECURITY_WEP_KEY3, error))
		return FALSE;

	/* WPA-PSK */
	if (   priv->psk
	    && strcmp (priv->key_mgmt, "sae") != 0
	    && !nm_utils_wpa_psk_valid (priv->psk)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_PSK);
		return FALSE;
	}

	return TRUE;
}

static gboolean
get_secret_flags (NMSetting *setting,
                  const char *secret_name,
                  NMSettingSecretFlags *out_flags,
                  GError **error)
{
	NMSettingSecretFlags flags;

	if (NM_IN_STRSET (secret_name, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0,
	                               NM_SETTING_WIRELESS_SECURITY_WEP_KEY1,
	                               NM_SETTING_WIRELESS_SECURITY_WEP_KEY2,
	                               NM_SETTING_WIRELESS_SECURITY_WEP_KEY3)) {
		/* There's only one 'flags' property for WEP keys, so alias all the WEP key
		 * property names to that flags property. */
		nm_assert (_nm_setting_property_is_regular_secret (setting, secret_name));
		nm_assert (_nm_setting_property_is_regular_secret_flags (setting, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS));

		g_object_get (G_OBJECT (setting),
		              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS,
		              &flags,
		              NULL);
		NM_SET_OUT (out_flags, flags);
		return TRUE;
	}

	return NM_SETTING_CLASS (nm_setting_wireless_security_parent_class)->get_secret_flags (setting, secret_name, out_flags, error);
}

static gboolean
set_secret_flags (NMSetting *setting,
                  const char *secret_name,
                  NMSettingSecretFlags flags,
                  GError **error)
{
	if (NM_IN_STRSET (secret_name, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0,
	                               NM_SETTING_WIRELESS_SECURITY_WEP_KEY1,
	                               NM_SETTING_WIRELESS_SECURITY_WEP_KEY2,
	                               NM_SETTING_WIRELESS_SECURITY_WEP_KEY3)) {
		/* There's only one 'flags' property for WEP keys, so alias all the WEP key
		 * property names to that flags property. */
		nm_assert (_nm_setting_property_is_regular_secret (setting, secret_name));
		nm_assert (_nm_setting_property_is_regular_secret_flags (setting, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS));

		if (!nm_g_object_set_property_flags (G_OBJECT (setting),
		                                     NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS,
		                                     NM_TYPE_SETTING_SECRET_FLAGS,
		                                     flags,
		                                     error))
			g_return_val_if_reached (FALSE);
		return TRUE;
	}

	return NM_SETTING_CLASS (nm_setting_wireless_security_parent_class)->set_secret_flags (setting, secret_name, flags, error);
}

/* NMSettingWirelessSecurity:wep-key-type is an enum, but needs to be marshalled
 * as 'u', not 'i', for backward-compatibility.
 */
static GVariant *
wep_key_type_to_dbus (const GValue *from)
{
	return g_variant_new_uint32 (g_value_get_enum (from));
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingWirelessSecurity *setting = NM_SETTING_WIRELESS_SECURITY (object);
	NMSettingWirelessSecurityPrivate *priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_KEY_MGMT:
		g_value_set_string (value, priv->key_mgmt);
		break;
	case PROP_WEP_TX_KEYIDX:
		g_value_set_uint (value, priv->wep_tx_keyidx);
		break;
	case PROP_AUTH_ALG:
		g_value_set_string (value, priv->auth_alg);
		break;
	case PROP_PROTO:
		g_value_take_boxed (value, _nm_utils_slist_to_strv (priv->proto, TRUE));
		break;
	case PROP_PAIRWISE:
		g_value_take_boxed (value, _nm_utils_slist_to_strv (priv->pairwise, TRUE));
		break;
	case PROP_GROUP:
		g_value_take_boxed (value, _nm_utils_slist_to_strv (priv->group, TRUE));
		break;
	case PROP_PMF:
		g_value_set_int (value, nm_setting_wireless_security_get_pmf (setting));
		break;
	case PROP_LEAP_USERNAME:
		g_value_set_string (value, priv->leap_username);
		break;
	case PROP_WEP_KEY0:
		g_value_set_string (value, priv->wep_key0);
		break;
	case PROP_WEP_KEY1:
		g_value_set_string (value, priv->wep_key1);
		break;
	case PROP_WEP_KEY2:
		g_value_set_string (value, priv->wep_key2);
		break;
	case PROP_WEP_KEY3:
		g_value_set_string (value, priv->wep_key3);
		break;
	case PROP_WEP_KEY_FLAGS:
		g_value_set_flags (value, priv->wep_key_flags);
		break;
	case PROP_PSK:
		g_value_set_string (value, priv->psk);
		break;
	case PROP_PSK_FLAGS:
		g_value_set_flags (value, priv->psk_flags);
		break;
	case PROP_LEAP_PASSWORD:
		g_value_set_string (value, priv->leap_password);
		break;
	case PROP_LEAP_PASSWORD_FLAGS:
		g_value_set_flags (value, priv->leap_password_flags);
		break;
	case PROP_WEP_KEY_TYPE:
		g_value_set_enum (value, priv->wep_key_type);
		break;
	case PROP_WPS_METHOD:
		g_value_set_uint (value, priv->wps_method);
		break;
	case PROP_FILS:
		g_value_set_int (value, nm_setting_wireless_security_get_fils (setting));
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
	NMSettingWirelessSecurity *setting = NM_SETTING_WIRELESS_SECURITY (object);
	NMSettingWirelessSecurityPrivate *priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	const char *str;

	switch (prop_id) {
	case PROP_KEY_MGMT:
		g_free (priv->key_mgmt);
		str = g_value_get_string (value);
		priv->key_mgmt = str ? g_ascii_strdown (str, -1) : NULL;
		break;
	case PROP_WEP_TX_KEYIDX:
		priv->wep_tx_keyidx = g_value_get_uint (value);
		break;
	case PROP_AUTH_ALG:
		g_free (priv->auth_alg);
		str = g_value_get_string (value);
		priv->auth_alg = str ? g_ascii_strdown (str, -1) : NULL;
		break;
	case PROP_PROTO:
		g_slist_free_full (priv->proto, g_free);
		priv->proto = _nm_utils_strv_to_slist (g_value_get_boxed (value), TRUE);
		break;
	case PROP_PAIRWISE:
		g_slist_free_full (priv->pairwise, g_free);
		priv->pairwise = _nm_utils_strv_to_slist (g_value_get_boxed (value), TRUE);
		break;
	case PROP_GROUP:
		g_slist_free_full (priv->group, g_free);
		priv->group = _nm_utils_strv_to_slist (g_value_get_boxed (value), TRUE);
		break;
	case PROP_PMF:
		priv->pmf = g_value_get_int (value);
		break;
	case PROP_LEAP_USERNAME:
		g_free (priv->leap_username);
		priv->leap_username = g_value_dup_string (value);
		break;
	case PROP_WEP_KEY0:
		g_free (priv->wep_key0);
		priv->wep_key0 = g_value_dup_string (value);
		break;
	case PROP_WEP_KEY1:
		g_free (priv->wep_key1);
		priv->wep_key1 = g_value_dup_string (value);
		break;
	case PROP_WEP_KEY2:
		g_free (priv->wep_key2);
		priv->wep_key2 = g_value_dup_string (value);
		break;
	case PROP_WEP_KEY3:
		g_free (priv->wep_key3);
		priv->wep_key3 = g_value_dup_string (value);
		break;
	case PROP_WEP_KEY_FLAGS:
		priv->wep_key_flags = g_value_get_flags (value);
		break;
	case PROP_PSK:
		g_free (priv->psk);
		priv->psk = g_value_dup_string (value);
		break;
	case PROP_PSK_FLAGS:
		priv->psk_flags = g_value_get_flags (value);
		break;
	case PROP_LEAP_PASSWORD:
		g_free (priv->leap_password);
		priv->leap_password = g_value_dup_string (value);
		break;
	case PROP_LEAP_PASSWORD_FLAGS:
		priv->leap_password_flags = g_value_get_flags (value);
		break;
	case PROP_WEP_KEY_TYPE:
		priv->wep_key_type = g_value_get_enum (value);
		break;
	case PROP_WPS_METHOD:
		priv->wps_method = g_value_get_uint (value);
		break;
	case PROP_FILS:
		priv->fils = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_wireless_security_init (NMSettingWirelessSecurity *setting)
{
}

/**
 * nm_setting_wireless_security_new:
 *
 * Creates a new #NMSettingWirelessSecurity object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingWirelessSecurity object
 **/
NMSetting *
nm_setting_wireless_security_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_WIRELESS_SECURITY, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingWirelessSecurity *self = NM_SETTING_WIRELESS_SECURITY (object);
	NMSettingWirelessSecurityPrivate *priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (self);

	g_free (priv->key_mgmt);
	g_free (priv->auth_alg);
	g_free (priv->leap_username);
	g_free (priv->wep_key0);
	g_free (priv->wep_key1);
	g_free (priv->wep_key2);
	g_free (priv->wep_key3);
	g_free (priv->psk);
	g_free (priv->leap_password);

	g_slist_free_full (priv->proto, g_free);
	g_slist_free_full (priv->pairwise, g_free);
	g_slist_free_full (priv->group, g_free);

	G_OBJECT_CLASS (nm_setting_wireless_security_parent_class)->finalize (object);
}

static void
nm_setting_wireless_security_class_init (NMSettingWirelessSecurityClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	g_type_class_add_private (klass, sizeof (NMSettingWirelessSecurityPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify           = verify;
	setting_class->verify_secrets   = verify_secrets;
	setting_class->need_secrets     = need_secrets;
	setting_class->get_secret_flags = get_secret_flags;
	setting_class->set_secret_flags = set_secret_flags;

	/**
	 * NMSettingWirelessSecurity:key-mgmt:
	 *
	 * Key management used for the connection.  One of "none" (WEP),
	 * "ieee8021x" (Dynamic WEP), "wpa-psk" (infrastructure WPA-PSK), "sae"
	 * (SAE) or "wpa-eap" (WPA-Enterprise).  This property must be set for
	 * any Wi-Fi connection that uses security.
	 **/
	/* ---ifcfg-rh---
	 * property: key-mgmt
	 * variable: KEY_MGMT(+)
	 * values: IEEE8021X, WPA-PSK, WPA-EAP
	 * description: Key management menthod.
	 * ---end---
	 */
	obj_properties[PROP_KEY_MGMT] =
	    g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_REQUIRED |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:wep-tx-keyidx:
	 *
	 * When static WEP is used (ie, key-mgmt = "none") and a non-default WEP key
	 * index is used by the AP, put that WEP key index here.  Valid values are 0
	 * (default key) through 3.  Note that some consumer access points (like the
	 * Linksys WRT54G) number the keys 1 - 4.
	 **/
	/* ---ifcfg-rh---
	 * property: wep-tx-keyidx
	 * variable: DEFAULTKEY
	 * values: 1, 2, 3, 4
	 * default: 1
	 * description: Index of active WEP key.
	 * ---end---
	 */
	obj_properties[PROP_WEP_TX_KEYIDX] =
	    g_param_spec_uint (NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, "", "",
	                       0, 3, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:auth-alg:
	 *
	 * When WEP is used (ie, key-mgmt = "none" or "ieee8021x") indicate the
	 * 802.11 authentication algorithm required by the AP here.  One of "open"
	 * for Open System, "shared" for Shared Key, or "leap" for Cisco LEAP.  When
	 * using Cisco LEAP (ie, key-mgmt = "ieee8021x" and auth-alg = "leap") the
	 * "leap-username" and "leap-password" properties must be specified.
	 **/
	/* ---ifcfg-rh---
	 * property: auth-alg
	 * variable: SECURITYMODE(+)
	 * values: restricted, open, leap
	 * description: Authentication algorithm for WEP.
	 * ---end---
	 */
	obj_properties[PROP_AUTH_ALG] =
	    g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:proto:
	 *
	 * List of strings specifying the allowed WPA protocol versions to use.
	 * Each element may be one "wpa" (allow WPA) or "rsn" (allow WPA2/RSN).  If
	 * not specified, both WPA and RSN connections are allowed.
	 **/
	/* ---ifcfg-rh---
	 * property: proto
	 * variable: WPA_ALLOW_WPA(+), WPA_ALLOW_WPA2(+)
	 * values: yes, no
	 * default: no
	 * description: Allowed WPA protocols, WPA and WPA2 (RSN).
	 * ---end---
	 */
	obj_properties[PROP_PROTO] =
	    g_param_spec_boxed (NM_SETTING_WIRELESS_SECURITY_PROTO, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:pairwise:
	 *
	 * A list of pairwise encryption algorithms which prevents connections to
	 * Wi-Fi networks that do not utilize one of the algorithms in the list.
	 * For maximum compatibility leave this property empty.  Each list element
	 * may be one of "tkip" or "ccmp".
	 **/
	/* ---ifcfg-rh---
	 * property: pairwise
	 * variable: CIPHER_PAIRWISE(+)
	 * values: CCMP, TKIP
	 * description: Restrict pairwise encryption algorithms, specified as a space
	 *   separated list.
	 * ---end---
	 */
	obj_properties[PROP_PAIRWISE] =
	    g_param_spec_boxed (NM_SETTING_WIRELESS_SECURITY_PAIRWISE, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:group:
	 *
	 * A list of group/broadcast encryption algorithms which prevents
	 * connections to Wi-Fi networks that do not utilize one of the algorithms
	 * in the list.  For maximum compatibility leave this property empty.  Each
	 * list element may be one of "wep40", "wep104", "tkip", or "ccmp".
	 **/
	/* ---ifcfg-rh---
	 * property: group
	 * variable: CIPHER_GROUP(+)
	 * values: CCMP, TKIP, WEP40, WEP104
	 * description: Restrict group/broadcast encryption algorithms, specified as a space
	 *   separated list.
	 * ---end---
	 */
	obj_properties[PROP_GROUP] =
	    g_param_spec_boxed (NM_SETTING_WIRELESS_SECURITY_GROUP, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:pmf:
	 *
	 * Indicates whether Protected Management Frames (802.11w) must be enabled
	 * for the connection.  One of %NM_SETTING_WIRELESS_SECURITY_PMF_DEFAULT
	 * (use global default value), %NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE
	 * (disable PMF), %NM_SETTING_WIRELESS_SECURITY_PMF_OPTIONAL (enable PMF if
	 * the supplicant and the access point support it) or
	 * %NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED (enable PMF and fail if not
	 * supported).  When set to %NM_SETTING_WIRELESS_SECURITY_PMF_DEFAULT and no
	 * global default is set, PMF will be optionally enabled.
	 *
	 * Since: 1.10
	 **/
	/* ---ifcfg-rh---
	 * property: pmf
	 * variable: PMF(+)
	 * values: default, disable, optional, required
	 * description: Enables or disables PMF (802.11w)
	 * example: PMF=required
	 * ---end---
	 */
	obj_properties[PROP_PMF] =
	    g_param_spec_int (NM_SETTING_WIRELESS_SECURITY_PMF, "", "",
	                      G_MININT32, G_MAXINT32, 0,
	                      G_PARAM_READWRITE |
	                      G_PARAM_CONSTRUCT |
	                      NM_SETTING_PARAM_FUZZY_IGNORE |
	                      G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:leap-username:
	 *
	 * The login username for legacy LEAP connections (ie, key-mgmt =
	 * "ieee8021x" and auth-alg = "leap").
	 **/
	/* ---ifcfg-rh---
	 * property: leap-username
	 * variable: IEEE_8021X_IDENTITY(+)
	 * description: Login name for LEAP.
	 * ---end---
	 */
	obj_properties[PROP_LEAP_USERNAME] =
	    g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:wep-key0:
	 *
	 * Index 0 WEP key.  This is the WEP key used in most networks.  See the
	 * "wep-key-type" property for a description of how this key is interpreted.
	 **/
	/* ---ifcfg-rh---
	 * property: wep-key0
	 * variable: KEY1, KEY_PASSPHRASE1(+)
	 * description: The first WEP key (used in most networks). See also DEFAULTKEY for key index.
	 * ---end---
	 */
	obj_properties[PROP_WEP_KEY0] =
	    g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY0, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:wep-key1:
	 *
	 * Index 1 WEP key.  This WEP index is not used by most networks.  See the
	 * "wep-key-type" property for a description of how this key is interpreted.
	 **/
	/* ---ifcfg-rh---
	 * property: wep-key1
	 * variable: KEY2, KEY_PASSPHRASE2(+)
	 * description: WEP key with index 1. See also DEFAULTKEY for key index.
	 * ---end---
	 */
	obj_properties[PROP_WEP_KEY1] =
	    g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY1, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:wep-key2:
	 *
	 * Index 2 WEP key.  This WEP index is not used by most networks.  See the
	 * "wep-key-type" property for a description of how this key is interpreted.
	 **/
	/* ---ifcfg-rh---
	 * property: wep-key2
	 * variable: KEY3, KEY_PASSPHRASE3(+)
	 * description: WEP key with index 2. See also DEFAULTKEY for key index.
	 * ---end---
	 */
	obj_properties[PROP_WEP_KEY2] =
	    g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY2, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:wep-key3:
	 *
	 * Index 3 WEP key.  This WEP index is not used by most networks.  See the
	 * "wep-key-type" property for a description of how this key is interpreted.
	 **/
	/* ---ifcfg-rh---
	 * property: wep-key3
	 * variable: KEY4, KEY_PASSPHRASE4(+)
	 * description: WEP key with index 3. See also DEFAULTKEY for key index.
	 * ---end---
	 */
	obj_properties[PROP_WEP_KEY3] =
	    g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY3, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:wep-key-flags:
	 *
	 * Flags indicating how to handle the #NMSettingWirelessSecurity:wep-key0,
	 * #NMSettingWirelessSecurity:wep-key1, #NMSettingWirelessSecurity:wep-key2,
	 * and #NMSettingWirelessSecurity:wep-key3 properties.
	 **/
	/* ---ifcfg-rh---
	 * property: wep-key-flags
	 * variable: WEP_KEY_FLAGS(+)
	 * format: NMSettingSecretFlags
	 * description: Password flags for KEY<i>, KEY_PASSPHRASE<i> password.
	 * ---end---
	 */
	obj_properties[PROP_WEP_KEY_FLAGS] =
	    g_param_spec_flags (NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:psk:
	 *
	 * Pre-Shared-Key for WPA networks. For WPA-PSK, it's either an ASCII
	 * passphrase of 8 to 63 characters that is (as specified in the 802.11i
	 * standard) hashed to derive the actual key, or the key in form of 64
	 * hexadecimal character. The WPA3-Personal networks use a passphrase
	 * of any length for SAE authentication.
	 **/
	/* ---ifcfg-rh---
	 * property: psk
	 * variable: WPA_PSK
	 * description: Pre-Shared-Key for WPA networks.
	 * ---end---
	 */
	obj_properties[PROP_PSK] =
	    g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_PSK, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:psk-flags:
	 *
	 * Flags indicating how to handle the #NMSettingWirelessSecurity:psk
	 * property.
	 **/
	/* ---ifcfg-rh---
	 * property: psk-flags
	 * variable: WPA_PSK_FLAGS(+)
	 * format: NMSettingSecretFlags
	 * description: Password flags for WPA_PSK_FLAGS.
	 * example: WPA_PSK_FLAGS=user
	 * ---end---
	 */
	obj_properties[PROP_PSK_FLAGS] =
	    g_param_spec_flags (NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:leap-password:
	 *
	 * The login password for legacy LEAP connections (ie, key-mgmt =
	 * "ieee8021x" and auth-alg = "leap").
	 **/
	/* ---ifcfg-rh---
	 * property: leap-password
	 * variable: IEEE_8021X_PASSWORD(+)
	 * description: Password for LEAP. It can also go to "key-"
	 *  lookaside file, or it can be owned by a secret agent.
	 * ---end---
	 */
	obj_properties[PROP_LEAP_PASSWORD] =
	    g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:leap-password-flags:
	 *
	 * Flags indicating how to handle the
	 * #NMSettingWirelessSecurity:leap-password property.
	 **/
	/* ---ifcfg-rh---
	 * property: leap-password-flags
	 * variable: IEEE_8021X_PASSWORD_FLAGS(+)
	 * format: NMSettingSecretFlags
	 * description: Password flags for IEEE_8021X_PASSWORD_FLAGS.
	 * ---end---
	 */
	obj_properties[PROP_LEAP_PASSWORD_FLAGS] =
	    g_param_spec_flags (NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:wep-key-type:
	 *
	 * Controls the interpretation of WEP keys.  Allowed values are
	 * %NM_WEP_KEY_TYPE_KEY, in which case the key is either a 10- or
	 * 26-character hexadecimal string, or a 5- or 13-character ASCII password;
	 * or %NM_WEP_KEY_TYPE_PASSPHRASE, in which case the passphrase is provided
	 * as a string and will be hashed using the de-facto MD5 method to derive
	 * the actual WEP key.
	 **/
	/* ---ifcfg-rh---
	 * property: wep-key-type
	 * variable: KEY<i> or KEY_PASSPHRASE<i>(+); KEY_TYPE(+)
	 * description: KEY is used for "key" type (10 or 26 hexadecimal characters,
	 *   or 5 or 13 character string prefixed with "s:"). KEY_PASSPHRASE is used
	 *   for WEP passphrases. KEY_TYPE specifies the key type and can be either
	 *   'key' or 'passphrase'. KEY_TYPE is redundant and can be omitted.
	 * example: KEY1=s:ahoj, KEY1=0a1c45bc02, KEY_PASSPHRASE1=mysupersecretkey
	 * ---end---
	 */
	obj_properties[PROP_WEP_KEY_TYPE] =
	    g_param_spec_enum (NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, "", "",
	                       NM_TYPE_WEP_KEY_TYPE,
	                       NM_WEP_KEY_TYPE_UNKNOWN,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS);

	_properties_override_add_transform (properties_override,
	                                    obj_properties[PROP_WEP_KEY_TYPE],
	                                    G_VARIANT_TYPE_UINT32,
	                                    wep_key_type_to_dbus,
	                                    NULL);
	/**
	 * NMSettingWirelessSecurity:wps-method:
	 *
	 * Flags indicating which mode of WPS is to be used if any.
	 *
	 * There's little point in changing the default setting as NetworkManager will
	 * automatically determine whether it's feasible to start WPS enrollment from
	 * the Access Point capabilities.
	 *
	 * WPS can be disabled by setting this property to a value of 1.
	 *
	 * Since: 1.10
	 **/
	/* ---ifcfg-rh---
	 * property: wps-method
	 * variable: WPS_METHOD
	 * description: Used to control the WPS methods to be used
	 *    Valid values are "default", "auto", "disabled", "pin" and "pbc".
	 *    If omitted, whatver the AP announces is used.
	 * example: WPS_METHOD=disabled, WPS_METHOD="pin pbc"
	 * ---end---
	 */
	obj_properties[PROP_WPS_METHOD] =
	    g_param_spec_uint (NM_SETTING_WIRELESS_SECURITY_WPS_METHOD, "", "",
	                       0, G_MAXUINT32, NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWirelessSecurity:fils:
	 *
	 * Indicates whether Fast Initial Link Setup (802.11ai) must be enabled for
	 * the connection.  One of %NM_SETTING_WIRELESS_SECURITY_FILS_DEFAULT (use
	 * global default value), %NM_SETTING_WIRELESS_SECURITY_FILS_DISABLE
	 * (disable FILS), %NM_SETTING_WIRELESS_SECURITY_FILS_OPTIONAL (enable FILS
	 * if the supplicant and the access point support it) or
	 * %NM_SETTING_WIRELESS_SECURITY_FILS_REQUIRED (enable FILS and fail if not
	 * supported).  When set to %NM_SETTING_WIRELESS_SECURITY_FILS_DEFAULT and
	 * no global default is set, FILS will be optionally enabled.
	 *
	 * Since: 1.12
	 **/
	/* ---ifcfg-rh---
	 * property: fils
	 * variable: FILS(+)
	 * values: default, disable, optional, required
	 * description: Enables or disables FILS (802.11ai)
	 * example: FILS=required
	 * ---end---
	 */
	obj_properties[PROP_FILS] =
	    g_param_spec_int (NM_SETTING_WIRELESS_SECURITY_FILS, "", "",
	                      G_MININT32, G_MAXINT32, 0,
	                      G_PARAM_READWRITE |
	                      G_PARAM_CONSTRUCT |
	                      NM_SETTING_PARAM_FUZZY_IGNORE |
	                      G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_WIRELESS_SECURITY,
	                               NULL, properties_override);
}
