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

#include "nm-default.h"

#include <string.h>
#include <dbus/dbus-glib.h>

#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-wireless-security
 * @short_description: Describes connection properties for Wi-Fi networks that
 * use WEP, LEAP, WPA or WPA2/RSN security
 * @include: nm-setting-wireless-security.h
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

/**
 * nm_setting_wireless_security_error_quark:
 *
 * Registers an error quark for #NMSettingWired if necessary.
 *
 * Returns: the error quark used for #NMSettingWired errors.
 **/
GQuark
nm_setting_wireless_security_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-wireless-security-error-quark");
	return quark;
}

G_DEFINE_TYPE_WITH_CODE (NMSettingWirelessSecurity, nm_setting_wireless_security, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                                               g_define_type_id,
                                               2,
                                               NM_SETTING_WIRELESS_SECURITY_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_WIRELESS_SECURITY)

#define NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_WIRELESS_SECURITY, NMSettingWirelessSecurityPrivate))

typedef struct {
	char *key_mgmt;
	char *auth_alg;
	GSList *proto; /* GSList of strings */
	GSList *pairwise; /* GSList of strings */
	GSList *group; /* GSList of strings */

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
} NMSettingWirelessSecurityPrivate;

enum {
	PROP_0,
	PROP_KEY_MGMT,
	PROP_WEP_TX_KEYIDX,
	PROP_AUTH_ALG,
	PROP_PROTO,
	PROP_PAIRWISE,
	PROP_GROUP,
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

	LAST_PROP
};

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
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_PROTO);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_PROTO);
}

/**
 * nm_setting_wireless_security_remove_proto_by_value:
 * @setting: the #NMSettingWirelessSecurity
 * @proto: the protocol to remove, one of "wpa" or "rsn"
 *
 * Removes a protocol from the allowed protocol list.
 *
 * Returns: %TRUE if the protocol was found and removed; %FALSE if it was not.
 *
 * Since: 0.9.10
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
			g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_PROTO);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_PROTO);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
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
 *
 * Since: 0.9.10
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
			g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_GROUP);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_GROUP);
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
 *
 * Since: 0.9.10
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
			g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_GROUP);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_GROUP);
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
		g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);
		break;
	case 1:
		g_free (priv->wep_key1);
		priv->wep_key1 = g_strdup (key);
		g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_WEP_KEY1);
		break;
	case 2:
		g_free (priv->wep_key2);
		priv->wep_key2 = g_strdup (key);
		g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_WEP_KEY2);
		break;
	case 3:
		g_free (priv->wep_key3);
		priv->wep_key3 = g_strdup (key);
		g_object_notify (G_OBJECT (setting), NM_SETTING_WIRELESS_SECURITY_WEP_KEY3);
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

	/* WPA-PSK infrastructure and adhoc */
	if (   (strcmp (priv->key_mgmt, "wpa-none") == 0)
	    || (strcmp (priv->key_mgmt, "wpa-psk") == 0)) {
		if (!nm_utils_wpa_psk_valid (priv->psk)) {
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
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingWirelessSecurity *self = NM_SETTING_WIRELESS_SECURITY (setting);
	NMSettingWirelessSecurityPrivate *priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (self);
	const char *valid_key_mgmt[] = { "none", "ieee8021x", "wpa-none", "wpa-psk", "wpa-eap", NULL };
	const char *valid_auth_algs[] = { "open", "shared", "leap", NULL };
	const char *valid_protos[] = { "wpa", "rsn", NULL };
	const char *valid_pairwise[] = { "tkip", "ccmp", NULL };
	const char *valid_groups[] = { "wep40", "wep104", "tkip", "ccmp", NULL };

	if (!priv->key_mgmt) {
		g_set_error_literal (error,
		                     NM_SETTING_WIRELESS_SECURITY_ERROR,
		                     NM_SETTING_WIRELESS_SECURITY_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
		return FALSE;
	}

	if (!g_strv_contains (valid_key_mgmt, priv->key_mgmt)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->key_mgmt);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
		return FALSE;
	}

	if (priv->auth_alg && !strcmp (priv->auth_alg, "leap")) {
		/* LEAP must use ieee8021x key management */
		if (strcmp (priv->key_mgmt, "ieee8021x")) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_SECURITY_ERROR,
			             NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_802_1X,
			             _("'%s' security requires '%s=%s'"),
			             "leap", NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x");
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
			return FALSE;
		}
		if (!priv->leap_username) {
			g_set_error_literal (error,
			                     NM_SETTING_WIRELESS_SECURITY_ERROR,
			                     NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_USERNAME,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
			return FALSE;
		}
	} else {
		if (   (strcmp (priv->key_mgmt, "ieee8021x") == 0)
		    || (strcmp (priv->key_mgmt, "wpa-eap") == 0)) {
			/* Need an 802.1x setting too */
			if (!nm_setting_find_in_list (all_settings, NM_SETTING_802_1X_SETTING_NAME)) {
				g_set_error (error,
				             NM_SETTING_WIRELESS_SECURITY_ERROR,
				             NM_SETTING_WIRELESS_SECURITY_ERROR_MISSING_802_1X_SETTING,
				             _("'%s' security requires '%s' setting presence"),
				             priv->key_mgmt, NM_SETTING_802_1X_SETTING_NAME);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
				return FALSE;
			}
		}
	}

	if (priv->leap_username && !strlen (priv->leap_username)) {
		g_set_error_literal (error,
		                     NM_SETTING_WIRELESS_SECURITY_ERROR,
		                     NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
		return FALSE;
	}

	if (priv->wep_tx_keyidx > 3) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             _("'%d' value is out of range <0-3>"),
		             priv->wep_tx_keyidx);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX);
		return FALSE;
	}

	if (priv->wep_key_type > NM_WEP_KEY_TYPE_LAST) {
		g_set_error_literal (error,
		                     NM_SETTING_WIRELESS_SECURITY_ERROR,
		                     NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE);
		return FALSE;
	}

	if (priv->auth_alg && !g_strv_contains (valid_auth_algs, priv->auth_alg)) {
		g_set_error_literal (error,
		                     NM_SETTING_WIRELESS_SECURITY_ERROR,
		                     NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
		return FALSE;
	}

	if (priv->proto && !_nm_utils_string_slist_validate (priv->proto, valid_protos)) {
		g_set_error_literal (error,
		                     NM_SETTING_WIRELESS_SECURITY_ERROR,
		                     NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_PROTO);
		return FALSE;
	}

	if (priv->pairwise) {
		const char *wpa_none[] = { "wpa-none", NULL };

		/* For ad-hoc connections, pairwise must be "none" */
		if (g_strv_contains (wpa_none, priv->key_mgmt)) {
			GSList *iter;
			gboolean found = FALSE;

			for (iter = priv->pairwise; iter; iter = g_slist_next (iter)) {
				if (!strcmp ((char *) iter->data, "none")) {
					found = TRUE;
					break;
				}
			}

			/* pairwise cipher list didn't contain "none", which is invalid
			 * for WPA adhoc connections.
			 */
			if (!found) {
				g_set_error (error,
				             NM_SETTING_WIRELESS_SECURITY_ERROR,
				             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
				             _("'%s' connections require '%s' in this property"),
				             NM_SETTING_WIRELESS_MODE_ADHOC, "none");
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
				return FALSE;
			}
		} else if (!_nm_utils_string_slist_validate (priv->pairwise, valid_pairwise)) {
			g_set_error_literal (error,
			                     NM_SETTING_WIRELESS_SECURITY_ERROR,
			                     NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
			                     _("property is invalid"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
			return FALSE;
		}
	}

	if (priv->group && !_nm_utils_string_slist_validate (priv->group, valid_groups)) {
		g_set_error_literal (error,
		                     NM_SETTING_WIRELESS_SECURITY_ERROR,
		                     NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_GROUP);
		return FALSE;
	}

	/* Shared Key auth can only be used with WEP */
	if (priv->auth_alg && !strcmp (priv->auth_alg, "shared")) {
		if (priv->key_mgmt && strcmp (priv->key_mgmt, "none")) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_SECURITY_ERROR,
			             NM_SETTING_WIRELESS_SECURITY_ERROR_SHARED_KEY_REQUIRES_WEP,
			             _("'%s' can only be used with '%s=%s' (WEP)"),
			             "shared", NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none");
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
get_secret_flags (NMSetting *setting,
                  const char *secret_name,
                  gboolean verify_secret,
                  NMSettingSecretFlags *out_flags,
                  GError **error)
{
	NMSettingClass *setting_class;
	gboolean verify_override = verify_secret;

	/* There's only one 'flags' property for WEP keys, so alias all the WEP key
	 * property names to that flags property.
	 */
	if (   !g_strcmp0 (secret_name, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0)
	    || !g_strcmp0 (secret_name, NM_SETTING_WIRELESS_SECURITY_WEP_KEY1)
	    || !g_strcmp0 (secret_name, NM_SETTING_WIRELESS_SECURITY_WEP_KEY2)
	    || !g_strcmp0 (secret_name, NM_SETTING_WIRELESS_SECURITY_WEP_KEY3)) {
		secret_name = "wep-key";
		verify_override = FALSE; /* Already know it's a secret */
	}

	/* Chain up to superclass with modified key name */
	setting_class = NM_SETTING_CLASS (nm_setting_wireless_security_parent_class);
	return setting_class->get_secret_flags (setting, secret_name, verify_override, out_flags, error);
}

static gboolean
set_secret_flags (NMSetting *setting,
                  const char *secret_name,
                  gboolean verify_secret,
                  NMSettingSecretFlags flags,
                  GError **error)
{
	NMSettingClass *setting_class;
	gboolean verify_override = verify_secret;

	/* There's only one 'flags' property for WEP keys, so alias all the WEP key
	 * property names to that flags property.
	 */
	if (   !g_strcmp0 (secret_name, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0)
	    || !g_strcmp0 (secret_name, NM_SETTING_WIRELESS_SECURITY_WEP_KEY1)
	    || !g_strcmp0 (secret_name, NM_SETTING_WIRELESS_SECURITY_WEP_KEY2)
	    || !g_strcmp0 (secret_name, NM_SETTING_WIRELESS_SECURITY_WEP_KEY3)) {
		secret_name = "wep-key";
		verify_override = FALSE; /* Already know it's a secret */
	}

	/* Chain up to superclass with modified key name */
	setting_class = NM_SETTING_CLASS (nm_setting_wireless_security_parent_class);
	return setting_class->set_secret_flags (setting, secret_name, verify_override, flags, error);
}

static void
nm_setting_wireless_security_init (NMSettingWirelessSecurity *setting)
{
}

static void
finalize (GObject *object)
{
	NMSettingWirelessSecurity *self = NM_SETTING_WIRELESS_SECURITY (object);
	NMSettingWirelessSecurityPrivate *priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (self);

	/* Strings first. g_free() already checks for NULLs so we don't have to */

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
		priv->proto = g_value_dup_boxed (value);
		break;
	case PROP_PAIRWISE:
		g_slist_free_full (priv->pairwise, g_free);
		priv->pairwise = g_value_dup_boxed (value);
		break;
	case PROP_GROUP:
		g_slist_free_full (priv->group, g_free);
		priv->group = g_value_dup_boxed (value);
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
		priv->wep_key_flags = g_value_get_uint (value);
		break;
	case PROP_PSK:
		g_free (priv->psk);
		priv->psk = g_value_dup_string (value);
		break;
	case PROP_PSK_FLAGS:
		priv->psk_flags = g_value_get_uint (value);
		break;
	case PROP_LEAP_PASSWORD:
		g_free (priv->leap_password);
		priv->leap_password = g_value_dup_string (value);
		break;
	case PROP_LEAP_PASSWORD_FLAGS:
		priv->leap_password_flags = g_value_get_uint (value);
		break;
	case PROP_WEP_KEY_TYPE:
		priv->wep_key_type = g_value_get_uint (value);
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
		g_value_set_boxed (value, priv->proto);
		break;
	case PROP_PAIRWISE:
		g_value_set_boxed (value, priv->pairwise);
		break;
	case PROP_GROUP:
		g_value_set_boxed (value, priv->group);
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
		g_value_set_uint (value, priv->wep_key_flags);
		break;
	case PROP_PSK:
		g_value_set_string (value, priv->psk);
		break;
	case PROP_PSK_FLAGS:
		g_value_set_uint (value, priv->psk_flags);
		break;
	case PROP_LEAP_PASSWORD:
		g_value_set_string (value, priv->leap_password);
		break;
	case PROP_LEAP_PASSWORD_FLAGS:
		g_value_set_uint (value, priv->leap_password_flags);
		break;
	case PROP_WEP_KEY_TYPE:
		g_value_set_uint (value, priv->wep_key_type);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_wireless_security_class_init (NMSettingWirelessSecurityClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingWirelessSecurityPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	parent_class->verify           = verify;
	parent_class->need_secrets     = need_secrets;
	parent_class->get_secret_flags = get_secret_flags;
	parent_class->set_secret_flags = set_secret_flags;

	/* Properties */
	/**
	 * NMSettingWirelessSecurity:key-mgmt:
	 *
	 * Key management used for the connection.  One of "none" (WEP), "ieee8021x"
	 * (Dynamic WEP), "wpa-none" (Ad-Hoc WPA-PSK), "wpa-psk" (infrastructure
	 * WPA-PSK), or "wpa-eap" (WPA-Enterprise).  This property must be set for
	 * any Wi-Fi connection that uses security.
	 **/
	g_object_class_install_property
		(object_class, PROP_KEY_MGMT,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_REQUIRED |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:wep-tx-keyidx:
	 *
	 * When static WEP is used (ie, key-mgmt = "none") and a non-default WEP key
	 * index is used by the AP, put that WEP key index here.  Valid values are 0
	 * (default key) through 3.  Note that some consumer access points (like the
	 * Linksys WRT54G) number the keys 1 - 4.
	 **/
	g_object_class_install_property
		(object_class, PROP_WEP_TX_KEYIDX,
		 g_param_spec_uint (NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, "", "",
		                    0, 3, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:auth-alg:
	 *
	 * When WEP is used (ie, key-mgmt = "none" or "ieee8021x") indicate the
	 * 802.11 authentication algorithm required by the AP here.  One of "open"
	 * for Open System, "shared" for Shared Key, or "leap" for Cisco LEAP.  When
	 * using Cisco LEAP (ie, key-mgmt = "ieee8021x" and auth-alg = "leap") the
	 * "leap-username" and "leap-password" properties must be specified.
	 **/
	g_object_class_install_property
		(object_class, PROP_AUTH_ALG,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:proto:
	 *
	 * List of strings specifying the allowed WPA protocol versions to use.
	 * Each element may be one "wpa" (allow WPA) or "rsn" (allow WPA2/RSN).  If
	 * not specified, both WPA and RSN connections are allowed.
	 **/
	g_object_class_install_property
		(object_class, PROP_PROTO,
		 _nm_param_spec_specialized (NM_SETTING_WIRELESS_SECURITY_PROTO, "", "",
		                             DBUS_TYPE_G_LIST_OF_STRING,
		                             G_PARAM_READWRITE |
		                             G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:pairwise:
	 *
	 * A list of pairwise encryption algorithms which prevents connections to
	 * Wi-Fi networks that do not utilize one of the algorithms in the list.
	 * For maximum compatibility leave this property empty.  Each list element
	 * may be one of "tkip" or "ccmp".
	 **/
	g_object_class_install_property
		(object_class, PROP_PAIRWISE,
		 _nm_param_spec_specialized (NM_SETTING_WIRELESS_SECURITY_PAIRWISE, "", "",
		                             DBUS_TYPE_G_LIST_OF_STRING,
		                             G_PARAM_READWRITE |
		                             G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:group:
	 *
	 * A list of group/broadcast encryption algorithms which prevents
	 * connections to Wi-Fi networks that do not utilize one of the algorithms
	 * in the list.  For maximum compatibility leave this property empty.  Each
	 * list element may be one of "wep40", "wep104", "tkip", or "ccmp".
	 **/
	g_object_class_install_property
		(object_class, PROP_GROUP,
		 _nm_param_spec_specialized (NM_SETTING_WIRELESS_SECURITY_GROUP, "", "",
		                             DBUS_TYPE_G_LIST_OF_STRING,
		                             G_PARAM_READWRITE |
		                             G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:leap-username:
	 *
	 * The login username for legacy LEAP connections (ie, key-mgmt =
	 * "ieee8021x" and auth-alg = "leap").
	 **/
	g_object_class_install_property
		(object_class, PROP_LEAP_USERNAME,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:wep-key0:
	 *
	 * Index 0 WEP key.  This is the WEP key used in most networks.  See the
	 * "wep-key-type" property for a description of how this key is interpreted.
	 **/
	g_object_class_install_property
		(object_class, PROP_WEP_KEY0,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY0, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_SECRET |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:wep-key1:
	 *
	 * Index 1 WEP key.  This WEP index is not used by most networks.  See the
	 * "wep-key-type" property for a description of how this key is interpreted.
	 **/
	g_object_class_install_property
		(object_class, PROP_WEP_KEY1,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY1, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_SECRET |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:wep-key2:
	 *
	 * Index 2 WEP key.  This WEP index is not used by most networks.  See the
	 * "wep-key-type" property for a description of how this key is interpreted.
	 **/
	g_object_class_install_property
		(object_class, PROP_WEP_KEY2,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY2, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_SECRET |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:wep-key3:
	 *
	 * Index 3 WEP key.  This WEP index is not used by most networks.  See the
	 * "wep-key-type" property for a description of how this key is interpreted.
	 **/
	g_object_class_install_property
		(object_class, PROP_WEP_KEY3,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY3, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_SECRET |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:wep-key-flags:
	 *
	 * Flags indicating how to handle the #NMSettingWirelessSecurity:wep-key0,
	 * #NMSettingWirelessSecurity:wep-key1, #NMSettingWirelessSecurity:wep-key2,
	 * and #NMSettingWirelessSecurity:wep-key3 properties.
	 **/
	g_object_class_install_property
		(object_class, PROP_WEP_KEY_FLAGS,
		 g_param_spec_uint (NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS, "", "",
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    NM_SETTING_SECRET_FLAGS_ALL,
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:psk:
	 *
	 * Pre-Shared-Key for WPA networks.  If the key is 64-characters long, it
	 * must contain only hexadecimal characters and is interpreted as a
	 * hexadecimal WPA key.  Otherwise, the key must be between 8 and 63 ASCII
	 * characters (as specified in the 802.11i standard) and is interpreted as a
	 * WPA passphrase, and is hashed to derive the actual WPA-PSK used when
	 * connecting to the Wi-Fi network.
	 **/
	g_object_class_install_property
		(object_class, PROP_PSK,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_PSK, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_SECRET |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:psk-flags:
	 *
	 * Flags indicating how to handle the #NMSettingWirelessSecurity:psk
	 * property.
	 **/
	g_object_class_install_property
		(object_class, PROP_PSK_FLAGS,
		 g_param_spec_uint (NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS, "", "",
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    NM_SETTING_SECRET_FLAGS_ALL,
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:leap-password:
	 *
	 * The login password for legacy LEAP connections (ie, key-mgmt =
	 * "ieee8021x" and auth-alg = "leap").
	 **/
	g_object_class_install_property
		(object_class, PROP_LEAP_PASSWORD,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_SECRET |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWirelessSecurity:leap-password-flags:
	 *
	 * Flags indicating how to handle the
	 * #NMSettingWirelessSecurity:leap-password property.
	 **/
	g_object_class_install_property
		(object_class, PROP_LEAP_PASSWORD_FLAGS,
		 g_param_spec_uint (NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS, "", "",
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    NM_SETTING_SECRET_FLAGS_ALL,
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_WEP_KEY_TYPE,
		 g_param_spec_uint (NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, "", "",
		                    NM_WEP_KEY_TYPE_UNKNOWN,
		                    NM_WEP_KEY_TYPE_LAST,
		                    NM_WEP_KEY_TYPE_UNKNOWN,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    G_PARAM_STATIC_STRINGS));
}
