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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <ctype.h>
#include <dbus/dbus-glib.h>
#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"
#include "nm-utils-private.h"

GQuark
nm_setting_wireless_security_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-wireless-security-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_wireless_security_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_WIRELESS_SECURITY_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_WIRELESS_SECURITY_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The required 802.1x setting is missing */
			ENUM_ENTRY (NM_SETTING_WIRELESS_SECURITY_ERROR_MISSING_802_1X_SETTING, "Missing8021xSetting"),
			/* The LEAP authentication algorithm requires use of 802.1x key management. */
			ENUM_ENTRY (NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_802_1X, "LEAPRequires8021x"),
			/* The LEAP authentication algorithm requires a username. */
			ENUM_ENTRY (NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_USERNAME, "LEAPRequiresUsername"),
			/* Shared Key authentication can only be used with WEP encryption. */
			ENUM_ENTRY (NM_SETTING_WIRELESS_SECURITY_ERROR_SHARED_KEY_REQUIRES_WEP, "SharedKeyRequiresWEP"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingWirelessSecurityError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingWirelessSecurity, nm_setting_wireless_security, NM_TYPE_SETTING)

#define NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_WIRELESS_SECURITY, NMSettingWirelessSecurityPrivate))

typedef struct {
	char *key_mgmt;
	guint32 wep_tx_keyidx;
	char *auth_alg;
	GSList *proto; /* GSList of strings */
	GSList *pairwise; /* GSList of strings */
	GSList *group; /* GSList of strings */
	char *leap_username;
	char *wep_key0;
	char *wep_key1;
	char *wep_key2;
	char *wep_key3;
	char *psk;
	char *leap_password;
	NMWepKeyType wep_key_type;
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
	PROP_PSK,
	PROP_LEAP_PASSWORD,
	PROP_WEP_KEY_TYPE,

	LAST_PROP
};

NMSetting *
nm_setting_wireless_security_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_WIRELESS_SECURITY, NULL);
}

const char *
nm_setting_wireless_security_get_key_mgmt (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->key_mgmt;
}

guint32
nm_setting_wireless_security_get_num_protos (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), 0);

	return g_slist_length (NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->proto);
}

const char *
nm_setting_wireless_security_get_proto (NMSettingWirelessSecurity *setting, guint32 i)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->proto), NULL);

	return (const char *) g_slist_nth_data (priv->proto, i);
}

gboolean
nm_setting_wireless_security_add_proto (NMSettingWirelessSecurity *setting, const char *proto)
{
	NMSettingWirelessSecurityPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), FALSE);
	g_return_val_if_fail (proto != NULL, FALSE);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	for (iter = priv->proto; iter; iter = g_slist_next (iter)) {
		if (!strcmp (proto, (char *) iter->data))
			return FALSE;
	}

	priv->proto = g_slist_append (priv->proto, g_ascii_strdown (proto, -1));
	return TRUE;
}

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
}

void
nm_setting_wireless_security_clear_protos (NMSettingWirelessSecurity *setting)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting));

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	nm_utils_slist_free (priv->proto, g_free);
	priv->proto = NULL;
}

guint32
nm_setting_wireless_security_get_num_pairwise (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), 0);

	return g_slist_length (NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->pairwise);
}

const char *
nm_setting_wireless_security_get_pairwise (NMSettingWirelessSecurity *setting, guint32 i)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->pairwise), NULL);

	return (const char *) g_slist_nth_data (priv->pairwise, i);
}

gboolean
nm_setting_wireless_security_add_pairwise (NMSettingWirelessSecurity *setting, const char *pairwise)
{
	NMSettingWirelessSecurityPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), FALSE);
	g_return_val_if_fail (pairwise != NULL, FALSE);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	for (iter = priv->pairwise; iter; iter = g_slist_next (iter)) {
		if (!strcmp (pairwise, (char *) iter->data))
			return FALSE;
	}

	priv->pairwise = g_slist_append (priv->pairwise, g_ascii_strdown (pairwise, -1));
	return TRUE;
}

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
}

void
nm_setting_wireless_security_clear_pairwise (NMSettingWirelessSecurity *setting)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting));

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	nm_utils_slist_free (priv->pairwise, g_free);
	priv->pairwise = NULL;
}

guint32
nm_setting_wireless_security_get_num_groups (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), 0);

	return g_slist_length (NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->group);
}

const char *
nm_setting_wireless_security_get_group (NMSettingWirelessSecurity *setting, guint32 i)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->group), NULL);

	return (const char *) g_slist_nth_data (priv->group, i);
}

gboolean
nm_setting_wireless_security_add_group (NMSettingWirelessSecurity *setting, const char *group)
{
	NMSettingWirelessSecurityPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), FALSE);
	g_return_val_if_fail (group != NULL, FALSE);

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	for (iter = priv->group; iter; iter = g_slist_next (iter)) {
		if (!strcmp (group, (char *) iter->data))
			return FALSE;
	}

	priv->group = g_slist_append (priv->group, g_ascii_strdown (group, -1));
	return TRUE;
}

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
}

void
nm_setting_wireless_security_clear_groups (NMSettingWirelessSecurity *setting)
{
	NMSettingWirelessSecurityPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting));

	priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting);
	nm_utils_slist_free (priv->group, g_free);
	priv->group = NULL;
}

const char *
nm_setting_wireless_security_get_psk (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->psk;
}

const char *
nm_setting_wireless_security_get_leap_username (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->leap_username;
}

const char *
nm_setting_wireless_security_get_leap_password (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->leap_password;
}

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
		break;
	case 1:
		g_free (priv->wep_key1);
		priv->wep_key1 = g_strdup (key);
		break;
	case 2:
		g_free (priv->wep_key2);
		priv->wep_key2 = g_strdup (key);
		break;
	case 3:
		g_free (priv->wep_key3);
		priv->wep_key3 = g_strdup (key);
		break;
	default:
		g_assert_not_reached ();
	}
}

guint32
nm_setting_wireless_security_get_wep_tx_keyidx (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), 0);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->wep_tx_keyidx;
}

const char *
nm_setting_wireless_security_get_auth_alg (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), NULL);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->auth_alg;
}

NMWepKeyType
nm_setting_wireless_security_get_wep_key_type (NMSettingWirelessSecurity *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), 0);

	return NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (setting)->wep_key_type;
}

static gboolean
verify_wep_key (const char *key, NMWepKeyType wep_type)
{
	int keylen, i;

	if (!key)
		return FALSE;

	keylen = strlen (key);
	if (wep_type == NM_WEP_KEY_TYPE_KEY || NM_WEP_KEY_TYPE_UNKNOWN) {
		if (keylen == 10 || keylen == 26) {
			/* Hex key */
			for (i = 0; i < keylen; i++) {
				if (!isxdigit (key[i]))
					return FALSE;
			}
		} else if (keylen == 5 || keylen == 13) {
			/* ASCII key */
			for (i = 0; i < keylen; i++) {
				if (!isascii (key[i]))
					return FALSE;
			}
		} else
			return FALSE;

	} else if (wep_type == NM_WEP_KEY_TYPE_PASSPHRASE) {
		if (!keylen || keylen > 64)
			return FALSE;
	}

	return TRUE;
}

static gboolean
verify_wpa_psk (const char *psk)
{
	int psklen, i;

	if (!psk)
		return FALSE;

	psklen = strlen (psk);
	if (psklen < 8 || psklen > 64)
		return FALSE;

	if (psklen == 64) {
		/* Hex PSK */
		for (i = 0; i < psklen; i++) {
			if (!isxdigit (psk[i]))
				return FALSE;
		}
	}

	return TRUE;
}


static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSettingWirelessSecurity *self = NM_SETTING_WIRELESS_SECURITY (setting);
	NMSettingWirelessSecurityPrivate *priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (self);
	GPtrArray *secrets;

	secrets = g_ptr_array_sized_new (4);
	if (!secrets) {
		g_warning ("Not enough memory to create required secrets array.");
		return NULL;
	}

	g_assert (priv->key_mgmt);

	/* Static WEP */
	if (strcmp (priv->key_mgmt, "none") == 0) {
		if ((priv->wep_tx_keyidx == 0) && !verify_wep_key (priv->wep_key0, priv->wep_key_type)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);
			return secrets;
		}
		if ((priv->wep_tx_keyidx == 1) && !verify_wep_key (priv->wep_key1, priv->wep_key_type)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_WEP_KEY1);
			return secrets;
		}
		if ((priv->wep_tx_keyidx == 2) && !verify_wep_key (priv->wep_key2, priv->wep_key_type)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_WEP_KEY2);
			return secrets;
		}
		if ((priv->wep_tx_keyidx == 3) && !verify_wep_key (priv->wep_key3, priv->wep_key_type)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_WEP_KEY3);
			return secrets;
		}
		goto no_secrets;
	}

	/* WPA-PSK infrastructure and adhoc */
	if (   (strcmp (priv->key_mgmt, "wpa-none") == 0)
	    || (strcmp (priv->key_mgmt, "wpa-psk") == 0)) {
		if (!verify_wpa_psk (priv->psk)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_PSK);
			return secrets;
		}
		goto no_secrets;
	}

	/* LEAP */
	if (   priv->auth_alg
	    && !strcmp (priv->auth_alg, "leap")
	    && !strcmp (priv->key_mgmt, "ieee8021x")) {
		if (!priv->leap_password || !strlen (priv->leap_password)) {
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

static gint
find_setting_by_name (gconstpointer a, gconstpointer b)
{
	NMSetting *setting = NM_SETTING (a);
	const char *str = (const char *) b;

	return strcmp (nm_setting_get_name (setting), str);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingWirelessSecurity *self = NM_SETTING_WIRELESS_SECURITY (setting);
	NMSettingWirelessSecurityPrivate *priv = NM_SETTING_WIRELESS_SECURITY_GET_PRIVATE (self);
	const char *valid_key_mgmt[] = { "none", "ieee8021x", "wpa-none", "wpa-psk", "wpa-eap", NULL };
	const char *valid_auth_algs[] = { "open", "shared", "leap", NULL };
	const char *valid_protos[] = { "wpa", "rsn", NULL };
	const char *valid_pairwise[] = { "wep40", "wep104", "tkip", "ccmp", NULL };
	const char *valid_groups[] = { "wep40", "wep104", "tkip", "ccmp", NULL };

	if (!priv->key_mgmt) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_MISSING_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
		return FALSE;
	}

	if (!_nm_utils_string_in_list (priv->key_mgmt, valid_key_mgmt)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
		return FALSE;
	}

	if (priv->auth_alg && !strcmp (priv->auth_alg, "leap")) {
		/* LEAP must use ieee8021x key management */
		if (strcmp (priv->key_mgmt, "ieee8021x")) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_SECURITY_ERROR,
			             NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_802_1X,
			             NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
			return FALSE;
		}
		if (!priv->leap_username) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_SECURITY_ERROR,
			             NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_USERNAME,
			             NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
			return FALSE;
		}
		if (priv->leap_password && !strlen (priv->leap_password)) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_SECURITY_ERROR,
			             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
			             NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD);
			return FALSE;
		}
	} else {
		if (   (strcmp (priv->key_mgmt, "ieee8021x") == 0)
		    || (strcmp (priv->key_mgmt, "wpa-eap") == 0)) {
			/* Need an 802.1x setting too */
			if (!g_slist_find_custom (all_settings, NM_SETTING_802_1X_SETTING_NAME, find_setting_by_name)) {
				g_set_error (error,
				             NM_SETTING_WIRELESS_SECURITY_ERROR,
				             NM_SETTING_WIRELESS_SECURITY_ERROR_MISSING_802_1X_SETTING,
				             NULL);
				return FALSE;
			}
		}
	}

	if (priv->leap_username && !strlen (priv->leap_username)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
		return FALSE;
	}

	if (priv->wep_tx_keyidx > 3) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX);
		return FALSE;
	}

	if (priv->wep_key_type > NM_WEP_KEY_TYPE_LAST) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE);
		return FALSE;
	}

	if (priv->wep_key0 && !verify_wep_key (priv->wep_key0, priv->wep_key_type)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);
		return FALSE;
	}
	if (priv->wep_key1 && !verify_wep_key (priv->wep_key1, priv->wep_key_type)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_WEP_KEY1);
		return FALSE;
	}
	if (priv->wep_key2 && !verify_wep_key (priv->wep_key2, priv->wep_key_type)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_WEP_KEY2);
		return FALSE;
	}
	if (priv->wep_key3 && !verify_wep_key (priv->wep_key3, priv->wep_key_type)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_WEP_KEY3);
		return FALSE;
	}

	if (priv->auth_alg && !_nm_utils_string_in_list (priv->auth_alg, valid_auth_algs)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
		return FALSE;
	}

	if (priv->psk && !verify_wpa_psk (priv->psk)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_PSK);
		return FALSE;
	}

	if (priv->proto && !_nm_utils_string_slist_validate (priv->proto, valid_protos)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_PROTO);
		return FALSE;
	}

	if (priv->pairwise) {
		const char *wpa_none[] = { "wpa-none", NULL };

		/* For ad-hoc connections, pairwise must be "none" */
		if (_nm_utils_string_in_list (priv->key_mgmt, wpa_none)) {
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
				             NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
				return FALSE;
			}
		} else if (!_nm_utils_string_slist_validate (priv->pairwise, valid_pairwise)) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_SECURITY_ERROR,
			             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
			             NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
			return FALSE;
		}
	}

	if (priv->group && !_nm_utils_string_slist_validate (priv->group, valid_groups)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_GROUP);
		return FALSE;
	}

	/* Shared Key auth can only be used with WEP */
	if (priv->auth_alg && !strcmp (priv->auth_alg, "shared")) {
		if (priv->key_mgmt && strcmp (priv->key_mgmt, "none")) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_SECURITY_ERROR,
			             NM_SETTING_WIRELESS_SECURITY_ERROR_SHARED_KEY_REQUIRES_WEP,
			             NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
			return FALSE;
		}
	}

	return TRUE;
}

static void
nm_setting_wireless_security_init (NMSettingWirelessSecurity *setting)
{
	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NULL);
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

	nm_utils_slist_free (priv->proto, g_free);
	nm_utils_slist_free (priv->pairwise, g_free);
	nm_utils_slist_free (priv->group, g_free);

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
		nm_utils_slist_free (priv->proto, g_free);
		priv->proto = g_value_dup_boxed (value);
		break;
	case PROP_PAIRWISE:
		nm_utils_slist_free (priv->pairwise, g_free);
		priv->pairwise = g_value_dup_boxed (value);
		break;
	case PROP_GROUP:
		nm_utils_slist_free (priv->group, g_free);
		priv->group = g_value_dup_boxed (value);
		break;
	case PROP_LEAP_USERNAME:
		g_free (priv->leap_username);
		priv->leap_username = g_value_dup_string (value);
		break;
	case PROP_WEP_KEY0:
		nm_setting_wireless_security_set_wep_key (setting, 0, g_value_get_string (value));
		break;
	case PROP_WEP_KEY1:
		nm_setting_wireless_security_set_wep_key (setting, 1, g_value_get_string (value));
		break;
	case PROP_WEP_KEY2:
		nm_setting_wireless_security_set_wep_key (setting, 2, g_value_get_string (value));
		break;
	case PROP_WEP_KEY3:
		nm_setting_wireless_security_set_wep_key (setting, 3, g_value_get_string (value));
		break;
	case PROP_PSK:
		g_free (priv->psk);
		priv->psk = g_value_dup_string (value);
		break;
	case PROP_LEAP_PASSWORD:
		g_free (priv->leap_password);
		priv->leap_password = g_value_dup_string (value);
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
	case PROP_PSK:
		g_value_set_string (value, priv->psk);
		break;
	case PROP_LEAP_PASSWORD:
		g_value_set_string (value, priv->leap_password);
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

	parent_class->verify         = verify;
	parent_class->need_secrets   = need_secrets;

	/* Properties */
	/**
	 * NMSettingWirelessSecurity:key-mgmt:
	 *
	 * Key management used for the connection.  One of 'none' (WEP), 'ieee8021x'
	 * (Dynamic WEP), 'wpa-none' (Ad-Hoc WPA-PSK), 'wpa-psk' (infrastructure
	 * WPA-PSK), or 'wpa-eap' (WPA-Enterprise).  This property must be set for
	 * any WiFi connection that uses security.
	 **/
	g_object_class_install_property
		(object_class, PROP_KEY_MGMT,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
						  "Key management",
						  "Key management used for the connection.  One of "
						  "'none' (WEP), 'ieee8021x' (Dynamic WEP), 'wpa-none' "
						  "(WPA-PSK Ad-Hoc), 'wpa-psk' (infrastructure WPA-PSK), "
						  "or 'wpa-eap' (WPA-Enterprise).  This property must "
						  "be set for any WiFi connection that uses security.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_REQUIRED));

	/**
	 * NMSettingWirelessSecurity:wep-tx-keyidx:
	 *
	 * When static WEP is used (ie, key-mgmt = 'none') and a non-default WEP key
	 * index is used by the AP, put that WEP key index here.  Valid values are 0
	 * (default key) through 3.  Note that some consumer access points (like the
	 * Linksys WRT54G) number the keys 1 - 4.
	 **/
	g_object_class_install_property
		(object_class, PROP_WEP_TX_KEYIDX,
		 g_param_spec_uint (NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX,
						"WEP TX key index",
						"When static WEP is used (ie, key-mgmt = 'none') and a "
						"non-default WEP key index is used by the AP, put that "
						"WEP key index here.  Valid values are 0 (default key) "
						"through 3.  Note that some consumer access points "
						"(like the Linksys WRT54G) number the keys 1 - 4.",
						0, 3, 0,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWirelessSecurity:auth-alg:
	 *
	 * When WEP is used (ie, key-mgmt = 'none' or 'ieee8021x') indicate the
	 * 802.11 authentication algorithm required by the AP here.  One of 'open'
	 * for Open System, 'shared' for Shared Key, or 'leap' for Cisco LEAP.
	 * When using Cisco LEAP (ie, key-mgmt = 'ieee8021x' and auth-alg = 'leap')
	 * the 'leap-username' and 'leap-password' properties must be specified.
	 **/
	g_object_class_install_property
		(object_class, PROP_AUTH_ALG,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
						  "AuthAlg",
						  "When WEP is used (ie, key-mgmt = 'none' or "
						  "'ieee8021x') indicate the 802.11 authentication "
						  "algorithm required by the AP here.  One of 'open' for "
						  "Open System, 'shared' for Shared Key, or 'leap' for "
						  "Cisco LEAP.  When using Cisco LEAP (ie, key-mgmt = "
						  "'ieee8021x' and auth-alg = 'leap') the 'leap-username' "
						  "and 'leap-password' properties must be specified.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWirelessSecurity:proto:
	 *
	 * List of strings specifying the allowed WPA protocol versions to use.
	 * Each element may be one 'wpa' (allow WPA) or 'rsn' (allow WPA2/RSN).  If
	 * not specified, both WPA and RSN connections are allowed.
	 **/
	g_object_class_install_property
		(object_class, PROP_PROTO,
		 _nm_param_spec_specialized (NM_SETTING_WIRELESS_SECURITY_PROTO,
							   "Proto",
							   "List of strings specifying the allowed WPA "
							   "protocol versions to use.  Each element may be "
							   "one 'wpa' (allow WPA) or 'rsn' (allow "
							   "WPA2/RSN).  If not specified, both WPA and RSN "
							   "connections are allowed.",
							   DBUS_TYPE_G_LIST_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWirelessSecurity:pairwise:
	 *
	 * If specified, will only connect to WPA networks that provide the
	 * specified pairwise encryption capabilities.  Each element may be one of
	 * 'wep40', 'wep104', 'tkip', or 'ccmp'.
	 **/
	g_object_class_install_property
		(object_class, PROP_PAIRWISE,
		 _nm_param_spec_specialized (NM_SETTING_WIRELESS_SECURITY_PAIRWISE,
							   "Pairwise",
							   "If specified, will only connect to WPA networks "
							   "that provide the specified pairwise encryption "
							   "capabilities.  Each element may be one of 'wep40', "
							   "'wep104', 'tkip', or 'ccmp'.",
							   DBUS_TYPE_G_LIST_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWirelessSecurity:group:
	 *
	 * If specified, will only connect to WPA networks that provide the
	 * specified group/multicast encryption capabilities.  Each element may be
	 * one of 'wep40', 'wep104', 'tkip', or 'ccmp'.
	 **/
	g_object_class_install_property
		(object_class, PROP_GROUP,
		 _nm_param_spec_specialized (NM_SETTING_WIRELESS_SECURITY_GROUP,
							   "Group",
							   "If specified, will only connect to WPA networks "
							   "that provide the specified group/multicast "
							   "encryption capabilities.  Each element may be "
							   "one of 'wep40', 'wep104', 'tkip', or 'ccmp'.",
							   DBUS_TYPE_G_LIST_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWirelessSecurity:leap-username:
	 *
	 * The login username for legacy LEAP connections (ie, key-mgmt =
	 * 'ieee8021x' and auth-alg = 'leap').
	 **/
	g_object_class_install_property
		(object_class, PROP_LEAP_USERNAME,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME,
						  "LEAP Username",
						  "The login username for legacy LEAP connections "
						  "(ie, key-mgmt = 'ieee8021x' and auth-alg = 'leap').",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWirelessSecurity:wep-key0:
	 *
	 * Index 0 WEP key.  This is the WEP key used in most networks.  See the
	 * 'wep-key-type' property for a description of how this key is interpreted.
	 **/
	g_object_class_install_property
		(object_class, PROP_WEP_KEY0,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY0,
						  "WEP key0",
						  "Index 0 WEP key.  This is the WEP key used in most "
						  "networks.  See the 'wep-key-type' property for a "
						  "description of how this key is interpreted.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSettingWirelessSecurity:wep-key1:
	 *
	 * Index 1 WEP key.  This WEP index is not used by most networks.  See the
	 * 'wep-key-type' property for a description of how this key is interpreted.
	 **/
	g_object_class_install_property
		(object_class, PROP_WEP_KEY1,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY1,
						  "WEP key1",
						  "Index 1 WEP key.  This WEP index is not used by most "
						  "networks.  See the 'wep-key-type' property for a "
						  "description of how this key is interpreted.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSettingWirelessSecurity:wep-key2:
	 *
	 * Index 2 WEP key.  This WEP index is not used by most networks.  See the
	 * 'wep-key-type' property for a description of how this key is interpreted.
	 **/
	g_object_class_install_property
		(object_class, PROP_WEP_KEY2,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY2,
						  "WEP key2",
						  "Index 2 WEP key.  This WEP index is not used by most "
						  "networks.  See the 'wep-key-type' property for a "
						  "description of how this key is interpreted.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSettingWirelessSecurity:wep-key3:
	 *
	 * Index 3 WEP key.  This WEP index is not used by most networks.  See the
	 * 'wep-key-type' property for a description of how this key is interpreted.
	 **/
	g_object_class_install_property
		(object_class, PROP_WEP_KEY3,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY3,
						  "WEP key3",
						  "Index 3 WEP key.  This WEP index is not used by most "
						  "networks.  See the 'wep-key-type' property for a "
						  "description of how this key is interpreted.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSettingWirelessSecurity:psk:
	 *
	 * Pre-Shared-Key for WPA networks.  If the key is 64-characters long, it
	 * must contain only hexadecimal characters and is interpreted as a
	 * hexadecimal WPA key.  Otherwise, the key must be between 8 and 63 ASCII
	 * characters (as specified in the 802.11i standard) and is interpreted as
	 * a WPA passphrase, and is hashed to derive the actual WPA-PSK used when
	 * connecting to the WiFi network.
	 **/
	g_object_class_install_property
		(object_class, PROP_PSK,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_PSK,
						  "PSK",
						  "Pre-Shared-Key for WPA networks.  If the key is "
						  "64-characters long, it must contain only hexadecimal "
						  "characters and is interpreted as a hexadecimal WPA "
						  "key.  Otherwise, the key must be between 8 and 63 "
						  "ASCII characters (as specified in the 802.11i standard) "
						  "and is interpreted as a WPA passphrase, and is hashed "
						  "to derive the actual WPA-PSK used when connecting to "
						  "the WiFi network.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSettingWirelessSecurity:leap-password:
	 *
	 * The login password for legacy LEAP connections (ie, key-mgmt =
	 * 'ieee8021x' and auth-alg = 'leap').
	 **/
	g_object_class_install_property
		(object_class, PROP_LEAP_PASSWORD,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
						  "LEAP Password",
						  "The login password for legacy LEAP connections "
						  "(ie, key-mgmt = 'ieee8021x' and auth-alg = 'leap').",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSettingWirelessSecurity:wep-key-type:
	 *
	 * Controls the interpretation of WEP keys.  Allowed values are 1 (interpret
	 * WEP keys as hexadecimal or ASCII keys) or 2 (interpret WEP keys as WEP
	 * Passphrases).  If set to 1 and the keys are hexadecimal, they must be
	 * either 10 or 26 characters in length.  If set to 1 and the keys are
	 * ASCII keys, they must be either 5 or 13 characters in length.  If set to
	 * 2, the passphrase is hashed using the de-facto MD5 method to derive the
	 * actual WEP key.
	 **/
	g_object_class_install_property
		(object_class, PROP_WEP_KEY_TYPE,
		 g_param_spec_uint (NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE,
						"WEP Key Type",
						"Controls the interpretation of WEP keys.  Allowed values "
						"are 1 (interpret WEP keys as hexadecimal or ASCII keys) "
						"or 2 (interpret WEP keys as WEP Passphrases).  If set to "
						"1 and the keys are hexadecimal, they must be either 10 or "
						"26 characters in length.  If set to 1 and the keys are "
						"ASCII keys, they must be either 5 or 13 characters in "
						"length.  If set to 2, the passphrase is hashed using "
						" the de-facto MD5 method to derive the actual WEP key.",
						NM_WEP_KEY_TYPE_UNKNOWN,
						NM_WEP_KEY_TYPE_LAST,
						NM_WEP_KEY_TYPE_UNKNOWN,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));
}
