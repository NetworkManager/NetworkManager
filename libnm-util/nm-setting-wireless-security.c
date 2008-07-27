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

	LAST_PROP
};

NMSetting *
nm_setting_wireless_security_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_WIRELESS_SECURITY, NULL);
}

static gboolean
verify_wep_key (const char *key)
{
	int keylen, i;

	if (!key)
		return FALSE;

	keylen = strlen (key);
	if (keylen != 10 && keylen != 26)
		return FALSE;

	for (i = 0; i < keylen; i++) {
		if (!isxdigit (key[i]))
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
	if (psklen != 64)
		return FALSE;

	for (i = 0; i < psklen; i++) {
		if (!isxdigit (psk[i]))
			return FALSE;
	}

	return TRUE;
}


static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSettingWirelessSecurity *self = NM_SETTING_WIRELESS_SECURITY (setting);
	GPtrArray *secrets;

	secrets = g_ptr_array_sized_new (4);
	if (!secrets) {
		g_warning ("Not enough memory to create required secrets array.");
		return NULL;
	}

	g_assert (self->key_mgmt);

	/* Static WEP */
	if (strcmp (self->key_mgmt, "none") == 0) {
		if ((self->wep_tx_keyidx == 0) && !verify_wep_key (self->wep_key0)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);
			return secrets;
		}
		if ((self->wep_tx_keyidx == 1) && !verify_wep_key (self->wep_key1)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_WEP_KEY1);
			return secrets;
		}
		if ((self->wep_tx_keyidx == 2) && !verify_wep_key (self->wep_key2)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_WEP_KEY2);
			return secrets;
		}
		if ((self->wep_tx_keyidx == 3) && !verify_wep_key (self->wep_key3)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_WEP_KEY3);
			return secrets;
		}
		goto no_secrets;
	}

	/* WPA-PSK infrastructure and adhoc */
	if (   (strcmp (self->key_mgmt, "wpa-none") == 0)
	    || (strcmp (self->key_mgmt, "wpa-psk") == 0)) {
		if (!verify_wpa_psk (self->psk)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_PSK);
			return secrets;
		}
		goto no_secrets;
	}

	/* LEAP */
	if (   self->auth_alg
	    && !strcmp (self->auth_alg, "leap")
	    && !strcmp (self->key_mgmt, "ieee8021x")) {
		if (!self->leap_password || !strlen (self->leap_password)) {
			g_ptr_array_add (secrets, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD);
			return secrets;
		}
		goto no_secrets;
	}

	if (   (strcmp (self->key_mgmt, "ieee8021x") == 0)
	    || (strcmp (self->key_mgmt, "wpa-eap") == 0)) {
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
	const char *valid_key_mgmt[] = { "none", "ieee8021x", "wpa-none", "wpa-psk", "wpa-eap", NULL };
	const char *valid_auth_algs[] = { "open", "shared", "leap", NULL };
	const char *valid_protos[] = { "wpa", "rsn", NULL };
	const char *valid_pairwise[] = { "wep40", "wep104", "tkip", "ccmp", NULL };
	const char *valid_groups[] = { "wep40", "wep104", "tkip", "ccmp", NULL };

	if (!self->key_mgmt) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_MISSING_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
		return FALSE;
	}

	if (!nm_utils_string_in_list (self->key_mgmt, valid_key_mgmt)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
		return FALSE;
	}

	if (self->auth_alg && !strcmp (self->auth_alg, "leap")) {
		/* LEAP must use ieee8021x key management */
		if (strcmp (self->key_mgmt, "ieee8021x")) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_SECURITY_ERROR,
			             NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_802_1X,
			             NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
			return FALSE;
		}
		if (!self->leap_username) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_SECURITY_ERROR,
			             NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_USERNAME,
			             NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
			return FALSE;
		}
	} else {
		if (   (strcmp (self->key_mgmt, "ieee8021x") == 0)
	        || (strcmp (self->key_mgmt, "wpa-eap") == 0)) {
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

	if (self->leap_username && !strlen (self->leap_username)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
		return FALSE;
	}

	if (self->wep_tx_keyidx > 3) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX);
		return FALSE;
	}

	if (self->wep_key0 && !strlen (self->wep_key0)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);
		return FALSE;
	}
	if (self->wep_key1 && !strlen (self->wep_key1)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_WEP_KEY1);
		return FALSE;
	}
	if (self->wep_key2 && !strlen (self->wep_key2)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_WEP_KEY2);
		return FALSE;
	}
	if (self->wep_key3 && !strlen (self->wep_key3)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_WEP_KEY3);
		return FALSE;
	}

	if (self->auth_alg && !nm_utils_string_in_list (self->auth_alg, valid_auth_algs)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
		return FALSE;
	}

	if (self->proto && !nm_utils_string_slist_validate (self->proto, valid_protos)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_PROTO);
		return FALSE;
	}

	if (self->pairwise && !nm_utils_string_slist_validate (self->pairwise, valid_pairwise)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
		return FALSE;
	}

	if (self->group && !nm_utils_string_slist_validate (self->group, valid_groups)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_SECURITY_ERROR,
		             NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SECURITY_GROUP);
		return FALSE;
	}

	/* Shared Key auth can only be used with WEP */
	if (self->auth_alg && !strcmp (self->auth_alg, "shared")) {
		if (self->key_mgmt && strcmp (self->key_mgmt, "none")) {
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
	((NMSetting *) setting)->name = g_strdup (NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
}

static void
finalize (GObject *object)
{
	NMSettingWirelessSecurity *self = NM_SETTING_WIRELESS_SECURITY (object);

	/* Strings first. g_free() already checks for NULLs so we don't have to */

	g_free (self->key_mgmt);
	g_free (self->auth_alg);
	g_free (self->leap_username);
	g_free (self->wep_key0);
	g_free (self->wep_key1);
	g_free (self->wep_key2);
	g_free (self->wep_key3);
	g_free (self->psk);
	g_free (self->leap_password);

	nm_utils_slist_free (self->proto, g_free);
	nm_utils_slist_free (self->pairwise, g_free);
	nm_utils_slist_free (self->group, g_free);

	G_OBJECT_CLASS (nm_setting_wireless_security_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingWirelessSecurity *setting = NM_SETTING_WIRELESS_SECURITY (object);

	switch (prop_id) {
	case PROP_KEY_MGMT:
		g_free (setting->key_mgmt);
		setting->key_mgmt = g_value_dup_string (value);
		break;
	case PROP_WEP_TX_KEYIDX:
		setting->wep_tx_keyidx = g_value_get_uint (value);
		break;
	case PROP_AUTH_ALG:
		g_free (setting->auth_alg);
		setting->auth_alg = g_value_dup_string (value);
		break;
	case PROP_PROTO:
		nm_utils_slist_free (setting->proto, g_free);
		setting->proto = g_value_dup_boxed (value);
		break;
	case PROP_PAIRWISE:
		nm_utils_slist_free (setting->pairwise, g_free);
		setting->pairwise = g_value_dup_boxed (value);
		break;
	case PROP_GROUP:
		nm_utils_slist_free (setting->group, g_free);
		setting->group = g_value_dup_boxed (value);
		break;
	case PROP_LEAP_USERNAME:
		g_free (setting->leap_username);
		setting->leap_username = g_value_dup_string (value);
		break;
	case PROP_WEP_KEY0:
		g_free (setting->wep_key0);
		setting->wep_key0 = g_value_dup_string (value);
		break;
	case PROP_WEP_KEY1:
		g_free (setting->wep_key1);
		setting->wep_key1 = g_value_dup_string (value);
		break;
	case PROP_WEP_KEY2:
		g_free (setting->wep_key2);
		setting->wep_key2 = g_value_dup_string (value);
		break;
	case PROP_WEP_KEY3:
		g_free (setting->wep_key3);
		setting->wep_key3 = g_value_dup_string (value);
		break;
	case PROP_PSK:
		g_free (setting->psk);
		setting->psk = g_value_dup_string (value);
		break;
	case PROP_LEAP_PASSWORD:
		g_free (setting->leap_password);
		setting->leap_password = g_value_dup_string (value);
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

	switch (prop_id) {
	case PROP_KEY_MGMT:
		g_value_set_string (value, setting->key_mgmt);
		break;
	case PROP_WEP_TX_KEYIDX:
		g_value_set_uint (value, setting->wep_tx_keyidx);
		break;
	case PROP_AUTH_ALG:
		g_value_set_string (value, setting->auth_alg);
		break;
	case PROP_PROTO:
		g_value_set_boxed (value, setting->proto);
		break;
	case PROP_PAIRWISE:
		g_value_set_boxed (value, setting->pairwise);
		break;
	case PROP_GROUP:
		g_value_set_boxed (value, setting->group);
		break;
	case PROP_LEAP_USERNAME:
		g_value_set_string (value, setting->leap_username);
		break;
	case PROP_WEP_KEY0:
		g_value_set_string (value, setting->wep_key0);
		break;
	case PROP_WEP_KEY1:
		g_value_set_string (value, setting->wep_key1);
		break;
	case PROP_WEP_KEY2:
		g_value_set_string (value, setting->wep_key2);
		break;
	case PROP_WEP_KEY3:
		g_value_set_string (value, setting->wep_key3);
		break;
	case PROP_PSK:
		g_value_set_string (value, setting->psk);
		break;
	case PROP_LEAP_PASSWORD:
		g_value_set_string (value, setting->leap_password);
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

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	parent_class->verify         = verify;
	parent_class->need_secrets   = need_secrets;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_KEY_MGMT,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
						  "Key management",
						  "Key management",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_REQUIRED));

	g_object_class_install_property
		(object_class, PROP_WEP_TX_KEYIDX,
		 g_param_spec_uint (NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX,
						"WEP TX key index",
						"WEP TX key index",
						0, 3, 0,
						G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_AUTH_ALG,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
						  "AuthAlg",
						  "AuthAlg",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_PROTO,
		 nm_param_spec_specialized (NM_SETTING_WIRELESS_SECURITY_PROTO,
							   "Proto",
							   "Proto",
							   DBUS_TYPE_G_LIST_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_PAIRWISE,
		 nm_param_spec_specialized (NM_SETTING_WIRELESS_SECURITY_PAIRWISE,
							   "Pairwise",
							   "Pairwise",
							   DBUS_TYPE_G_LIST_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_GROUP,
		 nm_param_spec_specialized (NM_SETTING_WIRELESS_SECURITY_GROUP,
							   "Group",
							   "Group",
							   DBUS_TYPE_G_LIST_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_LEAP_USERNAME,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME,
						  "LEAP Username",
						  "LEAP Username",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_WEP_KEY0,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY0,
						  "WEP key0",
						  "WEP key0",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	g_object_class_install_property
		(object_class, PROP_WEP_KEY1,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY1,
						  "WEP key1",
						  "WEP key1",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	g_object_class_install_property
		(object_class, PROP_WEP_KEY2,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY2,
						  "WEP key2",
						  "WEP key2",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	g_object_class_install_property
		(object_class, PROP_WEP_KEY3,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_WEP_KEY3,
						  "WEP key3",
						  "WEP key3",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	g_object_class_install_property
		(object_class, PROP_PSK,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_PSK,
						  "PSK",
						  "PSK",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	g_object_class_install_property
		(object_class, PROP_LEAP_PASSWORD,
		 g_param_spec_string (NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
						  "LEAP Password",
						  "LEAP Password",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));
}
