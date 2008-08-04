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
#include "nm-setting-gsm.h"
#include "nm-setting-serial.h"
#include "nm-utils.h"

GQuark
nm_setting_gsm_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-gsm-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_gsm_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_GSM_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_GSM_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_GSM_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The required serial setting is missing */
			ENUM_ENTRY (NM_SETTING_GSM_ERROR_MISSING_SERIAL_SETTING, "MissingSerialSetting"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingGsmError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingGsm, nm_setting_gsm, NM_TYPE_SETTING)

enum {
	PROP_0,
	PROP_NUMBER,
	PROP_USERNAME,
	PROP_PASSWORD,
	PROP_APN,
	PROP_NETWORK_ID,
	PROP_NETWORK_TYPE,
	PROP_BAND,
	PROP_PIN,
	PROP_PUK,

	LAST_PROP
};

NMSetting *
nm_setting_gsm_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_GSM, NULL);
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
	NMSettingGsm *self = NM_SETTING_GSM (setting);

	/* Serial connections require a PPP setting */
	if (all_settings && 
	    !g_slist_find_custom (all_settings, NM_SETTING_SERIAL_SETTING_NAME, find_setting_by_name)) {
		g_set_error (error,
		             NM_SETTING_GSM_ERROR,
		             NM_SETTING_GSM_ERROR_MISSING_SERIAL_SETTING,
		             NULL);
		return FALSE;
	}

	if (!self->number) {
		g_set_error (error,
		             NM_SETTING_GSM_ERROR,
		             NM_SETTING_GSM_ERROR_MISSING_PROPERTY,
		             NM_SETTING_GSM_NUMBER);
		return FALSE;
	} else if (!strlen (self->number)) {
		g_set_error (error,
		             NM_SETTING_GSM_ERROR,
		             NM_SETTING_GSM_ERROR_INVALID_PROPERTY,
		             NM_SETTING_GSM_NUMBER);
		return FALSE;
	}

	if (self->apn && (strlen (self->apn) < 1 || strchr (self->apn, '"'))) {
		g_set_error (error,
		             NM_SETTING_GSM_ERROR,
		             NM_SETTING_GSM_ERROR_INVALID_PROPERTY,
		             NM_SETTING_GSM_APN);
		return FALSE;
	}

	if (self->username && !strlen (self->username)) {
		g_set_error (error,
		             NM_SETTING_GSM_ERROR,
		             NM_SETTING_GSM_ERROR_INVALID_PROPERTY,
		             NM_SETTING_GSM_USERNAME);
		return FALSE;
	}

	if (self->password && !strlen (self->password)) {
		g_set_error (error,
		             NM_SETTING_GSM_ERROR,
		             NM_SETTING_GSM_ERROR_INVALID_PROPERTY,
		             NM_SETTING_GSM_USERNAME);
		return FALSE;
	}

	return TRUE;
}

static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSettingGsm *self = NM_SETTING_GSM (setting);
	GPtrArray *secrets = NULL;

	if (self->password)
		return NULL;

	if (self->username) {
		secrets = g_ptr_array_sized_new (1);
		g_ptr_array_add (secrets, NM_SETTING_GSM_PASSWORD);
	}

	return secrets;
}

static void
nm_setting_gsm_init (NMSettingGsm *setting)
{
	((NMSetting *) setting)->name = g_strdup (NM_SETTING_GSM_SETTING_NAME);
}

static void
finalize (GObject *object)
{
	NMSettingGsm *self = NM_SETTING_GSM (object);

	g_free (self->number);
	g_free (self->username);
	g_free (self->password);
	g_free (self->apn);
	g_free (self->network_id);
	g_free (self->pin);
	g_free (self->puk);

	G_OBJECT_CLASS (nm_setting_gsm_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingGsm *setting = NM_SETTING_GSM (object);

	switch (prop_id) {
	case PROP_NUMBER:
		g_free (setting->number);
		setting->number = g_value_dup_string (value);
		break;
	case PROP_USERNAME:
		g_free (setting->username);
		setting->username = g_value_dup_string (value);
		break;
	case PROP_PASSWORD:
		g_free (setting->password);
		setting->password = g_value_dup_string (value);
		break;
	case PROP_APN:
		g_free (setting->apn);
		setting->apn = g_value_dup_string (value);
		break;
	case PROP_NETWORK_ID:
		g_free (setting->network_id);
		setting->network_id = g_value_dup_string (value);
		break;
	case PROP_NETWORK_TYPE:
		setting->network_type = g_value_get_int (value);
		break;
	case PROP_BAND:
		setting->band = g_value_get_int (value);
		break;
	case PROP_PIN:
		g_free (setting->pin);
		setting->pin = g_value_dup_string (value);
		break;
	case PROP_PUK:
		g_free (setting->puk);
		setting->puk = g_value_dup_string (value);
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
	NMSettingGsm *setting = NM_SETTING_GSM (object);

	switch (prop_id) {
	case PROP_NUMBER:
		g_value_set_string (value, setting->number);
		break;
	case PROP_USERNAME:
		g_value_set_string (value, setting->username);
		break;
	case PROP_PASSWORD:
		g_value_set_string (value, setting->password);
		break;
	case PROP_APN:
		g_value_set_string (value, setting->apn);
		break;
	case PROP_NETWORK_ID:
		g_value_set_string (value, setting->network_id);
		break;
	case PROP_NETWORK_TYPE:
		g_value_set_int (value, setting->network_type);
		break;
	case PROP_BAND:
		g_value_set_int (value, setting->band);
		break;
	case PROP_PIN:
		g_value_set_string (value, setting->pin);
		break;
	case PROP_PUK:
		g_value_set_string (value, setting->puk);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_gsm_class_init (NMSettingGsmClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;
	parent_class->need_secrets = need_secrets;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_NUMBER,
		 g_param_spec_string (NM_SETTING_GSM_NUMBER,
						  "Number",
						  "Number",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_USERNAME,
		 g_param_spec_string (NM_SETTING_GSM_USERNAME,
						  "Username",
						  "Username",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_PASSWORD,
		 g_param_spec_string (NM_SETTING_GSM_PASSWORD,
						  "Password",
						  "Password",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	g_object_class_install_property
		(object_class, PROP_APN,
		 g_param_spec_string (NM_SETTING_GSM_APN,
						  "APN",
						  "APN",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_NETWORK_ID,
		 g_param_spec_string (NM_SETTING_GSM_NETWORK_ID,
						  "Network ID",
						  "Network ID",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_NETWORK_TYPE,
		 g_param_spec_int (NM_SETTING_GSM_NETWORK_TYPE,
					    "Network type",
					    "Network type",
					    NM_GSM_NETWORK_ANY,
					    NM_GSM_NETWORK_PREFER_GSM,
					    NM_GSM_NETWORK_ANY,
					    G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_BAND,
		 g_param_spec_int (NM_SETTING_GSM_BAND,
					    "Band",
					    "Band",
					    -1, 5, -1, /* FIXME: Use an enum for it */
					    G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_PIN,
		 g_param_spec_string (NM_SETTING_GSM_PIN,
						  "PIN",
						  "PIN",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	g_object_class_install_property
		(object_class, PROP_PUK,
		 g_param_spec_string (NM_SETTING_GSM_PUK,
						  "PUK",
						  "PUK",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));
}
