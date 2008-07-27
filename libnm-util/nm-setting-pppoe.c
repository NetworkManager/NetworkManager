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
#include "nm-setting-pppoe.h"
#include "nm-setting-ppp.h"

GQuark
nm_setting_pppoe_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-pppoe-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_pppoe_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_PPPOE_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_PPPOE_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_PPPOE_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The required PPP setting is missing */
			ENUM_ENTRY (NM_SETTING_PPPOE_ERROR_MISSING_PPP_SETTING, "MissingPPPSetting"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingPPPOEError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingPPPOE, nm_setting_pppoe, NM_TYPE_SETTING)

enum {
	PROP_0,
	PROP_SERVICE,
	PROP_USERNAME,
	PROP_PASSWORD,

	LAST_PROP
};

NMSetting *
nm_setting_pppoe_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_PPPOE, NULL);
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
	NMSettingPPPOE *self = NM_SETTING_PPPOE (setting);

	if (!self->username) {
		g_set_error (error,
		             NM_SETTING_PPPOE_ERROR,
		             NM_SETTING_PPPOE_ERROR_MISSING_PROPERTY,
		             NM_SETTING_PPPOE_USERNAME);
		return FALSE;
	} else if (!strlen (self->username)) {
		g_set_error (error,
		             NM_SETTING_PPPOE_ERROR,
		             NM_SETTING_PPPOE_ERROR_INVALID_PROPERTY,
		             NM_SETTING_PPPOE_USERNAME);
		return FALSE;
	}

	if (self->service && !strlen (self->service)) {
		g_set_error (error,
		             NM_SETTING_PPPOE_ERROR,
		             NM_SETTING_PPPOE_ERROR_INVALID_PROPERTY,
		             NM_SETTING_PPPOE_SERVICE);
		return FALSE;
	}

	if (!g_slist_find_custom (all_settings, NM_SETTING_PPP_SETTING_NAME, find_setting_by_name)) {
		g_set_error (error,
		             NM_SETTING_PPPOE_ERROR,
		             NM_SETTING_PPPOE_ERROR_MISSING_PPP_SETTING,
		             NULL);
		return FALSE;
	}

	return TRUE;
}

static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSettingPPPOE *self = NM_SETTING_PPPOE (setting);
	GPtrArray *secrets;

	if (self->password)
		return NULL;

	secrets = g_ptr_array_sized_new (1);
	g_ptr_array_add (secrets, NM_SETTING_PPPOE_PASSWORD);

	return secrets;
}

static void
nm_setting_pppoe_init (NMSettingPPPOE *setting)
{
	((NMSetting *) setting)->name = g_strdup (NM_SETTING_PPPOE_SETTING_NAME);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingPPPOE *setting = NM_SETTING_PPPOE (object);

	switch (prop_id) {
	case PROP_SERVICE:
		g_free (setting->service);
		setting->service = g_value_dup_string (value);
		break;
	case PROP_USERNAME:
		g_free (setting->username);
		setting->username = g_value_dup_string (value);
		break;
	case PROP_PASSWORD:
		g_free (setting->password);
		setting->password = g_value_dup_string (value);
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
	NMSettingPPPOE *setting = NM_SETTING_PPPOE (object);

	switch (prop_id) {
	case PROP_SERVICE:
		g_value_set_string (value, setting->service);
		break;
	case PROP_USERNAME:
		g_value_set_string (value, setting->username);
		break;
	case PROP_PASSWORD:
		g_value_set_string (value, setting->password);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_pppoe_class_init (NMSettingPPPOEClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	parent_class->verify       = verify;
	parent_class->need_secrets = need_secrets;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_SERVICE,
		 g_param_spec_string (NM_SETTING_PPPOE_SERVICE,
						  "Service",
						  "Service",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_USERNAME,
		 g_param_spec_string (NM_SETTING_PPPOE_USERNAME,
						  "Username",
						  "Username",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_PASSWORD,
		 g_param_spec_string (NM_SETTING_PPPOE_PASSWORD,
						  "Password",
						  "Password",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));
}
