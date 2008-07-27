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
#include "nm-setting-connection.h"

GQuark
nm_setting_connection_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-connection-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_connection_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_CONNECTION_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_CONNECTION_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_CONNECTION_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The setting specified by the 'type' field was not found. */
			ENUM_ENTRY (NM_SETTING_CONNECTION_ERROR_TYPE_SETTING_NOT_FOUND, "TypeSettingNotFound"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingConnectionError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingConnection, nm_setting_connection, NM_TYPE_SETTING)

enum {
	PROP_0,
	PROP_ID,
	PROP_TYPE,
	PROP_AUTOCONNECT,
	PROP_TIMESTAMP,

	LAST_PROP
};

NMSetting *nm_setting_connection_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_CONNECTION, NULL);
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
	NMSettingConnection *self = NM_SETTING_CONNECTION (setting);

	if (!self->id) {
		g_set_error (error,
		             NM_SETTING_CONNECTION_ERROR,
		             NM_SETTING_CONNECTION_ERROR_MISSING_PROPERTY,
		             NM_SETTING_CONNECTION_ID);
		return FALSE;
	} else if (!strlen (self->id)) {
		g_set_error (error,
		             NM_SETTING_CONNECTION_ERROR,
		             NM_SETTING_CONNECTION_ERROR_INVALID_PROPERTY,
		             NM_SETTING_CONNECTION_ID);
		return FALSE;
	}

	if (!self->type) {
		g_set_error (error,
		             NM_SETTING_CONNECTION_ERROR,
		             NM_SETTING_CONNECTION_ERROR_MISSING_PROPERTY,
		             NM_SETTING_CONNECTION_TYPE);
		return FALSE;
	} else if (!strlen (self->type)) {
		g_set_error (error,
		             NM_SETTING_CONNECTION_ERROR,
		             NM_SETTING_CONNECTION_ERROR_INVALID_PROPERTY,
		             NM_SETTING_CONNECTION_TYPE);
		return FALSE;
	}

	/* Make sure the corresponding 'type' item is present */
	if (all_settings && !g_slist_find_custom (all_settings, self->type, find_setting_by_name)) {
		g_set_error (error,
		             NM_SETTING_CONNECTION_ERROR,
		             NM_SETTING_CONNECTION_ERROR_TYPE_SETTING_NOT_FOUND,
		             NM_SETTING_CONNECTION_TYPE);
		return FALSE;
	}

	return TRUE;
}

static void
nm_setting_connection_init (NMSettingConnection *setting)
{
	((NMSetting *) setting)->name = g_strdup (NM_SETTING_CONNECTION_SETTING_NAME);
}

static void
finalize (GObject *object)
{
	NMSettingConnection *self = NM_SETTING_CONNECTION (object);

	g_free (self->id);
	g_free (self->type);

	G_OBJECT_CLASS (nm_setting_connection_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingConnection *setting = NM_SETTING_CONNECTION (object);

	switch (prop_id) {
	case PROP_ID:
		g_free (setting->id);
		setting->id = g_value_dup_string (value);
		break;
	case PROP_TYPE:
		g_free (setting->type);
		setting->type = g_value_dup_string (value);
		break;
	case PROP_AUTOCONNECT:
		setting->autoconnect = g_value_get_boolean (value);
		break;
	case PROP_TIMESTAMP:
		setting->timestamp = g_value_get_uint64 (value);
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
	NMSettingConnection *setting = NM_SETTING_CONNECTION (object);

	switch (prop_id) {
	case PROP_ID:
		g_value_set_string (value, setting->id);
		break;
	case PROP_TYPE:
		g_value_set_string (value, setting->type);
		break;
	case PROP_AUTOCONNECT:
		g_value_set_boolean (value, setting->autoconnect);
		break;
	case PROP_TIMESTAMP:
		g_value_set_uint64 (value, setting->timestamp);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_connection_class_init (NMSettingConnectionClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_ID,
		 g_param_spec_string (NM_SETTING_CONNECTION_ID,
						  "ID",
						  "User-readable connection identifier/name",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	g_object_class_install_property
		(object_class, PROP_TYPE,
		 g_param_spec_string (NM_SETTING_CONNECTION_TYPE,
						  "Type",
						  "Connection type",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_AUTOCONNECT,
		 g_param_spec_boolean (NM_SETTING_CONNECTION_AUTOCONNECT,
						   "Autoconnect",
						   "Connection autoconnect",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	g_object_class_install_property
		(object_class, PROP_TIMESTAMP,
		 g_param_spec_uint64 (NM_SETTING_CONNECTION_TIMESTAMP,
						  "Timestamp",
						  "Connection timestamp",
						  0, G_MAXUINT64, 0,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));
}
