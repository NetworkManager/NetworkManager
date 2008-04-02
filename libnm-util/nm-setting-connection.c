/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <string.h>
#include "nm-setting-connection.h"

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
verify (NMSetting *setting, GSList *all_settings)
{
	NMSettingConnection *self = NM_SETTING_CONNECTION (setting);

	if (!self->id || !strlen (self->id))
		return FALSE;

	if (!self->type || !strlen (self->type))
		return FALSE;

	/* Make sure the corresponding 'type' item is present */
	if (all_settings && !g_slist_find_custom (all_settings, self->type, find_setting_by_name)) {
		g_warning ("Required setting '%s' not found.", self->type);
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
