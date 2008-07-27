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

#include <dbus/dbus-glib.h>
#include "nm-setting-vpn-properties.h"
#include "nm-param-spec-specialized.h"
#include "nm-dbus-glib-types.h"

GQuark
nm_setting_vpn_properties_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-vpn-properties-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_vpn_properties_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_VPN_PROPERTIES_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_VPN_PROPERTIES_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_VPN_PROPERTIES_ERROR_MISSING_PROPERTY, "MissingProperty"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingVPNPropertiesError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingVPNProperties, nm_setting_vpn_properties, NM_TYPE_SETTING)

enum {
	PROP_0,
	PROP_DATA,

	LAST_PROP
};

NMSetting *
nm_setting_vpn_properties_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_VPN_PROPERTIES, NULL);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingVPNProperties *self = NM_SETTING_VPN_PROPERTIES (setting);

	g_return_val_if_fail (self->data != NULL, FALSE);

	/* FIXME: actually check the data as well */

	return TRUE;
}

static void
nm_gvalue_destroy (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static void
update_one_secret (NMSetting *setting, const char *key, GValue *value)
{
	NMSettingVPNProperties *self = NM_SETTING_VPN_PROPERTIES (setting);
	GValue *copy_val;

	g_return_if_fail (key != NULL);
	g_return_if_fail (value != NULL);

	/* Secrets are really only known to the VPNs themselves. */
	copy_val = g_slice_new0 (GValue);
	g_value_init (copy_val, G_VALUE_TYPE (value));
	g_value_copy (value, copy_val);
	g_hash_table_insert (self->data, g_strdup (key), copy_val);
}

static void
nm_setting_vpn_properties_init (NMSettingVPNProperties *self)
{
	g_object_set (NM_SETTING (self), "name", NM_SETTING_VPN_PROPERTIES_SETTING_NAME, NULL);

	self->data = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, nm_gvalue_destroy);
}

static void
finalize (GObject *object)
{
	NMSettingVPNProperties *self = NM_SETTING_VPN_PROPERTIES (object);

	g_hash_table_destroy (self->data);

	G_OBJECT_CLASS (nm_setting_vpn_properties_parent_class)->finalize (object);
}

static void
copy_hash (gpointer key, gpointer data, gpointer user_data)
{
	GHashTable *hash = (GHashTable *) user_data;
	GValue *src_val = (GValue *) data;
	GValue *copy_val;

	copy_val = g_slice_new0 (GValue);
	g_value_init (copy_val, G_VALUE_TYPE (src_val));
	g_value_copy (src_val, copy_val);
	g_hash_table_insert (hash, g_strdup (key), copy_val);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingVPNProperties *setting = NM_SETTING_VPN_PROPERTIES (object);

	switch (prop_id) {
	case PROP_DATA:
		/* Must make a deep copy of the hash table here... */
		g_hash_table_remove_all (setting->data);
		g_hash_table_foreach (g_value_get_boxed (value), copy_hash, setting->data);
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
	NMSettingVPNProperties *setting = NM_SETTING_VPN_PROPERTIES (object);

	switch (prop_id) {
	case PROP_DATA:
		g_value_set_boxed (value, setting->data);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_vpn_properties_class_init (NMSettingVPNPropertiesClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;
	parent_class->update_one_secret = update_one_secret;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_DATA,
		 nm_param_spec_specialized (NM_SETTING_VPN_PROPERTIES_DATA,
							   "Data",
							   "VPN Service specific data",
							   DBUS_TYPE_G_MAP_OF_VARIANT,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));
}
