/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-match.h"

#include "nm-setting-private.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-match
 * @short_description: Properties to match a connection with a device.
 * @include: nm-setting-match.h
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingMatch,
	PROP_INTERFACE_NAME,
);

/**
 * NMSettingMatch:
 *
 * Match settings.
 *
 * Since: 1.14
 */
struct _NMSettingMatch {
	NMSetting parent;
	GPtrArray *interface_name;
};

struct _NMSettingMatchClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE (NMSettingMatch, nm_setting_match, NM_TYPE_SETTING)

/*****************************************************************************/

/**
 * nm_setting_match_get_num_interface_names:
 * @setting: the #NMSettingMatch
 *
 * Returns: the number of configured interface names
 *
 * Since: 1.14
 **/
guint
nm_setting_match_get_num_interface_names (NMSettingMatch *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), 0);

	return setting->interface_name->len;
}

/**
 * nm_setting_match_get_interface_name:
 * @setting: the #NMSettingMatch
 * @idx: index number of the DNS search domain to return
 *
 * Returns: the interface name at index @idx
 *
 * Since: 1.14
 **/
const char *
nm_setting_match_get_interface_name (NMSettingMatch *setting, int idx)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), NULL);

	g_return_val_if_fail (idx >= 0 && idx < setting->interface_name->len, NULL);

	return setting->interface_name->pdata[idx];
}

/**
 * nm_setting_match_add_interface_name:
 * @setting: the #NMSettingMatch
 * @interface_name: the interface name to add
 *
 * Adds a new interface name to the setting.
 *
 * Since: 1.14
 **/
void
nm_setting_match_add_interface_name (NMSettingMatch *setting,
                                     const char *interface_name)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));
	g_return_if_fail (interface_name != NULL);
	g_return_if_fail (interface_name[0] != '\0');

	g_ptr_array_add (setting->interface_name, g_strdup (interface_name));
	_notify (setting, PROP_INTERFACE_NAME);
}

/**
 * nm_setting_match_remove_interface_name:
 * @setting: the #NMSettingMatch
 * @idx: index number of the interface name
 *
 * Removes the interface name at index @idx.
 *
 * Since: 1.14
 **/
void
nm_setting_match_remove_interface_name (NMSettingMatch *setting, int idx)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));

	g_return_if_fail (idx >= 0 && idx < setting->interface_name->len);

	g_ptr_array_remove_index (setting->interface_name, idx);
	_notify (setting, PROP_INTERFACE_NAME);
}

/**
 * nm_setting_match_remove_interface_name_by_value:
 * @setting: the #NMSettingMatch
 * @interface_name: the interface name to remove
 *
 * Removes @interface_name.
 *
 * Returns: %TRUE if the interface name was found and removed; %FALSE if it was not.
 *
 * Since: 1.14
 **/
gboolean
nm_setting_match_remove_interface_name_by_value (NMSettingMatch *setting,
                                                 const char *interface_name)
{
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), FALSE);
	g_return_val_if_fail (interface_name != NULL, FALSE);
	g_return_val_if_fail (interface_name[0] != '\0', FALSE);

	for (i = 0; i < setting->interface_name->len; i++) {
		if (nm_streq (interface_name, setting->interface_name->pdata[i])) {
			g_ptr_array_remove_index (setting->interface_name, i);
			_notify (setting, PROP_INTERFACE_NAME);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_match_clear_interface_names:
 * @setting: the #NMSettingMatch
 *
 * Removes all configured interface names.
 *
 * Since: 1.14
 **/
void
nm_setting_match_clear_interface_names (NMSettingMatch *setting)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));

	if (setting->interface_name->len != 0) {
		g_ptr_array_set_size (setting->interface_name, 0);
		_notify (setting, PROP_INTERFACE_NAME);
	}
}

/**
 * nm_setting_match_get_interface_names:
 * @setting: the #NMSettingMatch
 *
 * Returns all the interface names.
 *
 * Returns: (transfer none): the configured interface names.
 *
 * Since: 1.14
 **/
const char *const *
nm_setting_match_get_interface_names (NMSettingMatch *setting, guint *length)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), NULL);
	g_return_val_if_fail (length, NULL);

	NM_SET_OUT (length, setting->interface_name->len);
	return (const char *const *) setting->interface_name->pdata;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingMatch *self = NM_SETTING_MATCH (object);

	switch (prop_id) {
	case PROP_INTERFACE_NAME:
		g_value_take_boxed (value, _nm_utils_ptrarray_to_strv (self->interface_name));
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
	NMSettingMatch *self = NM_SETTING_MATCH (object);

	switch (prop_id) {
	case PROP_INTERFACE_NAME:
		g_ptr_array_unref (self->interface_name);
		self->interface_name = _nm_utils_strv_to_ptrarray (g_value_get_boxed (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_match_init (NMSettingMatch *setting)
{
	setting->interface_name = g_ptr_array_new_with_free_func (g_free);
}

/**
 * nm_setting_match_new:
 *
 * Creates a new #NMSettingMatch object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingMatch object
 *
 * Since: 1.14
 **/
NMSetting *
nm_setting_match_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_MATCH, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingMatch *self = NM_SETTING_MATCH (object);

	g_ptr_array_unref (self->interface_name);

	G_OBJECT_CLASS (nm_setting_match_parent_class)->finalize (object);
}

static void
nm_setting_match_class_init (NMSettingMatchClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	/**
	 * NMSettingMatch:interface-name
	 *
	 * A list of interface names to match. Each element is a shell wildcard
	 * pattern.  When an element is prefixed with exclamation mark (!) the
	 * condition is inverted.
	 *
	 * A candidate interface name is considered matching when both these
	 * conditions are satisfied: (a) any of the elements not prefixed with '!'
	 * matches or there aren't such elements; (b) none of the elements
	 * prefixed with '!' match.
	 *
	 * Since: 1.14
	 **/
	obj_properties[PROP_INTERFACE_NAME] =
	    g_param_spec_boxed (NM_SETTING_MATCH_INTERFACE_NAME, "", "",
	                        G_TYPE_STRV,
	                        NM_SETTING_PARAM_FUZZY_IGNORE |
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit (setting_class, NM_META_SETTING_TYPE_MATCH);
}
