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
 * Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-settings-storage.h"

#include "nm-utils.h"
#include "nm-settings-plugin.h"

#include "settings/plugins/keyfile/nms-keyfile-storage.h"

/*****************************************************************************/

int
nm_settings_storage_cmp (NMSettingsStorage *a,
                         NMSettingsStorage *b,
                         const GSList *plugin_list)
{
	NMSettingsStorageClass *klass;

	/* Sort by priority.
	 *
	 * If a > b (by priority), we return a positive number (as one
	 * would expect by a cmp() function). */

	nm_assert (NM_IS_SETTINGS_STORAGE (a));
	nm_assert (NM_IS_SETTINGS_STORAGE (b));
	nm_assert (a != b);
	nm_assert (nm_streq (nm_settings_storage_get_uuid (a), nm_settings_storage_get_uuid (b)));

	/* in-memory has always higher priority */
	NM_CMP_DIRECT (nm_settings_storage_is_keyfile_run (a),
	               nm_settings_storage_is_keyfile_run (b));

	NM_CMP_RETURN (nm_settings_plugin_cmp_by_priority (nm_settings_storage_get_plugin (a),
	                                                   nm_settings_storage_get_plugin (b),
	                                                   plugin_list));

	klass = NM_SETTINGS_STORAGE_GET_CLASS (a);
	if (klass != NM_SETTINGS_STORAGE_GET_CLASS (b)) {
		/* one plugin must return storages of the same type. Otherwise, it's
		 * unclear how cmp_fcn() should compare them. */
		nm_assert_not_reached ();
		return 0;
	}

	if (klass->cmp_fcn)
		NM_CMP_RETURN (klass->cmp_fcn (a, b));

	return 0;
}

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PLUGIN,
	PROP_UUID,
	PROP_FILENAME,
);

G_DEFINE_TYPE (NMSettingsStorage, nm_settings_storage, G_TYPE_OBJECT)

/*****************************************************************************/

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingsStorage *self = NM_SETTINGS_STORAGE (object);

	switch (prop_id) {
	case PROP_PLUGIN:
		/* construct-only */
		self->_plugin = g_object_ref (g_value_get_object (value));
		nm_assert (NM_IS_SETTINGS_PLUGIN (self->_plugin));
		break;
	case PROP_UUID:
		/* construct-only */
		self->_uuid = g_value_dup_string (value);
		nm_assert (!self->_uuid || nm_utils_is_uuid (self->_uuid));
		break;
	case PROP_FILENAME:
		/* construct-only */
		self->_filename = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_settings_storage_init (NMSettingsStorage *self)
{
	c_list_init (&self->_storage_lst);
	c_list_init (&self->_storage_by_uuid_lst);
}

NMSettingsStorage *
nm_settings_storage_new (NMSettingsPlugin *plugin,
                         const char *uuid,
                         const char *filename)
{
	nm_assert (NM_IS_SETTINGS_PLUGIN (plugin));
	nm_assert (nm_utils_is_uuid (uuid));

	return g_object_new (NM_TYPE_SETTINGS_STORAGE,
	                     NM_SETTINGS_STORAGE_PLUGIN, plugin,
	                     NM_SETTINGS_STORAGE_UUID, uuid,
	                     NM_SETTINGS_STORAGE_FILENAME, filename,
	                     NULL);
}

static void
finalize (GObject *object)
{
	NMSettingsStorage *self = NM_SETTINGS_STORAGE (object);

	c_list_unlink_stale (&self->_storage_lst);
	c_list_unlink_stale (&self->_storage_by_uuid_lst);

	g_object_unref (self->_plugin);
	g_free (self->_uuid);
	g_free (self->_filename);

	G_OBJECT_CLASS (nm_settings_storage_parent_class)->finalize (object);
}

static void
nm_settings_storage_class_init (NMSettingsStorageClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	obj_properties[PROP_PLUGIN] =
	    g_param_spec_object (NM_SETTINGS_STORAGE_PLUGIN, "", "",
	                         NM_TYPE_SETTINGS_PLUGIN,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_UUID] =
	    g_param_spec_string (NM_SETTINGS_STORAGE_UUID, "", "",
	                         NULL,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_FILENAME] =
	    g_param_spec_string (NM_SETTINGS_STORAGE_FILENAME, "", "",
	                         NULL,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
