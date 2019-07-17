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

#ifndef __NM_SETTINGS_STORAGE_H__
#define __NM_SETTINGS_STORAGE_H__

/*****************************************************************************/

#include "c-list/src/c-list.h"

#define NM_TYPE_SETTINGS_STORAGE            (nm_settings_storage_get_type ())
#define NM_SETTINGS_STORAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTINGS_STORAGE, NMSettingsStorage))
#define NM_SETTINGS_STORAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTINGS_STORAGE, NMSettingsStorageClass))
#define NM_IS_SETTINGS_STORAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTINGS_STORAGE))
#define NM_IS_SETTINGS_STORAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTINGS_STORAGE))
#define NM_SETTINGS_STORAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTINGS_STORAGE, NMSettingsStorageClass))

#define NM_SETTINGS_STORAGE_PLUGIN   "plugin"
#define NM_SETTINGS_STORAGE_UUID     "uuid"
#define NM_SETTINGS_STORAGE_FILENAME "filename"

struct _NMSettingsPlugin;

typedef struct NMSettingsStorage {
	GObject parent;
	struct _NMSettingsPlugin *_plugin;
	char *_uuid;
	char *_filename;
	CList _storage_lst;
	CList _storage_by_uuid_lst;
} NMSettingsStorage;

typedef struct {
	GObjectClass parent;

	int (*cmp_fcn) (NMSettingsStorage *a,
	                NMSettingsStorage *b);

} NMSettingsStorageClass;

GType nm_settings_storage_get_type (void);

NMSettingsStorage *nm_settings_storage_new (struct _NMSettingsPlugin *plugin,
                                            const char *uuid,
                                            const char *filename);

static inline struct _NMSettingsPlugin *
nm_settings_storage_get_plugin (const NMSettingsStorage *self)
{
	GType nm_settings_plugin_get_type (void);

	g_return_val_if_fail (NM_IS_SETTINGS_STORAGE (self), NULL);

	nm_assert (G_TYPE_CHECK_INSTANCE_TYPE (self->_plugin, nm_settings_plugin_get_type ()));
	return self->_plugin;
}

static inline const char *
nm_settings_storage_get_uuid (const NMSettingsStorage *self)
{
	gboolean nm_utils_is_uuid (const char *str);

	g_return_val_if_fail (NM_IS_SETTINGS_STORAGE (self), NULL);

	nm_assert (nm_utils_is_uuid (self->_uuid));
	return self->_uuid;
}

static inline const char *
nm_settings_storage_get_uuid_opt (const NMSettingsStorage *self)
{
	gboolean nm_utils_is_uuid (const char *str);

	g_return_val_if_fail (NM_IS_SETTINGS_STORAGE (self), NULL);

	nm_assert (!self->_uuid || nm_utils_is_uuid (self->_uuid));
	return self->_uuid;
}

static inline const char *
nm_settings_storage_get_filename (const NMSettingsStorage *self)
{
	g_return_val_if_fail (NM_IS_SETTINGS_STORAGE (self), NULL);

	return self->_filename;
}

/*****************************************************************************/

#define nm_assert_valid_settings_storage(plugin, storage) \
	G_STMT_START { \
		NMSettingsPlugin *const _plugin = (plugin); \
		NMSettingsStorage *const _storage = (storage); \
		\
		nm_assert (!_plugin || NM_IS_SETTINGS_PLUGIN (_plugin)); \
		nm_assert (NM_IS_SETTINGS_STORAGE (_storage)); \
		nm_assert (!_plugin || nm_settings_storage_get_plugin (_storage) == _plugin); \
	} G_STMT_END

/*****************************************************************************/

int nm_settings_storage_cmp (NMSettingsStorage *sd_a,
                             NMSettingsStorage *sd_b,
                             const GSList *plugin_list);

#endif /* __NM_SETTINGS_STORAGE_H__ */
