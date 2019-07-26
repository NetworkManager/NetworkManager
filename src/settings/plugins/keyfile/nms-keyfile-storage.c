/* NetworkManager system settings service - keyfile plugin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nms-keyfile-storage.h"

#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nms-keyfile-plugin.h"

/*****************************************************************************/

struct _NMSKeyfileStorageClass {
	NMSettingsStorageClass parent;
};

G_DEFINE_TYPE (NMSKeyfileStorage, nms_keyfile_storage, NM_TYPE_SETTINGS_STORAGE)

/*****************************************************************************/

void
nms_keyfile_storage_copy_content (NMSKeyfileStorage *dst,
                                  const NMSKeyfileStorage *src)
{
	nm_assert (src != dst);
	nm_assert (nm_streq (nms_keyfile_storage_get_uuid (dst), nms_keyfile_storage_get_uuid (src)));
	nm_assert (   nms_keyfile_storage_get_filename (dst)
	           && nm_streq (nms_keyfile_storage_get_filename (dst), nms_keyfile_storage_get_filename (src)));
	nm_assert (dst->storage_type == src->storage_type);
	nm_assert (dst->is_meta_data == src->is_meta_data);

	if (dst->is_meta_data) {
		gs_free char *shadowed_storage_to_free = NULL;

		shadowed_storage_to_free = g_steal_pointer (&dst->u.meta_data.shadowed_storage);
		dst->u.meta_data = src->u.meta_data;
		dst->u.meta_data.shadowed_storage = g_strdup (dst->u.meta_data.shadowed_storage);
	} else {
		gs_unref_object NMConnection *connection_to_free = NULL;
		gs_free char *shadowed_storage_to_free = NULL;

		connection_to_free = g_steal_pointer (&dst->u.conn_data.connection);
		shadowed_storage_to_free = g_steal_pointer (&dst->u.conn_data.shadowed_storage);
		dst->u.conn_data = src->u.conn_data;
		nm_g_object_ref (dst->u.conn_data.connection);
		dst->u.conn_data.shadowed_storage = g_strdup (dst->u.conn_data.shadowed_storage);
	}
}

NMConnection *
nms_keyfile_storage_steal_connection (NMSKeyfileStorage *self)
{
	nm_assert (NMS_IS_KEYFILE_STORAGE (self));
	nm_assert (   self->is_meta_data
	           || NM_IS_CONNECTION (self->u.conn_data.connection));

	return   self->is_meta_data
	       ? NULL
	       : g_steal_pointer (&self->u.conn_data.connection);
}

/*****************************************************************************/

static int
cmp_fcn (const NMSKeyfileStorage *a,
         const NMSKeyfileStorage *b)
{
	nm_assert (NMS_IS_KEYFILE_STORAGE (a));
	nm_assert (NMS_IS_KEYFILE_STORAGE (b));
	nm_assert (a != b);

	/* sort by storage-type, which also has a numeric value according to their
	 * (inverse) priority. */
	NM_CMP_FIELD_UNSAFE (b, a, storage_type);

	/* meta-data is more important. */
	NM_CMP_FIELD_UNSAFE (a, b, is_meta_data);

	if (a->is_meta_data) {
		nm_assert (nm_streq (nms_keyfile_storage_get_filename (a), nms_keyfile_storage_get_filename (b)));
		NM_CMP_FIELD_UNSAFE (a, b, u.meta_data.is_tombstone);
	} else {
		/* newer files are more important. */
		NM_CMP_FIELD (a, b, u.conn_data.stat_mtime.tv_sec);
		NM_CMP_FIELD (a, b, u.conn_data.stat_mtime.tv_nsec);

		NM_CMP_DIRECT_STRCMP (nms_keyfile_storage_get_filename (a), nms_keyfile_storage_get_filename (b));
	}

	return 0;
}

/*****************************************************************************/

static void
nms_keyfile_storage_init (NMSKeyfileStorage *self)
{
}

static NMSKeyfileStorage *
_storage_new (NMSKeyfilePlugin *plugin,
              const char *uuid,
              const char *filename,
              gboolean is_meta_data,
              NMSKeyfileStorageType storage_type)

{
	NMSKeyfileStorage *self;

	nm_assert (NMS_IS_KEYFILE_PLUGIN (plugin));
	nm_assert (nm_utils_is_uuid (uuid));
	nm_assert (filename && filename[0] == '/');

	self = g_object_new (NMS_TYPE_KEYFILE_STORAGE,
	                     NM_SETTINGS_STORAGE_PLUGIN, plugin,
	                     NM_SETTINGS_STORAGE_UUID, uuid,
	                     NM_SETTINGS_STORAGE_FILENAME, filename,
	                     NULL);

	*((bool *) &self->is_meta_data) = is_meta_data;
	*((NMSKeyfileStorageType *) &self->storage_type) = storage_type;

	return self;
}

NMSKeyfileStorage *
nms_keyfile_storage_new_tombstone (NMSKeyfilePlugin *plugin,
                                   const char *uuid,
                                   const char *filename,
                                   NMSKeyfileStorageType storage_type,
                                   const char *shadowed_storage)
{
	NMSKeyfileStorage *self;

	nm_assert (nm_utils_is_uuid (uuid));
	nm_assert (filename && filename[0] == '/');
	nm_assert (nms_keyfile_nmmeta_check_filename (filename, NULL));
	nm_assert (NM_IN_SET (storage_type, NMS_KEYFILE_STORAGE_TYPE_ETC,
	                                    NMS_KEYFILE_STORAGE_TYPE_RUN));

	self = _storage_new (plugin, uuid, filename, TRUE, storage_type);
	self->u.meta_data.is_tombstone = TRUE;
	if (storage_type == NMS_KEYFILE_STORAGE_TYPE_RUN)
		self->u.meta_data.shadowed_storage = g_strdup (shadowed_storage);
	return self;
}

NMSKeyfileStorage *
nms_keyfile_storage_new_connection (NMSKeyfilePlugin *plugin,
                                    NMConnection *connection_take /* pass reference */,
                                    const char *filename,
                                    NMSKeyfileStorageType storage_type,
                                    NMTernary is_nm_generated_opt,
                                    NMTernary is_volatile_opt,
                                    const char *shadowed_storage,
                                    NMTernary shadowed_owned_opt,
                                    const struct timespec *stat_mtime)
{
	NMSKeyfileStorage *self;

	nm_assert (NMS_IS_KEYFILE_PLUGIN (plugin));
	nm_assert (NM_IS_CONNECTION (connection_take));
	nm_assert (_nm_connection_verify (connection_take, NULL) == NM_SETTING_VERIFY_SUCCESS);
	nm_assert (filename && filename[0] == '/');
	nm_assert (   storage_type >= NMS_KEYFILE_STORAGE_TYPE_RUN
	           && storage_type <= _NMS_KEYFILE_STORAGE_TYPE_LIB_LAST);
	nmtst_connection_assert_unchanging (connection_take);

	self = _storage_new (plugin, nm_connection_get_uuid (connection_take), filename, FALSE, storage_type);

	self->u.conn_data.connection = connection_take; /* take reference. */

	self->u.conn_data.shadowed_storage = g_strdup (shadowed_storage);

	if (stat_mtime)
		self->u.conn_data.stat_mtime = *stat_mtime;

	if (storage_type == NMS_KEYFILE_STORAGE_TYPE_RUN) {
		self->u.conn_data.is_nm_generated = (is_nm_generated_opt == NM_TERNARY_TRUE);
		self->u.conn_data.is_volatile     = (is_volatile_opt == NM_TERNARY_TRUE);
		self->u.conn_data.shadowed_owned  =    shadowed_storage
		                                    && (shadowed_owned_opt == NM_TERNARY_TRUE);
	}

	return self;
}

static void
_storage_clear (NMSKeyfileStorage *self)
{
	c_list_unlink (&self->parent._storage_lst);
	c_list_unlink (&self->parent._storage_by_uuid_lst);
	if (self->is_meta_data)
		nm_clear_g_free (&self->u.meta_data.shadowed_storage);
	else {
		g_clear_object (&self->u.conn_data.connection);
		nm_clear_g_free (&self->u.conn_data.shadowed_storage);
		self->u.conn_data.shadowed_owned = FALSE;
	}
}

static void
dispose (GObject *object)
{
	NMSKeyfileStorage *self = NMS_KEYFILE_STORAGE (object);

	_storage_clear (self);

	G_OBJECT_CLASS (nms_keyfile_storage_parent_class)->dispose (object);
}

void
nms_keyfile_storage_destroy (NMSKeyfileStorage *self)
{
	_storage_clear (self);
	g_object_unref (self);
}

static void
nms_keyfile_storage_class_init (NMSKeyfileStorageClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingsStorageClass *storage_class = NM_SETTINGS_STORAGE_CLASS (klass);

	object_class->dispose = dispose;

	storage_class->cmp_fcn = (int (*) (NMSettingsStorage *, NMSettingsStorage *)) cmp_fcn;
}

/*****************************************************************************/

#include "settings/nm-settings-connection.h"

void
nm_settings_storage_load_sett_flags (NMSettingsStorage *self,
                                     NMSettingsConnectionIntFlags *sett_flags,
                                     NMSettingsConnectionIntFlags *sett_mask)
{
	NMSKeyfileStorage *s;

	*sett_flags = NM_SETTINGS_CONNECTION_INT_FLAGS_NONE;
	*sett_mask =   NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
	             | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE;

	if (!NMS_IS_KEYFILE_STORAGE (self))
		return;

	s = NMS_KEYFILE_STORAGE (self);

	if (s->is_meta_data)
		return;
	if (s->storage_type != NMS_KEYFILE_STORAGE_TYPE_RUN)
		return;

	if (s->u.conn_data.is_nm_generated)
		*sett_flags |= NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED;

	if (s->u.conn_data.is_volatile)
		*sett_flags |= NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE;
}
