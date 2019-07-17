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
	nm_assert (nms_keyfile_storage_get_filename (dst) && nm_streq (nms_keyfile_storage_get_filename (dst), nms_keyfile_storage_get_filename (src)));

	nm_g_object_ref_set (&dst->connection, src->connection);
	dst->storage_type     = src->storage_type;
	dst->stat_mtime       = src->stat_mtime;
	dst->is_nm_generated  = src->is_nm_generated;
	dst->is_volatile      = src->is_volatile;
	dst->is_tombstone     = src->is_tombstone;
}

NMConnection *
nms_keyfile_storage_steal_connection (NMSKeyfileStorage *self)
{
	nm_assert (NMS_IS_KEYFILE_STORAGE (self));
	nm_assert (NM_IS_CONNECTION (self->connection));

	return g_steal_pointer (&self->connection);
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

	/* tombstones are more important. */
	nm_assert (a->is_tombstone == nm_settings_storage_is_keyfile_tombstone (NM_SETTINGS_STORAGE (a)));
	nm_assert (b->is_tombstone == nm_settings_storage_is_keyfile_tombstone (NM_SETTINGS_STORAGE (b)));
	NM_CMP_FIELD_UNSAFE (a, b, is_tombstone);

	/* newer files are more important. */
	NM_CMP_FIELD (b, a, stat_mtime.tv_sec);
	NM_CMP_FIELD (b, a, stat_mtime.tv_nsec);

	NM_CMP_DIRECT_STRCMP (nms_keyfile_storage_get_filename (a), nms_keyfile_storage_get_filename (b));

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
              const char *filename)
{
	nm_assert (NMS_IS_KEYFILE_PLUGIN (plugin));
	nm_assert (nm_utils_is_uuid (uuid));
	nm_assert (filename && filename[0] == '/');

	return g_object_new (NMS_TYPE_KEYFILE_STORAGE,
	                     NM_SETTINGS_STORAGE_PLUGIN, plugin,
	                     NM_SETTINGS_STORAGE_UUID, uuid,
	                     NM_SETTINGS_STORAGE_FILENAME, filename,
	                     NULL);
}

NMSKeyfileStorage *
nms_keyfile_storage_new_tombstone (NMSKeyfilePlugin *plugin,
                                   const char *uuid,
                                   const char *filename,
                                   NMSKeyfileStorageType storage_type)
{
	NMSKeyfileStorage *self;

	nm_assert (nm_utils_is_uuid (uuid));
	nm_assert (filename && filename[0] == '/');
	nm_assert (nms_keyfile_nmmeta_check_filename (filename, NULL));
	nm_assert (NM_IN_SET (storage_type, NMS_KEYFILE_STORAGE_TYPE_ETC,
	                                    NMS_KEYFILE_STORAGE_TYPE_RUN));

	self = _storage_new (plugin, uuid, filename);

	self->is_tombstone = TRUE;

	self->storage_type = storage_type;

	return self;
}

NMSKeyfileStorage *
nms_keyfile_storage_new_connection (NMSKeyfilePlugin *plugin,
                                    NMConnection *connection_take /* pass reference */,
                                    const char *filename,
                                    NMSKeyfileStorageType storage_type,
                                    NMTernary is_nm_generated_opt,
                                    NMTernary is_volatile_opt,
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

	self = _storage_new (plugin, nm_connection_get_uuid (connection_take), filename);

	self->connection = connection_take; /* take reference. */

	if (storage_type == NMS_KEYFILE_STORAGE_TYPE_RUN) {
		self->is_nm_generated = (is_nm_generated_opt == NM_TERNARY_TRUE);
		self->is_volatile     = (is_volatile_opt == NM_TERNARY_TRUE);
	}

	if (stat_mtime)
		self->stat_mtime = *stat_mtime;

	self->storage_type = storage_type;

	return self;
}

static void
_storage_clear (NMSKeyfileStorage *self)
{
	c_list_unlink (&self->parent._storage_lst);
	c_list_unlink (&self->parent._storage_by_uuid_lst);
	g_clear_object (&self->connection);
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
	if (s->storage_type != NMS_KEYFILE_STORAGE_TYPE_RUN)
		return;

	if (s->is_nm_generated)
		*sett_flags |= NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED;

	if (s->is_volatile)
		*sett_flags |= NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE;
}
