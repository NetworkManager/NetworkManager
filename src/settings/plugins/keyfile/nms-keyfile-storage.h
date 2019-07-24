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

#ifndef __NMS_KEYFILE_STORAGE_H__
#define __NMS_KEYFILE_STORAGE_H__

#include "c-list/src/c-list.h"
#include "settings/nm-settings-storage.h"
#include "nms-keyfile-utils.h"

/*****************************************************************************/

#define NMS_TYPE_KEYFILE_STORAGE            (nms_keyfile_storage_get_type ())
#define NMS_KEYFILE_STORAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMS_TYPE_KEYFILE_STORAGE, NMSKeyfileStorage))
#define NMS_KEYFILE_STORAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMS_TYPE_KEYFILE_STORAGE, NMSKeyfileStorageClass))
#define NMS_IS_KEYFILE_STORAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMS_TYPE_KEYFILE_STORAGE))
#define NMS_IS_KEYFILE_STORAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMS_TYPE_KEYFILE_STORAGE))
#define NMS_KEYFILE_STORAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMS_TYPE_KEYFILE_STORAGE, NMSKeyfileStorageClass))

typedef struct {
	/* whether this is a tombstone to hide a UUID (via symlink to /dev/null). */
	char *shadowed_storage;
	bool is_tombstone:1;
} NMSettingsMetaData;

typedef struct {
	NMSettingsStorage parent;

	/* The connection. Note that there are tombstones (loaded-uuid files to /dev/null)
	 * that don't have a connection.
	 *
	 * Also, we don't actually remember the loaded connection after returning it
	 * to NMSettings. So, also for regular storages (non-tombstones) this field
	 * is often cleared. */
	union {
		struct {
			NMConnection *connection;

			/* when we move a profile from permanent storage to unsaved (/run), then
			 * we may leave the profile on disk (depending on options for Update2()).
			 *
			 * Later, when we save the profile again to disk, we want to re-use that filename.
			 * Likewise, we delete the (now in-memory) profile, we may want to also delete
			 * the original filename.
			 *
			 * This is the original filename, and we store it inside [.nmmeta] in the
			 * keyfile in /run. Note that we don't store this in the .nmmeta file, because
			 * the information is tied to the particular keyfile in /run, not to all UUIDs
			 * in general. */
			char *shadowed_storage;

			/* the timestamp (stat's mtime) of the keyfile. For meta-data this
			 * is irrelevant. The purpose is that if the same storage type (directory) has
			 * multiple files with the same UUID, then the newer file gets preferred. */
			struct timespec stat_mtime;

			/* these flags are only relevant for storages with %NMS_KEYFILE_STORAGE_TYPE_RUN
			 * (and non-metadata). This is to persist and reload these settings flags to
			 * /run.
			 *
			 * Note that these flags are not stored in as meta-data. The reason is that meta-data
			 * is per UUID. But these flags are only relevant for a particular keyfile on disk.
			 * That is, it must be tied to the actual keyfile, and not to the UUID. */
			bool is_nm_generated:1;
			bool is_volatile:1;

			/* if shadowed_storage is set, then this flag indicates whether the file
			 * is owned. The difference comes into play when deleting the in-memory,
			 * shadowing profile: a owned profile will also be deleted. */
			bool shadowed_owned:1;

		} conn_data;

		/* the content from the .nmmeta file. Note that the nmmeta file has the UUID
		 * in the filename, that means there can be only two variants of this file:
		 * in /etc and in /run. As such, this is really meta-data about the entire profile
		 * (the UUID), and not about the individual keyfile. */
		NMSettingsMetaData meta_data;

	} u;

	/* The storage type. This is directly related to the filename. Since
	 * the filename cannot change, this value is unchanging. */
	const NMSKeyfileStorageType storage_type;

	/* whether union "u" has meta_data or conn_data. Since the type of the storage
	 * depends on the (immutable) filename, this is also const. */
	const bool is_meta_data;

	/* this flag is only used during reload to mark and prune old entries. */
	bool is_dirty:1;

} NMSKeyfileStorage;

typedef struct _NMSKeyfileStorageClass NMSKeyfileStorageClass;

GType nms_keyfile_storage_get_type (void);

struct _NMSKeyfilePlugin;

NMSKeyfileStorage *nms_keyfile_storage_new_tombstone (struct _NMSKeyfilePlugin *self,
                                                      const char *uuid,
                                                      const char *filename,
                                                      NMSKeyfileStorageType storage_type,
                                                      const char *shadowed_storage);

NMSKeyfileStorage *nms_keyfile_storage_new_connection (struct _NMSKeyfilePlugin *self,
                                                       NMConnection *connection_take /* pass reference */,
                                                       const char *filename,
                                                       NMSKeyfileStorageType storage_type,
                                                       NMTernary is_nm_generated_opt,
                                                       NMTernary is_volatile_opt,
                                                       const char *shadowed_storage,
                                                       NMTernary shadowed_owned_opt,
                                                       const struct timespec *stat_mtime);

void nms_keyfile_storage_destroy (NMSKeyfileStorage *storage);

/*****************************************************************************/

void nms_keyfile_storage_copy_content (NMSKeyfileStorage *dst,
                                       const NMSKeyfileStorage *src);

NMConnection *nms_keyfile_storage_steal_connection (NMSKeyfileStorage *storage);

/*****************************************************************************/

static inline const char *
nms_keyfile_storage_get_uuid (const NMSKeyfileStorage *self)
{
	return nm_settings_storage_get_uuid ((const NMSettingsStorage *) self);
}

static inline const char *
nms_keyfile_storage_get_filename (const NMSKeyfileStorage *self)
{
	return nm_settings_storage_get_filename ((const NMSettingsStorage *) self);
}

/*****************************************************************************/

static inline gboolean
nm_settings_storage_is_keyfile_run (const NMSettingsStorage *self)
{
	return    NMS_IS_KEYFILE_STORAGE (self)
	       && (((NMSKeyfileStorage *) self)->storage_type == NMS_KEYFILE_STORAGE_TYPE_RUN);
}

static inline gboolean
nm_settings_storage_is_keyfile_lib (const NMSettingsStorage *self)
{
	return    NMS_IS_KEYFILE_STORAGE (self)
	       && (((NMSKeyfileStorage *) self)->storage_type >= NMS_KEYFILE_STORAGE_TYPE_LIB_BASE);
}

static inline const NMSettingsMetaData *
nm_settings_storage_is_meta_data (const NMSettingsStorage *storage)
{
	const NMSKeyfileStorage *self;

	if (!NMS_IS_KEYFILE_STORAGE (storage))
		return NULL;

	self = (NMSKeyfileStorage *) storage;

	if (!self->is_meta_data)
		return NULL;

	return &self->u.meta_data;
}

static inline const NMSettingsMetaData *
nm_settings_storage_is_meta_data_alive (const NMSettingsStorage *storage)
{
	const NMSettingsMetaData *meta_data;

	meta_data = nm_settings_storage_is_meta_data (storage);

	if (!meta_data)
		return NULL;

	/* Regular (all other) storages are alive as long as they report a NMConnection, and
	 * they will be dropped, once they have no more connection.
	 *
	 * Meta-data storages are special: they never report a NMConnection.
	 * So, a meta-data storage is alive as long as it is tracked by the
	 * settings plugin.
	 *
	 * This function is used to ckeck for that. */

	if (c_list_is_empty (&storage->_storage_lst))
		return NULL;

	return meta_data;
}

static inline const char *
nm_settings_storage_get_shadowed_storage (const NMSettingsStorage *storage,
                                          gboolean *out_shadowed_owned)
{
	if (NMS_IS_KEYFILE_STORAGE (storage)) {
		const NMSKeyfileStorage *self = (const NMSKeyfileStorage *) storage;

		if (self->storage_type == NMS_KEYFILE_STORAGE_TYPE_RUN) {
			if (!self->is_meta_data) {
				if (self->u.conn_data.shadowed_storage) {
					NM_SET_OUT (out_shadowed_owned, self->u.conn_data.shadowed_owned);
					return self->u.conn_data.shadowed_storage;
				}
			} else {
				NM_SET_OUT (out_shadowed_owned, FALSE);
				return self->u.meta_data.shadowed_storage;
			}
		}
	}

	NM_SET_OUT (out_shadowed_owned, FALSE);
	return NULL;
}

static inline const char *
nm_settings_storage_get_filename_for_shadowed_storage (const NMSettingsStorage *storage)
{
	g_return_val_if_fail (NM_IS_SETTINGS_STORAGE (storage), NULL);

	if (!storage->_filename)
		return NULL;

	if (NMS_IS_KEYFILE_STORAGE (storage)) {
		const NMSKeyfileStorage *self = (const NMSKeyfileStorage *) storage;

		if (   self->is_meta_data
		    || self->storage_type != NMS_KEYFILE_STORAGE_TYPE_ETC)
			return NULL;
	}

	return storage->_filename;
}

/*****************************************************************************/

enum _NMSettingsConnectionIntFlags;

void nm_settings_storage_load_sett_flags (NMSettingsStorage *self,
                                          enum _NMSettingsConnectionIntFlags *sett_flags,
                                          enum _NMSettingsConnectionIntFlags *sett_mask);

#endif /* __NMS_KEYFILE_STORAGE_H__ */
