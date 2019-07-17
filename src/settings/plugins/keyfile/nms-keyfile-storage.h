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
	NMSettingsStorage parent;

	/* The connection. Note that there are tombstones (loaded-uuid files to /dev/null)
	 * that don't have a connection.
	 *
	 * Also, we don't actually remember the loaded connection after returning it
	 * to NMSettings. So, also for regular storages (non-tombstones) this field
	 * is often cleared. */
	NMConnection *connection;

	NMSKeyfileStorageType storage_type;

	/* the timestamp (stat's mtime) of the keyfile. For tombstones this
	 * is irrelevant. The purpose is that if the same storage type (directory) has
	 * multiple files with the same UUID, then the newer file gets preferred. */
	struct timespec stat_mtime;

	/* these flags are only relevant for storages with %NMS_KEYFILE_STORAGE_TYPE_RUN
	 * (and non-tombstones). This is to persist and reload these settings flags to
	 * /run. */
	bool is_nm_generated:1;
	bool is_volatile:1;

	/* whether this is a tombstone to hide a UUID (via the loaded uuid symlinks).
	 * If this is falls, the storage contains a profile, though note that
	 * the connection field will be cleared when it's not used. So, a non-tombstone
	 * has a connection in principle, but the connection field may still be %NULL.
	 *
	 * Note that a tombstone instance doesn't have a connection, but NMSettings
	 * considers it alive because is_tombstone is %TRUE. That means, once a tombstone
	 * gets removed, this flag is cleared. Then the storage instance has no connnection
	 * and is no longer a tombstone, and NMSettings considers it ready for deletion.
	 */
	bool is_tombstone:1;

	/* this flag is only used during reload to mark and prune old entries. */
	bool dirty:1;

} NMSKeyfileStorage;

typedef struct _NMSKeyfileStorageClass NMSKeyfileStorageClass;

GType nms_keyfile_storage_get_type (void);

struct _NMSKeyfilePlugin;

NMSKeyfileStorage *nms_keyfile_storage_new_tombstone (struct _NMSKeyfilePlugin *self,
                                                      const char *uuid,
                                                      const char *filename,
                                                      NMSKeyfileStorageType storage_type);

NMSKeyfileStorage *nms_keyfile_storage_new_connection (struct _NMSKeyfilePlugin *self,
                                                       NMConnection *connection_take /* pass reference */,
                                                       const char *filename,
                                                       NMSKeyfileStorageType storage_type,
                                                       NMTernary is_nm_generated_opt,
                                                       NMTernary is_volatile_opt,
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

static inline gboolean
nm_settings_storage_is_keyfile_tombstone (const NMSettingsStorage *self)
{
	/* Only keyfile storage supports tombstones. They indicate that a uuid
	 * is shadowed via a symlink to /dev/null.
	 *
	 * Note that tombstones don't have a NMConnection instead they shadow
	 * a UUID. As such, NMSettings considers them alive also if they have
	 * not profile. That means, when a tombstone gets removed for good,
	 * the is_tombstone must be cleared (so that it becomes truly dead). */
	return    NMS_IS_KEYFILE_STORAGE (self)
	       && ((NMSKeyfileStorage *) self)->is_tombstone;
}

/*****************************************************************************/

enum _NMSettingsConnectionIntFlags;

void nm_settings_storage_load_sett_flags (NMSettingsStorage *self,
                                          enum _NMSettingsConnectionIntFlags *sett_flags,
                                          enum _NMSettingsConnectionIntFlags *sett_mask);

#endif /* __NMS_KEYFILE_STORAGE_H__ */
