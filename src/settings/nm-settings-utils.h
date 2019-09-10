// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright 2019 Red Hat, Inc.
 */

#ifndef __NM_SETTINGS_UTILS_H__
#define __NM_SETTINGS_UTILS_H__

#include "nm-settings-storage.h"

/*****************************************************************************/

struct timespec;

const struct timespec *nm_sett_util_stat_mtime (const char *filename,
                                                gboolean do_lstat,
                                                struct timespec *out_val);

/*****************************************************************************/

typedef struct {
	const char *uuid;

	CList _storage_by_uuid_lst_head;

	char uuid_data[];
} NMSettUtilStorageByUuidHead;

typedef struct {
	CList _storage_lst_head;
	GHashTable *idx_by_filename;
	GHashTable *idx_by_uuid;
} NMSettUtilStorages;

void nm_sett_util_storage_by_uuid_head_destroy (NMSettUtilStorageByUuidHead *sbuh);

#define NM_SETT_UTIL_STORAGES_INIT(storages, storage_destroy_fcn) \
	{ \
		._storage_lst_head = C_LIST_INIT (((storages)._storage_lst_head)), \
		.idx_by_filename   = g_hash_table_new_full (nm_str_hash, \
		                                            g_str_equal, \
		                                            NULL, \
		                                            (GDestroyNotify) storage_destroy_fcn), \
		.idx_by_uuid       = g_hash_table_new_full (nm_pstr_hash, \
		                                            nm_pstr_equal, \
		                                            NULL, \
		                                            (GDestroyNotify) nm_sett_util_storage_by_uuid_head_destroy), \
	}

void nm_sett_util_storages_clear (NMSettUtilStorages *storages);

#define nm_auto_clear_sett_util_storages nm_auto(nm_sett_util_storages_clear)

void nm_sett_util_storages_add_take (NMSettUtilStorages *storages,
                                     gpointer storage_take_p);

gpointer nm_sett_util_storages_steal (NMSettUtilStorages *storages,
                                      gpointer storage_p);

/*****************************************************************************/

static inline gpointer /* NMSettingsStorage * */
nm_sett_util_storages_lookup_by_filename (NMSettUtilStorages *storages,
                                          const char *filename)
{
	nm_assert (filename);

	return g_hash_table_lookup (storages->idx_by_filename, filename);
}

static inline NMSettUtilStorageByUuidHead *
nm_sett_util_storages_lookup_by_uuid (NMSettUtilStorages *storages,
                                      const char *uuid)
{
	nm_assert (uuid);

	return g_hash_table_lookup (storages->idx_by_uuid, &uuid);
}

/*****************************************************************************/

typedef struct {
	GHashTable *idx_by_filename;
	const char *allowed_filename;
} NMSettUtilAllowFilenameData;

#define NM_SETT_UTIL_ALLOW_FILENAME_DATA(_storages, _allowed_filename) \
    (&((NMSettUtilAllowFilenameData) { \
       .idx_by_filename  = (_storages)->idx_by_filename, \
       .allowed_filename = (_allowed_filename), \
    }))

gboolean nm_sett_util_allow_filename_cb (const char *filename,
                                         gpointer user_data);

#endif /* __NM_SETTINGS_UTILS_H__ */
