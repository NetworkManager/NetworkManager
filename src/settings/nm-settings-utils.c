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
 * Copyright (C) 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-settings-utils.h"

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "nm-settings-plugin.h"

/*****************************************************************************/

const struct timespec *
nm_sett_util_stat_mtime (const char *filename,
                         gboolean do_lstat,
                         struct timespec *out_val)
{
	struct stat st;
	struct timeval now_tv;

	if (filename) {
		if (do_lstat) {
			if (lstat (filename, &st) == 0) {
				*out_val = st.st_mtim;
				return out_val;
			}
		} else {
			if (stat (filename, &st) == 0) {
				*out_val = st.st_mtim;
				return out_val;
			}
		}
	}

	if (gettimeofday (&now_tv, NULL) == 0) {
		*out_val = (struct timespec) {
			.tv_sec  = now_tv.tv_sec,
			.tv_nsec = now_tv.tv_usec * 1000u,
		};
		return out_val;
	}

	*out_val = (struct timespec) { };
	return out_val;
}

/*****************************************************************************/

gboolean
nm_sett_util_allow_filename_cb (const char *filename,
                                gpointer user_data)
{
	const NMSettUtilAllowFilenameData *allow_filename_data = user_data;

	if (   allow_filename_data->allowed_filename
	    && nm_streq (allow_filename_data->allowed_filename, filename))
		return TRUE;

	return !g_hash_table_contains (allow_filename_data->idx_by_filename, filename);
}

/*****************************************************************************/

void
nm_sett_util_storage_by_uuid_head_destroy (NMSettUtilStorageByUuidHead *sbuh)
{
	CList *iter;

	while ((iter = c_list_first (&sbuh->_storage_by_uuid_lst_head)))
		c_list_unlink (iter);
	g_free (sbuh);
}

/*****************************************************************************/

void
nm_sett_util_storages_clear (NMSettUtilStorages *storages)
{
	nm_clear_pointer (&storages->idx_by_uuid, g_hash_table_destroy);
	nm_clear_pointer (&storages->idx_by_filename, g_hash_table_destroy);
	nm_assert (c_list_is_empty (&storages->_storage_lst_head));
}

void
nm_sett_util_storages_add_take (NMSettUtilStorages *storages,
                                gpointer storage_take_p /* NMSettingsStorage *, take reference */)
{
	NMSettingsStorage *storage_take = storage_take_p;
	NMSettUtilStorageByUuidHead *sbuh;
	const char *uuid;

	nm_assert (storage_take);
	nm_assert (c_list_is_empty (&storage_take->_storage_lst));
	nm_assert (c_list_is_empty (&storage_take->_storage_by_uuid_lst));
	nm_assert (nm_settings_storage_get_filename (storage_take));

	if (!g_hash_table_replace (storages->idx_by_filename,
	                           (char *) nm_settings_storage_get_filename (storage_take),
	                           storage_take /* takes ownership of reference. */))
		nm_assert_not_reached ();

	uuid = nm_settings_storage_get_uuid_opt (storage_take);

	if (uuid) {
		sbuh = nm_sett_util_storages_lookup_by_uuid (storages, uuid);
		if (!sbuh) {
			gsize l = strlen (uuid) + 1;

			sbuh = g_malloc (sizeof (NMSettUtilStorageByUuidHead) + l);
			sbuh->uuid = sbuh->uuid_data;
			c_list_init (&sbuh->_storage_by_uuid_lst_head);
			memcpy (sbuh->uuid_data, uuid, l);
			g_hash_table_add (storages->idx_by_uuid, sbuh);
		}
		c_list_link_tail (&sbuh->_storage_by_uuid_lst_head, &storage_take->_storage_by_uuid_lst);
	}

	c_list_link_tail (&storages->_storage_lst_head, &storage_take->_storage_lst);
}

gpointer /* NMSettingsStorage * */
nm_sett_util_storages_steal (NMSettUtilStorages *storages,
                             gpointer storage_p /* NMSettingsStorage **/)
{
	NMSettingsStorage *storage = storage_p;
	NMSettUtilStorageByUuidHead *sbuh;
	const char *uuid;

	nm_assert (storage);
	nm_assert (nm_sett_util_storages_lookup_by_filename (storages, nm_settings_storage_get_filename (storage)) == storage);
	nm_assert (c_list_contains (&storages->_storage_lst_head, &storage->_storage_lst));

	uuid = nm_settings_storage_get_uuid_opt (storage);

	if (!uuid) {
		nm_assert (c_list_is_empty (&storage->_storage_by_uuid_lst));
	} else {
		nm_assert (!c_list_is_empty (&storage->_storage_by_uuid_lst));

		sbuh = nm_sett_util_storages_lookup_by_uuid (storages, uuid);

		nm_assert (sbuh);
		nm_assert (c_list_contains (&sbuh->_storage_by_uuid_lst_head, &storage->_storage_by_uuid_lst));
		c_list_unlink (&storage->_storage_by_uuid_lst);

		if (c_list_is_empty (&sbuh->_storage_by_uuid_lst_head))
			g_hash_table_remove (storages->idx_by_uuid, sbuh);
	}

	c_list_unlink (&storage->_storage_lst);

	g_hash_table_steal (storages->idx_by_filename, nm_settings_storage_get_filename (storage));

	return storage;
}
