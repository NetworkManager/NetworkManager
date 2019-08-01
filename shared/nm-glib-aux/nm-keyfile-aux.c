/* NetworkManager -- Network link manager
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
 * (C) Copyright 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-keyfile-aux.h"

#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "nm-io-utils.h"

/*****************************************************************************/

struct _NMKeyFileDB {
	NMKeyFileDBLogFcn log_fcn;
	NMKeyFileDBGotDirtyFcn got_dirty_fcn;
	gpointer user_data;
	const char *group_name;
	GKeyFile *kf;
	guint ref_count;

	bool is_started:1;
	bool dirty:1;
	bool destroyed:1;

	char filename[];
};

#define _NMLOG(self, \
               syslog_level, \
               fmt, \
               ...) \
	G_STMT_START { \
		NMKeyFileDB *_self = (self); \
		\
		nm_assert (_self); \
		nm_assert (!_self->destroyed); \
		\
		if (_self->log_fcn) { \
			_self->log_fcn (_self, \
			                (syslog_level), \
			                _self->user_data, \
			                ""fmt"", \
			                ##__VA_ARGS__); \
		}; \
	} G_STMT_END

#define _LOGD(...) _NMLOG (self, LOG_DEBUG, __VA_ARGS__)

static gboolean
_IS_KEY_FILE_DB (NMKeyFileDB *self, gboolean require_is_started, gboolean allow_destroyed)
{
	if (self == NULL)
		return FALSE;
	if (self->ref_count <= 0) {
		nm_assert_not_reached ();
		return FALSE;
	}
	if (   require_is_started
	    && !self->is_started)
		return FALSE;
	if (   !allow_destroyed
	    && self->destroyed)
		return FALSE;
	return TRUE;
}

/*****************************************************************************/

NMKeyFileDB *
nm_key_file_db_new (const char *filename,
                    const char *group_name,
                    NMKeyFileDBLogFcn log_fcn,
                    NMKeyFileDBGotDirtyFcn got_dirty_fcn,
                    gpointer user_data)
{
	NMKeyFileDB *self;
	gsize l_filename;
	gsize l_group;

	g_return_val_if_fail (filename && filename[0], NULL);
	g_return_val_if_fail (group_name && group_name[0], NULL);

	l_filename = strlen (filename);
	l_group = strlen (group_name);

	self = g_malloc0 (sizeof (NMKeyFileDB) + l_filename + 1 + l_group + 1);
	self->ref_count = 1;
	self->log_fcn = log_fcn;
	self->got_dirty_fcn = got_dirty_fcn;
	self->user_data = user_data;
	self->kf = g_key_file_new ();
	g_key_file_set_list_separator (self->kf, ',');
	memcpy (self->filename, filename, l_filename + 1);
	self->group_name = &self->filename[l_filename + 1];
	memcpy ((char *) self->group_name, group_name, l_group + 1);

	return self;
}

NMKeyFileDB *
nm_key_file_db_ref (NMKeyFileDB *self)
{
	if (!self)
		return NULL;

	g_return_val_if_fail (_IS_KEY_FILE_DB (self, FALSE, TRUE), NULL);

	nm_assert (self->ref_count < G_MAXUINT);
	self->ref_count++;
	return self;
}

void
nm_key_file_db_unref (NMKeyFileDB *self)
{
	if (!self)
		return;

	g_return_if_fail (_IS_KEY_FILE_DB (self, FALSE, TRUE));

	if (--self->ref_count > 0)
		return;

	g_key_file_unref (self->kf);

	g_free (self);
}

/* destroy() is like unref, but it also makes the instance unusable.
 * All changes afterwards fail with an assertion.
 *
 * The point is that NMKeyFileDB is ref-counted in principle. But there
 * is a primary owner who also provides the log_fcn().
 *
 * When the primary owner goes out of scope and gives up the reference, it does
 * not want to receive any log notifications anymore.
 *
 * The way NMKeyFileDB is intended to be used is in a very strict context:
 * NMSettings owns the NMKeyFileDB instance and receives logging notifications.
 * It's also the last one to persist the data to disk. Afterwards, no other user
 * is supposed to be around and do anything with NMKeyFileDB. But since NMKeyFileDB
 * is ref-counted it's hard to ensure that this is truly honored. So we start
 * asserting at that point.
 */
void
nm_key_file_db_destroy (NMKeyFileDB *self)
{
	if (!self)
		return;

	g_return_if_fail (_IS_KEY_FILE_DB (self, FALSE, FALSE));
	g_return_if_fail (!self->destroyed);

	self->destroyed = TRUE;
	nm_key_file_db_unref (self);
}

/*****************************************************************************/

/* nm_key_file_db_start() is supposed to be called right away, after creating the
 * instance.
 *
 * It's not done as separate step after nm_key_file_db_new(), because we want to log,
 * and the log_fcn returns the self pointer (which we should not expose before
 * nm_key_file_db_new() returns. */
void
nm_key_file_db_start (NMKeyFileDB *self)
{
	int r;
	gs_free char *contents = NULL;
	gsize contents_len;
	gs_free_error GError *error = NULL;

	g_return_if_fail (_IS_KEY_FILE_DB (self, FALSE, FALSE));
	g_return_if_fail (!self->is_started);

	self->is_started = TRUE;

	r = nm_utils_file_get_contents (-1,
	                                self->filename,
	                                20*1024*1024,
	                                NM_UTILS_FILE_GET_CONTENTS_FLAG_NONE,
	                                &contents,
	                                &contents_len,
	                                &error);
	if (r < 0) {
		_LOGD ("failed to read \"%s\": %s", self->filename, error->message);
		return;
	}

	if (!g_key_file_load_from_data (self->kf,
	                                contents,
	                                contents_len,
	                                G_KEY_FILE_KEEP_COMMENTS,
	                                &error)) {
		_LOGD ("failed to load keyfile \"%s\": %s", self->filename, error->message);
		return;
	}

	_LOGD ("loaded keyfile-db for \"%s\"", self->filename);
}

/*****************************************************************************/

const char *
nm_key_file_db_get_filename (NMKeyFileDB *self)
{
	g_return_val_if_fail (_IS_KEY_FILE_DB (self, FALSE, TRUE), NULL);

	return self->filename;
}

gboolean
nm_key_file_db_is_dirty (NMKeyFileDB *self)
{
	g_return_val_if_fail (_IS_KEY_FILE_DB (self, FALSE, TRUE), FALSE);

	return self->dirty;
}

/*****************************************************************************/

char *
nm_key_file_db_get_value (NMKeyFileDB *self,
                          const char *key)
{
	g_return_val_if_fail (_IS_KEY_FILE_DB (self, TRUE, TRUE), NULL);

	return g_key_file_get_value (self->kf, self->group_name, key, NULL);
}

char **
nm_key_file_db_get_string_list (NMKeyFileDB *self,
                                const char *key,
                                gsize *out_len)
{
	g_return_val_if_fail (_IS_KEY_FILE_DB (self, TRUE, TRUE), NULL);

	return g_key_file_get_string_list (self->kf, self->group_name, key, out_len, NULL);
}

/*****************************************************************************/

static void
_got_dirty (NMKeyFileDB *self,
            const char *key)
{
	nm_assert (_IS_KEY_FILE_DB (self, TRUE, FALSE));
	nm_assert (!self->dirty);

	_LOGD ("updated entry for %s.%s", self->group_name, key);

	self->dirty = TRUE;
	if (self->got_dirty_fcn)
		self->got_dirty_fcn (self, self->user_data);
}

/*****************************************************************************/

void
nm_key_file_db_remove_key (NMKeyFileDB *self,
                           const char *key)
{
	gboolean got_dirty = FALSE;

	g_return_if_fail (_IS_KEY_FILE_DB (self, TRUE, FALSE));

	if (!key)
		return;

	if (!self->dirty) {
		gs_free_error GError *error = NULL;

		g_key_file_has_key (self->kf, self->group_name, key, &error);
		got_dirty = (error != NULL);
	}
	g_key_file_remove_key (self->kf, self->group_name, key, NULL);

	if (got_dirty)
		_got_dirty (self, key);
}

void
nm_key_file_db_set_value (NMKeyFileDB *self,
                          const char *key,
                          const char *value)
{
	gs_free char *old_value = NULL;
	gboolean got_dirty = FALSE;

	g_return_if_fail (_IS_KEY_FILE_DB (self, TRUE, FALSE));
	g_return_if_fail (key);

	if (!value) {
		nm_key_file_db_remove_key (self, key);
		return;
	}

	if (!self->dirty) {
		gs_free_error GError *error = NULL;

		old_value = g_key_file_get_value (self->kf, self->group_name, key, &error);
		if (error)
			got_dirty = TRUE;
	}

	g_key_file_set_value (self->kf, self->group_name, key, value);

	if (   !self->dirty
	    && !got_dirty) {
		gs_free_error GError *error = NULL;
		gs_free char *new_value = NULL;

		new_value = g_key_file_get_value (self->kf, self->group_name, key, &error);
		if (   error
		    || !new_value
		    || !nm_streq0 (old_value, new_value))
			got_dirty = TRUE;
	}

	if (got_dirty)
		_got_dirty (self, key);
}

void
nm_key_file_db_set_string_list (NMKeyFileDB *self,
                                const char *key,
                                const char *const*value,
                                gssize len)
{
	gs_free char *old_value = NULL;
	gboolean got_dirty = FALSE;;

	g_return_if_fail (_IS_KEY_FILE_DB (self, TRUE, FALSE));
	g_return_if_fail (key);

	if (!value) {
		nm_key_file_db_remove_key (self, key);
		return;
	}

	if (!self->dirty) {
		gs_free_error GError *error = NULL;

		old_value = g_key_file_get_value (self->kf, self->group_name, key, &error);
		if (error)
			got_dirty = TRUE;
	}

	if (len < 0)
		len = NM_PTRARRAY_LEN (value);

	g_key_file_set_string_list (self->kf, self->group_name, key, value, len);

	if (   !self->dirty
	    && !got_dirty) {
		gs_free_error GError *error = NULL;
		gs_free char *new_value = NULL;

		new_value = g_key_file_get_value (self->kf, self->group_name, key, &error);
		if (   error
		    || !new_value
		    || !nm_streq0 (old_value, new_value))
			got_dirty = TRUE;
	}

	if (got_dirty)
		_got_dirty (self, key);
}

/*****************************************************************************/

void
nm_key_file_db_to_file (NMKeyFileDB *self,
                        gboolean force)
{
	gs_free_error GError *error = NULL;

	g_return_if_fail (_IS_KEY_FILE_DB (self, TRUE, FALSE));

	if (   !force
	    && !self->dirty)
		return;

	self->dirty = FALSE;

	if (!g_key_file_save_to_file (self->kf,
	                              self->filename,
	                              &error)) {
		_LOGD ("failure to write keyfile \"%s\": %s", self->filename, error->message);
	} else
		_LOGD ("write keyfile: \"%s\"", self->filename);
}
