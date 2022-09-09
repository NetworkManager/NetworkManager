/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-keyfile-aux.h"

#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "nm-io-utils.h"

/*****************************************************************************/

struct _NMKeyFileDB {
    NMKeyFileDBLogFcn      log_fcn;
    NMKeyFileDBGotDirtyFcn got_dirty_fcn;
    gpointer               user_data;
    const char            *group_name;
    GKeyFile              *kf;
    guint                  ref_count;

    bool is_started : 1;
    bool dirty : 1;
    bool destroyed : 1;

    bool groups_pruned : 1;

    char filename[];
};

#define _NMLOG(self, syslog_level, fmt, ...)                                                   \
    G_STMT_START                                                                               \
    {                                                                                          \
        NMKeyFileDB *_self = (self);                                                           \
                                                                                               \
        nm_assert(_self);                                                                      \
        nm_assert(!_self->destroyed);                                                          \
                                                                                               \
        if (_self->log_fcn) {                                                                  \
            _self->log_fcn(_self, (syslog_level), _self->user_data, "" fmt "", ##__VA_ARGS__); \
        };                                                                                     \
    }                                                                                          \
    G_STMT_END

#define _LOGD(...) _NMLOG(self, LOG_DEBUG, __VA_ARGS__)

static gboolean
_IS_KEY_FILE_DB(NMKeyFileDB *self, gboolean require_is_started, gboolean allow_destroyed)
{
    if (self == NULL)
        return FALSE;
    if (self->ref_count <= 0) {
        nm_assert_not_reached();
        return FALSE;
    }
    if (require_is_started && !self->is_started)
        return FALSE;
    if (!allow_destroyed && self->destroyed)
        return FALSE;
    return TRUE;
}

static GKeyFile *
_key_file_new(void)
{
    GKeyFile *kf;

    kf = g_key_file_new();
    g_key_file_set_list_separator(kf, ',');
    return kf;
}

/*****************************************************************************/

NMKeyFileDB *
nm_key_file_db_new(const char            *filename,
                   const char            *group_name,
                   NMKeyFileDBLogFcn      log_fcn,
                   NMKeyFileDBGotDirtyFcn got_dirty_fcn,
                   gpointer               user_data)
{
    NMKeyFileDB *self;
    gsize        l_filename;
    gsize        l_group;

    g_return_val_if_fail(filename && filename[0], NULL);
    g_return_val_if_fail(group_name && group_name[0], NULL);

    l_filename = strlen(filename);
    l_group    = strlen(group_name);

    self                = g_malloc0(sizeof(NMKeyFileDB) + l_filename + 1 + l_group + 1);
    self->ref_count     = 1;
    self->log_fcn       = log_fcn;
    self->got_dirty_fcn = got_dirty_fcn;
    self->user_data     = user_data;
    self->kf            = _key_file_new();
    memcpy(self->filename, filename, l_filename + 1);
    self->group_name = &self->filename[l_filename + 1];
    memcpy((char *) self->group_name, group_name, l_group + 1);

    return self;
}

NMKeyFileDB *
nm_key_file_db_ref(NMKeyFileDB *self)
{
    if (!self)
        return NULL;

    g_return_val_if_fail(_IS_KEY_FILE_DB(self, FALSE, TRUE), NULL);

    nm_assert(self->ref_count < G_MAXUINT);
    self->ref_count++;
    return self;
}

void
nm_key_file_db_unref(NMKeyFileDB *self)
{
    if (!self)
        return;

    g_return_if_fail(_IS_KEY_FILE_DB(self, FALSE, TRUE));

    if (--self->ref_count > 0)
        return;

    g_key_file_unref(self->kf);

    g_free(self);
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
nm_key_file_db_destroy(NMKeyFileDB *self)
{
    if (!self)
        return;

    g_return_if_fail(_IS_KEY_FILE_DB(self, FALSE, FALSE));
    g_return_if_fail(!self->destroyed);

    self->destroyed = TRUE;
    nm_key_file_db_unref(self);
}

/*****************************************************************************/

/* nm_key_file_db_start() is supposed to be called right away, after creating the
 * instance.
 *
 * It's not done as separate step after nm_key_file_db_new(), because we want to log,
 * and the log_fcn returns the self pointer (which we should not expose before
 * nm_key_file_db_new() returns. */
void
nm_key_file_db_start(NMKeyFileDB *self)
{
    gs_free char         *contents = NULL;
    gsize                 contents_len;
    gs_free_error GError *error = NULL;

    g_return_if_fail(_IS_KEY_FILE_DB(self, FALSE, FALSE));
    g_return_if_fail(!self->is_started);

    self->is_started = TRUE;

    if (!nm_utils_file_get_contents(-1,
                                    self->filename,
                                    20 * 1024 * 1024,
                                    NM_UTILS_FILE_GET_CONTENTS_FLAG_NONE,
                                    &contents,
                                    &contents_len,
                                    NULL,
                                    &error)) {
        _LOGD("failed to read \"%s\": %s", self->filename, error->message);
        return;
    }

    if (!g_key_file_load_from_data(self->kf,
                                   contents,
                                   contents_len,
                                   G_KEY_FILE_KEEP_COMMENTS,
                                   &error)) {
        _LOGD("failed to load keyfile \"%s\": %s", self->filename, error->message);
        return;
    }

    _LOGD("loaded keyfile-db for \"%s\"", self->filename);
}

/*****************************************************************************/

const char *
nm_key_file_db_get_filename(NMKeyFileDB *self)
{
    g_return_val_if_fail(_IS_KEY_FILE_DB(self, FALSE, TRUE), NULL);

    return self->filename;
}

gboolean
nm_key_file_db_is_dirty(NMKeyFileDB *self)
{
    g_return_val_if_fail(_IS_KEY_FILE_DB(self, FALSE, TRUE), FALSE);

    return self->dirty;
}

/*****************************************************************************/

char *
nm_key_file_db_get_value(NMKeyFileDB *self, const char *key)
{
    g_return_val_if_fail(_IS_KEY_FILE_DB(self, TRUE, TRUE), NULL);

    return g_key_file_get_value(self->kf, self->group_name, key, NULL);
}

char **
nm_key_file_db_get_string_list(NMKeyFileDB *self, const char *key, gsize *out_len)
{
    g_return_val_if_fail(_IS_KEY_FILE_DB(self, TRUE, TRUE), NULL);

    return g_key_file_get_string_list(self->kf, self->group_name, key, out_len, NULL);
}

/*****************************************************************************/

static void
_got_dirty(NMKeyFileDB *self, const char *key)
{
    nm_assert(_IS_KEY_FILE_DB(self, TRUE, FALSE));
    nm_assert(!self->dirty);

    _LOGD("updated entry for %s.%s", self->group_name, key);

    self->dirty = TRUE;
    if (self->got_dirty_fcn)
        self->got_dirty_fcn(self, self->user_data);
}

/*****************************************************************************/

void
nm_key_file_db_remove_key(NMKeyFileDB *self, const char *key)
{
    gboolean got_dirty = FALSE;

    g_return_if_fail(_IS_KEY_FILE_DB(self, TRUE, FALSE));

    if (!key)
        return;

    if (!self->dirty) {
        gs_free_error GError *error = NULL;

        g_key_file_has_key(self->kf, self->group_name, key, &error);
        got_dirty = (error != NULL);
    }
    g_key_file_remove_key(self->kf, self->group_name, key, NULL);

    if (got_dirty)
        _got_dirty(self, key);
}

void
nm_key_file_db_set_value(NMKeyFileDB *self, const char *key, const char *value)
{
    gs_free char *old_value = NULL;
    gboolean      got_dirty = FALSE;

    g_return_if_fail(_IS_KEY_FILE_DB(self, TRUE, FALSE));
    g_return_if_fail(key);

    if (!value) {
        nm_key_file_db_remove_key(self, key);
        return;
    }

    if (!self->dirty) {
        gs_free_error GError *error = NULL;

        old_value = g_key_file_get_value(self->kf, self->group_name, key, &error);
        if (error)
            got_dirty = TRUE;
    }

    g_key_file_set_value(self->kf, self->group_name, key, value);

    if (!self->dirty && !got_dirty) {
        gs_free_error GError *error     = NULL;
        gs_free char         *new_value = NULL;

        new_value = g_key_file_get_value(self->kf, self->group_name, key, &error);
        if (error || !new_value || !nm_streq0(old_value, new_value))
            got_dirty = TRUE;
    }

    if (got_dirty)
        _got_dirty(self, key);
}

void
nm_key_file_db_set_string_list(NMKeyFileDB       *self,
                               const char        *key,
                               const char *const *value,
                               gssize             len)
{
    gs_free char *old_value = NULL;
    gboolean      got_dirty = FALSE;

    g_return_if_fail(_IS_KEY_FILE_DB(self, TRUE, FALSE));
    g_return_if_fail(key);

    if (!value) {
        nm_key_file_db_remove_key(self, key);
        return;
    }

    if (!self->dirty) {
        gs_free_error GError *error = NULL;

        old_value = g_key_file_get_value(self->kf, self->group_name, key, &error);
        if (error)
            got_dirty = TRUE;
    }

    if (len < 0)
        len = NM_PTRARRAY_LEN(value);

    g_key_file_set_string_list(self->kf, self->group_name, key, value, len);

    if (!self->dirty && !got_dirty) {
        gs_free_error GError *error     = NULL;
        gs_free char         *new_value = NULL;

        new_value = g_key_file_get_value(self->kf, self->group_name, key, &error);
        if (error || !new_value || !nm_streq0(old_value, new_value))
            got_dirty = TRUE;
    }

    if (got_dirty)
        _got_dirty(self, key);
}

/*****************************************************************************/

void
nm_key_file_db_to_file(NMKeyFileDB *self, gboolean force)
{
    gs_free_error GError *error = NULL;

    g_return_if_fail(_IS_KEY_FILE_DB(self, TRUE, FALSE));

    if (!force && !self->dirty)
        return;

    self->dirty = FALSE;

    if (!g_key_file_save_to_file(self->kf, self->filename, &error)) {
        _LOGD("failure to write keyfile \"%s\": %s", self->filename, error->message);
    } else
        _LOGD("write keyfile: \"%s\"", self->filename);
}

/*****************************************************************************/

void
nm_key_file_db_prune_tmp_files(NMKeyFileDB *self)
{
    gs_free char      *n_file   = NULL;
    gs_free char      *n_dir    = NULL;
    gs_strfreev char **tmpfiles = NULL;
    gsize              i;

    n_file = g_path_get_basename(self->filename);
    n_dir  = g_path_get_dirname(self->filename);

    tmpfiles = nm_utils_find_mkstemp_files(n_dir, n_file);
    if (!tmpfiles)
        return;

    for (i = 0; tmpfiles[i]; i++) {
        const char   *tmpfile   = tmpfiles[i];
        gs_free char *full_file = NULL;
        int           r;

        full_file = g_strdup_printf("%s/%s", n_dir, tmpfile);

        r = unlink(full_file);
        if (r != 0) {
            int errsv = errno;

            if (errsv != ENOENT) {
                _LOGD("prune left over temp file %s failed: %s",
                      full_file,
                      nm_strerror_native(errsv));
            }
            continue;
        }

        _LOGD("prune left over temp file %s", full_file);
    }
}

/*****************************************************************************/

void
nm_key_file_db_prune(NMKeyFileDB *self,
                     gboolean (*predicate)(const char *key, gpointer user_data),
                     gpointer user_data)
{
    gs_strfreev char              **keys       = NULL;
    nm_auto_unref_keyfile GKeyFile *kf_to_free = NULL;
    GKeyFile                       *kf_src     = NULL;
    GKeyFile                       *kf_dst     = NULL;
    guint                           k;

    g_return_if_fail(_IS_KEY_FILE_DB(self, TRUE, FALSE));
    nm_assert(predicate);

    _LOGD("prune keyfile of old entries: \"%s\"", self->filename);

    if (!self->groups_pruned) {
        /* When we prune the first time, we swap the GKeyFile instance.
         * The instance loaded from disk might have unrelated groups and
         * comments. Let's get rid of them by creating a new instance.
         *
         * Otherwise, we know that self->kf only contains good keys,
         * and at most we need to remove some of them. */
        kf_to_free          = g_steal_pointer(&self->kf);
        self->kf            = _key_file_new();
        kf_src              = kf_to_free;
        self->groups_pruned = TRUE;
        self->dirty         = TRUE;
    } else
        kf_src = self->kf;
    kf_dst = self->kf;

    keys = g_key_file_get_keys(kf_src, self->group_name, NULL, NULL);
    if (keys) {
        for (k = 0; keys[k]; k++) {
            const char *key = keys[k];
            gboolean    keep;

            keep = predicate(key, user_data);

            if (!keep) {
                if (kf_dst == kf_src) {
                    g_key_file_remove_key(kf_dst, self->group_name, key, NULL);
                    self->dirty = TRUE;
                }
                continue;
            }

            if (kf_dst != kf_src) {
                gs_free char *value = NULL;

                value = g_key_file_get_value(kf_src, self->group_name, key, NULL);
                if (value)
                    g_key_file_set_value(kf_dst, self->group_name, key, value);
                else
                    self->dirty = TRUE;
            }
        }
    }
}
