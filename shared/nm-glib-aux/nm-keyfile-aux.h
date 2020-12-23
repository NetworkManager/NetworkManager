/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#ifndef __NM_KEYFILE_AUX_H__
#define __NM_KEYFILE_AUX_H__

/*****************************************************************************/

typedef struct _NMKeyFileDB NMKeyFileDB;

typedef void (*NMKeyFileDBLogFcn)(NMKeyFileDB *self,
                                  int          syslog_level,
                                  gpointer     user_data,
                                  const char * fmt,
                                  ...) G_GNUC_PRINTF(4, 5);

typedef void (*NMKeyFileDBGotDirtyFcn)(NMKeyFileDB *self, gpointer user_data);

NMKeyFileDB *nm_key_file_db_new(const char *           filename,
                                const char *           group,
                                NMKeyFileDBLogFcn      log_fcn,
                                NMKeyFileDBGotDirtyFcn got_dirty_fcn,
                                gpointer               user_data);

void nm_key_file_db_start(NMKeyFileDB *self);

NMKeyFileDB *nm_key_file_db_ref(NMKeyFileDB *self);
void         nm_key_file_db_unref(NMKeyFileDB *self);

void nm_key_file_db_destroy(NMKeyFileDB *self);

const char *nm_key_file_db_get_filename(NMKeyFileDB *self);

gboolean nm_key_file_db_is_dirty(NMKeyFileDB *self);

char *nm_key_file_db_get_value(NMKeyFileDB *self, const char *key);

char **nm_key_file_db_get_string_list(NMKeyFileDB *self, const char *key, gsize *out_len);

void nm_key_file_db_remove_key(NMKeyFileDB *self, const char *key);

void nm_key_file_db_set_value(NMKeyFileDB *self, const char *key, const char *value);

void nm_key_file_db_set_string_list(NMKeyFileDB *      self,
                                    const char *       key,
                                    const char *const *value,
                                    gssize             len);

void nm_key_file_db_to_file(NMKeyFileDB *self, gboolean force);

/*****************************************************************************/

#endif /* __NM_KEYFILE_AUX_H__ */
