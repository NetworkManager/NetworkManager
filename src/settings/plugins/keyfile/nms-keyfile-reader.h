/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef __NMS_KEYFILE_READER_H__
#define __NMS_KEYFILE_READER_H__

#include "nm-connection.h"

NMConnection *nms_keyfile_reader_from_keyfile(GKeyFile *  key_file,
                                              const char *filename,
                                              const char *base_dir,
                                              const char *profile_dir,
                                              gboolean    verbose,
                                              GError **   error);

struct stat;

NMConnection *nms_keyfile_reader_from_file(const char * full_filename,
                                           const char * profile_dir,
                                           struct stat *out_stat,
                                           NMTernary *  out_is_nm_generated,
                                           NMTernary *  out_is_volatile,
                                           NMTernary *  out_is_external,
                                           char **      out_shadowed_storage,
                                           NMTernary *  out_shadowed_owned,
                                           GError **    error);

#endif /* __NMS_KEYFILE_READER_H__ */
