// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager system settings service - keyfile plugin
 *
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 */

#ifndef __NMS_KEYFILE_WRITER_H__
#define __NMS_KEYFILE_WRITER_H__

#include "nm-connection.h"

typedef gboolean (*NMSKeyfileWriterAllowFilenameCb) (const char *check_filename,
                                                     gpointer allow_filename_user_data);

gboolean nms_keyfile_writer_connection (NMConnection *connection,
                                        gboolean is_nm_generated,
                                        gboolean is_volatile,
                                        const char *shadowed_storage,
                                        gboolean shadowed_owned,
                                        const char *keyfile_dir,
                                        const char *profile_dir,
                                        const char *existing_path,
                                        gboolean existing_path_read_only,
                                        gboolean force_rename,
                                        NMSKeyfileWriterAllowFilenameCb allow_filename_cb,
                                        gpointer allow_filename_user_data,
                                        char **out_path,
                                        NMConnection **out_reread,
                                        gboolean *out_reread_same,
                                        GError **error);

gboolean nms_keyfile_writer_test_connection (NMConnection *connection,
                                             const char *keyfile_dir,
                                             uid_t owner_uid,
                                             pid_t owner_grp,
                                             char **out_path,
                                             NMConnection **out_reread,
                                             gboolean *out_reread_same,
                                             GError **error);

#endif /* __NMS_KEYFILE_WRITER_H__ */
