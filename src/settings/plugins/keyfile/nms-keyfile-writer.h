/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 */

#ifndef __NMS_KEYFILE_WRITER_H__
#define __NMS_KEYFILE_WRITER_H__

#include "nm-connection.h"

gboolean nms_keyfile_writer_connection (NMConnection *connection,
                                        gboolean save_to_disk,
                                        const char *existing_path,
                                        gboolean force_rename,
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
