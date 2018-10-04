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
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef __NMS_KEYFILE_READER_H__
#define __NMS_KEYFILE_READER_H__

#include "nm-connection.h"

NMConnection *nms_keyfile_reader_from_keyfile (GKeyFile *key_file,
                                               const char *filename,
                                               const char *base_dir,
                                               const char *profile_dir,
                                               gboolean verbose,
                                               GError **error);

NMConnection *nms_keyfile_reader_from_file (const char *full_filename,
                                            const char *profile_dir,
                                            GError **error);

#endif /* __NMS_KEYFILE_READER_H__ */
