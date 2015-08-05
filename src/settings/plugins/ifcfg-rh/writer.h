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
 * Copyright (C) 2009 Red Hat, Inc.
 */

#ifndef _WRITER_H_
#define _WRITER_H_

#include <sys/types.h>

#include <nm-connection.h>

#include "nm-default.h"

gboolean writer_can_write_connection (NMConnection *connection,
                                      GError **error);

gboolean writer_new_connection (NMConnection *connection,
                                const char *ifcfg_dir,
                                char **out_filename,
                                GError **error);

gboolean writer_update_connection (NMConnection *connection,
                                   const char *ifcfg_dir,
                                   const char *filename,
                                   const char *keyfile,
                                   GError **error);

#endif /* _WRITER_H_ */
