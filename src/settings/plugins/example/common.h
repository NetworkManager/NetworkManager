/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * (C) Copyright 2012 Red Hat, Inc.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <glib.h>

#include <nm-connection.h>

/* General info about the plugin that the code may want to use for logging
 * purposes.
 */
#define EXAMPLE_PLUGIN_NAME "example"
#define EXAMPLE_PLUGIN_INFO "(c) 2012 Red Hat, Inc.  To report bugs please use the NetworkManager mailing list."

#define EXAMPLE_DIR NMCONFDIR "/example-plugin"

/* Boilerplate stuff for the plugin's error domain.  Bits of the code that
 * create new errors in the plugin's domain will create errors of
 * type EXAMPLE_PLUGIN_ERROR like so:
 *
 *  error = g_error_new_literal (EXAMPLE_PLUGIN_ERROR,
 *                               <specific error number>,
 *                               "This is a really bad error.");
 */
#define EXAMPLE_PLUGIN_ERROR (example_plugin_error_quark ())
GQuark example_plugin_error_quark (void);

/* Prototypes for the reader/writer functions */
NMConnection *connection_from_file (const char *filename, GError **error);

gboolean write_connection (NMConnection *connection,
                           const char *existing_path,
                           char **out_path,
                           GError **error);

#endif  /* __COMMON_H__ */

