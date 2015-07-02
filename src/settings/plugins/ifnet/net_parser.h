/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Mu Qiao <qiaomuf@gmail.com>
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
 * Copyright (C) 1999-2010 Gentoo Foundation, Inc.
 */

#ifndef _NET_PARSER_H
#define _NET_PARSER_H

#include <glib.h>

#define CONF_NET_FILE SYSCONFDIR "/conf.d/net"

gboolean ifnet_init (gchar * config_file);
void ifnet_destroy (void);

/* Reader functions */
GList *ifnet_get_connection_names (void);
const char *ifnet_get_data (const char *conn_name, const char *key);
const char *ifnet_get_global_data (const char *key);
gboolean ifnet_has_network (const char *conn_name);

/* Writer functions */
gboolean ifnet_flush_to_file (const char *config_file, gchar **out_backup);
void ifnet_set_data (const char *conn_name, const char *key, const char *value);
gboolean ifnet_add_network (const char *name, const char *type);
gboolean ifnet_delete_network (const char *conn_name);
#endif
