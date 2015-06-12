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

#ifndef _IFNET_UTILS_H
#define _IFNET_UTILS_H
#define IFNET_PLUGIN_NAME "SCPlugin-Ifnet"
#include <glib.h>
#include <arpa/inet.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-ip4-config.h>
#include "net_parser.h"
#define has_default_ip4_route(conn_name) has_default_route((conn_name), &is_ip4_address)
#define has_default_ip6_route(conn_name) has_default_route((conn_name), &is_ip6_address)

typedef struct _ip_block {
	char *ip;
	guint32 prefix;
	char *next_hop;
	struct _ip_block *next;
} ip_block;

gboolean is_static_ip4 (const char *conn_name);
gboolean is_static_ip6 (const char *conn_name);
gboolean is_ip4_address (const char *in_address);
gboolean is_ip6_address (const char *in_address);
gboolean has_ip6_address (const char *conn_name);
gboolean has_default_route (const char *conn_name, gboolean (*check_fn) (const char *));
gboolean reload_parsers (void);

ip_block *convert_ip4_config_block (const char *conn_name);
ip_block *convert_ip6_config_block (const char *conn_name);
ip_block *convert_ip4_routes_block (const char *conn_name);
ip_block *convert_ip6_routes_block (const char *conn_name);
void destroy_ip_block (ip_block * iblock);

void set_ip4_dns_servers (NMSettingIPConfig * s_ip4, const char *conn_name);
void set_ip6_dns_servers (NMSettingIPConfig * s_ip6, const char *conn_name);

gchar *strip_string (gchar *str, gchar t);
gboolean is_managed (const char *conn_name);

gboolean is_hex (const char *value);
gboolean is_ascii (const char *value);
gboolean is_true (const char *str);

void get_dhcp_hostname_and_client_id (char **hostname, char **client_id);

gchar *backup_file (const gchar* target);
#endif
