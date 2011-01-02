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

#ifndef _WPA_PARSER_H
#define _WPA_PARSER_H
#define WPA_SUPPLICANT_CONF "/etc/wpa_supplicant/wpa_supplicant.conf"
#include <glib.h>
void wpa_parser_init (gchar * wpa_supplicant_conf);
void wpa_parser_destroy (void);

/* reader functions */
gchar *wpa_get_value (gchar * ssid, gchar * key);
gboolean exist_ssid (gchar * ssid);
GHashTable *_get_hash_table (gchar * ssid);
gboolean wpa_has_security (gchar * ssid);

/* writer functions */
gboolean wpa_flush_to_file (gchar * config_file);
void wpa_set_data (gchar * ssid, gchar * key, gchar * value);
gboolean wpa_add_security (gchar * ssid);
gboolean wpa_delete_security (gchar * ssid);
#endif
