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

#include "nm-glib.h"

#define WPA_SUPPLICANT_CONF SYSCONFDIR "/wpa_supplicant/wpa_supplicant.conf"

void wpa_parser_init (const char *wpa_supplicant_conf);
void wpa_parser_destroy (void);

/* reader functions */
const char *wpa_get_value (const char *ssid, const char *key);
gboolean exist_ssid (const char *ssid);
GHashTable *_get_hash_table (const char *ssid);
gboolean wpa_has_security (const char *ssid);

/* writer functions */
gboolean wpa_flush_to_file (const char *config_file);
void wpa_set_data (const char *ssid, const char *key, const char *value);
gboolean wpa_add_security (const char *ssid);
gboolean wpa_delete_security (const char *ssid);
#endif
