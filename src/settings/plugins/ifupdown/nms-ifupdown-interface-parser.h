/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * Tom Parker <palfrey@tevp.net>
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
 * (C) Copyright 2004 Tom Parker
 */

#ifndef _INTERFACE_PARSER_H
#define _INTERFACE_PARSER_H

typedef struct _if_data {
	char *key;
	char *data;
	struct _if_data *next;
} if_data;

typedef struct _if_block {
	char *type;
	char *name;
	if_data *info;
	struct _if_block *next;
} if_block;

typedef struct _if_parser if_parser;

if_parser *ifparser_parse (const char *eni_file, int quiet);

void ifparser_destroy (if_parser *parser);
NM_AUTO_DEFINE_FCN0 (if_parser *, _nm_auto_ifparser, ifparser_destroy);
#define nm_auto_ifparser nm_auto(_nm_auto_ifparser)

if_block *ifparser_getif (if_parser *parser, const char* iface);
if_block *ifparser_getfirst (if_parser *parser);
const char *ifparser_getkey (if_block* iface, const char *key);
gboolean ifparser_haskey (if_block* iface, const char *key);
int ifparser_get_num_blocks (if_parser *parser);
int ifparser_get_num_info (if_block* iface);

#endif
