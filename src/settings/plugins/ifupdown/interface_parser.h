/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
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

#include "nm-glib.h"

typedef struct _if_data
{
	char *key;
	char *data;
	struct _if_data *next;
} if_data;

typedef struct _if_block
{
	char *type;
	char *name;
	if_data *info;
	struct _if_block *next;
} if_block;

void ifparser_init(const char *eni_file, int quiet);
void ifparser_destroy(void);

if_block *ifparser_getif(const char* iface);
if_block *ifparser_getfirst(void);
const char *ifparser_getkey(if_block* iface, const char *key);
gboolean ifparser_haskey(if_block* iface, const char *key);
int ifparser_get_num_blocks(void);
int ifparser_get_num_info(if_block* iface);

void add_block(const char *type, const char* name);
void add_data(const char *key,const char *data);
void _destroy_data(if_data *ifd);
void _destroy_block(if_block* ifb);
#endif
