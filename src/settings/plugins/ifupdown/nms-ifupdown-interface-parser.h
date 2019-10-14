// SPDX-License-Identifier: GPL-2.0+
/*
 * Tom Parker <palfrey@tevp.net>
 * Copyright (C) 2004 Tom Parker
 */

#ifndef _INTERFACE_PARSER_H
#define _INTERFACE_PARSER_H

#include "c-list/src/c-list.h"

typedef struct {
	CList data_lst;
	const char *data;
	const char key[];
} if_data;

typedef struct {
	CList block_lst;
	CList data_lst_head;
	const char *type;
	const char name[];
} if_block;

typedef struct {
	CList block_lst_head;
} if_parser;

if_parser *ifparser_parse (const char *eni_file, int quiet);

void ifparser_destroy (if_parser *parser);
NM_AUTO_DEFINE_FCN0 (if_parser *, _nm_auto_ifparser, ifparser_destroy);
#define nm_auto_ifparser nm_auto(_nm_auto_ifparser)

if_block *ifparser_getif (if_parser *parser, const char* iface);
if_block *ifparser_getfirst (if_parser *parser);
const char *ifparser_getkey (if_block* iface, const char *key);
gboolean ifparser_haskey (if_block* iface, const char *key);

guint ifparser_get_num_blocks (if_parser *parser);
guint ifparser_get_num_info (if_block* iface);

#endif
