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


#include "interface_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nm-utils.h"

if_block* first;
if_block* last;

if_data* last_data;

void add_block(const char *type, const char* name)
{
	if_block *ret = (if_block*)calloc(1,sizeof(struct _if_block));
	ret->name = g_strdup(name);
	ret->type = g_strdup(type);
	if (first == NULL)
		first = last = ret;
	else
	{
		last->next = ret;
		last = ret;
	}
	last_data = NULL;
	//printf("added block '%s' with type '%s'\n",name,type);
}

void add_data(const char *key,const char *data)
{
	if_data *ret;

	// Check if there is a block where we can attach our data
	if (first == NULL)
		return;

	ret = (if_data*) calloc(1,sizeof(struct _if_data));
	ret->key = g_strdup(key);
	ret->data = g_strdup(data);

	if (last->info == NULL)
	{
		last->info = ret;
		last_data = ret;
	}
	else
	{
		last_data->next = ret;
		last_data = last_data->next;
	}
	//printf("added data '%s' with key '%s'\n",data,key);
}

#define SPACE_OR_TAB(string,ret) {ret = strchr(string,' ');ret=(ret == NULL?strchr(string,'\t'):ret);}

void ifparser_init(void)
{
	FILE *inp = fopen(ENI_INTERFACES_FILE, "r");
	int ret = 0;
	char *line;
	char *space;
	char rline[255];

	if (inp == NULL)
	{
		nm_warning ("Error: Can't open %s\n", ENI_INTERFACES_FILE);
		return;
	}
	first = last = NULL;
	while(1)
	{
		line = space = NULL;
		ret = fscanf(inp,"%255[^\n]\n",rline);
		if (ret == EOF)
			break;
		// If the line did not match, skip it
		if (ret == 0) {
			char *ignored;

			ignored = fgets(rline, 255, inp);
			continue;
		}

		line = rline;
		while(line[0] == ' ')
			line++;
		if (line[0]=='#' || line[0]=='\0')
			continue;

		SPACE_OR_TAB(line,space)
			if (space == NULL)
			{
				nm_warning ("Error: Can't parse interface line '%s'\n",line);
				continue;
			}
		space[0] = '\0';

		// There are four different stanzas:
		// iface, mapping, auto and allow-*. Create a block for each of them.
		if (strcmp(line,"iface")==0)
		{
			char *space2 = strchr(space+1,' ');
			if (space2 == NULL)
			{
				nm_warning ("Error: Can't parse iface line '%s'\n",space+1);
				continue;
			}
			space2[0]='\0';
			add_block(line,space+1);

			if (space2[1]!='\0')
			{
				space = strchr(space2+1,' ');
				if (space == NULL)
				{
					nm_warning ("Error: Can't parse data '%s'\n",space2+1);
					continue;
				}
				space[0] = '\0';
				add_data(space2+1,space+1);
			}
		}
		else if (strcmp(line,"auto")==0)
			add_block(line,space+1);
		else if (strcmp(line,"mapping")==0)
			add_block(line,space+1);
		else if (strncmp(line,"allow-",6)==0)
			add_block(line,space+1);
		else
			add_data(line,space+1);

		//printf("line: '%s' ret=%d\n",rline,ret);
	}
	fclose(inp);
}

void _destroy_data(if_data *ifd)
{
	if (ifd == NULL)
		return;
	_destroy_data(ifd->next);
	free(ifd->key);
	free(ifd->data);
	free(ifd);
	return;
}

void _destroy_block(if_block* ifb)
{
	if (ifb == NULL)
		return;
	_destroy_block(ifb->next);
	_destroy_data(ifb->info);
	free(ifb->name);
	free(ifb->type);
	free(ifb);
	return;
}

void ifparser_destroy(void)
{
	_destroy_block(first);
	first = last = NULL;
}

if_block *ifparser_getfirst(void)
{
	return first;
}

if_block *ifparser_getif(const char* iface)
{
	if_block *curr = first;
	while(curr!=NULL)
	{
		if (strcmp(curr->type,"iface")==0 && strcmp(curr->name,iface)==0)
			return curr;
		curr = curr->next;
	}
	return NULL;
}

const char *ifparser_getkey(if_block* iface, const char *key)
{
	if_data *curr = iface->info;
	while(curr!=NULL)
	{
		if (strcmp(curr->key,key)==0)
			return curr->data;
		curr = curr->next;
	}
	return NULL;
}
