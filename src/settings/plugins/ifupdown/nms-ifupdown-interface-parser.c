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

#include "nm-default.h"

#include "nms-ifupdown-interface-parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wordexp.h>
#include <libgen.h>

#include "nm-utils.h"

if_block* first;
if_block* last;

if_data* last_data;

void add_block(const char *type, const char* name)
{
	if_block *ret = g_slice_new0 (struct _if_block);
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
}

void add_data(const char *key,const char *data)
{
	if_data *ret;
	char *idx;

	/* Check if there is a block where we can attach our data */
	if (first == NULL)
		return;

	ret = g_slice_new0 (struct _if_data);
	ret->key = g_strdup(key);

	/* Normalize keys. Convert '_' to '-', as ifupdown accepts both variants.
	 * When querying keys via ifparser_getkey(), use '-'. */
	while ((idx = strrchr(ret->key, '_'))) {
		*idx = '-';
	}
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
}

/* join values in src with spaces into dst;  dst needs to be large enough */
static char *join_values_with_spaces(char *dst, char **src)
{
	if (dst != NULL) {
		*dst = '\0';
		if (src != NULL && *src != NULL) {
			strcat(dst, *src);

			for (src++; *src != NULL; src++) {
				strcat(dst, " ");
				strcat(dst, *src);
			}
		}
	}
	return(dst);
}

static void _ifparser_source (const char *path, const char *en_dir, int quiet, int dir);

static void
_recursive_ifparser (const char *eni_file, int quiet)
{
	FILE *inp;
	char line[255];
	int skip_to_block = 1;
	int skip_long_line = 0;
	int offs = 0;

	/* Check if interfaces file exists and open it */
	if (!g_file_test (eni_file, G_FILE_TEST_EXISTS)) {
		if (!quiet)
			nm_log_warn (LOGD_SETTINGS, "interfaces file %s doesn't exist\n", eni_file);
		return;
	}
	inp = fopen (eni_file, "re");
	if (inp == NULL) {
		if (!quiet)
			nm_log_warn (LOGD_SETTINGS, "Can't open %s\n", eni_file);
		return;
	}
	if (!quiet)
		nm_log_info (LOGD_SETTINGS, "      interface-parser: parsing file %s\n", eni_file);

	while (!feof(inp))
	{
		char *token[128]; /* 255 chars can only be split into 127 tokens */
		char value[255];  /* large enough to join previously split tokens */
		char *safeptr;
		int toknum;
		int len = 0;

		char *ptr = fgets(line+offs, 255-offs, inp);
		if (ptr == NULL)
			break;

		len = strlen(line);
		/* skip over-long lines */
		if (!feof(inp) && len > 0 &&  line[len-1] != '\n') {
			if (!skip_long_line) {
				if (!quiet)
					nm_log_warn (LOGD_SETTINGS, "Skipping over-long-line '%s...'\n", line);
			}
			skip_long_line = 1;
			continue;
		}

		/* trailing '\n' found: remove it & reset offset to 0 */
		if (len > 0 && line[len-1] == '\n') {
			line[--len] = '\0';
			offs = 0;
		}

		/* if we're in long_line_skip mode, terminate it for real next line */
		if (skip_long_line) {
			if (len == 0 || line[len-1] != '\\')
				skip_long_line = 0;
			continue;
		}

		/* unwrap wrapped lines */
		if (len > 0 && line[len-1] == '\\') {
			offs = len - 1;
			continue;
		}

#define SPACES " \t"
		/* tokenize input; */
		for (toknum = 0, token[toknum] = strtok_r(line, SPACES, &safeptr);
		     token[toknum] != NULL;
		     toknum++, token[toknum] = strtok_r(NULL, SPACES, &safeptr))
			;

		/* ignore comments and empty lines */
		if (toknum == 0 || *token[0]=='#')
			continue;

		if (toknum < 2) {
			if (!quiet) {
				nm_log_warn (LOGD_SETTINGS, "Can't parse interface line '%s'\n",
				             join_values_with_spaces(value, token));
			}
			skip_to_block = 1;
			continue;
		}

		/* There are six different stanzas:
		 * iface, mapping, auto, allow-*, source, and source-directory.
		 * Create a block for each of them except source and source-directory.  */

		/* iface stanza takes at least 3 parameters */
		if (strcmp(token[0], "iface") == 0) {
			if (toknum < 4) {
				if (!quiet) {
					nm_log_warn (LOGD_SETTINGS, "Can't parse iface line '%s'\n",
					             join_values_with_spaces(value, token));
				}
				continue;
			}
			add_block(token[0], token[1]);
			skip_to_block = 0;
			add_data(token[2], join_values_with_spaces(value, token + 3));
		}
		/* auto and allow-auto stanzas are equivalent,
		 * both can take multiple interfaces as parameters: add one block for each */
		else if (strcmp(token[0], "auto") == 0 ||
			 strcmp(token[0], "allow-auto") == 0) {
			int i;
			for (i = 1; i < toknum; i++)
				add_block("auto", token[i]);
			skip_to_block = 0;
		}
		else if (strcmp(token[0], "mapping") == 0) {
			add_block(token[0], join_values_with_spaces(value, token + 1));
			skip_to_block = 0;
		}
		/* allow-* can take multiple interfaces as parameters: add one block for each */
		else if (strncmp(token[0],"allow-",6) == 0) {
			int i;
			for (i = 1; i < toknum; i++)
				add_block(token[0], token[i]);
			skip_to_block = 0;
		}
		/* source and source-directory stanzas take one or more paths as parameters */
		else if (strcmp (token[0], "source") == 0 || strcmp (token[0], "source-directory") == 0) {
			int i;
			char *en_dir;

			skip_to_block = 0;
			en_dir = g_path_get_dirname (eni_file);
			for (i = 1; i < toknum; ++i) {
				if (strcmp (token[0], "source-directory") == 0)
					_ifparser_source (token[i], en_dir, quiet, TRUE);
				else
					_ifparser_source (token[i], en_dir, quiet, FALSE);
			}
			g_free (en_dir);
		}
		else {
			if (skip_to_block) {
				if (!quiet) {
					nm_log_warn (LOGD_SETTINGS, "ignoring out-of-block data '%s'\n",
					             join_values_with_spaces(value, token));
				}
			} else
				add_data(token[0], join_values_with_spaces(value, token + 1));
		}
	}
	fclose(inp);

	if (!quiet)
		nm_log_info (LOGD_SETTINGS, "      interface-parser: finished parsing file %s\n", eni_file);
}

static void
_ifparser_source (const char *path, const char *en_dir, int quiet, int dir)
{
	char *abs_path;
	const char *item;
	wordexp_t we;
	GDir *source_dir;
	GError *error = NULL;
	uint i;

	if (g_path_is_absolute (path))
		abs_path = g_strdup (path);
	else
		abs_path = g_build_filename (en_dir, path, NULL);

	if (!quiet)
		nm_log_info (LOGD_SETTINGS, "      interface-parser: source line includes interfaces file(s) %s\n", abs_path);

	/* ifupdown uses WRDE_NOCMD for wordexp. */
	if (wordexp (abs_path, &we, WRDE_NOCMD)) {
		if (!quiet)
			nm_log_warn (LOGD_SETTINGS, "word expansion for %s failed\n", abs_path);
	} else {
		for (i = 0; i < we.we_wordc; i++) {
			if (dir) {
				source_dir = g_dir_open (we.we_wordv[i], 0, &error);
				if (!source_dir) {
					if (!quiet) {
						nm_log_warn (LOGD_SETTINGS, "Failed to open directory %s: %s",
						             we.we_wordv[i], error->message);
					}
					g_clear_error (&error);
				} else {
					while ((item = g_dir_read_name (source_dir)))
						_ifparser_source (item, we.we_wordv[i], quiet, FALSE);
					g_dir_close (source_dir);
				}
			} else
				_recursive_ifparser (we.we_wordv[i], quiet);
		}
		wordfree (&we);
	}
	g_free (abs_path);
}

void ifparser_init (const char *eni_file, int quiet)
{
	first = last = NULL;
	_recursive_ifparser (eni_file, quiet);
}

void _destroy_data(if_data *ifd)
{
	if (ifd == NULL)
		return;
	_destroy_data(ifd->next);
	g_free(ifd->key);
	g_free(ifd->data);
	g_slice_free(struct _if_data, ifd);
	return;
}

void _destroy_block(if_block* ifb)
{
	if (ifb == NULL)
		return;
	_destroy_block(ifb->next);
	_destroy_data(ifb->info);
	g_free(ifb->name);
	g_free(ifb->type);
	g_slice_free(struct _if_block, ifb);
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

int ifparser_get_num_blocks(void)
{
	int i = 0;
	if_block *iter = first;

	while (iter) {
		i++;
		iter = iter->next;
	}
	return i;
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

gboolean
ifparser_haskey(if_block* iface, const char *key)
{
	if_data *curr = iface->info;

	while (curr != NULL) {
		if (strcmp (curr->key, key) == 0)
			return TRUE;
		curr = curr->next;
	}
	return FALSE;
}

int ifparser_get_num_info(if_block* iface)
{
	int i = 0;
	if_data *iter = iface->info;

	while (iter) {
		i++;
		iter = iter->next;
	}
	return i;
}
