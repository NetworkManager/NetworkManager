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
#include <wordexp.h>
#include <libgen.h>

#include "nm-utils.h"

/*****************************************************************************/

static void _ifparser_source (if_parser *parser, const char *path, const char *en_dir, int quiet, int dir);

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME      "ifupdown"
#define _NMLOG_DOMAIN           LOGD_SETTINGS
#define _NMLOG(level, ...) \
    nm_log ((level), _NMLOG_DOMAIN, NULL, NULL, \
            "%s" _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
            _NMLOG_PREFIX_NAME": " \
            _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

static void
add_block (if_parser *parser, const char *type, const char* name)
{
	if_block *ifb;
	gsize l_type, l_name;

	l_type = strlen (type) + 1;
	l_name = strlen (name) + 1;

	ifb = g_malloc (sizeof (if_block) + l_type + l_name);
	memcpy ((char *) ifb->name, name, l_name);
	ifb->type = &ifb->name[l_name];
	memcpy ((char *) ifb->type, type, l_type);
	c_list_init (&ifb->data_lst_head);
	c_list_link_tail (&parser->block_lst_head, &ifb->block_lst);
}

static void
add_data (if_parser *parser, const char *key, const char *data)
{
	if_block *last_block;
	if_data *ifd;
	char *idx;
	gsize l_key, l_data;

	last_block = c_list_last_entry (&parser->block_lst_head, if_block, block_lst);

	/* Check if there is a block where we can attach our data */
	if (!last_block)
		return;

	l_key = strlen (key) + 1;
	l_data = strlen (data) + 1;

	ifd = g_malloc (sizeof (if_data) + l_key + l_data);
	memcpy ((char *) ifd->key, key, l_key);
	ifd->data = &ifd->key[l_key];
	memcpy ((char *) ifd->data, data, l_data);

	/* Normalize keys. Convert '_' to '-', as ifupdown accepts both variants.
	 * When querying keys via ifparser_getkey(), use '-'. */
	idx = (char *) ifd->key;
	while ((idx = strchr (idx, '_')))
		*(idx++) = '-';

	c_list_link_tail (&last_block->data_lst_head, &ifd->data_lst);
}

/* join values in src with spaces into dst;  dst needs to be large enough */
static char *
join_values_with_spaces (char *dst, char **src)
{
	if (dst != NULL) {
		*dst = '\0';
		if (src != NULL && *src != NULL) {
			strcat (dst, *src);

			for (src++; *src != NULL; src++) {
				strcat (dst, " ");
				strcat (dst, *src);
			}
		}
	}
	return (dst);
}

static void
_recursive_ifparser (if_parser *parser, const char *eni_file, int quiet)
{
	FILE *inp;
	char line[255];
	int skip_to_block = 1;
	int skip_long_line = 0;
	int offs = 0;

	/* Check if interfaces file exists and open it */
	if (!g_file_test (eni_file, G_FILE_TEST_EXISTS)) {
		if (!quiet)
			_LOGW ("interfaces file %s doesn't exist", eni_file);
		return;
	}
	inp = fopen (eni_file, "re");
	if (inp == NULL) {
		if (!quiet)
			_LOGW ("Can't open %s", eni_file);
		return;
	}
	if (!quiet)
		_LOGI ("      interface-parser: parsing file %s", eni_file);

	while (!feof (inp)) {
		char *token[128]; /* 255 chars can only be split into 127 tokens */
		char value[255];  /* large enough to join previously split tokens */
		char *safeptr;
		int toknum;
		int len = 0;

		char *ptr = fgets (line+offs, 255-offs, inp);
		if (ptr == NULL)
			break;

		len = strlen (line);
		/* skip over-long lines */
		if (!feof (inp) && len > 0 &&  line[len-1] != '\n') {
			if (!skip_long_line) {
				if (!quiet)
					_LOGW ("Skipping over-long-line '%s...'", line);
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
		for (toknum = 0, token[toknum] = strtok_r (line, SPACES, &safeptr);
		     token[toknum] != NULL;
		     toknum++, token[toknum] = strtok_r (NULL, SPACES, &safeptr))
			;

		/* ignore comments and empty lines */
		if (toknum == 0 || *token[0]=='#')
			continue;

		if (toknum < 2) {
			if (!quiet) {
				_LOGW ("Can't parse interface line '%s'",
				       join_values_with_spaces (value, token));
			}
			skip_to_block = 1;
			continue;
		}

		/* There are six different stanzas:
		 * iface, mapping, auto, allow-*, source, and source-directory.
		 * Create a block for each of them except source and source-directory.  */

		/* iface stanza takes at least 3 parameters */
		if (nm_streq (token[0], "iface")) {
			if (toknum < 4) {
				if (!quiet) {
					_LOGW ("Can't parse iface line '%s'",
					       join_values_with_spaces (value, token));
				}
				continue;
			}
			add_block (parser, token[0], token[1]);
			skip_to_block = 0;
			add_data (parser, token[2], join_values_with_spaces (value, token + 3));
		}
		/* auto and allow-auto stanzas are equivalent,
		 * both can take multiple interfaces as parameters: add one block for each */
		else if (NM_IN_STRSET (token[0], "auto", "allow-auto")) {
			int i;

			for (i = 1; i < toknum; i++)
				add_block (parser, "auto", token[i]);
			skip_to_block = 0;
		}
		else if (nm_streq (token[0], "mapping")) {
			add_block (parser, token[0], join_values_with_spaces (value, token + 1));
			skip_to_block = 0;
		}
		/* allow-* can take multiple interfaces as parameters: add one block for each */
		else if (g_str_has_prefix (token[0], "allow-")) {
			int i;
			for (i = 1; i < toknum; i++)
				add_block (parser, token[0], token[i]);
			skip_to_block = 0;
		}
		/* source and source-directory stanzas take one or more paths as parameters */
		else if (NM_IN_STRSET (token[0], "source", "source-directory")) {
			int i;
			char *en_dir;

			skip_to_block = 0;
			en_dir = g_path_get_dirname (eni_file);
			for (i = 1; i < toknum; ++i) {
				if (nm_streq (token[0], "source-directory"))
					_ifparser_source (parser, token[i], en_dir, quiet, TRUE);
				else
					_ifparser_source (parser, token[i], en_dir, quiet, FALSE);
			}
			g_free (en_dir);
		}
		else {
			if (skip_to_block) {
				if (!quiet) {
					_LOGW ("ignoring out-of-block data '%s'",
					       join_values_with_spaces (value, token));
				}
			} else
				add_data (parser, token[0], join_values_with_spaces (value, token + 1));
		}
	}
	fclose (inp);

	if (!quiet)
		_LOGI ("      interface-parser: finished parsing file %s", eni_file);
}

static void
_ifparser_source (if_parser *parser, const char *path, const char *en_dir, int quiet, int dir)
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
		_LOGI ("      interface-parser: source line includes interfaces file(s) %s", abs_path);

	/* ifupdown uses WRDE_NOCMD for wordexp. */
	if (wordexp (abs_path, &we, WRDE_NOCMD)) {
		if (!quiet)
			_LOGW ("word expansion for %s failed", abs_path);
	} else {
		for (i = 0; i < we.we_wordc; i++) {
			if (dir) {
				source_dir = g_dir_open (we.we_wordv[i], 0, &error);
				if (!source_dir) {
					if (!quiet) {
						_LOGW ("Failed to open directory %s: %s",
						       we.we_wordv[i], error->message);
					}
					g_clear_error (&error);
				} else {
					while ((item = g_dir_read_name (source_dir)))
						_ifparser_source (parser, item, we.we_wordv[i], quiet, FALSE);
					g_dir_close (source_dir);
				}
			} else
				_recursive_ifparser (parser, we.we_wordv[i], quiet);
		}
		wordfree (&we);
	}
	g_free (abs_path);
}

if_parser *
ifparser_parse (const char *eni_file, int quiet)
{
	if_parser *parser;

	parser = g_slice_new (if_parser);
	c_list_init (&parser->block_lst_head);
	_recursive_ifparser (parser, eni_file, quiet);
	return parser;
}

static void
_destroy_data (if_data *ifd)
{
	c_list_unlink_stale (&ifd->data_lst);
	g_free (ifd);
}

static void
_destroy_block (if_block* ifb)
{
	if_data *ifd;

	while ((ifd = c_list_first_entry (&ifb->data_lst_head, if_data, data_lst)))
		_destroy_data (ifd);
	c_list_unlink_stale (&ifb->block_lst);
	g_free (ifb);
}

void
ifparser_destroy (if_parser *parser)
{
	if_block *ifb;

	while ((ifb = c_list_first_entry (&parser->block_lst_head, if_block, block_lst)))
		_destroy_block (ifb);
	g_slice_free (if_parser, parser);
}

if_block *
ifparser_getfirst (if_parser *parser)
{
	return c_list_first_entry (&parser->block_lst_head, if_block, block_lst);
}

guint
ifparser_get_num_blocks (if_parser *parser)
{
	return c_list_length (&parser->block_lst_head);
}

if_block *
ifparser_getif (if_parser *parser, const char* iface)
{
	if_block *ifb;

	c_list_for_each_entry (ifb, &parser->block_lst_head, block_lst) {
		if (   nm_streq (ifb->type, "iface")
		    && nm_streq (ifb->name, iface))
			return ifb;
	}
	return NULL;
}

static if_data *
ifparser_findkey (if_block* iface, const char *key)
{
	if_data *ifd;

	c_list_for_each_entry (ifd, &iface->data_lst_head, data_lst) {
		if (nm_streq (ifd->key, key))
			return ifd;
	}
	return NULL;
}

const char *
ifparser_getkey (if_block* iface, const char *key)
{
	if_data *ifd;

	ifd = ifparser_findkey (iface, key);
	return ifd ? ifd->data : NULL;
}

gboolean
ifparser_haskey (if_block* iface, const char *key)
{
	return !!ifparser_findkey (iface, key);
}

guint
ifparser_get_num_info (if_block* iface)
{
	return c_list_length (&iface->data_lst_head);
}
