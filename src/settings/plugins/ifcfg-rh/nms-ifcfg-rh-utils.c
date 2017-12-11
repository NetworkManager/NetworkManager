/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * (C) Copyright 2008 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nms-ifcfg-rh-utils.h"

#include <stdlib.h>
#include <string.h>

#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

#include "nms-ifcfg-rh-common.h"

/*
 * Check ';[a-fA-F0-9]{8}' file suffix used for temporary files by rpm when
 * installing packages.
 *
 * Implementation taken from upstart.
 */
static gboolean
check_rpm_temp_suffix (const char *path)
{
	const char *ptr;

	g_return_val_if_fail (path != NULL, FALSE);

	/* Matches *;[a-fA-F0-9]{8}; used by rpm */
	ptr = strrchr (path, ';');
	if (   ptr
	    && strspn (ptr + 1, "abcdefABCDEF0123456789") == 8
	    && !ptr[9])
		return TRUE;
	return FALSE;
}

static gboolean
check_suffix (const char *base, const char *tag)
{
	int len, tag_len;

	g_return_val_if_fail (base != NULL, TRUE);
	g_return_val_if_fail (tag != NULL, TRUE);

	len = strlen (base);
	tag_len = strlen (tag);
	if ((len > tag_len) && !strcasecmp (base + len - tag_len, tag))
		return TRUE;
	return FALSE;
}

gboolean
utils_should_ignore_file (const char *filename, gboolean only_ifcfg)
{
	gs_free char *base = NULL;

	g_return_val_if_fail (filename != NULL, TRUE);

	base = g_path_get_basename (filename);

	/* Only handle ifcfg, keys, and routes files */
	if (strncmp (base, IFCFG_TAG, strlen (IFCFG_TAG)) != 0) {
		if (only_ifcfg)
			return TRUE;
		else if (   strncmp (base, KEYS_TAG, strlen (KEYS_TAG)) != 0
		         && strncmp (base, ROUTE_TAG, strlen (ROUTE_TAG)) != 0
		         && strncmp (base, ROUTE6_TAG, strlen (ROUTE6_TAG)) != 0)
			return TRUE;
	}

	/* But not those that have certain suffixes */
	if (   check_suffix (base, BAK_TAG)
	    || check_suffix (base, TILDE_TAG)
	    || check_suffix (base, ORIG_TAG)
	    || check_suffix (base, REJ_TAG)
	    || check_suffix (base, RPMNEW_TAG)
	    || check_suffix (base, AUGNEW_TAG)
	    || check_suffix (base, AUGTMP_TAG)
	    || check_rpm_temp_suffix (base))
		return TRUE;

	return FALSE;
}

char *
utils_cert_path (const char *parent, const char *suffix, const char *extension)
{
	gs_free char *dir = NULL;
	const char *name;

	g_return_val_if_fail (parent, NULL);
	g_return_val_if_fail (suffix, NULL);
	g_return_val_if_fail (extension, NULL);

	name = utils_get_ifcfg_name (parent, FALSE);
	g_return_val_if_fail (name, NULL);

	dir = g_path_get_dirname (parent);
	return g_strdup_printf ("%s/%s-%s.%s", dir, name, suffix, extension);
}

const char *
utils_get_ifcfg_name (const char *file, gboolean only_ifcfg)
{
	const char *name;

	g_return_val_if_fail (file != NULL, NULL);

	name = strrchr (file, '/');
	if (!name)
		name = file;
	else
		name++;
	if (!*name)
		return NULL;

#define MATCH_TAG_AND_RETURN(name, TAG) \
	G_STMT_START { \
		if (strncmp (name, TAG, NM_STRLEN (TAG)) == 0) { \
			name += NM_STRLEN (TAG); \
			if (name[0] == '\0') \
				return NULL; \
			else \
				return name; \
		} \
	} G_STMT_END

	/* Do not detect alias files and return 'eth0:0' instead of 'eth0'.
	 * Unfortunately, we cannot be sure that our files don't contain colons,
	 * so we cannot reject files with colons.
	 *
	 * Instead, you must not call utils_get_ifcfg_name() with an alias file
	 * or files that are ignored. */
	MATCH_TAG_AND_RETURN (name, IFCFG_TAG);
	if (!only_ifcfg) {
		MATCH_TAG_AND_RETURN (name, KEYS_TAG);
		MATCH_TAG_AND_RETURN (name, ROUTE_TAG);
		MATCH_TAG_AND_RETURN (name, ROUTE6_TAG);
	}

	return NULL;
}

/* Used to get any ifcfg/extra file path from any other ifcfg/extra path
 * in the form <tag><name>.
 */
static char *
utils_get_extra_path (const char *parent, const char *tag)
{
	char *item_path = NULL, *dirname;
	const char *name;

	g_return_val_if_fail (parent != NULL, NULL);
	g_return_val_if_fail (tag != NULL, NULL);

	dirname = g_path_get_dirname (parent);
	if (!dirname)
		g_return_val_if_reached (NULL);

	name = utils_get_ifcfg_name (parent, FALSE);
	if (name) {
		if (!strcmp (dirname, "."))
			item_path = g_strdup_printf ("%s%s", tag, name);
		else
			item_path = g_strdup_printf ("%s/%s%s", dirname, tag, name);
	}
	g_free (dirname);

	return item_path;
}

char *
utils_get_ifcfg_path (const char *parent)
{
	return utils_get_extra_path (parent, IFCFG_TAG);
}

char *
utils_get_keys_path (const char *parent)
{
	return utils_get_extra_path (parent, KEYS_TAG);
}

char *
utils_get_route_path (const char *parent)
{
	return utils_get_extra_path (parent, ROUTE_TAG);
}

char *
utils_get_route6_path (const char *parent)
{
	return utils_get_extra_path (parent, ROUTE6_TAG);
}

shvarFile *
utils_get_extra_ifcfg (const char *parent, const char *tag, gboolean should_create)
{
	shvarFile *ifcfg = NULL;
	char *path;

	path = utils_get_extra_path (parent, tag);
	if (!path)
		return NULL;

	if (should_create && !g_file_test (path, G_FILE_TEST_EXISTS))
		ifcfg = svCreateFile (path);

	if (!ifcfg)
		ifcfg = svOpenFile (path, NULL);

	g_free (path);
	return ifcfg;
}

shvarFile *
utils_get_keys_ifcfg (const char *parent, gboolean should_create)
{
	return utils_get_extra_ifcfg (parent, KEYS_TAG, should_create);
}

shvarFile *
utils_get_route_ifcfg (const char *parent, gboolean should_create)
{
	return utils_get_extra_ifcfg (parent, ROUTE_TAG, should_create);
}

/* Finds out if route file has new or older format
 * Returns TRUE  - new syntax (ADDRESS<n>=a.b.c.d ...), error opening file or empty
 *         FALSE - older syntax, i.e. argument to 'ip route add' (1.2.3.0/24 via 11.22.33.44)
 */
gboolean
utils_has_route_file_new_syntax (const char *filename)
{
	char *contents = NULL;
	gsize len = 0;
	gboolean ret = FALSE;
	const char *pattern = "^[[:space:]]*ADDRESS[0-9]+=";

	g_return_val_if_fail (filename != NULL, TRUE);

	if (!g_file_get_contents (filename, &contents, &len, NULL))
		return TRUE;

	if (len <= 0) {
		ret = TRUE;
		goto gone;
	}

	if (g_regex_match_simple (pattern, contents, G_REGEX_MULTILINE, 0))
		ret = TRUE;

gone:
	g_free (contents);
	return ret;
}

gboolean
utils_has_complex_routes (const char *filename, int addr_family)
{
	g_return_val_if_fail (filename, TRUE);

	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET)) {
		gs_free char *rules = utils_get_extra_path (filename, RULE_TAG);

		if (g_file_test (rules, G_FILE_TEST_EXISTS))
			return TRUE;
	}

	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET6)) {
		gs_free char *rules = utils_get_extra_path (filename, RULE6_TAG);
		if (g_file_test (rules, G_FILE_TEST_EXISTS))
			return TRUE;
	}

	return FALSE;
}

/* Find out if the 'alias' file name might be an alias file for 'ifcfg' file name,
 * or any alias when 'ifcfg' is NULL. Does not check that it's actually a valid
 * alias name; that happens in reader.c
 */
gboolean
utils_is_ifcfg_alias_file (const char *alias, const char *ifcfg)
{
	g_return_val_if_fail (alias != NULL, FALSE);

	if (strncmp (alias, IFCFG_TAG, strlen (IFCFG_TAG)))
		return FALSE;

	if (ifcfg) {
		size_t len = strlen (ifcfg);

		return (strncmp (alias, ifcfg, len) == 0 && alias[len] == ':');
	} else {
		return (strchr (alias, ':') != NULL);
	}
}

char *
utils_detect_ifcfg_path (const char *path, gboolean only_ifcfg)
{
	gs_free char *base = NULL;
	char *ptr, *ifcfg = NULL;

	g_return_val_if_fail (path != NULL, NULL);

	if (utils_should_ignore_file (path, only_ifcfg))
		return NULL;

	base = g_path_get_basename (path);

	if (strncmp (base, IFCFG_TAG, NM_STRLEN (IFCFG_TAG)) == 0) {
		if (base[NM_STRLEN (IFCFG_TAG)] == '\0')
			return NULL;
		if (utils_is_ifcfg_alias_file (base, NULL)) {
			ifcfg = g_strdup (path);
			ptr = strrchr (ifcfg, ':');
			if (ptr && ptr > ifcfg) {
				*ptr = '\0';
				if (g_file_test (ifcfg, G_FILE_TEST_EXISTS)) {
					/* the file has a colon, so it is probably an alias.
					 * To be ~more~ certain that this is an alias file,
					 * check whether a corresponding base file exists. */
					if (only_ifcfg) {
						g_free (ifcfg);
						return NULL;
					}
					return ifcfg;
				}
			}
			g_free (ifcfg);
		}
		return g_strdup (path);
	}

	if (only_ifcfg)
		return NULL;
	return utils_get_ifcfg_path (path);
}

void
nms_ifcfg_rh_utils_user_key_encode (const char *key, GString *str_buffer)
{
	gsize i;

	nm_assert (key);
	nm_assert (str_buffer);

	for (i = 0; key[i]; i++) {
		char ch = key[i];

		/* we encode the key in only upper case letters, digits, and underscore.
		 * As we expect lower-case letters to be more common, we encode lower-case
		 * letters as upper case, and upper-case letters with a leading underscore. */

		if (ch >= '0' && ch <= '9') {
			g_string_append_c (str_buffer, ch);
			continue;
		}
		if (ch >= 'a' && ch <= 'z') {
			g_string_append_c (str_buffer, ch - 'a' + 'A');
			continue;
		}
		if (ch == '.') {
			g_string_append (str_buffer, "__");
			continue;
		}
		if (ch >= 'A' && ch <= 'Z') {
			g_string_append_c (str_buffer, '_');
			g_string_append_c (str_buffer, ch);
			continue;
		}
		g_string_append_printf (str_buffer, "_%03o", (unsigned) ch);
	}
}

gboolean
nms_ifcfg_rh_utils_user_key_decode (const char *name, GString *str_buffer)
{
	gsize i;

	nm_assert (name);
	nm_assert (str_buffer);

	if (!name[0])
		return FALSE;

	for (i = 0; name[i]; ) {
		char ch = name[i];

		if (ch >= '0' && ch <= '9') {
			g_string_append_c (str_buffer, ch);
			i++;
			continue;
		}
		if (ch >= 'A' && ch <= 'Z') {
			g_string_append_c (str_buffer, ch - 'A' + 'a');
			i++;
			continue;
		}

		if (ch == '_') {
			ch = name[i + 1];
			if (ch == '_') {
				g_string_append_c (str_buffer, '.');
				i += 2;
				continue;
			}
			if (ch >= 'A' && ch <= 'Z') {
				g_string_append_c (str_buffer, ch);
				i += 2;
				continue;
			}
			if (ch >= '0' && ch <= '7') {
				char ch2, ch3;
				unsigned v;

				ch2 = name[i + 2];
				if (!(ch2 >= '0' && ch2 <= '7'))
					return FALSE;

				ch3 = name[i + 3];
				if (!(ch3 >= '0' && ch3 <= '7'))
					return FALSE;

#define OCTAL_VALUE(ch) ((unsigned) ((ch) - '0'))
				v = (OCTAL_VALUE (ch)  << 6) +
				    (OCTAL_VALUE (ch2) << 3) +
				     OCTAL_VALUE (ch3);
				if (   v > 0xFF
				    || v == 0)
					return FALSE;
				ch = (char) v;
				if (   (ch >= 'A' && ch <= 'Z')
				    || (ch >= '0' && ch <= '9')
				    || (ch == '.')
				    || (ch >= 'a' && ch <= 'z')) {
					/* such characters are not expected to be encoded via
					 * octal representation. The encoding is invalid. */
					return FALSE;
				}
				g_string_append_c (str_buffer, ch);
				i += 4;
				continue;
			}
			return FALSE;
		}

		return FALSE;
	}

	return TRUE;
}
