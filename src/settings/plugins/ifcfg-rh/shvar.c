/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * shvar.c
 *
 * Implementation of non-destructively reading/writing files containing
 * only shell variable declarations and full-line comments.
 *
 * Copyright 1999,2000 Red Hat, Inc.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "nm-default.h"

#include "shvar.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nm-core-internal.h"
#include "nm-core-utils.h"
#include "nm-utils/nm-enum-utils.h"
#include "c-list/src/c-list.h"

/*****************************************************************************/

struct _shvarLine {

	CList lst;

	/* There are three cases:
	 *
	 * 1) the line is not a valid variable assignment (that is, it doesn't
	 *   start with a "FOO=" with possible whitespace prefix).
	 *   In that case, @key and @key_with_prefix are %NULL, and the entire
	 *   original line is in @line. Such entries are ignored for the most part.
	 *
	 * 2) if the line can be parsed with a "FOO=" assignment, then @line contains
	 *   the part after '=', @key_with_prefix contains the key "FOO" with possible
	 *   whitespace prefix, and @key points into @key_with_prefix skipping over the
	 *   whitespace.
	 *
	 * 3) like 2, but if the value was deleted via svSetValue(), the entry is not removed,
	 *   but only marked for deletion. That is done by clearing @line but preserving
	 *   @key/@key_with_prefix.
	 * */
	char *line;
	const char *key;
	char *key_with_prefix;
};

typedef struct _shvarLine shvarLine;

struct _shvarFile {
	char      *fileName;
	int        fd;
	CList      lst_head;
	gboolean   modified;
};

/*****************************************************************************/

/**
 * svParseBoolean:
 * @value: the input string
 * @fallback: the fallback value
 *
 * Parses a string and returns the boolean value it contains or,
 * in case no valid value is found, the fallback value. Valid values
 * are: "yes", "true", "t", "y", "1" and "no", "false", "f", "n", "0".
 *
 * Returns: the parsed boolean value or @fallback.
 */
gint
svParseBoolean (const char *value, gint fallback)
{
	if (!value)
		return fallback;

	if (   !g_ascii_strcasecmp ("yes", value)
	    || !g_ascii_strcasecmp ("true", value)
	    || !g_ascii_strcasecmp ("t", value)
	    || !g_ascii_strcasecmp ("y", value)
	    || !g_ascii_strcasecmp ("1", value))
		return TRUE;
	else if (   !g_ascii_strcasecmp ("no", value)
	         || !g_ascii_strcasecmp ("false", value)
	         || !g_ascii_strcasecmp ("f", value)
	         || !g_ascii_strcasecmp ("n", value)
	         || !g_ascii_strcasecmp ("0", value))
		return FALSE;

	return fallback;
}

/*****************************************************************************/

static gboolean
_shell_is_name (const char *key, gssize len)
{
	gssize i;

	/* whether @key is a valid identifier (name). */
	if (!key || len == 0)
		return FALSE;
	if (   !g_ascii_isalpha (key[0])
	    && key[0] != '_')
		return FALSE;
	for (i = 1; TRUE; i++) {
		if (len < 0) {
			if (!key[i])
				return TRUE;
		} else {
			if (i >= len)
				return TRUE;
		}
		if (   !g_ascii_isalnum (key[i])
		    && key[i] != '_')
			return FALSE;
	}
}

/*****************************************************************************/

/* like g_strescape(), except that it also escapes '\''' *sigh*.
 *
 * While at it, add $''. */
static char *
_escape_ansic (const char *source)
{
	const char *p;
	gchar *dest;
	gchar *q;

	nm_assert (source);

	p = (const char *) source;
	/* Each source byte needs maximally four destination chars (\777) */
	q = dest = g_malloc (strlen (source) * 4 + 1 + 3);

	*q++ = '$';
	*q++ = '\'';

	while (*p) {
		switch (*p) {
		case '\b':
			*q++ = '\\';
			*q++ = 'b';
			break;
		case '\f':
			*q++ = '\\';
			*q++ = 'f';
			break;
		case '\n':
			*q++ = '\\';
			*q++ = 'n';
			break;
		case '\r':
			*q++ = '\\';
			*q++ = 'r';
			break;
		case '\t':
			*q++ = '\\';
			*q++ = 't';
			break;
		case '\v':
			*q++ = '\\';
			*q++ = 'v';
			break;
		case '\\':
		case '"':
		case '\'':
			*q++ = '\\';
			*q++ = *p;
			break;
		default:
			if ((*p < ' ') || (*p >= 0177)) {
				*q++ = '\\';
				*q++ = '0' + (((*p) >> 6) & 07);
				*q++ = '0' + (((*p) >> 3) & 07);
				*q++ = '0' + ((*p) & 07);
			} else
				*q++ = *p;
			break;
		}
		p++;
	}
	*q++ = '\'';
	*q++ = '\0';

	nm_assert (q - dest <= strlen (source) * 4 + 1 + 3);

	return dest;
}

/*****************************************************************************/

#define _char_req_escape(ch)        NM_IN_SET (ch,      '\"', '\\',       '$', '`')
#define _char_req_escape_old(ch)    NM_IN_SET (ch,      '\"', '\\', '\'', '$', '`', '~')
#define _char_req_quotes(ch)        NM_IN_SET (ch, ' ',             '\'',           '~', '\t', '|', '&', ';', '(', ')', '<', '>')

const char *
svEscape (const char *s, char **to_free)
{
	char *new;
	gsize mangle = 0;
	gboolean requires_quotes = FALSE;
	int newlen;
	size_t i, j, slen;

	for (slen = 0; s[slen]; slen++) {
		if (_char_req_escape (s[slen]))
			mangle++;
		else if (_char_req_quotes (s[slen]))
			requires_quotes = TRUE;
		else if (s[slen] < ' ') {
			/* if the string contains newline we can only express it using ANSI C quotation
			 * (as we don't support line continuation).
			 * Additionally, ANSI control characters look odd with regular quotation, so handle
			 * them too. */
			return (*to_free = _escape_ansic (s));
		}
	}
	if (!mangle && !requires_quotes) {
		*to_free = NULL;
		return s;
	}

	newlen = slen + mangle + 3; /* 3 is extra ""\0 */
	new = g_malloc (newlen);

	j = 0;
	new[j++] = '"';
	for (i = 0; i < slen; i++) {
		if (_char_req_escape (s[i]))
			new[j++] = '\\';
		new[j++] = s[i];
	}
	new[j++] = '"';
	new[j++] = '\0';

	nm_assert (j == slen + mangle + 3);

	*to_free = new;
	return new;
}

static gboolean
_looks_like_old_svescaped (const char *value)
{
	gsize k;

	if (value[0] != '"')
		return FALSE;

	for (k = 1; ; k++) {
		if (value[k] == '\0')
			return FALSE;
		if (!_char_req_escape_old (value[k]))
			continue;

		if (value[k] == '"')
			return (value[k + 1] == '\0');
		else if (value[k] == '\\') {
			k++;
			if (!_char_req_escape_old (value[k]))
				return FALSE;
		} else
			return FALSE;
	}
}

static gboolean
_ch_octal_is (char ch)
{
	return ch >= '0' && ch < '8';
}

static guint8
_ch_octal_get (char ch)
{
	nm_assert (_ch_octal_is (ch));
	return (ch - '0');
}

static gboolean
_ch_hex_is (char ch)
{
	return g_ascii_isxdigit (ch);
}

static guint8
_ch_hex_get (char ch)
{
	nm_assert (_ch_hex_is (ch));
	return ch <= '9' ? ch - '0' : (ch & 0x4F) - 'A' + 10;
}

static void
_gstr_init (GString **str, const char *value, gsize i)
{
	nm_assert (str);
	nm_assert (value);

	if (!(*str)) {
		/* if @str is not yet initialized, it allocates
		 * a new GString and copies @i characters from
		 * @value over.
		 *
		 * Unescaping usually does not extend the length of a string,
		 * so we might be tempted to allocate a fixed buffer of length
		 * (strlen(value)+CONST).
		 * However, due to $'\Ux' escapes, the maxium length is some
		 * (FACTOR*strlen(value) + CONST), which is non trivial to get
		 * right in all cases. Also, we would have to provision for the
		 * very unlikely extreme case.
		 * Instead, use a GString buffer which can grow as needed. But for an
		 * initial guess, strlen(value) is a good start */
		*str = g_string_new_len (NULL, strlen (value) + 3);
		if (i)
			g_string_append_len (*str, value, i);
	}
}

const char *
svUnescape (const char *value, char **to_free)
{
	gsize i, j;
	GString *str = NULL;
	int looks_like_old_svescaped = -1;

	/* we handle bash syntax here (note that ifup has #!/bin/bash.
	 * Thus, see https://www.gnu.org/software/bash/manual/html_node/Quoting.html#Quoting */

	/* @value shall start with the first character after "FOO=" */

	nm_assert (value);
	nm_assert (to_free);

	/* we don't expect any newlines. They must be filtered out before-hand.
	 * We also don't support line continuation. */
	nm_assert (!NM_STRCHAR_ANY (value, ch, ch == '\n'));

	i = 0;
	while (TRUE) {

		if (value[i] == '\0')
			goto out_value;

		if (   g_ascii_isspace (value[i])
		    || value[i] == ';') {
			gboolean has_semicolon = (value[i] == ';');

			/* starting with space is only allowed, if the entire
			 * string consists of spaces (possibly terminated by a comment).
			 * This disallows for example
			 *   LANG=C ls -1
			 *   LANG=  ls -1
			 * but allows
			 *   LANG= #comment
			 *
			 * As a special case, we also allow one trailing semicolon, as long
			 * it is only followed by whitespace or a #-comment.
			 *   FOO=;
			 *   FOO=a;
			 *   FOO=b ; #hallo
			 */
			j = i + 1;
			while (   g_ascii_isspace (value[j])
			       || (   !has_semicolon
			           && (has_semicolon = (value[j] == ';'))))
				j++;
			if (!NM_IN_SET (value[j], '\0', '#'))
				goto out_error;
			goto out_value;
		}

		if (value[i] == '\\') {
			/* backslash escape */
			_gstr_init (&str, value, i);
			i++;
			if (G_UNLIKELY (value[i] == '\0')) {
				/* we don't support line continuation */
				goto out_error;
			}
			g_string_append_c (str, value[i]);
			i++;
			goto loop1_next;
		}

		if (value[i] == '\'') {
			/* single quotes */
			_gstr_init (&str, value, i);
			i++;
			j = i;
			while (TRUE) {
				if (value[j] == '\0') {
					/* unterminated single quote. We don't support line continuation */
					goto out_error;
				}
				if (value[j] == '\'')
					break;
				j++;
			}
			g_string_append_len (str, &value[i], j - i);
			i = j + 1;
			goto loop1_next;
		}

		if (value[i] == '"') {
			/* double quotes */
			_gstr_init (&str, value, i);
			i++;
			while (TRUE) {
				if (value[i] == '"') {
					i++;
					break;
				}
				if (value[i] == '\0') {
					/* unterminated double quote. We don't support line continuation. */
					goto out_error;
				}
				if (NM_IN_SET (value[i], '`', '$')) {
					/* we don't support shell expansion. */
					goto out_error;
				}
				if (value[i] == '\\') {
					i++;
					if (value[i] == '\0') {
						/* we don't support line continuation */
						goto out_error;
					}
					if (NM_IN_SET (value[i], '$', '`', '"', '\\')) {
						/* Drop the backslash. */
					} else if (NM_IN_SET (value[i], '\'', '~')) {
						/* '\'' and '~' in double qoutes are not handled special by shell.
						 * However, old versions of svEscape() would wrongly use double-quoting
						 * with backslash escaping for these characters (expecting svUnescape()
						 * to remove the backslash).
						 *
						 * In order to preserve previous behavior, we continue to read such
						 * strings different then shell does. */

						/* Actually, we can relax this. Old svEscape() escaped the entire value
						 * in a particular way with double quotes.
						 * If the value doesn't exactly look like something as created by svEscape(),
						 * don't do the compat hack and preserve the backslash. */
						if (looks_like_old_svescaped < 0)
							looks_like_old_svescaped = _looks_like_old_svescaped (value);
						if (!looks_like_old_svescaped)
							g_string_append_c (str, '\\');
					} else
						g_string_append_c (str, '\\');
				}
				g_string_append_c (str, value[i]);
				i++;
			}
			goto loop1_next;
		}

		if (   value[i] == '$'
		    && value[i + 1] == '\'') {
			/* ANSI-C Quoting */
			_gstr_init (&str, value, i);
			i += 2;
			while (TRUE) {
				char ch;

				if (value[i] == '\'') {
					i++;
					break;
				}
				if (value[i] == '\0') {
					/* unterminated double quote. We don't support line continuation. */
					goto out_error;
				}
				if (value[i] == '\\') {

					i++;
					if (value[i] == '\0') {
						/* we don't support line continuation */
						goto out_error;
					}
					switch (value[i]) {
					case 'a':  ch = '\a';  break;
					case 'b':  ch = '\b';  break;
					case 'e':  ch = '\e';  break;
					case 'E':  ch = '\E';  break;
					case 'f':  ch = '\f';  break;
					case 'n':  ch = '\n';  break;
					case 'r':  ch = '\r';  break;
					case 't':  ch = '\t';  break;
					case 'v':  ch = '\v';  break;
					case '?':  ch = '\?';  break;
					case '"':  ch = '"';   break;
					case '\\': ch = '\\';  break;
					case '\'': ch = '\'';  break;
					default:
						if (_ch_octal_is (value[i])) {
							guint v;

							v = _ch_octal_get (value[i]);
							i++;
							if (_ch_octal_is (value[i])) {
								v = (v * 8) + _ch_octal_get (value[i]);
								i++;
								if (_ch_octal_is (value[i])) {
									v = (v * 8) + _ch_octal_get (value[i]);
									i++;
								}
							}
							/* like bash, we cut too large numbers off. E.g. A=$'\772' becomes 0xfa  */
							g_string_append_c (str, (guint8) v);
						} else if (NM_IN_SET (value[i], 'x', 'u', 'U')) {
							const char escape_type = value[i];
							int max_digits = escape_type == 'x' ? 2 : escape_type == 'u' ? 4 : 8;
							guint64 v;

							i++;
							if (!_ch_hex_is (value[i])) {
								/* missing hex value after "\x" escape. This is treated like no escaping. */
								g_string_append_c (str, '\\');
								g_string_append_c (str, escape_type);
							} else {
								v = _ch_hex_get (value[i]);
								i++;

								while (--max_digits > 0) {
									if (!_ch_hex_is (value[i]))
										break;
									v = v * 16 + _ch_hex_get (value[i]);
									i++;
								}
								if (escape_type == 'x')
									g_string_append_c (str, v);
								else {
									/* we treat the unicode escapes as utf-8 encoded values. */
									g_string_append_unichar (str, v);
								}
							}
						} else {
							g_string_append_c (str, '\\');
							g_string_append_c (str, value[i]);
							i++;
						}
						goto loop_ansic_next;
					}
				} else
					ch = value[i];
				g_string_append_c (str, ch);
				i++;
loop_ansic_next: ;
			}
			goto loop1_next;
		}

		if (NM_IN_SET (value[i], '|', '&', '(', ')', '<', '>')) {
			/* shell metacharacters are not supported without quoting.
			 * Note that ';' is already handled above. */
			goto out_error;
		}

		/* an unquoted, regular character. Just consume it directly. */
		if (str)
			g_string_append_c (str, value[i]);
		i++;

loop1_next: ;
	}

	nm_assert_not_reached ();

out_value:
	if (i == 0) {
		nm_assert (!str);
		*to_free = NULL;
		return "";
	}

	if (str) {
		if (str->len == 0 || str->str[0] == '\0') {
			g_string_free (str, TRUE);
			*to_free = NULL;
			return "";
		} else {
			*to_free = g_string_free (str, FALSE);
			return *to_free;
		}
	}

	if (value[i] != '\0') {
		*to_free = g_strndup (value, i);
		return *to_free;
	}

	*to_free = NULL;
	return value;

out_error:
	if (str)
		g_string_free (str, TRUE);
	*to_free = NULL;
	return NULL;
}

/*****************************************************************************/

static shvarFile *
svFile_new (const char *name)
{
	shvarFile *s;

	s = g_slice_new0 (shvarFile);
	s->fd = -1;
	s->fileName = g_strdup (name);
	c_list_init (&s->lst_head);
	return s;
}

const char *
svFileGetName (const shvarFile *s)
{
	nm_assert (s);

	return s->fileName;
}

void
_nmtst_svFileSetName (shvarFile *s, const char *fileName)
{
	/* changing the file name is not supported for regular
	 * operation. Only allowed to use in tests, othewise,
	 * the filename is immutable. */
	g_free (s->fileName);
	s->fileName = g_strdup (fileName);
}

void
_nmtst_svFileSetModified (shvarFile *s)
{
	/* marking a file as modified is only for testing. */
	s->modified = TRUE;
}

/*****************************************************************************/

static void
ASSERT_shvarLine (const shvarLine *line)
{
#if NM_MORE_ASSERTS > 5
	const char *s, *s2;

	nm_assert (line);
	if (!line->key) {
		nm_assert (line->line);
		nm_assert (!line->key_with_prefix);
		s = nm_str_skip_leading_spaces (line->line);
		s2 = strchr (s, '=');
		nm_assert (!s2 || !_shell_is_name (s, s2 - s));
	} else {
		nm_assert (line->key_with_prefix);
		nm_assert (line->key == nm_str_skip_leading_spaces (line->key_with_prefix));
		nm_assert (_shell_is_name (line->key, -1));
	}
#endif
}

static shvarLine *
line_new_parse (const char *value, gsize len)
{
	shvarLine *line;
	gsize k, e;

	nm_assert (value);

	line = g_slice_new0 (shvarLine);
	c_list_init (&line->lst);

	for (k = 0; k < len; k++) {
		if (g_ascii_isspace (value[k]))
			continue;

		if (   g_ascii_isalpha (value[k])
		    || value[k] == '_') {
			for (e = k + 1; e < len; e++) {
				if (value[e] == '=') {
					nm_assert (_shell_is_name (&value[k], e - k));
					line->line = g_strndup (&value[e + 1], len - e - 1);
					line->key_with_prefix = g_strndup (value, e);
					line->key = &line->key_with_prefix[k];
					ASSERT_shvarLine (line);
					return line;
				}
				if (   !g_ascii_isalnum (value[e])
				    && value[e] != '_')
					break;
			}
		}
		break;
	}
	line->line = g_strndup (value, len);
	ASSERT_shvarLine (line);
	return line;
}

static shvarLine *
line_new_build (const char *key, const char *value)
{
	char *value_escaped = NULL;
	shvarLine *line;

	value = svEscape (value, &value_escaped);

	line = g_slice_new (shvarLine);
	c_list_init (&line->lst);
	line->line = value_escaped ?: g_strdup (value);
	line->key_with_prefix = g_strdup (key);
	line->key = line->key_with_prefix;
	ASSERT_shvarLine (line);
	return line;
}

static gboolean
line_set (shvarLine *line, const char *value)
{
	char *value_escaped = NULL;
	gboolean changed = FALSE;

	ASSERT_shvarLine (line);
	nm_assert (line->key);

	if (line->key != line->key_with_prefix) {
		memmove (line->key_with_prefix, line->key, strlen (line->key) + 1);
		line->key = line->key_with_prefix;
		changed = TRUE;
		ASSERT_shvarLine (line);
	}

	value = svEscape (value, &value_escaped);

	if (line->line) {
		if (nm_streq (value, line->line)) {
			g_free (value_escaped);
			return changed;
		}
		g_free (line->line);
	}

	line->line = value_escaped ?: g_strdup (value);
	ASSERT_shvarLine (line);
	return TRUE;
}

static void
line_free (shvarLine *line)
{
	ASSERT_shvarLine (line);
	g_free (line->line);
	g_free (line->key_with_prefix);
	c_list_unlink_stale (&line->lst);
	g_slice_free (shvarLine, line);
}

/*****************************************************************************/

/* Open the file <name>, returning a shvarFile on success and NULL on failure.
 * Add a wrinkle to let the caller specify whether or not to create the file
 * (actually, return a structure anyway) if it doesn't exist.
 */
static shvarFile *
svOpenFileInternal (const char *name, gboolean create, GError **error)
{
	shvarFile *s;
	gboolean closefd = FALSE;
	int errsv = 0;
	char *arena;
	const char *p, *q;
	gs_free_error GError *local = NULL;
	nm_auto_close int fd = -1;

	if (create)
		fd = open (name, O_RDWR | O_CLOEXEC); /* NOT O_CREAT */
	if (fd < 0) {
		/* try read-only */
		fd = open (name, O_RDONLY | O_CLOEXEC); /* NOT O_CREAT */
		if (fd < 0)
			errsv = errno;
		else
			closefd = TRUE;
	}

	if (fd < 0) {
		if (create)
			return svFile_new (name);

		g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errsv),
		             "Could not read file '%s': %s",
		             name, strerror (errsv));
		return NULL;
	}

	if (nm_utils_fd_get_contents (closefd ? nm_steal_fd (&fd) : fd,
	                              closefd,
	                              10 * 1024 * 1024,
	                              &arena,
	                              NULL,
	                              &local) < 0) {
		if (create)
			return svFile_new (name);

		g_set_error (error, G_FILE_ERROR,
		             local->domain == G_FILE_ERROR ? local->code : G_FILE_ERROR_FAILED,
		             "Could not read file '%s': %s",
		             name, local->message);
		return NULL;
	}

	s = svFile_new (name);

	for (p = arena; (q = strchr (p, '\n')) != NULL; p = q + 1)
		c_list_link_tail (&s->lst_head, &line_new_parse (p, q - p)->lst);
	if (p[0])
		c_list_link_tail (&s->lst_head, &line_new_parse (p, strlen (p))->lst);
	g_free (arena);

	/* closefd is set if we opened the file read-only, so go ahead and
	 * close it, because we can't write to it anyway */
	if (!closefd) {
		nm_assert (fd > 0);
		s->fd = nm_steal_fd (&fd);
	}

	return s;
}

/* Open the file <name>, return shvarFile on success, NULL on failure */
shvarFile *
svOpenFile (const char *name, GError **error)
{
	return svOpenFileInternal (name, FALSE, error);
}

/* Create a new file structure, returning actual data if the file exists,
 * and a suitable starting point if it doesn't.
 */
shvarFile *
svCreateFile (const char *name)
{
	return svOpenFileInternal (name, TRUE, NULL);
}

/*****************************************************************************/

GHashTable *
svGetKeys (shvarFile *s)
{
	GHashTable *keys = NULL;
	CList *current;
	const shvarLine *line;

	nm_assert (s);

	c_list_for_each (current, &s->lst_head) {
		line = c_list_entry (current, shvarLine, lst);
		if (line->key && line->line) {
			/* we don't clone the keys. The keys are only valid
			 * until @s gets modified. */
			if (!keys)
				keys = g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, NULL);
			g_hash_table_add (keys, (gpointer) line->key);
		}
	}
	return keys;
}

/*****************************************************************************/

const char *
svFindFirstKeyWithPrefix (shvarFile *s, const char *key_prefix)
{
	CList *current;
	const shvarLine *l;

	g_return_val_if_fail (s, NULL);
	g_return_val_if_fail (key_prefix, NULL);

	c_list_for_each (current, &s->lst_head) {
		l = c_list_entry (current, shvarLine, lst);
		if (   l->key
		    && l->line
		    && g_str_has_prefix (l->key, key_prefix))
			return l->key;
	}

	return NULL;
}

/*****************************************************************************/

static const char *
_svGetValue (shvarFile *s, const char *key, char **to_free)
{
	CList *current;
	const shvarLine *line, *l;
	const char *v;

	nm_assert (s);
	nm_assert (_shell_is_name (key, -1));
	nm_assert (to_free);

	line = NULL;
	c_list_for_each (current, &s->lst_head) {
		l = c_list_entry (current, shvarLine, lst);
		if (l->key && nm_streq (l->key, key))
			line = l;
	}

	if (line && line->line) {
		v = svUnescape (line->line, to_free);
		if (!v) {
			/* a wrongly quoted value is treated like the empty string.
			 * See also svWriteFile(), which handles unparsable values
			 * that way. */
			nm_assert (!*to_free);
			return "";
		}
		return v;
	}
	*to_free = NULL;
	return NULL;
}

/* Returns the value for key. The value is either owned by @s
 * or returned as to_free. This aims to avoid cloning the string.
 *
 * - like svGetValue_cp(), but avoids cloning the value if possible.
 * - like svGetValueStr(), but does not ignore empty string values.
 */
const char *
svGetValue (shvarFile *s, const char *key, char **to_free)
{
	g_return_val_if_fail (s, NULL);
	g_return_val_if_fail (key, NULL);
	g_return_val_if_fail (to_free, NULL);

	return _svGetValue (s, key, to_free);
}

/* Returns the value for key. The value is either owned by @s
 * or returned as to_free. This aims to avoid cloning the string.
 *
 * - like svGetValue(), but does not return an empty string.
 * - like svGetValueStr_cp(), but avoids cloning the value if possible.
 */
const char *
svGetValueStr (shvarFile *s, const char *key, char **to_free)
{
	const char *value;

	g_return_val_if_fail (s, NULL);
	g_return_val_if_fail (key, NULL);
	g_return_val_if_fail (to_free, NULL);

	value = _svGetValue (s, key, to_free);
	if (!value || !value[0]) {
		nm_assert (!*to_free);
		return NULL;
	}
	return value;
}

/* Returns the value for key. The returned value must be freed
 * by the caller.
 *
 * - like svGetValue(), but always returns a copy of the value.
 * - like svGetValueStr_cp(), but does not ignore an empty string.
 */
char *
svGetValue_cp (shvarFile *s, const char *key)
{
	char *to_free;
	const char *value;

	g_return_val_if_fail (s, NULL);
	g_return_val_if_fail (key, NULL);

	value = _svGetValue (s, key, &to_free);
	if (!value) {
		nm_assert (!to_free);
		return NULL;
	}
	return to_free ?: g_strdup (value);
}

/* Returns the value for key. The returned value must be freed
 * by the caller.
 * If the key is unset or the value an empty string, NULL is returned.
 *
 * - like svGetValueStr(), but always returns a copy of the value.
 * - like svGetValue_cp(), but returns NULL instead of an empty string.
 */
char *
svGetValueStr_cp (shvarFile *s, const char *key)
{
	char *to_free;
	const char *value;

	g_return_val_if_fail (s, NULL);
	g_return_val_if_fail (key, NULL);

	value = _svGetValue (s, key, &to_free);
	if (!value || !value[0]) {
		nm_assert (!to_free);
		return NULL;
	}
	return to_free ?: g_strdup (value);
}

/* svGetValueBoolean:
 * @s: fhe file
 * @key: the name of the key to read
 * @fallback: the fallback value in any error case
 *
 * Reads a value @key and converts it to a boolean using svParseBoolean().
 *
 * Returns: the parsed boolean value or @fallback.
 */
gint
svGetValueBoolean (shvarFile *s, const char *key, gint fallback)
{
	gs_free char *to_free = NULL;
	const char *value;

	value = _svGetValue (s, key, &to_free);
	return svParseBoolean (value, fallback);
}

/* svGetValueInt64:
 * @s: fhe file
 * @key: the name of the key to read
 * @base: the numeric base (usually 10). Setting to 0 means "auto". Usually you want 10.
 * @min: the minimum for range-check
 * @max: the maximum for range-check
 * @fallback: the fallback value in any error case
 *
 * Reads a value @key and converts it to an integer using _nm_utils_ascii_str_to_int64().
 * In case of error, @errno will be set and @fallback returned. */
gint64
svGetValueInt64 (shvarFile *s, const char *key, guint base, gint64 min, gint64 max, gint64 fallback)
{
	char *to_free;
	const char *value;
	gint64 result;
	int errsv;

	value = _svGetValue (s, key, &to_free);
	if (!value) {
		nm_assert (!to_free);
		/* indicate that the key does not exist (or has a syntax error
		 * and svUnescape() failed). */
		errno = ENOKEY;
		return fallback;
	}

	result = _nm_utils_ascii_str_to_int64 (value, base, min, max, fallback);
	if (to_free) {
		errsv = errno;
		g_free (to_free);
		errno = errsv;
	}
	return result;
}

gboolean
svGetValueEnum (shvarFile *s, const char *key,
                GType gtype, int *out_value,
                GError **error)
{
	gs_free char *to_free = NULL;
	const char *svalue;
	gs_free char *err_token = NULL;
	int value;

	svalue = _svGetValue (s, key, &to_free);
	if (!svalue) {
		/* don't touch out_value. The caller is supposed
		 * to initialize it with the default value. */
		return TRUE;
	}

	if (!nm_utils_enum_from_str (gtype, svalue, &value, &err_token)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "Invalid token \"%s\" in \"%s\" for %s",
		             err_token, svalue, key);
		return FALSE;
	}

	NM_SET_OUT (out_value, value);
	return TRUE;
}

/*****************************************************************************/

static gboolean
_is_all_digits (const char *str)
{
	return    str[0]
	       && NM_STRCHAR_ALL (str, ch, g_ascii_isdigit (ch));
}

#define IS_NUMBERED_TAG(key, tab_name) \
	({ \
		const char *_key = (key); \
		\
		(   (strncmp (_key, tab_name, NM_STRLEN (tab_name)) == 0) \
		 && _is_all_digits (&_key[NM_STRLEN (tab_name)])); \
	})

gboolean
svUnsetAll (shvarFile *s, SvKeyType match_key_type)
{
	CList *current;
	shvarLine *line;
	gboolean changed = FALSE;

	g_return_val_if_fail (s, FALSE);

	c_list_for_each (current, &s->lst_head) {
		line = c_list_entry (current, shvarLine, lst);
		ASSERT_shvarLine (line);
		if (!line->key)
			continue;

		if (NM_FLAGS_HAS (match_key_type, SV_KEY_TYPE_ANY))
			goto do_clear;
		if (NM_FLAGS_HAS (match_key_type, SV_KEY_TYPE_ROUTE_SVFORMAT)) {
			if (   IS_NUMBERED_TAG (line->key, "ADDRESS")
			    || IS_NUMBERED_TAG (line->key, "NETMASK")
			    || IS_NUMBERED_TAG (line->key, "GATEWAY")
			    || IS_NUMBERED_TAG (line->key, "METRIC")
			    || IS_NUMBERED_TAG (line->key, "OPTIONS"))
				goto do_clear;
		}
		if (NM_FLAGS_HAS (match_key_type, SV_KEY_TYPE_IP4_ADDRESS)) {
			if (   IS_NUMBERED_TAG (line->key, "IPADDR")
			    || IS_NUMBERED_TAG (line->key, "PREFIX")
			    || IS_NUMBERED_TAG (line->key, "NETMASK")
			    || IS_NUMBERED_TAG (line->key, "GATEWAY"))
				goto do_clear;
		}
		if (NM_FLAGS_HAS (match_key_type, SV_KEY_TYPE_USER)) {
			if (g_str_has_prefix (line->key, "NM_USER_"))
				goto do_clear;
		}
		if (NM_FLAGS_HAS (match_key_type, SV_KEY_TYPE_TC)) {
			if (   IS_NUMBERED_TAG (line->key, "QDISC")
			    || IS_NUMBERED_TAG (line->key, "FILTER"))
				goto do_clear;
		}

		continue;
do_clear:
		if (nm_clear_g_free (&line->line)) {
			ASSERT_shvarLine (line);
			changed = TRUE;
		}
	}

	if (changed)
		s->modified = TRUE;
	return changed;
}

/* Same as svSetValueStr() but it preserves empty @value -- contrary to
 * svSetValueStr() for which "" effectively means to remove the value. */
gboolean
svSetValue (shvarFile *s, const char *key, const char *value)
{
	CList *current;
	shvarLine *line, *l;
	gboolean changed = FALSE;

	g_return_val_if_fail (s, FALSE);
	g_return_val_if_fail (key, FALSE);

	nm_assert (_shell_is_name (key, -1));

	line = NULL;
	c_list_for_each (current, &s->lst_head) {
		l = c_list_entry (current, shvarLine, lst);
		if (l->key && nm_streq (l->key, key)) {
			if (line) {
				/* if we find multiple entries for the same key, we can
				 * delete all but the last. */
				line_free (line);
				changed = TRUE;
			}
			line = l;
		}
	}

	if (!value) {
		if (line) {
			if (nm_clear_g_free (&line->line)) {
				changed = TRUE;
			}
		}
	} else {
		if (!line) {
			c_list_link_tail (&s->lst_head, &line_new_build (key, value)->lst);
			changed = TRUE;
		} else {
			if (line_set (line, value))
				changed = TRUE;
		}
	}

	if (changed)
		s->modified = TRUE;
	return changed;
}

/* Set the variable <key> equal to the value <value>.
 * If <key> does not exist, and the <current> pointer is set, append
 * the key=value pair after that line.  Otherwise, append the pair
 * to the bottom of the file.
 */
gboolean
svSetValueStr (shvarFile *s, const char *key, const char *value)
{
	return svSetValue (s, key, value && value[0] ? value : NULL);
}

gboolean
svSetValueInt64 (shvarFile *s, const char *key, gint64 value)
{
	char buf[NM_DECIMAL_STR_MAX (value)];

	return svSetValue (s, key, nm_sprintf_buf (buf, "%"G_GINT64_FORMAT, value));
}

gboolean
svSetValueInt64_cond (shvarFile *s, const char *key, gboolean do_set, gint64 value)
{
	if (do_set)
		return svSetValueInt64 (s, key, value);
	else
		return svUnsetValue (s, key);
}

gboolean
svSetValueBoolean (shvarFile *s, const char *key, gboolean value)
{
	return svSetValue (s, key, value ? "yes" : "no");
}

gboolean
svSetValueEnum (shvarFile *s, const char *key, GType gtype, int value)
{
	gs_free char *v = NULL;

	v = _nm_utils_enum_to_str_full (gtype, value, " ", NULL);
	return svSetValueStr (s, key, v);
}

gboolean
svUnsetValue (shvarFile *s, const char *key)
{
	return svSetValue (s, key, NULL);
}

/*****************************************************************************/

/* Write the current contents iff modified.  Returns FALSE on error
 * and TRUE on success.  Do not write if no values have been modified.
 * The mode argument is only used if creating the file, not if
 * re-writing an existing file, and is passed unchanged to the
 * open() syscall.
 */
gboolean
svWriteFile (shvarFile *s, int mode, GError **error)
{
	FILE *f;
	int tmpfd;
	CList *current;

	if (s->modified) {
		if (s->fd == -1)
			s->fd = open (s->fileName, O_WRONLY | O_CREAT | O_CLOEXEC, mode);
		if (s->fd == -1) {
			int errsv = errno;

			g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errsv),
			             "Could not open file '%s' for writing: %s",
			             s->fileName, strerror (errsv));
			return FALSE;
		}
		if (ftruncate (s->fd, 0) < 0) {
			int errsv = errno;

			g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errsv),
			             "Could not overwrite file '%s': %s",
			             s->fileName, strerror (errsv));
			return FALSE;
		}

		tmpfd = fcntl (s->fd, F_DUPFD_CLOEXEC, 0);
		if (tmpfd == -1) {
			int errsv = errno;

			g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errsv),
			             "Internal error writing file '%s': %s",
			             s->fileName, strerror (errsv));
			return FALSE;
		}
		f = fdopen (tmpfd, "w");
		fseek (f, 0, SEEK_SET);
		c_list_for_each (current, &s->lst_head) {
			const shvarLine *line = c_list_entry (current, shvarLine, lst);
			const char *str;
			char *s_tmp;
			gboolean valid_value;

			ASSERT_shvarLine (line);

			if (!line->key) {
				str = nm_str_skip_leading_spaces (line->line);
				if (NM_IN_SET (str[0], '\0', '#'))
					fprintf (f, "%s\n", line->line);
				else
					fprintf (f, "#NM: %s\n", line->line);
				continue;
			}

			if (!line->line)
				continue;

			/* we check that the assignment can be properly unescaped. */
			valid_value = !!svUnescape (line->line, &s_tmp);
			g_free (s_tmp);

			if (valid_value)
				fprintf (f, "%s=%s\n", line->key_with_prefix, line->line);
			else {
				fprintf (f, "%s=\n", line->key);
				fprintf (f, "#NM: %s=%s\n", line->key_with_prefix, line->line);
			}
		}
		fclose (f);
	}

	return TRUE;
}

void
svCloseFile (shvarFile *s)
{
	CList *current, *safe;

	g_return_if_fail (s != NULL);

	if (s->fd >= 0)
		nm_close (s->fd);
	g_free (s->fileName);
	c_list_for_each_safe (current, safe, &s->lst_head)
		line_free (c_list_entry (current, shvarLine, lst));
	g_slice_free (shvarFile, s);
}
