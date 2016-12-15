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

/*****************************************************************************/

typedef struct {
	gchar *original;
	gchar *value;
} shvarLine;

struct _shvarFile {
	char      *fileName;    /* read-only */
	int        fd;          /* read-only */
	GList     *lineList;    /* read-only */
	gboolean   modified;    /* ignore */
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
_shell_is_name (const char *key)
{
	/* whether @key is a valid identifier (name). */
	if (!key)
		return FALSE;
	if (   !g_ascii_isalpha (key[0])
	    && key[0] != '_')
		return FALSE;
	return NM_STRCHAR_ALL (&key[1], ch,
	                       g_ascii_isalnum (ch) || ch == '_');
}

static const char *
_shell_is_name_assignment (const char *key)
{
	/* whether @key is a valid identifier (name). */
	if (!key)
		return NULL;
	if (   !g_ascii_isalpha (key[0])
	    && key[0] != '_')
		return NULL;
	while (TRUE) {
		const char ch = (++key)[0];

		if (ch == '=')
			return &key[1];
		if (!g_ascii_isalnum (ch) && ch != '_')
			return NULL;
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

	slen = strlen (s);

	for (i = 0; i < slen; i++) {
		if (_char_req_escape (s[i]))
			mangle++;
		else if (_char_req_quotes (s[i]))
			requires_quotes = TRUE;
		else if (s[i] < ' ') {
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

const char *
svFileGetName (const shvarFile *s)
{
	nm_assert (s);

	return s->fileName;
}

void
svFileSetName (shvarFile *s, const char *fileName)
{
	g_free (s->fileName);
	s->fileName = g_strdup (fileName);
}

void
svFileSetModified (shvarFile *s)
{
	s->modified = TRUE;
}

/*****************************************************************************/

static shvarLine *
line_new (char *value)
{
	shvarLine *line;

	line = g_slice_new0 (shvarLine);
	line->original = line->value = value;

	return line;
}

static void
line_free (shvarLine *line)
{
	g_free (line->value);
	if (line->original != line->value)
		g_free (line->original);
	g_slice_free (shvarLine, line);
}

static const char *
line_value (const shvarLine *line, const char *key)
{
#if NM_MORE_ASSERTS > 5
	const char *v;

	nm_assert (line);
	nm_assert (line->value);
	nm_assert (key && _shell_is_name (key));

	v = line->value;
	while (g_ascii_isspace (v[0]))
		v++;
	nm_assert (g_str_has_prefix (v, key));
	nm_assert (v[strlen (key)] == '=');
	nm_assert (&v[strlen (key)] == strchr (line->value, '='));
#endif
	return strchr (line->value, '=') + 1;
}

/*****************************************************************************/

/* Open the file <name>, returning a shvarFile on success and NULL on failure.
 * Add a wrinkle to let the caller specify whether or not to create the file
 * (actually, return a structure anyway) if it doesn't exist.
 */
static shvarFile *
svOpenFileInternal (const char *name, gboolean create, GError **error)
{
	shvarFile *s = NULL;
	gboolean closefd = FALSE;
	int errsv = 0;

	s = g_slice_new0 (shvarFile);

	s->fd = -1;
	if (create)
		s->fd = open (name, O_RDWR | O_CLOEXEC); /* NOT O_CREAT */

	if (!create || s->fd == -1) {
		/* try read-only */
		s->fd = open (name, O_RDONLY | O_CLOEXEC); /* NOT O_CREAT */
		if (s->fd == -1)
			errsv = errno;
		else
			closefd = TRUE;
	}
	s->fileName = g_strdup (name);

	if (s->fd != -1) {
		struct stat buf;
		char *arena, *p, *q;
		ssize_t nread, total = 0;

		if (fstat (s->fd, &buf) < 0) {
			errsv = errno;
			goto bail;
		}
		arena = g_malloc (buf.st_size + 1);
		arena[buf.st_size] = '\0';

		while (total < buf.st_size) {
			nread = read (s->fd, arena + total, buf.st_size - total);
			if (nread == -1 && errno == EINTR)
				continue;
			if (nread <= 0) {
				errsv = errno;
				g_free (arena);
				goto bail;
			}
			total += nread;
		}

		/* we'd use g_strsplit() here, but we want a list, not an array */
		for (p = arena; (q = strchr (p, '\n')) != NULL; p = q + 1)
			s->lineList = g_list_prepend (s->lineList, line_new (g_strndup (p, q - p)));
		if (p[0])
			s->lineList = g_list_prepend (s->lineList, line_new (g_strdup (p)));
		g_free (arena);
		s->lineList = g_list_reverse (s->lineList);

		/* closefd is set if we opened the file read-only, so go ahead and
		 * close it, because we can't write to it anyway
		 */
		if (closefd) {
			close (s->fd);
			s->fd = -1;
		}

		return s;
	}

	if (create)
		return s;

 bail:
	if (s->fd != -1)
		close (s->fd);
	g_free (s->fileName);
	g_slice_free (shvarFile, s);

	g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errsv),
	             "Could not read file '%s': %s",
	             name, errsv ? strerror (errsv) : "Unknown error");
	return NULL;
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

static const GList *
shlist_find (const GList *current, const char *key)
{
	gsize len;

	nm_assert (_shell_is_name (key));

	if (current) {
		len = strlen (key);
		do {
			shvarLine *line = current->data;
			const char *original = line->original;

			/* skip over leading spaces */
			while (g_ascii_isspace (original[0]))
				original++;

			if (!strncmp (key, original, len) && original[len] == '=')
				return current;
			current = current->next;
		} while (current);
	}
	return NULL;
}

/*****************************************************************************/

static const char *
_svGetValue (shvarFile *s, const char *key, char **to_free)
{
	const GList *current, *last;

	nm_assert (s);
	nm_assert (_shell_is_name (key));
	nm_assert (to_free);

	last = NULL;
	current = s->lineList;
	while ((current = shlist_find (current, key))) {
		last = current;
		current = current->next;
	}

	if (last) {
		const shvarLine *line = last->data;

		if (line->value)
			return svUnescape (line_value (line, key), to_free);
	}

	*to_free = NULL;
	return NULL;
}

const char *
svGetValue (shvarFile *s, const char *key, char **to_free)
{
	g_return_val_if_fail (s != NULL, NULL);
	g_return_val_if_fail (key != NULL, NULL);
	g_return_val_if_fail (to_free, NULL);

	return _svGetValue (s, key, to_free);
}

/* Get the value associated with the key, and leave the current pointer
 * pointing at the line containing the value.  The char* returned MUST
 * be freed by the caller.
 */
char *
svGetValueString (shvarFile *s, const char *key)
{
	char *to_free;
	const char *value;

	value = _svGetValue (s, key, &to_free);
	if (!value) {
		nm_assert (!to_free);
		return NULL;
	}
	if (!value[0]) {
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

/*****************************************************************************/

/* Same as svSetValueString() but it preserves empty @value -- contrary to
 * svSetValueString() for which "" effectively means to remove the value. */
void
svSetValue (shvarFile *s, const char *key, const char *value)
{
	GList *current, *last;

	g_return_if_fail (s != NULL);
	g_return_if_fail (key != NULL);

	nm_assert (_shell_is_name (key));

	last = NULL;
	current = s->lineList;
	while ((current = (GList *) shlist_find (current, key))) {
		if (last) {
			/* if we find multiple entries for the same key, we can
			 * delete all but the last. */
			line_free (last->data);
			s->lineList = g_list_delete_link (s->lineList, last);
			s->modified = TRUE;
		}
		last = current;
		current = current->next;
	}

	if (!value) {
		if (last) {
			shvarLine *line = last->data;

			if (line->value) {
				if (line->value != line->original)
					g_free (line->value);
				line->value = NULL;
				s->modified = TRUE;
			}
		}
	} else {
		gs_free char *newval_free = NULL;
		shvarLine *line;
		char *new_value;

		value = svEscape (value, &newval_free);

		if (!last) {
			new_value = g_strdup_printf ("%s=%s", key, value);
			s->lineList = g_list_append (s->lineList, line_new (new_value));
		} else {
			line = last->data;
			if (line->value) {
				if (nm_streq (line_value (line, key), value))
					return;
				if (line->value != line->original)
					g_free (line->value);
			}
			new_value = g_strdup_printf ("%s=%s", key, value);
			line->value = new_value;
		}
		s->modified = TRUE;
	}
}

/* Set the variable <key> equal to the value <value>.
 * If <key> does not exist, and the <current> pointer is set, append
 * the key=value pair after that line.  Otherwise, append the pair
 * to the bottom of the file.
 */
void
svSetValueString (shvarFile *s, const char *key, const char *value)
{
	svSetValue (s, key, value && value[0] ? value : NULL);
}

void
svSetValueInt64 (shvarFile *s, const char *key, gint64 value)
{
	char buf[NM_DECIMAL_STR_MAX (value)];

	svSetValue (s, key, nm_sprintf_buf (buf, "%"G_GINT64_FORMAT, value));
}

void
svSetValueBoolean (shvarFile *s, const char *key, gboolean value)
{
	svSetValue (s, key, value ? "yes" : "no");
}

void
svUnsetValue (shvarFile *s, const char *key)
{
	svSetValue (s, key, NULL);
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
	const GList *current;

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

		tmpfd = dup (s->fd);
		if (tmpfd == -1) {
			int errsv = errno;

			g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errsv),
			             "Internal error writing file '%s': %s",
			             s->fileName, strerror (errsv));
			return FALSE;
		}
		f = fdopen (tmpfd, "w");
		fseek (f, 0, SEEK_SET);
		for (current = s->lineList; current; current = current->next) {
			shvarLine *line = current->data;
			const char *str;
			const char *value;

			str = line->value;
			if (!str)
				continue;

			while (g_ascii_isspace (str[0]))
				str++;
			if (NM_IN_SET (str[0], '\0', '#'))
				goto write_regular;

			value = _shell_is_name_assignment (str);
			if (value) {
				gs_free char *s_tmp = NULL;

				/* we check that the assignment can be properly unescaped. */
				if (svUnescape (value, &s_tmp))
					goto write_regular;
				nm_clear_g_free (&s_tmp);
				s_tmp = g_strndup (str, value - str);
				fprintf (f, "%s\n", s_tmp);
			}
			fprintf (f, "#NM: %s\n", line->value);
			continue;
write_regular:
			fprintf (f, "%s\n", line->value);
		}
		fclose (f);
	}

	return TRUE;
}


/* Close the file descriptor (if open) and free the shvarFile. */
void
svCloseFile (shvarFile *s)
{
	g_return_if_fail (s != NULL);

	if (s->fd != -1)
		close (s->fd);

	g_free (s->fileName);
	g_list_free_full (s->lineList, (GDestroyNotify) line_free);
	g_slice_free (shvarFile, s);
}
