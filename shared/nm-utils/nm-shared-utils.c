/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-shared-utils.h"

#include <errno.h>
#include <arpa/inet.h>

/*****************************************************************************/

const void *const _NM_PTRARRAY_EMPTY[1] = { NULL };

/*****************************************************************************/

const NMIPAddr nm_ip_addr_zero = { 0 };

/*****************************************************************************/

void
nm_utils_strbuf_append_c (char **buf, gsize *len, char c)
{
	switch (*len) {
	case 0:
		return;
	case 1:
		(*buf)[0] = '\0';
		*len = 0;
		(*buf)++;
		return;
	default:
		(*buf)[0] = c;
		(*buf)[1] = '\0';
		(*len)--;
		(*buf)++;
		return;
	}
}

void
nm_utils_strbuf_append_str (char **buf, gsize *len, const char *str)
{
	gsize src_len;

	switch (*len) {
	case 0:
		return;
	case 1:
		if (!str || !*str) {
			(*buf)[0] = '\0';
			return;
		}
		(*buf)[0] = '\0';
		*len = 0;
		(*buf)++;
		return;
	default:
		if (!str || !*str) {
			(*buf)[0] = '\0';
			return;
		}
		src_len = g_strlcpy (*buf, str, *len);
		if (src_len >= *len) {
			*buf = &(*buf)[*len];
			*len = 0;
		} else {
			*buf = &(*buf)[src_len];
			*len -= src_len;
		}
		return;
	}
}

void
nm_utils_strbuf_append (char **buf, gsize *len, const char *format, ...)
{
	char *p = *buf;
	va_list args;
	gint retval;

	if (*len == 0)
		return;

	va_start (args, format);
	retval = g_vsnprintf (p, *len, format, args);
	va_end (args);

	if (retval >= *len) {
		*buf = &p[*len];
		*len = 0;
	} else {
		*buf = &p[retval];
		*len -= retval;
	}
}

/*****************************************************************************/

/**
 * _nm_utils_ip4_prefix_to_netmask:
 * @prefix: a CIDR prefix
 *
 * Returns: the netmask represented by the prefix, in network byte order
 **/
guint32
_nm_utils_ip4_prefix_to_netmask (guint32 prefix)
{
	return prefix < 32 ? ~htonl(0xFFFFFFFF >> prefix) : 0xFFFFFFFF;
}

/**
 * _nm_utils_ip4_get_default_prefix:
 * @ip: an IPv4 address (in network byte order)
 *
 * When the Internet was originally set up, various ranges of IP addresses were
 * segmented into three network classes: A, B, and C.  This function will return
 * a prefix that is associated with the IP address specified defining where it
 * falls in the predefined classes.
 *
 * Returns: the default class prefix for the given IP
 **/
/* The function is originally from ipcalc.c of Red Hat's initscripts. */
guint32
_nm_utils_ip4_get_default_prefix (guint32 ip)
{
	if (((ntohl (ip) & 0xFF000000) >> 24) <= 127)
		return 8;  /* Class A - 255.0.0.0 */
	else if (((ntohl (ip) & 0xFF000000) >> 24) <= 191)
		return 16;  /* Class B - 255.255.0.0 */

	return 24;  /* Class C - 255.255.255.0 */
}

gboolean
nm_utils_ip_is_site_local (int addr_family,
                           const void *address)
{
	in_addr_t addr4;

	switch (addr_family) {
	case AF_INET:
		/* RFC1918 private addresses
		 * 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 */
		addr4 = ntohl (*((const in_addr_t *) address));
		return    (addr4 & 0xff000000) == 0x0a000000
		       || (addr4 & 0xfff00000) == 0xac100000
		       || (addr4 & 0xffff0000) == 0xc0a80000;
	case AF_INET6:
		return IN6_IS_ADDR_SITELOCAL (address);
	default:
		g_return_val_if_reached (FALSE);
	}
}

/*****************************************************************************/

gboolean
nm_utils_parse_inaddr_bin  (const char *text,
                            int family,
                            gpointer out_addr)
{
	NMIPAddr addrbin;

	g_return_val_if_fail (text, FALSE);

	if (family == AF_UNSPEC)
		family = strchr (text, ':') ? AF_INET6 : AF_INET;
	else
		g_return_val_if_fail (NM_IN_SET (family, AF_INET, AF_INET6), FALSE);

	if (inet_pton (family, text, out_addr ?: &addrbin) != 1)
		return FALSE;
	return TRUE;
}

gboolean
nm_utils_parse_inaddr (const char *text,
                       int family,
                       char **out_addr)
{
	NMIPAddr addrbin;
	char addrstr_buf[MAX (INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];

	if (!nm_utils_parse_inaddr_bin (text, family, &addrbin))
		return FALSE;
	NM_SET_OUT (out_addr, g_strdup (inet_ntop (family, &addrbin, addrstr_buf, sizeof (addrstr_buf))));
	return TRUE;
}

gboolean
nm_utils_parse_inaddr_prefix_bin (const char *text,
                                  int family,
                                  gpointer out_addr,
                                  int *out_prefix)
{
	gs_free char *addrstr_free = NULL;
	int prefix = -1;
	const char *slash;
	const char *addrstr;
	NMIPAddr addrbin;
	int addr_len;

	g_return_val_if_fail (text, FALSE);

	if (family == AF_UNSPEC)
		family = strchr (text, ':') ? AF_INET6 : AF_INET;

	if (family == AF_INET)
		addr_len = sizeof (in_addr_t);
	else if (family == AF_INET6)
		addr_len = sizeof (struct in6_addr);
	else
		g_return_val_if_reached (FALSE);

	slash = strchr (text, '/');
	if (slash)
		addrstr = addrstr_free = g_strndup (text, slash - text);
	else
		addrstr = text;

	if (inet_pton (family, addrstr, &addrbin) != 1)
		return FALSE;

	if (slash) {
		prefix = _nm_utils_ascii_str_to_int64 (slash + 1, 10,
		                                       0,
		                                       family == AF_INET ? 32 : 128,
		                                       -1);
		if (prefix == -1)
			return FALSE;
	}

	if (out_addr)
		memcpy (out_addr, &addrbin, addr_len);
	NM_SET_OUT (out_prefix, prefix);
	return TRUE;
}

gboolean
nm_utils_parse_inaddr_prefix (const char *text,
                              int family,
                              char **out_addr,
                              int *out_prefix)
{
	NMIPAddr addrbin;
	char addrstr_buf[MAX (INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];

	if (!nm_utils_parse_inaddr_prefix_bin (text, family, &addrbin, out_prefix))
		return FALSE;
	NM_SET_OUT (out_addr, g_strdup (inet_ntop (family, &addrbin, addrstr_buf, sizeof (addrstr_buf))));
	return TRUE;
}

/*****************************************************************************/

/* _nm_utils_ascii_str_to_int64:
 *
 * A wrapper for g_ascii_strtoll, that checks whether the whole string
 * can be successfully converted to a number and is within a given
 * range. On any error, @fallback will be returned and %errno will be set
 * to a non-zero value. On success, %errno will be set to zero, check %errno
 * for errors. Any trailing or leading (ascii) white space is ignored and the
 * functions is locale independent.
 *
 * The function is guaranteed to return a value between @min and @max
 * (inclusive) or @fallback. Also, the parsing is rather strict, it does
 * not allow for any unrecognized characters, except leading and trailing
 * white space.
 **/
gint64
_nm_utils_ascii_str_to_int64 (const char *str, guint base, gint64 min, gint64 max, gint64 fallback)
{
	gint64 v;
	const char *s = NULL;

	if (str) {
		while (g_ascii_isspace (str[0]))
			str++;
	}
	if (!str || !str[0]) {
		errno = EINVAL;
		return fallback;
	}

	errno = 0;
	v = g_ascii_strtoll (str, (char **) &s, base);

	if (errno != 0)
		return fallback;
	if (s[0] != '\0') {
		while (g_ascii_isspace (s[0]))
			s++;
		if (s[0] != '\0') {
			errno = EINVAL;
			return fallback;
		}
	}
	if (v > max || v < min) {
		errno = ERANGE;
		return fallback;
	}

	return v;
}

/*****************************************************************************/

/**
 * nm_utils_strsplit_set:
 * @str: the string to split.
 * @delimiters: the set of delimiters. If %NULL, defaults to " \t\n",
 *   like bash's $IFS.
 *
 * This is a replacement for g_strsplit_set() which avoids copying
 * each word once (the entire strv array), but instead copies it once
 * and all words point into that internal copy.
 *
 * Another difference from g_strsplit_set() is that this never returns
 * empty words. Multiple delimiters are combined and treated as one.
 *
 * Returns: %NULL if @str is %NULL or contains only delimiters.
 *   Otherwise, a %NULL terminated strv array containing non-empty
 *   words, split at the delimiter characters (delimiter characters
 *   are removed).
 *   The strings to which the result strv array points to are allocated
 *   after the returned result itself. Don't free the strings themself,
 *   but free everything with g_free().
 */
const char **
nm_utils_strsplit_set (const char *str, const char *delimiters)
{
	const char **ptr, **ptr0;
	gsize alloc_size, plen, i;
	gsize str_len;
	char *s0;
	char *s;
	guint8 delimiters_table[256];

	if (!str)
		return NULL;

	/* initialize lookup table for delimiter */
	if (!delimiters)
		delimiters = " \t\n";
	memset (delimiters_table, 0, sizeof (delimiters_table));
	for (i = 0; delimiters[i]; i++)
		delimiters_table[(guint8) delimiters[i]] = 1;

#define _is_delimiter(ch, delimiters_table) \
	((delimiters_table)[(guint8) (ch)] != 0)

	/* skip initial delimiters, and return of the remaining string is
	 * empty. */
	while (_is_delimiter (str[0], delimiters_table))
		str++;
	if (!str[0])
		return NULL;

	str_len = strlen (str) + 1;
	alloc_size = 8;

	/* we allocate the buffer larger, so to copy @str at the
	 * end of it as @s0. */
	ptr0 = g_malloc ((sizeof (const char *) * (alloc_size + 1)) + str_len);
	s0 = (char *) &ptr0[alloc_size + 1];
	memcpy (s0, str, str_len);

	plen = 0;
	s = s0;
	ptr = ptr0;

	while (TRUE) {
		if (plen >= alloc_size) {
			const char **ptr_old = ptr;

			/* reallocate the buffer. Note that for now the string
			 * continues to be in ptr0/s0. We fix that at the end. */
			alloc_size += 2;
			ptr = g_malloc ((sizeof (const char *) * (alloc_size + 1)) + str_len);
			memcpy (ptr, ptr_old, sizeof (const char *) * plen);
			if (ptr_old != ptr0)
				g_free (ptr_old);
		}

		ptr[plen++] = s;

		nm_assert (s[0] && !_is_delimiter (s[0], delimiters_table));

		while (TRUE) {
			s++;
			if (_is_delimiter (s[0], delimiters_table))
				break;
			if (s[0] == '\0')
				goto done;
		}

		s[0] = '\0';
		s++;
		while (_is_delimiter (s[0], delimiters_table))
			s++;
		if (s[0] == '\0')
			break;
	}
done:
	ptr[plen] = NULL;

	if (ptr != ptr0) {
		/* we reallocated the buffer. We must copy over the
		 * string @s0 and adjust the pointers. */
		s = (char *) &ptr[alloc_size + 1];
		memcpy (s, s0, str_len);
		for (i = 0; i < plen; i++)
			ptr[i] = &s[ptr[i] - s0];
		g_free (ptr0);
	}

	return ptr;
}

/**
 * nm_utils_strv_find_first:
 * @list: the strv list to search
 * @len: the length of the list, or a negative value if @list is %NULL terminated.
 * @needle: the value to search for. The search is done using strcmp().
 *
 * Searches @list for @needle and returns the index of the first match (based
 * on strcmp()).
 *
 * For convenience, @list has type 'char**' instead of 'const char **'.
 *
 * Returns: index of first occurrence or -1 if @needle is not found in @list.
 */
gssize
nm_utils_strv_find_first (char **list, gssize len, const char *needle)
{
	gssize i;

	if (len > 0) {
		g_return_val_if_fail (list, -1);

		if (!needle) {
			/* if we search a list with known length, %NULL is a valid @needle. */
			for (i = 0; i < len; i++) {
				if (!list[i])
					return i;
			}
		} else {
			for (i = 0; i < len; i++) {
				if (list[i] && !strcmp (needle, list[i]))
					return i;
			}
		}
	} else if (len < 0) {
		g_return_val_if_fail (needle, -1);

		if (list) {
			for (i = 0; list[i]; i++) {
				if (strcmp (needle, list[i]) == 0)
					return i;
			}
		}
	}
	return -1;
}

char **
_nm_utils_strv_cleanup (char **strv,
                        gboolean strip_whitespace,
                        gboolean skip_empty,
                        gboolean skip_repeated)
{
	guint i, j;

	if (!strv || !*strv)
		return strv;

	if (strip_whitespace) {
		for (i = 0; strv[i]; i++)
			g_strstrip (strv[i]);
	}
	if (!skip_empty && !skip_repeated)
		return strv;
	j = 0;
	for (i = 0; strv[i]; i++) {
		if (   (skip_empty && !*strv[i])
		    || (skip_repeated && nm_utils_strv_find_first (strv, j, strv[i]) >= 0))
			g_free (strv[i]);
		else
			strv[j++] = strv[i];
	}
	strv[j] = NULL;
	return strv;
}

/*****************************************************************************/

gint
_nm_utils_ascii_str_to_bool (const char *str,
                             gint default_value)
{
	gsize len;
	char *s = NULL;

	if (!str)
		return default_value;

	while (str[0] && g_ascii_isspace (str[0]))
		str++;

	if (!str[0])
		return default_value;

	len = strlen (str);
	if (g_ascii_isspace (str[len - 1])) {
		s = g_strdup (str);
		g_strchomp (s);
		str = s;
	}

	if (!g_ascii_strcasecmp (str, "true") || !g_ascii_strcasecmp (str, "yes") || !g_ascii_strcasecmp (str, "on") || !g_ascii_strcasecmp (str, "1"))
		default_value = TRUE;
	else if (!g_ascii_strcasecmp (str, "false") || !g_ascii_strcasecmp (str, "no") || !g_ascii_strcasecmp (str, "off") || !g_ascii_strcasecmp (str, "0"))
		default_value = FALSE;
	if (s)
		g_free (s);
	return default_value;
}

/*****************************************************************************/

NM_CACHED_QUARK_FCN ("nm-utils-error-quark", nm_utils_error_quark)

void
nm_utils_error_set_cancelled (GError **error,
                              gboolean is_disposing,
                              const char *instance_name)
{
	if (is_disposing) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_CANCELLED_DISPOSING,
		             "Disposing %s instance",
		             instance_name && *instance_name ? instance_name : "source");
	} else {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
		                     "Request cancelled");
	}
}

gboolean
nm_utils_error_is_cancelled (GError *error,
                             gboolean consider_is_disposing)
{
	if (error) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			return TRUE;
		if (   consider_is_disposing
		    && g_error_matches (error, NM_UTILS_ERROR, NM_UTILS_ERROR_CANCELLED_DISPOSING))
			return TRUE;
	}
	return FALSE;
}

/*****************************************************************************/

/**
 * nm_g_object_set_property:
 * @object: the target object
 * @property_name: the property name
 * @value: the #GValue to set
 * @error: (allow-none): optional error argument
 *
 * A reimplementation of g_object_set_property(), but instead
 * returning an error instead of logging a warning. All g_object_set*()
 * versions in glib require you to not pass invalid types or they will
 * log a g_warning() -- without reporting an error. We don't want that,
 * so we need to hack error checking around it.
 *
 * Returns: whether the value was successfully set.
 */
gboolean
nm_g_object_set_property (GObject *object,
                          const gchar  *property_name,
                          const GValue *value,
                          GError **error)
{
	GParamSpec *pspec;
	nm_auto_unset_gvalue GValue tmp_value = G_VALUE_INIT;
	GObjectClass *klass;

	g_return_val_if_fail (G_IS_OBJECT (object), FALSE);
	g_return_val_if_fail (property_name != NULL, FALSE);
	g_return_val_if_fail (G_IS_VALUE (value), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	/* g_object_class_find_property() does g_param_spec_get_redirect_target(),
	 * where we differ from a plain g_object_set_property(). */
	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (object), property_name);

	if (!pspec) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("object class '%s' has no property named '%s'"),
		             G_OBJECT_TYPE_NAME (object),
		             property_name);
		return FALSE;
	}
	if (!(pspec->flags & G_PARAM_WRITABLE)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("property '%s' of object class '%s' is not writable"),
		             pspec->name,
		             G_OBJECT_TYPE_NAME (object));
		return FALSE;
	}
	if ((pspec->flags & G_PARAM_CONSTRUCT_ONLY)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("construct property \"%s\" for object '%s' can't be set after construction"),
		             pspec->name, G_OBJECT_TYPE_NAME (object));
		return FALSE;
	}

	klass = g_type_class_peek (pspec->owner_type);
	if (klass == NULL) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("'%s::%s' is not a valid property name; '%s' is not a GObject subtype"),
		            g_type_name (pspec->owner_type), pspec->name, g_type_name (pspec->owner_type));
		return FALSE;
	}

	/* provide a copy to work from, convert (if necessary) and validate */
	g_value_init (&tmp_value, pspec->value_type);
	if (!g_value_transform (value, &tmp_value)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("unable to set property '%s' of type '%s' from value of type '%s'"),
		             pspec->name,
		             g_type_name (pspec->value_type),
		             G_VALUE_TYPE_NAME (value));
		return FALSE;
	}
	if (   g_param_value_validate (pspec, &tmp_value)
	    && !(pspec->flags & G_PARAM_LAX_VALIDATION)) {
		gs_free char *contents = g_strdup_value_contents (value);

		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("value \"%s\" of type '%s' is invalid or out of range for property '%s' of type '%s'"),
		             contents,
		             G_VALUE_TYPE_NAME (value),
		             pspec->name,
		             g_type_name (pspec->value_type));
		return FALSE;
	}

	g_object_set_property (object, property_name, &tmp_value);
	return TRUE;
}

GParamSpec *
nm_g_object_class_find_property_from_gtype (GType gtype,
                                            const char *property_name)
{
	nm_auto_unref_gtypeclass GObjectClass *gclass = NULL;

	gclass = g_type_class_ref (gtype);
	return g_object_class_find_property (gclass, property_name);
}

/*****************************************************************************/

static void
_str_append_escape (GString *s, char ch)
{
	g_string_append_c (s, '\\');
	g_string_append_c (s, '0' + ((((guchar) ch) >> 6) & 07));
	g_string_append_c (s, '0' + ((((guchar) ch) >> 3) & 07));
	g_string_append_c (s, '0' + ( ((guchar) ch)       & 07));
}

/**
 * nm_utils_str_utf8safe_escape:
 * @str: NUL terminated input string, possibly in utf-8 encoding
 * @flags: #NMUtilsStrUtf8SafeFlags flags
 * @to_free: (out): return the pointer location of the string
 *   if a copying was necessary.
 *
 * Returns the possible non-UTF-8 NUL terminated string @str
 * and uses backslash escaping (C escaping, like g_strescape())
 * to sanitize non UTF-8 characters. The result is valid
 * UTF-8.
 *
 * The operation can be reverted with g_strcompress() or
 * nm_utils_str_utf8safe_unescape().
 *
 * Depending on @flags, valid UTF-8 characters are not escaped at all
 * (except the escape character '\\'). This is the difference to g_strescape(),
 * which escapes all non-ASCII characters. This allows to pass on
 * valid UTF-8 characters as-is and can be directly shown to the user
 * as UTF-8 -- with exception of the backslash escape character,
 * invalid UTF-8 sequences, and other (depending on @flags).
 *
 * Returns: the escaped input string, as valid UTF-8. If no escaping
 *   is necessary, it returns the input @str. Otherwise, an allocated
 *   string @to_free is returned which must be freed by the caller
 *   with g_free. The escaping can be reverted by g_strcompress().
 **/
const char *
nm_utils_str_utf8safe_escape (const char *str, NMUtilsStrUtf8SafeFlags flags, char **to_free)
{
	const char *p = NULL;
	GString *s;

	g_return_val_if_fail (to_free, NULL);

	*to_free = NULL;
	if (!str || !str[0])
		return str;

	if (   g_utf8_validate (str, -1, &p)
	    && !NM_STRCHAR_ANY (str, ch,
	                        (   ch == '\\' \
	                         || (   NM_FLAGS_HAS (flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL) \
	                             && ch < ' ') \
	                         || (   NM_FLAGS_HAS (flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII) \
	                             && ((guchar) ch) >= 127))))
		return str;

	s = g_string_sized_new ((p - str) + strlen (p) + 5);

	do {
		for (; str < p; str++) {
			char ch = str[0];

			if (ch == '\\')
				g_string_append (s, "\\\\");
			else if (   (   NM_FLAGS_HAS (flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL) \
			             && ch < ' ') \
			         || (   NM_FLAGS_HAS (flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII) \
			             && ((guchar) ch) >= 127))
				_str_append_escape (s, ch);
			else
				g_string_append_c (s, ch);
		}

		if (p[0] == '\0')
			break;
		_str_append_escape (s, p[0]);

		str = &p[1];
		g_utf8_validate (str, -1, &p);
	} while (TRUE);

	*to_free = g_string_free (s, FALSE);
	return *to_free;
}

const char *
nm_utils_str_utf8safe_unescape (const char *str, char **to_free)
{
	g_return_val_if_fail (to_free, NULL);

	if (!str || !strchr (str, '\\')) {
		*to_free = NULL;
		return str;
	}
	return (*to_free = g_strcompress (str));
}

/**
 * nm_utils_str_utf8safe_escape_cp:
 * @str: NUL terminated input string, possibly in utf-8 encoding
 * @flags: #NMUtilsStrUtf8SafeFlags flags
 *
 * Like nm_utils_str_utf8safe_escape(), except the returned value
 * is always a copy of the input and must be freed by the caller.
 *
 * Returns: the escaped input string in UTF-8 encoding. The returned
 *   value should be freed with g_free().
 *   The escaping can be reverted by g_strcompress().
 **/
char *
nm_utils_str_utf8safe_escape_cp (const char *str, NMUtilsStrUtf8SafeFlags flags)
{
	char *s;

	nm_utils_str_utf8safe_escape (str, flags, &s);
	return s ?: g_strdup (str);
}

char *
nm_utils_str_utf8safe_unescape_cp (const char *str)
{
	return str ? g_strcompress (str) : NULL;
}

char *
nm_utils_str_utf8safe_escape_take (char *str, NMUtilsStrUtf8SafeFlags flags)
{
	char *str_to_free;

	nm_utils_str_utf8safe_escape (str, flags, &str_to_free);
	if (str_to_free) {
		g_free (str);
		return str_to_free;
	}
	return str;
}
