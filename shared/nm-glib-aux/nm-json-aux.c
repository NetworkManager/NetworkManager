/*
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
 * Copyright 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-json-aux.h"

/*****************************************************************************/

static void
_gstr_append_string_len (GString *gstr,
                         const char *str,
                         gsize len)
{
	g_string_append_c (gstr, '\"');

	while (len > 0) {
		gsize n;
		const char *end;
		gboolean valid;

		nm_assert (len > 0);

		valid = g_utf8_validate (str, len, &end);

		nm_assert (   end
		           && end >= str
		           && end <= &str[len]);

		if (end > str) {
			const char *s;

			for (s = str; s < end; s++) {
				nm_assert (s[0] != '\0');

				if (s[0] < 0x20) {
					const char *text;

					switch (s[0]) {
					case '\\': text = "\\\\"; break;
					case '\"': text = "\\\""; break;
					case '\b': text = "\\b";  break;
					case '\f': text = "\\f";  break;
					case '\n': text = "\\n";  break;
					case '\r': text = "\\r";  break;
					case '\t': text = "\\t";  break;
					default:
						g_string_append_printf (gstr, "\\u%04X", (guint) s[0]);
						continue;
					}
					g_string_append (gstr, text);
					continue;
				}

				if (NM_IN_SET (s[0], '\\', '\"'))
					g_string_append_c (gstr, '\\');
				g_string_append_c (gstr, s[0]);
			}
		} else
			nm_assert (!valid);

		if (valid) {
			nm_assert (end == &str[len]);
			break;
		}

		nm_assert (end < &str[len]);

		if (end[0] == '\0') {
			/* there is a NUL byte in the string. Technically this is valid UTF-8, so we
			 * encode it there. However, this will likely result in a truncated string when
			 * parsing. */
			g_string_append (gstr, "\\u0000");
		} else {
			/* the character is not valid UTF-8. There is nothing we can do about it, because
			 * JSON can only contain UTF-8 and even the escape sequences can only escape Unicode
			 * codepoints (but not binary).
			 *
			 * The argument is not a a string (in any known encoding), hence we cannot represent
			 * it as a JSON string (which are unicode strings).
			 *
			 * Print an underscore instead of the invalid char :) */
			g_string_append_c (gstr, '_');
		}

		n = str - end;
		nm_assert (n < len);
		n++;
		str += n;
		len -= n;
	}

	g_string_append_c (gstr, '\"');
}

void
nm_json_aux_gstr_append_string_len (GString *gstr,
                                    const char *str,
                                    gsize n)
{
	g_return_if_fail (gstr);

	_gstr_append_string_len (gstr, str, n);
}

void
nm_json_aux_gstr_append_string (GString *gstr,
                                const char *str)
{
	g_return_if_fail (gstr);

	if (!str)
		g_string_append (gstr, "null");
	else
		_gstr_append_string_len (gstr, str, strlen (str));
}

void
nm_json_aux_gstr_append_obj_name (GString *gstr,
                                  const char *key,
                                  char start_container)
{
	g_return_if_fail (gstr);
	g_return_if_fail (key);

	nm_json_aux_gstr_append_string (gstr, key);

	if (start_container != '\0') {
		nm_assert (NM_IN_SET (start_container, '[', '{'));
		g_string_append_printf (gstr, ": %c ", start_container);
	} else
		g_string_append (gstr, ": ");
}
