/* NetworkManager -- Network link manager
 *
 * Ray Strode <rstrode@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <glib.h>
#include "nm-utils.h"

gchar *nm_dbus_escape_object_path (const gchar *utf8_string)
{
	const gchar *p;
	gchar *object_path;
	GString *string;

	g_return_val_if_fail (utf8_string != NULL, NULL);	
	g_return_val_if_fail (g_utf8_validate (utf8_string, -1, NULL), NULL);

	string = g_string_sized_new ((strlen (utf8_string) + 1) * 6);

	for (p = utf8_string; *p != '\0'; p = g_utf8_next_char (p))
	{
		gunichar character;

		character = g_utf8_get_char (p);

		if (((character >= ((gunichar) 'a')) && 
		     (character <= ((gunichar) 'z'))) ||
		    ((character >= ((gunichar) 'A')) && 
		     (character <= ((gunichar) 'Z'))) ||
		    ((character >= ((gunichar) '0')) && 
		     (character <= ((gunichar) '9'))) ||
		     (character == ((gunichar) '/')))
		{
			g_string_append_c (string, (gchar) character);
			continue;
		}

		g_string_append_printf (string, "_%x_", character);
	}

	object_path = string->str;

	g_string_free (string, FALSE);

	return object_path;
}

gchar *nm_dbus_unescape_object_path (const gchar *object_path)
{
	const gchar *p;
	gchar *utf8_string;
	GString *string;

	g_return_val_if_fail (object_path != NULL, NULL);	

	string = g_string_sized_new (strlen (object_path) + 1);

	for (p = object_path; *p != '\0'; p++)
	{
		const gchar *q;
		gchar *hex_digits, *end, utf8_character[6] = { '\0' };
		gint utf8_character_size;
		gunichar character;
		gulong hex_value;

		if (*p != '_')
		{
		    g_string_append_c (string, *p);
		    continue;
		}

		q = strchr (p + 1, '_'); 

		if ((q == NULL) || (q == p + 1))
		{
		    g_string_free (string, TRUE);
		    return NULL;
		}

		hex_digits = g_strndup (p + 1, (q - 1) - p);

		hex_value = strtoul (hex_digits, &end, 16);

		character = (gunichar) hex_value;

		if (((hex_value == G_MAXLONG) && (errno == ERANGE)) ||
		    (hex_value > G_MAXUINT32) ||
		    (*end != '\0') ||
		    (!g_unichar_validate (character)))
		{
		    g_free (hex_digits);
		    g_string_free (string, TRUE);
		    return NULL;
		}

		utf8_character_size = 
			g_unichar_to_utf8 (character, utf8_character);

		g_assert (utf8_character_size > 0);

		g_string_append_len (string, utf8_character,
				     utf8_character_size);

		p = q;
	}

	utf8_string = string->str;

	g_string_free (string, FALSE);

	return utf8_string;
}
