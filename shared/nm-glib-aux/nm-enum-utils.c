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
 * (C) Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-enum-utils.h"

/*****************************************************************************/

#define IS_FLAGS_SEPARATOR(ch)  (NM_IN_SET ((ch), ' ', '\t', ',', '\n', '\r'))

static void
_ASSERT_enum_values_info (GType type,
                          const NMUtilsEnumValueInfo *value_infos)
{
#if NM_MORE_ASSERTS > 5
	nm_auto_unref_gtypeclass GTypeClass *klass = NULL;
	gs_unref_hashtable GHashTable *ht = NULL;

	klass = g_type_class_ref (type);

	g_assert (G_IS_ENUM_CLASS (klass) || G_IS_FLAGS_CLASS (klass));

	if (!value_infos)
		return;

	ht = g_hash_table_new (g_str_hash, g_str_equal);

	for (; value_infos->nick; value_infos++) {

		g_assert (value_infos->nick[0]);

		/* duplicate nicks make no sense!! */
		g_assert (!g_hash_table_contains (ht, value_infos->nick));
		g_hash_table_add (ht, (gpointer) value_infos->nick);

		if (G_IS_ENUM_CLASS (klass)) {
			GEnumValue *enum_value;

			enum_value = g_enum_get_value_by_nick (G_ENUM_CLASS (klass), value_infos->nick);
			if (enum_value) {
				/* we do allow specifying the same name via @value_infos and @type.
				 * That might make sense, if @type comes from a library where older versions
				 * of the library don't yet support the value. In this case, the caller can
				 * provide the nick via @value_infos, to support the older library version.
				 * And then, when actually running against a newer library version where
				 * @type knows the nick, we have this situation.
				 *
				 * Another reason for specifying a nick both in @value_infos and @type,
				 * is to specify an alias which is not used with highest preference. For
				 * example, if you add an alias "disabled" for "none" (both numerically
				 * equal), then the first alias in @value_infos will be preferred over
				 * the name from @type. So, to still use "none" as preferred name, you may
				 * explicitly specify the "none" alias in @value_infos before "disabled".
				 *
				 * However, what never is allowed, is to use a name (nick) to re-number
				 * the value. That is, if both @value_infos and @type contain a particular
				 * nick, their numeric values must agree as well.
				 * Allowing this, would be very confusing, because the name would have a different
				 * value from the regular GLib GEnum API.
				 */
				g_assert (enum_value->value == value_infos->value);
			}
		} else {
			GFlagsValue *flags_value;

			flags_value = g_flags_get_value_by_nick (G_FLAGS_CLASS (klass), value_infos->nick);
			if (flags_value) {
				/* see ENUM case above. */
				g_assert (flags_value->value == (guint) value_infos->value);
			}
		}
	}
#endif
}

static gboolean
_is_hex_string (const char *str)
{
	return    str[0] == '0'
	       && str[1] == 'x'
	       && str[2]
	       && NM_STRCHAR_ALL (&str[2], ch, g_ascii_isxdigit (ch));
}

static gboolean
_is_dec_string (const char *str)
{
	return    str[0]
	       && NM_STRCHAR_ALL (&str[0], ch, g_ascii_isdigit (ch));
}

static gboolean
_enum_is_valid_enum_nick (const char *str)
{
	return    str[0]
	       && !NM_STRCHAR_ANY (str, ch, g_ascii_isspace (ch))
	       && !_is_dec_string (str)
	       && !_is_hex_string (str);
}

static gboolean
_enum_is_valid_flags_nick (const char *str)
{
	return    str[0]
	       && !NM_STRCHAR_ANY (str, ch, IS_FLAGS_SEPARATOR (ch))
	       && !_is_dec_string (str)
	       && !_is_hex_string (str);
}

char *
_nm_utils_enum_to_str_full (GType type,
                            int value,
                            const char *flags_separator,
                            const NMUtilsEnumValueInfo *value_infos)
{
	nm_auto_unref_gtypeclass GTypeClass *klass = NULL;

	_ASSERT_enum_values_info (type, value_infos);

	if (   flags_separator
	    && (   !flags_separator[0]
	        || NM_STRCHAR_ANY (flags_separator, ch, !IS_FLAGS_SEPARATOR (ch))))
		g_return_val_if_reached (NULL);

	klass = g_type_class_ref (type);

	if (G_IS_ENUM_CLASS (klass)) {
		GEnumValue *enum_value;

		for ( ; value_infos && value_infos->nick; value_infos++) {
			if (value_infos->value == value)
				return g_strdup (value_infos->nick);
		}

		enum_value = g_enum_get_value (G_ENUM_CLASS (klass), value);
		if (   !enum_value
		    || !_enum_is_valid_enum_nick (enum_value->value_nick))
			return g_strdup_printf ("%d", value);
		else
			return g_strdup (enum_value->value_nick);
	} else if (G_IS_FLAGS_CLASS (klass)) {
		GFlagsValue *flags_value;
		GString *str = g_string_new ("");
		unsigned uvalue = (unsigned) value;

		flags_separator = flags_separator ?: " ";

		for ( ; value_infos && value_infos->nick; value_infos++) {

			nm_assert (_enum_is_valid_flags_nick (value_infos->nick));

			if (uvalue == 0) {
				if (value_infos->value != 0)
					continue;
			} else {
				if (!NM_FLAGS_ALL (uvalue, (unsigned) value_infos->value))
					continue;
			}

			if (str->len)
				g_string_append (str, flags_separator);
			g_string_append (str, value_infos->nick);
			uvalue &= ~((unsigned) value_infos->value);
			if (uvalue == 0) {
				/* we printed all flags. Done. */
				goto flags_done;
			}
		}

		do {
			flags_value = g_flags_get_first_value (G_FLAGS_CLASS (klass), uvalue);
			if (str->len)
				g_string_append (str, flags_separator);
			if (   !flags_value
			    || !_enum_is_valid_flags_nick (flags_value->value_nick)) {
				if (uvalue)
					g_string_append_printf (str, "0x%x", uvalue);
				break;
			}
			g_string_append (str, flags_value->value_nick);
			uvalue &= ~flags_value->value;
		} while (uvalue);

flags_done:
		return g_string_free (str, FALSE);
	}

	g_return_val_if_reached (NULL);
}

static const NMUtilsEnumValueInfo *
_find_value_info (const NMUtilsEnumValueInfo *value_infos, const char *needle)
{
	if (value_infos) {
		for (; value_infos->nick; value_infos++) {
			if (nm_streq (needle, value_infos->nick))
				return value_infos;
		}
	}
	return NULL;
}

gboolean
_nm_utils_enum_from_str_full (GType type,
                              const char *str,
                              int *out_value,
                              char **err_token,
                              const NMUtilsEnumValueInfo *value_infos)
{
	GTypeClass *klass;
	gboolean ret = FALSE;
	int value = 0;
	gs_free char *str_clone = NULL;
	char *s;
	gint64 v64;
	const NMUtilsEnumValueInfo *nick;

	g_return_val_if_fail (str, FALSE);

	_ASSERT_enum_values_info (type, value_infos);

	str_clone = strdup (str);
	s = nm_str_skip_leading_spaces (str_clone);
	g_strchomp (s);

	klass = g_type_class_ref (type);

	if (G_IS_ENUM_CLASS (klass)) {
		GEnumValue *enum_value;

		if (s[0]) {
			if (_is_hex_string (s)) {
				v64 = _nm_utils_ascii_str_to_int64 (s, 16, 0, G_MAXUINT, -1);
				if (v64 != -1) {
					value = (int) v64;
					ret = TRUE;
				}
			} else if (_is_dec_string (s)) {
				v64 = _nm_utils_ascii_str_to_int64 (s, 10, 0, G_MAXUINT, -1);
				if (v64 != -1) {
					value = (int) v64;
					ret = TRUE;
				}
			} else if ((nick = _find_value_info (value_infos, s))) {
				value = nick->value;
				ret = TRUE;
			} else if ((enum_value = g_enum_get_value_by_nick (G_ENUM_CLASS (klass), s))) {
				value = enum_value->value;
				ret = TRUE;
			}
		}
	} else if (G_IS_FLAGS_CLASS (klass)) {
		GFlagsValue *flags_value;
		unsigned uvalue = 0;

		ret = TRUE;
		while (s[0]) {
			char *s_end;

			for (s_end = s; s_end[0]; s_end++) {
				if (IS_FLAGS_SEPARATOR (s_end[0])) {
					s_end[0] = '\0';
					s_end++;
					break;
				}
			}

			if (s[0]) {
				if (_is_hex_string (s)) {
					v64 = _nm_utils_ascii_str_to_int64 (&s[2], 16, 0, G_MAXUINT, -1);
					if (v64 == -1) {
						ret = FALSE;
						break;
					}
					uvalue |= (unsigned) v64;
				} else if (_is_dec_string (s)) {
					v64 = _nm_utils_ascii_str_to_int64 (s, 10, 0, G_MAXUINT, -1);
					if (v64 == -1) {
						ret = FALSE;
						break;
					}
					uvalue |= (unsigned) v64;
				} else if ((nick = _find_value_info (value_infos, s)))
					uvalue |= (unsigned) nick->value;
				else if ((flags_value = g_flags_get_value_by_nick (G_FLAGS_CLASS (klass), s)))
					uvalue |= flags_value->value;
				else {
					ret = FALSE;
					break;
				}
			}

			s = s_end;
		}

		value = (int) uvalue;
	} else
		g_return_val_if_reached (FALSE);

	NM_SET_OUT (err_token, !ret && s[0] ? g_strdup (s) : NULL);
	NM_SET_OUT (out_value, ret ? value : 0);
	g_type_class_unref (klass);
	return ret;
}

const char **
_nm_utils_enum_get_values (GType type, int from, int to)
{
	GTypeClass *klass;
	GPtrArray *array;
	int i;
	char sbuf[64];

	klass = g_type_class_ref (type);
	array = g_ptr_array_new ();

	if (G_IS_ENUM_CLASS (klass)) {
		GEnumClass *enum_class = G_ENUM_CLASS (klass);
		GEnumValue *enum_value;

		for (i = 0; i < enum_class->n_values; i++) {
			enum_value = &enum_class->values[i];
			if (enum_value->value >= from && enum_value->value <= to) {
				if (_enum_is_valid_enum_nick (enum_value->value_nick))
					g_ptr_array_add (array, (gpointer) enum_value->value_nick);
				else
					g_ptr_array_add (array, (gpointer) g_intern_string (nm_sprintf_buf (sbuf, "%d", enum_value->value)));
			}
		}
	} else if (G_IS_FLAGS_CLASS (klass)) {
		GFlagsClass *flags_class = G_FLAGS_CLASS (klass);
		GFlagsValue *flags_value;

		for (i = 0; i < flags_class->n_values; i++) {
			flags_value = &flags_class->values[i];
			if (flags_value->value >= (guint) from && flags_value->value <= (guint) to) {
				if (_enum_is_valid_flags_nick (flags_value->value_nick))
					g_ptr_array_add (array, (gpointer) flags_value->value_nick);
				else
					g_ptr_array_add (array, (gpointer) g_intern_string (nm_sprintf_buf (sbuf, "0x%x", (unsigned) flags_value->value)));
			}
		}
	} else {
		g_type_class_unref (klass);
		g_ptr_array_free (array, TRUE);
		g_return_val_if_reached (NULL);
	}

	g_type_class_unref (klass);
	g_ptr_array_add (array, NULL);

	return (const char **) g_ptr_array_free (array, FALSE);
}
