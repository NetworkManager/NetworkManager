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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <glib.h>
#include <dbus/dbus.h>
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


/**
 * Start a dict in a dbus message.  Should be paired with a call to
 * {@link nmu_dbus_dict_close_write}.
 *
 * @param iter A valid dbus message iterator
 * @param iter_dict (out) A dict iterator to pass to further dict functions
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_open_write (DBusMessageIter *iter, DBusMessageIter *iter_dict)
{	
	if (!iter || !iter_dict)
		return FALSE;

	return dbus_message_iter_open_container (iter,
					  DBUS_TYPE_ARRAY,
					  DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					  DBUS_TYPE_STRING_AS_STRING
					  DBUS_TYPE_VARIANT_AS_STRING
					  DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					  iter_dict);
}

/**
 * End a dict element in a dbus message.  Should be paired with
 * a call to {@link nmu_dbus_dict_open_write}.
 *
 * @param iter valid dbus message iterator, same as passed to
 *    nmu_dbus_dict_open_write()
 * @param iter_dict a dbus dict iterator returned from {@link nmu_dbus_dict_open_write}
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_close_write (DBusMessageIter *iter, DBusMessageIter *iter_dict)
{	
	if (!iter || !iter_dict)
		return FALSE;

	return dbus_message_iter_close_container (iter, iter_dict);
}


static const char *
_nmu_get_type_as_string_from_type (const int type)
{
	switch (type)
	{
		case DBUS_TYPE_BYTE:
			return DBUS_TYPE_BYTE_AS_STRING;
		case DBUS_TYPE_BOOLEAN:
			return DBUS_TYPE_BOOLEAN_AS_STRING;
		case DBUS_TYPE_INT16:
			return DBUS_TYPE_INT16_AS_STRING;
		case DBUS_TYPE_UINT16:
			return DBUS_TYPE_UINT16_AS_STRING;
		case DBUS_TYPE_INT32:
			return DBUS_TYPE_INT32_AS_STRING;
		case DBUS_TYPE_UINT32:
			return DBUS_TYPE_UINT32_AS_STRING;
		case DBUS_TYPE_INT64:
			return DBUS_TYPE_INT64_AS_STRING;
		case DBUS_TYPE_UINT64:
			return DBUS_TYPE_UINT64_AS_STRING;
		case DBUS_TYPE_DOUBLE:
			return DBUS_TYPE_DOUBLE_AS_STRING;
		case DBUS_TYPE_STRING:
			return DBUS_TYPE_STRING_AS_STRING;
		case DBUS_TYPE_OBJECT_PATH:
			return DBUS_TYPE_OBJECT_PATH_AS_STRING;
		case DBUS_TYPE_ARRAY:
			return DBUS_TYPE_ARRAY_AS_STRING;
		default:
			return NULL;
	}
	return NULL;
}


static dbus_bool_t
_nmu_dbus_add_dict_entry_start (DBusMessageIter *iter_dict,
                                DBusMessageIter *iter_dict_entry,
                                const char *key,
                                const int value_type)
{
	if (!dbus_message_iter_open_container (iter_dict,
					  DBUS_TYPE_DICT_ENTRY,
					  NULL,
					  iter_dict_entry))
		return FALSE;

	if (!dbus_message_iter_append_basic (iter_dict_entry, DBUS_TYPE_STRING, &key))
		return FALSE;

	return TRUE;
}


static dbus_bool_t
_nmu_dbus_add_dict_entry_end (DBusMessageIter *iter_dict,
                              DBusMessageIter *iter_dict_entry,
                              DBusMessageIter *iter_dict_val)
{
	if (!dbus_message_iter_close_container (iter_dict_entry, iter_dict_val))
		return FALSE;
	if (!dbus_message_iter_close_container (iter_dict, iter_dict_entry))
		return FALSE;

	return TRUE;
}


static dbus_bool_t
_nmu_dbus_add_dict_entry_basic (DBusMessageIter *iter_dict,
                                const char *key,
                                const int value_type,
                                const void *value)
{
	DBusMessageIter iter_dict_entry, iter_dict_val;
	const char * type_as_string = NULL;

	type_as_string = _nmu_get_type_as_string_from_type (value_type);
	if (!type_as_string)
		return FALSE;

	if (!_nmu_dbus_add_dict_entry_start (iter_dict, &iter_dict_entry,
			key, value_type))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_entry,
					  DBUS_TYPE_VARIANT,
					  type_as_string,
					  &iter_dict_val))
		return FALSE;

	if (!dbus_message_iter_append_basic (&iter_dict_val, value_type, value))
		return FALSE;

	if (!_nmu_dbus_add_dict_entry_end (iter_dict, &iter_dict_entry,
			&iter_dict_val))
		return FALSE;

	return TRUE;
}


static dbus_bool_t
_nmu_dbus_add_dict_entry_byte_array (DBusMessageIter *iter_dict,
                                     const char *key,
                                     const char *value,
                                     const dbus_uint32_t value_len)
{
	DBusMessageIter iter_dict_entry, iter_dict_val, iter_array;
	dbus_uint32_t i;

	if (!_nmu_dbus_add_dict_entry_start (iter_dict, &iter_dict_entry,
			key, DBUS_TYPE_ARRAY))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_entry,
					  DBUS_TYPE_VARIANT,
					  DBUS_TYPE_ARRAY_AS_STRING
					  DBUS_TYPE_BYTE_AS_STRING,
					  &iter_dict_val))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_val, DBUS_TYPE_ARRAY,
			DBUS_TYPE_BYTE_AS_STRING, &iter_array))
		return FALSE;

	for (i = 0; i < value_len; i++)
	{
		if (!dbus_message_iter_append_basic (&iter_array, DBUS_TYPE_BYTE,
				&(value[i])))
			return FALSE;
	}
	
	if (!dbus_message_iter_close_container (&iter_dict_val, &iter_array))
		return FALSE;

	if (!_nmu_dbus_add_dict_entry_end (iter_dict, &iter_dict_entry,
			&iter_dict_val))
		return FALSE;

	return TRUE;
}


static dbus_bool_t
_nmu_dbus_add_dict_entry_string_array (DBusMessageIter *iter_dict,
                                       const char *key,
                                       const char **items,
                                       const dbus_uint32_t num_items)
{
	DBusMessageIter iter_dict_entry, iter_dict_val, iter_array;
	dbus_uint32_t i;

	if (!_nmu_dbus_add_dict_entry_start (iter_dict, &iter_dict_entry,
			key, DBUS_TYPE_ARRAY))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_entry,
					  DBUS_TYPE_VARIANT,
					  DBUS_TYPE_ARRAY_AS_STRING
					  DBUS_TYPE_STRING_AS_STRING,
					  &iter_dict_val))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_val, DBUS_TYPE_ARRAY,
			DBUS_TYPE_BYTE_AS_STRING, &iter_array))
		return FALSE;

	for (i = 0; i < num_items; i++)
	{
		if (!dbus_message_iter_append_basic (&iter_array, DBUS_TYPE_STRING,
				&(items[i])))
			return FALSE;
	}
	
	if (!dbus_message_iter_close_container (&iter_dict_val, &iter_array))
		return FALSE;

	if (!_nmu_dbus_add_dict_entry_end (iter_dict, &iter_dict_entry,
			&iter_dict_val))
		return FALSE;

	return TRUE;
}

/**
 * Add a string entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The string value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_string (DBusMessageIter *iter_dict,
                             const char * key,
                             const char * value)
{
	if (!key || !value) return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_STRING, &value);
}

/**
 * Add a byte entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The byte value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_byte (DBusMessageIter *iter_dict,
                           const char * key,
                           const char value)
{
	if (!key) return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_BYTE, &value);
}

/**
 * Add a boolean entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The boolean value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_bool (DBusMessageIter *iter_dict,
                           const char * key,
                           const dbus_bool_t value)
{
	if (!key) return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_BOOLEAN, &value);
}

/**
 * Add a 16-bit signed integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The 16-bit signed integer value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_int16 (DBusMessageIter *iter_dict,
                            const char * key,
                            const dbus_int16_t value)
{
	if (!key) return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_INT16, &value);
}

/**
 * Add a 16-bit unsigned integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The 16-bit unsigned integer value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_uint16 (DBusMessageIter *iter_dict,
                             const char * key,
                             const dbus_uint16_t value)
{
	if (!key) return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_UINT16, &value);
}

/**
 * Add a 32-bit signed integer to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The 32-bit signed integer value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_int32 (DBusMessageIter *iter_dict,
                            const char * key,
                            const dbus_int32_t value)
{
	if (!key) return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_INT32, &value);
}

/**
 * Add a 32-bit unsigned integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The 32-bit unsigned integer value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_uint32 (DBusMessageIter *iter_dict,
                             const char * key,
                             const dbus_uint32_t value)
{
	if (!key) return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_UINT32, &value);
}

/**
 * Add a 64-bit integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The 64-bit integer value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_int64 (DBusMessageIter *iter_dict,
                            const char * key,
                            const dbus_int64_t value)
{
	if (!key) return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_INT64, &value);
}

/**
 * Add a 64-bit unsigned integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The 64-bit unsigned integer value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_uint64 (DBusMessageIter *iter_dict,
                             const char * key,
                             const dbus_uint64_t value)
{
	if (!key) return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_UINT64, &value);
}

/**
 * Add a double-precision floating point entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The double-precision floating point value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_double (DBusMessageIter *iter_dict,
                             const char * key,
                             const double value)
{
	if (!key) return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_DOUBLE, &value);
}

/**
 * Add a DBus object path entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The DBus object path value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_object_path (DBusMessageIter *iter_dict,
                                  const char * key,
                                  const char * value)
{
	if (!key || !value) return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_OBJECT_PATH, &value);
}

/**
 * Add a byte array entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The byte array
 * @param value_len The length of the byte array, in bytes
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_byte_array (DBusMessageIter *iter_dict,
                                 const char * key,
                                 const char * value,
                                 const dbus_uint32_t value_len)
{
	if (!key) return FALSE;
	if (!value && (value_len != 0)) return FALSE;
	return _nmu_dbus_add_dict_entry_byte_array (iter_dict, key, value, value_len);
}


/**
 * Add a string array entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param items The array of strings
 * @param num_items The number of strings in the array
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_string_array (DBusMessageIter *iter_dict,
                                   const char * key,
                                   const char ** items,
                                   const dbus_uint32_t num_items)
{
	if (!key) return FALSE;
	if (!items && (num_items != 0)) return FALSE;
	return _nmu_dbus_add_dict_entry_string_array (iter_dict, key, items, num_items);
}

