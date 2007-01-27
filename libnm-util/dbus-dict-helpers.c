/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2006 Red Hat, Inc.
 */

#include <dbus/dbus.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "dbus-dict-helpers.h"


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
nmu_dbus_dict_open_write (DBusMessageIter *iter,
                          DBusMessageIter *iter_dict)
{	
	dbus_bool_t result;

	if (!iter || !iter_dict)
		return FALSE;

	result = dbus_message_iter_open_container (iter,
	                                           DBUS_TYPE_ARRAY,
	                                           DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
	                                           DBUS_TYPE_STRING_AS_STRING
	                                           DBUS_TYPE_VARIANT_AS_STRING
	                                           DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
	                                           iter_dict);
	return result;
}


/**
 * End a dict element in a dbus message.  Should be paired with
 * a call to {@link nmu_dbus_dict_open_write}.
 *
 * @param iter valid dbus message iterator, same as passed to
 *    nmu_dbus_dict_open_write()
 * @param iter_dict a dbus dict iterator returned from
 *    {@link nmu_dbus_dict_open_write}
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_close_write (DBusMessageIter *iter,
                           DBusMessageIter *iter_dict)
{	
	if (!iter || !iter_dict)
		return FALSE;

	return dbus_message_iter_close_container (iter, iter_dict);
}


static const char *
_nmu_get_type_as_string_from_type (const int type)
{
	switch (type) {
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

	if (!dbus_message_iter_append_basic (iter_dict_entry,
	                                     DBUS_TYPE_STRING,
	                                     &key))
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

	if (!_nmu_dbus_add_dict_entry_start (iter_dict,
	                                     &iter_dict_entry,
	                                     key,
	                                     value_type))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_entry,
	                                       DBUS_TYPE_VARIANT,
	                                       type_as_string,
	                                       &iter_dict_val))
		return FALSE;

	if (!dbus_message_iter_append_basic (&iter_dict_val, value_type, value))
		return FALSE;

	if (!_nmu_dbus_add_dict_entry_end (iter_dict,
	                                   &iter_dict_entry,
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

	if (!_nmu_dbus_add_dict_entry_start (iter_dict,
	                                     &iter_dict_entry,
	                                     key,
	                                     DBUS_TYPE_ARRAY))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_entry,
	                                       DBUS_TYPE_VARIANT,
	                                       DBUS_TYPE_ARRAY_AS_STRING
	                                       DBUS_TYPE_BYTE_AS_STRING,
	                                       &iter_dict_val))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_val,
	                                       DBUS_TYPE_ARRAY,
	                                       DBUS_TYPE_BYTE_AS_STRING,
	                                       &iter_array))
		return FALSE;

	for (i = 0; i < value_len; i++) {
		if (!dbus_message_iter_append_basic (&iter_array,
		                                     DBUS_TYPE_BYTE,
		                                     &(value[i])))
			return FALSE;
	}
	
	if (!dbus_message_iter_close_container (&iter_dict_val, &iter_array))
		return FALSE;

	if (!_nmu_dbus_add_dict_entry_end (iter_dict,
	                                   &iter_dict_entry,
	                                   &iter_dict_val))
		return FALSE;

	return TRUE;
}


static dbus_bool_t
_nmu_dbus_add_dict_entry_uint32_array (DBusMessageIter *iter_dict,
                                       const char *key,
                                       const dbus_uint32_t *value,
                                       const dbus_uint32_t value_len)
{
	DBusMessageIter iter_dict_entry, iter_dict_val, iter_array;
	dbus_uint32_t i;

	if (!_nmu_dbus_add_dict_entry_start (iter_dict,
	                                     &iter_dict_entry,
	                                     key,
	                                     DBUS_TYPE_ARRAY))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_entry,
	                                       DBUS_TYPE_VARIANT,
	                                       DBUS_TYPE_ARRAY_AS_STRING
	                                       DBUS_TYPE_UINT32_AS_STRING,
	                                       &iter_dict_val))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_val,
	                                       DBUS_TYPE_ARRAY,
	                                       DBUS_TYPE_UINT32_AS_STRING,
	                                       &iter_array))
		return FALSE;

	for (i = 0; i < value_len; i++) {
		if (!dbus_message_iter_append_basic (&iter_array,
		                                     DBUS_TYPE_UINT32,
		                                     &(value[i])))
			return FALSE;
	}
	
	if (!dbus_message_iter_close_container (&iter_dict_val, &iter_array))
		return FALSE;

	if (!_nmu_dbus_add_dict_entry_end (iter_dict,
	                                   &iter_dict_entry,
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

	if (!_nmu_dbus_add_dict_entry_start (iter_dict,
	                                     &iter_dict_entry,
	                                     key,
	                                     DBUS_TYPE_ARRAY))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_entry,
	                                       DBUS_TYPE_VARIANT,
	                                       DBUS_TYPE_ARRAY_AS_STRING
	                                       DBUS_TYPE_STRING_AS_STRING,
	                                       &iter_dict_val))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_val,
	                                       DBUS_TYPE_ARRAY,
	                                       DBUS_TYPE_BYTE_AS_STRING,
	                                       &iter_array))
		return FALSE;

	for (i = 0; i < num_items; i++) {
		if (!dbus_message_iter_append_basic (&iter_array,
		                                     DBUS_TYPE_STRING,
		                                     &(items[i])))
			return FALSE;
	}
	
	if (!dbus_message_iter_close_container (&iter_dict_val, &iter_array))
		return FALSE;

	if (!_nmu_dbus_add_dict_entry_end (iter_dict,
	                                   &iter_dict_entry,
	                                   &iter_dict_val))
		return FALSE;

	return TRUE;
}

/**
 * Add a string entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
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
	if (!key || !value)
		return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_STRING, &value);
}

/**
 * Add a byte entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
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
	if (!key)
		return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_BYTE, &value);
}

/**
 * Add a boolean entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
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
	if (!key)
		return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_BOOLEAN, &value);
}

/**
 * Add a 16-bit signed integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
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
	if (!key)
		return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_INT16, &value);
}

/**
 * Add a 16-bit unsigned integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
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
	if (!key)
		return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_UINT16, &value);
}

/**
 * Add a 32-bit signed integer to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
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
	if (!key)
		return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_INT32, &value);
}

/**
 * Add a 32-bit unsigned integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
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
	if (!key)
		return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_UINT32, &value);
}

/**
 * Add a 64-bit integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
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
	if (!key)
		return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_INT64, &value);
}

/**
 * Add a 64-bit unsigned integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
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
	if (!key)
		return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_UINT64, &value);
}

/**
 * Add a double-precision floating point entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
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
	if (!key)
		return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_DOUBLE, &value);
}

/**
 * Add a DBus object path entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
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
	if (!key || !value)
		return FALSE;
	return _nmu_dbus_add_dict_entry_basic (iter_dict, key, DBUS_TYPE_OBJECT_PATH, &value);
}

/**
 * Add a byte array entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
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
	if (!key)
		return FALSE;
	if (!value && (value_len != 0))
		return FALSE;
	return _nmu_dbus_add_dict_entry_byte_array (iter_dict, key, value, value_len);
}


/**
 * Add a uint32 array entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The uint32 array
 * @param value_len The length of the uint32 array, in # of elements
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_uint32_array (DBusMessageIter *iter_dict,
                                   const char * key,
                                   const dbus_uint32_t * value,
                                   const dbus_uint32_t value_len)
{
	if (!key)
		return FALSE;
	if (!value && (value_len != 0))
		return FALSE;
	return _nmu_dbus_add_dict_entry_uint32_array (iter_dict, key, value, value_len);
}


/**
 * Begin a string array entry in the dict
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param iter_dict_entry A private DBusMessageIter provided by the caller to
 *    be passed to {@link nmu_dbus_dict_end_string_array}
 * @param iter_dict_val A private DBusMessageIter provided by the caller to
 *    be passed to {@link nmu_dbus_dict_end_string_array}
 * @param iter_array On return, the DBusMessageIter to be passed to 
 *    {@link nmu_dbus_dict_string_array_add_element}
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_begin_string_array (DBusMessageIter *iter_dict,
                                  const char *key,
                                  DBusMessageIter *iter_dict_entry,
                                  DBusMessageIter *iter_dict_val,
                                  DBusMessageIter *iter_array)
{
	if (!iter_dict || !iter_dict_entry || !iter_dict_val || !iter_array)
		return FALSE;

	if (!_nmu_dbus_add_dict_entry_start (iter_dict,
	                                     iter_dict_entry,
	                                     key,
	                                     DBUS_TYPE_ARRAY))
		return FALSE;

	if (!dbus_message_iter_open_container (iter_dict_entry,
	                                       DBUS_TYPE_VARIANT,
	                                       DBUS_TYPE_ARRAY_AS_STRING
	                                       DBUS_TYPE_STRING_AS_STRING,
	                                       iter_dict_val))
		return FALSE;

	if (!dbus_message_iter_open_container (iter_dict_val,
	                                       DBUS_TYPE_ARRAY,
	                                       DBUS_TYPE_BYTE_AS_STRING,
	                                       iter_array))
		return FALSE;

	return TRUE;
}


/**
 * Add a single string element to a string array dict entry
 *
 * @param iter_array A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_begin_string_array}'s iter_array parameter
 * @param elem The string element to be added to the dict entry's string array
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_string_array_add_element (DBusMessageIter *iter_array,
                                        const char *elem)
{
	if (!iter_array || !elem)
		return FALSE;
	return dbus_message_iter_append_basic (iter_array, DBUS_TYPE_STRING, &elem);
}


/**
 * End a string array dict entry
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
 * @param iter_dict_entry A private DBusMessageIter returned from
 *    {@link nmu_dbus_dict_end_string_array}
 * @param iter_dict_val A private DBusMessageIter returned from
 *    {@link nmu_dbus_dict_end_string_array}
 * @param iter_array A DBusMessageIter returned from
 *    {@link nmu_dbus_dict_end_string_array}
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_end_string_array (DBusMessageIter *iter_dict,
                                DBusMessageIter *iter_dict_entry,
                                DBusMessageIter *iter_dict_val,
                                DBusMessageIter *iter_array)
{
	if (!iter_dict || !iter_dict_entry || !iter_dict_val || !iter_array)
		return FALSE;

	if (!dbus_message_iter_close_container (iter_dict_val, iter_array))
		return FALSE;

	if (!_nmu_dbus_add_dict_entry_end (iter_dict,
	                                   iter_dict_entry,
	                                   iter_dict_val))
		return FALSE;

	return TRUE;
}


/**
 * Convenience function to add an entire string array to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param items The array of strings
 * @param num_items The number of strings in the array
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_append_string_array (DBusMessageIter *iter_dict,
                                   const char *key,
                                   const char **items,
                                   const dbus_uint32_t num_items)
{
	DBusMessageIter iter_dict_entry, iter_dict_val, iter_array;
	dbus_uint32_t i;

	if (!key)
		return FALSE;
	if (!items && (num_items != 0))
		return FALSE;

	if (!nmu_dbus_dict_begin_string_array (iter_dict,
	                                       key,
	                                       &iter_dict_entry,
	                                       &iter_dict_val,
	                                       &iter_array))
		return FALSE;

	for (i = 0; i < num_items; i++) {
		if (!nmu_dbus_dict_string_array_add_element (&iter_array, items[i]))
			return FALSE;
	}

	if (!nmu_dbus_dict_end_string_array (iter_dict,
	                                     &iter_dict_entry,
	                                     &iter_dict_val,
	                                     &iter_array))
		return FALSE;

	return TRUE;
}


/*****************************************************/
/* Stuff for reading dicts                           */
/*****************************************************/

/**
 * Start reading from a dbus dict.
 *
 * @param iter A valid DBusMessageIter pointing to the start of the dict
 * @param iter_dict (out) A DBusMessageIter to be passed to
 *    {@link nmu_dbus_dict_read_next_entry}
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_open_read (DBusMessageIter *iter,
                         DBusMessageIter *iter_dict)
{
	if (!iter || !iter_dict) return FALSE;

	if (dbus_message_iter_get_arg_type (iter) != DBUS_TYPE_ARRAY  ||
	    dbus_message_iter_get_element_type (iter) != DBUS_TYPE_DICT_ENTRY)
		return FALSE;

	dbus_message_iter_recurse (iter, iter_dict);
	return TRUE;
}


#define BYTE_ARRAY_CHUNK_SIZE 34
#define BYTE_ARRAY_ITEM_SIZE (sizeof (char))

static dbus_bool_t
_nmu_dbus_dict_entry_get_byte_array (DBusMessageIter *iter,
                                     int array_type,
                                     NMUDictEntry *entry)
{
	dbus_uint32_t count = 0;
	dbus_bool_t success = FALSE;
	char * buffer;

	entry->bytearray_value = NULL;
	entry->array_type = DBUS_TYPE_BYTE;

	buffer = malloc (BYTE_ARRAY_ITEM_SIZE * BYTE_ARRAY_CHUNK_SIZE);
	if (!buffer) {
		fprintf (stderr, "%s out of memory trying to retrieve a byte "
		         "array.\n", __func__);
		goto done;
	}

	entry->bytearray_value = buffer;
	entry->array_len = 0;
	while (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_BYTE) {
		char byte;

		if ((count % BYTE_ARRAY_CHUNK_SIZE) == 0 && count != 0) {
			buffer = realloc (buffer, BYTE_ARRAY_ITEM_SIZE * (count + BYTE_ARRAY_CHUNK_SIZE));
			if (buffer == NULL) {
				fprintf (stderr, "%s() out of memory trying to retrieve"
				         "the string array.\n", __func__);
				goto done;
			}
		}
		entry->bytearray_value = buffer;

		dbus_message_iter_get_basic (iter, &byte);
		entry->bytearray_value[count] = byte;
		entry->array_len = ++count;
		dbus_message_iter_next (iter);
	}

	/* Zero-length arrays are valid. */
	if (entry->array_len == 0) {
		free (entry->bytearray_value);
		entry->bytearray_value = NULL;
	}

	success = TRUE;

done:
	return success;
}

#define UINT32_ARRAY_CHUNK_SIZE 4
#define UINT32_ARRAY_ITEM_SIZE (sizeof (dbus_uint32_t))

static dbus_bool_t
_nmu_dbus_dict_entry_get_uint32_array (DBusMessageIter *iter,
                                       int array_type,
                                       NMUDictEntry *entry)
{
	dbus_uint32_t count = 0;
	dbus_bool_t success = FALSE;
	dbus_uint32_t * buffer;

	entry->uint32array_value = NULL;
	entry->array_type = DBUS_TYPE_UINT32;

	buffer = malloc (UINT32_ARRAY_ITEM_SIZE * UINT32_ARRAY_CHUNK_SIZE);
	if (!buffer) {
		fprintf (stderr, "%s out of memory trying to retrieve a uint32 "
		         "array.\n", __func__);
		goto done;
	}

	entry->uint32array_value = buffer;
	entry->array_len = 0;
	while (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_UINT32) {
		dbus_uint32_t uint32;

		if ((count % UINT32_ARRAY_CHUNK_SIZE) == 0 && count != 0) {
			buffer = realloc (buffer, UINT32_ARRAY_ITEM_SIZE * (count + UINT32_ARRAY_CHUNK_SIZE));
			if (buffer == NULL) {
				fprintf (stderr, "%s() out of memory trying to retrieve"
				         "the string array.\n", __func__);
				goto done;
			}
		}
		entry->uint32array_value = buffer;

		dbus_message_iter_get_basic (iter, &uint32);
		entry->uint32array_value[count] = uint32;
		entry->array_len = ++count;
		dbus_message_iter_next (iter);
	}

	/* Zero-length arrays are valid. */
	if (entry->array_len == 0) {
		free (entry->uint32array_value);
		entry->uint32array_value = NULL;
	}

	success = TRUE;

done:
	return success;
}

#define STR_ARRAY_CHUNK_SIZE 8
#define STR_ARRAY_ITEM_SIZE (sizeof (char *))

static dbus_bool_t
_nmu_dbus_dict_entry_get_string_array (DBusMessageIter *iter,
                                       int array_type,
                                       NMUDictEntry *entry)
{
	dbus_uint32_t count = 0;
	dbus_bool_t success = FALSE;
	char ** buffer;

	entry->strarray_value = NULL;
	entry->array_type = DBUS_TYPE_STRING;

	buffer = (char **)malloc (STR_ARRAY_ITEM_SIZE * STR_ARRAY_CHUNK_SIZE);
	if (buffer == NULL) {
		fprintf (stderr, "%s() out of memory trying to retrieve a string"
		         " array.\n", __func__);
		goto done;
	}

	entry->strarray_value = buffer;
	entry->array_len = 0;
	while (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_STRING) {
		const char *value;
		char *str;

		if ((count % STR_ARRAY_CHUNK_SIZE) == 0 && count != 0) {
			buffer = realloc (buffer, STR_ARRAY_ITEM_SIZE * (count + STR_ARRAY_CHUNK_SIZE));
			if (buffer == NULL) {
				fprintf (stderr, "%s() out of memory trying to retrieve"
				         "the string array.\n", __func__);
				goto done;
			}
		}
		entry->strarray_value = buffer;

		dbus_message_iter_get_basic (iter, &value);
		str = strdup (value);
		if (str == NULL) {
			fprintf (stderr, "%s() out of memory trying to duplicate"
			         "the string array.\n", __func__);
			goto done;
		}
		entry->strarray_value[count] = str;
		entry->array_len = ++count;
		dbus_message_iter_next (iter);
	}

	/* Zero-length arrays are valid. */
	if (entry->array_len == 0) {
		free (entry->strarray_value);
		entry->strarray_value = NULL;
	}

	success = TRUE;

done:
	return success;
}


static dbus_bool_t
_nmu_dbus_dict_entry_get_array (DBusMessageIter *iter_dict_val,
                                NMUDictEntry *entry)
{
	int array_type = dbus_message_iter_get_element_type (iter_dict_val);
	dbus_bool_t success = FALSE;
	DBusMessageIter iter_array;

	if (!entry)
		return FALSE;

	dbus_message_iter_recurse (iter_dict_val, &iter_array);

 	switch (array_type) {
		case DBUS_TYPE_BYTE:
			success = _nmu_dbus_dict_entry_get_byte_array (&iter_array,
			                                               array_type,
			                                               entry);
			break;
		case DBUS_TYPE_UINT32:
			success = _nmu_dbus_dict_entry_get_uint32_array (&iter_array,
			                                                 array_type,
			                                                 entry);
			break;
		case DBUS_TYPE_STRING:
			success = _nmu_dbus_dict_entry_get_string_array (&iter_array,
			                                                 array_type,
			                                                 entry);
			break;
		default:
			break;
	}

	return success;
}


static dbus_bool_t
_nmu_dbus_dict_fill_value_from_variant (NMUDictEntry *entry,
                                        DBusMessageIter *iter_dict_val)
{
	dbus_bool_t success = TRUE;

	switch (entry->type) {
		case DBUS_TYPE_STRING: {
			const char *v;
			dbus_message_iter_get_basic (iter_dict_val, &v);
			entry->str_value = strdup (v);
			break;
		}
		case DBUS_TYPE_BOOLEAN: {
			dbus_bool_t v;
			dbus_message_iter_get_basic (iter_dict_val, &v);
			entry->bool_value = v;
			break;
		}
		case DBUS_TYPE_BYTE: {
			char v;
			dbus_message_iter_get_basic (iter_dict_val, &v);
			entry->byte_value = v;
			break;
		}
		case DBUS_TYPE_INT16: {
			dbus_int16_t v;
			dbus_message_iter_get_basic (iter_dict_val, &v);			
			entry->int16_value = v;
			break;
		}
		case DBUS_TYPE_UINT16: {
			dbus_uint16_t v;
			dbus_message_iter_get_basic (iter_dict_val, &v);			
			entry->uint16_value = v;
			break;
		}
		case DBUS_TYPE_INT32: {
			dbus_int32_t v;
			dbus_message_iter_get_basic (iter_dict_val, &v);			
			entry->int32_value = v;
			break;
		}
		case DBUS_TYPE_UINT32: {
			dbus_uint32_t v;
			dbus_message_iter_get_basic (iter_dict_val, &v);			
			entry->uint32_value = v;
			break;
		}
		case DBUS_TYPE_INT64: {
			dbus_int64_t v;
			dbus_message_iter_get_basic (iter_dict_val, &v);
			entry->int64_value = v;
			break;
		}
		case DBUS_TYPE_UINT64: {
			dbus_uint64_t v;
			dbus_message_iter_get_basic (iter_dict_val, &v);
			entry->uint64_value = v;
			break;
		}
		case DBUS_TYPE_DOUBLE: {
			double v;
			dbus_message_iter_get_basic (iter_dict_val, &v);
			entry->double_value = v;
			break;
		}
		case DBUS_TYPE_OBJECT_PATH: {
			char *v;
			dbus_message_iter_get_basic (iter_dict_val, &v);
			entry->str_value = strdup (v);
			break;
		}
		case DBUS_TYPE_ARRAY: {
			success = _nmu_dbus_dict_entry_get_array (iter_dict_val, entry);
			break;
		}
		default:
			success = FALSE;
			break;
	}

	return success;
}


/**
 * Read the current key/value entry from the dict.  Entries are dynamically
 * allocated when needed and must be freed after use with the
 * {@link nmu_dbus_dict_entry_clear} function.
 *
 * The returned entry object will be filled with the type and value of the next
 * entry in the dict, or the type will be DBUS_TYPE_INVALID if an error
 * occurred.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_read}
 * @param entry A valid dict entry object into which the dict key and value
 *    will be placed
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
nmu_dbus_dict_get_entry (DBusMessageIter *iter_dict,
                         NMUDictEntry * entry)
{
	DBusMessageIter iter_dict_entry, iter_dict_val;
	int type;
	const char *key;

	if (!iter_dict || !entry)
		goto error;

	if (dbus_message_iter_get_arg_type (iter_dict) != DBUS_TYPE_DICT_ENTRY)
		goto error;

	dbus_message_iter_recurse (iter_dict, &iter_dict_entry);
	dbus_message_iter_get_basic (&iter_dict_entry, &key);
	entry->key = key;

	if (!dbus_message_iter_next (&iter_dict_entry))
		goto error;
	type = dbus_message_iter_get_arg_type (&iter_dict_entry);
	if (type != DBUS_TYPE_VARIANT)
		goto error;
		
	dbus_message_iter_recurse (&iter_dict_entry, &iter_dict_val);
	entry->type = dbus_message_iter_get_arg_type (&iter_dict_val);
	if(!_nmu_dbus_dict_fill_value_from_variant (entry, &iter_dict_val))
		goto error;

	dbus_message_iter_next (iter_dict);
	return TRUE;

error:
	nmu_dbus_dict_entry_clear (entry);
	entry->type = DBUS_TYPE_INVALID;
	entry->array_type = DBUS_TYPE_INVALID;
	return FALSE;
}


/**
 * Return whether or not there are additional dictionary entries.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link nmu_dbus_dict_open_read}
 * @return TRUE if more dict entries exists, FALSE if no more dict entries
 *    exist
 *
 */
dbus_bool_t
nmu_dbus_dict_has_dict_entry (DBusMessageIter *iter_dict)
{
	if (!iter_dict) {
		fprintf (stderr, "%s called with invalid arguments; this is an "
				"error in the program.\n", __func__);
		return FALSE;
	}
	return dbus_message_iter_get_arg_type (iter_dict) == DBUS_TYPE_DICT_ENTRY;
}


/**
 * Free any memory used by the entry object.
 *
 * @param entry The entry object
 */
void
nmu_dbus_dict_entry_clear (NMUDictEntry *entry)
{
	if (!entry)
		return;
	switch (entry->type) {
		case DBUS_TYPE_OBJECT_PATH:
		case DBUS_TYPE_STRING:
			free (entry->str_value);
			break;
		case DBUS_TYPE_ARRAY:
			switch (entry->array_type) {
				case DBUS_TYPE_BYTE: {
					free (entry->bytearray_value);
					break;
				}
				case DBUS_TYPE_UINT32: {
					free (entry->uint32array_value);
					break;
				}
				case DBUS_TYPE_STRING: {
					int i;
					for (i = 0; i < entry->array_len; i++)
						free (entry->strarray_value[i]);
					free (entry->strarray_value);
					break;
				}
			}
			break;
	}

	memset (entry, 0, sizeof (NMUDictEntry));
}
