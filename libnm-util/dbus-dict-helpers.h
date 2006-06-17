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

#ifndef DBUS_DICT_HELPERS_H
#define DBUS_DICT_HELPERS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Adding a dict to a DBusMessage
 */

dbus_bool_t
nmu_dbus_dict_open_write (DBusMessageIter *iter,
                          DBusMessageIter *iter_dict);

dbus_bool_t
nmu_dbus_dict_close_write (DBusMessageIter *iter,
                           DBusMessageIter *iter_dict);

dbus_bool_t
nmu_dbus_dict_append_string (DBusMessageIter *iter_dict,
                             const char * key,
                             const char * value);

dbus_bool_t
nmu_dbus_dict_append_byte (DBusMessageIter *iter_dict,
                           const char * key,
                           const char value);

dbus_bool_t
nmu_dbus_dict_append_bool (DBusMessageIter *iter_dict,
                           const char * key,
                           const dbus_bool_t value);

dbus_bool_t
nmu_dbus_dict_append_int16 (DBusMessageIter *iter_dict,
                            const char * key,
                            const dbus_int16_t value);

dbus_bool_t
nmu_dbus_dict_append_uint16 (DBusMessageIter *iter_dict,
                             const char * key,
                             const dbus_uint16_t value);

dbus_bool_t
nmu_dbus_dict_append_int32 (DBusMessageIter *iter_dict,
                            const char * key,
                            const dbus_int32_t value);

dbus_bool_t
nmu_dbus_dict_append_uint32 (DBusMessageIter *iter_dict,
                             const char * key,
                             const dbus_uint32_t value);

dbus_bool_t
nmu_dbus_dict_append_int64 (DBusMessageIter *iter_dict,
                            const char * key,
                            const dbus_int64_t value);

dbus_bool_t
nmu_dbus_dict_append_uint64 (DBusMessageIter *iter_dict,
                             const char * key,
                             const dbus_uint64_t value);

dbus_bool_t
nmu_dbus_dict_append_double (DBusMessageIter *iter_dict,
                             const char * key,
                             const double value);

dbus_bool_t
nmu_dbus_dict_append_object_path (DBusMessageIter *iter_dict,
                                  const char * key,
                                  const char * value);

dbus_bool_t
nmu_dbus_dict_append_byte_array (DBusMessageIter *iter_dict,
                                 const char * key,
                                 const char * value,
                                 const dbus_uint32_t value_len);

/*
 * Reading a dict from a DBusMessage
 */

typedef struct NMUDictEntry {
	int type;
	int array_type;
	const char *key;

	/** Possible values of the property */
	union {
		char *str_value;
		char byte_value;
		dbus_bool_t bool_value;
		dbus_int16_t int16_value;
		dbus_uint16_t uint16_value;
		dbus_int32_t int32_value;
		dbus_uint32_t uint32_value;
		dbus_int64_t int64_value;
		dbus_uint64_t uint64_value;
		double double_value;
		char * bytearray_value;
	};
	dbus_uint32_t array_len;
} NMUDictEntry;

dbus_bool_t
nmu_dbus_dict_open_read (DBusMessageIter *iter,
                         DBusMessageIter *iter_dict);

dbus_bool_t
nmu_dbus_dict_get_entry (DBusMessageIter *iter_dict,
                         NMUDictEntry * entry);

dbus_bool_t
nmu_dbus_dict_has_dict_entry (DBusMessageIter *iter_dict);

void
nmu_dbus_dict_entry_clear (NMUDictEntry *entry);

#ifdef __cplusplus
}
#endif

#endif  /* DBUS_DICT_HELPERS_H */
