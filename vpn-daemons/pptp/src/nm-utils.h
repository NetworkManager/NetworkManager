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

#ifndef NM_UTILS_H
#define NM_UTILS_H

#include <glib.h>
#include <execinfo.h>

#define nm_print_backtrace()						\
G_STMT_START								\
{									\
	void *_call_stack[512];						\
	int  _call_stack_size;						\
	char **_symbols;						\
	_call_stack_size = backtrace (_call_stack,			\
				      G_N_ELEMENTS (_call_stack));	\
	_symbols = backtrace_symbols (_call_stack, _call_stack_size);	\
	if (_symbols != NULL)						\
	{								\
		int _i;							\
		_i = 0;							\
		g_critical ("traceback:\n");				\
		while (_i < _call_stack_size)				\
		{							\
			g_critical ("\t%s\n", _symbols[_i]);		\
			_i++;						\
		}							\
		free (_symbols);					\
	}								\
}									\
G_STMT_END

#define nm_get_timestamp(timestamp)					\
G_STMT_START								\
{									\
	GTimeVal _tv;							\
	g_get_current_time (&_tv);					\
	*timestamp = (_tv.tv_sec * (1.0 * G_USEC_PER_SEC) +		\
		      _tv.tv_usec) / G_USEC_PER_SEC;			\
}									\
G_STMT_END

#define nm_info(fmt, args...)						\
G_STMT_START								\
{									\
	g_message ("<information>\t" fmt "\n", ##args);			\
} G_STMT_END

#define nm_info_str(fmt_str, args...)						\
G_STMT_START								\
{									\
	g_message ("<information>\t%s\n", fmt_str, ##args);			\
} G_STMT_END

#define nm_debug(fmt, args...)						\
G_STMT_START								\
{									\
	gdouble _timestamp;						\
	nm_get_timestamp (&_timestamp);					\
	g_debug ("<debug info>\t[%f] %s (): " fmt "\n", _timestamp,	\
		 G_STRFUNC, ##args);				\
} G_STMT_END

#define nm_debug_str(fmt_str, args...)						\
G_STMT_START								\
{									\
	gdouble _timestamp;						\
	nm_get_timestamp (&_timestamp);					\
	g_debug ("<debug info>\t[%f] %s (): %s\n", _timestamp,	\
		 G_STRFUNC, fmt_str, ##args);				\
} G_STMT_END

#define nm_warning(fmt, args...)					\
G_STMT_START								\
{									\
	g_warning ("<WARNING>\t %s (): " fmt "\n", 			\
		   G_STRFUNC, ##args);			\
} G_STMT_END

#define nm_warning_str(fmt_str, args...)					\
G_STMT_START								\
{									\
	g_warning ("<WARNING>\t %s (): %s\n", 			\
		   G_STRFUNC, fmt_str, ##args);			\
} G_STMT_END

#define nm_error(fmt, args...)						\
G_STMT_START								\
{									\
	gdouble _timestamp;						\
	nm_get_timestamp (&_timestamp);					\
	g_critical ("<ERROR>\t[%f] %s (): " fmt "\n", _timestamp,	\
		    G_STRFUNC, ##args);			\
	nm_print_backtrace ();						\
	G_BREAKPOINT ();						\
} G_STMT_END

#define nm_error_str(fmt_str, args...)						\
G_STMT_START								\
{									\
	gdouble _timestamp;						\
	nm_get_timestamp (&_timestamp);					\
	g_critical ("<ERROR>\t[%f] %s (): %s\n", _timestamp,	\
		    G_STRFUNC, fmt_str, ##args);			\
	nm_print_backtrace ();						\
	G_BREAKPOINT ();						\
} G_STMT_END

gchar *nm_dbus_escape_object_path (const gchar *utf8_string);
gchar *nm_dbus_unescape_object_path (const gchar *object_path);

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

dbus_bool_t
nmu_dbus_dict_append_string_array (DBusMessageIter *iter_dict,
                                   const char * key,
                                   const char ** items,
                                   const dbus_uint32_t num_items);

#endif /* NM_UTILS_H */
