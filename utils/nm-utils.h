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

#ifndef NM_UTILS_H
#define NM_UTILS_H

#include <glib.h>
#include <execinfo.h>
#include <dbus/dbus.h>

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
	g_message ("<info>  " fmt "\n", ##args);			\
} G_STMT_END

#define nm_info_str(fmt_str, args...)						\
G_STMT_START								\
{									\
	g_message ("<info>  %s\n", fmt_str, ##args);			\
} G_STMT_END

#define nm_debug(fmt, args...)						\
G_STMT_START								\
{									\
	gdouble _timestamp;						\
	nm_get_timestamp (&_timestamp);					\
	g_debug ("<debug> [%f] %s(): " fmt "\n", _timestamp,	\
		 G_STRFUNC, ##args);				\
} G_STMT_END

#define nm_debug_str(fmt_str, args...)						\
G_STMT_START								\
{									\
	gdouble _timestamp;						\
	nm_get_timestamp (&_timestamp);					\
	g_debug ("<debug> [%f] %s(): %s\n", _timestamp,	\
		 G_STRFUNC, fmt_str, ##args);				\
} G_STMT_END

#define nm_warning(fmt, args...)					\
G_STMT_START								\
{									\
	g_warning ("<WARN>  %s(): " fmt "\n", 			\
		   G_STRFUNC, ##args);			\
} G_STMT_END

#define nm_warning_str(fmt_str, args...)					\
G_STMT_START								\
{									\
	g_warning ("<WARN>  %s(): %s\n", 			\
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

char *nm_utils_essid_to_utf8 (const char *orig_essid);

/* #define DBUS_PENDING_CALL_DEBUG */

DBusPendingCall * nm_dbus_send_with_callback (DBusConnection *connection,
                                              DBusMessage *msg, 
                                              DBusPendingCallNotifyFunction func,
                                              gpointer data,
                                              DBusFreeFunction free_func,
                                              const char *caller);
void nm_dbus_send_with_callback_replied (DBusPendingCall *pcall,
                                         const char *caller);

#endif /* NM_UTILS_H */
