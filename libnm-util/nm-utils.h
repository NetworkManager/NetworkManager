/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/* NetworkManager -- Network link manager
 *
 * Ray Strode <rstrode@redhat.com>
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
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
 * (C) Copyright 2005 - 2008 Red Hat, Inc.
 */

#ifndef NM_UTILS_H
#define NM_UTILS_H

#include <glib.h>
#include <execinfo.h>

#include "nm-connection.h"

/*********************************************************/
/* The API defined here is _NOT_ guaranteed in any way!! */
/*********************************************************/

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

/* SSID helpers */
gboolean    nm_utils_is_empty_ssid    (const guint8 * ssid, int len);
const char *nm_utils_escape_ssid      (const guint8 *ssid, guint32 len);
gboolean    nm_utils_same_ssid        (const GByteArray * ssid1,
							    const GByteArray * ssid2,
							    gboolean ignore_trailing_null);

char *nm_utils_ssid_to_utf8 (const char *ssid, guint32 len);

GHashTable *nm_utils_gvalue_hash_dup  (GHashTable *hash);

/* Converts a GArray into a UTF-8 string */
char       *nm_utils_garray_to_string (GArray *array);

void        nm_utils_slist_free       (GSList *list,
							    GDestroyNotify elem_destroy_fn);

gboolean    nm_utils_string_in_list   (const char *str,
							    const char **valid_strings);

gboolean    nm_utils_string_list_contains  (GSList *list, 
								    const char *string);

gboolean    nm_utils_string_slist_validate (GSList *list,
								    const char **valid_values);

void        nm_utils_register_value_transformations (void);

typedef enum {
	NMU_SEC_INVALID = 0,
	NMU_SEC_NONE,
	NMU_SEC_STATIC_WEP,
	NMU_SEC_LEAP,
	NMU_SEC_DYNAMIC_WEP,
	NMU_SEC_WPA_PSK,
	NMU_SEC_WPA_ENTERPRISE,
	NMU_SEC_WPA2_PSK,
	NMU_SEC_WPA2_ENTERPRISE
} NMUtilsSecurityType;

gboolean nm_utils_security_valid (NMUtilsSecurityType type,
                                  guint32 dev_caps,
                                  gboolean have_ap,
                                  gboolean adhoc,
                                  guint32 ap_flags,
                                  guint32 ap_wpa,
                                  guint32 ap_rsn);

GSList *nm_utils_ip4_addresses_from_gvalue (const GValue *value);
void nm_utils_ip4_addresses_to_gvalue (GSList *list, GValue *value);

guint32 nm_utils_ip4_netmask_to_prefix (guint32 ip4_netmask);
guint32 nm_utils_ip4_prefix_to_netmask (guint32 ip4_prefix);

GSList *nm_utils_ip6_addresses_from_gvalue (const GValue *value);
void nm_utils_ip6_addresses_to_gvalue (GSList *list, GValue *value);

GSList *nm_utils_ip6_dns_from_gvalue (const GValue *value);
void nm_utils_ip6_dns_to_gvalue (GSList *list, GValue *value);

#endif /* NM_UTILS_H */
