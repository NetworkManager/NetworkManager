/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef NM_UTILS_H
#define NM_UTILS_H

#include <dbus/dbus-glib.h>

char *_nm_dbus_get_string_property (DBusGProxy *proxy,
								   const char *interface,
								   const char *prop_name);

char *_nm_dbus_get_object_path_property (DBusGProxy *proxy,
										const char *interface,
										const char *prop_name);

gint32 _nm_dbus_get_int_property (DBusGProxy *proxy,
								 const char *interface,
								 const char *prop_name);

guint32 _nm_dbus_get_uint_property (DBusGProxy *proxy,
								   const char *interface,
								   const char *prop_name);

gboolean  _nm_dbus_get_property (DBusGProxy *proxy,
								const char *interface,
								const char *prop_name,
								GValue *value);
void      _nm_dbus_set_property (DBusGProxy *proxy,
								const char *interface,
								const char *prop_name,
								GValue *value);

char     *_nm_dbus_introspect   (DBusGConnection *connection,
								const char *interface,
								const char *path);

#endif /* NM_UTILS_H */
