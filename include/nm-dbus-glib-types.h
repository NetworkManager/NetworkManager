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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#ifndef DBUS_GLIB_TYPES_H
#define DBUS_GLIB_TYPES_H

#include <dbus/dbus-glib.h>

#define DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH   (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_OBJECT_PATH))
#define DBUS_TYPE_G_ARRAY_OF_STRING        (dbus_g_type_get_collection ("GPtrArray", G_TYPE_STRING))
#define DBUS_TYPE_G_ARRAY_OF_UINT          (dbus_g_type_get_collection ("GArray", G_TYPE_UINT))
#define DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_ARRAY_OF_UINT))
#define DBUS_TYPE_G_MAP_OF_VARIANT         (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))
#define DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT  (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, DBUS_TYPE_G_MAP_OF_VARIANT))
#define DBUS_TYPE_G_MAP_OF_STRING          (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_STRING))
#define DBUS_TYPE_G_LIST_OF_STRING         (dbus_g_type_get_collection ("GSList", G_TYPE_STRING))

#endif /* DBUS_GLIB_TYPES_H */

