/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2008 Red Hat, Inc.
 */

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <string.h>
#include "nm-types.h"
#include "nm-types-private.h"
#include "nm-object-private.h"
#include "nm-object-cache.h"
#include "nm-dbus-glib-types.h"
#include "nm-setting-ip6-config.h"

static gpointer
_nm_ip6_address_object_array_copy (GPtrArray *src)
{
	GPtrArray *dest;
	int i;

	dest = g_ptr_array_sized_new (src->len);
	for (i = 0; i < src->len; i++)
		g_ptr_array_add (dest, nm_ip6_address_dup (g_ptr_array_index (src, i)));
	return dest;
}

static void
_nm_ip6_address_object_array_free (GPtrArray *array)
{
	int i;

	for (i = 0; i < array->len; i++)
		nm_ip6_address_unref (g_ptr_array_index (array, i));
	g_ptr_array_free (array, TRUE);
}

GType
nm_ip6_address_object_array_get_type (void)
{
	static GType our_type = 0;

	if (our_type == 0)
		our_type = g_boxed_type_register_static (g_intern_static_string ("NMIP6AddressObjectArray"),
		                                         (GBoxedCopyFunc) _nm_ip6_address_object_array_copy,
		                                         (GBoxedFreeFunc) _nm_ip6_address_object_array_free);
	return our_type;
}

/*****************************/

static gpointer
_nm_ip6_route_object_array_copy (GPtrArray *src)
{
	GPtrArray *dest;
	int i;

	dest = g_ptr_array_sized_new (src->len);
	for (i = 0; i < src->len; i++)
		g_ptr_array_add (dest, nm_ip6_route_dup (g_ptr_array_index (src, i)));
	return dest;
}

static void
_nm_ip6_route_object_array_free (GPtrArray *array)
{
	int i;

	for (i = 0; i < array->len; i++)
		nm_ip6_route_unref (g_ptr_array_index (array, i));
	g_ptr_array_free (array, TRUE);
}

GType
nm_ip6_route_object_array_get_type (void)
{
	static GType our_type = 0;

	if (our_type == 0)
		our_type = g_boxed_type_register_static (g_intern_static_string ("NMIP6RouteObjectArray"),
		                                         (GBoxedCopyFunc) _nm_ip6_route_object_array_copy,
		                                         (GBoxedFreeFunc) _nm_ip6_route_object_array_free);
	return our_type;
}
