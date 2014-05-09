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
 * Copyright 2007 - 2008 Red Hat, Inc.
 */

#ifndef NM_TYPES_PRIVATE_H
#define NM_TYPES_PRIVATE_H

#include <dbus/dbus-glib.h>
#include "nm-types.h"
#include "nm-object-private.h"

gboolean _nm_ssid_demarshal (GValue *value, GByteArray **dest);
gboolean _nm_uint_array_demarshal (GValue *value, GArray **dest);
gboolean _nm_string_array_demarshal (GValue *value, GPtrArray **dest);
gboolean _nm_object_array_demarshal (GValue *value,
                                     GPtrArray **dest,
                                     DBusGConnection *connection,
                                     NMObjectCreatorFunc func);
gboolean _nm_ip6_address_array_demarshal (GValue *value, GSList **dest);

#endif /* NM_TYPES_PRIVATE_H */
