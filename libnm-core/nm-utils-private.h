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
 * Copyright 2005 - 2014 Red Hat, Inc.
 */

#ifndef __NM_UTILS_PRIVATE_H__
#define __NM_UTILS_PRIVATE_H__

#ifdef __NETWORKMANAGER_TYPES_H__
#error "nm-utils-private.h" must not be used outside of libnm-core/. Do you want "nm-core-internal.h"?
#endif

#include "nm-setting-private.h"
#include "nm-setting-ip-config.h"

gboolean    _nm_utils_string_slist_validate (GSList *list,
                                             const char **valid_values);

/* D-Bus transform funcs */

GVariant *  _nm_utils_hwaddr_to_dbus   (const GValue *prop_value);
void        _nm_utils_hwaddr_from_dbus (GVariant *dbus_value,
                                        GValue *prop_value);

GVariant *  _nm_utils_strdict_to_dbus   (const GValue *prop_value);
void        _nm_utils_strdict_from_dbus (GVariant *dbus_value,
                                         GValue *prop_value);

GVariant *  _nm_utils_bytes_to_dbus     (const GValue *prop_value);
void        _nm_utils_bytes_from_dbus   (GVariant *dbus_value,
                                         GValue *prop_value);

char *      _nm_utils_hwaddr_canonical_or_invalid (const char *mac, gssize length);

#endif
