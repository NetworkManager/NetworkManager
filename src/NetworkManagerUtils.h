/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright 2004 - 2016 Red Hat, Inc.
 * Copyright 2005 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_UTILS_H__
#define __NETWORKMANAGER_UTILS_H__

#include "nm-core-utils.h"

/*****************************************************************************/

const char *nm_utils_get_shared_wifi_permission (NMConnection *connection);

void nm_utils_complete_generic (NMPlatform *platform,
                                NMConnection *connection,
                                const char *ctype,
                                const GSList *existing,
                                const char *preferred_id,
                                const char *fallback_id_prefix,
                                const char *ifname_prefix,
                                gboolean default_enable_ipv6);

typedef gboolean (NMUtilsMatchFilterFunc) (NMConnection *connection, gpointer user_data);

NMConnection *nm_utils_match_connection (NMConnection *const*connections,
                                         NMConnection *original,
                                         gboolean indicated,
                                         gboolean device_has_carrier,
                                         gint64 default_v4_metric,
                                         gint64 default_v6_metric,
                                         NMUtilsMatchFilterFunc match_filter_func,
                                         gpointer match_filter_data);

void nm_utils_g_value_set_object_path (GValue *value, gpointer object);

/**
 * NMUtilsObjectFunc:
 * @object: the object to filter on
 * @user_data: data passed to the function from the caller
 *
 * Returns: %TRUE if the object should be used, %FALSE if not
 */
typedef gboolean (*NMUtilsObjectFunc) (GObject *object, gpointer user_data);

void nm_utils_g_value_set_object_path_array (GValue *value,
                                             GSList *objects,
                                             NMUtilsObjectFunc filter_func,
                                             gpointer user_data);

/*****************************************************************************/

#endif /* __NETWORKMANAGER_UTILS_H__ */
