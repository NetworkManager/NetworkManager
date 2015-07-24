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
 * Copyright (C) 2015 Red Hat, Inc.
 */


#include "nm-glib.h"
#include "nm-types.h"

#ifndef __NETWORKMANAGER_ROUTE_MANAGER_H__
#define __NETWORKMANAGER_ROUTE_MANAGER_H__

#define NM_TYPE_ROUTE_MANAGER            (nm_route_manager_get_type ())
#define NM_ROUTE_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ROUTE_MANAGER, NMRouteManager))
#define NM_ROUTE_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_ROUTE_MANAGER, NMRouteManagerClass))
#define NM_IS_ROUTE_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ROUTE_MANAGER))
#define NM_IS_ROUTE_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_ROUTE_MANAGER))
#define NM_ROUTE_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_ROUTE_MANAGER, NMRouteManagerClass))

struct _NMRouteManager {
	GObject parent;
};

typedef struct {
	GObjectClass parent;
} NMRouteManagerClass;

GType nm_route_manager_get_type (void);

gboolean nm_route_manager_ip4_route_sync (NMRouteManager *self, int ifindex, const GArray *known_routes, gboolean ignore_kernel_routes, gboolean full_sync);
gboolean nm_route_manager_ip6_route_sync (NMRouteManager *self, int ifindex, const GArray *known_routes, gboolean ignore_kernel_routes, gboolean full_sync);
gboolean nm_route_manager_route_flush (NMRouteManager *self, int ifindex);

void nm_route_manager_ip4_route_register_device_route_purge_list (NMRouteManager *self, GArray *device_route_purge_list);

NMRouteManager *nm_route_manager_get (void);

#endif  /* NM_ROUTE_MANAGER_H */
