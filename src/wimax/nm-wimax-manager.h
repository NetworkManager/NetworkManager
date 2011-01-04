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
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
 */

#ifndef NM_WIMAX_MANAGER_H
#define NM_WIMAX_MANAGER_H

#include <glib.h>
#include <glib-object.h>

#define NM_TYPE_WIMAX_MANAGER            (nm_wimax_manager_get_type ())
#define NM_WIMAX_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIMAX_MANAGER, NMWimaxManager))
#define NM_WIMAX_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_WIMAX_MANAGER, NMWimaxManagerClass))
#define NM_IS_WIMAX_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WIMAX_MANAGER))
#define NM_IS_WIMAX_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_WIMAX_MANAGER))
#define NM_WIMAX_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_WIMAX_MANAGER, NMWimaxManagerClass))

#define NM_WIMAX_MANAGER_DEVICE_ADDED   "device-added"
#define NM_WIMAX_MANAGER_DEVICE_REMOVED "device-removed"

typedef struct {
	GObject parent;
} NMWimaxManager;

typedef struct {
	GObjectClass parent;
} NMWimaxManagerClass;

GType nm_wimax_manager_get_type (void);

NMWimaxManager *nm_wimax_manager_get (void);

#endif /* NM_WIMAX_MANAGER_H */

