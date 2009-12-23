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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#ifndef NM_UDEV_MANAGER_H
#define NM_UDEV_MANAGER_H

#include <glib.h>
#include <glib-object.h>

#define G_UDEV_API_IS_SUBJECT_TO_CHANGE
#include <gudev/gudev.h>

#include "nm-rfkill.h"

G_BEGIN_DECLS

#define NM_TYPE_UDEV_MANAGER            (nm_udev_manager_get_type ())
#define NM_UDEV_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_UDEV_MANAGER, NMUdevManager))
#define NM_UDEV_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_UDEV_MANAGER, NMUdevManagerClass))
#define NM_IS_UDEV_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_UDEV_MANAGER))
#define NM_IS_UDEV_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_UDEV_MANAGER))
#define NM_UDEV_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_UDEV_MANAGER, NMUdevManagerClass))

typedef struct {
	GObject parent;
} NMUdevManager;

typedef GObject *(*NMDeviceCreatorFn) (NMUdevManager *manager,
                                       GUdevDevice *device,
                                       gboolean sleeping);

typedef struct {
	GObjectClass parent;

	/* Virtual functions */
	void (*device_added) (NMUdevManager *manager,
	                      GUdevDevice *device,
	                      NMDeviceCreatorFn creator_fn);

	void (*device_removed) (NMUdevManager *manager, GUdevDevice *device);

	void (*rfkill_changed) (NMUdevManager *manager, RfKillType rtype, RfKillState state);
} NMUdevManagerClass;

GType nm_udev_manager_get_type (void);

NMUdevManager *nm_udev_manager_new (void);

void nm_udev_manager_query_devices (NMUdevManager *manager);

RfKillState nm_udev_manager_get_rfkill_state (NMUdevManager *manager, RfKillType rtype);

#endif /* NM_UDEV_MANAGER_H */

