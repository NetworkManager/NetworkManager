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

#ifndef NM_HAL_MANAGER_H
#define NM_HAL_MANAGER_H

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define NM_TYPE_HAL_MANAGER            (nm_hal_manager_get_type ())
#define NM_HAL_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_HAL_MANAGER, NMHalManager))
#define NM_HAL_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_HAL_MANAGER, NMHalManagerClass))
#define NM_IS_HAL_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_HAL_MANAGER))
#define NM_IS_HAL_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_HAL_MANAGER))
#define NM_HAL_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_HAL_MANAGER, NMHalManagerClass))

typedef struct {
	GObject parent;
} NMHalManager;

typedef GObject *(*NMDeviceCreatorFn) (NMHalManager *manager,
                                       const char *udi,
                                       gboolean managed);

typedef struct {
	GObjectClass parent;

	/* Virtual functions */
	void (*udi_added) (NMHalManager *manager,
	                   const char *udi,
	                   const char *type_name,
	                   NMDeviceCreatorFn creator_fn);

	void (*udi_removed) (NMHalManager *manager, const char *udi);

	void (*rfkill_changed) (NMHalManager *manager, gboolean hw_enabled);

	void (*hal_reappeared) (NMHalManager *manager);
} NMHalManagerClass;

GType nm_hal_manager_get_type (void);

NMHalManager *nm_hal_manager_new (void);
gboolean nm_hal_manager_get_rfkilled (NMHalManager *manager);
void nm_hal_manager_query_devices (NMHalManager *manager);
gboolean nm_hal_manager_udi_exists (NMHalManager *manager, const char *udi);

#endif /* NM_HAL_MANAGER_H */
