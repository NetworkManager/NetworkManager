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
 * Copyright (C) 2007 - 2012 Red Hat, Inc.
 */

#ifndef NM_ATM_MANAGER_H
#define NM_ATM_MANAGER_H

#include <glib.h>
#include <glib-object.h>

#include <gudev/gudev.h>

G_BEGIN_DECLS

#define NM_TYPE_ATM_MANAGER            (nm_atm_manager_get_type ())
#define NM_ATM_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ATM_MANAGER, NMAtmManager))
#define NM_ATM_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_ATM_MANAGER, NMAtmManagerClass))
#define NM_IS_ATM_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ATM_MANAGER))
#define NM_IS_ATM_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_ATM_MANAGER))
#define NM_ATM_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_ATM_MANAGER, NMAtmManagerClass))

typedef struct {
	GObject parent;
} NMAtmManager;

typedef struct {
	GObjectClass parent;

	/* signals */
	void (*device_added)   (NMAtmManager *manager,
	                        const char *iface,
	                        const char *sysfs_path,
	                        const char *driver);

	void (*device_removed) (NMAtmManager *manager,
	                        const char *iface);
} NMAtmManagerClass;

GType nm_atm_manager_get_type (void);

NMAtmManager *nm_atm_manager_new (void);

void nm_atm_manager_query_devices (NMAtmManager *manager);

#endif /* NM_ATM_MANAGER_H */

