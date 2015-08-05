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
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_BLUEZ4_MANAGER_H__
#define __NETWORKMANAGER_BLUEZ4_MANAGER_H__

#include "nm-default.h"
#include "nm-connection-provider.h"

G_BEGIN_DECLS

#define NM_TYPE_BLUEZ4_MANAGER            (nm_bluez4_manager_get_type ())
#define NM_BLUEZ4_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BLUEZ4_MANAGER, NMBluez4Manager))
#define NM_BLUEZ4_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_BLUEZ4_MANAGER, NMBluez4ManagerClass))
#define NM_IS_BLUEZ4_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_BLUEZ4_MANAGER))
#define NM_IS_BLUEZ4_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_BLUEZ4_MANAGER))
#define NM_BLUEZ4_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_BLUEZ4_MANAGER, NMBluez4ManagerClass))

typedef struct {
	GObject parent;
} NMBluez4Manager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*bdaddr_added) (NMBluez4Manager *manager,
	                      const char *bdaddr,
	                      const char *name,
	                      const char *object_path,
	                      guint uuids);
} NMBluez4ManagerClass;

GType nm_bluez4_manager_get_type (void);

NMBluez4Manager *nm_bluez4_manager_new (NMConnectionProvider *provider);

void nm_bluez4_manager_query_devices (NMBluez4Manager *manager);

#endif /* __NETWORKMANAGER_BLUEZ4_MANAGER_H__ */

