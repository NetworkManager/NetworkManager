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
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_BLUEZ_MANAGER_H__
#define __NETWORKMANAGER_BLUEZ_MANAGER_H__

#include "nm-glib.h"

G_BEGIN_DECLS

#define NM_TYPE_BLUEZ_MANAGER (nm_bluez_manager_get_type ())
#define NM_BLUEZ_MANAGER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BLUEZ_MANAGER, NMBluezManager))

#define NM_BLUEZ_MANAGER_BDADDR_ADDED "bdaddr-added"

typedef struct {
	GObject parent;
} NMBluezManager;

typedef struct {
	GObjectClass parent;
} NMBluezManagerClass;

#endif /* __NETWORKMANAGER_BLUEZ_MANAGER_H__ */

