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
 * Copyright (C) 2005 - 2012 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef NM_DEVICE_WIRED_H
#define NM_DEVICE_WIRED_H

#include <glib-object.h>

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_WIRED			(nm_device_wired_get_type ())
#define NM_DEVICE_WIRED(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_WIRED, NMDeviceWired))
#define NM_DEVICE_WIRED_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_WIRED, NMDeviceWiredClass))
#define NM_IS_DEVICE_WIRED(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_WIRED))
#define NM_IS_DEVICE_WIRED_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_WIRED))
#define NM_DEVICE_WIRED_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_WIRED, NMDeviceWiredClass))

typedef struct {
	NMDevice parent;
} NMDeviceWired;

typedef struct {
	NMDeviceClass parent;

	void (*carrier_action) (NMDeviceWired *self,
	                        NMDeviceState state,
	                        gboolean carrier);
} NMDeviceWiredClass;

GType nm_device_wired_get_type (void);

gboolean      nm_device_wired_get_carrier     (NMDeviceWired *dev);
guint32       nm_device_wired_get_speed       (NMDeviceWired *dev);

G_END_DECLS

#endif	/* NM_DEVICE_WIRED_H */
