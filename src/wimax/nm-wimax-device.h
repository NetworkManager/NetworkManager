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
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef NM_WIMAX_DEVICE_H
#define NM_WIMAX_DEVICE_H

#include <net/ethernet.h>
#include <WiMaxType.h>
#include "nm-device.h"
#include "nm-wimax-nsp.h"

G_BEGIN_DECLS

#define NM_TYPE_WIMAX_DEVICE			(nm_wimax_device_get_type ())
#define NM_WIMAX_DEVICE(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIMAX_DEVICE, NMWimaxDevice))
#define NM_WIMAX_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_WIMAX_DEVICE, NMWimaxDeviceClass))
#define NM_IS_WIMAX_DEVICE(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WIMAX_DEVICE))
#define NM_IS_WIMAX_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_WIMAX_DEVICE))
#define NM_WIMAX_DEVICE_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_WIMAX_DEVICE, NMWimaxDeviceClass))

#define NM_WIMAX_DEVICE_INDEX      "index"
#define NM_WIMAX_DEVICE_IFINDEX    "ifindex"
#define NM_WIMAX_DEVICE_HW_ADDRESS "hw-address"
#define NM_WIMAX_DEVICE_ACTIVE_NSP "active-nsp"

typedef struct {
	NMDevice parent;
} NMWimaxDevice;

typedef struct {
	NMDeviceClass parent;

	/* Signals */
	void (*nsp_added)   (NMWimaxDevice *wimax, NMWimaxNsp *nsp);
	void (*nsp_removed) (NMWimaxDevice *wimax, NMWimaxNsp *nsp);
	void (*properties_changed) (NMWimaxDevice *wimax, GHashTable *properties);
} NMWimaxDeviceClass;

GType nm_wimax_device_get_type (void);

NMDevice   *nm_wimax_device_new            (const char *udi,
											const char *iface,
											const char *driver,
											int ifindex,
											guchar wimax_device_index);

void        nm_wimax_device_get_hw_address (NMWimaxDevice *self,
											struct ether_addr *addr);

guint32     nm_wimax_device_get_ifindex    (NMWimaxDevice *self);
void        nm_wimax_device_set_enabled    (NMWimaxDevice *self,
											gboolean enabled);

GSList     *nm_wimax_device_get_nsps       (NMWimaxDevice *self);
NMWimaxNsp *nm_wimax_device_get_active_nsp (NMWimaxDevice *self);

G_END_DECLS

#endif	/* NM_WIMAX_DEVICE_H */
