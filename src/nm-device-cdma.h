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
 * Copyright (C) 2009 Red Hat, Inc.
 */

#ifndef NM_DEVICE_CDMA_H
#define NM_DEVICE_CDMA_H

#include "nm-device-modem.h"
#include "nm-modem-cdma.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_CDMA            (nm_device_cdma_get_type ())
#define NM_DEVICE_CDMA(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_CDMA, NMDeviceCdma))
#define NM_DEVICE_CDMA_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_CDMA, NMDeviceCdmaClass))
#define NM_IS_DEVICE_CDMA(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_CDMA))
#define NM_IS_DEVICE_CDMA_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_CDMA))
#define NM_DEVICE_CDMA_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_CDMA, NMDeviceCdmaClass))

typedef struct {
	NMDeviceModem parent;
} NMDeviceCdma;

typedef struct {
	NMDeviceModemClass parent;

	/* Signals */
	void (*signal_quality) (NMDeviceCdma *self, guint32 quality);

	void (*properties_changed) (NMDeviceCdma *self, GHashTable *properties);
} NMDeviceCdmaClass;

GType nm_device_cdma_get_type (void);

NMDevice *nm_device_cdma_new (NMModemCdma *modem, const char *driver);

G_END_DECLS

#endif /* NM_DEVICE_CDMA_H */
