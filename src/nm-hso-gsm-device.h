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
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef NM_HSO_GSM_DEVICE_H
#define NM_HSO_GSM_DEVICE_H

#include <nm-gsm-device.h>

G_BEGIN_DECLS

#define NM_TYPE_HSO_GSM_DEVICE				(nm_hso_gsm_device_get_type ())
#define NM_HSO_GSM_DEVICE(obj)				(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_HSO_GSM_DEVICE, NMHsoGsmDevice))
#define NM_HSO_GSM_DEVICE_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_HSO_GSM_DEVICE, NMHsoGsmDeviceClass))
#define NM_IS_HSO_GSM_DEVICE(obj)			(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_HSO_GSM_DEVICE))
#define NM_IS_HSO_GSM_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_HSO_GSM_DEVICE))
#define NM_HSO_GSM_DEVICE_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_HSO_GSM_DEVICE, NMHsoGsmDeviceClass))

#define NM_HSO_GSM_DEVICE_NETDEV_IFACE "netdev-iface"

typedef struct {
	NMGsmDevice parent;
} NMHsoGsmDevice;

typedef struct {
	NMGsmDeviceClass parent;
} NMHsoGsmDeviceClass;

GType nm_hso_gsm_device_get_type (void);

NMHsoGsmDevice *nm_hso_gsm_device_new (const char *udi,
                                       const char *data_iface,
                                       const char *monitor_iface,
                                       const char *netdev_iface,
                                       const char *driver,
                                       gboolean managed);

G_END_DECLS

#endif /* NM_HSO_GSM_DEVICE_H */
