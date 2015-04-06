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
 * Author: Pantelis Koukousoulas <pktoss@gmail.com>
 * Copyright (C) 2009 - 2011 Red Hat Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_ADSL_H__
#define __NETWORKMANAGER_DEVICE_ADSL_H__

// Parent class
#include "nm-glib.h"
#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_ADSL            (nm_device_adsl_get_type ())
#define NM_DEVICE_ADSL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_ADSL, NMDeviceAdsl))
#define NM_DEVICE_ADSL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_ADSL, NMDeviceAdslClass))
#define NM_IS_DEVICE_ADSL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_ADSL))
#define NM_IS_DEVICE_ADSL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_ADSL))
#define NM_DEVICE_ADSL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_ADSL, NMDeviceAdslClass))

typedef struct {
	NMDevice parent;
} NMDeviceAdsl;

typedef struct {
	NMDeviceClass parent;

} NMDeviceAdslClass;

GType nm_device_adsl_get_type (void);

NMDevice *nm_device_adsl_new (const char *udi,
                              const char *iface,
                              const char *driver);

G_END_DECLS

#endif	/* NM_DEVICE_ADSL_H */
