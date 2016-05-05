/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2011 - 2012 Red Hat, Inc.
 * Copyright 2008 Novell, Inc.
 */

#ifndef __NM_DEVICE_MODEM_H__
#define __NM_DEVICE_MODEM_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <nm-device.h>

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_MODEM            (nm_device_modem_get_type ())
#define NM_DEVICE_MODEM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_MODEM, NMDeviceModem))
#define NM_DEVICE_MODEM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_MODEM, NMDeviceModemClass))
#define NM_IS_DEVICE_MODEM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_MODEM))
#define NM_IS_DEVICE_MODEM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_MODEM))
#define NM_DEVICE_MODEM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_MODEM, NMDeviceModemClass))

#define NM_DEVICE_MODEM_MODEM_CAPABILITIES   "modem-capabilities"
#define NM_DEVICE_MODEM_CURRENT_CAPABILITIES "current-capabilities"

/**
 * NMDeviceModem:
 */
struct _NMDeviceModem {
	NMDevice parent;
};

typedef struct {
	NMDeviceClass parent;

	/*< private >*/
	gpointer padding[4];
} NMDeviceModemClass;

GType nm_device_modem_get_type (void);

NMDeviceModemCapabilities nm_device_modem_get_modem_capabilities (NMDeviceModem *self);
NMDeviceModemCapabilities nm_device_modem_get_current_capabilities (NMDeviceModem *self);

G_END_DECLS

#endif /* __NM_DEVICE_MODEM_H__ */
