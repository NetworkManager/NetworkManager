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
 * Copyright (C) 2011 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_MODEM_H__
#define __NETWORKMANAGER_DEVICE_MODEM_H__

#include "nm-device.h"
#include "nm-modem.h"

#define NM_TYPE_DEVICE_MODEM            (nm_device_modem_get_type ())
#define NM_DEVICE_MODEM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_MODEM, NMDeviceModem))
#define NM_DEVICE_MODEM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_MODEM, NMDeviceModemClass))
#define NM_IS_DEVICE_MODEM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_MODEM))
#define NM_IS_DEVICE_MODEM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_MODEM))
#define NM_DEVICE_MODEM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_MODEM, NMDeviceModemClass))

#define NM_DEVICE_MODEM_MODEM "modem"
#define NM_DEVICE_MODEM_CAPABILITIES "modem-capabilities"
#define NM_DEVICE_MODEM_CURRENT_CAPABILITIES "current-capabilities"

typedef struct _NMDeviceModem NMDeviceModem;
typedef struct _NMDeviceModemClass NMDeviceModemClass;

GType nm_device_modem_get_type (void);

NMDevice *nm_device_modem_new (NMModem *modem);

#endif /* __NETWORKMANAGER_DEVICE_MODEM_H__ */
