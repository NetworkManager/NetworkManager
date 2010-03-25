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

#include <glib.h>

#include "nm-device-modem.h"
#include "nm-device-interface.h"
#include "nm-modem.h"

static void device_interface_init (NMDeviceInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (NMDeviceModem, nm_device_modem, NM_TYPE_DEVICE, G_TYPE_FLAG_ABSTRACT,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_DEVICE_INTERFACE, device_interface_init))

/*****************************************************************************/

static gboolean
real_get_enabled (NMDeviceInterface *device)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (device);
	NMModem *modem;

	g_assert (NM_DEVICE_MODEM_GET_CLASS (self)->get_modem);
	modem = NM_DEVICE_MODEM_GET_CLASS (self)->get_modem (self);

	return modem ? nm_modem_get_mm_enabled (modem) : TRUE;
}

/*****************************************************************************/

static void
device_interface_init (NMDeviceInterface *iface_class)
{
    iface_class->get_enabled = real_get_enabled;
}

static void
nm_device_modem_init (NMDeviceModem *self)
{
}

static void
nm_device_modem_class_init (NMDeviceModemClass *config_class)
{
}

