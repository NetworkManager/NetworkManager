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

#include <gmodule.h>

#include "nm-device-factory.h"
#include "nm-device-wimax.h"

G_MODULE_EXPORT GObject *
nm_device_factory_create_device (GUdevDevice *device,
                                 const char *devpath,
                                 const char *ifname,
                                 const char *driver,
                                 GError **error)
{
	GObject *dev;

	/* FIXME: check 'DEVTYPE' instead; but since we only support Intel
	 * WiMAX devices for now this is appropriate.
	 */
	if (g_strcmp0 (driver, "i2400m_usb") != 0)
		return NULL;  /* unsupported */

	dev = (GObject *) nm_device_wimax_new (devpath, ifname, driver);
	if (dev == NULL)
		g_set_error_literal (error, 0, 0, "Failed to create WiMAX device.");
	return dev;
}

G_MODULE_EXPORT guint32
nm_device_factory_get_priority (void)
{
	return 0;
}

G_MODULE_EXPORT NMDeviceType
nm_device_factory_get_type (void)
{
	return NM_DEVICE_TYPE_WIMAX;
}

