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
 * Copyright (C) 2011 - 2014 Red Hat, Inc.
 */

#include "config.h"

#include <gmodule.h>

#include "nm-device-factory.h"
#include "nm-device-wimax.h"
#include "nm-platform.h"
#include "nm-setting-wimax.h"

#define NM_TYPE_WIMAX_FACTORY            (nm_wimax_factory_get_type ())
#define NM_WIMAX_FACTORY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_WIMAX_FACTORY, NMWimaxFactory))

typedef struct {
	GObject parent;
} NMWimaxFactory;

typedef struct {
	GObjectClass parent;
} NMWimaxFactoryClass;

static GType nm_wimax_factory_get_type (void);

static void device_factory_interface_init (NMDeviceFactory *factory_iface);

G_DEFINE_TYPE_EXTENDED (NMWimaxFactory, nm_wimax_factory, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_DEVICE_FACTORY, device_factory_interface_init))

/**************************************************************************/

G_MODULE_EXPORT NMDeviceFactory *
nm_device_factory_create (GError **error)
{
	return (NMDeviceFactory *) g_object_new (NM_TYPE_WIMAX_FACTORY, NULL);
}

/**************************************************************************/

static NMDevice *
new_link (NMDeviceFactory *factory, NMPlatformLink *plink, GError **error)
{
	/* FIXME: check udev 'DEVTYPE' instead; but since we only support Intel
	 * WiMAX devices for now this is appropriate.
	 */
	if (g_strcmp0 (plink->driver, "i2400m_usb") != 0)
		return NULL;  /* unsupported */

	return (NMDevice *) nm_device_wimax_new (plink);
}

NM_DEVICE_FACTORY_DECLARE_TYPES (
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_WIMAX)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_WIMAX_SETTING_NAME)
)

static void
device_factory_interface_init (NMDeviceFactory *factory_iface)
{
	factory_iface->new_link = new_link;
	factory_iface->get_supported_types = get_supported_types;
}

static void
nm_wimax_factory_init (NMWimaxFactory *factory)
{
}

static void
nm_wimax_factory_class_init (NMWimaxFactoryClass *wf_class)
{
}

