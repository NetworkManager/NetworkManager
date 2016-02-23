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

#include "nm-default.h"

#include <gmodule.h>

#include "nm-device-factory.h"
#include "nm-setting-wireless.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-device-wifi.h"
#include "nm-device-olpc-mesh.h"
#include "nm-settings-connection.h"
#include "nm-platform.h"

#define NM_TYPE_WIFI_FACTORY (nm_wifi_factory_get_type ())
#define NM_WIFI_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIFI_FACTORY, NMWifiFactory))

typedef struct {
	GObject parent;
} NMWifiFactory;

typedef struct {
	GObjectClass parent;
} NMWifiFactoryClass;

static GType nm_wifi_factory_get_type (void);

static void device_factory_interface_init (NMDeviceFactoryInterface *factory_iface);

G_DEFINE_TYPE_EXTENDED (NMWifiFactory, nm_wifi_factory, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_DEVICE_FACTORY, device_factory_interface_init))

/**************************************************************************/

G_MODULE_EXPORT NMDeviceFactory *
nm_device_factory_create (GError **error)
{
	return (NMDeviceFactory *) g_object_new (NM_TYPE_WIFI_FACTORY, NULL);
}

/**************************************************************************/

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	NMDeviceWifiCapabilities capabilities;
	NM80211Mode mode;

	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (plink != NULL, NULL);
	g_return_val_if_fail (g_strcmp0 (iface, plink->name) == 0, NULL);
	g_return_val_if_fail (NM_IN_SET (plink->type, NM_LINK_TYPE_WIFI, NM_LINK_TYPE_OLPC_MESH), NULL);

	if (!nm_platform_wifi_get_capabilities (NM_PLATFORM_GET,
	                                        plink->ifindex,
	                                        &capabilities)) {
		nm_log_warn (LOGD_HW | LOGD_WIFI, "(%s) failed to initialize Wi-Fi driver for ifindex %d", iface, plink->ifindex);
		return NULL;
	}

	/* Ignore monitor-mode and other unhandled interface types.
	 * FIXME: keep TYPE_MONITOR devices in UNAVAILABLE state and manage
	 * them if/when they change to a handled type.
	 */
	mode = nm_platform_wifi_get_mode (NM_PLATFORM_GET, plink->ifindex);
	if (mode == NM_802_11_MODE_UNKNOWN) {
		*out_ignore = TRUE;
		return NULL;
	}

	if (plink->type == NM_LINK_TYPE_WIFI)
		return nm_device_wifi_new (iface, capabilities);
	else
		return nm_device_olpc_mesh_new (iface);
}

NM_DEVICE_FACTORY_DECLARE_TYPES (
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_WIFI, NM_LINK_TYPE_OLPC_MESH)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_OLPC_MESH_SETTING_NAME)
)

static void
device_factory_interface_init (NMDeviceFactoryInterface *factory_iface)
{
	factory_iface->create_device = create_device;
	factory_iface->get_supported_types = get_supported_types;
}

static void
nm_wifi_factory_init (NMWifiFactory *self)
{
}

static void
nm_wifi_factory_class_init (NMWifiFactoryClass *wf_class)
{
}

