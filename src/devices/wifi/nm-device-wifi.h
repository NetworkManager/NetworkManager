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
 * Copyright (C) 2005 - 2016 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_WIFI_H__
#define __NETWORKMANAGER_DEVICE_WIFI_H__

#include "devices/nm-device.h"
#include "nm-wifi-ap.h"

#define NM_TYPE_DEVICE_WIFI             (nm_device_wifi_get_type ())
#define NM_DEVICE_WIFI(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_WIFI, NMDeviceWifi))
#define NM_DEVICE_WIFI_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_WIFI, NMDeviceWifiClass))
#define NM_IS_DEVICE_WIFI(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_WIFI))
#define NM_IS_DEVICE_WIFI_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_WIFI))
#define NM_DEVICE_WIFI_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_WIFI, NMDeviceWifiClass))

#define NM_DEVICE_WIFI_MODE                "mode"
#define NM_DEVICE_WIFI_BITRATE             "bitrate"
#define NM_DEVICE_WIFI_ACCESS_POINTS       "access-points"
#define NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT "active-access-point"
#define NM_DEVICE_WIFI_CAPABILITIES        "wireless-capabilities"
#define NM_DEVICE_WIFI_SCANNING            "scanning"

/* signals */
#define NM_DEVICE_WIFI_ACCESS_POINT_ADDED  "access-point-added"
#define NM_DEVICE_WIFI_ACCESS_POINT_REMOVED "access-point-removed"

/* internal signals */
#define NM_DEVICE_WIFI_SCANNING_PROHIBITED    "scanning-prohibited"

typedef struct _NMDeviceWifi NMDeviceWifi;
typedef struct _NMDeviceWifiClass NMDeviceWifiClass;

GType nm_device_wifi_get_type (void);

NMDevice * nm_device_wifi_new (const char *iface, NMDeviceWifiCapabilities capabilities);

#endif /* __NETWORKMANAGER_DEVICE_WIFI_H__ */
