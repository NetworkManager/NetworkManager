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
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2012 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_WIFI_H__
#define __NM_DEVICE_WIFI_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_WIFI            (nm_device_wifi_get_type ())
#define NM_DEVICE_WIFI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_WIFI, NMDeviceWifi))
#define NM_DEVICE_WIFI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_WIFI, NMDeviceWifiClass))
#define NM_IS_DEVICE_WIFI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_WIFI))
#define NM_IS_DEVICE_WIFI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_WIFI))
#define NM_DEVICE_WIFI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_WIFI, NMDeviceWifiClass))

#define NM_DEVICE_WIFI_HW_ADDRESS          "hw-address"
#define NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS "perm-hw-address"
#define NM_DEVICE_WIFI_MODE                "mode"
#define NM_DEVICE_WIFI_BITRATE             "bitrate"
#define NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT "active-access-point"
#define NM_DEVICE_WIFI_CAPABILITIES        "wireless-capabilities"
#define NM_DEVICE_WIFI_ACCESS_POINTS       "access-points"
#define NM_DEVICE_WIFI_LAST_SCAN           "last-scan"

/**
 * NMDeviceWifi:
 */
struct _NMDeviceWifi {
	NMDevice parent;
};

typedef struct {
	NMDeviceClass parent;

	/* Signals */
	void (*access_point_added) (NMDeviceWifi *device, NMAccessPoint *ap);
	void (*access_point_removed) (NMDeviceWifi *device, NMAccessPoint *ap);

	/*< private >*/
	gpointer padding[4];
} NMDeviceWifiClass;

GType nm_device_wifi_get_type (void);

const char *             nm_device_wifi_get_hw_address           (NMDeviceWifi *device);
const char *             nm_device_wifi_get_permanent_hw_address (NMDeviceWifi *device);
NM80211Mode              nm_device_wifi_get_mode                 (NMDeviceWifi *device);
guint32                  nm_device_wifi_get_bitrate              (NMDeviceWifi *device);
NMDeviceWifiCapabilities nm_device_wifi_get_capabilities         (NMDeviceWifi *device);
NMAccessPoint *          nm_device_wifi_get_active_access_point  (NMDeviceWifi *device);

NMAccessPoint *          nm_device_wifi_get_access_point_by_path (NMDeviceWifi *device,
                                                                  const char *path);

const GPtrArray *        nm_device_wifi_get_access_points        (NMDeviceWifi *device);

NM_AVAILABLE_IN_1_12
gint64                   nm_device_wifi_get_last_scan            (NMDeviceWifi *device);

gboolean                 nm_device_wifi_request_scan             (NMDeviceWifi *device,
                                                                  GCancellable *cancellable,
                                                                  GError **error);
NM_AVAILABLE_IN_1_2
gboolean                 nm_device_wifi_request_scan_options     (NMDeviceWifi *device,
                                                                  GVariant *options,
                                                                  GCancellable *cancellable,
                                                                  GError **error);
void                     nm_device_wifi_request_scan_async       (NMDeviceWifi *device,
                                                                  GCancellable *cancellable,
                                                                  GAsyncReadyCallback callback,
                                                                  gpointer user_data);
NM_AVAILABLE_IN_1_2
void                     nm_device_wifi_request_scan_options_async (NMDeviceWifi *device,
                                                                    GVariant *options,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);
gboolean                 nm_device_wifi_request_scan_finish      (NMDeviceWifi *device,
                                                                  GAsyncResult *result,
                                                                  GError **error);

G_END_DECLS

#endif /* __NM_DEVICE_WIFI_H__ */
