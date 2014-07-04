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

#ifndef NM_DEVICE_WIFI_H
#define NM_DEVICE_WIFI_H

#include "nm-device.h"
#include "nm-access-point.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_WIFI            (nm_device_wifi_get_type ())
#define NM_DEVICE_WIFI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_WIFI, NMDeviceWifi))
#define NM_DEVICE_WIFI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_WIFI, NMDeviceWifiClass))
#define NM_IS_DEVICE_WIFI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_WIFI))
#define NM_IS_DEVICE_WIFI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_WIFI))
#define NM_DEVICE_WIFI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_WIFI, NMDeviceWifiClass))

/**
 * NMDeviceWifiError:
 * @NM_DEVICE_WIFI_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_DEVICE_WIFI_ERROR_NOT_WIFI_CONNECTION: the connection was not of Wi-Fi type
 * @NM_DEVICE_WIFI_ERROR_INVALID_WIFI_CONNECTION: the Wi-Fi connection was invalid
 * @NM_DEVICE_WIFI_ERROR_INVALID_DEVICE_MAC: the device's MAC was invalid
 * @NM_DEVICE_WIFI_ERROR_MAC_MISMATCH: the MACs of the connection and the device mismatched
 * @NM_DEVICE_WIFI_ERROR_MISSING_DEVICE_WPA_CAPS: the device missed WPA capabilities
 * required by the connection
 * @NM_DEVICE_WIFI_ERROR_MISSING_DEVICE_RSN_CAPS: the device missed RSN capabilities
 * required by the connection
 */
typedef enum {
	NM_DEVICE_WIFI_ERROR_UNKNOWN = 0,             /*< nick=UnknownError >*/
	NM_DEVICE_WIFI_ERROR_NOT_WIFI_CONNECTION,     /*< nick=NotWifiConnection >*/
	NM_DEVICE_WIFI_ERROR_INVALID_WIFI_CONNECTION, /*< nick=InvalidWifiConnection >*/
	NM_DEVICE_WIFI_ERROR_INVALID_DEVICE_MAC,      /*< nick=InvalidDeviceMac >*/
	NM_DEVICE_WIFI_ERROR_MAC_MISMATCH,            /*< nick=MacMismatch >*/
	NM_DEVICE_WIFI_ERROR_MISSING_DEVICE_WPA_CAPS, /*< nick=MissingDeviceWpaCaps >*/
	NM_DEVICE_WIFI_ERROR_MISSING_DEVICE_RSN_CAPS, /*< nick=MissingDeviceRsnCaps >*/
} NMDeviceWifiError;

#define NM_DEVICE_WIFI_ERROR nm_device_wifi_error_quark ()
GQuark nm_device_wifi_error_quark (void);

#define NM_DEVICE_WIFI_HW_ADDRESS          "hw-address"
#define NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS "perm-hw-address"
#define NM_DEVICE_WIFI_MODE                "mode"
#define NM_DEVICE_WIFI_BITRATE             "bitrate"
#define NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT "active-access-point"
#define NM_DEVICE_WIFI_CAPABILITIES        "wireless-capabilities"
#define NM_DEVICE_WIFI_ACCESS_POINTS       "access-points"

typedef struct {
	NMDevice parent;
} NMDeviceWifi;

typedef struct {
	NMDeviceClass parent;

	/* Signals */
	void (*access_point_added) (NMDeviceWifi *device, NMAccessPoint *ap);
	void (*access_point_removed) (NMDeviceWifi *device, NMAccessPoint *ap);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMDeviceWifiClass;

GType nm_device_wifi_get_type (void);

GObject *nm_device_wifi_new (DBusGConnection *connection, const char *path);

const char *             nm_device_wifi_get_hw_address           (NMDeviceWifi *device);
const char *             nm_device_wifi_get_permanent_hw_address (NMDeviceWifi *device);
NM80211Mode              nm_device_wifi_get_mode                 (NMDeviceWifi *device);
guint32                  nm_device_wifi_get_bitrate              (NMDeviceWifi *device);
NMDeviceWifiCapabilities nm_device_wifi_get_capabilities         (NMDeviceWifi *device);
NMAccessPoint *          nm_device_wifi_get_active_access_point  (NMDeviceWifi *device);

NMAccessPoint *          nm_device_wifi_get_access_point_by_path (NMDeviceWifi *device,
                                                                  const char *path);

const GPtrArray *        nm_device_wifi_get_access_points        (NMDeviceWifi *device);

typedef void             (*NMDeviceWifiRequestScanFn)            (NMDeviceWifi *device,
                                                                  GError *error,
                                                                  gpointer user_data);
void                     nm_device_wifi_request_scan_simple      (NMDeviceWifi *device,
                                                                  NMDeviceWifiRequestScanFn callback,
                                                                  gpointer user_data);

G_END_DECLS

#endif /* NM_DEVICE_WIFI_H */
