// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2005 - 2016 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_WIFI_H__
#define __NETWORKMANAGER_DEVICE_WIFI_H__

#include "devices/nm-device.h"

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
#define NM_DEVICE_WIFI_LAST_SCAN           "last-scan"

#define NM_DEVICE_WIFI_SCANNING_PROHIBITED    "scanning-prohibited"
#define NM_DEVICE_WIFI_P2P_DEVICE_CREATED     "p2p-device-created"

typedef struct _NMDeviceWifi NMDeviceWifi;
typedef struct _NMDeviceWifiClass NMDeviceWifiClass;

GType nm_device_wifi_get_type (void);

NMDevice * nm_device_wifi_new (const char *iface, NMDeviceWifiCapabilities capabilities);

const CList *_nm_device_wifi_get_aps (NMDeviceWifi *self);

void _nm_device_wifi_request_scan (NMDeviceWifi *self,
                                   GVariant *options,
                                   GDBusMethodInvocation *invocation);

GPtrArray *nmtst_ssids_options_to_ptrarray (GVariant *value, GError **error);

gboolean nm_device_wifi_get_scanning (NMDeviceWifi *self);

#endif /* __NETWORKMANAGER_DEVICE_WIFI_H__ */
