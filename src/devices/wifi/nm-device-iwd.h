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
 * Copyright (C) 2017 Intel Corporation
 */

#ifndef __NETWORKMANAGER_DEVICE_IWD_H__
#define __NETWORKMANAGER_DEVICE_IWD_H__

#include "devices/nm-device.h"
#include "nm-wifi-ap.h"
#include "nm-device-wifi.h"

#define NM_TYPE_DEVICE_IWD              (nm_device_iwd_get_type ())
#define NM_DEVICE_IWD(obj)              (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_IWD, NMDeviceIwd))
#define NM_DEVICE_IWD_CLASS(klass)      (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_IWD, NMDeviceIwdClass))
#define NM_IS_DEVICE_IWD(obj)           (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_IWD))
#define NM_IS_DEVICE_IWD_CLASS(klass)   (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_IWD))
#define NM_DEVICE_IWD_GET_CLASS(obj)    (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_IWD, NMDeviceIwdClass))

#define NM_DEVICE_IWD_MODE                NM_DEVICE_WIFI_MODE
#define NM_DEVICE_IWD_BITRATE             NM_DEVICE_WIFI_BITRATE
#define NM_DEVICE_IWD_ACCESS_POINTS       NM_DEVICE_WIFI_ACCESS_POINTS
#define NM_DEVICE_IWD_ACTIVE_ACCESS_POINT NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT
#define NM_DEVICE_IWD_CAPABILITIES        NM_DEVICE_WIFI_CAPABILITIES
#define NM_DEVICE_IWD_SCANNING            NM_DEVICE_WIFI_SCANNING
#define NM_DEVICE_IWD_LAST_SCAN           NM_DEVICE_WIFI_LAST_SCAN

#define NM_DEVICE_IWD_SCANNING_PROHIBITED  NM_DEVICE_WIFI_SCANNING_PROHIBITED

typedef struct _NMDeviceIwd NMDeviceIwd;
typedef struct _NMDeviceIwdClass NMDeviceIwdClass;

GType nm_device_iwd_get_type (void);

NMDevice *nm_device_iwd_new (const char *iface, NMDeviceWifiCapabilities capabilities);

void nm_device_iwd_set_dbus_object (NMDeviceIwd *device, GDBusObject *object);

gboolean nm_device_iwd_agent_query (NMDeviceIwd *device,
                                    GDBusMethodInvocation *invocation);

const CList *_nm_device_iwd_get_aps (NMDeviceIwd *self);

void _nm_device_iwd_request_scan (NMDeviceIwd *self,
                                  GVariant *options,
                                  GDBusMethodInvocation *invocation);

#endif /* __NETWORKMANAGER_DEVICE_IWD_H__ */
