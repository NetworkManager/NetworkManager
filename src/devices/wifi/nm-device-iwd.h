// SPDX-License-Identifier: GPL-2.0+
/*
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

NMDevice *nm_device_iwd_new (const char *iface);

void nm_device_iwd_set_dbus_object (NMDeviceIwd *device, GDBusObject *object);

gboolean nm_device_iwd_agent_query (NMDeviceIwd *device,
                                    GDBusMethodInvocation *invocation);

const CList *_nm_device_iwd_get_aps (NMDeviceIwd *self);

void _nm_device_iwd_request_scan (NMDeviceIwd *self,
                                  GVariant *options,
                                  GDBusMethodInvocation *invocation);

#endif /* __NETWORKMANAGER_DEVICE_IWD_H__ */
