/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_WIFI_COMMON_H__
#define __NM_WIFI_COMMON_H__

#include "nm-dbus-utils.h"
#include "nm-wifi-ap.h"

/*****************************************************************************/

void nm_device_wifi_emit_signal_access_point(NMDevice *device,
                                             NMWifiAP *ap,
                                             gboolean  is_added /* or else is_removed */);

extern const NMDBusInterfaceInfoExtended nm_interface_info_device_wireless;
extern const GDBusSignalInfo             nm_signal_info_wireless_access_point_added;
extern const GDBusSignalInfo             nm_signal_info_wireless_access_point_removed;

#endif /* __NM_WIFI_COMMON_H__ */
