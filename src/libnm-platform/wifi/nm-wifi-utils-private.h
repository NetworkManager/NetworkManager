/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2011 - 2018 Red Hat, Inc.
 */

#ifndef __WIFI_UTILS_PRIVATE_H__
#define __WIFI_UTILS_PRIVATE_H__

#include "nm-wifi-utils.h"
#include "libnm-platform/nm-platform.h"

typedef struct {
    GObjectClass parent;

    _NM80211Mode (*get_mode)(NMWifiUtils *data);

    gboolean (*set_mode)(NMWifiUtils *data, const _NM80211Mode mode);

    /* Set power saving mode on an interface */
    gboolean (*set_powersave)(NMWifiUtils *data, guint32 powersave);

    /* Get WakeOnWLAN configuration on an interface */
    _NMSettingWirelessWakeOnWLan (*get_wake_on_wlan)(NMWifiUtils *data);

    /* Set WakeOnWLAN mode on an interface */
    gboolean (*set_wake_on_wlan)(NMWifiUtils *data, _NMSettingWirelessWakeOnWLan wowl);

    /* Return current frequency in MHz (really associated BSS frequency) */
    guint32 (*get_freq)(NMWifiUtils *data);

    /* Return first supported frequency in the zero-terminated list. @ap
     * indicates that the frequency must be suited for AP mode. */
    guint32 (*find_freq)(NMWifiUtils *data, const guint32 *freqs, gboolean ap);

    /*
     * @out_bssid: must be NULL or an ETH_ALEN-byte buffer
     * @out_quality: receives signal strength percentage 0 - 100% for the current BSSID, if not NULL
     * @out_rate: receives current bitrate in Kbps if not NULL
     *
     * Returns %TRUE on succcess, %FALSE on errors or if not associated.
     */
    gboolean (*get_station)(NMWifiUtils *data,
                            NMEtherAddr *out_bssid,
                            int         *out_quality,
                            guint32     *out_rate);

    /* OLPC Mesh-only functions */

    guint32 (*get_mesh_channel)(NMWifiUtils *data);

    /* channel == 0 means "auto channel" */
    gboolean (*set_mesh_channel)(NMWifiUtils *data, guint32 channel);

    /* ssid == NULL means "auto SSID" */
    gboolean (*set_mesh_ssid)(NMWifiUtils *data, const guint8 *ssid, gsize len);

    gboolean (*indicate_addressing_running)(NMWifiUtils *data, gboolean running);

    gboolean (*get_csme_conn_info)(NMWifiUtils *data, NMPlatformCsmeConnInfo *out_conn_info);

    gboolean (*get_device_from_csme)(NMWifiUtils *data);
} NMWifiUtilsClass;

struct NMWifiUtils {
    GObject parent;

    int                       ifindex;
    _NMDeviceWifiCapabilities caps;
};

#endif /* __WIFI_UTILS_PRIVATE_H__ */
