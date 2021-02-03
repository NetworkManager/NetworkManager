/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2011 - 2018 Red Hat, Inc.
 */

#ifndef __WIFI_UTILS_PRIVATE_H__
#define __WIFI_UTILS_PRIVATE_H__

#include "nm-dbus-interface.h"
#include "nm-wifi-utils.h"

typedef struct {
    GObjectClass parent;

    NM80211Mode (*get_mode)(NMWifiUtils *data);

    gboolean (*set_mode)(NMWifiUtils *data, const NM80211Mode mode);

    /* Set power saving mode on an interface */
    gboolean (*set_powersave)(NMWifiUtils *data, guint32 powersave);

    /* Get WakeOnWLAN configuration on an interface */
    NMSettingWirelessWakeOnWLan (*get_wake_on_wlan)(NMWifiUtils *data);

    /* Set WakeOnWLAN mode on an interface */
    gboolean (*set_wake_on_wlan)(NMWifiUtils *data, NMSettingWirelessWakeOnWLan wowl);

    /* Return current frequency in MHz (really associated BSS frequency) */
    guint32 (*get_freq)(NMWifiUtils *data);

    /* Return first supported frequency in the zero-terminated list */
    guint32 (*find_freq)(NMWifiUtils *data, const guint32 *freqs);

    /*
     * @out_bssid: must be NULL or an ETH_ALEN-byte buffer
     * @out_quality: receives signal strength percentage 0 - 100% for the current BSSID, if not NULL
     * @out_rate: receives current bitrate in Kbps if not NULL
     *
     * Returns %TRUE on succcess, %FALSE on errors or if not associated.
     */
    gboolean (*get_station)(NMWifiUtils *data,
                            NMEtherAddr *out_bssid,
                            int *        out_quality,
                            guint32 *    out_rate);

    /* OLPC Mesh-only functions */

    guint32 (*get_mesh_channel)(NMWifiUtils *data);

    /* channel == 0 means "auto channel" */
    gboolean (*set_mesh_channel)(NMWifiUtils *data, guint32 channel);

    /* ssid == NULL means "auto SSID" */
    gboolean (*set_mesh_ssid)(NMWifiUtils *data, const guint8 *ssid, gsize len);

    gboolean (*indicate_addressing_running)(NMWifiUtils *data, gboolean running);
} NMWifiUtilsClass;

struct NMWifiUtils {
    GObject parent;

    int                      ifindex;
    NMDeviceWifiCapabilities caps;
};

#endif /* __WIFI_UTILS_PRIVATE_H__ */
