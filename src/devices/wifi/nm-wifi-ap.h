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
 * Copyright (C) 2004 - 2017 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NM_WIFI_AP_H__
#define __NM_WIFI_AP_H__

#include "nm-exported-object.h"
#include "nm-dbus-interface.h"
#include "nm-connection.h"

#define NM_TYPE_WIFI_AP            (nm_wifi_ap_get_type ())
#define NM_WIFI_AP(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIFI_AP, NMWifiAP))
#define NM_WIFI_AP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_WIFI_AP, NMWifiAPClass))
#define NM_IS_WIFI_AP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WIFI_AP))
#define NM_IS_WIFI_AP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_WIFI_AP))
#define NM_WIFI_AP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_WIFI_AP, NMWifiAPClass))

#define NM_WIFI_AP_FLAGS                "flags"
#define NM_WIFI_AP_WPA_FLAGS            "wpa-flags"
#define NM_WIFI_AP_RSN_FLAGS            "rsn-flags"
#define NM_WIFI_AP_SSID                 "ssid"
#define NM_WIFI_AP_FREQUENCY            "frequency"
#define NM_WIFI_AP_HW_ADDRESS           "hw-address"
#define NM_WIFI_AP_MODE                 "mode"
#define NM_WIFI_AP_MAX_BITRATE          "max-bitrate"
#define NM_WIFI_AP_STRENGTH             "strength"
#define NM_WIFI_AP_LAST_SEEN            "last-seen"

typedef struct _NMWifiAP NMWifiAP;
typedef struct _NMWifiAPClass NMWifiAPClass;

GType nm_wifi_ap_get_type (void);

NMWifiAP *   nm_wifi_ap_new_from_properties      (const char *supplicant_path,
                                                  GVariant *properties);
NMWifiAP *   nm_wifi_ap_new_fake_from_connection (NMConnection *connection);

gboolean          nm_wifi_ap_update_from_properties   (NMWifiAP *ap,
                                                       const char *supplicant_path,
                                                       GVariant *properties);

gboolean          nm_wifi_ap_check_compatible         (NMWifiAP *self,
                                                       NMConnection *connection);

gboolean          nm_wifi_ap_complete_connection      (NMWifiAP *self,
                                                       NMConnection *connection,
                                                       gboolean lock_bssid,
                                                       GError **error);

const char *      nm_wifi_ap_get_supplicant_path      (NMWifiAP *ap);
guint64           nm_wifi_ap_get_id                   (NMWifiAP *ap);
const GByteArray *nm_wifi_ap_get_ssid                 (const NMWifiAP *ap);
gboolean          nm_wifi_ap_set_ssid                 (NMWifiAP *ap,
                                                       const guint8 *ssid,
                                                       gsize len);
const char *      nm_wifi_ap_get_address              (const NMWifiAP *ap);
gboolean          nm_wifi_ap_set_address              (NMWifiAP *ap,
                                                       const char *addr);
NM80211Mode       nm_wifi_ap_get_mode                 (NMWifiAP *ap);
gboolean          nm_wifi_ap_is_hotspot               (NMWifiAP *ap);
gint8             nm_wifi_ap_get_strength             (NMWifiAP *ap);
gboolean          nm_wifi_ap_set_strength             (NMWifiAP *ap,
                                                       gint8 strength);
guint32           nm_wifi_ap_get_freq                 (NMWifiAP *ap);
gboolean          nm_wifi_ap_set_freq                 (NMWifiAP *ap,
                                                       guint32 freq);
guint32           nm_wifi_ap_get_max_bitrate          (NMWifiAP *ap);
gboolean          nm_wifi_ap_set_max_bitrate          (NMWifiAP *ap,
                                                       guint32 bitrate);
gboolean          nm_wifi_ap_get_fake                 (const NMWifiAP *ap);
gboolean          nm_wifi_ap_set_fake                 (NMWifiAP *ap,
                                                       gboolean fake);
NM80211ApFlags    nm_wifi_ap_get_flags                (const NMWifiAP *self);

const char       *nm_wifi_ap_to_string                (const NMWifiAP *self,
                                                       char *str_buf,
                                                       gulong buf_len,
                                                       gint32 now_s);

#endif /* __NM_WIFI_AP_H__ */
