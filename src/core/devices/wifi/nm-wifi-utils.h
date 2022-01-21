/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 Red Hat, Inc.
 */

#ifndef __NM_WIFI_UTILS_H__
#define __NM_WIFI_UTILS_H__

#include "nm-dbus-interface.h"
#include "nm-connection.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"
#include "libnm-base/nm-base.h"

typedef enum {
    NM_IWD_NETWORK_SECURITY_OPEN,
    NM_IWD_NETWORK_SECURITY_WEP,
    NM_IWD_NETWORK_SECURITY_PSK,
    NM_IWD_NETWORK_SECURITY_8021X,
} NMIwdNetworkSecurity;

typedef struct {
    bool     source;
    bool     sink;
    uint16_t port;
    bool     has_audio;
    bool     has_uibc;
    bool     has_cp;
} NMIwdWfdInfo;

gboolean nm_wifi_utils_complete_connection(GBytes       *ssid,
                                           const char   *bssid,
                                           _NM80211Mode  mode,
                                           guint32       ap_freq,
                                           guint32       flags,
                                           guint32       wpa_flags,
                                           guint32       rsn_flags,
                                           NMConnection *connection,
                                           gboolean      lock_bssid,
                                           GError      **error);

gboolean nm_wifi_utils_is_manf_default_ssid(GBytes *ssid);

gboolean nm_wifi_connection_get_iwd_ssid_and_security(NMConnection         *connection,
                                                      char                **ssid,
                                                      NMIwdNetworkSecurity *security);
char    *nm_wifi_utils_get_iwd_config_filename(const char          *ssid,
                                               gssize               ssid_len,
                                               NMIwdNetworkSecurity security);

GKeyFile *
nm_wifi_utils_connection_to_iwd_config(NMConnection *conn, char **out_filename, GError **error);

bool    nm_wifi_utils_parse_wfd_ies(GBytes *ies, NMIwdWfdInfo *out_wfd);
GBytes *nm_wifi_utils_build_wfd_ies(const NMIwdWfdInfo *wfd);
bool    nm_wifi_utils_wfd_info_eq(const NMIwdWfdInfo *a, const NMIwdWfdInfo *b);

#endif /* __NM_WIFI_UTILS_H__ */
