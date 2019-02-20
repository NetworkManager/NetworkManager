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
 * (C) Copyright 2011 Red Hat, Inc.
 */

#ifndef __NM_WIFI_UTILS_H__
#define __NM_WIFI_UTILS_H__

#include "nm-dbus-interface.h"
#include "nm-connection.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"

typedef enum {
	NM_IWD_NETWORK_SECURITY_NONE,
	NM_IWD_NETWORK_SECURITY_WEP,
	NM_IWD_NETWORK_SECURITY_PSK,
	NM_IWD_NETWORK_SECURITY_8021X,
} NMIwdNetworkSecurity;

gboolean nm_wifi_utils_complete_connection (GBytes *ssid,
                                            const char *bssid,
                                            NM80211Mode mode,
                                            guint32 ap_freq,
                                            guint32 flags,
                                            guint32 wpa_flags,
                                            guint32 rsn_flags,
                                            NMConnection *connection,
                                            gboolean lock_bssid,
                                            GError **error);

guint32 nm_wifi_utils_level_to_quality (int val);

gboolean nm_wifi_utils_is_manf_default_ssid (GBytes *ssid);

NMIwdNetworkSecurity nm_wifi_connection_get_iwd_security (NMConnection *connection,
                                                          gboolean *mapped);

#endif  /* __NM_WIFI_UTILS_H__ */
