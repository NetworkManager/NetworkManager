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
 * (C) Copyright 2011 Red Hat, Inc.
 */

#ifndef NM_WIFI_AP_UTILS_H
#define NM_WIFI_AP_UTILS_H

#include <net/ethernet.h>

#include <NetworkManager.h>
#include <nm-connection.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>
#include <nm-setting-8021x.h>

gboolean nm_ap_utils_complete_connection (const GByteArray *ssid,
                                          const guint8 bssid[ETH_ALEN],
                                          NM80211Mode mode,
                                          guint32 flags,
                                          guint32 wpa_flags,
                                          guint32 rsn_flags,
                                          NMConnection *connection,
                                          gboolean lock_bssid,
                                          GError **error);

guint32 nm_ap_utils_level_to_quality (gint val);

#endif  /* NM_WIFI_AP_UTILS_H */

