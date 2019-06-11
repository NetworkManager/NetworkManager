/* NetworkManager -- Network link manager
 *
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
 * (C) Copyright 2016 Red Hat, Inc.
 */

#ifndef __NM_COMMON_MACROS_H__
#define __NM_COMMON_MACROS_H__

/*****************************************************************************/

#define NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK     "org.freedesktop.NetworkManager.enable-disable-network"
#define NM_AUTH_PERMISSION_SLEEP_WAKE                 "org.freedesktop.NetworkManager.sleep-wake"
#define NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI        "org.freedesktop.NetworkManager.enable-disable-wifi"
#define NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN        "org.freedesktop.NetworkManager.enable-disable-wwan"
#define NM_AUTH_PERMISSION_ENABLE_DISABLE_WIMAX       "org.freedesktop.NetworkManager.enable-disable-wimax"
#define NM_AUTH_PERMISSION_NETWORK_CONTROL            "org.freedesktop.NetworkManager.network-control"
#define NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED       "org.freedesktop.NetworkManager.wifi.share.protected"
#define NM_AUTH_PERMISSION_WIFI_SHARE_OPEN            "org.freedesktop.NetworkManager.wifi.share.open"
#define NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM     "org.freedesktop.NetworkManager.settings.modify.system"
#define NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN        "org.freedesktop.NetworkManager.settings.modify.own"
#define NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME   "org.freedesktop.NetworkManager.settings.modify.hostname"
#define NM_AUTH_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS "org.freedesktop.NetworkManager.settings.modify.global-dns"
#define NM_AUTH_PERMISSION_RELOAD                     "org.freedesktop.NetworkManager.reload"
#define NM_AUTH_PERMISSION_CHECKPOINT_ROLLBACK        "org.freedesktop.NetworkManager.checkpoint-rollback"
#define NM_AUTH_PERMISSION_ENABLE_DISABLE_STATISTICS  "org.freedesktop.NetworkManager.enable-disable-statistics"
#define NM_AUTH_PERMISSION_ENABLE_DISABLE_CONNECTIVITY_CHECK "org.freedesktop.NetworkManager.enable-disable-connectivity-check"
#define NM_AUTH_PERMISSION_WIFI_SCAN                  "org.freedesktop.NetworkManager.wifi.scan"

#define NM_CLONED_MAC_PRESERVE                          "preserve"
#define NM_CLONED_MAC_PERMANENT                         "permanent"
#define NM_CLONED_MAC_RANDOM                            "random"
#define NM_CLONED_MAC_STABLE                            "stable"

static inline gboolean
NM_CLONED_MAC_IS_SPECIAL (const char *str)
{
	return NM_IN_STRSET (str,
	                     NM_CLONED_MAC_PRESERVE,
	                     NM_CLONED_MAC_PERMANENT,
	                     NM_CLONED_MAC_RANDOM,
	                     NM_CLONED_MAC_STABLE);
}

/*****************************************************************************/

#endif /* __NM_COMMON_MACROS_H__ */
