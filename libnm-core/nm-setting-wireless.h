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
 * Copyright 2007 - 2014 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_WIRELESS_H__
#define __NM_SETTING_WIRELESS_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <nm-setting.h>
#include <nm-setting-wireless-security.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_WIRELESS            (nm_setting_wireless_get_type ())
#define NM_SETTING_WIRELESS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_WIRELESS, NMSettingWireless))
#define NM_SETTING_WIRELESS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_WIRELESS, NMSettingWirelessClass))
#define NM_IS_SETTING_WIRELESS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_WIRELESS))
#define NM_IS_SETTING_WIRELESS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_WIRELESS))
#define NM_SETTING_WIRELESS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_WIRELESS, NMSettingWirelessClass))

#define NM_SETTING_WIRELESS_SETTING_NAME "802-11-wireless"

#define NM_SETTING_WIRELESS_SSID        "ssid"
#define NM_SETTING_WIRELESS_MODE        "mode"
#define NM_SETTING_WIRELESS_BAND        "band"
#define NM_SETTING_WIRELESS_CHANNEL     "channel"
#define NM_SETTING_WIRELESS_BSSID       "bssid"
#define NM_SETTING_WIRELESS_RATE        "rate"
#define NM_SETTING_WIRELESS_TX_POWER    "tx-power"
#define NM_SETTING_WIRELESS_MAC_ADDRESS "mac-address"
#define NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS "cloned-mac-address"
#define NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST "mac-address-blacklist"
#define NM_SETTING_WIRELESS_MTU         "mtu"
#define NM_SETTING_WIRELESS_SEEN_BSSIDS "seen-bssids"
#define NM_SETTING_WIRELESS_HIDDEN      "hidden"
#define NM_SETTING_WIRELESS_POWERSAVE   "powersave"

/**
 * NM_SETTING_WIRELESS_MODE_ADHOC:
 *
 * Indicates Ad-Hoc mode where no access point is expected to be present.
 */
#define NM_SETTING_WIRELESS_MODE_ADHOC  "adhoc"

/**
 * NM_SETTING_WIRELESS_MODE_AP:
 *
 * Indicates AP/master mode where the wireless device is started as an access
 * point/hotspot.
 */
#define NM_SETTING_WIRELESS_MODE_AP     "ap"

/**
 * NM_SETTING_WIRELESS_MODE_INFRA:
 *
 * Indicates infrastructure mode where an access point is expected to be present
 * for this connection.
 */
#define NM_SETTING_WIRELESS_MODE_INFRA  "infrastructure"

struct _NMSettingWireless {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingWirelessClass;

GType nm_setting_wireless_get_type (void);

NMSetting *nm_setting_wireless_new (void);

GBytes           *nm_setting_wireless_get_ssid               (NMSettingWireless *setting);
const char       *nm_setting_wireless_get_mode               (NMSettingWireless *setting);
const char       *nm_setting_wireless_get_band               (NMSettingWireless *setting);
guint32           nm_setting_wireless_get_channel            (NMSettingWireless *setting);
const char       *nm_setting_wireless_get_bssid              (NMSettingWireless *setting);
guint32           nm_setting_wireless_get_rate               (NMSettingWireless *setting);
guint32           nm_setting_wireless_get_tx_power           (NMSettingWireless *setting);
const char       *nm_setting_wireless_get_mac_address        (NMSettingWireless *setting);
const char       *nm_setting_wireless_get_cloned_mac_address (NMSettingWireless *setting);

const char * const *nm_setting_wireless_get_mac_address_blacklist   (NMSettingWireless *setting);
guint32           nm_setting_wireless_get_num_mac_blacklist_items (NMSettingWireless *setting);
const char *      nm_setting_wireless_get_mac_blacklist_item      (NMSettingWireless *setting,
                                                                   guint32 idx);
gboolean          nm_setting_wireless_add_mac_blacklist_item      (NMSettingWireless *setting,
                                                                   const char *mac);
void              nm_setting_wireless_remove_mac_blacklist_item   (NMSettingWireless *setting,
                                                                   guint32 idx);
gboolean          nm_setting_wireless_remove_mac_blacklist_item_by_value (NMSettingWireless *setting,
                                                                          const char *mac);
void              nm_setting_wireless_clear_mac_blacklist_items   (NMSettingWireless *setting);

guint32           nm_setting_wireless_get_mtu                (NMSettingWireless *setting);
gboolean          nm_setting_wireless_get_hidden             (NMSettingWireless *setting);
NM_AVAILABLE_IN_1_2
guint32           nm_setting_wireless_get_powersave          (NMSettingWireless *setting);

gboolean          nm_setting_wireless_add_seen_bssid         (NMSettingWireless *setting,
                                                              const char *bssid);

guint32           nm_setting_wireless_get_num_seen_bssids    (NMSettingWireless *setting);
const char       *nm_setting_wireless_get_seen_bssid         (NMSettingWireless *setting,
                                                              guint32 i);

gboolean          nm_setting_wireless_ap_security_compatible (NMSettingWireless *s_wireless,
                                                              NMSettingWirelessSecurity *s_wireless_sec,
                                                              NM80211ApFlags ap_flags,
                                                              NM80211ApSecurityFlags ap_wpa,
                                                              NM80211ApSecurityFlags ap_rsn,
                                                              NM80211Mode ap_mode);

G_END_DECLS

#endif /* __NM_SETTING_WIRELESS_H__ */
