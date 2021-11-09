/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_WIRELESS_H__
#define __NM_SETTING_WIRELESS_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"
#include "nm-setting-wireless-security.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_WIRELESS (nm_setting_wireless_get_type())
#define NM_SETTING_WIRELESS(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_WIRELESS, NMSettingWireless))
#define NM_SETTING_WIRELESS_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_WIRELESS, NMSettingWirelessClass))
#define NM_IS_SETTING_WIRELESS(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_WIRELESS))
#define NM_IS_SETTING_WIRELESS_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_WIRELESS))
#define NM_SETTING_WIRELESS_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_WIRELESS, NMSettingWirelessClass))

#define NM_SETTING_WIRELESS_SETTING_NAME "802-11-wireless"

/**
 * NMSettingWirelessWakeOnWLan:
 * @NM_SETTING_WIRELESS_WAKE_ON_WLAN_NONE: Wake-on-WLAN disabled
 * @NM_SETTING_WIRELESS_WAKE_ON_WLAN_ANY: Wake on any activity
 * @NM_SETTING_WIRELESS_WAKE_ON_WLAN_DISCONNECT: Wake on disconnect
 * @NM_SETTING_WIRELESS_WAKE_ON_WLAN_MAGIC: Wake on magic packet
 * @NM_SETTING_WIRELESS_WAKE_ON_WLAN_GTK_REKEY_FAILURE: Wake on GTK rekey failure
 * @NM_SETTING_WIRELESS_WAKE_ON_WLAN_EAP_IDENTITY_REQUEST: Wake on EAP identity request
 * @NM_SETTING_WIRELESS_WAKE_ON_WLAN_4WAY_HANDSHAKE: Wake on 4way handshake
 * @NM_SETTING_WIRELESS_WAKE_ON_WLAN_RFKILL_RELEASE: Wake on rfkill release
 * @NM_SETTING_WIRELESS_WAKE_ON_WLAN_ALL: Wake on all events. This does not
 *   include the exclusive flags @NM_SETTING_WIRELESS_WAKE_ON_WLAN_DEFAULT or
 *   @NM_SETTING_WIRELESS_WAKE_ON_WLAN_IGNORE.
 * @NM_SETTING_WIRELESS_WAKE_ON_WLAN_DEFAULT: Use the default value
 * @NM_SETTING_WIRELESS_WAKE_ON_WLAN_IGNORE: Don't change configured settings
 * @NM_SETTING_WIRELESS_WAKE_ON_WLAN_EXCLUSIVE_FLAGS: Mask of flags that are
 *   incompatible with other flags
 *
 * Options for #NMSettingWireless:wake-on-wlan. Note that not all options
 * are supported by all devices.
 *
 * Since: 1.12
 */
/* clang-format off */
typedef enum {                                                            /*< flags >*/
    NM_SETTING_WIRELESS_WAKE_ON_WLAN_NONE                 = 0, /*< skip >*/
    NM_SETTING_WIRELESS_WAKE_ON_WLAN_ANY                  = 0x2,
    NM_SETTING_WIRELESS_WAKE_ON_WLAN_DISCONNECT           = 0x4,
    NM_SETTING_WIRELESS_WAKE_ON_WLAN_MAGIC                = 0x8,
    NM_SETTING_WIRELESS_WAKE_ON_WLAN_GTK_REKEY_FAILURE    = 0x10,
    NM_SETTING_WIRELESS_WAKE_ON_WLAN_EAP_IDENTITY_REQUEST = 0x20,
    NM_SETTING_WIRELESS_WAKE_ON_WLAN_4WAY_HANDSHAKE       = 0x40,
    NM_SETTING_WIRELESS_WAKE_ON_WLAN_RFKILL_RELEASE       = 0x80,
    NM_SETTING_WIRELESS_WAKE_ON_WLAN_TCP                  = 0x100,

    NM_SETTING_WIRELESS_WAKE_ON_WLAN_ALL = 0x1FE,

    NM_SETTING_WIRELESS_WAKE_ON_WLAN_DEFAULT = 0x1,
    NM_SETTING_WIRELESS_WAKE_ON_WLAN_IGNORE  = 0x8000,

    NM_SETTING_WIRELESS_WAKE_ON_WLAN_EXCLUSIVE_FLAGS = NM_SETTING_WIRELESS_WAKE_ON_WLAN_DEFAULT | NM_SETTING_WIRELESS_WAKE_ON_WLAN_IGNORE, /*< skip >*/
} NMSettingWirelessWakeOnWLan;
/* clang-format on */

#define NM_SETTING_WIRELESS_SSID                      "ssid"
#define NM_SETTING_WIRELESS_MODE                      "mode"
#define NM_SETTING_WIRELESS_BAND                      "band"
#define NM_SETTING_WIRELESS_CHANNEL                   "channel"
#define NM_SETTING_WIRELESS_BSSID                     "bssid"
#define NM_SETTING_WIRELESS_RATE                      "rate"
#define NM_SETTING_WIRELESS_TX_POWER                  "tx-power"
#define NM_SETTING_WIRELESS_MAC_ADDRESS               "mac-address"
#define NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS        "cloned-mac-address"
#define NM_SETTING_WIRELESS_GENERATE_MAC_ADDRESS_MASK "generate-mac-address-mask"
#define NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST     "mac-address-blacklist"
#define NM_SETTING_WIRELESS_MTU                       "mtu"
#define NM_SETTING_WIRELESS_SEEN_BSSIDS               "seen-bssids"
#define NM_SETTING_WIRELESS_HIDDEN                    "hidden"
#define NM_SETTING_WIRELESS_POWERSAVE                 "powersave"
#define NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION "mac-address-randomization"
#define NM_SETTING_WIRELESS_WAKE_ON_WLAN              "wake-on-wlan"
#define NM_SETTING_WIRELESS_AP_ISOLATION              "ap-isolation"

/**
 * NM_SETTING_WIRELESS_MODE_ADHOC:
 *
 * Indicates Ad-Hoc mode where no access point is expected to be present.
 */
#define NM_SETTING_WIRELESS_MODE_ADHOC "adhoc"

/**
 * NM_SETTING_WIRELESS_MODE_AP:
 *
 * Indicates AP/master mode where the wireless device is started as an access
 * point/hotspot.
 */
#define NM_SETTING_WIRELESS_MODE_AP "ap"

/**
 * NM_SETTING_WIRELESS_MODE_INFRA:
 *
 * Indicates infrastructure mode where an access point is expected to be present
 * for this connection.
 */
#define NM_SETTING_WIRELESS_MODE_INFRA "infrastructure"

/**
 * NM_SETTING_WIRELESS_MODE_MESH:
 *
 * Indicates that the connection should create a mesh point.
 *
 * Since: 1.20
 */
#define NM_SETTING_WIRELESS_MODE_MESH "mesh"

/**
 * NMSettingWirelessPowersave:
 * @NM_SETTING_WIRELESS_POWERSAVE_DEFAULT: use the default value
 * @NM_SETTING_WIRELESS_POWERSAVE_IGNORE: don't touch existing setting
 * @NM_SETTING_WIRELESS_POWERSAVE_DISABLE: disable powersave
 * @NM_SETTING_WIRELESS_POWERSAVE_ENABLE: enable powersave
 *
 * These flags indicate whether wireless powersave must be enabled.
 **/
typedef enum {
    NM_SETTING_WIRELESS_POWERSAVE_DEFAULT = 0,
    NM_SETTING_WIRELESS_POWERSAVE_IGNORE  = 1,
    NM_SETTING_WIRELESS_POWERSAVE_DISABLE = 2,
    NM_SETTING_WIRELESS_POWERSAVE_ENABLE  = 3,
    _NM_SETTING_WIRELESS_POWERSAVE_NUM,                                          /*< skip >*/
    NM_SETTING_WIRELESS_POWERSAVE_LAST = _NM_SETTING_WIRELESS_POWERSAVE_NUM - 1, /*< skip >*/
} NMSettingWirelessPowersave;

typedef struct _NMSettingWirelessClass NMSettingWirelessClass;

GType nm_setting_wireless_get_type(void);

NMSetting *nm_setting_wireless_new(void);

GBytes     *nm_setting_wireless_get_ssid(NMSettingWireless *setting);
const char *nm_setting_wireless_get_mode(NMSettingWireless *setting);
const char *nm_setting_wireless_get_band(NMSettingWireless *setting);
guint32     nm_setting_wireless_get_channel(NMSettingWireless *setting);
const char *nm_setting_wireless_get_bssid(NMSettingWireless *setting);
guint32     nm_setting_wireless_get_rate(NMSettingWireless *setting);
guint32     nm_setting_wireless_get_tx_power(NMSettingWireless *setting);
const char *nm_setting_wireless_get_mac_address(NMSettingWireless *setting);
const char *nm_setting_wireless_get_cloned_mac_address(NMSettingWireless *setting);

NM_AVAILABLE_IN_1_4
const char *nm_setting_wireless_get_generate_mac_address_mask(NMSettingWireless *setting);

const char *const *nm_setting_wireless_get_mac_address_blacklist(NMSettingWireless *setting);
guint32            nm_setting_wireless_get_num_mac_blacklist_items(NMSettingWireless *setting);
const char *nm_setting_wireless_get_mac_blacklist_item(NMSettingWireless *setting, guint32 idx);
gboolean    nm_setting_wireless_add_mac_blacklist_item(NMSettingWireless *setting, const char *mac);
void        nm_setting_wireless_remove_mac_blacklist_item(NMSettingWireless *setting, guint32 idx);
gboolean    nm_setting_wireless_remove_mac_blacklist_item_by_value(NMSettingWireless *setting,
                                                                   const char        *mac);
void        nm_setting_wireless_clear_mac_blacklist_items(NMSettingWireless *setting);

guint32  nm_setting_wireless_get_mtu(NMSettingWireless *setting);
gboolean nm_setting_wireless_get_hidden(NMSettingWireless *setting);
NM_AVAILABLE_IN_1_2
guint32 nm_setting_wireless_get_powersave(NMSettingWireless *setting);

NM_AVAILABLE_IN_1_2
NMSettingMacRandomization
nm_setting_wireless_get_mac_address_randomization(NMSettingWireless *setting);

gboolean nm_setting_wireless_add_seen_bssid(NMSettingWireless *setting, const char *bssid);

guint32     nm_setting_wireless_get_num_seen_bssids(NMSettingWireless *setting);
const char *nm_setting_wireless_get_seen_bssid(NMSettingWireless *setting, guint32 i);

gboolean nm_setting_wireless_ap_security_compatible(NMSettingWireless         *s_wireless,
                                                    NMSettingWirelessSecurity *s_wireless_sec,
                                                    NM80211ApFlags             ap_flags,
                                                    NM80211ApSecurityFlags     ap_wpa,
                                                    NM80211ApSecurityFlags     ap_rsn,
                                                    NM80211Mode                ap_mode);

NM_AVAILABLE_IN_1_12
NMSettingWirelessWakeOnWLan nm_setting_wireless_get_wake_on_wlan(NMSettingWireless *setting);

NM_AVAILABLE_IN_1_28
NMTernary nm_setting_wireless_get_ap_isolation(NMSettingWireless *setting);

G_END_DECLS

#endif /* __NM_SETTING_WIRELESS_H__ */
