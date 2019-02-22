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

#ifndef __NM_SETTING_WIRED_H__
#define __NM_SETTING_WIRED_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_WIRED            (nm_setting_wired_get_type ())
#define NM_SETTING_WIRED(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_WIRED, NMSettingWired))
#define NM_SETTING_WIRED_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_WIRED, NMSettingWiredClass))
#define NM_IS_SETTING_WIRED(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_WIRED))
#define NM_IS_SETTING_WIRED_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_WIRED))
#define NM_SETTING_WIRED_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_WIRED, NMSettingWiredClass))

#define NM_SETTING_WIRED_SETTING_NAME "802-3-ethernet"

/**
 * NMSettingWiredWakeOnLan:
 * @NM_SETTING_WIRED_WAKE_ON_LAN_NONE: Wake-on-LAN disabled
 * @NM_SETTING_WIRED_WAKE_ON_LAN_PHY: Wake on PHY activity
 * @NM_SETTING_WIRED_WAKE_ON_LAN_UNICAST: Wake on unicast messages
 * @NM_SETTING_WIRED_WAKE_ON_LAN_MULTICAST: Wake on multicast messages
 * @NM_SETTING_WIRED_WAKE_ON_LAN_BROADCAST: Wake on broadcast messages
 * @NM_SETTING_WIRED_WAKE_ON_LAN_ARP: Wake on ARP
 * @NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC: Wake on magic packet
 * @NM_SETTING_WIRED_WAKE_ON_LAN_ALL: Wake on all events. This does not
 *   include the exclusive flags @NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT or
 *   @NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE.
 * @NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT: Use the default value
 * @NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE: Don't change configured settings
 * @NM_SETTING_WIRED_WAKE_ON_LAN_EXCLUSIVE_FLAGS: Mask of flags that are
 *   incompatible with other flags
 *
 * Options for #NMSettingWired:wake-on-lan. Note that not all options
 * are supported by all devices.
 *
 * Since: 1.2
 */
typedef enum { /*< flags >*/
	NM_SETTING_WIRED_WAKE_ON_LAN_NONE            = 0, /*< skip >*/
	NM_SETTING_WIRED_WAKE_ON_LAN_PHY             = 0x2,
	NM_SETTING_WIRED_WAKE_ON_LAN_UNICAST         = 0x4,
	NM_SETTING_WIRED_WAKE_ON_LAN_MULTICAST       = 0x8,
	NM_SETTING_WIRED_WAKE_ON_LAN_BROADCAST       = 0x10,
	NM_SETTING_WIRED_WAKE_ON_LAN_ARP             = 0x20,
	NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC           = 0x40,

	NM_SETTING_WIRED_WAKE_ON_LAN_ALL             = 0x7E, /*< skip >*/

	NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT         = 0x1,
	NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE          = 0x8000,
	NM_SETTING_WIRED_WAKE_ON_LAN_EXCLUSIVE_FLAGS = 0x8001, /*< skip >*/
} NMSettingWiredWakeOnLan;

#define NM_SETTING_WIRED_PORT "port"
#define NM_SETTING_WIRED_SPEED "speed"
#define NM_SETTING_WIRED_DUPLEX "duplex"
#define NM_SETTING_WIRED_AUTO_NEGOTIATE "auto-negotiate"
#define NM_SETTING_WIRED_MAC_ADDRESS "mac-address"
#define NM_SETTING_WIRED_CLONED_MAC_ADDRESS "cloned-mac-address"
#define NM_SETTING_WIRED_GENERATE_MAC_ADDRESS_MASK "generate-mac-address-mask"
#define NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST "mac-address-blacklist"
#define NM_SETTING_WIRED_MTU "mtu"
#define NM_SETTING_WIRED_S390_SUBCHANNELS "s390-subchannels"
#define NM_SETTING_WIRED_S390_NETTYPE "s390-nettype"
#define NM_SETTING_WIRED_S390_OPTIONS "s390-options"
#define NM_SETTING_WIRED_WAKE_ON_LAN "wake-on-lan"
#define NM_SETTING_WIRED_WAKE_ON_LAN_PASSWORD "wake-on-lan-password"

/**
 * NMSettingWired:
 *
 * Wired Ethernet Settings
 */
struct _NMSettingWired {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingWiredClass;

GType nm_setting_wired_get_type (void);

NMSetting *       nm_setting_wired_new                  (void);
const char *      nm_setting_wired_get_port             (NMSettingWired *setting);
guint32           nm_setting_wired_get_speed            (NMSettingWired *setting);
const char *      nm_setting_wired_get_duplex           (NMSettingWired *setting);
gboolean          nm_setting_wired_get_auto_negotiate   (NMSettingWired *setting);
const char *      nm_setting_wired_get_mac_address      (NMSettingWired *setting);
const char *      nm_setting_wired_get_cloned_mac_address (NMSettingWired *setting);

NM_AVAILABLE_IN_1_4
const char *      nm_setting_wired_get_generate_mac_address_mask (NMSettingWired *setting);

const char * const *nm_setting_wired_get_mac_address_blacklist   (NMSettingWired *setting);
guint32           nm_setting_wired_get_num_mac_blacklist_items (NMSettingWired *setting);
const char *      nm_setting_wired_get_mac_blacklist_item      (NMSettingWired *setting,
                                                                guint32 idx);
gboolean          nm_setting_wired_add_mac_blacklist_item      (NMSettingWired *setting,
                                                                const char *mac);
void              nm_setting_wired_remove_mac_blacklist_item   (NMSettingWired *setting,
                                                                guint32 idx);
gboolean          nm_setting_wired_remove_mac_blacklist_item_by_value (NMSettingWired *setting,
                                                                       const char *mac);
void              nm_setting_wired_clear_mac_blacklist_items   (NMSettingWired *setting);

guint32           nm_setting_wired_get_mtu              (NMSettingWired *setting);

const char * const *nm_setting_wired_get_s390_subchannels (NMSettingWired *setting);
const char *      nm_setting_wired_get_s390_nettype     (NMSettingWired *setting);

guint32           nm_setting_wired_get_num_s390_options (NMSettingWired *setting);
gboolean          nm_setting_wired_get_s390_option      (NMSettingWired *setting,
                                                         guint32 idx,
                                                         const char **out_key,
                                                         const char **out_value);
const char *      nm_setting_wired_get_s390_option_by_key (NMSettingWired *setting,
                                                           const char *key);
gboolean          nm_setting_wired_add_s390_option      (NMSettingWired *setting,
                                                         const char *key,
                                                         const char *value);
gboolean          nm_setting_wired_remove_s390_option   (NMSettingWired *setting,
                                                         const char *key);
const char **     nm_setting_wired_get_valid_s390_options (NMSettingWired *setting);

NMSettingWiredWakeOnLan  nm_setting_wired_get_wake_on_lan          (NMSettingWired *setting);
const char *             nm_setting_wired_get_wake_on_lan_password (NMSettingWired *setting);

G_END_DECLS

#endif /* __NM_SETTING_WIRED_H__ */
