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
 * Copyright 2019 Red Hat, Inc.
 */

#ifndef __NM_SETTING_P2P_WIRELESS_H__
#define __NM_SETTING_P2P_WIRELESS_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"
#include "nm-setting-wireless-security.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_P2P_WIRELESS            (nm_setting_p2p_wireless_get_type ())
#define NM_SETTING_P2P_WIRELESS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_P2P_WIRELESS, NMSettingP2PWireless))
#define NM_SETTING_P2P_WIRELESS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_P2P_WIRELESS, NMSettingP2PWirelessClass))
#define NM_IS_SETTING_P2P_WIRELESS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_P2P_WIRELESS))
#define NM_IS_SETTING_P2P_WIRELESS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_P2P_WIRELESS))
#define NM_SETTING_P2P_WIRELESS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_P2P_WIRELESS, NMSettingP2PWirelessClass))

#define NM_SETTING_P2P_WIRELESS_SETTING_NAME "p2p-wireless"

/**
 * NM_SETTING_P2P_WIRELESS_PEER:
 *
 * The mac address of the peer to connect to.
 */
#define NM_SETTING_P2P_WIRELESS_PEER        "peer"
#define NM_SETTING_P2P_WIRELESS_WPS_METHOD  "wps-method"

typedef struct _NMSettingP2PWirelessClass NMSettingP2PWirelessClass;

NM_AVAILABLE_IN_1_16
GType nm_setting_p2p_wireless_get_type (void);

NM_AVAILABLE_IN_1_16
NMSetting *nm_setting_p2p_wireless_new (void);

NM_AVAILABLE_IN_1_16
const char *nm_setting_p2p_wireless_get_peer (NMSettingP2PWireless *setting);

NM_AVAILABLE_IN_1_16
NMSettingWirelessSecurityWpsMethod nm_setting_p2p_wireless_get_wps_method (NMSettingP2PWireless *setting);

G_END_DECLS

#endif /* __NM_SETTING_P2P_WIRELESS_H__ */
