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
 * Copyright 2014 - 2018 Red Hat, Inc.
 */

#ifndef __NM_CORE_TYPES_H__
#define __NM_CORE_TYPES_H__

#include <glib-object.h>

#include "nm-version.h"
#include "nm-dbus-interface.h"
#include "nm-core-enum-types.h"

typedef struct _NMConnection              NMConnection;
typedef struct _NMSetting                 NMSetting;
typedef struct _NMSetting6Lowpan          NMSetting6Lowpan;
typedef struct _NMSetting8021x            NMSetting8021x;
typedef struct _NMSettingAdsl             NMSettingAdsl;
typedef struct _NMSettingBluetooth        NMSettingBluetooth;
typedef struct _NMSettingBond             NMSettingBond;
typedef struct _NMSettingBridge           NMSettingBridge;
typedef struct _NMSettingBridgePort       NMSettingBridgePort;
typedef struct _NMSettingCdma             NMSettingCdma;
typedef struct _NMSettingConnection       NMSettingConnection;
typedef struct _NMSettingDcb              NMSettingDcb;
typedef struct _NMSettingDummy            NMSettingDummy;
typedef struct _NMSettingEthtool          NMSettingEthtool;
typedef struct _NMSettingGeneric          NMSettingGeneric;
typedef struct _NMSettingGsm              NMSettingGsm;
typedef struct _NMSettingIP4Config        NMSettingIP4Config;
typedef struct _NMSettingIP6Config        NMSettingIP6Config;
typedef struct _NMSettingIPConfig         NMSettingIPConfig;
typedef struct _NMSettingIPTunnel         NMSettingIPTunnel;
typedef struct _NMSettingInfiniband       NMSettingInfiniband;
typedef struct _NMSettingMacsec           NMSettingMacsec;
typedef struct _NMSettingMacvlan          NMSettingMacvlan;
typedef struct _NMSettingMatch            NMSettingMatch;
typedef struct _NMSettingOlpcMesh         NMSettingOlpcMesh;
typedef struct _NMSettingOvsBridge        NMSettingOvsBridge;
typedef struct _NMSettingOvsInterface     NMSettingOvsInterface;
typedef struct _NMSettingOvsPatch         NMSettingOvsPatch;
typedef struct _NMSettingOvsPort          NMSettingOvsPort;
typedef struct _NMSettingPpp              NMSettingPpp;
typedef struct _NMSettingPppoe            NMSettingPppoe;
typedef struct _NMSettingProxy            NMSettingProxy;
typedef struct _NMSettingSerial           NMSettingSerial;
typedef struct _NMSettingSriov            NMSettingSriov;
typedef struct _NMSettingTCConfig         NMSettingTCConfig;
typedef struct _NMSettingTeam             NMSettingTeam;
typedef struct _NMSettingTeamPort         NMSettingTeamPort;
typedef struct _NMSettingTun              NMSettingTun;
typedef struct _NMSettingUser             NMSettingUser;
typedef struct _NMSettingVlan             NMSettingVlan;
typedef struct _NMSettingVpn              NMSettingVpn;
typedef struct _NMSettingVxlan            NMSettingVxlan;
typedef struct _NMSettingWifiP2P          NMSettingWifiP2P;
typedef struct _NMSettingWimax            NMSettingWimax;
typedef struct _NMSettingWired            NMSettingWired;
typedef struct _NMSettingWireGuard        NMSettingWireGuard;
typedef struct _NMSettingWireless         NMSettingWireless;
typedef struct _NMSettingWirelessSecurity NMSettingWirelessSecurity;
typedef struct _NMSettingWpan             NMSettingWpan;
typedef struct _NMSimpleConnection        NMSimpleConnection;

#endif  /* __NM_CORE_TYPES_H__ */
