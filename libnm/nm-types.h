/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2014 - 2018 Red Hat, Inc.
 */

#ifndef __NM_TYPES_H__
#define __NM_TYPES_H__

#include <gio/gio.h>

#include "nm-dbus-interface.h"
#include "nm-connection.h"

typedef struct _NMAccessPoint        NMAccessPoint;
typedef struct _NMActiveConnection   NMActiveConnection;
typedef struct _NMCheckpoint         NMCheckpoint;
typedef struct _NMClient             NMClient;
typedef struct _NMDevice             NMDevice;
typedef struct _NMDevice6Lowpan      NMDevice6Lowpan;
typedef struct _NMDeviceAdsl         NMDeviceAdsl;
typedef struct _NMDeviceBond         NMDeviceBond;
typedef struct _NMDeviceBridge       NMDeviceBridge;
typedef struct _NMDeviceBt           NMDeviceBt;
typedef struct _NMDeviceDummy        NMDeviceDummy;
typedef struct _NMDeviceEthernet     NMDeviceEthernet;
typedef struct _NMDeviceGeneric      NMDeviceGeneric;
typedef struct _NMDeviceIPTunnel     NMDeviceIPTunnel;
typedef struct _NMDeviceInfiniband   NMDeviceInfiniband;
typedef struct _NMDeviceMacsec       NMDeviceMacsec;
typedef struct _NMDeviceMacvlan      NMDeviceMacvlan;
typedef struct _NMDeviceModem        NMDeviceModem;
typedef struct _NMDeviceOlpcMesh     NMDeviceOlpcMesh;
typedef struct _NMDeviceOvsBridge    NMDeviceOvsBridge;
typedef struct _NMDeviceOvsInterface NMDeviceOvsInterface;
typedef struct _NMDeviceOvsPort      NMDeviceOvsPort;
typedef struct _NMDevicePpp          NMDevicePpp;
typedef struct _NMDeviceTeam         NMDeviceTeam;
typedef struct _NMDeviceTun          NMDeviceTun;
typedef struct _NMDeviceVeth         NMDeviceVeth;
typedef struct _NMDeviceVlan         NMDeviceVlan;
typedef struct _NMDeviceVrf          NMDeviceVrf;
typedef struct _NMDeviceVxlan        NMDeviceVxlan;
typedef struct _NMDeviceWifi         NMDeviceWifi;
typedef struct _NMDeviceWifiP2P      NMDeviceWifiP2P;
typedef struct _NMDeviceWimax        NMDeviceWimax;
typedef struct _NMDeviceWireGuard    NMDeviceWireGuard;
typedef struct _NMDeviceWpan         NMDeviceWpan;
typedef struct _NMDhcpConfig         NMDhcpConfig;
typedef struct _NMIPConfig           NMIPConfig;
typedef struct _NMObject             NMObject;
typedef struct _NMRemoteConnection   NMRemoteConnection;
typedef struct _NMVpnConnection      NMVpnConnection;
typedef struct _NMWifiP2PPeer        NMWifiP2PPeer;
typedef struct _NMWimaxNsp           NMWimaxNsp;

#endif /* NM_TYPES_H */
