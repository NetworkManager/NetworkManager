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
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef __NM_TYPES_H__
#define __NM_TYPES_H__

#include <gio/gio.h>

#include <nm-dbus-interface.h>
#include <nm-connection.h>

typedef struct _NMAccessPoint       NMAccessPoint;
typedef struct _NMActiveConnection  NMActiveConnection;
typedef struct _NMClient            NMClient;
typedef struct _NMDevice            NMDevice;
typedef struct _NMDeviceAdsl        NMDeviceAdsl;
typedef struct _NMDeviceBond        NMDeviceBond;
typedef struct _NMDeviceBridge      NMDeviceBridge;
typedef struct _NMDeviceBt          NMDeviceBt;
typedef struct _NMDeviceEthernet    NMDeviceEthernet;
typedef struct _NMDeviceGeneric     NMDeviceGeneric;
typedef struct _NMDeviceInfiniband  NMDeviceInfiniband;
typedef struct _NMDeviceIPTunnel    NMDeviceIPTunnel;
typedef struct _NMDeviceMacvlan     NMDeviceMacvlan;
typedef struct _NMDeviceModem       NMDeviceModem;
typedef struct _NMDeviceOlpcMesh    NMDeviceOlpcMesh;
typedef struct _NMDeviceTeam        NMDeviceTeam;
typedef struct _NMDeviceTun         NMDeviceTun;
typedef struct _NMDeviceVlan        NMDeviceVlan;
typedef struct _NMDeviceVxlan       NMDeviceVxlan;
typedef struct _NMDeviceWifi        NMDeviceWifi;
typedef struct _NMDeviceWimax       NMDeviceWimax;
typedef struct _NMDhcpConfig        NMDhcpConfig;
typedef struct _NMIPConfig          NMIPConfig;
typedef struct _NMObject            NMObject;
typedef struct _NMRemoteConnection  NMRemoteConnection;
typedef struct _NMVpnConnection     NMVpnConnection;
typedef struct _NMWimaxNsp          NMWimaxNsp;

#endif  /* NM_TYPES_H */
