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
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef NM_TYPES_H
#define NM_TYPES_H

/* core */
typedef struct _NMActiveConnection   NMActiveConnection;
typedef struct _NMActRequest         NMActRequest;
typedef struct _NMAuthSubject        NMAuthSubject;
typedef struct _NMConnectionProvider NMConnectionProvider;
typedef struct _NMConnectivity       NMConnectivity;
typedef struct _NMDBusManager        NMDBusManager;
typedef struct _NMDevice             NMDevice;
typedef struct _NMDHCP4Config        NMDHCP4Config;
typedef struct _NMDHCP6Config        NMDHCP6Config;
typedef struct _NMIP4Config          NMIP4Config;
typedef struct _NMIP6Config          NMIP6Config;
typedef struct _NMManager            NMManager;
typedef struct _NMPolicy             NMPolicy;
typedef struct _NMRfkillManager      NMRfkillManager;
typedef struct _NMSessionMonitor     NMSessionMonitor;
typedef struct _NMSleepMonitor       NMSleepMonitor;

/* platform */
typedef struct _NMPlatformIP4Address NMPlatformIP4Address;
typedef struct _NMPlatformIP4Route   NMPlatformIP4Route;
typedef struct _NMPlatformIP6Address NMPlatformIP6Address;
typedef struct _NMPlatformIP6Route   NMPlatformIP6Route;
typedef struct _NMPlatformLink       NMPlatformLink;

/* settings */
typedef struct _NMAgentManager       NMAgentManager;
typedef struct _NMSecretAgent        NMSecretAgent;
typedef struct _NMSettings           NMSettings;
typedef struct _NMSettingsConnection NMSettingsConnection;

#endif  /* NM_TYPES_H */
