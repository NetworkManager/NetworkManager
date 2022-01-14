/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2012 - 2018 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_TYPES_H__
#define __NETWORKMANAGER_TYPES_H__

#if !((NETWORKMANAGER_COMPILATION) &NM_NETWORKMANAGER_COMPILATION_WITH_DAEMON)
#error Cannot use this header.
#endif

/* core */
typedef struct _NMDBusObject            NMDBusObject;
typedef struct _NMActiveConnection      NMActiveConnection;
typedef struct _NMAuditManager          NMAuditManager;
typedef struct _NMVpnConnection         NMVpnConnection;
typedef struct _NMActRequest            NMActRequest;
typedef struct _NMAuthSubject           NMAuthSubject;
typedef struct _NMDBusManager           NMDBusManager;
typedef struct _NMConfig                NMConfig;
typedef struct _NMConfigData            NMConfigData;
typedef struct _NMConnectivity          NMConnectivity;
typedef struct _NML3Cfg                 NML3Cfg;
typedef struct _NML3ConfigData          NML3ConfigData;
typedef struct _NMDevice                NMDevice;
typedef struct _NMDhcpConfig            NMDhcpConfig;
typedef struct _NMIPConfig              NMIPConfig;
typedef struct _NMManager               NMManager;
typedef struct _NMNetns                 NMNetns;
typedef struct _NMPolicy                NMPolicy;
typedef struct _NMRfkillManager         NMRfkillManager;
typedef struct _NMPacrunnerManager      NMPacrunnerManager;
typedef struct _NMSessionMonitor        NMSessionMonitor;
typedef struct _NMKeepAlive             NMKeepAlive;
typedef struct _NMSleepMonitor          NMSleepMonitor;
typedef struct _NMLldpListener          NMLldpListener;
typedef struct _NMConfigDeviceStateData NMConfigDeviceStateData;

typedef void (*NMManagerDeviceAuthRequestFunc)(NMDevice              *device,
                                               GDBusMethodInvocation *context,
                                               NMAuthSubject         *subject,
                                               GError                *error,
                                               gpointer               user_data);

struct _NMDedupMultiIndex;

typedef struct _NMRefString NMRefString;

/*****************************************************************************/

typedef enum {
    /* Do a full activation. */
    NM_ACTIVATION_TYPE_MANAGED = 0,

    /* gracefully/seamlessly take over the device. This leaves additional
     * IP addresses and does not restore missing manual addresses. */
    NM_ACTIVATION_TYPE_ASSUME = 1,

    /* external activation. This device is not managed by NM, instead
     * a in-memory connection is generated and NM pretends the device
     * to be active, but it doesn't do anything really. */
    NM_ACTIVATION_TYPE_EXTERNAL = 2,
} NMActivationType;

typedef enum {
    NM_ACTIVATION_REASON_UNSET,
    NM_ACTIVATION_REASON_EXTERNAL,
    NM_ACTIVATION_REASON_ASSUME,
    NM_ACTIVATION_REASON_AUTOCONNECT,
    NM_ACTIVATION_REASON_AUTOCONNECT_SLAVES,
    NM_ACTIVATION_REASON_USER_REQUEST,
} NMActivationReason;

/**
 * NMIPConfigMergeFlags:
 * @NM_IP_CONFIG_MERGE_DEFAULT: no flags set
 * @NM_IP_CONFIG_MERGE_NO_ROUTES: don't merge routes
 * @NM_IP_CONFIG_MERGE_NO_DEFAULT_ROUTES: don't merge default routes.
 *   Note that if the source IP config has NM_IP_CONFIG_FLAGS_IGNORE_MERGE_NO_DEFAULT_ROUTES
 *   set, this flag gets ignored during merge.
 * @NM_IP_CONFIG_MERGE_NO_DNS: don't merge DNS information
 * @NM_IP_CONFIG_MERGE_EXTERNAL: mark new addresses as external
 */
typedef enum {
    NM_IP_CONFIG_MERGE_DEFAULT           = 0,
    NM_IP_CONFIG_MERGE_NO_ROUTES         = (1LL << 0),
    NM_IP_CONFIG_MERGE_NO_DEFAULT_ROUTES = (1LL << 1),
    NM_IP_CONFIG_MERGE_NO_DNS            = (1LL << 2),
    NM_IP_CONFIG_MERGE_EXTERNAL          = (1LL << 3),
} NMIPConfigMergeFlags;

/* settings */
typedef struct _NMAgentManager       NMAgentManager;
typedef struct _NMSecretAgent        NMSecretAgent;
typedef struct _NMSettings           NMSettings;
typedef struct _NMSettingsConnection NMSettingsConnection;

#define NM_SETTING_CONNECTION_MDNS_UNKNOWN ((NMSettingConnectionMdns) -42)

#endif /* NM_TYPES_H */
