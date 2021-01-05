/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2004 - 2012 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#ifndef __NM_DISPATCHER_H__
#define __NM_DISPATCHER_H__

#include "nm-connection.h"

typedef enum {
    NM_DISPATCHER_ACTION_HOSTNAME,
    NM_DISPATCHER_ACTION_PRE_UP,
    NM_DISPATCHER_ACTION_UP,
    NM_DISPATCHER_ACTION_PRE_DOWN,
    NM_DISPATCHER_ACTION_DOWN,
    NM_DISPATCHER_ACTION_VPN_PRE_UP,
    NM_DISPATCHER_ACTION_VPN_UP,
    NM_DISPATCHER_ACTION_VPN_PRE_DOWN,
    NM_DISPATCHER_ACTION_VPN_DOWN,
    NM_DISPATCHER_ACTION_DHCP4_CHANGE,
    NM_DISPATCHER_ACTION_DHCP6_CHANGE,
    NM_DISPATCHER_ACTION_CONNECTIVITY_CHANGE
} NMDispatcherAction;

typedef struct NMDispatcherCallId NMDispatcherCallId;

typedef void (*NMDispatcherFunc)(NMDispatcherCallId *call_id, gpointer user_data);

gboolean nm_dispatcher_call_hostname(NMDispatcherFunc     callback,
                                     gpointer             user_data,
                                     NMDispatcherCallId **out_call_id);

gboolean nm_dispatcher_call_device(NMDispatcherAction   action,
                                   NMDevice *           device,
                                   NMActRequest *       act_request,
                                   NMDispatcherFunc     callback,
                                   gpointer             user_data,
                                   NMDispatcherCallId **out_call_id);

gboolean nm_dispatcher_call_device_sync(NMDispatcherAction action,
                                        NMDevice *         device,
                                        NMActRequest *     act_request);

gboolean nm_dispatcher_call_vpn(NMDispatcherAction    action,
                                NMSettingsConnection *settings_connection,
                                NMConnection *        applied_connection,
                                NMDevice *            parent_device,
                                const char *          vpn_iface,
                                NMProxyConfig *       vpn_proxy_config,
                                NMIP4Config *         vpn_ip4_config,
                                NMIP6Config *         vpn_ip6_config,
                                NMDispatcherFunc      callback,
                                gpointer              user_data,
                                NMDispatcherCallId ** out_call_id);

gboolean nm_dispatcher_call_vpn_sync(NMDispatcherAction    action,
                                     NMSettingsConnection *settings_connection,
                                     NMConnection *        applied_connection,
                                     NMDevice *            parent_device,
                                     const char *          vpn_iface,
                                     NMProxyConfig *       vpn_proxy_config,
                                     NMIP4Config *         vpn_ip4_config,
                                     NMIP6Config *         vpn_ip6_config);

gboolean nm_dispatcher_call_connectivity(NMConnectivityState  state,
                                         NMDispatcherFunc     callback,
                                         gpointer             user_data,
                                         NMDispatcherCallId **out_call_id);

void nm_dispatcher_call_cancel(NMDispatcherCallId *call_id);

#endif /* __NM_DISPATCHER_H__ */
