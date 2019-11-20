// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2016 Red Hat, Inc.
 */

#ifndef __NM_PPP_MANAGER_H__
#define __NM_PPP_MANAGER_H__

#define NM_PPP_MANAGER_PARENT_IFACE    "parent-iface"

#define NM_PPP_MANAGER_SIGNAL_STATE_CHANGED "state-changed"
#define NM_PPP_MANAGER_SIGNAL_IFINDEX_SET   "ifindex-set"
#define NM_PPP_MANAGER_SIGNAL_IP4_CONFIG    "ip4-config"
#define NM_PPP_MANAGER_SIGNAL_IP6_CONFIG    "ip6-config"
#define NM_PPP_MANAGER_SIGNAL_STATS         "stats"

typedef struct _NMPPPManager NMPPPManager;

typedef struct _NMPPPManagerStopHandle NMPPPManagerStopHandle;

typedef void (*NMPPPManagerStopCallback) (NMPPPManager *manager,
                                          NMPPPManagerStopHandle *handle,
                                          gboolean was_cancelled,
                                          gpointer user_data);

#endif /* __NM_PPP_MANAGER_H__ */
