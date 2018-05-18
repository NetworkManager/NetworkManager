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
