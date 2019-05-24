/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-dhcp-manager.c - Handle the DHCP daemon for NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP_MANAGER_H__
#define __NETWORKMANAGER_DHCP_MANAGER_H__

#include "nm-dhcp-client.h"
#include "nm-ip4-config.h"
#include "nm-dhcp4-config.h"

#define NM_TYPE_DHCP_MANAGER            (nm_dhcp_manager_get_type ())
#define NM_DHCP_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_MANAGER, NMDhcpManager))
#define NM_DHCP_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_MANAGER, NMDhcpManagerClass))
#define NM_IS_DHCP_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_MANAGER))
#define NM_IS_DHCP_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP_MANAGER))
#define NM_DHCP_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_MANAGER, NMDhcpManagerClass))

typedef struct _NMDhcpManager NMDhcpManager;
typedef struct _NMDhcpManagerClass NMDhcpManagerClass;

GType nm_dhcp_manager_get_type (void);

NMDhcpManager *nm_dhcp_manager_get (void);

const char *nm_dhcp_manager_get_config (NMDhcpManager *self);

void           nm_dhcp_manager_set_default_hostname (NMDhcpManager *manager,
                                                     const char *hostname);

NMDhcpClient * nm_dhcp_manager_start_ip4     (NMDhcpManager *manager,
                                              struct _NMDedupMultiIndex *multi_idx,
                                              const char *iface,
                                              int ifindex,
                                              GBytes *hwaddr,
                                              const char *uuid,
                                              guint32 route_table,
                                              guint32 route_metric,
                                              gboolean send_hostname,
                                              const char *dhcp_hostname,
                                              const char *dhcp_fqdn,
                                              GBytes *dhcp_client_id,
                                              guint32 timeout,
                                              const char *dhcp_anycast_addr,
                                              const char *last_ip_address,
                                              GError **error);

NMDhcpClient * nm_dhcp_manager_start_ip6     (NMDhcpManager *manager,
                                              struct _NMDedupMultiIndex *multi_idx,
                                              const char *iface,
                                              int ifindex,
                                              GBytes *hwaddr,
                                              const struct in6_addr *ll_addr,
                                              const char *uuid,
                                              guint32 route_table,
                                              guint32 route_metric,
                                              gboolean send_hostname,
                                              const char *dhcp_hostname,
                                              GBytes *duid,
                                              gboolean enforce_duid,
                                              guint32 timeout,
                                              const char *dhcp_anycast_addr,
                                              gboolean info_only,
                                              NMSettingIP6ConfigPrivacy privacy,
                                              guint needed_prefixes,
                                              GError **error);

/* For testing only */
extern const char* nm_dhcp_helper_path;

extern const NMDhcpClientFactory *const _nm_dhcp_manager_factories[5];

void nmtst_dhcp_manager_unget (gpointer singleton_instance);

#endif /* __NETWORKMANAGER_DHCP_MANAGER_H__ */
