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


#include "nm-default.h"
#include "nm-dhcp-client.h"
#include "nm-ip4-config.h"
#include "nm-dhcp4-config.h"

#define NM_TYPE_DHCP_MANAGER            (nm_dhcp_manager_get_type ())
#define NM_DHCP_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_MANAGER, NMDhcpManager))
#define NM_DHCP_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_MANAGER, NMDhcpManagerClass))
#define NM_IS_DHCP_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_MANAGER))
#define NM_IS_DHCP_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP_MANAGER))
#define NM_DHCP_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_MANAGER, NMDhcpManagerClass))

typedef struct {
	GObject parent;
} NMDhcpManager;

typedef struct {
	GObjectClass parent;
} NMDhcpManagerClass;

GType nm_dhcp_manager_get_type (void);

NMDhcpManager *nm_dhcp_manager_get (void);

void           nm_dhcp_manager_set_default_hostname (NMDhcpManager *manager,
                                                     const char *hostname);

NMDhcpClient * nm_dhcp_manager_start_ip4     (NMDhcpManager *manager,
                                              const char *iface,
                                              int ifindex,
                                              const GByteArray *hwaddr,
                                              const char *uuid,
                                              guint32 priority,
                                              gboolean send_hostname,
                                              const char *dhcp_hostname,
                                              const char *dhcp_client_id,
                                              guint32 timeout,
                                              const char *dhcp_anycast_addr,
                                              const char *last_ip_address);

NMDhcpClient * nm_dhcp_manager_start_ip6     (NMDhcpManager *manager,
                                              const char *iface,
                                              int ifindex,
                                              const GByteArray *hwaddr,
                                              const char *uuid,
                                              guint32 priority,
                                              gboolean send_hostname,
                                              const char *dhcp_hostname,
                                              guint32 timeout,
                                              const char *dhcp_anycast_addr,
                                              gboolean info_only,
                                              NMSettingIP6ConfigPrivacy privacy);

GSList *       nm_dhcp_manager_get_lease_ip_configs (NMDhcpManager *self,
                                                     const char *iface,
                                                     int ifindex,
                                                     const char *uuid,
                                                     gboolean ipv6,
                                                     guint32 default_route_metric);

/* For testing only */
extern const char* nm_dhcp_helper_path;

#endif /* __NETWORKMANAGER_DHCP_MANAGER_H__ */
