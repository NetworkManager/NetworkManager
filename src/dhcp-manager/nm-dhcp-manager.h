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

#ifndef NM_DHCP_MANAGER_H
#define NM_DHCP_MANAGER_H

#include <glib.h>
#include <glib-object.h>

#include "nm-dhcp-client.h"
#include "nm-ip4-config.h"
#include "nm-dhcp4-config.h"

typedef enum {
	NM_DHCP_MANAGER_ERROR_BAD_CLIENT = 0, /*< nick=BadClient >*/
	NM_DHCP_MANAGER_ERROR_INTERNAL = 1,   /*< nick=InternalError >*/
} NMDHCPManagerError;

#define NM_DHCP_MANAGER_ERROR (nm_dhcp_manager_error_quark ())

GQuark nm_dhcp_manager_error_quark    (void);


#define NM_TYPE_DHCP_MANAGER            (nm_dhcp_manager_get_type ())
#define NM_DHCP_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_MANAGER, NMDHCPManager))
#define NM_DHCP_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_MANAGER, NMDHCPManagerClass))
#define NM_IS_DHCP_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_MANAGER))
#define NM_IS_DHCP_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP_MANAGER))
#define NM_DHCP_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_MANAGER, NMDHCPManagerClass))

typedef struct {
	GObject parent;
} NMDHCPManager;

typedef struct {
	GObjectClass parent;
} NMDHCPManagerClass;

GType nm_dhcp_manager_get_type (void);

NMDHCPManager *nm_dhcp_manager_get (void);

void           nm_dhcp_manager_set_default_hostname (NMDHCPManager *manager,
                                                     const char *hostname);

NMDHCPClient * nm_dhcp_manager_start_ip4     (NMDHCPManager *manager,
                                              const char *iface,
                                              int ifindex,
                                              const GByteArray *hwaddr,
                                              const char *uuid,
                                              guint priority,
                                              gboolean send_hostname,
                                              const char *dhcp_hostname,
                                              const char *dhcp_client_id,
                                              guint32 timeout,
                                              GByteArray *dhcp_anycast_addr);

NMDHCPClient * nm_dhcp_manager_start_ip6     (NMDHCPManager *manager,
                                              const char *iface,
                                              int ifindex,
                                              const GByteArray *hwaddr,
                                              const char *uuid,
                                              guint priority,
                                              const char *dhcp_hostname,
                                              guint32 timeout,
                                              GByteArray *dhcp_anycast_addr,
                                              gboolean info_only);

GSList *       nm_dhcp_manager_get_lease_ip_configs (NMDHCPManager *self,
                                                     const char *iface,
                                                     const char *uuid,
                                                     gboolean ipv6);

/* For testing only */
extern const char* nm_dhcp_helper_path;

#endif /* NM_DHCP_MANAGER_H */
