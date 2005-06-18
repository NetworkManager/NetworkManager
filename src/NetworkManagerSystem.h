/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef NETWORK_MANAGER_SYSTEM_H
#define NETWORK_MANAGER_SYSTEM_H

#include <glib.h>
#include "NetworkManagerDevice.h"


/* Prototypes for system/distribution dependent functions,
 * implemented in the backend files in backends/ directory
 */

void			nm_system_init (void);
gboolean		nm_system_device_has_active_routes			(NMDevice *dev);
void			nm_system_device_flush_routes				(NMDevice *dev);
void			nm_system_device_add_default_route_via_device(NMDevice *dev);
void			nm_system_device_flush_addresses			(NMDevice *dev);
void			nm_system_device_update_config_info		(NMDevice *dev);
gboolean		nm_system_device_setup_static_ip4_config	(NMDevice *dev);
void			nm_system_enable_loopback				(void);
void			nm_system_flush_loopback_routes			(void);
void			nm_system_delete_default_route			(void);
void			nm_system_flush_arp_cache				(void);
void			nm_system_kill_all_dhcp_daemons			(void);
void			nm_system_update_dns					(void);
void			nm_system_load_device_modules				(void);
void			nm_system_restart_mdns_responder			(void);
void			nm_system_device_add_ip6_link_address 		(NMDevice *dev);

/* Prototyps for system-layer network functions (ie setting IP address, etc) */
gboolean		nm_system_device_set_ip4_address			(NMDevice *dev, int ip4_address);
gboolean		nm_system_device_set_ip4_netmask			(NMDevice *dev, int ip4_netmask);
gboolean		nm_system_device_set_ip4_broadcast			(NMDevice *dev, int ip4_broadcast);
gboolean		nm_system_device_set_ip4_default_route		(NMDevice *dev, int ip4_def_route);
gboolean		nm_system_device_add_ip4_nameserver		(NMDevice *dev, guint32 ip4_nameserver);
void			nm_system_device_clear_ip4_nameservers		(NMDevice *dev);
gboolean		nm_system_device_add_domain_search			(NMDevice *dev, const char *search);
void			nm_system_device_clear_domain_searches		(NMDevice *dev);

#endif
