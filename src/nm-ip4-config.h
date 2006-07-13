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

#ifndef NM_IP4_CONFIG_H
#define NM_IP4_CONFIG_H

#include <glib.h>

typedef struct NMIP4Config NMIP4Config;


NMIP4Config *	nm_ip4_config_new				(void);
NMIP4Config *	nm_ip4_config_copy				(NMIP4Config *config);
void			nm_ip4_config_ref				(NMIP4Config *config);
void			nm_ip4_config_unref				(NMIP4Config *config);

gboolean		nm_ip4_config_get_secondary		(NMIP4Config *config);
void			nm_ip4_config_set_secondary		(NMIP4Config *config, gboolean secondary);

guint32		nm_ip4_config_get_address		(NMIP4Config *config);
void			nm_ip4_config_set_address		(NMIP4Config *config, guint32 addr);

guint32		nm_ip4_config_get_ptp_address		(NMIP4Config *config);
void			nm_ip4_config_set_ptp_address		(NMIP4Config *config, guint32 ptp_addr);

guint32		nm_ip4_config_get_gateway		(NMIP4Config *config);
void			nm_ip4_config_set_gateway		(NMIP4Config *config, guint32 gateway);

guint32		nm_ip4_config_get_netmask		(NMIP4Config *config);
void			nm_ip4_config_set_netmask		(NMIP4Config *config, guint32 netmask);

guint32		nm_ip4_config_get_broadcast		(NMIP4Config *config);
void			nm_ip4_config_set_broadcast		(NMIP4Config *config, guint32 broadcast);

void			nm_ip4_config_add_nameserver		(NMIP4Config *config, guint32 nameserver);
guint32		nm_ip4_config_get_nameserver		(NMIP4Config *config, guint i);
guint32		nm_ip4_config_get_num_nameservers	(NMIP4Config *config);

void			nm_ip4_config_add_nis_server		(NMIP4Config *config, guint32 nis_server);
guint32		nm_ip4_config_get_nis_server		(NMIP4Config *config, guint i);
guint32		nm_ip4_config_get_num_nis_servers	(NMIP4Config *config);

void			nm_ip4_config_set_hostname		(NMIP4Config *config, const char *hostname);
const char * 	nm_ip4_config_get_hostname		(NMIP4Config *config);

void			nm_ip4_config_set_nis_domain		(NMIP4Config *config, const char *domain);
const char *	nm_ip4_config_get_nis_domain		(NMIP4Config *config);

void			nm_ip4_config_add_domain			(NMIP4Config *config, const char *domain);
const char *	nm_ip4_config_get_domain			(NMIP4Config *config, guint i);
guint32		nm_ip4_config_get_num_domains		(NMIP4Config *config);

guint32		nm_ip4_config_get_mtu			(NMIP4Config *config);
void			nm_ip4_config_set_mtu			(NMIP4Config *config, guint32 mtu);

guint32		nm_ip4_config_get_mss			(NMIP4Config *config);
void			nm_ip4_config_set_mss			(NMIP4Config *config, guint32 mss);

/* Flags for nm_ip4_config_to_rtnl_addr() */
#define NM_RTNL_ADDR_NONE		0x0000
#define NM_RTNL_ADDR_ADDR		0x0001
#define NM_RTNL_ADDR_PTP_ADDR		0x0002
#define NM_RTNL_ADDR_NETMASK		0x0004
#define NM_RTNL_ADDR_BROADCAST	0x0008

#define NM_RTNL_ADDR_DEFAULT		(NM_RTNL_ADDR_ADDR | NM_RTNL_ADDR_NETMASK | NM_RTNL_ADDR_BROADCAST)
#define NM_RTNL_ADDR_PTP_DEFAULT	(NM_RTNL_ADDR_ADDR | NM_RTNL_ADDR_NETMASK | NM_RTNL_ADDR_PTP_ADDR)

struct rtnl_addr *	nm_ip4_config_to_rtnl_addr	(NMIP4Config *config, guint32 flags);


#endif
