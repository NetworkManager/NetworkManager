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

guint32		nm_ip4_config_get_address		(NMIP4Config *config);
void			nm_ip4_config_set_address		(NMIP4Config *config, guint32 addr);

guint32		nm_ip4_config_get_gateway		(NMIP4Config *config);
void			nm_ip4_config_set_gateway		(NMIP4Config *config, guint32 gateway);

guint32		nm_ip4_config_get_netmask		(NMIP4Config *config);
void			nm_ip4_config_set_netmask		(NMIP4Config *config, guint32 netmask);

guint32		nm_ip4_config_get_broadcast		(NMIP4Config *config);
void			nm_ip4_config_set_broadcast		(NMIP4Config *config, guint32 broadcast);

void			nm_ip4_config_add_nameserver		(NMIP4Config *config, guint32 nameserver);
guint32		nm_ip4_config_get_nameserver		(NMIP4Config *config, guint index);
guint32		nm_ip4_config_get_nameserver_id	(NMIP4Config *config, guint index);
void			nm_ip4_config_set_nameserver_id	(NMIP4Config *config, guint index, guint32 id);
guint32		nm_ip4_config_get_num_nameservers	(NMIP4Config *config);

void			nm_ip4_config_add_domain			(NMIP4Config *config, const char *domain);
const char *	nm_ip4_config_get_domain			(NMIP4Config *config, guint index);
guint32		nm_ip4_config_get_domain_id		(NMIP4Config *config, guint index);
void			nm_ip4_config_set_domain_id		(NMIP4Config *config, guint index, guint32 id);
guint32		nm_ip4_config_get_num_domains		(NMIP4Config *config);

#endif
