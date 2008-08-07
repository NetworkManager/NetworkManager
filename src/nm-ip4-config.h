/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef NM_IP4_CONFIG_H
#define NM_IP4_CONFIG_H

#include <glib/gtypes.h>
#include <glib-object.h>

#include "nm-setting-ip4-config.h"

#define NM_TYPE_IP4_CONFIG            (nm_ip4_config_get_type ())
#define NM_IP4_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IP4_CONFIG, NMIP4Config))
#define NM_IP4_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IP4_CONFIG, NMIP4ConfigClass))
#define NM_IS_IP4_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IP4_CONFIG))
#define NM_IS_IP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_IP4_CONFIG))
#define NM_IP4_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IP4_CONFIG, NMIP4ConfigClass))

typedef struct {
	GObject parent;
} NMIP4Config;

typedef struct {
	GObjectClass parent;
} NMIP4ConfigClass;

#define NM_IP4_CONFIG_ADDRESSES "addresses"
#define NM_IP4_CONFIG_HOSTNAME "hostname"
#define NM_IP4_CONFIG_NAMESERVERS "nameservers"
#define NM_IP4_CONFIG_DOMAINS "domains"
#define NM_IP4_CONFIG_NIS_DOMAIN "nis-domain"
#define NM_IP4_CONFIG_NIS_SERVERS "nis-servers"
#define NM_IP4_CONFIG_ROUTES "routes"

GType nm_ip4_config_get_type (void);


NMIP4Config *	nm_ip4_config_new				(void);
NMIP4Config *	nm_ip4_config_copy				(NMIP4Config *config);

void					nm_ip4_config_take_address		(NMIP4Config *config, NMSettingIP4Address *address);
void					nm_ip4_config_add_address		(NMIP4Config *config, NMSettingIP4Address *address);
void					nm_ip4_config_replace_address		(NMIP4Config *config, guint32 i, NMSettingIP4Address *new_address);
const NMSettingIP4Address *	nm_ip4_config_get_address		(NMIP4Config *config, guint32 i);
guint32					nm_ip4_config_get_num_addresses	(NMIP4Config *config);

guint32		nm_ip4_config_get_ptp_address		(NMIP4Config *config);
void			nm_ip4_config_set_ptp_address		(NMIP4Config *config, guint32 ptp_addr);

void			nm_ip4_config_add_nameserver		(NMIP4Config *config, guint32 nameserver);
guint32		nm_ip4_config_get_nameserver		(NMIP4Config *config, guint i);
guint32		nm_ip4_config_get_num_nameservers	(NMIP4Config *config);
void			nm_ip4_config_reset_nameservers		(NMIP4Config *config);

void			nm_ip4_config_take_route		(NMIP4Config *config, NMSettingIP4Route *route);
void			nm_ip4_config_add_route			(NMIP4Config *config, NMSettingIP4Route *route);
void			nm_ip4_config_replace_route		(NMIP4Config *config, guint32 i, NMSettingIP4Route *new_route);
const NMSettingIP4Route *	nm_ip4_config_get_route		(NMIP4Config *config, guint32 i);
guint32		nm_ip4_config_get_num_routes		(NMIP4Config *config);
void            nm_ip4_config_reset_routes		(NMIP4Config *config);

void			nm_ip4_config_set_hostname		(NMIP4Config *config, const char *hostname);
const char * 	nm_ip4_config_get_hostname		(NMIP4Config *config);

void			nm_ip4_config_add_domain			(NMIP4Config *config, const char *domain);
const char *	nm_ip4_config_get_domain			(NMIP4Config *config, guint i);
guint32		nm_ip4_config_get_num_domains		(NMIP4Config *config);

void			nm_ip4_config_add_search			(NMIP4Config *config, const char *search);
const char *	nm_ip4_config_get_search			(NMIP4Config *config, guint i);
guint32		nm_ip4_config_get_num_searches		(NMIP4Config *config);
void			nm_ip4_config_reset_searches		(NMIP4Config *config);

guint32		nm_ip4_config_get_mtu			(NMIP4Config *config);
void			nm_ip4_config_set_mtu			(NMIP4Config *config, guint32 mtu);

guint32		nm_ip4_config_get_mss			(NMIP4Config *config);
void			nm_ip4_config_set_mss			(NMIP4Config *config, guint32 mss);

/* Flags for nm_ip4_config_to_rtnl_addr() */
#define NM_RTNL_ADDR_NONE		0x0000
#define NM_RTNL_ADDR_ADDR		0x0001
#define NM_RTNL_ADDR_PTP_ADDR		0x0002
#define NM_RTNL_ADDR_PREFIX		0x0004
#define NM_RTNL_ADDR_BROADCAST	0x0008

#define NM_RTNL_ADDR_DEFAULT		(NM_RTNL_ADDR_ADDR | NM_RTNL_ADDR_PREFIX | NM_RTNL_ADDR_BROADCAST)
#define NM_RTNL_ADDR_PTP_DEFAULT	(NM_RTNL_ADDR_ADDR | NM_RTNL_ADDR_PREFIX | NM_RTNL_ADDR_PTP_ADDR)

struct rtnl_addr *nm_ip4_config_to_rtnl_addr (NMIP4Config *config, guint32 i, guint32 flags);

#endif /* NM_IP4_CONFIG_H */
