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
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef NM_IP6_CONFIG_H
#define NM_IP6_CONFIG_H

#include <glib.h>
#include <glib-object.h>

#include "nm-setting-ip6-config.h"

#define NM_TYPE_IP6_CONFIG            (nm_ip6_config_get_type ())
#define NM_IP6_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IP6_CONFIG, NMIP6Config))
#define NM_IP6_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IP6_CONFIG, NMIP6ConfigClass))
#define NM_IS_IP6_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IP6_CONFIG))
#define NM_IS_IP6_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_IP6_CONFIG))
#define NM_IP6_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IP6_CONFIG, NMIP6ConfigClass))

typedef struct {
	GObject parent;
} NMIP6Config;

typedef struct {
	GObjectClass parent;
} NMIP6ConfigClass;

#define NM_IP6_CONFIG_ADDRESSES "addresses"
#define NM_IP6_CONFIG_NAMESERVERS "nameservers"
#define NM_IP6_CONFIG_DOMAINS "domains"
#define NM_IP6_CONFIG_ROUTES "routes"

GType nm_ip6_config_get_type (void);


NMIP6Config * nm_ip6_config_new                 (void);
void          nm_ip6_config_export              (NMIP6Config *config);
const char *  nm_ip6_config_get_dbus_path       (NMIP6Config *config);

void          nm_ip6_config_take_address        (NMIP6Config *config, NMIP6Address *address);
void          nm_ip6_config_add_address         (NMIP6Config *config, NMIP6Address *address);
void          nm_ip6_config_replace_address     (NMIP6Config *config, guint32 i, NMIP6Address *new_address);
NMIP6Address *nm_ip6_config_get_address         (NMIP6Config *config, guint32 i);
guint32       nm_ip6_config_get_num_addresses   (NMIP6Config *config);

const struct in6_addr *nm_ip6_config_get_ptp_address (NMIP6Config *config);
void          nm_ip6_config_set_ptp_address     (NMIP6Config *config, const struct in6_addr *ptp_addr);

void          nm_ip6_config_add_nameserver      (NMIP6Config *config, const struct in6_addr *nameserver);
const struct in6_addr *nm_ip6_config_get_nameserver      (NMIP6Config *config, guint i);
guint32       nm_ip6_config_get_num_nameservers (NMIP6Config *config);
void          nm_ip6_config_reset_nameservers   (NMIP6Config *config);

void          nm_ip6_config_take_route          (NMIP6Config *config, NMIP6Route *route);
void          nm_ip6_config_add_route           (NMIP6Config *config, NMIP6Route *route);
void          nm_ip6_config_replace_route       (NMIP6Config *config, guint32 i, NMIP6Route *new_route);
NMIP6Route *  nm_ip6_config_get_route           (NMIP6Config *config, guint32 i);
guint32       nm_ip6_config_get_num_routes      (NMIP6Config *config);
void          nm_ip6_config_reset_routes        (NMIP6Config *config);

void          nm_ip6_config_add_domain          (NMIP6Config *config, const char *domain);
const char *  nm_ip6_config_get_domain          (NMIP6Config *config, guint i);
guint32       nm_ip6_config_get_num_domains     (NMIP6Config *config);
void          nm_ip6_config_reset_domains       (NMIP6Config *config);

void          nm_ip6_config_add_search          (NMIP6Config *config, const char *search);
const char *  nm_ip6_config_get_search          (NMIP6Config *config, guint i);
guint32       nm_ip6_config_get_num_searches    (NMIP6Config *config);
void          nm_ip6_config_reset_searches      (NMIP6Config *config);

guint32       nm_ip6_config_get_mss             (NMIP6Config *config);
void          nm_ip6_config_set_mss             (NMIP6Config *config, guint32 mss);

gboolean      nm_ip6_config_get_never_default   (NMIP6Config *config);
void          nm_ip6_config_set_never_default   (NMIP6Config *config, gboolean never_default);

/* Flags for nm_ip6_config_to_rtnl_addr() */
#define NM_RTNL_ADDR_NONE		0x0000
#define NM_RTNL_ADDR_ADDR		0x0001
#define NM_RTNL_ADDR_PTP_ADDR		0x0002
#define NM_RTNL_ADDR_PREFIX		0x0004
#define NM_RTNL_ADDR_BROADCAST	0x0008

#define NM_RTNL_ADDR_DEFAULT		(NM_RTNL_ADDR_ADDR | NM_RTNL_ADDR_PREFIX | NM_RTNL_ADDR_BROADCAST)
#define NM_RTNL_ADDR_PTP_DEFAULT	(NM_RTNL_ADDR_ADDR | NM_RTNL_ADDR_PREFIX | NM_RTNL_ADDR_PTP_ADDR)

struct rtnl_addr *nm_ip6_config_to_rtnl_addr (NMIP6Config *config, guint32 i, guint32 flags);

typedef enum {
	NM_IP6_COMPARE_FLAG_NONE        = 0x00000000,  /* match nothing, kinda pointless */
	NM_IP6_COMPARE_FLAG_ADDRESSES   = 0x00000001,
	NM_IP6_COMPARE_FLAG_PTP_ADDRESS = 0x00000002,
	NM_IP6_COMPARE_FLAG_NAMESERVERS = 0x00000004,
	NM_IP6_COMPARE_FLAG_ROUTES      = 0x00000008,
	NM_IP6_COMPARE_FLAG_DOMAINS     = 0x00000010,
	NM_IP6_COMPARE_FLAG_SEARCHES    = 0x00000020,
	NM_IP6_COMPARE_FLAG_MSS         = 0x00000080,
	NM_IP6_COMPARE_FLAG_ALL         = 0xFFFFFFFF   /* match everything */
} NMIP6ConfigCompareFlags;

/* Returns a bitfield representing how the two IP6 configs differ */
NMIP6ConfigCompareFlags nm_ip6_config_diff (NMIP6Config *a, NMIP6Config *b);

#endif /* NM_IP6_CONFIG_H */
