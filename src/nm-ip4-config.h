/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager
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
 * Copyright (C) 2008–2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_IP4_CONFIG_H__
#define __NETWORKMANAGER_IP4_CONFIG_H__

#include "nm-exported-object.h"
#include "nm-setting-ip4-config.h"

#define NM_TYPE_IP4_CONFIG (nm_ip4_config_get_type ())
#define NM_IP4_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IP4_CONFIG, NMIP4Config))
#define NM_IP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IP4_CONFIG, NMIP4ConfigClass))
#define NM_IS_IP4_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IP4_CONFIG))
#define NM_IS_IP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_IP4_CONFIG))
#define NM_IP4_CONFIG_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IP4_CONFIG, NMIP4ConfigClass))

struct _NMIP4ConfigPrivate;

struct _NMIP4Config {
	NMExportedObject parent;

	/* private */
	struct _NMIP4ConfigPrivate *priv;
};

typedef struct {
	NMExportedObjectClass parent;
} NMIP4ConfigClass;

/* internal */
#define NM_IP4_CONFIG_IFINDEX "ifindex"

/* public*/
#define NM_IP4_CONFIG_ADDRESS_DATA "address-data"
#define NM_IP4_CONFIG_ROUTE_DATA "route-data"
#define NM_IP4_CONFIG_GATEWAY "gateway"
#define NM_IP4_CONFIG_NAMESERVERS "nameservers"
#define NM_IP4_CONFIG_DOMAINS "domains"
#define NM_IP4_CONFIG_SEARCHES "searches"
#define NM_IP4_CONFIG_DNS_OPTIONS "dns-options"
#define NM_IP4_CONFIG_WINS_SERVERS "wins-servers"

/* deprecated */
#define NM_IP4_CONFIG_ADDRESSES "addresses"
#define NM_IP4_CONFIG_ROUTES "routes"

GType nm_ip4_config_get_type (void);


NMIP4Config * nm_ip4_config_new (int ifindex);

int nm_ip4_config_get_ifindex (const NMIP4Config *config);

/* Integration with nm-platform and nm-setting */
NMIP4Config *nm_ip4_config_capture (int ifindex, gboolean capture_resolv_conf);
gboolean nm_ip4_config_commit (const NMIP4Config *config, int ifindex, gboolean routes_full_sync, gint64 default_route_metric);
void nm_ip4_config_merge_setting (NMIP4Config *config, NMSettingIPConfig *setting, guint32 default_route_metric);
NMSetting *nm_ip4_config_create_setting (const NMIP4Config *config);

/* Utility functions */
void nm_ip4_config_merge (NMIP4Config *dst, const NMIP4Config *src, NMIPConfigMergeFlags merge_flags);
void nm_ip4_config_subtract (NMIP4Config *dst, const NMIP4Config *src);
void nm_ip4_config_intersect (NMIP4Config *dst, const NMIP4Config *src);
gboolean nm_ip4_config_replace (NMIP4Config *dst, const NMIP4Config *src, gboolean *relevant_changes);
gboolean nm_ip4_config_destination_is_direct (const NMIP4Config *config, guint32 dest, guint8 plen);
void nm_ip4_config_dump (const NMIP4Config *config, const char *detail);

/* Gateways */
void nm_ip4_config_set_never_default (NMIP4Config *config, gboolean never_default);
gboolean nm_ip4_config_get_never_default (const NMIP4Config *config);
void nm_ip4_config_set_gateway (NMIP4Config *config, guint32 gateway);
void nm_ip4_config_unset_gateway (NMIP4Config *config);
gboolean nm_ip4_config_has_gateway (const NMIP4Config *config);
guint32 nm_ip4_config_get_gateway (const NMIP4Config *config);
gint64 nm_ip4_config_get_route_metric (const NMIP4Config *config);

/* Addresses */
void nm_ip4_config_reset_addresses (NMIP4Config *config);
void nm_ip4_config_add_address (NMIP4Config *config, const NMPlatformIP4Address *address);
void nm_ip4_config_del_address (NMIP4Config *config, guint i);
guint nm_ip4_config_get_num_addresses (const NMIP4Config *config);
const NMPlatformIP4Address *nm_ip4_config_get_address (const NMIP4Config *config, guint i);
gboolean nm_ip4_config_address_exists (const NMIP4Config *config, const NMPlatformIP4Address *address);
gboolean nm_ip4_config_addresses_sort (NMIP4Config *config);

/* Routes */
void nm_ip4_config_reset_routes (NMIP4Config *config);
void nm_ip4_config_add_route (NMIP4Config *config, const NMPlatformIP4Route *route);
void nm_ip4_config_del_route (NMIP4Config *config, guint i);
guint32 nm_ip4_config_get_num_routes (const NMIP4Config *config);
const NMPlatformIP4Route *nm_ip4_config_get_route (const NMIP4Config *config, guint32 i);

const NMPlatformIP4Route *nm_ip4_config_get_direct_route_for_host (const NMIP4Config *config, guint32 host);

/* Nameservers */
void nm_ip4_config_reset_nameservers (NMIP4Config *config);
void nm_ip4_config_add_nameserver (NMIP4Config *config, guint32 nameserver);
void nm_ip4_config_del_nameserver (NMIP4Config *config, guint i);
guint32 nm_ip4_config_get_num_nameservers (const NMIP4Config *config);
guint32 nm_ip4_config_get_nameserver (const NMIP4Config *config, guint i);

/* Domains */
void nm_ip4_config_reset_domains (NMIP4Config *config);
void nm_ip4_config_add_domain (NMIP4Config *config, const char *domain);
void nm_ip4_config_del_domain (NMIP4Config *config, guint i);
guint32 nm_ip4_config_get_num_domains (const NMIP4Config *config);
const char * nm_ip4_config_get_domain (const NMIP4Config *config, guint i);

/* Search lists */
void nm_ip4_config_reset_searches (NMIP4Config *config);
void nm_ip4_config_add_search (NMIP4Config *config, const char *search);
void nm_ip4_config_del_search (NMIP4Config *config, guint i);
guint32 nm_ip4_config_get_num_searches (const NMIP4Config *config);
const char * nm_ip4_config_get_search (const NMIP4Config *config, guint i);

/* DNS options */
void nm_ip4_config_reset_dns_options (NMIP4Config *config);
void nm_ip4_config_add_dns_option (NMIP4Config *config, const char *option);
void nm_ip4_config_del_dns_option (NMIP4Config *config, guint i);
guint32 nm_ip4_config_get_num_dns_options (const NMIP4Config *config);
const char * nm_ip4_config_get_dns_option (const NMIP4Config *config, guint i);

/* MSS */
void nm_ip4_config_set_mss (NMIP4Config *config, guint32 mss);
guint32 nm_ip4_config_get_mss (const NMIP4Config *config);

/* NIS */
void nm_ip4_config_reset_nis_servers (NMIP4Config *config);
void nm_ip4_config_add_nis_server (NMIP4Config *config, guint32 nis);
void nm_ip4_config_del_nis_server (NMIP4Config *config, guint i);
guint32 nm_ip4_config_get_num_nis_servers (const NMIP4Config *config);
guint32 nm_ip4_config_get_nis_server (const NMIP4Config *config, guint i);
void nm_ip4_config_set_nis_domain (NMIP4Config *config, const char *domain);
const char * nm_ip4_config_get_nis_domain (const NMIP4Config *config);

/* WINS */
void nm_ip4_config_reset_wins (NMIP4Config *config);
void nm_ip4_config_add_wins (NMIP4Config *config, guint32 wins);
void nm_ip4_config_del_wins (NMIP4Config *config, guint i);
guint32 nm_ip4_config_get_num_wins (const NMIP4Config *config);
guint32 nm_ip4_config_get_wins (const NMIP4Config *config, guint i);

/* MTU */
void nm_ip4_config_set_mtu (NMIP4Config *config, guint32 mtu, NMIPConfigSource source);
guint32 nm_ip4_config_get_mtu (const NMIP4Config *config);
NMIPConfigSource nm_ip4_config_get_mtu_source (const NMIP4Config *config);

/* Metered */
void nm_ip4_config_set_metered (NMIP4Config *config, gboolean metered);
gboolean nm_ip4_config_get_metered (const NMIP4Config *config);

void nm_ip4_config_hash (const NMIP4Config *config, GChecksum *sum, gboolean dns_only);
gboolean nm_ip4_config_equal (const NMIP4Config *a, const NMIP4Config *b);

/******************************************************/
/* Testing-only functions */

gboolean nm_ip4_config_capture_resolv_conf (GArray *nameservers, GPtrArray *dns_options,
                                            const char *rc_contents);

#endif /* __NETWORKMANAGER_IP4_CONFIG_H__ */
