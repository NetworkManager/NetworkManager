/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <net/if_arp.h>

#include "nm-utils/nm-dedup-multi.h"

#include "nm-utils.h"
#include "nm-dhcp-utils.h"
#include "NetworkManagerUtils.h"
#include "platform/nm-platform.h"
#include "nm-dhcp-client-logging.h"
#include "systemd/nm-sd.h"

/*****************************************************************************/

#define NM_TYPE_DHCP_SYSTEMD            (nm_dhcp_systemd_get_type ())
#define NM_DHCP_SYSTEMD(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_SYSTEMD, NMDhcpSystemd))
#define NM_DHCP_SYSTEMD_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_SYSTEMD, NMDhcpSystemdClass))
#define NM_IS_DHCP_SYSTEMD(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_SYSTEMD))
#define NM_IS_DHCP_SYSTEMD_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP_SYSTEMD))
#define NM_DHCP_SYSTEMD_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_SYSTEMD, NMDhcpSystemdClass))

typedef struct _NMDhcpSystemd NMDhcpSystemd;
typedef struct _NMDhcpSystemdClass NMDhcpSystemdClass;

static GType nm_dhcp_systemd_get_type (void);

/*****************************************************************************/

typedef struct {
	sd_dhcp_client *client4;
	sd_dhcp6_client *client6;
	char *lease_file;

	guint request_count;

	gboolean privacy;
	gboolean info_only;
} NMDhcpSystemdPrivate;

struct _NMDhcpSystemd {
	NMDhcpClient parent;
	NMDhcpSystemdPrivate _priv;
};

struct _NMDhcpSystemdClass {
	NMDhcpClientClass parent;
};

G_DEFINE_TYPE (NMDhcpSystemd, nm_dhcp_systemd, NM_TYPE_DHCP_CLIENT)

#define NM_DHCP_SYSTEMD_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDhcpSystemd, NM_IS_DHCP_SYSTEMD)

/*****************************************************************************/

#define DHCP_OPTION_NIS_DOMAIN         40
#define DHCP_OPTION_NIS_SERVERS        41

/* Internal values */
#define DHCP_OPTION_IP_ADDRESS       1024
#define DHCP_OPTION_EXPIRY           1025
#define DHCP6_OPTION_IP_ADDRESS      1026
#define DHCP6_OPTION_PREFIXLEN       1027
#define DHCP6_OPTION_PREFERRED_LIFE  1028
#define DHCP6_OPTION_MAX_LIFE        1029
#define DHCP6_OPTION_STARTS          1030
#define DHCP6_OPTION_LIFE_STARTS     1031
#define DHCP6_OPTION_RENEW           1032
#define DHCP6_OPTION_REBIND          1033
#define DHCP6_OPTION_IAID            1034

typedef struct {
	guint num;
	const char *name;
	gboolean include;
} ReqOption;

#define REQPREFIX "requested_"

static const ReqOption dhcp4_requests[] = {
	{ SD_DHCP_OPTION_SUBNET_MASK,                    REQPREFIX "subnet_mask",                     TRUE },
	{ SD_DHCP_OPTION_TIME_OFFSET,                    REQPREFIX "time_offset",                     TRUE },
	{ SD_DHCP_OPTION_ROUTER,                         REQPREFIX "routers",                         TRUE },
	{ SD_DHCP_OPTION_DOMAIN_NAME_SERVER,             REQPREFIX "domain_name_servers",             TRUE },
	{ SD_DHCP_OPTION_HOST_NAME,                      REQPREFIX "host_name",                       TRUE },
	{ SD_DHCP_OPTION_DOMAIN_NAME,                    REQPREFIX "domain_name",                     TRUE },
	{ SD_DHCP_OPTION_INTERFACE_MTU,                  REQPREFIX "interface_mtu",                   TRUE },
	{ SD_DHCP_OPTION_BROADCAST,                      REQPREFIX "broadcast_address",               TRUE },
	{ SD_DHCP_OPTION_STATIC_ROUTE,                   REQPREFIX "static_routes",                   TRUE },
	{ DHCP_OPTION_NIS_DOMAIN,                        REQPREFIX "nis_domain",                      TRUE },
	{ DHCP_OPTION_NIS_SERVERS,                       REQPREFIX "nis_servers",                     TRUE },
	{ SD_DHCP_OPTION_NTP_SERVER,                     REQPREFIX "ntp_servers",                     TRUE },
	{ SD_DHCP_OPTION_SERVER_IDENTIFIER,              REQPREFIX "dhcp_server_identifier",          TRUE },
	{ SD_DHCP_OPTION_DOMAIN_SEARCH_LIST,             REQPREFIX "domain_search",                   TRUE },
	{ SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,         REQPREFIX "rfc3442_classless_static_routes", TRUE },
	{ SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE, REQPREFIX "ms_classless_static_routes",      TRUE },
	{ SD_DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY,    REQPREFIX "wpad",                            TRUE },

	/* Internal values */
	{ SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME,          REQPREFIX "expiry",                          FALSE },
	{ SD_DHCP_OPTION_CLIENT_IDENTIFIER,              REQPREFIX "dhcp_client_identifier",          FALSE },
	{ DHCP_OPTION_IP_ADDRESS,                        REQPREFIX "ip_address",                      FALSE },
	{ 0, NULL, FALSE }
};

static const ReqOption dhcp6_requests[] = {
	{ SD_DHCP6_OPTION_CLIENTID,                      REQPREFIX "dhcp6_client_id",     TRUE },

	/* Don't request server ID by default; some servers don't reply to
	 * Information Requests that request the Server ID.
	 */
	{ SD_DHCP6_OPTION_SERVERID,                      REQPREFIX "dhcp6_server_id",     FALSE },

	{ SD_DHCP6_OPTION_DNS_SERVERS,                   REQPREFIX "dhcp6_name_servers",  TRUE },
	{ SD_DHCP6_OPTION_DOMAIN_LIST,                   REQPREFIX "dhcp6_domain_search", TRUE },
	{ SD_DHCP6_OPTION_SNTP_SERVERS,                  REQPREFIX "dhcp6_sntp_servers",  TRUE },

	/* Internal values */
	{ DHCP6_OPTION_IP_ADDRESS,                       REQPREFIX "ip6_address",         FALSE },
	{ DHCP6_OPTION_PREFIXLEN,                        REQPREFIX "ip6_prefixlen",       FALSE },
	{ DHCP6_OPTION_PREFERRED_LIFE,                   REQPREFIX "preferred_life",      FALSE },
	{ DHCP6_OPTION_MAX_LIFE,                         REQPREFIX "max_life",            FALSE },
	{ DHCP6_OPTION_STARTS,                           REQPREFIX "starts",              FALSE },
	{ DHCP6_OPTION_LIFE_STARTS,                      REQPREFIX "life_starts",         FALSE },
	{ DHCP6_OPTION_RENEW,                            REQPREFIX "renew",               FALSE },
	{ DHCP6_OPTION_REBIND,                           REQPREFIX "rebind",              FALSE },
	{ DHCP6_OPTION_IAID,                             REQPREFIX "iaid",                FALSE },
	{ 0, NULL, FALSE }
};

static void
take_option (GHashTable *options,
             const ReqOption *requests,
             guint option,
             char *value)
{
	guint i;

	g_return_if_fail (value != NULL);

	for (i = 0; requests[i].name; i++) {
		if (requests[i].num == option) {
			g_hash_table_insert (options,
			                     (gpointer) (requests[i].name + NM_STRLEN (REQPREFIX)),
			                     value);
			break;
		}
	}
	/* Option should always be found */
	g_assert (requests[i].name);
}

static void
add_option (GHashTable *options, const ReqOption *requests, guint option, const char *value)
{
	if (options)
		take_option (options, requests, option, g_strdup (value));
}

static void
add_option_u32 (GHashTable *options, const ReqOption *requests, guint option, guint32 value)
{
	if (options)
		take_option (options, requests, option, g_strdup_printf ("%u", value));
}

static void
add_option_u64 (GHashTable *options, const ReqOption *requests, guint option, guint64 value)
{
	if (options)
		take_option (options, requests, option, g_strdup_printf ("%" G_GUINT64_FORMAT, value));
}

static void
add_requests_to_options (GHashTable *options, const ReqOption *requests)
{
	guint i;

	for (i = 0; options && requests[i].name; i++) {
		if (requests[i].include)
			g_hash_table_insert (options, (gpointer) requests[i].name, g_strdup ("1"));
	}
}

#define LOG_LEASE(domain, ...) \
G_STMT_START { \
	if (log_lease) { \
		_LOG2I ((domain), (iface), "  "__VA_ARGS__); \
	} \
} G_STMT_END

static NMIP4Config *
lease_to_ip4_config (NMDedupMultiIndex *multi_idx,
                     const char *iface,
                     int ifindex,
                     sd_dhcp_lease *lease,
                     GHashTable *options,
                     guint32 route_table,
                     guint32 route_metric,
                     gboolean log_lease,
                     GError **error)
{
	NMIP4Config *ip4_config = NULL;
	struct in_addr tmp_addr;
	const struct in_addr *addr_list;
	char buf[INET_ADDRSTRLEN];
	const char *s;
	guint32 lifetime = 0, i;
	NMPlatformIP4Address address;
	nm_auto_free_gstring GString *str = NULL;
	gs_free sd_dhcp_route **routes = NULL;
	const char *const*search_domains = NULL;
	guint16 mtu;
	int r, num;
	guint64 end_time;
	const void *data;
	gsize data_len;
	gboolean metered = FALSE;
	gboolean static_default_gateway = FALSE;
	gboolean gateway_has = FALSE;
	in_addr_t gateway = 0;

	g_return_val_if_fail (lease != NULL, NULL);

	ip4_config = nm_ip4_config_new (multi_idx, ifindex);

	/* Address */
	sd_dhcp_lease_get_address (lease, &tmp_addr);
	memset (&address, 0, sizeof (address));
	address.address = tmp_addr.s_addr;
	address.peer_address = tmp_addr.s_addr;
	s = nm_utils_inet4_ntop (tmp_addr.s_addr, NULL);
	LOG_LEASE (LOGD_DHCP4, "address %s", s);
	add_option (options, dhcp4_requests, DHCP_OPTION_IP_ADDRESS, s);

	/* Prefix/netmask */
	sd_dhcp_lease_get_netmask (lease, &tmp_addr);
	address.plen = nm_utils_ip4_netmask_to_prefix (tmp_addr.s_addr);
	LOG_LEASE (LOGD_DHCP4, "plen %d", address.plen);
	add_option (options,
	            dhcp4_requests,
	            SD_DHCP_OPTION_SUBNET_MASK,
	            nm_utils_inet4_ntop (tmp_addr.s_addr, NULL));

	/* Lease time */
	sd_dhcp_lease_get_lifetime (lease, &lifetime);
	address.timestamp = nm_utils_get_monotonic_timestamp_s ();
	address.lifetime = address.preferred = lifetime;
	end_time = (guint64) time (NULL) + lifetime;
	LOG_LEASE (LOGD_DHCP4, "expires in %" G_GUINT32_FORMAT " seconds", lifetime);
	add_option_u64 (options,
	                dhcp4_requests,
	                SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
	                end_time);

	address.addr_source = NM_IP_CONFIG_SOURCE_DHCP;
	nm_ip4_config_add_address (ip4_config, &address);

	/* DNS Servers */
	num = sd_dhcp_lease_get_dns (lease, &addr_list);
	if (num > 0) {
		nm_gstring_prepare (&str);
		for (i = 0; i < num; i++) {
			if (addr_list[i].s_addr) {
				nm_ip4_config_add_nameserver (ip4_config, addr_list[i].s_addr);
				s = nm_utils_inet4_ntop (addr_list[i].s_addr, NULL);
				LOG_LEASE (LOGD_DHCP4, "nameserver '%s'", s);
				g_string_append_printf (str, "%s%s", str->len ? " " : "", s);
			}
		}
		if (str->len)
			add_option (options, dhcp4_requests, SD_DHCP_OPTION_DOMAIN_NAME_SERVER, str->str);
	}

	/* Search domains */
	num = sd_dhcp_lease_get_search_domains (lease, (char ***) &search_domains);
	if (num > 0) {
		nm_gstring_prepare (&str);
		for (i = 0; i < num; i++) {
			nm_ip4_config_add_search (ip4_config, search_domains[i]);
			g_string_append_printf (str, "%s%s", str->len ? " " : "", search_domains[i]);
			LOG_LEASE (LOGD_DHCP4, "domain search '%s'", search_domains[i]);
		}
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_DOMAIN_SEARCH_LIST, str->str);
	}

	/* Domain Name */
	r = sd_dhcp_lease_get_domainname (lease, &s);
	if (r == 0) {
		/* Multiple domains sometimes stuffed into option 15 "Domain Name".
		 * As systemd escapes such characters, split them at \\032. */
		char **domains = g_strsplit (s, "\\032", 0);
		char **d;

		for (d = domains; *d; d++) {
			LOG_LEASE (LOGD_DHCP4, "domain name '%s'", *d);
			nm_ip4_config_add_domain (ip4_config, *d);
		}
		g_strfreev (domains);
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_DOMAIN_NAME, s);
	}

	/* Hostname */
	r = sd_dhcp_lease_get_hostname (lease, &s);
	if (r == 0) {
		LOG_LEASE (LOGD_DHCP4, "hostname '%s'", s);
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_HOST_NAME, s);
	}

	/* Routes */
	num = sd_dhcp_lease_get_routes (lease, &routes);
	if (num > 0) {
		nm_gstring_prepare (&str);
		for (i = 0; i < num; i++) {
			NMPlatformIP4Route route = { 0 };
			const char *gw_str;
			guint8 plen;
			struct in_addr a;

			if (sd_dhcp_route_get_destination (routes[i], &a) < 0)
				continue;

			if (   sd_dhcp_route_get_destination_prefix_length (routes[i], &plen) < 0
			    || plen > 32)
				continue;

			route.plen = plen;
			route.network = nm_utils_ip4_address_clear_host_address (a.s_addr, plen);

			if (sd_dhcp_route_get_gateway (routes[i], &a) < 0)
				continue;
			route.gateway = a.s_addr;

			if (route.plen) {
				route.rt_source = NM_IP_CONFIG_SOURCE_DHCP;
				route.metric = route_metric;
				route.table_coerced = nm_platform_route_table_coerce (route_table);
				nm_ip4_config_add_route (ip4_config, &route, NULL);

				s = nm_utils_inet4_ntop (route.network, buf);
				gw_str = nm_utils_inet4_ntop (route.gateway, NULL);
				LOG_LEASE (LOGD_DHCP4, "static route %s/%d gw %s", s, route.plen, gw_str);

				g_string_append_printf (str, "%s%s/%d %s", str->len ? " " : "", s, route.plen, gw_str);
			} else {
				if (!static_default_gateway) {
					static_default_gateway = TRUE;
					gateway_has = TRUE;
					gateway = route.gateway;

					s = nm_utils_inet4_ntop (route.gateway, NULL);
					LOG_LEASE (LOGD_DHCP4, "gateway %s", s);
					add_option (options, dhcp4_requests, SD_DHCP_OPTION_ROUTER, s);
				}
			}
		}
		if (str->len)
			add_option (options, dhcp4_requests, SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE, str->str);
	}

	/* If the DHCP server returns both a Classless Static Routes option and a
	 * Router option, the DHCP client MUST ignore the Router option [RFC 3442].
	 * Be more lenient and ignore the Router option only if Classless Static
	 * Routes contain a default gateway (as other DHCP backends do).
	 */
	/* Gateway */
	if (!static_default_gateway) {
		r = sd_dhcp_lease_get_router (lease, &tmp_addr);
		if (r == 0) {
			gateway_has = TRUE;
			gateway = tmp_addr.s_addr;
			s = nm_utils_inet4_ntop (tmp_addr.s_addr, NULL);
			LOG_LEASE (LOGD_DHCP4, "gateway %s", s);
			add_option (options, dhcp4_requests, SD_DHCP_OPTION_ROUTER, s);
		}
	}

	if (gateway_has) {
		const NMPlatformIP4Route rt = {
			.rt_source = NM_IP_CONFIG_SOURCE_DHCP,
			.gateway = gateway,
			.table_coerced = nm_platform_route_table_coerce (route_table),
			.metric = route_metric,
		};

		nm_ip4_config_add_route (ip4_config, &rt, NULL);
	}

	/* MTU */
	r = sd_dhcp_lease_get_mtu (lease, &mtu);
	if (r == 0 && mtu) {
		nm_ip4_config_set_mtu (ip4_config, mtu, NM_IP_CONFIG_SOURCE_DHCP);
		add_option_u32 (options, dhcp4_requests, SD_DHCP_OPTION_INTERFACE_MTU, mtu);
		LOG_LEASE (LOGD_DHCP4, "mtu %u", mtu);
	}

	/* NTP servers */
	num = sd_dhcp_lease_get_ntp (lease, &addr_list);
	if (num > 0) {
		nm_gstring_prepare (&str);
		for (i = 0; i < num; i++) {
			s = nm_utils_inet4_ntop (addr_list[i].s_addr, buf);
			LOG_LEASE (LOGD_DHCP4, "ntp server '%s'", s);
			g_string_append_printf (str, "%s%s", str->len ? " " : "", s);
		}
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_NTP_SERVER, str->str);
	}

	r = sd_dhcp_lease_get_vendor_specific (lease, &data, &data_len);
	if (r >= 0)
		metered = !!memmem (data, data_len, "ANDROID_METERED", NM_STRLEN ("ANDROID_METERED"));
	nm_ip4_config_set_metered (ip4_config, metered);

	return ip4_config;
}

/*****************************************************************************/

static char *
get_leasefile_path (int addr_family, const char *iface, const char *uuid)
{
	return g_strdup_printf (NMSTATEDIR "/internal%s-%s-%s.lease",
	                        addr_family == AF_INET6 ? "6" : "",
	                        uuid,
	                        iface);
}

static GSList *
nm_dhcp_systemd_get_lease_ip_configs (NMDedupMultiIndex *multi_idx,
                                      int addr_family,
                                      const char *iface,
                                      int ifindex,
                                      const char *uuid,
                                      guint32 route_table,
                                      guint32 route_metric)
{
	GSList *leases = NULL;
	gs_free char *path = NULL;
	sd_dhcp_lease *lease = NULL;
	NMIP4Config *ip4_config;
	int r;

	if (addr_family != AF_INET)
		return NULL;

	path = get_leasefile_path (addr_family, iface, uuid);
	r = dhcp_lease_load (&lease, path);
	if (r == 0 && lease) {
		ip4_config = lease_to_ip4_config (multi_idx, iface, ifindex, lease, NULL, route_table, route_metric, FALSE, NULL);
		if (ip4_config)
			leases = g_slist_append (leases, ip4_config);
		sd_dhcp_lease_unref (lease);
	}

	return leases;
}

/*****************************************************************************/

static void
_save_client_id (NMDhcpSystemd *self,
                 uint8_t type,
                 const uint8_t *client_id,
                 size_t len)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (client_id != NULL);
	g_return_if_fail (len > 0);

	if (!nm_dhcp_client_get_client_id (NM_DHCP_CLIENT (self))) {
		nm_dhcp_client_set_client_id_bin (NM_DHCP_CLIENT (self),
		                                  type, client_id, len);
	}
}

static void
bound4_handle (NMDhcpSystemd *self)
{
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (self);
	const char *iface = nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self));
	sd_dhcp_lease *lease;
	NMIP4Config *ip4_config;
	GHashTable *options;
	GError *error = NULL;
	int r;

	r = sd_dhcp_client_get_lease (priv->client4, &lease);
	if (r < 0 || !lease) {
		_LOGW ("no lease!");
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return;
	}

	_LOGD ("lease available");

	options = g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, g_free);
	ip4_config = lease_to_ip4_config (nm_dhcp_client_get_multi_idx (NM_DHCP_CLIENT (self)),
	                                  iface,
	                                  nm_dhcp_client_get_ifindex (NM_DHCP_CLIENT (self)),
	                                  lease,
	                                  options,
	                                  nm_dhcp_client_get_route_table (NM_DHCP_CLIENT (self)),
	                                  nm_dhcp_client_get_route_metric (NM_DHCP_CLIENT (self)),
	                                  TRUE,
	                                  &error);
	if (ip4_config) {
		const uint8_t *client_id = NULL;
		size_t client_id_len = 0;
		uint8_t type = 0;

		add_requests_to_options (options, dhcp4_requests);
		dhcp_lease_save (lease, priv->lease_file);

		sd_dhcp_client_get_client_id (priv->client4, &type, &client_id, &client_id_len);
		if (client_id)
			_save_client_id (self, type, client_id, client_id_len);

		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self),
		                          NM_DHCP_STATE_BOUND,
		                          G_OBJECT (ip4_config),
		                          options);
	} else {
		_LOGW ("%s", error->message);
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		g_clear_error (&error);
	}

	g_hash_table_destroy (options);
	g_clear_object (&ip4_config);
}

static void
dhcp_event_cb (sd_dhcp_client *client, int event, gpointer user_data)
{
	NMDhcpSystemd *self = NM_DHCP_SYSTEMD (user_data);
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (self);

	g_assert (priv->client4 == client);

	_LOGD ("client event %d", event);

	switch (event) {
	case SD_DHCP_CLIENT_EVENT_EXPIRED:
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (user_data), NM_DHCP_STATE_EXPIRE, NULL, NULL);
		break;
	case SD_DHCP_CLIENT_EVENT_STOP:
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (user_data), NM_DHCP_STATE_FAIL, NULL, NULL);
		break;
	case SD_DHCP_CLIENT_EVENT_RENEW:
	case SD_DHCP_CLIENT_EVENT_IP_CHANGE:
	case SD_DHCP_CLIENT_EVENT_IP_ACQUIRE:
		bound4_handle (self);
		break;
	default:
		_LOGW ("unhandled DHCP event %d", event);
		break;
	}
}

static guint16
get_arp_type (const GByteArray *hwaddr)
{
	if (hwaddr->len == ETH_ALEN)
		return ARPHRD_ETHER;
	else if (hwaddr->len == INFINIBAND_ALEN)
		return ARPHRD_INFINIBAND;
	else
		return ARPHRD_NONE;
}

static gboolean
ip4_start (NMDhcpClient *client, const char *dhcp_anycast_addr, const char *last_ip4_address)
{
	NMDhcpSystemd *self = NM_DHCP_SYSTEMD (client);
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (self);
	const char *iface = nm_dhcp_client_get_iface (client);
	const GByteArray *hwaddr;
	sd_dhcp_lease *lease = NULL;
	GBytes *override_client_id;
	const uint8_t *client_id = NULL;
	size_t client_id_len = 0;
	struct in_addr last_addr = { 0 };
	const char *hostname;
	int r, i;
	gboolean success = FALSE;
	guint16 arp_type;

	g_assert (priv->client4 == NULL);
	g_assert (priv->client6 == NULL);

	g_free (priv->lease_file);
	priv->lease_file = get_leasefile_path (AF_INET, iface, nm_dhcp_client_get_uuid (client));

	r = sd_dhcp_client_new (&priv->client4, FALSE);
	if (r < 0) {
		_LOGW ("failed to create client (%d)", r);
		return FALSE;
	}

	_LOGT ("dhcp-client4: set %p", priv->client4);

	r = sd_dhcp_client_attach_event (priv->client4, NULL, 0);
	if (r < 0) {
		_LOGW ("failed to attach event (%d)", r);
		goto error;
	}

	hwaddr = nm_dhcp_client_get_hw_addr (client);
	if (hwaddr) {
		arp_type= get_arp_type (hwaddr);
		if (arp_type == ARPHRD_NONE) {
			_LOGW ("failed to determine ARP type");
			goto error;
		}

		r = sd_dhcp_client_set_mac (priv->client4,
		                            hwaddr->data,
		                            hwaddr->len,
		                            arp_type);
		if (r < 0) {
			_LOGW ("failed to set MAC address (%d)", r);
			goto error;
		}
	}

	r = sd_dhcp_client_set_ifindex (priv->client4, nm_dhcp_client_get_ifindex (client));
	if (r < 0) {
		_LOGW ("failed to set ififindex (%d)", r);
		goto error;
	}

	r = sd_dhcp_client_set_callback (priv->client4, dhcp_event_cb, client);
	if (r < 0) {
		_LOGW ("failed to set callback (%d)", r);
		goto error;
	}

	r = sd_dhcp_client_set_request_broadcast (priv->client4, true);
	if (r < 0) {
		_LOGW ("failed to enable broadcast mode (%d)", r);
		goto error;
	}

	dhcp_lease_load (&lease, priv->lease_file);

	if (last_ip4_address)
		inet_pton (AF_INET, last_ip4_address, &last_addr);
	else if (lease)
		sd_dhcp_lease_get_address (lease, &last_addr);

	if (last_addr.s_addr) {
		r = sd_dhcp_client_set_request_address (priv->client4, &last_addr);
		if (r < 0) {
			_LOGW ("failed to set last IPv4 address (%d)", r);
			goto error;
		}
	}

	override_client_id = nm_dhcp_client_get_client_id (client);
	if (override_client_id) {
		client_id = g_bytes_get_data (override_client_id, &client_id_len);
		nm_assert (client_id && client_id_len >= 2);
		sd_dhcp_client_set_client_id (priv->client4,
		                              client_id[0],
		                              client_id + 1,
		                              NM_MIN (client_id_len - 1, _NM_SD_MAX_CLIENT_ID_LEN));
	} else if (lease) {
		r = sd_dhcp_lease_get_client_id (lease, (const void **) &client_id, &client_id_len);
		if (r == 0 && client_id_len >= 2) {
			sd_dhcp_client_set_client_id (priv->client4,
			                              client_id[0],
			                              client_id + 1,
			                              client_id_len - 1);
			_save_client_id (NM_DHCP_SYSTEMD (client),
			                 client_id[0],
			                 client_id + 1,
			                 client_id_len - 1);
		}
	}


	/* Add requested options */
	for (i = 0; dhcp4_requests[i].name; i++) {
		if (dhcp4_requests[i].include)
			sd_dhcp_client_set_request_option (priv->client4, dhcp4_requests[i].num);
	}

	hostname = nm_dhcp_client_get_hostname (client);
	if (hostname) {
		/* FIXME: sd-dhcp decides which hostname/FQDN option to send (12 or 81)
		 * only based on whether the hostname has a domain part or not. At the
		 * moment there is no way to force one or another.
		 */
		r = sd_dhcp_client_set_hostname (priv->client4, hostname);
		if (r < 0) {
			_LOGW ("failed to set DHCP hostname to '%s' (%d)", hostname, r);
			goto error;
		}
	}

	r = sd_dhcp_client_start (priv->client4);
	if (r < 0) {
		_LOGW ("failed to start client (%d)", r);
		goto error;
	}

	nm_dhcp_client_start_timeout (client);

	success = TRUE;

error:
	sd_dhcp_lease_unref (lease);
	if (!success)
		priv->client4 = sd_dhcp_client_unref (priv->client4);
	return success;
}

static NMIP6Config *
lease_to_ip6_config (NMDedupMultiIndex *multi_idx,
                     const char *iface,
                     int ifindex,
                     sd_dhcp6_lease *lease,
                     GHashTable *options,
                     gboolean log_lease,
                     gboolean info_only,
                     GError **error)
{
	struct in6_addr tmp_addr, *dns;
	uint32_t lft_pref, lft_valid;
	NMIP6Config *ip6_config;
	const char *addr_str;
	char **domains;
	nm_auto_free_gstring GString *str = NULL;
	int num, i;
	gint32 ts;

	g_return_val_if_fail (lease, NULL);
	ip6_config = nm_ip6_config_new (multi_idx, ifindex);
	ts = nm_utils_get_monotonic_timestamp_s ();

	/* Addresses */
	sd_dhcp6_lease_reset_address_iter (lease);
	nm_gstring_prepare (&str);
	while (sd_dhcp6_lease_get_address (lease, &tmp_addr, &lft_pref, &lft_valid) >= 0) {
		NMPlatformIP6Address address = {
			.plen = 128,
			.address = tmp_addr,
			.timestamp = ts,
			.lifetime = lft_valid,
			.preferred = lft_pref,
			.addr_source = NM_IP_CONFIG_SOURCE_DHCP,
		};

		nm_ip6_config_add_address (ip6_config, &address);

		addr_str = nm_utils_inet6_ntop (&tmp_addr, NULL);
		g_string_append_printf (str, "%s%s", str->len ? " " : "", addr_str);

		LOG_LEASE (LOGD_DHCP6,
		           "address %s",
		           nm_platform_ip6_address_to_string (&address, NULL, 0));
	};

	if (str->len)
		add_option (options, dhcp6_requests, DHCP6_OPTION_IP_ADDRESS, str->str);

	if (!info_only && nm_ip6_config_get_num_addresses (ip6_config) == 0) {
		g_object_unref (ip6_config);
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_FAILED,
		                     "no address received in managed mode");
		return NULL;
	}

	/* DNS servers */
	num = sd_dhcp6_lease_get_dns (lease, &dns);
	if (num > 0) {
		nm_gstring_prepare (&str);
		for (i = 0; i < num; i++) {
			nm_ip6_config_add_nameserver (ip6_config, &dns[i]);
			addr_str = nm_utils_inet6_ntop (&dns[i], NULL);
			g_string_append_printf (str, "%s%s", str->len ? " " : "", addr_str);
			LOG_LEASE (LOGD_DHCP6, "nameserver %s", addr_str);
		}
		add_option (options, dhcp6_requests, SD_DHCP6_OPTION_DNS_SERVERS, str->str);
	}

	/* Search domains */
	num = sd_dhcp6_lease_get_domains (lease, &domains);
	if (num > 0) {
		nm_gstring_prepare (&str);
		for (i = 0; i < num; i++) {
			nm_ip6_config_add_search (ip6_config, domains[i]);
			g_string_append_printf (str, "%s%s", str->len ? " " : "", domains[i]);
			LOG_LEASE (LOGD_DHCP6, "domain name '%s'", domains[i]);
		}
		add_option (options, dhcp6_requests, SD_DHCP6_OPTION_DOMAIN_LIST, str->str);
	}

	return ip6_config;
}

static void
bound6_handle (NMDhcpSystemd *self)
{
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (self);
	const char *iface = nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self));
	gs_unref_object NMIP6Config *ip6_config = NULL;
	gs_unref_hashtable GHashTable *options = NULL;
	gs_free_error GError *error = NULL;
	sd_dhcp6_lease *lease;
	int r;

	r = sd_dhcp6_client_get_lease (priv->client6, &lease);
	if (r < 0 || !lease) {
		_LOGW (" no lease!");
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return;
	}

	_LOGD ("lease available");

	options = g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, g_free);
	ip6_config = lease_to_ip6_config (nm_dhcp_client_get_multi_idx (NM_DHCP_CLIENT (self)),
	                                  iface,
	                                  nm_dhcp_client_get_ifindex (NM_DHCP_CLIENT (self)),
	                                  lease,
	                                  options,
	                                  TRUE,
	                                  priv->info_only,
	                                  &error);

	if (ip6_config) {
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self),
		                          NM_DHCP_STATE_BOUND,
		                          G_OBJECT (ip6_config),
		                          options);
	} else {
		_LOGW ("%s", error->message);
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
	}
}

static void
dhcp6_event_cb (sd_dhcp6_client *client, int event, gpointer user_data)
{
	NMDhcpSystemd *self = NM_DHCP_SYSTEMD (user_data);
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (self);

	g_assert (priv->client6 == client);

	_LOGD ("client event %d", event);

	switch (event) {
	case SD_DHCP6_CLIENT_EVENT_RETRANS_MAX:
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (user_data), NM_DHCP_STATE_TIMEOUT, NULL, NULL);
		break;
	case SD_DHCP6_CLIENT_EVENT_RESEND_EXPIRE:
	case SD_DHCP6_CLIENT_EVENT_STOP:
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (user_data), NM_DHCP_STATE_FAIL, NULL, NULL);
		break;
	case SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE:
	case SD_DHCP6_CLIENT_EVENT_INFORMATION_REQUEST:
		bound6_handle (self);
		break;
	default:
		_LOGW ("unhandled event %d", event);
		break;
	}
}

static gboolean
ip6_start (NMDhcpClient *client,
           const char *dhcp_anycast_addr,
           const struct in6_addr *ll_addr,
           gboolean info_only,
           NMSettingIP6ConfigPrivacy privacy,
           const GByteArray *duid,
           guint needed_prefixes)
{
	NMDhcpSystemd *self = NM_DHCP_SYSTEMD (client);
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (self);
	const char *iface = nm_dhcp_client_get_iface (client);
	const GByteArray *hwaddr;
	int r, i;

	g_assert (priv->client4 == NULL);
	g_assert (priv->client6 == NULL);
	g_return_val_if_fail (duid != NULL, FALSE);

	g_free (priv->lease_file);
	priv->lease_file = get_leasefile_path (AF_INET6, iface, nm_dhcp_client_get_uuid (client));
	priv->info_only = info_only;

	r = sd_dhcp6_client_new (&priv->client6);
	if (r < 0) {
		_LOGW ("failed to create client (%d)", r);
		return FALSE;
	}

	if (needed_prefixes > 0) {
		_LOGW ("dhcp-client6: prefix delegation not yet supported, won't supply %d prefixes\n",
		       needed_prefixes);
	}

	_LOGT ("dhcp-client6: set %p", priv->client6);

	if (info_only)
	    sd_dhcp6_client_set_information_request (priv->client6, 1);

	/* NM stores the entire DUID which includes the uint16 "type", while systemd
	 * wants the type passed separately from the following data.
	 */
	r = sd_dhcp6_client_set_duid (priv->client6,
	                              ntohs (((const guint16 *) duid->data)[0]),
	                              duid->data + 2,
	                              duid->len - 2);
	if (r < 0) {
		_LOGW ("failed to set DUID (%d)", r);
		return FALSE;
	}

	r = sd_dhcp6_client_attach_event (priv->client6, NULL, 0);
	if (r < 0) {
		_LOGW ("failed to attach event (%d)", r);
		goto error;
	}

	hwaddr = nm_dhcp_client_get_hw_addr (client);
	if (hwaddr) {
		r = sd_dhcp6_client_set_mac (priv->client6,
		                             hwaddr->data,
		                             hwaddr->len,
		                             get_arp_type (hwaddr));
		if (r < 0) {
			_LOGW ("failed to set MAC address (%d)", r);
			goto error;
		}
	}

	r = sd_dhcp6_client_set_ifindex (priv->client6, nm_dhcp_client_get_ifindex (client));
	if (r < 0) {
		_LOGW ("failed to set ifindex (%d)", r);
		goto error;
	}

	r = sd_dhcp6_client_set_callback (priv->client6, dhcp6_event_cb, client);
	if (r < 0) {
		_LOGW ("failed to set callback (%d)", r);
		goto error;
	}

	/* Add requested options */
	for (i = 0; dhcp6_requests[i].name; i++) {
		if (dhcp6_requests[i].include)
			sd_dhcp6_client_set_request_option (priv->client6, dhcp6_requests[i].num);
	}

	r = sd_dhcp6_client_set_local_address (priv->client6, ll_addr);
	if (r < 0) {
		_LOGW ("failed to set local address (%d)", r);
		goto error;
	}

	r = sd_dhcp6_client_start (priv->client6);
	if (r < 0) {
		_LOGW ("failed to start client (%d)", r);
		goto error;
	}

	nm_dhcp_client_start_timeout (client);

	return TRUE;

error:
	sd_dhcp6_client_unref (priv->client6);
	priv->client6 = NULL;
	return FALSE;
}

static void
stop (NMDhcpClient *client, gboolean release, const GByteArray *duid)
{
	NMDhcpSystemd *self = NM_DHCP_SYSTEMD (client);
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (self);
	int r = 0;

	_LOGT ("dhcp-client%d: stop %p",
	       priv->client4 ? '4' : '6',
	       priv->client4 ? (gpointer) priv->client4 : (gpointer) priv->client6);

	if (priv->client4) {
		sd_dhcp_client_set_callback (priv->client4, NULL, NULL);
		r = sd_dhcp_client_stop (priv->client4);
	} else if (priv->client6) {
		sd_dhcp6_client_set_callback (priv->client6, NULL, NULL);
		r = sd_dhcp6_client_stop (priv->client6);
	}

	if (r)
		_LOGW ("failed to stop client (%d)", r);
}

/*****************************************************************************/

static void
nm_dhcp_systemd_init (NMDhcpSystemd *self)
{
}

static void
dispose (GObject *object)
{
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE ((NMDhcpSystemd *) object);

	g_clear_pointer (&priv->lease_file, g_free);

	if (priv->client4) {
		sd_dhcp_client_stop (priv->client4);
		sd_dhcp_client_unref (priv->client4);
		priv->client4 = NULL;
	}

	if (priv->client6) {
		sd_dhcp6_client_stop (priv->client6);
		sd_dhcp6_client_unref (priv->client6);
		priv->client6 = NULL;
	}

	G_OBJECT_CLASS (nm_dhcp_systemd_parent_class)->dispose (object);
}

static void
nm_dhcp_systemd_class_init (NMDhcpSystemdClass *sdhcp_class)
{
	NMDhcpClientClass *client_class = NM_DHCP_CLIENT_CLASS (sdhcp_class);
	GObjectClass *object_class = G_OBJECT_CLASS (sdhcp_class);

	object_class->dispose = dispose;

	client_class->ip4_start = ip4_start;
	client_class->ip6_start = ip6_start;
	client_class->stop = stop;
}

const NMDhcpClientFactory _nm_dhcp_client_factory_internal = {
	.name = "internal",
	.get_type = nm_dhcp_systemd_get_type,
	.get_path = NULL,
	.get_lease_ip_configs = nm_dhcp_systemd_get_lease_ip_configs,
};
