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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <net/if_arp.h>

#include "nm-utils/nm-dedup-multi.h"
#include "nm-utils/unaligned.h"

#include "nm-utils.h"
#include "nm-config.h"
#include "nm-dhcp-utils.h"
#include "nm-core-utils.h"
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

	bool privacy:1;
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
	const char *name;
	uint16_t option_num;
	bool include;
} ReqOption;

#define REQPREFIX "requested_"

#define REQ(_num, _name, _include) \
	{ \
		.name = REQPREFIX""_name, \
		.option_num = _num, \
		.include = _include, \
	}

static const ReqOption dhcp4_requests[] = {
	REQ (SD_DHCP_OPTION_SUBNET_MASK,                    "subnet_mask",                     TRUE ),
	REQ (SD_DHCP_OPTION_TIME_OFFSET,                    "time_offset",                     TRUE ),
	REQ (SD_DHCP_OPTION_DOMAIN_NAME_SERVER,             "domain_name_servers",             TRUE ),
	REQ (SD_DHCP_OPTION_HOST_NAME,                      "host_name",                       TRUE ),
	REQ (SD_DHCP_OPTION_DOMAIN_NAME,                    "domain_name",                     TRUE ),
	REQ (SD_DHCP_OPTION_INTERFACE_MTU,                  "interface_mtu",                   TRUE ),
	REQ (SD_DHCP_OPTION_BROADCAST,                      "broadcast_address",               TRUE ),

	/* RFC 3442: The Classless Static Routes option code MUST appear in the parameter
	 *   request list prior to both the Router option code and the Static
	 *   Routes option code, if present. */
	REQ (SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,         "rfc3442_classless_static_routes", TRUE ),
	REQ (SD_DHCP_OPTION_ROUTER,                         "routers",                         TRUE ),
	REQ (SD_DHCP_OPTION_STATIC_ROUTE,                   "static_routes",                   TRUE ),

	REQ (DHCP_OPTION_NIS_DOMAIN,                        "nis_domain",                      TRUE ),
	REQ (DHCP_OPTION_NIS_SERVERS,                       "nis_servers",                     TRUE ),
	REQ (SD_DHCP_OPTION_NTP_SERVER,                     "ntp_servers",                     TRUE ),
	REQ (SD_DHCP_OPTION_SERVER_IDENTIFIER,              "dhcp_server_identifier",          TRUE ),
	REQ (SD_DHCP_OPTION_DOMAIN_SEARCH_LIST,             "domain_search",                   TRUE ),
	REQ (SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE, "ms_classless_static_routes",      TRUE ),
	REQ (SD_DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY,    "wpad",                            TRUE ),
	REQ (SD_DHCP_OPTION_ROOT_PATH,                      "root_path",                       TRUE ),

	/* Internal values */
	REQ (SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME,          "expiry",                          FALSE ),
	REQ (SD_DHCP_OPTION_CLIENT_IDENTIFIER,              "dhcp_client_identifier",          FALSE ),
	REQ (DHCP_OPTION_IP_ADDRESS,                        "ip_address",                      FALSE ),

	{ 0 }
};

static const ReqOption dhcp6_requests[] = {
	REQ (SD_DHCP6_OPTION_CLIENTID,                      "dhcp6_client_id",     FALSE ),

	/* Don't request server ID by default; some servers don't reply to
	 * Information Requests that request the Server ID.
	 */
	REQ (SD_DHCP6_OPTION_SERVERID,                      "dhcp6_server_id",     FALSE ),

	REQ (SD_DHCP6_OPTION_DNS_SERVERS,                   "dhcp6_name_servers",  TRUE ),
	REQ (SD_DHCP6_OPTION_DOMAIN_LIST,                   "dhcp6_domain_search", TRUE ),
	REQ (SD_DHCP6_OPTION_SNTP_SERVERS,                  "dhcp6_sntp_servers",  TRUE ),

	/* Internal values */
	REQ (DHCP6_OPTION_IP_ADDRESS,                       "ip6_address",         FALSE ),
	REQ (DHCP6_OPTION_PREFIXLEN,                        "ip6_prefixlen",       FALSE ),
	REQ (DHCP6_OPTION_PREFERRED_LIFE,                   "preferred_life",      FALSE ),
	REQ (DHCP6_OPTION_MAX_LIFE,                         "max_life",            FALSE ),
	REQ (DHCP6_OPTION_STARTS,                           "starts",              FALSE ),
	REQ (DHCP6_OPTION_LIFE_STARTS,                      "life_starts",         FALSE ),
	REQ (DHCP6_OPTION_RENEW,                            "renew",               FALSE ),
	REQ (DHCP6_OPTION_REBIND,                           "rebind",              FALSE ),
	REQ (DHCP6_OPTION_IAID,                             "iaid",                FALSE ),

	{ 0 }
};

static void
take_option (GHashTable *options,
             const ReqOption *requests,
             guint option,
             char *value)
{
	guint i;

	nm_assert (options);
	nm_assert (requests);
	nm_assert (value);

	for (i = 0; requests[i].name; i++) {
		nm_assert (g_str_has_prefix (requests[i].name, REQPREFIX));
		if (requests[i].option_num == option) {
			g_hash_table_insert (options,
			                     (gpointer) (requests[i].name + NM_STRLEN (REQPREFIX)),
			                     value);
			return;
		}
	}

	/* Option should always be found */
	nm_assert_not_reached ();
}

static void
add_option (GHashTable *options, const ReqOption *requests, guint option, const char *value)
{
	if (options)
		take_option (options, requests, option, g_strdup (value));
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

	if (!options)
		return;

	for (i = 0; requests[i].name; i++) {
		if (requests[i].include)
			g_hash_table_insert (options, (gpointer) requests[i].name, g_strdup ("1"));
	}
}

static GHashTable *
create_options_dict (void)
{
	return g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, g_free);
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
                     guint32 route_table,
                     guint32 route_metric,
                     gboolean log_lease,
                     GHashTable **out_options,
                     GError **error)
{
	gs_unref_object NMIP4Config *ip4_config = NULL;
	gs_unref_hashtable GHashTable *options = NULL;
	const struct in_addr *addr_list;
	char addr_str[NM_UTILS_INET_ADDRSTRLEN];
	const char *s;
	nm_auto_free_gstring GString *str = NULL;
	gs_free sd_dhcp_route **routes = NULL;
	const char *const*search_domains = NULL;
	guint16 mtu;
	int i, num;
	const void *data;
	gsize data_len;
	gboolean metered = FALSE;
	gboolean has_router_from_classless = FALSE;
	gboolean has_classless_route = FALSE;
	gboolean has_static_route = FALSE;
	const gint32 ts = nm_utils_get_monotonic_timestamp_s ();
	gint64 ts_time = time (NULL);
	struct in_addr a_address;
	struct in_addr a_netmask;
	const struct in_addr *a_router;
	guint32 a_plen;
	guint32 a_lifetime;

	g_return_val_if_fail (lease != NULL, NULL);

	if (sd_dhcp_lease_get_address (lease, &a_address) < 0) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "could not get address from lease");
		return NULL;
	}

	if (sd_dhcp_lease_get_netmask (lease, &a_netmask) < 0) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "could not get netmask from lease");
		return NULL;
	}

	if (sd_dhcp_lease_get_lifetime (lease, &a_lifetime) < 0) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "could not get lifetime from lease");
		return NULL;
	}

	ip4_config = nm_ip4_config_new (multi_idx, ifindex);

	options = out_options ? create_options_dict () : NULL;

	nm_utils_inet4_ntop (a_address.s_addr, addr_str);
	LOG_LEASE (LOGD_DHCP4, "address %s", addr_str);
	add_option (options, dhcp4_requests, DHCP_OPTION_IP_ADDRESS, addr_str);

	a_plen = nm_utils_ip4_netmask_to_prefix (a_netmask.s_addr);
	LOG_LEASE (LOGD_DHCP4, "plen %u", (guint) a_plen);
	add_option (options,
	            dhcp4_requests,
	            SD_DHCP_OPTION_SUBNET_MASK,
	            nm_utils_inet4_ntop (a_netmask.s_addr, addr_str));

	LOG_LEASE (LOGD_DHCP4, "expires in %u seconds (at %lld)",
	           (guint) a_lifetime,
	           (long long) (ts_time + a_lifetime));
	add_option_u64 (options,
	                dhcp4_requests,
	                SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
	                (guint64) (ts_time + a_lifetime));

	nm_ip4_config_add_address (ip4_config,
	                           &((const NMPlatformIP4Address) {
	                               .address      = a_address.s_addr,
	                               .peer_address = a_address.s_addr,
	                               .plen         = a_plen,
	                               .addr_source  = NM_IP_CONFIG_SOURCE_DHCP,
	                               .timestamp    = ts,
	                               .lifetime     = a_lifetime,
	                               .preferred    = a_lifetime,
	                           }));

	num = sd_dhcp_lease_get_dns (lease, &addr_list);
	if (num > 0) {
		nm_gstring_prepare (&str);
		for (i = 0; i < num; i++) {
			nm_utils_inet4_ntop (addr_list[i].s_addr, addr_str);
			g_string_append (nm_gstring_add_space_delimiter (str), addr_str);

			if (   addr_list[i].s_addr == 0
			    || nm_ip4_addr_is_localhost (addr_list[i].s_addr)) {
				/* Skip localhost addresses, like also networkd does.
				 * See https://github.com/systemd/systemd/issues/4524. */
				continue;
			}
			nm_ip4_config_add_nameserver (ip4_config, addr_list[i].s_addr);
		}
		LOG_LEASE (LOGD_DHCP4, "nameserver '%s'", str->str);
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_DOMAIN_NAME_SERVER, str->str);
	}

	num = sd_dhcp_lease_get_search_domains (lease, (char ***) &search_domains);
	if (num > 0) {
		nm_gstring_prepare (&str);
		for (i = 0; i < num; i++) {
			g_string_append (nm_gstring_add_space_delimiter (str), search_domains[i]);
			nm_ip4_config_add_search (ip4_config, search_domains[i]);
		}
		LOG_LEASE (LOGD_DHCP4, "domain search '%s'", str->str);
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_DOMAIN_SEARCH_LIST, str->str);
	}

	if (sd_dhcp_lease_get_domainname (lease, &s) >= 0) {
		gs_strfreev char **domains = NULL;
		char **d;

		LOG_LEASE (LOGD_DHCP4, "domain name '%s'", s);
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_DOMAIN_NAME, s);

		/* Multiple domains sometimes stuffed into option 15 "Domain Name".
		 * As systemd escapes such characters, split them at \\032. */
		domains = g_strsplit (s, "\\032", 0);
		for (d = domains; *d; d++)
			nm_ip4_config_add_domain (ip4_config, *d);
	}

	if (sd_dhcp_lease_get_hostname (lease, &s) >= 0) {
		LOG_LEASE (LOGD_DHCP4, "hostname '%s'", s);
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_HOST_NAME, s);
	}

	num = sd_dhcp_lease_get_routes (lease, &routes);
	if (num > 0) {
		nm_auto_free_gstring GString *str_classless = NULL;
		nm_auto_free_gstring GString *str_static = NULL;
		guint32 default_route_metric = route_metric;

		for (i = 0; i < num; i++) {
			switch (sd_dhcp_route_get_option (routes[i])) {
			case SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE:
				has_classless_route = TRUE;
				break;
			case SD_DHCP_OPTION_STATIC_ROUTE:
				has_static_route = TRUE;
				break;
			}
		}

		if (has_classless_route)
			str_classless = g_string_sized_new (30);
		if (has_static_route)
			str_static = g_string_sized_new (30);

		for (i = 0; i < num; i++) {
			char network_net_str[NM_UTILS_INET_ADDRSTRLEN];
			char gateway_str[NM_UTILS_INET_ADDRSTRLEN];
			guint8 r_plen;
			struct in_addr r_network;
			struct in_addr r_gateway;
			in_addr_t network_net;
			int option;
			guint32 m;

			option = sd_dhcp_route_get_option (routes[i]);
			if (!NM_IN_SET (option, SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
			                        SD_DHCP_OPTION_STATIC_ROUTE))
				continue;

			if (sd_dhcp_route_get_destination (routes[i], &r_network) < 0)
				continue;
			if (   sd_dhcp_route_get_destination_prefix_length (routes[i], &r_plen) < 0
			    || r_plen > 32)
				continue;
			if (sd_dhcp_route_get_gateway (routes[i], &r_gateway) < 0)
				continue;

			network_net = nm_utils_ip4_address_clear_host_address (r_network.s_addr,
			                                                       r_plen);
			nm_utils_inet4_ntop (network_net, network_net_str);
			nm_utils_inet4_ntop (r_gateway.s_addr, gateway_str);

			LOG_LEASE (LOGD_DHCP4,
			           "%sstatic route %s/%d gw %s",
			             option == SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE
			           ? "classless "
			           : "",
			           network_net_str,
			           (int) r_plen,
			           gateway_str);
			g_string_append_printf (nm_gstring_add_space_delimiter (  option == SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE
			                                                        ? str_classless
			                                                        : str_static),
			                        "%s/%d %s",
			                        network_net_str,
			                        (int) r_plen,
			                        gateway_str);

			if (   option == SD_DHCP_OPTION_STATIC_ROUTE
			    && has_classless_route) {
				/* RFC 3443: if the DHCP server returns both a Classless Static Routes
				 * option and a Static Routes option, the DHCP client MUST ignore the
				 * Static Routes option. */
				continue;
			}

			if (   r_plen == 0
			    && option == SD_DHCP_OPTION_STATIC_ROUTE) {
				/* for option 33 (static route), RFC 2132 says:
				 *
				 * The default route (0.0.0.0) is an illegal destination for a static
				 * route. */
				continue;
			}

			if (r_plen == 0) {
				/* if there are multiple default routes, we add them with differing
				 * metrics. */
				m = default_route_metric;
				if (default_route_metric < G_MAXUINT32)
					default_route_metric++;

				has_router_from_classless = TRUE;
			} else
				m = route_metric;

			nm_ip4_config_add_route (ip4_config,
			                         &((const NMPlatformIP4Route) {
			                             .network       = network_net,
			                             .plen          = r_plen,
			                             .gateway       = r_gateway.s_addr,
			                             .rt_source     = NM_IP_CONFIG_SOURCE_DHCP,
			                             .metric        = m,
			                             .table_coerced = nm_platform_route_table_coerce (route_table),
			                         }),
			                         NULL);
		}

		if (str_classless && str_classless->len > 0)
			add_option (options, dhcp4_requests, SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE, str_classless->str);
		if (str_static && str_static->len > 0)
			add_option (options, dhcp4_requests, SD_DHCP_OPTION_STATIC_ROUTE, str_static->str);
	}

	num = sd_dhcp_lease_get_router (lease, &a_router);
	if (num > 0) {
		guint32 default_route_metric = route_metric;

		nm_gstring_prepare (&str);
		for (i = 0; i < num; i++) {
			guint32 m;

			s = nm_utils_inet4_ntop (a_router[i].s_addr, addr_str);
			g_string_append (nm_gstring_add_space_delimiter (str), s);

			if (a_router[i].s_addr == 0) {
				/* silently skip 0.0.0.0 */
				continue;
			}

			if (has_router_from_classless) {
				/* If the DHCP server returns both a Classless Static Routes option and a
				 * Router option, the DHCP client MUST ignore the Router option [RFC 3442].
				 *
				 * Be more lenient and ignore the Router option only if Classless Static
				 * Routes contain a default gateway (as other DHCP backends do).
				 */
				continue;
			}

			/* if there are multiple default routes, we add them with differing
			 * metrics. */
			m = default_route_metric;
			if (default_route_metric < G_MAXUINT32)
				default_route_metric++;

			nm_ip4_config_add_route (ip4_config,
			                         &((const NMPlatformIP4Route) {
			                             .rt_source     = NM_IP_CONFIG_SOURCE_DHCP,
			                             .gateway       = a_router[i].s_addr,
			                             .table_coerced = nm_platform_route_table_coerce (route_table),
			                             .metric        = m,
			                         }),
			                         NULL);
		}
		LOG_LEASE (LOGD_DHCP4, "router %s", str->str);
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_ROUTER, str->str);
	}

	if (   sd_dhcp_lease_get_mtu (lease, &mtu) >= 0
	    && mtu) {
		LOG_LEASE (LOGD_DHCP4, "mtu %u", mtu);
		add_option_u64 (options, dhcp4_requests, SD_DHCP_OPTION_INTERFACE_MTU, mtu);
		nm_ip4_config_set_mtu (ip4_config, mtu, NM_IP_CONFIG_SOURCE_DHCP);
	}

	num = sd_dhcp_lease_get_ntp (lease, &addr_list);
	if (num > 0) {
		nm_gstring_prepare (&str);
		for (i = 0; i < num; i++) {
			nm_utils_inet4_ntop (addr_list[i].s_addr, addr_str);
			g_string_append (nm_gstring_add_space_delimiter (str), addr_str);
		}
		LOG_LEASE (LOGD_DHCP4, "ntp server '%s'", str->str);
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_NTP_SERVER, str->str);
	}

	if (sd_dhcp_lease_get_root_path (lease, &s) >= 0) {
		LOG_LEASE (LOGD_DHCP4, "root path '%s'", s);
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_ROOT_PATH, s);
	}

	if (sd_dhcp_lease_get_vendor_specific (lease, &data, &data_len) >= 0)
		metered = !!memmem (data, data_len, "ANDROID_METERED", NM_STRLEN ("ANDROID_METERED"));
	nm_ip4_config_set_metered (ip4_config, metered);

	NM_SET_OUT (out_options, g_steal_pointer (&options));
	return g_steal_pointer (&ip4_config);
}

/*****************************************************************************/

static char *
get_leasefile_path (int addr_family, const char *iface, const char *uuid)
{
	char *rundir_path;
	char *statedir_path;

	rundir_path = g_strdup_printf (NMRUNDIR "/internal%s-%s-%s.lease",
	                               addr_family == AF_INET6 ? "6" : "",
	                               uuid,
	                               iface);

	if (g_file_test (rundir_path, G_FILE_TEST_EXISTS))
		return rundir_path;

	statedir_path = g_strdup_printf (NMSTATEDIR "/internal%s-%s-%s.lease",
	                                 addr_family == AF_INET6 ? "6" : "",
	                                 uuid,
	                                 iface);

	if (   g_file_test (statedir_path, G_FILE_TEST_EXISTS)
	    || nm_config_get_configure_and_quit (nm_config_get ()) != NM_CONFIG_CONFIGURE_AND_QUIT_INITRD) {
		g_free (rundir_path);
		return statedir_path;
	} else {
		g_free (statedir_path);
		return rundir_path;
	}
}

/*****************************************************************************/

static void
bound4_handle (NMDhcpSystemd *self)
{
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (self);
	const char *iface = nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self));
	sd_dhcp_lease *lease;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	gs_unref_hashtable GHashTable *options = NULL;
	GError *error = NULL;

	if (   sd_dhcp_client_get_lease (priv->client4, &lease) < 0
	    || !lease) {
		_LOGW ("no lease!");
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return;
	}

	_LOGD ("lease available");

	ip4_config = lease_to_ip4_config (nm_dhcp_client_get_multi_idx (NM_DHCP_CLIENT (self)),
	                                  iface,
	                                  nm_dhcp_client_get_ifindex (NM_DHCP_CLIENT (self)),
	                                  lease,
	                                  nm_dhcp_client_get_route_table (NM_DHCP_CLIENT (self)),
	                                  nm_dhcp_client_get_route_metric (NM_DHCP_CLIENT (self)),
	                                  TRUE,
	                                  &options,
	                                  &error);
	if (!ip4_config) {
		_LOGW ("%s", error->message);
		g_clear_error (&error);
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return;
	}

	add_requests_to_options (options, dhcp4_requests);
	dhcp_lease_save (lease, priv->lease_file);

	nm_dhcp_client_set_state (NM_DHCP_CLIENT (self),
	                          NM_DHCP_STATE_BOUND,
	                          NM_IP_CONFIG_CAST (ip4_config),
	                          options);
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

static gboolean
ip4_start (NMDhcpClient *client,
           const char *dhcp_anycast_addr,
           const char *last_ip4_address,
           GError **error)
{
	nm_auto (sd_dhcp_client_unrefp) sd_dhcp_client *sd_client = NULL;
	NMDhcpSystemd *self = NM_DHCP_SYSTEMD (client);
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (self);
	gs_free char *lease_file = NULL;
	GBytes *hwaddr;
	const uint8_t *hwaddr_arr;
	gsize hwaddr_len;
	int arp_type;
	GBytes *client_id;
	gs_unref_bytes GBytes *client_id_new = NULL;
	const uint8_t *client_id_arr;
	size_t client_id_len;
	struct in_addr last_addr = { 0 };
	const char *hostname;
	int r, i;

	g_return_val_if_fail (!priv->client4, FALSE);
	g_return_val_if_fail (!priv->client6, FALSE);

	r = sd_dhcp_client_new (&sd_client, FALSE);
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to create dhcp-client: %s");
		return FALSE;
	}

	_LOGT ("dhcp-client4: set %p", sd_client);

	r = sd_dhcp_client_attach_event (sd_client, NULL, 0);
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to attach event: %s");
		return FALSE;
	}

	hwaddr = nm_dhcp_client_get_hw_addr (client);
	if (   !hwaddr
	    || !(hwaddr_arr = g_bytes_get_data (hwaddr, &hwaddr_len))
	    || (arp_type = nm_utils_arp_type_detect_from_hwaddrlen (hwaddr_len)) < 0) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "invalid MAC address");
		return FALSE;
	}
	r = sd_dhcp_client_set_mac (sd_client,
	                            hwaddr_arr,
	                            hwaddr_len,
	                            (guint16) arp_type);
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to set MAC address: %s");
		return FALSE;
	}

	r = sd_dhcp_client_set_ifindex (sd_client,
	                                nm_dhcp_client_get_ifindex (client));
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to set ifindex: %s");
		return FALSE;
	}

	lease_file = get_leasefile_path (AF_INET,
	                                 nm_dhcp_client_get_iface (client),
	                                 nm_dhcp_client_get_uuid (client));

	if (last_ip4_address)
		inet_pton (AF_INET, last_ip4_address, &last_addr);
	else {
		nm_auto (sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;

		dhcp_lease_load (&lease, lease_file);
		if (lease)
			sd_dhcp_lease_get_address (lease, &last_addr);
	}

	if (last_addr.s_addr) {
		r = sd_dhcp_client_set_request_address (sd_client, &last_addr);
		if (r < 0) {
			nm_utils_error_set_errno (error, r, "failed to set last IPv4 address: %s");
			return FALSE;
		}
	}

	client_id = nm_dhcp_client_get_client_id (client);
	if (!client_id) {
		client_id_new = nm_utils_dhcp_client_id_mac (arp_type, hwaddr_arr, hwaddr_len);
		client_id = client_id_new;
	}

	if (   !(client_id_arr = g_bytes_get_data (client_id, &client_id_len))
	    || client_id_len < 2) {

		/* invalid client-ids are not expected. */
		nm_assert_not_reached ();

		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "no valid IPv4 client-id");
		return FALSE;
	}

	/* Note that we always set a client-id. In particular for infiniband that is necessary,
	 * see https://tools.ietf.org/html/rfc4390#section-2.1 . */
	r = sd_dhcp_client_set_client_id (sd_client,
	                                  client_id_arr[0],
	                                  client_id_arr + 1,
	                                  NM_MIN (client_id_len - 1, _NM_SD_MAX_CLIENT_ID_LEN));
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to set IPv4 client-id: %s");
		return FALSE;
	}

	/* Add requested options */
	for (i = 0; dhcp4_requests[i].name; i++) {
		if (dhcp4_requests[i].include) {
			nm_assert (dhcp4_requests[i].option_num <= 255);
			r = sd_dhcp_client_set_request_option (sd_client, dhcp4_requests[i].option_num);
			nm_assert (r >= 0 || r == -EEXIST);
		}
	}

	hostname = nm_dhcp_client_get_hostname (client);
	if (hostname) {
		/* FIXME: sd-dhcp decides which hostname/FQDN option to send (12 or 81)
		 * only based on whether the hostname has a domain part or not. At the
		 * moment there is no way to force one or another.
		 */
		r = sd_dhcp_client_set_hostname (sd_client, hostname);
		if (r < 0) {
			nm_utils_error_set_errno (error, r, "failed to set DHCP hostname: %s");
			return FALSE;
		}
	}

	r = sd_dhcp_client_set_callback (sd_client, dhcp_event_cb, client);
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to set callback: %s");
		return FALSE;
	}

	priv->client4 = g_steal_pointer (&sd_client);

	g_free (priv->lease_file);
	priv->lease_file = g_steal_pointer (&lease_file);

	nm_dhcp_client_set_client_id (client, client_id);

	r = sd_dhcp_client_start (priv->client4);
	if (r < 0) {
		sd_dhcp_client_set_callback (priv->client4, NULL, NULL);
		nm_clear_pointer (&priv->client4, sd_dhcp_client_unref);
		nm_utils_error_set_errno (error, r, "failed to start DHCP client: %s");
		return FALSE;
	}

	nm_dhcp_client_start_timeout (client);
	return TRUE;
}

static NMIP6Config *
lease_to_ip6_config (NMDedupMultiIndex *multi_idx,
                     const char *iface,
                     int ifindex,
                     sd_dhcp6_lease *lease,
                     gboolean log_lease,
                     gboolean info_only,
                     GHashTable **out_options,
                     GError **error)
{
	gs_unref_object NMIP6Config *ip6_config = NULL;
	gs_unref_hashtable GHashTable *options = NULL;
	struct in6_addr tmp_addr, *dns;
	uint32_t lft_pref, lft_valid;
	char addr_str[NM_UTILS_INET_ADDRSTRLEN];
	char **domains;
	nm_auto_free_gstring GString *str = NULL;
	int num, i;
	const gint32 ts = nm_utils_get_monotonic_timestamp_s ();

	g_return_val_if_fail (lease, NULL);

	ip6_config = nm_ip6_config_new (multi_idx, ifindex);

	options = out_options ? create_options_dict () : NULL;

	sd_dhcp6_lease_reset_address_iter (lease);
	nm_gstring_prepare (&str);
	while (sd_dhcp6_lease_get_address (lease, &tmp_addr, &lft_pref, &lft_valid) >= 0) {
		char sbuf[400];
		const NMPlatformIP6Address address = {
			.plen        = 128,
			.address     = tmp_addr,
			.timestamp   = ts,
			.lifetime    = lft_valid,
			.preferred   = lft_pref,
			.addr_source = NM_IP_CONFIG_SOURCE_DHCP,
		};

		nm_ip6_config_add_address (ip6_config, &address);

		nm_utils_inet6_ntop (&tmp_addr, addr_str);
		g_string_append (nm_gstring_add_space_delimiter (str), addr_str);

		LOG_LEASE (LOGD_DHCP6,
		           "address %s",
		           nm_platform_ip6_address_to_string (&address, sbuf, sizeof (sbuf)));
	};
	if (str->len)
		add_option (options, dhcp6_requests, DHCP6_OPTION_IP_ADDRESS, str->str);

	if (   !info_only
	    && nm_ip6_config_get_num_addresses (ip6_config) == 0) {
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_FAILED,
		                     "no address received in managed mode");
		return NULL;
	}

	num = sd_dhcp6_lease_get_dns (lease, &dns);
	if (num > 0) {
		nm_gstring_prepare (&str);
		for (i = 0; i < num; i++) {
			nm_utils_inet6_ntop (&dns[i], addr_str);
			g_string_append (nm_gstring_add_space_delimiter (str), addr_str);
			nm_ip6_config_add_nameserver (ip6_config, &dns[i]);
		}
		LOG_LEASE (LOGD_DHCP6, "nameserver %s", str->str);
		add_option (options, dhcp6_requests, SD_DHCP6_OPTION_DNS_SERVERS, str->str);
	}

	num = sd_dhcp6_lease_get_domains (lease, &domains);
	if (num > 0) {
		nm_gstring_prepare (&str);
		for (i = 0; i < num; i++) {
			g_string_append (nm_gstring_add_space_delimiter (str), domains[i]);
			nm_ip6_config_add_search (ip6_config, domains[i]);
		}
		LOG_LEASE (LOGD_DHCP6, "domain name '%s'", str->str);
		add_option (options, dhcp6_requests, SD_DHCP6_OPTION_DOMAIN_LIST, str->str);
	}

	NM_SET_OUT (out_options, g_steal_pointer (&options));
	return g_steal_pointer (&ip6_config);
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

	if (   sd_dhcp6_client_get_lease (priv->client6, &lease) < 0
	    || !lease) {
		_LOGW (" no lease!");
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return;
	}

	_LOGD ("lease available");

	ip6_config = lease_to_ip6_config (nm_dhcp_client_get_multi_idx (NM_DHCP_CLIENT (self)),
	                                  iface,
	                                  nm_dhcp_client_get_ifindex (NM_DHCP_CLIENT (self)),
	                                  lease,
	                                  TRUE,
	                                  nm_dhcp_client_get_info_only (NM_DHCP_CLIENT (self)),
	                                  &options,
	                                  &error);

	if (!ip6_config) {
		_LOGW ("%s", error->message);
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return;
	}

	nm_dhcp_client_set_state (NM_DHCP_CLIENT (self),
	                          NM_DHCP_STATE_BOUND,
	                          NM_IP_CONFIG_CAST (ip6_config),
	                          options);
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
           NMSettingIP6ConfigPrivacy privacy,
           guint needed_prefixes,
           GError **error)
{
	NMDhcpSystemd *self = NM_DHCP_SYSTEMD (client);
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (self);
	nm_auto (sd_dhcp6_client_unrefp) sd_dhcp6_client *sd_client = NULL;
	GBytes *hwaddr;
	const char *hostname;
	const char *iface;
	int r, i;
	const guint8 *duid_arr;
	gsize duid_len;
	GBytes *duid;
	const uint8_t *hwaddr_arr;
	gsize hwaddr_len;
	int arp_type;

	g_return_val_if_fail (!priv->client4, FALSE);
	g_return_val_if_fail (!priv->client6, FALSE);

	if (   !(duid = nm_dhcp_client_get_client_id (client))
	    || !(duid_arr = g_bytes_get_data (duid, &duid_len))
	    || duid_len < 2) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "missing DUID");
		g_return_val_if_reached (FALSE);
	}

	r = sd_dhcp6_client_new (&sd_client);
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to create dhcp-client: %s");
		return FALSE;
	}

	if (needed_prefixes > 0) {
		_LOGW ("dhcp-client6: prefix delegation not yet supported, won't supply %d prefixes",
		       needed_prefixes);
	}

	_LOGT ("dhcp-client6: set %p", sd_client);

	if (nm_dhcp_client_get_info_only (client))
		sd_dhcp6_client_set_information_request (sd_client, 1);

	iface = nm_dhcp_client_get_iface (client);

	r = sd_dhcp6_client_set_iaid (sd_client,
	                              nm_utils_create_dhcp_iaid (TRUE,
	                                                         (const guint8 *) iface,
	                                                         strlen (iface)));
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to set IAID: %s");
		return FALSE;
	}

	r = sd_dhcp6_client_set_duid (sd_client,
	                              unaligned_read_be16 (&duid_arr[0]),
	                              &duid_arr[2],
	                              duid_len - 2);
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to set DUID: %s");
		return FALSE;
	}

	r = sd_dhcp6_client_attach_event (sd_client, NULL, 0);
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to attach event: %s");
		return FALSE;
	}

	hwaddr = nm_dhcp_client_get_hw_addr (client);
	if (   !hwaddr
	    || !(hwaddr_arr = g_bytes_get_data (hwaddr, &hwaddr_len))
	    || (arp_type = nm_utils_arp_type_detect_from_hwaddrlen (hwaddr_len)) < 0) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "invalid MAC address");
		return FALSE;
	}
	r = sd_dhcp6_client_set_mac (sd_client,
	                             hwaddr_arr,
	                             hwaddr_len,
	                             (guint16) arp_type);
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to set MAC address: %s");
		return FALSE;
	}

	r = sd_dhcp6_client_set_ifindex (sd_client,
	                                 nm_dhcp_client_get_ifindex (client));
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to set ifindex: %s");
		return FALSE;
	}

	/* Add requested options */
	for (i = 0; dhcp6_requests[i].name; i++) {
		if (dhcp6_requests[i].include) {
			r = sd_dhcp6_client_set_request_option (sd_client, dhcp6_requests[i].option_num);
			nm_assert (r >= 0 || r == -EEXIST);
		}
	}

	r = sd_dhcp6_client_set_local_address (sd_client, ll_addr);
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to set local address: %s");
		return FALSE;
	}

	hostname = nm_dhcp_client_get_hostname (client);
	r = sd_dhcp6_client_set_fqdn (sd_client, hostname);
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to set DHCP hostname: %s");
		return FALSE;
	}

	r = sd_dhcp6_client_set_callback (sd_client, dhcp6_event_cb, client);
	if (r < 0) {
		nm_utils_error_set_errno (error, r, "failed to set callback: %s");
		return FALSE;
	}

	priv->client6 = g_steal_pointer (&sd_client);

	r = sd_dhcp6_client_start (priv->client6);
	if (r < 0) {
		sd_dhcp6_client_set_callback (priv->client6, NULL, NULL);
		nm_clear_pointer (&priv->client6, sd_dhcp6_client_unref);
		nm_utils_error_set_errno (error, r, "failed to start client: %s");
		return FALSE;
	}

	nm_dhcp_client_start_timeout (client);
	return TRUE;
}

static void
stop (NMDhcpClient *client, gboolean release)
{
	NMDhcpSystemd *self = NM_DHCP_SYSTEMD (client);
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (self);
	int r = 0;

	NM_DHCP_CLIENT_CLASS (nm_dhcp_systemd_parent_class)->stop (client, release);

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
};
