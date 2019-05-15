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
 * Copyright (C) 2014-2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <net/if_arp.h>

#include "nm-glib-aux/nm-dedup-multi.h"
#include "nm-std-aux/unaligned.h"

#include "nm-utils.h"
#include "nm-config.h"
#include "nm-dhcp-utils.h"
#include "nm-core-utils.h"
#include "NetworkManagerUtils.h"
#include "platform/nm-platform.h"
#include "nm-dhcp-client-logging.h"
#include "n-dhcp4/src/n-dhcp4.h"

/*****************************************************************************/

#define NM_TYPE_DHCP_NETTOOLS            (nm_dhcp_nettools_get_type ())
#define NM_DHCP_NETTOOLS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_NETTOOLS, NMDhcpNettools))
#define NM_DHCP_NETTOOLS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_NETTOOLS, NMDhcpNettoolsClass))
#define NM_IS_DHCP_NETTOOLS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_NETTOOLS))
#define NM_IS_DHCP_NETTOOLS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP_NETTOOLS))
#define NM_DHCP_NETTOOLS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_NETTOOLS, NMDhcpNettoolsClass))

typedef struct _NMDhcpNettools NMDhcpNettools;
typedef struct _NMDhcpNettoolsClass NMDhcpNettoolsClass;

static GType nm_dhcp_nettools_get_type (void);

/*****************************************************************************/

typedef struct {
	NDhcp4Client *client;
	NDhcp4ClientProbe *probe;
	NDhcp4ClientLease *lease;
	GIOChannel *channel;
	guint event_id;
} NMDhcpNettoolsPrivate;

struct _NMDhcpNettools {
	NMDhcpClient parent;
	NMDhcpNettoolsPrivate _priv;
};

struct _NMDhcpNettoolsClass {
	NMDhcpClientClass parent;
};

G_DEFINE_TYPE (NMDhcpNettools, nm_dhcp_nettools, NM_TYPE_DHCP_CLIENT)

#define NM_DHCP_NETTOOLS_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDhcpNettools, NM_IS_DHCP_NETTOOLS)

/*****************************************************************************/

#define DHCP_OPTION_SUBNET_MASK                        1
#define DHCP_OPTION_TIME_OFFSET                        2
#define DHCP_OPTION_ROUTER                             3
#define DHCP_OPTION_DOMAIN_NAME_SERVER                 6
#define DHCP_OPTION_HOST_NAME                         12
#define DHCP_OPTION_DOMAIN_NAME                       15
#define DHCP_OPTION_ROOT_PATH                         17
#define DHCP_OPTION_INTERFACE_MTU                     26
#define DHCP_OPTION_BROADCAST                         28
#define DHCP_OPTION_STATIC_ROUTE                      33
#define DHCP_OPTION_NIS_DOMAIN                        40
#define DHCP_OPTION_NIS_SERVERS                       41
#define DHCP_OPTION_NTP_SERVER                        42
#define DHCP_OPTION_VENDOR_SPECIFIC                   43
#define DHCP_OPTION_IP_ADDRESS_LEASE_TIME             51
#define DHCP_OPTION_SERVER_IDENTIFIER                 54
#define DHCP_OPTION_CLIENT_IDENTIFIER                 61
#define DHCP_OPTION_DOMAIN_SEARCH_LIST               119
#define DHCP_OPTION_CLASSLESS_STATIC_ROUTE           121
#define DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE   249
#define DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY      252

/* Internal values */
#define DHCP_OPTION_IP_ADDRESS       1024
#define DHCP_OPTION_EXPIRY           1025

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
	REQ (DHCP_OPTION_SUBNET_MASK,                    "subnet_mask",                     TRUE ),
	REQ (DHCP_OPTION_TIME_OFFSET,                    "time_offset",                     TRUE ),
	REQ (DHCP_OPTION_DOMAIN_NAME_SERVER,             "domain_name_servers",             TRUE ),
	REQ (DHCP_OPTION_HOST_NAME,                      "host_name",                       TRUE ),
	REQ (DHCP_OPTION_DOMAIN_NAME,                    "domain_name",                     TRUE ),
	REQ (DHCP_OPTION_INTERFACE_MTU,                  "interface_mtu",                   TRUE ),
	REQ (DHCP_OPTION_BROADCAST,                      "broadcast_address",               TRUE ),

	/* RFC 3442: The Classless Static Routes option code MUST appear in the parameter
	 *   request list prior to both the Router option code and the Static
	 *   Routes option code, if present. */
	REQ (DHCP_OPTION_CLASSLESS_STATIC_ROUTE,         "rfc3442_classless_static_routes", TRUE ),
	REQ (DHCP_OPTION_ROUTER,                         "routers",                         TRUE ),
	REQ (DHCP_OPTION_STATIC_ROUTE,                   "static_routes",                   TRUE ),
	REQ (DHCP_OPTION_NIS_DOMAIN,                     "nis_domain",                      TRUE ),
	REQ (DHCP_OPTION_NIS_SERVERS,                    "nis_servers",                     TRUE ),
	REQ (DHCP_OPTION_NTP_SERVER,                     "ntp_servers",                     TRUE ),
	REQ (DHCP_OPTION_SERVER_IDENTIFIER,              "dhcp_server_identifier",          TRUE ),
	REQ (DHCP_OPTION_DOMAIN_SEARCH_LIST,             "domain_search",                   TRUE ),
	REQ (DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE, "ms_classless_static_routes",      TRUE ),
	REQ (DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY,    "wpad",                            TRUE ),
	REQ (DHCP_OPTION_ROOT_PATH,                      "root_path",                       TRUE ),

	/* Internal values */
	REQ (DHCP_OPTION_IP_ADDRESS_LEASE_TIME,          "expiry",                          FALSE ),
	REQ (DHCP_OPTION_CLIENT_IDENTIFIER,              "dhcp_client_identifier",          FALSE ),
	REQ (DHCP_OPTION_IP_ADDRESS,                     "ip_address",                      FALSE ),

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

static gboolean
lease_get_in_addr(NDhcp4ClientLease *lease, guint8 option, struct in_addr *addrp) {
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query(lease, option, &data, &n_data);
	if (r)
		return FALSE;

	if (n_data != sizeof (struct in_addr))
		return FALSE;

	memcpy(&addrp->s_addr, data, sizeof (struct in_addr));
	return TRUE;
}

static gboolean
lease_get_in_addrs(NDhcp4ClientLease *lease, guint8 option, uint8_t **addrsp, size_t *n_addrsp) {
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query(lease, option, &data, &n_data);
	if (r)
		return FALSE;

	if (n_data % sizeof (struct in_addr))
		return FALSE;

	*addrsp = data;
	*n_addrsp = n_data / sizeof (struct in_addr);
	return TRUE;
}

static gboolean
lease_get_u16(NDhcp4ClientLease *lease, uint8_t option, uint16_t *u16p)
{
	uint8_t *data;
	size_t n_data;
	uint16_t u16;
	int r;

	r = n_dhcp4_client_lease_query(lease, option, &data, &n_data);
	if (r)
		return FALSE;

	if (n_data != sizeof (u16))
		return FALSE;

	memcpy(&u16, data, sizeof (u16));

	*u16p = u16;
	return TRUE;
}

#define LOG_LEASE(domain, ...) \
G_STMT_START { \
	if (log_lease) { \
		_LOG2I ((domain), (iface), "  "__VA_ARGS__); \
	} \
} G_STMT_END

static gboolean
lease_parse_address (NDhcp4ClientLease *lease,
                     const char *iface,
		     NMIP4Config *ip4_config,
		     GHashTable *options,
		     gboolean log_lease,
		     GError **error)
{
	char addr_str[NM_UTILS_INET_ADDRSTRLEN];
	const gint64 ts = nm_utils_get_monotonic_timestamp_ns ();
	struct in_addr a_address;
	struct in_addr a_netmask;
	guint32 a_plen;
	guint64 a_lifetime;

	n_dhcp4_client_lease_get_yiaddr (lease, &a_address);
	n_dhcp4_client_lease_get_lifetime (lease, &a_lifetime);

	if (!lease_get_in_addr (lease, DHCP_OPTION_SUBNET_MASK, &a_netmask)) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "could not get netmask from lease");
		return FALSE;
	}

	nm_utils_inet4_ntop (a_address.s_addr, addr_str);
	LOG_LEASE (LOGD_DHCP4, "address %s", addr_str);
	add_option (options, dhcp4_requests, DHCP_OPTION_IP_ADDRESS, addr_str);

	a_plen = nm_utils_ip4_netmask_to_prefix (a_netmask.s_addr);
	LOG_LEASE (LOGD_DHCP4, "plen %u", (guint) a_plen);
	add_option (options,
	            dhcp4_requests,
	            DHCP_OPTION_SUBNET_MASK,
	            nm_utils_inet4_ntop (a_netmask.s_addr, addr_str));

	LOG_LEASE (LOGD_DHCP4, "expires in %u seconds",
	           (guint) ((a_lifetime - ts)/1000000000));
	add_option_u64 (options,
	                dhcp4_requests,
	                DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
	                (guint64) (a_lifetime / 1000000000));

	nm_ip4_config_add_address (ip4_config,
	                           &((const NMPlatformIP4Address) {
	                               .address      = a_address.s_addr,
	                               .peer_address = a_address.s_addr,
	                               .plen         = a_plen,
	                               .addr_source  = NM_IP_CONFIG_SOURCE_DHCP,
	                               .timestamp    = ts / 1000000000,
	                               .lifetime     = (a_lifetime - ts) / 1000000000,
	                               .preferred    = (a_lifetime - ts) / 1000000000,
	                           }));

	return TRUE;
}

static void
lease_parse_domain_name_servers (NDhcp4ClientLease *lease,
				 const char *iface,
				 NMIP4Config *ip4_config,
				 GHashTable *options,
				 gboolean log_lease)
{
	nm_auto_free_gstring GString *str = NULL;
	char addr_str[NM_UTILS_INET_ADDRSTRLEN];
	uint8_t *addrs;
	size_t n_addrs;

	if (lease_get_in_addrs (lease, DHCP_OPTION_DOMAIN_NAME_SERVER, &addrs, &n_addrs)) {
		size_t i;

		nm_gstring_prepare (&str);
		for (i = 0; i < n_addrs; i++) {
			struct in_addr addr;

			memcpy(&addr, addrs + i * sizeof (struct in_addr), sizeof (struct in_addr));

			nm_utils_inet4_ntop (addr.s_addr, addr_str);
			g_string_append (nm_gstring_add_space_delimiter (str), addr_str);

			if (   addr.s_addr == 0
			    || nm_ip4_addr_is_localhost (addr.s_addr)) {
				/* Skip localhost addresses, like also networkd does.
				 * See https://github.com/systemd/systemd/issues/4524. */
				continue;
			}
			nm_ip4_config_add_nameserver (ip4_config, addr.s_addr);
		}
		LOG_LEASE (LOGD_DHCP4, "nameserver '%s'", str->str);
		add_option (options, dhcp4_requests, DHCP_OPTION_DOMAIN_NAME_SERVER, str->str);
	}
}

static void
lease_parse_routes (NDhcp4ClientLease *lease,
		    const char *iface,
		    NMIP4Config *ip4_config,
		    GHashTable *options,
		    guint32 route_table,
		    guint32 route_metric,
		    gboolean log_lease)
{
	nm_auto_free_gstring GString *str = NULL;
	char addr_str[NM_UTILS_INET_ADDRSTRLEN];
	uint8_t *addrs;
	size_t n_addrs;
	gboolean has_router_from_classless = FALSE;

#if 0
	gboolean has_classless_route = FALSE;
	gboolean has_static_route = FALSE;

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
#endif

	if (lease_get_in_addrs (lease, DHCP_OPTION_ROUTER, &addrs, &n_addrs)) {
		size_t i;

		nm_gstring_prepare (&str);
		for (i = 0; i < n_addrs; i++) {
			struct in_addr a_router;
			const char *s;
			guint32 m;

			memcpy(&a_router, addrs + i * sizeof (struct in_addr), sizeof (struct in_addr));

			s = nm_utils_inet4_ntop (a_router.s_addr, addr_str);
			g_string_append (nm_gstring_add_space_delimiter (str), s);

			if (a_router.s_addr == 0) {
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
			m = route_metric;
			if (route_metric < G_MAXUINT32)
				route_metric++;

			nm_ip4_config_add_route (ip4_config,
			                         &((const NMPlatformIP4Route) {
			                             .rt_source     = NM_IP_CONFIG_SOURCE_DHCP,
			                             .gateway       = a_router.s_addr,
			                             .table_coerced = nm_platform_route_table_coerce (route_table),
			                             .metric        = m,
			                         }),
			                         NULL);
		}
		LOG_LEASE (LOGD_DHCP4, "router %s", str->str);
		add_option (options, dhcp4_requests, DHCP_OPTION_ROUTER, str->str);
	}
}

static void
lease_parse_mtu (NDhcp4ClientLease *lease,
		 const char *iface,
		 NMIP4Config *ip4_config,
		 GHashTable *options,
		 gboolean log_lease)
{
	uint16_t mtu;

	if (!lease_get_u16 (lease, DHCP_OPTION_INTERFACE_MTU, &mtu))
		return;

	if (mtu < 68)
		return;

	LOG_LEASE (LOGD_DHCP4, "mtu %u", mtu);
	add_option_u64 (options, dhcp4_requests, DHCP_OPTION_INTERFACE_MTU, mtu);
	nm_ip4_config_set_mtu (ip4_config, mtu, NM_IP_CONFIG_SOURCE_DHCP);
}

static void
lease_parse_metered (NDhcp4ClientLease *lease,
		     const char *iface,
		     NMIP4Config *ip4_config,
		     GHashTable *options,
		     gboolean log_lease)
{
	gboolean metered = FALSE;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query(lease, DHCP_OPTION_VENDOR_SPECIFIC, &data, &n_data);
	if (r) {
		metered = FALSE;
	} else {
		metered = !!memmem (data, n_data, "ANDROID_METERED", NM_STRLEN ("ANDROID_METERED"));
	}

	LOG_LEASE (LOGD_DHCP4, "%s", metered ? "metered" : "unmetered");
	nm_ip4_config_set_metered (ip4_config, metered);
}

static void
lease_parse_domainname (NDhcp4ClientLease *lease,
			const char *iface,
			NMIP4Config *ip4_config,
			GHashTable *options,
			gboolean log_lease)
{
	nm_auto_free_gstring GString *str = NULL;
	gs_strfreev char **domains = NULL;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query(lease, DHCP_OPTION_DOMAIN_NAME, &data, &n_data);
	if (r)
		return;

	/* XXX
	 * Parse correctly.
	 */

	str = g_string_new_len ((char *)data, n_data);
	LOG_LEASE (LOGD_DHCP4, "domain name '%s'", str->str);
	add_option (options, dhcp4_requests, DHCP_OPTION_DOMAIN_NAME, str->str);

	/* Multiple domains sometimes stuffed into option 15 "Domain Name". */
	domains = g_strsplit (str->str, " ", 0);
	for (char **d = domains; *d; d++)
		nm_ip4_config_add_domain (ip4_config, *d);
}

static void
lease_parse_search_domains (NDhcp4ClientLease *lease,
			    const char *iface,
			    NMIP4Config *ip4_config,
			    GHashTable *options,
			    gboolean log_lease)
{
	nm_auto_free_gstring GString *str = NULL;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query(lease, DHCP_OPTION_DOMAIN_SEARCH_LIST, &data, &n_data);
	if (r)
		return;

	/* XXX
	 * Parse correctly.
	 */
#if 0
	nm_gstring_prepare (&str);
	for (i = 0; i < num; i++) {
		g_string_append (nm_gstring_add_space_delimiter (str), search_domains[i]);
		nm_ip4_config_add_search (ip4_config, search_domains[i]);
	}
	LOG_LEASE (LOGD_DHCP4, "domain search '%s'", str->str);
	add_option (options, dhcp4_requests, DHCP_OPTION_DOMAIN_SEARCH_LIST, str->str);
#endif
}
	
static void
lease_parse_ntps (NDhcp4ClientLease *lease,
		  const char *iface,
		  GHashTable *options,
		  gboolean log_lease)
{
	nm_auto_free_gstring GString *str = NULL;
	char addr_str[NM_UTILS_INET_ADDRSTRLEN];
	uint8_t *addrs;
	size_t n_addrs;

	if (lease_get_in_addrs (lease, DHCP_OPTION_NTP_SERVER, &addrs, &n_addrs)) {
		size_t i;

		nm_gstring_prepare (&str);
		for (i = 0; i < n_addrs; i++) {
			struct in_addr addr;

			memcpy(&addr, addrs + i * sizeof (struct in_addr), sizeof (struct in_addr));

			nm_utils_inet4_ntop (addr.s_addr, addr_str);
			g_string_append (nm_gstring_add_space_delimiter (str), addr_str);
		}
		LOG_LEASE (LOGD_DHCP4, "ntp server '%s'", str->str);
		add_option (options, dhcp4_requests, DHCP_OPTION_NTP_SERVER, str->str);
	}
}

static void
lease_parse_hostname (NDhcp4ClientLease *lease,
		      const char *iface,
		      GHashTable *options,
		      gboolean log_lease)
{
	nm_auto_free_gstring GString *str = NULL;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query(lease, DHCP_OPTION_HOST_NAME, &data, &n_data);
	if (r)
		return;

	/* XXX
	 * Parse correctly.
	 */

	str = g_string_new_len ((char *)data, n_data);
	LOG_LEASE (LOGD_DHCP4, "hostname '%s'", str->str);
	add_option (options, dhcp4_requests, DHCP_OPTION_HOST_NAME, str->str);
}

static void
lease_parse_root_path (NDhcp4ClientLease *lease,
		       const char *iface,
		       GHashTable *options,
		       gboolean log_lease)
{
	nm_auto_free_gstring GString *str = NULL;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query(lease, DHCP_OPTION_ROOT_PATH, &data, &n_data);
	if (r)
		return;

	str = g_string_new_len ((char *)data, n_data);
	LOG_LEASE (LOGD_DHCP4, "root path '%s'", str->str);
	add_option (options, dhcp4_requests, DHCP_OPTION_ROOT_PATH, str->str);
}

static void
lease_parse_wpad (NDhcp4ClientLease *lease,
		  const char *iface,
		  GHashTable *options,
		  gboolean log_lease)
{
	nm_auto_free_gstring GString *str = NULL;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query(lease, DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY, &data, &n_data);
	if (r)
		return;

	str = g_string_new_len ((char *)data, n_data);
	LOG_LEASE (LOGD_DHCP4, "wpad '%s'", str->str);
	add_option (options, dhcp4_requests, DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY, str->str);
}

static NMIP4Config *
lease_to_ip4_config (NMDedupMultiIndex *multi_idx,
                     const char *iface,
                     int ifindex,
                     NDhcp4ClientLease *lease,
                     guint32 route_table,
                     guint32 route_metric,
                     gboolean log_lease,
                     GHashTable **out_options,
                     GError **error)
{
	gs_unref_object NMIP4Config *ip4_config = NULL;
	gs_unref_hashtable GHashTable *options = NULL;

	g_return_val_if_fail (lease != NULL, NULL);

	ip4_config = nm_ip4_config_new (multi_idx, ifindex);
	options = out_options ? create_options_dict () : NULL;

	if (!lease_parse_address (lease, iface, ip4_config, options, log_lease, error))
		return NULL;

	lease_parse_routes (lease, iface, ip4_config, options, route_table, route_metric, log_lease);
	lease_parse_domain_name_servers (lease, iface, ip4_config, options, log_lease);
	lease_parse_domainname (lease, iface, ip4_config, options, log_lease);
	lease_parse_search_domains (lease, iface, ip4_config, options, log_lease);
	lease_parse_mtu (lease, iface, ip4_config, options, log_lease);
	lease_parse_metered (lease, iface, ip4_config, options, log_lease);

	lease_parse_hostname (lease, iface, options, log_lease);
	lease_parse_ntps (lease, iface, options, log_lease);
	lease_parse_root_path (lease, iface, options, log_lease);
	lease_parse_wpad (lease, iface, options, log_lease);

	NM_SET_OUT (out_options, g_steal_pointer (&options));
	return g_steal_pointer (&ip4_config);
}

/*****************************************************************************/

static void
bound4_handle (NMDhcpNettools *self, NDhcp4ClientLease *lease)
{
	const char *iface = nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self));
	gs_unref_object NMIP4Config *ip4_config = NULL;
	gs_unref_hashtable GHashTable *options = NULL;
	GError *error = NULL;

	_LOGT ("lease available");

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

	nm_dhcp_client_set_state (NM_DHCP_CLIENT (self),
	                          NM_DHCP_STATE_BOUND,
	                          NM_IP_CONFIG_CAST (ip4_config),
	                          options);
}

static gboolean
dhcp4_event_handle(NMDhcpNettools *self, NDhcp4ClientEvent *event) {
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE (self);
	int r;

	_LOGT ("client event %d", event->event);

	switch (event->event) {
	case N_DHCP4_CLIENT_EVENT_OFFER:
		/* always accept the first lease */
		r = n_dhcp4_client_lease_select(event->offer.lease);
		if (r) {
			_LOGW("selecting lease failed: %d", r);
		}
		break;
	case N_DHCP4_CLIENT_EVENT_EXPIRED:
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_EXPIRE, NULL, NULL);
		break;
	case N_DHCP4_CLIENT_EVENT_RETRACTED:
	case N_DHCP4_CLIENT_EVENT_CANCELLED:
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		break;
	case N_DHCP4_CLIENT_EVENT_GRANTED:
		priv->lease = n_dhcp4_client_lease_ref(event->granted.lease);
		bound4_handle (self, event->granted.lease);
		break;
	case N_DHCP4_CLIENT_EVENT_EXTENDED:
		bound4_handle (self, event->extended.lease);
		break;
	case N_DHCP4_CLIENT_EVENT_DOWN:
		/* ignore down events, they are purely informational */
		break;
	default:
		_LOGW ("unhandled DHCP event %d", event->event);
		break;
	}

	return TRUE;
}

static gboolean
dhcp4_event_cb (GIOChannel *source, GIOCondition condition, gpointer data)
{
	NMDhcpNettools *self = data;
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE (self);
	NDhcp4ClientEvent *event;
	int r;

	r = n_dhcp4_client_dispatch(priv->client);
	if (r < 0)
		return G_SOURCE_CONTINUE;

	while (!n_dhcp4_client_pop_event(priv->client, &event) && event) {
		dhcp4_event_handle(self, event);
	}

	return G_SOURCE_CONTINUE;
}

static gboolean
nettools_create (NMDhcpNettools *self,
                 const char *dhcp_anycast_addr,
		 GError **error) {
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE (self);
	nm_auto (n_dhcp4_client_config_freep) NDhcp4ClientConfig *config = NULL;
	nm_auto (n_dhcp4_client_unrefp) NDhcp4Client *client = NULL;
	GBytes *hwaddr;
	const uint8_t *hwaddr_arr;
	gsize hwaddr_len;
	GBytes *client_id;
	gs_unref_bytes GBytes *client_id_new = NULL;
	const uint8_t *client_id_arr;
	size_t client_id_len;
	int r, fd, arp_type, transport;

	g_return_val_if_fail (!priv->client, FALSE);

	hwaddr = nm_dhcp_client_get_hw_addr (NM_DHCP_CLIENT (self));
	if (   !hwaddr
	    || !(hwaddr_arr = g_bytes_get_data (hwaddr, &hwaddr_len))
	    || (arp_type = nm_utils_arp_type_detect_from_hwaddrlen (hwaddr_len)) < 0) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "invalid MAC address");
		return FALSE;
	}

	switch (arp_type) {
	case ARPHRD_ETHER:
		transport = N_DHCP4_TRANSPORT_ETHERNET;
		break;
	case ARPHRD_INFINIBAND:
		transport = N_DHCP4_TRANSPORT_INFINIBAND;
		break;
	default:
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "unsupported ARP type");
		return FALSE;
	}

	/* Note that we always set a client-id. In particular for infiniband that is necessary,
	 * see https://tools.ietf.org/html/rfc4390#section-2.1 . */
	client_id = nm_dhcp_client_get_client_id (NM_DHCP_CLIENT (self));
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

	r = n_dhcp4_client_config_new (&config);
	if (r) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "failed to create client-config");
		return FALSE;
	}

	n_dhcp4_client_config_set_ifindex (config, nm_dhcp_client_get_ifindex (NM_DHCP_CLIENT (self)));
	n_dhcp4_client_config_set_transport (config, transport);
	n_dhcp4_client_config_set_mac (config, hwaddr_arr, hwaddr_len);
	n_dhcp4_client_config_set_broadcast_mac (config, (unsigned char[]){ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, }, ETH_ALEN); /* XXX */
	r = n_dhcp4_client_config_set_client_id (config, client_id_arr, client_id_len);
	if (r) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "failed to set client-id");
		return FALSE;
	}

	r = n_dhcp4_client_new (&client, config);
	if (r) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "failed to create client");
		return FALSE;
	}

	priv->client = client;
	client = NULL;

	n_dhcp4_client_get_fd (priv->client, &fd);
        priv->channel = g_io_channel_unix_new (fd);
        priv->event_id = g_io_add_watch (priv->channel, G_IO_IN, dhcp4_event_cb, self);

	return TRUE;
}

static gboolean
ip4_accept (NMDhcpClient *client,
            GError **error)
{
	NMDhcpNettools *self = NM_DHCP_NETTOOLS (client);
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE (self);
	int r;

	g_return_val_if_fail (priv->lease, FALSE);

	_LOGT ("accept");

	r = n_dhcp4_client_lease_accept(priv->lease);
	if (r) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "failed to accept lease");
		return FALSE;
	}

	priv->lease = n_dhcp4_client_lease_unref(priv->lease);

	return TRUE;
}

static gboolean
ip4_decline (NMDhcpClient *client,
	     const char *error_message,
             GError **error)
{
	NMDhcpNettools *self = NM_DHCP_NETTOOLS (client);
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE (self);
	int r;

	g_return_val_if_fail (priv->lease, FALSE);

	_LOGT ("dhcp4-client: decline");

	r = n_dhcp4_client_lease_decline(priv->lease, error_message);
	if (r) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "failed to decline lease");
		return FALSE;
	}

	priv->lease = n_dhcp4_client_lease_unref(priv->lease);

	return TRUE;
}

static gboolean
ip4_start (NMDhcpClient *client,
           const char *dhcp_anycast_addr,
           const char *last_ip4_address,
           GError **error)
{
	nm_auto (n_dhcp4_client_probe_config_freep) NDhcp4ClientProbeConfig *config = NULL;
	NMDhcpNettools *self = NM_DHCP_NETTOOLS (client);
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE (self);
	struct in_addr last_addr = { 0 };
	const char *hostname;
	int r, i;

	g_return_val_if_fail (!priv->probe, FALSE);

	if (!nettools_create(self, dhcp_anycast_addr, error))
		return FALSE;

	r = n_dhcp4_client_probe_config_new(&config);
	if (r) {
		nm_utils_error_set_errno (error, r, "failed to create dhcp-client-probe-config: %s");
		return FALSE;
	}

	/*
	 * XXX
	 * Select, or configure, a reasonable start delay, to protect poor servers beeing flooded.
	 */
	n_dhcp4_client_probe_config_set_start_delay (config, 500);

	if (last_ip4_address) {
		inet_pton (AF_INET, last_ip4_address, &last_addr);
		n_dhcp4_client_probe_config_set_requested_ip (config, last_addr);
	}

	/* Add requested options */
	for (i = 0; dhcp4_requests[i].name; i++) {
		if (dhcp4_requests[i].include) {
			nm_assert (dhcp4_requests[i].option_num <= 255);
			n_dhcp4_client_probe_config_request_option(config, dhcp4_requests[i].option_num);
		}
	}

	hostname = nm_dhcp_client_get_hostname (client);
	if (hostname) {
		/* XXX: select hostname/FQDN */
		r = n_dhcp4_client_probe_config_append_option(config,
				                              DHCP_OPTION_HOST_NAME,
							      hostname,
							      strlen(hostname));
		if (r) {
			nm_utils_error_set_errno (error, r, "failed to set DHCP hostname: %s");
			return FALSE;
		}
	}

	r = n_dhcp4_client_probe(priv->client, &priv->probe, config);
	if (r) {
		nm_utils_error_set_errno (error, r, "failed to start DHCP client: %s");
		return FALSE;
	}

	_LOGT ("dhcp-client4: start %p", (gpointer) priv->client);

	nm_dhcp_client_start_timeout (client);
	return TRUE;
}

static gboolean
ip6_start (NMDhcpClient *client,
           const char *dhcp_anycast_addr,
           const struct in6_addr *ll_addr,
           NMSettingIP6ConfigPrivacy privacy,
           guint needed_prefixes,
           GError **error)
{
	nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "nettools plugin does not support IPv6");
        return FALSE;
}

static void
stop (NMDhcpClient *client, gboolean release)
{
	NMDhcpNettools *self = NM_DHCP_NETTOOLS (client);
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE (self);

	NM_DHCP_CLIENT_CLASS (nm_dhcp_nettools_parent_class)->stop (client, release);

	_LOGT ("dhcp-client4: stop %p",
	       (gpointer) priv->client);

	priv->probe = n_dhcp4_client_probe_free(priv->probe);
}

/*****************************************************************************/

static void
nm_dhcp_nettools_init (NMDhcpNettools *self)
{
}

static void
dispose (GObject *object)
{
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE ((NMDhcpNettools *) object);

	nm_clear_pointer (&priv->channel, g_io_channel_unref);
        nm_clear_g_source (&priv->event_id);
	nm_clear_pointer (&priv->lease, n_dhcp4_client_lease_unref);
	nm_clear_pointer (&priv->probe, n_dhcp4_client_probe_free);
        nm_clear_pointer (&priv->client, n_dhcp4_client_unref);


	G_OBJECT_CLASS (nm_dhcp_nettools_parent_class)->dispose (object);
}

static void
nm_dhcp_nettools_class_init (NMDhcpNettoolsClass *class)
{
	NMDhcpClientClass *client_class = NM_DHCP_CLIENT_CLASS (class);
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	object_class->dispose = dispose;

	client_class->ip4_start = ip4_start;
	client_class->ip4_accept = ip4_accept;
	client_class->ip4_decline = ip4_decline;
	client_class->ip6_start = ip6_start;
	client_class->stop = stop;
}

const NMDhcpClientFactory _nm_dhcp_client_factory_nettools = {
	.name = "nettools",
	.get_type = nm_dhcp_nettools_get_type,
	.get_path = NULL,
};
