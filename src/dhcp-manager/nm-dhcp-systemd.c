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

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <net/if_arp.h>

#include "nm-default.h"
#include "nm-dhcp-systemd.h"
#include "nm-utils.h"
#include "nm-dhcp-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-platform.h"

#include "sd-dhcp-client.h"
#include "sd-dhcp6-client.h"
#include "dhcp-protocol.h"
#include "dhcp-lease-internal.h"
#include "dhcp6-protocol.h"
#include "dhcp6-lease-internal.h"

G_DEFINE_TYPE (NMDhcpSystemd, nm_dhcp_systemd, NM_TYPE_DHCP_CLIENT)

#define NM_DHCP_SYSTEMD_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_SYSTEMD, NMDhcpSystemdPrivate))

typedef struct {
	struct sd_dhcp_client *client4;
	struct sd_dhcp6_client *client6;
	char *lease_file;

	guint timeout_id;
	guint request_count;

	gboolean privacy;
} NMDhcpSystemdPrivate;

/************************************************************/

#define DHCP_OPTION_NIS_DOMAIN         40
#define DHCP_OPTION_NIS_SERVERS        41
#define DHCP_OPTION_DOMAIN_SEARCH     119
#define DHCP_OPTION_RFC3442_ROUTES    121
#define DHCP_OPTION_MS_ROUTES         249
#define DHCP_OPTION_WPAD              252

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
	{ DHCP_OPTION_SUBNET_MASK,            REQPREFIX "subnet_mask",                     TRUE },
	{ DHCP_OPTION_TIME_OFFSET,            REQPREFIX "time_offset",                     TRUE },
	{ DHCP_OPTION_ROUTER,                 REQPREFIX "routers",                         TRUE },
	{ DHCP_OPTION_DOMAIN_NAME_SERVER,     REQPREFIX "domain_name_servers",             TRUE },
	{ DHCP_OPTION_HOST_NAME,              REQPREFIX "host_name",                       TRUE },
	{ DHCP_OPTION_DOMAIN_NAME,            REQPREFIX "domain_name",                     TRUE },
	{ DHCP_OPTION_INTERFACE_MTU,          REQPREFIX "interface_mtu",                   TRUE },
	{ DHCP_OPTION_BROADCAST,              REQPREFIX "broadcast_address",               TRUE },
	{ DHCP_OPTION_STATIC_ROUTE,           REQPREFIX "static_routes",                   TRUE },
	{ DHCP_OPTION_NIS_DOMAIN,             REQPREFIX "nis_domain",                      TRUE },
	{ DHCP_OPTION_NIS_SERVERS,            REQPREFIX "nis_servers",                     TRUE },
	{ DHCP_OPTION_NTP_SERVER,             REQPREFIX "ntp_servers",                     TRUE },
	{ DHCP_OPTION_SERVER_IDENTIFIER,      REQPREFIX "dhcp_server_identifier",          TRUE },
	{ DHCP_OPTION_DOMAIN_SEARCH,          REQPREFIX "domain_search",                   TRUE },
	{ DHCP_OPTION_CLASSLESS_STATIC_ROUTE, REQPREFIX "rfc3442_classless_static_routes", TRUE },
	{ DHCP_OPTION_MS_ROUTES,              REQPREFIX "ms_classless_static_routes",      TRUE },
	{ DHCP_OPTION_WPAD,                   REQPREFIX "wpad",                            TRUE },

	/* Internal values */
	{ DHCP_OPTION_IP_ADDRESS_LEASE_TIME, REQPREFIX "expiry",                          FALSE },
	{ DHCP_OPTION_CLIENT_IDENTIFIER,     REQPREFIX "dhcp_client_identifier",          FALSE },
	{ DHCP_OPTION_IP_ADDRESS,            REQPREFIX "ip_address",                      FALSE },
	{ 0, NULL, FALSE }
};

static const ReqOption dhcp6_requests[] = {
	{ DHCP6_OPTION_CLIENTID,       REQPREFIX "dhcp6_client_id",     TRUE },

	/* Don't request server ID by default; some servers don't reply to
	 * Information Requests that request the Server ID.
	 */
	{ DHCP6_OPTION_SERVERID,       REQPREFIX "dhcp6_server_id",     FALSE },

	{ DHCP6_OPTION_DNS_SERVERS,    REQPREFIX "dhcp6_name_servers",  TRUE },
	{ DHCP6_OPTION_DOMAIN_LIST,    REQPREFIX "dhcp6_domain_search", TRUE },
	{ DHCP6_OPTION_SNTP_SERVERS,   REQPREFIX "dhcp6_sntp_servers",  TRUE },

	/* Internal values */
	{ DHCP6_OPTION_IP_ADDRESS,     REQPREFIX "ip6_address",         FALSE },
	{ DHCP6_OPTION_PREFIXLEN,      REQPREFIX "ip6_prefixlen",       FALSE },
	{ DHCP6_OPTION_PREFERRED_LIFE, REQPREFIX "preferred_life",      FALSE },
	{ DHCP6_OPTION_MAX_LIFE,       REQPREFIX "max_life",            FALSE },
	{ DHCP6_OPTION_STARTS,         REQPREFIX "starts",              FALSE },
	{ DHCP6_OPTION_LIFE_STARTS,    REQPREFIX "life_starts",         FALSE },
	{ DHCP6_OPTION_RENEW,          REQPREFIX "renew",               FALSE },
	{ DHCP6_OPTION_REBIND,         REQPREFIX "rebind",              FALSE },
	{ DHCP6_OPTION_IAID,           REQPREFIX "iaid",                FALSE },
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
			                     (gpointer) (requests[i].name + STRLEN (REQPREFIX)),
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
		nm_log (LOGL_INFO, (domain), __VA_ARGS__); \
	} \
} G_STMT_END

static NMIP4Config *
lease_to_ip4_config (const char *iface,
                     int ifindex,
                     sd_dhcp_lease *lease,
                     GHashTable *options,
                     guint32 default_priority,
                     gboolean log_lease,
                     GError **error)
{
	NMIP4Config *ip4_config = NULL;
	struct in_addr tmp_addr;
	const struct in_addr *addr_list;
	char buf[INET_ADDRSTRLEN];
	const char *str;
	guint32 lifetime = 0, i;
	NMPlatformIP4Address address;
	GString *l;
	struct sd_dhcp_route *routes;
	guint16 mtu;
	int r, num;
	guint64 end_time;
	const void *data;
	gsize data_len;
	gboolean metered = FALSE;

	g_return_val_if_fail (lease != NULL, NULL);

	ip4_config = nm_ip4_config_new (ifindex);

	/* Address */
	sd_dhcp_lease_get_address (lease, &tmp_addr);
	memset (&address, 0, sizeof (address));
	address.address = tmp_addr.s_addr;
	str = nm_utils_inet4_ntop (tmp_addr.s_addr, NULL);
	LOG_LEASE (LOGD_DHCP4, "  address %s", str);
	add_option (options, dhcp4_requests, DHCP_OPTION_IP_ADDRESS, str);

	/* Prefix/netmask */
	sd_dhcp_lease_get_netmask (lease, &tmp_addr);
	address.plen = nm_utils_ip4_netmask_to_prefix (tmp_addr.s_addr);
	LOG_LEASE (LOGD_DHCP4, "  plen %d", address.plen);
	add_option (options,
	            dhcp4_requests,
	            DHCP_OPTION_SUBNET_MASK,
	            nm_utils_inet4_ntop (tmp_addr.s_addr, NULL));

	/* Lease time */
	sd_dhcp_lease_get_lifetime (lease, &lifetime);
	address.timestamp = nm_utils_get_monotonic_timestamp_s ();
	address.lifetime = address.preferred = lifetime;
	end_time = (guint64) time (NULL) + lifetime;
	LOG_LEASE (LOGD_DHCP4, "  expires in %" G_GUINT32_FORMAT " seconds", lifetime);
	add_option_u64 (options,
	                dhcp4_requests,
	                DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
	                end_time);

	address.source = NM_IP_CONFIG_SOURCE_DHCP;
	nm_ip4_config_add_address (ip4_config, &address);

	/* Gateway */
	r = sd_dhcp_lease_get_router (lease, &tmp_addr);
	if (r == 0) {
		nm_ip4_config_set_gateway (ip4_config, tmp_addr.s_addr);
		str = nm_utils_inet4_ntop (tmp_addr.s_addr, NULL);
		LOG_LEASE (LOGD_DHCP4, "  gateway %s", str);
		add_option (options, dhcp4_requests, DHCP_OPTION_ROUTER, str);
	}

	/* DNS Servers */
	num = sd_dhcp_lease_get_dns (lease, &addr_list);
	if (num > 0) {
		l = g_string_sized_new (30);
		for (i = 0; i < num; i++) {
			if (addr_list[i].s_addr) {
				nm_ip4_config_add_nameserver (ip4_config, addr_list[i].s_addr);
				str = nm_utils_inet4_ntop (addr_list[i].s_addr, NULL);
				LOG_LEASE (LOGD_DHCP4, "  nameserver '%s'", str);
				g_string_append_printf (l, "%s%s", l->len ? " " : "", str);
			}
		}
		if (l->len)
			add_option (options, dhcp4_requests, DHCP_OPTION_DOMAIN_NAME_SERVER, l->str);
		g_string_free (l, TRUE);
	}

	/* Domain Name */
	r = sd_dhcp_lease_get_domainname (lease, &str);
	if (r == 0) {
		/* Multiple domains sometimes stuffed into the option */
		char **domains = g_strsplit (str, " ", 0);
		char **s;

		for (s = domains; *s; s++) {
			LOG_LEASE (LOGD_DHCP4, "  domain name '%s'", *s);
			nm_ip4_config_add_domain (ip4_config, *s);
		}
		g_strfreev (domains);
		add_option (options, dhcp4_requests, DHCP_OPTION_DOMAIN_NAME, str);
	}

	/* Hostname */
	r = sd_dhcp_lease_get_hostname (lease, &str);
	if (r == 0) {
		LOG_LEASE (LOGD_DHCP4, "  hostname '%s'", str);
		add_option (options, dhcp4_requests, DHCP_OPTION_HOST_NAME, str);
	}

	/* Routes */
	num = sd_dhcp_lease_get_routes (lease, &routes);
	if (num > 0) {
		l = g_string_sized_new (30);
		for (i = 0; i < num; i++) {
			NMPlatformIP4Route route;
			const char *gw_str;

			memset (&route, 0, sizeof (route));
			route.network = routes[i].dst_addr.s_addr;
			route.plen = routes[i].dst_prefixlen;
			route.gateway = routes[i].gw_addr.s_addr;
			route.source = NM_IP_CONFIG_SOURCE_DHCP;
			route.metric = default_priority;
			nm_ip4_config_add_route (ip4_config, &route);

			str = nm_utils_inet4_ntop (route.network, buf);
			gw_str = nm_utils_inet4_ntop (route.gateway, NULL);
			LOG_LEASE (LOGD_DHCP4, "  static route %s/%d gw %s", str, route.plen, gw_str);

			g_string_append_printf (l, "%s%s/%d %s", l->len ? " " : "", str, route.plen, gw_str);
		}
		add_option (options, dhcp4_requests, DHCP_OPTION_RFC3442_ROUTES, l->str);
		g_string_free (l, TRUE);
	}

	/* MTU */
	r = sd_dhcp_lease_get_mtu (lease, &mtu);
	if (r == 0 && mtu) {
		nm_ip4_config_set_mtu (ip4_config, mtu, NM_IP_CONFIG_SOURCE_DHCP);
		add_option_u32 (options, dhcp4_requests, DHCP_OPTION_INTERFACE_MTU, mtu);
		LOG_LEASE (LOGD_DHCP4, "  mtu %u", mtu);
	}

	/* NTP servers */
	num = sd_dhcp_lease_get_ntp (lease, &addr_list);
	if (num > 0) {
		l = g_string_sized_new (30);
		for (i = 0; i < num; i++) {
			str = nm_utils_inet4_ntop (addr_list[i].s_addr, buf);
			LOG_LEASE (LOGD_DHCP4, "  ntp server '%s'", str);
			g_string_append_printf (l, "%s%s", l->len ? " " : "", str);
		}
		add_option (options, dhcp4_requests, DHCP_OPTION_NTP_SERVER, l->str);
		g_string_free (l, TRUE);
	}

	r = sd_dhcp_lease_get_vendor_specific (lease, &data, &data_len);
	if (r >= 0)
		metered = !!memmem (data, data_len, "ANDROID_METERED", STRLEN ("ANDROID_METERED"));
	nm_ip4_config_set_metered (ip4_config, metered);

	return ip4_config;
}

/************************************************************/

static char *
get_leasefile_path (const char *iface, const char *uuid, gboolean ipv6)
{
	return g_strdup_printf (NMSTATEDIR "/internal%s-%s-%s.lease",
	                        ipv6 ? "6" : "",
	                        uuid,
	                        iface);
}

static GSList *
nm_dhcp_systemd_get_lease_ip_configs (const char *iface,
                                      int ifindex,
                                      const char *uuid,
                                      gboolean ipv6,
                                      guint32 default_route_metric)
{
	GSList *leases = NULL;
	gs_free char *path = NULL;
	sd_dhcp_lease *lease = NULL;
	NMIP4Config *ip4_config;
	int r;

	if (ipv6)
		return NULL;

	path = get_leasefile_path (iface, uuid, FALSE);
	r = dhcp_lease_load (&lease, path);
	if (r == 0 && lease) {
		ip4_config = lease_to_ip4_config (iface, ifindex, lease, NULL, default_route_metric, FALSE, NULL);
		if (ip4_config)
			leases = g_slist_append (leases, ip4_config);
	}

	return leases;
}

/************************************************************/

static void
_save_client_id (NMDhcpSystemd *self,
                 uint8_t type,
                 const uint8_t *client_id,
                 size_t len)
{
	gs_unref_bytes GBytes *b = NULL;
	gs_free char *buf = NULL;

	g_return_if_fail (self != NULL);
	g_return_if_fail (client_id != NULL);
	g_return_if_fail (len > 0);

	if (!nm_dhcp_client_get_client_id (NM_DHCP_CLIENT (self))) {
		buf = g_malloc (len + 1);
		buf[0] = type;
		memcpy (buf + 1, client_id, len);
		b = g_bytes_new (buf, len + 1);
		nm_dhcp_client_set_client_id (NM_DHCP_CLIENT (self), b);
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

	nm_log_dbg (LOGD_DHCP4, "(%s): lease available", iface);

	r = sd_dhcp_client_get_lease (priv->client4, &lease);
	if (r < 0 || !lease) {
		nm_log_warn (LOGD_DHCP4, "(%s): no lease!", iface);
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return;
	}

	options = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);
	ip4_config = lease_to_ip4_config (iface,
	                                  nm_dhcp_client_get_ifindex (NM_DHCP_CLIENT (self)),
	                                  lease,
	                                  options,
	                                  nm_dhcp_client_get_priority (NM_DHCP_CLIENT (self)),
	                                  TRUE,
	                                  &error);
	if (ip4_config) {
		const uint8_t *client_id = NULL;
		size_t client_id_len = 0;
		uint8_t type = 0;

		add_requests_to_options (options, dhcp4_requests);
		dhcp_lease_save (lease, priv->lease_file);

		sd_dhcp_client_get_client_id(priv->client4, &type, &client_id, &client_id_len);
		if (client_id)
			_save_client_id (self, type, client_id, client_id_len);

		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self),
		                          NM_DHCP_STATE_BOUND,
		                          G_OBJECT (ip4_config),
		                          options);
	} else {
		nm_log_warn (LOGD_DHCP4, "(%s): %s", iface, error->message);
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		g_clear_error (&error);
	}

	sd_dhcp_lease_unref (lease);
	g_hash_table_destroy (options);
	g_clear_object (&ip4_config);
}

static void
dhcp_event_cb (sd_dhcp_client *client, int event, gpointer user_data)
{
	NMDhcpSystemd *self = NM_DHCP_SYSTEMD (user_data);
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (self);
	const char *iface = nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self));

	g_assert (priv->client4 == client);

	nm_log_dbg (LOGD_DHCP4, "(%s): DHCPv4 client event %d", iface, event);

	switch (event) {
	case DHCP_EVENT_EXPIRED:
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (user_data), NM_DHCP_STATE_EXPIRE, NULL, NULL);
		break;
	case DHCP_EVENT_STOP:
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (user_data), NM_DHCP_STATE_FAIL, NULL, NULL);
		break;
	case DHCP_EVENT_RENEW:
	case DHCP_EVENT_IP_CHANGE:
	case DHCP_EVENT_IP_ACQUIRE:
		bound4_handle (self);
		break;
	default:
		nm_log_warn (LOGD_DHCP4, "(%s): unhandled DHCP event %d", iface, event);
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
		g_assert_not_reached ();
}

static gboolean
ip4_start (NMDhcpClient *client, const char *dhcp_anycast_addr, const char *last_ip4_address)
{
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (client);
	const char *iface = nm_dhcp_client_get_iface (client);
	const GByteArray *hwaddr;
	sd_dhcp_lease *lease = NULL;
	GBytes *override_client_id;
	const uint8_t *client_id = NULL;
	size_t client_id_len = 0;
	struct in_addr last_addr = { 0 };
	const char *hostname;
	int r, i;

	g_assert (priv->client4 == NULL);
	g_assert (priv->client6 == NULL);

	g_free (priv->lease_file);
	priv->lease_file = get_leasefile_path (iface, nm_dhcp_client_get_uuid (client), FALSE);

	r = sd_dhcp_client_new (&priv->client4);
	if (r < 0) {
		nm_log_warn (LOGD_DHCP4, "(%s): failed to create DHCPv4 client (%d)", iface, r);
		return FALSE;
	}

	r = sd_dhcp_client_attach_event (priv->client4, NULL, 0);
	if (r < 0) {
		nm_log_warn (LOGD_DHCP4, "(%s): failed to attach DHCP event (%d)", iface, r);
		goto error;
	}

	hwaddr = nm_dhcp_client_get_hw_addr (client);
	if (hwaddr) {
		r = sd_dhcp_client_set_mac (priv->client4,
		                            hwaddr->data,
		                            hwaddr->len,
		                            get_arp_type (hwaddr));
		if (r < 0) {
			nm_log_warn (LOGD_DHCP4, "(%s): failed to set DHCP MAC address (%d)", iface, r);
			goto error;
		}
	}

	r = sd_dhcp_client_set_index (priv->client4, nm_dhcp_client_get_ifindex (client));
	if (r < 0) {
		nm_log_warn (LOGD_DHCP4, "(%s): failed to set DHCP ifindex (%d)", iface, r);
		goto error;
	}

	r = sd_dhcp_client_set_callback (priv->client4, dhcp_event_cb, client);
	if (r < 0) {
		nm_log_warn (LOGD_DHCP4, "(%s): failed to set DHCP callback (%d)", iface, r);
		goto error;
	}

	r = sd_dhcp_client_set_request_broadcast (priv->client4, true);
	if (r < 0) {
		nm_log_warn (LOGD_DHCP4, "(%s): failed to set DHCP broadcast (%d)", iface, r);
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
			nm_log_warn (LOGD_DHCP4, "(%s): failed to set last IPv4 address (%d)", iface, r);
			goto error;
		}
	}

	override_client_id = nm_dhcp_client_get_client_id (client);
	if (override_client_id) {
		client_id = g_bytes_get_data (override_client_id, &client_id_len);
		g_assert (client_id && client_id_len);
		sd_dhcp_client_set_client_id (priv->client4,
		                              client_id[0],
		                              client_id + 1,
		                              client_id_len - 1);
	} else if (lease) {
		r = sd_dhcp_lease_get_client_id (lease, (const void **) &client_id, &client_id_len);
		if (r == 0 && client_id_len) {
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

	if (lease)
		sd_dhcp_lease_unref (lease);

	/* Add requested options */
	for (i = 0; dhcp4_requests[i].name; i++) {
		if (dhcp4_requests[i].include)
			sd_dhcp_client_set_request_option (priv->client4, dhcp4_requests[i].num);
	}

	hostname = nm_dhcp_client_get_hostname (client);
	if (hostname) {
		r = sd_dhcp_client_set_hostname (priv->client4, hostname);
		if (r < 0) {
			nm_log_warn (LOGD_DHCP4, "(%s): failed to set DHCP hostname (%d)", iface, r);
			goto error;
		}
	}

	r = sd_dhcp_client_start (priv->client4);
	if (r < 0) {
		nm_log_warn (LOGD_DHCP4, "(%s): failed to start DHCP (%d)", iface, r);
		goto error;
	}

	return TRUE;

error:
	sd_dhcp_client_unref (priv->client4);
	priv->client4 = NULL;
	return FALSE;
}

static void
bound6_handle (NMDhcpSystemd *self)
{
	/* not yet supported... */
	nm_log_warn (LOGD_DHCP6, "(%s): internal DHCP does not yet support DHCPv6",
	             nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));
	nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
}

static void
dhcp6_event_cb (sd_dhcp6_client *client, int event, gpointer user_data)
{
	NMDhcpSystemd *self = NM_DHCP_SYSTEMD (user_data);
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (self);
	const char *iface = nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self));

	g_assert (priv->client6 == client);

	nm_log_dbg (LOGD_DHCP6, "(%s): DHCPv6 client event %d", iface, event);

	switch (event) {
	case DHCP6_EVENT_RETRANS_MAX:
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (user_data), NM_DHCP_STATE_TIMEOUT, NULL, NULL);
		break;
	case DHCP6_EVENT_RESEND_EXPIRE:
	case DHCP6_EVENT_STOP:
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (user_data), NM_DHCP_STATE_FAIL, NULL, NULL);
		break;
	case DHCP6_EVENT_IP_ACQUIRE:
		bound6_handle (self);
		break;
	default:
		nm_log_warn (LOGD_DHCP6, "(%s): unhandled DHCPv6 event %d", iface, event);
		break;
	}
}

static gboolean
ip6_start (NMDhcpClient *client,
           const char *dhcp_anycast_addr,
           gboolean info_only,
           NMSettingIP6ConfigPrivacy privacy,
           const GByteArray *duid)
{
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (client);
	const char *iface = nm_dhcp_client_get_iface (client);
	const GByteArray *hwaddr;
	int r, i;

	g_assert (priv->client4 == NULL);
	g_assert (priv->client6 == NULL);
	g_return_val_if_fail (duid != NULL, FALSE);

	g_free (priv->lease_file);
	priv->lease_file = get_leasefile_path (iface, nm_dhcp_client_get_uuid (client), TRUE);

	r = sd_dhcp6_client_new (&priv->client6);
	if (r < 0) {
		nm_log_warn (LOGD_DHCP6, "(%s): failed to create DHCPv6 client (%d)", iface, r);
		return FALSE;
	}

	/* NM stores the entire DUID which includes the uint16 "type", while systemd
	 * wants the type passed separately from the following data.
	 */
	r = sd_dhcp6_client_set_duid (priv->client6,
	                              ntohs (((const guint16 *) duid->data)[0]),
	                              duid->data + 2,
	                              duid->len - 2);
	if (r < 0) {
		nm_log_warn (LOGD_DHCP6, "(%s): failed to create DHCPv6 client (%d)", iface, r);
		return FALSE;
	}

	r = sd_dhcp6_client_attach_event (priv->client6, NULL, 0);
	if (r < 0) {
		nm_log_warn (LOGD_DHCP6, "(%s): failed to attach DHCP event (%d)", iface, r);
		goto error;
	}

	hwaddr = nm_dhcp_client_get_hw_addr (client);
	if (hwaddr) {
		r = sd_dhcp6_client_set_mac (priv->client6,
		                             hwaddr->data,
		                             hwaddr->len,
		                             get_arp_type (hwaddr));
		if (r < 0) {
			nm_log_warn (LOGD_DHCP6, "(%s): failed to set DHCP MAC address (%d)", iface, r);
			goto error;
		}
	}

	r = sd_dhcp6_client_set_index (priv->client6, nm_dhcp_client_get_ifindex (client));
	if (r < 0) {
		nm_log_warn (LOGD_DHCP6, "(%s): failed to set DHCP ifindex (%d)", iface, r);
		goto error;
	}

	r = sd_dhcp6_client_set_callback (priv->client6, dhcp6_event_cb, client);
	if (r < 0) {
		nm_log_warn (LOGD_DHCP6, "(%s): failed to set DHCP callback (%d)", iface, r);
		goto error;
	}

	/* Add requested options */
	for (i = 0; dhcp6_requests[i].name; i++) {
		if (dhcp6_requests[i].include)
			sd_dhcp6_client_set_request_option (priv->client6, dhcp6_requests[i].num);
	}

	r = sd_dhcp6_client_start (priv->client6);
	if (r < 0) {
		nm_log_warn (LOGD_DHCP6, "(%s): failed to start DHCP (%d)", iface, r);
		goto error;
	}

	return TRUE;

error:
	sd_dhcp6_client_unref (priv->client6);
	priv->client6 = NULL;
	return FALSE;
}

static void
stop (NMDhcpClient *client, gboolean release, const GByteArray *duid)
{
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (client);
	int r = 0;

	if (priv->client4)
		r = sd_dhcp_client_stop (priv->client4);
	else if (priv->client6)
		r = sd_dhcp6_client_stop (priv->client6);

	if (r) {
		nm_log_warn (priv->client6 ? LOGD_DHCP6 : LOGD_DHCP4,
			         "(%s): failed to stop DHCP client (%d)",
			         nm_dhcp_client_get_iface (client),
			         r);
	}
}

/***************************************************/

static void
nm_dhcp_systemd_init (NMDhcpSystemd *self)
{
}

static void
dispose (GObject *object)
{
	NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE (object);

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

	g_type_class_add_private (sdhcp_class, sizeof (NMDhcpSystemdPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	client_class->ip4_start = ip4_start;
	client_class->ip6_start = ip6_start;
	client_class->stop = stop;
}

static void __attribute__((constructor))
register_dhcp_dhclient (void)
{
	nm_g_type_init ();
	_nm_dhcp_client_register (NM_TYPE_DHCP_SYSTEMD,
	                          "internal",
	                          NULL,
	                          nm_dhcp_systemd_get_lease_ip_configs);
}

