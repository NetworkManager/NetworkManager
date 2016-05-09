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

#include "nm-dhcp-systemd.h"
#include "nm-utils.h"
#include "nm-dhcp-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-platform.h"
#include "nm-dhcp-client-logging.h"

#include "sd-dhcp-client.h"
#include "sd-dhcp6-client.h"

#include "nm-sd-adapt.h"
#include "dhcp-lease-internal.h"

G_DEFINE_TYPE (NMDhcpSystemd, nm_dhcp_systemd, NM_TYPE_DHCP_CLIENT)

#define NM_DHCP_SYSTEMD_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_SYSTEMD, NMDhcpSystemdPrivate))

typedef struct {
	sd_dhcp_client *client4;
	sd_dhcp6_client *client6;
	char *lease_file;

	guint request_count;

	gboolean privacy;
	gboolean info_only;
} NMDhcpSystemdPrivate;

/************************************************************/

#define DHCP_OPTION_NIS_DOMAIN         40
#define DHCP_OPTION_NIS_SERVERS        41
#define DHCP_OPTION_DOMAIN_SEARCH     119
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
	{ SD_DHCP_OPTION_SUBNET_MASK,            REQPREFIX "subnet_mask",                     TRUE },
	{ SD_DHCP_OPTION_TIME_OFFSET,            REQPREFIX "time_offset",                     TRUE },
	{ SD_DHCP_OPTION_ROUTER,                 REQPREFIX "routers",                         TRUE },
	{ SD_DHCP_OPTION_DOMAIN_NAME_SERVER,     REQPREFIX "domain_name_servers",             TRUE },
	{ SD_DHCP_OPTION_HOST_NAME,              REQPREFIX "host_name",                       TRUE },
	{ SD_DHCP_OPTION_DOMAIN_NAME,            REQPREFIX "domain_name",                     TRUE },
	{ SD_DHCP_OPTION_INTERFACE_MTU,          REQPREFIX "interface_mtu",                   TRUE },
	{ SD_DHCP_OPTION_BROADCAST,              REQPREFIX "broadcast_address",               TRUE },
	{ SD_DHCP_OPTION_STATIC_ROUTE,           REQPREFIX "static_routes",                   TRUE },
	{ DHCP_OPTION_NIS_DOMAIN,                REQPREFIX "nis_domain",                      TRUE },
	{ DHCP_OPTION_NIS_SERVERS,               REQPREFIX "nis_servers",                     TRUE },
	{ SD_DHCP_OPTION_NTP_SERVER,             REQPREFIX "ntp_servers",                     TRUE },
	{ SD_DHCP_OPTION_SERVER_IDENTIFIER,      REQPREFIX "dhcp_server_identifier",          TRUE },
	{ DHCP_OPTION_DOMAIN_SEARCH,             REQPREFIX "domain_search",                   TRUE },
	{ SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE, REQPREFIX "rfc3442_classless_static_routes", TRUE },
	{ DHCP_OPTION_MS_ROUTES,                 REQPREFIX "ms_classless_static_routes",      TRUE },
	{ DHCP_OPTION_WPAD,                      REQPREFIX "wpad",                            TRUE },

	/* Internal values */
	{ SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME,  REQPREFIX "expiry",                          FALSE },
	{ SD_DHCP_OPTION_CLIENT_IDENTIFIER,      REQPREFIX "dhcp_client_identifier",          FALSE },
	{ DHCP_OPTION_IP_ADDRESS,                REQPREFIX "ip_address",                      FALSE },
	{ 0, NULL, FALSE }
};

static const ReqOption dhcp6_requests[] = {
	{ SD_DHCP6_OPTION_CLIENTID,              REQPREFIX "dhcp6_client_id",     TRUE },

	/* Don't request server ID by default; some servers don't reply to
	 * Information Requests that request the Server ID.
	 */
	{ SD_DHCP6_OPTION_SERVERID,              REQPREFIX "dhcp6_server_id",     FALSE },

	{ SD_DHCP6_OPTION_DNS_SERVERS,           REQPREFIX "dhcp6_name_servers",  TRUE },
	{ SD_DHCP6_OPTION_DOMAIN_LIST,           REQPREFIX "dhcp6_domain_search", TRUE },
	{ SD_DHCP6_OPTION_SNTP_SERVERS,          REQPREFIX "dhcp6_sntp_servers",  TRUE },

	/* Internal values */
	{ DHCP6_OPTION_IP_ADDRESS,               REQPREFIX "ip6_address",         FALSE },
	{ DHCP6_OPTION_PREFIXLEN,                REQPREFIX "ip6_prefixlen",       FALSE },
	{ DHCP6_OPTION_PREFERRED_LIFE,           REQPREFIX "preferred_life",      FALSE },
	{ DHCP6_OPTION_MAX_LIFE,                 REQPREFIX "max_life",            FALSE },
	{ DHCP6_OPTION_STARTS,                   REQPREFIX "starts",              FALSE },
	{ DHCP6_OPTION_LIFE_STARTS,              REQPREFIX "life_starts",         FALSE },
	{ DHCP6_OPTION_RENEW,                    REQPREFIX "renew",               FALSE },
	{ DHCP6_OPTION_REBIND,                   REQPREFIX "rebind",              FALSE },
	{ DHCP6_OPTION_IAID,                     REQPREFIX "iaid",                FALSE },
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
	gs_free sd_dhcp_route **routes = NULL;
	guint16 mtu;
	int r, num;
	guint64 end_time;
	const void *data;
	gsize data_len;
	gboolean metered = FALSE;
	gboolean static_default_gateway = FALSE;

	g_return_val_if_fail (lease != NULL, NULL);

	ip4_config = nm_ip4_config_new (ifindex);

	/* Address */
	sd_dhcp_lease_get_address (lease, &tmp_addr);
	memset (&address, 0, sizeof (address));
	address.address = tmp_addr.s_addr;
	address.peer_address = tmp_addr.s_addr;
	str = nm_utils_inet4_ntop (tmp_addr.s_addr, NULL);
	LOG_LEASE (LOGD_DHCP4, "  address %s", str);
	add_option (options, dhcp4_requests, DHCP_OPTION_IP_ADDRESS, str);

	/* Prefix/netmask */
	sd_dhcp_lease_get_netmask (lease, &tmp_addr);
	address.plen = nm_utils_ip4_netmask_to_prefix (tmp_addr.s_addr);
	LOG_LEASE (LOGD_DHCP4, "  plen %d", address.plen);
	add_option (options,
	            dhcp4_requests,
	            SD_DHCP_OPTION_SUBNET_MASK,
	            nm_utils_inet4_ntop (tmp_addr.s_addr, NULL));

	/* Lease time */
	sd_dhcp_lease_get_lifetime (lease, &lifetime);
	address.timestamp = nm_utils_get_monotonic_timestamp_s ();
	address.lifetime = address.preferred = lifetime;
	end_time = (guint64) time (NULL) + lifetime;
	LOG_LEASE (LOGD_DHCP4, "  expires in %" G_GUINT32_FORMAT " seconds", lifetime);
	add_option_u64 (options,
	                dhcp4_requests,
	                SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
	                end_time);

	address.source = NM_IP_CONFIG_SOURCE_DHCP;
	nm_ip4_config_add_address (ip4_config, &address);

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
			add_option (options, dhcp4_requests, SD_DHCP_OPTION_DOMAIN_NAME_SERVER, l->str);
		g_string_free (l, TRUE);
	}

	/* Domain Name */
	r = sd_dhcp_lease_get_domainname (lease, &str);
	if (r == 0) {
		/* Multiple domains sometimes stuffed into option 15 "Domain Name".
		 * As systemd escapes such characters, split them at \\032. */
		char **domains = g_strsplit (str, "\\032", 0);
		char **s;

		for (s = domains; *s; s++) {
			LOG_LEASE (LOGD_DHCP4, "  domain name '%s'", *s);
			nm_ip4_config_add_domain (ip4_config, *s);
		}
		g_strfreev (domains);
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_DOMAIN_NAME, str);
	}

	/* Hostname */
	r = sd_dhcp_lease_get_hostname (lease, &str);
	if (r == 0) {
		LOG_LEASE (LOGD_DHCP4, "  hostname '%s'", str);
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_HOST_NAME, str);
	}

	/* Routes */
	num = sd_dhcp_lease_get_routes (lease, &routes);
	if (num > 0) {
		l = g_string_sized_new (30);
		for (i = 0; i < num; i++) {
			NMPlatformIP4Route route = { 0 };
			const char *gw_str;
			guint8 plen;
			struct in_addr a;

			if (sd_dhcp_route_get_destination (routes[i], &a) < 0)
				continue;
			route.network = a.s_addr;

			if (   sd_dhcp_route_get_destination_prefix_length (routes[i], &plen) < 0
			    || plen > 32)
				continue;
			route.plen = plen;

			if (sd_dhcp_route_get_gateway (routes[i], &a) < 0)
				continue;
			route.gateway = a.s_addr;

			if (route.plen) {
				route.source = NM_IP_CONFIG_SOURCE_DHCP;
				route.metric = default_priority;
				nm_ip4_config_add_route (ip4_config, &route);

				str = nm_utils_inet4_ntop (route.network, buf);
				gw_str = nm_utils_inet4_ntop (route.gateway, NULL);
				LOG_LEASE (LOGD_DHCP4, "  static route %s/%d gw %s", str, route.plen, gw_str);

				g_string_append_printf (l, "%s%s/%d %s", l->len ? " " : "", str, route.plen, gw_str);
			} else {
				if (!static_default_gateway) {
					static_default_gateway = TRUE;
					nm_ip4_config_set_gateway (ip4_config, route.gateway);

					str = nm_utils_inet4_ntop (route.gateway, NULL);
					LOG_LEASE (LOGD_DHCP4, "  gateway %s", str);
					add_option (options, dhcp4_requests, SD_DHCP_OPTION_ROUTER, str);
				}
			}
		}
		if (l->len)
			add_option (options, dhcp4_requests, SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE, l->str);
		g_string_free (l, TRUE);
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
			nm_ip4_config_set_gateway (ip4_config, tmp_addr.s_addr);
			str = nm_utils_inet4_ntop (tmp_addr.s_addr, NULL);
			LOG_LEASE (LOGD_DHCP4, "  gateway %s", str);
			add_option (options, dhcp4_requests, SD_DHCP_OPTION_ROUTER, str);
		}
	}

	/* MTU */
	r = sd_dhcp_lease_get_mtu (lease, &mtu);
	if (r == 0 && mtu) {
		nm_ip4_config_set_mtu (ip4_config, mtu, NM_IP_CONFIG_SOURCE_DHCP);
		add_option_u32 (options, dhcp4_requests, SD_DHCP_OPTION_INTERFACE_MTU, mtu);
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
		add_option (options, dhcp4_requests, SD_DHCP_OPTION_NTP_SERVER, l->str);
		g_string_free (l, TRUE);
	}

	r = sd_dhcp_lease_get_vendor_specific (lease, &data, &data_len);
	if (r >= 0)
		metered = !!memmem (data, data_len, "ANDROID_METERED", NM_STRLEN ("ANDROID_METERED"));
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
		sd_dhcp_lease_unref (lease);
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

	r = sd_dhcp_client_get_lease (priv->client4, &lease);
	if (r < 0 || !lease) {
		_LOGW ("no lease!");
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return;
	}

	_LOGD ("lease available");

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
	const char *hostname, *fqdn;
	int r, i;
	gboolean success = FALSE;
	guint16 arp_type;

	g_assert (priv->client4 == NULL);
	g_assert (priv->client6 == NULL);

	g_free (priv->lease_file);
	priv->lease_file = get_leasefile_path (iface, nm_dhcp_client_get_uuid (client), FALSE);

	r = sd_dhcp_client_new (&priv->client4);
	if (r < 0) {
		_LOGW ("failed to create client (%d)", r);
		return FALSE;
	}

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

	r = sd_dhcp_client_set_index (priv->client4, nm_dhcp_client_get_ifindex (client));
	if (r < 0) {
		_LOGW ("failed to set ifindex (%d)", r);
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


	/* Add requested options */
	for (i = 0; dhcp4_requests[i].name; i++) {
		if (dhcp4_requests[i].include)
			sd_dhcp_client_set_request_option (priv->client4, dhcp4_requests[i].num);
	}

	hostname = nm_dhcp_client_get_hostname (client);
	if (hostname) {
		char *prefix, *dot;

		prefix = strdup (hostname);
		dot = strchr (prefix, '.');
		/* get rid of the domain */
		if (dot)
			*dot = '\0';

		r = sd_dhcp_client_set_hostname (priv->client4, prefix);
		free (prefix);

		if (r < 0) {
			_LOGW ("failed to set DHCP hostname (%d)", r);
			goto error;
		}
	}

	fqdn = nm_dhcp_client_get_fqdn (client);
	if (fqdn) {
		r = sd_dhcp_client_set_hostname (priv->client4, fqdn);
		if (r < 0) {
			_LOGW ("failed to set DHCP FQDN (%d)", r);
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
lease_to_ip6_config (const char *iface,
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
	GString *str;
	int num, i;
	gint32 ts;

	g_return_val_if_fail (lease, NULL);
	ip6_config = nm_ip6_config_new (ifindex);
	ts = nm_utils_get_monotonic_timestamp_s ();
	str = g_string_sized_new (30);

	/* Addresses */
	sd_dhcp6_lease_reset_address_iter (lease);
	while (sd_dhcp6_lease_get_address (lease, &tmp_addr, &lft_pref, &lft_valid) >= 0) {
		NMPlatformIP6Address address = {
			.plen = 128,
			.address = tmp_addr,
			.timestamp = ts,
			.lifetime = lft_valid,
			.preferred = lft_pref,
			.source = NM_IP_CONFIG_SOURCE_DHCP,
		};

		nm_ip6_config_add_address (ip6_config, &address);

		addr_str = nm_utils_inet6_ntop (&tmp_addr, NULL);
		g_string_append_printf (str, "%s%s", str->len ? " " : "", addr_str);

		LOG_LEASE (LOGD_DHCP6,
		           "  address %s",
		           nm_platform_ip6_address_to_string (&address, NULL, 0));
	};

	if (str->len) {
		add_option (options, dhcp6_requests, DHCP6_OPTION_IP_ADDRESS, str->str);
		g_string_set_size (str , 0);
	}

	if (!info_only && nm_ip6_config_get_num_addresses (ip6_config) == 0) {
		g_string_free (str, TRUE);
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
		for (i = 0; i < num; i++) {
			nm_ip6_config_add_nameserver (ip6_config, &dns[i]);
			addr_str = nm_utils_inet6_ntop (&dns[i], NULL);
			g_string_append_printf (str, "%s%s", str->len ? " " : "", addr_str);
			LOG_LEASE (LOGD_DHCP6, "  nameserver %s", addr_str);
		}
		add_option (options, dhcp6_requests, SD_DHCP6_OPTION_DNS_SERVERS, str->str);
		g_string_set_size (str, 0);
	}

	/* Search domains */
	num = sd_dhcp6_lease_get_domains (lease, &domains);
	if (num > 0) {
		for (i = 0; i < num; i++) {
			nm_ip6_config_add_search (ip6_config, domains[i]);
			g_string_append_printf (str, "%s%s", str->len ? " " : "", domains[i]);
			LOG_LEASE (LOGD_DHCP6, "  domain name '%s'", domains[i]);
		}
		add_option (options, dhcp6_requests, SD_DHCP6_OPTION_DOMAIN_LIST, str->str);
		g_string_set_size (str, 0);
	}

	g_string_free (str, TRUE);

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

	options = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);
	ip6_config = lease_to_ip6_config (iface,
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
           const GByteArray *duid)
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
	priv->lease_file = get_leasefile_path (iface, nm_dhcp_client_get_uuid (client), TRUE);
	priv->info_only = info_only;

	r = sd_dhcp6_client_new (&priv->client6);
	if (r < 0) {
		_LOGW ("failed to create client (%d)", r);
		return FALSE;
	}

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

	r = sd_dhcp6_client_set_index (priv->client6, nm_dhcp_client_get_ifindex (client));
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

