/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Library General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

#include "nm-sd-adapt-shared.h"
#include "hostname-util.h"

#include "nm-glib-aux/nm-dedup-multi.h"
#include "nm-std-aux/unaligned.h"

#include "nm-utils.h"
#include "nm-config.h"
#include "nm-dhcp-utils.h"
#include "nm-dhcp-options.h"
#include "nm-core-utils.h"
#include "NetworkManagerUtils.h"
#include "platform/nm-platform.h"
#include "nm-dhcp-client-logging.h"
#include "n-dhcp4/src/n-dhcp4.h"
#include "systemd/nm-sd-utils-shared.h"

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

#define DHCP_MAX_FQDN_LENGTH 255

enum {
	DHCP_FQDN_FLAG_S = (1 << 0),
	DHCP_FQDN_FLAG_O = (1 << 1),
	DHCP_FQDN_FLAG_E = (1 << 2),
	DHCP_FQDN_FLAG_N = (1 << 3),
};

enum {
	NM_IN_ADDR_CLASS_A,
	NM_IN_ADDR_CLASS_B,
	NM_IN_ADDR_CLASS_C,
	NM_IN_ADDR_CLASS_INVALID,
};

static int
in_addr_class (struct in_addr addr)
{
	switch (ntohl (addr.s_addr) >> 24) {
	case   0 ... 127:
		return NM_IN_ADDR_CLASS_A;
	case 128 ... 191:
		return NM_IN_ADDR_CLASS_B;
	case 192 ... 223:
		return NM_IN_ADDR_CLASS_C;
	default:
		return NM_IN_ADDR_CLASS_INVALID;
	}
}

static gboolean
lease_option_consume (void *out,
                      size_t n_out,
                      uint8_t **datap,
                      size_t *n_datap)
{
	if (*n_datap < n_out)
		return FALSE;

	memcpy (out, *datap, n_out);
	*datap += n_out;
	*n_datap -= n_out;
	return TRUE;
}

static gboolean
lease_option_next_in_addr (struct in_addr *addrp,
                           uint8_t **datap,
                           size_t *n_datap)
{
	return lease_option_consume (addrp, sizeof (struct in_addr), datap, n_datap);
}

static gboolean
lease_option_next_route (struct in_addr *destp,
                         uint8_t *plenp,
                         struct in_addr *gatewayp,
                         gboolean classless,
                         uint8_t **datap,
                         size_t *n_datap)
{
	struct in_addr dest = {}, gateway;
	uint8_t *data = *datap;
	size_t n_data = *n_datap;
	uint8_t plen;

	if (classless) {
		if (!lease_option_consume (&plen, sizeof (plen), &data, &n_data))
			return FALSE;

		if (plen > 32)
			return FALSE;

		if (!lease_option_consume (&dest, plen / 8, &data, &n_data))
			return FALSE;
	} else {
		if (!lease_option_next_in_addr (&dest, &data, &n_data))
			return FALSE;

		switch (in_addr_class (dest)) {
		case NM_IN_ADDR_CLASS_A:
			plen = 8;
			break;
		case NM_IN_ADDR_CLASS_B:
			plen = 16;
			break;
		case NM_IN_ADDR_CLASS_C:
			plen = 24;
			break;
		case NM_IN_ADDR_CLASS_INVALID:
			return FALSE;
		}
	}

	dest.s_addr = nm_utils_ip4_address_clear_host_address (dest.s_addr, plen);

	if (!lease_option_next_in_addr (&gateway, &data, &n_data))
		return FALSE;

	*destp = dest;
	*plenp = plen;
	*gatewayp = gateway;
	*datap = data;
	*n_datap = n_data;
	return TRUE;
}

static gboolean
lease_option_print_label (GString *str, size_t n_label, uint8_t **datap, size_t *n_datap)
{
	for (size_t i = 0; i < n_label; ++i) {
		uint8_t c;

		if (!lease_option_consume(&c, sizeof (c), datap, n_datap))
			return FALSE;

		switch (c) {
                case 'a' ... 'z':
                case 'A' ... 'Z':
		case '0' ... '9':
                case '-':
		case '_':
			g_string_append_c(str, c);
			break;
		case '.':
		case '\\':
			g_string_append_printf(str, "\\%c", c);
			break;
		default:
			g_string_append_printf(str, "\\%3d", c);
		}
	}

	return TRUE;
}

static gboolean
lease_option_print_domain_name (GString *str, uint8_t *cache, size_t *n_cachep, uint8_t **datap, size_t *n_datap)
{
	uint8_t *domain;
	size_t n_domain, n_cache = *n_cachep;
	uint8_t **domainp = datap;
	size_t *n_domainp = n_datap;
	gboolean first = TRUE;
	uint8_t c;

	/*
	 * We are given two adjacent memory regions. The @cache contains alreday parsed
	 * domain names, and the @datap contains the remaining data to parse.
	 *
	 * A domain name is formed from a sequence of labels. Each label start with
	 * a length byte, where the two most significant bits are unset. A zero-length
	 * label indicates the end of the domain name.
	 *
	 * Alternatively, a label can be followed by an offset (indicated by the two
	 * most significant bits being set in the next byte that is read). The offset
	 * is an offset into the cache, where the next label of the domain name can
	 * be found.
	 *
	 * Note, that each time a jump to an offset is performed, the size of the
	 * cache shrinks, so this is guaranteed to terminate.
	 */
	if (cache + n_cache != *datap)
		return FALSE;

	for (;;) {
		if (!lease_option_consume(&c, sizeof (c), domainp, n_domainp))
			return FALSE;

		switch (c & 0xC0) {
		case 0x00: /* label length */
		{
			size_t n_label = c;

			if (n_label == 0) {
				/*
				 * We reached the final label of the domain name. Adjust
				 * the cache to include the consumed data, and return.
				 */
				*n_cachep = *datap - cache;
				return TRUE;
			}

			if (!first) {
				g_string_append_c(str, '.');
				first = FALSE;
			}

			if (!lease_option_print_label (str, n_label, domainp, n_domainp))
				return FALSE;

			break;
		}
		case 0xC0: /* back pointer */
		{
			size_t offset = (c & 0x3F) << 16;

			/*
			 * The offset is given as two bytes (in big endian), where the
			 * two high bits are masked out.
			 */

			if (!lease_option_consume (&c, sizeof (c), domainp, n_domainp))
				return FALSE;

			offset += c;

			if (offset >= n_cache)
				return FALSE;

			domain = cache + offset;
			n_domain = n_cache - offset;
			n_cache = offset;

			domainp = &domain;
			n_domainp = &n_domain;

			break;
		}
		default:
			return FALSE;
		}
	}
}

static gboolean
lease_get_in_addr (NDhcp4ClientLease *lease,
                   guint8 option,
                   struct in_addr *addrp) {
	struct in_addr addr;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query (lease, option, &data, &n_data);
	if (r)
		return FALSE;

	if (!lease_option_next_in_addr (&addr, &data, &n_data))
		return FALSE;

	if (n_data != 0)
		return FALSE;

	*addrp = addr;
	return TRUE;
}

static gboolean
lease_get_u16 (NDhcp4ClientLease *lease,
               uint8_t option,
               uint16_t *u16p)
{
	uint8_t *data;
	size_t n_data;
	uint16_t be16;
	int r;

	r = n_dhcp4_client_lease_query (lease, option, &data, &n_data);
	if (r)
		return FALSE;

	if (n_data != sizeof (be16))
		return FALSE;

	memcpy (&be16, data, sizeof (be16));

	*u16p = ntohs(be16);
	return TRUE;
}

#define LOG_LEASE(domain, ...) \
    G_STMT_START { \
        _LOG2I ((domain), (iface), "  "__VA_ARGS__); \
    } G_STMT_END

static gboolean
lease_parse_address (NDhcp4ClientLease *lease,
                     const char *iface,
                     NMIP4Config *ip4_config,
                     GHashTable *options,
                     GError **error)
{
	char addr_str[NM_UTILS_INET_ADDRSTRLEN];
	const gint64 ts = nm_utils_get_monotonic_timestamp_ns ();
	struct in_addr a_address;
	struct in_addr a_netmask;
	guint32 a_plen;
	guint64 a_lifetime;

	n_dhcp4_client_lease_get_yiaddr (lease, &a_address);
	if (a_address.s_addr == INADDR_ANY) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "could not get address from lease");
		return FALSE;
	}

	/* n_dhcp4_client_lease_get_lifetime() never fails */
	n_dhcp4_client_lease_get_lifetime (lease, &a_lifetime);

	if (!lease_get_in_addr (lease, NM_DHCP_OPTION_DHCP4_SUBNET_MASK, &a_netmask)) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "could not get netmask from lease");
		return FALSE;
	}

	nm_utils_inet4_ntop (a_address.s_addr, addr_str);
	a_plen = nm_utils_ip4_netmask_to_prefix (a_netmask.s_addr);

	LOG_LEASE (LOGD_DHCP4, "address %s/%u", addr_str, a_plen);
	nm_dhcp_option_add_option (options,
	                           _nm_dhcp_option_dhcp4_options,
	                           NM_DHCP_OPTION_DHCP4_NM_IP_ADDRESS,
	                           addr_str);
	nm_dhcp_option_add_option (options,
	                           _nm_dhcp_option_dhcp4_options,
	                           NM_DHCP_OPTION_DHCP4_SUBNET_MASK,
	                           nm_utils_inet4_ntop (a_netmask.s_addr, addr_str));

	LOG_LEASE (LOGD_DHCP4, "expires in %u seconds",
	           (guint) ((a_lifetime - ts)/1000000000));
	nm_dhcp_option_add_option_u64 (options,
	                               _nm_dhcp_option_dhcp4_options,
	                               NM_DHCP_OPTION_DHCP4_IP_ADDRESS_LEASE_TIME,
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
                                 GHashTable *options)
{
	nm_auto_free_gstring GString *str = NULL;
	char addr_str[NM_UTILS_INET_ADDRSTRLEN];
	struct in_addr addr;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query (lease, NM_DHCP_OPTION_DHCP4_DOMAIN_NAME_SERVER, &data, &n_data);
	if (r)
		return;

	nm_gstring_prepare (&str);

	while (lease_option_next_in_addr (&addr, &data, &n_data)) {

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
	nm_dhcp_option_add_option (options,
	                           _nm_dhcp_option_dhcp4_options,
	                           NM_DHCP_OPTION_DHCP4_DOMAIN_NAME_SERVER,
	                           str->str);
}

static void
lease_parse_routes (NDhcp4ClientLease *lease,
                    const char *iface,
                    NMIP4Config *ip4_config,
                    GHashTable *options,
                    guint32 route_table,
                    guint32 route_metric)
{
	nm_auto_free_gstring GString *str = NULL;
	char dest_str[NM_UTILS_INET_ADDRSTRLEN];
	char gateway_str[NM_UTILS_INET_ADDRSTRLEN];
	const char *s;
	struct in_addr dest, gateway;
	uint8_t plen;
	guint32 m;
	gboolean has_router_from_classless = FALSE, has_classless = FALSE;
	guint32 default_route_metric = route_metric;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query (lease, NM_DHCP_OPTION_DHCP4_CLASSLESS_STATIC_ROUTE, &data, &n_data);
	if (!r) {
		nm_gstring_prepare (&str);

		has_classless = TRUE;

		while (lease_option_next_route (&dest, &plen, &gateway, TRUE, &data, &n_data)) {

			nm_utils_inet4_ntop (dest.s_addr, dest_str);
			nm_utils_inet4_ntop (gateway.s_addr, gateway_str);

			LOG_LEASE (LOGD_DHCP4,
			           "classless static route %s/%d gw %s",
			           dest_str,
			           (int) plen,
			           gateway_str);
			g_string_append_printf (nm_gstring_add_space_delimiter (str),
			                        "%s/%d %s",
			                        dest_str,
			                        (int) plen,
			                        gateway_str);

			if (plen == 0) {
				/* if there are multiple default routes, we add them with differing
				 * metrics. */
				m = default_route_metric;
				if (default_route_metric < G_MAXUINT32)
					default_route_metric++;

				has_router_from_classless = TRUE;
			} else {
				m = route_metric;
                        }

			nm_ip4_config_add_route (ip4_config,
			                         &((const NMPlatformIP4Route) {
			                             .network       = dest.s_addr,
			                             .plen          = plen,
			                             .gateway       = gateway.s_addr,
			                             .rt_source     = NM_IP_CONFIG_SOURCE_DHCP,
			                             .metric        = m,
			                             .table_coerced = nm_platform_route_table_coerce (route_table),
			                         }),
			                         NULL);
		}
		nm_dhcp_option_add_option (options,
		                           _nm_dhcp_option_dhcp4_options,
		                           NM_DHCP_OPTION_DHCP4_CLASSLESS_STATIC_ROUTE,
		                           str->str);
	}

	r = n_dhcp4_client_lease_query (lease, NM_DHCP_OPTION_DHCP4_STATIC_ROUTE, &data, &n_data);
	if (!r) {
		nm_gstring_prepare (&str);

		while (lease_option_next_route (&dest, &plen, &gateway, FALSE, &data, &n_data)) {

			nm_utils_inet4_ntop (dest.s_addr, dest_str);
			nm_utils_inet4_ntop (gateway.s_addr, gateway_str);

			LOG_LEASE (LOGD_DHCP4,
			           "static route %s/%d gw %s",
			           dest_str,
			           (int) plen,
			           gateway_str);
			g_string_append_printf (nm_gstring_add_space_delimiter (str),
			                        "%s/%d %s",
			                        dest_str,
			                        (int) plen,
			                        gateway_str);

			if (has_classless) {
				/* RFC 3443: if the DHCP server returns both a Classless Static Routes
				 * option and a Static Routes option, the DHCP client MUST ignore the
				 * Static Routes option. */
				continue;
			}

			if (plen == 0) {
				/* for option 33 (static route), RFC 2132 says:
				 *
				 * The default route (0.0.0.0) is an illegal destination for a static
				 * route. */
				continue;
			}

			nm_ip4_config_add_route (ip4_config,
			                         &((const NMPlatformIP4Route) {
			                             .network       = dest.s_addr,
			                             .plen          = plen,
			                             .gateway       = gateway.s_addr,
			                             .rt_source     = NM_IP_CONFIG_SOURCE_DHCP,
			                             .metric        = route_metric,
			                             .table_coerced = nm_platform_route_table_coerce (route_table),
			                         }),
			                         NULL);
		}
		nm_dhcp_option_add_option (options,
		                           _nm_dhcp_option_dhcp4_options,
		                           NM_DHCP_OPTION_DHCP4_STATIC_ROUTE,
		                           str->str);
	}

	r = n_dhcp4_client_lease_query (lease, NM_DHCP_OPTION_DHCP4_ROUTER, &data, &n_data);
	if (!r) {
		nm_gstring_prepare (&str);

		while (lease_option_next_in_addr (&gateway, &data, &n_data)) {
			s = nm_utils_inet4_ntop (gateway.s_addr, gateway_str);
			g_string_append (nm_gstring_add_space_delimiter (str), s);

			if (gateway.s_addr == 0) {
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
			                                 .gateway       = gateway.s_addr,
			                                 .table_coerced = nm_platform_route_table_coerce (route_table),
			                                 .metric        = m,
			                         }),
			                         NULL);
		}
		LOG_LEASE (LOGD_DHCP4, "router %s", str->str);
		nm_dhcp_option_add_option (options,
		                           _nm_dhcp_option_dhcp4_options,
		                           NM_DHCP_OPTION_DHCP4_ROUTER,
		                           str->str);
	}
}

static void
lease_parse_mtu (NDhcp4ClientLease *lease,
                 const char *iface,
                 NMIP4Config *ip4_config,
                 GHashTable *options)
{
	uint16_t mtu;

	if (!lease_get_u16 (lease, NM_DHCP_OPTION_DHCP4_INTERFACE_MTU, &mtu))
		return;

	if (mtu < 68)
		return;

	LOG_LEASE (LOGD_DHCP4, "mtu %u", mtu);
	nm_dhcp_option_add_option_u64 (options,
	                               _nm_dhcp_option_dhcp4_options,
	                               NM_DHCP_OPTION_DHCP4_INTERFACE_MTU,
	                               mtu);
	nm_ip4_config_set_mtu (ip4_config, mtu, NM_IP_CONFIG_SOURCE_DHCP);
}

static void
lease_parse_metered (NDhcp4ClientLease *lease,
                     const char *iface,
                     NMIP4Config *ip4_config,
                     GHashTable *options)
{
	gboolean metered = FALSE;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query (lease, NM_DHCP_OPTION_DHCP4_VENDOR_SPECIFIC, &data, &n_data);
	if (r) {
		metered = FALSE;
	} else {
		metered = !!memmem (data, n_data, "ANDROID_METERED", NM_STRLEN ("ANDROID_METERED"));
	}

	LOG_LEASE (LOGD_DHCP4, "%s", metered ? "metered" : "unmetered");
	nm_ip4_config_set_metered (ip4_config, metered);
}

static void
lease_parse_ntps (NDhcp4ClientLease *lease,
                  const char *iface,
                  GHashTable *options)
{
	nm_auto_free_gstring GString *str = NULL;
	char addr_str[NM_UTILS_INET_ADDRSTRLEN];
	struct in_addr addr;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query (lease, NM_DHCP_OPTION_DHCP4_NTP_SERVER, &data, &n_data);
	if (r)
		return;

	nm_gstring_prepare (&str);

	while (lease_option_next_in_addr (&addr, &data, &n_data)) {
		nm_utils_inet4_ntop (addr.s_addr, addr_str);
		g_string_append (nm_gstring_add_space_delimiter (str), addr_str);
	}

	LOG_LEASE (LOGD_DHCP4, "ntp server '%s'", str->str);
	nm_dhcp_option_add_option (options, _nm_dhcp_option_dhcp4_options, NM_DHCP_OPTION_DHCP4_NTP_SERVER, str->str);
}

static void
lease_parse_hostname (NDhcp4ClientLease *lease,
                      const char *iface,
                      GHashTable *options)
{
	nm_auto_free_gstring GString *str = NULL;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query (lease, NM_DHCP_OPTION_DHCP4_HOST_NAME, &data, &n_data);
	if (r)
		return;

	str = g_string_new_len ((char *)data, n_data);

	if (is_localhost(str->str))
		return;

	LOG_LEASE (LOGD_DHCP4, "hostname '%s'", str->str);
	nm_dhcp_option_add_option (options, _nm_dhcp_option_dhcp4_options, NM_DHCP_OPTION_DHCP4_HOST_NAME, str->str);
}

static void
lease_parse_domainname (NDhcp4ClientLease *lease,
                        const char *iface,
                        NMIP4Config *ip4_config,
                        GHashTable *options)
{
	nm_auto_free_gstring GString *str = NULL;
	gs_strfreev char **domains = NULL;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query (lease, NM_DHCP_OPTION_DHCP4_DOMAIN_NAME, &data, &n_data);
	if (r)
		return;

	str = g_string_new_len ((char *)data, n_data);

	/* Multiple domains sometimes stuffed into option 15 "Domain Name". */
	domains = g_strsplit (str->str, " ", 0);
	nm_gstring_prepare (&str);

	for (char **d = domains; *d; d++) {
		if (is_localhost(*d))
			return;

		g_string_append (nm_gstring_add_space_delimiter (str), *d);
		nm_ip4_config_add_domain (ip4_config, *d);
	}
	LOG_LEASE (LOGD_DHCP4, "domain name '%s'", str->str);
	nm_dhcp_option_add_option (options, _nm_dhcp_option_dhcp4_options, NM_DHCP_OPTION_DHCP4_DOMAIN_NAME, str->str);
}

static void
lease_parse_search_domains (NDhcp4ClientLease *lease,
                            const char *iface,
                            NMIP4Config *ip4_config,
                            GHashTable *options)
{
	nm_auto_free_gstring GString *str = NULL;
	uint8_t *data, *cache;
	size_t n_data, n_cache = 0;
	int r;

	r = n_dhcp4_client_lease_query (lease, NM_DHCP_OPTION_DHCP4_DOMAIN_SEARCH_LIST, &data, &n_data);
	if (r)
		return;

	cache = data;

	nm_gstring_prepare (&str);

	for (;;) {
		nm_auto_free_gstring GString *domain = NULL;

		nm_gstring_prepare (&domain);

		if (!lease_option_print_domain_name (domain, cache, &n_cache, &data, &n_data))
			break;

		g_string_append (nm_gstring_add_space_delimiter (str), domain->str);
		nm_ip4_config_add_search (ip4_config, domain->str);
	}
	LOG_LEASE (LOGD_DHCP4, "domain search '%s'", str->str);
	nm_dhcp_option_add_option (options,
	                           _nm_dhcp_option_dhcp4_options,
	                           NM_DHCP_OPTION_DHCP4_DOMAIN_SEARCH_LIST,
	                           str->str);
}

static void
lease_parse_root_path (NDhcp4ClientLease *lease,
                       const char *iface,
                       GHashTable *options)
{
	nm_auto_free_gstring GString *str = NULL;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query (lease, NM_DHCP_OPTION_DHCP4_ROOT_PATH, &data, &n_data);
	if (r)
		return;

	str = g_string_new_len ((char *)data, n_data);
	LOG_LEASE (LOGD_DHCP4, "root path '%s'", str->str);
	nm_dhcp_option_add_option (options, _nm_dhcp_option_dhcp4_options, NM_DHCP_OPTION_DHCP4_ROOT_PATH, str->str);
}

static void
lease_parse_wpad (NDhcp4ClientLease *lease,
                  const char *iface,
                  GHashTable *options)
{
	nm_auto_free_gstring GString *str = NULL;
	uint8_t *data;
	size_t n_data;
	int r;

	r = n_dhcp4_client_lease_query (lease, NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY, &data, &n_data);
	if (r)
		return;

	str = g_string_new_len ((char *)data, n_data);
	LOG_LEASE (LOGD_DHCP4, "wpad '%s'", str->str);
	nm_dhcp_option_add_option (options,
	                           _nm_dhcp_option_dhcp4_options,
	                           NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY,
	                           str->str);
}

static NMIP4Config *
lease_to_ip4_config (NMDedupMultiIndex *multi_idx,
                     const char *iface,
                     int ifindex,
                     NDhcp4ClientLease *lease,
                     guint32 route_table,
                     guint32 route_metric,
                     GHashTable **out_options,
                     GError **error)
{
	gs_unref_object NMIP4Config *ip4_config = NULL;
	gs_unref_hashtable GHashTable *options = NULL;

	g_return_val_if_fail (lease != NULL, NULL);

	ip4_config = nm_ip4_config_new (multi_idx, ifindex);
	options = out_options ? nm_dhcp_option_create_options_dict () : NULL;

	if (!lease_parse_address (lease, iface, ip4_config, options, error))
		return NULL;

	lease_parse_routes (lease, iface, ip4_config, options, route_table, route_metric);
	lease_parse_domain_name_servers (lease, iface, ip4_config, options);
	lease_parse_domainname (lease, iface, ip4_config, options);
	lease_parse_search_domains (lease, iface, ip4_config, options);
	lease_parse_mtu (lease, iface, ip4_config, options);
	lease_parse_metered (lease, iface, ip4_config, options);

	lease_parse_hostname (lease, iface, options);
	lease_parse_ntps (lease, iface, options);
	lease_parse_root_path (lease, iface, options);
	lease_parse_wpad (lease, iface, options);

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
	                                  &options,
	                                  &error);
	if (!ip4_config) {
		_LOGW ("%s", error->message);
		g_clear_error (&error);
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return;
	}

	nm_dhcp_option_add_requests_to_options (options, _nm_dhcp_option_dhcp4_options);

	nm_dhcp_client_set_state (NM_DHCP_CLIENT (self),
	                          NM_DHCP_STATE_BOUND,
	                          NM_IP_CONFIG_CAST (ip4_config),
	                          options);
}

static gboolean
dhcp4_event_handle (NMDhcpNettools *self,
                    NDhcp4ClientEvent *event)
{
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE (self);
	int r;

	_LOGT ("client event %d", event->event);

	switch (event->event) {
	case N_DHCP4_CLIENT_EVENT_OFFER:
		/* always accept the first lease */
		r = n_dhcp4_client_lease_select (event->offer.lease);
		if (r) {
			_LOGW ("selecting lease failed: %d", r);
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
		priv->lease = n_dhcp4_client_lease_ref (event->granted.lease);
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
dhcp4_event_cb (GIOChannel *source,
                GIOCondition condition,
                gpointer data)
{
	NMDhcpNettools *self = data;
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE (self);
	NDhcp4ClientEvent *event;
	int r;

	r = n_dhcp4_client_dispatch (priv->client);
	if (r < 0)
		return G_SOURCE_CONTINUE;

	while (!n_dhcp4_client_pop_event (priv->client, &event) && event) {
		dhcp4_event_handle (self, event);
	}

	return G_SOURCE_CONTINUE;
}

static gboolean
nettools_create (NMDhcpNettools *self,
                 const char *dhcp_anycast_addr,
                 GError **error)
{
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE (self);
	nm_auto (n_dhcp4_client_config_freep) NDhcp4ClientConfig *config = NULL;
	nm_auto (n_dhcp4_client_unrefp) NDhcp4Client *client = NULL;
	GBytes *hwaddr;
	GBytes *bcast_hwaddr;
	const uint8_t *hwaddr_arr;
	const uint8_t *bcast_hwaddr_arr;
	gsize hwaddr_len;
	gsize bcast_hwaddr_len;
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

	bcast_hwaddr = nm_dhcp_client_get_broadcast_hw_addr (NM_DHCP_CLIENT (self));
	bcast_hwaddr_arr = g_bytes_get_data (bcast_hwaddr, &bcast_hwaddr_len);

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
		nm_utils_error_set_errno (error, r, "failed to create client-config: %s");
		return FALSE;
	}

	n_dhcp4_client_config_set_ifindex (config, nm_dhcp_client_get_ifindex (NM_DHCP_CLIENT (self)));
	n_dhcp4_client_config_set_transport (config, transport);
	n_dhcp4_client_config_set_mac (config, hwaddr_arr, hwaddr_len);
	n_dhcp4_client_config_set_broadcast_mac (config, bcast_hwaddr_arr, bcast_hwaddr_len);
	r = n_dhcp4_client_config_set_client_id (config, client_id_arr, client_id_len);
	if (r) {
		nm_utils_error_set_errno (error, r, "failed to set client-id: %s");
		return FALSE;
	}

	r = n_dhcp4_client_new (&client, config);
	if (r) {
		nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN, "failed to create client: error %d", r);
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
_accept (NMDhcpClient *client,
         GError **error)
{
	NMDhcpNettools *self = NM_DHCP_NETTOOLS (client);
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE (self);
	int r;

	g_return_val_if_fail (priv->lease, FALSE);

	_LOGT ("accept");

	r = n_dhcp4_client_lease_accept (priv->lease);
	if (r) {
		nm_utils_error_set_errno (error, r, "failed to accept lease: %s");
		return FALSE;
	}

	priv->lease = n_dhcp4_client_lease_unref (priv->lease);

	return TRUE;
}

static gboolean
decline (NMDhcpClient *client,
         const char *error_message,
         GError **error)
{
	NMDhcpNettools *self = NM_DHCP_NETTOOLS (client);
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE (self);
	int r;

	g_return_val_if_fail (priv->lease, FALSE);

	_LOGT ("dhcp4-client: decline");

	r = n_dhcp4_client_lease_decline (priv->lease, error_message);
	if (r) {
		nm_utils_error_set_errno (error, r, "failed to decline lease: %s");
		return FALSE;
	}

	priv->lease = n_dhcp4_client_lease_unref (priv->lease);

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

	if (!nettools_create (self, dhcp_anycast_addr, error))
		return FALSE;

	r = n_dhcp4_client_probe_config_new (&config);
	if (r) {
		nm_utils_error_set_errno (error, r, "failed to create dhcp-client-probe-config: %s");
		return FALSE;
	}

	/*
	 * FIXME:
	 * Select, or configure, a reasonable start delay, to protect poor servers beeing flooded.
	 */
	n_dhcp4_client_probe_config_set_start_delay (config, 1);

	if (last_ip4_address) {
		inet_pton (AF_INET, last_ip4_address, &last_addr);
		n_dhcp4_client_probe_config_set_requested_ip (config, last_addr);
	}

	/* Add requested options */
	for (i = 0; _nm_dhcp_option_dhcp4_options[i].name; i++) {
		if (_nm_dhcp_option_dhcp4_options[i].include) {
			nm_assert (_nm_dhcp_option_dhcp4_options[i].option_num <= 255);
			n_dhcp4_client_probe_config_request_option (config,
			                                            _nm_dhcp_option_dhcp4_options[i].option_num);
		}
	}

	hostname = nm_dhcp_client_get_hostname (client);
	if (hostname) {
		if (nm_dhcp_client_get_use_fqdn (client)) {
			uint8_t buffer[3 + DHCP_MAX_FQDN_LENGTH];

			buffer[0] = DHCP_FQDN_FLAG_S | /* Request server to perform A RR DNS updates */
			            DHCP_FQDN_FLAG_E;  /* Canonical wire format */
			buffer[1] = 0;                 /* RCODE1 (deprecated) */
			buffer[2] = 0;                 /* RCODE2 (deprecated) */

			r = nm_sd_dns_name_to_wire_format (hostname,
			                                   buffer + 3,
			                                   sizeof (buffer) - 3,
			                                   FALSE);
			if (r < 0) {
				nm_utils_error_set_errno (error, r, "failed to convert DHCP FQDN: %s");
				return FALSE;
			}

			r = n_dhcp4_client_probe_config_append_option (config,
			                                               NM_DHCP_OPTION_DHCP4_CLIENT_FQDN,
			                                               buffer,
			                                               3 + r);
			if (r) {
				nm_utils_error_set_errno (error, r, "failed to set DHCP FQDN: %s");
				return FALSE;
			}
		} else {
			r = n_dhcp4_client_probe_config_append_option (config,
			                                               NM_DHCP_OPTION_DHCP4_HOST_NAME,
			                                               hostname,
			                                               strlen (hostname));
			if (r) {
				nm_utils_error_set_errno (error, r, "failed to set DHCP hostname: %s");
				return FALSE;
			}
		}
	}

	r = n_dhcp4_client_probe (priv->client, &priv->probe, config);
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
stop (NMDhcpClient *client,
      gboolean release)
{
	NMDhcpNettools *self = NM_DHCP_NETTOOLS (client);
	NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE (self);

	NM_DHCP_CLIENT_CLASS (nm_dhcp_nettools_parent_class)->stop (client, release);

	_LOGT ("dhcp-client4: stop %p",
	       (gpointer) priv->client);

	priv->probe = n_dhcp4_client_probe_free (priv->probe);
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
	client_class->ip6_start = ip6_start;
	client_class->accept = _accept;
	client_class->decline = decline;
	client_class->stop = stop;
}

const NMDhcpClientFactory _nm_dhcp_client_factory_nettools = {
	.name = "nettools",
	.get_type = nm_dhcp_nettools_get_type,
	.get_path = NULL,
};
