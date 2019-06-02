/* nm-lndp-ndisc.c - Router discovery implementation using libndp
 *
 * This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-lndp-ndisc.h"

#include <arpa/inet.h>
#include <netinet/icmp6.h>
/* stdarg.h included because of a bug in ndp.h */
#include <stdarg.h>
#include <ndp.h>

#include "nm-ndisc-private.h"
#include "NetworkManagerUtils.h"
#include "platform/nm-platform.h"
#include "platform/nmp-netns.h"

#define _NMLOG_PREFIX_NAME                "ndisc-lndp"

/*****************************************************************************/

typedef struct {
	struct ndp *ndp;

	GIOChannel *event_channel;
	guint event_id;
} NMLndpNDiscPrivate;

/*****************************************************************************/

struct _NMLndpNDisc {
	NMNDisc parent;
	NMLndpNDiscPrivate _priv;
};

struct _NMLndpNDiscClass {
	NMNDiscClass parent;
};

/*****************************************************************************/

G_DEFINE_TYPE (NMLndpNDisc, nm_lndp_ndisc, NM_TYPE_NDISC)

#define NM_LNDP_NDISC_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMLndpNDisc, NM_IS_LNDP_NDISC)

/*****************************************************************************/

static gboolean
send_rs (NMNDisc *ndisc, GError **error)
{
	NMLndpNDiscPrivate *priv = NM_LNDP_NDISC_GET_PRIVATE ((NMLndpNDisc *) ndisc);
	struct ndp_msg *msg;
	int errsv;

	errsv = ndp_msg_new (&msg, NDP_MSG_RS);
	if (errsv) {
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     "cannot create router solicitation");
		return FALSE;
	}
	ndp_msg_ifindex_set (msg, nm_ndisc_get_ifindex (ndisc));

	errsv = ndp_msg_send (priv->ndp, msg);
	ndp_msg_destroy (msg);
	if (errsv) {
		errsv = nm_errno_native (errsv);
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "%s (%d)",
		             nm_strerror_native (errsv), errsv);
		return FALSE;
	}

	return TRUE;
}

static NMIcmpv6RouterPref
_route_preference_coerce (enum ndp_route_preference pref)
{
	switch (pref) {
	case NDP_ROUTE_PREF_LOW:
		return NM_ICMPV6_ROUTER_PREF_LOW;
	case NDP_ROUTE_PREF_MEDIUM:
		return NM_ICMPV6_ROUTER_PREF_MEDIUM;
	case NDP_ROUTE_PREF_HIGH:
		return NM_ICMPV6_ROUTER_PREF_HIGH;
	}
	/* unexpected value must be treated as MEDIUM (RFC 4191). */
	return NM_ICMPV6_ROUTER_PREF_MEDIUM;
}

static int
receive_ra (struct ndp *ndp, struct ndp_msg *msg, gpointer user_data)
{
	NMNDisc *ndisc = (NMNDisc *) user_data;
	NMNDiscDataInternal *rdata = ndisc->rdata;
	NMNDiscConfigMap changed = 0;
	struct ndp_msgra *msgra = ndp_msgra (msg);
	struct in6_addr gateway_addr;
	gint32 now = nm_utils_get_monotonic_timestamp_s ();
	int offset;
	int hop_limit;

	/* Router discovery is subject to the following RFC documents:
	 *
	 * http://tools.ietf.org/html/rfc4861
	 * http://tools.ietf.org/html/rfc4862
	 *
	 * The biggest difference from good old DHCP is that all configuration
	 * items have their own lifetimes and they are merged from various
	 * sources. Router discovery is *not* contract-based, so there is *no*
	 * single time when the configuration is finished and updates can
	 * come at any time.
	 */
	_LOGD ("received router advertisement at %d", (int) now);

	gateway_addr = *ndp_msg_addrto (msg);
	if (IN6_IS_ADDR_UNSPECIFIED (&gateway_addr))
		g_return_val_if_reached (0);

	/* DHCP level:
	 *
	 * The problem with DHCP level is what to do if subsequent
	 * router advertisements carry different flags. Currently we just
	 * rewrite the flag with every inbound RA.
	 */
	{
		NMNDiscDHCPLevel dhcp_level;

		if (ndp_msgra_flag_managed (msgra))
			dhcp_level = NM_NDISC_DHCP_LEVEL_MANAGED;
		else if (ndp_msgra_flag_other (msgra))
			dhcp_level = NM_NDISC_DHCP_LEVEL_OTHERCONF;
		else
			dhcp_level = NM_NDISC_DHCP_LEVEL_NONE;

		/* when receiving multiple RA (possibly from different routers),
		 * let's keep the "most managed" level. */
		G_STATIC_ASSERT_EXPR (NM_NDISC_DHCP_LEVEL_MANAGED > NM_NDISC_DHCP_LEVEL_OTHERCONF);
		G_STATIC_ASSERT_EXPR (NM_NDISC_DHCP_LEVEL_OTHERCONF > NM_NDISC_DHCP_LEVEL_NONE);
		dhcp_level = MAX (dhcp_level, rdata->public.dhcp_level);

		if (dhcp_level != rdata->public.dhcp_level) {
			rdata->public.dhcp_level = dhcp_level;
			changed |= NM_NDISC_CONFIG_DHCP_LEVEL;
		}
	}

	/* Default gateway:
	 *
	 * Subsequent router advertisements can represent new default gateways
	 * on the network. We should present all of them in router preference
	 * order.
	 */
	{
		const NMNDiscGateway gateway = {
			.address = gateway_addr,
			.timestamp = now,
			.lifetime = ndp_msgra_router_lifetime (msgra),
			.preference = _route_preference_coerce (ndp_msgra_route_preference (msgra)),
		};

		if (nm_ndisc_add_gateway (ndisc, &gateway))
			changed |= NM_NDISC_CONFIG_GATEWAYS;
	}

	/* Addresses & Routes */
	ndp_msg_opt_for_each_offset (offset, msg, NDP_MSG_OPT_PREFIX) {
		guint8 r_plen;
		struct in6_addr r_network;

		/* Device route */

		r_plen = ndp_msg_opt_prefix_len (msg, offset);
		if (r_plen == 0 || r_plen > 128)
			continue;
		nm_utils_ip6_address_clear_host_address (&r_network, ndp_msg_opt_prefix (msg, offset), r_plen);

		if (   IN6_IS_ADDR_UNSPECIFIED (&r_network)
		    || IN6_IS_ADDR_LINKLOCAL (&r_network))
			continue;

		if (ndp_msg_opt_prefix_flag_on_link (msg, offset)) {
			const NMNDiscRoute route = {
				.network = r_network,
				.plen = r_plen,
				.timestamp = now,
				.lifetime = ndp_msg_opt_prefix_valid_time (msg, offset),
			};

			if (nm_ndisc_add_route (ndisc, &route))
				changed |= NM_NDISC_CONFIG_ROUTES;
		}

		/* Address */
		if (   r_plen == 64
		    && ndp_msg_opt_prefix_flag_auto_addr_conf (msg, offset)) {
			NMNDiscAddress address = {
				.address = r_network,
				.timestamp = now,
				.lifetime = ndp_msg_opt_prefix_valid_time (msg, offset),
				.preferred = ndp_msg_opt_prefix_preferred_time (msg, offset),
			};

			if (address.preferred <= address.lifetime) {
				if (nm_ndisc_complete_and_add_address (ndisc, &address, now))
					changed |= NM_NDISC_CONFIG_ADDRESSES;
			}
		}
	}
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_ROUTE) {
		NMNDiscRoute route = {
			.gateway = gateway_addr,
			.plen = ndp_msg_opt_route_prefix_len (msg, offset),
			.timestamp = now,
			.lifetime = ndp_msg_opt_route_lifetime (msg, offset),
			.preference = _route_preference_coerce (ndp_msg_opt_route_preference (msg, offset)),
		};

		if (route.plen == 0 || route.plen > 128)
			continue;

		/* Routers through this particular gateway */
		nm_utils_ip6_address_clear_host_address (&route.network, ndp_msg_opt_route_prefix (msg, offset), route.plen);
		if (nm_ndisc_add_route (ndisc, &route))
			changed |= NM_NDISC_CONFIG_ROUTES;
	}

	/* DNS information */
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_RDNSS) {
		static struct in6_addr *addr;
		int addr_index;

		ndp_msg_opt_rdnss_for_each_addr (addr, addr_index, msg, offset) {
			NMNDiscDNSServer dns_server = {
				.address = *addr,
				.timestamp = now,
				.lifetime = ndp_msg_opt_rdnss_lifetime (msg, offset),
			};

			/* Pad the lifetime somewhat to give a bit of slack in cases
			 * where one RA gets lost or something (which can happen on unreliable
			 * links like Wi-Fi where certain types of frames are not retransmitted).
			 * Note that 0 has special meaning and is therefore not adjusted.
			 */
			if (dns_server.lifetime && dns_server.lifetime < 7200)
				dns_server.lifetime = 7200;
			if (nm_ndisc_add_dns_server (ndisc, &dns_server))
				changed |= NM_NDISC_CONFIG_DNS_SERVERS;
		}
	}
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_DNSSL) {
		char *domain;
		int domain_index;

		ndp_msg_opt_dnssl_for_each_domain (domain, domain_index, msg, offset) {
			NMNDiscDNSDomain dns_domain = {
				.domain = domain,
				.timestamp = now,
				.lifetime = ndp_msg_opt_rdnss_lifetime (msg, offset),
			};

			/* Pad the lifetime somewhat to give a bit of slack in cases
			 * where one RA gets lost or something (which can happen on unreliable
			 * links like Wi-Fi where certain types of frames are not retransmitted).
			 * Note that 0 has special meaning and is therefore not adjusted.
			 */
			if (dns_domain.lifetime && dns_domain.lifetime < 7200)
				dns_domain.lifetime = 7200;
			if (nm_ndisc_add_dns_domain (ndisc, &dns_domain))
				changed |= NM_NDISC_CONFIG_DNS_DOMAINS;
		}
	}

	hop_limit = ndp_msgra_curhoplimit (msgra);
	if (rdata->public.hop_limit != hop_limit) {
		rdata->public.hop_limit = hop_limit;
		changed |= NM_NDISC_CONFIG_HOP_LIMIT;
	}

	/* MTU */
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_MTU) {
		guint32 mtu = ndp_msg_opt_mtu(msg, offset);
		if (mtu >= 1280) {
			if (rdata->public.mtu != mtu) {
				rdata->public.mtu = mtu;
				changed |= NM_NDISC_CONFIG_MTU;
			}
		} else {
			/* All sorts of bad things would happen if we accepted this.
			 * Kernel would set it, but would flush out all IPv6 addresses away
			 * from the link, even the link-local, and we wouldn't be able to
			 * listen for further RAs that could fix the MTU. */
			_LOGW ("MTU too small for IPv6 ignored: %d", mtu);
		}
	}

	nm_ndisc_ra_received (ndisc, now, changed);
	return 0;
}

static void *
_ndp_msg_add_option (struct ndp_msg *msg, int len)
{
	void *ret = (uint8_t *)msg + ndp_msg_payload_len (msg);

	len += ndp_msg_payload_len (msg);
	if (len > ndp_msg_payload_maxlen (msg))
		return NULL;

	ndp_msg_payload_len_set (msg, len);
	return ret;
}

#define NM_ND_OPT_RDNSS 25
typedef struct {
	struct nd_opt_hdr header;
	uint16_t reserved;
	uint32_t lifetime;;
	struct in6_addr addrs[0];
} NMLndpRdnssOption;

#define NM_ND_OPT_DNSSL 31
typedef struct {
	struct nd_opt_hdr header;
	uint16_t reserved;
	uint32_t lifetime;
	char search_list[0];
} NMLndpDnsslOption;

static gboolean
send_ra (NMNDisc *ndisc, GError **error)
{
	NMLndpNDiscPrivate *priv = NM_LNDP_NDISC_GET_PRIVATE ((NMLndpNDisc *) ndisc);
	NMNDiscDataInternal *rdata = ndisc->rdata;
	gint32 now = nm_utils_get_monotonic_timestamp_s ();
	int errsv;
	struct in6_addr *addr;
	struct ndp_msg *msg;
	struct nd_opt_prefix_info *prefix;
	int i;

	errsv = ndp_msg_new (&msg, NDP_MSG_RA);
	if (errsv) {
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     "cannot create a router advertisement");
		return FALSE;
	}

	ndp_msg_ifindex_set (msg, nm_ndisc_get_ifindex (ndisc));

	/* Multicast to all nodes. */
	addr = ndp_msg_addrto (msg);
	addr->s6_addr32[0] = htonl(0xff020000);
	addr->s6_addr32[1] = 0;
	addr->s6_addr32[2] = 0;
	addr->s6_addr32[3] = htonl(0x1);

	ndp_msgra_router_lifetime_set (ndp_msgra (msg), NM_NDISC_ROUTER_LIFETIME);

	/* The device let us know about all addresses that the device got
	 * whose prefixes are suitable for delegating. Let's announce them. */
	for (i = 0; i < rdata->addresses->len; i++) {
		NMNDiscAddress *address = &g_array_index (rdata->addresses, NMNDiscAddress, i);
		guint32 age = NM_CLAMP ((gint64) now - (gint64) address->timestamp, 0, G_MAXUINT32 - 1);
		guint32 lifetime = address->lifetime;
		guint32 preferred = address->preferred;

		/* Clamp the life times if they're not forever. */
		if (lifetime != NM_NDISC_INFINITY)
			lifetime = lifetime > age ? lifetime - age : 0;
		if (preferred != NM_NDISC_INFINITY)
			preferred = preferred > age ? preferred - age : 0;

		prefix = _ndp_msg_add_option (msg, sizeof(*prefix));
		if (!prefix) {
			/* Maybe we could sent separate RAs, but why bother... */
			_LOGW ("The RA is too big, had to omit some some prefixes.");
			break;
		}

		prefix->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		prefix->nd_opt_pi_len = 4;
		prefix->nd_opt_pi_prefix_len = 64;
		prefix->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
		prefix->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
		prefix->nd_opt_pi_valid_time = htonl(lifetime);
		prefix->nd_opt_pi_preferred_time = htonl(preferred);
		prefix->nd_opt_pi_prefix.s6_addr32[0] = address->address.s6_addr32[0];
		prefix->nd_opt_pi_prefix.s6_addr32[1] = address->address.s6_addr32[1];
		prefix->nd_opt_pi_prefix.s6_addr32[2] = 0;
		prefix->nd_opt_pi_prefix.s6_addr32[3] = 0;
	}

	if (rdata->dns_servers->len) {
		NMLndpRdnssOption *option;
		int len = sizeof(*option) + sizeof(option->addrs[0]) * rdata->dns_servers->len;

		option = _ndp_msg_add_option (msg, len);
		if (option) {
			option->header.nd_opt_type = NM_ND_OPT_RDNSS;
			option->header.nd_opt_len = len / 8;
			option->lifetime = htonl (900);

			for (i = 0; i < rdata->dns_servers->len; i++) {
				NMNDiscDNSServer *dns_server = &g_array_index (rdata->dns_servers, NMNDiscDNSServer, i);
				option->addrs[i] = dns_server->address;
			}
		} else {
			_LOGW ("The RA is too big, had to omit DNS information.");
		}

	}

	if (rdata->dns_domains->len) {
		NMLndpDnsslOption *option;
		NMNDiscDNSDomain *dns_server;
		int len = sizeof(*option);
		char *search_list;

		for (i = 0; i < rdata->dns_domains->len; i++) {
			dns_server = &g_array_index (rdata->dns_domains, NMNDiscDNSDomain, i);
			len += strlen (dns_server->domain) + 2;
		}
		len = (len + 8) & ~0x7;

		option = _ndp_msg_add_option (msg, len);
		if (option) {
			option->header.nd_opt_type = NM_ND_OPT_DNSSL;
			option->header.nd_opt_len = len / 8;
			option->lifetime = htonl (900);

			search_list = option->search_list;
			for (i = 0; i < rdata->dns_domains->len; i++) {
				NMNDiscDNSDomain *dns_domain = &g_array_index (rdata->dns_domains, NMNDiscDNSDomain, i);
				uint8_t domain_len = strlen (dns_domain->domain);

				*search_list++ = domain_len;
				memcpy (search_list, dns_domain->domain, domain_len);
				search_list += domain_len;
				*search_list++ = '\0';
			}
		} else {
			_LOGW ("The RA is too big, had to omit DNS search list.");
		}
	}

	errsv = ndp_msg_send (priv->ndp, msg);

	ndp_msg_destroy (msg);
	if (errsv) {
		errsv = nm_errno_native (errsv);
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "%s (%d)",
		             nm_strerror_native (errsv), errsv);
		return FALSE;
	}

	return TRUE;
}

static int
receive_rs (struct ndp *ndp, struct ndp_msg *msg, gpointer user_data)
{
	NMNDisc *ndisc = user_data;

	nm_ndisc_rs_received (ndisc);
	return 0;
}

static gboolean
event_ready (GIOChannel *source, GIOCondition condition, NMNDisc *ndisc)
{
	_nm_unused gs_unref_object NMNDisc *ndisc_keep_alive = g_object_ref (ndisc);
	nm_auto_pop_netns NMPNetns *netns = NULL;
	NMLndpNDiscPrivate *priv = NM_LNDP_NDISC_GET_PRIVATE ((NMLndpNDisc *) ndisc);

	_LOGD ("processing libndp events");

	if (!nm_ndisc_netns_push (ndisc, &netns)) {
		/* something is very wrong. Stop handling events. */
		priv->event_id = 0;
		return G_SOURCE_REMOVE;
	}

	ndp_callall_eventfd_handler (priv->ndp);
	return G_SOURCE_CONTINUE;
}

static void
start (NMNDisc *ndisc)
{
	NMLndpNDiscPrivate *priv = NM_LNDP_NDISC_GET_PRIVATE ((NMLndpNDisc *) ndisc);
	int fd = ndp_get_eventfd (priv->ndp);

	g_return_if_fail (!priv->event_channel);
	g_return_if_fail (!priv->event_id);

	priv->event_channel = g_io_channel_unix_new (fd);
	priv->event_id = g_io_add_watch (priv->event_channel, G_IO_IN, (GIOFunc) event_ready, ndisc);

	/* Flush any pending messages to avoid using obsolete information */
	event_ready (priv->event_channel, 0, ndisc);

	switch (nm_ndisc_get_node_type (ndisc)) {
	case NM_NDISC_NODE_TYPE_HOST:
		ndp_msgrcv_handler_register (priv->ndp, receive_ra, NDP_MSG_RA, nm_ndisc_get_ifindex (ndisc), ndisc);
		break;
	case NM_NDISC_NODE_TYPE_ROUTER:
		ndp_msgrcv_handler_register (priv->ndp, receive_rs, NDP_MSG_RS, nm_ndisc_get_ifindex (ndisc), ndisc);
		break;
	default:
		g_assert_not_reached ();
	}
}

/*****************************************************************************/

static int
ipv6_sysctl_get (NMPlatform *platform, const char *ifname, const char *property, int min, int max, int defval)
{
	return nm_platform_sysctl_ip_conf_get_int_checked (platform,
	                                                   AF_INET6,
	                                                   ifname,
	                                                   property,
	                                                   10,
	                                                   min,
	                                                   max,
	                                                   defval);
}

static void
nm_lndp_ndisc_init (NMLndpNDisc *lndp_ndisc)
{
}

NMNDisc *
nm_lndp_ndisc_new (NMPlatform *platform,
                   int ifindex,
                   const char *ifname,
                   NMUtilsStableType stable_type,
                   const char *network_id,
                   NMSettingIP6ConfigAddrGenMode addr_gen_mode,
                   NMNDiscNodeType node_type,
                   GError **error)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	NMNDisc *ndisc;
	NMLndpNDiscPrivate *priv;
	int errsv;

	g_return_val_if_fail (NM_IS_PLATFORM (platform), NULL);
	g_return_val_if_fail (!error || !*error, NULL);
	g_return_val_if_fail (network_id, NULL);

	if (!nm_platform_netns_push (platform, &netns))
		return NULL;

	ndisc = g_object_new (NM_TYPE_LNDP_NDISC,
	                      NM_NDISC_PLATFORM, platform,
	                      NM_NDISC_STABLE_TYPE, (int) stable_type,
	                      NM_NDISC_IFINDEX, ifindex,
	                      NM_NDISC_IFNAME, ifname,
	                      NM_NDISC_NETWORK_ID, network_id,
	                      NM_NDISC_ADDR_GEN_MODE, (int) addr_gen_mode,
	                      NM_NDISC_NODE_TYPE, (int) node_type,
	                      NM_NDISC_MAX_ADDRESSES, ipv6_sysctl_get (platform, ifname,
	                                                               "max_addresses",
	                                                               0, G_MAXINT32, NM_NDISC_MAX_ADDRESSES_DEFAULT),
	                      NM_NDISC_ROUTER_SOLICITATIONS, ipv6_sysctl_get (platform, ifname,
	                                                                      "router_solicitations",
	                                                                      1, G_MAXINT32, NM_NDISC_ROUTER_SOLICITATIONS_DEFAULT),
	                      NM_NDISC_ROUTER_SOLICITATION_INTERVAL, ipv6_sysctl_get (platform, ifname,
	                                                                              "router_solicitation_interval",
	                                                                              1, G_MAXINT32, NM_NDISC_ROUTER_SOLICITATION_INTERVAL_DEFAULT),
	                      NULL);

	priv = NM_LNDP_NDISC_GET_PRIVATE ((NMLndpNDisc *) ndisc);

	errsv = ndp_open (&priv->ndp);

	if (errsv != 0) {
		errsv = nm_errno_native (errsv);
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "failure creating libndp socket: %s (%d)",
		             nm_strerror_native (errsv), errsv);
		g_object_unref (ndisc);
		return NULL;
	}
	return ndisc;
}

static void
dispose (GObject *object)
{
	NMNDisc *ndisc = (NMNDisc *) object;
	NMLndpNDiscPrivate *priv = NM_LNDP_NDISC_GET_PRIVATE ((NMLndpNDisc *) ndisc);

	nm_clear_g_source (&priv->event_id);
	g_clear_pointer (&priv->event_channel, g_io_channel_unref);

	if (priv->ndp) {
		switch (nm_ndisc_get_node_type (ndisc)) {
		case NM_NDISC_NODE_TYPE_HOST:
			ndp_msgrcv_handler_unregister (priv->ndp, receive_ra, NDP_MSG_RA, nm_ndisc_get_ifindex (ndisc), ndisc);
			break;
		case NM_NDISC_NODE_TYPE_ROUTER:
			ndp_msgrcv_handler_unregister (priv->ndp, receive_rs, NDP_MSG_RS, nm_ndisc_get_ifindex (ndisc), ndisc);
			break;
		default:
			g_assert_not_reached ();
		}
		ndp_close (priv->ndp);
		priv->ndp = NULL;
	}

	G_OBJECT_CLASS (nm_lndp_ndisc_parent_class)->dispose (object);
}

static void
nm_lndp_ndisc_class_init (NMLndpNDiscClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMNDiscClass *ndisc_class = NM_NDISC_CLASS (klass);

	object_class->dispose = dispose;
	ndisc_class->start = start;
	ndisc_class->send_rs = send_rs;
	ndisc_class->send_ra = send_ra;
}
