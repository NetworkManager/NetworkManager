/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-lndp-rdisc.c - Router discovery implementation using libndp
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

#include <string.h>
#include <arpa/inet.h>
/* stdarg.h included because of a bug in ndp.h */
#include <stdarg.h>
#include <ndp.h>

#include "nm-lndp-rdisc.h"

#include "nm-logging.h"

#define debug(...) nm_log_dbg (LOGD_IP6, __VA_ARGS__)
#define warning(...) nm_log_warn (LOGD_IP6, __VA_ARGS__)
#define error(...) nm_log_err (LOGD_IP6, __VA_ARGS__)

typedef struct {
	struct ndp *ndp;

	guint send_rs_id;
	GIOChannel *event_channel;
	guint event_id;
	guint timeout_id;
} NMLNDPRDiscPrivate;

#define NM_LNDP_RDISC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_LNDP_RDISC, NMLNDPRDiscPrivate))

G_DEFINE_TYPE (NMLNDPRDisc, nm_lndp_rdisc, NM_TYPE_RDISC)

/******************************************************************/

NMRDisc *
nm_lndp_rdisc_new (int ifindex, const char *ifname)
{
	NMRDisc *rdisc;
	NMLNDPRDiscPrivate *priv;
	int error;

	rdisc = g_object_new (NM_TYPE_LNDP_RDISC, NULL);
	g_assert (rdisc);

	rdisc->ifindex = ifindex;
	rdisc->ifname = g_strdup (ifname);

	priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);
	error = ndp_open (&priv->ndp);
	if (error != 0) {
		g_object_unref (rdisc);
		debug ("(%s): error creating socket for NDP; errno=%d", ifname, -error);
		return NULL;
	}
	return rdisc;
}

static gboolean
add_gateway (NMRDisc *rdisc, const NMRDiscGateway *new)
{
	int i;

	for (i = 0; i < rdisc->gateways->len; i++) {
		NMRDiscGateway *item = &g_array_index (rdisc->gateways, NMRDiscGateway, i);

		if (IN6_ARE_ADDR_EQUAL (&item->address, &new->address)) {
			if (item->preference != new->preference) {
				g_array_remove_index (rdisc->gateways, i--);
				continue;
			}
			memcpy (item, new, sizeof (*new));
			return FALSE;
		}

		/* Put before less preferable gateways. */
		if (item->preference < new->preference)
			break;
	}

	g_array_insert_val (rdisc->gateways, i, *new);
	return TRUE;
}

static gboolean
add_address (NMRDisc *rdisc, const NMRDiscAddress *new)
{
	int i;

	for (i = 0; i < rdisc->addresses->len; i++) {
		NMRDiscAddress *item = &g_array_index (rdisc->addresses, NMRDiscAddress, i);

		if (IN6_ARE_ADDR_EQUAL (&item->address, &new->address)) {
			gboolean changed = item->timestamp + item->lifetime  != new->timestamp + new->lifetime ||
			                   item->timestamp + item->preferred != new->timestamp + new->preferred;

			*item = *new;
			return changed;
		}
	}

	g_array_insert_val (rdisc->addresses, i, *new);
	return TRUE;
}

static gboolean
add_route (NMRDisc *rdisc, const NMRDiscRoute *new)
{
	int i;

	for (i = 0; i < rdisc->routes->len; i++) {
		NMRDiscRoute *item = &g_array_index (rdisc->routes, NMRDiscRoute, i);

		if (IN6_ARE_ADDR_EQUAL (&item->network, &new->network) && item->plen == new->plen) {
			if (item->preference != new->preference) {
				g_array_remove_index (rdisc->routes, i--);
				continue;
			}
			memcpy (item, new, sizeof (*new));
			return FALSE;
		}

		/* Put before less preferable routes. */
		if (item->preference < new->preference)
			break;
	}

	g_array_insert_val (rdisc->routes, i, *new);
	return TRUE;
}

static gboolean
add_server (NMRDisc *rdisc, const NMRDiscDNSServer *new)
{
	int i;

	for (i = 0; i < rdisc->dns_servers->len; i++) {
		NMRDiscDNSServer *item = &g_array_index (rdisc->dns_servers, NMRDiscDNSServer, i);

		if (IN6_ARE_ADDR_EQUAL (&item->address, &new->address))
			return FALSE;
	}

	g_array_insert_val (rdisc->dns_servers, i, *new);

	return TRUE;
}

static gboolean
add_domain (NMRDisc *rdisc, const NMRDiscDNSDomain *new)
{
	int i;

	for (i = 0; i < rdisc->dns_domains->len; i++) {
		NMRDiscDNSDomain *item = &g_array_index (rdisc->dns_domains, NMRDiscDNSDomain, i);

		if (!g_strcmp0 (item->domain, new->domain))
			return FALSE;
	}

	g_array_insert_val (rdisc->dns_domains, i, *new);

	return TRUE;
}

#define RETRY 10

static gboolean
send_rs (NMRDisc *rdisc)
{
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);
	struct ndp_msg *msg;
	int error;

	error = ndp_msg_new (&msg, NDP_MSG_RS);
	g_assert (!error);
	ndp_msg_ifindex_set (msg, rdisc->ifindex);

	debug ("(%s): sending router solicitation: %d", rdisc->ifname, rdisc->ifindex);

	error = ndp_msg_send (priv->ndp, msg);
	if (error)
		error ("(%s): cannot send router solicitation: %d.", rdisc->ifname, error);

	ndp_msg_destroy (msg);

	debug ("(%s): scheduling router solicitation retry in %d seconds.", rdisc->ifname, RETRY);
	priv->send_rs_id = g_timeout_add_seconds (RETRY, (GSourceFunc) send_rs, rdisc);

	return FALSE;
}

static void
solicit (NMRDisc *rdisc)
{
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);

	if (!priv->send_rs_id) {
		debug ("(%s): scheduling router solicitation.", rdisc->ifname);
		priv->send_rs_id = g_idle_add ((GSourceFunc) send_rs, rdisc);
	}
}

static void
clean_gateways (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap *changed, guint32 *nextevent)
{
	int i;

	for (i = 0; i < rdisc->gateways->len; i++) {
		NMRDiscGateway *item = &g_array_index (rdisc->gateways, NMRDiscGateway, i);
		guint32 expiry = item->timestamp + item->lifetime;

		if (item->lifetime == UINT_MAX)
			continue;

		if (now >= expiry) {
			g_array_remove_index (rdisc->gateways, i--);
			*changed |= NM_RDISC_CONFIG_GATEWAYS;
		} else if (*nextevent > expiry)
			*nextevent = expiry;
	}
}

static void
clean_addresses (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap *changed, guint32 *nextevent)
{
	int i;

	for (i = 0; i < rdisc->addresses->len; i++) {
		NMRDiscAddress *item = &g_array_index (rdisc->addresses, NMRDiscAddress, i);
		guint32 expiry = item->timestamp + item->lifetime;

		if (item->lifetime == UINT_MAX)
			continue;

		if (now >= expiry) {
			g_array_remove_index (rdisc->addresses, i--);
			*changed |= NM_RDISC_CONFIG_ADDRESSES;
		} else if (*nextevent > expiry)
			*nextevent = expiry;
	}
}

static void
clean_routes (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap *changed, guint32 *nextevent)
{
	int i;

	for (i = 0; i < rdisc->routes->len; i++) {
		NMRDiscRoute *item = &g_array_index (rdisc->routes, NMRDiscRoute, i);
		guint32 expiry = item->timestamp + item->lifetime;

		if (item->lifetime == UINT_MAX)
			continue;

		if (now >= expiry) {
			g_array_remove_index (rdisc->routes, i--);
			*changed |= NM_RDISC_CONFIG_ROUTES;
		} else if (*nextevent > expiry)
			*nextevent = expiry;
	}
}

static void
clean_servers (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap *changed, guint32 *nextevent)
{
	int i;

	for (i = 0; i < rdisc->dns_servers->len; i++) {
		NMRDiscDNSServer *item = &g_array_index (rdisc->dns_servers, NMRDiscDNSServer, i);
		guint32 expiry = item->timestamp + item->lifetime;
		guint32 refresh = item->timestamp + item->lifetime / 2;

		if (item->lifetime == UINT_MAX)
			continue;

		if (now >= expiry) {
			g_array_remove_index (rdisc->dns_servers, i--);
			*changed |= NM_RDISC_CONFIG_ROUTES;
		} else if (now >= refresh)
			solicit (rdisc);
		else if (*nextevent > refresh)
			*nextevent = refresh;
	}
}

static void
clean_domains (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap *changed, guint32 *nextevent)
{
	int i;

	for (i = 0; i < rdisc->dns_domains->len; i++) {
		NMRDiscDNSDomain *item = &g_array_index (rdisc->dns_domains, NMRDiscDNSDomain, i);
		guint32 expiry = item->timestamp + item->lifetime;
		guint32 refresh = item->timestamp + item->lifetime / 2;

		if (item->lifetime == UINT_MAX)
			continue;

		if (now >= expiry) {
			g_array_remove_index (rdisc->dns_domains, i--);
			*changed |= NM_RDISC_CONFIG_ROUTES;
		} else if (now >= refresh)
			solicit (rdisc);
		else if (*nextevent >=refresh)
			*nextevent = refresh;
	}
}

static gboolean timeout_cb (gpointer user_data);

static void
check_timestamps (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap changed)
{
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);
	/* Use a magic date in distant enough future as there's no guint32 max macro. */
	guint32 never = G_MAXINT32;
	guint32 nextevent = never;

	if (priv->timeout_id) {
		g_source_remove (priv->timeout_id);
		priv->timeout_id = 0;
	}

	clean_gateways (rdisc, now, &changed, &nextevent);
	clean_addresses (rdisc, now, &changed, &nextevent);
	clean_routes (rdisc, now, &changed, &nextevent);
	clean_servers (rdisc, now, &changed, &nextevent);
	clean_domains (rdisc, now, &changed, &nextevent);

	if (changed)
		g_signal_emit_by_name (rdisc, NM_RDISC_CONFIG_CHANGED, changed);

	if (nextevent != never) {
		debug ("Scheduling next now/lifetime check: %d seconds", (int) nextevent);
		priv->timeout_id = g_timeout_add_seconds (nextevent, timeout_cb, rdisc);
	}
}

static guint32
get_time (void)
{
	struct timespec tp;

	clock_gettime (CLOCK_MONOTONIC, &tp);

	return tp.tv_sec;
}

static gboolean
timeout_cb (gpointer user_data)
{
	check_timestamps (user_data, get_time (), 0);

	return TRUE;
}

static NMRDiscPreference
translate_preference (enum ndp_route_preference preference)
{
	switch (preference) {
	case NDP_ROUTE_PREF_LOW:
		return NM_RDISC_PREFERENCE_LOW;
	case NDP_ROUTE_PREF_MEDIUM:
		return NM_RDISC_PREFERENCE_MEDIUM;
	case NDP_ROUTE_PREF_HIGH:
		return NM_RDISC_PREFERENCE_HIGH;
	default:
		return NM_RDISC_PREFERENCE_INVALID;
	}
}

static void
fill_address_from_mac (struct in6_addr *address, const char *mac)
{
	unsigned char *identifier = address->s6_addr + 8;

	if (!mac)
		return;

	/* Translate 48-bit MAC address to a 64-bit modified interface identifier
	 * and write it to the second half of the IPv6 address.
	 *
	 * See http://tools.ietf.org/html/rfc3513#page-21
	 */
	memcpy (identifier, mac, 3);
	identifier[0] ^= 0x02;
	identifier[3] = 0xff;
	identifier[4] = 0xfe;
	memcpy (identifier + 5, mac + 3, 3);
}

/* Ensure the given address is masked with its prefix and that all host
 * bits are set to zero.  Some IPv6 router advertisement daemons (eg, radvd)
 * don't enforce this in their configuration.
 */
static void
set_address_masked (struct in6_addr *dst, struct in6_addr *src, guint8 plen)
{
	guint nbytes = plen / 8;
	guint nbits = plen % 8;

	g_return_if_fail (plen <= 128);
	g_assert (src);
	g_assert (dst);

	if (plen >= 128)
		*dst = *src;
	else {
		memset (dst, 0, sizeof (*dst));
		memcpy (dst, src, nbytes);
		dst->s6_addr[nbytes] = (src->s6_addr[nbytes] & (0xFF << (8 - nbits)));
	}
}

static int
receive_ra (struct ndp *ndp, struct ndp_msg *msg, gpointer user_data)
{
	NMRDisc *rdisc = (NMRDisc *) user_data;
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);
	NMRDiscConfigMap changed = 0;
	size_t lladdrlen = 0;
	const char *lladdr = NULL;
	struct ndp_msgra *msgra = ndp_msgra (msg);
	NMRDiscGateway gateway;
	guint32 now = get_time ();
	int offset;

	if (rdisc->lladdr)
		lladdr = g_bytes_get_data (rdisc->lladdr, &lladdrlen);

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
	debug ("Received router advertisement: %d at %d", rdisc->ifindex, (int) now);

	if (priv->send_rs_id) {
		g_source_remove (priv->send_rs_id);
		priv->send_rs_id = 0;
	}

	/* DHCP level:
	 *
	 * The problem with DHCP level is what to do if subsequent
	 * router advertisements carry different flags. Currently we just
	 * rewrite the flag with every inbound RA.
	 */
	{
		NMRDiscDHCPLevel dhcp_level;

		if (ndp_msgra_flag_managed (msgra))
			dhcp_level = NM_RDISC_DHCP_LEVEL_MANAGED;
		else if (ndp_msgra_flag_other (msgra))
			dhcp_level = NM_RDISC_DHCP_LEVEL_OTHERCONF;
		else
			dhcp_level = NM_RDISC_DHCP_LEVEL_NONE;

		if (dhcp_level != rdisc->dhcp_level) {
			rdisc->dhcp_level = dhcp_level;
			changed |= NM_RDISC_CONFIG_DHCP_LEVEL;
		}
	}

	/* Default gateway:
	 *
	 * Subsequent router advertisements can represent new default gateways
	 * on the network. We should present all of them in router preference
	 * order.
	 */
	memset (&gateway, 0, sizeof (gateway));
	gateway.address = *ndp_msg_addrto (msg);
	gateway.timestamp = now;
	gateway.lifetime = ndp_msgra_router_lifetime (msgra);
	gateway.preference = translate_preference (ndp_msgra_route_preference (msgra));
	if (add_gateway (rdisc, &gateway))
		changed |= NM_RDISC_CONFIG_GATEWAYS;

	/* Addresses & Routes */
	ndp_msg_opt_for_each_offset (offset, msg, NDP_MSG_OPT_PREFIX) {
		NMRDiscRoute route;
		NMRDiscAddress address;

		/* Device route */
		memset (&route, 0, sizeof (route));
		route.plen = ndp_msg_opt_prefix_len (msg, offset);
		set_address_masked (&route.network, ndp_msg_opt_prefix (msg, offset), route.plen);
		route.timestamp = now;
		if (ndp_msg_opt_prefix_flag_on_link (msg, offset)) {
			route.lifetime = ndp_msg_opt_prefix_valid_time (msg, offset);
			if (add_route (rdisc, &route))
				changed |= NM_RDISC_CONFIG_ROUTES;
		}

		/* Address */
		if (ndp_msg_opt_prefix_flag_auto_addr_conf (msg, offset)) {
			if (route.plen == 64 && lladdrlen == 6) {
				memset (&address, 0, sizeof (address));
				address.address = route.network;
				address.timestamp = now;
				address.lifetime = ndp_msg_opt_prefix_valid_time (msg, offset);
				address.preferred = ndp_msg_opt_prefix_preferred_time (msg, offset);

				fill_address_from_mac (&address.address, lladdr);

				if (add_address (rdisc, &address))
					changed |= NM_RDISC_CONFIG_ADDRESSES;
			}
		}
	}
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_ROUTE) {
		NMRDiscRoute route;

		/* Routers through this particular gateway */
		memset (&route, 0, sizeof (route));
		route.gateway = gateway.address;
		route.plen = ndp_msg_opt_route_prefix_len (msg, offset);
		set_address_masked (&route.network, ndp_msg_opt_route_prefix (msg, offset), route.plen);
		route.timestamp = now;
		route.lifetime = ndp_msg_opt_route_lifetime (msg, offset);
		route.preference = translate_preference (ndp_msg_opt_route_preference (msg, offset));
		if (add_route (rdisc, &route))
			changed |= NM_RDISC_CONFIG_ROUTES;
	}

	/* DNS information */
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_RDNSS) {
		static struct in6_addr *addr;
		int addr_index;

		ndp_msg_opt_rdnss_for_each_addr (addr, addr_index, msg, offset) {
			NMRDiscDNSServer dns_server;

			memset (&dns_server, 0, sizeof (dns_server));
			dns_server.address = *addr;
			dns_server.timestamp = now;
			dns_server.lifetime = ndp_msg_opt_rdnss_lifetime (msg, offset);
			/* Pad the lifetime somewhat to give a bit of slack in cases
			 * where one RA gets lost or something (which can happen on unreliable
			 * links like WiFi where certain types of frames are not retransmitted).
			 * Note that 0 has special meaning and is therefore not adjusted.
			 */
			if (dns_server.lifetime && dns_server.lifetime < 7200)
				dns_server.lifetime = 7200;
			if (add_server (rdisc, &dns_server))
				changed |= NM_RDISC_CONFIG_DNS_SERVERS;
		}
	}
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_DNSSL) {
		char *domain;
		int domain_index;

		ndp_msg_opt_dnssl_for_each_domain (domain, domain_index, msg, offset) {
			NMRDiscDNSDomain dns_domain;

			memset (&dns_domain, 0, sizeof (dns_domain));
			dns_domain.domain = g_strdup (domain);
			dns_domain.timestamp = now;
			dns_domain.lifetime = ndp_msg_opt_rdnss_lifetime (msg, offset);
			/* Pad the lifetime somewhat to give a bit of slack in cases
			 * where one RA gets lost or something (which can happen on unreliable
			 * links like WiFi where certain types of frames are not retransmitted).
			 * Note that 0 has special meaning and is therefore not adjusted.
			 */
			if (dns_domain.lifetime && dns_domain.lifetime < 7200)
				dns_domain.lifetime = 7200;
			if (add_domain (rdisc, &dns_domain))
				changed |= NM_RDISC_CONFIG_DNS_DOMAINS;
		}
	}

	check_timestamps (rdisc, now, changed);

	return 0;
}

static void
process_events (NMRDisc *rdisc)
{
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);

	debug ("(%s): processing libndp events.", rdisc->ifname);
	ndp_callall_eventfd_handler (priv->ndp);
}

static gboolean
event_ready (GIOChannel *source, GIOCondition condition, NMRDisc *rdisc)
{
	process_events (rdisc);

	return TRUE;
}

static void
start (NMRDisc *rdisc)
{
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);
	int fd = ndp_get_eventfd (priv->ndp);

	priv->event_channel = g_io_channel_unix_new (fd);
	priv->event_id = g_io_add_watch (priv->event_channel, G_IO_IN, (GIOFunc) event_ready, rdisc);

	/* Flush any pending messages to avoid using obsolete information */
	process_events (rdisc);

	ndp_msgrcv_handler_register (priv->ndp, &receive_ra, NDP_MSG_RA, rdisc->ifindex, rdisc);
	solicit (rdisc);
}

/******************************************************************/

static void
nm_lndp_rdisc_init (NMLNDPRDisc *lndp_rdisc)
{
}

static void
nm_lndp_rdisc_finalize (GObject *object)
{
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (object);

	if (priv->send_rs_id)
		g_source_remove (priv->send_rs_id);
	if (priv->timeout_id)
		g_source_remove (priv->timeout_id);
	if (priv->event_channel)
		g_io_channel_unref (priv->event_channel);
	if (priv->event_id)
		g_source_remove (priv->event_id);

	if (priv->ndp)
		ndp_close (priv->ndp);
}

static void
nm_lndp_rdisc_class_init (NMLNDPRDiscClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMRDiscClass *rdisc_class = NM_RDISC_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMLNDPRDiscPrivate));

	object_class->finalize = nm_lndp_rdisc_finalize;
	rdisc_class->start = start;
}
