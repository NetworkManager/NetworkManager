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

#include "config.h"

#include <string.h>
#include <arpa/inet.h>
/* stdarg.h included because of a bug in ndp.h */
#include <stdarg.h>
#include <ndp.h>

#include "nm-lndp-rdisc.h"
#include "nm-rdisc-private.h"

#include "NetworkManagerUtils.h"
#include "nm-logging.h"
#include "nm-platform.h"

#define debug(...) nm_log_dbg (LOGD_IP6, __VA_ARGS__)
#define warning(...) nm_log_warn (LOGD_IP6, __VA_ARGS__)
#define error(...) nm_log_err (LOGD_IP6, __VA_ARGS__)

typedef struct {
	struct ndp *ndp;

	GIOChannel *event_channel;
	guint event_id;
	guint ra_timeout_id;  /* first RA timeout */
} NMLNDPRDiscPrivate;

#define NM_LNDP_RDISC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_LNDP_RDISC, NMLNDPRDiscPrivate))

G_DEFINE_TYPE (NMLNDPRDisc, nm_lndp_rdisc, NM_TYPE_RDISC)

/******************************************************************/

static gboolean
send_rs (NMRDisc *rdisc)
{
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);
	struct ndp_msg *msg;
	int error;

	error = ndp_msg_new (&msg, NDP_MSG_RS);
	g_assert (!error);
	ndp_msg_ifindex_set (msg, rdisc->ifindex);

	error = ndp_msg_send (priv->ndp, msg);
	ndp_msg_destroy (msg);
	if (error) {
		error ("(%s): cannot send router solicitation: %d.", rdisc->ifname, error);
		return FALSE;
	}

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

static int
receive_ra (struct ndp *ndp, struct ndp_msg *msg, gpointer user_data)
{
	NMRDisc *rdisc = (NMRDisc *) user_data;
	NMRDiscConfigMap changed = 0;
	struct ndp_msgra *msgra = ndp_msgra (msg);
	NMRDiscGateway gateway;
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
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
	debug ("(%s): received router advertisement at %u", rdisc->ifname, now);

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
	if (nm_rdisc_add_gateway (rdisc, &gateway))
		changed |= NM_RDISC_CONFIG_GATEWAYS;

	/* Addresses & Routes */
	ndp_msg_opt_for_each_offset (offset, msg, NDP_MSG_OPT_PREFIX) {
		NMRDiscRoute route;
		NMRDiscAddress address;

		/* Device route */
		memset (&route, 0, sizeof (route));
		route.plen = ndp_msg_opt_prefix_len (msg, offset);
		nm_utils_ip6_address_clear_host_address (&route.network, ndp_msg_opt_prefix (msg, offset), route.plen);
		route.timestamp = now;
		if (ndp_msg_opt_prefix_flag_on_link (msg, offset)) {
			route.lifetime = ndp_msg_opt_prefix_valid_time (msg, offset);
			if (nm_rdisc_add_route (rdisc, &route))
				changed |= NM_RDISC_CONFIG_ROUTES;
		}

		/* Address */
		if (ndp_msg_opt_prefix_flag_auto_addr_conf (msg, offset)) {
			if (route.plen == 64 && rdisc->iid.id) {
				memset (&address, 0, sizeof (address));
				address.address = route.network;
				address.timestamp = now;
				address.lifetime = ndp_msg_opt_prefix_valid_time (msg, offset);
				address.preferred = ndp_msg_opt_prefix_preferred_time (msg, offset);
				if (address.preferred > address.lifetime)
					address.preferred = address.lifetime;

				/* Add the Interface Identifier to the lower 64 bits */
				nm_utils_ipv6_addr_set_interface_identfier (&address.address, rdisc->iid);

				if (nm_rdisc_add_address (rdisc, &address))
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
		nm_utils_ip6_address_clear_host_address (&route.network, ndp_msg_opt_route_prefix (msg, offset), route.plen);
		route.timestamp = now;
		route.lifetime = ndp_msg_opt_route_lifetime (msg, offset);
		route.preference = translate_preference (ndp_msg_opt_route_preference (msg, offset));
		if (nm_rdisc_add_route (rdisc, &route))
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
			if (nm_rdisc_add_dns_server (rdisc, &dns_server))
				changed |= NM_RDISC_CONFIG_DNS_SERVERS;
		}
	}
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_DNSSL) {
		char *domain;
		int domain_index;

		ndp_msg_opt_dnssl_for_each_domain (domain, domain_index, msg, offset) {
			NMRDiscDNSDomain dns_domain;

			memset (&dns_domain, 0, sizeof (dns_domain));
			dns_domain.domain = domain;
			dns_domain.timestamp = now;
			dns_domain.lifetime = ndp_msg_opt_rdnss_lifetime (msg, offset);
			/* Pad the lifetime somewhat to give a bit of slack in cases
			 * where one RA gets lost or something (which can happen on unreliable
			 * links like WiFi where certain types of frames are not retransmitted).
			 * Note that 0 has special meaning and is therefore not adjusted.
			 */
			if (dns_domain.lifetime && dns_domain.lifetime < 7200)
				dns_domain.lifetime = 7200;
			if (nm_rdisc_add_dns_domain (rdisc, &dns_domain))
				changed |= NM_RDISC_CONFIG_DNS_DOMAINS;
		}
	}

	hop_limit = ndp_msgra_curhoplimit (msgra);
	if (rdisc->hop_limit != hop_limit) {
		rdisc->hop_limit = hop_limit;
		changed |= NM_RDISC_CONFIG_HOP_LIMIT;
	}

	/* MTU */
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_MTU) {
		guint32 mtu = ndp_msg_opt_mtu(msg, offset);
		if (mtu >= 1280) {
			rdisc->mtu = mtu;
			changed |= NM_RDISC_CONFIG_MTU;
		} else {
			/* All sorts of bad things would happen if we accepted this.
			 * Kernel would set it, but would flush out all IPv6 addresses away
			 * from the link, even the link-local, and we wouldn't be able to
			 * listen for further RAs that could fix the MTU. */
			warning ("(%s): MTU too small for IPv6 ignored: %d", rdisc->ifname, mtu);
		}
	}

	nm_rdisc_ra_received (rdisc, now, changed);
	return 0;
}

static gboolean
event_ready (GIOChannel *source, GIOCondition condition, NMRDisc *rdisc)
{
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);

	debug ("(%s): processing libndp events.", rdisc->ifname);
	ndp_callall_eventfd_handler (priv->ndp);
	return G_SOURCE_CONTINUE;
}

static void
start (NMRDisc *rdisc)
{
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);
	int fd = ndp_get_eventfd (priv->ndp);

	priv->event_channel = g_io_channel_unix_new (fd);
	priv->event_id = g_io_add_watch (priv->event_channel, G_IO_IN, (GIOFunc) event_ready, rdisc);

	/* Flush any pending messages to avoid using obsolete information */
	event_ready (priv->event_channel, 0, rdisc);

	ndp_msgrcv_handler_register (priv->ndp, receive_ra, NDP_MSG_RA, rdisc->ifindex, rdisc);
}

/******************************************************************/

static inline gint32
ipv6_sysctl_get (const char *ifname, const char *property, gint32 defval)
{
	return nm_platform_sysctl_get_int32 (NM_PLATFORM_GET, nm_utils_ip6_property_path (ifname, property), defval);
}

NMRDisc *
nm_lndp_rdisc_new (int ifindex, const char *ifname)
{
	NMRDisc *rdisc;
	NMLNDPRDiscPrivate *priv;
	int error;

	rdisc = g_object_new (NM_TYPE_LNDP_RDISC, NULL);

	rdisc->ifindex = ifindex;
	rdisc->ifname = g_strdup (ifname);

	rdisc->max_addresses = ipv6_sysctl_get (ifname, "max_addresses",
	                                        NM_RDISC_MAX_ADDRESSES_DEFAULT);
	rdisc->rtr_solicitations = ipv6_sysctl_get (ifname, "router_solicitations",
	                                            NM_RDISC_RTR_SOLICITATIONS_DEFAULT);
	rdisc->rtr_solicitation_interval = ipv6_sysctl_get (ifname, "router_solicitation_interval",
	                                                    NM_RDISC_RTR_SOLICITATION_INTERVAL_DEFAULT);

	priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);
	error = ndp_open (&priv->ndp);
	if (error != 0) {
		g_object_unref (rdisc);
		debug ("(%s): error creating socket for NDP; errno=%d", ifname, -error);
		return NULL;
	}
	return rdisc;
}

static void
nm_lndp_rdisc_init (NMLNDPRDisc *lndp_rdisc)
{
}

static void
dispose (GObject *object)
{
	NMLNDPRDisc *rdisc = NM_LNDP_RDISC (object);
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);

	if (priv->event_id) {
		g_source_remove (priv->event_id);
		priv->event_id = 0;
	}
	g_clear_pointer (&priv->event_channel, g_io_channel_unref);

	if (priv->ndp) {
		ndp_msgrcv_handler_unregister (priv->ndp, receive_ra, NDP_MSG_RA, NM_RDISC (rdisc)->ifindex, rdisc);
		ndp_close (priv->ndp);
		priv->ndp = NULL;
	}

	G_OBJECT_CLASS (nm_lndp_rdisc_parent_class)->dispose (object);
}

static void
nm_lndp_rdisc_class_init (NMLNDPRDiscClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMRDiscClass *rdisc_class = NM_RDISC_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMLNDPRDiscPrivate));

	object_class->dispose = dispose;
	rdisc_class->start = start;
	rdisc_class->send_rs = send_rs;
}
