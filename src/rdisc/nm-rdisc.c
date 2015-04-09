/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-rdisc.c - Perform IPv6 router discovery
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

#include <stdlib.h>
#include <arpa/inet.h>

#include "nm-rdisc.h"

#include "nm-logging.h"
#include "nm-utils.h"

#define debug(...) nm_log_dbg (LOGD_IP6, __VA_ARGS__)

G_DEFINE_TYPE (NMRDisc, nm_rdisc, G_TYPE_OBJECT)

enum {
	CONFIG_CHANGED,
	RA_TIMEOUT,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/******************************************************************/

/**
 * nm_rdisc_set_iid:
 * @rdisc: the #NMRDisc
 * @iid: the new interface ID
 *
 * Sets the "Modified EUI-64" interface ID to be used when generating
 * IPv6 addresses using received prefixes. Identifiers are either generated
 * from the hardware addresses or manually set by the operator with
 * "ip token" command.
 *
 * Upon token change (or initial setting) all addresses generated using
 * the old identifier are removed. The caller should ensure the addresses
 * will be reset by soliciting router advertisements.
 *
 * Returns: %TRUE if the token was changed, %FALSE otherwise.
 **/
gboolean
nm_rdisc_set_iid (NMRDisc *rdisc, const NMUtilsIPv6IfaceId iid)
{
	g_return_val_if_fail (NM_IS_RDISC (rdisc), FALSE);

	if (rdisc->iid.id != iid.id) {
		rdisc->iid = iid;
		if (rdisc->addresses->len) {
			debug ("(%s) IPv6 interface identifier changed, flushing addresses", rdisc->ifname);
			g_array_remove_range (rdisc->addresses, 0, rdisc->addresses->len);
			g_signal_emit_by_name (rdisc, NM_RDISC_CONFIG_CHANGED, NM_RDISC_CONFIG_ADDRESSES);
		}
		return TRUE;
	}

	return FALSE;
}

void
nm_rdisc_start (NMRDisc *rdisc)
{
	NMRDiscClass *klass = NM_RDISC_GET_CLASS (rdisc);

	g_assert (klass->start);

	debug ("(%s): starting router discovery: %d", rdisc->ifname, rdisc->ifindex);

	if (klass->start)
		klass->start (rdisc);
}

#define CONFIG_MAP_MAX_STR 7

static void
config_map_to_string (NMRDiscConfigMap map, char *p)
{
	if (map & NM_RDISC_CONFIG_DHCP_LEVEL)
		*p++ = 'd';
	if (map & NM_RDISC_CONFIG_GATEWAYS)
		*p++ = 'G';
	if (map & NM_RDISC_CONFIG_ADDRESSES)
		*p++ = 'A';
	if (map & NM_RDISC_CONFIG_ROUTES)
		*p++ = 'R';
	if (map & NM_RDISC_CONFIG_DNS_SERVERS)
		*p++ = 'S';
	if (map & NM_RDISC_CONFIG_DNS_DOMAINS)
		*p++ = 'D';
	*p = '\0';
}

static const char *
dhcp_level_to_string (NMRDiscDHCPLevel dhcp_level)
{
	switch (dhcp_level) {
	case NM_RDISC_DHCP_LEVEL_NONE:
		return "none";
	case NM_RDISC_DHCP_LEVEL_OTHERCONF:
		return "otherconf";
	case NM_RDISC_DHCP_LEVEL_MANAGED:
		return "managed";
	default:
		return "INVALID";
	}
}

#define expiry(item) (item->timestamp + item->lifetime)

static void
config_changed (NMRDisc *rdisc, NMRDiscConfigMap changed)
{
	int i;
	char changedstr[CONFIG_MAP_MAX_STR];
	char addrstr[INET6_ADDRSTRLEN];

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_IP6)) {
		config_map_to_string (changed, changedstr);
		debug ("(%s): router discovery configuration changed [%s]:", rdisc->ifname, changedstr);
		debug ("  dhcp-level %s", dhcp_level_to_string (rdisc->dhcp_level));
		for (i = 0; i < rdisc->gateways->len; i++) {
			NMRDiscGateway *gateway = &g_array_index (rdisc->gateways, NMRDiscGateway, i);

			inet_ntop (AF_INET6, &gateway->address, addrstr, sizeof (addrstr));
			debug ("  gateway %s pref %d exp %u", addrstr, gateway->preference, expiry (gateway));
		}
		for (i = 0; i < rdisc->addresses->len; i++) {
			NMRDiscAddress *address = &g_array_index (rdisc->addresses, NMRDiscAddress, i);

			inet_ntop (AF_INET6, &address->address, addrstr, sizeof (addrstr));
			debug ("  address %s exp %u", addrstr, expiry (address));
		}
		for (i = 0; i < rdisc->routes->len; i++) {
			NMRDiscRoute *route = &g_array_index (rdisc->routes, NMRDiscRoute, i);

			inet_ntop (AF_INET6, &route->network, addrstr, sizeof (addrstr));
			debug ("  route %s/%d via %s pref %d exp %u", addrstr, route->plen,
				   nm_utils_inet6_ntop (&route->gateway, NULL), route->preference,
				   expiry (route));
		}
		for (i = 0; i < rdisc->dns_servers->len; i++) {
			NMRDiscDNSServer *dns_server = &g_array_index (rdisc->dns_servers, NMRDiscDNSServer, i);

			inet_ntop (AF_INET6, &dns_server->address, addrstr, sizeof (addrstr));
			debug ("  dns_server %s exp %u", addrstr, expiry (dns_server));
		}
		for (i = 0; i < rdisc->dns_domains->len; i++) {
			NMRDiscDNSDomain *dns_domain = &g_array_index (rdisc->dns_domains, NMRDiscDNSDomain, i);

			debug ("  dns_domain %s exp %u", dns_domain->domain, expiry (dns_domain));
		}
	}
}

/******************************************************************/

static void
nm_rdisc_init (NMRDisc *rdisc)
{
	rdisc->gateways = g_array_new (FALSE, FALSE, sizeof (NMRDiscGateway));
	rdisc->addresses = g_array_new (FALSE, FALSE, sizeof (NMRDiscAddress));
	rdisc->routes = g_array_new (FALSE, FALSE, sizeof (NMRDiscRoute));
	rdisc->dns_servers = g_array_new (FALSE, FALSE, sizeof (NMRDiscDNSServer));
	rdisc->dns_domains = g_array_new (FALSE, FALSE, sizeof (NMRDiscDNSDomain));
	rdisc->hop_limit = 64;
}

static void
nm_rdisc_finalize (GObject *object)
{
	NMRDisc *rdisc = NM_RDISC (object);

	g_free (rdisc->ifname);
	g_array_unref (rdisc->gateways);
	g_array_unref (rdisc->addresses);
	g_array_unref (rdisc->routes);
	g_array_unref (rdisc->dns_servers);
	g_array_unref (rdisc->dns_domains);

	G_OBJECT_CLASS (nm_rdisc_parent_class)->finalize (object);
}

static void
nm_rdisc_class_init (NMRDiscClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = nm_rdisc_finalize;

	klass->config_changed = config_changed;

	signals[CONFIG_CHANGED] = g_signal_new (
			NM_RDISC_CONFIG_CHANGED,
			G_OBJECT_CLASS_TYPE (klass),
			G_SIGNAL_RUN_FIRST,
			G_STRUCT_OFFSET (NMRDiscClass, config_changed),
			NULL, NULL, NULL,
			G_TYPE_NONE, 1, G_TYPE_INT);

	signals[RA_TIMEOUT] = g_signal_new (
			NM_RDISC_RA_TIMEOUT,
			G_OBJECT_CLASS_TYPE (klass),
			G_SIGNAL_RUN_FIRST,
			G_STRUCT_OFFSET (NMRDiscClass, ra_timeout),
			NULL, NULL, NULL,
			G_TYPE_NONE, 0);
}
