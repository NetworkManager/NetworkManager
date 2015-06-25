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
#include <string.h>

#include "nm-rdisc.h"
#include "nm-rdisc-private.h"

#include "nm-logging.h"
#include "nm-utils.h"

#define debug(...) nm_log_dbg (LOGD_IP6, __VA_ARGS__)

typedef struct {
	int solicitations_left;
	guint send_rs_id;
	gint64 last_rs;
	guint ra_timeout_id;  /* first RA timeout */
	guint timeout_id;   /* prefix/dns/etc lifetime timeout */
} NMRDiscPrivate;

#define NM_RDISC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_RDISC, NMRDiscPrivate))

G_DEFINE_TYPE (NMRDisc, nm_rdisc, G_TYPE_OBJECT)

enum {
	CONFIG_CHANGED,
	RA_TIMEOUT,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/******************************************************************/

gboolean
nm_rdisc_add_gateway (NMRDisc *rdisc, const NMRDiscGateway *new)
{
	int i, insert_idx = -1;

	for (i = 0; i < rdisc->gateways->len; i++) {
		NMRDiscGateway *item = &g_array_index (rdisc->gateways, NMRDiscGateway, i);

		if (IN6_ARE_ADDR_EQUAL (&item->address, &new->address)) {
			if (new->lifetime == 0) {
				g_array_remove_index (rdisc->gateways, i--);
				return TRUE;
			}

			if (item->preference != new->preference) {
				g_array_remove_index (rdisc->gateways, i--);
				continue;
			}

			memcpy (item, new, sizeof (*new));
			return FALSE;
		}

		/* Put before less preferable gateways. */
		if (item->preference < new->preference && insert_idx < 0)
			insert_idx = i;
	}

	if (new->lifetime)
		g_array_insert_val (rdisc->gateways, MAX (insert_idx, 0), *new);
	return !!new->lifetime;
}

gboolean
nm_rdisc_add_address (NMRDisc *rdisc, const NMRDiscAddress *new)
{
	int i;

	for (i = 0; i < rdisc->addresses->len; i++) {
		NMRDiscAddress *item = &g_array_index (rdisc->addresses, NMRDiscAddress, i);

		if (IN6_ARE_ADDR_EQUAL (&item->address, &new->address)) {
			gboolean changed;

			if (new->lifetime == 0) {
				g_array_remove_index (rdisc->addresses, i--);
				return TRUE;
			}

			changed = item->timestamp + item->lifetime  != new->timestamp + new->lifetime ||
			          item->timestamp + item->preferred != new->timestamp + new->preferred;
			*item = *new;
			return changed;
		}
	}

	/* we create at most max_addresses autoconf addresses. This is different from
	 * what the kernel does, because it considers *all* addresses (including
	 * static and other temporary addresses).
	 **/
	if (rdisc->max_addresses && rdisc->addresses->len >= rdisc->max_addresses)
		return FALSE;

	if (new->lifetime)
		g_array_insert_val (rdisc->addresses, i, *new);
	return !!new->lifetime;
}

gboolean
nm_rdisc_add_route (NMRDisc *rdisc, const NMRDiscRoute *new)
{
	int i, insert_idx = -1;

	for (i = 0; i < rdisc->routes->len; i++) {
		NMRDiscRoute *item = &g_array_index (rdisc->routes, NMRDiscRoute, i);

		if (IN6_ARE_ADDR_EQUAL (&item->network, &new->network) && item->plen == new->plen) {
			if (new->lifetime == 0) {
				g_array_remove_index (rdisc->routes, i--);
				return TRUE;
			}

			if (item->preference != new->preference) {
				g_array_remove_index (rdisc->routes, i--);
				continue;
			}

			memcpy (item, new, sizeof (*new));
			return FALSE;
		}

		/* Put before less preferable routes. */
		if (item->preference < new->preference && insert_idx < 0)
			insert_idx = i;
	}

	if (new->lifetime)
		g_array_insert_val (rdisc->routes, CLAMP (insert_idx, 0, G_MAXINT), *new);
	return !!new->lifetime;
}

gboolean
nm_rdisc_add_dns_server (NMRDisc *rdisc, const NMRDiscDNSServer *new)
{
	int i;

	for (i = 0; i < rdisc->dns_servers->len; i++) {
		NMRDiscDNSServer *item = &g_array_index (rdisc->dns_servers, NMRDiscDNSServer, i);

		if (IN6_ARE_ADDR_EQUAL (&item->address, &new->address)) {
			if (new->lifetime == 0) {
				g_array_remove_index (rdisc->dns_servers, i);
				return TRUE;
			}
			if (item->timestamp != new->timestamp || item->lifetime != new->lifetime) {
				*item = *new;
				return TRUE;
			}
			return FALSE;
		}
	}

	if (new->lifetime)
		g_array_insert_val (rdisc->dns_servers, i, *new);
	return !!new->lifetime;
}

/* Copies new->domain if 'new' is added to the dns_domains list */
gboolean
nm_rdisc_add_dns_domain (NMRDisc *rdisc, const NMRDiscDNSDomain *new)
{
	NMRDiscDNSDomain *item;
	int i;

	for (i = 0; i < rdisc->dns_domains->len; i++) {
		item = &g_array_index (rdisc->dns_domains, NMRDiscDNSDomain, i);

		if (!g_strcmp0 (item->domain, new->domain)) {
			gboolean changed;

			if (new->lifetime == 0) {
				g_array_remove_index (rdisc->dns_domains, i);
				return TRUE;
			}

			changed = (item->timestamp != new->timestamp ||
			           item->lifetime != new->lifetime);
			if (changed) {
				item->timestamp = new->timestamp;
				item->lifetime = new->lifetime;
			}
			return changed;
		}
	}

	if (new->lifetime) {
		g_array_insert_val (rdisc->dns_domains, i, *new);
		item = &g_array_index (rdisc->dns_domains, NMRDiscDNSDomain, i);
		item->domain = g_strdup (new->domain);
	}
	return !!new->lifetime;
}

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

static void
clear_ra_timeout (NMRDisc *rdisc)
{
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);

	if (priv->ra_timeout_id) {
		g_source_remove (priv->ra_timeout_id);
		priv->ra_timeout_id = 0;
	}
}

static void
clear_rs_timeout (NMRDisc *rdisc)
{
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);

	if (priv->send_rs_id) {
		g_source_remove (priv->send_rs_id);
		priv->send_rs_id = 0;
	}
}

static gboolean
send_rs (NMRDisc *rdisc)
{
	NMRDiscClass *klass = NM_RDISC_GET_CLASS (rdisc);
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);

	debug ("(%s): sending router solicitation", rdisc->ifname);

	if (klass->send_rs (rdisc))
		priv->solicitations_left--;

	priv->last_rs = nm_utils_get_monotonic_timestamp_s ();
	if (priv->solicitations_left > 0) {
		debug ("(%s): scheduling router solicitation retry in %d seconds.",
		       rdisc->ifname, rdisc->rtr_solicitation_interval);
		priv->send_rs_id = g_timeout_add_seconds (rdisc->rtr_solicitation_interval,
		                                          (GSourceFunc) send_rs, rdisc);
	} else {
		debug ("(%s): did not receive a router advertisement after %d solicitations.",
		       rdisc->ifname, rdisc->rtr_solicitations);
		priv->send_rs_id = 0;
	}

	return G_SOURCE_REMOVE;
}

static void
solicit (NMRDisc *rdisc)
{
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	gint64 next;

	if (!priv->send_rs_id) {
		priv->solicitations_left = rdisc->rtr_solicitations;

		next = CLAMP (priv->last_rs + rdisc->rtr_solicitation_interval - now, 0, G_MAXINT32);
		debug ("(%s): scheduling explicit router solicitation request in %" G_GINT64_FORMAT " seconds.",
		       rdisc->ifname, next);
		priv->send_rs_id = g_timeout_add_seconds ((guint32) next, (GSourceFunc) send_rs, rdisc);
	}
}

static gboolean
rdisc_ra_timeout_cb (gpointer user_data)
{
	NMRDisc *rdisc = NM_RDISC (user_data);

	NM_RDISC_GET_PRIVATE (rdisc)->ra_timeout_id = 0;
	g_signal_emit_by_name (rdisc, NM_RDISC_RA_TIMEOUT);
	return G_SOURCE_REMOVE;
}

void
nm_rdisc_start (NMRDisc *rdisc)
{
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);
	NMRDiscClass *klass = NM_RDISC_GET_CLASS (rdisc);
	guint ra_wait_secs;

	g_assert (klass->start);

	debug ("(%s): starting router discovery: %d", rdisc->ifname, rdisc->ifindex);

	clear_ra_timeout (rdisc);
	ra_wait_secs = CLAMP (rdisc->rtr_solicitations * rdisc->rtr_solicitation_interval, 30, 120);
	priv->ra_timeout_id = g_timeout_add_seconds (ra_wait_secs, rdisc_ra_timeout_cb, rdisc);
	debug ("(%s): scheduling RA timeout in %d seconds", rdisc->ifname, ra_wait_secs);

	if (klass->start)
		klass->start (rdisc);

	solicit (rdisc);
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

static void
clean_gateways (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap *changed, guint32 *nextevent)
{
	int i;

	for (i = 0; i < rdisc->gateways->len; i++) {
		NMRDiscGateway *item = &g_array_index (rdisc->gateways, NMRDiscGateway, i);
		guint64 expiry = (guint64) item->timestamp + item->lifetime;

		if (item->lifetime == G_MAXUINT32)
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
		guint64 expiry = (guint64) item->timestamp + item->lifetime;

		if (item->lifetime == G_MAXUINT32)
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
		guint64 expiry = (guint64) item->timestamp + item->lifetime;

		if (item->lifetime == G_MAXUINT32)
			continue;

		if (now >= expiry) {
			g_array_remove_index (rdisc->routes, i--);
			*changed |= NM_RDISC_CONFIG_ROUTES;
		} else if (*nextevent > expiry)
			*nextevent = expiry;
	}
}

static void
clean_dns_servers (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap *changed, guint32 *nextevent)
{
	int i;

	for (i = 0; i < rdisc->dns_servers->len; i++) {
		NMRDiscDNSServer *item = &g_array_index (rdisc->dns_servers, NMRDiscDNSServer, i);
		guint64 expiry = (guint64) item->timestamp + item->lifetime;
		guint64 refresh = (guint64) item->timestamp + item->lifetime / 2;

		if (item->lifetime == G_MAXUINT32)
			continue;

		if (now >= expiry) {
			g_array_remove_index (rdisc->dns_servers, i--);
			*changed |= NM_RDISC_CONFIG_DNS_SERVERS;
		} else if (now >= refresh)
			solicit (rdisc);
		else if (*nextevent > refresh)
			*nextevent = refresh;
	}
}

static void
clean_dns_domains (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap *changed, guint32 *nextevent)
{
	int i;

	for (i = 0; i < rdisc->dns_domains->len; i++) {
		NMRDiscDNSDomain *item = &g_array_index (rdisc->dns_domains, NMRDiscDNSDomain, i);
		guint64 expiry = (guint64) item->timestamp + item->lifetime;
		guint64 refresh = (guint64) item->timestamp + item->lifetime / 2;

		if (item->lifetime == G_MAXUINT32)
			continue;

		if (now >= expiry) {
			g_array_remove_index (rdisc->dns_domains, i--);
			*changed |= NM_RDISC_CONFIG_DNS_DOMAINS;
		} else if (now >= refresh)
			solicit (rdisc);
		else if (*nextevent > refresh)
			*nextevent = refresh;
	}
}

static gboolean timeout_cb (gpointer user_data);

static void
check_timestamps (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap changed)
{
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);
	/* Use a magic date in the distant future (~68 years) */
	guint32 never = G_MAXINT32;
	guint32 nextevent = never;

	if (priv->timeout_id) {
		g_source_remove (priv->timeout_id);
		priv->timeout_id = 0;
	}

	clean_gateways (rdisc, now, &changed, &nextevent);
	clean_addresses (rdisc, now, &changed, &nextevent);
	clean_routes (rdisc, now, &changed, &nextevent);
	clean_dns_servers (rdisc, now, &changed, &nextevent);
	clean_dns_domains (rdisc, now, &changed, &nextevent);

	if (changed)
		g_signal_emit_by_name (rdisc, NM_RDISC_CONFIG_CHANGED, changed);

	if (nextevent != never) {
		g_return_if_fail (nextevent > now);
		debug ("(%s): scheduling next now/lifetime check: %u seconds",
		       rdisc->ifname, nextevent - now);
		priv->timeout_id = g_timeout_add_seconds (nextevent - now, timeout_cb, rdisc);
	}
}

static gboolean
timeout_cb (gpointer user_data)
{
	NM_RDISC_GET_PRIVATE (user_data)->timeout_id = 0;
	check_timestamps (NM_RDISC (user_data), nm_utils_get_monotonic_timestamp_s (), 0);
	return G_SOURCE_REMOVE;
}

void
nm_rdisc_ra_received (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap changed)
{
	clear_ra_timeout (rdisc);
	clear_rs_timeout (rdisc);
	check_timestamps (rdisc, now, changed);
}

/******************************************************************/

static void
dns_domain_free (gpointer data)
{
	g_free (((NMRDiscDNSDomain *)(data))->domain);
}

static void
nm_rdisc_init (NMRDisc *rdisc)
{
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);

	rdisc->gateways = g_array_new (FALSE, FALSE, sizeof (NMRDiscGateway));
	rdisc->addresses = g_array_new (FALSE, FALSE, sizeof (NMRDiscAddress));
	rdisc->routes = g_array_new (FALSE, FALSE, sizeof (NMRDiscRoute));
	rdisc->dns_servers = g_array_new (FALSE, FALSE, sizeof (NMRDiscDNSServer));
	rdisc->dns_domains = g_array_new (FALSE, FALSE, sizeof (NMRDiscDNSDomain));
	g_array_set_clear_func (rdisc->dns_domains, dns_domain_free);
	rdisc->hop_limit = 64;

	/* Start at very low number so that last_rs - rtr_solicitation_interval
	 * is much lower than nm_utils_get_monotonic_timestamp_s() at startup.
	 */
	priv->last_rs = G_MININT32;
}

static void
dispose (GObject *object)
{
	NMRDisc *rdisc = NM_RDISC (object);
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);

	clear_ra_timeout (rdisc);
	clear_rs_timeout (rdisc);

	if (priv->timeout_id) {
		g_source_remove (priv->timeout_id);
		priv->timeout_id = 0;
	}

	G_OBJECT_CLASS (nm_rdisc_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
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

	g_type_class_add_private (klass, sizeof (NMRDiscPrivate));

	object_class->dispose = dispose;
	object_class->finalize = finalize;
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
