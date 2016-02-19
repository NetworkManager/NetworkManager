/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-fake-rdisc.c - Fake implementation of router discovery
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

#include <string.h>
#include <arpa/inet.h>

#include "nm-fake-rdisc.h"
#include "nm-rdisc-private.h"

#define _NMLOG_PREFIX_NAME                "rdisc-fake"

typedef struct {
	guint id;
	guint when;

	NMRDiscDHCPLevel dhcp_level;
	GArray *gateways;
	GArray *prefixes;
	GArray *dns_servers;
	GArray *dns_domains;
	int hop_limit;
	guint32 mtu;
} FakeRa;

typedef struct {
        struct in6_addr network;
        int plen;
        struct in6_addr gateway;
        guint32 timestamp;
        guint32 lifetime;
        guint32 preferred;
        NMRDiscPreference preference;
} FakePrefix;

typedef struct {
	guint receive_ra_id;
	GSList *ras;
} NMFakeRDiscPrivate;

#define NM_FAKE_RDISC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_FAKE_RDISC, NMFakeRDiscPrivate))

G_DEFINE_TYPE (NMFakeRDisc, nm_fake_rdisc, NM_TYPE_RDISC)

enum {
	RS_SENT,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

/******************************************************************/

static void
fake_ra_free (gpointer data)
{
	FakeRa *ra = data;

	g_array_free (ra->gateways, TRUE);
	g_array_free (ra->prefixes, TRUE);
	g_array_free (ra->dns_servers, TRUE);
	g_array_free (ra->dns_domains, TRUE);
	g_free (ra);
}

static void
ra_dns_domain_free (gpointer data)
{
	g_free (((NMRDiscDNSDomain *)(data))->domain);
}

static FakeRa *
find_ra (GSList *ras, guint id)
{
	GSList *iter;

	for (iter = ras; iter; iter = iter->next) {
		if (((FakeRa *) iter->data)->id == id)
			return iter->data;
	}
	return NULL;
}

guint
nm_fake_rdisc_add_ra (NMFakeRDisc *self,
                      guint seconds_after_previous,
                      NMRDiscDHCPLevel dhcp_level,
                      int hop_limit,
                      guint32 mtu)
{
	NMFakeRDiscPrivate *priv = NM_FAKE_RDISC_GET_PRIVATE (self);
	static guint counter = 1;
	FakeRa *ra;

	ra = g_malloc0 (sizeof (*ra));
	ra->id = counter++;
	ra->when = seconds_after_previous;
	ra->dhcp_level = dhcp_level;
	ra->hop_limit = hop_limit;
	ra->mtu = mtu;
	ra->gateways = g_array_new (FALSE, FALSE, sizeof (NMRDiscGateway));
	ra->prefixes = g_array_new (FALSE, FALSE, sizeof (FakePrefix));
	ra->dns_servers = g_array_new (FALSE, FALSE, sizeof (NMRDiscDNSServer));
	ra->dns_domains = g_array_new (FALSE, FALSE, sizeof (NMRDiscDNSDomain));
	g_array_set_clear_func (ra->dns_domains, ra_dns_domain_free);

	priv->ras = g_slist_append (priv->ras, ra);
	return ra->id;
}

void
nm_fake_rdisc_add_gateway (NMFakeRDisc *self,
                           guint ra_id,
                           const char *addr,
                           guint32 timestamp,
                           guint32 lifetime,
                           NMRDiscPreference preference)
{
	NMFakeRDiscPrivate *priv = NM_FAKE_RDISC_GET_PRIVATE (self);
	FakeRa *ra = find_ra (priv->ras, ra_id);
	NMRDiscGateway *gw;

	g_assert (ra);
	g_array_set_size (ra->gateways, ra->gateways->len + 1);
	gw = &g_array_index (ra->gateways, NMRDiscGateway, ra->gateways->len - 1);
	g_assert (inet_pton (AF_INET6, addr, &gw->address) == 1);
	gw->timestamp = timestamp;
	gw->lifetime = lifetime;
	gw->preference = preference;
}

void
nm_fake_rdisc_add_prefix (NMFakeRDisc *self,
                          guint ra_id,
                          const char *network,
                          guint plen,
                          const char *gateway,
                          guint32 timestamp,
                          guint32 lifetime,
                          guint32 preferred,
                          NMRDiscPreference preference)
{
	NMFakeRDiscPrivate *priv = NM_FAKE_RDISC_GET_PRIVATE (self);
	FakeRa *ra = find_ra (priv->ras, ra_id);
	FakePrefix *prefix;

	g_assert (ra);
	g_array_set_size (ra->prefixes, ra->prefixes->len + 1);
	prefix = &g_array_index (ra->prefixes, FakePrefix, ra->prefixes->len - 1);
	memset (prefix, 0, sizeof (*prefix));
	g_assert (inet_pton (AF_INET6, network, &prefix->network) == 1);
	g_assert (inet_pton (AF_INET6, gateway, &prefix->gateway) == 1);
	prefix->plen = plen;
	prefix->timestamp = timestamp;
	prefix->lifetime = lifetime;
	prefix->preferred = preferred;
	prefix->preference = preference;
}

void
nm_fake_rdisc_add_dns_server (NMFakeRDisc *self,
                              guint ra_id,
                              const char *address,
                              guint32 timestamp,
                              guint32 lifetime)
{
	NMFakeRDiscPrivate *priv = NM_FAKE_RDISC_GET_PRIVATE (self);
	FakeRa *ra = find_ra (priv->ras, ra_id);
	NMRDiscDNSServer *dns;

	g_assert (ra);
	g_array_set_size (ra->dns_servers, ra->dns_servers->len + 1);
	dns = &g_array_index (ra->dns_servers, NMRDiscDNSServer, ra->dns_servers->len - 1);
	g_assert (inet_pton (AF_INET6, address, &dns->address) == 1);
	dns->timestamp = timestamp;
	dns->lifetime = lifetime;
}

void
nm_fake_rdisc_add_dns_domain (NMFakeRDisc *self,
                              guint ra_id,
                              const char *domain,
                              guint32 timestamp,
                              guint32 lifetime)
{
	NMFakeRDiscPrivate *priv = NM_FAKE_RDISC_GET_PRIVATE (self);
	FakeRa *ra = find_ra (priv->ras, ra_id);
	NMRDiscDNSDomain *dns;

	g_assert (ra);
	g_array_set_size (ra->dns_domains, ra->dns_domains->len + 1);
	dns = &g_array_index (ra->dns_domains, NMRDiscDNSDomain, ra->dns_domains->len - 1);
	dns->domain = g_strdup (domain);
	dns->timestamp = timestamp;
	dns->lifetime = lifetime;
}

gboolean
nm_fake_rdisc_done (NMFakeRDisc *self)
{
	return !NM_FAKE_RDISC_GET_PRIVATE (self)->ras;
}

/******************************************************************/

static gboolean
send_rs (NMRDisc *rdisc, GError **error)
{
	g_signal_emit (rdisc, signals[RS_SENT], 0);
	return TRUE;
}

static gboolean
receive_ra (gpointer user_data)
{
	NMFakeRDisc *self = user_data;
	NMFakeRDiscPrivate *priv = NM_FAKE_RDISC_GET_PRIVATE (self);
	NMRDisc *rdisc = NM_RDISC (self);
	FakeRa *ra = priv->ras->data;
	NMRDiscConfigMap changed = 0;
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	guint i;

	priv->receive_ra_id = 0;

	if (rdisc->dhcp_level != ra->dhcp_level) {
		rdisc->dhcp_level = ra->dhcp_level;
		changed |= NM_RDISC_CONFIG_DHCP_LEVEL;
	}

	for (i = 0; i < ra->gateways->len; i++) {
		NMRDiscGateway *item = &g_array_index (ra->gateways, NMRDiscGateway, i);

		if (nm_rdisc_add_gateway (rdisc, item))
			changed |= NM_RDISC_CONFIG_GATEWAYS;
	}

	for (i = 0; i < ra->prefixes->len; i++) {
		FakePrefix *item = &g_array_index (ra->prefixes, FakePrefix, i);
		NMRDiscRoute route = {
			.network = item->network,
			.plen = item->plen,
			.gateway = item->gateway,
			.timestamp = item->timestamp,
			.lifetime = item->lifetime,
			.preference = item->preference,
		};

		if (nm_rdisc_add_route (rdisc, &route))
			changed |= NM_RDISC_CONFIG_ROUTES;

		if (item->plen == 64) {
			NMRDiscAddress address = {
				.address = item->network,
				.timestamp = item->timestamp,
				.lifetime = item->lifetime,
				.preferred = item->preferred,
				.dad_counter = 0,
			};

			if (nm_rdisc_complete_and_add_address (rdisc, &address))
				changed |= NM_RDISC_CONFIG_ADDRESSES;
		}
	}

	for (i = 0; i < ra->dns_servers->len; i++) {
		NMRDiscDNSServer *item = &g_array_index (ra->dns_servers, NMRDiscDNSServer, i);

		if (nm_rdisc_add_dns_server (rdisc, item))
			changed |= NM_RDISC_CONFIG_DNS_SERVERS;
	}

	for (i = 0; i < ra->dns_domains->len; i++) {
		NMRDiscDNSDomain *item = &g_array_index (ra->dns_domains, NMRDiscDNSDomain, i);

		if (nm_rdisc_add_dns_domain (rdisc, item))
			changed |= NM_RDISC_CONFIG_DNS_DOMAINS;
	}

	if (rdisc->mtu != ra->mtu) {
		rdisc->mtu = ra->mtu;
		changed |= NM_RDISC_CONFIG_MTU;
	}

	if (rdisc->hop_limit != ra->hop_limit) {
		rdisc->hop_limit = ra->hop_limit;
		changed |= NM_RDISC_CONFIG_HOP_LIMIT;
	}

	priv->ras = g_slist_remove (priv->ras, priv->ras->data);
	fake_ra_free (ra);

	nm_rdisc_ra_received (NM_RDISC (self), now, changed);

	/* Schedule next RA */
	if (priv->ras) {
		ra = priv->ras->data;
		priv->receive_ra_id = g_timeout_add_seconds (ra->when, receive_ra, self);
	}

	return G_SOURCE_REMOVE;
}

static void
start (NMRDisc *rdisc)
{
	NMFakeRDiscPrivate *priv = NM_FAKE_RDISC_GET_PRIVATE (rdisc);
	FakeRa *ra;

	/* Queue up the first fake RA */
	g_assert (priv->ras);
	ra = NM_FAKE_RDISC_GET_PRIVATE (rdisc)->ras->data;

	g_assert (!priv->receive_ra_id);
	priv->receive_ra_id = g_timeout_add_seconds (ra->when, receive_ra, rdisc);
}

void
nm_fake_rdisc_emit_new_ras (NMFakeRDisc *self)
{
	if (!NM_FAKE_RDISC_GET_PRIVATE (self)->receive_ra_id)
		start (NM_RDISC (self));
}

/******************************************************************/

NMRDisc *
nm_fake_rdisc_new (int ifindex, const char *ifname)
{
	NMRDisc *rdisc = g_object_new (NM_TYPE_FAKE_RDISC, NULL);

	rdisc->ifindex = ifindex;
	rdisc->ifname = g_strdup (ifname);
	rdisc->max_addresses = NM_RDISC_MAX_ADDRESSES_DEFAULT;
	rdisc->rtr_solicitations = NM_RDISC_RTR_SOLICITATIONS_DEFAULT;
	rdisc->rtr_solicitation_interval = NM_RDISC_RTR_SOLICITATION_INTERVAL_DEFAULT;

	return rdisc;
}

static void
nm_fake_rdisc_init (NMFakeRDisc *fake_rdisc)
{
}

static void
dispose (GObject *object)
{
	NMFakeRDiscPrivate *priv = NM_FAKE_RDISC_GET_PRIVATE (object);

	nm_clear_g_source (&priv->receive_ra_id);

	g_slist_free_full (priv->ras, fake_ra_free);
	priv->ras = NULL;

	G_OBJECT_CLASS (nm_fake_rdisc_parent_class)->dispose (object);
}

static void
nm_fake_rdisc_class_init (NMFakeRDiscClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMRDiscClass *rdisc_class = NM_RDISC_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMFakeRDiscPrivate));

	object_class->dispose = dispose;
	rdisc_class->start = start;
	rdisc_class->send_rs = send_rs;

	signals[RS_SENT] = g_signal_new (
			NM_FAKE_RDISC_RS_SENT,
			G_OBJECT_CLASS_TYPE (klass),
			G_SIGNAL_RUN_FIRST,
			0,  NULL, NULL, NULL,
			G_TYPE_NONE, 0);
}
