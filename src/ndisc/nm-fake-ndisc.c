/* nm-fake-ndisc.c - Fake implementation of neighbor discovery
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

#include "nm-fake-ndisc.h"

#include <arpa/inet.h>

#include "nm-ndisc-private.h"

#define _NMLOG_PREFIX_NAME                "ndisc-fake"

/*****************************************************************************/

typedef struct {
	guint id;
	guint when;

	NMNDiscDHCPLevel dhcp_level;
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
        NMIcmpv6RouterPref preference;
} FakePrefix;

/*****************************************************************************/

enum {
	RS_SENT,
	LAST_SIGNAL,
};
static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	guint receive_ra_id;
	GSList *ras;
} NMFakeNDiscPrivate;

struct _NMFakeRNDisc {
	NMNDisc parent;
	NMFakeNDiscPrivate _priv;
};

struct _NMFakeRNDiscClass {
	NMNDiscClass parent;
};

G_DEFINE_TYPE (NMFakeNDisc, nm_fake_ndisc, NM_TYPE_NDISC)

#define NM_FAKE_NDISC_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMFakeNDisc, NM_IS_FAKE_NDISC)

/*****************************************************************************/

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
	g_free (((NMNDiscDNSDomain *)(data))->domain);
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
nm_fake_ndisc_add_ra (NMFakeNDisc *self,
                      guint seconds_after_previous,
                      NMNDiscDHCPLevel dhcp_level,
                      int hop_limit,
                      guint32 mtu)
{
	NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE (self);
	static guint counter = 1;
	FakeRa *ra;

	ra = g_malloc0 (sizeof (*ra));
	ra->id = counter++;
	ra->when = seconds_after_previous;
	ra->dhcp_level = dhcp_level;
	ra->hop_limit = hop_limit;
	ra->mtu = mtu;
	ra->gateways = g_array_new (FALSE, FALSE, sizeof (NMNDiscGateway));
	ra->prefixes = g_array_new (FALSE, FALSE, sizeof (FakePrefix));
	ra->dns_servers = g_array_new (FALSE, FALSE, sizeof (NMNDiscDNSServer));
	ra->dns_domains = g_array_new (FALSE, FALSE, sizeof (NMNDiscDNSDomain));
	g_array_set_clear_func (ra->dns_domains, ra_dns_domain_free);

	priv->ras = g_slist_append (priv->ras, ra);
	return ra->id;
}

void
nm_fake_ndisc_add_gateway (NMFakeNDisc *self,
                           guint ra_id,
                           const char *addr,
                           guint32 timestamp,
                           guint32 lifetime,
                           NMIcmpv6RouterPref preference)
{
	NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE (self);
	FakeRa *ra = find_ra (priv->ras, ra_id);
	NMNDiscGateway *gw;

	g_assert (ra);
	g_array_set_size (ra->gateways, ra->gateways->len + 1);
	gw = &g_array_index (ra->gateways, NMNDiscGateway, ra->gateways->len - 1);
	g_assert (inet_pton (AF_INET6, addr, &gw->address) == 1);
	gw->timestamp = timestamp;
	gw->lifetime = lifetime;
	gw->preference = preference;
}

void
nm_fake_ndisc_add_prefix (NMFakeNDisc *self,
                          guint ra_id,
                          const char *network,
                          guint plen,
                          const char *gateway,
                          guint32 timestamp,
                          guint32 lifetime,
                          guint32 preferred,
                          NMIcmpv6RouterPref preference)
{
	NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE (self);
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
nm_fake_ndisc_add_dns_server (NMFakeNDisc *self,
                              guint ra_id,
                              const char *address,
                              guint32 timestamp,
                              guint32 lifetime)
{
	NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE (self);
	FakeRa *ra = find_ra (priv->ras, ra_id);
	NMNDiscDNSServer *dns;

	g_assert (ra);
	g_array_set_size (ra->dns_servers, ra->dns_servers->len + 1);
	dns = &g_array_index (ra->dns_servers, NMNDiscDNSServer, ra->dns_servers->len - 1);
	g_assert (inet_pton (AF_INET6, address, &dns->address) == 1);
	dns->timestamp = timestamp;
	dns->lifetime = lifetime;
}

void
nm_fake_ndisc_add_dns_domain (NMFakeNDisc *self,
                              guint ra_id,
                              const char *domain,
                              guint32 timestamp,
                              guint32 lifetime)
{
	NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE (self);
	FakeRa *ra = find_ra (priv->ras, ra_id);
	NMNDiscDNSDomain *dns;

	g_assert (ra);
	g_array_set_size (ra->dns_domains, ra->dns_domains->len + 1);
	dns = &g_array_index (ra->dns_domains, NMNDiscDNSDomain, ra->dns_domains->len - 1);
	dns->domain = g_strdup (domain);
	dns->timestamp = timestamp;
	dns->lifetime = lifetime;
}

gboolean
nm_fake_ndisc_done (NMFakeNDisc *self)
{
	return !NM_FAKE_NDISC_GET_PRIVATE (self)->ras;
}

/*****************************************************************************/

static gboolean
send_rs (NMNDisc *ndisc, GError **error)
{
	g_signal_emit (ndisc, signals[RS_SENT], 0);
	return TRUE;
}

static gboolean
receive_ra (gpointer user_data)
{
	NMFakeNDisc *self = user_data;
	NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE (self);
	NMNDisc *ndisc = NM_NDISC (self);
	NMNDiscDataInternal *rdata = ndisc->rdata;
	FakeRa *ra = priv->ras->data;
	NMNDiscConfigMap changed = 0;
	gint32 now = nm_utils_get_monotonic_timestamp_s ();
	guint i;
	NMNDiscDHCPLevel dhcp_level;

	priv->receive_ra_id = 0;

	/* preserve the "most managed" level  on updates. */
	dhcp_level = MAX (rdata->public.dhcp_level, ra->dhcp_level);

	if (rdata->public.dhcp_level != dhcp_level) {
		rdata->public.dhcp_level = dhcp_level;
		changed |= NM_NDISC_CONFIG_DHCP_LEVEL;
	}

	for (i = 0; i < ra->gateways->len; i++) {
		NMNDiscGateway *item = &g_array_index (ra->gateways, NMNDiscGateway, i);

		if (nm_ndisc_add_gateway (ndisc, item))
			changed |= NM_NDISC_CONFIG_GATEWAYS;
	}

	for (i = 0; i < ra->prefixes->len; i++) {
		FakePrefix *item = &g_array_index (ra->prefixes, FakePrefix, i);
		NMNDiscRoute route = {
			.network = item->network,
			.plen = item->plen,
			.gateway = item->gateway,
			.timestamp = item->timestamp,
			.lifetime = item->lifetime,
			.preference = item->preference,
		};

		g_assert (route.plen > 0 && route.plen <= 128);

		if (nm_ndisc_add_route (ndisc, &route))
			changed |= NM_NDISC_CONFIG_ROUTES;

		if (item->plen == 64) {
			NMNDiscAddress address = {
				.address = item->network,
				.timestamp = item->timestamp,
				.lifetime = item->lifetime,
				.preferred = item->preferred,
				.dad_counter = 0,
			};

			if (nm_ndisc_complete_and_add_address (ndisc, &address, now))
				changed |= NM_NDISC_CONFIG_ADDRESSES;
		}
	}

	for (i = 0; i < ra->dns_servers->len; i++) {
		NMNDiscDNSServer *item = &g_array_index (ra->dns_servers, NMNDiscDNSServer, i);

		if (nm_ndisc_add_dns_server (ndisc, item))
			changed |= NM_NDISC_CONFIG_DNS_SERVERS;
	}

	for (i = 0; i < ra->dns_domains->len; i++) {
		NMNDiscDNSDomain *item = &g_array_index (ra->dns_domains, NMNDiscDNSDomain, i);

		if (nm_ndisc_add_dns_domain (ndisc, item))
			changed |= NM_NDISC_CONFIG_DNS_DOMAINS;
	}

	if (rdata->public.mtu != ra->mtu) {
		rdata->public.mtu = ra->mtu;
		changed |= NM_NDISC_CONFIG_MTU;
	}

	if (rdata->public.hop_limit != ra->hop_limit) {
		rdata->public.hop_limit = ra->hop_limit;
		changed |= NM_NDISC_CONFIG_HOP_LIMIT;
	}

	priv->ras = g_slist_remove (priv->ras, priv->ras->data);
	fake_ra_free (ra);

	nm_ndisc_ra_received (NM_NDISC (self), now, changed);

	/* Schedule next RA */
	if (priv->ras) {
		ra = priv->ras->data;
		priv->receive_ra_id = g_timeout_add_seconds (ra->when, receive_ra, self);
	}

	return G_SOURCE_REMOVE;
}

static void
start (NMNDisc *ndisc)
{
	NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE ((NMFakeNDisc *) ndisc);
	FakeRa *ra;

	/* Queue up the first fake RA */
	g_assert (priv->ras);
	ra = priv->ras->data;

	g_assert (!priv->receive_ra_id);
	priv->receive_ra_id = g_timeout_add_seconds (ra->when, receive_ra, ndisc);
}

void
nm_fake_ndisc_emit_new_ras (NMFakeNDisc *self)
{
	if (!NM_FAKE_NDISC_GET_PRIVATE (self)->receive_ra_id)
		start (NM_NDISC (self));
}

/*****************************************************************************/

static void
nm_fake_ndisc_init (NMFakeNDisc *fake_ndisc)
{
}

NMNDisc *
nm_fake_ndisc_new (int ifindex, const char *ifname)
{
	return g_object_new (NM_TYPE_FAKE_NDISC,
	                     NM_NDISC_IFINDEX, ifindex,
	                     NM_NDISC_IFNAME, ifname,
	                     NM_NDISC_NODE_TYPE, (int) NM_NDISC_NODE_TYPE_HOST,
	                     NM_NDISC_STABLE_TYPE, (int) NM_UTILS_STABLE_TYPE_UUID,
	                     NM_NDISC_NETWORK_ID, "fake",
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE ((NMFakeNDisc *) object);

	nm_clear_g_source (&priv->receive_ra_id);

	g_slist_free_full (priv->ras, fake_ra_free);
	priv->ras = NULL;

	G_OBJECT_CLASS (nm_fake_ndisc_parent_class)->dispose (object);
}

static void
nm_fake_ndisc_class_init (NMFakeNDiscClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMNDiscClass *ndisc_class = NM_NDISC_CLASS (klass);

	object_class->dispose = dispose;

	ndisc_class->start = start;
	ndisc_class->send_rs = send_rs;

	signals[RS_SENT] =
	    g_signal_new (NM_FAKE_NDISC_RS_SENT,
	                  G_OBJECT_CLASS_TYPE (klass),
	                  G_SIGNAL_RUN_FIRST,
	                  0,  NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);
}
