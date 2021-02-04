/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-fake-ndisc.h"

#include <arpa/inet.h>

#include "nm-ndisc-private.h"

#define _NMLOG_PREFIX_NAME "ndisc-fake"

/*****************************************************************************/

typedef struct {
    guint id;
    guint when;

    NMNDiscDHCPLevel dhcp_level;
    GArray *         gateways;
    GArray *         prefixes;
    GArray *         dns_servers;
    GArray *         dns_domains;
    int              hop_limit;
    guint32          mtu;
} FakeRa;

typedef struct {
    struct in6_addr    network;
    struct in6_addr    gateway;
    gint64             expiry_msec;
    gint64             expiry_preferred_msec;
    int                plen;
    NMIcmpv6RouterPref preference;
} FakePrefix;

/*****************************************************************************/

enum {
    RS_SENT,
    LAST_SIGNAL,
};
static guint signals[LAST_SIGNAL] = {0};

typedef struct {
    guint   receive_ra_id;
    GSList *ras;
} NMFakeNDiscPrivate;

struct _NMFakeRNDisc {
    NMNDisc            parent;
    NMFakeNDiscPrivate _priv;
};

struct _NMFakeRNDiscClass {
    NMNDiscClass parent;
};

G_DEFINE_TYPE(NMFakeNDisc, nm_fake_ndisc, NM_TYPE_NDISC)

#define NM_FAKE_NDISC_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMFakeNDisc, NM_IS_FAKE_NDISC, NMNDisc)

/*****************************************************************************/

static void
fake_ra_free(gpointer data)
{
    FakeRa *ra = data;

    g_array_free(ra->gateways, TRUE);
    g_array_free(ra->prefixes, TRUE);
    g_array_free(ra->dns_servers, TRUE);
    g_array_free(ra->dns_domains, TRUE);
    g_free(ra);
}

static void
ra_dns_domain_free(gpointer data)
{
    g_free(((NMNDiscDNSDomain *) (data))->domain);
}

static FakeRa *
find_ra(GSList *ras, guint id)
{
    GSList *iter;

    for (iter = ras; iter; iter = iter->next) {
        if (((FakeRa *) iter->data)->id == id)
            return iter->data;
    }
    return NULL;
}

guint
nm_fake_ndisc_add_ra(NMFakeNDisc *    self,
                     guint            seconds_after_previous,
                     NMNDiscDHCPLevel dhcp_level,
                     int              hop_limit,
                     guint32          mtu)
{
    NMFakeNDiscPrivate *priv    = NM_FAKE_NDISC_GET_PRIVATE(self);
    static guint        counter = 1;
    FakeRa *            ra;

    ra              = g_malloc0(sizeof(*ra));
    ra->id          = counter++;
    ra->when        = seconds_after_previous;
    ra->dhcp_level  = dhcp_level;
    ra->hop_limit   = hop_limit;
    ra->mtu         = mtu;
    ra->gateways    = g_array_new(FALSE, FALSE, sizeof(NMNDiscGateway));
    ra->prefixes    = g_array_new(FALSE, FALSE, sizeof(FakePrefix));
    ra->dns_servers = g_array_new(FALSE, FALSE, sizeof(NMNDiscDNSServer));
    ra->dns_domains = g_array_new(FALSE, FALSE, sizeof(NMNDiscDNSDomain));
    g_array_set_clear_func(ra->dns_domains, ra_dns_domain_free);

    priv->ras = g_slist_append(priv->ras, ra);
    return ra->id;
}

void
nm_fake_ndisc_add_gateway(NMFakeNDisc *      self,
                          guint              ra_id,
                          const char *       addr,
                          gint64             expiry_msec,
                          NMIcmpv6RouterPref preference)
{
    NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE(self);
    FakeRa *            ra   = find_ra(priv->ras, ra_id);
    NMNDiscGateway *    gw;

    g_assert(ra);

    gw = nm_g_array_append_new(ra->gateways, NMNDiscGateway);
    if (inet_pton(AF_INET6, addr, &gw->address) != 1)
        g_assert_not_reached();
    gw->expiry_msec = expiry_msec;
    gw->preference  = preference;
}

void
nm_fake_ndisc_add_prefix(NMFakeNDisc *      self,
                         guint              ra_id,
                         const char *       network,
                         guint              plen,
                         const char *       gateway,
                         gint64             expiry_msec,
                         gint64             expiry_preferred_msec,
                         NMIcmpv6RouterPref preference)
{
    NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE(self);
    FakeRa *            ra   = find_ra(priv->ras, ra_id);
    FakePrefix *        prefix;

    g_assert(ra);

    prefix  = nm_g_array_append_new(ra->prefixes, FakePrefix);
    *prefix = (FakePrefix){
        .plen                  = plen,
        .expiry_msec           = expiry_msec,
        .expiry_preferred_msec = expiry_preferred_msec,
        .preference            = preference,
    };
    if (inet_pton(AF_INET6, network, &prefix->network) != 1)
        g_assert_not_reached();
    if (inet_pton(AF_INET6, gateway, &prefix->gateway) != 1)
        g_assert_not_reached();
}

void
nm_fake_ndisc_add_dns_server(NMFakeNDisc *self,
                             guint        ra_id,
                             const char * address,
                             gint64       expiry_msec)
{
    NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE(self);
    FakeRa *            ra   = find_ra(priv->ras, ra_id);
    NMNDiscDNSServer *  dns;

    g_assert(ra);

    dns = nm_g_array_append_new(ra->dns_servers, NMNDiscDNSServer);

    dns->expiry_msec = expiry_msec;
    if (inet_pton(AF_INET6, address, &dns->address) != 1)
        g_assert_not_reached();
}

void
nm_fake_ndisc_add_dns_domain(NMFakeNDisc *self, guint ra_id, const char *domain, gint64 expiry_msec)
{
    NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE(self);
    FakeRa *            ra   = find_ra(priv->ras, ra_id);
    NMNDiscDNSDomain *  dns;

    g_assert(ra);

    dns = nm_g_array_append_new(ra->dns_domains, NMNDiscDNSDomain);

    dns->domain      = g_strdup(domain);
    dns->expiry_msec = expiry_msec;
}

gboolean
nm_fake_ndisc_done(NMFakeNDisc *self)
{
    return !NM_FAKE_NDISC_GET_PRIVATE(self)->ras;
}

/*****************************************************************************/

static gboolean
send_rs(NMNDisc *ndisc, GError **error)
{
    _LOGT("send_rs()");
    g_signal_emit(ndisc, signals[RS_SENT], 0);
    return TRUE;
}

static gboolean
receive_ra(gpointer user_data)
{
    NMFakeNDisc *        self     = user_data;
    NMFakeNDiscPrivate * priv     = NM_FAKE_NDISC_GET_PRIVATE(self);
    NMNDisc *            ndisc    = NM_NDISC(self);
    NMNDiscDataInternal *rdata    = ndisc->rdata;
    FakeRa *             ra       = priv->ras->data;
    NMNDiscConfigMap     changed  = 0;
    const gint64         now_msec = nm_utils_get_monotonic_timestamp_msec();
    guint                i;
    NMNDiscDHCPLevel     dhcp_level;

    priv->receive_ra_id = 0;

    /* preserve the "most managed" level  on updates. */
    dhcp_level = MAX(rdata->public.dhcp_level, ra->dhcp_level);

    if (rdata->public.dhcp_level != dhcp_level) {
        rdata->public.dhcp_level = dhcp_level;
        changed |= NM_NDISC_CONFIG_DHCP_LEVEL;
    }

    for (i = 0; i < ra->gateways->len; i++) {
        const NMNDiscGateway *item = &g_array_index(ra->gateways, NMNDiscGateway, i);

        if (nm_ndisc_add_gateway(ndisc, item, now_msec))
            changed |= NM_NDISC_CONFIG_GATEWAYS;
    }

    for (i = 0; i < ra->prefixes->len; i++) {
        FakePrefix *       item  = &g_array_index(ra->prefixes, FakePrefix, i);
        const NMNDiscRoute route = {
            .network     = item->network,
            .plen        = item->plen,
            .gateway     = item->gateway,
            .expiry_msec = item->expiry_msec,
            .preference  = item->preference,
        };

        g_assert(route.plen > 0 && route.plen <= 128);

        if (nm_ndisc_add_route(ndisc, &route, now_msec))
            changed |= NM_NDISC_CONFIG_ROUTES;

        if (item->plen == 64) {
            const NMNDiscAddress address = {
                .address               = item->network,
                .expiry_msec           = item->expiry_msec,
                .expiry_preferred_msec = item->expiry_preferred_msec,
                .dad_counter           = 0,
            };

            if (nm_ndisc_complete_and_add_address(ndisc, &address, now_msec))
                changed |= NM_NDISC_CONFIG_ADDRESSES;
        }
    }

    for (i = 0; i < ra->dns_servers->len; i++) {
        const NMNDiscDNSServer *item = &g_array_index(ra->dns_servers, NMNDiscDNSServer, i);

        if (nm_ndisc_add_dns_server(ndisc, item, now_msec))
            changed |= NM_NDISC_CONFIG_DNS_SERVERS;
    }

    for (i = 0; i < ra->dns_domains->len; i++) {
        const NMNDiscDNSDomain *item = &g_array_index(ra->dns_domains, NMNDiscDNSDomain, i);

        if (nm_ndisc_add_dns_domain(ndisc, item, now_msec))
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

    priv->ras = g_slist_remove(priv->ras, priv->ras->data);
    fake_ra_free(ra);

    nm_ndisc_ra_received(NM_NDISC(self), now_msec, changed);

    /* Schedule next RA */
    if (priv->ras) {
        ra                  = priv->ras->data;
        priv->receive_ra_id = g_timeout_add_seconds(ra->when, receive_ra, self);
    }

    return G_SOURCE_REMOVE;
}

static void
start(NMNDisc *ndisc)
{
    NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE(ndisc);
    FakeRa *            ra;

    /* Queue up the first fake RA */
    g_assert(priv->ras);
    ra = priv->ras->data;

    g_assert(!priv->receive_ra_id);
    priv->receive_ra_id = g_timeout_add_seconds(ra->when, receive_ra, ndisc);
}

static void
stop(NMNDisc *ndisc)
{
    NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE(ndisc);

    nm_clear_g_source(&priv->receive_ra_id);
}

void
nm_fake_ndisc_emit_new_ras(NMFakeNDisc *self)
{
    if (!NM_FAKE_NDISC_GET_PRIVATE(self)->receive_ra_id)
        start(NM_NDISC(self));
}

/*****************************************************************************/

static void
nm_fake_ndisc_init(NMFakeNDisc *fake_ndisc)
{}

NMNDisc *
nm_fake_ndisc_new(int ifindex, const char *ifname)
{
    return g_object_new(NM_TYPE_FAKE_NDISC,
                        NM_NDISC_IFINDEX,
                        ifindex,
                        NM_NDISC_IFNAME,
                        ifname,
                        NM_NDISC_NODE_TYPE,
                        (int) NM_NDISC_NODE_TYPE_HOST,
                        NM_NDISC_STABLE_TYPE,
                        (int) NM_UTILS_STABLE_TYPE_UUID,
                        NM_NDISC_NETWORK_ID,
                        "fake",
                        NM_NDISC_MAX_ADDRESSES,
                        NM_NDISC_MAX_ADDRESSES_DEFAULT,
                        NM_NDISC_ROUTER_SOLICITATIONS,
                        NM_NDISC_ROUTER_SOLICITATIONS_DEFAULT,
                        NM_NDISC_ROUTER_SOLICITATION_INTERVAL,
                        NM_NDISC_RFC4861_RTR_SOLICITATION_INTERVAL,
                        NM_NDISC_RA_TIMEOUT,
                        30u,
                        NULL);
}

static void
dispose(GObject *object)
{
    NMFakeNDiscPrivate *priv = NM_FAKE_NDISC_GET_PRIVATE(object);

    nm_clear_g_source(&priv->receive_ra_id);

    g_slist_free_full(priv->ras, fake_ra_free);
    priv->ras = NULL;

    G_OBJECT_CLASS(nm_fake_ndisc_parent_class)->dispose(object);
}

static void
nm_fake_ndisc_class_init(NMFakeNDiscClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);
    NMNDiscClass *ndisc_class  = NM_NDISC_CLASS(klass);

    object_class->dispose = dispose;

    ndisc_class->start   = start;
    ndisc_class->stop    = stop;
    ndisc_class->send_rs = send_rs;

    signals[RS_SENT] = g_signal_new(NM_FAKE_NDISC_RS_SENT,
                                    G_OBJECT_CLASS_TYPE(klass),
                                    G_SIGNAL_RUN_FIRST,
                                    0,
                                    NULL,
                                    NULL,
                                    NULL,
                                    G_TYPE_NONE,
                                    0);
}
