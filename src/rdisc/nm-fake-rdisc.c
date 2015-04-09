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

#include "config.h"

#include <string.h>
#include <arpa/inet.h>

#include "nm-fake-rdisc.h"
#include "nm-rdisc-private.h"

#include "nm-logging.h"

#define debug(...) nm_log_dbg (LOGD_IP6, __VA_ARGS__)
#define warning(...) nm_log_warn (LOGD_IP6, __VA_ARGS__)
#define error(...) nm_log_err (LOGD_IP6, __VA_ARGS__)

typedef struct {
	guint ra_received_id;
} NMFakeRDiscPrivate;

#define NM_FAKE_RDISC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_FAKE_RDISC, NMFakeRDiscPrivate))

G_DEFINE_TYPE (NMFakeRDisc, nm_fake_rdisc, NM_TYPE_RDISC)

/******************************************************************/

static gboolean
ra_received (gpointer user_data)
{
	NMFakeRDisc *self = NM_FAKE_RDISC (user_data);
	NMRDisc *rdisc = NM_RDISC (self);
	NMRDiscConfigMap changed = 0;
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	NMRDiscGateway gateway;
	NMRDiscAddress address;
	NMRDiscRoute route;
	NMRDiscDNSServer dns_server;
	NMRDiscDNSDomain dns_domain;

	NM_FAKE_RDISC_GET_PRIVATE (self)->ra_received_id = 0;

	debug ("(%s): received router advertisement at %u", NM_RDISC (self)->ifname, now);

	rdisc->dhcp_level = NM_RDISC_DHCP_LEVEL_NONE;

	memset (&gateway, 0, sizeof (gateway));
	inet_pton (AF_INET6, "fe80::1", &gateway.address);
	if (nm_rdisc_add_gateway (rdisc, &gateway))
		changed |= NM_RDISC_CONFIG_GATEWAYS;
	inet_pton (AF_INET6, "fe80::2", &gateway.address);
	if (nm_rdisc_add_gateway (rdisc, &gateway))
		changed |= NM_RDISC_CONFIG_GATEWAYS;
	inet_pton (AF_INET6, "fe80::3", &gateway.address);
	if (nm_rdisc_add_gateway (rdisc, &gateway))
		changed |= NM_RDISC_CONFIG_GATEWAYS;

	memset (&address, 0, sizeof (address));
	inet_pton (AF_INET6, "2001:db8:a:a::1", &address.address);
	if (nm_rdisc_add_address (rdisc, &address))
		changed |= NM_RDISC_CONFIG_ADDRESSES;
	inet_pton (AF_INET6, "2001:db8:a:a::2", &address.address);
	if (nm_rdisc_add_address (rdisc, &address))
		changed |= NM_RDISC_CONFIG_ADDRESSES;
	inet_pton (AF_INET6, "2001:db8:f:f::1", &address.address);
	if (nm_rdisc_add_address (rdisc, &address))
		changed |= NM_RDISC_CONFIG_ADDRESSES;

	memset (&route, 0, sizeof (route));
	route.plen = 64;
	inet_pton (AF_INET6, "2001:db8:a:a::", &route.network);
	if (nm_rdisc_add_route (rdisc, &route))
		changed |= NM_RDISC_CONFIG_ROUTES;
	inet_pton (AF_INET6, "2001:db8:b:b::", &route.network);
	if (nm_rdisc_add_route (rdisc, &route))
		changed |= NM_RDISC_CONFIG_ROUTES;

	memset (&dns_server, 0, sizeof (dns_server));
	inet_pton (AF_INET6, "2001:db8:c:c::1", &dns_server.address);
	if (nm_rdisc_add_dns_server (rdisc, &dns_server))
		changed |= NM_RDISC_CONFIG_DNS_SERVERS;
	inet_pton (AF_INET6, "2001:db8:c:c::2", &dns_server.address);
	if (nm_rdisc_add_dns_server (rdisc, &dns_server))
		changed |= NM_RDISC_CONFIG_DNS_SERVERS;
	inet_pton (AF_INET6, "2001:db8:c:c::3", &dns_server.address);
	if (nm_rdisc_add_dns_server (rdisc, &dns_server))
		changed |= NM_RDISC_CONFIG_DNS_SERVERS;
	inet_pton (AF_INET6, "2001:db8:c:c::4", &dns_server.address);
	if (nm_rdisc_add_dns_server (rdisc, &dns_server))
		changed |= NM_RDISC_CONFIG_DNS_SERVERS;
	inet_pton (AF_INET6, "2001:db8:c:c::5", &dns_server.address);
	if (nm_rdisc_add_dns_server (rdisc, &dns_server))
		changed |= NM_RDISC_CONFIG_DNS_SERVERS;

	memset (&dns_domain, 0, sizeof (dns_domain));
	dns_domain.domain = g_strdup ("example.net");
	if (nm_rdisc_add_dns_domain (rdisc, &dns_domain))
		changed |= NM_RDISC_CONFIG_DNS_DOMAINS;
	dns_domain.domain = g_strdup ("example.com");
	if (nm_rdisc_add_dns_domain (rdisc, &dns_domain))
		changed |= NM_RDISC_CONFIG_DNS_DOMAINS;
	dns_domain.domain = g_strdup ("example.org");
	if (nm_rdisc_add_dns_domain (rdisc, &dns_domain))
		changed |= NM_RDISC_CONFIG_DNS_DOMAINS;

	nm_rdisc_ra_received (NM_RDISC (self), now, changed);
	return G_SOURCE_REMOVE;
}

static gboolean
send_rs (NMRDisc *rdisc)
{
	NMFakeRDiscPrivate *priv = NM_FAKE_RDISC_GET_PRIVATE (rdisc);

	if (priv->ra_received_id)
		g_source_remove (priv->ra_received_id);
	priv->ra_received_id = g_timeout_add_seconds (3, ra_received, rdisc);

	return TRUE;
}

static void
start (NMRDisc *rdisc)
{
	nm_rdisc_solicit (rdisc);
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

	if (priv->ra_received_id) {
		g_source_remove (priv->ra_received_id);
		priv->ra_received_id = 0;
	}

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
}
