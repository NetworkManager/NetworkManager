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

#include <string.h>
#include <arpa/inet.h>

#include "nm-fake-rdisc.h"

#include "nm-logging.h"

#define debug(...) nm_log_dbg (LOGD_IP6, __VA_ARGS__)
#define warning(...) nm_log_warn (LOGD_IP6, __VA_ARGS__)
#define error(...) nm_log_err (LOGD_IP6, __VA_ARGS__)

#define NM_FAKE_RDISC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_FAKE_RDISC, NMFakeRDiscPrivate))

G_DEFINE_TYPE (NMFakeRDisc, nm_fake_rdisc, NM_TYPE_RDISC)

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
delayed_start (NMRDisc *rdisc)
{
	int changed =
		NM_RDISC_CONFIG_GATEWAYS | NM_RDISC_CONFIG_ADDRESSES | NM_RDISC_CONFIG_ROUTES |
		NM_RDISC_CONFIG_DNS_SERVERS | NM_RDISC_CONFIG_DNS_DOMAINS;
	debug ("%d", rdisc->dhcp_level);

	g_signal_emit_by_name (
			rdisc, NM_RDISC_CONFIG_CHANGED, changed);
}

static void
start (NMRDisc *rdisc)
{
	g_idle_add ((GSourceFunc) (delayed_start), rdisc);
}

/******************************************************************/

static void
nm_fake_rdisc_init (NMFakeRDisc *fake_rdisc)
{
	NMRDisc *rdisc = NM_RDISC (fake_rdisc);
	NMRDiscGateway gateway;
	NMRDiscAddress address;
	NMRDiscRoute route;
	NMRDiscDNSServer dns_server;
	NMRDiscDNSDomain dns_domain;

	rdisc->dhcp_level = NM_RDISC_DHCP_LEVEL_NONE;

	memset (&gateway, 0, sizeof (gateway));
	inet_pton (AF_INET6, "fe80::1", &gateway.address);
	g_array_append_val (rdisc->gateways, gateway);
	inet_pton (AF_INET6, "fe80::2", &gateway.address);
	g_array_append_val (rdisc->gateways, gateway);
	inet_pton (AF_INET6, "fe80::3", &gateway.address);
	g_array_append_val (rdisc->gateways, gateway);

	memset (&address, 0, sizeof (address));
	inet_pton (AF_INET6, "2001:db8:a:a::1", &address.address);
	g_array_append_val (rdisc->addresses, address);
	inet_pton (AF_INET6, "2001:db8:a:a::2", &address.address);
	g_array_append_val (rdisc->addresses, address);
	inet_pton (AF_INET6, "2001:db8:f:f::1", &address.address);
	g_array_append_val (rdisc->addresses, address);

	memset (&route, 0, sizeof (route));
	route.plen = 64;
	inet_pton (AF_INET6, "2001:db8:a:a::", &route.network);
	g_array_append_val (rdisc->routes, route);
	inet_pton (AF_INET6, "2001:db8:b:b::", &route.network);
	g_array_append_val (rdisc->routes, route);

	memset (&dns_server, 0, sizeof (dns_server));
	inet_pton (AF_INET6, "2001:db8:c:c::1", &dns_server.address);
	g_array_append_val (rdisc->dns_servers, dns_server);
	inet_pton (AF_INET6, "2001:db8:c:c::2", &dns_server.address);
	g_array_append_val (rdisc->dns_servers, dns_server);
	inet_pton (AF_INET6, "2001:db8:c:c::3", &dns_server.address);
	g_array_append_val (rdisc->dns_servers, dns_server);
	inet_pton (AF_INET6, "2001:db8:c:c::4", &dns_server.address);
	g_array_append_val (rdisc->dns_servers, dns_server);
	inet_pton (AF_INET6, "2001:db8:c:c::5", &dns_server.address);
	g_array_append_val (rdisc->dns_servers, dns_server);

	memset (&dns_domain, 0, sizeof (dns_domain));
	dns_domain.domain = g_strdup ("example.net");
	g_array_append_val (rdisc->dns_domains, dns_domain);
	dns_domain.domain = g_strdup ("example.com");
	g_array_append_val (rdisc->dns_domains, dns_domain);
	dns_domain.domain = g_strdup ("example.org");
	g_array_append_val (rdisc->dns_domains, dns_domain);
}

static void
nm_fake_rdisc_class_init (NMFakeRDiscClass *klass)
{
	NMRDiscClass *rdisc_class = NM_RDISC_CLASS (klass);

	rdisc_class->start = start;
}
