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

#include "nm-default.h"

#include "nm-rdisc.h"

#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#include "nm-setting-ip6-config.h"

#include "nm-rdisc-private.h"
#include "nm-utils.h"
#include "nm-platform.h"
#include "nmp-netns.h"

#define _NMLOG_PREFIX_NAME                "rdisc"

/*****************************************************************************/

struct _NMRDiscPrivate {
	/* this *must* be the first field. */
	NMRDiscDataInternal rdata;

	gint32 solicitations_left;
	guint send_rs_id;
	gint32 last_rs;
	guint ra_timeout_id;  /* first RA timeout */
	guint timeout_id;   /* prefix/dns/etc lifetime timeout */
	char *last_send_rs_error;
	NMUtilsIPv6IfaceId iid;

	/* immutable values: */
	int ifindex;
	char *ifname;
	char *network_id;
	NMSettingIP6ConfigAddrGenMode addr_gen_mode;
	NMUtilsStableType stable_type;
	gint32 max_addresses;
	gint32 router_solicitations;
	gint32 router_solicitation_interval;

	NMPlatform *platform;
	NMPNetns *netns;
};

typedef struct _NMRDiscPrivate NMRDiscPrivate;

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PLATFORM,
	PROP_IFINDEX,
	PROP_IFNAME,
	PROP_STABLE_TYPE,
	PROP_NETWORK_ID,
	PROP_ADDR_GEN_MODE,
	PROP_MAX_ADDRESSES,
	PROP_ROUTER_SOLICITATIONS,
	PROP_ROUTER_SOLICITATION_INTERVAL,
);

enum {
	CONFIG_CHANGED,
	RA_TIMEOUT,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (NMRDisc, nm_rdisc, G_TYPE_OBJECT)

#define NM_RDISC_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMRDisc, NM_IS_RDISC)

/*****************************************************************************/

static void _config_changed_log (NMRDisc *rdisc, NMRDiscConfigMap changed);

/*****************************************************************************/

NMPNetns *
nm_rdisc_netns_get (NMRDisc *self)
{
	g_return_val_if_fail (NM_IS_RDISC (self), NULL);

	return NM_RDISC_GET_PRIVATE (self)->netns;
}

gboolean
nm_rdisc_netns_push (NMRDisc *self, NMPNetns **netns)
{
	NMRDiscPrivate *priv;

	g_return_val_if_fail (NM_IS_RDISC (self), FALSE);

	priv = NM_RDISC_GET_PRIVATE (self);
	if (   priv->netns
	    && !nmp_netns_push (priv->netns)) {
		NM_SET_OUT (netns, NULL);
		return FALSE;
	}

	NM_SET_OUT (netns, priv->netns);
	return TRUE;
}

/*****************************************************************************/

int
nm_rdisc_get_ifindex (NMRDisc *self)
{
	g_return_val_if_fail (NM_IS_RDISC (self), 0);

	return NM_RDISC_GET_PRIVATE (self)->ifindex;
}

const char *
nm_rdisc_get_ifname (NMRDisc *self)
{
	g_return_val_if_fail (NM_IS_RDISC (self), NULL);

	return NM_RDISC_GET_PRIVATE (self)->ifname;
}

/*****************************************************************************/

static const NMRDiscData *
_data_complete (NMRDiscDataInternal *data)
{
#define _SET(data, field) \
	G_STMT_START { \
		if ((data->public.field##_n = data->field->len) > 0) \
			data->public.field = (gpointer) data->field->data; \
		else \
			data->public.field = NULL; \
	} G_STMT_END
	_SET (data, gateways);
	_SET (data, addresses);
	_SET (data, routes);
	_SET (data, dns_servers);
	_SET (data, dns_domains);
#undef _SET
	return &data->public;
}

static void
_emit_config_change (NMRDisc *self, NMRDiscConfigMap changed)
{
	_config_changed_log (self, changed);
	g_signal_emit (self, signals[CONFIG_CHANGED], 0,
	               _data_complete (&NM_RDISC_GET_PRIVATE (self)->rdata),
	               (guint) changed);
}

/*****************************************************************************/

gboolean
nm_rdisc_add_gateway (NMRDisc *rdisc, const NMRDiscGateway *new)
{
	NMRDiscDataInternal *rdata = &NM_RDISC_GET_PRIVATE(rdisc)->rdata;
	int i, insert_idx = -1;

	for (i = 0; i < rdata->gateways->len; i++) {
		NMRDiscGateway *item = &g_array_index (rdata->gateways, NMRDiscGateway, i);

		if (IN6_ARE_ADDR_EQUAL (&item->address, &new->address)) {
			if (new->lifetime == 0) {
				g_array_remove_index (rdata->gateways, i--);
				return TRUE;
			}

			if (item->preference != new->preference) {
				g_array_remove_index (rdata->gateways, i--);
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
		g_array_insert_val (rdata->gateways, MAX (insert_idx, 0), *new);
	return !!new->lifetime;
}

/**
 * complete_address:
 * @rdisc: the #NMRDisc
 * @addr: the #NMRDiscAddress
 *
 * Adds the host part to the address that has network part set.
 * If the address already has a host part, add a different host part
 * if possible (this is useful in case DAD failed).
 *
 * Can fail if a different address can not be generated (DAD failure
 * for an EUI-64 address or DAD counter overflow).
 *
 * Returns: %TRUE if the address could be completed, %FALSE otherwise.
 **/
static gboolean
complete_address (NMRDisc *rdisc, NMRDiscAddress *addr)
{
	NMRDiscPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (NM_IS_RDISC (rdisc), FALSE);

	priv = NM_RDISC_GET_PRIVATE (rdisc);
	if (priv->addr_gen_mode == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY) {
		if (!nm_utils_ipv6_addr_set_stable_privacy (priv->stable_type,
		                                            &addr->address,
		                                            priv->ifname,
		                                            priv->network_id,
		                                            addr->dad_counter++,
		                                            &error)) {
			_LOGW ("complete-address: failed to generate an stable-privacy address: %s",
			       error->message);
			g_clear_error (&error);
			return FALSE;
		}
		_LOGD ("complete-address: using an stable-privacy address");
		return TRUE;
	}

	if (!priv->iid.id) {
		_LOGW ("complete-address: can't generate an EUI-64 address: no interface identifier");
		return FALSE;
	}

	if (addr->address.s6_addr32[2] == 0x0 && addr->address.s6_addr32[3] == 0x0) {
		_LOGD ("complete-address: adding an EUI-64 address");
		nm_utils_ipv6_addr_set_interface_identifier (&addr->address, priv->iid);
		return TRUE;
	}

	_LOGW ("complete-address: can't generate a new EUI-64 address");
	return FALSE;
}

gboolean
nm_rdisc_complete_and_add_address (NMRDisc *rdisc, NMRDiscAddress *new)
{
	NMRDiscPrivate *priv;
	NMRDiscDataInternal *rdata;
	int i;

	if (!complete_address (rdisc, new))
		return FALSE;

	priv = NM_RDISC_GET_PRIVATE (rdisc);
	rdata = &priv->rdata;

	for (i = 0; i < rdata->addresses->len; i++) {
		NMRDiscAddress *item = &g_array_index (rdata->addresses, NMRDiscAddress, i);

		if (IN6_ARE_ADDR_EQUAL (&item->address, &new->address)) {
			gboolean changed;

			if (new->lifetime == 0) {
				g_array_remove_index (rdata->addresses, i--);
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
	if (priv->max_addresses && rdata->addresses->len >= priv->max_addresses)
		return FALSE;

	if (new->lifetime)
		g_array_insert_val (rdata->addresses, i, *new);
	return !!new->lifetime;
}

gboolean
nm_rdisc_add_route (NMRDisc *rdisc, const NMRDiscRoute *new)
{
	NMRDiscPrivate *priv;
	NMRDiscDataInternal *rdata;
	int i, insert_idx = -1;

	if (new->plen == 0 || new->plen > 128) {
		/* Only expect non-default routes.  The router has no idea what the
		 * local configuration or user preferences are, so sending routes
		 * with a prefix length of 0 must be ignored by NMRDisc.
		 *
		 * Also, upper layers also don't expect that NMRDisc exposes routes
		 * with a plen or zero or larger then 128.
		 */
		g_return_val_if_reached (FALSE);
	}

	priv = NM_RDISC_GET_PRIVATE (rdisc);
	rdata = &priv->rdata;

	for (i = 0; i < rdata->routes->len; i++) {
		NMRDiscRoute *item = &g_array_index (rdata->routes, NMRDiscRoute, i);

		if (IN6_ARE_ADDR_EQUAL (&item->network, &new->network) && item->plen == new->plen) {
			if (new->lifetime == 0) {
				g_array_remove_index (rdata->routes, i--);
				return TRUE;
			}

			if (item->preference != new->preference) {
				g_array_remove_index (rdata->routes, i--);
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
		g_array_insert_val (rdata->routes, CLAMP (insert_idx, 0, G_MAXINT), *new);
	return !!new->lifetime;
}

gboolean
nm_rdisc_add_dns_server (NMRDisc *rdisc, const NMRDiscDNSServer *new)
{
	NMRDiscPrivate *priv;
	NMRDiscDataInternal *rdata;
	int i;

	priv = NM_RDISC_GET_PRIVATE (rdisc);
	rdata = &priv->rdata;

	for (i = 0; i < rdata->dns_servers->len; i++) {
		NMRDiscDNSServer *item = &g_array_index (rdata->dns_servers, NMRDiscDNSServer, i);

		if (IN6_ARE_ADDR_EQUAL (&item->address, &new->address)) {
			if (new->lifetime == 0) {
				g_array_remove_index (rdata->dns_servers, i);
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
		g_array_insert_val (rdata->dns_servers, i, *new);
	return !!new->lifetime;
}

/* Copies new->domain if 'new' is added to the dns_domains list */
gboolean
nm_rdisc_add_dns_domain (NMRDisc *rdisc, const NMRDiscDNSDomain *new)
{
	NMRDiscPrivate *priv;
	NMRDiscDataInternal *rdata;
	NMRDiscDNSDomain *item;
	int i;

	priv = NM_RDISC_GET_PRIVATE (rdisc);
	rdata = &priv->rdata;

	for (i = 0; i < rdata->dns_domains->len; i++) {
		item = &g_array_index (rdata->dns_domains, NMRDiscDNSDomain, i);

		if (!g_strcmp0 (item->domain, new->domain)) {
			gboolean changed;

			if (new->lifetime == 0) {
				g_array_remove_index (rdata->dns_domains, i);
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
		g_array_insert_val (rdata->dns_domains, i, *new);
		item = &g_array_index (rdata->dns_domains, NMRDiscDNSDomain, i);
		item->domain = g_strdup (new->domain);
	}
	return !!new->lifetime;
}

/*****************************************************************************/

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
 * In case the stable privacy addressing is used %FALSE is returned and
 * addresses are left untouched.
 *
 * Returns: %TRUE if addresses need to be regenerated, %FALSE otherwise.
 **/
gboolean
nm_rdisc_set_iid (NMRDisc *rdisc, const NMUtilsIPv6IfaceId iid)
{
	NMRDiscPrivate *priv;
	NMRDiscDataInternal *rdata;

	g_return_val_if_fail (NM_IS_RDISC (rdisc), FALSE);

	priv = NM_RDISC_GET_PRIVATE (rdisc);
	rdata = &priv->rdata;

	if (priv->iid.id != iid.id) {
		priv->iid = iid;

		if (priv->addr_gen_mode == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY)
			return FALSE;

		if (rdata->addresses->len) {
			_LOGD ("IPv6 interface identifier changed, flushing addresses");
			g_array_remove_range (rdata->addresses, 0, rdata->addresses->len);
			_emit_config_change (rdisc, NM_RDISC_CONFIG_ADDRESSES);
		}
		return TRUE;
	}

	return FALSE;
}

static gboolean
send_rs_timeout (NMRDisc *rdisc)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	NMRDiscClass *klass = NM_RDISC_GET_CLASS (rdisc);
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);
	GError *error = NULL;

	priv->send_rs_id = 0;

	if (!nm_rdisc_netns_push (rdisc, &netns))
		return G_SOURCE_REMOVE;

	if (klass->send_rs (rdisc, &error)) {
		_LOGD ("router solicitation sent");
		priv->solicitations_left--;
		g_clear_pointer (&priv->last_send_rs_error, g_free);
	} else {
		gboolean different_message;

		different_message = g_strcmp0 (priv->last_send_rs_error, error->message) != 0;
		_NMLOG (different_message ? LOGL_WARN : LOGL_DEBUG,
		        "failure sending router solicitation: %s", error->message);
		if (different_message) {
			g_clear_pointer (&priv->last_send_rs_error, g_free);
			priv->last_send_rs_error = g_strdup (error->message);
		}
		g_clear_error (&error);
	}

	priv->last_rs = nm_utils_get_monotonic_timestamp_s ();
	if (priv->solicitations_left > 0) {
		_LOGD ("scheduling router solicitation retry in %d seconds.",
		       (int) priv->router_solicitation_interval);
		priv->send_rs_id = g_timeout_add_seconds (priv->router_solicitation_interval,
		                                          (GSourceFunc) send_rs_timeout, rdisc);
	} else {
		_LOGD ("did not receive a router advertisement after %d solicitations.",
		       (int) priv->router_solicitations);
	}

	return G_SOURCE_REMOVE;
}

static void
solicit (NMRDisc *rdisc)
{
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);
	gint64 next, now;

	if (priv->send_rs_id)
		return;

	now = nm_utils_get_monotonic_timestamp_s ();

	priv->solicitations_left = priv->router_solicitations;

	next = (((gint64) priv->last_rs) + priv->router_solicitation_interval) - now;
	next = CLAMP (next, 0, G_MAXINT32);
	_LOGD ("scheduling explicit router solicitation request in %" G_GINT64_FORMAT " seconds.",
	       next);
	priv->send_rs_id = g_timeout_add_seconds ((guint32) next, (GSourceFunc) send_rs_timeout, rdisc);
}

static gboolean
rdisc_ra_timeout_cb (gpointer user_data)
{
	NMRDisc *rdisc = NM_RDISC (user_data);

	NM_RDISC_GET_PRIVATE (rdisc)->ra_timeout_id = 0;
	g_signal_emit (rdisc, signals[RA_TIMEOUT], 0);
	return G_SOURCE_REMOVE;
}

void
nm_rdisc_start (NMRDisc *rdisc)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);
	NMRDiscClass *klass = NM_RDISC_GET_CLASS (rdisc);
	gint64 ra_wait_secs;

	g_assert (klass->start);

	_LOGD ("starting router discovery: %d", priv->ifindex);

	if (!nm_rdisc_netns_push (rdisc, &netns))
		return;

	nm_clear_g_source (&priv->ra_timeout_id);
	ra_wait_secs = (((gint64) priv->router_solicitations) * priv->router_solicitation_interval) + 1;
	ra_wait_secs = CLAMP (ra_wait_secs, 30, 120);
	priv->ra_timeout_id = g_timeout_add_seconds (ra_wait_secs, rdisc_ra_timeout_cb, rdisc);
	_LOGD ("scheduling RA timeout in %d seconds", (int) ra_wait_secs);

	if (klass->start)
		klass->start (rdisc);

	solicit (rdisc);
}

void
nm_rdisc_dad_failed (NMRDisc *rdisc, struct in6_addr *address)
{
	NMRDiscDataInternal *rdata;
	int i;
	gboolean changed = FALSE;

	rdata = &NM_RDISC_GET_PRIVATE (rdisc)->rdata;

	for (i = 0; i < rdata->addresses->len; i++) {
		NMRDiscAddress *item = &g_array_index (rdata->addresses, NMRDiscAddress, i);

		if (!IN6_ARE_ADDR_EQUAL (&item->address, address))
			continue;

		_LOGD ("DAD failed for discovered address %s", nm_utils_inet6_ntop (address, NULL));
		if (!complete_address (rdisc, item))
			g_array_remove_index (rdata->addresses, i--);
		changed = TRUE;
	}

	if (changed)
		_emit_config_change (rdisc, NM_RDISC_CONFIG_ADDRESSES);
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
_config_changed_log (NMRDisc *rdisc, NMRDiscConfigMap changed)
{
	NMRDiscPrivate *priv;
	NMRDiscDataInternal *rdata;
	int i;
	char changedstr[CONFIG_MAP_MAX_STR];
	char addrstr[INET6_ADDRSTRLEN];

	if (!_LOGD_ENABLED ())
		return;

	priv = NM_RDISC_GET_PRIVATE (rdisc);
	rdata = &priv->rdata;

	config_map_to_string (changed, changedstr);
	_LOGD ("router discovery configuration changed [%s]:", changedstr);
	_LOGD ("  dhcp-level %s", dhcp_level_to_string (priv->rdata.public.dhcp_level));
	for (i = 0; i < rdata->gateways->len; i++) {
		NMRDiscGateway *gateway = &g_array_index (rdata->gateways, NMRDiscGateway, i);

		inet_ntop (AF_INET6, &gateway->address, addrstr, sizeof (addrstr));
		_LOGD ("  gateway %s pref %d exp %u", addrstr, gateway->preference, expiry (gateway));
	}
	for (i = 0; i < rdata->addresses->len; i++) {
		NMRDiscAddress *address = &g_array_index (rdata->addresses, NMRDiscAddress, i);

		inet_ntop (AF_INET6, &address->address, addrstr, sizeof (addrstr));
		_LOGD ("  address %s exp %u", addrstr, expiry (address));
	}
	for (i = 0; i < rdata->routes->len; i++) {
		NMRDiscRoute *route = &g_array_index (rdata->routes, NMRDiscRoute, i);

		inet_ntop (AF_INET6, &route->network, addrstr, sizeof (addrstr));
		_LOGD ("  route %s/%d via %s pref %d exp %u", addrstr, (int) route->plen,
		       nm_utils_inet6_ntop (&route->gateway, NULL), route->preference,
		       expiry (route));
	}
	for (i = 0; i < rdata->dns_servers->len; i++) {
		NMRDiscDNSServer *dns_server = &g_array_index (rdata->dns_servers, NMRDiscDNSServer, i);

		inet_ntop (AF_INET6, &dns_server->address, addrstr, sizeof (addrstr));
		_LOGD ("  dns_server %s exp %u", addrstr, expiry (dns_server));
	}
	for (i = 0; i < rdata->dns_domains->len; i++) {
		NMRDiscDNSDomain *dns_domain = &g_array_index (rdata->dns_domains, NMRDiscDNSDomain, i);

		_LOGD ("  dns_domain %s exp %u", dns_domain->domain, expiry (dns_domain));
	}
}

static void
clean_gateways (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap *changed, guint32 *nextevent)
{
	NMRDiscDataInternal *rdata;
	guint i;

	rdata = &NM_RDISC_GET_PRIVATE (rdisc)->rdata;

	for (i = 0; i < rdata->gateways->len; i++) {
		NMRDiscGateway *item = &g_array_index (rdata->gateways, NMRDiscGateway, i);
		guint64 expiry = (guint64) item->timestamp + item->lifetime;

		if (item->lifetime == G_MAXUINT32)
			continue;

		if (now >= expiry) {
			g_array_remove_index (rdata->gateways, i--);
			*changed |= NM_RDISC_CONFIG_GATEWAYS;
		} else if (*nextevent > expiry)
			*nextevent = expiry;
	}
}

static void
clean_addresses (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap *changed, guint32 *nextevent)
{
	NMRDiscDataInternal *rdata;
	guint i;

	rdata = &NM_RDISC_GET_PRIVATE (rdisc)->rdata;

	for (i = 0; i < rdata->addresses->len; i++) {
		NMRDiscAddress *item = &g_array_index (rdata->addresses, NMRDiscAddress, i);
		guint64 expiry = (guint64) item->timestamp + item->lifetime;

		if (item->lifetime == G_MAXUINT32)
			continue;

		if (now >= expiry) {
			g_array_remove_index (rdata->addresses, i--);
			*changed |= NM_RDISC_CONFIG_ADDRESSES;
		} else if (*nextevent > expiry)
			*nextevent = expiry;
	}
}

static void
clean_routes (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap *changed, guint32 *nextevent)
{
	NMRDiscDataInternal *rdata;
	guint i;

	rdata = &NM_RDISC_GET_PRIVATE (rdisc)->rdata;

	for (i = 0; i < rdata->routes->len; i++) {
		NMRDiscRoute *item = &g_array_index (rdata->routes, NMRDiscRoute, i);
		guint64 expiry = (guint64) item->timestamp + item->lifetime;

		if (item->lifetime == G_MAXUINT32)
			continue;

		if (now >= expiry) {
			g_array_remove_index (rdata->routes, i--);
			*changed |= NM_RDISC_CONFIG_ROUTES;
		} else if (*nextevent > expiry)
			*nextevent = expiry;
	}
}

static void
clean_dns_servers (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap *changed, guint32 *nextevent)
{
	NMRDiscDataInternal *rdata;
	guint i;

	rdata = &NM_RDISC_GET_PRIVATE (rdisc)->rdata;

	for (i = 0; i < rdata->dns_servers->len; i++) {
		NMRDiscDNSServer *item = &g_array_index (rdata->dns_servers, NMRDiscDNSServer, i);
		guint64 expiry = (guint64) item->timestamp + item->lifetime;
		guint64 refresh = (guint64) item->timestamp + item->lifetime / 2;

		if (item->lifetime == G_MAXUINT32)
			continue;

		if (now >= expiry) {
			g_array_remove_index (rdata->dns_servers, i--);
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
	NMRDiscDataInternal *rdata;
	guint i;

	rdata = &NM_RDISC_GET_PRIVATE (rdisc)->rdata;

	for (i = 0; i < rdata->dns_domains->len; i++) {
		NMRDiscDNSDomain *item = &g_array_index (rdata->dns_domains, NMRDiscDNSDomain, i);
		guint64 expiry = (guint64) item->timestamp + item->lifetime;
		guint64 refresh = (guint64) item->timestamp + item->lifetime / 2;

		if (item->lifetime == G_MAXUINT32)
			continue;

		if (now >= expiry) {
			g_array_remove_index (rdata->dns_domains, i--);
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

	nm_clear_g_source (&priv->timeout_id);

	clean_gateways (rdisc, now, &changed, &nextevent);
	clean_addresses (rdisc, now, &changed, &nextevent);
	clean_routes (rdisc, now, &changed, &nextevent);
	clean_dns_servers (rdisc, now, &changed, &nextevent);
	clean_dns_domains (rdisc, now, &changed, &nextevent);

	if (changed)
		_emit_config_change (rdisc, changed);

	if (nextevent != never) {
		g_return_if_fail (nextevent > now);
		_LOGD ("scheduling next now/lifetime check: %u seconds",
		       nextevent - now);
		priv->timeout_id = g_timeout_add_seconds (nextevent - now, timeout_cb, rdisc);
	}
}

static gboolean
timeout_cb (gpointer user_data)
{
	NMRDisc *self = user_data;

	NM_RDISC_GET_PRIVATE (self)->timeout_id = 0;
	check_timestamps (self, nm_utils_get_monotonic_timestamp_s (), 0);
	return G_SOURCE_REMOVE;
}

void
nm_rdisc_ra_received (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap changed)
{
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);

	nm_clear_g_source (&priv->ra_timeout_id);
	nm_clear_g_source (&priv->send_rs_id);
	g_clear_pointer (&priv->last_send_rs_error, g_free);
	check_timestamps (rdisc, now, changed);
}

/*****************************************************************************/

static void
dns_domain_free (gpointer data)
{
	g_free (((NMRDiscDNSDomain *)(data))->domain);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMRDisc *self = NM_RDISC (object);
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_PLATFORM:
		/* construct-only */
		priv->platform = g_value_get_object (value) ? : NM_PLATFORM_GET;
		if (!priv->platform)
			g_return_if_reached ();

		g_object_ref (priv->platform);

		priv->netns = nm_platform_netns_get (priv->platform);
		if (priv->netns)
			g_object_ref (priv->netns);

		g_return_if_fail (!priv->netns || priv->netns == nmp_netns_get_current ());
		break;
	case PROP_IFINDEX:
		/* construct-only */
		priv->ifindex = g_value_get_int (value);
		g_return_if_fail (priv->ifindex > 0);
		break;
	case PROP_IFNAME:
		/* construct-only */
		priv->ifname = g_value_dup_string (value);
		g_return_if_fail (priv->ifname && priv->ifname[0]);
		break;
	case PROP_STABLE_TYPE:
		/* construct-only */
		priv->stable_type = g_value_get_int (value);
		break;
	case PROP_NETWORK_ID:
		/* construct-only */
		priv->network_id = g_value_dup_string (value);
		break;
	case PROP_ADDR_GEN_MODE:
		/* construct-only */
		priv->addr_gen_mode = g_value_get_int (value);
		break;
	case PROP_MAX_ADDRESSES:
		/* construct-only */
		priv->max_addresses = g_value_get_int (value);
		break;
	case PROP_ROUTER_SOLICITATIONS:
		/* construct-only */
		priv->router_solicitations = g_value_get_int (value);
		break;
	case PROP_ROUTER_SOLICITATION_INTERVAL:
		/* construct-only */
		priv->router_solicitation_interval = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_rdisc_init (NMRDisc *rdisc)
{
	NMRDiscPrivate *priv;
	NMRDiscDataInternal *rdata;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (rdisc, NM_TYPE_RDISC, NMRDiscPrivate);
	rdisc->_priv = priv;

	rdata = &priv->rdata;

	rdata->gateways = g_array_new (FALSE, FALSE, sizeof (NMRDiscGateway));
	rdata->addresses = g_array_new (FALSE, FALSE, sizeof (NMRDiscAddress));
	rdata->routes = g_array_new (FALSE, FALSE, sizeof (NMRDiscRoute));
	rdata->dns_servers = g_array_new (FALSE, FALSE, sizeof (NMRDiscDNSServer));
	rdata->dns_domains = g_array_new (FALSE, FALSE, sizeof (NMRDiscDNSDomain));
	g_array_set_clear_func (rdata->dns_domains, dns_domain_free);
	priv->rdata.public.hop_limit = 64;

	/* Start at very low number so that last_rs - router_solicitation_interval
	 * is much lower than nm_utils_get_monotonic_timestamp_s() at startup.
	 */
	priv->last_rs = G_MININT32;
}

static void
dispose (GObject *object)
{
	NMRDisc *rdisc = NM_RDISC (object);
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);

	nm_clear_g_source (&priv->ra_timeout_id);
	nm_clear_g_source (&priv->send_rs_id);
	g_clear_pointer (&priv->last_send_rs_error, g_free);

	nm_clear_g_source (&priv->timeout_id);

	G_OBJECT_CLASS (nm_rdisc_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMRDisc *rdisc = NM_RDISC (object);
	NMRDiscPrivate *priv = NM_RDISC_GET_PRIVATE (rdisc);
	NMRDiscDataInternal *rdata = &priv->rdata;

	g_free (priv->ifname);
	g_free (priv->network_id);

	g_array_unref (rdata->gateways);
	g_array_unref (rdata->addresses);
	g_array_unref (rdata->routes);
	g_array_unref (rdata->dns_servers);
	g_array_unref (rdata->dns_domains);

	g_clear_object (&priv->netns);
	g_clear_object (&priv->platform);

	G_OBJECT_CLASS (nm_rdisc_parent_class)->finalize (object);
}

static void
nm_rdisc_class_init (NMRDiscClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMRDiscPrivate));

	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	obj_properties[PROP_PLATFORM] =
	    g_param_spec_object (NM_RDISC_PLATFORM, "", "",
	                         NM_TYPE_PLATFORM,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IFINDEX] =
	    g_param_spec_int (NM_RDISC_IFINDEX, "", "",
	                      0, G_MAXINT, 0,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IFNAME] =
	    g_param_spec_string (NM_RDISC_IFNAME, "", "",
	                         NULL,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_STABLE_TYPE] =
	    g_param_spec_int (NM_RDISC_STABLE_TYPE, "", "",
	                      NM_UTILS_STABLE_TYPE_UUID, NM_UTILS_STABLE_TYPE_STABLE_ID, NM_UTILS_STABLE_TYPE_UUID,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_NETWORK_ID] =
	    g_param_spec_string (NM_RDISC_NETWORK_ID, "", "",
	                         NULL,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ADDR_GEN_MODE] =
	    g_param_spec_int (NM_RDISC_ADDR_GEN_MODE, "", "",
	                      NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_MAX_ADDRESSES] =
	    g_param_spec_int (NM_RDISC_MAX_ADDRESSES, "", "",
	                      0, G_MAXINT32, NM_RDISC_MAX_ADDRESSES_DEFAULT,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ROUTER_SOLICITATIONS] =
	    g_param_spec_int (NM_RDISC_ROUTER_SOLICITATIONS, "", "",
	                      1, G_MAXINT32, NM_RDISC_ROUTER_SOLICITATIONS_DEFAULT,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ROUTER_SOLICITATION_INTERVAL] =
	    g_param_spec_int (NM_RDISC_ROUTER_SOLICITATION_INTERVAL, "", "",
	                      1, G_MAXINT32, NM_RDISC_ROUTER_SOLICITATION_INTERVAL_DEFAULT,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[CONFIG_CHANGED] =
	    g_signal_new (NM_RDISC_CONFIG_CHANGED,
	                  G_OBJECT_CLASS_TYPE (klass),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_POINTER, G_TYPE_UINT);
	signals[RA_TIMEOUT] =
	    g_signal_new (NM_RDISC_RA_TIMEOUT,
	                  G_OBJECT_CLASS_TYPE (klass),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);
}
