/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-ndisc.c - Perform IPv6 neighbor discovery
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

#include "nm-ndisc.h"

#include <stdlib.h>
#include <arpa/inet.h>

#include "nm-setting-ip6-config.h"

#include "nm-ndisc-private.h"
#include "nm-utils.h"
#include "platform/nm-platform.h"
#include "platform/nmp-netns.h"

#define _NMLOG_PREFIX_NAME                "ndisc"

/*****************************************************************************/

struct _NMNDiscPrivate {
	/* this *must* be the first field. */
	NMNDiscDataInternal rdata;

	union {
		gint32 solicitations_left;
		gint32 announcements_left;
	};
	union {
		guint send_rs_id;
		guint send_ra_id;
	};
	union {
		gint32 last_rs;
		gint32 last_ra;
	};
	guint ra_timeout_id;  /* first RA timeout */
	guint timeout_id;   /* prefix/dns/etc lifetime timeout */
	char *last_error;
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
	NMNDiscNodeType node_type;

	NMPlatform *platform;
	NMPNetns *netns;
};

typedef struct _NMNDiscPrivate NMNDiscPrivate;

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
	PROP_NODE_TYPE,
);

enum {
	CONFIG_RECEIVED,
	RA_TIMEOUT,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (NMNDisc, nm_ndisc, G_TYPE_OBJECT)

#define NM_NDISC_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMNDisc, NM_IS_NDISC)

/*****************************************************************************/

static void _config_changed_log (NMNDisc *ndisc, NMNDiscConfigMap changed);

/*****************************************************************************/

static guint8
_preference_to_priority (NMIcmpv6RouterPref pref)
{
	switch (pref) {
	case NM_ICMPV6_ROUTER_PREF_LOW:
		return 1;
	case NM_ICMPV6_ROUTER_PREF_MEDIUM:
		return 2;
	case NM_ICMPV6_ROUTER_PREF_HIGH:
		return 3;
	case NM_ICMPV6_ROUTER_PREF_INVALID:
		break;
	}
	return 0;
}

/*****************************************************************************/

/* we rely on the fact, that _EXPIRY_INFINITY > any other valid gint64 timestamps. */
#define _EXPIRY_INFINITY G_MAXINT64

static gint64
get_expiry_time (guint32 timestamp, guint32 lifetime)
{
	nm_assert (timestamp > 0);
	nm_assert (timestamp <= G_MAXINT32);

	if (lifetime == NM_NDISC_INFINITY)
		return _EXPIRY_INFINITY;
	return ((gint64) timestamp) + ((gint64) lifetime);
}

#define get_expiry(item) \
	({ \
		typeof (item) _item = (item); \
		nm_assert (_item); \
		get_expiry_time (_item->timestamp, _item->lifetime); \
	})

#define get_expiry_half(item) \
	({ \
		typeof (item) _item = (item); \
		nm_assert (_item); \
		(_item->lifetime == NM_NDISC_INFINITY) \
		  ? _EXPIRY_INFINITY \
		  : get_expiry_time (_item->timestamp, _item->lifetime / 2); \
	})

#define get_expiry_preferred(item) \
	({ \
		typeof (item) _item = (item); \
		nm_assert (_item); \
		get_expiry_time (_item->timestamp, _item->preferred); \
	})

static gboolean
expiry_next (gint32 now_s, gint64 expiry_timestamp, gint32 *nextevent)
{
	gint32 e;

	if (expiry_timestamp == _EXPIRY_INFINITY)
		return TRUE;
	e = MIN (expiry_timestamp, ((gint64) (G_MAXINT32 - 1)));
	if (now_s >= e)
		return FALSE;
	if (nextevent) {
		if (*nextevent > e)
			*nextevent = e;
	}
	return TRUE;
}

static const char *
_get_exp (char *buf, gsize buf_size, gint64 now_ns, gint64 expiry_time)
{
	int l;

	if (expiry_time == _EXPIRY_INFINITY)
		return "permanent";
	l = g_snprintf (buf, buf_size,
	                "%.4f",
	                ((double) ((expiry_time * NM_UTILS_NS_PER_SECOND) - now_ns)) / ((double) NM_UTILS_NS_PER_SECOND));
	nm_assert (l < buf_size);
	return buf;
}

#define get_exp(buf, now_ns, item) \
	_get_exp ((buf), G_N_ELEMENTS (buf), (now_ns), (get_expiry (item)))

/*****************************************************************************/

NMPNetns *
nm_ndisc_netns_get (NMNDisc *self)
{
	g_return_val_if_fail (NM_IS_NDISC (self), NULL);

	return NM_NDISC_GET_PRIVATE (self)->netns;
}

gboolean
nm_ndisc_netns_push (NMNDisc *self, NMPNetns **netns)
{
	NMNDiscPrivate *priv;

	g_return_val_if_fail (NM_IS_NDISC (self), FALSE);

	priv = NM_NDISC_GET_PRIVATE (self);
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
nm_ndisc_get_ifindex (NMNDisc *self)
{
	g_return_val_if_fail (NM_IS_NDISC (self), 0);

	return NM_NDISC_GET_PRIVATE (self)->ifindex;
}

const char *
nm_ndisc_get_ifname (NMNDisc *self)
{
	g_return_val_if_fail (NM_IS_NDISC (self), NULL);

	return NM_NDISC_GET_PRIVATE (self)->ifname;
}

NMNDiscNodeType
nm_ndisc_get_node_type (NMNDisc *self)
{
	g_return_val_if_fail (NM_IS_NDISC (self), NM_NDISC_NODE_TYPE_INVALID);

	return NM_NDISC_GET_PRIVATE (self)->node_type;
}

/*****************************************************************************/

static void
_ASSERT_data_gateways (const NMNDiscDataInternal *data)
{
#if NM_MORE_ASSERTS > 10
	guint i, j;
	const NMNDiscGateway *item_prev = NULL;

	if (!data->gateways->len)
		return;

	for (i = 0; i < data->gateways->len; i++) {
		const NMNDiscGateway *item = &g_array_index (data->gateways, NMNDiscGateway, i);

		nm_assert (!IN6_IS_ADDR_UNSPECIFIED (&item->address));
		nm_assert (item->timestamp > 0 && item->timestamp <= G_MAXINT32);
		for (j = 0; j < i; j++) {
			const NMNDiscGateway *item2 = &g_array_index (data->gateways, NMNDiscGateway, j);

			nm_assert (!IN6_ARE_ADDR_EQUAL (&item->address, &item2->address));
		}

		nm_assert (item->lifetime > 0);
		if (i > 0)
			nm_assert (_preference_to_priority (item_prev->preference) >= _preference_to_priority (item->preference));

		item_prev = item;
	}
#endif
}

/*****************************************************************************/

static const NMNDiscData *
_data_complete (NMNDiscDataInternal *data)
{
	_ASSERT_data_gateways (data);

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

void
nm_ndisc_emit_config_change (NMNDisc *self, NMNDiscConfigMap changed)
{
	_config_changed_log (self, changed);
	g_signal_emit (self, signals[CONFIG_RECEIVED], 0,
	               _data_complete (&NM_NDISC_GET_PRIVATE (self)->rdata),
	               (guint) changed);
}

/*****************************************************************************/

gboolean
nm_ndisc_add_gateway (NMNDisc *ndisc, const NMNDiscGateway *new)
{
	NMNDiscDataInternal *rdata = &NM_NDISC_GET_PRIVATE(ndisc)->rdata;
	guint i;
	guint insert_idx = G_MAXUINT;

	for (i = 0; i < rdata->gateways->len; ) {
		NMNDiscGateway *item = &g_array_index (rdata->gateways, NMNDiscGateway, i);

		if (IN6_ARE_ADDR_EQUAL (&item->address, &new->address)) {
			if (new->lifetime == 0) {
				g_array_remove_index (rdata->gateways, i);
				_ASSERT_data_gateways (rdata);
				return TRUE;
			}

			if (item->preference != new->preference) {
				g_array_remove_index (rdata->gateways, i);
				continue;
			}

			if (get_expiry (item) == get_expiry (new))
				return FALSE;

			*item = *new;
			_ASSERT_data_gateways (rdata);
			return TRUE;
		}

		/* Put before less preferable gateways. */
		if (   _preference_to_priority (item->preference) < _preference_to_priority (new->preference)
		    && insert_idx == G_MAXUINT)
			insert_idx = i;

		i++;
	}

	if (new->lifetime) {
		g_array_insert_val (rdata->gateways,
		                    insert_idx == G_MAXUINT
		                      ? rdata->gateways->len
		                      : insert_idx,
		                    *new);
	}
	_ASSERT_data_gateways (rdata);
	return !!new->lifetime;
}

/**
 * complete_address:
 * @ndisc: the #NMNDisc
 * @addr: the #NMNDiscAddress
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
complete_address (NMNDisc *ndisc, NMNDiscAddress *addr)
{
	NMNDiscPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (NM_IS_NDISC (ndisc), FALSE);

	priv = NM_NDISC_GET_PRIVATE (ndisc);
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

static gboolean
nm_ndisc_add_address (NMNDisc *ndisc,
                      const NMNDiscAddress *new,
                      gint32 now_s,
                      gboolean from_ra)
{
	NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE (ndisc);
	NMNDiscDataInternal *rdata = &priv->rdata;
	NMNDiscAddress new2;
	NMNDiscAddress *existing = NULL;
	guint i;

	nm_assert (new);
	nm_assert (new->timestamp > 0 && new->timestamp < G_MAXINT32);
	nm_assert (!IN6_IS_ADDR_UNSPECIFIED (&new->address));
	nm_assert (!IN6_IS_ADDR_LINKLOCAL (&new->address));
	nm_assert (new->preferred <= new->lifetime);
	nm_assert (!from_ra || now_s > 0);

	for (i = 0; i < rdata->addresses->len; i++) {
		NMNDiscAddress *item = &g_array_index (rdata->addresses, NMNDiscAddress, i);

		if (from_ra) {
			/* RFC4862 5.5.3.d, we find an existing address with the same prefix.
			 * (note that all prefixes at this point have implicitly length /64). */
			if (memcmp (&item->address, &new->address, 8) == 0) {
				existing = item;
				break;
			}
		} else {
			if (IN6_ARE_ADDR_EQUAL (&item->address, &new->address)) {
				existing = item;
				break;
			}
		}
	}

	if (existing) {
		if (from_ra) {
			const gint32 NM_NDISC_PREFIX_LFT_MIN = 7200; /* seconds, RFC4862 5.5.3.e */
			gint64 old_expiry_lifetime, old_expiry_preferred;

			old_expiry_lifetime = get_expiry (existing);
			old_expiry_preferred = get_expiry_preferred (existing);

			if (new->lifetime == NM_NDISC_INFINITY)
				existing->lifetime = NM_NDISC_INFINITY;
			else {
				gint64 new_lifetime, remaining_lifetime;

				/* see RFC4862 5.5.3.e */
				if (existing->lifetime == NM_NDISC_INFINITY)
					remaining_lifetime = G_MAXINT64;
				else
					remaining_lifetime = ((gint64) existing->timestamp) + ((gint64) existing->lifetime) - ((gint64) now_s);
				new_lifetime = ((gint64) new->timestamp) + ((gint64) new->lifetime) - ((gint64) now_s);

				if (   new_lifetime > (gint64) NM_NDISC_PREFIX_LFT_MIN
				    || new_lifetime > remaining_lifetime) {
					existing->timestamp = now_s;
					existing->lifetime = CLAMP (new_lifetime, (gint64) 0, (gint64) (G_MAXUINT32 - 1));
				} else if (remaining_lifetime <= (gint64) NM_NDISC_PREFIX_LFT_MIN) {
					/* keep the current lifetime. */
				} else {
					existing->timestamp = now_s;
					existing->lifetime = NM_NDISC_PREFIX_LFT_MIN;
				}
			}

			if (new->preferred == NM_NDISC_INFINITY) {
				nm_assert (existing->lifetime == NM_NDISC_INFINITY);
				existing->preferred = new->preferred;
			} else {
				existing->preferred = NM_CLAMP (((gint64) new->timestamp) + ((gint64) new->preferred) - ((gint64) existing->timestamp),
				                                0, G_MAXUINT32 - 1);
				if (existing->lifetime != NM_NDISC_INFINITY)
					existing->preferred = MIN (existing->preferred, existing->lifetime);
			}

			return    old_expiry_lifetime != get_expiry (existing)
			       || old_expiry_preferred != get_expiry_preferred (existing);
		}

		if (new->lifetime == 0) {
			g_array_remove_index (rdata->addresses, i);
			return TRUE;
		}

		if (   get_expiry (existing) == get_expiry (new)
		    && get_expiry_preferred (existing) == get_expiry_preferred (new))
			return FALSE;

		existing->timestamp = new->timestamp;
		existing->lifetime = new->lifetime;
		existing->preferred = new->preferred;
		return TRUE;
	}

	/* we create at most max_addresses autoconf addresses. This is different from
	 * what the kernel does, because it considers *all* addresses (including
	 * static and other temporary addresses).
	 **/
	if (   priv->max_addresses
	    && rdata->addresses->len >= priv->max_addresses)
		return FALSE;

	if (new->lifetime == 0)
		return FALSE;

	if (from_ra) {
		new2 = *new;
		new2.dad_counter = 0;
		if (!complete_address (ndisc, &new2))
			return FALSE;
		new = &new2;
	}

	g_array_append_val (rdata->addresses, *new);
	return TRUE;
}

gboolean
nm_ndisc_complete_and_add_address (NMNDisc *ndisc,
                                   const NMNDiscAddress *new,
                                   gint32 now_s)
{
	return nm_ndisc_add_address (ndisc, new, now_s, TRUE);
}

gboolean
nm_ndisc_add_route (NMNDisc *ndisc, const NMNDiscRoute *new)
{
	NMNDiscPrivate *priv;
	NMNDiscDataInternal *rdata;
	guint i;
	guint insert_idx = G_MAXUINT;

	if (new->plen == 0 || new->plen > 128) {
		/* Only expect non-default routes.  The router has no idea what the
		 * local configuration or user preferences are, so sending routes
		 * with a prefix length of 0 must be ignored by NMNDisc.
		 *
		 * Also, upper layers also don't expect that NMNDisc exposes routes
		 * with a plen or zero or larger then 128.
		 */
		g_return_val_if_reached (FALSE);
	}

	priv = NM_NDISC_GET_PRIVATE (ndisc);
	rdata = &priv->rdata;

	for (i = 0; i < rdata->routes->len; ) {
		NMNDiscRoute *item = &g_array_index (rdata->routes, NMNDiscRoute, i);

		if (   IN6_ARE_ADDR_EQUAL (&item->network, &new->network)
		    && item->plen == new->plen) {
			if (new->lifetime == 0) {
				g_array_remove_index (rdata->routes, i);
				return TRUE;
			}

			if (item->preference != new->preference) {
				g_array_remove_index (rdata->routes, i);
				continue;
			}

			if (   get_expiry (item) == get_expiry (new)
			    && IN6_ARE_ADDR_EQUAL (&item->gateway, &new->gateway))
				return FALSE;

			*item = *new;
			return TRUE;
		}

		/* Put before less preferable routes. */
		if (   _preference_to_priority (item->preference) < _preference_to_priority (new->preference)
		    && insert_idx == G_MAXUINT)
			insert_idx = i;

		i++;
	}

	if (new->lifetime) {
		g_array_insert_val (rdata->routes,
		                    insert_idx == G_MAXUINT
		                      ? 0u
		                      : insert_idx,
		                    *new);
	}
	return !!new->lifetime;
}

gboolean
nm_ndisc_add_dns_server (NMNDisc *ndisc, const NMNDiscDNSServer *new)
{
	NMNDiscPrivate *priv;
	NMNDiscDataInternal *rdata;
	guint i;

	priv = NM_NDISC_GET_PRIVATE (ndisc);
	rdata = &priv->rdata;

	for (i = 0; i < rdata->dns_servers->len; i++) {
		NMNDiscDNSServer *item = &g_array_index (rdata->dns_servers, NMNDiscDNSServer, i);

		if (IN6_ARE_ADDR_EQUAL (&item->address, &new->address)) {
			if (new->lifetime == 0) {
				g_array_remove_index (rdata->dns_servers, i);
				return TRUE;
			}

			if (get_expiry (item) == get_expiry (new))
				return FALSE;

			*item = *new;
			return TRUE;
		}
	}

	if (new->lifetime)
		g_array_append_val (rdata->dns_servers, *new);
	return !!new->lifetime;
}

/* Copies new->domain if 'new' is added to the dns_domains list */
gboolean
nm_ndisc_add_dns_domain (NMNDisc *ndisc, const NMNDiscDNSDomain *new)
{
	NMNDiscPrivate *priv;
	NMNDiscDataInternal *rdata;
	NMNDiscDNSDomain *item;
	guint i;

	priv = NM_NDISC_GET_PRIVATE (ndisc);
	rdata = &priv->rdata;

	for (i = 0; i < rdata->dns_domains->len; i++) {
		item = &g_array_index (rdata->dns_domains, NMNDiscDNSDomain, i);

		if (!g_strcmp0 (item->domain, new->domain)) {
			if (new->lifetime == 0) {
				g_array_remove_index (rdata->dns_domains, i);
				return TRUE;
			}

			if (get_expiry (item) == get_expiry (new))
				return FALSE;

			item->timestamp = new->timestamp;
			item->lifetime = new->lifetime;
			return TRUE;
		}
	}

	if (new->lifetime) {
		g_array_append_val (rdata->dns_domains, *new);
		item = &g_array_index (rdata->dns_domains,
		                       NMNDiscDNSDomain,
		                       rdata->dns_domains->len - 1);
		item->domain = g_strdup (new->domain);
	}
	return !!new->lifetime;
}

/*****************************************************************************/

#define _MAYBE_WARN(...) G_STMT_START { \
		gboolean _different_message; \
		\
		_different_message = g_strcmp0 (priv->last_error, error->message) != 0; \
		_NMLOG (_different_message ? LOGL_WARN : LOGL_DEBUG, __VA_ARGS__); \
		if (_different_message) { \
			g_clear_pointer (&priv->last_error, g_free); \
			priv->last_error = g_strdup (error->message); \
		} \
	} G_STMT_END

static gboolean
send_rs_timeout (NMNDisc *ndisc)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	NMNDiscClass *klass = NM_NDISC_GET_CLASS (ndisc);
	NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE (ndisc);
	GError *error = NULL;

	priv->send_rs_id = 0;

	if (!nm_ndisc_netns_push (ndisc, &netns))
		return G_SOURCE_REMOVE;

	if (klass->send_rs (ndisc, &error)) {
		_LOGD ("router solicitation sent");
		priv->solicitations_left--;
		g_clear_pointer (&priv->last_error, g_free);
	} else {
		_MAYBE_WARN ("failure sending router solicitation: %s", error->message);
		g_clear_error (&error);
	}

	priv->last_rs = nm_utils_get_monotonic_timestamp_s ();
	if (priv->solicitations_left > 0) {
		_LOGD ("scheduling router solicitation retry in %d seconds.",
		       (int) priv->router_solicitation_interval);
		priv->send_rs_id = g_timeout_add_seconds (priv->router_solicitation_interval,
		                                          (GSourceFunc) send_rs_timeout, ndisc);
	} else {
		_LOGD ("did not receive a router advertisement after %d solicitations.",
		       (int) priv->router_solicitations);
	}

	return G_SOURCE_REMOVE;
}

static void
solicit_routers (NMNDisc *ndisc)
{
	NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE (ndisc);
	gint32 now, next;
	gint64 t;

	if (priv->send_rs_id)
		return;

	now = nm_utils_get_monotonic_timestamp_s ();
	priv->solicitations_left = priv->router_solicitations;

	t = (((gint64) priv->last_rs) + priv->router_solicitation_interval) - now;
	next = CLAMP (t, 0, G_MAXINT32);
	_LOGD ("scheduling explicit router solicitation request in %" G_GINT32_FORMAT " seconds.",
	       next);
	priv->send_rs_id = g_timeout_add_seconds ((guint32) next, (GSourceFunc) send_rs_timeout, ndisc);
}

static gboolean
announce_router (NMNDisc *ndisc)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	NMNDiscClass *klass = NM_NDISC_GET_CLASS (ndisc);
	NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE (ndisc);
	GError *error = NULL;

	if (!nm_ndisc_netns_push (ndisc, &netns))
		return G_SOURCE_REMOVE;

	priv->last_ra = nm_utils_get_monotonic_timestamp_s ();
	if (klass->send_ra (ndisc, &error)) {
		_LOGD ("router advertisement sent");
		g_clear_pointer (&priv->last_error, g_free);
	} else {
		_MAYBE_WARN ("failure sending router advertisement: %s", error->message);
		g_clear_error (&error);
	}

	if (--priv->announcements_left) {
		_LOGD ("will resend an initial router advertisement");

		/* Schedule next initial announcement retransmit. */
		priv->send_ra_id = g_timeout_add_seconds (g_random_int_range (NM_NDISC_ROUTER_ADVERT_DELAY,
		                                                              NM_NDISC_ROUTER_ADVERT_INITIAL_INTERVAL),
		                                          (GSourceFunc) announce_router, ndisc);
	} else {
		_LOGD ("will send an unsolicited router advertisement");

		/* Schedule next unsolicited announcement. */
		priv->announcements_left = 1;
		priv->send_ra_id = g_timeout_add_seconds (NM_NDISC_ROUTER_ADVERT_MAX_INTERVAL,
		                                          (GSourceFunc) announce_router,
		                                          ndisc);
	}

	return G_SOURCE_REMOVE;
}

static void
announce_router_initial (NMNDisc *ndisc)
{
	NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE (ndisc);

	_LOGD ("will send an initial router advertisement");

	/* Retry three more times. */
	priv->announcements_left = NM_NDISC_ROUTER_ADVERTISEMENTS_DEFAULT;

	/* Unschedule an unsolicited resend if we are allowed to send now. */
	if (G_LIKELY (nm_utils_get_monotonic_timestamp_s () - priv->last_ra > NM_NDISC_ROUTER_ADVERT_DELAY))
		nm_clear_g_source (&priv->send_ra_id);

	/* Schedule the initial send rather early. Clamp the delay by minimal
	 * delay and not the initial advert internal so that we start fast. */
	if (G_LIKELY (!priv->send_ra_id)) {
		priv->send_ra_id = g_timeout_add_seconds (g_random_int_range (0, NM_NDISC_ROUTER_ADVERT_DELAY),
		                                          (GSourceFunc) announce_router, ndisc);
	}
}

static void
announce_router_solicited (NMNDisc *ndisc)
{
	NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE (ndisc);

	_LOGD ("will send an solicited router advertisement");

	/* Unschedule an unsolicited resend if we are allowed to send now. */
	if (nm_utils_get_monotonic_timestamp_s () - priv->last_ra > NM_NDISC_ROUTER_ADVERT_DELAY)
		nm_clear_g_source (&priv->send_ra_id);

	if (!priv->send_ra_id) {
		priv->send_ra_id = g_timeout_add (g_random_int_range (0, NM_NDISC_ROUTER_ADVERT_DELAY_MS),
		                                  (GSourceFunc) announce_router, ndisc);
	}
}

/*****************************************************************************/

void
nm_ndisc_set_config (NMNDisc *ndisc,
                     const GArray *addresses,
                     const GArray *dns_servers,
                     const GArray *dns_domains)
{
	gboolean changed = FALSE;
	guint i;

	for (i = 0; i < addresses->len; i++) {
		if (nm_ndisc_add_address (ndisc, &g_array_index (addresses, NMNDiscAddress, i), 0, FALSE))
			changed = TRUE;
	}

	for (i = 0; i < dns_servers->len; i++) {
		if (nm_ndisc_add_dns_server (ndisc, &g_array_index (dns_servers, NMNDiscDNSServer, i)))
			changed = TRUE;
	}

	for (i = 0; i < dns_domains->len; i++) {
		if (nm_ndisc_add_dns_domain (ndisc, &g_array_index (dns_domains, NMNDiscDNSDomain, i)))
			changed = TRUE;
	}

	if (changed)
		announce_router_initial (ndisc);
}

/**
 * nm_ndisc_set_iid:
 * @ndisc: the #NMNDisc
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
nm_ndisc_set_iid (NMNDisc *ndisc, const NMUtilsIPv6IfaceId iid)
{
	NMNDiscPrivate *priv;
	NMNDiscDataInternal *rdata;

	g_return_val_if_fail (NM_IS_NDISC (ndisc), FALSE);

	priv = NM_NDISC_GET_PRIVATE (ndisc);
	rdata = &priv->rdata;

	if (priv->iid.id != iid.id) {
		priv->iid = iid;

		if (priv->addr_gen_mode == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY)
			return FALSE;

		if (rdata->addresses->len) {
			_LOGD ("IPv6 interface identifier changed, flushing addresses");
			g_array_remove_range (rdata->addresses, 0, rdata->addresses->len);
			nm_ndisc_emit_config_change (ndisc, NM_NDISC_CONFIG_ADDRESSES);
			solicit_routers (ndisc);
		}
		return TRUE;
	}

	return FALSE;
}

static gboolean
ndisc_ra_timeout_cb (gpointer user_data)
{
	NMNDisc *ndisc = NM_NDISC (user_data);

	NM_NDISC_GET_PRIVATE (ndisc)->ra_timeout_id = 0;
	g_signal_emit (ndisc, signals[RA_TIMEOUT], 0);
	return G_SOURCE_REMOVE;
}

void
nm_ndisc_start (NMNDisc *ndisc)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE (ndisc);
	NMNDiscClass *klass = NM_NDISC_GET_CLASS (ndisc);
	gint64 ra_wait_secs;

	g_return_if_fail (klass->start);
	g_return_if_fail (!priv->ra_timeout_id);

	_LOGD ("starting neighbor discovery: %d", priv->ifindex);

	if (!nm_ndisc_netns_push (ndisc, &netns))
		return;

	klass->start (ndisc);

	switch (priv->node_type) {
	case NM_NDISC_NODE_TYPE_HOST:
		ra_wait_secs = (((gint64) priv->router_solicitations) * priv->router_solicitation_interval) + 1;
		ra_wait_secs = CLAMP (ra_wait_secs, 30, 120);
		priv->ra_timeout_id = g_timeout_add_seconds (ra_wait_secs, ndisc_ra_timeout_cb, ndisc);
		_LOGD ("scheduling RA timeout in %d seconds", (int) ra_wait_secs);
		solicit_routers (ndisc);
		break;
	case NM_NDISC_NODE_TYPE_ROUTER:
		announce_router_initial (ndisc);
		break;
	default:
		g_assert_not_reached ();
	}
}

NMNDiscConfigMap
nm_ndisc_dad_failed (NMNDisc *ndisc, const struct in6_addr *address, gboolean emit_changed_signal)
{
	NMNDiscDataInternal *rdata;
	guint i;
	gboolean changed = FALSE;

	rdata = &NM_NDISC_GET_PRIVATE (ndisc)->rdata;

	for (i = 0; i < rdata->addresses->len; ) {
		NMNDiscAddress *item = &g_array_index (rdata->addresses, NMNDiscAddress, i);

		if (IN6_ARE_ADDR_EQUAL (&item->address, address)) {
			char sbuf[NM_UTILS_INET_ADDRSTRLEN];

			_LOGD ("DAD failed for discovered address %s", nm_utils_inet6_ntop (address, sbuf));
			changed = TRUE;
			if (!complete_address (ndisc, item)) {
				g_array_remove_index (rdata->addresses, i);
				continue;
			}
		}
		i++;
	}

	if (emit_changed_signal && changed)
		nm_ndisc_emit_config_change (ndisc, NM_NDISC_CONFIG_ADDRESSES);

	return changed ? NM_NDISC_CONFIG_ADDRESSES : NM_NDISC_CONFIG_NONE;
}

#define CONFIG_MAP_MAX_STR 7

static void
config_map_to_string (NMNDiscConfigMap map, char *p)
{
	if (map & NM_NDISC_CONFIG_DHCP_LEVEL)
		*p++ = 'd';
	if (map & NM_NDISC_CONFIG_GATEWAYS)
		*p++ = 'G';
	if (map & NM_NDISC_CONFIG_ADDRESSES)
		*p++ = 'A';
	if (map & NM_NDISC_CONFIG_ROUTES)
		*p++ = 'R';
	if (map & NM_NDISC_CONFIG_DNS_SERVERS)
		*p++ = 'S';
	if (map & NM_NDISC_CONFIG_DNS_DOMAINS)
		*p++ = 'D';
	*p = '\0';
}

static const char *
dhcp_level_to_string (NMNDiscDHCPLevel dhcp_level)
{
	switch (dhcp_level) {
	case NM_NDISC_DHCP_LEVEL_NONE:
		return "none";
	case NM_NDISC_DHCP_LEVEL_OTHERCONF:
		return "otherconf";
	case NM_NDISC_DHCP_LEVEL_MANAGED:
		return "managed";
	default:
		return "INVALID";
	}
}

static void
_config_changed_log (NMNDisc *ndisc, NMNDiscConfigMap changed)
{
	NMNDiscPrivate *priv;
	NMNDiscDataInternal *rdata;
	guint i;
	char changedstr[CONFIG_MAP_MAX_STR];
	char addrstr[INET6_ADDRSTRLEN];
	char str_pref[35];
	char str_exp[100];
	gint64 now_ns;

	if (!_LOGD_ENABLED ())
		return;

	now_ns = nm_utils_get_monotonic_timestamp_ns ();

	priv = NM_NDISC_GET_PRIVATE (ndisc);
	rdata = &priv->rdata;

	config_map_to_string (changed, changedstr);
	_LOGD ("neighbor discovery configuration changed [%s]:", changedstr);
	_LOGD ("  dhcp-level %s", dhcp_level_to_string (priv->rdata.public.dhcp_level));
	for (i = 0; i < rdata->gateways->len; i++) {
		NMNDiscGateway *gateway = &g_array_index (rdata->gateways, NMNDiscGateway, i);

		inet_ntop (AF_INET6, &gateway->address, addrstr, sizeof (addrstr));
		_LOGD ("  gateway %s pref %s exp %s", addrstr,
		       nm_icmpv6_router_pref_to_string (gateway->preference, str_pref, sizeof (str_pref)),
		       get_exp (str_exp, now_ns, gateway));
	}
	for (i = 0; i < rdata->addresses->len; i++) {
		const NMNDiscAddress *address = &g_array_index (rdata->addresses, NMNDiscAddress, i);

		inet_ntop (AF_INET6, &address->address, addrstr, sizeof (addrstr));
		_LOGD ("  address %s exp %s", addrstr,
		       get_exp (str_exp, now_ns, address));
	}
	for (i = 0; i < rdata->routes->len; i++) {
		NMNDiscRoute *route = &g_array_index (rdata->routes, NMNDiscRoute, i);
		char sbuf[NM_UTILS_INET_ADDRSTRLEN];

		inet_ntop (AF_INET6, &route->network, addrstr, sizeof (addrstr));
		_LOGD ("  route %s/%u via %s pref %s exp %s", addrstr, (guint) route->plen,
		       nm_utils_inet6_ntop (&route->gateway, sbuf),
		       nm_icmpv6_router_pref_to_string (route->preference, str_pref, sizeof (str_pref)),
		       get_exp (str_exp, now_ns, route));
	}
	for (i = 0; i < rdata->dns_servers->len; i++) {
		NMNDiscDNSServer *dns_server = &g_array_index (rdata->dns_servers, NMNDiscDNSServer, i);

		inet_ntop (AF_INET6, &dns_server->address, addrstr, sizeof (addrstr));
		_LOGD ("  dns_server %s exp %s", addrstr,
		       get_exp (str_exp, now_ns, dns_server));
	}
	for (i = 0; i < rdata->dns_domains->len; i++) {
		NMNDiscDNSDomain *dns_domain = &g_array_index (rdata->dns_domains, NMNDiscDNSDomain, i);

		_LOGD ("  dns_domain %s exp %s", dns_domain->domain,
		       get_exp (str_exp, now_ns, dns_domain));
	}
}

static void
clean_gateways (NMNDisc *ndisc, gint32 now, NMNDiscConfigMap *changed, gint32 *nextevent)
{
	NMNDiscDataInternal *rdata;
	guint i;

	rdata = &NM_NDISC_GET_PRIVATE (ndisc)->rdata;

	for (i = 0; i < rdata->gateways->len; ) {
		NMNDiscGateway *item = &g_array_index (rdata->gateways, NMNDiscGateway, i);

		if (!expiry_next (now, get_expiry (item), nextevent)) {
			g_array_remove_index (rdata->gateways, i);
			*changed |= NM_NDISC_CONFIG_GATEWAYS;
			continue;
		}

		i++;
	}

	_ASSERT_data_gateways (rdata);
}

static void
clean_addresses (NMNDisc *ndisc, gint32 now, NMNDiscConfigMap *changed, gint32 *nextevent)
{
	NMNDiscDataInternal *rdata;
	guint i;

	rdata = &NM_NDISC_GET_PRIVATE (ndisc)->rdata;

	for (i = 0; i < rdata->addresses->len; ) {
		const NMNDiscAddress *item = &g_array_index (rdata->addresses, NMNDiscAddress, i);

		if (!expiry_next (now, get_expiry (item), nextevent)) {
			g_array_remove_index (rdata->addresses, i);
			*changed |= NM_NDISC_CONFIG_ADDRESSES;
			continue;
		}

		i++;
	}
}

static void
clean_routes (NMNDisc *ndisc, gint32 now, NMNDiscConfigMap *changed, gint32 *nextevent)
{
	NMNDiscDataInternal *rdata;
	guint i;

	rdata = &NM_NDISC_GET_PRIVATE (ndisc)->rdata;

	for (i = 0; i < rdata->routes->len; ) {
		NMNDiscRoute *item = &g_array_index (rdata->routes, NMNDiscRoute, i);

		if (!expiry_next (now, get_expiry (item), nextevent)) {
			g_array_remove_index (rdata->routes, i);
			*changed |= NM_NDISC_CONFIG_ROUTES;
			continue;
		}

		i++;
	}
}

static void
clean_dns_servers (NMNDisc *ndisc, gint32 now, NMNDiscConfigMap *changed, gint32 *nextevent)
{
	NMNDiscDataInternal *rdata;
	guint i;

	rdata = &NM_NDISC_GET_PRIVATE (ndisc)->rdata;

	for (i = 0; i < rdata->dns_servers->len; ) {
		NMNDiscDNSServer *item = &g_array_index (rdata->dns_servers, NMNDiscDNSServer, i);
		gint64 refresh;

		refresh = get_expiry_half (item);
		if (refresh != _EXPIRY_INFINITY) {
			if (!expiry_next (now, get_expiry (item), NULL)) {
				g_array_remove_index (rdata->dns_servers, i);
				*changed |= NM_NDISC_CONFIG_DNS_SERVERS;
				continue;
			}

			if (now >= refresh)
				solicit_routers (ndisc);
			else if (*nextevent > refresh)
				*nextevent = refresh;
		}
		i++;
	}
}

static void
clean_dns_domains (NMNDisc *ndisc, gint32 now, NMNDiscConfigMap *changed, gint32 *nextevent)
{
	NMNDiscDataInternal *rdata;
	guint i;

	rdata = &NM_NDISC_GET_PRIVATE (ndisc)->rdata;

	for (i = 0; i < rdata->dns_domains->len; ) {
		NMNDiscDNSDomain *item = &g_array_index (rdata->dns_domains, NMNDiscDNSDomain, i);
		gint64 refresh;

		refresh = get_expiry_half (item);
		if (refresh != _EXPIRY_INFINITY) {
			if (!expiry_next (now, get_expiry (item), NULL)) {
				g_array_remove_index (rdata->dns_domains, i);
				*changed |= NM_NDISC_CONFIG_DNS_DOMAINS;
				continue;
			}

			if (now >= refresh)
				solicit_routers (ndisc);
			else if (*nextevent > refresh)
				*nextevent = refresh;
		}
		i++;
	}
}

static gboolean timeout_cb (gpointer user_data);

static void
check_timestamps (NMNDisc *ndisc, gint32 now, NMNDiscConfigMap changed)
{
	NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE (ndisc);
	/* Use a magic date in the distant future (~68 years) */
	gint32 nextevent = G_MAXINT32;

	nm_clear_g_source (&priv->timeout_id);

	clean_gateways (ndisc, now, &changed, &nextevent);
	clean_addresses (ndisc, now, &changed, &nextevent);
	clean_routes (ndisc, now, &changed, &nextevent);
	clean_dns_servers (ndisc, now, &changed, &nextevent);
	clean_dns_domains (ndisc, now, &changed, &nextevent);

	if (nextevent != G_MAXINT32) {
		if (nextevent <= now)
			g_return_if_reached ();
		_LOGD ("scheduling next now/lifetime check: %d seconds",
		       (int) (nextevent - now));
		priv->timeout_id = g_timeout_add_seconds (nextevent - now, timeout_cb, ndisc);
	}

	if (changed)
		nm_ndisc_emit_config_change (ndisc, changed);
}

static gboolean
timeout_cb (gpointer user_data)
{
	NMNDisc *self = user_data;

	NM_NDISC_GET_PRIVATE (self)->timeout_id = 0;
	check_timestamps (self, nm_utils_get_monotonic_timestamp_s (), 0);
	return G_SOURCE_REMOVE;
}

void
nm_ndisc_ra_received (NMNDisc *ndisc, gint32 now, NMNDiscConfigMap changed)
{
	NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE (ndisc);

	nm_clear_g_source (&priv->ra_timeout_id);
	nm_clear_g_source (&priv->send_rs_id);
	g_clear_pointer (&priv->last_error, g_free);
	check_timestamps (ndisc, now, changed);
}

void
nm_ndisc_rs_received (NMNDisc *ndisc)
{
	NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE (ndisc);

	g_clear_pointer (&priv->last_error, g_free);
	announce_router_solicited (ndisc);
}

/*****************************************************************************/

static void
dns_domain_free (gpointer data)
{
	g_free (((NMNDiscDNSDomain *)(data))->domain);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMNDisc *self = NM_NDISC (object);
	NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_PLATFORM:
		/* construct-only */
		priv->platform = g_value_get_object (value) ?: NM_PLATFORM_GET;
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
		g_return_if_fail (priv->network_id);
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
	case PROP_NODE_TYPE:
		/* construct-only */
		priv->node_type = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ndisc_init (NMNDisc *ndisc)
{
	NMNDiscPrivate *priv;
	NMNDiscDataInternal *rdata;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (ndisc, NM_TYPE_NDISC, NMNDiscPrivate);
	ndisc->_priv = priv;

	rdata = &priv->rdata;

	rdata->gateways = g_array_new (FALSE, FALSE, sizeof (NMNDiscGateway));
	rdata->addresses = g_array_new (FALSE, FALSE, sizeof (NMNDiscAddress));
	rdata->routes = g_array_new (FALSE, FALSE, sizeof (NMNDiscRoute));
	rdata->dns_servers = g_array_new (FALSE, FALSE, sizeof (NMNDiscDNSServer));
	rdata->dns_domains = g_array_new (FALSE, FALSE, sizeof (NMNDiscDNSDomain));
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
	NMNDisc *ndisc = NM_NDISC (object);
	NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE (ndisc);

	nm_clear_g_source (&priv->ra_timeout_id);
	nm_clear_g_source (&priv->send_rs_id);
	nm_clear_g_source (&priv->send_ra_id);
	g_clear_pointer (&priv->last_error, g_free);

	nm_clear_g_source (&priv->timeout_id);

	G_OBJECT_CLASS (nm_ndisc_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMNDisc *ndisc = NM_NDISC (object);
	NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE (ndisc);
	NMNDiscDataInternal *rdata = &priv->rdata;

	g_free (priv->ifname);
	g_free (priv->network_id);

	g_array_unref (rdata->gateways);
	g_array_unref (rdata->addresses);
	g_array_unref (rdata->routes);
	g_array_unref (rdata->dns_servers);
	g_array_unref (rdata->dns_domains);

	g_clear_object (&priv->netns);
	g_clear_object (&priv->platform);

	G_OBJECT_CLASS (nm_ndisc_parent_class)->finalize (object);
}

static void
nm_ndisc_class_init (NMNDiscClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMNDiscPrivate));

	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	obj_properties[PROP_PLATFORM] =
	    g_param_spec_object (NM_NDISC_PLATFORM, "", "",
	                         NM_TYPE_PLATFORM,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IFINDEX] =
	    g_param_spec_int (NM_NDISC_IFINDEX, "", "",
	                      0, G_MAXINT, 0,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IFNAME] =
	    g_param_spec_string (NM_NDISC_IFNAME, "", "",
	                         NULL,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_STABLE_TYPE] =
	    g_param_spec_int (NM_NDISC_STABLE_TYPE, "", "",
	                      NM_UTILS_STABLE_TYPE_UUID, NM_UTILS_STABLE_TYPE_RANDOM, NM_UTILS_STABLE_TYPE_UUID,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_NETWORK_ID] =
	    g_param_spec_string (NM_NDISC_NETWORK_ID, "", "",
	                         NULL,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ADDR_GEN_MODE] =
	    g_param_spec_int (NM_NDISC_ADDR_GEN_MODE, "", "",
	                      NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_MAX_ADDRESSES] =
	    g_param_spec_int (NM_NDISC_MAX_ADDRESSES, "", "",
	                      0, G_MAXINT32, NM_NDISC_MAX_ADDRESSES_DEFAULT,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ROUTER_SOLICITATIONS] =
	    g_param_spec_int (NM_NDISC_ROUTER_SOLICITATIONS, "", "",
	                      1, G_MAXINT32, NM_NDISC_ROUTER_SOLICITATIONS_DEFAULT,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ROUTER_SOLICITATION_INTERVAL] =
	    g_param_spec_int (NM_NDISC_ROUTER_SOLICITATION_INTERVAL, "", "",
	                      1, G_MAXINT32, NM_NDISC_ROUTER_SOLICITATION_INTERVAL_DEFAULT,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_NODE_TYPE] =
	    g_param_spec_int (NM_NDISC_NODE_TYPE, "", "",
	                      NM_NDISC_NODE_TYPE_INVALID, NM_NDISC_NODE_TYPE_ROUTER, NM_NDISC_NODE_TYPE_INVALID,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[CONFIG_RECEIVED] =
	    g_signal_new (NM_NDISC_CONFIG_RECEIVED,
	                  G_OBJECT_CLASS_TYPE (klass),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_POINTER, G_TYPE_UINT);
	signals[RA_TIMEOUT] =
	    g_signal_new (NM_NDISC_RA_TIMEOUT,
	                  G_OBJECT_CLASS_TYPE (klass),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);
}
