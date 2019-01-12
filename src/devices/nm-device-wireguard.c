/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2018 Javier Arteaga <jarteaga@jbeta.is>
 */

#include "nm-default.h"

#include "nm-device-wireguard.h"

#include "nm-setting-wireguard.h"
#include "nm-core-internal.h"
#include "nm-utils/nm-secret-utils.h"
#include "nm-device-private.h"
#include "platform/nm-platform.h"
#include "platform/nmp-object.h"
#include "nm-device-factory.h"
#include "nm-active-connection.h"
#include "nm-act-request.h"
#include "dns/nm-dns-manager.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceWireGuard);

/* XXX: TODO: what happens when setting wireguard.private-key-flags=not-required? Should
 *   that be rejected as invalid configuration? */

/* XXX: TODO: currently, ipv4.method still defaults to "auto", which isn't working. I
 *   wonder, whether "auto" should be forbidden entirely, or whether auto should
 *   get a new meaning (see commit adbb9eb).
 *     - at least, if you create a profile in nmcli, it should default to an
 *       IP method that actually works ("auto" does not).
 */

/* XXX: TODO: requesting preshared-key secrets is not yet implemented. */

/* XXX: TODO: WireGuard links are always taken down on exit of NM, and cannot be
 *   assumed. */

/* XXX: TODO: when NM exits, it tears down the WireGuard interface but doesn't remove it. */

/* XXX: TODO: avoid WGPEER_F_REPLACE_ALLOWEDIPS on updates */

/* XXX: TODO: support Reapply */

/* XXX: TODO: treated WG as VPN (w.r.t. DNS priorities, etc). */

/*****************************************************************************/

G_STATIC_ASSERT (NM_WIREGUARD_PUBLIC_KEY_LEN   == NMP_WIREGUARD_PUBLIC_KEY_LEN);
G_STATIC_ASSERT (NM_WIREGUARD_SYMMETRIC_KEY_LEN == NMP_WIREGUARD_SYMMETRIC_KEY_LEN);

/*****************************************************************************/

#define LINK_CONFIG_RATE_LIMIT_NSEC (50 * NM_UTILS_NS_PER_MSEC)

/* a special @next_try_at_nsec timestamp indicating that we should try again as soon as possible. */
#define NEXT_TRY_AT_NSEC_ASAP ((gint64) G_MAXINT64)

/* a special @next_try_at_nsec timestamp that is
 *  - positive (indicating resolve-checks are enabled)
 *  - already in the past (we use the absolute timestamp of 1nsec for that). */
#define NEXT_TRY_AT_NSEC_PAST ((gint64) 1)

/* like %NEXT_TRY_AT_NSEC_ASAP, but used for indicating to retry ASAP for a @retry_in_msec value.
 * That is a relative time duraction, contrary to @next_try_at_nsec which is an absolute
 * timestamp. */
#define RETRY_IN_MSEC_ASAP ((gint64) G_MAXINT64)

#define RETRY_IN_MSEC_MAX ((gint64) (30 * 60 * 1000))

typedef struct {
	GCancellable *cancellable;

	NMSockAddrUnion sockaddr;

	/* the timestamp (in nm_utils_get_monotonic_timestamp_ns() scale) when we want
	 * to retry resolving the endpoint (again).
	 *
	 * It may be set to %NEXT_TRY_AT_NSEC_ASAP to indicate to re-resolve as soon as possible.
	 *
	 * A @sockaddr is either fixed or it has
	 *   - @cancellable set to indicate an ongoing request
	 *   - @next_try_at_nsec set to a positive value, indicating when
	 *     we ought to retry. */
	gint64 next_try_at_nsec;

	guint resolv_fail_count;
} PeerEndpointResolveData;

typedef struct {
	NMWireGuardPeer *peer;

	NMDeviceWireGuard *self;

	CList lst_peers;

	PeerEndpointResolveData ep_resolv;

	/* dirty flag used during _peers_update_all(). */
	bool dirty_update_all:1;
} PeerData;

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceWireGuard,
	PROP_PUBLIC_KEY,
	PROP_LISTEN_PORT,
	PROP_FWMARK,
);

typedef struct {

	NMDnsManager *dns_manager;

	NMPlatformLnkWireGuard lnk_curr;
	NMPlatformLnkWireGuard lnk_want;
	NMActRequestGetSecretsCallId *secrets_call_id;

	CList lst_peers_head;
	GHashTable *peers;

	gint64 resolve_next_try_at;
	guint  resolve_next_try_id;

	gint64 link_config_last_at;
	guint  link_config_delayed_id;

	bool link_config_is_update:1;
} NMDeviceWireGuardPrivate;

struct _NMDeviceWireGuard {
	NMDevice parent;
	NMDeviceWireGuardPrivate _priv;
};

struct _NMDeviceWireGuardClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceWireGuard, nm_device_wireguard, NM_TYPE_DEVICE)

#define NM_DEVICE_WIREGUARD_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceWireGuard, NM_IS_DEVICE_WIREGUARD, NMDevice)

/*****************************************************************************/

static void _peers_resolve_start (NMDeviceWireGuard *self,
                                  PeerData *peer_data);

static void _peers_resolve_retry_reschedule (NMDeviceWireGuard *self,
                                             gint64 new_next_try_at_nsec);

static gboolean link_config_delayed_resolver_cb (gpointer user_data);

static NMActStageReturn link_config (NMDeviceWireGuard *self,
                                     gboolean allow_rate_limit,
                                     gboolean fail_state_on_failure,
                                     const char *reason,
                                     NMDeviceStateReason *out_failure_reason);

/*****************************************************************************/

static gboolean
_peer_data_equal (gconstpointer ptr_a, gconstpointer ptr_b)
{
	const PeerData *peer_data_a = ptr_a;
	const PeerData *peer_data_b = ptr_b;

	return nm_streq (nm_wireguard_peer_get_public_key (peer_data_a->peer),
	                 nm_wireguard_peer_get_public_key (peer_data_b->peer));
}

static guint
_peer_data_hash (gconstpointer ptr)
{
	const PeerData *peer_data = ptr;

	return nm_hash_str (nm_wireguard_peer_get_public_key (peer_data->peer));
}

static PeerData *
_peers_find (NMDeviceWireGuardPrivate *priv,
             NMWireGuardPeer *peer)
{
	nm_assert (peer);

	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (PeerData, peer) == 0);

	return g_hash_table_lookup (priv->peers, &peer);
}

static void
_peers_remove (NMDeviceWireGuardPrivate *priv,
               PeerData *peer_data)
{
	nm_assert (peer_data);
	nm_assert (g_hash_table_lookup (priv->peers, peer_data) == peer_data);

	if (!g_hash_table_remove (priv->peers, peer_data))
		nm_assert_not_reached ();

	c_list_unlink_stale (&peer_data->lst_peers);
	nm_wireguard_peer_unref (peer_data->peer);
	nm_clear_g_cancellable (&peer_data->ep_resolv.cancellable);
	g_slice_free (PeerData, peer_data);

	if (c_list_is_empty (&peer_data->lst_peers)) {
		nm_clear_g_source (&priv->resolve_next_try_id);
		nm_clear_g_source (&priv->link_config_delayed_id);
	}
}

static PeerData *
_peers_add (NMDeviceWireGuard *self,
            NMWireGuardPeer *peer)
{
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);
	PeerData *peer_data;

	nm_assert (peer);
	nm_assert (nm_wireguard_peer_is_sealed (peer));
	nm_assert (!_peers_find (priv, peer));

	peer_data = g_slice_new (PeerData);
	*peer_data = (PeerData) {
		.self = self,
		.peer = nm_wireguard_peer_ref (peer),
		.ep_resolv = {
			.sockaddr = NM_SOCK_ADDR_UNION_INIT_UNSPEC,
		},
	};

	c_list_link_tail (&priv->lst_peers_head, &peer_data->lst_peers);
	if (!nm_g_hash_table_add (priv->peers, peer_data))
		nm_assert_not_reached ();
	return peer_data;
}

static gboolean
_peers_resolve_retry_timeout (gpointer user_data)
{
	NMDeviceWireGuard *self = user_data;
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);
	PeerData *peer_data;
	gint64 now;
	gint64 next;

	priv->resolve_next_try_id = 0;

	_LOGT (LOGD_DEVICE, "wireguard-peers: rechecking peer endpoints...");

	now = nm_utils_get_monotonic_timestamp_ns ();
	next = G_MAXINT64;
	c_list_for_each_entry (peer_data, &priv->lst_peers_head, lst_peers) {
		if (peer_data->ep_resolv.next_try_at_nsec <= 0)
			continue;

		if (peer_data->ep_resolv.cancellable) {
			/* we are currently resolving a name. We don't need the global
			 * watchdog to guard this peer. No need to adjust @next for
			 * this one, when the currently ongoing resolving completes, we
			 * may reschedule. Skip. */
			continue;
		}

		if (   peer_data->ep_resolv.next_try_at_nsec == NEXT_TRY_AT_NSEC_ASAP
		    || now >= peer_data->ep_resolv.next_try_at_nsec) {
			_peers_resolve_start (self, peer_data);
			/* same here. Now we are resolving. We don't need the global
			 * watchdog. Skip w.r.t. finding @next. */
			continue;
		}

		if (next > peer_data->ep_resolv.next_try_at_nsec)
			next = peer_data->ep_resolv.next_try_at_nsec;
	}
	if (next < G_MAXINT64)
		_peers_resolve_retry_reschedule (self, next);

	return G_SOURCE_REMOVE;
}

static void
_peers_resolve_retry_reschedule (NMDeviceWireGuard *self,
                                 gint64 new_next_try_at_nsec)
{
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);
	guint32 interval_ms;
	gint64 now;

	nm_assert (new_next_try_at_nsec > 0);
	nm_assert (new_next_try_at_nsec != NEXT_TRY_AT_NSEC_ASAP);

	if (   priv->resolve_next_try_id
	    && priv->resolve_next_try_at <= new_next_try_at_nsec) {
		/* we already have an earlier timeout scheduled (possibly for
		 * another peer that expires sooner). Don't reschedule now.
		 * Even if the scheduled timeout expires too early, we will
		 * compute the right next-timeout and reschedule then. */
		return;
	}

	now = nm_utils_get_monotonic_timestamp_ns ();

	/* schedule at most one day ahead. No problem if we expire earlier
	 * than expected. Also, rate-limit to 500 msec. */
	interval_ms = NM_CLAMP ((new_next_try_at_nsec - now) / NM_UTILS_NS_PER_MSEC,
	                        (gint64) 500,
	                        (gint64) (24*60*60*1000));

	_LOGT (LOGD_DEVICE, "wireguard-peers: schedule rechecking peer endpoints in %u msec",
	       interval_ms);

	nm_clear_g_source (&priv->resolve_next_try_id);
	priv->resolve_next_try_at = new_next_try_at_nsec;
	priv->resolve_next_try_id = g_timeout_add (interval_ms,
	                                           _peers_resolve_retry_timeout,
	                                           self);
}

static void
_peers_resolve_retry_reschedule_for_peer (NMDeviceWireGuard *self,
                                          PeerData *peer_data,
                                          gint64 retry_in_msec)
{
	nm_assert (retry_in_msec >= 0);

	if (retry_in_msec == RETRY_IN_MSEC_ASAP) {
		_peers_resolve_start (self, peer_data);
		return;
	}

	peer_data->ep_resolv.next_try_at_nsec =   nm_utils_get_monotonic_timestamp_ns ()
	                                        + (retry_in_msec * NM_UTILS_NS_PER_MSEC);
	_peers_resolve_retry_reschedule (self, peer_data->ep_resolv.next_try_at_nsec);
}

static gint64
_peers_retry_in_msec (PeerData *peer_data,
                      gboolean after_failure)
{
	if (peer_data->ep_resolv.next_try_at_nsec == NEXT_TRY_AT_NSEC_ASAP) {
		peer_data->ep_resolv.resolv_fail_count = 0;
		return RETRY_IN_MSEC_ASAP;
	}

	if (after_failure) {
		if (peer_data->ep_resolv.resolv_fail_count < G_MAXUINT)
			peer_data->ep_resolv.resolv_fail_count++;
	} else
		peer_data->ep_resolv.resolv_fail_count = 0;

	if (!after_failure)
		return RETRY_IN_MSEC_MAX;

	if (peer_data->ep_resolv.resolv_fail_count > 20)
		return RETRY_IN_MSEC_MAX;

	/* double the retry-time, starting with one second. */
	return NM_MIN (RETRY_IN_MSEC_MAX,
	               (1u << peer_data->ep_resolv.resolv_fail_count) * 500);
}

static void
_peers_resolve_cb (GObject *source_object,
                   GAsyncResult *res,
                   gpointer user_data)
{
	NMDeviceWireGuard *self;
	PeerData *peer_data;
	gs_free_error GError *resolv_error = NULL;
	GList *list;
	gboolean changed = FALSE;
	NMSockAddrUnion sockaddr;
	gint64 retry_in_msec;
	char s_sockaddr[100];
	char s_retry[100];

	list = g_resolver_lookup_by_name_finish (G_RESOLVER (source_object), res, &resolv_error);

	if (nm_utils_error_is_cancelled (resolv_error, FALSE))
		return;

	peer_data = user_data;
	self = peer_data->self;

	g_clear_object (&peer_data->ep_resolv.cancellable);

	nm_assert ((!resolv_error) != (!list));

#define _retry_in_msec_to_string(retry_in_msec, s_retry) \
	({ \
		gint64 _retry_in_msec = (retry_in_msec); \
		\
		  _retry_in_msec == RETRY_IN_MSEC_ASAP \
		? "right away" \
		: nm_sprintf_buf (s_retry, "in %"G_GINT64_FORMAT" msec", _retry_in_msec); \
	})

	if (   resolv_error
	    && !g_error_matches (resolv_error, G_RESOLVER_ERROR, G_RESOLVER_ERROR_NOT_FOUND)) {
		retry_in_msec = _peers_retry_in_msec (peer_data, TRUE);

		_LOGT (LOGD_DEVICE, "wireguard-peer[%s]: failure to resolve endpoint \"%s\": %s (retry %s)",
		       nm_wireguard_peer_get_public_key (peer_data->peer),
		       nm_wireguard_peer_get_endpoint (peer_data->peer),
		       resolv_error->message,
		       _retry_in_msec_to_string (retry_in_msec, s_retry));

		_peers_resolve_retry_reschedule_for_peer (self, peer_data, retry_in_msec);
		return;
	}

	sockaddr = (NMSockAddrUnion) NM_SOCK_ADDR_UNION_INIT_UNSPEC;

	if (!resolv_error) {
		GList *iter;

		for (iter = list; iter; iter = iter->next) {
			GInetAddress *a = iter->data;
			GSocketFamily f = g_inet_address_get_family (a);

			if (f == G_SOCKET_FAMILY_IPV4) {
				nm_assert (g_inet_address_get_native_size (a) == sizeof (struct in_addr));
				sockaddr.in = (struct sockaddr_in) {
					.sin_family = AF_INET,
					.sin_port   = htons (nm_sock_addr_endpoint_get_port (_nm_wireguard_peer_get_endpoint (peer_data->peer))),
				};
				memcpy (&sockaddr.in.sin_addr, g_inet_address_to_bytes (a), sizeof (struct in_addr));
				break;
			}
			if (f == G_SOCKET_FAMILY_IPV6) {
				nm_assert (g_inet_address_get_native_size (a) == sizeof (struct in6_addr));
				sockaddr.in6 = (struct sockaddr_in6) {
					.sin6_family   = AF_INET6,
					.sin6_port     = htons (nm_sock_addr_endpoint_get_port (_nm_wireguard_peer_get_endpoint (peer_data->peer))),
					.sin6_scope_id = 0,
					.sin6_flowinfo = 0,
				};
				memcpy (&sockaddr.in6.sin6_addr, g_inet_address_to_bytes (a), sizeof (struct in6_addr));
				break;
			}
		}

		g_list_free_full (list, g_object_unref);
	}

	if (sockaddr.sa.sa_family == AF_UNSPEC) {
		/* we failed to resolve the name. There is no need to reset the previous
		 * sockaddr. Either it was already AF_UNSPEC, or we had a good name
		 * from resolving before. In that case, we don't want to throw away
		 * a possibly good IP address, since WireGuard supports automatic roaming
		 * anyway. Either the IP address is still good (and we would wrongly
		 * reject it), or it isn't -- in which case it does not hurt much. */
	} else {
		if (nm_sock_addr_union_cmp (&peer_data->ep_resolv.sockaddr, &sockaddr) != 0)
			changed = TRUE;
		peer_data->ep_resolv.sockaddr = sockaddr;
	}

	if (   resolv_error
	    || peer_data->ep_resolv.sockaddr.sa.sa_family == AF_UNSPEC) {
		/* while it technically did not fail, something is probably odd. Retry frequently to
		 * resolve the name, like we would do for normal failures. */
		retry_in_msec = _peers_retry_in_msec (peer_data, TRUE);
		_LOGT (LOGD_DEVICE, "wireguard-peer[%s]: no %sresults for endpoint \"%s\" (retry %s)",
		       nm_wireguard_peer_get_public_key (peer_data->peer),
		       resolv_error ? "" : "suitable ",
		       nm_wireguard_peer_get_endpoint (peer_data->peer),
		       _retry_in_msec_to_string (retry_in_msec, s_retry));
	} else {
		retry_in_msec = _peers_retry_in_msec (peer_data, FALSE);
		_LOGT (LOGD_DEVICE, "wireguard-peer[%s]: endpoint \"%s\" resolved to %s (retry %s)",
		       nm_wireguard_peer_get_public_key (peer_data->peer),
		       nm_wireguard_peer_get_endpoint (peer_data->peer),
		       nm_sock_addr_union_to_string (&peer_data->ep_resolv.sockaddr, s_sockaddr, sizeof (s_sockaddr)),
		       _retry_in_msec_to_string (retry_in_msec, s_retry));
	}

	_peers_resolve_retry_reschedule_for_peer (self, peer_data, retry_in_msec);

	if (changed) {
		NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

		/* schedule the job in the background, to give multiple resolve events time
		 * to complete. */
		nm_clear_g_source (&priv->link_config_delayed_id);
		priv->link_config_delayed_id = g_idle_add_full (G_PRIORITY_DEFAULT_IDLE + 1,
		                                                link_config_delayed_resolver_cb,
		                                                self,
		                                                NULL);
	}
}

static void
_peers_resolve_start (NMDeviceWireGuard *self,
                      PeerData *peer_data)
{
	gs_unref_object GResolver *resolver = NULL;
	const char *host;

	resolver = g_resolver_get_default ();

	nm_assert (!peer_data->ep_resolv.cancellable);

	peer_data->ep_resolv.cancellable = g_cancellable_new ();

	/* set a special next-try timestamp. It is positive, and indicates
	 * that we are in the process of trying.
	 * This timestamp however already lies in the past, but that is correct,
	 * because we are currently in the process of trying. We will determine
	 * a next-try timestamp once the try completes. */
	peer_data->ep_resolv.next_try_at_nsec = NEXT_TRY_AT_NSEC_PAST;

	host = nm_sock_addr_endpoint_get_host (_nm_wireguard_peer_get_endpoint (peer_data->peer));

	g_resolver_lookup_by_name_async (resolver,
	                                 host,
	                                 peer_data->ep_resolv.cancellable,
	                                 _peers_resolve_cb,
	                                 peer_data);

	_LOGT (LOGD_DEVICE, "wireguard-peer[%s]: resolving name \"%s\" for endpoint \"%s\"...",
	       nm_wireguard_peer_get_public_key (peer_data->peer),
	       host,
	       nm_wireguard_peer_get_endpoint (peer_data->peer));
}

static void
_peers_resolve_reresolve_all (NMDeviceWireGuard *self)
{
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);
	PeerData *peer_data;

	c_list_for_each_entry (peer_data, &priv->lst_peers_head, lst_peers) {
		if (peer_data->ep_resolv.cancellable) {
			/* remember to retry when the currently ongoing request completes. */
			peer_data->ep_resolv.next_try_at_nsec = NEXT_TRY_AT_NSEC_ASAP;
		} else if (peer_data->ep_resolv.next_try_at_nsec <= 0) {
			/* this peer does not require resolving the name. Skip it. */
		} else {
			/* we have a next-try scheduled. Restart right away. */
			peer_data->ep_resolv.resolv_fail_count = 0;
			_peers_resolve_start (self, peer_data);
		}
	}
}

static gboolean
_peers_update (NMDeviceWireGuard *self,
               PeerData *peer_data,
               NMWireGuardPeer *peer,
               gboolean force_update)
{
	nm_auto_unref_wgpeer NMWireGuardPeer *old_peer = NULL;
	NMSockAddrEndpoint *old_endpoint;
	NMSockAddrEndpoint *endpoint;
	gboolean endpoint_changed = FALSE;
	gboolean changed;
	NMSockAddrUnion sockaddr;
	gboolean sockaddr_fixed;
	char sockaddr_sbuf[100];

	nm_assert (peer);
	nm_assert (nm_wireguard_peer_is_sealed (peer));

	if (   peer == peer_data->peer
	    && !force_update)
		return FALSE;

	changed = (nm_wireguard_peer_cmp (peer,
	                                  peer_data->peer,
	                                  NM_SETTING_COMPARE_FLAG_EXACT) != 0);

	old_peer = peer_data->peer;
	peer_data->peer = nm_wireguard_peer_ref (peer);

	old_endpoint = old_peer ? _nm_wireguard_peer_get_endpoint (old_peer) : NULL;
	endpoint     = peer     ? _nm_wireguard_peer_get_endpoint (peer)     : NULL;

	endpoint_changed = (   endpoint != old_endpoint
	                    && (   !old_endpoint
	                        || !endpoint
	                        || !nm_streq (nm_sock_addr_endpoint_get_endpoint (old_endpoint),
	                                      nm_sock_addr_endpoint_get_endpoint (endpoint))));

	if (   !force_update
	    && !endpoint_changed) {
		/* nothing to do. */
		return changed;
	}

	sockaddr = (NMSockAddrUnion) NM_SOCK_ADDR_UNION_INIT_UNSPEC;
	sockaddr_fixed = TRUE;
	if (   endpoint
	    && nm_sock_addr_endpoint_get_host (endpoint)) {
		if (!nm_sock_addr_endpoint_get_fixed_sockaddr (endpoint, &sockaddr)) {
			/* we have an endpoint, but it's not a static IP address. We need to resolve
			 * the names. */
			sockaddr_fixed = FALSE;
		}
	}

	if (nm_sock_addr_union_cmp (&peer_data->ep_resolv.sockaddr, &sockaddr) != 0)
		changed = TRUE;

	nm_clear_g_cancellable (&peer_data->ep_resolv.cancellable);

	peer_data->ep_resolv = (PeerEndpointResolveData) {
		.sockaddr          = sockaddr,
		.resolv_fail_count = 0,
		.cancellable       = NULL,
		.next_try_at_nsec  = 0,
	};

	if (!endpoint) {
		_LOGT (LOGD_DEVICE, "wireguard-peer[%s]: no endpoint configured",
		       nm_wireguard_peer_get_public_key (peer_data->peer));
	} else if (!nm_sock_addr_endpoint_get_host (endpoint)) {
		_LOGT (LOGD_DEVICE, "wireguard-peer[%s]: invalid endpoint \"%s\"",
		       nm_wireguard_peer_get_public_key (peer_data->peer),
		       nm_sock_addr_endpoint_get_endpoint (endpoint));
	} else if (sockaddr_fixed) {
		_LOGT (LOGD_DEVICE, "wireguard-peer[%s]: fixed endpoint \"%s\" (%s)",
		       nm_wireguard_peer_get_public_key (peer_data->peer),
		       nm_sock_addr_endpoint_get_endpoint (endpoint),
		       nm_sock_addr_union_to_string (&peer_data->ep_resolv.sockaddr, sockaddr_sbuf, sizeof (sockaddr_sbuf)));
	} else
		_peers_resolve_start (self, peer_data);

	return changed;
}

static void
_peers_remove_all (NMDeviceWireGuardPrivate *priv)
{
	PeerData *peer_data;

	while ((peer_data = c_list_first_entry (&priv->lst_peers_head, PeerData, lst_peers)))
		_peers_remove (priv, peer_data);
}

static void
_peers_update_all (NMDeviceWireGuard *self,
                   NMSettingWireGuard *s_wg,
                   gboolean *out_peers_removed)
{
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);
	PeerData *peer_data_safe;
	PeerData *peer_data;
	guint i, n;
	gboolean peers_removed = FALSE;

	c_list_for_each_entry (peer_data, &priv->lst_peers_head, lst_peers)
		peer_data->dirty_update_all = TRUE;

	n = nm_setting_wireguard_get_peers_len (s_wg);
	for (i = 0; i < n; i++) {
		NMWireGuardPeer *peer = nm_setting_wireguard_get_peer (s_wg, i);
		gboolean added = FALSE;

		peer_data = _peers_find (priv, peer);
		if (!peer_data) {
			peer_data = _peers_add (self, peer);
			added = TRUE;
		}
		_peers_update (self, peer_data, peer, added);
		peer_data->dirty_update_all = FALSE;
	}

	c_list_for_each_entry_safe (peer_data, peer_data_safe, &priv->lst_peers_head, lst_peers) {
		if (peer_data->dirty_update_all) {
			_peers_remove (priv, peer_data);
			peers_removed = TRUE;
		}
	}

	NM_SET_OUT (out_peers_removed, peers_removed);
}

static NMPWireGuardPeer *
_peers_get_platform_list (NMDeviceWireGuardPrivate *priv,
                          guint *out_len,
                          GArray **out_allowed_ips_data)
{
	gs_free NMPWireGuardPeer *plpeers = NULL;
	gs_unref_array GArray *allowed_ips = NULL;
	PeerData *peer_data;
	guint i_good;
	guint n_aip;
	guint i_aip;
	guint len;
	guint i;

	nm_assert (out_allowed_ips_data && !*out_allowed_ips_data);

	len = g_hash_table_size (priv->peers);

	nm_assert (len == c_list_length (&priv->lst_peers_head));

	if (len == 0) {
		*out_len = 0;
		return NULL;
	}

	plpeers = g_new0 (NMPWireGuardPeer, len);

	i_good = 0;
	c_list_for_each_entry (peer_data, &priv->lst_peers_head, lst_peers) {
		NMPWireGuardPeer *plp = &plpeers[i_good];
		NMSettingSecretFlags psk_secret_flags;

		if (!_nm_utils_wireguard_decode_key (nm_wireguard_peer_get_public_key (peer_data->peer),
		                                     sizeof (plp->public_key),
		                                     plp->public_key))
			continue;

		plp->persistent_keepalive_interval = nm_wireguard_peer_get_persistent_keepalive (peer_data->peer);

		/* if the peer has an endpoint but it is not yet resolved (not ready),
		 * we still configure it and leave the endpoint unspecified. Later,
		 * when we can resolve the endpoint, we will update. */
		plp->endpoint = peer_data->ep_resolv.sockaddr;

		psk_secret_flags = nm_wireguard_peer_get_preshared_key_flags (peer_data->peer);
		if (!NM_FLAGS_HAS (psk_secret_flags, NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
			if (!_nm_utils_wireguard_decode_key (nm_wireguard_peer_get_preshared_key (peer_data->peer),
			                                     sizeof (plp->preshared_key),
			                                     plp->preshared_key))
				goto skip;
		}

		n_aip = nm_wireguard_peer_get_allowed_ips_len (peer_data->peer);

		if (n_aip > 0) {
			if (!allowed_ips)
				allowed_ips = g_array_new (FALSE, FALSE, sizeof (NMPWireGuardAllowedIP));

			plp->_construct_idx_start = allowed_ips->len;
			for (i_aip = 0; i_aip < n_aip; i_aip++) {
				const char *aip;
				NMIPAddr addrbin = { 0 };
				int addr_family;
				gboolean valid;
				int prefix;

				aip = nm_wireguard_peer_get_allowed_ip (peer_data->peer, i_aip, &valid);
				if (   !valid
				    || !nm_utils_parse_inaddr_prefix_bin (AF_UNSPEC,
				                                          aip,
				                                          &addr_family,
				                                          &addrbin,
				                                          &prefix)) {
					/* the address is really not expected to be invalid, because then
					 * the connection would not verify. Anyway, silently skip it. */
					continue;
				}

				if (prefix == -1)
					prefix = addr_family == AF_INET ? 32 : 128;

				g_array_append_val (allowed_ips,
				                    ((NMPWireGuardAllowedIP) {
				                        .family = addr_family,
				                        .mask = prefix,
				                        .addr = addrbin,
				                    }));
			}
			plp->_construct_idx_end = allowed_ips->len;
		}

		i_good++;
		continue;

skip:
		memset (plp, 0, sizeof (*plp));
	}

	for (i = 0; i < i_good; i++) {
		NMPWireGuardPeer *plp = &plpeers[i];
		guint l;

		if (plp->_construct_idx_end == 0) {
			nm_assert (plp->_construct_idx_start == 0);
			plp->allowed_ips = NULL;
			plp->allowed_ips_len = 0;
		} else {
			nm_assert (plp->_construct_idx_start < plp->_construct_idx_end);
			l = plp->_construct_idx_end - plp->_construct_idx_start;
			plp->allowed_ips = &g_array_index (allowed_ips, NMPWireGuardAllowedIP, plp->_construct_idx_start);
			plp->allowed_ips_len = l;
		}
	}

	*out_len = i_good;
	*out_allowed_ips_data = g_steal_pointer (&allowed_ips);
	return i_good > 0 ? g_steal_pointer (&plpeers) : NULL;
}

/*****************************************************************************/

static void
update_properties (NMDevice *device)
{
	NMDeviceWireGuard *self;
	NMDeviceWireGuardPrivate *priv;
	const NMPlatformLink *plink;
	const NMPlatformLnkWireGuard *props = NULL;
	int ifindex;

	g_return_if_fail (NM_IS_DEVICE_WIREGUARD (device));
	self = NM_DEVICE_WIREGUARD (device);
	priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

	ifindex = nm_device_get_ifindex (device);
	props = nm_platform_link_get_lnk_wireguard (nm_device_get_platform (device), ifindex, &plink);
	if (!props) {
		_LOGW (LOGD_PLATFORM, "could not get wireguard properties");
		return;
	}

	g_object_freeze_notify (G_OBJECT (device));

#define CHECK_PROPERTY_CHANGED(field, prop) \
	G_STMT_START { \
		if (priv->lnk_curr.field != props->field) { \
			priv->lnk_curr.field = props->field; \
			_notify (self, prop); \
		} \
	} G_STMT_END

#define CHECK_PROPERTY_CHANGED_ARRAY(field, prop) \
	G_STMT_START { \
		if (memcmp (&priv->lnk_curr.field, &props->field, sizeof (priv->lnk_curr.field)) != 0) { \
			memcpy (&priv->lnk_curr.field, &props->field, sizeof (priv->lnk_curr.field)); \
			_notify (self, prop); \
		} \
	} G_STMT_END

	CHECK_PROPERTY_CHANGED_ARRAY (public_key, PROP_PUBLIC_KEY);
	CHECK_PROPERTY_CHANGED (listen_port, PROP_LISTEN_PORT);
	CHECK_PROPERTY_CHANGED (fwmark, PROP_FWMARK);

	g_object_thaw_notify (G_OBJECT (device));
}

static void
link_changed (NMDevice *device,
              const NMPlatformLink *pllink)
{
	NM_DEVICE_CLASS (nm_device_wireguard_parent_class)->link_changed (device, pllink);
	update_properties (device);
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_IS_SOFTWARE;
}

/*****************************************************************************/

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	const char *iface = nm_device_get_iface (device);
	int r;

	g_return_val_if_fail (iface, FALSE);

	r = nm_platform_link_wireguard_add (nm_device_get_platform (device), iface, out_plink);
	if (r < 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create WireGuard interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_strerror (r));
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static void
_secrets_cancel (NMDeviceWireGuard *self)
{
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

	if (priv->secrets_call_id)
		nm_act_request_cancel_secrets (NULL, priv->secrets_call_id);
	nm_assert (!priv->secrets_call_id);
}

static void
_secrets_cb (NMActRequest *req,
             NMActRequestGetSecretsCallId *call_id,
             NMSettingsConnection *connection,
             GError *error,
             gpointer user_data)
{
	NMDeviceWireGuard *self = NM_DEVICE_WIREGUARD (user_data);
	NMDevice *device = NM_DEVICE (self);
	NMDeviceWireGuardPrivate *priv;

	g_return_if_fail (NM_IS_DEVICE_WIREGUARD (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

	g_return_if_fail (priv->secrets_call_id == call_id);

	priv->secrets_call_id = NULL;

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	g_return_if_fail (req == nm_device_get_act_request (device));
	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);
	g_return_if_fail (nm_act_request_get_settings_connection (req) == connection);

	if (error) {
		_LOGW (LOGD_ETHER, "%s", error->message);
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_NO_SECRETS);
	} else
		nm_device_activate_schedule_stage1_device_prepare (device);
}

static void
_secrets_get_secrets (NMDeviceWireGuard *self,
                      const char *setting_name,
                      NMSecretAgentGetSecretsFlags flags)
{
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);
	NMActRequest *req;

	_secrets_cancel (self);

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	priv->secrets_call_id = nm_act_request_get_secrets (req,
	                                                    TRUE,
	                                                    setting_name,
	                                                    flags,
	                                                    NULL,
	                                                    _secrets_cb,
	                                                    self);
	g_return_if_fail (priv->secrets_call_id);
}

static NMActStageReturn
_secrets_handle_auth_or_fail (NMDeviceWireGuard *self,
                              NMActRequest *req,
                              gboolean new_secrets)
{
	NMConnection *applied_connection;
	const char *setting_name;

	if (!nm_device_auth_retries_try_next (NM_DEVICE (self)))
		return NM_ACT_STAGE_RETURN_FAILURE;

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);

	nm_active_connection_clear_secrets (NM_ACTIVE_CONNECTION (req));

	applied_connection = nm_act_request_get_applied_connection (req);
	setting_name = nm_connection_need_secrets (applied_connection, NULL);
	if (!setting_name) {
		_LOGI (LOGD_DEVICE, "Cleared secrets, but setting didn't need any secrets.");
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	_secrets_get_secrets (self,
	                      setting_name,
	                        NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION
	                      | (new_secrets ? NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW : 0));
	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/

static void
_dns_config_changed (NMDnsManager *dns_manager, NMDeviceWireGuard *self)
{
	/* when the DNS configuration changes, we re-resolve the peer addresses.
	 *
	 * Possibly, we should also do that when the default-route changes, but it's
	 * hard to figure out when that happens. */
	_peers_resolve_reresolve_all (self);
}

/*****************************************************************************/

static gboolean
link_config_delayed (NMDeviceWireGuard *self,
                     const char *reason)
{
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

	priv->link_config_delayed_id = 0;
	link_config (self, TRUE, FALSE, reason, NULL);
	return G_SOURCE_REMOVE;
}

static gboolean
link_config_delayed_ratelimit_cb (gpointer user_data)
{
	return link_config_delayed (user_data, "again");
}

static gboolean
link_config_delayed_resolver_cb (gpointer user_data)
{
	return link_config_delayed (user_data, "resolver-update");
}

static NMActStageReturn
link_config (NMDeviceWireGuard *self,
             gboolean allow_rate_limit,
             gboolean fail_state_on_failure,
             const char *reason,
             NMDeviceStateReason *out_failure_reason)
{
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);
	NMSettingWireGuard *s_wg;
	NMConnection *connection;
	NMActStageReturn ret;
	gs_unref_array GArray *allowed_ips_data = NULL;
	gs_free NMPWireGuardPeer *plpeers = NULL;
	guint plpeers_len;
	const char *setting_name;
	NMDeviceStateReason failure_reason;
	gboolean peers_removed;
	gboolean replace_peers;
	gint64 now;
	int ifindex;
	int r;

	/* we currently don't allow rate-limiting and fail the state (because the timeout
	 * handler doesn't know whether to fail the state. It's not needed anyway. */
	nm_assert (!fail_state_on_failure || !allow_rate_limit);

	if (!priv->dns_manager) {
		priv->dns_manager = g_object_ref (nm_dns_manager_get ());
		g_signal_connect (priv->dns_manager, NM_DNS_MANAGER_CONFIG_CHANGED, G_CALLBACK (_dns_config_changed), self);
	}

	connection = nm_device_get_applied_connection (NM_DEVICE (self));
	s_wg = NM_SETTING_WIREGUARD (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIREGUARD));
	g_return_val_if_fail (s_wg, NM_ACT_STAGE_RETURN_FAILURE);

	nm_clear_g_source (&priv->link_config_delayed_id);
	now = nm_utils_get_monotonic_timestamp_ns ();
	if (   allow_rate_limit
	    && priv->link_config_last_at != 0
	    && now < priv->link_config_last_at + LINK_CONFIG_RATE_LIMIT_NSEC) {
		/* we ratelimit calls to link_config(), because we call this whenver a resolver
		 * completes. */
		_LOGT (LOGD_DEVICE, "wireguard link config (%s) (postponed)", reason);
		priv->link_config_delayed_id = g_timeout_add (NM_MAX ((priv->link_config_last_at + LINK_CONFIG_RATE_LIMIT_NSEC - now) / NM_UTILS_NS_PER_MSEC,
		                                                      (gint64) 1),
		                                              link_config_delayed_ratelimit_cb,
		                                              self);
		return NM_ACT_STAGE_RETURN_POSTPONE;
	}
	priv->link_config_last_at = now;

	_LOGT (LOGD_DEVICE, "wireguard link config (%s)...", reason);

	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		NMActRequest *req = nm_device_get_act_request (NM_DEVICE (self));

		_LOGD (LOGD_DEVICE,
		       "Activation: connection '%s' has security, but secrets are required.",
		       nm_connection_get_id (connection));

		ret = _secrets_handle_auth_or_fail (self, req, FALSE);
		if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
			return ret;
		if (ret != NM_ACT_STAGE_RETURN_SUCCESS) {
			failure_reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
			goto out_ret;
		}
	}

	ifindex = nm_device_get_ip_ifindex (NM_DEVICE (self));
	if (ifindex <= 0) {
		failure_reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		goto out_ret_fail;
	}

	priv->lnk_want = (NMPlatformLnkWireGuard) {
		.listen_port = nm_setting_wireguard_get_listen_port (s_wg),
		.fwmark      = nm_setting_wireguard_get_fwmark (s_wg),
	};

	if (!_nm_utils_wireguard_decode_key (nm_setting_wireguard_get_private_key (s_wg),
	                                     sizeof (priv->lnk_want.private_key),
	                                     priv->lnk_want.private_key)) {
		_LOGD (LOGD_DEVICE, "the provided private-key is invalid");
		failure_reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
		goto out_ret_fail;
	}

	_peers_update_all (self, s_wg, &peers_removed);

	plpeers = _peers_get_platform_list (priv, &plpeers_len, &allowed_ips_data);

	replace_peers =    peers_removed
	                || !priv->link_config_is_update;

	r = nm_platform_link_wireguard_change (nm_device_get_platform (NM_DEVICE (self)),
	                                       ifindex,
	                                       &priv->lnk_want,
	                                       plpeers,
	                                       plpeers_len,
	                                       replace_peers);

	nm_explicit_bzero (plpeers, sizeof (plpeers) * plpeers_len);

	if (r < 0) {
		failure_reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		goto out_ret_fail;
	}

	/* future changes are marked to be an update only. */
	priv->link_config_is_update = TRUE;

	NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_NONE);
	return NM_ACT_STAGE_RETURN_SUCCESS;

out_ret_fail:
	ret = NM_ACT_STAGE_RETURN_FAILURE;
out_ret:
	NM_SET_OUT (out_failure_reason, failure_reason);
	if (fail_state_on_failure) {
		nm_device_state_changed (NM_DEVICE (self),
		                         NM_DEVICE_STATE_FAILED,
		                         failure_reason);
	}
	return ret;
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	return link_config (NM_DEVICE_WIREGUARD (device), FALSE, TRUE, "configure", out_failure_reason);
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason)
{
	NMDeviceWireGuardPrivate *priv;

	if (new_state <= NM_DEVICE_STATE_ACTIVATED)
		return;

	priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (device);

	_peers_remove_all (priv);
	nm_explicit_bzero (priv->lnk_want.private_key, sizeof (priv->lnk_want.private_key));
	_secrets_cancel (NM_DEVICE_WIREGUARD (device));
	priv->link_config_is_update = FALSE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceWireGuard *self = NM_DEVICE_WIREGUARD (object);
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_PUBLIC_KEY:
		g_value_take_variant (value,
		                      g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                                 priv->lnk_curr.public_key,
		                                                 sizeof (priv->lnk_curr.public_key),
		                                                 1));
		break;
	case PROP_LISTEN_PORT:
		g_value_set_uint (value, priv->lnk_curr.listen_port);
		break;
	case PROP_FWMARK:
		g_value_set_uint (value, priv->lnk_curr.fwmark);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_device_wireguard_init (NMDeviceWireGuard *self)
{
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

	c_list_init (&priv->lst_peers_head);
	priv->peers = g_hash_table_new (_peer_data_hash, _peer_data_equal);
}

static void
dispose (GObject *object)
{
	NMDeviceWireGuard *self = NM_DEVICE_WIREGUARD (object);
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

	_secrets_cancel (self);

	_peers_remove_all (priv);

	G_OBJECT_CLASS (nm_device_wireguard_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceWireGuard *self = NM_DEVICE_WIREGUARD (object);
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

	nm_explicit_bzero (priv->lnk_want.private_key, sizeof (priv->lnk_want.private_key));
	nm_explicit_bzero (priv->lnk_curr.private_key, sizeof (priv->lnk_curr.private_key));

	if (priv->dns_manager) {
		g_signal_handlers_disconnect_by_func (priv->dns_manager, _dns_config_changed, self);
		g_object_unref (priv->dns_manager);
	}

	G_OBJECT_CLASS (nm_device_wireguard_parent_class)->finalize (object);
}

static const NMDBusInterfaceInfoExtended interface_info_device_wireguard = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_WIREGUARD,
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("PublicKey",  "ay", NM_DEVICE_WIREGUARD_PUBLIC_KEY),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("ListenPort", "q", NM_DEVICE_WIREGUARD_LISTEN_PORT),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("FwMark",     "u", NM_DEVICE_WIREGUARD_FWMARK),
		),
	),
};

static void
nm_device_wireguard_class_init (NMDeviceWireGuardClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_wireguard);

	device_class->connection_type_supported = NM_SETTING_WIREGUARD_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_WIREGUARD_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_WIREGUARD);

	device_class->state_changed = device_state_changed;
	device_class->create_and_realize = create_and_realize;
	device_class->act_stage2_config = act_stage2_config;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->link_changed = link_changed;

	obj_properties[PROP_PUBLIC_KEY] =
	    g_param_spec_variant (NM_DEVICE_WIREGUARD_PUBLIC_KEY,
	                          "", "",
	                          G_VARIANT_TYPE ("ay"),
	                          NULL,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_LISTEN_PORT] =
	    g_param_spec_uint (NM_DEVICE_WIREGUARD_LISTEN_PORT,
	                       "", "",
	                       0, G_MAXUINT16, 0,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_FWMARK] =
	    g_param_spec_uint (NM_DEVICE_WIREGUARD_FWMARK,
	                       "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*************************************************************/

#define NM_TYPE_WIREGUARD_DEVICE_FACTORY (nm_wireguard_device_factory_get_type ())
#define NM_WIREGUARD_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIREGUARD_DEVICE_FACTORY, NMWireGuardDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_WIREGUARD,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "WireGuard",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_WIREGUARD,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_WIREGUARD,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (WIREGUARD, WireGuard, wireguard,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_WIREGUARD)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_WIREGUARD_SETTING_NAME),
	factory_class->create_device = create_device;
)
