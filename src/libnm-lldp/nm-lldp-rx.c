/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-lldp-rx.h"

#include <arpa/inet.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>

#include "libnm-glib-aux/nm-io-utils.h"
#include "libnm-glib-aux/nm-time-utils.h"
#include "nm-lldp-network.h"
#include "nm-lldp-neighbor.h"
#include "nm-lldp-rx-internal.h"

#define LLDP_DEFAULT_NEIGHBORS_MAX 128U

/*****************************************************************************/

static void lldp_rx_start_timer(NMLldpRX *lldp_rx, NMLldpNeighbor *neighbor);

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE(nm_lldp_rx_event_to_string,
                           NMLldpRXEvent,
                           NM_UTILS_LOOKUP_DEFAULT_WARN("<unknown>"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_LLDP_RX_EVENT_ADDED, "added"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_LLDP_RX_EVENT_REMOVED, "removed"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_LLDP_RX_EVENT_UPDATED, "updated"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_LLDP_RX_EVENT_REFRESHED, "refreshed"),
                           NM_UTILS_LOOKUP_ITEM_IGNORE_OTHER());

/*****************************************************************************/

#define nm_assert_is_lldp_rx(lldp_rx)       \
    G_STMT_START                            \
    {                                       \
        NMLldpRX *_lldp_rx = (lldp_rx);     \
                                            \
        nm_assert(_lldp_rx);                \
        nm_assert(_lldp_rx->ref_count > 0); \
    }                                       \
    G_STMT_END

/*****************************************************************************/

/* This needs to be first. Check nm_lldp_rx_get_id(). */
G_STATIC_ASSERT(G_STRUCT_OFFSET(NMLldpNeighbor, id) == 0);

/*****************************************************************************/

static void
lldp_rx_callback(NMLldpRX *lldp_rx, NMLldpRXEvent event, NMLldpNeighbor *n)
{
    nm_assert_is_lldp_rx(lldp_rx);
    nm_assert(event >= 0 && event < _NM_LLDP_RX_EVENT_MAX);

    _LOG2D(lldp_rx, "invoking callback for '%s' event", nm_lldp_rx_event_to_string(event));
    lldp_rx->config.callback(lldp_rx, event, n, lldp_rx->config.userdata);
}

static gboolean
lldp_rx_make_space(NMLldpRX *lldp_rx, gboolean flush, size_t extra)
{
    nm_auto(nm_lldp_rx_unrefp) NMLldpRX *lldp_rx_alive = NULL;
    gint64                               now_usec      = 0;
    gboolean                             changed       = FALSE;
    size_t                               max;

    /* Remove all entries that are past their TTL, and more until at least the specified number of extra entries
     * are free. */

    max = (!flush && lldp_rx->config.neighbors_max > extra)
              ? (lldp_rx->config.neighbors_max - extra)
              : 0u;

    for (;;) {
        NMLldpNeighbor *n;

        nm_assert(g_hash_table_size(lldp_rx->neighbor_by_id)
                  == nm_prioq_size(&lldp_rx->neighbor_by_expiry));

        n = nm_prioq_peek(&lldp_rx->neighbor_by_expiry);
        if (!n)
            break;

        if (nm_prioq_size(&lldp_rx->neighbor_by_expiry) > max) {
            /* drop it. */
        } else {
            if (n->until_usec > nm_utils_get_monotonic_timestamp_usec_cached(&now_usec))
                break;
        }

        if (flush) {
            changed = TRUE;
            nm_lldp_neighbor_unlink(n);
        } else {
            nm_auto(nm_lldp_neighbor_unrefp) NMLldpNeighbor *n_alive = NULL;

            if (!changed) {
                lldp_rx_alive = nm_lldp_rx_ref(lldp_rx);
                changed       = TRUE;
            }
            n_alive = nm_lldp_neighbor_ref(n);
            nm_lldp_neighbor_unlink(n);
            lldp_rx_callback(lldp_rx, NM_LLDP_RX_EVENT_REMOVED, n);
        }
    }

    return changed;
}

static bool
lldp_rx_keep_neighbor(NMLldpRX *lldp_rx, NMLldpNeighbor *n)
{
    nm_assert_is_lldp_rx(lldp_rx);
    nm_assert(n);

    /* Don't keep data with a zero TTL */
    if (n->ttl <= 0)
        return FALSE;

    /* Filter out data from the filter address */
    if (!nm_ether_addr_is_zero(&lldp_rx->config.filter_address)
        && nm_ether_addr_equal(&lldp_rx->config.filter_address, &n->source_address))
        return FALSE;

    /* Only add if the neighbor has a capability we are interested in. Note that we also store all neighbors with
     * no caps field set. */
    if (n->has_capabilities && (n->enabled_capabilities & lldp_rx->config.capability_mask) == 0)
        return FALSE;

    /* Keep everything else */
    return TRUE;
}

static void
lldp_rx_add_neighbor(NMLldpRX *lldp_rx, NMLldpNeighbor *n)
{
    nm_auto(nm_lldp_neighbor_unrefp) NMLldpNeighbor *old_alive = NULL;
    NMLldpNeighbor                                  *old;
    gboolean                                         keep;

    nm_assert_is_lldp_rx(lldp_rx);
    nm_assert(n);
    nm_assert(!n->lldp_rx);

    keep = lldp_rx_keep_neighbor(lldp_rx, n);

    /* First retrieve the old entry for this MSAP */
    old = g_hash_table_lookup(lldp_rx->neighbor_by_id, n);
    if (old) {
        old_alive = nm_lldp_neighbor_ref(old);

        if (!keep) {
            nm_lldp_neighbor_unlink(old);
            lldp_rx_callback(lldp_rx, NM_LLDP_RX_EVENT_REMOVED, old);
            return;
        }

        if (nm_lldp_neighbor_equal(n, old)) {
            /* Is this equal, then restart the TTL counter, but don't do anything else. */
            old->timestamp_usec = n->timestamp_usec;
            lldp_rx_start_timer(lldp_rx, old);
            lldp_rx_callback(lldp_rx, NM_LLDP_RX_EVENT_REFRESHED, old);
            return;
        }

        /* Data changed, remove the old entry, and add a new one */
        nm_lldp_neighbor_unlink(old);

    } else if (!keep)
        return;

    /* Then, make room for at least one new neighbor */
    lldp_rx_make_space(lldp_rx, FALSE, 1);

    if (!g_hash_table_add(lldp_rx->neighbor_by_id, n))
        nm_assert_not_reached();

    nm_prioq_put(&lldp_rx->neighbor_by_expiry, n, &n->prioq_idx);

    n->lldp_rx = lldp_rx;

    lldp_rx_start_timer(lldp_rx, n);
    lldp_rx_callback(lldp_rx, old ? NM_LLDP_RX_EVENT_UPDATED : NM_LLDP_RX_EVENT_ADDED, n);
}

static gboolean
lldp_rx_receive_datagram(int fd, GIOCondition condition, gpointer user_data)

{
    NMLldpRX                                        *lldp_rx = user_data;
    nm_auto(nm_lldp_neighbor_unrefp) NMLldpNeighbor *n       = NULL;
    ssize_t                                          space;
    ssize_t                                          length;
    struct timespec                                  ts;
    gint64                                           ts_usec;
    gint64                                           now_usec;
    gint64                                           now_usec_rt;
    gint64                                           now_usec_bt;
    int                                              r;

    nm_assert_is_lldp_rx(lldp_rx);
    nm_assert(lldp_rx->fd == fd);

    _LOG2T(lldp_rx, "fd ready");

    space = nm_fd_next_datagram_size(lldp_rx->fd);
    if (space < 0) {
        if (!NM_ERRNO_IS_TRANSIENT(space) && !NM_ERRNO_IS_DISCONNECT(space)) {
            _LOG2D(lldp_rx,
                   "Failed to determine datagram size to read, ignoring: %s",
                   nm_strerror_native(-space));
        }
        return G_SOURCE_CONTINUE;
    }

    n = nm_lldp_neighbor_new(space);

    length = recv(lldp_rx->fd, NM_LLDP_NEIGHBOR_RAW(n), n->raw_size, MSG_DONTWAIT);
    if (length < 0) {
        if (!NM_ERRNO_IS_TRANSIENT(errno) && !NM_ERRNO_IS_DISCONNECT(errno)) {
            _LOG2D(lldp_rx,
                   "Failed to read LLDP datagram, ignoring: %s",
                   nm_strerror_native(errno));
        }
        return G_SOURCE_CONTINUE;
    }

    if ((size_t) length != n->raw_size) {
        _LOG2D(lldp_rx, "Packet size mismatch, ignoring");
        return G_SOURCE_CONTINUE;
    }

    /* Try to get the timestamp of this packet if it is known */
    if (ioctl(lldp_rx->fd, SIOCGSTAMPNS, &ts) >= 0
        && (ts_usec = nm_utils_timespec_to_usec(&ts)) < G_MAXINT64
        && (now_usec_bt = nm_utils_clock_gettime_usec(CLOCK_BOOTTIME)) >= 0
        && (now_usec_rt = nm_utils_clock_gettime_usec(CLOCK_REALTIME)) >= 0) {
        gint64 t;

        now_usec = nm_utils_monotonic_timestamp_from_boottime(now_usec_bt, 1000);
        ts_usec  = nm_time_map_clock(ts_usec, now_usec_rt, now_usec_bt);

        t = now_usec;
        if (ts_usec >= 0) {
            ts_usec = nm_utils_monotonic_timestamp_from_boottime(ts_usec, 1000);
            if (ts_usec > NM_UTILS_USEC_PER_SEC && ts_usec < now_usec)
                t = ts_usec;
        }

        n->timestamp_usec = t;
    } else
        n->timestamp_usec = nm_utils_get_monotonic_timestamp_usec();

    r = nm_lldp_neighbor_parse(n);
    if (r < 0) {
        _LOG2D(lldp_rx, "Failure parsing invalid LLDP datagram.");
        return G_SOURCE_CONTINUE;
    }

    _LOG2D(lldp_rx, "Successfully processed LLDP datagram.");
    lldp_rx_add_neighbor(lldp_rx, n);

    return G_SOURCE_CONTINUE;
}

static void
lldp_rx_reset(NMLldpRX *lldp_rx)
{
    nm_clear_g_source_inst(&lldp_rx->timer_event_source);
    nm_clear_g_source_inst(&lldp_rx->io_event_source);
    nm_clear_fd(&lldp_rx->fd);

    lldp_rx_make_space(lldp_rx, TRUE, 0);

    nm_assert(g_hash_table_size(lldp_rx->neighbor_by_id) == 0);
    nm_assert(nm_prioq_size(&lldp_rx->neighbor_by_expiry) == 0);
}

gboolean
nm_lldp_rx_is_running(NMLldpRX *lldp_rx)
{
    if (!lldp_rx)
        return FALSE;

    return lldp_rx->fd >= 0;
}

int
nm_lldp_rx_start(NMLldpRX *lldp_rx)
{
    int r;

    g_return_val_if_fail(lldp_rx, -EINVAL);
    nm_assert(lldp_rx->main_context);
    nm_assert(lldp_rx->config.ifindex > 0);

    if (nm_lldp_rx_is_running(lldp_rx))
        return 0;

    nm_assert(!lldp_rx->io_event_source);

    r = nm_lldp_network_bind_raw_socket(lldp_rx->config.ifindex);
    if (r < 0) {
        _LOG2D(lldp_rx, "start failed to bind socket (%s)", nm_strerror_native(-r));
        return r;
    }

    lldp_rx->fd = r;

    lldp_rx->io_event_source = nm_g_source_attach(nm_g_unix_fd_source_new(lldp_rx->fd,
                                                                          G_IO_IN,
                                                                          G_PRIORITY_DEFAULT,
                                                                          lldp_rx_receive_datagram,
                                                                          lldp_rx,
                                                                          NULL),
                                                  lldp_rx->main_context);

    _LOG2D(lldp_rx, "started (fd %d)", lldp_rx->fd);
    return 1;
}

int
nm_lldp_rx_stop(NMLldpRX *lldp_rx)
{
    if (!nm_lldp_rx_is_running(lldp_rx))
        return 0;

    _LOG2D(lldp_rx, "stopping");

    lldp_rx_reset(lldp_rx);
    return 1;
}

static gboolean
on_timer_event(gpointer user_data)
{
    NMLldpRX *lldp_rx = user_data;

    lldp_rx_make_space(lldp_rx, FALSE, 0);
    lldp_rx_start_timer(lldp_rx, NULL);
    return G_SOURCE_CONTINUE;
}

static void
lldp_rx_start_timer(NMLldpRX *lldp_rx, NMLldpNeighbor *neighbor)
{
    NMLldpNeighbor *n;
    gint64          timeout_msec;

    nm_assert_is_lldp_rx(lldp_rx);

    nm_clear_g_source_inst(&lldp_rx->timer_event_source);

    if (neighbor)
        nm_lldp_neighbor_start_ttl(neighbor);

    n = nm_prioq_peek(&lldp_rx->neighbor_by_expiry);
    if (!n)
        return;

    timeout_msec = (n->until_usec / 1000) - nm_utils_get_monotonic_timestamp_msec();

    lldp_rx->timer_event_source =
        nm_g_source_attach(nm_g_timeout_source_new(NM_CLAMP(timeout_msec, 0, G_MAXUINT),
                                                   G_PRIORITY_DEFAULT,
                                                   on_timer_event,
                                                   lldp_rx,
                                                   NULL),
                           lldp_rx->main_context);
}

static inline int
neighbor_compare_func(gconstpointer p_a, gconstpointer p_b, gpointer user_data)
{
    NMLldpNeighbor *const *a = p_a;
    NMLldpNeighbor *const *b = p_b;

    nm_assert(a);
    nm_assert(b);
    nm_assert(*a);
    nm_assert(*b);

    return nm_lldp_neighbor_id_cmp(&(*a)->id, &(*b)->id);
}

NMLldpNeighbor **
nm_lldp_rx_get_neighbors(NMLldpRX *lldp_rx, guint *out_len)
{
    g_return_val_if_fail(lldp_rx, NULL);

    return (NMLldpNeighbor **)
        nm_utils_hash_keys_to_array(lldp_rx->neighbor_by_id, neighbor_compare_func, NULL, out_len);
}

/*****************************************************************************/

NMLldpRX *
nm_lldp_rx_new(const NMLldpRXConfig *config)
{
    NMLldpRX *lldp_rx;

    nm_assert(config);
    nm_assert(config->ifindex > 0);
    nm_assert(config->callback);

    /* This needs to be first, see neighbor_by_id hash. */
    G_STATIC_ASSERT_EXPR(G_STRUCT_OFFSET(NMLldpNeighbor, id) == 0);

    lldp_rx  = g_slice_new(NMLldpRX);
    *lldp_rx = (NMLldpRX){
        .ref_count      = 1,
        .fd             = -1,
        .main_context   = g_main_context_ref_thread_default(),
        .config         = *config,
        .neighbor_by_id = g_hash_table_new((GHashFunc) nm_lldp_neighbor_id_hash,
                                           (GEqualFunc) nm_lldp_neighbor_id_equal),
    };
    lldp_rx->config.log_ifname = g_strdup(lldp_rx->config.log_ifname);
    lldp_rx->config.log_uuid   = g_strdup(lldp_rx->config.log_uuid);
    if (lldp_rx->config.neighbors_max == 0)
        lldp_rx->config.neighbors_max = LLDP_DEFAULT_NEIGHBORS_MAX;
    if (!lldp_rx->config.has_capability_mask && lldp_rx->config.capability_mask == 0)
        lldp_rx->config.capability_mask = UINT16_MAX;

    nm_prioq_init(&lldp_rx->neighbor_by_expiry, (GCompareFunc) nm_lldp_neighbor_prioq_compare_func);

    return lldp_rx;
}

NMLldpRX *
nm_lldp_rx_ref(NMLldpRX *lldp_rx)
{
    if (!lldp_rx)
        return NULL;

    nm_assert_is_lldp_rx(lldp_rx);
    nm_assert(lldp_rx->ref_count < G_MAXINT);

    lldp_rx->ref_count++;
    return lldp_rx;
}

void
nm_lldp_rx_unref(NMLldpRX *lldp_rx)
{
    if (!lldp_rx)
        return;

    nm_assert_is_lldp_rx(lldp_rx);

    if (--lldp_rx->ref_count > 0)
        return;

    lldp_rx_reset(lldp_rx);

    g_hash_table_unref(lldp_rx->neighbor_by_id);
    nm_prioq_destroy(&lldp_rx->neighbor_by_expiry);

    free((char *) lldp_rx->config.log_ifname);
    free((char *) lldp_rx->config.log_uuid);

    g_main_context_unref(lldp_rx->main_context);

    nm_g_slice_free(lldp_rx);
}
