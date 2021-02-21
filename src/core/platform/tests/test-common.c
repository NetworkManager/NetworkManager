/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2016 - 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "test-common.h"

#include <sys/mount.h>
#include <sched.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <linux/if_tun.h>

#include "n-acd/src/n-acd.h"

#define SIGNAL_DATA_FMT "'%s-%s' ifindex %d%s%s%s (%d times received)"
#define SIGNAL_DATA_ARG(data)                                                                     \
    (data)->name, nm_platform_signal_change_type_to_string((data)->change_type), (data)->ifindex, \
        (data)->ifname ? " ifname '" : "", (data)->ifname ?: "", (data)->ifname ? "'" : "",       \
        (data)->received_count

int NMTSTP_ENV1_IFINDEX = -1;
int NMTSTP_ENV1_EX      = -1;

/*****************************************************************************/

void
nmtstp_setup_platform(void)
{
    g_assert(_nmtstp_setup_platform_func);
    _nmtstp_setup_platform_func();
}

gboolean
nmtstp_is_root_test(void)
{
    g_assert(_nmtstp_setup_platform_func);
    return _nmtstp_setup_platform_func == nm_linux_platform_setup;
}

gboolean
nmtstp_is_sysfs_writable(void)
{
    return !nmtstp_is_root_test() || (access("/sys/devices", W_OK) == 0);
}

static void
_init_platform(NMPlatform **platform, gboolean external_command)
{
    g_assert(platform);
    if (!*platform)
        *platform = NM_PLATFORM_GET;
    g_assert(NM_IS_PLATFORM(*platform));

    if (external_command)
        g_assert(NM_IS_LINUX_PLATFORM(*platform));
}

/*****************************************************************************/

static GArray *
_ipx_address_get_all(NMPlatform *self, int ifindex, NMPObjectType obj_type)
{
    NMPLookup lookup;

    g_assert(NM_IS_PLATFORM(self));
    g_assert(ifindex > 0);
    g_assert(NM_IN_SET(obj_type, NMP_OBJECT_TYPE_IP4_ADDRESS, NMP_OBJECT_TYPE_IP6_ADDRESS));
    nmp_lookup_init_object(&lookup, obj_type, ifindex);
    return nmp_cache_lookup_to_array(nm_platform_lookup(self, &lookup),
                                     obj_type,
                                     FALSE /*addresses are always visible. */);
}

GArray *
nmtstp_platform_ip4_address_get_all(NMPlatform *self, int ifindex)
{
    return _ipx_address_get_all(self, ifindex, NMP_OBJECT_TYPE_IP4_ADDRESS);
}

GArray *
nmtstp_platform_ip6_address_get_all(NMPlatform *self, int ifindex)
{
    return _ipx_address_get_all(self, ifindex, NMP_OBJECT_TYPE_IP6_ADDRESS);
}

const NMPlatformIPAddress *
nmtstp_platform_ip_address_find(NMPlatform *self, int ifindex, int addr_family, gconstpointer addr)
{
    const int                  IS_IPv4 = NM_IS_IPv4(addr_family);
    const NMPlatformIPAddress *found   = NULL;
    NMDedupMultiIter           iter;
    const NMPObject *          obj;
    NMPLookup                  lookup;

    g_assert(NM_IS_PLATFORM(self));
    nm_assert(ifindex >= 0);
    nm_assert_addr_family(addr_family);
    nm_assert(addr);

    nmp_lookup_init_object(&lookup, NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4), ifindex);
    nm_platform_iter_obj_for_each (&iter, self, &lookup, &obj) {
        const NMPlatformIPAddress *a = NMP_OBJECT_CAST_IP_ADDRESS(obj);

        g_assert(NMP_OBJECT_GET_ADDR_FAMILY(obj) == addr_family);
        g_assert(ifindex <= 0 || a->ifindex == ifindex);

        if (memcmp(addr, a->address_ptr, nm_utils_addr_family_to_size(addr_family)) != 0)
            continue;

        g_assert(!found);
        found = a;
    }

    if (!IS_IPv4 && ifindex > 0)
        g_assert(found
                 == (const NMPlatformIPAddress *) nm_platform_ip6_address_get(self, ifindex, addr));

    return found;
}

/*****************************************************************************/

typedef struct {
    NMIPAddr addr;
    int      addr_family;
    bool     found : 1;
} IPAddressesAssertData;

void
_nmtstp_platform_ip_addresses_assert(const char *       filename,
                                     int                lineno,
                                     NMPlatform *       self,
                                     int                ifindex,
                                     gboolean           force_exact_4,
                                     gboolean           force_exact_6,
                                     gboolean           ignore_ll6,
                                     guint              addrs_len,
                                     const char *const *addrs)
{
    gs_free IPAddressesAssertData *addrs_bin = NULL;
    int                            IS_IPv4;
    guint                          i;

    g_assert(filename);
    g_assert(lineno >= 0);
    g_assert(NM_IS_PLATFORM(self));
    g_assert(ifindex >= 0);

    addrs_bin = g_new(IPAddressesAssertData, addrs_len);

    for (i = 0; i < addrs_len; i++) {
        const char *addrstr = addrs[i];
        int         addr_family;
        NMIPAddr    a;

        if (!addrstr) {
            addr_family = AF_UNSPEC;
            a           = nm_ip_addr_zero;
        } else if (inet_pton(AF_INET, addrstr, &a) == 1)
            addr_family = AF_INET;
        else if (inet_pton(AF_INET6, addrstr, &a) == 1)
            addr_family = AF_INET6;
        else
            g_error("%s:%d: invalid IP address in argument: %s", filename, lineno, addrstr);

        addrs_bin[i] = (IPAddressesAssertData){
            .addr_family = addr_family,
            .addr        = a,
            .found       = FALSE,
        };
    }

    for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
        const int         addr_family           = IS_IPv4 ? AF_INET : AF_INET6;
        gs_unref_ptrarray GPtrArray *plat_addrs = NULL;
        NMPLookup                    lookup;
        guint                        j;

        plat_addrs = nm_platform_lookup_clone(
            self,
            nmp_lookup_init_object(&lookup, NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4), ifindex),
            NULL,
            NULL);

        for (i = 0; i < addrs_len; i++) {
            IPAddressesAssertData *addr_bin = &addrs_bin[i];

            if (addr_bin->addr_family != addr_family)
                continue;

            g_assert(!addr_bin->found);
            for (j = 0; j < nm_g_ptr_array_len(plat_addrs);) {
                const NMPlatformIPAddress *a = NMP_OBJECT_CAST_IP_ADDRESS(plat_addrs->pdata[j]);

                if (memcmp(&addr_bin->addr,
                           a->address_ptr,
                           nm_utils_addr_family_to_size(addr_family))
                    != 0) {
                    j++;
                    continue;
                }

                g_assert(!addr_bin->found);
                addr_bin->found = TRUE;
                g_ptr_array_remove_index_fast(plat_addrs, j);
            }

            if (!addr_bin->found) {
                char sbuf[NM_UTILS_INET_ADDRSTRLEN];

                g_error("%s:%d: IPv%c address %s was not found on ifindex %d",
                        filename,
                        lineno,
                        nm_utils_addr_family_to_char(addr_bin->addr_family),
                        nm_utils_inet_ntop(addr_bin->addr_family, &addr_bin->addr, sbuf),
                        ifindex);
            }
        }
        if (!IS_IPv4 && ignore_ll6 && nm_g_ptr_array_len(plat_addrs) > 0) {
            /* we prune all remaining, non-matching IPv6 link local addresses. */
            for (j = 0; j < nm_g_ptr_array_len(plat_addrs);) {
                const NMPlatformIPAddress *a = NMP_OBJECT_CAST_IP_ADDRESS(plat_addrs->pdata[j]);

                if (!IN6_IS_ADDR_LINKLOCAL(a->address_ptr)) {
                    j++;
                    continue;
                }

                g_ptr_array_remove_index_fast(plat_addrs, j);
            }
        }
        if ((IS_IPv4 ? force_exact_4 : force_exact_6) && nm_g_ptr_array_len(plat_addrs) > 0) {
            char sbuf[sizeof(_nm_utils_to_string_buffer)];

            g_error("%s:%d: %u IPv%c addresses found on ifindex %d that should not be there (one "
                    "is %s)",
                    filename,
                    lineno,
                    plat_addrs->len,
                    nm_utils_addr_family_to_char(addr_family),
                    ifindex,
                    nmp_object_to_string(plat_addrs->pdata[0],
                                         NMP_OBJECT_TO_STRING_PUBLIC,
                                         sbuf,
                                         sizeof(sbuf)));
        }
    }
}

/*****************************************************************************/

gboolean
nmtstp_platform_ip4_route_delete(NMPlatform *platform,
                                 int         ifindex,
                                 in_addr_t   network,
                                 guint8      plen,
                                 guint32     metric)
{
    NMDedupMultiIter iter;

    nm_platform_process_events(platform);

    nm_dedup_multi_iter_for_each (
        &iter,
        nm_platform_lookup_object(platform, NMP_OBJECT_TYPE_IP4_ROUTE, ifindex)) {
        const NMPlatformIP4Route *r = NMP_OBJECT_CAST_IP4_ROUTE(iter.current->obj);

        if (r->ifindex != ifindex || r->network != network || r->plen != plen
            || r->metric != metric) {
            continue;
        }

        return nm_platform_object_delete(platform, NMP_OBJECT_UP_CAST(r));
    }

    return TRUE;
}

gboolean
nmtstp_platform_ip6_route_delete(NMPlatform *    platform,
                                 int             ifindex,
                                 struct in6_addr network,
                                 guint8          plen,
                                 guint32         metric)
{
    NMDedupMultiIter iter;

    nm_platform_process_events(platform);

    nm_dedup_multi_iter_for_each (
        &iter,
        nm_platform_lookup_object(platform, NMP_OBJECT_TYPE_IP6_ROUTE, ifindex)) {
        const NMPlatformIP6Route *r = NMP_OBJECT_CAST_IP6_ROUTE(iter.current->obj);

        if (r->ifindex != ifindex || !IN6_ARE_ADDR_EQUAL(&r->network, &network) || r->plen != plen
            || r->metric != metric) {
            continue;
        }

        return nm_platform_object_delete(platform, NMP_OBJECT_UP_CAST(r));
    }

    return TRUE;
}

/*****************************************************************************/

SignalData *
add_signal_full(const char *               name,
                NMPlatformSignalChangeType change_type,
                GCallback                  callback,
                int                        ifindex,
                const char *               ifname)
{
    SignalData *data = g_new0(SignalData, 1);

    data->name           = name;
    data->change_type    = change_type;
    data->received_count = 0;
    data->handler_id     = g_signal_connect(NM_PLATFORM_GET, name, callback, data);
    data->ifindex        = ifindex;
    data->ifname         = ifname;

    g_assert(data->handler_id > 0);

    return data;
}

void
_accept_signal(const char *file, int line, const char *func, SignalData *data)
{
    _LOGD("NMPlatformSignalAssert: %s:%d, %s(): Accepting signal one time: " SIGNAL_DATA_FMT,
          file,
          line,
          func,
          SIGNAL_DATA_ARG(data));
    if (data->received_count != 1)
        g_error("NMPlatformSignalAssert: %s:%d, %s(): failure to accept signal one "
                "time: " SIGNAL_DATA_FMT,
                file,
                line,
                func,
                SIGNAL_DATA_ARG(data));
    data->received_count = 0;
}

void
_accept_signals(const char *file, int line, const char *func, SignalData *data, int min, int max)
{
    _LOGD("NMPlatformSignalAssert: %s:%d, %s(): Accepting signal [%d,%d] times: " SIGNAL_DATA_FMT,
          file,
          line,
          func,
          min,
          max,
          SIGNAL_DATA_ARG(data));
    if (data->received_count < min || data->received_count > max)
        g_error("NMPlatformSignalAssert: %s:%d, %s(): failure to accept signal [%d,%d] "
                "times: " SIGNAL_DATA_FMT,
                file,
                line,
                func,
                min,
                max,
                SIGNAL_DATA_ARG(data));
    data->received_count = 0;
}

void
_ensure_no_signal(const char *file, int line, const char *func, SignalData *data)
{
    _LOGD("NMPlatformSignalAssert: %s:%d, %s(): Accepting signal 0 times: " SIGNAL_DATA_FMT,
          file,
          line,
          func,
          SIGNAL_DATA_ARG(data));
    if (data->received_count > 0)
        g_error("NMPlatformSignalAssert: %s:%d, %s(): failure to accept signal 0 "
                "times: " SIGNAL_DATA_FMT,
                file,
                line,
                func,
                SIGNAL_DATA_ARG(data));
}

void
_accept_or_wait_signal(const char *file, int line, const char *func, SignalData *data)
{
    _LOGD("NMPlatformSignalAssert: %s:%d, %s(): accept-or-wait signal: " SIGNAL_DATA_FMT,
          file,
          line,
          func,
          SIGNAL_DATA_ARG(data));
    if (data->received_count == 0) {
        data->loop = g_main_loop_new(NULL, FALSE);
        g_main_loop_run(data->loop);
        nm_clear_pointer(&data->loop, g_main_loop_unref);
    }

    _accept_signal(file, line, func, data);
}

void
_wait_signal(const char *file, int line, const char *func, SignalData *data)
{
    _LOGD("NMPlatformSignalAssert: %s:%d, %s(): wait signal: " SIGNAL_DATA_FMT,
          file,
          line,
          func,
          SIGNAL_DATA_ARG(data));
    if (data->received_count)
        g_error("NMPlatformSignalAssert: %s:%d, %s(): failure to wait for signal: " SIGNAL_DATA_FMT,
                file,
                line,
                func,
                SIGNAL_DATA_ARG(data));

    data->loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(data->loop);
    nm_clear_pointer(&data->loop, g_main_loop_unref);

    _accept_signal(file, line, func, data);
}

void
_free_signal(const char *file, int line, const char *func, SignalData *data)
{
    _LOGD("NMPlatformSignalAssert: %s:%d, %s(): free signal: " SIGNAL_DATA_FMT,
          file,
          line,
          func,
          SIGNAL_DATA_ARG(data));
    if (data->received_count != 0)
        g_error("NMPlatformSignalAssert: %s:%d, %s(): failure to free non-accepted "
                "signal: " SIGNAL_DATA_FMT,
                file,
                line,
                func,
                SIGNAL_DATA_ARG(data));

    g_signal_handler_disconnect(NM_PLATFORM_GET, data->handler_id);
    g_free(data);
}

void
link_callback(NMPlatform *    platform,
              int             obj_type_i,
              int             ifindex,
              NMPlatformLink *received,
              int             change_type_i,
              SignalData *    data)
{
    const NMPObjectType              obj_type    = obj_type_i;
    const NMPlatformSignalChangeType change_type = change_type_i;
    NMPLookup                        lookup;
    NMDedupMultiIter                 iter;
    const NMPlatformLink *           cached;

    g_assert_cmpint(obj_type, ==, NMP_OBJECT_TYPE_LINK);
    g_assert(received);
    g_assert_cmpint(received->ifindex, ==, ifindex);
    g_assert(data && data->name);
    g_assert_cmpstr(data->name, ==, NM_PLATFORM_SIGNAL_LINK_CHANGED);

    if (data->ifindex && data->ifindex != received->ifindex)
        return;
    if (data->ifname
        && g_strcmp0(data->ifname, nm_platform_link_get_name(NM_PLATFORM_GET, ifindex)) != 0)
        return;
    if (change_type != data->change_type)
        return;

    if (data->loop) {
        _LOGD("Quitting main loop.");
        g_main_loop_quit(data->loop);
    }

    data->received_count++;
    _LOGD("Received signal '%s-%s' ifindex %d ifname '%s' %dth time.",
          data->name,
          nm_platform_signal_change_type_to_string(data->change_type),
          ifindex,
          received->name,
          data->received_count);

    if (change_type == NM_PLATFORM_SIGNAL_REMOVED)
        g_assert(!nm_platform_link_get_name(NM_PLATFORM_GET, ifindex));
    else
        g_assert(nm_platform_link_get_name(NM_PLATFORM_GET, ifindex));

    /* Check the data */
    g_assert(received->ifindex > 0);

    nmp_lookup_init_obj_type(&lookup, NMP_OBJECT_TYPE_LINK);
    nmp_cache_iter_for_each_link (&iter, nm_platform_lookup(platform, &lookup), &cached) {
        if (!nmp_object_is_visible(NMP_OBJECT_UP_CAST(cached)))
            continue;
        if (cached->ifindex == received->ifindex) {
            g_assert_cmpint(nm_platform_link_cmp(cached, received), ==, 0);
            g_assert(!memcmp(cached, received, sizeof(*cached)));
            if (data->change_type == NM_PLATFORM_SIGNAL_REMOVED)
                g_error("Deleted link still found in the local cache.");
            return;
        }
    }

    if (data->change_type != NM_PLATFORM_SIGNAL_REMOVED)
        g_error("Added/changed link not found in the local cache.");
}

/*****************************************************************************/

static const NMPlatformIP4Route *
_ip4_route_get(NMPlatform *platform,
               int         ifindex,
               guint32     network,
               int         plen,
               guint32     metric,
               guint8      tos,
               guint *     out_c_exists)
{
    NMDedupMultiIter          iter;
    NMPLookup                 lookup;
    const NMPObject *         o = NULL;
    guint                     c;
    const NMPlatformIP4Route *r = NULL;

    _init_platform(&platform, FALSE);

    nmp_lookup_init_ip4_route_by_weak_id(&lookup, network, plen, metric, tos);

    c = 0;
    nmp_cache_iter_for_each (&iter, nm_platform_lookup(platform, &lookup), &o) {
        if (NMP_OBJECT_CAST_IP4_ROUTE(o)->ifindex != ifindex && ifindex > 0)
            continue;
        if (!r)
            r = NMP_OBJECT_CAST_IP4_ROUTE(o);
        c++;
    }

    NM_SET_OUT(out_c_exists, c);
    return r;
}

const NMPlatformIP4Route *
_nmtstp_assert_ip4_route_exists(const char *file,
                                guint       line,
                                const char *func,
                                NMPlatform *platform,
                                int         c_exists,
                                const char *ifname,
                                guint32     network,
                                int         plen,
                                guint32     metric,
                                guint8      tos)
{
    int                       ifindex;
    guint                     c;
    const NMPlatformIP4Route *r = NULL;

    _init_platform(&platform, FALSE);

    ifindex = -1;
    if (ifname) {
        ifindex = nm_platform_link_get_ifindex(platform, ifname);
        g_assert(ifindex > 0);
    }

    r = _ip4_route_get(platform, ifindex, network, plen, metric, tos, &c);

    if (c != c_exists && c_exists != -1) {
        char sbuf[NM_UTILS_INET_ADDRSTRLEN];

        g_error("[%s:%u] %s(): The ip4 route %s/%d metric %u tos %u shall exist %u times, but "
                "platform has it %u times",
                file,
                line,
                func,
                _nm_utils_inet4_ntop(network, sbuf),
                plen,
                metric,
                tos,
                c_exists,
                c);
    }

    return r;
}

const NMPlatformIP4Route *
nmtstp_ip4_route_get(NMPlatform *platform,
                     int         ifindex,
                     guint32     network,
                     int         plen,
                     guint32     metric,
                     guint8      tos)
{
    return _ip4_route_get(platform, ifindex, network, plen, metric, tos, NULL);
}

/*****************************************************************************/

static const NMPlatformIP6Route *
_ip6_route_get(NMPlatform *           platform,
               int                    ifindex,
               const struct in6_addr *network,
               guint                  plen,
               guint32                metric,
               const struct in6_addr *src,
               guint8                 src_plen,
               guint *                out_c_exists)
{
    NMDedupMultiIter          iter;
    NMPLookup                 lookup;
    const NMPObject *         o = NULL;
    guint                     c;
    const NMPlatformIP6Route *r = NULL;

    _init_platform(&platform, FALSE);

    nmp_lookup_init_ip6_route_by_weak_id(&lookup, network, plen, metric, src, src_plen);

    c = 0;
    nmp_cache_iter_for_each (&iter, nm_platform_lookup(platform, &lookup), &o) {
        if (NMP_OBJECT_CAST_IP6_ROUTE(o)->ifindex != ifindex && ifindex > 0)
            continue;
        if (!r)
            r = NMP_OBJECT_CAST_IP6_ROUTE(o);
        c++;
    }

    NM_SET_OUT(out_c_exists, c);
    return r;
}

const NMPlatformIP6Route *
_nmtstp_assert_ip6_route_exists(const char *           file,
                                guint                  line,
                                const char *           func,
                                NMPlatform *           platform,
                                int                    c_exists,
                                const char *           ifname,
                                const struct in6_addr *network,
                                guint                  plen,
                                guint32                metric,
                                const struct in6_addr *src,
                                guint8                 src_plen)
{
    int                       ifindex;
    guint                     c;
    const NMPlatformIP6Route *r = NULL;

    _init_platform(&platform, FALSE);

    ifindex = -1;
    if (ifname) {
        ifindex = nm_platform_link_get_ifindex(platform, ifname);
        g_assert(ifindex > 0);
    }

    r = _ip6_route_get(platform, ifindex, network, plen, metric, src, src_plen, &c);

    if (c != c_exists && c_exists != -1) {
        char s_src[NM_UTILS_INET_ADDRSTRLEN];
        char s_network[NM_UTILS_INET_ADDRSTRLEN];

        g_error("[%s:%u] %s(): The ip6 route %s/%d metric %u src %s/%d shall exist %u times, but "
                "platform has it %u times",
                file,
                line,
                func,
                _nm_utils_inet6_ntop(network, s_network),
                plen,
                metric,
                _nm_utils_inet6_ntop(src, s_src),
                src_plen,
                c_exists,
                c);
    }

    return r;
}

const NMPlatformIP6Route *
nmtstp_ip6_route_get(NMPlatform *           platform,
                     int                    ifindex,
                     const struct in6_addr *network,
                     guint                  plen,
                     guint32                metric,
                     const struct in6_addr *src,
                     guint8                 src_plen)
{
    return _ip6_route_get(platform, ifindex, network, plen, metric, src, src_plen, NULL);
}

/*****************************************************************************/

int
nmtstp_run_command(const char *format, ...)
{
    int           result;
    gs_free char *command = NULL;
    va_list       ap;

    va_start(ap, format);
    command = g_strdup_vprintf(format, ap);
    va_end(ap);

    _LOGD("Running command: %s", command);
    result = system(command);
    _LOGD("Command finished: result=%d", result);

    return result;
}

/*****************************************************************************/

typedef struct {
    GMainLoop *loop;
    guint      signal_counts;
    guint      id;
} WaitForSignalData;

static void
_wait_for_signal_cb(NMPlatform *    platform,
                    int             obj_type_i,
                    int             ifindex,
                    NMPlatformLink *plink,
                    int             change_type_i,
                    gpointer        user_data)
{
    WaitForSignalData *data = user_data;

    data->signal_counts++;
    nm_clear_g_source(&data->id);
    g_main_loop_quit(data->loop);
}

static gboolean
_wait_for_signal_timeout(gpointer user_data)
{
    WaitForSignalData *data = user_data;

    g_assert(data->id);
    data->id = 0;
    g_main_loop_quit(data->loop);
    return G_SOURCE_REMOVE;
}

guint
nmtstp_wait_for_signal(NMPlatform *platform, gint64 timeout_msec)
{
    WaitForSignalData data = {0};
    gulong            id_link, id_ip4_address, id_ip6_address, id_ip4_route, id_ip6_route;
    gulong            id_qdisc, id_tfilter;

    _init_platform(&platform, FALSE);

    data.loop = g_main_loop_new(NULL, FALSE);

    id_link        = g_signal_connect(platform,
                               NM_PLATFORM_SIGNAL_LINK_CHANGED,
                               G_CALLBACK(_wait_for_signal_cb),
                               &data);
    id_ip4_address = g_signal_connect(platform,
                                      NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED,
                                      G_CALLBACK(_wait_for_signal_cb),
                                      &data);
    id_ip6_address = g_signal_connect(platform,
                                      NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED,
                                      G_CALLBACK(_wait_for_signal_cb),
                                      &data);
    id_ip4_route   = g_signal_connect(platform,
                                    NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED,
                                    G_CALLBACK(_wait_for_signal_cb),
                                    &data);
    id_ip6_route   = g_signal_connect(platform,
                                    NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED,
                                    G_CALLBACK(_wait_for_signal_cb),
                                    &data);
    id_qdisc       = g_signal_connect(platform,
                                NM_PLATFORM_SIGNAL_QDISC_CHANGED,
                                G_CALLBACK(_wait_for_signal_cb),
                                &data);
    id_tfilter     = g_signal_connect(platform,
                                  NM_PLATFORM_SIGNAL_TFILTER_CHANGED,
                                  G_CALLBACK(_wait_for_signal_cb),
                                  &data);

    /* if timeout_msec is negative, it means the wait-time already expired.
     * Maybe, we should do nothing and return right away, without even
     * processing events from platform. However, that inconsistency (of not
     * processing events from mainloop) is inconvenient.
     *
     * It's better that on the return of nmtstp_wait_for_signal(), we always
     * have no events pending. So, a negative timeout is treated the same as
     * a zero timeout: we check whether there are any events pending in platform,
     * and quite the mainloop immediately afterwards. But we always check. */

    data.id = g_timeout_add(CLAMP(timeout_msec, 0, G_MAXUINT32), _wait_for_signal_timeout, &data);

    g_main_loop_run(data.loop);

    g_assert(!data.id);
    g_assert(nm_clear_g_signal_handler(platform, &id_link));
    g_assert(nm_clear_g_signal_handler(platform, &id_ip4_address));
    g_assert(nm_clear_g_signal_handler(platform, &id_ip6_address));
    g_assert(nm_clear_g_signal_handler(platform, &id_ip4_route));
    g_assert(nm_clear_g_signal_handler(platform, &id_ip6_route));
    g_assert(nm_clear_g_signal_handler(platform, &id_tfilter));
    g_assert(nm_clear_g_signal_handler(platform, &id_qdisc));

    nm_clear_pointer(&data.loop, g_main_loop_unref);

    /* return the number of signals, or 0 if timeout was reached .*/
    return data.signal_counts;
}

guint
nmtstp_wait_for_signal_until(NMPlatform *platform, gint64 until_ms)
{
    gint64 now;
    guint  signal_counts;

    while (TRUE) {
        now = nm_utils_get_monotonic_timestamp_msec();

        if (until_ms < now)
            return 0;

        signal_counts = nmtstp_wait_for_signal(platform, until_ms - now);
        if (signal_counts)
            return signal_counts;
    }
}

const NMPlatformLink *
nmtstp_wait_for_link(NMPlatform *platform,
                     const char *ifname,
                     NMLinkType  expected_link_type,
                     gint64      timeout_msec)
{
    return nmtstp_wait_for_link_until(
        platform,
        ifname,
        expected_link_type,
        timeout_msec ? nm_utils_get_monotonic_timestamp_msec() + timeout_msec : 0);
}

const NMPlatformLink *
nmtstp_wait_for_link_until(NMPlatform *platform,
                           const char *ifname,
                           NMLinkType  expected_link_type,
                           gint64      until_ms)
{
    const NMPlatformLink *plink;
    gint64                now;
    gboolean              waited_once = FALSE;

    _init_platform(&platform, FALSE);

    while (TRUE) {
        now = nm_utils_get_monotonic_timestamp_msec();

        plink = nm_platform_link_get_by_ifname(platform, ifname);
        if (plink && (expected_link_type == NM_LINK_TYPE_NONE || plink->type == expected_link_type))
            return plink;

        if (until_ms == 0) {
            /* don't wait, don't even poll the socket. */
            return NULL;
        }

        if (waited_once && until_ms < now) {
            /* timeout reached (+ we already waited for a signal at least once). */
            return NULL;
        }

        waited_once = TRUE;
        /* regardless of whether timeout is already reached, we poll the netlink
         * socket a bit. */
        nmtstp_wait_for_signal(platform, until_ms - now);
    }
}

/*****************************************************************************/

int
nmtstp_run_command_check_external_global(void)
{
    if (!nmtstp_is_root_test())
        return FALSE;
    switch (nmtst_get_rand_uint32() % 3) {
    case 0:
        return -1;
    case 1:
        return FALSE;
    default:
        return TRUE;
    }
}

gboolean
nmtstp_run_command_check_external(int external_command)
{
    if (external_command != -1) {
        g_assert(NM_IN_SET(external_command, FALSE, TRUE));
        g_assert(!external_command || nmtstp_is_root_test());
        return !!external_command;
    }
    if (!nmtstp_is_root_test())
        return FALSE;
    return (nmtst_get_rand_uint32() % 2) == 0;
}

/*****************************************************************************/

#define CHECK_LIFETIME_MAX_DIFF 2

gboolean
nmtstp_ip_address_check_lifetime(const NMPlatformIPAddress *addr,
                                 gint64                     now,
                                 guint32                    expected_lifetime,
                                 guint32                    expected_preferred)
{
    gint64 offset;
    int    i;

    g_assert(addr);

    if (now == -1)
        now = nm_utils_get_monotonic_timestamp_sec();
    g_assert(now > 0);

    g_assert(expected_preferred <= expected_lifetime);

    if (expected_lifetime == NM_PLATFORM_LIFETIME_PERMANENT
        && expected_preferred == NM_PLATFORM_LIFETIME_PERMANENT) {
        return addr->timestamp == 0 && addr->lifetime == NM_PLATFORM_LIFETIME_PERMANENT
               && addr->preferred == NM_PLATFORM_LIFETIME_PERMANENT;
    }

    if (addr->timestamp == 0)
        return FALSE;

    offset = (gint64) now - addr->timestamp;

    for (i = 0; i < 2; i++) {
        guint32 lft = i ? expected_lifetime : expected_preferred;
        guint32 adr = i ? addr->lifetime : addr->preferred;

        if (lft == NM_PLATFORM_LIFETIME_PERMANENT) {
            if (adr != NM_PLATFORM_LIFETIME_PERMANENT)
                return FALSE;
        } else {
            if (((gint64) adr) - offset <= ((gint64) lft) - CHECK_LIFETIME_MAX_DIFF
                || ((gint64) adr) - offset >= ((gint64) lft) + CHECK_LIFETIME_MAX_DIFF)
                return FALSE;
        }
    }
    return TRUE;
}

void
nmtstp_ip_address_assert_lifetime(const NMPlatformIPAddress *addr,
                                  gint64                     now,
                                  guint32                    expected_lifetime,
                                  guint32                    expected_preferred)
{
    gint64 n = now;
    gint64 offset;
    int    i;

    g_assert(addr);

    if (now == -1)
        now = nm_utils_get_monotonic_timestamp_sec();
    g_assert(now > 0);

    g_assert(expected_preferred <= expected_lifetime);

    if (expected_lifetime == NM_PLATFORM_LIFETIME_PERMANENT
        && expected_preferred == NM_PLATFORM_LIFETIME_PERMANENT) {
        g_assert_cmpint(addr->timestamp, ==, 0);
        g_assert_cmpint(addr->lifetime, ==, NM_PLATFORM_LIFETIME_PERMANENT);
        g_assert_cmpint(addr->preferred, ==, NM_PLATFORM_LIFETIME_PERMANENT);
        return;
    }

    g_assert_cmpint(addr->timestamp, >, 0);
    g_assert_cmpint(addr->timestamp, <=, now);

    offset = (gint64) now - addr->timestamp;
    g_assert_cmpint(offset, >=, 0);

    for (i = 0; i < 2; i++) {
        guint32 lft = i ? expected_lifetime : expected_preferred;
        guint32 adr = i ? addr->lifetime : addr->preferred;

        if (lft == NM_PLATFORM_LIFETIME_PERMANENT)
            g_assert_cmpint(adr, ==, NM_PLATFORM_LIFETIME_PERMANENT);
        else {
            g_assert_cmpint(adr - offset, <=, lft + CHECK_LIFETIME_MAX_DIFF);
            g_assert_cmpint(adr - offset, >=, lft - CHECK_LIFETIME_MAX_DIFF);
        }
    }

    g_assert(nmtstp_ip_address_check_lifetime(addr, n, expected_lifetime, expected_preferred));
}

/*****************************************************************************/

static void
_ip_address_add(NMPlatform *    platform,
                gboolean        external_command,
                gboolean        is_v4,
                int             ifindex,
                const NMIPAddr *address,
                int             plen,
                const NMIPAddr *peer_address,
                guint32         lifetime,
                guint32         preferred,
                guint32         flags,
                const char *    label)
{
    gint64 end_time;

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        const char *  ifname;
        gs_free char *s_valid     = NULL;
        gs_free char *s_preferred = NULL;
        gs_free char *s_label     = NULL;
        char          b1[NM_UTILS_INET_ADDRSTRLEN];
        char          b2[NM_UTILS_INET_ADDRSTRLEN];

        ifname = nm_platform_link_get_name(platform, ifindex);
        g_assert(ifname);

        if (lifetime != NM_PLATFORM_LIFETIME_PERMANENT)
            s_valid = g_strdup_printf(" valid_lft %d", lifetime);
        if (preferred != NM_PLATFORM_LIFETIME_PERMANENT)
            s_preferred = g_strdup_printf(" preferred_lft %d", preferred);
        if (label)
            s_label = g_strdup_printf("%s:%s", ifname, label);

        if (is_v4) {
            char s_peer[NM_UTILS_INET_ADDRSTRLEN + 50];

            g_assert(flags == 0);

            if (peer_address->addr4 != address->addr4 || nmtst_get_rand_uint32() % 2) {
                /* If the peer is the same as the local address, we can omit it. The result should be identical */
                nm_sprintf_buf(s_peer, " peer %s", _nm_utils_inet4_ntop(peer_address->addr4, b2));
            } else
                s_peer[0] = '\0';

            nmtstp_run_command_check("ip address change %s%s/%d dev %s%s%s%s",
                                     _nm_utils_inet4_ntop(address->addr4, b1),
                                     s_peer,
                                     plen,
                                     ifname,
                                     s_valid ?: "",
                                     s_preferred ?: "",
                                     s_label ?: "");
        } else {
            g_assert(label == NULL);

            /* flags not implemented (yet) */
            g_assert(flags == 0);
            nmtstp_run_command_check("ip address change %s%s%s/%d dev %s%s%s%s",
                                     _nm_utils_inet6_ntop(&address->addr6, b1),
                                     !IN6_IS_ADDR_UNSPECIFIED(&peer_address->addr6) ? " peer " : "",
                                     !IN6_IS_ADDR_UNSPECIFIED(&peer_address->addr6)
                                         ? _nm_utils_inet6_ntop(&peer_address->addr6, b2)
                                         : "",
                                     plen,
                                     ifname,
                                     s_valid ?: "",
                                     s_preferred ?: "",
                                     s_label ?: "");
        }
    } else {
        gboolean success;

        if (is_v4) {
            success = nm_platform_ip4_address_add(platform,
                                                  ifindex,
                                                  address->addr4,
                                                  plen,
                                                  peer_address->addr4,
                                                  0u,
                                                  lifetime,
                                                  preferred,
                                                  flags,
                                                  label);
        } else {
            g_assert(label == NULL);
            success = nm_platform_ip6_address_add(platform,
                                                  ifindex,
                                                  address->addr6,
                                                  plen,
                                                  peer_address->addr6,
                                                  lifetime,
                                                  preferred,
                                                  flags);
        }
        g_assert(success);
    }

    /* Let's wait until we see the address. */
    end_time = nm_utils_get_monotonic_timestamp_msec() + 500;
    do {
        if (external_command)
            nm_platform_process_events(platform);

        /* let's wait until we see the address as we added it. */
        if (is_v4) {
            const NMPlatformIP4Address *a;

            g_assert(flags == 0);
            a = nm_platform_ip4_address_get(platform,
                                            ifindex,
                                            address->addr4,
                                            plen,
                                            peer_address->addr4);
            if (a && a->peer_address == peer_address->addr4
                && nmtstp_ip_address_check_lifetime((NMPlatformIPAddress *) a,
                                                    -1,
                                                    lifetime,
                                                    preferred)
                && strcmp(a->label, label ?: "") == 0)
                break;
        } else {
            const NMPlatformIP6Address *a;

            g_assert(label == NULL);
            g_assert(flags == 0);

            a = nm_platform_ip6_address_get(platform, ifindex, &address->addr6);
            if (a
                && !memcmp(nm_platform_ip6_address_get_peer(a),
                           (IN6_IS_ADDR_UNSPECIFIED(&peer_address->addr6)
                            || IN6_ARE_ADDR_EQUAL(&address->addr6, &peer_address->addr6))
                               ? &address->addr6
                               : &peer_address->addr6,
                           sizeof(struct in6_addr))
                && nmtstp_ip_address_check_lifetime((NMPlatformIPAddress *) a,
                                                    -1,
                                                    lifetime,
                                                    preferred))
                break;
        }

        /* for internal command, we expect not to reach this line.*/
        g_assert(external_command);

        nmtstp_assert_wait_for_signal_until(platform, end_time);
    } while (TRUE);
}

void
nmtstp_ip4_address_add(NMPlatform *platform,
                       gboolean    external_command,
                       int         ifindex,
                       in_addr_t   address,
                       int         plen,
                       in_addr_t   peer_address,
                       guint32     lifetime,
                       guint32     preferred,
                       guint32     flags,
                       const char *label)
{
    _ip_address_add(platform,
                    external_command,
                    TRUE,
                    ifindex,
                    (NMIPAddr *) &address,
                    plen,
                    (NMIPAddr *) &peer_address,
                    lifetime,
                    preferred,
                    flags,
                    label);
}

void
nmtstp_ip6_address_add(NMPlatform *    platform,
                       gboolean        external_command,
                       int             ifindex,
                       struct in6_addr address,
                       int             plen,
                       struct in6_addr peer_address,
                       guint32         lifetime,
                       guint32         preferred,
                       guint32         flags)
{
    _ip_address_add(platform,
                    external_command,
                    FALSE,
                    ifindex,
                    (NMIPAddr *) &address,
                    plen,
                    (NMIPAddr *) &peer_address,
                    lifetime,
                    preferred,
                    flags,
                    NULL);
}

void
nmtstp_ip4_route_add(NMPlatform *     platform,
                     int              ifindex,
                     NMIPConfigSource source,
                     in_addr_t        network,
                     guint8           plen,
                     in_addr_t        gateway,
                     in_addr_t        pref_src,
                     guint32          metric,
                     guint32          mss)
{
    NMPlatformIP4Route route = {};

    route.ifindex   = ifindex;
    route.rt_source = source;
    route.network   = network;
    route.plen      = plen;
    route.gateway   = gateway;
    route.pref_src  = pref_src;
    route.metric    = metric;
    route.mss       = mss;

    g_assert(
        NMTST_NM_ERR_SUCCESS(nm_platform_ip4_route_add(platform, NMP_NLM_FLAG_REPLACE, &route)));
}

void
nmtstp_ip6_route_add(NMPlatform *     platform,
                     int              ifindex,
                     NMIPConfigSource source,
                     struct in6_addr  network,
                     guint8           plen,
                     struct in6_addr  gateway,
                     struct in6_addr  pref_src,
                     guint32          metric,
                     guint32          mss)
{
    NMPlatformIP6Route route = {};

    route.ifindex   = ifindex;
    route.rt_source = source;
    route.network   = network;
    route.plen      = plen;
    route.gateway   = gateway;
    route.pref_src  = pref_src;
    route.metric    = metric;
    route.mss       = mss;

    g_assert(
        NMTST_NM_ERR_SUCCESS(nm_platform_ip6_route_add(platform, NMP_NLM_FLAG_REPLACE, &route)));
}

/*****************************************************************************/

static void
_ip_address_del(NMPlatform *    platform,
                gboolean        external_command,
                gboolean        is_v4,
                int             ifindex,
                const NMIPAddr *address,
                int             plen,
                const NMIPAddr *peer_address)
{
    gint64 end_time;

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        const char *ifname;
        char        b1[NM_UTILS_INET_ADDRSTRLEN];
        char        b2[NM_UTILS_INET_ADDRSTRLEN];
        int         success;
        gboolean    had_address;

        ifname = nm_platform_link_get_name(platform, ifindex);
        g_assert(ifname);

        /* let's wait until we see the address as we added it. */
        if (is_v4)
            had_address = !!nm_platform_ip4_address_get(platform,
                                                        ifindex,
                                                        address->addr4,
                                                        plen,
                                                        peer_address->addr4);
        else
            had_address = !!nm_platform_ip6_address_get(platform, ifindex, &address->addr6);

        if (is_v4) {
            success = nmtstp_run_command("ip address delete %s%s%s/%d dev %s",
                                         _nm_utils_inet4_ntop(address->addr4, b1),
                                         peer_address->addr4 != address->addr4 ? " peer " : "",
                                         peer_address->addr4 != address->addr4
                                             ? _nm_utils_inet4_ntop(peer_address->addr4, b2)
                                             : "",
                                         plen,
                                         ifname);
        } else {
            g_assert(!peer_address);
            success = nmtstp_run_command("ip address delete %s/%d dev %s",
                                         _nm_utils_inet6_ntop(&address->addr6, b1),
                                         plen,
                                         ifname);
        }
        g_assert(success == 0 || !had_address);
    } else {
        gboolean success;

        if (is_v4) {
            success = nm_platform_ip4_address_delete(platform,
                                                     ifindex,
                                                     address->addr4,
                                                     plen,
                                                     peer_address->addr4);
        } else {
            g_assert(!peer_address);
            success = nm_platform_ip6_address_delete(platform, ifindex, address->addr6, plen);
        }
        g_assert(success);
    }

    /* Let's wait until we get the result */
    end_time = nm_utils_get_monotonic_timestamp_msec() + 250;
    do {
        if (external_command)
            nm_platform_process_events(platform);

        /* let's wait until we see the address as we added it. */
        if (is_v4) {
            const NMPlatformIP4Address *a;

            a = nm_platform_ip4_address_get(platform,
                                            ifindex,
                                            address->addr4,
                                            plen,
                                            peer_address->addr4);
            if (!a)
                break;
        } else {
            const NMPlatformIP6Address *a;

            a = nm_platform_ip6_address_get(platform, ifindex, &address->addr6);
            if (!a)
                break;
        }

        /* for internal command, we expect not to reach this line.*/
        g_assert(external_command);

        nmtstp_assert_wait_for_signal_until(platform, end_time);
    } while (TRUE);
}

void
nmtstp_ip4_address_del(NMPlatform *platform,
                       gboolean    external_command,
                       int         ifindex,
                       in_addr_t   address,
                       int         plen,
                       in_addr_t   peer_address)
{
    _ip_address_del(platform,
                    external_command,
                    TRUE,
                    ifindex,
                    (NMIPAddr *) &address,
                    plen,
                    (NMIPAddr *) &peer_address);
}

void
nmtstp_ip6_address_del(NMPlatform *    platform,
                       gboolean        external_command,
                       int             ifindex,
                       struct in6_addr address,
                       int             plen)
{
    _ip_address_del(platform, external_command, FALSE, ifindex, (NMIPAddr *) &address, plen, NULL);
}

/*****************************************************************************/

#define _assert_pllink(platform, success, pllink, name, type)                               \
    G_STMT_START                                                                            \
    {                                                                                       \
        const NMPlatformLink *_pllink = (pllink);                                           \
                                                                                            \
        if ((success)) {                                                                    \
            g_assert(_pllink);                                                              \
            g_assert(_pllink                                                                \
                     == nmtstp_link_get_typed(platform, _pllink->ifindex, (name), (type))); \
        } else {                                                                            \
            g_assert(!_pllink);                                                             \
            g_assert(!nmtstp_link_get(platform, 0, (name)));                                \
        }                                                                                   \
    }                                                                                       \
    G_STMT_END

const NMPlatformLink *
nmtstp_link_bridge_add(NMPlatform *               platform,
                       gboolean                   external_command,
                       const char *               name,
                       const NMPlatformLnkBridge *lnk)
{
    const NMPlatformLink *     pllink = NULL;
    const NMPlatformLnkBridge *ll     = NULL;
    int                        r      = 0;

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        char sbuf_gfw[100];
        char sbuf_mhm[100];
        char sbuf_mlmc[100];
        char sbuf_mlmi[100];
        char sbuf_mmi[100];
        char sbuf_mqi[100];
        char sbuf_mqii[100];
        char sbuf_msqc[100];
        char sbuf_msqi[100];
        char sbuf_mqri[100];

        r = nmtstp_run_command(
            "ip link add %s type bridge "
            "forward_delay %u "
            "hello_time %u "
            "max_age %u "
            "ageing_time %u "
            "stp_state %d "
            "priority %u "
            "vlan_protocol %u "
            "vlan_stats_enabled %d "
            "%s" /* group_fwd_mask */
            "group_address " NM_ETHER_ADDR_FORMAT_STR " "
            "mcast_snooping %d "
            "mcast_router %u "
            "mcast_query_use_ifaddr %d "
            "mcast_querier %d "
            "%s" /* mcast_hash_max */
            "%s" /* mcast_last_member_count */
            "%s" /* mcast_startup_query_count */
            "%s" /* mcast_last_member_interval */
            "%s" /* mcast_membership_interval */
            "%s" /* mcast_querier_interval */
            "%s" /* mcast_query_interval */
            "%s" /* mcast_query_response_interval */
            "%s" /* mcast_startup_query_interval */
            "",
            name,
            lnk->forward_delay,
            lnk->hello_time,
            lnk->max_age,
            lnk->ageing_time,
            (int) lnk->stp_state,
            lnk->priority,
            lnk->vlan_protocol,
            (int) lnk->vlan_stats_enabled,
            lnk->group_fwd_mask != 0
                ? nm_sprintf_buf(sbuf_gfw, "group_fwd_mask %#x ", lnk->group_fwd_mask)
                : "",
            NM_ETHER_ADDR_FORMAT_VAL(&lnk->group_addr),
            (int) lnk->mcast_snooping,
            lnk->mcast_router,
            (int) lnk->mcast_query_use_ifaddr,
            (int) lnk->mcast_querier,
            lnk->mcast_hash_max != NM_BRIDGE_MULTICAST_HASH_MAX_DEF
                ? nm_sprintf_buf(sbuf_mhm, "mcast_hash_max %u ", lnk->mcast_hash_max)
                : "",
            lnk->mcast_last_member_count != NM_BRIDGE_MULTICAST_LAST_MEMBER_COUNT_DEF
                ? nm_sprintf_buf(sbuf_mlmc,
                                 "mcast_last_member_count %u ",
                                 lnk->mcast_last_member_count)
                : "",
            lnk->mcast_startup_query_count != NM_BRIDGE_MULTICAST_STARTUP_QUERY_COUNT_DEF
                ? nm_sprintf_buf(sbuf_msqc,
                                 "mcast_startup_query_count %u ",
                                 lnk->mcast_startup_query_count)
                : "",
            lnk->mcast_last_member_interval != NM_BRIDGE_MULTICAST_LAST_MEMBER_INTERVAL_DEF
                ? nm_sprintf_buf(sbuf_mlmi,
                                 "mcast_last_member_interval %" G_GUINT64_FORMAT " ",
                                 lnk->mcast_last_member_interval)
                : "",
            lnk->mcast_membership_interval != NM_BRIDGE_MULTICAST_MEMBERSHIP_INTERVAL_DEF
                ? nm_sprintf_buf(sbuf_mmi,
                                 "mcast_membership_interval %" G_GUINT64_FORMAT " ",
                                 lnk->mcast_membership_interval)
                : "",
            lnk->mcast_querier_interval != NM_BRIDGE_MULTICAST_QUERIER_INTERVAL_DEF
                ? nm_sprintf_buf(sbuf_mqi,
                                 "mcast_querier_interval %" G_GUINT64_FORMAT " ",
                                 lnk->mcast_querier_interval)
                : "",
            lnk->mcast_query_interval != NM_BRIDGE_MULTICAST_QUERY_INTERVAL_DEF
                ? nm_sprintf_buf(sbuf_mqii,
                                 "mcast_query_interval %" G_GUINT64_FORMAT " ",
                                 lnk->mcast_query_interval)
                : "",
            lnk->mcast_query_response_interval != NM_BRIDGE_MULTICAST_QUERY_RESPONSE_INTERVAL_DEF
                ? nm_sprintf_buf(sbuf_mqri,
                                 "mcast_query_response_interval %" G_GUINT64_FORMAT " ",
                                 lnk->mcast_query_response_interval)
                : "",
            lnk->mcast_startup_query_interval != NM_BRIDGE_MULTICAST_STARTUP_QUERY_INTERVAL_DEF
                ? nm_sprintf_buf(sbuf_msqi,
                                 "mcast_startup_query_interval %" G_GUINT64_FORMAT " ",
                                 lnk->mcast_startup_query_interval)
                : "");
        if (r == 0)
            pllink = nmtstp_assert_wait_for_link(platform, name, NM_LINK_TYPE_BRIDGE, 100);
        else
            _LOGI(
                "Adding bridge device via iproute2 failed. Assume iproute2 is not up to the task.");
    }

    if (!pllink) {
        r = nm_platform_link_bridge_add(platform, name, NULL, 0, 0, lnk, &pllink);
    }

    _assert_pllink(platform, r == 0, pllink, name, NM_LINK_TYPE_BRIDGE);

    ll = NMP_OBJECT_CAST_LNK_BRIDGE(NMP_OBJECT_UP_CAST(pllink)->_link.netlink.lnk);

    /* account for roundtrip rounding error with clock_t_to_jiffies()/jiffies_to_clock_t(). */
    g_assert_cmpint(lnk->forward_delay, >=, ll->forward_delay - 1);
    g_assert_cmpint(lnk->forward_delay, <=, ll->forward_delay);

    g_assert_cmpint(lnk->hello_time, ==, ll->hello_time);
    g_assert_cmpint(lnk->max_age, ==, ll->max_age);
    g_assert_cmpint(lnk->ageing_time, ==, ll->ageing_time);
    g_assert_cmpint(lnk->stp_state, ==, ll->stp_state);
    g_assert_cmpint(lnk->priority, ==, ll->priority);
    g_assert_cmpint(lnk->vlan_stats_enabled, ==, ll->vlan_stats_enabled);
    g_assert_cmpint(lnk->group_fwd_mask, ==, ll->group_fwd_mask);
    g_assert_cmpint(lnk->mcast_snooping, ==, ll->mcast_snooping);
    g_assert_cmpint(lnk->mcast_router, ==, ll->mcast_router);
    g_assert_cmpint(lnk->mcast_query_use_ifaddr, ==, ll->mcast_query_use_ifaddr);
    g_assert_cmpint(lnk->mcast_querier, ==, ll->mcast_querier);
    g_assert_cmpint(lnk->mcast_hash_max, ==, ll->mcast_hash_max);
    g_assert_cmpint(lnk->mcast_last_member_count, ==, ll->mcast_last_member_count);
    g_assert_cmpint(lnk->mcast_startup_query_count, ==, ll->mcast_startup_query_count);
    g_assert_cmpint(lnk->mcast_last_member_interval, ==, ll->mcast_last_member_interval);
    g_assert_cmpint(lnk->mcast_membership_interval, ==, ll->mcast_membership_interval);
    g_assert_cmpint(lnk->mcast_querier_interval, ==, ll->mcast_querier_interval);
    g_assert_cmpint(lnk->mcast_query_interval, ==, ll->mcast_query_interval);
    g_assert_cmpint(lnk->mcast_query_response_interval, ==, ll->mcast_query_response_interval);
    g_assert_cmpint(lnk->mcast_startup_query_interval, ==, ll->mcast_startup_query_interval);

    return pllink;
}
const NMPlatformLink *
nmtstp_link_veth_add(NMPlatform *platform,
                     gboolean    external_command,
                     const char *name,
                     const char *peer)
{
    const NMPlatformLink *pllink  = NULL;
    gboolean              success = FALSE;

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        success = !nmtstp_run_command("ip link add dev %s type veth peer name %s", name, peer);
        if (success) {
            pllink = nmtstp_assert_wait_for_link(platform, name, NM_LINK_TYPE_VETH, 100);
            nmtstp_assert_wait_for_link(platform, peer, NM_LINK_TYPE_VETH, 10);
        } else {
            /* iproute2 might fail in copr. See below.
             * We accept that and try our platform implementation instead. */
            _LOGI("iproute2 failed to add veth device. Retry with platform code.");
            external_command = FALSE;
        }
    }

    if (!external_command) {
        int try_count = 0;
        int r;

again:
        r = nm_platform_link_veth_add(platform, name, peer, &pllink);
        if (r == -EPERM && try_count++ < 5) {
            /* in copr (mock with Fedora 33 builders), this randomly fails with EPERM.
             * Very odd. Try to work around by retrying. */
            _LOGI("netlink failuer EPERM to add veth device. Retry.");
            goto again;
        }
        success = NMTST_NM_ERR_SUCCESS(r);
    }

    g_assert(success);
    _assert_pllink(platform, success, pllink, name, NM_LINK_TYPE_VETH);
    return pllink;
}

const NMPlatformLink *
nmtstp_link_dummy_add(NMPlatform *platform, gboolean external_command, const char *name)
{
    const NMPlatformLink *pllink = NULL;
    gboolean              success;

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        success = !nmtstp_run_command("ip link add %s type dummy", name);
        if (success)
            pllink = nmtstp_assert_wait_for_link(platform, name, NM_LINK_TYPE_DUMMY, 100);
    } else
        success = NMTST_NM_ERR_SUCCESS(nm_platform_link_dummy_add(platform, name, &pllink));

    g_assert(success);
    _assert_pllink(platform, success, pllink, name, NM_LINK_TYPE_DUMMY);
    return pllink;
}

const NMPlatformLink *
nmtstp_link_gre_add(NMPlatform *            platform,
                    gboolean                external_command,
                    const char *            name,
                    const NMPlatformLnkGre *lnk)
{
    const NMPlatformLink *pllink = NULL;
    gboolean              success;
    char                  b1[INET_ADDRSTRLEN];
    char                  b2[INET_ADDRSTRLEN];
    NMLinkType            link_type;

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));

    external_command = nmtstp_run_command_check_external(external_command);
    link_type        = lnk->is_tap ? NM_LINK_TYPE_GRETAP : NM_LINK_TYPE_GRE;

    _init_platform(&platform, external_command);

    if (external_command) {
        gs_free char *dev = NULL;
        char *        obj, *type;

        if (lnk->parent_ifindex)
            dev =
                g_strdup_printf("dev %s", nm_platform_link_get_name(platform, lnk->parent_ifindex));

        obj  = lnk->is_tap ? "link" : "tunnel";
        type = lnk->is_tap ? "type gretap" : "mode gre";

        success = !nmtstp_run_command("ip %s add %s %s %s local %s remote %s ttl %u tos %02x %s",
                                      obj,
                                      name,
                                      type,
                                      dev ?: "",
                                      _nm_utils_inet4_ntop(lnk->local, b1),
                                      _nm_utils_inet4_ntop(lnk->remote, b2),
                                      lnk->ttl,
                                      lnk->tos,
                                      lnk->path_mtu_discovery ? "pmtudisc" : "nopmtudisc");
        if (success)
            pllink = nmtstp_assert_wait_for_link(platform, name, link_type, 100);
    } else
        success =
            NMTST_NM_ERR_SUCCESS(nm_platform_link_gre_add(platform, name, NULL, 0, lnk, &pllink));

    _assert_pllink(platform, success, pllink, name, link_type);

    return pllink;
}

const NMPlatformLink *
nmtstp_link_ip6tnl_add(NMPlatform *               platform,
                       gboolean                   external_command,
                       const char *               name,
                       const NMPlatformLnkIp6Tnl *lnk)
{
    const NMPlatformLink *pllink = NULL;
    gboolean              success;
    char                  b1[NM_UTILS_INET_ADDRSTRLEN];
    char                  b2[NM_UTILS_INET_ADDRSTRLEN];
    char                  encap[20];
    char                  tclass[20];
    gboolean              encap_ignore;
    gboolean              tclass_inherit;

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));
    g_assert(!lnk->is_gre);

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        gs_free char *dev = NULL;
        const char *  mode;

        if (lnk->parent_ifindex)
            dev =
                g_strdup_printf("dev %s", nm_platform_link_get_name(platform, lnk->parent_ifindex));

        switch (lnk->proto) {
        case IPPROTO_IPIP:
            mode = "ipip6";
            break;
        case IPPROTO_IPV6:
            mode = "ip6ip6";
            break;
        default:
            g_assert_not_reached();
        }

        encap_ignore   = NM_FLAGS_HAS(lnk->flags, IP6_TNL_F_IGN_ENCAP_LIMIT);
        tclass_inherit = NM_FLAGS_HAS(lnk->flags, IP6_TNL_F_USE_ORIG_TCLASS);

        success = !nmtstp_run_command(
            "ip -6 tunnel add %s mode %s %s local %s remote %s ttl %u tclass %s encaplimit %s "
            "flowlabel %x",
            name,
            mode,
            dev,
            _nm_utils_inet6_ntop(&lnk->local, b1),
            _nm_utils_inet6_ntop(&lnk->remote, b2),
            lnk->ttl,
            tclass_inherit ? "inherit" : nm_sprintf_buf(tclass, "%02x", lnk->tclass),
            encap_ignore ? "none" : nm_sprintf_buf(encap, "%u", lnk->encap_limit),
            lnk->flow_label);
        if (success)
            pllink = nmtstp_assert_wait_for_link(platform, name, NM_LINK_TYPE_IP6TNL, 100);
    } else
        success = NMTST_NM_ERR_SUCCESS(nm_platform_link_ip6tnl_add(platform, name, lnk, &pllink));

    _assert_pllink(platform, success, pllink, name, NM_LINK_TYPE_IP6TNL);

    return pllink;
}

const NMPlatformLink *
nmtstp_link_ip6gre_add(NMPlatform *               platform,
                       gboolean                   external_command,
                       const char *               name,
                       const NMPlatformLnkIp6Tnl *lnk)
{
    const NMPlatformLink *pllink = NULL;
    gboolean              success;
    char                  b1[NM_UTILS_INET_ADDRSTRLEN];
    char                  b2[NM_UTILS_INET_ADDRSTRLEN];
    char                  tclass[20];
    gboolean              tclass_inherit;

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));
    g_assert(lnk->is_gre);

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        gs_free char *dev = NULL;

        if (lnk->parent_ifindex)
            dev =
                g_strdup_printf("dev %s", nm_platform_link_get_name(platform, lnk->parent_ifindex));

        tclass_inherit = NM_FLAGS_HAS(lnk->flags, IP6_TNL_F_USE_ORIG_TCLASS);

        success = !nmtstp_run_command(
            "ip link add %s type %s %s local %s remote %s ttl %u tclass %s flowlabel %x",
            name,
            lnk->is_tap ? "ip6gretap" : "ip6gre",
            dev,
            _nm_utils_inet6_ntop(&lnk->local, b1),
            _nm_utils_inet6_ntop(&lnk->remote, b2),
            lnk->ttl,
            tclass_inherit ? "inherit" : nm_sprintf_buf(tclass, "%02x", lnk->tclass),
            lnk->flow_label);
        if (success) {
            pllink = nmtstp_assert_wait_for_link(platform,
                                                 name,
                                                 lnk->is_tap ? NM_LINK_TYPE_IP6GRETAP
                                                             : NM_LINK_TYPE_IP6GRE,
                                                 100);
        }
    } else
        success = NMTST_NM_ERR_SUCCESS(
            nm_platform_link_ip6gre_add(platform, name, NULL, 0, lnk, &pllink));

    _assert_pllink(platform,
                   success,
                   pllink,
                   name,
                   lnk->is_tap ? NM_LINK_TYPE_IP6GRETAP : NM_LINK_TYPE_IP6GRE);

    return pllink;
}

const NMPlatformLink *
nmtstp_link_ipip_add(NMPlatform *             platform,
                     gboolean                 external_command,
                     const char *             name,
                     const NMPlatformLnkIpIp *lnk)
{
    const NMPlatformLink *pllink = NULL;
    gboolean              success;
    char                  b1[INET_ADDRSTRLEN];
    char                  b2[INET_ADDRSTRLEN];

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        gs_free char *dev = NULL;

        if (lnk->parent_ifindex)
            dev =
                g_strdup_printf("dev %s", nm_platform_link_get_name(platform, lnk->parent_ifindex));

        success = !nmtstp_run_command(
            "ip tunnel add %s mode ipip %s local %s remote %s ttl %u tos %02x %s",
            name,
            dev,
            _nm_utils_inet4_ntop(lnk->local, b1),
            _nm_utils_inet4_ntop(lnk->remote, b2),
            lnk->ttl,
            lnk->tos,
            lnk->path_mtu_discovery ? "pmtudisc" : "nopmtudisc");
        if (success)
            pllink = nmtstp_assert_wait_for_link(platform, name, NM_LINK_TYPE_IPIP, 100);
    } else
        success = NMTST_NM_ERR_SUCCESS(nm_platform_link_ipip_add(platform, name, lnk, &pllink));

    _assert_pllink(platform, success, pllink, name, NM_LINK_TYPE_IPIP);

    return pllink;
}

const NMPlatformLink *
nmtstp_link_macvlan_add(NMPlatform *                platform,
                        gboolean                    external_command,
                        const char *                name,
                        int                         parent,
                        const NMPlatformLnkMacvlan *lnk)
{
    const NMPlatformLink *pllink = NULL;
    gboolean              success;
    NMLinkType            link_type;

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    link_type = lnk->tap ? NM_LINK_TYPE_MACVTAP : NM_LINK_TYPE_MACVLAN;

    if (external_command) {
        const char *dev;
        char *      modes[] = {
            [MACVLAN_MODE_BRIDGE]   = "bridge",
            [MACVLAN_MODE_VEPA]     = "vepa",
            [MACVLAN_MODE_PRIVATE]  = "private",
            [MACVLAN_MODE_PASSTHRU] = "passthru",
        };

        dev = nm_platform_link_get_name(platform, parent);
        g_assert(dev);
        g_assert_cmpint(lnk->mode, <, G_N_ELEMENTS(modes));

        success = !nmtstp_run_command("ip link add name %s link %s type %s mode %s %s",
                                      name,
                                      dev,
                                      lnk->tap ? "macvtap" : "macvlan",
                                      modes[lnk->mode],
                                      lnk->no_promisc ? "nopromisc" : "");
        if (success)
            pllink = nmtstp_assert_wait_for_link(platform, name, link_type, 100);
    } else
        success = NMTST_NM_ERR_SUCCESS(
            nm_platform_link_macvlan_add(platform, name, parent, lnk, &pllink));

    _assert_pllink(platform, success, pllink, name, link_type);

    return pllink;
}

const NMPlatformLink *
nmtstp_link_sit_add(NMPlatform *            platform,
                    gboolean                external_command,
                    const char *            name,
                    const NMPlatformLnkSit *lnk)
{
    const NMPlatformLink *pllink = NULL;
    gboolean              success;
    char                  b1[INET_ADDRSTRLEN];
    char                  b2[INET_ADDRSTRLEN];

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        const char *dev = "";

        if (lnk->parent_ifindex) {
            const char *parent_name;

            parent_name = nm_platform_link_get_name(platform, lnk->parent_ifindex);
            g_assert(parent_name);
            dev = nm_sprintf_bufa(100, " dev %s", parent_name);
        }

        success =
            !nmtstp_run_command("ip tunnel add %s mode sit%s local %s remote %s ttl %u tos %02x %s",
                                name,
                                dev,
                                _nm_utils_inet4_ntop(lnk->local, b1),
                                _nm_utils_inet4_ntop(lnk->remote, b2),
                                lnk->ttl,
                                lnk->tos,
                                lnk->path_mtu_discovery ? "pmtudisc" : "nopmtudisc");
        if (success)
            pllink = nmtstp_assert_wait_for_link(platform, name, NM_LINK_TYPE_SIT, 100);
    } else
        success = NMTST_NM_ERR_SUCCESS(nm_platform_link_sit_add(platform, name, lnk, &pllink));

    _assert_pllink(platform, success, pllink, name, NM_LINK_TYPE_SIT);

    return pllink;
}

const NMPlatformLink *
nmtstp_link_tun_add(NMPlatform *            platform,
                    gboolean                external_command,
                    const char *            name,
                    const NMPlatformLnkTun *lnk,
                    int *                   out_fd)
{
    const NMPlatformLink *pllink = NULL;
    int                   err;
    int                   r;

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));
    g_assert(lnk);
    g_assert(NM_IN_SET(lnk->type, IFF_TUN, IFF_TAP));
    g_assert(!out_fd || *out_fd == -1);

    if (!lnk->persist) {
        /* ip tuntap does not support non-persistent devices.
         *
         * Add this device only via NMPlatform. */
        if (external_command == -1)
            external_command = FALSE;
    }

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        g_assert(lnk->persist);

        err = nmtstp_run_command(
            "ip tuntap add"
            " mode %s"
            "%s" /* user */
            "%s" /* group */
            "%s" /* pi */
            "%s" /* vnet_hdr */
            "%s" /* multi_queue */
            " name %s",
            lnk->type == IFF_TUN ? "tun" : "tap",
            lnk->owner_valid ? nm_sprintf_bufa(100, " user %u", (guint) lnk->owner) : "",
            lnk->group_valid ? nm_sprintf_bufa(100, " group %u", (guint) lnk->group) : "",
            lnk->pi ? " pi" : "",
            lnk->vnet_hdr ? " vnet_hdr" : "",
            lnk->multi_queue ? " multi_queue" : "",
            name);
        /* Older versions of iproute2 don't support adding  devices.
         * On failure, fallback to using platform code. */
        if (err == 0)
            pllink = nmtstp_assert_wait_for_link(platform, name, NM_LINK_TYPE_TUN, 100);
        else
            g_error("failure to add tun/tap device via ip-route");
    } else {
        g_assert(lnk->persist || out_fd);
        r = nm_platform_link_tun_add(platform, name, lnk, &pllink, out_fd);
        g_assert_cmpint(r, ==, 0);
    }

    g_assert(pllink);
    g_assert_cmpint(pllink->type, ==, NM_LINK_TYPE_TUN);
    g_assert_cmpstr(pllink->name, ==, name);
    return pllink;
}

const NMPlatformLink *
nmtstp_link_vrf_add(NMPlatform *            platform,
                    gboolean                external_command,
                    const char *            name,
                    const NMPlatformLnkVrf *lnk,
                    gboolean *              out_not_supported)
{
    const NMPlatformLink *pllink = NULL;
    int                   r      = 0;

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));

    NM_SET_OUT(out_not_supported, FALSE);
    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        r = nmtstp_run_command("ip link add %s type vrf table %u", name, lnk->table);

        if (r == 0)
            pllink = nmtstp_assert_wait_for_link(platform, name, NM_LINK_TYPE_VRF, 100);
        else
            _LOGI("Adding vrf device via iproute2 failed. Assume iproute2 is not up to the task.");
    }

    if (!pllink) {
        r = nm_platform_link_vrf_add(platform, name, lnk, &pllink);
        if (r == -EOPNOTSUPP)
            NM_SET_OUT(out_not_supported, TRUE);
    }

    _assert_pllink(platform, r == 0, pllink, name, NM_LINK_TYPE_VRF);

    return pllink;
}

const NMPlatformLink *
nmtstp_link_vxlan_add(NMPlatform *              platform,
                      gboolean                  external_command,
                      const char *              name,
                      const NMPlatformLnkVxlan *lnk)
{
    const NMPlatformLink *pllink = NULL;
    int                   err;
    int                   r;

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        gs_free char *dev = NULL;
        char          local[NM_UTILS_INET_ADDRSTRLEN];
        char          group[NM_UTILS_INET_ADDRSTRLEN];

        if (lnk->parent_ifindex)
            dev =
                g_strdup_printf("dev %s", nm_platform_link_get_name(platform, lnk->parent_ifindex));

        if (lnk->local)
            _nm_utils_inet4_ntop(lnk->local, local);
        else if (memcmp(&lnk->local6, &in6addr_any, sizeof(in6addr_any)))
            _nm_utils_inet6_ntop(&lnk->local6, local);
        else
            local[0] = '\0';

        if (lnk->group)
            _nm_utils_inet4_ntop(lnk->group, group);
        else if (memcmp(&lnk->group6, &in6addr_any, sizeof(in6addr_any)))
            _nm_utils_inet6_ntop(&lnk->group6, group);
        else
            group[0] = '\0';

        err = nmtstp_run_command("ip link add %s type vxlan id %u %s local %s group %s ttl %u tos "
                                 "%02x dstport %u srcport %u %u ageing %u",
                                 name,
                                 lnk->id,
                                 dev ?: "",
                                 local,
                                 group,
                                 lnk->ttl,
                                 lnk->tos,
                                 lnk->dst_port,
                                 lnk->src_port_min,
                                 lnk->src_port_max,
                                 lnk->ageing);
        /* Older versions of iproute2 don't support adding vxlan devices.
         * On failure, fallback to using platform code. */
        if (err == 0)
            pllink = nmtstp_assert_wait_for_link(platform, name, NM_LINK_TYPE_VXLAN, 100);
        else
            _LOGI(
                "Adding vxlan device via iproute2 failed. Assume iproute2 is not up to the task.");
    }
    if (!pllink) {
        r = nm_platform_link_vxlan_add(platform, name, lnk, &pllink);
        g_assert(NMTST_NM_ERR_SUCCESS(r));
        g_assert(pllink);
    }

    g_assert_cmpint(pllink->type, ==, NM_LINK_TYPE_VXLAN);
    g_assert_cmpstr(pllink->name, ==, name);
    return pllink;
}

/*****************************************************************************/

const NMPlatformLink *
nmtstp_link_get_typed(NMPlatform *platform, int ifindex, const char *name, NMLinkType link_type)
{
    const NMPlatformLink *pllink = NULL;

    _init_platform(&platform, FALSE);

    if (ifindex > 0) {
        pllink = nm_platform_link_get(platform, ifindex);

        if (pllink) {
            g_assert_cmpint(pllink->ifindex, ==, ifindex);
            if (name)
                g_assert_cmpstr(name, ==, pllink->name);
        } else {
            if (name)
                g_assert(!nm_platform_link_get_by_ifname(platform, name));
        }
    } else {
        g_assert(name);

        pllink = nm_platform_link_get_by_ifname(platform, name);

        if (pllink)
            g_assert_cmpstr(name, ==, pllink->name);
    }

    g_assert(!name || nm_utils_ifname_valid_kernel(name, NULL));

    if (pllink && link_type != NM_LINK_TYPE_NONE)
        g_assert_cmpint(pllink->type, ==, link_type);

    return pllink;
}

const NMPlatformLink *
nmtstp_link_get(NMPlatform *platform, int ifindex, const char *name)
{
    return nmtstp_link_get_typed(platform, ifindex, name, NM_LINK_TYPE_NONE);
}

/*****************************************************************************/

void
nmtstp_link_delete(NMPlatform *platform,
                   gboolean    external_command,
                   int         ifindex,
                   const char *name,
                   gboolean    require_exist)
{
    gint64                end_time;
    const NMPlatformLink *pllink;
    gboolean              success;
    gs_free char *        name_copy = NULL;

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    pllink = nmtstp_link_get(platform, ifindex, name);

    if (!pllink) {
        g_assert(!require_exist);
        return;
    }

    name = name_copy = g_strdup(pllink->name);
    ifindex          = pllink->ifindex;

    if (external_command) {
        nmtstp_run_command_check("ip link delete %s", name);
    } else {
        success = nm_platform_link_delete(platform, ifindex);
        g_assert(success);
    }

    /* Let's wait until we get the result */
    end_time = nm_utils_get_monotonic_timestamp_msec() + 250;
    do {
        if (external_command)
            nm_platform_process_events(platform);

        if (!nm_platform_link_get(platform, ifindex)) {
            g_assert(!nm_platform_link_get_by_ifname(platform, name));
            break;
        }

        /* for internal command, we expect not to reach this line.*/
        g_assert(external_command);

        nmtstp_assert_wait_for_signal_until(platform, end_time);
    } while (TRUE);
}

/*****************************************************************************/

void
nmtstp_link_set_updown(NMPlatform *platform, gboolean external_command, int ifindex, gboolean up)
{
    const NMPlatformLink *plink;
    gint64                end_time;

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        const char *ifname;

        ifname = nm_platform_link_get_name(platform, ifindex);
        g_assert(ifname);

        nmtstp_run_command_check("ip link set %s %s", ifname, up ? "up" : "down");
    } else {
        if (up)
            g_assert(nm_platform_link_set_up(platform, ifindex, NULL));
        else
            g_assert(nm_platform_link_set_down(platform, ifindex));
    }

    /* Let's wait until we get the result */
    end_time = nm_utils_get_monotonic_timestamp_msec() + 250;
    do {
        if (external_command)
            nm_platform_process_events(platform);

        /* let's wait until we see the address as we added it. */
        plink = nm_platform_link_get(platform, ifindex);
        g_assert(plink);

        if (NM_FLAGS_HAS(plink->n_ifi_flags, IFF_UP) == !!up)
            break;

        /* for internal command, we expect not to reach this line.*/
        g_assert(external_command);

        nmtstp_assert_wait_for_signal_until(platform, end_time);
    } while (TRUE);
}

/*****************************************************************************/

gboolean
nmtstp_kernel_support_get(NMPlatformKernelSupportType type)
{
    const NMPlatformLink *pllink;
    NMOptionBool          v;

    v = nm_platform_kernel_support_get_full(type, FALSE);
    if (v != NM_OPTION_BOOL_DEFAULT)
        return v != NM_OPTION_BOOL_FALSE;

    switch (type) {
    case NM_PLATFORM_KERNEL_SUPPORT_TYPE_IFLA_BR_VLAN_STATS_ENABLED:
        pllink = nmtstp_link_bridge_add(NULL, -1, "br-test-11", &nm_platform_lnk_bridge_default);
        nmtstp_link_delete(NULL, -1, pllink->ifindex, NULL, TRUE);
        v = nm_platform_kernel_support_get_full(type, FALSE);
        g_assert(v != NM_OPTION_BOOL_DEFAULT);
        return v;
    default:
        g_assert_not_reached();
    }
}

/*****************************************************************************/

struct _NMTstpNamespaceHandle {
    pid_t pid;
    int   pipe_fd;
};

NMTstpNamespaceHandle *
nmtstp_namespace_create(int unshare_flags, GError **error)
{
    NMTstpNamespaceHandle *ns_handle;
    int                    e;
    int                    errsv;
    pid_t                  pid, pid2;
    int                    pipefd_c2p[2];
    int                    pipefd_p2c[2];
    ssize_t                r;

    e = pipe2(pipefd_c2p, O_CLOEXEC);
    if (e != 0) {
        errsv = errno;
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    "pipe() failed with %d (%s)",
                    errsv,
                    nm_strerror_native(errsv));
        return FALSE;
    }

    e = pipe2(pipefd_p2c, O_CLOEXEC);
    if (e != 0) {
        errsv = errno;
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    "pipe() failed with %d (%s)",
                    errsv,
                    nm_strerror_native(errsv));
        nm_close(pipefd_c2p[0]);
        nm_close(pipefd_c2p[1]);
        return FALSE;
    }

    pid = fork();
    if (pid < 0) {
        errsv = errno;
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    "fork() failed with %d (%s)",
                    errsv,
                    nm_strerror_native(errsv));
        nm_close(pipefd_c2p[0]);
        nm_close(pipefd_c2p[1]);
        nm_close(pipefd_p2c[0]);
        nm_close(pipefd_p2c[1]);
        return FALSE;
    }

    if (pid == 0) {
        char read_buf[1];

        nm_close(pipefd_c2p[0]); /* close read-end */
        nm_close(pipefd_p2c[1]); /* close write-end */

        if (unshare(unshare_flags) != 0) {
            errsv = errno;
            if (errsv == 0)
                errsv = -1;
        } else
            errsv = 0;

        /* sync with parent process and send result. */
        do {
            r = write(pipefd_c2p[1], &errsv, sizeof(errsv));
        } while (r < 0 && errno == EINTR);
        if (r != sizeof(errsv)) {
            errsv = errno;
            if (errsv == 0)
                errsv = -2;
        }
        nm_close(pipefd_c2p[1]);

        /* wait until parent process terminates (or kills us). */
        if (errsv == 0) {
            do {
                r = read(pipefd_p2c[0], read_buf, sizeof(read_buf));
            } while (r < 0 && errno == EINTR);
        }
        nm_close(pipefd_p2c[0]);
        _exit(0);
    }

    nm_close(pipefd_c2p[1]); /* close write-end */
    nm_close(pipefd_p2c[0]); /* close read-end */

    /* sync with child process. */
    do {
        r = read(pipefd_c2p[0], &errsv, sizeof(errsv));
    } while (r < 0 && errno == EINTR);

    nm_close(pipefd_c2p[0]);

    if (r != sizeof(errsv) || errsv != 0) {
        int status;

        if (r != sizeof(errsv)) {
            g_set_error(error,
                        NM_UTILS_ERROR,
                        NM_UTILS_ERROR_UNKNOWN,
                        "child process failed for unknown reason");
        } else {
            g_set_error(error,
                        NM_UTILS_ERROR,
                        NM_UTILS_ERROR_UNKNOWN,
                        "child process signaled failure %d (%s)",
                        errsv,
                        nm_strerror_native(errsv));
        }
        nm_close(pipefd_p2c[1]);
        kill(pid, SIGKILL);
        do {
            pid2 = waitpid(pid, &status, 0);
        } while (pid2 == -1 && errno == EINTR);
        return FALSE;
    }

    ns_handle          = g_new0(NMTstpNamespaceHandle, 1);
    ns_handle->pid     = pid;
    ns_handle->pipe_fd = pipefd_p2c[1];
    return ns_handle;
}

pid_t
nmtstp_namespace_handle_get_pid(NMTstpNamespaceHandle *ns_handle)
{
    g_return_val_if_fail(ns_handle, 0);
    g_return_val_if_fail(ns_handle->pid > 0, 0);

    return ns_handle->pid;
}

void
nmtstp_namespace_handle_release(NMTstpNamespaceHandle *ns_handle)
{
    pid_t pid;
    int   status;

    if (!ns_handle)
        return;

    g_return_if_fail(ns_handle->pid > 0);

    nm_close(ns_handle->pipe_fd);
    ns_handle->pipe_fd = 0;

    kill(ns_handle->pid, SIGKILL);

    do {
        pid = waitpid(ns_handle->pid, &status, 0);
    } while (pid == -1 && errno == EINTR);
    ns_handle->pid = 0;

    g_free(ns_handle);
}

int
nmtstp_namespace_get_fd_for_process(pid_t pid, const char *ns_name)
{
    char p[1000];

    g_return_val_if_fail(pid > 0, 0);
    g_return_val_if_fail(ns_name && ns_name[0] && strlen(ns_name) < 50, 0);

    nm_sprintf_buf(p, "/proc/%lu/ns/%s", (unsigned long) pid, ns_name);

    return open(p, O_RDONLY | O_CLOEXEC);
}

/*****************************************************************************/

void
nmtstp_netns_select_random(NMPlatform **platforms, gsize n_platforms, NMPNetns **netns)
{
    int i;

    g_assert(platforms);
    g_assert(n_platforms && n_platforms <= G_MAXINT32);
    g_assert(netns && !*netns);
    for (i = 0; i < n_platforms; i++)
        g_assert(NM_IS_PLATFORM(platforms[i]));

    i = nmtst_get_rand_uint32() % (n_platforms + 1);
    if (i == 0)
        return;
    g_assert(nm_platform_netns_push(platforms[i - 1], netns));
}

/*****************************************************************************/

NMTST_DEFINE();

static gboolean
unshare_user(void)
{
    FILE *f;
    uid_t uid = geteuid();
    gid_t gid = getegid();

    /* Already a root? */
    if (gid == 0 && uid == 0)
        return TRUE;

    /* Become a root in new user NS. */
    if (unshare(CLONE_NEWUSER) != 0)
        return FALSE;

    /* Since Linux 3.19 we have to disable setgroups() in order to map users.
     * Just proceed if the file is not there. */
    f = fopen("/proc/self/setgroups", "we");
    if (f) {
        fprintf(f, "deny");
        fclose(f);
    }

    /* Map current UID to root in NS to be created. */
    f = fopen("/proc/self/uid_map", "we");
    if (!f)
        return FALSE;
    fprintf(f, "0 %d 1", uid);
    fclose(f);

    /* Map current GID to root in NS to be created. */
    f = fopen("/proc/self/gid_map", "we");
    if (!f)
        return FALSE;
    fprintf(f, "0 %d 1", gid);
    fclose(f);

    return TRUE;
}

int
main(int argc, char **argv)
{
    int         result;
    const char *program = *argv;

    _nmtstp_init_tests(&argc, &argv);

    if (nmtstp_is_root_test() && (geteuid() != 0 || getegid() != 0)) {
        if (g_getenv("NMTST_FORCE_REAL_ROOT") || !unshare_user()) {
            /* Try to exec as sudo, this function does not return, if a sudo-cmd is set. */
            nmtst_reexec_sudo();

#ifdef REQUIRE_ROOT_TESTS
            g_print("Fail test: requires root privileges (%s)\n", program);
            return EXIT_FAILURE;
#else
            g_print("Skipping test: requires root privileges (%s)\n", program);
            return g_test_run();
#endif
        }
    }

    if (nmtstp_is_root_test() && !g_getenv("NMTST_NO_UNSHARE")) {
        int errsv;

        if (unshare(CLONE_NEWNET | CLONE_NEWNS) != 0) {
            errsv = errno;
            if (errsv == EPERM) {
#ifdef REQUIRE_ROOT_TESTS
                g_print("Fail test: unshare(CLONE_NEWNET|CLONE_NEWNS) failed with %s (%d)\n",
                        nm_strerror_native(errsv),
                        errsv);
                return EXIT_FAILURE;
#else
                g_print("Skipping test: unshare(CLONE_NEWNET|CLONE_NEWNS) failed with %s (%d)\n",
                        nm_strerror_native(errsv),
                        errsv);
                return g_test_run();
#endif
            }
            g_error("Fail test: unshare(CLONE_NEWNET|CLONE_NEWNS) failed with %s (%d)",
                    nm_strerror_native(errsv),
                    errsv);
        }

        /* We need a read-only /sys so that the platform knows there's no udev. */
        mount(NULL, "/sys", "sysfs", MS_SLAVE, NULL);
        if (mount("sys", "/sys", "sysfs", MS_RDONLY, NULL) != 0) {
            errsv = errno;
            g_error("mount(\"/sys\") failed with %s (%d)", nm_strerror_native(errsv), errsv);
        }
    }

    nmtstp_setup_platform();

    _nmtstp_setup_tests();

    result = g_test_run();

    nmtstp_link_delete(NM_PLATFORM_GET, -1, -1, DEVICE_NAME, FALSE);

    g_object_unref(NM_PLATFORM_GET);
    return result;
}

/*****************************************************************************/

struct _NMTstpAcdDefender {
    int        ifindex;
    in_addr_t  ip_addr;
    NAcd *     nacd;
    NAcdProbe *probe;
    GSource *  source;
    gint8      announce_started;
};

static gboolean
_l3_acd_nacd_event(int fd, GIOCondition condition, gpointer user_data)
{
    NMTstpAcdDefender *defender = user_data;
    int                r;

    r = n_acd_dispatch(defender->nacd);
    if (r == N_ACD_E_PREEMPTED)
        r = 0;
    g_assert_cmpint(r, ==, 0);

    while (TRUE) {
        NAcdEvent *event;

        r = n_acd_pop_event(defender->nacd, &event);
        g_assert_cmpint(r, ==, 0);
        if (!event)
            return G_SOURCE_CONTINUE;

        switch (event->event) {
        case N_ACD_EVENT_READY:
            g_assert_cmpint(defender->announce_started, ==, 0);
            g_assert(defender->probe == event->ready.probe);
            defender->announce_started++;
            _LOGT("acd-defender[" NM_HASH_OBFUSCATE_PTR_FMT "]: start announcing",
                  NM_HASH_OBFUSCATE_PTR(defender));
            r = n_acd_probe_announce(defender->probe, N_ACD_DEFEND_ALWAYS);
            g_assert_cmpint(r, ==, 0);
            break;
        case N_ACD_EVENT_DEFENDED:
            g_assert(defender->probe == event->defended.probe);
            g_assert_cmpint(event->defended.n_sender, ==, ETH_ALEN);
            _LOGT("acd-defender[" NM_HASH_OBFUSCATE_PTR_FMT
                  "]: defended from " NM_ETHER_ADDR_FORMAT_STR,
                  NM_HASH_OBFUSCATE_PTR(defender),
                  NM_ETHER_ADDR_FORMAT_VAL((const NMEtherAddr *) event->defended.sender));
            break;
        case N_ACD_EVENT_USED:
        case N_ACD_EVENT_CONFLICT:
        case N_ACD_EVENT_DOWN:
        default:
            g_assert_not_reached();
            break;
        }
    }
}

NMTstpAcdDefender *
nmtstp_acd_defender_new(int ifindex, in_addr_t ip_addr, const NMEtherAddr *mac_addr)
{
    NMTstpAcdDefender *                                defender;
    nm_auto(n_acd_config_freep) NAcdConfig *           config       = NULL;
    nm_auto(n_acd_unrefp) NAcd *                       nacd         = NULL;
    nm_auto(n_acd_probe_config_freep) NAcdProbeConfig *probe_config = NULL;
    NAcdProbe *                                        probe        = NULL;
    int                                                fd;
    int                                                r;
    char                                               sbuf_addr[NM_UTILS_INET_ADDRSTRLEN];

    g_assert_cmpint(ifindex, >, 0);
    g_assert(mac_addr);

    r = n_acd_config_new(&config);
    g_assert_cmpint(r, ==, 0);
    g_assert(config);

    n_acd_config_set_ifindex(config, ifindex);
    n_acd_config_set_transport(config, N_ACD_TRANSPORT_ETHERNET);
    n_acd_config_set_mac(config, (const guint8 *) mac_addr, sizeof(*mac_addr));

    r = n_acd_new(&nacd, config);
    g_assert_cmpint(r, ==, 0);
    g_assert(nacd);

    r = n_acd_probe_config_new(&probe_config);
    g_assert_cmpint(r, ==, 0);
    g_assert(probe_config);

    n_acd_probe_config_set_ip(probe_config, (struct in_addr){ip_addr});
    n_acd_probe_config_set_timeout(probe_config, 0);

    r = n_acd_probe(nacd, &probe, probe_config);
    g_assert_cmpint(r, ==, 0);
    g_assert(probe);

    defender  = g_slice_new(NMTstpAcdDefender);
    *defender = (NMTstpAcdDefender){
        .ifindex = ifindex,
        .ip_addr = ip_addr,
        .nacd    = g_steal_pointer(&nacd),
        .probe   = g_steal_pointer(&probe),
    };

    _LOGT("acd-defender[" NM_HASH_OBFUSCATE_PTR_FMT
          "]: new for ifindex=%d, hwaddr=" NM_ETHER_ADDR_FORMAT_STR ", ipaddr=%s",
          NM_HASH_OBFUSCATE_PTR(defender),
          ifindex,
          NM_ETHER_ADDR_FORMAT_VAL(mac_addr),
          _nm_utils_inet4_ntop(ip_addr, sbuf_addr));

    n_acd_probe_set_userdata(defender->probe, defender);

    n_acd_get_fd(defender->nacd, &fd);
    g_assert_cmpint(fd, >=, 0);

    defender->source = nm_g_source_attach(nm_g_unix_fd_source_new(fd,
                                                                  G_IO_IN,
                                                                  G_PRIORITY_DEFAULT,
                                                                  _l3_acd_nacd_event,
                                                                  defender,
                                                                  NULL),
                                          NULL);

    return defender;
}

void
nmtstp_acd_defender_destroy(NMTstpAcdDefender *defender)
{
    if (!defender)
        return;

    _LOGT("acd-defender[" NM_HASH_OBFUSCATE_PTR_FMT "]: destroy", NM_HASH_OBFUSCATE_PTR(defender));

    nm_clear_g_source_inst(&defender->source);
    nm_clear_pointer(&defender->nacd, n_acd_unref);
    nm_clear_pointer(&defender->probe, n_acd_probe_free);

    nm_g_slice_free(defender);
}
