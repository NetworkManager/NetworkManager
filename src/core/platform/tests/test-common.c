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
#include <linux/rtnetlink.h>

#include "n-acd/src/n-acd.h"
#include "libnm-platform/nm-platform-utils.h"

#define SIGNAL_DATA_FMT "'%s-%s' ifindex %d%s%s%s (%d times received)"
#define SIGNAL_DATA_ARG(data)                                                                     \
    (data)->name, nm_platform_signal_change_type_to_string((data)->change_type), (data)->ifindex, \
        (data)->ifname ? " ifname '" : "", (data)->ifname ?: "", (data)->ifname ? "'" : "",       \
        (data)->received_count

int NMTSTP_ENV1_IFINDEXES[];

const char *const NMTSTP_ENV1_DEVICE_NAME[] = {
    "nm-test-device0",
    "nm-test-device1",
};

int NMTSTP_ENV1_EX = -1;

/*****************************************************************************/

typedef struct {
    const char *module_name;

    NMLinkType iftype;

    /* These modules create additional interfaces, like
     * "gre0" for "ip_gre" module.
     *
     * - actually some modules create multiple interfaces, like "ip_gre"
     *   creating "gre0", "gretap0", "erspan0".
     * - if already an interface with such name exist, kernel would create
     *   names like "gre1" or "gretap1". We don't care for that, because
     *   we run in our own namespace and we control which interfaces are there.
     *   We wouldn't create an interface with such a conflicting name.
     *
     * Anyway. This is the name of *one* of the interfaces that the module would
     * create. */
    const char *ifname;

    /* This only gets set, if iftype is NM_LINK_TYPE_UNKNOWN. It corresponds to
     * NMPlatformLink.kind. */
    const char *ifkind;

} IPTunnelModInfo;

#define INF(_module_name, _iftype, _ifname, ...)                                           \
    {                                                                                      \
        .module_name = ""_module_name, .iftype = _iftype, .ifname = ""_ifname, __VA_ARGS__ \
    }

static const IPTunnelModInfo ip_tunnel_mod_infos[] = {
    INF("ip_gre", NM_LINK_TYPE_GRE, "gre0"),
    INF("ip_gre", NM_LINK_TYPE_GRETAP, "gretap0"),
    INF("ip_gre", NM_LINK_TYPE_UNKNOWN, "erspan0", .ifkind = "erspan"),
    INF("ipip", NM_LINK_TYPE_IPIP, "tunl0"),
    INF("ip6_tunnel", NM_LINK_TYPE_IP6TNL, "ip6tnl0"),
    INF("ip6_gre", NM_LINK_TYPE_IP6GRE, "ip6gre0"),
    INF("sit", NM_LINK_TYPE_SIT, "sit0"),
    INF("ip_vti", NM_LINK_TYPE_VTI, "ip_vti0"),
    INF("ip6_vti", NM_LINK_TYPE_VTI6, "ip6_vti0"),
};

#undef INF

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
    return NM_IN_SET(_nmtstp_setup_platform_func,
                     nm_linux_platform_setup,
                     nm_linux_platform_setup_with_tc_cache);
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
    nmp_lookup_init_object_by_ifindex(&lookup, obj_type, ifindex);
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
    const NMPObject           *obj;
    NMPLookup                  lookup;

    g_assert(NM_IS_PLATFORM(self));
    nm_assert(ifindex >= 0);
    nm_assert_addr_family(addr_family);
    nm_assert(addr);

    if (ifindex > 0)
        nmp_lookup_init_object_by_ifindex(&lookup, NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4), ifindex);
    else
        nmp_lookup_init_obj_type(&lookup, NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4));

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
_nmtstp_platform_ip_addresses_assert(const char        *filename,
                                     int                lineno,
                                     NMPlatform        *self,
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
        const int                    addr_family = IS_IPv4 ? AF_INET : AF_INET6;
        gs_unref_ptrarray GPtrArray *plat_addrs  = NULL;
        NMPLookup                    lookup;
        guint                        j;

        plat_addrs = nm_platform_lookup_clone(
            self,
            nmp_lookup_init_object_by_ifindex(&lookup,
                                              NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4),
                                              ifindex),
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
                char sbuf[NM_INET_ADDRSTRLEN];

                g_error("%s:%d: IPv%c address %s was not found on ifindex %d",
                        filename,
                        lineno,
                        nm_utils_addr_family_to_char(addr_bin->addr_family),
                        nm_inet_ntop(addr_bin->addr_family, &addr_bin->addr, sbuf),
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
            char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];

            NM_PRAGMA_WARNING_DISABLE_DANGLING_POINTER
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
            NM_PRAGMA_WARNING_REENABLE
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
nmtstp_platform_ip6_route_delete(NMPlatform     *platform,
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
add_signal_full(const char                *name,
                NMPlatformSignalChangeType change_type,
                GCallback                  callback,
                int                        ifindex,
                const char                *ifname)
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
link_callback(NMPlatform     *platform,
              int             obj_type_i,
              int             ifindex,
              NMPlatformLink *received,
              int             change_type_i,
              SignalData     *data)
{
    const NMPObjectType              obj_type    = obj_type_i;
    const NMPlatformSignalChangeType change_type = change_type_i;
    NMPLookup                        lookup;
    NMDedupMultiIter                 iter;
    const NMPlatformLink            *cached;

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
               guint      *out_c_exists)
{
    NMDedupMultiIter          iter;
    NMPLookup                 lookup;
    const NMPObject          *o = NULL;
    guint                     c;
    const NMPlatformIP4Route *r = NULL;

    _init_platform(&platform, FALSE);

    nmp_lookup_init_ip4_route_by_weak_id(&lookup, RT_TABLE_MAIN, network, plen, metric, tos);

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
        char sbuf[NM_INET_ADDRSTRLEN];

        NM_PRAGMA_WARNING_DISABLE_DANGLING_POINTER
        g_error("[%s:%u] %s(): The ip4 route %s/%d metric %u tos %u shall exist %u times, but "
                "platform has it %u times",
                file,
                line,
                func,
                nm_inet4_ntop(network, sbuf),
                plen,
                metric,
                tos,
                c_exists,
                c);
        NM_PRAGMA_WARNING_REENABLE
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
_ip6_route_get(NMPlatform            *platform,
               int                    ifindex,
               const struct in6_addr *network,
               guint                  plen,
               guint32                metric,
               const struct in6_addr *src,
               guint8                 src_plen,
               guint                 *out_c_exists)
{
    NMDedupMultiIter          iter;
    NMPLookup                 lookup;
    const NMPObject          *o = NULL;
    guint                     c;
    const NMPlatformIP6Route *r = NULL;

    _init_platform(&platform, FALSE);

    nmp_lookup_init_ip6_route_by_weak_id(&lookup,
                                         RT_TABLE_MAIN,
                                         network,
                                         plen,
                                         metric,
                                         src,
                                         src_plen);

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
_nmtstp_assert_ip6_route_exists(const char            *file,
                                guint                  line,
                                const char            *func,
                                NMPlatform            *platform,
                                int                    c_exists,
                                const char            *ifname,
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
        char s_src[NM_INET_ADDRSTRLEN];
        char s_network[NM_INET_ADDRSTRLEN];

        NM_PRAGMA_WARNING_DISABLE_DANGLING_POINTER
        g_error("[%s:%u] %s(): The ip6 route %s/%d metric %u src %s/%d shall exist %u times, but "
                "platform has it %u times",
                file,
                line,
                func,
                nm_inet6_ntop(network, s_network),
                plen,
                metric,
                nm_inet6_ntop(src, s_src),
                src_plen,
                c_exists,
                c);
        NM_PRAGMA_WARNING_REENABLE
    }

    return r;
}

const NMPlatformIP6Route *
nmtstp_ip6_route_get(NMPlatform            *platform,
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

static int
_assert_platform_sort_objs(gconstpointer ptr_a, gconstpointer ptr_b)
{
    const NMPObject *a = *((const NMPObject *const *) ptr_a);
    const NMPObject *b = *((const NMPObject *const *) ptr_b);

    g_assert(NMP_OBJECT_IS_VALID(a));
    g_assert(NMP_OBJECT_IS_VALID(b));
    g_assert(NMP_OBJECT_GET_TYPE(a) == NMP_OBJECT_GET_TYPE(b));

    NM_CMP_RETURN(nmp_object_id_cmp(a, b));
    g_assert_not_reached();
    return 0;
}

static void
_assert_platform_printarr(NMPObjectType obj_type, GPtrArray *arr1, GPtrArray *arr2)
{
    char  sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    guint i;

    _LOGT("compare arrays of %s. In cache %u entries, fetched %u entries",
          NMP_OBJECT_TYPE_NAME(obj_type),
          nm_g_ptr_array_len(arr1),
          nm_g_ptr_array_len(arr2));

    for (i = 0; i < nm_g_ptr_array_len(arr1); i++) {
        _LOGT("cache[%u] %s",
              i,
              nmp_object_to_string(arr1->pdata[i], NMP_OBJECT_TO_STRING_ALL, sbuf, sizeof(sbuf)));
    }
    for (i = 0; i < nm_g_ptr_array_len(arr2); i++) {
        _LOGT("fetch[%u] %s",
              i,
              nmp_object_to_string(arr2->pdata[i], NMP_OBJECT_TO_STRING_ALL, sbuf, sizeof(sbuf)));
    }

    switch (obj_type) {
    case NMP_OBJECT_TYPE_LINK:
        nmtstp_run_command("ip -d link");
        break;
    case NMP_OBJECT_TYPE_IP4_ADDRESS:
        nmtstp_run_command("ip -d -4 address");
        break;
    case NMP_OBJECT_TYPE_IP6_ADDRESS:
        nmtstp_run_command("ip -d -6 address");
        break;
    case NMP_OBJECT_TYPE_IP4_ROUTE:
        nmtstp_run_command("ip -d -4 route show table all");
        break;
    case NMP_OBJECT_TYPE_IP6_ROUTE:
        nmtstp_run_command("ip -d -6 route show table all");
        break;
    default:
        g_assert_not_reached();
        break;
    }
}

static gboolean
_assert_platform_normalize_all(GPtrArray *arr)
{
    guint    i;
    gboolean normalized = FALSE;

    for (i = 0; i < nm_g_ptr_array_len(arr); i++) {
        const NMPObject **ptr         = (gpointer) &arr->pdata[i];
        nm_auto_nmpobj NMPObject *new = NULL;
        gboolean skip                 = FALSE;

        switch (NMP_OBJECT_GET_TYPE(*ptr)) {
        case NMP_OBJECT_TYPE_LINK:
        {
            const NMPlatformLink *link = NMP_OBJECT_CAST_LINK(*ptr);

            if (nmtstp_link_is_iptunnel_special(link)) {
                /* These are special interfaces for the ip tunnel modules, like
                 * "gre0" created by the "ip_gre" module.
                 *
                 * These interfaces can appear at any moment, when the module
                 * gets loaded (by anybody on the host). We might want to avoid
                 * that by calling nmtstp_ensure_module(), but it's worse.
                 * Kernel does not send correct RTM_NEWLINK events when those
                 * interfaces get created. So the cache content based on the
                 * events will differ from a new load from a dump.
                 *
                 * We need to ignore those interfaces. */
                skip = TRUE;
            } else if (link->type == NM_LINK_TYPE_UNKNOWN) {
                /* The link type is not detected. This might be a generated
                 * interface like nmtstp_link_is_iptunnel_special(), but for
                 * kernel modules that we don't know about. Ignore them too. */
                skip = TRUE;
            }

            if (!skip) {
                new                  = nmp_object_clone(*ptr, FALSE);
                new->link.rx_packets = 0;
                new->link.rx_bytes   = 0;
                new->link.tx_packets = 0;
                new->link.tx_bytes   = 0;
            }
            if (nmp_object_ref_set(ptr, new))
                normalized = TRUE;
            break;
        }
        default:
            break;
        }
    }

    while (g_ptr_array_remove(arr, NULL)) {
        /* Remove NULL values. */
        normalized = TRUE;
    }

    return normalized;
}

static gboolean
_assert_platform_compare_arr(NMPObjectType obj_type,
                             const char   *detail_type,
                             GPtrArray    *arr1,
                             GPtrArray    *arr2,
                             gboolean      normalized,
                             gboolean      share_multi_idx,
                             gboolean      do_assert)
{
    const NMPClass *obj_class = nmp_class_from_type(obj_type);
    char            sbuf1[NM_UTILS_TO_STRING_BUFFER_SIZE];
    char            sbuf2[NM_UTILS_TO_STRING_BUFFER_SIZE];
    int             idx;
    int             idx_pointer_comp = -1;

#define _fail_msg(do_assert, ...) \
    G_STMT_START                  \
    {                             \
        if (do_assert) {          \
            g_error(__VA_ARGS__); \
        } else {                  \
            _LOGW(__VA_ARGS__);   \
            return FALSE;         \
        }                         \
    }                             \
    G_STMT_END

    for (idx = 0; TRUE; idx++) {
        if (nm_g_ptr_array_len(arr1) == idx && nm_g_ptr_array_len(arr2) == idx)
            break;
        if (idx >= nm_g_ptr_array_len(arr1)) {
            _assert_platform_printarr(obj_type, arr1, arr2);
            _fail_msg(do_assert,
                      "Comparing %s (%s) for platform fails. Platform now shows entry #%u which is "
                      "not in the cache but expected %s",
                      obj_class->obj_type_name,
                      detail_type,
                      idx,
                      nmp_object_to_string(arr2->pdata[idx],
                                           NMP_OBJECT_TO_STRING_ALL,
                                           sbuf1,
                                           sizeof(sbuf1)));
        }
        if (idx >= nm_g_ptr_array_len(arr2)) {
            _assert_platform_printarr(obj_type, arr1, arr2);
            _fail_msg(
                do_assert,
                "Comparing %s (%s) for platform fails. Platform has no more entry #%u which is "
                "still in the cache as %s",
                obj_class->obj_type_name,
                detail_type,
                idx,
                nmp_object_to_string(arr1->pdata[idx],
                                     NMP_OBJECT_TO_STRING_ALL,
                                     sbuf1,
                                     sizeof(sbuf1)));
        }
        if (!nmp_object_equal(arr1->pdata[idx], arr2->pdata[idx])) {
            _assert_platform_printarr(obj_type, arr1, arr2);
            _fail_msg(do_assert,
                      "Comparing %s (%s) for platform fails. Platform entry #%u is now %s but in "
                      "cache is %s",
                      obj_class->obj_type_name,
                      detail_type,
                      idx,
                      nmp_object_to_string(arr2->pdata[idx],
                                           NMP_OBJECT_TO_STRING_ALL,
                                           sbuf1,
                                           sizeof(sbuf1)),
                      nmp_object_to_string(arr1->pdata[idx],
                                           NMP_OBJECT_TO_STRING_ALL,
                                           sbuf2,
                                           sizeof(sbuf2)));
        }

        if (!normalized && (share_multi_idx != (arr1->pdata[idx] == arr2->pdata[idx]))
            && idx_pointer_comp == -1)
            idx_pointer_comp = idx;
    }

    if (idx_pointer_comp != -1) {
        _assert_platform_printarr(obj_type, arr1, arr2);
        _fail_msg(do_assert,
                  "Comparing %s (%s) for platform fails for pointer comparison. Platform entry "
                  "#%u is now %s but in cache is %s",
                  obj_class->obj_type_name,
                  detail_type,
                  idx_pointer_comp,
                  nmp_object_to_string(arr2->pdata[idx_pointer_comp],
                                       NMP_OBJECT_TO_STRING_ALL,
                                       sbuf1,
                                       sizeof(sbuf1)),
                  nmp_object_to_string(arr1->pdata[idx_pointer_comp],
                                       NMP_OBJECT_TO_STRING_ALL,
                                       sbuf2,
                                       sizeof(sbuf2)));
    }

    return TRUE;
}

/*****************************************************************************/

gboolean
nmtstp_link_is_iptunnel_special(const NMPlatformLink *link)
{
    int i;

    g_assert(link);

    /* These interfaces are autogenerated when loading the ip tunnel
     * modules. For example, loading "ip_gre" results in interfaces
     * "gre0", "gretap0", "erspan0".
     *
     * Actually, if the interface names are already taken ("gre0" already
     * exists), it will create "gre1" and so on. We don't care about that,
     * because in our test's netns that is not happening. */

    for (i = 0; i < (int) G_N_ELEMENTS(ip_tunnel_mod_infos); i++) {
        const IPTunnelModInfo *module_info = &ip_tunnel_mod_infos[i];

        if (module_info->iftype != link->type)
            continue;
        if (!nm_streq(module_info->ifname, link->name))
            continue;
        if (module_info->ifkind && !nm_streq(module_info->ifkind, link->kind))
            continue;

        return TRUE;
    }

    return FALSE;
}

/*****************************************************************************/

gboolean
nmtstp_ensure_module(const char *module_name)
{
    /* using iproute2 seems to fail sometimes? Force use of platform code. */
    const int              EX          = 0;
    gs_free char          *test_ifname = NULL;
    const NMPlatformLink  *link;
    static int             module_state[G_N_ELEMENTS(ip_tunnel_mod_infos)] = {0};
    int                    i_module_info;
    const IPTunnelModInfo *module_info = NULL;
    int                    i;
    int                    ifindex;
    gboolean               result;

    if (!module_name) {
        result = TRUE;
        for (i = 0; i < (int) G_N_ELEMENTS(ip_tunnel_mod_infos); i++) {
            if (!nmtstp_ensure_module(ip_tunnel_mod_infos[i].module_name))
                result = FALSE;
        }
        return result;
    }

    for (i_module_info = 0; i_module_info < (int) G_N_ELEMENTS(ip_tunnel_mod_infos);
         i_module_info++) {
        if (nm_streq(module_name, ip_tunnel_mod_infos[i_module_info].module_name)) {
            module_info = &ip_tunnel_mod_infos[i_module_info];
            break;
        }
    }
    if (!module_info)
        g_error("%s:%d: Module name \"%s\" not implemented!", __FILE__, __LINE__, module_name);

    test_ifname = g_strdup_printf("nm-mod-%s", module_info->ifname);
    g_assert(nm_utils_ifname_valid_kernel(test_ifname, NULL));

again:
    i = g_atomic_int_get(&module_state[i_module_info]);
    if (i != 0)
        return i > 0;

    /* When tunnel modules get loaded, then interfaces like "gre0", "gretap0"
     * and "erspan0" (for "ip_gre" module) appear. For other modules, the interfaces
     * are named differently. Of course, unless those interface name are already taken,
     * in which case it will create "gre1", etc). So ugly.
     *
     * Anyway. as we run unit tests in parallel (`make check -j`), another
     * test might just load the module just now, which results in the creation of
     * those interfaces in our current namespace. That can break the test.
     */

    link = nmtstp_link_get_typed(NM_PLATFORM_GET, 0, test_ifname, module_info->iftype);
    g_assert(!link);

    link = nmtstp_link_get_typed(NM_PLATFORM_GET, 0, module_info->ifname, module_info->iftype);
    if (link) {
        g_assert(nmtstp_link_is_iptunnel_special(link));
        /* An interface with this name exists. While technically this could not be the interface
         * generated by the kernel module, in our test netns we can assume that it is. This is
         * good enough. */
        result = TRUE;
        goto out;
    }

    /* Try to load the module. It probably won't work, because we don't have permissions.
     * Ignore any failure. */
    nmp_utils_modprobe(NULL, TRUE, module_info->module_name, NULL);

    if (nm_streq(module_name, "ip_gre")) {
        link = nmtstp_link_gre_add(NULL,
                                   EX,
                                   test_ifname,
                                   &((const NMPlatformLnkGre){
                                       .local          = nmtst_inet4_from_string("192.168.233.204"),
                                       .remote         = nmtst_inet4_from_string("172.168.10.25"),
                                       .parent_ifindex = 0,
                                       .ttl            = 174,
                                       .tos            = 37,
                                       .path_mtu_discovery = TRUE,
                                   }));
    } else if (nm_streq(module_name, "ipip")) {
        link = nmtstp_link_ipip_add(NULL,
                                    EX,
                                    test_ifname,
                                    &((const NMPlatformLnkIpIp){
                                        .local              = nmtst_inet4_from_string("1.2.3.4"),
                                        .remote             = nmtst_inet4_from_string("5.6.7.8"),
                                        .parent_ifindex     = 0,
                                        .tos                = 32,
                                        .path_mtu_discovery = FALSE,
                                    }));
    } else if (nm_streq(module_name, "ip6_tunnel")) {
        link = nmtstp_link_ip6tnl_add(NULL,
                                      EX,
                                      test_ifname,
                                      &((const NMPlatformLnkIp6Tnl){
                                          .local       = nmtst_inet6_from_string("fd01::15"),
                                          .remote      = nmtst_inet6_from_string("fd01::16"),
                                          .tclass      = 20,
                                          .encap_limit = 6,
                                          .flow_label  = 1337,
                                          .proto       = IPPROTO_IPV6,
                                      }));
    } else if (nm_streq(module_name, "ip6_gre")) {
        link = nmtstp_link_ip6gre_add(NULL,
                                      EX,
                                      test_ifname,
                                      &((const NMPlatformLnkIp6Tnl){
                                          .local      = nmtst_inet6_from_string("fd01::42"),
                                          .remote     = nmtst_inet6_from_string("fd01::aaaa"),
                                          .tclass     = 21,
                                          .flow_label = 1338,
                                          .is_gre     = TRUE,
                                      }));
    } else if (nm_streq(module_name, "sit")) {
        link = nmtstp_link_sit_add(NULL,
                                   EX,
                                   test_ifname,
                                   &((const NMPlatformLnkSit){
                                       .local  = nmtst_inet4_from_string("192.168.200.1"),
                                       .remote = nmtst_inet4_from_string("172.25.100.14"),
                                       .ttl    = 0,
                                       .tos    = 31,
                                       .path_mtu_discovery = FALSE,
                                   }));
    } else if (nm_streq(module_name, "ip_vti")) {
        link = nmtstp_link_vti_add(NULL,
                                   EX,
                                   test_ifname,
                                   &((const NMPlatformLnkVti){
                                       .local  = nmtst_inet4_from_string("192.168.212.204"),
                                       .remote = nmtst_inet4_from_string("172.168.11.25"),
                                       .ikey   = 12,
                                       .okey   = 13,
                                   }));
    } else if (nm_streq(module_name, "ip6_vti")) {
        link = nmtstp_link_vti6_add(NULL,
                                    EX,
                                    test_ifname,
                                    &((const NMPlatformLnkVti6){
                                        .local  = nmtst_inet6_from_string("fd01::1"),
                                        .remote = nmtst_inet6_from_string("fd02::2"),
                                        .ikey   = 13,
                                        .okey   = 14,
                                    }));
    } else
        g_error("%s:%d: Module name \"%s\" not implemented!", __FILE__, __LINE__, module_name);

    if (!link) {
        /* We might be unable to add the interface, if the kernel module does not exist.
         * Be graceful about that. */
        ifindex = 0;
        g_assert(!nmtstp_link_get_typed(NM_PLATFORM_GET, 0, test_ifname, module_info->iftype));
        g_assert(
            !nmtstp_link_get_typed(NM_PLATFORM_GET, 0, module_info->ifname, module_info->iftype));
    } else {
        ifindex = link->ifindex;

        g_assert(link);
        g_assert(
            link
            == nmtstp_link_get_typed(NM_PLATFORM_GET, ifindex, test_ifname, module_info->iftype));

        nmtstp_link_delete(NULL, -1, link->ifindex, test_ifname, TRUE);

        link = nmtstp_link_get_typed(NM_PLATFORM_GET, 0, module_info->ifname, module_info->iftype);
        g_assert(nmtstp_link_is_iptunnel_special(link));
    }

    result = ifindex > 0 ? 1 : -1;

out:
    if (!g_atomic_int_compare_and_exchange(&module_state[i_module_info], 0, result))
        goto again;

    if (!result) {
        /* The function aims to be graceful about missing kernel modules. */

        /* g_error("Failure to ensure module \"%s\"", module_name); */
    }

    return result;
}

gboolean
nmtstp_check_platform_full(NMPlatform *platform, guint32 obj_type_flags, gboolean do_assert)
{
    static const NMPObjectType obj_types[] = {
        NMP_OBJECT_TYPE_IP4_ADDRESS,
        NMP_OBJECT_TYPE_IP6_ADDRESS,
        NMP_OBJECT_TYPE_IP4_ROUTE,
        NMP_OBJECT_TYPE_IP6_ROUTE,
        NMP_OBJECT_TYPE_LINK,
    };
    gboolean                    obj_type_flags_all = (obj_type_flags == 0u);
    gs_unref_object NMPlatform *platform2          = NULL;
    int                         i_obj_types;
    gboolean                    share_multi_idx = nmtst_get_rand_bool();

    /* This test creates a new NMLinuxPlatform instance. This will fill
     * the cache with a new dump.
     *
     * Then it compares the content with @platform and checks that they
     * agree. This tests that @platform cache is consistent, as it was
     * updated based on netlink events. */

    g_assert(NM_IS_LINUX_PLATFORM(platform));

    _LOGD("assert-platform: start");

    nm_platform_process_events(platform);

    platform2 = nm_linux_platform_new(share_multi_idx ? nm_platform_get_multi_idx(platform) : NULL,
                                      TRUE,
                                      nmtst_get_rand_bool(),
                                      nmtst_get_rand_bool());
    g_assert(NM_IS_LINUX_PLATFORM(platform2));

    for (i_obj_types = 0; i_obj_types < (int) G_N_ELEMENTS(obj_types); i_obj_types++) {
        const NMPObjectType          obj_type         = obj_types[i_obj_types];
        const guint32                i_obj_type_flags = nmp_object_type_to_flags(obj_type);
        gs_unref_ptrarray GPtrArray *arr1             = NULL;
        gs_unref_ptrarray GPtrArray *arr2             = NULL;
        NMPLookup                    lookup;
        gboolean                     check_unordered = TRUE;
        guint                        idx;
        gboolean                     normalized;

        if (!obj_type_flags_all) {
            if (!NM_FLAGS_ANY(obj_type_flags, i_obj_type_flags))
                continue;
            obj_type_flags = NM_FLAGS_UNSET(obj_type_flags, i_obj_type_flags);
        }

        nmp_lookup_init_obj_type(&lookup, obj_type);

        arr1 = nm_platform_lookup_clone(platform, &lookup, NULL, NULL) ?: g_ptr_array_new();
        arr2 = nm_platform_lookup_clone(platform2, &lookup, NULL, NULL) ?: g_ptr_array_new();

        normalized = _assert_platform_normalize_all(arr1);
        normalized = _assert_platform_normalize_all(arr2);

        if (check_unordered) {
            /* We need to sort the two lists. */
            g_ptr_array_sort(arr1, _assert_platform_sort_objs);
            g_ptr_array_sort(arr2, _assert_platform_sort_objs);
        }

        if (!_assert_platform_compare_arr(obj_type,
                                          "main",
                                          arr1,
                                          arr2,
                                          normalized,
                                          share_multi_idx,
                                          do_assert))
            return FALSE;

        if (NM_IN_SET(obj_type, NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE)) {
            /* For routes, the WEAK_ID needs to be sorted and match the expected order. Check that. */
            g_assert(!normalized);
            for (idx = 0; idx < nm_g_ptr_array_len(arr1); idx++) {
                const NMPObject             *obj1         = arr1->pdata[idx];
                const NMPObject             *obj2         = arr2->pdata[idx];
                gs_unref_ptrarray GPtrArray *arr1b        = NULL;
                gs_unref_ptrarray GPtrArray *arr2b        = NULL;
                gs_unref_ptrarray GPtrArray *arr1b_sorted = NULL;
                gs_unref_ptrarray GPtrArray *arr2b_sorted = NULL;
                guint                        found_obj1   = 0;
                guint                        found_obj2   = 0;
                guint                        i;

                nmp_lookup_init_route_by_weak_id(&lookup, obj1);
                arr1b =
                    nm_platform_lookup_clone(platform, &lookup, NULL, NULL) ?: g_ptr_array_new();
                g_assert_cmpint(arr1b->len, >, 0u);

                nmp_lookup_init_route_by_weak_id(&lookup, obj2);
                arr2b =
                    nm_platform_lookup_clone(platform2, &lookup, NULL, NULL) ?: g_ptr_array_new();
                g_assert_cmpint(arr2b->len, ==, arr1b->len);

                /* First check that the lists agree, if we sort them. The list of
                 * weak-ids was supposed to honor the sort order from `ip route show`,
                 * but as that is not the case (see blow), first check whether at
                 * least the same routes are in the list (with wrong sort order). */
                arr1b_sorted = nm_g_ptr_array_new_clone(arr1b, NULL, NULL, NULL);
                arr2b_sorted = nm_g_ptr_array_new_clone(arr2b, NULL, NULL, NULL);
                g_ptr_array_sort(arr1b_sorted, _assert_platform_sort_objs);
                g_ptr_array_sort(arr2b_sorted, _assert_platform_sort_objs);
                if (!_assert_platform_compare_arr(obj_type,
                                                  "weak-id-sorted",
                                                  arr1b_sorted,
                                                  arr2b_sorted,
                                                  normalized,
                                                  share_multi_idx,
                                                  do_assert))
                    return FALSE;

                if (obj_type == NMP_OBJECT_TYPE_IP6_ROUTE) {
                    /* For IPv6, the weak-ids are actually not sorted correctly.
                     * This is because IPv6 multihop/ECMP routes get split into
                     * multiple objects, and we don't get this right.
                     *
                     * This may be a bug. But we probably don't rely on this
                     * anymore, because the weak-id were used to find which
                     * route got replaced with `NLM_F_REPLACE`, but that anyway
                     * doesn't work. We now always request a new dump. */
                } else if (obj_type == NMP_OBJECT_TYPE_IP4_ROUTE) {
                    /* For IPv4, it also does not reliably always work. This may
                     * be a bug we want to fix. For now, ignore the check.
                     *
                     * a) Kernel can wrongly allow to configure the same route twice.
                     * That means, the same route is visible in `ip route` output,
                     * meaning, it would be added twice to the platform cache.
                     * At least due to that problem, may the weak-id not be properly sorted.
                     * See https://bugzilla.redhat.com/show_bug.cgi?id=2165720 which is
                     * a bug of kernel allowing to configure the exact same route twice.
                     *
                     * b) See https://bugzilla.redhat.com/show_bug.cgi?id=2162315 which is
                     * a bug where kernel does allow to configure single-hop routes that differ by
                     * their next-hop weight, but on the netlink API those routes look the same.
                     *
                     * Due to a) and b), the platform cache may contain only one instance
                     * of a route, which is visible more than once in `ip route` output.
                     * This merging of different routes causes problems, and it also means
                     * that the RTM_NEWROUTE events are wrongly interpreted and the weak-id
                     * is not properly sorted.
                     */
                } else {
                    /* Assert that also the original, not-sorted lists agree. */
                    if (!_assert_platform_compare_arr(obj_type,
                                                      "weak-id",
                                                      arr1b,
                                                      arr2b,
                                                      normalized,
                                                      share_multi_idx,
                                                      do_assert))
                        return FALSE;
                }

                for (i = 0; i < arr1b->len; i++) {
                    if (arr1b->pdata[i] == obj1)
                        found_obj1++;
                    if (arr2b->pdata[i] == obj2)
                        found_obj2++;
                }

                g_assert_cmpint(found_obj1, ==, 1u);
                g_assert_cmpint(found_obj2, ==, 1u);
            }
        }
    }

    g_clear_object(&platform2);

    _LOGD("assert-platform: done");

    g_assert_cmpint(obj_type_flags, ==, 0u);

    return TRUE;
}

void
nmtstp_check_platform(NMPlatform *platform, guint32 obj_type_flags)
{
    if (!nmtstp_check_platform_full(platform, obj_type_flags, FALSE)) {
        /* It's unclear why this failure sometimes happens. It happens
         * on gitlab-ci on Ubuntu/Debian(??).
         *
         * Retrying shortly after seems to avoid it. */
        g_usleep(20 * 1000);
        nm_platform_process_events(platform);
        nmtstp_run_command("ip route");
        nm_platform_process_events(platform);

        nmtstp_check_platform_full(platform, obj_type_flags, TRUE);
    }
}

/*****************************************************************************/

typedef struct {
    GMainLoop *loop;
    guint      signal_counts;
    guint      id;
} WaitForSignalData;

static void
_wait_for_signal_cb(NMPlatform     *platform,
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
_ip_address_add(NMPlatform     *platform,
                int             external_command,
                gboolean        is_v4,
                int             ifindex,
                const NMIPAddr *address,
                int             plen,
                const NMIPAddr *peer_address,
                guint32         lifetime,
                guint32         preferred,
                guint32         flags,
                const char     *label)
{
    gint64 end_time;

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        const char   *ifname;
        gs_free char *s_valid     = NULL;
        gs_free char *s_preferred = NULL;
        gs_free char *s_label     = NULL;
        char          b1[NM_INET_ADDRSTRLEN];
        char          b2[NM_INET_ADDRSTRLEN];

        ifname = nm_platform_link_get_name(platform, ifindex);
        g_assert(ifname);

        if (lifetime != NM_PLATFORM_LIFETIME_PERMANENT)
            s_valid = g_strdup_printf(" valid_lft %d", lifetime);
        if (preferred != NM_PLATFORM_LIFETIME_PERMANENT)
            s_preferred = g_strdup_printf(" preferred_lft %d", preferred);
        if (label)
            s_label = g_strdup_printf("%s:%s", ifname, label);

        if (is_v4) {
            char s_peer[NM_INET_ADDRSTRLEN + 50];

            g_assert(flags == 0);

            if (peer_address->addr4 != address->addr4 || nmtst_get_rand_uint32() % 2) {
                /* If the peer is the same as the local address, we can omit it. The result should be identical */
                nm_sprintf_buf(s_peer, " peer %s", nm_inet4_ntop(peer_address->addr4, b2));
            } else
                s_peer[0] = '\0';

            nmtstp_run_command_check("ip address change %s%s/%d dev %s%s%s%s",
                                     nm_inet4_ntop(address->addr4, b1),
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
                                     nm_inet6_ntop(&address->addr6, b1),
                                     !IN6_IS_ADDR_UNSPECIFIED(&peer_address->addr6) ? " peer " : "",
                                     !IN6_IS_ADDR_UNSPECIFIED(&peer_address->addr6)
                                         ? nm_inet6_ntop(&peer_address->addr6, b2)
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
                       int         external_command,
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
                    &((NMIPAddr){
                        .addr4 = address,
                    }),
                    plen,
                    &((NMIPAddr){
                        .addr4 = peer_address,
                    }),
                    lifetime,
                    preferred,
                    flags,
                    label);
}

void
nmtstp_ip6_address_add(NMPlatform     *platform,
                       int             external_command,
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
nmtstp_ip4_route_add(NMPlatform      *platform,
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

    g_assert(NMTST_NM_ERR_SUCCESS(
        nm_platform_ip4_route_add(platform, NMP_NLM_FLAG_REPLACE, &route, NULL)));
}

void
nmtstp_ip6_route_add(NMPlatform      *platform,
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
_ip_address_del(NMPlatform     *platform,
                int             external_command,
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
        char        b1[NM_INET_ADDRSTRLEN];
        char        b2[NM_INET_ADDRSTRLEN];
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
            success = nmtstp_run_command(
                "ip address delete %s%s%s/%d dev %s",
                nm_inet4_ntop(address->addr4, b1),
                peer_address->addr4 != address->addr4 ? " peer " : "",
                peer_address->addr4 != address->addr4 ? nm_inet4_ntop(peer_address->addr4, b2) : "",
                plen,
                ifname);
        } else {
            g_assert(!peer_address);
            success = nmtstp_run_command("ip address delete %s/%d dev %s",
                                         nm_inet6_ntop(&address->addr6, b1),
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
                       int         external_command,
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
nmtstp_ip6_address_del(NMPlatform     *platform,
                       int             external_command,
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

/* Due to rounding errors with clock_t_to_jiffies()/jiffies_to_clock_t(), kernel cannot
 * store all requested values. That means, when we try to configure a bridge with
 * the @requested values, the actually configured settings are slightly off, as
 * @kernel.
 *
 * This function takes @requested and returns it as @dst output. All fields
 * that might be mangled by kernel (according to @kernel) are adjusted. The
 * result is almost identical to @requested, but some fields might be adjusted
 * to their @kernel value. */
const NMPlatformLnkBridge *
nmtstp_link_bridge_normalize_jiffies_time(const NMPlatformLnkBridge *requested,
                                          const NMPlatformLnkBridge *kernel,
                                          NMPlatformLnkBridge       *dst)
{
    g_assert(requested);
    g_assert(dst);
    g_assert(kernel);

    if (dst != requested)
        *dst = *requested;

#define _normalize_field(dst, kernel, field)                                         \
    G_STMT_START                                                                     \
    {                                                                                \
        (dst)->field = nmtstp_normalize_jiffies_time((dst)->field, (kernel)->field); \
    }                                                                                \
    G_STMT_END

    _normalize_field(dst, kernel, forward_delay);
    _normalize_field(dst, kernel, hello_time);
    _normalize_field(dst, kernel, max_age);
    _normalize_field(dst, kernel, ageing_time);
    _normalize_field(dst, kernel, mcast_last_member_interval);
    _normalize_field(dst, kernel, mcast_membership_interval);
    _normalize_field(dst, kernel, mcast_querier_interval);
    _normalize_field(dst, kernel, mcast_query_interval);
    _normalize_field(dst, kernel, mcast_query_response_interval);
    _normalize_field(dst, kernel, mcast_startup_query_interval);

    return dst;
}

const NMPlatformLink *
nmtstp_link_bridge_add(NMPlatform                *platform,
                       int                        external_command,
                       const char                *name,
                       const NMPlatformLnkBridge *lnk)
{
    const NMPlatformLink      *pllink = NULL;
    const NMPlatformLnkBridge *ll     = NULL;
    NMPlatformLnkBridge        lnk_normalized;
    int                        r = 0;

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

    lnk = nmtstp_link_bridge_normalize_jiffies_time(lnk, ll, &lnk_normalized);

    g_assert_cmpint(lnk->forward_delay, ==, ll->forward_delay);
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
nmtstp_link_veth_add(NMPlatform *platform, int external_command, const char *name, const char *peer)
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
nmtstp_link_dummy_add(NMPlatform *platform, int external_command, const char *name)
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
nmtstp_link_gre_add(NMPlatform             *platform,
                    int                     external_command,
                    const char             *name,
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
        char         *obj, *type;

        if (lnk->parent_ifindex)
            dev =
                g_strdup_printf("dev %s", nm_platform_link_get_name(platform, lnk->parent_ifindex));

        obj  = lnk->is_tap ? "link" : "tunnel";
        type = lnk->is_tap ? "type gretap" : "mode gre";

        success = !nmtstp_run_command("ip %s add %s %s%s%s local %s remote %s ttl %u tos %02x %s",
                                      obj,
                                      name,
                                      type,
                                      NM_PRINT_FMT_QUOTED2(dev, " ", dev, ""),
                                      nm_inet4_ntop(lnk->local, b1),
                                      nm_inet4_ntop(lnk->remote, b2),
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
nmtstp_link_ip6tnl_add(NMPlatform                *platform,
                       int                        external_command,
                       const char                *name,
                       const NMPlatformLnkIp6Tnl *lnk)
{
    const NMPlatformLink *pllink = NULL;
    gboolean              success;
    char                  b1[NM_INET_ADDRSTRLEN];
    char                  b2[NM_INET_ADDRSTRLEN];
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
        const char   *mode;

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
            "ip -6 tunnel add %s mode %s%s%s local %s remote %s ttl %u tclass %s encaplimit %s "
            "flowlabel %x",
            name,
            mode,
            NM_PRINT_FMT_QUOTED2(dev, " ", dev, ""),
            nm_inet6_ntop(&lnk->local, b1),
            nm_inet6_ntop(&lnk->remote, b2),
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
nmtstp_link_ip6gre_add(NMPlatform                *platform,
                       int                        external_command,
                       const char                *name,
                       const NMPlatformLnkIp6Tnl *lnk)
{
    const NMPlatformLink *pllink = NULL;
    gboolean              success;
    char                  b1[NM_INET_ADDRSTRLEN];
    char                  b2[NM_INET_ADDRSTRLEN];
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
            "ip link add %s type %s%s%s local %s remote %s ttl %u tclass %s flowlabel %x",
            name,
            lnk->is_tap ? "ip6gretap" : "ip6gre",
            NM_PRINT_FMT_QUOTED2(dev, " ", dev, ""),
            nm_inet6_ntop(&lnk->local, b1),
            nm_inet6_ntop(&lnk->remote, b2),
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
nmtstp_link_ipip_add(NMPlatform              *platform,
                     int                      external_command,
                     const char              *name,
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
            "ip tunnel add %s mode ipip%s%s local %s remote %s ttl %u tos %02x %s",
            name,
            NM_PRINT_FMT_QUOTED2(dev, " ", dev, ""),
            nm_inet4_ntop(lnk->local, b1),
            nm_inet4_ntop(lnk->remote, b2),
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
nmtstp_link_macvlan_add(NMPlatform                 *platform,
                        int                         external_command,
                        const char                 *name,
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
        char       *modes[] = {
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
nmtstp_link_sit_add(NMPlatform             *platform,
                    int                     external_command,
                    const char             *name,
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
                                nm_inet4_ntop(lnk->local, b1),
                                nm_inet4_ntop(lnk->remote, b2),
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
nmtstp_link_tun_add(NMPlatform             *platform,
                    int                     external_command,
                    const char             *name,
                    const NMPlatformLnkTun *lnk,
                    int                    *out_fd)
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
nmtstp_link_vlan_add(NMPlatform              *platform,
                     int                      external_command,
                     const char              *name,
                     int                      parent,
                     const NMPlatformLnkVlan *lnk)
{
    const NMPlatformLink *pllink = NULL;
    gboolean              success;

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));

    external_command = nmtstp_run_command_check_external(external_command);

    _init_platform(&platform, external_command);

    if (external_command) {
        const char *dev;

        dev = nm_platform_link_get_name(platform, parent);
        g_assert(dev);
        g_assert(NM_IN_SET(lnk->protocol, ETH_P_8021Q, ETH_P_8021AD));

        success = !nmtstp_run_command(
            "ip link add name %s link %s type vlan id %hu protocol %s%s%s%s%s",
            name,
            dev,
            lnk->id,
            lnk->protocol == ETH_P_8021Q ? "802.1Q" : "802.1ad",
            !(lnk->flags & _NM_VLAN_FLAG_REORDER_HEADERS) ? " reorder_hdr off" : "",
            (lnk->flags & _NM_VLAN_FLAG_GVRP) ? " gvrp on" : "",
            (lnk->flags & _NM_VLAN_FLAG_MVRP) ? " mvrp on" : "",
            (lnk->flags & _NM_VLAN_FLAG_LOOSE_BINDING) ? " loose_binding on" : "");
        if (success)
            pllink = nmtstp_assert_wait_for_link(platform, name, NM_LINK_TYPE_VLAN, 100);
    } else
        success =
            NMTST_NM_ERR_SUCCESS(nm_platform_link_vlan_add(platform, name, parent, lnk, &pllink));

    _assert_pllink(platform, success, pllink, name, NM_LINK_TYPE_VLAN);

    return pllink;
}

const NMPlatformLink *
nmtstp_link_vti_add(NMPlatform             *platform,
                    gboolean                external_command,
                    const char             *name,
                    const NMPlatformLnkVti *lnk)
{
    const NMPlatformLink *pllink = NULL;
    gboolean              success;
    char                  b1[INET_ADDRSTRLEN];
    char                  b2[INET_ADDRSTRLEN];

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));
    external_command = nmtstp_run_command_check_external(external_command);
    _init_platform(&platform, external_command);
    g_assert(lnk->fwmark == 0);

    if (external_command) {
        gs_free char *dev = NULL;

        if (lnk->parent_ifindex)
            dev =
                g_strdup_printf("dev %s", nm_platform_link_get_name(platform, lnk->parent_ifindex));

        success =
            !nmtstp_run_command("ip link add %s type vti %s local %s remote %s ikey %u okey %u",
                                name,
                                dev ?: "",
                                nm_inet4_ntop(lnk->local, b1),
                                nm_inet4_ntop(lnk->remote, b2),
                                lnk->ikey,
                                lnk->okey);
        if (success)
            pllink = nmtstp_assert_wait_for_link(platform, name, NM_LINK_TYPE_VTI, 100);
    } else
        success = NMTST_NM_ERR_SUCCESS(nm_platform_link_vti_add(platform, name, lnk, &pllink));

    _assert_pllink(platform, success, pllink, name, NM_LINK_TYPE_VTI);

    return pllink;
}

const NMPlatformLink *
nmtstp_link_vti6_add(NMPlatform              *platform,
                     gboolean                 external_command,
                     const char              *name,
                     const NMPlatformLnkVti6 *lnk)
{
    const NMPlatformLink *pllink = NULL;
    gboolean              success;
    char                  b1[INET6_ADDRSTRLEN];
    char                  b2[INET6_ADDRSTRLEN];

    g_assert(nm_utils_ifname_valid_kernel(name, NULL));
    external_command = nmtstp_run_command_check_external(external_command);
    _init_platform(&platform, external_command);
    g_assert(lnk->fwmark == 0);

    if (external_command) {
        gs_free char *dev = NULL;

        if (lnk->parent_ifindex)
            dev =
                g_strdup_printf("dev %s", nm_platform_link_get_name(platform, lnk->parent_ifindex));

        success =
            !nmtstp_run_command("ip link add %s type vti6 %s local %s remote %s ikey %u okey %u",
                                name,
                                dev ?: "",
                                nm_inet6_ntop(&lnk->local, b1),
                                nm_inet6_ntop(&lnk->remote, b2),
                                lnk->ikey,
                                lnk->okey);
        if (success)
            pllink = nmtstp_assert_wait_for_link(platform, name, NM_LINK_TYPE_VTI6, 100);
    } else
        success = NMTST_NM_ERR_SUCCESS(nm_platform_link_vti6_add(platform, name, lnk, &pllink));

    _assert_pllink(platform, success, pllink, name, NM_LINK_TYPE_VTI6);

    return pllink;
}

const NMPlatformLink *
nmtstp_link_vrf_add(NMPlatform             *platform,
                    int                     external_command,
                    const char             *name,
                    const NMPlatformLnkVrf *lnk,
                    gboolean               *out_not_supported)
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
nmtstp_link_vxlan_add(NMPlatform               *platform,
                      int                       external_command,
                      const char               *name,
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
        char          local[NM_INET_ADDRSTRLEN];
        char          group[NM_INET_ADDRSTRLEN];

        if (lnk->parent_ifindex)
            dev =
                g_strdup_printf("dev %s", nm_platform_link_get_name(platform, lnk->parent_ifindex));

        if (lnk->local)
            nm_inet4_ntop(lnk->local, local);
        else if (memcmp(&lnk->local6, &in6addr_any, sizeof(in6addr_any)))
            nm_inet6_ntop(&lnk->local6, local);
        else
            local[0] = '\0';

        if (lnk->group)
            nm_inet4_ntop(lnk->group, group);
        else if (memcmp(&lnk->group6, &in6addr_any, sizeof(in6addr_any)))
            nm_inet6_ntop(&lnk->group6, group);
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
                   int         external_command,
                   int         ifindex,
                   const char *name,
                   gboolean    require_exist)
{
    gint64                end_time;
    const NMPlatformLink *pllink;
    gboolean              success;
    gs_free char         *name_copy = NULL;

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
nmtstp_link_set_updown(NMPlatform *platform, int external_command, int ifindex, gboolean up)
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
            g_assert(nm_platform_link_change_flags(platform, ifindex, IFF_UP, TRUE) >= 0);
        else
            g_assert(nm_platform_link_change_flags(platform, ifindex, IFF_UP, FALSE) >= 0);
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
    NAcd      *nacd;
    NAcdProbe *probe;
    GSource   *source;
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
        case N_ACD_EVENT_DOWN:
            /* Not sure why this sometimes happens. But this is only the test stub, ignore it. */
            _LOGT("acd-defender[" NM_HASH_OBFUSCATE_PTR_FMT "]: link down event received",
                  NM_HASH_OBFUSCATE_PTR(defender));
            break;
        case N_ACD_EVENT_USED:
        case N_ACD_EVENT_CONFLICT:
        default:
            g_assert_not_reached();
            break;
        }
    }
}

NMTstpAcdDefender *
nmtstp_acd_defender_new(int ifindex, in_addr_t ip_addr, const NMEtherAddr *mac_addr)
{
    NMTstpAcdDefender                                 *defender;
    nm_auto(n_acd_config_freep) NAcdConfig            *config       = NULL;
    nm_auto(n_acd_unrefp) NAcd                        *nacd         = NULL;
    nm_auto(n_acd_probe_config_freep) NAcdProbeConfig *probe_config = NULL;
    NAcdProbe                                         *probe        = NULL;
    int                                                fd;
    int                                                r;
    char                                               sbuf_addr[NM_INET_ADDRSTRLEN];

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
          nm_inet4_ntop(ip_addr, sbuf_addr));

    n_acd_probe_set_userdata(defender->probe, defender);

    n_acd_get_fd(defender->nacd, &fd);
    g_assert_cmpint(fd, >=, 0);

    defender->source = nm_g_unix_fd_add_source(fd, G_IO_IN, _l3_acd_nacd_event, defender);

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
