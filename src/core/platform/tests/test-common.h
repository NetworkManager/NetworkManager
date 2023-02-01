/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2016 - 2017 Red Hat, Inc.
 */

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/ip6_tunnel.h>

#include "libnm-platform/nm-platform.h"
#include "libnm-platform/nmp-object.h"
#include "platform/nm-fake-platform.h"
#include "libnm-platform/nm-linux-platform.h"

#include "nm-test-utils-core.h"

/*****************************************************************************/

#define nmtstp_normalize_jiffies_time(requested_value, kernel_value)                             \
    ({                                                                                           \
        typeof(kernel_value)  _kernel_value    = (kernel_value);                                 \
        typeof(_kernel_value) _requested_value = (requested_value);                              \
                                                                                                 \
        /* kernel stores some values (like bridge's forward_delay) in jiffies. When converting
         * back and forth (clock_t_to_jiffies()/jiffies_to_clock_t()), the value reported back
         * to user space may have rounding errors (of +/- 1), depending on CONFIG_HZ setting.
         *
         * Normalize the requested_value to the kernel_value, if it look as if a rounding
         * error happens. If the difference is larger than +/- 1, no normalization happens! */   \
                                                                                                 \
        ((_requested_value >= (NM_MAX(_kernel_value, 1) - 1))                                    \
         && (_requested_value <= (NM_MIN(_kernel_value, ~((typeof(_kernel_value)) 0) - 1) + 1))) \
            ? _kernel_value                                                                      \
            : _requested_value;                                                                  \
    })

#define _NMLOG_PREFIX_NAME "platform-test"
#define _NMLOG_DOMAIN      LOGD_PLATFORM
#define _NMLOG(level, ...) _LOG(level, _NMLOG_DOMAIN, __VA_ARGS__)

#define _LOG(level, domain, ...)                                                             \
    G_STMT_START                                                                             \
    {                                                                                        \
        const NMLogLevel  __level  = (level);                                                \
        const NMLogDomain __domain = (domain);                                               \
                                                                                             \
        if (nm_logging_enabled(__level, __domain)) {                                         \
            gint64 _ts = nm_utils_get_monotonic_timestamp_nsec();                            \
                                                                                             \
            _nm_log(__level,                                                                 \
                    __domain,                                                                \
                    0,                                                                       \
                    NULL,                                                                    \
                    NULL,                                                                    \
                    "%s[%ld.%09ld]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                    \
                    _NMLOG_PREFIX_NAME,                                                      \
                    (long) (_ts / NM_UTILS_NSEC_PER_SEC),                                    \
                    (long) (_ts % NM_UTILS_NSEC_PER_SEC) _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        }                                                                                    \
    }                                                                                        \
    G_STMT_END

/*****************************************************************************/

gboolean nmtstp_is_root_test(void);
gboolean nmtstp_is_sysfs_writable(void);

/*****************************************************************************/

typedef struct _NMTstpNamespaceHandle NMTstpNamespaceHandle;

NMTstpNamespaceHandle *nmtstp_namespace_create(int flags, GError **error);

void  nmtstp_namespace_handle_release(NMTstpNamespaceHandle *handle);
pid_t nmtstp_namespace_handle_get_pid(NMTstpNamespaceHandle *handle);

int nmtstp_namespace_get_fd_for_process(pid_t pid, const char *ns_name);

/*****************************************************************************/

void nmtstp_netns_select_random(NMPlatform **platforms, gsize n_platforms, NMPNetns **netns);

/*****************************************************************************/

typedef struct {
    gulong                     handler_id;
    const char                *name;
    NMPlatformSignalChangeType change_type;
    int                        received_count;
    GMainLoop                 *loop;
    int                        ifindex;
    const char                *ifname;
} SignalData;

SignalData *add_signal_full(const char                *name,
                            NMPlatformSignalChangeType change_type,
                            GCallback                  callback,
                            int                        ifindex,
                            const char                *ifname);
#define add_signal(name, change_type, callback) \
    add_signal_full(name, change_type, G_CALLBACK(callback), 0, NULL)
#define add_signal_ifindex(name, change_type, callback, ifindex) \
    add_signal_full(name, change_type, G_CALLBACK(callback), ifindex, NULL)
#define add_signal_ifname(name, change_type, callback, ifname) \
    add_signal_full(name, change_type, G_CALLBACK(callback), 0, ifname)
void _accept_signal(const char *file, int line, const char *func, SignalData *data);
void
_accept_signals(const char *file, int line, const char *func, SignalData *data, int min, int max);
void _wait_signal(const char *file, int line, const char *func, SignalData *data);
void _accept_or_wait_signal(const char *file, int line, const char *func, SignalData *data);
void _ensure_no_signal(const char *file, int line, const char *func, SignalData *data);
void _free_signal(const char *file, int line, const char *func, SignalData *data);
#define accept_signal(data) _accept_signal(__FILE__, __LINE__, G_STRFUNC, data)
#define accept_signals(data, min, max) \
    _accept_signals(__FILE__, __LINE__, G_STRFUNC, data, min, max)
#define wait_signal(data)           _wait_signal(__FILE__, __LINE__, G_STRFUNC, data)
#define accept_or_wait_signal(data) _accept_or_wait_signal(__FILE__, __LINE__, G_STRFUNC, data)
#define ensure_no_signal(data)      _ensure_no_signal(__FILE__, __LINE__, G_STRFUNC, data)
#define free_signal(data)           _free_signal(__FILE__, __LINE__, G_STRFUNC, data)

void link_callback(NMPlatform     *platform,
                   int             obj_type_i,
                   int             ifindex,
                   NMPlatformLink *received,
                   int             change_type_i,
                   SignalData     *data);

/*****************************************************************************/

int nmtstp_run_command(const char *format, ...) _nm_printf(1, 2);
#define nmtstp_run_command_check(...)                            \
    do {                                                         \
        g_assert_cmpint(nmtstp_run_command(__VA_ARGS__), ==, 0); \
    } while (0)

/*****************************************************************************/

gboolean
nmtstp_check_platform_full(NMPlatform *platform, guint32 obj_type_flags, gboolean do_assert);

void nmtstp_check_platform(NMPlatform *platform, guint32 obj_type_flags);

/*****************************************************************************/

guint                 nmtstp_wait_for_signal(NMPlatform *platform, gint64 timeout_msec);
guint                 nmtstp_wait_for_signal_until(NMPlatform *platform, gint64 until_ms);
const NMPlatformLink *nmtstp_wait_for_link(NMPlatform *platform,
                                           const char *ifname,
                                           NMLinkType  expected_link_type,
                                           gint64      timeout_msec);
const NMPlatformLink *nmtstp_wait_for_link_until(NMPlatform *platform,
                                                 const char *ifname,
                                                 NMLinkType  expected_link_type,
                                                 gint64      until_ms);

#define nmtstp_assert_wait_for_signal(platform, timeout_msec)    \
    G_STMT_START                                                 \
    {                                                            \
        if (nmtstp_wait_for_signal(platform, timeout_msec) == 0) \
            g_assert_not_reached();                              \
    }                                                            \
    G_STMT_END

#define nmtstp_assert_wait_for_signal_until(platform, until_ms)    \
    G_STMT_START                                                   \
    {                                                              \
        if (nmtstp_wait_for_signal_until(platform, until_ms) == 0) \
            g_assert_not_reached();                                \
    }                                                              \
    G_STMT_END

#define nmtstp_assert_wait_for_link(platform, ifname, expected_link_type, timeout_msec) \
    nmtst_assert_nonnull(nmtstp_wait_for_link(platform, ifname, expected_link_type, timeout_msec))

#define nmtstp_assert_wait_for_link_until(platform, ifname, expected_link_type, until_ms) \
    nmtst_assert_nonnull(nmtstp_wait_for_link_until(platform, ifname, expected_link_type, until_ms))

/*****************************************************************************/

int      nmtstp_run_command_check_external_global(void);
gboolean nmtstp_run_command_check_external(int external_command);

/*****************************************************************************/

const NMPlatformIP4Route *_nmtstp_assert_ip4_route_exists(const char *file,
                                                          guint       line,
                                                          const char *func,
                                                          NMPlatform *platform,
                                                          int         c_exists,
                                                          const char *ifname,
                                                          guint32     network,
                                                          int         plen,
                                                          guint32     metric,
                                                          guint8      tos);
#define nmtstp_assert_ip4_route_exists(platform, c_exists, ifname, network, plen, metric, tos) \
    _nmtstp_assert_ip4_route_exists(__FILE__,                                                  \
                                    __LINE__,                                                  \
                                    G_STRFUNC,                                                 \
                                    platform,                                                  \
                                    c_exists,                                                  \
                                    ifname,                                                    \
                                    network,                                                   \
                                    plen,                                                      \
                                    metric,                                                    \
                                    tos)

const NMPlatformIP4Route *nmtstp_ip4_route_get(NMPlatform *platform,
                                               int         ifindex,
                                               guint32     network,
                                               int         plen,
                                               guint32     metric,
                                               guint8      tos);

const NMPlatformIP6Route *_nmtstp_assert_ip6_route_exists(const char            *file,
                                                          guint                  line,
                                                          const char            *func,
                                                          NMPlatform            *platform,
                                                          int                    c_exists,
                                                          const char            *ifname,
                                                          const struct in6_addr *network,
                                                          guint                  plen,
                                                          guint32                metric,
                                                          const struct in6_addr *src,
                                                          guint8                 src_plen);
#define nmtstp_assert_ip6_route_exists(platform, \
                                       c_exists, \
                                       ifname,   \
                                       network,  \
                                       plen,     \
                                       metric,   \
                                       src,      \
                                       src_plen) \
    _nmtstp_assert_ip6_route_exists(__FILE__,    \
                                    __LINE__,    \
                                    G_STRFUNC,   \
                                    platform,    \
                                    c_exists,    \
                                    ifname,      \
                                    network,     \
                                    plen,        \
                                    metric,      \
                                    src,         \
                                    src_plen)

const NMPlatformIP6Route *nmtstp_ip6_route_get(NMPlatform            *platform,
                                               int                    ifindex,
                                               const struct in6_addr *network,
                                               guint                  plen,
                                               guint32                metric,
                                               const struct in6_addr *src,
                                               guint8                 src_plen);

/*****************************************************************************/

gboolean nmtstp_ip_address_check_lifetime(const NMPlatformIPAddress *addr,
                                          gint64                     now,
                                          guint32                    expected_lifetime,
                                          guint32                    expected_preferred);
void     nmtstp_ip_address_assert_lifetime(const NMPlatformIPAddress *addr,
                                           gint64                     now,
                                           guint32                    expected_lifetime,
                                           guint32                    expected_preferred);

void nmtstp_ip4_address_add(NMPlatform *platform,
                            int         external_command,
                            int         ifindex,
                            in_addr_t   address,
                            int         plen,
                            in_addr_t   peer_address,
                            guint32     lifetime,
                            guint32     preferred,
                            guint32     flags,
                            const char *label);
void nmtstp_ip6_address_add(NMPlatform     *platform,
                            int             external_command,
                            int             ifindex,
                            struct in6_addr address,
                            int             plen,
                            struct in6_addr peer_address,
                            guint32         lifetime,
                            guint32         preferred,
                            guint32         flags);
void nmtstp_ip4_address_del(NMPlatform *platform,
                            int         external_command,
                            int         ifindex,
                            in_addr_t   address,
                            int         plen,
                            in_addr_t   peer_address);
void nmtstp_ip6_address_del(NMPlatform     *platform,
                            int             external_command,
                            int             ifindex,
                            struct in6_addr address,
                            int             plen);

void nmtstp_ip4_route_add(NMPlatform      *platform,
                          int              ifindex,
                          NMIPConfigSource source,
                          in_addr_t        network,
                          guint8           plen,
                          in_addr_t        gateway,
                          in_addr_t        pref_src,
                          guint32          metric,
                          guint32          mss);

void nmtstp_ip6_route_add(NMPlatform      *platform,
                          int              ifindex,
                          NMIPConfigSource source,
                          struct in6_addr  network,
                          guint8           plen,
                          struct in6_addr  gateway,
                          struct in6_addr  pref_src,
                          guint32          metric,
                          guint32          mss);

static inline GPtrArray *
nmtstp_ip4_route_get_all(NMPlatform *platform, int ifindex)
{
    return nm_platform_lookup_object_clone(
        platform,
        NMP_OBJECT_TYPE_IP4_ROUTE,
        ifindex,
        nm_platform_lookup_predicate_routes_main_skip_rtprot_kernel,
        NULL);
}

static inline GPtrArray *
nmtstp_ip6_route_get_all(NMPlatform *platform, int ifindex)
{
    return nm_platform_lookup_object_clone(
        platform,
        NMP_OBJECT_TYPE_IP6_ROUTE,
        ifindex,
        nm_platform_lookup_predicate_routes_main_skip_rtprot_kernel,
        NULL);
}

/*****************************************************************************/

GArray *nmtstp_platform_ip4_address_get_all(NMPlatform *self, int ifindex);
GArray *nmtstp_platform_ip6_address_get_all(NMPlatform *self, int ifindex);

/*****************************************************************************/

const NMPlatformIPAddress *
nmtstp_platform_ip_address_find(NMPlatform *self, int ifindex, int addr_family, gconstpointer addr);

static inline const NMPlatformIP4Address *
nmtstp_platform_ip4_address_find(NMPlatform *self, int ifindex, in_addr_t addr)
{
    return (const NMPlatformIP4Address *)
        nmtstp_platform_ip_address_find(self, ifindex, AF_INET, &addr);
}

static inline const NMPlatformIP6Address *
nmtstp_platform_ip6_address_find(NMPlatform *self, int ifindex, const struct in6_addr *addr)
{
    return (const NMPlatformIP6Address *)
        nmtstp_platform_ip_address_find(self, ifindex, AF_INET6, addr);
}

void _nmtstp_platform_ip_addresses_assert(const char        *filename,
                                          int                lineno,
                                          NMPlatform        *self,
                                          int                ifindex,
                                          gboolean           force_exact_4,
                                          gboolean           force_exact_6,
                                          gboolean           ignore_ll6,
                                          guint              addrs_len,
                                          const char *const *addrs);

#define nmtstp_platform_ip_addresses_assert(self,                                              \
                                            ifindex,                                           \
                                            force_exact_4,                                     \
                                            force_exact_6,                                     \
                                            ignore_ll6,                                        \
                                            ...)                                               \
    _nmtstp_platform_ip_addresses_assert(__FILE__,                                             \
                                         __LINE__,                                             \
                                         (self),                                               \
                                         (ifindex),                                            \
                                         (force_exact_4),                                      \
                                         (force_exact_6),                                      \
                                         (ignore_ll6),                                         \
                                         NM_NARG(__VA_ARGS__),                                 \
                                         ((const char *const[]){"dummy", ##__VA_ARGS__, NULL}) \
                                             + 1)

/*****************************************************************************/

static inline gboolean
_nmtstp_platform_routing_rules_get_all_predicate(const NMPObject *obj, gpointer user_data)
{
    int addr_family = GPOINTER_TO_INT(user_data);

    g_assert(NMP_OBJECT_GET_TYPE(obj) == NMP_OBJECT_TYPE_ROUTING_RULE);

    return addr_family == AF_UNSPEC
           || NMP_OBJECT_CAST_ROUTING_RULE(obj)->addr_family == addr_family;
}

static inline GPtrArray *
nmtstp_platform_routing_rules_get_all(NMPlatform *platform, int addr_family)
{
    NMPLookup lookup;

    g_assert(NM_IS_PLATFORM(platform));
    g_assert(NM_IN_SET(addr_family, AF_UNSPEC, AF_INET, AF_INET6));

    nmp_lookup_init_obj_type(&lookup, NMP_OBJECT_TYPE_ROUTING_RULE);
    return nm_platform_lookup_clone(platform,
                                    &lookup,
                                    _nmtstp_platform_routing_rules_get_all_predicate,
                                    GINT_TO_POINTER(addr_family));
}

static inline guint
nmtstp_platform_routing_rules_get_count(NMPlatform *platform, int addr_family)
{
    const NMDedupMultiHeadEntry *head_entry;
    NMDedupMultiIter             iter;
    const NMPObject             *obj;
    NMPLookup                    lookup;
    guint                        n;

    g_assert(NM_IS_PLATFORM(platform));
    g_assert(NM_IN_SET(addr_family, AF_UNSPEC, AF_INET, AF_INET6));

    nmp_lookup_init_obj_type(&lookup, NMP_OBJECT_TYPE_ROUTING_RULE);
    head_entry = nm_platform_lookup(platform, &lookup);

    n = 0;
    nmp_cache_iter_for_each (&iter, head_entry, &obj) {
        if (_nmtstp_platform_routing_rules_get_all_predicate(obj, GINT_TO_POINTER(addr_family)))
            n++;
    }
    return n;
}

gboolean nmtstp_platform_ip4_route_delete(NMPlatform *platform,
                                          int         ifindex,
                                          in_addr_t   network,
                                          guint8      plen,
                                          guint32     metric);
gboolean nmtstp_platform_ip6_route_delete(NMPlatform     *platform,
                                          int             ifindex,
                                          struct in6_addr network,
                                          guint8          plen,
                                          guint32         metric);

const NMPlatformLink *
nmtstp_link_get_typed(NMPlatform *platform, int ifindex, const char *name, NMLinkType link_type);
const NMPlatformLink *nmtstp_link_get(NMPlatform *platform, int ifindex, const char *name);

gboolean nmtstp_kernel_support_get(NMPlatformKernelSupportType type);

void nmtstp_link_set_updown(NMPlatform *platform, int external_command, int ifindex, gboolean up);

const NMPlatformLnkBridge *
nmtstp_link_bridge_normalize_jiffies_time(const NMPlatformLnkBridge *requested,
                                          const NMPlatformLnkBridge *kernel,
                                          NMPlatformLnkBridge       *dst);

const NMPlatformLink *nmtstp_link_bridge_add(NMPlatform                *platform,
                                             int                        external_command,
                                             const char                *name,
                                             const NMPlatformLnkBridge *lnk);
const NMPlatformLink *nmtstp_link_veth_add(NMPlatform *platform,
                                           int         external_command,
                                           const char *name,
                                           const char *peer);
const NMPlatformLink *
nmtstp_link_dummy_add(NMPlatform *platform, int external_command, const char *name);
const NMPlatformLink *nmtstp_link_gre_add(NMPlatform             *platform,
                                          int                     external_command,
                                          const char             *name,
                                          const NMPlatformLnkGre *lnk);
const NMPlatformLink *nmtstp_link_ip6tnl_add(NMPlatform                *platform,
                                             int                        external_command,
                                             const char                *name,
                                             const NMPlatformLnkIp6Tnl *lnk);
const NMPlatformLink *nmtstp_link_ip6gre_add(NMPlatform                *platform,
                                             int                        external_command,
                                             const char                *name,
                                             const NMPlatformLnkIp6Tnl *lnk);
const NMPlatformLink *nmtstp_link_ipip_add(NMPlatform              *platform,
                                           int                      external_command,
                                           const char              *name,
                                           const NMPlatformLnkIpIp *lnk);
const NMPlatformLink *nmtstp_link_macvlan_add(NMPlatform                 *platform,
                                              int                         external_command,
                                              const char                 *name,
                                              int                         parent,
                                              const NMPlatformLnkMacvlan *lnk);
const NMPlatformLink *nmtstp_link_sit_add(NMPlatform             *platform,
                                          int                     external_command,
                                          const char             *name,
                                          const NMPlatformLnkSit *lnk);
const NMPlatformLink *nmtstp_link_tun_add(NMPlatform             *platform,
                                          int                     external_command,
                                          const char             *name,
                                          const NMPlatformLnkTun *lnk,
                                          int                    *out_fd);
const NMPlatformLink *nmtstp_link_vlan_add(NMPlatform              *platform,
                                           int                      external_command,
                                           const char              *name,
                                           int                      parent,
                                           const NMPlatformLnkVlan *lnk);
const NMPlatformLink *nmtstp_link_vti_add(NMPlatform             *platform,
                                          gboolean                external_command,
                                          const char             *name,
                                          const NMPlatformLnkVti *lnk);
const NMPlatformLink *nmtstp_link_vti6_add(NMPlatform              *platform,
                                           gboolean                 external_command,
                                           const char              *name,
                                           const NMPlatformLnkVti6 *lnk);
const NMPlatformLink *nmtstp_link_vrf_add(NMPlatform             *platform,
                                          int                     external_command,
                                          const char             *name,
                                          const NMPlatformLnkVrf *lnk,
                                          gboolean               *out_not_supported);
const NMPlatformLink *nmtstp_link_vxlan_add(NMPlatform               *platform,
                                            int                       external_command,
                                            const char               *name,
                                            const NMPlatformLnkVxlan *lnk);

void nmtstp_link_delete(NMPlatform *platform,
                        int         external_command,
                        int         ifindex,
                        const char *name,
                        gboolean    require_exist);

gboolean nmtstp_link_is_iptunnel_special(const NMPlatformLink *link);

gboolean nmtstp_ensure_module(const char *module_name);

/*****************************************************************************/

#define nmtst_object_new_mptcp_addr(...) \
    nmp_object_new(NMP_OBJECT_TYPE_MPTCP_ADDR, &((const NMPlatformMptcpAddr){__VA_ARGS__}))

/*****************************************************************************/

extern int               NMTSTP_ENV1_IFINDEXES[2];
extern const char *const NMTSTP_ENV1_DEVICE_NAME[G_N_ELEMENTS(NMTSTP_ENV1_IFINDEXES)];

#define DEVICE_NAME         "nm-test-device0"
#define NMTSTP_ENV1_IFINDEX (NMTSTP_ENV1_IFINDEXES[0])

extern int NMTSTP_ENV1_EX;

static inline void
_nmtstp_env1_wrapper_setup(const NmtstTestData *test_data)
{
    int     *p_ifindexes;
    gpointer p_n_ifaces;
    gpointer p_ifup;
    int      n_ifaces;
    int      i;

    _LOGT("TEST[%s]: setup", test_data->testpath);

    nmtst_test_data_unpack(test_data, &p_ifindexes, &p_n_ifaces, NULL, NULL, NULL, &p_ifup);

    n_ifaces = GPOINTER_TO_UINT(p_n_ifaces);
    g_assert_cmpint(n_ifaces, >=, 1);
    g_assert_cmpint(n_ifaces, <=, (int) G_N_ELEMENTS(NMTSTP_ENV1_IFINDEXES));

    for (i = 0; i < (int) G_N_ELEMENTS(NMTSTP_ENV1_IFINDEXES); i++) {
        g_assert_cmpint(NMTSTP_ENV1_IFINDEXES[i], ==, 0);
        g_assert_cmpint(p_ifindexes[i], ==, 0);
    }

    for (i = 0; i < n_ifaces; i++) {
        p_ifindexes[i] = nmtstp_link_dummy_add(NULL, -1, NMTSTP_ENV1_DEVICE_NAME[i])->ifindex;
        if (GPOINTER_TO_INT(p_ifup))
            nmtstp_link_set_updown(NULL, -1, p_ifindexes[i], TRUE);
    }

    nm_platform_process_events(NM_PLATFORM_GET);

    for (i = 0; i < n_ifaces; i++)
        NMTSTP_ENV1_IFINDEXES[i] = p_ifindexes[i];
    NMTSTP_ENV1_EX = nmtstp_run_command_check_external_global();
}

static inline void
_nmtstp_env1_wrapper_run(gconstpointer user_data)
{
    const NmtstTestData *test_data = user_data;
    GTestDataFunc        test_func_data;
    GTestFunc            test_func;
    gconstpointer        d;

    nmtst_test_data_unpack(test_data, NULL, NULL, &test_func, &test_func_data, &d, NULL);

    _LOGT("TEST[%s]: run", test_data->testpath);
    if (test_func)
        test_func();
    else
        test_func_data(d);
}

static inline void
_nmtstp_env1_wrapper_teardown(const NmtstTestData *test_data)
{
    int     *p_ifindexes;
    gpointer p_n_ifaces;
    int      n_ifaces;
    int      i;

    _LOGT("TEST[%s]: teardown", test_data->testpath);

    nmtst_test_data_unpack(test_data, &p_ifindexes, &p_n_ifaces, NULL, NULL, NULL, NULL);

    n_ifaces = GPOINTER_TO_UINT(p_n_ifaces);
    g_assert_cmpint(n_ifaces, >=, 1);
    g_assert_cmpint(n_ifaces, <=, (int) G_N_ELEMENTS(NMTSTP_ENV1_IFINDEXES));

    for (i = 0; i < (int) G_N_ELEMENTS(NMTSTP_ENV1_IFINDEXES); i++) {
        if (i < n_ifaces)
            g_assert_cmpint(p_ifindexes[i], >, 0);
        else
            g_assert_cmpint(p_ifindexes[i], ==, 0);
        g_assert_cmpint(NMTSTP_ENV1_IFINDEXES[i], ==, p_ifindexes[i]);
        NMTSTP_ENV1_IFINDEXES[i] = 0;
    }

    for (i = 0; i < n_ifaces; i++)
        nmtstp_link_delete(NULL, -1, p_ifindexes[i], NMTSTP_ENV1_DEVICE_NAME[i], TRUE);

    nm_platform_process_events(NM_PLATFORM_GET);

    _LOGT("TEST[%s]: finished", test_data->testpath);

    for (i = 0; i < (int) G_N_ELEMENTS(NMTSTP_ENV1_IFINDEXES); i++)
        p_ifindexes[i] = 0;
}

/* add test function, that set's up a particular environment, consisting
 * of a dummy device with ifindex NMTSTP_ENV1_IFINDEX. */
#define _nmtstp_env1_add_test_func_full(testpath, test_func, test_data_func, arg, n_ifaces, ifup)  \
    nmtst_add_test_func_full(testpath,                                                             \
                             _nmtstp_env1_wrapper_run,                                             \
                             _nmtstp_env1_wrapper_setup,                                           \
                             _nmtstp_env1_wrapper_teardown,                                        \
                             ({                                                                    \
                                 static int _ifindexes[G_N_ELEMENTS(NMTSTP_ENV1_IFINDEXES)] = {0}; \
                                 _ifindexes;                                                       \
                             }),                                                                   \
                             ({                                                                    \
                                 guint _n_ifaces = (n_ifaces);                                     \
                                 GUINT_TO_POINTER(_n_ifaces);                                      \
                             }),                                                                   \
                             ({                                                                    \
                                 GTestFunc _test_func = (test_func);                               \
                                 _test_func;                                                       \
                             }),                                                                   \
                             ({                                                                    \
                                 GTestDataFunc _test_func = (test_data_func);                      \
                                 _test_func;                                                       \
                             }),                                                                   \
                             (arg),                                                                \
                             ({                                                                    \
                                 gboolean _ifup = (ifup);                                          \
                                 GINT_TO_POINTER(!!_ifup);                                         \
                             }))

#define nmtstp_env1_add_test_func_data(testpath, test_func, arg, n_ifaces, ifup) \
    _nmtstp_env1_add_test_func_full(testpath, NULL, test_func, arg, n_ifaces, ifup)

#define nmtstp_env1_add_test_func(testpath, test_func, n_ifaces, ifup) \
    _nmtstp_env1_add_test_func_full(testpath, test_func, NULL, NULL, n_ifaces, ifup)

/*****************************************************************************/

typedef void (*NMTstpSetupFunc)(void);
extern NMTstpSetupFunc const _nmtstp_setup_platform_func;

void nmtstp_setup_platform(void);

/*****************************************************************************/

typedef struct _NMTstpAcdDefender NMTstpAcdDefender;

NMTstpAcdDefender *
nmtstp_acd_defender_new(int ifindex, in_addr_t ip_addr, const NMEtherAddr *mac_addr);

void nmtstp_acd_defender_destroy(NMTstpAcdDefender *defender);

/*****************************************************************************/

void _nmtstp_init_tests(int *argc, char ***argv);
void _nmtstp_setup_tests(void);
