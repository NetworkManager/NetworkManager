/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2012 - 2018 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-platform.h"

#include "libnm-std-aux/nm-linux-compat.h"

#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/fib_rules.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_tunnel.h>
#include <linux/rtnetlink.h>
#include <linux/tc_act/tc_mirred.h>
#include <libudev.h>

#include "libnm-base/nm-net-aux.h"
#include "libnm-glib-aux/nm-dedup-multi.h"
#include "libnm-glib-aux/nm-secret-utils.h"
#include "libnm-glib-aux/nm-time-utils.h"
#include "libnm-log-core/nm-logging.h"
#include "libnm-platform/nm-platform-utils.h"
#include "libnm-platform/nmp-netns.h"
#include "libnm-udev-aux/nm-udev-utils.h"
#include "nm-platform-private.h"
#include "nmp-object.h"

/*****************************************************************************/

G_STATIC_ASSERT(G_STRUCT_OFFSET(NMPlatformIPAddress, address_ptr)
                == G_STRUCT_OFFSET(NMPlatformIP4Address, address));
G_STATIC_ASSERT(G_STRUCT_OFFSET(NMPlatformIPAddress, address_ptr)
                == G_STRUCT_OFFSET(NMPlatformIP6Address, address));
G_STATIC_ASSERT(G_STRUCT_OFFSET(NMPlatformIPRoute, network_ptr)
                == G_STRUCT_OFFSET(NMPlatformIP4Route, network));
G_STATIC_ASSERT(G_STRUCT_OFFSET(NMPlatformIPRoute, network_ptr)
                == G_STRUCT_OFFSET(NMPlatformIP6Route, network));

G_STATIC_ASSERT(_nm_alignof(NMPlatformIPRoute) == _nm_alignof(NMPlatformIP4Route));
G_STATIC_ASSERT(_nm_alignof(NMPlatformIPRoute) == _nm_alignof(NMPlatformIP6Route));
G_STATIC_ASSERT(_nm_alignof(NMPlatformIPRoute) == _nm_alignof(NMPlatformIPXRoute));

G_STATIC_ASSERT(_nm_alignof(NMPlatformIPAddress) == _nm_alignof(NMPlatformIP4Address));
G_STATIC_ASSERT(_nm_alignof(NMPlatformIPAddress) == _nm_alignof(NMPlatformIP6Address));
G_STATIC_ASSERT(_nm_alignof(NMPlatformIPAddress) == _nm_alignof(NMPlatformIPXAddress));

/*****************************************************************************/

G_STATIC_ASSERT(sizeof(((NMPLinkAddress *) NULL)->data) == _NM_UTILS_HWADDR_LEN_MAX);
G_STATIC_ASSERT(sizeof(((NMPlatformLink *) NULL)->l_address.data) == _NM_UTILS_HWADDR_LEN_MAX);
G_STATIC_ASSERT(sizeof(((NMPlatformLink *) NULL)->l_perm_address.data) == _NM_UTILS_HWADDR_LEN_MAX);
G_STATIC_ASSERT(sizeof(((NMPlatformLink *) NULL)->l_broadcast.data) == _NM_UTILS_HWADDR_LEN_MAX);

static const char *
_nmp_link_address_to_string(const NMPLinkAddress *addr,
                            char                  buf[static(_NM_UTILS_HWADDR_LEN_MAX * 3)])
{
    nm_assert(addr);

    if (addr->len > 0) {
        if (!_nm_utils_hwaddr_ntoa(addr->data,
                                   addr->len,
                                   TRUE,
                                   buf,
                                   _NM_UTILS_HWADDR_LEN_MAX * 3)) {
            buf[0] = '\0';
            g_return_val_if_reached(buf);
        }
    } else
        buf[0] = '\0';

    return buf;
}

gconstpointer
nmp_link_address_get(const NMPLinkAddress *addr, size_t *length)
{
    if (!addr || addr->len <= 0) {
        NM_SET_OUT(length, 0);
        return NULL;
    }

    if (addr->len > _NM_UTILS_HWADDR_LEN_MAX) {
        NM_SET_OUT(length, 0);
        g_return_val_if_reached(NULL);
    }

    NM_SET_OUT(length, addr->len);
    return addr->data;
}

GBytes *
nmp_link_address_get_as_bytes(const NMPLinkAddress *addr)
{
    gconstpointer data;
    size_t        length;

    data = nmp_link_address_get(addr, &length);

    return length > 0 ? g_bytes_new(data, length) : NULL;
}

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_PLATFORM
#define _NMLOG_PREFIX_NAME "platform"

#define NMLOG_COMMON(level, name, ...)                                 \
    G_STMT_START                                                       \
    {                                                                  \
        char                    __prefix[64];                          \
        const char             *__p_prefix = _NMLOG_PREFIX_NAME;       \
        const NMPlatform *const __self     = (self);                   \
        const char             *__name     = name;                     \
                                                                       \
        if (__self && NM_PLATFORM_GET_PRIVATE(__self)->log_with_ptr) { \
            g_snprintf(__prefix,                                       \
                       sizeof(__prefix),                               \
                       "%s[" NM_HASH_OBFUSCATE_PTR_FMT "]",            \
                       _NMLOG_PREFIX_NAME,                             \
                       NM_HASH_OBFUSCATE_PTR(__self));                 \
            __p_prefix = __prefix;                                     \
        }                                                              \
        _nm_log((level),                                               \
                _NMLOG_DOMAIN,                                         \
                0,                                                     \
                __name,                                                \
                NULL,                                                  \
                "%s: %s%s%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__),       \
                __p_prefix,                                            \
                NM_PRINT_FMT_QUOTED(__name, "(", __name, ") ", "")     \
                    _NM_UTILS_MACRO_REST(__VA_ARGS__));                \
    }                                                                  \
    G_STMT_END

#define _NMLOG(level, ...)                                \
    G_STMT_START                                          \
    {                                                     \
        const NMLogLevel __level = (level);               \
                                                          \
        if (nm_logging_enabled(__level, _NMLOG_DOMAIN)) { \
            NMLOG_COMMON(level, NULL, __VA_ARGS__);       \
        }                                                 \
    }                                                     \
    G_STMT_END

#define _NMLOG2(level, ...)                               \
    G_STMT_START                                          \
    {                                                     \
        const NMLogLevel __level = (level);               \
                                                          \
        if (nm_logging_enabled(__level, _NMLOG_DOMAIN)) { \
            NMLOG_COMMON(level, name, __VA_ARGS__);       \
        }                                                 \
    }                                                     \
    G_STMT_END

#define _NMLOG3(level, ...)                                                             \
    G_STMT_START                                                                        \
    {                                                                                   \
        const NMLogLevel __level = (level);                                             \
                                                                                        \
        if (nm_logging_enabled(__level, _NMLOG_DOMAIN)) {                               \
            NMLOG_COMMON(level,                                                         \
                         ifindex > 0 ? nm_platform_link_get_name(self, ifindex) : NULL, \
                         __VA_ARGS__);                                                  \
        }                                                                               \
    }                                                                                   \
    G_STMT_END

/*****************************************************************************/

static guint signals[_NM_PLATFORM_SIGNAL_ID_LAST] = {0};

enum {
    PROP_0,
    PROP_MULTI_IDX,
    PROP_NETNS_SUPPORT,
    PROP_USE_UDEV,
    PROP_LOG_WITH_PTR,
    PROP_CACHE_TC,
    LAST_PROP,
};

typedef struct _NMPlatformPrivate {
    bool use_udev : 1;
    bool log_with_ptr : 1;
    bool cache_tc : 1;

    guint              ip4_dev_route_blacklist_check_id;
    guint              ip4_dev_route_blacklist_gc_timeout_id;
    GHashTable        *ip4_dev_route_blacklist_hash;
    CList              ip6_dadfailed_lst_head;
    NMDedupMultiIndex *multi_idx;
    NMPCache          *cache;
} NMPlatformPrivate;

G_DEFINE_TYPE(NMPlatform, nm_platform, G_TYPE_OBJECT)

#define NM_PLATFORM_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMPlatform, NM_IS_PLATFORM)

/*****************************************************************************/

static void _ip4_dev_route_blacklist_schedule(NMPlatform *self);

/*****************************************************************************/

gboolean
nm_platform_get_use_udev(NMPlatform *self)
{
    return NM_PLATFORM_GET_PRIVATE(self)->use_udev;
}

gboolean
nm_platform_get_log_with_ptr(NMPlatform *self)
{
    return NM_PLATFORM_GET_PRIVATE(self)->log_with_ptr;
}

gboolean
nm_platform_get_cache_tc(NMPlatform *self)
{
    return NM_PLATFORM_GET_PRIVATE(self)->cache_tc;
}

/*****************************************************************************/

guint
_nm_platform_signal_id_get(NMPlatformSignalIdType signal_type)
{
    nm_assert(signal_type > 0 && signal_type != NM_PLATFORM_SIGNAL_ID_NONE
              && signal_type < _NM_PLATFORM_SIGNAL_ID_LAST);

    return signals[signal_type];
}

/*****************************************************************************/

/* Just always initialize a @klass instance. NM_PLATFORM_GET_CLASS()
 * is only a plain read on the self instance, which the compiler
 * like can optimize out.
 */
#define _CHECK_SELF_VOID(self, klass)           \
    NMPlatformClass *klass;                     \
    do {                                        \
        g_return_if_fail(NM_IS_PLATFORM(self)); \
        klass = NM_PLATFORM_GET_CLASS(self);    \
        (void) klass;                           \
    } while (0)

#define _CHECK_SELF(self, klass, err_val)                    \
    NMPlatformClass *klass;                                  \
    do {                                                     \
        g_return_val_if_fail(NM_IS_PLATFORM(self), err_val); \
        klass = NM_PLATFORM_GET_CLASS(self);                 \
        (void) klass;                                        \
    } while (0)

#define _CHECK_SELF_NETNS(self, klass, netns, err_val)       \
    nm_auto_pop_netns NMPNetns *netns = NULL;                \
    NMPlatformClass            *klass;                       \
    do {                                                     \
        g_return_val_if_fail(NM_IS_PLATFORM(self), err_val); \
        klass = NM_PLATFORM_GET_CLASS(self);                 \
        (void) klass;                                        \
        if (!nm_platform_netns_push(self, &netns))           \
            return (err_val);                                \
    } while (0)

/*****************************************************************************/

NMDedupMultiIndex *
nm_platform_get_multi_idx(NMPlatform *self)
{
    g_return_val_if_fail(NM_IS_PLATFORM(self), NULL);

    return NM_PLATFORM_GET_PRIVATE(self)->multi_idx;
}

/*****************************************************************************/

static NM_UTILS_LOOKUP_STR_DEFINE(
    _nmp_nlm_flag_to_string_lookup,
    NMPNlmFlags,
    NM_UTILS_LOOKUP_DEFAULT(NULL),
    NM_UTILS_LOOKUP_ITEM(NMP_NLM_FLAG_ADD, "add"),
    NM_UTILS_LOOKUP_ITEM(NMP_NLM_FLAG_CHANGE, "change"),
    NM_UTILS_LOOKUP_ITEM(NMP_NLM_FLAG_REPLACE, "replace"),
    NM_UTILS_LOOKUP_ITEM(NMP_NLM_FLAG_PREPEND, "prepend"),
    NM_UTILS_LOOKUP_ITEM(NMP_NLM_FLAG_APPEND, "append"),
    NM_UTILS_LOOKUP_ITEM(NMP_NLM_FLAG_TEST, "test"),
    NM_UTILS_LOOKUP_ITEM_IGNORE(NMP_NLM_FLAG_F_APPEND),
    NM_UTILS_LOOKUP_ITEM_IGNORE(NMP_NLM_FLAG_FMASK),
    NM_UTILS_LOOKUP_ITEM_IGNORE(NMP_NLM_FLAG_SUPPRESS_NETLINK_FAILURE),
    NM_UTILS_LOOKUP_ITEM_IGNORE(NMP_NLM_FLAG_F_ECHO), );

#define _nmp_nlm_flag_to_string(flags)                               \
    ({                                                               \
        NMPNlmFlags _flags = (flags);                                \
                                                                     \
        _nmp_nlm_flag_to_string_lookup(flags)                        \
            ?: nm_sprintf_bufa(100, "new[0x%x]", (unsigned) _flags); \
    })

/*****************************************************************************/

volatile int _nm_platform_kernel_support_state[_NM_PLATFORM_KERNEL_SUPPORT_NUM] = {};

static const struct {
    bool        compile_time_default;
    const char *name;
    const char *desc;
} _nm_platform_kernel_support_info[_NM_PLATFORM_KERNEL_SUPPORT_NUM] = {
    [NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_L3MDEV] =
        {
            .compile_time_default = (FRA_MAX >= 19 /* FRA_L3MDEV */),
            .name                 = "FRA_L3MDEV",
            .desc                 = "FRA_L3MDEV attribute for policy routing rules",
        },
    [NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_UID_RANGE] =
        {
            .compile_time_default = (FRA_MAX >= 20 /* FRA_UID_RANGE */),
            .name                 = "FRA_UID_RANGE",
            .desc                 = "FRA_UID_RANGE attribute for policy routing rules",
        },
    [NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_PROTOCOL] =
        {
            .compile_time_default = (FRA_MAX >= 21 /* FRA_PROTOCOL */),
            .name                 = "FRA_PROTOCOL",
            .desc                 = "FRA_PROTOCOL attribute for policy routing rules",
        },
    [NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_IP_PROTO] =
        {
            .compile_time_default = (FRA_MAX >= 22 /* FRA_IP_PROTO */),
            .name                 = "FRA_IP_PROTO",
            .desc = "FRA_IP_PROTO, FRA_SPORT_RANGE, FRA_DPORT_RANGE attributes for policy routing "
                    "rules",
        },
    [NM_PLATFORM_KERNEL_SUPPORT_TYPE_IFLA_BR_VLAN_STATS_ENABLED] =
        {
            .compile_time_default = (IFLA_BR_MAX >= 41 /* IFLA_BR_VLAN_STATS_ENABLED */),
            .name                 = "IFLA_BR_VLAN_STATS_ENABLE",
            .desc                 = "IFLA_BR_VLAN_STATS_ENABLE bridge link attribute",
        },
    [NM_PLATFORM_KERNEL_SUPPORT_TYPE_IFLA_PERM_ADDRESS] =
        {
            .compile_time_default = (IFLA_MAX >= 54 /* IFLA_PERM_ADDRESS */),
            .name                 = "IFLA_PERM_ADDRESS",
            .desc                 = "IFLA_PERM_ADDRESS netlink attribute",
        },
};

int
_nm_platform_kernel_support_init(NMPlatformKernelSupportType type, int value)
{
    volatile int *p_state;
    gboolean      set_default = FALSE;

    nm_assert(_NM_INT_NOT_NEGATIVE(type) && type < G_N_ELEMENTS(_nm_platform_kernel_support_state));

    p_state = &_nm_platform_kernel_support_state[type];

    if (value == 0) {
        set_default = TRUE;
        value       = _nm_platform_kernel_support_info[type].compile_time_default ? 1 : -1;
    }

    nm_assert(NM_IN_SET(value, -1, 1));

    if (!g_atomic_int_compare_and_exchange(p_state, 0, value)) {
        value = g_atomic_int_get(p_state);
        nm_assert(NM_IN_SET(value, -1, 1));
        return value;
    }

#undef NM_THREAD_SAFE_ON_MAIN_THREAD
#define NM_THREAD_SAFE_ON_MAIN_THREAD 0

    if (set_default) {
        nm_log_dbg(LOGD_PLATFORM,
                   "platform: kernel-support for %s (%s) not detected: assume %ssupported",
                   _nm_platform_kernel_support_info[type].name,
                   _nm_platform_kernel_support_info[type].desc,
                   value >= 0 ? "" : "not ");
    } else {
        nm_log_dbg(LOGD_PLATFORM,
                   "platform: kernel-support for %s (%s) detected: %ssupported",
                   _nm_platform_kernel_support_info[type].name,
                   _nm_platform_kernel_support_info[type].desc,
                   value >= 0 ? "" : "not ");
    }

#undef NM_THREAD_SAFE_ON_MAIN_THREAD
#define NM_THREAD_SAFE_ON_MAIN_THREAD 1

    return value;
}

/*****************************************************************************/

const NMPGenlFamilyInfo nmp_genl_family_infos[_NMP_GENL_FAMILY_TYPE_NUM] = {
    [NMP_GENL_FAMILY_TYPE_ETHTOOL] =
        {
            .name = "ethtool",
        },
    [NMP_GENL_FAMILY_TYPE_MPTCP_PM] =
        {
            .name = MPTCP_PM_NAME,
        },
    [NMP_GENL_FAMILY_TYPE_NL80211] =
        {
            .name = "nl80211",
        },
    [NMP_GENL_FAMILY_TYPE_NL802154] =
        {
            .name = "nl802154",
        },
    [NMP_GENL_FAMILY_TYPE_WIREGUARD] =
        {
            .name = "wireguard",
        },
};

NMPGenlFamilyType
nmp_genl_family_type_from_name(const char *name)
{
    int imin, imax, imid;

    if (NM_MORE_ASSERT_ONCE(50)) {
        int i;

        for (i = 0; i < (int) G_N_ELEMENTS(nmp_genl_family_infos); i++) {
            nm_assert(nmp_genl_family_infos[i].name);
            if (i > 0)
                nm_assert(strcmp(nmp_genl_family_infos[i - 1].name, nmp_genl_family_infos[i].name)
                          < 0);
        }
    }

    if (!name)
        goto out;

    imin = 0;
    imax = G_N_ELEMENTS(nmp_genl_family_infos) - 1;
    imid = imax / 2;

    while (TRUE) {
        int c;

        c = strcmp(nmp_genl_family_infos[imid].name, name);
        if (c == 0)
            return (NMPGenlFamilyType) imid;

        if (c < 0)
            imin = imid + 1;
        else
            imax = imid - 1;

        if (imin > imax)
            break;

        imid = (imax + imin) / 2;
    }

out:
    return _NMP_GENL_FAMILY_TYPE_NONE;
}

/*****************************************************************************/

/**
 * nm_platform_process_events:
 * @self: platform instance
 *
 * Process pending events or handle pending delayed-actions.
 * Effectively, this reads the netlink socket and processes
 * new netlink messages. Possibly it will raise change signals.
 */
void
nm_platform_process_events(NMPlatform *self)
{
    _CHECK_SELF_VOID(self, klass);

    if (klass->process_events)
        klass->process_events(self);
}

const NMPlatformLink *
nm_platform_process_events_ensure_link(NMPlatform *self, int ifindex, const char *ifname)
{
    const NMPObject *obj;
    gboolean         refreshed = FALSE;

    g_return_val_if_fail(NM_IS_PLATFORM(self), NULL);

    if (ifindex <= 0 && !ifname)
        return NULL;

    /* we look into the cache, whether a link for given ifindex/ifname
     * exits. If not, we poll the netlink socket, maybe the event
     * with the link is waiting.
     *
     * Then we try again to find the object.
     *
     * If the link is already cached the first time, we avoid polling
     * the netlink socket. */
again:
    obj = nmp_cache_lookup_link_full(
        nm_platform_get_cache(self),
        ifindex,
        ifname,
        FALSE, /* also invisible. We don't care here whether udev is ready */
        NM_LINK_TYPE_NONE,
        NULL,
        NULL);
    if (obj)
        return NMP_OBJECT_CAST_LINK(obj);
    if (!refreshed) {
        refreshed = TRUE;
        nm_platform_process_events(self);
        goto again;
    }

    return NULL;
}

/*****************************************************************************/

/**
 * nm_platform_sysctl_open_netdir:
 * @self: platform instance
 * @ifindex: the ifindex for which to open /sys/class/net/%s
 * @out_ifname: optional output argument of the found ifname.
 *
 * Wraps nmp_utils_sysctl_open_netdir() by first changing into the right
 * network-namespace.
 *
 * Returns: on success, the open file descriptor to the /sys/class/net/%s
 *   directory.
 */
int
nm_platform_sysctl_open_netdir(NMPlatform *self, int ifindex, char *out_ifname)
{
    const char *ifname_guess;
    _CHECK_SELF_NETNS(self, klass, netns, -1);

    g_return_val_if_fail(ifindex > 0, -1);

    /* we don't have an @ifname_guess argument to make the API nicer.
     * But still do a cache-lookup first. Chances are good that we have
     * the right ifname cached and save if_indextoname() */
    ifname_guess = nm_platform_link_get_name(self, ifindex);

    return nmp_utils_sysctl_open_netdir(ifindex, ifname_guess, out_ifname);
}

/**
 * nm_platform_sysctl_set:
 * @self: platform instance
 * @pathid: if @dirfd is present, this must be the full path that is looked up.
 *   It is required for logging.
 * @dirfd: optional file descriptor for parent directory for openat()
 * @path: Absolute option path
 * @value: Value to write
 *
 * This function is intended to be used for writing values to sysctl-style
 * virtual runtime configuration files. This includes not only /proc/sys
 * but also for example /sys/class.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_sysctl_set(NMPlatform *self,
                       const char *pathid,
                       int         dirfd,
                       const char *path,
                       const char *value)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(path, FALSE);
    g_return_val_if_fail(value, FALSE);

    return klass->sysctl_set(self, pathid, dirfd, path, value);
}

/**
 * nm_platform_sysctl_set_async:
 * @self: platform instance
 * @pathid: if @dirfd is present, this must be the full path that is looked up
 * @dirfd: optional file descriptor for parent directory for openat()
 * @path: absolute option path
 * @values: NULL-terminated array of strings to be written
 * @callback: function called on termination
 * @data: data passed to callback function
 * @cancellable: to cancel the operation
 *
 * This function is intended to be used for writing values to sysctl-style
 * virtual runtime configuration files. This includes not only /proc/sys
 * but also for example /sys/class. The function does not block and returns
 * immediately. The callback is always invoked, and asynchronously. The file
 * is closed after writing each value and reopened to write the next one so
 * that the function can be used safely on all /proc and /sys files,
 * independently of how /proc/sys/kernel/sysctl_writes_strict is configured.
 */
void
nm_platform_sysctl_set_async(NMPlatform             *self,
                             const char             *pathid,
                             int                     dirfd,
                             const char             *path,
                             const char *const      *values,
                             NMPlatformAsyncCallback callback,
                             gpointer                data,
                             GCancellable           *cancellable)
{
    _CHECK_SELF_VOID(self, klass);

    klass->sysctl_set_async(self, pathid, dirfd, path, values, callback, data, cancellable);
}

gboolean
nm_platform_sysctl_ip_conf_set_ipv6_hop_limit_safe(NMPlatform *self, const char *iface, int value)
{
    const char *path;
    gint64      cur;
    char        buf[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];

    _CHECK_SELF(self, klass, FALSE);

    /* the hop-limit provided via RA is uint8. */
    if (value > 0xFF)
        return FALSE;

    /* don't allow unreasonable small values */
    if (value < 10)
        return FALSE;

    path = nm_utils_sysctl_ip_conf_path(AF_INET6, buf, iface, "hop_limit");
    cur  = nm_platform_sysctl_get_int_checked(self,
                                             NMP_SYSCTL_PATHID_ABSOLUTE(path),
                                             10,
                                             1,
                                             G_MAXINT32,
                                             -1);

    /* only allow increasing the hop-limit to avoid DOS by an attacker
     * setting a low hop-limit (CVE-2015-2924, rh#1209902) */

    if (value < cur)
        return FALSE;
    if (value != cur) {
        char svalue[20];

        sprintf(svalue, "%d", value);
        nm_platform_sysctl_set(self, NMP_SYSCTL_PATHID_ABSOLUTE(path), svalue);
    }

    return TRUE;
}

gboolean
nm_platform_sysctl_ip_neigh_set_ipv6_reachable_time(NMPlatform *self,
                                                    const char *iface,
                                                    guint       value_ms)
{
    char  path[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];
    char  str[128];
    guint clamped;

    _CHECK_SELF(self, klass, FALSE);

    if (!value_ms)
        return TRUE;

    /* RFC 4861 says the value can't be greater than one hour.
     * Also use a reasonable lower threshold. */
    clamped = NM_CLAMP(value_ms, 100, 3600000);
    nm_sprintf_buf(path, "/proc/sys/net/ipv6/neigh/%s/base_reachable_time_ms", iface);
    nm_sprintf_buf(str, "%u", clamped);
    if (!nm_platform_sysctl_set(self, NMP_SYSCTL_PATHID_ABSOLUTE(path), str))
        return FALSE;

    /* Set stale time in the same way as kernel */
    nm_sprintf_buf(path, "/proc/sys/net/ipv6/neigh/%s/gc_stale_time", iface);
    nm_sprintf_buf(str, "%u", clamped * 3 / 1000);

    return nm_platform_sysctl_set(self, NMP_SYSCTL_PATHID_ABSOLUTE(path), str);
}

gboolean
nm_platform_sysctl_ip_neigh_set_ipv6_retrans_time(NMPlatform *self,
                                                  const char *iface,
                                                  guint       value_ms)
{
    char path[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];
    char str[128];

    _CHECK_SELF(self, klass, FALSE);

    if (!value_ms)
        return TRUE;

    nm_sprintf_buf(path, "/proc/sys/net/ipv6/neigh/%s/retrans_time_ms", iface);
    nm_sprintf_buf(str, "%u", NM_CLAMP(value_ms, 10, 3600000));

    return nm_platform_sysctl_set(self, NMP_SYSCTL_PATHID_ABSOLUTE(path), str);
}

/**
 * nm_platform_sysctl_get:
 * @self: platform instance
 * @dirfd: if non-negative, used to lookup the path via openat().
 * @pathid: if @dirfd is present, this must be the full path that is looked up.
 *   It is required for logging.
 * @path: Absolute path to sysctl
 *
 * Returns: (transfer full): Contents of the virtual sysctl file.
 *
 * If the path does not exist, %NULL is returned and %errno set to %ENOENT.
 */
char *
nm_platform_sysctl_get(NMPlatform *self, const char *pathid, int dirfd, const char *path)
{
    _CHECK_SELF(self, klass, NULL);

    g_return_val_if_fail(path, NULL);

    return klass->sysctl_get(self, pathid, dirfd, path);
}

/**
 * nm_platform_sysctl_get_int32:
 * @self: platform instance
 * @pathid: if @dirfd is present, this must be the full path that is looked up.
 *   It is required for logging.
 * @dirfd: if non-negative, used to lookup the path via openat().
 * @path: Absolute path to sysctl
 * @fallback: default value, if the content of path could not be read
 * as decimal integer.
 *
 * Returns: contents of the sysctl file parsed as s32 integer, or
 * @fallback on error. On error, %errno will be set to a non-zero
 * value, on success %errno will be set to zero.
 */
gint32
nm_platform_sysctl_get_int32(NMPlatform *self,
                             const char *pathid,
                             int         dirfd,
                             const char *path,
                             gint32      fallback)
{
    return nm_platform_sysctl_get_int_checked(self,
                                              pathid,
                                              dirfd,
                                              path,
                                              10,
                                              G_MININT32,
                                              G_MAXINT32,
                                              fallback);
}

/**
 * nm_platform_sysctl_get_int_checked:
 * @self: platform instance
 * @pathid: if @dirfd is present, this must be the full path that is looked up.
 *   It is required for logging.
 * @dirfd: if non-negative, used to lookup the path via openat().
 * @path: Absolute path to sysctl
 * @base: base of numeric conversion
 * @min: minimal value that is still valid
 * @max: maximal value that is still valid
 * @fallback: default value, if the content of path could not be read
 * as valid integer.
 *
 * Returns: contents of the sysctl file parsed as s64 integer, or
 * @fallback on error. On error, %errno will be set to a non-zero
 * value. On success, %errno will be set to zero. The returned value
 * will always be in the range between @min and @max
 * (inclusive) or @fallback.
 * If the file does not exist, the fallback is returned and %errno
 * is set to ENOENT.
 */
gint64
nm_platform_sysctl_get_int_checked(NMPlatform *self,
                                   const char *pathid,
                                   int         dirfd,
                                   const char *path,
                                   guint       base,
                                   gint64      min,
                                   gint64      max,
                                   gint64      fallback)
{
    char  *value = NULL;
    gint32 ret;
    int    errsv;

    _CHECK_SELF(self, klass, fallback);

    g_return_val_if_fail(path, fallback);

    if (!path) {
        errno = EINVAL;
        return fallback;
    }

    value = nm_platform_sysctl_get(self, pathid, dirfd, path);
    if (!value) {
        /* nm_platform_sysctl_get() set errno to ENOENT if the file does not exist.
         * Propagate/preserve that. */
        if (errno != ENOENT)
            errno = EINVAL;
        return fallback;
    }

    ret   = _nm_utils_ascii_str_to_int64(value, base, min, max, fallback);
    errsv = errno;
    g_free(value);
    errno = errsv;
    return ret;
}

/*****************************************************************************/

char *
nm_platform_sysctl_ip_conf_get(NMPlatform *self,
                               int         addr_family,
                               const char *ifname,
                               const char *property)
{
    char buf[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];

    return nm_platform_sysctl_get(
        self,
        NMP_SYSCTL_PATHID_ABSOLUTE(
            nm_utils_sysctl_ip_conf_path(addr_family, buf, ifname, property)));
}

gint64
nm_platform_sysctl_ip_conf_get_int_checked(NMPlatform *self,
                                           int         addr_family,
                                           const char *ifname,
                                           const char *property,
                                           guint       base,
                                           gint64      min,
                                           gint64      max,
                                           gint64      fallback)
{
    char buf[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];

    return nm_platform_sysctl_get_int_checked(
        self,
        NMP_SYSCTL_PATHID_ABSOLUTE(
            nm_utils_sysctl_ip_conf_path(addr_family, buf, ifname, property)),
        base,
        min,
        max,
        fallback);
}

gboolean
nm_platform_sysctl_ip_conf_set(NMPlatform *self,
                               int         addr_family,
                               const char *ifname,
                               const char *property,
                               const char *value)
{
    char buf[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];

    return nm_platform_sysctl_set(
        self,
        NMP_SYSCTL_PATHID_ABSOLUTE(
            nm_utils_sysctl_ip_conf_path(addr_family, buf, ifname, property)),
        value);
}

gboolean
nm_platform_sysctl_ip_conf_set_int64(NMPlatform *self,
                                     int         addr_family,
                                     const char *ifname,
                                     const char *property,
                                     gint64      value)
{
    char buf[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];
    char s[64];

    return nm_platform_sysctl_set(
        self,
        NMP_SYSCTL_PATHID_ABSOLUTE(
            nm_utils_sysctl_ip_conf_path(addr_family, buf, ifname, property)),
        nm_sprintf_buf(s, "%" G_GINT64_FORMAT, value));
}

int
nm_platform_sysctl_ip_conf_get_rp_filter_ipv4(NMPlatform *self,
                                              const char *ifname,
                                              gboolean    consider_all,
                                              gboolean   *out_due_to_all)
{
    int val, val_all;

    NM_SET_OUT(out_due_to_all, FALSE);

    if (!ifname)
        return -1;

    val = nm_platform_sysctl_ip_conf_get_int_checked(self,
                                                     AF_INET,
                                                     ifname,
                                                     "rp_filter",
                                                     10,
                                                     0,
                                                     2,
                                                     -1);
    if (val == -1)
        return -1;

    /* the effectively used value is the rp_filter sysctl value of MAX(all,ifname).
     * Note that this is the numerical MAX(), despite rp_filter "1" being more strict
     * than "2". */
    if (val < 2 && consider_all && !nm_streq(ifname, "all")) {
        val_all = nm_platform_sysctl_ip_conf_get_int_checked(self,
                                                             AF_INET,
                                                             "all",
                                                             "rp_filter",
                                                             10,
                                                             0,
                                                             2,
                                                             val);
        if (val_all > val) {
            val = val_all;
            NM_SET_OUT(out_due_to_all, TRUE);
        }
    }

    return val;
}

/*****************************************************************************/

static int
_link_get_all_presort(gconstpointer p_a, gconstpointer p_b, gpointer sort_by_name)
{
    const NMPlatformLink *a = NMP_OBJECT_CAST_LINK(*((const NMPObject **) p_a));
    const NMPlatformLink *b = NMP_OBJECT_CAST_LINK(*((const NMPObject **) p_b));

    /* Loopback always first */
    if (a->ifindex == NM_LOOPBACK_IFINDEX)
        return -1;
    if (b->ifindex == NM_LOOPBACK_IFINDEX)
        return 1;

    if (GPOINTER_TO_INT(sort_by_name)) {
        /* Initialized links first */
        if (a->initialized > b->initialized)
            return -1;
        if (a->initialized < b->initialized)
            return 1;

        return strcmp(a->name, b->name);
    } else
        return a->ifindex - b->ifindex;
}

/**
 * nm_platform_link_get_all:
 * @self: platform instance
 * @sort_by_name: whether to sort by name or ifindex.
 *
 * Retrieve a snapshot of configuration for all links at once. The result is
 * owned by the caller and should be freed with g_ptr_array_unref().
 */
GPtrArray *
nm_platform_link_get_all(NMPlatform *self, gboolean sort_by_name)
{
    gs_unref_ptrarray GPtrArray   *links = NULL;
    GPtrArray                     *result;
    guint                          i, nresult;
    gs_unref_hashtable GHashTable *unseen = NULL;
    const NMPlatformLink          *item;
    NMPLookup                      lookup;

    _CHECK_SELF(self, klass, NULL);

    nmp_lookup_init_obj_type(&lookup, NMP_OBJECT_TYPE_LINK);
    links = nm_dedup_multi_objs_to_ptr_array_head(nm_platform_lookup(self, &lookup), NULL, NULL);
    if (!links)
        return NULL;

    for (i = 0; i < links->len;) {
        if (!nmp_object_is_visible(links->pdata[i]))
            g_ptr_array_remove_index_fast(links, i);
        else
            i++;
    }

    if (links->len == 0)
        return NULL;

    /* first sort the links by their ifindex or name. Below we will sort
     * further by moving children/slaves to the end. */
    g_ptr_array_sort_with_data(links, _link_get_all_presort, GINT_TO_POINTER(sort_by_name));

    unseen = g_hash_table_new(nm_direct_hash, NULL);
    for (i = 0; i < links->len; i++) {
        item = NMP_OBJECT_CAST_LINK(links->pdata[i]);
        nm_assert(item->ifindex > 0);
        if (!g_hash_table_insert(unseen, GINT_TO_POINTER(item->ifindex), NULL))
            nm_assert_not_reached();
    }

#if NM_MORE_ASSERTS
    /* Ensure that link_get_all returns a consistent and valid result. */
    for (i = 0; i < links->len; i++) {
        item = NMP_OBJECT_CAST_LINK(links->pdata[i]);

        if (!item->ifindex)
            continue;
        if (item->master != 0) {
            g_warn_if_fail(item->master > 0);
            g_warn_if_fail(item->master != item->ifindex);
            g_warn_if_fail(g_hash_table_contains(unseen, GINT_TO_POINTER(item->master)));
        }
        if (item->parent != 0) {
            if (item->parent != NM_PLATFORM_LINK_OTHER_NETNS) {
                g_warn_if_fail(item->parent > 0);
                g_warn_if_fail(item->parent != item->ifindex);
                g_warn_if_fail(g_hash_table_contains(unseen, GINT_TO_POINTER(item->parent)));
            }
        }
    }
#endif

    /* Re-order the links list such that children/slaves come after all ancestors */
    nm_assert(g_hash_table_size(unseen) == links->len);
    nresult = links->len;
    result  = g_ptr_array_new_full(nresult, (GDestroyNotify) nmp_object_unref);

    while (TRUE) {
        gboolean found_something = FALSE;
        guint    first_idx       = G_MAXUINT;

        for (i = 0; i < links->len; i++) {
            item = NMP_OBJECT_CAST_LINK(links->pdata[i]);

            if (!item)
                continue;

            g_assert(g_hash_table_contains(unseen, GINT_TO_POINTER(item->ifindex)));

            if (item->master > 0 && g_hash_table_contains(unseen, GINT_TO_POINTER(item->master)))
                goto skip;
            if (item->parent > 0 && g_hash_table_contains(unseen, GINT_TO_POINTER(item->parent)))
                goto skip;

            g_hash_table_remove(unseen, GINT_TO_POINTER(item->ifindex));
            g_ptr_array_add(result, links->pdata[i]);
            links->pdata[i] = NULL;
            found_something = TRUE;
            continue;
skip:
            if (first_idx == G_MAXUINT)
                first_idx = i;
        }

        if (found_something) {
            if (first_idx == G_MAXUINT)
                break;
        } else {
            nm_assert(first_idx != G_MAXUINT);
            /* There is a loop, pop the first (remaining) element from the list.
             * This can happen for veth pairs where each peer is parent of the other end. */
            item = NMP_OBJECT_CAST_LINK(links->pdata[first_idx]);
            nm_assert(item);
            g_hash_table_remove(unseen, GINT_TO_POINTER(item->ifindex));
            g_ptr_array_add(result, links->pdata[first_idx]);
            links->pdata[first_idx] = NULL;
        }
        nm_assert(result->len < nresult);
    }
    nm_assert(result->len == nresult);

    return result;
}

/*****************************************************************************/

const NMPObject *
nm_platform_link_get_obj(NMPlatform *self, int ifindex, gboolean visible_only)
{
    const NMPObject *obj_cache;

    _CHECK_SELF(self, klass, NULL);

    obj_cache = nmp_cache_lookup_link(nm_platform_get_cache(self), ifindex);
    if (!obj_cache || (visible_only && !nmp_object_is_visible(obj_cache)))
        return NULL;
    return obj_cache;
}

/*****************************************************************************/

/**
 * nm_platform_link_get:
 * @self: platform instance
 * @ifindex: ifindex of the link
 *
 * Lookup the internal NMPlatformLink object.
 *
 * Returns: %NULL, if such a link exists or the internal
 * platform link object. Do not modify the returned value.
 * Also, be aware that any subsequent platform call might
 * invalidate/modify the returned instance.
 **/
const NMPlatformLink *
nm_platform_link_get(NMPlatform *self, int ifindex)
{
    return NMP_OBJECT_CAST_LINK(nm_platform_link_get_obj(self, ifindex, TRUE));
}

/**
 * nm_platform_link_get_by_ifname:
 * @self: platform instance
 * @ifname: the ifname
 *
 * Returns: the first #NMPlatformLink instance with the given name.
 **/
const NMPlatformLink *
nm_platform_link_get_by_ifname(NMPlatform *self, const char *ifname)
{
    const NMPObject *obj;

    _CHECK_SELF(self, klass, NULL);

    if (!ifname || !*ifname)
        return NULL;

    obj = nmp_cache_lookup_link_full(nm_platform_get_cache(self),
                                     0,
                                     ifname,
                                     TRUE,
                                     NM_LINK_TYPE_NONE,
                                     NULL,
                                     NULL);
    return NMP_OBJECT_CAST_LINK(obj);
}

struct _nm_platform_link_get_by_address_data {
    gconstpointer data;
    guint8        len;
};

static gboolean
_nm_platform_link_get_by_address_match_link(const NMPObject                              *obj,
                                            struct _nm_platform_link_get_by_address_data *d)
{
    return obj->link.l_address.len == d->len && !memcmp(obj->link.l_address.data, d->data, d->len);
}

/**
 * nm_platform_link_get_by_address:
 * @self: platform instance
 * @address: a pointer to the binary hardware address
 * @length: the size of @address in bytes
 *
 * Returns: the first #NMPlatformLink object with a matching
 * address.
 **/
const NMPlatformLink *
nm_platform_link_get_by_address(NMPlatform   *self,
                                NMLinkType    link_type,
                                gconstpointer address,
                                size_t        length)
{
    const NMPObject                             *obj;
    struct _nm_platform_link_get_by_address_data d = {
        .data = address,
        .len  = length,
    };

    _CHECK_SELF(self, klass, NULL);

    if (length == 0)
        return NULL;

    if (length > _NM_UTILS_HWADDR_LEN_MAX)
        g_return_val_if_reached(NULL);
    if (!address)
        g_return_val_if_reached(NULL);

    obj = nmp_cache_lookup_link_full(nm_platform_get_cache(self),
                                     0,
                                     NULL,
                                     TRUE,
                                     link_type,
                                     (NMPObjectMatchFn) _nm_platform_link_get_by_address_match_link,
                                     &d);
    return NMP_OBJECT_CAST_LINK(obj);
}

static int
_link_add_check_existing(NMPlatform            *self,
                         const char            *name,
                         NMLinkType             type,
                         const NMPlatformLink **out_link)
{
    const NMPlatformLink *pllink;

    pllink = nm_platform_link_get_by_ifname(self, name);
    if (pllink) {
        gboolean wrong_type;

        wrong_type = type != NM_LINK_TYPE_NONE && pllink->type != type;
        _LOG2D("link: skip adding link due to existing interface of type %s%s%s",
               nm_link_type_to_string(pllink->type),
               wrong_type ? ", expected " : "",
               wrong_type ? nm_link_type_to_string(type) : "");
        if (out_link)
            *out_link = pllink;
        if (wrong_type)
            return -NME_PL_WRONG_TYPE;
        return -NME_PL_EXISTS;
    }
    if (out_link)
        *out_link = NULL;
    return 0;
}

/**
 * nm_platform_link_add:
 * @self: platform instance
 * @type: Interface type
 * @name: Interface name
 * @parent: the IFLA_LINK parameter or 0.
 * @address: (allow-none): set the mac address of the link
 * @address_len: the length of the @address
 * @extra_data: depending on @type, additional data.
 * @out_link: on success, the link object
 *
 * Add a software interface.  If the interface already exists and is of type
 * @type, return -NME_PL_EXISTS and returns the link
 * in @out_link.  If the interface already exists and is not of type @type,
 * return -NME_PL_WRONG_TYPE.
 *
 * Any link-changed ADDED signal will be emitted directly, before this
 * function finishes.
 *
 * Returns: the negative nm-error on failure.
 */
int
nm_platform_link_add(NMPlatform            *self,
                     NMLinkType             type,
                     const char            *name,
                     int                    parent,
                     const void            *address,
                     size_t                 address_len,
                     guint32                mtu,
                     gconstpointer          extra_data,
                     const NMPlatformLink **out_link)
{
    int  r;
    char addr_buf[_NM_UTILS_HWADDR_LEN_MAX * 3];
    char mtu_buf[16];
    char parent_buf[64];
    char buf[512];

    _CHECK_SELF(self, klass, -NME_BUG);

    g_return_val_if_fail(name, -NME_BUG);
    g_return_val_if_fail((address != NULL) ^ (address_len == 0), -NME_BUG);
    g_return_val_if_fail(address_len <= _NM_UTILS_HWADDR_LEN_MAX, -NME_BUG);
    g_return_val_if_fail(parent >= 0, -NME_BUG);

    r = _link_add_check_existing(self, name, type, out_link);
    if (r < 0)
        return r;

    _LOG2D("link: adding link: "
           "%s "    /* type */
           "\"%s\"" /* name */
           "%s%s"   /* parent */
           "%s%s"   /* address */
           "%s%s"   /* mtu */
           "%s"     /* extra_data */
           "",
           nm_link_type_to_string(type),
           name,
           parent > 0 ? ", parent " : "",
           parent > 0 ? nm_sprintf_buf(parent_buf, "%d", parent) : "",
           address ? ", address: " : "",
           address ? _nm_utils_hwaddr_ntoa(address, address_len, FALSE, addr_buf, sizeof(addr_buf))
                   : "",
           mtu ? ", mtu: " : "",
           mtu ? nm_sprintf_buf(mtu_buf, "%u", mtu) : "",
           ({
               char *buf_p   = buf;
               gsize buf_len = sizeof(buf);

               buf[0] = '\0';

               switch (type) {
               case NM_LINK_TYPE_BRIDGE:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_bridge_to_string((const NMPlatformLnkBridge *) extra_data,
                                                    buf_p,
                                                    buf_len);
                   break;
               case NM_LINK_TYPE_VLAN:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_vlan_to_string((const NMPlatformLnkVlan *) extra_data,
                                                  buf_p,
                                                  buf_len);
                   break;
               case NM_LINK_TYPE_VRF:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_vrf_to_string((const NMPlatformLnkVrf *) extra_data,
                                                 buf_p,
                                                 buf_len);
                   break;
               case NM_LINK_TYPE_VXLAN:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_vxlan_to_string((const NMPlatformLnkVxlan *) extra_data,
                                                   buf_p,
                                                   buf_len);
                   break;
               case NM_LINK_TYPE_VETH:
                   nm_sprintf_buf(buf, ", veth-peer \"%s\"", (const char *) extra_data);
                   break;
               case NM_LINK_TYPE_GRE:
               case NM_LINK_TYPE_GRETAP:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_gre_to_string((const NMPlatformLnkGre *) extra_data,
                                                 buf_p,
                                                 buf_len);
                   break;
               case NM_LINK_TYPE_SIT:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_sit_to_string((const NMPlatformLnkSit *) extra_data,
                                                 buf_p,
                                                 buf_len);
                   break;
               case NM_LINK_TYPE_IP6TNL:
               case NM_LINK_TYPE_IP6GRE:
               case NM_LINK_TYPE_IP6GRETAP:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_ip6tnl_to_string((const NMPlatformLnkIp6Tnl *) extra_data,
                                                    buf_p,
                                                    buf_len);
                   break;
               case NM_LINK_TYPE_IPIP:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_ipip_to_string((const NMPlatformLnkIpIp *) extra_data,
                                                  buf_p,
                                                  buf_len);
                   break;
               case NM_LINK_TYPE_MACSEC:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_macsec_to_string((const NMPlatformLnkMacsec *) extra_data,
                                                    buf_p,
                                                    buf_len);
                   break;
               case NM_LINK_TYPE_MACVLAN:
               case NM_LINK_TYPE_MACVTAP:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_macvlan_to_string((const NMPlatformLnkMacvlan *) extra_data,
                                                     buf_p,
                                                     buf_len);
                   break;
               case NM_LINK_TYPE_VTI:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_vti_to_string((const NMPlatformLnkVti *) extra_data,
                                                 buf_p,
                                                 buf_len);
                   break;
               case NM_LINK_TYPE_VTI6:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_vti6_to_string((const NMPlatformLnkVti6 *) extra_data,
                                                  buf_p,
                                                  buf_len);
                   break;
               case NM_LINK_TYPE_BOND:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_bond_to_string((const NMPlatformLnkBond *) extra_data,
                                                  buf_p,
                                                  buf_len);
                   break;
               default:
                   nm_assert(!extra_data);
                   break;
               }

               buf;
           }));

    return klass
        ->link_add(self, type, name, parent, address, address_len, mtu, extra_data, out_link);
}

int
nm_platform_link_change(NMPlatform *self, NMLinkType type, int ifindex, gconstpointer extra_data)
{
    char        buf[512];
    const char *name = nm_platform_link_get_name(self, ifindex);

    _CHECK_SELF(self, klass, -NME_BUG);

    _LOG2D("link: changing link: "
           "%s "    /* type */
           "\"%s\"" /* name */
           "%s"     /* extra_data */
           "",
           nm_link_type_to_string(type),
           name,
           ({
               char *buf_p   = buf;
               gsize buf_len = sizeof(buf);

               buf[0] = '\0';

               switch (type) {
               case NM_LINK_TYPE_BRIDGE:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_bridge_to_string((const NMPlatformLnkBridge *) extra_data,
                                                    buf_p,
                                                    buf_len);
                   break;
               case NM_LINK_TYPE_BOND:
                   nm_strbuf_append_str(&buf_p, &buf_len, ", ");
                   nm_platform_lnk_bond_to_string((const NMPlatformLnkBond *) extra_data,
                                                  buf_p,
                                                  buf_len);
                   break;
               default:
                   nm_assert(!extra_data);
                   break;
               }

               buf;
           }));

    return klass->link_change(self, type, ifindex, extra_data);
}

/**
 * nm_platform_link_delete:
 * @self: platform instance
 * @ifindex: Interface index
 */
gboolean
nm_platform_link_delete(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    _LOG3D("link: deleting");
    return klass->link_delete(self, ifindex);
}

/**
 * nm_platform_link_set_netns:
 * @self: platform instance
 * @ifindex: Interface index
 * @netns_fd: the file descriptor for the new netns.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_link_set_netns(NMPlatform *self, int ifindex, int netns_fd)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(netns_fd > 0, FALSE);

    _LOG3D("link: move link to network namespace with fd %d", netns_fd);
    return klass->link_set_netns(self, ifindex, netns_fd);
}

/**
 * nm_platform_link_get_index:
 * @self: platform instance
 * @name: Interface name
 *
 * Returns: The interface index corresponding to the given interface name
 * or 0. Interface name is owned by #NMPlatform, don't free it.
 */
int
nm_platform_link_get_ifindex(NMPlatform *self, const char *name)
{
    const NMPlatformLink *pllink;

    pllink = nm_platform_link_get_by_ifname(self, name);
    return pllink ? pllink->ifindex : 0;
}

const char *
nm_platform_if_indextoname(NMPlatform *self, int ifindex, char out_ifname[static 16 /* IFNAMSIZ */])
{
    _CHECK_SELF_NETNS(self, klass, netns, FALSE);

    return nmp_utils_if_indextoname(ifindex, out_ifname);
}

int
nm_platform_if_nametoindex(NMPlatform *self, const char *ifname)
{
    _CHECK_SELF_NETNS(self, klass, netns, FALSE);

    return nmp_utils_if_nametoindex(ifname);
}

/**
 * nm_platform_link_get_name:
 * @self: platform instance
 * @name: Interface name
 *
 * Returns: The interface name corresponding to the given interface index
 * or %NULL.
 */
const char *
nm_platform_link_get_name(NMPlatform *self, int ifindex)
{
    const NMPlatformLink *pllink;

    pllink = nm_platform_link_get(self, ifindex);
    return pllink ? pllink->name : NULL;
}

/**
 * nm_platform_link_get_type:
 * @self: platform instance
 * @ifindex: Interface index.
 *
 * Returns: Link type constant as defined in nm-platform.h. On error,
 * NM_LINK_TYPE_NONE is returned.
 */
NMLinkType
nm_platform_link_get_type(NMPlatform *self, int ifindex)
{
    const NMPlatformLink *pllink;

    pllink = nm_platform_link_get(self, ifindex);
    return pllink ? pllink->type : NM_LINK_TYPE_NONE;
}

/**
 * nm_platform_link_get_type_name:
 * @self: platform instance
 * @ifindex: Interface index.
 *
 * Returns: A string describing the type of link. In some cases this
 * may be more specific than nm_platform_link_get_type(), but in
 * other cases it may not. On error, %NULL is returned.
 */
const char *
nm_platform_link_get_type_name(NMPlatform *self, int ifindex)
{
    const NMPObject *obj;

    obj = nm_platform_link_get_obj(self, ifindex, TRUE);
    if (!obj)
        return NULL;

    if (obj->link.type != NM_LINK_TYPE_UNKNOWN) {
        /* We could detect the @link_type. In this case the function returns
         * our internal module names, which differs from rtnl_link_get_type():
         *   - NM_LINK_TYPE_INFINIBAND (gives "infiniband", instead of "ipoib")
         *   - NM_LINK_TYPE_TAP (gives "tap", instead of "tun").
         * Note that this functions is only used by NMDeviceGeneric to
         * set type_description. */
        return nm_link_type_to_string(obj->link.type);
    }
    /* Link type not detected. Fallback to rtnl_link_get_type()/IFLA_INFO_KIND. */
    return obj->link.kind ?: "unknown";
}

gboolean
nm_platform_link_get_udev_property(NMPlatform  *self,
                                   int          ifindex,
                                   const char  *name,
                                   const char **out_value)
{
    struct udev_device *udevice = NULL;
    const char         *uproperty;

    udevice = nm_platform_link_get_udev_device(self, ifindex);
    if (!udevice)
        return FALSE;

    uproperty = udev_device_get_property_value(udevice, name);
    if (!uproperty)
        return FALSE;

    NM_SET_OUT(out_value, uproperty);
    return TRUE;
}

/**
 * nm_platform_link_get_unmanaged:
 * @self: platform instance
 * @ifindex: interface index
 * @unmanaged: management status (in case %TRUE is returned)
 *
 * Returns: %TRUE if platform overrides NM default-unmanaged status,
 * %FALSE otherwise (with @unmanaged unmodified).
 */
gboolean
nm_platform_link_get_unmanaged(NMPlatform *self, int ifindex, gboolean *unmanaged)
{
    const char *value;

    if (nm_platform_link_get_udev_property(self, ifindex, "NM_UNMANAGED", &value)) {
        NM_SET_OUT(unmanaged, _nm_utils_ascii_str_to_bool(value, FALSE));
        return TRUE;
    }

    return FALSE;
}

/**
 * nm_platform_link_is_software:
 * @self: platform instance
 * @ifindex: Interface index.
 *
 * Returns: %TRUE if ifindex belongs to a software interface, not backed by
 * a physical device.
 */
gboolean
nm_platform_link_is_software(NMPlatform *self, int ifindex)
{
    return nm_link_type_is_software(nm_platform_link_get_type(self, ifindex));
}

/**
 * nm_platform_link_supports_slaves:
 * @self: platform instance
 * @ifindex: Interface index.
 *
 * Returns: %TRUE if ifindex belongs to an interface capable of enslaving
 * other interfaces.
 */
gboolean
nm_platform_link_supports_slaves(NMPlatform *self, int ifindex)
{
    return nm_link_type_supports_slaves(nm_platform_link_get_type(self, ifindex));
}

/**
 * nm_platform_link_refresh:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Reload the cache for ifindex synchronously.
 */
gboolean
nm_platform_link_refresh(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    if (klass->link_refresh)
        return klass->link_refresh(self, ifindex);

    return TRUE;
}

int
nm_platform_link_get_ifi_flags(NMPlatform *self, int ifindex, guint requested_flags)
{
    const NMPlatformLink *pllink;

    /* include invisible links (only in netlink, not udev). */
    pllink = NMP_OBJECT_CAST_LINK(nm_platform_link_get_obj(self, ifindex, FALSE));
    if (!pllink)
        return -ENODEV;

    /* Errors are signaled as negative values. That means, you cannot request
     * the most significant bit (2^31) with this API. Assert against that. */
    nm_assert((int) requested_flags >= 0);
    nm_assert(requested_flags < (guint) G_MAXINT);

    return (int) (pllink->n_ifi_flags & requested_flags);
}

/**
 * nm_platform_link_is_up:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Check if the interface is up.
 */
gboolean
nm_platform_link_is_up(NMPlatform *self, int ifindex)
{
    return nm_platform_link_get_ifi_flags(self, ifindex, IFF_UP) == IFF_UP;
}

/**
 * nm_platform_link_is_connected:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Check if the interface is connected.
 */
gboolean
nm_platform_link_is_connected(NMPlatform *self, int ifindex)
{
    const NMPlatformLink *pllink;

    pllink = nm_platform_link_get(self, ifindex);
    return pllink ? pllink->connected : FALSE;
}

/**
 * nm_platform_link_uses_arp:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Check if the interface is configured to use ARP.
 */
gboolean
nm_platform_link_uses_arp(NMPlatform *self, int ifindex)
{
    int f;

    f = nm_platform_link_get_ifi_flags(self, ifindex, IFF_NOARP);

    if (f < 0)
        return FALSE;
    if (f == IFF_NOARP)
        return FALSE;
    return TRUE;
}

/**
 * nm_platform_link_set_ipv6_token:
 * @self: platform instance
 * @ifindex: Interface index
 * @iid: Tokenized interface identifier
 *
 * Sets then IPv6 tokenized interface identifier.
 *
 * Returns: %TRUE a tokenized identifier was available
 */
gboolean
nm_platform_link_set_ipv6_token(NMPlatform *self, int ifindex, const NMUtilsIPv6IfaceId *iid)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex >= 0, FALSE);

    if (klass->link_set_token)
        return klass->link_set_token(self, ifindex, iid);
    return FALSE;
}

const char *
nm_platform_link_get_udi(NMPlatform *self, int ifindex)
{
    struct udev_device *device;

    device = nm_platform_link_get_udev_device(self, ifindex);
    return device ? udev_device_get_syspath(device) : NULL;
}

const char *
nm_platform_link_get_path(NMPlatform *self, int ifindex)
{
    const char *value = NULL;

    nm_platform_link_get_udev_property(self, ifindex, "ID_PATH", &value);
    return value;
}

struct udev_device *
nm_platform_link_get_udev_device(NMPlatform *self, int ifindex)
{
    const NMPObject *obj_cache;

    obj_cache = nm_platform_link_get_obj(self, ifindex, FALSE);
    return obj_cache ? obj_cache->_link.udev.device : NULL;
}

int
nm_platform_link_get_inet6_addr_gen_mode(NMPlatform *self, int ifindex)
{
    return _nm_platform_link_get_inet6_addr_gen_mode(nm_platform_link_get(self, ifindex));
}

int
nm_platform_link_set_inet6_addr_gen_mode(NMPlatform *self, int ifindex, guint8 mode)
{
    _CHECK_SELF(self, klass, -NME_BUG);

    g_return_val_if_fail(ifindex > 0, -NME_BUG);

    return klass->link_set_inet6_addr_gen_mode(self, ifindex, mode);
}

/**
 * nm_platform_link_set_address:
 * @self: platform instance
 * @ifindex: Interface index
 * @address: The new MAC address
 *
 * Set interface MAC address.
 */
int
nm_platform_link_set_address(NMPlatform *self, int ifindex, gconstpointer address, size_t length)
{
    gs_free char *mac = NULL;

    _CHECK_SELF(self, klass, -NME_BUG);

    g_return_val_if_fail(ifindex > 0, -NME_BUG);
    g_return_val_if_fail(address, -NME_BUG);
    g_return_val_if_fail(length > 0, -NME_BUG);

    _LOG3D("link: setting hardware address to %s",
           _nm_utils_hwaddr_ntoa_maybe_a(address, length, &mac));

    return klass->link_set_address(self, ifindex, address, length);
}

/**
 * nm_platform_link_get_address:
 * @self: platform instance
 * @ifindex: Interface index
 * @length: Pointer to a variable to store address length
 *
 * Returns: the interface hardware address as an array of bytes of
 * length @length.
 */
gconstpointer
nm_platform_link_get_address(NMPlatform *self, int ifindex, size_t *length)
{
    const NMPlatformLink *pllink;

    pllink = nm_platform_link_get(self, ifindex);
    return nmp_link_address_get(pllink ? &pllink->l_address : NULL, length);
}

/**
 * nm_platform_link_get_permanent_address_ethtool:
 * @self: platform instance
 * @ifindex: Interface index
 * @buf: buffer of at least %_NM_UTILS_HWADDR_LEN_MAX bytes, on success
 * the permanent hardware address
 * @length: Pointer to a variable to store address length
 *
 * Returns: %TRUE on success, %FALSE on failure to read the permanent hardware
 * address.
 */
gboolean
nm_platform_link_get_permanent_address_ethtool(NMPlatform     *self,
                                               int             ifindex,
                                               NMPLinkAddress *out_address)
{
    _CHECK_SELF(self, klass, FALSE);

    if (out_address)
        out_address->len = 0;

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(out_address, FALSE);

    if (klass->link_get_permanent_address_ethtool)
        return klass->link_get_permanent_address_ethtool(self, ifindex, out_address);
    return FALSE;
}

gboolean
nm_platform_link_get_permanent_address(NMPlatform           *self,
                                       const NMPlatformLink *plink,
                                       NMPLinkAddress       *out_address)
{
    _CHECK_SELF(self, klass, FALSE);
    nm_assert(out_address);

    if (!plink)
        return FALSE;
    if (plink->l_perm_address.len > 0) {
        *out_address = plink->l_perm_address;
        return TRUE;
    }
    if (nm_platform_kernel_support_get_full(NM_PLATFORM_KERNEL_SUPPORT_TYPE_IFLA_PERM_ADDRESS,
                                            FALSE)
        == NM_OPTION_BOOL_TRUE) {
        /* kernel supports the netlink API IFLA_PERM_ADDRESS, but we don't have the
         * address cached. There is no need to fallback to ethtool ioctl. */
        return FALSE;
    }
    return nm_platform_link_get_permanent_address_ethtool(self, plink->ifindex, out_address);
}

gboolean
nm_platform_link_supports_carrier_detect(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex >= 0, FALSE);

    return klass->link_supports_carrier_detect(self, ifindex);
}

gboolean
nm_platform_link_supports_vlans(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex >= 0, FALSE);

    return klass->link_supports_vlans(self, ifindex);
}

gboolean
nm_platform_link_supports_sriov(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex >= 0, FALSE);

    return klass->link_supports_sriov(self, ifindex);
}

/**
 * nm_platform_link_set_sriov_params:
 * @self: platform instance
 * @ifindex: the index of the interface to change
 * @num_vfs: the number of VFs to create
 * @autoprobe: the new autoprobe-drivers value (pass
 *     %NM_OPTION_BOOL_DEFAULT to keep current value)
 * @callback: called when the operation finishes
 * @callback_data: data passed to @callback
 * @cancellable: cancellable to abort the operation
 *
 * Sets SR-IOV parameters asynchronously without
 * blocking the main thread. The callback function is
 * always invoked, and asynchronously.
 */
void
nm_platform_link_set_sriov_params_async(NMPlatform             *self,
                                        int                     ifindex,
                                        guint                   num_vfs,
                                        NMOptionBool            autoprobe,
                                        NMPlatformAsyncCallback callback,
                                        gpointer                callback_data,
                                        GCancellable           *cancellable)
{
    _CHECK_SELF_VOID(self, klass);

    g_return_if_fail(ifindex > 0);

    _LOG3D("link: setting %u total VFs and autoprobe %d", num_vfs, (int) autoprobe);
    klass->link_set_sriov_params_async(self,
                                       ifindex,
                                       num_vfs,
                                       autoprobe,
                                       callback,
                                       callback_data,
                                       cancellable);
}

gboolean
nm_platform_link_set_sriov_vfs(NMPlatform *self, int ifindex, const NMPlatformVF *const *vfs)
{
    guint i;
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    if (_LOGD_ENABLED()) {
        _LOG3D("link: setting VFs");
        for (i = 0; vfs[i]; i++) {
            char                sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
            const NMPlatformVF *vf = vfs[i];

            _LOG3D("link:   VF %s", nm_platform_vf_to_string(vf, sbuf, sizeof(sbuf)));
        }
    }

    return klass->link_set_sriov_vfs(self, ifindex, vfs);
}

gboolean
nm_platform_link_set_bridge_vlans(NMPlatform                        *self,
                                  int                                ifindex,
                                  gboolean                           on_master,
                                  const NMPlatformBridgeVlan *const *vlans)
{
    guint i;
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    if (_LOGD_ENABLED()) {
        _LOG3D("link: %s bridge VLANs on %s",
               vlans ? "setting" : "clearing",
               on_master ? "master" : "self");
        if (vlans) {
            for (i = 0; vlans[i]; i++) {
                char                        sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
                const NMPlatformBridgeVlan *vlan = vlans[i];

                _LOG3D("link:   bridge VLAN %s",
                       nm_platform_bridge_vlan_to_string(vlan, sbuf, sizeof(sbuf)));
            }
        }
    }

    return klass->link_set_bridge_vlans(self, ifindex, on_master, vlans);
}

/**
 * nm_platform_link_change_flags_full:
 * @self: platform instance
 * @ifindex: interface index
 * @flags_mask: flag mask to be set
 * @flags_set: flag to be set on the flag mask
 *
 * Change the interface flag mask to the value specified.
 *
 * Returns: nm-errno code.
 *
 */
int
nm_platform_link_change_flags_full(NMPlatform *self,
                                   int         ifindex,
                                   unsigned    flags_mask,
                                   unsigned    flags_set)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, -NME_BUG);

    return klass->link_change_flags(self, ifindex, flags_mask, flags_set);
}

/**
 * nm_platform_link_set_mtu:
 * @self: platform instance
 * @ifindex: Interface index
 * @mtu: The new MTU value
 *
 * Set interface MTU.
 */
int
nm_platform_link_set_mtu(NMPlatform *self, int ifindex, guint32 mtu)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex >= 0, FALSE);
    g_return_val_if_fail(mtu > 0, FALSE);

    _LOG3D("link: setting mtu %" G_GUINT32_FORMAT, mtu);
    return klass->link_set_mtu(self, ifindex, mtu);
}

/**
 * nm_platform_link_get_mtu:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Returns: MTU value for the interface or 0 on error.
 */
guint32
nm_platform_link_get_mtu(NMPlatform *self, int ifindex)
{
    const NMPlatformLink *pllink;

    pllink = nm_platform_link_get(self, ifindex);
    return pllink ? pllink->mtu : 0;
}

/**
 * nm_platform_link_set_name:
 * @self: platform instance
 * @ifindex: Interface index
 * @name: The new interface name
 *
 * Set interface name.
 */
gboolean
nm_platform_link_set_name(NMPlatform *self, int ifindex, const char *name)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex >= 0, FALSE);
    g_return_val_if_fail(name, FALSE);

    _LOG3D("link: setting name %s", name);

    if (strlen(name) + 1 > IFNAMSIZ)
        return FALSE;

    return klass->link_set_name(self, ifindex, name);
}

/**
 * nm_platform_link_get_physical_port_id:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * The physical port ID, if present, indicates some unique identifier of
 * the parent interface (eg, the physical port of which this link is a child).
 * Two links that report the same physical port ID can be assumed to be
 * children of the same physical port and may share resources that limit
 * their abilities.
 *
 * Returns: physical port ID for the interface, or %NULL on error
 * or if the interface has no physical port ID.
 */
char *
nm_platform_link_get_physical_port_id(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, NULL);

    g_return_val_if_fail(ifindex >= 0, NULL);

    if (klass->link_get_physical_port_id)
        return klass->link_get_physical_port_id(self, ifindex);
    return NULL;
}

/**
 * nm_platform_link_get_dev_id:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * In contrast to the physical device ID (which indicates which parent a
 * child has) the device ID differentiates sibling devices that may share
 * the same MAC address.
 *
 * Returns: device ID for the interface, or 0 on error or if the
 * interface has no device ID.
 */
guint
nm_platform_link_get_dev_id(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, 0);

    g_return_val_if_fail(ifindex >= 0, 0);

    if (klass->link_get_dev_id)
        return klass->link_get_dev_id(self, ifindex);
    return 0;
}

/**
 * nm_platform_link_get_wake_onlan:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Returns: the "Wake-on-LAN" status for @ifindex.
 */
gboolean
nm_platform_link_get_wake_on_lan(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex >= 0, FALSE);

    if (klass->link_get_wake_on_lan)
        return klass->link_get_wake_on_lan(self, ifindex);
    return FALSE;
}

/**
 * nm_platform_link_get_driver_info:
 * @self: platform instance
 * @ifindex: Interface index
 * @out_driver_name: (transfer full): on success, the driver name if available
 * @out_driver_version: (transfer full): on success, the driver version if available
 * @out_fw_version: (transfer full): on success, the firmware version if available
 *
 * Returns: %TRUE on success (though @out_driver_name, @out_driver_version and
 * @out_fw_version can be %NULL if no information was available), %FALSE on
 * failure.
 */
gboolean
nm_platform_link_get_driver_info(NMPlatform *self,
                                 int         ifindex,
                                 char      **out_driver_name,
                                 char      **out_driver_version,
                                 char      **out_fw_version)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex >= 0, FALSE);

    return klass->link_get_driver_info(self,
                                       ifindex,
                                       out_driver_name,
                                       out_driver_version,
                                       out_fw_version);
}

/**
 * nm_platform_link_enslave:
 * @self: platform instance
 * @master: Interface index of the master
 * @ifindex: Interface index of the slave
 *
 * Enslave @ifindex to @master.
 */
gboolean
nm_platform_link_enslave(NMPlatform *self, int master, int ifindex)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(master > 0, FALSE);
    g_return_val_if_fail(ifindex > 0, FALSE);

    _LOG3D("link: enslaving to master '%s'", nm_platform_link_get_name(self, master));
    return klass->link_enslave(self, master, ifindex);
}

/**
 * nm_platform_link_release:
 * @self: platform instance
 * @master: Interface index of the master
 * @ifindex: Interface index of the slave
 *
 * Release @slave from @master.
 */
gboolean
nm_platform_link_release(NMPlatform *self, int master, int ifindex)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(master > 0, FALSE);
    g_return_val_if_fail(ifindex > 0, FALSE);

    if (nm_platform_link_get_master(self, ifindex) != master)
        return FALSE;

    _LOG3D("link: releasing %d from master '%s' (%d)",
           ifindex,
           nm_platform_link_get_name(self, master),
           master);
    return klass->link_release(self, master, ifindex);
}

/**
 * nm_platform_link_get_master:
 * @self: platform instance
 * @slave: Interface index of the slave.
 *
 * Returns: Interface index of the slave's master.
 */
int
nm_platform_link_get_master(NMPlatform *self, int slave)
{
    const NMPlatformLink *pllink;

    pllink = nm_platform_link_get(self, slave);
    return pllink ? pllink->master : 0;
}

/*****************************************************************************/

gboolean
nm_platform_link_can_assume(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, FALSE);

    if (klass->link_can_assume)
        return klass->link_can_assume(self, ifindex);
    g_return_val_if_reached(FALSE);
}

/*****************************************************************************/

/**
 * nm_platform_link_get_lnk:
 * @self: the platform instance
 * @ifindex: the link ifindex to lookup
 * @link_type: filter by link-type.
 * @out_link: (allow-none): returns the platform link instance
 *
 * If the function returns %NULL, that could mean that no such ifindex
 * exists, of that the link has no lnk data. You can find that out
 * by checking @out_link. @out_link will always be set if a link
 * with @ifindex exists.
 *
 * If @link_type is %NM_LINK_TYPE_NONE, the function returns the lnk
 * object if it is present. If you set link-type, you can be sure
 * that only a link type of the matching type is returned (or %NULL).
 *
 * Returns: the internal link lnk object. The returned object
 * is owned by the platform cache and must not be modified. Note
 * however, that the object is guaranteed to be immutable, so
 * you can safely take a reference and keep it for yourself
 * (but don't modify it).
 */
const NMPObject *
nm_platform_link_get_lnk(NMPlatform            *self,
                         int                    ifindex,
                         NMLinkType             link_type,
                         const NMPlatformLink **out_link)
{
    const NMPObject *obj;

    obj = nm_platform_link_get_obj(self, ifindex, TRUE);
    if (!obj) {
        NM_SET_OUT(out_link, NULL);
        return NULL;
    }

    NM_SET_OUT(out_link, &obj->link);

    if (!obj->_link.netlink.lnk)
        return NULL;
    if (link_type != NM_LINK_TYPE_NONE
        && (link_type != obj->link.type
            || link_type != NMP_OBJECT_GET_CLASS(obj->_link.netlink.lnk)->lnk_link_type))
        return NULL;

    return obj->_link.netlink.lnk;
}

static gconstpointer
_link_get_lnk(NMPlatform *self, int ifindex, NMLinkType link_type, const NMPlatformLink **out_link)
{
    const NMPObject *lnk;

    lnk = nm_platform_link_get_lnk(self, ifindex, link_type, out_link);
    return lnk ? &lnk->object : NULL;
}

const NMPlatformLnkBond *
nm_platform_link_get_lnk_bond(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_BOND, out_link);
}

const NMPlatformLnkBridge *
nm_platform_link_get_lnk_bridge(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_BRIDGE, out_link);
}

const NMPlatformLnkGre *
nm_platform_link_get_lnk_gre(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_GRE, out_link);
}

const NMPlatformLnkGre *
nm_platform_link_get_lnk_gretap(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_GRETAP, out_link);
}

const NMPlatformLnkInfiniband *
nm_platform_link_get_lnk_infiniband(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_INFINIBAND, out_link);
}

const NMPlatformLnkIp6Tnl *
nm_platform_link_get_lnk_ip6tnl(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_IP6TNL, out_link);
}

const NMPlatformLnkIp6Tnl *
nm_platform_link_get_lnk_ip6gre(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_IP6GRE, out_link);
}

const NMPlatformLnkIp6Tnl *
nm_platform_link_get_lnk_ip6gretap(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_IP6GRETAP, out_link);
}

const NMPlatformLnkIpIp *
nm_platform_link_get_lnk_ipip(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_IPIP, out_link);
}

const NMPlatformLnkMacsec *
nm_platform_link_get_lnk_macsec(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_MACSEC, out_link);
}

const NMPlatformLnkMacvlan *
nm_platform_link_get_lnk_macvlan(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_MACVLAN, out_link);
}

const NMPlatformLnkMacvlan *
nm_platform_link_get_lnk_macvtap(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_MACVTAP, out_link);
}

const NMPlatformLnkSit *
nm_platform_link_get_lnk_sit(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_SIT, out_link);
}

const NMPlatformLnkTun *
nm_platform_link_get_lnk_tun(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_TUN, out_link);
}

const NMPlatformLnkVlan *
nm_platform_link_get_lnk_vlan(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_VLAN, out_link);
}

const NMPlatformLnkVrf *
nm_platform_link_get_lnk_vrf(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_VRF, out_link);
}

const NMPlatformLnkVti *
nm_platform_link_get_lnk_vti(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_VTI, out_link);
}

const NMPlatformLnkVti6 *
nm_platform_link_get_lnk_vti6(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_VTI6, out_link);
}

const NMPlatformLnkVxlan *
nm_platform_link_get_lnk_vxlan(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_VXLAN, out_link);
}

const NMPlatformLnkWireGuard *
nm_platform_link_get_lnk_wireguard(NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
    return _link_get_lnk(self, ifindex, NM_LINK_TYPE_WIREGUARD, out_link);
}

/*****************************************************************************/

static NM_UTILS_FLAGS2STR_DEFINE(
    _wireguard_change_flags_to_string,
    NMPlatformWireGuardChangeFlags,
    NM_UTILS_FLAGS2STR(NM_PLATFORM_WIREGUARD_CHANGE_FLAG_NONE, "none"),
    NM_UTILS_FLAGS2STR(NM_PLATFORM_WIREGUARD_CHANGE_FLAG_REPLACE_PEERS, "replace-peers"),
    NM_UTILS_FLAGS2STR(NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_PRIVATE_KEY, "has-private-key"),
    NM_UTILS_FLAGS2STR(NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_LISTEN_PORT, "has-listen-port"),
    NM_UTILS_FLAGS2STR(NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_FWMARK, "has-fwmark"), );

static NM_UTILS_FLAGS2STR_DEFINE(
    _wireguard_change_peer_flags_to_string,
    NMPlatformWireGuardChangePeerFlags,
    NM_UTILS_FLAGS2STR(NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_NONE, "none"),
    NM_UTILS_FLAGS2STR(NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_REMOVE_ME, "remove"),
    NM_UTILS_FLAGS2STR(NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_PRESHARED_KEY, "psk"),
    NM_UTILS_FLAGS2STR(NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_KEEPALIVE_INTERVAL, "ka"),
    NM_UTILS_FLAGS2STR(NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ENDPOINT, "ep"),
    NM_UTILS_FLAGS2STR(NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ALLOWEDIPS, "aips"),
    NM_UTILS_FLAGS2STR(NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_REPLACE_ALLOWEDIPS, "remove-aips"), );

int
nm_platform_link_wireguard_change(NMPlatform                               *self,
                                  int                                       ifindex,
                                  const NMPlatformLnkWireGuard             *lnk_wireguard,
                                  const NMPWireGuardPeer                   *peers,
                                  const NMPlatformWireGuardChangePeerFlags *peer_flags,
                                  guint                                     peers_len,
                                  NMPlatformWireGuardChangeFlags            change_flags)
{
    _CHECK_SELF(self, klass, -NME_BUG);

    nm_assert(klass->link_wireguard_change);

    if (_LOGD_ENABLED()) {
        char buf_lnk[256];
        char buf_peers[512];
        char buf_change_flags[100];

        buf_peers[0] = '\0';
        if (peers_len > 0) {
            char *b   = buf_peers;
            gsize len = sizeof(buf_peers);
            guint i;

            nm_strbuf_append_str(&b, &len, " { ");
            for (i = 0; i < peers_len; i++) {
                nm_strbuf_append_str(&b, &len, " { ");
                nm_platform_wireguard_peer_to_string(&peers[i], b, len);
                nm_strbuf_seek_end(&b, &len);
                if (peer_flags) {
                    nm_strbuf_append(
                        &b,
                        &len,
                        " (%s)",
                        _wireguard_change_peer_flags_to_string(peer_flags[i],
                                                               buf_change_flags,
                                                               sizeof(buf_change_flags)));
                }
                nm_strbuf_append_str(&b, &len, " } ");
            }
            nm_strbuf_append_str(&b, &len, "}");
        }

        _LOG3D("link: change wireguard ifindex %d, %s, (%s), %u peers%s",
               ifindex,
               nm_platform_lnk_wireguard_to_string(lnk_wireguard, buf_lnk, sizeof(buf_lnk)),
               _wireguard_change_flags_to_string(change_flags,
                                                 buf_change_flags,
                                                 sizeof(buf_change_flags)),
               peers_len,
               buf_peers);
    }

    return klass->link_wireguard_change(self,
                                        ifindex,
                                        lnk_wireguard,
                                        peers,
                                        peer_flags,
                                        peers_len,
                                        change_flags);
}

/*****************************************************************************/

/**
 * nm_platform_link_tun_add:
 * @self: platform instance
 * @name: new interface name
 * @tap: whether the interface is a TAP
 * @owner: interface owner or -1
 * @group: interface group or -1
 * @pi: whether to clear the IFF_NO_PI flag
 * @vnet_hdr: whether to set the IFF_VNET_HDR flag
 * @multi_queue: whether to set the IFF_MULTI_QUEUE flag
 * @out_link: on success, the link object
 * @out_fd: (allow-none): if give, return the file descriptor for the
 *   created device. Note that when creating a non-persistent device,
 *   this argument is mandatory, otherwise it makes no sense
 *   to create such an interface.
 *   The caller is responsible for closing this file descriptor.
 *
 * Create a TUN or TAP interface.
 */
int
nm_platform_link_tun_add(NMPlatform             *self,
                         const char             *name,
                         const NMPlatformLnkTun *props,
                         const NMPlatformLink  **out_link,
                         int                    *out_fd)
{
    char b[255];
    int  r;

    _CHECK_SELF(self, klass, -NME_BUG);

    g_return_val_if_fail(name, -NME_BUG);
    g_return_val_if_fail(props, -NME_BUG);
    g_return_val_if_fail(NM_IN_SET(props->type, IFF_TUN, IFF_TAP), -NME_BUG);

    /* creating a non-persistent device requires that the caller handles
     * the file descriptor. */
    g_return_val_if_fail(props->persist || out_fd, -NME_BUG);

    NM_SET_OUT(out_fd, -1);

    r = _link_add_check_existing(self, name, NM_LINK_TYPE_TUN, out_link);
    if (r < 0)
        return r;

    _LOG2D("link: adding link %s", nm_platform_lnk_tun_to_string(props, b, sizeof(b)));

    if (!klass->link_tun_add(self, name, props, out_link, out_fd))
        return -NME_UNSPEC;
    return 0;
}

gboolean
nm_platform_link_6lowpan_get_properties(NMPlatform *self, int ifindex, int *out_parent)
{
    const NMPlatformLink *plink;

    plink = nm_platform_link_get(self, ifindex);
    if (!plink)
        return FALSE;

    if (plink->type != NM_LINK_TYPE_6LOWPAN)
        return FALSE;

    if (plink->parent != 0) {
        NM_SET_OUT(out_parent, plink->parent);
        return TRUE;
    }

    /* As of 4.16 kernel does not expose the peer_ifindex as IFA_LINK.
     * Find the WPAN device with the same MAC address. */
    if (out_parent) {
        const NMPlatformLink *parent_plink;

        parent_plink = nm_platform_link_get_by_address(self,
                                                       NM_LINK_TYPE_WPAN,
                                                       plink->l_address.data,
                                                       plink->l_address.len);
        NM_SET_OUT(out_parent, parent_plink ? parent_plink->ifindex : -1);
    }

    return TRUE;
}

/*****************************************************************************/

static gboolean
link_set_option(NMPlatform *self,
                int         ifindex,
                const char *category,
                const char *option,
                const char *value)
{
    nm_auto_close int dirfd = -1;
    char              ifname_verified[IFNAMSIZ];
    const char       *path;

    if (!category || !option)
        return FALSE;

    dirfd = nm_platform_sysctl_open_netdir(self, ifindex, ifname_verified);
    if (dirfd < 0)
        return FALSE;

    path =
        nm_sprintf_buf_unsafe_a(strlen(category) + strlen(option) + 2, "%s/%s", category, option);
    return nm_platform_sysctl_set(self,
                                  NMP_SYSCTL_PATHID_NETDIR_unsafe(dirfd, ifname_verified, path),
                                  value);
}

static char *
link_get_option(NMPlatform *self, int ifindex, const char *category, const char *option)
{
    nm_auto_close int dirfd = -1;
    char              ifname_verified[IFNAMSIZ];
    const char       *path;

    if (!category || !option)
        return NULL;

    dirfd = nm_platform_sysctl_open_netdir(self, ifindex, ifname_verified);
    if (dirfd < 0)
        return NULL;

    path =
        nm_sprintf_buf_unsafe_a(strlen(category) + strlen(option) + 2, "%s/%s", category, option);
    return nm_platform_sysctl_get(self,
                                  NMP_SYSCTL_PATHID_NETDIR_unsafe(dirfd, ifname_verified, path));
}

static const char *
master_category(NMPlatform *self, int master)
{
    switch (nm_platform_link_get_type(self, master)) {
    case NM_LINK_TYPE_BRIDGE:
        return "bridge";
    case NM_LINK_TYPE_BOND:
        return "bonding";
    default:
        return NULL;
    }
}

static const char *
slave_category(NMPlatform *self, int slave)
{
    int master = nm_platform_link_get_master(self, slave);

    if (master <= 0)
        return NULL;

    switch (nm_platform_link_get_type(self, master)) {
    case NM_LINK_TYPE_BRIDGE:
        return "brport";
    case NM_LINK_TYPE_BOND:
        return "bonding_slave";
    default:
        return NULL;
    }
}

gboolean
nm_platform_sysctl_master_set_option(NMPlatform *self,
                                     int         ifindex,
                                     const char *option,
                                     const char *value)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(option, FALSE);
    g_return_val_if_fail(value, FALSE);

    return link_set_option(self, ifindex, master_category(self, ifindex), option, value);
}

char *
nm_platform_sysctl_master_get_option(NMPlatform *self, int ifindex, const char *option)
{
    _CHECK_SELF(self, klass, NULL);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(option, FALSE);

    return link_get_option(self, ifindex, master_category(self, ifindex), option);
}

gboolean
nm_platform_sysctl_slave_set_option(NMPlatform *self,
                                    int         ifindex,
                                    const char *option,
                                    const char *value)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(option, FALSE);
    g_return_val_if_fail(value, FALSE);

    return link_set_option(self, ifindex, slave_category(self, ifindex), option, value);
}

char *
nm_platform_sysctl_slave_get_option(NMPlatform *self, int ifindex, const char *option)
{
    _CHECK_SELF(self, klass, NULL);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(option, FALSE);

    return link_get_option(self, ifindex, slave_category(self, ifindex), option);
}

/*****************************************************************************/

gboolean
nm_platform_link_vlan_change(NMPlatform             *self,
                             int                     ifindex,
                             _NMVlanFlags            flags_mask,
                             _NMVlanFlags            flags_set,
                             gboolean                ingress_reset_all,
                             const NMVlanQosMapping *ingress_map,
                             gsize                   n_ingress_map,
                             gboolean                egress_reset_all,
                             const NMVlanQosMapping *egress_map,
                             gsize                   n_egress_map)
{
    _CHECK_SELF(self, klass, FALSE);

    nm_assert(klass->link_vlan_change);

    g_return_val_if_fail(!n_ingress_map || ingress_map, FALSE);
    g_return_val_if_fail(!n_egress_map || egress_map, FALSE);

    flags_set &= flags_mask;

    if (_LOGD_ENABLED()) {
        char  buf[512];
        char *b = buf;
        gsize len, i;

        b[0] = '\0';
        len  = sizeof(buf);

        if (flags_mask)
            nm_strbuf_append(&b,
                             &len,
                             " flags 0x%x/0x%x",
                             (unsigned) flags_set,
                             (unsigned) flags_mask);

        if (ingress_reset_all || n_ingress_map) {
            nm_strbuf_append_str(&b, &len, " ingress-qos-map");
            nm_platform_vlan_qos_mapping_to_string("", ingress_map, n_ingress_map, b, len);
            i = strlen(b);
            b += i;
            len -= i;
            if (ingress_reset_all)
                nm_strbuf_append_str(&b, &len, " (reset-all)");
        }

        if (egress_reset_all || n_egress_map) {
            nm_strbuf_append_str(&b, &len, " egress-qos-map");
            nm_platform_vlan_qos_mapping_to_string("", egress_map, n_egress_map, b, len);
            i = strlen(b);
            b += i;
            len -= i;
            if (egress_reset_all)
                nm_strbuf_append_str(&b, &len, " (reset-all)");
        }

        _LOG3D("link: change vlan %s", buf);
    }
    return klass->link_vlan_change(self,
                                   ifindex,
                                   flags_mask,
                                   flags_set,
                                   ingress_reset_all,
                                   ingress_map,
                                   n_ingress_map,
                                   egress_reset_all,
                                   egress_map,
                                   n_egress_map);
}

gboolean
nm_platform_link_vlan_set_ingress_map(NMPlatform *self, int ifindex, int from, int to)
{
    NMVlanQosMapping map = {
        .from = from,
        .to   = to,
    };

    return nm_platform_link_vlan_change(self, ifindex, 0, 0, FALSE, &map, 1, FALSE, NULL, 0);
}

gboolean
nm_platform_link_vlan_set_egress_map(NMPlatform *self, int ifindex, int from, int to)
{
    NMVlanQosMapping map = {
        .from = from,
        .to   = to,
    };

    return nm_platform_link_vlan_change(self, ifindex, 0, 0, FALSE, NULL, 0, FALSE, &map, 1);
}

static int
_infiniband_add_add_or_delete(NMPlatform            *self,
                              int                    ifindex,
                              int                    p_key,
                              gboolean               add,
                              const NMPlatformLink **out_link)
{
    char                  name[IFNAMSIZ];
    const NMPlatformLink *parent_link;
    int                   r;

    _CHECK_SELF(self, klass, -NME_BUG);

    g_return_val_if_fail(ifindex >= 0, -NME_BUG);
    g_return_val_if_fail(p_key >= 0 && p_key <= 0xffff, -NME_BUG);

    /* the special keys 0x0000 and 0x8000 are not allowed. */
    if (NM_IN_SET(p_key, 0, 0x8000))
        return -NME_UNSPEC;

    parent_link = nm_platform_link_get(self, ifindex);
    if (!parent_link)
        return -NME_PL_NOT_FOUND;

    if (parent_link->type != NM_LINK_TYPE_INFINIBAND)
        return -NME_PL_WRONG_TYPE;

    nmp_utils_new_infiniband_name(name, parent_link->name, p_key);

    if (add) {
        r = _link_add_check_existing(self, name, NM_LINK_TYPE_INFINIBAND, out_link);
        if (r < 0)
            return r;

        _LOG3D("link: adding infiniband partition %s, key %d", name, p_key);
        if (!klass->infiniband_partition_add(self, ifindex, p_key, out_link))
            return -NME_UNSPEC;
    } else {
        _LOG3D("link: deleting infiniband partition %s, key %d", name, p_key);

        if (!klass->infiniband_partition_delete(self, ifindex, p_key))
            return -NME_UNSPEC;
    }

    return 0;
}

int
nm_platform_link_infiniband_add(NMPlatform            *self,
                                int                    parent,
                                int                    p_key,
                                const NMPlatformLink **out_link)
{
    return _infiniband_add_add_or_delete(self, parent, p_key, TRUE, out_link);
}

int
nm_platform_link_infiniband_delete(NMPlatform *self, int parent, int p_key)
{
    return _infiniband_add_add_or_delete(self, parent, p_key, FALSE, NULL);
}

gboolean
nm_platform_link_infiniband_get_properties(NMPlatform  *self,
                                           int          ifindex,
                                           int         *out_parent,
                                           int         *out_p_key,
                                           const char **out_mode)
{
    nm_auto_close int              dirfd = -1;
    char                           ifname_verified[IFNAMSIZ];
    const NMPlatformLnkInfiniband *plnk;
    const NMPlatformLink          *plink;
    char                          *contents;
    const char                    *mode;
    int                            p_key = 0;

    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    plnk = nm_platform_link_get_lnk_infiniband(self, ifindex, &plink);

    if (!plink || plink->type != NM_LINK_TYPE_INFINIBAND)
        return FALSE;

    if (plnk) {
        NM_SET_OUT(out_parent, plink->parent);
        NM_SET_OUT(out_p_key, plnk->p_key);
        NM_SET_OUT(out_mode, plnk->mode);
        return TRUE;
    }

    /* Could not get the link information via netlink. To support older kernels,
     * fallback to reading sysfs. */

    dirfd = nm_platform_sysctl_open_netdir(self, ifindex, ifname_verified);
    if (dirfd < 0)
        return FALSE;

    contents =
        nm_platform_sysctl_get(self, NMP_SYSCTL_PATHID_NETDIR(dirfd, ifname_verified, "mode"));
    if (!contents)
        return FALSE;
    if (strstr(contents, "datagram"))
        mode = "datagram";
    else if (strstr(contents, "connected"))
        mode = "connected";
    else
        mode = NULL;
    g_free(contents);

    p_key =
        nm_platform_sysctl_get_int_checked(self,
                                           NMP_SYSCTL_PATHID_NETDIR(dirfd, ifname_verified, "pkey"),
                                           16,
                                           0,
                                           0xFFFF,
                                           -1);
    if (p_key < 0)
        return FALSE;

    NM_SET_OUT(out_parent, plink->parent);
    NM_SET_OUT(out_p_key, p_key);
    NM_SET_OUT(out_mode, mode);
    return TRUE;
}

gboolean
nm_platform_link_veth_get_properties(NMPlatform *self, int ifindex, int *out_peer_ifindex)
{
    const NMPlatformLink *plink;
    int                   peer_ifindex;

    plink = nm_platform_link_get(self, ifindex);
    if (!plink)
        return FALSE;

    if (plink->type != NM_LINK_TYPE_VETH)
        return FALSE;

    if (plink->parent != 0) {
        NM_SET_OUT(out_peer_ifindex, plink->parent);
        return TRUE;
    }

    /* Pre-4.1 kernel did not expose the peer_ifindex as IFA_LINK. Lookup via ethtool. */
    if (out_peer_ifindex) {
        nm_auto_pop_netns NMPNetns *netns = NULL;

        if (!nm_platform_netns_push(self, &netns))
            return FALSE;
        peer_ifindex = nmp_utils_ethtool_get_peer_ifindex(plink->ifindex);
        if (peer_ifindex <= 0)
            return FALSE;

        *out_peer_ifindex = peer_ifindex;
    }
    return TRUE;
}

/**
 * nm_platform_link_tun_get_properties:
 * @self: the #NMPlatform instance
 * @ifindex: the ifindex to look up
 * @out_properties: (out) (allow-none): return the read properties
 *
 * Only recent versions of kernel export tun properties via netlink.
 * So, if that's the case, then we have the NMPlatformLnkTun instance
 * in the platform cache ready to return. Otherwise, this function
 * falls back reading sysctl to obtain the tun properties. That
 * is racy, because querying sysctl means that the object might
 * be already removed from cache (while NM didn't yet process the
 * netlink message).
 *
 * Hence, to lookup the tun properties, you always need to use this
 * function, and use it with care knowing that it might obtain its
 * data by reading sysctl. Note that we don't want to add this workaround
 * to the platform cache itself, because the cache should (mainly)
 * contain data from netlink. To access the sysctl side channel, the
 * user needs to do explicitly.
 *
 * Returns: #TRUE, if the properties could be read. */
gboolean
nm_platform_link_tun_get_properties(NMPlatform *self, int ifindex, NMPlatformLnkTun *out_properties)
{
    const NMPObject *plobj;
    const NMPObject *pllnk;
    char             ifname[IFNAMSIZ];
    gint64           owner;
    gint64           group;
    gint64           flags;

    /* we consider also invisible links (those that are not yet in udev). */
    plobj = nm_platform_link_get_obj(self, ifindex, FALSE);
    if (!plobj)
        return FALSE;

    if (NMP_OBJECT_CAST_LINK(plobj)->type != NM_LINK_TYPE_TUN)
        return FALSE;

    pllnk = plobj->_link.netlink.lnk;
    if (pllnk) {
        nm_assert(NMP_OBJECT_GET_TYPE(pllnk) == NMP_OBJECT_TYPE_LNK_TUN);
        nm_assert(NMP_OBJECT_GET_CLASS(pllnk)->lnk_link_type == NM_LINK_TYPE_TUN);

        /* recent kernels expose tun properties via netlink and thus we have them
         * in the platform cache. */
        NM_SET_OUT(out_properties, pllnk->lnk_tun);
        return TRUE;
    }

    /* fallback to reading sysctl. */
    {
        nm_auto_close int dirfd = -1;

        dirfd = nm_platform_sysctl_open_netdir(self, ifindex, ifname);
        if (dirfd < 0)
            return FALSE;

        owner = nm_platform_sysctl_get_int_checked(self,
                                                   NMP_SYSCTL_PATHID_NETDIR(dirfd, ifname, "owner"),
                                                   10,
                                                   -1,
                                                   G_MAXUINT32,
                                                   -2);
        if (owner == -2)
            return FALSE;

        group = nm_platform_sysctl_get_int_checked(self,
                                                   NMP_SYSCTL_PATHID_NETDIR(dirfd, ifname, "group"),
                                                   10,
                                                   -1,
                                                   G_MAXUINT32,
                                                   -2);
        if (group == -2)
            return FALSE;

        flags =
            nm_platform_sysctl_get_int_checked(self,
                                               NMP_SYSCTL_PATHID_NETDIR(dirfd, ifname, "tun_flags"),
                                               16,
                                               0,
                                               G_MAXINT64,
                                               -1);
        if (flags == -1)
            return FALSE;
    }

    if (out_properties) {
        memset(out_properties, 0, sizeof(*out_properties));
        if (owner != -1) {
            out_properties->owner_valid = TRUE;
            out_properties->owner       = owner;
        }
        if (group != -1) {
            out_properties->group_valid = TRUE;
            out_properties->group       = group;
        }
        out_properties->type        = (flags & TUN_TYPE_MASK);
        out_properties->pi          = !(flags & IFF_NO_PI);
        out_properties->vnet_hdr    = !!(flags & IFF_VNET_HDR);
        out_properties->multi_queue = !!(flags & NM_IFF_MULTI_QUEUE);
        out_properties->persist     = !!(flags & IFF_PERSIST);
    }
    return TRUE;
}

gboolean
nm_platform_wifi_get_capabilities(NMPlatform *self, int ifindex, _NMDeviceWifiCapabilities *caps)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return klass->wifi_get_capabilities(self, ifindex, caps);
}

guint32
nm_platform_wifi_get_frequency(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, 0);

    g_return_val_if_fail(ifindex > 0, 0);

    return klass->wifi_get_frequency(self, ifindex);
}

gboolean
nm_platform_wifi_get_station(NMPlatform  *self,
                             int          ifindex,
                             NMEtherAddr *out_bssid,
                             int         *out_quality,
                             guint32     *out_rate)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return klass->wifi_get_station(self, ifindex, out_bssid, out_quality, out_rate);
}

_NM80211Mode
nm_platform_wifi_get_mode(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, _NM_802_11_MODE_UNKNOWN);

    g_return_val_if_fail(ifindex > 0, _NM_802_11_MODE_UNKNOWN);

    return klass->wifi_get_mode(self, ifindex);
}

void
nm_platform_wifi_set_mode(NMPlatform *self, int ifindex, _NM80211Mode mode)
{
    _CHECK_SELF_VOID(self, klass);

    g_return_if_fail(ifindex > 0);

    klass->wifi_set_mode(self, ifindex, mode);
}

static void
wifi_set_powersave(NMPlatform *p, int ifindex, guint32 powersave)
{
    /* empty */
}

void
nm_platform_wifi_set_powersave(NMPlatform *self, int ifindex, guint32 powersave)
{
    _CHECK_SELF_VOID(self, klass);

    g_return_if_fail(ifindex > 0);

    klass->wifi_set_powersave(self, ifindex, powersave);
}

guint32
nm_platform_wifi_find_frequency(NMPlatform *self, int ifindex, const guint32 *freqs)
{
    _CHECK_SELF(self, klass, 0);

    g_return_val_if_fail(ifindex > 0, 0);
    g_return_val_if_fail(freqs != NULL, 0);

    return klass->wifi_find_frequency(self, ifindex, freqs);
}

void
nm_platform_wifi_indicate_addressing_running(NMPlatform *self, int ifindex, gboolean running)
{
    _CHECK_SELF_VOID(self, klass);

    g_return_if_fail(ifindex > 0);

    klass->wifi_indicate_addressing_running(self, ifindex, running);
}

_NMSettingWirelessWakeOnWLan
nm_platform_wifi_get_wake_on_wlan(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return klass->wifi_get_wake_on_wlan(self, ifindex);
}

gboolean
nm_platform_wifi_set_wake_on_wlan(NMPlatform *self, int ifindex, _NMSettingWirelessWakeOnWLan wowl)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return klass->wifi_set_wake_on_wlan(self, ifindex, wowl);
}

gboolean
nm_platform_wifi_get_csme_conn_info(NMPlatform             *self,
                                    int                     ifindex,
                                    NMPlatformCsmeConnInfo *out_conn_info)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return klass->wifi_get_csme_conn_info(self, ifindex, out_conn_info);
}

gboolean
nm_platform_wifi_get_device_from_csme(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return klass->wifi_get_device_from_csme(self, ifindex);
}

guint32
nm_platform_mesh_get_channel(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, 0);

    g_return_val_if_fail(ifindex > 0, 0);

    return klass->mesh_get_channel(self, ifindex);
}

gboolean
nm_platform_mesh_set_channel(NMPlatform *self, int ifindex, guint32 channel)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return klass->mesh_set_channel(self, ifindex, channel);
}

gboolean
nm_platform_mesh_set_ssid(NMPlatform *self, int ifindex, const guint8 *ssid, gsize len)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(ssid != NULL, FALSE);

    return klass->mesh_set_ssid(self, ifindex, ssid, len);
}

guint16
nm_platform_wpan_get_pan_id(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return klass->wpan_get_pan_id(self, ifindex);
}

gboolean
nm_platform_wpan_set_pan_id(NMPlatform *self, int ifindex, guint16 pan_id)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return klass->wpan_set_pan_id(self, ifindex, pan_id);
}

guint16
nm_platform_wpan_get_short_addr(NMPlatform *self, int ifindex)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return klass->wpan_get_short_addr(self, ifindex);
}

gboolean
nm_platform_wpan_set_short_addr(NMPlatform *self, int ifindex, guint16 short_addr)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return klass->wpan_set_short_addr(self, ifindex, short_addr);
}

gboolean
nm_platform_wpan_set_channel(NMPlatform *self, int ifindex, guint8 page, guint8 channel)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return klass->wpan_set_channel(self, ifindex, page, channel);
}

/*****************************************************************************/

#define _to_string_dev(arr, ifindex)                                                   \
    ({                                                                                 \
        const int _ifindex = (ifindex);                                                \
                                                                                       \
        _ifindex ? nm_sprintf_buf((arr), " dev %d", ifindex) : nm_str_truncate((arr)); \
    })

/*****************************************************************************/

gboolean
nm_platform_ethtool_set_wake_on_lan(NMPlatform              *self,
                                    int                      ifindex,
                                    _NMSettingWiredWakeOnLan wol,
                                    const char              *wol_password)
{
    _CHECK_SELF_NETNS(self, klass, netns, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return nmp_utils_ethtool_set_wake_on_lan(ifindex, wol, wol_password);
}

gboolean
nm_platform_ethtool_set_link_settings(NMPlatform              *self,
                                      int                      ifindex,
                                      gboolean                 autoneg,
                                      guint32                  speed,
                                      NMPlatformLinkDuplexType duplex)
{
    _CHECK_SELF_NETNS(self, klass, netns, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return nmp_utils_ethtool_set_link_settings(ifindex, autoneg, speed, duplex);
}

gboolean
nm_platform_ethtool_get_link_settings(NMPlatform               *self,
                                      int                       ifindex,
                                      gboolean                 *out_autoneg,
                                      guint32                  *out_speed,
                                      NMPlatformLinkDuplexType *out_duplex)
{
    _CHECK_SELF_NETNS(self, klass, netns, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return nmp_utils_ethtool_get_link_settings(ifindex, out_autoneg, out_speed, out_duplex);
}

/*****************************************************************************/

NMEthtoolFeatureStates *
nm_platform_ethtool_get_link_features(NMPlatform *self, int ifindex)
{
    _CHECK_SELF_NETNS(self, klass, netns, NULL);

    g_return_val_if_fail(ifindex > 0, NULL);

    return nmp_utils_ethtool_get_features(ifindex);
}

gboolean
nm_platform_ethtool_set_features(
    NMPlatform                   *self,
    int                           ifindex,
    const NMEthtoolFeatureStates *features,
    const NMOptionBool *requested /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */,
    gboolean            do_set /* or reset */)
{
    _CHECK_SELF_NETNS(self, klass, netns, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return nmp_utils_ethtool_set_features(ifindex, features, requested, do_set);
}

gboolean
nm_platform_ethtool_get_link_coalesce(NMPlatform             *self,
                                      int                     ifindex,
                                      NMEthtoolCoalesceState *coalesce)
{
    _CHECK_SELF_NETNS(self, klass, netns, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(coalesce, FALSE);

    return nmp_utils_ethtool_get_coalesce(ifindex, coalesce);
}

gboolean
nm_platform_ethtool_set_coalesce(NMPlatform                   *self,
                                 int                           ifindex,
                                 const NMEthtoolCoalesceState *coalesce)
{
    _CHECK_SELF_NETNS(self, klass, netns, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return nmp_utils_ethtool_set_coalesce(ifindex, coalesce);
}

gboolean
nm_platform_ethtool_get_link_ring(NMPlatform *self, int ifindex, NMEthtoolRingState *ring)
{
    _CHECK_SELF_NETNS(self, klass, netns, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(ring, FALSE);

    return nmp_utils_ethtool_get_ring(ifindex, ring);
}

gboolean
nm_platform_ethtool_set_ring(NMPlatform *self, int ifindex, const NMEthtoolRingState *ring)
{
    _CHECK_SELF_NETNS(self, klass, netns, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return nmp_utils_ethtool_set_ring(ifindex, ring);
}

gboolean
nm_platform_ethtool_get_link_pause(NMPlatform *self, int ifindex, NMEthtoolPauseState *pause)
{
    _CHECK_SELF_NETNS(self, klass, netns, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(pause, FALSE);

    return nmp_utils_ethtool_get_pause(ifindex, pause);
}

gboolean
nm_platform_ethtool_set_pause(NMPlatform *self, int ifindex, const NMEthtoolPauseState *pause)
{
    _CHECK_SELF_NETNS(self, klass, netns, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);

    return nmp_utils_ethtool_set_pause(ifindex, pause);
}

/*****************************************************************************/

const NMDedupMultiHeadEntry *
nm_platform_lookup_all(NMPlatform *self, NMPCacheIdType cache_id_type, const NMPObject *obj)
{
    return nmp_cache_lookup_all(nm_platform_get_cache(self), cache_id_type, obj);
}

const NMDedupMultiEntry *
nm_platform_lookup_entry(NMPlatform *self, NMPCacheIdType cache_id_type, const NMPObject *obj)
{
    return nmp_cache_lookup_entry_with_idx_type(nm_platform_get_cache(self), cache_id_type, obj);
}

const NMDedupMultiHeadEntry *
nm_platform_lookup(NMPlatform *self, const NMPLookup *lookup)
{
    return nmp_cache_lookup(nm_platform_get_cache(self), lookup);
}

gboolean
nm_platform_lookup_predicate_routes_main(const NMPObject *obj, gpointer user_data)
{
    nm_assert(
        NM_IN_SET(NMP_OBJECT_GET_TYPE(obj), NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE));
    return nm_platform_route_table_is_main(
        nm_platform_ip_route_get_effective_table(&obj->ip_route));
}

gboolean
nm_platform_lookup_predicate_routes_main_skip_rtprot_kernel(const NMPObject *obj,
                                                            gpointer         user_data)
{
    nm_assert(
        NM_IN_SET(NMP_OBJECT_GET_TYPE(obj), NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE));
    return nm_platform_route_table_is_main(nm_platform_ip_route_get_effective_table(&obj->ip_route))
           && obj->ip_route.rt_source != NM_IP_CONFIG_SOURCE_RTPROT_KERNEL;
}

/**
 * nm_platform_lookup_clone:
 * @self:
 * @lookup:
 * @predicate: if given, only objects for which @predicate returns %TRUE are included
 *   in the result.
 * @user_data: user data for @predicate
 *
 * Returns the result of lookup in a GPtrArray. The result array contains
 * references objects from the cache, its destroy function will unref them.
 *
 * The user must unref the GPtrArray, which will also unref the NMPObject
 * elements.
 *
 * The elements in the array *must* not be modified.
 *
 * Returns: the result of the lookup.
 */
GPtrArray *
nm_platform_lookup_clone(NMPlatform            *self,
                         const NMPLookup       *lookup,
                         NMPObjectPredicateFunc predicate,
                         gpointer               user_data)
{
    return nm_dedup_multi_objs_to_ptr_array_head(nm_platform_lookup(self, lookup),
                                                 (NMDedupMultiFcnSelectPredicate) predicate,
                                                 user_data);
}

gboolean
nm_platform_ip4_address_add(NMPlatform *self,
                            int         ifindex,
                            in_addr_t   address,
                            guint8      plen,
                            in_addr_t   peer_address,
                            in_addr_t   broadcast_address,
                            guint32     lifetime,
                            guint32     preferred,
                            guint32     flags,
                            const char *label)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(plen <= 32, FALSE);
    g_return_val_if_fail(lifetime > 0, FALSE);
    g_return_val_if_fail(preferred <= lifetime, FALSE);
    g_return_val_if_fail(!label || strlen(label) < sizeof(((NMPlatformIP4Address *) NULL)->label),
                         FALSE);

    if (_LOGD_ENABLED()) {
        char                 sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
        NMPlatformIP4Address addr;

        addr = (NMPlatformIP4Address){
            .ifindex           = ifindex,
            .address           = address,
            .peer_address      = peer_address,
            .plen              = plen,
            .timestamp         = 0, /* set it at zero, which to_string will treat as *now* */
            .lifetime          = lifetime,
            .preferred         = preferred,
            .n_ifa_flags       = flags,
            .broadcast_address = broadcast_address,
            .use_ip4_broadcast_address = TRUE,
        };
        if (label)
            g_strlcpy(addr.label, label, sizeof(addr.label));

        _LOG3D("address: adding or updating IPv4 address: %s",
               nm_platform_ip4_address_to_string(&addr, sbuf, sizeof(sbuf)));
    }
    return klass->ip4_address_add(self,
                                  ifindex,
                                  address,
                                  plen,
                                  peer_address,
                                  broadcast_address,
                                  lifetime,
                                  preferred,
                                  flags,
                                  label);
}

gboolean
nm_platform_ip6_address_add(NMPlatform     *self,
                            int             ifindex,
                            struct in6_addr address,
                            guint8          plen,
                            struct in6_addr peer_address,
                            guint32         lifetime,
                            guint32         preferred,
                            guint32         flags)
{
    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(plen <= 128, FALSE);
    g_return_val_if_fail(lifetime > 0, FALSE);
    g_return_val_if_fail(preferred <= lifetime, FALSE);

    if (_LOGD_ENABLED()) {
        char                 sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
        NMPlatformIP6Address addr = {0};

        addr.ifindex      = ifindex;
        addr.address      = address;
        addr.peer_address = peer_address;
        addr.plen         = plen;
        addr.timestamp    = 0; /* set it to zero, which to_string will treat as *now* */
        addr.lifetime     = lifetime;
        addr.preferred    = preferred;
        addr.n_ifa_flags  = flags;

        _LOG3D("address: adding or updating IPv6 address: %s",
               nm_platform_ip6_address_to_string(&addr, sbuf, sizeof(sbuf)));
    }

    nm_platform_ip6_dadfailed_set(self, ifindex, &address, FALSE);

    return klass
        ->ip6_address_add(self, ifindex, address, plen, peer_address, lifetime, preferred, flags);
}

gboolean
nm_platform_ip4_address_delete(NMPlatform *self,
                               int         ifindex,
                               in_addr_t   address,
                               guint8      plen,
                               in_addr_t   peer_address)
{
    char str_dev[30];
    char b1[NM_INET_ADDRSTRLEN];
    char b2[NM_INET_ADDRSTRLEN];
    char str_peer[INET_ADDRSTRLEN + 50];

    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(plen <= 32, FALSE);

    _LOG3D("address: deleting IPv4 address %s/%d, %s%s",
           nm_inet4_ntop(address, b1),
           plen,
           peer_address != address
               ? nm_sprintf_buf(str_peer, "peer %s, ", nm_inet4_ntop(peer_address, b2))
               : "",
           _to_string_dev(str_dev, ifindex));
    return klass->ip4_address_delete(self, ifindex, address, plen, peer_address);
}

gboolean
nm_platform_ip6_address_delete(NMPlatform *self, int ifindex, struct in6_addr address, guint8 plen)
{
    char str_dev[30];
    char sbuf[NM_INET_ADDRSTRLEN];

    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(plen <= 128, FALSE);

    _LOG3D("address: deleting IPv6 address %s/%d, %s",
           nm_inet6_ntop(&address, sbuf),
           plen,
           _to_string_dev(str_dev, ifindex));
    return klass->ip6_address_delete(self, ifindex, address, plen);
}

const NMPObject *
nm_platform_ip_address_get(NMPlatform                                 *self,
                           int                                         addr_family,
                           int                                         ifindex,
                           gconstpointer /* (NMPlatformIPAddress *) */ needle)
{
    const NMPlatformIPXAddress *addr;
    NMPObject                   obj_id;
    const NMPObject            *obj;

    nm_assert(NM_IS_PLATFORM(self));
    nm_assert_addr_family(addr_family);
    nm_assert(needle);

    addr = needle;

    if (ifindex <= 0) {
        /* We allow the caller to override the ifindex. */
        ifindex = addr->ax.ifindex;
    }

    if (NM_IS_IPv4(addr_family)) {
        nmp_object_stackinit_id_ip4_address(&obj_id,
                                            ifindex,
                                            addr->a4.address,
                                            addr->a4.plen,
                                            addr->a4.peer_address);
    } else
        nmp_object_stackinit_id_ip6_address(&obj_id, ifindex, &addr->a6.address);

    obj = nmp_cache_lookup_obj(nm_platform_get_cache(self), &obj_id);
    nm_assert(!obj || nmp_object_is_visible(obj));
    return obj;
}

const NMPlatformIP4Address *
nm_platform_ip4_address_get(NMPlatform *self,
                            int         ifindex,
                            in_addr_t   address,
                            guint8      plen,
                            in_addr_t   peer_address)
{
    NMPObject        obj_id;
    const NMPObject *obj;

    _CHECK_SELF(self, klass, NULL);

    g_return_val_if_fail(plen <= 32, NULL);

    nmp_object_stackinit_id_ip4_address(&obj_id, ifindex, address, plen, peer_address);
    obj = nmp_cache_lookup_obj(nm_platform_get_cache(self), &obj_id);
    nm_assert(!obj || nmp_object_is_visible(obj));
    return NMP_OBJECT_CAST_IP4_ADDRESS(obj);
}

const NMPlatformIP6Address *
nm_platform_ip6_address_get(NMPlatform *self, int ifindex, const struct in6_addr *address)
{
    NMPObject        obj_id;
    const NMPObject *obj;

    _CHECK_SELF(self, klass, NULL);

    nm_assert(address);

    nmp_object_stackinit_id_ip6_address(&obj_id, ifindex, address);
    obj = nmp_cache_lookup_obj(nm_platform_get_cache(self), &obj_id);
    nm_assert(!obj || nmp_object_is_visible(obj));
    return NMP_OBJECT_CAST_IP6_ADDRESS(obj);
}

static gboolean
_addr_array_clean_expired(int          addr_family,
                          int          ifindex,
                          GPtrArray   *array,
                          gint32      *cached_now,
                          GHashTable **idx)
{
    guint    i;
    gboolean any_addrs = FALSE;

    nm_assert_addr_family(addr_family);
    nm_assert(ifindex > 0);
    nm_assert(cached_now);
    nm_assert(*cached_now >= 0);

    if (!array)
        return FALSE;

    /* remove all addresses that are already expired. */
    for (i = 0; i < array->len; i++) {
        const NMPlatformIPAddress *a = NMP_OBJECT_CAST_IP_ADDRESS(array->pdata[i]);

#if NM_MORE_ASSERTS > 10
        nm_assert(a);
        nm_assert(a->ifindex == ifindex);
        {
            const NMPObject *o = NMP_OBJECT_UP_CAST(a);
            guint            j;

            nm_assert(NMP_OBJECT_GET_CLASS(o)->addr_family == addr_family);
            for (j = i + 1; j < array->len; j++) {
                const NMPObject *o2 = array->pdata[j];

                nm_assert(NMP_OBJECT_GET_TYPE(o) == NMP_OBJECT_GET_TYPE(o2));
                nm_assert(!nmp_object_id_equal(o, o2));
            }
        }
#endif

        if (!NM_IS_IPv4(addr_family) && NM_FLAGS_HAS(a->n_ifa_flags, IFA_F_SECONDARY)) {
            /* temporary addresses are never added explicitly by NetworkManager but
             * kernel adds them via mngtempaddr flag.
             *
             * We drop them from this list. */
            goto clear_and_next;
        }

        if (!nmp_utils_lifetime_get(a->timestamp, a->lifetime, a->preferred, cached_now, NULL))
            goto clear_and_next;

        if (G_UNLIKELY(!*idx)) {
            *idx =
                g_hash_table_new((GHashFunc) nmp_object_id_hash, (GEqualFunc) nmp_object_id_equal);
        }
        if (!g_hash_table_add(*idx, (gpointer) NMP_OBJECT_UP_CAST(a)))
            nm_assert_not_reached();

        any_addrs = TRUE;
        continue;

clear_and_next:
        nmp_object_unref(g_steal_pointer(&array->pdata[i]));
    }

    return any_addrs;
}

static gboolean
ip4_addr_subnets_is_plain_address(const GPtrArray *addresses, gconstpointer needle)
{
    return nm_ptr_to_uintptr(needle) >= nm_ptr_to_uintptr(&addresses->pdata[0])
           && nm_ptr_to_uintptr(needle) < nm_ptr_to_uintptr(&addresses->pdata[addresses->len]);
}

static const NMPObject **
ip4_addr_subnets_addr_list_get(const GPtrArray *addr_list, guint idx)
{
    nm_assert(addr_list);
    nm_assert(addr_list->len > 1);
    nm_assert(idx < addr_list->len);
    nm_assert(addr_list->pdata[idx]);
    nm_assert(!(*((gpointer *) addr_list->pdata[idx]))
              || NMP_OBJECT_CAST_IP4_ADDRESS(*((gpointer *) addr_list->pdata[idx])));
    nm_assert(idx == 0 || ip4_addr_subnets_addr_list_get(addr_list, idx - 1));
    return addr_list->pdata[idx];
}

static void
ip4_addr_subnets_destroy_index(GHashTable *subnets, const GPtrArray *addresses)
{
    GHashTableIter iter;
    gpointer       p;

    if (!subnets)
        return;

    g_hash_table_iter_init(&iter, subnets);
    while (g_hash_table_iter_next(&iter, NULL, &p)) {
        if (!ip4_addr_subnets_is_plain_address(addresses, p))
            g_ptr_array_free((GPtrArray *) p, TRUE);
    }

    g_hash_table_unref(subnets);
}

static guint
_ip4_addr_subnets_hash(gconstpointer ptr)
{
    const NMPlatformIP4Address *addr = NMP_OBJECT_CAST_IP4_ADDRESS(ptr);

    return nm_hash_vals(3282159733,
                        addr->plen,
                        nm_ip4_addr_clear_host_address(addr->address, addr->plen));
}

static gboolean
_ip4_addr_subnets_equal(gconstpointer p_a, gconstpointer p_b)
{
    const NMPlatformIP4Address *a = NMP_OBJECT_CAST_IP4_ADDRESS(p_a);
    const NMPlatformIP4Address *b = NMP_OBJECT_CAST_IP4_ADDRESS(p_b);

    return a->plen == b->plen
           && (nm_ip4_addr_clear_host_address(a->address, a->plen)
               == nm_ip4_addr_clear_host_address(b->address, b->plen));
}

static GHashTable *
ip4_addr_subnets_build_index(const GPtrArray *addresses,
                             gboolean         consider_flags,
                             gboolean         full_index)
{
    GHashTable *subnets;
    guint       i;

    nm_assert(addresses && addresses->len);

    subnets = g_hash_table_new(_ip4_addr_subnets_hash, _ip4_addr_subnets_equal);

    /* Build a hash table of all addresses per subnet */
    for (i = 0; i < addresses->len; i++) {
        const NMPObject           **p_obj;
        const NMPObject            *obj;
        const NMPlatformIP4Address *address;
        GPtrArray                  *addr_list;
        int                         position;
        gpointer                    p;

        if (!addresses->pdata[i])
            continue;

        p_obj = (const NMPObject **) &addresses->pdata[i];
        obj   = *p_obj;

        if (!g_hash_table_lookup_extended(subnets, obj, NULL, &p)) {
            g_hash_table_insert(subnets, (gpointer) obj, p_obj);
            continue;
        }
        nm_assert(p);

        address = NMP_OBJECT_CAST_IP4_ADDRESS(obj);

        if (full_index) {
            if (ip4_addr_subnets_is_plain_address(addresses, p)) {
                addr_list = g_ptr_array_new();
                g_hash_table_insert(subnets, (gpointer) obj, addr_list);
                g_ptr_array_add(addr_list, p);
            } else
                addr_list = p;

            if (!consider_flags || NM_FLAGS_HAS(address->n_ifa_flags, IFA_F_SECONDARY))
                position = -1; /* append */
            else
                position = 0; /* prepend */
            g_ptr_array_insert(addr_list, position, p_obj);
        } else {
            /* we only care about the primary. No need to track the secondaries
             * as a GPtrArray. */
            nm_assert(ip4_addr_subnets_is_plain_address(addresses, p));
            if (consider_flags && !NM_FLAGS_HAS(address->n_ifa_flags, IFA_F_SECONDARY)) {
                g_hash_table_insert(subnets, (gpointer) obj, p_obj);
            }
        }
    }

    return subnets;
}

/**
 * ip4_addr_subnets_is_secondary:
 * @address: an address
 * @subnets: the hash table mapping subnets to addresses
 * @addresses: array of addresses in the hash table
 * @out_addr_list: array of addresses belonging to the same subnet
 *
 * Checks whether @address is secondary and returns in @out_addr_list the list of addresses
 * belonging to the same subnet, if it contains other elements.
 *
 * Returns: %TRUE if the address is secondary, %FALSE otherwise
 */
static gboolean
ip4_addr_subnets_is_secondary(const NMPObject  *address,
                              GHashTable       *subnets,
                              const GPtrArray  *addresses,
                              const GPtrArray **out_addr_list)
{
    const GPtrArray  *addr_list;
    gconstpointer     p;
    const NMPObject **o;

    p = g_hash_table_lookup(subnets, address);
    nm_assert(p);
    if (!ip4_addr_subnets_is_plain_address(addresses, p)) {
        addr_list = p;
        nm_assert(addr_list->len > 1);
        NM_SET_OUT(out_addr_list, addr_list);
        o = ip4_addr_subnets_addr_list_get(addr_list, 0);
        nm_assert(o && *o);
        if (*o != address)
            return TRUE;
    } else {
        NM_SET_OUT(out_addr_list, NULL);
        return address != *((gconstpointer *) p);
    }
    return FALSE;
}

typedef enum {
    IP6_ADDR_SCOPE_LOOPBACK,
    IP6_ADDR_SCOPE_LINKLOCAL,
    IP6_ADDR_SCOPE_SITELOCAL,
    IP6_ADDR_SCOPE_OTHER,
} IP6AddrScope;

static IP6AddrScope
ip6_address_scope(const NMPlatformIP6Address *a)
{
    if (IN6_IS_ADDR_LOOPBACK(&a->address))
        return IP6_ADDR_SCOPE_LOOPBACK;
    if (IN6_IS_ADDR_LINKLOCAL(&a->address))
        return IP6_ADDR_SCOPE_LINKLOCAL;
    if (IN6_IS_ADDR_SITELOCAL(&a->address))
        return IP6_ADDR_SCOPE_SITELOCAL;
    return IP6_ADDR_SCOPE_OTHER;
}

static int
ip6_address_scope_cmp_ascending(gconstpointer p_a, gconstpointer p_b, gpointer unused)
{
    NM_CMP_DIRECT(ip6_address_scope(NMP_OBJECT_CAST_IP6_ADDRESS(*(const NMPObject *const *) p_a)),
                  ip6_address_scope(NMP_OBJECT_CAST_IP6_ADDRESS(*(const NMPObject *const *) p_b)));
    return 0;
}

static int
ip6_address_scope_cmp_descending(gconstpointer p_a, gconstpointer p_b, gpointer unused)
{
    return ip6_address_scope_cmp_ascending(p_b, p_a, NULL);
}

/**
 * nm_platform_ip_address_sync:
 * @self: platform instance
 * @addr_family: the address family AF_INET or AF_INET6.
 * @ifindex: Interface index
 * @known_addresses: List of addresses. The list will be modified and
 *   expired addresses will be cleared (by calling nmp_object_unref()
 *   on the array element).
 * @addresses_prune: (allow-none): the list of addresses to delete.
 *   If platform has such an address configured, it will be deleted
 *   at the beginning of the sync. Note that the array will be modified
 *   by the function.
 *   Addresses that are both contained in @known_addresses and @addresses_prune
 *   will be configured.
 * @flags: #NMPIPAddressSyncFlags to affect the sync. If "with-noprefixroute"
 *   flag is set, the method will automatically set IFA_F_NOPREFIXROUTE for
 *   all addresses.
 *
 * A convenience function to synchronize addresses for a specific interface
 * with the least possible disturbance. It simply removes addresses that are
 * not listed and adds addresses that are.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_ip_address_sync(NMPlatform           *self,
                            int                   addr_family,
                            int                   ifindex,
                            GPtrArray            *known_addresses,
                            GPtrArray            *addresses_prune,
                            NMPIPAddressSyncFlags flags)
{
    gint32                         now     = 0;
    const int                      IS_IPv4 = NM_IS_IPv4(addr_family);
    NMPLookup                      lookup;
    const gboolean                 EXTRA_LOGGING        = FALSE;
    gs_unref_hashtable GHashTable *known_addresses_idx  = NULL;
    gs_unref_hashtable GHashTable *plat_addrs_to_delete = NULL;
    gs_unref_ptrarray GPtrArray   *plat_addresses       = NULL;
    gboolean                       success;
    guint                          i_plat;
    guint                          i_know;
    guint                          i;
    guint                          j;

    _CHECK_SELF(self, klass, FALSE);

#define _plat_addrs_to_delete_ensure(ptr)                                    \
    ({                                                                       \
        GHashTable **_ptr = (ptr);                                           \
                                                                             \
        if (!*_ptr) {                                                        \
            *_ptr = g_hash_table_new_full((GHashFunc) nmp_object_id_hash,    \
                                          (GEqualFunc) nmp_object_id_equal,  \
                                          (GDestroyNotify) nmp_object_unref, \
                                          NULL);                             \
        }                                                                    \
        *_ptr;                                                               \
    })

    /* Disabled. Enable this for printf debugging. */
    if (EXTRA_LOGGING) {
        char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
        char sbuf1[50];

        _LOG3T("IPv%c address sync on %d (%u addresses, %u to prune)",
               nm_utils_addr_family_to_char(addr_family),
               ifindex,
               nm_g_ptr_array_len(known_addresses),
               nm_g_ptr_array_len(addresses_prune));
        for (i = 0; known_addresses && i < known_addresses->len; i++) {
            _LOG3T("  address#%u: %s%s",
                   i,
                   nmp_object_to_string(known_addresses->pdata[i],
                                        NMP_OBJECT_TO_STRING_ALL,
                                        sbuf,
                                        sizeof(sbuf)),
                   IS_IPv4 ? ""
                           : nm_sprintf_buf(sbuf1,
                                            " (scope %d)",
                                            (int) ip6_address_scope(NMP_OBJECT_CAST_IP6_ADDRESS(
                                                known_addresses->pdata[i]))));
        }
        for (i = 0; addresses_prune && i < addresses_prune->len; i++) {
            _LOG3T("  prune  #%u: %s",
                   i,
                   nmp_object_to_string(addresses_prune->pdata[i],
                                        NMP_OBJECT_TO_STRING_ALL,
                                        sbuf,
                                        sizeof(sbuf)));
        }
    }

    /* @known_addresses are in decreasing priority order (highest priority addresses first). */

    /* The order we want to enforce is only among addresses with the same
     * scope, as the kernel keeps addresses sorted by scope. Therefore,
     * apply the same sorting to known addresses, so that we don't try to
     * unnecessary change the order of addresses with different scopes. */
    if (!IS_IPv4) {
        if (known_addresses)
            g_ptr_array_sort_with_data(known_addresses, ip6_address_scope_cmp_descending, NULL);
    }

    if (!_addr_array_clean_expired(addr_family,
                                   ifindex,
                                   known_addresses,
                                   &now,
                                   &known_addresses_idx))
        known_addresses = NULL;

    if (nm_g_ptr_array_len(addresses_prune) > 0) {
        /* First delete addresses that we should prune (and which are no longer tracked
         * as @known_addresses. */
        for (i = 0; i < addresses_prune->len; i++) {
            const NMPObject *prune_obj = addresses_prune->pdata[i];

            nm_assert(NM_IN_SET(NMP_OBJECT_GET_TYPE(prune_obj),
                                NMP_OBJECT_TYPE_IP4_ADDRESS,
                                NMP_OBJECT_TYPE_IP6_ADDRESS));

            if (nm_g_hash_table_contains(known_addresses_idx, prune_obj))
                continue;

            nm_platform_ip_address_delete(self,
                                          addr_family,
                                          ifindex,
                                          NMP_OBJECT_CAST_IP_ADDRESS(prune_obj));
        }
    }

    /* ensure we have the platform cache up to date. */
    nm_platform_process_events(self);

    /* @plat_addresses for IPv6 must be sorted in decreasing priority order (highest priority addresses first).
     * IPv4 are probably unsorted or sorted with lowest priority first, but their order doesn't matter because
     * we check the "secondary" flag. */
    plat_addresses = nm_platform_lookup_clone(
        self,
        nmp_lookup_init_object_by_ifindex(&lookup, NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4), ifindex),
        NULL,
        NULL);

    if (EXTRA_LOGGING && plat_addresses) {
        for (i = 0; i < plat_addresses->len; i++) {
            char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
            char sbuf1[50];

            _LOG3T("  platform#%u: %s%s",
                   i,
                   nmp_object_to_string(plat_addresses->pdata[i],
                                        NMP_OBJECT_TO_STRING_ALL,
                                        sbuf,
                                        sizeof(sbuf)),
                   IS_IPv4 ? ""
                           : nm_sprintf_buf(sbuf1,
                                            " (scope %d)",
                                            (int) ip6_address_scope(NMP_OBJECT_CAST_IP6_ADDRESS(
                                                plat_addresses->pdata[i]))));
        }
    }

    if (nm_g_ptr_array_len(plat_addresses) > 0) {
        /* Delete addresses that interfere with our intended order. */
        if (IS_IPv4) {
            GHashTable   *known_subnets = NULL;
            GHashTable   *plat_subnets;
            gs_free bool *plat_handled_to_free = NULL;
            bool         *plat_handled         = NULL;

            /* For IPv4, we only consider it a conflict for addresses in the same
             * subnet. That's where kernel will assign a primary/secondary flag.
             * For different subnets, we don't define the order. */

            plat_subnets = ip4_addr_subnets_build_index(plat_addresses, TRUE, TRUE);

            for (i = 0; i < plat_addresses->len; i++) {
                const NMPObject            *plat_obj = plat_addresses->pdata[i];
                const NMPObject            *known_obj;
                const NMPlatformIP4Address *plat_address;
                const GPtrArray            *addr_list;
                gboolean                    secondary;

                if (plat_handled && plat_handled[i])
                    continue;

                known_obj = nm_g_hash_table_lookup(known_addresses_idx, plat_obj);

                if (!known_obj) {
                    /* this address is added externally. Even if it's presence would mess
                     * with our desired order, we cannot delete it. Skip it. */
                    if (!plat_handled) {
                        plat_handled = nm_malloc0_maybe_a(300,
                                                          sizeof(bool) * plat_addresses->len,
                                                          &plat_handled_to_free);
                    }
                    plat_handled[i] = TRUE;
                    continue;
                }

                if (!known_subnets)
                    known_subnets = ip4_addr_subnets_build_index(known_addresses, FALSE, FALSE);

                plat_address = NMP_OBJECT_CAST_IP4_ADDRESS(plat_obj);

                secondary =
                    ip4_addr_subnets_is_secondary(known_obj, known_subnets, known_addresses, NULL);
                if (secondary == NM_FLAGS_HAS(plat_address->n_ifa_flags, IFA_F_SECONDARY)) {
                    /* if we have an existing known-address, with matching secondary role,
                     * do not delete the platform-address. */
                    continue;
                }

                if (!plat_handled) {
                    plat_handled = nm_malloc0_maybe_a(300,
                                                      sizeof(bool) * plat_addresses->len,
                                                      &plat_handled_to_free);
                }
                plat_handled[i] = TRUE;

                g_hash_table_add(_plat_addrs_to_delete_ensure(&plat_addrs_to_delete),
                                 (gpointer) nmp_object_ref(plat_obj));

                if (!ip4_addr_subnets_is_secondary(plat_obj,
                                                   plat_subnets,
                                                   plat_addresses,
                                                   &addr_list)
                    && addr_list) {
                    /* If we just deleted a primary addresses and there were
                     * secondary ones the kernel can do two things, depending on
                     * version and sysctl setting: delete also secondary addresses
                     * or promote a secondary to primary. Ensure that secondary
                     * addresses are deleted, so that we can start with a clean
                     * slate and add addresses in the right order. */
                    for (j = 1; j < addr_list->len; j++) {
                        const NMPObject **o = ip4_addr_subnets_addr_list_get(addr_list, j);
                        guint             o_idx;

                        o_idx = (o - ((const NMPObject **) &plat_addresses->pdata[0]));

                        nm_assert(o_idx < plat_addresses->len);
                        nm_assert(o == ((const NMPObject **) &plat_addresses->pdata[o_idx]));

                        if (plat_handled[o_idx])
                            continue;

                        plat_handled[o_idx] = TRUE;

                        if (!nm_g_hash_table_contains(known_addresses_idx, *o)) {
                            /* Again, this is an external address. We cannot delete
                             * it to fix the address order. Pass. */
                            continue;
                        }

                        g_hash_table_add(_plat_addrs_to_delete_ensure(&plat_addrs_to_delete),
                                         (gpointer) nmp_object_ref(*o));
                    }
                }
            }
            ip4_addr_subnets_destroy_index(plat_subnets, plat_addresses);
            ip4_addr_subnets_destroy_index(known_subnets, known_addresses);
        } else {
            IP6AddrScope cur_scope;
            gboolean     delete_remaining_addrs;

            /* For IPv6, we only compare addresses per-scope. Addresses in different
             * scopes don't have a defined order. */

            g_ptr_array_sort_with_data(plat_addresses, ip6_address_scope_cmp_descending, NULL);

            /* First, check that existing addresses have a matching plen as the ones
             * we are about to configure (@known_addresses). If not, delete them. */
            for (i_plat = 0; i_plat < plat_addresses->len; i_plat++) {
                const NMPObject *plat_obj = plat_addresses->pdata[i_plat];
                const NMPObject *known_obj;

                known_obj = nm_g_hash_table_lookup(known_addresses_idx, plat_obj);
                if (!known_obj) {
                    /* We don't know this address. It was added externally. Keep it configured.
                     * We also don't want to delete the address below, so mark it as handled
                     * by clearing the pointer. */
                    nm_clear_pointer(&plat_addresses->pdata[i_plat], nmp_object_unref);
                    continue;
                }

                if (NMP_OBJECT_CAST_IP6_ADDRESS(plat_obj)->plen
                    != NMP_OBJECT_CAST_IP6_ADDRESS(known_obj)->plen) {
                    /* technically, plen is not part of the ID for IPv6 addresses and thus
                     * @plat_addr is essentially the same address as @know_addr (w.r.t.
                     * its identity, not its other attributes).
                     * However, we cannot modify an existing addresses' plen without
                     * removing and readding it. Thus, we need to delete plat_addr.
                     *
                     * We don't just add this address to @plat_addrs_to_delete, because
                     * it's too different. Instead, delete and re-add below. */
                    nm_platform_ip_address_delete(self,
                                                  AF_INET6,
                                                  ifindex,
                                                  NMP_OBJECT_CAST_IP6_ADDRESS(plat_obj));
                    /* Mark address as handled. */
                    nm_clear_pointer(&plat_addresses->pdata[i_plat], nmp_object_unref);
                }
            }

            /* Next, we must preserve the priority of the routes. That is, source address
             * selection will choose addresses in the order as they are reported by kernel.
             * Note that the order in @plat_addresses of the remaining matches is highest
             * priority first.
             * We need to compare this to the order of addresses with same scope in
             * @known_addresses (which has lowest priority first).
             *
             * If we find a first discrepancy, we need to delete all remaining addresses
             * for same scope from that point on, because below we must re-add all the
             * addresses in the right order to get their priority right. */
            cur_scope              = IP6_ADDR_SCOPE_LOOPBACK;
            delete_remaining_addrs = FALSE;
            i_plat                 = plat_addresses->len;
            i_know                 = nm_g_ptr_array_len(known_addresses);

            while (i_plat > 0) {
                const NMPObject            *plat_obj  = plat_addresses->pdata[--i_plat];
                const NMPlatformIP6Address *plat_addr = NMP_OBJECT_CAST_IP6_ADDRESS(plat_obj);
                IP6AddrScope                plat_scope;

                if (!plat_addr)
                    continue;

                plat_scope = ip6_address_scope(plat_addr);
                if (cur_scope != plat_scope) {
                    nm_assert(cur_scope < plat_scope);
                    delete_remaining_addrs = FALSE;
                    cur_scope              = plat_scope;
                }

                if (!delete_remaining_addrs) {
                    while (i_know > 0) {
                        const NMPlatformIP6Address *know_addr =
                            NMP_OBJECT_CAST_IP6_ADDRESS(known_addresses->pdata[--i_know]);
                        IP6AddrScope know_scope;

                        if (!know_addr)
                            continue;

                        know_scope = ip6_address_scope(know_addr);
                        if (know_scope < plat_scope)
                            continue;

                        if (IN6_ARE_ADDR_EQUAL(&plat_addr->address, &know_addr->address)) {
                            /* we have a match. Mark address as handled. */
                            goto next_plat;
                        }

                        /* "plat_address" has no match. "delete_remaining_addrs" will be set to TRUE and we will
                         * delete all the remaining addresses with "cur_scope". */
                        break;
                    }
                    delete_remaining_addrs = TRUE;
                }

                g_hash_table_add(_plat_addrs_to_delete_ensure(&plat_addrs_to_delete),
                                 (gpointer) nmp_object_ref(plat_obj));
next_plat:;
            }
        }
    }

    if (!known_addresses)
        return TRUE;

    success = TRUE;

    /* Add missing addresses. New addresses are added by kernel with top
     * priority.
     */
    for (i = 0; i < known_addresses->len; i++) {
        const NMPObject            *plat_obj;
        const NMPObject            *known_obj;
        const NMPlatformIPXAddress *known_address;
        guint32                     lifetime;
        guint32                     preferred;

        /* IPv4 addresses we need to add in the order most important first.
         * IPv6 addresses we need to add in the reverse order with least
         *   important first. Kernel will interpret the last address as most
         *   important.
         *
         * @known_addresses is always in the order most-important-first. */
        i_know = IS_IPv4 ? i : (known_addresses->len - i - 1u);

        known_obj = known_addresses->pdata[i_know];
        if (!known_obj)
            continue;

        nm_assert(NMP_OBJECT_GET_TYPE(known_obj) == NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4));

        known_address = NMP_OBJECT_CAST_IPX_ADDRESS(known_obj);

        lifetime = nmp_utils_lifetime_get(known_address->ax.timestamp,
                                          known_address->ax.lifetime,
                                          known_address->ax.preferred,
                                          &now,
                                          &preferred);
        nm_assert(lifetime > 0);

        plat_obj = nm_platform_ip_address_get(self, addr_family, ifindex, known_address);

        if (plat_obj && nm_g_hash_table_contains(plat_addrs_to_delete, plat_obj)) {
            /* This address exists, but it had the wrong priority earlier. We
             * cannot just update it, we need to remove it first. */
            nm_platform_ip_address_delete(self,
                                          addr_family,
                                          ifindex,
                                          NMP_OBJECT_CAST_IP_ADDRESS(plat_obj));
            plat_obj = NULL;
        }

        if (plat_obj
            && nm_platform_vtable_address.vx[IS_IPv4].address_cmp(
                   known_address,
                   NMP_OBJECT_CAST_IPX_ADDRESS(plat_obj),
                   NM_PLATFORM_IP_ADDRESS_CMP_TYPE_SEMANTICALLY)
                   == 0) {
            char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];

            /* The object is already added. Skip update. */
            _LOG3T(
                "address: skip updating IPv%c address: %s",
                nm_utils_addr_family_to_char(addr_family),
                nmp_object_to_string(known_obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
            continue;
        }

        if (IS_IPv4) {
            if (!nm_platform_ip4_address_add(
                    self,
                    ifindex,
                    known_address->a4.address,
                    known_address->a4.plen,
                    known_address->a4.peer_address,
                    nm_platform_ip4_broadcast_address_from_addr(&known_address->a4),
                    lifetime,
                    preferred,
                    NM_FLAGS_HAS(flags, NMP_IP_ADDRESS_SYNC_FLAGS_WITH_NOPREFIXROUTE)
                        ? IFA_F_NOPREFIXROUTE
                        : 0,
                    known_address->a4.label))
                success = FALSE;
        } else {
            if (!nm_platform_ip6_address_add(
                    self,
                    ifindex,
                    known_address->a6.address,
                    known_address->a6.plen,
                    known_address->a6.peer_address,
                    lifetime,
                    preferred,
                    (NM_FLAGS_HAS(flags, NMP_IP_ADDRESS_SYNC_FLAGS_WITH_NOPREFIXROUTE)
                         ? IFA_F_NOPREFIXROUTE
                         : 0)
                        | known_address->a6.n_ifa_flags))
                success = FALSE;
        }
    }

    return success;
}

gboolean
nm_platform_ip_address_flush(NMPlatform *self, int addr_family, int ifindex)
{
    gboolean success = TRUE;
    int      IS_IPv4;

    _CHECK_SELF(self, klass, FALSE);

    nm_assert_addr_family_or_unspec(addr_family);

    for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
        gs_unref_ptrarray GPtrArray *addresses_prune = NULL;
        const int                    addr_family2    = IS_IPv4 ? AF_INET : AF_INET6;

        if (!NM_IN_SET(addr_family, AF_UNSPEC, addr_family2))
            continue;

        addresses_prune =
            nm_platform_ip_address_get_prune_list(self, addr_family2, ifindex, NULL, 0);

        if (!nm_platform_ip_address_sync(self,
                                         addr_family2,
                                         ifindex,
                                         NULL,
                                         addresses_prune,
                                         NMP_IP_ADDRESS_SYNC_FLAGS_NONE))
            success = FALSE;
    }
    return success;
}

/*****************************************************************************/

static gboolean
_err_inval_due_to_ipv6_tentative_pref_src(NMPlatform *self, const NMPObject *obj)
{
    const NMPlatformIP6Route   *r;
    const NMPlatformIP6Address *a;

    nm_assert(NM_IS_PLATFORM(self));
    nm_assert(NMP_OBJECT_IS_VALID(obj));

    /* trying to add an IPv6 route with pref-src fails, if the address is
     * still tentative (rh#1452684). We need to hack around that.
     *
     * Detect it, by guessing whether that's the case. */

    if (NMP_OBJECT_GET_TYPE(obj) != NMP_OBJECT_TYPE_IP6_ROUTE)
        return FALSE;

    r = NMP_OBJECT_CAST_IP6_ROUTE(obj);

    /* we only allow this workaround for routes added manually by the user. */
    if (r->rt_source != NM_IP_CONFIG_SOURCE_USER)
        return FALSE;

    if (IN6_IS_ADDR_UNSPECIFIED(&r->pref_src))
        return FALSE;

    a = nm_platform_ip6_address_get(self, r->ifindex, &r->pref_src);
    if (!a)
        return FALSE;
    if (!NM_FLAGS_HAS(a->n_ifa_flags, IFA_F_TENTATIVE)
        || NM_FLAGS_HAS(a->n_ifa_flags, IFA_F_DADFAILED))
        return FALSE;

    return TRUE;
}

static guint
_ipv6_temporary_addr_prefixes_keep_hash(gconstpointer ptr)
{
    return nm_hash_mem(1161670183u, ptr, 8);
}

static gboolean
_ipv6_temporary_addr_prefixes_keep_equal(gconstpointer ptr_a, gconstpointer ptr_b)
{
    return !memcmp(ptr_a, ptr_b, 8);
}

GPtrArray *
nm_platform_ip_address_get_prune_list(NMPlatform            *self,
                                      int                    addr_family,
                                      int                    ifindex,
                                      const struct in6_addr *ipv6_temporary_addr_prefixes_keep,
                                      guint                  ipv6_temporary_addr_prefixes_keep_len)
{
    gs_unref_hashtable GHashTable *ipv6_temporary_addr_prefixes_keep_idx = NULL;
    const int                      IS_IPv4                               = NM_IS_IPv4(addr_family);
    const NMDedupMultiHeadEntry   *head_entry;
    NMPLookup                      lookup;
    GPtrArray                     *result = NULL;
    CList                         *iter;

    nmp_lookup_init_object_by_ifindex(&lookup,
                                      NMP_OBJECT_TYPE_IP_ADDRESS(NM_IS_IPv4(addr_family)),
                                      ifindex);

    head_entry = nm_platform_lookup(self, &lookup);

    if (!head_entry)
        return NULL;

    c_list_for_each (iter, &head_entry->lst_entries_head) {
        const NMPObject *obj = c_list_entry(iter, NMDedupMultiEntry, lst_entries)->obj;

        if (IS_IPv4) {
            const NMPlatformIP4Address *a4 = NMP_OBJECT_CAST_IP4_ADDRESS(obj);

            if (a4->address == NM_IPV4LO_ADDR1 && a4->plen == NM_IPV4LO_PREFIXLEN) {
                const NMPlatformIP4Address addr = (NMPlatformIP4Address){
                    .ifindex                   = NM_LOOPBACK_IFINDEX,
                    .address                   = NM_IPV4LO_ADDR1,
                    .peer_address              = NM_IPV4LO_ADDR1,
                    .plen                      = NM_IPV4LO_PREFIXLEN,
                    .use_ip4_broadcast_address = TRUE,
                };

                if (nm_platform_ip4_address_cmp(a4,
                                                &addr,
                                                NM_PLATFORM_IP_ADDRESS_CMP_TYPE_SEMANTICALLY)
                    == 0) {
                    continue;
                }
            }
        } else {
            const NMPlatformIP6Address *a6 = NMP_OBJECT_CAST_IP6_ADDRESS(obj);

            if (NM_FLAGS_HAS(a6->n_ifa_flags, IFA_F_SECONDARY)
                && ipv6_temporary_addr_prefixes_keep_len > 0 && a6->plen == 64) {
                gboolean keep = FALSE;
                guint    i;

                if (ipv6_temporary_addr_prefixes_keep_len < 10) {
                    for (i = 0; i < ipv6_temporary_addr_prefixes_keep_len; i++) {
                        if (memcmp(&ipv6_temporary_addr_prefixes_keep[i], &a6->address, 8) == 0) {
                            keep = TRUE;
                            break;
                        }
                    }
                } else {
                    /* We have a larger number of addresses. We want that our functions are O(n),
                     * so build a lookup index. */
                    if (!ipv6_temporary_addr_prefixes_keep_idx) {
                        ipv6_temporary_addr_prefixes_keep_idx =
                            g_hash_table_new(_ipv6_temporary_addr_prefixes_keep_hash,
                                             _ipv6_temporary_addr_prefixes_keep_equal);
                        for (i = 0; i < ipv6_temporary_addr_prefixes_keep_len; i++) {
                            g_hash_table_add(ipv6_temporary_addr_prefixes_keep_idx,
                                             (gpointer) &ipv6_temporary_addr_prefixes_keep[i]);
                        }
                    }
                    if (g_hash_table_contains(ipv6_temporary_addr_prefixes_keep_idx, &a6->address))
                        keep = TRUE;
                }
                if (keep) {
                    /* This IPv6 temporary address has a prefix that we want to keep. */
                    continue;
                }
            }
        }

        if (!result)
            result = g_ptr_array_new_full(head_entry->len, (GDestroyNotify) nmp_object_unref);

        g_ptr_array_add(result, (gpointer) nmp_object_ref(obj));
    }

    return result;
}

GPtrArray *
nm_platform_ip_route_get_prune_list(NMPlatform            *self,
                                    int                    addr_family,
                                    int                    ifindex,
                                    NMIPRouteTableSyncMode route_table_sync)
{
    NMPLookup                    lookup;
    GPtrArray                   *routes_prune = NULL;
    const NMDedupMultiHeadEntry *head_entry;
    CList                       *iter;
    const NMPlatformLink        *pllink;
    const NMPlatformLnkVrf      *lnk_vrf;
    guint32                      local_table;

    nm_assert(NM_IS_PLATFORM(self));
    nm_assert(NM_IN_SET(addr_family, AF_INET, AF_INET6));
    nm_assert(NM_IN_SET(route_table_sync,
                        NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN,
                        NM_IP_ROUTE_TABLE_SYNC_MODE_FULL,
                        NM_IP_ROUTE_TABLE_SYNC_MODE_ALL,
                        NM_IP_ROUTE_TABLE_SYNC_MODE_ALL_PRUNE));

    nmp_lookup_init_object_by_ifindex(&lookup,
                                      NMP_OBJECT_TYPE_IP_ROUTE(NM_IS_IPv4(addr_family)),
                                      ifindex);
    head_entry = nm_platform_lookup(self, &lookup);
    if (!head_entry)
        return NULL;

    lnk_vrf = nm_platform_link_get_lnk_vrf(self, ifindex, &pllink);
    if (!lnk_vrf && pllink && pllink->master > 0)
        lnk_vrf = nm_platform_link_get_lnk_vrf(self, pllink->master, NULL);
    local_table = lnk_vrf ? lnk_vrf->table : RT_TABLE_LOCAL;

    c_list_for_each (iter, &head_entry->lst_entries_head) {
        const NMPObject          *obj = c_list_entry(iter, NMDedupMultiEntry, lst_entries)->obj;
        const NMPlatformIPXRoute *rt  = NMP_OBJECT_CAST_IPX_ROUTE(obj);

        switch (route_table_sync) {
        case NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN:
            if (!nm_platform_route_table_is_main(nm_platform_ip_route_get_effective_table(&rt->rx)))
                continue;
            break;
        case NM_IP_ROUTE_TABLE_SYNC_MODE_FULL:
            if (nm_platform_ip_route_get_effective_table(&rt->rx) == RT_TABLE_LOCAL)
                continue;
            break;
        case NM_IP_ROUTE_TABLE_SYNC_MODE_ALL:

            /* FIXME: we should better handle routes that are automatically added by kernel.
             *
             * For now, make a good guess which are those routes and exclude them from
             * pruning them. */

            if (NM_IS_IPv4(addr_family)) {
                if (ifindex == NM_LOOPBACK_IFINDEX
                    && NM_IN_SET(rt->r4.network, NM_IPV4LO_ADDR1, NM_IPV4LO_NETWORK)) {
                    NMPlatformIP4Route r;

                    if (rt->r4.network == NM_IPV4LO_ADDR1) {
                        r = (NMPlatformIP4Route){
                            .ifindex       = NM_LOOPBACK_IFINDEX,
                            .type_coerced  = nm_platform_route_type_coerce(RTN_LOCAL),
                            .table_coerced = nm_platform_route_table_coerce(local_table),
                            .network       = NM_IPV4LO_ADDR1,
                            .plen          = 32,
                            .metric        = 0,
                            .rt_source     = NM_IPV4LO_ADDR1,
                            .scope_inv     = nm_platform_route_scope_inv(RT_SCOPE_HOST),
                            .pref_src      = NM_IPV4LO_ADDR1,
                        };
                    } else {
                        r = (NMPlatformIP4Route){
                            .ifindex       = NM_LOOPBACK_IFINDEX,
                            .type_coerced  = nm_platform_route_type_coerce(RTN_LOCAL),
                            .table_coerced = nm_platform_route_table_coerce(local_table),
                            .network       = NM_IPV4LO_NETWORK,
                            .plen          = NM_IPV4LO_PREFIXLEN,
                            .metric        = 0,
                            .rt_source     = NM_IPV4LO_ADDR1,
                            .scope_inv     = nm_platform_route_scope_inv(RT_SCOPE_HOST),
                            .pref_src      = NM_IPV4LO_ADDR1,
                        };
                    }

                    if (nm_platform_ip4_route_cmp(&rt->r4,
                                                  &r,
                                                  NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
                        == 0) {
                        continue;
                    }
                }

                /* for each IPv4 address kernel adds a route like
                 *
                 *  local $ADDR dev $IFACE table local proto kernel scope host src $PRIMARY_ADDR
                 *
                 * Check whether route could be of that kind. */
                if (nm_platform_ip_route_get_effective_table(&rt->rx) == local_table
                    && rt->rx.plen == 32 && rt->rx.rt_source == NM_IP_CONFIG_SOURCE_RTPROT_KERNEL
                    && rt->rx.metric == 0
                    && rt->r4.scope_inv == nm_platform_route_scope_inv(RT_SCOPE_HOST)
                    && rt->r4.gateway == INADDR_ANY) {
                    const NMPlatformIP4Route r = {
                        .ifindex       = ifindex,
                        .type_coerced  = nm_platform_route_type_coerce(RTN_LOCAL),
                        .plen          = 32,
                        .rt_source     = NM_IP_CONFIG_SOURCE_RTPROT_KERNEL,
                        .metric        = 0,
                        .table_coerced = nm_platform_route_table_coerce(local_table),
                        .scope_inv     = nm_platform_route_scope_inv(RT_SCOPE_HOST),
                        .gateway       = INADDR_ANY,
                        /* the possible "network" depends on the addresses we have. We don't check that
                         * carefully. If the other parameters match, we assume that this route is the one
                         * generated by kernel. */
                        .network  = rt->r4.network,
                        .pref_src = rt->r4.pref_src,
                    };

                    /* to be more confident about comparing the value, use our nm_platform_ip4_route_cmp()
                     * implementation. That will also consider parameters that we leave unspecified here. */
                    if (nm_platform_ip4_route_cmp(&rt->r4,
                                                  &r,
                                                  NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
                        == 0)
                        continue;
                }
            } else {
                /* for each IPv6 address (that is no longer tentative) kernel adds a route like
                 *
                 *  local $ADDR dev $IFACE table local proto kernel metric 0 pref medium
                 *
                 * Same as for the IPv4 case. */
                if (nm_platform_ip_route_get_effective_table(&rt->rx) == local_table
                    && rt->rx.plen == 128 && rt->rx.rt_source == NM_IP_CONFIG_SOURCE_RTPROT_KERNEL
                    && rt->rx.metric == 0 && rt->r6.rt_pref == NM_ICMPV6_ROUTER_PREF_MEDIUM
                    && IN6_IS_ADDR_UNSPECIFIED(&rt->r6.gateway)) {
                    const NMPlatformIP6Route r = {
                        .ifindex       = ifindex,
                        .type_coerced  = nm_platform_route_type_coerce(RTN_LOCAL),
                        .plen          = 128,
                        .rt_source     = NM_IP_CONFIG_SOURCE_RTPROT_KERNEL,
                        .metric        = 0,
                        .table_coerced = nm_platform_route_table_coerce(local_table),
                        .rt_pref       = NM_ICMPV6_ROUTER_PREF_MEDIUM,
                        .gateway       = IN6ADDR_ANY_INIT,
                        .network       = rt->r6.network,
                    };

                    if (nm_platform_ip6_route_cmp(&rt->r6,
                                                  &r,
                                                  NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
                        == 0)
                        continue;
                }

                /* Kernels < 5.11 add a route like:
                 *
                 * unicast ff00::/8 dev $IFACE proto boot scope global metric 256 pref medium
                 *
                 * to allow sending and receiving IPv6 multicast traffic. Don't remove it.
                 * Since kernel 5.11 the route looks like:
                 *
                 * multicast ff00::/8 dev $IFACE proto kernel metric 256 pref medium
                 *
                 * As NM ignores routes with rtm_type multicast, there is no need for the code
                 * below on newer kernels.
                 */
                if (nm_platform_ip_route_get_effective_table(&rt->rx) == local_table
                    && rt->rx.plen == 8 && rt->rx.rt_source == NM_IP_CONFIG_SOURCE_RTPROT_BOOT
                    && rt->rx.metric == 256 && rt->r6.rt_pref == NM_ICMPV6_ROUTER_PREF_MEDIUM
                    && IN6_IS_ADDR_UNSPECIFIED(&rt->r6.gateway)) {
                    const NMPlatformIP6Route r = {
                        .ifindex       = ifindex,
                        .type_coerced  = nm_platform_route_type_coerce(RTN_UNICAST),
                        .plen          = 8,
                        .rt_source     = NM_IP_CONFIG_SOURCE_RTPROT_BOOT,
                        .metric        = 256,
                        .table_coerced = nm_platform_route_table_coerce(local_table),
                        .rt_pref       = NM_ICMPV6_ROUTER_PREF_MEDIUM,
                        .gateway       = IN6ADDR_ANY_INIT,
                        .network =
                            NM_IN6ADDR_INIT(0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                    };

                    if (nm_platform_ip6_route_cmp(&rt->r6,
                                                  &r,
                                                  NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
                        == 0)
                        continue;
                }
            }
            break;

        case NM_IP_ROUTE_TABLE_SYNC_MODE_ALL_PRUNE:
            break;

        default:
            nm_assert_not_reached();
            break;
        }

        if (!routes_prune) {
            routes_prune =
                g_ptr_array_new_full(head_entry->len, (GDestroyNotify) nm_dedup_multi_obj_unref);
        }

        g_ptr_array_add(routes_prune, (gpointer) nmp_object_ref(obj));
    }

    return routes_prune;
}

/**
 * nm_platform_ip_route_sync:
 * @self: the #NMPlatform instance.
 * @addr_family: AF_INET or AF_INET6.
 * @ifindex: the @ifindex for which the routes are to be added.
 * @routes: (allow-none): a list of routes to configure. Must contain
 *   NMPObject instances of routes, according to @addr_family.
 * @routes_prune: (allow-none): the list of routes to delete.
 *   If platform has such a route configured, it will be deleted
 *   at the end of the operation. Note that if @routes contains
 *   the same route, then it will not be deleted. @routes overrules
 *   @routes_prune list.
 * @out_temporary_not_available: (allow-none) (out): routes that could
 *   currently not be synced. The caller shall keep them and try later again.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_ip_route_sync(NMPlatform *self,
                          int         addr_family,
                          int         ifindex,
                          GPtrArray  *routes,
                          GPtrArray  *routes_prune,
                          GPtrArray **out_temporary_not_available)
{
    const int                      IS_IPv4 = NM_IS_IPv4(addr_family);
    const NMPlatformVTableRoute   *vt;
    gs_unref_hashtable GHashTable *routes_idx = NULL;
    const NMPObject               *conf_o;
    const NMDedupMultiEntry       *plat_entry;
    guint                          i;
    int                            i_type;
    gboolean                       success = TRUE;
    char                           sbuf1[NM_UTILS_TO_STRING_BUFFER_SIZE];
    char                           sbuf2[NM_UTILS_TO_STRING_BUFFER_SIZE];

    nm_assert(NM_IS_PLATFORM(self));
    nm_assert(ifindex > 0);

    vt = &nm_platform_vtable_route.vx[IS_IPv4];

    for (i_type = 0; routes && i_type < 2; i_type++) {
        for (i = 0; i < routes->len; i++) {
            int      r, r2;
            gboolean gateway_route_added = FALSE;

            conf_o = routes->pdata[i];

            /* User space cannot add IPv6 routes with metric 0. However, kernel can, and we might track such
             * routes in @route as they are present external. As we already skipped external routes above,
             * we don't expect a user's choice to add such a route (it won't work anyway). */
            nm_assert(
                IS_IPv4
                || nm_platform_ip6_route_get_effective_metric(NMP_OBJECT_CAST_IP6_ROUTE(conf_o))
                       != 0);

#define VTABLE_IS_DEVICE_ROUTE(vt, o)                          \
    (vt->is_ip4 ? (NMP_OBJECT_CAST_IP4_ROUTE(o)->gateway == 0) \
                : IN6_IS_ADDR_UNSPECIFIED(&NMP_OBJECT_CAST_IP6_ROUTE(o)->gateway))

            if ((i_type == 0 && !VTABLE_IS_DEVICE_ROUTE(vt, conf_o))
                || (i_type == 1 && VTABLE_IS_DEVICE_ROUTE(vt, conf_o))) {
                /* we add routes in two runs over @i_type.
                 *
                 * First device routes, then gateway routes. */
                continue;
            }

            if (!routes_idx) {
                routes_idx = g_hash_table_new((GHashFunc) nmp_object_id_hash,
                                              (GEqualFunc) nmp_object_id_equal);
            }
            if (!g_hash_table_add(routes_idx, (gpointer) conf_o)) {
                _LOG3D("route-sync: skip adding duplicate route %s",
                       nmp_object_to_string(conf_o,
                                            NMP_OBJECT_TO_STRING_PUBLIC,
                                            sbuf1,
                                            sizeof(sbuf1)));
                continue;
            }

            plat_entry = nm_platform_lookup_entry(self, NMP_CACHE_ID_TYPE_OBJECT_TYPE, conf_o);
            if (plat_entry) {
                const NMPObject *plat_o;

                plat_o = plat_entry->obj;

                if (vt->route_cmp(NMP_OBJECT_CAST_IPX_ROUTE(conf_o),
                                  NMP_OBJECT_CAST_IPX_ROUTE(plat_o),
                                  NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
                    == 0)
                    continue;

                /* we need to replace the existing route with a (slightly) different
                 * one. Delete it first. */
                if (!nm_platform_object_delete(self, plat_o)) {
                    /* ignore error. */
                }
            }

sync_route_add:
            r = nm_platform_ip_route_add(self,
                                         NMP_NLM_FLAG_APPEND
                                             | NMP_NLM_FLAG_SUPPRESS_NETLINK_FAILURE,
                                         conf_o);
            if (r < 0) {
                if (r == -EEXIST) {
                    /* Don't fail for EEXIST. It's not clear that the existing route
                     * is identical to the one that we were about to add. However,
                     * above we should have deleted conflicting (non-identical) routes. */
                    if (_LOGD_ENABLED()) {
                        plat_entry =
                            nm_platform_lookup_entry(self, NMP_CACHE_ID_TYPE_OBJECT_TYPE, conf_o);
                        if (!plat_entry) {
                            _LOG3D("route-sync: adding route %s failed with EEXIST, however we "
                                   "cannot find such a route",
                                   nmp_object_to_string(conf_o,
                                                        NMP_OBJECT_TO_STRING_PUBLIC,
                                                        sbuf1,
                                                        sizeof(sbuf1)));
                        } else if (vt->route_cmp(NMP_OBJECT_CAST_IPX_ROUTE(conf_o),
                                                 NMP_OBJECT_CAST_IPX_ROUTE(plat_entry->obj),
                                                 NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
                                   != 0) {
                            _LOG3D("route-sync: adding route %s failed due to existing "
                                   "(different!) route %s",
                                   nmp_object_to_string(conf_o,
                                                        NMP_OBJECT_TO_STRING_PUBLIC,
                                                        sbuf1,
                                                        sizeof(sbuf1)),
                                   nmp_object_to_string(plat_entry->obj,
                                                        NMP_OBJECT_TO_STRING_PUBLIC,
                                                        sbuf2,
                                                        sizeof(sbuf2)));
                        }
                    }
                } else if (NMP_OBJECT_CAST_IP_ROUTE(conf_o)->rt_source < NM_IP_CONFIG_SOURCE_USER) {
                    _LOG3D("route-sync: ignore failure to add IPv%c route: %s: %s",
                           vt->is_ip4 ? '4' : '6',
                           nmp_object_to_string(conf_o,
                                                NMP_OBJECT_TO_STRING_PUBLIC,
                                                sbuf1,
                                                sizeof(sbuf1)),
                           nm_strerror(r));
                } else if (r == -EINVAL && out_temporary_not_available
                           && _err_inval_due_to_ipv6_tentative_pref_src(self, conf_o)) {
                    _LOG3D("route-sync: ignore failure to add IPv6 route with tentative IPv6 "
                           "pref-src: %s: %s",
                           nmp_object_to_string(conf_o,
                                                NMP_OBJECT_TO_STRING_PUBLIC,
                                                sbuf1,
                                                sizeof(sbuf1)),
                           nm_strerror(r));
                    if (!*out_temporary_not_available)
                        *out_temporary_not_available =
                            g_ptr_array_new_full(0, (GDestroyNotify) nmp_object_unref);
                    g_ptr_array_add(*out_temporary_not_available,
                                    (gpointer) nmp_object_ref(conf_o));
                } else if (!gateway_route_added
                           && ((r == -ENETUNREACH && vt->is_ip4
                                && !!NMP_OBJECT_CAST_IP4_ROUTE(conf_o)->gateway)
                               || (r == -EHOSTUNREACH && !vt->is_ip4
                                   && !IN6_IS_ADDR_UNSPECIFIED(
                                       &NMP_OBJECT_CAST_IP6_ROUTE(conf_o)->gateway)))) {
                    NMPObject oo;

                    if (vt->is_ip4) {
                        const NMPlatformIP4Route *rt = NMP_OBJECT_CAST_IP4_ROUTE(conf_o);

                        nmp_object_stackinit(
                            &oo,
                            NMP_OBJECT_TYPE_IP4_ROUTE,
                            &((NMPlatformIP4Route){
                                .ifindex       = rt->ifindex,
                                .network       = rt->gateway,
                                .plen          = 32,
                                .metric        = nm_platform_ip4_route_get_effective_metric(rt),
                                .rt_source     = rt->rt_source,
                                .table_coerced = nm_platform_ip_route_get_effective_table(
                                    NM_PLATFORM_IP_ROUTE_CAST(rt)),
                            }));
                    } else {
                        const NMPlatformIP6Route *rt = NMP_OBJECT_CAST_IP6_ROUTE(conf_o);

                        nmp_object_stackinit(
                            &oo,
                            NMP_OBJECT_TYPE_IP6_ROUTE,
                            &((NMPlatformIP6Route){
                                .ifindex       = rt->ifindex,
                                .network       = rt->gateway,
                                .plen          = 128,
                                .metric        = nm_platform_ip6_route_get_effective_metric(rt),
                                .rt_source     = rt->rt_source,
                                .table_coerced = nm_platform_ip_route_get_effective_table(
                                    NM_PLATFORM_IP_ROUTE_CAST(rt)),
                            }));
                    }

                    _LOG3D("route-sync: failure to add IPv%c route: %s: %s; try adding direct "
                           "route to gateway %s",
                           vt->is_ip4 ? '4' : '6',
                           nmp_object_to_string(conf_o,
                                                NMP_OBJECT_TO_STRING_PUBLIC,
                                                sbuf1,
                                                sizeof(sbuf1)),
                           nm_strerror(r),
                           nmp_object_to_string(&oo,
                                                NMP_OBJECT_TO_STRING_PUBLIC,
                                                sbuf2,
                                                sizeof(sbuf2)));

                    r2 = nm_platform_ip_route_add(self,
                                                  NMP_NLM_FLAG_APPEND
                                                      | NMP_NLM_FLAG_SUPPRESS_NETLINK_FAILURE,
                                                  &oo);

                    if (r2 < 0) {
                        _LOG3D("route-sync: failure to add gateway IPv%c route: %s: %s",
                               vt->is_ip4 ? '4' : '6',
                               nmp_object_to_string(conf_o,
                                                    NMP_OBJECT_TO_STRING_PUBLIC,
                                                    sbuf1,
                                                    sizeof(sbuf1)),
                               nm_strerror(r2));
                    }

                    gateway_route_added = TRUE;
                    goto sync_route_add;
                } else {
                    _LOG3W("route-sync: failure to add IPv%c route: %s: %s",
                           vt->is_ip4 ? '4' : '6',
                           nmp_object_to_string(conf_o,
                                                NMP_OBJECT_TO_STRING_PUBLIC,
                                                sbuf1,
                                                sizeof(sbuf1)),
                           nm_strerror(r));
                    success = FALSE;
                }
            }
        }
    }

    if (routes_prune) {
        for (i = 0; i < routes_prune->len; i++) {
            const NMPObject *prune_o;

            prune_o = routes_prune->pdata[i];

            nm_assert((NM_IS_IPv4(addr_family)
                       && NMP_OBJECT_GET_TYPE(prune_o) == NMP_OBJECT_TYPE_IP4_ROUTE)
                      || (!NM_IS_IPv4(addr_family)
                          && NMP_OBJECT_GET_TYPE(prune_o) == NMP_OBJECT_TYPE_IP6_ROUTE));

            if (nm_g_hash_table_lookup(routes_idx, prune_o))
                continue;

            if (!nm_platform_lookup_entry(self, NMP_CACHE_ID_TYPE_OBJECT_TYPE, prune_o))
                continue;

            if (!nm_platform_object_delete(self, prune_o)) {
                /* ignore error... */
            }
        }
    }

    return success;
}

gboolean
nm_platform_ip_route_flush(NMPlatform *self, int addr_family, int ifindex)
{
    gboolean success = TRUE;

    _CHECK_SELF(self, klass, FALSE);

    nm_assert(NM_IN_SET(addr_family, AF_UNSPEC, AF_INET, AF_INET6));

    if (NM_IN_SET(addr_family, AF_UNSPEC, AF_INET)) {
        gs_unref_ptrarray GPtrArray *routes_prune = NULL;

        routes_prune = nm_platform_ip_route_get_prune_list(self,
                                                           AF_INET,
                                                           ifindex,
                                                           NM_IP_ROUTE_TABLE_SYNC_MODE_ALL_PRUNE);
        success &= nm_platform_ip_route_sync(self, AF_INET, ifindex, NULL, routes_prune, NULL);
    }
    if (NM_IN_SET(addr_family, AF_UNSPEC, AF_INET6)) {
        gs_unref_ptrarray GPtrArray *routes_prune = NULL;

        routes_prune = nm_platform_ip_route_get_prune_list(self,
                                                           AF_INET6,
                                                           ifindex,
                                                           NM_IP_ROUTE_TABLE_SYNC_MODE_ALL_PRUNE);
        success &= nm_platform_ip_route_sync(self, AF_INET6, ifindex, NULL, routes_prune, NULL);
    }
    return success;
}

/*****************************************************************************/

static guint8
_ip_route_scope_inv_get_normalized(const NMPlatformIP4Route *route)
{
    /* in kernel, you cannot set scope to RT_SCOPE_NOWHERE (255).
     * That means, in NM, we treat RT_SCOPE_NOWHERE as unset, and detect
     * it based on the presence of the gateway. In other words, when adding
     * a route with scope RT_SCOPE_NOWHERE (in NetworkManager) to kernel,
     * the resulting scope will be either "link" or "universe" (depending
     * on the gateway).
     *
     * Note that internally, we track @scope_inv is the inverse of scope,
     * so that the default equals zero (~(RT_SCOPE_NOWHERE)).
     **/
    if (route->scope_inv == 0) {
        if (route->type_coerced == nm_platform_route_type_coerce(RTN_LOCAL))
            return nm_platform_route_scope_inv(RT_SCOPE_HOST);
        else {
            return nm_platform_route_scope_inv(!route->gateway ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSE);
        }
    }
    return route->scope_inv;
}

static guint8
_route_pref_normalize(guint8 pref)
{
    /* for kernel (and ICMPv6) pref can only have one of 3 values. Normalize. */
    return NM_IN_SET(pref, NM_ICMPV6_ROUTER_PREF_LOW, NM_ICMPV6_ROUTER_PREF_HIGH)
               ? pref
               : NM_ICMPV6_ROUTER_PREF_MEDIUM;
}

/**
 * nm_platform_ip_route_normalize:
 * @addr_family: AF_INET or AF_INET6
 * @route: an NMPlatformIP4Route or NMPlatformIP6Route instance, depending on @addr_family.
 *
 * Adding a route to kernel via nm_platform_ip_route_add() will normalize/coerce some
 * properties of the route. This function modifies (normalizes) the route like it
 * would be done by adding the route in kernel.
 *
 * Note that this function is related to NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY
 * in that if two routes compare semantically equal, after normalizing they also shall
 * compare equal with NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL.
 */
void
nm_platform_ip_route_normalize(int addr_family, NMPlatformIPRoute *route)
{
    NMPlatformIP4Route *r4;
    NMPlatformIP6Route *r6;

    route->table_coerced =
        nm_platform_route_table_coerce(nm_platform_ip_route_get_effective_table(route));
    route->table_any = FALSE;

    route->rt_source = nmp_utils_ip_config_source_round_trip_rtprot(route->rt_source);

    switch (addr_family) {
    case AF_INET:
        r4                = (NMPlatformIP4Route *) route;
        route->metric     = nm_platform_ip4_route_get_effective_metric(r4);
        route->metric_any = FALSE;
        r4->network       = nm_ip4_addr_clear_host_address(r4->network, r4->plen);
        r4->scope_inv     = _ip_route_scope_inv_get_normalized(r4);
        break;
    case AF_INET6:
        r6                = (NMPlatformIP6Route *) route;
        route->metric     = nm_platform_ip6_route_get_effective_metric(r6);
        route->metric_any = FALSE;
        nm_ip6_addr_clear_host_address(&r6->network, &r6->network, r6->plen);
        nm_ip6_addr_clear_host_address(&r6->src, &r6->src, r6->src_plen);
        break;
    default:
        nm_assert_not_reached();
        break;
    }
}

static int
_ip_route_add(NMPlatform *self, NMPNlmFlags flags, NMPObject *obj_stack)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    int  ifindex;

    _CHECK_SELF(self, klass, FALSE);

    /* The caller already ensures that this is a stack allocated copy, that
     * - stays alive for the duration of the call.
     * - that the ip_route_add() implementation is allowed to modify.
     */
    nm_assert(obj_stack);
    nm_assert(NMP_OBJECT_IS_STACKINIT(obj_stack));
    nm_assert(NM_IN_SET(NMP_OBJECT_GET_TYPE(obj_stack),
                        NMP_OBJECT_TYPE_IP4_ROUTE,
                        NMP_OBJECT_TYPE_IP6_ROUTE));

    nm_assert(NMP_OBJECT_GET_TYPE(obj_stack) != NMP_OBJECT_TYPE_IP4_ROUTE
              || obj_stack->ip4_route.n_nexthops <= 1u || obj_stack->_ip4_route.extra_nexthops);

    nm_platform_ip_route_normalize(NMP_OBJECT_GET_ADDR_FAMILY((obj_stack)),
                                   NMP_OBJECT_CAST_IP_ROUTE(obj_stack));

    ifindex = obj_stack->ip_route.ifindex;

    _LOG3D("route: %-10s IPv%c route: %s",
           _nmp_nlm_flag_to_string(flags & NMP_NLM_FLAG_FMASK),
           nm_utils_addr_family_to_char(NMP_OBJECT_GET_ADDR_FAMILY(obj_stack)),
           nmp_object_to_string(obj_stack, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));

    /* At this point, we pass "obj_stack" to the klass->ip_route_add() implementation.
     * The callee can rely on:
     * - the object being normalized and validated.
     * - staying fully alive until the function returns. In this case it
     *   is stack allocated (and the potential "extra_nexthops" array is
     *   guaranteed to stay alive too).
     */
    return klass->ip_route_add(self, flags, obj_stack);
}

int
nm_platform_ip_route_add(NMPlatform *self, NMPNlmFlags flags, const NMPObject *obj)
{
    nm_auto_nmpobj const NMPObject *obj_keep_alive = NULL;
    NMPObject                       obj_stack;

    nm_assert(
        NM_IN_SET(NMP_OBJECT_GET_TYPE(obj), NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE));

    nmp_object_stackinit(&obj_stack, NMP_OBJECT_GET_TYPE(obj), &obj->ip_route);

    if (NMP_OBJECT_GET_TYPE(obj) == NMP_OBJECT_TYPE_IP4_ROUTE && obj->ip4_route.n_nexthops > 1u) {
        /* Ensure @obj stays alive, so we can alias extra_nexthops from the stackallocated
         * @obj_stack. */
        nm_assert(obj->_ip4_route.extra_nexthops);
        obj_keep_alive                      = nmp_object_ref(obj);
        obj_stack._ip4_route.extra_nexthops = obj->_ip4_route.extra_nexthops;
    }

    return _ip_route_add(self, flags, &obj_stack);
}

int
nm_platform_ip4_route_add(NMPlatform                   *self,
                          NMPNlmFlags                   flags,
                          const NMPlatformIP4Route     *route,
                          const NMPlatformIP4RtNextHop *extra_nexthops)
{
    gs_free NMPlatformIP4RtNextHop *extra_nexthops_free = NULL;
    NMPObject                       obj;

    nm_assert(route);
    nm_assert(route->n_nexthops <= 1u || extra_nexthops);

    nmp_object_stackinit(&obj, NMP_OBJECT_TYPE_IP4_ROUTE, (const NMPlatformObject *) route);

    if (route->n_nexthops > 1u) {
        nm_assert(extra_nexthops);
        /* we need to ensure that @extra_nexthops stays alive until the function returns.
         * Copy the buffer.
         *
         * This is probably not necessary, because likely the caller will somehow ensure that
         * the extra_nexthops stay alive. Still do it, because it is a very unusual case and
         * likely cheap. */
        obj._ip4_route.extra_nexthops =
            nm_memdup_maybe_a(500u,
                              extra_nexthops,
                              sizeof(extra_nexthops[0]) * (route->n_nexthops - 1u),
                              &extra_nexthops_free);
    }

    return _ip_route_add(self, flags, &obj);
}

int
nm_platform_ip6_route_add(NMPlatform *self, NMPNlmFlags flags, const NMPlatformIP6Route *route)
{
    NMPObject obj;

    nmp_object_stackinit(&obj, NMP_OBJECT_TYPE_IP6_ROUTE, (const NMPlatformObject *) route);
    return _ip_route_add(self, flags, &obj);
}

gboolean
nm_platform_object_delete(NMPlatform *self, const NMPObject *obj)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    int  ifindex;

    _CHECK_SELF(self, klass, FALSE);

    if (_LOGD_ENABLED()) {
        switch (NMP_OBJECT_GET_TYPE(obj)) {
        case NMP_OBJECT_TYPE_ROUTING_RULE:
        case NMP_OBJECT_TYPE_MPTCP_ADDR:
            _LOGD("%s: delete %s",
                  NMP_OBJECT_GET_CLASS(obj)->obj_type_name,
                  nmp_object_to_string(obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
            break;
        case NMP_OBJECT_TYPE_IP4_ROUTE:
        case NMP_OBJECT_TYPE_IP6_ROUTE:
        case NMP_OBJECT_TYPE_QDISC:
        case NMP_OBJECT_TYPE_TFILTER:
            ifindex = NMP_OBJECT_CAST_OBJ_WITH_IFINDEX(obj)->ifindex;
            _LOG3D("%s: delete %s",
                   NMP_OBJECT_GET_CLASS(obj)->obj_type_name,
                   nmp_object_to_string(obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
            break;
        default:
            g_return_val_if_reached(FALSE);
        }
    }

    return klass->object_delete(self, obj);
}

/*****************************************************************************/

int
nm_platform_ip_route_get(NMPlatform   *self,
                         int           addr_family,
                         gconstpointer address /* in_addr_t or struct in6_addr */,
                         int           oif_ifindex,
                         NMPObject   **out_route)
{
    char                      sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    nm_auto_nmpobj NMPObject *route = NULL;
    int                       result;
    char                      buf[NM_INET_ADDRSTRLEN];
    char                      buf_oif[64];

    _CHECK_SELF(self, klass, FALSE);

    g_return_val_if_fail(address, -NME_BUG);
    g_return_val_if_fail(NM_IN_SET(addr_family, AF_INET, AF_INET6), -NME_BUG);

    _LOGT("route: get IPv%c route for: %s%s",
          nm_utils_addr_family_to_char(addr_family),
          inet_ntop(addr_family, address, buf, sizeof(buf)),
          oif_ifindex > 0 ? nm_sprintf_buf(buf_oif, " oif %d", oif_ifindex) : "");

    if (!klass->ip_route_get)
        result = -NME_PL_OPNOTSUPP;
    else {
        result = klass->ip_route_get(self, addr_family, address, oif_ifindex, &route);
    }

    if (result < 0) {
        nm_assert(!route);
        _LOGW("route: get IPv%c route for: %s failed with %s",
              nm_utils_addr_family_to_char(addr_family),
              inet_ntop(addr_family, address, buf, sizeof(buf)),
              nm_strerror(result));
    } else {
        nm_assert(NM_IN_SET(NMP_OBJECT_GET_TYPE(route),
                            NMP_OBJECT_TYPE_IP4_ROUTE,
                            NMP_OBJECT_TYPE_IP6_ROUTE));
        nm_assert(!NMP_OBJECT_IS_STACKINIT(route));
        nm_assert(route->parent._ref_count == 1);
        _LOGD("route: get IPv%c route for: %s succeeded: %s",
              nm_utils_addr_family_to_char(addr_family),
              inet_ntop(addr_family, address, buf, sizeof(buf)),
              nmp_object_to_string(route, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
        NM_SET_OUT(out_route, g_steal_pointer(&route));
    }
    return result;
}

/*****************************************************************************/

#define IP4_DEV_ROUTE_BLACKLIST_TIMEOUT_MS ((int) 1500)
#define IP4_DEV_ROUTE_BLACKLIST_GC_TIMEOUT_S \
    ((int) (((IP4_DEV_ROUTE_BLACKLIST_TIMEOUT_MS + 999) * 3) / 1000))

static gint64
_ip4_dev_route_blacklist_timeout_ms_get(gint64 timeout_msec)
{
    return timeout_msec >> 1;
}

static gint64
_ip4_dev_route_blacklist_timeout_ms_marked(gint64 timeout_msec)
{
    return !!(timeout_msec & ((gint64) 1));
}

static gboolean
_ip4_dev_route_blacklist_check_cb(gpointer user_data)
{
    char               sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    NMPlatform        *self = user_data;
    NMPlatformPrivate *priv = NM_PLATFORM_GET_PRIVATE(self);
    GHashTableIter     iter;
    const NMPObject   *p_obj;
    gint64            *p_timeout_ms;
    gint64             now_ms;

    priv->ip4_dev_route_blacklist_check_id = 0;

again:
    if (!priv->ip4_dev_route_blacklist_hash)
        goto out;

    now_ms = nm_utils_get_monotonic_timestamp_msec();

    g_hash_table_iter_init(&iter, priv->ip4_dev_route_blacklist_hash);
    while (g_hash_table_iter_next(&iter, (gpointer *) &p_obj, (gpointer *) &p_timeout_ms)) {
        if (!_ip4_dev_route_blacklist_timeout_ms_marked(*p_timeout_ms))
            continue;

        /* unmark because we checked it. */
        *p_timeout_ms = *p_timeout_ms & ~((gint64) 1);

        if (now_ms > _ip4_dev_route_blacklist_timeout_ms_get(*p_timeout_ms))
            continue;

        if (!nm_platform_lookup_entry(self, NMP_CACHE_ID_TYPE_OBJECT_TYPE, p_obj))
            continue;

        _LOGT("ip4-dev-route: delete %s",
              nmp_object_to_string(p_obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
        nm_platform_object_delete(self, p_obj);
        goto again;
    }

out:
    return G_SOURCE_REMOVE;
}

static void
_ip4_dev_route_blacklist_check_schedule(NMPlatform *self)
{
    NMPlatformPrivate *priv = NM_PLATFORM_GET_PRIVATE(self);

    if (!priv->ip4_dev_route_blacklist_check_id) {
        priv->ip4_dev_route_blacklist_check_id =
            g_idle_add_full(G_PRIORITY_HIGH, _ip4_dev_route_blacklist_check_cb, self, NULL);
    }
}

static void
_ip4_dev_route_blacklist_notify_route(NMPlatform *self, const NMPObject *obj)
{
    NMPlatformPrivate *priv;
    const NMPObject   *p_obj;
    gint64            *p_timeout_ms;
    gint64             now_ms;

    nm_assert(NM_IS_PLATFORM(self));
    nm_assert(NMP_OBJECT_GET_TYPE(obj) == NMP_OBJECT_TYPE_IP4_ROUTE);

    priv = NM_PLATFORM_GET_PRIVATE(self);

    nm_assert(priv->ip4_dev_route_blacklist_gc_timeout_id);

    if (!g_hash_table_lookup_extended(priv->ip4_dev_route_blacklist_hash,
                                      obj,
                                      (gpointer *) &p_obj,
                                      (gpointer *) &p_timeout_ms))
        return;

    now_ms = nm_utils_get_monotonic_timestamp_msec();
    if (now_ms > _ip4_dev_route_blacklist_timeout_ms_get(*p_timeout_ms)) {
        /* already expired. Wait for gc. */
        return;
    }

    if (_ip4_dev_route_blacklist_timeout_ms_marked(*p_timeout_ms)) {
        nm_assert(priv->ip4_dev_route_blacklist_check_id);
        return;
    }

    /* We cannot delete it right away because we are in the process of receiving netlink messages.
     * It may be possible to do so, but complicated and error prone.
     *
     * Instead, we mark the entry and schedule an idle action (with high priority). */
    *p_timeout_ms = (*p_timeout_ms) | ((gint64) 1);
    _ip4_dev_route_blacklist_check_schedule(self);
}

static gboolean
_ip4_dev_route_blacklist_gc_timeout_handle(gpointer user_data)
{
    char               sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    NMPlatform        *self = user_data;
    NMPlatformPrivate *priv = NM_PLATFORM_GET_PRIVATE(self);
    GHashTableIter     iter;
    const NMPObject   *p_obj;
    gint64            *p_timeout_ms;
    gint64             now_ms;

    nm_assert(priv->ip4_dev_route_blacklist_gc_timeout_id);

    now_ms = nm_utils_get_monotonic_timestamp_msec();

    g_hash_table_iter_init(&iter, priv->ip4_dev_route_blacklist_hash);
    while (g_hash_table_iter_next(&iter, (gpointer *) &p_obj, (gpointer *) &p_timeout_ms)) {
        if (now_ms > _ip4_dev_route_blacklist_timeout_ms_get(*p_timeout_ms)) {
            _LOGT("ip4-dev-route: cleanup %s",
                  nmp_object_to_string(p_obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
            g_hash_table_iter_remove(&iter);
        }
    }

    _ip4_dev_route_blacklist_schedule(self);
    return G_SOURCE_CONTINUE;
}

static void
_ip4_dev_route_blacklist_schedule(NMPlatform *self)
{
    NMPlatformPrivate *priv = NM_PLATFORM_GET_PRIVATE(self);

    if (!priv->ip4_dev_route_blacklist_hash
        || g_hash_table_size(priv->ip4_dev_route_blacklist_hash) == 0) {
        nm_clear_pointer(&priv->ip4_dev_route_blacklist_hash, g_hash_table_unref);
        nm_clear_g_source(&priv->ip4_dev_route_blacklist_gc_timeout_id);
    } else {
        if (!priv->ip4_dev_route_blacklist_gc_timeout_id) {
            /* this timeout is only to garbage collect the expired entries from priv->ip4_dev_route_blacklist_hash.
             * It can run infrequently, and it doesn't hurt if expired entries linger around a bit
             * longer then necessary. */
            priv->ip4_dev_route_blacklist_gc_timeout_id =
                g_timeout_add_seconds(IP4_DEV_ROUTE_BLACKLIST_GC_TIMEOUT_S,
                                      _ip4_dev_route_blacklist_gc_timeout_handle,
                                      self);
        }
    }
}

/**
 * nm_platform_ip4_dev_route_blacklist_set:
 * @self:
 * @ifindex:
 * @ip4_dev_route_blacklist:
 *
 * When adding an IP address, kernel automatically adds a device route.
 * This can be suppressed via the IFA_F_NOPREFIXROUTE address flag. For proper
 * IPv6 support, we require kernel support for IFA_F_NOPREFIXROUTE and always
 * add the device route manually.
 *
 * For IPv4, this flag is rather new and we don't rely on it yet. We want to use
 * it (but currently still don't). So, for IPv4, kernel possibly adds a device
 * route, however it has a wrong metric of zero. We add our own device route (with
 * proper metric), but need to delete the route that kernel adds.
 *
 * The problem is, that kernel does not immediately add the route, when adding
 * the address. It only shows up some time later. So, we register here a list
 * of blacklisted routes, and when they show up within a time out, we assume it's
 * the kernel generated one, and we delete it.
 *
 * Eventually, we want to get rid of this and use IFA_F_NOPREFIXROUTE for IPv4
 * routes as well.
 */
void
nm_platform_ip4_dev_route_blacklist_set(NMPlatform *self,
                                        int         ifindex,
                                        GPtrArray  *ip4_dev_route_blacklist)
{
    char               sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    NMPlatformPrivate *priv;
    GHashTableIter     iter;
    const NMPObject   *p_obj;
    guint              i;
    gint64             timeout_msec;
    gint64             timeout_msec_val;
    gint64            *p_timeout_ms;
    gboolean           needs_check = FALSE;

    nm_assert(NM_IS_PLATFORM(self));
    nm_assert(ifindex > 0);

    /* TODO: the blacklist should be maintained by NML3Cfg. */

    priv = NM_PLATFORM_GET_PRIVATE(self);

    /* first, expire all for current ifindex... */
    if (priv->ip4_dev_route_blacklist_hash) {
        g_hash_table_iter_init(&iter, priv->ip4_dev_route_blacklist_hash);
        while (g_hash_table_iter_next(&iter, (gpointer *) &p_obj, (gpointer *) &p_timeout_ms)) {
            if (NMP_OBJECT_CAST_IP4_ROUTE(p_obj)->ifindex == ifindex) {
                /* we could g_hash_table_iter_remove(&iter) the current entry.
                 * Instead, just expire it and let _ip4_dev_route_blacklist_gc_timeout_handle()
                 * handle it.
                 *
                 * The assumption is, that ip4_dev_route_blacklist contains the very same entry
                 * again, with a new timeout. So, we can un-expire it below. */
                *p_timeout_ms = 0;
            }
        }
    }

    if (ip4_dev_route_blacklist && ip4_dev_route_blacklist->len > 0) {
        if (!priv->ip4_dev_route_blacklist_hash) {
            priv->ip4_dev_route_blacklist_hash =
                g_hash_table_new_full((GHashFunc) nmp_object_id_hash,
                                      (GEqualFunc) nmp_object_id_equal,
                                      (GDestroyNotify) nmp_object_unref,
                                      nm_g_slice_free_fcn_gint64);
        }

        timeout_msec = nm_utils_get_monotonic_timestamp_msec() + IP4_DEV_ROUTE_BLACKLIST_TIMEOUT_MS;
        timeout_msec_val = (timeout_msec << 1) | ((gint64) 1);
        for (i = 0; i < ip4_dev_route_blacklist->len; i++) {
            const NMPObject *o;

            needs_check = TRUE;
            o           = ip4_dev_route_blacklist->pdata[i];
            if (g_hash_table_lookup_extended(priv->ip4_dev_route_blacklist_hash,
                                             o,
                                             (gpointer *) &p_obj,
                                             (gpointer *) &p_timeout_ms)) {
                if (nmp_object_equal(p_obj, o)) {
                    /* un-expire and reuse the entry. */
                    _LOGT("ip4-dev-route: register %s (update)",
                          nmp_object_to_string(p_obj,
                                               NMP_OBJECT_TO_STRING_PUBLIC,
                                               sbuf,
                                               sizeof(sbuf)));
                    *p_timeout_ms = timeout_msec_val;
                    continue;
                }
            }

            _LOGT("ip4-dev-route: register %s",
                  nmp_object_to_string(o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
            p_timeout_ms  = g_slice_new(gint64);
            *p_timeout_ms = timeout_msec_val;
            g_hash_table_replace(priv->ip4_dev_route_blacklist_hash,
                                 (gpointer) nmp_object_ref(o),
                                 p_timeout_ms);
        }
    }

    _ip4_dev_route_blacklist_schedule(self);

    if (needs_check)
        _ip4_dev_route_blacklist_check_schedule(self);
}

/*****************************************************************************/

int
nm_platform_routing_rule_add(NMPlatform                  *self,
                             NMPNlmFlags                  flags,
                             const NMPlatformRoutingRule *routing_rule)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    _CHECK_SELF(self, klass, -NME_BUG);

    g_return_val_if_fail(routing_rule, -NME_BUG);

    _LOGD("routing-rule: adding or updating: %s",
          nm_platform_routing_rule_to_string(routing_rule, sbuf, sizeof(sbuf)));
    return klass->routing_rule_add(self, flags, routing_rule);
}

/*****************************************************************************/

int
nm_platform_qdisc_add(NMPlatform *self, NMPNlmFlags flags, const NMPlatformQdisc *qdisc)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    int  ifindex = qdisc->ifindex;
    _CHECK_SELF(self, klass, -NME_BUG);

    /* Note: @qdisc must not be copied or kept alive because the lifetime of qdisc.kind
     * is undefined. */

    _LOG3D("adding or updating a qdisc: %s",
           nm_platform_qdisc_to_string(qdisc, sbuf, sizeof(sbuf)));
    return klass->qdisc_add(self, flags, qdisc);
}

int
nm_platform_qdisc_delete(NMPlatform *self, int ifindex, guint32 parent, gboolean log_error)
{
    _CHECK_SELF(self, klass, -NME_BUG);

    _LOG3D("deleting a qdisc: parent 0x%08x", parent);
    return klass->qdisc_delete(self, ifindex, parent, log_error);
}

/*****************************************************************************/

int
nm_platform_tfilter_add(NMPlatform *self, NMPNlmFlags flags, const NMPlatformTfilter *tfilter)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    int  ifindex = tfilter->ifindex;
    _CHECK_SELF(self, klass, -NME_BUG);

    /* Note: @tfilter must not be copied or kept alive because the lifetime of tfilter.kind
     * and tfilter.action.kind is undefined. */

    _LOG3D("adding or updating a tfilter: %s",
           nm_platform_tfilter_to_string(tfilter, sbuf, sizeof(sbuf)));
    return klass->tfilter_add(self, flags, tfilter);
}

int
nm_platform_tfilter_delete(NMPlatform *self, int ifindex, guint32 parent, gboolean log_error)
{
    _CHECK_SELF(self, klass, -NME_BUG);

    _LOG3D("deleting a tfilter: parent 0x%08x", parent);
    return klass->tfilter_delete(self, ifindex, parent, log_error);
}

/**
 * nm_platform_tc_sync:
 * @self: the #NMPlatform instance
 * @ifindex: the ifindex where to configure qdiscs and filters.
 * @known_qdiscs: the list of qdiscs (#NMPObject).
 * @known_tfilters: the list of tfilters (#NMPObject).
 *
 * The function promises not to take any reference to the
 * instances from @known_qdiscs and @known_tfilters, nor to
 * keep them around after the function returns. This is important,
 * because it allows the caller to pass NMPlatformQdisc and
 * NMPlatformTfilter instances which "kind" string have a limited
 * lifetime.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_tc_sync(NMPlatform *self,
                    int         ifindex,
                    GPtrArray  *known_qdiscs,
                    GPtrArray  *known_tfilters)
{
    guint    i;
    gboolean success = TRUE;

    nm_assert(NM_IS_PLATFORM(self));
    nm_assert(ifindex > 0);

    nm_platform_qdisc_delete(self, ifindex, TC_H_ROOT, FALSE);
    nm_platform_qdisc_delete(self, ifindex, TC_H_INGRESS, FALSE);

    /* At this point we can only have a root default qdisc
     * (which can't be deleted). Ensure it doesn't have any
     * filters attached.
     */
    nm_platform_tfilter_delete(self, ifindex, TC_H_ROOT, FALSE);

    if (known_qdiscs) {
        for (i = 0; i < known_qdiscs->len; i++) {
            const NMPObject *q = g_ptr_array_index(known_qdiscs, i);

            success &=
                (nm_platform_qdisc_add(self, NMP_NLM_FLAG_ADD, NMP_OBJECT_CAST_QDISC(q)) >= 0);
        }
    }

    if (known_tfilters) {
        for (i = 0; i < known_tfilters->len; i++) {
            const NMPObject *q = g_ptr_array_index(known_tfilters, i);

            success &=
                (nm_platform_tfilter_add(self, NMP_NLM_FLAG_ADD, NMP_OBJECT_CAST_TFILTER(q)) >= 0);
        }
    }

    return success;
}

/*****************************************************************************/

const char *
nm_platform_vlan_qos_mapping_to_string(const char             *name,
                                       const NMVlanQosMapping *map,
                                       gsize                   n_map,
                                       char                   *buf,
                                       gsize                   len)
{
    gsize i;
    char *b;

    nm_utils_to_string_buffer_init(&buf, &len);

    if (!n_map) {
        nm_strbuf_append_str(&buf, &len, "");
        return buf;
    }

    if (!map)
        g_return_val_if_reached("");

    b = buf;

    if (name) {
        nm_strbuf_append_str(&b, &len, name);
        nm_strbuf_append_str(&b, &len, " {");
    } else
        nm_strbuf_append_c(&b, &len, '{');

    for (i = 0; i < n_map; i++)
        nm_strbuf_append(&b, &len, " %u:%u", map[i].from, map[i].to);
    nm_strbuf_append_str(&b, &len, " }");
    return buf;
}

/**
 * nm_platform_link_to_string:
 * @route: pointer to NMPlatformLink address structure
 * @buf: (allow-none): an optional buffer. If %NULL, a static buffer is used.
 * @len: the size of the @buf. If @buf is %NULL, this argument is ignored.
 *
 * A method for converting an link struct into a string representation.
 *
 * Returns: a string representation of the link.
 */
const char *
nm_platform_link_to_string(const NMPlatformLink *link, char *buf, gsize len)
{
    char        master[20];
    char        parent[20];
    char        str_flags[1 + NM_PLATFORM_LINK_FLAGS2STR_MAX_LEN + 1];
    char        str_highlighted_flags[50];
    char       *s;
    gsize       l;
    char        str_addrmode[30];
    char        str_address[_NM_UTILS_HWADDR_LEN_MAX * 3];
    char        str_perm_address[_NM_UTILS_HWADDR_LEN_MAX * 3];
    char        str_broadcast[_NM_UTILS_HWADDR_LEN_MAX * 3];
    char        str_inet6_token[NM_INET_ADDRSTRLEN];
    const char *str_link_type;

    if (!nm_utils_to_string_buffer_init_null(link, &buf, &len))
        return buf;

    s = str_highlighted_flags;
    l = sizeof(str_highlighted_flags);
    if (NM_FLAGS_HAS(link->n_ifi_flags, IFF_NOARP))
        nm_strbuf_append_str(&s, &l, "NOARP,");
    if (NM_FLAGS_HAS(link->n_ifi_flags, IFF_UP))
        nm_strbuf_append_str(&s, &l, "UP");
    else
        nm_strbuf_append_str(&s, &l, "DOWN");
    if (link->connected)
        nm_strbuf_append_str(&s, &l, ",LOWER_UP");
    nm_assert(s > str_highlighted_flags && l > 0);

    if (link->n_ifi_flags) {
        str_flags[0] = ';';
        nm_platform_link_flags2str(link->n_ifi_flags, &str_flags[1], sizeof(str_flags) - 1);
    } else
        str_flags[0] = '\0';

    if (link->master)
        g_snprintf(master, sizeof(master), " master %d", link->master);
    else
        master[0] = 0;

    if (link->parent > 0)
        g_snprintf(parent, sizeof(parent), "@%d", link->parent);
    else if (link->parent == NM_PLATFORM_LINK_OTHER_NETNS)
        g_strlcpy(parent, "@other-netns", sizeof(parent));
    else
        parent[0] = 0;

    _nmp_link_address_to_string(&link->l_address, str_address);
    _nmp_link_address_to_string(&link->l_perm_address, str_perm_address);
    _nmp_link_address_to_string(&link->l_broadcast, str_broadcast);

    str_link_type = nm_link_type_to_string(link->type);

    g_snprintf(
        buf,
        len,
        "%d: "    /* ifindex */
        "%s"      /* name */
        "%s"      /* parent */
        " <%s%s>" /* flags */
        " mtu %d"
        "%s"      /* master */
        " arp %u" /* arptype */
        " %s"     /* link->type */
        "%s%s"    /* kind */
        "%s"      /* is-in-udev */
        "%s%s"    /* addr-gen-mode */
        "%s%s"    /* l_address */
        "%s%s"    /* l_perm_address */
        "%s%s"    /* l_broadcast */
        "%s%s"    /* inet6_token */
        "%s%s"    /* driver */
        " rx:%" G_GUINT64_FORMAT ",%" G_GUINT64_FORMAT " tx:%" G_GUINT64_FORMAT
        ",%" G_GUINT64_FORMAT,
        link->ifindex,
        link->name,
        parent,
        str_highlighted_flags,
        str_flags,
        link->mtu,
        master,
        link->arptype,
        str_link_type ?: "???",
        link->kind ? (g_strcmp0(str_link_type, link->kind) ? "/" : "*") : "?",
        link->kind && g_strcmp0(str_link_type, link->kind) ? link->kind : "",
        link->initialized ? " init" : " not-init",
        link->inet6_addr_gen_mode_inv ? " addrgenmode " : "",
        link->inet6_addr_gen_mode_inv ? nm_platform_link_inet6_addrgenmode2str(
            _nm_platform_uint8_inv(link->inet6_addr_gen_mode_inv),
            str_addrmode,
            sizeof(str_addrmode))
                                      : "",
        str_address[0] ? " addr " : "",
        str_address[0] ? str_address : "",
        str_perm_address[0] ? " permaddr " : "",
        str_perm_address[0] ? str_perm_address : "",
        str_broadcast[0] ? " brd " : "",
        str_broadcast[0] ? str_broadcast : "",
        link->inet6_token.id ? " inet6token " : "",
        link->inet6_token.id
            ? nm_utils_inet6_interface_identifier_to_token(&link->inet6_token, str_inet6_token)
            : "",
        link->driver ? " driver " : "",
        link->driver ?: "",
        link->rx_packets,
        link->rx_bytes,
        link->tx_packets,
        link->tx_bytes);
    return buf;
}

const NMPlatformLnkBridge nm_platform_lnk_bridge_default = {
    .forward_delay                 = NM_BRIDGE_FORWARD_DELAY_DEF_SYS,
    .hello_time                    = NM_BRIDGE_HELLO_TIME_DEF_SYS,
    .max_age                       = NM_BRIDGE_MAX_AGE_DEF_SYS,
    .ageing_time                   = NM_BRIDGE_AGEING_TIME_DEF_SYS,
    .stp_state                     = FALSE,
    .priority                      = NM_BRIDGE_PRIORITY_DEF,
    .vlan_protocol                 = 0x8100,
    .vlan_stats_enabled            = NM_BRIDGE_VLAN_STATS_ENABLED_DEF,
    .group_fwd_mask                = 0,
    .group_addr                    = NM_ETHER_ADDR_INIT(NM_BRIDGE_GROUP_ADDRESS_DEF_BIN),
    .mcast_snooping                = NM_BRIDGE_MULTICAST_SNOOPING_DEF,
    .mcast_router                  = 1,
    .mcast_query_use_ifaddr        = NM_BRIDGE_MULTICAST_QUERY_USE_IFADDR_DEF,
    .mcast_querier                 = NM_BRIDGE_MULTICAST_QUERIER_DEF,
    .mcast_hash_max                = NM_BRIDGE_MULTICAST_HASH_MAX_DEF,
    .mcast_last_member_count       = NM_BRIDGE_MULTICAST_LAST_MEMBER_COUNT_DEF,
    .mcast_startup_query_count     = NM_BRIDGE_MULTICAST_STARTUP_QUERY_COUNT_DEF,
    .mcast_last_member_interval    = NM_BRIDGE_MULTICAST_LAST_MEMBER_INTERVAL_DEF,
    .mcast_membership_interval     = NM_BRIDGE_MULTICAST_MEMBERSHIP_INTERVAL_DEF,
    .mcast_querier_interval        = NM_BRIDGE_MULTICAST_QUERIER_INTERVAL_DEF,
    .mcast_query_interval          = NM_BRIDGE_MULTICAST_QUERY_INTERVAL_DEF,
    .mcast_query_response_interval = NM_BRIDGE_MULTICAST_QUERY_RESPONSE_INTERVAL_DEF,
    .mcast_startup_query_interval  = NM_BRIDGE_MULTICAST_STARTUP_QUERY_INTERVAL_DEF,
};

const char *
nm_platform_lnk_bridge_to_string(const NMPlatformLnkBridge *lnk, char *buf, gsize len)
{
    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    g_snprintf(buf,
               len,
               "forward_delay %u"
               " hello_time %u"
               " max_age %u"
               " ageing_time %u"
               " stp_state %d"
               " priority %u"
               " vlan_protocol %u"
               " vlan_stats_enabled %d"
               " group_fwd_mask %#x"
               " group_address " NM_ETHER_ADDR_FORMAT_STR " mcast_snooping %d"
               " mcast_router %u"
               " mcast_query_use_ifaddr %d"
               " mcast_querier %d"
               " mcast_hash_max %u"
               " mcast_last_member_count %u"
               " mcast_startup_query_count %u"
               " mcast_last_member_interval %" G_GUINT64_FORMAT
               " mcast_membership_interval %" G_GUINT64_FORMAT
               " mcast_querier_interval %" G_GUINT64_FORMAT
               " mcast_query_interval %" G_GUINT64_FORMAT
               " mcast_query_response_interval %" G_GUINT64_FORMAT
               " mcast_startup_query_interval %" G_GUINT64_FORMAT "",
               lnk->forward_delay,
               lnk->hello_time,
               lnk->max_age,
               lnk->ageing_time,
               (int) lnk->stp_state,
               lnk->priority,
               lnk->vlan_protocol,
               (int) lnk->vlan_stats_enabled,
               lnk->group_fwd_mask,
               NM_ETHER_ADDR_FORMAT_VAL(&lnk->group_addr),
               (int) lnk->mcast_snooping,
               lnk->mcast_router,
               (int) lnk->mcast_query_use_ifaddr,
               (int) lnk->mcast_querier,
               lnk->mcast_hash_max,
               lnk->mcast_last_member_count,
               lnk->mcast_startup_query_count,
               lnk->mcast_last_member_interval,
               lnk->mcast_membership_interval,
               lnk->mcast_querier_interval,
               lnk->mcast_query_interval,
               lnk->mcast_query_response_interval,
               lnk->mcast_startup_query_interval);
    return buf;
}

const char *
nm_platform_lnk_bond_to_string(const NMPlatformLnkBond *lnk, char *buf, gsize len)
{
    char sbuf_miimon[30];
    char sbuf_updelay[30];
    char sbuf_downdelay[30];
    char sbuf_peer_notif_delay[60];
    char sbuf_resend_igmp[30];
    char sbuf_lp_interval[30];
    char sbuf_tlb_dynamic_lb[30];
    int  i;

    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    nm_strbuf_append(
        &buf,
        &len,
        "bond"
        " mode %u"
        " primary %d"
        "%s" /* miimon */
        "%s" /* updelay */
        "%s" /* downdelay */
        " arp_interval %u"
        "%s" /* resend_igmp */
        " min_links %u"
        "%s" /* lp_interval */
        " packets_per_port %u"
        "%s" /* peer_notif_delay */
        " arp_all_targets %u"
        " arp_validate %u"
        " ad_actor_sys_prio %u"
        " ad_user_port_key %u"
        " ad_actor_system " NM_ETHER_ADDR_FORMAT_STR ""
        " primary_reselect %u"
        " fail_over_mac %u"
        " xmit_hash_policy %u"
        " num_gray_arp %u"
        " all_ports_active %u"
        " lacp_rate %u"
        " ad_select %u"
        " use_carrier %d"
        "%s" /* tlb_dynamic_lb */,
        lnk->mode,
        lnk->primary,
        lnk->miimon_has || lnk->miimon != 0
            ? nm_sprintf_buf(sbuf_miimon, " miimon%s %u", !lnk->miimon_has ? "?" : "", lnk->miimon)
            : "",
        lnk->updelay_has || lnk->updelay != 0 ? nm_sprintf_buf(sbuf_updelay,
                                                               " updelay%s %u",
                                                               !lnk->updelay_has ? "?" : "",
                                                               lnk->updelay)
                                              : "",
        lnk->downdelay_has || lnk->downdelay != 0 ? nm_sprintf_buf(sbuf_downdelay,
                                                                   " downdelay%s %u",
                                                                   !lnk->downdelay_has ? "?" : "",
                                                                   lnk->downdelay)
                                                  : "",
        lnk->arp_interval,
        lnk->resend_igmp_has || lnk->resend_igmp != 0
            ? nm_sprintf_buf(sbuf_resend_igmp,
                             " resend_igmp%s %u",
                             !lnk->resend_igmp_has ? "?" : "",
                             lnk->resend_igmp)
            : "",
        lnk->min_links,
        lnk->lp_interval_has || lnk->lp_interval != 1
            ? nm_sprintf_buf(sbuf_lp_interval,
                             " lp_interval%s %u",
                             !lnk->lp_interval_has ? "?" : "",
                             lnk->lp_interval)
            : "",
        lnk->packets_per_port,
        lnk->peer_notif_delay_has || lnk->peer_notif_delay != 0
            ? nm_sprintf_buf(sbuf_peer_notif_delay,
                             " peer_notif_delay%s %u",
                             !lnk->peer_notif_delay_has ? "?" : "",
                             lnk->peer_notif_delay)
            : "",
        lnk->arp_all_targets,
        lnk->arp_validate,
        lnk->ad_actor_sys_prio,
        lnk->ad_user_port_key,
        NM_ETHER_ADDR_FORMAT_VAL(&lnk->ad_actor_system),
        lnk->primary_reselect,
        lnk->fail_over_mac,
        lnk->xmit_hash_policy,
        lnk->num_grat_arp,
        lnk->all_ports_active,
        lnk->lacp_rate,
        lnk->ad_select,
        (int) lnk->use_carrier,
        lnk->tlb_dynamic_lb_has ? nm_sprintf_buf(sbuf_tlb_dynamic_lb,
                                                 " tlb_dynamic_lb%s %u",
                                                 !lnk->tlb_dynamic_lb_has ? "?" : "",
                                                 (int) lnk->tlb_dynamic_lb)
                                : "");

    if (lnk->arp_ip_targets_num > 0) {
        nm_strbuf_append_str(&buf, &len, " arp_ip_target");
        for (i = 0; i < lnk->arp_ip_targets_num; i++) {
            char target[INET_ADDRSTRLEN];

            nm_strbuf_append_c(&buf, &len, ' ');
            nm_strbuf_append_str(&buf, &len, nm_inet4_ntop(lnk->arp_ip_target[i], target));
        }
    }
    return buf;
}

const char *
nm_platform_lnk_gre_to_string(const NMPlatformLnkGre *lnk, char *buf, gsize len)
{
    char str_local[30];
    char str_local1[NM_INET_ADDRSTRLEN];
    char str_remote[30];
    char str_remote1[NM_INET_ADDRSTRLEN];
    char str_ttl[30];
    char str_tos[30];
    char str_parent_ifindex[30];
    char str_input_flags[30];
    char str_output_flags[30];
    char str_input_key[30];
    char str_input_key1[NM_INET_ADDRSTRLEN];
    char str_output_key[30];
    char str_output_key1[NM_INET_ADDRSTRLEN];

    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    g_snprintf(
        buf,
        len,
        "gre%s" /* is_tap */
        "%s"    /* remote */
        "%s"    /* local */
        "%s"    /* parent_ifindex */
        "%s"    /* ttl */
        "%s"    /* tos */
        "%s"    /* path_mtu_discovery */
        "%s"    /* iflags */
        "%s"    /* oflags */
        "%s"    /* ikey */
        "%s"    /* okey */
        "",
        lnk->is_tap ? "tap" : "",
        lnk->remote
            ? nm_sprintf_buf(str_remote, " remote %s", nm_inet4_ntop(lnk->remote, str_remote1))
            : "",
        lnk->local ? nm_sprintf_buf(str_local, " local %s", nm_inet4_ntop(lnk->local, str_local1))
                   : "",
        lnk->parent_ifindex ? nm_sprintf_buf(str_parent_ifindex, " dev %d", lnk->parent_ifindex)
                            : "",
        lnk->ttl ? nm_sprintf_buf(str_ttl, " ttl %u", lnk->ttl) : " ttl inherit",
        lnk->tos ? (lnk->tos == 1 ? " tos inherit" : nm_sprintf_buf(str_tos, " tos 0x%x", lnk->tos))
                 : "",
        lnk->path_mtu_discovery ? "" : " nopmtudisc",
        lnk->input_flags ? nm_sprintf_buf(str_input_flags, " iflags 0x%x", lnk->input_flags) : "",
        lnk->output_flags ? nm_sprintf_buf(str_output_flags, " oflags 0x%x", lnk->output_flags)
                          : "",
        NM_FLAGS_HAS(lnk->input_flags, GRE_KEY) || lnk->input_key
            ? nm_sprintf_buf(str_input_key,
                             " ikey %s",
                             nm_inet4_ntop(lnk->input_key, str_input_key1))
            : "",
        NM_FLAGS_HAS(lnk->output_flags, GRE_KEY) || lnk->output_key
            ? nm_sprintf_buf(str_output_key,
                             " okey %s",
                             nm_inet4_ntop(lnk->output_key, str_output_key1))
            : "");
    return buf;
}

const char *
nm_platform_lnk_infiniband_to_string(const NMPlatformLnkInfiniband *lnk, char *buf, gsize len)
{
    char str_p_key[64];

    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    g_snprintf(buf,
               len,
               "infiniband"
               "%s"   /* p_key */
               "%s%s" /* mode */
               "",
               lnk->p_key ? nm_sprintf_buf(str_p_key, " pkey %d", lnk->p_key) : "",
               lnk->mode ? " mode " : "",
               lnk->mode ?: "");
    return buf;
}

const char *
nm_platform_lnk_ip6tnl_to_string(const NMPlatformLnkIp6Tnl *lnk, char *buf, gsize len)
{
    char  str_local[30];
    char  str_local1[NM_INET_ADDRSTRLEN];
    char  str_remote[30];
    char  str_remote1[NM_INET_ADDRSTRLEN];
    char  str_ttl[30];
    char  str_tclass[30];
    char  str_flow[30];
    char  str_encap[30];
    char  str_proto[30];
    char  str_parent_ifindex[30];
    char *str_type;

    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    if (lnk->is_gre)
        str_type = lnk->is_tap ? "ip6gretap" : "ip6gre";
    else
        str_type = "ip6tnl";

    g_snprintf(buf,
               len,
               "%s" /* type */
               "%s" /* remote */
               "%s" /* local */
               "%s" /* parent_ifindex */
               "%s" /* ttl */
               "%s" /* tclass */
               "%s" /* encap limit */
               "%s" /* flow label */
               "%s" /* proto */
               " flags 0x%x"
               "",
               str_type,
               nm_sprintf_buf(str_remote, " remote %s", nm_inet6_ntop(&lnk->remote, str_remote1)),
               nm_sprintf_buf(str_local, " local %s", nm_inet6_ntop(&lnk->local, str_local1)),
               lnk->parent_ifindex
                   ? nm_sprintf_buf(str_parent_ifindex, " dev %d", lnk->parent_ifindex)
                   : "",
               lnk->ttl ? nm_sprintf_buf(str_ttl, " ttl %u", lnk->ttl) : " ttl inherit",
               lnk->tclass == 1 ? " tclass inherit"
                                : nm_sprintf_buf(str_tclass, " tclass 0x%x", lnk->tclass),
               nm_sprintf_buf(str_encap, " encap-limit %u", lnk->encap_limit),
               nm_sprintf_buf(str_flow, " flow-label 0x05%x", lnk->flow_label),
               nm_sprintf_buf(str_proto, " proto %u", lnk->proto),
               (guint) lnk->flags);
    return buf;
}

const char *
nm_platform_lnk_ipip_to_string(const NMPlatformLnkIpIp *lnk, char *buf, gsize len)
{
    char str_local[30];
    char str_local1[NM_INET_ADDRSTRLEN];
    char str_remote[30];
    char str_remote1[NM_INET_ADDRSTRLEN];
    char str_ttl[30];
    char str_tos[30];
    char str_parent_ifindex[30];

    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    g_snprintf(
        buf,
        len,
        "ipip"
        "%s" /* remote */
        "%s" /* local */
        "%s" /* parent_ifindex */
        "%s" /* ttl */
        "%s" /* tos */
        "%s" /* path_mtu_discovery */
        "",
        lnk->remote
            ? nm_sprintf_buf(str_remote, " remote %s", nm_inet4_ntop(lnk->remote, str_remote1))
            : "",
        lnk->local ? nm_sprintf_buf(str_local, " local %s", nm_inet4_ntop(lnk->local, str_local1))
                   : "",
        lnk->parent_ifindex ? nm_sprintf_buf(str_parent_ifindex, " dev %d", lnk->parent_ifindex)
                            : "",
        lnk->ttl ? nm_sprintf_buf(str_ttl, " ttl %u", lnk->ttl) : " ttl inherit",
        lnk->tos ? (lnk->tos == 1 ? " tos inherit" : nm_sprintf_buf(str_tos, " tos 0x%x", lnk->tos))
                 : "",
        lnk->path_mtu_discovery ? "" : " nopmtudisc");
    return buf;
}

const char *
nm_platform_lnk_macsec_to_string(const NMPlatformLnkMacsec *lnk, char *buf, gsize len)
{
    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    g_snprintf(buf,
               len,
               "macsec "
               "sci %016llx "
               "protect %s "
               "cipher %016llx "
               "icvlen %u "
               "encodingsa %u "
               "validate %u "
               "encrypt %s "
               "send_sci %s "
               "end_station %s "
               "scb %s "
               "replay %s",
               (unsigned long long) lnk->sci,
               lnk->protect ? "on" : "off",
               (unsigned long long) lnk->cipher_suite,
               lnk->icv_length,
               lnk->encoding_sa,
               lnk->validation,
               lnk->encrypt ? "on" : "off",
               lnk->include_sci ? "on" : "off",
               lnk->es ? "on" : "off",
               lnk->scb ? "on" : "off",
               lnk->replay_protect ? "on" : "off");
    return buf;
}

const char *
nm_platform_lnk_macvlan_to_string(const NMPlatformLnkMacvlan *lnk, char *buf, gsize len)
{
    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    g_snprintf(buf,
               len,
               "%s mode %u %s",
               lnk->tap ? "macvtap" : "macvlan",
               lnk->mode,
               lnk->no_promisc ? "not-promisc" : "promisc");
    return buf;
}

const char *
nm_platform_lnk_sit_to_string(const NMPlatformLnkSit *lnk, char *buf, gsize len)
{
    char str_local[30];
    char str_local1[NM_INET_ADDRSTRLEN];
    char str_remote[30];
    char str_remote1[NM_INET_ADDRSTRLEN];
    char str_ttl[30];
    char str_tos[30];
    char str_flags[30];
    char str_proto[30];
    char str_parent_ifindex[30];

    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    g_snprintf(
        buf,
        len,
        "sit"
        "%s" /* remote */
        "%s" /* local */
        "%s" /* parent_ifindex */
        "%s" /* ttl */
        "%s" /* tos */
        "%s" /* path_mtu_discovery */
        "%s" /* flags */
        "%s" /* proto */
        "",
        lnk->remote
            ? nm_sprintf_buf(str_remote, " remote %s", nm_inet4_ntop(lnk->remote, str_remote1))
            : "",
        lnk->local ? nm_sprintf_buf(str_local, " local %s", nm_inet4_ntop(lnk->local, str_local1))
                   : "",
        lnk->parent_ifindex ? nm_sprintf_buf(str_parent_ifindex, " dev %d", lnk->parent_ifindex)
                            : "",
        lnk->ttl ? nm_sprintf_buf(str_ttl, " ttl %u", lnk->ttl) : " ttl inherit",
        lnk->tos ? (lnk->tos == 1 ? " tos inherit" : nm_sprintf_buf(str_tos, " tos 0x%x", lnk->tos))
                 : "",
        lnk->path_mtu_discovery ? "" : " nopmtudisc",
        lnk->flags ? nm_sprintf_buf(str_flags, " flags 0x%x", lnk->flags) : "",
        lnk->proto ? nm_sprintf_buf(str_proto, " proto 0x%x", lnk->proto) : "");
    return buf;
}

const char *
nm_platform_lnk_tun_to_string(const NMPlatformLnkTun *lnk, char *buf, gsize len)
{
    char        str_owner[50];
    char        str_group[50];
    char        str_type[50];
    const char *type;

    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    if (lnk->type == IFF_TUN)
        type = "tun";
    else if (lnk->type == IFF_TAP)
        type = "tap";
    else
        type = nm_sprintf_buf(str_type, "tun type %u", (guint) lnk->type);

    g_snprintf(buf,
               len,
               "%s" /* type */
               "%s" /* pi */
               "%s" /* vnet_hdr */
               "%s" /* multi_queue */
               "%s" /* persist */
               "%s" /* owner */
               "%s" /* group */
               "",
               type,
               lnk->pi ? " pi" : "",
               lnk->vnet_hdr ? " vnet_hdr" : "",
               lnk->multi_queue ? " multi_queue" : "",
               lnk->persist ? " persist" : "",
               lnk->owner_valid ? nm_sprintf_buf(str_owner, " owner %u", (guint) lnk->owner) : "",
               lnk->group_valid ? nm_sprintf_buf(str_group, " group %u", (guint) lnk->group) : "");
    return buf;
}

const char *
nm_platform_lnk_vlan_to_string(const NMPlatformLnkVlan *lnk, char *buf, gsize len)
{
    char *b;
    char  protocol[32];

    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    b = buf;

    switch (lnk->protocol) {
    case ETH_P_8021AD:
        nm_sprintf_buf(protocol, "802.1ad");
        break;
    case ETH_P_8021Q:
        nm_sprintf_buf(protocol, "802.1Q");
        break;
    default:
        nm_sprintf_buf(protocol, "0x%04hx", lnk->protocol);
        break;
    }

    nm_strbuf_append(&b, &len, "vlan %u", lnk->id);
    nm_strbuf_append(&b, &len, " protocol %s", protocol);
    if (lnk->flags)
        nm_strbuf_append(&b, &len, " flags 0x%x", lnk->flags);
    return buf;
}

const char *
nm_platform_lnk_vti_to_string(const NMPlatformLnkVti *lnk, char *buf, gsize len)
{
    char str_local[30 + NM_INET_ADDRSTRLEN];
    char str_local1[NM_INET_ADDRSTRLEN];
    char str_remote[30 + NM_INET_ADDRSTRLEN];
    char str_remote1[NM_INET_ADDRSTRLEN];
    char str_ikey[30];
    char str_okey[30];
    char str_fwmark[30];
    char str_parent_ifindex[30];

    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    g_snprintf(
        buf,
        len,
        "vti"
        "%s" /* remote */
        "%s" /* local */
        "%s" /* parent_ifindex */
        "%s" /* ikey */
        "%s" /* okey */
        "%s" /* fwmark */
        "",
        lnk->remote
            ? nm_sprintf_buf(str_remote, " remote %s", nm_inet4_ntop(lnk->remote, str_remote1))
            : "",
        lnk->local ? nm_sprintf_buf(str_local, " local %s", nm_inet4_ntop(lnk->local, str_local1))
                   : "",
        lnk->parent_ifindex ? nm_sprintf_buf(str_parent_ifindex, " dev %d", lnk->parent_ifindex)
                            : "",
        lnk->ikey ? nm_sprintf_buf(str_ikey, " ikey %u", lnk->ikey) : "",
        lnk->okey ? nm_sprintf_buf(str_okey, " okey %u", lnk->okey) : "",
        lnk->fwmark ? nm_sprintf_buf(str_fwmark, " fwmark 0x%x", lnk->fwmark) : "");
    return buf;
}

const char *
nm_platform_lnk_vti6_to_string(const NMPlatformLnkVti6 *lnk, char *buf, gsize len)
{
    char str_local[30 + NM_INET_ADDRSTRLEN];
    char str_local1[NM_INET_ADDRSTRLEN];
    char str_remote[30 + NM_INET_ADDRSTRLEN];
    char str_remote1[NM_INET_ADDRSTRLEN];
    char str_ikey[30];
    char str_okey[30];
    char str_fwmark[30];
    char str_parent_ifindex[30];

    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    g_snprintf(
        buf,
        len,
        "vti6"
        "%s" /* remote */
        "%s" /* local */
        "%s" /* parent_ifindex */
        "%s" /* ikey */
        "%s" /* okey */
        "%s" /* fwmark */
        "",
        IN6_IS_ADDR_UNSPECIFIED(&lnk->remote)
            ? ""
            : nm_sprintf_buf(str_remote, " remote %s", nm_inet6_ntop(&lnk->remote, str_remote1)),
        IN6_IS_ADDR_UNSPECIFIED(&lnk->local)
            ? ""
            : nm_sprintf_buf(str_local, " local %s", nm_inet6_ntop(&lnk->local, str_local1)),
        lnk->parent_ifindex ? nm_sprintf_buf(str_parent_ifindex, " dev %d", lnk->parent_ifindex)
                            : "",
        lnk->ikey ? nm_sprintf_buf(str_ikey, " ikey %u", lnk->ikey) : "",
        lnk->okey ? nm_sprintf_buf(str_okey, " okey %u", lnk->okey) : "",
        lnk->fwmark ? nm_sprintf_buf(str_fwmark, " fwmark 0x%x", lnk->fwmark) : "");
    return buf;
}

const char *
nm_platform_lnk_vrf_to_string(const NMPlatformLnkVrf *lnk, char *buf, gsize len)
{
    char *b;

    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    b = buf;

    nm_strbuf_append(&b, &len, "table %u", lnk->table);
    return buf;
}

const char *
nm_platform_lnk_vxlan_to_string(const NMPlatformLnkVxlan *lnk, char *buf, gsize len)
{
    char str_group[100];
    char str_group6[100];
    char str_local[100];
    char str_local6[100];
    char str_dev[30];
    char str_limit[25];
    char str_src_port[35];
    char str_dst_port[25];
    char str_tos[25];
    char str_ttl[25];
    char sbuf[NM_INET_ADDRSTRLEN];

    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    if (lnk->group == 0)
        str_group[0] = '\0';
    else {
        g_snprintf(str_group,
                   sizeof(str_group),
                   " %s %s",
                   IN_MULTICAST(ntohl(lnk->group)) ? "group" : "remote",
                   nm_inet4_ntop(lnk->group, sbuf));
    }
    if (IN6_IS_ADDR_UNSPECIFIED(&lnk->group6))
        str_group6[0] = '\0';
    else {
        g_snprintf(str_group6,
                   sizeof(str_group6),
                   " %s%s %s",
                   IN6_IS_ADDR_MULTICAST(&lnk->group6) ? "group" : "remote",
                   str_group[0] ? "6" : "", /* usually, a vxlan has either v4 or v6 only. */
                   nm_inet6_ntop(&lnk->group6, sbuf));
    }

    if (lnk->local == 0)
        str_local[0] = '\0';
    else {
        g_snprintf(str_local, sizeof(str_local), " local %s", nm_inet4_ntop(lnk->local, sbuf));
    }
    if (IN6_IS_ADDR_UNSPECIFIED(&lnk->local6))
        str_local6[0] = '\0';
    else {
        g_snprintf(str_local6,
                   sizeof(str_local6),
                   " local%s %s",
                   str_local[0] ? "6" : "", /* usually, a vxlan has either v4 or v6 only. */
                   nm_inet6_ntop(&lnk->local6, sbuf));
    }

    g_snprintf(
        buf,
        len,
        "vxlan"
        " id %u"     /* id */
        "%s%s"       /* group/group6 */
        "%s%s"       /* local/local6 */
        "%s"         /* dev */
        "%s"         /* src_port_min/src_port_max */
        "%s"         /* dst_port */
        "%s"         /* learning */
        "%s"         /* proxy */
        "%s"         /* rsc */
        "%s"         /* l2miss */
        "%s"         /* l3miss */
        "%s"         /* tos */
        "%s"         /* ttl */
        " ageing %u" /* ageing */
        "%s"         /* limit */
        "",
        (guint) lnk->id,
        str_group,
        str_group6,
        str_local,
        str_local6,
        _to_string_dev(str_dev, lnk->parent_ifindex),
        lnk->src_port_min || lnk->src_port_max
            ? nm_sprintf_buf(str_src_port, " srcport %u %u", lnk->src_port_min, lnk->src_port_max)
            : "",
        lnk->dst_port ? nm_sprintf_buf(str_dst_port, " dstport %u", lnk->dst_port) : "",
        !lnk->learning ? " nolearning" : "",
        lnk->proxy ? " proxy" : "",
        lnk->rsc ? " rsc" : "",
        lnk->l2miss ? " l2miss" : "",
        lnk->l3miss ? " l3miss" : "",
        lnk->tos == 1 ? " tos inherit" : nm_sprintf_buf(str_tos, " tos %#x", lnk->tos),
        lnk->ttl ? nm_sprintf_buf(str_ttl, " ttl %u", lnk->ttl) : "",
        lnk->ageing,
        lnk->limit ? nm_sprintf_buf(str_limit, " maxaddr %u", lnk->limit) : "");
    return buf;
}

const char *
nm_platform_wireguard_peer_to_string(const NMPWireGuardPeer *peer, char *buf, gsize len)
{
    char         *buf0           = buf;
    gs_free char *public_key_b64 = NULL;
    char          s_sockaddr[NM_INET_ADDRSTRLEN + 100];
    char          s_endpoint[20 + sizeof(s_sockaddr)];
    char          s_addr[NM_INET_ADDRSTRLEN];
    char          s_keepalive[100];
    guint         i;

    nm_utils_to_string_buffer_init(&buf, &len);

    public_key_b64 = g_base64_encode(peer->public_key, sizeof(peer->public_key));

    if (peer->endpoint.sa.sa_family != AF_UNSPEC) {
        nm_sprintf_buf(
            s_endpoint,
            " endpoint %s",
            nm_sock_addr_union_to_string(&peer->endpoint, s_sockaddr, sizeof(s_sockaddr)));
    } else
        s_endpoint[0] = '\0';

    nm_strbuf_append(&buf,
                     &len,
                     "public-key %s"
                     "%s" /* preshared-key */
                     "%s" /* endpoint */
                     " rx %" G_GUINT64_FORMAT " tx %" G_GUINT64_FORMAT
                     "%s"  /* persistent-keepalive */
                     "%s", /* allowed-ips */
                     public_key_b64,
                     nm_utils_memeqzero_secret(peer->preshared_key, sizeof(peer->preshared_key))
                         ? ""
                         : " preshared-key (hidden)",
                     s_endpoint,
                     peer->rx_bytes,
                     peer->tx_bytes,
                     peer->persistent_keepalive_interval > 0
                         ? nm_sprintf_buf(s_keepalive,
                                          " keepalive %u",
                                          (guint) peer->persistent_keepalive_interval)
                         : "",
                     peer->allowed_ips_len > 0 ? " allowed-ips" : "");

    for (i = 0; i < peer->allowed_ips_len; i++) {
        const NMPWireGuardAllowedIP *allowed_ip = &peer->allowed_ips[i];

        nm_strbuf_append(&buf,
                         &len,
                         " %s/%u",
                         nm_inet_ntop(allowed_ip->family, &allowed_ip->addr, s_addr),
                         allowed_ip->mask);
    }

    return buf0;
}

const char *
nm_platform_lnk_wireguard_to_string(const NMPlatformLnkWireGuard *lnk, char *buf, gsize len)
{
    gs_free char *public_b64 = NULL;

    if (!nm_utils_to_string_buffer_init_null(lnk, &buf, &len))
        return buf;

    if (!nm_utils_memeqzero(lnk->public_key, sizeof(lnk->public_key)))
        public_b64 = g_base64_encode(lnk->public_key, sizeof(lnk->public_key));

    g_snprintf(buf,
               len,
               "wireguard"
               "%s%s" /* public-key */
               "%s"   /* private-key */
               " listen-port %u"
               " fwmark 0x%x",
               public_b64 ? " public-key " : "",
               public_b64 ?: "",
               nm_utils_memeqzero_secret(lnk->private_key, sizeof(lnk->private_key))
                   ? ""
                   : " private-key (hidden)",
               lnk->listen_port,
               lnk->fwmark);

    return buf;
}

static NM_UTILS_FLAGS2STR_DEFINE(_rtm_flags_to_string,
                                 unsigned,
                                 NM_UTILS_FLAGS2STR(RTNH_F_DEAD, "dead"),
                                 NM_UTILS_FLAGS2STR(RTNH_F_PERVASIVE, "pervasive"),
                                 NM_UTILS_FLAGS2STR(RTNH_F_ONLINK, "onlink"),
                                 NM_UTILS_FLAGS2STR(8 /*RTNH_F_OFFLOAD*/, "offload"),
                                 NM_UTILS_FLAGS2STR(16 /*RTNH_F_LINKDOWN*/, "linkdown"),
                                 NM_UTILS_FLAGS2STR(32 /*RTNH_F_UNRESOLVED*/, "unresolved"),

                                 NM_UTILS_FLAGS2STR(RTM_F_NOTIFY, "notify"),
                                 NM_UTILS_FLAGS2STR(RTM_F_CLONED, "cloned"),
                                 NM_UTILS_FLAGS2STR(RTM_F_EQUALIZE, "equalize"),
                                 NM_UTILS_FLAGS2STR(RTM_F_PREFIX, "prefix"),
                                 NM_UTILS_FLAGS2STR(0x1000 /*RTM_F_LOOKUP_TABLE*/, "lookup-table"),
                                 NM_UTILS_FLAGS2STR(0x2000 /*RTM_F_FIB_MATCH*/, "fib-match"), );

#define _RTM_FLAGS_TO_STRING_MAXLEN 200

static const char *
_rtm_flags_to_string_full(char *buf, gsize buf_size, unsigned rtm_flags)
{
    const char *buf0 = buf;

    nm_assert(buf_size >= _RTM_FLAGS_TO_STRING_MAXLEN);

    if (!rtm_flags)
        return "";

    nm_strbuf_append_str(&buf, &buf_size, " rtm_flags ");
    _rtm_flags_to_string(rtm_flags, buf, buf_size);
    nm_assert(strlen(buf) < buf_size);
    return buf0;
}

/**
 * nm_platform_ip4_route_to_string:
 * @route: pointer to NMPlatformIP4Route route structure
 * @extra_nexthops: (allow-none): the route might be a ECMP multihop route
 *   (with n_nexthops > 1). In that case, provide the list of extra hops
 *   to print too. It is allowed for a multihop route to omit the extra hops
 *   by passing NULL.
 * @buf: (allow-none): an optional buffer. If %NULL, a static buffer is used.
 * @len: the size of the @buf. If @buf is %NULL, this argument is ignored.
 *
 * A method for converting a route struct into a string representation.
 *
 * Example output: "192.168.1.0/24 via 0.0.0.0 dev em1 metric 0 mss 0"
 *
 * Returns: a string representation of the route.
 */
const char *
nm_platform_ip4_route_to_string_full(const NMPlatformIP4Route     *route,
                                     const NMPlatformIP4RtNextHop *extra_nexthops,
                                     char                         *buf,
                                     gsize                         len)
{
    char *buf0;
    char  s_network[INET_ADDRSTRLEN];
    char  s_gateway[INET_ADDRSTRLEN];
    char  s_pref_src[INET_ADDRSTRLEN];
    char  str_dev[30];
    char  str_mss[32];
    char  str_table[30];
    char  str_scope[30];
    char  s_source[50];
    char  str_tos[32];
    char  str_window[32];
    char  str_cwnd[32];
    char  str_initcwnd[32];
    char  str_initrwnd[32];
    char  str_rto_min[32];
    char  str_mtu[32];
    char  str_rtm_flags[_RTM_FLAGS_TO_STRING_MAXLEN];
    char  str_type[30];
    char  str_metric[30];
    char  weight_str[20];
    guint n_nexthops;

    if (!nm_utils_to_string_buffer_init_null(route, &buf, &len))
        return buf;

    buf0 = buf;

    n_nexthops = nm_platform_ip4_route_get_n_nexthops(route);

    inet_ntop(AF_INET, &route->network, s_network, sizeof(s_network));

    if (route->gateway == 0)
        s_gateway[0] = '\0';
    else
        inet_ntop(AF_INET, &route->gateway, s_gateway, sizeof(s_gateway));

    nm_strbuf_append(
        &buf,
        &len,
        "type %s " /* type */
        "%s"       /* table */
        "%s/%d"
        "%s%s" /* gateway */
        "%s%s" /* weight */
        "%s"   /* dev/ifindex */
        " metric %s"
        "%s"         /* mss */
        " rt-src %s" /* protocol */
        "%s"         /* rtm_flags */
        "%s%s"       /* scope */
        "%s%s"       /* pref-src */
        "%s"         /* tos */
        "%s"         /* window */
        "%s"         /* cwnd */
        "%s"         /* initcwnd */
        "%s"         /* initrwnd */
        "%s"         /* rto_min */
        "%s"         /* quickack */
        "%s"         /* mtu */
        "%s"         /* r_force_commit */
        "",
        nm_net_aux_rtnl_rtntype_n2a_maybe_buf(nm_platform_route_type_uncoerce(route->type_coerced),
                                              str_type),
        route->table_any
            ? "table ?? "
            : (route->table_coerced
                   ? nm_sprintf_buf(str_table,
                                    "table %u ",
                                    nm_platform_route_table_uncoerce(route->table_coerced, FALSE))
                   : ""),
        s_network,
        route->plen,
        n_nexthops <= 1 && s_gateway[0] ? " via " : "",
        n_nexthops <= 1 ? s_gateway : "",
        NM_PRINT_FMT_QUOTED2(n_nexthops <= 1 && route->weight != 0,
                             " weight ",
                             nm_sprintf_buf(weight_str, "%u", route->weight),
                             ""),
        n_nexthops <= 1 ? _to_string_dev(str_dev, route->ifindex) : "",
        route->metric_any
            ? (route->metric ? nm_sprintf_buf(str_metric, "??+%u", route->metric) : "??")
            : nm_sprintf_buf(str_metric, "%u", route->metric),
        nm_sprintf_buf(str_mss,
                       " mss %s%" G_GUINT32_FORMAT,
                       route->lock_mss ? "lock " : "",
                       route->mss),
        nmp_utils_ip_config_source_to_string(route->rt_source, s_source, sizeof(s_source)),
        _rtm_flags_to_string_full(str_rtm_flags, sizeof(str_rtm_flags), route->r_rtm_flags),
        route->scope_inv ? " scope " : "",
        route->scope_inv
            ? (nm_platform_route_scope2str(nm_platform_route_scope_inv(route->scope_inv),
                                           str_scope,
                                           sizeof(str_scope)))
            : "",
        route->pref_src ? " pref-src " : "",
        route->pref_src ? inet_ntop(AF_INET, &route->pref_src, s_pref_src, sizeof(s_pref_src)) : "",
        route->tos ? nm_sprintf_buf(str_tos, " tos 0x%x", (unsigned) route->tos) : "",
        route->window || route->lock_window ? nm_sprintf_buf(str_window,
                                                             " window %s%" G_GUINT32_FORMAT,
                                                             route->lock_window ? "lock " : "",
                                                             route->window)
                                            : "",
        route->cwnd || route->lock_cwnd ? nm_sprintf_buf(str_cwnd,
                                                         " cwnd %s%" G_GUINT32_FORMAT,
                                                         route->lock_cwnd ? "lock " : "",
                                                         route->cwnd)
                                        : "",
        route->initcwnd || route->lock_initcwnd
            ? nm_sprintf_buf(str_initcwnd,
                             " initcwnd %s%" G_GUINT32_FORMAT,
                             route->lock_initcwnd ? "lock " : "",
                             route->initcwnd)
            : "",
        route->initrwnd || route->lock_initrwnd
            ? nm_sprintf_buf(str_initrwnd,
                             " initrwnd %s%" G_GUINT32_FORMAT,
                             route->lock_initrwnd ? "lock " : "",
                             route->initrwnd)
            : "",
        route->rto_min ? nm_sprintf_buf(str_rto_min, " rto_min %" G_GUINT32_FORMAT, route->rto_min)
                       : "",
        route->quickack ? " quickack 1" : "",
        route->mtu || route->lock_mtu ? nm_sprintf_buf(str_mtu,
                                                       " mtu %s%" G_GUINT32_FORMAT,
                                                       route->lock_mtu ? "lock " : "",
                                                       route->mtu)
                                      : "",
        route->r_force_commit ? " force-commit" : "");

    if ((n_nexthops == 1 && route->ifindex > 0) || n_nexthops == 0) {
        /* A plain single hop route. Nothing extra to remark. */
    } else {
        nm_strbuf_append(&buf, &len, " n_nexthops %u", n_nexthops);
        if (n_nexthops > 1) {
            nm_strbuf_append(&buf,
                             &len,
                             " nexthop"
                             "%s%s"       /* gateway */
                             " weight %s" /* weight */
                             "%s"         /* dev/ifindex */
                             "",
                             s_gateway[0] ? " via " : "",
                             s_gateway,
                             nm_sprintf_buf(weight_str, "%u", route->weight),
                             _to_string_dev(str_dev, route->ifindex));
            if (!extra_nexthops)
                nm_strbuf_append_str(&buf, &len, " nexthops [...]");
            else {
                guint i;

                for (i = 1; i < n_nexthops; i++) {
                    const NMPlatformIP4RtNextHop *nexthop = &extra_nexthops[i - 1];

                    nm_strbuf_append(
                        &buf,
                        &len,
                        " nexthop"
                        "%s"         /* ifindex */
                        "%s%s"       /* gateway */
                        " weight %s" /* weight */
                        "",
                        NM_PRINT_FMT_QUOTED2(nexthop->gateway != 0 || nexthop->ifindex <= 0,
                                             " via ",
                                             nm_inet4_ntop(nexthop->gateway, s_gateway),
                                             ""),
                        _to_string_dev(str_dev, nexthop->ifindex),
                        nm_sprintf_buf(weight_str, "%u", nexthop->weight));
                }
            }
        }
    }
    return buf0;
}

/**
 * nm_platform_ip6_route_to_string:
 * @route: pointer to NMPlatformIP6Route route structure
 * @buf: (allow-none): an optional buffer. If %NULL, a static buffer is used.
 * @len: the size of the @buf. If @buf is %NULL, this argument is ignored.
 *
 * A method for converting a route struct into a string representation.
 *
 * Example output: "ff02::fb/128 via :: dev em1 metric 0"
 *
 * Returns: a string representation of the route.
 */
const char *
nm_platform_ip6_route_to_string(const NMPlatformIP6Route *route, char *buf, gsize len)
{
    char s_network[INET6_ADDRSTRLEN];
    char s_gateway[INET6_ADDRSTRLEN];
    char s_pref_src[INET6_ADDRSTRLEN];
    char s_src_all[INET6_ADDRSTRLEN + 40];
    char s_src[INET6_ADDRSTRLEN];
    char str_type[30];
    char str_table[30];
    char str_pref[40];
    char str_pref2[30];
    char str_dev[30];
    char str_mss[32];
    char s_source[50];
    char str_window[32];
    char str_cwnd[32];
    char str_initcwnd[32];
    char str_initrwnd[32];
    char str_rto_min[32];
    char str_mtu[32];
    char str_rtm_flags[_RTM_FLAGS_TO_STRING_MAXLEN];
    char str_metric[30];

    if (!nm_utils_to_string_buffer_init_null(route, &buf, &len))
        return buf;

    inet_ntop(AF_INET6, &route->network, s_network, sizeof(s_network));

    if (IN6_IS_ADDR_UNSPECIFIED(&route->gateway))
        s_gateway[0] = '\0';
    else
        inet_ntop(AF_INET6, &route->gateway, s_gateway, sizeof(s_gateway));

    if (IN6_IS_ADDR_UNSPECIFIED(&route->pref_src))
        s_pref_src[0] = 0;
    else
        inet_ntop(AF_INET6, &route->pref_src, s_pref_src, sizeof(s_pref_src));

    g_snprintf(
        buf,
        len,
        "type %s " /* type */
        "%s"       /* table */
        "%s/%d"
        "%s%s" /* gateway */
        "%s"
        " metric %s"
        "%s"         /* mss */
        " rt-src %s" /* protocol */
        "%s"         /* source */
        "%s"         /* rtm_flags */
        "%s%s"       /* pref-src */
        "%s"         /* window */
        "%s"         /* cwnd */
        "%s"         /* initcwnd */
        "%s"         /* initrwnd */
        "%s"         /* rto_min */
        "%s"         /* quickack */
        "%s"         /* mtu */
        "%s"         /* pref */
        "%s"         /* r_force_commit */
        "",
        nm_net_aux_rtnl_rtntype_n2a_maybe_buf(nm_platform_route_type_uncoerce(route->type_coerced),
                                              str_type),
        route->table_any
            ? "table ?? "
            : (route->table_coerced
                   ? nm_sprintf_buf(str_table,
                                    "table %u ",
                                    nm_platform_route_table_uncoerce(route->table_coerced, FALSE))
                   : ""),
        s_network,
        route->plen,
        s_gateway[0] ? " via " : "",
        s_gateway,
        _to_string_dev(str_dev, route->ifindex),
        route->metric_any
            ? (route->metric ? nm_sprintf_buf(str_metric, "??+%u", route->metric) : "??")
            : nm_sprintf_buf(str_metric, "%u", route->metric),
        nm_sprintf_buf(str_mss,
                       " mss %s%" G_GUINT32_FORMAT,
                       route->lock_mss ? "lock " : "",
                       route->mss),
        nmp_utils_ip_config_source_to_string(route->rt_source, s_source, sizeof(s_source)),
        route->src_plen || !IN6_IS_ADDR_UNSPECIFIED(&route->src)
            ? nm_sprintf_buf(s_src_all,
                             " src %s/%u",
                             nm_inet6_ntop(&route->src, s_src),
                             (unsigned) route->src_plen)
            : "",
        _rtm_flags_to_string_full(str_rtm_flags, sizeof(str_rtm_flags), route->r_rtm_flags),
        s_pref_src[0] ? " pref-src " : "",
        s_pref_src[0] ? s_pref_src : "",
        route->window || route->lock_window ? nm_sprintf_buf(str_window,
                                                             " window %s%" G_GUINT32_FORMAT,
                                                             route->lock_window ? "lock " : "",
                                                             route->window)
                                            : "",
        route->cwnd || route->lock_cwnd ? nm_sprintf_buf(str_cwnd,
                                                         " cwnd %s%" G_GUINT32_FORMAT,
                                                         route->lock_cwnd ? "lock " : "",
                                                         route->cwnd)
                                        : "",
        route->initcwnd || route->lock_initcwnd
            ? nm_sprintf_buf(str_initcwnd,
                             " initcwnd %s%" G_GUINT32_FORMAT,
                             route->lock_initcwnd ? "lock " : "",
                             route->initcwnd)
            : "",
        route->initrwnd || route->lock_initrwnd
            ? nm_sprintf_buf(str_initrwnd,
                             " initrwnd %s%" G_GUINT32_FORMAT,
                             route->lock_initrwnd ? "lock " : "",
                             route->initrwnd)
            : "",
        route->rto_min ? nm_sprintf_buf(str_rto_min, " rto_min %" G_GUINT32_FORMAT, route->rto_min)
                       : "",
        route->quickack ? " quickack 1" : "",
        route->mtu || route->lock_mtu ? nm_sprintf_buf(str_mtu,
                                                       " mtu %s%" G_GUINT32_FORMAT,
                                                       route->lock_mtu ? "lock " : "",
                                                       route->mtu)
                                      : "",
        route->rt_pref ? nm_sprintf_buf(
            str_pref,
            " pref %s",
            nm_icmpv6_router_pref_to_string(route->rt_pref, str_pref2, sizeof(str_pref2)))
                       : "",
        route->r_force_commit ? " force-commit" : "");

    return buf;
}

static void
_routing_rule_addr_to_string(char          **buf,
                             gsize          *len,
                             int             addr_family,
                             const NMIPAddr *addr,
                             guint8          plen,
                             gboolean        is_src)
{
    char     s_addr[NM_INET_ADDRSTRLEN];
    gboolean is_zero;
    gsize    addr_size;

    nm_assert_addr_family(addr_family);
    nm_assert(addr);

    addr_size = nm_utils_addr_family_to_size(addr_family);

    is_zero = nm_utils_memeqzero(addr, addr_size);

    if (plen == 0 && is_zero) {
        if (is_src)
            nm_strbuf_append_str(buf, len, " from all");
        else
            nm_strbuf_append_str(buf, len, "");
        return;
    }

    nm_strbuf_append_str(buf, len, is_src ? " from " : " to ");

    nm_strbuf_append_str(buf, len, nm_inet_ntop(addr_family, addr, s_addr));

    if (plen != (addr_size * 8))
        nm_strbuf_append(buf, len, "/%u", plen);
}

static void
_routing_rule_port_range_to_string(char                    **buf,
                                   gsize                    *len,
                                   const NMFibRulePortRange *port_range,
                                   const char               *name)
{
    if (port_range->start == 0 && port_range->end == 0)
        nm_strbuf_append_str(buf, len, "");
    else {
        nm_strbuf_append(buf, len, " %s %u", name, port_range->start);
        if (port_range->start != port_range->end)
            nm_strbuf_append(buf, len, "-%u", port_range->end);
    }
}

const char *
nm_platform_routing_rule_to_string(const NMPlatformRoutingRule *routing_rule, char *buf, gsize len)
{
    const char *buf0;
    guint32     rr_flags;

    if (!nm_utils_to_string_buffer_init_null(routing_rule, &buf, &len))
        return buf;

    if (!NM_IN_SET(routing_rule->addr_family, AF_INET, AF_INET6)) {
        /* invalid addr-family. The other fields are undefined. */
        if (routing_rule->addr_family == AF_UNSPEC)
            g_snprintf(buf, len, "[routing-rule]");
        else
            g_snprintf(buf, len, "[routing-rule family:%u]", routing_rule->addr_family);
        return buf;
    }

    buf0 = buf;

    rr_flags = routing_rule->flags;

    rr_flags = NM_FLAGS_UNSET(rr_flags, FIB_RULE_INVERT);
    nm_strbuf_append(&buf,
                     &len,
                     "[%c] " /* addr-family */
                     "%u:"   /* priority */
                     "%s",   /* not/FIB_RULE_INVERT */
                     nm_utils_addr_family_to_char(routing_rule->addr_family),
                     routing_rule->priority,
                     (NM_FLAGS_HAS(routing_rule->flags, FIB_RULE_INVERT) ? " not" : ""));

    _routing_rule_addr_to_string(&buf,
                                 &len,
                                 routing_rule->addr_family,
                                 &routing_rule->src,
                                 routing_rule->src_len,
                                 TRUE);

    _routing_rule_addr_to_string(&buf,
                                 &len,
                                 routing_rule->addr_family,
                                 &routing_rule->dst,
                                 routing_rule->dst_len,
                                 FALSE);

    if (routing_rule->tos)
        nm_strbuf_append(&buf, &len, " tos 0x%02x", routing_rule->tos);

    if (routing_rule->fwmark != 0 || routing_rule->fwmask != 0) {
        nm_strbuf_append(&buf, &len, " fwmark %#x", (unsigned) routing_rule->fwmark);
        if (routing_rule->fwmark != 0xFFFFFFFFu)
            nm_strbuf_append(&buf, &len, "/%#x", (unsigned) routing_rule->fwmask);
    }

    if (routing_rule->iifname[0]) {
        nm_strbuf_append(&buf, &len, " iif %s", routing_rule->iifname);
        rr_flags = NM_FLAGS_UNSET(rr_flags, FIB_RULE_IIF_DETACHED);
        if (NM_FLAGS_HAS(routing_rule->flags, FIB_RULE_IIF_DETACHED))
            nm_strbuf_append_str(&buf, &len, " [detached]");
    }

    if (routing_rule->oifname[0]) {
        nm_strbuf_append(&buf, &len, " oif %s", routing_rule->oifname);
        rr_flags = NM_FLAGS_UNSET(rr_flags, FIB_RULE_OIF_DETACHED);
        if (NM_FLAGS_HAS(routing_rule->flags, FIB_RULE_OIF_DETACHED))
            nm_strbuf_append_str(&buf, &len, " [detached]");
    }

    if (routing_rule->l3mdev != 0) {
        if (routing_rule->l3mdev == 1)
            nm_strbuf_append_str(&buf, &len, " lookup [l3mdev-table]");
        else {
            nm_strbuf_append(&buf,
                             &len,
                             " lookup [l3mdev-table/%u]",
                             (unsigned) routing_rule->l3mdev);
        }
    }

    if (routing_rule->uid_range_has || routing_rule->uid_range.start
        || routing_rule->uid_range.end) {
        nm_strbuf_append(&buf,
                         &len,
                         " uidrange %u-%u%s",
                         routing_rule->uid_range.start,
                         routing_rule->uid_range.end,
                         routing_rule->uid_range_has ? "" : "(?)");
    }

    if (routing_rule->ip_proto != 0) {
        /* we don't call getprotobynumber(), just print the numeric value.
         * This differs from what ip-rule prints. */
        nm_strbuf_append(&buf, &len, " ipproto %u", routing_rule->ip_proto);
    }

    _routing_rule_port_range_to_string(&buf, &len, &routing_rule->sport_range, "sport");

    _routing_rule_port_range_to_string(&buf, &len, &routing_rule->dport_range, "dport");

    if (routing_rule->tun_id != 0) {
        nm_strbuf_append(&buf, &len, " tun_id %" G_GUINT64_FORMAT, routing_rule->tun_id);
    }

    if (routing_rule->table != 0) {
        nm_strbuf_append(&buf, &len, " lookup %u", routing_rule->table);
    }

    if (routing_rule->suppress_prefixlen_inverse != 0) {
        nm_strbuf_append(&buf,
                         &len,
                         " suppress_prefixlen %d",
                         (int) (~routing_rule->suppress_prefixlen_inverse));
    }

    if (routing_rule->suppress_ifgroup_inverse != 0) {
        nm_strbuf_append(&buf,
                         &len,
                         " suppress_ifgroup %d",
                         (int) (~routing_rule->suppress_ifgroup_inverse));
    }

    if (routing_rule->flow) {
        /* FRA_FLOW is only for IPv4, but we want to print the value for all address-families,
         * to see when it is set. In practice, this should not be set except for IPv4.
         *
         * We don't follow the style how ip-rule prints flow/realms. It's confusing. Just
         * print the value hex. */
        nm_strbuf_append(&buf, &len, " realms 0x%08x", routing_rule->flow);
    }

    if (routing_rule->action == RTN_NAT) {
        G_STATIC_ASSERT_EXPR(RTN_NAT == 10);

        /* NAT is deprecated for many years. We don't support RTA_GATEWAY/FRA_UNUSED2
         * for the gateway, and so do recent kernels ignore that parameter. */
        nm_strbuf_append_str(&buf, &len, " masquerade");
    } else if (routing_rule->action == FR_ACT_GOTO) {
        if (routing_rule->goto_target != 0)
            nm_strbuf_append(&buf, &len, " goto %u", routing_rule->goto_target);
        else
            nm_strbuf_append_str(&buf, &len, " goto none");
        rr_flags = NM_FLAGS_UNSET(rr_flags, FIB_RULE_UNRESOLVED);
        if (NM_FLAGS_HAS(routing_rule->flags, FIB_RULE_UNRESOLVED))
            nm_strbuf_append_str(&buf, &len, " unresolved");
    } else if (routing_rule->action != FR_ACT_TO_TBL) {
        char ss_buf[60];

        nm_strbuf_append(&buf,
                         &len,
                         " %s",
                         nm_net_aux_rtnl_rtntype_n2a(routing_rule->action)
                             ?: nm_sprintf_buf(ss_buf, "action-%u", routing_rule->action));
    }

    if (routing_rule->protocol != RTPROT_UNSPEC)
        nm_strbuf_append(&buf, &len, " protocol %u", routing_rule->protocol);

    if (routing_rule->goto_target != 0 && routing_rule->action != FR_ACT_GOTO) {
        /* a trailing target is set for an unexpected action. Print it. */
        nm_strbuf_append(&buf, &len, " goto-target %u", routing_rule->goto_target);
    }

    if (rr_flags != 0) {
        /* we have some flags we didn't print about yet. */
        nm_strbuf_append(&buf, &len, " remaining-flags %x", rr_flags);
    }

    return buf0;
}

const char *
nm_platform_qdisc_to_string(const NMPlatformQdisc *qdisc, char *buf, gsize len)
{
    char        str_dev[30];
    const char *buf0;

    if (!nm_utils_to_string_buffer_init_null(qdisc, &buf, &len))
        return buf;

    buf0 = buf;

    nm_strbuf_append(&buf,
                     &len,
                     "%s%s family %u handle %x parent %x info %x",
                     qdisc->kind,
                     _to_string_dev(str_dev, qdisc->ifindex),
                     qdisc->addr_family,
                     qdisc->handle,
                     qdisc->parent,
                     qdisc->info);

    if (nm_streq0(qdisc->kind, "fq_codel")) {
        if (qdisc->fq_codel.limit)
            nm_strbuf_append(&buf, &len, " limit %u", qdisc->fq_codel.limit);
        if (qdisc->fq_codel.flows)
            nm_strbuf_append(&buf, &len, " flows %u", qdisc->fq_codel.flows);
        if (qdisc->fq_codel.target)
            nm_strbuf_append(&buf, &len, " target %u", qdisc->fq_codel.target);
        if (qdisc->fq_codel.interval)
            nm_strbuf_append(&buf, &len, " interval %u", qdisc->fq_codel.interval);
        if (qdisc->fq_codel.quantum)
            nm_strbuf_append(&buf, &len, " quantum %u", qdisc->fq_codel.quantum);
        if (qdisc->fq_codel.ce_threshold != NM_PLATFORM_FQ_CODEL_CE_THRESHOLD_DISABLED)
            nm_strbuf_append(&buf, &len, " ce_threshold %u", qdisc->fq_codel.ce_threshold);
        if (qdisc->fq_codel.memory_limit != NM_PLATFORM_FQ_CODEL_MEMORY_LIMIT_UNSET)
            nm_strbuf_append(&buf, &len, " memory_limit %u", qdisc->fq_codel.memory_limit);
        if (qdisc->fq_codel.ecn)
            nm_strbuf_append(&buf, &len, " ecn");
    } else if (nm_streq0(qdisc->kind, "sfq")) {
        if (qdisc->sfq.quantum)
            nm_strbuf_append(&buf, &len, " quantum %u", qdisc->sfq.quantum);
        if (qdisc->sfq.perturb_period)
            nm_strbuf_append(&buf, &len, " perturb %d", qdisc->sfq.perturb_period);
        if (qdisc->sfq.limit)
            nm_strbuf_append(&buf, &len, " limit %u", (guint) qdisc->sfq.limit);
        if (qdisc->sfq.divisor)
            nm_strbuf_append(&buf, &len, " divisor %u", qdisc->sfq.divisor);
        if (qdisc->sfq.flows)
            nm_strbuf_append(&buf, &len, " flows %u", qdisc->sfq.flows);
        if (qdisc->sfq.depth)
            nm_strbuf_append(&buf, &len, " depth %u", qdisc->sfq.depth);
    } else if (nm_streq0(qdisc->kind, "tbf")) {
        nm_strbuf_append(&buf, &len, " rate %" G_GUINT64_FORMAT, qdisc->tbf.rate);
        nm_strbuf_append(&buf, &len, " burst %u", qdisc->tbf.burst);
        if (qdisc->tbf.limit)
            nm_strbuf_append(&buf, &len, " limit %u", qdisc->tbf.limit);
        if (qdisc->tbf.latency)
            nm_strbuf_append(&buf, &len, " latency %uns", qdisc->tbf.latency);
    }

    return buf0;
}

void
nm_platform_qdisc_hash_update(const NMPlatformQdisc *obj, NMHashState *h)
{
    nm_hash_update_str0(h, obj->kind);
    nm_hash_update_vals(h, obj->ifindex, obj->addr_family, obj->handle, obj->parent, obj->info);
    if (nm_streq0(obj->kind, "fq_codel")) {
        nm_hash_update_vals(h,
                            obj->fq_codel.limit,
                            obj->fq_codel.flows,
                            obj->fq_codel.target,
                            obj->fq_codel.interval,
                            obj->fq_codel.quantum,
                            obj->fq_codel.ce_threshold,
                            obj->fq_codel.memory_limit,
                            NM_HASH_COMBINE_BOOLS(guint8, obj->fq_codel.ecn));
    } else if (nm_streq0(obj->kind, "sfq")) {
        nm_hash_update_vals(h,
                            obj->sfq.quantum,
                            obj->sfq.perturb_period,
                            obj->sfq.limit,
                            obj->sfq.divisor,
                            obj->sfq.flows,
                            obj->sfq.depth);
    } else if (nm_streq0(obj->kind, "tbf")) {
        nm_hash_update_vals(h, obj->tbf.rate, obj->tbf.burst, obj->tbf.limit, obj->tbf.latency);
    }
}

int
nm_platform_qdisc_cmp(const NMPlatformQdisc *a, const NMPlatformQdisc *b, gboolean compare_handle)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, ifindex);
    NM_CMP_FIELD(a, b, parent);
    NM_CMP_FIELD_STR_INTERNED(a, b, kind);
    NM_CMP_FIELD(a, b, addr_family);
    if (compare_handle)
        NM_CMP_FIELD(a, b, handle);
    NM_CMP_FIELD(a, b, info);

    if (nm_streq0(a->kind, "fq_codel")) {
        NM_CMP_FIELD(a, b, fq_codel.limit);
        NM_CMP_FIELD(a, b, fq_codel.flows);
        NM_CMP_FIELD(a, b, fq_codel.target);
        NM_CMP_FIELD(a, b, fq_codel.interval);
        NM_CMP_FIELD(a, b, fq_codel.quantum);
        NM_CMP_FIELD(a, b, fq_codel.ce_threshold);
        NM_CMP_FIELD(a, b, fq_codel.memory_limit);
        NM_CMP_FIELD_UNSAFE(a, b, fq_codel.ecn);
    } else if (nm_streq0(a->kind, "sfq")) {
        NM_CMP_FIELD(a, b, sfq.quantum);
        NM_CMP_FIELD(a, b, sfq.perturb_period);
        NM_CMP_FIELD(a, b, sfq.limit);
        NM_CMP_FIELD(a, b, sfq.flows);
        NM_CMP_FIELD(a, b, sfq.divisor);
        NM_CMP_FIELD(a, b, sfq.depth);
    } else if (nm_streq0(a->kind, "tbf")) {
        NM_CMP_FIELD(a, b, tbf.rate);
        NM_CMP_FIELD(a, b, tbf.burst);
        NM_CMP_FIELD(a, b, tbf.limit);
        NM_CMP_FIELD(a, b, tbf.latency);
    }

    return 0;
}

const char *
nm_platform_tfilter_to_string(const NMPlatformTfilter *tfilter, char *buf, gsize len)
{
    char  str_dev[30];
    char  act_buf[300];
    char *p;
    gsize l;

    if (!nm_utils_to_string_buffer_init_null(tfilter, &buf, &len))
        return buf;

    if (tfilter->action.kind) {
        p = act_buf;
        l = sizeof(act_buf);

        nm_strbuf_append(&p, &l, " \"%s\"", tfilter->action.kind);
        if (nm_streq(tfilter->action.kind, NM_PLATFORM_ACTION_KIND_SIMPLE)) {
            gs_free char *t = NULL;

            nm_strbuf_append(
                &p,
                &l,
                " (\"%s\")",
                nm_utils_str_utf8safe_escape(tfilter->action.kind,
                                             NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL
                                                 | NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII,
                                             &t));
        } else if (nm_streq(tfilter->action.kind, NM_PLATFORM_ACTION_KIND_MIRRED)) {
            nm_strbuf_append(&p,
                             &l,
                             "%s%s%s%s dev %d",
                             tfilter->action.mirred.ingress ? " ingress" : "",
                             tfilter->action.mirred.egress ? " egress" : "",
                             tfilter->action.mirred.mirror ? " mirror" : "",
                             tfilter->action.mirred.redirect ? " redirect" : "",
                             tfilter->action.mirred.ifindex);
        }
    } else
        act_buf[0] = '\0';

    g_snprintf(buf,
               len,
               "%s%s family %u handle %x parent %x info %x%s",
               tfilter->kind,
               _to_string_dev(str_dev, tfilter->ifindex),
               tfilter->addr_family,
               tfilter->handle,
               tfilter->parent,
               tfilter->info,
               act_buf);

    return buf;
}

void
nm_platform_tfilter_hash_update(const NMPlatformTfilter *obj, NMHashState *h)
{
    nm_hash_update_str0(h, obj->kind);
    nm_hash_update_vals(h, obj->ifindex, obj->addr_family, obj->handle, obj->parent, obj->info);
    if (obj->action.kind) {
        nm_hash_update_str(h, obj->action.kind);
        if (nm_streq(obj->action.kind, NM_PLATFORM_ACTION_KIND_SIMPLE)) {
            nm_hash_update_strarr(h, obj->action.simple.sdata);
        } else if (nm_streq(obj->action.kind, NM_PLATFORM_ACTION_KIND_MIRRED)) {
            nm_hash_update_vals(h,
                                obj->action.mirred.ifindex,
                                NM_HASH_COMBINE_BOOLS(guint8,
                                                      obj->action.mirred.ingress,
                                                      obj->action.mirred.egress,
                                                      obj->action.mirred.mirror,
                                                      obj->action.mirred.redirect));
        }
    }
}

int
nm_platform_tfilter_cmp(const NMPlatformTfilter *a, const NMPlatformTfilter *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, ifindex);
    NM_CMP_FIELD(a, b, parent);
    NM_CMP_FIELD_STR_INTERNED(a, b, kind);
    NM_CMP_FIELD(a, b, addr_family);
    NM_CMP_FIELD(a, b, handle);
    NM_CMP_FIELD(a, b, info);

    NM_CMP_FIELD_STR_INTERNED(a, b, action.kind);
    if (a->action.kind) {
        if (nm_streq(a->action.kind, NM_PLATFORM_ACTION_KIND_SIMPLE)) {
            NM_CMP_FIELD_STR(a, b, action.simple.sdata);
        } else if (nm_streq(a->action.kind, NM_PLATFORM_ACTION_KIND_MIRRED)) {
            NM_CMP_FIELD(a, b, action.mirred.ifindex);
            NM_CMP_FIELD_UNSAFE(a, b, action.mirred.ingress);
            NM_CMP_FIELD_UNSAFE(a, b, action.mirred.egress);
            NM_CMP_FIELD_UNSAFE(a, b, action.mirred.mirror);
            NM_CMP_FIELD_UNSAFE(a, b, action.mirred.redirect);
        }
    }

    return 0;
}

static NM_UTILS_FLAGS2STR_DEFINE(_mptcp_flags_to_string,
                                 guint32,
                                 NM_UTILS_FLAGS2STR(NM_MPTCP_PM_ADDR_FLAG_SIGNAL, "signal"),
                                 NM_UTILS_FLAGS2STR(NM_MPTCP_PM_ADDR_FLAG_SUBFLOW, "subflow"),
                                 NM_UTILS_FLAGS2STR(NM_MPTCP_PM_ADDR_FLAG_BACKUP, "backup"),
                                 NM_UTILS_FLAGS2STR(NM_MPTCP_PM_ADDR_FLAG_FULLMESH, "fullmesh"));

const char *
nm_platform_mptcp_addr_to_string(const NMPlatformMptcpAddr *mptcp_addr, char *buf, gsize len)
{
    char str_addr[30 + NM_INET_ADDRSTRLEN];
    char str_port[30];
    char str_id[30];
    char str_flags[200];
    char str_flags2[30 + sizeof(str_flags)];
    char str_ifindex[30];

    if (!nm_utils_to_string_buffer_init_null(mptcp_addr, &buf, &len))
        return buf;

    if (mptcp_addr->addr_family == 0)
        nm_sprintf_buf(str_addr, "no-addr");
    else if (NM_IN_SET(mptcp_addr->addr_family, AF_INET, AF_INET6))
        nm_inet_ntop(mptcp_addr->addr_family, &mptcp_addr->addr, str_addr);
    else
        nm_sprintf_buf(str_addr, "af %d", mptcp_addr->addr_family);

    if (mptcp_addr->flags != 0)
        _mptcp_flags_to_string(mptcp_addr->flags, str_flags, sizeof(str_flags));
    else
        str_flags[0] = '\0';

    g_snprintf(buf,
               len,
               "%s" /* address */
               "%s" /* port */
               "%s" /* id */
               "%s" /* flags */
               "%s" /* ifindex */
               "",
               str_addr,
               mptcp_addr->port == 0 ? "" : nm_sprintf_buf(str_port, " port %u", mptcp_addr->port),
               mptcp_addr->id == 0 ? "" : nm_sprintf_buf(str_id, " id %u", mptcp_addr->id),
               str_flags[0] == '\0' ? "" : nm_sprintf_buf(str_flags2, " flags %s", str_flags),
               mptcp_addr->ifindex == 0
                   ? ""
                   : nm_sprintf_buf(str_ifindex, " ifindex %d", mptcp_addr->ifindex));
    return buf;
}

void
nm_platform_mptcp_addr_hash_update(const NMPlatformMptcpAddr *obj, NMHashState *h)
{
    nm_assert(obj);
    nm_assert_addr_family_or_unspec(obj->addr_family);

    nm_hash_update_vals(h, obj->id, obj->flags, obj->port, obj->addr_family, obj->ifindex);
    if (NM_IN_SET(obj->addr_family, AF_INET, AF_INET6))
        nm_hash_update(h, &obj->addr, nm_utils_addr_family_to_size(obj->addr_family));
}

int
nm_platform_mptcp_addr_cmp(const NMPlatformMptcpAddr *a, const NMPlatformMptcpAddr *b)
{
    NM_CMP_SELF(a, b);

    nm_assert_addr_family_or_unspec(a->addr_family);
    nm_assert_addr_family_or_unspec(b->addr_family);

    NM_CMP_FIELD(a, b, ifindex);
    NM_CMP_FIELD(a, b, id);
    NM_CMP_FIELD(a, b, addr_family);
    if (NM_IN_SET(a->addr_family, AF_INET, AF_INET6))
        NM_CMP_FIELD_MEMCMP_LEN(a, b, addr, nm_utils_addr_family_to_size(a->addr_family));
    NM_CMP_FIELD(a, b, port);

    return 0;
}

guint
nm_platform_mptcp_addr_index_addr_cmp(gconstpointer data)
{
    const NMPlatformMptcpAddr *mptcp_addr = data;
    NMHashState                h;

    nm_hash_init(&h, 1408914077u);
    nm_hash_update_val(&h, mptcp_addr->addr_family);
    nm_hash_update(&h, &mptcp_addr->addr, nm_utils_addr_family_to_size(mptcp_addr->addr_family));
    return nm_hash_complete(&h);
}

gboolean
nm_platform_mptcp_addr_index_addr_equal(gconstpointer data_a, gconstpointer data_b)
{
    const NMPlatformMptcpAddr *mptcp_addr_a = data_a;
    const NMPlatformMptcpAddr *mptcp_addr_b = data_b;

    return mptcp_addr_a->addr_family == mptcp_addr_b->addr_family
           && nm_ip_addr_equal(mptcp_addr_a->addr_family, &mptcp_addr_a->addr, &mptcp_addr_b->addr);
}

const char *
nm_platform_vf_to_string(const NMPlatformVF *vf, char *buf, gsize len)
{
    char                          str_mac[128], mac[128];
    char                          str_spoof_check[64];
    char                          str_trust[64];
    char                          str_min_tx_rate[64];
    char                          str_max_tx_rate[64];
    nm_auto_free_gstring GString *gstr_vlans = NULL;
    guint                         i;

    if (!nm_utils_to_string_buffer_init_null(vf, &buf, &len))
        return buf;

    if (vf->mac.len) {
        _nm_utils_hwaddr_ntoa(vf->mac.data, vf->mac.len, TRUE, mac, sizeof(mac));
        nm_sprintf_buf(str_mac, " mac %s", mac);
    } else
        str_mac[0] = '\0';

    if (vf->num_vlans) {
        gstr_vlans = g_string_new("");
        for (i = 0; i < vf->num_vlans; i++) {
            g_string_append_printf(gstr_vlans, " vlan %u", (unsigned) vf->vlans[i].id);
            if (vf->vlans[i].qos)
                g_string_append_printf(gstr_vlans, " qos %u", (unsigned) vf->vlans[i].qos);
            if (vf->vlans[i].proto_ad)
                g_string_append(gstr_vlans, " proto 802.1ad");
        }
    }

    g_snprintf(buf,
               len,
               "%u"  /* index */
               "%s"  /* MAC */
               "%s"  /* spoof check */
               "%s"  /* trust */
               "%s"  /* min tx rate */
               "%s"  /* max tx rate */
               "%s", /* VLANs */
               vf->index,
               str_mac,
               vf->spoofchk >= 0 ? nm_sprintf_buf(str_spoof_check, " spoofchk %d", vf->spoofchk)
                                 : "",
               vf->trust >= 0 ? nm_sprintf_buf(str_trust, " trust %d", vf->trust) : "",
               vf->min_tx_rate
                   ? nm_sprintf_buf(str_min_tx_rate, " min_tx_rate %u", (unsigned) vf->min_tx_rate)
                   : "",
               vf->max_tx_rate
                   ? nm_sprintf_buf(str_max_tx_rate, " max_tx_rate %u", (unsigned) vf->max_tx_rate)
                   : "",
               gstr_vlans ? gstr_vlans->str : "");

    return buf;
}

const char *
nm_platform_bridge_vlan_to_string(const NMPlatformBridgeVlan *vlan, char *buf, gsize len)
{
    char str_vid_end[64];

    if (!nm_utils_to_string_buffer_init_null(vlan, &buf, &len))
        return buf;

    g_snprintf(buf,
               len,
               "%u"
               "%s"
               "%s"
               "%s",
               vlan->vid_start,
               vlan->vid_start != vlan->vid_end ? nm_sprintf_buf(str_vid_end, "-%u", vlan->vid_end)
                                                : "",
               vlan->pvid ? " PVID" : "",
               vlan->untagged ? " untagged" : "");

    return buf;
}

void
nm_platform_link_hash_update(const NMPlatformLink *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->ifindex,
                        obj->master,
                        obj->parent,
                        obj->n_ifi_flags,
                        obj->mtu,
                        obj->type,
                        obj->arptype,
                        obj->inet6_addr_gen_mode_inv,
                        obj->inet6_token,
                        obj->rx_packets,
                        obj->rx_bytes,
                        obj->tx_packets,
                        obj->tx_bytes,
                        NM_HASH_COMBINE_BOOLS(guint8, obj->connected, obj->initialized));
    nm_hash_update_strarr(h, obj->name);
    nm_hash_update_str0(h, obj->kind);
    nm_hash_update_str0(h, obj->driver);
    /* nm_hash_update_mem() also hashes the length obj->addr.len */
    nm_hash_update_mem(h,
                       obj->l_address.data,
                       NM_MIN(obj->l_address.len, sizeof(obj->l_address.data)));
    nm_hash_update_mem(h,
                       obj->l_perm_address.data,
                       NM_MIN(obj->l_perm_address.len, sizeof(obj->l_perm_address.data)));
    nm_hash_update_mem(h,
                       obj->l_broadcast.data,
                       NM_MIN(obj->l_broadcast.len, sizeof(obj->l_broadcast.data)));
}

int
nm_platform_link_cmp(const NMPlatformLink *a, const NMPlatformLink *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, ifindex);
    NM_CMP_FIELD(a, b, type);
    NM_CMP_FIELD_STR(a, b, name);
    NM_CMP_FIELD(a, b, master);
    NM_CMP_FIELD(a, b, parent);
    NM_CMP_FIELD(a, b, n_ifi_flags);
    NM_CMP_FIELD_UNSAFE(a, b, connected);
    NM_CMP_FIELD(a, b, mtu);
    NM_CMP_FIELD_BOOL(a, b, initialized);
    NM_CMP_FIELD(a, b, arptype);
    NM_CMP_FIELD(a, b, l_address.len);
    NM_CMP_FIELD(a, b, l_perm_address.len);
    NM_CMP_FIELD(a, b, l_broadcast.len);
    NM_CMP_FIELD(a, b, inet6_addr_gen_mode_inv);
    NM_CMP_FIELD_STR_INTERNED(a, b, kind);
    NM_CMP_FIELD_STR_INTERNED(a, b, driver);
    if (a->l_address.len)
        NM_CMP_FIELD_MEMCMP_LEN(a, b, l_address.data, a->l_address.len);
    if (a->l_perm_address.len)
        NM_CMP_FIELD_MEMCMP_LEN(a, b, l_perm_address.data, a->l_perm_address.len);
    if (a->l_broadcast.len)
        NM_CMP_FIELD_MEMCMP_LEN(a, b, l_broadcast.data, a->l_broadcast.len);
    NM_CMP_FIELD_MEMCMP(a, b, inet6_token);
    NM_CMP_FIELD(a, b, rx_packets);
    NM_CMP_FIELD(a, b, rx_bytes);
    NM_CMP_FIELD(a, b, tx_packets);
    NM_CMP_FIELD(a, b, tx_bytes);
    return 0;
}

void
nm_platform_lnk_bridge_hash_update(const NMPlatformLnkBridge *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->forward_delay,
                        obj->hello_time,
                        obj->max_age,
                        obj->ageing_time,
                        obj->priority,
                        obj->vlan_protocol,
                        obj->group_fwd_mask,
                        obj->group_addr,
                        obj->mcast_hash_max,
                        obj->mcast_last_member_count,
                        obj->mcast_startup_query_count,
                        obj->mcast_last_member_interval,
                        obj->mcast_membership_interval,
                        obj->mcast_querier_interval,
                        obj->mcast_query_interval,
                        obj->mcast_router,
                        obj->mcast_query_response_interval,
                        obj->mcast_startup_query_interval,
                        NM_HASH_COMBINE_BOOLS(guint8,
                                              obj->stp_state,
                                              obj->mcast_querier,
                                              obj->mcast_query_use_ifaddr,
                                              obj->mcast_snooping,
                                              obj->vlan_stats_enabled));
}

void
nm_platform_lnk_bond_hash_update(const NMPlatformLnkBond *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->arp_all_targets,
                        obj->arp_interval,
                        obj->arp_validate,
                        obj->downdelay,
                        obj->lp_interval,
                        obj->miimon,
                        obj->min_links,
                        obj->packets_per_port,
                        obj->peer_notif_delay,
                        obj->primary,
                        obj->resend_igmp,
                        obj->updelay,
                        obj->ad_actor_sys_prio,
                        obj->ad_user_port_key,
                        obj->ad_actor_system,
                        obj->ad_select,
                        obj->all_ports_active,
                        obj->arp_ip_targets_num,
                        obj->fail_over_mac,
                        obj->lacp_rate,
                        obj->num_grat_arp,
                        obj->mode,
                        obj->primary_reselect,
                        obj->xmit_hash_policy,
                        NM_HASH_COMBINE_BOOLS(guint16,
                                              obj->downdelay_has,
                                              obj->lp_interval_has,
                                              obj->miimon_has,
                                              obj->peer_notif_delay_has,
                                              obj->resend_igmp_has,
                                              obj->tlb_dynamic_lb,
                                              obj->tlb_dynamic_lb_has,
                                              obj->updelay_has,
                                              obj->use_carrier));

    nm_hash_update(h, obj->arp_ip_target, obj->arp_ip_targets_num * sizeof(obj->arp_ip_target[0]));
}

int
nm_platform_lnk_bond_cmp(const NMPlatformLnkBond *a, const NMPlatformLnkBond *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, arp_ip_targets_num);
    NM_CMP_FIELD_MEMCMP_LEN(a,
                            b,
                            arp_ip_target,
                            a->arp_ip_targets_num * sizeof(a->arp_ip_target[0]));
    NM_CMP_FIELD(a, b, arp_all_targets);
    NM_CMP_FIELD(a, b, arp_interval);
    NM_CMP_FIELD(a, b, arp_validate);
    NM_CMP_FIELD(a, b, downdelay);
    NM_CMP_FIELD(a, b, lp_interval);
    NM_CMP_FIELD(a, b, miimon);
    NM_CMP_FIELD(a, b, min_links);
    NM_CMP_FIELD(a, b, packets_per_port);
    NM_CMP_FIELD(a, b, peer_notif_delay);
    NM_CMP_FIELD(a, b, primary);
    NM_CMP_FIELD(a, b, resend_igmp);
    NM_CMP_FIELD(a, b, updelay);
    NM_CMP_FIELD(a, b, ad_actor_sys_prio);
    NM_CMP_FIELD(a, b, ad_user_port_key);
    NM_CMP_FIELD_MEMCMP(a, b, ad_actor_system);
    NM_CMP_FIELD(a, b, ad_select);
    NM_CMP_FIELD(a, b, all_ports_active);
    NM_CMP_FIELD(a, b, fail_over_mac);
    NM_CMP_FIELD(a, b, lacp_rate);
    NM_CMP_FIELD(a, b, num_grat_arp);
    NM_CMP_FIELD(a, b, mode);
    NM_CMP_FIELD(a, b, primary_reselect);
    NM_CMP_FIELD(a, b, xmit_hash_policy);
    NM_CMP_FIELD_BOOL(a, b, downdelay_has);
    NM_CMP_FIELD_BOOL(a, b, lp_interval_has);
    NM_CMP_FIELD_BOOL(a, b, miimon_has);
    NM_CMP_FIELD_BOOL(a, b, peer_notif_delay_has);
    NM_CMP_FIELD_BOOL(a, b, resend_igmp_has);
    NM_CMP_FIELD_BOOL(a, b, tlb_dynamic_lb);
    NM_CMP_FIELD_BOOL(a, b, tlb_dynamic_lb_has);
    NM_CMP_FIELD_BOOL(a, b, updelay_has);
    NM_CMP_FIELD_BOOL(a, b, use_carrier);

    return 0;
}

int
nm_platform_lnk_bridge_cmp(const NMPlatformLnkBridge *a, const NMPlatformLnkBridge *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, forward_delay);
    NM_CMP_FIELD(a, b, hello_time);
    NM_CMP_FIELD(a, b, max_age);
    NM_CMP_FIELD(a, b, ageing_time);
    NM_CMP_FIELD_BOOL(a, b, stp_state);
    NM_CMP_FIELD(a, b, priority);
    NM_CMP_FIELD(a, b, vlan_protocol);
    NM_CMP_FIELD_BOOL(a, b, vlan_stats_enabled);
    NM_CMP_FIELD(a, b, group_fwd_mask);
    NM_CMP_FIELD_MEMCMP(a, b, group_addr);
    NM_CMP_FIELD_BOOL(a, b, mcast_snooping);
    NM_CMP_FIELD(a, b, mcast_router);
    NM_CMP_FIELD_BOOL(a, b, mcast_query_use_ifaddr);
    NM_CMP_FIELD_BOOL(a, b, mcast_querier);
    NM_CMP_FIELD(a, b, mcast_hash_max);
    NM_CMP_FIELD(a, b, mcast_last_member_count);
    NM_CMP_FIELD(a, b, mcast_startup_query_count);
    NM_CMP_FIELD(a, b, mcast_last_member_interval);
    NM_CMP_FIELD(a, b, mcast_membership_interval);
    NM_CMP_FIELD(a, b, mcast_querier_interval);
    NM_CMP_FIELD(a, b, mcast_query_interval);
    NM_CMP_FIELD(a, b, mcast_query_response_interval);
    NM_CMP_FIELD(a, b, mcast_startup_query_interval);

    return 0;
}

void
nm_platform_lnk_gre_hash_update(const NMPlatformLnkGre *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->local,
                        obj->remote,
                        obj->parent_ifindex,
                        obj->input_flags,
                        obj->output_flags,
                        obj->input_key,
                        obj->output_key,
                        obj->ttl,
                        obj->tos,
                        (bool) obj->path_mtu_discovery,
                        (bool) obj->is_tap);
}

int
nm_platform_lnk_gre_cmp(const NMPlatformLnkGre *a, const NMPlatformLnkGre *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, parent_ifindex);
    NM_CMP_FIELD(a, b, input_flags);
    NM_CMP_FIELD(a, b, output_flags);
    NM_CMP_FIELD(a, b, input_key);
    NM_CMP_FIELD(a, b, output_key);
    NM_CMP_FIELD(a, b, local);
    NM_CMP_FIELD(a, b, remote);
    NM_CMP_FIELD(a, b, ttl);
    NM_CMP_FIELD(a, b, tos);
    NM_CMP_FIELD_BOOL(a, b, path_mtu_discovery);
    NM_CMP_FIELD_BOOL(a, b, is_tap);
    return 0;
}

void
nm_platform_lnk_infiniband_hash_update(const NMPlatformLnkInfiniband *obj, NMHashState *h)
{
    nm_hash_update_val(h, obj->p_key);
    nm_hash_update_str0(h, obj->mode);
}

int
nm_platform_lnk_infiniband_cmp(const NMPlatformLnkInfiniband *a, const NMPlatformLnkInfiniband *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, p_key);
    NM_CMP_FIELD_STR_INTERNED(a, b, mode);
    return 0;
}

void
nm_platform_lnk_ip6tnl_hash_update(const NMPlatformLnkIp6Tnl *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->local,
                        obj->remote,
                        obj->parent_ifindex,
                        obj->ttl,
                        obj->tclass,
                        obj->encap_limit,
                        obj->proto,
                        obj->flow_label,
                        obj->flags,
                        obj->input_flags,
                        obj->output_flags,
                        obj->input_key,
                        obj->output_key,
                        (bool) obj->is_gre,
                        (bool) obj->is_tap);
}

int
nm_platform_lnk_ip6tnl_cmp(const NMPlatformLnkIp6Tnl *a, const NMPlatformLnkIp6Tnl *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, parent_ifindex);
    NM_CMP_FIELD_MEMCMP(a, b, local);
    NM_CMP_FIELD_MEMCMP(a, b, remote);
    NM_CMP_FIELD(a, b, ttl);
    NM_CMP_FIELD(a, b, tclass);
    NM_CMP_FIELD(a, b, encap_limit);
    NM_CMP_FIELD(a, b, flow_label);
    NM_CMP_FIELD(a, b, proto);
    NM_CMP_FIELD(a, b, flags);
    NM_CMP_FIELD(a, b, input_flags);
    NM_CMP_FIELD(a, b, output_flags);
    NM_CMP_FIELD(a, b, input_key);
    NM_CMP_FIELD(a, b, output_key);
    NM_CMP_FIELD_BOOL(a, b, is_gre);
    NM_CMP_FIELD_BOOL(a, b, is_tap);
    return 0;
}

void
nm_platform_lnk_ipip_hash_update(const NMPlatformLnkIpIp *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->local,
                        obj->remote,
                        obj->parent_ifindex,
                        obj->ttl,
                        obj->tos,
                        (bool) obj->path_mtu_discovery);
}

int
nm_platform_lnk_ipip_cmp(const NMPlatformLnkIpIp *a, const NMPlatformLnkIpIp *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, parent_ifindex);
    NM_CMP_FIELD(a, b, local);
    NM_CMP_FIELD(a, b, remote);
    NM_CMP_FIELD(a, b, ttl);
    NM_CMP_FIELD(a, b, tos);
    NM_CMP_FIELD_BOOL(a, b, path_mtu_discovery);
    return 0;
}

void
nm_platform_lnk_macsec_hash_update(const NMPlatformLnkMacsec *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->sci,
                        obj->cipher_suite,
                        obj->window,
                        obj->icv_length,
                        obj->encoding_sa,
                        obj->validation,
                        NM_HASH_COMBINE_BOOLS(guint8,
                                              obj->encrypt,
                                              obj->protect,
                                              obj->include_sci,
                                              obj->es,
                                              obj->scb,
                                              obj->replay_protect));
}

int
nm_platform_lnk_macsec_cmp(const NMPlatformLnkMacsec *a, const NMPlatformLnkMacsec *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, sci);
    NM_CMP_FIELD(a, b, icv_length);
    NM_CMP_FIELD(a, b, cipher_suite);
    NM_CMP_FIELD(a, b, window);
    NM_CMP_FIELD(a, b, encoding_sa);
    NM_CMP_FIELD(a, b, validation);
    NM_CMP_FIELD_UNSAFE(a, b, encrypt);
    NM_CMP_FIELD_UNSAFE(a, b, protect);
    NM_CMP_FIELD_UNSAFE(a, b, include_sci);
    NM_CMP_FIELD_UNSAFE(a, b, es);
    NM_CMP_FIELD_UNSAFE(a, b, scb);
    NM_CMP_FIELD_UNSAFE(a, b, replay_protect);
    return 0;
}

void
nm_platform_lnk_macvlan_hash_update(const NMPlatformLnkMacvlan *obj, NMHashState *h)
{
    nm_hash_update_vals(h, obj->mode, NM_HASH_COMBINE_BOOLS(guint8, obj->no_promisc, obj->tap));
}

int
nm_platform_lnk_macvlan_cmp(const NMPlatformLnkMacvlan *a, const NMPlatformLnkMacvlan *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, mode);
    NM_CMP_FIELD_UNSAFE(a, b, no_promisc);
    NM_CMP_FIELD_UNSAFE(a, b, tap);
    return 0;
}

void
nm_platform_lnk_sit_hash_update(const NMPlatformLnkSit *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->local,
                        obj->remote,
                        obj->parent_ifindex,
                        obj->flags,
                        obj->ttl,
                        obj->tos,
                        obj->proto,
                        (bool) obj->path_mtu_discovery);
}

int
nm_platform_lnk_sit_cmp(const NMPlatformLnkSit *a, const NMPlatformLnkSit *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, parent_ifindex);
    NM_CMP_FIELD(a, b, local);
    NM_CMP_FIELD(a, b, remote);
    NM_CMP_FIELD(a, b, ttl);
    NM_CMP_FIELD(a, b, tos);
    NM_CMP_FIELD_BOOL(a, b, path_mtu_discovery);
    NM_CMP_FIELD(a, b, flags);
    NM_CMP_FIELD(a, b, proto);
    return 0;
}

void
nm_platform_lnk_tun_hash_update(const NMPlatformLnkTun *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->type,
                        obj->owner,
                        obj->group,
                        NM_HASH_COMBINE_BOOLS(guint8,
                                              obj->owner_valid,
                                              obj->group_valid,
                                              obj->pi,
                                              obj->vnet_hdr,
                                              obj->multi_queue,
                                              obj->persist));
}

int
nm_platform_lnk_tun_cmp(const NMPlatformLnkTun *a, const NMPlatformLnkTun *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, type);
    NM_CMP_FIELD(a, b, owner);
    NM_CMP_FIELD(a, b, group);
    NM_CMP_FIELD_BOOL(a, b, owner_valid);
    NM_CMP_FIELD_BOOL(a, b, group_valid);
    NM_CMP_FIELD_BOOL(a, b, pi);
    NM_CMP_FIELD_BOOL(a, b, vnet_hdr);
    NM_CMP_FIELD_BOOL(a, b, multi_queue);
    NM_CMP_FIELD_BOOL(a, b, persist);
    return 0;
}

void
nm_platform_lnk_vlan_hash_update(const NMPlatformLnkVlan *obj, NMHashState *h)
{
    nm_hash_update_vals(h, obj->id, obj->protocol, obj->flags);
}

int
nm_platform_lnk_vlan_cmp(const NMPlatformLnkVlan *a, const NMPlatformLnkVlan *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, id);
    NM_CMP_FIELD(a, b, protocol);
    NM_CMP_FIELD(a, b, flags);
    return 0;
}

void
nm_platform_lnk_vrf_hash_update(const NMPlatformLnkVrf *obj, NMHashState *h)
{
    nm_hash_update_vals(h, obj->table);
}

int
nm_platform_lnk_vrf_cmp(const NMPlatformLnkVrf *a, const NMPlatformLnkVrf *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, table);
    return 0;
}

void
nm_platform_lnk_vti_hash_update(const NMPlatformLnkVti *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->local,
                        obj->remote,
                        obj->parent_ifindex,
                        obj->ikey,
                        obj->okey,
                        obj->fwmark);
}

int
nm_platform_lnk_vti_cmp(const NMPlatformLnkVti *a, const NMPlatformLnkVti *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, parent_ifindex);
    NM_CMP_FIELD(a, b, local);
    NM_CMP_FIELD(a, b, remote);
    NM_CMP_FIELD(a, b, ikey);
    NM_CMP_FIELD(a, b, okey);
    NM_CMP_FIELD(a, b, fwmark);
    return 0;
}

void
nm_platform_lnk_vti6_hash_update(const NMPlatformLnkVti6 *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->local,
                        obj->remote,
                        obj->parent_ifindex,
                        obj->ikey,
                        obj->okey,
                        obj->fwmark);
}

int
nm_platform_lnk_vti6_cmp(const NMPlatformLnkVti6 *a, const NMPlatformLnkVti6 *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, parent_ifindex);
    NM_CMP_FIELD_MEMCMP(a, b, local);
    NM_CMP_FIELD_MEMCMP(a, b, remote);
    NM_CMP_FIELD(a, b, ikey);
    NM_CMP_FIELD(a, b, okey);
    NM_CMP_FIELD(a, b, fwmark);
    return 0;
}

void
nm_platform_lnk_vxlan_hash_update(const NMPlatformLnkVxlan *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->group6,
                        obj->local6,
                        obj->group,
                        obj->local,
                        obj->parent_ifindex,
                        obj->id,
                        obj->ageing,
                        obj->limit,
                        obj->dst_port,
                        obj->src_port_min,
                        obj->src_port_max,
                        obj->tos,
                        obj->ttl,
                        NM_HASH_COMBINE_BOOLS(guint8,
                                              obj->learning,
                                              obj->proxy,
                                              obj->rsc,
                                              obj->l2miss,
                                              obj->l3miss));
}

int
nm_platform_lnk_vxlan_cmp(const NMPlatformLnkVxlan *a, const NMPlatformLnkVxlan *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, parent_ifindex);
    NM_CMP_FIELD(a, b, id);
    NM_CMP_FIELD(a, b, group);
    NM_CMP_FIELD(a, b, local);
    NM_CMP_FIELD_MEMCMP(a, b, group6);
    NM_CMP_FIELD_MEMCMP(a, b, local6);
    NM_CMP_FIELD(a, b, tos);
    NM_CMP_FIELD(a, b, ttl);
    NM_CMP_FIELD_BOOL(a, b, learning);
    NM_CMP_FIELD(a, b, ageing);
    NM_CMP_FIELD(a, b, limit);
    NM_CMP_FIELD(a, b, dst_port);
    NM_CMP_FIELD(a, b, src_port_min);
    NM_CMP_FIELD(a, b, src_port_max);
    NM_CMP_FIELD_BOOL(a, b, proxy);
    NM_CMP_FIELD_BOOL(a, b, rsc);
    NM_CMP_FIELD_BOOL(a, b, l2miss);
    NM_CMP_FIELD_BOOL(a, b, l3miss);
    return 0;
}

void
nm_platform_lnk_wireguard_hash_update(const NMPlatformLnkWireGuard *obj, NMHashState *h)
{
    nm_hash_update_vals(h, obj->listen_port, obj->fwmark);
    nm_hash_update(h, obj->private_key, sizeof(obj->private_key));
    nm_hash_update(h, obj->public_key, sizeof(obj->public_key));
}

int
nm_platform_lnk_wireguard_cmp(const NMPlatformLnkWireGuard *a, const NMPlatformLnkWireGuard *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, listen_port);
    NM_CMP_FIELD(a, b, fwmark);
    NM_CMP_FIELD_MEMCMP(a, b, private_key);
    NM_CMP_FIELD_MEMCMP(a, b, public_key);
    return 0;
}

void
nm_platform_ip4_rt_nexthop_hash_update(const NMPlatformIP4RtNextHop *obj,
                                       gboolean                      for_id,
                                       NMHashState                  *h)
{
    guint8 w;

    nm_assert(obj);

    w = for_id ? NM_MAX(obj->weight, 1u) : obj->weight;

    nm_hash_update_vals(h, obj->ifindex, obj->gateway, w);
}

void
nm_platform_ip4_route_hash_update(const NMPlatformIP4Route *obj,
                                  NMPlatformIPRouteCmpType  cmp_type,
                                  NMHashState              *h)
{
    switch (cmp_type) {
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID:
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_ECMP_ID:
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID:
        nm_hash_update_vals(
            h,
            nm_platform_ip_route_get_effective_table(NM_PLATFORM_IP_ROUTE_CAST(obj)),
            nm_ip4_addr_clear_host_address(obj->network, obj->plen),
            obj->plen,
            obj->metric,
            obj->tos,
            NM_HASH_COMBINE_BOOLS(guint8, obj->metric_any, obj->table_any));
        if (NM_IN_SET(cmp_type,
                      NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID,
                      NM_PLATFORM_IP_ROUTE_CMP_TYPE_ECMP_ID)) {
            nm_hash_update_vals(h,
                                obj->type_coerced,
                                nmp_utils_ip_config_source_round_trip_rtprot(obj->rt_source),
                                _ip_route_scope_inv_get_normalized(obj),
                                obj->mss,
                                obj->pref_src,
                                obj->window,
                                obj->cwnd,
                                obj->initcwnd,
                                obj->initrwnd,
                                obj->mtu,
                                obj->rto_min,
                                obj->r_rtm_flags & RTNH_F_ONLINK,
                                NM_HASH_COMBINE_BOOLS(guint16,
                                                      obj->quickack,
                                                      obj->lock_window,
                                                      obj->lock_cwnd,
                                                      obj->lock_initcwnd,
                                                      obj->lock_initrwnd,
                                                      obj->lock_mtu,
                                                      obj->lock_mss));
            if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID) {
                nm_hash_update_vals(h,
                                    obj->ifindex,
                                    nm_platform_ip4_route_get_n_nexthops(obj),
                                    obj->gateway,
                                    (guint8) MAX(obj->weight, 1u));
            }
        }
        break;
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY:
        nm_hash_update_vals(
            h,
            obj->type_coerced,
            nm_platform_ip_route_get_effective_table(NM_PLATFORM_IP_ROUTE_CAST(obj)),
            obj->ifindex,
            nm_ip4_addr_clear_host_address(obj->network, obj->plen),
            obj->plen,
            obj->metric,
            nm_platform_ip4_route_get_n_nexthops(obj),
            obj->gateway,
            (guint8) MAX(obj->weight, 1u),
            nmp_utils_ip_config_source_round_trip_rtprot(obj->rt_source),
            _ip_route_scope_inv_get_normalized(obj),
            obj->tos,
            obj->mss,
            obj->pref_src,
            obj->window,
            obj->cwnd,
            obj->initcwnd,
            obj->initrwnd,
            obj->mtu,
            obj->rto_min,
            obj->r_rtm_flags & (RTM_F_CLONED | RTNH_F_ONLINK),
            NM_HASH_COMBINE_BOOLS(guint16,
                                  obj->metric_any,
                                  obj->table_any,
                                  obj->quickack,
                                  obj->lock_window,
                                  obj->lock_cwnd,
                                  obj->lock_initcwnd,
                                  obj->lock_initrwnd,
                                  obj->lock_mtu,
                                  obj->lock_mss));
        break;
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL:
        nm_hash_update_vals(h,
                            obj->type_coerced,
                            obj->table_coerced,
                            obj->ifindex,
                            obj->network,
                            obj->plen,
                            obj->metric,
                            obj->gateway,
                            obj->n_nexthops,
                            obj->weight,
                            obj->rt_source,
                            obj->scope_inv,
                            obj->tos,
                            obj->mss,
                            obj->pref_src,
                            obj->window,
                            obj->cwnd,
                            obj->initcwnd,
                            obj->initrwnd,
                            obj->mtu,
                            obj->rto_min,
                            obj->r_rtm_flags,
                            NM_HASH_COMBINE_BOOLS(guint16,
                                                  obj->metric_any,
                                                  obj->table_any,
                                                  obj->quickack,
                                                  obj->lock_window,
                                                  obj->lock_cwnd,
                                                  obj->lock_initcwnd,
                                                  obj->lock_initrwnd,
                                                  obj->lock_mtu,
                                                  obj->lock_mss,
                                                  obj->r_force_commit));
        break;
    }
}

int
nm_platform_ip4_rt_nexthop_cmp(const NMPlatformIP4RtNextHop *a,
                               const NMPlatformIP4RtNextHop *b,
                               gboolean                      for_id)
{
    guint8 w_a;
    guint8 w_b;

    /* Note that weight zero is not valid (in kernel). We thus treat
     * weight zero usually the same as 1.
     *
     * Not here for cmp/hash_update functions. These functions check for the exact
     * bit-pattern, and not the it means at other places. */
    NM_CMP_SELF(a, b);
    NM_CMP_FIELD(a, b, ifindex);
    NM_CMP_FIELD(a, b, gateway);

    w_a = for_id ? NM_MAX(a->weight, 1u) : a->weight;
    w_b = for_id ? NM_MAX(b->weight, 1u) : b->weight;
    NM_CMP_DIRECT(w_a, w_b);

    return 0;
}

int
nm_platform_ip4_route_cmp(const NMPlatformIP4Route *a,
                          const NMPlatformIP4Route *b,
                          NMPlatformIPRouteCmpType  cmp_type)
{
    NM_CMP_SELF(a, b);
    switch (cmp_type) {
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_ECMP_ID:
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID:
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID:
        NM_CMP_FIELD_UNSAFE(a, b, table_any);
        NM_CMP_DIRECT(nm_platform_ip_route_get_effective_table(NM_PLATFORM_IP_ROUTE_CAST(a)),
                      nm_platform_ip_route_get_effective_table(NM_PLATFORM_IP_ROUTE_CAST(b)));
        NM_CMP_DIRECT_IP4_ADDR_SAME_PREFIX(a->network, b->network, MIN(a->plen, b->plen));
        NM_CMP_FIELD(a, b, plen);
        NM_CMP_FIELD_UNSAFE(a, b, metric_any);
        NM_CMP_FIELD(a, b, metric);
        NM_CMP_FIELD(a, b, tos);
        if (NM_IN_SET(cmp_type,
                      NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID,
                      NM_PLATFORM_IP_ROUTE_CMP_TYPE_ECMP_ID)) {
            NM_CMP_FIELD(a, b, type_coerced);
            NM_CMP_DIRECT(nmp_utils_ip_config_source_round_trip_rtprot(a->rt_source),
                          nmp_utils_ip_config_source_round_trip_rtprot(b->rt_source));
            NM_CMP_DIRECT(_ip_route_scope_inv_get_normalized(a),
                          _ip_route_scope_inv_get_normalized(b));
            NM_CMP_FIELD(a, b, mss);
            NM_CMP_FIELD(a, b, pref_src);
            NM_CMP_FIELD(a, b, window);
            NM_CMP_FIELD(a, b, cwnd);
            NM_CMP_FIELD(a, b, initcwnd);
            NM_CMP_FIELD(a, b, initrwnd);
            NM_CMP_FIELD(a, b, mtu);
            NM_CMP_FIELD(a, b, rto_min);

            /* Note that for NetworkManager, the onlink flag is only part of the entire route.
             * For kernel, each next hop has it's own onlink flag (rtnh_flags). This means,
             * we can only merge ECMP routes, if they agree with their onlink flag, and then
             * all next hops are onlink (or not). */
            NM_CMP_DIRECT(a->r_rtm_flags & RTNH_F_ONLINK, b->r_rtm_flags & RTNH_F_ONLINK);

            NM_CMP_FIELD_UNSAFE(a, b, quickack);
            NM_CMP_FIELD_UNSAFE(a, b, lock_window);
            NM_CMP_FIELD_UNSAFE(a, b, lock_cwnd);
            NM_CMP_FIELD_UNSAFE(a, b, lock_initcwnd);
            NM_CMP_FIELD_UNSAFE(a, b, lock_initrwnd);
            NM_CMP_FIELD_UNSAFE(a, b, lock_mtu);
            NM_CMP_FIELD_UNSAFE(a, b, lock_mss);
            if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID) {
                NM_CMP_FIELD(a, b, ifindex);
                NM_CMP_FIELD(a, b, gateway);
                NM_CMP_DIRECT(NM_MAX(a->weight, 1u), NM_MAX(b->weight, 1u));
                NM_CMP_DIRECT(nm_platform_ip4_route_get_n_nexthops(a),
                              nm_platform_ip4_route_get_n_nexthops(b));
            }
        }
        break;
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY:
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL:
        NM_CMP_FIELD(a, b, type_coerced);
        NM_CMP_FIELD_UNSAFE(a, b, table_any);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) {
            NM_CMP_DIRECT(nm_platform_ip_route_get_effective_table(NM_PLATFORM_IP_ROUTE_CAST(a)),
                          nm_platform_ip_route_get_effective_table(NM_PLATFORM_IP_ROUTE_CAST(b)));
        } else
            NM_CMP_FIELD(a, b, table_coerced);
        NM_CMP_FIELD(a, b, ifindex);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
            NM_CMP_DIRECT_IP4_ADDR_SAME_PREFIX(a->network, b->network, MIN(a->plen, b->plen));
        else
            NM_CMP_FIELD(a, b, network);
        NM_CMP_FIELD(a, b, plen);
        NM_CMP_FIELD_UNSAFE(a, b, metric_any);
        NM_CMP_FIELD(a, b, metric);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) {
            NM_CMP_DIRECT(nm_platform_ip4_route_get_n_nexthops(a),
                          nm_platform_ip4_route_get_n_nexthops(b));
        } else
            NM_CMP_FIELD(a, b, n_nexthops);
        NM_CMP_FIELD(a, b, gateway);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
            NM_CMP_DIRECT(NM_MAX(a->weight, 1u), NM_MAX(b->weight, 1u));
        else
            NM_CMP_FIELD(a, b, weight);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) {
            NM_CMP_DIRECT(nmp_utils_ip_config_source_round_trip_rtprot(a->rt_source),
                          nmp_utils_ip_config_source_round_trip_rtprot(b->rt_source));
            NM_CMP_DIRECT(_ip_route_scope_inv_get_normalized(a),
                          _ip_route_scope_inv_get_normalized(b));
        } else {
            NM_CMP_FIELD(a, b, rt_source);
            NM_CMP_FIELD(a, b, scope_inv);
        }
        NM_CMP_FIELD(a, b, mss);
        NM_CMP_FIELD(a, b, pref_src);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) {
            NM_CMP_DIRECT(a->r_rtm_flags & (RTM_F_CLONED | RTNH_F_ONLINK),
                          b->r_rtm_flags & (RTM_F_CLONED | RTNH_F_ONLINK));
        } else
            NM_CMP_FIELD(a, b, r_rtm_flags);
        NM_CMP_FIELD(a, b, tos);
        NM_CMP_FIELD_UNSAFE(a, b, quickack);
        NM_CMP_FIELD_UNSAFE(a, b, lock_window);
        NM_CMP_FIELD_UNSAFE(a, b, lock_cwnd);
        NM_CMP_FIELD_UNSAFE(a, b, lock_initcwnd);
        NM_CMP_FIELD_UNSAFE(a, b, lock_initrwnd);
        NM_CMP_FIELD_UNSAFE(a, b, lock_mtu);
        NM_CMP_FIELD_UNSAFE(a, b, lock_mss);
        NM_CMP_FIELD(a, b, window);
        NM_CMP_FIELD(a, b, cwnd);
        NM_CMP_FIELD(a, b, initcwnd);
        NM_CMP_FIELD(a, b, initrwnd);
        NM_CMP_FIELD(a, b, mtu);
        NM_CMP_FIELD(a, b, rto_min);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL)
            NM_CMP_FIELD_UNSAFE(a, b, r_force_commit);
        break;
    }
    return 0;
}

void
nm_platform_ip6_route_hash_update(const NMPlatformIP6Route *obj,
                                  NMPlatformIPRouteCmpType  cmp_type,
                                  NMHashState              *h)
{
    struct in6_addr a1, a2;

    switch (cmp_type) {
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID:
        nm_hash_update_vals(
            h,
            nm_platform_ip_route_get_effective_table(NM_PLATFORM_IP_ROUTE_CAST(obj)),
            *nm_ip6_addr_clear_host_address(&a1, &obj->network, obj->plen),
            obj->plen,
            obj->metric,
            *nm_ip6_addr_clear_host_address(&a2, &obj->src, obj->src_plen),
            obj->src_plen,
            NM_HASH_COMBINE_BOOLS(guint8, obj->metric_any, obj->table_any));
        break;
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_ECMP_ID:
        nm_assert_not_reached();
        /* fall-through */
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID:
        nm_hash_update_vals(
            h,
            obj->type_coerced,
            nm_platform_ip_route_get_effective_table(NM_PLATFORM_IP_ROUTE_CAST(obj)),
            *nm_ip6_addr_clear_host_address(&a1, &obj->network, obj->plen),
            obj->plen,
            obj->metric,
            *nm_ip6_addr_clear_host_address(&a2, &obj->src, obj->src_plen),
            obj->src_plen,
            NM_HASH_COMBINE_BOOLS(guint8, obj->metric_any, obj->table_any),
            /* on top of WEAK_ID: */
            obj->ifindex,
            obj->gateway);
        break;
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY:
        nm_hash_update_vals(
            h,
            obj->type_coerced,
            nm_platform_ip_route_get_effective_table(NM_PLATFORM_IP_ROUTE_CAST(obj)),
            obj->ifindex,
            *nm_ip6_addr_clear_host_address(&a1, &obj->network, obj->plen),
            obj->plen,
            obj->metric,
            obj->gateway,
            obj->pref_src,
            *nm_ip6_addr_clear_host_address(&a2, &obj->src, obj->src_plen),
            obj->src_plen,
            nmp_utils_ip_config_source_round_trip_rtprot(obj->rt_source),
            obj->mss,
            obj->r_rtm_flags & RTM_F_CLONED,
            NM_HASH_COMBINE_BOOLS(guint16,
                                  obj->metric_any,
                                  obj->table_any,
                                  obj->quickack,
                                  obj->lock_window,
                                  obj->lock_cwnd,
                                  obj->lock_initcwnd,
                                  obj->lock_initrwnd,
                                  obj->lock_mtu,
                                  obj->lock_mss),
            obj->window,
            obj->cwnd,
            obj->initcwnd,
            obj->initrwnd,
            obj->mtu,
            obj->rto_min,
            _route_pref_normalize(obj->rt_pref));
        break;
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL:
        nm_hash_update_vals(h,
                            obj->type_coerced,
                            obj->table_coerced,
                            obj->ifindex,
                            obj->network,
                            obj->metric,
                            obj->gateway,
                            obj->pref_src,
                            obj->src,
                            obj->src_plen,
                            obj->rt_source,
                            obj->mss,
                            obj->r_rtm_flags,
                            NM_HASH_COMBINE_BOOLS(guint16,
                                                  obj->metric_any,
                                                  obj->table_any,
                                                  obj->quickack,
                                                  obj->lock_window,
                                                  obj->lock_cwnd,
                                                  obj->lock_initcwnd,
                                                  obj->lock_initrwnd,
                                                  obj->lock_mtu,
                                                  obj->lock_mss,
                                                  obj->r_force_commit),
                            obj->window,
                            obj->cwnd,
                            obj->initcwnd,
                            obj->initrwnd,
                            obj->mtu,
                            obj->rto_min,
                            obj->rt_pref);
        break;
    }
}

int
nm_platform_ip6_route_cmp(const NMPlatformIP6Route *a,
                          const NMPlatformIP6Route *b,
                          NMPlatformIPRouteCmpType  cmp_type)
{
    NM_CMP_SELF(a, b);
    switch (cmp_type) {
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_ECMP_ID:
        nm_assert_not_reached();
        /* fall-through */
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID:
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID:
        NM_CMP_FIELD_UNSAFE(a, b, table_any);
        NM_CMP_DIRECT(nm_platform_ip_route_get_effective_table(NM_PLATFORM_IP_ROUTE_CAST(a)),
                      nm_platform_ip_route_get_effective_table(NM_PLATFORM_IP_ROUTE_CAST(b)));
        NM_CMP_DIRECT_IP6_ADDR_SAME_PREFIX(&a->network, &b->network, MIN(a->plen, b->plen));
        NM_CMP_FIELD(a, b, plen);
        NM_CMP_FIELD_UNSAFE(a, b, metric_any);
        NM_CMP_FIELD(a, b, metric);
        NM_CMP_DIRECT_IP6_ADDR_SAME_PREFIX(&a->src, &b->src, MIN(a->src_plen, b->src_plen));
        NM_CMP_FIELD(a, b, src_plen);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID) {
            NM_CMP_FIELD(a, b, ifindex);
            NM_CMP_FIELD(a, b, type_coerced);
            NM_CMP_FIELD_IN6ADDR(a, b, gateway);
        }
        break;
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY:
    case NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL:
        NM_CMP_FIELD(a, b, type_coerced);
        NM_CMP_FIELD_UNSAFE(a, b, table_any);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) {
            NM_CMP_DIRECT(nm_platform_ip_route_get_effective_table(NM_PLATFORM_IP_ROUTE_CAST(a)),
                          nm_platform_ip_route_get_effective_table(NM_PLATFORM_IP_ROUTE_CAST(b)));
        } else
            NM_CMP_FIELD(a, b, table_coerced);
        NM_CMP_FIELD(a, b, ifindex);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
            NM_CMP_DIRECT_IP6_ADDR_SAME_PREFIX(&a->network, &b->network, MIN(a->plen, b->plen));
        else
            NM_CMP_FIELD_IN6ADDR(a, b, network);
        NM_CMP_FIELD(a, b, plen);
        NM_CMP_FIELD_UNSAFE(a, b, metric_any);
        NM_CMP_FIELD(a, b, metric);
        NM_CMP_FIELD_IN6ADDR(a, b, gateway);
        NM_CMP_FIELD_IN6ADDR(a, b, pref_src);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) {
            NM_CMP_DIRECT_IP6_ADDR_SAME_PREFIX(&a->src, &b->src, MIN(a->src_plen, b->src_plen));
            NM_CMP_FIELD(a, b, src_plen);
            NM_CMP_DIRECT(nmp_utils_ip_config_source_round_trip_rtprot(a->rt_source),
                          nmp_utils_ip_config_source_round_trip_rtprot(b->rt_source));
        } else {
            NM_CMP_FIELD_IN6ADDR(a, b, src);
            NM_CMP_FIELD(a, b, src_plen);
            NM_CMP_FIELD(a, b, rt_source);
        }
        NM_CMP_FIELD(a, b, mss);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) {
            NM_CMP_DIRECT(a->r_rtm_flags & RTM_F_CLONED, b->r_rtm_flags & RTM_F_CLONED);
        } else
            NM_CMP_FIELD(a, b, r_rtm_flags);
        NM_CMP_FIELD_UNSAFE(a, b, quickack);
        NM_CMP_FIELD_UNSAFE(a, b, lock_window);
        NM_CMP_FIELD_UNSAFE(a, b, lock_cwnd);
        NM_CMP_FIELD_UNSAFE(a, b, lock_initcwnd);
        NM_CMP_FIELD_UNSAFE(a, b, lock_initrwnd);
        NM_CMP_FIELD_UNSAFE(a, b, lock_mtu);
        NM_CMP_FIELD_UNSAFE(a, b, lock_mss);
        NM_CMP_FIELD(a, b, window);
        NM_CMP_FIELD(a, b, cwnd);
        NM_CMP_FIELD(a, b, initcwnd);
        NM_CMP_FIELD(a, b, initrwnd);
        NM_CMP_FIELD(a, b, mtu);
        NM_CMP_FIELD(a, b, rto_min);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
            NM_CMP_DIRECT(_route_pref_normalize(a->rt_pref), _route_pref_normalize(b->rt_pref));
        else
            NM_CMP_FIELD(a, b, rt_pref);
        if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL)
            NM_CMP_FIELD_UNSAFE(a, b, r_force_commit);
        break;
    }
    return 0;
}

#define _ROUTING_RULE_FLAGS_IGNORE \
    (FIB_RULE_UNRESOLVED | FIB_RULE_IIF_DETACHED | FIB_RULE_OIF_DETACHED)

#define _routing_rule_compare(cmp_type, kernel_support_type) \
    ((cmp_type) == NM_PLATFORM_ROUTING_RULE_CMP_TYPE_FULL    \
     || nm_platform_kernel_support_get(kernel_support_type))

void
nm_platform_routing_rule_hash_update(const NMPlatformRoutingRule *obj,
                                     NMPlatformRoutingRuleCmpType cmp_type,
                                     NMHashState                 *h)
{
    gboolean cmp_full = TRUE;
    gsize    addr_size;
    guint32  flags_mask = G_MAXUINT32;

    if (G_UNLIKELY(!NM_IN_SET(obj->addr_family, AF_INET, AF_INET6))) {
        /* the address family is not one of the supported ones. That means, the
         * instance will only compare equal to itself (pointer-equality). */
        nm_hash_update_val(h, (gconstpointer) obj);
        return;
    }

    switch (cmp_type) {
    case NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID:

        flags_mask &= ~_ROUTING_RULE_FLAGS_IGNORE;

        /* fall-through */
    case NM_PLATFORM_ROUTING_RULE_CMP_TYPE_SEMANTICALLY:

        cmp_full = FALSE;

        /* fall-through */
    case NM_PLATFORM_ROUTING_RULE_CMP_TYPE_FULL:

        nm_hash_update_vals(
            h,
            obj->addr_family,
            obj->tun_id,
            obj->table,
            obj->flags & flags_mask,
            obj->priority,
            obj->fwmark,
            obj->fwmask,
            ((cmp_full
              || (cmp_type == NM_PLATFORM_ROUTING_RULE_CMP_TYPE_SEMANTICALLY
                  && obj->action == FR_ACT_GOTO))
                 ? obj->goto_target
                 : (guint32) 0u),
            ((cmp_full || obj->addr_family == AF_INET) ? obj->flow : (guint32) 0u),
            NM_HASH_COMBINE_BOOLS(
                guint8,
                (_routing_rule_compare(cmp_type, NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_UID_RANGE)
                     ? obj->uid_range_has
                     : FALSE)),
            obj->suppress_prefixlen_inverse,
            obj->suppress_ifgroup_inverse,
            (_routing_rule_compare(cmp_type, NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_L3MDEV)
                 ? (cmp_full ? (guint16) obj->l3mdev : (guint16) !!obj->l3mdev)
                 : G_MAXUINT16),
            obj->action,
            obj->tos,
            obj->src_len,
            obj->dst_len,
            (_routing_rule_compare(cmp_type, NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_PROTOCOL)
                 ? (guint16) obj->protocol
                 : G_MAXUINT16));
        addr_size = nm_utils_addr_family_to_size(obj->addr_family);
        if (cmp_full || obj->src_len > 0)
            nm_hash_update(h, &obj->src, addr_size);
        if (cmp_full || obj->dst_len > 0)
            nm_hash_update(h, &obj->dst, addr_size);
        if (_routing_rule_compare(cmp_type, NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_UID_RANGE)) {
            if (cmp_full || obj->uid_range_has)
                nm_hash_update_valp(h, &obj->uid_range);
        }
        if (_routing_rule_compare(cmp_type, NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_IP_PROTO)) {
            nm_hash_update_val(h, obj->ip_proto);
            nm_hash_update_valp(h, &obj->sport_range);
            nm_hash_update_valp(h, &obj->dport_range);
        }
        nm_hash_update_str(h, obj->iifname);
        nm_hash_update_str(h, obj->oifname);
        return;
    }

    nm_assert_not_reached();
}

int
nm_platform_routing_rule_cmp(const NMPlatformRoutingRule *a,
                             const NMPlatformRoutingRule *b,
                             NMPlatformRoutingRuleCmpType cmp_type)
{
    gboolean cmp_full = TRUE;
    gsize    addr_size;
    bool     valid;
    guint32  flags_mask = G_MAXUINT32;

    NM_CMP_SELF(a, b);

    valid = NM_IN_SET(a->addr_family, AF_INET, AF_INET6);
    NM_CMP_DIRECT(valid, (bool) NM_IN_SET(b->addr_family, AF_INET, AF_INET6));

    if (G_UNLIKELY(!valid)) {
        /* the address family is not one of the supported ones. That means, the
         * instance will only compare equal to itself. */
        NM_CMP_DIRECT((uintptr_t) a, (uintptr_t) b);
        nm_assert_not_reached();
        return 0;
    }

    switch (cmp_type) {
    case NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID:

        flags_mask &= ~_ROUTING_RULE_FLAGS_IGNORE;

        /* fall-through */
    case NM_PLATFORM_ROUTING_RULE_CMP_TYPE_SEMANTICALLY:

        cmp_full = FALSE;

        /* fall-through */
    case NM_PLATFORM_ROUTING_RULE_CMP_TYPE_FULL:
        NM_CMP_FIELD(a, b, addr_family);
        NM_CMP_FIELD(a, b, action);
        NM_CMP_FIELD(a, b, priority);
        NM_CMP_FIELD(a, b, tun_id);

        if (_routing_rule_compare(cmp_type, NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_L3MDEV)) {
            if (cmp_full)
                NM_CMP_FIELD(a, b, l3mdev);
            else
                NM_CMP_FIELD_BOOL(a, b, l3mdev);
        }

        NM_CMP_FIELD(a, b, table);

        NM_CMP_DIRECT(a->flags & flags_mask, b->flags & flags_mask);

        NM_CMP_FIELD(a, b, fwmark);
        NM_CMP_FIELD(a, b, fwmask);

        if (cmp_full
            || (cmp_type == NM_PLATFORM_ROUTING_RULE_CMP_TYPE_SEMANTICALLY
                && a->action == FR_ACT_GOTO))
            NM_CMP_FIELD(a, b, goto_target);

        NM_CMP_FIELD(a, b, suppress_prefixlen_inverse);
        NM_CMP_FIELD(a, b, suppress_ifgroup_inverse);
        NM_CMP_FIELD(a, b, tos);

        if (cmp_full || a->addr_family == AF_INET)
            NM_CMP_FIELD(a, b, flow);

        if (_routing_rule_compare(cmp_type, NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_PROTOCOL))
            NM_CMP_FIELD(a, b, protocol);

        if (_routing_rule_compare(cmp_type, NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_IP_PROTO)) {
            NM_CMP_FIELD(a, b, ip_proto);
            NM_CMP_FIELD(a, b, sport_range.start);
            NM_CMP_FIELD(a, b, sport_range.end);
            NM_CMP_FIELD(a, b, dport_range.start);
            NM_CMP_FIELD(a, b, dport_range.end);
        }

        addr_size = nm_utils_addr_family_to_size(a->addr_family);

        NM_CMP_FIELD(a, b, src_len);
        if (cmp_full || a->src_len > 0)
            NM_CMP_FIELD_MEMCMP_LEN(a, b, src, addr_size);

        NM_CMP_FIELD(a, b, dst_len);
        if (cmp_full || a->dst_len > 0)
            NM_CMP_FIELD_MEMCMP_LEN(a, b, dst, addr_size);

        if (_routing_rule_compare(cmp_type, NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_UID_RANGE)) {
            NM_CMP_FIELD_UNSAFE(a, b, uid_range_has);
            if (cmp_full || a->uid_range_has) {
                NM_CMP_FIELD(a, b, uid_range.start);
                NM_CMP_FIELD(a, b, uid_range.end);
            }
        }

        NM_CMP_FIELD_STR(a, b, iifname);
        NM_CMP_FIELD_STR(a, b, oifname);
        return 0;
    }

    nm_assert_not_reached();
    return 0;
}

/**
 * nm_platform_ip_address_cmp_expiry:
 * @a: a NMPlatformIPAddress to compare
 * @b: the other NMPlatformIPAddress to compare
 *
 * Compares two addresses and returns which one has a longer remaining lifetime.
 * If both addresses have the same lifetime, look at the remaining preferred time.
 *
 * For comparison, only the timestamp, lifetime and preferred fields are considered.
 * If they compare equal (== 0), their other fields were not considered.
 *
 * Returns: -1, 0, or 1 according to the comparison
 **/
int
nm_platform_ip_address_cmp_expiry(const NMPlatformIPAddress *a, const NMPlatformIPAddress *b)
{
    gint64 ta = 0, tb = 0;

    NM_CMP_SELF(a, b);

    if (a->lifetime == NM_PLATFORM_LIFETIME_PERMANENT || a->lifetime == 0)
        ta = G_MAXINT64;
    else if (a->timestamp)
        ta = ((gint64) a->timestamp) + a->lifetime;

    if (b->lifetime == NM_PLATFORM_LIFETIME_PERMANENT || b->lifetime == 0)
        tb = G_MAXINT64;
    else if (b->timestamp)
        tb = ((gint64) b->timestamp) + b->lifetime;

    if (ta == tb) {
        /* if the lifetime is equal, compare the preferred time. */
        ta = tb = 0;

        if (a->preferred == NM_PLATFORM_LIFETIME_PERMANENT
            || a->lifetime == 0 /* lifetime==0 means permanent! */)
            ta = G_MAXINT64;
        else if (a->timestamp)
            ta = ((gint64) a->timestamp) + a->preferred;

        if (b->preferred == NM_PLATFORM_LIFETIME_PERMANENT || b->lifetime == 0)
            tb = G_MAXINT64;
        else if (b->timestamp)
            tb = ((gint64) b->timestamp) + b->preferred;

        if (ta == tb)
            return 0;
    }

    return ta < tb ? -1 : 1;
}

/*****************************************************************************/

guint16
nm_platform_genl_get_family_id(NMPlatform *self, NMPGenlFamilyType family_type)
{
    _CHECK_SELF(self, klass, 0);

    if (!_NM_INT_NOT_NEGATIVE(family_type) || family_type >= _NMP_GENL_FAMILY_TYPE_NUM)
        g_return_val_if_reached(0);

    return klass->genl_get_family_id(self, family_type);
}

/*****************************************************************************/

int
nm_platform_mptcp_addr_update(NMPlatform *self, NMOptionBool add, const NMPlatformMptcpAddr *addr)
{
    _CHECK_SELF(self, klass, -NME_BUG);

    return klass->mptcp_addr_update(self, add, addr);
}

GPtrArray *
nm_platform_mptcp_addrs_dump(NMPlatform *self)
{
    _CHECK_SELF(self, klass, NULL);

    return klass->mptcp_addrs_dump(self);
}

/*****************************************************************************/

GHashTable *
nm_platform_ip4_address_addr_to_hash(NMPlatform *self, int ifindex)
{
    const NMDedupMultiHeadEntry *head_entry;
    NMDedupMultiIter             iter;
    const NMPObject             *obj;
    NMPLookup                    lookup;
    GHashTable                  *hash;

    g_return_val_if_fail(NM_IS_PLATFORM(self), NULL);
    g_return_val_if_fail(ifindex > 0, NULL);

    nmp_lookup_init_object_by_ifindex(&lookup, NMP_OBJECT_TYPE_IP4_ADDRESS, ifindex);

    head_entry = nmp_cache_lookup(NM_PLATFORM_GET_PRIVATE(self)->cache, &lookup);

    if (!head_entry)
        return NULL;

    hash = g_hash_table_new(nm_direct_hash, NULL);

    nmp_cache_iter_for_each (&iter, head_entry, &obj) {
        const NMPlatformIP4Address *a = NMP_OBJECT_CAST_IP4_ADDRESS(obj);

        g_hash_table_add(hash, GUINT_TO_POINTER(a->address));
    }

    return hash;
}

/*****************************************************************************/

NMPlatformIP4Route *
nm_platform_ip4_address_generate_device_route(const NMPlatformIP4Address *addr,
                                              int                         ifindex,
                                              guint32                     route_table,
                                              guint32                     route_metric,
                                              gboolean                    force_commit,
                                              NMPlatformIP4Route         *dst)
{
    in_addr_t network_4;

    /* When you add an IPv4 address (without "noprefixroute" flag), then kernel will
     * automatically add a device route for the IPv4 subnet. This function generates
     * such a route for the given address. */

    nm_assert(addr);
    nm_assert(addr->plen <= 32);

    if (addr->plen == 0)
        return NULL;

    network_4 = nm_ip4_addr_clear_host_address(addr->peer_address, addr->plen);

    if (nm_ip4_addr_is_zeronet(network_4)) {
        /* Kernel doesn't add device-routes for destinations that
         * start with 0.x.y.z. Skip them. */
        return NULL;
    }

    if (addr->plen == 32 && addr->address == addr->peer_address) {
        /* Kernel doesn't add device-routes for /32 addresses unless
         * they have a peer. */
        return NULL;
    }

    *dst = (NMPlatformIP4Route){
        .ifindex        = ifindex,
        .rt_source      = NM_IP_CONFIG_SOURCE_KERNEL,
        .network        = network_4,
        .plen           = addr->plen,
        .pref_src       = addr->address,
        .table_coerced  = nm_platform_route_table_coerce(route_table),
        .metric         = route_metric,
        .scope_inv      = nm_platform_route_scope_inv(NM_RT_SCOPE_LINK),
        .r_force_commit = force_commit,
    };

    nm_platform_ip_route_normalize(AF_INET, (NMPlatformIPRoute *) dst);

    return dst;
}

const char *
nm_platform_signal_change_type_to_string(NMPlatformSignalChangeType change_type)
{
    switch (change_type) {
    case NM_PLATFORM_SIGNAL_ADDED:
        return "added";
    case NM_PLATFORM_SIGNAL_CHANGED:
        return "changed";
    case NM_PLATFORM_SIGNAL_REMOVED:
        return "removed";
    default:
        g_return_val_if_reached("UNKNOWN");
    }
}

static void
log_link(NMPlatform                *self,
         NMPObjectType              obj_type,
         int                        ifindex,
         NMPlatformLink            *device,
         NMPlatformSignalChangeType change_type,
         gpointer                   user_data)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];

    if (_LOGD_ENABLED()) {
        NMLOG_COMMON(LOGL_DEBUG,
                     device->name,
                     "signal: link %7s: %s",
                     nm_platform_signal_change_type_to_string(change_type),
                     nm_platform_link_to_string(device, sbuf, sizeof(sbuf)));
    }
}

static void
log_ip4_address(NMPlatform                *self,
                NMPObjectType              obj_type,
                int                        ifindex,
                NMPlatformIP4Address      *address,
                NMPlatformSignalChangeType change_type,
                gpointer                   user_data)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];

    _LOG3D("signal: address 4 %7s: %s",
           nm_platform_signal_change_type_to_string(change_type),
           nm_platform_ip4_address_to_string(address, sbuf, sizeof(sbuf)));
}

static void
log_ip6_address(NMPlatform                *self,
                NMPObjectType              obj_type,
                int                        ifindex,
                NMPlatformIP6Address      *address,
                NMPlatformSignalChangeType change_type,
                gpointer                   user_data)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];

    _LOG3D("signal: address 6 %7s: %s",
           nm_platform_signal_change_type_to_string(change_type),
           nm_platform_ip6_address_to_string(address, sbuf, sizeof(sbuf)));
}

static void
log_ip4_route(NMPlatform                *self,
              NMPObjectType              obj_type,
              int                        ifindex,
              NMPlatformIP4Route        *route,
              NMPlatformSignalChangeType change_type,
              gpointer                   user_data)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];

    _LOG3D("signal: route   4 %7s: %s",
           nm_platform_signal_change_type_to_string(change_type),
           nmp_object_to_string(NMP_OBJECT_UP_CAST(route),
                                NMP_OBJECT_TO_STRING_PUBLIC,
                                sbuf,
                                sizeof(sbuf)));
}

static void
log_ip6_route(NMPlatform                *self,
              NMPObjectType              obj_type,
              int                        ifindex,
              NMPlatformIP6Route        *route,
              NMPlatformSignalChangeType change_type,
              gpointer                   user_data)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];

    _LOG3D("signal: route   6 %7s: %s",
           nm_platform_signal_change_type_to_string(change_type),
           nmp_object_to_string(NMP_OBJECT_UP_CAST(route),
                                NMP_OBJECT_TO_STRING_PUBLIC,
                                sbuf,
                                sizeof(sbuf)));
}

static void
log_routing_rule(NMPlatform                *self,
                 NMPObjectType              obj_type,
                 int                        ifindex,
                 NMPlatformRoutingRule     *routing_rule,
                 NMPlatformSignalChangeType change_type,
                 gpointer                   user_data)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];

    /* routing rules don't have an ifindex. We probably should refactor the signals that are emitted for platform changes. */
    _LOG3D("signal: rt-rule %7s: %s",
           nm_platform_signal_change_type_to_string(change_type),
           nm_platform_routing_rule_to_string(routing_rule, sbuf, sizeof(sbuf)));
}

static void
log_qdisc(NMPlatform                *self,
          NMPObjectType              obj_type,
          int                        ifindex,
          NMPlatformQdisc           *qdisc,
          NMPlatformSignalChangeType change_type,
          gpointer                   user_data)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];

    _LOG3D("signal: qdisc %7s: %s",
           nm_platform_signal_change_type_to_string(change_type),
           nm_platform_qdisc_to_string(qdisc, sbuf, sizeof(sbuf)));
}

static void
log_tfilter(NMPlatform                *self,
            NMPObjectType              obj_type,
            int                        ifindex,
            NMPlatformTfilter         *tfilter,
            NMPlatformSignalChangeType change_type,
            gpointer                   user_data)
{
    char sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];

    _LOG3D("signal: tfilter %7s: %s",
           nm_platform_signal_change_type_to_string(change_type),
           nm_platform_tfilter_to_string(tfilter, sbuf, sizeof(sbuf)));
}

/*****************************************************************************/

void
nm_platform_cache_update_emit_signal(NMPlatform      *self,
                                     NMPCacheOpsType  cache_op,
                                     const NMPObject *obj_old,
                                     const NMPObject *obj_new)
{
    char             sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    gboolean         visible_new;
    gboolean         visible_old;
    const NMPObject *o;
    const NMPClass  *klass;
    int              ifindex;

    nm_assert(NM_IN_SET((NMPlatformSignalChangeType) cache_op,
                        NM_PLATFORM_SIGNAL_NONE,
                        NM_PLATFORM_SIGNAL_ADDED,
                        NM_PLATFORM_SIGNAL_CHANGED,
                        NM_PLATFORM_SIGNAL_REMOVED));

    ASSERT_nmp_cache_ops(nm_platform_get_cache(self), cache_op, obj_old, obj_new);

    NMTST_ASSERT_PLATFORM_NETNS_CURRENT(self);

    switch (cache_op) {
    case NMP_CACHE_OPS_ADDED:
        if (!nmp_object_is_visible(obj_new))
            return;
        o = obj_new;
        break;
    case NMP_CACHE_OPS_UPDATED:
        visible_old = nmp_object_is_visible(obj_old);
        visible_new = nmp_object_is_visible(obj_new);
        if (!visible_old && visible_new) {
            o        = obj_new;
            cache_op = NMP_CACHE_OPS_ADDED;
        } else if (visible_old && !visible_new) {
            o        = obj_old;
            cache_op = NMP_CACHE_OPS_REMOVED;
        } else if (!visible_new) {
            /* it was invisible and stayed invisible. Nothing to do. */
            return;
        } else
            o = obj_new;
        break;
    case NMP_CACHE_OPS_REMOVED:
        if (!nmp_object_is_visible(obj_old))
            return;
        o = obj_old;
        break;
    default:
        nm_assert(cache_op == NMP_CACHE_OPS_UNCHANGED);
        return;
    }

    klass = NMP_OBJECT_GET_CLASS(o);

    if (klass->obj_type == NMP_OBJECT_TYPE_ROUTING_RULE)
        ifindex = 0;
    else
        ifindex = NMP_OBJECT_CAST_OBJ_WITH_IFINDEX(o)->ifindex;

    if (klass->obj_type == NMP_OBJECT_TYPE_IP4_ROUTE
        && NM_PLATFORM_GET_PRIVATE(self)->ip4_dev_route_blacklist_gc_timeout_id
        && NM_IN_SET(cache_op, NMP_CACHE_OPS_ADDED, NMP_CACHE_OPS_UPDATED))
        _ip4_dev_route_blacklist_notify_route(self, o);

    _LOG3t("emit signal %s %s: %s",
           klass->signal_type,
           nm_platform_signal_change_type_to_string((NMPlatformSignalChangeType) cache_op),
           nmp_object_to_string(o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));

    nmp_object_ref(o);
    g_signal_emit(self,
                  _nm_platform_signal_id_get(klass->signal_type_id),
                  0,
                  (int) klass->obj_type,
                  ifindex,
                  &o->object,
                  (int) cache_op);
    nmp_object_unref(o);
}

/*****************************************************************************/

NMPCache *
nm_platform_get_cache(NMPlatform *self)
{
    return NM_PLATFORM_GET_PRIVATE(self)->cache;
}

NMPNetns *
nm_platform_netns_get(NMPlatform *self)
{
    _CHECK_SELF(self, klass, NULL);

    return self->_netns;
}

gboolean
nm_platform_netns_push(NMPlatform *self, NMPNetns **netns)
{
    g_return_val_if_fail(NM_IS_PLATFORM(self), FALSE);

    if (self->_netns && !nmp_netns_push(self->_netns)) {
        NM_SET_OUT(netns, NULL);
        return FALSE;
    }

    NM_SET_OUT(netns, self->_netns);
    return TRUE;
}

/*****************************************************************************/

typedef struct {
    struct in6_addr address;
    CList           lst;
    gint64          timestamp_nsec;
    int             ifindex;
} IP6DadFailedAddr;

static void
ip6_dadfailed_addr_free(IP6DadFailedAddr *addr)
{
    c_list_unlink_stale(&addr->lst);
    nm_g_slice_free(addr);
}

static void
ip6_dadfailed_prune_old(NMPlatform *self, gint64 now_nsec)
{
    NMPlatformPrivate *priv = NM_PLATFORM_GET_PRIVATE(self);
    IP6DadFailedAddr  *addr;
    IP6DadFailedAddr  *safe;

    c_list_for_each_entry_safe (addr, safe, &priv->ip6_dadfailed_lst_head, lst) {
        if (addr->timestamp_nsec + (10 * NM_UTILS_NSEC_PER_SEC) > now_nsec)
            break;
        ip6_dadfailed_addr_free(addr);
    }
}

gboolean
nm_platform_ip6_dadfailed_check(NMPlatform *self, int ifindex, const struct in6_addr *ip6)
{
    NMPlatformPrivate *priv = NM_PLATFORM_GET_PRIVATE(self);
    IP6DadFailedAddr  *addr;

    ip6_dadfailed_prune_old(self, nm_utils_get_monotonic_timestamp_nsec());

    c_list_for_each_entry_prev (addr, &priv->ip6_dadfailed_lst_head, lst) {
        if (addr->ifindex == ifindex && IN6_ARE_ADDR_EQUAL(&addr->address, ip6)) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * If an IPv6 address fails DAD and has infinite lifetime, kernel just
 * sets the DADFAILED flag. However when the address has a finite
 * lifetime kernel deletes it immediately and the RTM_DELLINK netlink
 * message contains the DADFAILED flag. In the second case, we remove
 * the address from the platform cache and there is no way for
 * platform's clients to check whether DAD failed. To work around
 * this, we store all deleted-with-DADFAILED addresses and provide a
 * mechanism to access them.
 */
void
nm_platform_ip6_dadfailed_set(NMPlatform            *self,
                              int                    ifindex,
                              const struct in6_addr *ip6,
                              gboolean               failed)
{
    NMPlatformPrivate *priv     = NM_PLATFORM_GET_PRIVATE(self);
    gint64             now_nsec = nm_utils_get_monotonic_timestamp_nsec();
    IP6DadFailedAddr  *addr;
    IP6DadFailedAddr  *safe;

    ip6_dadfailed_prune_old(self, now_nsec);

    if (failed) {
        addr  = g_slice_new(IP6DadFailedAddr);
        *addr = (IP6DadFailedAddr){
            .address        = *ip6,
            .ifindex        = ifindex,
            .timestamp_nsec = now_nsec,
        };
        c_list_link_tail(&priv->ip6_dadfailed_lst_head, &addr->lst);
    } else {
        c_list_for_each_entry_safe (addr, safe, &priv->ip6_dadfailed_lst_head, lst) {
            if (addr->ifindex == ifindex && IN6_ARE_ADDR_EQUAL(&addr->address, ip6)) {
                ip6_dadfailed_addr_free(addr);
            }
        }
    }
}

/*****************************************************************************/

const _NMPlatformVTableRouteUnion nm_platform_vtable_route = {
    .v4 =
        {
            .is_ip4          = TRUE,
            .obj_type        = NMP_OBJECT_TYPE_IP4_ROUTE,
            .addr_family     = AF_INET,
            .sizeof_route    = sizeof(NMPlatformIP4Route),
            .route_cmp       = (int (*)(const NMPlatformIPXRoute *a,
                                  const NMPlatformIPXRoute *b,
                                  NMPlatformIPRouteCmpType  cmp_type)) nm_platform_ip4_route_cmp,
            .route_to_string = (const char *(*) (const NMPlatformIPXRoute *route,
                                                 char                     *buf,
                                                 gsize len)) nm_platform_ip4_route_to_string,
        },
    .v6 =
        {
            .is_ip4          = FALSE,
            .obj_type        = NMP_OBJECT_TYPE_IP6_ROUTE,
            .addr_family     = AF_INET6,
            .sizeof_route    = sizeof(NMPlatformIP6Route),
            .route_cmp       = (int (*)(const NMPlatformIPXRoute *a,
                                  const NMPlatformIPXRoute *b,
                                  NMPlatformIPRouteCmpType  cmp_type)) nm_platform_ip6_route_cmp,
            .route_to_string = (const char *(*) (const NMPlatformIPXRoute *route,
                                                 char                     *buf,
                                                 gsize len)) nm_platform_ip6_route_to_string,
        },
};

/*****************************************************************************/

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMPlatform        *self = NM_PLATFORM(object);
    NMPlatformPrivate *priv = NM_PLATFORM_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_MULTI_IDX:
        /* construct-only */
        {
            NMDedupMultiIndex *multi_idx;

            multi_idx = g_value_get_pointer(value);
            if (!multi_idx)
                multi_idx = nm_dedup_multi_index_new();
            else
                multi_idx = nm_dedup_multi_index_ref(multi_idx);

            priv->multi_idx = multi_idx;
            break;
        }
    case PROP_NETNS_SUPPORT:
        /* construct-only */
        if (g_value_get_boolean(value)) {
            NMPNetns *netns;

            netns = nmp_netns_get_current();
            if (netns)
                self->_netns = g_object_ref(netns);
        }
        break;
    case PROP_USE_UDEV:
        /* construct-only */
        priv->use_udev = g_value_get_boolean(value);
        break;
    case PROP_LOG_WITH_PTR:
        /* construct-only */
        priv->log_with_ptr = g_value_get_boolean(value);
        break;
    case PROP_CACHE_TC:
        /* construct-only */
        priv->cache_tc = g_value_get_boolean(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nm_platform_init(NMPlatform *self)
{
    self->_priv = G_TYPE_INSTANCE_GET_PRIVATE(self, NM_TYPE_PLATFORM, NMPlatformPrivate);
}

static GObject *
constructor(GType type, guint n_construct_params, GObjectConstructParam *construct_params)
{
    GObject           *object;
    NMPlatform        *self;
    NMPlatformPrivate *priv;

    object = G_OBJECT_CLASS(nm_platform_parent_class)
                 ->constructor(type, n_construct_params, construct_params);
    self = NM_PLATFORM(object);
    priv = NM_PLATFORM_GET_PRIVATE(self);

    nm_assert(priv->multi_idx);

    priv->cache = nmp_cache_new(priv->multi_idx, priv->use_udev);
    c_list_init(&priv->ip6_dadfailed_lst_head);

    return object;
}

static void
finalize(GObject *object)
{
    NMPlatform        *self = NM_PLATFORM(object);
    NMPlatformPrivate *priv = NM_PLATFORM_GET_PRIVATE(self);
    IP6DadFailedAddr  *addr;

    nm_clear_g_source(&priv->ip4_dev_route_blacklist_check_id);
    nm_clear_g_source(&priv->ip4_dev_route_blacklist_gc_timeout_id);
    nm_clear_pointer(&priv->ip4_dev_route_blacklist_hash, g_hash_table_unref);
    g_clear_object(&self->_netns);
    nm_dedup_multi_index_unref(priv->multi_idx);
    nmp_cache_free(priv->cache);

    while ((addr = c_list_first_entry(&priv->ip6_dadfailed_lst_head, IP6DadFailedAddr, lst))) {
        ip6_dadfailed_addr_free(addr);
    }

    G_OBJECT_CLASS(nm_platform_parent_class)->finalize(object);
}

static void
nm_platform_class_init(NMPlatformClass *platform_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(platform_class);

    g_type_class_add_private(object_class, sizeof(NMPlatformPrivate));

    object_class->constructor  = constructor;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    platform_class->wifi_set_powersave = wifi_set_powersave;

    g_object_class_install_property(
        object_class,
        PROP_MULTI_IDX,
        g_param_spec_pointer(NM_PLATFORM_MULTI_IDX,
                             "",
                             "",
                             G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(
        object_class,
        PROP_NETNS_SUPPORT,
        g_param_spec_boolean(NM_PLATFORM_NETNS_SUPPORT,
                             "",
                             "",
                             NM_PLATFORM_NETNS_SUPPORT_DEFAULT,
                             G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(
        object_class,
        PROP_USE_UDEV,
        g_param_spec_boolean(NM_PLATFORM_USE_UDEV,
                             "",
                             "",
                             FALSE,
                             G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(
        object_class,
        PROP_LOG_WITH_PTR,
        g_param_spec_boolean(NM_PLATFORM_LOG_WITH_PTR,
                             "",
                             "",
                             TRUE,
                             G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(
        object_class,
        PROP_CACHE_TC,
        g_param_spec_boolean(NM_PLATFORM_CACHE_TC,
                             "",
                             "",
                             FALSE,
                             G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

#define SIGNAL(signal, signal_id, method)                                                \
    G_STMT_START                                                                         \
    {                                                                                    \
        signals[signal] =                                                                \
            g_signal_new_class_handler("" signal_id "",                                  \
                                       G_OBJECT_CLASS_TYPE(object_class),                \
                                       G_SIGNAL_RUN_FIRST,                               \
                                       G_CALLBACK(method),                               \
                                       NULL,                                             \
                                       NULL,                                             \
                                       NULL,                                             \
                                       G_TYPE_NONE,                                      \
                                       4,                                                \
                                       G_TYPE_INT, /* (int) NMPObjectType */             \
                                       G_TYPE_INT, /* ifindex */                         \
                                       G_TYPE_POINTER /* const NMPObject * */,           \
                                       G_TYPE_INT /* (int) NMPlatformSignalChangeType */ \
            );                                                                           \
    }                                                                                    \
    G_STMT_END

    /* Signals */
    SIGNAL(NM_PLATFORM_SIGNAL_ID_LINK, NM_PLATFORM_SIGNAL_LINK_CHANGED, log_link);
    SIGNAL(NM_PLATFORM_SIGNAL_ID_IP4_ADDRESS,
           NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED,
           log_ip4_address);
    SIGNAL(NM_PLATFORM_SIGNAL_ID_IP6_ADDRESS,
           NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED,
           log_ip6_address);
    SIGNAL(NM_PLATFORM_SIGNAL_ID_IP4_ROUTE, NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, log_ip4_route);
    SIGNAL(NM_PLATFORM_SIGNAL_ID_IP6_ROUTE, NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED, log_ip6_route);
    SIGNAL(NM_PLATFORM_SIGNAL_ID_ROUTING_RULE,
           NM_PLATFORM_SIGNAL_ROUTING_RULE_CHANGED,
           log_routing_rule);
    SIGNAL(NM_PLATFORM_SIGNAL_ID_QDISC, NM_PLATFORM_SIGNAL_QDISC_CHANGED, log_qdisc);
    SIGNAL(NM_PLATFORM_SIGNAL_ID_TFILTER, NM_PLATFORM_SIGNAL_TFILTER_CHANGED, log_tfilter);
}
