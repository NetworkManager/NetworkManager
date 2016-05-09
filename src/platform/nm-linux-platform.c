/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-linux-platform.c - Linux kernel & udev network configuration layer
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
 * Copyright (C) 2012-2015 Red Hat, Inc.
 */
#include "nm-default.h"

#include "nm-linux-platform.h"

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/if_tunnel.h>
#include <netlink/netlink.h>
#include <netlink/object.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <netlink/route/link/vlan.h>
#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <gudev/gudev.h>

#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nm-setting-vlan.h"

#include "nm-core-utils.h"
#include "nmp-object.h"
#include "nmp-netns.h"
#include "nm-platform-utils.h"
#include "wifi/wifi-utils.h"
#include "wifi/wifi-utils-wext.h"

#define offset_plus_sizeof(t,m) (offsetof (t,m) + sizeof (((t *) NULL)->m))

#define VLAN_FLAG_MVRP 0x8

/* nm-internal error codes for libnl. Make sure they don't overlap. */
#define _NLE_NM_NOBUFS 500

/*********************************************************************************************/

#define IFQDISCSIZ                      32

/*********************************************************************************************/

#ifndef IFLA_PROMISCUITY
#define IFLA_PROMISCUITY                30
#endif
#define IFLA_NUM_TX_QUEUES              31
#define IFLA_NUM_RX_QUEUES              32
#define IFLA_CARRIER                    33
#define IFLA_PHYS_PORT_ID               34
#define IFLA_LINK_NETNSID               37
#define __IFLA_MAX                      39

#define IFLA_INET6_TOKEN                7
#define IFLA_INET6_ADDR_GEN_MODE        8
#define __IFLA_INET6_MAX                9

#define IFLA_VLAN_PROTOCOL              5
#define __IFLA_VLAN_MAX                 6

#define IFA_FLAGS                       8
#define __IFA_MAX                       9

#define IFLA_MACVLAN_FLAGS              2
#define __IFLA_MACVLAN_MAX              3

#define IFLA_IPTUN_LINK                 1
#define IFLA_IPTUN_LOCAL                2
#define IFLA_IPTUN_REMOTE               3
#define IFLA_IPTUN_TTL                  4
#define IFLA_IPTUN_TOS                  5
#define IFLA_IPTUN_ENCAP_LIMIT          6
#define IFLA_IPTUN_FLOWINFO             7
#define IFLA_IPTUN_FLAGS                8
#define IFLA_IPTUN_PROTO                9
#define IFLA_IPTUN_PMTUDISC             10
#define __IFLA_IPTUN_MAX                19
#ifndef IFLA_IPTUN_MAX
#define IFLA_IPTUN_MAX                  (__IFLA_IPTUN_MAX - 1)
#endif

#ifndef MACVLAN_FLAG_NOPROMISC
#define MACVLAN_FLAG_NOPROMISC          1
#endif

#define IP6_FLOWINFO_TCLASS_MASK        0x0FF00000
#define IP6_FLOWINFO_TCLASS_SHIFT       20
#define IP6_FLOWINFO_FLOWLABEL_MASK     0x000FFFFF

/*********************************************************************************************/

#define _NMLOG_PREFIX_NAME                "platform-linux"
#define _NMLOG_DOMAIN                     LOGD_PLATFORM
#define _NMLOG2_DOMAIN                    LOGD_PLATFORM
#define _NMLOG(level, ...)                _LOG     (       level, _NMLOG_DOMAIN,  platform, __VA_ARGS__)
#define _NMLOG_err(errsv, level, ...)     _LOG_err (errsv, level, _NMLOG_DOMAIN,  platform, __VA_ARGS__)
#define _NMLOG2(level, ...)               _LOG     (       level, _NMLOG2_DOMAIN, NULL,     __VA_ARGS__)
#define _NMLOG2_err(errsv, level, ...)    _LOG_err (errsv, level, _NMLOG2_DOMAIN, NULL,     __VA_ARGS__)


#define _LOG_print(__level, __domain, __errsv, self, ...) \
    G_STMT_START { \
        char __prefix[32]; \
        const char *__p_prefix = _NMLOG_PREFIX_NAME; \
        const void *const __self = (self); \
        \
        if (__self && __self != nm_platform_try_get ()) { \
            g_snprintf (__prefix, sizeof (__prefix), "%s[%p]", _NMLOG_PREFIX_NAME, __self); \
            __p_prefix = __prefix; \
        } \
        _nm_log (__level, __domain, __errsv, \
                 "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                 __p_prefix _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
    } G_STMT_END

#define _LOG(level, domain, self, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        const NMLogDomain __domain = (domain); \
        \
        if (nm_logging_enabled (__level, __domain)) { \
            _LOG_print (__level, __domain, 0, self, __VA_ARGS__); \
        } \
    } G_STMT_END

#define _LOG_err(errsv, level, domain, self, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        const NMLogDomain __domain = (domain); \
        \
        if (nm_logging_enabled (__level, __domain)) { \
            int __errsv = (errsv); \
            \
            /* The %m format specifier (GNU extension) would alread allow you to specify the error
             * message conveniently (and nm_log would get that right too). But we don't want to depend
             * on that, so instead append the message at the end.
             * Currently users are expected not to use %m in the format string. */ \
            _LOG_print (__level, __domain, __errsv, self, \
                        _NM_UTILS_MACRO_FIRST (__VA_ARGS__) ": %s (%d)" \
                        _NM_UTILS_MACRO_REST (__VA_ARGS__), \
                        g_strerror (__errsv), __errsv); \
        } \
    } G_STMT_END


#define LOG_FMT_IP_TUNNEL "adding %s '%s' parent %u local %s remote %s"

/******************************************************************
 * Forward declarations and enums
 ******************************************************************/

typedef enum {
	INFINIBAND_ACTION_CREATE_CHILD,
	INFINIBAND_ACTION_DELETE_CHILD,
} InfinibandAction;

enum {
	DELAYED_ACTION_IDX_REFRESH_ALL_LINKS,
	DELAYED_ACTION_IDX_REFRESH_ALL_IP4_ADDRESSES,
	DELAYED_ACTION_IDX_REFRESH_ALL_IP6_ADDRESSES,
	DELAYED_ACTION_IDX_REFRESH_ALL_IP4_ROUTES,
	DELAYED_ACTION_IDX_REFRESH_ALL_IP6_ROUTES,
	_DELAYED_ACTION_IDX_REFRESH_ALL_NUM,
};

typedef enum {
	DELAYED_ACTION_TYPE_NONE                        = 0,
	DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS           = (1LL << DELAYED_ACTION_IDX_REFRESH_ALL_LINKS),
	DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES   = (1LL << DELAYED_ACTION_IDX_REFRESH_ALL_IP4_ADDRESSES),
	DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES   = (1LL << DELAYED_ACTION_IDX_REFRESH_ALL_IP6_ADDRESSES),
	DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES      = (1LL << DELAYED_ACTION_IDX_REFRESH_ALL_IP4_ROUTES),
	DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES      = (1LL << DELAYED_ACTION_IDX_REFRESH_ALL_IP6_ROUTES),
	DELAYED_ACTION_TYPE_REFRESH_LINK                = (1LL << 5),
	DELAYED_ACTION_TYPE_MASTER_CONNECTED            = (1LL << 6),
	DELAYED_ACTION_TYPE_READ_NETLINK                = (1LL << 7),
	DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE        = (1LL << 8),
	__DELAYED_ACTION_TYPE_MAX,

	DELAYED_ACTION_TYPE_REFRESH_ALL                 = DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS |
	                                                  DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES |
	                                                  DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES |
	                                                  DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES |
	                                                  DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,

	DELAYED_ACTION_TYPE_MAX                         = __DELAYED_ACTION_TYPE_MAX -1,
} DelayedActionType;

#define FOR_EACH_DELAYED_ACTION(iflags, flags_all) \
	for ((iflags) = (DelayedActionType) 0x1LL; (iflags) <= DELAYED_ACTION_TYPE_MAX; (iflags) <<= 1) \
		if (NM_FLAGS_HAS (flags_all, iflags))

typedef enum {
	/* Negative values are errors from kernel. Add dummy member to
	 * make enum signed. */
	_WAIT_FOR_NL_RESPONSE_RESULT_SYSTEM_ERROR = -1,

	WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN = 0,
	WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK,
	WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_UNKNOWN,
	WAIT_FOR_NL_RESPONSE_RESULT_FAILED_RESYNC,
	WAIT_FOR_NL_RESPONSE_RESULT_FAILED_POLL,
	WAIT_FOR_NL_RESPONSE_RESULT_FAILED_TIMEOUT,
	WAIT_FOR_NL_RESPONSE_RESULT_FAILED_DISPOSING,
} WaitForNlResponseResult;

typedef void (*WaitForNlResponseCallback) (NMPlatform *platform,
                                           guint32 seq_number,
                                           WaitForNlResponseResult seq_result,
                                           gpointer user_data);

static void delayed_action_schedule (NMPlatform *platform, DelayedActionType action_type, gpointer user_data);
static gboolean delayed_action_handle_all (NMPlatform *platform, gboolean read_netlink);
static void do_request_link_no_delayed_actions (NMPlatform *platform, int ifindex, const char *name);
static void do_request_all_no_delayed_actions (NMPlatform *platform, DelayedActionType action_type);
static void cache_pre_hook (NMPCache *cache, const NMPObject *old, const NMPObject *new, NMPCacheOpsType ops_type, gpointer user_data);
static void cache_prune_candidates_prune (NMPlatform *platform);
static gboolean event_handler_read_netlink (NMPlatform *platform, gboolean wait_for_acks);
static void _assert_netns_current (NMPlatform *platform);

/*****************************************************************************/

static const char *
wait_for_nl_response_to_string (WaitForNlResponseResult seq_result, char *buf, gsize buf_size)
{
	char *buf0 = buf;

	switch (seq_result) {
	case WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN:
		nm_utils_strbuf_append_str (&buf, &buf_size, "unknown");
		break;
	case WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK:
		nm_utils_strbuf_append_str (&buf, &buf_size, "success");
		break;
	case WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_UNKNOWN:
		nm_utils_strbuf_append_str (&buf, &buf_size, "failure");
		break;
	default:
		if (seq_result < 0)
			nm_utils_strbuf_append (&buf, &buf_size, "failure %d (%s)", -((int) seq_result), g_strerror (-((int) seq_result)));
		else
			nm_utils_strbuf_append (&buf, &buf_size, "internal failure %d", (int) seq_result);
		break;
	}
	return buf0;
}

/******************************************************************
 * Support IFLA_INET6_ADDR_GEN_MODE
 ******************************************************************/

static int _support_user_ipv6ll = 0;
#define _support_user_ipv6ll_still_undecided() (G_UNLIKELY (_support_user_ipv6ll == 0))

static gboolean
_support_user_ipv6ll_get (void)
{
	if (_support_user_ipv6ll_still_undecided ()) {
		_support_user_ipv6ll = -1;
		_LOG2W ("kernel support for IFLA_INET6_ADDR_GEN_MODE %s", "failed to detect; assume no support");
		return FALSE;
	}
	return _support_user_ipv6ll > 0;

}

static void
_support_user_ipv6ll_detect (struct nlattr **tb)
{
	if (_support_user_ipv6ll_still_undecided ()) {
		if (tb[IFLA_INET6_ADDR_GEN_MODE]) {
			_support_user_ipv6ll = 1;
			_LOG2D ("kernel support for IFLA_INET6_ADDR_GEN_MODE %s", "detected");
		} else {
			_support_user_ipv6ll = -1;
			_LOG2D ("kernel support for IFLA_INET6_ADDR_GEN_MODE %s", "not detected");
		}
	}
}

/******************************************************************
 * Various utilities
 ******************************************************************/

static int
_vlan_qos_mapping_cmp_from (gconstpointer a, gconstpointer b, gpointer user_data)
{
	const NMVlanQosMapping *map_a = a;
	const NMVlanQosMapping *map_b = b;

	if (map_a->from != map_b->from)
		return map_a->from < map_b->from ? -1 : 1;
	return 0;
}

static int
_vlan_qos_mapping_cmp_from_ptr (gconstpointer a, gconstpointer b, gpointer user_data)
{
	return _vlan_qos_mapping_cmp_from (*((const NMVlanQosMapping **) a),
	                                   *((const NMVlanQosMapping **) b),
	                                   NULL);
}

/******************************************************************
 * NMLinkType functions
 ******************************************************************/

typedef struct {
	const NMLinkType nm_type;
	const char *type_string;

	/* IFLA_INFO_KIND / rtnl_link_get_type() where applicable; the rtnl type
	 * should only be specified if the device type can be created without
	 * additional parameters, and if the device type can be determined from
	 * the rtnl_type.  eg, tun/tap should not be specified since both
	 * tun and tap devices use "tun", and InfiniBand should not be
	 * specified because a PKey is required at creation. Drivers set this
	 * value from their 'struct rtnl_link_ops' structure.
	 */
	const char *rtnl_type;

	/* uevent DEVTYPE where applicable, from /sys/class/net/<ifname>/uevent;
	 * drivers set this value from their SET_NETDEV_DEV() call and the
	 * 'struct device_type' name member.
	 */
	const char *devtype;
} LinkDesc;

static const LinkDesc linktypes[] = {
	{ NM_LINK_TYPE_NONE,          "none",        NULL,          NULL },
	{ NM_LINK_TYPE_UNKNOWN,       "unknown",     NULL,          NULL },

	{ NM_LINK_TYPE_ETHERNET,      "ethernet",    NULL,          NULL },
	{ NM_LINK_TYPE_INFINIBAND,    "infiniband",  NULL,          NULL },
	{ NM_LINK_TYPE_OLPC_MESH,     "olpc-mesh",   NULL,          NULL },
	{ NM_LINK_TYPE_WIFI,          "wifi",        NULL,          "wlan" },
	{ NM_LINK_TYPE_WWAN_ETHERNET, "wwan",        NULL,          "wwan" },
	{ NM_LINK_TYPE_WIMAX,         "wimax",       "wimax",       "wimax" },

	{ NM_LINK_TYPE_DUMMY,         "dummy",       "dummy",       NULL },
	{ NM_LINK_TYPE_GRE,           "gre",         "gre",         NULL },
	{ NM_LINK_TYPE_GRETAP,        "gretap",      "gretap",      NULL },
	{ NM_LINK_TYPE_IFB,           "ifb",         "ifb",         NULL },
	{ NM_LINK_TYPE_IP6TNL,        "ip6tnl",      "ip6tnl",      NULL },
	{ NM_LINK_TYPE_IPIP,          "ipip",        "ipip",        NULL },
	{ NM_LINK_TYPE_LOOPBACK,      "loopback",    NULL,          NULL },
	{ NM_LINK_TYPE_MACVLAN,       "macvlan",     "macvlan",     NULL },
	{ NM_LINK_TYPE_MACVTAP,       "macvtap",     "macvtap",     NULL },
	{ NM_LINK_TYPE_OPENVSWITCH,   "openvswitch", "openvswitch", NULL },
	{ NM_LINK_TYPE_SIT,           "sit",         "sit",         NULL },
	{ NM_LINK_TYPE_TAP,           "tap",         NULL,          NULL },
	{ NM_LINK_TYPE_TUN,           "tun",         NULL,          NULL },
	{ NM_LINK_TYPE_VETH,          "veth",        "veth",        NULL },
	{ NM_LINK_TYPE_VLAN,          "vlan",        "vlan",        "vlan" },
	{ NM_LINK_TYPE_VXLAN,         "vxlan",       "vxlan",       "vxlan" },
	{ NM_LINK_TYPE_BNEP,          "bluetooth",   NULL,          "bluetooth" },

	{ NM_LINK_TYPE_BRIDGE,        "bridge",      "bridge",      "bridge" },
	{ NM_LINK_TYPE_BOND,          "bond",        "bond",        "bond" },
	{ NM_LINK_TYPE_TEAM,          "team",        "team",        NULL },
};

static const char *
nm_link_type_to_rtnl_type_string (NMLinkType type)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS (linktypes); i++) {
		if (type == linktypes[i].nm_type)
			return linktypes[i].rtnl_type;
	}
	g_return_val_if_reached (NULL);
}

const char *
nm_link_type_to_string (NMLinkType type)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS (linktypes); i++) {
		if (type == linktypes[i].nm_type)
			return linktypes[i].type_string;
	}
	g_return_val_if_reached (NULL);
}

/******************************************************************
 * Utilities
 ******************************************************************/

/* _timestamp_nl_to_ms:
 * @timestamp_nl: a timestamp from ifa_cacheinfo.
 * @monotonic_ms: *now* in CLOCK_MONOTONIC. Needed to estimate the current
 * uptime and how often timestamp_nl wrapped.
 *
 * Convert the timestamp from ifa_cacheinfo to CLOCK_MONOTONIC milliseconds.
 * The ifa_cacheinfo fields tstamp and cstamp contains timestamps that counts
 * with in 1/100th of a second of clock_gettime(CLOCK_MONOTONIC). However,
 * the uint32 counter wraps every 497 days of uptime, so we have to compensate
 * for that. */
static gint64
_timestamp_nl_to_ms (guint32 timestamp_nl, gint64 monotonic_ms)
{
	const gint64 WRAP_INTERVAL = (((gint64) G_MAXUINT32) + 1) * (1000 / 100);
	gint64 timestamp_nl_ms;

	/* convert timestamp from 1/100th of a second to msec. */
	timestamp_nl_ms = ((gint64) timestamp_nl) * (1000 / 100);

	/* timestamp wraps every 497 days. Try to compensate for that.*/
	if (timestamp_nl_ms > monotonic_ms) {
		/* timestamp_nl_ms is in the future. Truncate it to *now* */
		timestamp_nl_ms = monotonic_ms;
	} else if (monotonic_ms >= WRAP_INTERVAL) {
		timestamp_nl_ms += (monotonic_ms / WRAP_INTERVAL) * WRAP_INTERVAL;
		if (timestamp_nl_ms > monotonic_ms)
			timestamp_nl_ms -= WRAP_INTERVAL;
	}

	return timestamp_nl_ms;
}

static guint32
_addrtime_timestamp_to_nm (guint32 timestamp, gint32 *out_now_nm)
{
	struct timespec tp;
	gint64 now_nl, now_nm, result;
	int err;

	/* timestamp is unset. Default to 1. */
	if (!timestamp) {
		if (out_now_nm)
			*out_now_nm = 0;
		return 1;
	}

	/* do all the calculations in milliseconds scale */

	err = clock_gettime (CLOCK_MONOTONIC, &tp);
	g_assert (err == 0);
	now_nm = nm_utils_get_monotonic_timestamp_ms ();
	now_nl = (((gint64) tp.tv_sec) * ((gint64) 1000)) +
	         (tp.tv_nsec / (NM_UTILS_NS_PER_SECOND/1000));

	result = now_nm - (now_nl - _timestamp_nl_to_ms (timestamp, now_nl));

	if (out_now_nm)
		*out_now_nm = now_nm / 1000;

	/* converting the timestamp into nm_utils_get_monotonic_timestamp_ms() scale is
	 * a good guess but fails in the following situations:
	 *
	 * - If the address existed before start of the process, the timestamp in nm scale would
	 *   be negative or zero. In this case we default to 1.
	 * - during hibernation, the CLOCK_MONOTONIC/timestamp drifts from
	 *   nm_utils_get_monotonic_timestamp_ms() scale.
	 */
	if (result <= 1000)
		return 1;

	if (result > now_nm)
		return now_nm / 1000;

	return result / 1000;
}

static guint32
_addrtime_extend_lifetime (guint32 lifetime, guint32 seconds)
{
	guint64 v;

	if (   lifetime == NM_PLATFORM_LIFETIME_PERMANENT
	    || seconds == 0)
		return lifetime;

	v = (guint64) lifetime + (guint64) seconds;
	return MIN (v, NM_PLATFORM_LIFETIME_PERMANENT - 1);
}

/* The rtnl_addr object contains relative lifetimes @valid and @preferred
 * that count in seconds, starting from the moment when the kernel constructed
 * the netlink message.
 *
 * There is also a field rtnl_addr_last_update_time(), which is the absolute
 * time in 1/100th of a second of clock_gettime (CLOCK_MONOTONIC) when the address
 * was modified (wrapping every 497 days).
 * Immediately at the time when the address was last modified, #NOW and @last_update_time
 * are the same, so (only) in that case @valid and @preferred are anchored at @last_update_time.
 * However, this is not true in general. As time goes by, whenever kernel sends a new address
 * via netlink, the lifetimes keep counting down.
 **/
static void
_addrtime_get_lifetimes (guint32 timestamp,
                         guint32 lifetime,
                         guint32 preferred,
                         guint32 *out_timestamp,
                         guint32 *out_lifetime,
                         guint32 *out_preferred)
{
	gint32 now;

	if (   lifetime != NM_PLATFORM_LIFETIME_PERMANENT
	    || preferred != NM_PLATFORM_LIFETIME_PERMANENT) {
		if (preferred > lifetime)
			preferred = lifetime;
		timestamp = _addrtime_timestamp_to_nm (timestamp, &now);

		if (now == 0) {
			/* strange. failed to detect the last-update time and assumed that timestamp is 1. */
			nm_assert (timestamp == 1);
			now = nm_utils_get_monotonic_timestamp_s ();
		}
		if (timestamp < now) {
			guint32 diff = now - timestamp;

			lifetime = _addrtime_extend_lifetime (lifetime, diff);
			preferred = _addrtime_extend_lifetime (preferred, diff);
		} else
			nm_assert (timestamp == now);
	} else
		timestamp = 0;
	*out_timestamp = timestamp;
	*out_lifetime = lifetime;
	*out_preferred = preferred;
}

/******************************************************************/

static const NMPObject *
_lookup_cached_link (const NMPCache *cache, int ifindex, gboolean *completed_from_cache, const NMPObject **link_cached)
{
	const NMPObject *obj;

	nm_assert (completed_from_cache && link_cached);

	if (!*completed_from_cache) {
		obj = ifindex > 0 && cache ? nmp_cache_lookup_link (cache, ifindex) : NULL;

		if (obj && obj->_link.netlink.is_in_netlink)
			*link_cached = obj;
		else
			*link_cached = NULL;
		*completed_from_cache = TRUE;
	}
	return *link_cached;
}

/******************************************************************/

#define DEVTYPE_PREFIX "DEVTYPE="

static char *
_linktype_read_devtype (const char *ifname)
{
	char uevent[NM_STRLEN ("/sys/class/net/123456789012345/uevent\0") + 100 /*safety*/];
	char *contents = NULL;
	char *cont, *end;

	nm_sprintf_buf (uevent,
	                "/sys/class/net/%s/uevent",
	                NM_ASSERT_VALID_PATH_COMPONENT (ifname));
	nm_assert (strlen (uevent) < sizeof (uevent) - 1);

	if (!g_file_get_contents (uevent, &contents, NULL, NULL))
		return NULL;
	for (cont = contents; cont; cont = end) {
		end = strpbrk (cont, "\r\n");
		if (end)
			*end++ = '\0';
		if (strncmp (cont, DEVTYPE_PREFIX, NM_STRLEN (DEVTYPE_PREFIX)) == 0) {
			cont += NM_STRLEN (DEVTYPE_PREFIX);
			memmove (contents, cont, strlen (cont) + 1);
			return contents;
		}
	}
	g_free (contents);
	return NULL;
}

static NMLinkType
_linktype_get_type (NMPlatform *platform,
                    const NMPCache *cache,
                    const char *kind,
                    int ifindex,
                    const char *ifname,
                    unsigned flags,
                    unsigned arptype,
                    gboolean *completed_from_cache,
                    const NMPObject **link_cached,
                    const char **out_kind)
{
	guint i;

	_assert_netns_current (platform);

	if (completed_from_cache) {
		const NMPObject *obj;

		obj = _lookup_cached_link (cache, ifindex, completed_from_cache, link_cached);

		/* If we detected the link type before, we stick to that
		 * decision unless the "kind" no "name" changed. If "name" changed,
		 * it means that their type may not have been determined correctly
		 * due to race conditions while accessing sysfs.
		 *
		 * This way, we save edditional ethtool/sysctl lookups, but moreover,
		 * we keep the linktype stable and don't change it as long as the link
		 * exists.
		 *
		 * Note that kernel *can* reuse the ifindex (on integer overflow, and
		 * when moving interfce to other netns). Thus here there is a tiny potential
		 * of messing stuff up. */
		if (   obj
		    && !NM_IN_SET (obj->link.type, NM_LINK_TYPE_UNKNOWN, NM_LINK_TYPE_NONE)
		    && !g_strcmp0 (ifname, obj->link.name)
		    && (   !kind
		        || !g_strcmp0 (kind, obj->link.kind))) {
			nm_assert (obj->link.kind == g_intern_string (obj->link.kind));
			*out_kind = obj->link.kind;
			return obj->link.type;
		}
	}

	*out_kind = g_intern_string (kind);

	if (kind) {
		for (i = 0; i < G_N_ELEMENTS (linktypes); i++) {
			if (g_strcmp0 (kind, linktypes[i].rtnl_type) == 0)
				return linktypes[i].nm_type;
		}

		if (!strcmp (kind, "tun")) {
			NMPlatformTunProperties props;

			if (   platform
			    && nm_platform_link_tun_get_properties_ifname (platform, ifname, &props)) {
				if (!g_strcmp0 (props.mode, "tap"))
					return NM_LINK_TYPE_TAP;
				if (!g_strcmp0 (props.mode, "tun"))
					return NM_LINK_TYPE_TUN;
			}

			/* try guessing the type using the link flags instead... */
			if (flags & IFF_POINTOPOINT)
				return NM_LINK_TYPE_TUN;
			return NM_LINK_TYPE_TAP;
		}
	}

	if (arptype == ARPHRD_LOOPBACK)
		return NM_LINK_TYPE_LOOPBACK;
	else if (arptype == ARPHRD_INFINIBAND)
		return NM_LINK_TYPE_INFINIBAND;
	else if (arptype == ARPHRD_SIT)
		return NM_LINK_TYPE_SIT;
	else if (arptype == ARPHRD_TUNNEL6)
		return NM_LINK_TYPE_IP6TNL;

	if (ifname) {
		char anycast_mask[NM_STRLEN ("/sys/class/net/123456789012345/anycast_mask\0") + 100 /*safety*/];
		gs_free char *driver = NULL;
		gs_free char *devtype = NULL;

		/* Fallback OVS detection for kernel <= 3.16 */
		if (nmp_utils_ethtool_get_driver_info (ifname, &driver, NULL, NULL)) {
			if (!g_strcmp0 (driver, "openvswitch"))
				return NM_LINK_TYPE_OPENVSWITCH;

			if (arptype == 256) {
				/* Some s390 CTC-type devices report 256 for the encapsulation type
				 * for some reason, but we need to call them Ethernet.
				 */
				if (!g_strcmp0 (driver, "ctcm"))
					return NM_LINK_TYPE_ETHERNET;
			}
		}

		nm_sprintf_buf (anycast_mask,
		                "/sys/class/net/%s/anycast_mask",
		                NM_ASSERT_VALID_PATH_COMPONENT (ifname));
		nm_assert (strlen (anycast_mask) < sizeof (anycast_mask) - 1);

		if (g_file_test (anycast_mask, G_FILE_TEST_EXISTS))
			return NM_LINK_TYPE_OLPC_MESH;

		devtype = _linktype_read_devtype (ifname);
		for (i = 0; devtype && i < G_N_ELEMENTS (linktypes); i++) {
			if (g_strcmp0 (devtype, linktypes[i].devtype) == 0) {
				if (linktypes[i].nm_type == NM_LINK_TYPE_BNEP) {
					/* Both BNEP and 6lowpan use DEVTYPE=bluetooth, so we must
					 * use arptype to distinguish between them.
					 */
					if (arptype != ARPHRD_ETHER)
						continue;
				}
				return linktypes[i].nm_type;
			}
		}

		/* Fallback for drivers that don't call SET_NETDEV_DEVTYPE() */
		if (wifi_utils_is_wifi (ifname))
			return NM_LINK_TYPE_WIFI;

		if (arptype == ARPHRD_ETHER) {
			/* Standard wired ethernet interfaces don't report an rtnl_link_type, so
			 * only allow fallback to Ethernet if no type is given.  This should
			 * prevent future virtual network drivers from being treated as Ethernet
			 * when they should be Generic instead.
			 */
			if (!kind && !devtype)
				return NM_LINK_TYPE_ETHERNET;
			/* The USB gadget interfaces behave and look like ordinary ethernet devices
			 * aside from the DEVTYPE. */
			if (!g_strcmp0 (devtype, "gadget"))
				return NM_LINK_TYPE_ETHERNET;
		}
	}

	return NM_LINK_TYPE_UNKNOWN;
}

/******************************************************************
 * libnl unility functions and wrappers
 ******************************************************************/

#define nm_auto_nlmsg __attribute__((cleanup(_nm_auto_nl_msg_cleanup)))
static void
_nm_auto_nl_msg_cleanup (void *ptr)
{
	nlmsg_free (*((struct nl_msg **) ptr));
}

static const char *
_nl_nlmsg_type_to_str (guint16 type, char *buf, gsize len)
{
	const char *str_type = NULL;

	switch (type) {
	case RTM_NEWLINK:  str_type = "NEWLINK";  break;
	case RTM_DELLINK:  str_type = "DELLINK";  break;
	case RTM_NEWADDR:  str_type = "NEWADDR";  break;
	case RTM_DELADDR:  str_type = "DELADDR";  break;
	case RTM_NEWROUTE: str_type = "NEWROUTE"; break;
	case RTM_DELROUTE: str_type = "DELROUTE"; break;
	}
	if (str_type)
		g_strlcpy (buf, str_type, len);
	else
		g_snprintf (buf, len, "(%d)", type);
	return buf;
}

/******************************************************************
 * NMPObject/netlink functions
 ******************************************************************/

#define _check_addr_or_errout(tb, attr, addr_len) \
	({ \
	    const struct nlattr *__t = (tb)[(attr)]; \
		\
	    if (__t) { \
			if (nla_len (__t) != (addr_len)) { \
				goto errout; \
			} \
		} \
		!!__t; \
	})

/*****************************************************************************/

/* Copied and heavily modified from libnl3's inet6_parse_protinfo(). */
static gboolean
_parse_af_inet6 (NMPlatform *platform,
                 struct nlattr *attr,
                 NMUtilsIPv6IfaceId *out_iid,
                 guint8 *out_iid_is_valid,
                 guint8 *out_addr_gen_mode_inv)
{
	static struct nla_policy policy[IFLA_INET6_MAX+1] = {
		[IFLA_INET6_FLAGS]              = { .type = NLA_U32 },
		[IFLA_INET6_CACHEINFO]          = { .minlen = offset_plus_sizeof(struct ifla_cacheinfo, retrans_time) },
		[IFLA_INET6_CONF]               = { .minlen = 4 },
		[IFLA_INET6_STATS]              = { .minlen = 8 },
		[IFLA_INET6_ICMP6STATS]         = { .minlen = 8 },
		[IFLA_INET6_TOKEN]              = { .minlen = sizeof(struct in6_addr) },
		[IFLA_INET6_ADDR_GEN_MODE]      = { .type = NLA_U8 },
	};
	struct nlattr *tb[IFLA_INET6_MAX+1];
	int err;
	struct in6_addr i6_token;
	gboolean iid_is_valid = FALSE;
	guint8 i6_addr_gen_mode_inv = 0;
	gboolean success = FALSE;

	err = nla_parse_nested (tb, IFLA_INET6_MAX, attr, policy);
	if (err < 0)
		goto errout;

	if (tb[IFLA_INET6_CONF] && nla_len(tb[IFLA_INET6_CONF]) % 4)
		goto errout;
	if (tb[IFLA_INET6_STATS] && nla_len(tb[IFLA_INET6_STATS]) % 8)
		goto errout;
	if (tb[IFLA_INET6_ICMP6STATS] && nla_len(tb[IFLA_INET6_ICMP6STATS]) % 8)
		goto errout;

	if (_check_addr_or_errout (tb, IFLA_INET6_TOKEN, sizeof (struct in6_addr))) {
		nla_memcpy (&i6_token, tb[IFLA_INET6_TOKEN], sizeof (struct in6_addr));
		if (!IN6_IS_ADDR_UNSPECIFIED (&i6_token))
			iid_is_valid = TRUE;
	}

	/* Hack to detect support addrgenmode of the kernel. We only parse
	 * netlink messages that we receive from kernel, hence this check
	 * is valid. */
	_support_user_ipv6ll_detect (tb);

	if (tb[IFLA_INET6_ADDR_GEN_MODE]) {
		i6_addr_gen_mode_inv = _nm_platform_uint8_inv (nla_get_u8 (tb[IFLA_INET6_ADDR_GEN_MODE]));
		if (i6_addr_gen_mode_inv == 0) {
			/* an inverse addrgenmode of zero is unexpected. We need to reserve zero
			 * to signal "unset". */
			goto errout;
		}
	}

	success = TRUE;
	if (iid_is_valid) {
		nm_utils_ipv6_interface_identifier_get_from_addr (out_iid, &i6_token);
		*out_iid_is_valid = TRUE;
	}
	*out_addr_gen_mode_inv = i6_addr_gen_mode_inv;
errout:
	return success;
}

/*****************************************************************************/

static NMPObject *
_parse_lnk_gre (const char *kind, struct nlattr *info_data)
{
	static struct nla_policy policy[IFLA_GRE_MAX + 1] = {
		[IFLA_GRE_LINK]     = { .type = NLA_U32 },
		[IFLA_GRE_IFLAGS]   = { .type = NLA_U16 },
		[IFLA_GRE_OFLAGS]   = { .type = NLA_U16 },
		[IFLA_GRE_IKEY]     = { .type = NLA_U32 },
		[IFLA_GRE_OKEY]     = { .type = NLA_U32 },
		[IFLA_GRE_LOCAL]    = { .type = NLA_U32 },
		[IFLA_GRE_REMOTE]   = { .type = NLA_U32 },
		[IFLA_GRE_TTL]      = { .type = NLA_U8 },
		[IFLA_GRE_TOS]      = { .type = NLA_U8 },
		[IFLA_GRE_PMTUDISC] = { .type = NLA_U8 },
	};
	struct nlattr *tb[IFLA_GRE_MAX + 1];
	int err;
	NMPObject *obj;
	NMPlatformLnkGre *props;

	if (!info_data || g_strcmp0 (kind, "gre"))
		return NULL;

	err = nla_parse_nested (tb, IFLA_GRE_MAX, info_data, policy);
	if (err < 0)
		return NULL;

	obj = nmp_object_new (NMP_OBJECT_TYPE_LNK_GRE, NULL);
	props = &obj->lnk_gre;

	props->parent_ifindex = tb[IFLA_GRE_LINK] ? nla_get_u32 (tb[IFLA_GRE_LINK]) : 0;
	props->input_flags = tb[IFLA_GRE_IFLAGS] ? ntohs (nla_get_u16 (tb[IFLA_GRE_IFLAGS])) : 0;
	props->output_flags = tb[IFLA_GRE_OFLAGS] ? ntohs (nla_get_u16 (tb[IFLA_GRE_OFLAGS])) : 0;
	props->input_key = tb[IFLA_GRE_IKEY] ? ntohl (nla_get_u32 (tb[IFLA_GRE_IKEY])) : 0;
	props->output_key = tb[IFLA_GRE_OKEY] ? ntohl (nla_get_u32 (tb[IFLA_GRE_OKEY])) : 0;
	props->local = tb[IFLA_GRE_LOCAL] ? nla_get_u32 (tb[IFLA_GRE_LOCAL]) : 0;
	props->remote = tb[IFLA_GRE_REMOTE] ? nla_get_u32 (tb[IFLA_GRE_REMOTE]) : 0;
	props->tos = tb[IFLA_GRE_TOS] ? nla_get_u8 (tb[IFLA_GRE_TOS]) : 0;
	props->ttl = tb[IFLA_GRE_TTL] ? nla_get_u8 (tb[IFLA_GRE_TTL]) : 0;
	props->path_mtu_discovery = !tb[IFLA_GRE_PMTUDISC] || !!nla_get_u8 (tb[IFLA_GRE_PMTUDISC]);

	return obj;
}

/*****************************************************************************/

/* IFLA_IPOIB_* were introduced in the 3.7 kernel, but the kernel headers
 * we're building against might not have those properties even though the
 * running kernel might.
 */
#define IFLA_IPOIB_UNSPEC 0
#define IFLA_IPOIB_PKEY   1
#define IFLA_IPOIB_MODE   2
#define IFLA_IPOIB_UMCAST 3
#undef IFLA_IPOIB_MAX
#define IFLA_IPOIB_MAX IFLA_IPOIB_UMCAST

#define IPOIB_MODE_DATAGRAM  0 /* using unreliable datagram QPs */
#define IPOIB_MODE_CONNECTED 1 /* using connected QPs */

static NMPObject *
_parse_lnk_infiniband (const char *kind, struct nlattr *info_data)
{
	static struct nla_policy policy[IFLA_IPOIB_MAX + 1] = {
		[IFLA_IPOIB_PKEY]   = { .type = NLA_U16 },
		[IFLA_IPOIB_MODE]   = { .type = NLA_U16 },
		[IFLA_IPOIB_UMCAST] = { .type = NLA_U16 },
	};
	struct nlattr *tb[IFLA_IPOIB_MAX + 1];
	NMPlatformLnkInfiniband *info;
	NMPObject *obj;
	int err;
	const char *mode;

	if (!info_data || g_strcmp0 (kind, "ipoib"))
		return NULL;

	err = nla_parse_nested (tb, IFLA_IPOIB_MAX, info_data, policy);
	if (err < 0)
		return NULL;

	if (!tb[IFLA_IPOIB_PKEY] || !tb[IFLA_IPOIB_MODE])
		return NULL;

	switch (nla_get_u16 (tb[IFLA_IPOIB_MODE])) {
	case IPOIB_MODE_DATAGRAM:
		mode = "datagram";
		break;
	case IPOIB_MODE_CONNECTED:
		mode = "connected";
		break;
	default:
		return NULL;
	}

	obj = nmp_object_new (NMP_OBJECT_TYPE_LNK_INFINIBAND, NULL);
	info = &obj->lnk_infiniband;

	info->p_key = nla_get_u16 (tb[IFLA_IPOIB_PKEY]);
	info->mode = mode;

	return obj;
}

/*****************************************************************************/

static NMPObject *
_parse_lnk_ip6tnl (const char *kind, struct nlattr *info_data)
{
	static struct nla_policy policy[IFLA_IPTUN_MAX + 1] = {
		[IFLA_IPTUN_LINK]        = { .type = NLA_U32 },
		[IFLA_IPTUN_LOCAL]       = { .type = NLA_UNSPEC,
		                             .minlen = sizeof (struct in6_addr)},
		[IFLA_IPTUN_REMOTE]      = { .type = NLA_UNSPEC,
		                             .minlen = sizeof (struct in6_addr)},
		[IFLA_IPTUN_TTL]         = { .type = NLA_U8 },
		[IFLA_IPTUN_ENCAP_LIMIT] = { .type = NLA_U8 },
		[IFLA_IPTUN_FLOWINFO]    = { .type = NLA_U32 },
		[IFLA_IPTUN_PROTO]       = { .type = NLA_U8 },
	};
	struct nlattr *tb[IFLA_IPTUN_MAX + 1];
	int err;
	NMPObject *obj;
	NMPlatformLnkIp6Tnl *props;
	guint32 flowinfo;

	if (!info_data || g_strcmp0 (kind, "ip6tnl"))
		return NULL;

	err = nla_parse_nested (tb, IFLA_IPTUN_MAX, info_data, policy);
	if (err < 0)
		return NULL;

	obj = nmp_object_new (NMP_OBJECT_TYPE_LNK_IP6TNL, NULL);
	props = &obj->lnk_ip6tnl;

	if (tb[IFLA_IPTUN_LINK])
		props->parent_ifindex = nla_get_u32 (tb[IFLA_IPTUN_LINK]);
	if (tb[IFLA_IPTUN_LOCAL])
		memcpy (&props->local, nla_data (tb[IFLA_IPTUN_LOCAL]), sizeof (props->local));
	if (tb[IFLA_IPTUN_REMOTE])
		memcpy (&props->remote, nla_data (tb[IFLA_IPTUN_REMOTE]), sizeof (props->remote));
	if (tb[IFLA_IPTUN_TTL])
		props->ttl = nla_get_u8 (tb[IFLA_IPTUN_TTL]);
	if (tb[IFLA_IPTUN_ENCAP_LIMIT])
		props->encap_limit = nla_get_u8 (tb[IFLA_IPTUN_ENCAP_LIMIT]);
	if (tb[IFLA_IPTUN_FLOWINFO]) {
		flowinfo = ntohl (nla_get_u32 (tb[IFLA_IPTUN_FLOWINFO]));
		props->flow_label = flowinfo & IP6_FLOWINFO_FLOWLABEL_MASK;
		props->tclass = (flowinfo & IP6_FLOWINFO_TCLASS_MASK) >> IP6_FLOWINFO_TCLASS_SHIFT;
	}
	if (tb[IFLA_IPTUN_PROTO])
		props->proto = nla_get_u8 (tb[IFLA_IPTUN_PROTO]);

	return obj;
}

/*****************************************************************************/

static NMPObject *
_parse_lnk_ipip (const char *kind, struct nlattr *info_data)
{
	static struct nla_policy policy[IFLA_IPTUN_MAX + 1] = {
		[IFLA_IPTUN_LINK]     = { .type = NLA_U32 },
		[IFLA_IPTUN_LOCAL]    = { .type = NLA_U32 },
		[IFLA_IPTUN_REMOTE]   = { .type = NLA_U32 },
		[IFLA_IPTUN_TTL]      = { .type = NLA_U8 },
		[IFLA_IPTUN_TOS]      = { .type = NLA_U8 },
		[IFLA_IPTUN_PMTUDISC] = { .type = NLA_U8 },
	};
	struct nlattr *tb[IFLA_IPTUN_MAX + 1];
	int err;
	NMPObject *obj;
	NMPlatformLnkIpIp *props;

	if (!info_data || g_strcmp0 (kind, "ipip"))
		return NULL;

	err = nla_parse_nested (tb, IFLA_IPTUN_MAX, info_data, policy);
	if (err < 0)
		return NULL;

	obj = nmp_object_new (NMP_OBJECT_TYPE_LNK_IPIP, NULL);
	props = &obj->lnk_ipip;

	props->parent_ifindex = tb[IFLA_IPTUN_LINK] ? nla_get_u32 (tb[IFLA_IPTUN_LINK]) : 0;
	props->local = tb[IFLA_IPTUN_LOCAL] ? nla_get_u32 (tb[IFLA_IPTUN_LOCAL]) : 0;
	props->remote = tb[IFLA_IPTUN_REMOTE] ? nla_get_u32 (tb[IFLA_IPTUN_REMOTE]) : 0;
	props->tos = tb[IFLA_IPTUN_TOS] ? nla_get_u8 (tb[IFLA_IPTUN_TOS]) : 0;
	props->ttl = tb[IFLA_IPTUN_TTL] ? nla_get_u8 (tb[IFLA_IPTUN_TTL]) : 0;
	props->path_mtu_discovery = !tb[IFLA_IPTUN_PMTUDISC] || !!nla_get_u8 (tb[IFLA_IPTUN_PMTUDISC]);

	return obj;
}

/*****************************************************************************/

static NMPObject *
_parse_lnk_macvlan (const char *kind, struct nlattr *info_data)
{
	static struct nla_policy policy[IFLA_MACVLAN_MAX + 1] = {
		[IFLA_MACVLAN_MODE]  = { .type = NLA_U32 },
		[IFLA_MACVLAN_FLAGS] = { .type = NLA_U16 },
	};
	NMPlatformLnkMacvlan *props;
	struct nlattr *tb[IFLA_MACVLAN_MAX + 1];
	int err;
	NMPObject *obj;
	gboolean tap;

	if (!info_data)
		return NULL;

	if (!g_strcmp0 (kind, "macvlan"))
		tap = FALSE;
	else if (!g_strcmp0 (kind, "macvtap"))
		tap = TRUE;
	else
		return NULL;

	err = nla_parse_nested (tb, IFLA_MACVLAN_MAX, info_data, policy);
	if (err < 0)
		return NULL;

	if (!tb[IFLA_MACVLAN_MODE])
		return NULL;

	obj = nmp_object_new (tap ? NMP_OBJECT_TYPE_LNK_MACVTAP : NMP_OBJECT_TYPE_LNK_MACVLAN, NULL);
	props = &obj->lnk_macvlan;
	props->mode = nla_get_u32 (tb[IFLA_MACVLAN_MODE]);
	props->tap = tap;

	if (tb[IFLA_MACVLAN_FLAGS])
		props->no_promisc = NM_FLAGS_HAS (nla_get_u16 (tb[IFLA_MACVLAN_FLAGS]), MACVLAN_FLAG_NOPROMISC);

	return obj;
}

/*****************************************************************************/

static NMPObject *
_parse_lnk_sit (const char *kind, struct nlattr *info_data)
{
	static struct nla_policy policy[IFLA_IPTUN_MAX + 1] = {
		[IFLA_IPTUN_LINK]     = { .type = NLA_U32 },
		[IFLA_IPTUN_LOCAL]    = { .type = NLA_U32 },
		[IFLA_IPTUN_REMOTE]   = { .type = NLA_U32 },
		[IFLA_IPTUN_TTL]      = { .type = NLA_U8 },
		[IFLA_IPTUN_TOS]      = { .type = NLA_U8 },
		[IFLA_IPTUN_PMTUDISC] = { .type = NLA_U8 },
		[IFLA_IPTUN_FLAGS]    = { .type = NLA_U16 },
		[IFLA_IPTUN_PROTO]    = { .type = NLA_U8 },
	};
	struct nlattr *tb[IFLA_IPTUN_MAX + 1];
	int err;
	NMPObject *obj;
	NMPlatformLnkSit *props;

	if (!info_data || g_strcmp0 (kind, "sit"))
		return NULL;

	err = nla_parse_nested (tb, IFLA_IPTUN_MAX, info_data, policy);
	if (err < 0)
		return NULL;

	obj = nmp_object_new (NMP_OBJECT_TYPE_LNK_SIT, NULL);
	props = &obj->lnk_sit;

	props->parent_ifindex = tb[IFLA_IPTUN_LINK] ? nla_get_u32 (tb[IFLA_IPTUN_LINK]) : 0;
	props->local = tb[IFLA_IPTUN_LOCAL] ? nla_get_u32 (tb[IFLA_IPTUN_LOCAL]) : 0;
	props->remote = tb[IFLA_IPTUN_REMOTE] ? nla_get_u32 (tb[IFLA_IPTUN_REMOTE]) : 0;
	props->tos = tb[IFLA_IPTUN_TOS] ? nla_get_u8 (tb[IFLA_IPTUN_TOS]) : 0;
	props->ttl = tb[IFLA_IPTUN_TTL] ? nla_get_u8 (tb[IFLA_IPTUN_TTL]) : 0;
	props->path_mtu_discovery = !tb[IFLA_IPTUN_PMTUDISC] || !!nla_get_u8 (tb[IFLA_IPTUN_PMTUDISC]);
	props->flags = tb[IFLA_IPTUN_FLAGS] ? nla_get_u16 (tb[IFLA_IPTUN_FLAGS]) : 0;
	props->proto = tb[IFLA_IPTUN_PROTO] ? nla_get_u8 (tb[IFLA_IPTUN_PROTO]) : 0;

	return obj;
}

/*****************************************************************************/

static gboolean
_vlan_qos_mapping_from_nla (struct nlattr *nlattr,
                            const NMVlanQosMapping **out_map,
                            guint *out_n_map)
{
	struct nlattr *nla;
	int remaining;
	gs_unref_ptrarray GPtrArray *array = NULL;

	G_STATIC_ASSERT (sizeof (NMVlanQosMapping) == sizeof (struct ifla_vlan_qos_mapping));
	G_STATIC_ASSERT (sizeof (((NMVlanQosMapping *) 0)->to) == sizeof (((struct ifla_vlan_qos_mapping *) 0)->to));
	G_STATIC_ASSERT (sizeof (((NMVlanQosMapping *) 0)->from) == sizeof (((struct ifla_vlan_qos_mapping *) 0)->from));
	G_STATIC_ASSERT (sizeof (NMVlanQosMapping) == sizeof (((NMVlanQosMapping *) 0)->from) + sizeof (((NMVlanQosMapping *) 0)->to));

	nm_assert (out_map && !*out_map);
	nm_assert (out_n_map && !*out_n_map);

	if (!nlattr)
		return TRUE;

	array = g_ptr_array_new ();
	nla_for_each_nested (nla, nlattr, remaining) {
		if (nla_len (nla) < sizeof(NMVlanQosMapping))
			return FALSE;
		g_ptr_array_add (array, nla_data (nla));
	}

	if (array->len > 0) {
		NMVlanQosMapping *list;
		guint i, j;

		/* The sorting is necessary, because for egress mapping, kernel
		 * doesn't sent the items strictly sorted by the from field. */
		g_ptr_array_sort_with_data (array, _vlan_qos_mapping_cmp_from_ptr, NULL);

		list = g_new (NMVlanQosMapping,  array->len);

		for (i = 0, j = 0; i < array->len; i++) {
			NMVlanQosMapping *map;

			map = array->pdata[i];

			/* kernel doesn't really send us duplicates. Just be extra cautious
			 * because we want strong guarantees about the sort order and uniqueness
			 * of our mapping list (for simpler equality comparison). */
			if (   j > 0
			    && list[j - 1].from == map->from)
				list[j - 1] = *map;
			else
				list[j++] = *map;
		}

		*out_n_map = j;
		*out_map = list;
	}

	return TRUE;
}

/* Copied and heavily modified from libnl3's vlan_parse() */
static NMPObject *
_parse_lnk_vlan (const char *kind, struct nlattr *info_data)
{
	static struct nla_policy policy[IFLA_VLAN_MAX+1] = {
		[IFLA_VLAN_ID]          = { .type = NLA_U16 },
		[IFLA_VLAN_FLAGS]       = { .minlen = offset_plus_sizeof(struct ifla_vlan_flags, flags) },
		[IFLA_VLAN_INGRESS_QOS] = { .type = NLA_NESTED },
		[IFLA_VLAN_EGRESS_QOS]  = { .type = NLA_NESTED },
		[IFLA_VLAN_PROTOCOL]    = { .type = NLA_U16 },
	};
	struct nlattr *tb[IFLA_VLAN_MAX+1];
	int err;
	nm_auto_nmpobj NMPObject *obj = NULL;
	NMPObject *obj_result;

	if (!info_data || g_strcmp0 (kind, "vlan"))
		return NULL;

	if ((err = nla_parse_nested (tb, IFLA_VLAN_MAX, info_data, policy)) < 0)
		return NULL;

	if (!tb[IFLA_VLAN_ID])
		return NULL;

	obj = nmp_object_new (NMP_OBJECT_TYPE_LNK_VLAN, NULL);
	obj->lnk_vlan.id = nla_get_u16 (tb[IFLA_VLAN_ID]);

	if (tb[IFLA_VLAN_FLAGS]) {
		struct ifla_vlan_flags flags;

		nla_memcpy (&flags, tb[IFLA_VLAN_FLAGS], sizeof(flags));

		obj->lnk_vlan.flags = flags.flags;
	}

	if (!_vlan_qos_mapping_from_nla (tb[IFLA_VLAN_INGRESS_QOS],
	                                 &obj->_lnk_vlan.ingress_qos_map,
	                                 &obj->_lnk_vlan.n_ingress_qos_map))
		return NULL;

	if (!_vlan_qos_mapping_from_nla (tb[IFLA_VLAN_EGRESS_QOS],
	                                 &obj->_lnk_vlan.egress_qos_map,
	                                 &obj->_lnk_vlan.n_egress_qos_map))
		return NULL;


	obj_result = obj;
	obj = NULL;
	return obj_result;
}

/*****************************************************************************/

/* The installed kernel headers might not have VXLAN stuff at all, or
 * they might have the original properties, but not PORT, GROUP6, or LOCAL6.
 * So until we depend on kernel >= 3.11, we just ignore the actual enum
 * in if_link.h and define the values ourselves.
 */
#define IFLA_VXLAN_UNSPEC      0
#define IFLA_VXLAN_ID          1
#define IFLA_VXLAN_GROUP       2
#define IFLA_VXLAN_LINK        3
#define IFLA_VXLAN_LOCAL       4
#define IFLA_VXLAN_TTL         5
#define IFLA_VXLAN_TOS         6
#define IFLA_VXLAN_LEARNING    7
#define IFLA_VXLAN_AGEING      8
#define IFLA_VXLAN_LIMIT       9
#define IFLA_VXLAN_PORT_RANGE 10
#define IFLA_VXLAN_PROXY      11
#define IFLA_VXLAN_RSC        12
#define IFLA_VXLAN_L2MISS     13
#define IFLA_VXLAN_L3MISS     14
#define IFLA_VXLAN_PORT       15
#define IFLA_VXLAN_GROUP6     16
#define IFLA_VXLAN_LOCAL6     17
#undef IFLA_VXLAN_MAX
#define IFLA_VXLAN_MAX IFLA_VXLAN_LOCAL6

/* older kernel header might not contain 'struct ifla_vxlan_port_range'.
 * Redefine it. */
struct nm_ifla_vxlan_port_range {
	guint16 low;
	guint16 high;
};

static NMPObject *
_parse_lnk_vxlan (const char *kind, struct nlattr *info_data)
{
	static struct nla_policy policy[IFLA_VXLAN_MAX + 1] = {
		[IFLA_VXLAN_ID]         = { .type = NLA_U32 },
		[IFLA_VXLAN_GROUP]      = { .type = NLA_U32 },
		[IFLA_VXLAN_GROUP6]     = { .type = NLA_UNSPEC,
		                            .minlen = sizeof (struct in6_addr) },
		[IFLA_VXLAN_LINK]       = { .type = NLA_U32 },
		[IFLA_VXLAN_LOCAL]      = { .type = NLA_U32 },
		[IFLA_VXLAN_LOCAL6]     = { .type = NLA_UNSPEC,
		                            .minlen = sizeof (struct in6_addr) },
		[IFLA_VXLAN_TOS]        = { .type = NLA_U8 },
		[IFLA_VXLAN_TTL]        = { .type = NLA_U8 },
		[IFLA_VXLAN_LEARNING]   = { .type = NLA_U8 },
		[IFLA_VXLAN_AGEING]     = { .type = NLA_U32 },
		[IFLA_VXLAN_LIMIT]      = { .type = NLA_U32 },
		[IFLA_VXLAN_PORT_RANGE] = { .type = NLA_UNSPEC,
		                            .minlen  = sizeof (struct nm_ifla_vxlan_port_range) },
		[IFLA_VXLAN_PROXY]      = { .type = NLA_U8 },
		[IFLA_VXLAN_RSC]        = { .type = NLA_U8 },
		[IFLA_VXLAN_L2MISS]     = { .type = NLA_U8 },
		[IFLA_VXLAN_L3MISS]     = { .type = NLA_U8 },
		[IFLA_VXLAN_PORT]       = { .type = NLA_U16 },
	};
	NMPlatformLnkVxlan *props;
	struct nlattr *tb[IFLA_VXLAN_MAX + 1];
	struct nm_ifla_vxlan_port_range *range;
	int err;
	NMPObject *obj;

	if (!info_data || g_strcmp0 (kind, "vxlan"))
		return NULL;

	err = nla_parse_nested (tb, IFLA_VXLAN_MAX, info_data, policy);
	if (err < 0)
		return NULL;

	obj = nmp_object_new (NMP_OBJECT_TYPE_LNK_VXLAN, NULL);

	props = &obj->lnk_vxlan;

	if (tb[IFLA_VXLAN_LINK])
		props->parent_ifindex = nla_get_u32 (tb[IFLA_VXLAN_LINK]);
	if (tb[IFLA_VXLAN_ID])
		props->id = nla_get_u32 (tb[IFLA_VXLAN_ID]);
	if (tb[IFLA_VXLAN_GROUP])
		props->group = nla_get_u32 (tb[IFLA_VXLAN_GROUP]);
	if (tb[IFLA_VXLAN_LOCAL])
		props->local = nla_get_u32 (tb[IFLA_VXLAN_LOCAL]);
	if (tb[IFLA_VXLAN_GROUP6])
		memcpy (&props->group6, nla_data (tb[IFLA_VXLAN_GROUP6]), sizeof (props->group6));
	if (tb[IFLA_VXLAN_LOCAL6])
		memcpy (&props->local6, nla_data (tb[IFLA_VXLAN_LOCAL6]), sizeof (props->local6));

	if (tb[IFLA_VXLAN_AGEING])
		props->ageing = nla_get_u32 (tb[IFLA_VXLAN_AGEING]);
	if (tb[IFLA_VXLAN_LIMIT])
		props->limit = nla_get_u32 (tb[IFLA_VXLAN_LIMIT]);
	if (tb[IFLA_VXLAN_TOS])
		props->tos = nla_get_u8 (tb[IFLA_VXLAN_TOS]);
	if (tb[IFLA_VXLAN_TTL])
		props->ttl = nla_get_u8 (tb[IFLA_VXLAN_TTL]);

	if (tb[IFLA_VXLAN_PORT])
		props->dst_port = ntohs (nla_get_u16 (tb[IFLA_VXLAN_PORT]));

	if (tb[IFLA_VXLAN_PORT_RANGE]) {
		range = nla_data (tb[IFLA_VXLAN_PORT_RANGE]);
		props->src_port_min = ntohs (range->low);
		props->src_port_max = ntohs (range->high);
	}

	if (tb[IFLA_VXLAN_LEARNING])
		props->learning = !!nla_get_u8 (tb[IFLA_VXLAN_LEARNING]);
	if (tb[IFLA_VXLAN_PROXY])
		props->proxy = !!nla_get_u8 (tb[IFLA_VXLAN_PROXY]);
	if (tb[IFLA_VXLAN_RSC])
		props->rsc = !!nla_get_u8 (tb[IFLA_VXLAN_RSC]);
	if (tb[IFLA_VXLAN_L2MISS])
		props->l2miss = !!nla_get_u8 (tb[IFLA_VXLAN_L2MISS]);
	if (tb[IFLA_VXLAN_L3MISS])
		props->l3miss = !!nla_get_u8 (tb[IFLA_VXLAN_L3MISS]);

	return obj;
}

/*****************************************************************************/

/* Copied and heavily modified from libnl3's link_msg_parser(). */
static NMPObject *
_new_from_nl_link (NMPlatform *platform, const NMPCache *cache, struct nlmsghdr *nlh, gboolean id_only)
{
	static struct nla_policy policy[IFLA_MAX+1] = {
		[IFLA_IFNAME]           = { .type = NLA_STRING,
		                            .maxlen = IFNAMSIZ },
		[IFLA_MTU]              = { .type = NLA_U32 },
		[IFLA_TXQLEN]           = { .type = NLA_U32 },
		[IFLA_LINK]             = { .type = NLA_U32 },
		[IFLA_WEIGHT]           = { .type = NLA_U32 },
		[IFLA_MASTER]           = { .type = NLA_U32 },
		[IFLA_OPERSTATE]        = { .type = NLA_U8 },
		[IFLA_LINKMODE]         = { .type = NLA_U8 },
		[IFLA_LINKINFO]         = { .type = NLA_NESTED },
		[IFLA_QDISC]            = { .type = NLA_STRING,
		                            .maxlen = IFQDISCSIZ },
		[IFLA_STATS]            = { .minlen = offset_plus_sizeof(struct rtnl_link_stats, tx_compressed) },
		[IFLA_STATS64]          = { .minlen = offset_plus_sizeof(struct rtnl_link_stats64, tx_compressed)},
		[IFLA_MAP]              = { .minlen = offset_plus_sizeof(struct rtnl_link_ifmap, port) },
		[IFLA_IFALIAS]          = { .type = NLA_STRING, .maxlen = IFALIASZ },
		[IFLA_NUM_VF]           = { .type = NLA_U32 },
		[IFLA_AF_SPEC]          = { .type = NLA_NESTED },
		[IFLA_PROMISCUITY]      = { .type = NLA_U32 },
		[IFLA_NUM_TX_QUEUES]    = { .type = NLA_U32 },
		[IFLA_NUM_RX_QUEUES]    = { .type = NLA_U32 },
		[IFLA_GROUP]            = { .type = NLA_U32 },
		[IFLA_CARRIER]          = { .type = NLA_U8 },
		[IFLA_PHYS_PORT_ID]     = { .type = NLA_UNSPEC },
		[IFLA_NET_NS_PID]       = { .type = NLA_U32 },
		[IFLA_NET_NS_FD]        = { .type = NLA_U32 },
	};
	static struct nla_policy policy_link_info[IFLA_INFO_MAX+1] = {
		[IFLA_INFO_KIND]        = { .type = NLA_STRING },
		[IFLA_INFO_DATA]        = { .type = NLA_NESTED },
		[IFLA_INFO_XSTATS]      = { .type = NLA_NESTED },
	};
	const struct ifinfomsg *ifi;
	struct nlattr *tb[IFLA_MAX+1];
	struct nlattr *li[IFLA_INFO_MAX+1];
	struct nlattr *nl_info_data = NULL;
	const char *nl_info_kind = NULL;
	int err;
	nm_auto_nmpobj NMPObject *obj = NULL;
	NMPObject *obj_result = NULL;
	gboolean completed_from_cache_val = FALSE;
	gboolean *completed_from_cache = cache ? &completed_from_cache_val : NULL;
	const NMPObject *link_cached = NULL;
	NMPObject *lnk_data = NULL;
	gboolean address_complete_from_cache = TRUE;
	gboolean lnk_data_complete_from_cache = TRUE;

	if (!nlmsg_valid_hdr (nlh, sizeof (*ifi)))
		return NULL;
	ifi = nlmsg_data(nlh);

	obj = nmp_object_new_link (ifi->ifi_index);

	if (id_only)
		goto id_only_handled;

	err = nlmsg_parse (nlh, sizeof (*ifi), tb, IFLA_MAX, policy);
	if (err < 0)
		goto errout;

	if (!tb[IFLA_IFNAME])
		goto errout;
	nla_strlcpy(obj->link.name, tb[IFLA_IFNAME], IFNAMSIZ);
	if (!obj->link.name[0])
		goto errout;

	if (tb[IFLA_LINKINFO]) {
		err = nla_parse_nested (li, IFLA_INFO_MAX, tb[IFLA_LINKINFO], policy_link_info);
		if (err < 0)
			goto errout;

		if (li[IFLA_INFO_KIND])
			nl_info_kind = nla_get_string (li[IFLA_INFO_KIND]);

		nl_info_data = li[IFLA_INFO_DATA];
	}

	obj->link.n_ifi_flags = ifi->ifi_flags;
	obj->link.connected = NM_FLAGS_HAS (obj->link.n_ifi_flags, IFF_LOWER_UP);
	obj->link.arptype = ifi->ifi_type;

	obj->link.type = _linktype_get_type (platform,
	                                     cache,
	                                     nl_info_kind,
	                                     obj->link.ifindex,
	                                     obj->link.name,
	                                     obj->link.n_ifi_flags,
	                                     obj->link.arptype,
	                                     completed_from_cache,
	                                     &link_cached,
	                                     &obj->link.kind);

	if (tb[IFLA_MASTER])
		obj->link.master = nla_get_u32 (tb[IFLA_MASTER]);

	if (tb[IFLA_LINK]) {
		if (!tb[IFLA_LINK_NETNSID])
			obj->link.parent = nla_get_u32 (tb[IFLA_LINK]);
		else
			obj->link.parent = NM_PLATFORM_LINK_OTHER_NETNS;
	}

	if (tb[IFLA_ADDRESS]) {
		int l = nla_len (tb[IFLA_ADDRESS]);

		if (l > 0 && l <= NM_UTILS_HWADDR_LEN_MAX) {
			G_STATIC_ASSERT (NM_UTILS_HWADDR_LEN_MAX == sizeof (obj->link.addr.data));
			memcpy (obj->link.addr.data, nla_data (tb[IFLA_ADDRESS]), l);
			obj->link.addr.len = l;
		}
		address_complete_from_cache = FALSE;
	}

	if (tb[IFLA_AF_SPEC]) {
		struct nlattr *af_attr;
		int remaining;

		nla_for_each_nested (af_attr, tb[IFLA_AF_SPEC], remaining) {
			switch (nla_type (af_attr)) {
			case AF_INET6:
				_parse_af_inet6 (platform,
				                 af_attr,
				                 &obj->link.inet6_token.iid,
				                 &obj->link.inet6_token.is_valid,
				                 &obj->link.inet6_addr_gen_mode_inv);
				break;
			}
		}
	}

	if (tb[IFLA_MTU])
		obj->link.mtu = nla_get_u32 (tb[IFLA_MTU]);

	switch (obj->link.type) {
	case NM_LINK_TYPE_GRE:
		lnk_data = _parse_lnk_gre (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_INFINIBAND:
		lnk_data = _parse_lnk_infiniband (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_IP6TNL:
		lnk_data = _parse_lnk_ip6tnl (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_IPIP:
		lnk_data = _parse_lnk_ipip (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_MACVLAN:
	case NM_LINK_TYPE_MACVTAP:
		lnk_data = _parse_lnk_macvlan (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_SIT:
		lnk_data = _parse_lnk_sit (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_VLAN:
		lnk_data = _parse_lnk_vlan (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_VXLAN:
		lnk_data = _parse_lnk_vxlan (nl_info_kind, nl_info_data);
		break;
	default:
		lnk_data_complete_from_cache = FALSE;
		break;
	}

	if (   completed_from_cache
	    && (   lnk_data_complete_from_cache
	        || address_complete_from_cache)) {
		_lookup_cached_link (cache, obj->link.ifindex, completed_from_cache, &link_cached);
		if (link_cached) {
			if (   lnk_data_complete_from_cache
			    && link_cached->link.type == obj->link.type
			    && link_cached->_link.netlink.lnk
			    && (   !lnk_data
			        || nmp_object_equal (lnk_data, link_cached->_link.netlink.lnk))) {
				/* We always try to look into the cache and reuse the object there.
				 * We do that, because we consider the lnk object as immutable and don't
				 * modify it after creating. Hence we can share it and reuse.
				 *
				 * Also, sometimes the info-data is missing for updates. In this case
				 * we want to keep the previously received lnk_data. */
				nmp_object_unref (lnk_data);
				lnk_data = nmp_object_ref (link_cached->_link.netlink.lnk);
			}
			if (address_complete_from_cache)
				obj->link.addr = link_cached->link.addr;
		}
	}

	obj->_link.netlink.lnk = lnk_data;

	obj->_link.netlink.is_in_netlink = TRUE;
id_only_handled:
	obj_result = obj;
	obj = NULL;
errout:
	return obj_result;
}

/* Copied and heavily modified from libnl3's addr_msg_parser(). */
static NMPObject *
_new_from_nl_addr (struct nlmsghdr *nlh, gboolean id_only)
{
	static struct nla_policy policy[IFA_MAX+1] = {
		[IFA_LABEL]     = { .type = NLA_STRING,
		                     .maxlen = IFNAMSIZ },
		[IFA_CACHEINFO] = { .minlen = offset_plus_sizeof(struct ifa_cacheinfo, tstamp) },
	};
	const struct ifaddrmsg *ifa;
	struct nlattr *tb[IFA_MAX+1];
	int err;
	gboolean is_v4;
	nm_auto_nmpobj NMPObject *obj = NULL;
	NMPObject *obj_result = NULL;
	int addr_len;
	guint32 lifetime, preferred, timestamp;

	if (!nlmsg_valid_hdr (nlh, sizeof (*ifa)))
		return NULL;
	ifa = nlmsg_data(nlh);

	if (!NM_IN_SET (ifa->ifa_family, AF_INET, AF_INET6))
		goto errout;
	is_v4 = ifa->ifa_family == AF_INET;

	err = nlmsg_parse(nlh, sizeof(*ifa), tb, IFA_MAX, policy);
	if (err < 0)
		goto errout;

	addr_len = is_v4
	           ? sizeof (in_addr_t)
	           : sizeof (struct in6_addr);

	if (ifa->ifa_prefixlen > (is_v4 ? 32 : 128))
		goto errout;

	/*****************************************************************/

	obj = nmp_object_new (is_v4 ? NMP_OBJECT_TYPE_IP4_ADDRESS : NMP_OBJECT_TYPE_IP6_ADDRESS, NULL);

	obj->ip_address.ifindex = ifa->ifa_index;
	obj->ip_address.plen = ifa->ifa_prefixlen;

	_check_addr_or_errout (tb, IFA_ADDRESS, addr_len);
	_check_addr_or_errout (tb, IFA_LOCAL, addr_len);
	if (is_v4) {
		/* For IPv4, kernel omits IFA_LOCAL/IFA_ADDRESS if (and only if) they
		 * are effectively 0.0.0.0 (all-zero). */
		if (tb[IFA_LOCAL])
			memcpy (&obj->ip4_address.address, nla_data (tb[IFA_LOCAL]), addr_len);
		if (tb[IFA_ADDRESS])
			memcpy (&obj->ip4_address.peer_address, nla_data (tb[IFA_ADDRESS]), addr_len);
	} else {
		/* For IPv6, IFA_ADDRESS is always present.
		 *
		 * If IFA_LOCAL is missing, IFA_ADDRESS is @address and @peer_address
		 * is :: (all-zero).
		 *
		 * If unexpectely IFA_ADDRESS is missing, make the best of it -- but it _should_
		 * actually be there. */
		if (tb[IFA_ADDRESS] || tb[IFA_LOCAL]) {
			if (tb[IFA_LOCAL]) {
				memcpy (&obj->ip6_address.address, nla_data (tb[IFA_LOCAL]), addr_len);
				if (tb[IFA_ADDRESS])
					memcpy (&obj->ip6_address.peer_address, nla_data (tb[IFA_ADDRESS]), addr_len);
				else
					obj->ip6_address.peer_address = obj->ip6_address.address;
			} else
				memcpy (&obj->ip6_address.address, nla_data (tb[IFA_ADDRESS]), addr_len);
		}
	}

	obj->ip_address.addr_source = NM_IP_CONFIG_SOURCE_KERNEL;

	obj->ip_address.n_ifa_flags = tb[IFA_FLAGS]
	                              ? nla_get_u32 (tb[IFA_FLAGS])
	                              : ifa->ifa_flags;

	if (is_v4) {
		if (tb[IFA_LABEL]) {
			char label[IFNAMSIZ];

			nla_strlcpy (label, tb[IFA_LABEL], IFNAMSIZ);

			/* Check for ':'; we're only interested in labels used as interface aliases */
			if (strchr (label, ':'))
				g_strlcpy (obj->ip4_address.label, label, sizeof (obj->ip4_address.label));
		}
	}

	lifetime = NM_PLATFORM_LIFETIME_PERMANENT;
	preferred = NM_PLATFORM_LIFETIME_PERMANENT;
	timestamp = 0;
	/* IPv6 only */
	if (tb[IFA_CACHEINFO]) {
		const struct ifa_cacheinfo *ca = nla_data(tb[IFA_CACHEINFO]);

		lifetime = ca->ifa_valid;
		preferred = ca->ifa_prefered;
		timestamp = ca->tstamp;
	}
	_addrtime_get_lifetimes (timestamp,
	                         lifetime,
	                         preferred,
	                         &obj->ip_address.timestamp,
	                         &obj->ip_address.lifetime,
	                         &obj->ip_address.preferred);

	obj_result = obj;
	obj = NULL;
errout:
	return obj_result;
}

/* Copied and heavily modified from libnl3's rtnl_route_parse() and parse_multipath(). */
static NMPObject *
_new_from_nl_route (struct nlmsghdr *nlh, gboolean id_only)
{
	static struct nla_policy policy[RTA_MAX+1] = {
		[RTA_IIF]       = { .type = NLA_U32 },
		[RTA_OIF]       = { .type = NLA_U32 },
		[RTA_PRIORITY]  = { .type = NLA_U32 },
		[RTA_FLOW]      = { .type = NLA_U32 },
		[RTA_CACHEINFO] = { .minlen = offset_plus_sizeof(struct rta_cacheinfo, rta_tsage) },
		[RTA_METRICS]   = { .type = NLA_NESTED },
		[RTA_MULTIPATH] = { .type = NLA_NESTED },
	};
	const struct rtmsg *rtm;
	struct nlattr *tb[RTA_MAX + 1];
	int err;
	gboolean is_v4;
	nm_auto_nmpobj NMPObject *obj = NULL;
	NMPObject *obj_result = NULL;
	int addr_len;
	struct {
		gboolean is_present;
		int ifindex;
		NMIPAddr gateway;
	} nh;
	guint32 mss;
	guint32 table;

	if (!nlmsg_valid_hdr (nlh, sizeof (*rtm)))
		return NULL;
	rtm = nlmsg_data(nlh);

	/*****************************************************************
	 * only handle ~normal~ routes.
	 *****************************************************************/

	if (!NM_IN_SET (rtm->rtm_family, AF_INET, AF_INET6))
		goto errout;

	if (   rtm->rtm_type != RTN_UNICAST
	    || rtm->rtm_tos != 0)
		goto errout;

	err = nlmsg_parse (nlh, sizeof (struct rtmsg), tb, RTA_MAX, policy);
	if (err < 0)
		goto errout;

	table = tb[RTA_TABLE]
	        ? nla_get_u32 (tb[RTA_TABLE])
	        : (guint32) rtm->rtm_table;
	if (table != RT_TABLE_MAIN)
		goto errout;

	/*****************************************************************/

	is_v4 = rtm->rtm_family == AF_INET;
	addr_len = is_v4
	           ? sizeof (in_addr_t)
	           : sizeof (struct in6_addr);

	if (rtm->rtm_dst_len > (is_v4 ? 32 : 128))
		goto errout;

	/*****************************************************************
	 * parse nexthops. Only handle routes with one nh.
	 *****************************************************************/

	memset (&nh, 0, sizeof (nh));

	if (tb[RTA_MULTIPATH]) {
		struct rtnexthop *rtnh = nla_data (tb[RTA_MULTIPATH]);
		size_t tlen = nla_len(tb[RTA_MULTIPATH]);

		while (tlen >= sizeof(*rtnh) && tlen >= rtnh->rtnh_len) {

			if (nh.is_present) {
				/* we don't support multipath routes. */
				goto errout;
			}
			nh.is_present = TRUE;

			nh.ifindex = rtnh->rtnh_ifindex;

			if (rtnh->rtnh_len > sizeof(*rtnh)) {
				struct nlattr *ntb[RTA_MAX + 1];

				err = nla_parse (ntb, RTA_MAX, (struct nlattr *)
				                 RTNH_DATA(rtnh),
				                 rtnh->rtnh_len - sizeof (*rtnh),
				                 policy);
				if (err < 0)
					goto errout;

				if (_check_addr_or_errout (ntb, RTA_GATEWAY, addr_len))
					memcpy (&nh.gateway, nla_data (ntb[RTA_GATEWAY]), addr_len);
			}

			tlen -= RTNH_ALIGN(rtnh->rtnh_len);
			rtnh = RTNH_NEXT(rtnh);
		}
	}

	if (   tb[RTA_OIF]
	    || tb[RTA_GATEWAY]
	    || tb[RTA_FLOW]) {
		int ifindex = 0;
		NMIPAddr gateway = NMIPAddrInit;

		if (tb[RTA_OIF])
			ifindex = nla_get_u32 (tb[RTA_OIF]);
		if (_check_addr_or_errout (tb, RTA_GATEWAY, addr_len))
			memcpy (&gateway, nla_data (tb[RTA_GATEWAY]), addr_len);

		if (!nh.is_present) {
			/* If no nexthops have been provided via RTA_MULTIPATH
			 * we add it as regular nexthop to maintain backwards
			 * compatibility */
			nh.ifindex = ifindex;
			nh.gateway = gateway;
		} else {
			/* Kernel supports new style nexthop configuration,
			 * verify that it is a duplicate and ignore old-style nexthop. */
			if (   nh.ifindex != ifindex
			    || memcmp (&nh.gateway, &gateway, addr_len) != 0)
				goto errout;
		}
	} else if (!nh.is_present)
		goto errout;

	/*****************************************************************/

	mss = 0;
	if (tb[RTA_METRICS]) {
		struct nlattr *mtb[RTAX_MAX + 1];
		int i;

		err = nla_parse_nested(mtb, RTAX_MAX, tb[RTA_METRICS], NULL);
		if (err < 0)
			goto errout;

		for (i = 1; i <= RTAX_MAX; i++) {
			if (mtb[i]) {
				if (i == RTAX_ADVMSS) {
					if (nla_len (mtb[i]) >= sizeof (uint32_t))
						mss = nla_get_u32(mtb[i]);
					break;
				}
			}
		}
	}

	/*****************************************************************/

	obj = nmp_object_new (is_v4 ? NMP_OBJECT_TYPE_IP4_ROUTE : NMP_OBJECT_TYPE_IP6_ROUTE, NULL);

	obj->ip_route.ifindex = nh.ifindex;

	if (_check_addr_or_errout (tb, RTA_DST, addr_len))
		memcpy (obj->ip_route.network_ptr, nla_data (tb[RTA_DST]), addr_len);

	obj->ip_route.plen = rtm->rtm_dst_len;

	if (tb[RTA_PRIORITY])
		obj->ip_route.metric = nla_get_u32(tb[RTA_PRIORITY]);

	if (is_v4)
		obj->ip4_route.gateway = nh.gateway.addr4;
	else
		obj->ip6_route.gateway = nh.gateway.addr6;

	if (is_v4)
		obj->ip4_route.scope_inv = nm_platform_route_scope_inv (rtm->rtm_scope);

	if (is_v4) {
		if (_check_addr_or_errout (tb, RTA_PREFSRC, addr_len))
			memcpy (&obj->ip4_route.pref_src, nla_data (tb[RTA_PREFSRC]), addr_len);
	}

	obj->ip_route.mss = mss;

	if (NM_FLAGS_HAS (rtm->rtm_flags, RTM_F_CLONED)) {
		/* we must not straight way reject cloned routes, because we might have cached
		 * a non-cloned route. If we now receive an update of the route with the route
		 * being cloned, we must still return the object, so that we can remove the old
		 * one from the cache.
		 *
		 * This happens, because this route is not nmp_object_is_alive().
		 * */
		obj->ip_route.rt_cloned = TRUE;
	}

	obj->ip_route.rt_source = nmp_utils_ip_config_source_from_rtprot (rtm->rtm_protocol);

	obj_result = obj;
	obj = NULL;
errout:
	return obj_result;
}

/**
 * nmp_object_new_from_nl:
 * @platform: (allow-none): for creating certain objects, the constructor wants to check
 *   sysfs. For this the platform instance is needed. If missing, the object might not
 *   be correctly detected.
 * @cache: (allow-none): for certain objects, the netlink message doesn't contain all the information.
 *   If a cache is given, the object is completed with information from the cache.
 * @nlh: the netlink message header
 * @id_only: whether only to create an empty object with only the ID fields set.
 *
 * Returns: %NULL or a newly created NMPObject instance.
 **/
static NMPObject *
nmp_object_new_from_nl (NMPlatform *platform, const NMPCache *cache, struct nl_msg *msg, gboolean id_only)
{
	struct nlmsghdr *msghdr;

	if (nlmsg_get_proto (msg) != NETLINK_ROUTE)
		return NULL;

	msghdr = nlmsg_hdr (msg);

	switch (msghdr->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
	case RTM_GETLINK:
	case RTM_SETLINK:
		return _new_from_nl_link (platform, cache, msghdr, id_only);
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_GETADDR:
		return _new_from_nl_addr (msghdr, id_only);
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
	case RTM_GETROUTE:
		return _new_from_nl_route (msghdr, id_only);
	default:
		return NULL;
	}
}

/******************************************************************/

static gboolean
_nl_msg_new_link_set_afspec (struct nl_msg *msg,
                             int addr_gen_mode)
{
	struct nlattr *af_spec;
	struct nlattr *af_attr;

	nm_assert (msg);

	if (!(af_spec = nla_nest_start (msg, IFLA_AF_SPEC)))
		goto nla_put_failure;

	if (addr_gen_mode >= 0) {
		if (!(af_attr = nla_nest_start (msg, AF_INET6)))
			goto nla_put_failure;

		NLA_PUT_U8 (msg, IFLA_INET6_ADDR_GEN_MODE, addr_gen_mode);

		nla_nest_end (msg, af_attr);
	}

	nla_nest_end (msg, af_spec);

	return TRUE;
nla_put_failure:
	return FALSE;
}

static gboolean
_nl_msg_new_link_set_linkinfo (struct nl_msg *msg,
                               NMLinkType link_type)
{
	struct nlattr *info;
	const char *kind;

	nm_assert (msg);

	kind = nm_link_type_to_rtnl_type_string (link_type);
	if (!kind)
		goto nla_put_failure;

	if (!(info = nla_nest_start (msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING (msg, IFLA_INFO_KIND, kind);

	nla_nest_end (msg, info);

	return TRUE;
nla_put_failure:
	return FALSE;
}

static gboolean
_nl_msg_new_link_set_linkinfo_vlan (struct nl_msg *msg,
                                    int vlan_id,
                                    guint32 flags_mask,
                                    guint32 flags_set,
                                    const NMVlanQosMapping *ingress_qos,
                                    int ingress_qos_len,
                                    const NMVlanQosMapping *egress_qos,
                                    int egress_qos_len)
{
	struct nlattr *info;
	struct nlattr *data;
	guint i;
	gboolean has_any_vlan_properties = FALSE;

#define VLAN_XGRESS_PRIO_VALID(from) (((from) & ~(guint32) 0x07) == 0)

	nm_assert (msg);

	/* We must not create an empty IFLA_LINKINFO section. Otherwise, kernel
	 * rejects the request as invalid. */
	if (   flags_mask != 0
	    || vlan_id >= 0)
		has_any_vlan_properties = TRUE;
	if (   !has_any_vlan_properties
	    && ingress_qos && ingress_qos_len > 0) {
		for (i = 0; i < ingress_qos_len; i++) {
			if (VLAN_XGRESS_PRIO_VALID (ingress_qos[i].from)) {
				has_any_vlan_properties = TRUE;
				break;
			}
		}
	}
	if (   !has_any_vlan_properties
	    && egress_qos && egress_qos_len > 0) {
		for (i = 0; i < egress_qos_len; i++) {
			if (VLAN_XGRESS_PRIO_VALID (egress_qos[i].to)) {
				has_any_vlan_properties = TRUE;
				break;
			}
		}
	}
	if (!has_any_vlan_properties)
		return TRUE;

	if (!(info = nla_nest_start (msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING (msg, IFLA_INFO_KIND, "vlan");

	if (!(data = nla_nest_start (msg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	if (vlan_id >= 0)
		NLA_PUT_U16 (msg, IFLA_VLAN_ID, vlan_id);

	if (flags_mask != 0) {
		struct ifla_vlan_flags flags = {
			.flags = flags_mask & flags_set,
			.mask = flags_mask,
		};

		NLA_PUT (msg, IFLA_VLAN_FLAGS, sizeof (flags), &flags);
	}

	if (ingress_qos && ingress_qos_len > 0) {
		struct nlattr *qos = NULL;

		for (i = 0; i < ingress_qos_len; i++) {
			/* Silently ignore invalid mappings. Kernel would truncate
			 * them and modify the wrong mapping. */
			if (VLAN_XGRESS_PRIO_VALID (ingress_qos[i].from)) {
				if (!qos) {
					if (!(qos = nla_nest_start (msg, IFLA_VLAN_INGRESS_QOS)))
						goto nla_put_failure;
				}
				NLA_PUT (msg, i, sizeof (ingress_qos[i]), &ingress_qos[i]);
			}
		}

		if (qos)
			nla_nest_end (msg, qos);
	}

	if (egress_qos && egress_qos_len > 0) {
		struct nlattr *qos = NULL;

		for (i = 0; i < egress_qos_len; i++) {
			if (VLAN_XGRESS_PRIO_VALID (egress_qos[i].to)) {
				if (!qos) {
					if (!(qos = nla_nest_start(msg, IFLA_VLAN_EGRESS_QOS)))
						goto nla_put_failure;
				}
				NLA_PUT (msg, i, sizeof (egress_qos[i]), &egress_qos[i]);
			}
		}

		if (qos)
			nla_nest_end(msg, qos);
	}

	nla_nest_end (msg, data);
	nla_nest_end (msg, info);

	return TRUE;
nla_put_failure:
	return FALSE;
}

static struct nl_msg *
_nl_msg_new_link (int nlmsg_type,
                  int nlmsg_flags,
                  int ifindex,
                  const char *ifname,
                  unsigned flags_mask,
                  unsigned flags_set)
{
	struct nl_msg *msg;
	struct ifinfomsg ifi = {
		.ifi_change = flags_mask,
		.ifi_flags = flags_set,
		.ifi_index = ifindex,
	};

	nm_assert (NM_IN_SET (nlmsg_type, RTM_DELLINK, RTM_NEWLINK, RTM_GETLINK));

	if (!(msg = nlmsg_alloc_simple (nlmsg_type, nlmsg_flags)))
		g_return_val_if_reached (NULL);

	if (nlmsg_append (msg, &ifi, sizeof (ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (ifname)
		NLA_PUT_STRING (msg, IFLA_IFNAME, ifname);

	return msg;
nla_put_failure:
	nlmsg_free (msg);
	g_return_val_if_reached (NULL);
}

/* Copied and modified from libnl3's build_addr_msg(). */
static struct nl_msg *
_nl_msg_new_address (int nlmsg_type,
                     int nlmsg_flags,
                     int family,
                     int ifindex,
                     gconstpointer address,
                     guint8 plen,
                     gconstpointer peer_address,
                     guint32 flags,
                     int scope,
                     guint32 lifetime,
                     guint32 preferred,
                     const char *label)
{
	struct nl_msg *msg;
	struct ifaddrmsg am = {
		.ifa_family = family,
		.ifa_index = ifindex,
		.ifa_prefixlen = plen,
		.ifa_flags = flags,
	};
	gsize addr_len;

	nm_assert (NM_IN_SET (family, AF_INET, AF_INET6));
	nm_assert (NM_IN_SET (nlmsg_type, RTM_NEWADDR, RTM_DELADDR));

	msg = nlmsg_alloc_simple (nlmsg_type, nlmsg_flags);
	if (!msg)
		g_return_val_if_reached (NULL);

	if (scope == -1) {
		/* Allow having scope unset, and detect the scope (including IPv4 compatibility hack). */
		if (   family == AF_INET
		    && address
		    && *((char *) address) == 127)
			scope = RT_SCOPE_HOST;
		else
			scope = RT_SCOPE_UNIVERSE;
	}
	am.ifa_scope = scope,

	addr_len = family == AF_INET ? sizeof (in_addr_t) : sizeof (struct in6_addr);

	if (nlmsg_append (msg, &am, sizeof (am), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (address)
		NLA_PUT (msg, IFA_LOCAL, addr_len, address);

	if (peer_address)
		NLA_PUT (msg, IFA_ADDRESS, addr_len, peer_address);
	else if (address)
		NLA_PUT (msg, IFA_ADDRESS, addr_len, address);

	if (label && label[0])
		NLA_PUT_STRING (msg, IFA_LABEL, label);

	if (   family == AF_INET
	    && nlmsg_type != RTM_DELADDR
	    && address
	    && *((in_addr_t *) address) != 0) {
		in_addr_t broadcast;

		broadcast = *((in_addr_t *) address) | ~nm_utils_ip4_prefix_to_netmask (plen);
		NLA_PUT (msg, IFA_BROADCAST, addr_len, &broadcast);
	}

	if (   lifetime != NM_PLATFORM_LIFETIME_PERMANENT
	    || preferred != NM_PLATFORM_LIFETIME_PERMANENT) {
		struct ifa_cacheinfo ca = {
			.ifa_valid = lifetime,
			.ifa_prefered = preferred,
		};

		NLA_PUT (msg, IFA_CACHEINFO, sizeof(ca), &ca);
	}

	if (flags & ~((guint32) 0xFF)) {
		/* only set the IFA_FLAGS attribute, if they actually contain additional
		 * flags that are not already set to am.ifa_flags.
		 *
		 * Older kernels refuse RTM_NEWADDR and RTM_NEWROUTE messages with EINVAL
		 * if they contain unknown netlink attributes. See net/core/rtnetlink.c, which
		 * was fixed by kernel commit 661d2967b3f1b34eeaa7e212e7b9bbe8ee072b59. */
		NLA_PUT_U32 (msg, IFA_FLAGS, flags);
	}

	return msg;

nla_put_failure:
	nlmsg_free (msg);
	g_return_val_if_reached (NULL);
}

/* Copied and modified from libnl3's build_route_msg() and rtnl_route_build_msg(). */
static struct nl_msg *
_nl_msg_new_route (int nlmsg_type,
                   int nlmsg_flags,
                   int family,
                   int ifindex,
                   NMIPConfigSource source,
                   unsigned char scope,
                   gconstpointer network,
                   guint8 plen,
                   gconstpointer gateway,
                   guint32 metric,
                   guint32 mss,
                   gconstpointer pref_src)
{
	struct nl_msg *msg;
	struct rtmsg rtmsg = {
		.rtm_family = family,
		.rtm_tos = 0,
		.rtm_table = RT_TABLE_MAIN, /* omit setting RTA_TABLE attribute */
		.rtm_protocol = nmp_utils_ip_config_source_coerce_to_rtprot (source),
		.rtm_scope = scope,
		.rtm_type = RTN_UNICAST,
		.rtm_flags = 0,
		.rtm_dst_len = plen,
		.rtm_src_len = 0,
	};
	NMIPAddr network_clean;

	gsize addr_len;

	nm_assert (NM_IN_SET (family, AF_INET, AF_INET6));
	nm_assert (NM_IN_SET (nlmsg_type, RTM_NEWROUTE, RTM_DELROUTE));
	nm_assert (network);

	msg = nlmsg_alloc_simple (nlmsg_type, nlmsg_flags);
	if (!msg)
		g_return_val_if_reached (NULL);

	if (nlmsg_append (msg, &rtmsg, sizeof (rtmsg), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	addr_len = family == AF_INET ? sizeof (in_addr_t) : sizeof (struct in6_addr);

	nm_utils_ipx_address_clear_host_address (family, &network_clean, network, plen);
	NLA_PUT (msg, RTA_DST, addr_len, &network_clean);

	NLA_PUT_U32 (msg, RTA_PRIORITY, metric);

	if (pref_src)
		NLA_PUT (msg, RTA_PREFSRC, addr_len, pref_src);

	if (mss > 0) {
		struct nlattr *metrics;

		metrics = nla_nest_start (msg, RTA_METRICS);
		if (!metrics)
			goto nla_put_failure;

		NLA_PUT_U32 (msg, RTAX_ADVMSS, mss);

		nla_nest_end(msg, metrics);
	}

	/* We currently don't have need for multi-hop routes... */
	if (   gateway
	    && memcmp (gateway, &nm_ip_addr_zero, addr_len) != 0)
		NLA_PUT (msg, RTA_GATEWAY, addr_len, gateway);
	NLA_PUT_U32 (msg, RTA_OIF, ifindex);

	return msg;

nla_put_failure:
	nlmsg_free (msg);
	g_return_val_if_reached (NULL);
}

/******************************************************************/

static int _support_kernel_extended_ifa_flags = -1;

#define _support_kernel_extended_ifa_flags_still_undecided() (G_UNLIKELY (_support_kernel_extended_ifa_flags == -1))

static void
_support_kernel_extended_ifa_flags_detect (struct nl_msg *msg)
{
	struct nlmsghdr *msg_hdr;

	if (!_support_kernel_extended_ifa_flags_still_undecided ())
		return;

	msg_hdr = nlmsg_hdr (msg);
	if (msg_hdr->nlmsg_type != RTM_NEWADDR)
		return;

	/* the extended address flags are only set for AF_INET6 */
	if (((struct ifaddrmsg *) nlmsg_data (msg_hdr))->ifa_family != AF_INET6)
		return;

	/* see if the nl_msg contains the IFA_FLAGS attribute. If it does,
	 * we assume, that the kernel supports extended flags, IFA_F_MANAGETEMPADDR
	 * and IFA_F_NOPREFIXROUTE (they were added together).
	 **/
	_support_kernel_extended_ifa_flags = !!nlmsg_find_attr (msg_hdr, sizeof (struct ifaddrmsg), 8 /* IFA_FLAGS */);
	_LOG2D ("support: kernel-extended-ifa-flags: %ssupported", _support_kernel_extended_ifa_flags ? "" : "not ");
}

static gboolean
_support_kernel_extended_ifa_flags_get (void)
{
	if (_support_kernel_extended_ifa_flags_still_undecided ()) {
		_LOG2W ("support: kernel-extended-ifa-flags: unable to detect kernel support for handling IPv6 temporary addresses. Assume support");
		_support_kernel_extended_ifa_flags = 1;
	}
	return _support_kernel_extended_ifa_flags;
}

/******************************************************************
 * NMPlatform types and functions
 ******************************************************************/

typedef struct {
	guint32 seq_number;
	WaitForNlResponseResult seq_result;
	gint64 timeout_abs_ns;
	WaitForNlResponseResult *out_seq_result;
	gint *out_refresh_all_in_progess;
} DelayedActionWaitForNlResponseData;

typedef struct _NMLinuxPlatformPrivate NMLinuxPlatformPrivate;

struct _NMLinuxPlatformPrivate {
	struct nl_sock *nlh;
	guint32 nlh_seq_next;
#ifdef NM_MORE_LOGGING
	guint32 nlh_seq_last_handled;
#endif
	guint32 nlh_seq_last_seen;
	NMPCache *cache;
	GIOChannel *event_channel;
	guint event_id;

	gboolean sysctl_get_warned;
	GHashTable *sysctl_get_prev_values;

	GUdevClient *udev_client;

	struct {
		/* which delayed actions are scheduled, as marked in @flags.
		 * Some types have additional arguments in the fields below. */
		DelayedActionType flags;

		/* counter that a refresh all action is in progress, separated
		 * by type. */
		gint refresh_all_in_progess[_DELAYED_ACTION_IDX_REFRESH_ALL_NUM];

		GPtrArray *list_master_connected;
		GPtrArray *list_refresh_link;
		GArray *list_wait_for_nl_response;

		gint is_handling;
	} delayed_action;

	GHashTable *prune_candidates;

	GHashTable *wifi_data;
};

static inline NMLinuxPlatformPrivate *
NM_LINUX_PLATFORM_GET_PRIVATE (const void *self)
{
	nm_assert (NM_IS_LINUX_PLATFORM (self));

	return ((NMLinuxPlatform *) self)->priv;
}

G_DEFINE_TYPE (NMLinuxPlatform, nm_linux_platform, NM_TYPE_PLATFORM)

NMPlatform *
nm_linux_platform_new (gboolean netns_support)
{
	return g_object_new (NM_TYPE_LINUX_PLATFORM,
	                     NM_PLATFORM_REGISTER_SINGLETON, FALSE,
	                     NM_PLATFORM_NETNS_SUPPORT, netns_support,
	                     NULL);
}

void
nm_linux_platform_setup (void)
{
	g_object_new (NM_TYPE_LINUX_PLATFORM,
	              NM_PLATFORM_REGISTER_SINGLETON, TRUE,
	              NM_PLATFORM_NETNS_SUPPORT, FALSE,
	              NULL);
}

/******************************************************************/

static void
_assert_netns_current (NMPlatform *platform)
{
#if NM_MORE_ASSERTS
	nm_assert (NM_IS_LINUX_PLATFORM (platform));

	nm_assert (NM_IN_SET (nm_platform_netns_get (platform), NULL, nmp_netns_get_current ()));
#endif
}

static void
_log_dbg_sysctl_set_impl (NMPlatform *platform, const char *path, const char *value)
{
	GError *error = NULL;
	char *contents, *contents_escaped;
	char *value_escaped = g_strescape (value, NULL);

	if (!g_file_get_contents (path, &contents, NULL, &error)) {
		_LOGD ("sysctl: setting '%s' to '%s' (current value cannot be read: %s)", path, value_escaped, error->message);
		g_clear_error (&error);
	} else {
		g_strstrip (contents);
		contents_escaped = g_strescape (contents, NULL);
		if (strcmp (contents, value) == 0)
			_LOGD ("sysctl: setting '%s' to '%s' (current value is identical)", path, value_escaped);
		else
			_LOGD ("sysctl: setting '%s' to '%s' (current value is '%s')", path, value_escaped, contents_escaped);
		g_free (contents);
		g_free (contents_escaped);
	}
	g_free (value_escaped);
}

#define _log_dbg_sysctl_set(platform, path, value) \
	G_STMT_START { \
		if (_LOGD_ENABLED ()) { \
			_log_dbg_sysctl_set_impl (platform, path, value); \
		} \
	} G_STMT_END

static gboolean
sysctl_set (NMPlatform *platform, const char *path, const char *value)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	int fd, tries;
	gssize nwrote;
	gsize len;
	char *actual;
	gs_free char *actual_free = NULL;
	int errsv;

	g_return_val_if_fail (path != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	/* Don't write outside known locations */
	g_assert (g_str_has_prefix (path, "/proc/sys/")
	          || g_str_has_prefix (path, "/sys/"));
	/* Don't write to suspicious locations */
	g_assert (!strstr (path, "/../"));

	if (!nm_platform_netns_push (platform, &netns)) {
		errno = ENETDOWN;
		return FALSE;
	}

	fd = open (path, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		errsv = errno;
		if (errsv == ENOENT) {
			_LOGD ("sysctl: failed to open '%s': (%d) %s",
			       path, errsv, strerror (errsv));
		} else {
			_LOGE ("sysctl: failed to open '%s': (%d) %s",
			       path, errsv, strerror (errsv));
		}
		errno = errsv;
		return FALSE;
	}

	_log_dbg_sysctl_set (platform, path, value);

	/* Most sysfs and sysctl options don't care about a trailing LF, while some
	 * (like infiniband) do.  So always add the LF.  Also, neither sysfs nor
	 * sysctl support partial writes so the LF must be added to the string we're
	 * about to write.
	 */
	len = strlen (value) + 1;
	if (len > 512)
		actual = actual_free = g_malloc (len + 1);
	else
		actual = g_alloca (len + 1);
	memcpy (actual, value, len - 1);
	actual[len - 1] = '\n';
	actual[len] = '\0';

	/* Try to write the entire value three times if a partial write occurs */
	errsv = 0;
	for (tries = 0, nwrote = 0; tries < 3 && nwrote != len; tries++) {
		nwrote = write (fd, actual, len);
		if (nwrote == -1) {
			errsv = errno;
			if (errsv == EINTR) {
				_LOGD ("sysctl: interrupted, will try again");
				continue;
			}
			break;
		}
	}
	if (nwrote == -1 && errsv != EEXIST) {
		_LOGE ("sysctl: failed to set '%s' to '%s': (%d) %s",
		       path, value, errsv, strerror (errsv));
	} else if (nwrote < len) {
		_LOGE ("sysctl: failed to set '%s' to '%s' after three attempts",
		       path, value);
	}

	if (nwrote != len) {
		if (close (fd) != 0) {
			if (errsv != 0)
				errno = errsv;
		} else if (errsv != 0)
			errno = errsv;
		else
			errno = EIO;
		return FALSE;
	}
	if (close (fd) != 0) {
		/* errno is already properly set. */
		return FALSE;
	}

	/* success. errno is undefined (no need to set). */
	return TRUE;
}

static GSList *sysctl_clear_cache_list;

static void
_nm_logging_clear_platform_logging_cache_impl (void)
{
	while (sysctl_clear_cache_list) {
		NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (sysctl_clear_cache_list->data);

		sysctl_clear_cache_list = g_slist_delete_link (sysctl_clear_cache_list, sysctl_clear_cache_list);

		g_hash_table_destroy (priv->sysctl_get_prev_values);
		priv->sysctl_get_prev_values = NULL;
		priv->sysctl_get_warned = FALSE;
	}
}

static void
_log_dbg_sysctl_get_impl (NMPlatform *platform, const char *path, const char *contents)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	const char *prev_value = NULL;

	if (!priv->sysctl_get_prev_values) {
		_nm_logging_clear_platform_logging_cache = _nm_logging_clear_platform_logging_cache_impl;
		sysctl_clear_cache_list = g_slist_prepend (sysctl_clear_cache_list, platform);
		priv->sysctl_get_prev_values = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	} else
		prev_value = g_hash_table_lookup (priv->sysctl_get_prev_values, path);

	if (prev_value) {
		if (strcmp (prev_value, contents) != 0) {
			char *contents_escaped = g_strescape (contents, NULL);
			char *prev_value_escaped = g_strescape (prev_value, NULL);

			_LOGD ("sysctl: reading '%s': '%s' (changed from '%s' on last read)", path, contents_escaped, prev_value_escaped);
			g_free (contents_escaped);
			g_free (prev_value_escaped);
			g_hash_table_insert (priv->sysctl_get_prev_values, g_strdup (path), g_strdup (contents));
		}
	} else {
		char *contents_escaped = g_strescape (contents, NULL);

		_LOGD ("sysctl: reading '%s': '%s'", path, contents_escaped);
		g_free (contents_escaped);
		g_hash_table_insert (priv->sysctl_get_prev_values, g_strdup (path), g_strdup (contents));
	}

	if (   !priv->sysctl_get_warned
	    && g_hash_table_size (priv->sysctl_get_prev_values) > 50000) {
		_LOGW ("sysctl: the internal cache for debug-logging of sysctl values grew pretty large. You can clear it by disabling debug-logging: `nmcli general logging level KEEP domains PLATFORM:INFO`.");
		priv->sysctl_get_warned = TRUE;
	}
}

#define _log_dbg_sysctl_get(platform, path, contents) \
	G_STMT_START { \
		if (_LOGD_ENABLED ()) \
			_log_dbg_sysctl_get_impl (platform, path, contents); \
	} G_STMT_END

static char *
sysctl_get (NMPlatform *platform, const char *path)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	GError *error = NULL;
	char *contents;

	/* Don't write outside known locations */
	g_assert (g_str_has_prefix (path, "/proc/sys/")
	          || g_str_has_prefix (path, "/sys/"));
	/* Don't write to suspicious locations */
	g_assert (!strstr (path, "/../"));

	if (!nm_platform_netns_push (platform, &netns))
		return NULL;

	if (!g_file_get_contents (path, &contents, NULL, &error)) {
		/* We assume FAILED means EOPNOTSUP */
		if (   g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT)
		    || g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_FAILED))
			_LOGD ("error reading %s: %s", path, error->message);
		else
			_LOGE ("error reading %s: %s", path, error->message);
		g_clear_error (&error);
		return NULL;
	}

	g_strstrip (contents);

	_log_dbg_sysctl_get (platform, path, contents);

	return contents;
}

/******************************************************************/

static gboolean
check_support_kernel_extended_ifa_flags (NMPlatform *platform)
{
	g_return_val_if_fail (NM_IS_LINUX_PLATFORM (platform), FALSE);

	return _support_kernel_extended_ifa_flags_get ();
}

static gboolean
check_support_user_ipv6ll (NMPlatform *platform)
{
	g_return_val_if_fail (NM_IS_LINUX_PLATFORM (platform), FALSE);

	return _support_user_ipv6ll_get ();
}

static void
process_events (NMPlatform *platform)
{
	delayed_action_handle_all (platform, TRUE);
}

/******************************************************************/

#define cache_lookup_all_objects(type, platform, obj_type, visible_only) \
	((const type *const*) nmp_cache_lookup_multi (NM_LINUX_PLATFORM_GET_PRIVATE ((platform))->cache, \
	                                              nmp_cache_id_init_object_type (NMP_CACHE_ID_STATIC, (obj_type), (visible_only)), \
	                                              NULL))

/******************************************************************/

static void
do_emit_signal (NMPlatform *platform, const NMPObject *obj, NMPCacheOpsType cache_op, gboolean was_visible)
{
	gboolean is_visible;
	NMPObject obj_clone;
	const NMPClass *klass;

	nm_assert (NM_IN_SET ((NMPlatformSignalChangeType) cache_op, (NMPlatformSignalChangeType) NMP_CACHE_OPS_UNCHANGED, NM_PLATFORM_SIGNAL_ADDED, NM_PLATFORM_SIGNAL_CHANGED, NM_PLATFORM_SIGNAL_REMOVED));

	nm_assert (obj || cache_op == NMP_CACHE_OPS_UNCHANGED);
	nm_assert (!obj || cache_op == NMP_CACHE_OPS_REMOVED || obj == nmp_cache_lookup_obj (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, obj));
	nm_assert (!obj || cache_op != NMP_CACHE_OPS_REMOVED || obj != nmp_cache_lookup_obj (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, obj));

	/* we raise the signals inside the namespace of the NMPlatform instance. */
	_assert_netns_current (platform);

	switch (cache_op) {
	case NMP_CACHE_OPS_ADDED:
		if (!nmp_object_is_visible (obj))
			return;
		break;
	case NMP_CACHE_OPS_UPDATED:
		is_visible = nmp_object_is_visible (obj);
		if (!was_visible && is_visible)
			cache_op = NMP_CACHE_OPS_ADDED;
		else if (was_visible && !is_visible) {
			/* This is a bit ugly. The object was visible and changed in a way that it became invisible.
			 * We raise a removed signal, but contrary to a real 'remove', @obj is already changed to be
			 * different from what it was when the user saw it the last time.
			 *
			 * The more correct solution would be to have cache_pre_hook() create a clone of the original
			 * value before it was changed to become invisible.
			 *
			 * But, don't bother. Probably nobody depends on the original values and only cares about the
			 * id properties (which are still correct).
			 */
			cache_op = NMP_CACHE_OPS_REMOVED;
		} else if (!is_visible)
			return;
		break;
	case NMP_CACHE_OPS_REMOVED:
		if (!was_visible)
			return;
		break;
	default:
		g_assert (cache_op == NMP_CACHE_OPS_UNCHANGED);
		return;
	}

	klass = NMP_OBJECT_GET_CLASS (obj);

	_LOGt ("emit signal %s %s: %s",
	       klass->signal_type,
	       nm_platform_signal_change_type_to_string ((NMPlatformSignalChangeType) cache_op),
	       nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));

	/* don't expose @obj directly, but clone the public fields. A signal handler might
	 * call back into NMPlatform which could invalidate (or modify) @obj. */
	memcpy (&obj_clone.object, &obj->object, klass->sizeof_public);
	g_signal_emit (platform,
	               _nm_platform_signal_id_get (klass->signal_type_id),
	               0,
	               klass->obj_type,
	               obj_clone.object.ifindex,
	               &obj_clone.object,
	               (NMPlatformSignalChangeType) cache_op);
}

/******************************************************************/

_NM_UTILS_LOOKUP_DEFINE (static, delayed_action_refresh_from_object_type, NMPObjectType, DelayedActionType,
	NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT (DELAYED_ACTION_TYPE_NONE),
	NM_UTILS_LOOKUP_ITEM (NMP_OBJECT_TYPE_LINK,        DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS),
	NM_UTILS_LOOKUP_ITEM (NMP_OBJECT_TYPE_IP4_ADDRESS, DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES),
	NM_UTILS_LOOKUP_ITEM (NMP_OBJECT_TYPE_IP6_ADDRESS, DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES),
	NM_UTILS_LOOKUP_ITEM (NMP_OBJECT_TYPE_IP4_ROUTE,   DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES),
	NM_UTILS_LOOKUP_ITEM (NMP_OBJECT_TYPE_IP6_ROUTE,   DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES),
	NM_UTILS_LOOKUP_ITEM_IGNORE_OTHER (),
);

_NM_UTILS_LOOKUP_DEFINE (static, delayed_action_refresh_to_object_type, DelayedActionType, NMPObjectType,
	NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT (NMP_OBJECT_TYPE_UNKNOWN),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS,         NMP_OBJECT_TYPE_LINK),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES, NMP_OBJECT_TYPE_IP4_ADDRESS),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES, NMP_OBJECT_TYPE_IP6_ADDRESS),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES,    NMP_OBJECT_TYPE_IP4_ROUTE),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,    NMP_OBJECT_TYPE_IP6_ROUTE),
	NM_UTILS_LOOKUP_ITEM_IGNORE_OTHER (),
);

_NM_UTILS_LOOKUP_DEFINE (static, delayed_action_refresh_all_to_idx, DelayedActionType, guint,
	NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT (0),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS,         DELAYED_ACTION_IDX_REFRESH_ALL_LINKS),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES, DELAYED_ACTION_IDX_REFRESH_ALL_IP4_ADDRESSES),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES, DELAYED_ACTION_IDX_REFRESH_ALL_IP6_ADDRESSES),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES,    DELAYED_ACTION_IDX_REFRESH_ALL_IP4_ROUTES),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,    DELAYED_ACTION_IDX_REFRESH_ALL_IP6_ROUTES),
	NM_UTILS_LOOKUP_ITEM_IGNORE_OTHER (),
);

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (delayed_action_to_string, DelayedActionType,
	NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT ("unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS,         "refresh-all-links"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES, "refresh-all-ip4-addresses"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES, "refresh-all-ip6-addresses"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES,    "refresh-all-ip4-routes"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,    "refresh-all-ip6-routes"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_LINK,              "refresh-link"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_MASTER_CONNECTED,          "master-connected"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_READ_NETLINK,              "read-netlink"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE,      "wait-for-nl-response"),
	NM_UTILS_LOOKUP_ITEM_IGNORE (DELAYED_ACTION_TYPE_NONE),
	NM_UTILS_LOOKUP_ITEM_IGNORE (DELAYED_ACTION_TYPE_REFRESH_ALL),
	NM_UTILS_LOOKUP_ITEM_IGNORE (__DELAYED_ACTION_TYPE_MAX),
);

static const char *
delayed_action_to_string_full (DelayedActionType action_type, gpointer user_data, char *buf, gsize buf_size)
{
	char *buf0 = buf;
	const DelayedActionWaitForNlResponseData *data;

	nm_utils_strbuf_append_str (&buf, &buf_size, delayed_action_to_string (action_type));
	switch (action_type) {
	case DELAYED_ACTION_TYPE_MASTER_CONNECTED:
		nm_utils_strbuf_append (&buf, &buf_size, " (master-ifindex %d)", GPOINTER_TO_INT (user_data));
		break;
	case DELAYED_ACTION_TYPE_REFRESH_LINK:
		nm_utils_strbuf_append (&buf, &buf_size, " (ifindex %d)", GPOINTER_TO_INT (user_data));
		break;
	case DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE:
		data = user_data;

		if (data) {
			gint64 timeout = data->timeout_abs_ns - nm_utils_get_monotonic_timestamp_ns ();
			char b[255];

			nm_utils_strbuf_append (&buf, &buf_size, " (seq %u, timeout in %s%"G_GINT64_FORMAT".%09"G_GINT64_FORMAT"%s%s)",
			                        data->seq_number,
			                        timeout < 0 ? "-" : "",
			                        (timeout < 0 ? -timeout : timeout) / NM_UTILS_NS_PER_SECOND,
			                        (timeout < 0 ? -timeout : timeout) % NM_UTILS_NS_PER_SECOND,
			                        data->seq_result ? ", " : "",
			                        data->seq_result ? wait_for_nl_response_to_string (data->seq_result, b, sizeof (b)) : "");
		} else
			nm_utils_strbuf_append_str (&buf, &buf_size, " (any)");
		break;
	default:
		nm_assert (!user_data);
		break;
	}
	return buf0;
}

#define _LOGt_delayed_action(action_type, user_data, operation) \
    G_STMT_START { \
        char _buf[255]; \
        \
        _LOGt ("delayed-action: %s %s", \
               ""operation, \
               delayed_action_to_string_full (action_type, user_data, _buf, sizeof (_buf))); \
    } G_STMT_END

/*****************************************************************************/

static gboolean
delayed_action_refresh_all_in_progress (NMPlatform *platform, DelayedActionType action_type)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	nm_assert (nm_utils_is_power_of_two (action_type));
	nm_assert (NM_FLAGS_ANY (action_type, DELAYED_ACTION_TYPE_REFRESH_ALL));
	nm_assert (!NM_FLAGS_ANY (action_type, ~DELAYED_ACTION_TYPE_REFRESH_ALL));

	if (NM_FLAGS_ANY (priv->delayed_action.flags, action_type))
		return TRUE;

	if (priv->delayed_action.refresh_all_in_progess[delayed_action_refresh_all_to_idx (action_type)] > 0)
		return TRUE;

	return FALSE;
}

static void
delayed_action_wait_for_nl_response_complete (NMPlatform *platform,
                                              guint idx,
                                              WaitForNlResponseResult seq_result)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	DelayedActionWaitForNlResponseData *data;

	nm_assert (NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE));
	nm_assert (idx < priv->delayed_action.list_wait_for_nl_response->len);
	nm_assert (seq_result);

	data = &g_array_index (priv->delayed_action.list_wait_for_nl_response, DelayedActionWaitForNlResponseData, idx);

	_LOGt_delayed_action (DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE, data, "complete");

	if (priv->delayed_action.list_wait_for_nl_response->len <= 1)
		priv->delayed_action.flags &= ~DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE;
	if (data->out_seq_result)
		*data->out_seq_result = seq_result;
	if (data->out_refresh_all_in_progess) {
		nm_assert (*data->out_refresh_all_in_progess > 0);
		*data->out_refresh_all_in_progess -= 1;
	}

	g_array_remove_index_fast (priv->delayed_action.list_wait_for_nl_response, idx);
}

static void
delayed_action_wait_for_nl_response_complete_all (NMPlatform *platform,
                                                  WaitForNlResponseResult fallback_result)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	if (NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE)) {
		while (priv->delayed_action.list_wait_for_nl_response->len > 0) {
			const DelayedActionWaitForNlResponseData *data;
			guint idx = priv->delayed_action.list_wait_for_nl_response->len - 1;
			WaitForNlResponseResult r;

			data = &g_array_index (priv->delayed_action.list_wait_for_nl_response, DelayedActionWaitForNlResponseData, idx);

			/* prefer the result that we already have. */
			r = data->seq_result ? : fallback_result;

			delayed_action_wait_for_nl_response_complete (platform, idx, r);
		}
	}
	nm_assert (!NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE));
	nm_assert (priv->delayed_action.list_wait_for_nl_response->len == 0);
}

/*****************************************************************************/

static void
delayed_action_handle_MASTER_CONNECTED (NMPlatform *platform, int master_ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	nm_auto_nmpobj NMPObject *obj_cache = NULL;
	gboolean was_visible;
	NMPCacheOpsType cache_op;

	cache_op = nmp_cache_update_link_master_connected (priv->cache, master_ifindex, &obj_cache, &was_visible, cache_pre_hook, platform);
	do_emit_signal (platform, obj_cache, cache_op, was_visible);
}

static void
delayed_action_handle_REFRESH_LINK (NMPlatform *platform, int ifindex)
{
	do_request_link_no_delayed_actions (platform, ifindex, NULL);
}

static void
delayed_action_handle_REFRESH_ALL (NMPlatform *platform, DelayedActionType flags)
{
	do_request_all_no_delayed_actions (platform, flags);
}

static void
delayed_action_handle_READ_NETLINK (NMPlatform *platform)
{
	event_handler_read_netlink (platform, FALSE);
}

static void
delayed_action_handle_WAIT_FOR_NL_RESPONSE (NMPlatform *platform)
{
	event_handler_read_netlink (platform, TRUE);
}

static gboolean
delayed_action_handle_one (NMPlatform *platform)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	gpointer user_data;

	if (priv->delayed_action.flags == DELAYED_ACTION_TYPE_NONE)
		return FALSE;

	/* First process DELAYED_ACTION_TYPE_MASTER_CONNECTED actions.
	 * This type of action is entirely cache-internal and is here to resolve a
	 * cache inconsistency. It should be fixed right away. */
	if (NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_MASTER_CONNECTED)) {
		nm_assert (priv->delayed_action.list_master_connected->len > 0);

		user_data = priv->delayed_action.list_master_connected->pdata[0];
		g_ptr_array_remove_index_fast (priv->delayed_action.list_master_connected, 0);
		if (priv->delayed_action.list_master_connected->len == 0)
			priv->delayed_action.flags &= ~DELAYED_ACTION_TYPE_MASTER_CONNECTED;
		nm_assert (_nm_utils_ptrarray_find_first (priv->delayed_action.list_master_connected->pdata, priv->delayed_action.list_master_connected->len, user_data) < 0);

		_LOGt_delayed_action (DELAYED_ACTION_TYPE_MASTER_CONNECTED, user_data, "handle");
		delayed_action_handle_MASTER_CONNECTED (platform, GPOINTER_TO_INT (user_data));
		return TRUE;
	}
	nm_assert (priv->delayed_action.list_master_connected->len == 0);

	/* Next we prefer read-netlink, because the buffer size is limited and we want to process events
	 * from netlink early. */
	if (NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_READ_NETLINK)) {
		_LOGt_delayed_action (DELAYED_ACTION_TYPE_READ_NETLINK, NULL, "handle");
		priv->delayed_action.flags &= ~DELAYED_ACTION_TYPE_READ_NETLINK;
		delayed_action_handle_READ_NETLINK (platform);
		return TRUE;
	}

	if (NM_FLAGS_ANY (priv->delayed_action.flags, DELAYED_ACTION_TYPE_REFRESH_ALL)) {
		DelayedActionType flags, iflags;

		flags = priv->delayed_action.flags & DELAYED_ACTION_TYPE_REFRESH_ALL;

		priv->delayed_action.flags &= ~DELAYED_ACTION_TYPE_REFRESH_ALL;

		if (_LOGt_ENABLED ()) {
			FOR_EACH_DELAYED_ACTION (iflags, flags) {
				_LOGt_delayed_action (iflags, NULL, "handle");
			}
		}

		delayed_action_handle_REFRESH_ALL (platform, flags);
		return TRUE;
	}

	if (NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_REFRESH_LINK)) {
		nm_assert (priv->delayed_action.list_refresh_link->len > 0);

		user_data = priv->delayed_action.list_refresh_link->pdata[0];
		g_ptr_array_remove_index_fast (priv->delayed_action.list_refresh_link, 0);
		if (priv->delayed_action.list_refresh_link->len == 0)
			priv->delayed_action.flags &= ~DELAYED_ACTION_TYPE_REFRESH_LINK;
		nm_assert (_nm_utils_ptrarray_find_first (priv->delayed_action.list_refresh_link->pdata, priv->delayed_action.list_refresh_link->len, user_data) < 0);

		_LOGt_delayed_action (DELAYED_ACTION_TYPE_REFRESH_LINK, user_data, "handle");

		delayed_action_handle_REFRESH_LINK (platform, GPOINTER_TO_INT (user_data));

		return TRUE;
	}

	if (NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE)) {
		nm_assert (priv->delayed_action.list_wait_for_nl_response->len > 0);
		_LOGt_delayed_action (DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE, NULL, "handle");
		delayed_action_handle_WAIT_FOR_NL_RESPONSE (platform);
		return TRUE;
	}

	return FALSE;
}

static gboolean
delayed_action_handle_all (NMPlatform *platform, gboolean read_netlink)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	gboolean any = FALSE;

	g_return_val_if_fail (priv->delayed_action.is_handling == 0, FALSE);

	priv->delayed_action.is_handling++;
	if (read_netlink)
		delayed_action_schedule (platform, DELAYED_ACTION_TYPE_READ_NETLINK, NULL);
	while (delayed_action_handle_one (platform))
		any = TRUE;
	priv->delayed_action.is_handling--;

	cache_prune_candidates_prune (platform);

	return any;
}

static void
delayed_action_schedule (NMPlatform *platform, DelayedActionType action_type, gpointer user_data)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	DelayedActionType iflags;

	nm_assert (action_type != DELAYED_ACTION_TYPE_NONE);

	switch (action_type) {
	case DELAYED_ACTION_TYPE_REFRESH_LINK:
		if (_nm_utils_ptrarray_find_first (priv->delayed_action.list_refresh_link->pdata, priv->delayed_action.list_refresh_link->len, user_data) < 0)
			g_ptr_array_add (priv->delayed_action.list_refresh_link, user_data);
		break;
	case DELAYED_ACTION_TYPE_MASTER_CONNECTED:
		if (_nm_utils_ptrarray_find_first (priv->delayed_action.list_master_connected->pdata, priv->delayed_action.list_master_connected->len, user_data) < 0)
			g_ptr_array_add (priv->delayed_action.list_master_connected, user_data);
		break;
	case DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE:
		g_array_append_vals (priv->delayed_action.list_wait_for_nl_response, user_data, 1);
		break;
	default:
		nm_assert (!user_data);
		nm_assert (!NM_FLAGS_HAS (action_type, DELAYED_ACTION_TYPE_REFRESH_LINK));
		nm_assert (!NM_FLAGS_HAS (action_type, DELAYED_ACTION_TYPE_MASTER_CONNECTED));
		nm_assert (!NM_FLAGS_HAS (action_type, DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE));
		break;
	}

	priv->delayed_action.flags |= action_type;

	if (_LOGt_ENABLED ()) {
		FOR_EACH_DELAYED_ACTION (iflags, action_type) {
			_LOGt_delayed_action (iflags, user_data, "schedule");
		}
	}
}

static void
delayed_action_schedule_WAIT_FOR_NL_RESPONSE (NMPlatform *platform,
                                              guint32 seq_number,
                                              WaitForNlResponseResult *out_seq_result,
                                              gint *out_refresh_all_in_progess)
{
	DelayedActionWaitForNlResponseData data = {
		.seq_number = seq_number,
		.timeout_abs_ns = nm_utils_get_monotonic_timestamp_ns () + (200 * (NM_UTILS_NS_PER_SECOND / 1000)),
		.out_seq_result = out_seq_result,
		.out_refresh_all_in_progess = out_refresh_all_in_progess,
	};

	delayed_action_schedule (platform,
	                         DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE,
	                         &data);
}

/******************************************************************/

static void
cache_prune_candidates_record_all (NMPlatform *platform, NMPObjectType obj_type)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	priv->prune_candidates = nmp_cache_lookup_all_to_hash (priv->cache,
	                                                       nmp_cache_id_init_object_type (NMP_CACHE_ID_STATIC, obj_type, FALSE),
	                                                       priv->prune_candidates);
	_LOGt ("cache-prune: record %s (now %u candidates)", nmp_class_from_type (obj_type)->obj_type_name,
	       priv->prune_candidates ? g_hash_table_size (priv->prune_candidates) : 0);
}

static void
cache_prune_candidates_record_one (NMPlatform *platform, NMPObject *obj)
{
	NMLinuxPlatformPrivate *priv;

	if (!obj)
		return;

	priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	if (!priv->prune_candidates)
		priv->prune_candidates = g_hash_table_new_full (NULL, NULL, (GDestroyNotify) nmp_object_unref, NULL);

	if (_LOGt_ENABLED () && !g_hash_table_contains (priv->prune_candidates, obj))
		_LOGt ("cache-prune: record-one: %s", nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_ALL, NULL, 0));
	g_hash_table_add (priv->prune_candidates, nmp_object_ref (obj));
}

static void
cache_prune_candidates_drop (NMPlatform *platform, const NMPObject *obj)
{
	NMLinuxPlatformPrivate *priv;

	if (!obj)
		return;

	priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	if (priv->prune_candidates) {
		if (_LOGt_ENABLED () && g_hash_table_contains (priv->prune_candidates, obj))
			_LOGt ("cache-prune: drop-one: %s", nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_ALL, NULL, 0));
		g_hash_table_remove (priv->prune_candidates, obj);
	}
}

static void
cache_prune_candidates_prune (NMPlatform *platform)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GHashTable *prune_candidates;
	GHashTableIter iter;
	const NMPObject *obj;
	gboolean was_visible;
	NMPCacheOpsType cache_op;

	if (!priv->prune_candidates)
		return;

	prune_candidates = priv->prune_candidates;
	priv->prune_candidates = NULL;

	g_hash_table_iter_init (&iter, prune_candidates);
	while (g_hash_table_iter_next (&iter, (gpointer *)&obj, NULL)) {
		nm_auto_nmpobj NMPObject *obj_cache = NULL;

		_LOGt ("cache-prune: prune %s", nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_ALL, NULL, 0));
		cache_op = nmp_cache_remove (priv->cache, obj, TRUE, &obj_cache, &was_visible, cache_pre_hook, platform);
		do_emit_signal (platform, obj_cache, cache_op, was_visible);
	}

	g_hash_table_unref (prune_candidates);
}

static void
cache_pre_hook (NMPCache *cache, const NMPObject *old, const NMPObject *new, NMPCacheOpsType ops_type, gpointer user_data)
{
	NMPlatform *platform = user_data;
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	const NMPClass *klass;
	char str_buf[sizeof (_nm_utils_to_string_buffer)];
	char str_buf2[sizeof (_nm_utils_to_string_buffer)];

	nm_assert (old || new);
	nm_assert (NM_IN_SET (ops_type, NMP_CACHE_OPS_ADDED, NMP_CACHE_OPS_REMOVED, NMP_CACHE_OPS_UPDATED));
	nm_assert (ops_type != NMP_CACHE_OPS_ADDED   || (old == NULL && NMP_OBJECT_IS_VALID (new) && nmp_object_is_alive (new)));
	nm_assert (ops_type != NMP_CACHE_OPS_REMOVED || (new == NULL && NMP_OBJECT_IS_VALID (old) && nmp_object_is_alive (old)));
	nm_assert (ops_type != NMP_CACHE_OPS_UPDATED || (NMP_OBJECT_IS_VALID (old) && nmp_object_is_alive (old) && NMP_OBJECT_IS_VALID (new) && nmp_object_is_alive (new)));
	nm_assert (new == NULL || old == NULL || nmp_object_id_equal (new, old));
	nm_assert (!old || !new || NMP_OBJECT_GET_CLASS (old) == NMP_OBJECT_GET_CLASS (new));

	klass = old ? NMP_OBJECT_GET_CLASS (old) : NMP_OBJECT_GET_CLASS (new);

	nm_assert (klass == (new ? NMP_OBJECT_GET_CLASS (new) : NMP_OBJECT_GET_CLASS (old)));

	_LOGt ("update-cache-%s: %s: %s%s%s",
	       klass->obj_type_name,
	       (ops_type == NMP_CACHE_OPS_UPDATED
	           ? "UPDATE"
	           : (ops_type == NMP_CACHE_OPS_REMOVED
	                 ? "REMOVE"
	                 : (ops_type == NMP_CACHE_OPS_ADDED) ? "ADD" : "???")),
	       (ops_type != NMP_CACHE_OPS_ADDED
	           ? nmp_object_to_string (old, NMP_OBJECT_TO_STRING_ALL, str_buf2, sizeof (str_buf2))
	           : nmp_object_to_string (new, NMP_OBJECT_TO_STRING_ALL, str_buf2, sizeof (str_buf2))),
	       (ops_type == NMP_CACHE_OPS_UPDATED) ? " -> " : "",
	       (ops_type == NMP_CACHE_OPS_UPDATED
	           ? nmp_object_to_string (new, NMP_OBJECT_TO_STRING_ALL, str_buf, sizeof (str_buf))
	           : ""));

	switch (klass->obj_type) {
	case NMP_OBJECT_TYPE_LINK:
		{
			/* check whether changing a slave link can cause a master link (bridge or bond) to go up/down */
			if (   old
			    && nmp_cache_link_connected_needs_toggle_by_ifindex (priv->cache, old->link.master, new, old))
				delayed_action_schedule (platform, DELAYED_ACTION_TYPE_MASTER_CONNECTED, GINT_TO_POINTER (old->link.master));
			if (   new
			    && (!old || old->link.master != new->link.master)
			    && nmp_cache_link_connected_needs_toggle_by_ifindex (priv->cache, new->link.master, new, old))
				delayed_action_schedule (platform, DELAYED_ACTION_TYPE_MASTER_CONNECTED, GINT_TO_POINTER (new->link.master));
		}
		{
			/* check whether we are about to change a master link that needs toggling connected state. */
			if (   new /* <-- nonsensical, make coverity happy */
			    && nmp_cache_link_connected_needs_toggle (cache, new, new, old))
				delayed_action_schedule (platform, DELAYED_ACTION_TYPE_MASTER_CONNECTED, GINT_TO_POINTER (new->link.ifindex));
		}
		{
			int ifindex = 0;

			/* if we remove a link (from netlink), we must refresh the addresses and routes */
			if (   ops_type == NMP_CACHE_OPS_REMOVED
			    && old /* <-- nonsensical, make coverity happy */)
				ifindex = old->link.ifindex;
			else if (   ops_type == NMP_CACHE_OPS_UPDATED
			         && old && new /* <-- nonsensical, make coverity happy */
			         && !new->_link.netlink.is_in_netlink
			         && new->_link.netlink.is_in_netlink != old->_link.netlink.is_in_netlink)
				ifindex = new->link.ifindex;

			if (ifindex > 0) {
				delayed_action_schedule (platform,
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES |
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES |
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES |
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,
				                         NULL);
			}
		}
		{
			int ifindex = -1;

			/* removal of a link could be caused by moving the link to another netns.
			 * In this case, we potentially have to update other links that have this link as parent.
			 * Currently, kernel misses to sent us a notification in this case
			 * (https://bugzilla.redhat.com/show_bug.cgi?id=1262908). */

			if (   ops_type == NMP_CACHE_OPS_REMOVED
			    && old /* <-- nonsensical, make coverity happy */
			    && old->_link.netlink.is_in_netlink)
				ifindex = old->link.ifindex;
			else if (   ops_type == NMP_CACHE_OPS_UPDATED
			         && old && new /* <-- nonsensical, make coverity happy */
			         && old->_link.netlink.is_in_netlink
			         && !new->_link.netlink.is_in_netlink)
				ifindex = new->link.ifindex;

			if (ifindex > 0) {
				const NMPlatformLink *const *links;

				links = cache_lookup_all_objects (NMPlatformLink, platform, NMP_OBJECT_TYPE_LINK, FALSE);
				if (links) {
					for (; *links; links++) {
						const NMPlatformLink *l = (*links);

						if (l->parent == ifindex)
							delayed_action_schedule (platform, DELAYED_ACTION_TYPE_REFRESH_LINK, GINT_TO_POINTER (l->ifindex));
					}
				}
			}
		}
		{
			/* if a link goes down, we must refresh routes */
			if (   ops_type == NMP_CACHE_OPS_UPDATED
			    && old && new /* <-- nonsensical, make coverity happy */
			    && old->_link.netlink.is_in_netlink
			    && new->_link.netlink.is_in_netlink
			    && (   (   NM_FLAGS_HAS (old->link.n_ifi_flags, IFF_UP)
			            && !NM_FLAGS_HAS (new->link.n_ifi_flags, IFF_UP))
			        || (   NM_FLAGS_HAS (old->link.n_ifi_flags, IFF_LOWER_UP)
			            && !NM_FLAGS_HAS (new->link.n_ifi_flags, IFF_LOWER_UP)))) {
				/* FIXME: I suspect that IFF_LOWER_UP must not be considered, and I
				 * think kernel does send RTM_DELROUTE events for IPv6 routes, so
				 * we might not need to refresh IPv6 routes. */
				delayed_action_schedule (platform,
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES |
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,
				                         NULL);
			}
		}
		if (   NM_IN_SET (ops_type, NMP_CACHE_OPS_ADDED, NMP_CACHE_OPS_UPDATED)
		    && (new && new->_link.netlink.is_in_netlink)
		    && (!old || !old->_link.netlink.is_in_netlink))
		{
			if (!new->_link.netlink.lnk) {
				/* certain link-types also come with a IFLA_INFO_DATA/lnk_data. It may happen that
				 * kernel didn't send this notification, thus when we first learn about a link
				 * that lacks an lnk_data we re-request it again.
				 *
				 * For example https://bugzilla.redhat.com/show_bug.cgi?id=1284001 */
				switch (new->link.type) {
				case NM_LINK_TYPE_GRE:
				case NM_LINK_TYPE_IP6TNL:
				case NM_LINK_TYPE_INFINIBAND:
				case NM_LINK_TYPE_MACVLAN:
				case NM_LINK_TYPE_MACVTAP:
				case NM_LINK_TYPE_SIT:
				case NM_LINK_TYPE_VLAN:
				case NM_LINK_TYPE_VXLAN:
					delayed_action_schedule (platform,
					                         DELAYED_ACTION_TYPE_REFRESH_LINK,
					                         GINT_TO_POINTER (new->link.ifindex));
					break;
				default:
					break;
				}
			}
			if (   new->link.type == NM_LINK_TYPE_VETH
			    && new->link.parent == 0) {
				/* the initial notification when adding a veth pair can lack the parent/IFLA_LINK
				 * (https://bugzilla.redhat.com/show_bug.cgi?id=1285827).
				 * Request it again. */
				delayed_action_schedule (platform,
				                         DELAYED_ACTION_TYPE_REFRESH_LINK,
				                         GINT_TO_POINTER (new->link.ifindex));
			}
			if (   new->link.type == NM_LINK_TYPE_ETHERNET
			    && new->link.addr.len == 0) {
				/* Due to a kernel bug, we sometimes receive spurious NEWLINK
				 * messages after a wifi interface has disappeared. Since the
				 * link is not present anymore we can't determine its type and
				 * thus it will show up as a Ethernet one, with no address
				 * specified.  Request the link again to check if it really
				 * exists.  https://bugzilla.redhat.com/show_bug.cgi?id=1302037
				 */
				delayed_action_schedule (platform,
				                         DELAYED_ACTION_TYPE_REFRESH_LINK,
				                         GINT_TO_POINTER (new->link.ifindex));
			}
		}
		{
			/* on enslave/release, we also refresh the master. */
			int ifindex1 = 0, ifindex2 = 0;
			gboolean changed_master, changed_connected;

			changed_master =    (new && new->_link.netlink.is_in_netlink && new->link.master > 0 ? new->link.master : 0)
			                 != (old && old->_link.netlink.is_in_netlink && old->link.master > 0 ? old->link.master : 0);
			changed_connected =    (new && new->_link.netlink.is_in_netlink ? NM_FLAGS_HAS (new->link.n_ifi_flags, IFF_LOWER_UP) : 2)
			                    != (old && old->_link.netlink.is_in_netlink ? NM_FLAGS_HAS (old->link.n_ifi_flags, IFF_LOWER_UP) : 2);

			if (changed_master || changed_connected) {
				ifindex1 = (old && old->_link.netlink.is_in_netlink && old->link.master > 0) ? old->link.master : 0;
				ifindex2 = (new && new->_link.netlink.is_in_netlink && new->link.master > 0) ? new->link.master : 0;

				if (ifindex1 > 0)
					delayed_action_schedule (platform, DELAYED_ACTION_TYPE_REFRESH_LINK, GINT_TO_POINTER (ifindex1));
				if (ifindex2 > 0 && ifindex1 != ifindex2)
					delayed_action_schedule (platform, DELAYED_ACTION_TYPE_REFRESH_LINK, GINT_TO_POINTER (ifindex2));
			}
		}
		{
			if (   (       (ops_type == NMP_CACHE_OPS_REMOVED)
			        || (   (ops_type == NMP_CACHE_OPS_UPDATED)
			            && new
			            && !new->_link.netlink.is_in_netlink))
			    && old
			    && old->_link.netlink.is_in_netlink
			    && old->link.master) {
				/* sometimes we receive a wrong RTM_DELLINK message when unslaving
				 * a device. Refetch the link again to check whether the device
				 * is really gone.
				 *
				 * https://bugzilla.redhat.com/show_bug.cgi?id=1285719#c2 */
				delayed_action_schedule (platform, DELAYED_ACTION_TYPE_REFRESH_LINK, GINT_TO_POINTER (old->link.ifindex));
			}
		}
		break;
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
		{
			/* Address deletion is sometimes accompanied by route deletion. We need to
			 * check all routes belonging to the same interface. */
			if (ops_type == NMP_CACHE_OPS_REMOVED) {
				delayed_action_schedule (platform,
				                         (klass->obj_type == NMP_OBJECT_TYPE_IP4_ADDRESS)
				                             ? DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES
				                             : DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,
				                         NULL);
			}
		}
		break;
	default:
		break;
	}
}

static void
cache_post (NMPlatform *platform,
            struct nlmsghdr *msghdr,
            NMPCacheOpsType cache_op,
            NMPObject *obj,
            NMPObject *obj_cache)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	nm_assert (NMP_OBJECT_IS_VALID (obj));
	nm_assert (!obj_cache || nmp_object_id_equal (obj, obj_cache));

	if (msghdr->nlmsg_type == RTM_NEWROUTE) {
		DelayedActionType action_type;

		action_type = NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_IP4_ROUTE
		                  ? DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES
		                  : DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES;
		if (   !delayed_action_refresh_all_in_progress (platform, action_type)
		    && nmp_cache_find_other_route_for_same_destination (priv->cache, obj)) {
			/* via `iproute route change` the user can update an existing route which effectively
			 * means that a new object (with a different ID) comes into existance, replacing the
			 * old on. In other words, as the ID of the object changes, we really see a new
			 * object with the old one deleted.
			 * However, kernel decides not to send a RTM_DELROUTE event for that.
			 *
			 * To hack around that, check if the update leaves us with multiple routes for the
			 * same network/plen,metric part. In that case, we cannot do better then requesting
			 * all routes anew, which sucks.
			 *
			 * One mitigation to avoid a dump is only to request a new dump, if we are not in
			 * the middle of an ongoing dump (delayed_action_refresh_all_in_progress). */
			delayed_action_schedule (platform, action_type, NULL);
		}
	}
}

/******************************************************************/

static int
_nl_send_auto_with_seq (NMPlatform *platform,
                        struct nl_msg *nlmsg,
                        WaitForNlResponseResult *out_seq_result,
                        gint *out_refresh_all_in_progess)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	guint32 seq;
	int nle;

	/* complete the message with a sequence number (ensuring it's not zero). */
	seq = priv->nlh_seq_next++ ?: priv->nlh_seq_next++;

	nlmsg_hdr (nlmsg)->nlmsg_seq = seq;

	nle = nl_send_auto (priv->nlh, nlmsg);

	if (nle >= 0) {
		nle = 0;
		delayed_action_schedule_WAIT_FOR_NL_RESPONSE (platform, seq, out_seq_result, out_refresh_all_in_progess);
	} else
		_LOGD ("netlink: send: failed sending message: %s (%d)", nl_geterror (nle), nle);

	return nle;
}

static void
do_request_link_no_delayed_actions (NMPlatform *platform, int ifindex, const char *name)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;

	if (name && !name[0])
		name = NULL;

	g_return_if_fail (ifindex > 0 || name);

	_LOGD ("do-request-link: %d %s", ifindex, name ? name : "");

	if (ifindex > 0) {
		cache_prune_candidates_record_one (platform,
		                                   (NMPObject *) nmp_cache_lookup_link (priv->cache, ifindex));
	}

	event_handler_read_netlink (platform, FALSE);

	nlmsg = _nl_msg_new_link (RTM_GETLINK,
	                          0,
	                          ifindex,
	                          name,
	                          0,
	                          0);
	if (nlmsg)
		_nl_send_auto_with_seq (platform, nlmsg, NULL, NULL);
}

static void
do_request_link (NMPlatform *platform, int ifindex, const char *name)
{
	do_request_link_no_delayed_actions (platform, ifindex, name);
	delayed_action_handle_all (platform, FALSE);
}

static void
do_request_all_no_delayed_actions (NMPlatform *platform, DelayedActionType action_type)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	DelayedActionType iflags;

	nm_assert (!NM_FLAGS_ANY (action_type, ~DELAYED_ACTION_TYPE_REFRESH_ALL));
	action_type &= DELAYED_ACTION_TYPE_REFRESH_ALL;

	FOR_EACH_DELAYED_ACTION (iflags, action_type) {
		cache_prune_candidates_record_all (platform, delayed_action_refresh_to_object_type (iflags));
	}

	FOR_EACH_DELAYED_ACTION (iflags, action_type) {
		NMPObjectType obj_type = delayed_action_refresh_to_object_type (iflags);
		const NMPClass *klass = nmp_class_from_type (obj_type);
		nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
		struct rtgenmsg gmsg = {
			.rtgen_family = klass->addr_family,
		};
		int nle;
		gint *out_refresh_all_in_progess;

		out_refresh_all_in_progess = &priv->delayed_action.refresh_all_in_progess[delayed_action_refresh_all_to_idx (iflags)];
		nm_assert (*out_refresh_all_in_progess >= 0);
		*out_refresh_all_in_progess += 1;

		/* clear any delayed action that request a refresh of this object type. */
		priv->delayed_action.flags &= ~iflags;
		_LOGt_delayed_action (iflags, NULL, "handle (do-request-all)");
		if (obj_type == NMP_OBJECT_TYPE_LINK) {
			priv->delayed_action.flags &= ~DELAYED_ACTION_TYPE_REFRESH_LINK;
			g_ptr_array_set_size (priv->delayed_action.list_refresh_link, 0);
			_LOGt_delayed_action (DELAYED_ACTION_TYPE_REFRESH_LINK, NULL, "clear (do-request-all)");
		}

		event_handler_read_netlink (platform, FALSE);

		/* reimplement
		 *   nl_rtgen_request (sk, klass->rtm_gettype, klass->addr_family, NLM_F_DUMP);
		 * because we need the sequence number.
		 */
		nlmsg = nlmsg_alloc_simple (klass->rtm_gettype, NLM_F_DUMP);
		if (!nlmsg)
			continue;

		nle = nlmsg_append (nlmsg, &gmsg, sizeof (gmsg), NLMSG_ALIGNTO);
		if (nle < 0)
			continue;

		if (_nl_send_auto_with_seq (platform, nlmsg, NULL, out_refresh_all_in_progess) < 0) {
			nm_assert (*out_refresh_all_in_progess > 0);
			*out_refresh_all_in_progess -= 1;
		}
	}
}

static void
do_request_one_type (NMPlatform *platform, NMPObjectType obj_type)
{
	do_request_all_no_delayed_actions (platform, delayed_action_refresh_from_object_type (obj_type));
	delayed_action_handle_all (platform, FALSE);
}

static void
event_seq_check_refresh_all (NMPlatform *platform, guint32 seq_number)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	DelayedActionWaitForNlResponseData *data;
	guint i;

	if (NM_IN_SET (seq_number, 0, priv->nlh_seq_last_seen))
		return;

	if (NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE)) {
		nm_assert (priv->delayed_action.list_wait_for_nl_response->len > 0);

		for (i = 0; i < priv->delayed_action.list_wait_for_nl_response->len; i++) {
			data = &g_array_index (priv->delayed_action.list_wait_for_nl_response, DelayedActionWaitForNlResponseData, i);

			if (data->seq_number == priv->nlh_seq_last_seen) {
				if (data->out_refresh_all_in_progess) {
					nm_assert (*data->out_refresh_all_in_progess > 0);
					*data->out_refresh_all_in_progess -= 1;
					data->out_refresh_all_in_progess = NULL;
					break;
				}
			}
		}
	}

	priv->nlh_seq_last_seen = seq_number;
}

static void
event_seq_check (NMPlatform *platform, guint32 seq_number, WaitForNlResponseResult seq_result)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	DelayedActionWaitForNlResponseData *data;
	guint i;

	if (seq_number == 0)
		return;

	if (NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE)) {
		nm_assert (priv->delayed_action.list_wait_for_nl_response->len > 0);

		for (i = 0; i < priv->delayed_action.list_wait_for_nl_response->len; i++) {
			data = &g_array_index (priv->delayed_action.list_wait_for_nl_response, DelayedActionWaitForNlResponseData, i);

			if (data->seq_number == seq_number) {
				/* We potentially receive many parts partial responses for the same sequence number.
				 * Thus, we only remember the result, and collect it later. */
				if (data->seq_result < 0) {
					/* we already saw an error for this seqence number.
					 * Preserve it. */
				} else if (   seq_result != WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_UNKNOWN
				           || data->seq_result == WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN)
					data->seq_result = seq_result;
				return;
			}
		}
	}

#ifdef NM_MORE_LOGGING
	if (seq_number != priv->nlh_seq_last_handled)
		_LOGt ("netlink: recvmsg: unwaited sequence number %u", seq_number);
	priv->nlh_seq_last_handled = seq_number;
#endif
}

static void
event_valid_msg (NMPlatform *platform, struct nl_msg *msg, gboolean handle_events)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	nm_auto_nmpobj NMPObject *obj = NULL;
	nm_auto_nmpobj NMPObject *obj_cache = NULL;
	NMPCacheOpsType cache_op;
	struct nlmsghdr *msghdr;
	char buf_nlmsg_type[16];
	gboolean id_only = FALSE;
	gboolean was_visible;

	msghdr = nlmsg_hdr (msg);

	if (_support_kernel_extended_ifa_flags_still_undecided () && msghdr->nlmsg_type == RTM_NEWADDR)
		_support_kernel_extended_ifa_flags_detect (msg);

	if (!handle_events)
		return;

	if (NM_IN_SET (msghdr->nlmsg_type, RTM_DELLINK, RTM_DELADDR, RTM_DELROUTE)) {
		/* The event notifies about a deleted object. We don't need to initialize all
		 * fields of the object. */
		id_only = TRUE;
	}

	obj = nmp_object_new_from_nl (platform, priv->cache, msg, id_only);
	if (!obj) {
		_LOGT ("event-notification: %s, seq %u: ignore",
		       _nl_nlmsg_type_to_str (msghdr->nlmsg_type, buf_nlmsg_type, sizeof (buf_nlmsg_type)),
		       msghdr->nlmsg_seq);
		return;
	}

	_LOGT ("event-notification: %s, seq %u: %s",
	       _nl_nlmsg_type_to_str (msghdr->nlmsg_type, buf_nlmsg_type, sizeof (buf_nlmsg_type)),
	       msghdr->nlmsg_seq, nmp_object_to_string (obj,
	           id_only ? NMP_OBJECT_TO_STRING_ID : NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));

	switch (msghdr->nlmsg_type) {

	case RTM_NEWLINK:
	case RTM_NEWADDR:
	case RTM_NEWROUTE:
		cache_op = nmp_cache_update_netlink (priv->cache, obj, &obj_cache, &was_visible, cache_pre_hook, platform);

		cache_post (platform, msghdr, cache_op, obj, obj_cache);

		do_emit_signal (platform, obj_cache, cache_op, was_visible);
		break;

	case RTM_DELLINK:
	case RTM_DELADDR:
	case RTM_DELROUTE:
		cache_op = nmp_cache_remove_netlink (priv->cache, obj, &obj_cache, &was_visible, cache_pre_hook, platform);
		do_emit_signal (platform, obj_cache, cache_op, was_visible);
		break;

	default:
		break;
	}

	cache_prune_candidates_drop (platform, obj_cache);
}

/******************************************************************/

static const NMPObject *
cache_lookup_link (NMPlatform *platform, int ifindex)
{
	const NMPObject *obj_cache;

	obj_cache = nmp_cache_lookup_link (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, ifindex);
	if (!nmp_object_is_visible (obj_cache))
		return NULL;

	return obj_cache;
}

const NMPlatformObject *const*
nm_linux_platform_lookup (NMPlatform *platform, const NMPCacheId *cache_id, guint *out_len)
{
	g_return_val_if_fail (NM_IS_LINUX_PLATFORM (platform), NULL);
	g_return_val_if_fail (cache_id, NULL);

	return nmp_cache_lookup_multi (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache,
	                               cache_id, out_len);
}

static GArray *
link_get_all (NMPlatform *platform)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	return nmp_cache_lookup_multi_to_array (priv->cache,
	                                        NMP_OBJECT_TYPE_LINK,
	                                        nmp_cache_id_init_object_type (NMP_CACHE_ID_STATIC, NMP_OBJECT_TYPE_LINK, TRUE));
}

static const NMPlatformLink *
_nm_platform_link_get (NMPlatform *platform, int ifindex)
{
	const NMPObject *obj;

	obj = cache_lookup_link (platform, ifindex);
	return obj ? &obj->link : NULL;
}

static const NMPlatformLink *
_nm_platform_link_get_by_ifname (NMPlatform *platform,
                                 const char *ifname)
{
	const NMPObject *obj = NULL;

	if (ifname && *ifname) {
		obj = nmp_cache_lookup_link_full (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache,
		                                  0, ifname, TRUE, NM_LINK_TYPE_NONE, NULL, NULL);
	}
	return obj ? &obj->link : NULL;
}

struct _nm_platform_link_get_by_address_data {
	gconstpointer address;
	guint8 length;
};

static gboolean
_nm_platform_link_get_by_address_match_link (const NMPObject *obj, struct _nm_platform_link_get_by_address_data *d)
{
	return obj->link.addr.len == d->length && !memcmp (obj->link.addr.data, d->address, d->length);
}

static const NMPlatformLink *
_nm_platform_link_get_by_address (NMPlatform *platform,
                                  gconstpointer address,
                                  size_t length)
{
	const NMPObject *obj;
	struct _nm_platform_link_get_by_address_data d = {
		.address = address,
		.length = length,
	};

	if (length <= 0 || length > NM_UTILS_HWADDR_LEN_MAX)
		return NULL;
	if (!address)
		return NULL;

	obj = nmp_cache_lookup_link_full (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache,
	                                  0, NULL, TRUE, NM_LINK_TYPE_NONE,
	                                  (NMPObjectMatchFn) _nm_platform_link_get_by_address_match_link, &d);
	return obj ? &obj->link : NULL;
}

/*****************************************************************************/

static const NMPObject *
link_get_lnk (NMPlatform *platform, int ifindex, NMLinkType link_type, const NMPlatformLink **out_link)
{
	const NMPObject *obj = cache_lookup_link (platform, ifindex);

	if (!obj)
		return NULL;

	NM_SET_OUT (out_link, &obj->link);

	if (!obj->_link.netlink.lnk)
		return NULL;
	if (   link_type != NM_LINK_TYPE_NONE
	    && (   link_type != obj->link.type
	        || link_type != NMP_OBJECT_GET_CLASS (obj->_link.netlink.lnk)->lnk_link_type))
		return NULL;

	return obj->_link.netlink.lnk;
}

/*****************************************************************************/

static gboolean
do_add_link_with_lookup (NMPlatform *platform,
                         NMLinkType link_type,
                         const char *name,
                         struct nl_msg *nlmsg,
                         const NMPlatformLink **out_link)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	const NMPObject *obj = NULL;
	WaitForNlResponseResult seq_result = WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN;
	int nle;
	char s_buf[256];

	event_handler_read_netlink (platform, FALSE);

	if (nmp_cache_lookup_link_full (priv->cache, 0, name, FALSE, NM_LINK_TYPE_NONE, NULL, NULL)) {
		/* hm, a link with such a name already exists. Try reloading first. */
		do_request_link (platform, 0, name);

		obj = nmp_cache_lookup_link_full (priv->cache, 0, name, FALSE, NM_LINK_TYPE_NONE, NULL, NULL);
		if (obj) {
			_LOGE ("do-add-link[%s/%s]: link already exists: %s",
			       name,
			       nm_link_type_to_string (link_type),
			       nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_ID, NULL, 0));
			return FALSE;
		}
	}

	nle = _nl_send_auto_with_seq (platform, nlmsg, &seq_result, NULL);
	if (nle < 0) {
		_LOGE ("do-add-link[%s/%s]: failed sending netlink request \"%s\" (%d)",
		       name,
		       nm_link_type_to_string (link_type),
		       nl_geterror (nle), -nle);
		return FALSE;
	}

	delayed_action_handle_all (platform, FALSE);

	nm_assert (seq_result);

	_NMLOG (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK
	            ? LOGL_DEBUG
	            : LOGL_ERR,
	        "do-add-link[%s/%s]: %s",
	        name,
	        nm_link_type_to_string (link_type),
	        wait_for_nl_response_to_string (seq_result, s_buf, sizeof (s_buf)));

	if (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK)
		obj = nmp_cache_lookup_link_full (priv->cache, 0, name, FALSE, link_type, NULL, NULL);

	if (!obj) {
		/* either kernel signaled failure, or it signaled success and the link object
		 * is not (yet) in the cache. Try to reload it... */
		do_request_link (platform, 0, name);
		obj = nmp_cache_lookup_link_full (priv->cache, 0, name, FALSE, link_type, NULL, NULL);
	}

	if (out_link)
		*out_link = obj ? &obj->link : NULL;
	return !!obj;
}

static gboolean
do_add_addrroute (NMPlatform *platform, const NMPObject *obj_id, struct nl_msg *nlmsg)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	WaitForNlResponseResult seq_result = WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN;
	int nle;
	char s_buf[256];
	const NMPObject *obj;

	nm_assert (NM_IN_SET (NMP_OBJECT_GET_TYPE (obj_id),
	                      NMP_OBJECT_TYPE_IP4_ADDRESS, NMP_OBJECT_TYPE_IP6_ADDRESS,
	                      NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE));

	event_handler_read_netlink (platform, FALSE);

	nle = _nl_send_auto_with_seq (platform, nlmsg, &seq_result, NULL);
	if (nle < 0) {
		_LOGE ("do-add-%s[%s]: failure sending netlink request \"%s\" (%d)",
		       NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name,
		       nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0),
		       nl_geterror (nle), -nle);
		return FALSE;
	}

	delayed_action_handle_all (platform, FALSE);

	nm_assert (seq_result);

	_NMLOG (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK
	            ? LOGL_DEBUG
	            : LOGL_ERR,
	        "do-add-%s[%s]: %s",
	        NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name,
	        nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0),
	        wait_for_nl_response_to_string (seq_result, s_buf, sizeof (s_buf)));

	/* In rare cases, the object is not yet ready as we received the ACK from
	 * kernel. Need to refetch.
	 *
	 * We want to safe the expensive refetch, thus we look first into the cache
	 * whether the object exists.
	 *
	 * FIXME: if the object already existed previously, we might not notice a
	 * missing update. It's not clear how to fix that reliably without refechting
	 * all the time. */
	obj = nmp_cache_lookup_obj (priv->cache, obj_id);
	if (!obj) {
		do_request_one_type (platform, NMP_OBJECT_GET_TYPE (obj_id));
		obj = nmp_cache_lookup_obj (priv->cache, obj_id);
	}

	/* Adding is only successful, if kernel reported success *and* we have the
	 * expected object in cache afterwards. */
	return obj && seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK;
}

static gboolean
do_delete_object (NMPlatform *platform, const NMPObject *obj_id, struct nl_msg *nlmsg)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	WaitForNlResponseResult seq_result = WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN;
	int nle;
	char s_buf[256];
	gboolean success = TRUE;
	const char *log_detail = "";

	event_handler_read_netlink (platform, FALSE);

	nle = _nl_send_auto_with_seq (platform, nlmsg, &seq_result, NULL);
	if (nle < 0) {
		_LOGE ("do-delete-%s[%s]: failure sending netlink request \"%s\" (%d)",
		       NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name,
		       nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0),
		       nl_geterror (nle), -nle);
		goto out;
	}

	delayed_action_handle_all (platform, FALSE);

	nm_assert (seq_result);

	if (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK) {
		/* ok */
	} else if (NM_IN_SET (-((int) seq_result), ESRCH, ENOENT))
		log_detail = ", meaning the object was already removed";
	else if (   NM_IN_SET (-((int) seq_result), ENXIO)
	         && NM_IN_SET (NMP_OBJECT_GET_TYPE (obj_id), NMP_OBJECT_TYPE_IP6_ADDRESS)) {
		/* On RHEL7 kernel, deleting a non existing address fails with ENXIO */
		log_detail = ", meaning the address was already removed";
	} else if (   NM_IN_SET (-((int) seq_result), EADDRNOTAVAIL)
	           && NM_IN_SET (NMP_OBJECT_GET_TYPE (obj_id), NMP_OBJECT_TYPE_IP4_ADDRESS, NMP_OBJECT_TYPE_IP6_ADDRESS))
		log_detail = ", meaning the address was already removed";
	else
		success = FALSE;

	_NMLOG (success ? LOGL_DEBUG : LOGL_ERR,
	        "do-delete-%s[%s]: %s%s",
	        NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name,
	        nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0),
	        wait_for_nl_response_to_string (seq_result, s_buf, sizeof (s_buf)),
	        log_detail);

out:
	if (!nmp_cache_lookup_obj (priv->cache, obj_id))
		return TRUE;

	/* such an object still exists in the cache. To be sure, refetch it (and
	 * hope it's gone) */
	do_request_one_type (platform, NMP_OBJECT_GET_TYPE (obj_id));
	return !!nmp_cache_lookup_obj (priv->cache, obj_id);
}

static NMPlatformError
do_change_link (NMPlatform *platform,
                int ifindex,
                struct nl_msg *nlmsg)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	WaitForNlResponseResult seq_result = WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN;
	int nle;
	char s_buf[256];
	NMPlatformError result = NM_PLATFORM_ERROR_SUCCESS;
	NMLogLevel log_level = LOGL_DEBUG;
	const char *log_result = "failure", *log_detail = "";

	if (!nm_platform_netns_push (platform, &netns))
		return NM_PLATFORM_ERROR_UNSPECIFIED;

retry:
	nle = _nl_send_auto_with_seq (platform, nlmsg, &seq_result, NULL);
	if (nle < 0) {
		_LOGE ("do-change-link[%d]: failure sending netlink request \"%s\" (%d)",
		       ifindex,
		       nl_geterror (nle), -nle);
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	}

	/* always refetch the link after changing it. There seems to be issues
	 * and we sometimes lack events. Nuke it from the orbit... */
	delayed_action_schedule (platform, DELAYED_ACTION_TYPE_REFRESH_LINK, GINT_TO_POINTER (ifindex));

	delayed_action_handle_all (platform, FALSE);

	nm_assert (seq_result);

	if (   NM_IN_SET (-((int) seq_result), EOPNOTSUPP)
	    && nlmsg_hdr (nlmsg)->nlmsg_type == RTM_NEWLINK) {
		nlmsg_hdr (nlmsg)->nlmsg_type = RTM_SETLINK;
		goto retry;
	}

	if (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK) {
		log_result = "success";
	} else if (NM_IN_SET (-((int) seq_result), EEXIST, EADDRINUSE)) {
		/* */
	} else if (NM_IN_SET (-((int) seq_result), ESRCH, ENOENT)) {
		log_detail = ", firmware not found";
		result = NM_PLATFORM_ERROR_NO_FIRMWARE;
	} else {
		log_level = LOGL_ERR;
		result = NM_PLATFORM_ERROR_UNSPECIFIED;
	}
	_NMLOG (log_level,
	        "do-change-link[%d]: %s changing link: %s%s",
	        ifindex,
	        log_result,
	        wait_for_nl_response_to_string (seq_result, s_buf, sizeof (s_buf)),
	        log_detail);

	return result;
}

static gboolean
link_add (NMPlatform *platform,
          const char *name,
          NMLinkType type,
          const void *address,
          size_t address_len,
          const NMPlatformLink **out_link)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;

	if (type == NM_LINK_TYPE_BOND) {
		/* When the kernel loads the bond module, either via explicit modprobe
		 * or automatically in response to creating a bond master, it will also
		 * create a 'bond0' interface.  Since the bond we're about to create may
		 * or may not be named 'bond0' prevent potential confusion about a bond
		 * that the user didn't want by telling the bonding module not to create
		 * bond0 automatically.
		 */
		if (!g_file_test ("/sys/class/net/bonding_masters", G_FILE_TEST_EXISTS))
			(void) nm_utils_modprobe (NULL, TRUE, "bonding", "max_bonds=0", NULL);
	}

	_LOGD ("link: add link '%s' of type '%s' (%d)",
	       name, nm_link_type_to_string (type), (int) type);

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          NLM_F_CREATE | NLM_F_EXCL,
	                          0,
	                          name,
	                          0,
	                          0);
	if (!nlmsg)
		return FALSE;

	if (address && address_len)
		NLA_PUT (nlmsg, IFLA_ADDRESS, address_len, address);

	if (!_nl_msg_new_link_set_linkinfo (nlmsg, type))
		return FALSE;

	return do_add_link_with_lookup (platform, type, name, nlmsg, out_link);
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static gboolean
link_delete (NMPlatform *platform, int ifindex)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	NMPObject obj_id;
	const NMPObject *obj;

	obj = nmp_cache_lookup_link (priv->cache, ifindex);
	if (!obj || !obj->_link.netlink.is_in_netlink)
		return FALSE;

	nlmsg = _nl_msg_new_link (RTM_DELLINK,
	                          0,
	                          ifindex,
	                          NULL,
	                          0,
	                          0);

	nmp_object_stackinit_id_link (&obj_id, ifindex);
	return do_delete_object (platform, &obj_id, nlmsg);
}

static const char *
link_get_type_name (NMPlatform *platform, int ifindex)
{
	const NMPObject *obj = cache_lookup_link (platform, ifindex);

	if (!obj)
		return NULL;

	if (obj->link.type != NM_LINK_TYPE_UNKNOWN) {
		/* We could detect the @link_type. In this case the function returns
		 * our internel module names, which differs from rtnl_link_get_type():
		 *   - NM_LINK_TYPE_INFINIBAND (gives "infiniband", instead of "ipoib")
		 *   - NM_LINK_TYPE_TAP (gives "tap", instead of "tun").
		 * Note that this functions is only used by NMDeviceGeneric to
		 * set type_description. */
		return nm_link_type_to_string (obj->link.type);
	}
	/* Link type not detected. Fallback to rtnl_link_get_type()/IFLA_INFO_KIND. */
	return obj->link.kind ?: "unknown";
}

static gboolean
link_get_unmanaged (NMPlatform *platform, int ifindex, gboolean *unmanaged)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	const NMPObject *link;
	GUdevDevice *udev_device = NULL;

	link = nmp_cache_lookup_link (priv->cache, ifindex);
	if (link)
		udev_device = link->_link.udev.device;

	if (udev_device && g_udev_device_get_property (udev_device, "NM_UNMANAGED")) {
		*unmanaged = g_udev_device_get_property_as_boolean (udev_device, "NM_UNMANAGED");
		return TRUE;
	}

	return FALSE;
}

static gboolean
link_refresh (NMPlatform *platform, int ifindex)
{
	do_request_link (platform, ifindex, NULL);
	return !!cache_lookup_link (platform, ifindex);
}

static gboolean
link_set_netns (NMPlatform *platform,
                int ifindex,
                int netns_fd)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;

	_LOGD ("link: move link %d to network namespace with fd %d", ifindex, netns_fd);

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL,
	                          0,
	                          0);
	if (!nlmsg)
		return FALSE;

	NLA_PUT (nlmsg, IFLA_NET_NS_FD, 4, &netns_fd);
	return do_change_link (platform, ifindex, nlmsg) == NM_PLATFORM_ERROR_SUCCESS;

nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static NMPlatformError
link_change_flags (NMPlatform *platform,
                   int ifindex,
                   unsigned flags_mask,
                   unsigned flags_set)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	char s_flags[100];

	_LOGD ("link: change %d: flags: set 0x%x/0x%x ([%s] / [%s])",
	       ifindex,
	       flags_set,
	       flags_mask,
	       nm_platform_link_flags2str (flags_set, s_flags, sizeof (s_flags)),
	       nm_platform_link_flags2str (flags_mask, NULL, 0));

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL,
	                          flags_mask,
	                          flags_set);
	if (!nlmsg)
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return do_change_link (platform, ifindex, nlmsg);
}

static gboolean
link_set_up (NMPlatform *platform, int ifindex, gboolean *out_no_firmware)
{
	NMPlatformError plerr;

	plerr = link_change_flags (platform, ifindex, IFF_UP, IFF_UP);
	if (out_no_firmware)
		*out_no_firmware = plerr == NM_PLATFORM_ERROR_NO_FIRMWARE;
	return plerr == NM_PLATFORM_ERROR_SUCCESS;
}

static gboolean
link_set_down (NMPlatform *platform, int ifindex)
{
	return link_change_flags (platform, ifindex, IFF_UP, 0) == NM_PLATFORM_ERROR_SUCCESS;
}

static gboolean
link_set_arp (NMPlatform *platform, int ifindex)
{
	return link_change_flags (platform, ifindex, IFF_NOARP, 0) == NM_PLATFORM_ERROR_SUCCESS;
}

static gboolean
link_set_noarp (NMPlatform *platform, int ifindex)
{
	return link_change_flags (platform, ifindex, IFF_NOARP, IFF_NOARP) == NM_PLATFORM_ERROR_SUCCESS;
}

static const char *
link_get_udi (NMPlatform *platform, int ifindex)
{
	const NMPObject *obj = cache_lookup_link (platform, ifindex);

	if (   !obj
	    || !obj->_link.netlink.is_in_netlink
	    || !obj->_link.udev.device)
		return NULL;
	return g_udev_device_get_sysfs_path (obj->_link.udev.device);
}

static GObject *
link_get_udev_device (NMPlatform *platform, int ifindex)
{
	const NMPObject *obj_cache;

	/* we don't use cache_lookup_link() because this would return NULL
	 * if the link is not visible in libnl. For link_get_udev_device()
	 * we want to return whatever we have, even if the link itself
	 * appears invisible via other platform functions. */

	obj_cache = nmp_cache_lookup_link (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, ifindex);
	return obj_cache ? (GObject *) obj_cache->_link.udev.device : NULL;
}

static gboolean
link_set_user_ipv6ll_enabled (NMPlatform *platform, int ifindex, gboolean enabled)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	guint8 mode = enabled ? NM_IN6_ADDR_GEN_MODE_NONE : NM_IN6_ADDR_GEN_MODE_EUI64;

	if (!_support_user_ipv6ll_get ()) {
		_LOGD ("link: change %d: user-ipv6ll: not supported", ifindex);
		return FALSE;
	}

	_LOGD ("link: change %d: user-ipv6ll: set IPv6 address generation mode to %s",
	       ifindex,
	       nm_platform_link_inet6_addrgenmode2str (mode, NULL, 0));

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL,
	                          0,
	                          0);
	if (   !nlmsg
	    || !_nl_msg_new_link_set_afspec (nlmsg,
	                                     mode))
		g_return_val_if_reached (FALSE);

	return do_change_link (platform, ifindex, nlmsg) == NM_PLATFORM_ERROR_SUCCESS;
}

static gboolean
link_supports_carrier_detect (NMPlatform *platform, int ifindex)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	const char *name = nm_platform_link_get_name (platform, ifindex);

	if (!name)
		return FALSE;

	if (!nm_platform_netns_push (platform, &netns))
		return FALSE;

	/* We use netlink for the actual carrier detection, but netlink can't tell
	 * us whether the device actually supports carrier detection in the first
	 * place. We assume any device that does implements one of these two APIs.
	 */
	return nmp_utils_ethtool_supports_carrier_detect (name) || nmp_utils_mii_supports_carrier_detect (name);
}

static gboolean
link_supports_vlans (NMPlatform *platform, int ifindex)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	const NMPObject *obj;

	obj = cache_lookup_link (platform, ifindex);

	/* Only ARPHRD_ETHER links can possibly support VLANs. */
	if (!obj || obj->link.arptype != ARPHRD_ETHER)
		return FALSE;

	if (!nm_platform_netns_push (platform, &netns))
		return FALSE;

	return nmp_utils_ethtool_supports_vlans (obj->link.name);
}

static gboolean
link_set_address (NMPlatform *platform, int ifindex, gconstpointer address, size_t length)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	gs_free char *mac = NULL;

	if (!address || !length)
		g_return_val_if_reached (FALSE);

	_LOGD ("link: change %d: address: %s (%lu bytes)", ifindex,
	       (mac = nm_utils_hwaddr_ntoa (address, length)),
	       (unsigned long) length);

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL,
	                          0,
	                          0);
	if (!nlmsg)
		return FALSE;

	NLA_PUT (nlmsg, IFLA_ADDRESS, length, address);

	return do_change_link (platform, ifindex, nlmsg) == NM_PLATFORM_ERROR_SUCCESS;
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static gboolean
link_get_permanent_address (NMPlatform *platform,
                            int ifindex,
                            guint8 *buf,
                            size_t *length)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;

	if (!nm_platform_netns_push (platform, &netns))
		return FALSE;

	return nmp_utils_ethtool_get_permanent_address (nm_platform_link_get_name (platform, ifindex), buf, length);
}

static gboolean
link_set_mtu (NMPlatform *platform, int ifindex, guint32 mtu)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;

	_LOGD ("link: change %d: mtu: %u", ifindex, (unsigned) mtu);

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL,
	                          0,
	                          0);
	if (!nlmsg)
		return FALSE;

	NLA_PUT_U32 (nlmsg, IFLA_MTU, mtu);

	return do_change_link (platform, ifindex, nlmsg) == NM_PLATFORM_ERROR_SUCCESS;
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static char *
link_get_physical_port_id (NMPlatform *platform, int ifindex)
{
	const char *ifname;
	char *path, *id;

	ifname = nm_platform_link_get_name (platform, ifindex);
	if (!ifname)
		return NULL;

	ifname = NM_ASSERT_VALID_PATH_COMPONENT (ifname);

	path = g_strdup_printf ("/sys/class/net/%s/phys_port_id", ifname);
	id = sysctl_get (platform, path);
	g_free (path);

	return id;
}

static guint
link_get_dev_id (NMPlatform *platform, int ifindex)
{
	const char *ifname;
	gs_free char *path = NULL, *id = NULL;
	gint64 int_val;

	ifname = nm_platform_link_get_name (platform, ifindex);
	if (!ifname)
		return 0;

	ifname = NM_ASSERT_VALID_PATH_COMPONENT (ifname);

	path = g_strdup_printf ("/sys/class/net/%s/dev_id", ifname);
	id = sysctl_get (platform, path);
	if (!id || !*id)
		return 0;

	/* Value is reported as hex */
	int_val = _nm_utils_ascii_str_to_int64 (id, 16, 0, G_MAXUINT16, 0);

	return errno ? 0 : (int) int_val;
}

static int
vlan_add (NMPlatform *platform,
          const char *name,
          int parent,
          int vlan_id,
          guint32 vlan_flags,
          const NMPlatformLink **out_link)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;

	G_STATIC_ASSERT (NM_VLAN_FLAG_REORDER_HEADERS == (guint32) VLAN_FLAG_REORDER_HDR);
	G_STATIC_ASSERT (NM_VLAN_FLAG_GVRP == (guint32) VLAN_FLAG_GVRP);
	G_STATIC_ASSERT (NM_VLAN_FLAG_LOOSE_BINDING == (guint32) VLAN_FLAG_LOOSE_BINDING);
	G_STATIC_ASSERT (NM_VLAN_FLAG_MVRP == (guint32) VLAN_FLAG_MVRP);

	vlan_flags &= (guint32) NM_VLAN_FLAGS_ALL;

	_LOGD ("link: add vlan '%s', parent %d, vlan id %d, flags %X",
	       name, parent, vlan_id, (unsigned int) vlan_flags);

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          NLM_F_CREATE | NLM_F_EXCL,
	                          0,
	                          name,
	                          0,
	                          0);
	if (!nlmsg)
		return FALSE;

	NLA_PUT_U32 (nlmsg, IFLA_LINK, parent);

	if (!_nl_msg_new_link_set_linkinfo_vlan (nlmsg,
	                                         vlan_id,
	                                         NM_VLAN_FLAGS_ALL,
	                                         vlan_flags,
	                                         NULL,
	                                         0,
	                                         NULL,
	                                         0))
		return FALSE;

	return do_add_link_with_lookup (platform, NM_LINK_TYPE_VLAN, name, nlmsg, out_link);
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static int
link_gre_add (NMPlatform *platform,
              const char *name,
              const NMPlatformLnkGre *props,
              const NMPlatformLink **out_link)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	struct nlattr *info;
	struct nlattr *data;
	char buffer[INET_ADDRSTRLEN];

	_LOGD (LOG_FMT_IP_TUNNEL,
	       "gre",
	       name,
	       props->parent_ifindex,
	       nm_utils_inet4_ntop (props->local, NULL),
	       nm_utils_inet4_ntop (props->remote, buffer));

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          NLM_F_CREATE | NLM_F_EXCL,
	                          0,
	                          name,
	                          0,
	                          0);
	if (!nlmsg)
		return FALSE;

	if (!(info = nla_nest_start (nlmsg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING (nlmsg, IFLA_INFO_KIND, "gre");

	if (!(data = nla_nest_start (nlmsg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	if (props->parent_ifindex)
		NLA_PUT_U32 (nlmsg, IFLA_GRE_LINK, props->parent_ifindex);
	NLA_PUT_U32 (nlmsg, IFLA_GRE_LOCAL, props->local);
	NLA_PUT_U32 (nlmsg, IFLA_GRE_REMOTE, props->remote);
	NLA_PUT_U8 (nlmsg, IFLA_GRE_TTL, props->ttl);
	NLA_PUT_U8 (nlmsg, IFLA_GRE_TOS, props->tos);
	NLA_PUT_U8 (nlmsg, IFLA_GRE_PMTUDISC, !!props->path_mtu_discovery);
	NLA_PUT_U32 (nlmsg, IFLA_GRE_IKEY, htonl (props->input_key));
	NLA_PUT_U32 (nlmsg, IFLA_GRE_OKEY, htonl (props->output_key));
	NLA_PUT_U32 (nlmsg, IFLA_GRE_IFLAGS, htons (props->input_flags));
	NLA_PUT_U32 (nlmsg, IFLA_GRE_OFLAGS, htons (props->output_flags));

	nla_nest_end (nlmsg, data);
	nla_nest_end (nlmsg, info);

	return do_add_link_with_lookup (platform, NM_LINK_TYPE_GRE, name, nlmsg, out_link);
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static int
link_ip6tnl_add (NMPlatform *platform,
                 const char *name,
                 const NMPlatformLnkIp6Tnl *props,
                 const NMPlatformLink **out_link)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	struct nlattr *info;
	struct nlattr *data;
	char buffer[INET_ADDRSTRLEN];
	guint32 flowinfo;

	_LOGD (LOG_FMT_IP_TUNNEL,
	       "ip6tnl",
	       name,
	       props->parent_ifindex,
	       nm_utils_inet6_ntop (&props->local, NULL),
	       nm_utils_inet6_ntop (&props->remote, buffer));

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          NLM_F_CREATE | NLM_F_EXCL,
	                          0,
	                          name,
	                          0,
	                          0);
	if (!nlmsg)
		return FALSE;

	if (!(info = nla_nest_start (nlmsg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING (nlmsg, IFLA_INFO_KIND, "ip6tnl");

	if (!(data = nla_nest_start (nlmsg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	if (props->parent_ifindex)
		NLA_PUT_U32 (nlmsg, IFLA_IPTUN_LINK, props->parent_ifindex);

	if (memcmp (&props->local, &in6addr_any, sizeof (in6addr_any)))
		NLA_PUT (nlmsg, IFLA_IPTUN_LOCAL, sizeof (props->local), &props->local);
	if (memcmp (&props->remote, &in6addr_any, sizeof (in6addr_any)))
		NLA_PUT (nlmsg, IFLA_IPTUN_REMOTE, sizeof (props->remote), &props->remote);

	NLA_PUT_U8 (nlmsg, IFLA_IPTUN_TTL, props->ttl);
	NLA_PUT_U8 (nlmsg, IFLA_IPTUN_ENCAP_LIMIT, props->encap_limit);

	flowinfo = props->flow_label & IP6_FLOWINFO_FLOWLABEL_MASK;
	flowinfo |=   (props->tclass << IP6_FLOWINFO_TCLASS_SHIFT)
	            & IP6_FLOWINFO_TCLASS_MASK;
	NLA_PUT_U32 (nlmsg, IFLA_IPTUN_FLOWINFO, htonl (flowinfo));
	NLA_PUT_U8 (nlmsg, IFLA_IPTUN_PROTO, props->proto);

	nla_nest_end (nlmsg, data);
	nla_nest_end (nlmsg, info);

	return do_add_link_with_lookup (platform, NM_LINK_TYPE_IP6TNL, name, nlmsg, out_link);
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static int
link_ipip_add (NMPlatform *platform,
               const char *name,
               const NMPlatformLnkIpIp *props,
               const NMPlatformLink **out_link)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	struct nlattr *info;
	struct nlattr *data;
	char buffer[INET_ADDRSTRLEN];

	_LOGD (LOG_FMT_IP_TUNNEL,
	       "ipip",
	       name,
	       props->parent_ifindex,
	       nm_utils_inet4_ntop (props->local, NULL),
	       nm_utils_inet4_ntop (props->remote, buffer));

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          NLM_F_CREATE | NLM_F_EXCL,
	                          0,
	                          name,
	                          0,
	                          0);
	if (!nlmsg)
		return FALSE;

	if (!(info = nla_nest_start (nlmsg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING (nlmsg, IFLA_INFO_KIND, "ipip");

	if (!(data = nla_nest_start (nlmsg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	if (props->parent_ifindex)
		NLA_PUT_U32 (nlmsg, IFLA_IPTUN_LINK, props->parent_ifindex);
	NLA_PUT_U32 (nlmsg, IFLA_IPTUN_LOCAL, props->local);
	NLA_PUT_U32 (nlmsg, IFLA_IPTUN_REMOTE, props->remote);
	NLA_PUT_U8 (nlmsg, IFLA_IPTUN_TTL, props->ttl);
	NLA_PUT_U8 (nlmsg, IFLA_IPTUN_TOS, props->tos);
	NLA_PUT_U8 (nlmsg, IFLA_IPTUN_PMTUDISC, !!props->path_mtu_discovery);

	nla_nest_end (nlmsg, data);
	nla_nest_end (nlmsg, info);

	return do_add_link_with_lookup (platform, NM_LINK_TYPE_IPIP, name, nlmsg, out_link);
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static int
link_macvlan_add (NMPlatform *platform,
                  const char *name,
                  int parent,
                  const NMPlatformLnkMacvlan *props,
                  const NMPlatformLink **out_link)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	struct nlattr *info;
	struct nlattr *data;

	_LOGD ("adding %s '%s' parent %u mode %u",
	       props->tap ? "macvtap" : "macvlan",
	       name,
	       parent,
	       props->mode);

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          NLM_F_CREATE | NLM_F_EXCL,
	                          0,
	                          name,
	                          0,
	                          0);
	if (!nlmsg)
		return FALSE;

	NLA_PUT_U32 (nlmsg, IFLA_LINK, parent);

	if (!(info = nla_nest_start (nlmsg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING (nlmsg, IFLA_INFO_KIND, props->tap ? "macvtap" : "macvlan");

	if (!(data = nla_nest_start (nlmsg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	NLA_PUT_U32 (nlmsg, IFLA_MACVLAN_MODE, props->mode);
	NLA_PUT_U16 (nlmsg, IFLA_MACVLAN_FLAGS, props->no_promisc ? MACVLAN_FLAG_NOPROMISC : 0);

	nla_nest_end (nlmsg, data);
	nla_nest_end (nlmsg, info);

	return do_add_link_with_lookup (platform,
	                                props->tap ? NM_LINK_TYPE_MACVTAP : NM_LINK_TYPE_MACVLAN,
	                                name, nlmsg, out_link);
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static int
link_sit_add (NMPlatform *platform,
              const char *name,
              const NMPlatformLnkSit *props,
              const NMPlatformLink **out_link)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	struct nlattr *info;
	struct nlattr *data;
	char buffer[INET_ADDRSTRLEN];

	_LOGD (LOG_FMT_IP_TUNNEL,
	       "sit",
	       name,
	       props->parent_ifindex,
	       nm_utils_inet4_ntop (props->local, NULL),
	       nm_utils_inet4_ntop (props->remote, buffer));

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          NLM_F_CREATE | NLM_F_EXCL,
	                          0,
	                          name,
	                          0,
	                          0);
	if (!nlmsg)
		return FALSE;

	if (!(info = nla_nest_start (nlmsg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING (nlmsg, IFLA_INFO_KIND, "sit");

	if (!(data = nla_nest_start (nlmsg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	if (props->parent_ifindex)
		NLA_PUT_U32 (nlmsg, IFLA_IPTUN_LINK, props->parent_ifindex);
	NLA_PUT_U32 (nlmsg, IFLA_IPTUN_LOCAL, props->local);
	NLA_PUT_U32 (nlmsg, IFLA_IPTUN_REMOTE, props->remote);
	NLA_PUT_U8 (nlmsg, IFLA_IPTUN_TTL, props->ttl);
	NLA_PUT_U8 (nlmsg, IFLA_IPTUN_TOS, props->tos);
	NLA_PUT_U8 (nlmsg, IFLA_IPTUN_PMTUDISC, !!props->path_mtu_discovery);

	nla_nest_end (nlmsg, data);
	nla_nest_end (nlmsg, info);

	return do_add_link_with_lookup (platform, NM_LINK_TYPE_SIT, name, nlmsg, out_link);
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static gboolean
link_vxlan_add (NMPlatform *platform,
                const char *name,
                const NMPlatformLnkVxlan *props,
                const NMPlatformLink **out_link)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	struct nlattr *info;
	struct nlattr *data;
	struct nm_ifla_vxlan_port_range port_range;

	g_return_val_if_fail (props, FALSE);

	_LOGD ("link: add vxlan '%s', parent %d, vxlan id %d",
	       name, props->parent_ifindex, props->id);

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          NLM_F_CREATE | NLM_F_EXCL,
	                          0,
	                          name,
	                          0,
	                          0);
	if (!nlmsg)
		return FALSE;

	if (!(info = nla_nest_start (nlmsg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING (nlmsg, IFLA_INFO_KIND, "vxlan");

	if (!(data = nla_nest_start (nlmsg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	NLA_PUT_U32 (nlmsg, IFLA_VXLAN_ID, props->id);

	if (props->group)
		NLA_PUT (nlmsg, IFLA_VXLAN_GROUP, sizeof (props->group), &props->group);
	else if (memcmp (&props->group6, &in6addr_any, sizeof (in6addr_any)))
		NLA_PUT (nlmsg, IFLA_VXLAN_GROUP6, sizeof (props->group6), &props->group6);

	if (props->local)
		NLA_PUT (nlmsg, IFLA_VXLAN_LOCAL, sizeof (props->local), &props->local);
	else if (memcmp (&props->local6, &in6addr_any, sizeof (in6addr_any)))
		NLA_PUT (nlmsg, IFLA_VXLAN_LOCAL6, sizeof (props->local6), &props->local6);

	if (props->parent_ifindex >= 0)
		NLA_PUT_U32 (nlmsg, IFLA_VXLAN_LINK, props->parent_ifindex);

	if (props->src_port_min || props->src_port_max) {
		port_range.low = htons (props->src_port_min);
		port_range.high = htons (props->src_port_max);
		NLA_PUT (nlmsg, IFLA_VXLAN_PORT_RANGE, sizeof (port_range), &port_range);
	}

	NLA_PUT_U16 (nlmsg, IFLA_VXLAN_PORT, htons (props->dst_port));
	NLA_PUT_U8 (nlmsg, IFLA_VXLAN_TOS, props->tos);
	NLA_PUT_U8 (nlmsg, IFLA_VXLAN_TTL, props->ttl);
	NLA_PUT_U32 (nlmsg, IFLA_VXLAN_AGEING, props->ageing);
	NLA_PUT_U32 (nlmsg, IFLA_VXLAN_LIMIT, props->limit);
	NLA_PUT_U8 (nlmsg, IFLA_VXLAN_LEARNING, !!props->learning);
	NLA_PUT_U8 (nlmsg, IFLA_VXLAN_PROXY, !!props->proxy);
	NLA_PUT_U8 (nlmsg, IFLA_VXLAN_RSC, !!props->rsc);
	NLA_PUT_U8 (nlmsg, IFLA_VXLAN_L2MISS, !!props->l2miss);
	NLA_PUT_U8 (nlmsg, IFLA_VXLAN_L3MISS, !!props->l3miss);

	nla_nest_end (nlmsg, data);
	nla_nest_end (nlmsg, info);

	return do_add_link_with_lookup (platform, NM_LINK_TYPE_VXLAN, name, nlmsg, out_link);
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static void
_vlan_change_vlan_qos_mapping_create (gboolean is_ingress_map,
                                      gboolean reset_all,
                                      const NMVlanQosMapping *current_map,
                                      guint current_n_map,
                                      const NMVlanQosMapping *set_map,
                                      guint set_n_map,
                                      NMVlanQosMapping **out_map,
                                      guint *out_n_map)
{
	NMVlanQosMapping *map;
	guint i, j, len;
	const guint INGRESS_RANGE_LEN = 8;

	nm_assert (out_map && !*out_map);
	nm_assert (out_n_map && !*out_n_map);

	if (!reset_all)
		current_n_map = 0;
	else if (is_ingress_map)
		current_n_map = INGRESS_RANGE_LEN;

	len = current_n_map + set_n_map;

	if (len == 0)
		return;

	map = g_new (NMVlanQosMapping, len);

	if (current_n_map) {
		if (is_ingress_map) {
			/* For the ingress-map, there are only 8 entries (0 to 7).
			 * When the user requests to reset all entires, we don't actually
			 * need the cached entries, we can just explicitly clear all possible
			 * ones.
			 *
			 * That makes only a real difference in case our cache is out-of-date.
			 *
			 * For the egress map we cannot do that, because there are far too
			 * many. There we can only clear the entries that we know about. */
			for (i = 0; i < INGRESS_RANGE_LEN; i++) {
				map[i].from = i;
				map[i].to = 0;
			}
		} else {
			for (i = 0; i < current_n_map; i++) {
				map[i].from = current_map[i].from;
				map[i].to = 0;
			}
		}
	}
	if (set_n_map)
		memcpy (&map[current_n_map], set_map, sizeof (*set_map) * set_n_map);

	g_qsort_with_data (map,
	                   len,
	                   sizeof (*map),
	                   _vlan_qos_mapping_cmp_from,
	                   NULL);

	for (i = 0, j = 0; i < len; i++) {
		if (   ( is_ingress_map && !VLAN_XGRESS_PRIO_VALID (map[i].from))
		    || (!is_ingress_map && !VLAN_XGRESS_PRIO_VALID (map[i].to)))
			continue;
		if (   j > 0
		    && map[j - 1].from == map[i].from)
			map[j - 1] = map[i];
		else
			map[j++] = map[i];
	}

	*out_map = map;
	*out_n_map = j;
}

static gboolean
link_vlan_change (NMPlatform *platform,
                  int ifindex,
                  NMVlanFlags flags_mask,
                  NMVlanFlags flags_set,
                  gboolean ingress_reset_all,
                  const NMVlanQosMapping *ingress_map,
                  gsize n_ingress_map,
                  gboolean egress_reset_all,
                  const NMVlanQosMapping *egress_map,
                  gsize n_egress_map)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	const NMPObject *obj_cache;
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	const NMPObjectLnkVlan *lnk;
	guint new_n_ingress_map = 0;
	guint new_n_egress_map = 0;
	gs_free NMVlanQosMapping *new_ingress_map = NULL;
	gs_free NMVlanQosMapping *new_egress_map = NULL;
	char s_flags[64];
	char s_ingress[256];
	char s_egress[256];

	obj_cache = nmp_cache_lookup_link (priv->cache, ifindex);
	if (   !obj_cache
	    || !obj_cache->_link.netlink.is_in_netlink) {
		_LOGD ("link: change %d: %s: link does not exist", ifindex, "vlan");
		return FALSE;
	}

	lnk = obj_cache->_link.netlink.lnk ? &obj_cache->_link.netlink.lnk->_lnk_vlan : NULL;

	flags_set &= flags_mask;

	_vlan_change_vlan_qos_mapping_create (TRUE,
	                                      ingress_reset_all,
	                                      lnk ? lnk->ingress_qos_map : NULL,
	                                      lnk ? lnk->n_ingress_qos_map : 0,
	                                      ingress_map,
	                                      n_ingress_map,
	                                      &new_ingress_map,
	                                      &new_n_ingress_map);

	_vlan_change_vlan_qos_mapping_create (FALSE,
	                                      egress_reset_all,
	                                      lnk ? lnk->egress_qos_map : NULL,
	                                      lnk ? lnk->n_egress_qos_map : 0,
	                                      egress_map,
	                                      n_egress_map,
	                                      &new_egress_map,
	                                      &new_n_egress_map);

	_LOGD ("link: change %d: vlan:%s%s%s",
	       ifindex,
	       flags_mask
	           ? nm_sprintf_buf (s_flags, " flags 0x%x/0x%x", (unsigned) flags_set, (unsigned) flags_mask)
	           : "",
	       new_n_ingress_map
	           ? nm_platform_vlan_qos_mapping_to_string (" ingress-qos-map",
	                                                     new_ingress_map,
	                                                     new_n_ingress_map,
	                                                     s_ingress,
	                                                     sizeof (s_ingress))
	           : "",
	       new_n_egress_map
	           ? nm_platform_vlan_qos_mapping_to_string (" egress-qos-map",
	                                                     new_egress_map,
	                                                     new_n_egress_map,
	                                                     s_egress,
	                                                     sizeof (s_egress))
	           : "");

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL,
	                          0,
	                          0);
	if (   !nlmsg
	    || !_nl_msg_new_link_set_linkinfo_vlan (nlmsg,
	                                            -1,
	                                            flags_mask,
	                                            flags_set,
	                                            new_ingress_map,
	                                            new_n_ingress_map,
	                                            new_egress_map,
	                                            new_n_egress_map))
		g_return_val_if_reached (FALSE);

	return do_change_link (platform, ifindex, nlmsg) == NM_PLATFORM_ERROR_SUCCESS;
}

static int
tun_add (NMPlatform *platform, const char *name, gboolean tap,
         gint64 owner, gint64 group, gboolean pi, gboolean vnet_hdr,
         gboolean multi_queue, const NMPlatformLink **out_link)
{
	const NMPObject *obj;
	struct ifreq ifr = { };
	int fd;

	_LOGD ("link: add %s '%s' owner %" G_GINT64_FORMAT " group %" G_GINT64_FORMAT,
	       tap ? "tap" : "tun", name, owner, group);

	fd = open ("/dev/net/tun", O_RDWR);
	if (fd < 0)
		return FALSE;

	nm_utils_ifname_cpy (ifr.ifr_name, name);
	ifr.ifr_flags = tap ? IFF_TAP : IFF_TUN;

	if (!pi)
		ifr.ifr_flags |= IFF_NO_PI;
	if (vnet_hdr)
		ifr.ifr_flags |= IFF_VNET_HDR;
	if (multi_queue)
		ifr.ifr_flags |= NM_IFF_MULTI_QUEUE;

	if (ioctl (fd, TUNSETIFF, &ifr)) {
		close (fd);
		return FALSE;
	}

	if (owner >= 0 && owner < G_MAXINT32) {
		if (ioctl (fd, TUNSETOWNER, (uid_t) owner)) {
			close (fd);
			return FALSE;
		}
	}

	if (group >= 0 && group < G_MAXINT32) {
		if (ioctl (fd, TUNSETGROUP, (gid_t) group)) {
			close (fd);
			return FALSE;
		}
	}

	if (ioctl (fd, TUNSETPERSIST, 1)) {
		close (fd);
		return FALSE;
	}
	do_request_link (platform, 0, name);
	obj = nmp_cache_lookup_link_full (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache,
	                                  0, name, FALSE,
	                                  tap ? NM_LINK_TYPE_TAP : NM_LINK_TYPE_TUN,
	                                  NULL, NULL);
	if (out_link)
		*out_link = obj ? &obj->link : NULL;

	close (fd);
	return !!obj;
}

static gboolean
link_enslave (NMPlatform *platform, int master, int slave)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	int ifindex = slave;

	_LOGD ("link: change %d: enslave: master %d", slave, master);

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL,
	                          0,
	                          0);
	if (!nlmsg)
		return FALSE;

	NLA_PUT_U32 (nlmsg, IFLA_MASTER, master);

	return do_change_link (platform, ifindex, nlmsg) == NM_PLATFORM_ERROR_SUCCESS;
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static gboolean
link_release (NMPlatform *platform, int master, int slave)
{
	return link_enslave (platform, 0, slave);
}

/******************************************************************/

static gboolean
_infiniband_partition_action (NMPlatform *platform,
                              InfinibandAction action,
                              int parent,
                              int p_key,
                              const NMPlatformLink **out_link)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	const NMPObject *obj_parent;
	const NMPObject *obj;
	char path[NM_STRLEN ("/sys/class/net/%s/%s") + IFNAMSIZ + 100];
	char id[20];
	char name[IFNAMSIZ];
	gboolean success;

	nm_assert (NM_IN_SET (action, INFINIBAND_ACTION_CREATE_CHILD, INFINIBAND_ACTION_DELETE_CHILD));
	nm_assert (p_key > 0 && p_key <= 0xffff && p_key != 0x8000);

	obj_parent = nmp_cache_lookup_link (priv->cache, parent);
	if (!obj_parent || !obj_parent->link.name[0]) {
		errno = ENOENT;
		return FALSE;
	}

	nm_sprintf_buf (path,
	                "/sys/class/net/%s/%s",
	                NM_ASSERT_VALID_PATH_COMPONENT (obj_parent->link.name),
	                (action == INFINIBAND_ACTION_CREATE_CHILD
	                     ? "create_child"
	                     : "delete_child"));
	nm_sprintf_buf (id, "0x%04x", p_key);
	success = nm_platform_sysctl_set (platform, path, id);
	if (!success) {
		if (   action == INFINIBAND_ACTION_DELETE_CHILD
		    && errno == ENODEV)
			return TRUE;
		return FALSE;
	}

	nm_utils_new_infiniband_name (name, obj_parent->link.name, p_key);
	do_request_link (platform, 0, name);

	if (action == INFINIBAND_ACTION_DELETE_CHILD)
		return TRUE;

	obj = nmp_cache_lookup_link_full (priv->cache, 0, name, FALSE,
	                                  NM_LINK_TYPE_INFINIBAND, NULL, NULL);
	if (out_link)
		*out_link = obj ? &obj->link : NULL;
	return !!obj;
}

static gboolean
infiniband_partition_add (NMPlatform *platform, int parent, int p_key, const NMPlatformLink **out_link)
{
	return _infiniband_partition_action (platform, INFINIBAND_ACTION_CREATE_CHILD, parent, p_key, out_link);
}

static gboolean
infiniband_partition_delete (NMPlatform *platform, int parent, int p_key)
{
	return _infiniband_partition_action (platform, INFINIBAND_ACTION_DELETE_CHILD, parent, p_key, NULL);
}

/******************************************************************/

static WifiData *
wifi_get_wifi_data (NMPlatform *platform, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	WifiData *wifi_data;

	wifi_data = g_hash_table_lookup (priv->wifi_data, GINT_TO_POINTER (ifindex));
	if (!wifi_data) {
		const NMPlatformLink *pllink;

		pllink = nm_platform_link_get (platform, ifindex);
		if (pllink) {
			if (pllink->type == NM_LINK_TYPE_WIFI)
				wifi_data = wifi_utils_init (pllink->name, ifindex, TRUE);
			else if (pllink->type == NM_LINK_TYPE_OLPC_MESH) {
				/* The kernel driver now uses nl80211, but we force use of WEXT because
				 * the cfg80211 interactions are not quite ready to support access to
				 * mesh control through nl80211 just yet.
				 */
#if HAVE_WEXT
				wifi_data = wifi_wext_init (pllink->name, ifindex, FALSE);
#endif
			}

			if (wifi_data)
				g_hash_table_insert (priv->wifi_data, GINT_TO_POINTER (ifindex), wifi_data);
		}
	}

	return wifi_data;
}
#define WIFI_GET_WIFI_DATA_NETNS(wifi_data, platform, ifindex, retval) \
	nm_auto_pop_netns NMPNetns *netns = NULL; \
	WifiData *wifi_data; \
	if (!nm_platform_netns_push (platform, &netns)) \
		return retval; \
	wifi_data = wifi_get_wifi_data (platform, ifindex); \
	if (!wifi_data) \
		return retval;

static gboolean
wifi_get_capabilities (NMPlatform *platform, int ifindex, NMDeviceWifiCapabilities *caps)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	if (caps)
		*caps = wifi_utils_get_caps (wifi_data);
	return TRUE;
}

static gboolean
wifi_get_bssid (NMPlatform *platform, int ifindex, guint8 *bssid)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	return wifi_utils_get_bssid (wifi_data, bssid);
}

static guint32
wifi_get_frequency (NMPlatform *platform, int ifindex)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, 0);
	return wifi_utils_get_freq (wifi_data);
}

static gboolean
wifi_get_quality (NMPlatform *platform, int ifindex)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	return wifi_utils_get_qual (wifi_data);
}

static guint32
wifi_get_rate (NMPlatform *platform, int ifindex)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	return wifi_utils_get_rate (wifi_data);
}

static NM80211Mode
wifi_get_mode (NMPlatform *platform, int ifindex)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, NM_802_11_MODE_UNKNOWN);
	return wifi_utils_get_mode (wifi_data);
}

static void
wifi_set_mode (NMPlatform *platform, int ifindex, NM80211Mode mode)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, );
	wifi_utils_set_mode (wifi_data, mode);
}

static void
wifi_set_powersave (NMPlatform *platform, int ifindex, guint32 powersave)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, );
	wifi_utils_set_powersave (wifi_data, powersave);
}

static guint32
wifi_find_frequency (NMPlatform *platform, int ifindex, const guint32 *freqs)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, 0);
	return wifi_utils_find_freq (wifi_data, freqs);
}

static void
wifi_indicate_addressing_running (NMPlatform *platform, int ifindex, gboolean running)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, );
	wifi_utils_indicate_addressing_running (wifi_data, running);
}

/******************************************************************/

static gboolean
link_can_assume (NMPlatform *platform, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	NMPCacheId cache_id;
	const NMPlatformObject *const *objs;
	guint i, len;
	const NMPObject *link;

	if (ifindex <= 0)
		return FALSE;

	link = cache_lookup_link (platform, ifindex);
	if (!link)
		return FALSE;

	if (!NM_FLAGS_HAS (link->link.n_ifi_flags, IFF_UP))
		return FALSE;

	if (link->link.master > 0)
		return TRUE;

	if (nmp_cache_lookup_multi (priv->cache,
	                            nmp_cache_id_init_addrroute_visible_by_ifindex (&cache_id, NMP_OBJECT_TYPE_IP4_ADDRESS, ifindex),
	                            NULL))
		return TRUE;

	objs = nmp_cache_lookup_multi (priv->cache,
	                               nmp_cache_id_init_addrroute_visible_by_ifindex (&cache_id, NMP_OBJECT_TYPE_IP6_ADDRESS, ifindex),
	                               &len);
	if (objs) {
		for (i = 0; i < len; i++) {
			const NMPlatformIP6Address *a = (NMPlatformIP6Address *) objs[i];

			if (!IN6_IS_ADDR_LINKLOCAL (&a->address))
				return TRUE;
		}
	}
	return FALSE;
}

/******************************************************************/

static guint32
mesh_get_channel (NMPlatform *platform, int ifindex)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, 0);
	return wifi_utils_get_mesh_channel (wifi_data);
}

static gboolean
mesh_set_channel (NMPlatform *platform, int ifindex, guint32 channel)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	return wifi_utils_set_mesh_channel (wifi_data, channel);
}

static gboolean
mesh_set_ssid (NMPlatform *platform, int ifindex, const guint8 *ssid, gsize len)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	return wifi_utils_set_mesh_ssid (wifi_data, ssid, len);
}

/******************************************************************/

static gboolean
link_get_wake_on_lan (NMPlatform *platform, int ifindex)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	NMLinkType type = nm_platform_link_get_type (platform, ifindex);

	if (!nm_platform_netns_push (platform, &netns))
		return FALSE;

	if (type == NM_LINK_TYPE_ETHERNET)
		return nmp_utils_ethtool_get_wake_on_lan (nm_platform_link_get_name (platform, ifindex));
	else if (type == NM_LINK_TYPE_WIFI) {
		WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

		if (!wifi_data)
			return FALSE;

		return wifi_utils_get_wowlan (wifi_data);
	} else
		return FALSE;
}

static gboolean
link_get_driver_info (NMPlatform *platform,
                      int ifindex,
                      char **out_driver_name,
                      char **out_driver_version,
                      char **out_fw_version)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;

	if (!nm_platform_netns_push (platform, &netns))
		return FALSE;

	return nmp_utils_ethtool_get_driver_info (nm_platform_link_get_name (platform, ifindex),
	                                          out_driver_name,
	                                          out_driver_version,
	                                          out_fw_version);
}

/******************************************************************/

static GArray *
ipx_address_get_all (NMPlatform *platform, int ifindex, NMPObjectType obj_type)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	nm_assert (NM_IN_SET (obj_type, NMP_OBJECT_TYPE_IP4_ADDRESS, NMP_OBJECT_TYPE_IP6_ADDRESS));

	return nmp_cache_lookup_multi_to_array (priv->cache,
	                                        obj_type,
	                                        nmp_cache_id_init_addrroute_visible_by_ifindex (NMP_CACHE_ID_STATIC,
	                                                                                        obj_type,
	                                                                                        ifindex));
}

static GArray *
ip4_address_get_all (NMPlatform *platform, int ifindex)
{
	return ipx_address_get_all (platform, ifindex, NMP_OBJECT_TYPE_IP4_ADDRESS);
}

static GArray *
ip6_address_get_all (NMPlatform *platform, int ifindex)
{
	return ipx_address_get_all (platform, ifindex, NMP_OBJECT_TYPE_IP6_ADDRESS);
}

static gboolean
ip4_address_add (NMPlatform *platform,
                 int ifindex,
                 in_addr_t addr,
                 guint8 plen,
                 in_addr_t peer_addr,
                 guint32 lifetime,
                 guint32 preferred,
                 guint32 flags,
                 const char *label)
{
	NMPObject obj_id;
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;

	nlmsg = _nl_msg_new_address (RTM_NEWADDR,
	                             NLM_F_CREATE | NLM_F_REPLACE,
	                             AF_INET,
	                             ifindex,
	                             &addr,
	                             plen,
	                             &peer_addr,
	                             flags,
	                             nm_utils_ip4_address_is_link_local (addr) ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSE,
	                             lifetime,
	                             preferred,
	                             label);

	nmp_object_stackinit_id_ip4_address (&obj_id, ifindex, addr, plen, peer_addr);
	return do_add_addrroute (platform, &obj_id, nlmsg);
}

static gboolean
ip6_address_add (NMPlatform *platform,
                 int ifindex,
                 struct in6_addr addr,
                 guint8 plen,
                 struct in6_addr peer_addr,
                 guint32 lifetime,
                 guint32 preferred,
                 guint32 flags)
{
	NMPObject obj_id;
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;

	nlmsg = _nl_msg_new_address (RTM_NEWADDR,
	                             NLM_F_CREATE | NLM_F_REPLACE,
	                             AF_INET6,
	                             ifindex,
	                             &addr,
	                             plen,
	                             &peer_addr,
	                             flags,
	                             RT_SCOPE_UNIVERSE,
	                             lifetime,
	                             preferred,
	                             NULL);

	nmp_object_stackinit_id_ip6_address (&obj_id, ifindex, &addr, plen);
	return do_add_addrroute (platform, &obj_id, nlmsg);
}

static gboolean
ip4_address_delete (NMPlatform *platform, int ifindex, in_addr_t addr, guint8 plen, in_addr_t peer_address)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	NMPObject obj_id;

	nlmsg = _nl_msg_new_address (RTM_DELADDR,
	                             0,
	                             AF_INET,
	                             ifindex,
	                             &addr,
	                             plen,
	                             &peer_address,
	                             0,
	                             RT_SCOPE_NOWHERE,
	                             NM_PLATFORM_LIFETIME_PERMANENT,
	                             NM_PLATFORM_LIFETIME_PERMANENT,
	                             NULL);
	if (!nlmsg)
		g_return_val_if_reached (FALSE);

	nmp_object_stackinit_id_ip4_address (&obj_id, ifindex, addr, plen, peer_address);
	return do_delete_object (platform, &obj_id, nlmsg);
}

static gboolean
ip6_address_delete (NMPlatform *platform, int ifindex, struct in6_addr addr, guint8 plen)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	NMPObject obj_id;

	nlmsg = _nl_msg_new_address (RTM_DELADDR,
	                             0,
	                             AF_INET6,
	                             ifindex,
	                             &addr,
	                             plen,
	                             NULL,
	                             0,
	                             RT_SCOPE_NOWHERE,
	                             NM_PLATFORM_LIFETIME_PERMANENT,
	                             NM_PLATFORM_LIFETIME_PERMANENT,
	                             NULL);
	if (!nlmsg)
		g_return_val_if_reached (FALSE);

	nmp_object_stackinit_id_ip6_address (&obj_id, ifindex, &addr, plen);
	return do_delete_object (platform, &obj_id, nlmsg);
}

static const NMPlatformIP4Address *
ip4_address_get (NMPlatform *platform, int ifindex, in_addr_t addr, guint8 plen, in_addr_t peer_address)
{
	NMPObject obj_id;
	const NMPObject *obj;

	nmp_object_stackinit_id_ip4_address (&obj_id, ifindex, addr, plen, peer_address);
	obj = nmp_cache_lookup_obj (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, &obj_id);
	if (nmp_object_is_visible (obj))
		return &obj->ip4_address;
	return NULL;
}

static const NMPlatformIP6Address *
ip6_address_get (NMPlatform *platform, int ifindex, struct in6_addr addr, guint8 plen)
{
	NMPObject obj_id;
	const NMPObject *obj;

	nmp_object_stackinit_id_ip6_address (&obj_id, ifindex, &addr, plen);
	obj = nmp_cache_lookup_obj (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, &obj_id);
	if (nmp_object_is_visible (obj))
		return &obj->ip6_address;
	return NULL;
}

/******************************************************************/

static GArray *
ipx_route_get_all (NMPlatform *platform, int ifindex, NMPObjectType obj_type, NMPlatformGetRouteFlags flags)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	NMPCacheId cache_id;
	const NMPlatformIPRoute *const* routes;
	GArray *array;
	const NMPClass *klass;
	gboolean with_rtprot_kernel;
	guint i, len;

	nm_assert (NM_IN_SET (obj_type, NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE));

	if (!NM_FLAGS_ANY (flags, NM_PLATFORM_GET_ROUTE_FLAGS_WITH_DEFAULT | NM_PLATFORM_GET_ROUTE_FLAGS_WITH_NON_DEFAULT))
		flags |= NM_PLATFORM_GET_ROUTE_FLAGS_WITH_DEFAULT | NM_PLATFORM_GET_ROUTE_FLAGS_WITH_NON_DEFAULT;

	klass = nmp_class_from_type (obj_type);

	nmp_cache_id_init_routes_visible (&cache_id,
	                                  obj_type,
	                                  NM_FLAGS_HAS (flags, NM_PLATFORM_GET_ROUTE_FLAGS_WITH_DEFAULT),
	                                  NM_FLAGS_HAS (flags, NM_PLATFORM_GET_ROUTE_FLAGS_WITH_NON_DEFAULT),
	                                  ifindex);

	routes = (const NMPlatformIPRoute *const*) nmp_cache_lookup_multi (priv->cache, &cache_id, &len);

	array = g_array_sized_new (FALSE, FALSE, klass->sizeof_public, len);

	with_rtprot_kernel = NM_FLAGS_HAS (flags, NM_PLATFORM_GET_ROUTE_FLAGS_WITH_RTPROT_KERNEL);
	for (i = 0; i < len; i++) {
		nm_assert (NMP_OBJECT_GET_CLASS (NMP_OBJECT_UP_CAST (routes[i])) == klass);

		if (   with_rtprot_kernel
		    || routes[i]->rt_source != NM_IP_CONFIG_SOURCE_RTPROT_KERNEL)
			g_array_append_vals (array, routes[i], 1);
	}
	return array;
}

static GArray *
ip4_route_get_all (NMPlatform *platform, int ifindex, NMPlatformGetRouteFlags flags)
{
	return ipx_route_get_all (platform, ifindex, NMP_OBJECT_TYPE_IP4_ROUTE, flags);
}

static GArray *
ip6_route_get_all (NMPlatform *platform, int ifindex, NMPlatformGetRouteFlags flags)
{
	return ipx_route_get_all (platform, ifindex, NMP_OBJECT_TYPE_IP6_ROUTE, flags);
}

static gboolean
ip4_route_add (NMPlatform *platform, int ifindex, NMIPConfigSource source,
               in_addr_t network, guint8 plen, in_addr_t gateway,
               in_addr_t pref_src, guint32 metric, guint32 mss)
{
	NMPObject obj_id;
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;

	nlmsg = _nl_msg_new_route (RTM_NEWROUTE,
	                           NLM_F_CREATE | NLM_F_REPLACE,
	                           AF_INET,
	                           ifindex,
	                           source,
	                           gateway ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK,
	                           &network,
	                           plen,
	                           &gateway,
	                           metric,
	                           mss,
	                           pref_src ? &pref_src : NULL);

	nmp_object_stackinit_id_ip4_route (&obj_id, ifindex, network, plen, metric);
	return do_add_addrroute (platform, &obj_id, nlmsg);
}

static gboolean
ip6_route_add (NMPlatform *platform, int ifindex, NMIPConfigSource source,
               struct in6_addr network, guint8 plen, struct in6_addr gateway,
               guint32 metric, guint32 mss)
{
	NMPObject obj_id;
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;

	nlmsg = _nl_msg_new_route (RTM_NEWROUTE,
	                           NLM_F_CREATE | NLM_F_REPLACE,
	                           AF_INET6,
	                           ifindex,
	                           source,
	                           !IN6_IS_ADDR_UNSPECIFIED (&gateway) ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK,
	                           &network,
	                           plen,
	                           &gateway,
	                           metric,
	                           mss,
	                           NULL);

	nmp_object_stackinit_id_ip6_route (&obj_id, ifindex, &network, plen, metric);
	return do_add_addrroute (platform, &obj_id, nlmsg);
}

static gboolean
ip4_route_delete (NMPlatform *platform, int ifindex, in_addr_t network, guint8 plen, guint32 metric)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	NMPObject obj_id;

	nmp_object_stackinit_id_ip4_route (&obj_id, ifindex, network, plen, metric);

	if (metric == 0) {
		/* Deleting an IPv4 route with metric 0 does not only delete an exectly matching route.
		 * If no route with metric 0 exists, it might delete another route to the same destination.
		 * For nm_platform_ip4_route_delete() we don't want this semantic.
		 *
		 * Instead, make sure that we have the most recent state and process all
		 * delayed actions (including re-reading data from netlink). */
		delayed_action_handle_all (platform, TRUE);

		if (!nmp_cache_lookup_obj (priv->cache, &obj_id)) {
			/* hmm... we are about to delete an IP4 route with metric 0. We must only
			 * send the delete request if such a route really exists. Above we refreshed
			 * the platform cache, still no such route exists.
			 *
			 * Be extra careful and reload the routes. We must be sure that such a
			 * route doesn't exists, because when we add an IPv4 address, we immediately
			 * afterwards try to delete the kernel-added device route with metric 0.
			 * It might be, that we didn't yet get the notification about that route.
			 *
			 * FIXME: once our ip4_address_add() is sure that upon return we have
			 * the latest state from in the platform cache, we might save this
			 * additional expensive cache-resync. */
			do_request_one_type (platform, NMP_OBJECT_TYPE_IP4_ROUTE);

			if (!nmp_cache_lookup_obj (priv->cache, &obj_id))
				return TRUE;
		}
	}

	nlmsg = _nl_msg_new_route (RTM_DELROUTE,
	                           0,
	                           AF_INET,
	                           ifindex,
	                           NM_IP_CONFIG_SOURCE_UNKNOWN,
	                           RT_SCOPE_NOWHERE,
	                           &network,
	                           plen,
	                           NULL,
	                           metric,
	                           0,
	                           NULL);
	if (!nlmsg)
		return FALSE;

	return do_delete_object (platform, &obj_id, nlmsg);
}

static gboolean
ip6_route_delete (NMPlatform *platform, int ifindex, struct in6_addr network, guint8 plen, guint32 metric)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	NMPObject obj_id;

	metric = nm_utils_ip6_route_metric_normalize (metric);

	nlmsg = _nl_msg_new_route (RTM_DELROUTE,
	                           0,
	                           AF_INET6,
	                           ifindex,
	                           NM_IP_CONFIG_SOURCE_UNKNOWN,
	                           RT_SCOPE_NOWHERE,
	                           &network,
	                           plen,
	                           NULL,
	                           metric,
	                           0,
	                           NULL);
	if (!nlmsg)
		return FALSE;

	nmp_object_stackinit_id_ip6_route (&obj_id, ifindex, &network, plen, metric);

	return do_delete_object (platform, &obj_id, nlmsg);
}

static const NMPlatformIP4Route *
ip4_route_get (NMPlatform *platform, int ifindex, in_addr_t network, guint8 plen, guint32 metric)
{
	NMPObject obj_id;
	const NMPObject *obj;

	nmp_object_stackinit_id_ip4_route (&obj_id, ifindex, network, plen, metric);
	obj = nmp_cache_lookup_obj (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, &obj_id);
	if (nmp_object_is_visible (obj))
		return &obj->ip4_route;
	return NULL;
}

static const NMPlatformIP6Route *
ip6_route_get (NMPlatform *platform, int ifindex, struct in6_addr network, guint8 plen, guint32 metric)
{
	NMPObject obj_id;
	const NMPObject *obj;

	metric = nm_utils_ip6_route_metric_normalize (metric);

	nmp_object_stackinit_id_ip6_route (&obj_id, ifindex, &network, plen, metric);
	obj = nmp_cache_lookup_obj (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, &obj_id);
	if (nmp_object_is_visible (obj))
		return &obj->ip6_route;
	return NULL;
}

/******************************************************************/

#define EVENT_CONDITIONS      ((GIOCondition) (G_IO_IN | G_IO_PRI))
#define ERROR_CONDITIONS      ((GIOCondition) (G_IO_ERR | G_IO_NVAL))
#define DISCONNECT_CONDITIONS ((GIOCondition) (G_IO_HUP))

static gboolean
event_handler (GIOChannel *channel,
               GIOCondition io_condition,
               gpointer user_data)
{
	delayed_action_handle_all (NM_PLATFORM (user_data), TRUE);
	return TRUE;
}

/*****************************************************************************/

/* copied from libnl3's recvmsgs() */
static int
event_handler_recvmsgs (NMPlatform *platform, gboolean handle_events)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	struct nl_sock *sk = priv->nlh;
	int n, err = 0, multipart = 0, interrupted = 0;
	struct nlmsghdr *hdr;
	WaitForNlResponseResult seq_result;

	/*
	nla is passed on to not only to nl_recv() but may also be passed
	to a function pointer provided by the caller which may or may not
	initialize the variable. Thomas Graf.
	*/
	struct sockaddr_nl nla = {0};
	nm_auto_free struct ucred *creds = NULL;
	nm_auto_free unsigned char *buf = NULL;

continue_reading:
	g_clear_pointer (&buf, free);
	g_clear_pointer (&creds, free);
	errno = 0;
	n = nl_recv (sk, &nla, &buf, &creds);

	switch (n) {
	case 0:
		/* Work around a libnl bug fixed in 3.2.22 (375a6294) */
		if (errno == EAGAIN) {
			/* EAGAIN is equal to EWOULDBLOCK. If it would not be, we'd have to
			 * workaround libnl3 mapping EWOULDBLOCK to -NLE_FAILURE. */
			G_STATIC_ASSERT (EAGAIN == EWOULDBLOCK);
			n = -NLE_AGAIN;
		}
		break;
	case -NLE_NOMEM:
		if (errno == ENOBUFS) {
			/* we are very much interested in a overrun of the receive buffer.
			 * nl_recv() maps all kinds of errors to NLE_NOMEM, so check also
			 * for errno explicitly. And if so, hack our own return code to signal
			 * the overrun. */
			n = -_NLE_NM_NOBUFS;
		}
		break;
	}

	if (n <= 0)
		return n;

	hdr = (struct nlmsghdr *) buf;
	while (nlmsg_ok (hdr, n)) {
		nm_auto_nlmsg struct nl_msg *msg = NULL;
		gboolean abort_parsing = FALSE;
		gboolean process_valid_msg = FALSE;
		guint32 seq_number;

		msg = nlmsg_convert (hdr);
		if (!msg) {
			err = -NLE_NOMEM;
			goto out;
		}

		nlmsg_set_proto (msg, NETLINK_ROUTE);
		nlmsg_set_src (msg, &nla);

		if (!creds || creds->pid) {
			if (creds)
				_LOGT ("netlink: recvmsg: received non-kernel message (pid %d)", creds->pid);
			else
				_LOGT ("netlink: recvmsg: received message without credentials");
			err = 0;
			goto stop;
		}

		_LOGt ("netlink: recvmsg: new message type %d, seq %u",
		       hdr->nlmsg_type, hdr->nlmsg_seq);

		if (creds)
			nlmsg_set_creds (msg, creds);

		if (hdr->nlmsg_flags & NLM_F_MULTI)
			multipart = 1;

		if (hdr->nlmsg_flags & NLM_F_DUMP_INTR) {
			/*
			 * We have to continue reading to clear
			 * all messages until a NLMSG_DONE is
			 * received and report the inconsistency.
			 */
			interrupted = 1;
		}

		/* Other side wishes to see an ack for this message */
		if (hdr->nlmsg_flags & NLM_F_ACK) {
			/* FIXME: implement */
		}

		seq_result = WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_UNKNOWN;

		if (hdr->nlmsg_type == NLMSG_DONE) {
			/* messages terminates a multipart message, this is
			 * usually the end of a message and therefore we slip
			 * out of the loop by default. the user may overrule
			 * this action by skipping this packet. */
			multipart = 0;
			seq_result = WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK;
		} else if (hdr->nlmsg_type == NLMSG_NOOP) {
			/* Message to be ignored, the default action is to
			 * skip this message if no callback is specified. The
			 * user may overrule this action by returning
			 * NL_PROCEED. */
		} else if (hdr->nlmsg_type == NLMSG_OVERRUN) {
			/* Data got lost, report back to user. The default action is to
			 * quit parsing. The user may overrule this action by retuning
			 * NL_SKIP or NL_PROCEED (dangerous) */
			err = -NLE_MSG_OVERFLOW;
			abort_parsing = TRUE;
		} else if (hdr->nlmsg_type == NLMSG_ERROR) {
			/* Message carries a nlmsgerr */
			struct nlmsgerr *e = nlmsg_data (hdr);

			if (hdr->nlmsg_len < nlmsg_size (sizeof (*e))) {
				/* Truncated error message, the default action
				 * is to stop parsing. The user may overrule
				 * this action by returning NL_SKIP or
				 * NL_PROCEED (dangerous) */
				err = -NLE_MSG_TRUNC;
				abort_parsing = TRUE;
			} else if (e->error) {
				int errsv = e->error > 0 ? e->error : -e->error;

				/* Error message reported back from kernel. */
				_LOGD ("netlink: recvmsg: error message from kernel: %s (%d) for request %d",
				       strerror (errsv),
				       errsv,
				       nlmsg_hdr (msg)->nlmsg_seq);
				seq_result = -errsv;
			} else
				seq_result = WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK;
		} else
			process_valid_msg = TRUE;

		seq_number = nlmsg_hdr (msg)->nlmsg_seq;

		/* check whether the seq number is different from before, and
		 * whether the previous number (@nlh_seq_last_seen) is a pending
		 * refresh-all request. In that case, the pending request is thereby
		 * completed.
		 *
		 * We must do that before processing the message with event_valid_msg(),
		 * because we must track the completion of the pending request before that. */
		event_seq_check_refresh_all (platform, seq_number);

		if (process_valid_msg) {
			/* Valid message (not checking for MULTIPART bit to
			 * get along with broken kernels. NL_SKIP has no
			 * effect on this.  */

			event_valid_msg (platform, msg, handle_events);

			seq_result = WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK;
		}

		event_seq_check (platform, seq_number, seq_result);

		if (abort_parsing)
			goto stop;

		err = 0;
		hdr = nlmsg_next (hdr, &n);
	}

	if (multipart) {
		/* Multipart message not yet complete, continue reading */
		goto continue_reading;
	}
stop:
	if (!handle_events) {
		/* when we don't handle events, we want to drain all messages from the socket
		 * without handling the messages (but still check for sequence numbers).
		 * Repeat reading. */
		goto continue_reading;
	}
out:
	if (interrupted)
		err = -NLE_DUMP_INTR;
	return err;
}

/*****************************************************************************/

static gboolean
event_handler_read_netlink (NMPlatform *platform, gboolean wait_for_acks)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int r, nle;
	struct pollfd pfd;
	gboolean any = FALSE;
	gint64 now_ns;
	int timeout_ms;
	guint i;
	struct {
		guint32 seq_number;
		gint64 timeout_abs_ns;
	} data_next;

	if (!nm_platform_netns_push (platform, &netns))
		return FALSE;

	while (TRUE) {

		while (TRUE) {

			nle = event_handler_recvmsgs (platform, TRUE);

			if (nle < 0)
				switch (nle) {
				case -NLE_AGAIN:
					goto after_read;
				case -NLE_DUMP_INTR:
					_LOGD ("netlink: read: uncritical failure to retrieve incoming events: %s (%d)", nl_geterror (nle), nle);
					break;
				case -_NLE_NM_NOBUFS:
					_LOGI ("netlink: read: too many netlink events. Need to resynchronize platform cache");
					event_handler_recvmsgs (platform, FALSE);
					delayed_action_wait_for_nl_response_complete_all (platform, WAIT_FOR_NL_RESPONSE_RESULT_FAILED_RESYNC);
					delayed_action_schedule (platform,
					                         DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS |
					                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES |
					                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES |
					                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES |
					                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,
					                         NULL);
					break;
				default:
					_LOGE ("netlink: read: failed to retrieve incoming events: %s (%d)", nl_geterror (nle), nle);
					break;
			}
			any = TRUE;
		}

after_read:

		if (!NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE))
			return any;

		now_ns = 0;
		data_next.seq_number = 0;
		data_next.timeout_abs_ns = 0;

		for (i = 0; i < priv->delayed_action.list_wait_for_nl_response->len; ) {
			DelayedActionWaitForNlResponseData *data = &g_array_index (priv->delayed_action.list_wait_for_nl_response, DelayedActionWaitForNlResponseData, i);

			if (data->seq_result)
				delayed_action_wait_for_nl_response_complete (platform, i, data->seq_result);
			else if ((now_ns ?: (now_ns = nm_utils_get_monotonic_timestamp_ns ())) > data->timeout_abs_ns)
				delayed_action_wait_for_nl_response_complete (platform, i, WAIT_FOR_NL_RESPONSE_RESULT_FAILED_TIMEOUT);
			else {
				i++;

				if (   data_next.seq_number == 0
				    || data_next.timeout_abs_ns > data->timeout_abs_ns) {
					data_next.seq_number = data->seq_number;
					data_next.timeout_abs_ns = data->timeout_abs_ns;
				}
			}
		}

		if (   !wait_for_acks
		    || !NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE))
			return any;

		nm_assert (data_next.seq_number);
		nm_assert (data_next.timeout_abs_ns > 0);
		nm_assert (now_ns > 0);

		_LOGT ("netlink: read: wait for ACK for sequence number %u...", data_next.seq_number);

		timeout_ms = (data_next.timeout_abs_ns - now_ns) / (NM_UTILS_NS_PER_SECOND / 1000);

		memset (&pfd, 0, sizeof (pfd));
		pfd.fd = nl_socket_get_fd (priv->nlh);
		pfd.events = POLLIN;
		r = poll (&pfd, 1, MAX (1, timeout_ms));

		if (r == 0) {
			/* timeout and there is nothing to read. */
			goto after_read;
		}
		if (r < 0) {
			int errsv = errno;

			if (errsv != EINTR) {
				_LOGE ("netlink: read: poll failed with %s", strerror (errsv));
				delayed_action_wait_for_nl_response_complete_all (platform, WAIT_FOR_NL_RESPONSE_RESULT_FAILED_POLL);
				return any;
			}
			/* Continue to read again, even if there might be nothing to read after EINTR. */
		}
	}
}

/******************************************************************/

static void
cache_update_link_udev (NMPlatform *platform, int ifindex, GUdevDevice *udev_device)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	nm_auto_nmpobj NMPObject *obj_cache = NULL;
	gboolean was_visible;
	NMPCacheOpsType cache_op;

	cache_op = nmp_cache_update_link_udev (priv->cache, ifindex, udev_device, &obj_cache, &was_visible, cache_pre_hook, platform);

	if (cache_op != NMP_CACHE_OPS_UNCHANGED) {
		nm_auto_pop_netns NMPNetns *netns = NULL;

		if (!nm_platform_netns_push (platform, &netns))
			return;
		do_emit_signal (platform, obj_cache, cache_op, was_visible);
	}
}

static void
udev_device_added (NMPlatform *platform,
                   GUdevDevice *udev_device)
{
	const char *ifname;
	int ifindex;

	ifname = g_udev_device_get_name (udev_device);
	if (!ifname) {
		_LOGD ("udev-add: failed to get device's interface");
		return;
	}

	if (!g_udev_device_get_property (udev_device, "IFINDEX")) {
		_LOGW ("udev-add[%s]failed to get device's ifindex", ifname);
		return;
	}
	ifindex = g_udev_device_get_property_as_int (udev_device, "IFINDEX");
	if (ifindex <= 0) {
		_LOGW ("udev-add[%s]: retrieved invalid IFINDEX=%d", ifname, ifindex);
		return;
	}

	if (!g_udev_device_get_sysfs_path (udev_device)) {
		_LOGD ("udev-add[%s,%d]: couldn't determine device path; ignoring...", ifname, ifindex);
		return;
	}

	_LOGT ("udev-add[%s,%d]: device added", ifname, ifindex);
	cache_update_link_udev (platform, ifindex, udev_device);
}

static gboolean
_udev_device_removed_match_link (const NMPObject *obj, gpointer udev_device)
{
	return obj->_link.udev.device == udev_device;
}

static void
udev_device_removed (NMPlatform *platform,
                     GUdevDevice *udev_device)
{
	int ifindex = 0;

	if (g_udev_device_get_property (udev_device, "IFINDEX"))
		ifindex = g_udev_device_get_property_as_int (udev_device, "IFINDEX");
	else {
		const NMPObject *obj;

		obj = nmp_cache_lookup_link_full (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache,
		                                  0, NULL, FALSE, NM_LINK_TYPE_NONE, _udev_device_removed_match_link, udev_device);
		if (obj)
			ifindex = obj->link.ifindex;
	}

	_LOGD ("udev-remove: IFINDEX=%d", ifindex);
	if (ifindex <= 0)
		return;

	cache_update_link_udev (platform, ifindex, NULL);
}

static void
handle_udev_event (GUdevClient *client,
                   const char *action,
                   GUdevDevice *udev_device,
                   gpointer user_data)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	NMPlatform *platform = NM_PLATFORM (user_data);
	const char *subsys;
	const char *ifindex;
	guint64 seqnum;

	g_return_if_fail (action != NULL);

	if (!nm_platform_netns_push (platform, &netns))
		return;

	/* A bit paranoid */
	subsys = g_udev_device_get_subsystem (udev_device);
	g_return_if_fail (!g_strcmp0 (subsys, "net"));

	ifindex = g_udev_device_get_property (udev_device, "IFINDEX");
	seqnum = g_udev_device_get_seqnum (udev_device);
	_LOGD ("UDEV event: action '%s' subsys '%s' device '%s' (%s); seqnum=%" G_GUINT64_FORMAT,
	        action, subsys, g_udev_device_get_name (udev_device),
	        ifindex ? ifindex : "unknown", seqnum);

	if (!strcmp (action, "add") || !strcmp (action, "move"))
		udev_device_added (platform, udev_device);
	if (!strcmp (action, "remove"))
		udev_device_removed (platform, udev_device);
}

/******************************************************************/

static void
nm_linux_platform_init (NMLinuxPlatform *self)
{
	NMLinuxPlatformPrivate *priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_LINUX_PLATFORM, NMLinuxPlatformPrivate);
	gboolean use_udev;

	use_udev =    nmp_netns_is_initial ()
	           && access ("/sys", W_OK) == 0;

	self->priv = priv;

	priv->nlh_seq_next = 1;
	priv->cache = nmp_cache_new (use_udev);
	priv->delayed_action.list_master_connected = g_ptr_array_new ();
	priv->delayed_action.list_refresh_link = g_ptr_array_new ();
	priv->delayed_action.list_wait_for_nl_response = g_array_new (FALSE, TRUE, sizeof (DelayedActionWaitForNlResponseData));
	priv->wifi_data = g_hash_table_new_full (NULL, NULL, NULL, (GDestroyNotify) wifi_utils_deinit);

	if (use_udev)
		priv->udev_client = g_udev_client_new ((const char *[]) { "net", NULL });
}

static void
constructed (GObject *_object)
{
	NMPlatform *platform = NM_PLATFORM (_object);
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int channel_flags;
	gboolean status;
	int nle;

	nm_assert (!platform->_netns || platform->_netns == nmp_netns_get_current ());

	_LOGD ("create (%s netns, %s, %s udev)",
	       !platform->_netns ? "ignore" : "use",
	       !platform->_netns && nmp_netns_is_initial ()
	           ? "initial netns"
	           : (!nmp_netns_get_current ()
	                ? "no netns support"
	                : nm_sprintf_bufa (100, "in netns[%p]%s",
	                                   nmp_netns_get_current (),
	                                   nmp_netns_get_current () == nmp_netns_get_initial () ? "/main" : "")),
	       nmp_cache_use_udev_get (priv->cache) ? "use" : "no");

	priv->nlh = nl_socket_alloc ();
	g_assert (priv->nlh);

	nle = nl_connect (priv->nlh, NETLINK_ROUTE);
	g_assert (!nle);
	nle = nl_socket_set_passcred (priv->nlh, 1);
	g_assert (!nle);

	/* No blocking for event socket, so that we can drain it safely. */
	nle = nl_socket_set_nonblocking (priv->nlh);
	g_assert (!nle);

	/* use 8 MB for receive socket kernel queue. */
	nle = nl_socket_set_buffer_size (priv->nlh, 8*1024*1024, 0);
	g_assert (!nle);

	nle = nl_socket_add_memberships (priv->nlh,
	                                 RTNLGRP_LINK,
	                                 RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR,
	                                 RTNLGRP_IPV4_ROUTE,  RTNLGRP_IPV6_ROUTE,
	                                 0);
	g_assert (!nle);
	_LOGD ("Netlink socket for events established: port=%u, fd=%d", nl_socket_get_local_port (priv->nlh), nl_socket_get_fd (priv->nlh));

	priv->event_channel = g_io_channel_unix_new (nl_socket_get_fd (priv->nlh));
	g_io_channel_set_encoding (priv->event_channel, NULL, NULL);
	g_io_channel_set_close_on_unref (priv->event_channel, TRUE);

	channel_flags = g_io_channel_get_flags (priv->event_channel);
	status = g_io_channel_set_flags (priv->event_channel,
	                                 channel_flags | G_IO_FLAG_NONBLOCK, NULL);
	g_assert (status);
	priv->event_id = g_io_add_watch (priv->event_channel,
	                                (EVENT_CONDITIONS | ERROR_CONDITIONS | DISCONNECT_CONDITIONS),
	                                 event_handler, platform);

	/* complete construction of the GObject instance before populating the cache. */
	G_OBJECT_CLASS (nm_linux_platform_parent_class)->constructed (_object);

	_LOGD ("populate platform cache");
	delayed_action_schedule (platform,
	                         DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS |
	                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES |
	                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES |
	                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES |
	                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,
	                         NULL);

	delayed_action_handle_all (platform, FALSE);

	/* Set up udev monitoring */
	if (priv->udev_client) {
		GUdevEnumerator *enumerator;
		GList *devices, *iter;

		g_signal_connect (priv->udev_client, "uevent", G_CALLBACK (handle_udev_event), platform);

		/* And read initial device list */
		enumerator = g_udev_enumerator_new (priv->udev_client);
		g_udev_enumerator_add_match_subsystem (enumerator, "net");

		g_udev_enumerator_add_match_is_initialized (enumerator);

		devices = g_udev_enumerator_execute (enumerator);
		for (iter = devices; iter; iter = g_list_next (iter)) {
			udev_device_added (platform, G_UDEV_DEVICE (iter->data));
			g_object_unref (G_UDEV_DEVICE (iter->data));
		}
		g_list_free (devices);
		g_object_unref (enumerator);
	}
}

static void
dispose (GObject *object)
{
	NMPlatform *platform = NM_PLATFORM (object);
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	_LOGD ("dispose");

	delayed_action_wait_for_nl_response_complete_all (platform, WAIT_FOR_NL_RESPONSE_RESULT_FAILED_DISPOSING);

	priv->delayed_action.flags = DELAYED_ACTION_TYPE_NONE;
	g_ptr_array_set_size (priv->delayed_action.list_master_connected, 0);
	g_ptr_array_set_size (priv->delayed_action.list_refresh_link, 0);

	g_clear_pointer (&priv->prune_candidates, g_hash_table_unref);

	if (priv->udev_client) {
		g_signal_handlers_disconnect_by_func (priv->udev_client, G_CALLBACK (handle_udev_event), platform);
		g_clear_object (&priv->udev_client);
	}

	G_OBJECT_CLASS (nm_linux_platform_parent_class)->dispose (object);
}

static void
nm_linux_platform_finalize (GObject *object)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (object);

	nmp_cache_free (priv->cache);

	g_ptr_array_unref (priv->delayed_action.list_master_connected);
	g_ptr_array_unref (priv->delayed_action.list_refresh_link);
	g_array_unref (priv->delayed_action.list_wait_for_nl_response);

	/* Free netlink resources */
	g_source_remove (priv->event_id);
	g_io_channel_unref (priv->event_channel);
	nl_socket_free (priv->nlh);

	g_hash_table_unref (priv->wifi_data);

	if (priv->sysctl_get_prev_values) {
		sysctl_clear_cache_list = g_slist_remove (sysctl_clear_cache_list, object);
		g_hash_table_destroy (priv->sysctl_get_prev_values);
	}

	G_OBJECT_CLASS (nm_linux_platform_parent_class)->finalize (object);
}

#define OVERRIDE(function) platform_class->function = function

static void
nm_linux_platform_class_init (NMLinuxPlatformClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMPlatformClass *platform_class = NM_PLATFORM_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMLinuxPlatformPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->finalize = nm_linux_platform_finalize;

	platform_class->sysctl_set = sysctl_set;
	platform_class->sysctl_get = sysctl_get;

	platform_class->link_get = _nm_platform_link_get;
	platform_class->link_get_by_ifname = _nm_platform_link_get_by_ifname;
	platform_class->link_get_by_address = _nm_platform_link_get_by_address;
	platform_class->link_get_all = link_get_all;
	platform_class->link_add = link_add;
	platform_class->link_delete = link_delete;
	platform_class->link_get_type_name = link_get_type_name;
	platform_class->link_get_unmanaged = link_get_unmanaged;

	platform_class->link_get_lnk = link_get_lnk;

	platform_class->link_refresh = link_refresh;

	platform_class->link_set_netns = link_set_netns;

	platform_class->link_set_up = link_set_up;
	platform_class->link_set_down = link_set_down;
	platform_class->link_set_arp = link_set_arp;
	platform_class->link_set_noarp = link_set_noarp;

	platform_class->link_get_udi = link_get_udi;
	platform_class->link_get_udev_device = link_get_udev_device;

	platform_class->link_set_user_ipv6ll_enabled = link_set_user_ipv6ll_enabled;

	platform_class->link_set_address = link_set_address;
	platform_class->link_get_permanent_address = link_get_permanent_address;
	platform_class->link_set_mtu = link_set_mtu;

	platform_class->link_get_physical_port_id = link_get_physical_port_id;
	platform_class->link_get_dev_id = link_get_dev_id;
	platform_class->link_get_wake_on_lan = link_get_wake_on_lan;
	platform_class->link_get_driver_info = link_get_driver_info;

	platform_class->link_supports_carrier_detect = link_supports_carrier_detect;
	platform_class->link_supports_vlans = link_supports_vlans;

	platform_class->link_enslave = link_enslave;
	platform_class->link_release = link_release;

	platform_class->link_can_assume = link_can_assume;

	platform_class->vlan_add = vlan_add;
	platform_class->link_vlan_change = link_vlan_change;
	platform_class->link_vxlan_add = link_vxlan_add;

	platform_class->tun_add = tun_add;

	platform_class->infiniband_partition_add = infiniband_partition_add;
	platform_class->infiniband_partition_delete = infiniband_partition_delete;

	platform_class->wifi_get_capabilities = wifi_get_capabilities;
	platform_class->wifi_get_bssid = wifi_get_bssid;
	platform_class->wifi_get_frequency = wifi_get_frequency;
	platform_class->wifi_get_quality = wifi_get_quality;
	platform_class->wifi_get_rate = wifi_get_rate;
	platform_class->wifi_get_mode = wifi_get_mode;
	platform_class->wifi_set_mode = wifi_set_mode;
	platform_class->wifi_set_powersave = wifi_set_powersave;
	platform_class->wifi_find_frequency = wifi_find_frequency;
	platform_class->wifi_indicate_addressing_running = wifi_indicate_addressing_running;

	platform_class->mesh_get_channel = mesh_get_channel;
	platform_class->mesh_set_channel = mesh_set_channel;
	platform_class->mesh_set_ssid = mesh_set_ssid;

	platform_class->link_gre_add = link_gre_add;
	platform_class->link_ip6tnl_add = link_ip6tnl_add;
	platform_class->link_macvlan_add = link_macvlan_add;
	platform_class->link_ipip_add = link_ipip_add;
	platform_class->link_sit_add = link_sit_add;

	platform_class->ip4_address_get = ip4_address_get;
	platform_class->ip6_address_get = ip6_address_get;
	platform_class->ip4_address_get_all = ip4_address_get_all;
	platform_class->ip6_address_get_all = ip6_address_get_all;
	platform_class->ip4_address_add = ip4_address_add;
	platform_class->ip6_address_add = ip6_address_add;
	platform_class->ip4_address_delete = ip4_address_delete;
	platform_class->ip6_address_delete = ip6_address_delete;

	platform_class->ip4_route_get = ip4_route_get;
	platform_class->ip6_route_get = ip6_route_get;
	platform_class->ip4_route_get_all = ip4_route_get_all;
	platform_class->ip6_route_get_all = ip6_route_get_all;
	platform_class->ip4_route_add = ip4_route_add;
	platform_class->ip6_route_add = ip6_route_add;
	platform_class->ip4_route_delete = ip4_route_delete;
	platform_class->ip6_route_delete = ip6_route_delete;

	platform_class->check_support_kernel_extended_ifa_flags = check_support_kernel_extended_ifa_flags;
	platform_class->check_support_user_ipv6ll = check_support_user_ipv6ll;

	platform_class->process_events = process_events;
}

