// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2012 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-linux-platform.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <endian.h>
#include <fcntl.h>
#include <libudev.h>
#include <linux/fib_rules.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>
#include <linux/tc_act/tc_mirred.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "nm-std-aux/unaligned.h"

#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nm-setting-vlan.h"

#include "nm-glib-aux/nm-secret-utils.h"
#include "nm-glib-aux/nm-c-list.h"
#include "nm-netlink.h"
#include "nm-core-utils.h"
#include "nmp-object.h"
#include "nmp-netns.h"
#include "nm-platform-utils.h"
#include "nm-platform-private.h"
#include "wifi/nm-wifi-utils.h"
#include "wifi/nm-wifi-utils-wext.h"
#include "wpan/nm-wpan-utils.h"
#include "nm-glib-aux/nm-io-utils.h"
#include "nm-udev-aux/nm-udev-utils.h"

/*****************************************************************************/

/* re-implement <linux/tc_act/tc_defact.h> to build against kernel
 * headers that lack this. */

#include <linux/pkt_cls.h>

struct tc_defact {
	tc_gen;
};

enum {
	TCA_DEF_UNSPEC,
	TCA_DEF_TM,
	TCA_DEF_PARMS,
	TCA_DEF_DATA,
	TCA_DEF_PAD,
	__TCA_DEF_MAX
};
#define TCA_DEF_MAX (__TCA_DEF_MAX - 1)

/*****************************************************************************/

/* Compat with older kernels. */

#define TCA_FQ_CODEL_CE_THRESHOLD 7
#define TCA_FQ_CODEL_MEMORY_LIMIT 9

/*****************************************************************************/

#define VLAN_FLAG_MVRP 0x8

/*****************************************************************************/

#define IFQDISCSIZ                      32

/*****************************************************************************/

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

#define IFLA_TUN_UNSPEC                 0
#define IFLA_TUN_OWNER                  1
#define IFLA_TUN_GROUP                  2
#define IFLA_TUN_TYPE                   3
#define IFLA_TUN_PI                     4
#define IFLA_TUN_VNET_HDR               5
#define IFLA_TUN_PERSIST                6
#define IFLA_TUN_MULTI_QUEUE            7
#define IFLA_TUN_NUM_QUEUES             8
#define IFLA_TUN_NUM_DISABLED_QUEUES    9
#define __IFLA_TUN_MAX                  10
#define IFLA_TUN_MAX (__IFLA_TUN_MAX - 1)

G_STATIC_ASSERT (RTA_MAX == (__RTA_MAX - 1));
#define RTA_PREF                        20
#undef  RTA_MAX
#define RTA_MAX                        (MAX ((__RTA_MAX - 1), RTA_PREF))

#ifndef MACVLAN_FLAG_NOPROMISC
#define MACVLAN_FLAG_NOPROMISC          1
#endif

#define IP6_FLOWINFO_TCLASS_MASK        0x0FF00000
#define IP6_FLOWINFO_TCLASS_SHIFT       20
#define IP6_FLOWINFO_FLOWLABEL_MASK     0x000FFFFF

/*****************************************************************************/

/* Appeared in in kernel prior to 3.13 dated 19 January, 2014 */
#ifndef ARPHRD_6LOWPAN
#define ARPHRD_6LOWPAN 825
#endif

/*****************************************************************************/

#define FRA_TUN_ID              12
#define FRA_SUPPRESS_IFGROUP    13
#define FRA_SUPPRESS_PREFIXLEN  14
#define FRA_PAD                 18
#define FRA_L3MDEV              19
#define FRA_UID_RANGE           20
#define FRA_PROTOCOL            21
#define FRA_IP_PROTO            22
#define FRA_SPORT_RANGE         23
#define FRA_DPORT_RANGE         24

/*****************************************************************************/

#define IFLA_MACSEC_UNSPEC              0
#define IFLA_MACSEC_SCI                 1
#define IFLA_MACSEC_PORT                2
#define IFLA_MACSEC_ICV_LEN             3
#define IFLA_MACSEC_CIPHER_SUITE        4
#define IFLA_MACSEC_WINDOW              5
#define IFLA_MACSEC_ENCODING_SA         6
#define IFLA_MACSEC_ENCRYPT             7
#define IFLA_MACSEC_PROTECT             8
#define IFLA_MACSEC_INC_SCI             9
#define IFLA_MACSEC_ES                  10
#define IFLA_MACSEC_SCB                 11
#define IFLA_MACSEC_REPLAY_PROTECT      12
#define IFLA_MACSEC_VALIDATION          13
#define IFLA_MACSEC_PAD                 14
#define __IFLA_MACSEC_MAX               15

/*****************************************************************************/

#define WG_CMD_GET_DEVICE 0
#define WG_CMD_SET_DEVICE 1

#define WGDEVICE_F_REPLACE_PEERS               ((guint32) (1U << 0))

#define WGPEER_F_REMOVE_ME                     ((guint32) (1U << 0))
#define WGPEER_F_REPLACE_ALLOWEDIPS            ((guint32) (1U << 1))


#define WGDEVICE_A_UNSPEC                      0
#define WGDEVICE_A_IFINDEX                     1
#define WGDEVICE_A_IFNAME                      2
#define WGDEVICE_A_PRIVATE_KEY                 3
#define WGDEVICE_A_PUBLIC_KEY                  4
#define WGDEVICE_A_FLAGS                       5
#define WGDEVICE_A_LISTEN_PORT                 6
#define WGDEVICE_A_FWMARK                      7
#define WGDEVICE_A_PEERS                       8
#define WGDEVICE_A_MAX                         8

#define WGPEER_A_UNSPEC                        0
#define WGPEER_A_PUBLIC_KEY                    1
#define WGPEER_A_PRESHARED_KEY                 2
#define WGPEER_A_FLAGS                         3
#define WGPEER_A_ENDPOINT                      4
#define WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL 5
#define WGPEER_A_LAST_HANDSHAKE_TIME           6
#define WGPEER_A_RX_BYTES                      7
#define WGPEER_A_TX_BYTES                      8
#define WGPEER_A_ALLOWEDIPS                    9
#define WGPEER_A_MAX                           9

#define WGALLOWEDIP_A_UNSPEC                   0
#define WGALLOWEDIP_A_FAMILY                   1
#define WGALLOWEDIP_A_IPADDR                   2
#define WGALLOWEDIP_A_CIDR_MASK                3
#define WGALLOWEDIP_A_MAX                      3

/*****************************************************************************/

/* Redefine VF enums and structures that are not available on older kernels. */

#define IFLA_VF_UNSPEC                 0
#define IFLA_VF_MAC                    1
#define IFLA_VF_VLAN                   2
#define IFLA_VF_TX_RATE                3
#define IFLA_VF_SPOOFCHK               4
#define IFLA_VF_LINK_STATE             5
#define IFLA_VF_RATE                   6
#define IFLA_VF_RSS_QUERY_EN           7
#define IFLA_VF_STATS                  8
#define IFLA_VF_TRUST                  9
#define IFLA_VF_IB_NODE_GUID           10
#define IFLA_VF_IB_PORT_GUID           11
#define IFLA_VF_VLAN_LIST              12

#define IFLA_VF_VLAN_INFO_UNSPEC       0
#define IFLA_VF_VLAN_INFO              1

/* valid for TRUST, SPOOFCHK, LINK_STATE, RSS_QUERY_EN */
struct _ifla_vf_setting {
	guint32 vf;
	guint32 setting;
};

struct _ifla_vf_rate {
	guint32 vf;
	guint32 min_tx_rate;
	guint32 max_tx_rate;
};

struct _ifla_vf_vlan_info {
	guint32 vf;
	guint32 vlan; /* 0 - 4095, 0 disables VLAN filter */
	guint32 qos;
	guint16 vlan_proto; /* VLAN protocol, either 802.1Q or 802.1ad */
};

/*****************************************************************************/

/* Appeared in in kernel 4.0 dated April 12, 2015 */
#ifndef BRIDGE_VLAN_INFO_RANGE_BEGIN
#define BRIDGE_VLAN_INFO_RANGE_BEGIN    (1 << 3) /* VLAN is start of vlan range */
#define BRIDGE_VLAN_INFO_RANGE_END      (1 << 4) /* VLAN is end of vlan range */
#endif

/*****************************************************************************/

typedef enum {
	INFINIBAND_ACTION_CREATE_CHILD,
	INFINIBAND_ACTION_DELETE_CHILD,
} InfinibandAction;

typedef enum {
	CHANGE_LINK_TYPE_UNSPEC,
	CHANGE_LINK_TYPE_SET_MTU,
	CHANGE_LINK_TYPE_SET_ADDRESS,
} ChangeLinkType;

typedef struct {
	union {
		struct {
			gconstpointer address;
			gsize length;
		} set_address;
	};
} ChangeLinkData;

typedef enum {
	_REFRESH_ALL_TYPE_FIRST            = 0,

	REFRESH_ALL_TYPE_LINKS             = 0,
	REFRESH_ALL_TYPE_IP4_ADDRESSES     = 1,
	REFRESH_ALL_TYPE_IP6_ADDRESSES     = 2,
	REFRESH_ALL_TYPE_IP4_ROUTES        = 3,
	REFRESH_ALL_TYPE_IP6_ROUTES        = 4,
	REFRESH_ALL_TYPE_ROUTING_RULES_IP4 = 5,
	REFRESH_ALL_TYPE_ROUTING_RULES_IP6 = 6,
	REFRESH_ALL_TYPE_QDISCS            = 7,
	REFRESH_ALL_TYPE_TFILTERS          = 8,

	_REFRESH_ALL_TYPE_NUM,
} RefreshAllType;

typedef struct {
	NMPObjectType obj_type;

	/* for NLM_F_DUMP, which address family to request. */
	int addr_family;
} RefreshAllInfo;

typedef enum {
	DELAYED_ACTION_TYPE_NONE                          = 0,

#define F(val, name) ((sizeof (char[(((val)) == (name)) ? 1 : -1]) * 0) + (val))
	DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS             = 1 << F (0, REFRESH_ALL_TYPE_LINKS),
	DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES     = 1 << F (1, REFRESH_ALL_TYPE_IP4_ADDRESSES),
	DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES     = 1 << F (2, REFRESH_ALL_TYPE_IP6_ADDRESSES),
	DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES        = 1 << F (3, REFRESH_ALL_TYPE_IP4_ROUTES),
	DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES        = 1 << F (4, REFRESH_ALL_TYPE_IP6_ROUTES),
	DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_IP4 = 1 << F (5, REFRESH_ALL_TYPE_ROUTING_RULES_IP4),
	DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_IP6 = 1 << F (6, REFRESH_ALL_TYPE_ROUTING_RULES_IP6),
	DELAYED_ACTION_TYPE_REFRESH_ALL_QDISCS            = 1 << F (7, REFRESH_ALL_TYPE_QDISCS),
	DELAYED_ACTION_TYPE_REFRESH_ALL_TFILTERS          = 1 << F (8, REFRESH_ALL_TYPE_TFILTERS),
#undef F

	DELAYED_ACTION_TYPE_REFRESH_LINK                  = 1 <<  9,
	DELAYED_ACTION_TYPE_MASTER_CONNECTED              = 1 << 10,
	DELAYED_ACTION_TYPE_READ_NETLINK                  = 1 << 11,
	DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE          = 1 << 12,

	__DELAYED_ACTION_TYPE_MAX,

	DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_ALL = DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_IP4 |
	                                                    DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_IP6,

	DELAYED_ACTION_TYPE_REFRESH_ALL                   = DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS |
	                                                    DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES |
	                                                    DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES |
	                                                    DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES |
	                                                    DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES |
	                                                    DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_ALL |
	                                                    DELAYED_ACTION_TYPE_REFRESH_ALL_QDISCS |
	                                                    DELAYED_ACTION_TYPE_REFRESH_ALL_TFILTERS,

	DELAYED_ACTION_TYPE_MAX                           = __DELAYED_ACTION_TYPE_MAX -1,
} DelayedActionType;

#define FOR_EACH_DELAYED_ACTION(iflags, flags_all) \
	for ((iflags) = (DelayedActionType) 0x1LL; \
	     ({ \
	         gboolean _good = FALSE; \
	         \
	         nm_assert (nm_utils_is_power_of_two (iflags)); \
	         \
	         while ((iflags) <= DELAYED_ACTION_TYPE_MAX) { \
	             if (NM_FLAGS_ANY ((flags_all), (iflags))) { \
	                 _good = TRUE; \
	                 break; \
	             } \
	             (iflags) <<= 1; \
	         } \
	         _good; \
	     }); \
	     (iflags) <<= 1)

typedef enum {
	/* Negative values are errors from kernel. Add dummy member to
	 * make enum signed. */
	_WAIT_FOR_NL_RESPONSE_RESULT_SYSTEM_ERROR = G_MININT,

	WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN = 0,
	WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK,
	WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_UNKNOWN,
	WAIT_FOR_NL_RESPONSE_RESULT_FAILED_RESYNC,
	WAIT_FOR_NL_RESPONSE_RESULT_FAILED_POLL,
	WAIT_FOR_NL_RESPONSE_RESULT_FAILED_TIMEOUT,
	WAIT_FOR_NL_RESPONSE_RESULT_FAILED_DISPOSING,
	WAIT_FOR_NL_RESPONSE_RESULT_FAILED_SETNS,
} WaitForNlResponseResult;

typedef enum {
	DELAYED_ACTION_RESPONSE_TYPE_VOID                       = 0,
	DELAYED_ACTION_RESPONSE_TYPE_REFRESH_ALL_IN_PROGRESS    = 1,
	DELAYED_ACTION_RESPONSE_TYPE_ROUTE_GET                  = 2,
} DelayedActionWaitForNlResponseType;

typedef struct {
	guint32 seq_number;
	WaitForNlResponseResult seq_result;
	DelayedActionWaitForNlResponseType response_type;
	gint64 timeout_abs_ns;
	WaitForNlResponseResult *out_seq_result;
	char **out_errmsg;
	union {
		int *out_refresh_all_in_progress;
		NMPObject **out_route_get;
		gpointer out_data;
	} response;
} DelayedActionWaitForNlResponseData;

/*****************************************************************************/

typedef struct {
	struct nl_sock *genl;

	struct nl_sock *nlh;

	GSource *event_source;

	guint32 nlh_seq_next;
#if NM_MORE_LOGGING
	guint32 nlh_seq_last_handled;
#endif
	guint32 nlh_seq_last_seen;

	guint32 pruning[_REFRESH_ALL_TYPE_NUM];

	GHashTable *sysctl_get_prev_values;
	CList sysctl_list;

	NMUdevClient *udev_client;

	struct {
		/* which delayed actions are scheduled, as marked in @flags.
		 * Some types have additional arguments in the fields below. */
		DelayedActionType flags;

		/* counter that a refresh all action is in progress, separated
		 * by type. */
		int refresh_all_in_progress[_REFRESH_ALL_TYPE_NUM];

		GPtrArray *list_master_connected;
		GPtrArray *list_refresh_link;
		GArray *list_wait_for_nl_response;

		int is_handling;
	} delayed_action;
} NMLinuxPlatformPrivate;

struct _NMLinuxPlatform {
	NMPlatform parent;
	NMLinuxPlatformPrivate _priv;
};

struct _NMLinuxPlatformClass {
	NMPlatformClass parent;
};

G_DEFINE_TYPE (NMLinuxPlatform, nm_linux_platform, NM_TYPE_PLATFORM)

#define NM_LINUX_PLATFORM_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMLinuxPlatform, NM_IS_LINUX_PLATFORM, NMPlatform)

/*****************************************************************************/

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
        NMPlatform *const __self = (self); \
        \
        if (__self && nm_platform_get_log_with_ptr (__self)) { \
            g_snprintf (__prefix, sizeof (__prefix), "%s[%p]", _NMLOG_PREFIX_NAME, __self); \
            __p_prefix = __prefix; \
        } \
        _nm_log (__level, __domain, __errsv, NULL, NULL, \
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
            /* The %m format specifier (GNU extension) would already allow you to specify the error
             * message conveniently (and nm_log would get that right too). But we don't want to depend
             * on that, so instead append the message at the end.
             * Currently users are expected not to use %m in the format string. */ \
            _LOG_print (__level, __domain, __errsv, self, \
                        _NM_UTILS_MACRO_FIRST (__VA_ARGS__) ": %s (%d)" \
                        _NM_UTILS_MACRO_REST (__VA_ARGS__), \
                        nm_strerror_native (__errsv), __errsv); \
        } \
    } G_STMT_END

/*****************************************************************************/

static void delayed_action_schedule (NMPlatform *platform, DelayedActionType action_type, gpointer user_data);
static gboolean delayed_action_handle_all (NMPlatform *platform, gboolean read_netlink);
static void do_request_link_no_delayed_actions (NMPlatform *platform, int ifindex, const char *name);
static void do_request_all_no_delayed_actions (NMPlatform *platform, DelayedActionType action_type);
static void cache_on_change (NMPlatform *platform,
                             NMPCacheOpsType cache_op,
                             const NMPObject *obj_old,
                             const NMPObject *obj_new);
static void cache_prune_all (NMPlatform *platform);
static gboolean event_handler_read_netlink (NMPlatform *platform, gboolean wait_for_acks);
static struct nl_sock *_genl_sock (NMLinuxPlatform *platform);

/*****************************************************************************/

static int
wait_for_nl_response_to_nmerr (WaitForNlResponseResult seq_result)
{
	if (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK)
		return 0;
	if (seq_result < 0)
		return (int) seq_result;
	return -NME_PL_NETLINK;
}

static const char *
wait_for_nl_response_to_string (WaitForNlResponseResult seq_result,
                                const char *errmsg,
                                char *buf, gsize buf_size)
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
		if (seq_result < 0) {
			nm_utils_strbuf_append (&buf, &buf_size, "failure %d (%s%s%s)",
			                        -((int) seq_result),
			                        nm_strerror_native (-((int) seq_result)),
			                        errmsg ? " - " : "",
			                        errmsg ?: "");
		}
		else
			nm_utils_strbuf_append (&buf, &buf_size, "internal failure %d", (int) seq_result);
		break;
	}
	return buf0;
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
	{ NM_LINK_TYPE_WWAN_NET,      "wwan",        NULL,          "wwan" },
	{ NM_LINK_TYPE_WIMAX,         "wimax",       "wimax",       "wimax" },
	{ NM_LINK_TYPE_WPAN,          "wpan",        NULL,          NULL },
	{ NM_LINK_TYPE_6LOWPAN,       "6lowpan",     NULL,          NULL },

	{ NM_LINK_TYPE_BNEP,          "bluetooth",   NULL,          "bluetooth" },
	{ NM_LINK_TYPE_DUMMY,         "dummy",       "dummy",       NULL },
	{ NM_LINK_TYPE_GRE,           "gre",         "gre",         NULL },
	{ NM_LINK_TYPE_GRETAP,        "gretap",      "gretap",      NULL },
	{ NM_LINK_TYPE_IFB,           "ifb",         "ifb",         NULL },
	{ NM_LINK_TYPE_IP6TNL,        "ip6tnl",      "ip6tnl",      NULL },
	{ NM_LINK_TYPE_IP6GRE,        "ip6gre",      "ip6gre",      NULL },
	{ NM_LINK_TYPE_IP6GRETAP,     "ip6gretap",   "ip6gretap",   NULL },
	{ NM_LINK_TYPE_IPIP,          "ipip",        "ipip",        NULL },
	{ NM_LINK_TYPE_LOOPBACK,      "loopback",    NULL,          NULL },
	{ NM_LINK_TYPE_MACSEC,        "macsec",      "macsec",      NULL },
	{ NM_LINK_TYPE_MACVLAN,       "macvlan",     "macvlan",     NULL },
	{ NM_LINK_TYPE_MACVTAP,       "macvtap",     "macvtap",     NULL },
	{ NM_LINK_TYPE_OPENVSWITCH,   "openvswitch", "openvswitch", NULL },
	{ NM_LINK_TYPE_PPP,           "ppp",         NULL,          "ppp" },
	{ NM_LINK_TYPE_SIT,           "sit",         "sit",         NULL },
	{ NM_LINK_TYPE_TUN,           "tun",         "tun",         NULL },
	{ NM_LINK_TYPE_VETH,          "veth",        "veth",        NULL },
	{ NM_LINK_TYPE_VLAN,          "vlan",        "vlan",        "vlan" },
	{ NM_LINK_TYPE_VRF,           "vrf",         "vrf",         "vrf" },
	{ NM_LINK_TYPE_VXLAN,         "vxlan",       "vxlan",       "vxlan" },
	{ NM_LINK_TYPE_WIREGUARD,     "wireguard",   "wireguard",   "wireguard" },

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
	gint64 now_nl;
	gint64 now_nm;
	gint64 result;

	/* timestamp is unset. Default to 1. */
	if (!timestamp) {
		NM_SET_OUT (out_now_nm, 0);
		return 1;
	}

	/* do all the calculations in milliseconds scale */

	now_nm = nm_utils_get_monotonic_timestamp_msec ();
	now_nl = nm_utils_clock_gettime_ms (CLOCK_MONOTONIC);

	nm_assert (now_nm >= 1000);
	nm_assert (now_nl >= 0);

	result = now_nm - (now_nl - _timestamp_nl_to_ms (timestamp, now_nl));

	NM_SET_OUT (out_now_nm, now_nm / 1000);

	/* converting the timestamp into nm_utils_get_monotonic_timestamp_msec() scale is
	 * a good guess but fails in the following situations:
	 *
	 * - If the address existed before start of the process, the timestamp in nm scale would
	 *   be negative or zero. In this case we default to 1.
	 * - during hibernation, the CLOCK_MONOTONIC/timestamp drifts from
	 *   nm_utils_get_monotonic_timestamp_msec() scale.
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
			now = nm_utils_get_monotonic_timestamp_sec ();
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

/*****************************************************************************/

static const NMPObject *
_lookup_cached_link (const NMPCache *cache,
                     int ifindex,
                     gboolean *completed_from_cache,
                     const NMPObject **link_cached)
{
	const NMPObject *obj;

	nm_assert (completed_from_cache && link_cached);

	if (!*completed_from_cache) {
		obj = ifindex > 0 && cache
		      ? nmp_cache_lookup_link (cache, ifindex)
		      : NULL;

		*link_cached = obj;
		*completed_from_cache = TRUE;
	}
	return *link_cached;
}

/*****************************************************************************/

#define DEVTYPE_PREFIX "DEVTYPE="

static char *
_linktype_read_devtype (int dirfd)
{
	gs_free char *contents = NULL;
	char *cont, *end;

	nm_assert (dirfd >= 0);

	if (!nm_utils_file_get_contents (dirfd,
	                                 "uevent",
	                                 1*1024*1024,
	                                 NM_UTILS_FILE_GET_CONTENTS_FLAG_NONE,
	                                 &contents,
	                                 NULL,
	                                 NULL,
	                                 NULL))
		return NULL;
	for (cont = contents; cont; cont = end) {
		end = strpbrk (cont, "\r\n");
		if (end)
			*end++ = '\0';
		if (strncmp (cont, DEVTYPE_PREFIX, NM_STRLEN (DEVTYPE_PREFIX)) == 0) {
			cont += NM_STRLEN (DEVTYPE_PREFIX);
			memmove (contents, cont, strlen (cont) + 1);
			return g_steal_pointer (&contents);
		}
	}
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

	NMTST_ASSERT_PLATFORM_NETNS_CURRENT (platform);
	nm_assert (ifname);

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
		    && obj->_link.netlink.is_in_netlink
		    && !NM_IN_SET (obj->link.type, NM_LINK_TYPE_UNKNOWN, NM_LINK_TYPE_NONE)
		    && nm_streq (ifname, obj->link.name)
		    && (   !kind
		        || nm_streq0 (kind, obj->link.kind))) {
			nm_assert (obj->link.kind == g_intern_string (obj->link.kind));
			*out_kind = obj->link.kind;
			return obj->link.type;
		}
	}

	/* we intern kind to not require us to keep the pointer alive. Essentially
	 * leaking it in a global cache. That should be safe enough, because the
	 * kind comes only from kernel messages, which depend on the number of
	 * available drivers. So, there is not the danger that we leak uncontrolled
	 * many kinds. */
	*out_kind = g_intern_string (kind);

	if (kind) {
		for (i = 0; i < G_N_ELEMENTS (linktypes); i++) {
			if (nm_streq0 (kind, linktypes[i].rtnl_type)) {
				return linktypes[i].nm_type;
			}
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
	else if (arptype == ARPHRD_PPP)
		return NM_LINK_TYPE_PPP;
	else if (arptype == ARPHRD_IEEE802154)
		return NM_LINK_TYPE_WPAN;
	else if (arptype == ARPHRD_6LOWPAN)
		return NM_LINK_TYPE_6LOWPAN;

	{
		NMPUtilsEthtoolDriverInfo driver_info;

		/* Fallback OVS detection for kernel <= 3.16 */
		if (nmp_utils_ethtool_get_driver_info (ifindex, &driver_info)) {
			if (nm_streq (driver_info.driver, "openvswitch"))
				return NM_LINK_TYPE_OPENVSWITCH;

			if (arptype == 256) {
				/* Some s390 CTC-type devices report 256 for the encapsulation type
				 * for some reason, but we need to call them Ethernet.
				 */
				if (nm_streq (driver_info.driver, "ctcm"))
					return NM_LINK_TYPE_ETHERNET;
			}
		}
	}

	{
		nm_auto_close int dirfd = -1;
		gs_free char *devtype = NULL;
		char ifname_verified[IFNAMSIZ];

		dirfd = nmp_utils_sysctl_open_netdir (ifindex, ifname, ifname_verified);
		if (dirfd >= 0) {
			if (faccessat (dirfd, "anycast_mask", F_OK, 0) == 0)
				return NM_LINK_TYPE_OLPC_MESH;

			devtype = _linktype_read_devtype (dirfd);
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
			if (nm_wifi_utils_is_wifi (dirfd, ifname_verified))
				return NM_LINK_TYPE_WIFI;
		}

		if (arptype == ARPHRD_ETHER) {
			/* Misc non-upstream WWAN drivers.  rmnet is Qualcomm's proprietary
			 * modem interface, ccmni is MediaTek's.  FIXME: these drivers should
			 * really set devtype=WWAN.
			 */
			if (g_str_has_prefix (ifname, "rmnet") ||
			    g_str_has_prefix (ifname, "rev_rmnet") ||
			    g_str_has_prefix (ifname, "ccmni"))
				return NM_LINK_TYPE_WWAN_NET;

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

			/* Distributed Switch Architecture switch chips */
			if (!g_strcmp0 (devtype, "dsa"))
				return NM_LINK_TYPE_ETHERNET;
		}
	}

	return NM_LINK_TYPE_UNKNOWN;
}

/******************************************************************
 * libnl unility functions and wrappers
 ******************************************************************/

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((char *) (nmsg)) + NLMSG_ALIGN ((nmsg)->nlmsg_len)))

/* copied from iproute2's addattr_l(). */
static gboolean
_nl_addattr_l (struct nlmsghdr *n,
               int maxlen,
               int type,
               const void *data,
               int alen)
{
	int len = RTA_LENGTH (alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len) > maxlen)
		return FALSE;

	rta = NLMSG_TAIL (n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy (RTA_DATA (rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len);
	return TRUE;
}

/******************************************************************
 * NMPObject/netlink functions
 ******************************************************************/

#define _check_addr_or_return_val(tb, attr, addr_len, ret_val) \
	({ \
	    const struct nlattr *__t = (tb)[(attr)]; \
		\
	    if (__t) { \
			if (nla_len (__t) != (addr_len)) { \
				return ret_val; \
			} \
		} \
		!!__t; \
	})

#define _check_addr_or_return_null(tb, attr, addr_len) \
	_check_addr_or_return_val (tb, attr, addr_len, NULL)

/*****************************************************************************/

/* Copied and heavily modified from libnl3's inet6_parse_protinfo(). */
static gboolean
_parse_af_inet6 (NMPlatform *platform,
                 struct nlattr *attr,
                 NMUtilsIPv6IfaceId *out_token,
                 gboolean *out_token_valid,
                 guint8 *out_addr_gen_mode_inv,
                 gboolean *out_addr_gen_mode_valid)
{
	static const struct nla_policy policy[] = {
		[IFLA_INET6_FLAGS]              = { .type = NLA_U32 },
		[IFLA_INET6_CACHEINFO]          = { .minlen = nm_offsetofend (struct ifla_cacheinfo, retrans_time) },
		[IFLA_INET6_CONF]               = { .minlen = 4 },
		[IFLA_INET6_STATS]              = { .minlen = 8 },
		[IFLA_INET6_ICMP6STATS]         = { .minlen = 8 },
		[IFLA_INET6_TOKEN]              = { .minlen = sizeof (struct in6_addr) },
		[IFLA_INET6_ADDR_GEN_MODE]      = { .type = NLA_U8 },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	struct in6_addr i6_token;
	gboolean token_valid = FALSE;
	gboolean addr_gen_mode_valid = FALSE;
	guint8 i6_addr_gen_mode_inv = 0;

	if (nla_parse_nested_arr (tb, attr, policy) < 0)
		return FALSE;

	if (tb[IFLA_INET6_CONF] && nla_len (tb[IFLA_INET6_CONF]) % 4)
		return FALSE;
	if (tb[IFLA_INET6_STATS] && nla_len (tb[IFLA_INET6_STATS]) % 8)
		return FALSE;
	if (tb[IFLA_INET6_ICMP6STATS] && nla_len (tb[IFLA_INET6_ICMP6STATS]) % 8)
		return FALSE;

	if (_check_addr_or_return_val (tb, IFLA_INET6_TOKEN, sizeof (struct in6_addr), FALSE)) {
		nla_memcpy (&i6_token, tb[IFLA_INET6_TOKEN], sizeof (struct in6_addr));
		token_valid = TRUE;
	}

	/* Hack to detect support addrgenmode of the kernel. We only parse
	 * netlink messages that we receive from kernel, hence this check
	 * is valid. */
	if (!_nm_platform_kernel_support_detected (NM_PLATFORM_KERNEL_SUPPORT_TYPE_USER_IPV6LL)) {
		/* IFLA_INET6_ADDR_GEN_MODE was added in kernel 3.17, dated 5 October, 2014. */
		_nm_platform_kernel_support_init (NM_PLATFORM_KERNEL_SUPPORT_TYPE_USER_IPV6LL,
		                                  tb[IFLA_INET6_ADDR_GEN_MODE] ? 1 : -1);
	}

	if (tb[IFLA_INET6_ADDR_GEN_MODE]) {
		i6_addr_gen_mode_inv = _nm_platform_uint8_inv (nla_get_u8 (tb[IFLA_INET6_ADDR_GEN_MODE]));
		if (i6_addr_gen_mode_inv == 0) {
			/* an inverse addrgenmode of zero is unexpected. We need to reserve zero
			 * to signal "unset". */
			return FALSE;
		}
		addr_gen_mode_valid = TRUE;
	}

	if (token_valid) {
		*out_token_valid = token_valid;
		nm_utils_ipv6_interface_identifier_get_from_addr (out_token, &i6_token);
	}
	if (addr_gen_mode_valid) {
		*out_addr_gen_mode_valid = addr_gen_mode_valid;
		*out_addr_gen_mode_inv = i6_addr_gen_mode_inv;
	}
	return TRUE;
}

/*****************************************************************************/

static NMPObject *
_parse_lnk_gre (const char *kind, struct nlattr *info_data)
{
	static const struct nla_policy policy[] = {
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
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	NMPObject *obj;
	NMPlatformLnkGre *props;
	gboolean is_tap;

	if (   !info_data
	    || !kind)
		return NULL;

	if (nm_streq (kind, "gretap"))
		is_tap = TRUE;
	else if (nm_streq (kind, "gre"))
		is_tap = FALSE;
	else
		return NULL;

	if (nla_parse_nested_arr (tb, info_data, policy) < 0)
		return NULL;

	obj = nmp_object_new (is_tap ? NMP_OBJECT_TYPE_LNK_GRETAP : NMP_OBJECT_TYPE_LNK_GRE, NULL);
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
	props->is_tap = is_tap;

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
	static const struct nla_policy policy[] = {
		[IFLA_IPOIB_PKEY]   = { .type = NLA_U16 },
		[IFLA_IPOIB_MODE]   = { .type = NLA_U16 },
		[IFLA_IPOIB_UMCAST] = { .type = NLA_U16 },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	NMPlatformLnkInfiniband *info;
	NMPObject *obj;
	const char *mode;

	if (   !info_data
	    || !nm_streq0 (kind, "ipoib"))
		return NULL;

	if (nla_parse_nested_arr (tb, info_data, policy) < 0)
		return NULL;

	if (   !tb[IFLA_IPOIB_PKEY]
	    || !tb[IFLA_IPOIB_MODE])
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
	static const struct nla_policy policy[] = {
		[IFLA_IPTUN_LINK]        = { .type = NLA_U32 },
		[IFLA_IPTUN_LOCAL]       = { .minlen = sizeof (struct in6_addr)},
		[IFLA_IPTUN_REMOTE]      = { .minlen = sizeof (struct in6_addr)},
		[IFLA_IPTUN_TTL]         = { .type = NLA_U8 },
		[IFLA_IPTUN_ENCAP_LIMIT] = { .type = NLA_U8 },
		[IFLA_IPTUN_FLOWINFO]    = { .type = NLA_U32 },
		[IFLA_IPTUN_PROTO]       = { .type = NLA_U8 },
		[IFLA_IPTUN_FLAGS]       = { .type = NLA_U32 },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	NMPObject *obj;
	NMPlatformLnkIp6Tnl *props;
	guint32 flowinfo;

	if (   !info_data
	    || !nm_streq0 (kind, "ip6tnl"))
		return NULL;

	if (nla_parse_nested_arr (tb, info_data, policy) < 0)
		return NULL;

	obj = nmp_object_new (NMP_OBJECT_TYPE_LNK_IP6TNL, NULL);
	props = &obj->lnk_ip6tnl;

	if (tb[IFLA_IPTUN_LINK])
		props->parent_ifindex = nla_get_u32 (tb[IFLA_IPTUN_LINK]);
	if (tb[IFLA_IPTUN_LOCAL])
		props->local = *nla_data_as (struct in6_addr, tb[IFLA_IPTUN_LOCAL]);
	if (tb[IFLA_IPTUN_REMOTE])
		props->remote = *nla_data_as (struct in6_addr, tb[IFLA_IPTUN_REMOTE]);
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
	if (tb[IFLA_IPTUN_FLAGS])
		props->flags = nla_get_u32 (tb[IFLA_IPTUN_FLAGS]);

	return obj;
}

static NMPObject *
_parse_lnk_ip6gre (const char *kind, struct nlattr *info_data)
{
	static const struct nla_policy policy[] = {
		[IFLA_GRE_LINK]        = { .type = NLA_U32 },
		[IFLA_GRE_IFLAGS]      = { .type = NLA_U16 },
		[IFLA_GRE_OFLAGS]      = { .type = NLA_U16 },
		[IFLA_GRE_IKEY]        = { .type = NLA_U32 },
		[IFLA_GRE_OKEY]        = { .type = NLA_U32 },
		[IFLA_GRE_LOCAL]       = { .type = NLA_UNSPEC,
		                           .minlen = sizeof (struct in6_addr)},
		[IFLA_GRE_REMOTE]      = { .type = NLA_UNSPEC,
		                           .minlen = sizeof (struct in6_addr)},
		[IFLA_GRE_TTL]         = { .type = NLA_U8 },
		[IFLA_GRE_ENCAP_LIMIT] = { .type = NLA_U8 },
		[IFLA_GRE_FLOWINFO]    = { .type = NLA_U32 },
		[IFLA_GRE_FLAGS]       = { .type = NLA_U32 },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	NMPObject *obj;
	NMPlatformLnkIp6Tnl *props;
	guint32 flowinfo;
	gboolean is_tap;

	if (!info_data || !kind)
		return NULL;

	if (nm_streq (kind, "ip6gre"))
		is_tap = FALSE;
	else if (nm_streq (kind, "ip6gretap"))
		is_tap = TRUE;
	else
		return NULL;

	if (nla_parse_nested_arr (tb, info_data, policy) < 0)
		return NULL;

	obj = nmp_object_new (is_tap ? NMP_OBJECT_TYPE_LNK_IP6GRETAP : NMP_OBJECT_TYPE_LNK_IP6GRE, NULL);
	props = &obj->lnk_ip6tnl;
	props->is_gre = TRUE;
	props->is_tap = is_tap;

	if (tb[IFLA_GRE_LINK])
		props->parent_ifindex = nla_get_u32 (tb[IFLA_GRE_LINK]);
	if (tb[IFLA_GRE_IFLAGS])
		props->input_flags = ntohs (nla_get_u16 (tb[IFLA_GRE_IFLAGS]));
	if (tb[IFLA_GRE_OFLAGS])
		props->output_flags = ntohs (nla_get_u16 (tb[IFLA_GRE_OFLAGS]));
	if (tb[IFLA_GRE_IKEY])
		props->input_key = ntohl (nla_get_u32 (tb[IFLA_GRE_IKEY]));
	if (tb[IFLA_GRE_OKEY])
		props->output_key = ntohl (nla_get_u32 (tb[IFLA_GRE_OKEY]));
	if (tb[IFLA_GRE_LOCAL])
		props->local = *nla_data_as (struct in6_addr, tb[IFLA_GRE_LOCAL]);
	if (tb[IFLA_GRE_REMOTE])
		props->remote = *nla_data_as (struct in6_addr, tb[IFLA_GRE_REMOTE]);
	if (tb[IFLA_GRE_TTL])
		props->ttl = nla_get_u8 (tb[IFLA_GRE_TTL]);
	if (tb[IFLA_GRE_ENCAP_LIMIT])
		props->encap_limit = nla_get_u8 (tb[IFLA_GRE_ENCAP_LIMIT]);
	if (tb[IFLA_GRE_FLOWINFO]) {
		flowinfo = ntohl (nla_get_u32 (tb[IFLA_GRE_FLOWINFO]));
		props->flow_label = flowinfo & IP6_FLOWINFO_FLOWLABEL_MASK;
		props->tclass = (flowinfo & IP6_FLOWINFO_TCLASS_MASK) >> IP6_FLOWINFO_TCLASS_SHIFT;
	}
	if (tb[IFLA_GRE_FLAGS])
		props->flags = nla_get_u32 (tb[IFLA_GRE_FLAGS]);

	return obj;
}

/*****************************************************************************/

static NMPObject *
_parse_lnk_ipip (const char *kind, struct nlattr *info_data)
{
	static const struct nla_policy policy[] = {
		[IFLA_IPTUN_LINK]     = { .type = NLA_U32 },
		[IFLA_IPTUN_LOCAL]    = { .type = NLA_U32 },
		[IFLA_IPTUN_REMOTE]   = { .type = NLA_U32 },
		[IFLA_IPTUN_TTL]      = { .type = NLA_U8 },
		[IFLA_IPTUN_TOS]      = { .type = NLA_U8 },
		[IFLA_IPTUN_PMTUDISC] = { .type = NLA_U8 },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	NMPObject *obj;
	NMPlatformLnkIpIp *props;

	if (   !info_data
	    || !nm_streq0 (kind, "ipip"))
		return NULL;

	if (nla_parse_nested_arr (tb, info_data, policy) < 0)
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
	static const struct nla_policy policy[] = {
		[IFLA_MACVLAN_MODE]  = { .type = NLA_U32 },
		[IFLA_MACVLAN_FLAGS] = { .type = NLA_U16 },
	};
	NMPlatformLnkMacvlan *props;
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	NMPObject *obj;
	gboolean tap;

	if (   !info_data
	    || !kind)
		return NULL;

	if (nm_streq (kind, "macvlan"))
		tap = FALSE;
	else if (nm_streq (kind, "macvtap"))
		tap = TRUE;
	else
		return NULL;

	if (nla_parse_nested_arr (tb, info_data, policy) < 0)
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
_parse_lnk_macsec (const char *kind, struct nlattr *info_data)
{
	static const struct nla_policy policy[] = {
		[IFLA_MACSEC_SCI]            = { .type = NLA_U64 },
		[IFLA_MACSEC_ICV_LEN]        = { .type = NLA_U8 },
		[IFLA_MACSEC_CIPHER_SUITE]   = { .type = NLA_U64 },
		[IFLA_MACSEC_WINDOW]         = { .type = NLA_U32 },
		[IFLA_MACSEC_ENCODING_SA]    = { .type = NLA_U8 },
		[IFLA_MACSEC_ENCRYPT]        = { .type = NLA_U8 },
		[IFLA_MACSEC_PROTECT]        = { .type = NLA_U8 },
		[IFLA_MACSEC_INC_SCI]        = { .type = NLA_U8 },
		[IFLA_MACSEC_ES]             = { .type = NLA_U8 },
		[IFLA_MACSEC_SCB]            = { .type = NLA_U8 },
		[IFLA_MACSEC_REPLAY_PROTECT] = { .type = NLA_U8 },
		[IFLA_MACSEC_VALIDATION]     = { .type = NLA_U8 },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	NMPObject *obj;
	NMPlatformLnkMacsec *props;

	if (   !info_data
	    || !nm_streq0 (kind, "macsec"))
		return NULL;

	if (nla_parse_nested_arr (tb, info_data, policy) < 0)
		return NULL;

	obj = nmp_object_new (NMP_OBJECT_TYPE_LNK_MACSEC, NULL);
	props = &obj->lnk_macsec;

	if (tb[IFLA_MACSEC_SCI])            { props->sci            =   nla_get_be64 (tb[IFLA_MACSEC_SCI]);            }
	if (tb[IFLA_MACSEC_ICV_LEN])        { props->icv_length     =   nla_get_u8   (tb[IFLA_MACSEC_ICV_LEN]);        }
	if (tb[IFLA_MACSEC_CIPHER_SUITE])   { props->cipher_suite   =   nla_get_u64  (tb[IFLA_MACSEC_CIPHER_SUITE]);   }
	if (tb[IFLA_MACSEC_WINDOW])         { props->window         =   nla_get_u32  (tb[IFLA_MACSEC_WINDOW]);         }
	if (tb[IFLA_MACSEC_ENCODING_SA])    { props->encoding_sa    = !!nla_get_u8   (tb[IFLA_MACSEC_ENCODING_SA]);    }
	if (tb[IFLA_MACSEC_ENCRYPT])        { props->encrypt        = !!nla_get_u8   (tb[IFLA_MACSEC_ENCRYPT]);        }
	if (tb[IFLA_MACSEC_PROTECT])        { props->protect        = !!nla_get_u8   (tb[IFLA_MACSEC_PROTECT]);        }
	if (tb[IFLA_MACSEC_INC_SCI])        { props->include_sci    = !!nla_get_u8   (tb[IFLA_MACSEC_INC_SCI]);        }
	if (tb[IFLA_MACSEC_ES])             { props->es             = !!nla_get_u8   (tb[IFLA_MACSEC_ES]);             }
	if (tb[IFLA_MACSEC_SCB])            { props->scb            = !!nla_get_u8   (tb[IFLA_MACSEC_SCB]);            }
	if (tb[IFLA_MACSEC_REPLAY_PROTECT]) { props->replay_protect = !!nla_get_u8   (tb[IFLA_MACSEC_REPLAY_PROTECT]); }
	if (tb[IFLA_MACSEC_VALIDATION])     { props->validation     =   nla_get_u8   (tb[IFLA_MACSEC_VALIDATION]);     }

	return obj;
}

/*****************************************************************************/

static NMPObject *
_parse_lnk_sit (const char *kind, struct nlattr *info_data)
{
	static const struct nla_policy policy[] = {
		[IFLA_IPTUN_LINK]     = { .type = NLA_U32 },
		[IFLA_IPTUN_LOCAL]    = { .type = NLA_U32 },
		[IFLA_IPTUN_REMOTE]   = { .type = NLA_U32 },
		[IFLA_IPTUN_TTL]      = { .type = NLA_U8 },
		[IFLA_IPTUN_TOS]      = { .type = NLA_U8 },
		[IFLA_IPTUN_PMTUDISC] = { .type = NLA_U8 },
		[IFLA_IPTUN_FLAGS]    = { .type = NLA_U16 },
		[IFLA_IPTUN_PROTO]    = { .type = NLA_U8 },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	NMPObject *obj;
	NMPlatformLnkSit *props;

	if (   !info_data
	    || !nm_streq0 (kind, "sit"))
		return NULL;

	if (nla_parse_nested_arr (tb, info_data, policy) < 0)
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

static NMPObject *
_parse_lnk_tun (const char *kind, struct nlattr *info_data)
{
	static const struct nla_policy policy[] = {
		[IFLA_TUN_OWNER]               = { .type = NLA_U32 },
		[IFLA_TUN_GROUP]               = { .type = NLA_U32 },
		[IFLA_TUN_TYPE]                = { .type = NLA_U8 },
		[IFLA_TUN_PI]                  = { .type = NLA_U8 },
		[IFLA_TUN_VNET_HDR]            = { .type = NLA_U8 },
		[IFLA_TUN_PERSIST]             = { .type = NLA_U8 },
		[IFLA_TUN_MULTI_QUEUE]         = { .type = NLA_U8 },
		[IFLA_TUN_NUM_QUEUES]          = { .type = NLA_U32 },
		[IFLA_TUN_NUM_DISABLED_QUEUES] = { .type = NLA_U32 },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	NMPObject *obj;
	NMPlatformLnkTun *props;

	if (   !info_data
	    || !nm_streq0 (kind, "tun"))
		return NULL;

	if (nla_parse_nested_arr (tb, info_data, policy) < 0)
		return NULL;

	if (!tb[IFLA_TUN_TYPE])
		return NULL;

	obj = nmp_object_new (NMP_OBJECT_TYPE_LNK_TUN, NULL);
	props = &obj->lnk_tun;

	props->type = nla_get_u8 (tb[IFLA_TUN_TYPE]);

	props->pi = !!nla_get_u8_cond (tb, IFLA_TUN_PI, FALSE);
	props->vnet_hdr = !!nla_get_u8_cond (tb, IFLA_TUN_VNET_HDR, FALSE);
	props->multi_queue = !!nla_get_u8_cond (tb, IFLA_TUN_MULTI_QUEUE, FALSE);
	props->persist = !!nla_get_u8_cond (tb, IFLA_TUN_PERSIST, FALSE);

	if (tb[IFLA_TUN_OWNER]) {
		props->owner_valid = TRUE;
		props->owner = nla_get_u32 (tb[IFLA_TUN_OWNER]);
	}
	if (tb[IFLA_TUN_GROUP]) {
		props->group_valid = TRUE;
		props->group = nla_get_u32 (tb[IFLA_TUN_GROUP]);
	}
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
		if (nla_len (nla) < sizeof (NMVlanQosMapping))
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
	static const struct nla_policy policy[] = {
		[IFLA_VLAN_ID]          = { .type = NLA_U16 },
		[IFLA_VLAN_FLAGS]       = { .minlen = nm_offsetofend (struct ifla_vlan_flags, flags) },
		[IFLA_VLAN_INGRESS_QOS] = { .type = NLA_NESTED },
		[IFLA_VLAN_EGRESS_QOS]  = { .type = NLA_NESTED },
		[IFLA_VLAN_PROTOCOL]    = { .type = NLA_U16 },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	nm_auto_nmpobj NMPObject *obj = NULL;
	NMPObject *obj_result;

	if (   !info_data
	    || !nm_streq0 (kind, "vlan"))
		return NULL;

	if (nla_parse_nested_arr (tb, info_data, policy) < 0)
		return NULL;

	if (!tb[IFLA_VLAN_ID])
		return NULL;

	obj = nmp_object_new (NMP_OBJECT_TYPE_LNK_VLAN, NULL);
	obj->lnk_vlan.id = nla_get_u16 (tb[IFLA_VLAN_ID]);

	if (tb[IFLA_VLAN_FLAGS]) {
		struct ifla_vlan_flags flags;

		nla_memcpy (&flags, tb[IFLA_VLAN_FLAGS], sizeof (flags));

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

#define IFLA_VRF_TABLE        1

/* older kernel header might not contain 'struct ifla_vxlan_port_range'.
 * Redefine it. */
struct nm_ifla_vxlan_port_range {
	guint16 low;
	guint16 high;
};

static NMPObject *
_parse_lnk_vxlan (const char *kind, struct nlattr *info_data)
{
	static const struct nla_policy policy[] = {
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
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	NMPObject *obj;

	if (   !info_data
	    || !nm_streq0 (kind, "vxlan"))
		return NULL;

	if (nla_parse_nested_arr (tb, info_data, policy) < 0)
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
	if (tb[IFLA_VXLAN_LOCAL6])
		props->local6 = *nla_data_as (struct in6_addr, tb[IFLA_VXLAN_LOCAL6]);
	if (tb[IFLA_VXLAN_GROUP6])
		props->group6 = *nla_data_as (struct in6_addr, tb[IFLA_VXLAN_GROUP6]);

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
		struct nm_ifla_vxlan_port_range *range;

		range = nla_data_as (struct nm_ifla_vxlan_port_range, tb[IFLA_VXLAN_PORT_RANGE]);
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

static NMPObject *
_parse_lnk_vrf (const char *kind, struct nlattr *info_data)
{
	static const struct nla_policy policy[] = {
		[IFLA_VRF_TABLE]         = { .type = NLA_U32 },
	};
	NMPlatformLnkVrf *props;
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	NMPObject *obj;

	if (   !info_data
	    || !nm_streq0 (kind, "vrf"))
		return NULL;

	if (nla_parse_nested_arr (tb, info_data, policy) < 0)
		return NULL;

	obj = nmp_object_new (NMP_OBJECT_TYPE_LNK_VRF, NULL);

	props = &obj->lnk_vrf;

	if (tb[IFLA_VRF_TABLE])
		props->table = nla_get_u32 (tb[IFLA_VRF_TABLE]);

	return obj;
}

/*****************************************************************************/

static gboolean
_wireguard_update_from_allowed_ips_nla (NMPWireGuardAllowedIP *allowed_ip,
                                        struct nlattr *nlattr)
{
	static const struct nla_policy policy[] = {
		[WGALLOWEDIP_A_FAMILY]    = { .type = NLA_U16 },
		[WGALLOWEDIP_A_IPADDR]    = { .minlen = sizeof (struct in_addr) },
		[WGALLOWEDIP_A_CIDR_MASK] = { .type = NLA_U8 },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	int family;
	int addr_len;

	if (nla_parse_nested_arr (tb, nlattr, policy) < 0)
		return FALSE;

	if (!tb[WGALLOWEDIP_A_FAMILY])
		return FALSE;

	family = nla_get_u16 (tb[WGALLOWEDIP_A_FAMILY]);
	if (family == AF_INET)
		addr_len = sizeof (in_addr_t);
	else if (family == AF_INET6)
		addr_len = sizeof (struct in6_addr);
	else
		return FALSE;

	_check_addr_or_return_val (tb, WGALLOWEDIP_A_IPADDR, addr_len, FALSE);

	*allowed_ip = (NMPWireGuardAllowedIP) {
		.family = family,
	};

	nm_assert ((int) allowed_ip->family == family);

	if (tb[WGALLOWEDIP_A_IPADDR])
		nla_memcpy (&allowed_ip->addr, tb[WGALLOWEDIP_A_IPADDR], addr_len);
	if (tb[WGALLOWEDIP_A_CIDR_MASK])
		allowed_ip->mask = nla_get_u8 (tb[WGALLOWEDIP_A_CIDR_MASK]);

	return TRUE;
}

typedef struct {
	CList lst;
	NMPWireGuardPeer data;
} WireGuardPeerConstruct;

static gboolean
_wireguard_update_from_peers_nla (CList *peers,
                                  GArray **p_allowed_ips,
                                  struct nlattr *peer_attr)
{
	static const struct nla_policy policy[] = {
		[WGPEER_A_PUBLIC_KEY]                    = { .minlen = NMP_WIREGUARD_PUBLIC_KEY_LEN },
		[WGPEER_A_PRESHARED_KEY]                 = { },
		[WGPEER_A_FLAGS]                         = { .type = NLA_U32 },
		[WGPEER_A_ENDPOINT]                      = { },
		[WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL] = { .type = NLA_U16 },
		[WGPEER_A_LAST_HANDSHAKE_TIME]           = { },
		[WGPEER_A_RX_BYTES]                      = { .type = NLA_U64 },
		[WGPEER_A_TX_BYTES]                      = { .type = NLA_U64 },
		[WGPEER_A_ALLOWEDIPS]                    = { .type = NLA_NESTED },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	WireGuardPeerConstruct *peer_c;

	if (nla_parse_nested_arr (tb, peer_attr, policy) < 0)
		return FALSE;

	if (!tb[WGPEER_A_PUBLIC_KEY])
		return FALSE;

	/* a peer with the same public key as last peer is just a continuation for extra AllowedIPs */
	peer_c = c_list_last_entry (peers, WireGuardPeerConstruct, lst);
	if (   peer_c
	    && !memcmp (nla_data (tb[WGPEER_A_PUBLIC_KEY]), peer_c->data.public_key, NMP_WIREGUARD_PUBLIC_KEY_LEN)) {
		G_STATIC_ASSERT_EXPR (NMP_WIREGUARD_PUBLIC_KEY_LEN == sizeof (peer_c->data.public_key));
		/* this message is a continuation of the previous peer.
		 * Only parse WGPEER_A_ALLOWEDIPS below. */
	}
	else {
		/* otherwise, start a new peer */
		peer_c = g_slice_new0 (WireGuardPeerConstruct);
		c_list_link_tail (peers, &peer_c->lst);

		nla_memcpy (&peer_c->data.public_key, tb[WGPEER_A_PUBLIC_KEY], sizeof (peer_c->data.public_key));

		if (tb[WGPEER_A_PRESHARED_KEY]) {
			nla_memcpy (&peer_c->data.preshared_key, tb[WGPEER_A_PRESHARED_KEY], sizeof (peer_c->data.preshared_key));
			/* FIXME(netlink-bzero-secret) */
			nm_explicit_bzero (nla_data (tb[WGPEER_A_PRESHARED_KEY]),
			                   nla_len (tb[WGPEER_A_PRESHARED_KEY]));
		}

		nm_sock_addr_union_cpy_untrusted (&peer_c->data.endpoint,
		                                  tb[WGPEER_A_ENDPOINT] ? nla_data (tb[WGPEER_A_ENDPOINT]) : NULL,
		                                  tb[WGPEER_A_ENDPOINT] ? nla_len  (tb[WGPEER_A_ENDPOINT]) : 0);

		if (tb[WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL])
			peer_c->data.persistent_keepalive_interval = nla_get_u16 (tb[WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]);
		if (tb[WGPEER_A_LAST_HANDSHAKE_TIME]) {
			if (nla_len (tb[WGPEER_A_LAST_HANDSHAKE_TIME]) >= sizeof (peer_c->data.last_handshake_time))
				nla_memcpy (&peer_c->data.last_handshake_time, tb[WGPEER_A_LAST_HANDSHAKE_TIME], sizeof (peer_c->data.last_handshake_time));
		}
		if (tb[WGPEER_A_RX_BYTES])
			peer_c->data.rx_bytes = nla_get_u64 (tb[WGPEER_A_RX_BYTES]);
		if (tb[WGPEER_A_TX_BYTES])
			peer_c->data.tx_bytes = nla_get_u64 (tb[WGPEER_A_TX_BYTES]);
	}

	if (tb[WGPEER_A_ALLOWEDIPS]) {
		struct nlattr *attr;
		int rem;
		GArray *allowed_ips = *p_allowed_ips;

		nla_for_each_nested (attr, tb[WGPEER_A_ALLOWEDIPS], rem) {
			if (!allowed_ips) {
				allowed_ips = g_array_new (FALSE, FALSE, sizeof (NMPWireGuardAllowedIP));
				*p_allowed_ips = allowed_ips;
				g_array_set_size (allowed_ips, 1);
			} else
				g_array_set_size (allowed_ips, allowed_ips->len + 1);

			if (!_wireguard_update_from_allowed_ips_nla (&g_array_index (allowed_ips,
			                                                             NMPWireGuardAllowedIP,
			                                                             allowed_ips->len - 1),
			                                            attr)) {
				/* we ignore the error of parsing one allowed-ip. */
				g_array_set_size (allowed_ips, allowed_ips->len - 1);
				continue;
			}

			if (!peer_c->data._construct_idx_end)
				peer_c->data._construct_idx_start = allowed_ips->len - 1;
			peer_c->data._construct_idx_end = allowed_ips->len;
		}
	}

	return TRUE;
}

typedef struct {
	const int ifindex;
	NMPObject *obj;
	CList peers;
	GArray *allowed_ips;
} WireGuardParseData;

static int
_wireguard_get_device_cb (struct nl_msg *msg, void *arg)
{
	static const struct nla_policy policy[] = {
		[WGDEVICE_A_IFINDEX]     = { .type = NLA_U32 },
		[WGDEVICE_A_IFNAME]      = { .type = NLA_NUL_STRING, .maxlen = IFNAMSIZ },
		[WGDEVICE_A_PRIVATE_KEY] = { },
		[WGDEVICE_A_PUBLIC_KEY]  = { },
		[WGDEVICE_A_FLAGS]       = { .type = NLA_U32 },
		[WGDEVICE_A_LISTEN_PORT] = { .type = NLA_U16 },
		[WGDEVICE_A_FWMARK]      = { .type = NLA_U32 },
		[WGDEVICE_A_PEERS]       = { .type = NLA_NESTED },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	WireGuardParseData *parse_data = arg;

	if (genlmsg_parse_arr (nlmsg_hdr (msg), 0, tb, policy) < 0)
		return NL_SKIP;

	if (tb[WGDEVICE_A_IFINDEX]) {
		int ifindex;

		ifindex = (int) nla_get_u32 (tb[WGDEVICE_A_IFINDEX]);
		if (   ifindex <= 0
		    || parse_data->ifindex != ifindex)
			return NL_SKIP;
	} else {
		if (!parse_data->obj)
			return NL_SKIP;
	}

	if (parse_data->obj) {
		/* we already have an object instance. This means the netlink message
		 * is a continuation, only providing more WGDEVICE_A_PEERS data below. */
	} else {
		NMPObject *obj;
		NMPlatformLnkWireGuard *props;

		obj = nmp_object_new (NMP_OBJECT_TYPE_LNK_WIREGUARD, NULL);
		props = &obj->lnk_wireguard;

		if (tb[WGDEVICE_A_PRIVATE_KEY]) {
			nla_memcpy (props->private_key, tb[WGDEVICE_A_PRIVATE_KEY], sizeof (props->private_key));
			/* FIXME(netlink-bzero-secret): extend netlink library to wipe memory. For now,
			 * just hack it here (yes, this does not cover all places where the
			 * private key was copied). */
			nm_explicit_bzero (nla_data (tb[WGDEVICE_A_PRIVATE_KEY]),
			                   nla_len (tb[WGDEVICE_A_PRIVATE_KEY]));
		}
		if (tb[WGDEVICE_A_PUBLIC_KEY])
			nla_memcpy (props->public_key, tb[WGDEVICE_A_PUBLIC_KEY], sizeof (props->public_key));
		if (tb[WGDEVICE_A_LISTEN_PORT])
			props->listen_port = nla_get_u16 (tb[WGDEVICE_A_LISTEN_PORT]);
		if (tb[WGDEVICE_A_FWMARK])
			props->fwmark = nla_get_u32 (tb[WGDEVICE_A_FWMARK]);

		parse_data->obj = obj;
	}

	if (tb[WGDEVICE_A_PEERS]) {
		struct nlattr *attr;
		int rem;

		nla_for_each_nested (attr, tb[WGDEVICE_A_PEERS], rem) {
			if (!_wireguard_update_from_peers_nla (&parse_data->peers, &parse_data->allowed_ips, attr)) {
				/* we ignore the error of parsing one peer.
				 * _wireguard_update_from_peers_nla() leaves the @peers array in the
				 * desired state. */
			}
		}
	}

	return NL_OK;
}

static const NMPObject *
_wireguard_read_info (NMPlatform *platform /* used only as logging context */,
                      struct nl_sock *genl,
                      int wireguard_family_id,
                      int ifindex)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	NMPObject *obj = NULL;
	WireGuardPeerConstruct *peer_c;
	WireGuardPeerConstruct *peer_c_safe;
	gs_unref_array GArray *allowed_ips = NULL;
	WireGuardParseData parse_data = {
		.ifindex = ifindex,
	};
	guint i;

	nm_assert (genl);
	nm_assert (wireguard_family_id >= 0);
	nm_assert (ifindex > 0);

	_LOGT ("wireguard: fetching information for ifindex %d (genl-id %d)...", ifindex, wireguard_family_id);

	msg = nlmsg_alloc ();

	if (!genlmsg_put (msg,
	                  NL_AUTO_PORT,
	                  NL_AUTO_SEQ,
	                  wireguard_family_id,
	                  0,
	                  NLM_F_DUMP,
	                  WG_CMD_GET_DEVICE,
	                  1))
		return NULL;

	NLA_PUT_U32 (msg, WGDEVICE_A_IFINDEX, (guint32) ifindex);

	if (nl_send_auto (genl, msg) < 0)
		return NULL;

	c_list_init (&parse_data.peers);

	/* we ignore errors, and return whatever we could successfully
	 * parse. */
	nl_recvmsgs (genl,
	             &((const struct nl_cb) {
	                 .valid_cb = _wireguard_get_device_cb,
	                 .valid_arg = (gpointer) &parse_data,
	             }));

	/* unpack: transfer ownership */
	obj = parse_data.obj;
	allowed_ips = parse_data.allowed_ips;

	if (!obj) {
		while ((peer_c = c_list_first_entry (&parse_data.peers, WireGuardPeerConstruct, lst))) {
			c_list_unlink_stale (&peer_c->lst);
			nm_explicit_bzero (&peer_c->data.preshared_key, sizeof (peer_c->data.preshared_key));
			g_slice_free (WireGuardPeerConstruct, peer_c);
		}
		return NULL;
	}

	/* we receive peers/allowed-ips possibly in separate netlink messages. Hence, while
	 * parsing the dump, we don't know upfront how many peers/allowed-ips we will receive.
	 *
	 * We solve that, by collecting all peers with a CList. It's done this way,
	 * because a GArray would require growing the array, but we want to bzero()
	 * the preshared-key of each peer while reallocating. The CList apprach avoids
	 * that.
	 *
	 * For allowed-ips, we instead track one GArray, which are all appended
	 * there. The realloc/resize of the GArray is fine there. However,
	 * while we build the GArray, we don't yet have the final pointers.
	 * Hence, while constructing, we track the indexes with peer->_construct_idx_*
	 * fields. These indexes must be converted to actual pointers blow.
	 *
	 * This is all done during parsing. In the final NMPObjectLnkWireGuard we
	 * don't want the CList anymore and repackage the NMPObject tightly. The
	 * reason is, that NMPObject instances are immutable and long-living. Spend
	 * a bit effort below during construction to obtain a most suitable representation
	 * in this regard. */
	obj->_lnk_wireguard.peers_len = c_list_length (&parse_data.peers);
	obj->_lnk_wireguard.peers = obj->_lnk_wireguard.peers_len > 0
	                            ? g_new (NMPWireGuardPeer, obj->_lnk_wireguard.peers_len)
	                            : NULL;

	/* duplicate allowed_ips instead of using the pointer. The GArray possibly has more
	 * space allocated then we need, and we want to get rid of this excess buffer.
	 * Note that NMPObject instance is possibly put into the cache and long-living. */
	obj->_lnk_wireguard._allowed_ips_buf_len = allowed_ips ? allowed_ips->len : 0u;
	obj->_lnk_wireguard._allowed_ips_buf = obj->_lnk_wireguard._allowed_ips_buf_len > 0
	                                       ? (NMPWireGuardAllowedIP *) nm_memdup (allowed_ips->data,
	                                                                              sizeof (NMPWireGuardAllowedIP) * allowed_ips->len)
	                                       : NULL;

	i = 0;
	c_list_for_each_entry_safe (peer_c, peer_c_safe, &parse_data.peers, lst) {
		NMPWireGuardPeer *peer = (NMPWireGuardPeer *) &obj->_lnk_wireguard.peers[i++];

		*peer = peer_c->data;

		c_list_unlink_stale (&peer_c->lst);
		nm_explicit_bzero (&peer_c->data.preshared_key, sizeof (peer_c->data.preshared_key));
		g_slice_free (WireGuardPeerConstruct, peer_c);

		if (peer->_construct_idx_end != 0) {
			guint len;

			nm_assert (obj->_lnk_wireguard._allowed_ips_buf);
			nm_assert (peer->_construct_idx_end > peer->_construct_idx_start);
			nm_assert (peer->_construct_idx_start < obj->_lnk_wireguard._allowed_ips_buf_len);
			nm_assert (peer->_construct_idx_end <= obj->_lnk_wireguard._allowed_ips_buf_len);

			len = peer->_construct_idx_end - peer->_construct_idx_start;
			peer->allowed_ips = &obj->_lnk_wireguard._allowed_ips_buf[peer->_construct_idx_start];
			peer->allowed_ips_len = len;
		} else {
			nm_assert (!peer->_construct_idx_start);
			nm_assert (!peer->_construct_idx_end);
			peer->allowed_ips = NULL;
			peer->allowed_ips_len = 0;
		}
	}

	return obj;

nla_put_failure:
	g_return_val_if_reached (NULL);
}

static int
_wireguard_get_family_id (NMPlatform *platform, int ifindex_try)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int wireguard_family_id = -1;

	if (ifindex_try > 0) {
		const NMPlatformLink *plink;

		if (nm_platform_link_get_lnk_wireguard (platform, ifindex_try, &plink))
			wireguard_family_id = NMP_OBJECT_UP_CAST (plink)->_link.wireguard_family_id;
	}
	if (wireguard_family_id < 0)
		wireguard_family_id = genl_ctrl_resolve (priv->genl, "wireguard");
	return wireguard_family_id;
}

static const NMPObject *
_wireguard_refresh_link (NMPlatform *platform,
                         int wireguard_family_id,
                         int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	nm_auto_nmpobj const NMPObject *obj_new = NULL;
	nm_auto_nmpobj const NMPObject *lnk_new = NULL;
	NMPCacheOpsType cache_op;
	const NMPObject *plink = NULL;
	nm_auto_nmpobj NMPObject *obj = NULL;

	nm_assert (wireguard_family_id >= 0);
	nm_assert (ifindex > 0);

	nm_platform_process_events (platform);

	plink = nm_platform_link_get_obj (platform, ifindex, TRUE);

	if (   !plink
	    || plink->link.type != NM_LINK_TYPE_WIREGUARD) {
		nm_platform_link_refresh (platform, ifindex);
		plink = nm_platform_link_get_obj (platform, ifindex, TRUE);
		if (   !plink
		    || plink->link.type != NM_LINK_TYPE_WIREGUARD)
			return NULL;
		if (NMP_OBJECT_GET_TYPE (plink->_link.netlink.lnk) == NMP_OBJECT_TYPE_LNK_WIREGUARD)
			lnk_new = nmp_object_ref (plink->_link.netlink.lnk);
	} else {
		lnk_new = _wireguard_read_info (platform,
		                                priv->genl,
		                                wireguard_family_id,
		                                ifindex);
		if (!lnk_new) {
			if (NMP_OBJECT_GET_TYPE (plink->_link.netlink.lnk) == NMP_OBJECT_TYPE_LNK_WIREGUARD)
				lnk_new = nmp_object_ref (plink->_link.netlink.lnk);
		} else if (nmp_object_equal (plink->_link.netlink.lnk, lnk_new)) {
			nmp_object_unref (lnk_new);
			lnk_new = nmp_object_ref (plink->_link.netlink.lnk);
		}
	}

	if (   plink->_link.wireguard_family_id == wireguard_family_id
	    && plink->_link.netlink.lnk == lnk_new)
		return plink;

	/* we use nmp_cache_update_netlink() to re-inject the new object into the cache.
	 * For that, we need to clone it, and tweak it so that it's suitable. It's a bit
	 * of a hack, in particular that we need to clear driver and udev-device. */
	obj = nmp_object_clone (plink, FALSE);
	obj->_link.wireguard_family_id = wireguard_family_id;
	nmp_object_unref (obj->_link.netlink.lnk);
	obj->_link.netlink.lnk = g_steal_pointer (&lnk_new);
	obj->link.driver = NULL;
	nm_clear_pointer (&obj->_link.udev.device, udev_device_unref);

	cache_op = nmp_cache_update_netlink (nm_platform_get_cache (platform),
	                                     obj,
	                                     FALSE,
	                                     &obj_old,
	                                     &obj_new);
	nm_assert (NM_IN_SET (cache_op, NMP_CACHE_OPS_UPDATED));
	if (cache_op != NMP_CACHE_OPS_UNCHANGED) {
		cache_on_change (platform, cache_op, obj_old, obj_new);
		nm_platform_cache_update_emit_signal (platform, cache_op, obj_old, obj_new);
	}

	nm_assert (   !obj_new
	           || (   NMP_OBJECT_GET_TYPE (obj_new) == NMP_OBJECT_TYPE_LINK
	               && obj_new->link.type == NM_LINK_TYPE_WIREGUARD
	               && (   !obj_new->_link.netlink.lnk
	                   || NMP_OBJECT_GET_TYPE (obj_new->_link.netlink.lnk) == NMP_OBJECT_TYPE_LNK_WIREGUARD)));
	return obj_new;
}

static int
_wireguard_create_change_nlmsgs (NMPlatform *platform,
                                 int ifindex,
                                 int wireguard_family_id,
                                 const NMPlatformLnkWireGuard *lnk_wireguard,
                                 const NMPWireGuardPeer *peers,
                                 const NMPlatformWireGuardChangePeerFlags *peer_flags,
                                 guint peers_len,
                                 NMPlatformWireGuardChangeFlags change_flags,
                                 GPtrArray **out_msgs)
{
	gs_unref_ptrarray GPtrArray *msgs = NULL;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	const guint IDX_NIL = G_MAXUINT;
	guint idx_peer_curr;
	guint idx_allowed_ips_curr;
	struct nlattr *nest_peers;
	struct nlattr *nest_curr_peer;
	struct nlattr *nest_allowed_ips;
	struct nlattr *nest_curr_allowed_ip;
	NMPlatformWireGuardChangePeerFlags p_flags = NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_DEFAULT;

#define _nla_nest_end(msg, nest_start) \
	G_STMT_START { \
		if (nla_nest_end ((msg), (nest_start)) < 0) \
			g_return_val_if_reached (-NME_BUG); \
	} G_STMT_END

	/* Adapted from LGPL-2.1+ code [1].
	 *
	 * [1] https://git.zx2c4.com/WireGuard/tree/contrib/examples/embeddable-wg-library/wireguard.c?id=5e99a6d43fe2351adf36c786f5ea2086a8fe7ab8#n1073 */

	idx_peer_curr = IDX_NIL;
	idx_allowed_ips_curr = IDX_NIL;

	/* TODO: for the moment, we always reset all peers and allowed-ips (WGDEVICE_F_REPLACE_PEERS, WGPEER_F_REPLACE_ALLOWEDIPS).
	 * The platform API should be extended to also support partial updates. In particular, configuring the same configuration
	 * multiple times, should not clear and re-add all settings, but rather sync the existing settings with the desired configuration. */

again:

	msg = nlmsg_alloc ();
	if (!genlmsg_put (msg,
	                  NL_AUTO_PORT,
	                  NL_AUTO_SEQ,
	                  wireguard_family_id,
	                  0,
	                  NLM_F_REQUEST,
	                  WG_CMD_SET_DEVICE,
	                  1))
		g_return_val_if_reached (-NME_BUG);

	NLA_PUT_U32 (msg, WGDEVICE_A_IFINDEX, (guint32) ifindex);

	if (idx_peer_curr == IDX_NIL) {
		guint32 flags;

		if (NM_FLAGS_HAS (change_flags, NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_PRIVATE_KEY))
			NLA_PUT (msg, WGDEVICE_A_PRIVATE_KEY, sizeof (lnk_wireguard->private_key), lnk_wireguard->private_key);
		if (NM_FLAGS_HAS (change_flags, NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_LISTEN_PORT))
			NLA_PUT_U16 (msg, WGDEVICE_A_LISTEN_PORT, lnk_wireguard->listen_port);
		if (NM_FLAGS_HAS (change_flags, NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_FWMARK))
			NLA_PUT_U32 (msg, WGDEVICE_A_FWMARK, lnk_wireguard->fwmark);

		flags = 0;
		if (NM_FLAGS_HAS (change_flags, NM_PLATFORM_WIREGUARD_CHANGE_FLAG_REPLACE_PEERS))
			flags |= WGDEVICE_F_REPLACE_PEERS;
		NLA_PUT_U32 (msg, WGDEVICE_A_FLAGS, flags);
	}

	if (peers_len == 0)
		goto send;

	nest_curr_peer = NULL;
	nest_allowed_ips = NULL;
	nest_curr_allowed_ip = NULL;

	nest_peers = nla_nest_start (msg, WGDEVICE_A_PEERS);
	if (!nest_peers)
		g_return_val_if_reached (-NME_BUG);

	if (idx_peer_curr == IDX_NIL)
		idx_peer_curr = 0;
	for (; idx_peer_curr < peers_len; idx_peer_curr++) {
		const NMPWireGuardPeer *p = &peers[idx_peer_curr];

		if (peer_flags) {
			p_flags = peer_flags[idx_peer_curr];
			if (!NM_FLAGS_ANY (p_flags,   NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_REMOVE_ME
			                            | NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_PRESHARED_KEY
			                            | NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_KEEPALIVE_INTERVAL
			                            | NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ENDPOINT
			                            | NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ALLOWEDIPS
			                            | NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_REPLACE_ALLOWEDIPS)) {
				/* no flags set. We take that as indication to skip configuring the peer
				 * entirely. */
				nm_assert (p_flags == NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_NONE);
				continue;
			}
		}

		nest_curr_peer = nla_nest_start (msg, 0);
		if (!nest_curr_peer)
			goto toobig_peers;

		if (nla_put (msg, WGPEER_A_PUBLIC_KEY, NMP_WIREGUARD_PUBLIC_KEY_LEN, p->public_key) < 0)
			goto toobig_peers;

		if (NM_FLAGS_HAS (p_flags, NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_REMOVE_ME)) {
			/* all other p_flags are silently ignored. */
			if (nla_put_uint32 (msg, WGPEER_A_FLAGS, WGPEER_F_REMOVE_ME) < 0)
				goto toobig_peers;
		} else {

			if (idx_allowed_ips_curr == IDX_NIL) {
				if (   NM_FLAGS_HAS (p_flags, NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_PRESHARED_KEY)
				    && nla_put (msg, WGPEER_A_PRESHARED_KEY, sizeof (p->preshared_key), p->preshared_key) < 0)
					goto toobig_peers;

				if (   NM_FLAGS_HAS (p_flags, NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_KEEPALIVE_INTERVAL)
				    && nla_put_uint16 (msg, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, p->persistent_keepalive_interval) < 0)
					goto toobig_peers;

				if (   NM_FLAGS_HAS (p_flags, NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_REPLACE_ALLOWEDIPS)
				    && nla_put_uint32 (msg, WGPEER_A_FLAGS, WGPEER_F_REPLACE_ALLOWEDIPS) < 0)
					goto toobig_peers;

				if (NM_FLAGS_HAS (p_flags, NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ENDPOINT)) {
					if (NM_IN_SET (p->endpoint.sa.sa_family, AF_INET, AF_INET6)) {
						if (nla_put (msg,
						             WGPEER_A_ENDPOINT,
						               p->endpoint.sa.sa_family == AF_INET
						             ? sizeof (p->endpoint.in)
						             : sizeof (p->endpoint.in6),
						             &p->endpoint) < 0)
							goto toobig_peers;
					} else {
						/* I think there is no way to clear an endpoint, though there shold be. */
						nm_assert (p->endpoint.sa.sa_family == AF_UNSPEC);
					}
				}
			}

			if (   NM_FLAGS_HAS (p_flags, NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ALLOWEDIPS)
			    && p->allowed_ips_len > 0) {
				if (idx_allowed_ips_curr == IDX_NIL)
					idx_allowed_ips_curr = 0;

				nest_allowed_ips = nla_nest_start (msg, WGPEER_A_ALLOWEDIPS);
				if (!nest_allowed_ips)
					goto toobig_allowedips;

				for (; idx_allowed_ips_curr < p->allowed_ips_len; idx_allowed_ips_curr++) {
					const NMPWireGuardAllowedIP *aip = &p->allowed_ips[idx_allowed_ips_curr];

					nest_curr_allowed_ip = nla_nest_start (msg, 0);
					if (!nest_curr_allowed_ip)
						goto toobig_allowedips;

					g_return_val_if_fail (NM_IN_SET (aip->family, AF_INET, AF_INET6), -NME_BUG);

					if (nla_put_uint16 (msg, WGALLOWEDIP_A_FAMILY, aip->family) < 0)
						goto toobig_allowedips;
					if (nla_put (msg,
					             WGALLOWEDIP_A_IPADDR,
					             nm_utils_addr_family_to_size (aip->family),
					             &aip->addr) < 0)
						goto toobig_allowedips;
					if (nla_put_uint8 (msg, WGALLOWEDIP_A_CIDR_MASK, aip->mask) < 0)
						goto toobig_allowedips;

					_nla_nest_end (msg, nest_curr_allowed_ip);
					nest_curr_allowed_ip = NULL;
				}
				idx_allowed_ips_curr = IDX_NIL;

				_nla_nest_end (msg, nest_allowed_ips);
				nest_allowed_ips = NULL;
			}
		}

		_nla_nest_end (msg, nest_curr_peer);
		nest_curr_peer = NULL;
	}

	_nla_nest_end (msg, nest_peers);
	goto send;

toobig_allowedips:
	if (nest_curr_allowed_ip)
		nla_nest_cancel (msg, nest_curr_allowed_ip);
	if (nest_allowed_ips)
		nla_nest_cancel (msg, nest_allowed_ips);
	_nla_nest_end (msg, nest_curr_peer);
	_nla_nest_end (msg, nest_peers);
	goto send;

toobig_peers:
	if (nest_curr_peer)
		nla_nest_cancel (msg, nest_curr_peer);
	_nla_nest_end (msg, nest_peers);
	goto send;

send:
	if (!msgs)
		msgs = g_ptr_array_new_with_free_func ((GDestroyNotify) nlmsg_free);
	g_ptr_array_add (msgs, g_steal_pointer (&msg));

	if (   idx_peer_curr != IDX_NIL
	    && idx_peer_curr < peers_len)
		goto again;

	NM_SET_OUT (out_msgs, g_steal_pointer (&msgs));
	return 0;

nla_put_failure:
	g_return_val_if_reached (-NME_BUG);

#undef _nla_nest_end
}

static int
link_wireguard_change (NMPlatform *platform,
                       int ifindex,
                       const NMPlatformLnkWireGuard *lnk_wireguard,
                       const NMPWireGuardPeer *peers,
                       const NMPlatformWireGuardChangePeerFlags *peer_flags,
                       guint peers_len,
                       NMPlatformWireGuardChangeFlags change_flags)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	gs_unref_ptrarray GPtrArray *msgs = NULL;
	int wireguard_family_id;
	guint i;
	int r;

	wireguard_family_id = _wireguard_get_family_id (platform, ifindex);
	if (wireguard_family_id < 0)
		return -NME_PL_NO_FIRMWARE;

	r = _wireguard_create_change_nlmsgs (platform,
	                                     ifindex,
	                                     wireguard_family_id,
	                                     lnk_wireguard,
	                                     peers,
	                                     peer_flags,
	                                     peers_len,
	                                     change_flags,
	                                     &msgs);
	if (r < 0) {
		_LOGW ("wireguard: set-device, cannot construct netlink message: %s", nm_strerror (r));
		return r;
	}

	for (i = 0; i < msgs->len; i++) {
		r = nl_send_auto (priv->genl, msgs->pdata[i]);
		if (r < 0) {
			_LOGW ("wireguard: set-device, send netlink message #%u failed: %s", i, nm_strerror (r));
			return r;
		}

		do {
			r = nl_recvmsgs (priv->genl, NULL);
		} while (r == -EAGAIN);
		if (r < 0) {
			_LOGW ("wireguard: set-device, message #%u was rejected: %s", i, nm_strerror (r));
			return r;
		}

		_LOGT ("wireguard: set-device, message #%u sent and confirmed", i);
	}

	_wireguard_refresh_link (platform, wireguard_family_id, ifindex);

	return 0;
}

/*****************************************************************************/

static void
_nmp_link_address_set (NMPLinkAddress *dst,
                       const struct nlattr *nla)
{
	*dst = (NMPLinkAddress) {
		.len = 0,
	};
	if (nla) {
		int l = nla_len (nla);

		if (   l > 0
		    && l <= NM_UTILS_HWADDR_LEN_MAX) {
			G_STATIC_ASSERT_EXPR (sizeof (dst->data) == NM_UTILS_HWADDR_LEN_MAX);
			memcpy (dst->data, nla_data (nla), l);
			dst->len = l;
		}
	}
}

/* Copied and heavily modified from libnl3's link_msg_parser(). */
static NMPObject *
_new_from_nl_link (NMPlatform *platform, const NMPCache *cache, struct nlmsghdr *nlh, gboolean id_only)
{
	static const struct nla_policy policy[] = {
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
		[IFLA_STATS]            = { .minlen = nm_offsetofend (struct rtnl_link_stats, tx_compressed) },
		[IFLA_STATS64]          = { .minlen = nm_offsetofend (struct rtnl_link_stats64, tx_compressed)},
		[IFLA_MAP]              = { .minlen = nm_offsetofend (struct rtnl_link_ifmap, port) },
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
		[IFLA_LINK_NETNSID]     = { },
	};
	const struct ifinfomsg *ifi;
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	struct nlattr *nl_info_data = NULL;
	const char *nl_info_kind = NULL;
	nm_auto_nmpobj NMPObject *obj = NULL;
	gboolean completed_from_cache_val = FALSE;
	gboolean *completed_from_cache = cache ? &completed_from_cache_val : NULL;
	const NMPObject *link_cached = NULL;
	const NMPObject *lnk_data = NULL;
	gboolean address_complete_from_cache = TRUE;
	gboolean broadcast_complete_from_cache = TRUE;
	gboolean lnk_data_complete_from_cache = TRUE;
	gboolean need_ext_data = FALSE;
	gboolean af_inet6_token_valid = FALSE;
	gboolean af_inet6_addr_gen_mode_valid = FALSE;

	if (!nlmsg_valid_hdr (nlh, sizeof (*ifi)))
		return NULL;

	ifi = nlmsg_data (nlh);

	if (ifi->ifi_family != AF_UNSPEC)
		return NULL;
	if (ifi->ifi_index <= 0)
		return NULL;

	obj = nmp_object_new_link (ifi->ifi_index);

	if (id_only)
		return g_steal_pointer (&obj);

	if (nlmsg_parse_arr (nlh, sizeof (*ifi), tb, policy) < 0)
		return NULL;

	if (!tb[IFLA_IFNAME])
		return NULL;
	nla_strlcpy (obj->link.name, tb[IFLA_IFNAME], IFNAMSIZ);
	if (!obj->link.name[0])
		return NULL;

	if (!tb[IFLA_MTU]) {
		/* Kernel has two places that send RTM_GETLINK messages:
		 * net/core/rtnetlink.c and net/wireless/ext-core.c.
		 * Unfotunatelly ext-core.c sets only IFLA_WIRELESS and
		 * IFLA_IFNAME. This confuses code in this function, because
		 * it cannot get complete set of data for the interface and
		 * later incomplete object this function creates is used to
		 * overwrite existing data in NM's cache.
		 * Since ext-core.c doesn't set IFLA_MTU we can use it as a
		 * signal to ignore incoming message.
		 * To some extent this is a hack and correct approach is to
		 * merge objects per-field.
		 */
		return NULL;
	}
	obj->link.mtu = nla_get_u32 (tb[IFLA_MTU]);

	if (tb[IFLA_LINKINFO]) {
		static const struct nla_policy policy_link_info[] = {
			[IFLA_INFO_KIND]        = { .type = NLA_STRING },
			[IFLA_INFO_DATA]        = { .type = NLA_NESTED },
			[IFLA_INFO_XSTATS]      = { .type = NLA_NESTED },
		};
		struct nlattr *li[G_N_ELEMENTS (policy_link_info)];

		if (nla_parse_nested_arr (li, tb[IFLA_LINKINFO], policy_link_info) < 0)
			return NULL;

		if (li[IFLA_INFO_KIND])
			nl_info_kind = nla_get_string (li[IFLA_INFO_KIND]);

		nl_info_data = li[IFLA_INFO_DATA];
	}

	if (tb[IFLA_STATS64]) {
		const char *stats = nla_data (tb[IFLA_STATS64]);

		obj->link.rx_packets = unaligned_read_ne64 (&stats[G_STRUCT_OFFSET (struct rtnl_link_stats64, rx_packets)]);
		obj->link.rx_bytes   = unaligned_read_ne64 (&stats[G_STRUCT_OFFSET (struct rtnl_link_stats64, rx_bytes)]);
		obj->link.tx_packets = unaligned_read_ne64 (&stats[G_STRUCT_OFFSET (struct rtnl_link_stats64, tx_packets)]);
		obj->link.tx_bytes   = unaligned_read_ne64 (&stats[G_STRUCT_OFFSET (struct rtnl_link_stats64, tx_bytes)]);
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
		_nmp_link_address_set (&obj->link.l_address, tb[IFLA_ADDRESS]);
		address_complete_from_cache = FALSE;
	}

	if (tb[IFLA_BROADCAST]) {
		_nmp_link_address_set (&obj->link.l_broadcast, tb[IFLA_BROADCAST]);
		broadcast_complete_from_cache = FALSE;
	}

	if (tb[IFLA_AF_SPEC]) {
		struct nlattr *af_attr;
		int remaining;

		nla_for_each_nested (af_attr, tb[IFLA_AF_SPEC], remaining) {
			switch (nla_type (af_attr)) {
			case AF_INET6:
				_parse_af_inet6 (platform,
				                 af_attr,
				                 &obj->link.inet6_token,
				                 &af_inet6_token_valid,
				                 &obj->link.inet6_addr_gen_mode_inv,
				                 &af_inet6_addr_gen_mode_valid);
				break;
			}
		}
	}

	switch (obj->link.type) {
	case NM_LINK_TYPE_GRE:
	case NM_LINK_TYPE_GRETAP:
		lnk_data = _parse_lnk_gre (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_INFINIBAND:
		lnk_data = _parse_lnk_infiniband (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_IP6TNL:
		lnk_data = _parse_lnk_ip6tnl (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_IP6GRE:
	case NM_LINK_TYPE_IP6GRETAP:
		lnk_data = _parse_lnk_ip6gre (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_IPIP:
		lnk_data = _parse_lnk_ipip (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_MACSEC:
		lnk_data = _parse_lnk_macsec (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_MACVLAN:
	case NM_LINK_TYPE_MACVTAP:
		lnk_data = _parse_lnk_macvlan (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_SIT:
		lnk_data = _parse_lnk_sit (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_TUN:
		lnk_data = _parse_lnk_tun (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_VLAN:
		lnk_data = _parse_lnk_vlan (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_VRF:
		lnk_data = _parse_lnk_vrf (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_VXLAN:
		lnk_data = _parse_lnk_vxlan (nl_info_kind, nl_info_data);
		break;
	case NM_LINK_TYPE_WIFI:
	case NM_LINK_TYPE_OLPC_MESH:
	case NM_LINK_TYPE_WPAN:
		need_ext_data = TRUE;
		lnk_data_complete_from_cache = FALSE;
		break;
	case NM_LINK_TYPE_WIREGUARD:
		lnk_data_complete_from_cache = TRUE;
		break;
	default:
		lnk_data_complete_from_cache = FALSE;
		break;
	}

	if (   completed_from_cache
	    && (   lnk_data_complete_from_cache
	        || need_ext_data
	        || address_complete_from_cache
	        || broadcast_complete_from_cache
	        || !af_inet6_token_valid
	        || !af_inet6_addr_gen_mode_valid
	        || !tb[IFLA_STATS64])) {
		_lookup_cached_link (cache, obj->link.ifindex, completed_from_cache, &link_cached);
		if (   link_cached
		    && link_cached->_link.netlink.is_in_netlink) {
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

			if (   need_ext_data
			    && link_cached->link.type == obj->link.type
			    && link_cached->_link.ext_data) {
				/* Prefer reuse of existing ext_data object */
				obj->_link.ext_data = g_object_ref (link_cached->_link.ext_data);
			}

			if (address_complete_from_cache)
				obj->link.l_address = link_cached->link.l_address;
			if (broadcast_complete_from_cache)
				obj->link.l_broadcast = link_cached->link.l_broadcast;
			if (!af_inet6_token_valid)
				obj->link.inet6_token = link_cached->link.inet6_token;
			if (!af_inet6_addr_gen_mode_valid)
				obj->link.inet6_addr_gen_mode_inv = link_cached->link.inet6_addr_gen_mode_inv;
			if (!tb[IFLA_STATS64]) {
				obj->link.rx_packets = link_cached->link.rx_packets;
				obj->link.rx_bytes = link_cached->link.rx_bytes;
				obj->link.tx_packets = link_cached->link.tx_packets;
				obj->link.tx_bytes = link_cached->link.tx_bytes;
			}
		}
	}

	obj->_link.netlink.lnk = lnk_data;

	if (   need_ext_data
	    && obj->_link.ext_data == NULL) {
		switch (obj->link.type) {
		case NM_LINK_TYPE_WIFI:
		case NM_LINK_TYPE_OLPC_MESH:
			obj->_link.ext_data = (GObject *) nm_wifi_utils_new (ifi->ifi_index,
			                                                     _genl_sock (NM_LINUX_PLATFORM (platform)),
			                                                     TRUE);
			break;
		case NM_LINK_TYPE_WPAN:
			obj->_link.ext_data = (GObject *) nm_wpan_utils_new (ifi->ifi_index,
			                                                     _genl_sock (NM_LINUX_PLATFORM (platform)),
			                                                     TRUE);
			break;
		default:
			g_assert_not_reached ();
		}
	}

	if (obj->link.type == NM_LINK_TYPE_WIREGUARD) {
		const NMPObject *lnk_data_new = NULL;
		struct nl_sock *genl = NM_LINUX_PLATFORM_GET_PRIVATE (platform)->genl;

		/* The WireGuard kernel module does not yet send link update
		 * notifications, so we don't actually update the cache. For
		 * now, always refetch link data here. */

		_lookup_cached_link (cache, obj->link.ifindex, completed_from_cache, &link_cached);
		if (   link_cached
		    && link_cached->_link.netlink.is_in_netlink
		    && link_cached->link.type == NM_LINK_TYPE_WIREGUARD)
			obj->_link.wireguard_family_id = link_cached->_link.wireguard_family_id;
		else
			obj->_link.wireguard_family_id = -1;

		if (obj->_link.wireguard_family_id < 0)
			obj->_link.wireguard_family_id = genl_ctrl_resolve (genl, "wireguard");

		if (obj->_link.wireguard_family_id >= 0) {
			lnk_data_new = _wireguard_read_info (platform,
			                                     genl,
			                                     obj->_link.wireguard_family_id,
			                                     obj->link.ifindex);
		}

		if (   lnk_data_new
		    && obj->_link.netlink.lnk
		    && nmp_object_equal (obj->_link.netlink.lnk, lnk_data_new))
			nmp_object_unref (lnk_data_new);
		else {
			nmp_object_unref (obj->_link.netlink.lnk);
			obj->_link.netlink.lnk = lnk_data_new;
		}
	}

	obj->_link.netlink.is_in_netlink = TRUE;
	return g_steal_pointer (&obj);
}

/* Copied and heavily modified from libnl3's addr_msg_parser(). */
static NMPObject *
_new_from_nl_addr (struct nlmsghdr *nlh, gboolean id_only)
{
	static const struct nla_policy policy[] = {
		[IFA_LABEL]     = { .type = NLA_STRING,
		                    .maxlen = IFNAMSIZ },
		[IFA_CACHEINFO] = { .minlen = nm_offsetofend (struct ifa_cacheinfo, tstamp) },
		[IFA_FLAGS]     = { },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	const struct ifaddrmsg *ifa;
	gboolean is_v4;
	nm_auto_nmpobj NMPObject *obj = NULL;
	int addr_len;
	guint32 lifetime, preferred, timestamp;

	if (!nlmsg_valid_hdr (nlh, sizeof (*ifa)))
		return NULL;

	ifa = nlmsg_data (nlh);

	if (!NM_IN_SET (ifa->ifa_family, AF_INET, AF_INET6))
		return NULL;

	is_v4 = ifa->ifa_family == AF_INET;

	if (nlmsg_parse_arr (nlh, sizeof (*ifa), tb, policy) < 0)
		return NULL;

	addr_len = is_v4
	           ? sizeof (in_addr_t)
	           : sizeof (struct in6_addr);

	if (ifa->ifa_prefixlen > (is_v4 ? 32 : 128))
		return NULL;

	/*****************************************************************/

	obj = nmp_object_new (is_v4 ? NMP_OBJECT_TYPE_IP4_ADDRESS : NMP_OBJECT_TYPE_IP6_ADDRESS, NULL);

	obj->ip_address.ifindex = ifa->ifa_index;
	obj->ip_address.plen = ifa->ifa_prefixlen;

	_check_addr_or_return_null (tb, IFA_ADDRESS, addr_len);
	_check_addr_or_return_null (tb, IFA_LOCAL, addr_len);
	if (is_v4) {
		/* For IPv4, kernel omits IFA_LOCAL/IFA_ADDRESS if (and only if) they
		 * are effectively 0.0.0.0 (all-zero). */
		if (tb[IFA_LOCAL])
			memcpy (&obj->ip4_address.address, nla_data (tb[IFA_LOCAL]), addr_len);
		if (tb[IFA_ADDRESS])
			memcpy (&obj->ip4_address.peer_address, nla_data (tb[IFA_ADDRESS]), addr_len);

		_check_addr_or_return_null (tb, IFA_BROADCAST, addr_len);
		obj->ip4_address.broadcast_address =   tb[IFA_BROADCAST]
		                                     ? nla_get_u32 (tb[IFA_BROADCAST])
		                                     : 0u;
		obj->ip4_address.use_ip4_broadcast_address = TRUE;
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
		const struct ifa_cacheinfo *ca;

		ca = nla_data_as (struct ifa_cacheinfo, tb[IFA_CACHEINFO]);
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

	return g_steal_pointer (&obj);
}

/* Copied and heavily modified from libnl3's rtnl_route_parse() and parse_multipath(). */
static NMPObject *
_new_from_nl_route (struct nlmsghdr *nlh, gboolean id_only)
{
	static const struct nla_policy policy[] = {
		[RTA_TABLE]     = { .type = NLA_U32 },
		[RTA_IIF]       = { .type = NLA_U32 },
		[RTA_OIF]       = { .type = NLA_U32 },
		[RTA_PRIORITY]  = { .type = NLA_U32 },
		[RTA_PREF]      = { .type = NLA_U8 },
		[RTA_FLOW]      = { .type = NLA_U32 },
		[RTA_CACHEINFO] = { .minlen = nm_offsetofend (struct rta_cacheinfo, rta_tsage) },
		[RTA_METRICS]   = { .type = NLA_NESTED },
		[RTA_MULTIPATH] = { .type = NLA_NESTED },
	};
	const struct rtmsg *rtm;
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	gboolean is_v4;
	nm_auto_nmpobj NMPObject *obj = NULL;
	int addr_len;
	struct {
		gboolean is_present;
		int ifindex;
		NMIPAddr gateway;
	} nh = {
		.is_present = FALSE,
	};
	guint32 mss;
	guint32 window = 0;
	guint32 cwnd = 0;
	guint32 initcwnd = 0;
	guint32 initrwnd = 0;
	guint32 mtu = 0;
	guint32 lock = 0;

	if (!nlmsg_valid_hdr (nlh, sizeof (*rtm)))
		return NULL;

	rtm = nlmsg_data (nlh);

	/*****************************************************************
	 * only handle ~normal~ routes.
	 *****************************************************************/

	if (!NM_IN_SET (rtm->rtm_family, AF_INET, AF_INET6))
		return NULL;

	if (rtm->rtm_type != RTN_UNICAST)
		return NULL;

	if (nlmsg_parse_arr (nlh,
	                     sizeof (struct rtmsg),
	                     tb,
	                     policy) < 0)
		return NULL;

	/*****************************************************************/

	is_v4 = rtm->rtm_family == AF_INET;
	addr_len = is_v4
	           ? sizeof (in_addr_t)
	           : sizeof (struct in6_addr);

	if (rtm->rtm_dst_len > (is_v4 ? 32 : 128))
		return NULL;

	/*****************************************************************
	 * parse nexthops. Only handle routes with one nh.
	 *****************************************************************/

	if (tb[RTA_MULTIPATH]) {
		size_t tlen = nla_len (tb[RTA_MULTIPATH]);
		struct rtnexthop *rtnh;

		if (tlen < sizeof (*rtnh))
			goto rta_multipath_done;

		rtnh = nla_data_as (struct rtnexthop, tb[RTA_MULTIPATH]);

		if (tlen < rtnh->rtnh_len)
			goto rta_multipath_done;

		while (TRUE) {

			if (nh.is_present) {
				/* we don't support multipath routes. */
				return NULL;
			}

			nh.is_present = TRUE;
			nh.ifindex = rtnh->rtnh_ifindex;

			if (rtnh->rtnh_len > sizeof (*rtnh)) {
				struct nlattr *ntb[G_N_ELEMENTS (policy)];

				if (nla_parse_arr (ntb,
				                   (struct nlattr *) RTNH_DATA (rtnh),
				                   rtnh->rtnh_len - sizeof (*rtnh),
				                   policy) < 0)
					return NULL;

				if (_check_addr_or_return_null (ntb, RTA_GATEWAY, addr_len))
					memcpy (&nh.gateway, nla_data (ntb[RTA_GATEWAY]), addr_len);
			}

			if (tlen < RTNH_ALIGN (rtnh->rtnh_len) + sizeof (*rtnh))
				goto rta_multipath_done;

			tlen -= RTNH_ALIGN (rtnh->rtnh_len);
			rtnh = RTNH_NEXT (rtnh);
		}
rta_multipath_done:
		;
	}

	if (   tb[RTA_OIF]
	    || tb[RTA_GATEWAY]
	    || tb[RTA_FLOW]) {
		int ifindex = 0;
		NMIPAddr gateway = { };

		if (tb[RTA_OIF])
			ifindex = nla_get_u32 (tb[RTA_OIF]);
		if (_check_addr_or_return_null (tb, RTA_GATEWAY, addr_len))
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
				return NULL;
		}
	} else if (!nh.is_present)
		return NULL;

	/*****************************************************************/

	mss = 0;
	if (tb[RTA_METRICS]) {
		static const struct nla_policy rtax_policy[] = {
			[RTAX_LOCK]        = { .type = NLA_U32 },
			[RTAX_ADVMSS]      = { .type = NLA_U32 },
			[RTAX_WINDOW]      = { .type = NLA_U32 },
			[RTAX_CWND]        = { .type = NLA_U32 },
			[RTAX_INITCWND]    = { .type = NLA_U32 },
			[RTAX_INITRWND]    = { .type = NLA_U32 },
			[RTAX_MTU]         = { .type = NLA_U32 },
		};
		struct nlattr *mtb[G_N_ELEMENTS (rtax_policy)];

		if (nla_parse_nested_arr (mtb, tb[RTA_METRICS], rtax_policy) < 0)
			return NULL;

		if (mtb[RTAX_LOCK])
			lock = nla_get_u32 (mtb[RTAX_LOCK]);
		if (mtb[RTAX_ADVMSS])
			mss = nla_get_u32 (mtb[RTAX_ADVMSS]);
		if (mtb[RTAX_WINDOW])
			window = nla_get_u32 (mtb[RTAX_WINDOW]);
		if (mtb[RTAX_CWND])
			cwnd = nla_get_u32 (mtb[RTAX_CWND]);
		if (mtb[RTAX_INITCWND])
			initcwnd = nla_get_u32 (mtb[RTAX_INITCWND]);
		if (mtb[RTAX_INITRWND])
			initrwnd = nla_get_u32 (mtb[RTAX_INITRWND]);
		if (mtb[RTAX_MTU])
			mtu = nla_get_u32 (mtb[RTAX_MTU]);
	}

	/*****************************************************************/

	obj = nmp_object_new (is_v4 ? NMP_OBJECT_TYPE_IP4_ROUTE : NMP_OBJECT_TYPE_IP6_ROUTE, NULL);

	obj->ip_route.table_coerced = nm_platform_route_table_coerce (  tb[RTA_TABLE]
	                                                              ? nla_get_u32 (tb[RTA_TABLE])
	                                                              : (guint32) rtm->rtm_table);

	obj->ip_route.ifindex = nh.ifindex;

	if (_check_addr_or_return_null (tb, RTA_DST, addr_len))
		memcpy (obj->ip_route.network_ptr, nla_data (tb[RTA_DST]), addr_len);

	obj->ip_route.plen = rtm->rtm_dst_len;

	if (tb[RTA_PRIORITY])
		obj->ip_route.metric = nla_get_u32 (tb[RTA_PRIORITY]);

	if (is_v4)
		obj->ip4_route.gateway = nh.gateway.addr4;
	else
		obj->ip6_route.gateway = nh.gateway.addr6;

	if (is_v4)
		obj->ip4_route.scope_inv = nm_platform_route_scope_inv (rtm->rtm_scope);

	if (_check_addr_or_return_null (tb, RTA_PREFSRC, addr_len)) {
		if (is_v4)
			memcpy (&obj->ip4_route.pref_src, nla_data (tb[RTA_PREFSRC]), addr_len);
		else
			memcpy (&obj->ip6_route.pref_src, nla_data (tb[RTA_PREFSRC]), addr_len);
	}

	if (is_v4)
		obj->ip4_route.tos = rtm->rtm_tos;
	else {
		if (tb[RTA_SRC]) {
			_check_addr_or_return_null (tb, RTA_SRC, addr_len);
			memcpy (&obj->ip6_route.src, nla_data (tb[RTA_SRC]), addr_len);
		}
		obj->ip6_route.src_plen = rtm->rtm_src_len;
	}

	obj->ip_route.mss = mss;
	obj->ip_route.window = window;
	obj->ip_route.cwnd = cwnd;
	obj->ip_route.initcwnd = initcwnd;
	obj->ip_route.initrwnd = initrwnd;
	obj->ip_route.mtu = mtu;
	obj->ip_route.lock_window   = NM_FLAGS_HAS (lock, 1 << RTAX_WINDOW);
	obj->ip_route.lock_cwnd     = NM_FLAGS_HAS (lock, 1 << RTAX_CWND);
	obj->ip_route.lock_initcwnd = NM_FLAGS_HAS (lock, 1 << RTAX_INITCWND);
	obj->ip_route.lock_initrwnd = NM_FLAGS_HAS (lock, 1 << RTAX_INITRWND);
	obj->ip_route.lock_mtu      = NM_FLAGS_HAS (lock, 1 << RTAX_MTU);

	if (!is_v4) {

		if (!_nm_platform_kernel_support_detected (NM_PLATFORM_KERNEL_SUPPORT_TYPE_RTA_PREF)) {
			/* Detect support for RTA_PREF by inspecting the netlink message.
			 * RTA_PREF was added in kernel 4.1, dated 21 June, 2015. */
			_nm_platform_kernel_support_init (NM_PLATFORM_KERNEL_SUPPORT_TYPE_RTA_PREF,
			                                  tb[RTA_PREF] ? 1 : -1);
		}

		if (tb[RTA_PREF])
			obj->ip6_route.rt_pref = nla_get_u8 (tb[RTA_PREF]);
	}

	obj->ip_route.r_rtm_flags = rtm->rtm_flags;
	obj->ip_route.rt_source = nmp_utils_ip_config_source_from_rtprot (rtm->rtm_protocol);

	return g_steal_pointer (&obj);
}

static NMPObject *
_new_from_nl_routing_rule (struct nlmsghdr *nlh, gboolean id_only)
{
	static const struct nla_policy policy[] = {
		[FRA_UNSPEC]             = { },
		[FRA_DST]                = { /* struct in_addr, struct in6_addr */ },
		[FRA_SRC]                = { /* struct in_addr, struct in6_addr */ },
		[FRA_IIFNAME]            = { .type   = NLA_STRING,
		                             .maxlen = IFNAMSIZ, },
		[FRA_GOTO]               = { .type   = NLA_U32, },
		[FRA_UNUSED2]            = { },
		[FRA_PRIORITY]           = { .type   = NLA_U32, },
		[FRA_UNUSED3]            = { },
		[FRA_UNUSED4]            = { },
		[FRA_UNUSED5]            = { },
		[FRA_FWMARK]             = { .type   = NLA_U32, },
		[FRA_FLOW]               = { .type   = NLA_U32, },
		[FRA_TUN_ID]             = { .type   = NLA_U64, },
		[FRA_SUPPRESS_IFGROUP]   = { .type   = NLA_U32, },
		[FRA_SUPPRESS_PREFIXLEN] = { .type   = NLA_U32, },
		[FRA_TABLE]              = { .type   = NLA_U32, },
		[FRA_FWMASK]             = { .type   = NLA_U32, },
		[FRA_OIFNAME]            = { .type   = NLA_STRING,
		                             .maxlen = IFNAMSIZ, },
		[FRA_PAD]                = { .type   = NLA_U32, },
		[FRA_L3MDEV]             = { .type   = NLA_U8, },
		[FRA_UID_RANGE]          = { .minlen = sizeof(NMFibRuleUidRange),
		                             .maxlen = sizeof(NMFibRuleUidRange), },
		[FRA_PROTOCOL]           = { .type   = NLA_U8, },
		[FRA_IP_PROTO]           = { .type   = NLA_U8, },
		[FRA_SPORT_RANGE]        = { .minlen = sizeof(NMFibRulePortRange),
		                             .maxlen = sizeof(NMFibRulePortRange), },
		[FRA_DPORT_RANGE]        = { .minlen = sizeof(NMFibRulePortRange),
		                             .maxlen = sizeof(NMFibRulePortRange), },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	const struct fib_rule_hdr *frh;
	NMPlatformRoutingRule *props;
	nm_auto_nmpobj NMPObject *obj = NULL;
	int addr_family;
	guint8 addr_size;

	if (nlmsg_parse_arr (nlh, sizeof (*frh), tb, policy) < 0)
		return NULL;

	frh = nlmsg_data (nlh);

	addr_family = frh->family;

	if (!NM_IN_SET (addr_family, AF_INET, AF_INET6)) {
		/* we don't care about other address families. */
		return NULL;
	}

	addr_size = nm_utils_addr_family_to_size (addr_family);

	obj = nmp_object_new (NMP_OBJECT_TYPE_ROUTING_RULE, NULL);
	props = &obj->routing_rule;

	props->addr_family = addr_family;
	props->action      = frh->action;
	props->flags       = frh->flags;
	props->tos         = frh->tos;

	props->table =   tb[FRA_TABLE]
	               ? nla_get_u32 (tb[FRA_TABLE])
	               : frh->table;

	if (tb[FRA_SUPPRESS_PREFIXLEN])
		props->suppress_prefixlen_inverse = ~nla_get_u32 (tb[FRA_SUPPRESS_PREFIXLEN]);

	if (tb[FRA_SUPPRESS_IFGROUP])
		props->suppress_ifgroup_inverse = ~nla_get_u32 (tb[FRA_SUPPRESS_IFGROUP]);

	if (tb[FRA_IIFNAME])
		nla_strlcpy (props->iifname, tb[FRA_IIFNAME], sizeof (props->iifname));

	if (tb[FRA_OIFNAME])
		nla_strlcpy (props->oifname, tb[FRA_OIFNAME], sizeof (props->oifname));

	if (tb[FRA_PRIORITY])
		props->priority = nla_get_u32 (tb[FRA_PRIORITY]);

	if (tb[FRA_FWMARK])
		props->fwmark = nla_get_u32 (tb[FRA_FWMARK]);

	if (tb[FRA_FWMASK])
		props->fwmask = nla_get_u32 (tb[FRA_FWMASK]);

	if (tb[FRA_GOTO])
		props->goto_target = nla_get_u32 (tb[FRA_GOTO]);

	props->src_len = frh->src_len;
	if (props->src_len > addr_size * 8)
		return NULL;
	if (!tb[FRA_SRC]) {
		if (props->src_len > 0)
			return NULL;
	} else if (!nm_ip_addr_set_from_untrusted (addr_family,
	                                           &props->src,
	                                           nla_data (tb[FRA_SRC]),
	                                           nla_len (tb[FRA_SRC]),
	                                           NULL))
		return NULL;

	props->dst_len = frh->dst_len;
	if (props->dst_len > addr_size * 8)
		return NULL;
	if (!tb[FRA_DST]) {
		if (props->dst_len > 0)
			return NULL;
	} else if (!nm_ip_addr_set_from_untrusted (addr_family,
	                                           &props->dst,
	                                           nla_data (tb[FRA_DST]),
	                                           nla_len (tb[FRA_DST]),
	                                           NULL))
		return NULL;

	if (tb[FRA_FLOW])
		props->flow = nla_get_u32 (tb[FRA_FLOW]);

	if (tb[FRA_TUN_ID])
		props->tun_id = nla_get_be64 (tb[FRA_TUN_ID]);

	if (tb[FRA_L3MDEV]) {

		if (!_nm_platform_kernel_support_detected (NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_L3MDEV)) {
			/* support for FRA_L3MDEV was added in 96c63fa7393d0a346acfe5a91e0c7d4c7782641b,
			 * kernel 4.8, 3 October 2017.
			 *
			 * We can only detect support if the attribute is present. A missing attribute
			 * is not conclusive. */
			_nm_platform_kernel_support_init (NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_L3MDEV, 1);
		}

		/* actually, kernel only allows this attribute to be missing or
		 * "1". Still, encode it as full uint8.
		 *
		 * Note that FRA_L3MDEV and FRA_TABLE are mutally exclusive. */
		props->l3mdev = nla_get_u8 (tb[FRA_L3MDEV]);
	}

	if (tb[FRA_PROTOCOL])
		props->protocol = nla_get_u8 (tb[FRA_PROTOCOL]);
	else
		nm_assert (props->protocol == RTPROT_UNSPEC);

	if (!_nm_platform_kernel_support_detected (NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_PROTOCOL)) {
		/* FRA_PROTOCOL was added in kernel 4.17, dated 3 June, 2018.
		 * See commit 1b71af6053af1bd2f849e9fda4f71c1e3f145dcf. */
		_nm_platform_kernel_support_init (NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_PROTOCOL,
		                                  tb[FRA_PROTOCOL] ? 1 : -1);
	}

	if (tb[FRA_IP_PROTO])
		props->ip_proto = nla_get_u8 (tb[FRA_IP_PROTO]);

	G_STATIC_ASSERT_EXPR (sizeof (NMFibRulePortRange) == 4);
	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NMFibRulePortRange, start) == 0);
	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NMFibRulePortRange, end)   == 2);

	nla_memcpy_checked_size (&props->sport_range, tb[FRA_SPORT_RANGE], sizeof (props->sport_range));
	nla_memcpy_checked_size (&props->dport_range, tb[FRA_DPORT_RANGE], sizeof (props->dport_range));

	if (!_nm_platform_kernel_support_detected (NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_IP_PROTO)) {
		/* support for FRA_IP_PROTO, FRA_SPORT_RANGE, and FRA_DPORT_RANGE was added together
		 * by bfff4862653bb96001ab57c1edd6d03f48e5f035, kernel 4.17, 4 June 2018.
		 *
		 * Unfortunately, a missing attribute does not tell us anything about support.
		 * We can only tell for sure when we have support, but not when we don't have.  */
		if (   tb[FRA_IP_PROTO]
		    || tb[FRA_SPORT_RANGE]
		    || tb[FRA_DPORT_RANGE])
			_nm_platform_kernel_support_init (NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_IP_PROTO, 1);
	}

	G_STATIC_ASSERT_EXPR (sizeof (NMFibRuleUidRange) == 8);
	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NMFibRuleUidRange, start) == 0);
	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NMFibRuleUidRange, end) == 4);

	if (tb[FRA_UID_RANGE]) {

		if (!_nm_platform_kernel_support_detected (NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_UID_RANGE)) {
			/* support for FRA_UID_RANGE was added in 622ec2c9d52405973c9f1ca5116eb1c393adfc7d,
			 * kernel 4.10, 19 February 2017.
			 *
			 * We can only detect support if the attribute is present. A missing attribute
			 * is not conclusive. */
			_nm_platform_kernel_support_init (NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_UID_RANGE, 1);
		}

		nla_memcpy_checked_size (&props->uid_range, tb[FRA_UID_RANGE], sizeof (props->uid_range));
		props->uid_range_has = TRUE;
	}

	return g_steal_pointer (&obj);
}

static NMPObject *
_new_from_nl_qdisc (struct nlmsghdr *nlh, gboolean id_only)
{
	static const struct nla_policy policy[] = {
		[TCA_KIND] = { .type = NLA_STRING },
		[TCA_OPTIONS] = { .type = NLA_NESTED },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	const struct tcmsg *tcm;
	NMPObject *obj;

	if (nlmsg_parse_arr (nlh,
	                     sizeof (*tcm),
	                     tb,
	                     policy) < 0)
		return NULL;

	if (!tb[TCA_KIND])
		return NULL;

	tcm = nlmsg_data (nlh);

	obj = nmp_object_new (NMP_OBJECT_TYPE_QDISC, NULL);

	obj->qdisc.kind = g_intern_string (nla_get_string (tb[TCA_KIND]));
	obj->qdisc.ifindex = tcm->tcm_ifindex;
	obj->qdisc.addr_family = tcm->tcm_family;
	obj->qdisc.handle = tcm->tcm_handle;
	obj->qdisc.parent = tcm->tcm_parent;
	obj->qdisc.info = tcm->tcm_info;

	if (nm_streq0 (obj->qdisc.kind, "fq_codel")) {
		obj->qdisc.fq_codel.memory_limit = NM_PLATFORM_FQ_CODEL_MEMORY_LIMIT_UNSET;
		obj->qdisc.fq_codel.ce_threshold = NM_PLATFORM_FQ_CODEL_CE_THRESHOLD_DISABLED;
	}

	if (tb[TCA_OPTIONS]) {
		struct nlattr *options_attr;
		int remaining;

		nla_for_each_nested (options_attr, tb[TCA_OPTIONS], remaining) {
			if (nla_len (options_attr) < sizeof (uint32_t))
				continue;

			if (nm_streq0 (obj->qdisc.kind, "fq_codel")) {
				switch (nla_type (options_attr)) {
				case TCA_FQ_CODEL_LIMIT:
					obj->qdisc.fq_codel.limit = nla_get_u32 (options_attr);
					break;
				case TCA_FQ_CODEL_FLOWS:
					obj->qdisc.fq_codel.flows = nla_get_u32 (options_attr);
					break;
				case TCA_FQ_CODEL_TARGET:
					obj->qdisc.fq_codel.target = nla_get_u32 (options_attr);
					break;
				case TCA_FQ_CODEL_INTERVAL:
					obj->qdisc.fq_codel.interval = nla_get_u32 (options_attr);
					break;
				case TCA_FQ_CODEL_QUANTUM:
					obj->qdisc.fq_codel.quantum = nla_get_u32 (options_attr);
					break;
				case TCA_FQ_CODEL_CE_THRESHOLD:
					obj->qdisc.fq_codel.ce_threshold = nla_get_u32 (options_attr);
					break;
				case TCA_FQ_CODEL_MEMORY_LIMIT:
					obj->qdisc.fq_codel.memory_limit = nla_get_u32 (options_attr);
					break;
				case TCA_FQ_CODEL_ECN:
					obj->qdisc.fq_codel.ecn = !!nla_get_u32 (options_attr);
					break;
				}
			}
		}
	}

	return obj;
}

static NMPObject *
_new_from_nl_tfilter (struct nlmsghdr *nlh, gboolean id_only)
{
	static const struct nla_policy policy[] = {
		[TCA_KIND] = { .type = NLA_STRING },
	};
	struct nlattr *tb[G_N_ELEMENTS (policy)];
	NMPObject *obj = NULL;
	const struct tcmsg *tcm;

	if (nlmsg_parse_arr (nlh, sizeof (*tcm), tb, policy) < 0)
		return NULL;

	if (!tb[TCA_KIND])
		return NULL;

	tcm = nlmsg_data (nlh);

	obj = nmp_object_new (NMP_OBJECT_TYPE_TFILTER, NULL);

	obj->tfilter.kind = g_intern_string (nla_get_string (tb[TCA_KIND]));
	obj->tfilter.ifindex = tcm->tcm_ifindex;
	obj->tfilter.addr_family = tcm->tcm_family;
	obj->tfilter.handle = tcm->tcm_handle;
	obj->tfilter.parent = tcm->tcm_parent;
	obj->tfilter.info = tcm->tcm_info;

	return obj;
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
	case RTM_NEWRULE:
	case RTM_DELRULE:
	case RTM_GETRULE:
		return _new_from_nl_routing_rule (msghdr, id_only);
	case RTM_NEWQDISC:
	case RTM_DELQDISC:
	case RTM_GETQDISC:
		return _new_from_nl_qdisc (msghdr, id_only);
	case RTM_NEWTFILTER:
	case RTM_DELTFILTER:
	case RTM_GETTFILTER:
		return _new_from_nl_tfilter (msghdr, id_only);
	default:
		return NULL;
	}
}

/*****************************************************************************/

static gboolean
_nl_msg_new_link_set_afspec (struct nl_msg *msg,
                             int addr_gen_mode,
                             NMUtilsIPv6IfaceId *iid)
{
	struct nlattr *af_spec;
	struct nlattr *af_attr;

	nm_assert (msg);

	if (!(af_spec = nla_nest_start (msg, IFLA_AF_SPEC)))
		goto nla_put_failure;

	if (addr_gen_mode >= 0 || iid) {
		if (!(af_attr = nla_nest_start (msg, AF_INET6)))
			goto nla_put_failure;

		if (addr_gen_mode >= 0)
			NLA_PUT_U8 (msg, IFLA_INET6_ADDR_GEN_MODE, addr_gen_mode);

		if (iid) {
			struct in6_addr i6_token = { .s6_addr = { 0, } };

			nm_utils_ipv6_addr_set_interface_identifier (&i6_token, *iid);
			NLA_PUT (msg, IFLA_INET6_TOKEN, sizeof (struct in6_addr), &i6_token);
		}

		nla_nest_end (msg, af_attr);
	}

	nla_nest_end (msg, af_spec);

	return TRUE;
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static gboolean
_nl_msg_new_link_set_linkinfo (struct nl_msg *msg,
                               NMLinkType link_type,
                               gconstpointer extra_data)
{
	struct nlattr *info;
	struct nlattr *data = NULL;
	const char *kind;

	nm_assert (msg);

	kind = nm_link_type_to_rtnl_type_string (link_type);
	if (!kind)
		goto nla_put_failure;

	if (!(info = nla_nest_start (msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING (msg, IFLA_INFO_KIND, kind);

	switch (link_type) {
	case NM_LINK_TYPE_VLAN: {
		const NMPlatformLnkVlan *props = extra_data;

		nm_assert (extra_data);

		if (!(data = nla_nest_start (msg, IFLA_INFO_DATA)))
			goto nla_put_failure;

		NLA_PUT_U16 (msg, IFLA_VLAN_ID, props->id);

		{
			struct ifla_vlan_flags flags = {
				.flags = props->flags & NM_VLAN_FLAGS_ALL,
				.mask  = NM_VLAN_FLAGS_ALL,
			};

			NLA_PUT (msg, IFLA_VLAN_FLAGS, sizeof (flags), &flags);
		}
		break;
	}
	case NM_LINK_TYPE_VRF: {
		const NMPlatformLnkVrf *props = extra_data;

		nm_assert (extra_data);

		if (!(data = nla_nest_start (msg, IFLA_INFO_DATA)))
			goto nla_put_failure;

		NLA_PUT_U32 (msg, IFLA_VRF_TABLE, props->table);
		break;
	}
	case NM_LINK_TYPE_VXLAN: {
		const NMPlatformLnkVxlan *props = extra_data;

		nm_assert (extra_data);

		if (!(data = nla_nest_start (msg, IFLA_INFO_DATA)))
			goto nla_put_failure;

		NLA_PUT_U32 (msg, IFLA_VXLAN_ID, props->id);

		if (props->group)
			NLA_PUT (msg, IFLA_VXLAN_GROUP, sizeof (props->group), &props->group);
		else if (memcmp (&props->group6, &in6addr_any, sizeof (in6addr_any)))
			NLA_PUT (msg, IFLA_VXLAN_GROUP6, sizeof (props->group6), &props->group6);

		if (props->local)
			NLA_PUT (msg, IFLA_VXLAN_LOCAL, sizeof (props->local), &props->local);
		else if (memcmp (&props->local6, &in6addr_any, sizeof (in6addr_any)))
			NLA_PUT (msg, IFLA_VXLAN_LOCAL6, sizeof (props->local6), &props->local6);

		if (props->parent_ifindex >= 0)
			NLA_PUT_U32 (msg, IFLA_VXLAN_LINK, props->parent_ifindex);

		if (   props->src_port_min
		    || props->src_port_max) {
			struct nm_ifla_vxlan_port_range port_range = {
				.low  = htons (props->src_port_min),
				.high = htons (props->src_port_max),
			};

			NLA_PUT (msg, IFLA_VXLAN_PORT_RANGE, sizeof (port_range), &port_range);
		}

		NLA_PUT_U16 (msg, IFLA_VXLAN_PORT, htons (props->dst_port));
		NLA_PUT_U8 (msg, IFLA_VXLAN_TOS, props->tos);
		NLA_PUT_U8 (msg, IFLA_VXLAN_TTL, props->ttl);
		NLA_PUT_U32 (msg, IFLA_VXLAN_AGEING, props->ageing);
		NLA_PUT_U32 (msg, IFLA_VXLAN_LIMIT, props->limit);
		NLA_PUT_U8 (msg, IFLA_VXLAN_LEARNING, !!props->learning);
		NLA_PUT_U8 (msg, IFLA_VXLAN_PROXY, !!props->proxy);
		NLA_PUT_U8 (msg, IFLA_VXLAN_RSC, !!props->rsc);
		NLA_PUT_U8 (msg, IFLA_VXLAN_L2MISS, !!props->l2miss);
		NLA_PUT_U8 (msg, IFLA_VXLAN_L3MISS, !!props->l3miss);
		break;
	}
	case NM_LINK_TYPE_VETH: {
		const char *veth_peer = extra_data;
		const struct ifinfomsg ifi = { };
		struct nlattr *info_peer;

		nm_assert (veth_peer);

		if (!(data = nla_nest_start (msg, IFLA_INFO_DATA)))
			goto nla_put_failure;
		if (!(info_peer = nla_nest_start (msg, 1 /*VETH_INFO_PEER*/)))
			goto nla_put_failure;
		if (nlmsg_append_struct (msg, &ifi) < 0)
			goto nla_put_failure;
		NLA_PUT_STRING (msg, IFLA_IFNAME, veth_peer);
		nla_nest_end (msg, info_peer);
		break;
	}
	case NM_LINK_TYPE_GRE:
	case NM_LINK_TYPE_GRETAP: {
		const NMPlatformLnkGre *props = extra_data;

		nm_assert (props);
		nm_assert (props->is_tap == (link_type == NM_LINK_TYPE_GRETAP));

		if (!(data = nla_nest_start (msg, IFLA_INFO_DATA)))
			goto nla_put_failure;

		if (props->parent_ifindex)
			NLA_PUT_U32 (msg, IFLA_GRE_LINK, props->parent_ifindex);
		NLA_PUT_U32 (msg, IFLA_GRE_LOCAL, props->local);
		NLA_PUT_U32 (msg, IFLA_GRE_REMOTE, props->remote);
		NLA_PUT_U8 (msg, IFLA_GRE_TTL, props->ttl);
		NLA_PUT_U8 (msg, IFLA_GRE_TOS, props->tos);
		NLA_PUT_U8 (msg, IFLA_GRE_PMTUDISC, !!props->path_mtu_discovery);
		NLA_PUT_U32 (msg, IFLA_GRE_IKEY, htonl (props->input_key));
		NLA_PUT_U32 (msg, IFLA_GRE_OKEY, htonl (props->output_key));
		NLA_PUT_U16 (msg, IFLA_GRE_IFLAGS, htons (props->input_flags));
		NLA_PUT_U16 (msg, IFLA_GRE_OFLAGS, htons (props->output_flags));
		break;
	}
	case NM_LINK_TYPE_SIT: {
		const NMPlatformLnkSit *props = extra_data;

		nm_assert (props);

		if (!(data = nla_nest_start (msg, IFLA_INFO_DATA)))
			goto nla_put_failure;

		if (props->parent_ifindex)
			NLA_PUT_U32 (msg, IFLA_IPTUN_LINK, props->parent_ifindex);
		NLA_PUT_U32 (msg, IFLA_IPTUN_LOCAL, props->local);
		NLA_PUT_U32 (msg, IFLA_IPTUN_REMOTE, props->remote);
		NLA_PUT_U8 (msg, IFLA_IPTUN_TTL, props->ttl);
		NLA_PUT_U8 (msg, IFLA_IPTUN_TOS, props->tos);
		NLA_PUT_U8 (msg, IFLA_IPTUN_PMTUDISC, !!props->path_mtu_discovery);
		break;
	}
	case NM_LINK_TYPE_IP6TNL: {
		const NMPlatformLnkIp6Tnl *props = extra_data;
		guint32 flowinfo;

		nm_assert (props);
		nm_assert (!props->is_gre);

		if (!(data = nla_nest_start (msg, IFLA_INFO_DATA)))
			goto nla_put_failure;

		if (props->parent_ifindex)
			NLA_PUT_U32 (msg, IFLA_IPTUN_LINK, props->parent_ifindex);

		if (memcmp (&props->local, &in6addr_any, sizeof (in6addr_any)))
			NLA_PUT (msg, IFLA_IPTUN_LOCAL, sizeof (props->local), &props->local);
		if (memcmp (&props->remote, &in6addr_any, sizeof (in6addr_any)))
			NLA_PUT (msg, IFLA_IPTUN_REMOTE, sizeof (props->remote), &props->remote);

		NLA_PUT_U8 (msg, IFLA_IPTUN_TTL, props->ttl);
		NLA_PUT_U8 (msg, IFLA_IPTUN_ENCAP_LIMIT, props->encap_limit);

		flowinfo = props->flow_label & IP6_FLOWINFO_FLOWLABEL_MASK;
		flowinfo |=   (props->tclass << IP6_FLOWINFO_TCLASS_SHIFT)
		            & IP6_FLOWINFO_TCLASS_MASK;
		NLA_PUT_U32 (msg, IFLA_IPTUN_FLOWINFO, htonl (flowinfo));
		NLA_PUT_U8 (msg, IFLA_IPTUN_PROTO, props->proto);
		NLA_PUT_U32 (msg, IFLA_IPTUN_FLAGS, props->flags);
		break;
	}
	case NM_LINK_TYPE_IP6GRE:
	case NM_LINK_TYPE_IP6GRETAP: {
		const NMPlatformLnkIp6Tnl *props = extra_data;
		guint32 flowinfo;

		nm_assert (props);
		nm_assert (props->is_gre);

		if (!(data = nla_nest_start (msg, IFLA_INFO_DATA)))
			goto nla_put_failure;

		if (props->parent_ifindex)
			NLA_PUT_U32 (msg, IFLA_GRE_LINK, props->parent_ifindex);

		NLA_PUT_U32 (msg, IFLA_GRE_IKEY, htonl (props->input_key));
		NLA_PUT_U32 (msg, IFLA_GRE_OKEY, htonl (props->output_key));
		NLA_PUT_U16 (msg, IFLA_GRE_IFLAGS, htons (props->input_flags));
		NLA_PUT_U16 (msg, IFLA_GRE_OFLAGS, htons (props->output_flags));

		if (memcmp (&props->local, &in6addr_any, sizeof (in6addr_any)))
			NLA_PUT (msg, IFLA_GRE_LOCAL, sizeof (props->local), &props->local);
		if (memcmp (&props->remote, &in6addr_any, sizeof (in6addr_any)))
			NLA_PUT (msg, IFLA_GRE_REMOTE, sizeof (props->remote), &props->remote);

		NLA_PUT_U8 (msg, IFLA_GRE_TTL, props->ttl);
		NLA_PUT_U8 (msg, IFLA_GRE_ENCAP_LIMIT, props->encap_limit);

		flowinfo = props->flow_label & IP6_FLOWINFO_FLOWLABEL_MASK;
		flowinfo |=   (props->tclass << IP6_FLOWINFO_TCLASS_SHIFT)
		            & IP6_FLOWINFO_TCLASS_MASK;
		NLA_PUT_U32 (msg, IFLA_GRE_FLOWINFO, htonl (flowinfo));
		NLA_PUT_U32 (msg, IFLA_GRE_FLAGS, props->flags);
		break;
	}
	case NM_LINK_TYPE_IPIP: {
		const NMPlatformLnkIpIp *props = extra_data;

		nm_assert (props);

		if (!(data = nla_nest_start (msg, IFLA_INFO_DATA)))
			goto nla_put_failure;

		if (props->parent_ifindex)
			NLA_PUT_U32 (msg, IFLA_IPTUN_LINK, props->parent_ifindex);
		NLA_PUT_U32 (msg, IFLA_IPTUN_LOCAL, props->local);
		NLA_PUT_U32 (msg, IFLA_IPTUN_REMOTE, props->remote);
		NLA_PUT_U8 (msg, IFLA_IPTUN_TTL, props->ttl);
		NLA_PUT_U8 (msg, IFLA_IPTUN_TOS, props->tos);
		NLA_PUT_U8 (msg, IFLA_IPTUN_PMTUDISC, !!props->path_mtu_discovery);
		break;
	}
	case NM_LINK_TYPE_MACSEC: {
		const NMPlatformLnkMacsec *props = extra_data;

		nm_assert (props);

		if (!(data = nla_nest_start (msg, IFLA_INFO_DATA)))
			goto nla_put_failure;

		if (props->icv_length)
			NLA_PUT_U8 (msg, IFLA_MACSEC_ICV_LEN, 16);
		if (props->cipher_suite)
			NLA_PUT_U64 (msg, IFLA_MACSEC_CIPHER_SUITE, props->cipher_suite);
		if (props->replay_protect)
			NLA_PUT_U32 (msg, IFLA_MACSEC_WINDOW, props->window);

		NLA_PUT_U64 (msg, IFLA_MACSEC_SCI, htobe64 (props->sci));
		NLA_PUT_U8 (msg, IFLA_MACSEC_ENCODING_SA, props->encoding_sa);
		NLA_PUT_U8 (msg, IFLA_MACSEC_ENCRYPT, props->encrypt);
		NLA_PUT_U8 (msg, IFLA_MACSEC_PROTECT, props->protect);
		NLA_PUT_U8 (msg, IFLA_MACSEC_INC_SCI, props->include_sci);
		NLA_PUT_U8 (msg, IFLA_MACSEC_ES, props->es);
		NLA_PUT_U8 (msg, IFLA_MACSEC_SCB, props->scb);
		NLA_PUT_U8 (msg, IFLA_MACSEC_REPLAY_PROTECT, props->replay_protect);
		NLA_PUT_U8 (msg, IFLA_MACSEC_VALIDATION, props->validation);
		break;
	};
	case NM_LINK_TYPE_MACVTAP:
	case NM_LINK_TYPE_MACVLAN: {
		const NMPlatformLnkMacvlan *props = extra_data;

		nm_assert (props);

		if (!(data = nla_nest_start (msg, IFLA_INFO_DATA)))
			goto nla_put_failure;

		NLA_PUT_U32 (msg, IFLA_MACVLAN_MODE, props->mode);
		NLA_PUT_U16 (msg, IFLA_MACVLAN_FLAGS, props->no_promisc ? MACVLAN_FLAG_NOPROMISC : 0);
		break;
	}
	default:
		nm_assert (!extra_data);
		break;
	}

	if (data)
		nla_nest_end (msg, data);

	nla_nest_end (msg, info);

	return TRUE;
nla_put_failure:
	g_return_val_if_reached (FALSE);
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

	G_STATIC_ASSERT (NM_VLAN_FLAG_REORDER_HEADERS == (guint32) VLAN_FLAG_REORDER_HDR);
	G_STATIC_ASSERT (NM_VLAN_FLAG_GVRP == (guint32) VLAN_FLAG_GVRP);
	G_STATIC_ASSERT (NM_VLAN_FLAG_LOOSE_BINDING == (guint32) VLAN_FLAG_LOOSE_BINDING);
	G_STATIC_ASSERT (NM_VLAN_FLAG_MVRP == (guint32) VLAN_FLAG_MVRP);

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
					if (!(qos = nla_nest_start (msg, IFLA_VLAN_EGRESS_QOS)))
						goto nla_put_failure;
				}
				NLA_PUT (msg, i, sizeof (egress_qos[i]), &egress_qos[i]);
			}
		}

		if (qos)
			nla_nest_end (msg, qos);
	}

	nla_nest_end (msg, data);
	nla_nest_end (msg, info);

	return TRUE;
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static struct nl_msg *
_nl_msg_new_link_full (int nlmsg_type,
                       int nlmsg_flags,
                       int ifindex,
                       const char *ifname,
                       guint8 family,
                       unsigned flags_mask,
                       unsigned flags_set)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	const struct ifinfomsg ifi = {
		.ifi_family = family,
		.ifi_change = flags_mask,
		.ifi_flags = flags_set,
		.ifi_index = ifindex,
	};

	nm_assert (NM_IN_SET (nlmsg_type, RTM_DELLINK, RTM_NEWLINK, RTM_GETLINK, RTM_SETLINK));

	msg = nlmsg_alloc_simple (nlmsg_type, nlmsg_flags);

	if (nlmsg_append_struct (msg, &ifi) < 0)
		goto nla_put_failure;

	if (ifname)
		NLA_PUT_STRING (msg, IFLA_IFNAME, ifname);

	return g_steal_pointer (&msg);

nla_put_failure:
	g_return_val_if_reached (NULL);
}

static struct nl_msg *
_nl_msg_new_link (int nlmsg_type,
                  int nlmsg_flags,
                  int ifindex,
                  const char *ifname)
{
	return _nl_msg_new_link_full (nlmsg_type, nlmsg_flags, ifindex, ifname, AF_UNSPEC, 0, 0);
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
                     in_addr_t ip4_broadcast_address,
                     const char *label)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
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

	if (nlmsg_append_struct (msg, &am) < 0)
		goto nla_put_failure;

	if (address)
		NLA_PUT (msg, IFA_LOCAL, addr_len, address);

	if (peer_address)
		NLA_PUT (msg, IFA_ADDRESS, addr_len, peer_address);
	else if (address)
		NLA_PUT (msg, IFA_ADDRESS, addr_len, address);

	if (label && label[0])
		NLA_PUT_STRING (msg, IFA_LABEL, label);

	if (ip4_broadcast_address != 0)
		NLA_PUT (msg, IFA_BROADCAST, sizeof (in_addr_t), &ip4_broadcast_address);

	if (   lifetime != NM_PLATFORM_LIFETIME_PERMANENT
	    || preferred != NM_PLATFORM_LIFETIME_PERMANENT) {
		struct ifa_cacheinfo ca = {
			.ifa_valid = lifetime,
			.ifa_prefered = preferred,
		};

		NLA_PUT (msg, IFA_CACHEINFO, sizeof (ca), &ca);
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

	return g_steal_pointer (&msg);

nla_put_failure:
	g_return_val_if_reached (NULL);
}

static guint32
ip_route_get_lock_flag (const NMPlatformIPRoute *route)
{
	return   (((guint32) route->lock_window)   << RTAX_WINDOW)
	       | (((guint32) route->lock_cwnd)     << RTAX_CWND)
	       | (((guint32) route->lock_initcwnd) << RTAX_INITCWND)
	       | (((guint32) route->lock_initrwnd) << RTAX_INITRWND)
	       | (((guint32) route->lock_mtu)      << RTAX_MTU);
}

/* Copied and modified from libnl3's build_route_msg() and rtnl_route_build_msg(). */
static struct nl_msg *
_nl_msg_new_route (int nlmsg_type,
                   guint16 nlmsgflags,
                   const NMPObject *obj)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	const NMPClass *klass = NMP_OBJECT_GET_CLASS (obj);
	gboolean is_v4 = klass->addr_family == AF_INET;
	const guint32 lock = ip_route_get_lock_flag (NMP_OBJECT_CAST_IP_ROUTE (obj));
	const guint32 table = nm_platform_route_table_uncoerce (NMP_OBJECT_CAST_IP_ROUTE (obj)->table_coerced, TRUE);
	const struct rtmsg rtmsg = {
		.rtm_family = klass->addr_family,
		.rtm_tos = is_v4
		           ? obj->ip4_route.tos
		           : 0,
		.rtm_table = table <= 0xFF ? table : RT_TABLE_UNSPEC,
		.rtm_protocol = nmp_utils_ip_config_source_coerce_to_rtprot (obj->ip_route.rt_source),
		.rtm_scope = is_v4
		             ? nm_platform_route_scope_inv (obj->ip4_route.scope_inv)
		             : RT_SCOPE_NOWHERE,
		.rtm_type = RTN_UNICAST,
		.rtm_flags = obj->ip_route.r_rtm_flags & ((unsigned) (RTNH_F_ONLINK)),
		.rtm_dst_len = obj->ip_route.plen,
		.rtm_src_len = is_v4
		               ? 0
		               : NMP_OBJECT_CAST_IP6_ROUTE (obj)->src_plen,
	};

	gsize addr_len;

	nm_assert (NM_IN_SET (NMP_OBJECT_GET_TYPE (obj), NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE));
	nm_assert (NM_IN_SET (nlmsg_type, RTM_NEWROUTE, RTM_DELROUTE));

	msg = nlmsg_alloc_simple (nlmsg_type, (int) nlmsgflags);

	if (nlmsg_append_struct (msg, &rtmsg) < 0)
		goto nla_put_failure;

	addr_len = is_v4
	             ? sizeof (in_addr_t)
	             : sizeof (struct in6_addr);

	NLA_PUT (msg, RTA_DST, addr_len,
	         is_v4
	           ? (gconstpointer) &obj->ip4_route.network
	           : (gconstpointer) &obj->ip6_route.network);

	if (!is_v4) {
		if (!IN6_IS_ADDR_UNSPECIFIED (&NMP_OBJECT_CAST_IP6_ROUTE (obj)->src))
			NLA_PUT (msg, RTA_SRC, addr_len, &obj->ip6_route.src);
	}

	NLA_PUT_U32 (msg, RTA_PRIORITY, obj->ip_route.metric);

	if (table > 0xFF)
		NLA_PUT_U32 (msg, RTA_TABLE, table);

	if (is_v4) {
		if (NMP_OBJECT_CAST_IP4_ROUTE (obj)->pref_src)
			NLA_PUT (msg, RTA_PREFSRC, addr_len, &obj->ip4_route.pref_src);
	} else {
		if (!IN6_IS_ADDR_UNSPECIFIED (&NMP_OBJECT_CAST_IP6_ROUTE (obj)->pref_src))
			NLA_PUT (msg, RTA_PREFSRC, addr_len, &obj->ip6_route.pref_src);
	}

	if (   obj->ip_route.mss
	    || obj->ip_route.window
	    || obj->ip_route.cwnd
	    || obj->ip_route.initcwnd
	    || obj->ip_route.initrwnd
	    || obj->ip_route.mtu
	    || lock) {
		struct nlattr *metrics;

		metrics = nla_nest_start (msg, RTA_METRICS);
		if (!metrics)
			goto nla_put_failure;

		if (obj->ip_route.mss)
			NLA_PUT_U32 (msg, RTAX_ADVMSS, obj->ip_route.mss);
		if (obj->ip_route.window)
			NLA_PUT_U32 (msg, RTAX_WINDOW, obj->ip_route.window);
		if (obj->ip_route.cwnd)
			NLA_PUT_U32 (msg, RTAX_CWND, obj->ip_route.cwnd);
		if (obj->ip_route.initcwnd)
			NLA_PUT_U32 (msg, RTAX_INITCWND, obj->ip_route.initcwnd);
		if (obj->ip_route.initrwnd)
			NLA_PUT_U32 (msg, RTAX_INITRWND, obj->ip_route.initrwnd);
		if (obj->ip_route.mtu)
			NLA_PUT_U32 (msg, RTAX_MTU, obj->ip_route.mtu);
		if (lock)
			NLA_PUT_U32 (msg, RTAX_LOCK, lock);

		nla_nest_end (msg, metrics);
	}

	/* We currently don't have need for multi-hop routes... */
	if (is_v4) {
		NLA_PUT (msg, RTA_GATEWAY, addr_len, &obj->ip4_route.gateway);
	} else {
		if (!IN6_IS_ADDR_UNSPECIFIED (&obj->ip6_route.gateway))
			NLA_PUT (msg, RTA_GATEWAY, addr_len, &obj->ip6_route.gateway);
	}
	NLA_PUT_U32 (msg, RTA_OIF, obj->ip_route.ifindex);

	if (   !is_v4
	    && obj->ip6_route.rt_pref != NM_ICMPV6_ROUTER_PREF_MEDIUM)
		NLA_PUT_U8 (msg, RTA_PREF, obj->ip6_route.rt_pref);

	return g_steal_pointer (&msg);

nla_put_failure:
	g_return_val_if_reached (NULL);
}

static struct nl_msg *
_nl_msg_new_routing_rule (int nlmsg_type,
                          int nlmsg_flags,
                          const NMPlatformRoutingRule *routing_rule)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	const guint8 addr_size = nm_utils_addr_family_to_size (routing_rule->addr_family);
	guint32 table;

	msg = nlmsg_alloc_simple (nlmsg_type, nlmsg_flags);

	table = routing_rule->table;

	if (   NM_IN_SET (routing_rule->addr_family, AF_INET, AF_INET6)
	    && routing_rule->action == FR_ACT_TO_TBL
	    && routing_rule->l3mdev == 0
	    && table == RT_TABLE_UNSPEC) {
		/* for IPv6, this setting is invalid and rejected by kernel. That's fine.
		 *
		 * for IPv4, kernel will automatically assign an unused table. That's not
		 * fine, because we don't know what we will get.
		 *
		 * The caller must not allow that to happen. */
		nm_assert_not_reached ();
	}

	{
		const struct fib_rule_hdr frh = {
			.family  = routing_rule->addr_family,
			.src_len = routing_rule->src_len,
			.dst_len = routing_rule->dst_len,
			.tos     = routing_rule->tos,
			.table   = table < 0x100u ? (guint8) table : (guint8) RT_TABLE_UNSPEC,
			.action  = routing_rule->action,

			/* we only allow setting the "not" flag. */
			.flags   = routing_rule->flags & ((guint32) FIB_RULE_INVERT),
		};

		if (nlmsg_append_struct (msg, &frh) < 0)
			goto nla_put_failure;
	}

	if (table > G_MAXINT8)
		NLA_PUT_U32 (msg, FRA_TABLE, table);

	if (routing_rule->suppress_prefixlen_inverse != 0)
		NLA_PUT_U32 (msg, FRA_SUPPRESS_PREFIXLEN, ~routing_rule->suppress_prefixlen_inverse);

	if (routing_rule->suppress_ifgroup_inverse != 0)
		NLA_PUT_U32 (msg, FRA_SUPPRESS_IFGROUP, ~routing_rule->suppress_ifgroup_inverse);

	if (routing_rule->iifname[0] != '\0')
		NLA_PUT_STRING (msg, FRA_IIFNAME, routing_rule->iifname);

	if (routing_rule->oifname[0] != '\0')
		NLA_PUT_STRING (msg, FRA_OIFNAME, routing_rule->oifname);

	/* we always set the priority and don't support letting kernel pick one. */
	NLA_PUT_U32 (msg, FRA_PRIORITY, routing_rule->priority);

	if (   routing_rule->fwmark != 0
	    || routing_rule->fwmask != 0) {
		NLA_PUT_U32 (msg, FRA_FWMARK, routing_rule->fwmark);
		NLA_PUT_U32 (msg, FRA_FWMASK, routing_rule->fwmask);
	}

	if (routing_rule->src_len > 0)
		NLA_PUT (msg, FRA_SRC, addr_size, &routing_rule->src);

	if (routing_rule->dst_len > 0)
		NLA_PUT (msg, FRA_DST, addr_size, &routing_rule->dst);

	if (routing_rule->flow != 0) {
		/* only relevant for IPv4. */
		NLA_PUT_U32 (msg, FRA_FLOW, routing_rule->flow);
	}

	if (routing_rule->tun_id != 0)
		NLA_PUT_U64 (msg, FRA_TUN_ID, htobe64 (routing_rule->tun_id));

	if (routing_rule->l3mdev)
		NLA_PUT_U8 (msg, FRA_L3MDEV, routing_rule->l3mdev);

	if (routing_rule->protocol != RTPROT_UNSPEC)
		NLA_PUT_U8 (msg, FRA_PROTOCOL, routing_rule->protocol);

	if (routing_rule->ip_proto != 0)
		NLA_PUT_U8 (msg, FRA_IP_PROTO, routing_rule->ip_proto);

	if (   routing_rule->sport_range.start
	    || routing_rule->sport_range.end)
		NLA_PUT (msg, FRA_SPORT_RANGE, sizeof (routing_rule->sport_range), &routing_rule->sport_range);

	if (   routing_rule->dport_range.start
	    || routing_rule->dport_range.end)
		NLA_PUT (msg, FRA_DPORT_RANGE, sizeof (routing_rule->dport_range), &routing_rule->dport_range);

	if (routing_rule->uid_range_has)
		NLA_PUT (msg, FRA_UID_RANGE, sizeof (routing_rule->uid_range), &routing_rule->uid_range);

	switch (routing_rule->action) {
	case FR_ACT_GOTO:
		NLA_PUT_U32 (msg, FRA_GOTO, routing_rule->goto_target);
		break;
	}

	return g_steal_pointer (&msg);

nla_put_failure:
	g_return_val_if_reached (NULL);
}

static struct nl_msg *
_nl_msg_new_qdisc (int nlmsg_type,
                   int nlmsg_flags,
                   const NMPlatformQdisc *qdisc)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	struct nlattr *tc_options;
	const struct tcmsg tcm = {
		.tcm_family = qdisc->addr_family,
		.tcm_ifindex = qdisc->ifindex,
		.tcm_handle = qdisc->handle,
		.tcm_parent = qdisc->parent,
		.tcm_info = qdisc->info,
	};

	msg = nlmsg_alloc_simple (nlmsg_type, nlmsg_flags);

	if (nlmsg_append_struct (msg, &tcm) < 0)
		goto nla_put_failure;

	NLA_PUT_STRING (msg, TCA_KIND, qdisc->kind);

	if (!(tc_options = nla_nest_start (msg, TCA_OPTIONS)))
		goto nla_put_failure;

	if (strcmp (qdisc->kind, "fq_codel") == 0) {
		if (qdisc->fq_codel.limit)
			NLA_PUT_U32 (msg, TCA_FQ_CODEL_LIMIT, qdisc->fq_codel.limit);
		if (qdisc->fq_codel.flows)
			NLA_PUT_U32 (msg, TCA_FQ_CODEL_FLOWS, qdisc->fq_codel.flows);
		if (qdisc->fq_codel.target)
			NLA_PUT_U32 (msg, TCA_FQ_CODEL_TARGET, qdisc->fq_codel.target);
		if (qdisc->fq_codel.interval)
			NLA_PUT_U32 (msg, TCA_FQ_CODEL_INTERVAL, qdisc->fq_codel.interval);
		if (qdisc->fq_codel.quantum)
			NLA_PUT_U32 (msg, TCA_FQ_CODEL_QUANTUM, qdisc->fq_codel.quantum);
		if (qdisc->fq_codel.ce_threshold != NM_PLATFORM_FQ_CODEL_CE_THRESHOLD_DISABLED)
			NLA_PUT_U32 (msg, TCA_FQ_CODEL_CE_THRESHOLD, qdisc->fq_codel.ce_threshold);
		if (qdisc->fq_codel.memory_limit != NM_PLATFORM_FQ_CODEL_MEMORY_LIMIT_UNSET)
			NLA_PUT_U32 (msg, TCA_FQ_CODEL_MEMORY_LIMIT, qdisc->fq_codel.memory_limit);
		if (qdisc->fq_codel.ecn)
			NLA_PUT_U32 (msg, TCA_FQ_CODEL_ECN, qdisc->fq_codel.ecn);
	}

	nla_nest_end (msg, tc_options);

	return g_steal_pointer (&msg);

nla_put_failure:
	g_return_val_if_reached (NULL);
}

static struct nl_msg *
_nl_msg_new_tfilter (int nlmsg_type,
                     int nlmsg_flags,
                     const NMPlatformTfilter *tfilter)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	struct nlattr *tc_options;
	struct nlattr *act_tab;
	const struct tcmsg tcm = {
		.tcm_family = tfilter->addr_family,
		.tcm_ifindex = tfilter->ifindex,
		.tcm_handle = tfilter->handle,
		.tcm_parent = tfilter->parent,
		.tcm_info = tfilter->info,
	};

	msg = nlmsg_alloc_simple (nlmsg_type, nlmsg_flags);

	if (nlmsg_append_struct (msg, &tcm) < 0)
		goto nla_put_failure;

	NLA_PUT_STRING (msg, TCA_KIND, tfilter->kind);

	if (!(tc_options = nla_nest_start (msg, TCA_OPTIONS)))
		goto nla_put_failure;

	if (!(act_tab = nla_nest_start (msg, TCA_OPTIONS))) // 3 TCA_ACT_KIND TCA_ACT_KIND
		goto nla_put_failure;

	if (tfilter->action.kind) {
		const NMPlatformAction *action = &tfilter->action;
		struct nlattr *prio;
		struct nlattr *act_options;

		if (!(prio = nla_nest_start (msg, 1 /* priority */)))
			goto nla_put_failure;

		NLA_PUT_STRING (msg, TCA_ACT_KIND, action->kind);

		if (nm_streq (action->kind, NM_PLATFORM_ACTION_KIND_SIMPLE)) {
			const NMPlatformActionSimple *simple = &action->simple;
			struct tc_defact sel = { 0, };

			if (!(act_options = nla_nest_start (msg, TCA_ACT_OPTIONS)))
				goto nla_put_failure;

			NLA_PUT (msg, TCA_DEF_PARMS, sizeof (sel), &sel);
			NLA_PUT (msg, TCA_DEF_DATA, sizeof (simple->sdata), simple->sdata);

			nla_nest_end (msg, act_options);

		} else if (nm_streq (action->kind, NM_PLATFORM_ACTION_KIND_MIRRED)) {
			const NMPlatformActionMirred *mirred = &action->mirred;
			struct tc_mirred sel = { 0, };

			if (!(act_options = nla_nest_start (msg, TCA_ACT_OPTIONS)))
				goto nla_put_failure;

			if (mirred->egress && mirred->redirect)
				sel.eaction = TCA_EGRESS_REDIR;
			else if (mirred->egress && mirred->mirror)
				sel.eaction = TCA_EGRESS_MIRROR;
			else if (mirred->ingress && mirred->redirect)
				sel.eaction = TCA_INGRESS_REDIR;
			else if (mirred->ingress && mirred->mirror)
				sel.eaction = TCA_INGRESS_MIRROR;
			sel.ifindex = mirred->ifindex;

			NLA_PUT (msg, TCA_MIRRED_PARMS, sizeof (sel), &sel);

			nla_nest_end (msg, act_options);
		}

		nla_nest_end (msg, prio);
	}

	nla_nest_end (msg, tc_options);

	nla_nest_end (msg, act_tab);

	return g_steal_pointer (&msg);

nla_put_failure:
	g_return_val_if_reached (NULL);
}

/*****************************************************************************/

static struct nl_sock *
_genl_sock (NMLinuxPlatform *platform)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	return priv->genl;
}

#define ASSERT_SYSCTL_ARGS(pathid, dirfd, path) \
	G_STMT_START { \
		const char *const _pathid = (pathid); \
		const int _dirfd = (dirfd); \
		const char *const _path = (path); \
		\
		nm_assert (_path && _path[0]); \
		g_assert (!strstr (_path, "/../")); \
		if (_dirfd < 0) { \
			nm_assert (!_pathid); \
			nm_assert (_path[0] == '/'); \
			nm_assert (   g_str_has_prefix (_path, "/proc/sys/") \
			           || g_str_has_prefix (_path, "/sys/")); \
		} else { \
			nm_assert (_pathid && _pathid[0] && _pathid[0] != '/'); \
			nm_assert (_path[0] != '/'); \
		} \
	} G_STMT_END

/*****************************************************************************/

/* core sysctl-set functions can be called from a non-main thread.
 * Hence, we require locking from nm-logging. Indicate that by
 * setting NM_THREAD_SAFE_ON_MAIN_THREAD to zero. */
#undef NM_THREAD_SAFE_ON_MAIN_THREAD
#define NM_THREAD_SAFE_ON_MAIN_THREAD 0

static void
_log_dbg_sysctl_set_impl (NMPlatform *platform, const char *pathid, int dirfd, const char *path, const char *value)
{
	GError *error = NULL;
	gs_free char *contents = NULL;
	gs_free char *value_escaped = g_strescape (value, NULL);

	if (!nm_utils_file_get_contents (dirfd,
	                                 path,
	                                 1*1024*1024,
	                                 NM_UTILS_FILE_GET_CONTENTS_FLAG_NONE,
	                                 &contents,
	                                 NULL,
	                                 NULL,
	                                 &error)) {
		_LOGD ("sysctl: setting '%s' to '%s' (current value cannot be read: %s)", pathid ?: path, value_escaped, error->message);
		g_clear_error (&error);
		return;
	}

	g_strstrip (contents);
	if (nm_streq (contents, value))
		_LOGD ("sysctl: setting '%s' to '%s' (current value is identical)", pathid ?: path, value_escaped);
	else {
		gs_free char *contents_escaped = g_strescape (contents, NULL);

		_LOGD ("sysctl: setting '%s' to '%s' (current value is '%s')", pathid ?: path, value_escaped, contents_escaped);
	}
}

#define _log_dbg_sysctl_set(platform, pathid, dirfd, path, value) \
	G_STMT_START { \
		if (_LOGD_ENABLED ()) { \
			_log_dbg_sysctl_set_impl (platform, pathid, dirfd, path, value); \
		} \
	} G_STMT_END

static gboolean
sysctl_set_internal (NMPlatform *platform,
                     const char *pathid,
                     int dirfd,
                     const char *path,
                     const char *value)
{
	int fd, tries;
	gssize nwrote;
	gssize len;
	char *actual;
	gs_free char *actual_free = NULL;
	int errsv;

	if (dirfd < 0) {
		pathid = path;

		fd = open (path, O_WRONLY | O_TRUNC | O_CLOEXEC);
		if (fd == -1) {
			errsv = errno;
			if (errsv == ENOENT) {
				_LOGD ("sysctl: failed to open '%s': (%d) %s",
				       pathid, errsv, nm_strerror_native (errsv));
			} else {
				_LOGE ("sysctl: failed to open '%s': (%d) %s",
				       pathid, errsv, nm_strerror_native (errsv));
			}
			errno = errsv;
			return FALSE;
		}
	} else {
		fd = openat (dirfd, path, O_WRONLY | O_TRUNC | O_CLOEXEC);
		if (fd == -1) {
			errsv = errno;
			if (errsv == ENOENT) {
				_LOGD ("sysctl: failed to openat '%s': (%d) %s",
				       pathid, errsv, nm_strerror_native (errsv));
			} else {
				_LOGE ("sysctl: failed to openat '%s': (%d) %s",
				       pathid, errsv, nm_strerror_native (errsv));
			}
			errno = errsv;
			return FALSE;
		}
	}

	_log_dbg_sysctl_set (platform, pathid, dirfd, path, value);

	/* Most sysfs and sysctl options don't care about a trailing LF, while some
	 * (like infiniband) do.  So always add the LF.  Also, neither sysfs nor
	 * sysctl support partial writes so the LF must be added to the string we're
	 * about to write.
	 */
	len = strlen (value) + 1;
	nm_assert (len > 0);
	if (len > 512)
		actual = actual_free = g_malloc (len + 1);
	else
		actual = g_alloca (len + 1);
	memcpy (actual, value, len - 1);
	actual[len - 1] = '\n';
	actual[len] = '\0';

	/* Try to write the entire value three times if a partial write occurs */
	errsv = 0;
	for (tries = 0, nwrote = 0; tries < 3 && nwrote < len - 1; tries++) {
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
	if (nwrote == -1) {
		NMLogLevel level = LOGL_ERR;

		if (errsv == EEXIST) {
			level = LOGL_DEBUG;
		} else if (   errsv == EINVAL
		           && nm_utils_sysctl_ip_conf_is_path (AF_INET6, path, NULL, "mtu")) {
			/* setting the MTU can fail under regular conditions. Suppress
			 * logging a warning. */
			level = LOGL_DEBUG;
		}

		_NMLOG (level, "sysctl: failed to set '%s' to '%s': (%d) %s",
		        path, value, errsv, nm_strerror_native (errsv));
	} else if (nwrote < len - 1) {
		_LOGE ("sysctl: failed to set '%s' to '%s' after three attempts",
		       path, value);
	}

	if (nwrote < len - 1) {
		if (nm_close (fd) != 0) {
			if (errsv != 0)
				errno = errsv;
		} else if (errsv != 0)
			errno = errsv;
		else
			errno = EIO;
		return FALSE;
	}
	if (nm_close (fd) != 0) {
		/* errno is already properly set. */
		return FALSE;
	}

	/* success. errno is undefined (no need to set). */
	return TRUE;
}

#undef NM_THREAD_SAFE_ON_MAIN_THREAD
#define NM_THREAD_SAFE_ON_MAIN_THREAD 1

/*****************************************************************************/

static gboolean
sysctl_set (NMPlatform *platform,
            const char *pathid,
            int dirfd,
            const char *path,
            const char *value)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;

	g_return_val_if_fail (path, FALSE);
	g_return_val_if_fail (value, FALSE);

	ASSERT_SYSCTL_ARGS (pathid, dirfd, path);

	if (   dirfd < 0
	    && !nm_platform_netns_push (platform, &netns)) {
		errno = ENETDOWN;
		return FALSE;
	}

	return sysctl_set_internal (platform, pathid, dirfd, path, value);
}

typedef struct {
	NMPlatform *platform;
	char *pathid;
	int dirfd;
	char *path;
	char **values;
	GCancellable *cancellable;
	NMPlatformAsyncCallback callback;
	gpointer callback_data;
} SysctlAsyncInfo;

static void
sysctl_async_info_free (SysctlAsyncInfo *info)
{
	g_object_unref (info->platform);
	g_free (info->pathid);
	if (info->dirfd >= 0)
		nm_close (info->dirfd);
	g_free (info->path);
	g_strfreev (info->values);
	g_object_unref (info->cancellable);
	g_slice_free (SysctlAsyncInfo, info);
}

static void
sysctl_async_cb (GObject *object,
                 GAsyncResult *res,
                 gpointer user_data)
{
	NMPlatform *platform;
	GTask *task = G_TASK (res);
	SysctlAsyncInfo *info;
	gs_free_error GError *error = NULL;
	gs_free char *values_str = NULL;

	info = g_task_get_task_data (task);

	if (g_task_propagate_boolean (task, &error)) {
		platform = info->platform;
		_LOGD ("sysctl: successfully set-async '%s' to values '%s'",
		       info->pathid ?: info->path,
		       (values_str = g_strjoinv (", ", info->values)));
	}

	if (info->callback)
		info->callback (error, info->callback_data);
}

static void
sysctl_async_thread_fn (GTask *task,
                        gpointer source_object,
                        gpointer task_data,
                        GCancellable *cancellable)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	SysctlAsyncInfo *info = task_data;
	GError *error = NULL;
	char **value;

	if (g_task_return_error_if_cancelled (task))
		return;

	if (   info->dirfd < 0
	    && !nm_platform_netns_push (info->platform, &netns)) {
		g_set_error_literal (&error,
		                     NM_UTILS_ERROR,
		                     NM_UTILS_ERROR_UNKNOWN,
		                     "sysctl: failed changing namespace");
		g_task_return_error (task, error);
		return;
	}

	for (value = info->values; *value; value++) {
		if (!sysctl_set_internal (info->platform,
		                          info->pathid,
		                          info->dirfd,
		                          info->path,
		                          *value)) {
			g_set_error (&error,
			             NM_UTILS_ERROR,
			             NM_UTILS_ERROR_UNKNOWN,
			             "sysctl: failed setting '%s' to value '%s': %s",
			             info->pathid ?: info->path,
			             *value,
			             nm_strerror_native (errno));
			g_task_return_error (task, error);
			return;
		}
		if (g_task_return_error_if_cancelled (task))
			return;
	}
	g_task_return_boolean (task, TRUE);
}

static void
sysctl_set_async_return_idle (gpointer user_data,
                              GCancellable *cancellable)
{
	gs_unref_object NMPlatform *platform = NULL;
	gs_free_error GError *cancelled_error = NULL;
	gs_free_error GError *error = NULL;
	NMPlatformAsyncCallback callback;
	gpointer callback_data;

	nm_utils_user_data_unpack (user_data, &platform, &callback, &callback_data, &error);
	g_cancellable_set_error_if_cancelled (cancellable, &cancelled_error);
	callback (cancelled_error ?: error, callback_data);
}

static void
sysctl_set_async (NMPlatform *platform,
                  const char *pathid,
                  int dirfd,
                  const char *path,
                  const char *const *values,
                  NMPlatformAsyncCallback callback,
                  gpointer data,
                  GCancellable *cancellable)
{
	SysctlAsyncInfo *info;
	GTask *task;
	int dirfd_dup, errsv;
	gpointer packed;
	GError *error = NULL;

	g_return_if_fail (platform);
	g_return_if_fail (path);
	g_return_if_fail (values && values[0]);
	g_return_if_fail (cancellable);
	g_return_if_fail (!data || callback);

	ASSERT_SYSCTL_ARGS (pathid, dirfd, path);

	if (dirfd >= 0) {
		dirfd_dup = fcntl (dirfd, F_DUPFD_CLOEXEC, 0);
		if (dirfd_dup < 0) {
			if (!callback)
				return;
			errsv = errno;
			g_set_error (&error,
			             NM_UTILS_ERROR,
			             NM_UTILS_ERROR_UNKNOWN,
			             "sysctl: failure duplicating directory fd: %s",
			             nm_strerror_native (errsv));
			packed = nm_utils_user_data_pack (g_object_ref (platform),
			                                  callback,
			                                  data,
			                                  error);
			nm_utils_invoke_on_idle (sysctl_set_async_return_idle,
			                         packed,
			                         cancellable);
			return;
		}
	} else
		dirfd_dup = -1;

	info = g_slice_new0 (SysctlAsyncInfo);
	info->platform = g_object_ref (platform);
	info->pathid = g_strdup (pathid);
	info->dirfd = dirfd_dup;
	info->path = g_strdup (path);
	info->values = g_strdupv ((char **) values);
	info->callback = callback;
	info->callback_data = data;
	info->cancellable = g_object_ref (cancellable);

	task = g_task_new (platform, cancellable, sysctl_async_cb, NULL);
	g_task_set_task_data (task, info, (GDestroyNotify) sysctl_async_info_free);
	g_task_set_return_on_cancel (task, FALSE);
	g_task_run_in_thread (task, sysctl_async_thread_fn);
	g_object_unref (task);
}

static GSList *sysctl_clear_cache_list;

void
_nm_logging_clear_platform_logging_cache (void)
{
	while (sysctl_clear_cache_list) {
		NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (sysctl_clear_cache_list->data);

		sysctl_clear_cache_list = g_slist_delete_link (sysctl_clear_cache_list, sysctl_clear_cache_list);

		g_hash_table_destroy (priv->sysctl_get_prev_values);
		priv->sysctl_get_prev_values = NULL;
	}
}

typedef struct {
	const char *path;
	CList lst;
	char *value;
	char path_data[];
} SysctlCacheEntry;

static void
sysctl_cache_entry_free (SysctlCacheEntry *entry)
{
	c_list_unlink_stale (&entry->lst);
	g_free (entry->value);
	g_free (entry);
}

static void
_log_dbg_sysctl_get_impl (NMPlatform *platform, const char *pathid, const char *contents)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	SysctlCacheEntry *entry = NULL;

	if (!priv->sysctl_get_prev_values) {
		sysctl_clear_cache_list = g_slist_prepend (sysctl_clear_cache_list, platform);
		c_list_init (&priv->sysctl_list);
		priv->sysctl_get_prev_values = g_hash_table_new_full (nm_pstr_hash,
		                                                      nm_pstr_equal,
		                                                      (GDestroyNotify) sysctl_cache_entry_free,
		                                                      NULL);
	} else
		entry = g_hash_table_lookup (priv->sysctl_get_prev_values, &pathid);

	if (entry) {
		if (!nm_streq (entry->value, contents)) {
			gs_free char *contents_escaped = g_strescape (contents, NULL);
			gs_free char *prev_value_escaped = g_strescape (entry->value, NULL);

			_LOGD ("sysctl: reading '%s': '%s' (changed from '%s' on last read)", pathid, contents_escaped, prev_value_escaped);
			g_free (entry->value);
			entry->value = g_strdup (contents);
		}
		nm_c_list_move_front (&priv->sysctl_list, &entry->lst);
	} else {
		gs_free char *contents_escaped = g_strescape (contents, NULL);
		SysctlCacheEntry *old;
		size_t len;

		len = strlen (pathid);
		entry = g_malloc (sizeof (SysctlCacheEntry) + len + 1);
		entry->value = g_strdup (contents);
		entry->path = entry->path_data;
		memcpy (entry->path_data, pathid, len + 1);

		/* Remove oldest entry when the cache becomes too big */
		if (g_hash_table_size (priv->sysctl_get_prev_values) > 1000) {
			old = c_list_last_entry (&priv->sysctl_list, SysctlCacheEntry, lst);
			g_hash_table_remove (priv->sysctl_get_prev_values, old);
		}

		_LOGD ("sysctl: reading '%s': '%s'", pathid, contents_escaped);

		g_hash_table_add (priv->sysctl_get_prev_values, entry);
		c_list_link_front (&priv->sysctl_list, &entry->lst);
	}
}

#define _log_dbg_sysctl_get(platform, pathid, contents) \
	G_STMT_START { \
		if (_LOGD_ENABLED ()) \
			_log_dbg_sysctl_get_impl (platform, pathid, contents); \
	} G_STMT_END

static char *
sysctl_get (NMPlatform *platform, const char *pathid, int dirfd, const char *path)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	GError *error = NULL;
	gs_free char *contents = NULL;

	ASSERT_SYSCTL_ARGS (pathid, dirfd, path);

	if (dirfd < 0) {
		if (!nm_platform_netns_push (platform, &netns)) {
			errno = EBUSY;
			return NULL;
		}
		pathid = path;
	}

	if (!nm_utils_file_get_contents (dirfd,
	                                 path,
	                                 1*1024*1024,
	                                 NM_UTILS_FILE_GET_CONTENTS_FLAG_NONE,
	                                 &contents,
	                                 NULL,
	                                 NULL,
	                                 &error)) {
		NMLogLevel log_level = LOGL_ERR;
		int errsv = EBUSY;

		if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			errsv = ENOENT;
			log_level = LOGL_DEBUG;
		} else if (   g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NODEV)
		           || g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_FAILED)) {
			/* We assume FAILED means EOPNOTSUP and don't log a error message. */
			log_level = LOGL_DEBUG;
		}

		_NMLOG (log_level, "error reading %s: %s", pathid, error->message);
		g_clear_error (&error);
		errno = errsv;
		return NULL;
	}

	g_strstrip (contents);

	_log_dbg_sysctl_get (platform, pathid, contents);

	/* errno is left undefined (as we don't return NULL). */
	return g_steal_pointer (&contents);
}

/*****************************************************************************/

static void
process_events (NMPlatform *platform)
{
	delayed_action_handle_all (platform, TRUE);
}

/*****************************************************************************/

static const RefreshAllInfo *
refresh_all_type_get_info (RefreshAllType refresh_all_type)
{
	static const RefreshAllInfo infos[] = {
#define R(_refresh_all_type, _obj_type, _addr_family) [_refresh_all_type] = { .obj_type = _obj_type, .addr_family = _addr_family, }
		R (REFRESH_ALL_TYPE_LINKS,             NMP_OBJECT_TYPE_LINK,         AF_UNSPEC),
		R (REFRESH_ALL_TYPE_IP4_ADDRESSES,     NMP_OBJECT_TYPE_IP4_ADDRESS,  AF_UNSPEC),
		R (REFRESH_ALL_TYPE_IP6_ADDRESSES,     NMP_OBJECT_TYPE_IP6_ADDRESS,  AF_UNSPEC),
		R (REFRESH_ALL_TYPE_IP4_ROUTES,        NMP_OBJECT_TYPE_IP4_ROUTE,    AF_UNSPEC),
		R (REFRESH_ALL_TYPE_IP6_ROUTES,        NMP_OBJECT_TYPE_IP6_ROUTE,    AF_UNSPEC),
		R (REFRESH_ALL_TYPE_ROUTING_RULES_IP4, NMP_OBJECT_TYPE_ROUTING_RULE, AF_INET),
		R (REFRESH_ALL_TYPE_ROUTING_RULES_IP6, NMP_OBJECT_TYPE_ROUTING_RULE, AF_INET6),
		R (REFRESH_ALL_TYPE_QDISCS,            NMP_OBJECT_TYPE_QDISC,        AF_UNSPEC),
		R (REFRESH_ALL_TYPE_TFILTERS,          NMP_OBJECT_TYPE_TFILTER,      AF_UNSPEC),
#undef R
	};

	nm_assert (_NM_INT_NOT_NEGATIVE (refresh_all_type));
	nm_assert (refresh_all_type < G_N_ELEMENTS (infos));
	nm_assert (nmp_class_from_type (infos[refresh_all_type].obj_type));

	return &infos[refresh_all_type];
}

_NM_UTILS_LOOKUP_DEFINE (static, delayed_action_type_to_refresh_all_type, DelayedActionType, RefreshAllType,
	NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT (0),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS,             REFRESH_ALL_TYPE_LINKS),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES,     REFRESH_ALL_TYPE_IP4_ADDRESSES),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES,     REFRESH_ALL_TYPE_IP6_ADDRESSES),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES,        REFRESH_ALL_TYPE_IP4_ROUTES),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,        REFRESH_ALL_TYPE_IP6_ROUTES),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_IP4, REFRESH_ALL_TYPE_ROUTING_RULES_IP4),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_IP6, REFRESH_ALL_TYPE_ROUTING_RULES_IP6),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_QDISCS,            REFRESH_ALL_TYPE_QDISCS),
	NM_UTILS_LOOKUP_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_TFILTERS,          REFRESH_ALL_TYPE_TFILTERS),
	NM_UTILS_LOOKUP_ITEM_IGNORE_OTHER (),
);

static DelayedActionType
delayed_action_type_from_refresh_all_type (RefreshAllType refresh_all_type)
{
	DelayedActionType t;

	nm_assert (refresh_all_type_get_info (refresh_all_type));

	t = (((DelayedActionType) 1) << refresh_all_type);

	nm_assert (refresh_all_type == delayed_action_type_to_refresh_all_type (t));

	return t;
}

static RefreshAllType
refresh_all_type_from_needle_object (const NMPObject *obj_needle)
{
	switch (NMP_OBJECT_GET_TYPE (obj_needle)) {
	case NMP_OBJECT_TYPE_LINK:        return REFRESH_ALL_TYPE_LINKS;
	case NMP_OBJECT_TYPE_IP4_ADDRESS: return REFRESH_ALL_TYPE_IP4_ADDRESSES;
	case NMP_OBJECT_TYPE_IP6_ADDRESS: return REFRESH_ALL_TYPE_IP6_ADDRESSES;
	case NMP_OBJECT_TYPE_IP4_ROUTE:   return REFRESH_ALL_TYPE_IP4_ROUTES;
	case NMP_OBJECT_TYPE_IP6_ROUTE:   return REFRESH_ALL_TYPE_IP6_ROUTES;
	case NMP_OBJECT_TYPE_QDISC:       return REFRESH_ALL_TYPE_QDISCS;
	case NMP_OBJECT_TYPE_TFILTER:     return REFRESH_ALL_TYPE_TFILTERS;
	case NMP_OBJECT_TYPE_ROUTING_RULE:
		switch (NMP_OBJECT_CAST_ROUTING_RULE (obj_needle)->addr_family) {
		case AF_INET:  return REFRESH_ALL_TYPE_ROUTING_RULES_IP4;
		case AF_INET6: return REFRESH_ALL_TYPE_ROUTING_RULES_IP6;
		}
		nm_assert_not_reached ();
		return 0;
	default:
		nm_assert_not_reached ();
		return 0;
	}
}

static const NMPLookup *
refresh_all_type_init_lookup (RefreshAllType refresh_all_type,
                              NMPLookup *lookup)
{
	const RefreshAllInfo *refresh_all_info;

	nm_assert (lookup);

	refresh_all_info = refresh_all_type_get_info (refresh_all_type);

	nm_assert (refresh_all_info);

	if (NM_IN_SET (refresh_all_info->obj_type, NMP_OBJECT_TYPE_ROUTING_RULE)) {
		return nmp_lookup_init_object_by_addr_family (lookup,
		                                              refresh_all_info->obj_type,
		                                              refresh_all_info->addr_family);
	}

	/* not yet implemented. */
	nm_assert (refresh_all_info->addr_family == AF_UNSPEC);

	return nmp_lookup_init_obj_type (lookup,
	                                 refresh_all_info->obj_type);
}

static DelayedActionType
delayed_action_refresh_from_needle_object (const NMPObject *obj_needle)
{
	return delayed_action_type_from_refresh_all_type (refresh_all_type_from_needle_object (obj_needle));
}

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (delayed_action_to_string, DelayedActionType,
	NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT ("unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS,             "refresh-all-links"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES,     "refresh-all-ip4-addresses"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES,     "refresh-all-ip6-addresses"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES,        "refresh-all-ip4-routes"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,        "refresh-all-ip6-routes"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_IP4, "refresh-all-routing-rules-ip4"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_IP6, "refresh-all-routing-rules-ip6"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_QDISCS,            "refresh-all-qdiscs"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_ALL_TFILTERS,          "refresh-all-tfilters"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_REFRESH_LINK,                  "refresh-link"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_MASTER_CONNECTED,              "master-connected"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_READ_NETLINK,                  "read-netlink"),
	NM_UTILS_LOOKUP_STR_ITEM (DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE,          "wait-for-nl-response"),
	NM_UTILS_LOOKUP_ITEM_IGNORE (DELAYED_ACTION_TYPE_NONE),
	NM_UTILS_LOOKUP_ITEM_IGNORE (DELAYED_ACTION_TYPE_REFRESH_ALL),
	NM_UTILS_LOOKUP_ITEM_IGNORE (DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_ALL),
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
			gint64 timeout = data->timeout_abs_ns - nm_utils_get_monotonic_timestamp_nsec ();
			char b[255];

			nm_utils_strbuf_append (&buf, &buf_size, " (seq %u, timeout in %s%"G_GINT64_FORMAT".%09"G_GINT64_FORMAT", response-type %d%s%s)",
			                        data->seq_number,
			                        timeout < 0 ? "-" : "",
			                        (timeout < 0 ? -timeout : timeout) / NM_UTILS_NSEC_PER_SEC,
			                        (timeout < 0 ? -timeout : timeout) % NM_UTILS_NSEC_PER_SEC,
			                        (int) data->response_type,
			                        data->seq_result ? ", " : "",
			                        data->seq_result ? wait_for_nl_response_to_string (data->seq_result, NULL, b, sizeof (b)) : "");
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
	RefreshAllType refresh_all_type;

	nm_assert (nm_utils_is_power_of_two (action_type));
	nm_assert (NM_FLAGS_ANY (action_type, DELAYED_ACTION_TYPE_REFRESH_ALL));
	nm_assert (!NM_FLAGS_ANY (action_type, ~DELAYED_ACTION_TYPE_REFRESH_ALL));

	if (NM_FLAGS_ANY (priv->delayed_action.flags, action_type))
		return TRUE;

	refresh_all_type = delayed_action_type_to_refresh_all_type (action_type);
	return (priv->delayed_action.refresh_all_in_progress[refresh_all_type] > 0);
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
	switch (data->response_type) {
	case DELAYED_ACTION_RESPONSE_TYPE_VOID:
		break;
	case DELAYED_ACTION_RESPONSE_TYPE_REFRESH_ALL_IN_PROGRESS:
		if (data->response.out_refresh_all_in_progress) {
			nm_assert (*data->response.out_refresh_all_in_progress > 0);
			*data->response.out_refresh_all_in_progress -= 1;
			data->response.out_refresh_all_in_progress = NULL;
		}
		break;
	case DELAYED_ACTION_RESPONSE_TYPE_ROUTE_GET:
		if (data->response.out_route_get) {
			nm_assert (!*data->response.out_route_get);
			data->response.out_route_get = NULL;
		}
		break;
	}

	g_array_remove_index_fast (priv->delayed_action.list_wait_for_nl_response, idx);
}

static void
delayed_action_wait_for_nl_response_complete_check (NMPlatform *platform,
                                                    WaitForNlResponseResult force_result,
                                                    guint32 *out_next_seq_number,
                                                    gint64 *out_next_timeout_abs_ns,
                                                    gint64 *p_now_ns)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	guint i;
	guint32 next_seq_number = 0;
	gint64 next_timeout_abs_ns = 0;
	int now_ns = 0;

	for (i = 0; i < priv->delayed_action.list_wait_for_nl_response->len; ) {
		const DelayedActionWaitForNlResponseData *data = &g_array_index (priv->delayed_action.list_wait_for_nl_response, DelayedActionWaitForNlResponseData, i);

		if (data->seq_result)
			delayed_action_wait_for_nl_response_complete (platform, i, data->seq_result);
		else if (   p_now_ns
		         && ((now_ns ?: (now_ns = nm_utils_get_monotonic_timestamp_nsec ())) >= data->timeout_abs_ns)) {
			/* the caller can optionally check for timeout by providing a p_now_ns argument. */
			delayed_action_wait_for_nl_response_complete (platform, i, WAIT_FOR_NL_RESPONSE_RESULT_FAILED_TIMEOUT);
		} else if (force_result != WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN)
			delayed_action_wait_for_nl_response_complete (platform, i, force_result);
		else {
			if (   next_seq_number == 0
			    || next_timeout_abs_ns > data->timeout_abs_ns) {
				next_seq_number = data->seq_number;
				next_timeout_abs_ns = data->timeout_abs_ns;
			}
			i++;
		}
	}

	if (force_result != WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN) {
		nm_assert (!NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE));
		nm_assert (priv->delayed_action.list_wait_for_nl_response->len == 0);
	}

	NM_SET_OUT (out_next_seq_number, next_seq_number);
	NM_SET_OUT (out_next_timeout_abs_ns, next_timeout_abs_ns);
	NM_SET_OUT (p_now_ns, now_ns);
}

static void
delayed_action_wait_for_nl_response_complete_all (NMPlatform *platform,
                                                  WaitForNlResponseResult fallback_result)
{
	delayed_action_wait_for_nl_response_complete_check (platform,
	                                                    fallback_result,
	                                                    NULL,
	                                                    NULL,
	                                                    NULL);
}

/*****************************************************************************/

static void
delayed_action_handle_MASTER_CONNECTED (NMPlatform *platform, int master_ifindex)
{
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	nm_auto_nmpobj const NMPObject *obj_new = NULL;
	NMPCacheOpsType cache_op;

	cache_op = nmp_cache_update_link_master_connected (nm_platform_get_cache (platform), master_ifindex, &obj_old, &obj_new);
	if (cache_op == NMP_CACHE_OPS_UNCHANGED)
		return;
	cache_on_change (platform, cache_op, obj_old, obj_new);
	nm_platform_cache_update_emit_signal (platform, cache_op, obj_old, obj_new);
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
		nm_assert (_nm_utils_ptrarray_find_first ((gconstpointer *) priv->delayed_action.list_master_connected->pdata, priv->delayed_action.list_master_connected->len, user_data) < 0);

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
			FOR_EACH_DELAYED_ACTION (iflags, flags)
				_LOGt_delayed_action (iflags, NULL, "handle");
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
		nm_assert (_nm_utils_ptrarray_find_first ((gconstpointer *) priv->delayed_action.list_refresh_link->pdata, priv->delayed_action.list_refresh_link->len, user_data) < 0);

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

	cache_prune_all (platform);

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
		if (_nm_utils_ptrarray_find_first ((gconstpointer *) priv->delayed_action.list_refresh_link->pdata, priv->delayed_action.list_refresh_link->len, user_data) < 0)
			g_ptr_array_add (priv->delayed_action.list_refresh_link, user_data);
		break;
	case DELAYED_ACTION_TYPE_MASTER_CONNECTED:
		if (_nm_utils_ptrarray_find_first ((gconstpointer *) priv->delayed_action.list_master_connected->pdata, priv->delayed_action.list_master_connected->len, user_data) < 0)
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
		FOR_EACH_DELAYED_ACTION (iflags, action_type)
			_LOGt_delayed_action (iflags, user_data, "schedule");
	}
}

static void
delayed_action_schedule_WAIT_FOR_NL_RESPONSE (NMPlatform *platform,
                                              guint32 seq_number,
                                              WaitForNlResponseResult *out_seq_result,
                                              char **out_errmsg,
                                              DelayedActionWaitForNlResponseType response_type,
                                              gpointer response_out_data)
{
	DelayedActionWaitForNlResponseData data = {
		.seq_number = seq_number,
		.timeout_abs_ns = nm_utils_get_monotonic_timestamp_nsec () + (200 * (NM_UTILS_NSEC_PER_SEC / 1000)),
		.out_seq_result = out_seq_result,
		.out_errmsg = out_errmsg,
		.response_type = response_type,
		.response.out_data = response_out_data,
	};

	delayed_action_schedule (platform,
	                         DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE,
	                         &data);
}

/*****************************************************************************/

static void
cache_prune_one_type (NMPlatform *platform,
                      const NMPLookup *lookup)
{
	NMDedupMultiIter iter;
	const NMPObject *obj;
	NMPCacheOpsType cache_op;
	NMPCache *cache = nm_platform_get_cache (platform);

	nm_dedup_multi_iter_init (&iter,
	                          nmp_cache_lookup (cache,
	                                            lookup));
	while (nm_dedup_multi_iter_next (&iter)) {
		const NMDedupMultiEntry *main_entry;

		/* we only track the dirty flag for the OBJECT-TYPE index. That means,
		 * for other lookup types we need to check the dirty flag of the main-entry. */
		main_entry = nmp_cache_reresolve_main_entry (cache, iter.current, lookup);
		if (!main_entry->dirty)
			continue;

		obj = main_entry->obj;

		_LOGt ("cache-prune: prune %s", nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_ALL, NULL, 0));

		{
			nm_auto_nmpobj const NMPObject *obj_old = NULL;

			cache_op = nmp_cache_remove (cache, obj, TRUE, TRUE, &obj_old);
			nm_assert (cache_op == NMP_CACHE_OPS_REMOVED);
			cache_on_change (platform, cache_op, obj_old, NULL);
			nm_platform_cache_update_emit_signal (platform, cache_op, obj_old, NULL);
		}
	}
}

static void
cache_prune_all (NMPlatform *platform)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	RefreshAllType refresh_all_type;

	for (refresh_all_type = _REFRESH_ALL_TYPE_FIRST; refresh_all_type < _REFRESH_ALL_TYPE_NUM; refresh_all_type++) {
		NMPLookup lookup;

		if (priv->pruning[refresh_all_type] == 0)
			continue;
		priv->pruning[refresh_all_type] -= 1;
		if (priv->pruning[refresh_all_type] > 0)
			continue;
		refresh_all_type_init_lookup (refresh_all_type,
		                              &lookup);
		cache_prune_one_type (platform, &lookup);
	}
}

static void
cache_on_change (NMPlatform *platform,
                 NMPCacheOpsType cache_op,
                 const NMPObject *obj_old,
                 const NMPObject *obj_new)
{
	const NMPClass *klass;
	char str_buf[sizeof (_nm_utils_to_string_buffer)];
	char str_buf2[sizeof (_nm_utils_to_string_buffer)];
	NMPCache *cache = nm_platform_get_cache (platform);

	ASSERT_nmp_cache_ops (cache, cache_op, obj_old, obj_new);
	nm_assert (cache_op != NMP_CACHE_OPS_UNCHANGED);

	klass = obj_old ? NMP_OBJECT_GET_CLASS (obj_old) : NMP_OBJECT_GET_CLASS (obj_new);

	_LOGt ("update-cache-%s: %s: %s%s%s",
	       klass->obj_type_name,
	       (cache_op == NMP_CACHE_OPS_UPDATED
	           ? "UPDATE"
	           : (cache_op == NMP_CACHE_OPS_REMOVED
	                 ? "REMOVE"
	                 : (cache_op == NMP_CACHE_OPS_ADDED) ? "ADD" : "???")),
	       (cache_op != NMP_CACHE_OPS_ADDED
	           ? nmp_object_to_string (obj_old, NMP_OBJECT_TO_STRING_ALL, str_buf2, sizeof (str_buf2))
	           : nmp_object_to_string (obj_new, NMP_OBJECT_TO_STRING_ALL, str_buf2, sizeof (str_buf2))),
	       (cache_op == NMP_CACHE_OPS_UPDATED) ? " -> " : "",
	       (cache_op == NMP_CACHE_OPS_UPDATED
	           ? nmp_object_to_string (obj_new, NMP_OBJECT_TO_STRING_ALL, str_buf, sizeof (str_buf))
	           : ""));

	switch (klass->obj_type) {
	case NMP_OBJECT_TYPE_LINK:
		{
			/* check whether changing a slave link can cause a master link (bridge or bond) to go up/down */
			if (   obj_old
			    && nmp_cache_link_connected_needs_toggle_by_ifindex (cache, obj_old->link.master, obj_new, obj_old))
				delayed_action_schedule (platform, DELAYED_ACTION_TYPE_MASTER_CONNECTED, GINT_TO_POINTER (obj_old->link.master));
			if (   obj_new
			    && (!obj_old || obj_old->link.master != obj_new->link.master)
			    && nmp_cache_link_connected_needs_toggle_by_ifindex (cache, obj_new->link.master, obj_new, obj_old))
				delayed_action_schedule (platform, DELAYED_ACTION_TYPE_MASTER_CONNECTED, GINT_TO_POINTER (obj_new->link.master));
		}
		{
			/* check whether we are about to change a master link that needs toggling connected state. */
			if (   obj_new /* <-- nonsensical, make coverity happy */
			    && nmp_cache_link_connected_needs_toggle (cache, obj_new, obj_new, obj_old))
				delayed_action_schedule (platform, DELAYED_ACTION_TYPE_MASTER_CONNECTED, GINT_TO_POINTER (obj_new->link.ifindex));
		}
		{
			int ifindex = 0;

			/* if we remove a link (from netlink), we must refresh the addresses, routes, qdiscs and tfilters */
			if (   cache_op == NMP_CACHE_OPS_REMOVED
			    && obj_old /* <-- nonsensical, make coverity happy */)
				ifindex = obj_old->link.ifindex;
			else if (   cache_op == NMP_CACHE_OPS_UPDATED
			         && obj_old && obj_new /* <-- nonsensical, make coverity happy */
			         && !obj_new->_link.netlink.is_in_netlink
			         && obj_new->_link.netlink.is_in_netlink != obj_old->_link.netlink.is_in_netlink)
				ifindex = obj_new->link.ifindex;

			if (ifindex > 0) {
				delayed_action_schedule (platform,
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES |
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES |
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES |
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES |
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_ALL |
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_QDISCS |
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_TFILTERS,
				                         NULL);
			}
		}
		{
			int ifindex = -1;

			/* removal of a link could be caused by moving the link to another netns.
			 * In this case, we potentially have to update other links that have this link as parent.
			 * Currently, kernel misses to sent us a notification in this case
			 * (https://bugzilla.redhat.com/show_bug.cgi?id=1262908). */

			if (   cache_op == NMP_CACHE_OPS_REMOVED
			    && obj_old /* <-- nonsensical, make coverity happy */
			    && obj_old->_link.netlink.is_in_netlink)
				ifindex = obj_old->link.ifindex;
			else if (   cache_op == NMP_CACHE_OPS_UPDATED
			         && obj_old && obj_new /* <-- nonsensical, make coverity happy */
			         && obj_old->_link.netlink.is_in_netlink
			         && !obj_new->_link.netlink.is_in_netlink)
				ifindex = obj_new->link.ifindex;

			if (ifindex > 0) {
				NMPLookup lookup;
				NMDedupMultiIter iter;
				const NMPlatformLink *l;

				nmp_lookup_init_obj_type (&lookup, NMP_OBJECT_TYPE_LINK);
				nmp_cache_iter_for_each_link (&iter,
				                              nmp_cache_lookup (cache, &lookup),
				                              &l) {
					if (l->parent == ifindex)
						delayed_action_schedule (platform, DELAYED_ACTION_TYPE_REFRESH_LINK, GINT_TO_POINTER (l->ifindex));
				}
			}
		}
		{
			/* if a link goes down, we must refresh routes */
			if (   cache_op == NMP_CACHE_OPS_UPDATED
			    && obj_old && obj_new /* <-- nonsensical, make coverity happy */
			    && obj_old->_link.netlink.is_in_netlink
			    && obj_new->_link.netlink.is_in_netlink
			    && (   (   NM_FLAGS_HAS (obj_old->link.n_ifi_flags, IFF_UP)
			            && !NM_FLAGS_HAS (obj_new->link.n_ifi_flags, IFF_UP))
			        || (   NM_FLAGS_HAS (obj_old->link.n_ifi_flags, IFF_LOWER_UP)
			            && !NM_FLAGS_HAS (obj_new->link.n_ifi_flags, IFF_LOWER_UP)))) {
				/* FIXME: I suspect that IFF_LOWER_UP must not be considered, and I
				 * think kernel does send RTM_DELROUTE events for IPv6 routes, so
				 * we might not need to refresh IPv6 routes. */
				delayed_action_schedule (platform,
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES |
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,
				                         NULL);
			}
		}
		if (   NM_IN_SET (cache_op, NMP_CACHE_OPS_ADDED, NMP_CACHE_OPS_UPDATED)
		    && (obj_new && obj_new->_link.netlink.is_in_netlink)
		    && (!obj_old || !obj_old->_link.netlink.is_in_netlink))
		{
			gboolean re_request_link = FALSE;
			const NMPlatformLnkTun *lnk_tun;

			if (   !obj_new->_link.netlink.lnk
			    && NM_IN_SET (obj_new->link.type, NM_LINK_TYPE_GRE,
			                                      NM_LINK_TYPE_GRETAP,
			                                      NM_LINK_TYPE_IP6TNL,
			                                      NM_LINK_TYPE_IP6GRE,
			                                      NM_LINK_TYPE_IP6GRETAP,
			                                      NM_LINK_TYPE_INFINIBAND,
			                                      NM_LINK_TYPE_MACVLAN,
			                                      NM_LINK_TYPE_MACVLAN,
			                                      NM_LINK_TYPE_SIT,
			                                      NM_LINK_TYPE_TUN,
			                                      NM_LINK_TYPE_VLAN,
			                                      NM_LINK_TYPE_VXLAN)) {
				/* certain link-types also come with a IFLA_INFO_DATA/lnk_data. It may happen that
				 * kernel didn't send this notification, thus when we first learn about a link
				 * that lacks an lnk_data we re-request it again.
				 *
				 * For example https://bugzilla.redhat.com/show_bug.cgi?id=1284001 */
				re_request_link = TRUE;
			} else if (   obj_new->link.type == NM_LINK_TYPE_TUN
			           && obj_new->_link.netlink.lnk
			           && (lnk_tun = &(obj_new->_link.netlink.lnk)->lnk_tun)
			           && !lnk_tun->persist
			           && lnk_tun->pi
			           && !lnk_tun->vnet_hdr
			           && !lnk_tun->multi_queue
			           && !lnk_tun->owner_valid
			           && !lnk_tun->group_valid) {
				/* kernel has/had a know issue that the first notification for TUN device would
				 * be sent with invalid parameters. The message looks like that kind, so refetch
				 * it. */
				re_request_link = TRUE;
			} else if (   obj_new->link.type == NM_LINK_TYPE_VETH
			           && obj_new->link.parent == 0) {
				/* the initial notification when adding a veth pair can lack the parent/IFLA_LINK
				 * (https://bugzilla.redhat.com/show_bug.cgi?id=1285827).
				 * Request it again. */
				re_request_link = TRUE;
			} else if (   obj_new->link.type == NM_LINK_TYPE_ETHERNET
			           && obj_new->link.l_address.len == 0) {
				/* Due to a kernel bug, we sometimes receive spurious NEWLINK
				 * messages after a wifi interface has disappeared. Since the
				 * link is not present anymore we can't determine its type and
				 * thus it will show up as a Ethernet one, with no address
				 * specified.  Request the link again to check if it really
				 * exists.  https://bugzilla.redhat.com/show_bug.cgi?id=1302037
				 */
				re_request_link = TRUE;
			}
			if (re_request_link) {
				delayed_action_schedule (platform,
				                         DELAYED_ACTION_TYPE_REFRESH_LINK,
				                         GINT_TO_POINTER (obj_new->link.ifindex));
			}
		}
		{
			/* on enslave/release, we also refresh the master. */
			int ifindex1 = 0, ifindex2 = 0;
			gboolean changed_master, changed_connected;

			changed_master =    (obj_new && obj_new->_link.netlink.is_in_netlink && obj_new->link.master > 0 ? obj_new->link.master : 0)
			                 != (obj_old && obj_old->_link.netlink.is_in_netlink && obj_old->link.master > 0 ? obj_old->link.master : 0);
			changed_connected =    (obj_new && obj_new->_link.netlink.is_in_netlink ? NM_FLAGS_HAS (obj_new->link.n_ifi_flags, IFF_LOWER_UP) : 2)
			                    != (obj_old && obj_old->_link.netlink.is_in_netlink ? NM_FLAGS_HAS (obj_old->link.n_ifi_flags, IFF_LOWER_UP) : 2);

			if (changed_master || changed_connected) {
				ifindex1 = (obj_old && obj_old->_link.netlink.is_in_netlink && obj_old->link.master > 0) ? obj_old->link.master : 0;
				ifindex2 = (obj_new && obj_new->_link.netlink.is_in_netlink && obj_new->link.master > 0) ? obj_new->link.master : 0;

				if (ifindex1 > 0)
					delayed_action_schedule (platform, DELAYED_ACTION_TYPE_REFRESH_LINK, GINT_TO_POINTER (ifindex1));
				if (ifindex2 > 0 && ifindex1 != ifindex2)
					delayed_action_schedule (platform, DELAYED_ACTION_TYPE_REFRESH_LINK, GINT_TO_POINTER (ifindex2));
			}
		}
		break;
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
		{
			/* Address deletion is sometimes accompanied by route deletion. We need to
			 * check all routes belonging to the same interface. */
			if (cache_op == NMP_CACHE_OPS_REMOVED) {
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

/*****************************************************************************/

static guint32
_nlh_seq_next_get (NMLinuxPlatformPrivate *priv)
{
	/* generate a new sequence number, but never return zero.
	 * Wrapping numbers are not a problem, because we don't rely
	 * on strictly increasing sequence numbers. */
	return (++priv->nlh_seq_next) ?: (++priv->nlh_seq_next);
}

/**
 * _nl_send_nlmsghdr:
 * @platform:
 * @nlhdr:
 * @out_seq_result:
 * @response_type:
 * @response_out_data:
 *
 * Returns: 0 on success or a negative errno.
 */
static int
_nl_send_nlmsghdr (NMPlatform *platform,
                   struct nlmsghdr *nlhdr,
                   WaitForNlResponseResult *out_seq_result,
                   char **out_errmsg,
                   DelayedActionWaitForNlResponseType response_type,
                   gpointer response_out_data)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	guint32 seq;
	int errsv;

	nm_assert (nlhdr);

	seq = _nlh_seq_next_get (priv);
	nlhdr->nlmsg_seq = seq;

	{
		struct sockaddr_nl nladdr = {
			.nl_family = AF_NETLINK,
		};
		struct iovec iov = {
			.iov_base = nlhdr,
			.iov_len = nlhdr->nlmsg_len
		};
		struct msghdr msg = {
			.msg_name = &nladdr,
			.msg_namelen = sizeof (nladdr),
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};
		int try_count;

		if (!nlhdr->nlmsg_pid)
			nlhdr->nlmsg_pid = nl_socket_get_local_port (priv->nlh);
		nlhdr->nlmsg_flags |= (NLM_F_REQUEST | NLM_F_ACK);

		try_count = 0;
again:
		errsv = sendmsg (nl_socket_get_fd (priv->nlh), &msg, 0);
		if (errsv < 0) {
			errsv = errno;
			if (errsv == EINTR && try_count++ < 100)
				goto again;
			_LOGD ("netlink: nl-send-nlmsghdr: failed sending message: %s (%d)", nm_strerror_native (errsv), errsv);
			return -nm_errno_from_native (errsv);
		}
	}

	delayed_action_schedule_WAIT_FOR_NL_RESPONSE (platform, seq, out_seq_result, out_errmsg,
	                                              response_type, response_out_data);
	return 0;
}

/**
 * _nl_send_nlmsg:
 * @platform:
 * @nlmsg:
 * @out_seq_result:
 * @response_type:
 * @response_out_data:
 *
 * Returns: 0 on success, or a negative libnl3 error code (beware, it's not an errno).
 */
static int
_nl_send_nlmsg (NMPlatform *platform,
                struct nl_msg *nlmsg,
                WaitForNlResponseResult *out_seq_result,
                char **out_errmsg,
                DelayedActionWaitForNlResponseType response_type,
                gpointer response_out_data)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	struct nlmsghdr *nlhdr;
	guint32 seq;
	int nle;

	nlhdr = nlmsg_hdr (nlmsg);
	seq = _nlh_seq_next_get (priv);
	nlhdr->nlmsg_seq = seq;

	nle = nl_send_auto (priv->nlh, nlmsg);
	if (nle < 0) {
		_LOGD ("netlink: nl-send-nlmsg: failed sending message: %s (%d)", nm_strerror (nle), nle);
		return nle;
	}

	delayed_action_schedule_WAIT_FOR_NL_RESPONSE (platform, seq, out_seq_result, out_errmsg,
	                                              response_type, response_out_data);
	return 0;
}

static void
do_request_link_no_delayed_actions (NMPlatform *platform, int ifindex, const char *name)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	int nle;

	if (name && !name[0])
		name = NULL;

	g_return_if_fail (ifindex > 0 || name);

	_LOGD ("do-request-link: %d %s", ifindex, name ?: "");

	if (ifindex > 0) {
		const NMDedupMultiEntry *entry;

		entry = nmp_cache_lookup_entry_link (nm_platform_get_cache (platform), ifindex);
		if (entry) {
			priv->pruning[REFRESH_ALL_TYPE_LINKS] += 1;
			nm_dedup_multi_entry_set_dirty (entry, TRUE);
		}
	}

	event_handler_read_netlink (platform, FALSE);

	nlmsg = _nl_msg_new_link (RTM_GETLINK,
	                          0,
	                          ifindex,
	                          name);
	if (nlmsg) {
		nle = _nl_send_nlmsg (platform, nlmsg, NULL, NULL, DELAYED_ACTION_RESPONSE_TYPE_VOID, NULL);
		if (nle < 0) {
			_LOGE ("do-request-link: %d %s: failed sending netlink request \"%s\" (%d)",
			       ifindex, name ?: "",
			       nm_strerror (nle), -nle);
			return;
		}
	}
}

static void
do_request_link (NMPlatform *platform, int ifindex, const char *name)
{
	do_request_link_no_delayed_actions (platform, ifindex, name);
	delayed_action_handle_all (platform, FALSE);
}

static struct nl_msg *
_nl_msg_new_dump (NMPObjectType obj_type,
                  int preferred_addr_family)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	const NMPClass *klass;

	klass = nmp_class_from_type (obj_type);

	nm_assert (klass);
	nm_assert (klass->rtm_gettype > 0);

	nlmsg = nlmsg_alloc_simple (klass->rtm_gettype, NLM_F_DUMP);

	if (klass->addr_family != AF_UNSPEC) {
		/* if the class specifies a particular address family, then it is preferred. */
		nm_assert (NM_IN_SET (preferred_addr_family, AF_UNSPEC, klass->addr_family));
		preferred_addr_family = klass->addr_family;
	}

	switch (klass->obj_type) {
	case NMP_OBJECT_TYPE_QDISC:
	case NMP_OBJECT_TYPE_TFILTER:
		{
			const struct tcmsg tcmsg = {
				.tcm_family = preferred_addr_family,
			};

			if (nlmsg_append_struct (nlmsg, &tcmsg) < 0)
				g_return_val_if_reached (NULL);
		}
		break;
	case NMP_OBJECT_TYPE_LINK:
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
	case NMP_OBJECT_TYPE_IP4_ROUTE:
	case NMP_OBJECT_TYPE_IP6_ROUTE:
	case NMP_OBJECT_TYPE_ROUTING_RULE:
		{
			const struct rtgenmsg gmsg = {
				.rtgen_family = preferred_addr_family,
			};

			if (nlmsg_append_struct (nlmsg, &gmsg) < 0)
				g_return_val_if_reached (NULL);
		}
		break;
	default:
		g_return_val_if_reached (NULL);
	}

	return g_steal_pointer (&nlmsg);
}

static void
do_request_all_no_delayed_actions (NMPlatform *platform, DelayedActionType action_type)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	DelayedActionType action_type_prune;
	DelayedActionType iflags;

	nm_assert (!NM_FLAGS_ANY (action_type, ~DELAYED_ACTION_TYPE_REFRESH_ALL));
	action_type &= DELAYED_ACTION_TYPE_REFRESH_ALL;

	action_type_prune = action_type;

	/* calling nmp_cache_dirty_set_all_main() with a non-main lookup-index requires an extra
	 * cache lookup for every entry.
	 *
	 * Avoid that, by special casing routing-rules here. */
	if (NM_FLAGS_ALL (action_type_prune, DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_ALL)) {
		NMPLookup lookup;

		priv->pruning[REFRESH_ALL_TYPE_ROUTING_RULES_IP4] += 1;
		priv->pruning[REFRESH_ALL_TYPE_ROUTING_RULES_IP6] += 1;
		nmp_lookup_init_obj_type (&lookup, NMP_OBJECT_TYPE_ROUTING_RULE);
		nmp_cache_dirty_set_all_main (nm_platform_get_cache (platform),
		                              &lookup);
		action_type_prune &= ~DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_ALL;
	}

	FOR_EACH_DELAYED_ACTION (iflags, action_type_prune) {
		RefreshAllType refresh_all_type = delayed_action_type_to_refresh_all_type (iflags);
		NMPLookup lookup;

		priv->pruning[refresh_all_type] += 1;
		refresh_all_type_init_lookup (refresh_all_type,
		                              &lookup);
		nmp_cache_dirty_set_all_main (nm_platform_get_cache (platform),
		                              &lookup);
	}

	FOR_EACH_DELAYED_ACTION (iflags, action_type) {
		RefreshAllType refresh_all_type = delayed_action_type_to_refresh_all_type (iflags);
		const RefreshAllInfo *refresh_all_info = refresh_all_type_get_info (refresh_all_type);
		nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
		int *out_refresh_all_in_progress;

		out_refresh_all_in_progress = &priv->delayed_action.refresh_all_in_progress[refresh_all_type];
		nm_assert (*out_refresh_all_in_progress >= 0);
		*out_refresh_all_in_progress += 1;

		/* clear any delayed action that request a refresh of this object type. */
		priv->delayed_action.flags &= ~iflags;
		_LOGt_delayed_action (iflags, NULL, "handle (do-request-all)");

		if (refresh_all_type == REFRESH_ALL_TYPE_LINKS) {
			nm_assert (   (priv->delayed_action.list_refresh_link->len > 0)
			           == NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_REFRESH_LINK));
			if (NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_REFRESH_LINK)) {
				_LOGt_delayed_action (DELAYED_ACTION_TYPE_REFRESH_LINK, NULL, "clear (do-request-all)");
				priv->delayed_action.flags &= ~DELAYED_ACTION_TYPE_REFRESH_LINK;
				g_ptr_array_set_size (priv->delayed_action.list_refresh_link, 0);
			}
		}

		event_handler_read_netlink (platform, FALSE);

		nlmsg = _nl_msg_new_dump (refresh_all_info->obj_type,
		                          refresh_all_info->addr_family);
		if (!nlmsg)
			goto next_after_fail;

		if (_nl_send_nlmsg (platform,
		                    nlmsg,
		                    NULL,
		                    NULL,
		                    DELAYED_ACTION_RESPONSE_TYPE_REFRESH_ALL_IN_PROGRESS,
		                    out_refresh_all_in_progress) < 0)
			goto next_after_fail;

		continue;

next_after_fail:
		nm_assert (*out_refresh_all_in_progress > 0);
		*out_refresh_all_in_progress -= 1;
	}
}

static void
do_request_one_type_by_needle_object (NMPlatform *platform, const NMPObject *obj_needle)
{
	do_request_all_no_delayed_actions (platform, delayed_action_refresh_from_needle_object (obj_needle));
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

			if (   data->response_type == DELAYED_ACTION_RESPONSE_TYPE_REFRESH_ALL_IN_PROGRESS
			    && data->response.out_refresh_all_in_progress
			    && data->seq_number == priv->nlh_seq_last_seen) {
				*data->response.out_refresh_all_in_progress -= 1;
				data->response.out_refresh_all_in_progress = NULL;
				break;
			}
		}
	}

	priv->nlh_seq_last_seen = seq_number;
}

static void
event_seq_check (NMPlatform *platform, guint32 seq_number, WaitForNlResponseResult seq_result, const char *msg)
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
					/* we already saw an error for this sequence number.
					 * Preserve it. */
				} else if (   seq_result != WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_UNKNOWN
				           || data->seq_result == WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN)
					data->seq_result = seq_result;
				if (data->out_errmsg && !*data->out_errmsg)
					*data->out_errmsg = g_strdup (msg);
				return;
			}
		}
	}

#if NM_MORE_LOGGING
	if (seq_number != priv->nlh_seq_last_handled)
		_LOGt ("netlink: recvmsg: unwaited sequence number %u", seq_number);
	priv->nlh_seq_last_handled = seq_number;
#endif
}

static void
event_valid_msg (NMPlatform *platform, struct nl_msg *msg, gboolean handle_events)
{
	NMLinuxPlatformPrivate *priv;
	nm_auto_nmpobj NMPObject *obj = NULL;
	NMPCacheOpsType cache_op;
	struct nlmsghdr *msghdr;
	char buf_nlmsghdr[400];
	gboolean is_del = FALSE;
	gboolean is_dump = FALSE;
	NMPCache *cache = nm_platform_get_cache (platform);

	msghdr = nlmsg_hdr (msg);

	if (   !_nm_platform_kernel_support_detected (NM_PLATFORM_KERNEL_SUPPORT_TYPE_EXTENDED_IFA_FLAGS)
	    && msghdr->nlmsg_type == RTM_NEWADDR) {
		/* IFA_FLAGS is set for IPv4 and IPv6 addresses. It was added first to IPv6,
		 * but if we encounter an IPv4 address with IFA_FLAGS, we surely have support. */
		if (   nlmsg_valid_hdr (msghdr, sizeof (struct ifaddrmsg))
		    && NM_IN_SET (((struct ifaddrmsg *) nlmsg_data (msghdr))->ifa_family,
		                  AF_INET,
		                  AF_INET6)) {
			/* see if the nl_msg contains the IFA_FLAGS attribute. If it does,
			 * we assume, that the kernel supports extended flags, IFA_F_MANAGETEMPADDR
			 * and IFA_F_NOPREFIXROUTE for IPv6. They were added together in kernel 3.14,
			 * dated 30 March, 2014.
			 *
			 * For IPv4, IFA_F_NOPREFIXROUTE was added later, but there is no easy
			 * way to detect kernel support. */
			_nm_platform_kernel_support_init (NM_PLATFORM_KERNEL_SUPPORT_TYPE_EXTENDED_IFA_FLAGS,
			                                    !!nlmsg_find_attr (msghdr, sizeof (struct ifaddrmsg), IFA_FLAGS)
			                                  ? 1
			                                  : -1);
		}
	}

	if (!handle_events)
		return;

	if (NM_IN_SET (msghdr->nlmsg_type, RTM_DELLINK,
	                                   RTM_DELADDR,
	                                   RTM_DELROUTE,
	                                   RTM_DELRULE,
	                                   RTM_DELQDISC,
	                                   RTM_DELTFILTER)) {
		/* The event notifies about a deleted object. We don't need to initialize all
		 * fields of the object. */
		is_del = TRUE;
	}

	obj = nmp_object_new_from_nl (platform, cache, msg, is_del);
	if (!obj) {
		_LOGT ("event-notification: %s: ignore",
		       nl_nlmsghdr_to_str (msghdr, buf_nlmsghdr, sizeof (buf_nlmsghdr)));
		return;
	}

	if (   !is_del
	    && NM_IN_SET (msghdr->nlmsg_type, RTM_NEWADDR,
	                                      RTM_NEWLINK,
	                                      RTM_NEWROUTE,
	                                      RTM_NEWRULE,
	                                      RTM_NEWQDISC,
	                                      RTM_NEWTFILTER)) {
		is_dump = delayed_action_refresh_all_in_progress (platform,
		                                                  delayed_action_refresh_from_needle_object (obj));
	}

	_LOGT ("event-notification: %s%s: %s",
	       nl_nlmsghdr_to_str (msghdr, buf_nlmsghdr, sizeof (buf_nlmsghdr)),
	       is_dump ? ", in-dump" : "",
	       nmp_object_to_string (obj,
	                             is_del ? NMP_OBJECT_TO_STRING_ID : NMP_OBJECT_TO_STRING_PUBLIC,
	                             NULL, 0));

	{
		nm_auto_nmpobj const NMPObject *obj_old = NULL;
		nm_auto_nmpobj const NMPObject *obj_new = NULL;

		switch (msghdr->nlmsg_type) {

		case RTM_GETLINK:
		case RTM_NEWADDR:
		case RTM_NEWLINK:
		case RTM_NEWQDISC:
		case RTM_NEWRULE:
		case RTM_NEWTFILTER:
			cache_op = nmp_cache_update_netlink (cache, obj, is_dump, &obj_old, &obj_new);
			if (cache_op != NMP_CACHE_OPS_UNCHANGED) {
				cache_on_change (platform, cache_op, obj_old, obj_new);
				nm_platform_cache_update_emit_signal (platform, cache_op, obj_old, obj_new);
			}
			break;

		case RTM_NEWROUTE: {
			nm_auto_nmpobj const NMPObject *obj_replace = NULL;
			gboolean resync_required = FALSE;
			gboolean only_dirty = FALSE;
			gboolean is_ipv6;

			/* IPv4 routes that are a response to RTM_GETROUTE must have
			 * the cloned flag while IPv6 routes don't have to. */
			is_ipv6 = NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_IP6_ROUTE;
			if (is_ipv6 || NM_FLAGS_HAS (obj->ip_route.r_rtm_flags, RTM_F_CLONED)) {
				nm_assert (is_ipv6 || !nmp_object_is_alive (obj));
				priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
				if (NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE)) {
					guint i;

					nm_assert (priv->delayed_action.list_wait_for_nl_response->len > 0);
					for (i = 0; i < priv->delayed_action.list_wait_for_nl_response->len; i++) {
						DelayedActionWaitForNlResponseData *data = &g_array_index (priv->delayed_action.list_wait_for_nl_response, DelayedActionWaitForNlResponseData, i);

						if (   data->response_type == DELAYED_ACTION_RESPONSE_TYPE_ROUTE_GET
						    && data->response.out_route_get) {
							nm_assert (!*data->response.out_route_get);
							if (data->seq_number == nlmsg_hdr (msg)->nlmsg_seq) {
								*data->response.out_route_get = nmp_object_clone (obj, FALSE);
								data->response.out_route_get = NULL;
								break;
							}
						}
					}
				}
			}

			cache_op = nmp_cache_update_netlink_route (cache,
			                                           obj,
			                                           is_dump,
			                                           msghdr->nlmsg_flags,
			                                           &obj_old,
			                                           &obj_new,
			                                           &obj_replace,
			                                           &resync_required);
			if (cache_op != NMP_CACHE_OPS_UNCHANGED) {
				if (obj_replace) {
					const NMDedupMultiEntry *entry_replace;

					/* we found an object that is to be replaced by the RTM_NEWROUTE message.
					 * While we invoke the signal, the platform cache might change and invalidate
					 * the findings. Mitigate that (for the most part), by marking the entry as
					 * dirty and only delete @obj_replace if it is still dirty afterwards.
					 *
					 * Yes, there is a tiny tiny chance for still getting it wrong. But in practice,
					 * the signal handlers do not cause to call the platform again, so the cache
					 * is not really changing. -- if they would, it would anyway be dangerous to overflow
					 * the stack and it's not ensured that the processing of netlink messages is
					 * reentrant (maybe it is).
					 */
					entry_replace = nmp_cache_lookup_entry (cache, obj_replace);
					nm_assert (entry_replace && entry_replace->obj == obj_replace);
					nm_dedup_multi_entry_set_dirty (entry_replace, TRUE);
					only_dirty = TRUE;
				}
				cache_on_change (platform, cache_op, obj_old, obj_new);
				nm_platform_cache_update_emit_signal (platform, cache_op, obj_old, obj_new);
			}

			if (obj_replace) {
				/* the RTM_NEWROUTE message indicates that another route was replaced.
				 * Remove it now. */
				cache_op = nmp_cache_remove (cache, obj_replace, TRUE, only_dirty, NULL);
				if (cache_op != NMP_CACHE_OPS_UNCHANGED) {
					nm_assert (cache_op == NMP_CACHE_OPS_REMOVED);
					cache_on_change (platform, cache_op, obj_replace, NULL);
					nm_platform_cache_update_emit_signal (platform, cache_op, obj_replace, NULL);
				}
			}

			if (resync_required) {
				/* we'd like to avoid such resyncs as they are expensive and we should only rely on the
				 * netlink events. This needs investigation. */
				_LOGT ("schedule resync of routes after RTM_NEWROUTE");
				delayed_action_schedule (platform,
				                         delayed_action_refresh_from_needle_object (obj),
				                         NULL);
			}
			break;
		}

		case RTM_DELADDR:
		case RTM_DELLINK:
		case RTM_DELQDISC:
		case RTM_DELROUTE:
		case RTM_DELRULE:
		case RTM_DELTFILTER:
			cache_op = nmp_cache_remove_netlink (cache, obj, &obj_old, &obj_new);
			if (cache_op != NMP_CACHE_OPS_UNCHANGED) {
				cache_on_change (platform, cache_op, obj_old, obj_new);
				nm_platform_cache_update_emit_signal (platform, cache_op, obj_old, obj_new);
			}
			break;
		default:
			break;
		}
	}
}

/*****************************************************************************/

static int
do_add_link_with_lookup (NMPlatform *platform,
                         NMLinkType link_type,
                         const char *name,
                         struct nl_msg *nlmsg,
                         const NMPlatformLink **out_link)
{
	const NMPObject *obj = NULL;
	WaitForNlResponseResult seq_result = WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN;
	gs_free char *errmsg = NULL;
	int nle;
	char s_buf[256];
	NMPCache *cache = nm_platform_get_cache (platform);

	event_handler_read_netlink (platform, FALSE);

	nle = _nl_send_nlmsg (platform, nlmsg, &seq_result, &errmsg, DELAYED_ACTION_RESPONSE_TYPE_VOID, NULL);
	if (nle < 0) {
		_LOGE ("do-add-link[%s/%s]: failed sending netlink request \"%s\" (%d)",
		       name,
		       nm_link_type_to_string (link_type),
		       nm_strerror (nle), -nle);
		NM_SET_OUT (out_link, NULL);
		return nle;
	}

	delayed_action_handle_all (platform, FALSE);

	nm_assert (seq_result);

	_NMLOG (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK
	            ? LOGL_DEBUG
	            : LOGL_WARN,
	        "do-add-link[%s/%s]: %s",
	        name,
	        nm_link_type_to_string (link_type),
	        wait_for_nl_response_to_string (seq_result, errmsg, s_buf, sizeof (s_buf)));

	if (out_link) {
		obj = nmp_cache_lookup_link_full (cache, 0, name, FALSE, link_type, NULL, NULL);
		*out_link = NMP_OBJECT_CAST_LINK (obj);
	}

	return wait_for_nl_response_to_nmerr (seq_result);
}

static int
do_add_addrroute (NMPlatform *platform,
                  const NMPObject *obj_id,
                  struct nl_msg *nlmsg,
                  gboolean suppress_netlink_failure)
{
	WaitForNlResponseResult seq_result = WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN;
	gs_free char *errmsg = NULL;
	int nle;
	char s_buf[256];

	nm_assert (NM_IN_SET (NMP_OBJECT_GET_TYPE (obj_id),
	                      NMP_OBJECT_TYPE_IP4_ADDRESS, NMP_OBJECT_TYPE_IP6_ADDRESS,
	                      NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE));

	event_handler_read_netlink (platform, FALSE);

	nle = _nl_send_nlmsg (platform, nlmsg, &seq_result, &errmsg, DELAYED_ACTION_RESPONSE_TYPE_VOID, NULL);
	if (nle < 0) {
		_LOGE ("do-add-%s[%s]: failure sending netlink request \"%s\" (%d)",
		       NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name,
		       nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0),
		       nm_strerror (nle), -nle);
		return -NME_PL_NETLINK;
	}

	delayed_action_handle_all (platform, FALSE);

	nm_assert (seq_result);

	_NMLOG ((   seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK
	         || (   suppress_netlink_failure
	             && seq_result < 0))
	            ? LOGL_DEBUG
	            : LOGL_WARN,
	        "do-add-%s[%s]: %s",
	        NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name,
	        nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0),
	        wait_for_nl_response_to_string (seq_result, errmsg, s_buf, sizeof (s_buf)));

	if (NMP_OBJECT_GET_TYPE (obj_id) == NMP_OBJECT_TYPE_IP6_ADDRESS) {
		/* In rare cases, the object is not yet ready as we received the ACK from
		 * kernel. Need to refetch.
		 *
		 * We want to safe the expensive refetch, thus we look first into the cache
		 * whether the object exists.
		 *
		 * rh#1484434 */
		if (!nmp_cache_lookup_obj (nm_platform_get_cache (platform), obj_id))
			do_request_one_type_by_needle_object (platform, obj_id);
	}

	return wait_for_nl_response_to_nmerr (seq_result);
}

static gboolean
do_delete_object (NMPlatform *platform, const NMPObject *obj_id, struct nl_msg *nlmsg)
{
	WaitForNlResponseResult seq_result = WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN;
	gs_free char *errmsg = NULL;
	int nle;
	char s_buf[256];
	gboolean success;
	const char *log_detail = "";

	event_handler_read_netlink (platform, FALSE);

	nle = _nl_send_nlmsg (platform, nlmsg, &seq_result, &errmsg, DELAYED_ACTION_RESPONSE_TYPE_VOID, NULL);
	if (nle < 0) {
		_LOGE ("do-delete-%s[%s]: failure sending netlink request \"%s\" (%d)",
		       NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name,
		       nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0),
		       nm_strerror (nle), -nle);
		return FALSE;
	}

	delayed_action_handle_all (platform, FALSE);

	nm_assert (seq_result);

	success = TRUE;
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

	_NMLOG (success ? LOGL_DEBUG : LOGL_WARN,
	        "do-delete-%s[%s]: %s%s",
	        NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name,
	        nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0),
	        wait_for_nl_response_to_string (seq_result, errmsg, s_buf, sizeof (s_buf)),
	        log_detail);

	if (NM_IN_SET (NMP_OBJECT_GET_TYPE (obj_id),
	               NMP_OBJECT_TYPE_IP6_ADDRESS,
	               NMP_OBJECT_TYPE_QDISC,
	               NMP_OBJECT_TYPE_TFILTER)) {
		/* In rare cases, the object is still there after we receive the ACK from
		 * kernel. Need to refetch.
		 *
		 * We want to safe the expensive refetch, thus we look first into the cache
		 * whether the object exists.
		 *
		 * rh#1484434 */
		if (nmp_cache_lookup_obj (nm_platform_get_cache (platform), obj_id))
			do_request_one_type_by_needle_object (platform, obj_id);
	}

	return success;
}

static int
do_change_link (NMPlatform *platform,
                ChangeLinkType change_link_type,
                int ifindex,
                struct nl_msg *nlmsg,
                const ChangeLinkData *data)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	int nle;
	WaitForNlResponseResult seq_result = WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN;
	gs_free char *errmsg = NULL;
	char s_buf[256];
	int result = 0;
	NMLogLevel log_level = LOGL_DEBUG;
	const char *log_result = "failure";
	const char *log_detail = "";
	gs_free char *log_detail_free = NULL;
	const NMPObject *obj_cache;

	if (!nm_platform_netns_push (platform, &netns)) {
		log_level = LOGL_ERR;
		log_detail = ", failure to change network namespace";
		goto out;
	}

retry:
	nle = _nl_send_nlmsg (platform, nlmsg, &seq_result, &errmsg, DELAYED_ACTION_RESPONSE_TYPE_VOID, NULL);
	if (nle < 0) {
		log_level = LOGL_ERR;
		log_detail_free = g_strdup_printf (", failure sending netlink request: %s (%d)",
		                                   nm_strerror (nle), -nle);
		log_detail = log_detail_free;
		goto out;
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
		result = -NME_PL_NO_FIRMWARE;
	} else if (   NM_IN_SET (-((int) seq_result), ERANGE)
	           && change_link_type == CHANGE_LINK_TYPE_SET_MTU) {
		log_detail = ", setting MTU to requested size is not possible";
		result = -NME_PL_CANT_SET_MTU;
	} else if (   NM_IN_SET (-((int) seq_result), ENFILE)
	           && change_link_type == CHANGE_LINK_TYPE_SET_ADDRESS
	           && (obj_cache = nmp_cache_lookup_link (nm_platform_get_cache (platform), ifindex))
	           && obj_cache->link.l_address.len == data->set_address.length
	           && memcmp (obj_cache->link.l_address.data, data->set_address.address, data->set_address.length) == 0) {
		/* workaround ENFILE which may be wrongly returned (bgo #770456).
		 * If the MAC address is as expected, assume success? */
		log_result = "success";
		log_detail = " (assume success changing address)";
		result = 0;
	} else if (NM_IN_SET (-((int) seq_result), ENODEV)) {
		log_level = LOGL_DEBUG;
		result = -NME_PL_NOT_FOUND;
	} else if (-((int) seq_result) == EAFNOSUPPORT) {
		log_level = LOGL_DEBUG;
		result = -NME_PL_OPNOTSUPP;
	} else {
		log_level = LOGL_WARN;
		result = -NME_UNSPEC;
	}

out:
	_NMLOG (log_level,
	        "do-change-link[%d]: %s changing link: %s%s",
	        ifindex,
	        log_result,
	        wait_for_nl_response_to_string (seq_result, errmsg, s_buf, sizeof (s_buf)),
	        log_detail);
	return result;
}

static int
link_add (NMPlatform *platform,
          NMLinkType type,
          const char *name,
          int parent,
          const void *address,
          size_t address_len,
          gconstpointer extra_data,
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

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          NLM_F_CREATE | NLM_F_EXCL,
	                          0,
	                          name);
	if (!nlmsg)
		return -NME_UNSPEC;

	if (parent > 0)
		NLA_PUT_U32 (nlmsg, IFLA_LINK, parent);

	if (address && address_len)
		NLA_PUT (nlmsg, IFLA_ADDRESS, address_len, address);

	if (!_nl_msg_new_link_set_linkinfo (nlmsg, type, extra_data))
		return -NME_UNSPEC;

	return do_add_link_with_lookup (platform, type, name, nlmsg, out_link);
nla_put_failure:
	g_return_val_if_reached (-NME_BUG);
}

static gboolean
link_delete (NMPlatform *platform, int ifindex)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	NMPObject obj_id;
	const NMPObject *obj;

	obj = nmp_cache_lookup_link (nm_platform_get_cache (platform), ifindex);
	if (!obj || !obj->_link.netlink.is_in_netlink)
		return FALSE;

	nlmsg = _nl_msg_new_link (RTM_DELLINK,
	                          0,
	                          ifindex,
	                          NULL);

	nmp_object_stackinit_id_link (&obj_id, ifindex);
	return do_delete_object (platform, &obj_id, nlmsg);
}

static gboolean
link_refresh (NMPlatform *platform, int ifindex)
{
	do_request_link (platform, ifindex, NULL);
	return !!nm_platform_link_get_obj (platform, ifindex, TRUE);
}

static gboolean
link_set_netns (NMPlatform *platform,
                int ifindex,
                int netns_fd)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL);
	if (!nlmsg)
		return FALSE;

	NLA_PUT (nlmsg, IFLA_NET_NS_FD, 4, &netns_fd);
	return (do_change_link (platform, CHANGE_LINK_TYPE_UNSPEC, ifindex, nlmsg, NULL) >= 0);

nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static int
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

	nlmsg = _nl_msg_new_link_full (RTM_NEWLINK,
	                               0,
	                               ifindex,
	                               NULL,
	                               AF_UNSPEC,
	                               flags_mask,
	                               flags_set);
	if (!nlmsg)
		return -NME_UNSPEC;
	return do_change_link (platform, CHANGE_LINK_TYPE_UNSPEC, ifindex, nlmsg, NULL);
}

static gboolean
link_set_up (NMPlatform *platform, int ifindex, gboolean *out_no_firmware)
{
	int r;

	r = link_change_flags (platform, ifindex, IFF_UP, IFF_UP);
	NM_SET_OUT (out_no_firmware, (r == -NME_PL_NO_FIRMWARE));
	return r >= 0;
}

static gboolean
link_set_down (NMPlatform *platform, int ifindex)
{
	return (link_change_flags (platform, ifindex, IFF_UP, 0) >= 0);
}

static gboolean
link_set_arp (NMPlatform *platform, int ifindex)
{
	return (link_change_flags (platform, ifindex, IFF_NOARP, 0) >= 0);
}

static gboolean
link_set_noarp (NMPlatform *platform, int ifindex)
{
	return (link_change_flags (platform, ifindex, IFF_NOARP, IFF_NOARP) >= 0);
}

static const char *
link_get_udi (NMPlatform *platform, int ifindex)
{
	const NMPObject *obj = nm_platform_link_get_obj (platform, ifindex, TRUE);

	if (   !obj
	    || !obj->_link.netlink.is_in_netlink
	    || !obj->_link.udev.device)
		return NULL;
	return udev_device_get_syspath (obj->_link.udev.device);
}

static int
link_set_user_ipv6ll_enabled (NMPlatform *platform, int ifindex, gboolean enabled)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	guint8 mode = enabled ? NM_IN6_ADDR_GEN_MODE_NONE : NM_IN6_ADDR_GEN_MODE_EUI64;

	_LOGD ("link: change %d: user-ipv6ll: set IPv6 address generation mode to %s",
	       ifindex,
	       nm_platform_link_inet6_addrgenmode2str (mode, NULL, 0));

	if (!nm_platform_kernel_support_get (NM_PLATFORM_KERNEL_SUPPORT_TYPE_USER_IPV6LL)) {
		_LOGD ("link: change %d: user-ipv6ll: not supported", ifindex);
		return -NME_PL_OPNOTSUPP;
	}

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL);
	if (   !nlmsg
	    || !_nl_msg_new_link_set_afspec (nlmsg, mode, NULL))
		g_return_val_if_reached (-NME_BUG);

	return do_change_link (platform, CHANGE_LINK_TYPE_UNSPEC, ifindex, nlmsg, NULL);
}

static gboolean
link_set_token (NMPlatform *platform, int ifindex, NMUtilsIPv6IfaceId iid)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	char sbuf[NM_UTILS_INET_ADDRSTRLEN];

	_LOGD ("link: change %d: token: set IPv6 address generation token to %s",
	       ifindex, nm_utils_inet6_interface_identifier_to_token (iid, sbuf));

	nlmsg = _nl_msg_new_link (RTM_NEWLINK, 0, ifindex, NULL);
	if (!nlmsg || !_nl_msg_new_link_set_afspec (nlmsg, -1, &iid))
		g_return_val_if_reached (FALSE);

	return (do_change_link (platform, CHANGE_LINK_TYPE_UNSPEC, ifindex, nlmsg, NULL) >= 0);
}

static gboolean
link_supports_carrier_detect (NMPlatform *platform, int ifindex)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;

	if (!nm_platform_netns_push (platform, &netns))
		return FALSE;

	/* We use netlink for the actual carrier detection, but netlink can't tell
	 * us whether the device actually supports carrier detection in the first
	 * place. We assume any device that does implements one of these two APIs.
	 */
	return    nmp_utils_ethtool_supports_carrier_detect (ifindex)
	       || nmp_utils_mii_supports_carrier_detect (ifindex);
}

static gboolean
link_supports_vlans (NMPlatform *platform, int ifindex)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	const NMPObject *obj;

	obj = nm_platform_link_get_obj (platform, ifindex, TRUE);

	/* Only ARPHRD_ETHER links can possibly support VLANs. */
	if (!obj || obj->link.arptype != ARPHRD_ETHER)
		return FALSE;

	if (!nm_platform_netns_push (platform, &netns))
		return FALSE;

	return nmp_utils_ethtool_supports_vlans (ifindex);
}

static gboolean
link_supports_sriov (NMPlatform *platform, int ifindex)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	nm_auto_close int dirfd = -1;
	char ifname[IFNAMSIZ];
	int total = -1;

	if (!nm_platform_netns_push (platform, &netns))
		return FALSE;

	dirfd = nm_platform_sysctl_open_netdir (platform, ifindex, ifname);
	if (dirfd < 0)
		return FALSE;

	total = nm_platform_sysctl_get_int32 (platform,
	                                      NMP_SYSCTL_PATHID_NETDIR (dirfd,
	                                                                ifname,
	                                                                "device/sriov_totalvfs"),
	                                      -1);

	return total > 0;
}

static int
link_set_address (NMPlatform *platform, int ifindex, gconstpointer address, size_t length)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	const ChangeLinkData d = {
		.set_address = {
			.address = address,
			.length = length,
		},
	};

	if (!address || !length)
		g_return_val_if_reached (-NME_BUG);

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL);
	if (!nlmsg)
		g_return_val_if_reached (-NME_BUG);

	NLA_PUT (nlmsg, IFLA_ADDRESS, length, address);

	return do_change_link (platform, CHANGE_LINK_TYPE_SET_ADDRESS, ifindex, nlmsg, &d);
nla_put_failure:
	g_return_val_if_reached (-NME_BUG);
}

static int
link_set_name (NMPlatform *platform, int ifindex, const char *name)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL);
	if (!nlmsg)
		g_return_val_if_reached (-NME_BUG);

	NLA_PUT (nlmsg, IFLA_IFNAME, strlen (name) + 1, name);

	return (do_change_link (platform, CHANGE_LINK_TYPE_UNSPEC, ifindex, nlmsg, NULL) >= 0);
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

	return nmp_utils_ethtool_get_permanent_address (ifindex, buf, length);
}

static int
link_set_mtu (NMPlatform *platform, int ifindex, guint32 mtu)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL);
	if (!nlmsg)
		return FALSE;

	NLA_PUT_U32 (nlmsg, IFLA_MTU, mtu);

	return do_change_link (platform, CHANGE_LINK_TYPE_SET_MTU, ifindex, nlmsg, NULL);
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static void
sriov_idle_cb (gpointer user_data,
               GCancellable *cancellable)
{
	gs_unref_object NMPlatform *platform = NULL;
	gs_free_error GError *cancelled_error = NULL;
	gs_free_error GError *error = NULL;
	NMPlatformAsyncCallback callback;
	gpointer callback_data;

	g_cancellable_set_error_if_cancelled (cancellable, &cancelled_error);
	nm_utils_user_data_unpack (user_data, &platform, &error, &callback, &callback_data);
	callback (cancelled_error ?: error, callback_data);
}

static void
link_set_sriov_params_async (NMPlatform *platform,
                             int ifindex,
                             guint num_vfs,
                             NMTernary autoprobe,
                             NMPlatformAsyncCallback callback,
                             gpointer data,
                             GCancellable *cancellable)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	gs_free_error GError *error = NULL;
	nm_auto_close int dirfd = -1;
	int current_autoprobe;
	guint i, total;
	gint64 current_num;
	char ifname[IFNAMSIZ];
	gpointer packed;
	const char *values[3];
	char buf[64];

	g_return_if_fail (callback || !data);
	g_return_if_fail (cancellable);

	if (!nm_platform_netns_push (platform, &netns)) {
		g_set_error_literal (&error,
		                     NM_UTILS_ERROR,
		                     NM_UTILS_ERROR_UNKNOWN,
		                     "couldn't change namespace");
		goto out_idle;
	}

	dirfd = nm_platform_sysctl_open_netdir (platform, ifindex, ifname);
	if (!dirfd) {
		g_set_error_literal (&error,
		                     NM_UTILS_ERROR,
		                     NM_UTILS_ERROR_UNKNOWN,
		                     "couldn't open netdir");
		goto out_idle;
	}

	total = nm_platform_sysctl_get_int_checked (platform,
	                                            NMP_SYSCTL_PATHID_NETDIR (dirfd,
	                                                                      ifname,
	                                                                      "device/sriov_totalvfs"),
	                                            10, 0, G_MAXUINT, 0);
	if (errno) {
		g_set_error (&error,
		             NM_UTILS_ERROR,
		             NM_UTILS_ERROR_UNKNOWN,
		             "failed reading sriov_totalvfs value: %s",
		             nm_strerror_native (errno));
		goto out_idle;
	}
	if (num_vfs > total) {
		_LOGW ("link: %d only supports %u VFs (requested %u)", ifindex, total, num_vfs);
		num_vfs = total;
	}

	/*
	 * Take special care when setting new values:
	 *  - don't touch anything if the right values are already set
	 *  - to change the number of VFs or autoprobe we need to destroy existing VFs
	 *  - the autoprobe setting is irrelevant when numvfs is zero
	 */
	current_num = nm_platform_sysctl_get_int_checked (platform,
	                                                  NMP_SYSCTL_PATHID_NETDIR (dirfd,
	                                                                            ifname,
	                                                                            "device/sriov_numvfs"),
	                                                  10, 0, G_MAXUINT, -1);
	current_autoprobe = nm_platform_sysctl_get_int_checked (platform,
	                                                        NMP_SYSCTL_PATHID_NETDIR (dirfd,
	                                                                                  ifname,
	                                                                                  "device/sriov_drivers_autoprobe"),
	                                                        10, 0, 1, -1);

	if (   current_autoprobe == -1
	    && errno == ENOENT) {
		/* older kernel versions don't have this sysctl. Assume the value is
		 * "1". */
		current_autoprobe = 1;
	}

	if (   current_num == num_vfs
	    && (autoprobe == NM_TERNARY_DEFAULT || current_autoprobe == autoprobe))
		goto out_idle;

	if (   NM_IN_SET (autoprobe, NM_TERNARY_TRUE, NM_TERNARY_FALSE)
	    && current_autoprobe != autoprobe
	    && !nm_platform_sysctl_set (NM_PLATFORM_GET,
	                                NMP_SYSCTL_PATHID_NETDIR (dirfd,
	                                                          ifname,
	                                                          "device/sriov_drivers_autoprobe"),
	                                nm_sprintf_buf (buf, "%d", (int) autoprobe))) {
		g_set_error (&error,
		             NM_UTILS_ERROR,
		             NM_UTILS_ERROR_UNKNOWN,
		             "couldn't set SR-IOV drivers-autoprobe to %d: %s",
		            (int) autoprobe, nm_strerror_native (errno));
		goto out_idle;
	}

	if (current_num == 0 && num_vfs == 0)
		goto out_idle;

	i = 0;
	if (current_num != 0)
		values[i++] = "0";
	if (num_vfs != 0)
		values[i++] = nm_sprintf_bufa (32, "%u", num_vfs);
	values[i++] = NULL;

	sysctl_set_async (platform,
	                  NMP_SYSCTL_PATHID_NETDIR (dirfd, ifname, "device/sriov_numvfs"),
	                  values,
	                  callback,
	                  data,
	                  cancellable);
	return;

out_idle:
	if (callback) {
		packed = nm_utils_user_data_pack (g_object_ref (platform),
		                                  g_steal_pointer (&error),
		                                  callback,
		                                  data);
		nm_utils_invoke_on_idle (sriov_idle_cb, packed, cancellable);
	}
}

static gboolean
link_set_sriov_vfs (NMPlatform *platform, int ifindex, const NMPlatformVF *const *vfs)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	struct nlattr *list, *info, *vlan_list;
	guint i;

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL);
	if (!nlmsg)
		g_return_val_if_reached (-NME_BUG);

	if (!(list = nla_nest_start (nlmsg, IFLA_VFINFO_LIST)))
		goto nla_put_failure;

	for (i = 0; vfs[i]; i++) {
		const NMPlatformVF *vf = vfs[i];

		if (!(info = nla_nest_start (nlmsg, IFLA_VF_INFO)))
			goto nla_put_failure;

		if (vf->spoofchk >= 0) {
			struct _ifla_vf_setting ivs = { 0 };

			ivs.vf = vf->index;
			ivs.setting = vf->spoofchk;
			NLA_PUT (nlmsg, IFLA_VF_SPOOFCHK, sizeof (ivs), &ivs);
		}

		if (vf->trust >= 0) {
			struct _ifla_vf_setting ivs = { 0 };

			ivs.vf = vf->index;
			ivs.setting = vf->trust;
			NLA_PUT (nlmsg, IFLA_VF_TRUST, sizeof (ivs), &ivs);
		}

		if (vf->mac.len) {
			struct ifla_vf_mac ivm = { 0 };

			ivm.vf = vf->index;
			memcpy (ivm.mac, vf->mac.data, vf->mac.len);
			NLA_PUT (nlmsg, IFLA_VF_MAC, sizeof (ivm), &ivm);
		}

		if (vf->min_tx_rate || vf->max_tx_rate) {
			struct _ifla_vf_rate ivr = { 0 };

			ivr.vf = vf->index;
			ivr.min_tx_rate = vf->min_tx_rate;
			ivr.max_tx_rate = vf->max_tx_rate;
			NLA_PUT (nlmsg, IFLA_VF_RATE, sizeof (ivr), &ivr);
		}

		/* Kernel only supports one VLAN per VF now. If this
		 * changes in the future, we need to figure out how to
		 * clear existing VLANs and set new ones in one message
		 * with the new API.*/
		if (vf->num_vlans > 1) {
			_LOGW ("multiple VLANs per VF are not supported at the moment");
			return FALSE;
		} else {
			struct _ifla_vf_vlan_info ivvi = { 0 };

			if (!(vlan_list = nla_nest_start (nlmsg, IFLA_VF_VLAN_LIST)))
				goto nla_put_failure;

			ivvi.vf = vf->index;
			if (vf->num_vlans == 1) {
				ivvi.vlan = vf->vlans[0].id;
				ivvi.qos = vf->vlans[0].qos;
				ivvi.vlan_proto = htons (vf->vlans[0].proto_ad ? ETH_P_8021AD : ETH_P_8021Q);
			} else {
				/* Clear existing VLAN */
				ivvi.vlan = 0;
				ivvi.qos = 0;
				ivvi.vlan_proto = htons (ETH_P_8021Q);
			}

			NLA_PUT (nlmsg, IFLA_VF_VLAN_INFO, sizeof (ivvi), &ivvi);
			nla_nest_end (nlmsg, vlan_list);
		}
		nla_nest_end (nlmsg, info);
	}
	nla_nest_end (nlmsg, list);

	return (do_change_link (platform, CHANGE_LINK_TYPE_UNSPEC, ifindex, nlmsg, NULL) >= 0);
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static gboolean
link_set_bridge_vlans (NMPlatform *platform,
                       int ifindex,
                       gboolean on_master,
                       const NMPlatformBridgeVlan *const *vlans)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	struct nlattr *list;
	struct bridge_vlan_info vinfo = { };
	guint i;

	nlmsg = _nl_msg_new_link_full (vlans ? RTM_SETLINK : RTM_DELLINK,
	                               0,
	                               ifindex,
	                               NULL,
	                               AF_BRIDGE,
	                               0,
	                               0);
	if (!nlmsg)
		g_return_val_if_reached (-NME_BUG);

	if (!(list = nla_nest_start (nlmsg, IFLA_AF_SPEC)))
		goto nla_put_failure;

	NLA_PUT_U16 (nlmsg,
	             IFLA_BRIDGE_FLAGS,
	             on_master ? BRIDGE_FLAGS_MASTER : BRIDGE_FLAGS_SELF);

	if (vlans) {
		/* Add VLANs */
		for (i = 0; vlans[i]; i++) {
			const NMPlatformBridgeVlan *vlan = vlans[i];
			gboolean is_range = vlan->vid_start != vlan->vid_end;

			vinfo.vid = vlan->vid_start;
			vinfo.flags = is_range ? BRIDGE_VLAN_INFO_RANGE_BEGIN : 0;

			if (vlan->untagged)
				vinfo.flags |= BRIDGE_VLAN_INFO_UNTAGGED;
			if (vlan->pvid)
				vinfo.flags |= BRIDGE_VLAN_INFO_PVID;

			NLA_PUT (nlmsg, IFLA_BRIDGE_VLAN_INFO, sizeof (vinfo), &vinfo);

			if (is_range) {
				vinfo.vid = vlan->vid_end;
				vinfo.flags = BRIDGE_VLAN_INFO_RANGE_END;
				NLA_PUT (nlmsg, IFLA_BRIDGE_VLAN_INFO, sizeof (vinfo), &vinfo);
			}
		}
	} else {
		/* Flush existing VLANs */
		vinfo.vid = 1;
		vinfo.flags = BRIDGE_VLAN_INFO_RANGE_BEGIN;
		NLA_PUT (nlmsg, IFLA_BRIDGE_VLAN_INFO, sizeof (vinfo), &vinfo);

		vinfo.vid = 4094;
		vinfo.flags = BRIDGE_VLAN_INFO_RANGE_END;
		NLA_PUT (nlmsg, IFLA_BRIDGE_VLAN_INFO, sizeof (vinfo), &vinfo);
	}

	nla_nest_end (nlmsg, list);

	return (do_change_link (platform, CHANGE_LINK_TYPE_UNSPEC, ifindex, nlmsg, NULL) >= 0);
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static char *
link_get_physical_port_id (NMPlatform *platform, int ifindex)
{
	nm_auto_close int dirfd = -1;
	char ifname_verified[IFNAMSIZ];

	dirfd = nm_platform_sysctl_open_netdir (platform, ifindex, ifname_verified);
	if (dirfd < 0)
		return NULL;
	return sysctl_get (platform, NMP_SYSCTL_PATHID_NETDIR (dirfd, ifname_verified, "phys_port_id"));
}

static guint
link_get_dev_id (NMPlatform *platform, int ifindex)
{
	nm_auto_close int dirfd = -1;
	char ifname_verified[IFNAMSIZ];

	dirfd = nm_platform_sysctl_open_netdir (platform, ifindex, ifname_verified);
	if (dirfd < 0)
		return 0;
	return nm_platform_sysctl_get_int_checked (platform,
	                                           NMP_SYSCTL_PATHID_NETDIR (dirfd, ifname_verified, "dev_id"),
	                                           16, 0, G_MAXUINT16, 0);
}

static gboolean
link_tun_add (NMPlatform *platform,
              const char *name,
              const NMPlatformLnkTun *props,
              const NMPlatformLink **out_link,
              int *out_fd)
{
	const NMPObject *obj;
	struct ifreq ifr = { };
	nm_auto_close int fd = -1;

	nm_assert (NM_IN_SET (props->type, IFF_TAP, IFF_TUN));
	nm_assert (props->persist || out_fd);

	fd = open ("/dev/net/tun", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return FALSE;

	nm_utils_ifname_cpy (ifr.ifr_name, name);
	ifr.ifr_flags =   ((short) props->type)
	                | ((short) IFF_TUN_EXCL)
	                | (!props->pi          ? (short) IFF_NO_PI          : (short) 0)
	                | ( props->vnet_hdr    ? (short) IFF_VNET_HDR       : (short) 0)
	                | ( props->multi_queue ? (short) NM_IFF_MULTI_QUEUE : (short) 0);
	if (ioctl (fd, TUNSETIFF, &ifr))
		return FALSE;

	if (props->owner_valid) {
		if (ioctl (fd, TUNSETOWNER, (uid_t) props->owner))
			return FALSE;
	}

	if (props->group_valid) {
		if (ioctl (fd, TUNSETGROUP, (gid_t) props->group))
			return FALSE;
	}

	if (props->persist) {
		if (ioctl (fd, TUNSETPERSIST, 1))
			return FALSE;
	}

	do_request_link (platform, 0, name);
	obj = nmp_cache_lookup_link_full (nm_platform_get_cache (platform),
	                                  0, name, FALSE,
	                                  NM_LINK_TYPE_TUN,
	                                  NULL, NULL);

	if (!obj)
		return FALSE;

	NM_SET_OUT (out_link, &obj->link);
	NM_SET_OUT (out_fd, nm_steal_fd (&fd));
	return TRUE;
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
			 * When the user requests to reset all entries, we don't actually
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
	const NMPObject *obj_cache;
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	const NMPObjectLnkVlan *lnk;
	guint new_n_ingress_map = 0;
	guint new_n_egress_map = 0;
	gs_free NMVlanQosMapping *new_ingress_map = NULL;
	gs_free NMVlanQosMapping *new_egress_map = NULL;

	obj_cache = nmp_cache_lookup_link (nm_platform_get_cache (platform), ifindex);
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

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL);
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

	return (do_change_link (platform, CHANGE_LINK_TYPE_UNSPEC, ifindex, nlmsg, NULL) >= 0);
}

static gboolean
link_enslave (NMPlatform *platform, int master, int slave)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	int ifindex = slave;

	nlmsg = _nl_msg_new_link (RTM_NEWLINK,
	                          0,
	                          ifindex,
	                          NULL);
	if (!nlmsg)
		return FALSE;

	NLA_PUT_U32 (nlmsg, IFLA_MASTER, master);

	return (do_change_link (platform, CHANGE_LINK_TYPE_UNSPEC, ifindex, nlmsg, NULL) >= 0);
nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static gboolean
link_release (NMPlatform *platform, int master, int slave)
{
	return link_enslave (platform, 0, slave);
}

/*****************************************************************************/

static gboolean
_infiniband_partition_action (NMPlatform *platform,
                              InfinibandAction action,
                              int parent,
                              int p_key,
                              const NMPlatformLink **out_link)
{
	nm_auto_close int dirfd = -1;
	char ifname_parent[IFNAMSIZ];
	const NMPObject *obj;
	char id[20];
	char name[IFNAMSIZ];
	gboolean success;

	nm_assert (NM_IN_SET (action, INFINIBAND_ACTION_CREATE_CHILD, INFINIBAND_ACTION_DELETE_CHILD));
	nm_assert (p_key > 0 && p_key <= 0xffff && p_key != 0x8000);

	dirfd = nm_platform_sysctl_open_netdir (platform, parent, ifname_parent);
	if (dirfd < 0) {
		errno = ENOENT;
		return FALSE;
	}

	nm_sprintf_buf (id, "0x%04x", p_key);
	if (action == INFINIBAND_ACTION_CREATE_CHILD)
		success = nm_platform_sysctl_set (platform, NMP_SYSCTL_PATHID_NETDIR (dirfd, ifname_parent, "create_child"), id);
	else
		success = nm_platform_sysctl_set (platform, NMP_SYSCTL_PATHID_NETDIR (dirfd, ifname_parent, "delete_child"), id);

	if (!success) {
		if (   action == INFINIBAND_ACTION_DELETE_CHILD
		    && errno == ENODEV)
			return TRUE;
		return FALSE;
	}

	nm_utils_new_infiniband_name (name, ifname_parent, p_key);
	do_request_link (platform, 0, name);

	if (action == INFINIBAND_ACTION_DELETE_CHILD)
		return TRUE;

	obj = nmp_cache_lookup_link_full (nm_platform_get_cache (platform), 0, name, FALSE,
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

/*****************************************************************************/

static GObject *
get_ext_data (NMPlatform *platform, int ifindex)
{
	const NMPObject *obj;

	obj = nmp_cache_lookup_link (nm_platform_get_cache (platform), ifindex);
	if (!obj)
		return NULL;

	return obj->_link.ext_data;
}

/*****************************************************************************/

#define WIFI_GET_WIFI_DATA_NETNS(wifi_data, platform, ifindex, retval) \
	nm_auto_pop_netns NMPNetns *netns = NULL; \
	NMWifiUtils *wifi_data; \
	if (!nm_platform_netns_push (platform, &netns)) \
		return retval; \
	wifi_data = NM_WIFI_UTILS (get_ext_data (platform, ifindex)); \
	if (!wifi_data) \
		return retval;

static gboolean
wifi_get_capabilities (NMPlatform *platform, int ifindex, NMDeviceWifiCapabilities *caps)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	if (caps)
		*caps = nm_wifi_utils_get_caps (wifi_data);
	return TRUE;
}

static gboolean
wifi_get_bssid (NMPlatform *platform, int ifindex, guint8 *bssid)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	return nm_wifi_utils_get_bssid (wifi_data, bssid);
}

static guint32
wifi_get_frequency (NMPlatform *platform, int ifindex)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, 0);
	return nm_wifi_utils_get_freq (wifi_data);
}

static gboolean
wifi_get_quality (NMPlatform *platform, int ifindex)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	return nm_wifi_utils_get_qual (wifi_data);
}

static guint32
wifi_get_rate (NMPlatform *platform, int ifindex)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	return nm_wifi_utils_get_rate (wifi_data);
}

static NM80211Mode
wifi_get_mode (NMPlatform *platform, int ifindex)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, NM_802_11_MODE_UNKNOWN);
	return nm_wifi_utils_get_mode (wifi_data);
}

static void
wifi_set_mode (NMPlatform *platform, int ifindex, NM80211Mode mode)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, );
	nm_wifi_utils_set_mode (wifi_data, mode);
}

static void
wifi_set_powersave (NMPlatform *platform, int ifindex, guint32 powersave)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, );
	nm_wifi_utils_set_powersave (wifi_data, powersave);
}

static guint32
wifi_find_frequency (NMPlatform *platform, int ifindex, const guint32 *freqs)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, 0);
	return nm_wifi_utils_find_freq (wifi_data, freqs);
}

static void
wifi_indicate_addressing_running (NMPlatform *platform, int ifindex, gboolean running)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, );
	nm_wifi_utils_indicate_addressing_running (wifi_data, running);
}

static NMSettingWirelessWakeOnWLan
wifi_get_wake_on_wlan (NMPlatform *platform, int ifindex)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	return nm_wifi_utils_get_wake_on_wlan (wifi_data);
}

static gboolean
wifi_set_wake_on_wlan (NMPlatform *platform, int ifindex,
                       NMSettingWirelessWakeOnWLan wowl)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	return nm_wifi_utils_set_wake_on_wlan (wifi_data, wowl);
}

/*****************************************************************************/

static gboolean
link_can_assume (NMPlatform *platform, int ifindex)
{
	NMPLookup lookup;
	const NMPObject *link, *o;
	NMDedupMultiIter iter;
	NMPCache *cache = nm_platform_get_cache (platform);

	if (ifindex <= 0)
		return FALSE;

	link = nm_platform_link_get_obj (platform, ifindex, TRUE);
	if (!link)
		return FALSE;

	if (!NM_FLAGS_HAS (link->link.n_ifi_flags, IFF_UP))
		return FALSE;

	if (link->link.master > 0)
		return TRUE;

	nmp_lookup_init_object (&lookup,
	                        NMP_OBJECT_TYPE_IP4_ADDRESS,
	                        ifindex);
	if (nmp_cache_lookup (cache, &lookup))
		return TRUE;

	nmp_lookup_init_object (&lookup,
	                        NMP_OBJECT_TYPE_IP6_ADDRESS,
	                        ifindex);
	nmp_cache_iter_for_each (&iter,
	                         nmp_cache_lookup (cache, &lookup),
	                         &o) {
		nm_assert (NMP_OBJECT_GET_TYPE (o) == NMP_OBJECT_TYPE_IP6_ADDRESS);
		if (!IN6_IS_ADDR_LINKLOCAL (&o->ip6_address.address))
			return TRUE;
	}
	return FALSE;
}

/*****************************************************************************/

static guint32
mesh_get_channel (NMPlatform *platform, int ifindex)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, 0);
	return nm_wifi_utils_get_mesh_channel (wifi_data);
}

static gboolean
mesh_set_channel (NMPlatform *platform, int ifindex, guint32 channel)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	return nm_wifi_utils_set_mesh_channel (wifi_data, channel);
}

static gboolean
mesh_set_ssid (NMPlatform *platform, int ifindex, const guint8 *ssid, gsize len)
{
	WIFI_GET_WIFI_DATA_NETNS (wifi_data, platform, ifindex, FALSE);
	return nm_wifi_utils_set_mesh_ssid (wifi_data, ssid, len);
}

/*****************************************************************************/

#define WPAN_GET_WPAN_DATA(wpan_data, platform, ifindex, retval) \
	NMWpanUtils *wpan_data = NM_WPAN_UTILS (get_ext_data (platform, ifindex)); \
	if (!wpan_data) \
		return retval;

static guint16
wpan_get_pan_id (NMPlatform *platform, int ifindex)
{
	WPAN_GET_WPAN_DATA (wpan_data, platform, ifindex, G_MAXINT16);
	return nm_wpan_utils_get_pan_id (wpan_data);
}

static gboolean
wpan_set_pan_id (NMPlatform *platform, int ifindex, guint16 pan_id)
{
	WPAN_GET_WPAN_DATA (wpan_data, platform, ifindex, FALSE);
	return nm_wpan_utils_set_pan_id (wpan_data, pan_id);
}

static guint16
wpan_get_short_addr (NMPlatform *platform, int ifindex)
{
	WPAN_GET_WPAN_DATA (wpan_data, platform, ifindex, G_MAXINT16);
	return nm_wpan_utils_get_short_addr (wpan_data);
}

static gboolean
wpan_set_short_addr (NMPlatform *platform, int ifindex, guint16 short_addr)
{
	WPAN_GET_WPAN_DATA (wpan_data, platform, ifindex, FALSE);
	return nm_wpan_utils_set_short_addr (wpan_data, short_addr);
}

static gboolean
wpan_set_channel (NMPlatform *platform, int ifindex, guint8 page, guint8 channel)
{
	WPAN_GET_WPAN_DATA (wpan_data, platform, ifindex, FALSE);
	return nm_wpan_utils_set_channel (wpan_data, page, channel);
}

/*****************************************************************************/

static gboolean
link_get_wake_on_lan (NMPlatform *platform, int ifindex)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	NMLinkType type = nm_platform_link_get_type (platform, ifindex);

	if (!nm_platform_netns_push (platform, &netns))
		return FALSE;

	if (type == NM_LINK_TYPE_ETHERNET)
		return nmp_utils_ethtool_get_wake_on_lan (ifindex);
	else if (type == NM_LINK_TYPE_WIFI) {
		NMWifiUtils *wifi_data = NM_WIFI_UTILS (get_ext_data (platform, ifindex));

		if (!wifi_data)
			return FALSE;

		return nm_wifi_utils_get_wake_on_wlan (wifi_data) != NM_SETTING_WIRELESS_WAKE_ON_WLAN_NONE;
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
	NMPUtilsEthtoolDriverInfo driver_info;

	if (!nm_platform_netns_push (platform, &netns))
		return FALSE;

	if (!nmp_utils_ethtool_get_driver_info (ifindex, &driver_info))
		return FALSE;
	NM_SET_OUT (out_driver_name,    g_strdup (driver_info.driver));
	NM_SET_OUT (out_driver_version, g_strdup (driver_info.version));
	NM_SET_OUT (out_fw_version,     g_strdup (driver_info.fw_version));
	return TRUE;
}

/*****************************************************************************/

static gboolean
ip4_address_add (NMPlatform *platform,
                 int ifindex,
                 in_addr_t addr,
                 guint8 plen,
                 in_addr_t peer_addr,
                 in_addr_t broadcast_address,
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
	                             broadcast_address,
	                             label);

	nmp_object_stackinit_id_ip4_address (&obj_id, ifindex, addr, plen, peer_addr);
	return (do_add_addrroute (platform, &obj_id, nlmsg, FALSE) >= 0);
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
	                             IN6_IS_ADDR_UNSPECIFIED (&peer_addr) ? NULL : &peer_addr,
	                             flags,
	                             RT_SCOPE_UNIVERSE,
	                             lifetime,
	                             preferred,
	                             0,
	                             NULL);

	nmp_object_stackinit_id_ip6_address (&obj_id, ifindex, &addr);
	return (do_add_addrroute (platform, &obj_id, nlmsg, FALSE) >= 0);
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
	                             0,
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
	                             0,
	                             NULL);
	if (!nlmsg)
		g_return_val_if_reached (FALSE);

	nmp_object_stackinit_id_ip6_address (&obj_id, ifindex, &addr);
	return do_delete_object (platform, &obj_id, nlmsg);
}

/*****************************************************************************/

static int
ip_route_add (NMPlatform *platform,
              NMPNlmFlags flags,
              int addr_family,
              const NMPlatformIPRoute *route)
{
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;
	NMPObject obj;

	switch (addr_family) {
	case AF_INET:
		nmp_object_stackinit (&obj, NMP_OBJECT_TYPE_IP4_ROUTE, (const NMPlatformObject *) route);
		break;
	case AF_INET6:
		nmp_object_stackinit (&obj, NMP_OBJECT_TYPE_IP6_ROUTE, (const NMPlatformObject *) route);
		break;
	default:
		nm_assert_not_reached ();
	}

	nm_platform_ip_route_normalize (addr_family, NMP_OBJECT_CAST_IP_ROUTE (&obj));

	nlmsg = _nl_msg_new_route (RTM_NEWROUTE, flags & NMP_NLM_FLAG_FMASK, &obj);
	if (!nlmsg)
		g_return_val_if_reached (-NME_BUG);
	return do_add_addrroute (platform,
	                         &obj,
	                         nlmsg,
	                         NM_FLAGS_HAS (flags, NMP_NLM_FLAG_SUPPRESS_NETLINK_FAILURE));
}

static gboolean
object_delete (NMPlatform *platform,
               const NMPObject *obj)
{
	nm_auto_nmpobj const NMPObject *obj_keep_alive = NULL;
	nm_auto_nlmsg struct nl_msg *nlmsg = NULL;

	if (!NMP_OBJECT_IS_STACKINIT (obj))
		obj_keep_alive = nmp_object_ref (obj);

	switch (NMP_OBJECT_GET_TYPE (obj)) {
	case NMP_OBJECT_TYPE_IP4_ROUTE:
	case NMP_OBJECT_TYPE_IP6_ROUTE:
		nlmsg = _nl_msg_new_route (RTM_DELROUTE, 0, obj);
		break;
	case NMP_OBJECT_TYPE_ROUTING_RULE:
		nlmsg = _nl_msg_new_routing_rule (RTM_DELRULE, 0, NMP_OBJECT_CAST_ROUTING_RULE (obj));
		break;
	case NMP_OBJECT_TYPE_QDISC:
		nlmsg = _nl_msg_new_qdisc (RTM_DELQDISC, 0, NMP_OBJECT_CAST_QDISC (obj));
		break;
	case NMP_OBJECT_TYPE_TFILTER:
		nlmsg = _nl_msg_new_tfilter (RTM_DELTFILTER, 0, NMP_OBJECT_CAST_TFILTER (obj));
		break;
	default:
		break;
	}

	if (!nlmsg)
		g_return_val_if_reached (FALSE);
	return do_delete_object (platform, obj, nlmsg);
}

/*****************************************************************************/

static int
ip_route_get (NMPlatform *platform,
              int addr_family,
              gconstpointer address,
              int oif_ifindex,
              NMPObject **out_route)
{
	const gboolean is_v4 = (addr_family == AF_INET);
	const int addr_len = is_v4 ? 4 : 16;
	int try_count = 0;
	WaitForNlResponseResult seq_result;
	int nle;
	nm_auto_nmpobj NMPObject *route = NULL;

	nm_assert (NM_IS_LINUX_PLATFORM (platform));
	nm_assert (NM_IN_SET (addr_family, AF_INET, AF_INET6));
	nm_assert (address);

	do {
		struct {
			struct nlmsghdr n;
			struct rtmsg r;
			char buf[64];
		} req = {
			.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg)),
			.n.nlmsg_flags = NLM_F_REQUEST,
			.n.nlmsg_type = RTM_GETROUTE,
			.r.rtm_family = addr_family,
			.r.rtm_tos = 0,
			.r.rtm_dst_len = is_v4 ? 32 : 128,
			.r.rtm_flags = 0x1000 /* RTM_F_LOOKUP_TABLE */,
		};

		g_clear_pointer (&route, nmp_object_unref);

		if (!_nl_addattr_l (&req.n, sizeof (req), RTA_DST, address, addr_len))
			nm_assert_not_reached ();

		if (oif_ifindex > 0) {
			gint32 ii = oif_ifindex;

			if (!_nl_addattr_l (&req.n, sizeof (req), RTA_OIF, &ii, sizeof (ii)))
				nm_assert_not_reached ();
		}

		seq_result = WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN;
		nle = _nl_send_nlmsghdr (platform, &req.n, &seq_result, NULL, DELAYED_ACTION_RESPONSE_TYPE_ROUTE_GET, &route);
		if (nle < 0) {
			_LOGE ("get-route: failure sending netlink request \"%s\" (%d)",
			       nm_strerror_native (-nle), -nle);
			return -NME_UNSPEC;
		}

		delayed_action_handle_all (platform, FALSE);

		/* Retry, if we failed due to a cache resync. That can happen when the netlink
		 * socket fills up and we lost the response. */
	} while (   seq_result == WAIT_FOR_NL_RESPONSE_RESULT_FAILED_RESYNC
	         && ++try_count < 10);

	if (seq_result < 0) {
		/* negative seq_result is an errno from kernel. Map it to negative
		 * int (which are also errno). */
		return (int) seq_result;
	}

	if (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK) {
		if (route) {
			NM_SET_OUT (out_route, g_steal_pointer (&route));
			return 0;
		}
		seq_result = WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_UNKNOWN;
	}

	return -NME_UNSPEC;
}

/*****************************************************************************/

static int
routing_rule_add (NMPlatform *platform,
                  NMPNlmFlags flags,
                  const NMPlatformRoutingRule *routing_rule)
{
	WaitForNlResponseResult seq_result = WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	gs_free char *errmsg = NULL;
	char s_buf[256];
	int nle;

	msg = _nl_msg_new_routing_rule (RTM_NEWRULE, flags, routing_rule);

	event_handler_read_netlink (platform, FALSE);

	nle = _nl_send_nlmsg (platform, msg, &seq_result, &errmsg, DELAYED_ACTION_RESPONSE_TYPE_VOID, NULL);
	if (nle < 0) {
		_LOGE ("do-add-rule: failed sending netlink request \"%s\" (%d)",
		      nm_strerror (nle), -nle);
		return -NME_PL_NETLINK;
	}

	delayed_action_handle_all (platform, FALSE);

	nm_assert (seq_result);

	_NMLOG (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK
	            ? LOGL_DEBUG
	            : LOGL_WARN,
	        "do-add-rule: %s",
	        wait_for_nl_response_to_string (seq_result, errmsg, s_buf, sizeof (s_buf)));

	if (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK)
		return 0;
	if (seq_result < 0)
		return seq_result;
	return -NME_UNSPEC;
}

/*****************************************************************************/

static int
qdisc_add (NMPlatform *platform,
           NMPNlmFlags flags,
           const NMPlatformQdisc *qdisc)
{
	WaitForNlResponseResult seq_result = WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN;
	gs_free char *errmsg = NULL;
	int nle;
	char s_buf[256];
	nm_auto_nlmsg struct nl_msg *msg = NULL;

	/* Note: @qdisc must not be copied or kept alive because the lifetime of qdisc.kind
	 * is undefined. */

	msg = _nl_msg_new_qdisc (RTM_NEWQDISC, flags, qdisc);

	event_handler_read_netlink (platform, FALSE);

	nle = _nl_send_nlmsg (platform, msg, &seq_result, &errmsg, DELAYED_ACTION_RESPONSE_TYPE_VOID, NULL);
	if (nle < 0) {
		_LOGE ("do-add-qdisc: failed sending netlink request \"%s\" (%d)",
		      nm_strerror (nle), -nle);
		return -NME_PL_NETLINK;
	}

	delayed_action_handle_all (platform, FALSE);

	nm_assert (seq_result);

	_NMLOG (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK
	            ? LOGL_DEBUG
	            : LOGL_WARN,
	        "do-add-qdisc: %s",
	        wait_for_nl_response_to_string (seq_result, errmsg, s_buf, sizeof (s_buf)));

	if (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK)
		return 0;
	if (seq_result < 0)
		return seq_result;
	return -NME_UNSPEC;
}

/*****************************************************************************/

static int
tfilter_add (NMPlatform *platform,
             NMPNlmFlags flags,
             const NMPlatformTfilter *tfilter)
{
	WaitForNlResponseResult seq_result = WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN;
	gs_free char *errmsg = NULL;
	int nle;
	char s_buf[256];
	nm_auto_nlmsg struct nl_msg *msg = NULL;

	/* Note: @tfilter must not be copied or kept alive because the lifetime of tfilter.kind
	 * and tfilter.action.kind is undefined. */

	msg = _nl_msg_new_tfilter (RTM_NEWTFILTER, flags, tfilter);

	event_handler_read_netlink (platform, FALSE);

	nle = _nl_send_nlmsg (platform, msg, &seq_result, &errmsg, DELAYED_ACTION_RESPONSE_TYPE_VOID, NULL);
	if (nle < 0) {
		_LOGE ("do-add-tfilter: failed sending netlink request \"%s\" (%d)",
		      nm_strerror (nle), -nle);
		return -NME_PL_NETLINK;
	}

	delayed_action_handle_all (platform, FALSE);

	nm_assert (seq_result);

	_NMLOG (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK
	            ? LOGL_DEBUG
	            : LOGL_WARN,
	        "do-add-tfilter: %s",
	        wait_for_nl_response_to_string (seq_result, errmsg, s_buf, sizeof (s_buf)));

	if (seq_result == WAIT_FOR_NL_RESPONSE_RESULT_RESPONSE_OK)
		return 0;

	return -NME_UNSPEC;
}

/*****************************************************************************/

static gboolean
event_handler (int fd,
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
	int n;
	int err = 0;
	gboolean multipart = 0;
	gboolean interrupted = FALSE;
	struct nlmsghdr *hdr;
	WaitForNlResponseResult seq_result;
	struct sockaddr_nl nla = {0};
	struct ucred creds;
	gboolean creds_has;
	nm_auto_free unsigned char *buf = NULL;

continue_reading:
	g_clear_pointer (&buf, free);
	n = nl_recv (sk, &nla, &buf, &creds, &creds_has);

	if (n <= 0) {

		if (n == -NME_NL_MSG_TRUNC) {
			int buf_size;

			/* the message receive buffer was too small. We lost one message, which
			 * is unfortunate. Try to double the buffer size for the next time. */
			buf_size = nl_socket_get_msg_buf_size (sk);
			if (buf_size < 512*1024) {
				buf_size *= 2;
				_LOGT ("netlink: recvmsg: increase message buffer size for recvmsg() to %d bytes", buf_size);
				if (nl_socket_set_msg_buf_size (sk, buf_size) < 0)
					nm_assert_not_reached ();
				if (!handle_events)
					goto continue_reading;
			}
		}

		return n;
	}

	hdr = (struct nlmsghdr *) buf;
	while (nlmsg_ok (hdr, n)) {
		nm_auto_nlmsg struct nl_msg *msg = NULL;
		gboolean abort_parsing = FALSE;
		gboolean process_valid_msg = FALSE;
		guint32 seq_number;
		char buf_nlmsghdr[400];
		const char *extack_msg = NULL;

		msg = nlmsg_alloc_convert (hdr);

		nlmsg_set_proto (msg, NETLINK_ROUTE);
		nlmsg_set_src (msg, &nla);

		if (!creds_has || creds.pid) {
			if (!creds_has)
				_LOGT ("netlink: recvmsg: received message without credentials");
			else
				_LOGT ("netlink: recvmsg: received non-kernel message (pid %d)", creds.pid);
			err = 0;
			goto stop;
		}

		_LOGt ("netlink: recvmsg: new message %s",
		       nl_nlmsghdr_to_str (hdr, buf_nlmsghdr, sizeof (buf_nlmsghdr)));

		nlmsg_set_creds (msg, &creds);

		if (hdr->nlmsg_flags & NLM_F_MULTI)
			multipart = TRUE;

		if (hdr->nlmsg_flags & NLM_F_DUMP_INTR) {
			/*
			 * We have to continue reading to clear
			 * all messages until a NLMSG_DONE is
			 * received and report the inconsistency.
			 */
			interrupted = TRUE;
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
			multipart = FALSE;
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
			err = -NME_NL_MSG_OVERFLOW;
			abort_parsing = TRUE;
		} else if (hdr->nlmsg_type == NLMSG_ERROR) {
			/* Message carries a nlmsgerr */
			struct nlmsgerr *e = nlmsg_data (hdr);

			if (hdr->nlmsg_len < nlmsg_size (sizeof (*e))) {
				/* Truncated error message, the default action
				 * is to stop parsing. The user may overrule
				 * this action by returning NL_SKIP or
				 * NL_PROCEED (dangerous) */
				err = -NME_NL_MSG_TRUNC;
				abort_parsing = TRUE;
			} else if (e->error) {
				int errsv = nm_errno_native (e->error);

				if (   NM_FLAGS_HAS (hdr->nlmsg_flags, NLM_F_ACK_TLVS)
				    && hdr->nlmsg_len >= sizeof (*e) + e->msg.nlmsg_len) {
					static const struct nla_policy policy[] = {
						[NLMSGERR_ATTR_MSG]     = { .type = NLA_STRING },
						[NLMSGERR_ATTR_OFFS]    = { .type = NLA_U32 },
					};
					struct nlattr *tb[G_N_ELEMENTS (policy)];
					struct nlattr *tlvs;

					tlvs = (struct nlattr *) ((char *) e + sizeof (*e) + e->msg.nlmsg_len - NLMSG_HDRLEN);
					if (nla_parse_arr (tb,
					                   tlvs,
					                   hdr->nlmsg_len - sizeof (*e) - e->msg.nlmsg_len,
					                   policy) >= 0) {
						if (tb[NLMSGERR_ATTR_MSG])
							extack_msg = nla_get_string (tb[NLMSGERR_ATTR_MSG]);
					}
				}

				/* Error message reported back from kernel. */
				_LOGD ("netlink: recvmsg: error message from kernel: %s (%d)%s%s%s for request %d",
				       nm_strerror_native (errsv),
				       errsv,
				       NM_PRINT_FMT_QUOTED (extack_msg, " \"", extack_msg, "\"", ""),
				       nlmsg_hdr (msg)->nlmsg_seq);
				seq_result = -NM_ERRNO_NATIVE (errsv);
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

		event_seq_check (platform, seq_number, seq_result, extack_msg);

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

	if (interrupted)
		return -NME_NL_DUMP_INTR;
	return err;
}

/*****************************************************************************/

static gboolean
event_handler_read_netlink (NMPlatform *platform, gboolean wait_for_acks)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int r;
	struct pollfd pfd;
	gboolean any = FALSE;
	int timeout_msec;
	struct {
		guint32 seq_number;
		gint64 timeout_abs_ns;
		gint64 now_ns;
	} next;

	if (!nm_platform_netns_push (platform, &netns)) {
		delayed_action_wait_for_nl_response_complete_all (platform,
		                                                  WAIT_FOR_NL_RESPONSE_RESULT_FAILED_SETNS);
		return FALSE;
	}

	for (;;) {
		for (;;) {
			int nle;

			nle = event_handler_recvmsgs (platform, TRUE);

			if (nle < 0) {
				switch (nle) {
				case -EAGAIN:
					goto after_read;
				case -NME_NL_DUMP_INTR:
					_LOGD ("netlink: read: uncritical failure to retrieve incoming events: %s (%d)", nm_strerror (nle), nle);
					break;
				case -NME_NL_MSG_TRUNC:
				case -ENOBUFS:
					_LOGI ("netlink: read: %s. Need to resynchronize platform cache",
					       ({
					            const char *_reason = "unknown";
					            switch (nle) {
					            case -NME_NL_MSG_TRUNC: _reason = "message truncated";       break;
					            case -ENOBUFS:       _reason = "too many netlink events"; break;
					            }
					            _reason;
					       }));
					event_handler_recvmsgs (platform, FALSE);
					delayed_action_wait_for_nl_response_complete_all (platform,
					                                                  WAIT_FOR_NL_RESPONSE_RESULT_FAILED_RESYNC);

					delayed_action_schedule (platform,
					                         DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS |
					                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES |
					                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES |
					                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES |
					                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES |
					                         DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_ALL |
					                         DELAYED_ACTION_TYPE_REFRESH_ALL_QDISCS |
					                         DELAYED_ACTION_TYPE_REFRESH_ALL_TFILTERS,
					                         NULL);
					break;
				default:
					_LOGE ("netlink: read: failed to retrieve incoming events: %s (%d)", nm_strerror (nle), nle);
					break;
				}
			}
			any = TRUE;
		}

after_read:

		if (!NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE))
			return any;

		delayed_action_wait_for_nl_response_complete_check (platform,
		                                                    WAIT_FOR_NL_RESPONSE_RESULT_UNKNOWN,
		                                                    &next.seq_number,
		                                                    &next.timeout_abs_ns,
		                                                    &next.now_ns);

		if (   !wait_for_acks
		    || !NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_WAIT_FOR_NL_RESPONSE))
			return any;

		nm_assert (next.seq_number);
		nm_assert (next.now_ns > 0);
		nm_assert (next.timeout_abs_ns > next.now_ns);

		_LOGT ("netlink: read: wait for ACK for sequence number %u...", next.seq_number);

		timeout_msec = (next.timeout_abs_ns - next.now_ns) / (NM_UTILS_NSEC_PER_SEC / 1000);

		memset (&pfd, 0, sizeof (pfd));
		pfd.fd = nl_socket_get_fd (priv->nlh);
		pfd.events = POLLIN;
		r = poll (&pfd, 1, MAX (1, timeout_msec));

		if (r == 0) {
			/* timeout and there is nothing to read. */
			goto after_read;
		}

		if (r < 0) {
			int errsv = errno;

			if (errsv != EINTR) {
				_LOGE ("netlink: read: poll failed with %s", nm_strerror_native (errsv));
				delayed_action_wait_for_nl_response_complete_all (platform, WAIT_FOR_NL_RESPONSE_RESULT_FAILED_POLL);
				return any;
			}
			/* Continue to read again, even if there might be nothing to read after EINTR. */
		}
	}
}

/*****************************************************************************/

static void
cache_update_link_udev (NMPlatform *platform,
                        int ifindex,
                        struct udev_device *udevice)
{
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	nm_auto_nmpobj const NMPObject *obj_new = NULL;
	NMPCacheOpsType cache_op;

	cache_op = nmp_cache_update_link_udev (nm_platform_get_cache (platform), ifindex, udevice, &obj_old, &obj_new);

	if (cache_op != NMP_CACHE_OPS_UNCHANGED) {
		nm_auto_pop_netns NMPNetns *netns = NULL;

		cache_on_change (platform, cache_op, obj_old, obj_new);
		if (!nm_platform_netns_push (platform, &netns))
			return;
		nm_platform_cache_update_emit_signal (platform, cache_op, obj_old, obj_new);
	}
}

static void
udev_device_added (NMPlatform *platform,
                   struct udev_device *udevice)
{
	const char *ifname;
	const char *ifindex_s;
	int ifindex;

	ifname = udev_device_get_sysname (udevice);
	if (!ifname) {
		_LOGD ("udev-add: failed to get device's interface");
		return;
	}

	ifindex_s = udev_device_get_property_value (udevice, "IFINDEX");
	if (!ifindex_s) {
		_LOGW ("udev-add[%s]failed to get device's ifindex", ifname);
		return;
	}
	ifindex = _nm_utils_ascii_str_to_int64 (ifindex_s, 10, 1, G_MAXINT, 0);
	if (ifindex <= 0) {
		_LOGW ("udev-add[%s]: retrieved invalid IFINDEX=%d", ifname, ifindex);
		return;
	}

	if (!udev_device_get_syspath (udevice)) {
		_LOGD ("udev-add[%s,%d]: couldn't determine device path; ignoring...", ifname, ifindex);
		return;
	}

	_LOGT ("udev-add[%s,%d]: device added", ifname, ifindex);
	cache_update_link_udev (platform, ifindex, udevice);
}

static gboolean
_udev_device_removed_match_link (const NMPObject *obj, gpointer udevice)
{
	return obj->_link.udev.device == udevice;
}

static void
udev_device_removed (NMPlatform *platform,
                     struct udev_device *udevice)
{
	const char *ifindex_s;
	int ifindex = 0;

	ifindex_s = udev_device_get_property_value (udevice, "IFINDEX");
	ifindex = _nm_utils_ascii_str_to_int64 (ifindex_s, 10, 1, G_MAXINT, 0);
	if (ifindex <= 0) {
		const NMPObject *obj;

		obj = nmp_cache_lookup_link_full (nm_platform_get_cache (platform),
		                                  0, NULL, FALSE, NM_LINK_TYPE_NONE, _udev_device_removed_match_link, udevice);
		if (obj)
			ifindex = obj->link.ifindex;
	}

	_LOGD ("udev-remove: IFINDEX=%d", ifindex);
	if (ifindex <= 0)
		return;

	cache_update_link_udev (platform, ifindex, NULL);
}

static void
handle_udev_event (NMUdevClient *udev_client,
                   struct udev_device *udevice,
                   gpointer user_data)
{
	nm_auto_pop_netns NMPNetns *netns = NULL;
	NMPlatform *platform = NM_PLATFORM (user_data);
	const char *subsys;
	const char *ifindex;
	guint64 seqnum;
	const char *action;

	action = udev_device_get_action (udevice);
	g_return_if_fail (action);

	subsys = udev_device_get_subsystem (udevice);
	g_return_if_fail (nm_streq0 (subsys, "net"));

	if (!nm_platform_netns_push (platform, &netns))
		return;

	ifindex = udev_device_get_property_value (udevice, "IFINDEX");
	seqnum = udev_device_get_seqnum (udevice);
	_LOGD ("UDEV event: action '%s' subsys '%s' device '%s' (%s); seqnum=%" G_GUINT64_FORMAT,
	        action, subsys, udev_device_get_sysname (udevice),
	        ifindex ?: "unknown", seqnum);

	if (NM_IN_STRSET (action, "add", "move"))
		udev_device_added (platform, udevice);
	else if (NM_IN_STRSET (action, "remove"))
		udev_device_removed (platform, udevice);
}

/*****************************************************************************/

void
nm_linux_platform_setup (void)
{
	nm_platform_setup (nm_linux_platform_new (FALSE, FALSE));
}

/*****************************************************************************/

static void
nm_linux_platform_init (NMLinuxPlatform *self)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (self);

	priv->delayed_action.list_master_connected = g_ptr_array_new ();
	priv->delayed_action.list_refresh_link = g_ptr_array_new ();
	priv->delayed_action.list_wait_for_nl_response = g_array_new (FALSE, TRUE, sizeof (DelayedActionWaitForNlResponseData));
}

static void
constructed (GObject *_object)
{
	NMPlatform *platform = NM_PLATFORM (_object);
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int nle;
	int fd;

	nm_assert (!platform->_netns || platform->_netns == nmp_netns_get_current ());

	if (nm_platform_get_use_udev (platform)) {
		priv->udev_client = nm_udev_client_new (NM_MAKE_STRV ("net"),
		                                        handle_udev_event, platform);
	}

	_LOGD ("create (%s netns, %s, %s udev)",
	       !platform->_netns ? "ignore" : "use",
	       !platform->_netns && nmp_netns_is_initial ()
	           ? "initial netns"
	           : (!nmp_netns_get_current ()
	                ? "no netns support"
	                : nm_sprintf_bufa (100, "in netns[%p]%s",
	                                   nmp_netns_get_current (),
	                                   nmp_netns_get_current () == nmp_netns_get_initial () ? "/main" : "")),
	       nm_platform_get_use_udev (platform) ? "use" : "no");


	priv->genl = nl_socket_alloc ();
	g_assert (priv->genl);

	nle = nl_connect (priv->genl, NETLINK_GENERIC);
	if (nle) {
		_LOGE ("unable to connect the generic netlink socket \"%s\" (%d)",
		       nm_strerror (nle), -nle);
		nl_socket_free (priv->genl);
		priv->genl = NULL;
	}

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

	nle = nl_socket_set_ext_ack (priv->nlh, TRUE);
	if (nle)
		_LOGD ("could not enable extended acks on netlink socket");

	/* explicitly set the msg buffer size and disable MSG_PEEK.
	 * If we later encounter NME_NL_MSG_TRUNC, we will adjust the buffer size. */
	nl_socket_disable_msg_peek (priv->nlh);
	nle = nl_socket_set_msg_buf_size (priv->nlh, 32 * 1024);
	g_assert (!nle);

	nle = nl_socket_add_memberships (priv->nlh,
	                                 RTNLGRP_IPV4_IFADDR,
	                                 RTNLGRP_IPV4_ROUTE,
	                                 RTNLGRP_IPV4_RULE,
	                                 RTNLGRP_IPV6_RULE,
	                                 RTNLGRP_IPV6_IFADDR,
	                                 RTNLGRP_IPV6_ROUTE,
	                                 RTNLGRP_LINK,
	                                 RTNLGRP_TC,
	                                 0);
	g_assert (!nle);

	fd = nl_socket_get_fd (priv->nlh);

	_LOGD ("Netlink socket for events established: port=%u, fd=%d", nl_socket_get_local_port (priv->nlh), fd);

	priv->event_source = nm_g_unix_fd_source_new (fd,
	                                              G_IO_IN | G_IO_NVAL | G_IO_PRI | G_IO_ERR | G_IO_HUP,
	                                              G_PRIORITY_DEFAULT,
	                                              event_handler,
	                                              platform,
	                                              NULL);
	g_source_attach (priv->event_source, NULL);

	/* complete construction of the GObject instance before populating the cache. */
	G_OBJECT_CLASS (nm_linux_platform_parent_class)->constructed (_object);

	_LOGD ("populate platform cache");
	delayed_action_schedule (platform,
	                         DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS |
	                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES |
	                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES |
	                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES |
	                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES |
	                         DELAYED_ACTION_TYPE_REFRESH_ALL_ROUTING_RULES_ALL |
	                         DELAYED_ACTION_TYPE_REFRESH_ALL_QDISCS |
	                         DELAYED_ACTION_TYPE_REFRESH_ALL_TFILTERS,
	                         NULL);

	delayed_action_handle_all (platform, FALSE);

	/* Set up udev monitoring */
	if (priv->udev_client) {
		struct udev_enumerate *enumerator;
		struct udev_list_entry *devices, *l;

		/* And read initial device list */
		enumerator = nm_udev_client_enumerate_new (priv->udev_client);

		udev_enumerate_add_match_is_initialized (enumerator);

		udev_enumerate_scan_devices (enumerator);

		devices = udev_enumerate_get_list_entry (enumerator);
		for (l = devices; l; l = udev_list_entry_get_next (l)) {
			struct udev_device *udevice;

			udevice = udev_device_new_from_syspath (udev_enumerate_get_udev (enumerator),
			                                        udev_list_entry_get_name (l));
			if (!udevice)
				continue;

			udev_device_added (platform, udevice);
			udev_device_unref (udevice);
		}

		udev_enumerate_unref (enumerator);
	}
}

NMPlatform *
nm_linux_platform_new (gboolean log_with_ptr, gboolean netns_support)
{
	gboolean use_udev = FALSE;

	if (   nmp_netns_is_initial ()
	    && access ("/sys", W_OK) == 0)
		use_udev = TRUE;

	return g_object_new (NM_TYPE_LINUX_PLATFORM,
	                     NM_PLATFORM_LOG_WITH_PTR, log_with_ptr,
	                     NM_PLATFORM_USE_UDEV, use_udev,
	                     NM_PLATFORM_NETNS_SUPPORT, netns_support,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMPlatform *platform = NM_PLATFORM (object);
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	_LOGD ("dispose");

	delayed_action_wait_for_nl_response_complete_all (platform,
	                                                  WAIT_FOR_NL_RESPONSE_RESULT_FAILED_DISPOSING);

	priv->delayed_action.flags = DELAYED_ACTION_TYPE_NONE;
	g_ptr_array_set_size (priv->delayed_action.list_master_connected, 0);
	g_ptr_array_set_size (priv->delayed_action.list_refresh_link, 0);

	G_OBJECT_CLASS (nm_linux_platform_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (object);

	g_ptr_array_unref (priv->delayed_action.list_master_connected);
	g_ptr_array_unref (priv->delayed_action.list_refresh_link);
	g_array_unref (priv->delayed_action.list_wait_for_nl_response);

	nl_socket_free (priv->genl);

	nm_clear_g_source_inst (&priv->event_source);

	nl_socket_free (priv->nlh);

	if (priv->sysctl_get_prev_values) {
		sysctl_clear_cache_list = g_slist_remove (sysctl_clear_cache_list, object);
		g_hash_table_destroy (priv->sysctl_get_prev_values);
	}

	priv->udev_client = nm_udev_client_unref (priv->udev_client);

	G_OBJECT_CLASS (nm_linux_platform_parent_class)->finalize (object);
}

static void
nm_linux_platform_class_init (NMLinuxPlatformClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMPlatformClass *platform_class = NM_PLATFORM_CLASS (klass);

	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	platform_class->sysctl_set = sysctl_set;
	platform_class->sysctl_set_async = sysctl_set_async;
	platform_class->sysctl_get = sysctl_get;

	platform_class->link_add = link_add;
	platform_class->link_delete = link_delete;

	platform_class->link_refresh = link_refresh;

	platform_class->link_set_netns = link_set_netns;

	platform_class->link_set_up = link_set_up;
	platform_class->link_set_down = link_set_down;
	platform_class->link_set_arp = link_set_arp;
	platform_class->link_set_noarp = link_set_noarp;

	platform_class->link_get_udi = link_get_udi;

	platform_class->link_set_user_ipv6ll_enabled = link_set_user_ipv6ll_enabled;
	platform_class->link_set_token = link_set_token;

	platform_class->link_set_address = link_set_address;
	platform_class->link_get_permanent_address = link_get_permanent_address;
	platform_class->link_set_mtu = link_set_mtu;
	platform_class->link_set_name = link_set_name;
	platform_class->link_set_sriov_params_async = link_set_sriov_params_async;
	platform_class->link_set_sriov_vfs = link_set_sriov_vfs;
	platform_class->link_set_bridge_vlans = link_set_bridge_vlans;

	platform_class->link_get_physical_port_id = link_get_physical_port_id;
	platform_class->link_get_dev_id = link_get_dev_id;
	platform_class->link_get_wake_on_lan = link_get_wake_on_lan;
	platform_class->link_get_driver_info = link_get_driver_info;

	platform_class->link_supports_carrier_detect = link_supports_carrier_detect;
	platform_class->link_supports_vlans = link_supports_vlans;
	platform_class->link_supports_sriov = link_supports_sriov;

	platform_class->link_enslave = link_enslave;
	platform_class->link_release = link_release;

	platform_class->link_can_assume = link_can_assume;

	platform_class->link_vlan_change = link_vlan_change;
	platform_class->link_wireguard_change = link_wireguard_change;

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
	platform_class->wifi_get_wake_on_wlan = wifi_get_wake_on_wlan;
	platform_class->wifi_set_wake_on_wlan = wifi_set_wake_on_wlan;

	platform_class->mesh_get_channel = mesh_get_channel;
	platform_class->mesh_set_channel = mesh_set_channel;
	platform_class->mesh_set_ssid = mesh_set_ssid;

	platform_class->wpan_get_pan_id = wpan_get_pan_id;
	platform_class->wpan_set_pan_id = wpan_set_pan_id;
	platform_class->wpan_get_short_addr = wpan_get_short_addr;
	platform_class->wpan_set_short_addr = wpan_set_short_addr;
	platform_class->wpan_set_channel = wpan_set_channel;

	platform_class->link_tun_add = link_tun_add;

	platform_class->object_delete = object_delete;
	platform_class->ip4_address_add = ip4_address_add;
	platform_class->ip6_address_add = ip6_address_add;
	platform_class->ip4_address_delete = ip4_address_delete;
	platform_class->ip6_address_delete = ip6_address_delete;

	platform_class->ip_route_add = ip_route_add;
	platform_class->ip_route_get = ip_route_get;

	platform_class->routing_rule_add = routing_rule_add;

	platform_class->qdisc_add = qdisc_add;
	platform_class->tfilter_add = tfilter_add;

	platform_class->process_events = process_events;
}

