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
#include "config.h"

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <dlfcn.h>
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

#if HAVE_LIBNL_INET6_ADDR_GEN_MODE || HAVE_LIBNL_INET6_TOKEN
#include <netlink/route/link/inet6.h>
#if HAVE_LIBNL_INET6_ADDR_GEN_MODE && HAVE_KERNEL_INET6_ADDR_GEN_MODE
#include <linux/if_link.h>
#else
#define IN6_ADDR_GEN_MODE_EUI64 0
#define IN6_ADDR_GEN_MODE_NONE  1
#endif
#endif

#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"
#include "nm-linux-platform.h"
#include "nm-platform-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-default.h"
#include "wifi/wifi-utils.h"
#include "wifi/wifi-utils-wext.h"
#include "nmp-object.h"

/* This is only included for the translation of VLAN flags */
#include "nm-setting-vlan.h"

#define VLAN_FLAG_MVRP 0x8

/*********************************************************************************************/

#define _NMLOG_PREFIX_NAME                "platform-linux"
#define _NMLOG_DOMAIN                     LOGD_PLATFORM
#define _NMLOG2_DOMAIN                    LOGD_PLATFORM
#define _NMLOG(level, ...)                _LOG(level, _NMLOG_DOMAIN,  platform, __VA_ARGS__)
#define _NMLOG2(level, ...)               _LOG(level, _NMLOG2_DOMAIN, NULL,     __VA_ARGS__)

#define _LOG(level, domain, self, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        const NMLogDomain __domain = (domain); \
        \
        if (nm_logging_enabled (__level, __domain)) { \
            char __prefix[32]; \
            const char *__p_prefix = _NMLOG_PREFIX_NAME; \
            const void *const __self = (self); \
            \
            if (__self && __self != nm_platform_try_get ()) { \
                g_snprintf (__prefix, sizeof (__prefix), "%s[%p]", _NMLOG_PREFIX_NAME, __self); \
                __p_prefix = __prefix; \
            } \
            _nm_log (__level, __domain, 0, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     __p_prefix _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/******************************************************************
 * Forward declarations and enums
 ******************************************************************/

typedef enum {
	DELAYED_ACTION_TYPE_NONE                        = 0,
	DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS           = (1LL << 0),
	DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES   = (1LL << 1),
	DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES   = (1LL << 2),
	DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES      = (1LL << 3),
	DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES      = (1LL << 4),
	DELAYED_ACTION_TYPE_REFRESH_LINK                = (1LL << 5),
	DELAYED_ACTION_TYPE_MASTER_CONNECTED            = (1LL << 6),
	DELAYED_ACTION_TYPE_READ_NETLINK                = (1LL << 7),
	__DELAYED_ACTION_TYPE_MAX,

	DELAYED_ACTION_TYPE_REFRESH_ALL                 = DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS |
	                                                  DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES |
	                                                  DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES |
	                                                  DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES |
	                                                  DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,

	DELAYED_ACTION_TYPE_MAX                         = __DELAYED_ACTION_TYPE_MAX -1,
} DelayedActionType;

static gboolean tun_get_properties_ifname (NMPlatform *platform, const char *ifname, NMPlatformTunProperties *props);
static void delayed_action_schedule (NMPlatform *platform, DelayedActionType action_type, gpointer user_data);
static gboolean delayed_action_handle_all (NMPlatform *platform, gboolean read_netlink);
static void do_request_link (NMPlatform *platform, int ifindex, const char *name, gboolean handle_delayed_action);
static void do_request_all (NMPlatform *platform, DelayedActionType action_type, gboolean handle_delayed_action);
static void cache_pre_hook (NMPCache *cache, const NMPObject *old, const NMPObject *new, NMPCacheOpsType ops_type, gpointer user_data);
static gboolean event_handler_read_netlink_all (NMPlatform *platform, gboolean wait_for_acks);
static NMPCacheOpsType cache_remove_netlink (NMPlatform *platform, const NMPObject *obj_needle, NMPObject **out_obj_cache, gboolean *out_was_visible, NMPlatformReason reason);

/******************************************************************
 * libnl unility functions and wrappers
 ******************************************************************/

struct libnl_vtable
{
	void *handle;
	void *handle_route;

	int (*f_nl_has_capability) (int capability);
	int (*f_rtnl_link_get_link_netnsid) (const struct rtnl_link *link, gint32 *out_link_netnsid);
};

static int
_nl_f_nl_has_capability (int capability)
{
	return FALSE;
}

static const struct libnl_vtable *
_nl_get_vtable (void)
{
	static struct libnl_vtable vtable;

	if (G_UNLIKELY (!vtable.f_nl_has_capability)) {
		vtable.handle = dlopen ("libnl-3.so.200", RTLD_LAZY | RTLD_NOLOAD);
		if (vtable.handle) {
			vtable.f_nl_has_capability = dlsym (vtable.handle, "nl_has_capability");
		}
		vtable.handle_route = dlopen ("libnl-route-3.so.200", RTLD_LAZY | RTLD_NOLOAD);
		if (vtable.handle_route) {
			vtable.f_rtnl_link_get_link_netnsid = dlsym (vtable.handle_route, "rtnl_link_get_link_netnsid");
		}

		if (!vtable.f_nl_has_capability)
			vtable.f_nl_has_capability = &_nl_f_nl_has_capability;

		_LOG2t ("libnl: rtnl_link_get_link_netnsid() %s", vtable.f_rtnl_link_get_link_netnsid ? "supported" : "not supported");

		g_return_val_if_fail (vtable.handle, &vtable);
		g_return_val_if_fail (vtable.handle_route, &vtable);
	}

	return &vtable;
}

static gboolean
_nl_has_capability (int capability)
{
	return (_nl_get_vtable ()->f_nl_has_capability) (capability);
}

static int
_rtnl_link_get_link_netnsid (const struct rtnl_link *link, gint32 *out_link_netnsid)
{
	const struct libnl_vtable *vtable;

	g_return_val_if_fail (link, -NLE_INVAL);
	g_return_val_if_fail (out_link_netnsid, -NLE_INVAL);

	vtable = _nl_get_vtable ();
	return vtable->f_rtnl_link_get_link_netnsid
	    ? vtable->f_rtnl_link_get_link_netnsid (link, out_link_netnsid)
	    : -NLE_OPNOTSUPP;
}

gboolean
nm_platform_check_support_libnl_link_netnsid (void)
{
	return !!(_nl_get_vtable ()->f_rtnl_link_get_link_netnsid);
}

/* Automatic deallocation of local variables */
#define auto_nl_object __attribute__((cleanup(_nl_auto_nl_object)))
static void
_nl_auto_nl_object (void *ptr)
{
	struct nl_object **object = ptr;

	if (object && *object) {
		nl_object_put (*object);
		*object = NULL;
	}
}

#define auto_nl_addr __attribute__((cleanup(_nl_auto_nl_addr)))
static void
_nl_auto_nl_addr (void *ptr)
{
	struct nl_addr **object = ptr;

	if (object && *object) {
		nl_addr_put (*object);
		*object = NULL;
	}
}

/* wrap the libnl alloc functions and abort on out-of-memory*/

static struct nl_addr *
_nl_addr_build (int family, const void *buf, size_t size)
{
	struct nl_addr *addr;

	addr = nl_addr_build (family, (void *) buf, size);
	if (!addr)
		g_error ("nl_addr_build() failed with out of memory");

	return addr;
}

static struct rtnl_link *
_nl_rtnl_link_alloc (int ifindex, const char*name)
{
	struct rtnl_link *rtnllink;

	rtnllink = rtnl_link_alloc ();
	if (!rtnllink)
		g_error ("rtnl_link_alloc() failed with out of memory");

	if (ifindex > 0)
		rtnl_link_set_ifindex (rtnllink, ifindex);
	if (name)
		rtnl_link_set_name (rtnllink, name);
	return rtnllink;
}

static struct rtnl_addr *
_nl_rtnl_addr_alloc (int ifindex)
{
	struct rtnl_addr *rtnladdr;

	rtnladdr = rtnl_addr_alloc ();
	if (!rtnladdr)
		g_error ("rtnl_addr_alloc() failed with out of memory");
	if (ifindex > 0)
		rtnl_addr_set_ifindex (rtnladdr, ifindex);
	return rtnladdr;
}

static struct rtnl_route *
_nl_rtnl_route_alloc (void)
{
	struct rtnl_route *rtnlroute = rtnl_route_alloc ();

	if (!rtnlroute)
		g_error ("rtnl_route_alloc() failed with out of memory");
	return rtnlroute;
}

static struct rtnl_nexthop *
_nl_rtnl_route_nh_alloc (void)
{
	struct rtnl_nexthop *nexthop;

	nexthop = rtnl_route_nh_alloc ();
	if (!nexthop)
		g_error ("rtnl_route_nh_alloc () failed with out of memory");
	return nexthop;
}

/* rtnl_addr_set_prefixlen fails to update the nl_addr prefixlen */
static void
_nl_rtnl_addr_set_prefixlen (struct rtnl_addr *rtnladdr, int plen)
{
	struct nl_addr *nladdr;

	rtnl_addr_set_prefixlen (rtnladdr, plen);

	nladdr = rtnl_addr_get_local (rtnladdr);
	if (nladdr)
		nl_addr_set_prefixlen (nladdr, plen);
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

/******************************************************************/

/* _nl_link_parse_info_data(): Re-fetches a link from the kernel
 * and parses its IFLA_INFO_DATA using a caller-provided parser.
 *
 * Code is stolen from rtnl_link_get_kernel(), nl_pickup(), and link_msg_parser().
 */

typedef int (*NMNLInfoDataParser) (struct nlattr *info_data, gpointer parser_data);

typedef struct {
	NMNLInfoDataParser parser;
	gpointer parser_data;
} NMNLInfoDataClosure;

static struct nla_policy info_data_link_policy[IFLA_MAX + 1] = {
	[IFLA_LINKINFO] = { .type = NLA_NESTED },
};

static struct nla_policy info_data_link_info_policy[IFLA_INFO_MAX + 1] = {
	[IFLA_INFO_DATA] = { .type = NLA_NESTED },
};

static int
_nl_link_parse_info_data_cb (struct nl_msg *msg, void *arg)
{
	NMNLInfoDataClosure *closure = arg;
	struct nlmsghdr *n = nlmsg_hdr (msg);
	struct nlattr *tb[IFLA_MAX + 1];
	struct nlattr *li[IFLA_INFO_MAX + 1];
	int err;

	if (!nlmsg_valid_hdr (n, sizeof (struct ifinfomsg)))
		return -NLE_MSG_TOOSHORT;

	err = nlmsg_parse (n, sizeof (struct ifinfomsg), tb, IFLA_MAX, info_data_link_policy);
	if (err < 0)
		return err;

	if (!tb[IFLA_LINKINFO])
		return -NLE_MISSING_ATTR;

	err = nla_parse_nested (li, IFLA_INFO_MAX, tb[IFLA_LINKINFO], info_data_link_info_policy);
	if (err < 0)
		return err;

	if (!li[IFLA_INFO_DATA])
		return -NLE_MISSING_ATTR;

	return closure->parser (li[IFLA_INFO_DATA], closure->parser_data);
}

static int
_nl_link_parse_info_data (struct nl_sock *sk, int ifindex,
                          NMNLInfoDataParser parser, gpointer parser_data)
{
	NMNLInfoDataClosure data = { .parser = parser, .parser_data = parser_data };
	struct nl_msg *msg = NULL;
	struct nl_cb *cb;
	int err;

	err = rtnl_link_build_get_request (ifindex, NULL, &msg);
	if (err < 0)
		return err;

	err = nl_send_auto (sk, msg);
	nlmsg_free (msg);
	if (err < 0)
		return err;

	cb = nl_cb_clone (nl_socket_get_cb (sk));
	if (cb == NULL)
		return -NLE_NOMEM;
	nl_cb_set (cb, NL_CB_VALID, NL_CB_CUSTOM, _nl_link_parse_info_data_cb, &data);

	err = nl_recvmsgs (sk, cb);
	nl_cb_put (cb);
	if (err < 0)
		return err;

	nl_wait_for_ack (sk);
	return 0;
}

/******************************************************************/

static int
_nl_sock_flush_data (struct nl_sock *sk)
{
	int nle;
	struct nl_cb *cb;

	cb = nl_cb_clone (nl_socket_get_cb (sk));
	if (cb == NULL)
		return -NLE_NOMEM;

	nl_cb_set (cb, NL_CB_VALID, NL_CB_DEFAULT, NULL, NULL);
	nl_cb_set (cb, NL_CB_SEQ_CHECK, NL_CB_DEFAULT, NULL, NULL);
	nl_cb_err (cb, NL_CB_DEFAULT, NULL, NULL);
	do {
		errno = 0;

		nle = nl_recvmsgs (sk, cb);

		/* Work around a libnl bug fixed in 3.2.22 (375a6294) */
		if (nle == 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			nle = -NLE_AGAIN;
	} while (nle != -NLE_AGAIN);

	nl_cb_put (cb);
	return nle;
}

static void
_nl_msg_set_seq (struct nl_sock *sk, struct nl_msg *msg, guint32 *out_seq)
{
	guint32 seq;

	/* choose our own sequence number, because libnl does not ensure that
	 * it isn't zero -- which would confuse our checking for outstanding
	 * messages. */
	seq = nl_socket_use_seq (sk);
	if (seq == 0)
		seq = nl_socket_use_seq (sk);

	nlmsg_hdr (msg)->nlmsg_seq = seq;
	if (out_seq)
		*out_seq = seq;
}

static int
_nl_sock_request_link (NMPlatform *platform, struct nl_sock *sk, int ifindex, const char *name, guint32 *out_seq)
{
	struct nl_msg *msg = NULL;
	int err;

	if (name && !name[0])
		name = NULL;

	g_return_val_if_fail (ifindex > 0 || name, -NLE_INVAL);

	_LOGT ("sock: request-link %d%s%s%s", ifindex, name ? ", \"" : "", name ? name : "", name ? "\"" : "");

	if ((err = rtnl_link_build_get_request (ifindex, name, &msg)) < 0)
		return err;

	_nl_msg_set_seq (sk, msg, out_seq);

	err = nl_send_auto (sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return 0;
}

static int
_nl_sock_request_all (NMPlatform *platform, struct nl_sock *sk, NMPObjectType obj_type, guint32 *out_seq)
{
	const NMPClass *klass;
	struct rtgenmsg gmsg = { 0 };
	struct nl_msg *msg;
	int err;

	klass = nmp_class_from_type (obj_type);

	_LOGT ("sock: request-all-%s", klass->obj_type_name);

	/* reimplement
	 *   nl_rtgen_request (sk, klass->rtm_gettype, klass->addr_family, NLM_F_DUMP);
	 * because we need the sequence number.
	 */
	msg = nlmsg_alloc_simple (klass->rtm_gettype, NLM_F_DUMP);
	if (!msg)
		return -NLE_NOMEM;

	gmsg.rtgen_family = klass->addr_family;
	err = nlmsg_append (msg, &gmsg, sizeof (gmsg), NLMSG_ALIGNTO);
	if (err < 0)
		goto errout;

	_nl_msg_set_seq (sk, msg, out_seq);

	err = nl_send_auto (sk, msg);
errout:
	nlmsg_free(msg);

	return err >= 0 ? 0 : err;
}

/******************************************************************/

#if HAVE_LIBNL_INET6_ADDR_GEN_MODE
static int _support_user_ipv6ll = 0;
#define _support_user_ipv6ll_still_undecided() (G_UNLIKELY (_support_user_ipv6ll == 0))
#else
#define _support_user_ipv6ll_still_undecided() (FALSE)
#endif

static gboolean
_support_user_ipv6ll_get (void)
{
#if HAVE_LIBNL_INET6_ADDR_GEN_MODE
	if (_support_user_ipv6ll_still_undecided ()) {
		_support_user_ipv6ll = -1;
		_LOG2W ("kernel support for IFLA_INET6_ADDR_GEN_MODE %s", "failed to detect; assume no support");
	} else
		return _support_user_ipv6ll > 0;
#endif

	return FALSE;
}

static void
_support_user_ipv6ll_detect (const struct rtnl_link *rtnl_link)
{
#if HAVE_LIBNL_INET6_ADDR_GEN_MODE
	/* If we ever see a link with valid IPv6 link-local address
	 * generation modes, the kernel supports it.
	 */
	if (_support_user_ipv6ll_still_undecided ()) {
		uint8_t mode;

		if (rtnl_link_inet6_get_addr_gen_mode ((struct rtnl_link *) rtnl_link, &mode) == 0) {
			_support_user_ipv6ll = 1;
			_LOG2D ("kernel support for IFLA_INET6_ADDR_GEN_MODE %s", "detected");
		} else {
			_support_user_ipv6ll = -1;
			_LOG2D ("kernel support for IFLA_INET6_ADDR_GEN_MODE %s", "not detected");
		}
	}
#endif
}

/******************************************************************/

static int _support_kernel_extended_ifa_flags = 0;

#define _support_kernel_extended_ifa_flags_still_undecided() (G_UNLIKELY (_support_kernel_extended_ifa_flags == 0))

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
	_support_kernel_extended_ifa_flags =
	    nlmsg_find_attr (msg_hdr, sizeof (struct ifaddrmsg), 8 /* IFA_FLAGS */)
	    ? 1 : -1;
}

static gboolean
_support_kernel_extended_ifa_flags_get (void)
{
	if (_support_kernel_extended_ifa_flags_still_undecided ()) {
		_LOG2W ("Unable to detect kernel support for extended IFA_FLAGS. Assume no kernel support.");
		_support_kernel_extended_ifa_flags = -1;
	}
	return _support_kernel_extended_ifa_flags > 0;
}

/******************************************************************
 * Object type specific utilities
 ******************************************************************/

static guint
_nm_ip_config_source_to_rtprot (NMIPConfigSource source)
{
	switch (source) {
	case NM_IP_CONFIG_SOURCE_UNKNOWN:
		return RTPROT_UNSPEC;
	case NM_IP_CONFIG_SOURCE_KERNEL:
	case NM_IP_CONFIG_SOURCE_RTPROT_KERNEL:
		return RTPROT_KERNEL;
	case NM_IP_CONFIG_SOURCE_DHCP:
		return RTPROT_DHCP;
	case NM_IP_CONFIG_SOURCE_RDISC:
		return RTPROT_RA;

	default:
		return RTPROT_STATIC;
	}
}

static NMIPConfigSource
_nm_ip_config_source_from_rtprot (guint rtprot)
{
	switch (rtprot) {
	case RTPROT_UNSPEC:
		return NM_IP_CONFIG_SOURCE_UNKNOWN;
	case RTPROT_KERNEL:
		return NM_IP_CONFIG_SOURCE_RTPROT_KERNEL;
	case RTPROT_REDIRECT:
		return NM_IP_CONFIG_SOURCE_KERNEL;
	case RTPROT_RA:
		return NM_IP_CONFIG_SOURCE_RDISC;
	case RTPROT_DHCP:
		return NM_IP_CONFIG_SOURCE_DHCP;

	default:
		return NM_IP_CONFIG_SOURCE_USER;
	}
}

/******************************************************************/

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
	{ NM_LINK_TYPE_LOOPBACK,      "loopback",    NULL,          NULL },
	{ NM_LINK_TYPE_MACVLAN,       "macvlan",     "macvlan",     NULL },
	{ NM_LINK_TYPE_MACVTAP,       "macvtap",     "macvtap",     NULL },
	{ NM_LINK_TYPE_OPENVSWITCH,   "openvswitch", "openvswitch", NULL },
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
 * NMPlatform types and functions
 ******************************************************************/

typedef struct _NMLinuxPlatformPrivate NMLinuxPlatformPrivate;

struct _NMLinuxPlatformPrivate {
	struct nl_sock *nlh;
	struct nl_sock *nlh_event;
	guint32 nlh_seq_expect;
	guint32 nlh_seq_last;
	NMPCache *cache;
	GIOChannel *event_channel;
	guint event_id;

	gboolean sysctl_get_warned;
	GHashTable *sysctl_get_prev_values;

	GUdevClient *udev_client;

	struct {
		DelayedActionType flags;
		GPtrArray *list_master_connected;
		GPtrArray *list_refresh_link;
		gint is_handling;
		guint idle_id;
	} delayed_action;

	GHashTable *prune_candidates;
	GHashTable *delayed_deletion;

	GHashTable *wifi_data;
};

static inline NMLinuxPlatformPrivate *
NM_LINUX_PLATFORM_GET_PRIVATE (const void *self)
{
	nm_assert (NM_IS_LINUX_PLATFORM (self));

	return ((NMLinuxPlatform *) self)->priv;
}

G_DEFINE_TYPE (NMLinuxPlatform, nm_linux_platform, NM_TYPE_PLATFORM)

void
nm_linux_platform_setup (void)
{
	g_object_new (NM_TYPE_LINUX_PLATFORM,
	              NM_PLATFORM_REGISTER_SINGLETON, TRUE,
	              NULL);
}

/******************************************************************/

NMPObjectType
_nlo_get_object_type (const struct nl_object *object)
{
	const char *type_str;

	if (!object || !(type_str = nl_object_get_type (object)))
		return NMP_OBJECT_TYPE_UNKNOWN;

	if (!strcmp (type_str, "route/link"))
		return NMP_OBJECT_TYPE_LINK;
	else if (!strcmp (type_str, "route/addr")) {
		switch (rtnl_addr_get_family ((struct rtnl_addr *) object)) {
		case AF_INET:
			return NMP_OBJECT_TYPE_IP4_ADDRESS;
		case AF_INET6:
			return NMP_OBJECT_TYPE_IP6_ADDRESS;
		default:
			return NMP_OBJECT_TYPE_UNKNOWN;
		}
	} else if (!strcmp (type_str, "route/route")) {
		switch (rtnl_route_get_family ((struct rtnl_route *) object)) {
		case AF_INET:
			return NMP_OBJECT_TYPE_IP4_ROUTE;
		case AF_INET6:
			return NMP_OBJECT_TYPE_IP6_ROUTE;
		default:
			return NMP_OBJECT_TYPE_UNKNOWN;
		}
	} else
		return NMP_OBJECT_TYPE_UNKNOWN;
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

#define DEVTYPE_PREFIX "DEVTYPE="

static char *
read_devtype (const char *sysfs_path)
{
	gs_free char *uevent = g_strdup_printf ("%s/uevent", sysfs_path);
	char *contents = NULL;
	char *cont, *end;

	if (!g_file_get_contents (uevent, &contents, NULL, NULL))
		return NULL;
	for (cont = contents; cont; cont = end) {
		end = strpbrk (cont, "\r\n");
		if (end)
			*end++ = '\0';
		if (strncmp (cont, DEVTYPE_PREFIX, STRLEN (DEVTYPE_PREFIX)) == 0) {
			cont += STRLEN (DEVTYPE_PREFIX);
			memmove (contents, cont, strlen (cont) + 1);
			return contents;
		}
	}
	g_free (contents);
	return NULL;
}

static const NMPObject *
_lookup_link_cached (NMPlatform *platform, int ifindex, gboolean *completed_from_cache, const NMPObject **link_cached)
{
	const NMPObject *obj;

	nm_assert (completed_from_cache && link_cached);

	if (!*completed_from_cache) {
		obj = ifindex > 0 ? nmp_cache_lookup_link (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, ifindex) : NULL;

		if (obj && !obj->_link.netlink.is_in_netlink)
			*link_cached = obj;
		else
			*link_cached = NULL;
		*completed_from_cache = TRUE;
	}
	return *link_cached;
}

static NMLinkType
link_extract_type (NMPlatform *platform, struct rtnl_link *rtnllink, gboolean *completed_from_cache, const NMPObject **link_cached, const char **out_kind)
{
	const char *rtnl_type, *ifname;
	int i, arptype;

	if (!rtnllink) {
		if (out_kind)
			*out_kind = NULL;
		return NM_LINK_TYPE_NONE;
	}

	rtnl_type = rtnl_link_get_type (rtnllink);
	if (!rtnl_type && completed_from_cache) {
		const NMPObject *obj;

		obj = _lookup_link_cached (platform, rtnl_link_get_ifindex (rtnllink), completed_from_cache, link_cached);
		if (obj && obj->link.kind) {
			rtnl_type = obj->link.kind;
			_LOGT ("link_extract_type(): complete kind from cache: ifindex=%d, kind=%s", rtnl_link_get_ifindex (rtnllink), rtnl_type);
		}
	}
	if (out_kind)
		*out_kind = rtnl_type;
	if (rtnl_type) {
		for (i = 0; i < G_N_ELEMENTS (linktypes); i++) {
			if (g_strcmp0 (rtnl_type, linktypes[i].rtnl_type) == 0)
				return linktypes[i].nm_type;
		}

		if (!strcmp (rtnl_type, "tun")) {
			NMPlatformTunProperties props;
			guint flags;

			if (tun_get_properties_ifname (platform, rtnl_link_get_name (rtnllink), &props)) {
				if (!g_strcmp0 (props.mode, "tap"))
					return NM_LINK_TYPE_TAP;
				if (!g_strcmp0 (props.mode, "tun"))
					return NM_LINK_TYPE_TUN;
			}
			flags = rtnl_link_get_flags (rtnllink);

			_LOGD ("Failed to read tun properties for interface %d (link flags: %X)",
			       rtnl_link_get_ifindex (rtnllink), flags);

			/* try guessing the type using the link flags instead... */
			if (flags & IFF_POINTOPOINT)
				return NM_LINK_TYPE_TUN;
			return NM_LINK_TYPE_TAP;
		}
	}

	arptype = rtnl_link_get_arptype (rtnllink);
	if (arptype == ARPHRD_LOOPBACK)
		return NM_LINK_TYPE_LOOPBACK;
	else if (arptype == ARPHRD_INFINIBAND)
		return NM_LINK_TYPE_INFINIBAND;

	ifname = rtnl_link_get_name (rtnllink);
	if (ifname) {
		gs_free char *driver = NULL;
		gs_free char *sysfs_path = NULL;
		gs_free char *anycast_mask = NULL;
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

		sysfs_path = g_strdup_printf ("/sys/class/net/%s", ifname);
		anycast_mask = g_strdup_printf ("%s/anycast_mask", sysfs_path);
		if (g_file_test (anycast_mask, G_FILE_TEST_EXISTS))
			return NM_LINK_TYPE_OLPC_MESH;

		devtype = read_devtype (sysfs_path);
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
		if (wifi_utils_is_wifi (ifname, sysfs_path))
			return NM_LINK_TYPE_WIFI;

		/* Standard wired ethernet interfaces don't report an rtnl_link_type, so
		 * only allow fallback to Ethernet if no type is given.  This should
		 * prevent future virtual network drivers from being treated as Ethernet
		 * when they should be Generic instead.
		 */
		if (arptype == ARPHRD_ETHER && !rtnl_type && !devtype)
			return NM_LINK_TYPE_ETHERNET;
	}

	return NM_LINK_TYPE_UNKNOWN;
}

gboolean
_nmp_vt_cmd_plobj_init_from_nl_link (NMPlatform *platform, NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only, gboolean complete_from_cache)
{
	NMPlatformLink *obj = (NMPlatformLink *) _obj;
	NMPObjectLink *obj_priv = (NMPObjectLink *) _obj;
	struct rtnl_link *nlo = (struct rtnl_link *) _nlo;
	const char *name;
	struct nl_addr *nladdr;
	const char *kind;
	gboolean completed_from_cache_val = FALSE;
	gboolean *completed_from_cache = complete_from_cache ? &completed_from_cache_val : NULL;
	const NMPObject *link_cached = NULL;
	int parent;

	nm_assert (memcmp (obj, ((char [sizeof (NMPObjectLink)]) { 0 }), sizeof (NMPObjectLink)) == 0);

	if (_LOGT_ENABLED () && !NM_IN_SET (rtnl_link_get_family (nlo), AF_UNSPEC, AF_BRIDGE))
		_LOGT ("netlink object for ifindex %d has unusual family %d", rtnl_link_get_ifindex (nlo), rtnl_link_get_family (nlo));

	obj->ifindex = rtnl_link_get_ifindex (nlo);

	if (id_only)
		return TRUE;

	name = rtnl_link_get_name (nlo);
	if (name)
		g_strlcpy (obj->name, name, sizeof (obj->name));
	obj->type = link_extract_type (platform, nlo, completed_from_cache, &link_cached, &kind);
	obj->kind = g_intern_string (kind);
	obj->flags = rtnl_link_get_flags (nlo);
	obj->connected = NM_FLAGS_HAS (obj->flags, IFF_LOWER_UP);
	obj->master = rtnl_link_get_master (nlo);
	parent = rtnl_link_get_link (nlo);
	if (parent > 0) {
		gint32 link_netnsid;

		if (_rtnl_link_get_link_netnsid (nlo, &link_netnsid) == 0)
			obj->parent = NM_PLATFORM_LINK_OTHER_NETNS;
		else
			obj->parent = parent;
	}
	obj->mtu = rtnl_link_get_mtu (nlo);
	obj->arptype = rtnl_link_get_arptype (nlo);

	if (obj->type == NM_LINK_TYPE_VLAN) {
		if (!g_strcmp0 (rtnl_link_get_type (nlo), "vlan"))
			obj->vlan_id = rtnl_link_vlan_get_id (nlo);
		else if (completed_from_cache) {
			_lookup_link_cached (platform, obj->ifindex, completed_from_cache, &link_cached);
			if (link_cached)
				obj->vlan_id = link_cached->link.vlan_id;
		}
	}

	if ((nladdr = rtnl_link_get_addr (nlo))) {
		unsigned int l = 0;

		l = nl_addr_get_len (nladdr);
		if (l > 0 && l <= NM_UTILS_HWADDR_LEN_MAX) {
			G_STATIC_ASSERT (NM_UTILS_HWADDR_LEN_MAX == sizeof (obj->addr.data));
			memcpy (obj->addr.data, nl_addr_get_binary_addr (nladdr), l);
			obj->addr.len = l;
		}
	}

#if HAVE_LIBNL_INET6_ADDR_GEN_MODE
	if (_support_user_ipv6ll_get ()) {
		guint8 mode = 0;

		if (rtnl_link_inet6_get_addr_gen_mode (nlo, &mode) == 0)
			obj->inet6_addr_gen_mode_inv = _nm_platform_uint8_inv (mode);
	}
#endif

#if HAVE_LIBNL_INET6_TOKEN
	if ((rtnl_link_inet6_get_token (nlo, &nladdr)) == 0) {
		if (   nl_addr_get_family (nladdr) == AF_INET6
		    && nl_addr_get_len (nladdr) == sizeof (struct in6_addr)) {
			struct in6_addr *addr;
			NMUtilsIPv6IfaceId *iid = &obj->inet6_token.iid;

			addr = nl_addr_get_binary_addr (nladdr);
			iid->id_u8[7] = addr->s6_addr[15];
			iid->id_u8[6] = addr->s6_addr[14];
			iid->id_u8[5] = addr->s6_addr[13];
			iid->id_u8[4] = addr->s6_addr[12];
			iid->id_u8[3] = addr->s6_addr[11];
			iid->id_u8[2] = addr->s6_addr[10];
			iid->id_u8[1] = addr->s6_addr[9];
			iid->id_u8[0] = addr->s6_addr[8];
			obj->inet6_token.is_valid = TRUE;
		}
		nl_addr_put (nladdr);
	}
#endif

	obj_priv->netlink.is_in_netlink = TRUE;

	return TRUE;
}

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
_rtnl_addr_last_update_time_to_nm (const struct rtnl_addr *rtnladdr, gint32 *out_now_nm)
{
	guint32 last_update_time = rtnl_addr_get_last_update_time ((struct rtnl_addr *) rtnladdr);
	struct timespec tp;
	gint64 now_nl, now_nm, result;
	int err;

	/* timestamp is unset. Default to 1. */
	if (!last_update_time) {
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

	result = now_nm - (now_nl - _timestamp_nl_to_ms (last_update_time, now_nl));

	if (out_now_nm)
		*out_now_nm = now_nm / 1000;

	/* converting the last_update_time into nm_utils_get_monotonic_timestamp_ms() scale is
	 * a good guess but fails in the following situations:
	 *
	 * - If the address existed before start of the process, the timestamp in nm scale would
	 *   be negative or zero. In this case we default to 1.
	 * - during hibernation, the CLOCK_MONOTONIC/last_update_time drifts from
	 *   nm_utils_get_monotonic_timestamp_ms() scale.
	 */
	if (result <= 1000)
		return 1;

	if (result > now_nm)
		return now_nm / 1000;

	return result / 1000;
}

static guint32
_extend_lifetime (guint32 lifetime, guint32 seconds)
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
_nlo_rtnl_addr_get_lifetimes (const struct rtnl_addr *rtnladdr,
                              guint32 *out_timestamp,
                              guint32 *out_lifetime,
                              guint32 *out_preferred)
{
	guint32 timestamp = 0;
	gint32 now;
	guint32 lifetime = rtnl_addr_get_valid_lifetime ((struct rtnl_addr *) rtnladdr);
	guint32 preferred = rtnl_addr_get_preferred_lifetime ((struct rtnl_addr *) rtnladdr);

	if (   lifetime != NM_PLATFORM_LIFETIME_PERMANENT
	    || preferred != NM_PLATFORM_LIFETIME_PERMANENT) {
		if (preferred > lifetime)
			preferred = lifetime;
		timestamp = _rtnl_addr_last_update_time_to_nm (rtnladdr, &now);

		if (now == 0) {
			/* strange. failed to detect the last-update time and assumed that timestamp is 1. */
			nm_assert (timestamp == 1);
			now = nm_utils_get_monotonic_timestamp_s ();
		}
		if (timestamp < now) {
			guint32 diff = now - timestamp;

			lifetime = _extend_lifetime (lifetime, diff);
			preferred = _extend_lifetime (preferred, diff);
		} else
			nm_assert (timestamp == now);
	}
	*out_timestamp = timestamp;
	*out_lifetime = lifetime;
	*out_preferred = preferred;
}

gboolean
_nmp_vt_cmd_plobj_init_from_nl_ip4_address (NMPlatform *platform, NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only, gboolean complete_from_cache)
{
	NMPlatformIP4Address *obj = (NMPlatformIP4Address *) _obj;
	struct rtnl_addr *nlo = (struct rtnl_addr *) _nlo;
	struct nl_addr *nladdr = rtnl_addr_get_local (nlo);
	struct nl_addr *nlpeer = rtnl_addr_get_peer (nlo);
	const char *label;

	if (!nladdr || nl_addr_get_len (nladdr) != sizeof (obj->address))
		g_return_val_if_reached (FALSE);

	obj->ifindex = rtnl_addr_get_ifindex (nlo);
	obj->plen = rtnl_addr_get_prefixlen (nlo);
	memcpy (&obj->address, nl_addr_get_binary_addr (nladdr), sizeof (obj->address));

	if (id_only)
		return TRUE;

	obj->source = NM_IP_CONFIG_SOURCE_KERNEL;
	_nlo_rtnl_addr_get_lifetimes (nlo,
	                              &obj->timestamp,
	                              &obj->lifetime,
	                              &obj->preferred);
	if (nlpeer) {
		if (nl_addr_get_len (nlpeer) != sizeof (obj->peer_address))
			g_warn_if_reached ();
		else
			memcpy (&obj->peer_address, nl_addr_get_binary_addr (nlpeer), sizeof (obj->peer_address));
	}
	label = rtnl_addr_get_label (nlo);
	/* Check for ':'; we're only interested in labels used as interface aliases */
	if (label && strchr (label, ':'))
		g_strlcpy (obj->label, label, sizeof (obj->label));

	return TRUE;
}

gboolean
_nmp_vt_cmd_plobj_init_from_nl_ip6_address (NMPlatform *platform, NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only, gboolean complete_from_cache)
{
	NMPlatformIP6Address *obj = (NMPlatformIP6Address *) _obj;
	struct rtnl_addr *nlo = (struct rtnl_addr *) _nlo;
	struct nl_addr *nladdr = rtnl_addr_get_local (nlo);
	struct nl_addr *nlpeer = rtnl_addr_get_peer (nlo);

	if (!nladdr || nl_addr_get_len (nladdr) != sizeof (obj->address))
		g_return_val_if_reached (FALSE);

	obj->ifindex = rtnl_addr_get_ifindex (nlo);
	obj->plen = rtnl_addr_get_prefixlen (nlo);
	memcpy (&obj->address, nl_addr_get_binary_addr (nladdr), sizeof (obj->address));

	if (id_only)
		return TRUE;

	obj->source = NM_IP_CONFIG_SOURCE_KERNEL;
	_nlo_rtnl_addr_get_lifetimes (nlo,
	                              &obj->timestamp,
	                              &obj->lifetime,
	                              &obj->preferred);
	obj->flags = rtnl_addr_get_flags (nlo);

	if (nlpeer) {
		if (nl_addr_get_len (nlpeer) != sizeof (obj->peer_address))
			g_warn_if_reached ();
		else
			memcpy (&obj->peer_address, nl_addr_get_binary_addr (nlpeer), sizeof (obj->peer_address));
	}

	return TRUE;
}

gboolean
_nmp_vt_cmd_plobj_init_from_nl_ip4_route (NMPlatform *platform, NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only, gboolean complete_from_cache)
{
	NMPlatformIP4Route *obj = (NMPlatformIP4Route *) _obj;
	struct rtnl_route *nlo = (struct rtnl_route *) _nlo;
	struct nl_addr *dst, *gw;
	struct rtnl_nexthop *nexthop;
	struct nl_addr *pref_src;

	if (rtnl_route_get_type (nlo) != RTN_UNICAST ||
	    rtnl_route_get_table (nlo) != RT_TABLE_MAIN ||
	    rtnl_route_get_tos (nlo) != 0 ||
	    rtnl_route_get_nnexthops (nlo) != 1)
		return FALSE;

	nexthop = rtnl_route_nexthop_n (nlo, 0);
	if (!nexthop)
		g_return_val_if_reached (FALSE);

	dst = rtnl_route_get_dst (nlo);
	if (!dst)
		g_return_val_if_reached (FALSE);

	if (nl_addr_get_len (dst)) {
		if (nl_addr_get_len (dst) != sizeof (obj->network))
			g_return_val_if_reached (FALSE);
		memcpy (&obj->network, nl_addr_get_binary_addr (dst), sizeof (obj->network));
	}
	obj->ifindex = rtnl_route_nh_get_ifindex (nexthop);
	obj->plen = nl_addr_get_prefixlen (dst);
	obj->metric = rtnl_route_get_priority (nlo);
	obj->scope_inv = nm_platform_route_scope_inv (rtnl_route_get_scope (nlo));

	gw = rtnl_route_nh_get_gateway (nexthop);
	if (gw) {
		if (nl_addr_get_len (gw) != sizeof (obj->gateway))
			g_warn_if_reached ();
		else
			memcpy (&obj->gateway, nl_addr_get_binary_addr (gw), sizeof (obj->gateway));
	}
	rtnl_route_get_metric (nlo, RTAX_ADVMSS, &obj->mss);
	if (rtnl_route_get_flags (nlo) & RTM_F_CLONED) {
		/* we must not straight way reject cloned routes, because we might have cached
		 * a non-cloned route. If we now receive an update of the route with the route
		 * being cloned, we must still return the object, so that we can remove the old
		 * one from the cache.
		 *
		 * This happens, because this route is not nmp_object_is_alive().
		 * */
		obj->source = _NM_IP_CONFIG_SOURCE_RTM_F_CLONED;
	} else
		obj->source = _nm_ip_config_source_from_rtprot (rtnl_route_get_protocol (nlo));

	pref_src = rtnl_route_get_pref_src (nlo);
	if (pref_src) {
		if (nl_addr_get_len (pref_src) != sizeof (obj->pref_src))
			g_warn_if_reached ();
		else
			memcpy (&obj->pref_src, nl_addr_get_binary_addr (pref_src), sizeof (obj->pref_src));
	}

	return TRUE;
}

gboolean
_nmp_vt_cmd_plobj_init_from_nl_ip6_route (NMPlatform *platform, NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only, gboolean complete_from_cache)
{
	NMPlatformIP6Route *obj = (NMPlatformIP6Route *) _obj;
	struct rtnl_route *nlo = (struct rtnl_route *) _nlo;
	struct nl_addr *dst, *gw;
	struct rtnl_nexthop *nexthop;

	if (rtnl_route_get_type (nlo) != RTN_UNICAST ||
	    rtnl_route_get_table (nlo) != RT_TABLE_MAIN ||
	    rtnl_route_get_tos (nlo) != 0 ||
	    rtnl_route_get_nnexthops (nlo) != 1)
		return FALSE;

	nexthop = rtnl_route_nexthop_n (nlo, 0);
	if (!nexthop)
		g_return_val_if_reached (FALSE);

	dst = rtnl_route_get_dst (nlo);
	if (!dst)
		g_return_val_if_reached (FALSE);

	if (nl_addr_get_len (dst)) {
		if (nl_addr_get_len (dst) != sizeof (obj->network))
			g_return_val_if_reached (FALSE);
		memcpy (&obj->network, nl_addr_get_binary_addr (dst), sizeof (obj->network));
	}
	obj->ifindex = rtnl_route_nh_get_ifindex (nexthop);
	obj->plen = nl_addr_get_prefixlen (dst);
	obj->metric = rtnl_route_get_priority (nlo);

	if (id_only)
		return TRUE;

	gw = rtnl_route_nh_get_gateway (nexthop);
	if (gw) {
		if (nl_addr_get_len (gw) != sizeof (obj->gateway))
			g_warn_if_reached ();
		else
			memcpy (&obj->gateway, nl_addr_get_binary_addr (gw), sizeof (obj->gateway));
	}
	rtnl_route_get_metric (nlo, RTAX_ADVMSS, &obj->mss);
	if (rtnl_route_get_flags (nlo) & RTM_F_CLONED)
		obj->source = _NM_IP_CONFIG_SOURCE_RTM_F_CLONED;
	else
		obj->source = _nm_ip_config_source_from_rtprot (rtnl_route_get_protocol (nlo));

	return TRUE;
}

/******************************************************************/

static void
do_emit_signal (NMPlatform *platform, const NMPObject *obj, NMPCacheOpsType cache_op, gboolean was_visible, NMPlatformReason reason)
{
	gboolean is_visible;
	NMPObject obj_clone;
	const NMPClass *klass;

	nm_assert (NM_IN_SET ((NMPlatformSignalChangeType) cache_op, (NMPlatformSignalChangeType) NMP_CACHE_OPS_UNCHANGED, NM_PLATFORM_SIGNAL_ADDED, NM_PLATFORM_SIGNAL_CHANGED, NM_PLATFORM_SIGNAL_REMOVED));

	nm_assert (obj || cache_op == NMP_CACHE_OPS_UNCHANGED);
	nm_assert (!obj || cache_op == NMP_CACHE_OPS_REMOVED || obj == nmp_cache_lookup_obj (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, obj));
	nm_assert (!obj || cache_op != NMP_CACHE_OPS_REMOVED || obj != nmp_cache_lookup_obj (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, obj));

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

	_LOGT ("emit signal %s %s: %s (%ld)",
	       klass->signal_type,
	       nm_platform_signal_change_type_to_string ((NMPlatformSignalChangeType) cache_op),
	       nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0),
	       (long) reason);

	/* don't expose @obj directly, but clone the public fields. A signal handler might
	 * call back into NMPlatform which could invalidate (or modify) @obj. */
	memcpy (&obj_clone.object, &obj->object, klass->sizeof_public);
	g_signal_emit_by_name (platform, klass->signal_type, klass->obj_type, obj_clone.object.ifindex, &obj_clone.object, (NMPlatformSignalChangeType) cache_op, reason);
}

/******************************************************************/

static DelayedActionType
delayed_action_refresh_from_object_type (NMPObjectType obj_type)
{
	switch (obj_type) {
	case NMP_OBJECT_TYPE_LINK:          return DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS;
	case NMP_OBJECT_TYPE_IP4_ADDRESS:   return DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES;
	case NMP_OBJECT_TYPE_IP6_ADDRESS:   return DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES;
	case NMP_OBJECT_TYPE_IP4_ROUTE:     return DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES;
	case NMP_OBJECT_TYPE_IP6_ROUTE:     return DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES;
	default: g_return_val_if_reached (DELAYED_ACTION_TYPE_NONE);
	}
}

static NMPObjectType
delayed_action_refresh_to_object_type (DelayedActionType action_type)
{
	switch (action_type) {
	case DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS:             return NMP_OBJECT_TYPE_LINK;
	case DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES:     return NMP_OBJECT_TYPE_IP4_ADDRESS;
	case DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES:     return NMP_OBJECT_TYPE_IP6_ADDRESS;
	case DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES:        return NMP_OBJECT_TYPE_IP4_ROUTE;
	case DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES:        return NMP_OBJECT_TYPE_IP6_ROUTE;
	default: g_return_val_if_reached (NMP_OBJECT_TYPE_UNKNOWN);
	}
}

static const char *
delayed_action_to_string (DelayedActionType action_type)
{
	switch (action_type) {
	case DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS              : return "refresh-all-links";
	case DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES      : return "refresh-all-ip4-addresses";
	case DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES      : return "refresh-all-ip6-addresses";
	case DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES         : return "refresh-all-ip4-routes";
	case DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES         : return "refresh-all-ip6-routes";
	case DELAYED_ACTION_TYPE_REFRESH_LINK                   : return "refresh-link";
	case DELAYED_ACTION_TYPE_MASTER_CONNECTED               : return "master-connected";
	case DELAYED_ACTION_TYPE_READ_NETLINK                   : return "read-netlink";
	default:
		return "unknown";
	}
}

#define _LOGT_delayed_action(action_type, arg, operation) \
    _LOGT ("delayed-action: %s %s (%d) [%p / %d]", ""operation, delayed_action_to_string (action_type), (int) action_type, arg, GPOINTER_TO_INT (arg))

static void
delayed_action_handle_MASTER_CONNECTED (NMPlatform *platform, int master_ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	nm_auto_nmpobj NMPObject *obj_cache = NULL;
	gboolean was_visible;
	NMPCacheOpsType cache_op;

	cache_op = nmp_cache_update_link_master_connected (priv->cache, master_ifindex, &obj_cache, &was_visible, cache_pre_hook, platform);
	do_emit_signal (platform, obj_cache, cache_op, was_visible, NM_PLATFORM_REASON_INTERNAL);
}

static void
delayed_action_handle_REFRESH_LINK (NMPlatform *platform, int ifindex)
{
	do_request_link (platform, ifindex, NULL, FALSE);
}

static void
delayed_action_handle_REFRESH_ALL (NMPlatform *platform, DelayedActionType flags)
{
	do_request_all (platform, flags, FALSE);
}

static void
delayed_action_handle_READ_NETLINK (NMPlatform *platform)
{
	event_handler_read_netlink_all (platform, TRUE);
}

static gboolean
delayed_action_handle_one (NMPlatform *platform)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	gpointer user_data;

	if (priv->delayed_action.flags == DELAYED_ACTION_TYPE_NONE) {
		nm_clear_g_source (&priv->delayed_action.idle_id);
		return FALSE;
	}

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

		_LOGT_delayed_action (DELAYED_ACTION_TYPE_MASTER_CONNECTED, user_data, "handle");
		delayed_action_handle_MASTER_CONNECTED (platform, GPOINTER_TO_INT (user_data));
		return TRUE;
	}
	nm_assert (priv->delayed_action.list_master_connected->len == 0);

	/* Next we prefer read-netlink, because the buffer size is limited and we want to process events
	 * from netlink early. */
	if (NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_READ_NETLINK)) {
		_LOGT_delayed_action (DELAYED_ACTION_TYPE_READ_NETLINK, NULL, "handle");
		priv->delayed_action.flags &= ~DELAYED_ACTION_TYPE_READ_NETLINK;
		delayed_action_handle_READ_NETLINK (platform);
		return TRUE;
	}

	if (NM_FLAGS_ANY (priv->delayed_action.flags, DELAYED_ACTION_TYPE_REFRESH_ALL)) {
		DelayedActionType flags, iflags;

		flags = priv->delayed_action.flags & DELAYED_ACTION_TYPE_REFRESH_ALL;

		priv->delayed_action.flags &= ~DELAYED_ACTION_TYPE_REFRESH_ALL;

		if (_LOGT_ENABLED ()) {
			for (iflags = (DelayedActionType) 0x1LL; iflags <= DELAYED_ACTION_TYPE_MAX; iflags <<= 1) {
				if (NM_FLAGS_HAS (flags, iflags))
					_LOGT_delayed_action (iflags, NULL, "handle");
			}
		}

		delayed_action_handle_REFRESH_ALL (platform, flags);
		return TRUE;
	}

	nm_assert (priv->delayed_action.flags == DELAYED_ACTION_TYPE_REFRESH_LINK);
	nm_assert (priv->delayed_action.list_refresh_link->len > 0);

	user_data = priv->delayed_action.list_refresh_link->pdata[0];
	g_ptr_array_remove_index_fast (priv->delayed_action.list_refresh_link, 0);
	if (priv->delayed_action.list_refresh_link->len == 0)
		priv->delayed_action.flags &= ~DELAYED_ACTION_TYPE_REFRESH_LINK;
	nm_assert (_nm_utils_ptrarray_find_first (priv->delayed_action.list_refresh_link->pdata, priv->delayed_action.list_refresh_link->len, user_data) < 0);

	_LOGT_delayed_action (DELAYED_ACTION_TYPE_REFRESH_LINK, user_data, "handle");

	delayed_action_handle_REFRESH_LINK (platform, GPOINTER_TO_INT (user_data));

	return TRUE;
}

static gboolean
delayed_action_handle_all (NMPlatform *platform, gboolean read_netlink)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	gboolean any = FALSE;

	nm_clear_g_source (&priv->delayed_action.idle_id);
	priv->delayed_action.is_handling++;
	if (read_netlink)
		delayed_action_schedule (platform, DELAYED_ACTION_TYPE_READ_NETLINK, NULL);
	while (delayed_action_handle_one (platform))
		any = TRUE;
	priv->delayed_action.is_handling--;
	return any;
}

static gboolean
delayed_action_handle_idle (gpointer user_data)
{
	NM_LINUX_PLATFORM_GET_PRIVATE (user_data)->delayed_action.idle_id = 0;
	delayed_action_handle_all (user_data, FALSE);
	return G_SOURCE_REMOVE;
}

static void
delayed_action_clear_REFRESH_LINK (NMPlatform *platform, int ifindex)
{
	NMLinuxPlatformPrivate *priv;
	gssize idx;
	gpointer user_data;

	if (ifindex <= 0)
		return;

	priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	if (!NM_FLAGS_HAS (priv->delayed_action.flags, DELAYED_ACTION_TYPE_REFRESH_LINK))
		return;

	user_data = GINT_TO_POINTER (ifindex);

	idx = _nm_utils_ptrarray_find_first (priv->delayed_action.list_refresh_link->pdata, priv->delayed_action.list_refresh_link->len, user_data);
	if (idx < 0)
		return;

	_LOGT_delayed_action (DELAYED_ACTION_TYPE_REFRESH_LINK, user_data, "clear");

	g_ptr_array_remove_index_fast (priv->delayed_action.list_refresh_link, idx);
	if (priv->delayed_action.list_refresh_link->len == 0)
		priv->delayed_action.flags &= ~DELAYED_ACTION_TYPE_REFRESH_LINK;
}

static void
delayed_action_schedule (NMPlatform *platform, DelayedActionType action_type, gpointer user_data)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	DelayedActionType iflags;

	nm_assert (action_type != DELAYED_ACTION_TYPE_NONE);

	if (NM_FLAGS_HAS (action_type, DELAYED_ACTION_TYPE_REFRESH_LINK)) {
		nm_assert (nm_utils_is_power_of_two (action_type));
		if (_nm_utils_ptrarray_find_first (priv->delayed_action.list_refresh_link->pdata, priv->delayed_action.list_refresh_link->len, user_data) < 0)
			g_ptr_array_add (priv->delayed_action.list_refresh_link, user_data);
	} else if (NM_FLAGS_HAS (action_type, DELAYED_ACTION_TYPE_MASTER_CONNECTED)) {
		nm_assert (nm_utils_is_power_of_two (action_type));
		if (_nm_utils_ptrarray_find_first (priv->delayed_action.list_master_connected->pdata, priv->delayed_action.list_master_connected->len, user_data) < 0)
			g_ptr_array_add (priv->delayed_action.list_master_connected, user_data);
	} else
		nm_assert (!user_data);

	priv->delayed_action.flags |= action_type;

	if (_LOGT_ENABLED ()) {
		for (iflags = (DelayedActionType) 0x1LL; iflags <= DELAYED_ACTION_TYPE_MAX; iflags <<= 1) {
			if (NM_FLAGS_HAS (action_type, iflags))
				_LOGT_delayed_action (iflags, user_data, "schedule");
		}
	}

	if (priv->delayed_action.is_handling == 0 && priv->delayed_action.idle_id == 0)
		priv->delayed_action.idle_id = g_idle_add (delayed_action_handle_idle, platform);
}

/******************************************************************/

static void
cache_prune_candidates_record_all (NMPlatform *platform, NMPObjectType obj_type)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	priv->prune_candidates = nmp_cache_lookup_all_to_hash (priv->cache,
	                                                       nmp_cache_id_init_object_type (NMP_CACHE_ID_STATIC, obj_type, FALSE),
	                                                       priv->prune_candidates);
	_LOGT ("cache-prune: record %s (now %u candidates)", nmp_class_from_type (obj_type)->obj_type_name,
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

	if (_LOGT_ENABLED () && !g_hash_table_contains (priv->prune_candidates, obj))
		_LOGT ("cache-prune: record-one: %s", nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_ALL, NULL, 0));
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
		if (_LOGT_ENABLED () && g_hash_table_contains (priv->prune_candidates, obj))
			_LOGT ("cache-prune: drop-one: %s", nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_ALL, NULL, 0));
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

		_LOGT ("cache-prune: prune %s", nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_ALL, NULL, 0));
		cache_op = nmp_cache_remove (priv->cache, obj, TRUE, &obj_cache, &was_visible, cache_pre_hook, platform);
		do_emit_signal (platform, obj_cache, cache_op, was_visible, NM_PLATFORM_REASON_INTERNAL);
	}

	g_hash_table_unref (prune_candidates);
}

static void
cache_delayed_deletion_prune (NMPlatform *platform)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GPtrArray *prune_list = NULL;
	GHashTableIter iter;
	guint i;
	NMPObject *obj;

	if (g_hash_table_size (priv->delayed_deletion) == 0)
		return;

	g_hash_table_iter_init (&iter, priv->delayed_deletion);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &obj)) {
		if (obj) {
			if (!prune_list)
				prune_list = g_ptr_array_new_full (g_hash_table_size (priv->delayed_deletion), (GDestroyNotify) nmp_object_unref);
			g_ptr_array_add (prune_list, nmp_object_ref (obj));
		}
	}

	g_hash_table_remove_all (priv->delayed_deletion);

	if (prune_list) {
		for (i = 0; i < prune_list->len; i++) {
			obj = prune_list->pdata[i];
			_LOGT ("delayed-deletion: delete %s", nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_ID, NULL, 0));
			cache_remove_netlink (platform, obj, NULL, NULL, NM_PLATFORM_REASON_EXTERNAL);
		}
		g_ptr_array_unref (prune_list);
	}
}

static void
cache_pre_hook (NMPCache *cache, const NMPObject *old, const NMPObject *new, NMPCacheOpsType ops_type, gpointer user_data)
{
	NMPlatform *platform = NM_PLATFORM (user_data);
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	const NMPClass *klass;
	char str_buf[sizeof (_nm_platform_to_string_buffer)];
	char str_buf2[sizeof (_nm_platform_to_string_buffer)];

	nm_assert (old || new);
	nm_assert (NM_IN_SET (ops_type, NMP_CACHE_OPS_ADDED, NMP_CACHE_OPS_REMOVED, NMP_CACHE_OPS_UPDATED));
	nm_assert (ops_type != NMP_CACHE_OPS_ADDED   || (old == NULL && NMP_OBJECT_IS_VALID (new) && nmp_object_is_alive (new)));
	nm_assert (ops_type != NMP_CACHE_OPS_REMOVED || (new == NULL && NMP_OBJECT_IS_VALID (old) && nmp_object_is_alive (old)));
	nm_assert (ops_type != NMP_CACHE_OPS_UPDATED || (NMP_OBJECT_IS_VALID (old) && nmp_object_is_alive (old) && NMP_OBJECT_IS_VALID (new) && nmp_object_is_alive (new)));
	nm_assert (new == NULL || old == NULL || nmp_object_id_equal (new, old));

	klass = old ? NMP_OBJECT_GET_CLASS (old) : NMP_OBJECT_GET_CLASS (new);

	nm_assert (klass == (new ? NMP_OBJECT_GET_CLASS (new) : NMP_OBJECT_GET_CLASS (old)));

	_LOGT ("update-cache-%s: %s: %s%s%s",
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
			 * Currently, kernel misses to sent us a notification in this case (rh #1262908). */

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
			    && NM_FLAGS_HAS (old->link.flags, IFF_LOWER_UP)
			    && new->_link.netlink.is_in_netlink
			    && !NM_FLAGS_HAS (new->link.flags, IFF_LOWER_UP)) {
				delayed_action_schedule (platform,
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES |
				                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,
				                         NULL);
			}
		}
		{
			/* on enslave/release, we also refresh the master. */
			int ifindex1 = 0, ifindex2 = 0;
			gboolean changed_master, changed_connected;

			changed_master =    (new && new->_link.netlink.is_in_netlink && new->link.master > 0 ? new->link.master : 0)
			                 != (old && old->_link.netlink.is_in_netlink && old->link.master > 0 ? old->link.master : 0);
			changed_connected =    (new && new->_link.netlink.is_in_netlink ? NM_FLAGS_HAS (new->link.flags, IFF_LOWER_UP) : 2)
			                    != (old && old->_link.netlink.is_in_netlink ? NM_FLAGS_HAS (old->link.flags, IFF_LOWER_UP) : 2);

			if (changed_master || changed_connected) {
				ifindex1 = (old && old->_link.netlink.is_in_netlink && old->link.master > 0) ? old->link.master : 0;
				ifindex2 = (new && new->_link.netlink.is_in_netlink && new->link.master > 0) ? new->link.master : 0;

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
			if (ops_type == NMP_CACHE_OPS_REMOVED) {
				delayed_action_schedule (platform,
				                         (klass->obj_type == NMP_OBJECT_TYPE_IP4_ADDRESS)
				                             ? DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES
				                             : DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,
				                         NULL);
			}
		}
	default:
		break;
	}
}

static NMPCacheOpsType
cache_remove_netlink (NMPlatform *platform, const NMPObject *obj_needle, NMPObject **out_obj_cache, gboolean *out_was_visible, NMPlatformReason reason)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	NMPObject *obj_cache;
	gboolean was_visible;
	NMPCacheOpsType cache_op;

	cache_op = nmp_cache_remove_netlink (priv->cache, obj_needle, &obj_cache, &was_visible, cache_pre_hook, platform);
	do_emit_signal (platform, obj_cache, cache_op, was_visible, NM_PLATFORM_REASON_INTERNAL);

	if (out_obj_cache)
		*out_obj_cache = obj_cache;
	else
		nmp_object_unref (obj_cache);
	if (out_was_visible)
		*out_was_visible = was_visible;

	return cache_op;
}

static NMPCacheOpsType
cache_update_netlink (NMPlatform *platform, NMPObject *obj, NMPObject **out_obj_cache, gboolean *out_was_visible, NMPlatformReason reason)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	NMPObject *obj_cache;
	gboolean was_visible;
	NMPCacheOpsType cache_op;

	/* This is basically a convenience method to call nmp_cache_update() and do_emit_signal()
	 * at once. */

	cache_op = nmp_cache_update_netlink (priv->cache, obj, &obj_cache, &was_visible, cache_pre_hook, platform);
	do_emit_signal (platform, obj_cache, cache_op, was_visible, reason);

	if (out_obj_cache)
		*out_obj_cache = obj_cache;
	else
		nmp_object_unref (obj_cache);
	if (out_was_visible)
		*out_was_visible = was_visible;

	return cache_op;
}

/******************************************************************/

static void
_new_sequence_number (NMPlatform *platform, guint32 seq)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	_LOGT ("_new_sequence_number(): new sequence number %u", seq);

	priv->nlh_seq_expect = seq;
}

static void
do_request_link (NMPlatform *platform, int ifindex, const char *name, gboolean handle_delayed_action)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	guint32 seq;

	_LOGT ("do_request_link (%d,%s)", ifindex, name ? name : "");

	if (ifindex > 0) {
		NMPObject *obj;

		cache_prune_candidates_record_one (platform,
		                                   (NMPObject *) nmp_cache_lookup_link (priv->cache, ifindex));
		obj = nmp_object_new_link (ifindex);
		_LOGT ("delayed-deletion: protect object %s", nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_ID, NULL, 0));
		g_hash_table_insert (priv->delayed_deletion, obj, NULL);
	}

	event_handler_read_netlink_all (platform, FALSE);

	if (_nl_sock_request_link (platform, priv->nlh_event, ifindex, name, &seq) == 0)
		_new_sequence_number (platform, seq);

	event_handler_read_netlink_all (platform, TRUE);

	cache_delayed_deletion_prune (platform);
	cache_prune_candidates_prune (platform);

	if (handle_delayed_action)
		delayed_action_handle_all (platform, FALSE);
}

static void
do_request_one_type (NMPlatform *platform, NMPObjectType obj_type, gboolean handle_delayed_action)
{
	do_request_all (platform, delayed_action_refresh_from_object_type (obj_type), handle_delayed_action);
}

static void
do_request_all (NMPlatform *platform, DelayedActionType action_type, gboolean handle_delayed_action)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	guint32 seq;
	DelayedActionType iflags;

	nm_assert (!NM_FLAGS_ANY (action_type, ~DELAYED_ACTION_TYPE_REFRESH_ALL));
	action_type &= DELAYED_ACTION_TYPE_REFRESH_ALL;

	for (iflags = (DelayedActionType) 0x1LL; iflags <= DELAYED_ACTION_TYPE_MAX; iflags <<= 1) {
		if (NM_FLAGS_HAS (action_type, iflags))
			cache_prune_candidates_record_all (platform, delayed_action_refresh_to_object_type (iflags));
	}

	for (iflags = (DelayedActionType) 0x1LL; iflags <= DELAYED_ACTION_TYPE_MAX; iflags <<= 1) {
		if (NM_FLAGS_HAS (action_type, iflags)) {
			NMPObjectType obj_type = delayed_action_refresh_to_object_type (iflags);

			/* clear any delayed action that request a refresh of this object type. */
			priv->delayed_action.flags &= ~iflags;
			_LOGT_delayed_action (iflags, NULL, "handle (do-request-all)");
			if (obj_type == NMP_OBJECT_TYPE_LINK) {
				priv->delayed_action.flags &= ~DELAYED_ACTION_TYPE_REFRESH_LINK;
				g_ptr_array_set_size (priv->delayed_action.list_refresh_link, 0);
				_LOGT_delayed_action (DELAYED_ACTION_TYPE_REFRESH_LINK, NULL, "clear (do-request-all)");
			}

			event_handler_read_netlink_all (platform, FALSE);

			if (_nl_sock_request_all (platform, priv->nlh_event, obj_type, &seq) == 0)
				_new_sequence_number (platform, seq);
		}
	}
	event_handler_read_netlink_all (platform, TRUE);

	cache_prune_candidates_prune (platform);

	if (handle_delayed_action)
		delayed_action_handle_all (platform, FALSE);
}

static gboolean
kernel_add_object (NMPlatform *platform, NMPObjectType obj_type, const struct nl_object *nlo)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int nle;

	g_return_val_if_fail (nlo, FALSE);

	switch (obj_type) {
	case NMP_OBJECT_TYPE_LINK:
		nle = rtnl_link_add (priv->nlh, (struct rtnl_link *) nlo, NLM_F_CREATE);
		break;
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
		nle = rtnl_addr_add (priv->nlh, (struct rtnl_addr *) nlo, NLM_F_CREATE | NLM_F_REPLACE);
		break;
	case NMP_OBJECT_TYPE_IP4_ROUTE:
	case NMP_OBJECT_TYPE_IP6_ROUTE:
		nle = rtnl_route_add (priv->nlh, (struct rtnl_route *) nlo, NLM_F_CREATE | NLM_F_REPLACE);
		break;
	default:
		g_return_val_if_reached (-NLE_INVAL);
	}

	_LOGT ("kernel-add-%s: returned %s (%d)",
	       nmp_class_from_type (obj_type)->obj_type_name, nl_geterror (nle), -nle);

	switch (nle) {
	case -NLE_SUCCESS:
		return -NLE_SUCCESS;
	case -NLE_EXIST:
		/* NLE_EXIST is considered equivalent to success to avoid race conditions. You
		 * never know when something sends an identical object just before
		 * NetworkManager. */
		if (obj_type != NMP_OBJECT_TYPE_LINK)
			return -NLE_SUCCESS;
		/* fall-through */
	default:
		return nle;
	}
}

static int
kernel_delete_object (NMPlatform *platform, NMPObjectType object_type, const struct nl_object *object)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int nle;

	switch (object_type) {
	case NMP_OBJECT_TYPE_LINK:
		nle = rtnl_link_delete (priv->nlh, (struct rtnl_link *) object);
		break;
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
		nle = rtnl_addr_delete (priv->nlh, (struct rtnl_addr *) object, 0);
		break;
	case NMP_OBJECT_TYPE_IP4_ROUTE:
	case NMP_OBJECT_TYPE_IP6_ROUTE:
		nle = rtnl_route_delete (priv->nlh, (struct rtnl_route *) object, 0);
		break;
	default:
		g_assert_not_reached ();
	}

	switch (nle) {
	case -NLE_SUCCESS:
		return NLE_SUCCESS;
	case -NLE_OBJ_NOTFOUND:
		_LOGT ("kernel-delete-%s: failed with \"%s\" (%d), meaning the object was already removed",
		       nmp_class_from_type (object_type)->obj_type_name, nl_geterror (nle), -nle);
		return -NLE_SUCCESS;
	case -NLE_FAILURE:
		if (object_type == NMP_OBJECT_TYPE_IP6_ADDRESS) {
			/* On RHEL7 kernel, deleting a non existing address fails with ENXIO (which libnl maps to NLE_FAILURE) */
			_LOGT ("kernel-delete-%s: deleting address failed with \"%s\" (%d), meaning the address was already removed",
			       nmp_class_from_type (object_type)->obj_type_name, nl_geterror (nle), -nle);
			return NLE_SUCCESS;
		}
		break;
	case -NLE_NOADDR:
		if (object_type == NMP_OBJECT_TYPE_IP4_ADDRESS || object_type == NMP_OBJECT_TYPE_IP6_ADDRESS) {
			_LOGT ("kernel-delete-%s: deleting address failed with \"%s\" (%d), meaning the address was already removed",
			       nmp_class_from_type (object_type)->obj_type_name, nl_geterror (nle), -nle);
			return -NLE_SUCCESS;
		}
		break;
	default:
		break;
	}
	_LOGT ("kernel-delete-%s: failed with %s (%d)",
	       nmp_class_from_type (object_type)->obj_type_name, nl_geterror (nle), -nle);
	return nle;
}

static int
kernel_change_link (NMPlatform *platform, struct rtnl_link *nlo, gboolean *complete_from_cache)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	struct nl_msg *msg;
	int nle;
	const int nlflags = 0;
	int ifindex;

	ifindex = rtnl_link_get_ifindex (nlo);

	g_return_val_if_fail (ifindex > 0, FALSE);

	/* Previously, we were using rtnl_link_change(), which builds a request based
	 * on the diff with an original link instance.
	 *
	 * The diff only reused ifi_family, ifi_index, ifi_flags, and name from
	 * the original link (see rtnl_link_build_change_request()).
	 *
	 * We don't do that anymore as we don't have an "orig" netlink instance that
	 * we can use. Instead the caller must ensure to properly initialize @nlo,
	 * especially it must set family, ifindex (or ifname) and flags.
	 * ifname should be set *only* if the caller wishes to change the name.
	 *
	 * @complete_from_cache is a convenience to copy the link flags over the link inside
	 * the platform cache. */

	if (*complete_from_cache) {
		const NMPObject *obj_cache;

		obj_cache = nmp_cache_lookup_link (priv->cache, ifindex);
		if (!obj_cache || !obj_cache->_link.netlink.is_in_netlink) {
			_LOGT ("kernel-change-link: failure changing link %d: cannot complete link", ifindex);
			*complete_from_cache = FALSE;
			return -NLE_INVAL;
		}

		rtnl_link_set_flags (nlo, obj_cache->link.flags);

		/* If the caller wants to rename the link, he should explicitly set
		 * rtnl_link_set_name(). In all other cases, it should leave the name
		 * unset. Unfortunately, there is not public API in libnl to modify the
		 * attribute mask and clear (link->ce_mask = ~LINK_ATTR_IFNAME), so we
		 * require the caller to do the right thing -- i.e. don't set the name.
		 */
	}

	/* We don't use rtnl_link_change() because we have no original rtnl_link object
	 * at hand. We also don't use rtnl_link_add() because that doesn't have the
	 * hack to retry with RTM_SETLINK. Reimplement a mix of both. */

	nle = rtnl_link_build_add_request (nlo, nlflags, &msg);
	if (nle < 0) {
		_LOGT ("kernel-change-link: failure changing link %d: cannot construct message (%s, %d)",
		       ifindex, nl_geterror (nle), -nle);
		return nle;
	}

retry:
	nle = nl_send_auto_complete (priv->nlh, msg);
	if (nle < 0)
		goto errout;

	nle = nl_wait_for_ack(priv->nlh);
	if (nle == -NLE_OPNOTSUPP && nlmsg_hdr (msg)->nlmsg_type == RTM_NEWLINK) {
		nlmsg_hdr (msg)->nlmsg_type = RTM_SETLINK;
		goto retry;
	}

errout:
	nlmsg_free(msg);

	/* NLE_EXIST is considered equivalent to success to avoid race conditions. You
	 * never know when something sends an identical object just before
	 * NetworkManager.
	 *
	 * When netlink returns NLE_OBJ_NOTFOUND, it usually means it failed to find
	 * firmware for the device, especially on nm_platform_link_set_up ().
	 * This is basically the same check as in the original code and could
	 * potentially be improved.
	 */
	switch (nle) {
	case -NLE_SUCCESS:
		_LOGT ("kernel-change-link: success changing link %d", ifindex);
		break;
	case -NLE_EXIST:
		_LOGT ("kernel-change-link: success changing link %d: %s (%d)",
		       ifindex, nl_geterror (nle), -nle);
		break;
	case -NLE_OBJ_NOTFOUND:
		_LOGT ("kernel-change-link: failure changing link %d: firmware not found (%s, %d)",
		       ifindex, nl_geterror (nle), -nle);
		break;
	default:
		_LOGT ("kernel-change-link: failure changing link %d: netlink error (%s, %d)",
		       ifindex, nl_geterror (nle), -nle);
		break;
	}

	return nle;
}

static void
ref_object (struct nl_object *obj, void *data)
{
	struct nl_object **out = data;

	nl_object_get (obj);
	*out = obj;
}

static int
event_seq_check (struct nl_msg *msg, gpointer user_data)
{
	NMPlatform *platform = NM_PLATFORM (user_data);
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	struct nlmsghdr *hdr;

	hdr = nlmsg_hdr (msg);

	if (hdr->nlmsg_seq == 0)
		return NL_OK;

	priv->nlh_seq_last = hdr->nlmsg_seq;

	if (priv->nlh_seq_expect == 0)
		_LOGT ("event_seq_check(): seq %u received (not waited)", hdr->nlmsg_seq);
	else if (hdr->nlmsg_seq == priv->nlh_seq_expect) {
		_LOGT ("event_seq_check(): seq %u received", hdr->nlmsg_seq);

		priv->nlh_seq_expect = 0;
	} else
		_LOGT ("event_seq_check(): seq %u received (wait for %u)", hdr->nlmsg_seq, priv->nlh_seq_last);

	return NL_OK;
}

static int
event_err (struct sockaddr_nl *nla, struct nlmsgerr *nlerr, gpointer platform)
{
	_LOGT ("event_err(): error from kernel: %s (%d) for request %d",
	       strerror (nlerr ? -nlerr->error : 0),
	       nlerr ? -nlerr->error : 0,
	       NM_LINUX_PLATFORM_GET_PRIVATE (platform)->nlh_seq_last);
	return NL_OK;
}

/* This function does all the magic to avoid race conditions caused
 * by concurrent usage of synchronous commands and an asynchronous cache. This
 * might be a nice future addition to libnl but it requires to do all operations
 * through the cache manager. In this case, nm-linux-platform serves as the
 * cache manager instead of the one provided by libnl.
 */
static int
event_notification (struct nl_msg *msg, gpointer user_data)
{
	NMPlatform *platform = NM_PLATFORM (user_data);
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (user_data);
	auto_nl_object struct nl_object *nlo = NULL;
	nm_auto_nmpobj NMPObject *obj = NULL;
	struct nlmsghdr *msghdr;
	char buf_nlmsg_type[16];

	msghdr = nlmsg_hdr (msg);

	if (_support_kernel_extended_ifa_flags_still_undecided () && msghdr->nlmsg_type == RTM_NEWADDR)
		_support_kernel_extended_ifa_flags_detect (msg);

	nl_msg_parse (msg, ref_object, &nlo);
	if (!nlo)
		return NL_OK;

	if (_support_user_ipv6ll_still_undecided() && msghdr->nlmsg_type == RTM_NEWLINK)
		_support_user_ipv6ll_detect ((struct rtnl_link *) nlo);

	switch (msghdr->nlmsg_type) {
	case RTM_DELADDR:
	case RTM_DELLINK:
	case RTM_DELROUTE:
		/* The event notifies about a deleted object. We don't need to initialize all the
		 * fields of the nmp-object. Shortcut nmp_object_from_nl(). */
		obj = nmp_object_from_nl (platform, nlo, TRUE, TRUE);
		_LOGt ("event-notification: %s, seq %u: %s",
		       _nl_nlmsg_type_to_str (msghdr->nlmsg_type, buf_nlmsg_type, sizeof (buf_nlmsg_type)),
		       msghdr->nlmsg_seq, nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_ID, NULL, 0));
		break;
	default:
		obj = nmp_object_from_nl (platform, nlo, FALSE, TRUE);
		_LOGt ("event-notification: %s, seq %u: %s",
		       _nl_nlmsg_type_to_str (msghdr->nlmsg_type, buf_nlmsg_type, sizeof (buf_nlmsg_type)),
		       msghdr->nlmsg_seq, nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));
		break;
	}

	if (obj) {
		nm_auto_nmpobj NMPObject *obj_cache = NULL;

		switch (msghdr->nlmsg_type) {

		case RTM_NEWLINK:
			if (NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_LINK) {
				if (g_hash_table_lookup (priv->delayed_deletion, obj) != NULL) {
					/* the object is scheduled for delayed deletion. Replace that object
					 * by clearing the value from priv->delayed_deletion. */
					_LOGT ("delayed-deletion: clear delayed deletion of protected object %s", nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_ID, NULL, 0));
					g_hash_table_insert (priv->delayed_deletion, nmp_object_ref (obj), NULL);
				}
				delayed_action_clear_REFRESH_LINK (platform, obj->link.ifindex);
			}
			/* fall-through */
		case RTM_NEWADDR:
		case RTM_NEWROUTE:
			cache_update_netlink (platform, obj, &obj_cache, NULL, NM_PLATFORM_REASON_EXTERNAL);
			break;

		case RTM_DELLINK:
			if (   NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_LINK
			    && g_hash_table_contains (priv->delayed_deletion, obj)) {
				/* We sometimes receive spurious RTM_DELLINK events. In this case, we want to delay
				 * the deletion of the object until later. */
				_LOGT ("delayed-deletion: delay deletion of protected object %s", nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_ID, NULL, 0));
				g_hash_table_insert (priv->delayed_deletion, nmp_object_ref (obj), nmp_object_ref (obj));
				break;
			}
			/* fall-through */
		case RTM_DELADDR:
		case RTM_DELROUTE:
			cache_remove_netlink (platform, obj, &obj_cache, NULL, NM_PLATFORM_REASON_EXTERNAL);
			break;

		default:
			break;
		}

		cache_prune_candidates_drop (platform, obj_cache);
	}

	return NL_OK;
}

/******************************************************************/

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
	int fd, len, nwrote, tries;
	char *actual;

	g_return_val_if_fail (path != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	/* Don't write outside known locations */
	g_assert (g_str_has_prefix (path, "/proc/sys/")
	          || g_str_has_prefix (path, "/sys/"));
	/* Don't write to suspicious locations */
	g_assert (!strstr (path, "/../"));

	fd = open (path, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		if (errno == ENOENT) {
			_LOGD ("sysctl: failed to open '%s': (%d) %s",
			       path, errno, strerror (errno));
		} else {
			_LOGE ("sysctl: failed to open '%s': (%d) %s",
			       path, errno, strerror (errno));
		}
		return FALSE;
	}

	_log_dbg_sysctl_set (platform, path, value);

	/* Most sysfs and sysctl options don't care about a trailing LF, while some
	 * (like infiniband) do.  So always add the LF.  Also, neither sysfs nor
	 * sysctl support partial writes so the LF must be added to the string we're
	 * about to write.
	 */
	actual = g_strdup_printf ("%s\n", value);

	/* Try to write the entire value three times if a partial write occurs */
	len = strlen (actual);
	for (tries = 0, nwrote = 0; tries < 3 && nwrote != len; tries++) {
		nwrote = write (fd, actual, len);
		if (nwrote == -1) {
			if (errno == EINTR) {
				_LOGD ("sysctl: interrupted, will try again");
				continue;
			}
			break;
		}
	}
	if (nwrote == -1 && errno != EEXIST) {
		_LOGE ("sysctl: failed to set '%s' to '%s': (%d) %s",
		       path, value, errno, strerror (errno));
	} else if (nwrote < len) {
		_LOGE ("sysctl: failed to set '%s' to '%s' after three attempts",
		       path, value);
	}

	g_free (actual);
	close (fd);
	return (nwrote == len);
}

static GSList *sysctl_clear_cache_list;

void
_nm_linux_platform_sysctl_clear_cache (void)
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
	GError *error = NULL;
	char *contents;

	/* Don't write outside known locations */
	g_assert (g_str_has_prefix (path, "/proc/sys/")
	          || g_str_has_prefix (path, "/sys/"));
	/* Don't write to suspicious locations */
	g_assert (!strstr (path, "/../"));

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

static const NMPObject *
cache_lookup_link (NMPlatform *platform, int ifindex)
{
	const NMPObject *obj_cache;

	obj_cache = nmp_cache_lookup_link (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, ifindex);
	if (!nmp_object_is_visible (obj_cache))
		return NULL;

	return obj_cache;
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

static struct nl_object *
build_rtnl_link (int ifindex, const char *name, NMLinkType type)
{
	struct rtnl_link *rtnllink;
	int nle;

	rtnllink = _nl_rtnl_link_alloc (ifindex, name);
	if (type) {
		nle = rtnl_link_set_type (rtnllink, nm_link_type_to_rtnl_type_string (type));
		g_assert (!nle);
	}
	return (struct nl_object *) rtnllink;
}

struct nl_object *
_nmp_vt_cmd_plobj_to_nl_link (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only)
{
	const NMPlatformLink *obj = (const NMPlatformLink *) _obj;

	return build_rtnl_link (obj->ifindex,
	                        obj->name[0] ? obj->name : NULL,
	                        obj->type);
}

static gboolean
do_add_link (NMPlatform *platform, const char *name, const struct rtnl_link *nlo)
{
	NMPObject obj_needle;
	int nle;

	event_handler_read_netlink_all (platform, FALSE);

	nle = kernel_add_object (platform, NMP_OBJECT_TYPE_LINK, (const struct nl_object *) nlo);
	if (nle < 0) {
		_LOGE ("do-add-link: failure adding link '%s': %s", name, nl_geterror (nle));
		return FALSE;
	}
	_LOGD ("do-add-link: success adding link '%s'", name);

	nmp_object_stackinit_id_link (&obj_needle, 0);
	g_strlcpy (obj_needle.link.name, name, sizeof (obj_needle.link.name));

	delayed_action_handle_all (platform, TRUE);

	/* FIXME: we add the link object via the second netlink socket. Sometimes,
	 * the notification is not yet ready via nlh_event, so we have to re-request the
	 * link so that it is in the cache. A better solution would be to do everything
	 * via one netlink socket. */
	if (!nmp_cache_lookup_link_full (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, 0, obj_needle.link.name, FALSE, NM_LINK_TYPE_NONE, NULL, NULL)) {
		_LOGT ("do-add-link: reload: the added link is not yet ready. Request %s", obj_needle.link.name);
		do_request_link (platform, 0, obj_needle.link.name, TRUE);
	}

	/* Return true, because kernel_add_object() succeeded. This doesn't indicate that the
	 * object is now actuall in the cache, because there could be a race.
	 *
	 * For that, you'd have to look at @out_obj. */
	return TRUE;
}

static gboolean
do_add_link_with_lookup (NMPlatform *platform, const char *name, const struct rtnl_link *nlo, NMLinkType expected_link_type, NMPlatformLink *out_link)
{
	const NMPObject *obj;

	do_add_link (platform, name, nlo);

	obj = nmp_cache_lookup_link_full (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache,
	                                  0, name, FALSE, expected_link_type, NULL, NULL);
	if (out_link && obj)
		*out_link = obj->link;
	return !!obj;
}

static gboolean
do_add_addrroute (NMPlatform *platform, const NMPObject *obj_id, const struct nl_object *nlo)
{
	int nle;

	nm_assert (NM_IN_SET (NMP_OBJECT_GET_TYPE (obj_id),
	                      NMP_OBJECT_TYPE_IP4_ADDRESS, NMP_OBJECT_TYPE_IP6_ADDRESS,
	                      NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE));

	event_handler_read_netlink_all (platform, FALSE);

	nle = kernel_add_object (platform, NMP_OBJECT_GET_CLASS (obj_id)->obj_type, (const struct nl_object *) nlo);
	if (nle < 0) {
		_LOGW ("do-add-%s: failure adding %s '%s': %s (%d)",
		       NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name,
		       NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name,
		       nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0),
		       nl_geterror (nle), -nle);
		return FALSE;
	}
	_LOGD ("do-add-%s: success adding object %s", NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name, nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0));

	delayed_action_handle_all (platform, TRUE);

	/* FIXME: instead of re-requesting the added object, add it via nlh_event
	 * so that the events are in sync. */
	if (!nmp_cache_lookup_obj (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, obj_id)) {
		_LOGT ("do-add-%s: reload: the added object is not yet ready. Request %s", NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name, nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0));
		do_request_one_type (platform, NMP_OBJECT_GET_TYPE (obj_id), TRUE);
	}

	/* The return value doesn't say, whether the object is in the platform cache after adding
	 * it.
	 * Instead the return value says, whether kernel_add_object() succeeded. */
	return TRUE;
}


static gboolean
do_delete_object (NMPlatform *platform, const NMPObject *obj_id, const struct nl_object *nlo)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	auto_nl_object struct nl_object *nlo_free = NULL;
	int nle;

	event_handler_read_netlink_all (platform, FALSE);

	if (!nlo)
		nlo = nlo_free = nmp_object_to_nl (platform, obj_id, FALSE);

	nle = kernel_delete_object (platform, NMP_OBJECT_GET_TYPE (obj_id), nlo);
	if (nle < 0)
		_LOGE ("do-delete-%s: failure deleting '%s': %s (%d)", NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name, nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0), nl_geterror (nle), -nle);
	else
		_LOGD ("do-delete-%s: success deleting '%s'", NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name, nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0));

	delayed_action_handle_all (platform, TRUE);

	/* FIXME: instead of re-requesting the deleted object, add it via nlh_event
	 * so that the events are in sync. */
	if (NMP_OBJECT_GET_TYPE (obj_id) == NMP_OBJECT_TYPE_LINK) {
		const NMPObject *obj;

		obj = nmp_cache_lookup_link_full (priv->cache, obj_id->link.ifindex, obj_id->link.ifindex <= 0 && obj_id->link.name[0] ? obj_id->link.name : NULL, FALSE, NM_LINK_TYPE_NONE, NULL, NULL);
		if (obj && obj->_link.netlink.is_in_netlink) {
			_LOGT ("do-delete-%s: reload: the deleted object is not yet removed. Request %s", NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name, nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0));
			do_request_link (platform, obj_id->link.ifindex, obj_id->link.name, TRUE);
		}
	} else {
		if (nmp_cache_lookup_obj (priv->cache, obj_id)) {
			_LOGT ("do-delete-%s: reload: the deleted object is not yet removed. Request %s", NMP_OBJECT_GET_CLASS (obj_id)->obj_type_name, nmp_object_to_string (obj_id, NMP_OBJECT_TO_STRING_ID, NULL, 0));
			do_request_one_type (platform, NMP_OBJECT_GET_TYPE (obj_id), TRUE);
		}
	}

	/* The return value doesn't say, whether the object is in the platform cache after adding
	 * it.
	 * Instead the return value says, whether kernel_add_object() succeeded. */
	return nle >= 0;
}

static NMPlatformError
do_change_link (NMPlatform *platform, struct rtnl_link *nlo, gboolean complete_from_cache)
{
	int nle;
	int ifindex;
	gboolean complete_from_cache2 = complete_from_cache;

	ifindex = rtnl_link_get_ifindex (nlo);
	if (ifindex <= 0)
		g_return_val_if_reached (NM_PLATFORM_ERROR_BUG);

	nle = kernel_change_link (platform, nlo, &complete_from_cache2);

	switch (nle) {
	case -NLE_SUCCESS:
		_LOGD ("do-change-link: success changing link %d", ifindex);
		break;
	case -NLE_EXIST:
		_LOGD ("do-change-link: success changing link %d: %s (%d)", ifindex, nl_geterror (nle), -nle);
		break;
	case -NLE_OBJ_NOTFOUND:
		/* fall-through */
	default:
		if (complete_from_cache != complete_from_cache2)
			_LOGD ("do-change-link: failure changing link %d: link does not exist in cache", ifindex);
		else
			_LOGE ("do-change-link: failure changing link %d: %s (%d)", ifindex, nl_geterror (nle), -nle);
		return nle == -NLE_OBJ_NOTFOUND ? NM_PLATFORM_ERROR_NO_FIRMWARE : NM_PLATFORM_ERROR_UNSPECIFIED;
	}

	/* FIXME: as we modify the link via a separate socket, the cache is not in
	 * sync and we have to refetch the link. */
	do_request_link (platform, ifindex, NULL, TRUE);
	return NM_PLATFORM_ERROR_SUCCESS;
}

static gboolean
link_add (NMPlatform *platform,
          const char *name,
          NMLinkType type,
          const void *address,
          size_t address_len,
          NMPlatformLink *out_link)
{
	auto_nl_object struct nl_object *l = NULL;

	if (type == NM_LINK_TYPE_BOND) {
		/* When the kernel loads the bond module, either via explicit modprobe
		 * or automatically in response to creating a bond master, it will also
		 * create a 'bond0' interface.  Since the bond we're about to create may
		 * or may not be named 'bond0' prevent potential confusion about a bond
		 * that the user didn't want by telling the bonding module not to create
		 * bond0 automatically.
		 */
		if (!g_file_test ("/sys/class/net/bonding_masters", G_FILE_TEST_EXISTS))
			nm_utils_modprobe (NULL, TRUE, "bonding", "max_bonds=0", NULL);
	}

	_LOGD ("link: add link '%s' of type '%s' (%d)",
	       name, nm_link_type_to_string (type), (int) type);

	l = build_rtnl_link (0, name, type);

	g_assert ( (address != NULL) ^ (address_len == 0) );
	if (address) {
		auto_nl_addr struct nl_addr *nladdr = _nl_addr_build (AF_LLC, address, address_len);

		rtnl_link_set_addr ((struct rtnl_link *) l, nladdr);
	}

	return do_add_link_with_lookup (platform, name, (struct rtnl_link *) l, type, out_link);
}

static gboolean
link_delete (NMPlatform *platform, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	NMPObject obj_needle;
	const NMPObject *obj;

	obj = nmp_cache_lookup_link (priv->cache, ifindex);
	if (!obj || !obj->_link.netlink.is_in_netlink)
		return FALSE;

	nmp_object_stackinit_id_link (&obj_needle, ifindex);
	return do_delete_object (platform, &obj_needle, NULL);
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
	return str_if_set (obj->link.kind, "unknown");
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
	do_request_link (platform, ifindex, NULL, TRUE);
	return !!cache_lookup_link (platform, ifindex);
}

static NMPlatformError
link_change_flags (NMPlatform *platform, int ifindex, unsigned int flags, gboolean value)
{
	auto_nl_object struct rtnl_link *change = _nl_rtnl_link_alloc (ifindex, NULL);
	const NMPObject *obj_cache;
	char buf[256];

	obj_cache = cache_lookup_link (platform, ifindex);
	if (!obj_cache)
		return NM_PLATFORM_ERROR_NOT_FOUND;

	rtnl_link_set_flags (change, obj_cache->link.flags);
	if (value)
		rtnl_link_set_flags (change, flags);
	else
		rtnl_link_unset_flags (change, flags);

	_LOGD ("link: change %d: flags %s '%s' (%d)", ifindex,
	       value ? "set" : "unset",
	       rtnl_link_flags2str (flags, buf, sizeof (buf)),
	       flags);

	return do_change_link (platform, change, FALSE);
}

static gboolean
link_set_up (NMPlatform *platform, int ifindex, gboolean *out_no_firmware)
{
	NMPlatformError plerr;

	plerr = link_change_flags (platform, ifindex, IFF_UP, TRUE);
	if (out_no_firmware)
		*out_no_firmware = plerr == NM_PLATFORM_ERROR_NO_FIRMWARE;
	return plerr == NM_PLATFORM_ERROR_SUCCESS;
}

static gboolean
link_set_down (NMPlatform *platform, int ifindex)
{
	return link_change_flags (platform, ifindex, IFF_UP, FALSE) == NM_PLATFORM_ERROR_SUCCESS;
}

static gboolean
link_set_arp (NMPlatform *platform, int ifindex)
{
	return link_change_flags (platform, ifindex, IFF_NOARP, FALSE) == NM_PLATFORM_ERROR_SUCCESS;
}

static gboolean
link_set_noarp (NMPlatform *platform, int ifindex)
{
	return link_change_flags (platform, ifindex, IFF_NOARP, TRUE) == NM_PLATFORM_ERROR_SUCCESS;
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
#if HAVE_LIBNL_INET6_ADDR_GEN_MODE
	if (_support_user_ipv6ll_get ()) {
		auto_nl_object struct rtnl_link *nlo = _nl_rtnl_link_alloc (ifindex, NULL);
		guint8 mode = enabled ? IN6_ADDR_GEN_MODE_NONE : IN6_ADDR_GEN_MODE_EUI64;
		char buf[32];

		rtnl_link_inet6_set_addr_gen_mode (nlo, mode);
		_LOGD ("link: change %d: set IPv6 address generation mode to %s",
		       ifindex, rtnl_link_inet6_addrgenmode2str (mode, buf, sizeof (buf)));
		return do_change_link (platform, nlo, TRUE) == NM_PLATFORM_ERROR_SUCCESS;
	}
#endif
	return FALSE;
}

static gboolean
link_supports_carrier_detect (NMPlatform *platform, int ifindex)
{
	const char *name = nm_platform_link_get_name (platform, ifindex);

	if (!name)
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
	const NMPObject *obj;

	obj = cache_lookup_link (platform, ifindex);

	/* Only ARPHRD_ETHER links can possibly support VLANs. */
	if (!obj || obj->link.arptype != ARPHRD_ETHER)
		return FALSE;

	return nmp_utils_ethtool_supports_vlans (obj->link.name);
}

static gboolean
link_set_address (NMPlatform *platform, int ifindex, gconstpointer address, size_t length)
{
	auto_nl_object struct rtnl_link *change = _nl_rtnl_link_alloc (ifindex, NULL);
	auto_nl_addr struct nl_addr *nladdr = _nl_addr_build (AF_LLC, address, length);
	gs_free char *mac = NULL;

	rtnl_link_set_addr (change, nladdr);

	_LOGD ("link: change %d: address %s (%lu bytes)", ifindex,
	       (mac = nm_utils_hwaddr_ntoa (address, length)),
	       (unsigned long) length);
	return do_change_link (platform, change, TRUE) == NM_PLATFORM_ERROR_SUCCESS;
}

static gboolean
link_get_permanent_address (NMPlatform *platform,
                            int ifindex,
                            guint8 *buf,
                            size_t *length)
{
	return nmp_utils_ethtool_get_permanent_address (nm_platform_link_get_name (platform, ifindex), buf, length);
}

static gboolean
link_set_mtu (NMPlatform *platform, int ifindex, guint32 mtu)
{
	auto_nl_object struct rtnl_link *change = _nl_rtnl_link_alloc (ifindex, NULL);

	rtnl_link_set_mtu (change, mtu);
	_LOGD ("link: change %d: mtu %lu", ifindex, (unsigned long)mtu);

	return do_change_link (platform, change, TRUE) == NM_PLATFORM_ERROR_SUCCESS;
}

static char *
link_get_physical_port_id (NMPlatform *platform, int ifindex)
{
	const char *ifname;
	char *path, *id;

	ifname = nm_platform_link_get_name (platform, ifindex);
	if (!ifname)
		return NULL;

	ifname = ASSERT_VALID_PATH_COMPONENT (ifname);

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

	ifname = ASSERT_VALID_PATH_COMPONENT (ifname);

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
          NMPlatformLink *out_link)
{
	auto_nl_object struct rtnl_link *rtnllink = (struct rtnl_link *) build_rtnl_link (0, name, NM_LINK_TYPE_VLAN);
	unsigned int kernel_flags;
	unsigned int all_flags = NM_VLAN_FLAGS_ALL;

	G_STATIC_ASSERT (NM_VLAN_FLAG_REORDER_HEADERS == (guint32) VLAN_FLAG_REORDER_HDR);
	G_STATIC_ASSERT (NM_VLAN_FLAG_GVRP == (guint32) VLAN_FLAG_GVRP);
	G_STATIC_ASSERT (NM_VLAN_FLAG_LOOSE_BINDING == (guint32) VLAN_FLAG_LOOSE_BINDING);
	G_STATIC_ASSERT (NM_VLAN_FLAG_MVRP == (guint32) VLAN_FLAG_MVRP);

	kernel_flags = vlan_flags & ((guint32) NM_VLAN_FLAGS_ALL);

	rtnl_link_set_link (rtnllink, parent);
	rtnl_link_vlan_set_id (rtnllink, vlan_id);
	rtnl_link_vlan_unset_flags (rtnllink, all_flags);
	rtnl_link_vlan_set_flags (rtnllink, kernel_flags);

	_LOGD ("link: add vlan '%s', parent %d, vlan id %d, flags %X (native: %X)",
	       name, parent, vlan_id, (unsigned int) vlan_flags, kernel_flags);

	return do_add_link_with_lookup (platform, name, rtnllink, NM_LINK_TYPE_VLAN, out_link);
}

static gboolean
vlan_get_info (NMPlatform *platform, int ifindex, int *parent, int *vlan_id)
{
	const NMPObject *obj = cache_lookup_link (platform, ifindex);
	int p = 0, v = 0;

	if (obj) {
		p = obj->link.parent;
		v = obj->link.vlan_id;
	}
	if (parent)
		*parent = p;
	if (vlan_id)
		*vlan_id = v;
	return !!obj;
}

static gboolean
vlan_set_ingress_map (NMPlatform *platform, int ifindex, int from, int to)
{
	auto_nl_object struct rtnl_link *change = (struct rtnl_link *) build_rtnl_link (ifindex, NULL, NM_LINK_TYPE_VLAN);

	rtnl_link_vlan_set_ingress_map (change, from, to);

	_LOGD ("link: change %d: vlan ingress map %d -> %d", ifindex, from, to);

	return do_change_link (platform, change, TRUE) == NM_PLATFORM_ERROR_SUCCESS;
}

static gboolean
vlan_set_egress_map (NMPlatform *platform, int ifindex, int from, int to)
{
	auto_nl_object struct rtnl_link *change = (struct rtnl_link *) build_rtnl_link (ifindex, NULL, NM_LINK_TYPE_VLAN);

	rtnl_link_vlan_set_egress_map (change, from, to);

	_LOGD ("link: change %d: vlan egress map %d -> %d", ifindex, from, to);

	return do_change_link (platform, change, TRUE) == NM_PLATFORM_ERROR_SUCCESS;
}

static gboolean
link_enslave (NMPlatform *platform, int master, int slave)
{
	auto_nl_object struct rtnl_link *change = _nl_rtnl_link_alloc (slave, NULL);

	rtnl_link_set_master (change, master);
	_LOGD ("link: change %d: enslave to master %d", slave, master);

	return do_change_link (platform, change, TRUE) == NM_PLATFORM_ERROR_SUCCESS;
}

static gboolean
link_release (NMPlatform *platform, int master, int slave)
{
	return link_enslave (platform, 0, slave);
}

static char *
link_option_path (NMPlatform *platform, int master, const char *category, const char *option)
{
	const char *name = nm_platform_link_get_name (platform, master);

	if (!name || !category || !option)
		return NULL;

	return g_strdup_printf ("/sys/class/net/%s/%s/%s",
	                        ASSERT_VALID_PATH_COMPONENT (name),
	                        ASSERT_VALID_PATH_COMPONENT (category),
	                        ASSERT_VALID_PATH_COMPONENT (option));
}

static gboolean
link_set_option (NMPlatform *platform, int master, const char *category, const char *option, const char *value)
{
	gs_free char *path = link_option_path (platform, master, category, option);

	return path && nm_platform_sysctl_set (platform, path, value);
}

static char *
link_get_option (NMPlatform *platform, int master, const char *category, const char *option)
{
	gs_free char *path = link_option_path (platform, master, category, option);

	return path ? nm_platform_sysctl_get (platform, path) : NULL;
}

static const char *
master_category (NMPlatform *platform, int master)
{
	switch (nm_platform_link_get_type (platform, master)) {
	case NM_LINK_TYPE_BRIDGE:
		return "bridge";
	case NM_LINK_TYPE_BOND:
		return "bonding";
	default:
		return NULL;
	}
}

static const char *
slave_category (NMPlatform *platform, int slave)
{
	int master = nm_platform_link_get_master (platform, slave);

	if (master <= 0)
		return NULL;

	switch (nm_platform_link_get_type (platform, master)) {
	case NM_LINK_TYPE_BRIDGE:
		return "brport";
	default:
		return NULL;
	}
}

static gboolean
master_set_option (NMPlatform *platform, int master, const char *option, const char *value)
{
	return link_set_option (platform, master, master_category (platform, master), option, value);
}

static char *
master_get_option (NMPlatform *platform, int master, const char *option)
{
	return link_get_option (platform, master, master_category (platform, master), option);
}

static gboolean
slave_set_option (NMPlatform *platform, int slave, const char *option, const char *value)
{
	return link_set_option (platform, slave, slave_category (platform, slave), option, value);
}

static char *
slave_get_option (NMPlatform *platform, int slave, const char *option)
{
	return link_get_option (platform, slave, slave_category (platform, slave), option);
}

/******************************************************************/

static gboolean
infiniband_partition_add (NMPlatform *platform, int parent, int p_key, NMPlatformLink *out_link)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	const NMPObject *obj_parent;
	const NMPObject *obj;
	gs_free char *path = NULL;
	gs_free char *id = NULL;
	gs_free char *ifname = NULL;

	obj_parent = nmp_cache_lookup_link (priv->cache, parent);
	if (!obj_parent || !obj_parent->link.name[0])
		g_return_val_if_reached (FALSE);

	ifname = g_strdup_printf ("%s.%04x", obj_parent->link.name, p_key);

	path = g_strdup_printf ("/sys/class/net/%s/create_child", ASSERT_VALID_PATH_COMPONENT (obj_parent->link.name));
	id = g_strdup_printf ("0x%04x", p_key);
	if (!nm_platform_sysctl_set (platform, path, id))
		return FALSE;

	do_request_link (platform, 0, ifname, TRUE);

	obj = nmp_cache_lookup_link_full (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache,
	                                  0, ifname, FALSE, NM_LINK_TYPE_INFINIBAND, NULL, NULL);
	if (out_link && obj)
		*out_link = obj->link;
	return !!obj;
}

typedef struct {
	int p_key;
	const char *mode;
} IpoibInfo;

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

static const struct nla_policy infiniband_info_policy[IFLA_IPOIB_MAX + 1] = {
	[IFLA_IPOIB_PKEY]	= { .type = NLA_U16 },
	[IFLA_IPOIB_MODE]	= { .type = NLA_U16 },
	[IFLA_IPOIB_UMCAST]	= { .type = NLA_U16 },
};

static int
infiniband_info_data_parser (struct nlattr *info_data, gpointer parser_data)
{
	IpoibInfo *info = parser_data;
	struct nlattr *tb[IFLA_MACVLAN_MAX + 1];
	int err;

	err = nla_parse_nested (tb, IFLA_IPOIB_MAX, info_data,
	                        (struct nla_policy *) infiniband_info_policy);
	if (err < 0)
		return err;
	if (!tb[IFLA_IPOIB_PKEY] || !tb[IFLA_IPOIB_MODE])
		return -EINVAL;

	info->p_key = nla_get_u16 (tb[IFLA_IPOIB_PKEY]);

	switch (nla_get_u16 (tb[IFLA_IPOIB_MODE])) {
	case IPOIB_MODE_DATAGRAM:
		info->mode = "datagram";
		break;
	case IPOIB_MODE_CONNECTED:
		info->mode = "connected";
		break;
	default:
		return -NLE_PARSE_ERR;
	}

	return 0;
}

static gboolean
infiniband_get_info (NMPlatform *platform, int ifindex, int *parent, int *p_key, const char **mode)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	const NMPObject *obj;
	IpoibInfo info = { -1, NULL };

	obj = cache_lookup_link (platform, ifindex);
	if (!obj)
		return FALSE;

	if (parent)
		*parent = obj->link.parent;

	if (_nl_link_parse_info_data (priv->nlh,
	                              ifindex,
	                              infiniband_info_data_parser,
	                              &info) != 0) {
		const char *iface = obj->link.name;
		char *path, *contents = NULL;

		/* Fall back to reading sysfs */
		path = g_strdup_printf ("/sys/class/net/%s/mode", ASSERT_VALID_PATH_COMPONENT (iface));
		contents = nm_platform_sysctl_get (platform, path);
		g_free (path);
		if (!contents)
			return FALSE;

		if (strstr (contents, "datagram"))
			info.mode = "datagram";
		else if (strstr (contents, "connected"))
			info.mode = "connected";
		g_free (contents);

		path = g_strdup_printf ("/sys/class/net/%s/pkey", ASSERT_VALID_PATH_COMPONENT (iface));
		contents = nm_platform_sysctl_get (platform, path);
		g_free (path);
		if (!contents)
			return FALSE;

		info.p_key = (int) _nm_utils_ascii_str_to_int64 (contents, 16, 0, 0xFFFF, -1);
		g_free (contents);

		if (info.p_key < 0)
			return FALSE;
	}

	if (p_key)
		*p_key = info.p_key;
	if (mode)
		*mode = info.mode;
	return TRUE;
}

/******************************************************************/

static gboolean
veth_get_properties (NMPlatform *platform, int ifindex, NMPlatformVethProperties *props)
{
	const char *ifname;
	int peer_ifindex;

	ifname = nm_platform_link_get_name (platform, ifindex);
	if (!ifname)
		return FALSE;

	peer_ifindex = nmp_utils_ethtool_get_peer_ifindex (ifname);
	if (peer_ifindex <= 0)
		return FALSE;

	props->peer = peer_ifindex;
	return TRUE;
}

/******************************************************************/

static gboolean
tun_get_properties_ifname (NMPlatform *platform, const char *ifname, NMPlatformTunProperties *props)
{
	char *path, *val;
	gboolean success = TRUE;

	g_return_val_if_fail (props, FALSE);

	memset (props, 0, sizeof (*props));
	props->owner = -1;
	props->group = -1;

	if (!ifname || !nm_utils_iface_valid_name (ifname))
		return FALSE;
	ifname = ASSERT_VALID_PATH_COMPONENT (ifname);

	path = g_strdup_printf ("/sys/class/net/%s/owner", ifname);
	val = nm_platform_sysctl_get (platform, path);
	g_free (path);
	if (val) {
		props->owner = _nm_utils_ascii_str_to_int64 (val, 10, -1, G_MAXINT64, -1);
		if (errno)
			success = FALSE;
		g_free (val);
	} else
		success = FALSE;

	path = g_strdup_printf ("/sys/class/net/%s/group", ifname);
	val = nm_platform_sysctl_get (platform, path);
	g_free (path);
	if (val) {
		props->group = _nm_utils_ascii_str_to_int64 (val, 10, -1, G_MAXINT64, -1);
		if (errno)
			success = FALSE;
		g_free (val);
	} else
		success = FALSE;

	path = g_strdup_printf ("/sys/class/net/%s/tun_flags", ifname);
	val = nm_platform_sysctl_get (platform, path);
	g_free (path);
	if (val) {
		gint64 flags;

		flags = _nm_utils_ascii_str_to_int64 (val, 16, 0, G_MAXINT64, 0);
		if (!errno) {
#ifndef IFF_MULTI_QUEUE
			const int IFF_MULTI_QUEUE = 0x0100;
#endif
			props->mode = ((flags & (IFF_TUN | IFF_TAP)) == IFF_TUN) ? "tun" : "tap";
			props->no_pi = !!(flags & IFF_NO_PI);
			props->vnet_hdr = !!(flags & IFF_VNET_HDR);
			props->multi_queue = !!(flags & IFF_MULTI_QUEUE);
		} else
			success = FALSE;
		g_free (val);
	} else
		success = FALSE;

	return success;
}

static gboolean
tun_get_properties (NMPlatform *platform, int ifindex, NMPlatformTunProperties *props)
{
	return tun_get_properties_ifname (platform, nm_platform_link_get_name (platform, ifindex), props);
}

/******************************************************************/

static const struct nla_policy macvlan_info_policy[IFLA_MACVLAN_MAX + 1] = {
	[IFLA_MACVLAN_MODE]  = { .type = NLA_U32 },
#ifdef MACVLAN_FLAG_NOPROMISC
	[IFLA_MACVLAN_FLAGS] = { .type = NLA_U16 },
#endif
};

static int
macvlan_info_data_parser (struct nlattr *info_data, gpointer parser_data)
{
	NMPlatformMacvlanProperties *props = parser_data;
	struct nlattr *tb[IFLA_MACVLAN_MAX + 1];
	int err;

	err = nla_parse_nested (tb, IFLA_MACVLAN_MAX, info_data,
	                        (struct nla_policy *) macvlan_info_policy);
	if (err < 0)
		return err;

	switch (nla_get_u32 (tb[IFLA_MACVLAN_MODE])) {
	case MACVLAN_MODE_PRIVATE:
		props->mode = "private";
		break;
	case MACVLAN_MODE_VEPA:
		props->mode = "vepa";
		break;
	case MACVLAN_MODE_BRIDGE:
		props->mode = "bridge";
		break;
	case MACVLAN_MODE_PASSTHRU:
		props->mode = "passthru";
		break;
	default:
		return -NLE_PARSE_ERR;
	}

#ifdef MACVLAN_FLAG_NOPROMISC
	props->no_promisc = !!(nla_get_u16 (tb[IFLA_MACVLAN_FLAGS]) & MACVLAN_FLAG_NOPROMISC);
#else
	props->no_promisc = FALSE;
#endif

	return 0;
}

static gboolean
macvlan_get_properties (NMPlatform *platform, int ifindex, NMPlatformMacvlanProperties *props)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int err;
	const NMPObject *obj;

	obj = cache_lookup_link (platform, ifindex);
	if (!obj)
		return FALSE;

	props->parent_ifindex = obj->link.parent;

	err = _nl_link_parse_info_data (priv->nlh, ifindex,
	                                macvlan_info_data_parser, props);
	if (err != 0) {
		_LOGW ("(%s) could not read properties: %s",
		       obj->link.name, nl_geterror (err));
	}
	return (err == 0);
}

/******************************************************************/

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

static const struct nla_policy vxlan_info_policy[IFLA_VXLAN_MAX + 1] = {
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

static int
vxlan_info_data_parser (struct nlattr *info_data, gpointer parser_data)
{
	NMPlatformVxlanProperties *props = parser_data;
	struct nlattr *tb[IFLA_VXLAN_MAX + 1];
	struct nm_ifla_vxlan_port_range *range;
	int err;

	err = nla_parse_nested (tb, IFLA_VXLAN_MAX, info_data,
	                        (struct nla_policy *) vxlan_info_policy);
	if (err < 0)
		return err;

	memset (props, 0, sizeof (*props));

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
		props->dst_port = nla_get_u16 (tb[IFLA_VXLAN_PORT]);

	if (tb[IFLA_VXLAN_PORT_RANGE]) {
		range = nla_data (tb[IFLA_VXLAN_PORT_RANGE]);
		props->src_port_min = range->low;
		props->src_port_max = range->high;
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

	return 0;
}

static gboolean
vxlan_get_properties (NMPlatform *platform, int ifindex, NMPlatformVxlanProperties *props)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int err;

	err = _nl_link_parse_info_data (priv->nlh, ifindex,
	                                vxlan_info_data_parser, props);
	if (err != 0) {
		_LOGW ("(%s) could not read vxlan properties: %s",
		       nm_platform_link_get_name (platform, ifindex), nl_geterror (err));
	}
	return (err == 0);
}

/******************************************************************/

static const struct nla_policy gre_info_policy[IFLA_GRE_MAX + 1] = {
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

static int
gre_info_data_parser (struct nlattr *info_data, gpointer parser_data)
{
	NMPlatformGreProperties *props = parser_data;
	struct nlattr *tb[IFLA_GRE_MAX + 1];
	int err;

	err = nla_parse_nested (tb, IFLA_GRE_MAX, info_data,
	                        (struct nla_policy *) gre_info_policy);
	if (err < 0)
		return err;

	props->parent_ifindex = tb[IFLA_GRE_LINK] ? nla_get_u32 (tb[IFLA_GRE_LINK]) : 0;
	props->input_flags = nla_get_u16 (tb[IFLA_GRE_IFLAGS]);
	props->output_flags = nla_get_u16 (tb[IFLA_GRE_OFLAGS]);
	props->input_key = (props->input_flags & GRE_KEY) ? nla_get_u32 (tb[IFLA_GRE_IKEY]) : 0;
	props->output_key = (props->output_flags & GRE_KEY) ? nla_get_u32 (tb[IFLA_GRE_OKEY]) : 0;
	props->local = nla_get_u32 (tb[IFLA_GRE_LOCAL]);
	props->remote = nla_get_u32 (tb[IFLA_GRE_REMOTE]);
	props->tos = nla_get_u8 (tb[IFLA_GRE_TOS]);
	props->ttl = nla_get_u8 (tb[IFLA_GRE_TTL]);
	props->path_mtu_discovery = !!nla_get_u8 (tb[IFLA_GRE_PMTUDISC]);

	return 0;
}

static gboolean
gre_get_properties (NMPlatform *platform, int ifindex, NMPlatformGreProperties *props)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int err;

	err = _nl_link_parse_info_data (priv->nlh, ifindex,
	                                gre_info_data_parser, props);
	if (err != 0) {
		_LOGW ("(%s) could not read gre properties: %s",
		       nm_platform_link_get_name (platform, ifindex), nl_geterror (err));
	}
	return (err == 0);
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

static gboolean
wifi_get_capabilities (NMPlatform *platform, int ifindex, NMDeviceWifiCapabilities *caps)
{
	WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

	if (!wifi_data)
		return FALSE;

	if (caps)
		*caps = wifi_utils_get_caps (wifi_data);
	return TRUE;
}

static gboolean
wifi_get_bssid (NMPlatform *platform, int ifindex, guint8 *bssid)
{
	WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

	if (!wifi_data)
		return FALSE;
	return wifi_utils_get_bssid (wifi_data, bssid);
}

static guint32
wifi_get_frequency (NMPlatform *platform, int ifindex)
{
	WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

	if (!wifi_data)
		return 0;
	return wifi_utils_get_freq (wifi_data);
}

static gboolean
wifi_get_quality (NMPlatform *platform, int ifindex)
{
	WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

	if (!wifi_data)
		return FALSE;
	return wifi_utils_get_qual (wifi_data);
}

static guint32
wifi_get_rate (NMPlatform *platform, int ifindex)
{
	WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

	if (!wifi_data)
		return FALSE;
	return wifi_utils_get_rate (wifi_data);
}

static NM80211Mode
wifi_get_mode (NMPlatform *platform, int ifindex)
{
	WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

	if (!wifi_data)
		return NM_802_11_MODE_UNKNOWN;

	return wifi_utils_get_mode (wifi_data);
}

static void
wifi_set_mode (NMPlatform *platform, int ifindex, NM80211Mode mode)
{
	WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

	if (wifi_data)
		wifi_utils_set_mode (wifi_data, mode);
}

static void
wifi_set_powersave (NMPlatform *platform, int ifindex, guint32 powersave)
{
	WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

	if (wifi_data)
		wifi_utils_set_powersave (wifi_data, powersave);
}

static guint32
wifi_find_frequency (NMPlatform *platform, int ifindex, const guint32 *freqs)
{
	WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

	if (!wifi_data)
		return 0;

	return wifi_utils_find_freq (wifi_data, freqs);
}

static void
wifi_indicate_addressing_running (NMPlatform *platform, int ifindex, gboolean running)
{
	WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

	if (wifi_data)
		wifi_utils_indicate_addressing_running (wifi_data, running);
}

/******************************************************************/

static guint32
mesh_get_channel (NMPlatform *platform, int ifindex)
{
	WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

	if (!wifi_data)
		return 0;

	return wifi_utils_get_mesh_channel (wifi_data);
}

static gboolean
mesh_set_channel (NMPlatform *platform, int ifindex, guint32 channel)
{
	WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

	if (!wifi_data)
		return FALSE;

	return wifi_utils_set_mesh_channel (wifi_data, channel);
}

static gboolean
mesh_set_ssid (NMPlatform *platform, int ifindex, const guint8 *ssid, gsize len)
{
	WifiData *wifi_data = wifi_get_wifi_data (platform, ifindex);

	if (!wifi_data)
		return FALSE;

	return wifi_utils_set_mesh_ssid (wifi_data, ssid, len);
}

/******************************************************************/

static gboolean
link_get_wake_on_lan (NMPlatform *platform, int ifindex)
{
	NMLinkType type = nm_platform_link_get_type (platform, ifindex);

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

#define IPV4LL_NETWORK (htonl (0xA9FE0000L))
#define IPV4LL_NETMASK (htonl (0xFFFF0000L))

static gboolean
ip4_is_link_local (const struct in_addr *src)
{
	return (src->s_addr & IPV4LL_NETMASK) == IPV4LL_NETWORK;
}

static struct nl_object *
build_rtnl_addr (NMPlatform *platform,
                 int family,
                 int ifindex,
                 gconstpointer addr,
                 gconstpointer peer_addr,
                 int plen,
                 guint32 lifetime,
                 guint32 preferred,
                 guint flags,
                 const char *label)
{
	auto_nl_object struct rtnl_addr *rtnladdr = _nl_rtnl_addr_alloc (ifindex);
	struct rtnl_addr *rtnladdr_copy;
	int addrlen = family == AF_INET ? sizeof (in_addr_t) : sizeof (struct in6_addr);
	auto_nl_addr struct nl_addr *nladdr = _nl_addr_build (family, addr, addrlen);
	int nle;

	/* IP address */
	nle = rtnl_addr_set_local (rtnladdr, nladdr);
	if (nle) {
		_LOGE ("build_rtnl_addr(): rtnl_addr_set_local failed with %s (%d)", nl_geterror (nle), nle);
		return NULL;
	}

	/* Tighten scope (IPv4 only) */
	if (family == AF_INET && ip4_is_link_local (addr))
		rtnl_addr_set_scope (rtnladdr, RT_SCOPE_LINK);

	/* IPv4 Broadcast address */
	if (family == AF_INET) {
		in_addr_t bcast;
		auto_nl_addr struct nl_addr *bcaddr = NULL;

		bcast = *((in_addr_t *) addr) | ~nm_utils_ip4_prefix_to_netmask (plen);
		bcaddr = _nl_addr_build (family, &bcast, addrlen);
		g_assert (bcaddr);
		rtnl_addr_set_broadcast (rtnladdr, bcaddr);
	}

	/* Peer/point-to-point address */
	if (peer_addr) {
		auto_nl_addr struct nl_addr *nlpeer = _nl_addr_build (family, peer_addr, addrlen);

		nle = rtnl_addr_set_peer (rtnladdr, nlpeer);
		if (nle && nle != -NLE_AF_NOSUPPORT) {
			/* IPv6 doesn't support peer addresses yet */
			_LOGE ("build_rtnl_addr(): rtnl_addr_set_peer failed with %s (%d)", nl_geterror (nle), nle);
			return NULL;
		}
	}

	_nl_rtnl_addr_set_prefixlen (rtnladdr, plen);
	if (   (lifetime  != 0 && lifetime  != NM_PLATFORM_LIFETIME_PERMANENT)
	    || (preferred != 0 && preferred != NM_PLATFORM_LIFETIME_PERMANENT)) {
		/* note that here we set the relative timestamps (ticking from *now*). */
		rtnl_addr_set_valid_lifetime (rtnladdr, lifetime);
		rtnl_addr_set_preferred_lifetime (rtnladdr, preferred);
	}
	if (flags) {
		if ((flags & ~0xFF) && !_support_kernel_extended_ifa_flags_get ()) {
			/* Older kernels don't accept unknown netlink attributes.
			 *
			 * With commit libnl commit 5206c050504f8676a24854519b9c351470fb7cc6, libnl will only set
			 * the extended address flags attribute IFA_FLAGS when necessary (> 8 bit). But it's up to
			 * us not to shove those extended flags on to older kernels.
			 *
			 * Just silently clear them. The kernel should ignore those unknown flags anyway. */
			flags &= 0xFF;
		}
		rtnl_addr_set_flags (rtnladdr, flags);
	}
	if (label && *label)
		rtnl_addr_set_label (rtnladdr, label);

	rtnladdr_copy = rtnladdr;
	rtnladdr = NULL;
	return (struct nl_object *) rtnladdr_copy;
}

struct nl_object *
_nmp_vt_cmd_plobj_to_nl_ip4_address (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only)
{
	const NMPlatformIP4Address *obj = (const NMPlatformIP4Address *) _obj;
	guint32 lifetime, preferred;

	nmp_utils_lifetime_get (obj->timestamp, obj->lifetime, obj->preferred,
	                        0, 0, &lifetime, &preferred);

	return build_rtnl_addr (platform,
	                        AF_INET,
	                        obj->ifindex,
	                        &obj->address,
	                        obj->peer_address ? &obj->peer_address : NULL,
	                        obj->plen,
	                        lifetime,
	                        preferred,
	                        0,
	                        obj->label[0] ? obj->label : NULL);
}

struct nl_object *
_nmp_vt_cmd_plobj_to_nl_ip6_address (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only)
{
	const NMPlatformIP6Address *obj = (const NMPlatformIP6Address *) _obj;
	guint32 lifetime, preferred;

	nmp_utils_lifetime_get (obj->timestamp, obj->lifetime, obj->preferred,
	                        0, 0, &lifetime, &preferred);

	return build_rtnl_addr (platform,
	                        AF_INET6,
	                        obj->ifindex,
	                        &obj->address,
	                        !IN6_IS_ADDR_UNSPECIFIED (&obj->peer_address) ? &obj->peer_address : NULL,
	                        obj->plen,
	                        lifetime,
	                        preferred,
	                        0,
	                        NULL);
}

static gboolean
ip4_address_add (NMPlatform *platform,
                 int ifindex,
                 in_addr_t addr,
                 int plen,
                 in_addr_t peer_addr,
                 guint32 lifetime,
                 guint32 preferred,
                 const char *label)
{
	NMPObject obj_needle;
	auto_nl_object struct nl_object *nlo = NULL;

	nlo = build_rtnl_addr (platform, AF_INET, ifindex, &addr,
	                       peer_addr ? &peer_addr : NULL,
	                       plen, lifetime, preferred, 0,
	                       label);
	return do_add_addrroute (platform,
	                         nmp_object_stackinit_id_ip4_address (&obj_needle, ifindex, addr, plen, peer_addr),
	                         nlo);
}

static gboolean
ip6_address_add (NMPlatform *platform,
                 int ifindex,
                 struct in6_addr addr,
                 int plen,
                 struct in6_addr peer_addr,
                 guint32 lifetime,
                 guint32 preferred,
                 guint flags)
{
	NMPObject obj_needle;
	auto_nl_object struct nl_object *nlo = NULL;

	nlo = build_rtnl_addr (platform, AF_INET6, ifindex, &addr,
	                       IN6_IS_ADDR_UNSPECIFIED (&peer_addr) ? NULL : &peer_addr,
	                       plen, lifetime, preferred, flags,
	                       NULL);
	return do_add_addrroute (platform,
	                         nmp_object_stackinit_id_ip6_address (&obj_needle, ifindex, &addr, plen),
	                         nlo);
}

static gboolean
ip4_address_delete (NMPlatform *platform, int ifindex, in_addr_t addr, int plen, in_addr_t peer_address)
{
	NMPObject obj_needle;

	nmp_object_stackinit_id_ip4_address (&obj_needle, ifindex, addr, plen, peer_address);
	return do_delete_object (platform, &obj_needle, NULL);
}

static gboolean
ip6_address_delete (NMPlatform *platform, int ifindex, struct in6_addr addr, int plen)
{
	NMPObject obj_needle;

	nmp_object_stackinit_id_ip6_address (&obj_needle, ifindex, &addr, plen);
	return do_delete_object (platform, &obj_needle, NULL);
}

static const NMPlatformIP4Address *
ip4_address_get (NMPlatform *platform, int ifindex, in_addr_t addr, int plen, in_addr_t peer_address)
{
	NMPObject obj_needle;
	const NMPObject *obj;

	nmp_object_stackinit_id_ip4_address (&obj_needle, ifindex, addr, plen, peer_address);
	obj = nmp_cache_lookup_obj (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, &obj_needle);
	if (nmp_object_is_visible (obj))
		return &obj->ip4_address;
	return NULL;
}

static const NMPlatformIP6Address *
ip6_address_get (NMPlatform *platform, int ifindex, struct in6_addr addr, int plen)
{
	NMPObject obj_needle;
	const NMPObject *obj;

	nmp_object_stackinit_id_ip6_address (&obj_needle, ifindex, &addr, plen);
	obj = nmp_cache_lookup_obj (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, &obj_needle);
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
		    || routes[i]->source != NM_IP_CONFIG_SOURCE_RTPROT_KERNEL)
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

static void
clear_host_address (int family, const void *network, int plen, void *dst)
{
	g_return_if_fail (plen == (guint8)plen);
	g_return_if_fail (network);

	switch (family) {
	case AF_INET:
		*((in_addr_t *) dst) = nm_utils_ip4_address_clear_host_address (*((in_addr_t *) network), plen);
		break;
	case AF_INET6:
		nm_utils_ip6_address_clear_host_address ((struct in6_addr *) dst, (const struct in6_addr *) network, plen);
		break;
	default:
		g_assert_not_reached ();
	}
}

static struct nl_object *
build_rtnl_route (int family, int ifindex, NMIPConfigSource source,
                  gconstpointer network, int plen, gconstpointer gateway,
                  gconstpointer pref_src,
                  guint32 metric, guint32 mss)
{
	guint32 network_clean[4];
	struct rtnl_route *rtnlroute;
	struct rtnl_nexthop *nexthop;
	int addrlen = (family == AF_INET) ? sizeof (in_addr_t) : sizeof (struct in6_addr);
	/* Workaround a libnl bug by using zero destination address length for default routes */
	auto_nl_addr struct nl_addr *dst = NULL;
	auto_nl_addr struct nl_addr *gw = gateway ? _nl_addr_build (family, gateway, addrlen) : NULL;
	auto_nl_addr struct nl_addr *pref_src_nl = pref_src ? _nl_addr_build (family, pref_src, addrlen) : NULL;

	/* There seem to be problems adding a route with non-zero host identifier.
	 * Adding IPv6 routes is simply ignored, without error message.
	 * In the IPv4 case, we got an error. Thus, we have to make sure, that
	 * the address is sane. */
	clear_host_address (family, network, plen, network_clean);
	dst = _nl_addr_build (family, network_clean, plen ? addrlen : 0);
	nl_addr_set_prefixlen (dst, plen);

	rtnlroute = _nl_rtnl_route_alloc ();
	rtnl_route_set_table (rtnlroute, RT_TABLE_MAIN);
	rtnl_route_set_tos (rtnlroute, 0);
	rtnl_route_set_dst (rtnlroute, dst);
	rtnl_route_set_priority (rtnlroute, metric);
	rtnl_route_set_family (rtnlroute, family);
	rtnl_route_set_protocol (rtnlroute, _nm_ip_config_source_to_rtprot (source));

	nexthop = _nl_rtnl_route_nh_alloc ();
	rtnl_route_nh_set_ifindex (nexthop, ifindex);
	if (gw && !nl_addr_iszero (gw))
		rtnl_route_nh_set_gateway (nexthop, gw);
	if (pref_src_nl)
		rtnl_route_set_pref_src (rtnlroute, pref_src_nl);
	rtnl_route_add_nexthop (rtnlroute, nexthop);

	if (mss > 0)
		rtnl_route_set_metric (rtnlroute, RTAX_ADVMSS, mss);

	return (struct nl_object *) rtnlroute;
}

struct nl_object *
_nmp_vt_cmd_plobj_to_nl_ip4_route (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only)
{
	const NMPlatformIP4Route *obj = (const NMPlatformIP4Route *) _obj;

	return build_rtnl_route (AF_INET,
	                         obj->ifindex,
	                         obj->source,
	                         &obj->network,
	                         obj->plen,
	                         &obj->gateway,
	                         obj->pref_src ? &obj->pref_src : NULL,
	                         obj->metric,
	                         obj->mss);
}

struct nl_object *
_nmp_vt_cmd_plobj_to_nl_ip6_route (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only)
{
	const NMPlatformIP6Route *obj = (const NMPlatformIP6Route *) _obj;

	return build_rtnl_route (AF_INET6,
	                         obj->ifindex,
	                         obj->source,
	                         &obj->network,
	                         obj->plen,
	                         &obj->gateway,
	                         NULL,
	                         obj->metric,
	                         obj->mss);
}

static gboolean
ip4_route_add (NMPlatform *platform, int ifindex, NMIPConfigSource source,
               in_addr_t network, int plen, in_addr_t gateway,
               guint32 pref_src, guint32 metric, guint32 mss)
{
	NMPObject obj_needle;
	auto_nl_object struct nl_object *nlo = NULL;

	nlo = build_rtnl_route (AF_INET, ifindex, source, &network, plen, &gateway, pref_src ? &pref_src : NULL, metric, mss);
	return do_add_addrroute (platform,
	                         nmp_object_stackinit_id_ip4_route (&obj_needle, ifindex, network, plen, metric),
	                         nlo);
}

static gboolean
ip6_route_add (NMPlatform *platform, int ifindex, NMIPConfigSource source,
               struct in6_addr network, int plen, struct in6_addr gateway,
               guint32 metric, guint32 mss)
{
	NMPObject obj_needle;
	auto_nl_object struct nl_object *nlo = NULL;

	metric = nm_utils_ip6_route_metric_normalize (metric);

	nlo = build_rtnl_route (AF_INET6, ifindex, source, &network, plen, &gateway, NULL, metric, mss);
	return do_add_addrroute (platform,
	                         nmp_object_stackinit_id_ip6_route (&obj_needle, ifindex, &network, plen, metric),
	                         nlo);
}

static gboolean
ip4_route_delete (NMPlatform *platform, int ifindex, in_addr_t network, int plen, guint32 metric)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	in_addr_t gateway = 0;
	auto_nl_object struct nl_object *nlo = build_rtnl_route (AF_INET, ifindex, NM_IP_CONFIG_SOURCE_UNKNOWN, &network, plen, &gateway, NULL, metric, 0);
	uint8_t scope = RT_SCOPE_NOWHERE;
	const NMPObject *obj;
	NMPObject obj_needle;

	g_return_val_if_fail (nlo, FALSE);

	nmp_object_stackinit_id_ip4_route (&obj_needle, ifindex, network, plen, metric);

	if (metric == 0) {
		/* Deleting an IPv4 route with metric 0 does not only delete an exectly matching route.
		 * If no route with metric 0 exists, it might delete another route to the same destination.
		 * For nm_platform_ip4_route_delete() we don't want this semantic.
		 *
		 * Instead, make sure that we have the most recent state and process all
		 * delayed actions (including re-reading data from netlink). */
		delayed_action_handle_all (platform, TRUE);
	}

	obj = nmp_cache_lookup_obj (priv->cache, &obj_needle);

	if (metric == 0 && !obj) {
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
		do_request_one_type (platform, NMP_OBJECT_TYPE_IP4_ROUTE, TRUE);

		obj = nmp_cache_lookup_obj (priv->cache, &obj_needle);
		if (!obj)
			return TRUE;
	}

	if (!_nl_has_capability (1 /* NL_CAPABILITY_ROUTE_BUILD_MSG_SET_SCOPE */)) {
		/* When searching for a matching IPv4 route to delete, the kernel
		 * searches for a matching scope, unless the RTM_DELROUTE message
		 * specifies RT_SCOPE_NOWHERE (see fib_table_delete()).
		 *
		 * However, if we set the scope of @rtnlroute to RT_SCOPE_NOWHERE (or
		 * leave it unset), rtnl_route_build_msg() will reset the scope to
		 * rtnl_route_guess_scope() -- which probably guesses wrong.
		 *
		 * As a workaround, we look at the cached route and use that scope.
		 *
		 * Newer versions of libnl, no longer reset the scope if explicitly set to RT_SCOPE_NOWHERE.
		 * So, this workaround is only needed unless we have NL_CAPABILITY_ROUTE_BUILD_MSG_SET_SCOPE.
		 **/

		if (obj)
			scope = nm_platform_route_scope_inv (obj->ip4_route.scope_inv);

		if (scope == RT_SCOPE_NOWHERE) {
			/* If we would set the scope to RT_SCOPE_NOWHERE, libnl would guess the scope.
			 * But probably it will guess 'link' because we set the next hop of the route
			 * to zero (0.0.0.0). A better guess is 'global'. */
			scope = RT_SCOPE_UNIVERSE;
		}
	}
	rtnl_route_set_scope ((struct rtnl_route *) nlo, scope);

	/* we only support routes with TOS zero. As such, delete_route() is also only able to delete
	 * routes with tos==0. build_rtnl_route() already initializes tos properly. */

	/* The following fields are also relevant when comparing the route, but the default values
	 * are already as we want them:
	 *
	 * type: RTN_UNICAST (setting to zero would ignore the type, but we only want to delete RTN_UNICAST)
	 * pref_src: NULL
	 */

	return do_delete_object (platform, &obj_needle, nlo);
}

static gboolean
ip6_route_delete (NMPlatform *platform, int ifindex, struct in6_addr network, int plen, guint32 metric)
{
	struct in6_addr gateway = IN6ADDR_ANY_INIT;
	auto_nl_object struct nl_object *nlo = NULL;
	NMPObject obj_needle;

	metric = nm_utils_ip6_route_metric_normalize (metric);

	nlo = build_rtnl_route (AF_INET6, ifindex, NM_IP_CONFIG_SOURCE_UNKNOWN ,&network, plen, &gateway, NULL, metric, 0);

	nmp_object_stackinit_id_ip6_route (&obj_needle, ifindex, &network, plen, metric);

	return do_delete_object (platform, &obj_needle, nlo);
}

static const NMPlatformIP4Route *
ip4_route_get (NMPlatform *platform, int ifindex, in_addr_t network, int plen, guint32 metric)
{
	NMPObject obj_needle;
	const NMPObject *obj;

	nmp_object_stackinit_id_ip4_route (&obj_needle, ifindex, network, plen, metric);
	obj = nmp_cache_lookup_obj (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, &obj_needle);
	if (nmp_object_is_visible (obj))
		return &obj->ip4_route;
	return NULL;
}

static const NMPlatformIP6Route *
ip6_route_get (NMPlatform *platform, int ifindex, struct in6_addr network, int plen, guint32 metric)
{
	NMPObject obj_needle;
	const NMPObject *obj;

	metric = nm_utils_ip6_route_metric_normalize (metric);

	nmp_object_stackinit_id_ip6_route (&obj_needle, ifindex, &network, plen, metric);
	obj = nmp_cache_lookup_obj (NM_LINUX_PLATFORM_GET_PRIVATE (platform)->cache, &obj_needle);
	if (nmp_object_is_visible (obj))
		return &obj->ip6_route;
	return NULL;
}

/******************************************************************/

#define EVENT_CONDITIONS      ((GIOCondition) (G_IO_IN | G_IO_PRI))
#define ERROR_CONDITIONS      ((GIOCondition) (G_IO_ERR | G_IO_NVAL))
#define DISCONNECT_CONDITIONS ((GIOCondition) (G_IO_HUP))

static int
verify_source (struct nl_msg *msg, NMPlatform *platform)
{
	struct ucred *creds = nlmsg_get_creds (msg);

	if (!creds || creds->pid) {
		if (creds)
			_LOGW ("netlink: received non-kernel message (pid %d)", creds->pid);
		else
			_LOGW ("netlink: received message without credentials");
		return NL_STOP;
	}

	return NL_OK;
}

static gboolean
event_handler (GIOChannel *channel,
               GIOCondition io_condition,
               gpointer user_data)
{
	delayed_action_handle_all (NM_PLATFORM (user_data), TRUE);
	return TRUE;
}

static gboolean
event_handler_read_netlink_one (NMPlatform *platform)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int nle;

	nle = nl_recvmsgs_default (priv->nlh_event);

	/* Work around a libnl bug fixed in 3.2.22 (375a6294) */
	if (nle == 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		nle = -NLE_AGAIN;

	if (nle < 0)
		switch (nle) {
		case -NLE_AGAIN:
			return FALSE;
		case -NLE_DUMP_INTR:
			_LOGD ("Uncritical failure to retrieve incoming events: %s (%d)", nl_geterror (nle), nle);
			break;
		case -NLE_NOMEM:
			_LOGI ("Too many netlink events. Need to resynchronize platform cache");
			/* Drain the event queue, we've lost events and are out of sync anyway and we'd
			 * like to free up some space. We'll read in the status synchronously. */
			_nl_sock_flush_data (priv->nlh_event);
			priv->nlh_seq_expect = 0;
			delayed_action_schedule (platform,
			                         DELAYED_ACTION_TYPE_REFRESH_ALL_LINKS |
			                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ADDRESSES |
			                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ADDRESSES |
			                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP4_ROUTES |
			                         DELAYED_ACTION_TYPE_REFRESH_ALL_IP6_ROUTES,
			                         NULL);
			break;
		default:
			_LOGE ("Failed to retrieve incoming events: %s (%d)", nl_geterror (nle), nle);
			break;
	}
	return TRUE;
}

static gboolean
event_handler_read_netlink_all (NMPlatform *platform, gboolean wait_for_acks)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int r;
	struct pollfd pfd;
	gboolean any = FALSE;
	gint64 timestamp = 0, now;
	const int TIMEOUT = 250;
	int timeout = 0;
	guint32 wait_for_seq = 0;

	while (TRUE) {
		while (event_handler_read_netlink_one (platform))
			any = TRUE;

		if (!wait_for_acks || priv->nlh_seq_expect == 0) {
			if (wait_for_seq)
				_LOGT ("read-netlink-all: ACK for sequence number %u received", priv->nlh_seq_expect);
			return any;
		}

		now = nm_utils_get_monotonic_timestamp_ms ();
		if (wait_for_seq != priv->nlh_seq_expect) {
			/* We are waiting for a new sequence number (or we will wait for the first time).
			 * Reset/start counting the overall wait time. */
			_LOGT ("read-netlink-all: wait for ACK for sequence number %u...", priv->nlh_seq_expect);
			wait_for_seq = priv->nlh_seq_expect;
			timestamp = now;
			timeout = TIMEOUT;
		} else {
			if ((now - timestamp) >= TIMEOUT) {
				/* timeout. Don't wait for this sequence number anymore. */
				break;
			}

			/* readjust the wait-time. */
			timeout = TIMEOUT - (now - timestamp);
		}

		memset (&pfd, 0, sizeof (pfd));
		pfd.fd = nl_socket_get_fd (priv->nlh_event);
		pfd.events = POLLIN;
		r = poll (&pfd, 1, timeout);

		if (r == 0) {
			/* timeout. */
			break;
		}
		if (r < 0) {
			int errsv = errno;

			if (errsv != EINTR) {
				_LOGE ("read-netlink-all: poll failed with %s", strerror (errsv));
				return any;
			}
			/* Continue to read again, even if there might be nothing to read after EINTR. */
		}
	}

	_LOGW ("read-netlink-all: timeout waiting for ACK to sequence number %u...", wait_for_seq);
	priv->nlh_seq_expect = 0;
	return any;
}

static struct nl_sock *
setup_socket (NMPlatform *platform, gboolean event)
{
	struct nl_sock *sock;
	int nle;

	sock = nl_socket_alloc ();
	g_return_val_if_fail (sock, NULL);

	/* Only ever accept messages from kernel */
	nle = nl_socket_modify_cb (sock, NL_CB_MSG_IN, NL_CB_CUSTOM, (nl_recvmsg_msg_cb_t) verify_source, platform);
	g_assert (!nle);

	/* Dispatch event messages (event socket only) */
	if (event) {
		nl_socket_modify_cb (sock, NL_CB_VALID, NL_CB_CUSTOM, event_notification, platform);
		nl_socket_modify_cb (sock, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, event_seq_check, platform);
		nl_socket_modify_err_cb (sock, NL_CB_CUSTOM, event_err, platform);
	}

	nle = nl_connect (sock, NETLINK_ROUTE);
	g_assert (!nle);
	nle = nl_socket_set_passcred (sock, 1);
	g_assert (!nle);

	/* No blocking for event socket, so that we can drain it safely. */
	if (event) {
		nle = nl_socket_set_nonblocking (sock);
		g_assert (!nle);
	}

	return sock;
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
	do_emit_signal (platform, obj_cache, cache_op, was_visible, NM_PLATFORM_REASON_INTERNAL);
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

	if (g_udev_device_get_property (udev_device, "IFINDEX"))
		ifindex = g_udev_device_get_property_as_int (udev_device, "IFINDEX");
	else {
		_LOGW ("(%s): udev-add: failed to get device's ifindex", ifname);
		return;
	}
	if (ifindex <= 0) {
		_LOGW ("(%s): udev-add: retrieved invalid IFINDEX=%d", ifname, ifindex);
		return;
	}

	if (!g_udev_device_get_sysfs_path (udev_device)) {
		_LOGD ("(%s): udev-add: couldn't determine device path; ignoring...", ifname);
		return;
	}

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
	NMPlatform *platform = NM_PLATFORM (user_data);
	const char *subsys;
	const char *ifindex;
	guint64 seqnum;

	g_return_if_fail (action != NULL);

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

	self->priv = priv;

	priv->delayed_deletion = g_hash_table_new_full ((GHashFunc) nmp_object_id_hash,
	                                                (GEqualFunc) nmp_object_id_equal,
	                                                (GDestroyNotify) nmp_object_unref,
	                                                (GDestroyNotify) nmp_object_unref);
	priv->cache = nmp_cache_new ();
	priv->delayed_action.list_master_connected = g_ptr_array_new ();
	priv->delayed_action.list_refresh_link = g_ptr_array_new ();
	priv->wifi_data = g_hash_table_new_full (NULL, NULL, NULL, (GDestroyNotify) wifi_utils_deinit);
}

static void
constructed (GObject *_object)
{
	NMPlatform *platform = NM_PLATFORM (_object);
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	const char *udev_subsys[] = { "net", NULL };
	int channel_flags;
	gboolean status;
	int nle;
	GUdevEnumerator *enumerator;
	GList *devices, *iter;

	_LOGD ("create");

	/* Initialize netlink socket for requests */
	priv->nlh = setup_socket (platform, FALSE);
	g_assert (priv->nlh);
	_LOGD ("Netlink socket for requests established: port=%u, fd=%d", nl_socket_get_local_port (priv->nlh), nl_socket_get_fd (priv->nlh));

	/* Initialize netlink socket for events */
	priv->nlh_event = setup_socket (platform, TRUE);
	g_assert (priv->nlh_event);
	/* The default buffer size wasn't enough for the testsuites. It might just
	 * as well happen with NetworkManager itself. For now let's hope 128KB is
	 * good enough.
	 */
	nle = nl_socket_set_buffer_size (priv->nlh_event, 131072, 0);
	g_assert (!nle);
	nle = nl_socket_add_memberships (priv->nlh_event,
	                                 RTNLGRP_LINK,
	                                 RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR,
	                                 RTNLGRP_IPV4_ROUTE,  RTNLGRP_IPV6_ROUTE,
	                                 0);
	g_assert (!nle);
	_LOGD ("Netlink socket for events established: port=%u, fd=%d", nl_socket_get_local_port (priv->nlh_event), nl_socket_get_fd (priv->nlh_event));

	priv->event_channel = g_io_channel_unix_new (nl_socket_get_fd (priv->nlh_event));
	g_io_channel_set_encoding (priv->event_channel, NULL, NULL);
	g_io_channel_set_close_on_unref (priv->event_channel, TRUE);

	channel_flags = g_io_channel_get_flags (priv->event_channel);
	status = g_io_channel_set_flags (priv->event_channel,
		channel_flags | G_IO_FLAG_NONBLOCK, NULL);
	g_assert (status);
	priv->event_id = g_io_add_watch (priv->event_channel,
	                                (EVENT_CONDITIONS | ERROR_CONDITIONS | DISCONNECT_CONDITIONS),
	                                 event_handler, platform);

	/* Set up udev monitoring */
	priv->udev_client = g_udev_client_new (udev_subsys);
	g_signal_connect (priv->udev_client, "uevent", G_CALLBACK (handle_udev_event), platform);

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

static void
dispose (GObject *object)
{
	NMPlatform *platform = NM_PLATFORM (object);
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	_LOGD ("dispose");

	priv->delayed_action.flags = DELAYED_ACTION_TYPE_NONE;
	g_ptr_array_set_size (priv->delayed_action.list_master_connected, 0);
	g_ptr_array_set_size (priv->delayed_action.list_refresh_link, 0);

	nm_clear_g_source (&priv->delayed_action.idle_id);

	g_clear_pointer (&priv->prune_candidates, g_hash_table_unref);
	g_clear_pointer (&priv->delayed_deletion, g_hash_table_unref);

	G_OBJECT_CLASS (nm_linux_platform_parent_class)->dispose (object);
}

static void
nm_linux_platform_finalize (GObject *object)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (object);

	nmp_cache_free (priv->cache);

	g_ptr_array_unref (priv->delayed_action.list_master_connected);
	g_ptr_array_unref (priv->delayed_action.list_refresh_link);

	/* Free netlink resources */
	g_source_remove (priv->event_id);
	g_io_channel_unref (priv->event_channel);
	nl_socket_free (priv->nlh);
	nl_socket_free (priv->nlh_event);

	g_object_unref (priv->udev_client);
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

	platform_class->link_refresh = link_refresh;

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
	platform_class->master_set_option = master_set_option;
	platform_class->master_get_option = master_get_option;
	platform_class->slave_set_option = slave_set_option;
	platform_class->slave_get_option = slave_get_option;

	platform_class->vlan_add = vlan_add;
	platform_class->vlan_get_info = vlan_get_info;
	platform_class->vlan_set_ingress_map = vlan_set_ingress_map;
	platform_class->vlan_set_egress_map = vlan_set_egress_map;

	platform_class->infiniband_partition_add = infiniband_partition_add;
	platform_class->infiniband_get_info = infiniband_get_info;

	platform_class->veth_get_properties = veth_get_properties;
	platform_class->tun_get_properties = tun_get_properties;
	platform_class->macvlan_get_properties = macvlan_get_properties;
	platform_class->vxlan_get_properties = vxlan_get_properties;
	platform_class->gre_get_properties = gre_get_properties;

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

