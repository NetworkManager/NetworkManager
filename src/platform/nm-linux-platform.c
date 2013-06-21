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
 * Copyright (C) 2012-2013 Red Hat, Inc.
 */
#include <config.h>

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/if_tunnel.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <netlink/netlink.h>
#include <netlink/object.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <netlink/route/link/vlan.h>
#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <gudev/gudev.h>

#include "nm-linux-platform.h"
#include "nm-logging.h"

/* This is only included for the translation of VLAN flags */
#include "nm-setting-vlan.h"

#define debug(...) nm_log_dbg (LOGD_PLATFORM, __VA_ARGS__)
#define warning(...) nm_log_warn (LOGD_PLATFORM, __VA_ARGS__)
#define error(...) nm_log_err (LOGD_PLATFORM, __VA_ARGS__)

typedef struct {
	struct nl_sock *nlh;
	struct nl_sock *nlh_event;
	struct nl_cache *link_cache;
	struct nl_cache *address_cache;
	struct nl_cache *route_cache;
	GIOChannel *event_channel;
	guint event_id;

	GUdevClient *udev_client;
	GHashTable *udev_devices;
} NMLinuxPlatformPrivate;

#define NM_LINUX_PLATFORM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_LINUX_PLATFORM, NMLinuxPlatformPrivate))

G_DEFINE_TYPE (NMLinuxPlatform, nm_linux_platform, NM_TYPE_PLATFORM)

void
nm_linux_platform_setup (void)
{
	nm_platform_setup (NM_TYPE_LINUX_PLATFORM);
}

/******************************************************************/

/* libnl library workarounds and additions */

/* Automatic deallocation of local variables */
#define auto_nl_object __attribute__((cleanup(put_nl_object)))
static void
put_nl_object (void *ptr)
{
	struct nl_object **object = ptr;

	if (object && *object) {
		nl_object_put (*object);
		*object = NULL;
	}
}

#define auto_nl_addr __attribute__((cleanup(put_nl_addr)))
static void
put_nl_addr (void *ptr)
{
	struct nl_addr **object = ptr;

	if (object && *object) {
		nl_addr_put (*object);
		*object = NULL;
	}
}

/* libnl doesn't use const where due */
#define nl_addr_build(family, addr, addrlen) nl_addr_build (family, (gpointer) addr, addrlen)

/* rtnl_addr_set_prefixlen fails to update the nl_addr prefixlen */
static void
nm_rtnl_addr_set_prefixlen (struct rtnl_addr *rtnladdr, int plen)
{
	struct nl_addr *nladdr;

	rtnl_addr_set_prefixlen (rtnladdr, plen);

	nladdr = rtnl_addr_get_local (rtnladdr);
	if (nladdr)
		nl_addr_set_prefixlen (nladdr, plen);
}
#define rtnl_addr_set_prefixlen nm_rtnl_addr_set_prefixlen

typedef enum {
	LINK,
	IP4_ADDRESS,
	IP6_ADDRESS,
	IP4_ROUTE,
	IP6_ROUTE,
	N_TYPES
} ObjectType;

typedef enum {
	ADDED,
	CHANGED,
	REMOVED,
	N_STATUSES
} ObjectStatus;

static ObjectType
object_type_from_nl_object (const struct nl_object *object)
{
	g_assert (object);

	if (!strcmp (nl_object_get_type (object), "route/link"))
		return LINK;
	else if (!strcmp (nl_object_get_type (object), "route/addr")) {
		switch (rtnl_addr_get_family ((struct rtnl_addr *) object)) {
		case AF_INET:
			return IP4_ADDRESS;
		case AF_INET6:
			return IP6_ADDRESS;
		default:
			g_assert_not_reached ();
		}
	} else if (!strcmp (nl_object_get_type (object), "route/route")) {
		switch (rtnl_route_get_family ((struct rtnl_route *) object)) {
		case AF_INET:
			return IP4_ROUTE;
		case AF_INET6:
			return IP6_ROUTE;
		default:
			g_assert_not_reached ();
		}
	} else
		g_assert_not_reached ();
}

/* libnl inclues LINK_ATTR_FAMILY in oo_id_attrs of link_obj_ops and thus
 * refuses to search for items that lack this attribute. I believe this is a
 * bug or a bad design at the least. Address family is not an identifying
 * attribute of a network interface and IMO is not an attribute of a network
 * interface at all.
 */
static struct nl_object *
nm_nl_cache_search (struct nl_cache *cache, struct nl_object *needle)
{
	if (object_type_from_nl_object (needle) == LINK)
		rtnl_link_set_family ((struct rtnl_link *) needle, AF_UNSPEC);

	return nl_cache_search (cache, needle);
}
#define nl_cache_search nm_nl_cache_search

/* Ask the kernel for an object identical (as in nl_cache_identical) to the
 * needle argument. This is a kernel counterpart for nl_cache_search.
 *
 * libnl 3.2 doesn't seem to provide such functionality.
 */
static struct nl_object *
get_kernel_object (struct nl_sock *sock, struct nl_object *needle)
{

	switch (object_type_from_nl_object (needle)) {
	case LINK:
		{
			struct nl_object *kernel_object;
			int ifindex = rtnl_link_get_ifindex ((struct rtnl_link *) needle);
			const char *name = rtnl_link_get_name ((struct rtnl_link *) needle);
			int nle;

			nle = rtnl_link_get_kernel (sock, ifindex, name, (struct rtnl_link **) &kernel_object);
			switch (nle) {
			case -NLE_SUCCESS:
				return kernel_object;
			case -NLE_NODEV:
				return NULL;
			default:
				error ("Netlink error: %s", nl_geterror (nle));
				return NULL;
			}
		}
	default:
		/* Fallback to a one-time cache allocation. */
		{
			struct nl_cache *cache;
			struct nl_object *object;
			int nle;

			nle = nl_cache_alloc_and_fill (
					nl_cache_ops_lookup (nl_object_get_type (needle)),
					sock, &cache);
			g_return_val_if_fail (!nle, NULL);
			object = nl_cache_search (cache, needle);

			nl_cache_free (cache);
			return object;
		}
	}
}

/* libnl 3.2 doesn't seem to provide such a generic way to add libnl-route objects. */
static int
add_kernel_object (struct nl_sock *sock, struct nl_object *object)
{
	switch (object_type_from_nl_object (object)) {
	case LINK:
		return rtnl_link_add (sock, (struct rtnl_link *) object, NLM_F_CREATE);
	case IP4_ADDRESS:
	case IP6_ADDRESS:
		return rtnl_addr_add (sock, (struct rtnl_addr *) object, NLM_F_CREATE);
	case IP4_ROUTE:
	case IP6_ROUTE:
		return rtnl_route_add (sock, (struct rtnl_route *) object, NLM_F_CREATE);
	default:
		g_assert_not_reached ();
	}
}

/* libnl 3.2 doesn't seem to provide such a generic way to delete libnl-route objects. */
static int
delete_kernel_object (struct nl_sock *sock, struct nl_object *object)
{
	switch (object_type_from_nl_object (object)) {
	case LINK:
		return rtnl_link_delete (sock, (struct rtnl_link *) object);
	case IP4_ADDRESS:
	case IP6_ADDRESS:
		return rtnl_addr_delete (sock, (struct rtnl_addr *) object, 0);
	case IP4_ROUTE:
	case IP6_ROUTE:
		return rtnl_route_delete (sock, (struct rtnl_route *) object, 0);
	default:
		g_assert_not_reached ();
	}
}

/* nm_rtnl_link_parse_info_data(): Re-fetches a link from the kernel
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
	[IFLA_LINKINFO]	= { .type = NLA_NESTED },
};

static struct nla_policy info_data_link_info_policy[IFLA_INFO_MAX + 1] = {
	[IFLA_INFO_DATA]	= { .type = NLA_NESTED },
};

static int
info_data_parser (struct nl_msg *msg, void *arg)
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
nm_rtnl_link_parse_info_data (struct nl_sock *sk, int ifindex,
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
	nl_cb_set (cb, NL_CB_VALID, NL_CB_CUSTOM, info_data_parser, &data);

	err = nl_recvmsgs (sk, cb);
	nl_cb_put (cb);
	if (err < 0)
		return err;

	nl_wait_for_ack (sk);
	return 0;
}

/******************************************************************/

/* Object type specific utilities */

static const char *
type_to_string (NMLinkType type)
{
	/* Note that this only has to support virtual types */
	switch (type) {
	case NM_LINK_TYPE_DUMMY:
		return "dummy";
	case NM_LINK_TYPE_GRE:
		return "gre";
	case NM_LINK_TYPE_GRETAP:
		return "gretap";
	case NM_LINK_TYPE_IFB:
		return "ifb";
	case NM_LINK_TYPE_MACVLAN:
		return "macvlan";
	case NM_LINK_TYPE_MACVTAP:
		return "macvtap";
	case NM_LINK_TYPE_TAP:
		return "tap";
	case NM_LINK_TYPE_TUN:
		return "tun";
	case NM_LINK_TYPE_VETH:
		return "veth";
	case NM_LINK_TYPE_VLAN:
		return "vlan";
	case NM_LINK_TYPE_BRIDGE:
		return "bridge";
	case NM_LINK_TYPE_BOND:
		return "bond";
	case NM_LINK_TYPE_TEAM:
		return "team";
	default:
		g_warning ("Wrong type: %d", type);
		return NULL;
	}
}

#define return_type(t, name) \
	G_STMT_START { \
		if (out_name) \
			*out_name = name; \
		return t; \
	} G_STMT_END

static NMLinkType
link_type_from_udev (NMPlatform *platform, struct rtnl_link *rtnllink, const char **out_name)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int ifindex = rtnl_link_get_ifindex (rtnllink);
	GUdevDevice *udev_device;
	const char *prop;

	g_assert_cmpint (rtnl_link_get_arptype (rtnllink), ==, ARPHRD_ETHER);

	udev_device = g_hash_table_lookup (priv->udev_devices, GINT_TO_POINTER (ifindex));
	if (!udev_device)
		return_type (NM_LINK_TYPE_UNKNOWN, "unknown");

	prop = g_udev_device_get_property (udev_device, "ID_NM_OLPC_MESH");
	if (prop)
		return_type (NM_LINK_TYPE_OLPC_MESH, "olpc-mesh");

	prop = g_udev_device_get_property (udev_device, "DEVTYPE");
	if (g_strcmp0 (prop, "wlan") == 0)
		return_type (NM_LINK_TYPE_WIFI, "wifi");

	/* Anything else is assumed to be ethernet */
	return_type (NM_LINK_TYPE_ETHERNET, "ethernet");
}

static NMLinkType
link_extract_type (NMPlatform *platform, struct rtnl_link *rtnllink, const char **out_name)
{
	const char *type;

	if (!rtnllink)
		return_type (NM_LINK_TYPE_NONE, NULL);

	type = rtnl_link_get_type (rtnllink);

	if (!type) {
		int arptype = rtnl_link_get_arptype (rtnllink);

		if (arptype == ARPHRD_LOOPBACK)
			return_type (NM_LINK_TYPE_LOOPBACK, "loopback");
		else if (arptype == ARPHRD_INFINIBAND)
			return_type (NM_LINK_TYPE_INFINIBAND, "infiniband");
		else if (arptype == 256) {
			/* Some s390 CTC-type devices report 256 for the encapsulation type
			 * for some reason, but we need to call them Ethernet. FIXME: use
			 * something other than interface name to detect CTC here.
			 */
			if (g_str_has_prefix (rtnl_link_get_name (rtnllink), "ctc"))
				return_type (NM_LINK_TYPE_ETHERNET, "ethernet");
		} else if (arptype == ARPHRD_ETHER)
			return link_type_from_udev (platform, rtnllink, out_name);
		else
			return_type (NM_LINK_TYPE_UNKNOWN, "unknown");
	} else if (!strcmp (type, "dummy"))
		return_type (NM_LINK_TYPE_DUMMY, "dummy");
	else if (!strcmp (type, "gre"))
		return_type (NM_LINK_TYPE_GRE, "gre");
	else if (!strcmp (type, "gretap"))
		return_type (NM_LINK_TYPE_GRETAP, "gretap");
	else if (!strcmp (type, "ifb"))
		return_type (NM_LINK_TYPE_IFB, "ifb");
	else if (!strcmp (type, "macvlan"))
		return_type (NM_LINK_TYPE_MACVLAN, "macvlan");
	else if (!strcmp (type, "macvtap"))
		return_type (NM_LINK_TYPE_MACVTAP, "macvtap");
	else if (!strcmp (type, "tun")) {
		NMPlatformTunProperties props;

		if (   nm_platform_tun_get_properties (rtnl_link_get_ifindex (rtnllink), &props)
		       && !strcmp (props.mode, "tap"))
			return_type (NM_LINK_TYPE_TAP, "tap");
		else
			return_type (NM_LINK_TYPE_TUN, "tun");
	} else if (!strcmp (type, "veth"))
		return_type (NM_LINK_TYPE_VETH, "veth");
	else if (!strcmp (type, "vlan"))
		return_type (NM_LINK_TYPE_VLAN, "vlan");
	else if (!strcmp (type, "bridge"))
		return_type (NM_LINK_TYPE_BRIDGE, "bridge");
	else if (!strcmp (type, "bond"))
		return_type (NM_LINK_TYPE_BOND, "bond");
	else if (!strcmp (type, "team"))
		return_type (NM_LINK_TYPE_TEAM, "team");

	return_type (NM_LINK_TYPE_UNKNOWN, type);
}

static const char *
udev_get_driver (NMPlatform *platform, GUdevDevice *device, int ifindex)
{
	GUdevDevice *parent = NULL, *grandparent = NULL;
	const char *driver, *subsys;

	driver = g_udev_device_get_driver (device);
	if (driver)
		return driver;

	/* Try the parent */
	parent = g_udev_device_get_parent (device);
	if (parent) {
		driver = g_udev_device_get_driver (parent);
		if (!driver) {
			/* Try the grandparent if it's an ibmebus device or if the
			 * subsys is NULL which usually indicates some sort of
			 * platform device like a 'gadget' net interface.
			 */
			subsys = g_udev_device_get_subsystem (parent);
			if (   (g_strcmp0 (subsys, "ibmebus") == 0)
			    || (subsys == NULL)) {
				grandparent = g_udev_device_get_parent (parent);
				if (grandparent) {
					driver = g_udev_device_get_driver (grandparent);
				}
			}
		}
	}

	/* Intern the string so we don't have to worry about memory
	 * management in NMPlatformLink.
	 */
	if (driver)
		driver = g_intern_string (driver);

	g_clear_object (&parent);
	g_clear_object (&grandparent);

	return driver;
}

static void
link_init (NMPlatform *platform, NMPlatformLink *info, struct rtnl_link *rtnllink)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GUdevDevice *udev_device;

	memset (info, 0, sizeof (*info));

	g_assert (rtnllink);

	info->ifindex = rtnl_link_get_ifindex (rtnllink);
	strcpy (info->name, rtnl_link_get_name (rtnllink));
	info->type = link_extract_type (platform, rtnllink, &info->type_name);
	info->up = !!(rtnl_link_get_flags (rtnllink) & IFF_UP);
	info->connected = !!(rtnl_link_get_flags (rtnllink) & IFF_LOWER_UP);
	info->arp = !(rtnl_link_get_flags (rtnllink) & IFF_NOARP);
	info->master = rtnl_link_get_master (rtnllink);
	info->parent = rtnl_link_get_link (rtnllink);
	info->mtu = rtnl_link_get_mtu (rtnllink);

	udev_device = g_hash_table_lookup (priv->udev_devices, GINT_TO_POINTER (info->ifindex));
	if (udev_device) {
		info->driver = udev_get_driver (platform, udev_device, info->ifindex);
		if (!info->driver)
			info->driver = rtnl_link_get_type (rtnllink);
		if (!info->driver)
			info->driver = "unknown";
		info->udi = g_udev_device_get_sysfs_path (udev_device);
	}
}

/* Hack: Empty bridges and bonds have IFF_LOWER_UP flag and therefore they break
 * the carrier detection. This hack makes nm-platform think they don't have the
 * IFF_LOWER_UP flag. This seems to also apply to bonds (specifically) with all
 * slaves down.
 *
 * Note: This is still a bit racy but when NetworkManager asks for enslaving a slave,
 * nm-platform will do that synchronously and will immediately ask for both master
 * and slave information after the enslaving request. After the synchronous call, the
 * master carrier is already updated with the slave carrier in mind.
 *
 * https://bugzilla.redhat.com/show_bug.cgi?id=910348
 */
static void
hack_empty_master_iff_lower_up (NMPlatform *platform, struct nl_object *object)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	struct rtnl_link *rtnllink;
	int ifindex;
	struct nl_object *slave;

	if (!object)
		return;
	if (strcmp (nl_object_get_type (object), "route/link"))
		return;

	rtnllink = (struct rtnl_link *) object;

	ifindex = rtnl_link_get_ifindex (rtnllink);

	switch (link_extract_type (platform, rtnllink, NULL)) {
	case NM_LINK_TYPE_BRIDGE:
	case NM_LINK_TYPE_BOND:
		for (slave = nl_cache_get_first (priv->link_cache); slave; slave = nl_cache_get_next (slave)) {
			struct rtnl_link *rtnlslave = (struct rtnl_link *) slave;
			if (rtnl_link_get_master (rtnlslave) == ifindex
					&& rtnl_link_get_flags (rtnlslave) & IFF_LOWER_UP)
				return;
		}
		break;
	default:
		return;
	}

	rtnl_link_unset_flags (rtnllink, IFF_LOWER_UP);
}

static void
init_ip4_address (NMPlatformIP4Address *address, struct rtnl_addr *rtnladdr)
{
	struct nl_addr *nladdr = rtnl_addr_get_local (rtnladdr);

	g_assert (nladdr);

	memset (address, 0, sizeof (*address));

	address->ifindex = rtnl_addr_get_ifindex (rtnladdr);
	address->plen = rtnl_addr_get_prefixlen (rtnladdr);
	g_assert (nl_addr_get_len (nladdr) == sizeof (address->address));
	memcpy (&address->address, nl_addr_get_binary_addr (nladdr), sizeof (address->address));
}

static void
init_ip6_address (NMPlatformIP6Address *address, struct rtnl_addr *rtnladdr)
{
	struct nl_addr *nladdr = rtnl_addr_get_local (rtnladdr);

	memset (address, 0, sizeof (*address));

	address->ifindex = rtnl_addr_get_ifindex (rtnladdr);
	address->plen = rtnl_addr_get_prefixlen (rtnladdr);
	g_assert (nl_addr_get_len (nladdr) == sizeof (address->address));
	memcpy (&address->address, nl_addr_get_binary_addr (nladdr), sizeof (address->address));
}

static void
init_ip4_route (NMPlatformIP4Route *route, struct rtnl_route *rtnlroute)
{
	struct nl_addr *dst, *gw;
	struct rtnl_nexthop *nexthop;

	g_assert (rtnl_route_get_nnexthops (rtnlroute) == 1);
	nexthop = rtnl_route_nexthop_n (rtnlroute, 0);
	dst = rtnl_route_get_dst (rtnlroute);
	gw = rtnl_route_nh_get_gateway (nexthop);

	memset (route, 0, sizeof (*route));
	route->ifindex = rtnl_route_nh_get_ifindex (nexthop);
	route->plen = nl_addr_get_prefixlen (dst);
	/* Workaround on previous workaround for libnl default route prefixlen bug. */
	if (nl_addr_get_len (dst)) {
		g_assert (nl_addr_get_len (dst) == sizeof (route->network));
		memcpy (&route->network, nl_addr_get_binary_addr (dst), sizeof (route->network));
	}
	if (gw) {
		g_assert (nl_addr_get_len (gw) == sizeof (route->network));
		memcpy (&route->gateway, nl_addr_get_binary_addr (gw), sizeof (route->gateway));
	}
	route->metric = rtnl_route_get_priority (rtnlroute);
	rtnl_route_get_metric (rtnlroute, RTAX_ADVMSS, &route->mss);
}

static void
init_ip6_route (NMPlatformIP6Route *route, struct rtnl_route *rtnlroute)
{
	struct nl_addr *dst, *gw;
	struct rtnl_nexthop *nexthop;

	g_assert (rtnl_route_get_nnexthops (rtnlroute) == 1);
	nexthop = rtnl_route_nexthop_n (rtnlroute, 0);
	dst = rtnl_route_get_dst (rtnlroute);
	gw = rtnl_route_nh_get_gateway (nexthop);

	memset (route, 0, sizeof (*route));
	route->ifindex = rtnl_route_nh_get_ifindex (nexthop);
	route->plen = nl_addr_get_prefixlen (dst);
	/* Workaround on previous workaround for libnl default route prefixlen bug. */
	if (nl_addr_get_len (dst)) {
		g_assert (nl_addr_get_len (dst) == sizeof (route->network));
		memcpy (&route->network, nl_addr_get_binary_addr (dst), sizeof (route->network));
	}
	if (gw) {
		g_assert (nl_addr_get_len (gw) == sizeof (route->network));
		memcpy (&route->gateway, nl_addr_get_binary_addr (gw), sizeof (route->gateway));
	}
	route->metric = rtnl_route_get_priority (rtnlroute);
	rtnl_route_get_metric (rtnlroute, RTAX_ADVMSS, &route->mss);
}

/******************************************************************/

/* Object and cache manipulation */

static const char *signal_by_type_and_status[N_TYPES][N_STATUSES] = {
	{ NM_PLATFORM_LINK_ADDED, NM_PLATFORM_LINK_CHANGED, NM_PLATFORM_LINK_REMOVED },
	{ NM_PLATFORM_IP4_ADDRESS_ADDED, NM_PLATFORM_IP4_ADDRESS_CHANGED, NM_PLATFORM_IP4_ADDRESS_REMOVED },
	{ NM_PLATFORM_IP6_ADDRESS_ADDED, NM_PLATFORM_IP6_ADDRESS_CHANGED, NM_PLATFORM_IP6_ADDRESS_REMOVED },
	{ NM_PLATFORM_IP4_ROUTE_ADDED, NM_PLATFORM_IP4_ROUTE_CHANGED, NM_PLATFORM_IP4_ROUTE_REMOVED },
	{ NM_PLATFORM_IP6_ROUTE_ADDED, NM_PLATFORM_IP6_ROUTE_CHANGED, NM_PLATFORM_IP6_ROUTE_REMOVED }
};

static struct nl_cache *
choose_cache (NMPlatform *platform, struct nl_object *object)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	switch (object_type_from_nl_object (object)) {
	case LINK:
		return priv->link_cache;
	case IP4_ADDRESS:
	case IP6_ADDRESS:
		return priv->address_cache;
	case IP4_ROUTE:
	case IP6_ROUTE:
		return priv->route_cache;
	default:
		g_assert_not_reached ();
	}
}

static void
announce_object (NMPlatform *platform, const struct nl_object *object, ObjectStatus status)
{
	ObjectType object_type = object_type_from_nl_object (object);
	const char *sig = signal_by_type_and_status[object_type][status];

	if (object_type == LINK && status == ADDED) {
		/* We have to wait until udev has registered the device; we'll
		 * emit NM_PLATFORM_LINK_ADDED from udev_device_added().
		 */
		return;
	}

	switch (object_type) {
	case LINK:
		{
			NMPlatformLink device;

			link_init (platform, &device, (struct rtnl_link *) object);
			g_signal_emit_by_name (platform, sig, device.ifindex, &device);
		}
		return;
	case IP4_ADDRESS:
		{
			NMPlatformIP4Address address;

			init_ip4_address (&address, (struct rtnl_addr *) object);
			g_signal_emit_by_name (platform, sig, address.ifindex, &address);
		}
		return;
	case IP6_ADDRESS:
		{
			NMPlatformIP6Address address;

			init_ip6_address (&address, (struct rtnl_addr *) object);
			g_signal_emit_by_name (platform, sig, address.ifindex, &address);
		}
		return;
	case IP4_ROUTE:
		{
			NMPlatformIP4Route route;

			init_ip4_route (&route, (struct rtnl_route *) object);
			g_signal_emit_by_name (platform, sig, route.ifindex, &route);
		}
		return;
	case IP6_ROUTE:
		{
			NMPlatformIP6Route route;

			init_ip6_route (&route, (struct rtnl_route *) object);
			g_signal_emit_by_name (platform, sig, route.ifindex, &route);
		}
		return;
	default:
		error ("Announcing object: object type unknown: %d", object_type);
	}
}

static struct nl_object * build_rtnl_link (int ifindex, const char *name, NMLinkType type);

static gboolean
refresh_object (NMPlatform *platform, struct nl_object *object, int nle)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	auto_nl_object struct nl_object *cached_object = NULL;
	auto_nl_object struct nl_object *kernel_object = NULL;
	struct nl_cache *cache;

	/* NLE_EXIST is considered equivalent to success to avoid race conditions. You
	 * never know when something sends an identical object just before
	 * NetworkManager.
	 */
	switch (nle) {
	case -NLE_SUCCESS:
	case -NLE_EXIST:
		break;
	default:
		error ("Netlink error: %s", nl_geterror (nle));
		return FALSE;
	}

	cache = choose_cache (platform, object);
	cached_object = nl_cache_search (choose_cache (platform, object), object);
	kernel_object = get_kernel_object (priv->nlh, object);

	g_return_val_if_fail (kernel_object, FALSE);

	hack_empty_master_iff_lower_up (platform, kernel_object);

	if (cached_object) {
		nl_cache_remove (cached_object);
		nle = nl_cache_add (cache, kernel_object);
		g_return_val_if_fail (!nle, 0);
	} else {
		nle = nl_cache_add (cache, kernel_object);
		g_return_val_if_fail (!nle, FALSE);
	}

	announce_object (platform, kernel_object, cached_object ? CHANGED : ADDED);

	/* Refresh the master device (even on enslave/release) */
	if (object_type_from_nl_object (kernel_object) == LINK) {
		int kernel_master = rtnl_link_get_master ((struct rtnl_link *) kernel_object);
		int cached_master = cached_object ? rtnl_link_get_master ((struct rtnl_link *) cached_object) : 0;
		struct nl_object *master_object;

		if (kernel_master) {
			master_object = build_rtnl_link (kernel_master, NULL, NM_LINK_TYPE_NONE);
			refresh_object (platform, master_object, 0);
			nl_object_put (master_object);
		}
		if (cached_master && cached_master != kernel_master) {
			master_object = build_rtnl_link (cached_master, NULL, NM_LINK_TYPE_NONE);
			refresh_object (platform, master_object, 0);
			nl_object_put (master_object);
		}
	}

	return TRUE;
}

/* Decreases the reference count if @obj for convenience */
static gboolean
add_object (NMPlatform *platform, struct nl_object *obj)
{
	auto_nl_object struct nl_object *object = obj;
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	return refresh_object (platform, object, add_kernel_object (priv->nlh, object));
}

static void
remove_if_ifindex (struct nl_object *object, gpointer user_data)
{
	int ifindex = *(int *) user_data;

	switch (object_type_from_nl_object (object)) {
	case IP4_ADDRESS:
	case IP6_ADDRESS:
		if (ifindex != rtnl_addr_get_ifindex ((struct rtnl_addr *) object))
			break;
		nl_cache_remove (object);
		break;
	case IP4_ROUTE:
	case IP6_ROUTE:
		{
			struct rtnl_route *rtnlroute = (struct rtnl_route *) object;
			struct rtnl_nexthop *nexthop;

			if (rtnl_route_get_nnexthops (rtnlroute) != 1)
				break;
			nexthop = rtnl_route_nexthop_n (rtnlroute, 0);
			if (ifindex != rtnl_route_nh_get_ifindex (nexthop))
				break;
			nl_cache_remove (object);
		}
		break;
	default:
		break;
	}
}

/* Decreases the reference count if @obj for convenience */
static gboolean
delete_object (NMPlatform *platform, struct nl_object *obj)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	auto_nl_object struct nl_object *object = obj;
	auto_nl_object struct nl_object *cached_object;
	int nle;

	cached_object = nl_cache_search (choose_cache (platform, object), object);
	g_assert (cached_object);

	nle = delete_kernel_object (priv->nlh, cached_object);

	/* NLE_OBJ_NOTFOUND is considered equivalent to success to avoid race conditions. You
	 * never know when something deletes the same object just before NetworkManager.
	 */
	switch (nle) {
	case -NLE_SUCCESS:
	case -NLE_OBJ_NOTFOUND:
		break;
	default:
		error ("Netlink error: %s", nl_geterror (nle));
		return FALSE;
	}

	nl_cache_remove (cached_object);
	if (object_type_from_nl_object (object) == LINK) {
		int ifindex = rtnl_link_get_ifindex ((struct rtnl_link *) object);

		nl_cache_foreach (priv->address_cache, remove_if_ifindex, &ifindex);
		nl_cache_foreach (priv->route_cache, remove_if_ifindex, &ifindex);
	}

	announce_object (platform, cached_object, REMOVED);

	return TRUE;
}

static void
ref_object (struct nl_object *obj, void *data)
{
	struct nl_object **out = data;

	nl_object_get (obj);
	*out = obj;
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
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	struct nl_cache *cache;
	auto_nl_object struct nl_object *object = NULL;
	auto_nl_object struct nl_object *cached_object = NULL;
	auto_nl_object struct nl_object *kernel_object = NULL;
	int event;
	int nle;

	event = nlmsg_hdr (msg)->nlmsg_type;
	nl_msg_parse (msg, ref_object, &object);
	g_return_val_if_fail (object, NL_OK);

	cache = choose_cache (platform, object);
	cached_object = nl_cache_search (cache, object);
	kernel_object = get_kernel_object (priv->nlh, object);

	debug ("netlink event (type %d)", event);

	hack_empty_master_iff_lower_up (platform, kernel_object);

	/* Removed object */
	switch (event) {
	case RTM_DELLINK:
	case RTM_DELADDR:
		/* Ignore inconsistent deletion
		 *
		 * Quick external deletion and addition can be occasionally
		 * seen as just a change.
		 */
		if (kernel_object)
			return NL_OK;
		/* Ignore internal deletion */
		if (!cached_object)
			return NL_OK;

		nl_cache_remove (cached_object);
		announce_object (platform, cached_object, REMOVED);

		return NL_OK;
	case RTM_NEWLINK:
	case RTM_NEWADDR:
		/* Ignore inconsistent addition or change (kernel will send a good one)
		 *
		 * Quick sequence of RTM_NEWLINK notifications can be occasionally
		 * collapsed to just one addition or deletion, depending of whether we
		 * already have the object in cache.
		 */
		if (!kernel_object)
			return NL_OK;
		/* Handle external addition */
		if (!cached_object) {
			nle = nl_cache_add (cache, kernel_object);
			if (nle) {
				error ("netlink cache error: %s", nl_geterror (nle));
				return NL_OK;
			}
			announce_object (platform, kernel_object, ADDED);
			return NL_OK;
		}
		/* Ignore non-change
		 *
		 * This also catches notifications for internal addition or change, unless
		 * another action occured very soon after it.
		 */
		if (!nl_object_diff (kernel_object, cached_object))
			return NL_OK;
		/* Handle external change */
		nl_cache_remove (cached_object);
		nle = nl_cache_add (cache, kernel_object);
		if (nle) {
			error ("netlink cache error: %s", nl_geterror (nle));
			return NL_OK;
		}
		announce_object (platform, kernel_object, CHANGED);

		return NL_OK;
	default:
		error ("Unknown netlink event: %d", event);
		return NL_OK;
	}
}

/******************************************************************/

static gboolean
sysctl_set (NMPlatform *platform, const char *path, const char *value)
{
	int fd, len, nwrote, tries;
	char *actual;

	g_return_val_if_fail (path != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	fd = open (path, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		error ("sysctl: failed to open '%s': (%d) %s",
				path, errno, strerror (errno));
		return FALSE;
	}

	debug ("sysctl: setting '%s' to '%s'", path, value);

	/* Most sysfs and sysctl options don't care about a trailing LF, while some
	 * (like infiniband) do.  So always add the LF.  Also, neither sysfs nor
	 * sysctl support partial writes so the LF must be added to the string we're
	 * about to write.
	 */
	actual = g_strdup_printf ("%s\n", value);

	/* Try to write the entire value three times if a partial write occurs */
	len = strlen (actual);
	for (tries = 0, nwrote = 0; tries < 3 && nwrote != len; tries++) {
		errno = 0;
		nwrote = write (fd, actual, len);
		if (nwrote == -1) {
			if (errno == EINTR) {
				error ("sysctl: interrupted, will try again");
				continue;
			}
			break;
		}
	}
	if (nwrote != len && errno != EEXIST) {
		error ("sysctl: failed to set '%s' to '%s': (%d) %s",
		             path, value, errno, strerror (errno));
	}

	g_free (actual);
	close (fd);
	return (nwrote == len);
}

static char *
sysctl_get (NMPlatform *platform, const char *path)
{
	GError *error = NULL;
	char *contents;

	if (!g_file_get_contents (path, &contents, NULL, &error)) {
		error ("error reading %s: %s", path, error->message);
		return NULL;
	}

	return g_strstrip (contents);
}

/******************************************************************/

static GArray *
link_get_all (NMPlatform *platform)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GArray *links = g_array_sized_new (TRUE, TRUE, sizeof (NMPlatformLink), nl_cache_nitems (priv->link_cache));
	NMPlatformLink device;
	struct nl_object *object;

	for (object = nl_cache_get_first (priv->link_cache); object; object = nl_cache_get_next (object)) {
		int ifindex = rtnl_link_get_ifindex ((struct rtnl_link *) object);

		if (g_hash_table_lookup (priv->udev_devices, GINT_TO_POINTER (ifindex))) {
			link_init (platform, &device, (struct rtnl_link *) object);
			g_array_append_val (links, device);
		}
	}

	return links;
}

static struct nl_object *
build_rtnl_link (int ifindex, const char *name, NMLinkType type)
{
	struct rtnl_link *rtnllink;
	int nle;

	rtnllink = rtnl_link_alloc ();
	g_assert (rtnllink);
	if (ifindex)
		rtnl_link_set_ifindex (rtnllink, ifindex);
	if (name)
		rtnl_link_set_name (rtnllink, name);
	if (type) {
		nle = rtnl_link_set_type (rtnllink, type_to_string (type));
		g_assert (!nle);
	}

	return (struct nl_object *) rtnllink;
}

static gboolean
link_add (NMPlatform *platform, const char *name, NMLinkType type)
{
	int r;

	if (type == NM_LINK_TYPE_BOND) {
		/* When the kernel loads the bond module, either via explicit modprobe
		 * or automatically in response to creating a bond master, it will also
		 * create a 'bond0' interface.  Since the bond we're about to create may
		 * or may not be named 'bond0' prevent potential confusion about a bond
		 * that the user didn't want by telling the bonding module not to create
		 * bond0 automatically.
		 */
		if (!g_file_test ("/sys/class/net/bonding_masters", G_FILE_TEST_EXISTS))
			/* Ignore return value to shut up the compiler */
			r = system ("modprobe bonding max_bonds=0");
	}

	return add_object (platform, build_rtnl_link (0, name, type));
}

static struct rtnl_link *
link_get (NMPlatform *platform, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	struct rtnl_link *rtnllink = rtnl_link_get (priv->link_cache, ifindex);

	if (!rtnllink)
		platform->error = NM_PLATFORM_ERROR_NOT_FOUND;

	return rtnllink;
}

static gboolean
link_change (NMPlatform *platform, int ifindex, struct rtnl_link *change)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);
	int nle;

	if (!rtnllink)
		return FALSE;

	nle = rtnl_link_change (priv->nlh, rtnllink, change, 0);

	/* When netlink returns this error, it usually means it failed to find
	 * firmware for the device, especially on nm_platform_link_set_up ().
	 * This is basically the same check as in the original code and could
	 * potentially be improved.
	 */
	if (nle == -NLE_OBJ_NOTFOUND) {
		platform->error = NM_PLATFORM_ERROR_NO_FIRMWARE;
		return FALSE;
	}

	return refresh_object (platform, (struct nl_object *) rtnllink, nle);
}

static gboolean
link_delete (NMPlatform *platform, int ifindex)
{
	return delete_object (platform, build_rtnl_link (ifindex, NULL, NM_LINK_TYPE_NONE));
}

static int
link_get_ifindex (NMPlatform *platform, const char *ifname)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	return rtnl_link_name2i (priv->link_cache, ifname);
}

static const char *
link_get_name (NMPlatform *platform, int ifindex)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);

	return rtnllink ? rtnl_link_get_name (rtnllink) : NULL;
}

static NMLinkType
link_get_type (NMPlatform *platform, int ifindex)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);

	return link_extract_type (platform, rtnllink, NULL);
}

static const char *
link_get_type_name (NMPlatform *platform, int ifindex)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);
	const char *type;

	link_extract_type (platform, rtnllink, &type);
	return type;
}

static guint32
link_get_flags (NMPlatform *platform, int ifindex)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);

	if (!rtnllink)
		return IFF_NOARP;

	return rtnl_link_get_flags (rtnllink);
}

static gboolean
link_is_up (NMPlatform *platform, int ifindex)
{
	return !!(link_get_flags (platform, ifindex) & IFF_UP);
}

static gboolean
link_is_connected (NMPlatform *platform, int ifindex)
{
	return !!(link_get_flags (platform, ifindex) & IFF_LOWER_UP);
}

static gboolean
link_uses_arp (NMPlatform *platform, int ifindex)
{
	return !(link_get_flags (platform, ifindex) & IFF_NOARP);
}

static gboolean
link_change_flags (NMPlatform *platform, int ifindex, unsigned int flags, gboolean value)
{
	auto_nl_object struct rtnl_link *change;

	change = rtnl_link_alloc ();
	g_return_val_if_fail (change != NULL, FALSE);

	if (value)
		rtnl_link_set_flags (change, flags);
	else
		rtnl_link_unset_flags (change, flags);

	return link_change (platform, ifindex, change);
}

static gboolean
link_set_up (NMPlatform *platform, int ifindex)
{
	return link_change_flags (platform, ifindex, IFF_UP, TRUE);
}

static gboolean
link_set_down (NMPlatform *platform, int ifindex)
{
	return link_change_flags (platform, ifindex, IFF_UP, FALSE);
}

static gboolean
link_set_arp (NMPlatform *platform, int ifindex)
{
	return link_change_flags (platform, ifindex, IFF_NOARP, FALSE);
}

static gboolean
link_set_noarp (NMPlatform *platform, int ifindex)
{
	return link_change_flags (platform, ifindex, IFF_NOARP, TRUE);
}

static gboolean
ethtool_get (const char *name, gpointer edata)
{
	struct ifreq ifr;
	int fd;

	memset (&ifr, 0, sizeof (ifr));
	strncpy (ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_data = edata;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		error ("ethtool: Could not open socket.");
		return FALSE;
	}

	if (ioctl (fd, SIOCETHTOOL, &ifr) < 0) {
		debug ("ethtool: Request failed: %s", strerror (errno));
		close (fd);
		return FALSE;
	}

	close (fd);
	return TRUE;
}

static int
ethtool_get_stringset_index (const char *ifname, int stringset_id, const char *string)
{
	auto_g_free struct ethtool_sset_info *info = NULL;
	auto_g_free struct ethtool_gstrings *strings = NULL;
	guint32 len, i;

	info = g_malloc0 (sizeof (*info) + sizeof (guint32));
	info->cmd = ETHTOOL_GSSET_INFO;
	info->reserved = 0;
	info->sset_mask = 1ULL << stringset_id;

	if (!ethtool_get (ifname, info))
		return -1;
	if (!info->sset_mask)
		return -1;

	len = info->data[0];

	strings = g_malloc0 (sizeof (*strings) + len * ETH_GSTRING_LEN);
	strings->cmd = ETHTOOL_GSTRINGS;
	strings->string_set = stringset_id;
	strings->len = len;
	if (!ethtool_get (ifname, strings))
		return -1;

	for (i = 0; i < len; i++) {
		if (!strcmp ((char *) &strings->data[i * ETH_GSTRING_LEN], string))
			return i;
	}

	return -1;
}

static gboolean
supports_ethtool_carrier_detect (const char *ifname)
{
	struct ethtool_cmd edata = { .cmd = ETHTOOL_GLINK };

	/* We ignore the result. If the ETHTOOL_GLINK call succeeded, then we
	 * assume the device supports carrier-detect, otherwise we assume it
	 * doesn't.
	 */
	return ethtool_get (ifname, &edata);
}

static gboolean
supports_mii_carrier_detect (const char *ifname)
{
	int fd;
	struct ifreq ifr;
	struct mii_ioctl_data *mii;
	gboolean supports_mii = FALSE;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_err (LOGD_PLATFORM, "couldn't open control socket.");
		return FALSE;
	}

	memset (&ifr, 0, sizeof (struct ifreq));
	strncpy (ifr.ifr_name, ifname, IFNAMSIZ);

	errno = 0;
	if (ioctl (fd, SIOCGMIIPHY, &ifr) < 0) {
		nm_log_dbg (LOGD_PLATFORM, "SIOCGMIIPHY failed: %d", errno);
		goto out;
	}

	/* If we can read the BMSR register, we assume that the card supports MII link detection */
	mii = (struct mii_ioctl_data *) &ifr.ifr_ifru;
	mii->reg_num = MII_BMSR;

	if (ioctl (fd, SIOCGMIIREG, &ifr) == 0) {
		nm_log_dbg (LOGD_PLATFORM, "SIOCGMIIREG result 0x%X", mii->val_out);
		supports_mii = TRUE;
	} else {
		nm_log_dbg (LOGD_PLATFORM, "SIOCGMIIREG failed: %d", errno);
	}

 out:
	close (fd);
	nm_log_dbg (LOGD_PLATFORM, "MII %s supported", supports_mii ? "is" : "not");
	return supports_mii;	
}

static gboolean
link_supports_carrier_detect (NMPlatform *platform, int ifindex)
{
	const char *name = nm_platform_link_get_name (ifindex);

	if (!name)
		return FALSE;

	/* We use netlink for the actual carrier detection, but netlink can't tell
	 * us whether the device actually supports carrier detection in the first
	 * place. We assume any device that does implements one of these two APIs.
	 */
	return supports_ethtool_carrier_detect (name) || supports_mii_carrier_detect (name);
}

static gboolean
link_supports_vlans (NMPlatform *platform, int ifindex)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);
	const char *name = nm_platform_link_get_name (ifindex);
	auto_g_free struct ethtool_gfeatures *features = NULL;
	int index, block, bit, size;

	/* Only ARPHRD_ETHER links can possibly support VLANs. */
	if (!rtnllink || rtnl_link_get_arptype (rtnllink) != ARPHRD_ETHER)
		return FALSE;

	if (!name)
		return FALSE;

	index = ethtool_get_stringset_index (name, ETH_SS_FEATURES, "vlan-challenged");
	if (index == -1) {
		debug ("vlan-challenged ethtool feature does not exist?");
		return FALSE;
	}

	block = index /  32;
	bit = index % 32;
	size = block + 1;

	features = g_malloc0 (sizeof (*features) + size * sizeof (struct ethtool_get_features_block));
	features->cmd = ETHTOOL_GFEATURES;
	features->size = size;

	if (!ethtool_get (name, features))
		return FALSE;

	return !(features->features[block].active & (1 << bit));
}

static gboolean
link_set_address (NMPlatform *platform, int ifindex, gconstpointer address, size_t length)
{
	auto_nl_object struct rtnl_link *change = NULL;
	auto_nl_addr struct nl_addr *nladdr = NULL;

	change = rtnl_link_alloc ();
	g_return_val_if_fail (change, FALSE);

	nladdr = nl_addr_build (AF_LLC, address, length);
	g_return_val_if_fail (nladdr, FALSE);

	rtnl_link_set_addr (change, nladdr);

	return link_change (platform, ifindex, change);
}

static gconstpointer
link_get_address (NMPlatform *platform, int ifindex, size_t *length)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);
	struct nl_addr *nladdr;

	nladdr = rtnllink ? rtnl_link_get_addr (rtnllink) : NULL;

	if (length)
		*length = nladdr ? nl_addr_get_len (nladdr) : 0;

	return nladdr ? nl_addr_get_binary_addr (nladdr) : NULL;
}

static gboolean
link_set_mtu (NMPlatform *platform, int ifindex, guint32 mtu)
{
	auto_nl_object struct rtnl_link *change;

	change = rtnl_link_alloc ();
	g_return_val_if_fail (change != NULL, FALSE);
	rtnl_link_set_mtu (change, mtu);

	return link_change (platform, ifindex, change);
}

static guint32
link_get_mtu (NMPlatform *platform, int ifindex)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);

	return rtnllink ? rtnl_link_get_mtu (rtnllink) : 0;
}

static int
vlan_add (NMPlatform *platform, const char *name, int parent, int vlan_id, guint32 vlan_flags)
{
	struct nl_object *object = build_rtnl_link (0, name, NM_LINK_TYPE_VLAN);
	struct rtnl_link *rtnllink = (struct rtnl_link *) object;
	unsigned int kernel_flags;

	kernel_flags = 0;
	if (vlan_flags & NM_VLAN_FLAG_REORDER_HEADERS)
		kernel_flags |= VLAN_FLAG_REORDER_HDR;
	if (vlan_flags & NM_VLAN_FLAG_GVRP)
		kernel_flags |= VLAN_FLAG_GVRP;
	if (vlan_flags & NM_VLAN_FLAG_LOOSE_BINDING)
		kernel_flags |= VLAN_FLAG_LOOSE_BINDING;

	rtnl_link_set_link (rtnllink, parent);
	rtnl_link_vlan_set_id (rtnllink, vlan_id);
	rtnl_link_vlan_set_flags (rtnllink, vlan_flags);

	return add_object (platform, object);
}

static gboolean
vlan_get_info (NMPlatform *platform, int ifindex, int *parent, int *vlan_id)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);

	if (parent)
		*parent = rtnllink ? rtnl_link_get_link (rtnllink) : 0;
	if (vlan_id)
		*vlan_id = rtnllink ? rtnl_link_vlan_get_id (rtnllink) : 0;

	return !!rtnllink;
}

static gboolean
vlan_set_ingress_map (NMPlatform *platform, int ifindex, int from, int to)
{
	auto_nl_object struct rtnl_link *change = rtnl_link_alloc ();

	g_assert (change);
	rtnl_link_vlan_set_egress_map (change, from, to);

	return link_change (platform, ifindex, change);
}

static gboolean
vlan_set_egress_map (NMPlatform *platform, int ifindex, int from, int to)
{
	auto_nl_object struct rtnl_link *change = rtnl_link_alloc ();

	g_assert (change);
	rtnl_link_vlan_set_egress_map (change, from, to);

	return link_change (platform, ifindex, change);
}

static gboolean
link_refresh (NMPlatform *platform, int ifindex, int nle)
{
	auto_nl_object struct nl_object *object = build_rtnl_link (ifindex, NULL, NM_LINK_TYPE_NONE);

	return refresh_object (platform, object, nle);
}

static gboolean
link_enslave (NMPlatform *platform, int master, int slave)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	return link_refresh (platform, slave, rtnl_link_enslave_ifindex (priv->nlh, master, slave));
}

static gboolean
link_release (NMPlatform *platform, int master, int slave)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	return link_refresh (platform, slave, rtnl_link_release_ifindex (priv->nlh, slave));
}

static int
link_get_master (NMPlatform *platform, int slave)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, slave);

	return rtnllink ? rtnl_link_get_master (rtnllink) : 0;
}

static char *
link_option_path (int master, const char *category, const char *option)
{
	const char *name = nm_platform_link_get_name (master);
   
	if (!name || !category || !option)
		return NULL;

	return g_strdup_printf ("/sys/class/net/%s/%s/%s", name, category, option);
}

static gboolean
link_set_option (int master, const char *category, const char *option, const char *value)
{
	auto_g_free char *path = link_option_path (master, category, option);

	return path && nm_platform_sysctl_set (path, value);
}

static char *
link_get_option (int master, const char *category, const char *option)
{
	auto_g_free char *path = link_option_path (master, category, option);

	return path ? nm_platform_sysctl_get (path) : NULL;
}

static const char *
master_category (NMPlatform *platform, int master)
{
	switch (link_get_type (platform, master)) {
	case NM_LINK_TYPE_BRIDGE:
		return "bridge";
	case NM_LINK_TYPE_BOND:
		return "bonding";
	default:
		g_assert_not_reached ();
	}
}

static const char *
slave_category (NMPlatform *platform, int slave)
{
	int master = link_get_master (platform, slave);

	if (master) {
		platform->error = NM_PLATFORM_ERROR_NOT_SLAVE;
		return NULL;
	}

	switch (link_get_type (platform, master)) {
	case NM_LINK_TYPE_BRIDGE:
		return "brport";
	default:
		g_assert_not_reached ();
	}
}

static gboolean
master_set_option (NMPlatform *platform, int master, const char *option, const char *value)
{
	return link_set_option (master, master_category (platform, master), option, value);
}

static char *
master_get_option (NMPlatform *platform, int master, const char *option)
{
	return link_get_option (master, master_category (platform, master), option);
}

static gboolean
slave_set_option (NMPlatform *platform, int slave, const char *option, const char *value)
{
	return link_set_option (slave, slave_category (platform, slave), option, value);
}

static char *
slave_get_option (NMPlatform *platform, int slave, const char *option)
{
	return link_get_option (slave, slave_category (platform, slave), option);
}

static gboolean
infiniband_partition_add (NMPlatform *platform, int parent, int p_key)
{
	const char *parent_name;
	char *path, *id;
	gboolean success;

	parent_name = nm_platform_link_get_name (parent);
	g_return_val_if_fail (parent_name != NULL, FALSE);

	path = g_strdup_printf ("/sys/class/net/%s/create_child", parent_name);
	id = g_strdup_printf ("0x%04x", p_key);
	success = nm_platform_sysctl_set (path, id);
	g_free (id);
	g_free (path);

	return success;
}

static gboolean
veth_get_properties (NMPlatform *platform, int ifindex, NMPlatformVethProperties *props)
{
	const char *ifname;
	auto_g_free struct ethtool_stats *stats = NULL;
	int peer_ifindex_stat;

	ifname = nm_platform_link_get_name (ifindex);
	if (!ifname)
		return FALSE;

	peer_ifindex_stat = ethtool_get_stringset_index (ifname, ETH_SS_STATS, "peer_ifindex");
	if (peer_ifindex_stat == -1) {
		debug ("%s: peer_ifindex ethtool stat does not exist?", ifname);
		return FALSE;
	}

	stats = g_malloc0 (sizeof (*stats) + (peer_ifindex_stat + 1) * sizeof (guint64));
	stats->cmd = ETHTOOL_GSTATS;
	stats->n_stats = peer_ifindex_stat + 1;
	if (!ethtool_get (ifname, stats))
		return FALSE;

	props->peer = stats->data[peer_ifindex_stat];
	return TRUE;
}

static gboolean
tun_get_properties (NMPlatform *platform, int ifindex, NMPlatformTunProperties *props)
{
	const char *ifname;
	char *path, *val;
	guint32 flags;

	ifname = nm_platform_link_get_name (ifindex);
	if (!ifname)
		return FALSE;

	path = g_strdup_printf ("/sys/class/net/%s/owner", ifname);
	val = nm_platform_sysctl_get (path);
	g_free (path);
	if (!val)
		return FALSE;
	props->owner = strtoll (val, NULL, 10);
	g_free (val);

	path = g_strdup_printf ("/sys/class/net/%s/group", ifname);
	val = nm_platform_sysctl_get (path);
	g_free (path);
	props->group = strtoll (val, NULL, 10);
	g_free (val);

	path = g_strdup_printf ("/sys/class/net/%s/tun_flags", ifname);
	val = nm_platform_sysctl_get (path);
	g_free (path);
	flags = strtoul (val, NULL, 16);
	props->mode = ((flags & TUN_TYPE_MASK) == TUN_TUN_DEV) ? "tun" : "tap";
	props->no_pi = !!(flags & IFF_NO_PI);
	props->vnet_hdr = !!(flags & IFF_VNET_HDR);
#ifdef IFF_MULTI_QUEUE
	props->multi_queue = !!(flags & IFF_MULTI_QUEUE);
#else
	props->multi_queue = FALSE;
#endif
	g_free (val);

	return TRUE;
}

static const struct nla_policy macvlan_info_policy[IFLA_MACVLAN_MAX + 1] = {
	[IFLA_MACVLAN_MODE]  = { .type = NLA_U32 },
#ifdef IFLA_MACVLAN_FLAGS
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
	auto_nl_object struct rtnl_link *rtnllink;
	int err;

	rtnllink = link_get (platform, ifindex);
	if (!rtnllink)
		return FALSE;

	props->parent_ifindex = rtnl_link_get_link (rtnllink);

	err = nm_rtnl_link_parse_info_data (priv->nlh, ifindex,
	                                    macvlan_info_data_parser, props);
	return (err == 0);
}

static const struct nla_policy gre_info_policy[IFLA_GRE_MAX + 1] = {
	[IFLA_GRE_LINK]		= { .type = NLA_U32 },
	[IFLA_GRE_IFLAGS]	= { .type = NLA_U16 },
	[IFLA_GRE_OFLAGS]	= { .type = NLA_U16 },
	[IFLA_GRE_IKEY]		= { .type = NLA_U32 },
	[IFLA_GRE_OKEY]		= { .type = NLA_U32 },
	[IFLA_GRE_LOCAL]	= { .type = NLA_U32 },
	[IFLA_GRE_REMOTE]	= { .type = NLA_U32 },
	[IFLA_GRE_TTL]		= { .type = NLA_U8 },
	[IFLA_GRE_TOS]		= { .type = NLA_U8 },
	[IFLA_GRE_PMTUDISC]	= { .type = NLA_U8 },
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
	props->path_mtu_discovery = nla_get_u8 (tb[IFLA_GRE_PMTUDISC]);

	return 0;
}

static gboolean
gre_get_properties (NMPlatform *platform, int ifindex, NMPlatformGreProperties *props)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int err;

	err = nm_rtnl_link_parse_info_data (priv->nlh, ifindex,
	                                    gre_info_data_parser, props);
	return (err == 0);
}

/******************************************************************/

static int
ip_address_mark_all (NMPlatform *platform, int family, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	struct nl_object *object;
	int count = 0;

	for (object = nl_cache_get_first (priv->address_cache); object; object = nl_cache_get_next (object)) {
		nl_object_unmark (object);
		if (rtnl_addr_get_family ((struct rtnl_addr *) object) != family)
			continue;
		if (rtnl_addr_get_ifindex ((struct rtnl_addr *) object) != ifindex)
			continue;
		nl_object_mark (object);
		count++;
	}

	return count;
}

static GArray *
ip4_address_get_all (NMPlatform *platform, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GArray *addresses;
	NMPlatformIP4Address address;
	struct nl_object *object;
	int count;

	count = ip_address_mark_all (platform, AF_INET, ifindex);
	addresses = g_array_sized_new (TRUE, TRUE, sizeof (NMPlatformIP4Address), count);

	for (object = nl_cache_get_first (priv->address_cache); object; object = nl_cache_get_next (object)) {
		if (nl_object_is_marked (object)) {
			init_ip4_address (&address, (struct rtnl_addr *) object);
			g_array_append_val (addresses, address);
			nl_object_unmark (object);
		}
	}

	return addresses;
}

static GArray *
ip6_address_get_all (NMPlatform *platform, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GArray *addresses;
	NMPlatformIP6Address address;
	struct nl_object *object;
	int count;

	count = ip_address_mark_all (platform, AF_INET6, ifindex);
	addresses = g_array_sized_new (TRUE, TRUE, sizeof (NMPlatformIP6Address), count);

	for (object = nl_cache_get_first (priv->address_cache); object; object = nl_cache_get_next (object)) {
		if (nl_object_is_marked (object)) {
			init_ip6_address (&address, (struct rtnl_addr *) object);
			g_array_append_val (addresses, address);
			nl_object_unmark (object);
		}
	}

	return addresses;
}

static struct nl_object *
build_rtnl_addr (int family, int ifindex, gconstpointer addr, int plen)
{
	struct rtnl_addr *rtnladdr = rtnl_addr_alloc ();
	int addrlen = family == AF_INET ? sizeof (in_addr_t) : sizeof (struct in6_addr);
	auto_nl_addr struct nl_addr *nladdr = nl_addr_build (family, addr, addrlen);
	int nle;

	g_assert (rtnladdr && nladdr);

	rtnl_addr_set_ifindex (rtnladdr, ifindex);
	nle = rtnl_addr_set_local (rtnladdr, nladdr);
	g_assert (!nle);
	rtnl_addr_set_prefixlen (rtnladdr, plen);

	return (struct nl_object *) rtnladdr;
}

static gboolean
ip4_address_add (NMPlatform *platform, int ifindex, in_addr_t addr, int plen)
{
	return add_object (platform, build_rtnl_addr (AF_INET, ifindex, &addr, plen));
}

static gboolean
ip6_address_add (NMPlatform *platform, int ifindex, struct in6_addr addr, int plen)
{
	return add_object (platform, build_rtnl_addr (AF_INET6, ifindex, &addr, plen));
}

static gboolean
ip4_address_delete (NMPlatform *platform, int ifindex, in_addr_t addr, int plen)
{
	return delete_object (platform, build_rtnl_addr (AF_INET, ifindex, &addr, plen));
}

static gboolean
ip6_address_delete (NMPlatform *platform, int ifindex, struct in6_addr addr, int plen)
{
	return delete_object (platform, build_rtnl_addr (AF_INET6, ifindex, &addr, plen));
}

static gboolean
ip_address_exists (NMPlatform *platform, int family, int ifindex, gconstpointer addr, int plen)
{
	auto_nl_object struct nl_object *object = build_rtnl_addr (family, ifindex, addr, plen);
	auto_nl_object struct nl_object *cached_object = nl_cache_search (choose_cache (platform, object), object);

	return !!cached_object;
}

static gboolean
ip4_address_exists (NMPlatform *platform, int ifindex, in_addr_t addr, int plen)
{
	return ip_address_exists (platform, AF_INET, ifindex, &addr, plen);
}

static gboolean
ip6_address_exists (NMPlatform *platform, int ifindex, struct in6_addr addr, int plen)
{
	return ip_address_exists (platform, AF_INET6, ifindex, &addr, plen);
}

/******************************************************************/

static int
ip_route_mark_all (NMPlatform *platform, int family, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	struct nl_object *object;
	int count = 0;

	for (object = nl_cache_get_first (priv->route_cache); object; object = nl_cache_get_next (object)) {
		struct rtnl_route *rtnlroute = (struct rtnl_route *) object;
		struct rtnl_nexthop *nexthop;

		nl_object_unmark (object);
		if (rtnl_route_get_type (rtnlroute) != RTN_UNICAST)
			continue;
		if (rtnl_route_get_table (rtnlroute) != RT_TABLE_MAIN)
			continue;
		if (rtnl_route_get_family (rtnlroute) != family)
			continue;
		if (rtnl_route_get_nnexthops (rtnlroute) != 1)
			continue;
		nexthop = rtnl_route_nexthop_n (rtnlroute, 0);
		if (rtnl_route_nh_get_ifindex (nexthop) != ifindex)
			continue;
		nl_object_mark (object);
		count++;
	}

	return count;
}

static GArray *
ip4_route_get_all (NMPlatform *platform, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GArray *routes;
	NMPlatformIP4Route route;
	struct nl_object *object;
	int count = 0;

	count = ip_route_mark_all (platform, AF_INET, ifindex);
	routes = g_array_sized_new (TRUE, TRUE, sizeof (NMPlatformIP4Route), count);

	for (object = nl_cache_get_first (priv->route_cache); object; object = nl_cache_get_next (object)) {
		if (nl_object_is_marked (object)) {
			init_ip4_route (&route, (struct rtnl_route *) object);
			g_array_append_val (routes, route);
			nl_object_unmark (object);
		}
	}

	return routes;
}

static GArray *
ip6_route_get_all (NMPlatform *platform, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GArray *routes;
	NMPlatformIP6Route route;
	struct nl_object *object;
	int count;

	count = ip_route_mark_all (platform, AF_INET6, ifindex);
	routes = g_array_sized_new (TRUE, TRUE, sizeof (NMPlatformIP6Route), count);

	for (object = nl_cache_get_first (priv->route_cache); object; object = nl_cache_get_next (object)) {
		if (nl_object_is_marked (object)) {
			init_ip6_route (&route, (struct rtnl_route *) object);
			g_array_append_val (routes, route);
			nl_object_unmark (object);
		}
	}

	return routes;
}

static struct nl_object *
build_rtnl_route (int family, int ifindex, gconstpointer network, int plen, gconstpointer gateway, int metric, int mss)
{
	struct rtnl_route *rtnlroute = rtnl_route_alloc ();
	struct rtnl_nexthop *nexthop = rtnl_route_nh_alloc ();
	int addrlen = (family == AF_INET) ? sizeof (in_addr_t) : sizeof (struct in6_addr);
	/* Workaround a libnl bug by using zero destination address length for default routes */
	auto_nl_addr struct nl_addr *dst = nl_addr_build (family, network, plen ? addrlen : 0);
	auto_nl_addr struct nl_addr *gw = gateway ? nl_addr_build (family, gateway, addrlen) : NULL;

	g_assert (rtnlroute && dst && nexthop);

	nl_addr_set_prefixlen (dst, plen);

	rtnl_route_set_table (rtnlroute, RT_TABLE_MAIN);
	rtnl_route_set_tos (rtnlroute, 0);
	rtnl_route_set_dst (rtnlroute, dst);
	rtnl_route_set_priority (rtnlroute, metric);

	rtnl_route_nh_set_ifindex (nexthop, ifindex);
	if (gw && !nl_addr_iszero (gw))
		rtnl_route_nh_set_gateway (nexthop, gw);
	rtnl_route_add_nexthop (rtnlroute, nexthop);

	if (mss > 0)
		rtnl_route_set_metric (rtnlroute, RTAX_ADVMSS, mss);

	return (struct nl_object *) rtnlroute;
}

static gboolean
ip4_route_add (NMPlatform *platform, int ifindex, in_addr_t network, int plen, in_addr_t gateway, int metric, int mss)
{
	return add_object (platform, build_rtnl_route (AF_INET, ifindex, &network, plen, &gateway, metric, mss));
}

static gboolean
ip6_route_add (NMPlatform *platform, int ifindex, struct in6_addr network, int plen, struct in6_addr gateway, int metric, int mss)
{
	return add_object (platform, build_rtnl_route (AF_INET6, ifindex, &network, plen, &gateway, metric, mss));
}

static gboolean
ip4_route_delete (NMPlatform *platform, int ifindex, in_addr_t network, int plen, int metric)
{
	in_addr_t gateway = 0;

	return delete_object (platform, build_rtnl_route (AF_INET, ifindex, &network, plen, &gateway, metric, 0));
}

static gboolean
ip6_route_delete (NMPlatform *platform, int ifindex, struct in6_addr network, int plen, int metric)
{
	struct in6_addr gateway = in6addr_any;

	return delete_object (platform, build_rtnl_route (AF_INET6, ifindex, &network, plen, &gateway, metric, 0));
}

static gboolean
ip_route_exists (NMPlatform *platform, int family, int ifindex, gpointer network, int plen, int metric)
{
	auto_nl_object struct nl_object *object = build_rtnl_route (
			family, ifindex, network, plen, INADDR_ANY, metric, 0);
	auto_nl_object struct nl_object *cached_object = nl_cache_search (
			choose_cache (platform, object), object);

	return !!cached_object;
}

static gboolean
ip4_route_exists (NMPlatform *platform, int ifindex, in_addr_t network, int plen, int metric)
{
	return ip_route_exists (platform, AF_INET, ifindex, &network, plen, metric);
}

static gboolean
ip6_route_exists (NMPlatform *platform, int ifindex, struct in6_addr network, int plen, int metric)
{
	return ip_route_exists (platform, AF_INET6, ifindex, &network, plen, metric);
}

/******************************************************************/

#define EVENT_CONDITIONS      ((GIOCondition) (G_IO_IN | G_IO_PRI))
#define ERROR_CONDITIONS      ((GIOCondition) (G_IO_ERR | G_IO_NVAL))
#define DISCONNECT_CONDITIONS ((GIOCondition) (G_IO_HUP))

static int
verify_source (struct nl_msg *msg, gpointer user_data)
{
	struct ucred *creds = nlmsg_get_creds (msg);

	if (!creds || creds->pid || creds->uid || creds->gid) {
		if (creds)
			warning ("netlink: received non-kernel message (pid %d uid %d gid %d)",
					creds->pid, creds->uid, creds->gid);
		else
			warning ("netlink: received message without credentials");
		return NL_STOP;
	}

	return NL_OK;
}

static gboolean
event_handler (GIOChannel *channel,
		GIOCondition io_condition,
		gpointer user_data)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (user_data);
	int nle;

	nle = nl_recvmsgs_default (priv->nlh_event);
	if (nle)
		error ("Failed to retrieve incoming events: %s", nl_geterror (nle));
	return TRUE;
}

static struct nl_sock *
setup_socket (gboolean event, gpointer user_data)
{
	struct nl_sock *sock;
	int nle;

	sock = nl_socket_alloc ();
	g_return_val_if_fail (sock, NULL);

	/* Only ever accept messages from kernel */
	nle = nl_socket_modify_cb (sock, NL_CB_MSG_IN, NL_CB_CUSTOM, verify_source, user_data);
	g_assert (!nle);

	/* Dispatch event messages (event socket only) */
	if (event) {
		nl_socket_modify_cb (sock, NL_CB_VALID, NL_CB_CUSTOM, event_notification, user_data);
		nl_socket_disable_seq_check (sock);
	}

	nle = nl_connect (sock, NETLINK_ROUTE);
	g_assert (!nle);
	nle = nl_socket_set_passcred (sock, 1);
	g_assert (!nle);

	return sock;
}

/******************************************************************/

static void
udev_device_added (NMPlatform *platform,
                   GUdevDevice *udev_device)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	auto_nl_object struct rtnl_link *rtnllink = NULL;
	const char *ifname, *devtype;
	NMPlatformLink link;
	int ifindex;

	ifname = g_udev_device_get_name (udev_device);
	if (!ifname) {
		debug ("failed to get device's interface");
		return;
	}

	if (g_udev_device_get_sysfs_attr (udev_device, "ifindex"))
		ifindex = g_udev_device_get_sysfs_attr_as_int (udev_device, "ifindex");
	else {
		warning ("(%s): failed to get device's ifindex", ifname);
		return;
	}

	if (!g_udev_device_get_sysfs_path (udev_device)) {
		debug ("(%s): couldn't determine device path; ignoring...", ifname);
		return;
	}

	/* Not all ethernet devices are immediately usable; newer mobile broadband
	 * devices (Ericsson, Option, Sierra) require setup on the tty before the
	 * ethernet device is usable.  2.6.33 and later kernels set the 'DEVTYPE'
	 * uevent variable which we can use to ignore the interface as a NMDevice
	 * subclass.  ModemManager will pick it up though and so we'll handle it
	 * through the mobile broadband stuff.
	 */
	devtype = g_udev_device_get_property (udev_device, "DEVTYPE");
	if (g_strcmp0 (devtype, "wwan") == 0) {
		debug ("(%s): ignoring interface with devtype '%s'", ifname, devtype);
		return;
	}

	rtnllink = link_get (platform, ifindex);
	if (!rtnllink) {
		debug ("%s: not found in link cache, ignoring...", ifname);
		return;
	}

	g_hash_table_insert (priv->udev_devices, GINT_TO_POINTER (ifindex),
	                     g_object_ref (udev_device));

	link_init (platform, &link, rtnllink);
	g_signal_emit_by_name (platform, NM_PLATFORM_LINK_ADDED, ifindex, &link);
}

static void
udev_device_removed (NMPlatform *platform,
                     GUdevDevice *udev_device)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int ifindex;

	if (g_udev_device_get_sysfs_attr (udev_device, "ifindex")) {
		ifindex = g_udev_device_get_sysfs_attr_as_int (udev_device, "ifindex");
		g_hash_table_remove (priv->udev_devices, GINT_TO_POINTER (ifindex));
	} else {
		GHashTableIter iter;
		gpointer key, value;

		/* On removal we aren't always be able to read properties like IFINDEX
		 * anymore, as they may have already been removed from sysfs.
		 */
		g_hash_table_iter_init (&iter, priv->udev_devices);
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			if ((GUdevDevice *)value == udev_device) {
				g_hash_table_iter_remove (&iter);
				break;
			}
		}
	}
}

static void
handle_udev_event (GUdevClient *client,
                   const char *action,
                   GUdevDevice *udev_device,
                   gpointer user_data)
{
	NMPlatform *platform = NM_PLATFORM (user_data);
	const char *subsys;

	g_return_if_fail (action != NULL);

	/* A bit paranoid */
	subsys = g_udev_device_get_subsystem (udev_device);
	g_return_if_fail (!g_strcmp0 (subsys, "net"));

	debug ("UDEV event: action '%s' subsys '%s' device '%s'",
	       action, subsys, g_udev_device_get_name (udev_device));

	if (!strcmp (action, "add"))
		udev_device_added (platform, udev_device);
	if (!strcmp (action, "remove"))
		udev_device_removed (platform, udev_device);
}

/******************************************************************/

static void
nm_linux_platform_init (NMLinuxPlatform *platform)
{
}

static gboolean
setup (NMPlatform *platform)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	const char *udev_subsys[] = { "net", NULL };
	GUdevEnumerator *enumerator;
	GList *devices, *iter;
	int channel_flags;
	gboolean status;
	int nle;

	/* Initialize netlink socket for requests */
	priv->nlh = setup_socket (FALSE, platform);
	g_assert (priv->nlh);
	debug ("Netlink socket for requests established: %d", nl_socket_get_local_port (priv->nlh));

	/* Initialize netlink socket for events */
	priv->nlh_event = setup_socket (TRUE, platform);
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
			NULL);
	g_assert (!nle);
	debug ("Netlink socket for events established: %d", nl_socket_get_local_port (priv->nlh_event));

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

	/* Allocate netlink caches */
	rtnl_link_alloc_cache (priv->nlh, AF_UNSPEC, &priv->link_cache);
	rtnl_addr_alloc_cache (priv->nlh, &priv->address_cache);
	rtnl_route_alloc_cache (priv->nlh, AF_UNSPEC, 0, &priv->route_cache);
	g_assert (priv->link_cache && priv->address_cache && priv->route_cache);

	/* Set up udev monitoring */
	priv->udev_client = g_udev_client_new (udev_subsys);
	g_signal_connect (priv->udev_client, "uevent", G_CALLBACK (handle_udev_event), platform);
	priv->udev_devices = g_hash_table_new_full (NULL, NULL, NULL, g_object_unref);

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

	return TRUE;
}

static void
nm_linux_platform_finalize (GObject *object)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (object);

	/* Free netlink resources */
	g_source_remove (priv->event_id);
	g_io_channel_unref (priv->event_channel);
	nl_socket_free (priv->nlh);
	nl_socket_free (priv->nlh_event);
	nl_cache_free (priv->link_cache);
	nl_cache_free (priv->address_cache);
	nl_cache_free (priv->route_cache);

	g_object_unref (priv->udev_client);
	g_hash_table_unref (priv->udev_devices);

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
	object_class->finalize = nm_linux_platform_finalize;

	platform_class->setup = setup;

	platform_class->sysctl_set = sysctl_set;
	platform_class->sysctl_get = sysctl_get;

	platform_class->link_get_all = link_get_all;
	platform_class->link_add = link_add;
	platform_class->link_delete = link_delete;
	platform_class->link_get_ifindex = link_get_ifindex;
	platform_class->link_get_name = link_get_name;
	platform_class->link_get_type = link_get_type;
	platform_class->link_get_type_name = link_get_type_name;

	platform_class->link_set_up = link_set_up;
	platform_class->link_set_down = link_set_down;
	platform_class->link_set_arp = link_set_arp;
	platform_class->link_set_noarp = link_set_noarp;
	platform_class->link_is_up = link_is_up;
	platform_class->link_is_connected = link_is_connected;
	platform_class->link_uses_arp = link_uses_arp;

	platform_class->link_get_address = link_get_address;
	platform_class->link_set_address = link_set_address;
	platform_class->link_get_mtu = link_get_mtu;
	platform_class->link_set_mtu = link_set_mtu;

	platform_class->link_supports_carrier_detect = link_supports_carrier_detect;
	platform_class->link_supports_vlans = link_supports_vlans;

	platform_class->link_enslave = link_enslave;
	platform_class->link_release = link_release;
	platform_class->link_get_master = link_get_master;
	platform_class->master_set_option = master_set_option;
	platform_class->master_get_option = master_get_option;
	platform_class->slave_set_option = slave_set_option;
	platform_class->slave_get_option = slave_get_option;

	platform_class->vlan_add = vlan_add;
	platform_class->vlan_get_info = vlan_get_info;
	platform_class->vlan_set_ingress_map = vlan_set_ingress_map;
	platform_class->vlan_set_egress_map = vlan_set_egress_map;

	platform_class->infiniband_partition_add = infiniband_partition_add;

	platform_class->veth_get_properties = veth_get_properties;
	platform_class->tun_get_properties = tun_get_properties;
	platform_class->macvlan_get_properties = macvlan_get_properties;
	platform_class->gre_get_properties = gre_get_properties;

	platform_class->ip4_address_get_all = ip4_address_get_all;
	platform_class->ip6_address_get_all = ip6_address_get_all;
	platform_class->ip4_address_add = ip4_address_add;
	platform_class->ip6_address_add = ip6_address_add;
	platform_class->ip4_address_delete = ip4_address_delete;
	platform_class->ip6_address_delete = ip6_address_delete;
	platform_class->ip4_address_exists = ip4_address_exists;
	platform_class->ip6_address_exists = ip6_address_exists;

	platform_class->ip4_route_get_all = ip4_route_get_all;
	platform_class->ip6_route_get_all = ip6_route_get_all;
	platform_class->ip4_route_add = ip4_route_add;
	platform_class->ip6_route_add = ip6_route_add;
	platform_class->ip4_route_delete = ip4_route_delete;
	platform_class->ip6_route_delete = ip6_route_delete;
	platform_class->ip4_route_exists = ip4_route_exists;
	platform_class->ip6_route_exists = ip6_route_exists;
}
