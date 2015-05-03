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

#if HAVE_LIBNL_INET6_ADDR_GEN_MODE || HAVE_LIBNL_INET6_TOKEN
#include <netlink/route/link/inet6.h>
#if HAVE_LIBNL_INET6_ADDR_GEN_MODE && HAVE_KERNEL_INET6_ADDR_GEN_MODE
#include <linux/if_link.h>
#else
#define IN6_ADDR_GEN_MODE_EUI64 0
#define IN6_ADDR_GEN_MODE_NONE  1
#endif
#endif

#include "gsystem-local-alloc.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"
#include "nm-linux-platform.h"
#include "nm-platform-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "wifi/wifi-utils.h"
#include "wifi/wifi-utils-wext.h"

/* This is only included for the translation of VLAN flags */
#include "nm-setting-vlan.h"

/*********************************************************************************************/

#define _LOG_DOMAIN LOGD_PLATFORM
#define _LOG_PREFIX_NAME "platform-linux"

#define _LOG(level, domain, self, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        const NMLogDomain __domain = (domain); \
        \
        if (nm_logging_enabled (__level, __domain)) { \
            char __prefix[32]; \
            const char *__p_prefix = _LOG_PREFIX_NAME; \
            const void *const __self = (self); \
            \
            if (__self && __self != nm_platform_try_get ()) { \
                g_snprintf (__prefix, sizeof (__prefix), "%s[%p]", _LOG_PREFIX_NAME, __self); \
                __p_prefix = __prefix; \
            } \
            _nm_log (__level, __domain, 0, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     __p_prefix _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END
#define _LOG_LEVEL_ENABLED(level, domain) \
    ( nm_logging_enabled ((level), (domain)) )

#ifdef NM_MORE_LOGGING
#define _LOGT_ENABLED()     _LOG_LEVEL_ENABLED (LOGL_TRACE, _LOG_DOMAIN)
#define _LOGT(...)          _LOG (LOGL_TRACE, _LOG_DOMAIN, platform, __VA_ARGS__)
#else
#define _LOGT_ENABLED()     FALSE
#define _LOGT(...)          G_STMT_START { if (FALSE) { _LOG (LOGL_TRACE, _LOG_DOMAIN, platform, __VA_ARGS__); } } G_STMT_END
#endif

#define _LOGD(...)      _LOG (LOGL_DEBUG, _LOG_DOMAIN, platform, __VA_ARGS__)
#define _LOGI(...)      _LOG (LOGL_INFO , _LOG_DOMAIN, platform, __VA_ARGS__)
#define _LOGW(...)      _LOG (LOGL_WARN , _LOG_DOMAIN, platform, __VA_ARGS__)
#define _LOGE(...)      _LOG (LOGL_ERR  , _LOG_DOMAIN, platform, __VA_ARGS__)

#define debug(...)      _LOG (LOGL_DEBUG, _LOG_DOMAIN, NULL, __VA_ARGS__)
#define warning(...)    _LOG (LOGL_WARN , _LOG_DOMAIN, NULL, __VA_ARGS__)
#define error(...)      _LOG (LOGL_ERR  , _LOG_DOMAIN, NULL, __VA_ARGS__)

static gboolean tun_get_properties_ifname (NMPlatform *platform, const char *ifname, NMPlatformTunProperties *props);

/******************************************************************
 * libnl unility functions and wrappers
 ******************************************************************/

struct libnl_vtable
{
	void *handle;

	int (*f_nl_has_capability) (int capability);
};

static int
_nl_f_nl_has_capability (int capability)
{
	return FALSE;
}

static struct libnl_vtable *
_nl_get_vtable (void)
{
	static struct libnl_vtable vtable;

	if (G_UNLIKELY (!vtable.f_nl_has_capability)) {
		void *handle;

		handle = dlopen ("libnl-3.so.200", RTLD_LAZY | RTLD_NOLOAD);
		if (handle) {
			vtable.handle = handle;
			vtable.f_nl_has_capability = dlsym (handle, "nl_has_capability");
		}

		if (!vtable.f_nl_has_capability)
			vtable.f_nl_has_capability = &_nl_f_nl_has_capability;

		g_return_val_if_fail (vtable.handle, &vtable);
	}

	return &vtable;
}

static gboolean
_nl_has_capability (int capability)
{
	return (_nl_get_vtable ()->f_nl_has_capability) (capability);
}

/* Automatic deallocation of local variables */
#define auto_nl_cache __attribute__((cleanup(put_nl_cache)))
static void
put_nl_cache (void *ptr)
{
	struct nl_cache **cache = ptr;

	if (cache && *cache) {
		nl_cache_free (*cache);
		*cache = NULL;
	}
}

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

/* wrap the libnl alloc functions and abort on out-of-memory*/

static struct nl_addr *
_nm_nl_addr_build (int family, const void *buf, size_t size)
{
	struct nl_addr *addr;

	addr = nl_addr_build (family, (void *) buf, size);
	if (!addr)
		g_error ("nl_addr_build() failed with out of memory");

	return addr;
}

static struct rtnl_link *
_nm_rtnl_link_alloc (int ifindex, const char*name)
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
_nm_rtnl_addr_alloc (int ifindex)
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
_nm_rtnl_route_alloc (void)
{
	struct rtnl_route *rtnlroute = rtnl_route_alloc ();

	if (!rtnlroute)
		g_error ("rtnl_route_alloc() failed with out of memory");
	return rtnlroute;
}

static struct rtnl_nexthop *
_nm_rtnl_route_nh_alloc (void)
{
	struct rtnl_nexthop *nexthop;

	nexthop = rtnl_route_nh_alloc ();
	if (!nexthop)
		g_error ("rtnl_route_nh_alloc () failed with out of memory");
	return nexthop;
}

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

/******************************************************************/

static guint32
_get_expiry (guint32 now_s, guint32 lifetime_s)
{
	gint64 t = ((gint64) now_s) + ((gint64) lifetime_s);

	return MIN (t, NM_PLATFORM_LIFETIME_PERMANENT - 1);
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
 *
 * As we cache the rtnl_addr object we must know the absolute expiries.
 * As a hack, modify the relative timestamps valid and preferred into absolute
 * timestamps of scale nm_utils_get_monotonic_timestamp_s().
 **/
static void
_rtnl_addr_hack_lifetimes_rel_to_abs (struct rtnl_addr *rtnladdr)
{
	guint32 a_valid  = rtnl_addr_get_valid_lifetime (rtnladdr);
	guint32 a_preferred = rtnl_addr_get_preferred_lifetime (rtnladdr);
	guint32 now;

	if (a_valid == NM_PLATFORM_LIFETIME_PERMANENT &&
	    a_preferred == NM_PLATFORM_LIFETIME_PERMANENT)
		return;

	now = (guint32) nm_utils_get_monotonic_timestamp_s ();

	if (a_preferred > a_valid)
		a_preferred = a_valid;

	if (a_valid != NM_PLATFORM_LIFETIME_PERMANENT)
		rtnl_addr_set_valid_lifetime (rtnladdr, _get_expiry (now, a_valid));
	rtnl_addr_set_preferred_lifetime (rtnladdr, _get_expiry (now, a_preferred));
}

/******************************************************************/

#if HAVE_LIBNL_INET6_ADDR_GEN_MODE
static int _support_user_ipv6ll = 0;
#endif

static gboolean
_support_user_ipv6ll_get ()
{
#if HAVE_LIBNL_INET6_ADDR_GEN_MODE
	if (G_UNLIKELY (_support_user_ipv6ll == 0)) {
		_support_user_ipv6ll = -1;
		nm_log_warn (LOGD_PLATFORM, "kernel support for IFLA_INET6_ADDR_GEN_MODE %s", "failed to detect; assume no support");
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
	if (G_UNLIKELY (_support_user_ipv6ll == 0)) {
		uint8_t mode;

		if (rtnl_link_inet6_get_addr_gen_mode ((struct rtnl_link *) rtnl_link, &mode) == 0) {
			_support_user_ipv6ll = 1;
			nm_log_dbg (LOGD_PLATFORM, "kernel support for IFLA_INET6_ADDR_GEN_MODE %s", "detected");
		} else {
			_support_user_ipv6ll = -1;
			nm_log_dbg (LOGD_PLATFORM, "kernel support for IFLA_INET6_ADDR_GEN_MODE %s", "not detected");
		}
	}
#endif
}

/******************************************************************
 * ethtool
 ******************************************************************/

static gboolean
ethtool_get (const char *name, gpointer edata)
{
	struct ifreq ifr;
	int fd;

	if (!name || !*name)
		return FALSE;

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
	gs_free struct ethtool_sset_info *info = NULL;
	gs_free struct ethtool_gstrings *strings = NULL;
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
ethtool_get_driver_info (const char *ifname,
                         char **out_driver_name,
                         char **out_driver_version,
                         char **out_fw_version)
{
	struct ethtool_drvinfo drvinfo = { 0 };

	if (!ifname)
		return FALSE;

	drvinfo.cmd = ETHTOOL_GDRVINFO;
	if (!ethtool_get (ifname, &drvinfo))
		return FALSE;

	if (out_driver_name)
		*out_driver_name = g_strdup (drvinfo.driver);
	if (out_driver_version)
		*out_driver_version = g_strdup (drvinfo.version);
	if (out_fw_version)
		*out_fw_version = g_strdup (drvinfo.fw_version);

	return TRUE;
}

static gboolean
ethtool_get_permanent_address (const char *ifname,
                               guint8 *buf,
                               size_t *length)
{
	gs_free struct ethtool_perm_addr *epaddr = NULL;

	if (!ifname)
		return FALSE;

	epaddr = g_malloc0 (sizeof (*epaddr) + NM_UTILS_HWADDR_LEN_MAX);
	epaddr->cmd = ETHTOOL_GPERMADDR;
	epaddr->size = NM_UTILS_HWADDR_LEN_MAX;

	if (!ethtool_get (ifname, epaddr))
		return FALSE;
	if (!nm_ethernet_address_is_valid (epaddr->data, epaddr->size))
		return FALSE;

	g_assert (epaddr->size <= NM_UTILS_HWADDR_LEN_MAX);
	memcpy (buf, epaddr->data, epaddr->size);
	*length = epaddr->size;
	return TRUE;
}

static gboolean
ethtool_supports_carrier_detect (const char *ifname)
{
	struct ethtool_cmd edata = { .cmd = ETHTOOL_GLINK };

	/* We ignore the result. If the ETHTOOL_GLINK call succeeded, then we
	 * assume the device supports carrier-detect, otherwise we assume it
	 * doesn't.
	 */
	return ethtool_get (ifname, &edata);
}

/******************************************************************
 * NMPlatform types and functions
 ******************************************************************/

typedef enum {
	OBJECT_TYPE_UNKNOWN,
	OBJECT_TYPE_LINK,
	OBJECT_TYPE_IP4_ADDRESS,
	OBJECT_TYPE_IP6_ADDRESS,
	OBJECT_TYPE_IP4_ROUTE,
	OBJECT_TYPE_IP6_ROUTE,
	__OBJECT_TYPE_LAST,
	OBJECT_TYPE_MAX = __OBJECT_TYPE_LAST - 1,
} ObjectType;

/******************************************************************/

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

	GHashTable *wifi_data;

	int support_kernel_extended_ifa_flags;
} NMLinuxPlatformPrivate;

#define NM_LINUX_PLATFORM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_LINUX_PLATFORM, NMLinuxPlatformPrivate))

G_DEFINE_TYPE (NMLinuxPlatform, nm_linux_platform, NM_TYPE_PLATFORM)

static const char *to_string_object (NMPlatform *platform, struct nl_object *obj);
static gboolean _address_match (struct rtnl_addr *addr, int family, int ifindex);
static gboolean _route_match (struct rtnl_route *rtnlroute, int family, int ifindex, gboolean include_proto_kernel);

void
nm_linux_platform_setup (void)
{
	nm_platform_setup (g_object_new (NM_TYPE_LINUX_PLATFORM, NULL));
}

/******************************************************************/

static ObjectType
_nlo_get_object_type (const struct nl_object *object)
{
	const char *type_str;

	if (!object || !(type_str = nl_object_get_type (object)))
		return OBJECT_TYPE_UNKNOWN;

	if (!strcmp (type_str, "route/link"))
		return OBJECT_TYPE_LINK;
	else if (!strcmp (type_str, "route/addr")) {
		switch (rtnl_addr_get_family ((struct rtnl_addr *) object)) {
		case AF_INET:
			return OBJECT_TYPE_IP4_ADDRESS;
		case AF_INET6:
			return OBJECT_TYPE_IP6_ADDRESS;
		default:
			return OBJECT_TYPE_UNKNOWN;
		}
	} else if (!strcmp (type_str, "route/route")) {
		switch (rtnl_route_get_family ((struct rtnl_route *) object)) {
		case AF_INET:
			return OBJECT_TYPE_IP4_ROUTE;
		case AF_INET6:
			return OBJECT_TYPE_IP6_ROUTE;
		default:
			return OBJECT_TYPE_UNKNOWN;
		}
	} else
		return OBJECT_TYPE_UNKNOWN;
}

static void
_nl_link_family_unset (struct nl_object *obj, int *family)
{
	if (!obj || _nlo_get_object_type (obj) != OBJECT_TYPE_LINK)
		*family = AF_UNSPEC;
	else {
		*family = rtnl_link_get_family ((struct rtnl_link *) obj);

		/* Always explicitly set the family to AF_UNSPEC, even if rtnl_link_get_family() might
		 * already return %AF_UNSPEC. The reason is, that %AF_UNSPEC is the default family
		 * and libnl nl_object_identical() function will only succeed, if the family is
		 * explicitly set (which we cannot be sure, unless setting it). */
		rtnl_link_set_family ((struct rtnl_link *) obj, AF_UNSPEC);
	}
}

/* In our link cache, we coerce the family of all link objects to AF_UNSPEC.
 * Thus, before searching for an object, we fixup @needle to have the right
 * id (by resetting the family). */
static struct nl_object *
nm_nl_cache_search (struct nl_cache *cache, struct nl_object *needle)
{
	int family;
	struct nl_object *obj;

	_nl_link_family_unset (needle, &family);
	obj = nl_cache_search (cache, needle);
	if (family != AF_UNSPEC) {
		/* restore the family of the @needle instance. If the family was
		 * unset before, we cannot make it unset again. Thus, in that case
		 * we cannot undo _nl_link_family_unset() entirely. */
		rtnl_link_set_family ((struct rtnl_link *) needle, family);
	}

	return obj;
}

/* Ask the kernel for an object identical (as in nl_cache_identical) to the
 * needle argument. This is a kernel counterpart for nl_cache_search.
 *
 * The returned object must be freed by the caller with nl_object_put().
 */
static struct nl_object *
get_kernel_object (struct nl_sock *sock, struct nl_object *needle)
{
	struct nl_object *object = NULL;
	ObjectType type = _nlo_get_object_type (needle);

	switch (type) {
	case OBJECT_TYPE_LINK:
		{
			int ifindex = rtnl_link_get_ifindex ((struct rtnl_link *) needle);
			const char *name = rtnl_link_get_name ((struct rtnl_link *) needle);
			int nle;

			nle = rtnl_link_get_kernel (sock, ifindex, name, (struct rtnl_link **) &object);
			switch (nle) {
			case -NLE_SUCCESS:
				_support_user_ipv6ll_detect ((struct rtnl_link *) object);
				if (nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM)) {
					name = rtnl_link_get_name ((struct rtnl_link *) object);
					debug ("get_kernel_object for link: %s (%d, family %d)",
					       name ? name : "(unknown)",
					       rtnl_link_get_ifindex ((struct rtnl_link *) object),
					       rtnl_link_get_family ((struct rtnl_link *) object));
				}

				_nl_link_family_unset (object, &nle);
				return object;
			case -NLE_NODEV:
				debug ("get_kernel_object for link %s (%d) had no result",
				       name ? name : "(unknown)", ifindex);
				return NULL;
			default:
				error ("get_kernel_object for link %s (%d) failed: %s (%d)",
				       name ? name : "(unknown)", ifindex, nl_geterror (nle), nle);
				return NULL;
			}
		}
	case OBJECT_TYPE_IP4_ADDRESS:
	case OBJECT_TYPE_IP6_ADDRESS:
	case OBJECT_TYPE_IP4_ROUTE:
	case OBJECT_TYPE_IP6_ROUTE:
		/* Fallback to a one-time cache allocation. */
		{
			struct nl_cache *cache;
			int nle;

			/* FIXME: every time we refresh *one* object, we request an
			 * entire dump. E.g. check_cache_items() gets O(n2) complexitly. */

			nle = nl_cache_alloc_and_fill (
					nl_cache_ops_lookup (nl_object_get_type (needle)),
					sock, &cache);
			if (nle) {
				error ("get_kernel_object for type %d failed: %s (%d)",
				       type, nl_geterror (nle), nle);
				return NULL;
			}

			object = nl_cache_search (cache, needle);

			nl_cache_free (cache);

			if (object && (type == OBJECT_TYPE_IP4_ADDRESS || type == OBJECT_TYPE_IP6_ADDRESS))
				_rtnl_addr_hack_lifetimes_rel_to_abs ((struct rtnl_addr *) object);

			if (object)
				debug ("get_kernel_object for type %d returned %p", type, object);
			else
				debug ("get_kernel_object for type %d had no result", type);
			return object;
		}
	default:
		g_return_val_if_reached (NULL);
		return NULL;
	}
}

/* libnl 3.2 doesn't seem to provide such a generic way to add libnl-route objects. */
static int
add_kernel_object (struct nl_sock *sock, struct nl_object *object)
{
	switch (_nlo_get_object_type (object)) {
	case OBJECT_TYPE_LINK:
		return rtnl_link_add (sock, (struct rtnl_link *) object, NLM_F_CREATE);
	case OBJECT_TYPE_IP4_ADDRESS:
	case OBJECT_TYPE_IP6_ADDRESS:
		return rtnl_addr_add (sock, (struct rtnl_addr *) object, NLM_F_CREATE | NLM_F_REPLACE);
	case OBJECT_TYPE_IP4_ROUTE:
	case OBJECT_TYPE_IP6_ROUTE:
		return rtnl_route_add (sock, (struct rtnl_route *) object, NLM_F_CREATE | NLM_F_REPLACE);
	default:
		g_return_val_if_reached (-NLE_INVAL);
		return -NLE_INVAL;
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
	[IFLA_LINKINFO] = { .type = NLA_NESTED },
};

static struct nla_policy info_data_link_info_policy[IFLA_INFO_MAX + 1] = {
	[IFLA_INFO_DATA] = { .type = NLA_NESTED },
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

static void
_check_support_kernel_extended_ifa_flags_init (NMLinuxPlatformPrivate *priv, struct nl_msg *msg)
{
	struct nlmsghdr *msg_hdr = nlmsg_hdr (msg);

	g_return_if_fail (priv->support_kernel_extended_ifa_flags == 0);
	g_return_if_fail (msg_hdr->nlmsg_type == RTM_NEWADDR);

	/* the extended address flags are only set for AF_INET6 */
	if (((struct ifaddrmsg *) nlmsg_data (msg_hdr))->ifa_family != AF_INET6)
		return;

	/* see if the nl_msg contains the IFA_FLAGS attribute. If it does,
	 * we assume, that the kernel supports extended flags, IFA_F_MANAGETEMPADDR
	 * and IFA_F_NOPREFIXROUTE (they were added together).
	 **/
	priv->support_kernel_extended_ifa_flags =
	    nlmsg_find_attr (msg_hdr, sizeof (struct ifaddrmsg), 8 /* IFA_FLAGS */)
	    ? 1 : -1;
}

static gboolean
check_support_kernel_extended_ifa_flags (NMPlatform *platform)
{
	NMLinuxPlatformPrivate *priv;

	g_return_val_if_fail (NM_IS_LINUX_PLATFORM (platform), FALSE);

	priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	if (priv->support_kernel_extended_ifa_flags == 0) {
		nm_log_warn (LOGD_PLATFORM, "Unable to detect kernel support for extended IFA_FLAGS. Assume no kernel support.");
		priv->support_kernel_extended_ifa_flags = -1;
	}

	return priv->support_kernel_extended_ifa_flags > 0;
}

static gboolean
check_support_user_ipv6ll (NMPlatform *platform)
{
	g_return_val_if_fail (NM_IS_LINUX_PLATFORM (platform), FALSE);

	return _support_user_ipv6ll_get ();
}

/* Object type specific utilities */

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

static NMLinkType
link_extract_type (NMPlatform *platform, struct rtnl_link *rtnllink)
{
	const char *rtnl_type, *ifname;
	int i, arptype;

	if (!rtnllink)
		return NM_LINK_TYPE_NONE;

	rtnl_type = rtnl_link_get_type (rtnllink);
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

			nm_log_dbg (LOGD_PLATFORM, "Failed to read tun properties for interface %d (link flags: %X)",
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

		if (arptype == 256) {
			/* Some s390 CTC-type devices report 256 for the encapsulation type
			 * for some reason, but we need to call them Ethernet.
			 */
			if (!g_strcmp0 (driver, "ctcm"))
				return NM_LINK_TYPE_ETHERNET;
		}

		/* Fallback OVS detection for kernel <= 3.16 */
		if (ethtool_get_driver_info (ifname, &driver, NULL, NULL)) {
			if (!g_strcmp0 (driver, "openvswitch"))
				return NM_LINK_TYPE_OPENVSWITCH;
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

static gboolean
init_link (NMPlatform *platform, NMPlatformLink *info, struct rtnl_link *rtnllink)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GUdevDevice *udev_device;
	const char *name;
	char *tmp;

	g_return_val_if_fail (rtnllink, FALSE);

	name = rtnl_link_get_name (rtnllink);
	memset (info, 0, sizeof (*info));

	info->ifindex = rtnl_link_get_ifindex (rtnllink);
	if (name)
		g_strlcpy (info->name, name, sizeof (info->name));
	else
		info->name[0] = '\0';
	info->type = link_extract_type (platform, rtnllink);
	info->kind = g_intern_string (rtnl_link_get_type (rtnllink));
	info->up = !!(rtnl_link_get_flags (rtnllink) & IFF_UP);
	info->connected = !!(rtnl_link_get_flags (rtnllink) & IFF_LOWER_UP);
	info->arp = !(rtnl_link_get_flags (rtnllink) & IFF_NOARP);
	info->master = rtnl_link_get_master (rtnllink);
	info->parent = rtnl_link_get_link (rtnllink);
	info->mtu = rtnl_link_get_mtu (rtnllink);

	udev_device = g_hash_table_lookup (priv->udev_devices, GINT_TO_POINTER (info->ifindex));
	if (udev_device) {
		info->driver = nmp_utils_udev_get_driver (udev_device);
		info->udi = g_udev_device_get_sysfs_path (udev_device);
		info->initialized = TRUE;
	}

	if (!info->driver)
		info->driver = info->kind;
	if (!info->driver) {
		if (ethtool_get_driver_info (name, &tmp, NULL, NULL)) {
			info->driver = g_intern_string (tmp);
			g_free (tmp);
		}
	}
	if (!info->driver)
		info->driver = "unknown";

	/* Only demand further initialization (udev rules ran, device has
	 * a stable name now) in case udev is running (not in a container). */
	if (   !info->initialized
	    && access ("/sys", W_OK) != 0)
		info->initialized = TRUE;

	return TRUE;
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
	const char *type;

	if (!object)
		return;
	if (strcmp (nl_object_get_type (object), "route/link"))
		return;

	rtnllink = (struct rtnl_link *) object;

	ifindex = rtnl_link_get_ifindex (rtnllink);

	type = rtnl_link_get_type (rtnllink);
	if (!type || (strcmp (type, "bridge") != 0 && strcmp (type, "bond") != 0))
		return;

	for (slave = nl_cache_get_first (priv->link_cache); slave; slave = nl_cache_get_next (slave)) {
		struct rtnl_link *rtnlslave = (struct rtnl_link *) slave;
		if (rtnl_link_get_master (rtnlslave) == ifindex
				&& rtnl_link_get_flags (rtnlslave) & IFF_LOWER_UP)
			return;
	}

	rtnl_link_unset_flags (rtnllink, IFF_LOWER_UP);
}

static guint32
_get_remaining_time (guint32 start_timestamp, guint32 end_timestamp)
{
	/* Return the remaining time between @start_timestamp until @end_timestamp.
	 *
	 * If @end_timestamp is NM_PLATFORM_LIFETIME_PERMANENT, it returns
	 * NM_PLATFORM_LIFETIME_PERMANENT. If @start_timestamp already passed
	 * @end_timestamp it returns 0. Beware, NMPlatformIPAddress treats a @lifetime
	 * of 0 as permanent.
	 */
	if (end_timestamp == NM_PLATFORM_LIFETIME_PERMANENT)
		return NM_PLATFORM_LIFETIME_PERMANENT;
	if (start_timestamp >= end_timestamp)
		return 0;
	return end_timestamp - start_timestamp;
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
_rtnl_addr_last_update_time_to_nm (const struct rtnl_addr *rtnladdr)
{
	guint32 last_update_time = rtnl_addr_get_last_update_time ((struct rtnl_addr *) rtnladdr);
	struct timespec tp;
	gint64 now_nl, now_nm, result;

	/* timestamp is unset. Default to 1. */
	if (!last_update_time)
		return 1;

	/* do all the calculations in milliseconds scale */

	clock_gettime (CLOCK_MONOTONIC, &tp);
	now_nm = nm_utils_get_monotonic_timestamp_ms ();
	now_nl = (((gint64) tp.tv_sec) * ((gint64) 1000)) +
	         (tp.tv_nsec / (NM_UTILS_NS_PER_SECOND/1000));

	result = now_nm - (now_nl - _timestamp_nl_to_ms (last_update_time, now_nl));

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

static void
_init_ip_address_lifetime (NMPlatformIPAddress *address, const struct rtnl_addr *rtnladdr)
{
	guint32 a_valid = rtnl_addr_get_valid_lifetime ((struct rtnl_addr *) rtnladdr);
	guint32 a_preferred = rtnl_addr_get_preferred_lifetime ((struct rtnl_addr *) rtnladdr);

	/* the meaning of the valid and preferred lifetimes is different from the
	 * original meaning. See _rtnl_addr_hack_lifetimes_rel_to_abs().
	 * Beware: this function expects hacked rtnl_addr objects.
	 */

	if (a_valid == NM_PLATFORM_LIFETIME_PERMANENT &&
	    a_preferred == NM_PLATFORM_LIFETIME_PERMANENT) {
		address->timestamp = 0;
		address->lifetime = NM_PLATFORM_LIFETIME_PERMANENT;
		address->preferred = NM_PLATFORM_LIFETIME_PERMANENT;
		return;
	}

	/* The valies are hacked and absolute expiry times. They must
	 * be positive and preferred<=valid. */
	g_assert (a_preferred <= a_valid &&
	          a_valid > 0 &&
	          a_preferred > 0);

	if (a_valid <= 1) {
		/* Since we want to have positive @timestamp and @valid != 0,
		 * we must handle this case special. */
		address->timestamp = 1;
		address->lifetime = 1; /* Extend the lifetime by one second */
		address->preferred = 0; /* no longer preferred. */
		return;
	}

	/* _rtnl_addr_last_update_time_to_nm() might be wrong, so don't rely on
	 * timestamp to have any meaning beyond anchoring the relative durations
	 * @lifetime and @preferred.
	 */
	address->timestamp = _rtnl_addr_last_update_time_to_nm (rtnladdr);

	/* We would expect @timestamp to be less then @a_valid. Just to be sure,
	 * fix it up. */
	address->timestamp = MIN (address->timestamp, a_valid - 1);
	address->lifetime = _get_remaining_time (address->timestamp, a_valid);
	address->preferred = _get_remaining_time (address->timestamp, a_preferred);
}

static gboolean
init_ip4_address (NMPlatformIP4Address *address, struct rtnl_addr *rtnladdr)
{
	struct nl_addr *nladdr = rtnl_addr_get_local (rtnladdr);
	struct nl_addr *nlpeer = rtnl_addr_get_peer (rtnladdr);
	const char *label;

	g_return_val_if_fail (nladdr, FALSE);

	memset (address, 0, sizeof (*address));

	address->source = NM_IP_CONFIG_SOURCE_KERNEL;
	address->ifindex = rtnl_addr_get_ifindex (rtnladdr);
	address->plen = rtnl_addr_get_prefixlen (rtnladdr);
	_init_ip_address_lifetime ((NMPlatformIPAddress *) address, rtnladdr);
	if (!nladdr || nl_addr_get_len (nladdr) != sizeof (address->address)) {
		g_return_val_if_reached (FALSE);
		return FALSE;
	}
	memcpy (&address->address, nl_addr_get_binary_addr (nladdr), sizeof (address->address));
	if (nlpeer) {
		if (nl_addr_get_len (nlpeer) != sizeof (address->peer_address)) {
			g_return_val_if_reached (FALSE);
			return FALSE;
		}
		memcpy (&address->peer_address, nl_addr_get_binary_addr (nlpeer), sizeof (address->peer_address));
	}
	label = rtnl_addr_get_label (rtnladdr);
	/* Check for ':'; we're only interested in labels used as interface aliases */
	if (label && strchr (label, ':'))
		g_strlcpy (address->label, label, sizeof (address->label));

	return TRUE;
}

static gboolean
init_ip6_address (NMPlatformIP6Address *address, struct rtnl_addr *rtnladdr)
{
	struct nl_addr *nladdr = rtnl_addr_get_local (rtnladdr);
	struct nl_addr *nlpeer = rtnl_addr_get_peer (rtnladdr);

	memset (address, 0, sizeof (*address));

	address->source = NM_IP_CONFIG_SOURCE_KERNEL;
	address->ifindex = rtnl_addr_get_ifindex (rtnladdr);
	address->plen = rtnl_addr_get_prefixlen (rtnladdr);
	_init_ip_address_lifetime ((NMPlatformIPAddress *) address, rtnladdr);
	address->flags = rtnl_addr_get_flags (rtnladdr);
	if (!nladdr || nl_addr_get_len (nladdr) != sizeof (address->address)) {
		g_return_val_if_reached (FALSE);
		return FALSE;
	}
	memcpy (&address->address, nl_addr_get_binary_addr (nladdr), sizeof (address->address));
	if (nlpeer) {
		if (nl_addr_get_len (nlpeer) != sizeof (address->peer_address)) {
			g_return_val_if_reached (FALSE);
			return FALSE;
		}
		memcpy (&address->peer_address, nl_addr_get_binary_addr (nlpeer), sizeof (address->peer_address));
	}

	return TRUE;
}

static guint
source_to_rtprot (NMIPConfigSource source)
{
	switch (source) {
	case NM_IP_CONFIG_SOURCE_UNKNOWN:
		return RTPROT_UNSPEC;
	case NM_IP_CONFIG_SOURCE_KERNEL:
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
rtprot_to_source (guint rtprot)
{
	switch (rtprot) {
	case RTPROT_UNSPEC:
		return NM_IP_CONFIG_SOURCE_UNKNOWN;
	case RTPROT_REDIRECT:
	case RTPROT_KERNEL:
		return NM_IP_CONFIG_SOURCE_KERNEL;
	case RTPROT_RA:
		return NM_IP_CONFIG_SOURCE_RDISC;
	case RTPROT_DHCP:
		return NM_IP_CONFIG_SOURCE_DHCP;

	default:
		return NM_IP_CONFIG_SOURCE_USER;
	}
}

static gboolean
_rtnl_route_is_default (const struct rtnl_route *rtnlroute)
{
	struct nl_addr *dst;

	return    rtnlroute
	       && (dst = rtnl_route_get_dst ((struct rtnl_route *) rtnlroute))
	       && nl_addr_get_prefixlen (dst) == 0;
}

static gboolean
init_ip4_route (NMPlatformIP4Route *route, struct rtnl_route *rtnlroute)
{
	struct nl_addr *dst, *gw;
	struct rtnl_nexthop *nexthop;

	memset (route, 0, sizeof (*route));

	/* Multi-hop routes not supported. */
	if (rtnl_route_get_nnexthops (rtnlroute) != 1)
		return FALSE;

	nexthop = rtnl_route_nexthop_n (rtnlroute, 0);
	dst = rtnl_route_get_dst (rtnlroute);
	gw = rtnl_route_nh_get_gateway (nexthop);

	route->ifindex = rtnl_route_nh_get_ifindex (nexthop);
	route->plen = nl_addr_get_prefixlen (dst);
	/* Workaround on previous workaround for libnl default route prefixlen bug. */
	if (nl_addr_get_len (dst)) {
		if (nl_addr_get_len (dst) != sizeof (route->network)) {
			g_return_val_if_reached (FALSE);
			return FALSE;
		}
		memcpy (&route->network, nl_addr_get_binary_addr (dst), sizeof (route->network));
	}
	if (gw) {
		if (nl_addr_get_len (gw) != sizeof (route->network)) {
			g_return_val_if_reached (FALSE);
			return FALSE;
		}
		memcpy (&route->gateway, nl_addr_get_binary_addr (gw), sizeof (route->gateway));
	}
	route->metric = rtnl_route_get_priority (rtnlroute);
	rtnl_route_get_metric (rtnlroute, RTAX_ADVMSS, &route->mss);
	route->source = rtprot_to_source (rtnl_route_get_protocol (rtnlroute));

	return TRUE;
}

static gboolean
init_ip6_route (NMPlatformIP6Route *route, struct rtnl_route *rtnlroute)
{
	struct nl_addr *dst, *gw;
	struct rtnl_nexthop *nexthop;

	memset (route, 0, sizeof (*route));

	/* Multi-hop routes not supported. */
	if (rtnl_route_get_nnexthops (rtnlroute) != 1)
		return FALSE;

	nexthop = rtnl_route_nexthop_n (rtnlroute, 0);
	dst = rtnl_route_get_dst (rtnlroute);
	gw = rtnl_route_nh_get_gateway (nexthop);

	route->ifindex = rtnl_route_nh_get_ifindex (nexthop);
	route->plen = nl_addr_get_prefixlen (dst);
	/* Workaround on previous workaround for libnl default route prefixlen bug. */
	if (nl_addr_get_len (dst)) {
		if (nl_addr_get_len (dst) != sizeof (route->network)) {
			g_return_val_if_reached (FALSE);
			return FALSE;
		}
		memcpy (&route->network, nl_addr_get_binary_addr (dst), sizeof (route->network));
	}
	if (gw) {
		if (nl_addr_get_len (gw) != sizeof (route->network)) {
			g_return_val_if_reached (FALSE);
			return FALSE;
		}
		memcpy (&route->gateway, nl_addr_get_binary_addr (gw), sizeof (route->gateway));
	}
	route->metric = rtnl_route_get_priority (rtnlroute);
	rtnl_route_get_metric (rtnlroute, RTAX_ADVMSS, &route->mss);
	route->source = rtprot_to_source (rtnl_route_get_protocol (rtnlroute));

	return TRUE;
}

static char to_string_buffer[255];

#define SET_AND_RETURN_STRING_BUFFER(...) \
	G_STMT_START { \
		g_snprintf (to_string_buffer, sizeof (to_string_buffer), ## __VA_ARGS__); \
		return to_string_buffer; \
	} G_STMT_END

static const char *
to_string_link (NMPlatform *platform, struct rtnl_link *obj)
{
	NMPlatformLink pl_obj;

	if (init_link (platform, &pl_obj, obj))
		return nm_platform_link_to_string (&pl_obj);
	SET_AND_RETURN_STRING_BUFFER ("(invalid link %p)", obj);
}

static const char *
to_string_ip4_address (struct rtnl_addr *obj)
{
	NMPlatformIP4Address pl_obj;

	if (init_ip4_address (&pl_obj, obj))
		return nm_platform_ip4_address_to_string (&pl_obj);
	SET_AND_RETURN_STRING_BUFFER ("(invalid ip4 address %p)", obj);
}

static const char *
to_string_ip6_address (struct rtnl_addr *obj)
{
	NMPlatformIP6Address pl_obj;

	if (init_ip6_address (&pl_obj, obj))
		return nm_platform_ip6_address_to_string (&pl_obj);
	SET_AND_RETURN_STRING_BUFFER ("(invalid ip6 address %p)", obj);
}

static const char *
to_string_ip4_route (struct rtnl_route *obj)
{
	NMPlatformIP4Route pl_obj;

	if (init_ip4_route (&pl_obj, obj))
		return nm_platform_ip4_route_to_string (&pl_obj);
	SET_AND_RETURN_STRING_BUFFER ("(invalid ip4 route %p)", obj);
}

static const char *
to_string_ip6_route (struct rtnl_route *obj)
{
	NMPlatformIP6Route pl_obj;

	if (init_ip6_route (&pl_obj, obj))
		return nm_platform_ip6_route_to_string (&pl_obj);
	SET_AND_RETURN_STRING_BUFFER ("(invalid ip6 route %p)", obj);
}

static const char *
to_string_object_with_type (NMPlatform *platform, struct nl_object *obj, ObjectType type)
{
	switch (type) {
	case OBJECT_TYPE_LINK:
		return to_string_link (platform, (struct rtnl_link *) obj);
	case OBJECT_TYPE_IP4_ADDRESS:
		return to_string_ip4_address ((struct rtnl_addr *) obj);
	case OBJECT_TYPE_IP6_ADDRESS:
		return to_string_ip6_address ((struct rtnl_addr *) obj);
	case OBJECT_TYPE_IP4_ROUTE:
		return to_string_ip4_route ((struct rtnl_route *) obj);
	case OBJECT_TYPE_IP6_ROUTE:
		return to_string_ip6_route ((struct rtnl_route *) obj);
	default:
		SET_AND_RETURN_STRING_BUFFER ("(unknown netlink object %p)", obj);
	}
}

static const char *
to_string_object (NMPlatform *platform, struct nl_object *obj)
{
	return to_string_object_with_type (platform, obj, _nlo_get_object_type (obj));
}

#undef SET_AND_RETURN_STRING_BUFFER

/******************************************************************/

/* Object and cache manipulation */

static const char *signal_by_type_and_status[OBJECT_TYPE_MAX + 1] = {
	[OBJECT_TYPE_LINK]        = NM_PLATFORM_SIGNAL_LINK_CHANGED,
	[OBJECT_TYPE_IP4_ADDRESS] = NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED,
	[OBJECT_TYPE_IP6_ADDRESS] = NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED,
	[OBJECT_TYPE_IP4_ROUTE]   = NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED,
	[OBJECT_TYPE_IP6_ROUTE]   = NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED,
};

static struct nl_cache *
choose_cache_by_type (NMPlatform *platform, ObjectType object_type)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);

	switch (object_type) {
	case OBJECT_TYPE_LINK:
		return priv->link_cache;
	case OBJECT_TYPE_IP4_ADDRESS:
	case OBJECT_TYPE_IP6_ADDRESS:
		return priv->address_cache;
	case OBJECT_TYPE_IP4_ROUTE:
	case OBJECT_TYPE_IP6_ROUTE:
		return priv->route_cache;
	default:
		g_return_val_if_reached (NULL);
		return NULL;
	}
}

static struct nl_cache *
choose_cache (NMPlatform *platform, struct nl_object *object)
{
	return choose_cache_by_type (platform, _nlo_get_object_type (object));
}

static gboolean
object_has_ifindex (struct nl_object *object, int ifindex)
{
	switch (_nlo_get_object_type (object)) {
	case OBJECT_TYPE_IP4_ADDRESS:
	case OBJECT_TYPE_IP6_ADDRESS:
		return ifindex == rtnl_addr_get_ifindex ((struct rtnl_addr *) object);
	case OBJECT_TYPE_IP4_ROUTE:
	case OBJECT_TYPE_IP6_ROUTE:
		{
			struct rtnl_route *rtnlroute = (struct rtnl_route *) object;
			struct rtnl_nexthop *nexthop;

			if (rtnl_route_get_nnexthops (rtnlroute) != 1)
				return FALSE;
			nexthop = rtnl_route_nexthop_n (rtnlroute, 0);

			return ifindex == rtnl_route_nh_get_ifindex (nexthop);
		}
	default:
		g_assert_not_reached ();
	}
}

static gboolean refresh_object (NMPlatform *platform, struct nl_object *object, gboolean removed, NMPlatformReason reason);

static void
check_cache_items (NMPlatform *platform, struct nl_cache *cache, int ifindex)
{
	auto_nl_cache struct nl_cache *cloned_cache = nl_cache_clone (cache);
	struct nl_object *object;
	GPtrArray *objects_to_refresh = g_ptr_array_new_with_free_func ((GDestroyNotify) nl_object_put);
	guint i;

	for (object = nl_cache_get_first (cloned_cache); object; object = nl_cache_get_next (object)) {
		if (object_has_ifindex (object, ifindex)) {
			nl_object_get (object);
			g_ptr_array_add (objects_to_refresh, object);
		}
	}

	for (i = 0; i < objects_to_refresh->len; i++)
		refresh_object (platform, objects_to_refresh->pdata[i], TRUE, NM_PLATFORM_REASON_CACHE_CHECK);

	g_ptr_array_free (objects_to_refresh, TRUE);
}

static void
announce_object (NMPlatform *platform, const struct nl_object *object, NMPlatformSignalChangeType change_type, NMPlatformReason reason)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	ObjectType object_type = _nlo_get_object_type (object);
	const char *sig = signal_by_type_and_status[object_type];

	switch (object_type) {
	case OBJECT_TYPE_LINK:
		{
			struct rtnl_link *rtnl_link = (struct rtnl_link *) object;
			NMPlatformLink device;

			if (!init_link (platform, &device, rtnl_link))
				return;

			/* Link deletion or setting down is sometimes accompanied by address
			 * and/or route deletion.
			 *
			 * More precisely, kernel removes routes when interface goes !IFF_UP and
			 * removes both addresses and routes when interface is removed.
			 */
			switch (change_type) {
			case NM_PLATFORM_SIGNAL_CHANGED:
				if (!device.connected)
					check_cache_items (platform, priv->route_cache, device.ifindex);
				break;
			case NM_PLATFORM_SIGNAL_REMOVED:
				check_cache_items (platform, priv->address_cache, device.ifindex);
				check_cache_items (platform, priv->route_cache, device.ifindex);
				g_hash_table_remove (priv->wifi_data, GINT_TO_POINTER (device.ifindex));
				break;
			default:
				break;
			}

			g_signal_emit_by_name (platform, sig, device.ifindex, &device, change_type, reason);
		}
		return;
	case OBJECT_TYPE_IP4_ADDRESS:
		{
			NMPlatformIP4Address address;

			/* Address deletion is sometimes accompanied by route deletion. We need to
			 * check all routes belonging to the same interface.
			 */
			switch (change_type) {
			case NM_PLATFORM_SIGNAL_REMOVED:
				check_cache_items (platform,
				                   priv->route_cache,
				                   rtnl_addr_get_ifindex ((struct rtnl_addr *) object));
				break;
			default:
				break;
			}

			if (!_address_match ((struct rtnl_addr *) object, AF_INET, 0)) {
				nm_log_dbg (LOGD_PLATFORM, "skip announce unmatching IP4 address %s", to_string_ip4_address ((struct rtnl_addr *) object));
				return;
			}
			if (!init_ip4_address (&address, (struct rtnl_addr *) object))
				return;
			g_signal_emit_by_name (platform, sig, address.ifindex, &address, change_type, reason);
		}
		return;
	case OBJECT_TYPE_IP6_ADDRESS:
		{
			NMPlatformIP6Address address;

			if (!_address_match ((struct rtnl_addr *) object, AF_INET6, 0)) {
				nm_log_dbg (LOGD_PLATFORM, "skip announce unmatching IP6 address %s", to_string_ip6_address ((struct rtnl_addr *) object));
				return;
			}
			if (!init_ip6_address (&address, (struct rtnl_addr *) object))
				return;
			g_signal_emit_by_name (platform, sig, address.ifindex, &address, change_type, reason);
		}
		return;
	case OBJECT_TYPE_IP4_ROUTE:
		{
			NMPlatformIP4Route route;

			if (reason == _NM_PLATFORM_REASON_CACHE_CHECK_INTERNAL)
				return;

			if (!_route_match ((struct rtnl_route *) object, AF_INET, 0, FALSE)) {
				nm_log_dbg (LOGD_PLATFORM, "skip announce unmatching IP4 route %s", to_string_ip4_route ((struct rtnl_route *) object));
				return;
			}
			if (init_ip4_route (&route, (struct rtnl_route *) object))
				g_signal_emit_by_name (platform, sig, route.ifindex, &route, change_type, reason);
		}
		return;
	case OBJECT_TYPE_IP6_ROUTE:
		{
			NMPlatformIP6Route route;

			if (reason == _NM_PLATFORM_REASON_CACHE_CHECK_INTERNAL)
				return;

			if (!_route_match ((struct rtnl_route *) object, AF_INET6, 0, FALSE)) {
				nm_log_dbg (LOGD_PLATFORM, "skip announce unmatching IP6 route %s", to_string_ip6_route ((struct rtnl_route *) object));
				return;
			}
			if (init_ip6_route (&route, (struct rtnl_route *) object))
				g_signal_emit_by_name (platform, sig, route.ifindex, &route, change_type, reason);
		}
		return;
	default:
		g_return_if_reached ();
	}
}

static struct nl_object * build_rtnl_link (int ifindex, const char *name, NMLinkType type);

static gboolean
refresh_object (NMPlatform *platform, struct nl_object *object, gboolean removed, NMPlatformReason reason)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	auto_nl_object struct nl_object *cached_object = NULL;
	auto_nl_object struct nl_object *kernel_object = NULL;
	struct nl_cache *cache;
	int nle;

	cache = choose_cache (platform, object);
	cached_object = nm_nl_cache_search (cache, object);
	kernel_object = get_kernel_object (priv->nlh, object);

	if (removed) {
		if (kernel_object)
			return TRUE;

		/* Only announce object if it was still in the cache. */
		if (cached_object) {
			nl_cache_remove (cached_object);

			announce_object (platform, cached_object, NM_PLATFORM_SIGNAL_REMOVED, reason);
		}
	} else {
		ObjectType type;

		if (!kernel_object)
			return FALSE;

		/* Unsupported object types should never have reached the caches */
		type = _nlo_get_object_type (kernel_object);
		g_assert (type != OBJECT_TYPE_UNKNOWN);

		hack_empty_master_iff_lower_up (platform, kernel_object);

		if (cached_object)
			nl_cache_remove (cached_object);
		nle = nl_cache_add (cache, kernel_object);
		if (nle) {
			nm_log_dbg (LOGD_PLATFORM, "refresh_object(reason %d) failed during nl_cache_add with %d", reason, nle);
			return FALSE;
		}

		announce_object (platform, kernel_object, cached_object ? NM_PLATFORM_SIGNAL_CHANGED : NM_PLATFORM_SIGNAL_ADDED, reason);

		if (type == OBJECT_TYPE_LINK) {
			int kernel_master = rtnl_link_get_master ((struct rtnl_link *) kernel_object);
			int cached_master = cached_object ? rtnl_link_get_master ((struct rtnl_link *) cached_object) : 0;
			const char *orig_link_type = rtnl_link_get_type ((struct rtnl_link *) object);
			const char *kernel_link_type = rtnl_link_get_type ((struct rtnl_link *) kernel_object);
			struct nl_object *master_object;

			/* Refresh the master device (even on enslave/release) */
			if (kernel_master) {
				master_object = build_rtnl_link (kernel_master, NULL, NM_LINK_TYPE_NONE);
				refresh_object (platform, master_object, FALSE, NM_PLATFORM_REASON_INTERNAL);
				nl_object_put (master_object);
			}
			if (cached_master && cached_master != kernel_master) {
				master_object = build_rtnl_link (cached_master, NULL, NM_LINK_TYPE_NONE);
				refresh_object (platform, master_object, FALSE, NM_PLATFORM_REASON_INTERNAL);
				nl_object_put (master_object);
			}

			/* Ensure the existing link type matches the refreshed link type */
			if (orig_link_type && kernel_link_type && strcmp (orig_link_type, kernel_link_type)) {
				platform->error = NM_PLATFORM_ERROR_WRONG_TYPE;
				return FALSE;
			}
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
	int nle;

	g_return_val_if_fail (object, FALSE);

	nle = add_kernel_object (priv->nlh, object);

	/* NLE_EXIST is considered equivalent to success to avoid race conditions. You
	 * never know when something sends an identical object just before
	 * NetworkManager.
	 */
	switch (nle) {
	case -NLE_SUCCESS:
	case -NLE_EXIST:
		break;
	default:
		error ("Netlink error adding %s: %s", to_string_object (platform, object),  nl_geterror (nle));
		if (nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM)) {
			char buf[256];
			struct nl_dump_params dp = {
				.dp_type = NL_DUMP_DETAILS,
				.dp_buf = buf,
				.dp_buflen = sizeof (buf),
			};

			nl_object_dump (object, &dp);
			buf[sizeof (buf) - 1] = '\0';
			debug ("netlink object:\n%s", buf);
		}
		return FALSE;
	}

	return refresh_object (platform, object, FALSE, NM_PLATFORM_REASON_INTERNAL);
}

/* Decreases the reference count if @obj for convenience */
static gboolean
delete_object (NMPlatform *platform, struct nl_object *object, gboolean do_refresh_object)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int object_type;
	int nle;
	gboolean result = FALSE;

	object_type = _nlo_get_object_type (object);
	g_return_val_if_fail (object_type != OBJECT_TYPE_UNKNOWN, FALSE);

	switch (object_type) {
	case OBJECT_TYPE_LINK:
		nle = rtnl_link_delete (priv->nlh, (struct rtnl_link *) object);
		break;
	case OBJECT_TYPE_IP4_ADDRESS:
	case OBJECT_TYPE_IP6_ADDRESS:
		nle = rtnl_addr_delete (priv->nlh, (struct rtnl_addr *) object, 0);
		break;
	case OBJECT_TYPE_IP4_ROUTE:
	case OBJECT_TYPE_IP6_ROUTE:
		nle = rtnl_route_delete (priv->nlh, (struct rtnl_route *) object, 0);
		break;
	default:
		g_assert_not_reached ();
	}

	switch (nle) {
	case -NLE_SUCCESS:
		break;
	case -NLE_OBJ_NOTFOUND:
		debug("delete_object failed with \"%s\" (%d), meaning the object was already removed",
		      nl_geterror (nle), nle);
		break;
	case -NLE_FAILURE:
		if (object_type == OBJECT_TYPE_IP6_ADDRESS) {
			/* On RHEL7 kernel, deleting a non existing address fails with ENXIO (which libnl maps to NLE_FAILURE) */
			debug("delete_object for address failed with \"%s\" (%d), meaning the address was already removed",
			      nl_geterror (nle), nle);
			break;
		}
		goto DEFAULT;
	case -NLE_NOADDR:
		if (object_type == OBJECT_TYPE_IP4_ADDRESS || object_type == OBJECT_TYPE_IP6_ADDRESS) {
			debug("delete_object for address failed with \"%s\" (%d), meaning the address was already removed",
			      nl_geterror (nle), nle);
			break;
		}
		goto DEFAULT;
	DEFAULT:
	default:
		error ("Netlink error deleting %s: %s (%d)", to_string_object (platform, object), nl_geterror (nle), nle);
		goto out;
	}

	if (do_refresh_object)
		refresh_object (platform, object, TRUE, NM_PLATFORM_REASON_INTERNAL);

	result = TRUE;

out:
	nl_object_put (object);
	return result;
}

static void
ref_object (struct nl_object *obj, void *data)
{
	struct nl_object **out = data;

	nl_object_get (obj);
	*out = obj;
}

static gboolean
_rtnl_addr_timestamps_equal_fuzzy (guint32 ts1, guint32 ts2)
{
	guint32 diff;

	if (ts1 == ts2)
		return TRUE;
	if (ts1 == NM_PLATFORM_LIFETIME_PERMANENT ||
	    ts2 == NM_PLATFORM_LIFETIME_PERMANENT)
		return FALSE;

	/** accept the timestamps as equal if they are within two seconds. */
	diff = ts1 > ts2 ? ts1 - ts2 : ts2 - ts1;
	return diff <= 2;
}

static gboolean
nm_nl_object_diff (ObjectType type, struct nl_object *_a, struct nl_object *_b)
{
	if (nl_object_diff (_a, _b)) {
		/* libnl thinks objects are different*/
		return TRUE;
	}

#if HAVE_LIBNL_INET6_TOKEN
	/* libnl ignores PROTINFO changes in object without AF assigned */
	if (type == OBJECT_TYPE_LINK) {
		struct rtnl_addr *a = (struct rtnl_addr *) _a;
		struct rtnl_addr *b = (struct rtnl_addr *) _b;
		auto_nl_addr struct nl_addr *token_a = NULL;
		auto_nl_addr struct nl_addr *token_b = NULL;

		if (rtnl_link_inet6_get_token ((struct rtnl_link *) a, &token_a) != 0)
			token_a = NULL;
		if (rtnl_link_inet6_get_token ((struct rtnl_link *) b, &token_b) != 0)
			token_b = NULL;

		if (token_a && token_b) {
			if (nl_addr_get_family (token_a) == AF_INET6 &&
			    nl_addr_get_family (token_b) == AF_INET6 &&
			    nl_addr_get_len (token_a) == sizeof (struct in6_addr) &&
			    nl_addr_get_len (token_b) == sizeof (struct in6_addr) &&
			    memcmp (nl_addr_get_binary_addr (token_a),
			            nl_addr_get_binary_addr (token_b),
			            sizeof (struct in6_addr))) {
				/* Token changed */
				return TRUE;
			}
		} else if (token_a != token_b) {
			/* Token added or removed (?). */
			return TRUE;
		}
	}
#endif

	if (type == OBJECT_TYPE_IP4_ADDRESS || type == OBJECT_TYPE_IP6_ADDRESS) {
		struct rtnl_addr *a = (struct rtnl_addr *) _a;
		struct rtnl_addr *b = (struct rtnl_addr *) _b;

		/* libnl nl_object_diff() ignores differences in timestamp. Let's care about
		 * them (if they are large enough).
		 *
		 * Note that these valid and preferred timestamps are absolute, after
		 * _rtnl_addr_hack_lifetimes_rel_to_abs(). */
		if (   !_rtnl_addr_timestamps_equal_fuzzy (rtnl_addr_get_preferred_lifetime (a),
							  rtnl_addr_get_preferred_lifetime (b))
		    || !_rtnl_addr_timestamps_equal_fuzzy (rtnl_addr_get_valid_lifetime (a),
							  rtnl_addr_get_valid_lifetime (b)))
			return TRUE;
	}

	return FALSE;
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
	ObjectType type;

	event = nlmsg_hdr (msg)->nlmsg_type;

	if (priv->support_kernel_extended_ifa_flags == 0 && event == RTM_NEWADDR) {
		/* if kernel support for extended ifa flags is still undecided, use the opportunity
		 * now and use @msg to decide it. This saves a blocking net link request.
		 **/
		_check_support_kernel_extended_ifa_flags_init (priv, msg);
	}

	nl_msg_parse (msg, ref_object, &object);
	if (!object)
		return NL_OK;

	type = _nlo_get_object_type (object);

	if (type == OBJECT_TYPE_LINK)
		_support_user_ipv6ll_detect ((struct rtnl_link *) object);

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM)) {
		if (type == OBJECT_TYPE_LINK) {
			const char *name = rtnl_link_get_name ((struct rtnl_link *) object);

			debug ("netlink event (type %d) for link: %s (%d, family %d)",
			       event, name ? name : "(unknown)",
			       rtnl_link_get_ifindex ((struct rtnl_link *) object),
			       rtnl_link_get_family ((struct rtnl_link *) object));
		} else
			debug ("netlink event (type %d)", event);
	}

	cache = choose_cache_by_type (platform, type);
	cached_object = nm_nl_cache_search (cache, object);
	kernel_object = get_kernel_object (priv->nlh, object);

	hack_empty_master_iff_lower_up (platform, kernel_object);

	/* Removed object */
	switch (event) {
	case RTM_DELLINK:
	case RTM_DELADDR:
	case RTM_DELROUTE:
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
		announce_object (platform, cached_object, NM_PLATFORM_SIGNAL_REMOVED, NM_PLATFORM_REASON_EXTERNAL);
		if (event == RTM_DELLINK) {
			int ifindex = rtnl_link_get_ifindex ((struct rtnl_link *) cached_object);

			g_hash_table_remove (priv->udev_devices, GINT_TO_POINTER (ifindex));
		}

		return NL_OK;
	case RTM_NEWLINK:
	case RTM_NEWADDR:
	case RTM_NEWROUTE:
		/* Ignore inconsistent addition or change (kernel will send a good one)
		 *
		 * Quick sequence of RTM_NEWLINK notifications can be occasionally
		 * collapsed to just one addition or deletion, depending of whether we
		 * already have the object in cache.
		 */
		if (!kernel_object)
			return NL_OK;

		/* Ignore unsupported object types (e.g. AF_PHONET family addresses) */
		if (type == OBJECT_TYPE_UNKNOWN)
			return NL_OK;

		/* Handle external addition */
		if (!cached_object) {
			nle = nl_cache_add (cache, kernel_object);
			if (nle) {
				error ("netlink cache error: %s", nl_geterror (nle));
				return NL_OK;
			}
			announce_object (platform, kernel_object, NM_PLATFORM_SIGNAL_ADDED, NM_PLATFORM_REASON_EXTERNAL);
			return NL_OK;
		}
		/* Ignore non-change
		 *
		 * This also catches notifications for internal addition or change, unless
		 * another action occured very soon after it.
		 */
		if (!nm_nl_object_diff (type, kernel_object, cached_object))
			return NL_OK;

		/* Handle external change */
		nl_cache_remove (cached_object);
		nle = nl_cache_add (cache, kernel_object);
		if (nle) {
			error ("netlink cache error: %s", nl_geterror (nle));
			return NL_OK;
		}
		announce_object (platform, kernel_object, NM_PLATFORM_SIGNAL_CHANGED, NM_PLATFORM_REASON_EXTERNAL);

		return NL_OK;
	default:
		error ("Unknown netlink event: %d", event);
		return NL_OK;
	}
}

/******************************************************************/

static void
_log_dbg_sysctl_set_impl (const char *path, const char *value)
{
	GError *error = NULL;
	char *contents, *contents_escaped;
	char *value_escaped = g_strescape (value, NULL);

	if (!g_file_get_contents (path, &contents, NULL, &error)) {
		debug ("sysctl: setting '%s' to '%s' (current value cannot be read: %s)", path, value_escaped, error->message);
		g_clear_error (&error);
	} else {
		g_strstrip (contents);
		contents_escaped = g_strescape (contents, NULL);
		if (strcmp (contents, value) == 0)
			debug ("sysctl: setting '%s' to '%s' (current value is identical)", path, value_escaped);
		else
			debug ("sysctl: setting '%s' to '%s' (current value is '%s')", path, value_escaped, contents_escaped);
		g_free (contents);
		g_free (contents_escaped);
	}
	g_free (value_escaped);
}

#define _log_dbg_sysctl_set(path, value) \
	G_STMT_START { \
		if (nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM)) { \
			_log_dbg_sysctl_set_impl (path, value); \
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
			debug ("sysctl: failed to open '%s': (%d) %s",
			       path, errno, strerror (errno));
		} else {
			error ("sysctl: failed to open '%s': (%d) %s",
			       path, errno, strerror (errno));
		}
		return FALSE;
	}

	_log_dbg_sysctl_set (path, value);

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
				debug ("sysctl: interrupted, will try again");
				continue;
			}
			break;
		}
	}
	if (nwrote == -1 && errno != EEXIST) {
		error ("sysctl: failed to set '%s' to '%s': (%d) %s",
		       path, value, errno, strerror (errno));
	} else if (nwrote < len) {
		error ("sysctl: failed to set '%s' to '%s' after three attempts",
		       path, value);
	}

	g_free (actual);
	close (fd);
	return (nwrote == len);
}

static GHashTable *sysctl_get_prev_values;

static void
_log_dbg_sysctl_get_impl (const char *path, const char *contents)
{
	const char *prev_value = NULL;

	if (!sysctl_get_prev_values)
		sysctl_get_prev_values = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	else
		prev_value = g_hash_table_lookup (sysctl_get_prev_values, path);

	if (prev_value) {
		if (strcmp (prev_value, contents) != 0) {
			char *contents_escaped = g_strescape (contents, NULL);
			char *prev_value_escaped = g_strescape (prev_value, NULL);

			debug ("sysctl: reading '%s': '%s' (changed from '%s' on last read)", path, contents_escaped, prev_value_escaped);
			g_free (contents_escaped);
			g_free (prev_value_escaped);
			g_hash_table_insert (sysctl_get_prev_values, g_strdup (path), g_strdup (contents));
		}
	} else {
		char *contents_escaped = g_strescape (contents, NULL);

		debug ("sysctl: reading '%s': '%s'", path, contents_escaped);
		g_free (contents_escaped);
		g_hash_table_insert (sysctl_get_prev_values, g_strdup (path), g_strdup (contents));
	}
}

#define _log_dbg_sysctl_get(path, contents) \
	G_STMT_START { \
		if (nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM)) { \
			_log_dbg_sysctl_get_impl (path, contents); \
		} else if (sysctl_get_prev_values) { \
			g_hash_table_destroy (sysctl_get_prev_values); \
			sysctl_get_prev_values = NULL; \
		} \
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
			debug ("error reading %s: %s", path, error->message);
		else
			error ("error reading %s: %s", path, error->message);
		g_clear_error (&error);
		return NULL;
	}

	g_strstrip (contents);

	_log_dbg_sysctl_get (path, contents);

	return contents;
}

/******************************************************************/

static GArray *
link_get_all (NMPlatform *platform)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GArray *links = g_array_sized_new (FALSE, FALSE, sizeof (NMPlatformLink), nl_cache_nitems (priv->link_cache));
	NMPlatformLink device;
	struct nl_object *object;

	for (object = nl_cache_get_first (priv->link_cache); object; object = nl_cache_get_next (object)) {
		if (init_link (platform, &device, (struct rtnl_link *) object))
			g_array_append_val (links, device);
	}

	return links;
}

static gboolean
_nm_platform_link_get (NMPlatform *platform, int ifindex, NMPlatformLink *l)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	auto_nl_object struct rtnl_link *rtnllink = NULL;
	NMPlatformLink tmp = { 0 };

	rtnllink = rtnl_link_get (priv->link_cache, ifindex);
	return (rtnllink && init_link (platform, l ? l : &tmp, rtnllink));
}

static gboolean
_nm_platform_link_get_by_address (NMPlatform *platform,
                                  gconstpointer address,
                                  size_t length,
                                  NMPlatformLink *l)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	struct nl_object *object;

	for (object = nl_cache_get_first (priv->link_cache); object; object = nl_cache_get_next (object)) {
		struct rtnl_link *rtnl_link = (struct rtnl_link *) object;
		struct nl_addr *nladdr;
		gconstpointer hwaddr;

		nladdr = rtnl_link_get_addr (rtnl_link);
		if (nladdr && (nl_addr_get_len (nladdr) == length)) {
			hwaddr = nl_addr_get_binary_addr (nladdr);
			if (hwaddr && memcmp (hwaddr, address, length) == 0)
				return init_link (platform, l, rtnl_link);
		}
	}
	return FALSE;
}

static struct nl_object *
build_rtnl_link (int ifindex, const char *name, NMLinkType type)
{
	struct rtnl_link *rtnllink;
	int nle;

	rtnllink = _nm_rtnl_link_alloc (ifindex, name);
	if (type) {
		nle = rtnl_link_set_type (rtnllink, nm_link_type_to_rtnl_type_string (type));
		g_assert (!nle);
	}
	return (struct nl_object *) rtnllink;
}

static gboolean
link_get_by_name (NMPlatform *platform, const char *name, NMPlatformLink *out_link)
{
	int ifindex;

	g_return_val_if_fail (name != NULL, FALSE);

	if (out_link) {
		ifindex = nm_platform_link_get_ifindex (platform, name);
		g_return_val_if_fail (ifindex > 0, FALSE);
		return _nm_platform_link_get (platform, ifindex, out_link);
	}
	return TRUE;
}

static gboolean
link_add (NMPlatform *platform,
          const char *name,
          NMLinkType type,
          const void *address,
          size_t address_len,
          NMPlatformLink *out_link)
{
	struct nl_object *l;

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

	debug ("link: add link '%s' of type '%s' (%d)",
	       name, nm_link_type_to_string (type), (int) type);

	l = build_rtnl_link (0, name, type);

	g_assert ( (address != NULL) ^ (address_len == 0) );
	if (address) {
		auto_nl_addr struct nl_addr *nladdr = _nm_nl_addr_build (AF_LLC, address, address_len);

		rtnl_link_set_addr ((struct rtnl_link *) l, nladdr);
	}

	if (!add_object (platform, l))
		return FALSE;

	return link_get_by_name (platform, name, out_link);
}

static struct rtnl_link *
link_get (NMPlatform *platform, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	struct rtnl_link *rtnllink = rtnl_link_get (priv->link_cache, ifindex);

	if (!rtnllink) {
		platform->error = NM_PLATFORM_ERROR_NOT_FOUND;
		return NULL;
	}

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
	g_return_val_if_fail (rtnl_link_get_ifindex (change) > 0, FALSE);

	nle = rtnl_link_change (priv->nlh, rtnllink, change, 0);

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
	case -NLE_EXIST:
		break;
	case -NLE_OBJ_NOTFOUND:
		error ("Firmware not found for changing link %s; Netlink error: %s)", to_string_link (platform, change), nl_geterror (nle));
		platform->error = NM_PLATFORM_ERROR_NO_FIRMWARE;
		return FALSE;
	default:
		error ("Netlink error changing link %s: %s", to_string_link (platform, change), nl_geterror (nle));
		return FALSE;
	}

	return refresh_object (platform, (struct nl_object *) rtnllink, FALSE, NM_PLATFORM_REASON_INTERNAL);
}

static gboolean
link_delete (NMPlatform *platform, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	auto_nl_object struct rtnl_link *rtnllink = rtnl_link_get (priv->link_cache, ifindex);

	if (!rtnllink) {
		platform->error = NM_PLATFORM_ERROR_NOT_FOUND;
		return FALSE;
	}

	return delete_object (platform, build_rtnl_link (ifindex, NULL, NM_LINK_TYPE_NONE), TRUE);
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

	return link_extract_type (platform, rtnllink);
}

static const char *
link_get_type_name (NMPlatform *platform, int ifindex)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);
	NMLinkType link_type;
	const char *l;

	if (!rtnllink)
		return NULL;

	link_type = link_extract_type (platform, rtnllink);
	if (link_type != NM_LINK_TYPE_UNKNOWN) {
		/* We could detect the @link_type. In this case the function returns
		 * our internel module names, which differs from rtnl_link_get_type():
		 *   - NM_LINK_TYPE_INFINIBAND (gives "infiniband", instead of "ipoib")
		 *   - NM_LINK_TYPE_TAP (gives "tap", instead of "tun").
		 * Note that this functions is only used by NMDeviceGeneric to
		 * set type_description. */
		return nm_link_type_to_string (link_type);
	}

	/* Link type not detected. Fallback to rtnl_link_get_type()/IFLA_INFO_KIND. */
	l = rtnl_link_get_type (rtnllink);
	return l ? g_intern_string (l) : "unknown";
}

static gboolean
link_get_unmanaged (NMPlatform *platform, int ifindex, gboolean *managed)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GUdevDevice *udev_device = g_hash_table_lookup (priv->udev_devices, GINT_TO_POINTER (ifindex));

	if (udev_device && g_udev_device_get_property (udev_device, "NM_UNMANAGED")) {
		*managed = g_udev_device_get_property_as_boolean (udev_device, "NM_UNMANAGED");
		return TRUE;
	}

	return FALSE;
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
link_refresh (NMPlatform *platform, int ifindex)
{
	auto_nl_object struct rtnl_link *rtnllink = _nm_rtnl_link_alloc (ifindex, NULL);

	return refresh_object (platform, (struct nl_object *) rtnllink, FALSE, NM_PLATFORM_REASON_EXTERNAL);
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
	auto_nl_object struct rtnl_link *change = _nm_rtnl_link_alloc (ifindex, NULL);

	if (value)
		rtnl_link_set_flags (change, flags);
	else
		rtnl_link_unset_flags (change, flags);

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM)) {
		char buf[512];

		rtnl_link_flags2str (flags, buf, sizeof (buf));
		debug ("link: change %d: flags %s '%s' (%d)", ifindex, value ? "set" : "unset", buf, flags);
	}

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
link_get_ipv6_token (NMPlatform *platform, int ifindex, NMUtilsIPv6IfaceId *iid)
{
#if HAVE_LIBNL_INET6_TOKEN
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);
	struct nl_addr *nladdr;
	struct in6_addr *addr;

	if (rtnllink &&
	    (rtnl_link_inet6_get_token (rtnllink, &nladdr)) == 0) {
		if (nl_addr_get_family (nladdr) != AF_INET6 ||
		    nl_addr_get_len (nladdr) != sizeof (struct in6_addr)) {
			nl_addr_put (nladdr);
			return FALSE;
		}

		addr = nl_addr_get_binary_addr (nladdr);
		iid->id_u8[7] = addr->s6_addr[15];
		iid->id_u8[6] = addr->s6_addr[14];
		iid->id_u8[5] = addr->s6_addr[13];
		iid->id_u8[4] = addr->s6_addr[12];
		iid->id_u8[3] = addr->s6_addr[11];
		iid->id_u8[2] = addr->s6_addr[10];
		iid->id_u8[1] = addr->s6_addr[9];
		iid->id_u8[0] = addr->s6_addr[8];
		nl_addr_put (nladdr);
		return TRUE;
	}
#endif
	return FALSE;
}

static gboolean
link_get_user_ipv6ll_enabled (NMPlatform *platform, int ifindex)
{
#if HAVE_LIBNL_INET6_ADDR_GEN_MODE
	if (_support_user_ipv6ll_get ()) {
		auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);
		uint8_t mode = 0;

		if (rtnllink) {
			if (rtnl_link_inet6_get_addr_gen_mode (rtnllink, &mode) != 0) {
				/* Default to "disabled" on error */
				return FALSE;
			}
			return mode == IN6_ADDR_GEN_MODE_NONE;
		}
	}
#endif
	return FALSE;
}

static gboolean
link_set_user_ipv6ll_enabled (NMPlatform *platform, int ifindex, gboolean enabled)
{
#if HAVE_LIBNL_INET6_ADDR_GEN_MODE
	if (_support_user_ipv6ll_get ()) {
		auto_nl_object struct rtnl_link *change = _nm_rtnl_link_alloc (ifindex, NULL);
		guint8 mode = enabled ? IN6_ADDR_GEN_MODE_NONE : IN6_ADDR_GEN_MODE_EUI64;
		char buf[32];

		rtnl_link_inet6_set_addr_gen_mode (change, mode);
		debug ("link: change %d: set IPv6 address generation mode to %s",
		       ifindex, rtnl_link_inet6_addrgenmode2str (mode, buf, sizeof (buf)));
		return link_change (platform, ifindex, change);
	}
#endif
	return FALSE;
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
	const char *name = nm_platform_link_get_name (platform, ifindex);

	if (!name)
		return FALSE;

	/* We use netlink for the actual carrier detection, but netlink can't tell
	 * us whether the device actually supports carrier detection in the first
	 * place. We assume any device that does implements one of these two APIs.
	 */
	return ethtool_supports_carrier_detect (name) || supports_mii_carrier_detect (name);
}

static gboolean
link_supports_vlans (NMPlatform *platform, int ifindex)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);
	const char *name = nm_platform_link_get_name (platform, ifindex);
	gs_free struct ethtool_gfeatures *features = NULL;
	int idx, block, bit, size;

	/* Only ARPHRD_ETHER links can possibly support VLANs. */
	if (!rtnllink || rtnl_link_get_arptype (rtnllink) != ARPHRD_ETHER)
		return FALSE;

	if (!name)
		return FALSE;

	idx = ethtool_get_stringset_index (name, ETH_SS_FEATURES, "vlan-challenged");
	if (idx == -1) {
		debug ("vlan-challenged ethtool feature does not exist?");
		return FALSE;
	}

	block = idx /  32;
	bit = idx % 32;
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
	auto_nl_object struct rtnl_link *change = _nm_rtnl_link_alloc (ifindex, NULL);
	auto_nl_addr struct nl_addr *nladdr = _nm_nl_addr_build (AF_LLC, address, length);

	rtnl_link_set_addr (change, nladdr);

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM)) {
		char *mac = nm_utils_hwaddr_ntoa (address, length);

		debug ("link: change %d: address %s (%lu bytes)", ifindex, mac, (unsigned long) length);
		g_free (mac);
	}

	return link_change (platform, ifindex, change);
}

static gconstpointer
link_get_address (NMPlatform *platform, int ifindex, size_t *length)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);
	struct nl_addr *nladdr;
	size_t l = 0;
	gconstpointer a = NULL;

	if (rtnllink &&
	    (nladdr = rtnl_link_get_addr (rtnllink))) {
		l = nl_addr_get_len (nladdr);
		if (l > NM_UTILS_HWADDR_LEN_MAX) {
			if (length)
				*length = 0;
			g_return_val_if_reached (NULL);
		} else if (l > 0)
			a = nl_addr_get_binary_addr (nladdr);
	}

	if (length)
		*length = l;
	return a;
}

static gboolean
link_get_permanent_address (NMPlatform *platform,
                            int ifindex,
                            guint8 *buf,
                            size_t *length)
{
	return ethtool_get_permanent_address (nm_platform_link_get_name (platform, ifindex), buf, length);
}

static gboolean
link_set_mtu (NMPlatform *platform, int ifindex, guint32 mtu)
{
	auto_nl_object struct rtnl_link *change = _nm_rtnl_link_alloc (ifindex, NULL);

	rtnl_link_set_mtu (change, mtu);
	debug ("link: change %d: mtu %lu", ifindex, (unsigned long)mtu);

	return link_change (platform, ifindex, change);
}

static guint32
link_get_mtu (NMPlatform *platform, int ifindex)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, ifindex);

	return rtnllink ? rtnl_link_get_mtu (rtnllink) : 0;
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
	rtnl_link_vlan_set_flags (rtnllink, kernel_flags);

	debug ("link: add vlan '%s', parent %d, vlan id %d, flags %X (native: %X)",
	       name, parent, vlan_id, (unsigned int) vlan_flags, kernel_flags);

	if (!add_object (platform, object))
		return FALSE;

	return link_get_by_name (platform, name, out_link);
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
	/* We have to use link_get() because a "blank" rtnl_link won't have the
	 * right data structures to be able to call rtnl_link_vlan_set_ingress_map()
	 * on it. (Likewise below in vlan_set_egress_map().)
	 */
	auto_nl_object struct rtnl_link *change = link_get (platform, ifindex);

	if (!change)
		return FALSE;
	rtnl_link_vlan_set_ingress_map (change, from, to);

	debug ("link: change %d: vlan ingress map %d -> %d", ifindex, from, to);

	return link_change (platform, ifindex, change);
}

static gboolean
vlan_set_egress_map (NMPlatform *platform, int ifindex, int from, int to)
{
	auto_nl_object struct rtnl_link *change = link_get (platform, ifindex);

	if (!change)
		return FALSE;
	rtnl_link_vlan_set_egress_map (change, from, to);

	debug ("link: change %d: vlan egress map %d -> %d", ifindex, from, to);

	return link_change (platform, ifindex, change);
}

static gboolean
link_enslave (NMPlatform *platform, int master, int slave)
{
	auto_nl_object struct rtnl_link *change = _nm_rtnl_link_alloc (slave, NULL);

	rtnl_link_set_master (change, master);
	debug ("link: change %d: enslave to master %d", slave, master);

	return link_change (platform, slave, change);
}

static gboolean
link_release (NMPlatform *platform, int master, int slave)
{
	return link_enslave (platform, 0, slave);
}

static int
link_get_master (NMPlatform *platform, int slave)
{
	auto_nl_object struct rtnl_link *rtnllink = link_get (platform, slave);

	return rtnllink ? rtnl_link_get_master (rtnllink) : 0;
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
	switch (link_get_type (platform, master)) {
	case NM_LINK_TYPE_BRIDGE:
		return "bridge";
	case NM_LINK_TYPE_BOND:
		return "bonding";
	default:
		g_return_val_if_reached (NULL);
		return NULL;
	}
}

static const char *
slave_category (NMPlatform *platform, int slave)
{
	int master = link_get_master (platform, slave);

	if (master <= 0) {
		platform->error = NM_PLATFORM_ERROR_NOT_SLAVE;
		return NULL;
	}

	switch (link_get_type (platform, master)) {
	case NM_LINK_TYPE_BRIDGE:
		return "brport";
	default:
		g_return_val_if_reached (NULL);
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

static gboolean
infiniband_partition_add (NMPlatform *platform, int parent, int p_key, NMPlatformLink *out_link)
{
	const char *parent_name;
	char *path, *id;
	gboolean success;

	parent_name = nm_platform_link_get_name (platform, parent);
	g_return_val_if_fail (parent_name != NULL, FALSE);

	path = g_strdup_printf ("/sys/class/net/%s/create_child", ASSERT_VALID_PATH_COMPONENT (parent_name));
	id = g_strdup_printf ("0x%04x", p_key);
	success = nm_platform_sysctl_set (platform, path, id);
	g_free (id);
	g_free (path);

	if (success) {
		gs_free char *ifname = g_strdup_printf ("%s.%04x", parent_name, p_key);
		auto_nl_object struct rtnl_link *rtnllink = NULL;

		rtnllink = (struct rtnl_link *) build_rtnl_link (0, ifname, NM_LINK_TYPE_INFINIBAND);
		success = refresh_object (platform, (struct nl_object *) rtnllink, FALSE, NM_PLATFORM_REASON_INTERNAL);
		if (success)
			success = link_get_by_name (platform, ifname, out_link);
	}

	return success;
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
	auto_nl_object struct rtnl_link *rtnllink = NULL;
	IpoibInfo info = { -1, NULL };

	rtnllink = link_get (platform, ifindex);
	if (!rtnllink)
		return FALSE;

	if (parent)
		*parent = rtnl_link_get_link (rtnllink);

	if (nm_rtnl_link_parse_info_data (priv->nlh,
	                                  ifindex,
	                                  infiniband_info_data_parser,
	                                  &info) != 0) {
		const char *iface = rtnl_link_get_name (rtnllink);
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

static gboolean
veth_get_properties (NMPlatform *platform, int ifindex, NMPlatformVethProperties *props)
{
	const char *ifname;
	gs_free struct ethtool_stats *stats = NULL;
	int peer_ifindex_stat;

	ifname = nm_platform_link_get_name (platform, ifindex);
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
	auto_nl_object struct rtnl_link *rtnllink = NULL;
	int err;

	rtnllink = link_get (platform, ifindex);
	if (!rtnllink)
		return FALSE;

	props->parent_ifindex = rtnl_link_get_link (rtnllink);

	err = nm_rtnl_link_parse_info_data (priv->nlh, ifindex,
	                                    macvlan_info_data_parser, props);
	if (err != 0) {
		warning ("(%s) could not read properties: %s",
		         rtnl_link_get_name (rtnllink), nl_geterror (err));
	}
	return (err == 0);
}

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

	err = nm_rtnl_link_parse_info_data (priv->nlh, ifindex,
	                                    vxlan_info_data_parser, props);
	if (err != 0) {
		warning ("(%s) could not read properties: %s",
		         link_get_name (platform, ifindex), nl_geterror (err));
	}
	return (err == 0);
}

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

	err = nm_rtnl_link_parse_info_data (priv->nlh, ifindex,
	                                    gre_info_data_parser, props);
	if (err != 0) {
		warning ("(%s) could not read properties: %s",
		         link_get_name (platform, ifindex), nl_geterror (err));
	}
	return (err == 0);
}

static WifiData *
wifi_get_wifi_data (NMPlatform *platform, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	WifiData *wifi_data;

	wifi_data = g_hash_table_lookup (priv->wifi_data, GINT_TO_POINTER (ifindex));
	if (!wifi_data) {
		NMLinkType type;
		const char *ifname;

		type = link_get_type (platform, ifindex);
		ifname = link_get_name (platform, ifindex);

		if (type == NM_LINK_TYPE_WIFI)
			wifi_data = wifi_utils_init (ifname, ifindex, TRUE);
		else if (type == NM_LINK_TYPE_OLPC_MESH) {
			/* The kernel driver now uses nl80211, but we force use of WEXT because
			 * the cfg80211 interactions are not quite ready to support access to
			 * mesh control through nl80211 just yet.
			 */
#if HAVE_WEXT
			wifi_data = wifi_wext_init (ifname, ifindex, FALSE);
#endif
		}

		if (wifi_data)
			g_hash_table_insert (priv->wifi_data, GINT_TO_POINTER (ifindex), wifi_data);
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

static gboolean
link_get_wake_on_lan (NMPlatform *platform, int ifindex)
{
	NMLinkType type = link_get_type (platform, ifindex);

	if (type == NM_LINK_TYPE_ETHERNET) {
		struct ethtool_wolinfo wol;

		memset (&wol, 0, sizeof (wol));
		wol.cmd = ETHTOOL_GWOL;
		if (!ethtool_get (link_get_name (platform, ifindex), &wol))
			return FALSE;

		return wol.wolopts != 0;
	} else if (type == NM_LINK_TYPE_WIFI) {
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
	return ethtool_get_driver_info (nm_platform_link_get_name (platform, ifindex),
	                                out_driver_name,
	                                out_driver_version,
	                                out_fw_version);
}

/******************************************************************/

static gboolean
_address_match (struct rtnl_addr *addr, int family, int ifindex)
{
	g_return_val_if_fail (addr, FALSE);

	return rtnl_addr_get_family (addr) == family &&
	       (ifindex == 0 || rtnl_addr_get_ifindex (addr) == ifindex);
}

static GArray *
ip4_address_get_all (NMPlatform *platform, int ifindex)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GArray *addresses;
	NMPlatformIP4Address address;
	struct nl_object *object;

	addresses = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP4Address));

	for (object = nl_cache_get_first (priv->address_cache); object; object = nl_cache_get_next (object)) {
		if (_address_match ((struct rtnl_addr *) object, AF_INET, ifindex)) {
			if (init_ip4_address (&address, (struct rtnl_addr *) object))
				g_array_append_val (addresses, address);
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

	addresses = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP6Address));

	for (object = nl_cache_get_first (priv->address_cache); object; object = nl_cache_get_next (object)) {
		if (_address_match ((struct rtnl_addr *) object, AF_INET6, ifindex)) {
			if (init_ip6_address (&address, (struct rtnl_addr *) object))
				g_array_append_val (addresses, address);
		}
	}

	return addresses;
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
	auto_nl_object struct rtnl_addr *rtnladdr = _nm_rtnl_addr_alloc (ifindex);
	struct rtnl_addr *rtnladdr_copy;
	int addrlen = family == AF_INET ? sizeof (in_addr_t) : sizeof (struct in6_addr);
	auto_nl_addr struct nl_addr *nladdr = _nm_nl_addr_build (family, addr, addrlen);
	int nle;

	/* IP address */
	nle = rtnl_addr_set_local (rtnladdr, nladdr);
	if (nle) {
		error ("build_rtnl_addr(): rtnl_addr_set_local failed with %s (%d)", nl_geterror (nle), nle);
		return NULL;
	}

	/* Tighten scope (IPv4 only) */
	if (family == AF_INET && ip4_is_link_local (addr))
		rtnl_addr_set_scope (rtnladdr, rtnl_str2scope ("link"));

	/* IPv4 Broadcast address */
	if (family == AF_INET) {
		in_addr_t bcast;
		auto_nl_addr struct nl_addr *bcaddr = NULL;

		bcast = *((in_addr_t *) addr) | ~nm_utils_ip4_prefix_to_netmask (plen);
		bcaddr = _nm_nl_addr_build (family, &bcast, addrlen);
		g_assert (bcaddr);
		rtnl_addr_set_broadcast (rtnladdr, bcaddr);
	}

	/* Peer/point-to-point address */
	if (peer_addr) {
		auto_nl_addr struct nl_addr *nlpeer = _nm_nl_addr_build (family, peer_addr, addrlen);

		nle = rtnl_addr_set_peer (rtnladdr, nlpeer);
		if (nle && nle != -NLE_AF_NOSUPPORT) {
			/* IPv6 doesn't support peer addresses yet */
			error ("build_rtnl_addr(): rtnl_addr_set_peer failed with %s (%d)", nl_geterror (nle), nle);
			return NULL;
		}
	}

	rtnl_addr_set_prefixlen (rtnladdr, plen);
	if (lifetime) {
		/* note that here we set the relative timestamps (ticking from *now*).
		 * Contrary to the rtnl_addr objects from our cache, which have absolute
		 * timestamps (see _rtnl_addr_hack_lifetimes_rel_to_abs()).
		 *
		 * This is correct, because we only use build_rtnl_addr() for
		 * add_object(), delete_object() and cache search (ip_address_exists). */
		rtnl_addr_set_valid_lifetime (rtnladdr, lifetime);
		rtnl_addr_set_preferred_lifetime (rtnladdr, preferred);
	}
	if (flags) {
		if ((flags & ~0xFF) && !check_support_kernel_extended_ifa_flags (platform)) {
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

static gboolean
ip4_address_add (NMPlatform *platform,
                 int ifindex,
                 in_addr_t addr,
                 in_addr_t peer_addr,
                 int plen,
                 guint32 lifetime,
                 guint32 preferred,
                 const char *label)
{
	return add_object (platform, build_rtnl_addr (platform, AF_INET, ifindex, &addr,
	                                              peer_addr ? &peer_addr : NULL,
	                                              plen, lifetime, preferred, 0,
	                                              label));
}

static gboolean
ip6_address_add (NMPlatform *platform,
                 int ifindex,
                 struct in6_addr addr,
                 struct in6_addr peer_addr,
                 int plen,
                 guint32 lifetime,
                 guint32 preferred,
                 guint flags)
{
	return add_object (platform, build_rtnl_addr (platform, AF_INET6, ifindex, &addr,
	                                              IN6_IS_ADDR_UNSPECIFIED (&peer_addr) ? NULL : &peer_addr,
	                                              plen, lifetime, preferred, flags,
	                                              NULL));
}

static gboolean
ip4_address_delete (NMPlatform *platform, int ifindex, in_addr_t addr, int plen, in_addr_t peer_address)
{
	return delete_object (platform, build_rtnl_addr (platform, AF_INET, ifindex, &addr, peer_address ? &peer_address : NULL, plen, 0, 0, 0, NULL), TRUE);
}

static gboolean
ip6_address_delete (NMPlatform *platform, int ifindex, struct in6_addr addr, int plen)
{
	return delete_object (platform, build_rtnl_addr (platform, AF_INET6, ifindex, &addr, NULL, plen, 0, 0, 0, NULL), TRUE);
}

static gboolean
ip_address_exists (NMPlatform *platform, int family, int ifindex, gconstpointer addr, int plen)
{
	auto_nl_object struct nl_object *object = build_rtnl_addr (platform, family, ifindex, addr, NULL, plen, 0, 0, 0, NULL);
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

static gboolean
ip4_check_reinstall_device_route (NMPlatform *platform, int ifindex, const NMPlatformIP4Address *address, guint32 device_route_metric)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	NMPlatformIP4Address addr_candidate;
	NMPlatformIP4Route route_candidate;
	struct nl_object *object;
	guint32 device_network;

	for (object = nl_cache_get_first (priv->address_cache); object; object = nl_cache_get_next (object)) {
		if (_address_match ((struct rtnl_addr *) object, AF_INET, 0)) {
			if (init_ip4_address (&addr_candidate, (struct rtnl_addr *) object))
				if (   addr_candidate.plen == address->plen
				    && addr_candidate.address == address->address) {
					/* If we already have the same address installed on any interface,
					 * we back off.
					 * Perform this check first, as we expect to have significantly less
					 * addresses to search. */
					return FALSE;
				}
		}
	}

	device_network = nm_utils_ip4_address_clear_host_address (address->address, address->plen);

	for (object = nl_cache_get_first (priv->route_cache); object; object = nl_cache_get_next (object)) {
		if (_route_match ((struct rtnl_route *) object, AF_INET, 0, TRUE)) {
			if (init_ip4_route (&route_candidate, (struct rtnl_route *) object)) {
				if (   route_candidate.network == device_network
				    && route_candidate.plen == address->plen
				    && (   route_candidate.metric == 0
				        || route_candidate.metric == device_route_metric)) {
					/* There is already any route with metric 0 or the metric we want to install
					 * for the same subnet. */
					return FALSE;
				}
			}
		}
	}

	return TRUE;
}

/******************************************************************/

static gboolean
_route_match (struct rtnl_route *rtnlroute, int family, int ifindex, gboolean include_proto_kernel)
{
	struct rtnl_nexthop *nexthop;

	g_return_val_if_fail (rtnlroute, FALSE);

	if (rtnl_route_get_type (rtnlroute) != RTN_UNICAST ||
	    rtnl_route_get_table (rtnlroute) != RT_TABLE_MAIN ||
	    rtnl_route_get_tos (rtnlroute) != 0 ||
	    (!include_proto_kernel && rtnl_route_get_protocol (rtnlroute) == RTPROT_KERNEL) ||
	    rtnl_route_get_family (rtnlroute) != family ||
	    rtnl_route_get_nnexthops (rtnlroute) != 1 ||
	    rtnl_route_get_flags (rtnlroute) & RTM_F_CLONED)
		return FALSE;

	if (ifindex == 0)
		return TRUE;

	nexthop = rtnl_route_nexthop_n (rtnlroute, 0);
	return rtnl_route_nh_get_ifindex (nexthop) == ifindex;
}

static GArray *
ip4_route_get_all (NMPlatform *platform, int ifindex, NMPlatformGetRouteMode mode)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GArray *routes;
	NMPlatformIP4Route route;
	struct nl_object *object;

	g_return_val_if_fail (NM_IN_SET (mode, NM_PLATFORM_GET_ROUTE_MODE_ALL, NM_PLATFORM_GET_ROUTE_MODE_NO_DEFAULT, NM_PLATFORM_GET_ROUTE_MODE_ONLY_DEFAULT), NULL);

	routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP4Route));

	for (object = nl_cache_get_first (priv->route_cache); object; object = nl_cache_get_next (object)) {
		if (_route_match ((struct rtnl_route *) object, AF_INET, ifindex, FALSE)) {
			if (_rtnl_route_is_default ((struct rtnl_route *) object)) {
				if (mode == NM_PLATFORM_GET_ROUTE_MODE_NO_DEFAULT)
					continue;
			} else {
				if (mode == NM_PLATFORM_GET_ROUTE_MODE_ONLY_DEFAULT)
					continue;
			}
			if (init_ip4_route (&route, (struct rtnl_route *) object))
				g_array_append_val (routes, route);
		}
	}

	return routes;
}

static GArray *
ip6_route_get_all (NMPlatform *platform, int ifindex, NMPlatformGetRouteMode mode)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	GArray *routes;
	NMPlatformIP6Route route;
	struct nl_object *object;

	g_return_val_if_fail (NM_IN_SET (mode, NM_PLATFORM_GET_ROUTE_MODE_ALL, NM_PLATFORM_GET_ROUTE_MODE_NO_DEFAULT, NM_PLATFORM_GET_ROUTE_MODE_ONLY_DEFAULT), NULL);

	routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP6Route));

	for (object = nl_cache_get_first (priv->route_cache); object; object = nl_cache_get_next (object)) {
		if (_route_match ((struct rtnl_route *) object, AF_INET6, ifindex, FALSE)) {
			if (_rtnl_route_is_default ((struct rtnl_route *) object)) {
				if (mode == NM_PLATFORM_GET_ROUTE_MODE_NO_DEFAULT)
					continue;
			} else {
				if (mode == NM_PLATFORM_GET_ROUTE_MODE_ONLY_DEFAULT)
					continue;
			}
			if (init_ip6_route (&route, (struct rtnl_route *) object))
				g_array_append_val (routes, route);
		}
	}

	return routes;
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
	auto_nl_addr struct nl_addr *gw = gateway ? _nm_nl_addr_build (family, gateway, addrlen) : NULL;
	auto_nl_addr struct nl_addr *pref_src_nl = pref_src ? _nm_nl_addr_build (family, pref_src, addrlen) : NULL;

	/* There seem to be problems adding a route with non-zero host identifier.
	 * Adding IPv6 routes is simply ignored, without error message.
	 * In the IPv4 case, we got an error. Thus, we have to make sure, that
	 * the address is sane. */
	clear_host_address (family, network, plen, network_clean);
	dst = _nm_nl_addr_build (family, network_clean, plen ? addrlen : 0);
	nl_addr_set_prefixlen (dst, plen);

	rtnlroute = _nm_rtnl_route_alloc ();
	rtnl_route_set_table (rtnlroute, RT_TABLE_MAIN);
	rtnl_route_set_tos (rtnlroute, 0);
	rtnl_route_set_dst (rtnlroute, dst);
	rtnl_route_set_priority (rtnlroute, metric);
	rtnl_route_set_family (rtnlroute, family);
	rtnl_route_set_protocol (rtnlroute, source_to_rtprot (source));

	nexthop = _nm_rtnl_route_nh_alloc ();
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

static gboolean
ip4_route_add (NMPlatform *platform, int ifindex, NMIPConfigSource source,
               in_addr_t network, int plen, in_addr_t gateway,
               guint32 pref_src, guint32 metric, guint32 mss)
{
	return add_object (platform, build_rtnl_route (AF_INET, ifindex, source, &network, plen, &gateway, pref_src ? &pref_src : NULL, metric, mss));
}

static gboolean
ip6_route_add (NMPlatform *platform, int ifindex, NMIPConfigSource source,
               struct in6_addr network, int plen, struct in6_addr gateway,
               guint32 metric, guint32 mss)
{
	metric = nm_utils_ip6_route_metric_normalize (metric);

	return add_object (platform, build_rtnl_route (AF_INET6, ifindex, source, &network, plen, &gateway, NULL, metric, mss));
}

static struct rtnl_route *
route_search_cache (struct nl_cache *cache, int family, int ifindex, const void *network, int plen, guint32 metric)
{
	guint32 network_clean[4], dst_clean[4];
	struct nl_object *object;

	clear_host_address (family, network, plen, network_clean);

	for (object = nl_cache_get_first (cache); object; object = nl_cache_get_next (object)) {
		struct nl_addr *dst;
		struct rtnl_route *rtnlroute = (struct rtnl_route *) object;

		if (!_route_match (rtnlroute, family, ifindex, FALSE))
			continue;

		if (metric != rtnl_route_get_priority (rtnlroute))
			continue;

		dst = rtnl_route_get_dst (rtnlroute);
		if (   !dst
		    || nl_addr_get_family (dst) != family
		    || nl_addr_get_prefixlen (dst) != plen)
			continue;

		/* plen = 0 means all host bits, so all bits should be cleared.
		 * Likewise if the binary address is not present or all zeros.
		 */
		if (plen == 0 || nl_addr_iszero (dst))
			memset (dst_clean, 0, sizeof (dst_clean));
		else
			clear_host_address (family, nl_addr_get_binary_addr (dst), plen, dst_clean);

		if (memcmp (dst_clean, network_clean,
		            family == AF_INET ? sizeof (guint32) : sizeof (struct in6_addr)) != 0)
			continue;

		rtnl_route_get (rtnlroute);
		return rtnlroute;
	}
	return NULL;
}

static gboolean
refresh_route (NMPlatform *platform, int family, int ifindex, const void *network, int plen, guint32 metric)
{
	struct nl_cache *cache;
	auto_nl_object struct rtnl_route *cached_object = NULL;

	cache = choose_cache_by_type (platform, family == AF_INET ? OBJECT_TYPE_IP4_ROUTE : OBJECT_TYPE_IP6_ROUTE);
	cached_object = route_search_cache (cache, family, ifindex, network, plen, metric);

	if (cached_object)
		return refresh_object (platform, (struct nl_object *) cached_object, TRUE, NM_PLATFORM_REASON_INTERNAL);
	return TRUE;
}

static gboolean
ip4_route_delete (NMPlatform *platform, int ifindex, in_addr_t network, int plen, guint32 metric)
{
	in_addr_t gateway = 0;
	struct rtnl_route *cached_object;
	struct nl_object *route = build_rtnl_route (AF_INET, ifindex, NM_IP_CONFIG_SOURCE_UNKNOWN, &network, plen, &gateway, NULL, metric, 0);
	uint8_t scope = RT_SCOPE_NOWHERE;
	struct nl_cache *cache;

	g_return_val_if_fail (route, FALSE);

	cache = choose_cache_by_type (platform, OBJECT_TYPE_IP4_ROUTE);

	if (metric == 0) {
		/* Deleting an IPv4 route with metric 0 does not only delete an exectly matching route.
		 * If no route with metric 0 exists, it might delete another route to the same destination.
		 * For nm_platform_ip4_route_delete() we don't want this semantic.
		 *
		 * Instead, re-fetch the route from kernel, and if that fails, there is nothing to do.
		 * On success, there is still a race that we might end up deleting the wrong route. */
		if (!refresh_object (platform, (struct nl_object *) route, FALSE, _NM_PLATFORM_REASON_CACHE_CHECK_INTERNAL)) {
			rtnl_route_put ((struct rtnl_route *) route);
			return TRUE;
		}
	}

	/* when deleting an IPv4 route, several fields of the provided route must match.
	 * Lookup in the cache so that we hopefully get the right values. */
	cached_object = (struct rtnl_route *) nl_cache_search (cache, route);
	if (!cached_object)
		cached_object = route_search_cache (cache, AF_INET, ifindex, &network, plen, metric);

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

		if (cached_object)
			scope = rtnl_route_get_scope (cached_object);

		if (scope == RT_SCOPE_NOWHERE) {
			/* If we would set the scope to RT_SCOPE_NOWHERE, libnl would guess the scope.
			 * But probably it will guess 'link' because we set the next hop of the route
			 * to zero (0.0.0.0). A better guess is 'global'. */
			scope = RT_SCOPE_UNIVERSE;
		}
	}
	rtnl_route_set_scope ((struct rtnl_route *) route, scope);

	/* we only support routes with TOS zero. As such, delete_route() is also only able to delete
	 * routes with tos==0. build_rtnl_route() already initializes tos properly. */

	/* The following fields are also relevant when comparing the route, but the default values
	 * are already as we want them:
	 *
	 * type: RTN_UNICAST (setting to zero would ignore the type, but we only want to delete RTN_UNICAST)
	 * pref_src: NULL
	 */

	rtnl_route_put (cached_object);
	return delete_object (platform, route, FALSE) && refresh_route (platform, AF_INET, ifindex, &network, plen, metric);
}

static gboolean
ip6_route_delete (NMPlatform *platform, int ifindex, struct in6_addr network, int plen, guint32 metric)
{
	struct in6_addr gateway = IN6ADDR_ANY_INIT;

	metric = nm_utils_ip6_route_metric_normalize (metric);

	return delete_object (platform, build_rtnl_route (AF_INET6, ifindex, NM_IP_CONFIG_SOURCE_UNKNOWN ,&network, plen, &gateway, NULL, metric, 0), FALSE) &&
	    refresh_route (platform, AF_INET6, ifindex, &network, plen, metric);
}

static gboolean
ip_route_exists (NMPlatform *platform, int family, int ifindex, gpointer network, int plen, guint32 metric)
{
	auto_nl_object struct nl_object *object = build_rtnl_route (family, ifindex,
	                                                            NM_IP_CONFIG_SOURCE_UNKNOWN,
	                                                            network, plen, NULL, NULL, metric, 0);
	struct nl_cache *cache = choose_cache (platform, object);
	auto_nl_object struct nl_object *cached_object = nl_cache_search (cache, object);

	if (!cached_object)
		cached_object = (struct nl_object *) route_search_cache (cache, family, ifindex, network, plen, metric);
	return !!cached_object;
}

static gboolean
ip4_route_exists (NMPlatform *platform, int ifindex, in_addr_t network, int plen, guint32 metric)
{
	return ip_route_exists (platform, AF_INET, ifindex, &network, plen, metric);
}

static gboolean
ip6_route_exists (NMPlatform *platform, int ifindex, struct in6_addr network, int plen, guint32 metric)
{
	metric = nm_utils_ip6_route_metric_normalize (metric);

	return ip_route_exists (platform, AF_INET6, ifindex, &network, plen, metric);
}

/******************************************************************/

/* Initialize the link cache while ensuring all links are of AF_UNSPEC,
 * family (even though the kernel might set AF_BRIDGE for bridges).
 * See also: _nl_link_family_unset() */
static void
init_link_cache (NMPlatform *platform)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	struct nl_object *object = NULL;

	rtnl_link_alloc_cache (priv->nlh, AF_UNSPEC, &priv->link_cache);

	do {
		for (object = nl_cache_get_first (priv->link_cache); object; object = nl_cache_get_next (object)) {
			if (rtnl_link_get_family ((struct rtnl_link *)object) != AF_UNSPEC)
				break;
		}

		if (object) {
			/* A non-AF_UNSPEC object encoutnered */
			struct nl_object *existing;

			nl_object_get (object);
			nl_cache_remove (object);
			rtnl_link_set_family ((struct rtnl_link *)object, AF_UNSPEC);
			existing = nl_cache_search (priv->link_cache, object);
			if (existing)
				nl_object_put (existing);
			else
				nl_cache_add (priv->link_cache, object);
			nl_object_put (object);
		}
	} while (object);
}

/* Calls announce_object with appropriate arguments for all objects
 * which are not coherent between old and new caches and deallocates
 * the old cache. */
static void
cache_announce_changes (NMPlatform *platform, struct nl_cache *new, struct nl_cache *old)
{
	struct nl_object *object;

	if (!old)
		return;

	for (object = nl_cache_get_first (new); object; object = nl_cache_get_next (object)) {
		struct nl_object *cached_object = nm_nl_cache_search (old, object);

		if (cached_object) {
			ObjectType type = _nlo_get_object_type (object);
			if (nm_nl_object_diff (type, object, cached_object))
				announce_object (platform, object, NM_PLATFORM_SIGNAL_CHANGED, NM_PLATFORM_REASON_EXTERNAL);
			nl_object_put (cached_object);
		} else
			announce_object (platform, object, NM_PLATFORM_SIGNAL_ADDED, NM_PLATFORM_REASON_EXTERNAL);
	}
	for (object = nl_cache_get_first (old); object; object = nl_cache_get_next (object)) {
		struct nl_object *cached_object = nm_nl_cache_search (new, object);
		if (cached_object)
			nl_object_put (cached_object);
		else
			announce_object (platform, object, NM_PLATFORM_SIGNAL_REMOVED, NM_PLATFORM_REASON_EXTERNAL);
	}

	nl_cache_free (old);
}

/* The cache should always avoid containing objects not handled by NM, like
 * e.g. addresses of the AF_PHONET family. */
static void
cache_remove_unknown (struct nl_cache *cache)
{
	GPtrArray *objects_to_remove = NULL;
	struct nl_object *object;

	for (object = nl_cache_get_first (cache); object; object = nl_cache_get_next (object)) {
		if (_nlo_get_object_type (object) == OBJECT_TYPE_UNKNOWN) {
			if (!objects_to_remove)
				objects_to_remove = g_ptr_array_new_with_free_func ((GDestroyNotify) nl_object_put);
			nl_object_get (object);
			g_ptr_array_add (objects_to_remove, object);
		}
	}

	if (objects_to_remove) {
		guint i;

		for (i = 0; i < objects_to_remove->len; i++)
			nl_cache_remove (g_ptr_array_index (objects_to_remove, i));

		g_ptr_array_free (objects_to_remove, TRUE);
	}
}

/* Creates and populates the netlink object caches. Called upon platform init and
 * when we run out of sync (out of buffer space, netlink congestion control). In case
 * the caches already exist, it finds changed, added and removed objects, announces
 * them and destroys the old caches. */
static void
cache_repopulate_all (NMPlatform *platform)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	struct nl_cache *old_link_cache = priv->link_cache;
	struct nl_cache *old_address_cache = priv->address_cache;
	struct nl_cache *old_route_cache = priv->route_cache;
	struct nl_object *object;

	debug ("platform: %spopulate platform cache", old_link_cache ? "re" : "");

	/* Allocate new netlink caches */
	init_link_cache (platform);
	rtnl_addr_alloc_cache (priv->nlh, &priv->address_cache);
	rtnl_route_alloc_cache (priv->nlh, AF_UNSPEC, 0, &priv->route_cache);
	g_assert (priv->link_cache && priv->address_cache && priv->route_cache);

	/* Remove all unknown objects from the caches */
	cache_remove_unknown (priv->link_cache);
	cache_remove_unknown (priv->address_cache);
	cache_remove_unknown (priv->route_cache);

	for (object = nl_cache_get_first (priv->address_cache); object; object = nl_cache_get_next (object)) {
		_rtnl_addr_hack_lifetimes_rel_to_abs ((struct rtnl_addr *) object);
	}

	/* Make sure all changes we've missed are announced. */
	cache_announce_changes (platform, priv->link_cache, old_link_cache);
	cache_announce_changes (platform, priv->address_cache, old_address_cache);
	cache_announce_changes (platform, priv->route_cache, old_route_cache);
}

/******************************************************************/

#define EVENT_CONDITIONS      ((GIOCondition) (G_IO_IN | G_IO_PRI))
#define ERROR_CONDITIONS      ((GIOCondition) (G_IO_ERR | G_IO_NVAL))
#define DISCONNECT_CONDITIONS ((GIOCondition) (G_IO_HUP))

static int
verify_source (struct nl_msg *msg, gpointer user_data)
{
	struct ucred *creds = nlmsg_get_creds (msg);

	if (!creds || creds->pid) {
		if (creds)
			warning ("netlink: received non-kernel message (pid %d)", creds->pid);
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
	NMPlatform *platform = NM_PLATFORM (user_data);
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int nle;

	nle = nl_recvmsgs_default (priv->nlh_event);
	if (nle < 0)
		switch (nle) {
		case -NLE_DUMP_INTR:
			/* this most likely happens due to our request (RTM_GETADDR, AF_INET6, NLM_F_DUMP)
			 * to detect support for support_kernel_extended_ifa_flags. This is not critical
			 * and can happen easily. */
			debug ("Uncritical failure to retrieve incoming events: %s (%d)", nl_geterror (nle), nle);
			break;
		case -NLE_NOMEM:
			warning ("Too many netlink events. Need to resynchronize platform cache");
			/* Drain the event queue, we've lost events and are out of sync anyway and we'd
			 * like to free up some space. We'll read in the status synchronously. */
			nl_socket_modify_cb (priv->nlh_event, NL_CB_VALID, NL_CB_DEFAULT, NULL, NULL);
			do {
				errno = 0;

				nle = nl_recvmsgs_default (priv->nlh_event);

				/* Work around a libnl bug fixed in 3.2.22 (375a6294) */
				if (nle == 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
					nle = -NLE_AGAIN;
			} while (nle != -NLE_AGAIN);
			nl_socket_modify_cb (priv->nlh_event, NL_CB_VALID, NL_CB_CUSTOM, event_notification, user_data);
			cache_repopulate_all (platform);
			break;
		default:
			error ("Failed to retrieve incoming events: %s (%d)", nl_geterror (nle), nle);
			break;
	}
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

	/* No blocking for event socket, so that we can drain it safely. */
	if (event) {
		nle = nl_socket_set_nonblocking (sock);
		g_assert (!nle);
	}

	return sock;
}

/******************************************************************/

static void
udev_device_added (NMPlatform *platform,
                   GUdevDevice *udev_device)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	auto_nl_object struct rtnl_link *rtnllink = NULL;
	const char *ifname;
	int ifindex;

	ifname = g_udev_device_get_name (udev_device);
	if (!ifname) {
		debug ("udev-add: failed to get device's interface");
		return;
	}

	if (g_udev_device_get_property (udev_device, "IFINDEX"))
		ifindex = g_udev_device_get_property_as_int (udev_device, "IFINDEX");
	else {
		warning ("(%s): udev-add: failed to get device's ifindex", ifname);
		return;
	}
	if (ifindex <= 0) {
		warning ("(%s): udev-add: retrieved invalid IFINDEX=%d", ifname, ifindex);
		return;
	}

	if (!g_udev_device_get_sysfs_path (udev_device)) {
		debug ("(%s): udev-add: couldn't determine device path; ignoring...", ifname);
		return;
	}

	g_hash_table_insert (priv->udev_devices, GINT_TO_POINTER (ifindex),
	                     g_object_ref (udev_device));

	rtnllink = rtnl_link_get (priv->link_cache, ifindex);
	if (!rtnllink) {
		debug ("(%s): udev-add: interface not known via netlink; ignoring ifindex %d...", ifname, ifindex);
		return;
	}

	announce_object (platform, (struct nl_object *) rtnllink, NM_PLATFORM_SIGNAL_CHANGED, NM_PLATFORM_REASON_EXTERNAL);
}

static void
udev_device_removed (NMPlatform *platform,
                     GUdevDevice *udev_device)
{
	NMLinuxPlatformPrivate *priv = NM_LINUX_PLATFORM_GET_PRIVATE (platform);
	int ifindex = 0;

	if (g_udev_device_get_property (udev_device, "IFINDEX"))
		ifindex = g_udev_device_get_property_as_int (udev_device, "IFINDEX");
	else {
		GHashTableIter iter;
		gpointer key, value;

		/* This should not happen, but just to be sure.
		 * If we can't get IFINDEX, go through the devices and
		 * compare the pointers.
		 */
		g_hash_table_iter_init (&iter, priv->udev_devices);
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			if ((GUdevDevice *)value == udev_device) {
				ifindex = GPOINTER_TO_INT (key);
				break;
			}
		}
	}

	debug ("udev-remove: IFINDEX=%d", ifindex);
	if (ifindex <= 0)
		return;

	g_hash_table_remove (priv->udev_devices, GINT_TO_POINTER (ifindex));
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
	debug ("UDEV event: action '%s' subsys '%s' device '%s' (%s); seqnum=%" G_GUINT64_FORMAT,
	       action, subsys, g_udev_device_get_name (udev_device),
	       ifindex ? ifindex : "unknown", seqnum);

	if (!strcmp (action, "add") || !strcmp (action, "move"))
		udev_device_added (platform, udev_device);
	if (!strcmp (action, "remove"))
		udev_device_removed (platform, udev_device);
}

/******************************************************************/

static void
nm_linux_platform_init (NMLinuxPlatform *platform)
{
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
	                                 RTNLGRP_IPV4_ROUTE,  RTNLGRP_IPV6_ROUTE,
	                                 0);
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

	cache_repopulate_all (platform);

#if HAVE_LIBNL_INET6_ADDR_GEN_MODE
	if (G_UNLIKELY (_support_user_ipv6ll == 0)) {
		struct nl_object *object;

		/* Initial check for user IPv6LL support once the link cache is allocated
		 * and filled.  If there are no links in the cache yet then we'll check
		 * when a new link shows up in announce_object().
		 */
		object = nl_cache_get_first (priv->link_cache);
		if (object)
			_support_user_ipv6ll_detect ((struct rtnl_link *) object);
	}
#endif

	/* Set up udev monitoring */
	priv->udev_client = g_udev_client_new (udev_subsys);
	g_signal_connect (priv->udev_client, "uevent", G_CALLBACK (handle_udev_event), platform);
	priv->udev_devices = g_hash_table_new_full (NULL, NULL, NULL, g_object_unref);

	/* request all IPv6 addresses (hopeing that there is at least one), to check for
	 * the IFA_FLAGS attribute. */
	nle = nl_rtgen_request (priv->nlh_event, RTM_GETADDR, AF_INET6, NLM_F_DUMP);
	if (nle < 0)
		nm_log_warn (LOGD_PLATFORM, "Netlink error: requesting RTM_GETADDR failed with %s", nl_geterror (nle));

	priv->wifi_data = g_hash_table_new_full (NULL, NULL, NULL, (GDestroyNotify) wifi_utils_deinit);

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

	G_OBJECT_CLASS (nm_linux_platform_parent_class)->constructed (_object);
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
	g_hash_table_unref (priv->wifi_data);

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
	object_class->finalize = nm_linux_platform_finalize;

	platform_class->sysctl_set = sysctl_set;
	platform_class->sysctl_get = sysctl_get;

	platform_class->link_get = _nm_platform_link_get;
	platform_class->link_get_by_address = _nm_platform_link_get_by_address;
	platform_class->link_get_all = link_get_all;
	platform_class->link_add = link_add;
	platform_class->link_delete = link_delete;
	platform_class->link_get_ifindex = link_get_ifindex;
	platform_class->link_get_name = link_get_name;
	platform_class->link_get_type = link_get_type;
	platform_class->link_get_type_name = link_get_type_name;
	platform_class->link_get_unmanaged = link_get_unmanaged;

	platform_class->link_refresh = link_refresh;

	platform_class->link_set_up = link_set_up;
	platform_class->link_set_down = link_set_down;
	platform_class->link_set_arp = link_set_arp;
	platform_class->link_set_noarp = link_set_noarp;
	platform_class->link_is_up = link_is_up;
	platform_class->link_is_connected = link_is_connected;
	platform_class->link_uses_arp = link_uses_arp;

	platform_class->link_get_ipv6_token = link_get_ipv6_token;

	platform_class->link_get_user_ipv6ll_enabled = link_get_user_ipv6ll_enabled;
	platform_class->link_set_user_ipv6ll_enabled = link_set_user_ipv6ll_enabled;

	platform_class->link_get_address = link_get_address;
	platform_class->link_set_address = link_set_address;
	platform_class->link_get_permanent_address = link_get_permanent_address;
	platform_class->link_get_mtu = link_get_mtu;
	platform_class->link_set_mtu = link_set_mtu;

	platform_class->link_get_physical_port_id = link_get_physical_port_id;
	platform_class->link_get_dev_id = link_get_dev_id;
	platform_class->link_get_wake_on_lan = link_get_wake_on_lan;
	platform_class->link_get_driver_info = link_get_driver_info;

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

	platform_class->ip4_address_get_all = ip4_address_get_all;
	platform_class->ip6_address_get_all = ip6_address_get_all;
	platform_class->ip4_address_add = ip4_address_add;
	platform_class->ip6_address_add = ip6_address_add;
	platform_class->ip4_address_delete = ip4_address_delete;
	platform_class->ip6_address_delete = ip6_address_delete;
	platform_class->ip4_address_exists = ip4_address_exists;
	platform_class->ip6_address_exists = ip6_address_exists;

	platform_class->ip4_check_reinstall_device_route = ip4_check_reinstall_device_route;

	platform_class->ip4_route_get_all = ip4_route_get_all;
	platform_class->ip6_route_get_all = ip6_route_get_all;
	platform_class->ip4_route_add = ip4_route_add;
	platform_class->ip6_route_add = ip6_route_add;
	platform_class->ip4_route_delete = ip4_route_delete;
	platform_class->ip6_route_delete = ip6_route_delete;
	platform_class->ip4_route_exists = ip4_route_exists;
	platform_class->ip6_route_exists = ip6_route_exists;

	platform_class->check_support_kernel_extended_ifa_flags = check_support_kernel_extended_ifa_flags;
	platform_class->check_support_user_ipv6ll = check_support_user_ipv6ll;
}
