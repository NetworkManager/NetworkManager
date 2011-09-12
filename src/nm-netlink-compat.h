/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * Copyright (C) 2011 Caixa Magica Software.
 */

#ifndef NM_NETLINK_COMPAT_H
#define NM_NETLINK_COMPAT_H

#include <errno.h>

#include <netlink/netlink.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>


#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/utils.h>
#include <netlink/data.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>
#include <netlink/route/link.h>
#include <netlink/route/nexthop.h>

#include <config.h>

/* libnl-1 API compatibility for libnl-2/3*/
#ifndef HAVE_LIBNL1

struct rtnl_nexthop * nm_netlink_get_nh(struct rtnl_route *);
int rtnl_route_get_oif(struct rtnl_route *);
int rtnl_route_set_oif(struct rtnl_route *, int);
int rtnl_route_set_gateway(struct rtnl_route *, struct nl_addr *);
int rtnl_route_get_dst_len(struct rtnl_route *);
struct nl_addr * rtnl_route_get_gateway(struct rtnl_route *);
#endif

/* libnl-2 API compatibility for libnl-3 */
#ifdef HAVE_LIBNL3
static inline int
__rtnl_link_alloc_cache (struct nl_sock *h, struct nl_cache **cache)
{
       return rtnl_link_alloc_cache (h, AF_UNSPEC, cache);
}
#define rtnl_link_alloc_cache __rtnl_link_alloc_cache
#endif

/* libnl-1.0 compat functions */
#ifdef HAVE_LIBNL1

#define nl_sock nl_handle

/* libnl-1.0 functions with similar prototypes */
#define nl_socket_alloc nl_handle_alloc
#define nl_socket_alloc_cb nl_handle_alloc_cb
#define nl_socket_free nl_handle_destroy
#define nl_socket_set_passcred nl_set_passcred
#define nl_socket_disable_seq_check nl_disable_sequence_check
#define rtnl_route_set_priority rtnl_route_set_prio
#define nlmsg_datalen nlmsg_len

/* auxiliary functions */
int nl_compat_error (int);

/* libnl-1.0 functions with modified prototypes in libnl-2/3*/
static inline const char * 
__nl_geterror (int err)
{
        /* err is set, can be parsed */
        return nl_geterror ();
}
#define nl_geterror __nl_geterror

static inline int
__rtnl_addr_alloc_cache (struct nl_sock *h, struct nl_cache **cache)
{
	g_return_val_if_fail (cache != NULL, -EINVAL);

	*cache = rtnl_addr_alloc_cache (h);
	return *cache ? 0 : -ENOMEM;
}
#define rtnl_addr_alloc_cache __rtnl_addr_alloc_cache

static inline int
__rtnl_route_alloc_cache (struct nl_sock *h, int family, int flags, struct nl_cache **cache)
{
	g_return_val_if_fail (cache != NULL, -EINVAL);

	*cache = rtnl_route_alloc_cache (h);
	return *cache ? 0 : -ENOMEM;
}
#define rtnl_route_alloc_cache __rtnl_route_alloc_cache

static inline int
__rtnl_link_alloc_cache (struct nl_sock *h, struct nl_cache **cache)
{
	g_return_val_if_fail (cache != NULL, -EINVAL);

	*cache = rtnl_link_alloc_cache (h);
	return *cache ? 0 : -ENOMEM;
}
#define rtnl_link_alloc_cache __rtnl_link_alloc_cache

static inline int
__rtnl_route_get_metric (struct rtnl_route *route, int metric, unsigned int *value)
{
	g_return_val_if_fail (value != NULL, -EINVAL);

	*value = rtnl_route_get_metric (route, metric);
	return 0;
}
#define rtnl_route_get_metric __rtnl_route_get_metric

static inline int
__rtnl_addr_add (struct nl_sock *h, struct rtnl_addr *addr, int flags)
{
	return nl_compat_error (rtnl_addr_add (h, addr, flags));
}
#define rtnl_addr_add __rtnl_addr_add

static inline int
__rtnl_route_add (struct nl_sock *sk, struct rtnl_route *route, int flags)
{
	return nl_compat_error (rtnl_route_add (sk, route, flags));
}
#define rtnl_route_add __rtnl_route_add

static inline int
rtnl_route_delete (struct nl_sock *h, struct rtnl_route *route, int flags)
{
	return nl_compat_error (rtnl_route_del (h, route, flags));
}
#define rtnl_route_del rtnl_route_delete

static inline int
__rtnl_link_change (struct nl_sock *h, struct rtnl_link *old, struct rtnl_link *tmpl, int flags)
{
	return nl_compat_error (rtnl_link_change (h, old, tmpl,flags));
}
#define rtnl_link_change __rtnl_link_change

static inline int
__nl_cache_include (struct nl_cache *cache, struct nl_object *obj, change_func_t cb, void *data)
{
	return nl_cache_include (cache, obj, cb);
}
#define nl_cache_include __nl_cache_include

#define NLE_SUCCESS             0
#define NLE_FAILURE             1
#define NLE_INTR                2
#define NLE_BAD_SOCK            3
#define NLE_AGAIN               4
#define NLE_NOMEM               5
#define NLE_EXIST               6
#define NLE_INVAL               7
#define NLE_RANGE               8
#define NLE_MSGSIZE             9
#define NLE_OPNOTSUPP           10
#define NLE_AF_NOSUPPORT        11
#define NLE_OBJ_NOTFOUND        12
#define NLE_NOATTR              13
#define NLE_MISSING_ATTR        14
#define NLE_AF_MISMATCH         15
#define NLE_SEQ_MISMATCH        16
#define NLE_MSG_OVERFLOW        17
#define NLE_MSG_TRUNC           18
#define NLE_NOADDR              19
#define NLE_SRCRT_NOSUPPORT     20
#define NLE_MSG_TOOSHORT        21
#define NLE_MSGTYPE_NOSUPPORT   22
#define NLE_OBJ_MISMATCH        23
#define NLE_NOCACHE             24
#define NLE_BUSY                25
#define NLE_PROTO_MISMATCH      26
#define NLE_NOACCESS            27
#define NLE_PERM                28
#define NLE_PKTLOC_FILE         29
#endif

#endif /* NM_NETLINK_COMPAT_H */
