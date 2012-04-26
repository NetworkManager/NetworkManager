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

#include <config.h>
#include <glib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>

#include "nm-logging.h"
#include "nm-netlink-compat.h"

#ifndef HAVE_LIBNL1
struct rtnl_nexthop *
nm_netlink_get_nh (struct rtnl_route * route)
{
	int hops;

	hops = rtnl_route_get_nnexthops (route);
	g_return_val_if_fail(hops > 0, NULL);
	return rtnl_route_nexthop_n (route, 0);
}

int
rtnl_route_get_oif (struct rtnl_route * route)
{
	struct rtnl_nexthop * nh;

	nh = nm_netlink_get_nh(route);
	g_return_val_if_fail(nh, -NLE_OBJ_NOTFOUND);
	return rtnl_route_nh_get_ifindex (nh);
}

int
rtnl_route_set_oif (struct rtnl_route * route, int ifindex)
{
	struct rtnl_nexthop * nh;

	nh = rtnl_route_nh_alloc();
	rtnl_route_nh_set_ifindex(nh, ifindex);
	rtnl_route_add_nexthop(route, nh);
	return 0;
}

struct nl_addr *
rtnl_route_get_gateway (struct rtnl_route * route)
{
	struct rtnl_nexthop * nh;

	nh = nm_netlink_get_nh(route);
	g_return_val_if_fail(nh, NULL);
	return rtnl_route_nh_get_gateway(nh);
}

int
rtnl_route_set_gateway (struct rtnl_route * route, struct nl_addr * gw_addr)
{
	struct rtnl_nexthop * nh;

	nh = nm_netlink_get_nh(route);
	g_return_val_if_fail(nh, -NLE_OBJ_NOTFOUND);

	rtnl_route_nh_set_gateway(nh, gw_addr);
	return 0;
}

int
rtnl_route_get_dst_len(struct rtnl_route * rtnlroute)
{
	struct nl_addr * dst;

	dst = rtnl_route_get_dst(rtnlroute);
	return nl_addr_get_prefixlen(dst);
}
#endif

#ifdef HAVE_LIBNL1
int
nl_compat_error (int err)
{
	err = abs (err);

	if (err == EEXIST)
		err = NLE_EXIST;
	else if (err == ENOENT || err == ESRCH)
		err = NLE_OBJ_NOTFOUND;
	else if (err == ERANGE)
		err = NLE_RANGE;

	return -err;
}

int
rtnl_link_vlan_get_id (struct rtnl_link *l)
{
	int fd;
	struct vlan_ioctl_args if_request;
	char *if_name = NULL;

	memset (&if_request, 0, sizeof (struct vlan_ioctl_args));

	if ((if_name = rtnl_link_get_name (l)) == NULL)
		return -1;

	g_strlcpy (if_request.device1, if_name, sizeof (if_request.device1));

	if ((fd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
		nm_log_err (LOGD_DEVICE, "couldn't open control socket.");
		return -1;
	}

	if_request.cmd = GET_VLAN_VID_CMD;
	if (ioctl (fd, SIOCSIFVLAN, &if_request) < 0) {
		nm_log_err (LOGD_DEVICE, "couldn't get vlan id for %s.", if_name);
		goto err_out;
	}

	close(fd);
	return if_request.u.VID;
err_out:
	close(fd);
	return -1;
}

int
rtnl_link_vlan_set_flags (struct rtnl_link *l, unsigned int flags)
{
	int fd;
	struct vlan_ioctl_args if_request;
	char *if_name = NULL;


	if ((if_name = rtnl_link_get_name (l)) == NULL)
		return -1;

	if ((fd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
		nm_log_err (LOGD_DEVICE, "couldn't open control socket.");
		return -1;
	}

	memset (&if_request, 0, sizeof (struct vlan_ioctl_args));
	g_strlcpy (if_request.device1, if_name, sizeof (if_request.device1));
	if_request.cmd = SET_VLAN_FLAG_CMD;
	if_request.u.flag = flags;

	if (ioctl (fd, SIOCSIFVLAN, &if_request) < 0) {
		nm_log_err (LOGD_DEVICE, "couldn't set flag in device %s.", if_name);
		goto err_out;
	}

	close(fd);
	return 0;
err_out:
	close(fd);
	return -1;
}

int
rtnl_link_vlan_set_ingress_map (struct rtnl_link *l, int from, uint32_t to)
{
	int fd;
	struct vlan_ioctl_args if_request;
	char *if_name = NULL;

	if ((if_name = rtnl_link_get_name (l)) == NULL)
		return -1;

	if ((fd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
		nm_log_err (LOGD_DEVICE, "couldn't open control socket.");
		return -1;
	}

	memset (&if_request, 0, sizeof (struct vlan_ioctl_args));
	g_strlcpy (if_request.device1, if_name, sizeof (if_request.device1));
	if_request.cmd = SET_VLAN_INGRESS_PRIORITY_CMD;
	if_request.u.skb_priority = from;
	if_request.vlan_qos = to;

	if (ioctl (fd, SIOCSIFVLAN, &if_request) < 0) {
		nm_log_err (LOGD_DEVICE, "couldn't set ingress map on device %s.", if_name);
		goto err_out;
	}

	close(fd);
	return 0;
err_out:
	close(fd);
	return -1;
}

int
rtnl_link_vlan_set_egress_map (struct rtnl_link *l, int from, uint32_t to)
{
	int fd;
	struct vlan_ioctl_args if_request;
	char *if_name = NULL;

	if ((if_name = rtnl_link_get_name (l)) == NULL)
		return -1;

	if ((fd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
		nm_log_err (LOGD_DEVICE, "couldn't open control socket.");
		return -1;
	}

	memset (&if_request, 0, sizeof (struct vlan_ioctl_args));
	g_strlcpy (if_request.device1, if_name, sizeof (if_request.device1));
	if_request.cmd = SET_VLAN_EGRESS_PRIORITY_CMD;
	if_request.u.skb_priority = from;
	if_request.vlan_qos = to;

	if (ioctl (fd, SIOCSIFVLAN, &if_request) < 0) {
		nm_log_err (LOGD_DEVICE, "couldn't set egress map on device %s.", if_name);
		goto err_out;
	}

	close(fd);
	return 0;
err_out:
	close(fd);
	return -1;
}
#endif
