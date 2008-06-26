/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2007 Red Hat, Inc.
 */

#ifndef NM_NETLINK_H
#define NM_NETLINK_H

#include <asm/types.h>
#include <netlink/route/addr.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/link.h>

int    nm_netlink_iface_to_index (const char *iface);
char * nm_netlink_index_to_iface (int idx);
struct rtnl_link * nm_netlink_index_to_rtnl_link (int idx);

struct nl_handle * nm_netlink_get_default_handle (void);

#endif /* NM_NETLINK_H */
