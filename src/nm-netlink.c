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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2007 Red Hat, Inc.
 */

#include <asm/types.h>
#include "nm-netlink.h"
#include "nm-utils.h"

#include <glib.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

static struct nl_cache * link_cache = NULL;
static struct nl_handle * def_nl_handle = NULL;


static struct nl_cache *
get_link_cache (void)
{
	struct nl_handle * nlh;

	nlh = nm_netlink_get_default_handle ();
	g_assert (nlh);

	if (!link_cache)
		link_cache = rtnl_link_alloc_cache (nlh);
	g_assert (link_cache);

	nl_cache_update (nlh, link_cache);
	return link_cache;
}


struct nl_handle *
nm_netlink_get_default_handle (void)
{
	if (def_nl_handle)
		return def_nl_handle;

	def_nl_handle = nl_handle_alloc_nondefault (NL_CB_VERBOSE);
	g_assert (def_nl_handle);

	nl_handle_set_pid (def_nl_handle, (pthread_self () << 16 | getpid ()));
	if (nl_connect (def_nl_handle, NETLINK_ROUTE) < 0) {
		nm_error ("couldn't connect to netlink: %s", nl_geterror ());
		nl_handle_destroy (def_nl_handle);
		return NULL;
	}

	return def_nl_handle;
}

int
nm_netlink_iface_to_index (const char *iface)
{
	struct nl_cache * cache;

	g_return_val_if_fail (iface != NULL, -1);

	cache = get_link_cache ();
	g_assert (cache);
	return rtnl_link_name2i (cache, iface);
}


#define MAX_IFACE_LEN	33
char *
nm_netlink_index_to_iface (int idx)
{
	struct nl_cache * cache;
	char * buf = NULL;

	buf = g_malloc0 (MAX_IFACE_LEN);
	if (buf == NULL) {
		nm_warning ("Not enough memory to allocate interface name buffer.");
		return NULL;
	}

	cache = get_link_cache ();
	if (rtnl_link_i2name (cache, idx, buf, MAX_IFACE_LEN - 1) == NULL) {
		g_free (buf);
		buf = NULL;
	}

	return buf;
}

struct rtnl_link *
nm_netlink_index_to_rtnl_link (int idx)
{
	return rtnl_link_get (get_link_cache (), idx);
}

