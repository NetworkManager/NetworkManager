/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2010 Red Hat, Inc.
 *
 */

#include <arpa/inet.h>
#include <string.h>

#include "nm-dns-utils.h"
#include "nm-utils.h"

static void
add_ip4_to_rdns_array (guint32 ip, GPtrArray *domains) /* network byte order */
{
	guint32 defprefix;
	guchar *p;
	char *str = NULL;
	int i;

	defprefix = nm_utils_ip4_get_default_prefix (ip);

	/* Convert to host byte order, mask the host bits, and convert back */
	ip = ntohl (ip);
	ip &= 0xFFFFFFFF << (32 - defprefix);
	ip = htonl (ip);
	p = (guchar *) &ip;

	if (defprefix == 8)
		str = g_strdup_printf ("%u.in-addr.arpa", p[0] & 0xFF);
	else if (defprefix == 16)
		str = g_strdup_printf ("%u.%u.in-addr.arpa", p[1] & 0xFF, p[0] & 0xFF);
	else if (defprefix == 24)
		str = g_strdup_printf ("%u.%u.%u.in-addr.arpa", p[2] & 0xFF, p[1] & 0xFF, p[0] & 0xFF);

	if (!str) {
		g_return_if_fail (str != NULL);
		return;
	}

	/* Suppress duplicates */
	for (i = 0; i < domains->len; i++) {
		if (strcmp (str, g_ptr_array_index (domains, i)) == 0)
			break;
	}

	if (i == domains->len)
		g_ptr_array_add (domains, str);
	else
		g_free (str);
}

char **
nm_dns_utils_get_ip4_rdns_domains (NMIP4Config *ip4)
{
	GPtrArray *domains = NULL;
	int i;

	g_return_val_if_fail (ip4 != NULL, NULL);

	domains = g_ptr_array_sized_new (5);

	/* To calculate the reverse DNS domains for this IP4 config, we take
	 * all the IP addresses and routes in the config, calculate the network
	 * portion, and convert that to classful, and use the network bits for
	 * the final domain.  FIXME: better handle classless routing, which might
	 * require us to add multiple domains for each actual network prefix to
	 * cover all the separate networks in that block.
	 */

	for (i = 0; i < nm_ip4_config_get_num_addresses (ip4); i++) {
		const NMPlatformIP4Address *address = nm_ip4_config_get_address (ip4, i);

		add_ip4_to_rdns_array (address->address, domains);
	}

	for (i = 0; i < nm_ip4_config_get_num_routes (ip4); i++) {
		const NMPlatformIP4Route *route = nm_ip4_config_get_route (ip4, i);

		add_ip4_to_rdns_array (route->network, domains);
	}

	/* Terminating NULL so we can use g_strfreev() to free it */
	g_ptr_array_add (domains, NULL);

	/* Free the array and return NULL if the only element was the ending NULL */
	return (char **) g_ptr_array_free (domains, (domains->len == 1));
}

