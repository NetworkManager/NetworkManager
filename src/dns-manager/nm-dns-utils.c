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

#include "nm-default.h"

#include <arpa/inet.h>
#include <string.h>

#include "nm-dns-utils.h"
#include "nm-core-internal.h"
#include "nm-platform.h"
#include "nm-utils.h"

char **
nm_dns_utils_get_ip4_rdns_domains (NMIP4Config *ip4)
{
	char **strv;
	GPtrArray *domains = NULL;
	int i;

	g_return_val_if_fail (ip4 != NULL, NULL);

	domains = g_ptr_array_sized_new (5);

	for (i = 0; i < nm_ip4_config_get_num_addresses (ip4); i++) {
		const NMPlatformIP4Address *address = nm_ip4_config_get_address (ip4, i);

		nm_utils_get_reverse_dns_domains_ip4 (address->address, address->plen, domains);
	}

	for (i = 0; i < nm_ip4_config_get_num_routes (ip4); i++) {
		const NMPlatformIP4Route *route = nm_ip4_config_get_route (ip4, i);

		nm_utils_get_reverse_dns_domains_ip4 (route->network, route->plen, domains);
	}

	/* Terminating NULL so we can use g_strfreev() to free it */
	g_ptr_array_add (domains, NULL);

	/* Free the array and return NULL if the only element was the ending NULL */
	strv = (char **) g_ptr_array_free (domains, (domains->len == 1));

	return _nm_utils_strv_cleanup (strv, FALSE, FALSE, TRUE);

}
