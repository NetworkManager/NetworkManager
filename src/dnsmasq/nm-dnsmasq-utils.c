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
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <arpa/inet.h>

#include "nm-dnsmasq-utils.h"
#include "nm-platform.h"
#include "nm-utils.h"

gboolean
nm_dnsmasq_utils_get_range (const NMPlatformIP4Address *addr,
                            char *out_first,
                            char *out_last,
                            char **out_error_desc)
{
	guint32 host = addr->address;
	guint8 prefix = addr->plen;
	guint32 netmask = nm_utils_ip4_prefix_to_netmask (prefix);
	guint32 first, last, reserved;

	g_return_val_if_fail (out_first != NULL, FALSE);
	g_return_val_if_fail (out_last != NULL, FALSE);

	if (prefix > 30) {
		if (out_error_desc)
			*out_error_desc = g_strdup_printf ("Address prefix %d is too small for DHCP.", prefix);
		return FALSE;
	}

	/* Find the first available address *after* the local machine's IP */
	first = (host & netmask) + htonl (1);

	/* Shortcut: allow a max of 253 addresses; the - htonl(1) here is to assure
	 * that we don't set 'last' to the broadcast address of the network. */
	if (prefix < 24)
		last = (host | ~nm_utils_ip4_prefix_to_netmask (24)) - htonl (1);
	else
		last = (host | ~netmask) - htonl(1);

	/* Figure out which range (either above the host address or below it)
	 * has more addresses.  Reserve some addresses for static IPs.
	 */
	if (ntohl (host) - ntohl (first) > ntohl (last) - ntohl (host)) {
		/* Range below the host's IP address */
		reserved = (guint32) ((ntohl (host) - ntohl (first)) / 10);
		last = host - htonl (MIN (reserved, 8)) - htonl (1);
	} else {
		/* Range above host's IP address */
		reserved = (guint32) ((ntohl (last) - ntohl (host)) / 10);
		first = host + htonl (MIN (reserved, 8)) + htonl (1);
	}

	nm_utils_inet4_ntop (first, out_first);
	nm_utils_inet4_ntop (last, out_last);

	return TRUE;
}

