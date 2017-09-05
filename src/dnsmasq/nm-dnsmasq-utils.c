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
#include "platform/nm-platform.h"
#include "nm-utils.h"

gboolean
nm_dnsmasq_utils_get_range (const NMPlatformIP4Address *addr,
                            char *out_first,
                            char *out_last,
                            char **out_error_desc)
{
	guint32 host = addr->address;
	guint8 prefix = addr->plen;
	guint32 netmask;
	guint32 first, last, mid, reserved;
	const guint32 NUM = 256;

	g_return_val_if_fail (out_first, FALSE);
	g_return_val_if_fail (out_last, FALSE);

	if (prefix > 30) {
		if (out_error_desc)
			*out_error_desc = g_strdup_printf ("Address prefix %d is too small for DHCP.", prefix);
		return FALSE;
	}

	if (prefix < 24) {
		/* if the subnet is larger then /24, we partition it and treat it
		 * like it would be a /24.
		 *
		 * Hence, the resulting range will always be between x.x.x.1/24
		 * and x.x.x.254/24, with x.x.x.0 being the network address of the
		 * host.
		 *
		 * In this case, only a /24 portion of the subnet is used.
		 * No particular reason for that, but it's unlikely that a user
		 * would use NetworkManager's shared method when having hundered
		 * of DHCP clients. So, restrict the range to the same /24 in
		 * which the host address lies.
		 */
		prefix = 24;
	}

	netmask = _nm_utils_ip4_prefix_to_netmask (prefix);

	/* treat addresses in host-order from here on. */
	netmask = ntohl (netmask);
	host = ntohl (host);

	/* if host is the network or broadcast address, coerce it to
	 * one above or below. Usually, we wouldn't expect the user
	 * to pick such an address. */
	if (host == (host & netmask))
		host++;
	else if (host == (host | ~netmask))
		host--;

	/* Exclude the network and broadcast address. */
	first = (host &  netmask) + 1;
	last =  (host | ~netmask) - 1;

	/* Depending on whether host is above or below the middle of
	 * the subnet, the larger part if handed out.
	 *
	 * If the host is in the lower half, the range starts
	 * at the lower end with the host (plus reserved), until the
	 * broadcast address
	 *
	 * If the host is in the upper half, the range starts above
	 * the network-address and goes up until the host (except reserved).
	 *
	 * reserved is up to 8 addresses, 10% of the determined range.
	 */
	mid =   (host & netmask) | (((first + last) / 2) & ~netmask);
	if (host > mid) {
		/* use lower range */
		reserved = NM_MIN (((host - first) / 10), 8);
		last = host - 1 - reserved;
		first = NM_MAX (first, last > NUM ? last - NUM : 0);
	} else {
		/* use upper range */
		reserved = NM_MIN (((last - host) / 10), 8);
		first = host + 1 + reserved;
		last = NM_MIN (last, first < 0xFFFFFFFF - NUM ? first + NUM : 0xFFFFFFFF);
	}

	first = htonl (first);
	last = htonl (last);

	nm_utils_inet4_ntop (first, out_first);
	nm_utils_inet4_ntop (last, out_last);

	return TRUE;
}

