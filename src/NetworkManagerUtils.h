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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef NETWORK_MANAGER_UTILS_H
#define NETWORK_MANAGER_UTILS_H

#include <glib.h>
#include <stdio.h>
#include <syslog.h>
#include <net/ethernet.h>
#include <iwlib.h>
#include <sys/time.h>
#include <stdarg.h>

#include "NetworkManager.h"
#include "nm-device.h"

int			nm_null_safe_strcmp				(const char *s1, const char *s2);

gboolean		nm_ethernet_address_is_valid		(const struct ether_addr *test_addr);
gboolean		nm_ethernet_addresses_are_equal	(const struct ether_addr *a, const struct ether_addr *b);

int			nm_spawn_process				(const char *args);

void			nm_print_device_capabilities		(NMDevice *dev);

gchar*			nm_utils_inet_ip4_address_as_string (guint32 ip);

struct nl_addr *	nm_utils_ip4_addr_to_nl_addr (guint32 ip4_addr);

int				nm_utils_ip4_netmask_to_prefix (guint32 ip4_netmask);

char *          nm_utils_hexstr2bin (const char *hex, size_t len);

#endif

