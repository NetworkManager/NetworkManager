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
#include <net/ethernet.h>
#include <iwlib.h>

#include "NetworkManager.h"
#include "NetworkManagerDevice.h"

#define NM_DEBUG_PRINT( s )				if (debug) fprintf( stderr, s );
#define NM_DEBUG_PRINT_1( s, a )			if (debug) fprintf( stderr, s, a );
#define NM_DEBUG_PRINT_2( s, a, b )		if (debug) fprintf( stderr, s, a, b );
#define NM_DEBUG_PRINT_3( s, a, b, c )		if (debug) fprintf( stderr, s, a, b, c );
#define NM_DEBUG_PRINT_4( s, a, b, c, d )	if (debug) fprintf( stderr, s, a, b, c, d );


gboolean		nm_try_acquire_mutex			(GMutex *mutex, const char *func);
void			nm_unlock_mutex				(GMutex *mutex, const char *func);

int			nm_null_safe_strcmp				(const char *s1, const char *s2);

int			nm_get_network_control_socket		(void);

gboolean		nm_ethernet_address_is_valid		(struct ether_addr *test_addr);

void			nm_dispose_scan_results			(wireless_scan *result_list);

#endif
