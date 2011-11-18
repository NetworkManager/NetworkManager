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
 * (C) Copyright 2004 - 2011 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "NetworkManagerGeneric.h"
#include "NetworkManagerUtils.h"

void nm_backend_enable_loopback (void)
{
	nm_generic_enable_loopback ();
}

void nm_backend_update_dns (void)
{
	/* Invalidate the nscd host cache since we changed resolv.conf */
	if (g_file_test ("/usr/sbin/nscd", G_FILE_TEST_EXISTS | G_FILE_TEST_IS_EXECUTABLE | G_FILE_TEST_IS_REGULAR)) {
		nm_spawn_process ("/etc/init.d/nscd condrestart");
		nm_spawn_process ("/usr/sbin/nscd -i hosts");
	}
}

