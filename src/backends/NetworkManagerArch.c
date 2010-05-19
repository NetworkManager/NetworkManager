/* NetworkManager -- Network link manager
 *
 * Backend implementation for the Arch Linux distribution http://www.archlinux.org
 * 
 * Tor Krill <tor@krill.nu> and Will Rea <sillywilly@gmail.com>
 *
 * Updated by Wael Nasreddine <gandalf@siemens-mobiles.org>
 *
 * Updated by Valentine Sinitsyn <e_val@inbox.ru>
 * 
 * Heavily based on NetworkManagerDebian.c by Matthew Garrett <mjg59@srcf.ucam.org>
 *
 * Heavily based on NetworkManagerRedhat.c by Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2004 Tom Parker
 * (C) Copyright 2004 Matthew Garrett
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "NetworkManagerGeneric.h"
#include "nm-system.h"
#include "NetworkManagerUtils.h"

/*
 * nm_system_enable_loopback
 *
 * Bring up the loopback interface
 *
 */
void nm_system_enable_loopback (void)
{
	nm_generic_enable_loopback ();
}

/*
 * nm_system_update_dns
 *
 * Make glibc/nscd aware of any changes to the resolv.conf file by
 * restarting nscd.
 *
 */
void nm_system_update_dns (void)
{
	/* Check if the daemon was already running - do not start a new instance */
	if (g_file_test("/var/run/daemons/nscd", G_FILE_TEST_EXISTS))
		nm_spawn_process ("/etc/rc.d/nscd restart");
}

