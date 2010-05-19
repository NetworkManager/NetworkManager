/* NetworkManager -- Network link manager
 *
 * Implementation for the Frugalware Linux distro - http://www.frugalware.org
 *
 * Alex Smith <alex.extreme2@gmail.com>
 *
 * Based on NetworkManagerSlackware.c by Narayan Newton <narayan_newton@yahoo.com>
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
 * (C) Copyright 2006 Alex Smith
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "nm-system.h"

/* Provided by the frugalwareutils package on Frugalware */
#include <libfwnetconfig.h> 

/*
 * nm_system_enable_loopback
 *
 * Bring up the loopback interface
 *
 */
void nm_system_enable_loopback (void)
{
	fwnet_loup ();
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
	/* I'm not running nscd */
}

