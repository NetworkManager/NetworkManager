/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
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
 * (C) Copyright 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-connection.h"

#include "nm-device-ethernet-utils.h"

char *
nm_device_ethernet_utils_get_default_wired_name (NMConnection *const *connections)
{
	char *temp;
	guint j;
	int i;

	/* Find the next available unique connection name */
	for (i = 1; i <= 10000; i++) {
		temp = g_strdup_printf (_("Wired connection %d"), i);
		for (j = 0; connections[j]; j++) {
			if (nm_streq0 (nm_connection_get_id (connections[j]), temp)) {
				g_free (temp);
				goto next;
			}
		}
		return temp;
next:
		;
	}

	return NULL;
}

