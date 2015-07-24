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

#include "config.h"

#include <string.h>
#include <glib/gi18n.h>

#include <nm-connection.h>
#include "nm-glib.h"
#include "nm-device-ethernet-utils.h"

char *
nm_device_ethernet_utils_get_default_wired_name (const GSList *connections)
{
	const GSList *iter;
	char *cname = NULL;
	int i = 0;

	/* Find the next available unique connection name */
	while (!cname && (i++ < 10000)) {
		char *temp;
		gboolean found = FALSE;

		temp = g_strdup_printf (_("Wired connection %d"), i);
		for (iter = connections; iter; iter = iter->next) {
			if (g_strcmp0 (nm_connection_get_id (NM_CONNECTION (iter->data)), temp) == 0) {
				found = TRUE;
				g_free (temp);
				break;
			}
		}

		if (found == FALSE)
			cname = temp;
	}

	return cname;
}

