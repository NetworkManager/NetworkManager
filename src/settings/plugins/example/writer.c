/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * Copyright (C) 2012 Red Hat, Inc.
 */

#include <config.h>
#include <glib.h>

#include <nm-connection.h>

#include "common.h"

gboolean
write_connection (NMConnection *connection,
                  const char *existing_path,
                  char **out_path,
                  GError **error)
{
	/* This function should take the NMConnection and convert it to the format
	 * which this plugin uses on-disk and then write out that data.  It returns
	 * the file path of the file that represents this connection data so that
	 * the plugin can track it for change notification and updates.  If
	 * 'existing_path' is given we can assume that this is an update of an
	 * existing connection and not a completely new one.
	 */

	/* There are two approaches to converting the data.  The first more manual
	 * approach consists of grabbing each setting value from the NMConnection
	 * and converting it into the appropriate value for the plugin's data
	 * format.  This is usually taken by distro plugins because their format
	 * is significantly different than NetworkManager's internal format.
	 * The second uses nm_connection_for_each_setting_value() to iterate
	 * through each value of each setting in the NMConnection, convert it to
	 * the required format, and write it out, but this requires that the
	 * plugin format more closely follow the NetworkManager internal format.
	 */

	return FALSE;
}

