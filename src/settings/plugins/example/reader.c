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
#include <NetworkManager.h>

#include "common.h"

NMConnection *
connection_from_file (const char *filename, GError **error)
{
	/* This function should, given a file path, read that file and convert its
	 * data into an NMConnection.  There are two approaches to this.  First,
	 * if the plugin data format is similar to the NMConnection internal
	 * format, you can get away with calling nm_connection_for_each_setting_value()
	 * to iterate through every possible setting's keys and read that value
	 * from the plugin's format.  If the plugin's format is siginificantly
	 * different then you may have to build up the connection manually by
	 * determining the type of connection from the on-disk data, creating
	 * each setting object, adding the values, then adding that setting to
	 * the NMConnection.
	 */

	return NULL;
}

