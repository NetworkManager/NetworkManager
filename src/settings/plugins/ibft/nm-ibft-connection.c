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
 * Copyright 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#include <glib/gstdio.h>

#include "nm-ibft-connection.h"
#include "reader.h"

G_DEFINE_TYPE (NMIbftConnection, nm_ibft_connection, NM_TYPE_SETTINGS_CONNECTION)

NMIbftConnection *
nm_ibft_connection_new (const GPtrArray *block, GError **error)
{
	NMConnection *source;
	GObject *object;

	source = connection_from_block (block, error);
	if (!source)
		return NULL;

	object = g_object_new (NM_TYPE_IBFT_CONNECTION, NULL);
	/* Update settings with what was read from iscsiadm */
	if (!nm_settings_connection_replace_settings (NM_SETTINGS_CONNECTION (object),
	                                              source,
	                                              FALSE,
	                                              NULL,
	                                              error))
		g_clear_object (&object);

	return (NMIbftConnection *) object;
}

/* GObject */

static void
nm_ibft_connection_init (NMIbftConnection *connection)
{
}

static void
nm_ibft_connection_class_init (NMIbftConnectionClass *ibft_connection_class)
{
}

