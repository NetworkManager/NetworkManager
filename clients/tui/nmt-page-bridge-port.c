/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-page-bridge-port
 * @short_description: The editor page for Bridge ports
 */

#include "config.h"

#include <glib.h>
#include <glib/gi18n-lib.h>

#include "nmt-page-bridge-port.h"

G_DEFINE_TYPE (NmtPageBridgePort, nmt_page_bridge_port, NMT_TYPE_EDITOR_PAGE)

NmtNewtWidget *
nmt_page_bridge_port_new (NMConnection *conn)
{
	return g_object_new (NMT_TYPE_PAGE_BRIDGE_PORT,
	                     "connection", conn,
	                     "title", _("BRIDGE PORT"),
	                     NULL);
}

static void
nmt_page_bridge_port_init (NmtPageBridgePort *bridge)
{
}

static void
nmt_page_bridge_port_constructed (GObject *object)
{
	NmtPageBridgePort *bridge = NMT_PAGE_BRIDGE_PORT (object);
	NmtPageGrid *grid;
	NMSettingBridgePort *s_port;
	NmtNewtWidget *widget;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (bridge));
	s_port = nm_connection_get_setting_bridge_port (conn);
	if (!s_port) {
		nm_connection_add_setting (conn, nm_setting_bridge_port_new ());
		s_port = nm_connection_get_setting_bridge_port (conn);
	}

	grid = NMT_PAGE_GRID (bridge);

	widget = nmt_newt_entry_numeric_new (10, 0, 63);
	g_object_bind_property (s_port, NM_SETTING_BRIDGE_PORT_PRIORITY,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_page_grid_append (grid, _("Priority"), widget, NULL);

	widget = nmt_newt_entry_numeric_new (10, 1, 65535);
	g_object_bind_property (s_port, NM_SETTING_BRIDGE_PORT_PATH_COST,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_page_grid_append (grid, _("Path cost"), widget, NULL);

	widget = nmt_newt_checkbox_new (_("Hairpin mode"));
	g_object_bind_property (s_port, NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_page_grid_append (grid, NULL, widget, NULL);

	G_OBJECT_CLASS (nmt_page_bridge_port_parent_class)->constructed (object);
}

static void
nmt_page_bridge_port_class_init (NmtPageBridgePortClass *bridge_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (bridge_class);

	object_class->constructed = nmt_page_bridge_port_constructed;
}
