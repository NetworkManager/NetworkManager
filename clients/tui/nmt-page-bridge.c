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
 * SECTION:nmt-page-bridge
 * @short_description: The editor page for Bridge connections
 */

#include "config.h"

#include <glib.h>
#include <glib/gi18n-lib.h>

#include "nmt-page-bridge.h"

#include "nmt-address-list.h"
#include "nmt-slave-list.h"

G_DEFINE_TYPE (NmtPageBridge, nmt_page_bridge, NMT_TYPE_PAGE_DEVICE)

NmtNewtWidget *
nmt_page_bridge_new (NMConnection   *conn,
                     NmtDeviceEntry *deventry)
{
	return g_object_new (NMT_TYPE_PAGE_BRIDGE,
	                     "connection", conn,
	                     "title", _("BRIDGE"),
	                     "device-entry", deventry,
	                     NULL);
}

static void
nmt_page_bridge_init (NmtPageBridge *bridge)
{
}

static gboolean
bridge_connection_type_filter (GType    connection_type,
                               gpointer user_data)
{
	return (   connection_type == NM_TYPE_SETTING_WIRED
	        || connection_type == NM_TYPE_SETTING_WIRELESS
	        || connection_type == NM_TYPE_SETTING_VLAN);
}

static void
nmt_page_bridge_constructed (GObject *object)
{
	NmtPageBridge *bridge = NMT_PAGE_BRIDGE (object);
	NmtDeviceEntry *deventry;
	NmtPageGrid *grid;
	NMSettingBridge *s_bridge;
	NmtNewtWidget *widget, *label, *stp;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (bridge));
	s_bridge = nm_connection_get_setting_bridge (conn);
	if (!s_bridge) {
		nm_connection_add_setting (conn, nm_setting_bridge_new ());
		s_bridge = nm_connection_get_setting_bridge (conn);
	}

	deventry = nmt_page_device_get_device_entry (NMT_PAGE_DEVICE (object));
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_INTERFACE_NAME,
	                        deventry, "interface-name",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

	grid = NMT_PAGE_GRID (bridge);

	widget = nmt_newt_separator_new ();
	nmt_page_grid_append (grid, _("Slaves"), widget, NULL);
	nmt_page_grid_set_row_flags (grid, widget, NMT_PAGE_GRID_ROW_LABEL_ALIGN_LEFT);

	widget = nmt_slave_list_new (conn, bridge_connection_type_filter, bridge);
	nmt_page_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_entry_numeric_new (10, 0, 1000000);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_AGEING_TIME,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	label = nmt_newt_label_new (_("seconds"));
	nmt_page_grid_append (grid, _("Aging time"), widget, label);

	widget = stp = nmt_newt_checkbox_new (_("Enable STP (Spanning Tree Protocol)"));
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_STP,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_page_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_entry_numeric_new (10, 0, G_MAXINT);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_PRIORITY,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_STP,
	                        widget, "sensitive",
	                        G_BINDING_SYNC_CREATE);
	nmt_page_grid_append (grid, _("Priority"), widget, NULL);

	widget = nmt_newt_entry_numeric_new (10, 2, 30);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_FORWARD_DELAY,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_STP,
	                        widget, "sensitive",
	                        G_BINDING_SYNC_CREATE);
	label = nmt_newt_label_new (_("seconds"));
	nmt_page_grid_append (grid, _("Forward delay"), widget, label);

	widget = nmt_newt_entry_numeric_new (10, 1, 10);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_HELLO_TIME,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_STP,
	                        widget, "sensitive",
	                        G_BINDING_SYNC_CREATE);
	label = nmt_newt_label_new (_("seconds"));
	nmt_page_grid_append (grid, _("Hello time"), widget, label);

	widget = nmt_newt_entry_numeric_new (10, 6, 40);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_MAX_AGE,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_STP,
	                        widget, "sensitive",
	                        G_BINDING_SYNC_CREATE);
	label = nmt_newt_label_new (_("seconds"));
	nmt_page_grid_append (grid, _("Max age"), widget, label);

	G_OBJECT_CLASS (nmt_page_bridge_parent_class)->constructed (object);
}

static void
nmt_page_bridge_class_init (NmtPageBridgeClass *bridge_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (bridge_class);

	object_class->constructed = nmt_page_bridge_constructed;
}
