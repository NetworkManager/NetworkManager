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

#include "nm-default.h"

#include "nmt-page-bridge.h"

#include "nmt-address-list.h"
#include "nmt-slave-list.h"

G_DEFINE_TYPE (NmtPageBridge, nmt_page_bridge, NMT_TYPE_EDITOR_PAGE_DEVICE)

#define NMT_PAGE_BRIDGE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_PAGE_BRIDGE, NmtPageBridgePrivate))

typedef struct {
        NmtSlaveList *slaves;
} NmtPageBridgePrivate;

NmtEditorPage *
nmt_page_bridge_new (NMConnection   *conn,
                     NmtDeviceEntry *deventry)
{
	return g_object_new (NMT_TYPE_PAGE_BRIDGE,
	                     "connection", conn,
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
	NmtPageBridgePrivate *priv = NMT_PAGE_BRIDGE_GET_PRIVATE (bridge);
	NmtEditorSection *section;
	NmtEditorGrid *grid;
	NMSettingBridge *s_bridge;
	NmtNewtWidget *widget, *label, *stp;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (bridge));
	s_bridge = nm_connection_get_setting_bridge (conn);
	if (!s_bridge) {
		nm_connection_add_setting (conn, nm_setting_bridge_new ());
		s_bridge = nm_connection_get_setting_bridge (conn);
	}

	section = nmt_editor_section_new (_("BRIDGE"), NULL, TRUE);
	grid = nmt_editor_section_get_body (section);

	widget = nmt_newt_separator_new ();
	nmt_editor_grid_append (grid, _("Slaves"), widget, NULL);
	nmt_editor_grid_set_row_flags (grid, widget, NMT_EDITOR_GRID_ROW_LABEL_ALIGN_LEFT);

	widget = nmt_slave_list_new (conn, bridge_connection_type_filter, bridge);
	nmt_editor_grid_append (grid, NULL, widget, NULL);
	priv->slaves = NMT_SLAVE_LIST (widget);

	widget = nmt_newt_entry_numeric_new (10, 0, 1000000);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_AGEING_TIME,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	label = nmt_newt_label_new (_("seconds"));
	nmt_editor_grid_append (grid, _("Aging time"), widget, label);

	widget = nmt_newt_checkbox_new (_("Enable IGMP snooping"));
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_MULTICAST_SNOOPING,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	widget = stp = nmt_newt_checkbox_new (_("Enable STP (Spanning Tree Protocol)"));
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_STP,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_entry_numeric_new (10, 0, G_MAXINT);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_PRIORITY,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_STP,
	                        widget, "sensitive",
	                        G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Priority"), widget, NULL);

	widget = nmt_newt_entry_numeric_new (10, 2, 30);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_FORWARD_DELAY,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_STP,
	                        widget, "sensitive",
	                        G_BINDING_SYNC_CREATE);
	label = nmt_newt_label_new (_("seconds"));
	nmt_editor_grid_append (grid, _("Forward delay"), widget, label);

	widget = nmt_newt_entry_numeric_new (10, 1, 10);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_HELLO_TIME,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_STP,
	                        widget, "sensitive",
	                        G_BINDING_SYNC_CREATE);
	label = nmt_newt_label_new (_("seconds"));
	nmt_editor_grid_append (grid, _("Hello time"), widget, label);

	widget = nmt_newt_entry_numeric_new (10, 6, 40);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_MAX_AGE,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_STP,
	                        widget, "sensitive",
	                        G_BINDING_SYNC_CREATE);
	label = nmt_newt_label_new (_("seconds"));
	nmt_editor_grid_append (grid, _("Max age"), widget, label);

	widget = nmt_newt_entry_numeric_new (10, 0, 65535);
	g_object_bind_property (s_bridge, NM_SETTING_BRIDGE_GROUP_FORWARD_MASK,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Group forward mask"), widget, NULL);

	nmt_editor_page_add_section (NMT_EDITOR_PAGE (bridge), section);

	G_OBJECT_CLASS (nmt_page_bridge_parent_class)->constructed (object);
}

static void
nmt_page_bridge_saved (NmtEditorPage *editor_page)
{
	NmtPageBridgePrivate *priv = NMT_PAGE_BRIDGE_GET_PRIVATE (editor_page);

	nmt_edit_connection_list_recommit (NMT_EDIT_CONNECTION_LIST (priv->slaves));
}

static void
nmt_page_bridge_class_init (NmtPageBridgeClass *bridge_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (bridge_class);
	NmtEditorPageClass *editor_page_class = NMT_EDITOR_PAGE_CLASS (bridge_class);

	object_class->constructed = nmt_page_bridge_constructed;
	editor_page_class->saved = nmt_page_bridge_saved;
}
