// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-page-bridge-port
 * @short_description: The editor page for Bridge ports
 */

#include "nm-default.h"

#include "nmt-page-bridge-port.h"

G_DEFINE_TYPE (NmtPageBridgePort, nmt_page_bridge_port, NMT_TYPE_EDITOR_PAGE)

NmtEditorPage *
nmt_page_bridge_port_new (NMConnection *conn)
{
	return g_object_new (NMT_TYPE_PAGE_BRIDGE_PORT,
	                     "connection", conn,
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
	NmtEditorSection *section;
	NmtEditorGrid *grid;
	NMSettingBridgePort *s_port;
	NmtNewtWidget *widget;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (bridge));
	s_port = nm_connection_get_setting_bridge_port (conn);
	if (!s_port) {
		nm_connection_add_setting (conn, nm_setting_bridge_port_new ());
		s_port = nm_connection_get_setting_bridge_port (conn);
	}

	section = nmt_editor_section_new (_("BRIDGE PORT"), NULL, TRUE);
	grid = nmt_editor_section_get_body (section);

	widget = nmt_newt_entry_numeric_new (10, 0, 63);
	g_object_bind_property (s_port, NM_SETTING_BRIDGE_PORT_PRIORITY,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Priority"), widget, NULL);

	widget = nmt_newt_entry_numeric_new (10, 1, 65535);
	g_object_bind_property (s_port, NM_SETTING_BRIDGE_PORT_PATH_COST,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Path cost"), widget, NULL);

	widget = nmt_newt_checkbox_new (_("Hairpin mode"));
	g_object_bind_property (s_port, NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	nmt_editor_page_add_section (NMT_EDITOR_PAGE (bridge), section);

	G_OBJECT_CLASS (nmt_page_bridge_port_parent_class)->constructed (object);
}

static void
nmt_page_bridge_port_class_init (NmtPageBridgePortClass *bridge_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (bridge_class);

	object_class->constructed = nmt_page_bridge_port_constructed;
}
