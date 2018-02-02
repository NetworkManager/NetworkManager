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
 * SECTION:nmt-page-team-port
 * @short_description: The editor page for Team ports.
 */

#include "nm-default.h"

#include "nmt-page-team-port.h"

G_DEFINE_TYPE (NmtPageTeamPort, nmt_page_team_port, NMT_TYPE_EDITOR_PAGE)

#define NMT_PAGE_TEAM_PORT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_PAGE_TEAM_PORT, NmtPageTeamPortPrivate))

typedef struct {
	NMSettingTeamPort *s_port;

} NmtPageTeamPortPrivate;

NmtEditorPage *
nmt_page_team_port_new (NMConnection *conn)
{
	return g_object_new (NMT_TYPE_PAGE_TEAM_PORT,
	                     "connection", conn,
	                     NULL);
}

static void
nmt_page_team_port_init (NmtPageTeamPort *team)
{
}

static void
edit_clicked (NmtNewtButton *button,
              gpointer       user_data)
{
	NmtPageTeamPort *team = user_data;
	NmtPageTeamPortPrivate *priv = NMT_PAGE_TEAM_PORT_GET_PRIVATE (team);
	const char *config;
	char *new_config;

	config = nm_setting_team_port_get_config (priv->s_port);
	if (!config)
		config = "";

	new_config = nmt_newt_edit_string (config);

	if (new_config && !*new_config)
		g_clear_pointer (&new_config, g_free);
	g_object_set (G_OBJECT (priv->s_port),
	              NM_SETTING_TEAM_PORT_CONFIG, new_config,
	              NULL);
	g_free (new_config);
}

static void
nmt_page_team_port_constructed (GObject *object)
{
	NmtPageTeamPort *team = NMT_PAGE_TEAM_PORT (object);
	NmtPageTeamPortPrivate *priv = NMT_PAGE_TEAM_PORT_GET_PRIVATE (team);
	NmtEditorSection *section;
	NmtNewtGrid *grid;
	NMSettingTeamPort *s_port;
	NmtNewtWidget *widget;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (team));
	s_port = nm_connection_get_setting_team_port (conn);
	if (!s_port) {
		nm_connection_add_setting (conn, nm_setting_team_port_new ());
		s_port = nm_connection_get_setting_team_port (conn);
	}
	priv->s_port = s_port;

	section = nmt_editor_section_new (_("TEAM PORT"), NULL, TRUE);

	widget = nmt_newt_grid_new ();
	nmt_editor_grid_append (nmt_editor_section_get_body (section), NULL, widget, NULL);

	grid = NMT_NEWT_GRID (widget);

	widget = nmt_newt_label_new (_("JSON configuration"));
	nmt_newt_grid_add (grid, widget, 0, 2);

	widget = nmt_newt_textbox_new (NMT_NEWT_TEXTBOX_SCROLLABLE | NMT_NEWT_TEXTBOX_SET_BACKGROUND, 60);
	g_object_bind_property (s_port, NM_SETTING_TEAM_PORT_CONFIG,
	                        widget, "text",
	                        G_BINDING_SYNC_CREATE);
	nmt_newt_grid_add (grid, widget, 0, 3);
	nmt_newt_widget_set_padding (widget, 2, 0, 2, 1);

	widget = nmt_newt_button_new (_("Edit..."));
	g_signal_connect (widget, "clicked", G_CALLBACK (edit_clicked), team);
	nmt_newt_grid_add (grid, widget, 0, 4);

	nmt_editor_page_add_section (NMT_EDITOR_PAGE (team), section);

	G_OBJECT_CLASS (nmt_page_team_port_parent_class)->constructed (object);
}

static void
nmt_page_team_port_class_init (NmtPageTeamPortClass *team_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (team_class);

	g_type_class_add_private (team_class, sizeof (NmtPageTeamPortPrivate));

	object_class->constructed = nmt_page_team_port_constructed;
}
