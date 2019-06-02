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
 * SECTION:nmt-page-team
 * @short_description: The editor page for Team connections
 */

#include "nm-default.h"

#include "nmt-page-team.h"

#include "nmt-slave-list.h"

G_DEFINE_TYPE (NmtPageTeam, nmt_page_team, NMT_TYPE_EDITOR_PAGE_DEVICE)

#define NMT_PAGE_TEAM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_PAGE_TEAM, NmtPageTeamPrivate))

typedef struct {
	NmtSlaveList *slaves;

	NMSettingTeam *s_team;
	GType slave_type;

} NmtPageTeamPrivate;

NmtEditorPage *
nmt_page_team_new (NMConnection   *conn,
                   NmtDeviceEntry *deventry)
{
	return g_object_new (NMT_TYPE_PAGE_TEAM,
	                     "connection", conn,
	                     "device-entry", deventry,
	                     NULL);
}

static void
nmt_page_team_init (NmtPageTeam *team)
{
	NmtPageTeamPrivate *priv = NMT_PAGE_TEAM_GET_PRIVATE (team);

	priv->slave_type = G_TYPE_NONE;
}

static void
slaves_changed (GObject    *object,
                GParamSpec *pspec,
                gpointer    user_data)
{
	NmtPageTeam *team = NMT_PAGE_TEAM (user_data);
	NmtPageTeamPrivate *priv = NMT_PAGE_TEAM_GET_PRIVATE (team);
	GPtrArray *slaves;

	g_object_get (object, "connections", &slaves, NULL);
	if (slaves->len == 0) {
		priv->slave_type = G_TYPE_NONE;
	} else if (priv->slave_type == G_TYPE_NONE) {
		NMConnection *slave = slaves->pdata[0];

		if (nm_connection_is_type (slave, NM_SETTING_INFINIBAND_SETTING_NAME))
			priv->slave_type = NM_TYPE_SETTING_INFINIBAND;
		else
			priv->slave_type = NM_TYPE_SETTING_WIRED;
	}
}

static gboolean
team_connection_type_filter (GType    connection_type,
                             gpointer user_data)
{
	NmtPageTeam *team = user_data;
	NmtPageTeamPrivate *priv = NMT_PAGE_TEAM_GET_PRIVATE (team);

	if (priv->slave_type != NM_TYPE_SETTING_WIRED) {
		if (connection_type == NM_TYPE_SETTING_INFINIBAND)
			return TRUE;
	}
	if (priv->slave_type != NM_TYPE_SETTING_INFINIBAND) {
		if (   connection_type == NM_TYPE_SETTING_WIRED
		    || connection_type == NM_TYPE_SETTING_WIRELESS
		    || connection_type == NM_TYPE_SETTING_VLAN)
			return TRUE;
	}

	return FALSE;
}

static void
edit_clicked (NmtNewtButton *button,
              gpointer       user_data)
{
	NmtPageTeam *team = user_data;
	NmtPageTeamPrivate *priv = NMT_PAGE_TEAM_GET_PRIVATE (team);
	const char *config;
	char *new_config;

	config = nm_setting_team_get_config (priv->s_team);
	if (!config)
		config = "";

	new_config = nmt_newt_edit_string (config);

	if (new_config && !*new_config)
		g_clear_pointer (&new_config, g_free);
	g_object_set (G_OBJECT (priv->s_team),
	              NM_SETTING_TEAM_CONFIG, new_config,
	              NULL);
	g_free (new_config);
}

static void
nmt_page_team_constructed (GObject *object)
{
	NmtPageTeam *team = NMT_PAGE_TEAM (object);
	NmtPageTeamPrivate *priv = NMT_PAGE_TEAM_GET_PRIVATE (team);
	NmtEditorSection *section;
	NmtNewtGrid *grid;
	NMSettingTeam *s_team;
	NmtNewtWidget *widget;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (team));
	s_team = nm_connection_get_setting_team (conn);
	if (!s_team) {
		nm_connection_add_setting (conn, nm_setting_team_new ());
		s_team = nm_connection_get_setting_team (conn);
	}
	priv->s_team = s_team;

	section = nmt_editor_section_new (_("TEAM"), NULL, TRUE);

	widget = nmt_newt_grid_new ();
	nmt_editor_grid_append (nmt_editor_section_get_body (section), NULL, widget, NULL);

	grid = NMT_NEWT_GRID (widget);

	widget = nmt_newt_label_new (_("Slaves"));
	nmt_newt_grid_add (grid, widget, 0, 0);

	widget = nmt_slave_list_new (conn, team_connection_type_filter, team);
	g_signal_connect (widget, "notify::connections",
	                  G_CALLBACK (slaves_changed), team);
	nmt_newt_grid_add (grid, widget, 0, 1);
	nmt_newt_widget_set_padding (widget, 0, 0, 0, 1);
	priv->slaves = NMT_SLAVE_LIST (widget);
	slaves_changed (G_OBJECT (priv->slaves), NULL, team);

	widget = nmt_newt_label_new (_("JSON configuration"));
	nmt_newt_grid_add (grid, widget, 0, 2);

	widget = nmt_newt_textbox_new (NMT_NEWT_TEXTBOX_SCROLLABLE | NMT_NEWT_TEXTBOX_SET_BACKGROUND, 60);
	g_object_bind_property (s_team, NM_SETTING_TEAM_CONFIG,
	                        widget, "text",
	                        G_BINDING_SYNC_CREATE);
	nmt_newt_grid_add (grid, widget, 0, 3);
	nmt_newt_widget_set_padding (widget, 2, 0, 2, 1);

	widget = nmt_newt_button_new (_("Edit..."));
	g_signal_connect (widget, "clicked", G_CALLBACK (edit_clicked), team);
	nmt_newt_grid_add (grid, widget, 0, 4);

	nmt_editor_page_add_section (NMT_EDITOR_PAGE (team), section);

	G_OBJECT_CLASS (nmt_page_team_parent_class)->constructed (object);
}

static void
nmt_page_team_saved (NmtEditorPage *editor_page)
{
	NmtPageTeamPrivate *priv = NMT_PAGE_TEAM_GET_PRIVATE (editor_page);

	nmt_edit_connection_list_recommit (NMT_EDIT_CONNECTION_LIST (priv->slaves));
}

static void
nmt_page_team_class_init (NmtPageTeamClass *team_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (team_class);
	NmtEditorPageClass *editor_page_class = NMT_EDITOR_PAGE_CLASS (team_class);

	g_type_class_add_private (team_class, sizeof (NmtPageTeamPrivate));

	object_class->constructed = nmt_page_team_constructed;
	editor_page_class->saved = nmt_page_team_saved;
}
