/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-page-team
 * @short_description: The editor page for Team connections
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmt-page-team.h"

#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "nmt-port-list.h"

G_DEFINE_TYPE(NmtPageTeam, nmt_page_team, NMT_TYPE_EDITOR_PAGE_DEVICE)

#define NMT_PAGE_TEAM_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NMT_TYPE_PAGE_TEAM, NmtPageTeamPrivate))

typedef struct {
    NmtPortList *ports;

    NMSettingTeam *s_team;
    GType          port_type;

} NmtPageTeamPrivate;

NmtEditorPage *
nmt_page_team_new(NMConnection *conn, NmtDeviceEntry *deventry)
{
    return g_object_new(NMT_TYPE_PAGE_TEAM, "connection", conn, "device-entry", deventry, NULL);
}

static void
nmt_page_team_init(NmtPageTeam *team)
{
    NmtPageTeamPrivate *priv = NMT_PAGE_TEAM_GET_PRIVATE(team);

    priv->port_type = G_TYPE_NONE;
}

static void
ports_changed(GObject *object, GParamSpec *pspec, gpointer user_data)
{
    NmtPageTeam        *team = NMT_PAGE_TEAM(user_data);
    NmtPageTeamPrivate *priv = NMT_PAGE_TEAM_GET_PRIVATE(team);
    GPtrArray          *ports;

    g_object_get(object, "connections", &ports, NULL);
    if (ports->len == 0) {
        priv->port_type = G_TYPE_NONE;
    } else if (priv->port_type == G_TYPE_NONE) {
        NMConnection *port = ports->pdata[0];

        if (nm_connection_is_type(port, NM_SETTING_INFINIBAND_SETTING_NAME))
            priv->port_type = NM_TYPE_SETTING_INFINIBAND;
        else
            priv->port_type = NM_TYPE_SETTING_WIRED;
    }
}

static gboolean
team_connection_type_filter(GType connection_type, gpointer user_data)
{
    NmtPageTeam        *team = user_data;
    NmtPageTeamPrivate *priv = NMT_PAGE_TEAM_GET_PRIVATE(team);

    if (priv->port_type != NM_TYPE_SETTING_WIRED) {
        if (connection_type == NM_TYPE_SETTING_INFINIBAND)
            return TRUE;
    }
    if (priv->port_type != NM_TYPE_SETTING_INFINIBAND) {
        if (connection_type == NM_TYPE_SETTING_WIRED || connection_type == NM_TYPE_SETTING_WIRELESS
            || connection_type == NM_TYPE_SETTING_VLAN)
            return TRUE;
    }

    return FALSE;
}

static void
edit_clicked(NmtNewtButton *button, gpointer user_data)
{
    NmtPageTeam        *team = user_data;
    NmtPageTeamPrivate *priv = NMT_PAGE_TEAM_GET_PRIVATE(team);
    const char         *config;
    char               *new_config;

    config = nm_setting_team_get_config(priv->s_team);
    if (!config)
        config = "";

    new_config = nmt_newt_edit_string(config);

    if (new_config && !*new_config)
        nm_clear_g_free(&new_config);
    g_object_set(G_OBJECT(priv->s_team), NM_SETTING_TEAM_CONFIG, new_config, NULL);
    g_free(new_config);
}

static void
nmt_page_team_constructed(GObject *object)
{
    NmtPageTeam        *team = NMT_PAGE_TEAM(object);
    NmtPageTeamPrivate *priv = NMT_PAGE_TEAM_GET_PRIVATE(team);
    NmtEditorSection   *section;
    NmtNewtGrid        *grid;
    NMSettingTeam      *s_team;
    NmtNewtWidget      *widget;
    NMConnection       *conn;

    conn         = nmt_editor_page_get_connection(NMT_EDITOR_PAGE(team));
    s_team       = _nm_connection_ensure_setting(conn, NM_TYPE_SETTING_TEAM);
    priv->s_team = s_team;

    section = nmt_editor_section_new(_("TEAM"), NULL, TRUE);

    widget = nmt_newt_grid_new();
    nmt_editor_grid_append(nmt_editor_section_get_body(section), NULL, widget, NULL);

    grid = NMT_NEWT_GRID(widget);

    widget = nmt_newt_label_new(_("Ports"));
    nmt_newt_grid_add(grid, widget, 0, 0);

    widget = nmt_port_list_new(conn, team_connection_type_filter, team);
    g_signal_connect(widget, "notify::connections", G_CALLBACK(ports_changed), team);
    nmt_newt_grid_add(grid, widget, 0, 1);
    nmt_newt_widget_set_padding(widget, 0, 0, 0, 1);
    priv->ports = NMT_PORT_LIST(widget);
    ports_changed(G_OBJECT(priv->ports), NULL, team);

    widget = nmt_newt_label_new(_("JSON configuration"));
    nmt_newt_grid_add(grid, widget, 0, 2);

    widget =
        nmt_newt_textbox_new(NMT_NEWT_TEXTBOX_SCROLLABLE | NMT_NEWT_TEXTBOX_SET_BACKGROUND, 60);
    g_object_bind_property(s_team, NM_SETTING_TEAM_CONFIG, widget, "text", G_BINDING_SYNC_CREATE);
    nmt_newt_grid_add(grid, widget, 0, 3);
    nmt_newt_widget_set_padding(widget, 2, 0, 2, 1);

    widget = nmt_newt_button_new(_("Edit..."));
    g_signal_connect(widget, "clicked", G_CALLBACK(edit_clicked), team);
    nmt_newt_grid_add(grid, widget, 0, 4);

    nmt_editor_page_add_section(NMT_EDITOR_PAGE(team), section);

    G_OBJECT_CLASS(nmt_page_team_parent_class)->constructed(object);
}

static void
nmt_page_team_saved(NmtEditorPage *editor_page)
{
    NmtPageTeamPrivate *priv = NMT_PAGE_TEAM_GET_PRIVATE(editor_page);

    nmt_edit_connection_list_recommit(NMT_EDIT_CONNECTION_LIST(priv->ports));
}

static void
nmt_page_team_class_init(NmtPageTeamClass *team_class)
{
    GObjectClass       *object_class      = G_OBJECT_CLASS(team_class);
    NmtEditorPageClass *editor_page_class = NMT_EDITOR_PAGE_CLASS(team_class);

    g_type_class_add_private(team_class, sizeof(NmtPageTeamPrivate));

    object_class->constructed = nmt_page_team_constructed;
    editor_page_class->saved  = nmt_page_team_saved;
}
