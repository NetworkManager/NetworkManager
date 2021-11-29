/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Red Hat, Inc.
 */
/**
 * SECTION:nmt-page-wireguard
 * @short_description: The editor page for WireGuard connections
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmt-page-wireguard.h"

#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "nmt-device-entry.h"
#include "nmt-mtu-entry.h"
#include "nmt-wireguard-peer-list.h"

G_DEFINE_TYPE(NmtPageWireGuard, nmt_page_wireguard, NMT_TYPE_EDITOR_PAGE_DEVICE)

#define NMT_PAGE_WIREGUARD_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NMT_TYPE_PAGE_WIREGUARD, NmtPageWireGuardPrivate))

typedef struct {
    NmtWireguardPeerList *peers;
} NmtPageWireGuardPrivate;

NmtEditorPage *
nmt_page_wireguard_new(NMConnection *conn, NmtDeviceEntry *deventry)
{
    return g_object_new(NMT_TYPE_PAGE_WIREGUARD,
                        "connection",
                        conn,
                        "device-entry",
                        deventry,
                        NULL);
}

static void
nmt_page_wireguard_init(NmtPageWireGuard *wireguard)
{}

static void
nmt_page_wireguard_constructed(GObject *object)
{
    NmtPageWireGuard        *wireguard = NMT_PAGE_WIREGUARD(object);
    NmtPageWireGuardPrivate *priv      = NMT_PAGE_WIREGUARD_GET_PRIVATE(wireguard);
    NmtEditorSection        *section;
    NmtEditorGrid           *grid;
    NMSettingWireGuard      *s_wireguard;
    NmtNewtWidget           *widget;
    NMConnection            *conn;

    conn        = nmt_editor_page_get_connection(NMT_EDITOR_PAGE(wireguard));
    s_wireguard = _nm_connection_ensure_setting(conn, NM_TYPE_SETTING_WIREGUARD);

    section = nmt_editor_section_new(_("WireGuard"), NULL, TRUE);
    grid    = nmt_editor_section_get_body(section);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(grid, _("Private key"), widget, NULL);
    g_object_bind_property(s_wireguard,
                           NM_SETTING_WIREGUARD_PRIVATE_KEY,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(grid, _("Listen port"), widget, NULL);
    g_object_bind_property(s_wireguard,
                           NM_SETTING_WIREGUARD_LISTEN_PORT,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(grid, _("Fwmark"), widget, NULL);
    g_object_bind_property(s_wireguard,
                           NM_SETTING_WIREGUARD_FWMARK,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_mtu_entry_new();
    nmt_editor_grid_append(grid, _("MTU"), widget, NULL);
    g_object_bind_property(s_wireguard,
                           NM_SETTING_WIREGUARD_MTU,
                           widget,
                           "mtu",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_newt_checkbox_new(_("Add peer routes"));
    nmt_editor_grid_append(grid, NULL, widget, NULL);
    g_object_bind_property(s_wireguard,
                           NM_SETTING_WIREGUARD_PEER_ROUTES,
                           widget,
                           "active",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_newt_separator_new();
    nmt_editor_grid_append(grid, _("Peers"), widget, NULL);
    nmt_editor_grid_set_row_flags(grid, widget, NMT_EDITOR_GRID_ROW_LABEL_ALIGN_LEFT);

    widget = nmt_wireguard_peer_list_new(s_wireguard);
    nmt_editor_grid_append(grid, NULL, widget, NULL);
    priv->peers = NMT_WIREGUARD_PEER_LIST(widget);

    nmt_editor_page_add_section(NMT_EDITOR_PAGE(wireguard), section);

    G_OBJECT_CLASS(nmt_page_wireguard_parent_class)->constructed(object);
}

static void
nmt_page_wireguard_class_init(NmtPageWireGuardClass *wireguard_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(wireguard_class);

    g_type_class_add_private(wireguard_class, sizeof(NmtPageWireGuardPrivate));

    object_class->constructed = nmt_page_wireguard_constructed;
}
