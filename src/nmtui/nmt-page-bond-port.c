/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2021 Red Hat, Inc.
 */

/**
 * SECTION:nmt-page-bond-port
 * @short_description: The editor page for Bond ports
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmt-page-bond-port.h"

#include "libnm-core-aux-intern/nm-libnm-core-utils.h"

G_DEFINE_TYPE(NmtPageBondPort, nmt_page_bond_port, NMT_TYPE_EDITOR_PAGE)

static void
nmt_page_bond_port_init(NmtPageBondPort *bond)
{}

NmtEditorPage *
nmt_page_bond_port_new(NMConnection *conn)
{
    return g_object_new(NMT_TYPE_PAGE_BOND_PORT, "connection", conn, NULL);
}

static void
nmt_page_bond_port_constructed(GObject *object)
{
    NmtPageBondPort   *bond = NMT_PAGE_BOND_PORT(object);
    NmtEditorSection  *section;
    NmtEditorGrid     *grid;
    NMSettingBondPort *s_port;
    NmtNewtWidget     *widget;
    NMConnection      *conn;

    conn   = nmt_editor_page_get_connection(NMT_EDITOR_PAGE(bond));
    s_port = _nm_connection_ensure_setting(conn, NM_TYPE_SETTING_BOND_PORT);

    section = nmt_editor_section_new(_("BOND PORT"), NULL, TRUE);
    grid    = nmt_editor_section_get_body(section);

    widget = nmt_newt_entry_numeric_new(10, 0, 63);
    g_object_bind_property(s_port,
                           NM_SETTING_BOND_PORT_QUEUE_ID,
                           widget,
                           "text",
                           G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
    nmt_editor_grid_append(grid, _("Queue ID"), widget, NULL);

    nmt_editor_page_add_section(NMT_EDITOR_PAGE(bond), section);

    G_OBJECT_CLASS(nmt_page_bond_port_parent_class)->constructed(object);
}

static void
nmt_page_bond_port_class_init(NmtPageBondPortClass *bond_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(bond_class);

    object_class->constructed = nmt_page_bond_port_constructed;
}
