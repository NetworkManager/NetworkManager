/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */
/**
 * SECTION:nmt-page-veth
 * @short_description: The editor page for veth connections
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include <linux/if_ether.h>

#include "nmt-page-veth.h"

#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "nmt-device-entry.h"
#include "nmt-mac-entry.h"
#include "nmt-mtu-entry.h"

G_DEFINE_TYPE(NmtPageVeth, nmt_page_veth, NMT_TYPE_EDITOR_PAGE_DEVICE)

#define NMT_PAGE_VETH_GET_PRIVATE(o) _NM_GET_PRIVATE(self, NmtPageVeth, NMT_IS_PAGE_VETH)

static void
nmt_page_veth_init(NmtPageVeth *veth)
{}

NmtEditorPage *
nmt_page_veth_new(NMConnection *conn, NmtDeviceEntry *deventry)
{
    return g_object_new(NMT_TYPE_PAGE_VETH, "connection", conn, "device-entry", deventry, NULL);
}

static void
nmt_page_veth_constructed(GObject *object)
{
    NmtPageVeth      *veth = NMT_PAGE_VETH(object);
    NmtEditorSection *section;
    NmtEditorGrid    *grid;
    NMSettingVeth    *s_veth;
    NMSettingWired   *s_wired;
    NmtNewtWidget    *widget;
    NMConnection     *conn;

    conn    = nmt_editor_page_get_connection(NMT_EDITOR_PAGE(veth));
    s_veth  = _nm_connection_ensure_setting(conn, NM_TYPE_SETTING_VETH);
    s_wired = _nm_connection_ensure_setting(conn, NM_TYPE_SETTING_WIRED);

    section = nmt_editor_section_new(_("VETH"), NULL, TRUE);
    grid    = nmt_editor_section_get_body(section);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(grid, _("Peer"), widget, NULL);
    g_object_bind_property(s_veth,
                           NM_SETTING_VETH_PEER,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    nmt_editor_page_add_section(NMT_EDITOR_PAGE(veth), section);

    section = nmt_editor_section_new(_("ETHERNET"), NULL, FALSE);
    grid    = nmt_editor_section_get_body(section);

    widget = nmt_mac_entry_new(40, ETH_ALEN, NMT_MAC_ENTRY_TYPE_CLONED_ETHERNET);
    g_object_bind_property(s_wired,
                           NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
                           widget,
                           "mac-address",
                           G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
    nmt_editor_grid_append(grid, _("Cloned MAC address"), widget, NULL);

    widget = nmt_mtu_entry_new();
    g_object_bind_property(s_wired,
                           NM_SETTING_WIRED_MTU,
                           widget,
                           "mtu",
                           G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
    nmt_editor_grid_append(grid, _("MTU"), widget, NULL);

    nmt_editor_page_add_section(NMT_EDITOR_PAGE(veth), section);

    G_OBJECT_CLASS(nmt_page_veth_parent_class)->constructed(object);
}

static void
nmt_page_veth_class_init(NmtPageVethClass *veth_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(veth_class);
    object_class->constructed  = nmt_page_veth_constructed;
}
