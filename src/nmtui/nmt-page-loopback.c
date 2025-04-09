/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */
/**
 * SECTION:nmt-page-loopback
 * @short_description: The editor page for the loopback interface
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include <linux/if_ether.h>

#include "nmt-page-loopback.h"

#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "nmt-mtu-entry.h"

G_DEFINE_TYPE(NmtPageLoopback, nmt_page_loopback, NMT_TYPE_EDITOR_PAGE_DEVICE)

#define NMT_PAGE_LOOPBACK_GET_PRIVATE(o) \
    _NM_GET_PRIVATE(self, NmtPageLoopback, NMT_IS_PAGE_LOOPBACK)

static void
nmt_page_loopback_init(NmtPageLoopback *loopback)
{}

NmtEditorPage *
nmt_page_loopback_new(NMConnection *conn)
{
    return g_object_new(NMT_TYPE_PAGE_LOOPBACK, "connection", conn, NULL);
}

static void
nmt_page_loopback_constructed(GObject *object)
{
    NmtPageLoopback   *loopback = NMT_PAGE_LOOPBACK(object);
    NmtEditorSection  *section;
    NmtEditorGrid     *grid;
    NMSettingLoopback *s_loopback;
    NmtNewtWidget     *widget;
    NMConnection      *conn;

    conn       = nmt_editor_page_get_connection(NMT_EDITOR_PAGE(loopback));
    s_loopback = _nm_connection_ensure_setting(conn, NM_TYPE_SETTING_LOOPBACK);

    section = nmt_editor_section_new(_("LOOPBACK"), NULL, FALSE);
    grid    = nmt_editor_section_get_body(section);

    widget = nmt_mtu_entry_new();
    g_object_bind_property(s_loopback,
                           NM_SETTING_LOOPBACK_MTU,
                           widget,
                           "mtu",
                           G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
    nmt_editor_grid_append(grid, _("MTU"), widget, NULL);

    nmt_editor_page_add_section(NMT_EDITOR_PAGE(loopback), section);

    G_OBJECT_CLASS(nmt_page_loopback_parent_class)->constructed(object);
}

static void
nmt_page_loopback_class_init(NmtPageLoopbackClass *loopback_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(loopback_class);
    object_class->constructed  = nmt_page_loopback_constructed;
}
