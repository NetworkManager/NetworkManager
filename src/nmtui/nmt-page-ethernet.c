/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-page-ethernet
 * @short_description: The editor page for Ethernet connections
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmt-page-ethernet.h"

#include <linux/if_ether.h>
#include <linux/if_infiniband.h>

#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "nmt-mac-entry.h"
#include "nmt-mtu-entry.h"
#include "nmt-8021x-fields.h"

typedef struct {
    NMSetting8021x *s_8021x;
    NmtNewtWidget  *dot1x_fields;
} NmtPageEthernetPrivate;

struct _NmtPageEthernet {
    NmtEditorPageDevice    parent;
    NmtPageEthernetPrivate _priv;
};

struct _NmtPageEthernetClass {
    NmtEditorPageDeviceClass parent;
};

G_DEFINE_TYPE(NmtPageEthernet, nmt_page_ethernet, NMT_TYPE_EDITOR_PAGE_DEVICE)

#define NMT_PAGE_ETHERNET_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NmtPageEthernet, NMT_IS_PAGE_ETHERNET)

NmtEditorPage *
nmt_page_ethernet_new(NMConnection *conn, NmtDeviceEntry *deventry)
{
    return g_object_new(NMT_TYPE_PAGE_ETHERNET, "connection", conn, "device-entry", deventry, NULL);
}

static void
nmt_page_ethernet_init(NmtPageEthernet *ethernet)
{}

static void
checkbox_8021x_changed(NmtNewtWidget *widget, GParamSpec *pspec, gpointer user_data)
{
    NMConnection           *conn;
    NmtPageEthernet        *ethernet = NMT_PAGE_ETHERNET(user_data);
    NmtPageEthernetPrivate *priv     = NMT_PAGE_ETHERNET_GET_PRIVATE(ethernet);
    gboolean                active;
    gboolean                has;

    conn   = nmt_editor_page_get_connection(NMT_EDITOR_PAGE(ethernet));
    active = nmt_newt_checkbox_get_active(NMT_NEWT_CHECKBOX(widget));
    has    = !!nm_connection_get_setting(conn, NM_TYPE_SETTING_802_1X);

    if (active != has) {
        if (active)
            nm_connection_add_setting(conn, NM_SETTING(priv->s_8021x));
        else
            nm_connection_remove_setting(conn, NM_TYPE_SETTING_802_1X);
    }

    nmt_newt_widget_set_visible(NMT_NEWT_WIDGET(priv->dot1x_fields), active);
}

static void
nmt_page_ethernet_constructed(GObject *object)
{
    NmtPageEthernet        *ethernet = NMT_PAGE_ETHERNET(object);
    NmtPageEthernetPrivate *priv     = NMT_PAGE_ETHERNET_GET_PRIVATE(object);
    NmtDeviceEntry         *deventry;
    NmtEditorSection       *section;
    NmtEditorGrid          *grid;
    NMSettingWired         *s_wired;
    NMSetting8021x         *s_8021x;
    NmtNewtWidget          *widget;
    NMConnection           *conn;
    gboolean                has_8021x;

    conn    = nmt_editor_page_get_connection(NMT_EDITOR_PAGE(ethernet));
    s_wired = _nm_connection_ensure_setting(conn, NM_TYPE_SETTING_WIRED);

    s_8021x   = nm_connection_get_setting_802_1x(conn);
    has_8021x = !!s_8021x;
    if (!s_8021x) {
        s_8021x = NM_SETTING_802_1X(nm_setting_802_1x_new());
        nm_setting_802_1x_add_eap_method(s_8021x, "TLS");
    }
    priv->s_8021x = g_object_ref(s_8021x);

    deventry = nmt_editor_page_device_get_device_entry(NMT_EDITOR_PAGE_DEVICE(object));
    g_object_bind_property(s_wired,
                           NM_SETTING_WIRED_MAC_ADDRESS,
                           deventry,
                           "mac-address",
                           G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

    section = nmt_editor_section_new(_("ETHERNET"), NULL, FALSE);
    grid    = nmt_editor_section_get_body(section);

    widget = nmt_mac_entry_new(40, ETH_ALEN, NMT_MAC_ENTRY_TYPE_CLONED);
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

    nmt_editor_page_add_section(NMT_EDITOR_PAGE(ethernet), section);

    /* 802.1X security */
    section = nmt_editor_section_new(_("802.1X SECURITY"), NULL, has_8021x);
    grid    = nmt_editor_section_get_body(section);
    widget  = nmt_newt_checkbox_new(_("Enable 802.1X security"));

    nmt_newt_checkbox_set_active(NMT_NEWT_CHECKBOX(widget), has_8021x);
    g_signal_connect(widget, "notify::active", G_CALLBACK(checkbox_8021x_changed), ethernet);
    nmt_editor_grid_append(grid, NULL, widget, NULL);
    priv->dot1x_fields = NMT_NEWT_WIDGET(nmt_8021x_fields_new(s_8021x, TRUE));
    checkbox_8021x_changed(widget, NULL, ethernet);
    nmt_editor_grid_append(grid, NULL, priv->dot1x_fields, NULL);
    nmt_editor_page_add_section(NMT_EDITOR_PAGE(ethernet), section);

    G_OBJECT_CLASS(nmt_page_ethernet_parent_class)->constructed(object);
}

static void
nmt_page_ethernet_finalize(GObject *object)
{
    NmtPageEthernetPrivate *priv = NMT_PAGE_ETHERNET_GET_PRIVATE(object);

    g_clear_object(&priv->s_8021x);

    G_OBJECT_CLASS(nmt_page_ethernet_parent_class)->finalize(object);
}

static void
nmt_page_ethernet_class_init(NmtPageEthernetClass *ethernet_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(ethernet_class);

    object_class->constructed = nmt_page_ethernet_constructed;
    object_class->finalize    = nmt_page_ethernet_finalize;
}
