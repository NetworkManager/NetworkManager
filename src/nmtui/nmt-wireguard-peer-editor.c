/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Red Hat, Inc.
 */
/**
 * SECTION:nmt-wireguard-peer-editor
 * @short_description: The editor page for Peer connections
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmt-wireguard-peer-editor.h"
#include "nmt-page-wireguard.h"

#include "nmt-device-entry.h"
#include "nmt-mtu-entry.h"
#include "nmt-wireguard-peer-list.h"

#include "nm-editor-bindings.h"

G_DEFINE_TYPE(NmtWireguardPeerEditor, nmt_wireguard_peer_editor, NMT_TYPE_NEWT_FORM)

#define NMT_WIREGUARD_PEER_EDITOR_GET_PRIVATE(o)                 \
    (G_TYPE_INSTANCE_GET_PRIVATE((o),                            \
                                 NMT_TYPE_WIREGUARD_PEER_EDITOR, \
                                 NmtWireguardPeerEditorPrivate))

typedef struct {
    NMSettingWireGuard *orig_setting;
    NMSettingWireGuard *edit_setting;
    NMWireGuardPeer    *peer;
    NmtNewtEntry       *private_key;
} NmtWireguardPeerEditorPrivate;

enum {
    PROP_0,

    PROP_SETTING,
    PROP_PEER,
    PROP_PUBLIC_KEY,

    LAST_PROP
};

NmtNewtForm *
nmt_wireguard_peer_editor_new(NMSettingWireGuard *setting, NMWireGuardPeer *peer)
{
    return g_object_new(NMT_TYPE_WIREGUARD_PEER_EDITOR, "setting", setting, "peer", peer, NULL);
}

static void
nmt_wireguard_peer_editor_init(NmtWireguardPeerEditor *peer)
{}

static void
save_peer_and_exit(NmtNewtButton *button, gpointer user_data)
{
    NmtWireguardPeerEditor        *editor = user_data;
    NmtWireguardPeerEditorPrivate *priv   = NMT_WIREGUARD_PEER_EDITOR_GET_PRIVATE(editor);

    nm_setting_wireguard_append_peer(priv->orig_setting, priv->peer);

    nmt_newt_form_quit(NMT_NEWT_FORM(editor));
}

static void
nmt_wireguard_peer_editor_constructed(GObject *object)
{
    NmtWireguardPeerEditor *peer = NMT_WIREGUARD_PEER_EDITOR(object);
    NmtEditorSection       *section;
    NmtEditorGrid          *grid;
    NmtNewtWidget          *widget, *label;
    NmtNewtWidget          *buttons, *ok, *cancel;

    if (G_OBJECT_CLASS(nmt_wireguard_peer_editor_parent_class)->constructed)
        G_OBJECT_CLASS(nmt_wireguard_peer_editor_parent_class)->constructed(object);

    section = nmt_editor_section_new(_("Peer"), NULL, TRUE);
    grid    = nmt_editor_section_get_body(section);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(grid, _("Public key"), widget, NULL);
    g_object_bind_property_full(object,
                                "peer",
                                widget,
                                "text",
                                G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL,
                                peer_transform_to_public_key_string,
                                peer_transform_from_public_key_string,
                                NULL,
                                NULL);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(grid, _("Allowed IPs"), widget, NULL);
    g_object_bind_property_full(peer,
                                "peer",
                                widget,
                                "text",
                                G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL,
                                peer_transform_to_allowed_ips_string,
                                peer_transform_from_allowed_ips_string,
                                NULL,
                                NULL);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(grid, _("Endpoint"), widget, NULL);
    g_object_bind_property_full(peer,
                                "peer",
                                widget,
                                "text",
                                G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL,
                                peer_transform_to_endpoint_string,
                                peer_transform_from_endpoint_string,
                                NULL,
                                NULL);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(grid, _("Preshared key"), widget, NULL);
    g_object_bind_property_full(peer,
                                "peer",
                                widget,
                                "text",
                                G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL,
                                peer_transform_to_preshared_key_string,
                                peer_transform_from_preshared_key_string,
                                NULL,
                                NULL);

    widget = nmt_newt_entry_numeric_new(10, 0, G_MAXINT);
    label  = nmt_newt_label_new(C_("seconds", "seconds"));
    nmt_editor_grid_append(grid, _("Persistent keepalive"), widget, label);
    g_object_bind_property_full(peer,
                                "peer",
                                widget,
                                "text",
                                G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL,
                                peer_transform_to_persistent_keepalive_string,
                                peer_transform_from_persistent_keepalive_string,
                                NULL,
                                NULL);

    buttons = nmt_newt_grid_new();
    nmt_editor_grid_append(grid, NULL, buttons, NULL);
    nmt_newt_widget_set_padding(buttons, 0, 1, 0, 0);

    cancel = g_object_ref_sink(nmt_newt_button_new(_("Cancel")));
    nmt_newt_widget_set_exit_on_activate(cancel, TRUE);
    nmt_newt_grid_add(NMT_NEWT_GRID(buttons), cancel, 0, 0);
    nmt_newt_grid_set_flags(NMT_NEWT_GRID(buttons),
                            cancel,
                            NMT_NEWT_GRID_EXPAND_X | NMT_NEWT_GRID_ANCHOR_RIGHT
                                | NMT_NEWT_GRID_FILL_Y);

    ok = g_object_ref_sink(nmt_newt_button_new(_("OK")));
    g_signal_connect(ok, "clicked", G_CALLBACK(save_peer_and_exit), peer);
    nmt_newt_grid_add(NMT_NEWT_GRID(buttons), ok, 1, 0);
    nmt_newt_widget_set_padding(ok, 1, 0, 0, 0);
    g_object_bind_property(NMT_NEWT_GRID(buttons), "valid", ok, "sensitive", G_BINDING_SYNC_CREATE);

    nmt_newt_form_set_content(NMT_NEWT_FORM(peer), NMT_NEWT_WIDGET(section));
}

static void
nmt_wireguard_peer_editor_set_property(GObject      *object,
                                       guint         prop_id,
                                       const GValue *value,
                                       GParamSpec   *pspec)
{
    NmtWireguardPeerEditorPrivate *priv = NMT_WIREGUARD_PEER_EDITOR_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_SETTING:
        priv->orig_setting = g_value_dup_object(value);
        priv->edit_setting =
            NM_SETTING_WIREGUARD(nm_setting_duplicate(NM_SETTING(priv->orig_setting)));
        break;
    case PROP_PEER:
        priv->peer = g_value_dup_boxed(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nmt_wireguard_peer_editor_get_property(GObject    *object,
                                       guint       prop_id,
                                       GValue     *value,
                                       GParamSpec *pspec)
{
    NmtWireguardPeerEditorPrivate *priv = NMT_WIREGUARD_PEER_EDITOR_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_SETTING:
        g_value_set_object(value, priv->edit_setting);
        break;
    case PROP_PEER:
        g_value_set_boxed(value, priv->peer);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nmt_wireguard_peer_editor_class_init(NmtWireguardPeerEditorClass *peer_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(peer_class);

    g_type_class_add_private(peer_class, sizeof(NmtWireguardPeerEditorPrivate));

    /* virtual methods */
    object_class->constructed  = nmt_wireguard_peer_editor_constructed;
    object_class->set_property = nmt_wireguard_peer_editor_set_property;
    object_class->get_property = nmt_wireguard_peer_editor_get_property;

    /* properties */

    /**
     * NmtPeerPage:setting:
     *
     * The page's #NMSettingWireGuard.
     */
    g_object_class_install_property(
        object_class,
        PROP_SETTING,
        g_param_spec_object("setting",
                            "",
                            "",
                            NM_TYPE_SETTING_WIREGUARD,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

    /**
     * NmtPeerPage:peer:
     *
     * The page's #NMWireGuardPeer.
     */
    g_object_class_install_property(object_class,
                                    PROP_PEER,
                                    g_param_spec_boxed("peer",
                                                       "",
                                                       "",
                                                       nm_wireguard_peer_get_type(),
                                                       G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}
