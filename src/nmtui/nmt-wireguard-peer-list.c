/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Red Hat, Inc.
 */

/**
 * SECTION:nmt-wireguard-peer-list:
 * @short_description: An editable list of a connection's peers
 *
 * #NmtWireguardPeerList implements an #NmtNewtGrid for the
 * peers of a connection.
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmtui.h"
#include "nmt-wireguard-peer-list.h"
#include "nmt-wireguard-peer-editor.h"

G_DEFINE_TYPE(NmtWireguardPeerList, nmt_wireguard_peer_list, NMT_TYPE_NEWT_GRID)

#define NMT_WIREGUARD_PEER_LIST_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NMT_TYPE_WIREGUARD_PEER_LIST, NmtWireguardPeerListPrivate))

typedef struct {
    NMSettingWireGuard *setting;
    GSList             *peers;

    NmtNewtListbox   *listbox;
    NmtNewtButtonBox *buttons;

    NmtNewtWidget *add;
    NmtNewtWidget *edit;
    NmtNewtWidget *delete;
} NmtWireguardPeerListPrivate;

enum {
    PROP_0,

    PROP_SETTING,
    PROP_PEERS,
    PROP_NUM_PEERS,

    LAST_PROP
};

enum {
    ADD_PEER,
    EDIT_PEER,
    REMOVE_PEER,

    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = {0};

/**
 * nmt_wireguard_peer_list_new:
 * @master: the master #NMSettingWireGuard whose peers are being listed
 *
 * Creates a new #NmtWireguardPeerList.
 *
 * Returns: a new #NmtWireguardPeerList.
 */
NmtNewtWidget *
nmt_wireguard_peer_list_new(NMSettingWireGuard *setting)
{
    return g_object_new(NMT_TYPE_WIREGUARD_PEER_LIST, "setting", setting, NULL);
}

static void
add_clicked(NmtNewtButton *button, gpointer list)
{
    g_signal_emit(list, signals[ADD_PEER], 0);
}

static void
edit_clicked(NmtNewtButton *button, gpointer list)
{
    g_signal_emit(list, signals[EDIT_PEER], 0);
}

static void
delete_clicked(NmtNewtButton *button, gpointer list)
{
    g_signal_emit(list, signals[REMOVE_PEER], 0);
}

static void
listbox_activated(NmtNewtWidget *listbox, gpointer list)
{
    NmtWireguardPeerListPrivate *priv = NMT_WIREGUARD_PEER_LIST_GET_PRIVATE(list);

    edit_clicked(NMT_NEWT_BUTTON(priv->edit), list);
}

static void
nmt_wireguard_peer_list_init(NmtWireguardPeerList *list)
{
    NmtWireguardPeerListPrivate *priv = NMT_WIREGUARD_PEER_LIST_GET_PRIVATE(list);
    NmtNewtWidget               *listbox, *buttons;
    NmtNewtGrid                 *grid = NMT_NEWT_GRID(list);

    listbox       = g_object_new(NMT_TYPE_NEWT_LISTBOX,
                           "flags",
                           NMT_NEWT_LISTBOX_SCROLL | NMT_NEWT_LISTBOX_BORDER,
                           "skip-null-keys",
                           TRUE,
                           NULL);
    priv->listbox = NMT_NEWT_LISTBOX(listbox);
    nmt_newt_grid_add(grid, listbox, 0, 0);
    nmt_newt_grid_set_flags(grid,
                            listbox,
                            NMT_NEWT_GRID_FILL_X | NMT_NEWT_GRID_FILL_Y | NMT_NEWT_GRID_EXPAND_X
                                | NMT_NEWT_GRID_EXPAND_Y);
    g_signal_connect(priv->listbox, "activated", G_CALLBACK(listbox_activated), list);

    buttons       = nmt_newt_button_box_new(NMT_NEWT_BUTTON_BOX_VERTICAL);
    priv->buttons = NMT_NEWT_BUTTON_BOX(buttons);
    nmt_newt_grid_add(grid, buttons, 1, 0);
    nmt_newt_widget_set_padding(buttons, 1, 1, 0, 1);
    nmt_newt_grid_set_flags(grid,
                            buttons,
                            NMT_NEWT_GRID_FILL_X | NMT_NEWT_GRID_FILL_Y | NMT_NEWT_GRID_EXPAND_Y);

    priv->add = nmt_newt_button_box_add_start(priv->buttons, _("Add"));
    g_signal_connect(priv->add, "clicked", G_CALLBACK(add_clicked), list);

    priv->edit = nmt_newt_button_box_add_start(priv->buttons, _("Edit..."));
    g_signal_connect(priv->edit, "clicked", G_CALLBACK(edit_clicked), list);

    priv->delete = nmt_newt_button_box_add_start(priv->buttons, _("Delete"));
    g_signal_connect(priv->delete, "clicked", G_CALLBACK(delete_clicked), list);
}

static void nmt_wireguard_peer_list_rebuild(NmtWireguardPeerList *list);

static void
rebuild_on_peer_changed(gpointer list)
{
    nmt_wireguard_peer_list_rebuild(list);
}

static void
free_peers(NmtWireguardPeerList *list)
{
    NmtWireguardPeerListPrivate *priv = NMT_WIREGUARD_PEER_LIST_GET_PRIVATE(list);

    g_slist_free(priv->peers);
    priv->peers = NULL;
}

static void
nmt_wireguard_peer_list_finalize(GObject *object)
{
    NmtWireguardPeerListPrivate *priv = NMT_WIREGUARD_PEER_LIST_GET_PRIVATE(object);

    free_peers(NMT_WIREGUARD_PEER_LIST(object));
    g_object_unref(priv->setting);
    g_object_unref(priv->peers);

    G_OBJECT_CLASS(nmt_wireguard_peer_list_parent_class)->finalize(object);
}

static void
nmt_wireguard_peer_list_add_peer(NmtWireguardPeerList *list)
{
    NmtWireguardPeerListPrivate *priv = NMT_WIREGUARD_PEER_LIST_GET_PRIVATE(list);
    NMWireGuardPeer             *peer = nm_wireguard_peer_new();
    NmtNewtForm                 *editor;

    editor = nmt_wireguard_peer_editor_new(priv->setting, peer);

    if (!editor)
        return;

    nmt_newt_form_run_sync(editor);
    g_object_unref(editor);
    rebuild_on_peer_changed(list);
}

static void
nmt_wireguard_peer_list_edit_peer(NmtWireguardPeerList *list)
{
    NmtWireguardPeerListPrivate *priv = NMT_WIREGUARD_PEER_LIST_GET_PRIVATE(list);
    NMWireGuardPeer             *orig_peer, *edit_peer;
    NmtNewtForm                 *editor;
    int                          selected_row;

    selected_row = nmt_newt_listbox_get_active(priv->listbox);

    if (selected_row >= 0) {
        orig_peer = nm_setting_wireguard_get_peer(priv->setting, (guint) selected_row);
        edit_peer = nm_wireguard_peer_new_clone(orig_peer, TRUE);
        editor    = nmt_wireguard_peer_editor_new(priv->setting, edit_peer);
        if (!editor)
            return;
        nmt_newt_form_run_sync(editor);
        g_object_unref(editor);
        rebuild_on_peer_changed(list);
    }
}

static void
nmt_wireguard_peer_list_remove_peer(NmtWireguardPeerList *list)
{
    NmtWireguardPeerListPrivate *priv = NMT_WIREGUARD_PEER_LIST_GET_PRIVATE(list);
    int                          selected_row;

    selected_row = nmt_newt_listbox_get_active(priv->listbox);

    if (selected_row >= 0) {
        nm_setting_wireguard_remove_peer(priv->setting, (guint) selected_row);
        rebuild_on_peer_changed(list);
    }
}

static void
nmt_wireguard_peer_list_set_property(GObject      *object,
                                     guint         prop_id,
                                     const GValue *value,
                                     GParamSpec   *pspec)
{
    NmtWireguardPeerListPrivate *priv = NMT_WIREGUARD_PEER_LIST_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_SETTING:
        priv->setting = g_value_get_pointer(value);
        break;
    case PROP_PEERS:
        priv->peers = g_value_get_pointer(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nmt_wireguard_peer_list_get_property(GObject    *object,
                                     guint       prop_id,
                                     GValue     *value,
                                     GParamSpec *pspec)
{
    NmtWireguardPeerListPrivate *priv = NMT_WIREGUARD_PEER_LIST_GET_PRIVATE(object);
    GPtrArray                   *peers;
    GSList                      *iter;

    switch (prop_id) {
    case PROP_SETTING:
        g_value_set_pointer(value, priv->setting);
        break;
    case PROP_PEERS:
        peers = g_ptr_array_new_with_free_func(g_object_unref);
        for (iter = priv->peers; iter; iter = iter->next)
            g_ptr_array_add(peers, g_object_ref(iter->data));
        g_value_take_boxed(value, peers);
        break;
    case PROP_NUM_PEERS:
        g_value_set_int(value, g_slist_length(priv->peers));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nmt_wireguard_peer_list_rebuild(NmtWireguardPeerList *list)
{
    NmtWireguardPeerListPrivate *priv = NMT_WIREGUARD_PEER_LIST_GET_PRIVATE(list);
    GSList                      *iter;
    NMWireGuardPeer             *peer, *selected_peer;
    int                          i, row, selected_row, num;
    NMSettingWireGuard          *setting = priv->setting;

    selected_row  = nmt_newt_listbox_get_active(priv->listbox);
    selected_peer = nmt_newt_listbox_get_active_key(priv->listbox);

    free_peers(list);
    num = nm_setting_wireguard_get_peers_len(setting);
    for (i = 0; i < num; i++) {
        peer        = nm_setting_wireguard_get_peer(setting, i);
        priv->peers = g_slist_append(priv->peers, peer);
    }
    g_object_notify(G_OBJECT(list), "peers");
    g_object_notify(G_OBJECT(list), "num-peers");

    nmt_newt_component_set_sensitive(NMT_NEWT_COMPONENT(priv->edit), priv->peers != NULL);
    nmt_newt_component_set_sensitive(NMT_NEWT_COMPONENT(priv->delete), priv->peers != NULL);

    nmt_newt_listbox_clear(priv->listbox);

    for (iter = priv->peers, row = 0; iter; iter = iter->next, row++) {
        peer = iter->data;
        nmt_newt_listbox_append(priv->listbox, nm_wireguard_peer_get_public_key(peer), peer);
        if (peer == selected_peer)
            selected_row = row;
    }
    if (selected_row >= row)
        selected_row = row - 1;
    nmt_newt_listbox_set_active(priv->listbox, selected_row);
}

static void
rebuild_on_peers_changed(GObject *object, GParamSpec *pspec, gpointer list)
{
    nmt_wireguard_peer_list_rebuild(list);
}

static void
nmt_wireguard_peer_list_constructed(GObject *object)
{
    NmtWireguardPeerList *list = NMT_WIREGUARD_PEER_LIST(object);

    g_signal_connect(nm_client,
                     "notify::" NM_CLIENT_CONNECTIONS,
                     G_CALLBACK(rebuild_on_peers_changed),
                     list);

    nmt_wireguard_peer_list_rebuild(list);

    G_OBJECT_CLASS(nmt_wireguard_peer_list_parent_class)->constructed(object);
}

static void
nmt_wireguard_peer_list_class_init(NmtWireguardPeerListClass *list_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(list_class);

    g_type_class_add_private(list_class, sizeof(NmtWireguardPeerListPrivate));

    /* virtual methods */
    object_class->constructed  = nmt_wireguard_peer_list_constructed;
    object_class->set_property = nmt_wireguard_peer_list_set_property;
    object_class->get_property = nmt_wireguard_peer_list_get_property;
    object_class->finalize     = nmt_wireguard_peer_list_finalize;

    list_class->add_peer    = nmt_wireguard_peer_list_add_peer;
    list_class->edit_peer   = nmt_wireguard_peer_list_edit_peer;
    list_class->remove_peer = nmt_wireguard_peer_list_remove_peer;

    /* signals */

    /**
     * NmtWireguardPeerList::add-connection:
     * @list: the #NmtWireguardPeerList
     *
     * Emitted when the user clicks the list's "Add" button.
     */
    signals[ADD_PEER] = g_signal_new("add-peer",
                                     G_OBJECT_CLASS_TYPE(object_class),
                                     G_SIGNAL_RUN_FIRST,
                                     G_STRUCT_OFFSET(NmtWireguardPeerListClass, add_peer),
                                     NULL,
                                     NULL,
                                     NULL,
                                     G_TYPE_NONE,
                                     0);

    /**
     * NmtWireguardPeerList::edit-connection:
     * @list: the #NmtWireguardPeerList
     * @connection: the connection to edit
     *
     * Emitted when the user clicks the list's "Edit" button, or
     * hits "Return" on the listbox.
     */
    signals[EDIT_PEER] = g_signal_new("edit-peer",
                                      G_OBJECT_CLASS_TYPE(object_class),
                                      G_SIGNAL_RUN_FIRST,
                                      G_STRUCT_OFFSET(NmtWireguardPeerListClass, edit_peer),
                                      NULL,
                                      NULL,
                                      NULL,
                                      G_TYPE_NONE,
                                      0);

    /**
     * NmtWireguardPeerList::remove-connection:
     * @list: the #NmtWireguardPeerList
     * @connection: the connection to remove
     *
     * Emitted when the user clicks the list's "Delete" button.
     */
    signals[REMOVE_PEER] = g_signal_new("remove-peer",
                                        G_OBJECT_CLASS_TYPE(object_class),
                                        G_SIGNAL_RUN_FIRST,
                                        G_STRUCT_OFFSET(NmtWireguardPeerListClass, remove_peer),
                                        NULL,
                                        NULL,
                                        NULL,
                                        G_TYPE_NONE,
                                        0);

    /* properties */

    /**
     * NmtWireguardPeerListFilter:
     * @list: the #NmtWireguardPeerList
     * @connection: an #NMConnection
     * @user_data: the user data
     *
     * Decides whether @connection should be displayed in @list.
     *
     * Returns: %TRUE or %FALSE
     */
    /**
     * NmtWireguardPeerList:connection-filter:
     *
     * A callback function for filtering which connections appear in
     * the list.
     */
    g_object_class_install_property(
        object_class,
        PROP_SETTING,
        g_param_spec_pointer("setting",
                             "",
                             "",
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

    /**
     * NmtWireguardPeerList:connections:
     *
     * The list of connections in the widget.
     *
     * Element-Type: #NMConnection
     */
    g_object_class_install_property(object_class,
                                    PROP_PEERS,
                                    g_param_spec_boxed("peers",
                                                       "",
                                                       "",
                                                       G_TYPE_PTR_ARRAY,
                                                       G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

    /**
     * NmtWireguardPeerList:num-connections:
     *
     * The number of connections in the widget.
     */
    g_object_class_install_property(object_class,
                                    PROP_NUM_PEERS,
                                    g_param_spec_int("num-peers",
                                                     "",
                                                     "",
                                                     0,
                                                     G_MAXINT,
                                                     0,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
}
