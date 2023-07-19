/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-port-list:
 * @short_description: An editable list of a connection's ports
 *
 * #NmtPortList implements an #NmtEditConnectionList for the
 * ports of a connection.
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmt-port-list.h"

G_DEFINE_TYPE(NmtPortList, nmt_port_list, NMT_TYPE_EDIT_CONNECTION_LIST)

#define NMT_PORT_LIST_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NMT_TYPE_PORT_LIST, NmtPortListPrivate))

typedef struct {
    NMConnection *controller;
    const char   *controller_type, *controller_uuid;

    NmtAddConnectionTypeFilter type_filter;
    gpointer                   type_filter_data;
} NmtPortListPrivate;

enum {
    PROP_0,
    PROP_CONTROLLER,
    PROP_TYPE_FILTER,
    PROP_TYPE_FILTER_DATA,

    LAST_PROP
};

static gboolean nmt_port_list_connection_filter(NmtEditConnectionList *list,
                                                NMConnection          *connection,
                                                gpointer               user_data);

/**
 * nmt_port_list_new:
 * @controller: the controller #NMConnection whose ports are being listed
 * @type_filter: (nullable): a function to limit the available port types
 * @type_filter_data: (nullable): data for @type_filter.
 *
 * Creates a new #NmtPortList.
 *
 * If @type_filter is non-%NULL, it will be used to limit the connection
 * types that are available when the user clicks on the "Add" button to add
 * a new port. If the @type_filter filters the list down to only a single
 * connection type, then the user will not be presented with a connection-type
 * dialog, and will instead be immediately taken to an editor window for the
 * new port after clicking "Add".
 *
 * Returns: a new #NmtPortList.
 */
NmtNewtWidget *
nmt_port_list_new(NMConnection              *controller,
                  NmtAddConnectionTypeFilter type_filter,
                  gpointer                   type_filter_data)
{
    return g_object_new(NMT_TYPE_PORT_LIST,
                        "controller",
                        controller,
                        "type-filter",
                        type_filter,
                        "type-filter-data",
                        type_filter_data,
                        "grouped",
                        FALSE,
                        "connection-filter",
                        nmt_port_list_connection_filter,
                        NULL);
}

static void
nmt_port_list_init(NmtPortList *list)
{}

static void
nmt_port_list_finalize(GObject *object)
{
    NmtPortListPrivate *priv = NMT_PORT_LIST_GET_PRIVATE(object);

    g_object_unref(priv->controller);

    G_OBJECT_CLASS(nmt_port_list_parent_class)->finalize(object);
}

static gboolean
nmt_port_list_connection_filter(NmtEditConnectionList *list,
                                NMConnection          *connection,
                                gpointer               user_data)
{
    NmtPortListPrivate  *priv = NMT_PORT_LIST_GET_PRIVATE(list);
    NMSettingConnection *s_con;
    const char          *controller, *controller_ifname, *port_type;

    s_con = nm_connection_get_setting_connection(connection);
    g_return_val_if_fail(s_con != NULL, FALSE);

    port_type = nm_setting_connection_get_slave_type(s_con);
    if (g_strcmp0(port_type, priv->controller_type) != 0)
        return FALSE;

    controller = nm_setting_connection_get_master(s_con);
    if (!controller)
        return FALSE;

    controller_ifname = nm_connection_get_interface_name(priv->controller);
    if (g_strcmp0(controller, controller_ifname) != 0
        && g_strcmp0(controller, priv->controller_uuid) != 0)
        return FALSE;

    return TRUE;
}

static void
nmt_port_list_add_connection(NmtEditConnectionList *list)
{
    NmtPortListPrivate *priv = NMT_PORT_LIST_GET_PRIVATE(list);

    nmt_add_connection_full(_("Select the type of slave connection you wish to add."),
                            NULL,
                            priv->controller,
                            priv->type_filter,
                            priv->type_filter_data);
}

static void
nmt_port_list_edit_connection(NmtEditConnectionList *list, NMConnection *connection)
{
    nmt_edit_connection(connection);
}

static void
nmt_port_list_remove_connection(NmtEditConnectionList *list, NMRemoteConnection *connection)
{
    nmt_remove_connection(connection);
}

static void
nmt_port_list_set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NmtPortListPrivate *priv = NMT_PORT_LIST_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_CONTROLLER:
        priv->controller = g_value_dup_object(value);
        if (priv->controller) {
            NMSettingConnection *s_con = nm_connection_get_setting_connection(priv->controller);

            priv->controller_type = nm_setting_connection_get_connection_type(s_con);
            priv->controller_uuid = nm_setting_connection_get_uuid(s_con);
        }
        break;
    case PROP_TYPE_FILTER:
        priv->type_filter = g_value_get_pointer(value);
        break;
    case PROP_TYPE_FILTER_DATA:
        priv->type_filter_data = g_value_get_pointer(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nmt_port_list_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NmtPortListPrivate *priv = NMT_PORT_LIST_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_CONTROLLER:
        g_value_set_object(value, priv->controller);
        break;
    case PROP_TYPE_FILTER:
        g_value_set_pointer(value, priv->type_filter);
        break;
    case PROP_TYPE_FILTER_DATA:
        g_value_set_pointer(value, priv->type_filter_data);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nmt_port_list_class_init(NmtPortListClass *list_class)
{
    GObjectClass               *object_class          = G_OBJECT_CLASS(list_class);
    NmtEditConnectionListClass *connection_list_class = NMT_EDIT_CONNECTION_LIST_CLASS(list_class);

    g_type_class_add_private(list_class, sizeof(NmtPortListPrivate));

    /* virtual methods */
    object_class->set_property = nmt_port_list_set_property;
    object_class->get_property = nmt_port_list_get_property;
    object_class->finalize     = nmt_port_list_finalize;

    connection_list_class->add_connection    = nmt_port_list_add_connection;
    connection_list_class->edit_connection   = nmt_port_list_edit_connection;
    connection_list_class->remove_connection = nmt_port_list_remove_connection;

    /**
     * NmtPortList:controller:
     *
     * The controller #NMConnection whose ports are being displayed.
     */
    g_object_class_install_property(
        object_class,
        PROP_CONTROLLER,
        g_param_spec_object("controller",
                            "",
                            "",
                            NM_TYPE_CONNECTION,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
    /**
     * NmtPortList:type-filter:
     *
     * If non-%NULL, this will be used to limit the connection types
     * that are available when the user clicks on the "Add" button to
     * add a new port. If the filter filters the list down to only a
     * single connection type, then the user will not be presented
     * with a connection-type dialog, and will instead be immediately
     * taken to an editor window for the new port after clicking
     * "Add".
     */
    g_object_class_install_property(
        object_class,
        PROP_TYPE_FILTER,
        g_param_spec_pointer("type-filter",
                             "",
                             "",
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
    /**
     * NmtPortList:type-filter-data:
     *
     * User data passed to #NmtPortList:type-filter
     */
    g_object_class_install_property(
        object_class,
        PROP_TYPE_FILTER_DATA,
        g_param_spec_pointer("type-filter-data",
                             "",
                             "",
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}
