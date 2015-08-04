/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * SECTION:nmt-edit-connection-list
 * @short_description: Connection list for "nmtui edit"
 *
 * #NmtEditConnectionList is the list of connections displayed by
 * "nmtui edit".
 */

#include "config.h"

#include "nmtui.h"
#include "nmtui-edit.h"
#include "nmt-edit-connection-list.h"
#include "nmt-editor.h"

#include "nm-editor-utils.h"

G_DEFINE_TYPE (NmtEditConnectionList, nmt_edit_connection_list, NMT_TYPE_NEWT_GRID)

#define NMT_EDIT_CONNECTION_LIST_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_EDIT_CONNECTION_LIST, NmtEditConnectionListPrivate))

typedef struct {
	GSList *connections;

	gboolean grouped;
	NmtEditConnectionListFilter connection_filter;
	gpointer connection_filter_data;

	NmtNewtListbox *listbox;
	NmtNewtButtonBox *buttons;

	NmtNewtWidget *add;
	NmtNewtWidget *edit;
	NmtNewtWidget *delete;
	NmtNewtWidget *extra;
} NmtEditConnectionListPrivate;

enum {
	PROP_0,

	PROP_GROUPED,
	PROP_CONNECTION_FILTER,
	PROP_CONNECTION_FILTER_DATA,
	PROP_EXTRA_WIDGET,
	PROP_CONNECTIONS,
	PROP_NUM_CONNECTIONS,

	LAST_PROP
};

enum {
	ADD_CONNECTION,
	EDIT_CONNECTION,
	REMOVE_CONNECTION,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void add_clicked (NmtNewtButton *button, gpointer list);
static void edit_clicked (NmtNewtButton *button, gpointer list);
static void delete_clicked (NmtNewtButton *button, gpointer list);
static void listbox_activated (NmtNewtWidget *listbox, gpointer list);

static void
nmt_edit_connection_list_init (NmtEditConnectionList *list)
{
	NmtEditConnectionListPrivate *priv = NMT_EDIT_CONNECTION_LIST_GET_PRIVATE (list);
	NmtNewtWidget *listbox, *buttons;
	NmtNewtGrid *grid = NMT_NEWT_GRID (list);

	listbox = g_object_new (NMT_TYPE_NEWT_LISTBOX,
	                        "flags", NMT_NEWT_LISTBOX_SCROLL | NMT_NEWT_LISTBOX_BORDER,
	                        "skip-null-keys", TRUE,
	                        NULL);
	priv->listbox = NMT_NEWT_LISTBOX (listbox);
	nmt_newt_grid_add (grid, listbox, 0, 0);
	nmt_newt_grid_set_flags (grid, listbox,
	                         NMT_NEWT_GRID_FILL_X | NMT_NEWT_GRID_FILL_Y |
	                         NMT_NEWT_GRID_EXPAND_X | NMT_NEWT_GRID_EXPAND_Y);
	g_signal_connect (priv->listbox, "activated", G_CALLBACK (listbox_activated), list);

	buttons = nmt_newt_button_box_new (NMT_NEWT_BUTTON_BOX_VERTICAL);
	priv->buttons = NMT_NEWT_BUTTON_BOX (buttons);
	nmt_newt_grid_add (grid, buttons, 1, 0);
	nmt_newt_widget_set_padding (buttons, 1, 1, 0, 1);
	nmt_newt_grid_set_flags (grid, buttons,
	                         NMT_NEWT_GRID_FILL_X | NMT_NEWT_GRID_FILL_Y |
	                         NMT_NEWT_GRID_EXPAND_Y);

	priv->add = nmt_newt_button_box_add_start (priv->buttons, _("Add"));
	g_signal_connect (priv->add, "clicked", G_CALLBACK (add_clicked), list);

	priv->edit = nmt_newt_button_box_add_start (priv->buttons, _("Edit..."));
	g_signal_connect (priv->edit, "clicked", G_CALLBACK (edit_clicked), list);

	priv->delete = nmt_newt_button_box_add_start (priv->buttons, _("Delete"));
	g_signal_connect (priv->delete, "clicked", G_CALLBACK (delete_clicked), list);
}

static int
sort_by_timestamp (gconstpointer  a,
                   gconstpointer  b)
{
	NMSettingConnection *s_con_a, *s_con_b;
	guint64 time_a, time_b;

	s_con_a = nm_connection_get_setting_connection ((NMConnection *) a);
	s_con_b = nm_connection_get_setting_connection ((NMConnection *) b);

	time_a = nm_setting_connection_get_timestamp (s_con_a);
	time_b = nm_setting_connection_get_timestamp (s_con_b);

	return (int) (time_b - time_a);
}

static void nmt_edit_connection_list_rebuild (NmtEditConnectionList *list);

static void
rebuild_on_connection_changed (NMRemoteConnection *connection,
                               gpointer            list)
{
	nmt_edit_connection_list_rebuild (list);
}

static void
free_connections (NmtEditConnectionList *list)
{
	NmtEditConnectionListPrivate *priv = NMT_EDIT_CONNECTION_LIST_GET_PRIVATE (list);
	NMConnection *conn;
	GSList *iter;

	for (iter = priv->connections; iter; iter = iter->next) {
		conn = iter->data;

		g_signal_handlers_disconnect_by_func (conn, G_CALLBACK (rebuild_on_connection_changed), list);
		g_object_unref (conn);
	}
	g_slist_free (priv->connections);
	priv->connections = NULL;
}

static void
nmt_edit_connection_list_rebuild (NmtEditConnectionList *list)
{
	NmtEditConnectionListPrivate *priv = NMT_EDIT_CONNECTION_LIST_GET_PRIVATE (list);
	const GPtrArray *connections;
	GSList *iter;
	gboolean did_header = FALSE, did_vpn = FALSE;
	NMEditorConnectionTypeData **types;
	NMConnection *conn, *selected_conn;
	int i, row, selected_row;

	selected_row = nmt_newt_listbox_get_active (priv->listbox);
	selected_conn = nmt_newt_listbox_get_active_key (priv->listbox);

	free_connections (list);
	connections = nm_client_get_connections (nm_client);
	for (i = 0; i < connections->len; i++) {
		conn = connections->pdata[i];

		if (   priv->connection_filter
		    && !priv->connection_filter (list, conn, priv->connection_filter_data))
			continue;

		g_signal_connect (conn, NM_CONNECTION_CHANGED,
		                  G_CALLBACK (rebuild_on_connection_changed), list);
		priv->connections = g_slist_prepend (priv->connections, g_object_ref (conn));
	}
	priv->connections = g_slist_sort (priv->connections, sort_by_timestamp);
	g_object_notify (G_OBJECT (list), "connections");
	g_object_notify (G_OBJECT (list), "num-connections");

	nmt_newt_component_set_sensitive (NMT_NEWT_COMPONENT (priv->edit),
	                                  priv->connections != NULL);
	nmt_newt_component_set_sensitive (NMT_NEWT_COMPONENT (priv->delete),
	                                  priv->connections != NULL);

	nmt_newt_listbox_clear (priv->listbox);

	if (!priv->grouped) {
		/* Just add the connections in order */
		for (iter = priv->connections, row = 0; iter; iter = iter->next, row++) {
			conn = iter->data;
			nmt_newt_listbox_append (priv->listbox, nm_connection_get_id (conn), conn);
			if (conn == selected_conn)
				selected_row = row;
		}
		if (selected_row >= row)
			selected_row = row - 1;
		nmt_newt_listbox_set_active (priv->listbox, selected_row);

		return;
	}

	types = nm_editor_utils_get_connection_type_list ();
	for (i = row = 0; types[i]; i++) {
		if (types[i]->setting_type == NM_TYPE_SETTING_VPN) {
			if (did_vpn)
				continue;
			did_vpn = TRUE;
		}

		did_header = FALSE;

		for (iter = priv->connections; iter; iter = iter->next) {
			NMSetting *setting;
			char *indented;

			conn = iter->data;
			setting = nm_connection_get_setting (conn, types[i]->setting_type);
			if (!setting)
				continue;
			if (!nm_connection_is_type (conn, nm_setting_get_name (setting)))
				continue;

			if (!did_header) {
				nmt_newt_listbox_append (priv->listbox, types[i]->name, NULL);
				if (row == selected_row)
					selected_row++;
				row++;
				did_header = TRUE;
			}

			indented = g_strdup_printf ("  %s", nm_connection_get_id (conn));
			nmt_newt_listbox_append (priv->listbox, indented, conn);
			g_free (indented);

			if (conn == selected_conn)
				selected_row = row;
			row++;
		}
	}

	if (selected_row >= row)
		selected_row = row - 1;
	nmt_newt_listbox_set_active (priv->listbox, selected_row);
}

static void
rebuild_on_connections_changed (GObject    *object,
                                GParamSpec *pspec,
                                gpointer    list)
{
	nmt_edit_connection_list_rebuild (list);
}

static void
nmt_edit_connection_list_constructed (GObject *object)
{
	NmtEditConnectionList *list = NMT_EDIT_CONNECTION_LIST (object);
	NmtEditConnectionListPrivate *priv = NMT_EDIT_CONNECTION_LIST_GET_PRIVATE (list);

	if (priv->extra)
		nmt_newt_button_box_add_widget_end (priv->buttons, priv->extra);

	g_signal_connect (nm_client, "notify::" NM_CLIENT_CONNECTIONS,
	                  G_CALLBACK (rebuild_on_connections_changed), list);

	nmt_edit_connection_list_rebuild (list);

	G_OBJECT_CLASS (nmt_edit_connection_list_parent_class)->constructed (object);
}

static void
add_clicked (NmtNewtButton *button, gpointer list)
{
	g_signal_emit (list, signals[ADD_CONNECTION], 0);
}

static void
edit_clicked (NmtNewtButton *button, gpointer list)
{
	NmtEditConnectionListPrivate *priv = NMT_EDIT_CONNECTION_LIST_GET_PRIVATE (list);
	NMConnection *connection;

	connection = nmt_newt_listbox_get_active_key (priv->listbox);
	g_return_if_fail (connection != NULL);

	g_signal_emit (list, signals[EDIT_CONNECTION], 0, connection);
}

static void
delete_clicked (NmtNewtButton *button, gpointer list)
{
	NmtEditConnectionListPrivate *priv = NMT_EDIT_CONNECTION_LIST_GET_PRIVATE (list);
	NMRemoteConnection *connection;

	connection = nmt_newt_listbox_get_active_key (priv->listbox);
	g_return_if_fail (connection != NULL);

	g_signal_emit (list, signals[REMOVE_CONNECTION], 0, connection);
}

static void
listbox_activated (NmtNewtWidget *listbox, gpointer list)
{
	NmtEditConnectionListPrivate *priv = NMT_EDIT_CONNECTION_LIST_GET_PRIVATE (list);

	edit_clicked (NMT_NEWT_BUTTON (priv->edit), list);
}

static void
nmt_edit_connection_list_finalize (GObject *object)
{
	NmtEditConnectionListPrivate *priv = NMT_EDIT_CONNECTION_LIST_GET_PRIVATE (object);

	free_connections (NMT_EDIT_CONNECTION_LIST (object));
	g_clear_object (&priv->extra);

	G_OBJECT_CLASS (nmt_edit_connection_list_parent_class)->finalize (object);
}

static void
nmt_edit_connection_list_set_property (GObject      *object,
                                       guint         prop_id,
                                       const GValue *value,
                                       GParamSpec   *pspec)
{
	NmtEditConnectionListPrivate *priv = NMT_EDIT_CONNECTION_LIST_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_GROUPED:
		priv->grouped = g_value_get_boolean (value);
		break;
	case PROP_CONNECTION_FILTER:
		priv->connection_filter = g_value_get_pointer (value);
		break;
	case PROP_CONNECTION_FILTER_DATA:
		priv->connection_filter_data = g_value_get_pointer (value);
		break;
	case PROP_EXTRA_WIDGET:
		priv->extra = g_value_get_object (value);
		if (priv->extra)
			g_object_ref_sink (priv->extra);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_edit_connection_list_get_property (GObject    *object,
                                       guint       prop_id,
                                       GValue     *value,
                                       GParamSpec *pspec)
{
	NmtEditConnectionListPrivate *priv = NMT_EDIT_CONNECTION_LIST_GET_PRIVATE (object);
	GPtrArray *connections;
	GSList *iter;

	switch (prop_id) {
	case PROP_GROUPED:
		g_value_set_boolean (value, priv->grouped);
		break;
	case PROP_CONNECTION_FILTER:
		g_value_set_pointer (value, priv->connection_filter);
		break;
	case PROP_CONNECTION_FILTER_DATA:
		g_value_set_pointer (value, priv->connection_filter_data);
		break;
	case PROP_EXTRA_WIDGET:
		g_value_set_object (value, priv->extra);
		break;
	case PROP_CONNECTIONS:
		connections = g_ptr_array_new_with_free_func (g_object_unref);
		for (iter = priv->connections; iter; iter = iter->next)
			g_ptr_array_add (connections, g_object_ref (iter->data));
		g_value_take_boxed (value, connections);
		break;
	case PROP_NUM_CONNECTIONS:
		g_value_set_int (value, g_slist_length (priv->connections));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_edit_connection_list_class_init (NmtEditConnectionListClass *list_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (list_class);

	g_type_class_add_private (list_class, sizeof (NmtEditConnectionListPrivate));

	/* virtual methods */
	object_class->constructed  = nmt_edit_connection_list_constructed;
	object_class->set_property = nmt_edit_connection_list_set_property;
	object_class->get_property = nmt_edit_connection_list_get_property;
	object_class->finalize     = nmt_edit_connection_list_finalize;

	/* signals */

	/**
	 * NmtEditConnectionList::add-connection:
	 * @list: the #NmtEditConnectionList
	 *
	 * Emitted when the user clicks the list's "Add" button.
	 */
	signals[ADD_CONNECTION] =
		g_signal_new ("add-connection",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NmtEditConnectionListClass, add_connection),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	/**
	 * NmtEditConnectionList::edit-connection:
	 * @list: the #NmtEditConnectionList
	 * @connection: the connection to edit
	 *
	 * Emitted when the user clicks the list's "Edit" button, or
	 * hits "Return" on the listbox.
	 */
	signals[EDIT_CONNECTION] =
		g_signal_new ("edit-connection",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NmtEditConnectionListClass, edit_connection),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              NM_TYPE_CONNECTION);

	/**
	 * NmtEditConnectionList::remove-connection:
	 * @list: the #NmtEditConnectionList
	 * @connection: the connection to remove
	 *
	 * Emitted when the user clicks the list's "Delete" button.
	 */
	signals[REMOVE_CONNECTION] =
		g_signal_new ("remove-connection",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NmtEditConnectionListClass, remove_connection),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              NM_TYPE_CONNECTION);

	/* properties */

	/**
	 * NmtEditConnectionList:grouped:
	 *
	 * If %TRUE, connections should be grouped by type, with headers
	 * indicating the types (as in the main connection list). If %FALSE,
	 * they will not be grouped (as in slave connection lists).
	 */
	g_object_class_install_property
		(object_class, PROP_GROUPED,
		 g_param_spec_boolean ("grouped", "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));
	
	/**
	 * NmtEditConnectionListFilter:
	 * @list: the #NmtEditConnectionList
	 * @connection: an #NMConnection
	 * @user_data: the user data
	 *
	 * Decides whether @connection should be displayed in @list.
	 *
	 * Returns: %TRUE or %FALSE
	 */
	/**
	 * NmtEditConnectionList:connection-filter:
	 *
	 * A callback function for filtering which connections appear in
	 * the list.
	 */
	g_object_class_install_property
		(object_class, PROP_CONNECTION_FILTER,
		 g_param_spec_pointer ("connection-filter", "", "",
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));
	/**
	 * NmtEditConnectionList:connection-filter-data:
	 *
	 * Data for the #NmtEditConnectionList:connection-filter.
	 */
	g_object_class_install_property
		(object_class, PROP_CONNECTION_FILTER_DATA,
		 g_param_spec_pointer ("connection-filter-data", "", "",
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NmtEditConnectionList:extra-widget:
	 *
	 * An extra button widget to display at the bottom of the button
	 * box.
	 */
	g_object_class_install_property
		(object_class, PROP_EXTRA_WIDGET,
		 g_param_spec_object ("extra-widget", "", "",
		                      NMT_TYPE_NEWT_WIDGET,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NmtEditConnectionList:connections:
	 *
	 * The list of connections in the widget.
	 *
	 * Element-Type: #NMConnection
	 */
	g_object_class_install_property
		(object_class, PROP_CONNECTIONS,
		 g_param_spec_boxed ("connections", "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NmtEditConnectionList:num-connections:
	 *
	 * The number of connections in the widget.
	 */
	g_object_class_install_property
		(object_class, PROP_NUM_CONNECTIONS,
		 g_param_spec_int ("num-connections", "", "",
		                   0, G_MAXINT, 0,
		                   G_PARAM_READABLE |
		                   G_PARAM_STATIC_STRINGS));
}
