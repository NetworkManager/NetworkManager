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
 * SECTION:nmtui-edit
 * @short_description: nm-connection-editor-like functionality
 *
 * nmtui-edit implements editing #NMConnections.
 */

#include "nm-default.h"

#include <stdlib.h>

#include "NetworkManager.h"

#include "nmtui.h"
#include "nmtui-edit.h"
#include "nmt-edit-connection-list.h"
#include "nmt-editor.h"
#include "nmt-utils.h"

#include "nm-editor-utils.h"

static void
list_add_connection (NmtEditConnectionList *list,
                     gpointer               form)
{
	nmt_add_connection ();
	nmt_newt_form_set_focus (form, NMT_NEWT_WIDGET (list));
}

static void
list_edit_connection (NmtEditConnectionList *list,
                      NMConnection          *connection,
                      gpointer               form)
{
	nmt_edit_connection (connection);
	nmt_newt_form_set_focus (form, NMT_NEWT_WIDGET (list));
}

static void
list_remove_connection (NmtEditConnectionList  *list,
                        NMRemoteConnection     *connection,
                        gpointer                form)
{
	nmt_remove_connection (connection);
	nmt_newt_form_set_focus (form, NMT_NEWT_WIDGET (list));
}

static gboolean
edit_connection_list_filter (NmtEditConnectionList *list,
                             NMConnection          *connection,
                             gpointer               user_data)
{
	NMSettingConnection *s_con;
	const char *master, *slave_type;
	const char *uuid, *ifname;
	const GPtrArray *conns;
	int i;
	gboolean found_master = FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	g_return_val_if_fail (s_con != NULL, FALSE);

	master = nm_setting_connection_get_master (s_con);
	if (!master)
		return TRUE;
	slave_type = nm_setting_connection_get_slave_type (s_con);
	if (   g_strcmp0 (slave_type, NM_SETTING_BOND_SETTING_NAME) != 0
	    && g_strcmp0 (slave_type, NM_SETTING_TEAM_SETTING_NAME) != 0
	    && g_strcmp0 (slave_type, NM_SETTING_BRIDGE_SETTING_NAME) != 0)
		return TRUE;

	conns = nm_client_get_connections (nm_client);
	for (i = 0; i < conns->len; i++) {
		NMConnection *candidate = conns->pdata[i];

		uuid = nm_connection_get_uuid (candidate);
		ifname = nm_connection_get_interface_name (candidate);
		if (!g_strcmp0 (master, uuid) || !g_strcmp0 (master, ifname)) {
			found_master = TRUE;
			break;
		}
	}

	return !found_master;
}

static NmtNewtForm *
nmt_edit_main_connection_list (void)
{
	int screen_width, screen_height;
	NmtNewtForm *form;
	NmtNewtWidget *quit, *list;

	newtGetScreenSize (&screen_width, &screen_height);

	form = g_object_new (NMT_TYPE_NEWT_FORM,
	                     "y", 2,
	                     "height", screen_height - 4,
	                     "escape-exits", TRUE,
	                     NULL);

	quit = nmt_newt_button_new (_("Quit"));
	nmt_newt_widget_set_exit_on_activate (quit, TRUE);

	list = g_object_new (NMT_TYPE_EDIT_CONNECTION_LIST,
	                     "extra-widget", quit,
	                     "connection-filter", edit_connection_list_filter,
	                     NULL);

	g_signal_connect (list, "add-connection",
	                  G_CALLBACK (list_add_connection), form);
	g_signal_connect (list, "edit-connection",
	                  G_CALLBACK (list_edit_connection), form);
	g_signal_connect (list, "remove-connection",
	                  G_CALLBACK (list_remove_connection), form);

	nmt_newt_form_set_content (form, list);
	return form;
}

#define NMT_TYPE_ADD_CONNECTION    (nmt_add_connection_get_type ())
#define NMT_ADD_CONNECTION(obj)    (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_ADD_CONNECTION, NmtAddConnection))
#define NMT_IS_ADD_CONNECTION(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_ADD_CONNECTION))

typedef NmtNewtForm NmtAddConnection;
typedef NmtNewtFormClass NmtAddConnectionClass;

GType nmt_add_connection_get_type (void);

G_DEFINE_TYPE (NmtAddConnection, nmt_add_connection, NMT_TYPE_NEWT_FORM)

#define NMT_ADD_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_ADD_CONNECTION, NmtAddConnectionPrivate))

typedef struct {
	NmtNewtTextbox *textbox;
	NmtNewtListbox *listbox;

	char *primary_text;
	char *secondary_text;
	NMConnection *master;
	NmtAddConnectionTypeFilter type_filter;
	gpointer type_filter_data;

	gboolean single_type;
} NmtAddConnectionPrivate;

enum {
	PROP_0,

	PROP_PRIMARY_TEXT,
	PROP_SECONDARY_TEXT,
	PROP_MASTER,
	PROP_TYPE_FILTER,
	PROP_TYPE_FILTER_DATA,

	LAST_PROP
};

static void
create_connection (NmtNewtWidget *widget, gpointer list)
{
	NmtAddConnectionPrivate *priv = NMT_ADD_CONNECTION_GET_PRIVATE (list);
	GType type = (GType) GPOINTER_TO_SIZE (nmt_newt_listbox_get_active_key (priv->listbox));
	NMConnection *connection;

	connection = nm_editor_utils_create_connection (type, priv->master, nm_client);
	nmt_edit_connection (connection);
	g_object_unref (connection);

	nmt_newt_form_quit (list);
}

static void
nmt_add_connection_init (NmtAddConnection *form)
{
	NmtAddConnectionPrivate *priv = NMT_ADD_CONNECTION_GET_PRIVATE (form);
	NmtNewtWidget *textbox, *listbox, *button;
	NmtNewtGrid *grid, *buttons;

	grid = NMT_NEWT_GRID (nmt_newt_grid_new ());

	textbox = nmt_newt_textbox_new (0, 60);
	priv->textbox = NMT_NEWT_TEXTBOX (textbox);
	nmt_newt_grid_add (grid, textbox, 0, 0);

	listbox = nmt_newt_listbox_new (5, NMT_NEWT_LISTBOX_SCROLL);
	priv->listbox = NMT_NEWT_LISTBOX (listbox);
	g_signal_connect (priv->listbox, "activated", G_CALLBACK (create_connection), form);
	nmt_newt_grid_add (grid, listbox, 0, 1);
	nmt_newt_widget_set_padding (listbox, 0, 1, 0, 0);
	nmt_newt_grid_set_flags (grid, listbox, NMT_NEWT_GRID_EXPAND_X);

	// FIXME: VPN description textbox

	buttons = NMT_NEWT_GRID (nmt_newt_grid_new ());
	nmt_newt_grid_add (grid, NMT_NEWT_WIDGET (buttons), 0, 2);
	nmt_newt_widget_set_padding (NMT_NEWT_WIDGET (buttons), 0, 1, 0, 0);

	button = g_object_ref_sink (nmt_newt_button_new (_("Cancel")));
	nmt_newt_widget_set_exit_on_activate (button, TRUE);
	nmt_newt_grid_add (NMT_NEWT_GRID (buttons), button, 0, 0);
	nmt_newt_widget_set_padding (button, 0, 0, 1, 0);
	nmt_newt_grid_set_flags (NMT_NEWT_GRID (buttons), button,
	                         NMT_NEWT_GRID_EXPAND_X | NMT_NEWT_GRID_ANCHOR_RIGHT |
	                         NMT_NEWT_GRID_FILL_Y);

	button = g_object_ref_sink (nmt_newt_button_new (_("Create")));
	g_signal_connect (button, "clicked", G_CALLBACK (create_connection), form);
	nmt_newt_grid_add (NMT_NEWT_GRID (buttons), button, 1, 0);

	nmt_newt_form_set_content (NMT_NEWT_FORM (form), NMT_NEWT_WIDGET (grid));
}

static void
nmt_add_connection_constructed (GObject *object)
{
	NmtAddConnectionPrivate *priv = NMT_ADD_CONNECTION_GET_PRIVATE (object);
	NMEditorConnectionTypeData **types;
	char *text;
	int i, num_types;

	if (priv->secondary_text) {
		text = g_strdup_printf ("%s\n\n%s",
		                        priv->primary_text,
		                        priv->secondary_text);
	} else
		text = g_strdup (priv->primary_text);
	nmt_newt_textbox_set_text (priv->textbox, text);
	g_free (text);

	types = nm_editor_utils_get_connection_type_list ();
	for (i = num_types = 0; types[i]; i++) {
		if (priv->type_filter && !priv->type_filter (types[i]->setting_type, priv->type_filter_data))
			continue;
		nmt_newt_listbox_append (priv->listbox, types[i]->name,
		                         GSIZE_TO_POINTER (types[i]->setting_type));
		num_types++;
	}

	if (num_types == 1)
		priv->single_type = TRUE;

	G_OBJECT_CLASS (nmt_add_connection_parent_class)->constructed (object);
}

static void
nmt_add_connection_show (NmtNewtForm *form)
{
	NmtAddConnectionPrivate *priv = NMT_ADD_CONNECTION_GET_PRIVATE (form);

	if (priv->single_type) {
		nmt_newt_listbox_set_active (priv->listbox, 0);
		create_connection (NMT_NEWT_WIDGET (priv->listbox), g_object_ref (form));
	} else
		NMT_NEWT_FORM_CLASS (nmt_add_connection_parent_class)->show (form);
}

static void
nmt_add_connection_finalize (GObject *object)
{
	NmtAddConnectionPrivate *priv = NMT_ADD_CONNECTION_GET_PRIVATE (object);

	g_free (priv->primary_text);
	g_free (priv->secondary_text);
	g_clear_object (&priv->master);

	G_OBJECT_CLASS (nmt_add_connection_parent_class)->finalize (object);
}

static void
nmt_add_connection_set_property (GObject      *object,
                                 guint         prop_id,
                                 const GValue *value,
                                 GParamSpec   *pspec)
{
	NmtAddConnectionPrivate *priv = NMT_ADD_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PRIMARY_TEXT:
		priv->primary_text = g_value_dup_string (value);
		break;
	case PROP_SECONDARY_TEXT:
		priv->secondary_text = g_value_dup_string (value);
		break;
	case PROP_MASTER:
		priv->master = g_value_dup_object (value);
		break;
	case PROP_TYPE_FILTER:
		priv->type_filter = g_value_get_pointer (value);
		break;
	case PROP_TYPE_FILTER_DATA:
		priv->type_filter_data = g_value_get_pointer (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_add_connection_get_property (GObject    *object,
                                 guint       prop_id,
                                 GValue     *value,
                                 GParamSpec *pspec)
{
	NmtAddConnectionPrivate *priv = NMT_ADD_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PRIMARY_TEXT:
		g_value_set_string (value, priv->primary_text);
		break;
	case PROP_SECONDARY_TEXT:
		g_value_set_string (value, priv->secondary_text);
		break;
	case PROP_MASTER:
		g_value_set_object (value, priv->master);
		break;
	case PROP_TYPE_FILTER:
		g_value_set_pointer (value, priv->type_filter);
		break;
	case PROP_TYPE_FILTER_DATA:
		g_value_set_pointer (value, priv->type_filter_data);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_add_connection_class_init (NmtAddConnectionClass *add_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (add_class);
	NmtNewtFormClass *form_class = NMT_NEWT_FORM_CLASS (add_class);

	g_type_class_add_private (add_class, sizeof (NmtAddConnectionPrivate));

	/* virtual methods */
	object_class->constructed  = nmt_add_connection_constructed;
	object_class->set_property = nmt_add_connection_set_property;
	object_class->get_property = nmt_add_connection_get_property;
	object_class->finalize     = nmt_add_connection_finalize;

	form_class->show = nmt_add_connection_show;

	g_object_class_install_property
		(object_class, PROP_PRIMARY_TEXT,
		 g_param_spec_string ("primary-text", "", "",
		                      _("Select the type of connection you wish to create."),
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_SECONDARY_TEXT,
		 g_param_spec_string ("secondary-text", "", "",
#if 0
		                      _("If you are creating a VPN, and the VPN connection you "
		                      "wish to create does not appear in the list, you may "
		                      "not have the correct VPN plugin installed."),
#else
		                      NULL,
#endif
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_MASTER,
		 g_param_spec_object ("master", "", "",
		                      NM_TYPE_CONNECTION,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_TYPE_FILTER,
		 g_param_spec_pointer ("type-filter", "", "",
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_TYPE_FILTER_DATA,
		 g_param_spec_pointer ("type-filter-data", "", "",
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));
}

void
nmt_add_connection (void)
{
	NmtNewtForm *form;

	form = g_object_new (NMT_TYPE_ADD_CONNECTION,
	                     "title", _("New Connection"),
	                     NULL);
	nmt_newt_form_show (form);
	g_object_unref (form);
}

void
nmt_add_connection_full (const char                 *primary_text,
                         const char                 *secondary_text,
                         NMConnection               *master,
                         NmtAddConnectionTypeFilter  type_filter,
                         gpointer                    type_filter_data)
{
	NmtNewtForm *form;

	form = g_object_new (NMT_TYPE_ADD_CONNECTION,
	                     "title", _("New Connection"),
	                     "primary-text", primary_text,
	                     "secondary-text", secondary_text,
	                     "master", master,
	                     "type-filter", type_filter,
	                     "type-filter-data", type_filter_data,
	                     NULL);
	nmt_newt_form_show (form);
	g_object_unref (form);
}

void
nmt_edit_connection (NMConnection *connection)
{
	NmtNewtForm *editor;

	editor = nmt_editor_new (connection);
	if (!editor)
		return;

	nmt_newt_form_show (editor);
	g_object_unref (editor);
}

typedef struct {
	NmtSyncOp op;
	gboolean got_callback, got_signal;
	NMRemoteConnection *connection;
} ConnectionDeleteData;

static void
connection_deleted_callback (GObject      *connection,
                             GAsyncResult *result,
                             gpointer      user_data)
{
	ConnectionDeleteData *data = user_data;
	GError *error = NULL;

	if (!nm_remote_connection_delete_finish (data->connection, result, &error)) {
		nmt_newt_message_dialog (_("Unable to delete connection: %s"),
		                         error->message);
	} else
		data->got_callback = TRUE;

	if (error || (data->got_callback && data->got_signal))
		nmt_sync_op_complete_boolean (&data->op, error == NULL, error);
	g_clear_error (&error);
}

static void
connection_removed_signal (NMClient           *client,
                           NMRemoteConnection *connection,
                           gpointer            user_data)
{
	ConnectionDeleteData *data = user_data;

	if (connection == data->connection) {
		data->got_signal = TRUE;
		if (data->got_callback && data->got_signal)
			nmt_sync_op_complete_boolean (&data->op, TRUE, NULL);
	}
}

static void
remove_one_connection (NMRemoteConnection *connection)
{
	ConnectionDeleteData data;
	GError *error = NULL;

	data.got_callback = data.got_signal = FALSE;
	nmt_sync_op_init (&data.op);

	data.connection = connection;
	g_signal_connect (nm_client, NM_CLIENT_CONNECTION_REMOVED,
	                  G_CALLBACK (connection_removed_signal), &data);
	nm_remote_connection_delete_async (connection, NULL, connection_deleted_callback, &data);

	if (!nmt_sync_op_wait_boolean (&data.op, &error)) {
		nmt_newt_message_dialog (_("Could not delete connection '%s': %s"),
		                         nm_connection_get_id (NM_CONNECTION (connection)),
		                         error->message);
		g_error_free (error);
	}

	g_signal_handlers_disconnect_by_func (nm_client, G_CALLBACK (connection_removed_signal), &data);
}

void
nmt_remove_connection (NMRemoteConnection *connection)
{
	const GPtrArray *all_conns;
	GSList *slaves, *iter;
	int i;
	NMRemoteConnection *slave;
	NMSettingConnection *s_con;
	const char *uuid, *iface, *master;
	int choice;

	choice = nmt_newt_choice_dialog (_("Cancel"),
	                                 _("Delete"),
	                                 _("Are you sure you want to delete the connection '%s'?"),
	                                 nm_connection_get_id (NM_CONNECTION (connection)));
	if (choice == 1)
		return;

	g_object_ref (connection);
	remove_one_connection (connection);

	uuid = nm_connection_get_uuid (NM_CONNECTION (connection));
	iface = nm_connection_get_interface_name (NM_CONNECTION (connection));

	all_conns = nm_client_get_connections (nm_client);
	slaves = NULL;
	for (i = 0; i < all_conns->len; i++) {
		slave = all_conns->pdata[i];
		s_con = nm_connection_get_setting_connection (NM_CONNECTION (slave));
		master = nm_setting_connection_get_master (s_con);
		if (master) {
			if (!g_strcmp0 (master, uuid) || !g_strcmp0 (master, iface))
				slaves = g_slist_prepend (slaves, g_object_ref (slave));
		}
	}

	for (iter = slaves; iter; iter = iter->next)
		remove_one_connection (iter->data);
	g_slist_free_full (slaves, g_object_unref);

	g_object_unref (connection);
}

NmtNewtForm *
nmtui_edit (int argc, char **argv)
{
	NMConnection *conn = NULL;

	if (argc == 2) {
		if (nm_utils_is_uuid (argv[1]))
			conn = NM_CONNECTION (nm_client_get_connection_by_uuid (nm_client, argv[1]));
		if (!conn)
			conn = NM_CONNECTION (nm_client_get_connection_by_id (nm_client, argv[1]));

		if (!conn) {
			nmt_newt_message_dialog ("%s: no such connection '%s'\n", argv[0], argv[1]);
			return NULL;
		}

		return nmt_editor_new (conn);
	} else
		return nmt_edit_main_connection_list ();
}
