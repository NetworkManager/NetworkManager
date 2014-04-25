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
 * SECTION:nmt-editor
 * @short_description: Connection editing form
 *
 * #NmtEditor is the top-level form for editing a connection.
 */

#include "config.h"

#include "nmt-editor.h"

#include <glib.h>
#include <glib/gi18n-lib.h>
#include <nm-utils.h>

#include "nmtui.h"

#include "nm-editor-utils.h"
#include "nmt-page-main.h"
#include "nmt-utils.h"

G_DEFINE_TYPE (NmtEditor, nmt_editor, NMT_TYPE_NEWT_FORM)

#define NMT_EDITOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_EDITOR, NmtEditorPrivate))

typedef struct {
	NMConnection *orig_connection;
	NMConnection *edit_connection;

	NMEditorConnectionTypeData *type_data;

	NmtNewtWidget *ok, *cancel;
	gboolean running;
} NmtEditorPrivate;

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_TYPE_DATA,

	LAST_PROP
};

/**
 * nmt_editor_new:
 * @connection: the #NMConnection to edit
 *
 * Creates a new #NmtEditor to edit @connection.
 *
 * Returns: a new #NmtEditor
 */
NmtNewtForm *
nmt_editor_new (NMConnection *connection)
{
	NMEditorConnectionTypeData *type_data;

	type_data = nm_editor_utils_get_connection_type_data (connection);
	if (!type_data) {
		NMSettingConnection *s_con;

		s_con = nm_connection_get_setting_connection (connection);
		if (s_con) {
			nmt_newt_message_dialog (_("Could not create editor for connection '%s' of type '%s'."),
			                         nm_connection_get_id (connection),
			                         nm_setting_connection_get_connection_type (s_con));
		} else {
			nmt_newt_message_dialog (_("Could not create editor for invalid connection '%s'."),
			                         nm_connection_get_id (connection));
		}

		return NULL;
	}

	return g_object_new (NMT_TYPE_EDITOR,
	                     "connection", connection,
	                     "type-data", type_data,
	                     "title", _("Edit Connection"),
	                     "fullscreen-vertical", TRUE,
	                     NULL);
}

static void
nmt_editor_init (NmtEditor *entry)
{
}

static void
connection_updated (NMRemoteConnection *connection,
                    GError             *error,
                    gpointer            op)
{
	nmt_sync_op_complete_boolean (op, error == NULL, error);
}

static void
connection_added (NMRemoteSettings   *settings,
                  NMRemoteConnection *connection,
                  GError             *error,
                  gpointer            op)
{
	nmt_sync_op_complete_boolean (op, error == NULL, error);
}

static void
save_connection_and_exit (NmtNewtButton *button,
                          gpointer       user_data)
{
	NmtEditor *editor = user_data;
	NmtEditorPrivate *priv = NMT_EDITOR_GET_PRIVATE (editor);
	NmtSyncOp op;
	GError *error = NULL;

	if (!nm_connection_replace_settings_from_connection (priv->orig_connection,
	                                                     priv->edit_connection,
	                                                     &error)) {
		nmt_newt_message_dialog (_("Error saving connection: %s"), error->message);
		g_error_free (error);
		return;
	}

	nmt_sync_op_init (&op);
	if (NM_IS_REMOTE_CONNECTION (priv->orig_connection)) {
		nm_remote_connection_commit_changes (NM_REMOTE_CONNECTION (priv->orig_connection),
		                                     connection_updated, &op);
		if (!nmt_sync_op_wait_boolean (&op, &error)) {
			nmt_newt_message_dialog (_("Unable to save connection: %s"),
			                         error->message);
			g_error_free (error);
			return;
		}

		/* Clear secrets so they don't lay around in memory; they'll get
		 * requested again anyway next time the connection is edited.
		 */
		nm_connection_clear_secrets (priv->orig_connection);
	} else {
		nm_remote_settings_add_connection (nm_settings, priv->orig_connection,
		                                   connection_added, &op);
		if (!nmt_sync_op_wait_boolean (&op, &error)) {
			nmt_newt_message_dialog (_("Unable to add new connection: %s"),
			                         error->message);
			g_error_free (error);
			return;
		}
	}

	nmt_newt_form_quit (NMT_NEWT_FORM (editor));
}

static void
got_secrets (NMRemoteConnection *connection,
             GHashTable         *secrets,
             GError             *error,
             gpointer            op)
{
	nmt_sync_op_complete_pointer (op, secrets, error);
}

static NMConnection *
build_edit_connection (NMConnection *orig_connection)
{
	NMConnection *edit_connection;
	GHashTable *settings, *secrets;
	GHashTableIter iter;
	const char *setting_name;
	NmtSyncOp op;

	edit_connection = nm_connection_duplicate (orig_connection);

	if (!NM_IS_REMOTE_CONNECTION (orig_connection))
		return edit_connection;

	settings = nm_connection_to_hash (orig_connection, NM_SETTING_HASH_FLAG_NO_SECRETS);
	g_hash_table_iter_init (&iter, settings);
	while (g_hash_table_iter_next (&iter, (gpointer) &setting_name, NULL)) {
		nmt_sync_op_init (&op);
		nm_remote_connection_get_secrets (NM_REMOTE_CONNECTION (orig_connection),
		                                  setting_name, got_secrets, &op);
		/* FIXME: error handling */
		secrets = nmt_sync_op_wait_pointer (&op, NULL);
		if (secrets)
			(void) nm_connection_update_secrets (edit_connection, setting_name, secrets, NULL);
	}
	g_hash_table_unref (settings);

	return edit_connection;
}

static void
nmt_editor_constructed (GObject *object)
{
	NmtEditor *editor = NMT_EDITOR (object);
	NmtEditorPrivate *priv = NMT_EDITOR_GET_PRIVATE (editor);
	NmtNewtWidget *vbox, *buttons, *page;

	if (G_OBJECT_CLASS (nmt_editor_parent_class)->constructed)
		G_OBJECT_CLASS (nmt_editor_parent_class)->constructed (object);

	priv->edit_connection = build_edit_connection (priv->orig_connection);

	vbox = nmt_newt_grid_new ();

	page = nmt_page_main_new (priv->edit_connection, priv->type_data);
	nmt_newt_grid_add (NMT_NEWT_GRID (vbox), page, 0, 0);

	buttons = nmt_newt_button_box_new (NMT_NEWT_BUTTON_BOX_HORIZONTAL);
	nmt_newt_grid_add (NMT_NEWT_GRID (vbox), buttons, 0, 1);
	nmt_newt_widget_set_padding (buttons, 0, 1, 0, 0);

	priv->cancel = nmt_newt_button_box_add_end (NMT_NEWT_BUTTON_BOX (buttons), _("Cancel"));
	nmt_newt_widget_set_exit_on_activate (priv->cancel, TRUE);

	priv->ok = nmt_newt_button_box_add_end (NMT_NEWT_BUTTON_BOX (buttons), _("OK"));
	g_signal_connect (priv->ok, "clicked", G_CALLBACK (save_connection_and_exit), editor);
	g_object_bind_property (page, "valid",
	                        priv->ok, "sensitive",
	                        G_BINDING_SYNC_CREATE);

	nmt_newt_form_set_content (NMT_NEWT_FORM (editor), vbox);
}

static void
nmt_editor_finalize (GObject *object)
{
	NmtEditorPrivate *priv = NMT_EDITOR_GET_PRIVATE (object);

	g_clear_object (&priv->orig_connection);
	g_clear_object (&priv->edit_connection);

	g_clear_object (&priv->ok);
	g_clear_object (&priv->cancel);

	G_OBJECT_CLASS (nmt_editor_parent_class)->finalize (object);
}

static void
nmt_editor_set_property (GObject      *object,
                         guint         prop_id,
                         const GValue *value,
                         GParamSpec   *pspec)
{
	NmtEditorPrivate *priv = NMT_EDITOR_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		priv->orig_connection = g_value_dup_object (value);
		break;
	case PROP_TYPE_DATA:
		priv->type_data = g_value_get_pointer (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_editor_get_property (GObject    *object,
                         guint       prop_id,
                         GValue     *value,
                         GParamSpec *pspec)
{
	NmtEditorPrivate *priv = NMT_EDITOR_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_object (value, priv->orig_connection);
		break;
	case PROP_TYPE_DATA:
		g_value_set_pointer (value, priv->type_data);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_editor_class_init (NmtEditorClass *entry_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (entry_class);

	g_type_class_add_private (entry_class, sizeof (NmtEditorPrivate));

	/* virtual methods */
	object_class->constructed  = nmt_editor_constructed;
	object_class->set_property = nmt_editor_set_property;
	object_class->get_property = nmt_editor_get_property;
	object_class->finalize     = nmt_editor_finalize;

	/**
	 * NmtEditor:connection:
	 *
	 * The connection being edited.
	 */
	g_object_class_install_property (object_class, PROP_CONNECTION,
	                                 g_param_spec_object ("connection", "", "",
	                                                      NM_TYPE_CONNECTION,
	                                                      G_PARAM_READWRITE |
	                                                      G_PARAM_CONSTRUCT_ONLY |
	                                                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtEditor:type-data:
	 *
	 * The #NmEditorConnectionTypeData for #NmtEditor:connection.
	 */
	g_object_class_install_property (object_class, PROP_TYPE_DATA,
	                                 g_param_spec_pointer ("type-data", "", "",
	                                                       G_PARAM_READWRITE |
	                                                       G_PARAM_CONSTRUCT_ONLY |
	                                                       G_PARAM_STATIC_STRINGS));
}
