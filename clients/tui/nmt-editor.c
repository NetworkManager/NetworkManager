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

#include <glib/gi18n-lib.h>
#include <nm-utils.h>

#include "nm-default.h"
#include "nmtui.h"

#include "nm-editor-utils.h"
#include "nmt-utils.h"

#include "nmt-device-entry.h"
#include "nmt-mac-entry.h"
#include "nmt-mtu-entry.h"

#include "nmt-page-bond.h"
#include "nmt-page-bridge.h"
#include "nmt-page-bridge-port.h"
#include "nmt-page-dsl.h"
#include "nmt-page-ethernet.h"
#include "nmt-page-infiniband.h"
#include "nmt-page-ip4.h"
#include "nmt-page-ip6.h"
#include "nmt-page-ppp.h"
#include "nmt-page-team.h"
#include "nmt-page-team-port.h"
#include "nmt-page-vlan.h"
#include "nmt-page-wifi.h"

G_DEFINE_TYPE (NmtEditor, nmt_editor, NMT_TYPE_NEWT_FORM)

#define NMT_EDITOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_EDITOR, NmtEditorPrivate))

typedef struct {
	NMConnection *orig_connection;
	NMConnection *edit_connection;

	NMEditorConnectionTypeData *type_data;

	GSList *pages;
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
connection_updated (GObject      *connection,
                    GAsyncResult *result,
                    gpointer      op)
{
	GError *error = NULL;

	nm_remote_connection_commit_changes_finish (NM_REMOTE_CONNECTION (connection), result, &error);
	nmt_sync_op_complete_boolean (op, error == NULL, error);
	g_clear_error (&error);
}

static void
connection_added (GObject      *client,
                  GAsyncResult *result,
                  gpointer      op)
{
	NMRemoteConnection *connection;
	GError *error = NULL;

	connection = nm_client_add_connection_finish (NM_CLIENT (client), result, &error);
	nmt_sync_op_complete_boolean (op, error == NULL, error);
	g_clear_object (&connection);
	g_clear_error (&error);
}

static void
save_connection_and_exit (NmtNewtButton *button,
                          gpointer       user_data)
{
	NmtEditor *editor = user_data;
	NmtEditorPrivate *priv = NMT_EDITOR_GET_PRIVATE (editor);
	NmtSyncOp op;
	GError *error = NULL;

	nm_connection_replace_settings_from_connection (priv->orig_connection,
	                                                priv->edit_connection);

	nmt_sync_op_init (&op);
	if (NM_IS_REMOTE_CONNECTION (priv->orig_connection)) {
		nm_remote_connection_commit_changes_async (NM_REMOTE_CONNECTION (priv->orig_connection),
		                                           TRUE, NULL, connection_updated, &op);
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
		nm_client_add_connection_async (nm_client, priv->orig_connection, TRUE,
		                                NULL, connection_added, &op);
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
got_secrets (GObject      *object,
             GAsyncResult *result,
             gpointer      op)
{
	GVariant *secrets;
	GError *error = NULL;

	secrets = nm_remote_connection_get_secrets_finish (NM_REMOTE_CONNECTION (object),
	                                                   result, &error);
	if (secrets)
		g_variant_ref (secrets);
	nmt_sync_op_complete_pointer (op, secrets, error);
	g_clear_error (&error);
}

static NMConnection *
build_edit_connection (NMConnection *orig_connection)
{
	NMConnection *edit_connection;
	GVariant *settings, *secrets;
	GVariantIter iter;
	const char *setting_name;
	NmtSyncOp op;

	edit_connection = nm_simple_connection_new_clone (orig_connection);

	if (!NM_IS_REMOTE_CONNECTION (orig_connection))
		return edit_connection;

	settings = nm_connection_to_dbus (orig_connection, NM_CONNECTION_SERIALIZE_NO_SECRETS);
	g_variant_iter_init (&iter, settings);
	while (g_variant_iter_next (&iter, "{&s@a{sv}}", &setting_name, NULL)) {
		nmt_sync_op_init (&op);
		nm_remote_connection_get_secrets_async (NM_REMOTE_CONNECTION (orig_connection),
		                                        setting_name, NULL, got_secrets, &op);
		/* FIXME: error handling */
		secrets = nmt_sync_op_wait_pointer (&op, NULL);
		if (secrets) {
			(void) nm_connection_update_secrets (edit_connection, setting_name, secrets, NULL);
			g_variant_unref (secrets);
		}
	}
	g_variant_unref (settings);

	return edit_connection;
}

static gboolean
permissions_transform_to_allusers (GBinding     *binding,
                                   const GValue *source_value,
                                   GValue       *target_value,
                                   gpointer      user_data)
{
	char **perms = g_value_get_boxed (source_value);

	g_value_set_boolean (target_value, g_strv_length (perms) == 0);
	return TRUE;
}

static gboolean
permissions_transform_from_allusers (GBinding     *binding,
                                     const GValue *source_value,
                                     GValue       *target_value,
                                     gpointer      user_data)
{
	gboolean allusers = g_value_get_boolean (source_value);
	char **perms = NULL;

	if (!allusers) {
		perms = g_new (char *, 2);

		perms[0] = g_strdup_printf ("user:%s:", g_get_user_name ());
		perms[1] = NULL;
	}
	g_value_take_boxed (target_value, perms);
	return TRUE;
}

static NmtNewtWidget *
add_sections_for_page (NmtEditor *editor, NmtEditorGrid *grid, NmtEditorPage *page)
{
	NmtEditorPrivate *priv = NMT_EDITOR_GET_PRIVATE (editor);
	NmtNewtWidget *first_section = NULL;
	const GSList *sections, *iter;

	g_return_val_if_fail (NMT_IS_EDITOR_PAGE (page), NULL);

	priv->pages = g_slist_prepend (priv->pages, page);

	sections = nmt_editor_page_get_sections (page);
	for (iter = sections; iter; iter = iter->next) {
		if (!first_section)
			first_section = iter->data;
		nmt_editor_grid_append (grid, NULL, iter->data, NULL);
	}

	return first_section;
}

static void
nmt_editor_constructed (GObject *object)
{
	NmtEditor *editor = NMT_EDITOR (object);
	NmtEditorPrivate *priv = NMT_EDITOR_GET_PRIVATE (editor);
	NMSettingConnection *s_con;
	NmtNewtWidget *vbox, *widget, *buttons;
	NmtEditorGrid *grid;
	const char *deventry_label;
	NmtDeviceEntry *deventry;
	GType hardware_type;
	const char *slave_type;
	NmtEditorPage *page;

	if (G_OBJECT_CLASS (nmt_editor_parent_class)->constructed)
		G_OBJECT_CLASS (nmt_editor_parent_class)->constructed (object);

	priv->edit_connection = build_edit_connection (priv->orig_connection);

	vbox = nmt_newt_grid_new ();

	s_con = nm_connection_get_setting_connection (priv->edit_connection);

	grid = NMT_EDITOR_GRID (nmt_editor_grid_new ());
	nmt_newt_grid_add (NMT_NEWT_GRID (vbox), NMT_NEWT_WIDGET (grid), 0, 0);

	/* Add the top widgets */

	widget = nmt_newt_entry_new (40, NMT_NEWT_ENTRY_NONEMPTY);
	g_object_bind_property (s_con, NM_SETTING_CONNECTION_ID,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Profile name"), widget, NULL);

	if (priv->type_data->virtual)
		hardware_type = G_TYPE_NONE;
	else
		hardware_type = priv->type_data->device_type;

	/* For connections involving multiple network devices, clarify which one
	 * NMSettingConnection:interface-name refers to.
	 */
	if (nm_connection_is_type (priv->edit_connection, NM_SETTING_PPPOE_SETTING_NAME))
		deventry_label = _("Ethernet device");
	else
		deventry_label = _("Device");

	widget = nmt_device_entry_new (deventry_label, 40, hardware_type);
	nmt_editor_grid_append (grid, NULL, widget, NULL);
	deventry = NMT_DEVICE_ENTRY (widget);
	g_object_bind_property (s_con, NM_SETTING_CONNECTION_INTERFACE_NAME,
	                        deventry, "interface-name",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

	nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	/* Now add the various pages... */

	if (nm_connection_is_type (priv->edit_connection, NM_SETTING_BOND_SETTING_NAME))
		page = nmt_page_bond_new (priv->edit_connection, deventry);
	else if (nm_connection_is_type (priv->edit_connection, NM_SETTING_BRIDGE_SETTING_NAME))
		page = nmt_page_bridge_new (priv->edit_connection, deventry);
	else if (nm_connection_is_type (priv->edit_connection, NM_SETTING_INFINIBAND_SETTING_NAME))
		page = nmt_page_infiniband_new (priv->edit_connection, deventry);
	else if (nm_connection_is_type (priv->edit_connection, NM_SETTING_PPPOE_SETTING_NAME))
		page = nmt_page_dsl_new (priv->edit_connection, deventry);
	else if (nm_connection_is_type (priv->edit_connection, NM_SETTING_TEAM_SETTING_NAME))
		page = nmt_page_team_new (priv->edit_connection, deventry);
	else if (nm_connection_is_type (priv->edit_connection, NM_SETTING_VLAN_SETTING_NAME))
		page = nmt_page_vlan_new (priv->edit_connection, deventry);
	else if (nm_connection_is_type (priv->edit_connection, NM_SETTING_WIRED_SETTING_NAME))
		page = nmt_page_ethernet_new (priv->edit_connection, deventry);
	else if (nm_connection_is_type (priv->edit_connection, NM_SETTING_WIRELESS_SETTING_NAME))
		page = nmt_page_wifi_new (priv->edit_connection, deventry);
	else
		g_assert_not_reached ();

	add_sections_for_page (editor, grid, page);
	nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	slave_type = nm_setting_connection_get_slave_type (s_con);
	if (slave_type) {
		if (!strcmp (slave_type, NM_SETTING_BRIDGE_SETTING_NAME))
			add_sections_for_page (editor, grid, nmt_page_bridge_port_new (priv->edit_connection));
		else if (!strcmp (slave_type, NM_SETTING_TEAM_SETTING_NAME))
			add_sections_for_page (editor, grid, nmt_page_team_port_new (priv->edit_connection));
	} else {
		NmtNewtWidget *section;

		section = add_sections_for_page (editor, grid, nmt_page_ip4_new (priv->edit_connection));

		/* Add a separator between ip4 and ip6 that's only visible if ip4 is open */
		widget = nmt_newt_separator_new ();
		g_object_bind_property (section, "open", widget, "visible", G_BINDING_SYNC_CREATE);
		nmt_editor_grid_append (grid, NULL, widget, NULL);

		add_sections_for_page (editor, grid, nmt_page_ip6_new (priv->edit_connection));

		nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);
	}

	/* And finally the bottom widgets */

	widget = nmt_newt_checkbox_new (_("Automatically connect"));
	g_object_bind_property (s_con, NM_SETTING_CONNECTION_AUTOCONNECT,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_checkbox_new (_("Available to all users"));
	g_object_bind_property_full (s_con, NM_SETTING_CONNECTION_PERMISSIONS,
	                             widget, "active",
	                             G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE,
	                             permissions_transform_to_allusers,
	                             permissions_transform_from_allusers,
	                             NULL, NULL);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	/* And the button box */

	buttons = nmt_newt_button_box_new (NMT_NEWT_BUTTON_BOX_HORIZONTAL);
	nmt_newt_grid_add (NMT_NEWT_GRID (vbox), buttons, 0, 1);
	nmt_newt_widget_set_padding (buttons, 0, 1, 0, 0);

	priv->cancel = nmt_newt_button_box_add_end (NMT_NEWT_BUTTON_BOX (buttons), _("Cancel"));
	nmt_newt_widget_set_exit_on_activate (priv->cancel, TRUE);

	priv->ok = nmt_newt_button_box_add_end (NMT_NEWT_BUTTON_BOX (buttons), _("OK"));
	g_signal_connect (priv->ok, "clicked", G_CALLBACK (save_connection_and_exit), editor);
	g_object_bind_property (NMT_NEWT_WIDGET (grid), "valid",
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

	g_slist_free_full (priv->pages, g_object_unref);

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
	g_object_class_install_property
		(object_class, PROP_CONNECTION,
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
	g_object_class_install_property
		(object_class, PROP_TYPE_DATA,
		 g_param_spec_pointer ("type-data", "", "",
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));
}
