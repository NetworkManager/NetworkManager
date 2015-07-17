/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Mu Qiao <qiaomuf@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 1999-2010 Gentoo Foundation, Inc.
 */

#include "config.h"

#include <string.h>
#include <glib/gstdio.h>
#include <nm-dbus-interface.h>
#include <nm-utils.h>
#include <nm-setting-wireless-security.h>
#include <nm-settings-connection.h>
#include <nm-system-config-interface.h>
#include "nm-logging.h"
#include "nm-ifnet-connection.h"
#include "connection_parser.h"
#include "net_parser.h"
#include "net_utils.h"
#include "wpa_parser.h"
#include "plugin.h"

G_DEFINE_TYPE (NMIfnetConnection, nm_ifnet_connection, NM_TYPE_SETTINGS_CONNECTION)

#define NM_IFNET_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IFNET_CONNECTION, NMIfnetConnectionPrivate))

enum {
	IFNET_SETUP_MONITORS,
	IFNET_CANCEL_MONITORS,
	IFNET_LAST_SIGNAL
};

static guint signals[IFNET_LAST_SIGNAL] = { 0 };

typedef struct {
	gchar *conn_name;
	NMSystemConfigInterface *config;
} NMIfnetConnectionPrivate;

NMIfnetConnection *
nm_ifnet_connection_new (NMConnection *source, const char *conn_name)
{
	NMConnection *tmp;
	GObject *object;
	GError *error = NULL;
	gboolean update_unsaved = TRUE;

	g_return_val_if_fail (source || conn_name, NULL);

	if (source)
		tmp = g_object_ref (source);
	else {
		tmp = ifnet_update_connection_from_config_block (conn_name, NULL, &error);
		if (!tmp) {
			g_error_free (error);
			return NULL;
		}

		/* If we just read the connection from disk, it's clearly not Unsaved */
		update_unsaved = FALSE;
	}

	object = (GObject *) g_object_new (NM_TYPE_IFNET_CONNECTION, NULL);
	g_assert (object);
	NM_IFNET_CONNECTION_GET_PRIVATE (object)->conn_name = g_strdup (conn_name);
	nm_settings_connection_replace_settings (NM_SETTINGS_CONNECTION (object),
	                                         tmp,
	                                         update_unsaved,
	                                         NULL,
	                                         NULL);
	g_object_unref (tmp);

	return NM_IFNET_CONNECTION (object);
}

static void
nm_ifnet_connection_init (NMIfnetConnection * connection)
{
}

const char *
nm_ifnet_connection_get_conn_name (NMIfnetConnection *connection)
{
	return NM_IFNET_CONNECTION_GET_PRIVATE (connection)->conn_name;
}

static void
commit_changes (NMSettingsConnection *connection,
                NMSettingsConnectionCommitReason commit_reason,
                NMSettingsConnectionCommitFunc callback,
                gpointer user_data)
{
	GError *error = NULL;
	NMIfnetConnectionPrivate *priv = NM_IFNET_CONNECTION_GET_PRIVATE (connection);
	gchar *new_name = NULL;
	gboolean success = FALSE;

	g_signal_emit (connection, signals[IFNET_CANCEL_MONITORS], 0);

	if (priv->conn_name) {
		/* Existing connection; update it */
		success = ifnet_update_parsers_by_connection (NM_CONNECTION (connection),
		                                              priv->conn_name,
		                                              CONF_NET_FILE,
		                                              WPA_SUPPLICANT_CONF,
		                                              &new_name,
		                                              NULL,
		                                              &error);
	} else {
		/* New connection, add it */
		success = ifnet_add_new_connection (NM_CONNECTION (connection),
		                                    CONF_NET_FILE,
		                                    WPA_SUPPLICANT_CONF,
		                                    &new_name,
		                                    NULL,
		                                    &error);
		if (success)
			reload_parsers ();
	}

	if (success) {
		/* update connection name */
		g_assert (new_name);
		g_free (priv->conn_name);
		priv->conn_name = new_name;

		NM_SETTINGS_CONNECTION_CLASS (nm_ifnet_connection_parent_class)->commit_changes (connection, commit_reason, callback, user_data);
		nm_log_info (LOGD_SETTINGS, "Successfully updated %s", priv->conn_name);
	} else {
		nm_log_warn (LOGD_SETTINGS, "Failed to update %s",
		             priv->conn_name ? priv->conn_name :
		             nm_connection_get_id (NM_CONNECTION (connection)));
		reload_parsers ();
		callback (connection, error, user_data);
		g_error_free (error);
	}

	g_signal_emit (connection, signals[IFNET_SETUP_MONITORS], 0);
}

static void 
do_delete (NMSettingsConnection *connection,
	       NMSettingsConnectionDeleteFunc callback,
	       gpointer user_data)
{
	GError *error = NULL;
	NMIfnetConnectionPrivate *priv = NM_IFNET_CONNECTION_GET_PRIVATE (connection);

	g_signal_emit (connection, signals[IFNET_CANCEL_MONITORS], 0);

	/* Only connections which exist in /etc/conf.d/net will have a conn_name */
	if (priv->conn_name) {
		if (!ifnet_delete_connection_in_parsers (priv->conn_name, CONF_NET_FILE, WPA_SUPPLICANT_CONF, NULL)) {
			nm_log_warn (LOGD_SETTINGS, "Failed to delete %s", priv->conn_name);
			reload_parsers ();
			callback (connection, error, user_data);
			g_error_free (error);
			g_signal_emit (connection, signals[IFNET_SETUP_MONITORS], 0);
			return;
		}
	}

	NM_SETTINGS_CONNECTION_CLASS (nm_ifnet_connection_parent_class)->delete (connection, callback, user_data);

	g_signal_emit (connection, signals[IFNET_SETUP_MONITORS], 0);

	nm_log_info (LOGD_SETTINGS, "Successfully deleted %s",
	             priv->conn_name ? priv->conn_name :
	             nm_connection_get_id (NM_CONNECTION (connection)));
}

static void
finalize (GObject * object)
{
	g_free (NM_IFNET_CONNECTION_GET_PRIVATE (object)->conn_name);
	G_OBJECT_CLASS (nm_ifnet_connection_parent_class)->finalize (object);
}

static void
nm_ifnet_connection_class_init (NMIfnetConnectionClass * ifnet_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ifnet_connection_class);
	NMSettingsConnectionClass *settings_class = NM_SETTINGS_CONNECTION_CLASS (ifnet_connection_class);

	g_type_class_add_private (ifnet_connection_class, sizeof (NMIfnetConnectionPrivate));

	object_class->finalize = finalize;
	settings_class->delete = do_delete;
	settings_class->commit_changes = commit_changes;

	signals[IFNET_SETUP_MONITORS] =
	    g_signal_new ("ifnet_setup_monitors",
			  G_OBJECT_CLASS_TYPE (object_class), G_SIGNAL_RUN_LAST,
			  0, NULL, NULL, g_cclosure_marshal_VOID__VOID,
			  G_TYPE_NONE, 0);
	signals[IFNET_CANCEL_MONITORS] =
	    g_signal_new ("ifnet_cancel_monitors",
			  G_OBJECT_CLASS_TYPE (object_class), G_SIGNAL_RUN_LAST,
			  0, NULL, NULL, g_cclosure_marshal_VOID__VOID,
			  G_TYPE_NONE, 0);

}
