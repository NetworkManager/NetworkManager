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

#include <string.h>
#include <glib/gstdio.h>
#include <NetworkManager.h>
#include <nm-utils.h>
#include <nm-setting-wireless-security.h>
#include <nm-settings-connection.h>
#include <nm-system-config-interface.h>
#include <nm-settings-error.h>
#include "nm-ifnet-connection.h"
#include "connection_parser.h"
#include "net_parser.h"
#include "net_utils.h"
#include "wpa_parser.h"
#include "plugin.h"

G_DEFINE_TYPE (NMIfnetConnection, nm_ifnet_connection, NM_TYPE_SETTINGS_CONNECTION)

#define NM_IFNET_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IFNET_CONNECTION, NMIfnetConnectionPrivate))
enum {
	PROP_ZERO,
	PROP_CONN_NAME,
	_PROP_END,
};

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
nm_ifnet_connection_new (const char *conn_name, NMConnection *source)
{
	NMConnection *tmp;
	GObject *object;
	GError *error = NULL;

	g_return_val_if_fail (conn_name != NULL, NULL);

	if (source)
		tmp = g_object_ref (source);
	else {
		tmp = ifnet_update_connection_from_config_block (conn_name, &error);
		if (!tmp){
			g_error_free (error);
			return NULL;
		}
	}

	object = (GObject *) g_object_new (NM_TYPE_IFNET_CONNECTION, NULL);
	if (!object) {
		g_object_unref (tmp);
		return NULL;
	}

	NM_IFNET_CONNECTION_GET_PRIVATE (object)->conn_name = g_strdup (conn_name);
	nm_settings_connection_replace_settings (NM_SETTINGS_CONNECTION (object), tmp, NULL);
	g_object_unref (tmp);

	return NM_IFNET_CONNECTION (object);
}

static void
nm_ifnet_connection_init (NMIfnetConnection * connection)
{
}

static void
commit_changes (NMSettingsConnection *connection,
                NMSettingsConnectionCommitFunc callback,
	            gpointer user_data)
{
	GError *error = NULL;
	NMIfnetConnectionPrivate *priv = NM_IFNET_CONNECTION_GET_PRIVATE (connection);
	gchar *new_name = NULL;

	g_signal_emit (connection, signals[IFNET_CANCEL_MONITORS], 0);
	if (!ifnet_update_parsers_by_connection (NM_CONNECTION (connection),
	                                         priv->conn_name,
	                                         CONF_NET_FILE,
	                                         WPA_SUPPLICANT_CONF,
	                                         &new_name,
	                                         &error)) {
		PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Failed to update %s", priv->conn_name);
		reload_parsers ();
		callback (connection, error, user_data);
		g_error_free (error);
		g_signal_emit (connection, signals[IFNET_SETUP_MONITORS], 0);
		return;
	}

	g_free (priv->conn_name);
	priv->conn_name = new_name;

	NM_SETTINGS_CONNECTION_CLASS (nm_ifnet_connection_parent_class)->commit_changes (connection, callback, user_data);
	PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Successfully updated %s", priv->conn_name);

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
	if (!ifnet_delete_connection_in_parsers
	    (priv->conn_name, CONF_NET_FILE, WPA_SUPPLICANT_CONF)) {
		PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Failed to delete %s",
			      priv->conn_name);
		reload_parsers ();
		callback (connection, error, user_data);
		g_error_free (error);
		g_signal_emit (connection, signals[IFNET_SETUP_MONITORS], 0);
		return;
	}

	NM_SETTINGS_CONNECTION_CLASS (nm_ifnet_connection_parent_class)->delete (connection, callback, user_data);

	PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Successfully deleted %s",
		      priv->conn_name);
	g_signal_emit (connection, signals[IFNET_SETUP_MONITORS], 0);
}

static void
finalize (GObject * object)
{
	NMIfnetConnectionPrivate *priv =
	    NM_IFNET_CONNECTION_GET_PRIVATE (object);
	g_return_if_fail (priv);

	g_free (priv->conn_name);
	G_OBJECT_CLASS (nm_ifnet_connection_parent_class)->finalize (object);
}

static void
nm_ifnet_connection_class_init (NMIfnetConnectionClass * ifnet_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ifnet_connection_class);
	NMSettingsConnectionClass *settings_class = NM_SETTINGS_CONNECTION_CLASS (ifnet_connection_class);

	g_type_class_add_private (ifnet_connection_class,
				  sizeof (NMIfnetConnectionPrivate));

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
