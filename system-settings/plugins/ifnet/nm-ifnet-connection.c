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
#include <nm-sysconfig-connection.h>
#include <nm-system-config-interface.h>
#include <nm-system-config-error.h>
#include "nm-ifnet-connection.h"
#include "connection_parser.h"
#include "net_parser.h"
#include "net_utils.h"
#include "wpa_parser.h"
#include "plugin.h"

static NMSettingsConnectionInterface *parent_settings_connection_iface;

static void settings_connection_interface_init (NMSettingsConnectionInterface *
						klass);

G_DEFINE_TYPE_EXTENDED (NMIfnetConnection, nm_ifnet_connection,
			NM_TYPE_SYSCONFIG_CONNECTION, 0,
			G_IMPLEMENT_INTERFACE
			(NM_TYPE_SETTINGS_CONNECTION_INTERFACE,
			 settings_connection_interface_init))
//    G_DEFINE_TYPE(NMIfnetConnection, nm_ifnet_connection,
//            NM_TYPE_SYSCONFIG_CONNECTION)
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
nm_ifnet_connection_new (gchar * conn_name)
{
	NMConnection *tmp;
	GObject *object;
	GError **error = NULL;

	g_return_val_if_fail (conn_name != NULL, NULL);
	tmp = ifnet_update_connection_from_config_block (conn_name, error);
	if (!tmp)
		return NULL;
	object = (GObject *) g_object_new (NM_TYPE_IFNET_CONNECTION,
					   NM_IFNET_CONNECTION_CONN_NAME,
					   conn_name, NULL);
	if (!object) {
		g_object_unref (tmp);
		return NULL;
	}
	nm_sysconfig_connection_update (NM_SYSCONFIG_CONNECTION (object), tmp,
					FALSE, NULL);
	g_object_unref (tmp);
	return NM_IFNET_CONNECTION (object);
}

static void
nm_ifnet_connection_init (NMIfnetConnection * connection)
{
}

static gboolean
update (NMSettingsConnectionInterface * connection,
	NMSettingsConnectionInterfaceUpdateFunc callback, gpointer user_data)
{
	GError *error = NULL;
	gchar *new_conn_name = NULL;
	gboolean result;
	NMIfnetConnectionPrivate *priv =
	    NM_IFNET_CONNECTION_GET_PRIVATE (connection);
	g_signal_emit (connection, signals[IFNET_CANCEL_MONITORS], 0);
	if (!ifnet_update_parsers_by_connection
	    (NM_CONNECTION (connection), priv->conn_name, &new_conn_name,
	     CONF_NET_FILE, WPA_SUPPLICANT_CONF, &error)) {
		if (new_conn_name)
			g_free (new_conn_name);
		PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Failed to update %s",
			      priv->conn_name);
		reload_parsers ();
		callback (connection, error, user_data);
		g_error_free (error);
		g_signal_emit (connection, signals[IFNET_SETUP_MONITORS], 0);
		return FALSE;
	}

	g_free (priv->conn_name);
	priv->conn_name = new_conn_name;
	result =
	    parent_settings_connection_iface->update (connection, callback,
						      user_data);
	if (result)
		PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Successfully updated %s",
			      priv->conn_name);
	g_signal_emit (connection, signals[IFNET_SETUP_MONITORS], 0);
	return result;
}

static gboolean
do_delete (NMSettingsConnectionInterface * connection,
	   NMSettingsConnectionInterfaceDeleteFunc callback, gpointer user_data)
{
	GError *error = NULL;
	gboolean result;
	NMIfnetConnectionPrivate *priv =
	    NM_IFNET_CONNECTION_GET_PRIVATE (connection);
	g_signal_emit (connection, signals[IFNET_CANCEL_MONITORS], 0);
	if (!ifnet_delete_connection_in_parsers
	    (priv->conn_name, CONF_NET_FILE, WPA_SUPPLICANT_CONF)) {
		PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Failed to delete %s",
			      priv->conn_name);
		reload_parsers ();
		callback (connection, error, user_data);
		g_error_free (error);
		g_signal_emit (connection, signals[IFNET_SETUP_MONITORS], 0);
		return FALSE;
	}
	result =
	    parent_settings_connection_iface->delete (connection, callback,
						      user_data);
	if (result)
		PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Successfully deleted %s",
			      priv->conn_name);
	g_signal_emit (connection, signals[IFNET_SETUP_MONITORS], 0);
	return result;
}

static void
settings_connection_interface_init (NMSettingsConnectionInterface * iface)
{
	parent_settings_connection_iface = g_type_interface_peek_parent (iface);
	iface->update = update;
	iface->delete = do_delete;
}

static void
set_property (GObject * object, guint prop_id,
	      const GValue * value, GParamSpec * pspec)
{
	NMIfnetConnectionPrivate *priv =
	    NM_IFNET_CONNECTION_GET_PRIVATE (object);
	g_return_if_fail (priv);

	switch (prop_id) {
	case PROP_CONN_NAME:
		if (priv->conn_name)
			g_free (priv->conn_name);
		priv->conn_name = g_strdup (g_value_get_pointer (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject * object, guint prop_id,
	      GValue * value, GParamSpec * pspec)
{
	NMIfnetConnectionPrivate *priv =
	    NM_IFNET_CONNECTION_GET_PRIVATE (object);
	g_return_if_fail (priv);

	switch (prop_id) {
	case PROP_CONN_NAME:
		g_value_set_pointer (value, priv->conn_name);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject * object)
{
	NMIfnetConnectionPrivate *priv =
	    NM_IFNET_CONNECTION_GET_PRIVATE (object);
	g_return_if_fail (priv);

	if (priv->conn_name)
		g_free (priv->conn_name);
	G_OBJECT_CLASS (nm_ifnet_connection_parent_class)->finalize (object);
}

static void
nm_ifnet_connection_class_init (NMIfnetConnectionClass * ifnet_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ifnet_connection_class);

	g_type_class_add_private (ifnet_connection_class,
				  sizeof (NMIfnetConnectionPrivate));

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* Properties */
	g_object_class_install_property
	    (object_class, PROP_CONN_NAME,
	     g_param_spec_pointer (NM_IFNET_CONNECTION_CONN_NAME,
				   "config_block",
				   "",
				   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
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
