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

#include "nm-default.h"

#include "nms-ifnet-connection.h"

#include <string.h>
#include <glib/gstdio.h>

#include "nm-dbus-interface.h"
#include "nm-utils.h"
#include "nm-setting-wireless-security.h"
#include "settings/nm-settings-connection.h"
#include "settings/nm-settings-plugin.h"

#include "nms-ifnet-connection-parser.h"
#include "nms-ifnet-net-parser.h"
#include "nms-ifnet-net-utils.h"
#include "nms-ifnet-wpa-parser.h"
#include "nms-ifnet-plugin.h"

/*****************************************************************************/

enum {
	IFNET_SETUP_MONITORS,
	IFNET_CANCEL_MONITORS,
	IFNET_LAST_SIGNAL
};

static guint signals[IFNET_LAST_SIGNAL] = { 0 };

typedef struct {
	gchar *conn_name;
	NMSettingsPlugin *config;
} NMIfnetConnectionPrivate;

struct _NMIfnetConnection {
	NMSettingsConnection parent;
	NMIfnetConnectionPrivate _priv;
};

struct _NMIfnetConnectionClass {
	NMSettingsConnectionClass parent;
};

G_DEFINE_TYPE (NMIfnetConnection, nm_ifnet_connection, NM_TYPE_SETTINGS_CONNECTION)

#define NM_IFNET_CONNECTION_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMIfnetConnection, NM_IS_IFNET_CONNECTION)

/*****************************************************************************/

const char *
nm_ifnet_connection_get_conn_name (NMIfnetConnection *connection)
{
	return NM_IFNET_CONNECTION_GET_PRIVATE (connection)->conn_name;
}

static gboolean
commit_changes (NMSettingsConnection *connection,
                NMConnection *new_connection,
                NMSettingsConnectionCommitReason commit_reason,
                NMConnection **out_reread_connection,
                char **out_logmsg_change,
                GError **error)
{
	NMIfnetConnectionPrivate *priv = NM_IFNET_CONNECTION_GET_PRIVATE ((NMIfnetConnection *) connection);
	char *new_name = NULL;
	gboolean success = FALSE;
	gboolean added = FALSE;

	nm_assert (out_reread_connection && !*out_reread_connection);
	nm_assert (!out_logmsg_change || !*out_logmsg_change);

	g_signal_emit (connection, signals[IFNET_CANCEL_MONITORS], 0);

	if (priv->conn_name) {
		success = ifnet_update_parsers_by_connection (new_connection,
		                                              priv->conn_name,
		                                              CONF_NET_FILE,
		                                              WPA_SUPPLICANT_CONF,
		                                              &new_name,
		                                              NULL,
		                                              error);
	} else {
		added = TRUE;
		success = ifnet_add_new_connection (new_connection,
		                                    CONF_NET_FILE,
		                                    WPA_SUPPLICANT_CONF,
		                                    &new_name,
		                                    NULL,
		                                    error);
	}

	g_assert (!!success == (new_name != NULL));
	if (success) {
		g_free (priv->conn_name);
		priv->conn_name = new_name;
	}

	reload_parsers ();

	g_signal_emit (connection, signals[IFNET_SETUP_MONITORS], 0);

	if (success) {
		NM_SET_OUT (out_logmsg_change,
		            g_strdup_printf ("ifcfg-rh: %s %s",
		                             added ? "persist" : "updated",
		                             new_name));
	}
	return success;
}

static gboolean
delete (NMSettingsConnection *connection,
        GError **error)
{
	NMIfnetConnectionPrivate *priv = NM_IFNET_CONNECTION_GET_PRIVATE ((NMIfnetConnection *) connection);

	/* Only connections which exist in /etc/conf.d/net will have a conn_name */
	if (priv->conn_name) {
		g_signal_emit (connection, signals[IFNET_CANCEL_MONITORS], 0);

		if (!ifnet_delete_connection_in_parsers (priv->conn_name, CONF_NET_FILE, WPA_SUPPLICANT_CONF, NULL)) {
			nm_log_warn (LOGD_SETTINGS, "Failed to delete %s", priv->conn_name);
			reload_parsers ();
			/* let's not return an error. */
		}

		g_signal_emit (connection, signals[IFNET_SETUP_MONITORS], 0);
	}

	return TRUE;
}

/*****************************************************************************/

static void
nm_ifnet_connection_init (NMIfnetConnection * connection)
{
}

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
			nm_log_warn (LOGD_SETTINGS, "Could not read connection '%s': %s",
			             conn_name, error->message);
			g_error_free (error);
			return NULL;
		}

		/* If we just read the connection from disk, it's clearly not Unsaved */
		update_unsaved = FALSE;
	}

	object = (GObject *) g_object_new (NM_TYPE_IFNET_CONNECTION, NULL);

	NM_IFNET_CONNECTION_GET_PRIVATE ((NMIfnetConnection *) object)->conn_name = g_strdup (conn_name);
	if (!nm_settings_connection_update (NM_SETTINGS_CONNECTION (object),
	                                    tmp,
	                                    update_unsaved
	                                      ? NM_SETTINGS_CONNECTION_PERSIST_MODE_UNSAVED
	                                      : NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP_SAVED,
	                                    NM_SETTINGS_CONNECTION_COMMIT_REASON_NONE,
	                                    NULL,
	                                    NULL)) {
		g_object_unref (object);
		return NULL;
	}
	g_object_unref (tmp);

	return NM_IFNET_CONNECTION (object);
}

static void
finalize (GObject * object)
{
	g_free (NM_IFNET_CONNECTION_GET_PRIVATE ((NMIfnetConnection *) object)->conn_name);
	G_OBJECT_CLASS (nm_ifnet_connection_parent_class)->finalize (object);
}

static void
nm_ifnet_connection_class_init (NMIfnetConnectionClass * ifnet_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ifnet_connection_class);
	NMSettingsConnectionClass *settings_class = NM_SETTINGS_CONNECTION_CLASS (ifnet_connection_class);

	object_class->finalize = finalize;

	settings_class->delete = delete;
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
