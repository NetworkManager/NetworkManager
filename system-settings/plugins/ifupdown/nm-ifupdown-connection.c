/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* NetworkManager system settings service (ifupdown)
 *
 * Alexander Sack <asac@ubuntu.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2007,2008 Canonical Ltd.
 */

#include <string.h>
#include <glib/gstdio.h>
#include <NetworkManager.h>
#include <nm-utils.h>
#include <nm-setting-wireless-security.h>
#include <nm-system-config-interface.h>
#include <nm-system-config-error.h>
#include <nm-settings.h>
#include "nm-ifupdown-connection.h"
#include "parser.h"

G_DEFINE_TYPE (NMIfupdownConnection,
			nm_ifupdown_connection,
			NM_TYPE_EXPORTED_CONNECTION)

#define NM_IFUPDOWN_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IFUPDOWN_CONNECTION, NMIfupdownConnectionPrivate))

typedef struct {
	if_block *ifblock;
} NMIfupdownConnectionPrivate;

enum {
	PROP_ZERO,
	PROP_IFBLOCK,
	_PROP_END,
};


static void
service_get_secrets (NMExportedConnection *exported,
                     const gchar *setting_name,
                     const gchar **hints,
                     gboolean request_new,
                     DBusGMethodInvocation *context);


NMIfupdownConnection*
nm_ifupdown_connection_new (if_block *block)
{
	g_return_val_if_fail (block != NULL, NULL);

	return (NMIfupdownConnection *) g_object_new (NM_TYPE_IFUPDOWN_CONNECTION,
										 NM_IFUPDOWN_CONNECTION_IFBLOCK, block,
										 NULL);
}

static GHashTable *
get_settings (NMExportedConnection *exported)
{
	return nm_connection_to_hash (nm_exported_connection_get_connection (exported));
}

static gboolean
update (NMExportedConnection *exported,
	   GHashTable *new_settings,
	   GError **err)
{
	g_set_error (err, NM_SYSCONFIG_SETTINGS_ERROR,
			   NM_SYSCONFIG_SETTINGS_ERROR_UPDATE_NOT_SUPPORTED,
			   "%s.%d - %s", __FILE__, __LINE__, "connection update not supported (read-only).");
	return FALSE;
}

static gboolean
delete (NMExportedConnection *exported, GError **err)
{
	g_set_error (err, NM_SYSCONFIG_SETTINGS_ERROR,
			   NM_SYSCONFIG_SETTINGS_ERROR_DELETE_NOT_SUPPORTED,
			   "%s", "ifupdown - connection delete not supported (read-only).");
	return FALSE;
}

/* GObject */
static void
nm_ifupdown_connection_init (NMIfupdownConnection *connection)
{
}

static GObject *
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	GObject *object;
	NMIfupdownConnectionPrivate *priv;
	NMConnection *wrapped = nm_connection_new();

	object = G_OBJECT_CLASS (nm_ifupdown_connection_parent_class)->constructor (type, n_construct_params, construct_params);
	g_return_val_if_fail (object, NULL);

	priv = NM_IFUPDOWN_CONNECTION_GET_PRIVATE (object);
	if (!priv) {
		nm_warning ("%s.%d - no private instance.", __FILE__, __LINE__);
		goto err;
	}
	if (!priv->ifblock) {
		nm_warning ("(ifupdown) ifblock not provided to constructor.");
		goto err;
	}

	g_object_set (object, NM_EXPORTED_CONNECTION_CONNECTION, wrapped, NULL);
	g_object_unref (wrapped);

	return object;

 err:
	g_object_unref (object);
	return NULL;
}

static void
finalize (GObject *object)
{
	G_OBJECT_CLASS (nm_ifupdown_connection_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMIfupdownConnectionPrivate *priv = NM_IFUPDOWN_CONNECTION_GET_PRIVATE (object);
	g_return_if_fail (priv);

	switch (prop_id) {
	case PROP_IFBLOCK:
		priv->ifblock = g_value_get_pointer (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMIfupdownConnectionPrivate *priv = NM_IFUPDOWN_CONNECTION_GET_PRIVATE (object);
	g_return_if_fail (priv);

	switch (prop_id) {
	case PROP_IFBLOCK:
		g_value_set_pointer (value, priv->ifblock);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ifupdown_connection_class_init (NMIfupdownConnectionClass *ifupdown_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ifupdown_connection_class);
	NMExportedConnectionClass *connection_class = NM_EXPORTED_CONNECTION_CLASS (ifupdown_connection_class);

	g_type_class_add_private (ifupdown_connection_class, sizeof (NMIfupdownConnectionPrivate));

	/* Virtual methods */
	object_class->constructor  = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	connection_class->get_settings = get_settings;
	connection_class->update       = update;
	connection_class->delete       = delete;
	connection_class->service_get_secrets = service_get_secrets;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_IFBLOCK,
		 g_param_spec_pointer (NM_IFUPDOWN_CONNECTION_IFBLOCK,
						   "ifblock",
						   "",
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

static void
service_get_secrets (NMExportedConnection *exported,
                     const gchar *setting_name,
                     const gchar **hints,
                     gboolean request_new,
                     DBusGMethodInvocation *context)
{
	NMConnection *connection;
	GError *error = NULL;
	GHashTable *settings = NULL;
	GHashTable *secrets = NULL;
	NMSetting *setting;

	PLUGIN_PRINT ("SCPlugin-Ifupdown", "get_secrets for setting_name:'%s')", setting_name);

	connection = nm_exported_connection_get_connection (exported);
	setting = nm_connection_get_setting_by_name (connection, setting_name);

	if (!setting) {
		g_set_error (&error, NM_SETTINGS_ERROR,
				   NM_SETTINGS_ERROR_INVALID_CONNECTION,
				   "%s.%d - Connection didn't have requested setting '%s'.",
				   __FILE__, __LINE__, setting_name);
		PLUGIN_PRINT ("SCPlugin-Ifupdown", "%s", error->message);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	settings = g_hash_table_new_full (g_str_hash, g_str_equal,
							    g_free, (GDestroyNotify) g_hash_table_destroy);

	if (!settings) {
		g_set_error (&error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INTERNAL_ERROR,
				   "%s.%d - failed to hash setting (OOM?)",
				   __FILE__, __LINE__);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	if (!strcmp (setting_name, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME)) {
		secrets = nm_setting_to_hash (setting);
		if (secrets) {
			g_hash_table_insert(settings, g_strdup(setting_name), secrets);
			dbus_g_method_return (context, settings);
		} else {
			g_set_error (&error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INTERNAL_ERROR,
					   "%s.%d - nm_setting_to_hash failed (OOM?)",
					   __FILE__, __LINE__);
			dbus_g_method_return_error (context, error);
			g_error_free (error);
			g_hash_table_destroy (settings);
		}
	} else {
		g_set_error (&error, NM_SETTING_WIRELESS_SECURITY_ERROR, 1,
				   "%s.%d - security setting name not supported '%s'.",
				   __FILE__, __LINE__, setting_name);
		PLUGIN_PRINT ("SCPlugin-Ifupdown", "%s", error->message);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}
