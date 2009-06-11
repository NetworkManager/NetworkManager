/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * (C) Copyright 2008 Novell, Inc.
 * (C) Copyright 2009 Red Hat, Inc.
 */

#include <netinet/ether.h>

#include <glib/gi18n.h>

#include <NetworkManager.h>
#include <nm-settings.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-utils.h>

#include "nm-dbus-glib-types.h"
#include "nm-marshal.h"
#include "nm-default-wired-connection.h"

G_DEFINE_TYPE (NMDefaultWiredConnection, nm_default_wired_connection, NM_TYPE_SYSCONFIG_CONNECTION)

#define NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEFAULT_WIRED_CONNECTION, NMDefaultWiredConnectionPrivate))

typedef struct {
	char *iface;
	GByteArray *mac;
	gboolean read_only;
} NMDefaultWiredConnectionPrivate;

enum {
	PROP_0,
	PROP_MAC,
	PROP_IFACE,
	PROP_READ_ONLY,
	LAST_PROP
};

enum {
	TRY_UPDATE,
	DELETED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


NMDefaultWiredConnection *
nm_default_wired_connection_new (const GByteArray *mac,
                                 const char *iface,
                                 gboolean read_only)
{

	g_return_val_if_fail (mac != NULL, NULL);
	g_return_val_if_fail (mac->len == ETH_ALEN, NULL);
	g_return_val_if_fail (iface != NULL, NULL);

	return g_object_new (NM_TYPE_DEFAULT_WIRED_CONNECTION,
	                     NM_DEFAULT_WIRED_CONNECTION_MAC, mac,
	                     NM_DEFAULT_WIRED_CONNECTION_IFACE, iface,
	                     NM_DEFAULT_WIRED_CONNECTION_READ_ONLY, read_only,
	                     NULL);
}

static GByteArray *
dup_wired_mac (NMExportedConnection *exported)
{
	NMConnection *wrapped;
	NMSettingWired *s_wired;
	const GByteArray *mac;
	GByteArray *dup;

	wrapped = nm_exported_connection_get_connection (exported);
	if (!wrapped)
		return NULL;

	s_wired = (NMSettingWired *) nm_connection_get_setting (wrapped, NM_TYPE_SETTING_WIRED);
	if (!s_wired)
		return NULL;

	mac = nm_setting_wired_get_mac_address (s_wired);	
	if (!mac || (mac->len != ETH_ALEN))
		return NULL;

	dup = g_byte_array_sized_new (ETH_ALEN);
	g_byte_array_append (dup, mac->data, ETH_ALEN);
	return dup;
}

static gboolean
update (NMExportedConnection *exported,
        GHashTable *new_settings,
        GError **error)
{
	NMDefaultWiredConnection *connection = NM_DEFAULT_WIRED_CONNECTION (exported);
	gboolean success;
	GByteArray *mac;

	/* Ensure object stays alive across signal emission */
	g_object_ref (exported);

	/* Save a copy of the current MAC address just in case the user
	 * changed it when updating the connection.
	 */
	mac = dup_wired_mac (exported);

	/* Let NMSysconfigConnection check permissions */
	success = NM_EXPORTED_CONNECTION_CLASS (nm_default_wired_connection_parent_class)->update (exported, new_settings, error);
	if (success) {
		g_signal_emit_by_name (connection, "try-update", new_settings, error);
		success = *error ? FALSE : TRUE;

		if (success)
			g_signal_emit (connection, signals[DELETED], 0, mac);
	}

	g_byte_array_free (mac, TRUE);
	g_object_unref (exported);
	return success;
}

static gboolean
do_delete (NMExportedConnection *exported, GError **error)
{
	gboolean success;
	GByteArray *mac;

	g_object_ref (exported);
	mac = dup_wired_mac (exported);

	success = NM_EXPORTED_CONNECTION_CLASS (nm_default_wired_connection_parent_class)->do_delete (exported, error);
	if (success)
		g_signal_emit (exported, signals[DELETED], 0, mac);
	
	g_byte_array_free (mac, TRUE);
	g_object_unref (exported);
	return success;
}

static void
nm_default_wired_connection_init (NMDefaultWiredConnection *self)
{
}

static GObject *
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDefaultWiredConnectionPrivate *priv;
	NMConnection *wrapped;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	char *id, *uuid;

	object = G_OBJECT_CLASS (nm_default_wired_connection_parent_class)->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	priv = NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE (object);

	wrapped = nm_connection_new ();

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	id = g_strdup_printf (_("Auto %s"), priv->iface);
	uuid = nm_utils_uuid_generate ();

	g_object_set (s_con,
		      NM_SETTING_CONNECTION_ID, id,
		      NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
		      NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
		      NM_SETTING_CONNECTION_UUID, uuid,
		      NM_SETTING_CONNECTION_READ_ONLY, priv->read_only,
		      NULL);

	g_free (id);
	g_free (uuid);

	nm_connection_add_setting (wrapped, NM_SETTING (s_con));

	/* Lock the connection to the specific device */
	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());
	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, priv->mac, NULL);
	nm_connection_add_setting (wrapped, NM_SETTING (s_wired));

	g_object_set (object, NM_EXPORTED_CONNECTION_CONNECTION, wrapped, NULL);
	g_object_unref (wrapped);

	return object;
}

static void
finalize (GObject *object)
{
	NMDefaultWiredConnectionPrivate *priv = NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE (object);

	g_free (priv->iface);
	g_byte_array_free (priv->mac, TRUE);

	G_OBJECT_CLASS (nm_default_wired_connection_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDefaultWiredConnectionPrivate *priv = NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MAC:
		g_value_set_pointer (value, priv->mac);
		break;
	case PROP_IFACE:
		g_value_set_string (value, priv->iface);
		break;
	case PROP_READ_ONLY:
		g_value_set_boolean (value, priv->read_only);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMDefaultWiredConnectionPrivate *priv = NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE (object);
	GByteArray *array;

	switch (prop_id) {
	case PROP_MAC:
		/* Construct only */
		array = g_value_get_pointer (value);
		if (priv->mac) {
			g_byte_array_free (priv->mac, TRUE);
			priv->mac = NULL;
		}
		if (array) {
			g_return_if_fail (array->len == ETH_ALEN);
			priv->mac = g_byte_array_sized_new (array->len);
			g_byte_array_append (priv->mac, array->data, ETH_ALEN);
		}
		break;
	case PROP_IFACE:
		g_free (priv->iface);
		priv->iface = g_value_dup_string (value);
		break;
	case PROP_READ_ONLY:
		priv->read_only = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static gboolean
try_update_signal_accumulator (GSignalInvocationHint *ihint,
                               GValue *return_accu,
                               const GValue *handler_return,
                               gpointer data)
{
	gpointer new_ptr = g_value_get_pointer (handler_return);

	g_value_set_pointer (return_accu, new_ptr);

	/* Continue if no error was returned from the handler */
	return new_ptr ? FALSE : TRUE;
}

static void
nm_default_wired_connection_class_init (NMDefaultWiredConnectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMExportedConnectionClass *exported_class = NM_EXPORTED_CONNECTION_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDefaultWiredConnectionPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	exported_class->update = update;
	exported_class->do_delete = do_delete;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_MAC,
		 g_param_spec_pointer (NM_DEFAULT_WIRED_CONNECTION_MAC,
		                       "MAC",
		                       "MAC Address",
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_IFACE,
		 g_param_spec_string (NM_DEFAULT_WIRED_CONNECTION_IFACE,
		                       "Iface",
		                       "Interface",
		                       NULL,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_READ_ONLY,
		 g_param_spec_boolean (NM_DEFAULT_WIRED_CONNECTION_READ_ONLY,
		                       "ReadOnly",
		                       "Read Only",
		                       FALSE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* Signals */
	signals[TRY_UPDATE] =
		g_signal_new ("try-update",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0, try_update_signal_accumulator, NULL,
			      _nm_marshal_POINTER__POINTER,
			      G_TYPE_POINTER, 1,
			      DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT);

	/* The 'deleted' signal is used to signal intentional deletions (like
	 * updating or user-requested deletion) rather than using the
	 * NMExportedConnection superclass' 'removed' signal, since that signal
	 * doesn't have the semantics we want; it gets emitted as a side-effect
	 * of various operations and is meant more for D-Bus clients instead
	 * of in-service uses.
	 */
	signals[DELETED] =
		g_signal_new ("deleted",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0, NULL, NULL,
			      g_cclosure_marshal_VOID__POINTER,
			      G_TYPE_NONE, 1, G_TYPE_POINTER);
}
