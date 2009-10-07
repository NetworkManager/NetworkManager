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
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-utils.h>

#include "nm-dbus-glib-types.h"
#include "nm-marshal.h"
#include "nm-default-wired-connection.h"
#include "nm-settings-connection-interface.h"

static NMSettingsConnectionInterface *parent_settings_connection_iface;

static void settings_connection_interface_init (NMSettingsConnectionInterface *iface);

G_DEFINE_TYPE_EXTENDED (NMDefaultWiredConnection, nm_default_wired_connection, NM_TYPE_SYSCONFIG_CONNECTION, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SETTINGS_CONNECTION_INTERFACE,
                                               settings_connection_interface_init))

#define NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEFAULT_WIRED_CONNECTION, NMDefaultWiredConnectionPrivate))

typedef struct {
	NMDevice *device;
	GByteArray *mac;
	gboolean read_only;
} NMDefaultWiredConnectionPrivate;

enum {
	PROP_0,
	PROP_MAC,
	PROP_DEVICE,
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
                                 NMDevice *device,
                                 gboolean read_only)
{

	g_return_val_if_fail (mac != NULL, NULL);
	g_return_val_if_fail (mac->len == ETH_ALEN, NULL);
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return g_object_new (NM_TYPE_DEFAULT_WIRED_CONNECTION,
	                     NM_DEFAULT_WIRED_CONNECTION_MAC, mac,
	                     NM_DEFAULT_WIRED_CONNECTION_DEVICE, device,
	                     NM_DEFAULT_WIRED_CONNECTION_READ_ONLY, read_only,
	                     NULL);
}

NMDevice *
nm_default_wired_connection_get_device (NMDefaultWiredConnection *wired)
{
	g_return_val_if_fail (NM_IS_DEFAULT_WIRED_CONNECTION (wired), NULL);

	return NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE (wired)->device;
}

static gboolean
update (NMSettingsConnectionInterface *connection,
	    NMSettingsConnectionInterfaceUpdateFunc callback,
	    gpointer user_data)
{
	NMDefaultWiredConnection *self = NM_DEFAULT_WIRED_CONNECTION (connection);

	/* Keep the object alive over try-update since it might get removed
	 * from the settings service there, but we still need it for the callback.
	 */
	g_object_ref (connection);
	g_signal_emit (self, signals[TRY_UPDATE], 0);
	callback (connection, NULL, user_data);
	g_object_unref (connection);
	return TRUE;
}

static gboolean 
do_delete (NMSettingsConnectionInterface *connection,
	       NMSettingsConnectionInterfaceDeleteFunc callback,
	       gpointer user_data)
{
	NMDefaultWiredConnection *self = NM_DEFAULT_WIRED_CONNECTION (connection);
	NMDefaultWiredConnectionPrivate *priv = NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE (connection);

	g_signal_emit (self, signals[DELETED], 0, priv->mac);
	return parent_settings_connection_iface->delete (connection, callback, user_data);
}

/****************************************************************/

static void
settings_connection_interface_init (NMSettingsConnectionInterface *iface)
{
	parent_settings_connection_iface = g_type_interface_peek_parent (iface);
	iface->update = update;
	iface->delete = do_delete;
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
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	char *id, *uuid;

	object = G_OBJECT_CLASS (nm_default_wired_connection_parent_class)->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	priv = NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE (object);

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	id = g_strdup_printf (_("Auto %s"), nm_device_get_iface (priv->device));
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

	nm_connection_add_setting (NM_CONNECTION (object), NM_SETTING (s_con));

	/* Lock the connection to the specific device */
	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());
	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, priv->mac, NULL);
	nm_connection_add_setting (NM_CONNECTION (object), NM_SETTING (s_wired));

	return object;
}

static void
finalize (GObject *object)
{
	NMDefaultWiredConnectionPrivate *priv = NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE (object);

	g_object_unref (priv->device);
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
	case PROP_DEVICE:
		g_value_set_object (value, priv->device);
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
	case PROP_DEVICE:
		if (priv->device)
			g_object_unref (priv->device);
		priv->device = g_value_dup_object (value);
		break;
	case PROP_READ_ONLY:
		priv->read_only = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_default_wired_connection_class_init (NMDefaultWiredConnectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDefaultWiredConnectionPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_MAC,
		 g_param_spec_pointer (NM_DEFAULT_WIRED_CONNECTION_MAC,
		                       "MAC",
		                       "MAC Address",
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_DEVICE,
		 g_param_spec_object (NM_DEFAULT_WIRED_CONNECTION_DEVICE,
		                       "Device",
		                       "Device",
		                       NM_TYPE_DEVICE,
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
			      0, NULL, NULL,
			      g_cclosure_marshal_VOID__VOID,
			      G_TYPE_NONE, 0);

	/* The 'deleted' signal is used to signal intentional deletions (like
	 * updating or user-requested deletion) rather than using the
	 * superclass' 'removed' signal, since that signal doesn't have the
	 * semantics we want; it gets emitted as a side-effect of various operations
	 * and is meant more for D-Bus clients instead of in-service uses.
	 */
	signals[DELETED] =
		g_signal_new ("deleted",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0, NULL, NULL,
			      g_cclosure_marshal_VOID__POINTER,
			      G_TYPE_NONE, 1, G_TYPE_POINTER);
}
