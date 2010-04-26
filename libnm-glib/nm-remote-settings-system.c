/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
 */

#include <string.h>
#include <NetworkManager.h>
#include <nm-connection.h>

#include "nm-marshal.h"
#include "nm-dbus-glib-types.h"
#include "nm-remote-settings-system.h"
#include "nm-settings-system-bindings.h"
#include "nm-settings-system-interface.h"

static void settings_system_interface_init (NMSettingsSystemInterface *klass);

G_DEFINE_TYPE_EXTENDED (NMRemoteSettingsSystem, nm_remote_settings_system, NM_TYPE_REMOTE_SETTINGS, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SETTINGS_SYSTEM_INTERFACE, settings_system_interface_init))

#define NM_REMOTE_SETTINGS_SYSTEM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_REMOTE_SETTINGS_SYSTEM, NMRemoteSettingsSystemPrivate))

typedef struct {
	DBusGProxy *proxy;
	DBusGProxy *props_proxy;

	char *hostname;
	gboolean can_modify;

	NMSettingsSystemPermissions permissions;
	gboolean have_permissions;

	gboolean disposed;
} NMRemoteSettingsSystemPrivate;

static void
properties_changed_cb (DBusGProxy *proxy,
                       GHashTable *properties,
                       gpointer user_data)
{
	NMRemoteSettingsSystem *self = NM_REMOTE_SETTINGS_SYSTEM (user_data);
	NMRemoteSettingsSystemPrivate *priv = NM_REMOTE_SETTINGS_SYSTEM_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer key, tmp;

	g_hash_table_iter_init (&iter, properties);
	while (g_hash_table_iter_next (&iter, &key, &tmp)) {
		GValue *value = tmp;

		if (!strcmp ((const char *) key, "Hostname")) {
			g_free (priv->hostname);
			priv->hostname = g_value_dup_string (value);
			g_object_notify (G_OBJECT (self), NM_SETTINGS_SYSTEM_INTERFACE_HOSTNAME);
		}

		if (!strcmp ((const char *) key, "CanModify")) {
			priv->can_modify = g_value_get_boolean (value);
			g_object_notify (G_OBJECT (self), NM_SETTINGS_SYSTEM_INTERFACE_CAN_MODIFY);
		}
	}
}

static void
get_all_cb  (DBusGProxy *proxy,
             DBusGProxyCall *call,
             gpointer user_data)
{
	NMRemoteSettingsSystem *self = NM_REMOTE_SETTINGS_SYSTEM (user_data);
	GHashTable *props = NULL;
	GError *error = NULL;

	if (!dbus_g_proxy_end_call (proxy, call, &error,
	                            DBUS_TYPE_G_MAP_OF_VARIANT, &props,
	                            G_TYPE_INVALID)) {
		/* Don't warn when the call times out because the settings service can't
		 * be activated or whatever.
		 */
		if (!(error->domain == DBUS_GERROR && error->code == DBUS_GERROR_NO_REPLY)) {
			g_warning ("%s: couldn't retrieve system settings properties: (%d) %s.",
			           __func__,
			           error ? error->code : -1,
			           (error && error->message) ? error->message : "(unknown)");
		}
		g_clear_error (&error);
		return;
	}

	properties_changed_cb (NULL, props, self);
	g_hash_table_destroy (props);
}

typedef struct {
	NMSettingsSystemInterface *settings;
	NMSettingsSystemSaveHostnameFunc callback;
	gpointer callback_data;
} SaveHostnameInfo;

static void
save_hostname_cb (DBusGProxy *proxy,
                  DBusGProxyCall *call,
                  gpointer user_data)
{
	SaveHostnameInfo *info = user_data;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID);
	info->callback (info->settings, error, info->callback_data);
	g_clear_error (&error);
}

static gboolean
save_hostname (NMSettingsSystemInterface *settings,
	           const char *hostname,
	           NMSettingsSystemSaveHostnameFunc callback,
	           gpointer user_data)
{
	NMRemoteSettingsSystem *self = NM_REMOTE_SETTINGS_SYSTEM (settings);
	NMRemoteSettingsSystemPrivate *priv = NM_REMOTE_SETTINGS_SYSTEM_GET_PRIVATE (self);
	SaveHostnameInfo *info;

	info = g_malloc0 (sizeof (SaveHostnameInfo));
	info->settings = settings;
	info->callback = callback;
	info->callback_data = user_data;

	dbus_g_proxy_begin_call (priv->proxy, "SaveHostname",
	                         save_hostname_cb,
	                         info,
	                         g_free,
	                         G_TYPE_STRING, hostname ? hostname : "",
	                         G_TYPE_INVALID);
	return TRUE;
}

typedef struct {
	NMSettingsSystemInterface *settings;
	NMSettingsSystemGetPermissionsFunc callback;
	gpointer callback_data;
} GetPermissionsInfo;

static void
get_permissions_cb  (DBusGProxy *proxy,
                     DBusGProxyCall *call,
                     gpointer user_data)
{
	GetPermissionsInfo *info = user_data;
	NMRemoteSettingsSystem *self = NM_REMOTE_SETTINGS_SYSTEM (info->settings);
	NMRemoteSettingsSystemPrivate *priv = NM_REMOTE_SETTINGS_SYSTEM_GET_PRIVATE (self);
	NMSettingsSystemPermissions permissions = NM_SETTINGS_SYSTEM_PERMISSION_NONE;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, call, &error,
	                       G_TYPE_UINT, &permissions,
	                       G_TYPE_INVALID);
	priv->permissions = permissions;
	priv->have_permissions = !error;
	info->callback (info->settings, permissions, error, info->callback_data);
	g_clear_error (&error);
}

static gboolean
get_permissions (NMSettingsSystemInterface *settings,
                 NMSettingsSystemGetPermissionsFunc callback,
                 gpointer user_data)
{
	NMRemoteSettingsSystemPrivate *priv = NM_REMOTE_SETTINGS_SYSTEM_GET_PRIVATE (settings);
	GetPermissionsInfo *info;

	/* Skip D-Bus if we already have permissions */
	if (priv->have_permissions) {
		callback (settings, priv->permissions, NULL, user_data);
		return TRUE;
	}

	/* Otherwise fetch them from NM */
	info = g_malloc0 (sizeof (GetPermissionsInfo));
	info->settings = settings;
	info->callback = callback;
	info->callback_data = user_data;

	dbus_g_proxy_begin_call (priv->proxy, "GetPermissions",
	                         get_permissions_cb,
	                         info,
	                         g_free,
	                         G_TYPE_INVALID);
	return TRUE;
}

static void
check_permissions_cb (DBusGProxy *proxy, gpointer user_data)
{
	NMRemoteSettingsSystem *self = NM_REMOTE_SETTINGS_SYSTEM (user_data);
	NMRemoteSettingsSystemPrivate *priv = NM_REMOTE_SETTINGS_SYSTEM_GET_PRIVATE (self);

	/* Permissions need to be re-fetched */
	priv->have_permissions = FALSE;
	g_signal_emit_by_name (self, NM_SETTINGS_SYSTEM_INTERFACE_CHECK_PERMISSIONS);
}

/****************************************************************/

static void
settings_system_interface_init (NMSettingsSystemInterface *klass)
{
	/* interface implementation */
	klass->save_hostname = save_hostname;
	klass->get_permissions = get_permissions;
}

/**
 * nm_remote_settings_system_new:
 * @bus: a valid and connected D-Bus connection
 *
 * Creates a new object representing the remote system settings service.
 *
 * Returns: the new remote system settings object on success, or %NULL on failure
 **/
NMRemoteSettingsSystem *
nm_remote_settings_system_new (DBusGConnection *bus)
{
	g_return_val_if_fail (bus != NULL, NULL);

	return (NMRemoteSettingsSystem *) g_object_new (NM_TYPE_REMOTE_SETTINGS_SYSTEM,
	                                                NM_REMOTE_SETTINGS_BUS, bus,
	                                                NM_REMOTE_SETTINGS_SCOPE, NM_CONNECTION_SCOPE_SYSTEM,
	                                                NULL);
}

static void
nm_remote_settings_system_init (NMRemoteSettingsSystem *self)
{
}

static GObject *
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMRemoteSettingsSystemPrivate *priv;
	DBusGConnection *bus = NULL;

	object = G_OBJECT_CLASS (nm_remote_settings_system_parent_class)->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	priv = NM_REMOTE_SETTINGS_SYSTEM_GET_PRIVATE (object);

	g_object_get (G_OBJECT (object), NM_REMOTE_SETTINGS_BUS, &bus, NULL);
	g_assert (bus);

	/* D-Bus properties proxy */
	priv->props_proxy = dbus_g_proxy_new_for_name (bus,
	                                               NM_DBUS_SERVICE_SYSTEM_SETTINGS,
	                                               NM_DBUS_PATH_SETTINGS,
	                                               "org.freedesktop.DBus.Properties");
	g_assert (priv->props_proxy);

	/* System settings proxy */
	priv->proxy = dbus_g_proxy_new_for_name (bus,
	                                         NM_DBUS_SERVICE_SYSTEM_SETTINGS,
	                                         NM_DBUS_PATH_SETTINGS,
	                                         NM_DBUS_IFACE_SETTINGS_SYSTEM);
	g_assert (priv->proxy);
	dbus_g_proxy_set_default_timeout (priv->proxy, G_MAXINT);

	dbus_g_object_register_marshaller (g_cclosure_marshal_VOID__BOXED,
	                                   G_TYPE_NONE,
	                                   DBUS_TYPE_G_MAP_OF_VARIANT,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->proxy, "PropertiesChanged",
	                         DBUS_TYPE_G_MAP_OF_VARIANT,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "PropertiesChanged",
	                             G_CALLBACK (properties_changed_cb),
	                             object,
	                             NULL);

	/* Monitor for permissions changes */
	dbus_g_proxy_add_signal (priv->proxy, "CheckPermissions", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "CheckPermissions",
	                             G_CALLBACK (check_permissions_cb),
	                             object,
	                             NULL);

	/* Get properties */
	dbus_g_proxy_begin_call (priv->props_proxy, "GetAll",
	                         get_all_cb,
	                         object,
	                         NULL,
	                         G_TYPE_STRING, NM_DBUS_IFACE_SETTINGS_SYSTEM,
	                         G_TYPE_INVALID);

	dbus_g_connection_unref (bus);

	return object;
}

static void
dispose (GObject *object)
{
	NMRemoteSettingsSystemPrivate *priv = NM_REMOTE_SETTINGS_SYSTEM_GET_PRIVATE (object);

	if (priv->disposed)
		return;

	priv->disposed = TRUE;

	g_free (priv->hostname);

	g_object_unref (priv->props_proxy);
	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_remote_settings_system_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMRemoteSettingsSystemPrivate *priv = NM_REMOTE_SETTINGS_SYSTEM_GET_PRIVATE (object);

	switch (prop_id) {
	case NM_SETTINGS_SYSTEM_INTERFACE_PROP_HOSTNAME:
		g_value_set_string (value, priv->hostname);
		break;
	case NM_SETTINGS_SYSTEM_INTERFACE_PROP_CAN_MODIFY:
		g_value_set_boolean (value, priv->can_modify);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_remote_settings_system_class_init (NMRemoteSettingsSystemClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMRemoteSettingsSystemPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	/* Properties */
	g_object_class_override_property (object_class,
									  NM_SETTINGS_SYSTEM_INTERFACE_PROP_HOSTNAME,
									  NM_SETTINGS_SYSTEM_INTERFACE_HOSTNAME);

	g_object_class_override_property (object_class,
									  NM_SETTINGS_SYSTEM_INTERFACE_PROP_CAN_MODIFY,
									  NM_SETTINGS_SYSTEM_INTERFACE_CAN_MODIFY);
}

