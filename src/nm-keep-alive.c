/*
 * NetworkManager -- Inhibition management
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
 * Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-keep-alive.h"

#include <string.h>

#include "settings/nm-settings-connection.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMKeepAlive,
	PROP_ALIVE,
);

typedef struct {
	NMSettingsConnection *connection;
	GDBusConnection *dbus_connection;
	char *dbus_client;

	guint subscription_id;

	bool floating:1;
	bool forced:1;
	bool alive:1;
} NMKeepAlivePrivate;

struct _NMKeepAlive {
	GObject parent;
	NMKeepAlivePrivate _priv;
};

struct _NMKeepAliveClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMKeepAlive, nm_keep_alive, G_TYPE_OBJECT)

#define NM_KEEP_ALIVE_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMKeepAlive, NM_IS_KEEP_ALIVE)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_CORE
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "keep-alive", __VA_ARGS__)

/*****************************************************************************/

static gboolean
_is_alive (NMKeepAlive *self)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	if (   priv->floating
	    || priv->forced)
		return TRUE;

	if (   priv->connection
	    && NM_FLAGS_HAS (nm_settings_connection_get_flags (priv->connection),
	                     NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE))
		return TRUE;

	if (priv->dbus_client)
		return TRUE;

	return FALSE;
}

static void
_notify_alive (NMKeepAlive *self)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	if (priv->alive == _is_alive (self))
		return;
	priv->alive = !priv->alive;
	_notify (self, PROP_ALIVE);
}

gboolean
nm_keep_alive_is_alive (NMKeepAlive *self)
{
	return NM_KEEP_ALIVE_GET_PRIVATE (self)->alive;
}

/*****************************************************************************/

void
nm_keep_alive_sink (NMKeepAlive *self)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	if (priv->floating) {
		priv->floating = FALSE;
		_notify_alive (self);
	}
}

void
nm_keep_alive_set_forced (NMKeepAlive *self, gboolean forced)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	if (priv->forced != (!!forced)) {
		priv->forced = forced;
		_notify_alive (self);
	}
}

/*****************************************************************************/

static void
connection_flags_changed (NMSettingsConnection *connection,
                          NMKeepAlive          *self)
{
	_notify_alive (self);
}

static void
_set_settings_connection_watch_visible (NMKeepAlive *self,
                                        NMSettingsConnection *connection,
                                        gboolean emit_signal)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);
	gs_unref_object NMSettingsConnection *old_connection = NULL;

	if (priv->connection == connection)
		return;

	if (priv->connection) {
		g_signal_handlers_disconnect_by_func (priv->connection,
		                                      G_CALLBACK (connection_flags_changed),
		                                      self);
		old_connection = g_steal_pointer (&priv->connection);
	}

	if (connection) {
		priv->connection = g_object_ref (connection);
		g_signal_connect (priv->connection,
		                  NM_SETTINGS_CONNECTION_FLAGS_CHANGED,
		                  G_CALLBACK (connection_flags_changed),
		                  self);
	}

	if (emit_signal)
		_notify_alive (self);
}

void
nm_keep_alive_set_settings_connection_watch_visible (NMKeepAlive         *self,
                                                     NMSettingsConnection *connection)
{
	_set_settings_connection_watch_visible (self, connection, TRUE);
}

/*****************************************************************************/

static void
cleanup_dbus_watch (NMKeepAlive *self)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	_LOGD ("Cleanup DBus client watch");

	g_clear_pointer (&priv->dbus_client, g_free);

	if (priv->dbus_connection)
		g_dbus_connection_signal_unsubscribe (priv->dbus_connection,
		                                      priv->subscription_id);
	g_clear_object (&priv->dbus_connection);
}

static void
name_owner_changed_cb (GDBusConnection *connection,
                       const char      *sender_name,
                       const char      *object_path,
                       const char      *interface_name,
                       const char      *signal_name,
                       GVariant        *parameters,
                       gpointer         user_data)
{
	NMKeepAlive *self = NM_KEEP_ALIVE (user_data);
	const char *old_owner;
	const char *new_owner;

	g_variant_get (parameters, "(&s&s&s)", NULL, &old_owner, &new_owner);

	if (!nm_streq0 (new_owner, ""))
		return;

	_LOGD ("DBus client for keep alive disappeared from bus");
	cleanup_dbus_watch (self);
	_notify_alive (self);
}

void
nm_keep_alive_set_dbus_client_watch (NMKeepAlive *self,
                                     GDBusConnection *connection,
                                     const char *client_address)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	cleanup_dbus_watch (self);

	if (client_address == NULL)
		return;

	_LOGD ("Registering dbus client watch for keep alive");

	priv->dbus_client = g_strdup (client_address);
	priv->dbus_connection = g_object_ref (connection);
	priv->subscription_id = g_dbus_connection_signal_subscribe (connection,
	                                                            "org.freedesktop.DBus",
	                                                            "org.freedesktop.DBus",
	                                                            "NameOwnerChanged",
	                                                            "/org/freedesktop/DBus",
	                                                            priv->dbus_client,
	                                                            G_DBUS_SIGNAL_FLAGS_NONE,
	                                                            name_owner_changed_cb,
	                                                            self,
	                                                            NULL);
}

/*****************************************************************************/

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMKeepAlive *self = NM_KEEP_ALIVE (object);

	switch (prop_id) {
	case PROP_ALIVE:
		g_value_set_boolean (value, nm_keep_alive_is_alive (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_keep_alive_init (NMKeepAlive *self)
{
	nm_assert (NM_KEEP_ALIVE_GET_PRIVATE (self)->alive == _is_alive (self));
}

NMKeepAlive *
nm_keep_alive_new (gboolean floating)
{
	NMKeepAlive *self = g_object_new (NM_TYPE_KEEP_ALIVE, NULL);
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	priv->floating = floating;
	priv->alive = TRUE;
	nm_assert (priv->alive == _is_alive (self));
	return self;
}

static void
dispose (GObject *object)
{
	NMKeepAlive *self = NM_KEEP_ALIVE (object);

	_set_settings_connection_watch_visible (self, NULL, FALSE);
	cleanup_dbus_watch (self);
}

static void
nm_keep_alive_class_init (NMKeepAliveClass *keep_alive_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (keep_alive_class);

	object_class->get_property = get_property;
	object_class->dispose = dispose;

	obj_properties[PROP_ALIVE] =
	    g_param_spec_string (NM_KEEP_ALIVE_ALIVE, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
