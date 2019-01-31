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

#include "settings/nm-settings-connection.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMKeepAlive,
	PROP_ALIVE,
);

typedef struct {
	GObject *owner;

	NMSettingsConnection *connection;
	GDBusConnection *dbus_connection;
	char *dbus_client;

	GCancellable *dbus_client_confirm_cancellable;
	guint subscription_id;

	bool armed:1;
	bool disarmed:1;

	bool alive:1;
	bool dbus_client_confirmed:1;
	bool dbus_client_watching:1;
	bool connection_was_visible:1;
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

static gboolean _is_alive_dbus_client (NMKeepAlive *self);
static void cleanup_dbus_watch (NMKeepAlive *self);

/*****************************************************************************/

static gboolean
_is_alive (NMKeepAlive *self)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	nm_assert (!priv->disarmed);

	if (!priv->armed) {
		/* before arming, the instance is always alive. */
		return TRUE;
	}

	if (priv->dbus_client_watching) {
		if (_is_alive_dbus_client (self)) {
			/* no matter what, the keep-alive is alive, because there is a D-Bus client
			 * still around keeping it alive. */
			return TRUE;
		}
		/* the D-Bus client is gone. The only other binding (below) for the connection's
		 * visibility cannot keep the instance alive.
		 *
		 * As such, a D-Bus client watch is authoritative and overrules other conditions (that
		 * we have so far). */
		return FALSE;
	}

	if (   priv->connection
	    && priv->connection_was_visible
	    && !NM_FLAGS_HAS (nm_settings_connection_get_flags (priv->connection),
	                      NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE)) {
		/* note that we only declare the keep-alive as dead due to invisible
		 * connection, if
		 *    (1) we monitor a connection, obviously
		 *    (2) the connection was visible earlier and is no longer. It was
		 *        was invisible all the time, it does not suffice.
		 */
		return FALSE;
	}

	/* by default, the instance is alive. */
	return TRUE;
}

static void
_notify_alive (NMKeepAlive *self)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	if (priv->disarmed) {
		/* once disarmed, the alive state is frozen. */
		return;
	}

	if (priv->alive == _is_alive (self))
		return;
	priv->alive = !priv->alive;
	_LOGD ("instance is now %s", priv->alive ? "alive" : "dead");
	_notify (self, PROP_ALIVE);
}

gboolean
nm_keep_alive_is_alive (NMKeepAlive *self)
{
	return NM_KEEP_ALIVE_GET_PRIVATE (self)->alive;
}

/*****************************************************************************/

static void
connection_flags_changed (NMSettingsConnection *connection,
                          NMKeepAlive          *self)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	if (   !priv->connection_was_visible
	    && NM_FLAGS_HAS (nm_settings_connection_get_flags (priv->connection),
	                     NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE)) {
		/* the profile was never visible but now it becomes visible.
		 * Remember that.
		 *
		 * Before this happens (that is, if the device was invisible all along),
		 * the keep alive instance is considered alive (w.r.t. watching the connection).
		 *
		 * The reason is to allow a user to manually activate an invisible profile and keep
		 * it alive. At least, as long until the user logs out the first time (which is the
		 * first time, the profiles changes from visible to invisible).
		 *
		 * Yes, that is odd. How to improve? */
		priv->connection_was_visible = TRUE;
	}
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

	if (   connection
	    && !priv->disarmed) {
		priv->connection = g_object_ref (connection);
		priv->connection_was_visible = NM_FLAGS_HAS (nm_settings_connection_get_flags (priv->connection),
		                                             NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE);
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
get_name_owner_cb (GObject *source_object,
                   GAsyncResult *res,
                   gpointer user_data)
{
	NMKeepAlive *self = user_data;
	NMKeepAlivePrivate *priv;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *result = NULL;
	const char *name_owner;

	result = g_dbus_connection_call_finish ((GDBusConnection *) source_object,
	                                        res,
	                                        &error);
	if (   !result
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	if (result) {
		g_variant_get (result, "(&s)", &name_owner);

		priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

		if (nm_streq (name_owner, priv->dbus_client)) {
			/* all good, the name is confirmed. */
			return;
		}
	}

	_LOGD ("DBus client for keep alive is not on the bus");
	cleanup_dbus_watch (self);
	_notify_alive (self);
}

static gboolean
_is_alive_dbus_client (NMKeepAlive *self)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	if (!priv->dbus_client)
		return FALSE;

	if (!priv->dbus_client_confirmed) {
		/* it's unconfirmed that the D-Bus client is really alive.
		 * It looks like it is, but as we are claiming that to be
		 * the case, issue an async GetNameOwner call to make sure. */
		priv->dbus_client_confirmed = TRUE;
		priv->dbus_client_confirm_cancellable = g_cancellable_new ();

		g_dbus_connection_call (priv->dbus_connection,
		                        "org.freedesktop.DBus",
		                        "/org/freedesktop/DBus",
		                        "org.freedesktop.DBus",
		                        "GetNameOwner",
		                        g_variant_new ("(s)", priv->dbus_client),
		                        G_VARIANT_TYPE ("(s)"),
		                        G_DBUS_CALL_FLAGS_NONE,
		                        -1,
		                        priv->dbus_client_confirm_cancellable,
		                        get_name_owner_cb,
		                        self);
	}
	return TRUE;
}

static void
cleanup_dbus_watch (NMKeepAlive *self)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	if (!priv->dbus_client)
		return;

	_LOGD ("Cleanup DBus client watch");

	nm_clear_g_cancellable (&priv->dbus_client_confirm_cancellable);
	nm_clear_g_free (&priv->dbus_client);
	if (priv->dbus_connection) {
		g_dbus_connection_signal_unsubscribe (priv->dbus_connection,
		                                      priv->subscription_id);
		g_clear_object (&priv->dbus_connection);
	}
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

	if (priv->disarmed)
		return;

	cleanup_dbus_watch (self);

	if (client_address) {
		_LOGD ("Registering dbus client watch for keep alive");

		priv->dbus_client = g_strdup (client_address);
		priv->dbus_client_watching = TRUE;
		priv->dbus_client_confirmed = FALSE;
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
	} else
		priv->dbus_client_watching = FALSE;

	_notify_alive (self);
}

/*****************************************************************************/

/**
 * nm_keep_alive_arm:
 * @self: the #NMKeepAlive
 *
 * A #NMKeepAlive instance is unarmed by default. That means, it's
 * alive and stays alive until being armed. Arming means, that the conditions
 * start to be actively evaluated, that the alive state may change, and
 * that property changed signals are emitted.
 *
 * The opposite is nm_keep_alive_disarm() which freezes the alive state
 * for good. Once disarmed, the instance cannot be armed again. Arming an
 * instance multiple times has no effect. Arming an already disarmed instance
 * also has no effect. */
void
nm_keep_alive_arm (NMKeepAlive *self)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	if (!priv->armed) {
		priv->armed = TRUE;
		_notify_alive (self);
	}
}

/**
 * nm_keep_alive_disarm:
 * @self: the #NMKeepAlive instance
 *
 * Once the instance is disarmed, it will not change its alive state
 * anymore and will not emit anymore property changed signals about
 * alive state changed.
 *
 * As such, it will also free internal resources (since they no longer
 * affect the externally visible state).
 *
 * Once disarmed, the instance is frozen and cannot change anymore.
 */
void
nm_keep_alive_disarm (NMKeepAlive *self)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	priv->disarmed = TRUE;

	/* release internal data. */
	_set_settings_connection_watch_visible (self, NULL, FALSE);
	cleanup_dbus_watch (self);
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

/**
 * nm_keep_alive_get_owner:
 * @self: the #NMKeepAlive
 *
 * Returns: the owner instance associated with this @self. This commonly
 *   is set to be the target instance, which @self guards for being alive.
 *   Returns a gpointer, but of course it's some GObject instance. */
gpointer /* GObject * */
nm_keep_alive_get_owner (NMKeepAlive *self)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	nm_assert (!priv->owner || G_IS_OBJECT (priv->owner));

	return priv->owner;
}

/**
 * _nm_keep_alive_set_owner:
 * @self: the #NMKeepAlive
 * @owner: the owner to set or unset.
 *
 * Sets or unsets the owner instance. Think of the owner the target
 * instance that is guarded by @self. It's the responsibility of the
 * owner to set and properly unset this pointer. As the owner also
 * controls the lifetime of the NMKeepAlive instance.
 *
 * This API is not to be called by everybody, but only the owner of
 * @self.
 */
void
_nm_keep_alive_set_owner (NMKeepAlive *self,
                          GObject *owner)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	nm_assert (!owner || G_IS_OBJECT (owner));

	/* it's bad style to reset the owner object. You are supposed to
	 * set it once, and clear it once. That's it. */
	nm_assert (!owner || !priv->owner);

	/* optimally, we would take a reference to @owner. But the
	 * owner already owns a reference to the keep-alive, so we cannot
	 * just own a reference back.
	 *
	 * We could register a weak-pointer here. But instead, declare that
	 * owner is required to set itself as owner when creating the
	 * keep-alive instance, and unset itself when it lets go of the
	 * keep-alive instance (at latest, when the owner itself gets destroyed).
	 */
	priv->owner = owner;
}

/*****************************************************************************/

static void
nm_keep_alive_init (NMKeepAlive *self)
{
	NMKeepAlivePrivate *priv = NM_KEEP_ALIVE_GET_PRIVATE (self);

	priv->alive = TRUE;

	nm_assert (priv->alive == _is_alive (self));
}

NMKeepAlive *
nm_keep_alive_new (void)
{
	return g_object_new (NM_TYPE_KEEP_ALIVE, NULL);
}

static void
dispose (GObject *object)
{
	NMKeepAlive *self = NM_KEEP_ALIVE (object);

	nm_assert (!NM_KEEP_ALIVE_GET_PRIVATE (self)->owner);

	/* disarm also happens to free all resources. */
	nm_keep_alive_disarm (self);
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
