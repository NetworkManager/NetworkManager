/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2013 - 2016 Canonical Ltd.
 */

#include "nm-default.h"

#include "nm-modem-ofono.h"

#include "nm-core-internal.h"
#include "devices/nm-device-private.h"
#include "nm-modem.h"
#include "platform/nm-platform.h"
#include "nm-ip4-config.h"

#define VARIANT_IS_OF_TYPE_BOOLEAN(v)      ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_BOOLEAN) ))
#define VARIANT_IS_OF_TYPE_STRING(v)       ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_STRING) ))
#define VARIANT_IS_OF_TYPE_OBJECT_PATH(v)  ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_OBJECT_PATH) ))
#define VARIANT_IS_OF_TYPE_STRING_ARRAY(v) ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_STRING_ARRAY) ))
#define VARIANT_IS_OF_TYPE_DICTIONARY(v)   ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_DICTIONARY) ))

/*****************************************************************************/

typedef struct {
	GHashTable *connect_properties;

	GDBusProxy *modem_proxy;
	GDBusProxy *connman_proxy;
	GDBusProxy *context_proxy;
	GDBusProxy *sim_proxy;

	GCancellable *modem_proxy_cancellable;
	GCancellable *connman_proxy_cancellable;
	GCancellable *context_proxy_cancellable;
	GCancellable *sim_proxy_cancellable;

	GError *property_error;

	char *context_path;
	char *imsi;

	gboolean modem_online;
	gboolean gprs_attached;

	NMIP4Config *ip4_config;
} NMModemOfonoPrivate;

struct _NMModemOfono {
	NMModem parent;
	NMModemOfonoPrivate _priv;
};

struct _NMModemOfonoClass {
	NMModemClass parent;
};

G_DEFINE_TYPE (NMModemOfono, nm_modem_ofono, NM_TYPE_MODEM)

#define NM_MODEM_OFONO_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMModemOfono, NM_IS_MODEM_OFONO)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_MB
#define _NMLOG_PREFIX_NAME "modem-ofono"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        const NMLogLevel _level = (level); \
        \
        if (nm_logging_enabled (_level, (_NMLOG_DOMAIN))) { \
            NMModemOfono *const __self = (self); \
            char __prefix_name[128]; \
            const char *__uid; \
            \
            _nm_log (_level, (_NMLOG_DOMAIN), 0, NULL, NULL, \
                     "%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                     _NMLOG_PREFIX_NAME, \
                     (__self \
                         ? ({ \
                                ((__uid = nm_modem_get_uid ((NMModem *) __self)) \
                                    ? nm_sprintf_buf (__prefix_name, "[%s]", __uid) \
                                    : "(null)"); \
                            }) \
                         : "") \
                     _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

static void
get_capabilities (NMModem *_self,
                  NMDeviceModemCapabilities *modem_caps,
                  NMDeviceModemCapabilities *current_caps)
{
	/* FIXME: auto-detect capabilities to allow LTE */
	*modem_caps = NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS;
	*current_caps = NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS;
}

static void
update_modem_state (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMModemState state = nm_modem_get_state (NM_MODEM (self));
	NMModemState new_state = NM_MODEM_STATE_DISABLED;
	const char *reason = NULL;

	_LOGI ("'Attached': %s 'Online': %s 'IMSI': %s",
	       priv->gprs_attached ? "true" : "false",
	       priv->modem_online ? "true" : "false",
	       priv->imsi);

	if (priv->modem_online == FALSE) {
		reason = "modem 'Online=false'";
	} else if (priv->imsi == NULL && state != NM_MODEM_STATE_ENABLING) {
		reason = "modem not ready";
	} else if (priv->gprs_attached == FALSE) {
		new_state = NM_MODEM_STATE_SEARCHING;
		reason = "modem searching";
	} else {
		new_state = NM_MODEM_STATE_REGISTERED;
		reason = "modem ready";
	}

	if (state != new_state)
		nm_modem_set_state (NM_MODEM (self), new_state, reason);
}

/* Disconnect */
typedef struct {
	NMModemOfono *self;
	_NMModemDisconnectCallback callback;
	gpointer callback_user_data;
	GCancellable *cancellable;
	gboolean warn;
} DisconnectContext;

static void
disconnect_context_complete (DisconnectContext *ctx, GError *error)
{
	if (ctx->callback)
		ctx->callback (NM_MODEM (ctx->self), error, ctx->callback_user_data);
	nm_g_object_unref (ctx->cancellable);
	g_object_unref (ctx->self);
	g_slice_free (DisconnectContext, ctx);
}

static void
disconnect_context_complete_on_idle (gpointer user_data,
                                     GCancellable *cancellable)
{
	DisconnectContext *ctx = user_data;
	gs_free_error GError *error = NULL;

	if (!g_cancellable_set_error_if_cancelled (cancellable, &error)) {
		g_set_error_literal (&error,
		                     NM_UTILS_ERROR,
		                     NM_UTILS_ERROR_UNKNOWN,
		                     ("modem is currently not connected"));
	}
	disconnect_context_complete (ctx, error);
}

static void
disconnect_done (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	DisconnectContext *ctx = user_data;
	NMModemOfono *self = ctx->self;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *v = NULL;

	v = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		disconnect_context_complete (ctx, error);
		return;
	}

	if (error && ctx->warn)
		_LOGW ("failed to disconnect modem: %s", error->message);

	_LOGD ("modem disconnected");

	update_modem_state (self);
	disconnect_context_complete (ctx, error);
}

static void
disconnect (NMModem *modem,
            gboolean warn,
            GCancellable *cancellable,
            _NMModemDisconnectCallback callback,
            gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (modem);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	DisconnectContext *ctx;
	NMModemState state = nm_modem_get_state (NM_MODEM (self));

	_LOGD ("warn: %s modem_state: %s",
	       warn ? "TRUE" : "FALSE",
	       nm_modem_state_to_string (state));

	ctx = g_slice_new0 (DisconnectContext);
	ctx->self = g_object_ref (self);
	ctx->cancellable = nm_g_object_ref (cancellable);
	ctx->warn = warn;
	ctx->callback = callback;
	ctx->callback_user_data = user_data;

	if (   state != NM_MODEM_STATE_CONNECTED
	    || g_cancellable_is_cancelled (cancellable)) {
		nm_utils_invoke_on_idle (disconnect_context_complete_on_idle,
		                         ctx,
		                         cancellable);
		return;
	}

	nm_modem_set_state (NM_MODEM (self),
	                    NM_MODEM_STATE_DISCONNECTING,
	                    nm_modem_state_to_string (NM_MODEM_STATE_DISCONNECTING));

	g_dbus_proxy_call (priv->context_proxy,
	                   "SetProperty",
	                   g_variant_new ("(sv)",
	                                  "Active",
	                                  g_variant_new ("b", warn)),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   20000,
	                   ctx->cancellable,
	                   disconnect_done,
	                   ctx);
}

static void
deactivate_cleanup (NMModem *modem,
                    NMDevice *device,
                    gboolean stop_ppp_manager)
{
	NMModemOfono *self = NM_MODEM_OFONO (modem);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	/* TODO: cancel SimpleConnect() if any */

	g_clear_object (&priv->ip4_config);

	NM_MODEM_CLASS (nm_modem_ofono_parent_class)->deactivate_cleanup (modem,
	                                                                  device,
	                                                                  stop_ppp_manager);
}

static gboolean
check_connection_compatible_with_modem (NMModem *modem,
                                        NMConnection *connection,
                                        GError **error)
{
	NMModemOfono *self = NM_MODEM_OFONO (modem);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	const char *id;

	if (!_nm_connection_check_main_setting (connection, NM_SETTING_GSM_SETTING_NAME, NULL)) {
		nm_utils_error_set (error,
		                    NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
		                    "connection type %s is not supported by ofono modem",
		                    nm_connection_get_connection_type (connection));
		return FALSE;
	}

	if (!priv->imsi) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "modem has no IMSI");
		return FALSE;
	}

	id = nm_connection_get_id (connection);

	if (!strstr (id, "/context")) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "the connection ID has no context");
		return FALSE;
	}

	if (!strstr (id, priv->imsi)) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "the connection ID does not contain the IMSI");
		return FALSE;
	}

	return TRUE;
}

static void
handle_sim_property (GDBusProxy *proxy,
                     const char *property,
                     GVariant *v,
                     gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	if (g_strcmp0 (property, "SubscriberIdentity") == 0 && VARIANT_IS_OF_TYPE_STRING (v)) {
		gsize length;
		const char *value_str = g_variant_get_string (v, &length);

		_LOGD ("SubscriberIdentify found");

		/* Check for empty DBus string value */
		if (length &&
			g_strcmp0 (value_str, "(null)") != 0 &&
			g_strcmp0 (value_str, priv->imsi) != 0) {

			if (priv->imsi != NULL) {
				_LOGW ("SimManager:'SubscriberIdentity' changed: %s", priv->imsi);
				g_free(priv->imsi);
			}

			priv->imsi = g_strdup (value_str);
			update_modem_state (self);
		}
	}
}

static void
sim_property_changed (GDBusProxy *proxy,
                      const char *property,
                      GVariant *v,
                      gpointer user_data)
{
	GVariant *v_child = g_variant_get_child_value (v, 0);

	handle_sim_property (proxy, property, v_child, user_data);
	g_variant_unref (v_child);
}

static void
sim_get_properties_done (GObject *source,
                         GAsyncResult *result,
                         gpointer user_data)
{
	NMModemOfono *self;
	NMModemOfonoPrivate *priv;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *v_properties = NULL;
	gs_unref_variant GVariant *v_dict = NULL;
	GVariant *v;
	GVariantIter i;
	const char *property;

	v_properties = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (source),
	                                           result,
	                                           G_VARIANT_TYPE ("(a{sv})"),
	                                           &error);
	if (   !v_properties
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_MODEM_OFONO (user_data);
	priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	g_clear_object (&priv->sim_proxy_cancellable);

	if (!v_properties) {
		g_dbus_error_strip_remote_error (error);
		_LOGW ("error getting sim properties: %s", error->message);
		return;
	}

	_LOGD ("sim v_properties is type: %s", g_variant_get_type_string (v_properties));

	v_dict = g_variant_get_child_value (v_properties, 0);
	if (!v_dict) {
		_LOGW ("error getting sim properties: no v_dict");
		return;
	}

	_LOGD ("sim v_dict is type: %s", g_variant_get_type_string (v_dict));

	/*
	 * TODO:
	 * 1) optimize by looking up properties ( Online, Interfaces ), instead
	 *    of iterating
	 *
	 * 2) reduce code duplication between all of the get_properties_done
	 *    functions in this class.
	 */

	g_variant_iter_init (&i, v_dict);
	while (g_variant_iter_next (&i, "{&sv}", &property, &v)) {
		handle_sim_property (NULL, property, v, self);
		g_variant_unref (v);
	}
}

static void
_sim_proxy_new_cb (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	NMModemOfono *self;
	NMModemOfonoPrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (   !proxy
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = user_data;
	priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	if (!proxy) {
		_LOGW ("failed to create SimManager proxy: %s", error->message);
		g_clear_object (&priv->sim_proxy_cancellable);
		return;
	}

	priv->sim_proxy = proxy;

	/* Watch for custom ofono PropertyChanged signals */
	_nm_dbus_signal_connect (priv->sim_proxy,
	                         "PropertyChanged",
	                         G_VARIANT_TYPE ("(sv)"),
	                         G_CALLBACK (sim_property_changed),
	                         self);

	g_dbus_proxy_call (priv->sim_proxy,
	                   "GetProperties",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE,
	                   20000,
	                   priv->sim_proxy_cancellable,
	                   sim_get_properties_done,
	                   self);
}

static void
handle_sim_iface (NMModemOfono *self, gboolean found)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	_LOGD ("SimManager interface %sfound", found ? "" : "not ");

	if (!found && (priv->sim_proxy || priv->sim_proxy_cancellable)) {
		_LOGI ("SimManager interface disappeared");
		nm_clear_g_cancellable (&priv->sim_proxy_cancellable);
		if (priv->sim_proxy) {
			g_signal_handlers_disconnect_by_data (priv->sim_proxy, self);
			g_clear_object (&priv->sim_proxy);
		}
		g_clear_pointer (&priv->imsi, g_free);
		update_modem_state (self);
	} else if (found && (!priv->sim_proxy && !priv->sim_proxy_cancellable)) {
		_LOGI ("found new SimManager interface");

		priv->sim_proxy_cancellable = g_cancellable_new ();

		g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
		                            G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
		                          | G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
		                          NULL, /* GDBusInterfaceInfo */
		                          OFONO_DBUS_SERVICE,
		                          nm_modem_get_path (NM_MODEM (self)),
		                          OFONO_DBUS_INTERFACE_SIM_MANAGER,
		                          priv->sim_proxy_cancellable, /* GCancellable */
		                          _sim_proxy_new_cb,
		                          self);
	}
}

static void
handle_connman_property (GDBusProxy *proxy,
                         const char *property,
                         GVariant *v,
                         gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	if (g_strcmp0 (property, "Attached") == 0 && VARIANT_IS_OF_TYPE_BOOLEAN (v)) {
		gboolean attached = g_variant_get_boolean (v);
		gboolean old_attached = priv->gprs_attached;

		_LOGD ("Attached: %s", attached ? "True" : "False");

		if (priv->gprs_attached != attached) {
			priv->gprs_attached = attached;

			_LOGI ("Attached %s -> %s",
			       old_attached ? "true" : "false",
			       attached ? "true" : "false");

			update_modem_state (self);
		}
	}
}

static void
connman_property_changed (GDBusProxy *proxy,
                        const char *property,
                        GVariant *v,
                        gpointer user_data)
{
	GVariant *v_child = g_variant_get_child_value (v, 0);

	handle_connman_property (proxy, property, v_child, user_data);
	g_variant_unref (v_child);
}

static void
connman_get_properties_done (GObject *source,
                             GAsyncResult *result,
                             gpointer user_data)
{
	NMModemOfono *self;
	NMModemOfonoPrivate *priv;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *v_properties = NULL;
	gs_unref_variant GVariant *v_dict = NULL;
	GVariant *v;
	GVariantIter i;
	const char *property;

	v_properties = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (source),
	                                           result,
	                                           G_VARIANT_TYPE ("(a{sv})"),
	                                           &error);
	if (   !v_properties
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_MODEM_OFONO (user_data);
	priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	g_clear_object (&priv->connman_proxy_cancellable);

	if (!v_properties) {
		g_dbus_error_strip_remote_error (error);
		_LOGW ("error getting connman properties: %s", error->message);
		return;
	}

	v_dict = g_variant_get_child_value (v_properties, 0);

	/*
	 * TODO:
	 * 1) optimize by looking up properties ( Online, Interfaces ), instead
	 *    of iterating
	 *
	 * 2) reduce code duplication between all of the get_properties_done
	 *    functions in this class.
	 */

	g_variant_iter_init (&i, v_dict);
	while (g_variant_iter_next (&i, "{&sv}", &property, &v)) {
		handle_connman_property (NULL, property, v, self);
		g_variant_unref (v);
	}
}

static void
_connman_proxy_new_cb (GObject *source,
                       GAsyncResult *result,
                       gpointer user_data)
{
	NMModemOfono *self;
	NMModemOfonoPrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (   !proxy
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = user_data;
	priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	if (!proxy) {
		_LOGW ("failed to create ConnectionManager proxy: %s", error->message);
		g_clear_object (&priv->connman_proxy_cancellable);
		return;
	}

	priv->connman_proxy = proxy;

	_nm_dbus_signal_connect (priv->connman_proxy,
	                         "PropertyChanged",
	                         G_VARIANT_TYPE ("(sv)"),
	                         G_CALLBACK (connman_property_changed),
	                         self);

	g_dbus_proxy_call (priv->connman_proxy,
	                   "GetProperties",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE,
	                   20000,
	                   priv->connman_proxy_cancellable,
	                   connman_get_properties_done,
	                   self);
}

static void
handle_connman_iface (NMModemOfono *self, gboolean found)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	_LOGD ("ConnectionManager interface %sfound", found ? "" : "not ");

	if (!found && (priv->connman_proxy || priv->connman_proxy_cancellable)) {
		_LOGI ("ConnectionManager interface disappeared");
		nm_clear_g_cancellable (&priv->connman_proxy_cancellable);
		if (priv->connman_proxy) {
			g_signal_handlers_disconnect_by_data (priv->connman_proxy, self);
			g_clear_object (&priv->connman_proxy);
		}

		/* The connection manager proxy disappeared, we should
		 * consider the modem disabled.
		 */
		priv->gprs_attached = FALSE;

		update_modem_state (self);
	} else if (found && (!priv->connman_proxy && !priv->connman_proxy_cancellable)) {
		_LOGI ("found new ConnectionManager interface");

		priv->connman_proxy_cancellable = g_cancellable_new ();

		g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
		                            G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
		                          | G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
		                          NULL, /* GDBusInterfaceInfo */
		                          OFONO_DBUS_SERVICE,
		                          nm_modem_get_path (NM_MODEM (self)),
		                          OFONO_DBUS_INTERFACE_CONNECTION_MANAGER,
		                          priv->connman_proxy_cancellable,
		                          _connman_proxy_new_cb,
		                          self);
	}
}

static void
handle_modem_property (GDBusProxy *proxy,
                       const char *property,
                       GVariant *v,
                       gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	if ((g_strcmp0 (property, "Online") == 0) && VARIANT_IS_OF_TYPE_BOOLEAN (v)) {
		gboolean online = g_variant_get_boolean (v);

		_LOGD ("Online: %s", online ? "True" : "False");

		if (online != priv->modem_online) {
			priv->modem_online = online;
			_LOGI ("modem is now %s", online ? "Online" : "Offline");
			update_modem_state (self);
		}

	} else if ((g_strcmp0 (property, "Interfaces") == 0) && VARIANT_IS_OF_TYPE_STRING_ARRAY (v)) {
		const char **array, **iter;
		gboolean found_connman = FALSE;
		gboolean found_sim = FALSE;

		_LOGD ("Interfaces found");

		array = g_variant_get_strv (v, NULL);
		if (array) {
			for (iter = array; *iter; iter++) {
				if (g_strcmp0 (OFONO_DBUS_INTERFACE_SIM_MANAGER, *iter) == 0)
					found_sim = TRUE;
				else if (g_strcmp0 (OFONO_DBUS_INTERFACE_CONNECTION_MANAGER, *iter) == 0)
					found_connman = TRUE;
			}
			g_free (array);
		}

		handle_sim_iface (self, found_sim);
		handle_connman_iface (self, found_connman);
	}
}

static void
modem_property_changed (GDBusProxy *proxy,
                        const char *property,
                        GVariant *v,
                        gpointer user_data)
{
	GVariant *v_child = g_variant_get_child_value (v, 0);

	handle_modem_property (proxy, property, v_child, user_data);
	g_variant_unref (v_child);
}

static void
modem_get_properties_done (GObject *source,
                           GAsyncResult *result,
                           gpointer user_data)
{
	NMModemOfono *self;
	NMModemOfonoPrivate *priv;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *v_properties = NULL;
	gs_unref_variant GVariant *v_dict = NULL;
	GVariant *v;
	GVariantIter i;
	const char *property;

	v_properties = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (source),
	                                           result,
	                                           G_VARIANT_TYPE ("(a{sv})"),
	                                           &error);
	if (   !v_properties
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_MODEM_OFONO (user_data);
	priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	g_clear_object (&priv->modem_proxy_cancellable);

	if (!v_properties) {
		g_dbus_error_strip_remote_error (error);
		_LOGW ("error getting modem properties: %s", error->message);
		return;
	}

	v_dict = g_variant_get_child_value (v_properties, 0);
	if (!v_dict) {
		_LOGW ("error getting modem properties: no v_dict");
		return;
	}

	/*
	 * TODO:
	 * 1) optimize by looking up properties ( Online, Interfaces ), instead
	 *    of iterating
	 *
	 * 2) reduce code duplication between all of the get_properties_done
	 *    functions in this class.
	 */

	g_variant_iter_init (&i, v_dict);
	while (g_variant_iter_next (&i, "{&sv}", &property, &v)) {
		handle_modem_property (NULL, property, v, self);
		g_variant_unref (v);
	}
}

static void
stage1_prepare_done (GObject *source,
                     GAsyncResult *result,
                     gpointer user_data)
{
	NMModemOfono *self;
	NMModemOfonoPrivate *priv;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *v = NULL;

	v = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_MODEM_OFONO (user_data);
	priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	g_clear_object (&priv->context_proxy_cancellable);

	g_clear_pointer (&priv->connect_properties, g_hash_table_destroy);

	if (error) {
		_LOGW ("connection failed: %s", error->message);

		nm_modem_emit_prepare_result (NM_MODEM (self), FALSE,
		                              NM_DEVICE_STATE_REASON_MODEM_BUSY);
		/*
		 * FIXME: add code to check for InProgress so that the
		 * connection doesn't continue to try and activate,
		 * leading to the connection being disabled, and a 5m
		 * timeout...
		 */
	}
}

static void
context_property_changed (GDBusProxy *proxy,
                          const char *property,
                          GVariant *v,
                          gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMPlatformIP4Address addr;
	gboolean ret = FALSE;
	gs_unref_variant GVariant *v_dict = NULL;
	const char *interface;
	const char *s;
	const char **array, **iter;
	guint32 address_network, gateway_network;
	guint32 ip4_route_table, ip4_route_metric;
	int ifindex;
	GError *error = NULL;

	_LOGD ("PropertyChanged: %s", property);

	/*
	 * TODO: might be a good idea and re-factor this to mimic bluez-device,
	 * ie. have this function just check the key, and call a sub-func to
	 * handle the action.
	 */

	if (g_strcmp0 (property, "Settings") != 0)
		return;

	v_dict = g_variant_get_child_value (v, 0);
	if (!v_dict) {
		_LOGW ("error getting IPv4 Settings: no v_dict");
		goto out;
	}

	_LOGI ("IPv4 static Settings:");

	if (!g_variant_lookup (v_dict, "Interface", "&s", &interface)) {
		_LOGW ("Settings 'Interface' missing");
		goto out;
	}

	_LOGD ("Interface: %s", interface);
	if (!nm_modem_set_data_port (NM_MODEM (self),
	                             NM_PLATFORM_GET,
	                             interface,
	                             NM_MODEM_IP_METHOD_STATIC,
	                             NM_MODEM_IP_METHOD_UNKNOWN,
	                             0,
	                             &error)) {
		_LOGW ("failed to connect to modem: %s", error->message);
		g_clear_error (&error);
		goto out;
	}

	ifindex = nm_modem_get_ip_ifindex (NM_MODEM (self));
	nm_assert (ifindex > 0);

	/* TODO: verify handling of ip4_config; check other places it's used... */
	g_clear_object (&priv->ip4_config);

	priv->ip4_config = nm_ip4_config_new (nm_platform_get_multi_idx (NM_PLATFORM_GET),
	                                      ifindex);

	if (!g_variant_lookup (v_dict, "Address", "&s", &s)) {
		_LOGW ("Settings 'Address' missing");
		goto out;
	}
	if (   !s
	    || !nm_utils_parse_inaddr_bin (AF_INET, s, NULL, &address_network)) {
		_LOGW ("can't convert 'Address' %s to addr", s ?: "");
		goto out;
	}
	memset (&addr, 0, sizeof (addr));
	addr.ifindex = ifindex;
	addr.address = address_network;
	addr.addr_source = NM_IP_CONFIG_SOURCE_WWAN;

	if (!g_variant_lookup (v_dict, "Netmask", "&s", &s)) {
		_LOGW ("Settings 'Netmask' missing");
		goto out;
	}
	if (   !s
	    || !nm_utils_parse_inaddr_bin (AF_INET, s, NULL, &address_network)) {
		_LOGW ("invalid 'Netmask': %s", s ?: "");
		goto out;
	}
	addr.plen = nm_utils_ip4_netmask_to_prefix (address_network);

	_LOGI ("Address: %s", nm_platform_ip4_address_to_string (&addr, NULL, 0));
	nm_ip4_config_add_address (priv->ip4_config, &addr);

	if (   !g_variant_lookup (v_dict, "Gateway", "&s", &s)
	    || !s) {
		_LOGW ("Settings 'Gateway' missing");
		goto out;
	}
	if (!nm_utils_parse_inaddr_bin (AF_INET, s, NULL, &gateway_network)) {
		_LOGW ("invalid 'Gateway': %s", s);
		goto out;
	}
	nm_modem_get_route_parameters (NM_MODEM (self),
	                               &ip4_route_table,
	                               &ip4_route_metric,
	                               NULL,
	                               NULL);
	{
		const NMPlatformIP4Route r = {
			.rt_source = NM_IP_CONFIG_SOURCE_WWAN,
			.gateway = gateway_network,
			.table_coerced = nm_platform_route_table_coerce (ip4_route_table),
			.metric = ip4_route_metric,
		};

		_LOGI ("Gateway: %s", s);
		nm_ip4_config_add_route (priv->ip4_config, &r, NULL);
	}

	if (!g_variant_lookup (v_dict, "DomainNameServers", "^a&s", &array)) {
		_LOGW ("Settings 'DomainNameServers' missing");
		goto out;
	}
	if (array) {
		for (iter = array; *iter; iter++) {
			if (   nm_utils_parse_inaddr_bin (AF_INET, *iter, NULL, &address_network)
			    && address_network) {
				_LOGI ("DNS: %s", *iter);
				nm_ip4_config_add_nameserver (priv->ip4_config, address_network);
			} else {
				_LOGW ("invalid NameServer: %s", *iter);
			}
		}

		if (iter == array) {
			_LOGW ("Settings: 'DomainNameServers': none specified");
			g_free (array);
			goto out;
		}
		g_free (array);
	}

	if (g_variant_lookup (v_dict, "MessageProxy", "&s", &s)) {
		_LOGI ("MessageProxy: %s", s);
		if (   s
		    && nm_utils_parse_inaddr_bin (AF_INET, s, NULL, &address_network)) {
			nm_modem_get_route_parameters (NM_MODEM (self),
			                               &ip4_route_table,
			                               &ip4_route_metric,
			                               NULL,
			                               NULL);

			{
				const NMPlatformIP4Route mms_route = {
					.network = address_network,
					.plen = 32,
					.gateway = gateway_network,
					.table_coerced = nm_platform_route_table_coerce (ip4_route_table),
					.metric = ip4_route_metric,
				};

				nm_ip4_config_add_route (priv->ip4_config, &mms_route, NULL);
			}
		} else {
			_LOGW ("invalid MessageProxy: %s", s);
		}
	}

	ret = TRUE;

out:
	if (nm_modem_get_state (NM_MODEM (self)) != NM_MODEM_STATE_CONNECTED) {
		_LOGI ("emitting PREPARE_RESULT: %s", ret ? "TRUE" : "FALSE");
		nm_modem_emit_prepare_result (NM_MODEM (self), ret,
		                              ret
		                                  ? NM_DEVICE_STATE_REASON_NONE
		                                  : NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	} else {
		_LOGW ("MODEM_PPP_FAILED");
		nm_modem_emit_ppp_failed (NM_MODEM (self), NM_DEVICE_STATE_REASON_PPP_FAILED);
	}
}

static NMActStageReturn
static_stage3_ip4_config_start (NMModem *modem,
                                NMActRequest *req,
                                NMDeviceStateReason *out_failure_reason)
{
	NMModemOfono *self = NM_MODEM_OFONO (modem);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GError *error = NULL;

	if (!priv->ip4_config) {
		_LOGD ("IP4 config not ready(?)");
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	_LOGD ("IP4 config is done; setting modem_state -> CONNECTED");
	g_signal_emit_by_name (self, NM_MODEM_IP4_CONFIG_RESULT, priv->ip4_config, error);

	/* Signal listener takes ownership of the IP4Config */
	priv->ip4_config = NULL;

	nm_modem_set_state (NM_MODEM (self),
	                    NM_MODEM_STATE_CONNECTED,
	                    nm_modem_state_to_string (NM_MODEM_STATE_CONNECTED));
	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static void
context_proxy_new_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMModemOfono *self;
	NMModemOfonoPrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (   !proxy
	    || g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_MODEM_OFONO (user_data);
	priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	if (!proxy) {
		_LOGE ("failed to create ofono ConnectionContext DBus proxy: %s", error->message);
		g_clear_object (&priv->context_proxy_cancellable);
		nm_modem_emit_prepare_result (NM_MODEM (self), FALSE,
		                              NM_DEVICE_STATE_REASON_MODEM_BUSY);
		return;
	}

	priv->context_proxy = proxy;

	if (!priv->gprs_attached) {
		g_clear_object (&priv->context_proxy_cancellable);
		nm_modem_emit_prepare_result (NM_MODEM (self), FALSE,
		                              NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER);
		return;
	}

	/* We have an old copy of the settings from a previous activation,
	 * clear it so that we can gate getting the IP config from oFono
	 * on whether or not we have already received them
	 */
	g_clear_object (&priv->ip4_config);

	_nm_dbus_signal_connect (priv->context_proxy,
	                         "PropertyChanged",
	                         G_VARIANT_TYPE ("(sv)"),
	                         G_CALLBACK (context_property_changed),
	                         self);

	g_dbus_proxy_call (priv->context_proxy,
	                   "SetProperty",
	                   g_variant_new ("(sv)",
	                                  "Active",
	                                   g_variant_new ("b", TRUE)),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   20000,
	                   priv->context_proxy_cancellable,
	                   stage1_prepare_done,
	                   self);
}

static void
do_context_activate (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	g_return_if_fail (NM_IS_MODEM_OFONO (self));

	nm_clear_g_cancellable (&priv->context_proxy_cancellable);
	g_clear_object (&priv->context_proxy);

	priv->context_proxy_cancellable = g_cancellable_new ();

	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                          NULL,
	                          OFONO_DBUS_SERVICE,
	                          priv->context_path,
	                          OFONO_DBUS_INTERFACE_CONNECTION_CONTEXT,
	                          priv->context_proxy_cancellable,
	                          context_proxy_new_cb,
	                          self);
}

static GHashTable *
create_connect_properties (NMConnection *connection)
{
	NMSettingGsm *setting;
	GHashTable *properties;
	const char *str;

	setting = nm_connection_get_setting_gsm (connection);
	properties = g_hash_table_new (nm_str_hash, g_str_equal);

	str = nm_setting_gsm_get_apn (setting);
	if (str)
		g_hash_table_insert (properties, "AccessPointName", g_strdup (str));

	str = nm_setting_gsm_get_username (setting);
	if (str)
		g_hash_table_insert (properties, "Username", g_strdup (str));

	str = nm_setting_gsm_get_password (setting);
	if (str)
		g_hash_table_insert (properties, "Password", g_strdup (str));

	return properties;
}

static NMActStageReturn
act_stage1_prepare (NMModem *modem,
                    NMConnection *connection,
                    NMDeviceStateReason *out_failure_reason)
{
	NMModemOfono *self = NM_MODEM_OFONO (modem);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	const char *context_id;
	char **id = NULL;

	context_id = nm_connection_get_id (connection);
	id = g_strsplit (context_id, "/", 0);
	g_return_val_if_fail (id[2], NM_ACT_STAGE_RETURN_FAILURE);

	_LOGD ("trying %s %s", id[1], id[2]);

	g_free (priv->context_path);
	priv->context_path = g_strdup_printf ("%s/%s",
	                                      nm_modem_get_path (modem),
	                                      id[2]);
	g_strfreev (id);

	if (!priv->context_path) {
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_GSM_APN_FAILED);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	if (priv->connect_properties)
		g_hash_table_destroy (priv->connect_properties);

	priv->connect_properties = create_connect_properties (connection);

	_LOGI ("activating context %s", priv->context_path);

	if (nm_modem_get_state (modem) == NM_MODEM_STATE_REGISTERED) {
		do_context_activate (self);
	} else {
		_LOGW ("could not activate context: modem is not registered.");
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static void
modem_proxy_new_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMModemOfono *self;
	NMModemOfonoPrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (   !proxy
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_MODEM_OFONO (user_data);
	priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	if (!proxy) {
		_LOGE ("failed to create ofono modem DBus proxy: %s", error->message);
		g_clear_object (&priv->modem_proxy_cancellable);
		return;
	}

	priv->modem_proxy = proxy;

	_nm_dbus_signal_connect (priv->modem_proxy,
	                         "PropertyChanged",
	                         G_VARIANT_TYPE ("(sv)"),
	                         G_CALLBACK (modem_property_changed),
	                         self);

	g_dbus_proxy_call (priv->modem_proxy,
	                   "GetProperties",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE,
	                   20000,
	                   priv->modem_proxy_cancellable,
	                   modem_get_properties_done,
	                   self);
}

/*****************************************************************************/

static void
nm_modem_ofono_init (NMModemOfono *self)
{
}

static void
constructed (GObject *object)
{
	NMModemOfono *self = NM_MODEM_OFONO (object);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	priv->modem_proxy_cancellable = g_cancellable_new ();

	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                          NULL,
	                          OFONO_DBUS_SERVICE,
	                          nm_modem_get_path (NM_MODEM (self)),
	                          OFONO_DBUS_INTERFACE_MODEM,
	                          priv->modem_proxy_cancellable,
	                          modem_proxy_new_cb,
	                          self);

	G_OBJECT_CLASS (nm_modem_ofono_parent_class)->constructed (object);
}

NMModem *
nm_modem_ofono_new (const char *path)
{
	gs_free char *basename = NULL;

	g_return_val_if_fail (path != NULL, NULL);

	nm_log_info (LOGD_MB, "ofono: creating new Ofono modem path %s", path);

	/* Use short modem name (not its object path) as the NM device name (which
	 * comes from NM_MODEM_UID)and the device ID.
	 */
	basename = g_path_get_basename (path);

	return (NMModem *) g_object_new (NM_TYPE_MODEM_OFONO,
	                                 NM_MODEM_PATH, path,
	                                 NM_MODEM_UID, basename,
	                                 NM_MODEM_DEVICE_ID, basename,
	                                 NM_MODEM_CONTROL_PORT, "ofono", /* mandatory */
	                                 NM_MODEM_DRIVER, "ofono",
	                                 NM_MODEM_STATE, (int) NM_MODEM_STATE_INITIALIZING,
	                                 NULL);
}

static void
dispose (GObject *object)
{
	NMModemOfono *self = NM_MODEM_OFONO (object);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_clear_g_cancellable (&priv->modem_proxy_cancellable);
	nm_clear_g_cancellable (&priv->connman_proxy_cancellable);
	nm_clear_g_cancellable (&priv->context_proxy_cancellable);
	nm_clear_g_cancellable (&priv->sim_proxy_cancellable);

	if (priv->connect_properties) {
		g_hash_table_destroy (priv->connect_properties);
		priv->connect_properties = NULL;
	}

	g_clear_object (&priv->ip4_config);

	if (priv->modem_proxy) {
		g_signal_handlers_disconnect_by_data (priv->modem_proxy, self);
		g_clear_object (&priv->modem_proxy);
	}

	if (priv->connman_proxy) {
		g_signal_handlers_disconnect_by_data (priv->connman_proxy, self);
		g_clear_object (&priv->connman_proxy);
	}

	if (priv->context_proxy) {
		g_signal_handlers_disconnect_by_data (priv->context_proxy, self);
		g_clear_object (&priv->context_proxy);
	}

	if (priv->sim_proxy) {
		g_signal_handlers_disconnect_by_data (priv->sim_proxy, self);
		g_clear_object (&priv->sim_proxy);
	}

	g_free (priv->imsi);
	priv->imsi = NULL;

	G_OBJECT_CLASS (nm_modem_ofono_parent_class)->dispose (object);
}

static void
nm_modem_ofono_class_init (NMModemOfonoClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	object_class->constructed = constructed;
	object_class->dispose = dispose;

	modem_class->get_capabilities = get_capabilities;
	modem_class->disconnect = disconnect;
	modem_class->deactivate_cleanup = deactivate_cleanup;
	modem_class->check_connection_compatible_with_modem = check_connection_compatible_with_modem;

	modem_class->act_stage1_prepare = act_stage1_prepare;
	modem_class->static_stage3_ip4_config_start = static_stage3_ip4_config_start;
}
