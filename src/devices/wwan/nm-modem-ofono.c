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

#include "config.h"

#include <string.h>
#include <glib/gi18n.h>

#include "nm-default.h"
#include "nm-core-internal.h"

#include "nm-modem-ofono.h"
#include "nm-device.h"
#include "nm-device-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-settings-connection.h"
#include "nm-enum-types.h"
#include "nm-logging.h"
#include "nm-modem.h"
#include "nm-platform.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMModemOfono, nm_modem_ofono, NM_TYPE_MODEM)

#define NM_MODEM_OFONO_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM_OFONO, NMModemOfonoPrivate))

#define VARIANT_IS_OF_TYPE_BOOLEAN(v)      ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_BOOLEAN) ))
#define VARIANT_IS_OF_TYPE_STRING(v)       ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_STRING) ))
#define VARIANT_IS_OF_TYPE_OBJECT_PATH(v)  ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_OBJECT_PATH) ))
#define VARIANT_IS_OF_TYPE_STRING_ARRAY(v) ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_STRING_ARRAY) ))
#define VARIANT_IS_OF_TYPE_DICTIONARY(v)   ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_DICTIONARY) ))

typedef struct {
	GDBusConnection *dbus_connection;

	GHashTable *connect_properties;

	GDBusProxy *modem_proxy;
	GDBusProxy *connman_proxy;
	GDBusProxy *context_proxy;
	GDBusProxy *sim_proxy;

	GError *property_error;

	char *context_path;
	char *imsi;

	gboolean modem_online;
	gboolean gprs_attached;

	NMIP4Config *ip4_config;

} NMModemOfonoPrivate;

static gboolean
ip_string_to_network_address (const gchar *str,
                              guint32 *out)
{
	guint32 addr = 0;
	gboolean success = FALSE;

	if (!str || inet_pton (AF_INET, str, &addr) != 1)
		addr = 0;
	else
		success = TRUE;

	*out = (guint32)addr;
	return success;
}

static void
get_capabilities (NMModem *_self,
                  NMDeviceModemCapabilities *modem_caps,
                  NMDeviceModemCapabilities *current_caps)
{
	NMDeviceModemCapabilities all_ofono_caps = NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS;

	*modem_caps = all_ofono_caps;
	*current_caps = all_ofono_caps;
}

static void
update_modem_state (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMModemState state = nm_modem_get_state (NM_MODEM (self));
	NMModemState new_state = NM_MODEM_STATE_DISABLED;
	const char *reason = NULL;

	nm_log_info (LOGD_MB, "(%s): %s: 'Attached': %s 'Online': %s 'IMSI': %s",
	             nm_modem_get_path (NM_MODEM (self)),
	             __func__,
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
	GSimpleAsyncResult *result;
	GCancellable *cancellable;
	gboolean warn;
} DisconnectContext;

static void
disconnect_context_complete (DisconnectContext *ctx)
{
	g_simple_async_result_complete_in_idle (ctx->result);
	if (ctx->cancellable)
		g_object_unref (ctx->cancellable);
	g_object_unref (ctx->result);
	g_object_unref (ctx->self);
	g_slice_free (DisconnectContext, ctx);
}

static gboolean
disconnect_context_complete_if_cancelled (DisconnectContext *ctx)
{
	GError *error = NULL;

	if (g_cancellable_set_error_if_cancelled (ctx->cancellable, &error)) {
		g_simple_async_result_take_error (ctx->result, error);
		disconnect_context_complete (ctx);
		return TRUE;
	}

	return FALSE;
}

static gboolean
disconnect_finish (NMModem *self,
                   GAsyncResult *result,
                   GError **error)
{
	return !g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error);
}

static void
disconnect_done (GDBusProxy *proxy,
				 GAsyncResult *result,
				 gpointer user_data)
{
	DisconnectContext *ctx = (DisconnectContext*) user_data;
	NMModemOfono *self = ctx->self;
	GError *error = NULL;



	g_dbus_proxy_call_finish (proxy, result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		nm_log_dbg (LOGD_MB, "(%s): disconnect cancelled",
		            nm_modem_get_uid (NM_MODEM (self)));
		return;
	}

	if (error) {
		if (ctx->warn)
			nm_log_warn (LOGD_MB, "(%s) failed to disconnect modem: %s",
			              nm_modem_get_uid (NM_MODEM (self)),
			              error && error->message ? error->message : "(unknown)");

		g_clear_error (&error);
	}

	nm_log_dbg (LOGD_MB, "(%s): modem disconnected",
				nm_modem_get_uid (NM_MODEM (self)));

	update_modem_state (self);
	disconnect_context_complete (ctx);
}

static void
disconnect (NMModem *self,
            gboolean warn,
            GCancellable *cancellable,
            GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	DisconnectContext *ctx;
	NMModemState state = nm_modem_get_state (NM_MODEM (self));

	nm_log_dbg (LOGD_MB, "(%s): warn: %s modem_state: %s",
				nm_modem_get_uid (NM_MODEM (self)),
				warn ? "TRUE" : "FALSE",
				nm_modem_state_to_string (state));

	if (state != NM_MODEM_STATE_CONNECTED)
		return;

	ctx = g_slice_new (DisconnectContext);
	ctx->self = g_object_ref (self);
	ctx->warn = warn;

	if (callback) {
		ctx->result = g_simple_async_result_new (G_OBJECT (self),
		                                         callback,
		                                         user_data,
		                                         disconnect);
	}
	/* Setup cancellable */
	ctx->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	if (disconnect_context_complete_if_cancelled (ctx))
		return;

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
	                   NULL,
	                   (GAsyncReadyCallback) disconnect_done,
	                   ctx);
}

static void
deactivate_cleanup (NMModem *_self, NMDevice *device)
{
	NMModemOfono *self = NM_MODEM_OFONO (_self);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	/* TODO: cancel SimpleConnect() if any */

	g_clear_object (&priv->ip4_config);

	/* Chain up parent's */
	NM_MODEM_CLASS (nm_modem_ofono_parent_class)->deactivate_cleanup (_self, device);
}


static gboolean
check_connection_compatible (NMModem *modem,
                             NMConnection *connection)
{
	NMModemOfono *self = NM_MODEM_OFONO (modem);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMSettingGsm *s_gsm;
	const char *uuid;
	const char *id;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	uuid = nm_connection_get_uuid (connection);
	id = nm_connection_get_id (connection);

	s_gsm = nm_connection_get_setting_gsm (connection);
	if (!s_gsm)
		return FALSE;

	if (!priv->imsi) {
		nm_log_warn (LOGD_MB, "ofono (%s): check_connection %s failed: no IMSI",
		             nm_modem_get_uid (NM_MODEM (self)), id);
		return FALSE;
	}

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_GSM_SETTING_NAME)) {
		nm_log_dbg (LOGD_MB, "%s (%s) isn't of the right type, skipping.", id, uuid);
		return FALSE;
	}

	if (!g_strrstr (id, "/context")) {
		nm_log_dbg (LOGD_MB, "%s (%s) isn't of the right type, skipping.", id, uuid);
		return FALSE;
	}

	if (!g_strrstr (id, priv->imsi)) {
		nm_log_dbg (LOGD_MB, "%s (%s) isn't for the right SIM, skipping.", id, uuid);
		return FALSE;
	}

	nm_log_dbg (LOGD_MB, "(%s): %s is compatible with IMSI %s",
				nm_modem_get_uid (NM_MODEM (self)), id, priv->imsi);

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

		nm_log_dbg (LOGD_MB, "(%s): SubscriberIdentity found", nm_modem_get_uid (NM_MODEM (self)));

		/* Check for empty DBus string value */
		if (length &&
			g_strcmp0 (value_str, "(null)") != 0 &&
			g_strcmp0 (value_str, priv->imsi) != 0) {

			if (priv->imsi != NULL) {
				nm_log_warn (LOGD_MB, "SimManager:'SubscriberIdentity' changed: %s", priv->imsi);
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
sim_get_properties_done (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	GError *error = NULL;
	GVariant *v_properties, *v_dict, *v;
	GVariantIter i;
	const char *property;

	nm_log_dbg (LOGD_MB, "%s", __func__);

	v_properties = _nm_dbus_proxy_call_finish (proxy,
	                                           result,
	                                           G_VARIANT_TYPE ("(a{sv})"),
	                                           &error);
	if (!v_properties) {
		g_dbus_error_strip_remote_error (error);
		nm_log_warn (LOGD_MB, "(%s) error getting sim properties: %s",
		             nm_modem_get_uid (NM_MODEM (self)),
		             error->message);
		g_error_free (error);
		return;
	}

	nm_log_dbg (LOGD_MB, "sim v_properties is type: %s", g_variant_get_type_string (v_properties));

	v_dict = g_variant_get_child_value (v_properties, 0);
	if (!v_dict) {
		nm_log_warn (LOGD_MB, "(%s) error getting sim properties: no v_dict",
		             nm_modem_get_uid (NM_MODEM (self)));
		return;
	}

	nm_log_dbg (LOGD_MB, "sim v_dict is type: %s", g_variant_get_type_string (v_dict));

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

	g_variant_unref (v_dict);
	g_variant_unref (v_properties);
}

static void
handle_sim_iface (NMModemOfono *self, gboolean found)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_log_dbg (LOGD_MB, "%s: %s", __func__, found ? "TRUE" : "FALSE");

	if (!found && priv->sim_proxy) {
		nm_log_info (LOGD_MB, "(%s): SimManager interface disappeared",
		             nm_modem_get_path (NM_MODEM (self)));

		g_signal_handlers_disconnect_by_data (priv->sim_proxy, NM_MODEM_OFONO (self));
		g_clear_object (&priv->sim_proxy);

		g_free (priv->imsi);
		priv->imsi = NULL;

		update_modem_state (self);
	} else if (found && !priv->sim_proxy) {
		GError *error = NULL;
		GDBusProxyFlags flags;

		nm_log_info (LOGD_MB, "(%s): found new SimManager interface",
		             nm_modem_get_path (NM_MODEM (self)));

		flags |= G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES;
		flags |= G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START;

		priv->sim_proxy = g_dbus_proxy_new_sync (priv->dbus_connection,
		                                         flags,
		                                         NULL, /* GDBusInterfaceInfo */
		                                         OFONO_DBUS_SERVICE,
		                                         nm_modem_get_path (NM_MODEM (self)),
		                                         OFONO_DBUS_INTERFACE_SIM_MANAGER,
		                                         NULL, /* GCancellable */
		                                         &error);
		if (priv->sim_proxy == NULL) {
			nm_log_warn (LOGD_MB, "(%s) failed to create SimManager proxy: %s",
			             nm_modem_get_uid (NM_MODEM (self)),
			             error && error->message ? error->message : "(unknown)");

			g_error_free (error);
			return;
		}

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
		                   NULL,
		                   (GAsyncReadyCallback) sim_get_properties_done,
		                   g_object_ref (self));
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

		nm_log_dbg (LOGD_MB, "(%s): Attached: %s",
		            nm_modem_get_uid (NM_MODEM (self)), attached ? "True" : "False");

		if (priv->gprs_attached != attached) {
			priv->gprs_attached = attached;

			nm_log_info (LOGD_MB, "(%s): %s: new value for 'Attached': %s",
			             nm_modem_get_path (NM_MODEM (self)),
			             __func__,
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
connman_get_properties_done (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	GError *error = NULL;
	GVariant *v_properties, *v_dict, *v;
	GVariantIter i;
	const char *property;

	nm_log_dbg (LOGD_MB, "%s", __func__);

	v_properties = _nm_dbus_proxy_call_finish (proxy,
		                                       result,
		                                       G_VARIANT_TYPE ("(a{sv})"),
		                                       &error);
	if (!v_properties) {
		g_dbus_error_strip_remote_error (error);
		nm_log_warn (LOGD_MB, "(%s) error getting connman properties: %s",
		             nm_modem_get_uid (NM_MODEM (self)),
		             error->message);
		g_error_free (error);
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

	g_variant_unref (v_dict);
	g_variant_unref (v_properties);
}

static void
handle_connman_iface (NMModemOfono *self, gboolean found)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_log_dbg (LOGD_MB, "%s: %s", __func__, found ? "TRUE" : "FALSE");

	if (!found && priv->connman_proxy) {
		nm_log_info (LOGD_MB, "(%s): ConnectionManager interface disappeared",
		             nm_modem_get_path (NM_MODEM (self)));

		g_signal_handlers_disconnect_by_data (priv->connman_proxy, NM_MODEM_OFONO (self));
		g_clear_object (&priv->connman_proxy);

		/* The connection manager proxy disappeared, we should
		 * consider the modem disabled.
		 */
		priv->gprs_attached = FALSE;

		update_modem_state (self);
	} else if (found && !priv->connman_proxy) {
		GError *error = NULL;
		GDBusProxyFlags flags;

		nm_log_info (LOGD_MB, "(%s): found new ConnectionManager interface",
		             nm_modem_get_path (NM_MODEM (self)));

		flags |= G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES;
		flags |= G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START;

		priv->connman_proxy = g_dbus_proxy_new_sync (priv->dbus_connection,
		                                             flags,
		                                             NULL, /* GDBusInterfaceInfo */
		                                             OFONO_DBUS_SERVICE,
		                                             nm_modem_get_path (NM_MODEM (self)),
		                                             OFONO_DBUS_INTERFACE_CONNECTION_MANAGER,
		                                             NULL, /* GCancellable */
		                                             &error);
		if (priv->connman_proxy == NULL) {
			nm_log_warn (LOGD_MB, "(%s) failed to create ConnectionManager proxy: %s",
			             nm_modem_get_uid (NM_MODEM (self)),
			             error && error->message ? error->message : "(unknown)");

			g_error_free (error);
			return;
		}

		/* Watch for custom ofono PropertyChanged signals */
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
		                   NULL,
		                   (GAsyncReadyCallback) connman_get_properties_done,
		                   g_object_ref (self));

		/* NM 0.9.10x version registers for "ContextAdded/Removed", but
		 * did nothing but log a message.  Removed for 1.2
		 */
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

		nm_log_dbg (LOGD_MB, "(%s): Online: %s",
		            nm_modem_get_uid (NM_MODEM (self)), online ? "True" : "False");

		if (online != priv->modem_online) {
			priv->modem_online = online;

			nm_log_info (LOGD_MB, "(%s) modem is now %s",
			             nm_modem_get_path (NM_MODEM (self)),
			             online ? "Online" : "Offline");

			update_modem_state (self);
		}

	} else if ((g_strcmp0 (property, "Interfaces") == 0) && VARIANT_IS_OF_TYPE_STRING_ARRAY (v)) {
		const char **array, **iter;
		gboolean found_connman = FALSE;
		gboolean found_sim = FALSE;

		nm_log_dbg (LOGD_MB, "(%s): Interfaces", nm_modem_get_uid (NM_MODEM (self)));

		array = g_variant_get_strv (v, NULL);
		if (array) {

			iter = array;
			while (*iter) {

				if (g_strcmp0 (OFONO_DBUS_INTERFACE_SIM_MANAGER, *iter) == 0)
					found_sim = TRUE;
				else if (g_strcmp0 (OFONO_DBUS_INTERFACE_CONNECTION_MANAGER, *iter) == 0)
					found_connman = TRUE;

				*iter++;
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
modem_get_properties_done (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	GError *error = NULL;
	GVariant *v_properties, *v_dict, *v;
	GVariantIter i;
	const char *property;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	v_properties = _nm_dbus_proxy_call_finish (proxy,
	                                           result,
	                                           G_VARIANT_TYPE ("(a{sv})"),
	                                           &error);
	if (!v_properties) {
		g_dbus_error_strip_remote_error (error);
		nm_log_warn (LOGD_MB, "(%s) error getting modem properties: %s",
		             nm_modem_get_uid (NM_MODEM (self)),
		             error->message);
		g_error_free (error);
		return;
	}

	v_dict = g_variant_get_child_value (v_properties, 0);
	if (!v_dict) {
		nm_log_warn (LOGD_MB, "(%s) error getting modem properties: no v_dict",
		             nm_modem_get_uid (NM_MODEM (self)));
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

	g_variant_unref (v_dict);
	g_variant_unref (v_properties);
}

NMModem *
nm_modem_ofono_new (const char *path)
{
	g_return_val_if_fail (path != NULL, NULL);

	nm_log_dbg (LOGD_MB, "in %s: path %s", __func__, path);

	return (NMModem *) g_object_new (NM_TYPE_MODEM_OFONO,
	                                 NM_MODEM_PATH, path,
	                                 NM_MODEM_UID, (path + 1),
	                                 NM_MODEM_DEVICE_ID, (path + 1),
	                                 NM_MODEM_CONTROL_PORT, "ofono", /* mandatory */
	                                 NM_MODEM_DRIVER, "ofono",
	                                 NM_MODEM_STATE, NM_MODEM_STATE_INITIALIZING,
	                                 NULL);
}

static void
stage1_prepare_done (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GError *error = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (priv->connect_properties) {
		g_hash_table_destroy (priv->connect_properties);
		priv->connect_properties = NULL;
	}

	g_dbus_proxy_call_finish (proxy, result, &error);

	if (error) {
		nm_log_warn (LOGD_MB, "ofono: connection failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");

		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE,
		                       NM_DEVICE_STATE_REASON_MODEM_BUSY);
		/*
		 * FIXME: add code to check for InProgress so that the
		 * connection doesn't continue to try and activate,
		 * leading to the connection being disabled, and a 5m
		 * timeout...
		 */

		g_clear_error (&error);
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
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	NMPlatformIP4Address addr;
	gboolean ret = FALSE;
	GVariant *v_dict;
	GVariantIter i;
	const gchar *s, *addr_s;
	const gchar **array, **iter;
	guint32 address_network, gateway_network;
	guint prefix = 0;

	nm_log_dbg (LOGD_MB, "PropertyChanged: %s", property);

	/*
	 * TODO: might be a good idea and re-factor this to mimic bluez-device,
	 * ie. have this function just check the key, and call a sub-func to
	 * handle the action.
	 */

	if (g_strcmp0 (property, "Settings") != 0)
		return;

	v_dict = g_variant_get_child_value (v, 0);
	if (!v_dict) {
		nm_log_warn (LOGD_MB, "ofono: (%s): error getting IPv4 Settings",
		             nm_modem_get_uid (NM_MODEM (self)));
		goto out;
	}

	nm_log_info (LOGD_MB, "ofono: (%s): IPv4 static Settings:", nm_modem_get_uid (NM_MODEM (self)));

	if (g_variant_lookup (v_dict, "Interface", "&s", &s)) {

		nm_log_dbg (LOGD_MB, "(%s): Interface: %s", nm_modem_get_uid (NM_MODEM (self)), s);

		if (s && strlen (s)) {
			g_object_set (self,
			              NM_MODEM_DATA_PORT, g_strdup (s),
			              NM_MODEM_IP4_METHOD, NM_MODEM_IP_METHOD_STATIC,
			              NULL);
		} else {
			nm_log_warn (LOGD_MB, "ofono: (%s): Settings 'Interface'; empty",
			             nm_modem_get_uid (NM_MODEM (self)));
			goto out;
		}

	} else {
		nm_log_warn (LOGD_MB, "ofono: (%s): Settings 'Interface' missing",
		             nm_modem_get_uid (NM_MODEM (self)));
		goto out;
	}

	/* TODO: verify handling of ip4_config; check other places it's used... */
	if (priv->ip4_config)
		g_object_unref (priv->ip4_config);

	memset (&addr, 0, sizeof (addr));

	/*
	 * TODO:
	 *
	 * NM 1.2 changed the NMIP4Config constructor to take an ifindex
	 * ( vs. void pre 1.2 ), to tie config instance to a specific
	 * platform interface.
	 *
	 * This doesn't work for ofono, as the devices are created
	 * dynamically ( eg. ril_0, ril_1 ) in NMModemManager.  The
	 * device created doesn't really map directly to a platform
	 * link.  The closest would be one of the devices owned by
	 * rild ( eg. ccmin0 ), which is passed to us above as
	 * 'Interface'.
	 *
	 * This needs discussion with upstream.
	 */
	priv->ip4_config = nm_ip4_config_new (0);

	/* TODO: simply if/else error logic! */

	if (g_variant_lookup (v_dict, "Address", "&s", &addr_s)) {
		nm_log_dbg (LOGD_MB, "(%s): Address: %s", nm_modem_get_uid (NM_MODEM (self)), addr_s);

		if (ip_string_to_network_address (addr_s, &address_network)) {
			addr.address = address_network;
			addr.addr_source = NM_IP_CONFIG_SOURCE_WWAN;
		} else {
			nm_log_warn (LOGD_MB, "ofono: (%s): can't convert 'Address' %s to addr",
			             nm_modem_get_uid (NM_MODEM (self)), s);
			goto out;
		}

	} else {
		nm_log_warn (LOGD_MB, "ofono: (%s): Settings 'Address' missing",
		             nm_modem_get_uid (NM_MODEM (self)));
		goto out;
	}

	if (g_variant_lookup (v_dict, "Netmask", "&s", &s)) {

		nm_log_dbg (LOGD_MB, "(%s): Netmask: %s", nm_modem_get_uid (NM_MODEM (self)), s);

		if (s && ip_string_to_network_address (s, &address_network)) {
			prefix = nm_utils_ip4_netmask_to_prefix (address_network);
			if (prefix > 0)
				addr.plen = prefix;
		} else {
			nm_log_warn (LOGD_MB, "ofono: (%s): invalid 'Netmask': %s",
			             nm_modem_get_uid (NM_MODEM (self)), s);
			goto out;
		}

	} else {
		nm_log_warn (LOGD_MB, "ofono: (%s): Settings 'Netmask' missing",
		            nm_modem_get_uid (NM_MODEM (self)));
		goto out;
	}

	nm_log_info (LOGD_MB, "ofono (%s) Address: %s/%d",
				 nm_modem_get_uid (NM_MODEM (self)), addr_s, prefix);

	nm_ip4_config_add_address (priv->ip4_config, &addr);

	if (g_variant_lookup (v_dict, "Gateway", "&s", &s)) {

		if (s && ip_string_to_network_address (s, &gateway_network)) {
			nm_log_info (LOGD_MB, "ofono: (%s):  Gateway: %s", nm_modem_get_uid (NM_MODEM (self)), s);

			nm_ip4_config_set_gateway (priv->ip4_config, gateway_network);
		} else {
			nm_log_warn (LOGD_MB, "ofono: (%s): invalid 'Gateway': %s",
			             nm_modem_get_uid (NM_MODEM (self)), s);
			goto out;
		}

		nm_ip4_config_set_gateway (priv->ip4_config, gateway_network);
	} else {
		nm_log_warn (LOGD_MB, "ofono: (%s): Settings 'Gateway' missing",
		            nm_modem_get_uid (NM_MODEM (self)));
		goto out;
	}

	if (g_variant_lookup (v_dict, "DomainNameServers", "^a&s", &array)) {
		iter = array;

		while (*iter) {
			if (ip_string_to_network_address (*iter, &address_network) && address_network > 0) {
				nm_log_info (LOGD_MB, "ofono: (%s): DNS: %s",
				             nm_modem_get_uid (NM_MODEM (self)), *iter);

				nm_ip4_config_add_nameserver (priv->ip4_config, address_network);
			} else {
				nm_log_warn (LOGD_MB, "ofono: (%s): invalid NameServer: %s",
				             nm_modem_get_uid (NM_MODEM (self)), *iter);
			}

			*iter++;
		}

		if (iter == array) {
			nm_log_warn (LOGD_MB, "ofono: (%s): Settings: 'DomainNameServers': none specified",
			             nm_modem_get_uid (NM_MODEM (self)));
			g_free (array);
			goto out;
		}

		g_free (array);
	} else {
		nm_log_warn (LOGD_MB, "ofono: (%s): Settings 'DomainNameServers' missing",
		             nm_modem_get_uid (NM_MODEM (self)));
		goto out;
	}

	if (g_variant_lookup (v_dict, "MessageProxy", "&s", &s)) {
		nm_log_info (LOGD_MB, "ofono: (%s): MessageProxy: %s",
		             nm_modem_get_uid (NM_MODEM (self)), s);

		if (s && ip_string_to_network_address (s, &address_network)) {
			NMPlatformIP4Route mms_route;

			mms_route.network = address_network;
			mms_route.plen = 32;
			mms_route.gateway = gateway_network;

			mms_route.metric = 1;

			nm_ip4_config_add_route (priv->ip4_config, &mms_route);
		} else {
			nm_log_warn (LOGD_MB, "ofono: (%s): invalid MessageProxy: %s",
			             nm_modem_get_uid (NM_MODEM (self)), s);
		}
	}

	ret = TRUE;

out:
	if (nm_modem_get_state (NM_MODEM (self)) != NM_MODEM_STATE_CONNECTED) {
		nm_log_info (LOGD_MB, "ofono: (%s): emitting PREPARE_RESULT: %s",
		             nm_modem_get_uid (NM_MODEM (self)), ret ? "TRUE" : "FALSE");

		if (!ret)
			reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;

		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, ret, reason);
	} else {
		nm_log_warn (LOGD_MB, "ofono: (%s): MODEM_PPP_FAILED", nm_modem_get_uid (NM_MODEM (self)));

		g_signal_emit_by_name (self, NM_MODEM_PPP_FAILED, NM_DEVICE_STATE_REASON_PPP_FAILED);
	}
}

static NMActStageReturn
static_stage3_ip4_config_start (NMModem *_self,
								NMActRequest *req,
								NMDeviceStateReason *reason)
{
	NMModemOfono *self = NM_MODEM_OFONO (_self);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	GError *error = NULL;

	nm_log_dbg (LOGD_MB, "(%s): stage_3_ip4_config_start",
	            nm_modem_get_uid (NM_MODEM (self)));

	if (priv->ip4_config) {
		nm_log_dbg (LOGD_MB, "(%s): IP4 config is done; setting modem_state -> CONNECTED",
		            nm_modem_get_uid (NM_MODEM (self)));

		g_signal_emit_by_name (self, NM_MODEM_IP4_CONFIG_RESULT, priv->ip4_config, error);

		/* TODO: review!!! */
		priv->ip4_config = NULL;
		nm_modem_set_state (NM_MODEM (self),
							NM_MODEM_STATE_CONNECTED,
							nm_modem_state_to_string (NM_MODEM_STATE_CONNECTED));
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	}

	return ret;
}

static void
context_proxy_new_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GError *error = NULL;

	nm_log_dbg (LOGD_MB, "%s:", __func__);

	priv->context_proxy = g_dbus_proxy_new_finish (result, &error);

	/* TODO: add path to log msg? */
	if (error) {
		nm_log_err (LOGD_MB, "(%s) failed to create ofono ConnectionContext DBus proxy: %s",
		            nm_modem_get_uid (NM_MODEM (self)),
		            error->message ? error->message : "(unknown)");

		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE,
		                       NM_DEVICE_STATE_REASON_MODEM_BUSY);
		return;
	}

	if (!priv->gprs_attached) {
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE,
		                       NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER);
		return;
	}

	/* We have an old copy of the settings from a previous activation,
	 * clear it so that we can gate getting the IP config from oFono
	 * on whether or not we have already received them
	 */
	if (priv->ip4_config)
		g_clear_object (&priv->ip4_config);

	/* Watch for custom ofono PropertyChanged signals */
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
	                   NULL,
	                   (GAsyncReadyCallback) stage1_prepare_done,
	                   g_object_ref (self));
}

static void
do_context_activate (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GValue value = G_VALUE_INIT;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_MODEM_OFONO (self), FALSE);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, TRUE);

	if (priv->context_proxy)
		g_clear_object (&priv->context_proxy);

	g_dbus_proxy_new (priv->dbus_connection,
	                  G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                  NULL,
	                  OFONO_DBUS_SERVICE,
	                  priv->context_path,
	                  OFONO_DBUS_INTERFACE_CONNECTION_CONTEXT,
	                  NULL,
	                  (GAsyncReadyCallback) context_proxy_new_cb,
	                  g_object_ref (self));
}

static GHashTable *
create_connect_properties (NMConnection *connection)
{
	NMSettingGsm *setting;
	GHashTable *properties;
	const char *str;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	setting = nm_connection_get_setting_gsm (connection);
	properties = g_hash_table_new (g_str_hash, g_str_equal);

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
                    NMDeviceStateReason *reason)
{
	NMModemOfono *self = NM_MODEM_OFONO (modem);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	const char *context_id;
	char **id = NULL;

	nm_log_dbg (LOGD_MB, "%s", __func__);

	context_id = nm_connection_get_id (connection);
	id = g_strsplit (context_id, "/", 0);
	g_assert (id[2]);

	nm_log_dbg (LOGD_MB, " trying %s %s", id[1], id[2]);

	if (priv->context_path)
		g_free (priv->context_path);

	priv->context_path = g_strdup_printf ("%s/%s",
										  nm_modem_get_path (modem),
										  id[2]);
	g_strfreev (id);

	if (!priv->context_path) {
		*reason = NM_DEVICE_STATE_REASON_GSM_APN_FAILED;
			return NM_ACT_STAGE_RETURN_FAILURE;
	}

	if (priv->connect_properties)
		g_hash_table_destroy (priv->connect_properties);

	priv->connect_properties = create_connect_properties (connection);

	nm_log_info (LOGD_MB, "(%s): activating context %s",
	             nm_modem_get_path (modem),
	             priv->context_path);

	if (nm_modem_get_state (modem) == NM_MODEM_STATE_REGISTERED) {
		do_context_activate (self);
	} else {
		nm_log_warn (LOGD_MB, "(%s): could not activate context, "
		             "modem is not registered.",
		             nm_modem_get_path (modem));
		*reason = NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static void
modem_proxy_new_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GError *error = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	priv->modem_proxy = g_dbus_proxy_new_finish (result, &error);

	if (error) {
		nm_log_err (LOGD_MB, "(%s) failed to create ofono modem DBus proxy: %s",
		            nm_modem_get_uid (NM_MODEM (self)),
		            error->message ? error->message : "(unknown)");

		return;
	}

	/* Watch for custom ofono PropertyChanged signals */
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
				       NULL,
				       (GAsyncReadyCallback) modem_get_properties_done,
					   g_object_ref (self));

	g_object_unref (self);
}

static void
bus_connected (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	g_dbus_proxy_new (priv->dbus_connection,
	                  G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                  NULL,
	                  OFONO_DBUS_SERVICE,
	                  nm_modem_get_path (NM_MODEM (self)),
	                  OFONO_DBUS_INTERFACE_MODEM,
	                  NULL,
	                  (GAsyncReadyCallback) modem_proxy_new_cb,
	                  g_object_ref (self));
}

static void
bus_get_ready (GObject *source,
               GAsyncResult *result,
               NMModemOfono *self)
{
	/* Note we always get an extra reference to self here */
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GError *error = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	priv->dbus_connection = g_bus_get_finish (result, &error);
	if (!priv->dbus_connection) {
		nm_log_warn (LOGD_CORE, "error getting bus connection: %s", error->message);
		g_error_free (error);

		/* FIXME (awe): what do do if bus connection fails??? */
	} else {
		/* Got the bus, ensure client */
		bus_connected (self);
	}

	/* Balance refcount */
	g_object_unref (self);
}

static gboolean
ensure_bus (NMModemOfono *self)
{
	/* FIXME: not sure how dbus_connection could ever be set here? */
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (!priv->dbus_connection)
		g_bus_get (G_BUS_TYPE_SYSTEM,
		           NULL,
		           (GAsyncReadyCallback) bus_get_ready,
		           g_object_ref (self));
	else
		bus_connected (self);

	return FALSE;
}

static void
nm_modem_ofono_init (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	priv->dbus_connection = NULL;

	priv->modem_proxy = NULL;
	priv->connman_proxy = NULL;
	priv->context_proxy = NULL;
	priv->sim_proxy = NULL;

	priv->modem_online = FALSE;
	priv->gprs_attached = FALSE;

	priv->ip4_config = NULL;

	ensure_bus (self);
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMModemOfonoPrivate *priv;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	object = G_OBJECT_CLASS (nm_modem_ofono_parent_class)->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	priv = NM_MODEM_OFONO_GET_PRIVATE (object);

	return object;
}

static void
dispose (GObject *object)
{
	NMModemOfono *self = NM_MODEM_OFONO (object);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (priv->connect_properties) {
		g_hash_table_destroy (priv->connect_properties);
		priv->connect_properties = NULL;
	}

	if (priv->ip4_config)
		g_clear_object (&priv->ip4_config);

	if (priv->modem_proxy) {
		g_signal_handlers_disconnect_by_data (priv->modem_proxy, NM_MODEM_OFONO (self));
		g_clear_object (&priv->modem_proxy);
	}

	if (priv->connman_proxy)
		g_clear_object (&priv->connman_proxy);
	if (priv->context_proxy)
		g_clear_object (&priv->context_proxy);

	if (priv->sim_proxy) {
		g_signal_handlers_disconnect_by_data (priv->sim_proxy, NM_MODEM_OFONO (self));
		g_clear_object (&priv->sim_proxy);
	}

	g_clear_object (&priv->dbus_connection);

	if (priv->imsi) {
		g_free (priv->imsi);
		priv->imsi = NULL;
	}

	G_OBJECT_CLASS (nm_modem_ofono_parent_class)->dispose (object);
}

static void
nm_modem_ofono_class_init (NMModemOfonoClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	g_type_class_add_private (object_class, sizeof (NMModemOfonoPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;

	modem_class->get_capabilities = get_capabilities;
	modem_class->disconnect = disconnect;
	modem_class->disconnect_finish = disconnect_finish;
	modem_class->deactivate_cleanup = deactivate_cleanup;
	modem_class->check_connection_compatible = check_connection_compatible;

	/* same as nm-modem-broadband */
	modem_class->act_stage1_prepare = act_stage1_prepare;

	/* same as nm-modem-broadband */
	modem_class->static_stage3_ip4_config_start = static_stage3_ip4_config_start;
}
