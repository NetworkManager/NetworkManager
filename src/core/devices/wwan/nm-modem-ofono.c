/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 - 2016 Canonical Ltd.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-modem-ofono.h"

#include "libnm-core-intern/nm-core-internal.h"
#include "devices/nm-device-private.h"
#include "nm-modem.h"
#include "libnm-platform/nm-platform.h"
#include "nm-l3-config-data.h"

#define VARIANT_IS_OF_TYPE_BOOLEAN(v) \
    ((v) != NULL && (g_variant_is_of_type((v), G_VARIANT_TYPE_BOOLEAN)))
#define VARIANT_IS_OF_TYPE_STRING(v) \
    ((v) != NULL && (g_variant_is_of_type((v), G_VARIANT_TYPE_STRING)))
#define VARIANT_IS_OF_TYPE_OBJECT_PATH(v) \
    ((v) != NULL && (g_variant_is_of_type((v), G_VARIANT_TYPE_OBJECT_PATH)))
#define VARIANT_IS_OF_TYPE_STRING_ARRAY(v) \
    ((v) != NULL && (g_variant_is_of_type((v), G_VARIANT_TYPE_STRING_ARRAY)))
#define VARIANT_IS_OF_TYPE_DICTIONARY(v) \
    ((v) != NULL && (g_variant_is_of_type((v), G_VARIANT_TYPE_DICTIONARY)))

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

    NML3ConfigData *l3cd_4;
} NMModemOfonoPrivate;

struct _NMModemOfono {
    NMModem             parent;
    NMModemOfonoPrivate _priv;
};

struct _NMModemOfonoClass {
    NMModemClass parent;
};

G_DEFINE_TYPE(NMModemOfono, nm_modem_ofono, NM_TYPE_MODEM)

#define NM_MODEM_OFONO_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMModemOfono, NM_IS_MODEM_OFONO)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_MB
#define _NMLOG_PREFIX_NAME "modem-ofono"
#define _NMLOG(level, ...)                                                  \
    G_STMT_START                                                            \
    {                                                                       \
        const NMLogLevel _level = (level);                                  \
                                                                            \
        if (nm_logging_enabled(_level, (_NMLOG_DOMAIN))) {                  \
            NMModemOfono *const __self = (self);                            \
            char                __prefix_name[128];                         \
            const char         *__uid;                                      \
                                                                            \
            _nm_log(_level,                                                 \
                    (_NMLOG_DOMAIN),                                        \
                    0,                                                      \
                    NULL,                                                   \
                    NULL,                                                   \
                    "%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),            \
                    _NMLOG_PREFIX_NAME,                                     \
                    (__self ? ({                                            \
                        ((__uid = nm_modem_get_uid((NMModem *) __self))     \
                             ? nm_sprintf_buf(__prefix_name, "[%s]", __uid) \
                             : "(null)");                                   \
                    })                                                      \
                            : "") _NM_UTILS_MACRO_REST(__VA_ARGS__));       \
        }                                                                   \
    }                                                                       \
    G_STMT_END

/*****************************************************************************/

static void
get_capabilities(NMModem                   *_self,
                 NMDeviceModemCapabilities *modem_caps,
                 NMDeviceModemCapabilities *current_caps)
{
    /* FIXME: auto-detect capabilities to allow LTE */
    *modem_caps   = NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS;
    *current_caps = NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS;
}

static void
update_modem_state(NMModemOfono *self)
{
    NMModemOfonoPrivate *priv      = NM_MODEM_OFONO_GET_PRIVATE(self);
    NMModemState         state     = nm_modem_get_state(NM_MODEM(self));
    NMModemState         new_state = NM_MODEM_STATE_DISABLED;
    const char          *reason    = NULL;

    _LOGI("'Attached': %s 'Online': %s 'IMSI': %s",
          priv->gprs_attached ? "true" : "false",
          priv->modem_online ? "true" : "false",
          priv->imsi);

    if (priv->modem_online == FALSE) {
        reason = "modem 'Online=false'";
    } else if (priv->imsi == NULL && state != NM_MODEM_STATE_ENABLING) {
        reason = "modem not ready";
    } else if (priv->gprs_attached == FALSE) {
        new_state = NM_MODEM_STATE_SEARCHING;
        reason    = "modem searching";
    } else {
        new_state = NM_MODEM_STATE_REGISTERED;
        reason    = "modem ready";
    }

    if (state != new_state)
        nm_modem_set_state(NM_MODEM(self), new_state, reason);
}

/* Disconnect */
typedef struct {
    NMModemOfono              *self;
    _NMModemDisconnectCallback callback;
    gpointer                   callback_user_data;
    GCancellable              *cancellable;
    gboolean                   warn;
} DisconnectContext;

static void
disconnect_context_complete(DisconnectContext *ctx, GError *error)
{
    if (ctx->callback)
        ctx->callback(NM_MODEM(ctx->self), error, ctx->callback_user_data);
    nm_g_object_unref(ctx->cancellable);
    g_object_unref(ctx->self);
    g_slice_free(DisconnectContext, ctx);
}

static void
disconnect_context_complete_on_idle(gpointer user_data, GCancellable *cancellable)
{
    DisconnectContext    *ctx   = user_data;
    gs_free_error GError *error = NULL;

    if (!g_cancellable_set_error_if_cancelled(cancellable, &error)) {
        g_set_error_literal(&error,
                            NM_UTILS_ERROR,
                            NM_UTILS_ERROR_UNKNOWN,
                            ("modem is currently not connected"));
    }
    disconnect_context_complete(ctx, error);
}

static void
disconnect_done(GObject *source, GAsyncResult *result, gpointer user_data)
{
    DisconnectContext         *ctx   = user_data;
    NMModemOfono              *self  = ctx->self;
    gs_free_error GError      *error = NULL;
    gs_unref_variant GVariant *v     = NULL;

    v = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), result, &error);
    if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
        disconnect_context_complete(ctx, error);
        return;
    }

    if (error && ctx->warn)
        _LOGW("failed to disconnect modem: %s", error->message);

    _LOGD("modem disconnected");

    update_modem_state(self);
    disconnect_context_complete(ctx, error);
}

static void
disconnect(NMModem                   *modem,
           gboolean                   warn,
           GCancellable              *cancellable,
           _NMModemDisconnectCallback callback,
           gpointer                   user_data)
{
    NMModemOfono        *self = NM_MODEM_OFONO(modem);
    NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE(self);
    DisconnectContext   *ctx;
    NMModemState         state = nm_modem_get_state(NM_MODEM(self));

    _LOGD("warn: %s modem_state: %s", warn ? "TRUE" : "FALSE", nm_modem_state_to_string(state));

    ctx                     = g_slice_new0(DisconnectContext);
    ctx->self               = g_object_ref(self);
    ctx->cancellable        = nm_g_object_ref(cancellable);
    ctx->warn               = warn;
    ctx->callback           = callback;
    ctx->callback_user_data = user_data;

    if (state != NM_MODEM_STATE_CONNECTED || g_cancellable_is_cancelled(cancellable)) {
        nm_utils_invoke_on_idle(cancellable, disconnect_context_complete_on_idle, ctx);
        return;
    }

    nm_modem_set_state(NM_MODEM(self),
                       NM_MODEM_STATE_DISCONNECTING,
                       nm_modem_state_to_string(NM_MODEM_STATE_DISCONNECTING));

    g_dbus_proxy_call(priv->context_proxy,
                      "SetProperty",
                      g_variant_new("(sv)", "Active", g_variant_new("b", warn)),
                      G_DBUS_CALL_FLAGS_NONE,
                      20000,
                      ctx->cancellable,
                      disconnect_done,
                      ctx);
}

static void
deactivate_cleanup(NMModem *modem, NMDevice *device, gboolean stop_ppp_manager)
{
    NMModemOfono        *self = NM_MODEM_OFONO(modem);
    NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    /* TODO: cancel SimpleConnect() if any */

    nm_clear_l3cd(&priv->l3cd_4);

    NM_MODEM_CLASS(nm_modem_ofono_parent_class)
        ->deactivate_cleanup(modem, device, stop_ppp_manager);
}

static gboolean
check_connection_compatible_with_modem(NMModem *modem, NMConnection *connection, GError **error)
{
    NMModemOfono        *self = NM_MODEM_OFONO(modem);
    NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE(self);
    const char          *id;

    if (!_nm_connection_check_main_setting(connection, NM_SETTING_GSM_SETTING_NAME, NULL)) {
        nm_utils_error_set(error,
                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                           "connection type %s is not supported by ofono modem",
                           nm_connection_get_connection_type(connection));
        return FALSE;
    }

    if (!priv->imsi) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "modem has no IMSI");
        return FALSE;
    }

    id = nm_connection_get_id(connection);

    if (!strstr(id, "/context")) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "the connection ID has no context");
        return FALSE;
    }

    if (!strstr(id, priv->imsi)) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "the connection ID does not contain the IMSI");
        return FALSE;
    }

    return TRUE;
}

static void
handle_sim_property(GDBusProxy *proxy, const char *property, GVariant *v, gpointer user_data)
{
    NMModemOfono        *self = NM_MODEM_OFONO(user_data);
    NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    if (g_strcmp0(property, "SubscriberIdentity") == 0 && VARIANT_IS_OF_TYPE_STRING(v)) {
        gsize       length;
        const char *value_str = g_variant_get_string(v, &length);

        _LOGD("SubscriberIdentify found");

        /* Check for empty DBus string value */
        if (length && g_strcmp0(value_str, "(null)") != 0
            && g_strcmp0(value_str, priv->imsi) != 0) {
            if (priv->imsi != NULL) {
                _LOGW("SimManager:'SubscriberIdentity' changed: %s", priv->imsi);
                g_free(priv->imsi);
            }

            priv->imsi = g_strdup(value_str);
            update_modem_state(self);
        }
    }
}

static void
sim_property_changed(GDBusProxy *proxy, const char *property, GVariant *v, gpointer user_data)
{
    gs_unref_variant GVariant *v_child = g_variant_get_child_value(v, 0);

    handle_sim_property(proxy, property, v_child, user_data);
}

static void
sim_get_properties_done(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMModemOfono              *self;
    NMModemOfonoPrivate       *priv;
    gs_free_error GError      *error        = NULL;
    gs_unref_variant GVariant *v_properties = NULL;
    gs_unref_variant GVariant *v_dict       = NULL;
    gs_unref_variant GVariant *v            = NULL;
    GVariantIter               i;
    const char                *property;

    v_properties =
        _nm_dbus_proxy_call_finish(G_DBUS_PROXY(source), result, G_VARIANT_TYPE("(a{sv})"), &error);
    if (!v_properties && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        return;

    self = NM_MODEM_OFONO(user_data);
    priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    g_clear_object(&priv->sim_proxy_cancellable);

    if (!v_properties) {
        g_dbus_error_strip_remote_error(error);
        _LOGW("error getting sim properties: %s", error->message);
        return;
    }

    _LOGD("sim v_properties is type: %s", g_variant_get_type_string(v_properties));

    v_dict = g_variant_get_child_value(v_properties, 0);
    if (!v_dict) {
        _LOGW("error getting sim properties: no v_dict");
        return;
    }

    _LOGD("sim v_dict is type: %s", g_variant_get_type_string(v_dict));

    /*
     * TODO:
     * 1) optimize by looking up properties ( Online, Interfaces ), instead
     *    of iterating
     *
     * 2) reduce code duplication between all of the get_properties_done
     *    functions in this class.
     */

    g_variant_iter_init(&i, v_dict);
    while (g_variant_iter_loop(&i, "{&sv}", &property, &v)) {
        handle_sim_property(NULL, property, v, self);
    }
}

static void
_sim_proxy_new_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMModemOfono         *self;
    NMModemOfonoPrivate  *priv;
    gs_free_error GError *error = NULL;
    GDBusProxy           *proxy;

    proxy = g_dbus_proxy_new_for_bus_finish(result, &error);
    if (!proxy && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        return;

    self = user_data;
    priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    if (!proxy) {
        _LOGW("failed to create SimManager proxy: %s", error->message);
        g_clear_object(&priv->sim_proxy_cancellable);
        return;
    }

    priv->sim_proxy = proxy;

    /* Watch for custom ofono PropertyChanged signals */
    _nm_dbus_signal_connect(priv->sim_proxy,
                            "PropertyChanged",
                            G_VARIANT_TYPE("(sv)"),
                            G_CALLBACK(sim_property_changed),
                            self);

    g_dbus_proxy_call(priv->sim_proxy,
                      "GetProperties",
                      NULL,
                      G_DBUS_CALL_FLAGS_NONE,
                      20000,
                      priv->sim_proxy_cancellable,
                      sim_get_properties_done,
                      self);
}

static void
handle_sim_iface(NMModemOfono *self, gboolean found)
{
    NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    _LOGD("SimManager interface %sfound", found ? "" : "not ");

    if (!found && (priv->sim_proxy || priv->sim_proxy_cancellable)) {
        _LOGI("SimManager interface disappeared");
        nm_clear_g_cancellable(&priv->sim_proxy_cancellable);
        if (priv->sim_proxy) {
            g_signal_handlers_disconnect_by_data(priv->sim_proxy, self);
            g_clear_object(&priv->sim_proxy);
        }
        nm_clear_g_free(&priv->imsi);
        update_modem_state(self);
    } else if (found && (!priv->sim_proxy && !priv->sim_proxy_cancellable)) {
        _LOGI("found new SimManager interface");

        priv->sim_proxy_cancellable = g_cancellable_new();

        g_dbus_proxy_new_for_bus(G_BUS_TYPE_SYSTEM,
                                 G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
                                     | G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
                                 NULL, /* GDBusInterfaceInfo */
                                 OFONO_DBUS_SERVICE,
                                 nm_modem_get_path(NM_MODEM(self)),
                                 OFONO_DBUS_INTERFACE_SIM_MANAGER,
                                 priv->sim_proxy_cancellable, /* GCancellable */
                                 _sim_proxy_new_cb,
                                 self);
    }
}

static void
handle_connman_property(GDBusProxy *proxy, const char *property, GVariant *v, gpointer user_data)
{
    NMModemOfono        *self = NM_MODEM_OFONO(user_data);
    NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    if (g_strcmp0(property, "Attached") == 0 && VARIANT_IS_OF_TYPE_BOOLEAN(v)) {
        gboolean attached     = g_variant_get_boolean(v);
        gboolean old_attached = priv->gprs_attached;

        _LOGD("Attached: %s", attached ? "True" : "False");

        if (priv->gprs_attached != attached) {
            priv->gprs_attached = attached;

            _LOGI("Attached %s -> %s",
                  old_attached ? "true" : "false",
                  attached ? "true" : "false");

            update_modem_state(self);
        }
    }
}

static void
connman_property_changed(GDBusProxy *proxy, const char *property, GVariant *v, gpointer user_data)
{
    gs_unref_variant GVariant *v_child = g_variant_get_child_value(v, 0);

    handle_connman_property(proxy, property, v_child, user_data);
}

static void
connman_get_properties_done(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMModemOfono              *self;
    NMModemOfonoPrivate       *priv;
    gs_free_error GError      *error        = NULL;
    gs_unref_variant GVariant *v_properties = NULL;
    gs_unref_variant GVariant *v_dict       = NULL;
    gs_unref_variant GVariant *v            = NULL;
    GVariantIter               i;
    const char                *property;

    v_properties =
        _nm_dbus_proxy_call_finish(G_DBUS_PROXY(source), result, G_VARIANT_TYPE("(a{sv})"), &error);
    if (!v_properties && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        return;

    self = NM_MODEM_OFONO(user_data);
    priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    g_clear_object(&priv->connman_proxy_cancellable);

    if (!v_properties) {
        g_dbus_error_strip_remote_error(error);
        _LOGW("error getting connman properties: %s", error->message);
        return;
    }

    v_dict = g_variant_get_child_value(v_properties, 0);

    /*
     * TODO:
     * 1) optimize by looking up properties ( Online, Interfaces ), instead
     *    of iterating
     *
     * 2) reduce code duplication between all of the get_properties_done
     *    functions in this class.
     */

    g_variant_iter_init(&i, v_dict);
    while (g_variant_iter_loop(&i, "{&sv}", &property, &v)) {
        handle_connman_property(NULL, property, v, self);
    }
}

static void
_connman_proxy_new_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMModemOfono         *self;
    NMModemOfonoPrivate  *priv;
    gs_free_error GError *error = NULL;
    GDBusProxy           *proxy;

    proxy = g_dbus_proxy_new_for_bus_finish(result, &error);
    if (!proxy && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        return;

    self = user_data;
    priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    if (!proxy) {
        _LOGW("failed to create ConnectionManager proxy: %s", error->message);
        g_clear_object(&priv->connman_proxy_cancellable);
        return;
    }

    priv->connman_proxy = proxy;

    _nm_dbus_signal_connect(priv->connman_proxy,
                            "PropertyChanged",
                            G_VARIANT_TYPE("(sv)"),
                            G_CALLBACK(connman_property_changed),
                            self);

    g_dbus_proxy_call(priv->connman_proxy,
                      "GetProperties",
                      NULL,
                      G_DBUS_CALL_FLAGS_NONE,
                      20000,
                      priv->connman_proxy_cancellable,
                      connman_get_properties_done,
                      self);
}

static void
handle_connman_iface(NMModemOfono *self, gboolean found)
{
    NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    _LOGD("ConnectionManager interface %sfound", found ? "" : "not ");

    if (!found && (priv->connman_proxy || priv->connman_proxy_cancellable)) {
        _LOGI("ConnectionManager interface disappeared");
        nm_clear_g_cancellable(&priv->connman_proxy_cancellable);
        if (priv->connman_proxy) {
            g_signal_handlers_disconnect_by_data(priv->connman_proxy, self);
            g_clear_object(&priv->connman_proxy);
        }

        /* The connection manager proxy disappeared, we should
         * consider the modem disabled.
         */
        priv->gprs_attached = FALSE;

        update_modem_state(self);
    } else if (found && (!priv->connman_proxy && !priv->connman_proxy_cancellable)) {
        _LOGI("found new ConnectionManager interface");

        priv->connman_proxy_cancellable = g_cancellable_new();

        g_dbus_proxy_new_for_bus(G_BUS_TYPE_SYSTEM,
                                 G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
                                     | G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
                                 NULL, /* GDBusInterfaceInfo */
                                 OFONO_DBUS_SERVICE,
                                 nm_modem_get_path(NM_MODEM(self)),
                                 OFONO_DBUS_INTERFACE_CONNECTION_MANAGER,
                                 priv->connman_proxy_cancellable,
                                 _connman_proxy_new_cb,
                                 self);
    }
}

static void
handle_modem_property(GDBusProxy *proxy, const char *property, GVariant *v, gpointer user_data)
{
    NMModemOfono        *self = NM_MODEM_OFONO(user_data);
    NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    if ((g_strcmp0(property, "Online") == 0) && VARIANT_IS_OF_TYPE_BOOLEAN(v)) {
        gboolean online = g_variant_get_boolean(v);

        _LOGD("Online: %s", online ? "True" : "False");

        if (online != priv->modem_online) {
            priv->modem_online = online;
            _LOGI("modem is now %s", online ? "Online" : "Offline");
            update_modem_state(self);
        }

    } else if ((g_strcmp0(property, "Interfaces") == 0) && VARIANT_IS_OF_TYPE_STRING_ARRAY(v)) {
        const char **array, **iter;
        gboolean     found_connman = FALSE;
        gboolean     found_sim     = FALSE;

        _LOGD("Interfaces found");

        array = g_variant_get_strv(v, NULL);
        if (array) {
            for (iter = array; *iter; iter++) {
                if (g_strcmp0(OFONO_DBUS_INTERFACE_SIM_MANAGER, *iter) == 0)
                    found_sim = TRUE;
                else if (g_strcmp0(OFONO_DBUS_INTERFACE_CONNECTION_MANAGER, *iter) == 0)
                    found_connman = TRUE;
            }
            g_free(array);
        }

        handle_sim_iface(self, found_sim);
        handle_connman_iface(self, found_connman);
    }
}

static void
modem_property_changed(GDBusProxy *proxy, const char *property, GVariant *v, gpointer user_data)
{
    GVariant *v_child = g_variant_get_child_value(v, 0);

    handle_modem_property(proxy, property, v_child, user_data);
    g_variant_unref(v_child);
}

static void
modem_get_properties_done(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMModemOfono              *self;
    NMModemOfonoPrivate       *priv;
    gs_free_error GError      *error        = NULL;
    gs_unref_variant GVariant *v_properties = NULL;
    gs_unref_variant GVariant *v_dict       = NULL;
    GVariant                  *v;
    GVariantIter               i;
    const char                *property;

    v_properties =
        _nm_dbus_proxy_call_finish(G_DBUS_PROXY(source), result, G_VARIANT_TYPE("(a{sv})"), &error);
    if (!v_properties && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        return;

    self = NM_MODEM_OFONO(user_data);
    priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    g_clear_object(&priv->modem_proxy_cancellable);

    if (!v_properties) {
        g_dbus_error_strip_remote_error(error);
        _LOGW("error getting modem properties: %s", error->message);
        return;
    }

    v_dict = g_variant_get_child_value(v_properties, 0);
    if (!v_dict) {
        _LOGW("error getting modem properties: no v_dict");
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

    g_variant_iter_init(&i, v_dict);
    while (g_variant_iter_loop(&i, "{&sv}", &property, &v)) {
        handle_modem_property(NULL, property, v, self);
    }
}

static void
stage1_prepare_done(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMModemOfono              *self;
    NMModemOfonoPrivate       *priv;
    gs_free_error GError      *error = NULL;
    gs_unref_variant GVariant *v     = NULL;

    v = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), result, &error);
    if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        return;

    self = NM_MODEM_OFONO(user_data);
    priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    g_clear_object(&priv->context_proxy_cancellable);

    nm_clear_pointer(&priv->connect_properties, g_hash_table_destroy);

    if (error) {
        if (!g_strstr_len(error->message,
                          NM_STRLEN(OFONO_ERROR_IN_PROGRESS),
                          OFONO_ERROR_IN_PROGRESS)) {
            nm_modem_emit_prepare_result(NM_MODEM(self), FALSE, NM_DEVICE_STATE_REASON_MODEM_BUSY);
        }
    }
}

static void
handle_settings(GVariant *v_dict, gpointer user_data)
{
    NMModemOfono        *self = NM_MODEM_OFONO(user_data);
    NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE(self);
    char                 sbuf[sizeof(_nm_utils_to_string_buffer)];
    NMPlatformIP4Address address;
    gboolean             ret = FALSE;
    const char          *interface;
    const char          *s;
    const char         **array;
    guint32              address_network, gateway_network;
    int                  ifindex;
    GError              *error = NULL;

    //_LOGD("PropertyChanged: %s", property);

    /*
     * TODO: might be a good idea and re-factor this to mimic bluez-device,
     * ie. have this function just check the key, and call a sub-func to
     * handle the action.
     */

    _LOGI("IPv4 static Settings:");

    if (!g_variant_lookup(v_dict, "Interface", "&s", &interface)) {
        _LOGW("Settings 'Interface' missing");
        goto out;
    }

    _LOGD("Interface: %s", interface);
    if (!nm_modem_set_data_port(NM_MODEM(self),
                                NM_PLATFORM_GET,
                                interface,
                                NM_MODEM_IP_METHOD_STATIC,
                                NM_MODEM_IP_METHOD_UNKNOWN,
                                0,
                                &error)) {
        _LOGW("failed to connect to modem: %s", error->message);
        g_clear_error(&error);
        goto out;
    }

    ifindex = nm_modem_get_ip_ifindex(NM_MODEM(self));
    g_return_if_fail(ifindex > 0);

    /* TODO: verify handling of l3cd_4; check other places it's used... */
    nm_clear_l3cd(&priv->l3cd_4);

    priv->l3cd_4 = nm_l3_config_data_new(nm_platform_get_multi_idx(NM_PLATFORM_GET),
                                         ifindex,
                                         NM_IP_CONFIG_SOURCE_WWAN);

    if (!g_variant_lookup(v_dict, "Address", "&s", &s)) {
        _LOGW("Settings 'Address' missing");
        goto out;
    }
    if (!s || !nm_utils_parse_inaddr_bin(AF_INET, s, NULL, &address_network)) {
        _LOGW("can't convert 'Address' %s to addr", s ?: "");
        goto out;
    }

    address = (NMPlatformIP4Address){
        .ifindex     = ifindex,
        .address     = address_network,
        .addr_source = NM_IP_CONFIG_SOURCE_WWAN,
    };

    if (!g_variant_lookup(v_dict, "Netmask", "&s", &s)) {
        _LOGW("Settings 'Netmask' missing");
        goto out;
    }
    if (!s || !nm_utils_parse_inaddr_bin(AF_INET, s, NULL, &address_network)) {
        _LOGW("invalid 'Netmask': %s", s ?: "");
        goto out;
    }
    address.plen = nm_utils_ip4_netmask_to_prefix(address_network);

    _LOGI("Address: %s", nm_platform_ip4_address_to_string(&address, sbuf, sizeof(sbuf)));
    nm_l3_config_data_add_address_4(priv->l3cd_4, &address);

    if (!g_variant_lookup(v_dict, "Gateway", "&s", &s) || !s) {
        _LOGW("Settings 'Gateway' missing");
        goto out;
    }
    if (!nm_utils_parse_inaddr_bin(AF_INET, s, NULL, &gateway_network)) {
        _LOGW("invalid 'Gateway': %s", s);
        goto out;
    }
    {
        const NMPlatformIP4Route r = {
            .rt_source     = NM_IP_CONFIG_SOURCE_WWAN,
            .gateway       = gateway_network,
            .table_any     = TRUE,
            .table_coerced = 0,
            .metric_any    = TRUE,
            .metric        = 0,
        };

        _LOGI("Gateway: %s", s);
        nm_l3_config_data_add_route_4(priv->l3cd_4, &r);
    }

    if (!g_variant_lookup(v_dict, "DomainNameServers", "^a&s", &array)) {
        _LOGW("Settings 'DomainNameServers' missing");
        goto out;
    }
    if (array) {
        gboolean any_good = FALSE;

        for (; array[0]; array++) {
            if (!nm_utils_parse_inaddr_bin(AF_INET, *array, NULL, &address_network)
                || !address_network) {
                _LOGW("invalid NameServer: %s", *array);
                continue;
            }
            any_good = TRUE;
            _LOGI("DNS: %s", *array);
            nm_l3_config_data_add_nameserver(priv->l3cd_4, AF_INET, &address_network);
        }
        if (!any_good) {
            _LOGW("Settings: 'DomainNameServers': none specified");
            goto out;
        }
    }

    if (g_variant_lookup(v_dict, "MessageProxy", "&s", &s)) {
        _LOGI("MessageProxy: %s", s);
        if (s && nm_utils_parse_inaddr_bin(AF_INET, s, NULL, &address_network)) {
            const NMPlatformIP4Route mms_route = {
                .network       = address_network,
                .plen          = 32,
                .gateway       = gateway_network,
                .table_any     = TRUE,
                .table_coerced = 0,
                .metric_any    = TRUE,
                .metric        = 0,
            };

            nm_l3_config_data_add_route_4(priv->l3cd_4, &mms_route);
        } else
            _LOGW("invalid MessageProxy: %s", s);
    }

    ret = TRUE;

out:
    if (priv->l3cd_4)
        nm_l3_config_data_seal(priv->l3cd_4);

    if (nm_modem_get_state(NM_MODEM(self)) != NM_MODEM_STATE_CONNECTED) {
        _LOGI("emitting PREPARE_RESULT: %s", ret ? "TRUE" : "FALSE");
        nm_modem_emit_prepare_result(NM_MODEM(self),
                                     ret,
                                     ret ? NM_DEVICE_STATE_REASON_NONE
                                         : NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
    } else {
        _LOGW("MODEM_PPP_FAILED");
        nm_modem_emit_ppp_failed(NM_MODEM(self), NM_DEVICE_STATE_REASON_PPP_FAILED);
    }
}

static void
context_property_changed(GDBusProxy *proxy, const char *property, GVariant *v, gpointer user_data)
{
    NMModemOfono              *self   = NM_MODEM_OFONO(user_data);
    gs_unref_variant GVariant *v_dict = NULL;

    _LOGD("PropertyChanged: %s", property);

    if (g_strcmp0(property, "Settings") != 0)
        return;

    v_dict = g_variant_get_child_value(v, 0);
    if (!v_dict) {
        _LOGW("ofono: (%s): error getting IPv4 Settings", nm_modem_get_uid(NM_MODEM(self)));
        return;
    }

    g_assert(g_variant_is_of_type(v_dict, G_VARIANT_TYPE_VARDICT));

    handle_settings(v_dict, user_data);
}

static void
stage3_ip_config_start(NMModem *modem, int addr_family, NMModemIPMethod ip_method)
{
    NMModemOfono         *self  = NM_MODEM_OFONO(modem);
    NMModemOfonoPrivate  *priv  = NM_MODEM_OFONO_GET_PRIVATE(self);
    gs_free_error GError *error = NULL;

    _LOGD("IP4 config is done; setting modem_state -> CONNECTED");

    if (!NM_IS_IPv4(addr_family) || ip_method == NM_MODEM_IP_METHOD_AUTO) {
        nm_modem_emit_signal_new_config_success(modem, addr_family, NULL, TRUE, NULL);
        goto out;
    }

    if (!priv->l3cd_4) {
        nm_utils_error_set(&error, NM_UTILS_ERROR_UNKNOWN, "IP config not received");
        nm_modem_emit_signal_new_config_failure(modem,
                                                addr_family,
                                                NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE,
                                                error);
        goto out;
    }

    nm_modem_emit_signal_new_config_success(modem, addr_family, priv->l3cd_4, FALSE, NULL);

out:
    nm_modem_set_state(NM_MODEM(self),
                       NM_MODEM_STATE_CONNECTED,
                       nm_modem_state_to_string(NM_MODEM_STATE_CONNECTED));
}

static void
context_properties_cb(GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
    NMModemOfono              *self;
    NMModemOfonoPrivate       *priv;
    gs_free_error GError      *error      = NULL;
    gs_unref_variant GVariant *properties = NULL;
    gs_unref_variant GVariant *settings   = NULL;
    gs_unref_variant GVariant *v_dict     = NULL;
    gboolean                   active;

    self = NM_MODEM_OFONO(user_data);
    priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    properties = g_dbus_proxy_call_finish(proxy, result, &error);

    if (!properties) {
        _LOGW("ofono: connection failed: no context properties returned %s", error->message);
        g_clear_error(&error);
        goto error;
    }

    v_dict = g_variant_get_child_value(properties, 0);
    if (!v_dict || !g_variant_is_of_type(v_dict, G_VARIANT_TYPE_VARDICT)) {
        _LOGW("ofono: connection failed; could not read connection properties");
        goto error;
    }

    if (!g_variant_lookup(v_dict, "Active", "b", &active)) {
        _LOGW("ofono: connection failed; can not read 'Active' property");
        goto error;
    }

    /* Watch for custom ofono PropertyChanged signals */
    _nm_dbus_signal_connect(priv->context_proxy,
                            "PropertyChanged",
                            G_VARIANT_TYPE("(sv)"),
                            G_CALLBACK(context_property_changed),
                            self);

    if (active) {
        _LOGD("ofono: connection is already Active");

        settings = g_variant_lookup_value(v_dict, "Settings", G_VARIANT_TYPE_VARDICT);
        if (settings == NULL) {
            _LOGW("ofono: connection failed; can not read 'Settings' property");
            goto error;
        }

        handle_settings(settings, user_data);
    } else {
        g_dbus_proxy_call(priv->context_proxy,
                          "SetProperty",
                          g_variant_new("(sv)", "Active", g_variant_new("b", TRUE)),
                          G_DBUS_CALL_FLAGS_NONE,
                          20000,
                          NULL,
                          (GAsyncReadyCallback) stage1_prepare_done,
                          self);
    }
    return;

error:
    nm_modem_emit_prepare_result(NM_MODEM(self), FALSE, NM_DEVICE_STATE_REASON_MODEM_BUSY);
}

static void
context_proxy_new_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMModemOfono         *self;
    NMModemOfonoPrivate  *priv;
    gs_free_error GError *error = NULL;
    GDBusProxy           *proxy;

    proxy = g_dbus_proxy_new_for_bus_finish(result, &error);
    if (!proxy || g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        return;

    self = NM_MODEM_OFONO(user_data);
    priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    if (!proxy) {
        _LOGE("failed to create ofono ConnectionContext DBus proxy: %s", error->message);
        g_clear_object(&priv->context_proxy_cancellable);
        nm_modem_emit_prepare_result(NM_MODEM(self), FALSE, NM_DEVICE_STATE_REASON_MODEM_BUSY);
        return;
    }

    priv->context_proxy = proxy;

    if (!priv->gprs_attached) {
        g_clear_object(&priv->context_proxy_cancellable);
        nm_modem_emit_prepare_result(NM_MODEM(self),
                                     FALSE,
                                     NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER);
        return;
    }

    /* We have an old copy of the settings from a previous activation,
     * clear it so that we can gate getting the IP config from oFono
     * on whether or not we have already received them
     */
    nm_clear_l3cd(&priv->l3cd_4);

    /* We need to directly query ConnectionContextinteface to get the current
     * property values */
    g_dbus_proxy_call(priv->context_proxy,
                      "GetProperties",
                      NULL,
                      G_DBUS_CALL_FLAGS_NONE,
                      20000,
                      NULL,
                      (GAsyncReadyCallback) context_properties_cb,
                      self);
}

static void
do_context_activate(NMModemOfono *self)
{
    NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    g_return_if_fail(NM_IS_MODEM_OFONO(self));

    nm_clear_g_cancellable(&priv->context_proxy_cancellable);
    g_clear_object(&priv->context_proxy);

    priv->context_proxy_cancellable = g_cancellable_new();

    g_dbus_proxy_new_for_bus(G_BUS_TYPE_SYSTEM,
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
create_connect_properties(NMConnection *connection)
{
    NMSettingGsm *setting;
    GHashTable   *properties;
    const char   *str;

    setting    = nm_connection_get_setting_gsm(connection);
    properties = g_hash_table_new(nm_str_hash, g_str_equal);

    str = nm_setting_gsm_get_apn(setting);
    if (str)
        g_hash_table_insert(properties, "AccessPointName", g_strdup(str));

    str = nm_setting_gsm_get_username(setting);
    if (str)
        g_hash_table_insert(properties, "Username", g_strdup(str));

    str = nm_setting_gsm_get_password(setting);
    if (str)
        g_hash_table_insert(properties, "Password", g_strdup(str));

    return properties;
}

static NMActStageReturn
modem_act_stage1_prepare(NMModem             *modem,
                         NMConnection        *connection,
                         NMDeviceStateReason *out_failure_reason)
{
    NMModemOfono        *self = NM_MODEM_OFONO(modem);
    NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE(self);
    const char          *context_id;
    char               **id = NULL;

    context_id = nm_connection_get_id(connection);
    id         = g_strsplit(context_id, "/", 0);
    g_return_val_if_fail(id[2], NM_ACT_STAGE_RETURN_FAILURE);

    _LOGD("trying %s %s", id[1], id[2]);

    g_free(priv->context_path);
    priv->context_path = g_strdup_printf("%s/%s", nm_modem_get_path(modem), id[2]);
    g_strfreev(id);

    if (!priv->context_path) {
        NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_GSM_APN_FAILED);
        return NM_ACT_STAGE_RETURN_FAILURE;
    }

    if (priv->connect_properties)
        g_hash_table_destroy(priv->connect_properties);

    priv->connect_properties = create_connect_properties(connection);

    _LOGI("activating context %s", priv->context_path);

    update_modem_state(self);
    if (nm_modem_get_state(modem) == NM_MODEM_STATE_REGISTERED) {
        do_context_activate(self);
    } else {
        _LOGW("could not activate context: modem is not registered.");
        NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER);
        return NM_ACT_STAGE_RETURN_FAILURE;
    }

    return NM_ACT_STAGE_RETURN_POSTPONE;
}

static void
modem_proxy_new_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMModemOfono         *self;
    NMModemOfonoPrivate  *priv;
    gs_free_error GError *error = NULL;
    GDBusProxy           *proxy;

    proxy = g_dbus_proxy_new_for_bus_finish(result, &error);
    if (!proxy && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        return;

    self = NM_MODEM_OFONO(user_data);
    priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    if (!proxy) {
        _LOGE("failed to create ofono modem DBus proxy: %s", error->message);
        g_clear_object(&priv->modem_proxy_cancellable);
        return;
    }

    priv->modem_proxy = proxy;

    _nm_dbus_signal_connect(priv->modem_proxy,
                            "PropertyChanged",
                            G_VARIANT_TYPE("(sv)"),
                            G_CALLBACK(modem_property_changed),
                            self);

    g_dbus_proxy_call(priv->modem_proxy,
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
nm_modem_ofono_init(NMModemOfono *self)
{}

static void
constructed(GObject *object)
{
    NMModemOfono        *self = NM_MODEM_OFONO(object);
    NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    priv->modem_proxy_cancellable = g_cancellable_new();

    g_dbus_proxy_new_for_bus(G_BUS_TYPE_SYSTEM,
                             G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
                             NULL,
                             OFONO_DBUS_SERVICE,
                             nm_modem_get_path(NM_MODEM(self)),
                             OFONO_DBUS_INTERFACE_MODEM,
                             priv->modem_proxy_cancellable,
                             modem_proxy_new_cb,
                             self);

    G_OBJECT_CLASS(nm_modem_ofono_parent_class)->constructed(object);
}

NMModem *
nm_modem_ofono_new(const char *path)
{
    gs_free char *basename = NULL;

    g_return_val_if_fail(path != NULL, NULL);

    nm_log_info(LOGD_MB, "ofono: creating new Ofono modem path %s", path);

    /* Use short modem name (not its object path) as the NM device name (which
     * comes from NM_MODEM_UID)and the device ID.
     */
    basename = g_path_get_basename(path);

    return g_object_new(NM_TYPE_MODEM_OFONO,
                        NM_MODEM_PATH,
                        path,
                        NM_MODEM_UID,
                        basename,
                        NM_MODEM_DEVICE_ID,
                        basename,
                        NM_MODEM_CONTROL_PORT,
                        "ofono", /* mandatory */
                        NM_MODEM_DRIVER,
                        "ofono",
                        NM_MODEM_STATE,
                        (int) NM_MODEM_STATE_INITIALIZING,
                        NULL);
}

static void
dispose(GObject *object)
{
    NMModemOfono        *self = NM_MODEM_OFONO(object);
    NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE(self);

    nm_clear_g_cancellable(&priv->modem_proxy_cancellable);
    nm_clear_g_cancellable(&priv->connman_proxy_cancellable);
    nm_clear_g_cancellable(&priv->context_proxy_cancellable);
    nm_clear_g_cancellable(&priv->sim_proxy_cancellable);

    if (priv->connect_properties) {
        g_hash_table_destroy(priv->connect_properties);
        priv->connect_properties = NULL;
    }

    nm_clear_l3cd(&priv->l3cd_4);

    if (priv->modem_proxy) {
        g_signal_handlers_disconnect_by_data(priv->modem_proxy, self);
        g_clear_object(&priv->modem_proxy);
    }

    if (priv->connman_proxy) {
        g_signal_handlers_disconnect_by_data(priv->connman_proxy, self);
        g_clear_object(&priv->connman_proxy);
    }

    if (priv->context_proxy) {
        g_signal_handlers_disconnect_by_data(priv->context_proxy, self);
        g_clear_object(&priv->context_proxy);
    }

    if (priv->sim_proxy) {
        g_signal_handlers_disconnect_by_data(priv->sim_proxy, self);
        g_clear_object(&priv->sim_proxy);
    }

    g_free(priv->imsi);
    priv->imsi = NULL;

    G_OBJECT_CLASS(nm_modem_ofono_parent_class)->dispose(object);
}

static void
nm_modem_ofono_class_init(NMModemOfonoClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);
    NMModemClass *modem_class  = NM_MODEM_CLASS(klass);

    object_class->constructed = constructed;
    object_class->dispose     = dispose;

    modem_class->get_capabilities                       = get_capabilities;
    modem_class->disconnect                             = disconnect;
    modem_class->deactivate_cleanup                     = deactivate_cleanup;
    modem_class->check_connection_compatible_with_modem = check_connection_compatible_with_modem;

    modem_class->modem_act_stage1_prepare = modem_act_stage1_prepare;
    modem_class->stage3_ip_config_start   = stage3_ip_config_start;
}
