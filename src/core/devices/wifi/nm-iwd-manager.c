/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Intel Corporation
 */

#include "src/core/nm-default-daemon.h"

#include "nm-iwd-manager.h"

#include <net/if.h>

#include "nm-core-internal.h"
#include "nm-manager.h"
#include "nm-device-iwd.h"
#include "nm-wifi-utils.h"
#include "nm-glib-aux/nm-random-utils.h"
#include "settings/nm-settings.h"
#include "nm-std-aux/nm-dbus-compat.h"

/*****************************************************************************/

typedef struct {
    const char *         name;
    NMIwdNetworkSecurity security;
    char                 buf[0];
} KnownNetworkId;

typedef struct {
    GDBusProxy *          known_network;
    NMSettingsConnection *mirror_connection;
} KnownNetworkData;

typedef struct {
    NMManager *         manager;
    NMSettings *        settings;
    GCancellable *      cancellable;
    gboolean            running;
    GDBusObjectManager *object_manager;
    guint               agent_id;
    char *              agent_path;
    GHashTable *        known_networks;
    NMDeviceIwd *       last_agent_call_device;
} NMIwdManagerPrivate;

struct _NMIwdManager {
    GObject             parent;
    NMIwdManagerPrivate _priv;
};

struct _NMIwdManagerClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NMIwdManager, nm_iwd_manager, G_TYPE_OBJECT)

#define NM_IWD_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMIwdManager, NM_IS_IWD_MANAGER)

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME "iwd-manager"
#define _NMLOG_DOMAIN      LOGD_WIFI

#define _NMLOG(level, ...)                                                 \
    G_STMT_START                                                           \
    {                                                                      \
        if (nm_logging_enabled(level, _NMLOG_DOMAIN)) {                    \
            char __prefix[32];                                             \
                                                                           \
            if (self)                                                      \
                g_snprintf(__prefix,                                       \
                           sizeof(__prefix),                               \
                           "%s[%p]",                                       \
                           ""_NMLOG_PREFIX_NAME                            \
                           "",                                             \
                           (self));                                        \
            else                                                           \
                g_strlcpy(__prefix, _NMLOG_PREFIX_NAME, sizeof(__prefix)); \
            _nm_log((level),                                               \
                    (_NMLOG_DOMAIN),                                       \
                    0,                                                     \
                    NULL,                                                  \
                    NULL,                                                  \
                    "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),             \
                    __prefix _NM_UTILS_MACRO_REST(__VA_ARGS__));           \
        }                                                                  \
    }                                                                      \
    G_STMT_END

/*****************************************************************************/

static void mirror_connection_take_and_delete(NMSettingsConnection *sett_conn,
                                              KnownNetworkData *    data);

/*****************************************************************************/

static const char *
get_variant_string_or_null(GVariant *v)
{
    if (!v)
        return NULL;

    if (!g_variant_is_of_type(v, G_VARIANT_TYPE_STRING)
        && !g_variant_is_of_type(v, G_VARIANT_TYPE_OBJECT_PATH))
        return NULL;

    return g_variant_get_string(v, NULL);
}

static const char *
get_property_string_or_null(GDBusProxy *proxy, const char *property)
{
    gs_unref_variant GVariant *value = NULL;

    if (!proxy || !property)
        return NULL;

    value = g_dbus_proxy_get_cached_property(proxy, property);

    return get_variant_string_or_null(value);
}

static gboolean
get_property_bool(GDBusProxy *proxy, const char *property, gboolean default_val)
{
    gs_unref_variant GVariant *value = NULL;

    if (!proxy || !property)
        return default_val;

    value = g_dbus_proxy_get_cached_property(proxy, property);
    if (!value || !g_variant_is_of_type(value, G_VARIANT_TYPE_BOOLEAN))
        return default_val;

    return g_variant_get_boolean(value);
}

static NMDeviceIwd *
get_device_from_network(NMIwdManager *self, GDBusProxy *network)
{
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    const char *         ifname;
    const char *         device_path;
    NMDevice *           device;
    gs_unref_object GDBusInterface *device_obj = NULL;

    /* Try not to rely on the path of the Device being a prefix of the
     * Network's object path.
     */

    device_path = get_property_string_or_null(network, "Device");
    if (!device_path) {
        _LOGD("Device not cached for network at %s", g_dbus_proxy_get_object_path(network));
        return NULL;
    }

    device_obj = g_dbus_object_manager_get_interface(priv->object_manager,
                                                     device_path,
                                                     NM_IWD_DEVICE_INTERFACE);

    ifname = get_property_string_or_null(G_DBUS_PROXY(device_obj), "Name");
    if (!ifname) {
        _LOGD("Name not cached for device at %s", device_path);
        return NULL;
    }

    device = nm_manager_get_device(priv->manager, ifname, NM_DEVICE_TYPE_WIFI);
    if (!device || !NM_IS_DEVICE_IWD(device)) {
        _LOGD("NM device %s is not an IWD-managed device", ifname);
        return NULL;
    }

    return NM_DEVICE_IWD(device);
}

static void
agent_dbus_method_cb(GDBusConnection *      connection,
                     const char *           sender,
                     const char *           object_path,
                     const char *           interface_name,
                     const char *           method_name,
                     GVariant *             parameters,
                     GDBusMethodInvocation *invocation,
                     gpointer               user_data)
{
    NMIwdManager *       self = user_data;
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    const char *         network_path;
    NMDeviceIwd *        device;
    gs_free char *       name_owner         = NULL;
    gs_unref_object GDBusInterface *network = NULL;

    /* Be paranoid and check the sender address */
    name_owner = g_dbus_object_manager_client_get_name_owner(
        G_DBUS_OBJECT_MANAGER_CLIENT(priv->object_manager));
    if (!nm_streq0(name_owner, sender))
        goto return_error;

    if (!strcmp(method_name, "Cancel")) {
        const char *reason = NULL;

        g_variant_get(parameters, "(&s)", &reason);
        _LOGD("agent-request: Cancel reason: %s", reason);

        if (!priv->last_agent_call_device)
            goto return_error;

        if (nm_device_iwd_agent_query(priv->last_agent_call_device, NULL)) {
            priv->last_agent_call_device = NULL;
            g_dbus_method_invocation_return_value(invocation, NULL);
            return;
        }

        priv->last_agent_call_device = NULL;
        goto return_error;
    }

    if (!strcmp(method_name, "RequestUserPassword"))
        g_variant_get(parameters, "(&os)", &network_path, NULL);
    else
        g_variant_get(parameters, "(&o)", &network_path);

    network = g_dbus_object_manager_get_interface(priv->object_manager,
                                                  network_path,
                                                  NM_IWD_NETWORK_INTERFACE);
    if (!network) {
        _LOGE("agent-request: unable to find the network object");
        goto return_error;
    }

    device = get_device_from_network(self, G_DBUS_PROXY(network));
    if (!device) {
        _LOGD("agent-request: device not found in IWD Agent request");
        goto return_error;
    }

    if (nm_device_iwd_agent_query(device, invocation)) {
        priv->last_agent_call_device = device;
        return;
    }

    _LOGD("agent-request: device %s did not handle the IWD Agent request",
          nm_device_get_iface(NM_DEVICE(device)));

return_error:
    /* IWD doesn't look at the specific error */
    g_dbus_method_invocation_return_error_literal(invocation,
                                                  NM_DEVICE_ERROR,
                                                  NM_DEVICE_ERROR_INVALID_CONNECTION,
                                                  "Secrets not available for this connection");
}

static const GDBusInterfaceInfo iwd_agent_iface_info = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
    "net.connman.iwd.Agent",
    .methods = NM_DEFINE_GDBUS_METHOD_INFOS(
        NM_DEFINE_GDBUS_METHOD_INFO(
            "RequestPassphrase",
            .in_args  = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("network", "o"), ),
            .out_args = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("passphrase", "s"), ), ),
        NM_DEFINE_GDBUS_METHOD_INFO(
            "RequestPrivateKeyPassphrase",
            .in_args  = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("network", "o"), ),
            .out_args = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("passphrase", "s"), ), ),
        NM_DEFINE_GDBUS_METHOD_INFO(
            "RequestUserNameAndPassword",
            .in_args  = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("network", "o"), ),
            .out_args = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("user", "s"),
                                                  NM_DEFINE_GDBUS_ARG_INFO("password", "s"), ), ),
        NM_DEFINE_GDBUS_METHOD_INFO(
            "RequestUserPassword",
            .in_args  = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("network", "o"),
                                                 NM_DEFINE_GDBUS_ARG_INFO("user", "s"), ),
            .out_args = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("password", "s"), ), ),
        NM_DEFINE_GDBUS_METHOD_INFO("Cancel",
                                    .in_args = NM_DEFINE_GDBUS_ARG_INFOS(
                                        NM_DEFINE_GDBUS_ARG_INFO("reason", "s"), ), ), ), );

static guint
iwd_agent_export(GDBusConnection *connection, gpointer user_data, char **agent_path, GError **error)
{
    static const GDBusInterfaceVTable vtable = {
        .method_call = agent_dbus_method_cb,
    };
    char         path[50];
    unsigned int rnd;
    guint        id;

    nm_utils_random_bytes(&rnd, sizeof(rnd));

    nm_sprintf_buf(path, "/agent/%u", rnd);

    id =
        g_dbus_connection_register_object(connection,
                                          path,
                                          NM_UNCONST_PTR(GDBusInterfaceInfo, &iwd_agent_iface_info),
                                          &vtable,
                                          user_data,
                                          NULL,
                                          error);

    if (id)
        *agent_path = g_strdup(path);
    return id;
}

static void
register_agent(NMIwdManager *self)
{
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    GDBusInterface *     agent_manager;

    agent_manager = g_dbus_object_manager_get_interface(priv->object_manager,
                                                        "/net/connman/iwd", /* IWD 1.0+ */
                                                        NM_IWD_AGENT_MANAGER_INTERFACE);
    if (!agent_manager) {
        _LOGE("unable to register the IWD Agent: PSK/8021x Wi-Fi networks may not work");
        return;
    }

    /* Register our agent */
    g_dbus_proxy_call(G_DBUS_PROXY(agent_manager),
                      "RegisterAgent",
                      g_variant_new("(o)", priv->agent_path),
                      G_DBUS_CALL_FLAGS_NONE,
                      -1,
                      NULL,
                      NULL,
                      NULL);

    g_object_unref(agent_manager);
}

/*****************************************************************************/

static KnownNetworkId *
known_network_id_new(const char *name, NMIwdNetworkSecurity security)
{
    KnownNetworkId *id;
    gsize           strsize = strlen(name) + 1;

    id           = g_malloc(sizeof(KnownNetworkId) + strsize);
    id->name     = id->buf;
    id->security = security;
    memcpy(id->buf, name, strsize);

    return id;
}

static guint
known_network_id_hash(KnownNetworkId *id)
{
    NMHashState h;

    nm_hash_init(&h, 1947951703u);
    nm_hash_update_val(&h, id->security);
    nm_hash_update_str(&h, id->name);
    return nm_hash_complete(&h);
}

static gboolean
known_network_id_equal(KnownNetworkId *a, KnownNetworkId *b)
{
    return a->security == b->security && nm_streq(a->name, b->name);
}

static void
known_network_data_free(KnownNetworkData *network)
{
    if (!network)
        return;

    g_object_unref(network->known_network);
    mirror_connection_take_and_delete(network->mirror_connection, network);
    g_slice_free(KnownNetworkData, network);
}

/*****************************************************************************/

static void
set_device_dbus_object(NMIwdManager *self, GDBusProxy *proxy, GDBusObject *object)
{
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    const char *         ifname;
    int                  ifindex;
    NMDevice *           device;
    int                  errsv;

    ifname = get_property_string_or_null(proxy, "Name");
    if (!ifname) {
        _LOGE("Name not cached for Device at %s", g_dbus_proxy_get_object_path(proxy));
        return;
    }

    ifindex = if_nametoindex(ifname);

    if (!ifindex) {
        errsv = errno;
        _LOGE("if_nametoindex failed for Name %s for Device at %s: %i",
              ifname,
              g_dbus_proxy_get_object_path(proxy),
              errsv);
        return;
    }

    device = nm_manager_get_device_by_ifindex(priv->manager, ifindex);
    if (!NM_IS_DEVICE_IWD(device)) {
        _LOGE("IWD device named %s is not a Wifi device", ifname);
        return;
    }

    nm_device_iwd_set_dbus_object(NM_DEVICE_IWD(device), object);
}

static void
known_network_update_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    gs_unref_variant GVariant *variant = NULL;
    gs_free_error GError *error        = NULL;

    variant = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &error);
    if (!variant) {
        nm_log_warn(LOGD_WIFI,
                    "Updating %s on IWD known network %s failed: %s",
                    (const char *) user_data,
                    g_dbus_proxy_get_object_path(G_DBUS_PROXY(source)),
                    error->message);
    }
}

static void
sett_conn_changed(NMSettingsConnection *sett_conn, guint update_reason, KnownNetworkData *data)
{
    NMSettingsConnectionIntFlags flags;
    NMConnection *               conn   = nm_settings_connection_get_connection(sett_conn);
    NMSettingConnection *        s_conn = nm_connection_get_setting_connection(conn);
    gboolean                     nm_autoconnectable = nm_setting_connection_get_autoconnect(s_conn);
    gboolean iwd_autoconnectable = get_property_bool(data->known_network, "AutoConnect", TRUE);

    nm_assert(sett_conn == data->mirror_connection);

    if (iwd_autoconnectable == nm_autoconnectable)
        return;

    /* If this is a generated connection it may be ourselves updating it */
    flags = nm_settings_connection_get_flags(data->mirror_connection);
    if (NM_FLAGS_HAS(flags, NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED))
        return;

    nm_log_dbg(LOGD_WIFI,
               "Updating AutoConnect on known network at %s based on connection %s",
               g_dbus_proxy_get_object_path(data->known_network),
               nm_settings_connection_get_id(data->mirror_connection));
    g_dbus_proxy_call(data->known_network,
                      DBUS_INTERFACE_PROPERTIES ".Set",
                      g_variant_new("(ssv)",
                                    NM_IWD_KNOWN_NETWORK_INTERFACE,
                                    "AutoConnect",
                                    g_variant_new_boolean(nm_autoconnectable)),
                      G_DBUS_CALL_FLAGS_NONE,
                      -1,
                      NULL,
                      known_network_update_cb,
                      "AutoConnect");
}

/* Look up an existing NMSettingsConnection for a network that has been
 * preprovisioned with an IWD config file or has been connected to before,
 * or create a new in-memory NMSettingsConnection object.  This will let
 * users control the few supported properties (mainly make it
 * IWD-autoconnectable or not), remove/forget the network, or, for a
 * WPA2-Enterprise type network it will inform the NM autoconnect mechanism
 * and the clients that this networks needs no additional EAP configuration
 * from the user.
 */
static NMSettingsConnection *
mirror_connection(NMIwdManager *        self,
                  const KnownNetworkId *id,
                  gboolean              create_new,
                  GDBusProxy *          known_network)
{
    NMIwdManagerPrivate *        priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    NMSettingsConnection *const *iter;
    gs_unref_object NMConnection *connection          = NULL;
    NMSettingsConnection *        settings_connection = NULL;
    char                          uuid[37];
    NMSetting *                   setting;
    gs_free_error GError *error            = NULL;
    gs_unref_bytes GBytes *new_ssid        = NULL;
    gsize                  ssid_len        = strlen(id->name);
    gboolean               autoconnectable = TRUE;
    gboolean               hidden          = FALSE;
    gboolean               exact_match     = TRUE;
    const char *           key_mgmt        = NULL;

    if (known_network) {
        autoconnectable = get_property_bool(known_network, "AutoConnect", TRUE);
        hidden          = get_property_bool(known_network, "Hidden", FALSE);
    }

    for (iter = nm_settings_get_connections(priv->settings, NULL); *iter; iter++) {
        NMSettingsConnection *sett_conn = *iter;
        NMConnection *        conn      = nm_settings_connection_get_connection(sett_conn);
        NMIwdNetworkSecurity  security;
        NMSettingWireless *   s_wifi;
        const guint8 *        ssid_bytes;
        gsize                 ssid_len2;

        if (!nm_wifi_connection_get_iwd_ssid_and_security(conn, NULL, &security))
            continue;

        if (security != id->security)
            continue;

        s_wifi = nm_connection_get_setting_wireless(conn);
        if (!s_wifi)
            continue;

        /* The SSID must be UTF-8 if it matches since id->name is known to be
         * valid UTF-8, so just memcmp them.
         */
        ssid_bytes = g_bytes_get_data(nm_setting_wireless_get_ssid(s_wifi), &ssid_len2);
        if (!ssid_bytes || ssid_len2 != ssid_len || memcmp(ssid_bytes, id->name, ssid_len))
            continue;

        exact_match = TRUE;

        if (known_network) {
            NMSettingConnection *s_conn = nm_connection_get_setting_connection(conn);

            if (nm_setting_connection_get_autoconnect(s_conn) != autoconnectable
                || nm_setting_wireless_get_hidden(s_wifi) != hidden)
                exact_match = FALSE;
        }

        switch (id->security) {
        case NM_IWD_NETWORK_SECURITY_WEP:
        case NM_IWD_NETWORK_SECURITY_OPEN:
        case NM_IWD_NETWORK_SECURITY_PSK:
            break;
        case NM_IWD_NETWORK_SECURITY_8021X:
        {
            NMSetting8021x *s_8021x  = nm_connection_get_setting_802_1x(conn);
            gboolean        external = FALSE;
            guint           i;

            for (i = 0; i < nm_setting_802_1x_get_num_eap_methods(s_8021x); i++) {
                if (nm_streq(nm_setting_802_1x_get_eap_method(s_8021x, i), "external")) {
                    external = TRUE;
                    break;
                }
            }

            /* Prefer returning connections with EAP method "external" */
            if (!external)
                exact_match = FALSE;
        }
        }

        if (!settings_connection || exact_match)
            settings_connection = sett_conn;

        if (exact_match)
            break;
    }

    if (settings_connection && known_network && !exact_match) {
        NMSettingsConnectionIntFlags flags = nm_settings_connection_get_flags(settings_connection);

        /* If we found a connection and it's generated (likely by ourselves)
         * it may have been created on a request by
         * nm_iwd_manager_get_ap_mirror_connection() when no Known Network
         * was available so we didn't have access to its properties other
         * than Name and Security.  Copy their values to the generated
         * NMConnection.
         * TODO: avoid notify signals triggering our own watch.
         *
         * If on the other hand this is a user-created NMConnection we
         * should try to copy the properties from it to IWD's Known Network
         * using the Properties DBus interface in case the user created an
         * NM connection before IWD appeared on the bus, or before IWD
         * created its Known Network object.
         */
        if (NM_FLAGS_HAS(flags, NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED)) {
            NMConnection *tmp_conn = nm_settings_connection_get_connection(settings_connection);
            NMSettingConnection *s_conn = nm_connection_get_setting_connection(tmp_conn);
            NMSettingWireless *  s_wifi = nm_connection_get_setting_wireless(tmp_conn);

            g_object_set(G_OBJECT(s_conn),
                         NM_SETTING_CONNECTION_AUTOCONNECT,
                         autoconnectable,
                         NULL);
            g_object_set(G_OBJECT(s_wifi), NM_SETTING_WIRELESS_HIDDEN, hidden, NULL);
        } else {
            KnownNetworkData data = {known_network, settings_connection};
            sett_conn_changed(settings_connection, 0, &data);
        }
    }

    if (settings_connection && known_network) {
        /* Reset NM_SETTINGS_CONNECTION_INT_FLAGS_EXTERNAL now that the
         * connection is going to be referenced by a known network, we don't
         * want it to be deleted when activation fails anymore.
         */
        nm_settings_connection_set_flags_full(settings_connection,
                                              NM_SETTINGS_CONNECTION_INT_FLAGS_EXTERNAL,
                                              0);
    }

    /* If we already have an NMSettingsConnection matching this
     * KnownNetwork, whether it's saved or an in-memory connection
     * potentially created by ourselves then we have nothing left to
     * do here.
     */
    if (settings_connection || !create_new)
        return settings_connection;

    connection = nm_simple_connection_new();

    setting = g_object_new(NM_TYPE_SETTING_CONNECTION,
                           NM_SETTING_CONNECTION_TYPE,
                           NM_SETTING_WIRELESS_SETTING_NAME,
                           NM_SETTING_CONNECTION_ID,
                           id->name,
                           NM_SETTING_CONNECTION_UUID,
                           nm_utils_uuid_generate_buf(uuid),
                           NM_SETTING_CONNECTION_AUTOCONNECT,
                           autoconnectable,
                           NULL);
    nm_connection_add_setting(connection, setting);

    new_ssid = g_bytes_new(id->name, ssid_len);
    setting  = g_object_new(NM_TYPE_SETTING_WIRELESS,
                           NM_SETTING_WIRELESS_SSID,
                           new_ssid,
                           NM_SETTING_WIRELESS_MODE,
                           NM_SETTING_WIRELESS_MODE_INFRA,
                           NM_SETTING_WIRELESS_HIDDEN,
                           hidden,
                           NULL);
    nm_connection_add_setting(connection, setting);

    switch (id->security) {
    case NM_IWD_NETWORK_SECURITY_WEP:
        key_mgmt = "none";
        break;
    case NM_IWD_NETWORK_SECURITY_OPEN:
        key_mgmt = NULL;
        break;
    case NM_IWD_NETWORK_SECURITY_PSK:
        key_mgmt = "wpa-psk";
        break;
    case NM_IWD_NETWORK_SECURITY_8021X:
        key_mgmt = "wpa-eap";
        break;
    }

    if (key_mgmt) {
        setting = g_object_new(NM_TYPE_SETTING_WIRELESS_SECURITY,
                               NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
                               "open",
                               NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
                               key_mgmt,
                               NULL);
        nm_connection_add_setting(connection, setting);
    }

    if (id->security == NM_IWD_NETWORK_SECURITY_8021X) {
        /* "password" and "private-key-password" may be requested by the IWD agent
         * from NM and IWD will implement a specific secret cache policy so by
         * default respect that policy and don't save copies of those secrets in
         * NM settings.  The saved values can not be used anyway because of our
         * use of NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW.
         */
        setting = g_object_new(NM_TYPE_SETTING_802_1X,
                               NM_SETTING_802_1X_PASSWORD_FLAGS,
                               NM_SETTING_SECRET_FLAG_NOT_SAVED,
                               NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS,
                               NM_SETTING_SECRET_FLAG_NOT_SAVED,
                               NULL);
        nm_setting_802_1x_add_eap_method(NM_SETTING_802_1X(setting), "external");
        nm_connection_add_setting(connection, setting);
    }

    if (!nm_connection_normalize(connection, NULL, NULL, NULL))
        return NULL;

    if (!nm_settings_add_connection(
            priv->settings,
            connection,
            NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY,
            NM_SETTINGS_CONNECTION_ADD_REASON_NONE,
            NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
                | (known_network ? 0 : NM_SETTINGS_CONNECTION_INT_FLAGS_EXTERNAL),
            &settings_connection,
            &error)) {
        _LOGW("failed to add a mirror NMConnection for IWD's Known Network '%s': %s",
              id->name,
              error->message);
        return NULL;
    }

    return settings_connection;
}

static void
mirror_connection_take_and_delete(NMSettingsConnection *sett_conn, KnownNetworkData *data)
{
    NMSettingsConnectionIntFlags flags;

    if (!sett_conn)
        return;

    flags = nm_settings_connection_get_flags(sett_conn);

    /* If connection has not been saved since we created it
     * in interface_added it too can be removed now. */
    if (NM_FLAGS_HAS(flags, NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED))
        nm_settings_connection_delete(sett_conn, FALSE);

    g_signal_handlers_disconnect_by_data(sett_conn, data);
    g_object_unref(sett_conn);
}

static void
interface_added(GDBusObjectManager *object_manager,
                GDBusObject *       object,
                GDBusInterface *    interface,
                gpointer            user_data)
{
    NMIwdManager *       self = user_data;
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    GDBusProxy *         proxy;
    const char *         iface_name;

    if (!priv->running)
        return;

    g_return_if_fail(G_IS_DBUS_PROXY(interface));

    proxy      = G_DBUS_PROXY(interface);
    iface_name = g_dbus_proxy_get_interface_name(proxy);

    if (nm_streq(iface_name, NM_IWD_DEVICE_INTERFACE)) {
        set_device_dbus_object(self, proxy, object);
        return;
    }

    if (nm_streq(iface_name, NM_IWD_KNOWN_NETWORK_INTERFACE)) {
        KnownNetworkId *      id;
        KnownNetworkId *      orig_id;
        KnownNetworkData *    data;
        NMIwdNetworkSecurity  security;
        const char *          type_str, *name;
        NMSettingsConnection *sett_conn = NULL;

        type_str = get_property_string_or_null(proxy, "Type");
        name     = get_property_string_or_null(proxy, "Name");
        if (!type_str || !name)
            return;

        if (nm_streq(type_str, "open"))
            security = NM_IWD_NETWORK_SECURITY_OPEN;
        else if (nm_streq(type_str, "psk"))
            security = NM_IWD_NETWORK_SECURITY_PSK;
        else if (nm_streq(type_str, "8021x"))
            security = NM_IWD_NETWORK_SECURITY_8021X;
        else
            return;

        id = known_network_id_new(name, security);

        if (g_hash_table_lookup_extended(priv->known_networks,
                                         id,
                                         (void **) &orig_id,
                                         (void **) &data)) {
            _LOGW("DBus error: KnownNetwork already exists ('%s', %s)", name, type_str);
            nm_g_object_ref_set(&data->known_network, proxy);
            g_free(id);
            id = orig_id;
        } else {
            data                = g_slice_new0(KnownNetworkData);
            data->known_network = g_object_ref(proxy);
            g_hash_table_insert(priv->known_networks, id, data);
        }

        sett_conn = mirror_connection(self, id, TRUE, proxy);

        if (sett_conn && sett_conn != data->mirror_connection) {
            NMSettingsConnection *sett_conn_old = data->mirror_connection;

            data->mirror_connection = nm_g_object_ref(sett_conn);
            mirror_connection_take_and_delete(sett_conn_old, data);

            g_signal_connect(sett_conn,
                             NM_SETTINGS_CONNECTION_UPDATED_INTERNAL,
                             G_CALLBACK(sett_conn_changed),
                             data);
        }

        return;
    }

    if (nm_streq(iface_name, NM_IWD_NETWORK_INTERFACE)) {
        NMDeviceIwd *device = get_device_from_network(self, proxy);

        if (device)
            nm_device_iwd_network_add_remove(device, proxy, TRUE);

        return;
    }
}

static void
interface_removed(GDBusObjectManager *object_manager,
                  GDBusObject *       object,
                  GDBusInterface *    interface,
                  gpointer            user_data)
{
    NMIwdManager *       self = user_data;
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    GDBusProxy *         proxy;
    const char *         iface_name;

    g_return_if_fail(G_IS_DBUS_PROXY(interface));

    proxy      = G_DBUS_PROXY(interface);
    iface_name = g_dbus_proxy_get_interface_name(proxy);

    if (nm_streq(iface_name, NM_IWD_DEVICE_INTERFACE)) {
        set_device_dbus_object(self, proxy, NULL);
        return;
    }

    if (nm_streq(iface_name, NM_IWD_KNOWN_NETWORK_INTERFACE)) {
        KnownNetworkId id;
        const char *   type_str;

        type_str = get_property_string_or_null(proxy, "Type");
        id.name  = get_property_string_or_null(proxy, "Name");
        if (!type_str || !id.name)
            return;

        if (nm_streq(type_str, "open"))
            id.security = NM_IWD_NETWORK_SECURITY_OPEN;
        else if (nm_streq(type_str, "psk"))
            id.security = NM_IWD_NETWORK_SECURITY_PSK;
        else if (nm_streq(type_str, "8021x"))
            id.security = NM_IWD_NETWORK_SECURITY_8021X;
        else
            return;

        g_hash_table_remove(priv->known_networks, &id);
        return;
    }

    if (nm_streq(iface_name, NM_IWD_NETWORK_INTERFACE)) {
        NMDeviceIwd *device = get_device_from_network(self, proxy);

        if (device)
            nm_device_iwd_network_add_remove(device, proxy, FALSE);

        return;
    }
}

static void
object_added(GDBusObjectManager *object_manager, GDBusObject *object, gpointer user_data)
{
    GList *interfaces, *iter;

    interfaces = g_dbus_object_get_interfaces(object);

    for (iter = interfaces; iter; iter = iter->next) {
        GDBusInterface *interface = G_DBUS_INTERFACE(iter->data);

        interface_added(NULL, object, interface, user_data);
    }

    g_list_free_full(interfaces, g_object_unref);
}

static void
object_removed(GDBusObjectManager *object_manager, GDBusObject *object, gpointer user_data)
{
    GList *interfaces, *iter;

    interfaces = g_dbus_object_get_interfaces(object);

    for (iter = interfaces; iter; iter = iter->next) {
        GDBusInterface *interface = G_DBUS_INTERFACE(iter->data);

        interface_removed(NULL, object, interface, user_data);
    }

    g_list_free_full(interfaces, g_object_unref);
}

static void
connection_removed(NMSettings *settings, NMSettingsConnection *sett_conn, gpointer user_data)
{
    NMIwdManager *        self = user_data;
    NMIwdManagerPrivate * priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    NMConnection *        conn = nm_settings_connection_get_connection(sett_conn);
    NMSettingWireless *   s_wireless;
    KnownNetworkData *    data;
    KnownNetworkId        id;
    char                  ssid_buf[33];
    const guint8 *        ssid_bytes;
    gsize                 ssid_len;
    NMSettingsConnection *new_mirror_conn;

    if (!nm_wifi_connection_get_iwd_ssid_and_security(conn, NULL, &id.security))
        return;

    s_wireless = nm_connection_get_setting_wireless(conn);
    if (!s_wireless)
        return;

    ssid_bytes = g_bytes_get_data(nm_setting_wireless_get_ssid(s_wireless), &ssid_len);
    if (!ssid_bytes || ssid_len > 32 || memchr(ssid_bytes, 0, ssid_len))
        return;

    memcpy(ssid_buf, ssid_bytes, ssid_len);
    ssid_buf[ssid_len] = '\0';
    id.name            = ssid_buf;
    data               = g_hash_table_lookup(priv->known_networks, &id);
    if (!data)
        return;

    if (data->mirror_connection != sett_conn)
        return;

    g_clear_object(&data->mirror_connection);

    /* Don't call Forget on the Known Network until there's no longer *any*
     * matching NMSettingsConnection (debatable)
     */
    new_mirror_conn = mirror_connection(self, &id, FALSE, NULL);
    if (new_mirror_conn) {
        data->mirror_connection = g_object_ref(new_mirror_conn);
        return;
    }

    if (!priv->running)
        return;

    g_dbus_proxy_call(data->known_network,
                      "Forget",
                      NULL,
                      G_DBUS_CALL_FLAGS_NONE,
                      -1,
                      NULL,
                      NULL,
                      NULL);
}

static gboolean
_om_has_name_owner(GDBusObjectManager *object_manager)
{
    gs_free char *name_owner = NULL;

    nm_assert(G_IS_DBUS_OBJECT_MANAGER_CLIENT(object_manager));

    name_owner =
        g_dbus_object_manager_client_get_name_owner(G_DBUS_OBJECT_MANAGER_CLIENT(object_manager));
    return !!name_owner;
}

static void
release_object_manager(NMIwdManager *self)
{
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);

    if (!priv->object_manager)
        return;

    g_signal_handlers_disconnect_by_data(priv->object_manager, self);

    if (priv->agent_id) {
        GDBusConnection *         agent_connection;
        GDBusObjectManagerClient *omc = G_DBUS_OBJECT_MANAGER_CLIENT(priv->object_manager);

        agent_connection = g_dbus_object_manager_client_get_connection(omc);

        /* We're is called when we're shutting down (i.e. our DBus connection
         * is being closed, and IWD will detect this) or IWD was stopped so
         * in either case calling UnregisterAgent will not do anything.
         */
        g_dbus_connection_unregister_object(agent_connection, priv->agent_id);
        priv->agent_id = 0;
        nm_clear_g_free(&priv->agent_path);
    }

    g_clear_object(&priv->object_manager);
}

static void prepare_object_manager(NMIwdManager *self);

static void
name_owner_changed(GObject *object, GParamSpec *pspec, gpointer user_data)
{
    NMIwdManager *       self           = user_data;
    NMIwdManagerPrivate *priv           = NM_IWD_MANAGER_GET_PRIVATE(self);
    GDBusObjectManager * object_manager = G_DBUS_OBJECT_MANAGER(object);

    nm_assert(object_manager == priv->object_manager);

    if (_om_has_name_owner(object_manager)) {
        release_object_manager(self);
        prepare_object_manager(self);
    } else {
        const CList *tmp_lst;
        NMDevice *   device;

        if (!priv->running)
            return;

        priv->running = false;

        nm_manager_for_each_device (priv->manager, device, tmp_lst) {
            if (NM_IS_DEVICE_IWD(device)) {
                nm_device_iwd_set_dbus_object(NM_DEVICE_IWD(device), NULL);
            }
        }
    }
}

static void
device_added(NMManager *manager, NMDevice *device, gpointer user_data)
{
    NMIwdManager *       self = user_data;
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    GList *              objects, *iter;

    if (!NM_IS_DEVICE_IWD(device))
        return;

    if (!priv->running)
        return;

    /* Here we handle a potential scenario where IWD's DBus objects for the
     * new device popped up before the NMDevice.  The
     * interface_added/object_added signals have been received already and
     * the handlers couldn't do much because the NMDevice wasn't there yet
     * so now we go over the Network and Device interfaces again.  In this
     * exact order for "object path" property consistency -- see reasoning
     * in object_compare_interfaces.
     */
    objects = g_dbus_object_manager_get_objects(priv->object_manager);

    for (iter = objects; iter; iter = iter->next) {
        GDBusObject *   object                    = G_DBUS_OBJECT(iter->data);
        gs_unref_object GDBusInterface *interface = NULL;

        interface = g_dbus_object_get_interface(object, NM_IWD_NETWORK_INTERFACE);
        if (!interface)
            continue;

        if (NM_DEVICE_IWD(device) == get_device_from_network(self, (GDBusProxy *) interface))
            nm_device_iwd_network_add_remove(NM_DEVICE_IWD(device), (GDBusProxy *) interface, TRUE);
    }

    for (iter = objects; iter; iter = iter->next) {
        GDBusObject *   object                    = G_DBUS_OBJECT(iter->data);
        gs_unref_object GDBusInterface *interface = NULL;
        const char *                    obj_ifname;

        interface  = g_dbus_object_get_interface(object, NM_IWD_DEVICE_INTERFACE);
        obj_ifname = get_property_string_or_null((GDBusProxy *) interface, "Name");

        if (!obj_ifname || strcmp(nm_device_get_iface(device), obj_ifname))
            continue;

        nm_device_iwd_set_dbus_object(NM_DEVICE_IWD(device), object);
        break;
    }

    g_list_free_full(objects, g_object_unref);
}

static void
device_removed(NMManager *manager, NMDevice *device, gpointer user_data)
{
    NMIwdManager *       self = user_data;
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);

    if (!NM_IS_DEVICE_IWD(device))
        return;

    if (priv->last_agent_call_device == NM_DEVICE_IWD(device))
        priv->last_agent_call_device = NULL;
}

/* This is used to sort the list of objects returned by GetManagedObjects()
 * based on the DBus interfaces available on these objects in such a way that
 * the interface_added calls happen in the right order.  The order is defined
 * by how some DBus interfaces point to interfaces on other objects using
 * DBus properties of the type "object path" ("o" signature).  This creates
 * "dependencies" between objects.
 *
 * When NM and IWD are running, the InterfacesAdded signals should come in
 * an order that ensures consistency of those object paths.  For example
 * when a Network interface is added with a KnownNetwork property, or that
 * property is assigned a new value, the KnownNetwork object pointed to by
 * it will have been added in an earlier InterfacesAdded signal.  Similarly
 * Station.ConnectedNetwork and Station.GetOrdereNetworks() only point to
 * existing Network objects.  (There may be circular dependencies but during
 * initialization we only need a subset of those properties that doesn't
 * have this problem.)
 *
 * But GetManagedObjects doesn't guarantee this kind of consistency so we
 * order the returned object list ourselves to simplify the job of
 * interface_added().  Objects that don't have any interfaces listed in
 * interface_order are moved to the end of the list.
 */
static int
object_compare_interfaces(gconstpointer a, gconstpointer b)
{
    static const char *interface_order[] = {
        NM_IWD_KNOWN_NETWORK_INTERFACE,
        NM_IWD_NETWORK_INTERFACE,
        NM_IWD_DEVICE_INTERFACE,
        NULL,
    };
    int   rank_a = G_N_ELEMENTS(interface_order);
    int   rank_b = G_N_ELEMENTS(interface_order);
    guint pos;

    for (pos = 0; interface_order[pos]; pos++) {
        GDBusInterface *iface_a;
        GDBusInterface *iface_b;

        if (rank_a == G_N_ELEMENTS(interface_order)
            && (iface_a = g_dbus_object_get_interface(G_DBUS_OBJECT(a), interface_order[pos]))) {
            rank_a = pos;
            g_object_unref(iface_a);
        }

        if (rank_b == G_N_ELEMENTS(interface_order)
            && (iface_b = g_dbus_object_get_interface(G_DBUS_OBJECT(b), interface_order[pos]))) {
            rank_b = pos;
            g_object_unref(iface_b);
        }
    }

    return rank_a - rank_b;
}

static void
got_object_manager(GObject *object, GAsyncResult *result, gpointer user_data)
{
    NMIwdManager *       self  = user_data;
    NMIwdManagerPrivate *priv  = NM_IWD_MANAGER_GET_PRIVATE(self);
    GError *             error = NULL;
    GDBusObjectManager * object_manager;
    GDBusConnection *    connection;

    object_manager = g_dbus_object_manager_client_new_for_bus_finish(result, &error);
    if (object_manager == NULL) {
        _LOGE("failed to acquire IWD Object Manager: Wi-Fi will not be available (%s)",
              error->message);
        g_clear_error(&error);
        return;
    }

    priv->object_manager = object_manager;

    g_signal_connect(priv->object_manager,
                     "notify::name-owner",
                     G_CALLBACK(name_owner_changed),
                     self);

    nm_assert(G_IS_DBUS_OBJECT_MANAGER_CLIENT(object_manager));

    connection =
        g_dbus_object_manager_client_get_connection(G_DBUS_OBJECT_MANAGER_CLIENT(object_manager));

    priv->agent_id = iwd_agent_export(connection, self, &priv->agent_path, &error);
    if (!priv->agent_id) {
        _LOGE("failed to export the IWD Agent: PSK/8021x Wi-Fi networks may not work: %s",
              error->message);
        g_clear_error(&error);
    }

    if (_om_has_name_owner(object_manager)) {
        GList *objects, *iter;

        priv->running = true;

        g_signal_connect(priv->object_manager,
                         "interface-added",
                         G_CALLBACK(interface_added),
                         self);
        g_signal_connect(priv->object_manager,
                         "interface-removed",
                         G_CALLBACK(interface_removed),
                         self);
        g_signal_connect(priv->object_manager, "object-added", G_CALLBACK(object_added), self);
        g_signal_connect(priv->object_manager, "object-removed", G_CALLBACK(object_removed), self);

        g_hash_table_remove_all(priv->known_networks);

        objects = g_dbus_object_manager_get_objects(object_manager);
        objects = g_list_sort(objects, object_compare_interfaces);
        for (iter = objects; iter; iter = iter->next)
            object_added(NULL, G_DBUS_OBJECT(iter->data), self);

        g_list_free_full(objects, g_object_unref);

        if (priv->agent_id)
            register_agent(self);
    }
}

static void
prepare_object_manager(NMIwdManager *self)
{
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);

    g_dbus_object_manager_client_new_for_bus(NM_IWD_BUS_TYPE,
                                             G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_NONE,
                                             NM_IWD_SERVICE,
                                             "/",
                                             NULL,
                                             NULL,
                                             NULL,
                                             priv->cancellable,
                                             got_object_manager,
                                             self);
}

gboolean
nm_iwd_manager_is_known_network(NMIwdManager *self, const char *name, NMIwdNetworkSecurity security)
{
    NMIwdManagerPrivate *priv  = NM_IWD_MANAGER_GET_PRIVATE(self);
    KnownNetworkId       kn_id = {name, security};

    return g_hash_table_contains(priv->known_networks, &kn_id);
}

NMSettingsConnection *
nm_iwd_manager_get_ap_mirror_connection(NMIwdManager *self, NMWifiAP *ap)
{
    NMIwdManagerPrivate *  priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    KnownNetworkData *     data;
    char                   name_buf[33];
    KnownNetworkId         kn_id = {name_buf, NM_IWD_NETWORK_SECURITY_OPEN};
    const guint8 *         ssid_bytes;
    gsize                  ssid_len;
    NM80211ApFlags         flags     = nm_wifi_ap_get_flags(ap);
    NM80211ApSecurityFlags sec_flags = nm_wifi_ap_get_wpa_flags(ap) | nm_wifi_ap_get_rsn_flags(ap);

    ssid_bytes = g_bytes_get_data(nm_wifi_ap_get_ssid(ap), &ssid_len);
    ssid_len   = MIN(ssid_len, 32);
    memcpy(name_buf, ssid_bytes, ssid_len);
    name_buf[ssid_len] = '\0';

    if (flags & NM_802_11_AP_FLAGS_PRIVACY)
        kn_id.security = NM_IWD_NETWORK_SECURITY_WEP;

    if (sec_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
        kn_id.security = NM_IWD_NETWORK_SECURITY_PSK;
    else if (sec_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
        kn_id.security = NM_IWD_NETWORK_SECURITY_8021X;

    /* Right now it's easier for us to do a name+security lookup than to use
     * the Network.KnownNetwork property to look up by path.
     */
    data = g_hash_table_lookup(priv->known_networks, &kn_id);
    if (data)
        return data->mirror_connection;

    /* We have no KnownNetwork for this AP, we're probably connecting to it for
     * the first time.  This is not a usual/supported scenario so we don't need
     * to bother too much about creating a great mirror connection, we don't
     * even have any more information than the Name & Type properties on the
     * Network interface.  This *should* never happen for an 8021x type network.
     */
    return mirror_connection(self, &kn_id, TRUE, NULL);
}

GDBusProxy *
nm_iwd_manager_get_dbus_interface(NMIwdManager *self, const char *path, const char *name)
{
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    GDBusInterface *     interface;

    if (!priv->object_manager)
        return NULL;

    interface = g_dbus_object_manager_get_interface(priv->object_manager, path, name);

    return interface ? G_DBUS_PROXY(interface) : NULL;
}

/*****************************************************************************/

NM_DEFINE_SINGLETON_GETTER(NMIwdManager, nm_iwd_manager_get, NM_TYPE_IWD_MANAGER);

static void
nm_iwd_manager_init(NMIwdManager *self)
{
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);

    priv->manager = g_object_ref(NM_MANAGER_GET);
    g_signal_connect(priv->manager, NM_MANAGER_DEVICE_ADDED, G_CALLBACK(device_added), self);
    g_signal_connect(priv->manager, NM_MANAGER_DEVICE_REMOVED, G_CALLBACK(device_removed), self);

    priv->settings = g_object_ref(NM_SETTINGS_GET);
    g_signal_connect(priv->settings,
                     NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,
                     G_CALLBACK(connection_removed),
                     self);

    priv->cancellable = g_cancellable_new();

    priv->known_networks = g_hash_table_new_full((GHashFunc) known_network_id_hash,
                                                 (GEqualFunc) known_network_id_equal,
                                                 g_free,
                                                 (GDestroyNotify) known_network_data_free);

    prepare_object_manager(self);
}

static void
dispose(GObject *object)
{
    NMIwdManager *       self = (NMIwdManager *) object;
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);

    release_object_manager(self);

    nm_clear_g_cancellable(&priv->cancellable);

    if (priv->settings) {
        g_signal_handlers_disconnect_by_data(priv->settings, self);
        g_clear_object(&priv->settings);
    }

    /* This may trigger mirror connection removals so it happens
     * after the g_signal_handlers_disconnect_by_data above.
     */
    nm_clear_pointer(&priv->known_networks, g_hash_table_destroy);

    if (priv->manager) {
        g_signal_handlers_disconnect_by_data(priv->manager, self);
        g_clear_object(&priv->manager);
    }

    priv->last_agent_call_device = NULL;

    G_OBJECT_CLASS(nm_iwd_manager_parent_class)->dispose(object);
}

static void
nm_iwd_manager_class_init(NMIwdManagerClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->dispose = dispose;
}
