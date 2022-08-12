/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Intel Corporation
 */

#include "src/core/nm-default-daemon.h"

#include "nm-iwd-manager.h"

#include <net/if.h>
#include <glib/gstdio.h>
#include <errno.h>
#include <sys/stat.h>

#include "libnm-core-intern/nm-core-internal.h"
#include "nm-manager.h"
#include "nm-device-iwd.h"
#include "nm-device-iwd-p2p.h"
#include "nm-wifi-utils.h"
#include "libnm-glib-aux/nm-uuid.h"
#include "libnm-glib-aux/nm-random-utils.h"
#include "libnm-glib-aux/nm-io-utils.h"
#include "settings/nm-settings.h"
#include "libnm-std-aux/nm-dbus-compat.h"
#include "nm-config.h"

/*****************************************************************************/

enum {
    P2P_DEVICE_ADDED,

    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL];

typedef struct {
    const char          *name;
    NMIwdNetworkSecurity security;
    char                 buf[0];
} KnownNetworkId;

typedef struct {
    GDBusProxy           *known_network;
    NMSettingsConnection *mirror_connection;
    const KnownNetworkId *id;
} KnownNetworkData;

typedef struct {
    GBytes *ssid;
    gint64  timestamp;
} RecentlyMirroredData;

typedef struct {
    NMManager          *manager;
    NMSettings         *settings;
    GCancellable       *cancellable;
    gboolean            running;
    GDBusObjectManager *object_manager;
    guint               agent_id;
    guint               netconfig_agent_id;
    GHashTable         *known_networks;
    NMDeviceIwd        *last_agent_call_device;
    char               *last_state_dir;
    char               *warned_state_dir;
    bool                netconfig_enabled;
    GHashTable         *p2p_devices;
    NMIwdWfdInfo        wfd_info;
    guint               wfd_use_count;
    GSList             *recently_mirrored;
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
                                              KnownNetworkData     *data);

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
    NMIwdManagerPrivate            *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    const char                     *ifname;
    const char                     *device_path;
    NMDevice                       *device;
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
agent_dbus_method_cb(GDBusConnection       *connection,
                     const char            *sender,
                     const char            *object_path,
                     const char            *interface_name,
                     const char            *method_name,
                     GVariant              *parameters,
                     GDBusMethodInvocation *invocation,
                     gpointer               user_data)
{
    NMIwdManager                   *self = user_data;
    NMIwdManagerPrivate            *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    const char                     *network_path;
    NMDeviceIwd                    *device;
    gs_free char                   *name_owner = NULL;
    gs_unref_object GDBusInterface *network    = NULL;

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

static void
netconfig_agent_dbus_method_cb(GDBusConnection       *connection,
                               const char            *sender,
                               const char            *object_path,
                               const char            *interface_name,
                               const char            *method_name,
                               GVariant              *parameters,
                               GDBusMethodInvocation *invocation,
                               gpointer               user_data)
{
    NMIwdManager                           *self       = user_data;
    NMIwdManagerPrivate                    *priv       = NM_IWD_MANAGER_GET_PRIVATE(self);
    gs_free char                           *name_owner = NULL;
    const char                             *device_path;
    gs_unref_object GDBusInterface         *device_obj = NULL;
    NMDevice                               *device;
    nm_auto_free_variant_iter GVariantIter *config_iter = NULL;
    const char                             *ifname;
    int                                     addr_family;

    /* Be paranoid and check the sender address */
    name_owner = g_dbus_object_manager_client_get_name_owner(
        G_DBUS_OBJECT_MANAGER_CLIENT(priv->object_manager));
    if (!nm_streq0(name_owner, sender))
        goto return_error;

    if (nm_streq(method_name, "ConfigureIPv4"))
        addr_family = AF_INET;
    else if (nm_streq(method_name, "ConfigureIPv6"))
        addr_family = AF_INET6;
    else
        goto return_error;

    g_variant_get(parameters, "(&oa{sv})", &device_path, &config_iter);

    device_obj = g_dbus_object_manager_get_interface(priv->object_manager,
                                                     device_path,
                                                     NM_IWD_DEVICE_INTERFACE);
    if (!device_obj) {
        _LOGE("netconfig-agent-request: unable to find the device object");
        goto return_error;
    }

    ifname = get_property_string_or_null(G_DBUS_PROXY(device_obj), "Name");
    if (!ifname) {
        _LOGD("Name not cached for device at %s", device_path);
        goto return_error;
    }

    device = nm_manager_get_device(priv->manager, ifname, NM_DEVICE_TYPE_WIFI);
    if (!device || !NM_IS_DEVICE_IWD(device)) {
        _LOGD("NM device %s is not an IWD-managed device", ifname);
        goto return_error;
    }

    if (nm_device_iwd_set_netconfig(NM_DEVICE_IWD(device), addr_family, config_iter)) {
        g_dbus_method_invocation_return_value(invocation, g_variant_new("()"));
        return;
    }

    _LOGD("netconfig-agent-request: device %s did not handle the IWD Netconfig Agent request",
          ifname);

return_error:
    /* IWD doesn't look at the specific error */
    g_dbus_method_invocation_return_error_literal(invocation,
                                                  NM_DEVICE_ERROR,
                                                  NM_DEVICE_ERROR_INVALID_CONNECTION,
                                                  "Couldn't set netconfig data");
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

static const GDBusInterfaceInfo iwd_netconfig_agent_iface_info =
    NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        "net.connman.iwd.NetworkConfigurationAgent",
        .methods = NM_DEFINE_GDBUS_METHOD_INFOS(
            NM_DEFINE_GDBUS_METHOD_INFO("ConfigureIPv4",
                                        .in_args = NM_DEFINE_GDBUS_ARG_INFOS(
                                            NM_DEFINE_GDBUS_ARG_INFO("device", "o"),
                                            NM_DEFINE_GDBUS_ARG_INFO("config", "a{sv}"), ), ),
            NM_DEFINE_GDBUS_METHOD_INFO("ConfigureIPv6",
                                        .in_args = NM_DEFINE_GDBUS_ARG_INFOS(
                                            NM_DEFINE_GDBUS_ARG_INFO("device", "o"),
                                            NM_DEFINE_GDBUS_ARG_INFO("config", "a{sv}"), ), ), ), );

static guint
iwd_agent_export(GDBusConnection *connection, gpointer user_data, GError **error)
{
    static const GDBusInterfaceVTable vtable = {
        .method_call = agent_dbus_method_cb,
    };

    return g_dbus_connection_register_object(
        connection,
        NM_IWD_AGENT_PATH,
        NM_UNCONST_PTR(GDBusInterfaceInfo, &iwd_agent_iface_info),
        &vtable,
        user_data,
        NULL,
        error);
}

static guint
iwd_netconfig_agent_export(GDBusConnection *connection, gpointer user_data, GError **error)
{
    static const GDBusInterfaceVTable vtable = {
        .method_call = netconfig_agent_dbus_method_cb,
    };

    return g_dbus_connection_register_object(
        connection,
        NM_IWD_AGENT_PATH,
        NM_UNCONST_PTR(GDBusInterfaceInfo, &iwd_netconfig_agent_iface_info),
        &vtable,
        user_data,
        NULL,
        error);
}

static void
register_agent(NMIwdManager *self, const char *method)
{
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    GDBusInterface      *agent_manager;

    agent_manager = g_dbus_object_manager_get_interface(priv->object_manager,
                                                        "/net/connman/iwd", /* IWD 1.0+ */
                                                        NM_IWD_AGENT_MANAGER_INTERFACE);
    if (!agent_manager) {
        _LOGE("unable to register the IWD Agent");
        return;
    }

    /* Register our agent */
    g_dbus_proxy_call(G_DBUS_PROXY(agent_manager),
                      method,
                      g_variant_new("(o)", NM_IWD_AGENT_PATH),
                      G_DBUS_CALL_FLAGS_NONE,
                      -1,
                      NULL,
                      NULL,
                      NULL);

    g_object_unref(agent_manager);
}

/*****************************************************************************/

static void
recently_mirrored_data_free(void *data)
{
    RecentlyMirroredData *rmd = data;

    g_bytes_unref(rmd->ssid);
    g_free(rmd);
}

/* When we mirror an 802.1x connection to an IWD config file, and there's an
 * AP in range with matching SSID, that connection should become available
 * for activation.  In IWD terms when an 802.1x network becomes a Known
 * Network, it can be connected to using the .Connect D-Bus method.
 *
 * However there's a delay between writing the IWD config file and receiving
 * the InterfaceAdded event for the Known Network so we don't immediately
 * find out that the network can now be used.  If an NM client creates a
 * new connection for an 802.1x AP and tries to activate it immediately,
 * NMDeviceIWD will not allow it to because it doesn't know the network is
 * known yet.  To work around this, we save the SSIDs of 802.1x connections
 * we recently mirrored to IWD config files, for 2 seconds, and we treat
 * them as Known Networks in that period since in theory activations should
 * succeed.
 */
bool
nm_iwd_manager_is_recently_mirrored(NMIwdManager *self, const GBytes *ssid)
{
    NMIwdManagerPrivate  *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    gint64                now  = nm_utils_get_monotonic_timestamp_nsec();
    GSList               *iter;
    RecentlyMirroredData *rmd;

    /* Drop entries older than 2 seconds */
    while (priv->recently_mirrored) {
        rmd = priv->recently_mirrored->data;
        if (now < rmd->timestamp + 2000000000)
            break;

        priv->recently_mirrored = g_slist_remove(priv->recently_mirrored, rmd);
        recently_mirrored_data_free(rmd);
    }

    for (iter = priv->recently_mirrored; iter; iter = iter->next) {
        rmd = iter->data;
        if (g_bytes_equal(ssid, rmd->ssid))
            return TRUE;
    }

    return FALSE;
}

static void
save_mirrored(NMIwdManager *self, GBytes *ssid)
{
    NMIwdManagerPrivate  *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    RecentlyMirroredData *rmd  = g_malloc(sizeof(RecentlyMirroredData));

    rmd->ssid               = g_bytes_ref(ssid);
    rmd->timestamp          = nm_utils_get_monotonic_timestamp_nsec();
    priv->recently_mirrored = g_slist_append(priv->recently_mirrored, rmd);
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
    const char          *ifname;
    int                  ifindex;
    NMDevice            *device;
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
add_p2p_device(NMIwdManager *self, GDBusProxy *proxy, GDBusObject *object)
{
    NMIwdManagerPrivate            *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    const char                     *path = g_dbus_object_get_object_path(object);
    NMDeviceIwdP2P                 *p2p;
    gs_unref_object GDBusInterface *wiphy = NULL;
    const char                     *phy_name;

    if (g_hash_table_contains(priv->p2p_devices, path))
        return;

    wiphy = g_dbus_object_get_interface(object, NM_IWD_WIPHY_INTERFACE);
    if (!wiphy)
        return;

    phy_name = get_property_string_or_null(G_DBUS_PROXY(wiphy), "Name");
    if (!phy_name) {
        _LOGE("Name not cached for phy at %s", path);
        return;
    }

    p2p = nm_device_iwd_p2p_new(object);
    if (!p2p) {
        _LOGE("Can't create NMDeviceIwdP2P for phy at %s", path);
        return;
    }

    g_hash_table_insert(priv->p2p_devices, g_strdup(path), p2p);
    g_signal_emit(self, signals[P2P_DEVICE_ADDED], 0, p2p, phy_name);

    /* There should be no peer objects before the device object appeared so don't
     * try to look for them and notify the new device.  */
}

static void
remove_p2p_device(NMIwdManager *self, GDBusProxy *proxy, GDBusObject *object)
{
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    const char          *path = g_dbus_object_get_object_path(object);
    NMDeviceIwdP2P      *p2p  = g_hash_table_lookup(priv->p2p_devices, path);

    if (!p2p)
        return;

    g_hash_table_remove(priv->p2p_devices, path);
}

static NMDeviceIwdP2P *
get_p2p_device_from_peer(NMIwdManager *self, GDBusProxy *proxy)
{
    NMIwdManagerPrivate *priv        = NM_IWD_MANAGER_GET_PRIVATE(self);
    const char          *device_path = get_property_string_or_null(proxy, "Device");

    if (!device_path)
        return NULL;

    return g_hash_table_lookup(priv->p2p_devices, device_path);
}

static void
known_network_update_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    gs_unref_variant GVariant *variant = NULL;
    gs_free_error GError      *error   = NULL;

    variant = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &error);
    if (!variant) {
        nm_log_warn(LOGD_WIFI,
                    "iwd: updating %s on IWD known network %s failed: %s",
                    (const char *) user_data,
                    g_dbus_proxy_get_object_path(G_DBUS_PROXY(source)),
                    error->message);
    }
}

static gboolean
iwd_config_write(GKeyFile              *config,
                 const char            *filepath,
                 const struct timespec *mtime,
                 GError               **error)
{
    gsize           length;
    gs_free char   *data     = g_key_file_to_data(config, &length, NULL);
    struct timespec times[2] = {{.tv_nsec = UTIME_OMIT}, *mtime};

    /* Atomically write or replace the file with the right permission bits
     * and timestamps set.  We rely on the temporary file created by
     * nm_utils_file_set_contents having only upper-case letters and digits
     * in the last few filename characters -- it cannot end in .open, .psk
     * or .8021x.
     */
    return nm_utils_file_set_contents(filepath, data, length, 0600, times, NULL, error);
}

static const char *
get_config_path(NMIwdManager *self)
{
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    const char          *path;

    path = nm_config_data_get_iwd_config_path(NM_CONFIG_GET_DATA);
    if (path && path[0] == '\0') {
        nm_clear_g_free(&priv->warned_state_dir);
        return NULL;
    }

    if (!path || nm_streq(path, "auto")) {
        path = priv->last_state_dir;
        if (!path) {
            nm_clear_g_free(&priv->warned_state_dir);
            return NULL;
        }
    }

    if (priv->warned_state_dir && !nm_streq(priv->warned_state_dir, path))
        nm_clear_g_free(&priv->warned_state_dir);

    if (path && (path[0] != '/' || !g_file_test(path, G_FILE_TEST_IS_DIR))) {
        if (!priv->warned_state_dir) {
            priv->warned_state_dir = g_strdup(path);
            _LOGW("IWD StateDirectory '%s' not accessible", priv->warned_state_dir);
        }
        return NULL;
    }

    return path;
}

static void
sett_conn_changed(NMSettingsConnection   *sett_conn,
                  guint                   update_reason,
                  const KnownNetworkData *data)
{
    NMSettingsConnectionIntFlags    flags;
    NMConnection                   *conn       = nm_settings_connection_get_connection(sett_conn);
    NMSettingConnection            *s_conn     = nm_connection_get_setting_connection(conn);
    NMSettingWireless              *s_wifi     = nm_connection_get_setting_wireless(conn);
    nm_auto_unref_keyfile GKeyFile *iwd_config = NULL;
    const char                     *iwd_dir;
    gs_free char                   *filename  = NULL;
    gs_free char                   *full_path = NULL;
    gs_free_error GError           *error     = NULL;
    NMIwdNetworkSecurity            security;
    GBytes                         *ssid;
    const guint8                   *ssid_data;
    gsize                           ssid_len;
    gboolean                        removed;
    GStatBuf                        statbuf;
    gboolean                        have_mtime;

    nm_assert(sett_conn == data->mirror_connection);

    if (!NM_FLAGS_ANY(update_reason,
                      NM_SETTINGS_CONNECTION_UPDATE_REASON_UPDATE_NON_SECRET
                          | NM_SETTINGS_CONNECTION_UPDATE_REASON_CLEAR_SYSTEM_SECRETS
                          | NM_SETTINGS_CONNECTION_UPDATE_REASON_RESET_SYSTEM_SECRETS))
        return;

    /* If this is a generated connection it may be ourselves updating it */
    flags = nm_settings_connection_get_flags(data->mirror_connection);
    if (NM_FLAGS_HAS(flags, NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED))
        return;

    iwd_dir = get_config_path(nm_iwd_manager_get());
    if (!iwd_dir) {
        gboolean nm_autoconnectable  = nm_setting_connection_get_autoconnect(s_conn);
        gboolean iwd_autoconnectable = get_property_bool(data->known_network, "AutoConnect", TRUE);

        if (iwd_autoconnectable != nm_autoconnectable) {
            nm_log_dbg(LOGD_WIFI,
                       "iwd: updating AutoConnect on known network at %s based on connection %s",
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

        return;
    }

    /* If the SSID and the security type in the NMSettingsConnection haven't
     * changed, we just need to overwrite the original IWD config file.
     * Otherwise we need to call Forget on the original KnownNetwork or
     * remove its file.  IWD will have to delete one D-Bus object and
     * create another anyway because the SSID and security type are in the
     * D-Bus object path, so no point renaming the file.
     */
    ssid       = nm_setting_wireless_get_ssid(s_wifi);
    ssid_data  = ssid ? g_bytes_get_data(ssid, &ssid_len) : NULL;
    removed    = FALSE;
    have_mtime = FALSE;

    if (!nm_wifi_connection_get_iwd_ssid_and_security(conn, NULL, &security)
        || security != data->id->security || !ssid_data || ssid_len != strlen(data->id->name)
        || memcmp(ssid_data, data->id->name, ssid_len)) {
        gs_free char *orig_filename =
            nm_wifi_utils_get_iwd_config_filename(data->id->name, -1, data->id->security);
        gs_free char *orig_full_path = g_strdup_printf("%s/%s", iwd_dir, orig_filename);

        if (g_stat(orig_full_path, &statbuf) == 0)
            have_mtime = TRUE;

        if (g_remove(orig_full_path) == 0)
            nm_log_dbg(LOGD_WIFI, "iwd: profile at %s removed", orig_full_path);
        else if (errno != ENOENT)
            nm_log_dbg(LOGD_WIFI,
                       "iwd: profile at %s not removed: %s (%i)",
                       orig_full_path,
                       strerror(errno),
                       errno);

        removed = TRUE;
    }

    if (!nm_streq(nm_settings_connection_get_connection_type(sett_conn), "802-11-wireless")
        || !s_wifi)
        return;

    /* If the connection has any permissions other than the default we don't
     * want to save it as an IWD profile.  IWD will make it available for
     * everybody to attempt a connection, remove, or toggle "autoconnectable".
     */
    if (s_conn && nm_setting_connection_get_num_permissions(s_conn)) {
        nm_log_dbg(
            LOGD_WIFI,
            "iwd: changed Wi-Fi connection %s not mirrored as IWD profile because of non-default "
            "permissions",
            nm_settings_connection_get_id(sett_conn));
        return;
    }

    iwd_config = nm_wifi_utils_connection_to_iwd_config(conn, &filename, &error);
    if (!iwd_config) {
        /* The error message here is not translated and it only goes in
         * the logs.
         */
        nm_log_dbg(LOGD_WIFI,
                   "iwd: changed Wi-Fi connection %s not mirrored as IWD profile: %s",
                   nm_settings_connection_get_id(sett_conn),
                   error->message);
        return;
    }

    full_path = g_strdup_printf("%s/%s", iwd_dir, filename);
    if (removed && g_file_test(full_path, G_FILE_TEST_EXISTS)) {
        nm_log_dbg(LOGD_WIFI,
                   "iwd: changed Wi-Fi connection %s not mirrored as IWD profile because %s "
                   "already exists",
                   nm_settings_connection_get_id(sett_conn),
                   full_path);
        return;
    }

    if (!removed && g_stat(full_path, &statbuf) == 0)
        have_mtime = TRUE;

    /* If modifying an existing network try to preserve the file mtime,
     * otherwise use a small non-zero timespec value to signal that the
     * network is autoconnectable (according to its AutoConnect value)
     * but hasn't recently been connected to and thus shouldn't be
     * prioritized by autoconnect.
     */
    if (!have_mtime) {
        statbuf.st_mtim.tv_sec  = 1;
        statbuf.st_mtim.tv_nsec = 0;
    }

    if (!iwd_config_write(iwd_config, full_path, &statbuf.st_mtim, &error)) {
        nm_log_dbg(LOGD_WIFI,
                   "iwd: changed Wi-Fi connection %s not mirrored as IWD profile: save error: %s",
                   nm_settings_connection_get_id(sett_conn),
                   error->message);
        return;
    }

    nm_log_dbg(LOGD_WIFI,
               "iwd: changed Wi-Fi connection %s mirrored as IWD profile %s",
               nm_settings_connection_get_id(sett_conn),
               full_path);

    if (security == NM_IWD_NETWORK_SECURITY_8021X)
        save_mirrored(nm_iwd_manager_get(), ssid);
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
mirror_connection(NMIwdManager         *self,
                  const KnownNetworkId *id,
                  gboolean              create_new,
                  GDBusProxy           *known_network)
{
    NMIwdManagerPrivate          *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    NMSettingsConnection *const  *iter;
    gs_unref_object NMConnection *connection          = NULL;
    NMSettingsConnection         *settings_connection = NULL;
    char                          uuid[37];
    NMSetting                    *setting;
    gs_free_error GError         *error           = NULL;
    gs_unref_bytes GBytes        *new_ssid        = NULL;
    gsize                         ssid_len        = strlen(id->name);
    gboolean                      autoconnectable = TRUE;
    gboolean                      hidden          = FALSE;
    gboolean                      exact_match     = TRUE;
    const char                   *key_mgmt        = NULL;

    if (known_network) {
        autoconnectable = get_property_bool(known_network, "AutoConnect", TRUE);
        hidden          = get_property_bool(known_network, "Hidden", FALSE);
    }

    for (iter = nm_settings_get_connections(priv->settings, NULL); *iter; iter++) {
        NMSettingsConnection *sett_conn = *iter;
        NMConnection         *conn      = nm_settings_connection_get_connection(sett_conn);
        NMIwdNetworkSecurity  security;
        NMSettingWireless    *s_wifi;
        const guint8         *ssid_bytes;
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
            NMSettingWireless   *s_wifi = nm_connection_get_setting_wireless(tmp_conn);

            g_object_set(G_OBJECT(s_conn),
                         NM_SETTING_CONNECTION_AUTOCONNECT,
                         autoconnectable,
                         NULL);
            g_object_set(G_OBJECT(s_wifi), NM_SETTING_WIRELESS_HIDDEN, hidden, NULL);
        } else {
            KnownNetworkData data = {known_network, settings_connection, id};
            sett_conn_changed(settings_connection,
                              NM_SETTINGS_CONNECTION_UPDATE_REASON_UPDATE_NON_SECRET,
                              &data);
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
                           nm_uuid_generate_random_str_arr(uuid),
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
            NULL,
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
                GDBusObject        *object,
                GDBusInterface     *interface,
                gpointer            user_data)
{
    NMIwdManager        *self = user_data;
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    GDBusProxy          *proxy;
    const char          *iface_name;

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
        KnownNetworkId       *id;
        KnownNetworkId       *orig_id;
        KnownNetworkData     *data;
        NMIwdNetworkSecurity  security;
        const char           *type_str, *name;
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
            data->id            = id;
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

    if (nm_streq(iface_name, NM_IWD_P2P_INTERFACE)) {
        add_p2p_device(self, proxy, object);
        return;
    }

    if (nm_streq(iface_name, NM_IWD_P2P_PEER_INTERFACE)) {
        NMDeviceIwdP2P *p2p = get_p2p_device_from_peer(self, proxy);

        /* This is more conveniently done with a direct call than a signal because
         * this way we only notify the interested NMDeviceIwdP2P.  */
        if (p2p)
            nm_device_iwd_p2p_peer_add_remove(p2p, object, TRUE);

        return;
    }
}

static void
interface_removed(GDBusObjectManager *object_manager,
                  GDBusObject        *object,
                  GDBusInterface     *interface,
                  gpointer            user_data)
{
    NMIwdManager        *self = user_data;
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    GDBusProxy          *proxy;
    const char          *iface_name;

    g_return_if_fail(G_IS_DBUS_PROXY(interface));

    proxy      = G_DBUS_PROXY(interface);
    iface_name = g_dbus_proxy_get_interface_name(proxy);

    if (nm_streq(iface_name, NM_IWD_DEVICE_INTERFACE)) {
        set_device_dbus_object(self, proxy, NULL);
        return;
    }

    if (nm_streq(iface_name, NM_IWD_KNOWN_NETWORK_INTERFACE)) {
        KnownNetworkId id;
        const char    *type_str;

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

    if (nm_streq(iface_name, NM_IWD_P2P_INTERFACE)) {
        remove_p2p_device(self, proxy, object);
        return;
    }

    if (nm_streq(iface_name, NM_IWD_P2P_PEER_INTERFACE)) {
        NMDeviceIwdP2P *p2p = get_p2p_device_from_peer(self, proxy);

        if (p2p)
            nm_device_iwd_p2p_peer_add_remove(p2p, object, FALSE);

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
    NMIwdManager         *self = user_data;
    NMIwdManagerPrivate  *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    NMConnection         *conn = nm_settings_connection_get_connection(sett_conn);
    NMSettingWireless    *s_wireless;
    KnownNetworkData     *data;
    KnownNetworkId        id;
    char                  ssid_buf[33];
    const guint8         *ssid_bytes;
    gsize                 ssid_len;
    NMSettingsConnection *new_mirror_conn;
    const char           *iwd_dir;
    gs_free char         *filename  = NULL;
    gs_free char         *full_path = NULL;

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
    if (!data) {
        if (!g_utf8_validate((const char *) ssid_bytes, ssid_len, NULL))
            return;

        goto try_delete_file;
    }

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
        goto try_delete_file;

    g_dbus_proxy_call(data->known_network,
                      "Forget",
                      NULL,
                      G_DBUS_CALL_FLAGS_NONE,
                      -1,
                      NULL,
                      NULL,
                      NULL);
    return;

try_delete_file:
    if (mirror_connection(self, &id, FALSE, NULL))
        return;

    iwd_dir = get_config_path(self);
    if (!iwd_dir)
        return;

    filename  = nm_wifi_utils_get_iwd_config_filename(id.name, ssid_len, id.security);
    full_path = g_strdup_printf("%s/%s", iwd_dir, filename);
    if (g_remove(full_path) == 0)
        _LOGD("IWD profile at %s removed", full_path);
    else if (errno != ENOENT)
        _LOGD("IWD profile at %s not removed: %s (%i)", full_path, strerror(errno), errno);
}

static void
connection_added(NMSettings *settings, NMSettingsConnection *sett_conn, gpointer user_data)
{
    NMIwdManager                   *self   = user_data;
    NMConnection                   *conn   = nm_settings_connection_get_connection(sett_conn);
    NMSettingConnection            *s_conn = nm_connection_get_setting_connection(conn);
    const char                     *iwd_dir;
    gs_free char                   *filename   = NULL;
    gs_free char                   *full_path  = NULL;
    gs_free_error GError           *error      = NULL;
    nm_auto_unref_keyfile GKeyFile *iwd_config = NULL;
    NMSettingsConnectionIntFlags    flags;
    NMIwdNetworkSecurity            security;

    if (!nm_streq(nm_settings_connection_get_connection_type(sett_conn), "802-11-wireless"))
        return;

    iwd_dir = get_config_path(self);
    if (!iwd_dir)
        return;

    /* If this is a generated connection it may be ourselves creating it and
     * directly assigning it to a KnownNetwork's .mirror_connection.
     */
    flags = nm_settings_connection_get_flags(sett_conn);
    if (NM_FLAGS_HAS(flags, NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED))
        return;

    /* If the connection has any permissions other than the default we don't
     * want to save it as an IWD profile.  IWD will make it available for
     * everybody to attempt a connection, remove, or toggle "autoconnectable".
     */
    if (s_conn && nm_setting_connection_get_num_permissions(s_conn)) {
        _LOGD("New Wi-Fi connection %s not mirrored as IWD profile because of non-default "
              "permissions",
              nm_settings_connection_get_id(sett_conn));
        return;
    }

    iwd_config = nm_wifi_utils_connection_to_iwd_config(conn, &filename, &error);
    if (!iwd_config) {
        /* The error message here is not translated and it only goes in
         * the logs.
         */
        _LOGD("New Wi-Fi connection %s not mirrored as IWD profile: %s",
              nm_settings_connection_get_id(sett_conn),
              error->message);
        return;
    }

    full_path = g_strdup_printf("%s/%s", iwd_dir, filename);
    if (g_file_test(full_path, G_FILE_TEST_EXISTS)) {
        _LOGD("New Wi-Fi connection %s not mirrored as IWD profile because %s already exists",
              nm_settings_connection_get_id(sett_conn),
              full_path);
        return;
    }

    if (!g_key_file_save_to_file(iwd_config, full_path, &error)) {
        _LOGD("New Wi-Fi connection %s not mirrored as IWD profile: save error: %s",
              nm_settings_connection_get_id(sett_conn),
              error->message);
        return;
    }

    _LOGD("New Wi-Fi connection %s mirrored as IWD profile %s",
          nm_settings_connection_get_id(sett_conn),
          full_path);

    if (nm_wifi_connection_get_iwd_ssid_and_security(conn, NULL, &security)
        && security == NM_IWD_NETWORK_SECURITY_8021X) {
        NMSettingWireless *s_wifi = nm_connection_get_setting_wireless(conn);
        save_mirrored(nm_iwd_manager_get(), nm_setting_wireless_get_ssid(s_wifi));
    }
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
    NMIwdManagerPrivate      *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    GDBusConnection          *agent_connection;
    GDBusObjectManagerClient *omc;

    if (!priv->object_manager)
        return;

    g_signal_handlers_disconnect_by_data(priv->object_manager, self);

    omc              = G_DBUS_OBJECT_MANAGER_CLIENT(priv->object_manager);
    agent_connection = g_dbus_object_manager_client_get_connection(omc);

    /* We're called when we're shutting down (i.e. our DBus connection
     * is being closed, and IWD will detect this) or IWD was stopped so
     * in either case calling UnregisterAgent will not do anything.
     * Just unregister the agent interfaces.  The agents are on the same
     * object (same path) but it seems g_dbus_connection_unregister_object()
     * should be called for each interface on the object separately.
     */
    if (priv->agent_id) {
        g_dbus_connection_unregister_object(agent_connection, priv->agent_id);
        priv->agent_id = 0;
    }

    if (priv->netconfig_agent_id) {
        g_dbus_connection_unregister_object(agent_connection, priv->netconfig_agent_id);
        priv->netconfig_agent_id = 0;
    }

    g_clear_object(&priv->object_manager);
}

static void prepare_object_manager(NMIwdManager *self);

static void
name_owner_changed(GObject *object, GParamSpec *pspec, gpointer user_data)
{
    NMIwdManager        *self           = user_data;
    NMIwdManagerPrivate *priv           = NM_IWD_MANAGER_GET_PRIVATE(self);
    GDBusObjectManager  *object_manager = G_DBUS_OBJECT_MANAGER(object);

    nm_assert(object_manager == priv->object_manager);

    if (_om_has_name_owner(object_manager)) {
        release_object_manager(self);
        prepare_object_manager(self);
    } else {
        const CList *tmp_lst;
        NMDevice    *device;

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
    NMIwdManager        *self = user_data;
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    GList               *objects, *iter;

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
        GDBusObject                    *object    = G_DBUS_OBJECT(iter->data);
        gs_unref_object GDBusInterface *interface = NULL;

        interface = g_dbus_object_get_interface(object, NM_IWD_NETWORK_INTERFACE);
        if (!interface)
            continue;

        if (NM_DEVICE_IWD(device) == get_device_from_network(self, (GDBusProxy *) interface))
            nm_device_iwd_network_add_remove(NM_DEVICE_IWD(device), (GDBusProxy *) interface, TRUE);
    }

    for (iter = objects; iter; iter = iter->next) {
        GDBusObject                    *object    = G_DBUS_OBJECT(iter->data);
        gs_unref_object GDBusInterface *interface = NULL;
        const char                     *obj_ifname;

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
    NMIwdManager        *self = user_data;
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
    static const char *const interface_order[] = {
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
get_daemon_info_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    NMIwdManager              *self = user_data;
    NMIwdManagerPrivate       *priv;
    gs_unref_variant GVariant *properties = NULL;
    gs_free_error GError      *error      = NULL;
    GVariantIter              *properties_iter;
    const char                *key;
    GVariant                  *value;

    properties = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &error);
    if (!properties) {
        if (nm_utils_error_is_cancelled(error))
            return;

        nm_log_warn(LOGD_WIFI, "iwd: Daemon.GetInfo() failed: %s", error->message);
        return;
    }

    priv = NM_IWD_MANAGER_GET_PRIVATE(self);

    if (!g_variant_is_of_type(properties, G_VARIANT_TYPE("(a{sv})"))) {
        _LOGE("Daemon.GetInfo returned type %s instead of (a{sv})",
              g_variant_get_type_string(properties));
        return;
    }

    g_variant_get(properties, "(a{sv})", &properties_iter);

    while (g_variant_iter_next(properties_iter, "{&sv}", &key, &value)) {
        if (nm_streq(key, "StateDirectory")) {
            if (!g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
                _LOGE("Daemon.GetInfo property %s is typed '%s' instead of 's'",
                      key,
                      g_variant_get_type_string(value));
                goto next;
            }

            nm_clear_g_free(&priv->last_state_dir);
            priv->last_state_dir = g_variant_dup_string(value, NULL);
        } else if (nm_streq(key, "NetworkConfigurationEnabled")) {
            if (!g_variant_is_of_type(value, G_VARIANT_TYPE_BOOLEAN)) {
                _LOGE("Daemon.GetInfo property %s is typed '%s' instead of 'b'",
                      key,
                      g_variant_get_type_string(value));
                goto next;
            }

            priv->netconfig_enabled = g_variant_get_boolean(value);
        }

next:
        g_variant_unref(value);
    }

    g_variant_iter_free(properties_iter);

    /* Register the netconfig agent only once we know netconfig is enabled */
    if (nm_iwd_manager_get_netconfig_enabled(self) && priv->netconfig_agent_id)
        register_agent(self, "RegisterNetworkConfigurationAgent");
}

static void
got_object_manager(GObject *object, GAsyncResult *result, gpointer user_data)
{
    NMIwdManager        *self  = user_data;
    NMIwdManagerPrivate *priv  = NM_IWD_MANAGER_GET_PRIVATE(self);
    GError              *error = NULL;
    GDBusObjectManager  *object_manager;
    GDBusConnection     *connection;

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

    priv->agent_id = iwd_agent_export(connection, self, &error);
    if (!priv->agent_id) {
        _LOGE("failed to export the IWD Agent: PSK/8021x Wi-Fi networks may not work: %s",
              error->message);
        g_clear_error(&error);
    }

    priv->netconfig_agent_id = iwd_netconfig_agent_export(connection, self, &error);
    if (!priv->netconfig_agent_id) {
        _LOGE("failed to export the IWD Netconfig Agent: %s", error->message);
        g_clear_error(&error);
    }

    if (_om_has_name_owner(object_manager)) {
        GList                          *objects, *iter;
        gs_unref_object GDBusInterface *daemon = NULL;

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
            register_agent(self, "RegisterAgent");

        priv->netconfig_enabled = false; /* Assume false until GetInfo() results come in */

        daemon = g_dbus_object_manager_get_interface(object_manager,
                                                     "/net/connman/iwd", /* IWD 1.15+ */
                                                     NM_IWD_DAEMON_INTERFACE);
        if (daemon)
            g_dbus_proxy_call(G_DBUS_PROXY(daemon),
                              "GetInfo",
                              g_variant_new("()"),
                              G_DBUS_CALL_FLAGS_NONE,
                              -1,
                              priv->cancellable,
                              get_daemon_info_cb,
                              self);
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
    NMIwdManagerPrivate   *priv = NM_IWD_MANAGER_GET_PRIVATE(self);
    KnownNetworkData      *data;
    char                   name_buf[33];
    KnownNetworkId         kn_id = {name_buf, NM_IWD_NETWORK_SECURITY_OPEN};
    const guint8          *ssid_bytes;
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
    GDBusInterface      *interface;

    if (!priv->object_manager)
        return NULL;

    interface = g_dbus_object_manager_get_interface(priv->object_manager, path, name);

    return interface ? G_DBUS_PROXY(interface) : NULL;
}

gboolean
nm_iwd_manager_get_netconfig_enabled(NMIwdManager *self)
{
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);

    return priv->netconfig_enabled;
}

/* IWD's net.connman.iwd.p2p.ServiceManager.RegisterDisplayService() is global so
 * two local Wi-Fi P2P devices can't be connected to (or even scanning for) WFD
 * peers using different WFD IE contents, e.g. one as a sink and one as a source.
 * If one device is connected to a peer without a WFD service, another can try
 * to establish a WFD connection to a peer since this won't disturb the first
 * connection.  Similarly if one device is connected to a peer with WFD, another
 * can make a connection to a non-WFD peer (if that exists...) because a non-WFD
 * peer will simply ignore the WFD IEs, but it cannot connect to or search for a
 * peer that's WFD capable without passing our own WFD IEs, i.e. if the new
 * NMSettingsConnection has no WFD IEs and we're already in a WFD connection on
 * another device, we can't activate that new connection.  We expose methods
 * for the NMDeviceIwdP2P's to register/unregister the service and one to check
 * if there's already an incompatible connection active.
 */
gboolean
nm_iwd_manager_check_wfd_info_compatible(NMIwdManager *self, const NMIwdWfdInfo *wfd_info)
{
    NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE(self);

    if (priv->wfd_use_count == 0)
        return TRUE;

    return nm_wifi_utils_wfd_info_eq(&priv->wfd_info, wfd_info);
}

gboolean
nm_iwd_manager_register_wfd(NMIwdManager *self, const NMIwdWfdInfo *wfd_info)
{
    NMIwdManagerPrivate            *priv            = NM_IWD_MANAGER_GET_PRIVATE(self);
    gs_unref_object GDBusInterface *service_manager = NULL;
    GVariantBuilder                 builder;

    nm_assert(nm_iwd_manager_check_wfd_info_compatible(self, wfd_info));

    if (!priv->object_manager)
        return FALSE;

    service_manager = g_dbus_object_manager_get_interface(priv->object_manager,
                                                          "/net/connman/iwd",
                                                          NM_IWD_P2P_SERVICE_MANAGER_INTERFACE);
    if (!service_manager) {
        _LOGE("IWD P2P service manager not found");
        return FALSE;
    }

    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add(&builder, "{sv}", "Source", g_variant_new_boolean(wfd_info->source));
    g_variant_builder_add(&builder, "{sv}", "Sink", g_variant_new_boolean(wfd_info->sink));

    if (wfd_info->source)
        g_variant_builder_add(&builder, "{sv}", "Port", g_variant_new_uint16(wfd_info->port));

    if (wfd_info->sink && wfd_info->has_audio)
        g_variant_builder_add(&builder, "{sv}", "HasAudio", g_variant_new_boolean(TRUE));

    if (wfd_info->has_uibc)
        g_variant_builder_add(&builder, "{sv}", "HasUIBC", g_variant_new_boolean(TRUE));

    if (wfd_info->has_cp)
        g_variant_builder_add(&builder,
                              "{sv}",
                              "HasContentProtection",
                              g_variant_new_boolean(TRUE));

    g_dbus_proxy_call(G_DBUS_PROXY(service_manager),
                      "RegisterDisplayService",
                      g_variant_new("(a{sv})", &builder),
                      G_DBUS_CALL_FLAGS_NONE,
                      -1,
                      NULL,
                      NULL,
                      NULL);

    memcpy(&priv->wfd_info, wfd_info, sizeof(priv->wfd_info));
    priv->wfd_use_count++;
    return TRUE;
}

void
nm_iwd_manager_unregister_wfd(NMIwdManager *self)
{
    NMIwdManagerPrivate            *priv            = NM_IWD_MANAGER_GET_PRIVATE(self);
    gs_unref_object GDBusInterface *service_manager = NULL;

    nm_assert(priv->wfd_use_count > 0);

    priv->wfd_use_count--;

    if (!priv->object_manager)
        return;

    service_manager = g_dbus_object_manager_get_interface(priv->object_manager,
                                                          "/net/connman/iwd",
                                                          NM_IWD_P2P_SERVICE_MANAGER_INTERFACE);
    if (!service_manager)
        return;

    g_dbus_proxy_call(G_DBUS_PROXY(service_manager),
                      "UnregisterDisplayService",
                      g_variant_new("()"),
                      G_DBUS_CALL_FLAGS_NONE,
                      -1,
                      NULL,
                      NULL,
                      NULL);
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

    /* The current logic is that we track all creations and removals but
     * for modifications we only listen to those connections that are
     * currently a KnownNetwork's mirror_connection.  There may be multiple
     * NMSettingsConnections referring to the same SSID+Security type tuple
     * so to the same KnownNetwork.  So to make connection profile editing
     * work at least for the simple cases, we track one NMSettingsConnection
     * out of those, and we map its changes to the IWD KnownNetwork.
     *
     * When an NMSettingsConnection is created by a user for a completely
     * new network and the settings are compatible with IWD, we create an
     * IWD KnownNetwork config file for it.  IWD will notice that and a
     * KnownNetwork objects pops up on D-Bus.  We look up a suitable
     * mirror_connection for it and only then subscribe to modification
     * signals.  There are various different ways that this could be done,
     * it's not clear which one's the best.
     */
    priv->settings = g_object_ref(NM_SETTINGS_GET);
    g_signal_connect(priv->settings,
                     NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,
                     G_CALLBACK(connection_removed),
                     self);
    g_signal_connect(priv->settings,
                     NM_SETTINGS_SIGNAL_CONNECTION_ADDED,
                     G_CALLBACK(connection_added),
                     self);

    priv->cancellable = g_cancellable_new();

    priv->known_networks = g_hash_table_new_full((GHashFunc) known_network_id_hash,
                                                 (GEqualFunc) known_network_id_equal,
                                                 g_free,
                                                 (GDestroyNotify) known_network_data_free);

    priv->p2p_devices = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, g_object_unref);

    prepare_object_manager(self);
}

static void
dispose(GObject *object)
{
    NMIwdManager        *self = (NMIwdManager *) object;
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

    nm_clear_g_free(&priv->last_state_dir);
    nm_clear_g_free(&priv->warned_state_dir);

    g_hash_table_unref(nm_steal_pointer(&priv->p2p_devices));

    g_slist_free_full(nm_steal_pointer(&priv->recently_mirrored), recently_mirrored_data_free);

    G_OBJECT_CLASS(nm_iwd_manager_parent_class)->dispose(object);
}

static void
nm_iwd_manager_class_init(NMIwdManagerClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->dispose = dispose;

    signals[P2P_DEVICE_ADDED] = g_signal_new(NM_IWD_MANAGER_P2P_DEVICE_ADDED,
                                             G_OBJECT_CLASS_TYPE(object_class),
                                             G_SIGNAL_RUN_LAST,
                                             0,
                                             NULL,
                                             NULL,
                                             NULL,
                                             G_TYPE_NONE,
                                             2,
                                             NM_TYPE_DEVICE,
                                             G_TYPE_STRING);
}
