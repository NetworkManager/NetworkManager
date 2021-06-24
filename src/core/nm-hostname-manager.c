/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-hostname-manager.h"

#include <sys/stat.h>

#if HAVE_SELINUX
#include <selinux/selinux.h>
#include <selinux/label.h>
#endif

#include "libnm-core-aux-intern/nm-common-macros.h"
#include "libnm-glib-aux/nm-dbus-aux.h"
#include "nm-dbus-interface.h"
#include "nm-connection.h"
#include "nm-utils.h"
#include "libnm-core-intern/nm-core-internal.h"

#include "NetworkManagerUtils.h"
#include "nm-dbus-manager.h"

/*****************************************************************************/

#define HOSTNAMED_SERVICE_NAME      "org.freedesktop.hostname1"
#define HOSTNAMED_SERVICE_PATH      "/org/freedesktop/hostname1"
#define HOSTNAMED_SERVICE_INTERFACE "org.freedesktop.hostname1"

#define HOSTNAME_FILE_DEFAULT        "/etc/hostname"
#define HOSTNAME_FILE_UCASE_HOSTNAME "/etc/HOSTNAME"
#define HOSTNAME_FILE_GENTOO         "/etc/conf.d/hostname"

#define CONF_DHCP SYSCONFDIR "/sysconfig/network/dhcp"

#if (defined(HOSTNAME_PERSIST_SUSE) + defined(HOSTNAME_PERSIST_SLACKWARE) \
     + defined(HOSTNAME_PERSIST_GENTOO))                                  \
    > 1
#error "Can only define one of HOSTNAME_PERSIST_*"
#endif

#if defined(HOSTNAME_PERSIST_SUSE)
#define HOSTNAME_FILE HOSTNAME_FILE_UCASE_HOSTNAME
#elif defined(HOSTNAME_PERSIST_SLACKWARE)
#define HOSTNAME_FILE HOSTNAME_FILE_UCASE_HOSTNAME
#elif defined(HOSTNAME_PERSIST_GENTOO)
#define HOSTNAME_FILE HOSTNAME_FILE_GENTOO
#else
#define HOSTNAME_FILE HOSTNAME_FILE_DEFAULT
#endif

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMHostnameManager, PROP_STATIC_HOSTNAME, );

typedef struct {
    char *static_hostname;

    GFileMonitor *monitor;
    GFileMonitor *dhcp_monitor;
    gulong        monitor_id;
    gulong        dhcp_monitor_id;

    GCancellable    *cancellable;
    guint            name_owner_changed_id;
    guint            dbus_properties_changed_id;
    GDBusConnection *dbus_connection;
    char            *name_owner;

    bool dbus_initied : 1;
    bool try_start_blocked : 1;
    bool try_start_in_progress : 1;
    bool has_file_monitors : 1;
} NMHostnameManagerPrivate;

struct _NMHostnameManager {
    GObject                  parent;
    NMHostnameManagerPrivate _priv;
};

struct _NMHostnameManagerClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NMHostnameManager, nm_hostname_manager, G_TYPE_OBJECT);

#define NM_HOSTNAME_MANAGER_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMHostnameManager, NM_IS_HOSTNAME_MANAGER)

NM_DEFINE_SINGLETON_GETTER(NMHostnameManager, nm_hostname_manager_get, NM_TYPE_HOSTNAME_MANAGER);

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_CORE
#define _NMLOG(level, ...) __NMLOG_DEFAULT(level, _NMLOG_DOMAIN, "hostname", __VA_ARGS__)

/*****************************************************************************/

static void _dbus_hostnamed_ready_or_not(NMHostnameManager *self);

/*****************************************************************************/

static inline GFileMonitor *
_file_monitor_new(const char *path)
{
    gs_unref_object GFile *file = NULL;

    nm_assert(path);

    file = g_file_new_for_path(path);
    return g_file_monitor_file(file, G_FILE_MONITOR_NONE, NULL, NULL);
}

/*****************************************************************************/

#if defined(HOSTNAME_PERSIST_GENTOO)
static char *
read_hostname_gentoo(const char *path)
{
    gs_free char      *contents  = NULL;
    gs_strfreev char **all_lines = NULL;
    const char        *tmp;
    guint              i;

    if (!g_file_get_contents(path, &contents, NULL, NULL))
        return NULL;

    all_lines = g_strsplit(contents, "\n", 0);
    for (i = 0; all_lines[i]; i++) {
        g_strstrip(all_lines[i]);
        if (all_lines[i][0] == '#' || all_lines[i][0] == '\0')
            continue;
        if (g_str_has_prefix(all_lines[i], "hostname=")) {
            tmp = &all_lines[i][NM_STRLEN("hostname=")];
            return g_shell_unquote(tmp, NULL);
        }
    }
    return NULL;
}
#endif

#if defined(HOSTNAME_PERSIST_SLACKWARE)
static char *
read_hostname_slackware(const char *path)
{
    gs_free char      *contents  = NULL;
    gs_strfreev char **all_lines = NULL;
    guint              i         = 0;

    if (!g_file_get_contents(path, &contents, NULL, NULL))
        return NULL;

    all_lines = g_strsplit(contents, "\n", 0);
    for (i = 0; all_lines[i]; i++) {
        g_strstrip(all_lines[i]);
        if (all_lines[i][0] == '#' || all_lines[i][0] == '\0')
            continue;
        return g_shell_unquote(&all_lines[i][0], NULL);
    }
    return NULL;
}
#endif

#if defined(HOSTNAME_PERSIST_SUSE)
static gboolean
hostname_is_dynamic(void)
{
    GIOChannel *channel;
    char       *str     = NULL;
    gboolean    dynamic = FALSE;

    channel = g_io_channel_new_file(CONF_DHCP, "r", NULL);
    if (!channel)
        return dynamic;

    while (g_io_channel_read_line(channel, &str, NULL, NULL, NULL) != G_IO_STATUS_EOF) {
        if (str) {
            g_strstrip(str);
            if (g_str_has_prefix(str, "DHCLIENT_SET_HOSTNAME="))
                dynamic = strcmp(&str[NM_STRLEN("DHCLIENT_SET_HOSTNAME=")], "\"yes\"") == 0;
            g_free(str);
        }
    }

    g_io_channel_shutdown(channel, FALSE, NULL);
    g_io_channel_unref(channel);

    return dynamic;
}
#endif

/*****************************************************************************/

const char *
nm_hostname_manager_get_static_hostname(NMHostnameManager *self)
{
    g_return_val_if_fail(NM_IS_HOSTNAME_MANAGER(self), NULL);

    return NM_HOSTNAME_MANAGER_GET_PRIVATE(self)->static_hostname;
}

static void
_set_hostname(NMHostnameManager *self, const char *hostname)
{
    NMHostnameManagerPrivate *priv          = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);
    gs_free char             *hostname_free = NULL;
    char                     *old_hostname;

    hostname = nm_str_not_empty(hostname);

    if (hostname) {
        /* as we also read the file from disk, it might not be in UTF-8 encoding.
         *
         * A hostname in non-UTF-8 encoding would be odd and cause issues when we
         * try to expose them on D-Bus via the NM_SETTINGS_STATIC_HOSTNAME property.
         *
         * Sanitize somewhat. It's wrong anyway. */
        hostname = nm_utils_str_utf8safe_escape(hostname,
                                                NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL,
                                                &hostname_free);
    }

    if (nm_streq0(hostname, priv->static_hostname))
        return;

    _LOGI("static hostname changed from %s%s%s to %s%s%s",
          NM_PRINT_FMT_QUOTED(priv->static_hostname, "\"", priv->static_hostname, "\"", "(none)"),
          NM_PRINT_FMT_QUOTED(hostname, "\"", hostname, "\"", "(none)"));

    old_hostname          = priv->static_hostname;
    priv->static_hostname = g_strdup(hostname);
    g_free(old_hostname);

    _notify(self, PROP_STATIC_HOSTNAME);
}

static void
_set_hostname_read_file(NMHostnameManager *self)
{
    gs_free char *hostname = NULL;

#if defined(HOSTNAME_PERSIST_SUSE)
    {
        NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);

        if (priv->dhcp_monitor_id && hostname_is_dynamic())
            return;
    }
#endif

#if defined(HOSTNAME_PERSIST_GENTOO)
    hostname = read_hostname_gentoo(HOSTNAME_FILE);
#elif defined(HOSTNAME_PERSIST_SLACKWARE)
    hostname = read_hostname_slackware(HOSTNAME_FILE);
#else
    if (g_file_get_contents(HOSTNAME_FILE, &hostname, NULL, NULL))
        g_strchomp(hostname);
#endif

    _set_hostname(self, hostname);
}

/*****************************************************************************/

static void
set_transient_hostname_done(GObject *object, GAsyncResult *res, gpointer user_data)
{
    GDBusProxy                    *proxy    = G_DBUS_PROXY(object);
    gs_unref_variant GVariant     *result   = NULL;
    gs_free_error GError          *error    = NULL;
    gs_free char                  *hostname = NULL;
    NMHostnameManagerSetHostnameCb cb;
    gpointer                       cb_user_data;

    nm_utils_user_data_unpack(user_data, &hostname, &cb, &cb_user_data);

    result = g_dbus_proxy_call_finish(proxy, res, &error);

    if (error) {
        _LOGW("couldn't set the system hostname to '%s' using hostnamed: %s",
              hostname,
              error->message);
    }

    cb(hostname, !error, cb_user_data);
}

void
nm_hostname_manager_set_transient_hostname(NMHostnameManager             *self,
                                           const char                    *hostname,
                                           NMHostnameManagerSetHostnameCb cb,
                                           gpointer                       user_data)
{
    NMHostnameManagerPrivate *priv;

    g_return_if_fail(NM_IS_HOSTNAME_MANAGER(self));

    priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);

    if (!priv->hostnamed_proxy) {
        cb(hostname, FALSE, user_data);
        return;
    }

    g_dbus_proxy_call(priv->hostnamed_proxy,
                      "SetHostname",
                      g_variant_new("(sb)", hostname, FALSE),
                      G_DBUS_CALL_FLAGS_NONE,
                      -1,
                      NULL,
                      set_transient_hostname_done,
                      nm_utils_user_data_pack(g_strdup(hostname), cb, user_data));
}

gboolean
nm_hostname_manager_get_transient_hostname(NMHostnameManager *self, char **hostname)
{
    NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);
    GVariant                 *v_hostname;

    if (!priv->hostnamed_proxy)
        return FALSE;

    v_hostname = g_dbus_proxy_get_cached_property(priv->hostnamed_proxy, "Hostname");
    if (!v_hostname) {
        _LOGT("transient hostname retrieval failed");
        return FALSE;
    }

    *hostname = g_variant_dup_string(v_hostname, NULL);
    g_variant_unref(v_hostname);

    return TRUE;
}

/*****************************************************************************/

static void
_write_hostname_dbus_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_object GTask     *task  = G_TASK(user_data);
    gs_unref_variant GVariant *res   = NULL;
    GError                    *error = NULL;

    res = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), result, &error);
    if (!res) {
        g_task_return_error(task, error);
        return;
    }
    g_task_return_boolean(task, TRUE);
}

static void
_write_hostname_on_idle_cb(gpointer user_data, GCancellable *cancellable)
{
    gs_unref_object GTask    *task = G_TASK(user_data);
    NMHostnameManager        *self;
    NMHostnameManagerPrivate *priv;
    const char               *hostname;
    gs_free char             *hostname_eol = NULL;
    gboolean                  ret;
    gs_free_error GError     *error     = NULL;
    const char               *file      = HOSTNAME_FILE;
    gs_free char             *link_path = NULL;
    struct stat               file_stat;
#if HAVE_SELINUX
    gboolean fcon_was_set = FALSE;
    char    *fcon_prev    = NULL;
#endif

    if (g_task_return_error_if_cancelled(task))
        return;

    self = g_task_get_source_object(task);
    priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);

    nm_assert(!priv->hostnamed_proxy);

    hostname = g_task_get_task_data(task);

    /* If the hostname file is a symbolic link, follow it to find where the
     * real file is located, otherwise g_file_set_contents will attempt to
     * replace the link with a plain file.
     */
    if (lstat(file, &file_stat) == 0 && S_ISLNK(file_stat.st_mode)
        && (link_path = nm_utils_read_link_absolute(file, NULL)))
        file = link_path;

    if (hostname) {
#if defined(HOSTNAME_PERSIST_GENTOO)
        hostname_eol = g_strdup_printf("#Generated by NetworkManager\n"
                                       "hostname=\"%s\"\n",
                                       hostname);
#else
        hostname_eol = g_strdup_printf("%s\n", hostname);
#endif
    }

#if HAVE_SELINUX
    /* Get default context for hostname file and set it for fscreate */
    {
        struct selabel_handle *handle;

        handle = selabel_open(SELABEL_CTX_FILE, NULL, 0);
        if (handle) {
            mode_t st_mode = 0;
            char  *fcon    = NULL;

            if (stat(file, &file_stat) == 0)
                st_mode = file_stat.st_mode;

            if ((selabel_lookup(handle, &fcon, file, st_mode) == 0)
                && (getfscreatecon(&fcon_prev) == 0)) {
                setfscreatecon(fcon);
                fcon_was_set = TRUE;
            }

            selabel_close(handle);
            freecon(fcon);
        }
    }
#endif

    ret = g_file_set_contents(file, hostname_eol ?: "", -1, &error);

#if HAVE_SELINUX
    /* Restore previous context and cleanup */
    if (fcon_was_set)
        setfscreatecon(fcon_prev);
    if (fcon_prev)
        freecon(fcon_prev);
#endif

    if (!ret) {
        g_task_return_new_error(task,
                                NM_UTILS_ERROR,
                                NM_UTILS_ERROR_UNKNOWN,
                                "could not save hostname to %s: %s",
                                file,
                                error->message);
        return;
    }

    g_task_return_boolean(task, TRUE);
}

void
nm_hostname_manager_write_hostname(NMHostnameManager  *self,
                                   const char         *hostname,
                                   GCancellable       *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer            user_data)
{
    NMHostnameManagerPrivate *priv;
    GTask                    *task;

    g_return_if_fail(NM_IS_HOSTNAME_MANAGER(self));

    priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);

    task =
        nm_g_task_new(self, cancellable, nm_hostname_manager_write_hostname, callback, user_data);

    g_task_set_task_data(task, g_strdup(hostname), g_free);

    if (priv->hostnamed_proxy) {
        g_dbus_proxy_call(priv->hostnamed_proxy,
                          "SetStaticHostname",
                          g_variant_new("(sb)", hostname ?: "", FALSE),
                          G_DBUS_CALL_FLAGS_NONE,
                          15000,
                          cancellable,
                          _write_hostname_dbus_cb,
                          task);
        return;
    }

    nm_utils_invoke_on_idle(cancellable, _write_hostname_on_idle_cb, task);
}

gboolean
nm_hostname_manager_write_hostname_finish(NMHostnameManager *self,
                                          GAsyncResult      *result,
                                          GError           **error)
{
    g_return_val_if_fail(NM_IS_HOSTNAME_MANAGER(self), FALSE);
    g_return_val_if_fail(nm_g_task_is_valid(result, self, nm_hostname_manager_write_hostname),
                         FALSE);

    return g_task_propagate_boolean(G_TASK(result), error);
}

/*****************************************************************************/

static void
_file_monitors_file_changed_cb(GFileMonitor     *monitor,
                               GFile            *file,
                               GFile            *other_file,
                               GFileMonitorEvent event_type,
                               gpointer          user_data)
{
    _set_hostname_read_file(user_data);
}

static void
_file_monitors_clear(NMHostnameManager *self)
{
    NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);

    if (priv->monitor) {
        nm_clear_g_signal_handler(priv->monitor, &priv->monitor_id);
        g_file_monitor_cancel(priv->monitor);
        g_clear_object(&priv->monitor);
    }

    if (priv->dhcp_monitor) {
        nm_clear_g_signal_handler(priv->dhcp_monitor, &priv->dhcp_monitor_id);
        g_file_monitor_cancel(priv->dhcp_monitor);
        g_clear_object(&priv->dhcp_monitor);
    }

    priv->has_file_monitors = FALSE;
}

static void
_file_monitors_setup(NMHostnameManager *self, gboolean force_restart)
{
    NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);
    GFileMonitor             *monitor;
    const char               *path      = HOSTNAME_FILE;
    gs_free char             *link_path = NULL;
    struct stat               file_stat;

    if (priv->has_file_monitors && !force_restart)
        return;

    _file_monitors_clear(self);

    priv->has_file_monitors = TRUE;

    _LOGT("setup file monitors for %s", path);

    /* resolve the path to the hostname file if it is a symbolic link */
    if (lstat(path, &file_stat) == 0 && S_ISLNK(file_stat.st_mode)
        && (link_path = nm_utils_read_link_absolute(path, NULL))) {
        path = link_path;
        if (lstat(link_path, &file_stat) == 0 && S_ISLNK(file_stat.st_mode)) {
            _LOGW("only one level of symbolic link indirection is allowed when "
                  "monitoring " HOSTNAME_FILE);
        }
    }

    /* monitor changes to hostname file */
    monitor = _file_monitor_new(path);
    if (monitor) {
        priv->monitor_id =
            g_signal_connect(monitor, "changed", G_CALLBACK(_file_monitors_file_changed_cb), self);
        priv->monitor = monitor;
    }

#if defined(HOSTNAME_PERSIST_SUSE)
    /* monitor changes to dhcp file to know whether the hostname is valid */
    monitor = _file_monitor_new(CONF_DHCP);
    if (monitor) {
        priv->dhcp_monitor_id =
            g_signal_connect(monitor, "changed", G_CALLBACK(_file_monitors_file_changed_cb), self);
        priv->dhcp_monitor = monitor;
    }
#endif

    _set_hostname_read_file(self);
}

/*****************************************************************************/

static void
_dbus_get_static_hostname_cb(GVariant *result, GError *error, gpointer user_data)
{
    const char *hostname = NULL;

    if (nm_utils_error_is_cancelled(error))
        return;

    if (result)
        g_variant_get(result, "(&s)", &hostname);

    _set_hostname(user_data, hostname);
}

static void
_dbus_properties_changed_cb(GDBusConnection *connection,
                            const char      *sender_name,
                            const char      *object_path,
                            const char      *signal_interface_name,
                            const char      *signal_name,
                            GVariant        *parameters,
                            gpointer         user_data)
{
    gs_unref_variant GVariant *changed_properties = NULL;
    gs_unref_variant GVariant *var                = NULL;

    if (!g_variant_is_of_type(parameters, G_VARIANT_TYPE("(sa{sv}as)")))
        return;

    g_variant_get(parameters, "(&s@a{sv}^a&s)", NULL, &changed_properties, NULL);
    var = g_variant_lookup_value(changed_properties, "StaticHostname", G_VARIANT_TYPE_STRING);
    if (var)
        _set_hostname(user_data, g_variant_get_string(var, NULL));
}

static void
_dbus_start_service_by_name_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMHostnameManager         *self;
    NMHostnameManagerPrivate  *priv;
    gs_unref_variant GVariant *res   = NULL;
    gs_free_error GError      *error = NULL;

    res = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (nm_utils_error_is_cancelled(error))
        return;

    self                        = user_data;
    priv                        = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);
    priv->try_start_in_progress = FALSE;
    _dbus_hostnamed_ready_or_not(self);
}

static void
_dbus_hostnamed_ready_or_not(NMHostnameManager *self)
{
    NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);

    if (!priv->name_owner) {
        nm_clear_g_dbus_connection_signal(priv->dbus_connection, &priv->dbus_properties_changed_id);

        if (!priv->try_start_blocked) {
            priv->try_start_blocked     = TRUE;
            priv->try_start_in_progress = TRUE;
            nm_dbus_connection_call_start_service_by_name(priv->dbus_connection,
                                                          HOSTNAMED_SERVICE_NAME,
                                                          500,
                                                          priv->cancellable,
                                                          _dbus_start_service_by_name_cb,
                                                          self);
            return;
        }
        if (priv->try_start_in_progress)
            return;

        _file_monitors_setup(self, FALSE);
        return;
    }

    _file_monitors_clear(self);

    if (!priv->dbus_properties_changed_id) {
        priv->dbus_properties_changed_id =
            nm_dbus_connection_signal_subscribe_properties_changed(priv->dbus_connection,
                                                                   priv->name_owner,
                                                                   HOSTNAMED_SERVICE_PATH,
                                                                   HOSTNAMED_SERVICE_INTERFACE,
                                                                   _dbus_properties_changed_cb,
                                                                   self,
                                                                   NULL);
        nm_dbus_connection_call_get(priv->dbus_connection,
                                    priv->name_owner,
                                    HOSTNAMED_SERVICE_PATH,
                                    HOSTNAMED_SERVICE_INTERFACE,
                                    "StaticHostname",
                                    500,
                                    priv->cancellable,
                                    _dbus_get_static_hostname_cb,
                                    self);
    }
}

static void
_dbus_name_owner_changed(NMHostnameManager *self, const char *owner)
{
    NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);

    owner = nm_str_not_empty(owner);

    if (!owner)
        _LOGT("D-Bus name for systemd-hostnamed has no owner");
    else
        _LOGT("D-Bus name for systemd-hostnamed has owner %s", owner);

    nm_utils_strdup_reset(&priv->name_owner, owner);

    _dbus_hostnamed_ready_or_not(self);
}

static void
_dbus_name_owner_changed_cb(GDBusConnection *connection,
                            const char      *sender_name,
                            const char      *object_path,
                            const char      *interface_name,
                            const char      *signal_name,
                            GVariant        *parameters,
                            gpointer         user_data)
{
    NMHostnameManager        *self = user_data;
    NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);
    const char               *new_owner;

    if (!priv->dbus_initied)
        return;

    if (!g_variant_is_of_type(parameters, G_VARIANT_TYPE("(sss)")))
        return;

    g_variant_get(parameters, "(&s&s&s)", NULL, NULL, &new_owner);
    _dbus_name_owner_changed(self, new_owner);
}

static void
_dbus_get_name_owner_cb(const char *name_owner, GError *error, gpointer user_data)
{
    NMHostnameManager        *self;
    NMHostnameManagerPrivate *priv;

    if (nm_utils_error_is_cancelled(error))
        return;

    self = user_data;
    priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);

    g_clear_object(&priv->cancellable);

    priv->dbus_initied = TRUE;
    _LOGT("D-Bus connection is ready");

    _dbus_name_owner_changed(self, name_owner);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMHostnameManager *self = NM_HOSTNAME_MANAGER(object);

    switch (prop_id) {
    case PROP_STATIC_HOSTNAME:
        g_value_set_string(value, nm_hostname_manager_get_static_hostname(self));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_hostname_manager_init(NMHostnameManager *self)
{
    NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);

    priv->cancellable = g_cancellable_new();

    priv->dbus_connection = nm_g_object_ref(NM_MAIN_DBUS_CONNECTION_GET);
    if (!priv->dbus_connection) {
        _LOGD("no D-Bus connection");
        _file_monitors_setup(self, FALSE);
        return;
    }

    priv->name_owner_changed_id =
        nm_dbus_connection_signal_subscribe_name_owner_changed(priv->dbus_connection,
                                                               HOSTNAMED_SERVICE_NAME,
                                                               _dbus_name_owner_changed_cb,
                                                               self,
                                                               NULL);
    nm_dbus_connection_call_get_name_owner(priv->dbus_connection,
                                           HOSTNAMED_SERVICE_NAME,
                                           -1,
                                           priv->cancellable,
                                           _dbus_get_name_owner_cb,
                                           self);
}

static void
dispose(GObject *object)
{
    NMHostnameManager        *self = NM_HOSTNAME_MANAGER(object);
    NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);

    nm_clear_g_cancellable(&priv->cancellable);

    nm_clear_g_dbus_connection_signal(priv->dbus_connection, &priv->name_owner_changed_id);
    nm_clear_g_dbus_connection_signal(priv->dbus_connection, &priv->dbus_properties_changed_id);

    _file_monitors_clear(self);

    nm_clear_g_free(&priv->static_hostname);
    g_clear_object(&priv->dbus_connection);
    nm_clear_g_free(&priv->name_owner);

    G_OBJECT_CLASS(nm_hostname_manager_parent_class)->dispose(object);
}

static void
nm_hostname_manager_class_init(NMHostnameManagerClass *class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(class);

    object_class->get_property = get_property;
    object_class->dispose      = dispose;

    obj_properties[PROP_STATIC_HOSTNAME] =
        g_param_spec_string(NM_HOSTNAME_MANAGER_STATIC_HOSTNAME,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
