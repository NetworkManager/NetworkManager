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
#include "nm-dbus-interface.h"
#include "nm-connection.h"
#include "nm-utils.h"
#include "libnm-core-intern/nm-core-internal.h"

#include "NetworkManagerUtils.h"

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
    char         *static_hostname;
    GFileMonitor *monitor;
    GFileMonitor *dhcp_monitor;
    gulong        monitor_id;
    gulong        dhcp_monitor_id;
    GDBusProxy   *hostnamed_proxy;
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

static inline GFileMonitor *
_file_monitor_new(const char *path)
{
    gs_unref_object GFile *file = NULL;

    nm_assert(path);

    file = g_file_new_for_path(path);
    return g_file_monitor_file(file, G_FILE_MONITOR_NONE, NULL, NULL);
}

/*****************************************************************************/

static char *
read_hostname(const char *path, gboolean is_gentoo)
{
    gs_free char        *contents  = NULL;
    gs_free const char **all_lines = NULL;
    const char          *tmp;
    gsize                i;

    if (!g_file_get_contents(path, &contents, NULL, NULL))
        return NULL;

    all_lines = nm_strsplit_set_full(contents, "\n", NM_STRSPLIT_SET_FLAGS_STRSTRIP);
    for (i = 0; (tmp = all_lines[i]); i++) {
        if (is_gentoo) {
            if (!NM_STR_HAS_PREFIX(tmp, "hostname="))
                continue;
            tmp = &tmp[NM_STRLEN("hostname=")];
        } else {
            if (tmp[0] == '#')
                continue;
        }
        nm_assert(tmp && tmp[0] != '\0');
        return g_shell_unquote(tmp, NULL);
    }
    return NULL;
}

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
    NMHostnameManagerPrivate *priv     = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);
    gs_free char             *hostname = NULL;

    if (priv->hostnamed_proxy) {
        /* read-hostname returns the current hostname with hostnamed. */
        return;
    }

#if defined(HOSTNAME_PERSIST_SUSE)
    if (priv->dhcp_monitor_id && hostname_is_dynamic())
        return;
#endif

#if defined(HOSTNAME_PERSIST_GENTOO)
    hostname = read_hostname(HOSTNAME_FILE, TRUE);
#elif defined(HOSTNAME_PERSIST_SLACKWARE)
    hostname = read_hostname(HOSTNAME_FILE, FALSE);
#else
    (void) read_hostname;
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
nm_hostname_manager_set_static_hostname(NMHostnameManager  *self,
                                        const char         *hostname,
                                        GCancellable       *cancellable,
                                        GAsyncReadyCallback callback,
                                        gpointer            user_data)
{
    NMHostnameManagerPrivate *priv;
    GTask                    *task;

    g_return_if_fail(NM_IS_HOSTNAME_MANAGER(self));

    priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);

    task = nm_g_task_new(self,
                         cancellable,
                         nm_hostname_manager_set_static_hostname,
                         callback,
                         user_data);

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
nm_hostname_manager_set_static_hostname_finish(NMHostnameManager *self,
                                               GAsyncResult      *result,
                                               GError           **error)
{
    g_return_val_if_fail(NM_IS_HOSTNAME_MANAGER(self), FALSE);
    g_return_val_if_fail(nm_g_task_is_valid(result, self, nm_hostname_manager_set_static_hostname),
                         FALSE);

    return g_task_propagate_boolean(G_TASK(result), error);
}

/*****************************************************************************/

static void
hostnamed_properties_changed(GDBusProxy *proxy,
                             GVariant   *changed_properties,
                             char      **invalidated_properties,
                             gpointer    user_data)
{
    NMHostnameManager         *self    = user_data;
    NMHostnameManagerPrivate  *priv    = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);
    gs_unref_variant GVariant *variant = NULL;

    variant = g_dbus_proxy_get_cached_property(priv->hostnamed_proxy, "StaticHostname");
    if (variant && g_variant_is_of_type(variant, G_VARIANT_TYPE_STRING))
        _set_hostname(self, g_variant_get_string(variant, NULL));
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
}

static void
_file_monitors_setup(NMHostnameManager *self)
{
    NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);
    GFileMonitor             *monitor;
    const char               *path      = HOSTNAME_FILE;
    gs_free char             *link_path = NULL;
    struct stat               file_stat;

    _file_monitors_clear(self);

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
{}

static void
constructed(GObject *object)
{
    NMHostnameManager        *self = NM_HOSTNAME_MANAGER(object);
    NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);
    GDBusProxy               *proxy;
    GVariant                 *variant;
    gs_free_error GError     *error = NULL;

    proxy = g_dbus_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
                                          0,
                                          NULL,
                                          HOSTNAMED_SERVICE_NAME,
                                          HOSTNAMED_SERVICE_PATH,
                                          HOSTNAMED_SERVICE_INTERFACE,
                                          NULL,
                                          &error);
    if (proxy) {
        variant = g_dbus_proxy_get_cached_property(proxy, "StaticHostname");
        if (variant) {
            _LOGI("hostname: using hostnamed");
            priv->hostnamed_proxy = proxy;
            g_signal_connect(proxy,
                             "g-properties-changed",
                             G_CALLBACK(hostnamed_properties_changed),
                             self);
            hostnamed_properties_changed(proxy, NULL, NULL, self);
            g_variant_unref(variant);
        } else {
            _LOGI("hostname: couldn't get property from hostnamed");
            g_object_unref(proxy);
        }
    } else {
        _LOGI("hostname: hostnamed not used as proxy creation failed with: %s", error->message);
        g_clear_error(&error);
    }

    if (!priv->hostnamed_proxy)
        _file_monitors_setup(self);

    G_OBJECT_CLASS(nm_hostname_manager_parent_class)->constructed(object);
}

static void
dispose(GObject *object)
{
    NMHostnameManager        *self = NM_HOSTNAME_MANAGER(object);
    NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE(self);

    if (priv->hostnamed_proxy) {
        g_signal_handlers_disconnect_by_func(priv->hostnamed_proxy,
                                             G_CALLBACK(hostnamed_properties_changed),
                                             self);
        g_clear_object(&priv->hostnamed_proxy);
    }

    _file_monitors_clear(self);

    nm_clear_g_free(&priv->static_hostname);

    G_OBJECT_CLASS(nm_hostname_manager_parent_class)->dispose(object);
}

static void
nm_hostname_manager_class_init(NMHostnameManagerClass *class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(class);

    object_class->constructed  = constructed;
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
