/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Jiri Pirko <jiri@resnulli.us>
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-team.h"

#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <teamdctl.h>
#include <stdlib.h>

#include "libnm-glib-aux/nm-jansson.h"
#include "NetworkManagerUtils.h"
#include "devices/nm-device-private.h"
#include "libnm-platform/nm-platform.h"
#include "nm-config.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-dbus-manager.h"
#include "libnm-std-aux/nm-dbus-compat.h"

#define _NMLOG_DEVICE_TYPE NMDeviceTeam
#include "devices/nm-device-logging.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMDeviceTeam, PROP_CONFIG, );

typedef struct {
    GDBusConnection   *dbus_connection;
    char              *dbus_name;
    char              *config;
    GPid               teamd_pid;
    guint              teamd_process_watch;
    guint              teamd_dbus_timeout;
    guint              teamd_read_timeout;
    guint              teamd_dbus_watch;
    NMDeviceStageState stage1_state : 3;
    GHashTable        *port_configs;
} NMDeviceTeamPrivate;

struct _NMDeviceTeam {
    NMDevice            parent;
    NMDeviceTeamPrivate _priv;
};

struct _NMDeviceTeamClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceTeam, nm_device_team, NM_TYPE_DEVICE)

#define NM_DEVICE_TEAM_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceTeam, NM_IS_DEVICE_TEAM, NMDevice)

/*****************************************************************************/

static gboolean teamd_start(NMDeviceTeam *self);

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *device)
{
    return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
complete_connection(NMDevice            *device,
                    NMConnection        *connection,
                    const char          *specific_object,
                    NMConnection *const *existing_connections,
                    GError             **error)
{
    nm_utils_complete_generic(nm_device_get_platform(device),
                              connection,
                              NM_SETTING_TEAM_SETTING_NAME,
                              existing_connections,
                              NULL,
                              _("Team connection"),
                              "team",
                              NULL,
                              TRUE);

    _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_TEAM);

    return TRUE;
}

static gboolean
_update_port_config(NMDeviceTeam *self, const char *port_iface, const char *sanitized_config)
{
    NMDeviceTeamPrivate       *priv  = NM_DEVICE_TEAM_GET_PRIVATE(self);
    gs_unref_variant GVariant *res   = NULL;
    GError                    *error = NULL;

    _LOGT(LOGD_TEAM, "setting port config: %s", sanitized_config);
    res = g_dbus_connection_call_sync(priv->dbus_connection,
                                      priv->dbus_name,
                                      "/org/libteam/teamd",
                                      "org.libteam.teamd",
                                      "PortConfigUpdate",
                                      g_variant_new("(ss)", port_iface, sanitized_config),
                                      NULL,
                                      G_DBUS_CALL_FLAGS_NO_AUTO_START,
                                      -1,
                                      NULL,
                                      &error);

    if (!res) {
        _LOGE(LOGD_TEAM, "failed to update config for port %s: %s", port_iface, error->message);
        g_clear_error(&error);
        return FALSE;
    }

    return TRUE;
}

static void
config_dump_cb(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    GDBusConnection           *connection = G_DBUS_CONNECTION(source_object);
    NMDeviceTeam              *self       = NM_DEVICE_TEAM(user_data);
    NMDeviceTeamPrivate       *priv       = NM_DEVICE_TEAM_GET_PRIVATE(self);
    NMDevice                  *device     = NM_DEVICE(self);
    gs_unref_variant GVariant *ret        = NULL;
    gs_free char              *config     = NULL;
    GError                    *error      = NULL;

    ret = g_dbus_connection_call_finish(connection, res, &error);
    if (!ret) {
        _LOGW(LOGD_TEAM, "Failed to read configuration: %s", error->message);
        g_error_free(error);
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED);
        return;
    }

    g_variant_get_child(ret, 0, "s", &config);
    if (!nm_streq0(config, priv->config)) {
        g_free(priv->config);
        priv->config = g_steal_pointer(&config);
        _notify(self, PROP_CONFIG);
    }

    if (nm_device_get_state(NM_DEVICE(self)) == NM_DEVICE_STATE_PREPARE) {
        priv->stage1_state = NM_DEVICE_STAGE_STATE_COMPLETED;
        nm_device_activate_schedule_stage1_device_prepare(device, FALSE);
    }
}

static void
teamd_read_config(NMDeviceTeam *self)
{
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);
    g_dbus_connection_call(priv->dbus_connection,
                           priv->dbus_name,
                           "/org/libteam/teamd",
                           "org.libteam.teamd",
                           "ConfigDumpActual",
                           NULL,
                           NULL,
                           G_DBUS_CALL_FLAGS_NO_AUTO_START,
                           -1,
                           NULL,
                           config_dump_cb,
                           self);
}

static gboolean
teamd_read_timeout_cb(gpointer user_data)
{
    NMDeviceTeam        *self = user_data;
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);

    priv->teamd_read_timeout = 0;
    teamd_read_config(self);
    return G_SOURCE_REMOVE;
}

static void
update_connection(NMDevice *device, NMConnection *connection)
{
    NMDeviceTeam  *self   = NM_DEVICE_TEAM(device);
    NMSettingTeam *s_team = _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_TEAM);

    g_object_set(G_OBJECT(s_team),
                 NM_SETTING_TEAM_CONFIG,
                 nm_str_not_empty(NM_DEVICE_TEAM_GET_PRIVATE(self)->config),
                 NULL);
}

/*****************************************************************************/

static gboolean
master_update_slave_connection(NMDevice     *device,
                               NMDevice     *slave,
                               NMConnection *connection,
                               GError      **error)
{
    NMDeviceTeam              *self = NM_DEVICE_TEAM(device);
    NMDeviceTeamPrivate       *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);
    NMSettingTeamPort         *s_port;
    char                      *port_config        = NULL;
    gs_unref_variant GVariant *res                = NULL;
    const char                *iface              = nm_device_get_iface(device);
    const char                *iface_slave        = nm_device_get_iface(slave);
    NMConnection              *applied_connection = nm_device_get_applied_connection(device);

    if (!priv->dbus_connection) {
        g_set_error(
            error,
            NM_DEVICE_ERROR,
            NM_DEVICE_ERROR_FAILED,
            "update slave connection for slave '%s' failed to connect to teamd for master %s",
            iface_slave,
            iface);
        return FALSE;
    }

    res = g_dbus_connection_call_sync(priv->dbus_connection,
                                      priv->dbus_name,
                                      "/org/libteam/teamd",
                                      "org.libteam.teamd",
                                      "PortConfigDump",
                                      g_variant_new("(s)", iface_slave),
                                      NULL,
                                      G_DBUS_CALL_FLAGS_NO_AUTO_START,
                                      -1,
                                      NULL,
                                      error);
    if (!res) {
        g_prefix_error(
            error,
            "update slave connection for slave '%s' failed to get configuration from teamd "
            "master %s: ",
            iface_slave,
            iface);
        return FALSE;
    }

    g_variant_get_child(res, 0, "s", &port_config);
    s_port = _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_TEAM_PORT);
    g_object_set(G_OBJECT(s_port), NM_SETTING_TEAM_PORT_CONFIG, port_config, NULL);
    g_free(port_config);

    g_object_set(nm_connection_get_setting_connection(connection),
                 NM_SETTING_CONNECTION_MASTER,
                 nm_connection_get_uuid(applied_connection),
                 NM_SETTING_CONNECTION_SLAVE_TYPE,
                 NM_SETTING_TEAM_SETTING_NAME,
                 NULL);
    return TRUE;
}

/*****************************************************************************/

static void
teamd_cleanup(NMDeviceTeam *self)
{
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);

    nm_clear_g_source(&priv->teamd_process_watch);
    nm_clear_g_source(&priv->teamd_dbus_timeout);
    nm_clear_g_source(&priv->teamd_read_timeout);

    if (priv->teamd_pid > 0) {
        _LOGI(LOGD_TEAM, "terminating our teamd instance");
        nm_utils_kill_child_async(priv->teamd_pid, SIGTERM, LOGD_TEAM, "teamd", 2000, NULL, NULL);
        priv->teamd_pid = 0;
    }
}

static gboolean
teamd_dbus_timeout_cb(gpointer user_data)
{
    NMDeviceTeam        *self   = NM_DEVICE_TEAM(user_data);
    NMDevice            *device = NM_DEVICE(self);
    NMDeviceTeamPrivate *priv   = NM_DEVICE_TEAM_GET_PRIVATE(self);

    _LOGW(LOGD_TEAM, "timed out waiting for teamd to appear on D-Bus");

    g_return_val_if_fail(priv->teamd_dbus_timeout, FALSE);
    priv->teamd_dbus_timeout = 0;

    nm_device_state_changed(device,
                            NM_DEVICE_STATE_FAILED,
                            NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED);

    return G_SOURCE_REMOVE;
}

static void
teamd_dbus_appeared(GDBusConnection *connection,
                    const char      *name,
                    const char      *name_owner,
                    gpointer         user_data)
{
    NMDeviceTeam        *self   = NM_DEVICE_TEAM(user_data);
    NMDeviceTeamPrivate *priv   = NM_DEVICE_TEAM_GET_PRIVATE(self);
    NMDevice            *device = NM_DEVICE(self);
    const char          *port_iface;
    const char          *port_config;
    GHashTableIter       iter;

    _LOGI(LOGD_TEAM, "teamd appeared on D-Bus");

    g_return_if_fail(priv->teamd_dbus_watch);

    nm_clear_g_source(&priv->teamd_dbus_timeout);

    g_clear_object(&priv->dbus_connection);
    priv->dbus_connection = nm_g_object_ref(connection);

    nm_device_queue_recheck_assume(device);

    teamd_read_config(self);

    /* This might have been an respawn. Ensure previously configured port
     * configs are applied to the new teamd as well.
     */
    g_hash_table_iter_init(&iter, priv->port_configs);
    while (g_hash_table_iter_next(&iter, (gpointer *) &port_iface, (gpointer *) &port_config))
        _update_port_config(self, port_iface, port_config);
}

static void
teamd_dbus_vanished(GDBusConnection *dbus_connection, const char *name, gpointer user_data)
{
    NMDeviceTeam        *self   = NM_DEVICE_TEAM(user_data);
    NMDeviceTeamPrivate *priv   = NM_DEVICE_TEAM_GET_PRIVATE(self);
    NMDevice            *device = NM_DEVICE(self);
    NMDeviceState        state;

    g_return_if_fail(priv->teamd_dbus_watch);

    if (!priv->dbus_connection) {
        /* g_bus_watch_name will always raise an initial signal, to indicate whether the
         * name exists/not exists initially. Do not take this as a failure if it hadn't
         * previously appeared.
         */
        _LOGD(LOGD_TEAM, "teamd not on D-Bus (ignored)");
        return;
    }

    _LOGI(LOGD_TEAM, "teamd vanished from D-Bus");
    g_clear_object(&priv->dbus_connection);
    teamd_cleanup(self);
    state = nm_device_get_state(device);

    /* Attempt to respawn teamd */
    if (state >= NM_DEVICE_STATE_PREPARE && state <= NM_DEVICE_STATE_ACTIVATED) {
        if (!teamd_start(self)) {
            nm_device_state_changed(device,
                                    NM_DEVICE_STATE_FAILED,
                                    NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED);
        }
    }
}

static void
teamd_process_watch_cb(GPid pid, int status, gpointer user_data)
{
    NMDeviceTeam        *self = NM_DEVICE_TEAM(user_data);
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);

    g_return_if_fail(priv->teamd_process_watch);

    _LOGI(LOGD_TEAM, "teamd %lld died with status %d", (long long) pid, status);
    priv->teamd_pid           = 0;
    priv->teamd_process_watch = 0;
}

static void
teamd_child_setup(gpointer user_data)
{
    nm_utils_setpgid(NULL);
    signal(SIGPIPE, SIG_IGN);
}

static const char **
teamd_env(void)
{
    const char **env = g_new0(const char *, 2);

    if (nm_config_get_is_debug(nm_config_get()))
        env[0] = "TEAM_LOG_OUTPUT=stderr";
    else
        env[0] = "TEAM_LOG_OUTPUT=syslog";

    return env;
}

static gboolean
teamd_kill(NMDeviceTeam *self, GError **error)
{
    gs_unref_ptrarray GPtrArray *argv    = NULL;
    gs_free char                *tmp_str = NULL;
    gs_free const char         **envp    = NULL;
    const char                  *teamd_binary;

    teamd_binary = nm_utils_find_helper("teamd", NULL, error);
    if (!teamd_binary) {
        _LOGW(LOGD_TEAM, "Activation: (team) failed to start teamd: teamd binary not found");
        return FALSE;
    }

    argv = g_ptr_array_new();
    g_ptr_array_add(argv, (gpointer) teamd_binary);
    g_ptr_array_add(argv, (gpointer) "-k");
    g_ptr_array_add(argv, (gpointer) "-t");
    g_ptr_array_add(argv, (gpointer) nm_device_get_iface(NM_DEVICE(self)));
    g_ptr_array_add(argv, NULL);

    envp = teamd_env();

    _LOGD(LOGD_TEAM, "running: %s", (tmp_str = g_strjoinv(" ", (char **) argv->pdata)));
    return g_spawn_async("/",
                         (char **) argv->pdata,
                         (char **) envp,
                         0,
                         teamd_child_setup,
                         NULL,
                         NULL,
                         error);
}

static gboolean
teamd_start(NMDeviceTeam *self)
{
    NMDeviceTeamPrivate         *priv  = NM_DEVICE_TEAM_GET_PRIVATE(self);
    const char                  *iface = nm_device_get_ip_iface(NM_DEVICE(self));
    NMConnection                *connection;
    gs_unref_ptrarray GPtrArray *argv    = NULL;
    gs_free_error GError        *error   = NULL;
    gs_free char                *tmp_str = NULL;
    const char                  *teamd_binary;
    const char                  *config;
    nm_auto_free const char     *config_free = NULL;
    NMSettingTeam               *s_team;
    gs_free char                *cloned_mac = NULL;
    gs_free const char         **envp       = NULL;

    g_return_val_if_fail(!priv->dbus_connection, FALSE);
    g_return_val_if_fail(!priv->teamd_process_watch, FALSE);
    g_return_val_if_fail(priv->teamd_pid <= 0, FALSE);

    connection = nm_device_get_applied_connection(NM_DEVICE(self));
    s_team     = nm_connection_get_setting_team(connection);
    g_return_val_if_fail(s_team, FALSE);

    nm_assert(iface);

    teamd_binary = nm_utils_find_helper("teamd", NULL, NULL);
    if (!teamd_binary) {
        _LOGW(LOGD_TEAM, "Activation: (team) failed to start teamd: teamd binary not found");
        return FALSE;
    }

    /* Start teamd now */
    argv = g_ptr_array_new();
    g_ptr_array_add(argv, (gpointer) teamd_binary);
    g_ptr_array_add(argv, (gpointer) "-o");
    g_ptr_array_add(argv, (gpointer) "-n");
    g_ptr_array_add(argv, (gpointer) "-U");
    g_ptr_array_add(argv, (gpointer) "-D");
    g_ptr_array_add(argv, (gpointer) "-N");
    g_ptr_array_add(argv, (gpointer) "-t");
    g_ptr_array_add(argv, (gpointer) iface);

    config = nm_setting_team_get_config(s_team);
    if (!nm_device_hw_addr_get_cloned(NM_DEVICE(self),
                                      connection,
                                      FALSE,
                                      &cloned_mac,
                                      NULL,
                                      &error)) {
        _LOGW(LOGD_DEVICE, "set-hw-addr: %s", error->message);
        return FALSE;
    }

    if (cloned_mac) {
        json_t      *json, *hwaddr;
        json_error_t jerror;

        /* Inject the hwaddr property into the JSON configuration.
         * While doing so, detect potential conflicts */

        json = json_loads(config ?: "{}", JSON_REJECT_DUPLICATES, &jerror);
        g_return_val_if_fail(json, FALSE);

        hwaddr = json_object_get(json, "hwaddr");
        if (hwaddr) {
            if (!json_is_string(hwaddr) || !nm_streq0(json_string_value(hwaddr), cloned_mac))
                _LOGW(LOGD_TEAM,
                      "set-hw-addr: can't set team cloned-mac-address as the JSON configuration "
                      "already contains \"hwaddr\"");
        } else {
            hwaddr = json_string(cloned_mac);
            json_object_set(json, "hwaddr", hwaddr);
            config = config_free =
                json_dumps(json, JSON_INDENT(0) | JSON_ENSURE_ASCII | JSON_SORT_KEYS);
            _LOGD(LOGD_TEAM,
                  "set-hw-addr: injected \"hwaddr\" \"%s\" into team configuration",
                  cloned_mac);
            json_decref(hwaddr);
        }
        json_decref(json);
    }

    if (config) {
        g_ptr_array_add(argv, (gpointer) "-c");
        g_ptr_array_add(argv, (gpointer) config);
    }

    if (nm_logging_enabled(LOGL_DEBUG, LOGD_TEAM))
        g_ptr_array_add(argv, (gpointer) "-gg");
    g_ptr_array_add(argv, NULL);

    envp = teamd_env();

    _LOGD(LOGD_TEAM, "running: %s", (tmp_str = g_strjoinv(" ", (char **) argv->pdata)));
    if (!g_spawn_async("/",
                       (char **) argv->pdata,
                       (char **) envp,
                       G_SPAWN_DO_NOT_REAP_CHILD,
                       teamd_child_setup,
                       NULL,
                       &priv->teamd_pid,
                       &error)) {
        _LOGW(LOGD_TEAM, "Activation: (team) failed to start teamd: %s", error->message);
        teamd_cleanup(self);
        return FALSE;
    }

    /* Start a timeout for teamd to appear at D-Bus */
    if (!priv->teamd_dbus_timeout)
        priv->teamd_dbus_timeout = g_timeout_add_seconds(5, teamd_dbus_timeout_cb, self);

    /* Monitor the child process so we know when it dies */
    priv->teamd_process_watch = g_child_watch_add(priv->teamd_pid, teamd_process_watch_cb, self);

    _LOGI(LOGD_TEAM, "Activation: (team) started teamd [pid %u]...", (guint) priv->teamd_pid);
    return TRUE;
}

static NMActStageReturn
act_stage1_prepare(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMDeviceTeam        *self = NM_DEVICE_TEAM(device);
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);
    NMSettingTeam       *s_team;

    if (nm_device_sys_iface_state_is_external(device))
        return NM_ACT_STAGE_RETURN_SUCCESS;

    s_team = nm_device_get_applied_setting(device, NM_TYPE_SETTING_TEAM);
    g_return_val_if_fail(s_team, FALSE);

    if (priv->stage1_state == NM_DEVICE_STAGE_STATE_PENDING)
        return NM_ACT_STAGE_RETURN_POSTPONE;

    if (priv->stage1_state == NM_DEVICE_STAGE_STATE_COMPLETED)
        return NM_ACT_STAGE_RETURN_SUCCESS;

    priv->stage1_state = NM_DEVICE_STAGE_STATE_PENDING;

    if (priv->config)
        return NM_ACT_STAGE_RETURN_SUCCESS;

    if (!priv->dbus_connection && !teamd_start(self))
        return NM_ACT_STAGE_RETURN_FAILURE;

    return NM_ACT_STAGE_RETURN_POSTPONE;
}

static void
deactivate(NMDevice *device)
{
    NMDeviceTeam        *self = NM_DEVICE_TEAM(device);
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);

    priv->stage1_state = NM_DEVICE_STAGE_STATE_INIT;

    if (priv->config) {
        nm_clear_g_free(&priv->config);
        _notify(self, PROP_CONFIG);
    }

    if (nm_device_sys_iface_state_is_external(device))
        return;

    if (priv->teamd_pid || priv->dbus_connection)
        _LOGI(LOGD_TEAM, "deactivation: stopping teamd...");

    if (!priv->teamd_pid)
        teamd_kill(self, NULL);

    teamd_cleanup(self);
}

static NMTernary
attach_port(NMDevice                  *device,
            NMDevice                  *port,
            NMConnection              *connection,
            gboolean                   configure,
            GCancellable              *cancellable,
            NMDeviceAttachPortCallback callback,
            gpointer                   user_data)
{
    NMDeviceTeam        *self       = NM_DEVICE_TEAM(device);
    NMDeviceTeamPrivate *priv       = NM_DEVICE_TEAM_GET_PRIVATE(self);
    gboolean             success    = TRUE;
    const char          *port_iface = nm_device_get_ip_iface(port);
    NMSettingTeamPort   *s_team_port;

    nm_device_master_check_slave_physical_port(device, port, LOGD_TEAM);

    if (configure) {
        nm_device_take_down(port, TRUE);

        s_team_port = nm_connection_get_setting_team_port(connection);
        if (s_team_port) {
            char *sanitized_config;

            sanitized_config = g_strdup(nm_setting_team_port_get_config(s_team_port) ?: "{}");
            g_strdelimit(sanitized_config, "\r\n", ' ');

            g_hash_table_insert(priv->port_configs, g_strdup(port_iface), sanitized_config);

            if (!priv->dbus_connection) {
                _LOGW(LOGD_TEAM,
                      "attached team port %s config not changed, not connected to teamd",
                      port_iface);
            } else {
                if (!_update_port_config(self, port_iface, sanitized_config))
                    return FALSE;
            }
        }
        success = nm_platform_link_enslave(nm_device_get_platform(device),
                                           nm_device_get_ip_ifindex(device),
                                           nm_device_get_ip_ifindex(port));
        nm_device_bring_up(port);

        if (!success)
            return FALSE;

        nm_clear_g_source(&priv->teamd_read_timeout);
        priv->teamd_read_timeout = g_timeout_add_seconds(5, teamd_read_timeout_cb, self);

        _LOGI(LOGD_TEAM, "attached team port %s", port_iface);
    } else
        _LOGI(LOGD_TEAM, "team port %s was attached", port_iface);

    return TRUE;
}

static void
detach_port(NMDevice *device, NMDevice *port, gboolean configure)
{
    NMDeviceTeam        *self       = NM_DEVICE_TEAM(device);
    NMDeviceTeamPrivate *priv       = NM_DEVICE_TEAM_GET_PRIVATE(self);
    const char          *port_iface = nm_device_get_ip_iface(port);
    gboolean             do_release, success;
    NMSettingTeamPort   *s_port;
    int                  ifindex_port;
    int                  ifindex;

    do_release = configure;
    if (do_release) {
        ifindex = nm_device_get_ifindex(device);
        if (ifindex <= 0 || !nm_platform_link_get(nm_device_get_platform(device), ifindex))
            do_release = FALSE;
    }

    ifindex_port = nm_device_get_ip_ifindex(port);

    if (ifindex_port <= 0) {
        _LOGD(LOGD_TEAM, "team port %s is already detached", port_iface);
    } else if (do_release) {
        success = nm_platform_link_release(nm_device_get_platform(device),
                                           nm_device_get_ip_ifindex(device),
                                           ifindex_port);
        if (success)
            _LOGI(LOGD_TEAM, "detached team port %s", port_iface);
        else
            _LOGW(LOGD_TEAM, "failed to detach team port %s", port_iface);

        /* Kernel team code "closes" the port when releasing it, (which clears
         * IFF_UP), so we must bring it back up here to ensure carrier changes and
         * other state is noticed by the now-released port.
         */
        if (!nm_device_bring_up(port)) {
            _LOGW(LOGD_TEAM, "detached team port %s could not be brought up", port_iface);
        }

        nm_clear_g_source(&priv->teamd_read_timeout);
        priv->teamd_read_timeout = g_timeout_add_seconds(5, teamd_read_timeout_cb, self);
    } else
        _LOGI(LOGD_TEAM, "team port %s was detached", port_iface);

    /* Delete any port configuration we previously set */
    if (configure && priv->dbus_connection
        && (s_port = nm_device_get_applied_setting(port, NM_TYPE_SETTING_TEAM_PORT))
        && (nm_setting_team_port_get_config(s_port))) {
        _update_port_config(self, port_iface, "{}");
        g_hash_table_remove(priv->port_configs, port_iface);
    }
}

static gboolean
create_and_realize(NMDevice              *device,
                   NMConnection          *connection,
                   NMDevice              *parent,
                   const NMPlatformLink **out_plink,
                   GError               **error)
{
    const char *iface = nm_device_get_iface(device);
    int         r;

    r = nm_platform_link_team_add(nm_device_get_platform(device), iface, out_plink);
    if (r < 0) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_CREATION_FAILED,
                    "Failed to create team master interface '%s' for '%s': %s",
                    iface,
                    nm_connection_get_id(connection),
                    nm_strerror(r));
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceTeam        *self = NM_DEVICE_TEAM(object);
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_CONFIG:
        g_value_set_string(value, priv->config);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_device_team_init(NMDeviceTeam *self)
{
    nm_assert(nm_device_is_master(NM_DEVICE(self)));
}

static void
constructed(GObject *object)
{
    NMDevice              *device = NM_DEVICE(object);
    NMDeviceTeamPrivate   *priv   = NM_DEVICE_TEAM_GET_PRIVATE(device);
    gs_unref_object GFile *file   = NULL;
    gs_free_error GError  *error  = NULL;

    G_OBJECT_CLASS(nm_device_team_parent_class)->constructed(object);

    priv->port_configs = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, g_free);
    priv->dbus_name    = g_strdup_printf("org.libteam.teamd.%s", nm_device_get_ip_iface(device));

    /* Register D-Bus name watcher */
    priv->teamd_dbus_watch = g_bus_watch_name(G_BUS_TYPE_SYSTEM,
                                              priv->dbus_name,
                                              G_BUS_NAME_WATCHER_FLAGS_NONE,
                                              teamd_dbus_appeared,
                                              teamd_dbus_vanished,
                                              NM_DEVICE(device),
                                              NULL);
    return;
}

NMDevice *
nm_device_team_new(const char *iface)
{
    return g_object_new(NM_TYPE_DEVICE_TEAM,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_DRIVER,
                        "team",
                        NM_DEVICE_TYPE_DESC,
                        "Team",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_TEAM,
                        NM_DEVICE_LINK_TYPE,
                        NM_LINK_TYPE_TEAM,
                        NULL);
}

static void
dispose(GObject *object)
{
    NMDeviceTeam        *self = NM_DEVICE_TEAM(object);
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);

    if (priv->teamd_dbus_watch) {
        g_bus_unwatch_name(priv->teamd_dbus_watch);
        priv->teamd_dbus_watch = 0;
    }

    teamd_cleanup(self);
    nm_clear_g_free(&priv->dbus_name);
    nm_clear_g_free(&priv->config);
    nm_clear_pointer(&priv->port_configs, g_hash_table_destroy);

    G_OBJECT_CLASS(nm_device_team_parent_class)->dispose(object);
}

static const NMDBusInterfaceInfoExtended interface_info_device_team = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_TEAM,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("HwAddress", "s", NM_DEVICE_HW_ADDRESS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Carrier", "b", NM_DEVICE_CARRIER),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Slaves", "ao", NM_DEVICE_SLAVES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Config",
                                                           "s",
                                                           NM_DEVICE_TEAM_CONFIG), ), ),
};

static void
nm_device_team_class_init(NMDeviceTeamClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    object_class->constructed  = constructed;
    object_class->dispose      = dispose;
    object_class->get_property = get_property;

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_team);

    device_class->connection_type_supported        = NM_SETTING_TEAM_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_TEAM_SETTING_NAME;
    device_class->link_types                       = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_TEAM);

    device_class->is_master                      = TRUE;
    device_class->create_and_realize             = create_and_realize;
    device_class->get_generic_capabilities       = get_generic_capabilities;
    device_class->complete_connection            = complete_connection;
    device_class->update_connection              = update_connection;
    device_class->master_update_slave_connection = master_update_slave_connection;

    device_class->act_stage1_prepare_also_for_external_or_assume = TRUE;
    device_class->act_stage1_prepare                             = act_stage1_prepare;
    device_class->get_configured_mtu = nm_device_get_configured_mtu_for_wired;
    device_class->deactivate         = deactivate;
    device_class->attach_port        = attach_port;
    device_class->detach_port        = detach_port;

    obj_properties[PROP_CONFIG] = g_param_spec_string(NM_DEVICE_TEAM_CONFIG,
                                                      "",
                                                      "",
                                                      NULL,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
