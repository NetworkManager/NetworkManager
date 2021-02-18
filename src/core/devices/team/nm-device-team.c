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

#include "nm-glib-aux/nm-jansson.h"
#include "NetworkManagerUtils.h"
#include "devices/nm-device-private.h"
#include "platform/nm-platform.h"
#include "nm-config.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-dbus-manager.h"
#include "nm-ip4-config.h"
#include "nm-std-aux/nm-dbus-compat.h"

#define _NMLOG_DEVICE_TYPE NMDeviceTeam
#include "devices/nm-device-logging.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMDeviceTeam, PROP_CONFIG, );

typedef struct {
    struct teamdctl *  tdc;
    char *             config;
    GPid               teamd_pid;
    guint              teamd_process_watch;
    guint              teamd_timeout;
    guint              teamd_read_timeout;
    guint              teamd_dbus_watch;
    bool               kill_in_progress : 1;
    GFileMonitor *     usock_monitor;
    NMDeviceStageState stage1_state : 3;
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
complete_connection(NMDevice *           device,
                    NMConnection *       connection,
                    const char *         specific_object,
                    NMConnection *const *existing_connections,
                    GError **            error)
{
    NMSettingTeam *s_team;

    nm_utils_complete_generic(nm_device_get_platform(device),
                              connection,
                              NM_SETTING_TEAM_SETTING_NAME,
                              existing_connections,
                              NULL,
                              _("Team connection"),
                              "team",
                              NULL,
                              TRUE);

    s_team = nm_connection_get_setting_team(connection);
    if (!s_team) {
        s_team = (NMSettingTeam *) nm_setting_team_new();
        nm_connection_add_setting(connection, NM_SETTING(s_team));
    }

    return TRUE;
}

static gboolean
ensure_teamd_connection(NMDevice *device)
{
    NMDeviceTeam *       self = NM_DEVICE_TEAM(device);
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);
    int                  err;

    if (priv->tdc)
        return TRUE;

    priv->tdc = teamdctl_alloc();
    g_assert(priv->tdc);
    err = teamdctl_connect(priv->tdc, nm_device_get_iface(device), NULL, NULL);
    if (err != 0) {
        _LOGE(LOGD_TEAM, "failed to connect to teamd (err=%d)", err);
        teamdctl_free(priv->tdc);
        priv->tdc = NULL;
    }

    return !!priv->tdc;
}

static const char *
_get_config(NMDeviceTeam *self)
{
    return nm_str_not_empty(NM_DEVICE_TEAM_GET_PRIVATE(self)->config);
}

static gboolean
teamd_read_config(NMDeviceTeam *self)
{
    NMDeviceTeamPrivate *priv   = NM_DEVICE_TEAM_GET_PRIVATE(self);
    const char *         config = NULL;
    int                  err;

    if (priv->tdc) {
        err = teamdctl_config_actual_get_raw_direct(priv->tdc, (char **) &config);
        if (err)
            return FALSE;
        if (!config) {
            /* set "" to distinguish an empty result from no config at all. */
            config = "";
        }
    }

    if (!nm_streq0(config, priv->config)) {
        g_free(priv->config);
        priv->config = g_strdup(config);
        _notify(self, PROP_CONFIG);
    }

    return TRUE;
}

static gboolean
teamd_read_timeout_cb(gpointer user_data)
{
    NMDeviceTeam *       self = user_data;
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);

    priv->teamd_read_timeout = 0;
    teamd_read_config(self);
    return G_SOURCE_REMOVE;
}

static void
update_connection(NMDevice *device, NMConnection *connection)
{
    NMDeviceTeam *       self   = NM_DEVICE_TEAM(device);
    NMSettingTeam *      s_team = nm_connection_get_setting_team(connection);
    NMDeviceTeamPrivate *priv   = NM_DEVICE_TEAM_GET_PRIVATE(self);
    struct teamdctl *    tdc    = priv->tdc;

    if (!s_team) {
        s_team = (NMSettingTeam *) nm_setting_team_new();
        nm_connection_add_setting(connection, (NMSetting *) s_team);
    }

    /* Read the configuration only if not already set */
    if (!priv->config && ensure_teamd_connection(device))
        teamd_read_config(self);

    /* Restore previous tdc state */
    if (priv->tdc && !tdc) {
        teamdctl_disconnect(priv->tdc);
        teamdctl_free(priv->tdc);
        priv->tdc = NULL;
    }

    g_object_set(G_OBJECT(s_team), NM_SETTING_TEAM_CONFIG, _get_config(self), NULL);
}

/*****************************************************************************/

static gboolean
master_update_slave_connection(NMDevice *    self,
                               NMDevice *    slave,
                               NMConnection *connection,
                               GError **     error)
{
    NMSettingTeamPort *s_port;
    char *             port_config = NULL;
    int                err         = 0;
    struct teamdctl *  tdc;
    const char *       team_port_config = NULL;
    const char *       iface            = nm_device_get_iface(self);
    const char *       iface_slave      = nm_device_get_iface(slave);

    tdc = teamdctl_alloc();
    if (!tdc) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_FAILED,
                    "update slave connection for slave '%s' failed to connect to teamd for master "
                    "%s (out of memory?)",
                    iface_slave,
                    iface);
        g_return_val_if_reached(FALSE);
    }

    err = teamdctl_connect(tdc, iface, NULL, NULL);
    if (err) {
        teamdctl_free(tdc);
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_FAILED,
                    "update slave connection for slave '%s' failed to connect to teamd for master "
                    "%s (err=%d)",
                    iface_slave,
                    iface,
                    err);
        return FALSE;
    }

    err = teamdctl_port_config_get_raw_direct(tdc, iface_slave, (char **) &team_port_config);
    port_config = g_strdup(team_port_config);
    teamdctl_disconnect(tdc);
    teamdctl_free(tdc);
    if (err) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_FAILED,
                    "update slave connection for slave '%s' failed to get configuration from teamd "
                    "master %s (err=%d)",
                    iface_slave,
                    iface,
                    err);
        g_free(port_config);
        return FALSE;
    }

    s_port = nm_connection_get_setting_team_port(connection);
    if (!s_port) {
        s_port = (NMSettingTeamPort *) nm_setting_team_port_new();
        nm_connection_add_setting(connection, NM_SETTING(s_port));
    }

    g_object_set(G_OBJECT(s_port), NM_SETTING_TEAM_PORT_CONFIG, port_config, NULL);
    g_free(port_config);

    g_object_set(nm_connection_get_setting_connection(connection),
                 NM_SETTING_CONNECTION_MASTER,
                 iface,
                 NM_SETTING_CONNECTION_SLAVE_TYPE,
                 NM_SETTING_TEAM_SETTING_NAME,
                 NULL);
    return TRUE;
}

/*****************************************************************************/

static void
teamd_kill_cb(pid_t pid, gboolean success, int child_status, void *user_data)
{
    gs_unref_object NMDeviceTeam *self = user_data;
    NMDeviceTeamPrivate *         priv = NM_DEVICE_TEAM_GET_PRIVATE(self);

    priv->kill_in_progress = FALSE;

    if (nm_device_get_state(NM_DEVICE(self)) != NM_DEVICE_STATE_PREPARE) {
        _LOGT(LOGD_TEAM, "kill terminated");
        return;
    }

    _LOGT(LOGD_TEAM, "kill terminated, starting teamd...");
    if (!teamd_start(self)) {
        nm_device_state_changed(NM_DEVICE(self),
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED);
    }
}

static void
teamd_cleanup(NMDeviceTeam *self, gboolean free_tdc)
{
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);

    nm_clear_g_source(&priv->teamd_process_watch);
    nm_clear_g_source(&priv->teamd_timeout);
    nm_clear_g_source(&priv->teamd_read_timeout);

    if (priv->teamd_pid > 0) {
        priv->kill_in_progress = TRUE;
        nm_utils_kill_child_async(priv->teamd_pid,
                                  SIGTERM,
                                  LOGD_TEAM,
                                  "teamd",
                                  2000,
                                  teamd_kill_cb,
                                  g_object_ref(self));
        priv->teamd_pid = 0;
    }

    if (priv->tdc && free_tdc) {
        teamdctl_disconnect(priv->tdc);
        teamdctl_free(priv->tdc);
        priv->tdc = NULL;
    }
}

static gboolean
teamd_timeout_cb(gpointer user_data)
{
    NMDeviceTeam *       self   = NM_DEVICE_TEAM(user_data);
    NMDevice *           device = NM_DEVICE(self);
    NMDeviceTeamPrivate *priv   = NM_DEVICE_TEAM_GET_PRIVATE(self);

    g_return_val_if_fail(priv->teamd_timeout, FALSE);
    priv->teamd_timeout = 0;

    if (priv->teamd_pid && !priv->tdc) {
        /* Timed out launching our own teamd process */
        _LOGW(LOGD_TEAM, "teamd timed out");
        teamd_cleanup(self, TRUE);

        g_warn_if_fail(nm_device_is_activating(device));
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED);
    } else {
        /* Read again the configuration after the timeout since it might
         * have changed.
         */
        if (!teamd_read_config(self)) {
            _LOGW(LOGD_TEAM, "failed to read teamd configuration");
            nm_device_state_changed(device,
                                    NM_DEVICE_STATE_FAILED,
                                    NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED);
        }
    }

    return G_SOURCE_REMOVE;
}

static void
teamd_ready(NMDeviceTeam *self)
{
    NMDeviceTeamPrivate *priv   = NM_DEVICE_TEAM_GET_PRIVATE(self);
    NMDevice *           device = NM_DEVICE(self);
    gboolean             success;

    if (priv->kill_in_progress) {
        /* If we are currently killing teamd, we are not
         * interested in knowing when it becomes ready. */
        return;
    }

    nm_device_queue_recheck_assume(device);

    /* Grab a teamd control handle even if we aren't going to use it
     * immediately.  But if we are, and grabbing it failed, fail the
     * device activation.
     */
    success = ensure_teamd_connection(device);

    if (nm_device_get_state(device) != NM_DEVICE_STATE_PREPARE
        || priv->stage1_state != NM_DEVICE_STAGE_STATE_PENDING)
        return;

    if (success)
        success = teamd_read_config(self);

    if (!success) {
        teamd_cleanup(self, TRUE);
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED);
        return;
    }

    priv->stage1_state = NM_DEVICE_STAGE_STATE_COMPLETED;
    nm_device_activate_schedule_stage1_device_prepare(device, FALSE);
}

static void
teamd_gone(NMDeviceTeam *self)
{
    NMDevice *    device = NM_DEVICE(self);
    NMDeviceState state;

    teamd_cleanup(self, TRUE);
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
teamd_dbus_appeared(GDBusConnection *connection,
                    const char *     name,
                    const char *     name_owner,
                    gpointer         user_data)
{
    NMDeviceTeam *       self = NM_DEVICE_TEAM(user_data);
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);

    g_return_if_fail(priv->teamd_dbus_watch);

    _LOGI(LOGD_TEAM, "teamd appeared on D-Bus");

    /* If another teamd grabbed the bus name while our teamd was starting,
     * just ignore the death of our teamd and run with the existing one.
     */
    if (priv->teamd_process_watch) {
        gs_unref_variant GVariant *ret = NULL;
        guint32                    pid;

        ret = g_dbus_connection_call_sync(connection,
                                          DBUS_SERVICE_DBUS,
                                          DBUS_PATH_DBUS,
                                          DBUS_INTERFACE_DBUS,
                                          "GetConnectionUnixProcessID",
                                          g_variant_new("(s)", name_owner),
                                          NULL,
                                          G_DBUS_CALL_FLAGS_NO_AUTO_START,
                                          2000,
                                          NULL,
                                          NULL);

        if (ret) {
            g_variant_get(ret, "(u)", &pid);
            if (pid != priv->teamd_pid)
                teamd_cleanup(self, FALSE);
        } else {
            /* The process that registered on the bus died. If it's
             * the teamd instance we just started, ignore the event
             * as we already detect the failure through the process
             * watch. If it's a previous instance that got killed,
             * also ignore that as our new instance will register
             * again. */
            _LOGD(LOGD_TEAM, "failed to determine D-Bus name owner, ignoring");
            return;
        }
    }

    teamd_ready(self);
}

static void
teamd_dbus_vanished(GDBusConnection *dbus_connection, const char *name, gpointer user_data)
{
    NMDeviceTeam *       self = NM_DEVICE_TEAM(user_data);
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);

    g_return_if_fail(priv->teamd_dbus_watch);

    if (!priv->tdc) {
        /* g_bus_watch_name will always raise an initial signal, to indicate whether the
         * name exists/not exists initially. Do not take this as a failure if it hadn't
         * previously appeared.
         */
        _LOGD(LOGD_TEAM, "teamd not on D-Bus (ignored)");
        return;
    }

    _LOGI(LOGD_TEAM, "teamd vanished from D-Bus");

    teamd_gone(self);
}

static void
monitor_changed_cb(GFileMonitor *    monitor,
                   GFile *           file,
                   GFile *           other_file,
                   GFileMonitorEvent event_type,
                   gpointer          user_data)
{
    NMDeviceTeam *self = NM_DEVICE_TEAM(user_data);

    switch (event_type) {
    case G_FILE_MONITOR_EVENT_CREATED:
        _LOGI(LOGD_TEAM, "file %s was created", g_file_get_path(file));
        teamd_ready(self);
        break;
    case G_FILE_MONITOR_EVENT_DELETED:
        _LOGI(LOGD_TEAM, "file %s was deleted", g_file_get_path(file));
        teamd_gone(self);
        break;
    default:;
    }
}

static void
teamd_process_watch_cb(GPid pid, int status, gpointer user_data)
{
    NMDeviceTeam *       self   = NM_DEVICE_TEAM(user_data);
    NMDeviceTeamPrivate *priv   = NM_DEVICE_TEAM_GET_PRIVATE(self);
    NMDevice *           device = NM_DEVICE(self);
    NMDeviceState        state  = nm_device_get_state(device);

    g_return_if_fail(priv->teamd_process_watch);

    _LOGD(LOGD_TEAM, "teamd %lld died with status %d", (long long) pid, status);
    priv->teamd_pid           = 0;
    priv->teamd_process_watch = 0;

    /* If teamd quit within 5 seconds of starting, it's probably hosed
     * and will just die again, so fail the activation.
     */
    if (priv->teamd_timeout && (state >= NM_DEVICE_STATE_PREPARE)
        && (state <= NM_DEVICE_STATE_ACTIVATED)) {
        _LOGW(LOGD_TEAM,
              "teamd process %lld quit unexpectedly; failing activation",
              (long long) pid);
        teamd_cleanup(self, TRUE);
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED);
    }
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
teamd_kill(NMDeviceTeam *self, const char *teamd_binary, GError **error)
{
    gs_unref_ptrarray GPtrArray *argv    = NULL;
    gs_free char *               tmp_str = NULL;
    gs_free const char **        envp    = NULL;

    if (!teamd_binary) {
        teamd_binary = nm_utils_find_helper("teamd", NULL, error);
        if (!teamd_binary) {
            _LOGW(LOGD_TEAM, "Activation: (team) failed to start teamd: teamd binary not found");
            return FALSE;
        }
    }

    argv = g_ptr_array_new();
    g_ptr_array_add(argv, (gpointer) teamd_binary);
    g_ptr_array_add(argv, (gpointer) "-k");
    g_ptr_array_add(argv, (gpointer) "-t");
    g_ptr_array_add(argv, (gpointer) nm_device_get_iface(NM_DEVICE(self)));
    g_ptr_array_add(argv, NULL);

    envp = teamd_env();

    _LOGD(LOGD_TEAM, "running: %s", (tmp_str = g_strjoinv(" ", (char **) argv->pdata)));
    return g_spawn_sync("/",
                        (char **) argv->pdata,
                        (char **) envp,
                        0,
                        teamd_child_setup,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        error);
}

static gboolean
teamd_start(NMDeviceTeam *self)
{
    NMDeviceTeamPrivate *priv  = NM_DEVICE_TEAM_GET_PRIVATE(self);
    const char *         iface = nm_device_get_ip_iface(NM_DEVICE(self));
    NMConnection *       connection;
    gs_unref_ptrarray GPtrArray *argv = NULL;
    gs_free_error GError *   error    = NULL;
    gs_free char *           tmp_str  = NULL;
    const char *             teamd_binary;
    const char *             config;
    nm_auto_free const char *config_free = NULL;
    NMSettingTeam *          s_team;
    gs_free char *           cloned_mac = NULL;
    gs_free const char **    envp       = NULL;

    connection = nm_device_get_applied_connection(NM_DEVICE(self));

    s_team = nm_connection_get_setting_team(connection);
    if (!s_team)
        g_return_val_if_reached(FALSE);

    nm_assert(iface);

    teamd_binary = nm_utils_find_helper("teamd", NULL, NULL);
    if (!teamd_binary) {
        _LOGW(LOGD_TEAM, "Activation: (team) failed to start teamd: teamd binary not found");
        return FALSE;
    }

    if (priv->teamd_process_watch || priv->teamd_pid > 0 || priv->tdc) {
        g_warn_if_reached();
        if (!priv->teamd_pid)
            teamd_kill(self, teamd_binary, NULL);
        teamd_cleanup(self, TRUE);
    }

    /* Start teamd now */
    argv = g_ptr_array_new();
    g_ptr_array_add(argv, (gpointer) teamd_binary);
    g_ptr_array_add(argv, (gpointer) "-o");
    g_ptr_array_add(argv, (gpointer) "-n");
    g_ptr_array_add(argv, (gpointer) "-U");
    if (priv->teamd_dbus_watch)
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
        json_t *     json, *hwaddr;
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
        teamd_cleanup(self, TRUE);
        return FALSE;
    }

    /* Start a timeout for teamd to appear at D-Bus */
    if (!priv->teamd_timeout)
        priv->teamd_timeout = g_timeout_add_seconds(5, teamd_timeout_cb, self);

    /* Monitor the child process so we know when it dies */
    priv->teamd_process_watch = g_child_watch_add(priv->teamd_pid, teamd_process_watch_cb, self);

    _LOGI(LOGD_TEAM, "Activation: (team) started teamd [pid %u]...", (guint) priv->teamd_pid);
    return TRUE;
}

static NMActStageReturn
act_stage1_prepare(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMDeviceTeam *       self   = NM_DEVICE_TEAM(device);
    NMDeviceTeamPrivate *priv   = NM_DEVICE_TEAM_GET_PRIVATE(self);
    gs_free_error GError *error = NULL;
    NMSettingTeam *       s_team;
    const char *          cfg;

    if (nm_device_sys_iface_state_is_external(device))
        return NM_ACT_STAGE_RETURN_SUCCESS;

    if (nm_device_sys_iface_state_is_external_or_assume(device)) {
        if (ensure_teamd_connection(device))
            return NM_ACT_STAGE_RETURN_SUCCESS;
    }

    s_team = nm_device_get_applied_setting(device, NM_TYPE_SETTING_TEAM);
    if (!s_team)
        g_return_val_if_reached(NM_ACT_STAGE_RETURN_FAILURE);

    if (priv->stage1_state == NM_DEVICE_STAGE_STATE_PENDING)
        return NM_ACT_STAGE_RETURN_POSTPONE;

    if (priv->stage1_state == NM_DEVICE_STAGE_STATE_COMPLETED)
        return NM_ACT_STAGE_RETURN_SUCCESS;

    priv->stage1_state = NM_DEVICE_STAGE_STATE_PENDING;

    if (priv->tdc) {
        /* If the existing teamd config is the same as we're about to use,
         * then we can proceed.  If it's not the same, and we have a PID,
         * kill it so we can respawn it with the right config.  If we don't
         * have a PID, then we must fail.
         */
        cfg = teamdctl_config_get_raw(priv->tdc);
        if (cfg && nm_streq0(cfg, nm_setting_team_get_config(s_team))) {
            _LOGD(LOGD_TEAM, "using existing matching teamd config");
            return NM_ACT_STAGE_RETURN_SUCCESS;
        }

        if (!priv->teamd_pid) {
            _LOGD(LOGD_TEAM, "existing teamd config mismatch; killing existing via teamdctl");
            if (!teamd_kill(self, NULL, &error)) {
                _LOGW(LOGD_TEAM,
                      "existing teamd config mismatch; failed to kill existing teamd: %s",
                      error->message);
                NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED);
                return NM_ACT_STAGE_RETURN_FAILURE;
            }
        }

        _LOGD(LOGD_TEAM, "existing teamd config mismatch; respawning...");
        teamd_cleanup(self, TRUE);
    }

    if (priv->kill_in_progress) {
        _LOGT(LOGD_TEAM, "kill in progress, wait before starting teamd");
        return NM_ACT_STAGE_RETURN_POSTPONE;
    }

    if (!teamd_start(self))
        return NM_ACT_STAGE_RETURN_FAILURE;

    return NM_ACT_STAGE_RETURN_POSTPONE;
}

static void
deactivate(NMDevice *device)
{
    NMDeviceTeam *       self = NM_DEVICE_TEAM(device);
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);

    priv->stage1_state = NM_DEVICE_STAGE_STATE_INIT;

    if (nm_device_sys_iface_state_is_external(device))
        return;

    if (priv->teamd_pid || priv->tdc)
        _LOGI(LOGD_TEAM, "deactivation: stopping teamd...");

    if (!priv->teamd_pid)
        teamd_kill(self, NULL, NULL);

    teamd_cleanup(self, TRUE);
}

static gboolean
enslave_slave(NMDevice *device, NMDevice *slave, NMConnection *connection, gboolean configure)
{
    NMDeviceTeam *       self        = NM_DEVICE_TEAM(device);
    NMDeviceTeamPrivate *priv        = NM_DEVICE_TEAM_GET_PRIVATE(self);
    gboolean             success     = TRUE;
    const char *         slave_iface = nm_device_get_ip_iface(slave);
    NMSettingTeamPort *  s_team_port;

    nm_device_master_check_slave_physical_port(device, slave, LOGD_TEAM);

    if (configure) {
        nm_device_take_down(slave, TRUE);

        s_team_port = nm_connection_get_setting_team_port(connection);
        if (s_team_port) {
            const char *config = nm_setting_team_port_get_config(s_team_port);

            if (config) {
                if (!priv->tdc) {
                    _LOGW(LOGD_TEAM,
                          "enslaved team port %s config not changed, not connected to teamd",
                          slave_iface);
                } else {
                    int   err;
                    char *sanitized_config;

                    sanitized_config = g_strdelimit(g_strdup(config), "\r\n", ' ');
                    err = teamdctl_port_config_update_raw(priv->tdc, slave_iface, sanitized_config);
                    g_free(sanitized_config);
                    if (err != 0) {
                        _LOGE(LOGD_TEAM,
                              "failed to update config for port %s (err=%d)",
                              slave_iface,
                              err);
                        return FALSE;
                    }
                }
            }
        }
        success = nm_platform_link_enslave(nm_device_get_platform(device),
                                           nm_device_get_ip_ifindex(device),
                                           nm_device_get_ip_ifindex(slave));
        nm_device_bring_up(slave, TRUE, NULL);

        if (!success)
            return FALSE;

        nm_clear_g_source(&priv->teamd_read_timeout);
        priv->teamd_read_timeout = g_timeout_add_seconds(5, teamd_read_timeout_cb, self);

        _LOGI(LOGD_TEAM, "enslaved team port %s", slave_iface);
    } else
        _LOGI(LOGD_TEAM, "team port %s was enslaved", slave_iface);

    return TRUE;
}

static void
release_slave(NMDevice *device, NMDevice *slave, gboolean configure)
{
    NMDeviceTeam *       self = NM_DEVICE_TEAM(device);
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);
    gboolean             do_release, success;
    NMSettingTeamPort *  s_port;
    int                  ifindex_slave;
    int                  ifindex;

    do_release = configure;
    if (do_release) {
        ifindex = nm_device_get_ifindex(device);
        if (ifindex <= 0 || !nm_platform_link_get(nm_device_get_platform(device), ifindex))
            do_release = FALSE;
    }

    ifindex_slave = nm_device_get_ip_ifindex(slave);

    if (ifindex_slave <= 0) {
        _LOGD(LOGD_TEAM, "team port %s is already released", nm_device_get_ip_iface(slave));
    } else if (do_release) {
        success = nm_platform_link_release(nm_device_get_platform(device),
                                           nm_device_get_ip_ifindex(device),
                                           ifindex_slave);
        if (success)
            _LOGI(LOGD_TEAM, "released team port %s", nm_device_get_ip_iface(slave));
        else
            _LOGW(LOGD_TEAM, "failed to release team port %s", nm_device_get_ip_iface(slave));

        /* Kernel team code "closes" the port when releasing it, (which clears
         * IFF_UP), so we must bring it back up here to ensure carrier changes and
         * other state is noticed by the now-released port.
         */
        if (!nm_device_bring_up(slave, TRUE, NULL)) {
            _LOGW(LOGD_TEAM,
                  "released team port %s could not be brought up",
                  nm_device_get_ip_iface(slave));
        }

        nm_clear_g_source(&priv->teamd_read_timeout);
        priv->teamd_read_timeout = g_timeout_add_seconds(5, teamd_read_timeout_cb, self);
    } else
        _LOGI(LOGD_TEAM, "team port %s was released", nm_device_get_ip_iface(slave));

    /* Delete any port configuration we previously set */
    if (configure && priv->tdc
        && (s_port = nm_device_get_applied_setting(slave, NM_TYPE_SETTING_TEAM_PORT))
        && (nm_setting_team_port_get_config(s_port)))
        teamdctl_port_config_update_raw(priv->tdc, nm_device_get_ip_iface(slave), "{}");
}

static gboolean
create_and_realize(NMDevice *             device,
                   NMConnection *         connection,
                   NMDevice *             parent,
                   const NMPlatformLink **out_plink,
                   GError **              error)
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
    NMDeviceTeam *self = NM_DEVICE_TEAM(object);

    switch (prop_id) {
    case PROP_CONFIG:
        g_value_set_string(value, _get_config(self));
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
    NMDevice *           device  = NM_DEVICE(object);
    NMDeviceTeamPrivate *priv    = NM_DEVICE_TEAM_GET_PRIVATE(device);
    gs_free char *       tmp_str = NULL;
    gs_unref_object GFile *file  = NULL;
    GError *               error;

    G_OBJECT_CLASS(nm_device_team_parent_class)->constructed(object);

    if (nm_dbus_manager_get_dbus_connection(nm_dbus_manager_get())) {
        /* Register D-Bus name watcher */
        tmp_str = g_strdup_printf("org.libteam.teamd.%s", nm_device_get_ip_iface(device));
        priv->teamd_dbus_watch = g_bus_watch_name(G_BUS_TYPE_SYSTEM,
                                                  tmp_str,
                                                  G_BUS_NAME_WATCHER_FLAGS_NONE,
                                                  teamd_dbus_appeared,
                                                  teamd_dbus_vanished,
                                                  NM_DEVICE(device),
                                                  NULL);
        return;
    }

    /* No D-Bus, watch unix socket */
    tmp_str             = g_strdup_printf("/run/teamd/%s.sock", nm_device_get_ip_iface(device));
    file                = g_file_new_for_path(tmp_str);
    priv->usock_monitor = g_file_monitor_file(file, G_FILE_MONITOR_NONE, NULL, &error);
    if (!priv->usock_monitor) {
        nm_log_warn(LOGD_TEAM, "error monitoring %s: %s", tmp_str, error->message);
    } else {
        g_signal_connect(priv->usock_monitor, "changed", G_CALLBACK(monitor_changed_cb), object);
    }
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
    NMDeviceTeam *       self = NM_DEVICE_TEAM(object);
    NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE(self);

    if (priv->teamd_dbus_watch) {
        g_bus_unwatch_name(priv->teamd_dbus_watch);
        priv->teamd_dbus_watch = 0;
    }

    if (priv->usock_monitor) {
        g_signal_handlers_disconnect_by_data(priv->usock_monitor, object);
        g_clear_object(&priv->usock_monitor);
    }

    teamd_cleanup(self, TRUE);
    nm_clear_g_free(&priv->config);

    G_OBJECT_CLASS(nm_device_team_parent_class)->dispose(object);
}

static const NMDBusInterfaceInfoExtended interface_info_device_team = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_TEAM,
        .signals    = NM_DEFINE_GDBUS_SIGNAL_INFOS(&nm_signal_info_property_changed_legacy, ),
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L("HwAddress",
                                                             "s",
                                                             NM_DEVICE_HW_ADDRESS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L("Carrier", "b", NM_DEVICE_CARRIER),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L("Slaves", "ao", NM_DEVICE_SLAVES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L("Config",
                                                             "s",
                                                             NM_DEVICE_TEAM_CONFIG), ), ),
    .legacy_property_changed = TRUE,
};

static void
nm_device_team_class_init(NMDeviceTeamClass *klass)
{
    GObjectClass *     object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass *    device_class      = NM_DEVICE_CLASS(klass);

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
    device_class->enslave_slave      = enslave_slave;
    device_class->release_slave      = release_slave;

    obj_properties[PROP_CONFIG] = g_param_spec_string(NM_DEVICE_TEAM_CONFIG,
                                                      "",
                                                      "",
                                                      NULL,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
