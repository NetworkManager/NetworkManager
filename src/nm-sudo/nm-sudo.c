/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-prog.h"

#include <gio/gunixfdlist.h>

#include "c-list/src/c-list.h"
#include "libnm-glib-aux/nm-dbus-aux.h"
#include "libnm-glib-aux/nm-io-utils.h"
#include "libnm-glib-aux/nm-logging-base.h"
#include "libnm-glib-aux/nm-shared-utils.h"
#include "libnm-glib-aux/nm-time-utils.h"
#include "libnm-base/nm-sudo-utils.h"

/* nm-sudo doesn't link with libnm-core nor libnm-base, but these headers
 * can be used independently. */
#include "libnm-core-public/nm-dbus-interface.h"

/*****************************************************************************/

#define IDLE_TIMEOUT_MSEC     2000
#define IDLE_TIMEOUT_INFINITY G_MAXINT32

/*****************************************************************************/

/* Serves only the purpose to mark environment variables that are honored by
 * the application. You can search for this macro, and find what options are supported. */
#define _ENV(var) ("" var "")

/*****************************************************************************/

typedef struct _GlobalData GlobalData;

typedef struct {
    CList       pending_jobs_lst;
    GlobalData *gl;
} PendingJobData;

struct _GlobalData {
    GCancellable *   quit_cancellable;
    GDBusConnection *dbus_connection;
    GSource *        source_sigterm;

    CList pending_jobs_lst_head;

    GSource *source_idle_timeout;
    char *   name_owner;
    guint    name_owner_changed_id;
    guint    service_regist_id;
    gint64   start_timestamp_msec;
    guint32  timeout_msec;
    bool     name_owner_initialized;
    bool     service_registered;
    bool     name_requested;

    /* This is controlled by $NM_SUDO_NO_AUTH_FOR_TESTING. It disables authentication
     * of the request, so it is ONLY for testing. */
    bool no_auth_for_testing;

    bool is_shutting_down_quitting;
    bool is_shutting_down_timeout;
    bool is_shutting_down_cleanup;
};

/*****************************************************************************/

static void _pending_job_register_object(GlobalData *gl, GObject *obj);

/*****************************************************************************/

#define _nm_log(level, ...) _nm_log_simple_printf((level), __VA_ARGS__)

#define _NMLOG(level, ...)                 \
    G_STMT_START                           \
    {                                      \
        const NMLogLevel _level = (level); \
                                           \
        if (_nm_logging_enabled(_level)) { \
            _nm_log(_level, __VA_ARGS__);  \
        }                                  \
    }                                      \
    G_STMT_END

/*****************************************************************************/

static void
_handle_ping(GlobalData *gl, GDBusMethodInvocation *invocation, const char *arg)
{
    gs_free char *msg = NULL;
    gint64        running_msec;

    running_msec = nm_utils_clock_gettime_msec(CLOCK_BOOTTIME) - gl->start_timestamp_msec;

    msg = g_strdup_printf("pid=%lu, unique-name=%s, nm-name-owner=%s, since=%" G_GINT64_FORMAT
                          ".%03d%s, pong=%s",
                          (unsigned long) getpid(),
                          g_dbus_connection_get_unique_name(gl->dbus_connection),
                          gl->name_owner ?: "(none)",
                          (gint64) (running_msec / 1000),
                          (int) (running_msec % 1000),
                          gl->no_auth_for_testing ? ", no-auth-for-testing" : "",
                          arg);
    g_dbus_method_invocation_return_value(invocation, g_variant_new("(s)", msg));
}

static void
_handle_get_fd(GlobalData *gl, GDBusMethodInvocation *invocation, guint32 fd_type)
{
    nm_auto_close int fd                 = -1;
    gs_unref_object GUnixFDList *fd_list = NULL;
    gs_free_error GError *error          = NULL;

    if (fd_type != (NMSudoGetFDType) fd_type)
        fd_type = NM_SUDO_GET_FD_TYPE_NONE;

    fd = nm_sudo_utils_open_fd(fd_type, &error);
    if (fd < 0) {
        g_dbus_method_invocation_take_error(invocation, g_steal_pointer(&error));
        return;
    }

    fd_list = g_unix_fd_list_new_from_array(&fd, 1);
    nm_steal_fd(&fd);

    g_dbus_method_invocation_return_value_with_unix_fd_list(invocation, NULL, fd_list);
}

/*****************************************************************************/

static gboolean
_signal_callback_term(gpointer user_data)
{
    GlobalData *gl = user_data;

    _LOGD("sigterm received (%s)",
          c_list_is_empty(&gl->pending_jobs_lst_head) ? "quit mainloop" : "cancel operations");

    gl->is_shutting_down_quitting = TRUE;
    g_cancellable_cancel(gl->quit_cancellable);
    return G_SOURCE_CONTINUE;
}

/*****************************************************************************/

typedef struct {
    GDBusConnection **p_dbus_connection;
    GError **         p_error;
} BusGetData;

static void
_bus_get_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    BusGetData *data = user_data;

    *data->p_dbus_connection = g_bus_get_finish(result, data->p_error);
}

static GDBusConnection *
_bus_get(GCancellable *cancellable, int *out_exit_code)
{
    gs_free_error GError *error                      = NULL;
    gs_unref_object GDBusConnection *dbus_connection = NULL;
    BusGetData                       data            = {
        .p_dbus_connection = &dbus_connection,
        .p_error           = &error,
    };

    g_bus_get(G_BUS_TYPE_SYSTEM, cancellable, _bus_get_cb, &data);

    while (!dbus_connection && !error)
        g_main_context_iteration(NULL, TRUE);

    if (!dbus_connection) {
        gboolean was_cancelled = nm_utils_error_is_cancelled(error);

        NM_SET_OUT(out_exit_code, was_cancelled ? EXIT_SUCCESS : EXIT_FAILURE);
        if (!was_cancelled)
            _LOGE("dbus: failure to get D-Bus connection: %s", error->message);
        return NULL;
    }

    /* On bus-disconnect, GDBus will raise(SIGTERM), which we handle like a
     * regular request to quit. */
    g_dbus_connection_set_exit_on_close(dbus_connection, TRUE);

    _LOGD("dbus: unique name: %s", g_dbus_connection_get_unique_name(dbus_connection));

    return g_steal_pointer(&dbus_connection);
}

/*****************************************************************************/

static void
_name_owner_changed_cb(GDBusConnection *connection,
                       const char *     sender_name,
                       const char *     object_path,
                       const char *     interface_name,
                       const char *     signal_name,
                       GVariant *       parameters,
                       gpointer         user_data)
{
    GlobalData *gl = user_data;
    const char *new_owner;

    if (!gl->name_owner_initialized)
        return;

    if (!g_variant_is_of_type(parameters, G_VARIANT_TYPE("(sss)")))
        return;

    g_variant_get(parameters, "(&s&s&s)", NULL, NULL, &new_owner);
    new_owner = nm_str_not_empty(new_owner);

    _LOGD("%s name-owner changed: %s -> %s",
          NM_DBUS_SERVICE,
          gl->name_owner ?: "(null)",
          new_owner ?: "(null)");

    nm_strdup_reset(&gl->name_owner, new_owner);
}

typedef struct {
    GlobalData *gl;
    char **     p_name_owner;
    gboolean    is_cancelled;
} BusFindNMNameOwnerData;

static void
_bus_find_nm_nameowner_cb(const char *name_owner, GError *error, gpointer user_data)
{
    BusFindNMNameOwnerData *data = user_data;

    *data->p_name_owner              = nm_strdup_not_empty(name_owner);
    data->is_cancelled               = nm_utils_error_is_cancelled(error);
    data->gl->name_owner_initialized = TRUE;
}

static gboolean
_bus_find_nm_nameowner(GlobalData *gl)
{
    BusFindNMNameOwnerData data;
    guint                  name_owner_changed_id;
    gs_free char *         name_owner = NULL;

    name_owner_changed_id =
        nm_dbus_connection_signal_subscribe_name_owner_changed(gl->dbus_connection,
                                                               NM_DBUS_SERVICE,
                                                               _name_owner_changed_cb,
                                                               gl,
                                                               NULL);

    data = (BusFindNMNameOwnerData){
        .gl           = gl,
        .is_cancelled = FALSE,
        .p_name_owner = &name_owner,
    };
    nm_dbus_connection_call_get_name_owner(gl->dbus_connection,
                                           NM_DBUS_SERVICE,
                                           10000,
                                           gl->quit_cancellable,
                                           _bus_find_nm_nameowner_cb,
                                           &data);
    while (!gl->name_owner_initialized)
        g_main_context_iteration(NULL, TRUE);

    if (data.is_cancelled) {
        g_dbus_connection_signal_unsubscribe(gl->dbus_connection, name_owner_changed_id);
        return FALSE;
    }

    gl->name_owner_changed_id = name_owner_changed_id;
    gl->name_owner            = g_steal_pointer(&name_owner);
    return TRUE;
}

/*****************************************************************************/

static void
_bus_method_call(GDBusConnection *      connection,
                 const char *           sender,
                 const char *           object_path,
                 const char *           interface_name,
                 const char *           method_name,
                 GVariant *             parameters,
                 GDBusMethodInvocation *invocation,
                 gpointer               user_data)
{
    GlobalData *gl = user_data;
    const char *arg_s;
    guint32     arg_u;

    nm_assert(nm_streq(object_path, NM_SUDO_DBUS_OBJECT_PATH));
    nm_assert(nm_streq(interface_name, NM_SUDO_DBUS_IFACE_NAME));

    if (!gl->no_auth_for_testing && !nm_streq0(sender, gl->name_owner)) {
        _LOGT("dbus: request sender=%s, %s%s, ACCESS DENIED",
              sender,
              method_name,
              g_variant_get_type_string(parameters));
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_ACCESS_DENIED,
                                              "Access denied");
        return;
    }

    _pending_job_register_object(gl, G_OBJECT(invocation));

    _LOGT("dbus: request sender=%s, %s%s",
          sender,
          method_name,
          g_variant_get_type_string(parameters));

    if (nm_streq(method_name, "Ping")) {
        g_variant_get(parameters, "(&s)", &arg_s);
        _handle_ping(gl, invocation, arg_s);
    } else if (nm_streq(method_name, "GetFD")) {
        g_variant_get(parameters, "(u)", &arg_u);
        _handle_get_fd(gl, invocation, arg_u);
    } else
        nm_assert_not_reached();
}

static GDBusInterfaceInfo *const interface_info = NM_DEFINE_GDBUS_INTERFACE_INFO(
    NM_SUDO_DBUS_IFACE_NAME,
    .methods = NM_DEFINE_GDBUS_METHOD_INFOS(
        NM_DEFINE_GDBUS_METHOD_INFO(
            "Ping",
            .in_args  = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("arg", "s"), ),
            .out_args = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("arg", "s"), ), ),
        NM_DEFINE_GDBUS_METHOD_INFO("GetFD",
                                    .in_args = NM_DEFINE_GDBUS_ARG_INFOS(
                                        NM_DEFINE_GDBUS_ARG_INFO("fd_type", "u"), ), ), ), );

typedef struct {
    GlobalData *gl;
    gboolean    is_waiting;
} BusRegisterServiceRequestNameData;

static void
_bus_register_service_request_name_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    BusRegisterServiceRequestNameData *data = user_data;
    gs_free_error GError *error             = NULL;
    gs_unref_variant GVariant *ret          = NULL;
    gboolean                   success      = FALSE;

    ret = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), res, &error);

    if (nm_utils_error_is_cancelled(error))
        goto out;

    if (error)
        _LOGE("d-bus: failed to request name %s: %s", NM_SUDO_DBUS_BUS_NAME, error->message);
    else {
        guint32 ret_val;

        g_variant_get(ret, "(u)", &ret_val);
        if (ret_val != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
            _LOGW("dbus: request name for %s failed to take name (response %u)",
                  NM_SUDO_DBUS_BUS_NAME,
                  ret_val);
        } else {
            _LOGD("dbus: request name for %s succeeded", NM_SUDO_DBUS_BUS_NAME);
            success = TRUE;
        }
    }

out:
    if (success)
        data->gl->service_registered = TRUE;
    data->is_waiting = FALSE;
}

static void
_bus_register_service(GlobalData *gl)
{
    static const GDBusInterfaceVTable interface_vtable = {
        .method_call = _bus_method_call,
    };
    gs_free_error GError *            error = NULL;
    BusRegisterServiceRequestNameData data;

    nm_assert(!gl->service_registered);

    gl->service_regist_id =
        g_dbus_connection_register_object(gl->dbus_connection,
                                          NM_SUDO_DBUS_OBJECT_PATH,
                                          interface_info,
                                          NM_UNCONST_PTR(GDBusInterfaceVTable, &interface_vtable),
                                          gl,
                                          NULL,
                                          &error);
    if (gl->service_regist_id == 0) {
        _LOGE("dbus: error registering object %s: %s", NM_SUDO_DBUS_OBJECT_PATH, error->message);
        return;
    }

    _LOGD("dbus: object %s registered", NM_SUDO_DBUS_OBJECT_PATH);

    data = (BusRegisterServiceRequestNameData){
        .gl         = gl,
        .is_waiting = TRUE,
    };

    /* regardless whether the request is successful, after we start calling
     * RequestName, we remember that we need to ReleaseName it. */
    gl->name_requested = TRUE;

    g_dbus_connection_call(
        gl->dbus_connection,
        DBUS_SERVICE_DBUS,
        DBUS_PATH_DBUS,
        DBUS_INTERFACE_DBUS,
        "RequestName",
        g_variant_new("(su)",
                      NM_SUDO_DBUS_BUS_NAME,
                      (guint) (DBUS_NAME_FLAG_ALLOW_REPLACEMENT | DBUS_NAME_FLAG_REPLACE_EXISTING)),
        G_VARIANT_TYPE("(u)"),
        G_DBUS_CALL_FLAGS_NONE,
        10000,
        gl->quit_cancellable,
        _bus_register_service_request_name_cb,
        &data);

    /* Note that with D-Bus activation, the first request will already hit us before RequestName
     * completes. */

    while (data.is_waiting)
        g_main_context_iteration(NULL, TRUE);
}

/*****************************************************************************/

static gboolean
_idle_timeout_cb(gpointer user_data)
{
    GlobalData *gl = user_data;

    _LOGT("idle-timeout: expired");
    gl->is_shutting_down_timeout = TRUE;
    return G_SOURCE_CONTINUE;
}

static void
_idle_timeout_restart(GlobalData *gl)
{
    nm_clear_g_source_inst(&gl->source_idle_timeout);

    if (gl->is_shutting_down_quitting)
        return;

    if (gl->is_shutting_down_cleanup)
        return;

    if (!c_list_is_empty(&gl->pending_jobs_lst_head))
        return;

    if (gl->timeout_msec == IDLE_TIMEOUT_INFINITY)
        return;

    nm_assert(gl->timeout_msec < G_MAXINT32);
    G_STATIC_ASSERT_EXPR(G_MAXINT32 < G_MAXUINT);

    _LOGT("idle-timeout: start (%u msec)", gl->timeout_msec);
    gl->source_idle_timeout = nm_g_timeout_add_source(gl->timeout_msec, _idle_timeout_cb, gl);
}

/*****************************************************************************/

static gboolean
_pending_job_register_object_release_on_idle_cb(gpointer data)
{
    PendingJobData *idle_data = data;
    GlobalData *    gl        = idle_data->gl;

    c_list_unlink_stale(&idle_data->pending_jobs_lst);
    nm_g_slice_free(idle_data);

    _idle_timeout_restart(gl);
    return G_SOURCE_REMOVE;
}

static void
_pending_job_register_object_weak_cb(gpointer data, GObject *where_the_object_was)
{
    /* The object might be destroyed on another thread. We need
     * to sync with the main GMainContext by scheduling an idle action
     * there. */
    nm_g_idle_add(_pending_job_register_object_release_on_idle_cb, data);
}

static void
_pending_job_register_object(GlobalData *gl, GObject *obj)
{
    PendingJobData *idle_data;

    /* if we just hit the timeout, we can ignore it. */
    gl->is_shutting_down_timeout = FALSE;

    if (nm_clear_g_source_inst(&gl->source_idle_timeout))
        _LOGT("idle-timeout: suspend timeout for pending request");

    idle_data = g_slice_new(PendingJobData);

    idle_data->gl = gl;
    c_list_link_tail(&gl->pending_jobs_lst_head, &idle_data->pending_jobs_lst);

    g_object_weak_ref(obj, _pending_job_register_object_weak_cb, idle_data);
}

/*****************************************************************************/

static void
_bus_release_name_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    _nm_unused gs_unref_object GObject *keep_alive_object = user_data;

    g_main_context_wakeup(NULL);
}

/*****************************************************************************/

static void
_initial_setup(GlobalData *gl)
{
    gl->no_auth_for_testing =
        _nm_utils_ascii_str_to_int64(g_getenv(_ENV("NM_SUDO_NO_AUTH_FOR_TESTING")), 0, 0, 1, 0);
    gl->timeout_msec = _nm_utils_ascii_str_to_int64(g_getenv(_ENV("NM_SUDO_IDLE_TIMEOUT_MSEC")),
                                                    0,
                                                    0,
                                                    G_MAXINT32,
                                                    IDLE_TIMEOUT_MSEC);

    gl->quit_cancellable = g_cancellable_new();

    signal(SIGPIPE, SIG_IGN);
    gl->source_sigterm = nm_g_unix_signal_add_source(SIGTERM, _signal_callback_term, gl);
}

int
main(int argc, char **argv)
{
    GlobalData _gl = {
        .quit_cancellable      = NULL,
        .pending_jobs_lst_head = C_LIST_INIT(_gl.pending_jobs_lst_head),
    };
    GlobalData *const gl = &_gl;
    int               exit_code;
    int               r = 0;

    _nm_logging_enabled_init(g_getenv(_ENV("NM_SUDO_LOG")));

    gl->start_timestamp_msec = nm_utils_clock_gettime_msec(CLOCK_BOOTTIME);

    _LOGD("starting nm-sudo (%s)", NM_DIST_VERSION);

    _initial_setup(gl);

    if (gl->no_auth_for_testing) {
        _LOGW("WARNING: running in debug mode without authentication "
              "(NM_SUDO_NO_AUTH_FOR_TESTING). ");
    }

    if (gl->timeout_msec != IDLE_TIMEOUT_INFINITY)
        _LOGT("idle-timeout: %u msec", gl->timeout_msec);
    else
        _LOGT("idle-timeout: disabled");

    gl->dbus_connection = _bus_get(gl->quit_cancellable, &r);
    if (!gl->dbus_connection) {
        exit_code = r;
        goto done;
    }

    if (!_bus_find_nm_nameowner(gl)) {
        /* abort due to cancellation. That is success. */
        exit_code = EXIT_SUCCESS;
        goto done;
    }
    _LOGD("%s name-owner: %s", NM_DBUS_SERVICE, gl->name_owner ?: "(null)");

    _idle_timeout_restart(gl);

    exit_code = EXIT_SUCCESS;

    _bus_register_service(gl);
    if (!gl->service_registered) {
        /* We failed to RequestName, but due to D-Bus activation we
         * might have a pending request still (on the unique name).
         * Process it below.
         *
         * Let's fake a shutdown signal, and still process the request below. */
        exit_code                     = EXIT_FAILURE;
        gl->is_shutting_down_quitting = TRUE;
    }

    while (TRUE) {
        if (!c_list_is_empty(&gl->pending_jobs_lst_head)) {
            /* we must first reply to all requests. No matter what. */
        } else if (gl->is_shutting_down_quitting || gl->is_shutting_down_timeout) {
            /* we either hit the idle timeout or received SIGTERM. Note that
             * if we received an idle-timeout and the very moment afterwards
             * a new request, then _bus_method_call() will clear gl->is_shutting_down_timeout
             * (via _pending_job_register_object()). */

            if (gl->name_requested) {
                gs_unref_object GObject *keep_alive_object = g_object_new(G_TYPE_OBJECT, NULL);

                /* We already requested a name. To exit-on-idle without race, we need to dance.
                 * See https://lists.freedesktop.org/archives/dbus/2015-May/016671.html . */

                gl->name_requested            = FALSE;
                gl->is_shutting_down_quitting = TRUE;

                _LOGT("shutdown: release-name");

                /* we use the _pending_job_register_object() mechanism to make the loop busy during
                 * shutdown. */
                _pending_job_register_object(gl, keep_alive_object);

                r = nm_sd_notify("STOPPING=1");
                if (r < 0)
                    _LOGW("shutdown: sd_notifiy(STOPPING=1) failed: %s", nm_strerror_native(-r));
                else
                    _LOGT("shutdown: sd_notifiy(STOPPING=1) succeeded");

                g_dbus_connection_call(gl->dbus_connection,
                                       DBUS_SERVICE_DBUS,
                                       DBUS_PATH_DBUS,
                                       DBUS_INTERFACE_DBUS,
                                       "ReleaseName",
                                       g_variant_new("(s)", NM_SUDO_DBUS_BUS_NAME),
                                       G_VARIANT_TYPE("(u)"),
                                       G_DBUS_CALL_FLAGS_NONE,
                                       10000,
                                       NULL,
                                       _bus_release_name_cb,
                                       g_steal_pointer(&keep_alive_object));
                continue;
            }

            break;
        }

        g_main_context_iteration(NULL, TRUE);
    }

done:
    gl->is_shutting_down_cleanup = TRUE;
    _LOGD("shutdown: cleanup");

    nm_assert(c_list_is_empty(&gl->pending_jobs_lst_head));

    if (gl->service_regist_id != 0) {
        g_dbus_connection_unregister_object(gl->dbus_connection,
                                            nm_steal_int(&gl->service_regist_id));
    }
    if (gl->name_owner_changed_id != 0) {
        g_dbus_connection_signal_unsubscribe(gl->dbus_connection,
                                             nm_steal_int(&gl->name_owner_changed_id));
    }
    nm_clear_g_cancellable(&gl->quit_cancellable);
    nm_clear_g_source_inst(&gl->source_sigterm);
    nm_clear_g_source_inst(&gl->source_idle_timeout);
    nm_clear_g_free(&gl->name_owner);

    while (g_main_context_iteration(NULL, FALSE)) {
        ;
    }

    if (gl->dbus_connection) {
        g_dbus_connection_flush_sync(gl->dbus_connection, NULL, NULL);
        g_clear_object(&gl->dbus_connection);

        while (g_main_context_iteration(NULL, FALSE)) {
            ;
        }
    }

    _LOGD("exit (%d)", exit_code);
    return exit_code;
}
