/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2010 - 2015 Red Hat, Inc.
 */

#include "libnm-client-impl/nm-default-libnm.h"

#include <sys/wait.h>

#include "NetworkManager.h"
#include "libnm-std-aux/nm-dbus-compat.h"

#include "libnm-client-test/nm-test-libnm-utils.h"

#define NMTSTC_NM_SERVICE NM_BUILD_SRCDIR "/tools/test-networkmanager-service.py"

/*****************************************************************************/

static gboolean
name_exists(GDBusConnection *c, const char *name)
{
    GVariant *reply;
    gboolean  exists = FALSE;

    reply = g_dbus_connection_call_sync(c,
                                        DBUS_SERVICE_DBUS,
                                        DBUS_PATH_DBUS,
                                        DBUS_INTERFACE_DBUS,
                                        "GetNameOwner",
                                        g_variant_new("(s)", name),
                                        NULL,
                                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
                                        -1,
                                        NULL,
                                        NULL);
    if (reply != NULL) {
        exists = TRUE;
        g_variant_unref(reply);
    }

    return exists;
}

typedef struct {
    GMainLoop       *mainloop;
    GDBusConnection *bus;
    int              exit_code;
    bool             exited : 1;
    bool             name_found : 1;
} ServiceInitWaitData;

static gboolean
_service_init_wait_probe_name(gpointer user_data)
{
    ServiceInitWaitData *data = user_data;

    if (!name_exists(data->bus, "org.freedesktop.NetworkManager"))
        return G_SOURCE_CONTINUE;

    data->name_found = TRUE;
    g_main_loop_quit(data->mainloop);
    return G_SOURCE_REMOVE;
}

static void
_service_init_wait_child_wait(GPid pid, int status, gpointer user_data)
{
    ServiceInitWaitData *data = user_data;

    data->exited    = TRUE;
    data->exit_code = status;
    g_main_loop_quit(data->mainloop);
}

NMTstcServiceInfo *
nmtstc_service_available(NMTstcServiceInfo *info)
{
    gs_free char *m = NULL;

    if (info)
        return info;

    /* This happens, when test-networkmanager-service.py exits with 77 status
     * code. */
    m = g_strdup_printf("missing dependency for running NetworkManager stub service %s",
                        NMTSTC_NM_SERVICE);
    g_test_skip(m);
    return NULL;
}

NMTstcServiceInfo *
nmtstc_service_init(void)
{
    NMTstcServiceInfo *info;
    const char        *args[] = {TEST_NM_PYTHON, NMTSTC_NM_SERVICE, NULL};
    GError            *error  = NULL;

    info = g_malloc0(sizeof(*info));

    info->bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    g_assert_no_error(error);

    /* Spawn the test service. info->keepalive_fd will be a pipe to the service's
     * stdin; if it closes, the service will exit immediately. We use this to
     * make sure the service exits if the test program crashes.
     */
    g_spawn_async_with_pipes(NULL,
                             (char **) args,
                             NULL,
                             G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD,
                             NULL,
                             NULL,
                             &info->pid,
                             &info->keepalive_fd,
                             NULL,
                             NULL,
                             &error);
    g_assert_no_error(error);

    {
        nm_auto_unref_gsource GSource *timeout_source = NULL;
        nm_auto_unref_gsource GSource *child_source   = NULL;
        GMainContext                  *context        = g_main_context_new();
        ServiceInitWaitData            data           = {
                                 .bus      = info->bus,
                                 .mainloop = g_main_loop_new(context, FALSE),
        };
        gboolean had_timeout;

        timeout_source = g_timeout_source_new(50);
        g_source_set_callback(timeout_source, _service_init_wait_probe_name, &data, NULL);
        g_source_attach(timeout_source, context);

        child_source = g_child_watch_source_new(info->pid);
        g_source_set_callback(child_source,
                              G_SOURCE_FUNC(_service_init_wait_child_wait),
                              &data,
                              NULL);
        g_source_attach(child_source, context);

        had_timeout = !nmtst_main_loop_run(data.mainloop, 30000);

        g_source_destroy(timeout_source);
        g_source_destroy(child_source);
        g_main_loop_unref(data.mainloop);
        g_main_context_unref(context);

        if (had_timeout)
            g_error("test service %s did not start in time", NMTSTC_NM_SERVICE);
        if (!data.name_found) {
            g_assert(data.exited);
            info->pid = NM_PID_T_INVAL;
            nmtstc_service_cleanup(info);

            if (WIFEXITED(data.exit_code) && WEXITSTATUS(data.exit_code) == 77) {
                /* If the stub service exited with status 77 it means that it decided
                 * that it cannot conduct the tests and the test should be (gracefully)
                 * skip. The likely reason for that, is that libnm is not available
                 * via pygobject. */
                return NULL;
            }
            g_error("test service %s exited with error code %d", NMTSTC_NM_SERVICE, data.exit_code);
        }
    }

    /* Grab a proxy to our fake NM service to trigger tests */
    info->proxy = g_dbus_proxy_new_sync(info->bus,
                                        G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
                                            | G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS
                                            | G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
                                        NULL,
                                        NM_DBUS_SERVICE,
                                        NM_DBUS_PATH,
                                        "org.freedesktop.NetworkManager.LibnmGlibTest",
                                        NULL,
                                        &error);
    g_assert_no_error(error);

    return info;
}

void
nmtstc_service_cleanup(NMTstcServiceInfo *info)
{
    int    ret;
    gint64 t;
    int    status;

    if (!info)
        return;

    nm_close(nm_steal_fd(&info->keepalive_fd));

    g_clear_object(&info->proxy);

    if (info->pid != NM_PID_T_INVAL) {
        kill(info->pid, SIGTERM);

        t = g_get_monotonic_time();
again_wait:
        ret = waitpid(info->pid, &status, WNOHANG);
        if (ret == 0) {
            if (t + 2000000 < g_get_monotonic_time()) {
                kill(info->pid, SIGKILL);
                g_error("child process %lld did not exit within timeout", (long long) info->pid);
            }
            g_usleep(G_USEC_PER_SEC / 50);
            goto again_wait;
        }
        if (ret == -1 && errno == EINTR)
            goto again_wait;

        g_assert(ret == info->pid);
    }

    nmtst_main_context_iterate_until_assert_full(
        NULL,
        1000,
        80,
        (!name_exists(info->bus, "org.freedesktop.NetworkManager")));

    g_clear_object(&info->bus);

    memset(info, 0, sizeof(*info));
    g_free(info);
}

typedef struct {
    GMainLoop  *loop;
    const char *ifname;
    const char *path;
    NMDevice   *device;
} AddDeviceInfo;

static void
device_added_cb(NMClient *client, NMDevice *device, gpointer user_data)
{
    AddDeviceInfo *info = user_data;

    g_assert(info);
    g_assert(!info->device);

    g_assert(NM_IS_DEVICE(device));
    g_assert_cmpstr(nm_object_get_path(NM_OBJECT(device)), ==, info->path);
    g_assert_cmpstr(nm_device_get_iface(device), ==, info->ifname);

    info->device = g_object_ref(device);
    g_main_loop_quit(info->loop);
}

static GVariant *
call_add_wired_device(GDBusProxy  *proxy,
                      const char  *ifname,
                      const char  *hwaddr,
                      const char **subchannels,
                      GError     **error)
{
    const char *empty[] = {NULL};

    if (!hwaddr)
        hwaddr = "/";
    if (!subchannels)
        subchannels = empty;

    return g_dbus_proxy_call_sync(proxy,
                                  "AddWiredDevice",
                                  g_variant_new("(ss^as)", ifname, hwaddr, subchannels),
                                  G_DBUS_CALL_FLAGS_NO_AUTO_START,
                                  3000,
                                  NULL,
                                  error);
}

static GVariant *
call_add_device(GDBusProxy *proxy, const char *method, const char *ifname, GError **error)
{
    return g_dbus_proxy_call_sync(proxy,
                                  method,
                                  g_variant_new("(s)", ifname),
                                  G_DBUS_CALL_FLAGS_NO_AUTO_START,
                                  3000,
                                  NULL,
                                  error);
}

static NMDevice *
add_device_common(NMTstcServiceInfo *sinfo,
                  NMClient          *client,
                  const char        *method,
                  const char        *ifname,
                  const char        *hwaddr,
                  const char       **subchannels)
{
    nm_auto_unref_gmainloop GMainLoop *loop  = NULL;
    gs_unref_variant GVariant         *ret   = NULL;
    gs_free_error GError              *error = NULL;
    AddDeviceInfo                      info;

    g_assert(sinfo);
    g_assert(NM_IS_CLIENT(client));

    if (nm_streq0(method, "AddWiredDevice"))
        ret = call_add_wired_device(sinfo->proxy, ifname, hwaddr, subchannels, &error);
    else
        ret = call_add_device(sinfo->proxy, method, ifname, &error);

    nmtst_assert_success(ret, error);
    g_assert_cmpstr(g_variant_get_type_string(ret), ==, "(o)");

    /* Wait for NMClient to find the device */

    loop = g_main_loop_new(nm_client_get_main_context(client), FALSE);

    info = (AddDeviceInfo){
        .ifname = ifname,
        .loop   = loop,
    };
    g_variant_get(ret, "(&o)", &info.path);

    g_signal_connect(client, NM_CLIENT_DEVICE_ADDED, G_CALLBACK(device_added_cb), &info);

    if (!nmtst_main_loop_run(loop, 5000))
        g_assert_not_reached();

    g_signal_handlers_disconnect_by_func(client, device_added_cb, &info);

    g_assert(NM_IS_DEVICE(info.device));

    g_assert(info.device
             == nm_client_get_device_by_path(client, nm_object_get_path(NM_OBJECT(info.device))));
    g_object_unref(info.device);
    return info.device;
}

NMDevice *
nmtstc_service_add_device(NMTstcServiceInfo *sinfo,
                          NMClient          *client,
                          const char        *method,
                          const char        *ifname)
{
    return add_device_common(sinfo, client, method, ifname, NULL, NULL);
}

NMDevice *
nmtstc_service_add_wired_device(NMTstcServiceInfo *sinfo,
                                NMClient          *client,
                                const char        *ifname,
                                const char        *hwaddr,
                                const char       **subchannels)
{
    return add_device_common(sinfo, client, "AddWiredDevice", ifname, hwaddr, subchannels);
}

void
nmtstc_service_add_connection(NMTstcServiceInfo *sinfo,
                              NMConnection      *connection,
                              gboolean           verify_connection,
                              char             **out_path)
{
    nmtstc_service_add_connection_variant(
        sinfo,
        nm_connection_to_dbus(connection, NM_CONNECTION_SERIALIZE_ALL),
        verify_connection,
        out_path);
}

void
nmtstc_service_add_connection_variant(NMTstcServiceInfo *sinfo,
                                      GVariant          *connection,
                                      gboolean           verify_connection,
                                      char             **out_path)
{
    GVariant *result;
    GError   *error = NULL;

    g_assert(sinfo);
    g_assert(G_IS_DBUS_PROXY(sinfo->proxy));
    g_assert(g_variant_is_of_type(connection, G_VARIANT_TYPE("a{sa{sv}}")));

    result = g_dbus_proxy_call_sync(sinfo->proxy,
                                    "AddConnection",
                                    g_variant_new("(vb)", connection, verify_connection),
                                    G_DBUS_CALL_FLAGS_NO_AUTO_START,
                                    3000,
                                    NULL,
                                    &error);
    g_assert_no_error(error);
    g_assert(g_variant_is_of_type(result, G_VARIANT_TYPE("(o)")));
    if (out_path)
        g_variant_get(result, "(o)", out_path);
    g_variant_unref(result);
}

void
nmtstc_service_update_connection(NMTstcServiceInfo *sinfo,
                                 const char        *path,
                                 NMConnection      *connection,
                                 gboolean           verify_connection)
{
    if (!path)
        path = nm_connection_get_path(connection);
    g_assert(path);

    nmtstc_service_update_connection_variant(
        sinfo,
        path,
        nm_connection_to_dbus(connection, NM_CONNECTION_SERIALIZE_ALL),
        verify_connection);
}

void
nmtstc_service_update_connection_variant(NMTstcServiceInfo *sinfo,
                                         const char        *path,
                                         GVariant          *connection,
                                         gboolean           verify_connection)
{
    GVariant *result;
    GError   *error = NULL;

    g_assert(sinfo);
    g_assert(G_IS_DBUS_PROXY(sinfo->proxy));
    g_assert(g_variant_is_of_type(connection, G_VARIANT_TYPE("a{sa{sv}}")));
    g_assert(path && path[0] == '/');

    result = g_dbus_proxy_call_sync(sinfo->proxy,
                                    "UpdateConnection",
                                    g_variant_new("(ovb)", path, connection, verify_connection),
                                    G_DBUS_CALL_FLAGS_NO_AUTO_START,
                                    3000,
                                    NULL,
                                    &error);
    g_assert_no_error(error);
    g_assert(g_variant_is_of_type(result, G_VARIANT_TYPE("()")));
    g_variant_unref(result);
}

/*****************************************************************************/

typedef struct {
    GType      gtype;
    GMainLoop *loop;
    GObject   *obj;
    bool       call_nm_client_new_async : 1;
} NMTstcObjNewData;

static void
_context_object_new_do_cb(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    NMTstcObjNewData     *d     = user_data;
    gs_free_error GError *error = NULL;

    g_assert(!d->obj);

    if (d->call_nm_client_new_async) {
        d->obj = G_OBJECT(nm_client_new_finish(res, nmtst_get_rand_bool() ? &error : NULL));
    } else {
        d->obj = g_async_initable_new_finish(G_ASYNC_INITABLE(source_object),
                                             res,
                                             nmtst_get_rand_bool() ? &error : NULL);
    }

    nmtst_assert_success(G_IS_OBJECT(d->obj), error);
    g_assert(G_OBJECT_TYPE(d->obj) == d->gtype);

    g_main_loop_quit(d->loop);
}

static GObject *
_context_object_new_do(GType       gtype,
                       gboolean    sync,
                       const char *first_property_name,
                       va_list     var_args)
{
    gs_free_error GError *error = NULL;
    GObject              *obj;

    /* Create a GObject instance synchronously, and arbitrarily use either
     * the sync or async constructor.
     *
     * Note that the sync and async construct differ in one important aspect:
     * the async constructor iterates the current g_main_context_get_thread_default(),
     * while the sync constructor does not! Aside from that, both should behave
     * pretty much the same way. */

    if (sync) {
        nm_auto_destroy_and_unref_gsource GSource *source = NULL;

        if (nmtst_get_rand_bool()) {
            /* the current main context must not be iterated! */
            source = g_idle_source_new();
            g_source_set_callback(source, nmtst_g_source_assert_not_called, NULL, NULL);
            g_source_attach(source, g_main_context_get_thread_default());
        }

        if (gtype != NM_TYPE_CLIENT || first_property_name || nmtst_get_rand_bool()) {
            gboolean success;

            if (first_property_name || nmtst_get_rand_bool())
                obj = g_object_new_valist(gtype, first_property_name, var_args);
            else
                obj = g_object_new(gtype, NULL);

            success = g_initable_init(G_INITABLE(obj), NULL, nmtst_get_rand_bool() ? &error : NULL);
            nmtst_assert_success(success, error);
        } else {
            obj = G_OBJECT(nm_client_new(NULL, nmtst_get_rand_bool() ? &error : NULL));
        }
    } else {
        nm_auto_unref_gmainloop GMainLoop *loop = NULL;
        NMTstcObjNewData                   d    = {
                                 .gtype = gtype,
                                 .loop  = NULL,
        };
        gs_unref_object GObject *obj2 = NULL;

        loop   = g_main_loop_new(g_main_context_get_thread_default(), FALSE);
        d.loop = loop;

        if (gtype != NM_TYPE_CLIENT || first_property_name || nmtst_get_rand_bool()) {
            if (first_property_name || nmtst_get_rand_bool())
                obj2 = g_object_new_valist(gtype, first_property_name, var_args);
            else
                obj2 = g_object_new(gtype, NULL);

            g_async_initable_init_async(G_ASYNC_INITABLE(obj2),
                                        G_PRIORITY_DEFAULT,
                                        NULL,
                                        _context_object_new_do_cb,
                                        &d);
        } else {
            d.call_nm_client_new_async = TRUE;
            nm_client_new_async(NULL, _context_object_new_do_cb, &d);
        }
        g_main_loop_run(loop);
        obj = d.obj;
        g_assert(!obj2 || obj == obj2);
    }

    nmtst_assert_success(G_IS_OBJECT(obj), error);
    g_assert(G_OBJECT_TYPE(obj) == gtype);
    return obj;
}

typedef struct {
    GType       gtype;
    const char *first_property_name;
    va_list     var_args;
    GMainLoop  *loop;
    GObject    *obj;
    bool        sync;
} NewSyncInsideDispatchedData;

static gboolean
_context_object_new_inside_loop_do(gpointer user_data)
{
    NewSyncInsideDispatchedData *d = user_data;

    g_assert(d->loop);
    g_assert(!d->obj);

    d->obj =
        nmtstc_context_object_new_valist(d->gtype, d->sync, d->first_property_name, d->var_args);
    g_main_loop_quit(d->loop);
    return G_SOURCE_CONTINUE;
}

static GObject *
_context_object_new_inside_loop(GType       gtype,
                                gboolean    sync,
                                const char *first_property_name,
                                va_list     var_args)
{
    GMainContext                      *context = g_main_context_get_thread_default();
    nm_auto_unref_gmainloop GMainLoop *loop    = g_main_loop_new(context, FALSE);
    NewSyncInsideDispatchedData        d       = {
                     .gtype               = gtype,
                     .first_property_name = first_property_name,
                     .sync                = sync,
                     .loop                = loop,
    };
    nm_auto_destroy_and_unref_gsource GSource *source = NULL;

    va_copy(d.var_args, var_args);

    source = g_idle_source_new();
    g_source_set_callback(source, _context_object_new_inside_loop_do, &d, NULL);
    g_source_attach(source, context);

    g_main_loop_run(loop);

    va_end(d.var_args);

    g_assert(G_IS_OBJECT(d.obj));
    g_assert(G_OBJECT_TYPE(d.obj) == gtype);
    return d.obj;
}

gpointer
nmtstc_context_object_new_valist(GType       gtype,
                                 gboolean    allow_iterate_main_context,
                                 const char *first_property_name,
                                 va_list     var_args)
{
    gboolean inside_loop;
    gboolean sync;

    if (!allow_iterate_main_context) {
        sync        = TRUE;
        inside_loop = FALSE;
    } else {
        /* The caller allows to iterate the main context. On that point,
         * we can both use the synchronous and the asynchronous initialization,
         * both should yield the same result. Choose one randomly. */
        sync        = nmtst_get_rand_bool();
        inside_loop = ((nmtst_get_rand_uint32() % 3) == 0);
    }

    if (inside_loop) {
        /* Create the obj on an idle handler of the current context.
         * In practice, it should make no difference, which this check
         * tries to prove. */
        return _context_object_new_inside_loop(gtype, sync, first_property_name, var_args);
    }

    return _context_object_new_do(gtype, sync, first_property_name, var_args);
}

gpointer
nmtstc_context_object_new(GType       gtype,
                          gboolean    allow_iterate_main_context,
                          const char *first_property_name,
                          ...)
{
    GObject *obj;
    va_list  var_args;

    va_start(var_args, first_property_name);
    obj = nmtstc_context_object_new_valist(gtype,
                                           allow_iterate_main_context,
                                           first_property_name,
                                           var_args);
    va_end(var_args);
    return obj;
}
