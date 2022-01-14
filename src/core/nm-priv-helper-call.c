/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-priv-helper-call.h"

#include <gio/gunixfdlist.h>

#include "nm-dbus-manager.h"

/*****************************************************************************/

static void
_nm_priv_helper_call_get_fd_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    NMPrivHelperCallGetFDCallback callback;
    gpointer                      callback_data;
    gs_unref_variant GVariant    *ret     = NULL;
    gs_free_error GError         *error   = NULL;
    gs_unref_object GUnixFDList  *fd_list = NULL;
    gs_free int                  *fd_arr  = NULL;

    nm_utils_user_data_unpack(user_data, &callback, &callback_data);

    ret = g_dbus_connection_call_with_unix_fd_list_finish(G_DBUS_CONNECTION(source),
                                                          &fd_list,
                                                          res,
                                                          &error);

    if (error) {
        callback(-1, error, callback_data);
        return;
    }

    if (!fd_list || g_unix_fd_list_get_length(fd_list) != 1) {
        nm_utils_error_set(&error,
                           NM_UTILS_ERROR_UNKNOWN,
                           "Unexpectedly not one FD is returned by nm-priv-helper GetFD()");
        callback(-1, error, callback_data);
        return;
    }

    fd_arr = g_unix_fd_list_steal_fds(fd_list, NULL);

    /* we transfer ownership of the file descriptor! */
    callback(fd_arr[0], NULL, callback_data);
}

static gboolean
_nm_priv_helper_call_get_fd_fail_on_idle(gpointer user_data)
{
    gs_unref_object GCancellable *cancellable = NULL;
    NMPrivHelperCallGetFDCallback callback;
    gpointer                      callback_data;
    gs_free_error GError         *error = NULL;

    nm_utils_user_data_unpack(user_data, &cancellable, &callback, &callback_data);

    if (!g_cancellable_set_error_if_cancelled(cancellable, &error))
        nm_utils_error_set(&error,
                           NM_UTILS_ERROR_UNKNOWN,
                           "Cannot talk to nm-priv-helper without D-Bus");

    callback(-1, error, callback_data);
    return G_SOURCE_REMOVE;
}

void
nm_priv_helper_call_get_fd(NMPrivHelperGetFDType         fd_type,
                           GCancellable                 *cancellable,
                           NMPrivHelperCallGetFDCallback callback,
                           gpointer                      user_data)
{
    GDBusConnection *dbus_connection;

    nm_assert(NM_IN_SET(fd_type, NM_PRIV_HELPER_GET_FD_TYPE_OVSDB_SOCKET));
    nm_assert(!cancellable || G_IS_CANCELLABLE(cancellable));
    nm_assert(callback);

    dbus_connection = NM_MAIN_DBUS_CONNECTION_GET;

    if (!dbus_connection) {
        nm_g_idle_add(_nm_priv_helper_call_get_fd_fail_on_idle,
                      nm_utils_user_data_pack(g_object_ref(cancellable), callback, user_data));
        return;
    }

    g_dbus_connection_call_with_unix_fd_list(dbus_connection,
                                             NM_PRIV_HELPER_DBUS_BUS_NAME,
                                             NM_PRIV_HELPER_DBUS_OBJECT_PATH,
                                             NM_PRIV_HELPER_DBUS_IFACE_NAME,
                                             "GetFD",
                                             g_variant_new("(u)", fd_type),
                                             G_VARIANT_TYPE("()"),
                                             G_DBUS_CALL_FLAGS_NONE,
                                             10000,
                                             NULL,
                                             cancellable,
                                             _nm_priv_helper_call_get_fd_cb,
                                             nm_utils_user_data_pack(callback, user_data));
}
