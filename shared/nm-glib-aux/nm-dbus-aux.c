// SPDX-License-Identifier: LGPL-2.1+
/* NetworkManager -- Network link manager
 *
 * (C) Copyright 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-dbus-aux.h"

/*****************************************************************************/

static void
_nm_dbus_connection_call_get_name_owner_cb (GObject *source,
                                            GAsyncResult *res,
                                            gpointer user_data)
{
	gs_unref_variant GVariant *ret = NULL;
	gs_free_error GError *error = NULL;
	const char *owner = NULL;
	gpointer orig_user_data;
	NMDBusConnectionCallGetNameOwnerCb callback;

	nm_utils_user_data_unpack (user_data, &orig_user_data, &callback);

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), res, &error);
	if (ret)
		g_variant_get (ret, "(&s)", &owner);

	callback (owner, error, orig_user_data);
}

void
nm_dbus_connection_call_get_name_owner (GDBusConnection *dbus_connection,
                                        const char *service_name,
                                        int timeout_msec,
                                        GCancellable *cancellable,
                                        NMDBusConnectionCallGetNameOwnerCb callback,
                                        gpointer user_data)
{
	nm_assert (callback);

	g_dbus_connection_call (dbus_connection,
	                        DBUS_SERVICE_DBUS,
	                        DBUS_PATH_DBUS,
	                        DBUS_INTERFACE_DBUS,
	                        "GetNameOwner",
	                        g_variant_new ("(s)", service_name),
	                        G_VARIANT_TYPE ("(s)"),
	                        G_DBUS_CALL_FLAGS_NONE,
	                        timeout_msec,
	                        cancellable,
	                        _nm_dbus_connection_call_get_name_owner_cb,
	                        nm_utils_user_data_pack (user_data, callback));
}
