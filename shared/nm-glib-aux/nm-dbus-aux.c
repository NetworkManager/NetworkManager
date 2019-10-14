// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2019 Red Hat, Inc.
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

/*****************************************************************************/

static void
_nm_dbus_connection_call_get_all_cb (GObject *source,
                                     GAsyncResult *res,
                                     gpointer user_data)
{
	gs_unref_variant GVariant *ret = NULL;
	gs_free_error GError *error = NULL;
	gpointer orig_user_data;
	NMDBusConnectionCallDefaultCb callback;

	nm_utils_user_data_unpack (user_data, &orig_user_data, &callback);

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), res, &error);

	nm_assert ((!!ret) != (!!error));

	callback (ret, error, orig_user_data);
}

void
nm_dbus_connection_call_get_all (GDBusConnection *dbus_connection,
                                 const char *bus_name,
                                 const char *object_path,
                                 const char *interface_name,
                                 int timeout_msec,
                                 GCancellable *cancellable,
                                 NMDBusConnectionCallDefaultCb callback,
                                 gpointer user_data)
{
	nm_assert (callback);

	g_dbus_connection_call (dbus_connection,
	                        bus_name,
	                        object_path,
	                        DBUS_INTERFACE_PROPERTIES,
	                        "GetAll",
	                        g_variant_new ("(s)", interface_name),
	                        G_VARIANT_TYPE ("(a{sv})"),
	                        G_DBUS_CALL_FLAGS_NONE,
	                        timeout_msec,
	                        cancellable,
	                        _nm_dbus_connection_call_get_all_cb,
	                        nm_utils_user_data_pack (user_data, callback));
}

/*****************************************************************************/

typedef struct {
	NMDBusConnectionSignalObjectMangerCb callback;
	gpointer user_data;
	GDestroyNotify user_data_free_func;
} SubscribeObjectManagerData;

static void
_subscribe_object_manager_cb (GDBusConnection *connection,
                              const char *sender_name,
                              const char *arg_object_path,
                              const char *interface_name,
                              const char *signal_name,
                              GVariant *parameters,
                              gpointer user_data)
{
	const SubscribeObjectManagerData *d = user_data;

	nm_assert (nm_streq0 (interface_name, DBUS_INTERFACE_OBJECT_MANAGER));

	if (nm_streq (signal_name, "InterfacesAdded")) {
		gs_unref_variant GVariant *interfaces_and_properties = NULL;
		const char *object_path;

		if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(oa{sa{sv}})")))
			return;

		g_variant_get (parameters,
		               "(&o@a{sa{sv}})",
		               &object_path,
		               &interfaces_and_properties);

		d->callback (object_path, interfaces_and_properties, NULL, d->user_data);
		return;
	}

	if (nm_streq (signal_name, "InterfacesRemoved")) {
		gs_free const char **interfaces = NULL;
		const char *object_path;

		if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(oas)")))
			return;

		g_variant_get (parameters,
		               "(&o^a&s)",
		               &object_path,
		               &interfaces);

		d->callback (object_path, NULL, interfaces, d->user_data);
		return;
	}
}

static void
_subscribe_object_manager_data_free (gpointer ptr)
{
	SubscribeObjectManagerData *d = ptr;

	if (d->user_data_free_func)
		d->user_data_free_func (d->user_data);
	nm_g_slice_free (d);
}

guint
nm_dbus_connection_signal_subscribe_object_manager (GDBusConnection *dbus_connection,
                                                    const char *service_name,
                                                    const char *object_path,
                                                    NMDBusConnectionSignalObjectMangerCb callback,
                                                    gpointer user_data,
                                                    GDestroyNotify user_data_free_func)
{
	SubscribeObjectManagerData *d;

	g_return_val_if_fail (callback, 0);

	d = g_slice_new (SubscribeObjectManagerData);
	*d = (SubscribeObjectManagerData) {
		.callback            = callback,
		.user_data           = user_data,
		.user_data_free_func = user_data_free_func,
	};

	return nm_dbus_connection_signal_subscribe_object_manager_plain (dbus_connection,
	                                                                 service_name,
	                                                                 object_path,
	                                                                 NULL,
	                                                                 _subscribe_object_manager_cb,
	                                                                 d,
	                                                                 _subscribe_object_manager_data_free);
}

/*****************************************************************************/

static void
_nm_dbus_connection_call_get_managed_objects_cb (GObject *source,
                                                 GAsyncResult *res,
                                                 gpointer user_data)
{
	gs_unref_variant GVariant *ret = NULL;
	gs_unref_variant GVariant *arg = NULL;
	gs_free_error GError *error = NULL;
	gpointer orig_user_data;
	NMDBusConnectionCallDefaultCb callback;

	nm_utils_user_data_unpack (user_data, &orig_user_data, &callback);

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), res, &error);

	nm_assert ((!!ret) != (!!error));

	if (ret) {
		nm_assert (g_variant_is_of_type (ret, G_VARIANT_TYPE ("(a{oa{sa{sv}}})")));
		arg = g_variant_get_child_value (ret, 0);
	}

	callback (arg, error, orig_user_data);
}

void
nm_dbus_connection_call_get_managed_objects (GDBusConnection *dbus_connection,
                                             const char *bus_name,
                                             const char *object_path,
                                             GDBusCallFlags flags,
                                             int timeout_msec,
                                             GCancellable *cancellable,
                                             NMDBusConnectionCallDefaultCb callback,
                                             gpointer user_data)
{
	nm_assert (callback);

	g_dbus_connection_call (dbus_connection,
	                        bus_name,
	                        object_path,
	                        DBUS_INTERFACE_OBJECT_MANAGER,
	                        "GetManagedObjects",
	                        NULL,
	                        G_VARIANT_TYPE ("(a{oa{sa{sv}}})"),
	                        flags,
	                        timeout_msec,
	                        cancellable,
	                        _nm_dbus_connection_call_get_managed_objects_cb,
	                        nm_utils_user_data_pack (user_data, callback));
}
