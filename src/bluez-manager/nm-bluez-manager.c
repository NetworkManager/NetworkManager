/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <gio/gio.h>

#include "nm-logging.h"
#include "nm-bluez-manager.h"
#include "nm-bluez4-manager.h"
#include "nm-bluez5-manager.h"
#include "nm-bluez-device.h"
#include "nm-bluez-common.h"

#include "nm-dbus-manager.h"

typedef struct {
	int bluez_version;

	NMConnectionProvider *provider;
	NMBluez4Manager *manager4;
	NMBluez5Manager *manager5;

	guint watch_name_id;

	GDBusProxy *introspect_proxy;
	GCancellable *async_cancellable;
} NMBluezManagerPrivate;

#define NM_BLUEZ_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_BLUEZ_MANAGER, NMBluezManagerPrivate))

G_DEFINE_TYPE (NMBluezManager, nm_bluez_manager, G_TYPE_OBJECT)

enum {
    PROP_0,
    PROP_PROVIDER,

    LAST_PROP
};

enum {
	BDADDR_ADDED,
	BDADDR_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


static void check_bluez_and_try_setup (NMBluezManager *self);


struct AsyncData {
	NMBluezManager *self;
	GCancellable *async_cancellable;
};

static struct AsyncData *
async_data_pack (NMBluezManager *self)
{
	struct AsyncData *data = g_new (struct AsyncData, 1);

	data->self = self;
	data->async_cancellable = g_object_ref (NM_BLUEZ_MANAGER_GET_PRIVATE (self)->async_cancellable);
	return data;
}

static NMBluezManager *
async_data_unpack (struct AsyncData *async_data)
{
	NMBluezManager *self = g_cancellable_is_cancelled (async_data->async_cancellable)
	                       ? NULL : async_data->self;

	g_object_unref (async_data->async_cancellable);
	g_free (async_data);
	return self;
}


/**
 * Cancel any current attempt to detect the version and cleanup
 * the related fields.
 **/
static void
cleanup_checking (NMBluezManager *self, gboolean do_unwatch_name)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	if (priv->async_cancellable) {
		g_cancellable_cancel (priv->async_cancellable);
		g_clear_object (&priv->async_cancellable);
	}

	g_clear_object (&priv->introspect_proxy);

	if (do_unwatch_name && priv->watch_name_id) {
		g_bus_unwatch_name (priv->watch_name_id);
		priv->watch_name_id = 0;
	}
}


static void
manager_bdaddr_added_cb (NMBluez4Manager *bluez_mgr,
                         NMBluezDevice *bt_device,
                         const char *bdaddr,
                         const char *name,
                         const char *object_path,
                         guint32 uuids,
                         gpointer user_data)
{
	/* forward the signal... */
	g_signal_emit (NM_BLUEZ_MANAGER (user_data), signals[BDADDR_ADDED], 0,
	               bt_device,
	               bdaddr,
	               name,
	               object_path,
	               uuids);
}

static void
manager_bdaddr_removed_cb (NMBluez4Manager *bluez_mgr,
                           const char *bdaddr,
                           const char *object_path,
                           gpointer user_data)
{
	/* forward the signal... */
	g_signal_emit (NM_BLUEZ_MANAGER (user_data), signals[BDADDR_REMOVED], 0,
	               bdaddr,
	               object_path);
}


static void
setup_version_number (NMBluezManager *self, int bluez_version)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (!priv->bluez_version);

	nm_log_info (LOGD_BT, "use BlueZ version %d", bluez_version);

	priv->bluez_version = bluez_version;

	/* Just detected the version. Cleanup the ongoing checking/detection. */
	cleanup_checking (self, TRUE);
}

static void
setup_bluez4 (NMBluezManager *self)
{
	NMBluez4Manager *manager;
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (!priv->manager4 && !priv->manager5 && !priv->bluez_version);

	setup_version_number (self, 4);
	priv->manager4 = manager = nm_bluez4_manager_new (priv->provider);

	g_signal_connect (manager,
	                  NM_BLUEZ_MANAGER_BDADDR_ADDED,
	                  G_CALLBACK (manager_bdaddr_added_cb),
	                  self);
	g_signal_connect (manager,
	                  NM_BLUEZ_MANAGER_BDADDR_REMOVED,
	                  G_CALLBACK (manager_bdaddr_removed_cb),
	                  self);

	nm_bluez4_manager_query_devices (manager);
}

static void
setup_bluez5 (NMBluezManager *self)
{
	NMBluez5Manager *manager;
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (!priv->manager4 && !priv->manager5 && !priv->bluez_version);

	setup_version_number (self, 5);
	priv->manager5 = manager = nm_bluez5_manager_new (priv->provider);

	g_signal_connect (manager,
	                  NM_BLUEZ_MANAGER_BDADDR_ADDED,
	                  G_CALLBACK (manager_bdaddr_added_cb),
	                  self);
	g_signal_connect (manager,
	                  NM_BLUEZ_MANAGER_BDADDR_REMOVED,
	                  G_CALLBACK (manager_bdaddr_removed_cb),
	                  self);

	nm_bluez5_manager_query_devices (manager);
}


static void
watch_name_on_appeared (GDBusConnection *connection,
                        const gchar *name,
                        const gchar *name_owner,
                        gpointer user_data)
{
	check_bluez_and_try_setup (NM_BLUEZ_MANAGER (user_data));
}


static void
check_bluez_and_try_setup_final_step (NMBluezManager *self, int bluez_version, const char *reason)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (!priv->bluez_version);

	switch (bluez_version) {
	case 4:
		setup_bluez4 (self);
		break;
	case 5:
		setup_bluez5 (self);
		break;
	default:
		nm_log_dbg (LOGD_BT, "detecting BlueZ version failed: %s", reason);

		/* cancel current attempts to detect the version. */
		cleanup_checking (self, FALSE);
		if (!priv->watch_name_id) {
			priv->watch_name_id = g_bus_watch_name (G_BUS_TYPE_SYSTEM,
			                                        BLUEZ_SERVICE,
			                                        G_BUS_NAME_WATCHER_FLAGS_NONE,
			                                        watch_name_on_appeared,
			                                        NULL,
			                                        self,
			                                        NULL);
		}
		break;
	}
}

static void
check_bluez_and_try_setup_do_introspect (GObject *source_object,
                                         GAsyncResult *res,
                                         gpointer user_data)
{
	NMBluezManager *self = async_data_unpack (user_data);
	NMBluezManagerPrivate *priv;
	GError *error = NULL;
	GVariant *result;
	const char *xml_data;
	int bluez_version = 0;
	const char *reason = NULL;

	if (!self)
		return;

	priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (priv->introspect_proxy);
	g_return_if_fail (!g_cancellable_is_cancelled (priv->async_cancellable));
	g_return_if_fail (!priv->bluez_version);

	g_clear_object (&priv->async_cancellable);

	result = g_dbus_proxy_call_finish (priv->introspect_proxy, res, &error);

	if (!result) {
		char *reason2 = g_strdup_printf ("introspect failed with %s", error->message);
		check_bluez_and_try_setup_final_step (self, 0, reason2);
		g_error_free (error);
		g_free (reason2);
		return;
	}

	g_variant_get (result, "(&s)", &xml_data);

	/* might not be the best approach to detect the version, but it's good enough in practice. */
	if (strstr (xml_data, "org.freedesktop.DBus.ObjectManager"))
		bluez_version = 5;
	else if (strstr (xml_data, BLUEZ4_MANAGER_INTERFACE))
		bluez_version = 4;
	else
		reason = "unexpected introspect result";

	g_variant_unref (result);

	check_bluez_and_try_setup_final_step (self, bluez_version, reason);
}

static void
check_bluez_and_try_setup_on_new_proxy (GObject *source_object,
                                        GAsyncResult *res,
                                        gpointer user_data)
{
	NMBluezManager *self = async_data_unpack (user_data);
	NMBluezManagerPrivate *priv;
	GError *error = NULL;

	if (!self)
		return;

	priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (!priv->introspect_proxy);
	g_return_if_fail (!g_cancellable_is_cancelled (priv->async_cancellable));
	g_return_if_fail (!priv->bluez_version);

	priv->introspect_proxy = g_dbus_proxy_new_for_bus_finish (res, &error);

	if (!priv->introspect_proxy) {
		char *reason = g_strdup_printf ("bluez error creating dbus proxy: %s", error->message);
		check_bluez_and_try_setup_final_step (self, 0, reason);
		g_error_free (error);
		g_free (reason);
		return;
	}

	g_dbus_proxy_call (priv->introspect_proxy,
	                   "Introspect",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                   3000,
	                   priv->async_cancellable,
	                   check_bluez_and_try_setup_do_introspect,
	                   async_data_pack (self));
}

static void
check_bluez_and_try_setup (NMBluezManager *self)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (!priv->bluez_version);

	/* there should be no ongoing detection. Anyway, cleanup_checking. */
	cleanup_checking (self, FALSE);

	priv->async_cancellable = g_cancellable_new ();

	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES | G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                          NULL,
	                          BLUEZ_SERVICE,
	                          "/",
	                          DBUS_INTERFACE_INTROSPECTABLE,
	                          priv->async_cancellable,
	                          check_bluez_and_try_setup_on_new_proxy,
	                          async_data_pack (self));
}


void
nm_bluez_manager_query_devices (NMBluezManager *self)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	switch (priv->bluez_version) {
	case 4:
		nm_bluez4_manager_query_devices (priv->manager4);
		break;
	case 5:
		nm_bluez5_manager_query_devices (priv->manager5);
		break;
	default:
		/* the proxy implementation does nothing in this case. */
		break;
	}
}


NMBluezManager *
nm_bluez_manager_new (NMConnectionProvider *provider)
{
	g_return_val_if_fail (NM_IS_CONNECTION_PROVIDER (provider), NULL);

	return g_object_new (NM_TYPE_BLUEZ_MANAGER,
	                     NM_BLUEZ_MANAGER_PROVIDER,
	                     provider,
	                     NULL);
}


static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PROVIDER:
		/* Construct only */
		priv->provider = g_value_dup_object (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PROVIDER:
		g_value_set_object (value, priv->provider);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}


static void
dispose (GObject *object)
{
	NMBluezManager *self = NM_BLUEZ_MANAGER (object);
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->provider);

	if (priv->manager4) {
		g_signal_handlers_disconnect_by_func (priv->manager4, G_CALLBACK (manager_bdaddr_added_cb), self);
		g_signal_handlers_disconnect_by_func (priv->manager4, G_CALLBACK (manager_bdaddr_removed_cb), self);
		g_clear_object (&priv->manager4);
	}
	if (priv->manager5) {
		g_signal_handlers_disconnect_by_func (priv->manager5, G_CALLBACK (manager_bdaddr_added_cb), self);
		g_signal_handlers_disconnect_by_func (priv->manager5, G_CALLBACK (manager_bdaddr_removed_cb), self);
		g_clear_object (&priv->manager5);
	}

	cleanup_checking (self, TRUE);

	priv->bluez_version = 0;
}

static void
constructed (GObject *object)
{
	NMBluezManager *self = NM_BLUEZ_MANAGER (object);
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	G_OBJECT_CLASS (nm_bluez_manager_parent_class)->constructed (object);

	g_return_if_fail (priv->provider);

	check_bluez_and_try_setup (self);
}

static void
nm_bluez_manager_init (NMBluezManager *self)
{
}

static void
nm_bluez_manager_class_init (NMBluezManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMBluezManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->constructed = constructed;

	g_object_class_install_property
	    (object_class, PROP_PROVIDER,
	     g_param_spec_object (NM_BLUEZ_MANAGER_PROVIDER,
	                          "Provider",
	                          "Connection Provider",
	                          NM_TYPE_CONNECTION_PROVIDER,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* Signals */
	signals[BDADDR_ADDED] =
	    g_signal_new (NM_BLUEZ_MANAGER_BDADDR_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  G_STRUCT_OFFSET (NMBluezManagerClass, bdaddr_added),
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 5, G_TYPE_OBJECT, G_TYPE_STRING,
	                  G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT);

	signals[BDADDR_REMOVED] =
	    g_signal_new (NM_BLUEZ_MANAGER_BDADDR_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  G_STRUCT_OFFSET (NMBluezManagerClass, bdaddr_removed),
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);
}

