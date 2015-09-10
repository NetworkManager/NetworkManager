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
 * Copyright (C) 2013 - 2014 Red Hat, Inc.
 */

#include "config.h"

#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <gmodule.h>

#include "nm-default.h"
#include "nm-bluez-manager.h"
#include "nm-device-factory.h"
#include "nm-setting-bluetooth.h"
#include "nm-bluez4-manager.h"
#include "nm-bluez5-manager.h"
#include "nm-bluez-device.h"
#include "nm-bluez-common.h"
#include "nm-connection-provider.h"
#include "nm-device-bt.h"
#include "nm-core-internal.h"
#include "nm-platform.h"
#include "nm-dbus-compat.h"

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

static GType nm_bluez_manager_get_type (void);

static void device_factory_interface_init (NMDeviceFactoryInterface *factory_iface);

G_DEFINE_TYPE_EXTENDED (NMBluezManager, nm_bluez_manager, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_DEVICE_FACTORY, device_factory_interface_init))

static void check_bluez_and_try_setup (NMBluezManager *self);

/**************************************************************************/

G_MODULE_EXPORT NMDeviceFactory *
nm_device_factory_create (GError **error)
{
	return (NMDeviceFactory *) g_object_new (NM_TYPE_BLUEZ_MANAGER, NULL);
}

/************************************************************************/

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
                         guint32 capabilities,
                         gpointer user_data)
{
	NMBluezManager *self = NM_BLUEZ_MANAGER (user_data);
	NMDevice *device;
	gboolean has_dun = (capabilities & NM_BT_CAPABILITY_DUN);
	gboolean has_nap = (capabilities & NM_BT_CAPABILITY_NAP);

	g_return_if_fail (bdaddr != NULL);
	g_return_if_fail (name != NULL);
	g_return_if_fail (object_path != NULL);
	g_return_if_fail (capabilities != NM_BT_CAPABILITY_NONE);
	g_return_if_fail (NM_IS_BLUEZ_DEVICE (bt_device));

	device = nm_device_bt_new (bt_device, object_path, bdaddr, name, capabilities);
	if (!device)
		return;

	nm_log_info (LOGD_BT, "BT device %s (%s) added (%s%s%s)",
	             name,
	             bdaddr,
	             has_dun ? "DUN" : "",
	             has_dun && has_nap ? " " : "",
	             has_nap ? "NAP" : "");
	g_signal_emit_by_name (self, NM_DEVICE_FACTORY_DEVICE_ADDED, device);
	g_object_unref (device);
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

	result = _nm_dbus_proxy_call_finish (priv->introspect_proxy, res,
	                                     G_VARIANT_TYPE ("(s)"), &error);
	if (!result) {
		char *reason2;

		g_dbus_error_strip_remote_error (error);
		reason2 = g_strdup_printf ("introspect failed with %s", error->message);
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

static void
start (NMDeviceFactory *factory)
{
	check_bluez_and_try_setup (NM_BLUEZ_MANAGER (factory));
}

NM_DEVICE_FACTORY_DECLARE_TYPES (
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_BNEP)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_BLUETOOTH_SETTING_NAME)
)

/*********************************************************************/

static void
dispose (GObject *object)
{
	NMBluezManager *self = NM_BLUEZ_MANAGER (object);
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	if (priv->manager4) {
		g_signal_handlers_disconnect_by_func (priv->manager4, manager_bdaddr_added_cb, self);
		g_clear_object (&priv->manager4);
	}
	if (priv->manager5) {
		g_signal_handlers_disconnect_by_func (priv->manager5, manager_bdaddr_added_cb, self);
		g_clear_object (&priv->manager5);
	}

	cleanup_checking (self, TRUE);

	priv->bluez_version = 0;
}

static void
nm_bluez_manager_init (NMBluezManager *self)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	priv->provider = nm_connection_provider_get ();
	g_assert (priv->provider);
}

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	g_warn_if_fail (plink->type == NM_LINK_TYPE_BNEP);
	*out_ignore = TRUE;
	return NULL;
}

static void
device_factory_interface_init (NMDeviceFactoryInterface *factory_iface)
{
	factory_iface->get_supported_types = get_supported_types;
	factory_iface->create_device = create_device;
	factory_iface->start = start;
}

static void
nm_bluez_manager_class_init (NMBluezManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMBluezManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
}

