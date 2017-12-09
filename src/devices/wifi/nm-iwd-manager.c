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
 * Copyright (C) 2017 Intel Corporation
 */

#include "nm-default.h"

#include "nm-iwd-manager.h"

#include <string.h>
#include <net/if.h>

#include "nm-logging.h"
#include "nm-manager.h"
#include "nm-device-iwd.h"

/*****************************************************************************/

typedef struct {
	GCancellable *cancellable;
	gboolean running;
	GDBusObjectManager *object_manager;
} NMIwdManagerPrivate;

struct _NMIwdManager {
	GObject parent;
	NMIwdManagerPrivate _priv;
};

struct _NMIwdManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMIwdManager, nm_iwd_manager, G_TYPE_OBJECT)

#define NM_IWD_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMIwdManager, NM_IS_IWD_MANAGER)

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME                "iwd-manager"
#define _NMLOG_DOMAIN                     LOGD_WIFI

#define _NMLOG(level, ...) \
	G_STMT_START { \
		if (nm_logging_enabled (level, _NMLOG_DOMAIN)) { \
			char __prefix[32]; \
			\
			if (self) \
				g_snprintf (__prefix, sizeof (__prefix), "%s[%p]", ""_NMLOG_PREFIX_NAME"", (self)); \
			else \
				g_strlcpy (__prefix, _NMLOG_PREFIX_NAME, sizeof (__prefix)); \
			_nm_log ((level), (_NMLOG_DOMAIN), 0, NULL, NULL, \
			          "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
			          __prefix _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
		} \
	} G_STMT_END

/*****************************************************************************/

static void
set_device_dbus_object (NMIwdManager *self, GDBusInterface *interface,
                        GDBusObject *object)
{
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	GDBusProxy *proxy;
	GVariant *value;
	const char *ifname;
	gint ifindex;
	NMDevice *device;
	NMManager *manager;

	if (!priv->running)
		return;

	g_return_if_fail (G_IS_DBUS_PROXY (interface));

	proxy = G_DBUS_PROXY (interface);

	if (strcmp (g_dbus_proxy_get_interface_name (proxy),
	            NM_IWD_DEVICE_INTERFACE))
		return;

	value = g_dbus_proxy_get_cached_property (proxy, "Name");
	if (!value) {
		_LOGE ("Name not cached for Device at %s",
		       g_dbus_proxy_get_object_path (proxy));
		return;
	}

	ifname = g_variant_get_string (value, NULL);
	ifindex = if_nametoindex (ifname);
	g_variant_unref (value);

	if (!ifindex) {
		_LOGE ("if_nametoindex failed for Name %s for Device at %s: %i",
		       ifname, g_dbus_proxy_get_object_path (proxy), errno);
		return;
	}

	manager = nm_manager_get ();

	device = nm_manager_get_device_by_ifindex (manager, ifindex);
	if (!NM_IS_DEVICE_IWD (device)) {
		_LOGE ("IWD device named %s is not a Wifi device", ifname);
		return;
	}

	nm_device_iwd_set_dbus_object (NM_DEVICE_IWD (device), object);
}

static void
interface_added (GDBusObjectManager *object_manager, GDBusObject *object,
                 GDBusInterface *interface, gpointer user_data)
{
	NMIwdManager *self = user_data;

	set_device_dbus_object (self, interface, object);
}

static void
interface_removed (GDBusObjectManager *object_manager, GDBusObject *object,
                   GDBusInterface *interface, gpointer user_data)
{
	NMIwdManager *self = user_data;

	/*
	 * TODO: we may need to save the GDBusInterface or GDBusObject
	 * pointer in the hash table because we may be no longer able to
	 * access the Name property or map the name to ifindex with
	 * if_nametoindex at this point.
	 */

	set_device_dbus_object (self, interface, NULL);
}

static gboolean
_om_has_name_owner (GDBusObjectManager *object_manager)
{
	gs_free char *name_owner = NULL;

	nm_assert (G_IS_DBUS_OBJECT_MANAGER_CLIENT (object_manager));

	name_owner = g_dbus_object_manager_client_get_name_owner (G_DBUS_OBJECT_MANAGER_CLIENT (object_manager));
	return !!name_owner;
}

static void
object_added (NMIwdManager *self, GDBusObject *object)
{
	GList *interfaces, *iter;

	interfaces = g_dbus_object_get_interfaces (object);
	for (iter = interfaces; iter; iter = iter->next) {
		GDBusInterface *interface = G_DBUS_INTERFACE (iter->data);

		set_device_dbus_object (self, interface, object);
	}

	g_list_free_full (interfaces, g_object_unref);
}

static void
name_owner_changed (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMIwdManager *self = user_data;
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	GDBusObjectManager *object_manager = G_DBUS_OBJECT_MANAGER (object);

	nm_assert (object_manager == priv->object_manager);

	if (_om_has_name_owner (object_manager)) {
		GList *objects, *iter;

		priv->running = true;

		objects = g_dbus_object_manager_get_objects (object_manager);
		for (iter = objects; iter; iter = iter->next)
			object_added (self, G_DBUS_OBJECT (iter->data));

		g_list_free_full (objects, g_object_unref);
	} else {
		NMManager *manager = nm_manager_get ();
		const GSList *devices, *iter;

		priv->running = false;

		devices = nm_manager_get_devices (manager);
		for (iter = devices; iter; iter = iter->next) {
			NMDevice *device = NM_DEVICE (iter->data);

			if (!NM_IS_DEVICE_IWD (device))
				continue;

			nm_device_iwd_set_dbus_object (NM_DEVICE_IWD (device),
			                                NULL);
		}
	}
}

static void
device_added (NMDevice *device, gpointer user_data)
{
	NMIwdManager *self = user_data;
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	GList *objects, *iter;

	if (!NM_IS_DEVICE_IWD (device))
		return;

	if (!priv->running)
		return;

	objects = g_dbus_object_manager_get_objects (priv->object_manager);
	for (iter = objects; iter; iter = iter->next) {
		GDBusObject *object = G_DBUS_OBJECT (iter->data);
		GDBusInterface *interface;
		GDBusProxy *proxy;
		GVariant *value;
		const char *obj_ifname;

		interface = g_dbus_object_get_interface (object,
		                                         NM_IWD_DEVICE_INTERFACE);
		if (!interface)
			continue;

		proxy = G_DBUS_PROXY (interface);
		value = g_dbus_proxy_get_cached_property (proxy, "Name");
		if (!value) {
			g_object_unref (interface);
			continue;
		}

		obj_ifname = g_variant_get_string (value, NULL);
		g_variant_unref (value);
		g_object_unref (interface);

		if (strcmp (nm_device_get_iface (device), obj_ifname))
			continue;

		nm_device_iwd_set_dbus_object (NM_DEVICE_IWD (device), object);
		break;
	}

	g_list_free_full (objects, g_object_unref);
}

static void
got_object_manager (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMIwdManager *self = user_data;
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;
	GDBusObjectManager *object_manager;
	GDBusConnection *connection;
	NMManager *manager = nm_manager_get ();

	g_clear_object (&priv->cancellable);

	object_manager = g_dbus_object_manager_client_new_for_bus_finish (result, &error);
	if (object_manager == NULL) {
		_LOGE ("failed to acquire IWD Object Manager: Wi-Fi will not be available (%s)",
		       NM_G_ERROR_MSG (error));
		g_clear_error (&error);
		return;
	}

	priv->object_manager = object_manager;

	g_signal_connect (priv->object_manager, "interface-added",
	                  G_CALLBACK (interface_added), self);
	g_signal_connect (priv->object_manager, "interface-removed",
	                  G_CALLBACK (interface_removed), self);
	g_signal_connect (priv->object_manager, "notify::name-owner",
	                  G_CALLBACK (name_owner_changed), self);

	nm_assert (G_IS_DBUS_OBJECT_MANAGER_CLIENT (object_manager));

	connection = g_dbus_object_manager_client_get_connection (G_DBUS_OBJECT_MANAGER_CLIENT (object_manager));

	name_owner_changed (G_OBJECT (object_manager), NULL, self);

	g_signal_connect (manager, "device-added",
	                  G_CALLBACK (device_added), self);
}

static void
prepare_object_manager (NMIwdManager *self)
{
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);

	g_dbus_object_manager_client_new_for_bus (NM_IWD_BUS_TYPE,
	                                          G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_DO_NOT_AUTO_START,
	                                          NM_IWD_SERVICE, "/",
	                                          NULL, NULL, NULL,
	                                          priv->cancellable,
	                                          got_object_manager, self);
}

/*****************************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMIwdManager, nm_iwd_manager_get,
                            NM_TYPE_IWD_MANAGER);

static void
nm_iwd_manager_init (NMIwdManager *self)
{
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);

	priv->cancellable = g_cancellable_new ();
	prepare_object_manager (self);
}

static void
dispose (GObject *object)
{
	NMIwdManager *self = (NMIwdManager *) object;
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);

	if (priv->object_manager)
		g_clear_object (&priv->object_manager);

	nm_clear_g_cancellable (&priv->cancellable);

	G_OBJECT_CLASS (nm_iwd_manager_parent_class)->dispose (object);
}

static void
nm_iwd_manager_class_init (NMIwdManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;
}
