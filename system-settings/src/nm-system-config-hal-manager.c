/*
 * Copyright (C) 2008 Dan Williams
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */


#include <string.h>
#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>

#include "nm-marshal.h"
#include "nm-dbus-glib-types.h"
#include "nm-system-config-hal-manager.h"
#include "nm-system-config-hal-manager-private.h"

#define NUM_DEVICE_TYPES	DEVICE_TYPE_CDMA

typedef struct {
	DBusGConnection *g_connection;
	DBusGProxy *proxy;
	GHashTable *devices;
} NMSystemConfigHalManagerPrivate;

#define NM_SYSTEM_CONFIG_HAL_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                                     NM_TYPE_SYSTEM_CONFIG_HAL_MANAGER, \
                                                     NMSystemConfigHalManagerPrivate))

G_DEFINE_TYPE (NMSystemConfigHalManager, nm_system_config_hal_manager, G_TYPE_OBJECT)

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static NMDeviceType
get_type_for_udi (NMSystemConfigHalManager *manager, const char *udi)
{
	NMSystemConfigHalManagerPrivate *priv = NM_SYSTEM_CONFIG_HAL_MANAGER_GET_PRIVATE (manager);
	NMDeviceType devtype = DEVICE_TYPE_UNKNOWN;
	DBusGProxy *dev_proxy;
	GError *error = NULL;
	GSList *capabilities = NULL, *iter;

	dev_proxy = dbus_g_proxy_new_for_name (priv->g_connection,
	                                       "org.freedesktop.Hal",
	                                       udi,
	                                       "org.freedesktop.Hal.Device");
	if (!dev_proxy)
		return DEVICE_TYPE_UNKNOWN;

	if (!dbus_g_proxy_call_with_timeout (dev_proxy,
	                                     "GetPropertyStringList", 10000, &error,
	                                     G_TYPE_STRING, "info.capabilities", G_TYPE_INVALID,
	                                     DBUS_TYPE_G_LIST_OF_STRING, &capabilities, G_TYPE_INVALID)) {		
		g_error_free (error);
		goto out;
	}

	if (!g_slist_length (capabilities))
		goto out;

	for (iter = capabilities; iter && (devtype == DEVICE_TYPE_UNKNOWN); iter = g_slist_next (iter)) {
		if (!strcmp (iter->data, "net.80203"))
			devtype = DEVICE_TYPE_802_3_ETHERNET;
		else if (!strcmp (iter->data, "net.80211"))
			devtype = DEVICE_TYPE_802_11_WIRELESS;
		else if (!strcmp (iter->data, "modem")) {
			GSList *csets = NULL, *elt;

			if (dbus_g_proxy_call_with_timeout (dev_proxy,
			                                    "GetPropertyStringList", 10000, &error,
			                                    G_TYPE_STRING, "modem.command_sets", G_TYPE_INVALID,
			                                    DBUS_TYPE_G_LIST_OF_STRING, &csets, G_TYPE_INVALID)) {		
				for (elt = csets; elt && (devtype == DEVICE_TYPE_UNKNOWN); elt = g_slist_next (elt)) {
					if (!strcmp (elt->data, "GSM-07.07"))
						devtype = DEVICE_TYPE_GSM;
					else if (!strcmp (elt->data, "IS-707-A"))
						devtype = DEVICE_TYPE_CDMA;
				}
			}
		}
	}

	g_boxed_free (DBUS_TYPE_G_LIST_OF_STRING, capabilities);

out:
	g_object_unref (dev_proxy);
	return devtype;
}

static void
device_added_cb (DBusGProxy *proxy, const char *udi, gpointer user_data)
{
	NMSystemConfigHalManager *manager = NM_SYSTEM_CONFIG_HAL_MANAGER (user_data);
	NMSystemConfigHalManagerPrivate *priv = NM_SYSTEM_CONFIG_HAL_MANAGER_GET_PRIVATE (manager);
	NMDeviceType devtype;

	if (!g_hash_table_lookup (priv->devices, udi)) {
		devtype = get_type_for_udi (manager, udi);
		if (devtype != DEVICE_TYPE_UNKNOWN) {
			g_hash_table_insert (priv->devices, g_strdup (udi), GUINT_TO_POINTER (devtype));
			g_signal_emit (manager, signals[DEVICE_ADDED], 0, udi, devtype);
		}
	}
}

static void
device_removed_cb (DBusGProxy *proxy, const char *udi, gpointer user_data)
{
	NMSystemConfigHalManager *manager = NM_SYSTEM_CONFIG_HAL_MANAGER (user_data);
	NMSystemConfigHalManagerPrivate *priv = NM_SYSTEM_CONFIG_HAL_MANAGER_GET_PRIVATE (manager);
	NMDeviceType devtype;

	devtype = GPOINTER_TO_UINT (g_hash_table_lookup (priv->devices, udi));
	if (devtype != DEVICE_TYPE_UNKNOWN) {
		g_signal_emit (manager, signals[DEVICE_REMOVED], 0, udi, devtype);
		g_hash_table_remove (priv->devices, udi);
	}
}

static void
device_new_capability_cb (DBusGProxy *proxy,
                          const char *udi,
                          const char *capability,
                          gpointer user_data)
{
	NMSystemConfigHalManager *manager = NM_SYSTEM_CONFIG_HAL_MANAGER (user_data);
	NMSystemConfigHalManagerPrivate *priv = NM_SYSTEM_CONFIG_HAL_MANAGER_GET_PRIVATE (manager);
	NMDeviceType devtype;

	if (!g_hash_table_lookup (priv->devices, udi)) {
		devtype = get_type_for_udi (manager, udi);
		if (devtype != DEVICE_TYPE_UNKNOWN) {
			g_hash_table_insert (priv->devices, g_strdup (udi), GUINT_TO_POINTER (devtype));
			g_signal_emit (manager, signals[DEVICE_ADDED], 0, udi, devtype);
		}
	}
}

static void
initial_add_devices_of_type (NMSystemConfigHalManager *manager, const char *capability)
{
	NMSystemConfigHalManagerPrivate *priv = NM_SYSTEM_CONFIG_HAL_MANAGER_GET_PRIVATE (manager);
	GSList *devices = NULL, *iter;
	GError *error = NULL;

	if (!dbus_g_proxy_call_with_timeout (priv->proxy,
	                                     "FindDeviceByCapability", 10000, &error,
	                                     G_TYPE_STRING, capability, G_TYPE_INVALID,
	                                     DBUS_TYPE_G_LIST_OF_STRING, &devices, G_TYPE_INVALID)) {		
		g_warning ("%s: could not get device from HAL: %s (%d).",
		           __func__, error->message, error->code);
		g_error_free (error);
		return;
	}

	for (iter = devices; iter; iter = g_slist_next (iter))
		device_added_cb (priv->proxy, (const char *) iter->data, manager);

	if (devices)
		g_boxed_free (DBUS_TYPE_G_LIST_OF_STRING, devices);
}

static gboolean
init_dbus (NMSystemConfigHalManager *manager, DBusGConnection *g_connection)
{
	NMSystemConfigHalManagerPrivate *priv = NM_SYSTEM_CONFIG_HAL_MANAGER_GET_PRIVATE (manager);

	priv->g_connection = g_connection;
	priv->proxy = dbus_g_proxy_new_for_name (priv->g_connection,
	                                         "org.freedesktop.Hal",
	                                         "/org/freedesktop/Hal/Manager",
	                                         "org.freedesktop.Hal.Manager");
	if (!priv->proxy) {
		g_warning ("Could not get the HAL object!");
		priv->g_connection = NULL;
		return FALSE;
	}

	dbus_g_proxy_add_signal (priv->proxy, "DeviceAdded", G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "DeviceAdded", G_CALLBACK (device_added_cb), manager, NULL);

	dbus_g_proxy_add_signal (priv->proxy, "DeviceRemoved", G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "DeviceRemoved", G_CALLBACK (device_removed_cb), manager, NULL);

	dbus_g_object_register_marshaller (nm_marshal_VOID__STRING_STRING,
									   G_TYPE_NONE,
									   G_TYPE_STRING, G_TYPE_STRING,
									   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->proxy, "NewCapability", G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "NewCapability", G_CALLBACK (device_new_capability_cb), manager, NULL);

	initial_add_devices_of_type (manager, "net.80203");
	initial_add_devices_of_type (manager, "net.80211");
	initial_add_devices_of_type (manager, "modem");

	return TRUE;
}

static void
remove_all_devices (gpointer key, gpointer data, gpointer user_data)
{
	NMSystemConfigHalManager *manager = NM_SYSTEM_CONFIG_HAL_MANAGER (user_data);

	g_signal_emit (manager, signals[DEVICE_REMOVED], 0, key, GPOINTER_TO_UINT (data));
}

static void
cleanup_dbus (NMSystemConfigHalManager *manager)
{
	NMSystemConfigHalManagerPrivate *priv = NM_SYSTEM_CONFIG_HAL_MANAGER_GET_PRIVATE (manager);

	g_hash_table_foreach (priv->devices, (GHFunc) remove_all_devices, manager);
	g_hash_table_remove_all (priv->devices);

	if (priv->proxy) {
		g_object_unref (priv->proxy);
		priv->proxy = NULL;
	}

	priv->g_connection = NULL;
}

static NMSystemConfigHalManager *
nm_system_config_hal_manager_new (DBusGConnection *g_connection)
{
	NMSystemConfigHalManager *manager;

	g_return_val_if_fail (g_connection != NULL, NULL);

	manager = g_object_new (NM_TYPE_SYSTEM_CONFIG_HAL_MANAGER, NULL);

	if (!init_dbus (manager, g_connection)) {
		g_object_unref (manager);
		return NULL;
	}

	return manager;
}

NMSystemConfigHalManager *
nm_system_config_hal_manager_get (DBusGConnection *g_connection)
{
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;
	static NMSystemConfigHalManager *singleton = NULL;

	g_static_mutex_lock (&mutex);
	if (!singleton)
		singleton = nm_system_config_hal_manager_new (g_connection);
	else
		g_object_ref (singleton);
	g_static_mutex_unlock (&mutex);

	return singleton;
}

static void
nm_system_config_hal_manager_init (NMSystemConfigHalManager *manager)
{
	NMSystemConfigHalManagerPrivate *priv = NM_SYSTEM_CONFIG_HAL_MANAGER_GET_PRIVATE (manager);

	priv->devices = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
}

static void
dispose (GObject *object)
{
	cleanup_dbus (NM_SYSTEM_CONFIG_HAL_MANAGER (object));

	G_OBJECT_CLASS (nm_system_config_hal_manager_parent_class)->dispose (object);
}

static void
nm_system_config_hal_manager_class_init (NMSystemConfigHalManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMSystemConfigHalManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	/* signals */
	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMSystemConfigHalManagerClass, device_added),
					  NULL, NULL,
					  nm_marshal_VOID__STRING_UINT,
					  G_TYPE_NONE, 2,
					  G_TYPE_STRING,
					  G_TYPE_UINT);

	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMSystemConfigHalManagerClass, device_removed),
					  NULL, NULL,
					  nm_marshal_VOID__STRING_UINT,
					  G_TYPE_NONE, 2,
					  G_TYPE_STRING,
					  G_TYPE_UINT);
}

void
nm_system_config_hal_manager_reinit_dbus (NMSystemConfigHalManager *manager,
                                          DBusGConnection *g_connection)
{
	init_dbus (manager, g_connection);
}

void
nm_system_config_hal_manager_deinit_dbus (NMSystemConfigHalManager *manager)
{
	cleanup_dbus (manager);
}

typedef struct {
	NMDeviceType devtype;
	GSList **list;
} GetDeviceInfo;

static void
add_devices_of_type (gpointer key, gpointer data, gpointer user_data)
{
	GetDeviceInfo *info = (GetDeviceInfo *) user_data;

	if (GPOINTER_TO_UINT (data) == info->devtype)
		*(info->list) = g_slist_append (*(info->list), g_strdup (key));
}

GSList *
nm_system_config_hal_manager_get_devices_of_type (NMSystemConfigHalManager *manager,
                                                  NMDeviceType devtype)
{
	NMSystemConfigHalManagerPrivate *priv;
	GetDeviceInfo info;
	GSList *list = NULL;

	g_return_val_if_fail (NM_IS_SYSTEM_CONFIG_HAL_MANAGER (manager), NULL);
	g_return_val_if_fail (devtype <= NUM_DEVICE_TYPES, NULL);

	priv = NM_SYSTEM_CONFIG_HAL_MANAGER_GET_PRIVATE (manager);
	info.devtype = devtype;
	info.list = &list;
	g_hash_table_foreach (priv->devices, (GHFunc) add_devices_of_type, &info);

	return list;
}

NMDeviceType
nm_system_config_hal_manager_get_type_for_udi (NMSystemConfigHalManager *manager,
                                               const char *udi)
{
	NMSystemConfigHalManagerPrivate *priv;

	g_return_val_if_fail (NM_IS_SYSTEM_CONFIG_HAL_MANAGER (manager), DEVICE_TYPE_UNKNOWN);
	g_return_val_if_fail (udi != NULL, DEVICE_TYPE_UNKNOWN);

	priv = NM_SYSTEM_CONFIG_HAL_MANAGER_GET_PRIVATE (manager);
	return GPOINTER_TO_UINT (g_hash_table_lookup (priv->devices, udi));
}

DBusGProxy *
nm_system_config_hal_manager_get_hal_proxy (NMSystemConfigHalManager *manager)
{
	g_return_val_if_fail (NM_IS_SYSTEM_CONFIG_HAL_MANAGER (manager), NULL);

	return NM_SYSTEM_CONFIG_HAL_MANAGER_GET_PRIVATE (manager)->proxy;
}

