/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <NetworkManager.h>
#include <nm-dbus-glib-types.h>
#include "nm-dbus-settings-system.h"
#include "nm-settings-system-bindings.h"

G_DEFINE_TYPE (NMDBusSettingsSystem, nm_dbus_settings_system, NM_TYPE_DBUS_SETTINGS)

#define NM_DBUS_SETTINGS_SYSTEM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DBUS_SETTINGS_SYSTEM, NMDBusSettingsSystemPrivate))

typedef struct {
	DBusGProxy *settings_proxy;
	DBusGProxy *props_proxy;

	gboolean got_unmanaged_devices;
	GSList *unmanaged_devices;

	gboolean disposed;
} NMDBusSettingsSystemPrivate;

enum {
	PROP_0,
	PROP_UNMANAGED_DEVICES,

	LAST_PROP
};

NMDBusSettingsSystem *
nm_dbus_settings_system_new (DBusGConnection *dbus_connection)
{
	g_return_val_if_fail (dbus_connection != NULL, NULL);

	return (NMDBusSettingsSystem *) g_object_new (NM_TYPE_DBUS_SETTINGS_SYSTEM,
										 NM_DBUS_SETTINGS_DBUS_CONNECTION, dbus_connection,
										 NM_DBUS_SETTINGS_SCOPE, NM_CONNECTION_SCOPE_SYSTEM,
										 NULL);
}

void
nm_dbus_settings_system_add_connection (NMDBusSettingsSystem *self,
								NMConnection *connection)
{
	NMDBusSettingsSystemPrivate *priv;
	GHashTable *settings;
	GError *err = NULL;

	g_return_if_fail (NM_IS_DBUS_SETTINGS_SYSTEM (self));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	priv = NM_DBUS_SETTINGS_SYSTEM_GET_PRIVATE (self);
	settings = nm_connection_to_hash (connection);

	org_freedesktop_NetworkManagerSettings_System_add_connection (priv->settings_proxy, settings, &err);
	if (err) {
		g_warning ("Could not add system settings: %s", err->message);
		g_error_free (err);
	}

	g_hash_table_destroy (settings);
}

static void
update_unmanaged_devices (NMDBusSettingsSystem *self, GValue *value)
{
	NMDBusSettingsSystemPrivate *priv = NM_DBUS_SETTINGS_SYSTEM_GET_PRIVATE (self);

	if (priv->unmanaged_devices) {
		g_slist_foreach (priv->unmanaged_devices, (GFunc) g_free, NULL);
		g_slist_free (priv->unmanaged_devices);
		priv->unmanaged_devices = NULL;
	}

	if (G_VALUE_TYPE (value) == DBUS_TYPE_G_OBJECT_ARRAY) {
		GPtrArray *array;
		int i;

		array = (GPtrArray *) g_value_get_boxed (value);
		for (i = 0; i < array->len; i++)
			priv->unmanaged_devices = g_slist_prepend (priv->unmanaged_devices,
											   g_strdup ((const char *) g_ptr_array_index (array, i)));

		priv->got_unmanaged_devices = TRUE;
	} else
		g_warning ("Invalid return value type: %s", G_VALUE_TYPE_NAME (&value));
}

GSList *
nm_dbus_settings_system_get_unmanaged_devices (NMDBusSettingsSystem *self)
{
	NMDBusSettingsSystemPrivate *priv;
	GValue value = { 0, };
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_DBUS_SETTINGS_SYSTEM (self), NULL);

	priv = NM_DBUS_SETTINGS_SYSTEM_GET_PRIVATE (self);

	if (priv->got_unmanaged_devices)
		return priv->unmanaged_devices;

	if (!dbus_g_proxy_call (priv->props_proxy, "Get", &err,
					    G_TYPE_STRING, NM_DBUS_SERVICE_SYSTEM_SETTINGS,
					    G_TYPE_STRING, "UnmanagedDevices",
					    G_TYPE_INVALID,
					    G_TYPE_VALUE, &value,
					    G_TYPE_INVALID)) {
		g_warning ("Could not retrieve unmanaged devices: %s", err->message);
		g_error_free (err);
		return NULL;
	}

	update_unmanaged_devices (self, &value);
	g_value_unset (&value);

	return priv->unmanaged_devices;
}

static void
proxy_properties_changed (DBusGProxy *proxy,
                          GHashTable *properties,
                          gpointer user_data)
{
	NMDBusSettingsSystem *self = NM_DBUS_SETTINGS_SYSTEM (user_data);
	GValue *value;

	value = (GValue *) g_hash_table_lookup (properties, "UnmanagedDevices");
	if (value) {
		update_unmanaged_devices (self, value);
		g_object_notify (G_OBJECT (self), NM_DBUS_SETTINGS_SYSTEM_UNMANAGED_DEVICES);
	}
}

static void
nm_dbus_settings_system_init (NMDBusSettingsSystem *self)
{
}

static GObject *
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDBusSettingsSystemPrivate *priv;
	DBusGConnection *dbus_connection = NULL;

	object = G_OBJECT_CLASS (nm_dbus_settings_system_parent_class)->constructor (type, n_construct_params, construct_params);

	if (!object)
		return NULL;

	priv = NM_DBUS_SETTINGS_SYSTEM_GET_PRIVATE (object);

	g_object_get (object,
			    NM_DBUS_SETTINGS_DBUS_CONNECTION, &dbus_connection,
			    NULL);

	priv->settings_proxy = dbus_g_proxy_new_for_name (dbus_connection,
											NM_DBUS_SERVICE_SYSTEM_SETTINGS,
											NM_DBUS_PATH_SETTINGS,
											NM_DBUS_IFACE_SETTINGS_SYSTEM);

	priv->props_proxy = dbus_g_proxy_new_for_name (dbus_connection,
										  NM_DBUS_SERVICE_SYSTEM_SETTINGS,
										  NM_DBUS_PATH_SETTINGS,
										  "org.freedesktop.DBus.Properties");

	dbus_g_proxy_add_signal (priv->props_proxy, "PropertiesChanged",
						DBUS_TYPE_G_MAP_OF_VARIANT,
						G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->props_proxy, "PropertiesChanged",
						    G_CALLBACK (proxy_properties_changed),
						    object, NULL);

	return object;
}

static void
dispose (GObject *object)
{
	NMDBusSettingsSystemPrivate *priv = NM_DBUS_SETTINGS_SYSTEM_GET_PRIVATE (object);

	if (priv->disposed)
		return;

	priv->disposed = TRUE;

	if (priv->unmanaged_devices) {
		g_slist_foreach (priv->unmanaged_devices, (GFunc) g_free, NULL);
		g_slist_free (priv->unmanaged_devices);
	}

	g_object_unref (priv->settings_proxy);
	g_object_unref (priv->props_proxy);

	G_OBJECT_CLASS (nm_dbus_settings_system_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMDBusSettingsSystem *self = NM_DBUS_SETTINGS_SYSTEM (object);

	switch (prop_id) {
	case PROP_UNMANAGED_DEVICES:
		g_value_set_pointer (value, nm_dbus_settings_system_get_unmanaged_devices (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_dbus_settings_system_class_init (NMDBusSettingsSystemClass *dbus_settings_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (dbus_settings_class);

	g_type_class_add_private (dbus_settings_class, sizeof (NMDBusSettingsSystemPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_UNMANAGED_DEVICES,
		 g_param_spec_pointer (NM_DBUS_SETTINGS_SYSTEM_UNMANAGED_DEVICES,
						   "Unmanaged devices",
						   "Unmanaged devices",
						   G_PARAM_READABLE));
}
