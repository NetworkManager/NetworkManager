/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <dbus/dbus-glib.h>
#include <string.h>
#include "nm-client.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "nm-umts-device.h"
#include "nm-device-private.h"
#include "nm-marshal.h"
#include <nm-utils.h>

#include "nm-client-bindings.h"

G_DEFINE_TYPE (NMClient, nm_client, NM_TYPE_OBJECT)

#define NM_CLIENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CLIENT, NMClientPrivate))

typedef struct {
	DBusGProxy *client_proxy;
	DBusGProxy *bus_proxy;
	gboolean manager_running;
	NMState state;
	gboolean have_device_list;
	GHashTable *devices;

	gboolean wireless_enabled;
	gboolean wireless_hw_enabled;
} NMClientPrivate;

enum {
	PROP_0,
	PROP_WIRELESS_ENABLED,
	PROP_WIRELESS_HARDWARE_ENABLED,

	LAST_PROP
};

enum {
	MANAGER_RUNNING,
	DEVICE_ADDED,
	DEVICE_REMOVED,
	STATE_CHANGE,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void proxy_name_owner_changed (DBusGProxy *proxy,
									  const char *name,
									  const char *old_owner,
									  const char *new_owner,
									  gpointer user_data);

static void client_state_change_proxy (DBusGProxy *proxy, guint state, gpointer user_data);
static void client_device_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data);
static void client_device_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data);

static void
nm_client_init (NMClient *client)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);

	priv->state = NM_STATE_UNKNOWN;
	priv->devices = g_hash_table_new_full (g_str_hash, g_str_equal,
										   (GDestroyNotify) g_free,
										   (GDestroyNotify) g_object_unref);
}

static void
update_wireless_status (NMClient *client)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);

	priv->wireless_enabled = nm_object_get_boolean_property (NM_OBJECT (client),
												  NM_DBUS_INTERFACE,
												  "WirelessEnabled");

	priv->wireless_hw_enabled = priv->wireless_enabled ?
		TRUE : nm_object_get_boolean_property (NM_OBJECT (client),
									    NM_DBUS_INTERFACE,
									    "WirelessHardwareEnabled");
}

static GObject*
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	NMObject *object;
	DBusGConnection *connection;
	NMClientPrivate *priv;
	GError *err = NULL;

	object = (NMObject *) G_OBJECT_CLASS (nm_client_parent_class)->constructor (type,
																 n_construct_params,
																 construct_params);
	if (!object)
		return NULL;

	priv = NM_CLIENT_GET_PRIVATE (object);
	connection = nm_object_get_connection (object);

	priv->client_proxy = dbus_g_proxy_new_for_name (connection,
										   NM_DBUS_SERVICE,
										   nm_object_get_path (object),
										   NM_DBUS_INTERFACE);

	dbus_g_proxy_add_signal (priv->client_proxy, "StateChange", G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->client_proxy,
						    "StateChange",
						    G_CALLBACK (client_state_change_proxy),
						    object,
						    NULL);

	dbus_g_proxy_add_signal (priv->client_proxy, "DeviceAdded", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->client_proxy,
						    "DeviceAdded",
						    G_CALLBACK (client_device_added_proxy),
						    object,
						    NULL);

	dbus_g_proxy_add_signal (priv->client_proxy, "DeviceRemoved", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->client_proxy,
						    "DeviceRemoved",
						    G_CALLBACK (client_device_removed_proxy),
						    object,
						    NULL);

	nm_object_handle_properties_changed (NM_OBJECT (object), priv->client_proxy);

	update_wireless_status (NM_CLIENT (object));

	priv->bus_proxy = dbus_g_proxy_new_for_name (connection,
										"org.freedesktop.DBus",
										"/org/freedesktop/DBus",
										"org.freedesktop.DBus");

	dbus_g_proxy_add_signal (priv->bus_proxy, "NameOwnerChanged",
						G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
						G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->bus_proxy,
						    "NameOwnerChanged",
						    G_CALLBACK (proxy_name_owner_changed),
						    object, NULL);

	if (!dbus_g_proxy_call (priv->bus_proxy,
					    "NameHasOwner", &err,
					    G_TYPE_STRING, NM_DBUS_SERVICE,
					    G_TYPE_INVALID,
					    G_TYPE_BOOLEAN, &priv->manager_running,
					    G_TYPE_INVALID)) {
		g_warning ("Error on NameHasOwner DBUS call: %s", err->message);
		g_error_free (err);
	}

	return G_OBJECT (object);
}

static void
finalize (GObject *object)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);

	g_object_unref (priv->client_proxy);
	g_object_unref (priv->bus_proxy);
	g_hash_table_destroy (priv->devices);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);
	gboolean b;

	switch (prop_id) {
	case PROP_WIRELESS_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->wireless_enabled != b) {
			priv->wireless_enabled = b;
			g_object_notify (object, NM_CLIENT_WIRELESS_ENABLED);
		}
		break;
	case PROP_WIRELESS_HARDWARE_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->wireless_hw_enabled != b) {
			priv->wireless_hw_enabled = b;
			g_object_notify (object, NM_CLIENT_WIRELESS_HARDWARE_ENABLED);
		}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_WIRELESS_ENABLED:
		g_value_set_boolean (value, priv->wireless_enabled);
		break;
	case PROP_WIRELESS_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->wireless_hw_enabled);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}


static void
manager_running (NMClient *client, gboolean running)
{
	if (!running) {
		NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);

		priv->state = NM_STATE_UNKNOWN;
		g_hash_table_remove_all (priv->devices);
		priv->have_device_list = FALSE;
		priv->wireless_enabled = FALSE;
		priv->wireless_hw_enabled = FALSE;
	} else {
		update_wireless_status (client);
	}
}

static void
nm_client_class_init (NMClientClass *client_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (client_class);

	g_type_class_add_private (client_class, sizeof (NMClientPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	client_class->manager_running = manager_running;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_WIRELESS_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WIRELESS_ENABLED,
						   "WirelessEnabled",
						   "Is wirless enabled",
						   TRUE,
						   G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_WIRELESS_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WIRELESS_HARDWARE_ENABLED,
						   "WirelessHardwareEnabled",
						   "Is wirless hardware enabled",
						   TRUE,
						   G_PARAM_READWRITE));

	/* signals */
	signals[MANAGER_RUNNING] =
		g_signal_new ("manager-running",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMClientClass, manager_running),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__BOOLEAN,
					  G_TYPE_NONE, 1,
					  G_TYPE_BOOLEAN);
	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMClientClass, device_added),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMClientClass, device_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[STATE_CHANGE] =
		g_signal_new ("state-change",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMClientClass, state_change),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__UINT,
					  G_TYPE_NONE, 1,
					  G_TYPE_UINT);
}

NMClient *
nm_client_new (void)
{
	DBusGConnection *connection;
	GError *err = NULL;

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection) {
		g_warning ("Couldn't connect to system bus: %s", err->message);
		g_error_free (err);
		return NULL;
	}

	return (NMClient *) g_object_new (NM_TYPE_CLIENT,
									  NM_OBJECT_CONNECTION, connection,
									  NM_OBJECT_PATH, NM_DBUS_PATH,
									  NULL);
}

static void
proxy_name_owner_changed (DBusGProxy *proxy,
						  const char *name,
						  const char *old_owner,
						  const char *new_owner,
						  gpointer user_data)
{
	if (name && !strcmp (name, NM_DBUS_SERVICE)) {
		NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (user_data);
		gboolean old_good = (old_owner && strlen (old_owner));
		gboolean new_good = (new_owner && strlen (new_owner));
		gboolean new_running = FALSE;

		if (!old_good && new_good)
			new_running = TRUE;
		else if (old_good && !new_good)
			new_running = FALSE;

		if (new_running != priv->manager_running) {
			priv->manager_running = new_running;
			g_signal_emit (NM_CLIENT (user_data),
			               signals[MANAGER_RUNNING],
			               0,
			               priv->manager_running);
		}
	}
}

static void
client_state_change_proxy (DBusGProxy *proxy, guint state, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);

	if (priv->state != state) {
		priv->state = state;
		g_signal_emit (client, signals[STATE_CHANGE], 0, state);
	}
}

static NMDevice *
get_device (NMClient *client, const char *path, gboolean create_if_not_found)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	NMDevice *device;

	device = g_hash_table_lookup (priv->devices, path);
	if (!device && create_if_not_found) {
		DBusGConnection *connection;
		NMDeviceType type;

		connection = nm_object_get_connection (NM_OBJECT (client));
		type = nm_device_type_for_path (connection, path);

		switch (type) {
		case DEVICE_TYPE_802_3_ETHERNET:
			device = NM_DEVICE (nm_device_802_3_ethernet_new (connection, path));
			break;
		case DEVICE_TYPE_802_11_WIRELESS:
			device = NM_DEVICE (nm_device_802_11_wireless_new (connection, path));
			break;
		case DEVICE_TYPE_UMTS:
			device = NM_DEVICE (nm_umts_device_new (connection, path));
			break;
		default:
			device = nm_device_new (connection, path);
		}

		if (device)
			g_hash_table_insert (priv->devices, g_strdup (path), device);
	}

	return device;
}

static void
client_device_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMDevice *device;

	device = get_device (client, path, TRUE);
	if (device)
		g_signal_emit (client, signals[DEVICE_ADDED], 0, device);
}

static void
client_device_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMDevice *device;

	device = get_device (client, path, FALSE);
	if (device) {
		g_signal_emit (client, signals[DEVICE_REMOVED], 0, device);
		g_hash_table_remove (NM_CLIENT_GET_PRIVATE (client)->devices, path);
	}
}

gboolean
nm_client_manager_is_running (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->manager_running;
}

static void
devices_to_slist (gpointer key, gpointer value, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_prepend (*list, value);
}

GSList *
nm_client_get_devices (NMClient *client)
{
	NMClientPrivate *priv;
	GSList *list = NULL;
	GPtrArray *array = NULL;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	priv = NM_CLIENT_GET_PRIVATE (client);

	if (priv->have_device_list) {
		g_hash_table_foreach (priv->devices, devices_to_slist, &list);
		return list;
	}

	if (!org_freedesktop_NetworkManager_get_devices (priv->client_proxy, &array, &err)) {
		g_warning ("Error in get_devices: %s", err->message);
		g_error_free (err);
	} else {
		int i;

		for (i = 0; i < array->len; i++) {
			NMDevice *device;
			char *path = g_ptr_array_index (array, i);

			device = get_device (client, (const char *) path, TRUE);
			if (device)
				list = g_slist_append (list, device);
			g_free (path);
		}

		g_ptr_array_free (array, TRUE);

		priv->have_device_list = TRUE;
	}

	return list;
}

NMDevice *
nm_client_get_device_by_path (NMClient *client, const char *object_path)
{
	GSList *devices;
	GSList *iter;
	NMDevice *device = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (object_path, NULL);

	devices = nm_client_get_devices (client);
	for (iter = devices; iter; iter = iter->next) {
		if (!strcmp (nm_object_get_path (NM_OBJECT (iter->data)), object_path)) {
			device = NM_DEVICE (iter->data);
			break;
		}
	}
	g_slist_free (devices);

	return device;
}

typedef struct {
	NMClientActivateDeviceFn fn;
	gpointer user_data;
} ActivateDeviceInfo;

static void
activate_cb (DBusGProxy *proxy, GError *err, gpointer user_data)
{
	ActivateDeviceInfo *info = (ActivateDeviceInfo *) user_data;

	if (info->fn)
		info->fn (info->user_data, err);
	else
		nm_warning ("Device activation failed: %s", err->message);

	/* FIXME: Free err as well? */

	g_slice_free (ActivateDeviceInfo, info);
}

void
nm_client_activate_device (NMClient *client,
					  NMDevice *device,
					  const char *service_name,
					  const char *connection_path,
					  const char *specific_object,
					  NMClientActivateDeviceFn callback,
					  gpointer user_data)
{
	ActivateDeviceInfo *info;
	char *internal_so = (char *) specific_object;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (NM_IS_DEVICE (device));
	g_return_if_fail (service_name != NULL);
	g_return_if_fail (connection_path != NULL);

	/* NULL specific object must be translated into "/" because D-Bus does
	 * not have any idea of NULL object paths.
	 */
	if (internal_so == NULL)
		internal_so = "/";

	info = g_slice_new (ActivateDeviceInfo);
	info->fn = callback;
	info->user_data = user_data;

	org_freedesktop_NetworkManager_activate_device_async (NM_CLIENT_GET_PRIVATE (client)->client_proxy,
											    nm_object_get_path (NM_OBJECT (device)),
											    service_name,
											    connection_path,
											    internal_so,
											    activate_cb,
											    info);
}


GSList * 
nm_client_get_active_connections (NMClient *client)
{
	NMClientPrivate *priv;
	GSList *connections = NULL;
	GPtrArray *array = NULL;
	GError *err = NULL;
	int i, j;
	static GType type = 0, ao_type = 0;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	priv = NM_CLIENT_GET_PRIVATE (client);
	if (!org_freedesktop_NetworkManager_get_active_connections (priv->client_proxy, &array, &err)) {
		g_warning ("Error in get_active_connections: %s", err->message);
		g_error_free (err);
		return NULL;
	}

	/* dbus signature "sooao" */
	if (G_UNLIKELY (ao_type) == 0)
		ao_type = dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_OBJECT_PATH);
	if (G_UNLIKELY (type) == 0) {
		type = dbus_g_type_get_struct ("GValueArray",
		                               G_TYPE_STRING,
		                               DBUS_TYPE_G_OBJECT_PATH,
		                               DBUS_TYPE_G_OBJECT_PATH,
		                               ao_type,
		                               G_TYPE_INVALID);
	}

	for (i = 0; i < array->len; i++) {
		NMClientActiveConnection *ac_elt;
		GValue val = {0, };
		GPtrArray *devices = NULL;

		ac_elt = g_slice_new0 (NMClientActiveConnection);
		if (!ac_elt) {
			g_warning ("Error in get_active_connections: not enough memory.");
			continue;
		}

		g_value_init (&val, type);
		g_value_take_boxed (&val, g_ptr_array_index (array, i));
		dbus_g_type_struct_get (&val,
		                        0, &(ac_elt->service_name),
		                        1, &(ac_elt->connection_path),
		                        2, &(ac_elt->specific_object),
		                        3, &devices,
		                        G_MAXUINT);
		g_value_unset (&val);

		if (devices == NULL || (devices->len == 0)) {
			g_warning ("Error in get_active_connections: no devices returned.");
			nm_client_free_active_connection_element (ac_elt);
			continue;
		}

		if (!strcmp (ac_elt->specific_object, "/")) {
			g_free (ac_elt->specific_object);
			ac_elt->specific_object = NULL;
		}

		for (j = 0; j < devices->len; j++) {
			NMDevice *device;
			char *path = g_ptr_array_index (devices, j);

			device = get_device (client, (const char *) path, TRUE);
			ac_elt->devices = g_slist_append (ac_elt->devices, g_object_ref (device));
			g_free (path);
		}
		g_ptr_array_free (devices, TRUE);

		connections = g_slist_append (connections, ac_elt);
	}

	g_ptr_array_free (array, TRUE);
	return connections;
}

void
nm_client_free_active_connection_element (NMClientActiveConnection *elt)
{
	g_return_if_fail (elt != NULL);

	g_free (elt->service_name);
	g_free (elt->connection_path);
	g_free (elt->specific_object);

	g_slist_foreach (elt->devices, (GFunc) g_object_unref, NULL);
	g_slist_free (elt->devices);

	g_slice_free (NMClientActiveConnection, elt);
}


gboolean
nm_client_wireless_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->wireless_enabled;
}

void
nm_client_wireless_set_enabled (NMClient *client, gboolean enabled)
{
	GValue value = {0,};

	g_return_if_fail (NM_IS_CLIENT (client));

	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, enabled);

	nm_object_set_property (NM_OBJECT (client),
					    NM_DBUS_INTERFACE,
					    "WirelessEnabled",
					    &value);
}

gboolean
nm_client_wireless_hardware_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->wireless_hw_enabled;
}

NMState
nm_client_get_state (NMClient *client)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NM_STATE_UNKNOWN);

	priv = NM_CLIENT_GET_PRIVATE (client);

	if (priv->state == NM_STATE_UNKNOWN)
		priv->state = nm_object_get_uint_property (NM_OBJECT (client), NM_DBUS_INTERFACE, "State");

	return priv->state;
}

void
nm_client_sleep (NMClient *client, gboolean sleep)
{
	GError *err = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));

	if (!org_freedesktop_NetworkManager_sleep (NM_CLIENT_GET_PRIVATE (client)->client_proxy, sleep, &err)) {
		g_warning ("Error in sleep: %s", err->message);
		g_error_free (err);
	}
}
