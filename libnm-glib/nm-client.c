#include <dbus/dbus-glib.h>
#include <string.h>
#include "nm-client.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "nm-utils.h"

#include "nm-client-bindings.h"

G_DEFINE_TYPE (NMClient, nm_client, DBUS_TYPE_G_PROXY)

#define NM_CLIENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CLIENT, NMClientPrivate))

typedef struct {
	DBusGProxy *bus_proxy;
	gboolean manager_running;
	NMState state;
	gboolean have_device_list;
	GHashTable *devices;
} NMClientPrivate;

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
finalize (GObject *object)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);

	g_object_unref (priv->bus_proxy);
	g_hash_table_destroy (priv->devices);
}

static void
manager_running (NMClient *client, gboolean running)
{
	if (!running) {
		NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);

		priv->state = NM_STATE_UNKNOWN;
		g_hash_table_remove_all (priv->devices);
		priv->have_device_list = FALSE;
	}
}

static void
nm_client_class_init (NMClientClass *client_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (client_class);

	g_type_class_add_private (client_class, sizeof (NMClientPrivate));

	/* virtual methods */
	object_class->finalize = finalize;

	client_class->manager_running = manager_running;

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

static void
setup_bus_listener (NMClient *client, DBusGConnection *connection)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	GError *err = NULL;

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
								 client, NULL);

	if (!dbus_g_proxy_call (priv->bus_proxy,
							"NameHasOwner", &err,
							G_TYPE_STRING, NM_DBUS_SERVICE,
							G_TYPE_INVALID,
							G_TYPE_BOOLEAN, &priv->manager_running,
							G_TYPE_INVALID)) {
		g_warning ("Error on NameHasOwner DBUS call: %s", err->message);
		g_error_free (err);
	}
}

NMClient *
nm_client_new (void)
{
	DBusGConnection *connection;
	DBusGProxy *proxy;
	NMClient *client;
	GError *err = NULL;

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection) {
		g_warning ("Couldn't connect to system bus: %s", err->message);
		g_error_free (err);
		return NULL;
	}

	client = (NMClient *) g_object_new (NM_TYPE_CLIENT,
										"name", NM_DBUS_SERVICE,
										"path", NM_DBUS_PATH,
										"interface", NM_DBUS_INTERFACE,
										"connection", connection,
										NULL);

	proxy = DBUS_G_PROXY (client);

	dbus_g_proxy_add_signal (proxy, "StateChange", G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy,
								 "StateChange",
								 G_CALLBACK (client_state_change_proxy),
								 NULL,
								 NULL);

	dbus_g_proxy_add_signal (proxy, "DeviceAdded", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy,
								 "DeviceAdded",
								 G_CALLBACK (client_device_added_proxy),
								 NULL,
								 NULL);

	dbus_g_proxy_add_signal (proxy, "DeviceRemoved", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy,
								 "DeviceRemoved",
								 G_CALLBACK (client_device_removed_proxy),
								 NULL,
								 NULL);

	setup_bus_listener (client, connection);

	return client;
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

		if (new_owner && strlen (new_owner) > 0)
			priv->manager_running = TRUE;
		else
			priv->manager_running = FALSE;

		g_signal_emit (NM_CLIENT (user_data), signals[MANAGER_RUNNING], 0, priv->manager_running);
	}
}

static void
client_state_change_proxy (DBusGProxy *proxy, guint state, gpointer user_data)
{
	NMClient *client = NM_CLIENT (proxy);
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
		DBusGConnection *connection = NULL;
		NMDeviceType type;

		g_object_get (client, "connection", &connection, NULL);
		type = nm_device_type_for_path (connection, path);

		switch (type) {
		case DEVICE_TYPE_802_3_ETHERNET:
			device = NM_DEVICE (nm_device_802_3_ethernet_new (connection, path));
			break;
		case DEVICE_TYPE_802_11_WIRELESS:
			device = NM_DEVICE (nm_device_802_11_wireless_new (connection, path));
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
	NMClient *client = NM_CLIENT (proxy);
	NMDevice *device;

	device = get_device (client, path, TRUE);
	if (device)
		g_signal_emit (client, signals[DEVICE_ADDED], 0, device);
}

static void
client_device_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMClient *client = NM_CLIENT (proxy);
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

	if (!org_freedesktop_NetworkManager_get_devices (DBUS_G_PROXY (client), &array, &err)) {
		g_warning ("Error in get_devices: %s", err->message);
		g_error_free (err);
	} else {
		int i;

		for (i = 0; i < array->len; i++) {
			NMDevice *device;

			device = get_device (client, (const char *) g_ptr_array_index (array, i), TRUE);
			if (device)
				list = g_slist_append (list, device);
		}

		g_ptr_array_free (array, TRUE);

		priv->have_device_list = TRUE;
	}

	return list;
}

gboolean
nm_client_wireless_get_enabled (NMClient *client)
{
	GValue value = {0,};
	gboolean enabled = FALSE;

	g_return_val_if_fail (NM_IS_CLIENT (client), enabled);

	if (nm_dbus_get_property (DBUS_G_PROXY (client),
							  NM_DBUS_INTERFACE,
							  "WirelessEnabled",
							  &value))
		enabled = g_value_get_boolean (&value);

	return enabled;
}

void
nm_client_wireless_set_enabled (NMClient *client, gboolean enabled)
{
	GValue value = {0,};

	g_return_if_fail (NM_IS_CLIENT (client));

	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, enabled);
	nm_dbus_set_property (DBUS_G_PROXY (client),
						  NM_DBUS_INTERFACE,
						  "WirelessEnabled",
						  &value);
}

NMState
nm_client_get_state (NMClient *client)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NM_STATE_UNKNOWN);

	priv = NM_CLIENT_GET_PRIVATE (client);

	if (priv->state == NM_STATE_UNKNOWN) {
		GValue value = {0,};

		if (nm_dbus_get_property (DBUS_G_PROXY (client),
								  NM_DBUS_INTERFACE,
								  "State",
								  &value))
			priv->state = g_value_get_uint (&value);
	}

	return priv->state;
}

void
nm_client_sleep (NMClient *client, gboolean sleep)
{
	GError *err = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));

	if (!org_freedesktop_NetworkManager_sleep (DBUS_G_PROXY (client), sleep, &err)) {
		g_warning ("Error in sleep: %s", err->message);
		g_error_free (err);
	}
}

