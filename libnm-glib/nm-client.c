#include <dbus/dbus-glib.h>
#include "nm-client.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "nm-utils.h"

#include "nm-client-bindings.h"

G_DEFINE_TYPE (NMClient, nm_client, DBUS_TYPE_G_PROXY)

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	STATE_CHANGE,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void client_state_change_proxy (DBusGProxy *proxy, guint state, gpointer user_data);
static void client_device_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data);
static void client_device_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data);

static void
nm_client_init (NMClient *client)
{
}

static void
nm_client_class_init (NMClientClass *client_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (client_class);

	/* signals */
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
								 client,
								 NULL);

	dbus_g_proxy_add_signal (proxy, "DeviceAdded", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy,
								 "DeviceAdded",
								 G_CALLBACK (client_device_added_proxy),
								 client,
								 NULL);

	dbus_g_proxy_add_signal (proxy, "DeviceRemoved", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy,
								 "DeviceRemoved",
								 G_CALLBACK (client_device_removed_proxy),
								 client,
								 NULL);

	return client;
}

static void
client_state_change_proxy (DBusGProxy *proxy, guint state, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);

	g_signal_emit (client, signals[STATE_CHANGE], 0, state);
}

static void
client_device_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMDevice *device;
	DBusGConnection *connection = NULL;

	g_object_get (client, "connection", &connection, NULL);
	device = nm_device_new (connection, path);
	g_signal_emit (client, signals[DEVICE_ADDED], 0, device);
	g_object_unref (device);
}

static void
client_device_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMDevice *device;
	DBusGConnection *connection = NULL;

	g_object_get (client, "connection", &connection, NULL);
	device = nm_device_new (connection, path);
	g_signal_emit (client, signals[DEVICE_REMOVED], 0, device);
	g_object_unref (device);
}


GSList *
nm_client_get_devices (NMClient *client)
{
	GSList *list = NULL;
	GPtrArray *array = NULL;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	if (!org_freedesktop_NetworkManager_get_devices (DBUS_G_PROXY (client), &array, &err)) {
		g_warning ("Error in get_devices: %s", err->message);
		g_error_free (err);
	} else {
		DBusGConnection *connection = NULL;
		int i;

		g_object_get (client, "connection", &connection, NULL);

		for (i = 0; i < array->len; i++) {
			NMDevice *device;
			const char *path = g_ptr_array_index (array, i);
			NMDeviceType type = nm_device_type_for_path (connection, path);

			switch (type) {
			case DEVICE_TYPE_802_3_ETHERNET:
				device = NM_DEVICE (nm_device_802_3_ethernet_new (connection, path));
				break;
			case DEVICE_TYPE_802_11_WIRELESS:
				device = NM_DEVICE (nm_device_802_11_wireless_new (connection, path));
				break;
			default:
				device = nm_device_new (connection, path);
				break;
			}

			list = g_slist_append (list, device);
		}

		g_ptr_array_free (array, TRUE);
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
	GValue value = {0,};
	NMState state = NM_STATE_UNKNOWN;

	g_return_val_if_fail (NM_IS_CLIENT (client), state);

	if (nm_dbus_get_property (DBUS_G_PROXY (client),
							  NM_DBUS_INTERFACE,
							  "State",
							  &value))
		state = g_value_get_uint (&value);

	return state;
}
