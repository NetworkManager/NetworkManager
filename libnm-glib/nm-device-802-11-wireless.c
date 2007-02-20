#include "nm-device-802-11-wireless.h"
#include "nm-device-private.h"
#include "nm-utils.h"

#include "nm-device-802-11-wireless-bindings.h"

G_DEFINE_TYPE (NMDevice80211Wireless, nm_device_802_11_wireless, NM_TYPE_DEVICE)

enum {
	NETWORK_ADDED,
	NETWORK_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void network_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data);
static void network_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data);

static void
nm_device_802_11_wireless_init (NMDevice80211Wireless *device)
{
}

static void
nm_device_802_11_wireless_class_init (NMDevice80211WirelessClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);

	/* signals */
	signals[NETWORK_ADDED] =
		g_signal_new ("network-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDevice80211WirelessClass, network_added),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[NETWORK_ADDED] =
		g_signal_new ("network-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDevice80211WirelessClass, network_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);
}

NMDevice80211Wireless *
nm_device_802_11_wireless_new (DBusGConnection *connection, const char *path)
{
	NMDevice80211Wireless *device;
	DBusGProxy *proxy;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	device = (NMDevice80211Wireless *) g_object_new (NM_TYPE_DEVICE_802_11_WIRELESS,
													 "name", NM_DBUS_SERVICE,
													 "path", path, 
													 "interface", NM_DBUS_INTERFACE_DEVICE_WIRELESS,
													 "connection", connection,
													 NULL);

	proxy = DBUS_G_PROXY (device);

	dbus_g_proxy_add_signal (proxy, "NetworkAdded", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy,
								 "NetworkAdded",
								 G_CALLBACK (network_added_proxy),
								 NULL,
								 NULL);

	dbus_g_proxy_add_signal (proxy, "NetworkRemoved", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy,
								 "NetworkRemoved",
								 G_CALLBACK (network_removed_proxy),
								 NULL,
								 NULL);

	return device;
}

char *
nm_device_802_11_wireless_get_hw_address (NMDevice80211Wireless *device)
{
	GValue value = {0,};
	char *address = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE_WIRELESS,
							  "HwAddress",
							  &value))
		address = g_strdup (g_value_get_string (&value));

	return address;
}

int
nm_device_802_11_wireless_get_mode (NMDevice80211Wireless *device)
{
	GValue value = {0,};
	int mode = 0;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE_WIRELESS,
							  "Mode",
							  &value))
		mode = g_value_get_int (&value);

	return mode;
}

int
nm_device_802_11_wireless_get_bitrate (NMDevice80211Wireless *device)
{
	GValue value = {0,};
	int bitrate = 0;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE_WIRELESS,
							  "Bitrate",
							  &value))
		bitrate = g_value_get_int (&value);

	return bitrate;
}

NMAccessPoint *
nm_device_802_11_wireless_get_active_network (NMDevice80211Wireless *device)
{
	GValue value = {0,};
	NMAccessPoint *ap = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE_WIRELESS,
							  "ActiveNetwork",
							  &value)) {
		DBusGConnection *connection = NULL;

		g_assert (G_VALUE_TYPE (&value) == DBUS_TYPE_G_OBJECT_PATH);

		g_object_get (device, "connection", &connection, NULL);
		ap = nm_access_point_new (connection, (const char *) g_value_get_boxed (&value));
	}

	return ap;
}

GSList *
nm_device_802_11_wireless_get_networks (NMDevice80211Wireless *device)
{
	GSList *list = NULL;
	GPtrArray *array = NULL;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);

	if (!org_freedesktop_NetworkManager_Device_Wireless_get_active_networks (DBUS_G_PROXY (device), &array, &err)) {
		g_warning ("Error in get_networks: %s", err->message);
		g_error_free (err);
	} else {
		DBusGConnection *connection = NULL;
		int i;

		g_object_get (device, "connection", &connection, NULL);
		for (i = 0; i < array->len; i++) {
			NMAccessPoint *ap = nm_access_point_new (connection, g_ptr_array_index (array, i));
			list = g_slist_prepend (list, ap);
		}

		list = g_slist_reverse (list);
		g_ptr_array_free (array, TRUE);
	}

	return list;
}

void
nm_device_802_11_wireless_activate (NMDevice80211Wireless *device,
									NMAccessPoint *ap,
									gboolean user_requested)
{
	GError *err = NULL;

	g_return_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device));
	g_return_if_fail (NM_IS_ACCESS_POINT (ap));

	if (!org_freedesktop_NetworkManager_Device_Wireless_activate (DBUS_G_PROXY (device),
																  dbus_g_proxy_get_path (DBUS_G_PROXY (ap)),
																  user_requested,
																  &err)) {
		g_warning ("Error in wireless_activate: %s", err->message);
		g_error_free (err);
	}
}

static void
network_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (proxy);
	NMAccessPoint *ap;
	DBusGConnection *connection = NULL;

	g_object_get (proxy, "connection", &connection, NULL);
	ap = nm_access_point_new (connection, path);
	g_signal_emit (device, signals[NETWORK_ADDED], 0, ap);
	g_object_unref (ap);
}

static void
network_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (proxy);
	NMAccessPoint *ap;
	DBusGConnection *connection = NULL;

	g_object_get (proxy, "connection", &connection, NULL);
	ap = nm_access_point_new (connection, path);
	g_signal_emit (device, signals[NETWORK_REMOVED], 0, ap);
	g_object_unref (ap);
}
