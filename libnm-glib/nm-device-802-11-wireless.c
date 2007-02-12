#include "nm-device-802-11-wireless.h"
#include "nm-device-private.h"

#include "nm-device-802-11-wireless-bindings.h"

G_DEFINE_TYPE (NMDevice80211Wireless, nm_device_802_11_wireless, NM_TYPE_DEVICE)

static void
nm_device_802_11_wireless_init (NMDevice80211Wireless *device)
{
}

static void
nm_device_802_11_wireless_class_init (NMDevice80211WirelessClass *device_class)
{
}

NMDevice80211Wireless *
nm_device_802_11_wireless_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return (NMDevice80211Wireless *) g_object_new (NM_TYPE_DEVICE_802_11_WIRELESS,
												   "name", NM_DBUS_SERVICE,
												   "path", path, 
												   "interface", NM_DBUS_INTERFACE_DEVICE_WIRELESS,
												   "connection", connection,
												   NULL);
}

char *
nm_device_802_11_wireless_get_address (NMDevice80211Wireless *device)
{
	GValue value = {0,};
	char *address = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE_WIRELESS,
							  "Address",
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
							  "Node",
							  &value))
		mode = g_value_get_int (&value);

	return mode;
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

		g_object_get (device, "connection", &connection, NULL);
		ap = nm_access_point_new (connection, g_value_get_string (&value));
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
