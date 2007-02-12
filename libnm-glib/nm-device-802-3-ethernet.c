#include "nm-device-802-3-ethernet.h"
#include "nm-device-private.h"

#include "nm-device-802-3-ethernet-bindings.h"

G_DEFINE_TYPE (NMDevice8023Ethernet, nm_device_802_3_ethernet, NM_TYPE_DEVICE)

static void
nm_device_802_3_ethernet_init (NMDevice8023Ethernet *device)
{
}

static void
nm_device_802_3_ethernet_class_init (NMDevice8023EthernetClass *device_class)
{
}

NMDevice8023Ethernet *
nm_device_802_3_ethernet_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return (NMDevice8023Ethernet *) g_object_new (NM_TYPE_DEVICE_802_3_ETHERNET,
												  "name", NM_DBUS_SERVICE,
												  "path", path, 
												  "interface",  NM_DBUS_INTERFACE_DEVICE_WIRED,
												  "connection", connection,
												  NULL);
}

int
nm_device_802_3_ethernet_get_speed (NMDevice8023Ethernet *device)
{
	int speed = 0;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_DEVICE_802_3_ETHERNET (device), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE_WIRED,
							  "Speed",
							  &value))
		speed = g_value_get_int (&value);

	return speed;
}

char *
nm_device_802_3_ethernet_get_address (NMDevice8023Ethernet *device)
{
	char *address = NULL;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_DEVICE_802_3_ETHERNET (device), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE_WIRED,
							  "Address",
							  &value))
		address = g_strdup (g_value_get_string (&value));

	return address;
}

void
nm_device_802_3_ethernet_activate (NMDevice8023Ethernet *device, gboolean user_requested)
{
	GError *err = NULL;

	g_return_if_fail (NM_IS_DEVICE_802_3_ETHERNET (device));

	if (!org_freedesktop_NetworkManager_Device_Wired_activate (DBUS_G_PROXY (device),
															   user_requested, &err)) {
		g_warning ("Activation failed: %s", err->message);
		g_error_free (err);
	}
}
