#include "nm-device-802-11-wireless.h"
#include "nm-device-private.h"
#include "nm-utils.h"

#include "nm-device-802-11-wireless-bindings.h"

G_DEFINE_TYPE (NMDevice80211Wireless, nm_device_802_11_wireless, NM_TYPE_DEVICE)

#define NM_DEVICE_802_11_WIRELESS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessPrivate))

typedef struct {
	gboolean have_network_list;
	GHashTable *networks;
} NMDevice80211WirelessPrivate;

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
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);

	priv->networks = g_hash_table_new_full (g_str_hash, g_str_equal,
											(GDestroyNotify) g_free,
											(GDestroyNotify) g_object_unref);
}

static void
finalize (GObject *object)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (object);

	g_hash_table_destroy (priv->networks);
}

static void
nm_device_802_11_wireless_class_init (NMDevice80211WirelessClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);

	g_type_class_add_private (device_class, sizeof (NMDevice80211WirelessPrivate));

	/* virtual methods */
	object_class->finalize = finalize;

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

guint32
nm_device_802_11_wireless_get_capabilities (NMDevice80211Wireless *device)
{
	guint32 caps = 0;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_DEVICE (device), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE_WIRELESS,
							  "WirelessCapabilities",
							  &value))
		caps = g_value_get_uint (&value);

	return caps;
}

static NMAccessPoint *
get_network (NMDevice80211Wireless *device, const char *path, gboolean create_if_not_found)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);
	NMAccessPoint *ap;

	ap = g_hash_table_lookup (priv->networks, path);
	if (!ap && create_if_not_found) {
		DBusGConnection *connection = NULL;

		g_object_get (device, "connection", &connection, NULL);
		ap = nm_access_point_new (connection, path);

		if (ap)
			g_hash_table_insert (priv->networks, g_strdup (path), ap);
	}

	return ap;
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
		g_assert (G_VALUE_TYPE (&value) == DBUS_TYPE_G_OBJECT_PATH);
		ap = get_network (device, (const char *) g_value_get_boxed (&value), TRUE);
	}

	return ap;
}

static void
networks_to_slist (gpointer key, gpointer value, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_prepend (*list, value);
}

GSList *
nm_device_802_11_wireless_get_networks (NMDevice80211Wireless *device)
{
	NMDevice80211WirelessPrivate *priv;
	GSList *list = NULL;
	GPtrArray *array = NULL;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);

	priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);

	if (priv->have_network_list) {
		g_hash_table_foreach (priv->networks, networks_to_slist, &list);
		return list;
	}

	if (!org_freedesktop_NetworkManager_Device_Wireless_get_active_networks (DBUS_G_PROXY (device), &array, &err)) {
		g_warning ("Error in get_networks: %s", err->message);
		g_error_free (err);
	} else {
		int i;

		for (i = 0; i < array->len; i++) {
			NMAccessPoint *ap = get_network (device, (const char *) g_ptr_array_index (array, i), TRUE);
			if (ap)
				list = g_slist_prepend (list, ap);
		}

		g_ptr_array_free (array, TRUE);
		list = g_slist_reverse (list);

		priv->have_network_list = TRUE;
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

	ap = get_network (device, path, TRUE);
	if (device)
		g_signal_emit (device, signals[NETWORK_ADDED], 0, ap);
}

static void
network_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (proxy);
	NMAccessPoint *ap;

	ap = get_network (device, path, FALSE);
	if (device) {
		g_signal_emit (device, signals[NETWORK_REMOVED], 0, ap);
		g_hash_table_remove (NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device)->networks, path);
	}
}
