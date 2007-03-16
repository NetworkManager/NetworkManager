#include "nm-device-802-11-wireless.h"
#include "nm-device-private.h"
#include "nm-utils.h"

#include "nm-device-802-11-wireless-bindings.h"

G_DEFINE_TYPE (NMDevice80211Wireless, nm_device_802_11_wireless, NM_TYPE_DEVICE)

#define NM_DEVICE_802_11_WIRELESS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessPrivate))

typedef struct {
	DBusGProxy *wireless_proxy;
	gboolean have_network_list;
	GHashTable *networks;

	gboolean disposed;
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

	priv->disposed = FALSE;
	priv->networks = g_hash_table_new_full (g_str_hash, g_str_equal,
											(GDestroyNotify) g_free,
											(GDestroyNotify) g_object_unref);
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDevice80211WirelessPrivate *priv;

	object = G_OBJECT_CLASS (nm_device_802_11_wireless_parent_class)->constructor (type,
																				   n_construct_params,
																				   construct_params);
	if (!object)
		return NULL;

	priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (object);

	priv->wireless_proxy = dbus_g_proxy_new_for_name (nm_device_get_connection (NM_DEVICE (object)),
													  NM_DBUS_SERVICE,
													  nm_device_get_path (NM_DEVICE (object)),
													  NM_DBUS_INTERFACE_DEVICE_WIRELESS);

	dbus_g_proxy_add_signal (priv->wireless_proxy, "NetworkAdded", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->wireless_proxy, "NetworkAdded",
								 G_CALLBACK (network_added_proxy),
								 object, NULL);

	dbus_g_proxy_add_signal (priv->wireless_proxy, "NetworkRemoved", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->wireless_proxy, "NetworkRemoved",
								 G_CALLBACK (network_removed_proxy),
								 object, NULL);
	
	return object;
}

static void
dispose (GObject *object)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (object);

	if (priv->disposed)
		return;

	priv->disposed = TRUE;

	g_object_unref (priv->wireless_proxy);

	G_OBJECT_CLASS (nm_device_802_11_wireless_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (object);

	g_hash_table_destroy (priv->networks);

	G_OBJECT_CLASS (nm_device_802_11_wireless_parent_class)->finalize (object);
}

static void
nm_device_802_11_wireless_class_init (NMDevice80211WirelessClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);

	g_type_class_add_private (device_class, sizeof (NMDevice80211WirelessPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;
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
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return (NMDevice80211Wireless *) g_object_new (NM_TYPE_DEVICE_802_11_WIRELESS,
												   NM_DEVICE_CONNECTION, connection,
												   NM_DEVICE_PATH, path,
												   NULL);
}

char *
nm_device_802_11_wireless_get_hw_address (NMDevice80211Wireless *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);

	return nm_dbus_get_string_property (nm_device_get_properties_proxy (NM_DEVICE (device)),
										NM_DBUS_INTERFACE_DEVICE_WIRELESS, "HwAddress");
}

int
nm_device_802_11_wireless_get_mode (NMDevice80211Wireless *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), 0);

	return nm_dbus_get_int_property (nm_device_get_properties_proxy (NM_DEVICE (device)),
									 NM_DBUS_INTERFACE_DEVICE_WIRELESS, "Mode");
}

int
nm_device_802_11_wireless_get_bitrate (NMDevice80211Wireless *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), 0);

	return nm_dbus_get_int_property (nm_device_get_properties_proxy (NM_DEVICE (device)),
									 NM_DBUS_INTERFACE_DEVICE_WIRELESS, "Bitrate");
}

guint32
nm_device_802_11_wireless_get_capabilities (NMDevice80211Wireless *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), 0);

	return nm_dbus_get_uint_property (nm_device_get_properties_proxy (NM_DEVICE (device)),
									  NM_DBUS_INTERFACE_DEVICE_WIRELESS, "WirelessCapabilities");
}

static NMAccessPoint *
get_network (NMDevice80211Wireless *device, const char *path, gboolean create_if_not_found)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);
	NMAccessPoint *ap;

	ap = g_hash_table_lookup (priv->networks, path);
	if (!ap && create_if_not_found) {
		ap = nm_access_point_new (nm_device_get_connection (NM_DEVICE (device)), path);
		if (ap)
			g_hash_table_insert (priv->networks, g_strdup (path), ap);
	}

	return ap;
}

NMAccessPoint *
nm_device_802_11_wireless_get_active_network (NMDevice80211Wireless *device)
{
	GError *err = NULL;
	char *path;
	NMAccessPoint *ap = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);

	path = nm_dbus_get_object_path_property (nm_device_get_properties_proxy (NM_DEVICE (device)),
											 NM_DBUS_INTERFACE_DEVICE_WIRELESS,
											 "ActiveNetwork");
	if (path) {
		ap = get_network (device, path, TRUE);
		g_free (path);
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

	if (!org_freedesktop_NetworkManager_Device_Wireless_get_active_networks
		(NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device)->wireless_proxy, &array, &err)) {

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

	if (!org_freedesktop_NetworkManager_Device_Wireless_activate
		(NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device)->wireless_proxy,
		 dbus_g_proxy_get_path (DBUS_G_PROXY (ap)), user_requested, &err)) {

		g_warning ("Error in wireless_activate: %s", err->message);
		g_error_free (err);
	}
}

static void
network_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (user_data);
	NMAccessPoint *ap;

	ap = get_network (device, path, TRUE);
	if (device)
		g_signal_emit (device, signals[NETWORK_ADDED], 0, ap);
}

static void
network_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (user_data);
	NMAccessPoint *ap;

	ap = get_network (device, path, FALSE);
	if (device) {
		g_signal_emit (device, signals[NETWORK_REMOVED], 0, ap);
		g_hash_table_remove (NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device)->networks, path);
	}
}
