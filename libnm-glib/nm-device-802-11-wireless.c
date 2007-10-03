#include "nm-device-802-11-wireless.h"
#include "nm-device-private.h"

#include "nm-device-802-11-wireless-bindings.h"

G_DEFINE_TYPE (NMDevice80211Wireless, nm_device_802_11_wireless, NM_TYPE_DEVICE)

#define NM_DEVICE_802_11_WIRELESS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessPrivate))

typedef struct {
	DBusGProxy *wireless_proxy;
	gboolean have_ap_list;
	GHashTable *aps;

	gboolean disposed;
} NMDevice80211WirelessPrivate;

enum {
	ACCESS_POINT_ADDED,
	ACCESS_POINT_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void access_point_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data);
static void access_point_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data);

static void
nm_device_802_11_wireless_init (NMDevice80211Wireless *device)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);

	priv->disposed = FALSE;
	priv->aps = g_hash_table_new_full (g_str_hash, g_str_equal,
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

	priv->wireless_proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
													  NM_DBUS_SERVICE,
													  nm_object_get_path (NM_OBJECT (object)),
													  NM_DBUS_INTERFACE_DEVICE_WIRELESS);

	dbus_g_proxy_add_signal (priv->wireless_proxy, "AccessPointAdded", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->wireless_proxy, "AccessPointAdded",
								 G_CALLBACK (access_point_added_proxy),
								 object, NULL);

	dbus_g_proxy_add_signal (priv->wireless_proxy, "AccessPointRemoved", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->wireless_proxy, "AccessPointRemoved",
								 G_CALLBACK (access_point_removed_proxy),
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

	g_hash_table_destroy (priv->aps);

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
	signals[ACCESS_POINT_ADDED] =
		g_signal_new ("access-point-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDevice80211WirelessClass, access_point_added),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[ACCESS_POINT_REMOVED] =
		g_signal_new ("access-point-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDevice80211WirelessClass, access_point_removed),
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
												   NM_OBJECT_CONNECTION, connection,
												   NM_OBJECT_PATH, path,
												   NULL);
}

char *
nm_device_802_11_wireless_get_hw_address (NMDevice80211Wireless *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);

	return nm_object_get_string_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE_WIRELESS, "HwAddress");
}

int
nm_device_802_11_wireless_get_mode (NMDevice80211Wireless *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), 0);

	return nm_object_get_int_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE_WIRELESS, "Mode");
}

int
nm_device_802_11_wireless_get_bitrate (NMDevice80211Wireless *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), 0);

	return nm_object_get_int_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE_WIRELESS, "Bitrate");
}

guint32
nm_device_802_11_wireless_get_capabilities (NMDevice80211Wireless *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), 0);

	return nm_object_get_uint_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE_WIRELESS, "WirelessCapabilities");
}

static NMAccessPoint *
get_access_point (NMDevice80211Wireless *device, const char *path, gboolean create_if_not_found)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);
	NMAccessPoint *ap;

	ap = g_hash_table_lookup (priv->aps, path);
	if (!ap && create_if_not_found) {
		ap = nm_access_point_new (nm_object_get_connection (NM_OBJECT (device)), path);
		if (ap)
			g_hash_table_insert (priv->aps, g_strdup (path), ap);
	}

	return ap;
}

NMAccessPoint *
nm_device_802_11_wireless_get_active_access_point (NMDevice80211Wireless *device)
{
	char *path;
	NMAccessPoint *ap = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);

	path = nm_object_get_object_path_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE_WIRELESS, "ActiveAccessPoint");
	if (path) {
		ap = get_access_point (device, path, TRUE);
		g_free (path);
	}

	return ap;
}

NMAccessPoint *
nm_device_802_11_wireless_get_access_point_by_path (NMDevice80211Wireless *device,
											        const char *object_path)
{
	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);
	g_return_val_if_fail (object_path != NULL, NULL);

	return get_access_point (device, object_path, TRUE);
}

static void
access_points_to_slist (gpointer key, gpointer value, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_prepend (*list, value);
}

GSList *
nm_device_802_11_wireless_get_access_points (NMDevice80211Wireless *device)
{
	NMDevice80211WirelessPrivate *priv;
	GSList *list = NULL;
	GPtrArray *array = NULL;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);

	priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);

	if (priv->have_ap_list) {
		g_hash_table_foreach (priv->aps, access_points_to_slist, &list);
		return list;
	}

	if (!org_freedesktop_NetworkManager_Device_Wireless_get_access_points
		(NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device)->wireless_proxy, &array, &err)) {

		g_warning ("Error in get_access_points: %s", err->message);
		g_error_free (err);
	} else {
		int i;

		for (i = 0; i < array->len; i++) {
			NMAccessPoint *ap = get_access_point (device, (const char *) g_ptr_array_index (array, i), TRUE);
			if (ap)
				list = g_slist_prepend (list, ap);
		}

		g_ptr_array_free (array, TRUE);
		list = g_slist_reverse (list);

		priv->have_ap_list = TRUE;
	}

	return list;
}

static void
access_point_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (user_data);
	NMAccessPoint *ap;

	ap = get_access_point (device, path, TRUE);
	if (device)
		g_signal_emit (device, signals[ACCESS_POINT_ADDED], 0, ap);
}

static void
access_point_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (user_data);
	NMAccessPoint *ap;

	ap = get_access_point (device, path, FALSE);
	if (device) {
		g_signal_emit (device, signals[ACCESS_POINT_REMOVED], 0, ap);
		g_hash_table_remove (NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device)->aps, path);
	}
}
