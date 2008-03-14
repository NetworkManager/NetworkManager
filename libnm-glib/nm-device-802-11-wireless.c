/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include "wireless-helper.h"

#include <string.h>

#include "nm-device-802-11-wireless.h"
#include "nm-device-private.h"

#include "nm-device-802-11-wireless-bindings.h"

G_DEFINE_TYPE (NMDevice80211Wireless, nm_device_802_11_wireless, NM_TYPE_DEVICE)

#define NM_DEVICE_802_11_WIRELESS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessPrivate))

typedef struct {
	DBusGProxy *wireless_proxy;
	gboolean have_ap_list;
	GHashTable *aps;

	char * hw_address;
	int mode;
	guint32 rate;
	NMAccessPoint *current_ap;
	guint32 wireless_caps;

	gboolean disposed;
} NMDevice80211WirelessPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_MODE,
	PROP_BITRATE,
	PROP_ACTIVE_ACCESS_POINT,
	PROP_WIRELESS_CAPABILITIES,

	LAST_PROP
};

#define DBUS_PROP_HW_ADDRESS "HwAddress"
#define DBUS_PROP_MODE "Mode"
#define DBUS_PROP_BITRATE "Bitrate"
#define DBUS_PROP_ACTIVE_ACCESS_POINT "ActiveAccessPoint"
#define DBUS_PROP_WIRELESS_CAPABILITIES "WirelessCapabilities"

enum {
	ACCESS_POINT_ADDED,
	ACCESS_POINT_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

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

static void
nm_device_802_11_wireless_set_hw_address (NMDevice80211Wireless *self,
								  const char *address)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	g_free (priv->hw_address);
	priv->hw_address = g_strdup (address);
	g_object_notify (G_OBJECT (self), NM_DEVICE_802_11_WIRELESS_HW_ADDRESS);
}

const char *
nm_device_802_11_wireless_get_hw_address (NMDevice80211Wireless *device)
{
	NMDevice80211WirelessPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);

	priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);
	if (!priv->hw_address) {
		priv->hw_address = nm_object_get_string_property (NM_OBJECT (device),
		                                                  NM_DBUS_INTERFACE_DEVICE_WIRELESS,
		                                                  DBUS_PROP_HW_ADDRESS);
	}

	return priv->hw_address;
}

static void
nm_device_802_11_wireless_set_mode (NMDevice80211Wireless *self, int mode)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	priv->mode = mode;
	g_object_notify (G_OBJECT (self), NM_DEVICE_802_11_WIRELESS_MODE);
}

int
nm_device_802_11_wireless_get_mode (NMDevice80211Wireless *device)
{
	NMDevice80211WirelessPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), 0);

	priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);
	if (!priv->mode) {
		priv->mode = nm_object_get_int_property (NM_OBJECT (device),
		                                         NM_DBUS_INTERFACE_DEVICE_WIRELESS,
		                                         DBUS_PROP_MODE);
	}

	return priv->mode;
}

static void
nm_device_802_11_wireless_set_bitrate (NMDevice80211Wireless *self, guint32 bitrate)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	if (priv->rate != bitrate) {
		priv->rate = bitrate;
		g_object_notify (G_OBJECT (self), NM_DEVICE_802_11_WIRELESS_BITRATE);
	}
}

guint32
nm_device_802_11_wireless_get_bitrate (NMDevice80211Wireless *device)
{
	NMDevice80211WirelessPrivate *priv;
	NMDeviceState state;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), 0);

	state = nm_device_get_state (NM_DEVICE (device));
	switch (state) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_ACTIVATED:
		break;
	default:
		return 0;
		break;
	}

	priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);
	if (!priv->rate) {
		priv->rate = nm_object_get_uint_property (NM_OBJECT (device),
		                                         NM_DBUS_INTERFACE_DEVICE_WIRELESS,
		                                         DBUS_PROP_BITRATE);
	}

	return priv->rate;
}

static void
nm_device_802_11_wireless_set_capabilities (NMDevice80211Wireless *self, guint caps)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	priv->wireless_caps = caps;
	g_object_notify (G_OBJECT (self), NM_DEVICE_802_11_WIRELESS_CAPABILITIES);
}

guint32
nm_device_802_11_wireless_get_capabilities (NMDevice80211Wireless *device)
{
	NMDevice80211WirelessPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), 0);

	priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);
	if (!priv->wireless_caps) {
		priv->wireless_caps = nm_object_get_uint_property (NM_OBJECT (device),
		                                                   NM_DBUS_INTERFACE_DEVICE_WIRELESS,
		                                                   DBUS_PROP_WIRELESS_CAPABILITIES);
	}

	return priv->wireless_caps;
}

static NMAccessPoint *
get_access_point (NMDevice80211Wireless *device, const char *path, gboolean create_if_not_found)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);
	NMAccessPoint *ap;

	g_return_val_if_fail (path != NULL, NULL);

	/* path of "/" means NULL */
	if (!strcmp (path, "/"))
		return NULL;

	ap = g_hash_table_lookup (priv->aps, path);
	if (!ap && create_if_not_found) {
		ap = nm_access_point_new (nm_object_get_connection (NM_OBJECT (device)), path);
		if (ap)
			g_hash_table_insert (priv->aps, g_strdup (path), ap);
	}

	return ap;
}

static void
nm_device_802_11_wireless_set_active_ap (NMDevice80211Wireless *self,
								 const char *ap_path)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	if (!priv->current_ap && !ap_path)
		return;

	if (priv->current_ap) {
		g_object_unref (priv->current_ap);
		priv->current_ap = NULL;
	}

	if (ap_path) {
		priv->current_ap = get_access_point (self, ap_path, TRUE);
		if (priv->current_ap)
			g_object_ref (priv->current_ap);
	}

	g_object_notify (G_OBJECT (self), NM_DEVICE_802_11_WIRELESS_ACTIVE_ACCESS_POINT);
}

NMAccessPoint *
nm_device_802_11_wireless_get_active_access_point (NMDevice80211Wireless *device)
{
	NMDevice80211WirelessPrivate *priv;
	NMDeviceState state;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);

	state = nm_device_get_state (NM_DEVICE (device));
	switch (state) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_ACTIVATED:
		break;
	default:
		return NULL;
		break;
	}

	priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);
	if (!priv->current_ap) {
		char *path;

		path = nm_object_get_object_path_property (NM_OBJECT (device),
		                                           NM_DBUS_INTERFACE_DEVICE_WIRELESS,
		                                           DBUS_PROP_ACTIVE_ACCESS_POINT);
		if (path) {
			priv->current_ap = get_access_point (device, path, TRUE);
			if (priv->current_ap)
				g_object_ref (priv->current_ap);
			g_free (path);
		}
	}

	return priv->current_ap;
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
			char *path = (char *) g_ptr_array_index (array, i);
			NMAccessPoint *ap = get_access_point (device, (const char *) path, TRUE);
			if (ap)
				list = g_slist_prepend (list, ap);
			g_free (path);
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
	if (device && ap)
		g_signal_emit (device, signals[ACCESS_POINT_ADDED], 0, ap);
}

static void
access_point_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (user_data);
	NMAccessPoint *ap;

	ap = get_access_point (device, path, FALSE);
	if (device && ap) {
		g_signal_emit (device, signals[ACCESS_POINT_REMOVED], 0, ap);
		g_hash_table_remove (NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device)->aps, path);
	}
}

/**************************************************************/

static void
nm_device_802_11_wireless_init (NMDevice80211Wireless *device)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);

	priv->disposed = FALSE;
	priv->aps = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                   (GDestroyNotify) g_free,
	                                   (GDestroyNotify) g_object_unref);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		nm_device_802_11_wireless_set_hw_address (device, g_value_get_string (value));
		break;
	case PROP_MODE:
		nm_device_802_11_wireless_set_mode (device, g_value_get_int (value));
		break;
	case PROP_BITRATE:
		nm_device_802_11_wireless_set_bitrate (device, g_value_get_uint (value));
		break;
	case PROP_ACTIVE_ACCESS_POINT:
		nm_device_802_11_wireless_set_active_ap (device, (char *) g_value_get_boxed (value));
		break;
	case PROP_WIRELESS_CAPABILITIES:
		nm_device_802_11_wireless_set_capabilities (device, g_value_get_uint (value));
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
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, priv->hw_address);
		break;
	case PROP_MODE:
		g_value_set_int (value, priv->mode);
		break;
	case PROP_BITRATE:
		g_value_set_uint (value, priv->rate);
		break;
	case PROP_ACTIVE_ACCESS_POINT:
		g_value_set_boxed (value, priv->current_ap ? nm_object_get_path (NM_OBJECT (priv->current_ap)) : "/");
		break;
	case PROP_WIRELESS_CAPABILITIES:
		g_value_set_uint (value, priv->wireless_caps);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
state_changed_cb (NMDevice *device, NMDeviceState state, gpointer user_data)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (device);

	switch (state) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_ACTIVATED:
		break;
	case NM_DEVICE_STATE_UNKNOWN:
	case NM_DEVICE_STATE_DOWN:
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_FAILED:
	case NM_DEVICE_STATE_CANCELLED:
	default:
		nm_device_802_11_wireless_set_active_ap (self, NULL);
		nm_device_802_11_wireless_set_bitrate (self, 0);
		break;
	}
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

	dbus_g_proxy_add_signal (priv->wireless_proxy, "AccessPointAdded",
	                         DBUS_TYPE_G_OBJECT_PATH,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->wireless_proxy, "AccessPointAdded",
						    G_CALLBACK (access_point_added_proxy),
						    object, NULL);

	dbus_g_proxy_add_signal (priv->wireless_proxy, "AccessPointRemoved",
	                         DBUS_TYPE_G_OBJECT_PATH,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->wireless_proxy, "AccessPointRemoved",
						    G_CALLBACK (access_point_removed_proxy),
						    object, NULL);

	nm_object_handle_properties_changed (NM_OBJECT (object), priv->wireless_proxy);

	g_signal_connect (NM_DEVICE (object),
	                  "state-changed",
	                  G_CALLBACK (state_changed_cb),
	                  NULL);

	return object;
}

static void
dispose (GObject *object)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_802_11_wireless_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	g_object_unref (priv->wireless_proxy);

	g_hash_table_destroy (priv->aps);
	priv->aps = NULL;

	if (priv->current_ap)
		g_object_unref (priv->current_ap);

	G_OBJECT_CLASS (nm_device_802_11_wireless_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (object);

	if (priv->hw_address)
		g_free (priv->hw_address);

	G_OBJECT_CLASS (nm_device_802_11_wireless_parent_class)->finalize (object);
}

static void
nm_device_802_11_wireless_class_init (NMDevice80211WirelessClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);

	g_type_class_add_private (device_class, sizeof (NMDevice80211WirelessPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_802_11_WIRELESS_HW_ADDRESS,
						  "MAC Address",
						  "Hardware MAC address",
						  NULL,
						  G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_int (NM_DEVICE_802_11_WIRELESS_MODE,
					    "Mode",
					    "Mode",
					    0, IW_MODE_INFRA, 0,
					    G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_BITRATE,
		 g_param_spec_uint (NM_DEVICE_802_11_WIRELESS_BITRATE,
					    "Bit Rate",
					    "Bit Rate",
					    0, G_MAXUINT32, 0,
					    G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_ACTIVE_ACCESS_POINT,
		 g_param_spec_boxed (NM_DEVICE_802_11_WIRELESS_ACTIVE_ACCESS_POINT,
						 "Active Access Point",
						 "Active Access Point",
						 DBUS_TYPE_G_OBJECT_PATH,
						 G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_WIRELESS_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_802_11_WIRELESS_CAPABILITIES,
		                    "Wireless Capabilities",
		                    "Wireless Capabilities",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE));

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
