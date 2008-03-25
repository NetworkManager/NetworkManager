/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include "wireless-helper.h"

#include <string.h>

#include "nm-device-802-11-wireless.h"
#include "nm-device-private.h"
#include "nm-object-private.h"
#include "nm-object-cache.h"
#include "nm-dbus-glib-types.h"
#include "nm-types-private.h"

#include "nm-device-802-11-wireless-bindings.h"

G_DEFINE_TYPE (NMDevice80211Wireless, nm_device_802_11_wireless, NM_TYPE_DEVICE)

#define NM_DEVICE_802_11_WIRELESS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessPrivate))

static gboolean demarshal_active_ap (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field);

void nm_device_802_11_wireless_set_wireless_enabled (NMDevice80211Wireless *device, gboolean enabled);

typedef struct {
	gboolean disposed;
	DBusGProxy *proxy;

	char *hw_address;
	int mode;
	guint32 rate;
	NMAccessPoint *active_ap;
	gboolean null_active_ap;
	guint32 wireless_caps;
	GPtrArray *aps;

	gboolean wireless_enabled;
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

GObject *
nm_device_802_11_wireless_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return g_object_new (NM_TYPE_DEVICE_802_11_WIRELESS,
	                     NM_OBJECT_DBUS_CONNECTION, connection,
	                     NM_OBJECT_DBUS_PATH, path,
	                     NULL);
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

NMAccessPoint *
nm_device_802_11_wireless_get_active_access_point (NMDevice80211Wireless *self)
{
	NMDevice80211WirelessPrivate *priv;
	NMDeviceState state;
	char *path;
	GValue value = { 0, };

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (self), NULL);

	state = nm_device_get_state (NM_DEVICE (self));
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

	priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	if (priv->active_ap)
		return priv->active_ap;
	if (priv->null_active_ap)
		return NULL;

	path = nm_object_get_object_path_property (NM_OBJECT (self),
	                                           NM_DBUS_INTERFACE_DEVICE_WIRELESS,
	                                           DBUS_PROP_ACTIVE_ACCESS_POINT);
	if (path) {
		g_value_init (&value, DBUS_TYPE_G_OBJECT_PATH);
		g_value_take_boxed (&value, path);
		demarshal_active_ap (NM_OBJECT (self), NULL, &value, &priv->active_ap);
		g_value_unset (&value);
	}

	return priv->active_ap;
}

GPtrArray *
nm_device_802_11_wireless_get_access_points (NMDevice80211Wireless *self)
{
	NMDevice80211WirelessPrivate *priv;
	DBusGConnection *connection;
	GValue value = { 0, };
	GError *error = NULL;
	GPtrArray *temp;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (self), NULL);

	priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	if (priv->aps)
		return priv->aps;

	if (!org_freedesktop_NetworkManager_Device_Wireless_get_access_points (priv->proxy, &temp, &error)) {
		g_warning ("%s: error getting access points: %s", __func__, error->message);
		g_error_free (error);
		return NULL;
	}

	g_value_init (&value, DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH);
	g_value_take_boxed (&value, temp);
	connection = nm_object_get_connection (NM_OBJECT (self));
	nm_object_array_demarshal (&value, &priv->aps, connection, nm_access_point_new);
	g_value_unset (&value);

	return priv->aps;
}

NMAccessPoint *
nm_device_802_11_wireless_get_access_point_by_path (NMDevice80211Wireless *self,
											        const char *path)
{
	GPtrArray *aps;
	int i;
	NMAccessPoint *ap = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (self), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	aps = nm_device_802_11_wireless_get_access_points (self);
	if (!aps)
		return NULL;

	for (i = 0; i < aps->len; i++) {
		NMAccessPoint *candidate = g_ptr_array_index (aps, i);
		if (!strcmp (nm_object_get_path (NM_OBJECT (candidate)), path)) {
			ap = candidate;
			break;
		}
	}

	return ap;
}

static void
access_point_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (user_data);
	NMAccessPoint *ap;

	g_return_if_fail (self != NULL);

	ap = nm_device_802_11_wireless_get_access_point_by_path (self, path);
	if (ap)
		g_signal_emit (self, signals[ACCESS_POINT_ADDED], 0, ap);
}

static void
access_point_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (user_data);
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	NMAccessPoint *ap;

	g_return_if_fail (self != NULL);

	ap = nm_device_802_11_wireless_get_access_point_by_path (self, path);
	if (ap) {
		g_signal_emit (self, signals[ACCESS_POINT_REMOVED], 0, ap);
		g_ptr_array_remove (priv->aps, ap);
	}
}

static void
clean_up_aps (NMDevice80211Wireless *self, gboolean notify)
{
	NMDevice80211WirelessPrivate *priv;

	g_return_if_fail (NM_IS_DEVICE_802_11_WIRELESS (self));

	priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	if (priv->active_ap)
		g_object_unref (priv->active_ap);

	if (priv->aps) {
		while (priv->aps->len) {
			NMAccessPoint *ap = NM_ACCESS_POINT (g_ptr_array_index (priv->aps, 0));

			if (notify)
				g_signal_emit (self, signals[ACCESS_POINT_REMOVED], 0, ap);
			g_ptr_array_remove (priv->aps, ap);
			g_object_unref (ap);
		}
		g_ptr_array_foreach (priv->aps, (GFunc) g_object_unref, NULL);
		g_ptr_array_free (priv->aps, TRUE);
		priv->aps = NULL;
	}
}

void
nm_device_802_11_wireless_set_wireless_enabled (NMDevice80211Wireless *device,
                                                gboolean enabled)
{
	g_return_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device));

	if (!enabled)
		clean_up_aps (device, TRUE);
}


/**************************************************************/

static void
nm_device_802_11_wireless_init (NMDevice80211Wireless *device)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);

	priv->disposed = FALSE;
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_802_11_wireless_get_hw_address (self));
		break;
	case PROP_MODE:
		g_value_set_int (value, nm_device_802_11_wireless_get_mode (self));
		break;
	case PROP_BITRATE:
		g_value_set_uint (value, nm_device_802_11_wireless_get_bitrate (self));
		break;
	case PROP_ACTIVE_ACCESS_POINT:
		g_value_set_object (value, nm_device_802_11_wireless_get_active_access_point (self));
		break;
	case PROP_WIRELESS_CAPABILITIES:
		g_value_set_uint (value, nm_device_802_11_wireless_get_capabilities (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
state_changed_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (device);
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	switch (nm_device_get_state (device)) {
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
		/* Just clear active AP; don't clear the AP list unless wireless is disabled completely */
		if (priv->active_ap) {
			g_object_unref (priv->active_ap);
			priv->active_ap = NULL;
			priv->null_active_ap = FALSE;
		}
		nm_object_queue_notify (NM_OBJECT (device), NM_DEVICE_802_11_WIRELESS_ACTIVE_ACCESS_POINT);
		priv->rate = 0;
		nm_object_queue_notify (NM_OBJECT (device), NM_DEVICE_802_11_WIRELESS_BITRATE);
		break;
	}
}

static gboolean
demarshal_active_ap (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (object);
	const char *path;
	NMAccessPoint *ap = NULL;
	DBusGConnection *connection;

	if (!G_VALUE_HOLDS (value, DBUS_TYPE_G_OBJECT_PATH))
		return FALSE;

	priv->null_active_ap = FALSE;

	path = g_value_get_boxed (value);
	if (path) {
		if (!strcmp (path, "/"))
			priv->null_active_ap = TRUE;
		else {
			ap = NM_ACCESS_POINT (nm_object_cache_get (path));
			if (ap)
				ap = g_object_ref (ap);
			else {
				connection = nm_object_get_connection (object);
				ap = NM_ACCESS_POINT (nm_access_point_new (connection, path));
			}
		}
	}

	if (priv->active_ap) {
		g_object_unref (priv->active_ap);
		priv->active_ap = NULL;
	}

	if (ap)
		priv->active_ap = ap;

	nm_object_queue_notify (object, NM_DEVICE_802_11_WIRELESS_ACTIVE_ACCESS_POINT);
	return TRUE;
}

static void
register_for_property_changed (NMDevice80211Wireless *device)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_DEVICE_802_11_WIRELESS_HW_ADDRESS,          nm_object_demarshal_generic, &priv->hw_address },
		{ NM_DEVICE_802_11_WIRELESS_MODE,                nm_object_demarshal_generic, &priv->mode },
		{ NM_DEVICE_802_11_WIRELESS_BITRATE,             nm_object_demarshal_generic, &priv->rate },
		{ NM_DEVICE_802_11_WIRELESS_ACTIVE_ACCESS_POINT, demarshal_active_ap,         &priv->active_ap },
		{ NM_DEVICE_802_11_WIRELESS_CAPABILITIES,        nm_object_demarshal_generic, &priv->wireless_caps },
		{ NULL },
	};

	nm_object_handle_properties_changed (NM_OBJECT (device),
	                                     priv->proxy,
	                                     property_changed_info);
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

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
											NM_DBUS_SERVICE,
											nm_object_get_path (NM_OBJECT (object)),
											NM_DBUS_INTERFACE_DEVICE_WIRELESS);

	dbus_g_proxy_add_signal (priv->proxy, "AccessPointAdded",
	                         DBUS_TYPE_G_OBJECT_PATH,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "AccessPointAdded",
						    G_CALLBACK (access_point_added_proxy),
						    object, NULL);

	dbus_g_proxy_add_signal (priv->proxy, "AccessPointRemoved",
	                         DBUS_TYPE_G_OBJECT_PATH,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "AccessPointRemoved",
						    G_CALLBACK (access_point_removed_proxy),
						    object, NULL);

	register_for_property_changed (NM_DEVICE_802_11_WIRELESS (object));

	g_signal_connect (NM_DEVICE (object),
	                  "notify::" NM_DEVICE_STATE,
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

	clean_up_aps (NM_DEVICE_802_11_WIRELESS (object), FALSE);
	g_object_unref (priv->proxy);

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
						  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_int (NM_DEVICE_802_11_WIRELESS_MODE,
					    "Mode",
					    "Mode",
					    0, IW_MODE_INFRA, 0,
					    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_BITRATE,
		 g_param_spec_uint (NM_DEVICE_802_11_WIRELESS_BITRATE,
					    "Bit Rate",
					    "Bit Rate",
					    0, G_MAXUINT32, 0,
					    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_ACTIVE_ACCESS_POINT,
		 g_param_spec_object (NM_DEVICE_802_11_WIRELESS_ACTIVE_ACCESS_POINT,
						 "Active Access Point",
						 "Active Access Point",
						 NM_TYPE_ACCESS_POINT,
						 G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_WIRELESS_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_802_11_WIRELESS_CAPABILITIES,
		                    "Wireless Capabilities",
		                    "Wireless Capabilities",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE));

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
