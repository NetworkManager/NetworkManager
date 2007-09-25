#include "nm-device.h"
#include "nm-device-private.h"

#include "nm-device-bindings.h"

G_DEFINE_TYPE (NMDevice, nm_device, NM_TYPE_OBJECT)

#define NM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE, NMDevicePrivate))

typedef struct {
	DBusGProxy *device_proxy;
	NMDeviceState state;

	gboolean carrier;
	gboolean carrier_valid;

	gboolean disposed;
} NMDevicePrivate;

enum {
	STATE_CHANGED,
	CARRIER_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_PATH,

	LAST_PROP
};


static void device_state_change_proxy (DBusGProxy *proxy, guint state, gpointer user_data);
static void device_carrier_changed_proxy (DBusGProxy *proxy, gboolean carrier, gpointer user_data);

static void
nm_device_init (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	priv->state = NM_DEVICE_STATE_UNKNOWN;
	priv->carrier = FALSE;
	priv->carrier_valid = FALSE;
	priv->disposed = FALSE;
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	NMObject *object;
	NMDevicePrivate *priv;

	object = (NMObject *) G_OBJECT_CLASS (nm_device_parent_class)->constructor (type,
																				n_construct_params,
																				construct_params);
	if (!object)
		return NULL;

	priv = NM_DEVICE_GET_PRIVATE (object);

	priv->device_proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (object),
													NM_DBUS_SERVICE,
													nm_object_get_path (object),
													NM_DBUS_INTERFACE_DEVICE);

	dbus_g_proxy_add_signal (priv->device_proxy, "StateChanged", G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->device_proxy, "StateChanged",
								 G_CALLBACK (device_state_change_proxy),
								 object, NULL);

	dbus_g_proxy_add_signal (priv->device_proxy, "CarrierChanged", G_TYPE_BOOLEAN, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->device_proxy, "CarrierChanged",
								 G_CALLBACK (device_carrier_changed_proxy),
								 object, NULL);
	return G_OBJECT (object);
}

static void
dispose (GObject *object)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);

	if (priv->disposed)
		return;

	priv->disposed = TRUE;

	g_object_unref (priv->device_proxy);

	G_OBJECT_CLASS (nm_device_parent_class)->dispose (object);
}

static void
nm_device_class_init (NMDeviceClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);

	g_type_class_add_private (device_class, sizeof (NMDevicePrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;

	/* signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDeviceClass, state_changed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__UINT,
					  G_TYPE_NONE, 1,
					  G_TYPE_UINT);
}

static void
device_state_change_proxy (DBusGProxy *proxy, guint state, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	if (priv->state != state) {
		priv->state = state;
		g_signal_emit (device, signals[STATE_CHANGED], 0, state);
	}
}

static void
device_carrier_changed_proxy (DBusGProxy *proxy, gboolean carrier, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	if ((priv->carrier != carrier) || !priv->carrier_valid) {
		priv->carrier_valid = TRUE;
		priv->carrier = carrier;
		g_signal_emit (device, signals[CARRIER_CHANGED], 0, carrier);
	}
}

NMDevice *
nm_device_new (DBusGConnection *connection, const char *path)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE,
									  NM_OBJECT_CONNECTION, connection,
									  NM_OBJECT_PATH, path,
									  NULL);
}

void
nm_device_activate (NMDevice *device,
                    const char *service_name,
                    const char *connection_path,
                    const char *specific_object)
{
	GError *err = NULL;

	g_return_if_fail (NM_IS_DEVICE (device));
	g_return_if_fail (service_name != NULL);
	g_return_if_fail (connection_path != NULL);

	if (!org_freedesktop_NetworkManager_Device_activate (NM_DEVICE_GET_PRIVATE (device)->device_proxy,
	                                                     service_name,
	                                                     connection_path,
	                                                     specific_object ? specific_object : "/",
	                                                     &err)) {
		g_warning ("Cannot activate device: %s", err->message);
		g_error_free (err);
	}
}

void
nm_device_deactivate (NMDevice *device)
{
	GError *err = NULL;

	g_return_if_fail (NM_IS_DEVICE (device));

	if (!org_freedesktop_NetworkManager_Device_deactivate (NM_DEVICE_GET_PRIVATE (device)->device_proxy, &err)) {
		g_warning ("Cannot deactivate device: %s", err->message);
		g_error_free (err);
	}
}

char *
nm_device_get_iface (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return nm_object_get_string_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "Interface");
}

char *
nm_device_get_udi (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return nm_object_get_string_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "Udi");
}

char *
nm_device_get_driver (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return nm_object_get_string_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "Driver");
}

guint32
nm_device_get_capabilities (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), 0);

	return nm_object_get_uint_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "Capabilities");
}

guint32
nm_device_get_ip4_address (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), 0);

	return nm_object_get_uint_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "Ip4Address");
}

NMIP4Config *
nm_device_get_ip4_config (NMDevice *device)
{
	char *path;
	NMIP4Config *config = NULL;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	path = nm_object_get_object_path_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "Ip4Config");

	if (path) {
		config = nm_ip4_config_new (nm_object_get_connection (NM_OBJECT (device)), path);
		g_free (path);
	}

	return config;
}

NMDeviceState
nm_device_get_state (NMDevice *device)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NM_DEVICE_STATE_UNKNOWN);

	priv = NM_DEVICE_GET_PRIVATE (device);

	if (priv->state == NM_DEVICE_STATE_UNKNOWN)
		priv->state = nm_object_get_uint_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "State");

	return priv->state;
}

char *
nm_device_get_description (NMDevice *device)
{
	DBusGProxy *proxy;
	GError *err = NULL;
	char *udi;
	char *physical_device_udi = NULL;
	char *vendor = NULL;
	char *product = NULL;
	char *description = NULL;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	/* First, get the physical device info */

	udi = nm_device_get_udi (device);
	proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (device)),
									   "org.freedesktop.Hal",
									   udi,
									   "org.freedesktop.Hal.Device");
	g_free (udi);

	if (!dbus_g_proxy_call (proxy, "GetPropertyString", &err,
							G_TYPE_STRING, "net.physical_device",
							G_TYPE_INVALID,
							G_TYPE_STRING, &physical_device_udi,
							G_TYPE_INVALID)) {
		g_warning ("Error getting physical device info from HAL: %s", err->message);
		g_error_free (err);
		goto out;
    }
	g_object_unref (proxy);

	/* Now get the vendor and product info from the physical device */

	proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (device)),
									   "org.freedesktop.Hal",
									   physical_device_udi,
									   "org.freedesktop.Hal.Device");

	if (!dbus_g_proxy_call (proxy, "GetPropertyString", &err,
							G_TYPE_STRING, "info.vendor",
							G_TYPE_INVALID,
							G_TYPE_STRING, &vendor,
							G_TYPE_INVALID)) {
		g_warning ("Error getting vendor info from HAL: %s", err->message);
		g_error_free (err);
		goto out;
    }

	if (!dbus_g_proxy_call (proxy, "GetPropertyString", &err,
							G_TYPE_STRING, "info.product",
							G_TYPE_INVALID,
							G_TYPE_STRING, &product,
							G_TYPE_INVALID)) {
		g_warning ("Error getting product info from HAL: %s", err->message);
		g_error_free (err);
		goto out;
    }

	description = g_strdup_printf ("%s %s", vendor, product);

 out:
	g_object_unref (proxy);
	g_free (physical_device_udi);
	g_free (vendor);
	g_free (product);

	return description;
}


gboolean
nm_device_get_carrier (NMDevice *device)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (device);

	if (!priv->carrier_valid) {
		priv->carrier = nm_object_get_boolean_property (NM_OBJECT (device),
		                                                NM_DBUS_INTERFACE_DEVICE, "Carrier");
		priv->carrier_valid = TRUE;
	}

	return priv->carrier;
}

NMDeviceType
nm_device_type_for_path (DBusGConnection *connection,
						 const char *path)
{
	DBusGProxy *proxy;
	GError *err = NULL;
	GValue value = {0,};
	NMDeviceType type = DEVICE_TYPE_UNKNOWN;

	g_return_val_if_fail (connection != NULL, type);
	g_return_val_if_fail (path != NULL, type);

	proxy = dbus_g_proxy_new_for_name (connection,
									   NM_DBUS_SERVICE,
									   path,
									   "org.freedesktop.DBus.Properties");

	if (dbus_g_proxy_call (proxy,
						   "Get", &err,
						   G_TYPE_STRING, NM_DBUS_INTERFACE_DEVICE,
						   G_TYPE_STRING, "DeviceType",
						   G_TYPE_INVALID,
						   G_TYPE_VALUE, &value,
						   G_TYPE_INVALID)) {
		type = (NMDeviceType) g_value_get_uint (&value);
	} else {
		g_warning ("Error in get_property: %s\n", err->message);
		g_error_free (err);
	}

	g_object_unref (proxy);

	return type;
}
