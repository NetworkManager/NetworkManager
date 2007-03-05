#include "nm-device.h"
#include "nm-device-private.h"
#include "nm-utils.h"

#include "nm-device-bindings.h"

G_DEFINE_TYPE (NMDevice, nm_device, DBUS_TYPE_G_PROXY)

#define NM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE, NMDevicePrivate))

typedef struct {
	NMDeviceState state;
} NMDevicePrivate;

enum {
	STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void device_state_change_proxy (DBusGProxy *proxy, guint state, gpointer user_data);

static void
nm_device_init (NMDevice *device)
{
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;

	object = G_OBJECT_CLASS (nm_device_parent_class)->constructor (type,
																   n_construct_params,
																   construct_params);

	if (!object)
		return NULL;

	dbus_g_proxy_add_signal (DBUS_G_PROXY (object), "StateChanged", G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (DBUS_G_PROXY (object),
								 "StateChanged",
								 G_CALLBACK (device_state_change_proxy),
								 object,
								 NULL);
	return object;
}

static void
nm_device_class_init (NMDeviceClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);

	g_type_class_add_private (device_class, sizeof (NMDevicePrivate));

	/* virtual methods */
	object_class->constructor = constructor;

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

NMDevice *
nm_device_new (DBusGConnection *connection, const char *path)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE,
									  "name", NM_DBUS_SERVICE,
									  "path", path, 
									  "interface", NM_DBUS_INTERFACE_DEVICE,
									  "connection", connection,
									  NULL);
}

void
nm_device_deactivate (NMDevice *device)
{
	GError *err = NULL;

	g_return_if_fail (NM_IS_DEVICE (device));

	if (!org_freedesktop_NetworkManager_Device_deactivate (DBUS_G_PROXY (device), &err)) {
		g_warning ("Cannot deactivate device: %s", err->message);
		g_error_free (err);
	}
}

char *
nm_device_get_iface (NMDevice *device)
{
	char *iface = NULL;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE,
							  "Interface",
							  &value))
		iface = g_strdup (g_value_get_string (&value));

	return iface;
}

char *
nm_device_get_udi (NMDevice *device)
{
	char *udi = NULL;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE,
							  "Udi",
							  &value))
		udi = g_strdup (g_value_get_string (&value));

	return udi;
}

char *
nm_device_get_driver (NMDevice *device)
{
	char *driver = NULL;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE,
							  "Driver",
							  &value))
		driver = g_strdup (g_value_get_string (&value));

	return driver;
}

guint32
nm_device_get_capabilities (NMDevice *device)
{
	guint32 caps = 0;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_DEVICE (device), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE,
							  "Capabilities",
							  &value))
		caps = g_value_get_uint (&value);

	return caps;
}

guint32
nm_device_get_ip4_address (NMDevice *device)
{
	guint32 address = 0;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_DEVICE (device), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE,
							  "Ip4Address",
							  &value))
		address = g_value_get_uint (&value);

	return address;
}

NMIP4Config *
nm_device_get_ip4_config (NMDevice *device)
{
	NMIP4Config *config = NULL;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_DEVICE (device), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (device),
							  NM_DBUS_INTERFACE_DEVICE,
							  "Ip4Config",
							  &value)) {
		DBusGConnection *connection = NULL;

		g_assert (G_VALUE_TYPE (&value) == DBUS_TYPE_G_OBJECT_PATH);

		g_object_get (device, "connection", &connection, NULL);

		config = nm_ip4_config_new (connection, (const char *) g_value_get_boxed (&value));
	}

	return config;
}

NMDeviceState
nm_device_get_state (NMDevice *device)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NM_DEVICE_STATE_UNKNOWN);

	priv = NM_DEVICE_GET_PRIVATE (device);

	if (priv->state == NM_DEVICE_STATE_UNKNOWN) {
		GValue value = {0,};

		if (nm_dbus_get_property (DBUS_G_PROXY (device),
								  NM_DBUS_INTERFACE_DEVICE,
								  "State",
								  &value))
			priv->state = g_value_get_uint (&value);
	}

	return priv->state;
}

NMDeviceType
nm_device_type_for_path (DBusGConnection *connection,
						 const char *path)
{
	DBusGProxy *proxy;
	GValue value = {0,};
	NMDeviceType type = DEVICE_TYPE_UNKNOWN;

	g_return_val_if_fail (connection != NULL, type);
	g_return_val_if_fail (path != NULL, type);

	proxy = dbus_g_proxy_new_for_name (connection,
									   NM_DBUS_SERVICE,
									   path,
									   NM_DBUS_INTERFACE_DEVICE);

	if (nm_dbus_get_property (proxy,
							  NM_DBUS_INTERFACE_DEVICE,
							  "DeviceType",
							  &value))
		type = (NMDeviceType) g_value_get_uint (&value);

	g_object_unref (proxy);

	return type;
}
