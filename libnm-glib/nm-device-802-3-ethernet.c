#include "nm-device-802-3-ethernet.h"
#include "nm-device-private.h"

#include "nm-device-802-3-ethernet-bindings.h"

G_DEFINE_TYPE (NMDevice8023Ethernet, nm_device_802_3_ethernet, NM_TYPE_DEVICE)

#define NM_DEVICE_802_3_ETHERNET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_3_ETHERNET, NMDevice8023EthernetPrivate))

typedef struct {
	DBusGProxy *ethernet_proxy;

	gboolean disposed;
} NMDevice8023EthernetPrivate;


static void
nm_device_802_3_ethernet_init (NMDevice8023Ethernet *device)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (device);

	priv->disposed = FALSE;
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDevice8023EthernetPrivate *priv;

	object = G_OBJECT_CLASS (nm_device_802_3_ethernet_parent_class)->constructor (type,
																				  n_construct_params,
																				  construct_params);
	if (!object)
		return NULL;

	priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (object);

	priv->ethernet_proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
													  NM_DBUS_SERVICE,
													  nm_object_get_path (NM_OBJECT (object)),
													  NM_DBUS_INTERFACE_DEVICE_WIRED);
	return object;
}

static void
dispose (GObject *object)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (object);

	if (priv->disposed)
		return;

	priv->disposed = TRUE;

	g_object_unref (priv->ethernet_proxy);

	G_OBJECT_CLASS (nm_device_802_3_ethernet_parent_class)->dispose (object);
}

static void
nm_device_802_3_ethernet_class_init (NMDevice8023EthernetClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);

	g_type_class_add_private (device_class, sizeof (NMDevice8023EthernetPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;
}

NMDevice8023Ethernet *
nm_device_802_3_ethernet_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return (NMDevice8023Ethernet *) g_object_new (NM_TYPE_DEVICE_802_3_ETHERNET,
												  NM_OBJECT_CONNECTION, connection,
												  NM_OBJECT_PATH, path,
												  NULL);
}

int
nm_device_802_3_ethernet_get_speed (NMDevice8023Ethernet *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_802_3_ETHERNET (device), 0);

	return nm_object_get_int_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE_WIRED, "Speed");
}

char *
nm_device_802_3_ethernet_get_hw_address (NMDevice8023Ethernet *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_802_3_ETHERNET (device), NULL);

	return nm_object_get_string_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE_WIRED, "HwAddress");
}
