/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include "nm-cdma-device.h"

G_DEFINE_TYPE (NMCdmaDevice, nm_cdma_device, NM_TYPE_DEVICE)

#define NM_CDMA_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CDMA_DEVICE, NMCdmaDevicePrivate))

typedef struct {
	DBusGProxy *cdma_proxy;

	gboolean disposed;
} NMCdmaDevicePrivate;

static void
nm_cdma_device_init (NMCdmaDevice *device)
{
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMCdmaDevicePrivate *priv;

	object = G_OBJECT_CLASS (nm_cdma_device_parent_class)->constructor (type,
														  n_construct_params,
														  construct_params);
	if (!object)
		return NULL;

	priv = NM_CDMA_DEVICE_GET_PRIVATE (object);

	priv->cdma_proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
	                                              NM_DBUS_SERVICE,
	                                              nm_object_get_path (NM_OBJECT (object)),
	                                              NM_DBUS_INTERFACE_CDMA_DEVICE);
	return object;
}

static void
dispose (GObject *object)
{
	NMCdmaDevicePrivate *priv = NM_CDMA_DEVICE_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_cdma_device_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	g_object_unref (priv->cdma_proxy);

	G_OBJECT_CLASS (nm_cdma_device_parent_class)->dispose (object);
}

static void
nm_cdma_device_class_init (NMCdmaDeviceClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);

	g_type_class_add_private (device_class, sizeof (NMCdmaDevicePrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;
}

NMCdmaDevice *
nm_cdma_device_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return (NMCdmaDevice *) g_object_new (NM_TYPE_CDMA_DEVICE,
	                                      NM_OBJECT_CONNECTION, connection,
	                                      NM_OBJECT_PATH, path,
	                                      NULL);
}
