// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include <gmodule.h>

#include "devices/nm-device-factory.h"
#include "nm-setting-gsm.h"
#include "nm-setting-cdma.h"
#include "nm-modem-manager.h"
#include "nm-device-modem.h"
#include "platform/nm-platform.h"

/*****************************************************************************/

#define NM_TYPE_WWAN_FACTORY            (nm_wwan_factory_get_type ())
#define NM_WWAN_FACTORY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WWAN_FACTORY, NMWwanFactory))
#define NM_WWAN_FACTORY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_WWAN_FACTORY, NMWwanFactoryClass))
#define NM_IS_WWAN_FACTORY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WWAN_FACTORY))
#define NM_IS_WWAN_FACTORY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_WWAN_FACTORY))
#define NM_WWAN_FACTORY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_WWAN_FACTORY, NMWwanFactoryClass))

typedef struct {
	NMModemManager *mm;
} NMWwanFactoryPrivate;

typedef struct {
	NMDeviceFactory parent;
	NMWwanFactoryPrivate _priv;
} NMWwanFactory;

typedef struct {
	NMDeviceFactoryClass parent;
} NMWwanFactoryClass;

static GType nm_wwan_factory_get_type (void);

G_DEFINE_TYPE (NMWwanFactory, nm_wwan_factory, NM_TYPE_DEVICE_FACTORY)

#define NM_WWAN_FACTORY_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMWwanFactory, NM_IS_WWAN_FACTORY)

/*****************************************************************************/

NM_DEVICE_FACTORY_DECLARE_TYPES (
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_WWAN_NET)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_GSM_SETTING_NAME, NM_SETTING_CDMA_SETTING_NAME)
)

G_MODULE_EXPORT NMDeviceFactory *
nm_device_factory_create (GError **error)
{
	return (NMDeviceFactory *) g_object_new (NM_TYPE_WWAN_FACTORY, NULL);
}

/*****************************************************************************/

static void
modem_added_cb (NMModemManager *manager,
                NMModem *modem,
                gpointer user_data)
{
	NMWwanFactory *self = NM_WWAN_FACTORY (user_data);
	gs_unref_object NMDevice *device = NULL;
	const char *driver;

	if (nm_modem_is_claimed (modem))
		return;

	driver = nm_modem_get_driver (modem);

	/* If it was a Bluetooth modem and no bluetooth device claimed it, ignore
	 * it.  The rfcomm port (and thus the modem) gets created automatically
	 * by the Bluetooth code during the connection process.
	 */
	if (   driver
	    && strstr (driver, "bluetooth")) {
		nm_log_dbg (LOGD_MB, "WWAN factory ignores bluetooth modem '%s' which should be handled by bluetooth plugin",
		            nm_modem_get_control_port (modem));
		return;
	}

	/* Make the new modem device */
	device = nm_device_modem_new (modem);
	g_signal_emit_by_name (self, NM_DEVICE_FACTORY_DEVICE_ADDED, device);
}

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	g_return_val_if_fail (plink, NULL);
	g_return_val_if_fail (plink->type == NM_LINK_TYPE_WWAN_NET, NULL);
	*out_ignore = TRUE;
	return NULL;
}

static void
start (NMDeviceFactory *factory)
{
	NMWwanFactory *self = NM_WWAN_FACTORY (factory);
	NMWwanFactoryPrivate *priv = NM_WWAN_FACTORY_GET_PRIVATE (self);

	priv->mm = g_object_ref (nm_modem_manager_get ());

	g_signal_connect (priv->mm,
	                  NM_MODEM_MANAGER_MODEM_ADDED,
	                  G_CALLBACK (modem_added_cb),
	                  self);
}

/*****************************************************************************/

static void
nm_wwan_factory_init (NMWwanFactory *self)
{
}

static void
dispose (GObject *object)
{
	NMWwanFactory *self = NM_WWAN_FACTORY (object);
	NMWwanFactoryPrivate *priv = NM_WWAN_FACTORY_GET_PRIVATE (self);

	if (priv->mm)
		g_signal_handlers_disconnect_by_func (priv->mm, modem_added_cb, self);
	g_clear_object (&priv->mm);

	/* Chain up to the parent class */
	G_OBJECT_CLASS (nm_wwan_factory_parent_class)->dispose (object);
}

static void
nm_wwan_factory_class_init (NMWwanFactoryClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceFactoryClass *factory_class = NM_DEVICE_FACTORY_CLASS (klass);

	object_class->dispose = dispose;

	factory_class->get_supported_types = get_supported_types;
	factory_class->create_device = create_device;
	factory_class->start = start;
}
