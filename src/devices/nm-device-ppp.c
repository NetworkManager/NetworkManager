/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-ppp.h"

#include "nm-device-factory.h"
#include "nm-device-private.h"
#include "platform/nm-platform.h"

#include "introspection/org.freedesktop.NetworkManager.Device.Ppp.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDevicePpp);

/*****************************************************************************/

typedef struct _NMDevicePppPrivate {
	int dummy;
} NMDevicePppPrivate;

struct _NMDevicePpp {
	NMDevice parent;
	NMDevicePppPrivate _priv;
};

struct _NMDevicePppClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDevicePpp, nm_device_ppp, NM_TYPE_DEVICE)

#define NM_DEVICE_PPP_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDevicePpp, NM_IS_DEVICE_PPP)

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	return NM_DEVICE_CAP_IS_SOFTWARE;
}

static void
nm_device_ppp_init (NMDevicePpp *self)
{
}

static void
dispose (GObject *object)
{
	G_OBJECT_CLASS (nm_device_ppp_parent_class)->dispose (object);
}

static void
nm_device_ppp_class_init (NMDevicePppClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NULL, NM_LINK_TYPE_PPP)

	object_class->dispose = dispose;
	parent_class->get_generic_capabilities = get_generic_capabilities;

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_PPP_SKELETON,
	                                        NULL);
}

/*****************************************************************************/

#define NM_TYPE_PPP_DEVICE_FACTORY (nm_ppp_device_factory_get_type ())
#define NM_PPP_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PPP_DEVICE_FACTORY, NMPppDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_PPP,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "Ppp",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_PPP,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_PPP,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (PPP, Ppp, ppp,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_PPP),
	factory_class->create_device = create_device;
);
