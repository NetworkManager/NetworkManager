/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 */

#ifndef NM_DEVICE_FACTORY_H
#define NM_DEVICE_FACTORY_H

#include <glib.h>
#include <glib-object.h>

#include "NetworkManager.h"
#include "nm-platform.h"
#include "nm-device.h"

/* WARNING: this file is private API between NetworkManager and its internal
 * device plugins.  Its API can change at any time and is not guaranteed to be
 * stable.  NM and device plugins are distributed together and this API is
 * not meant to enable third-party plugins.
 */

typedef struct _NMDeviceFactory NMDeviceFactory;

/**
 * nm_device_factory_create:
 * @error: an error if creation of the factory failed, or %NULL
 *
 * Creates a #GObject that implements the #NMDeviceFactory interface. This
 * function must not emit any signals or perform any actions that would cause
 * devices or components to be created immediately.  Instead these should be
 * deferred to an idle handler.
 *
 * Returns: the #GObject implementing #NMDeviceFactory or %NULL
 */
NMDeviceFactory *nm_device_factory_create (GError **error);

/* Should match nm_device_factory_create() */
typedef NMDeviceFactory * (*NMDeviceFactoryCreateFunc) (GError **error);

/**
 * nm_device_factory_get_device_type:
 *
 * Returns: the #NMDeviceType that this plugin creates
 */
NMDeviceType nm_device_factory_get_device_type (void);

/* Should match nm_device_factory_get_device_type() */
typedef NMDeviceType (*NMDeviceFactoryDeviceTypeFunc) (void);

/********************************************************************/

#define NM_TYPE_DEVICE_FACTORY               (nm_device_factory_get_type ())
#define NM_DEVICE_FACTORY(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_FACTORY, NMDeviceFactory))
#define NM_IS_DEVICE_FACTORY(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_FACTORY))
#define NM_DEVICE_FACTORY_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_DEVICE_FACTORY, NMDeviceFactory))

/* signals */
#define NM_DEVICE_FACTORY_COMPONENT_ADDED "component-added"
#define NM_DEVICE_FACTORY_DEVICE_ADDED    "device-added"

struct _NMDeviceFactory {
	GTypeInterface g_iface;

	/**
	 * new_link:
	 * @factory: the #NMDeviceFactory
	 * @link: the new link
	 * @error: error if the link could be claimed but an error occurred
	 *
	 * The NetworkManager core was notified of a new link which the plugin
	 * may want to claim and create a #NMDevice subclass for.  If the link
	 * represents a device the factory is capable of claiming, but the device
	 * could not be created, %NULL should be returned and @error should be set.
	 * %NULL should always be returned and @error should never be set if the
	 * factory cannot create devices for the type which @link represents.
	 *
	 * Returns: the #NMDevice if the link was claimed and created, %NULL if not
	 */
	NMDevice * (*new_link)        (NMDeviceFactory *factory,
	                               NMPlatformLink *plink,
	                               GError **error);

	/* Signals */

	/**
	 * device_added:
	 * @factory: the #NMDeviceFactory
	 * @device: the new #NMDevice subclass
	 *
	 * The factory emits this signal if it finds a new device by itself.
	 */
	void       (*device_added)    (NMDeviceFactory *factory, NMDevice *device);

	/**
	 * component_added:
	 * @factory: the #NMDeviceFactory
	 * @component: a new component which existing devices may wish to claim
	 *
	 * The factory emits this signal when it finds a new component.  For example,
	 * the WWAN factory may indicate that a new modem is available, which an
	 * existing Bluetooth device may wish to claim.  If no device claims the
	 * component, the plugin is allowed to create a new #NMDevice instance for
	 * that component and emit the "device-added" signal.
	 *
	 * Returns: %TRUE if the component was claimed by a device, %FALSE if not
	 */
	gboolean   (*component_added) (NMDeviceFactory *factory, GObject *component);
};

GType      nm_device_factory_get_type    (void);

NMDevice * nm_device_factory_new_link    (NMDeviceFactory *factory,
                                          NMPlatformLink *plink,
                                          GError **error);

/* For use by implementations */
gboolean   nm_device_factory_emit_component_added (NMDeviceFactory *factory,
                                                   GObject *component);

#endif /* NM_DEVICE_FACTORY_H */

