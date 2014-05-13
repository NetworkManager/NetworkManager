/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager
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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "nm-device-factory.h"

enum {
	DEVICE_ADDED,
	COMPONENT_ADDED,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

gboolean
nm_device_factory_emit_component_added (NMDeviceFactory *factory, GObject *component)
{
	gboolean consumed = FALSE;

	g_signal_emit (factory, signals[COMPONENT_ADDED], 0, component, &consumed);
	return consumed;
}

static void
interface_init (gpointer g_iface)
{
	GType iface_type = G_TYPE_FROM_INTERFACE (g_iface);
	static gboolean initialized = FALSE;

	if (G_LIKELY (initialized))
		return;

	/* Signals */
	signals[DEVICE_ADDED] = g_signal_new (NM_DEVICE_FACTORY_DEVICE_ADDED,
	                                      iface_type,
	                                      G_SIGNAL_RUN_FIRST,
	                                      G_STRUCT_OFFSET (NMDeviceFactory, device_added),
	                                      NULL, NULL, NULL,
	                                      G_TYPE_NONE, 1, NM_TYPE_DEVICE);

	signals[COMPONENT_ADDED] = g_signal_new (NM_DEVICE_FACTORY_COMPONENT_ADDED,
	                                         iface_type,
	                                         G_SIGNAL_RUN_LAST,
	                                         G_STRUCT_OFFSET (NMDeviceFactory, component_added),
	                                         g_signal_accumulator_true_handled, NULL, NULL,
	                                         G_TYPE_BOOLEAN, 1, G_TYPE_OBJECT);

	initialized = TRUE;
}

GType
nm_device_factory_get_type (void)
{
	static GType device_factory_type = 0;

	if (!device_factory_type) {
		const GTypeInfo device_factory_info = {
			sizeof (NMDeviceFactory), /* class_size */
			interface_init,           /* base_init */
			NULL,                     /* base_finalize */
			NULL,
			NULL,                     /* class_finalize */
			NULL,                     /* class_data */
			0,
			0,                        /* n_preallocs */
			NULL
		};

		device_factory_type = g_type_register_static (G_TYPE_INTERFACE,
		                                              "NMDeviceFactory",
		                                              &device_factory_info,
		                                              0);
		g_type_interface_add_prerequisite (device_factory_type, G_TYPE_OBJECT);
	}

	return device_factory_type;
}

NMDevice *
nm_device_factory_new_link (NMDeviceFactory *factory,
                            NMPlatformLink *plink,
                            GError **error)
{
	g_return_val_if_fail (factory != NULL, NULL);
	g_return_val_if_fail (plink != NULL, NULL);

	if (NM_DEVICE_FACTORY_GET_INTERFACE (factory)->new_link)
		return NM_DEVICE_FACTORY_GET_INTERFACE (factory)->new_link (factory, plink, error);
	return NULL;
}

