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
 * Copyright 2013 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>

#include "nm-test-device.h"
#include "nm-device-private.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMTestDevice, nm_test_device, NM_TYPE_DEVICE)

#define PARENT_CLASS (G_OBJECT_CLASS (g_type_class_peek_parent (nm_test_device_parent_class)))

static void
nm_test_device_init (NMTestDevice *self)
{
}

/* We jump over NMDevice's construct/destruct methods, which require NMPlatform
 * and NMConnectionProvider to be initialized.
 */

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	return PARENT_CLASS->constructor (type,
	                                  n_construct_params,
	                                  construct_params);
}

static void
constructed (GObject *object)
{
	PARENT_CLASS->constructed (object);
}

static void
dispose (GObject *object)
{
	PARENT_CLASS->dispose (object);
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	return NM_DEVICE_CAP_IS_NON_KERNEL;
}

static void
nm_test_device_class_init (NMTestDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->constructor = constructor;
	object_class->constructed = constructed;
	object_class->dispose = dispose;

	device_class->get_generic_capabilities = get_generic_capabilities;
}

NMDevice *
nm_test_device_new (const char *hwaddr)
{
	return g_object_new (NM_TYPE_TEST_DEVICE,
	                     NM_DEVICE_IFACE, "dummy",
	                     NM_DEVICE_HW_ADDRESS, hwaddr,
	                     NULL);
}
