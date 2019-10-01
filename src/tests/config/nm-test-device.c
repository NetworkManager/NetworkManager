// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-test-device.h"

#include "devices/nm-device-private.h"
#include "nm-utils.h"

/*****************************************************************************/

struct _NMTestDevice {
	NMDevice parent;
};

struct _NMTestDeviceClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMTestDevice, nm_test_device, NM_TYPE_DEVICE)

#define PARENT_CLASS (G_OBJECT_CLASS (g_type_class_peek_parent (nm_test_device_parent_class)))

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	return NM_DEVICE_CAP_IS_NON_KERNEL;
}

/*****************************************************************************/

static void
nm_test_device_init (NMTestDevice *self)
{
}

/* We jump over NMDevice's construct/destruct methods, which require NMPlatform
 * and NMSettings to be initialized.
 */
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

NMDevice *
nm_test_device_new (const char *hwaddr)
{
	return g_object_new (NM_TYPE_TEST_DEVICE,
	                     NM_DEVICE_IFACE, "dummy",
	                     NM_DEVICE_PERM_HW_ADDRESS, hwaddr,
	                     NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_ETHERNET,
	                     NULL);
}

static void
nm_test_device_class_init (NMTestDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->constructed = constructed;
	object_class->dispose = dispose;

	device_class->get_generic_capabilities = get_generic_capabilities;
}
