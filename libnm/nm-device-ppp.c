// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-ppp.h"
#include "nm-device.h"

struct _NMDevicePpp {
	NMDevice parent;
};

struct _NMDevicePppClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDevicePpp, nm_device_ppp, NM_TYPE_DEVICE)

#define NM_DEVICE_PPP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_PPP, NMDevicePppPrivate))

static void
nm_device_ppp_init (NMDevicePpp *device)
{
}

static void
nm_device_ppp_class_init (NMDevicePppClass *klass)
{
}
