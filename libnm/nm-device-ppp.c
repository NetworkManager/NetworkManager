/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
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
