// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_GENERIC_H__
#define __NETWORKMANAGER_DEVICE_GENERIC_H__

#include "nm-device.h"

#define NM_TYPE_DEVICE_GENERIC            (nm_device_generic_get_type ())
#define NM_DEVICE_GENERIC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_GENERIC, NMDeviceGeneric))
#define NM_DEVICE_GENERIC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_GENERIC, NMDeviceGenericClass))
#define NM_IS_DEVICE_GENERIC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_GENERIC))
#define NM_IS_DEVICE_GENERIC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_GENERIC))
#define NM_DEVICE_GENERIC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_GENERIC, NMDeviceGenericClass))

#define NM_DEVICE_GENERIC_TYPE_DESCRIPTION "type-description"

typedef struct _NMDeviceGeneric NMDeviceGeneric;
typedef struct _NMDeviceGenericClass NMDeviceGenericClass;

GType nm_device_generic_get_type (void);

NMDevice *nm_device_generic_new (const NMPlatformLink *plink,
                                 gboolean nm_plugin_missing);

#endif /* __NETWORKMANAGER_DEVICE_GENERIC_H__ */
