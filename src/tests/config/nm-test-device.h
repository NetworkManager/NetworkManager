// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_TEST_DEVICE_H__
#define __NETWORKMANAGER_TEST_DEVICE_H__

#include "devices/nm-device.h"

#define NM_TYPE_TEST_DEVICE            (nm_test_device_get_type ())
#define NM_TEST_DEVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_TEST_DEVICE, NMTestDevice))
#define NM_TEST_DEVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_TEST_DEVICE, NMTestDeviceClass))
#define NM_IS_TEST_DEVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_TEST_DEVICE))
#define NM_IS_TEST_DEVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_TEST_DEVICE))
#define NM_TEST_DEVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_TEST_DEVICE, NMTestDeviceClass))

typedef struct _NMTestDevice NMTestDevice;
typedef struct _NMTestDeviceClass NMTestDeviceClass;

GType nm_test_device_get_type (void);

NMDevice *nm_test_device_new (const char *hwaddr);

#endif /* __NETWORKMANAGER_TEST_DEVICE_H__ */
