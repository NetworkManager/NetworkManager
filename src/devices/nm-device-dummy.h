// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
 *
 * Copyright 2017 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_DUMMY_H__
#define __NETWORKMANAGER_DEVICE_DUMMY_H__

#include "nm-device-generic.h"

#define NM_TYPE_DEVICE_DUMMY            (nm_device_dummy_get_type ())
#define NM_DEVICE_DUMMY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_DUMMY, NMDeviceDummy))
#define NM_DEVICE_DUMMY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_DUMMY, NMDeviceDummyClass))
#define NM_IS_DEVICE_DUMMY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_DUMMY))
#define NM_IS_DEVICE_DUMMY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_DUMMY))
#define NM_DEVICE_DUMMY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_DUMMY, NMDeviceDummyClass))

typedef struct _NMDeviceDummy NMDeviceDummy;
typedef struct _NMDeviceDummyClass NMDeviceDummyClass;

GType nm_device_dummy_get_type (void);

#endif /* __NETWORKMANAGER_DEVICE_DUMMY_H__ */
