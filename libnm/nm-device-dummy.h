// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_DUMMY_H__
#define __NM_DEVICE_DUMMY_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_DUMMY            (nm_device_dummy_get_type ())
#define NM_DEVICE_DUMMY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_DUMMY, NMDeviceDummy))
#define NM_DEVICE_DUMMY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_DUMMY, NMDeviceDummyClass))
#define NM_IS_DEVICE_DUMMY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_DUMMY))
#define NM_IS_DEVICE_DUMMY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_DUMMY))
#define NM_DEVICE_DUMMY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_DUMMY, NMDeviceDummyClass))

#define NM_DEVICE_DUMMY_HW_ADDRESS  "hw-address"

/**
 * NMDeviceDummy:
 */
struct _NMDeviceDummy {
	NMDevice parent;
};

typedef struct {
	NMDeviceClass parent;

	/*< private >*/
	gpointer padding[4];
} NMDeviceDummyClass;

GType nm_device_dummy_get_type (void);
NM_AVAILABLE_IN_1_10
const char *nm_device_dummy_get_hw_address (NMDeviceDummy *device);

G_END_DECLS

#endif /* __NM_DEVICE_DUMMY_H__ */
