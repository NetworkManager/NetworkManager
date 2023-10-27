/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2023 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_HSR_H__
#define __NM_DEVICE_HSR_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_HSR (nm_device_hsr_get_type())
#define NM_DEVICE_HSR(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_HSR, NMDeviceHsr))
#define NM_DEVICE_HSR_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_HSR, NMDeviceHsClass))
#define NM_IS_DEVICE_HSR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_HSR))
#define NM_IS_DEVICE_HSR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_HSR))
#define NM_DEVICE_HSR_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_HSR, NMDeviceHsrClass))

#define NM_DEVICE_HSR_PORT1               "port1"
#define NM_DEVICE_HSR_PORT2               "port2"
#define NM_DEVICE_HSR_SUPERVISION_ADDRESS "supervision-address"
#define NM_DEVICE_HSR_MULTICAST_SPEC      "multicast-spec"
#define NM_DEVICE_HSR_PRP                 "prp"

/**
 * NMDeviceHsr:
 *
 * Since: 1.46
 */
typedef struct _NMDeviceHsr      NMDeviceHsr;
typedef struct _NMDeviceHsrClass NMDeviceHsrClass;

NM_AVAILABLE_IN_1_46
GType nm_device_hsr_get_type(void);

NM_AVAILABLE_IN_1_46
NMDevice *nm_device_hsr_get_port1(NMDeviceHsr *device);
NM_AVAILABLE_IN_1_46
NMDevice *nm_device_hsr_get_port2(NMDeviceHsr *device);
NM_AVAILABLE_IN_1_46
const char *nm_device_hsr_get_supervision_address(NMDeviceHsr *device);
NM_AVAILABLE_IN_1_46
guint8 nm_device_hsr_get_multicast_spec(NMDeviceHsr *device);
NM_AVAILABLE_IN_1_46
gboolean nm_device_hsr_get_prp(NMDeviceHsr *device);

G_END_DECLS

#endif /* __NM_DEVICE_HSR_H__ */
