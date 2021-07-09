/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_GENERIC_H__
#define __NM_DEVICE_GENERIC_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_GENERIC (nm_device_generic_get_type())
#define NM_DEVICE_GENERIC(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_GENERIC, NMDeviceGeneric))
#define NM_DEVICE_GENERIC_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_GENERIC, NMDeviceGenericClass))
#define NM_IS_DEVICE_GENERIC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_GENERIC))
#define NM_IS_DEVICE_GENERIC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_GENERIC))
#define NM_DEVICE_GENERIC_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_GENERIC, NMDeviceGenericClass))

#define NM_DEVICE_GENERIC_HW_ADDRESS       "hw-address"
#define NM_DEVICE_GENERIC_TYPE_DESCRIPTION "type-description"

/**
 * NMDeviceGeneric:
 */
typedef struct _NMDeviceGenericClass NMDeviceGenericClass;

GType nm_device_generic_get_type(void);

NM_DEPRECATED_IN_1_24_FOR(nm_device_get_hw_address)
const char *nm_device_generic_get_hw_address(NMDeviceGeneric *device);

G_END_DECLS

#endif /* __NM_DEVICE_GENERIC_H__ */
