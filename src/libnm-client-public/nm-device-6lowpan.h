/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_6LOWPAN_H__
#define __NM_DEVICE_6LOWPAN_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_6LOWPAN (nm_device_6lowpan_get_type())
#define NM_DEVICE_6LOWPAN(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_6LOWPAN, NMDevice6Lowpan))
#define NM_DEVICE_6LOWPAN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_6LOWPAN, NMDevice6LowpanClass))
#define NM_IS_DEVICE_6LOWPAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_6LOWPAN))
#define NM_IS_DEVICE_6LOWPAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_6LOWPAN))
#define NM_DEVICE_6LOWPAN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_6LOWPAN, NMDevice6LowpanClass))

#define NM_DEVICE_6LOWPAN_PARENT     "parent"
#define NM_DEVICE_6LOWPAN_HW_ADDRESS "hw-address"

/**
 * NMDevice6Lowpan:
 */
typedef struct _NMDevice6LowpanClass NMDevice6LowpanClass;

NM_AVAILABLE_IN_1_14
GType nm_device_6lowpan_get_type(void);

NM_AVAILABLE_IN_1_14
NMDevice *nm_device_6lowpan_get_parent(NMDevice6Lowpan *device);

NM_AVAILABLE_IN_1_14
NM_DEPRECATED_IN_1_24_FOR(nm_device_get_hw_address)
const char *nm_device_6lowpan_get_hw_address(NMDevice6Lowpan *device);

G_END_DECLS

#endif /* __NM_DEVICE_6LOWPAN_H__ */
