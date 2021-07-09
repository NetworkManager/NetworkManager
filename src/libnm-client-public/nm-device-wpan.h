/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Lubomir Rintel <lkundrak@v3.sk>
 */

#ifndef __NM_DEVICE_WPAN_H__
#define __NM_DEVICE_WPAN_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_WPAN (nm_device_wpan_get_type())
#define NM_DEVICE_WPAN(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_WPAN, NMDeviceWpan))
#define NM_DEVICE_WPAN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_WPAN, NMDeviceWpanClass))
#define NM_IS_DEVICE_WPAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_WPAN))
#define NM_IS_DEVICE_WPAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_WPAN))
#define NM_DEVICE_WPAN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_WPAN, NMDeviceWpanClass))

#define NM_DEVICE_WPAN_HW_ADDRESS "hw-address"

/**
 * NMDeviceWpan:
 */
typedef struct _NMDeviceWpanClass NMDeviceWpanClass;

NM_AVAILABLE_IN_1_14
GType nm_device_wpan_get_type(void);

NM_AVAILABLE_IN_1_14
NM_DEPRECATED_IN_1_24_FOR(nm_device_get_hw_address)
const char *nm_device_wpan_get_hw_address(NMDeviceWpan *device);

G_END_DECLS

#endif /* __NM_DEVICE_WPAN_H__ */
