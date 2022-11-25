/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_LOOPBACK_H__
#define __NM_DEVICE_LOOPBACK_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_LOOPBACK (nm_device_loopback_get_type())
#define NM_DEVICE_LOOPBACK(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_LOOPBACK, NMDeviceLoopback))
#define NM_DEVICE_LOOPBACK_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_LOOPBACK, NMDeviceLoopbackClass))
#define NM_IS_DEVICE_LOOPBACK(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_LOOPBACK))
#define NM_IS_DEVICE_LOOPBACK_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_LOOPBACK))
#define NM_DEVICE_LOOPBACK_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_LOOPBACK, NMDeviceLoopbackClass))

/**
 * NMDeviceLoopback:
 *
 * Since: 1.42
 */
typedef struct _NMDeviceLoopback      NMDeviceLoopback;
typedef struct _NMDeviceLoopbackClass NMDeviceLoopbackClass;

NM_AVAILABLE_IN_1_42
GType nm_device_loopback_get_type(void);

G_END_DECLS

#endif /* __NM_DEVICE_LOOPBACK_H__ */
