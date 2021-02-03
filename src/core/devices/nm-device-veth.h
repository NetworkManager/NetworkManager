/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_VETH_H__
#define __NETWORKMANAGER_DEVICE_VETH_H__

#include "nm-device-ethernet.h"

#define NM_TYPE_DEVICE_VETH (nm_device_veth_get_type())
#define NM_DEVICE_VETH(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_VETH, NMDeviceVeth))
#define NM_DEVICE_VETH_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_VETH, NMDeviceVethClass))
#define NM_IS_DEVICE_VETH(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_VETH))
#define NM_IS_DEVICE_VETH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_VETH))
#define NM_DEVICE_VETH_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_VETH, NMDeviceVethClass))

#define NM_DEVICE_VETH_PEER "peer"

typedef struct _NMDeviceVeth      NMDeviceVeth;
typedef struct _NMDeviceVethClass NMDeviceVethClass;

GType nm_device_veth_get_type(void);

#endif /* __NETWORKMANAGER_DEVICE_VETH_H__ */
