/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_IPVLAN_H__
#define __NM_DEVICE_IPVLAN_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_IPVLAN (nm_device_ipvlan_get_type())
#define NM_DEVICE_IPVLAN(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_IPVLAN, NMDeviceIpvlan))
#define NM_DEVICE_IPVLAN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_IPVLAN, NMDeviceIpvlanClass))
#define NM_IS_DEVICE_IPVLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_IPVLAN))
#define NM_IS_DEVICE_IPVLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_IPVLAN))
#define NM_DEVICE_IPVLAN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_IPVLAN, NMDeviceIpvlanClass))

#define NM_DEVICE_IPVLAN_PARENT  "parent"
#define NM_DEVICE_IPVLAN_MODE    "mode"
#define NM_DEVICE_IPVLAN_PRIVATE "private"
#define NM_DEVICE_IPVLAN_VEPA    "vepa"

/**
 * NMDeviceIpvlan:
 *
 * Since: 1.52
 */
typedef struct _NMDeviceIpvlan      NMDeviceIpvlan;
typedef struct _NMDeviceIpvlanClass NMDeviceIpvlanClass;

NM_AVAILABLE_IN_1_52
GType nm_device_ipvlan_get_type(void);

NM_AVAILABLE_IN_1_52
NMDevice *nm_device_ipvlan_get_parent(NMDeviceIpvlan *device);
NM_AVAILABLE_IN_1_52
const char *nm_device_ipvlan_get_mode(NMDeviceIpvlan *device);
NM_AVAILABLE_IN_1_52
gboolean nm_device_ipvlan_get_private(NMDeviceIpvlan *device);
NM_AVAILABLE_IN_1_52
gboolean nm_device_ipvlan_get_vepa(NMDeviceIpvlan *device);

G_END_DECLS

#endif /* __NM_DEVICE_IPVLAN_H__ */
