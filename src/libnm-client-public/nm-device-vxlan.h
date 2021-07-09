/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_VXLAN_H__
#define __NM_DEVICE_VXLAN_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_VXLAN (nm_device_vxlan_get_type())
#define NM_DEVICE_VXLAN(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_VXLAN, NMDeviceVxlan))
#define NM_DEVICE_VXLAN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_VXLAN, NMDeviceVxlanClass))
#define NM_IS_DEVICE_VXLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_VXLAN))
#define NM_IS_DEVICE_VXLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_VXLAN))
#define NM_DEVICE_VXLAN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_VXLAN, NMDeviceVxlanClass))

#define NM_DEVICE_VXLAN_HW_ADDRESS   "hw-address"
#define NM_DEVICE_VXLAN_CARRIER      "carrier"
#define NM_DEVICE_VXLAN_PARENT       "parent"
#define NM_DEVICE_VXLAN_ID           "id"
#define NM_DEVICE_VXLAN_GROUP        "group"
#define NM_DEVICE_VXLAN_LOCAL        "local"
#define NM_DEVICE_VXLAN_SRC_PORT_MIN "src-port-min"
#define NM_DEVICE_VXLAN_SRC_PORT_MAX "src-port-max"
#define NM_DEVICE_VXLAN_LEARNING     "learning"
#define NM_DEVICE_VXLAN_AGEING       "ageing"
#define NM_DEVICE_VXLAN_TOS          "tos"
#define NM_DEVICE_VXLAN_TTL          "ttl"
#define NM_DEVICE_VXLAN_LIMIT        "limit"
#define NM_DEVICE_VXLAN_PROXY        "proxy"
#define NM_DEVICE_VXLAN_RSC          "rsc"
#define NM_DEVICE_VXLAN_L2MISS       "l2miss"
#define NM_DEVICE_VXLAN_L3MISS       "l3miss"
#define NM_DEVICE_VXLAN_DST_PORT     "dst-port"

/**
 * NMDeviceVxlan:
 */
typedef struct _NMDeviceVxlanClass NMDeviceVxlanClass;

NM_AVAILABLE_IN_1_2
GType nm_device_vxlan_get_type(void);

NM_AVAILABLE_IN_1_2
NM_DEPRECATED_IN_1_24_FOR(nm_device_get_hw_address)
const char *nm_device_vxlan_get_hw_address(NMDeviceVxlan *device);

NM_AVAILABLE_IN_1_2
gboolean nm_device_vxlan_get_carrier(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
NMDevice *nm_device_vxlan_get_parent(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
guint nm_device_vxlan_get_id(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
const char *nm_device_vxlan_get_group(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
const char *nm_device_vxlan_get_local(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
guint nm_device_vxlan_get_src_port_min(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
guint nm_device_vxlan_get_src_port_max(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
guint nm_device_vxlan_get_dst_port(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
gboolean nm_device_vxlan_get_learning(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
guint nm_device_vxlan_get_ageing(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
guint nm_device_vxlan_get_tos(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
guint nm_device_vxlan_get_ttl(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
guint nm_device_vxlan_get_limit(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
gboolean nm_device_vxlan_get_proxy(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
gboolean nm_device_vxlan_get_rsc(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
gboolean nm_device_vxlan_get_l2miss(NMDeviceVxlan *device);
NM_AVAILABLE_IN_1_2
gboolean nm_device_vxlan_get_l3miss(NMDeviceVxlan *device);

G_END_DECLS

#endif /* __NM_DEVICE_VXLAN_H__ */
