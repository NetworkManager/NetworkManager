/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2012 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_ETHERNET_H__
#define __NM_DEVICE_ETHERNET_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_ETHERNET (nm_device_ethernet_get_type())
#define NM_DEVICE_ETHERNET(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernet))
#define NM_DEVICE_ETHERNET_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetClass))
#define NM_IS_DEVICE_ETHERNET(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_ETHERNET))
#define NM_IS_DEVICE_ETHERNET_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_ETHERNET))
#define NM_DEVICE_ETHERNET_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetClass))

#define NM_DEVICE_ETHERNET_HW_ADDRESS           "hw-address"
#define NM_DEVICE_ETHERNET_PERMANENT_HW_ADDRESS "perm-hw-address"
#define NM_DEVICE_ETHERNET_SPEED                "speed"
#define NM_DEVICE_ETHERNET_CARRIER              "carrier"
#define NM_DEVICE_ETHERNET_S390_SUBCHANNELS     "s390-subchannels"

/**
 * NMDeviceEthernet:
 */
typedef struct _NMDeviceEthernetClass NMDeviceEthernetClass;

GType nm_device_ethernet_get_type(void);

NM_DEPRECATED_IN_1_24_FOR(nm_device_get_hw_address)
const char *nm_device_ethernet_get_hw_address(NMDeviceEthernet *device);

const char *nm_device_ethernet_get_permanent_hw_address(NMDeviceEthernet *device);
guint32     nm_device_ethernet_get_speed(NMDeviceEthernet *device);
gboolean    nm_device_ethernet_get_carrier(NMDeviceEthernet *device);
NM_AVAILABLE_IN_1_2
const char *const *nm_device_ethernet_get_s390_subchannels(NMDeviceEthernet *device);

G_END_DECLS

#endif /* __NM_DEVICE_ETHERNET_H__ */
