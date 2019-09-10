// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
 *
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_ETHERNET_H__
#define __NETWORKMANAGER_DEVICE_ETHERNET_H__

#include "nm-device.h"

#define NM_TYPE_DEVICE_ETHERNET                 (nm_device_ethernet_get_type ())
#define NM_DEVICE_ETHERNET(obj)                 (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernet))
#define NM_DEVICE_ETHERNET_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetClass))
#define NM_IS_DEVICE_ETHERNET(obj)              (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_ETHERNET))
#define NM_IS_DEVICE_ETHERNET_CLASS(klass)      (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_ETHERNET))
#define NM_DEVICE_ETHERNET_GET_CLASS(obj)       (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetClass))

#define NM_DEVICE_ETHERNET_SPEED "speed"
#define NM_DEVICE_ETHERNET_S390_SUBCHANNELS "s390-subchannels"

struct _NMDeviceEthernetPrivate;

typedef struct {
        NMDevice parent;
        struct _NMDeviceEthernetPrivate *_priv;
} NMDeviceEthernet;

typedef struct {
        NMDeviceClass parent;
} NMDeviceEthernetClass;

GType nm_device_ethernet_get_type (void);

#endif /* __NETWORKMANAGER_DEVICE_ETHERNET_H__ */
