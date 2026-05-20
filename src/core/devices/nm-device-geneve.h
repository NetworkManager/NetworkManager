/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2026 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_GENEVE_H__
#define __NETWORKMANAGER_DEVICE_GENEVE_H__

#include "nm-device.h"

#define NM_TYPE_DEVICE_GENEVE (nm_device_geneve_get_type())
#define NM_DEVICE_GENEVE(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_GENEVE, NMDeviceGeneve))
#define NM_DEVICE_GENEVE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_GENEVE, NMDeviceGeneveClass))
#define NM_IS_DEVICE_GENEVE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_GENEVE))
#define NM_IS_DEVICE_GENEVE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_GENEVE))
#define NM_DEVICE_GENEVE_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_GENEVE, NMDeviceGeneveClass))

#define NM_DEVICE_GENEVE_ID       "id"
#define NM_DEVICE_GENEVE_REMOTE   "remote"
#define NM_DEVICE_GENEVE_TOS      "tos"
#define NM_DEVICE_GENEVE_TTL      "ttl"
#define NM_DEVICE_GENEVE_DF       "df"
#define NM_DEVICE_GENEVE_DST_PORT "dst-port"

typedef struct _NMDeviceGeneve      NMDeviceGeneve;
typedef struct _NMDeviceGeneveClass NMDeviceGeneveClass;

GType nm_device_geneve_get_type(void);

#endif /* __NETWORKMANAGER_DEVICE_GENEVE_H__ */
