/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_GENEVE_H__
#define __NM_DEVICE_GENEVE_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_GENEVE (nm_device_geneve_get_type())
#define NM_DEVICE_GENEVE(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_GENEVE, NMDeviceGeneve))
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
#define NM_DEVICE_GENEVE_DST_PORT "dst-port"
#define NM_DEVICE_GENEVE_DF       "df"

/**
 * NMDeviceGeneve:
 *
 * Since: 1.58, 1.56.1
 */
typedef struct _NMDeviceGeneve      NMDeviceGeneve;
typedef struct _NMDeviceGeneveClass NMDeviceGeneveClass;

NM_AVAILABLE_IN_1_56_1
GType nm_device_geneve_get_type(void);

NM_AVAILABLE_IN_1_56_1
guint nm_device_geneve_get_id(NMDeviceGeneve *device);
NM_AVAILABLE_IN_1_56_1
const char *nm_device_geneve_get_remote(NMDeviceGeneve *device);
NM_AVAILABLE_IN_1_56_1
guint nm_device_geneve_get_dst_port(NMDeviceGeneve *device);
NM_AVAILABLE_IN_1_56_1
guint nm_device_geneve_get_tos(NMDeviceGeneve *device);
NM_AVAILABLE_IN_1_56_1
guint nm_device_geneve_get_ttl(NMDeviceGeneve *device);
NM_AVAILABLE_IN_1_56_1
guint nm_device_geneve_get_df(NMDeviceGeneve *device);

G_END_DECLS

#endif /* __NM_DEVICE_GENEVE_H__ */
