/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_OLPC_MESH_H__
#define __NM_DEVICE_OLPC_MESH_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_OLPC_MESH (nm_device_olpc_mesh_get_type())
#define NM_DEVICE_OLPC_MESH(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMesh))
#define NM_DEVICE_OLPC_MESH_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMeshClass))
#define NM_IS_DEVICE_OLPC_MESH(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_OLPC_MESH))
#define NM_IS_DEVICE_OLPC_MESH_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_OLPC_MESH))
#define NM_DEVICE_OLPC_MESH_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMeshClass))

#define NM_DEVICE_OLPC_MESH_HW_ADDRESS     "hw-address"
#define NM_DEVICE_OLPC_MESH_COMPANION      "companion"
#define NM_DEVICE_OLPC_MESH_ACTIVE_CHANNEL "active-channel"

/**
 * NMDeviceOlpcMesh:
 */
typedef struct _NMDeviceOlpcMeshClass NMDeviceOlpcMeshClass;

GType nm_device_olpc_mesh_get_type(void);

NM_DEPRECATED_IN_1_24_FOR(nm_device_get_hw_address)
const char *nm_device_olpc_mesh_get_hw_address(NMDeviceOlpcMesh *device);

NMDeviceWifi *nm_device_olpc_mesh_get_companion(NMDeviceOlpcMesh *device);
guint32       nm_device_olpc_mesh_get_active_channel(NMDeviceOlpcMesh *device);

G_END_DECLS

#endif /* __NM_DEVICE_OLPC_MESH_H__ */
