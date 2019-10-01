// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 * Sjoerd Simons <sjoerd.simons@collabora.co.uk>
 * Daniel Drake <dsd@laptop.org>
 * Copyright (C) 2005 Red Hat, Inc.
 * Copyright (C) 2008 Collabora Ltd.
 * Copyright (C) 2009 One Laptop per Child
 */

#ifndef __NETWORKMANAGER_DEVICE_OLPC_MESH_H__
#define __NETWORKMANAGER_DEVICE_OLPC_MESH_H__

#include "devices/nm-device.h"

#define NM_TYPE_DEVICE_OLPC_MESH            (nm_device_olpc_mesh_get_type ())
#define NM_DEVICE_OLPC_MESH(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMesh))
#define NM_DEVICE_OLPC_MESH_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMeshClass))
#define NM_IS_DEVICE_OLPC_MESH(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_OLPC_MESH))
#define NM_IS_DEVICE_OLPC_MESH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_OLPC_MESH))
#define NM_DEVICE_OLPC_MESH_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMeshClass))

#define NM_DEVICE_OLPC_MESH_COMPANION      "companion"
#define NM_DEVICE_OLPC_MESH_BITRATE        "bitrate"
#define NM_DEVICE_OLPC_MESH_ACTIVE_CHANNEL "active-channel"

typedef struct _NMDeviceOlpcMesh NMDeviceOlpcMesh;
typedef struct _NMDeviceOlpcMeshClass NMDeviceOlpcMeshClass;

GType nm_device_olpc_mesh_get_type (void);

NMDevice *nm_device_olpc_mesh_new (const char *iface);

#endif /* __NETWORKMANAGER_DEVICE_OLPC_MESH_H__ */
