/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 * Sjoerd Simons <sjoerd.simons@collabora.co.uk>
 * Daniel Drake <dsd@laptop.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 * (C) Copyright 2008 Collabora Ltd.
 * (C) Copyright 2009 One Laptop per Child
 */

#ifndef __NETWORKMANAGER_DEVICE_OLPC_MESH_H__
#define __NETWORKMANAGER_DEVICE_OLPC_MESH_H__

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_OLPC_MESH            (nm_device_olpc_mesh_get_type ())
#define NM_DEVICE_OLPC_MESH(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMesh))
#define NM_DEVICE_OLPC_MESH_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMeshClass))
#define NM_IS_DEVICE_OLPC_MESH(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_OLPC_MESH))
#define NM_IS_DEVICE_OLPC_MESH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_OLPC_MESH))
#define NM_DEVICE_OLPC_MESH_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMeshClass))

#define NM_DEVICE_OLPC_MESH_COMPANION      "companion"
#define NM_DEVICE_OLPC_MESH_BITRATE        "bitrate"
#define NM_DEVICE_OLPC_MESH_ACTIVE_CHANNEL "active-channel"

#ifndef NM_DEVICE_OLPC_MESH_DEFINED
#define NM_DEVICE_OLPC_MESH_DEFINED
typedef struct _NMDeviceOlpcMesh NMDeviceOlpcMesh;
#endif

typedef struct _NMDeviceOlpcMeshClass NMDeviceOlpcMeshClass;
typedef struct _NMDeviceOlpcMeshPrivate NMDeviceOlpcMeshPrivate;

struct _NMDeviceOlpcMesh
{
	NMDevice parent;
};

struct _NMDeviceOlpcMeshClass
{
	NMDeviceClass parent;

};


GType nm_device_olpc_mesh_get_type (void);

NMDevice *nm_device_olpc_mesh_new (const char *iface);

G_END_DECLS

#endif  /* NM_DEVICE_OLPC_MESH_H */
