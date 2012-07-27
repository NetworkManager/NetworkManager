/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* vim: set ft=c ts=4 sts=4 sw=4 noexpandtab smartindent: */
/*
 * libnm-glib -- Access network status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef NM_DEVICE_OLPC_MESH_H
#define NM_DEVICE_OLPC_MESH_H

#include "nm-device.h"
#include "nm-device-wifi.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_OLPC_MESH            (nm_device_olpc_mesh_get_type ())
#define NM_DEVICE_OLPC_MESH(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMesh))
#define NM_DEVICE_OLPC_MESH_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMeshClass))
#define NM_IS_DEVICE_OLPC_MESH(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_OLPC_MESH))
#define NM_IS_DEVICE_OLPC_MESH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_OLPC_MESH))
#define NM_DEVICE_OLPC_MESH_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMeshClass))

/**
 * NMDeviceOlpcMeshError:
 * @NM_DEVICE_OLPC_MESH_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_DEVICE_OLPC_MESH_ERROR_NOT_OLPC_MESH_CONNECTION: the connection was not of Olpc Mesh type
 * @NM_DEVICE_OLPC_MESH_ERROR_INVALID_OLPC_MESH_CONNECTION: the Olpc Mesh connection was invalid
 */
typedef enum {
	NM_DEVICE_OLPC_MESH_ERROR_UNKNOWN = 0,                  /*< nick=UnknownError >*/
	NM_DEVICE_OLPC_MESH_ERROR_NOT_OLPC_MESH_CONNECTION,     /*< nick=NotOlpcMeshConnection >*/
	NM_DEVICE_OLPC_MESH_ERROR_INVALID_OLPC_MESH_CONNECTION, /*< nick=InvalidOlpcMeshConnection >*/
} NMDeviceOlpcMeshError;

#define NM_DEVICE_OLPC_MESH_ERROR nm_device_olpc_mesh_error_quark ()
GQuark nm_device_olpc_mesh_error_quark (void);

#define NM_DEVICE_OLPC_MESH_HW_ADDRESS     "hw-address"
#define NM_DEVICE_OLPC_MESH_COMPANION      "companion"
#define NM_DEVICE_OLPC_MESH_ACTIVE_CHANNEL "active-channel"

typedef struct {
	NMDevice parent;
} NMDeviceOlpcMesh;

typedef struct {
	NMDeviceClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMDeviceOlpcMeshClass;

GType nm_device_olpc_mesh_get_type (void);

GObject *nm_device_olpc_mesh_new (DBusGConnection *connection, const char *path);

const char   *nm_device_olpc_mesh_get_hw_address     (NMDeviceOlpcMesh *device);
NMDeviceWifi *nm_device_olpc_mesh_get_companion      (NMDeviceOlpcMesh *device);
guint32       nm_device_olpc_mesh_get_active_channel (NMDeviceOlpcMesh *device);

G_END_DECLS

#endif /* NM_DEVICE_OLPC_MESH_H */
