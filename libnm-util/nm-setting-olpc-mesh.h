/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 * Sjoerd Simons <sjoerd.simons@collabora.co.uk>
 * Daniel Drake <dsd@laptop.org>
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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 * (C) Copyright 2009 One Laptop per Child
 */

#ifndef NM_SETTING_OLPC_MESH_H
#define NM_SETTING_OLPC_MESH_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_OLPC_MESH            (nm_setting_olpc_mesh_get_type ())
#define NM_SETTING_OLPC_MESH(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_OLPC_MESH, NMSettingOlpcMesh))
#define NM_SETTING_OLPC_MESH_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_OLPC_MESH, NMSettingOlpcMeshClass))
#define NM_IS_SETTING_OLPC_MESH(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_OLPC_MESH))
#define NM_IS_SETTING_OLPC_MESH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_OLPC_MESH))
#define NM_SETTING_OLPC_MESH_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_OLPC_MESH, NMSettingOlpcMeshClass))

#define NM_SETTING_OLPC_MESH_SETTING_NAME "802-11-olpc-mesh"

/**
 * NMSettingOlpcMeshError:
 * @NM_SETTING_OLPC_MESH_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_OLPC_MESH_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_OLPC_MESH_ERROR_MISSING_PROPERTY: the property was missing and is
 * required
 */
typedef enum {
	NM_SETTING_OLPC_MESH_ERROR_UNKNOWN = 0,      /*< nick=UnknownError >*/
	NM_SETTING_OLPC_MESH_ERROR_INVALID_PROPERTY, /*< nick=InvalidProperty >*/
	NM_SETTING_OLPC_MESH_ERROR_MISSING_PROPERTY  /*< nick=MissingProperty >*/
} NMSettingOlpcMeshError;

#define NM_SETTING_OLPC_MESH_ERROR nm_setting_olpc_mesh_error_quark ()
GQuark nm_setting_olpc_mesh_error_quark (void);

#define NM_SETTING_OLPC_MESH_SSID                 "ssid"
#define NM_SETTING_OLPC_MESH_CHANNEL              "channel"
#define NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS "dhcp-anycast-address"

typedef struct {
	NMSetting parent;
} NMSettingOlpcMesh;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingOlpcMeshClass;

GType nm_setting_olpc_mesh_get_type (void);

NMSetting *       nm_setting_olpc_mesh_new                      (void);
const GByteArray *nm_setting_olpc_mesh_get_ssid                 (NMSettingOlpcMesh *setting);
guint32           nm_setting_olpc_mesh_get_channel              (NMSettingOlpcMesh *setting);
const GByteArray *nm_setting_olpc_mesh_get_dhcp_anycast_address (NMSettingOlpcMesh *setting);

G_END_DECLS

#endif /* NM_SETTING_OLPC_MESH_H */
