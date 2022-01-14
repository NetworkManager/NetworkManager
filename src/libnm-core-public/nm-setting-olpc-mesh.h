/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2009 One Laptop per Child
 */

#ifndef __NM_SETTING_OLPC_MESH_H__
#define __NM_SETTING_OLPC_MESH_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_OLPC_MESH (nm_setting_olpc_mesh_get_type())
#define NM_SETTING_OLPC_MESH(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_OLPC_MESH, NMSettingOlpcMesh))
#define NM_SETTING_OLPC_MESH_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_OLPC_MESH, NMSettingOlpcMeshClass))
#define NM_IS_SETTING_OLPC_MESH(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_OLPC_MESH))
#define NM_IS_SETTING_OLPC_MESH_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_OLPC_MESH))
#define NM_SETTING_OLPC_MESH_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_OLPC_MESH, NMSettingOlpcMeshClass))

#define NM_SETTING_OLPC_MESH_SETTING_NAME "802-11-olpc-mesh"

#define NM_SETTING_OLPC_MESH_SSID                 "ssid"
#define NM_SETTING_OLPC_MESH_CHANNEL              "channel"
#define NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS "dhcp-anycast-address"

typedef struct _NMSettingOlpcMeshClass NMSettingOlpcMeshClass;

GType nm_setting_olpc_mesh_get_type(void);

NMSetting  *nm_setting_olpc_mesh_new(void);
GBytes     *nm_setting_olpc_mesh_get_ssid(NMSettingOlpcMesh *setting);
guint32     nm_setting_olpc_mesh_get_channel(NMSettingOlpcMesh *setting);
const char *nm_setting_olpc_mesh_get_dhcp_anycast_address(NMSettingOlpcMesh *setting);

G_END_DECLS

#endif /* __NM_SETTING_OLPC_MESH_H__ */
