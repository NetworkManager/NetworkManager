/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SETTING_OLPC_MESH_H
#define NM_SETTING_OLPC_MESH_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_OLPC_MESH            (nm_setting_olpc_mesh_get_type ())
#define NM_SETTING_OLPC_MESH(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_OLPC_MESH, NMSettingOlpcMesh))
#define NM_SETTING_OLPC_MESH_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_OLPC_MESH, NMSettingOlpcMeshClass))
#define NM_IS_SETTING_OLPC_MESH(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_OLPC_MESH))
#define NM_IS_SETTING_OLPC_MESH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_OLPC_MESH))
#define NM_SETTING_OLPC_MESH_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_OLPC_MESH, NMSettingOlpcMeshClass))

#define NM_SETTING_OLPC_MESH_SETTING_NAME "802-11-olpc-mesh"

typedef enum
{
	NM_SETTING_OLPC_MESH_ERROR_UNKNOWN = 0,
	NM_SETTING_OLPC_MESH_ERROR_INVALID_PROPERTY,
	NM_SETTING_OLPC_MESH_ERROR_MISSING_PROPERTY
} NMSettingOlpcMeshError;

#define NM_TYPE_SETTING_OLPC_MESH_ERROR (nm_setting_olpc_mesh_error_get_type ()) 
GType nm_setting_olpc_mesh_error_get_type (void);

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

const GByteArray *nm_setting_olpc_mesh_get_ssid                 (NMSettingOlpcMesh *setting);
guint32           nm_setting_olpc_mesh_get_channel              (NMSettingOlpcMesh *setting);
const GByteArray *nm_setting_olpc_mesh_get_dhcp_anycast_address (NMSettingOlpcMesh *setting);

G_END_DECLS

#endif /* NM_SETTING_OLPC_MESH_H */
