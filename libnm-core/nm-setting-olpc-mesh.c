/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2007 - 2013 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2009 One Laptop per Child
 */

#include "nm-default.h"

#include <string.h>

#include "nm-setting-olpc-mesh.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-olpc-mesh
 * @short_description: Describes connection properties for OLPC-Mesh devices
 *
 * The #NMSettingOlpcMesh object is a #NMSetting subclass that describes properties
 * necessary for connection to OLPC-Mesh devices.
 **/

static void nm_setting_olpc_mesh_init (NMSettingOlpcMesh *setting);

G_DEFINE_TYPE_WITH_CODE (NMSettingOlpcMesh, nm_setting_olpc_mesh, NM_TYPE_SETTING,
                         _nm_register_setting (OLPC_MESH, NM_SETTING_PRIORITY_HW_BASE))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_OLPC_MESH)

#define NM_SETTING_OLPC_MESH_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_OLPC_MESH, NMSettingOlpcMeshPrivate))

typedef struct {
	GBytes *ssid;
	guint32 channel;
	char *dhcp_anycast_addr;
} NMSettingOlpcMeshPrivate;

enum {
	PROP_0,
	PROP_SSID,
	PROP_CHANNEL,
	PROP_DHCP_ANYCAST_ADDRESS,

	LAST_PROP
};

/**
 * nm_setting_olpc_mesh_new:
 *
 * Creates a new #NMSettingOlpcMesh object with default values.
 *
 * Returns: the new empty #NMSettingOlpcMesh object
 **/
NMSetting *nm_setting_olpc_mesh_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_OLPC_MESH, NULL);
}

static void
nm_setting_olpc_mesh_init (NMSettingOlpcMesh *setting)
{
}

/**
 * nm_setting_olpc_mesh_get_ssid:
 * @setting: the #NMSettingOlpcMesh
 *
 * Returns: (transfer none):
 */
GBytes *
nm_setting_olpc_mesh_get_ssid (NMSettingOlpcMesh *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_OLPC_MESH (setting), NULL);

	return NM_SETTING_OLPC_MESH_GET_PRIVATE (setting)->ssid;
}

guint32
nm_setting_olpc_mesh_get_channel (NMSettingOlpcMesh *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_OLPC_MESH (setting), 0);

	return NM_SETTING_OLPC_MESH_GET_PRIVATE (setting)->channel;
}

const char *
nm_setting_olpc_mesh_get_dhcp_anycast_address (NMSettingOlpcMesh *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_OLPC_MESH (setting), NULL);

	return NM_SETTING_OLPC_MESH_GET_PRIVATE (setting)->dhcp_anycast_addr;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingOlpcMeshPrivate *priv = NM_SETTING_OLPC_MESH_GET_PRIVATE (setting);
	gsize length;

	if (!priv->ssid) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_OLPC_MESH_SETTING_NAME, NM_SETTING_OLPC_MESH_SSID);
		return FALSE;
	}

	length = g_bytes_get_size (priv->ssid);
	if (length == 0 || length > 32) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("SSID length is out of range <1-32> bytes"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_OLPC_MESH_SETTING_NAME, NM_SETTING_OLPC_MESH_SSID);
		return FALSE;
	}

	if (priv->channel == 0 || priv->channel > 13) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%d' is not a valid channel"),
		             priv->channel);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_OLPC_MESH_SETTING_NAME, NM_SETTING_OLPC_MESH_CHANNEL);
		return FALSE;
	}

	if (priv->dhcp_anycast_addr && !nm_utils_hwaddr_valid (priv->dhcp_anycast_addr, ETH_ALEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_OLPC_MESH_SETTING_NAME, NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS);
		return FALSE;
	}

	return TRUE;
}

static void
finalize (GObject *object)
{
	NMSettingOlpcMeshPrivate *priv = NM_SETTING_OLPC_MESH_GET_PRIVATE (object);

	if (priv->ssid)
		g_bytes_unref (priv->ssid);
	g_free (priv->dhcp_anycast_addr);

	G_OBJECT_CLASS (nm_setting_olpc_mesh_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingOlpcMeshPrivate *priv = NM_SETTING_OLPC_MESH_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SSID:
		if (priv->ssid)
			g_bytes_unref (priv->ssid);
		priv->ssid = g_value_dup_boxed (value);
		break;
	case PROP_CHANNEL:
		priv->channel = g_value_get_uint (value);
		break;
	case PROP_DHCP_ANYCAST_ADDRESS:
		g_free (priv->dhcp_anycast_addr);
		priv->dhcp_anycast_addr = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingOlpcMesh *setting = NM_SETTING_OLPC_MESH (object);

	switch (prop_id) {
	case PROP_SSID:
		g_value_set_boxed (value, nm_setting_olpc_mesh_get_ssid (setting));
		break;
	case PROP_CHANNEL:
		g_value_set_uint (value, nm_setting_olpc_mesh_get_channel (setting));
		break;
	case PROP_DHCP_ANYCAST_ADDRESS:
		g_value_set_string (value, nm_setting_olpc_mesh_get_dhcp_anycast_address (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_olpc_mesh_class_init (NMSettingOlpcMeshClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingOlpcMeshPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
	/**
	 * NMSettingOlpcMesh:ssid:
	 *
	 * SSID of the mesh network to join.
	 **/
	g_object_class_install_property
		(object_class, PROP_SSID,
		 g_param_spec_boxed (NM_SETTING_OLPC_MESH_SSID, "", "",
		                     G_TYPE_BYTES,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingOlpcMesh:channel:
	 *
	 * Channel on which the mesh network to join is located.
	 **/
	g_object_class_install_property
		(object_class, PROP_CHANNEL,
		 g_param_spec_uint (NM_SETTING_OLPC_MESH_CHANNEL, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_INFERRABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingOlpcMesh:dhcp-anycast-address:
	 *
	 * Anycast DHCP MAC address used when requesting an IP address via DHCP.
	 * The specific anycast address used determines which DHCP server class
	 * answers the request.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP_ANYCAST_ADDRESS,
		 g_param_spec_string (NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS,
	                                      G_VARIANT_TYPE_BYTESTRING,
	                                      _nm_utils_hwaddr_to_dbus,
	                                      _nm_utils_hwaddr_from_dbus);
}
