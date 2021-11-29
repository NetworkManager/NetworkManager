/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2009 One Laptop per Child
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-olpc-mesh.h"

#include <linux/if_ether.h>

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

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_SSID, PROP_CHANNEL, PROP_DHCP_ANYCAST_ADDRESS, );

typedef struct {
    GBytes *ssid;
    char   *dhcp_anycast_addr;
    guint32 channel;
} NMSettingOlpcMeshPrivate;

/**
 * NMSettingOlpcMesh:
 *
 * OLPC Wireless Mesh Settings
 */
struct _NMSettingOlpcMesh {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingOlpcMeshClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingOlpcMesh, nm_setting_olpc_mesh, NM_TYPE_SETTING)

#define NM_SETTING_OLPC_MESH_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_OLPC_MESH, NMSettingOlpcMeshPrivate))

/*****************************************************************************/

/**
 * nm_setting_olpc_mesh_get_ssid:
 * @setting: the #NMSettingOlpcMesh
 *
 * Returns: (transfer none):
 */
GBytes *
nm_setting_olpc_mesh_get_ssid(NMSettingOlpcMesh *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_OLPC_MESH(setting), NULL);

    return NM_SETTING_OLPC_MESH_GET_PRIVATE(setting)->ssid;
}

guint32
nm_setting_olpc_mesh_get_channel(NMSettingOlpcMesh *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_OLPC_MESH(setting), 0);

    return NM_SETTING_OLPC_MESH_GET_PRIVATE(setting)->channel;
}

const char *
nm_setting_olpc_mesh_get_dhcp_anycast_address(NMSettingOlpcMesh *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_OLPC_MESH(setting), NULL);

    return NM_SETTING_OLPC_MESH_GET_PRIVATE(setting)->dhcp_anycast_addr;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingOlpcMeshPrivate *priv = NM_SETTING_OLPC_MESH_GET_PRIVATE(setting);
    gsize                     length;

    if (!priv->ssid) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            _("property is missing"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OLPC_MESH_SETTING_NAME,
                       NM_SETTING_OLPC_MESH_SSID);
        return FALSE;
    }

    length = g_bytes_get_size(priv->ssid);
    if (length == 0 || length > 32) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("SSID length is out of range <1-32> bytes"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OLPC_MESH_SETTING_NAME,
                       NM_SETTING_OLPC_MESH_SSID);
        return FALSE;
    }

    if (priv->channel == 0 || priv->channel > 13) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%d' is not a valid channel"),
                    priv->channel);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OLPC_MESH_SETTING_NAME,
                       NM_SETTING_OLPC_MESH_CHANNEL);
        return FALSE;
    }

    if (priv->dhcp_anycast_addr && !nm_utils_hwaddr_valid(priv->dhcp_anycast_addr, ETH_ALEN)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is invalid"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OLPC_MESH_SETTING_NAME,
                       NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS);
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_olpc_mesh_init(NMSettingOlpcMesh *setting)
{}

/**
 * nm_setting_olpc_mesh_new:
 *
 * Creates a new #NMSettingOlpcMesh object with default values.
 *
 * Returns: the new empty #NMSettingOlpcMesh object
 **/
NMSetting *
nm_setting_olpc_mesh_new(void)
{
    return g_object_new(NM_TYPE_SETTING_OLPC_MESH, NULL);
}

static void
nm_setting_olpc_mesh_class_init(NMSettingOlpcMeshClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingOlpcMeshPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingOlpcMesh:ssid:
     *
     * SSID of the mesh network to join.
     **/
    _nm_setting_property_define_direct_bytes(properties_override,
                                             obj_properties,
                                             NM_SETTING_OLPC_MESH_SSID,
                                             PROP_SSID,
                                             NM_SETTING_PARAM_INFERRABLE,
                                             NMSettingOlpcMeshPrivate,
                                             ssid);

    /**
     * NMSettingOlpcMesh:channel:
     *
     * Channel on which the mesh network to join is located.
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_OLPC_MESH_CHANNEL,
                                              PROP_CHANNEL,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOlpcMeshPrivate,
                                              channel);

    /**
     * NMSettingOlpcMesh:dhcp-anycast-address:
     *
     * Anycast DHCP MAC address used when requesting an IP address via DHCP.
     * The specific anycast address used determines which DHCP server class
     * answers the request.
     *
     * This is currently only implemented by dhclient DHCP plugin.
     **/
    _nm_setting_property_define_direct_mac_address(properties_override,
                                                   obj_properties,
                                                   NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS,
                                                   PROP_DHCP_ANYCAST_ADDRESS,
                                                   NM_SETTING_PARAM_NONE,
                                                   NMSettingOlpcMeshPrivate,
                                                   dhcp_anycast_addr,
                                                   .direct_set_string_mac_address_len = ETH_ALEN);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_OLPC_MESH,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
