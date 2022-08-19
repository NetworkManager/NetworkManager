/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-vxlan.h"

#include <stdlib.h>

#include "nm-utils.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-vxlan
 * @short_description: Describes connection properties for VXLAN interfaces
 *
 * The #NMSettingVxlan object is a #NMSetting subclass that describes properties
 * necessary for connection to VXLAN interfaces.
 **/

#define DST_PORT_DEFAULT 8472

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PARENT,
                                  PROP_ID,
                                  PROP_LOCAL,
                                  PROP_REMOTE,
                                  PROP_SOURCE_PORT_MIN,
                                  PROP_SOURCE_PORT_MAX,
                                  PROP_DESTINATION_PORT,
                                  PROP_TOS,
                                  PROP_TTL,
                                  PROP_AGEING,
                                  PROP_LIMIT,
                                  PROP_LEARNING,
                                  PROP_PROXY,
                                  PROP_RSC,
                                  PROP_L2_MISS,
                                  PROP_L3_MISS, );

typedef struct {
    char   *parent;
    char   *local;
    char   *remote;
    guint32 id;
    guint32 source_port_min;
    guint32 source_port_max;
    guint32 destination_port;
    guint32 tos;
    guint32 ttl;
    guint32 ageing;
    guint32 limit;
    bool    proxy;
    bool    learning;
    bool    rsc;
    bool    l2_miss;
    bool    l3_miss;
} NMSettingVxlanPrivate;

/**
 * NMSettingVxlan:
 *
 * VXLAN Settings
 */
struct _NMSettingVxlan {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingVxlanClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingVxlan, nm_setting_vxlan, NM_TYPE_SETTING)

#define NM_SETTING_VXLAN_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_VXLAN, NMSettingVxlanPrivate))

/*****************************************************************************/

/**
 * nm_setting_vxlan_get_parent:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:parent property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_vxlan_get_parent(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), NULL);

    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->parent;
}

/**
 * nm_setting_vxlan_get_id:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:id property of the setting
 *
 * Since: 1.2
 **/
guint
nm_setting_vxlan_get_id(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), 0);

    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->id;
}

/**
 * nm_setting_vxlan_get_local:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:local property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_vxlan_get_local(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), NULL);

    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->local;
}

/**
 * nm_setting_vxlan_get_remote:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:remote property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_vxlan_get_remote(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), NULL);

    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->remote;
}

/**
 * nm_setting_vxlan_get_source_port_min:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:source-port-min property of the setting
 *
 * Since: 1.2
 **/
guint
nm_setting_vxlan_get_source_port_min(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), 0);

    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->source_port_min;
}

/**
 * nm_setting_vxlan_get_source_port_max:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:source-port-max property of the setting
 *
 * Since: 1.2
 **/
guint
nm_setting_vxlan_get_source_port_max(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), 0);

    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->source_port_max;
}

/**
 * nm_setting_vxlan_get_destination_port:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:destination-port property of the setting
 *
 * Since: 1.2
 **/
guint
nm_setting_vxlan_get_destination_port(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), DST_PORT_DEFAULT);

    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->destination_port;
}

/**
 * nm_setting_vxlan_get_proxy:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:proxy property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_vxlan_get_proxy(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), FALSE);
    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->proxy;
}

/**
 * nm_setting_vxlan_get_ageing:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:ageing property of the setting
 *
 * Since: 1.2
 **/
guint
nm_setting_vxlan_get_ageing(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), 0);

    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->ageing;
}

/**
 * nm_setting_vxlan_get_limit:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:limit property of the setting
 *
 * Since: 1.2
 **/
guint
nm_setting_vxlan_get_limit(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), 0);

    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->limit;
}

/**
 * nm_setting_vxlan_get_tos:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:tos property of the setting
 *
 * Since: 1.2
 **/
guint
nm_setting_vxlan_get_tos(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), 0);

    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->tos;
}

/**
 * nm_setting_vxlan_get_ttl:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:ttl property of the setting
 *
 * Since: 1.2
 **/
guint
nm_setting_vxlan_get_ttl(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), 0);

    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->ttl;
}

/**
 * nm_setting_vxlan_get_learning:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:learning property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_vxlan_get_learning(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), FALSE);
    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->learning;
}

/**
 * nm_setting_vxlan_get_rsc:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:rsc property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_vxlan_get_rsc(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), FALSE);
    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->rsc;
}

/**
 * nm_setting_vxlan_get_l2_miss:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:l2_miss property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_vxlan_get_l2_miss(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), FALSE);
    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->l2_miss;
}

/**
 * nm_setting_vxlan_get_l3_miss:
 * @setting: the #NMSettingVxlan
 *
 * Returns: the #NMSettingVxlan:l3_miss property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_vxlan_get_l3_miss(NMSettingVxlan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_VXLAN(setting), FALSE);
    return NM_SETTING_VXLAN_GET_PRIVATE(setting)->l3_miss;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingVxlanPrivate *priv            = NM_SETTING_VXLAN_GET_PRIVATE(setting);
    int                    addr_family     = AF_UNSPEC;
    gboolean               remote_is_valid = TRUE;
    gboolean               local_is_valid  = TRUE;

    if (priv->remote && !nm_inet_parse_bin(addr_family, priv->remote, &addr_family, NULL))
        remote_is_valid = FALSE;
    if (priv->local && !nm_inet_parse_bin(addr_family, priv->local, &addr_family, NULL))
        local_is_valid = FALSE;

    if (!remote_is_valid) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid IP%s address"),
                    priv->remote,
                    addr_family == AF_UNSPEC ? "" : (addr_family == AF_INET ? "4" : "6"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_VXLAN_SETTING_NAME, NM_SETTING_VXLAN_REMOTE);
        return FALSE;
    }

    if (!local_is_valid) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid IP%s address"),
                    priv->local,
                    addr_family == AF_UNSPEC ? "" : (addr_family == AF_INET ? "4" : "6"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_VXLAN_SETTING_NAME, NM_SETTING_VXLAN_LOCAL);
        return FALSE;
    }

    if (priv->parent && !nm_utils_ifname_valid_kernel(priv->parent, NULL)
        && !nm_utils_is_uuid(priv->parent)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is neither an UUID nor an interface name"),
                    priv->parent);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_VXLAN_SETTING_NAME, NM_SETTING_VXLAN_PARENT);
        return FALSE;
    }

    if ((priv->source_port_min || priv->source_port_max)
        && (priv->source_port_min > priv->source_port_max)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("%d is greater than local port max %d"),
                    priv->source_port_min,
                    priv->source_port_max);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_VXLAN_SETTING_NAME,
                       NM_SETTING_VXLAN_SOURCE_PORT_MIN);
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_vxlan_init(NMSettingVxlan *self)
{}

/**
 * nm_setting_vxlan_new:
 *
 * Creates a new #NMSettingVxlan object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingVxlan object
 *
 * Since: 1.2
 **/
NMSetting *
nm_setting_vxlan_new(void)
{
    return g_object_new(NM_TYPE_SETTING_VXLAN, NULL);
}

static void
nm_setting_vxlan_class_init(NMSettingVxlanClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingVxlanPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingVxlan:parent:
     *
     * If given, specifies the parent interface name or parent connection UUID.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_VXLAN_PARENT,
                                              PROP_PARENT,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingVxlanPrivate,
                                              parent);

    /**
     * NMSettingVxlan:id:
     *
     * Specifies the VXLAN Network Identifier (or VXLAN Segment Identifier) to
     * use.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_VXLAN_ID,
                                              PROP_ID,
                                              0,
                                              (1 << 24) - 1,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingVxlanPrivate,
                                              id);

    /**
     * NMSettingVxlan:local:
     *
     * If given, specifies the source IP address to use in outgoing packets.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_VXLAN_LOCAL,
                                              PROP_LOCAL,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingVxlanPrivate,
                                              local,
                                              .direct_set_string_ip_address_addr_family =
                                                  AF_UNSPEC + 1);

    /**
     * NMSettingVxlan:remote:
     *
     * Specifies the unicast destination IP address to use in outgoing packets
     * when the destination link layer address is not known in the VXLAN device
     * forwarding database, or the multicast IP address to join.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_VXLAN_REMOTE,
                                              PROP_REMOTE,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingVxlanPrivate,
                                              remote,
                                              .direct_set_string_ip_address_addr_family =
                                                  AF_UNSPEC + 1);

    /**
     * NMSettingVxlan:source-port-min:
     *
     * Specifies the minimum UDP source port to communicate to the remote VXLAN
     * tunnel endpoint.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_VXLAN_SOURCE_PORT_MIN,
                                              PROP_SOURCE_PORT_MIN,
                                              0,
                                              G_MAXUINT16,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingVxlanPrivate,
                                              source_port_min);

    /**
     * NMSettingVxlan:source-port-max:
     *
     * Specifies the maximum UDP source port to communicate to the remote VXLAN
     * tunnel endpoint.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_VXLAN_SOURCE_PORT_MAX,
                                              PROP_SOURCE_PORT_MAX,
                                              0,
                                              G_MAXUINT16,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingVxlanPrivate,
                                              source_port_max);

    /**
     * NMSettingVxlan:destination-port:
     *
     * Specifies the UDP destination port to communicate to the remote VXLAN
     * tunnel endpoint.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_VXLAN_DESTINATION_PORT,
                                              PROP_DESTINATION_PORT,
                                              0,
                                              G_MAXUINT16,
                                              DST_PORT_DEFAULT,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingVxlanPrivate,
                                              destination_port);

    /**
     * NMSettingVxlan:ageing:
     *
     * Specifies the lifetime in seconds of FDB entries learnt by the kernel.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_VXLAN_AGEING,
                                              PROP_AGEING,
                                              0,
                                              G_MAXUINT32,
                                              300,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingVxlanPrivate,
                                              ageing);

    /**
     * NMSettingVxlan:limit:
     *
     * Specifies the maximum number of FDB entries. A value of zero means that
     * the kernel will store unlimited entries.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_VXLAN_LIMIT,
                                              PROP_LIMIT,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingVxlanPrivate,
                                              limit);

    /**
     * NMSettingVxlan:tos:
     *
     * Specifies the TOS value to use in outgoing packets.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_VXLAN_TOS,
                                              PROP_TOS,
                                              0,
                                              255,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingVxlanPrivate,
                                              tos);

    /**
     * NMSettingVxlan:ttl:
     *
     * Specifies the time-to-live value to use in outgoing packets.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_VXLAN_TTL,
                                              PROP_TTL,
                                              0,
                                              255,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingVxlanPrivate,
                                              ttl);

    /**
     * NMSettingVxlan:proxy:
     *
     * Specifies whether ARP proxy is turned on.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_VXLAN_PROXY,
                                               PROP_PROXY,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingVxlanPrivate,
                                               proxy);

    /**
     * NMSettingVxlan:learning:
     *
     * Specifies whether unknown source link layer addresses and IP addresses
     * are entered into the VXLAN device forwarding database.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_VXLAN_LEARNING,
                                               PROP_LEARNING,
                                               TRUE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingVxlanPrivate,
                                               learning);

    /**
     * NMSettingVxlan:rsc:
     *
     * Specifies whether route short circuit is turned on.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_VXLAN_RSC,
                                               PROP_RSC,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingVxlanPrivate,
                                               rsc);

    /**
     * NMSettingVxlan:l2-miss:
     *
     * Specifies whether netlink LL ADDR miss notifications are generated.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_VXLAN_L2_MISS,
                                               PROP_L2_MISS,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingVxlanPrivate,
                                               l2_miss);

    /**
     * NMSettingVxlan:l3-miss:
     *
     * Specifies whether netlink IP ADDR miss notifications are generated.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_VXLAN_L3_MISS,
                                               PROP_L3_MISS,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingVxlanPrivate,
                                               l3_miss);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_VXLAN,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
