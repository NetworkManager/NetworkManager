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
    char *parent;
    char *local;
    char *remote;
    guint id;
    guint source_port_min;
    guint source_port_max;
    guint destination_port;
    guint tos;
    guint ttl;
    guint ageing;
    guint limit;
    bool  learning : 1;
    bool  proxy : 1;
    bool  rsc : 1;
    bool  l2_miss : 1;
    bool  l3_miss : 1;
} NMSettingVxlanPrivate;

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

    if (priv->remote && !nm_utils_parse_inaddr_bin(addr_family, priv->remote, &addr_family, NULL))
        remote_is_valid = FALSE;
    if (priv->local && !nm_utils_parse_inaddr_bin(addr_family, priv->local, &addr_family, NULL))
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
_addrstr_set(char **dst, const char *src)
{
    gs_free char *old = NULL;

    old = *dst;
    if (!src)
        *dst = NULL;
    else if (!nm_utils_parse_inaddr(AF_UNSPEC, src, dst))
        *dst = g_strdup(src);
}
/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingVxlan *       setting = NM_SETTING_VXLAN(object);
    NMSettingVxlanPrivate *priv    = NM_SETTING_VXLAN_GET_PRIVATE(setting);

    switch (prop_id) {
    case PROP_PARENT:
        g_value_set_string(value, priv->parent);
        break;
    case PROP_ID:
        g_value_set_uint(value, priv->id);
        break;
    case PROP_LOCAL:
        g_value_set_string(value, priv->local);
        break;
    case PROP_REMOTE:
        g_value_set_string(value, priv->remote);
        break;
    case PROP_SOURCE_PORT_MIN:
        g_value_set_uint(value, priv->source_port_min);
        break;
    case PROP_SOURCE_PORT_MAX:
        g_value_set_uint(value, priv->source_port_max);
        break;
    case PROP_DESTINATION_PORT:
        g_value_set_uint(value, priv->destination_port);
        break;
    case PROP_TOS:
        g_value_set_uint(value, priv->tos);
        break;
    case PROP_AGEING:
        g_value_set_uint(value, priv->ageing);
        break;
    case PROP_LIMIT:
        g_value_set_uint(value, priv->limit);
        break;
    case PROP_PROXY:
        g_value_set_boolean(value, priv->proxy);
        break;
    case PROP_TTL:
        g_value_set_uint(value, priv->ttl);
        break;
    case PROP_LEARNING:
        g_value_set_boolean(value, priv->learning);
        break;
    case PROP_RSC:
        g_value_set_boolean(value, priv->rsc);
        break;
    case PROP_L2_MISS:
        g_value_set_boolean(value, priv->l2_miss);
        break;
    case PROP_L3_MISS:
        g_value_set_boolean(value, priv->l3_miss);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingVxlan *       setting = NM_SETTING_VXLAN(object);
    NMSettingVxlanPrivate *priv    = NM_SETTING_VXLAN_GET_PRIVATE(setting);

    switch (prop_id) {
    case PROP_PARENT:
        g_free(priv->parent);
        priv->parent = g_value_dup_string(value);
        break;
    case PROP_ID:
        priv->id = g_value_get_uint(value);
        break;
    case PROP_LOCAL:
        _addrstr_set(&priv->local, g_value_get_string(value));
        break;
    case PROP_REMOTE:
        _addrstr_set(&priv->remote, g_value_get_string(value));
        break;
    case PROP_SOURCE_PORT_MIN:
        priv->source_port_min = g_value_get_uint(value);
        break;
    case PROP_SOURCE_PORT_MAX:
        priv->source_port_max = g_value_get_uint(value);
        break;
    case PROP_DESTINATION_PORT:
        priv->destination_port = g_value_get_uint(value);
        break;
    case PROP_TOS:
        priv->tos = g_value_get_uint(value);
        break;
    case PROP_AGEING:
        priv->ageing = g_value_get_uint(value);
        break;
    case PROP_LIMIT:
        priv->limit = g_value_get_uint(value);
        break;
    case PROP_PROXY:
        priv->proxy = g_value_get_boolean(value);
        break;
    case PROP_TTL:
        priv->ttl = g_value_get_uint(value);
        break;
    case PROP_LEARNING:
        priv->learning = g_value_get_boolean(value);
        break;
    case PROP_RSC:
        priv->rsc = g_value_get_boolean(value);
        break;
    case PROP_L2_MISS:
        priv->l2_miss = g_value_get_boolean(value);
        break;
    case PROP_L3_MISS:
        priv->l3_miss = g_value_get_boolean(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_setting_vxlan_init(NMSettingVxlan *self)
{
    NMSettingVxlanPrivate *priv = NM_SETTING_VXLAN_GET_PRIVATE(self);

    priv->destination_port = DST_PORT_DEFAULT;
    priv->ageing           = 300;
    priv->learning         = TRUE;
}

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
finalize(GObject *object)
{
    NMSettingVxlan *       setting = NM_SETTING_VXLAN(object);
    NMSettingVxlanPrivate *priv    = NM_SETTING_VXLAN_GET_PRIVATE(setting);

    g_free(priv->parent);
    g_free(priv->local);
    g_free(priv->remote);

    G_OBJECT_CLASS(nm_setting_vxlan_parent_class)->finalize(object);
}

static void
nm_setting_vxlan_class_init(NMSettingVxlanClass *klass)
{
    GObjectClass *  object_class  = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class = NM_SETTING_CLASS(klass);

    g_type_class_add_private(klass, sizeof(NMSettingVxlanPrivate));

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    setting_class->verify = verify;

    /**
     * NMSettingVxlan:parent:
     *
     * If given, specifies the parent interface name or parent connection UUID.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_PARENT] = g_param_spec_string(
        NM_SETTING_VXLAN_PARENT,
        "",
        "",
        NULL,
        G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);
    /**
     * NMSettingVxlan:id:
     *
     * Specifies the VXLAN Network Identifier (or VXLAN Segment Identifier) to
     * use.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_ID] =
        g_param_spec_uint(NM_SETTING_VXLAN_ID,
                          "",
                          "",
                          0,
                          (1 << 24) - 1,
                          0,
                          G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingVxlan:local:
     *
     * If given, specifies the source IP address to use in outgoing packets.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_LOCAL] = g_param_spec_string(NM_SETTING_VXLAN_LOCAL,
                                                     "",
                                                     "",
                                                     NULL,
                                                     G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE
                                                         | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingVxlan:remote:
     *
     * Specifies the unicast destination IP address to use in outgoing packets
     * when the destination link layer address is not known in the VXLAN device
     * forwarding database, or the multicast IP address to join.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_REMOTE] = g_param_spec_string(
        NM_SETTING_VXLAN_REMOTE,
        "",
        "",
        NULL,
        G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingVxlan:source-port-min:
     *
     * Specifies the minimum UDP source port to communicate to the remote VXLAN
     * tunnel endpoint.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_SOURCE_PORT_MIN] =
        g_param_spec_uint(NM_SETTING_VXLAN_SOURCE_PORT_MIN,
                          "",
                          "",
                          0,
                          G_MAXUINT16,
                          0,
                          G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingVxlan:source-port-max:
     *
     * Specifies the maximum UDP source port to communicate to the remote VXLAN
     * tunnel endpoint.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_SOURCE_PORT_MAX] =
        g_param_spec_uint(NM_SETTING_VXLAN_SOURCE_PORT_MAX,
                          "",
                          "",
                          0,
                          G_MAXUINT16,
                          0,
                          G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingVxlan:destination-port:
     *
     * Specifies the UDP destination port to communicate to the remote VXLAN
     * tunnel endpoint.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_DESTINATION_PORT] =
        g_param_spec_uint(NM_SETTING_VXLAN_DESTINATION_PORT,
                          "",
                          "",
                          0,
                          G_MAXUINT16,
                          DST_PORT_DEFAULT,
                          G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingVxlan:ageing:
     *
     * Specifies the lifetime in seconds of FDB entries learnt by the kernel.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_AGEING] =
        g_param_spec_uint(NM_SETTING_VXLAN_AGEING,
                          "",
                          "",
                          0,
                          G_MAXUINT32,
                          300,
                          G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingVxlan:limit:
     *
     * Specifies the maximum number of FDB entries. A value of zero means that
     * the kernel will store unlimited entries.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_LIMIT] =
        g_param_spec_uint(NM_SETTING_VXLAN_LIMIT,
                          "",
                          "",
                          0,
                          G_MAXUINT32,
                          0,
                          G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingVxlan:tos:
     *
     * Specifies the TOS value to use in outgoing packets.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_TOS] =
        g_param_spec_uint(NM_SETTING_VXLAN_TOS,
                          "",
                          "",
                          0,
                          255,
                          0,
                          G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingVxlan:ttl:
     *
     * Specifies the time-to-live value to use in outgoing packets.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_TTL] =
        g_param_spec_uint(NM_SETTING_VXLAN_TTL,
                          "",
                          "",
                          0,
                          255,
                          0,
                          G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingVxlan:proxy:
     *
     * Specifies whether ARP proxy is turned on.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_PROXY] = g_param_spec_boolean(
        NM_SETTING_VXLAN_PROXY,
        "",
        "",
        FALSE,
        G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingVxlan:learning:
     *
     * Specifies whether unknown source link layer addresses and IP addresses
     * are entered into the VXLAN device forwarding database.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_LEARNING] = g_param_spec_boolean(
        NM_SETTING_VXLAN_LEARNING,
        "",
        "",
        TRUE,
        G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);
    /**
     * NMSettingVxlan:rsc:
     *
     * Specifies whether route short circuit is turned on.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_RSC] = g_param_spec_boolean(NM_SETTING_VXLAN_RSC,
                                                    "",
                                                    "",
                                                    FALSE,
                                                    G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE
                                                        | G_PARAM_STATIC_STRINGS);
    /**
     * NMSettingVxlan:l2-miss:
     *
     * Specifies whether netlink LL ADDR miss notifications are generated.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_L2_MISS] = g_param_spec_boolean(
        NM_SETTING_VXLAN_L2_MISS,
        "",
        "",
        FALSE,
        G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingVxlan:l3-miss:
     *
     * Specifies whether netlink IP ADDR miss notifications are generated.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_L3_MISS] = g_param_spec_boolean(
        NM_SETTING_VXLAN_L3_MISS,
        "",
        "",
        FALSE,
        G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class, NM_META_SETTING_TYPE_VXLAN);
}
