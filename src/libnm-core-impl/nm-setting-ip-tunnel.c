/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-ip-tunnel.h"

#include "nm-setting-private.h"
#include "nm-utils.h"

/**
 * SECTION:nm-setting-ip-tunnel
 * @short_description: Describes connection properties for IP tunnel devices
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PARENT,
                                  PROP_MODE,
                                  PROP_LOCAL,
                                  PROP_REMOTE,
                                  PROP_TTL,
                                  PROP_TOS,
                                  PROP_PATH_MTU_DISCOVERY,
                                  PROP_INPUT_KEY,
                                  PROP_OUTPUT_KEY,
                                  PROP_ENCAPSULATION_LIMIT,
                                  PROP_FLOW_LABEL,
                                  PROP_FWMARK,
                                  PROP_MTU,
                                  PROP_FLAGS, );

typedef struct {
    char   *parent;
    char   *local;
    char   *remote;
    char   *input_key;
    char   *output_key;
    guint32 ttl;
    guint32 tos;
    guint32 encapsulation_limit;
    guint32 flow_label;
    guint32 fwmark;
    guint32 mode;
    guint32 mtu;
    guint32 flags;
    bool    path_mtu_discovery;
} NMSettingIPTunnelPrivate;

/**
 * NMSettingIPTunnel:
 *
 * IP Tunneling Settings
 */
struct _NMSettingIPTunnel {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingIPTunnelClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingIPTunnel, nm_setting_ip_tunnel, NM_TYPE_SETTING)

#define NM_SETTING_IP_TUNNEL_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_IP_TUNNEL, NMSettingIPTunnelPrivate))

/*****************************************************************************/

/**
 * nm_setting_ip_tunnel_get_parent:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:parent property of the setting
 *
 * Returns: the parent device
 *
 * Since: 1.2
 **/
const char *
nm_setting_ip_tunnel_get_parent(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), NULL);
    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->parent;
}

/**
 * nm_setting_ip_tunnel_get_mode:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:mode property of the setting.
 *
 * Returns: the tunnel mode
 *
 * Since: 1.2
 **/
NMIPTunnelMode
nm_setting_ip_tunnel_get_mode(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), 0);

    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->mode;
}

/**
 * nm_setting_ip_tunnel_get_local:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:local property of the setting.
 *
 * Returns: the local endpoint
 *
 * Since: 1.2
 **/
const char *
nm_setting_ip_tunnel_get_local(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), NULL);

    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->local;
}

/**
 * nm_setting_ip_tunnel_get_remote:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:remote property of the setting.
 *
 * Returns: the remote endpoint
 *
 * Since: 1.2
 **/
const char *
nm_setting_ip_tunnel_get_remote(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), NULL);

    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->remote;
}

/**
 * nm_setting_ip_tunnel_get_ttl:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:ttl property of the setting.
 *
 * Returns: the Time-to-live value
 *
 * Since: 1.2
 **/

guint
nm_setting_ip_tunnel_get_ttl(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), 0);

    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->ttl;
}

/**
 * nm_setting_ip_tunnel_get_tos:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:tos property of the setting.
 *
 * Returns: the TOS value
 *
 * Since: 1.2
 **/
guint
nm_setting_ip_tunnel_get_tos(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), 0);

    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->tos;
}

/**
 * nm_setting_ip_tunnel_get_path_mtu_discovery:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:path-mtu-discovery property of the setting.
 *
 * Returns: whether path MTU discovery is enabled
 *
 * Since: 1.2
 **/
gboolean
nm_setting_ip_tunnel_get_path_mtu_discovery(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), TRUE);

    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->path_mtu_discovery;
}

/**
 * nm_setting_ip_tunnel_get_input_key:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:input-key property of the setting.
 *
 * Returns: the input key
 *
 * Since: 1.2
 **/
const char *
nm_setting_ip_tunnel_get_input_key(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), NULL);

    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->input_key;
}

/**
 * nm_setting_ip_tunnel_get_output_key:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:output-key property of the setting.
 *
 * Returns: the output key
 *
 * Since: 1.2
 **/
const char *
nm_setting_ip_tunnel_get_output_key(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), NULL);

    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->output_key;
}

/**
 * nm_setting_ip_tunnel_get_encapsulation_limit:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:encapsulation-limit property of the setting.
 *
 * Returns: the encapsulation limit value
 *
 * Since: 1.42
 **/
guint
nm_setting_ip_tunnel_get_encapsulation_limit(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), 0);

    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->encapsulation_limit;
}

/**
 * nm_setting_ip_tunnel_get_flow_label:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:flow-label property of the setting.
 *
 * Returns: the flow label value
 *
 * Since: 1.42
 **/
guint
nm_setting_ip_tunnel_get_flow_label(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), 0);

    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->flow_label;
}

/**
 * nm_setting_ip_tunnel_get_fwmark:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:fwmark property of the setting.
 *
 * Returns: the fwmark value
 *
 * Since: 1.42
 **/
guint32
nm_setting_ip_tunnel_get_fwmark(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), 0);

    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->fwmark;
}

/**
 * nm_setting_ip_tunnel_get_mtu:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:mtu property of the setting.
 *
 * Returns: the MTU
 *
 * Since: 1.2
 **/
guint
nm_setting_ip_tunnel_get_mtu(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), 0);

    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->mtu;
}

/**
 * nm_setting_ip_tunnel_get_flags:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:flags property of the setting.
 *
 * Returns: the tunnel flags
 *
 * Since: 1.12
 **/
NMIPTunnelFlags
nm_setting_ip_tunnel_get_flags(NMSettingIPTunnel *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_IP_TUNNEL(setting), NM_IP_TUNNEL_FLAG_NONE);

    return NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting)->flags;
}

/*****************************************************************************/

gboolean
_nm_ip_tunnel_mode_is_layer2(NMIPTunnelMode mode)
{
    return NM_IN_SET(mode, NM_IP_TUNNEL_MODE_GRETAP, NM_IP_TUNNEL_MODE_IP6GRETAP);
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingIPTunnelPrivate *priv   = NM_SETTING_IP_TUNNEL_GET_PRIVATE(setting);
    int                       family = AF_UNSPEC;
    guint32                   flags;

    switch (priv->mode) {
    case NM_IP_TUNNEL_MODE_IPIP:
    case NM_IP_TUNNEL_MODE_SIT:
    case NM_IP_TUNNEL_MODE_ISATAP:
    case NM_IP_TUNNEL_MODE_GRE:
    case NM_IP_TUNNEL_MODE_VTI:
    case NM_IP_TUNNEL_MODE_GRETAP:
        family = AF_INET;
        break;
    case NM_IP_TUNNEL_MODE_IP6IP6:
    case NM_IP_TUNNEL_MODE_IPIP6:
    case NM_IP_TUNNEL_MODE_IP6GRE:
    case NM_IP_TUNNEL_MODE_VTI6:
    case NM_IP_TUNNEL_MODE_IP6GRETAP:
        family = AF_INET6;
        break;
    case NM_IP_TUNNEL_MODE_UNKNOWN:
        break;
    }

    if (family == AF_UNSPEC) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%d' is not a valid tunnel mode"),
                    (int) priv->mode);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP_TUNNEL_SETTING_NAME,
                       NM_SETTING_IP_TUNNEL_MODE);
        return FALSE;
    }

    if (priv->parent && !nm_utils_ifname_valid_kernel(priv->parent, NULL)
        && !nm_utils_is_uuid(priv->parent)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is neither an UUID nor an interface name"),
                    priv->parent);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP_TUNNEL_SETTING_NAME,
                       NM_SETTING_IP_TUNNEL_PARENT);
        return FALSE;
    }

    if (priv->local && !nm_inet_is_valid(family, priv->local)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid IPv%c address"),
                    priv->local,
                    family == AF_INET ? '4' : '6');
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP_TUNNEL_SETTING_NAME,
                       NM_SETTING_IP_TUNNEL_LOCAL);
        return FALSE;
    }

    if (!priv->remote) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is missing"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP_TUNNEL_SETTING_NAME,
                       NM_SETTING_IP_TUNNEL_REMOTE);
        return FALSE;
    }

    if (!nm_inet_is_valid(family, priv->remote)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid IPv%c address"),
                    priv->remote,
                    family == AF_INET ? '4' : '6');
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP_TUNNEL_SETTING_NAME,
                       NM_SETTING_IP_TUNNEL_REMOTE);
        return FALSE;
    }

    if ((priv->input_key && priv->input_key[0]) || (priv->output_key && priv->output_key[0])) {
        if (!NM_IN_SET(priv->mode,
                       NM_IP_TUNNEL_MODE_GRE,
                       NM_IP_TUNNEL_MODE_GRETAP,
                       NM_IP_TUNNEL_MODE_IP6GRE,
                       NM_IP_TUNNEL_MODE_IP6GRETAP,
                       NM_IP_TUNNEL_MODE_VTI,
                       NM_IP_TUNNEL_MODE_VTI6)) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("tunnel keys can only be specified for GRE and VTI tunnels"));
            return FALSE;
        }
    }

    if (priv->input_key && priv->input_key[0]) {
        gint64 val;

        val = _nm_utils_ascii_str_to_int64(priv->input_key, 10, 0, G_MAXUINT32, -1);
        if (val == -1) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' is not a valid tunnel key"),
                        priv->input_key);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_IP_TUNNEL_SETTING_NAME,
                           NM_SETTING_IP_TUNNEL_INPUT_KEY);
            return FALSE;
        }
    }

    if (priv->output_key && priv->output_key[0]) {
        gint64 val;

        val = _nm_utils_ascii_str_to_int64(priv->output_key, 10, 0, G_MAXUINT32, -1);
        if (val == -1) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' is not a valid tunnel key"),
                        priv->output_key);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_IP_TUNNEL_SETTING_NAME,
                           NM_SETTING_IP_TUNNEL_OUTPUT_KEY);
            return FALSE;
        }
    }

    if (!priv->path_mtu_discovery && priv->ttl != 0) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("a fixed TTL is allowed only when path MTU discovery is enabled"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP_TUNNEL_SETTING_NAME,
                       NM_SETTING_IP_TUNNEL_TTL);
        return FALSE;
    }

    flags = priv->flags;
    if (NM_IN_SET(priv->mode, NM_IP_TUNNEL_MODE_IPIP6, NM_IP_TUNNEL_MODE_IP6IP6))
        flags &= (guint32) (~_NM_IP_TUNNEL_FLAG_ALL_IP6TNL);
    if (flags) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("some flags are invalid for the select mode: %s"),
                    nm_utils_enum_to_str(nm_ip_tunnel_flags_get_type(), flags));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP_TUNNEL_SETTING_NAME,
                       NM_SETTING_IP_TUNNEL_FLAGS);
        return FALSE;
    }

    if (priv->fwmark && !NM_IN_SET(priv->mode, NM_IP_TUNNEL_MODE_VTI, NM_IP_TUNNEL_MODE_VTI6)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("can be set only on VTI tunnels"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP_TUNNEL_SETTING_NAME,
                       NM_SETTING_IP_TUNNEL_FWMARK);
        return FALSE;
    }

    if (nm_connection_get_setting_wired(connection) && !_nm_ip_tunnel_mode_is_layer2(priv->mode)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("wired setting not allowed for mode %s"),
                    nm_utils_enum_to_str(nm_ip_tunnel_mode_get_type(), priv->mode));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP_TUNNEL_SETTING_NAME,
                       NM_SETTING_IP_TUNNEL_MODE);
        return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_ip_tunnel_init(NMSettingIPTunnel *self)
{}

/**
 * nm_setting_ip_tunnel_new:
 *
 * Creates a new #NMSettingIPTunnel object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingIPTunnel object
 *
 * Since: 1.2
 **/
NMSetting *
nm_setting_ip_tunnel_new(void)
{
    return g_object_new(NM_TYPE_SETTING_IP_TUNNEL, NULL);
}

static void
nm_setting_ip_tunnel_class_init(NMSettingIPTunnelClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingIPTunnelPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingIPTunnel:parent:
     *
     * If given, specifies the parent interface name or parent connection UUID
     * the new device will be bound to so that tunneled packets will only be
     * routed via that interface.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP_TUNNEL_PARENT,
                                              PROP_PARENT,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIPTunnelPrivate,
                                              parent);

    /**
     * NMSettingIPTunnel:mode:
     *
     * The tunneling mode, for example %NM_IP_TUNNEL_MODE_IPIP or
     * %NM_IP_TUNNEL_MODE_GRE.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP_TUNNEL_MODE,
                                              PROP_MODE,
                                              0,
                                              G_MAXUINT32,
                                              NM_IP_TUNNEL_MODE_UNKNOWN,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIPTunnelPrivate,
                                              mode);

    /**
     * NMSettingIPTunnel:local:
     *
     * The local endpoint of the tunnel; the value can be empty, otherwise it
     * must contain an IPv4 or IPv6 address.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP_TUNNEL_LOCAL,
                                              PROP_LOCAL,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIPTunnelPrivate,
                                              local);

    /**
     * NMSettingIPTunnel:remote:
     *
     * The remote endpoint of the tunnel; the value must contain an IPv4 or IPv6
     * address.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP_TUNNEL_REMOTE,
                                              PROP_REMOTE,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIPTunnelPrivate,
                                              remote);

    /**
     * NMSettingIPTunnel:ttl
     *
     * The TTL to assign to tunneled packets. 0 is a special value meaning that
     * packets inherit the TTL value.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP_TUNNEL_TTL,
                                              PROP_TTL,
                                              0,
                                              255,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIPTunnelPrivate,
                                              ttl);

    /**
     * NMSettingIPTunnel:tos
     *
     * The type of service (IPv4) or traffic class (IPv6) field to be set on
     * tunneled packets.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP_TUNNEL_TOS,
                                              PROP_TOS,
                                              0,
                                              255,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIPTunnelPrivate,
                                              tos);

    /**
     * NMSettingIPTunnel:path-mtu-discovery
     *
     * Whether to enable Path MTU Discovery on this tunnel.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_IP_TUNNEL_PATH_MTU_DISCOVERY,
                                               PROP_PATH_MTU_DISCOVERY,
                                               TRUE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingIPTunnelPrivate,
                                               path_mtu_discovery);

    /**
     * NMSettingIPTunnel:input-key:
     *
     * The key used for tunnel input packets; the property is valid only for
     * certain tunnel modes (GRE, IP6GRE). If empty, no key is used.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP_TUNNEL_INPUT_KEY,
                                              PROP_INPUT_KEY,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIPTunnelPrivate,
                                              input_key);

    /**
     * NMSettingIPTunnel:output-key:
     *
     * The key used for tunnel output packets; the property is valid only for
     * certain tunnel modes (GRE, IP6GRE). If empty, no key is used.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP_TUNNEL_OUTPUT_KEY,
                                              PROP_OUTPUT_KEY,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIPTunnelPrivate,
                                              output_key);

    /**
     * NMSettingIPTunnel:encapsulation-limit:
     *
     * How many additional levels of encapsulation are permitted to be prepended
     * to packets. This property applies only to IPv6 tunnels.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP_TUNNEL_ENCAPSULATION_LIMIT,
                                              PROP_ENCAPSULATION_LIMIT,
                                              0,
                                              255,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIPTunnelPrivate,
                                              encapsulation_limit);

    /**
     * NMSettingIPTunnel:flow-label:
     *
     * The flow label to assign to tunnel packets. This property applies only to
     * IPv6 tunnels.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP_TUNNEL_FLOW_LABEL,
                                              PROP_FLOW_LABEL,
                                              0,
                                              (1 << 20) - 1,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIPTunnelPrivate,
                                              flow_label);

    /**
     * NMSettingIPTunnel:fwmark:
     *
     * The fwmark value to assign to tunnel packets. This property can be set
     * to a non zero value only on VTI and VTI6 tunnels.
     *
     * Since: 1.42
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP_TUNNEL_FWMARK,
                                              PROP_FWMARK,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingIPTunnelPrivate,
                                              fwmark);

    /**
     * NMSettingIPTunnel:mtu:
     *
     * If non-zero, only transmit packets of the specified size or smaller,
     * breaking larger packets up into multiple fragments.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP_TUNNEL_MTU,
                                              PROP_MTU,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingIPTunnelPrivate,
                                              mtu);

    /**
     * NMSettingIPTunnel:flags:
     *
     * Tunnel flags. Currently, the following values are supported:
     * %NM_IP_TUNNEL_FLAG_IP6_IGN_ENCAP_LIMIT, %NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_TCLASS,
     * %NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_FLOWLABEL, %NM_IP_TUNNEL_FLAG_IP6_MIP6_DEV,
     * %NM_IP_TUNNEL_FLAG_IP6_RCV_DSCP_COPY, %NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_FWMARK.
     * They are valid only for IPv6 tunnels.
     *
     * Since: 1.12
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_IP_TUNNEL_FLAGS,
                                              PROP_FLAGS,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingIPTunnelPrivate,
                                              flags);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_IP_TUNNEL,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
