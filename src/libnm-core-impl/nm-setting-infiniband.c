/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 - 2013 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-infiniband.h"

#include <stdlib.h>
#include <linux/if_infiniband.h>

#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"
#include "nm-setting-connection.h"

/**
 * SECTION:nm-setting-infiniband
 * @short_description: Describes connection properties for IP-over-InfiniBand networks
 *
 * The #NMSettingInfiniband object is a #NMSetting subclass that describes properties
 * necessary for connection to IP-over-InfiniBand networks.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_MAC_ADDRESS,
                                  PROP_MTU,
                                  PROP_TRANSPORT_MODE,
                                  PROP_P_KEY,
                                  PROP_PARENT, );

typedef struct {
    char *  mac_address;
    char *  transport_mode;
    char *  parent;
    char *  virtual_iface_name;
    int     p_key;
    guint32 mtu;
} NMSettingInfinibandPrivate;

/**
 * NMSettingInfiniband:
 *
 * Infiniband Settings
 */
struct _NMSettingInfiniband {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingInfinibandClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingInfiniband, nm_setting_infiniband, NM_TYPE_SETTING)

#define NM_SETTING_INFINIBAND_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_INFINIBAND, NMSettingInfinibandPrivate))

/*****************************************************************************/

/**
 * nm_setting_infiniband_get_mac_address:
 * @setting: the #NMSettingInfiniband
 *
 * Returns: the #NMSettingInfiniband:mac-address property of the setting
 **/
const char *
nm_setting_infiniband_get_mac_address(NMSettingInfiniband *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_INFINIBAND(setting), NULL);

    return NM_SETTING_INFINIBAND_GET_PRIVATE(setting)->mac_address;
}

/**
 * nm_setting_infiniband_get_mtu:
 * @setting: the #NMSettingInfiniband
 *
 * Returns: the #NMSettingInfiniband:mtu property of the setting
 **/
guint32
nm_setting_infiniband_get_mtu(NMSettingInfiniband *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_INFINIBAND(setting), 0);

    return NM_SETTING_INFINIBAND_GET_PRIVATE(setting)->mtu;
}

/**
 * nm_setting_infiniband_get_transport_mode:
 * @setting: the #NMSettingInfiniband
 *
 * Returns the transport mode for this device. Either 'datagram' or
 * 'connected'.
 *
 * Returns: the IPoIB transport mode
 **/
const char *
nm_setting_infiniband_get_transport_mode(NMSettingInfiniband *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_INFINIBAND(setting), NULL);

    return NM_SETTING_INFINIBAND_GET_PRIVATE(setting)->transport_mode;
}

/**
 * nm_setting_infiniband_get_p_key:
 * @setting: the #NMSettingInfiniband
 *
 * Returns the P_Key to use for this device. A value of -1 means to
 * use the default P_Key (aka "the P_Key at index 0"). Otherwise, it is
 * a 16-bit unsigned integer.
 *
 * Returns: the IPoIB P_Key
 **/
int
nm_setting_infiniband_get_p_key(NMSettingInfiniband *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_INFINIBAND(setting), -1);

    return NM_SETTING_INFINIBAND_GET_PRIVATE(setting)->p_key;
}

/**
 * nm_setting_infiniband_get_parent:
 * @setting: the #NMSettingInfiniband
 *
 * Returns the parent interface name for this device, if set.
 *
 * Returns: the parent interface name
 **/
const char *
nm_setting_infiniband_get_parent(NMSettingInfiniband *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_INFINIBAND(setting), NULL);

    return NM_SETTING_INFINIBAND_GET_PRIVATE(setting)->parent;
}

/**
 * nm_setting_infiniband_get_virtual_interface_name:
 * @setting: the #NMSettingInfiniband
 *
 * Returns the interface name created by combining #NMSettingInfiniband:parent
 * and #NMSettingInfiniband:p-key. (If either property is unset, this will
 * return %NULL.)
 *
 * Returns: the interface name, or %NULL
 **/
const char *
nm_setting_infiniband_get_virtual_interface_name(NMSettingInfiniband *setting)
{
    NMSettingInfinibandPrivate *priv = NM_SETTING_INFINIBAND_GET_PRIVATE(setting);

    if (priv->p_key == -1 || !priv->parent)
        return NULL;

    if (!priv->virtual_iface_name)
        priv->virtual_iface_name = g_strdup_printf("%s.%04x", priv->parent, priv->p_key);

    return NM_SETTING_INFINIBAND_GET_PRIVATE(setting)->virtual_iface_name;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingConnection *       s_con = NULL;
    NMSettingInfinibandPrivate *priv  = NM_SETTING_INFINIBAND_GET_PRIVATE(setting);

    if (priv->mac_address && !nm_utils_hwaddr_valid(priv->mac_address, INFINIBAND_ALEN)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is invalid"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_INFINIBAND_SETTING_NAME,
                       NM_SETTING_INFINIBAND_MAC_ADDRESS);
        return FALSE;
    }

    if (!NM_IN_STRSET(priv->transport_mode, "datagram", "connected")) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is invalid"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_INFINIBAND_SETTING_NAME,
                       NM_SETTING_INFINIBAND_TRANSPORT_MODE);
        return FALSE;
    }

    if (priv->parent) {
        GError *tmp_error = NULL;

        if (!nm_utils_ifname_valid_kernel(priv->parent, &tmp_error)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        "'%s': %s",
                        priv->parent,
                        tmp_error->message);
            g_prefix_error(error, "%s: ", NM_SETTING_INFINIBAND_PARENT);
            g_error_free(tmp_error);
            return FALSE;
        }
        if (priv->p_key == -1) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("Must specify a P_Key if specifying parent"));
            g_prefix_error(error, "%s: ", NM_SETTING_INFINIBAND_PARENT);
        }
    }

    if (priv->p_key != -1) {
        if (!priv->mac_address && !priv->parent) {
            g_set_error_literal(
                error,
                NM_CONNECTION_ERROR,
                NM_CONNECTION_ERROR_MISSING_PROPERTY,
                _("InfiniBand P_Key connection did not specify parent interface name"));
            g_prefix_error(error, "%s: ", NM_SETTING_INFINIBAND_PARENT);
            return FALSE;
        }
    }

    if (connection)
        s_con = nm_connection_get_setting_connection(connection);
    if (s_con) {
        const char *interface_name = nm_setting_connection_get_interface_name(s_con);

        if (interface_name && priv->p_key != -1) {
            if (!priv->virtual_iface_name)
                priv->virtual_iface_name = g_strdup_printf("%s.%04x", priv->parent, priv->p_key);

            if (strcmp(interface_name, priv->virtual_iface_name) != 0) {
                /* We don't support renaming software infiniband devices. Later we might, but
                 * for now just reject such connections.
                 **/
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("interface name of software infiniband device must be '%s' or unset "
                              "(instead it is '%s')"),
                            priv->virtual_iface_name,
                            interface_name);
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_CONNECTION_SETTING_NAME,
                               NM_SETTING_CONNECTION_INTERFACE_NAME);
                return FALSE;
            }
        }
    }

    /* *** errors above here should be always fatal, below NORMALIZABLE_ERROR *** */

    if (priv->mtu > NM_INFINIBAND_MAX_MTU) {
        /* Traditionally, MTU for "datagram" mode was limited to 2044
         * and for "connected" mode it was 65520.
         *
         * This is no longer the case, and both transport modes use the same
         * maximum of 65520 (NM_INFINIBAND_MAX_MTU).
         *
         * Note that this is the MTU in the connection profile. Whether
         * we will be able to configure large MTUs later (during activation)
         * is unknown at this point. */
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("mtu can be at most %u but it is %u"),
                    NM_INFINIBAND_MAX_MTU,
                    priv->mtu);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_INFINIBAND_SETTING_NAME,
                       NM_SETTING_INFINIBAND_MTU);
        return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
    }

    return TRUE;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingInfiniband *setting = NM_SETTING_INFINIBAND(object);

    switch (prop_id) {
    case PROP_MAC_ADDRESS:
        g_value_set_string(value, nm_setting_infiniband_get_mac_address(setting));
        break;
    case PROP_MTU:
        g_value_set_uint(value, nm_setting_infiniband_get_mtu(setting));
        break;
    case PROP_TRANSPORT_MODE:
        g_value_set_string(value, nm_setting_infiniband_get_transport_mode(setting));
        break;
    case PROP_P_KEY:
        g_value_set_int(value, nm_setting_infiniband_get_p_key(setting));
        break;
    case PROP_PARENT:
        g_value_set_string(value, nm_setting_infiniband_get_parent(setting));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingInfinibandPrivate *priv = NM_SETTING_INFINIBAND_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_MAC_ADDRESS:
        g_free(priv->mac_address);
        priv->mac_address =
            _nm_utils_hwaddr_canonical_or_invalid(g_value_get_string(value), INFINIBAND_ALEN);
        break;
    case PROP_MTU:
        priv->mtu = g_value_get_uint(value);
        break;
    case PROP_TRANSPORT_MODE:
        g_free(priv->transport_mode);
        priv->transport_mode = g_value_dup_string(value);
        break;
    case PROP_P_KEY:
        priv->p_key = g_value_get_int(value);
        nm_clear_g_free(&priv->virtual_iface_name);
        break;
    case PROP_PARENT:
        g_free(priv->parent);
        priv->parent = g_value_dup_string(value);
        nm_clear_g_free(&priv->virtual_iface_name);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_setting_infiniband_init(NMSettingInfiniband *self)
{
    NMSettingInfinibandPrivate *priv = NM_SETTING_INFINIBAND_GET_PRIVATE(self);

    priv->p_key = -1;
}

/**
 * nm_setting_infiniband_new:
 *
 * Creates a new #NMSettingInfiniband object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingInfiniband object
 **/
NMSetting *
nm_setting_infiniband_new(void)
{
    return g_object_new(NM_TYPE_SETTING_INFINIBAND, NULL);
}

static void
finalize(GObject *object)
{
    NMSettingInfinibandPrivate *priv = NM_SETTING_INFINIBAND_GET_PRIVATE(object);

    g_free(priv->transport_mode);
    g_free(priv->mac_address);
    g_free(priv->parent);
    g_free(priv->virtual_iface_name);

    G_OBJECT_CLASS(nm_setting_infiniband_parent_class)->finalize(object);
}

static void
nm_setting_infiniband_class_init(NMSettingInfinibandClass *klass)
{
    GObjectClass *  object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray *        properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingInfinibandPrivate));

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    setting_class->verify = verify;

    /**
     * NMSettingInfiniband:mac-address:
     *
     * If specified, this connection will only apply to the IPoIB device whose
     * permanent MAC address matches. This property does not change the MAC
     * address of the device (i.e. MAC spoofing).
     **/
    /* ---keyfile---
     * property: mac-address
     * format: usual hex-digits-and-colons notation
     * description: MAC address in traditional hex-digits-and-colons notation, or
     *   or semicolon separated list of 20 decimal bytes (obsolete)
     * example: mac-address= 80:00:00:6d:fe:80:00:00:00:00:00:00:00:02:55:00:70:33:cf:01
     * ---end---
     * ---ifcfg-rh---
     * property: mac-address
     * variable: HWADDR
     * description: IBoIP 20-byte hardware address of the device (in traditional
     *    hex-digits-and-colons notation).
     *    Note that for initscripts this is the current MAC address of the device as found
     *    during ifup. For NetworkManager this is the permanent MAC address. Or in case no
     *    permanent MAC address exists, the MAC address initially configured on the device.
     * example: HWADDR=01:02:03:04:05:06:07:08:09:0A:01:02:03:04:05:06:07:08:09:11
     * ---end---
     */
    _nm_setting_property_define_direct_mac_address(properties_override,
                                                   obj_properties,
                                                   NM_SETTING_INFINIBAND_MAC_ADDRESS,
                                                   PROP_MAC_ADDRESS,
                                                   NM_SETTING_PARAM_INFERRABLE,
                                                   NMSettingInfinibandPrivate,
                                                   mac_address,
                                                   .direct_set_string_mac_address_len =
                                                       INFINIBAND_ALEN);

    /**
     * NMSettingInfiniband:mtu:
     *
     * If non-zero, only transmit packets of the specified size or smaller,
     * breaking larger packets up into multiple frames.
     **/
    /* ---ifcfg-rh---
     * property: mtu
     * variable: MTU
     * description: MTU of the interface.
     * ---end---
     */
    obj_properties[PROP_MTU] = g_param_spec_uint(NM_SETTING_INFINIBAND_MTU,
                                                 "",
                                                 "",
                                                 0,
                                                 G_MAXUINT32,
                                                 0,
                                                 G_PARAM_READWRITE | NM_SETTING_PARAM_FUZZY_IGNORE
                                                     | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingInfiniband:transport-mode:
     *
     * The IP-over-InfiniBand transport mode. Either "datagram" or
     * "connected".
     **/
    /* ---ifcfg-rh---
     * property: transport-mode
     * variable: CONNECTED_MODE
     * default: CONNECTED_MODE=no
     * description: CONNECTED_MODE=yes for "connected" mode, CONNECTED_MODE=no for
     *   "datagram" mode
     * ---end---
     */
    obj_properties[PROP_TRANSPORT_MODE] = g_param_spec_string(
        NM_SETTING_INFINIBAND_TRANSPORT_MODE,
        "",
        "",
        NULL,
        G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingInfiniband:p-key:
     *
     * The InfiniBand P_Key to use for this device. A value of -1 means to use
     * the default P_Key (aka "the P_Key at index 0"). Otherwise, it is a 16-bit
     * unsigned integer, whose high bit is set if it is a "full membership"
     * P_Key.
     **/
    /* ---ifcfg-rh---
     * property: p-key
     * variable: PKEY_ID (and PKEY=yes)
     * default: PKEY=no
     * description: InfiniBand P_Key. The value can be a hex number prefixed with "0x"
     *   or a decimal number.
     *   When PKEY_ID is specified, PHYSDEV and DEVICE also must be specified.
     * example: PKEY=yes PKEY_ID=2 PHYSDEV=mlx4_ib0 DEVICE=mlx4_ib0.8002
     * ---end---
     */
    obj_properties[PROP_P_KEY] =
        g_param_spec_int(NM_SETTING_INFINIBAND_P_KEY,
                         "",
                         "",
                         -1,
                         0xFFFF,
                         -1,
                         G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingInfiniband:parent:
     *
     * The interface name of the parent device of this device. Normally %NULL,
     * but if the #NMSettingInfiniband:p_key property is set, then you must
     * specify the base device by setting either this property or
     * #NMSettingInfiniband:mac-address.
     **/
    /* ---ifcfg-rh---
     * property: parent
     * variable: PHYSDEV (PKEY=yes)
     * default: PKEY=no
     * description: InfiniBand parent device.
     * example: PHYSDEV=ib0
     * ---end---
     */
    obj_properties[PROP_PARENT] = g_param_spec_string(
        NM_SETTING_INFINIBAND_PARENT,
        "",
        "",
        NULL,
        G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_INFINIBAND,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
