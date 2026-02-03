/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2026 Red Hat, Inc.
 */

#include "libnm-client-impl/nm-default-libnm.h"

#include "nm-device-geneve.h"

#include "nm-setting-connection.h"
#include "nm-setting-geneve.h"
#include "nm-utils.h"
#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_ID,
                                  PROP_REMOTE,
                                  PROP_TOS,
                                  PROP_TTL,
                                  PROP_DST_PORT,
                                  PROP_DF, );

typedef struct {
    char   *remote;
    guint32 id;
    gint32  ttl;
    guint16 dst_port;
    guint8  df;
    guint8  tos;
} NMDeviceGenevePrivate;

struct _NMDeviceGeneve {
    NMDevice              parent;
    NMDeviceGenevePrivate _priv;
};

struct _NMDeviceGeneveClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceGeneve, nm_device_geneve, NM_TYPE_DEVICE)

#define NM_DEVICE_GENEVE_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceGeneve, NM_IS_DEVICE_GENEVE, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_geneve_get_id:
 * @device: a #NMDeviceGeneve
 *
 * Returns: the device's GENEVE ID.
 *
 * Since: 1.58, 1.56.1
 **/
guint
nm_device_geneve_get_id(NMDeviceGeneve *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_GENEVE(device), 0);

    return NM_DEVICE_GENEVE_GET_PRIVATE(device)->id;
}

/**
 * nm_device_geneve_get_remote:
 * @device: a #NMDeviceGeneve
 *
 * Returns: the IP address of the remote tunnel endpoint
 *
 * Since: 1.58, 1.56.1
 **/
const char *
nm_device_geneve_get_remote(NMDeviceGeneve *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_GENEVE(device), NULL);

    return _nml_coerce_property_str_not_empty(NM_DEVICE_GENEVE_GET_PRIVATE(device)->remote);
}

/**
 * nm_device_geneve_get_dst_port:
 * @device: a #NMDeviceGeneve
 *
 * Returns: the UDP destination port
 *
 * Since: 1.58, 1.56.1
 **/
guint
nm_device_geneve_get_dst_port(NMDeviceGeneve *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_GENEVE(device), 0);

    return NM_DEVICE_GENEVE_GET_PRIVATE(device)->dst_port;
}

/**
 * nm_device_geneve_get_tos:
 * @device: a #NMDeviceGeneve
 *
 * Returns: the TOS value to use in outgoing packets
 *
 * Since: 1.58, 1.56.1
 **/
guint
nm_device_geneve_get_tos(NMDeviceGeneve *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_GENEVE(device), 0);

    return NM_DEVICE_GENEVE_GET_PRIVATE(device)->tos;
}

/**
 * nm_device_geneve_get_ttl:
 * @device: a #NMDeviceGeneve
 *
 * Returns: the time-to-live value to use in outgoing packets
 *
 * Since: 1.58, 1.56.1
 **/
guint
nm_device_geneve_get_ttl(NMDeviceGeneve *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_GENEVE(device), 0);

    return NM_DEVICE_GENEVE_GET_PRIVATE(device)->ttl;
}

/**
 * nm_device_geneve_get_df:
 * @device: a #NMDeviceGeneve
 *
 * Returns: the Don't Fragment (DF) bit to set in outgoing packets
 *
 * Since: 1.58, 1.56.1
 **/
guint
nm_device_geneve_get_df(NMDeviceGeneve *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_GENEVE(device), 0);

    return NM_DEVICE_GENEVE_GET_PRIVATE(device)->df;
}

static gboolean
connection_compatible(NMDevice *device, NMConnection *connection, GError **error)
{
    NMSettingGeneve *s_geneve;

    if (!NM_DEVICE_CLASS(nm_device_geneve_parent_class)
             ->connection_compatible(device, connection, error))
        return FALSE;

    if (!nm_connection_is_type(connection, NM_SETTING_GENEVE_SETTING_NAME)) {
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
                            _("The connection was not a GENEVE connection."));
        return FALSE;
    }

    s_geneve = nm_connection_get_setting_geneve(connection);
    if (nm_setting_geneve_get_id(s_geneve) != nm_device_geneve_get_id(NM_DEVICE_GENEVE(device))) {
        g_set_error_literal(
            error,
            NM_DEVICE_ERROR,
            NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
            _("The GENEVE identifiers of the device and the connection didn't match."));
        return FALSE;
    }

    return TRUE;
}

static GType
get_setting_type(NMDevice *device)
{
    return NM_TYPE_SETTING_GENEVE;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceGeneve *device = NM_DEVICE_GENEVE(object);

    switch (prop_id) {
    case PROP_ID:
        g_value_set_uint(value, nm_device_geneve_get_id(device));
        break;
    case PROP_REMOTE:
        g_value_set_string(value, nm_device_geneve_get_remote(device));
        break;
    case PROP_TOS:
        g_value_set_uint(value, nm_device_geneve_get_tos(device));
        break;
    case PROP_TTL:
        g_value_set_int(value, nm_device_geneve_get_ttl(device));
        break;
    case PROP_DST_PORT:
        g_value_set_uint(value, nm_device_geneve_get_dst_port(device));
        break;
    case PROP_DF:
        g_value_set_uint(value, nm_device_geneve_get_df(device));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nm_device_geneve_init(NMDeviceGeneve *device)
{}

static void
finalize(GObject *object)
{
    NMDeviceGenevePrivate *priv = NM_DEVICE_GENEVE_GET_PRIVATE(object);

    g_free(priv->remote);

    G_OBJECT_CLASS(nm_device_geneve_parent_class)->finalize(object);
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_geneve = NML_DBUS_META_IFACE_INIT_PROP(
    NM_DBUS_INTERFACE_DEVICE_GENEVE,
    nm_device_geneve_get_type,
    NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
    NML_DBUS_META_IFACE_DBUS_PROPERTIES(
        NML_DBUS_META_PROPERTY_INIT_Y("Df", PROP_DF, NMDeviceGeneve, _priv.df),
        NML_DBUS_META_PROPERTY_INIT_Q("DstPort", PROP_DST_PORT, NMDeviceGeneve, _priv.dst_port),
        NML_DBUS_META_PROPERTY_INIT_U("Id", PROP_ID, NMDeviceGeneve, _priv.id),
        NML_DBUS_META_PROPERTY_INIT_S("Remote", PROP_REMOTE, NMDeviceGeneve, _priv.remote),
        NML_DBUS_META_PROPERTY_INIT_Y("Tos", PROP_TOS, NMDeviceGeneve, _priv.tos),
        NML_DBUS_META_PROPERTY_INIT_I("Ttl", PROP_TTL, NMDeviceGeneve, _priv.ttl), ), );

static void
nm_device_geneve_class_init(NMDeviceGeneveClass *klass)
{
    GObjectClass  *object_class    = G_OBJECT_CLASS(klass);
    NMObjectClass *nm_object_class = NM_OBJECT_CLASS(klass);
    NMDeviceClass *device_class    = NM_DEVICE_CLASS(klass);

    object_class->get_property = get_property;
    object_class->finalize     = finalize;

    _NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT(nm_object_class, NMDeviceGeneve);

    device_class->connection_compatible = connection_compatible;
    device_class->get_setting_type      = get_setting_type;

    /**
     * NMDeviceGeneve:id:
     *
     * The device's GENEVE ID.
     *
     * Since: 1.58, 1.56.1
     **/
    obj_properties[PROP_ID] = g_param_spec_uint(NM_DEVICE_GENEVE_ID,
                                                "",
                                                "",
                                                0,
                                                (1 << 24) - 1,
                                                0,
                                                G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceGeneve:remote:
     *
     * The IP address of the remote tunnel endpoint.
     *
     * Since: 1.58, 1.56.1
     */
    obj_properties[PROP_REMOTE] = g_param_spec_string(NM_DEVICE_GENEVE_REMOTE,
                                                      "",
                                                      "",
                                                      NULL,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceGeneve:tos:
     *
     * The TOS value to use in outgoing packets.
     *
     * Since: 1.58, 1.56.1
     */
    obj_properties[PROP_TOS] = g_param_spec_uchar(NM_DEVICE_GENEVE_TOS,
                                                  "",
                                                  "",
                                                  0,
                                                  255,
                                                  0,
                                                  G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceGeneve:ttl:
     *
     * The time-to-live value to use in outgoing packets.
     *
     * Since: 1.58, 1.56.1
     */
    obj_properties[PROP_TTL] = g_param_spec_int(NM_DEVICE_GENEVE_TTL,
                                                "",
                                                "",
                                                -1,
                                                255,
                                                0,
                                                G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceGeneve:dst-port:
     *
     * The UDP destination port used to communicate with the remote GENEVE tunnel
     * endpoint.
     *
     * Since: 1.58, 1.56.1
     */
    obj_properties[PROP_DST_PORT] = g_param_spec_uint(NM_DEVICE_GENEVE_DST_PORT,
                                                      "",
                                                      "",
                                                      0,
                                                      65535,
                                                      0,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceGeneve:df:
     *
     * The Don't Fragment (DF) bit to set in outgoing packets.
     *
     * Since: 1.58, 1.56.1
     */
    obj_properties[PROP_DF] = g_param_spec_uchar(NM_DEVICE_GENEVE_DF,
                                                 "",
                                                 "",
                                                 0,
                                                 2,
                                                 0,
                                                 G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    _nml_dbus_meta_class_init_with_properties(object_class, &_nml_dbus_meta_iface_nm_device_geneve);
}
