/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Javier Arteaga <jarteaga@jbeta.is>
 */

#include "libnm/nm-default-libnm.h"

#include "nm-device-wireguard.h"

#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PUBLIC_KEY, PROP_LISTEN_PORT, PROP_FWMARK, );

typedef struct {
    GBytes *public_key;
    guint32 fwmark;
    guint16 listen_port;
} NMDeviceWireGuardPrivate;

struct _NMDeviceWireGuard {
    NMDevice                 parent;
    NMDeviceWireGuardPrivate _priv;
};

struct _NMDeviceWireGuardClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceWireGuard, nm_device_wireguard, NM_TYPE_DEVICE)

#define NM_DEVICE_WIREGUARD_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceWireGuard, NM_IS_DEVICE_WIREGUARD, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_wireguard_get_public_key:
 * @device: a #NMDeviceWireGuard
 *
 * Gets the public key for this interface
 *
 * Returns: (transfer none): the #GBytes containing the 32-byte public key
 *
 * Since: 1.14
 **/
GBytes *
nm_device_wireguard_get_public_key(NMDeviceWireGuard *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_WIREGUARD(device), NULL);

    return NM_DEVICE_WIREGUARD_GET_PRIVATE(device)->public_key;
}

/**
 * nm_device_wireguard_get_listen_port:
 * @device: a #NMDeviceWireGuard
 *
 * Gets the local UDP port this interface listens on
 *
 * Returns: UDP listen port
 *
 * Since: 1.14
 **/
guint16
nm_device_wireguard_get_listen_port(NMDeviceWireGuard *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_WIREGUARD(device), 0);

    return NM_DEVICE_WIREGUARD_GET_PRIVATE(device)->listen_port;
}

/**
 * nm_device_wireguard_get_fwmark:
 * @device: a #NMDeviceWireGuard
 *
 * Gets the fwmark (firewall mark) for this interface.
 * It can be used to set routing policy for outgoing encrypted packets.
 * See: ip-rule(8)
 *
 * Returns: 0 if fwmark not in use, 32-bit fwmark value otherwise
 *
 * Since: 1.14
 **/
guint32
nm_device_wireguard_get_fwmark(NMDeviceWireGuard *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_WIREGUARD(device), 0);

    return NM_DEVICE_WIREGUARD_GET_PRIVATE(device)->fwmark;
}

/***********************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceWireGuard *device = NM_DEVICE_WIREGUARD(object);

    switch (prop_id) {
    case PROP_PUBLIC_KEY:
        g_value_set_boxed(value, nm_device_wireguard_get_public_key(device));
        break;
    case PROP_LISTEN_PORT:
        g_value_set_uint(value, nm_device_wireguard_get_listen_port(device));
        break;
    case PROP_FWMARK:
        g_value_set_uint(value, nm_device_wireguard_get_fwmark(device));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nm_device_wireguard_init(NMDeviceWireGuard *device)
{}

static void
finalize(GObject *object)
{
    NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE(object);

    g_bytes_unref(priv->public_key);

    G_OBJECT_CLASS(nm_device_wireguard_parent_class)->finalize(object);
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_wireguard = NML_DBUS_META_IFACE_INIT_PROP(
    NM_DBUS_INTERFACE_DEVICE_WIREGUARD,
    nm_device_wireguard_get_type,
    NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
    NML_DBUS_META_IFACE_DBUS_PROPERTIES(
        NML_DBUS_META_PROPERTY_INIT_U("FwMark", PROP_FWMARK, NMDeviceWireGuard, _priv.fwmark),
        NML_DBUS_META_PROPERTY_INIT_Q("ListenPort",
                                      PROP_LISTEN_PORT,
                                      NMDeviceWireGuard,
                                      _priv.listen_port),
        NML_DBUS_META_PROPERTY_INIT_AY("PublicKey",
                                       PROP_PUBLIC_KEY,
                                       NMDeviceWireGuard,
                                       _priv.public_key), ), );

static void
nm_device_wireguard_class_init(NMDeviceWireGuardClass *wireguard_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(wireguard_class);

    object_class->get_property = get_property;
    object_class->finalize     = finalize;

    /**
     * NMDeviceWireGuard:public-key:
     *
     * 32-byte public key, derived from the current private key.
     *
     * Since: 1.14
     **/
    obj_properties[PROP_PUBLIC_KEY] = g_param_spec_boxed(NM_DEVICE_WIREGUARD_PUBLIC_KEY,
                                                         "",
                                                         "",
                                                         G_TYPE_BYTES,
                                                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceWireGuard:listen-port:
     *
     * Local UDP listen port.
     * Set to 0 to allow a random port to be chosen (default).
     *
     * Since: 1.14
     **/
    obj_properties[PROP_LISTEN_PORT] = g_param_spec_uint(NM_DEVICE_WIREGUARD_LISTEN_PORT,
                                                         "",
                                                         "",
                                                         0,
                                                         G_MAXUINT16,
                                                         0,
                                                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceWireGuard:fwmark:
     *
     * Optional firewall mark - see ip-rule(8).
     * Used when setting routing policy for outgoing encrypted packets.
     * Set to 0 to disable the mark (default).
     *
     * Since: 1.14
     **/
    obj_properties[PROP_FWMARK] = g_param_spec_uint(NM_DEVICE_WIREGUARD_FWMARK,
                                                    "",
                                                    "",
                                                    0,
                                                    G_MAXUINT32,
                                                    0,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    _nml_dbus_meta_class_init_with_properties(object_class,
                                              &_nml_dbus_meta_iface_nm_device_wireguard);
}
