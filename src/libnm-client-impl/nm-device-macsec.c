/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "libnm-client-impl/nm-default-libnm.h"

#include "nm-device-macsec.h"

#include "nm-device-private.h"
#include "nm-object-private.h"
#include "nm-utils.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PARENT,
                                  PROP_SCI,
                                  PROP_CIPHER_SUITE,
                                  PROP_ICV_LENGTH,
                                  PROP_WINDOW,
                                  PROP_ENCODING_SA,
                                  PROP_ENCRYPT,
                                  PROP_PROTECT,
                                  PROP_INCLUDE_SCI,
                                  PROP_ES,
                                  PROP_SCB,
                                  PROP_REPLAY_PROTECT,
                                  PROP_VALIDATION, );

typedef struct {
    NMLDBusPropertyO parent;
    char            *validation;
    guint64          sci;
    guint64          cipher_suite;
    guint32          window;
    guint8           icv_length;
    guint8           encoding_sa;
    bool             encrypt;
    bool             protect;
    bool             include_sci;
    bool             es;
    bool             scb;
    bool             replay_protect;
} NMDeviceMacsecPrivate;

struct _NMDeviceMacsec {
    NMDevice              parent;
    NMDeviceMacsecPrivate _priv;
};

struct _NMDeviceMacsecClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceMacsec, nm_device_macsec, NM_TYPE_DEVICE)

#define NM_DEVICE_MACSEC_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceMacsec, NM_IS_DEVICE_MACSEC, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_macsec_get_parent:
 * @device: a #NMDeviceMacsec
 *
 * Returns: (transfer none): the device's parent device
 *
 * Since: 1.42
 **/
NMDevice *
nm_device_macsec_get_parent(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), NULL);

    return nml_dbus_property_o_get_obj(&NM_DEVICE_MACSEC_GET_PRIVATE(device)->parent);
}

/**
 * nm_device_macsec_get_hw_address: (skip)
 * @device: a #NMDeviceMacsec
 *
 * Gets the hardware (MAC) address of the #NMDeviceMacsec
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 1.6
 *
 * Deprecated: 1.24: Use nm_device_get_hw_address() instead.
 **/
const char *
nm_device_macsec_get_hw_address(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), NULL);

    return nm_device_get_hw_address(NM_DEVICE(device));
}

/**
 * nm_device_macsec_get_sci:
 * @device: a #NMDeviceMacsec
 *
 * Gets the Secure Channel Identifier in use
 *
 * Returns: the SCI
 *
 * Since: 1.6
 **/
guint64
nm_device_macsec_get_sci(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), 0);

    return NM_DEVICE_MACSEC_GET_PRIVATE(device)->sci;
}

/**
 * nm_device_macsec_get_icv_length:
 * @device: a #NMDeviceMacsec
 *
 * Gets the length of ICV (Integrity Check Value)
 *
 * Returns: the length of ICV
 *
 * Since: 1.6
 **/
guint8
nm_device_macsec_get_icv_length(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), 0);

    return NM_DEVICE_MACSEC_GET_PRIVATE(device)->icv_length;
}

/**
 * nm_device_macsec_get_cipher_suite:
 * @device: a #NMDeviceMacsec
 *
 * Gets the set of cryptographic algorithms in use
 *
 * Returns: the set of cryptographic algorithms in use
 *
 * Since: 1.6
 **/
guint64
nm_device_macsec_get_cipher_suite(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), 0);

    return NM_DEVICE_MACSEC_GET_PRIVATE(device)->cipher_suite;
}

/**
 * nm_device_macsec_get_window:
 * @device: a #NMDeviceMacsec
 *
 * Gets the size of the replay window
 *
 * Returns: size of the replay window
 *
 * Since: 1.6
 **/
guint
nm_device_macsec_get_window(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), 0);

    return NM_DEVICE_MACSEC_GET_PRIVATE(device)->window;
}

/**
 * nm_device_macsec_get_encoding_sa:
 * @device: a #NMDeviceMacsec
 *
 * Gets the value of the Association Number (0..3) for the Security
 * Association in use.
 *
 * Returns: the current Security Association
 *
 * Since: 1.6
 **/
guint8
nm_device_macsec_get_encoding_sa(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), 0);

    return NM_DEVICE_MACSEC_GET_PRIVATE(device)->encoding_sa;
}

/**
 * nm_device_macsec_get_validation:
 * @device: a #NMDeviceMacsec
 *
 * Gets the validation mode for incoming packets (strict, check,
 * disabled)
 *
 * Returns: the validation mode
 *
 * Since: 1.6
 **/
const char *
nm_device_macsec_get_validation(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), NULL);

    return NM_DEVICE_MACSEC_GET_PRIVATE(device)->validation;
}

/**
 * nm_device_macsec_get_encrypt:
 * @device: a #NMDeviceMacsec
 *
 * Gets whether encryption of transmitted frames is enabled
 *
 * Returns: whether encryption is enabled
 *
 * Since: 1.6
 **/
gboolean
nm_device_macsec_get_encrypt(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), FALSE);

    return NM_DEVICE_MACSEC_GET_PRIVATE(device)->encrypt;
}

/**
 * nm_device_macsec_get_protect:
 * @device: a #NMDeviceMacsec
 *
 * Gets whether protection of transmitted frames is enabled
 *
 * Returns: whether protection is enabled
 *
 * Since: 1.6
 **/
gboolean
nm_device_macsec_get_protect(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), FALSE);

    return NM_DEVICE_MACSEC_GET_PRIVATE(device)->protect;
}

/**
 * nm_device_macsec_get_include_sci:
 * @device: a #NMDeviceMacsec
 *
 * Gets whether the SCI is always included in SecTAG for transmitted
 * frames
 *
 * Returns: whether the SCI is always included
 *
 * Since: 1.6
 **/
gboolean
nm_device_macsec_get_include_sci(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), FALSE);

    return NM_DEVICE_MACSEC_GET_PRIVATE(device)->include_sci;
}

/**
 * nm_device_macsec_get_es:
 * @device: a #NMDeviceMacsec
 *
 * Gets whether the ES (End station) bit is enabled in SecTAG for
 * transmitted frames
 *
 * Returns: whether the ES (End station) bit is enabled
 *
 * Since: 1.6
 **/
gboolean
nm_device_macsec_get_es(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), FALSE);

    return NM_DEVICE_MACSEC_GET_PRIVATE(device)->es;
}

/**
 * nm_device_macsec_get_scb:
 * @device: a #NMDeviceMacsec
 *
 * Gets whether the SCB (Single Copy Broadcast) bit is enabled in
 * SecTAG for transmitted frames
 *
 * Returns: whether the SCB (Single Copy Broadcast) bit is enabled
 *
 * Since: 1.6
 **/
gboolean
nm_device_macsec_get_scb(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), FALSE);

    return NM_DEVICE_MACSEC_GET_PRIVATE(device)->scb;
}

/**
 * nm_device_macsec_get_replay_protect:
 * @device: a #NMDeviceMacsec
 *
 * Gets whether replay protection is enabled
 *
 * Returns: whether replay protection is enabled
 *
 * Since: 1.6
 **/
gboolean
nm_device_macsec_get_replay_protect(NMDeviceMacsec *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_MACSEC(device), FALSE);

    return NM_DEVICE_MACSEC_GET_PRIVATE(device)->replay_protect;
}

/***********************************************************/

static void
nm_device_macsec_init(NMDeviceMacsec *device)
{}

static void
finalize(GObject *object)
{
    NMDeviceMacsecPrivate *priv = NM_DEVICE_MACSEC_GET_PRIVATE(object);

    g_free(priv->validation);

    G_OBJECT_CLASS(nm_device_macsec_parent_class)->finalize(object);
}

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceMacsec *device = NM_DEVICE_MACSEC(object);

    switch (prop_id) {
    case PROP_PARENT:
        g_value_set_object(value, nm_device_macsec_get_parent(device));
        break;
    case PROP_SCI:
        g_value_set_uint64(value, nm_device_macsec_get_sci(device));
        break;
    case PROP_ICV_LENGTH:
        g_value_set_uchar(value, nm_device_macsec_get_icv_length(device));
        break;
    case PROP_CIPHER_SUITE:
        g_value_set_uint64(value, nm_device_macsec_get_cipher_suite(device));
        break;
    case PROP_WINDOW:
        g_value_set_uint(value, nm_device_macsec_get_window(device));
        break;
    case PROP_ENCODING_SA:
        g_value_set_uchar(value, nm_device_macsec_get_encoding_sa(device));
        break;
    case PROP_VALIDATION:
        g_value_set_string(value, nm_device_macsec_get_validation(device));
        break;
    case PROP_ENCRYPT:
        g_value_set_boolean(value, nm_device_macsec_get_encrypt(device));
        break;
    case PROP_PROTECT:
        g_value_set_boolean(value, nm_device_macsec_get_protect(device));
        break;
    case PROP_INCLUDE_SCI:
        g_value_set_boolean(value, nm_device_macsec_get_include_sci(device));
        break;
    case PROP_ES:
        g_value_set_boolean(value, nm_device_macsec_get_es(device));
        break;
    case PROP_SCB:
        g_value_set_boolean(value, nm_device_macsec_get_scb(device));
        break;
    case PROP_REPLAY_PROTECT:
        g_value_set_boolean(value, nm_device_macsec_get_replay_protect(device));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_macsec = NML_DBUS_META_IFACE_INIT_PROP(
    NM_DBUS_INTERFACE_DEVICE_MACSEC,
    nm_device_macsec_get_type,
    NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
    NML_DBUS_META_IFACE_DBUS_PROPERTIES(
        NML_DBUS_META_PROPERTY_INIT_T("CipherSuite",
                                      PROP_CIPHER_SUITE,
                                      NMDeviceMacsec,
                                      _priv.cipher_suite),
        NML_DBUS_META_PROPERTY_INIT_Y("EncodingSa",
                                      PROP_ENCODING_SA,
                                      NMDeviceMacsec,
                                      _priv.encoding_sa),
        NML_DBUS_META_PROPERTY_INIT_B("Encrypt", PROP_ENCRYPT, NMDeviceMacsec, _priv.encrypt),
        NML_DBUS_META_PROPERTY_INIT_B("Es", PROP_ES, NMDeviceMacsec, _priv.es),
        NML_DBUS_META_PROPERTY_INIT_Y("IcvLength",
                                      PROP_ICV_LENGTH,
                                      NMDeviceMacsec,
                                      _priv.icv_length),
        NML_DBUS_META_PROPERTY_INIT_B("IncludeSci",
                                      PROP_INCLUDE_SCI,
                                      NMDeviceMacsec,
                                      _priv.include_sci),
        NML_DBUS_META_PROPERTY_INIT_O_PROP("Parent",
                                           PROP_PARENT,
                                           NMDeviceMacsec,
                                           _priv.parent,
                                           nm_device_get_type),
        NML_DBUS_META_PROPERTY_INIT_B("Protect", PROP_PROTECT, NMDeviceMacsec, _priv.protect),
        NML_DBUS_META_PROPERTY_INIT_B("ReplayProtect",
                                      PROP_REPLAY_PROTECT,
                                      NMDeviceMacsec,
                                      _priv.replay_protect),
        NML_DBUS_META_PROPERTY_INIT_B("Scb", PROP_SCB, NMDeviceMacsec, _priv.scb),
        NML_DBUS_META_PROPERTY_INIT_T("Sci", PROP_SCI, NMDeviceMacsec, _priv.sci),
        NML_DBUS_META_PROPERTY_INIT_S("Validation",
                                      PROP_VALIDATION,
                                      NMDeviceMacsec,
                                      _priv.validation),
        NML_DBUS_META_PROPERTY_INIT_U("Window", PROP_WINDOW, NMDeviceMacsec, _priv.window), ), );

static void
nm_device_macsec_class_init(NMDeviceMacsecClass *klass)
{
    GObjectClass  *object_class    = G_OBJECT_CLASS(klass);
    NMObjectClass *nm_object_class = NM_OBJECT_CLASS(klass);

    object_class->get_property = get_property;
    object_class->finalize     = finalize;

    _NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT(nm_object_class, NMDeviceMacsec);

    _NM_OBJECT_CLASS_INIT_PROPERTY_O_FIELDS_1(nm_object_class, NMDeviceMacsecPrivate, parent);

    /**
     * NMDeviceMacsec:parent:
     *
     * The devices's parent device.
     *
     * Since: 1.6
     **/
    obj_properties[PROP_PARENT] = g_param_spec_object(NM_DEVICE_MACSEC_PARENT,
                                                      "",
                                                      "",
                                                      NM_TYPE_DEVICE,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceMacsec:sci:
     *
     * The Secure Channel Identifier in use.
     *
     * Since: 1.6
     **/
    obj_properties[PROP_SCI] = g_param_spec_uint64(NM_DEVICE_MACSEC_SCI,
                                                   "",
                                                   "",
                                                   0,
                                                   G_MAXUINT64,
                                                   0,
                                                   G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceMacsec:icv-length:
     *
     * The length of ICV (Integrity Check Value).
     *
     * Since: 1.6
     **/
    obj_properties[PROP_ICV_LENGTH] = g_param_spec_uchar(NM_DEVICE_MACSEC_ICV_LENGTH,
                                                         "",
                                                         "",
                                                         0,
                                                         G_MAXUINT8,
                                                         0,
                                                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceMacsec:cipher-suite:
     *
     * The set of cryptographic algorithms in use.
     *
     * Since: 1.6
     **/
    obj_properties[PROP_CIPHER_SUITE] =
        g_param_spec_uint64(NM_DEVICE_MACSEC_CIPHER_SUITE,
                            "",
                            "",
                            0,
                            G_MAXUINT64,
                            0,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceMacsec:window:
     *
     * The size of the replay window.
     *
     * Since: 1.6
     **/
    obj_properties[PROP_WINDOW] = g_param_spec_uint(NM_DEVICE_MACSEC_WINDOW,
                                                    "",
                                                    "",
                                                    0,
                                                    G_MAXUINT32,
                                                    0,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceMacsec:encoding-sa:
     *
     * The value of the Association Number (0..3) for the Security
     * Association in use.
     *
     * Since: 1.6
     **/
    obj_properties[PROP_ENCODING_SA] =
        g_param_spec_uchar(NM_DEVICE_MACSEC_ENCODING_SA,
                           "",
                           "",
                           0,
                           G_MAXUINT8,
                           0,
                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceMacsec:validation:
     *
     * The validation mode for incoming packets (strict, check,
     * disabled).
     *
     * Since: 1.6
     **/
    obj_properties[PROP_VALIDATION] =
        g_param_spec_string(NM_DEVICE_MACSEC_VALIDATION,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceMacsec:encrypt:
     *
     * Whether encryption of transmitted frames is enabled.
     *
     * Since: 1.6
     **/
    obj_properties[PROP_ENCRYPT] = g_param_spec_boolean(NM_DEVICE_MACSEC_ENCRYPT,
                                                        "",
                                                        "",
                                                        FALSE,
                                                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceMacsec:protect:
     *
     * Whether protection of transmitted frames is enabled.
     *
     * Since: 1.6
     **/
    obj_properties[PROP_PROTECT] = g_param_spec_boolean(NM_DEVICE_MACSEC_PROTECT,
                                                        "",
                                                        "",
                                                        FALSE,
                                                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceMacsec:include-sci:
     *
     * Whether the SCI is always included in SecTAG for transmitted
     * frames.
     *
     * Since: 1.6
     **/
    obj_properties[PROP_INCLUDE_SCI] =
        g_param_spec_boolean(NM_DEVICE_MACSEC_INCLUDE_SCI,
                             "",
                             "",
                             FALSE,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceMacsec:es:
     *
     * Whether the ES (End station) bit is enabled in SecTAG for
     * transmitted frames.
     *
     * Since: 1.6
     **/
    obj_properties[PROP_ES] = g_param_spec_boolean(NM_DEVICE_MACSEC_ES,
                                                   "",
                                                   "",
                                                   FALSE,
                                                   G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceMacsec:scb:
     *
     * Whether the SCB (Single Copy Broadcast) bit is enabled in
     * SecTAG for transmitted frames.
     *
     * Since: 1.6
     **/
    obj_properties[PROP_SCB] = g_param_spec_boolean(NM_DEVICE_MACSEC_SCB,
                                                    "",
                                                    "",
                                                    FALSE,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceMacsec:replay-protect:
     *
     * Whether replay protection is enabled.
     *
     * Since: 1.6
     **/
    obj_properties[PROP_REPLAY_PROTECT] =
        g_param_spec_boolean(NM_DEVICE_MACSEC_REPLAY_PROTECT,
                             "",
                             "",
                             FALSE,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    _nml_dbus_meta_class_init_with_properties(object_class, &_nml_dbus_meta_iface_nm_device_macsec);
}
