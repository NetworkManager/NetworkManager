/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2023 Red Hat, Inc.
 */

#include "libnm-client-impl/nm-default-libnm.h"

#include "nm-device-hsr.h"

#include "nm-setting-connection.h"
#include "nm-setting-hsr.h"
#include "nm-utils.h"
#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PORT1,
                                  PROP_PORT2,
                                  PROP_SUPERVISION_ADDRESS,
                                  PROP_MULTICAST_SPEC,
                                  PROP_PRP, );

enum {
    PROPERTY_O_IDX_PORT1,
    PROPERTY_O_IDX_PORT2,
    _PROPERTY_O_IDX_NUM,
};

typedef struct {
    char            *supervision_address;
    NMLDBusPropertyO property_o[_PROPERTY_O_IDX_NUM];
    guint8           multicast_spec;
    bool             prp;
} NMDeviceHsrPrivate;

struct _NMDeviceHsr {
    NMDevice           parent;
    NMDeviceHsrPrivate _priv;
};

struct _NMDeviceHsrClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceHsr, nm_device_hsr, NM_TYPE_DEVICE)

#define NM_DEVICE_HSR_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceHsr, NM_IS_DEVICE_HSR, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_hsr_get_port1:
 * @device: a #NMDeviceHsr
 *
 * Returns: (transfer none): the device's port1 device
 *
 * Since: 1.46
 **/
NMDevice *
nm_device_hsr_get_port1(NMDeviceHsr *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_HSR(device), NULL);

    return nml_dbus_property_o_get_obj(
        &NM_DEVICE_HSR_GET_PRIVATE(device)->property_o[PROPERTY_O_IDX_PORT1]);
}

/**
 * nm_device_hsr_get_port2:
 * @device: a #NMDeviceHsr
 *
 * Returns: (transfer none): the device's port2 device
 *
 * Since: 1.46
 **/
NMDevice *
nm_device_hsr_get_port2(NMDeviceHsr *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_HSR(device), NULL);

    return nml_dbus_property_o_get_obj(
        &NM_DEVICE_HSR_GET_PRIVATE(device)->property_o[PROPERTY_O_IDX_PORT2]);
}

/**
 * nm_device_hsr_get_supervision_address:
 * @device: a #NMDeviceHsr
 *
 * Returns: the supervision MAC adddress
 *
 * Since: 1.46
 **/
const char *
nm_device_hsr_get_supervision_address(NMDeviceHsr *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_HSR(device), NULL);

    return NM_DEVICE_HSR_GET_PRIVATE(device)->supervision_address;
}

/**
 * nm_device_hsr_get_multicast_spec:
 * @device: a #NMDeviceHsr
 *
 * Returns: the last byte of the supervision address
 *
 * Since: 1.46
 **/
guint8
nm_device_hsr_get_multicast_spec(NMDeviceHsr *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_HSR(device), 0);

    return NM_DEVICE_HSR_GET_PRIVATE(device)->multicast_spec;
}

/**
 * nm_device_hsr_get_prp:
 * @device: a #NMDeviceHsr
 *
 * Returns: whether PRP protocol is used or not
 *
 * Since: 1.46
 **/
gboolean
nm_device_hsr_get_prp(NMDeviceHsr *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_HSR(device), FALSE);

    return NM_DEVICE_HSR_GET_PRIVATE(device)->prp;
}

/*****************************************************************************/

static void
nm_device_hsr_init(NMDeviceHsr *device)
{}

static void
finalize(GObject *object)
{
    NMDeviceHsrPrivate *priv = NM_DEVICE_HSR_GET_PRIVATE(object);

    g_free(priv->supervision_address);

    G_OBJECT_CLASS(nm_device_hsr_parent_class)->finalize(object);
}

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceHsr *device = NM_DEVICE_HSR(object);

    switch (prop_id) {
    case PROP_PORT1:
        g_value_set_object(value, nm_device_hsr_get_port1(device));
        break;
    case PROP_PORT2:
        g_value_set_object(value, nm_device_hsr_get_port2(device));
        break;
    case PROP_SUPERVISION_ADDRESS:
        g_value_set_string(value, nm_device_hsr_get_supervision_address(device));
        break;
    case PROP_MULTICAST_SPEC:
        g_value_set_uchar(value, nm_device_hsr_get_multicast_spec(device));
        break;
    case PROP_PRP:
        g_value_set_boolean(value, nm_device_hsr_get_prp(device));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_hsr = NML_DBUS_META_IFACE_INIT_PROP(
    NM_DBUS_INTERFACE_DEVICE_HSR,
    nm_device_hsr_get_type,
    NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
    NML_DBUS_META_IFACE_DBUS_PROPERTIES(
        NML_DBUS_META_PROPERTY_INIT_Y("MulticastSpec",
                                      PROP_MULTICAST_SPEC,
                                      NMDeviceHsr,
                                      _priv.multicast_spec),
        NML_DBUS_META_PROPERTY_INIT_O_PROP("Port1",
                                           PROP_PORT1,
                                           NMDeviceHsr,
                                           _priv.property_o[PROPERTY_O_IDX_PORT1],
                                           nm_device_get_type),
        NML_DBUS_META_PROPERTY_INIT_O_PROP("Port2",
                                           PROP_PORT2,
                                           NMDeviceHsr,
                                           _priv.property_o[PROPERTY_O_IDX_PORT2],
                                           nm_device_get_type),
        NML_DBUS_META_PROPERTY_INIT_B("Prp", PROP_PRP, NMDeviceHsr, _priv.prp),
        NML_DBUS_META_PROPERTY_INIT_S("SupervisionAddress",
                                      PROP_SUPERVISION_ADDRESS,
                                      NMDeviceHsr,
                                      _priv.supervision_address), ), );

static void
nm_device_hsr_class_init(NMDeviceHsrClass *klass)
{
    GObjectClass  *object_class    = G_OBJECT_CLASS(klass);
    NMObjectClass *nm_object_class = NM_OBJECT_CLASS(klass);

    object_class->get_property = get_property;
    object_class->finalize     = finalize;

    _NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT(nm_object_class, NMDeviceHsr);

    _NM_OBJECT_CLASS_INIT_PROPERTY_O_FIELDS_N(nm_object_class, NMDeviceHsrPrivate, property_o);

    /**
     * NMDeviceHsr:port1:
     *
     * The device's port1 device.
     *
     * Since: 1.46
     **/
    obj_properties[PROP_PORT1] = g_param_spec_object(NM_DEVICE_HSR_PORT1,
                                                     "",
                                                     "",
                                                     NM_TYPE_DEVICE,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceHsr:port2:
     *
     * The device's port2 device.
     *
     * Since: 1.46
     **/
    obj_properties[PROP_PORT2] = g_param_spec_object(NM_DEVICE_HSR_PORT2,
                                                     "",
                                                     "",
                                                     NM_TYPE_DEVICE,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceHsr:supervision-address:
     *
     * The device supervision MAC adddress.
     *
     * Since: 1.46
     **/
    obj_properties[PROP_SUPERVISION_ADDRESS] =
        g_param_spec_string(NM_DEVICE_HSR_SUPERVISION_ADDRESS,
                            "",
                            "",
                            FALSE,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceHsr:multicast-spec:
     *
     * The device last byte of the supervision address.
     *
     * Since: 1.46
     **/
    obj_properties[PROP_MULTICAST_SPEC] =
        g_param_spec_uchar(NM_DEVICE_HSR_MULTICAST_SPEC,
                           "",
                           "",
                           0,
                           G_MAXUINT8,
                           0,
                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceHsr:prp:
     *
     * Whether the PRP protocol is used or not.
     *
     * Since: 1.46
     **/
    obj_properties[PROP_PRP] = g_param_spec_boolean(NM_DEVICE_HSR_PRP,
                                                    "",
                                                    "",
                                                    FALSE,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    _nml_dbus_meta_class_init_with_properties(object_class, &_nml_dbus_meta_iface_nm_device_hsr);
}
