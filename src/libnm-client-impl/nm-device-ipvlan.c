/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */

#include "libnm-client-impl/nm-default-libnm.h"

#include "nm-device-ipvlan.h"

#include "nm-setting-connection.h"
#include "nm-setting-ipvlan.h"
#include "nm-utils.h"
#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PARENT, PROP_MODE, PROP_PRIVATE, PROP_VEPA, );

typedef struct {
    NMLDBusPropertyO parent;
    char            *mode;
    bool             private_flag;
    bool             vepa;
} NMDeviceIpvlanPrivate;

struct _NMDeviceIpvlan {
    NMDevice              parent;
    NMDeviceIpvlanPrivate _priv;
};

struct _NMDeviceIpvlanClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceIpvlan, nm_device_ipvlan, NM_TYPE_DEVICE)

#define NM_DEVICE_IPVLAN_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceIpvlan, NM_IS_DEVICE_IPVLAN, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_ipvlan_get_parent:
 * @device: a #NMDeviceIpvlan
 *
 * Returns: (transfer none): the device's parent device
 *
 * Since: 1.52
 **/
NMDevice *
nm_device_ipvlan_get_parent(NMDeviceIpvlan *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_IPVLAN(device), FALSE);

    return nml_dbus_property_o_get_obj(&NM_DEVICE_IPVLAN_GET_PRIVATE(device)->parent);
}

/**
 * nm_device_ipvlan_get_mode:
 * @device: a #NMDeviceIpvlan
 *
 * Gets the IPVLAN mode of the device.
 *
 * Returns: the IPVLAN mode. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 1.52
 **/
const char *
nm_device_ipvlan_get_mode(NMDeviceIpvlan *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_IPVLAN(device), NULL);

    return _nml_coerce_property_str_not_empty(NM_DEVICE_IPVLAN_GET_PRIVATE(device)->mode);
}

/**
 * nm_device_ipvlan_get_private
 * @device: a #NMDeviceIpvlan
 *
 * Gets the private flag of the device.
 *
 * Returns: the private flag of the device.
 *
 * Since: 1.52
 **/
gboolean
nm_device_ipvlan_get_private(NMDeviceIpvlan *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_IPVLAN(device), FALSE);

    return NM_DEVICE_IPVLAN_GET_PRIVATE(device)->private_flag;
}

/**
 * nm_device_ipvlan_get_vepa
 * @device: a #NMDeviceIpvlan
 *
 * Gets the VEPA flag of the device.
 *
 * Returns: the VEPA flag of the device.
 *
 * Since: 1.52
 **/
gboolean
nm_device_ipvlan_get_vepa(NMDeviceIpvlan *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_IPVLAN(device), FALSE);

    return NM_DEVICE_IPVLAN_GET_PRIVATE(device)->vepa;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceIpvlan *device = NM_DEVICE_IPVLAN(object);

    switch (prop_id) {
    case PROP_PARENT:
        g_value_set_object(value, nm_device_ipvlan_get_parent(device));
        break;
    case PROP_MODE:
        g_value_set_string(value, nm_device_ipvlan_get_mode(device));
        break;
    case PROP_PRIVATE:
        g_value_set_boolean(value, nm_device_ipvlan_get_private(device));
        break;
    case PROP_VEPA:
        g_value_set_boolean(value, nm_device_ipvlan_get_vepa(device));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nm_device_ipvlan_init(NMDeviceIpvlan *device)
{}

static void
finalize(GObject *object)
{
    NMDeviceIpvlanPrivate *priv = NM_DEVICE_IPVLAN_GET_PRIVATE(object);

    g_free(priv->mode);

    G_OBJECT_CLASS(nm_device_ipvlan_parent_class)->finalize(object);
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_ipvlan = NML_DBUS_META_IFACE_INIT_PROP(
    NM_DBUS_INTERFACE_DEVICE_IPVLAN,
    nm_device_ipvlan_get_type,
    NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
    NML_DBUS_META_IFACE_DBUS_PROPERTIES(
        NML_DBUS_META_PROPERTY_INIT_S("Mode", PROP_MODE, NMDeviceIpvlan, _priv.mode),
        NML_DBUS_META_PROPERTY_INIT_O_PROP("Parent",
                                           PROP_PARENT,
                                           NMDeviceIpvlan,
                                           _priv.parent,
                                           nm_device_get_type),
        NML_DBUS_META_PROPERTY_INIT_B("Private", PROP_PRIVATE, NMDeviceIpvlan, _priv.private_flag),
        NML_DBUS_META_PROPERTY_INIT_B("Vepa", PROP_VEPA, NMDeviceIpvlan, _priv.vepa), ), );

static void
nm_device_ipvlan_class_init(NMDeviceIpvlanClass *klass)
{
    GObjectClass  *object_class    = G_OBJECT_CLASS(klass);
    NMObjectClass *nm_object_class = NM_OBJECT_CLASS(klass);

    object_class->get_property = get_property;
    object_class->finalize     = finalize;

    _NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT(nm_object_class, NMDeviceIpvlan);

    _NM_OBJECT_CLASS_INIT_PROPERTY_O_FIELDS_1(nm_object_class, NMDeviceIpvlanPrivate, parent);

    /**
     * NMDeviceIpvlan:parent:
     *
     * The devices's parent device.
     *
     * Since: 1.52
     **/
    obj_properties[PROP_PARENT] = g_param_spec_object(NM_DEVICE_IPVLAN_PARENT,
                                                      "",
                                                      "",
                                                      NM_TYPE_DEVICE,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceIpvlan:mode:
     *
     * The IPVLAN mode.
     *
     * Since: 1.52
     **/
    obj_properties[PROP_MODE] = g_param_spec_string(NM_DEVICE_IPVLAN_MODE,
                                                    "",
                                                    "",
                                                    NULL,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceIpvlan:private:
     *
     * Whether the device has the private flag.
     *
     * Since: 1.52
     **/
    obj_properties[PROP_PRIVATE] = g_param_spec_boolean(NM_DEVICE_IPVLAN_PRIVATE,
                                                        "",
                                                        "",
                                                        FALSE,
                                                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceIpvlan:vepa:
     *
     * Whether the device has the VEPA flag.
     *
     * Since: 1.52
     **/
    obj_properties[PROP_VEPA] = g_param_spec_boolean(NM_DEVICE_IPVLAN_VEPA,
                                                     "",
                                                     "",
                                                     FALSE,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    _nml_dbus_meta_class_init_with_properties(object_class, &_nml_dbus_meta_iface_nm_device_ipvlan);
}
