/* SPDX-License-Identifier: LGPL-2.1+ */
/*
 * Copyright (C) 2020 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-veth.h"

#include "nm-setting-connection.h"
#include "nm-setting-veth.h"
#include "nm-setting-wired.h"
#include "nm-utils.h"
#include "nm-device-ethernet.h"
#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PEER, );

typedef struct {
    char *peer;
} NMDeviceVethPrivate;

struct _NMDeviceVeth {
    NMDeviceEthernet    parent;
    NMDeviceVethPrivate _priv;
};

struct _NMDeviceVethClass {
    NMDeviceEthernetClass parent;
};

G_DEFINE_TYPE(NMDeviceVeth, nm_device_veth, NM_TYPE_DEVICE_ETHERNET)

#define NM_DEVICE_VETH_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceVeth, NM_IS_DEVICE_VETH, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_veth_get_peer:
 * @device: a #NMDeviceVeth
 *
 * Returns: the device's peer name
 *
 * Since: 1.30
 **/
const char *
nm_device_veth_get_peer(NMDeviceVeth *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_VETH(device), NULL);

    return _nml_coerce_property_str_not_empty(NM_DEVICE_VETH_GET_PRIVATE(device)->peer);
}

static GType
get_setting_type(NMDevice *device)
{
    return NM_TYPE_SETTING_VETH;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceVeth *device = NM_DEVICE_VETH(object);

    switch (prop_id) {
    case PROP_PEER:
        g_value_set_string(value, nm_device_veth_get_peer(device));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nm_device_veth_init(NMDeviceVeth *device)
{}

static void
finalize(GObject *object)
{
    NMDeviceVethPrivate *priv = NM_DEVICE_VETH_GET_PRIVATE(object);

    g_free(priv->peer);

    G_OBJECT_CLASS(nm_device_veth_parent_class)->finalize(object);
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_veth = NML_DBUS_META_IFACE_INIT_PROP(
    NM_DBUS_INTERFACE_DEVICE_VETH,
    nm_device_veth_get_type,
    NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_20,
    NML_DBUS_META_IFACE_DBUS_PROPERTIES(
        NML_DBUS_META_PROPERTY_INIT_S("peer", PROP_PEER, NMDeviceVeth, _priv.peer), ), );

static void
nm_device_veth_class_init(NMDeviceVethClass *klass)
{
    GObjectClass * object_class    = G_OBJECT_CLASS(klass);
    NMObjectClass *nm_object_class = NM_OBJECT_CLASS(klass);
    NMDeviceClass *device_class    = NM_DEVICE_CLASS(klass);

    object_class->get_property = get_property;
    object_class->finalize     = finalize;

    _NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT(nm_object_class, NMDeviceVeth);

    device_class->get_setting_type = get_setting_type;

    /**
     * NMDeviceVeth:peer:
     *
     * The device's peer name.
     *
     * Since: 1.30
     **/
    obj_properties[PROP_PEER] = g_param_spec_string(NM_DEVICE_VETH_PEER,
                                                    "",
                                                    "",
                                                    NULL,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    _nml_dbus_meta_class_init_with_properties(object_class, &_nml_dbus_meta_iface_nm_device_veth);
}
