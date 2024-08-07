/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017, 2018 Red Hat, Inc.
 */

#include "libnm-client-impl/nm-default-libnm.h"

#include "nm-device-ovs-port.h"

#include "nm-object-private.h"
#include "nm-setting-ovs-port.h"
#include "nm-setting-ovs-port.h"
#include "nm-setting-connection.h"
#include "libnm-core-intern/nm-core-internal.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_SLAVES, );

struct _NMDeviceOvsPort {
    NMDevice parent;
};

struct _NMDeviceOvsPortClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceOvsPort, nm_device_ovs_port, NM_TYPE_DEVICE)

#define NM_DEVICE_OVS_PORT_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceOvsPort, NM_IS_DEVICE_OVS_PORT, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_ovs_port_get_slaves:
 * @device: a #NMDeviceOvsPort
 *
 * Gets the interfaces currently attached as port to @device.
 *
 * Returns: (element-type NMDevice): the #GPtrArray containing
 * #NMDevices that are ports of @device. This is the internal
 * copy used by the device, and must not be modified.
 *
 * Since: 1.14
 *
 * Deprecated: 1.34: Use nm_device_get_ports() instead.
 **/
const GPtrArray *
nm_device_ovs_port_get_slaves(NMDeviceOvsPort *device)
{
    return nm_device_get_ports(NM_DEVICE(device));
}

static const char *
get_type_description(NMDevice *device)
{
    return "ovs-port";
}

static gboolean
connection_compatible(NMDevice *device, NMConnection *connection, GError **error)
{
    const char *iface_name;

    if (!NM_DEVICE_CLASS(nm_device_ovs_port_parent_class)
             ->connection_compatible(device, connection, error))
        return FALSE;

    if (!nm_connection_is_type(connection, NM_SETTING_OVS_PORT_SETTING_NAME)) {
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
                            _("The connection was not a ovs_port connection."));
        return FALSE;
    }

    iface_name = nm_connection_get_interface_name(connection);
    if (!iface_name) {
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INVALID_CONNECTION,
                            _("The connection did not specify an interface name."));
        return FALSE;
    }

    return TRUE;
}

static GType
get_setting_type(NMDevice *device)
{
    return NM_TYPE_SETTING_OVS_PORT;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceOvsPort *device = NM_DEVICE_OVS_PORT(object);

    switch (prop_id) {
    case PROP_SLAVES:
        g_value_take_boxed(value,
                           _nm_utils_copy_object_array(nm_device_ovs_port_get_slaves(device)));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_device_ovs_port_init(NMDeviceOvsPort *device)
{}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_ovsport = NML_DBUS_META_IFACE_INIT_PROP(
    NM_DBUS_INTERFACE_DEVICE_OVS_PORT,
    nm_device_ovs_port_get_type,
    NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
    NML_DBUS_META_IFACE_DBUS_PROPERTIES(
        NML_DBUS_META_PROPERTY_INIT_FCN("Slaves",
                                        PROP_SLAVES,
                                        "ao",
                                        _nm_device_notify_update_prop_ports), ), );

static void
nm_device_ovs_port_class_init(NMDeviceOvsPortClass *klass)
{
    GObjectClass  *object_class = G_OBJECT_CLASS(klass);
    NMDeviceClass *device_class = NM_DEVICE_CLASS(klass);

    object_class->get_property = get_property;

    device_class->get_type_description  = get_type_description;
    device_class->connection_compatible = connection_compatible;
    device_class->get_setting_type      = get_setting_type;

    /**
     * NMDeviceOvsPort:slaves: (type GPtrArray(NMDevice))
     *
     * Gets the interfaces currently attached as port to the device.
     *
     * Since: 1.22
     */
    obj_properties[PROP_SLAVES] = g_param_spec_boxed(NM_DEVICE_OVS_PORT_SLAVES,
                                                     "",
                                                     "",
                                                     G_TYPE_PTR_ARRAY,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    _nml_dbus_meta_class_init_with_properties(object_class,
                                              &_nml_dbus_meta_iface_nm_device_ovsport);

    device_class->ports_param_spec = obj_properties[PROP_SLAVES];
}
