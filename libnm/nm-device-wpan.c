/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Lubomir Rintel <lkundrak@v3.sk>
 */

#include "libnm/nm-default-libnm.h"

#include "nm-device-wpan.h"

#include "nm-object-private.h"
#include "nm-setting-wpan.h"
#include "nm-setting-connection.h"

/*****************************************************************************/

struct _NMDeviceWpan {
    NMDevice parent;
};

struct _NMDeviceWpanClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceWpan, nm_device_wpan, NM_TYPE_DEVICE)
/*****************************************************************************/

/**
 * nm_device_wpan_get_hw_address: (skip)
 * @device: a #NMDeviceWpan
 *
 * Gets the active hardware (MAC) address of the #NMDeviceWpan
 *
 * Returns: the active hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Deprecated: 1.24: Use nm_device_get_hw_address() instead.
 **/
const char *
nm_device_wpan_get_hw_address(NMDeviceWpan *device)
{
    g_return_val_if_fail(NM_IS_DEVICE_WPAN(device), NULL);

    return nm_device_get_hw_address(NM_DEVICE(device));
}

static gboolean
connection_compatible(NMDevice *device, NMConnection *connection, GError **error)
{
    if (!NM_DEVICE_CLASS(nm_device_wpan_parent_class)
             ->connection_compatible(device, connection, error))
        return FALSE;

    if (!nm_connection_is_type(connection, NM_SETTING_WPAN_SETTING_NAME)) {
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
                            _("The connection was not a wpan connection."));
        return FALSE;
    }

    return TRUE;
}

static GType
get_setting_type(NMDevice *device)
{
    return NM_TYPE_SETTING_WPAN;
}

/*****************************************************************************/

static void
nm_device_wpan_init(NMDeviceWpan *device)
{}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_wpan = NML_DBUS_META_IFACE_INIT(
    NM_DBUS_INTERFACE_DEVICE_WPAN,
    nm_device_wpan_get_type,
    NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
    NML_DBUS_META_IFACE_DBUS_PROPERTIES(
        NML_DBUS_META_PROPERTY_INIT_FCN("HwAddress",
                                        0,
                                        "s",
                                        _nm_device_notify_update_prop_hw_address), ), );

static void
nm_device_wpan_class_init(NMDeviceWpanClass *wpan_class)
{
    NMDeviceClass *device_class = NM_DEVICE_CLASS(wpan_class);

    device_class->connection_compatible = connection_compatible;
    device_class->get_setting_type      = get_setting_type;
}
