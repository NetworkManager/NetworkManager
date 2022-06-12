/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */

#include "libnm-client-impl/nm-default-libnm.h"

#include "nm-device-loopback.h"

#include "nm-object-private.h"
#include "nm-setting-loopback.h"
#include "nm-setting-connection.h"

/*****************************************************************************/

struct _NMDeviceLoopback {
    NMDevice parent;
};

struct _NMDeviceLoopbackClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceLoopback, nm_device_loopback, NM_TYPE_DEVICE)

/*****************************************************************************/

static gboolean
connection_compatible(NMDevice *device, NMConnection *connection, GError **error)
{
    const char *iface_name;

    if (!NM_DEVICE_CLASS(nm_device_loopback_parent_class)
             ->connection_compatible(device, connection, error))
        return FALSE;

    if (!nm_connection_is_type(connection, NM_SETTING_LOOPBACK_SETTING_NAME)) {
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
                            _("The connection was not a loopback connection."));
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
    return NM_TYPE_SETTING_LOOPBACK;
}

/*****************************************************************************/

static void
nm_device_loopback_init(NMDeviceLoopback *device)
{}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_loopback =
    NML_DBUS_META_IFACE_INIT(NM_DBUS_INTERFACE_DEVICE_LOOPBACK,
                             nm_device_loopback_get_type,
                             NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30, );

static void
nm_device_loopback_class_init(NMDeviceLoopbackClass *loopback_class)
{
    NMDeviceClass *device_class = NM_DEVICE_CLASS(loopback_class);

    device_class->connection_compatible = connection_compatible;
    device_class->get_setting_type      = get_setting_type;
}
