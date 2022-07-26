/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-loopback.h"

#include <stdlib.h>
#include <sys/types.h>

#include "nm-act-request.h"
#include "nm-device-private.h"
#include "libnm-platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-setting-loopback.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "libnm-core-intern/nm-core-internal.h"

#define _NMLOG_DEVICE_TYPE NMDeviceLoopback
#include "nm-device-logging.h"

/*****************************************************************************/

struct _NMDeviceLoopback {
    NMDevice parent;
};

struct _NMDeviceLoopbackClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceLoopback, nm_device_loopback, NM_TYPE_DEVICE)

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *dev)
{
    return NM_DEVICE_CAP_NONE;
}

static guint32
get_configured_mtu(NMDevice *device, NMDeviceMtuSource *out_source, gboolean *out_force)
{
    return nm_device_get_configured_mtu_from_connection(device,
                                                        NM_TYPE_SETTING_LOOPBACK,
                                                        out_source);
}

static gboolean
complete_connection(NMDevice            *device,
                    NMConnection        *connection,
                    const char          *specific_object,
                    NMConnection *const *existing_connections,
                    GError             **error)
{
    nm_utils_complete_generic_with_params(nm_device_get_platform(device),
                                          connection,
                                          NM_SETTING_LOOPBACK_SETTING_NAME,
                                          existing_connections,
                                          NULL,
                                          _("Loopback connection"),
                                          NULL,
                                          nm_device_get_ip_iface(device));

    _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_LOOPBACK);

    return TRUE;
}

static void
update_connection(NMDevice *device, NMConnection *connection)
{
    _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_LOOPBACK);
}

/*****************************************************************************/

static const NMDBusInterfaceInfoExtended interface_info_device_loopback = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(NM_DBUS_INTERFACE_DEVICE_LOOPBACK, ),
};

static void
nm_device_loopback_init(NMDeviceLoopback *self)
{}

static void
nm_device_loopback_class_init(NMDeviceLoopbackClass *klass)
{
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_loopback);

    device_class->connection_type_supported        = NM_SETTING_LOOPBACK_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_LOOPBACK_SETTING_NAME;
    device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_LOOPBACK);

    device_class->complete_connection                    = complete_connection;
    device_class->get_generic_capabilities               = get_generic_capabilities;
    device_class->update_connection                      = update_connection;
    device_class->act_stage1_prepare_set_hwaddr_ethernet = TRUE;
    device_class->get_configured_mtu                     = get_configured_mtu;
    device_class->allow_autoconnect_on_external          = TRUE;
}

/*****************************************************************************/

#define NM_TYPE_LOOPBACK_DEVICE_FACTORY (nm_loopback_device_factory_get_type())
#define NM_LOOPBACK_DEVICE_FACTORY(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_LOOPBACK_DEVICE_FACTORY, NMLoopbackDeviceFactory))

static NMDevice *
create_device(NMDeviceFactory      *factory,
              const char           *iface,
              const NMPlatformLink *plink,
              NMConnection         *connection,
              gboolean             *out_ignore)
{
    return g_object_new(NM_TYPE_DEVICE_LOOPBACK,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_TYPE_DESC,
                        "Loopback",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_LOOPBACK,
                        NM_DEVICE_LINK_TYPE,
                        NM_LINK_TYPE_LOOPBACK,
                        NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL(
    LOOPBACK,
    Loopback,
    loopback,
    NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(NM_LINK_TYPE_LOOPBACK)
        NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_LOOPBACK_SETTING_NAME),
    factory_class->create_device = create_device;);
