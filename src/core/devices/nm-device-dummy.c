/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-dummy.h"

#include <stdlib.h>
#include <sys/types.h>

#include "nm-act-request.h"
#include "nm-device-private.h"
#include "libnm-platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-setting-dummy.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "libnm-core-intern/nm-core-internal.h"

#define _NMLOG_DEVICE_TYPE NMDeviceDummy
#include "nm-device-logging.h"

/*****************************************************************************/

struct _NMDeviceDummy {
    NMDevice parent;
};

struct _NMDeviceDummyClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceDummy, nm_device_dummy, NM_TYPE_DEVICE)

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *dev)
{
    return NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
complete_connection(NMDevice            *device,
                    NMConnection        *connection,
                    const char          *specific_object,
                    NMConnection *const *existing_connections,
                    GError             **error)
{
    nm_utils_complete_generic(nm_device_get_platform(device),
                              connection,
                              NM_SETTING_DUMMY_SETTING_NAME,
                              existing_connections,
                              NULL,
                              _("Dummy connection"),
                              NULL,
                              nm_device_get_ip_iface(device));

    _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_DUMMY);

    return TRUE;
}

static void
update_connection(NMDevice *device, NMConnection *connection)
{
    _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_DUMMY);
}

static gboolean
create_and_realize(NMDevice              *device,
                   NMConnection          *connection,
                   NMDevice              *parent,
                   const NMPlatformLink **out_plink,
                   GError               **error)
{
    const char     *iface = nm_device_get_iface(device);
    NMSettingDummy *s_dummy;
    int             r;

    s_dummy = nm_connection_get_setting_dummy(connection);
    g_assert(s_dummy);

    r = nm_platform_link_dummy_add(nm_device_get_platform(device), iface, out_plink);
    if (r < 0) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_CREATION_FAILED,
                    "Failed to create dummy interface '%s' for '%s': %s",
                    iface,
                    nm_connection_get_id(connection),
                    nm_strerror(r));
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_device_dummy_init(NMDeviceDummy *self)
{}

static const NMDBusInterfaceInfoExtended interface_info_device_dummy = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_DUMMY,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE(
                "HwAddress",
                "s",
                NM_DEVICE_HW_ADDRESS,
                .annotations = NM_GDBUS_ANNOTATION_INFO_LIST_DEPRECATED(), ), ), ),
};

static void
nm_device_dummy_class_init(NMDeviceDummyClass *klass)
{
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_dummy);

    device_class->connection_type_supported        = NM_SETTING_DUMMY_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_DUMMY_SETTING_NAME;
    device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_DUMMY);

    device_class->complete_connection                    = complete_connection;
    device_class->create_and_realize                     = create_and_realize;
    device_class->get_generic_capabilities               = get_generic_capabilities;
    device_class->update_connection                      = update_connection;
    device_class->act_stage1_prepare_set_hwaddr_ethernet = TRUE;
    device_class->get_configured_mtu                     = nm_device_get_configured_mtu_for_wired;
}

/*****************************************************************************/

#define NM_TYPE_DUMMY_DEVICE_FACTORY (nm_dummy_device_factory_get_type())
#define NM_DUMMY_DEVICE_FACTORY(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DUMMY_DEVICE_FACTORY, NMDummyDeviceFactory))

static NMDevice *
create_device(NMDeviceFactory      *factory,
              const char           *iface,
              const NMPlatformLink *plink,
              NMConnection         *connection,
              gboolean             *out_ignore)
{
    return g_object_new(NM_TYPE_DEVICE_DUMMY,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_TYPE_DESC,
                        "Dummy",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_DUMMY,
                        NM_DEVICE_LINK_TYPE,
                        NM_LINK_TYPE_DUMMY,
                        NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL(
    DUMMY,
    Dummy,
    dummy,
    NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(NM_LINK_TYPE_DUMMY)
        NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_DUMMY_SETTING_NAME),
    factory_class->create_device = create_device;);
