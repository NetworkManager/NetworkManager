/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-ovs-bridge.h"

#include "nm-device-ovs-interface.h"
#include "nm-device-ovs-port.h"
#include "nm-ovsdb.h"

#include "devices/nm-device-private.h"
#include "nm-active-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-ovs-bridge.h"
#include "nm-setting-ovs-external-ids.h"
#include "nm-core-internal.h"

#define _NMLOG_DEVICE_TYPE NMDeviceOvsBridge
#include "devices/nm-device-logging.h"

/*****************************************************************************/

struct _NMDeviceOvsBridge {
    NMDevice parent;
};

struct _NMDeviceOvsBridgeClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceOvsBridge, nm_device_ovs_bridge, NM_TYPE_DEVICE)

/*****************************************************************************/

static const char *
get_type_description(NMDevice *device)
{
    return "ovs-bridge";
}

static gboolean
create_and_realize(NMDevice *             device,
                   NMConnection *         connection,
                   NMDevice *             parent,
                   const NMPlatformLink **out_plink,
                   GError **              error)
{
    /* The actual backing resources will be created on enslavement by the port
     * when it can identify the port and the bridge. */

    return TRUE;
}

static gboolean
unrealize(NMDevice *device, GError **error)
{
    return TRUE;
}

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *device)
{
    return NM_DEVICE_CAP_IS_SOFTWARE;
}

static NMActStageReturn
act_stage3_ip_config_start(NMDevice *           device,
                           int                  addr_family,
                           gpointer *           out_config,
                           NMDeviceStateReason *out_failure_reason)
{
    return NM_ACT_STAGE_RETURN_IP_FAIL;
}

static gboolean
enslave_slave(NMDevice *device, NMDevice *slave, NMConnection *connection, gboolean configure)
{
    if (!configure)
        return TRUE;

    if (!NM_IS_DEVICE_OVS_PORT(slave))
        return FALSE;

    return TRUE;
}

static void
release_slave(NMDevice *device, NMDevice *slave, gboolean configure)
{}

void
nm_device_ovs_reapply_connection(NMDevice *self, NMConnection *con_old, NMConnection *con_new)
{
    NMDeviceType device_type;
    GType        type;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(g_type_parent(G_TYPE_FROM_INSTANCE(self)) == NM_TYPE_DEVICE);

    /* NMDevice's reapply_connection() doesn't do anything. No need to call the parent
     * implementation. */

    _LOGD(LOGD_DEVICE, "reapplying settings for OVS device");

    type = G_OBJECT_TYPE(self);
    if (type == NM_TYPE_DEVICE_OVS_INTERFACE)
        device_type = NM_DEVICE_TYPE_OVS_INTERFACE;
    else if (type == NM_TYPE_DEVICE_OVS_PORT)
        device_type = NM_DEVICE_TYPE_OVS_PORT;
    else {
        nm_assert(type == NM_TYPE_DEVICE_OVS_BRIDGE);
        device_type = NM_DEVICE_TYPE_OVS_BRIDGE;
    }

    nm_ovsdb_set_external_ids(
        nm_ovsdb_get(),
        device_type,
        nm_device_get_ip_iface(self),
        nm_connection_get_uuid(con_new),
        _nm_connection_get_setting(con_old, NM_TYPE_SETTING_OVS_EXTERNAL_IDS),
        _nm_connection_get_setting(con_new, NM_TYPE_SETTING_OVS_EXTERNAL_IDS));
}

/*****************************************************************************/

static void
nm_device_ovs_bridge_init(NMDeviceOvsBridge *self)
{}

static const NMDBusInterfaceInfoExtended interface_info_device_ovs_bridge = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_OVS_BRIDGE,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Slaves", "ao", NM_DEVICE_SLAVES), ),
        .signals = NM_DEFINE_GDBUS_SIGNAL_INFOS(&nm_signal_info_property_changed_legacy, ), ),
    .legacy_property_changed = TRUE,
};

static void
nm_device_ovs_bridge_class_init(NMDeviceOvsBridgeClass *klass)
{
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass *    device_class      = NM_DEVICE_CLASS(klass);

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_ovs_bridge);

    device_class->connection_type_supported        = NM_SETTING_OVS_BRIDGE_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_OVS_BRIDGE_SETTING_NAME;
    device_class->link_types                       = NM_DEVICE_DEFINE_LINK_TYPES();

    device_class->is_master                           = TRUE;
    device_class->get_type_description                = get_type_description;
    device_class->create_and_realize                  = create_and_realize;
    device_class->unrealize                           = unrealize;
    device_class->get_generic_capabilities            = get_generic_capabilities;
    device_class->act_stage3_ip_config_start          = act_stage3_ip_config_start;
    device_class->enslave_slave                       = enslave_slave;
    device_class->release_slave                       = release_slave;
    device_class->can_reapply_change_ovs_external_ids = TRUE;
    device_class->reapply_connection                  = nm_device_ovs_reapply_connection;
}
