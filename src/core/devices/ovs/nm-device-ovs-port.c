/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-ovs-port.h"

#include "nm-device-ovs-interface.h"
#include "nm-device-ovs-bridge.h"
#include "nm-ovsdb.h"

#include "devices/nm-device-private.h"
#include "nm-active-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-ovs-port.h"
#include "nm-setting-ovs-interface.h"
#include "nm-setting-wired.h"

#define _NMLOG_DEVICE_TYPE NMDeviceOvsPort
#include "devices/nm-device-logging.h"

/*****************************************************************************/

struct _NMDeviceOvsPort {
    NMDevice parent;
};

struct _NMDeviceOvsPortClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceOvsPort, nm_device_ovs_port, NM_TYPE_DEVICE)

/*****************************************************************************/

static const char *
get_type_description(NMDevice *device)
{
    return "ovs-port";
}

static gboolean
create_and_realize(NMDevice              *device,
                   NMConnection          *connection,
                   NMDevice              *parent,
                   const NMPlatformLink **out_plink,
                   GError               **error)
{
    /* The port will be added to ovsdb when an interface is enslaved,
     * because there's no such thing like an empty port. */

    return TRUE;
}

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *device)
{
    return NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
ready_for_ip_config(NMDevice *device, gboolean is_manual)
{
    return FALSE;
}

static void
act_stage3_ip_config(NMDevice *device, int addr_family)
{
    nm_device_devip_set_state(device, addr_family, NM_DEVICE_IP_STATE_READY, NULL);
}

typedef struct {
    NMDevice                  *device;
    NMDevice                  *port;
    GCancellable              *cancellable;
    NMDeviceAttachPortCallback callback;
    gpointer                   callback_user_data;
    gboolean                   add;
} AttachPortData;

static void
add_del_iface_cb(GError *error, gpointer user_data)
{
    AttachPortData       *data = user_data;
    NMDeviceOvsPort      *self;
    gs_free_error GError *local = NULL;

    if (g_cancellable_is_cancelled(data->cancellable)) {
        local = nm_utils_error_new_cancelled(FALSE, NULL);
        error = local;
    } else if (error && !nm_utils_error_is_cancelled_or_disposing(error)) {
        self = NM_DEVICE_OVS_PORT(data->device);
        _LOGW(LOGD_DEVICE,
              "device %s could not be %s a ovs port: %s",
              nm_device_get_iface(data->port),
              data->add ? "added to" : "removed from",
              error->message);
        nm_device_state_changed(data->port,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_OVSDB_FAILED);
    }

    if (data->callback)
        data->callback(data->device, error, data->callback_user_data);

    g_object_unref(data->device);
    g_object_unref(data->port);
    nm_clear_g_cancellable(&data->cancellable);

    nm_g_slice_free(data);
}

static gboolean
_ovs_interface_is_dpdk(NMDevice *device)
{
    NMSettingOvsInterface *s_ovs_iface;

    s_ovs_iface = nm_device_get_applied_setting(device, NM_TYPE_SETTING_OVS_INTERFACE);

    g_return_val_if_fail(s_ovs_iface, FALSE);

    return nm_streq(nm_setting_ovs_interface_get_interface_type(s_ovs_iface), "dpdk");
}

static void
set_mtu_cb(GError *error, gpointer user_data)
{
    NMDevice *self = user_data;

    if (error && !g_error_matches(error, NM_UTILS_ERROR, NM_UTILS_ERROR_CANCELLED_DISPOSING)) {
        _LOGW(LOGD_DEVICE,
              "could not change mtu of '%s': %s",
              nm_device_get_iface(self),
              error->message);
    }

    g_object_unref(self);
}

static NMTernary
attach_port(NMDevice                  *device,
            NMDevice                  *port,
            NMConnection              *connection,
            gboolean                   configure,
            GCancellable              *cancellable,
            NMDeviceAttachPortCallback callback,
            gpointer                   user_data)
{
    NMDeviceOvsPort    *self      = NM_DEVICE_OVS_PORT(device);
    NMActiveConnection *ac_port   = NULL;
    NMActiveConnection *ac_bridge = NULL;
    NMDevice           *bridge_device;
    NMSettingWired     *s_wired;
    AttachPortData     *data;

    if (!configure)
        return TRUE;

    ac_port   = NM_ACTIVE_CONNECTION(nm_device_get_act_request(device));
    ac_bridge = nm_active_connection_get_master(ac_port);
    if (!ac_bridge) {
        _LOGW(LOGD_DEVICE,
              "can't attach %s: bridge active-connection not found",
              nm_device_get_iface(port));
        return FALSE;
    }

    bridge_device = nm_active_connection_get_device(ac_bridge);
    if (!bridge_device) {
        _LOGW(LOGD_DEVICE, "can't attach %s: bridge device not found", nm_device_get_iface(port));
        return FALSE;
    }

    data  = g_slice_new(AttachPortData);
    *data = (AttachPortData){
        .device             = g_object_ref(device),
        .port               = g_object_ref(port),
        .cancellable        = g_object_ref(cancellable),
        .callback           = callback,
        .callback_user_data = user_data,
        .add                = TRUE,
    };

    nm_ovsdb_add_interface(nm_ovsdb_get(),
                           nm_active_connection_get_applied_connection(ac_bridge),
                           nm_device_get_applied_connection(device),
                           nm_device_get_applied_connection(port),
                           bridge_device,
                           port,
                           add_del_iface_cb,
                           data);

    /* DPDK ports does not have a link after the devbind, so the MTU must be
     * set on ovsdb after adding the interface. */
    if (NM_IS_DEVICE_OVS_INTERFACE(port) && _ovs_interface_is_dpdk(port)) {
        s_wired = nm_device_get_applied_setting(port, NM_TYPE_SETTING_WIRED);
        if (s_wired && nm_setting_wired_get_mtu(s_wired)) {
            nm_ovsdb_set_interface_mtu(nm_ovsdb_get(),
                                       nm_device_get_ip_iface(port),
                                       nm_setting_wired_get_mtu(s_wired),
                                       set_mtu_cb,
                                       g_object_ref(port));
        }
    }

    return NM_TERNARY_DEFAULT;
}

static NMTernary
detach_port(NMDevice                  *device,
            NMDevice                  *port,
            gboolean                   configure,
            GCancellable              *cancellable,
            NMDeviceAttachPortCallback callback,
            gpointer                   user_data)
{
    NMDeviceOvsPort *self             = NM_DEVICE_OVS_PORT(device);
    bool             port_not_managed = !NM_IN_SET(nm_device_sys_iface_state_get(port),
                                       NM_DEVICE_SYS_IFACE_STATE_MANAGED,
                                       NM_DEVICE_SYS_IFACE_STATE_ASSUME);
    NMTernary        ret              = TRUE;

    _LOGI(LOGD_DEVICE, "detaching ovs interface %s", nm_device_get_ip_iface(port));

    /* Even if the an interface's device has gone away (e.g. externally
     * removed and thus we're called with configure=FALSE), we still need
     * to make sure its OVSDB entry is gone.
     */
    if (configure || port_not_managed) {
        AttachPortData *data;

        data  = g_slice_new(AttachPortData);
        *data = (AttachPortData){
            .device             = g_object_ref(device),
            .port               = g_object_ref(port),
            .cancellable        = nm_g_object_ref(cancellable),
            .callback           = callback,
            .callback_user_data = user_data,
            .add                = FALSE,
        };

        nm_ovsdb_del_interface(nm_ovsdb_get(), nm_device_get_iface(port), add_del_iface_cb, data);
        ret = NM_TERNARY_DEFAULT;
    }

    if (configure) {
        /* Open VSwitch is going to delete this one. We must ignore what happens
         * next with the interface. */
        if (NM_IS_DEVICE_OVS_INTERFACE(port))
            nm_device_update_from_platform_link(port, NULL);
    }

    return ret;
}

/*****************************************************************************/

static void
nm_device_ovs_port_init(NMDeviceOvsPort *self)
{}

static const NMDBusInterfaceInfoExtended interface_info_device_ovs_port = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_OVS_PORT,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Slaves", "ao", NM_DEVICE_SLAVES), ), ),
};

static void
nm_device_ovs_port_class_init(NMDeviceOvsPortClass *klass)
{
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_ovs_port);

    device_class->connection_type_supported        = NM_SETTING_OVS_PORT_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_OVS_PORT_SETTING_NAME;
    device_class->link_types                       = NM_DEVICE_DEFINE_LINK_TYPES();

    device_class->is_master                           = TRUE;
    device_class->get_type_description                = get_type_description;
    device_class->create_and_realize                  = create_and_realize;
    device_class->get_generic_capabilities            = get_generic_capabilities;
    device_class->act_stage3_ip_config                = act_stage3_ip_config;
    device_class->ready_for_ip_config                 = ready_for_ip_config;
    device_class->attach_port                         = attach_port;
    device_class->detach_port                         = detach_port;
    device_class->can_reapply_change_ovs_external_ids = TRUE;
    device_class->reapply_connection                  = nm_device_ovs_reapply_connection;
}
