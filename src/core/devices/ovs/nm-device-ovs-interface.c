/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-ovs-interface.h"

#include "nm-device-ovs-bridge.h"
#include "nm-ovsdb.h"

#include "devices/nm-device-private.h"
#include "nm-active-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-ovs-bridge.h"
#include "nm-setting-ovs-interface.h"
#include "nm-setting-ovs-port.h"

#define _NMLOG_DEVICE_TYPE NMDeviceOvsInterface
#include "devices/nm-device-logging.h"

/*****************************************************************************/

typedef struct {
    NMOvsdb *ovsdb;
    GSource *wait_link_idle_source;
    gulong   wait_link_signal_id;
    int      wait_link_ifindex;
    bool     wait_link_is_waiting : 1;
} NMDeviceOvsInterfacePrivate;

struct _NMDeviceOvsInterface {
    NMDevice                    parent;
    NMDeviceOvsInterfacePrivate _priv;
};

struct _NMDeviceOvsInterfaceClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceOvsInterface, nm_device_ovs_interface, NM_TYPE_DEVICE)

#define NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceOvsInterface, NM_IS_DEVICE_OVS_INTERFACE, NMDevice)

/*****************************************************************************/

static const char *
get_type_description(NMDevice *device)
{
    return "ovs-interface";
}

static gboolean
create_and_realize(NMDevice              *device,
                   NMConnection          *connection,
                   NMDevice              *parent,
                   const NMPlatformLink **out_plink,
                   GError               **error)
{
    /* The actual backing resources will be created once an interface is
     * added to a port of ours, since there can be neither an empty port nor
     * an empty bridge. */

    return TRUE;
}

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *device)
{
    return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
is_available(NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
    NMDeviceOvsInterface        *self = NM_DEVICE_OVS_INTERFACE(device);
    NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);

    return nm_ovsdb_is_ready(priv->ovsdb);
}

static gboolean
can_auto_connect(NMDevice *device, NMSettingsConnection *sett_conn, char **specific_object)
{
    NMDeviceOvsInterface        *self = NM_DEVICE_OVS_INTERFACE(device);
    NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);

    return nm_ovsdb_is_ready(priv->ovsdb);
}

static gboolean
check_connection_compatible(NMDevice     *device,
                            NMConnection *connection,
                            gboolean      check_properties,
                            GError      **error)
{
    NMSettingOvsInterface *s_ovs_iface;

    if (!NM_DEVICE_CLASS(nm_device_ovs_interface_parent_class)
             ->check_connection_compatible(device, connection, check_properties, error))
        return FALSE;

    s_ovs_iface = nm_connection_get_setting_ovs_interface(connection);

    if (!NM_IN_STRSET(nm_setting_ovs_interface_get_interface_type(s_ovs_iface),
                      "dpdk",
                      "internal",
                      "patch")) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "unsupported OVS interface type in profile");
        return FALSE;
    }

    return TRUE;
}

static void
link_changed(NMDevice *device, const NMPlatformLink *pllink)
{
    NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(device);

    if (!pllink || !priv->wait_link_is_waiting)
        return;

    priv->wait_link_is_waiting = FALSE;

    if (nm_device_get_state(device) == NM_DEVICE_STATE_IP_CONFIG) {
        if (!nm_device_hw_addr_set_cloned(device,
                                          nm_device_get_applied_connection(device),
                                          FALSE)) {
            nm_device_devip_set_failed(device, AF_INET, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
            nm_device_devip_set_failed(device, AF_INET6, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
            return;
        }

        nm_device_link_properties_set(device, FALSE);
        nm_device_bring_up(device);

        nm_device_devip_set_state(device, AF_INET, NM_DEVICE_IP_STATE_PENDING, NULL);
        nm_device_devip_set_state(device, AF_INET6, NM_DEVICE_IP_STATE_PENDING, NULL);
        nm_device_activate_schedule_stage3_ip_config(device, FALSE);
        return;
    }

    nm_device_activate_schedule_stage2_device_config(device, FALSE);
}

static gboolean
_is_internal_interface(NMDevice *device)
{
    NMSettingOvsInterface *s_ovs_iface;

    s_ovs_iface = nm_device_get_applied_setting(device, NM_TYPE_SETTING_OVS_INTERFACE);

    g_return_val_if_fail(s_ovs_iface, FALSE);

    return nm_streq(nm_setting_ovs_interface_get_interface_type(s_ovs_iface), "internal");
}

static void
set_platform_mtu_cb(GError *error, gpointer user_data)
{
    NMDevice             *device = user_data;
    NMDeviceOvsInterface *self   = NM_DEVICE_OVS_INTERFACE(device);

    if (error && !g_error_matches(error, NM_UTILS_ERROR, NM_UTILS_ERROR_CANCELLED_DISPOSING)) {
        _LOGW(LOGD_DEVICE,
              "could not change mtu of '%s': %s",
              nm_device_get_iface(device),
              error->message);
    }

    g_object_unref(device);
}

static gboolean
set_platform_mtu(NMDevice *device, guint32 mtu)
{
    NMDeviceOvsInterface        *self = NM_DEVICE_OVS_INTERFACE(device);
    NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);

    /*
     * If the MTU is not set in ovsdb, Open vSwitch will change
     * the MTU of an internal interface to match the minimum of
     * the other interfaces in the bridge.
     */
    /* FIXME(shutdown): the function should become cancellable so
     * that it doesn't need to hold a reference to the device, and
     * it can be stopped during shutdown.
     */
    if (_is_internal_interface(device)) {
        nm_ovsdb_set_interface_mtu(priv->ovsdb,
                                   nm_device_get_ip_iface(device),
                                   mtu,
                                   set_platform_mtu_cb,
                                   g_object_ref(device));
    }

    return NM_DEVICE_CLASS(nm_device_ovs_interface_parent_class)->set_platform_mtu(device, mtu);
}

static gboolean
ready_for_ip_config(NMDevice *device, gboolean is_manual)
{
    return nm_device_get_ip_ifindex(device) > 0;
}

static gboolean
_set_ip_ifindex_tun(gpointer user_data)
{
    NMDevice                    *device = user_data;
    NMDeviceOvsInterface        *self   = NM_DEVICE_OVS_INTERFACE(device);
    NMDeviceOvsInterfacePrivate *priv   = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->wait_link_idle_source);

    priv->wait_link_is_waiting = FALSE;
    nm_device_set_ip_ifindex(device, priv->wait_link_ifindex);
    nm_device_link_properties_set(device, FALSE);

    nm_device_devip_set_state(device, AF_INET, NM_DEVICE_IP_STATE_PENDING, NULL);
    nm_device_devip_set_state(device, AF_INET6, NM_DEVICE_IP_STATE_PENDING, NULL);
    nm_device_activate_schedule_stage3_ip_config(device, FALSE);

    return G_SOURCE_CONTINUE;
}

static void
_netdev_tun_link_cb(NMPlatform     *platform,
                    int             obj_type_i,
                    int             ifindex,
                    NMPlatformLink *pllink,
                    int             change_type_i,
                    NMDevice       *device)
{
    const NMPlatformSignalChangeType change_type = change_type_i;
    NMDeviceOvsInterface            *self        = NM_DEVICE_OVS_INTERFACE(device);
    NMDeviceOvsInterfacePrivate     *priv        = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);

    if (change_type == NM_PLATFORM_SIGNAL_ADDED) {
        if (pllink->type == NM_LINK_TYPE_TUN
            && nm_streq0(pllink->name, nm_device_get_iface(device))) {
            nm_clear_g_signal_handler(platform, &priv->wait_link_signal_id);

            priv->wait_link_ifindex = ifindex;

            priv->wait_link_idle_source = nm_g_idle_add_source(_set_ip_ifindex_tun, device);
        }
    }
}

static void
act_stage3_ip_config(NMDevice *device, int addr_family)
{
    NMActiveConnection          *controller_act = NULL;
    NMSettingOvsBridge          *s_ovs_bridge   = NULL;
    NMDeviceOvsInterface        *self           = NM_DEVICE_OVS_INTERFACE(device);
    NMDeviceOvsInterfacePrivate *priv           = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);

    if (!_is_internal_interface(device)) {
        nm_device_devip_set_state(device, addr_family, NM_DEVICE_IP_STATE_READY, NULL);
        return;
    }

    /* When the ovs-bridge controller is using netdev datapath, the interface
     * link created is a tun device instead of a ovs-interface. NetworkManager must
     * detect the creation of the tun link and attach the ifindex to the
     * ovs-interface device. */
    controller_act = NM_ACTIVE_CONNECTION(nm_device_get_act_request(device));
    if (controller_act && nm_device_get_ip_ifindex(device) <= 0 && priv->wait_link_signal_id == 0) {
        controller_act = nm_active_connection_get_master(controller_act);
        if (controller_act) {
            controller_act = nm_active_connection_get_master(controller_act);
            if (controller_act)
                s_ovs_bridge = nm_connection_get_setting_ovs_bridge(
                    nm_active_connection_get_applied_connection(controller_act));
            if (s_ovs_bridge
                && nm_streq0(nm_setting_ovs_bridge_get_datapath_type(s_ovs_bridge), "netdev"))
                priv->wait_link_signal_id = g_signal_connect(nm_device_get_platform(device),
                                                             NM_PLATFORM_SIGNAL_LINK_CHANGED,
                                                             G_CALLBACK(_netdev_tun_link_cb),
                                                             self);
        }
    }

    /* FIXME(l3cfg): we should create the IP ifindex before stage3 start.
     *
     * For now it's here because when the ovs-interface enters stage3, then it's added to the
     * controller (ovs-port) and the entry is create in the ovsdb. Only after that the kernel
     * link appears.
     *
     * This should change. */
    if (nm_device_get_ip_ifindex(device) <= 0) {
        _LOGT(LOGD_DEVICE, "waiting for link to appear");
        priv->wait_link_is_waiting = TRUE;
        nm_device_devip_set_state(device, addr_family, NM_DEVICE_IP_STATE_PENDING, NULL);
        return;
    }

    priv->wait_link_is_waiting = FALSE;
    nm_clear_g_source_inst(&priv->wait_link_idle_source);
    nm_clear_g_signal_handler(nm_device_get_platform(device), &priv->wait_link_signal_id);

    if (!nm_device_hw_addr_set_cloned(device, nm_device_get_applied_connection(device), FALSE)) {
        nm_device_devip_set_failed(device, addr_family, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
        return;
    }

    nm_device_link_properties_set(device, FALSE);
    nm_device_devip_set_state(device, addr_family, NM_DEVICE_IP_STATE_READY, NULL);
}

static gboolean
can_unmanaged_external_down(NMDevice *self)
{
    return FALSE;
}

static void
deactivate(NMDevice *device)
{
    NMDeviceOvsInterface        *self = NM_DEVICE_OVS_INTERFACE(device);
    NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);

    priv->wait_link_is_waiting = FALSE;
    nm_clear_g_source_inst(&priv->wait_link_idle_source);
}

typedef struct {
    NMDeviceOvsInterface      *self;
    GCancellable              *cancellable;
    NMDeviceDeactivateCallback callback;
    gpointer                   callback_user_data;
    gulong                     link_changed_id;
    gulong                     cancelled_id;
    guint                      link_timeout_id;
} DeactivateData;

static void
deactivate_invoke_cb(DeactivateData *data, GError *error)
{
    NMDeviceOvsInterface *self = data->self;

    _LOGT(LOGD_CORE, "deactivate: async callback (%s)", error ? error->message : "success");
    data->callback(NM_DEVICE(data->self), error, data->callback_user_data);

    nm_clear_g_signal_handler(nm_device_get_platform(NM_DEVICE(data->self)),
                              &data->link_changed_id);
    nm_clear_g_signal_handler(data->cancellable, &data->cancelled_id);
    nm_clear_g_source(&data->link_timeout_id);
    g_object_unref(data->self);
    g_object_unref(data->cancellable);
    nm_g_slice_free(data);
}

static void
deactivate_link_changed_cb(NMPlatform     *platform,
                           int             obj_type_i,
                           int             ifindex,
                           NMPlatformLink *info,
                           int             change_type_i,
                           DeactivateData *data)
{
    NMDeviceOvsInterface            *self        = data->self;
    const NMPlatformSignalChangeType change_type = change_type_i;

    if (change_type == NM_PLATFORM_SIGNAL_REMOVED
        && nm_streq0(info->name, nm_device_get_iface(NM_DEVICE(self)))) {
        _LOGT(LOGD_DEVICE, "deactivate: link removed, proceeding");
        nm_device_update_from_platform_link(NM_DEVICE(self), NULL);
        deactivate_invoke_cb(data, NULL);
        return;
    }
}

static gboolean
deactivate_link_timeout(gpointer user_data)
{
    DeactivateData       *data = user_data;
    NMDeviceOvsInterface *self = data->self;

    _LOGT(LOGD_DEVICE, "deactivate: timeout waiting link removal");
    deactivate_invoke_cb(data, NULL);
    return G_SOURCE_REMOVE;
}

static void
deactivate_cancelled_cb(GCancellable *cancellable, gpointer user_data)
{
    gs_free_error GError *error = NULL;

    nm_utils_error_set_cancelled(&error, FALSE, NULL);
    deactivate_invoke_cb((DeactivateData *) user_data, error);
}

static void
deactivate_cb_on_idle(gpointer user_data, GCancellable *cancellable)
{
    DeactivateData       *data            = user_data;
    gs_free_error GError *cancelled_error = NULL;

    g_cancellable_set_error_if_cancelled(data->cancellable, &cancelled_error);
    deactivate_invoke_cb(data, cancelled_error);
}

static void
deactivate_async(NMDevice                  *device,
                 GCancellable              *cancellable,
                 NMDeviceDeactivateCallback callback,
                 gpointer                   callback_user_data)
{
    NMDeviceOvsInterface        *self = NM_DEVICE_OVS_INTERFACE(device);
    NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);
    DeactivateData              *data;

    _LOGT(LOGD_CORE, "deactivate: start async");

    /* We want to ensure that the kernel link for this device is
     * removed upon disconnection so that it will not interfere with
     * later activations of the same device. Unfortunately there is
     * no synchronization mechanism with vswitchd, we only update
     * ovsdb and wait that changes are picked up.
     */

    data  = g_slice_new(DeactivateData);
    *data = (DeactivateData){
        .self               = g_object_ref(self),
        .cancellable        = g_object_ref(cancellable),
        .callback           = callback,
        .callback_user_data = callback_user_data,
    };

    if (!priv->wait_link_is_waiting
        && !nm_platform_link_get_by_ifname(nm_device_get_platform(device),
                                           nm_device_get_iface(device))) {
        _LOGT(LOGD_CORE, "deactivate: link not present, proceeding");
        nm_device_update_from_platform_link(NM_DEVICE(self), NULL);
        nm_utils_invoke_on_idle(cancellable, deactivate_cb_on_idle, data);
        return;
    }

    nm_clear_g_source_inst(&priv->wait_link_idle_source);

    if (priv->wait_link_is_waiting) {
        /* At this point we have issued an INSERT and a DELETE
         * command for the interface to ovsdb. We don't know if
         * vswitchd will see the two updates or only one. We
         * must add a timeout to avoid waiting forever in case
         * the link doesn't appear.
         */
        data->link_timeout_id = g_timeout_add(6000, deactivate_link_timeout, data);
        _LOGT(LOGD_DEVICE, "deactivate: waiting for link to disappear in 6 seconds");
    } else
        _LOGT(LOGD_DEVICE, "deactivate: waiting for link to disappear");

    data->cancelled_id =
        g_cancellable_connect(cancellable, G_CALLBACK(deactivate_cancelled_cb), data, NULL);
    data->link_changed_id = g_signal_connect(nm_device_get_platform(device),
                                             NM_PLATFORM_SIGNAL_LINK_CHANGED,
                                             G_CALLBACK(deactivate_link_changed_cb),
                                             data);
}

static gboolean
can_update_from_platform_link(NMDevice *device, const NMPlatformLink *plink)
{
    /* If the device is deactivating, we already sent the
     * deletion command to ovsdb and we don't want to deal
     * with any new link appearing from the previous
     * activation.
     */
    return !plink || nm_device_get_state(device) != NM_DEVICE_STATE_DEACTIVATING;
}

/*****************************************************************************/

static void
ovsdb_ready(NMOvsdb *ovsdb, NMDeviceOvsInterface *self)
{
    NMDevice *device = NM_DEVICE(self);

    nm_device_queue_recheck_available(device,
                                      NM_DEVICE_STATE_REASON_NONE,
                                      NM_DEVICE_STATE_REASON_NONE);
    nm_device_recheck_available_connections(device);
    nm_device_recheck_auto_activate_schedule(device);
}

static void
nm_device_ovs_interface_init(NMDeviceOvsInterface *self)
{
    NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);

    priv->ovsdb = g_object_ref(nm_ovsdb_get());

    if (!nm_ovsdb_is_ready(priv->ovsdb))
        g_signal_connect(priv->ovsdb, NM_OVSDB_READY, G_CALLBACK(ovsdb_ready), self);
}

static void
dispose(GObject *object)
{
    NMDeviceOvsInterface        *self = NM_DEVICE_OVS_INTERFACE(object);
    NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);

    if (priv->ovsdb) {
        g_signal_handlers_disconnect_by_func(priv->ovsdb, G_CALLBACK(ovsdb_ready), self);
        g_clear_object(&priv->ovsdb);
    }

    G_OBJECT_CLASS(nm_device_ovs_interface_parent_class)->dispose(object);
}

static const NMDBusInterfaceInfoExtended interface_info_device_ovs_interface = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(NM_DBUS_INTERFACE_DEVICE_OVS_INTERFACE, ),
};

static void
nm_device_ovs_interface_class_init(NMDeviceOvsInterfaceClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    object_class->dispose = dispose;

    dbus_object_class->interface_infos =
        NM_DBUS_INTERFACE_INFOS(&interface_info_device_ovs_interface);

    device_class->connection_type_supported        = NM_SETTING_OVS_INTERFACE_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_OVS_INTERFACE_SETTING_NAME;
    device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_OPENVSWITCH);

    device_class->can_auto_connect                    = can_auto_connect;
    device_class->can_update_from_platform_link       = can_update_from_platform_link;
    device_class->deactivate                          = deactivate;
    device_class->deactivate_async                    = deactivate_async;
    device_class->get_type_description                = get_type_description;
    device_class->create_and_realize                  = create_and_realize;
    device_class->get_generic_capabilities            = get_generic_capabilities;
    device_class->is_available                        = is_available;
    device_class->check_connection_compatible         = check_connection_compatible;
    device_class->link_changed                        = link_changed;
    device_class->act_stage3_ip_config                = act_stage3_ip_config;
    device_class->ready_for_ip_config                 = ready_for_ip_config;
    device_class->can_unmanaged_external_down         = can_unmanaged_external_down;
    device_class->set_platform_mtu                    = set_platform_mtu;
    device_class->get_configured_mtu                  = nm_device_get_configured_mtu_for_wired;
    device_class->can_reapply_change_ovs_external_ids = TRUE;
    device_class->reapply_connection                  = nm_device_ovs_reapply_connection;
}
