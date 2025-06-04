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
#include "nm-setting-ovs-external-ids.h"
#include "nm-setting-ovs-other-config.h"

#define _NMLOG_DEVICE_TYPE NMDeviceOvsInterface
#include "devices/nm-device-logging.h"

/*****************************************************************************/

typedef struct {
    NMOvsdb *ovsdb;

    struct {
        /* The signal id for the TUN link-changed event */
        gulong tun_link_signal_id;
        /* The idle handler source for the TUN link-changed event */
        GSource *tun_link_idle_source;
        /* The ifindex for the TUN link-changed event */
        int tun_ifindex;

        /* The cloned MAC to set */
        char *cloned_mac;
        /* Whether we have determined the cloned MAC */
        bool cloned_mac_evaluated : 1;

        /* Whether we are waiting for the kernel link */
        bool waiting : 1;
    } wait_link;
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

static void _netdev_tun_link_cb(NMPlatform     *platform,
                                int             obj_type_i,
                                int             ifindex,
                                NMPlatformLink *pllink,
                                int             change_type_i,
                                NMDevice       *device);

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

static gboolean
check_waiting_for_link(NMDevice *device, const char *from)
{
    NMDeviceOvsInterface        *self     = NM_DEVICE_OVS_INTERFACE(device);
    NMDeviceOvsInterfacePrivate *priv     = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);
    NMPlatform                  *platform = nm_device_get_platform(device);
    const NMPlatformLink        *pllink;
    int                          ip_ifindex;
    const char                  *reason = NULL;

    if (!priv->wait_link.waiting)
        return FALSE;

    nm_assert(priv->wait_link.cloned_mac_evaluated);
    ip_ifindex = nm_device_get_ip_ifindex(device);

    if (ip_ifindex <= 0) {
        reason = "no ifindex";
    } else if (!(pllink = nm_platform_link_get(platform, ip_ifindex))) {
        reason = "platform link not found";
    } else if (!pllink->initialized) {
        reason = "link is not ready yet";
    } else if (priv->wait_link.cloned_mac
               && !nm_utils_hwaddr_matches(priv->wait_link.cloned_mac,
                                           -1,
                                           pllink->l_address.data,
                                           pllink->l_address.len)) {
        reason = "cloned MAC address is not set yet";
    } else {
        priv->wait_link.waiting = FALSE;
    }

    if (priv->wait_link.waiting)
        _LOGT(LOGD_DEVICE, "ovs-wait-link(%s): not ready: %s", from, reason);

    return priv->wait_link.waiting;
}

static void
link_changed(NMDevice *device, const NMPlatformLink *pllink)
{
    NMDeviceOvsInterface        *self = NM_DEVICE_OVS_INTERFACE(device);
    NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);

    if (!pllink || !priv->wait_link.waiting)
        return;

    if (nm_device_get_state(device) != NM_DEVICE_STATE_IP_CONFIG)
        return;

    if (check_waiting_for_link(device, "link-changed"))
        return;

    _LOGT(LOGD_CORE, "ovs-wait-link: link is ready after link changed event");

    nm_device_link_properties_set(device, FALSE);
    nm_device_bring_up(device);

    nm_device_devip_set_state(device, AF_INET, NM_DEVICE_IP_STATE_PENDING, NULL);
    nm_device_devip_set_state(device, AF_INET6, NM_DEVICE_IP_STATE_PENDING, NULL);
    nm_device_activate_schedule_stage3_ip_config(device, FALSE);
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
    NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(device);

    return nm_device_get_ip_ifindex(device) > 0 && !priv->wait_link.waiting;
}

static gboolean
_netdev_tun_link_cb_in_idle(gpointer user_data)
{
    NMDevice                    *device = user_data;
    NMDeviceOvsInterface        *self   = NM_DEVICE_OVS_INTERFACE(device);
    NMDeviceOvsInterfacePrivate *priv   = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);

    if (nm_device_get_ip_ifindex(device) <= 0) {
        _LOGT(LOGD_CORE,
              "ovs-wait-link: setting ip-ifindex %d from tun link",
              priv->wait_link.tun_ifindex);
        nm_device_set_ip_ifindex(device, priv->wait_link.tun_ifindex);
    }

    if (check_waiting_for_link(device, "tun-link-changed")) {
        nm_clear_g_source_inst(&priv->wait_link.tun_link_idle_source);
        return G_SOURCE_CONTINUE;
    }

    _LOGT(LOGD_CORE, "ovs-wait-link: tun link is ready");
    nm_device_link_properties_set(device, FALSE);
    nm_device_bring_up(device);

    nm_device_devip_set_state(device, AF_INET, NM_DEVICE_IP_STATE_PENDING, NULL);
    nm_device_devip_set_state(device, AF_INET6, NM_DEVICE_IP_STATE_PENDING, NULL);
    nm_device_activate_schedule_stage3_ip_config(device, FALSE);
    nm_clear_g_signal_handler(nm_device_get_platform(device), &priv->wait_link.tun_link_signal_id);
    nm_clear_g_source_inst(&priv->wait_link.tun_link_idle_source);

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

    /* This is the handler for the link-changed platform events. It is triggered for all
     * link changes. Keep only the ones matching our device. */
    if (!NM_IN_SET(change_type, NM_PLATFORM_SIGNAL_ADDED, NM_PLATFORM_SIGNAL_CHANGED))
        return;
    if (pllink->type != NM_LINK_TYPE_TUN || !nm_streq0(pllink->name, nm_device_get_iface(device)))
        return;

    _LOGT(LOGD_CORE,
          "ovs-wait-link: got platform event \'%s\' for ifindex %d, scheduling idle handler",
          change_type == NM_PLATFORM_SIGNAL_ADDED ? "added" : "changed",
          ifindex);

    /* The handler is invoked by the platform synchronously in the netlink receive loop.
     * We can't perform other platform operations (like bringing the interface up) since
     * the code there is not re-entrant. Schedule an idle handler. */
    nm_clear_g_source_inst(&priv->wait_link.tun_link_idle_source);
    priv->wait_link.tun_link_idle_source =
        nm_g_idle_add_source(_netdev_tun_link_cb_in_idle, device);
    priv->wait_link.tun_ifindex = ifindex;

    return;
}

static gboolean
ovs_interface_is_netdev_datapath(NMDeviceOvsInterface *self)
{
    NMDevice           *device       = NM_DEVICE(self);
    NMActiveConnection *ac           = NULL;
    NMSettingOvsBridge *s_ovs_bridge = NULL;

    ac = NM_ACTIVE_CONNECTION(nm_device_get_act_request(device));
    if (!ac)
        return FALSE;

    /* get ovs-port active-connection */
    ac = nm_active_connection_get_controller(ac);
    if (!ac)
        return FALSE;

    /* get ovs-bridge active-connection */
    ac = nm_active_connection_get_controller(ac);
    if (!ac)
        return FALSE;

    s_ovs_bridge =
        nm_connection_get_setting_ovs_bridge(nm_active_connection_get_applied_connection(ac));
    if (!s_ovs_bridge)
        return FALSE;

    return nm_streq0(nm_setting_ovs_bridge_get_datapath_type(s_ovs_bridge), "netdev");
}

static void
act_stage3_ip_config(NMDevice *device, int addr_family)
{
    NMDeviceOvsInterface        *self = NM_DEVICE_OVS_INTERFACE(device);
    NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);
    bool                         old_wait_link;

    /*
     * When the ovs-interface device enters stage3, it becomes eligible to be attached to
     * its controller (a ovs-port). If also the ovs-bridge is ready, an entry is created
     * in the ovsdb in NMDeviceOvsPort->attach_port().
     * FIXME(l3cfg): we should create the IP ifindex before stage3 start.
     *
     * NMDeviceOvsInterface->act_stage3_ip_config() is supposed to perform device-specific
     * IP configuration on the device. An ovs-interface can be of different types, that
     * require different handling:
     *
     *  - "patch" and "dpdk" interfaces don't have any kernel link associated and thus
     *  NetworkManager completely skips any kind of IP configuration on them, by returning
     *  FALSE to ->ready_for_ip_config().
     *
     *  - "system" interfaces represent other interface types with kernel link (for
     *  example, ethernet, bond, etc.) that get attached to a ovs bridge. Once they are
     *  attached, NetworkManager can start the IP configuration right away.
     *
     *  - "internal" interfaces are virtual interfaces created by openvswitch. Once the
     *  entry is created in the ovsdb, the kernel will create a link for the
     *  interface. When using the system datapath (the default), the link is of type
     *  "openvswitch", while when using the netdev (userspace) datapath, the link is a tun
     *  (tap) one. For both datapath types, we use this method to delay the IP
     *  configuration until the link appears. Note that ready_for_ip_config() returns FALSE
     *  when there is no ifindex, and so all the regular IP methods (static, auto, etc.)
     *  can't proceed.
     */

    if (!_is_internal_interface(device)) {
        nm_device_devip_set_state(device, addr_family, NM_DEVICE_IP_STATE_READY, NULL);
        return;
    }

    /*
    * If a ovs interface has the cloned-mac-address property set, we pass the desired MAC
    * to ovsdb when creating the db entry, and openvswitch will eventually assign it to
    * the interface. Note that usually the link will not have the desired MAC when it's
    * created, and so we need to also monitor link changes to detect when the MAC is
    * ready; only after that we can start IP configuration. Otherwise, the ARP
    * announcements, the DHCP client-id, etc will use the wrong MAC.
    */
    if (!priv->wait_link.cloned_mac_evaluated) {
        nm_assert(!priv->wait_link.cloned_mac);
        nm_device_hw_addr_get_cloned(device,
                                     nm_device_get_applied_connection(device),
                                     FALSE,
                                     &priv->wait_link.cloned_mac,
                                     NULL,
                                     NULL);
        priv->wait_link.cloned_mac_evaluated = TRUE;
    }

    old_wait_link           = priv->wait_link.waiting;
    priv->wait_link.waiting = TRUE;
    if (check_waiting_for_link(device, addr_family == AF_INET ? "stage3-ipv4" : "stage3-ipv6")) {
        nm_device_devip_set_state(device, addr_family, NM_DEVICE_IP_STATE_PENDING, NULL);
        if (nm_device_get_ip_ifindex(device) <= 0 && priv->wait_link.tun_link_signal_id == 0
            && priv->wait_link.tun_ifindex <= 0 && ovs_interface_is_netdev_datapath(self)) {
            priv->wait_link.tun_link_signal_id = g_signal_connect(nm_device_get_platform(device),
                                                                  NM_PLATFORM_SIGNAL_LINK_CHANGED,
                                                                  G_CALLBACK(_netdev_tun_link_cb),
                                                                  self);
        }
        return;
    }

    _LOGT(LOGD_DEVICE,
          "ovs-wait-link: link is ready, IPv%c can proceed",
          nm_utils_addr_family_to_char(addr_family));

    priv->wait_link.waiting = FALSE;
    /*
     * It is possible we detect the link is ready before link_changed event does. It could happen
     * because another stage3_ip_config scheduled happened right after the link is ready.
     * Therefore, if we learn on this function that we are not waiting for the link anymore,
     * we schedule a sync. stage3_ip_config. Otherwise, it could happen that we proceed with
     * IP configuration without the needed allocated resources like DHCP client.
     */
    if (old_wait_link) {
        nm_device_bring_up(device);
        nm_device_activate_schedule_stage3_ip_config(device, TRUE);
        return;
    }
    nm_clear_g_source_inst(&priv->wait_link.tun_link_idle_source);
    nm_clear_g_signal_handler(nm_device_get_platform(device), &priv->wait_link.tun_link_signal_id);

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

    priv->wait_link.tun_ifindex          = -1;
    priv->wait_link.waiting              = FALSE;
    priv->wait_link.cloned_mac_evaluated = FALSE;
    nm_clear_g_free(&priv->wait_link.cloned_mac);
    nm_clear_g_signal_handler(nm_device_get_platform(device), &priv->wait_link.tun_link_signal_id);
    nm_clear_g_source_inst(&priv->wait_link.tun_link_idle_source);
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

    nm_clear_g_signal_handler(nm_device_get_platform(device), &priv->wait_link.tun_link_signal_id);
    nm_clear_g_source_inst(&priv->wait_link.tun_link_idle_source);
    priv->wait_link.tun_ifindex          = -1;
    priv->wait_link.cloned_mac_evaluated = FALSE;
    nm_clear_g_free(&priv->wait_link.cloned_mac);

    /* We want to ensure that the kernel link for this device is removed upon
     * disconnection, so that it will not interfere with later activations of the same
     * device.
     *
     * To do so, we need to be very careful, because unfortunately there is no
     * synchronization mechanism with vswitchd: we only update ovsdb, wait that changes
     * are picked up and we see the effects on the kernel interface (appearing or going
     * away).
     *
     * That means for example that if the ovs interface entered stage3 and the entry was
     * added to the ovsdb, we expect a link to appear. If we disconnect at this point, we
     * delete the entry from the ovsdb. Now we don't know if ovs-vswitchd will see two
     * updates or only one. In other words, we don't know if the interface will appear and
     * go away, or if it will not appear ever. In this situation, the solution is to wait
     * with a timeout.
     */
    data  = g_slice_new(DeactivateData);
    *data = (DeactivateData) {
        .self               = g_object_ref(self),
        .cancellable        = g_object_ref(cancellable),
        .callback           = callback,
        .callback_user_data = callback_user_data,
    };

    if (!priv->wait_link.waiting
        && !nm_platform_link_get_by_ifname(nm_device_get_platform(device),
                                           nm_device_get_iface(device))) {
        _LOGT(LOGD_CORE, "deactivate: link not present, proceeding");
        nm_device_update_from_platform_link(NM_DEVICE(self), NULL);
        nm_utils_invoke_on_idle(cancellable, deactivate_cb_on_idle, data);
        return;
    }

    if (priv->wait_link.waiting) {
        /* Here we have issued an INSERT and a DELETE command for the interface to ovsdb,
         * and must wait with a timeout. */
        data->link_timeout_id = g_timeout_add(6000, deactivate_link_timeout, data);
        _LOGT(LOGD_DEVICE, "deactivate: waiting for link to disappear in 6 seconds");
    } else
        _LOGT(LOGD_DEVICE, "deactivate: waiting for link to disappear");

    priv->wait_link.waiting = FALSE;
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

static gboolean
can_reapply_change(NMDevice   *device,
                   const char *setting_name,
                   NMSetting  *s_old,
                   NMSetting  *s_new,
                   GHashTable *diffs,
                   GError    **error)
{
    NMDeviceClass *device_class = NM_DEVICE_CLASS(nm_device_ovs_interface_parent_class);

    if (NM_IN_STRSET(setting_name,
                     NM_SETTING_OVS_EXTERNAL_IDS_SETTING_NAME,
                     NM_SETTING_OVS_OTHER_CONFIG_SETTING_NAME)) {
        /* TODO: it's currently not possible to reapply those settings on OVS
         * system interfaces because they have type != "ovs-interface" (e.g.
         * "ethernet") */
        return TRUE;
    }

    return device_class->can_reapply_change(device, setting_name, s_old, s_new, diffs, error);
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

    priv->wait_link.tun_ifindex = -1;
}

static void
dispose(GObject *object)
{
    NMDeviceOvsInterface        *self = NM_DEVICE_OVS_INTERFACE(object);
    NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self);

    nm_assert(!priv->wait_link.waiting);
    nm_assert(priv->wait_link.tun_link_signal_id == 0);
    nm_assert(!priv->wait_link.tun_link_idle_source);

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

    device_class->can_auto_connect              = can_auto_connect;
    device_class->can_update_from_platform_link = can_update_from_platform_link;
    device_class->deactivate                    = deactivate;
    device_class->deactivate_async              = deactivate_async;
    device_class->get_type_description          = get_type_description;
    device_class->create_and_realize            = create_and_realize;
    device_class->get_generic_capabilities      = get_generic_capabilities;
    device_class->is_available                  = is_available;
    device_class->check_connection_compatible   = check_connection_compatible;
    device_class->link_changed                  = link_changed;
    device_class->act_stage3_ip_config          = act_stage3_ip_config;
    device_class->ready_for_ip_config           = ready_for_ip_config;
    device_class->can_unmanaged_external_down   = can_unmanaged_external_down;
    device_class->set_platform_mtu              = set_platform_mtu;
    device_class->get_configured_mtu            = nm_device_get_configured_mtu_for_wired;
    device_class->can_reapply_change            = can_reapply_change;
    device_class->reapply_connection            = nm_device_ovs_reapply_connection;
}
