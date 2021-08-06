/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-ppp.h"

#include "nm-l3-config-data.h"
#include "nm-act-request.h"
#include "nm-device-factory.h"
#include "nm-device-private.h"
#include "nm-manager.h"
#include "nm-setting-pppoe.h"
#include "libnm-platform/nm-platform.h"
#include "ppp/nm-ppp-manager.h"
#include "ppp/nm-ppp-manager-call.h"
#include "ppp/nm-ppp-status.h"

#define _NMLOG_DEVICE_TYPE NMDevicePpp
#include "nm-device-logging.h"

/*****************************************************************************/

typedef struct _NMDevicePppPrivate {
    NMPPPManager *        ppp_manager;
    const NML3ConfigData *l3cd_4;
} NMDevicePppPrivate;

struct _NMDevicePpp {
    NMDevice           parent;
    NMDevicePppPrivate _priv;
};

struct _NMDevicePppClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDevicePpp, nm_device_ppp, NM_TYPE_DEVICE)

#define NM_DEVICE_PPP_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDevicePpp, NM_IS_DEVICE_PPP, NMDevice)

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *device)
{
    return NM_DEVICE_CAP_IS_SOFTWARE;
}

static void
ppp_state_changed(NMPPPManager *ppp_manager, NMPPPStatus status, gpointer user_data)
{
    NMDevice *device = NM_DEVICE(user_data);

    switch (status) {
    case NM_PPP_STATUS_DISCONNECT:
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_PPP_DISCONNECT);
        break;
    case NM_PPP_STATUS_DEAD:
        nm_device_state_changed(device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_FAILED);
        break;
    default:
        break;
    }
}

static void
ppp_ifindex_set(NMPPPManager *ppp_manager, int ifindex, const char *iface, gpointer user_data)
{
    NMDevice *    device        = NM_DEVICE(user_data);
    NMDevicePpp * self          = NM_DEVICE_PPP(device);
    gs_free char *old_name      = NULL;
    gs_free_error GError *error = NULL;

    if (!nm_device_take_over_link(device, ifindex, &old_name, &error)) {
        _LOGW(LOGD_DEVICE | LOGD_PPP,
              "could not take control of link %d: %s",
              ifindex,
              error->message);
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
        return;
    }

    if (old_name)
        nm_manager_remove_device(NM_MANAGER_GET, old_name, NM_DEVICE_TYPE_PPP);

    nm_device_activate_schedule_stage3_ip_config(device, FALSE);
}

static void
_ppp_new_config_handle_4(NMDevicePpp *self)
{
    NMDevice *               device               = NM_DEVICE(self);
    NMDevicePppPrivate *     priv                 = NM_DEVICE_PPP_GET_PRIVATE(self);
    nm_auto_unref_l3cd const NML3ConfigData *l3cd = NULL;

    if (!priv->l3cd_4)
        return;

    l3cd = g_steal_pointer(&priv->l3cd_4);

    nm_device_devip_set_state(device, AF_INET, NM_DEVICE_IP_STATE_READY, l3cd);
    nm_device_activate_schedule_stage3_ip_config(device, FALSE);
}

static void
ppp_new_config(NMPPPManager *            ppp_manager,
               int                       addr_family,
               const NML3ConfigData *    l3cd,
               const NMUtilsIPv6IfaceId *iid,
               gpointer                  user_data)
{
    NMDevicePpp *       self = NM_DEVICE_PPP(user_data);
    NMDevicePppPrivate *priv = NM_DEVICE_PPP_GET_PRIVATE(self);

    nm_assert(addr_family == AF_INET);

    _LOGT(LOGD_DEVICE | LOGD_PPP, "received IPv4 config from pppd");
    nm_l3_config_data_reset(&priv->l3cd_4, l3cd);
    _ppp_new_config_handle_4(self);
}

static gboolean
check_connection_compatible(NMDevice *device, NMConnection *connection, GError **error)
{
    NMSettingPppoe *s_pppoe;

    if (!NM_DEVICE_CLASS(nm_device_ppp_parent_class)
             ->check_connection_compatible(device, connection, error))
        return FALSE;

    s_pppoe = nm_connection_get_setting_pppoe(connection);
    if (!s_pppoe || !nm_setting_pppoe_get_parent(s_pppoe)) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                   "the connection doesn't specify a PPPoE parent interface");
        return FALSE;
    }

    return TRUE;
}

static NMActStageReturn
act_stage2_config(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMDevicePpp *       self = NM_DEVICE_PPP(device);
    NMDevicePppPrivate *priv = NM_DEVICE_PPP_GET_PRIVATE(self);
    NMSettingPppoe *    s_pppoe;
    NMActRequest *      req;
    GError *            error = NULL;

    req = nm_device_get_act_request(device);
    g_return_val_if_fail(req, NM_ACT_STAGE_RETURN_FAILURE);

    s_pppoe = nm_device_get_applied_setting(device, NM_TYPE_SETTING_PPPOE);
    g_return_val_if_fail(s_pppoe, NM_ACT_STAGE_RETURN_FAILURE);

    nm_clear_l3cd(&priv->l3cd_4);

    priv->ppp_manager = nm_ppp_manager_create(nm_setting_pppoe_get_parent(s_pppoe), &error);

    if (!priv->ppp_manager
        || !nm_ppp_manager_start(priv->ppp_manager,
                                 req,
                                 nm_setting_pppoe_get_username(s_pppoe),
                                 30,
                                 0,
                                 &error)) {
        _LOGW(LOGD_DEVICE | LOGD_PPP, "PPPoE failed to start: %s", error->message);
        g_error_free(error);

        g_clear_object(&priv->ppp_manager);

        NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_PPP_START_FAILED);
        return NM_ACT_STAGE_RETURN_FAILURE;
    }

    g_signal_connect(priv->ppp_manager,
                     NM_PPP_MANAGER_SIGNAL_STATE_CHANGED,
                     G_CALLBACK(ppp_state_changed),
                     self);
    g_signal_connect(priv->ppp_manager,
                     NM_PPP_MANAGER_SIGNAL_IFINDEX_SET,
                     G_CALLBACK(ppp_ifindex_set),
                     self);
    g_signal_connect(priv->ppp_manager,
                     NM_PPP_MANAGER_SIGNAL_NEW_CONFIG,
                     G_CALLBACK(ppp_new_config),
                     self);
    return NM_ACT_STAGE_RETURN_POSTPONE;
}

static gboolean
_schedule_ip_config_result(gpointer user_data)
{
    gs_unref_object NMDevicePpp *self = user_data;

    _ppp_new_config_handle_4(self);
    return G_SOURCE_REMOVE;
}

static void
act_stage3_ip_config(NMDevice *device, int addr_family)
{
    NMDevicePpp *       self = NM_DEVICE_PPP(device);
    NMDevicePppPrivate *priv = NM_DEVICE_PPP_GET_PRIVATE(self);

    if (!NM_IS_IPv4(addr_family))
        return;

    if (nm_device_devip_get_state(device, addr_family) >= NM_DEVICE_IP_STATE_READY)
        return;

    nm_device_devip_set_state(device, addr_family, NM_DEVICE_IP_STATE_PENDING, NULL);
    if (priv->l3cd_4)
        nm_g_idle_add(_schedule_ip_config_result, g_object_ref(self));
}

static gboolean
create_and_realize(NMDevice *             device,
                   NMConnection *         connection,
                   NMDevice *             parent,
                   const NMPlatformLink **out_plink,
                   GError **              error)
{
    int parent_ifindex;

    if (!parent) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_MISSING_DEPENDENCIES,
                    "PPP devices can not be created without a parent interface");
        return FALSE;
    }

    parent_ifindex = nm_device_get_ifindex(parent);
    g_warn_if_fail(parent_ifindex > 0);

    nm_device_parent_set_ifindex(device, parent_ifindex);

    /* The interface is created later */

    return TRUE;
}

static void
deactivate(NMDevice *device)
{
    NMDevicePpp *       self = NM_DEVICE_PPP(device);
    NMDevicePppPrivate *priv = NM_DEVICE_PPP_GET_PRIVATE(self);

    if (priv->ppp_manager) {
        nm_ppp_manager_stop(priv->ppp_manager, NULL, NULL, NULL);
        g_clear_object(&priv->ppp_manager);
    }

    g_clear_object(&priv->l3cd_4);
}

static void
nm_device_ppp_init(NMDevicePpp *self)
{}

static void
dispose(GObject *object)
{
    NMDevicePpp *       self = NM_DEVICE_PPP(object);
    NMDevicePppPrivate *priv = NM_DEVICE_PPP_GET_PRIVATE(self);

    nm_clear_l3cd(&priv->l3cd_4);

    G_OBJECT_CLASS(nm_device_ppp_parent_class)->dispose(object);
}

static const NMDBusInterfaceInfoExtended interface_info_device_ppp = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(NM_DBUS_INTERFACE_DEVICE_PPP, ),
};

static void
nm_device_ppp_class_init(NMDevicePppClass *klass)
{
    GObjectClass *     object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass *    device_class      = NM_DEVICE_CLASS(klass);

    object_class->dispose = dispose;

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_ppp);

    device_class->connection_type_supported        = NM_SETTING_PPPOE_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_PPPOE_SETTING_NAME;
    device_class->link_types                       = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_PPP);

    device_class->act_stage2_config           = act_stage2_config;
    device_class->act_stage3_ip_config        = act_stage3_ip_config;
    device_class->check_connection_compatible = check_connection_compatible;
    device_class->create_and_realize          = create_and_realize;
    device_class->deactivate                  = deactivate;
    device_class->get_generic_capabilities    = get_generic_capabilities;
}

/*****************************************************************************/

#define NM_TYPE_PPP_DEVICE_FACTORY (nm_ppp_device_factory_get_type())
#define NM_PPP_DEVICE_FACTORY(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_PPP_DEVICE_FACTORY, NMPppDeviceFactory))

static NMDevice *
create_device(NMDeviceFactory *     factory,
              const char *          iface,
              const NMPlatformLink *plink,
              NMConnection *        connection,
              gboolean *            out_ignore)
{
    return g_object_new(NM_TYPE_DEVICE_PPP,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_TYPE_DESC,
                        "Ppp",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_PPP,
                        NM_DEVICE_LINK_TYPE,
                        NM_LINK_TYPE_PPP,
                        NULL);
}

static gboolean
match_connection(NMDeviceFactory *factory, NMConnection *connection)
{
    NMSettingPppoe *s_pppoe;

    s_pppoe = nm_connection_get_setting_pppoe(connection);
    nm_assert(s_pppoe);

    return !!nm_setting_pppoe_get_parent(s_pppoe);
}

static const char *
get_connection_parent(NMDeviceFactory *factory, NMConnection *connection)
{
    NMSettingPppoe *s_pppoe;

    nm_assert(nm_connection_is_type(connection, NM_SETTING_PPPOE_SETTING_NAME));

    s_pppoe = nm_connection_get_setting_pppoe(connection);
    nm_assert(s_pppoe);

    return nm_setting_pppoe_get_parent(s_pppoe);
}

static char *
get_connection_iface(NMDeviceFactory *factory, NMConnection *connection, const char *parent_iface)
{
    nm_assert(nm_connection_is_type(connection, NM_SETTING_PPPOE_SETTING_NAME));

    if (!parent_iface)
        return NULL;

    return g_strdup(nm_connection_get_interface_name(connection));
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL(
    PPP,
    Ppp,
    ppp,
    NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(NM_LINK_TYPE_PPP)
        NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_PPPOE_SETTING_NAME),
    factory_class->get_connection_parent = get_connection_parent;
    factory_class->get_connection_iface  = get_connection_iface;
    factory_class->create_device         = create_device;
    factory_class->match_connection      = match_connection;);
