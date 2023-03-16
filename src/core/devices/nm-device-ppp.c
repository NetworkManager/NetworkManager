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
#include "ppp/nm-ppp-mgr.h"

#define _NMLOG_DEVICE_TYPE NMDevicePpp
#include "nm-device-logging.h"

/*****************************************************************************/

typedef struct _NMDevicePppPrivate {
    NMPppMgr *ppp_mgr;
    union {
        struct {
            NML3CfgBlockHandle *l3cfg_block_handle_6;
            NML3CfgBlockHandle *l3cfg_block_handle_4;
        };
        NML3CfgBlockHandle *l3cfg_block_handle_x[2];
    };
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

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *device)
{
    return NM_DEVICE_CAP_IS_SOFTWARE;
}

/*****************************************************************************/

static void
_ppp_mgr_cleanup(NMDevicePpp *self)
{
    NMDevicePppPrivate *priv = NM_DEVICE_PPP_GET_PRIVATE(self);

    nm_clear_pointer(&priv->ppp_mgr, nm_ppp_mgr_destroy);
}

static void
_ppp_mgr_stage3_maybe_ready(NMDevicePpp *self)
{
    NMDevice           *device = NM_DEVICE(self);
    NMDevicePppPrivate *priv   = NM_DEVICE_PPP_GET_PRIVATE(self);
    int                 IS_IPv4;

    for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
        const int             addr_family = IS_IPv4 ? AF_INET : AF_INET6;
        const NMPppMgrIPData *ip_data;

        ip_data = nm_ppp_mgr_get_ip_data(priv->ppp_mgr, addr_family);
        if (ip_data->ip_received) {
            nm_clear_pointer(&priv->l3cfg_block_handle_x[IS_IPv4], nm_l3cfg_unblock_obj_pruning);
            nm_device_devip_set_state(device, addr_family, NM_DEVICE_IP_STATE_READY, ip_data->l3cd);
        }
    }

    if (nm_ppp_mgr_get_state(priv->ppp_mgr) >= NM_PPP_MGR_STATE_HAVE_IP_CONFIG)
        nm_device_devip_set_state(device, AF_UNSPEC, NM_DEVICE_IP_STATE_READY, NULL);
}

static void
_ppp_mgr_callback(NMPppMgr *ppp_mgr, const NMPppMgrCallbackData *callback_data, gpointer user_data)
{
    NMDevicePpp        *self   = NM_DEVICE_PPP(user_data);
    NMDevice           *device = NM_DEVICE(self);
    NMDevicePppPrivate *priv   = NM_DEVICE_PPP_GET_PRIVATE(self);
    NMDeviceState       device_state;

    if (callback_data->callback_type != NM_PPP_MGR_CALLBACK_TYPE_STATE_CHANGED)
        return;

    device_state = nm_device_get_state(device);

    if (callback_data->data.state >= _NM_PPP_MGR_STATE_FAILED_START) {
        if (device_state <= NM_DEVICE_STATE_ACTIVATED)
            nm_device_state_changed(device, NM_DEVICE_STATE_FAILED, callback_data->data.reason);
        return;
    }

    if (device_state < NM_DEVICE_STATE_IP_CONFIG) {
        if (callback_data->data.state >= NM_PPP_MGR_STATE_HAVE_IFINDEX) {
            gs_free char         *old_name = NULL;
            gs_free_error GError *error    = NULL;

            if (!nm_device_take_over_link(device, callback_data->data.ifindex, &old_name, &error)) {
                _LOGW(LOGD_DEVICE | LOGD_PPP,
                      "could not take control of link %d: %s",
                      callback_data->data.ifindex,
                      error->message);
                _ppp_mgr_cleanup(self);
                nm_device_state_changed(device,
                                        NM_DEVICE_STATE_FAILED,
                                        NM_DEVICE_STATE_REASON_CONFIG_FAILED);
                return;
            }

            /* pppd also tries to configure addresses by itself through some
             * ioctls. If we remove between those calls an address that was added,
             * pppd fails and quits. Temporarily block the removal of addresses
             * and routes. */
            if (!priv->l3cfg_block_handle_4) {
                priv->l3cfg_block_handle_4 =
                    nm_l3cfg_block_obj_pruning(nm_device_get_l3cfg(device), AF_INET);
            }
            if (!priv->l3cfg_block_handle_6) {
                priv->l3cfg_block_handle_6 =
                    nm_l3cfg_block_obj_pruning(nm_device_get_l3cfg(device), AF_INET6);
            }

            if (old_name)
                nm_manager_remove_device(NM_MANAGER_GET, old_name, NM_DEVICE_TYPE_PPP);

            nm_device_activate_schedule_stage2_device_config(device, FALSE);
        }
        return;
    }

    _ppp_mgr_stage3_maybe_ready(self);
}

/*****************************************************************************/

static gboolean
check_connection_compatible(NMDevice     *device,
                            NMConnection *connection,
                            gboolean      check_properties,
                            GError      **error)
{
    NMSettingPppoe *s_pppoe;

    if (!NM_DEVICE_CLASS(nm_device_ppp_parent_class)
             ->check_connection_compatible(device, connection, check_properties, error))
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
    NMDevicePpp        *self = NM_DEVICE_PPP(device);
    NMDevicePppPrivate *priv = NM_DEVICE_PPP_GET_PRIVATE(self);
    NMSettingPppoe     *s_pppoe;
    NMActRequest       *req;

    if (!priv->ppp_mgr) {
        gs_free_error GError *error = NULL;

        req = nm_device_get_act_request(device);
        g_return_val_if_fail(req, NM_ACT_STAGE_RETURN_FAILURE);

        s_pppoe = nm_device_get_applied_setting(device, NM_TYPE_SETTING_PPPOE);
        g_return_val_if_fail(s_pppoe, NM_ACT_STAGE_RETURN_FAILURE);

        priv->ppp_mgr = nm_ppp_mgr_start(&((const NMPppMgrConfig){
                                             .netns        = nm_device_get_netns(device),
                                             .parent_iface = nm_setting_pppoe_get_parent(s_pppoe),
                                             .callback     = _ppp_mgr_callback,
                                             .user_data    = self,
                                             .act_req      = req,
                                             .ppp_username = nm_setting_pppoe_get_username(s_pppoe),
                                             .timeout_secs = 30,
                                             .baud_override = 0,
                                         }),
                                         &error);
        if (!priv->ppp_mgr) {
            _LOGW(LOGD_DEVICE | LOGD_PPP, "PPPoE failed to start: %s", error->message);
            *out_failure_reason = NM_DEVICE_STATE_REASON_PPP_START_FAILED;
            return NM_ACT_STAGE_RETURN_FAILURE;
        }

        return NM_ACT_STAGE_RETURN_POSTPONE;
    }

    if (nm_ppp_mgr_get_state(priv->ppp_mgr) < NM_PPP_MGR_STATE_HAVE_IFINDEX)
        return NM_ACT_STAGE_RETURN_POSTPONE;

    return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
act_stage3_ip_config(NMDevice *device, int addr_family)
{
    NMDevicePpp        *self = NM_DEVICE_PPP(device);
    NMDevicePppPrivate *priv = NM_DEVICE_PPP_GET_PRIVATE(self);
    NMPppMgrState       ppp_state;

    if (!priv->ppp_mgr) {
        nm_assert_not_reached();
        return;
    }

    ppp_state = nm_ppp_mgr_get_state(priv->ppp_mgr);

    nm_assert(NM_IN_SET(ppp_state, NM_PPP_MGR_STATE_HAVE_IFINDEX, NM_PPP_MGR_STATE_HAVE_IP_CONFIG));

    if (ppp_state < NM_PPP_MGR_STATE_HAVE_IP_CONFIG) {
        nm_device_devip_set_state(device, AF_UNSPEC, NM_DEVICE_IP_STATE_PENDING, NULL);
        return;
    }

    _ppp_mgr_stage3_maybe_ready(self);
}

static const char *
get_ip_method_auto(NMDevice *device, int addr_family)
{
    if (NM_IS_IPv4(addr_family)) {
        /* We cannot do DHCPv4 on a PPP link, instead we get "auto" IP addresses
         * by pppd. Return "manual" here, which has the suitable effect to a
         * (zero) manual addresses in addition. */
        return NM_SETTING_IP6_CONFIG_METHOD_MANUAL;
    }

    /* We get a interface identifier via IPV6CP, used to construct a link-local
     * address. Method auto means autoconf6 as usual.*/
    return NM_SETTING_IP6_CONFIG_METHOD_AUTO;
}

static gboolean
create_and_realize(NMDevice              *device,
                   NMConnection          *connection,
                   NMDevice              *parent,
                   const NMPlatformLink **out_plink,
                   GError               **error)
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
    NMDevicePpp        *self = NM_DEVICE_PPP(device);
    NMDevicePppPrivate *priv = NM_DEVICE_PPP_GET_PRIVATE(self);

    nm_clear_pointer(&priv->l3cfg_block_handle_4, nm_l3cfg_unblock_obj_pruning);
    nm_clear_pointer(&priv->l3cfg_block_handle_6, nm_l3cfg_unblock_obj_pruning);

    _ppp_mgr_cleanup(self);
}

/*****************************************************************************/

static void
nm_device_ppp_init(NMDevicePpp *self)
{}

static void
dispose(GObject *object)
{
    NMDevicePpp *self = NM_DEVICE_PPP(object);

    _ppp_mgr_cleanup(self);

    G_OBJECT_CLASS(nm_device_ppp_parent_class)->dispose(object);
}

static const NMDBusInterfaceInfoExtended interface_info_device_ppp = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(NM_DBUS_INTERFACE_DEVICE_PPP, ),
};

static void
nm_device_ppp_class_init(NMDevicePppClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    object_class->dispose = dispose;

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_ppp);

    device_class->connection_type_supported        = NM_SETTING_PPPOE_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_PPPOE_SETTING_NAME;
    device_class->link_types                       = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_PPP);

    device_class->act_stage2_config           = act_stage2_config;
    device_class->act_stage3_ip_config        = act_stage3_ip_config;
    device_class->get_ip_method_auto          = get_ip_method_auto;
    device_class->check_connection_compatible = check_connection_compatible;
    device_class->create_and_realize          = create_and_realize;
    device_class->deactivate                  = deactivate;
    device_class->get_generic_capabilities    = get_generic_capabilities;
}

/*****************************************************************************/

#define NM_TYPE_PPP_DEVICE_FACTORY (nm_ppp_device_factory_get_type())
#define NM_PPP_DEVICE_FACTORY(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_PPP_DEVICE_FACTORY, NMPppDeviceFactory))

static NMDevice *
create_device(NMDeviceFactory      *factory,
              const char           *iface,
              const NMPlatformLink *plink,
              NMConnection         *connection,
              gboolean             *out_ignore)
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
