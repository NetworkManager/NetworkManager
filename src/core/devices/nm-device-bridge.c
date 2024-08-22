/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2011 - 2015 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-bridge.h"

#include <stdlib.h>
#include <linux/if_ether.h>

#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-platform/nm-platform-utils.h"
#include "nm-device-factory.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "libnm-core-intern/nm-core-internal.h"

#define _NMLOG_DEVICE_TYPE NMDeviceBridge
#include "nm-device-logging.h"

/*****************************************************************************/

enum _NMBtCbState {
    _NM_BT_CB_STATE_NONE    = 0, /* Registration not done    */
    _NM_BT_CB_STATE_WAIT    = 1, /* Waiting for the callback */
    _NM_BT_CB_STATE_SUCCESS = 2, /* Callback succeeded       */
};

struct _NMDeviceBridge {
    NMDevice      parent;
    GCancellable *bt_cancellable;
    bool          vlan_configured : 1;
    unsigned      bt_cb_state : 2;
};

struct _NMDeviceBridgeClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceBridge, nm_device_bridge, NM_TYPE_DEVICE)

/*****************************************************************************/

const NMBtVTableNetworkServer *nm_bt_vtable_network_server = NULL;

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *dev)
{
    return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
check_connection_available(NMDevice                      *device,
                           NMConnection                  *connection,
                           NMDeviceCheckConAvailableFlags flags,
                           const char                    *specific_object,
                           GError                       **error)
{
    NMDeviceBridge     *self = NM_DEVICE_BRIDGE(device);
    NMSettingBluetooth *s_bt;

    if (!NM_DEVICE_CLASS(nm_device_bridge_parent_class)
             ->check_connection_available(device, connection, flags, specific_object, error))
        return FALSE;

    s_bt = _nm_connection_get_setting_bluetooth_for_nap(connection);
    if (s_bt) {
        const char *bdaddr;

        if (!nm_bt_vtable_network_server) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "bluetooth plugin not available to activate NAP profile");
            return FALSE;
        }

        bdaddr = nm_setting_bluetooth_get_bdaddr(s_bt);
        if (!nm_bt_vtable_network_server->is_available(
                nm_bt_vtable_network_server,
                bdaddr,
                (self->bt_cancellable || self->bt_cb_state != _NM_BT_CB_STATE_NONE) ? device
                                                                                    : NULL)) {
            if (bdaddr)
                nm_utils_error_set(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "no suitable NAP device \"%s\" available",
                                   bdaddr);
            else
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                           "no suitable NAP device available");
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
check_connection_compatible(NMDevice     *device,
                            NMConnection *connection,
                            gboolean      check_properties,
                            GError      **error)
{
    NMSettingBridge *s_bridge;
    const char      *mac_address;

    if (!NM_DEVICE_CLASS(nm_device_bridge_parent_class)
             ->check_connection_compatible(device, connection, check_properties, error))
        return FALSE;

    if (nm_connection_is_type(connection, NM_SETTING_BLUETOOTH_SETTING_NAME)
        && _nm_connection_get_setting_bluetooth_for_nap(connection)) {
        s_bridge = nm_connection_get_setting_bridge(connection);
        if (!s_bridge) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "missing bridge setting for bluetooth NAP profile");
            return FALSE;
        }

        /* a bluetooth NAP connection is handled by the bridge.
         *
         * Proceed... */
    } else {
        s_bridge =
            _nm_connection_check_main_setting(connection, NM_SETTING_BRIDGE_SETTING_NAME, error);
        if (!s_bridge)
            return FALSE;
    }

    mac_address = nm_setting_bridge_get_mac_address(s_bridge);
    if (mac_address && nm_device_is_real(device)) {
        const char *hw_addr;

        hw_addr = nm_device_get_hw_address(device);
        if (!hw_addr || !nm_utils_hwaddr_matches(hw_addr, -1, mac_address, -1)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "mac address mismatches");
            return FALSE;
        }
    }

    return TRUE;
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
                              NM_SETTING_BRIDGE_SETTING_NAME,
                              existing_connections,
                              NULL,
                              _("Bridge connection"),
                              "bridge",
                              NULL,
                              TRUE);

    _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_BRIDGE);

    return TRUE;
}

static void
to_sysfs_group_address_sys(const char *group_address, NMEtherAddr *out_addr)
{
    if (group_address == NULL) {
        *out_addr = NM_ETHER_ADDR_INIT(NM_BRIDGE_GROUP_ADDRESS_DEF_BIN);
        return;
    }
    if (!nm_utils_hwaddr_aton(group_address, out_addr, ETH_ALEN))
        nm_assert_not_reached();
}

static void
from_sysfs_group_address(const char *value, GValue *out)
{
    if (!nm_utils_hwaddr_matches(value, -1, NM_BRIDGE_GROUP_ADDRESS_DEF_STR, -1))
        g_value_set_string(out, value);
}

static const char *
to_sysfs_group_address(GValue *value)
{
    return g_value_get_string(value) ?: NM_BRIDGE_GROUP_ADDRESS_DEF_STR;
}

static int
to_sysfs_vlan_protocol_sys(const char *value)
{
    if (nm_streq0(value, "802.1ad"))
        return ETH_P_8021AD;

    return ETH_P_8021Q;
}

static void
from_sysfs_vlan_protocol(const char *value, GValue *out)
{
    switch (_nm_utils_ascii_str_to_uint64(value, 16, 0, G_MAXUINT, -1)) {
    case ETH_P_8021Q:
        /* default value */
        break;
    case ETH_P_8021AD:
        g_value_set_string(out, "802.1ad");
        break;
    }
}

static const char *
to_sysfs_vlan_protocol(GValue *value)
{
    const char *str = g_value_get_string(value);

    if (nm_streq0(str, "802.1ad")) {
        G_STATIC_ASSERT_EXPR(ETH_P_8021AD == 0x88A8);
        return "0x88A8";
    }

    G_STATIC_ASSERT_EXPR(ETH_P_8021Q == 0x8100);
    return "0x8100";
}

static int
to_sysfs_multicast_router_sys(const char *value)
{
    if (nm_streq0(value, "disabled"))
        return 0;
    if (nm_streq0(value, "auto"))
        return 1;
    if (nm_streq0(value, "enabled"))
        return 2;

    return 1;
}

static const char *
to_sysfs_multicast_router(GValue *value)
{
    const char *str = g_value_get_string(value);

    if (nm_streq0(str, "disabled"))
        return "0";
    if (nm_streq0(str, "auto"))
        return "1";
    if (nm_streq0(str, "enabled"))
        return "2";

    return "1";
}

static void
from_sysfs_multicast_router(const char *value, GValue *out)
{
    switch (_nm_utils_ascii_str_to_uint64(value, 10, 0, G_MAXUINT, -1)) {
    case 0:
        g_value_set_string(out, "disabled");
        break;
    case 2:
        g_value_set_string(out, "enabled");
        break;
    case 1:
    default:
        /* default value */
        break;
    }
}

/*****************************************************************************/
#define _DEFAULT_IF_ZERO(val, def_val)    \
    ({                                    \
        typeof(val) _val     = (val);     \
        typeof(val) _def_val = (def_val); \
                                          \
        (_val == 0) ? _def_val : _val;    \
    })

typedef struct {
    const char *name;
    const char *sysname;
    const char *(*to_sysfs)(GValue *value);
    void (*from_sysfs)(const char *value, GValue *out);
    guint64 nm_min;
    guint64 nm_max;
    guint64 nm_default;
    bool    default_if_zero;
    bool    user_hz_compensate;
    bool    only_with_stp;
} Option;

#define OPTION(_name, _sysname, ...) \
    {.name    = ""_name              \
                "",                  \
     .sysname = ""_sysname           \
                "",                  \
     __VA_ARGS__}

#define OPTION_TYPE_INT(min, max, def) .nm_min = (min), .nm_max = (max), .nm_default = (def)

#define OPTION_TYPE_BOOL(def) OPTION_TYPE_INT(FALSE, TRUE, def)

#define OPTION_TYPE_TOFROM(to, fro) .to_sysfs = (to), .from_sysfs = (fro)

static const Option controller_options[] = {
    OPTION(NM_SETTING_BRIDGE_STP, /* this must stay as the first item */
           "stp_state",
           OPTION_TYPE_BOOL(NM_BRIDGE_STP_DEF), ),
    OPTION(NM_SETTING_BRIDGE_PRIORITY,
           "priority",
           OPTION_TYPE_INT(NM_BRIDGE_PRIORITY_MIN, NM_BRIDGE_PRIORITY_MAX, NM_BRIDGE_PRIORITY_DEF),
           .default_if_zero = TRUE,
           .only_with_stp   = TRUE, ),
    OPTION(NM_SETTING_BRIDGE_FORWARD_DELAY,
           "forward_delay",
           OPTION_TYPE_INT(NM_BRIDGE_FORWARD_DELAY_MIN,
                           NM_BRIDGE_FORWARD_DELAY_MAX,
                           NM_BRIDGE_FORWARD_DELAY_DEF),
           .default_if_zero    = TRUE,
           .user_hz_compensate = TRUE,
           .only_with_stp      = TRUE, ),
    OPTION(NM_SETTING_BRIDGE_HELLO_TIME,
           "hello_time",
           OPTION_TYPE_INT(NM_BRIDGE_HELLO_TIME_MIN,
                           NM_BRIDGE_HELLO_TIME_MAX,
                           NM_BRIDGE_HELLO_TIME_DEF),
           .default_if_zero    = TRUE,
           .user_hz_compensate = TRUE,
           .only_with_stp      = TRUE, ),
    OPTION(NM_SETTING_BRIDGE_MAX_AGE,
           "max_age",
           OPTION_TYPE_INT(NM_BRIDGE_MAX_AGE_MIN, NM_BRIDGE_MAX_AGE_MAX, NM_BRIDGE_MAX_AGE_DEF),
           .default_if_zero    = TRUE,
           .user_hz_compensate = TRUE,
           .only_with_stp      = TRUE, ),
    OPTION(NM_SETTING_BRIDGE_AGEING_TIME,
           "ageing_time",
           OPTION_TYPE_INT(NM_BRIDGE_AGEING_TIME_MIN,
                           NM_BRIDGE_AGEING_TIME_MAX,
                           NM_BRIDGE_AGEING_TIME_DEF),
           .user_hz_compensate = TRUE, ),
    OPTION(NM_SETTING_BRIDGE_GROUP_FORWARD_MASK, "group_fwd_mask", OPTION_TYPE_INT(0, 0xFFFF, 0), ),
    OPTION(NM_SETTING_BRIDGE_MULTICAST_HASH_MAX,
           "hash_max",
           OPTION_TYPE_INT(NM_BRIDGE_MULTICAST_HASH_MAX_MIN,
                           NM_BRIDGE_MULTICAST_HASH_MAX_MAX,
                           NM_BRIDGE_MULTICAST_HASH_MAX_DEF), ),
    OPTION(NM_SETTING_BRIDGE_MULTICAST_LAST_MEMBER_COUNT,
           "multicast_last_member_count",
           OPTION_TYPE_INT(NM_BRIDGE_MULTICAST_LAST_MEMBER_COUNT_MIN,
                           NM_BRIDGE_MULTICAST_LAST_MEMBER_COUNT_MAX,
                           NM_BRIDGE_MULTICAST_LAST_MEMBER_COUNT_DEF), ),
    OPTION(NM_SETTING_BRIDGE_MULTICAST_LAST_MEMBER_INTERVAL,
           "multicast_last_member_interval",
           OPTION_TYPE_INT(NM_BRIDGE_MULTICAST_LAST_MEMBER_INTERVAL_MIN,
                           NM_BRIDGE_MULTICAST_LAST_MEMBER_INTERVAL_MAX,
                           NM_BRIDGE_MULTICAST_LAST_MEMBER_INTERVAL_DEF), ),
    OPTION(NM_SETTING_BRIDGE_MULTICAST_MEMBERSHIP_INTERVAL,
           "multicast_membership_interval",
           OPTION_TYPE_INT(NM_BRIDGE_MULTICAST_MEMBERSHIP_INTERVAL_MIN,
                           NM_BRIDGE_MULTICAST_MEMBERSHIP_INTERVAL_MAX,
                           NM_BRIDGE_MULTICAST_MEMBERSHIP_INTERVAL_DEF), ),
    OPTION(NM_SETTING_BRIDGE_MULTICAST_QUERIER,
           "multicast_querier",
           OPTION_TYPE_BOOL(NM_BRIDGE_MULTICAST_QUERIER_DEF), ),
    OPTION(NM_SETTING_BRIDGE_MULTICAST_QUERIER_INTERVAL,
           "multicast_querier_interval",
           OPTION_TYPE_INT(NM_BRIDGE_MULTICAST_QUERIER_INTERVAL_MIN,
                           NM_BRIDGE_MULTICAST_QUERIER_INTERVAL_MAX,
                           NM_BRIDGE_MULTICAST_QUERIER_INTERVAL_DEF), ),
    OPTION(NM_SETTING_BRIDGE_MULTICAST_QUERY_INTERVAL,
           "multicast_query_interval",
           OPTION_TYPE_INT(NM_BRIDGE_MULTICAST_QUERY_INTERVAL_MIN,
                           NM_BRIDGE_MULTICAST_QUERY_INTERVAL_MAX,
                           NM_BRIDGE_MULTICAST_QUERY_INTERVAL_DEF), ),
    OPTION(NM_SETTING_BRIDGE_MULTICAST_QUERY_RESPONSE_INTERVAL,
           "multicast_query_response_interval",
           OPTION_TYPE_INT(NM_BRIDGE_MULTICAST_QUERY_RESPONSE_INTERVAL_MIN,
                           NM_BRIDGE_MULTICAST_QUERY_RESPONSE_INTERVAL_MAX,
                           NM_BRIDGE_MULTICAST_QUERY_RESPONSE_INTERVAL_DEF), ),
    OPTION(NM_SETTING_BRIDGE_MULTICAST_QUERY_USE_IFADDR,
           "multicast_query_use_ifaddr",
           OPTION_TYPE_BOOL(NM_BRIDGE_MULTICAST_QUERY_USE_IFADDR_DEF), ),
    OPTION(NM_SETTING_BRIDGE_MULTICAST_SNOOPING,
           "multicast_snooping",
           OPTION_TYPE_BOOL(NM_BRIDGE_MULTICAST_SNOOPING_DEF), ),
    OPTION(NM_SETTING_BRIDGE_MULTICAST_ROUTER,
           "multicast_router",
           OPTION_TYPE_TOFROM(to_sysfs_multicast_router, from_sysfs_multicast_router), ),
    OPTION(NM_SETTING_BRIDGE_MULTICAST_STARTUP_QUERY_COUNT,
           "multicast_startup_query_count",
           OPTION_TYPE_INT(NM_BRIDGE_MULTICAST_STARTUP_QUERY_COUNT_MIN,
                           NM_BRIDGE_MULTICAST_STARTUP_QUERY_COUNT_MAX,
                           NM_BRIDGE_MULTICAST_STARTUP_QUERY_COUNT_DEF), ),
    OPTION(NM_SETTING_BRIDGE_MULTICAST_STARTUP_QUERY_INTERVAL,
           "multicast_startup_query_interval",
           OPTION_TYPE_INT(NM_BRIDGE_MULTICAST_STARTUP_QUERY_INTERVAL_MIN,
                           NM_BRIDGE_MULTICAST_STARTUP_QUERY_INTERVAL_MAX,
                           NM_BRIDGE_MULTICAST_STARTUP_QUERY_INTERVAL_DEF), ),
    OPTION(NM_SETTING_BRIDGE_GROUP_ADDRESS,
           "group_addr",
           OPTION_TYPE_TOFROM(to_sysfs_group_address, from_sysfs_group_address), ),
    OPTION(NM_SETTING_BRIDGE_VLAN_PROTOCOL,
           "vlan_protocol",
           OPTION_TYPE_TOFROM(to_sysfs_vlan_protocol, from_sysfs_vlan_protocol), ),
    OPTION(NM_SETTING_BRIDGE_VLAN_STATS_ENABLED,
           "vlan_stats_enabled",
           OPTION_TYPE_BOOL(NM_BRIDGE_VLAN_STATS_ENABLED_DEF)),
    {
        0,
    }};

static NMPlatformBridgeVlan *
setting_vlans_to_platform(GPtrArray *array, guint *out_len)
{
    NMPlatformBridgeVlan *arr;
    guint                 i;

    if (!array || !array->len) {
        *out_len = 0;
        return NULL;
    }

    arr = g_new(NMPlatformBridgeVlan, array->len);

    for (i = 0; i < array->len; i++) {
        NMBridgeVlan *vlan = array->pdata[i];
        guint16       vid_start, vid_end;

        nm_bridge_vlan_get_vid_range(vlan, &vid_start, &vid_end);

        arr[i] = (NMPlatformBridgeVlan){
            .vid_start = vid_start,
            .vid_end   = vid_end,
            .pvid      = nm_bridge_vlan_is_pvid(vlan),
            .untagged  = nm_bridge_vlan_is_untagged(vlan),
        };
    }

    *out_len = array->len;
    return arr;
}

static void
commit_port_options(NMDevice *device, NMSettingBridgePort *setting)
{
    guint32 path_cost, priority;

    path_cost = nm_setting_bridge_port_get_path_cost(setting);
    if (path_cost == 0)
        path_cost = NM_BRIDGE_PORT_PATH_COST_DEF;

    priority = nm_setting_bridge_port_get_priority(setting);
    if (priority == 0)
        priority = NM_BRIDGE_PORT_PRIORITY_DEF;

    nm_platform_link_change(nm_device_get_platform(device),
                            nm_device_get_ifindex(device),
                            NULL,
                            NULL,
                            &((NMPlatformLinkBridgePort){
                                .path_cost = path_cost,
                                .priority  = priority,
                                .hairpin   = nm_setting_bridge_port_get_hairpin_mode(setting),
                            }),
                            0);
}

static void
update_connection(NMDevice *device, NMConnection *connection)
{
    NMDeviceBridge  *self     = NM_DEVICE_BRIDGE(device);
    NMSettingBridge *s_bridge = _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_BRIDGE);
    int              ifindex  = nm_device_get_ifindex(device);
    const Option    *option;
    gs_free char    *stp = NULL;
    int              stp_value;

    option = controller_options;
    nm_assert(nm_streq(option->sysname, "stp_state"));

    stp = nm_platform_sysctl_controller_get_option(nm_device_get_platform(device),
                                                   ifindex,
                                                   option->sysname);
    stp_value =
        _nm_utils_ascii_str_to_int64(stp, 10, option->nm_min, option->nm_max, option->nm_default);
    g_object_set(s_bridge, option->name, stp_value, NULL);
    option++;

    for (; option->name; option++) {
        nm_auto_unset_gvalue GValue value = G_VALUE_INIT;
        gs_free char               *str   = NULL;
        GParamSpec                 *pspec;

        str   = nm_platform_sysctl_controller_get_option(nm_device_get_platform(device),
                                                       ifindex,
                                                       option->sysname);
        pspec = g_object_class_find_property(G_OBJECT_GET_CLASS(s_bridge), option->name);

        if (!stp_value && option->only_with_stp)
            continue;

        if (!str) {
            _LOGW(LOGD_BRIDGE, "failed to read bridge setting '%s'", option->sysname);
            continue;
        }

        g_value_init(&value, G_PARAM_SPEC_VALUE_TYPE(pspec));

        if (option->from_sysfs) {
            option->from_sysfs(str, &value);
            goto out;
        }

        switch (pspec->value_type) {
        case G_TYPE_UINT64:
        case G_TYPE_UINT:
        {
            guint64 uvalue;

            /* See comments in set_sysfs_uint() about centiseconds. */
            if (option->user_hz_compensate) {
                uvalue = _nm_utils_ascii_str_to_int64(str,
                                                      10,
                                                      option->nm_min * 100,
                                                      option->nm_max * 100,
                                                      option->nm_default * 100);
                uvalue /= 100;
            } else {
                uvalue = _nm_utils_ascii_str_to_uint64(str,
                                                       10,
                                                       option->nm_min,
                                                       option->nm_max,
                                                       option->nm_default);
            }

            if (pspec->value_type == G_TYPE_UINT64)
                g_value_set_uint64(&value, uvalue);
            else
                g_value_set_uint(&value, (guint) uvalue);
        } break;
        case G_TYPE_BOOLEAN:
        {
            gboolean bvalue;

            bvalue = _nm_utils_ascii_str_to_int64(str,
                                                  10,
                                                  option->nm_min,
                                                  option->nm_max,
                                                  option->nm_default);
            g_value_set_boolean(&value, bvalue);
        } break;
        case G_TYPE_STRING:
            g_value_set_string(&value, str);
            break;
        default:
            nm_assert_not_reached();
            break;
        }

out:
        g_object_set_property(G_OBJECT(s_bridge), option->name, &value);
    }
}

static gboolean
controller_update_port_connection(NMDevice     *device,
                                  NMDevice     *port,
                                  NMConnection *connection,
                                  GError      **error)
{
    NMSettingConnection  *s_con;
    NMSettingBridgePort  *s_port;
    int                   ifindex_port       = nm_device_get_ifindex(port);
    NMConnection         *applied_connection = nm_device_get_applied_connection(device);
    const NMPlatformLink *pllink;

    g_return_val_if_fail(ifindex_port > 0, FALSE);

    s_con  = nm_connection_get_setting_connection(connection);
    s_port = _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_BRIDGE_PORT);
    pllink = nm_platform_link_get(nm_device_get_platform(port), ifindex_port);

    if (pllink && pllink->port_kind == NM_PORT_KIND_BRIDGE) {
        g_object_set(s_port,
                     NM_SETTING_BRIDGE_PORT_PATH_COST,
                     pllink->port_data.bridge.path_cost,
                     NULL);
        g_object_set(s_port,
                     NM_SETTING_BRIDGE_PORT_PRIORITY,
                     pllink->port_data.bridge.priority,
                     NULL);
        g_object_set(s_port,
                     NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE,
                     pllink->port_data.bridge.hairpin,
                     NULL);
    }

    g_object_set(s_con,
                 NM_SETTING_CONNECTION_CONTROLLER,
                 nm_connection_get_uuid(applied_connection),
                 NM_SETTING_CONNECTION_PORT_TYPE,
                 NM_SETTING_BRIDGE_SETTING_NAME,
                 NULL);
    return TRUE;
}

static gboolean
is_bridge_pvid_changed(NMDevice *device, NMSettingBridge *s_bridge)
{
    int                        ifindex = nm_device_get_ifindex(device);
    const NMPlatformLnkBridge *nmp_link_br;
    NMPlatform                *platform = nm_device_get_platform(device);
    bool    desired_vlan_filtering      = nm_setting_bridge_get_vlan_filtering(s_bridge);
    guint16 desired_pvid                = nm_setting_bridge_get_vlan_default_pvid(s_bridge);

    nm_platform_link_refresh(platform, ifindex);
    nmp_link_br = nm_platform_link_get_lnk_bridge(platform, ifindex, NULL);

    if (nmp_link_br) {
        return desired_vlan_filtering != nmp_link_br->vlan_filtering
               || desired_pvid != nmp_link_br->default_pvid;
    } else {
        return TRUE;
    }
}

static gboolean
bridge_set_vlan_options(NMDevice *device, NMSettingBridge *s_bridge, gboolean is_reapply)
{
    NMDeviceBridge               *self = NM_DEVICE_BRIDGE(device);
    gconstpointer                 hwaddr;
    size_t                        length;
    gboolean                      enabled;
    guint16                       pvid;
    NMPlatform                   *plat;
    int                           ifindex;
    gs_unref_ptrarray GPtrArray  *vlans      = NULL;
    gs_free NMPlatformBridgeVlan *plat_vlans = NULL;
    guint                         num_vlans;

    if (self->vlan_configured)
        return TRUE;

    plat    = nm_device_get_platform(device);
    ifindex = nm_device_get_ifindex(device);
    enabled = nm_setting_bridge_get_vlan_filtering(s_bridge);

    if (!enabled) {
        nm_platform_link_set_bridge_info(
            plat,
            ifindex,
            &((NMPlatformLinkSetBridgeInfoData){.vlan_filtering_has    = TRUE,
                                                .vlan_filtering_val    = FALSE,
                                                .vlan_default_pvid_has = TRUE,
                                                .vlan_default_pvid_val = 1}));
        nm_platform_link_set_bridge_vlans(plat, ifindex, FALSE, NULL, 0);
        return TRUE;
    }

    hwaddr = nm_platform_link_get_address(plat, ifindex, &length);
    g_return_val_if_fail(length == ETH_ALEN, FALSE);
    if (nm_utils_hwaddr_matches(hwaddr, length, &nm_ether_addr_zero, ETH_ALEN)) {
        /* We need a non-zero MAC address to set the default pvid.
         * Retry later. */
        return TRUE;
    }

    self->vlan_configured = TRUE;

    if (!is_reapply || is_bridge_pvid_changed(device, s_bridge)) {
        /* Filtering must be disabled to change the default PVID.
         * Clear the default PVID so that we later can force the re-creation of
         * default PVID VLANs by writing the option again. */

        if (is_reapply) {
            _LOGD(LOGD_BRIDGE, "default_pvid is changed, resetting bridge VLAN filtering");
        }

        nm_platform_link_set_bridge_info(
            plat,
            ifindex,
            &((NMPlatformLinkSetBridgeInfoData){.vlan_filtering_has    = TRUE,
                                                .vlan_filtering_val    = FALSE,
                                                .vlan_default_pvid_has = TRUE,
                                                .vlan_default_pvid_val = 0}));

        /* Clear all existing VLANs */
        if (!nm_platform_link_set_bridge_vlans(plat, ifindex, FALSE, NULL, 0))
            return FALSE;

        /* Now set the default PVID. After this point the kernel creates
         * a PVID VLAN on each port, including the bridge itself. */
        pvid = nm_setting_bridge_get_vlan_default_pvid(s_bridge);
        if (pvid) {
            nm_platform_link_set_bridge_info(
                plat,
                ifindex,
                &((NMPlatformLinkSetBridgeInfoData){.vlan_default_pvid_has = TRUE,
                                                    .vlan_default_pvid_val = pvid}));
        }
    }

    /* Create VLANs only after setting the default PVID, so that
     * any PVID VLAN overrides the bridge's default PVID. */
    g_object_get(s_bridge, NM_SETTING_BRIDGE_VLANS, &vlans, NULL);
    plat_vlans = setting_vlans_to_platform(vlans, &num_vlans);
    if (plat_vlans
        && !nm_platform_link_set_bridge_vlans(plat, ifindex, FALSE, plat_vlans, num_vlans))
        return FALSE;

    nm_platform_link_set_bridge_info(plat,
                                     ifindex,
                                     &((NMPlatformLinkSetBridgeInfoData){
                                         .vlan_filtering_has = TRUE,
                                         .vlan_filtering_val = TRUE,
                                     }));

    return TRUE;
}

static NMPlatformBridgeVlan *
merge_bridge_vlan_default_pvid(NMPlatformBridgeVlan *vlans, guint *num_vlans, guint default_pvid)
{
    NMPlatformBridgeVlan *vlan;
    gboolean              has_pvid = FALSE;
    guint                 i;

    for (i = 0; i < *num_vlans; i++) {
        if (vlans[i].pvid) {
            has_pvid = TRUE;
            break;
        }
    }

    /* search if the list of VLANs already contains the default PVID */
    vlan = NULL;
    for (i = 0; i < *num_vlans; i++) {
        if (default_pvid >= vlans[i].vid_start && default_pvid <= vlans[i].vid_end) {
            vlan = &vlans[i];
            break;
        }
    }

    if (!vlan) {
        /* VLAN id not found, append the default PVID at the end.
         * Set the PVID flag only if the port didn't have one. */
        vlans = g_realloc_n(vlans, *num_vlans + 1, sizeof(NMPlatformBridgeVlan));
        (*num_vlans)++;
        vlans[*num_vlans - 1] = (NMPlatformBridgeVlan){
            .vid_start = default_pvid,
            .vid_end   = default_pvid,
            .untagged  = TRUE,
            .pvid      = !has_pvid,
        };
    }

    return vlans;
}

void
nm_device_reapply_bridge_port_vlans(NMDevice *device)
{
    NMDevice                     *self = device; /* for logging */
    NMSettingBridgePort          *s_bridge_port;
    NMDevice                     *controller;
    NMSettingBridge              *s_bridge;
    gs_unref_ptrarray GPtrArray  *tmp_vlans         = NULL;
    gs_free NMPlatformBridgeVlan *setting_vlans     = NULL;
    gs_free NMPlatformBridgeVlan *plat_vlans        = NULL;
    guint                         num_setting_vlans = 0;
    guint                         num_plat_vlans    = 0;
    NMPlatform                   *plat;
    int                           ifindex;
    gboolean                      do_reapply;

    s_bridge_port = nm_device_get_applied_setting(device, NM_TYPE_SETTING_BRIDGE_PORT);
    if (!s_bridge_port)
        return;

    controller = nm_device_get_controller(device);
    if (!controller)
        return;

    s_bridge = nm_device_get_applied_setting(controller, NM_TYPE_SETTING_BRIDGE);
    if (!s_bridge)
        return;

    if (nm_setting_bridge_get_vlan_filtering(s_bridge)) {
        g_object_get(s_bridge_port, NM_SETTING_BRIDGE_PORT_VLANS, &tmp_vlans, NULL);
        setting_vlans = setting_vlans_to_platform(tmp_vlans, &num_setting_vlans);

        /* During a regular activation, we first set the default_pvid on the bridge
        * (which creates the PVID VLAN on the port) and then add the VLANs on the port.
        * This ensures that the PVID VLAN is inherited from the bridge, but it's
        * overridden if the port specifies one.
        * During a reapply on the port, we are not going to touch the bridge and
        * so we need to merge manually the PVID from the bridge with the port VLANs. */
        setting_vlans =
            merge_bridge_vlan_default_pvid(setting_vlans,
                                           &num_setting_vlans,
                                           nm_setting_bridge_get_vlan_default_pvid(s_bridge));
    }

    plat    = nm_device_get_platform(device);
    ifindex = nm_device_get_ifindex(device);

    if (!nm_platform_link_get_bridge_vlans(plat, ifindex, &plat_vlans, &num_plat_vlans)) {
        _LOGD(LOGD_DEVICE, "reapply-bridge-port-vlans: can't get current VLANs from platform");
        do_reapply = TRUE;
    } else {
        nmp_utils_bridge_vlan_normalize(setting_vlans, &num_setting_vlans);
        nmp_utils_bridge_vlan_normalize(plat_vlans, &num_plat_vlans);
        if (!nmp_utils_bridge_normalized_vlans_equal(setting_vlans,
                                                     num_setting_vlans,
                                                     plat_vlans,
                                                     num_plat_vlans)) {
            _LOGD(LOGD_DEVICE, "reapply-bridge-port-vlans: VLANs in platform need reapply");
            do_reapply = TRUE;
        } else {
            _LOGD(LOGD_DEVICE, "reapply-bridge-port-vlans: VLANs in platform didn't change");
            do_reapply = FALSE;
        }
    }

    if (do_reapply) {
        nm_platform_link_set_bridge_vlans(plat, ifindex, TRUE, NULL, 0);
        if (num_setting_vlans > 0)
            nm_platform_link_set_bridge_vlans(plat,
                                              ifindex,
                                              TRUE,
                                              setting_vlans,
                                              num_setting_vlans);
    }
}

static void
_platform_lnk_bridge_init_from_setting(NMSettingBridge *s_bridge, NMPlatformLnkBridge *props)
{
    *props = (NMPlatformLnkBridge){
        .forward_delay = _DEFAULT_IF_ZERO(nm_setting_bridge_get_forward_delay(s_bridge) * 100u,
                                          NM_BRIDGE_FORWARD_DELAY_DEF_SYS),
        .hello_time    = _DEFAULT_IF_ZERO(nm_setting_bridge_get_hello_time(s_bridge) * 100u,
                                       NM_BRIDGE_HELLO_TIME_DEF_SYS),
        .max_age       = _DEFAULT_IF_ZERO(nm_setting_bridge_get_max_age(s_bridge) * 100u,
                                    NM_BRIDGE_MAX_AGE_DEF_SYS),
        .ageing_time   = nm_setting_bridge_get_ageing_time(s_bridge) * 100u,
        .stp_state     = nm_setting_bridge_get_stp(s_bridge),
        .priority      = nm_setting_bridge_get_priority(s_bridge),
        .vlan_protocol = to_sysfs_vlan_protocol_sys(nm_setting_bridge_get_vlan_protocol(s_bridge)),
        .vlan_stats_enabled = nm_setting_bridge_get_vlan_stats_enabled(s_bridge),
        .group_fwd_mask     = nm_setting_bridge_get_group_forward_mask(s_bridge),
        .mcast_snooping     = nm_setting_bridge_get_multicast_snooping(s_bridge),
        .mcast_router =
            to_sysfs_multicast_router_sys(nm_setting_bridge_get_multicast_router(s_bridge)),
        .mcast_query_use_ifaddr    = nm_setting_bridge_get_multicast_query_use_ifaddr(s_bridge),
        .mcast_querier             = nm_setting_bridge_get_multicast_querier(s_bridge),
        .mcast_hash_max            = nm_setting_bridge_get_multicast_hash_max(s_bridge),
        .mcast_last_member_count   = nm_setting_bridge_get_multicast_last_member_count(s_bridge),
        .mcast_startup_query_count = nm_setting_bridge_get_multicast_startup_query_count(s_bridge),
        .mcast_last_member_interval =
            nm_setting_bridge_get_multicast_last_member_interval(s_bridge),
        .mcast_membership_interval = nm_setting_bridge_get_multicast_membership_interval(s_bridge),
        .mcast_querier_interval    = nm_setting_bridge_get_multicast_querier_interval(s_bridge),
        .mcast_query_interval      = nm_setting_bridge_get_multicast_query_interval(s_bridge),
        .mcast_query_response_interval =
            nm_setting_bridge_get_multicast_query_response_interval(s_bridge),
        .mcast_startup_query_interval =
            nm_setting_bridge_get_multicast_startup_query_interval(s_bridge),
    };

    to_sysfs_group_address_sys(nm_setting_bridge_get_group_address(s_bridge), &props->group_addr);
}

static gboolean
link_config(NMDevice *device, NMConnection *connection, gboolean is_reapply)
{
    int                 ifindex = nm_device_get_ifindex(device);
    NMSettingBridge    *s_bridge;
    NMPlatformLnkBridge props;

    s_bridge = nm_connection_get_setting_bridge(connection);
    g_return_val_if_fail(s_bridge, FALSE);

    _platform_lnk_bridge_init_from_setting(s_bridge, &props);

    if (nm_platform_link_bridge_change(nm_device_get_platform(device), ifindex, &props) < 0)
        return FALSE;

    return bridge_set_vlan_options(device, s_bridge, is_reapply);
}

static NMActStageReturn
act_stage1_prepare(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMConnection *connection;

    connection = nm_device_get_applied_connection(device);
    g_return_val_if_fail(connection, NM_ACT_STAGE_RETURN_FAILURE);

    if (!link_config(device, connection, FALSE)) {
        NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
        return NM_ACT_STAGE_RETURN_FAILURE;
    }

    return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
_bt_register_bridge_cb(GError *error, gpointer user_data)
{
    NMDeviceBridge *self;

    if (nm_utils_error_is_cancelled(error))
        return;

    self = user_data;

    g_clear_object(&self->bt_cancellable);

    if (error) {
        _LOGD(LOGD_DEVICE, "bluetooth NAP server failed to register bridge: %s", error->message);
        nm_device_state_changed(NM_DEVICE(self),
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_BT_FAILED);
        return;
    }

    self->bt_cb_state = _NM_BT_CB_STATE_SUCCESS;
    nm_device_activate_schedule_stage2_device_config(NM_DEVICE(self), FALSE);
}

void
_nm_device_bridge_notify_unregister_bt_nap(NMDevice *device, const char *reason)
{
    NMDeviceBridge *self = NM_DEVICE_BRIDGE(device);

    _LOGD(LOGD_DEVICE,
          "bluetooth NAP server unregistered from bridge: %s%s",
          reason,
          self->bt_cb_state != _NM_BT_CB_STATE_NONE ? "" : " (was no longer registered)");

    nm_clear_g_cancellable(&self->bt_cancellable);

    if (self->bt_cb_state != _NM_BT_CB_STATE_NONE) {
        self->bt_cb_state = _NM_BT_CB_STATE_NONE;
        nm_device_state_changed(device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_BT_FAILED);
    }
}

static NMActStageReturn
act_stage2_config(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMDeviceBridge       *self = NM_DEVICE_BRIDGE(device);
    NMConnection         *connection;
    NMSettingBluetooth   *s_bt;
    gs_free_error GError *error = NULL;

    connection = nm_device_get_applied_connection(device);

    s_bt = _nm_connection_get_setting_bluetooth_for_nap(connection);
    if (!s_bt)
        return NM_ACT_STAGE_RETURN_SUCCESS;

    if (!nm_bt_vtable_network_server) {
        _LOGD(LOGD_DEVICE, "bluetooth NAP server failed because bluetooth plugin not available");
        *out_failure_reason = NM_DEVICE_STATE_REASON_BT_FAILED;
        return NM_ACT_STAGE_RETURN_FAILURE;
    }

    if (self->bt_cancellable)
        return NM_ACT_STAGE_RETURN_POSTPONE;

    if (self->bt_cb_state == _NM_BT_CB_STATE_WAIT)
        return NM_ACT_STAGE_RETURN_POSTPONE;

    if (self->bt_cb_state == _NM_BT_CB_STATE_SUCCESS)
        return NM_ACT_STAGE_RETURN_SUCCESS;

    self->bt_cancellable = g_cancellable_new();
    if (!nm_bt_vtable_network_server->register_bridge(nm_bt_vtable_network_server,
                                                      nm_setting_bluetooth_get_bdaddr(s_bt),
                                                      device,
                                                      self->bt_cancellable,
                                                      _bt_register_bridge_cb,
                                                      device,
                                                      &error)) {
        _LOGD(LOGD_DEVICE, "bluetooth NAP server failed to register bridge: %s", error->message);
        *out_failure_reason = NM_DEVICE_STATE_REASON_BT_FAILED;
        return NM_ACT_STAGE_RETURN_FAILURE;
    }

    self->bt_cb_state = _NM_BT_CB_STATE_WAIT;
    return NM_ACT_STAGE_RETURN_POSTPONE;
}

static void
deactivate(NMDevice *device)
{
    NMDeviceBridge *self = NM_DEVICE_BRIDGE(device);

    _LOGD(LOGD_DEVICE,
          "deactivate bridge%s",
          self->bt_cb_state != _NM_BT_CB_STATE_NONE ? " (registered as NAP bluetooth device)" : "");

    self->vlan_configured = FALSE;

    nm_clear_g_cancellable(&self->bt_cancellable);

    if (self->bt_cb_state != _NM_BT_CB_STATE_NONE) {
        self->bt_cb_state = _NM_BT_CB_STATE_NONE;
        nm_bt_vtable_network_server->unregister_bridge(nm_bt_vtable_network_server, device);
    }
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
    NMDeviceBridge      *self = NM_DEVICE_BRIDGE(device);
    NMConnection        *controller_connection;
    NMSettingBridge     *s_bridge;
    NMSettingBridgePort *s_port;

    if (configure) {
        if (!nm_platform_link_attach_port(nm_device_get_platform(device),
                                          nm_device_get_ip_ifindex(device),
                                          nm_device_get_ip_ifindex(port)))
            return FALSE;

        controller_connection = nm_device_get_applied_connection(device);
        nm_assert(controller_connection);
        s_bridge = nm_connection_get_setting_bridge(controller_connection);
        nm_assert(s_bridge);
        s_port = nm_connection_get_setting_bridge_port(connection);

        if (!nm_device_sys_iface_state_is_external(device))
            bridge_set_vlan_options(device, s_bridge, FALSE);

        if (nm_setting_bridge_get_vlan_filtering(s_bridge)) {
            gs_free NMPlatformBridgeVlan *plat_vlans = NULL;
            gs_unref_ptrarray GPtrArray  *vlans      = NULL;
            guint                         num_vlans;

            if (s_port)
                g_object_get(s_port, NM_SETTING_BRIDGE_PORT_VLANS, &vlans, NULL);

            plat_vlans = setting_vlans_to_platform(vlans, &num_vlans);

            /* Since the link was just enportd, there are no existing VLANs
             * (except for the default one) and so there's no need to flush. */

            if (plat_vlans
                && !nm_platform_link_set_bridge_vlans(nm_device_get_platform(port),
                                                      nm_device_get_ifindex(port),
                                                      TRUE,
                                                      plat_vlans,
                                                      num_vlans))
                return FALSE;
        }

        commit_port_options(port, s_port);

        _LOGI(LOGD_BRIDGE, "attached bridge port %s", nm_device_get_ip_iface(port));
    } else {
        _LOGI(LOGD_BRIDGE, "bridge port %s was attached", nm_device_get_ip_iface(port));
    }

    return TRUE;
}

static NMTernary
detach_port(NMDevice                  *device,
            NMDevice                  *port,
            gboolean                   configure,
            GCancellable              *cancellable,
            NMDeviceAttachPortCallback callback,
            gpointer                   user_data)
{
    NMDeviceBridge *self = NM_DEVICE_BRIDGE(device);
    gboolean        success;
    int             ifindex_port;
    int             ifindex;

    if (configure) {
        ifindex = nm_device_get_ifindex(device);
        if (ifindex <= 0 || !nm_platform_link_get(nm_device_get_platform(device), ifindex))
            configure = FALSE;
    }

    ifindex_port = nm_device_get_ip_ifindex(port);

    if (ifindex_port <= 0) {
        _LOGD(LOGD_TEAM, "bridge port %s is already detached", nm_device_get_ip_iface(port));
        return TRUE;
    }

    if (configure) {
        success = nm_platform_link_release_port(nm_device_get_platform(device),
                                                nm_device_get_ip_ifindex(device),
                                                ifindex_port);

        if (success) {
            _LOGI(LOGD_BRIDGE, "detached bridge port %s", nm_device_get_ip_iface(port));
        } else {
            _LOGW(LOGD_BRIDGE, "failed to detach bridge port %s", nm_device_get_ip_iface(port));
        }
    } else {
        _LOGI(LOGD_BRIDGE, "bridge port %s was detached", nm_device_get_ip_iface(port));
    }

    return TRUE;
}

static gboolean
create_and_realize(NMDevice              *device,
                   NMConnection          *connection,
                   NMDevice              *parent,
                   const NMPlatformLink **out_plink,
                   GError               **error)
{
    NMSettingWired     *s_wired;
    NMSettingBridge    *s_bridge;
    const char         *iface = nm_device_get_iface(device);
    const char         *hwaddr;
    gs_free char       *hwaddr_cloned = NULL;
    guint8              mac_address[_NM_UTILS_HWADDR_LEN_MAX];
    NMPlatformLnkBridge props;
    int                 r;
    guint32             mtu = 0;

    nm_assert(iface);

    s_bridge = nm_connection_get_setting_bridge(connection);
    nm_assert(s_bridge);

    hwaddr = nm_setting_bridge_get_mac_address(s_bridge);
    if (!hwaddr
        && nm_device_hw_addr_get_cloned(device, connection, FALSE, &hwaddr_cloned, NULL, NULL)) {
        /* FIXME: we set the MAC address when creating the interface, while the
         * NMDevice is still unrealized. As we afterwards realize the device, it
         * forgets the parameters for the cloned MAC address, and in stage 1
         * it might create a different MAC address. That should be fixed by
         * better handling device realization. */
        hwaddr = hwaddr_cloned;
    }

    if (hwaddr) {
        if (!nm_utils_hwaddr_aton(hwaddr, mac_address, ETH_ALEN)) {
            g_set_error(error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_FAILED,
                        "Invalid hardware address '%s'",
                        hwaddr);
            g_return_val_if_reached(FALSE);
        }
    }

    _platform_lnk_bridge_init_from_setting(s_bridge, &props);

    s_wired = nm_connection_get_setting_wired(connection);
    nm_assert(s_wired);

    mtu = nm_setting_wired_get_mtu(s_wired);

    /* If mtu != 0, we set the MTU of the new bridge at creation time. However, kernel will still
     * automatically adjust the MTU of the bridge based on the minimum of the port's MTU.
     * We don't want this automatism as the user asked for a fixed MTU.
     *
     * To workaround this behavior of kernel, we will later toggle the MTU twice. See
     * NMDeviceClass.mtu_force_set. */
    r = nm_platform_link_bridge_add(nm_device_get_platform(device),
                                    iface,
                                    hwaddr ? mac_address : NULL,
                                    hwaddr ? ETH_ALEN : 0,
                                    mtu,
                                    &props,
                                    out_plink);
    if (r < 0) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_CREATION_FAILED,
                    "Failed to create bridge interface '%s' for '%s': %s",
                    iface,
                    nm_connection_get_id(connection),
                    nm_strerror(r));
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static gboolean
can_reapply_change(NMDevice   *device,
                   const char *setting_name,
                   NMSetting  *s_old,
                   NMSetting  *s_new,
                   GHashTable *diffs,
                   GError    **error)
{
    /* Delegate changes to other settings to parent class */
    if (!nm_streq(setting_name, NM_SETTING_BRIDGE_SETTING_NAME)) {
        return NM_DEVICE_CLASS(nm_device_bridge_parent_class)
            ->can_reapply_change(device, setting_name, s_old, s_new, diffs, error);
    }

    return nm_device_hash_check_invalid_keys(diffs,
                                             NM_SETTING_BRIDGE_SETTING_NAME,
                                             error,
                                             NM_SETTING_BRIDGE_STP,
                                             NM_SETTING_BRIDGE_PRIORITY,
                                             NM_SETTING_BRIDGE_FORWARD_DELAY,
                                             NM_SETTING_BRIDGE_HELLO_TIME,
                                             NM_SETTING_BRIDGE_MAX_AGE,
                                             NM_SETTING_BRIDGE_AGEING_TIME,
                                             NM_SETTING_BRIDGE_GROUP_FORWARD_MASK,
                                             NM_SETTING_BRIDGE_MULTICAST_HASH_MAX,
                                             NM_SETTING_BRIDGE_MULTICAST_LAST_MEMBER_COUNT,
                                             NM_SETTING_BRIDGE_MULTICAST_LAST_MEMBER_INTERVAL,
                                             NM_SETTING_BRIDGE_MULTICAST_MEMBERSHIP_INTERVAL,
                                             NM_SETTING_BRIDGE_MULTICAST_SNOOPING,
                                             NM_SETTING_BRIDGE_MULTICAST_ROUTER,
                                             NM_SETTING_BRIDGE_MULTICAST_QUERIER,
                                             NM_SETTING_BRIDGE_MULTICAST_QUERIER_INTERVAL,
                                             NM_SETTING_BRIDGE_MULTICAST_QUERY_INTERVAL,
                                             NM_SETTING_BRIDGE_MULTICAST_QUERY_RESPONSE_INTERVAL,
                                             NM_SETTING_BRIDGE_MULTICAST_QUERY_USE_IFADDR,
                                             NM_SETTING_BRIDGE_MULTICAST_STARTUP_QUERY_COUNT,
                                             NM_SETTING_BRIDGE_MULTICAST_STARTUP_QUERY_INTERVAL,
                                             NM_SETTING_BRIDGE_GROUP_ADDRESS,
                                             NM_SETTING_BRIDGE_VLAN_PROTOCOL,
                                             NM_SETTING_BRIDGE_VLAN_STATS_ENABLED,
                                             NM_SETTING_BRIDGE_VLAN_FILTERING,
                                             NM_SETTING_BRIDGE_VLAN_DEFAULT_PVID,
                                             NM_SETTING_BRIDGE_VLANS);
}

static void
reapply_connection(NMDevice *device, NMConnection *con_old, NMConnection *con_new)
{
    NMDeviceBridge  *self = NM_DEVICE_BRIDGE(device);
    NMSettingBridge *s_bridge;

    NM_DEVICE_CLASS(nm_device_bridge_parent_class)->reapply_connection(device, con_old, con_new);

    _LOGD(LOGD_BRIDGE, "reapplying bridge settings");
    s_bridge = nm_connection_get_setting_bridge(con_new);
    g_return_if_fail(s_bridge);

    /* Make sure bridge_set_vlan_options() called by link_config()
     * sets vlan_filtering and default_pvid anew. */
    self->vlan_configured = FALSE;
    link_config(device, con_new, TRUE);
}

/*****************************************************************************/

static void
nm_device_bridge_init(NMDeviceBridge *self)
{
    nm_assert(nm_device_is_controller(NM_DEVICE(self)));
}

static const NMDBusInterfaceInfoExtended interface_info_device_bridge = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_BRIDGE,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE(
                "HwAddress",
                "s",
                NM_DEVICE_HW_ADDRESS,
                .annotations = NM_GDBUS_ANNOTATION_INFO_LIST_DEPRECATED(), ),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE(
                "Carrier",
                "b",
                NM_DEVICE_CARRIER,
                .annotations = NM_GDBUS_ANNOTATION_INFO_LIST_DEPRECATED(), ),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE(
                "Slaves",
                "ao",
                NM_DEVICE_SLAVES,
                .annotations = NM_GDBUS_ANNOTATION_INFO_LIST_DEPRECATED(), ), ), ),
};

static void
nm_device_bridge_class_init(NMDeviceBridgeClass *klass)
{
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_bridge);

    device_class->connection_type_supported = NM_SETTING_BRIDGE_SETTING_NAME;
    device_class->link_types                = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_BRIDGE);

    device_class->is_controller               = TRUE;
    device_class->mtu_force_set               = TRUE;
    device_class->get_generic_capabilities    = get_generic_capabilities;
    device_class->check_connection_compatible = check_connection_compatible;
    device_class->check_connection_available  = check_connection_available;
    device_class->complete_connection         = complete_connection;

    device_class->update_connection                 = update_connection;
    device_class->controller_update_port_connection = controller_update_port_connection;

    device_class->create_and_realize                     = create_and_realize;
    device_class->act_stage1_prepare_set_hwaddr_ethernet = TRUE;
    device_class->act_stage1_prepare                     = act_stage1_prepare;
    device_class->act_stage2_config                      = act_stage2_config;
    device_class->deactivate                             = deactivate;
    device_class->attach_port                            = attach_port;
    device_class->detach_port                            = detach_port;
    device_class->get_configured_mtu                     = nm_device_get_configured_mtu_for_wired;
    device_class->can_reapply_change                     = can_reapply_change;
    device_class->reapply_connection                     = reapply_connection;
}

/*****************************************************************************/

#define NM_TYPE_BRIDGE_DEVICE_FACTORY (nm_bridge_device_factory_get_type())
#define NM_BRIDGE_DEVICE_FACTORY(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_BRIDGE_DEVICE_FACTORY, NMBridgeDeviceFactory))

static NMDevice *
create_device(NMDeviceFactory      *factory,
              const char           *iface,
              const NMPlatformLink *plink,
              NMConnection         *connection,
              gboolean             *out_ignore)
{
    return g_object_new(NM_TYPE_DEVICE_BRIDGE,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_DRIVER,
                        "bridge",
                        NM_DEVICE_TYPE_DESC,
                        "Bridge",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_BRIDGE,
                        NM_DEVICE_LINK_TYPE,
                        NM_LINK_TYPE_BRIDGE,
                        NULL);
}

static gboolean
match_connection(NMDeviceFactory *factory, NMConnection *connection)
{
    const char *type = nm_connection_get_connection_type(connection);

    if (nm_streq(type, NM_SETTING_BRIDGE_SETTING_NAME))
        return TRUE;

    nm_assert(nm_streq(type, NM_SETTING_BLUETOOTH_SETTING_NAME));

    if (!_nm_connection_get_setting_bluetooth_for_nap(connection))
        return FALSE;

    if (!g_type_from_name("NMBluezManager")) {
        /* bluetooth NAP connections are handled by bridge factory. However,
         * it needs help from the bluetooth plugin, so if the plugin is not loaded,
         * we claim not to support it. */
        return FALSE;
    }

    return TRUE;
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL(
    BRIDGE,
    Bridge,
    bridge,
    NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(NM_LINK_TYPE_BRIDGE)
        NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_BRIDGE_SETTING_NAME,
                                                NM_SETTING_BLUETOOTH_SETTING_NAME),
    factory_class->create_device    = create_device;
    factory_class->match_connection = match_connection;);
