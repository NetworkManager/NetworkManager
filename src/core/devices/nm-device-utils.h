/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __DEVICES_NM_DEVICE_UTILS_H__
#define __DEVICES_NM_DEVICE_UTILS_H__

/*****************************************************************************/

const char *nm_device_state_to_string(NMDeviceState state);
const char *nm_device_state_reason_to_string(NMDeviceStateReason reason);

#define nm_device_state_reason_to_string_a(reason) \
    NM_UTILS_LOOKUP_STR_A(nm_device_state_reason_to_string, reason)

static inline NMDeviceStateReason
nm_device_state_reason_check(NMDeviceStateReason reason)
{
    /* the device-state-reason serves mostly informational purpose during a state
     * change. In some cases however, decisions are made based on the reason.
     * I tend to think that interpreting the state reason to derive some behaviors
     * is confusing, because the cause and effect are so far apart.
     *
     * This function is here to mark source that inspects the reason to make
     * a decision -- contrary to places that set the reason. Thus, by grepping
     * for nm_device_state_reason_check() you can find the "effect" to a certain
     * reason.
     */
    return reason;
}

/*****************************************************************************/

#define NM_PENDING_ACTION_AUTOACTIVATE           "autoactivate"
#define NM_PENDING_ACTION_IN_STATE_CHANGE        "in-state-change"
#define NM_PENDING_ACTION_RECHECK_AVAILABLE      "recheck-available"
#define NM_PENDING_ACTION_CARRIER_WAIT           "carrier-wait"
#define NM_PENDING_ACTION_WAITING_FOR_SUPPLICANT "waiting-for-supplicant"
#define NM_PENDING_ACTION_WIFI_SCAN              "wifi-scan"
#define NM_PENDING_ACTION_WAITING_FOR_COMPANION  "waiting-for-companion"
#define NM_PENDING_ACTION_LINK_INIT              "link-init"

#define NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "queued-state-change-"
#define NM_PENDING_ACTIONPREFIX_ACTIVATION          "activation-"

const char *nm_device_state_queued_state_to_string(NMDeviceState state);

/*****************************************************************************/

typedef enum {
    NM_DEVICE_MTU_SOURCE_NONE,
    NM_DEVICE_MTU_SOURCE_PARENT,
    NM_DEVICE_MTU_SOURCE_IP_CONFIG,
    NM_DEVICE_MTU_SOURCE_CONNECTION,
} NMDeviceMtuSource;

const char *nm_device_mtu_source_to_string(NMDeviceMtuSource mtu_source);

/*****************************************************************************/

typedef enum _nm_packed {
    NM_DEVICE_SYS_IFACE_STATE_EXTERNAL,
    NM_DEVICE_SYS_IFACE_STATE_ASSUME,
    NM_DEVICE_SYS_IFACE_STATE_MANAGED,

    /* the REMOVED state applies when the device is manually set to unmanaged
     * or the link was externally removed. In both cases, we move the device
     * to UNMANAGED state, without touching the link -- be it, because the link
     * is already gone or because we want to release it (give it up).
     */
    NM_DEVICE_SYS_IFACE_STATE_REMOVED,
} NMDeviceSysIfaceState;

const char *nm_device_sys_iface_state_to_string(NMDeviceSysIfaceState sys_iface_state);

/*****************************************************************************/

typedef enum _nm_packed {
    NM_DEVICE_IP_STATE_NONE,
    NM_DEVICE_IP_STATE_PENDING,
    NM_DEVICE_IP_STATE_READY,
    NM_DEVICE_IP_STATE_FAILED,
} NMDeviceIPState;

const char *nm_device_ip_state_to_string(NMDeviceIPState ip_state);

/*****************************************************************************/

void nm_device_resolve_address(int                 addr_family,
                               gconstpointer       address,
                               GCancellable       *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer            cb_data);

char *nm_device_resolve_address_finish(GAsyncResult *result, GError **error);

#endif /* __DEVICES_NM_DEVICE_UTILS_H__ */
