/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "src/core/nm-default-daemon.h"
#include "src/core/dns/nm-dns-manager.h"
#include "src/core/dns/nm-dns-systemd-resolved.h"

#include "nm-device-utils.h"
#include "nm-core-utils.h"

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE(
    nm_device_state_queued_state_to_string,
    NMDeviceState,
    NM_UTILS_LOOKUP_DEFAULT(NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "???"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_UNKNOWN,
                             NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "unknown"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_UNMANAGED,
                             NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "unmanaged"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_UNAVAILABLE,
                             NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "unavailable"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_DISCONNECTED,
                             NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "disconnected"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_PREPARE,
                             NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "prepare"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_CONFIG,
                             NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "config"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_NEED_AUTH,
                             NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "need-auth"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_IP_CONFIG,
                             NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "ip-config"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_IP_CHECK,
                             NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "ip-check"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_SECONDARIES,
                             NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "secondaries"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_ACTIVATED,
                             NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "activated"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_DEACTIVATING,
                             NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "deactivating"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_FAILED,
                             NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "failed"), );

const char *
nm_device_state_to_string(NMDeviceState state)
{
    return nm_device_state_queued_state_to_string(state)
           + NM_STRLEN(NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE);
}

NM_UTILS_LOOKUP_STR_DEFINE(
    nm_device_state_reason_to_string,
    NMDeviceStateReason,
    NM_UTILS_LOOKUP_DEFAULT(NULL),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_UNKNOWN, "unknown"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_NONE, "none"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_NOW_MANAGED, "managed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_NOW_UNMANAGED, "unmanaged"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_CONFIG_FAILED, "config-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE, "ip-config-unavailable"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED, "ip-config-expired"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_NO_SECRETS, "no-secrets"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT, "supplicant-disconnect"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED,
                             "supplicant-config-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED, "supplicant-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT, "supplicant-timeout"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_PPP_START_FAILED, "ppp-start-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_PPP_DISCONNECT, "ppp-disconnect"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_PPP_FAILED, "ppp-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_DHCP_START_FAILED, "dhcp-start-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_DHCP_ERROR, "dhcp-error"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_DHCP_FAILED, "dhcp-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_SHARED_START_FAILED, "sharing-start-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_SHARED_FAILED, "sharing-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED, "autoip-start-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_AUTOIP_ERROR, "autoip-error"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_AUTOIP_FAILED, "autoip-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_MODEM_BUSY, "modem-busy"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE, "modem-no-dialtone"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER, "modem-no-carrier"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT, "modem-dial-timeout"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED, "modem-dial-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED, "modem-init-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_GSM_APN_FAILED, "gsm-apn-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING,
                             "gsm-registration-idle"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED,
                             "gsm-registration-denied"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT,
                             "gsm-registration-timeout"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED,
                             "gsm-registration-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED, "gsm-pin-check-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_FIRMWARE_MISSING, "firmware-missing"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_REMOVED, "removed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_SLEEPING, "sleeping"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_CONNECTION_REMOVED, "connection-removed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_USER_REQUESTED, "user-requested"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_CARRIER, "carrier-changed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED, "connection-assumed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE, "supplicant-available"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND, "modem-not-found"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_BT_FAILED, "bluetooth-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED, "gsm-sim-not-inserted"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED, "gsm-sim-pin-required"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED, "gsm-sim-puk-required"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_GSM_SIM_WRONG, "gsm-sim-wrong"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_INFINIBAND_MODE, "infiniband-mode"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED, "dependency-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_BR2684_FAILED, "br2684-bridge-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_MODEM_MANAGER_UNAVAILABLE,
                             "modem-manager-unavailable"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_SSID_NOT_FOUND, "ssid-not-found"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED,
                             "secondary-connection-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED, "dcb-fcoe-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED, "teamd-control-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_MODEM_FAILED, "modem-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_MODEM_AVAILABLE, "modem-available"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT, "sim-pin-incorrect"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_NEW_ACTIVATION, "new-activation"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_PARENT_CHANGED, "parent-changed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED,
                             "parent-managed-changed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_OVSDB_FAILED, "ovsdb-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_IP_ADDRESS_DUPLICATE, "ip-address-duplicate"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_IP_METHOD_UNSUPPORTED, "ip-method-unsupported"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_SRIOV_CONFIGURATION_FAILED,
                             "sriov-configuration-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_PEER_NOT_FOUND, "peer-not-found"), );

NM_UTILS_LOOKUP_STR_DEFINE(nm_device_mtu_source_to_string,
                           NMDeviceMtuSource,
                           NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT("unknown"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_MTU_SOURCE_NONE, "none"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_MTU_SOURCE_PARENT, "parent"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_MTU_SOURCE_IP_CONFIG, "ip-config"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_MTU_SOURCE_CONNECTION,
                                                    "connection"), );

NM_UTILS_LOOKUP_STR_DEFINE(nm_device_sys_iface_state_to_string,
                           NMDeviceSysIfaceState,
                           NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT("unknown"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_SYS_IFACE_STATE_EXTERNAL, "external"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_SYS_IFACE_STATE_ASSUME, "assume"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_SYS_IFACE_STATE_MANAGED, "managed"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_SYS_IFACE_STATE_REMOVED,
                                                    "removed"), );

NM_UTILS_LOOKUP_STR_DEFINE(nm_device_ip_state_to_string,
                           NMDeviceIPState,
                           NM_UTILS_LOOKUP_DEFAULT_WARN("unknown"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_IP_STATE_NONE, "none"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_IP_STATE_PENDING, "pending"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_IP_STATE_READY, "done"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_IP_STATE_FAILED, "fail"), );

/*****************************************************************************/

#define SD_RESOLVED_DNS (1UL << 0)
/* Don't answer request from locally synthesized records (which includes /etc/hosts) */
#define SD_RESOLVED_NO_SYNTHESIZE (1UL << 11)

typedef struct {
    int                                addr_family;
    NMIPAddr                           address;
    gulong                             cancellable_id;
    GTask                             *task;
    NMDnsSystemdResolvedResolveHandle *resolved_handle;
} ResolveAddrInfo;

#define _NMLOG_PREFIX_NAME "resolve-addr"
#define _NMLOG_DOMAIN      LOGD_CORE
#define _NMLOG2(level, info, ...)                                                   \
    G_STMT_START                                                                    \
    {                                                                               \
        if (nm_logging_enabled((level), (_NMLOG_DOMAIN))) {                         \
            ResolveAddrInfo *_info = (info);                                        \
            char             _addr_str[NM_INET_ADDRSTRLEN];                         \
                                                                                    \
            _nm_log((level),                                                        \
                    (_NMLOG_DOMAIN),                                                \
                    0,                                                              \
                    NULL,                                                           \
                    NULL,                                                           \
                    _NMLOG_PREFIX_NAME "[" NM_HASH_OBFUSCATE_PTR_FMT                \
                                       ",%s]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                    NM_HASH_OBFUSCATE_PTR(_info),                                   \
                    nm_inet_ntop(_info->addr_family, &_info->address, _addr_str)    \
                        _NM_UTILS_MACRO_REST(__VA_ARGS__));                         \
        }                                                                           \
    }                                                                               \
    G_STMT_END

static void
resolve_addr_info_free(ResolveAddrInfo *info)
{
    nm_assert(info->cancellable_id == 0);
    nm_assert(!info->resolved_handle);
    g_object_unref(info->task);
    g_free(info);
}

static void
resolve_addr_complete(ResolveAddrInfo *info, char *hostname_take, GError *error_take)
{
    nm_assert(!!hostname_take != !!error_take);

    nm_clear_g_cancellable_disconnect(g_task_get_cancellable(info->task), &info->cancellable_id);
    if (error_take)
        g_task_return_error(info->task, error_take);
    else
        g_task_return_pointer(info->task, hostname_take, g_free);

    resolve_addr_info_free(info);
}

static void
resolve_addr_helper_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    ResolveAddrInfo      *info   = user_data;
    gs_free_error GError *error  = NULL;
    gs_free char         *output = NULL;

    output = nm_utils_spawn_helper_finish(result, &error);
    if (nm_utils_error_is_cancelled(error))
        return;

    _LOG2D(info, "helper returned hostname '%s'", output);

    resolve_addr_complete(info, g_steal_pointer(&output), g_steal_pointer(&error));
}

static void
resolve_addr_spawn_helper(ResolveAddrInfo *info)
{
    char addr_str[NM_INET_ADDRSTRLEN];

    nm_inet_ntop(info->addr_family, &info->address, addr_str);
    _LOG2D(info, "start lookup via nm-daemon-helper");
    nm_utils_spawn_helper(NM_MAKE_STRV("resolve-address", addr_str),
                          g_task_get_cancellable(info->task),
                          resolve_addr_helper_cb,
                          info);
}

static void
resolve_addr_resolved_cb(NMDnsSystemdResolved                    *resolved,
                         NMDnsSystemdResolvedResolveHandle       *handle,
                         const NMDnsSystemdResolvedAddressResult *names,
                         guint                                    names_len,
                         guint64                                  flags,
                         GError                                  *error,
                         gpointer                                 user_data)
{
    ResolveAddrInfo *info = user_data;

    info->resolved_handle = NULL;

    if (nm_utils_error_is_cancelled(error))
        return;

    if (error) {
        gs_free char *dbus_error = NULL;

        _LOG2D(info, "error resolving via systemd-resolved: %s", error->message);

        dbus_error = g_dbus_error_get_remote_error(error);
        if (NM_STR_HAS_PREFIX(dbus_error, "org.freedesktop.resolve1.")) {
            /* systemd-resolved is enabled but it couldn't resolve the
             * address via DNS.  Don't fall back to spawning the helper,
             * because the helper will possibly ask again to
             * systemd-resolved (via /etc/resolv.conf), potentially using
             * other protocols than DNS or returning synthetic results.
             *
             * Consider the error as the final indication that the address
             * can't be resolved.
             *
             * See: https://www.freedesktop.org/wiki/Software/systemd/resolved/#commonerrors
             */
            resolve_addr_complete(info, NULL, g_error_copy(error));
            return;
        }

        resolve_addr_spawn_helper(info);
        return;
    }

    if (names_len == 0) {
        _LOG2D(info, "systemd-resolved returned no result");
        resolve_addr_complete(info, g_strdup(""), NULL);
        return;
    }

    _LOG2D(info, "systemd-resolved returned hostname '%s'", names[0].name);
    resolve_addr_complete(info, g_strdup(names[0].name), NULL);
}

static void
resolve_addr_cancelled(GObject *object, gpointer user_data)
{
    ResolveAddrInfo *info  = user_data;
    GError          *error = NULL;

    nm_clear_g_signal_handler(g_task_get_cancellable(info->task), &info->cancellable_id);
    nm_clear_pointer(&info->resolved_handle, nm_dns_systemd_resolved_resolve_cancel);
    nm_utils_error_set_cancelled(&error, FALSE, NULL);
    resolve_addr_complete(info, NULL, error);
}

void
nm_device_resolve_address(int                 addr_family,
                          gconstpointer       address,
                          GCancellable       *cancellable,
                          GAsyncReadyCallback callback,
                          gpointer            cb_data)
{
    ResolveAddrInfo      *info;
    NMDnsSystemdResolved *resolved;

    info  = g_new(ResolveAddrInfo, 1);
    *info = (ResolveAddrInfo){
        .task = nm_g_task_new(NULL, cancellable, nm_device_resolve_address, callback, cb_data),
        .addr_family = addr_family,
        .address     = nm_ip_addr_init(addr_family, address),
    };

    if (cancellable) {
        gulong signal_id;

        signal_id =
            g_cancellable_connect(cancellable, G_CALLBACK(resolve_addr_cancelled), info, NULL);
        if (signal_id == 0) {
            /* the request is already cancelled. Return. */
            return;
        }
        info->cancellable_id = signal_id;
    }

    resolved = (NMDnsSystemdResolved *) nm_dns_manager_get_systemd_resolved(nm_dns_manager_get());
    if (resolved) {
        _LOG2D(info, "start lookup via systemd-resolved");
        info->resolved_handle =
            nm_dns_systemd_resolved_resolve_address(resolved,
                                                    0,
                                                    addr_family,
                                                    address,
                                                    SD_RESOLVED_DNS | SD_RESOLVED_NO_SYNTHESIZE,
                                                    20000,
                                                    resolve_addr_resolved_cb,
                                                    info);
        return;
    }

    resolve_addr_spawn_helper(info);
}

char *
nm_device_resolve_address_finish(GAsyncResult *result, GError **error)
{
    GTask *task = G_TASK(result);

    nm_assert(nm_g_task_is_valid(result, NULL, nm_device_resolve_address));

    return g_task_propagate_pointer(task, error);
}
