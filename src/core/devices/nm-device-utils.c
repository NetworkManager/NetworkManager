/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <linux/if_ether.h>

#include "src/core/nm-default-daemon.h"
#include "src/core/dns/nm-dns-manager.h"
#include "src/core/dns/nm-dns-systemd-resolved.h"

#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-core-aux-intern/nm-common-macros.h"
#include "libnm-systemd-shared/nm-sd-utils-shared.h"

#include "nm-config.h"
#include "nm-core-utils.h"
#include "nm-device-utils.h"
#include "nm-device-loopback.h"
#include "nm-device.h"
#include "nm-device-logging.h"
#include "ndisc/nm-ndisc.h"

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
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_PEER_NOT_FOUND, "peer-not-found"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_STATE_REASON_DEVICE_HANDLER_FAILED,
                             "device-handler-failed"), );

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

const char *
nm_device_prop_get_connection_mud_url(NMDevice *self)
{
    NMSettingConnection *s_con;
    const char          *mud_url;
    const char          *s;

    s_con = nm_device_get_applied_setting(self, NM_TYPE_SETTING_IP4_CONFIG);
    nm_assert(s_con);
    mud_url = nm_setting_connection_get_mud_url(s_con);

    if (mud_url) {
        if (nm_streq(mud_url, NM_CONNECTION_MUD_URL_NONE))
            return NULL;
        return mud_url;
    }

    s = nm_config_data_get_connection_default(NM_CONFIG_GET_DATA,
                                              NM_CON_DEFAULT("connection.mud-url"),
                                              self);
    if (s) {
        if (nm_streq(s, NM_CONNECTION_MUD_URL_NONE))
            return NULL;
        if (nm_sd_http_url_is_valid_https(s))
            return s;
    }

    return NULL;
}

guint32
nm_device_prop_get_ipv4_dad_timeout(NMDevice *self)
{
    NMConnection      *connection;
    NMSettingIPConfig *s_ip4   = NULL;
    int                timeout = -1;

    connection = nm_device_get_applied_connection(self);
    if (connection)
        s_ip4 = nm_connection_get_setting_ip4_config(connection);
    if (s_ip4)
        timeout = nm_setting_ip_config_get_dad_timeout(s_ip4);

    nm_assert(timeout >= -1 && timeout <= NM_SETTING_IP_CONFIG_DAD_TIMEOUT_MAX);

    if (timeout >= 0)
        return timeout;

    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       NM_CON_DEFAULT("ipv4.dad-timeout"),
                                                       self,
                                                       0,
                                                       NM_SETTING_IP_CONFIG_DAD_TIMEOUT_MAX,
                                                       200);
}

guint32
nm_device_prop_get_ipv6_ra_timeout(NMDevice *self)
{
    NMConnection *connection;
    gint32        timeout;

    G_STATIC_ASSERT_EXPR(NM_RA_TIMEOUT_DEFAULT == 0);
    G_STATIC_ASSERT_EXPR(NM_RA_TIMEOUT_INFINITY == G_MAXINT32);

    connection = nm_device_get_applied_connection(self);

    timeout = nm_setting_ip6_config_get_ra_timeout(
        NM_SETTING_IP6_CONFIG(nm_connection_get_setting_ip6_config(connection)));
    if (timeout > 0)
        return timeout;
    nm_assert(timeout == 0);

    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       NM_CON_DEFAULT("ipv6.ra-timeout"),
                                                       self,
                                                       0,
                                                       G_MAXINT32,
                                                       0);
}

NMSettingConnectionMdns
nm_device_prop_get_connection_mdns(NMDevice *self)
{
    NMConnection           *connection;
    NMSettingConnectionMdns mdns = NM_SETTING_CONNECTION_MDNS_DEFAULT;

    g_return_val_if_fail(NM_IS_DEVICE(self), NM_SETTING_CONNECTION_MDNS_DEFAULT);

    connection = nm_device_get_applied_connection(self);
    if (connection)
        mdns = nm_setting_connection_get_mdns(nm_connection_get_setting_connection(connection));
    if (mdns != NM_SETTING_CONNECTION_MDNS_DEFAULT)
        return mdns;

    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       NM_CON_DEFAULT("connection.mdns"),
                                                       self,
                                                       NM_SETTING_CONNECTION_MDNS_NO,
                                                       NM_SETTING_CONNECTION_MDNS_YES,
                                                       NM_SETTING_CONNECTION_MDNS_DEFAULT);
}

NMSettingConnectionLlmnr
nm_device_prop_get_connection_llmnr(NMDevice *self)
{
    NMConnection            *connection;
    NMSettingConnectionLlmnr llmnr = NM_SETTING_CONNECTION_LLMNR_DEFAULT;

    g_return_val_if_fail(NM_IS_DEVICE(self), NM_SETTING_CONNECTION_LLMNR_DEFAULT);

    connection = nm_device_get_applied_connection(self);
    if (connection)
        llmnr = nm_setting_connection_get_llmnr(nm_connection_get_setting_connection(connection));
    if (llmnr != NM_SETTING_CONNECTION_LLMNR_DEFAULT)
        return llmnr;

    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       NM_CON_DEFAULT("connection.llmnr"),
                                                       self,
                                                       NM_SETTING_CONNECTION_LLMNR_NO,
                                                       NM_SETTING_CONNECTION_LLMNR_YES,
                                                       NM_SETTING_CONNECTION_LLMNR_DEFAULT);
}

NMSettingConnectionDnsOverTls
nm_device_prop_get_connection_dns_over_tls(NMDevice *self)
{
    NMConnection                 *connection;
    NMSettingConnectionDnsOverTls dns_over_tls = NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT;

    g_return_val_if_fail(NM_IS_DEVICE(self), NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT);

    connection = nm_device_get_applied_connection(self);
    if (connection)
        dns_over_tls = nm_setting_connection_get_dns_over_tls(
            nm_connection_get_setting_connection(connection));
    if (dns_over_tls != NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT)
        return dns_over_tls;

    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       NM_CON_DEFAULT("connection.dns-over-tls"),
                                                       self,
                                                       NM_SETTING_CONNECTION_DNS_OVER_TLS_NO,
                                                       NM_SETTING_CONNECTION_DNS_OVER_TLS_YES,
                                                       NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT);
}

NMMptcpFlags
nm_device_prop_get_connection_mptcp_flags(NMDevice *self)
{
    NMConnection *connection;
    NMMptcpFlags  mptcp_flags = NM_MPTCP_FLAGS_NONE;

    g_return_val_if_fail(NM_IS_DEVICE(self), NM_MPTCP_FLAGS_DISABLED);

    connection = nm_device_get_applied_connection(self);
    if (connection) {
        mptcp_flags =
            nm_setting_connection_get_mptcp_flags(nm_connection_get_setting_connection(connection));
    }

    if (mptcp_flags == NM_MPTCP_FLAGS_NONE) {
        guint64 v;

        v = nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                        NM_CON_DEFAULT("connection.mptcp-flags"),
                                                        self,
                                                        0,
                                                        G_MAXINT64,
                                                        NM_MPTCP_FLAGS_NONE);
        if (v != NM_MPTCP_FLAGS_NONE) {
            /* We silently ignore all invalid flags (and will normalize them away below). */
            mptcp_flags = (NMMptcpFlags) v;
            if (mptcp_flags == NM_MPTCP_FLAGS_NONE)
                mptcp_flags = NM_MPTCP_FLAGS_ENABLED;
        }
    }

    if (mptcp_flags == NM_MPTCP_FLAGS_NONE)
        mptcp_flags = _NM_MPTCP_FLAGS_DEFAULT;

    mptcp_flags = nm_mptcp_flags_normalize(mptcp_flags);

    if (!NM_FLAGS_HAS(mptcp_flags, NM_MPTCP_FLAGS_DISABLED)) {
        if (!NM_FLAGS_HAS(mptcp_flags, NM_MPTCP_FLAGS_ALSO_WITHOUT_SYSCTL)) {
            guint32 v;

            /* If enabled, but without "also-without-sysctl", then MPTCP is still
             * disabled, if the sysctl says so...
             *
             * We evaluate this here. The point is that the decision is then cached
             * until deactivation/reapply. The user can toggle the sysctl any time,
             * but we only pick it up at certain moments (now). */
            v = nm_platform_sysctl_get_int32(
                nm_device_get_platform(self),
                NMP_SYSCTL_PATHID_ABSOLUTE("/proc/sys/net/mptcp/enabled"),
                -1);
            if (v <= 0)
                mptcp_flags = NM_MPTCP_FLAGS_DISABLED;
        } else
            mptcp_flags = NM_FLAGS_UNSET(mptcp_flags, NM_MPTCP_FLAGS_ALSO_WITHOUT_SYSCTL);
    }

    return mptcp_flags;
}

gboolean
nm_device_prop_get_connection_lldp(NMDevice *self)
{
    NMConnection           *connection;
    NMSettingConnection    *s_con;
    NMSettingConnectionLldp lldp = NM_SETTING_CONNECTION_LLDP_DEFAULT;

    connection = nm_device_get_applied_connection(self);
    g_return_val_if_fail(connection, FALSE);

    s_con = nm_connection_get_setting_connection(connection);
    g_return_val_if_fail(s_con, FALSE);

    lldp = nm_setting_connection_get_lldp(s_con);
    if (lldp == NM_SETTING_CONNECTION_LLDP_DEFAULT) {
        lldp = nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                           NM_CON_DEFAULT("connection.lldp"),
                                                           self,
                                                           NM_SETTING_CONNECTION_LLDP_DEFAULT,
                                                           NM_SETTING_CONNECTION_LLDP_ENABLE_RX,
                                                           NM_SETTING_CONNECTION_LLDP_DEFAULT);
        if (lldp == NM_SETTING_CONNECTION_LLDP_DEFAULT)
            lldp = NM_SETTING_CONNECTION_LLDP_DISABLE;
    }
    return lldp == NM_SETTING_CONNECTION_LLDP_ENABLE_RX;
}

NMSettingIP4LinkLocal
nm_device_prop_get_ipv4_link_local(NMDevice *self)
{
    NMSettingIP4Config   *s_ip4;
    NMSettingIP4LinkLocal link_local;

    s_ip4 = nm_device_get_applied_setting(self, NM_TYPE_SETTING_IP4_CONFIG);
    if (!s_ip4)
        return NM_SETTING_IP4_LL_DISABLED;

    if (NM_IS_DEVICE_LOOPBACK(self))
        return NM_SETTING_IP4_LL_DISABLED;

    link_local = nm_setting_ip4_config_get_link_local(s_ip4);

    if (link_local == NM_SETTING_IP4_LL_DEFAULT) {
        /* For connections without a ipv4.link-local property configured the global configuration
           might defines the default value for ipv4.link-local. */
        link_local = nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                                 NM_CON_DEFAULT("ipv4.link-local"),
                                                                 self,
                                                                 NM_SETTING_IP4_LL_AUTO,
                                                                 NM_SETTING_IP4_LL_ENABLED,
                                                                 NM_SETTING_IP4_LL_DEFAULT);
        if (link_local == NM_SETTING_IP4_LL_DEFAULT) {
            /* If there is no global configuration for ipv4.link-local assume auto */
            link_local = NM_SETTING_IP4_LL_AUTO;
        } else if (link_local == NM_SETTING_IP4_LL_ENABLED
                   && nm_streq(nm_setting_ip_config_get_method((NMSettingIPConfig *) s_ip4),
                               NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
            /* ipv4.method=disabled has higher priority than the global ipv4.link-local=enabled */
            link_local = NM_SETTING_IP4_LL_DISABLED;
        } else if (link_local == NM_SETTING_IP4_LL_DISABLED
                   && nm_streq(nm_setting_ip_config_get_method((NMSettingIPConfig *) s_ip4),
                               NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)) {
            /* ipv4.method=link-local has higher priority than the global ipv4.link-local=disabled */
            link_local = NM_SETTING_IP4_LL_ENABLED;
        }
    }

    if (link_local == NM_SETTING_IP4_LL_AUTO) {
        link_local = nm_streq(nm_setting_ip_config_get_method((NMSettingIPConfig *) s_ip4),
                              NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)
                         ? NM_SETTING_IP4_LL_ENABLED
                         : NM_SETTING_IP4_LL_DISABLED;
    }

    return link_local;
}

guint32
nm_device_prop_get_ipvx_dns_priority(NMDevice *self, int addr_family)
{
    NMConnection      *connection;
    NMSettingIPConfig *s_ip;
    int                prio = 0;

    connection = nm_device_get_applied_connection(self);
    s_ip       = nm_connection_get_setting_ip_config(connection, addr_family);
    if (s_ip)
        prio = nm_setting_ip_config_get_dns_priority(s_ip);

    if (prio == 0) {
        prio = nm_config_data_get_connection_default_int64(
            NM_CONFIG_GET_DATA,
            NM_IS_IPv4(addr_family) ? NM_CON_DEFAULT("ipv4.dns-priority")
                                    : NM_CON_DEFAULT("ipv6.dns-priority"),
            self,
            G_MININT32,
            G_MAXINT32,
            0);
        if (prio == 0) {
            prio = nm_device_is_vpn(self) ? NM_DNS_PRIORITY_DEFAULT_VPN
                                          : NM_DNS_PRIORITY_DEFAULT_NORMAL;
        }
    }

    nm_assert(prio != 0);
    return prio;
}

guint32
nm_device_prop_get_ipvx_required_timeout(NMDevice *self, int addr_family)
{
    NMConnection      *connection;
    NMSettingIPConfig *s_ip;
    int                timeout;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert_addr_family(addr_family);

    connection = nm_device_get_applied_connection(self);
    if (!connection)
        return 0;

    s_ip = nm_connection_get_setting_ip_config(connection, addr_family);
    if (!s_ip)
        return 0;

    timeout = nm_setting_ip_config_get_required_timeout(s_ip);
    nm_assert(timeout >= -1);

    if (timeout > -1)
        return (guint32) timeout;

    return nm_config_data_get_connection_default_int64(
        NM_CONFIG_GET_DATA,
        NM_IS_IPv4(addr_family) ? NM_CON_DEFAULT("ipv4.required-timeout")
                                : NM_CON_DEFAULT("ipv6.required-timeout"),
        self,
        0,
        G_MAXINT32,
        0);
}

gboolean
nm_device_prop_get_ipvx_may_fail(NMDevice *self, int addr_family)
{
    NMConnection      *connection;
    NMSettingIPConfig *s_ip = NULL;

    connection = nm_device_get_applied_connection(self);
    if (connection)
        s_ip = nm_connection_get_setting_ip_config(connection, addr_family);

    return !s_ip || nm_setting_ip_config_get_may_fail(s_ip);
}

NMDhcpHostnameFlags
nm_device_prop_get_ipvx_dhcp_hostname_flags(NMDevice *self, int addr_family)
{
    NMConnection         *connection;
    NMSettingIPConfig    *s_ip;
    NMDhcpHostnameFlags   flags;
    gs_free_error GError *error = NULL;

    g_return_val_if_fail(NM_IS_DEVICE(self), NM_DHCP_HOSTNAME_FLAG_NONE);

    connection = nm_device_get_applied_connection(self);
    s_ip       = nm_connection_get_setting_ip_config(connection, addr_family);
    g_return_val_if_fail(s_ip, NM_DHCP_HOSTNAME_FLAG_NONE);

    if (!nm_setting_ip_config_get_dhcp_send_hostname(s_ip))
        return NM_DHCP_HOSTNAME_FLAG_NONE;

    flags = nm_setting_ip_config_get_dhcp_hostname_flags(s_ip);
    if (flags != NM_DHCP_HOSTNAME_FLAG_NONE)
        return flags;

    flags = nm_config_data_get_connection_default_int64(
        NM_CONFIG_GET_DATA,
        NM_IS_IPv4(addr_family) ? NM_CON_DEFAULT("ipv4.dhcp-hostname-flags")
                                : NM_CON_DEFAULT("ipv6.dhcp-hostname-flags"),
        self,
        0,
        NM_DHCP_HOSTNAME_FLAG_FQDN_CLEAR_FLAGS,
        0);

    if (!_nm_utils_validate_dhcp_hostname_flags(flags, addr_family, &error)) {
        _LOGW(LOGD_DEVICE,
              "invalid global default value 0x%x for ipv%c.%s: %s",
              (guint) flags,
              nm_utils_addr_family_to_char(addr_family),
              NM_SETTING_IP_CONFIG_DHCP_HOSTNAME_FLAGS,
              error->message);
        flags = NM_DHCP_HOSTNAME_FLAG_NONE;
    }

    if (flags != NM_DHCP_HOSTNAME_FLAG_NONE)
        return flags;

    if (NM_IS_IPv4(addr_family))
        return NM_DHCP_HOSTNAME_FLAGS_FQDN_DEFAULT_IP4;
    else
        return NM_DHCP_HOSTNAME_FLAGS_FQDN_DEFAULT_IP6;
}

guint8
nm_device_prop_get_ipv4_dhcp_dscp(NMDevice *self, gboolean *out_dscp_explicit)
{
    gs_free_error GError *error = NULL;
    NMConnection         *connection;
    NMSettingIPConfig    *s_ip;
    const char           *str;

    connection = nm_device_get_applied_connection(self);
    s_ip       = nm_connection_get_setting_ip_config(connection, AF_INET);
    g_return_val_if_fail(s_ip, 0);

    NM_SET_OUT(out_dscp_explicit, TRUE);

    str = nm_setting_ip_config_get_dhcp_dscp(s_ip);
    if (str) {
        nm_assert(nm_utils_validate_dhcp_dscp(str, NULL));
    } else {
        str = nm_config_data_get_connection_default(NM_CONFIG_GET_DATA,
                                                    NM_CON_DEFAULT("ipv4.dhcp-dscp"),
                                                    self);
        if (!str || !str[0]) {
            str = "CS0";
            NM_SET_OUT(out_dscp_explicit, FALSE);
        } else if (!nm_utils_validate_dhcp_dscp(str, &error)) {
            _LOGW(LOGD_DEVICE,
                  "invalid global default value '%s' for ipv4.%s: %s",
                  str,
                  NM_SETTING_IP_CONFIG_DHCP_DSCP,
                  error->message);
            str = "CS0";
            NM_SET_OUT(out_dscp_explicit, FALSE);
        }
    }

    if (nm_streq(str, "CS0")) {
        return 0;
    } else if (nm_streq(str, "CS6")) {
        return 0x30;
    } else if (nm_streq(str, "CS4")) {
        return 0x20;
    };

    return nm_assert_unreachable_val(0);
}

GBytes *
nm_device_prop_get_ipv4_dhcp_vendor_class_identifier(NMDevice *self, NMSettingIP4Config *s_ip4)
{
    gs_free char *to_free = NULL;
    const char   *conn_prop;
    GBytes       *bytes = NULL;
    const char   *bin;
    gsize         len;

    conn_prop = nm_setting_ip4_config_get_dhcp_vendor_class_identifier(s_ip4);

    if (!conn_prop) {
        /* set in NetworkManager.conf ? */
        conn_prop = nm_config_data_get_connection_default(
            NM_CONFIG_GET_DATA,
            NM_CON_DEFAULT("ipv4.dhcp-vendor-class-identifier"),
            self);

        if (conn_prop && !nm_utils_validate_dhcp4_vendor_class_id(conn_prop, NULL))
            conn_prop = NULL;
    }

    if (conn_prop) {
        bin = nm_utils_buf_utf8safe_unescape(conn_prop,
                                             NM_UTILS_STR_UTF8_SAFE_FLAG_NONE,
                                             &len,
                                             (gpointer *) &to_free);
        if (to_free)
            bytes = g_bytes_new_take(g_steal_pointer(&to_free), len);
        else
            bytes = g_bytes_new(bin, len);
    }

    return bytes;
}

NMSettingIP6ConfigAddrGenMode
nm_device_prop_get_ipv6_addr_gen_mode(NMDevice *self)
{
    NMSettingIP6ConfigAddrGenMode addr_gen_mode;
    NMSettingIP6Config           *s_ip6;
    gint64                        c;

    g_return_val_if_fail(self, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY);

    s_ip6 = nm_device_get_applied_setting(self, NM_TYPE_SETTING_IP6_CONFIG);
    if (s_ip6) {
        addr_gen_mode = nm_setting_ip6_config_get_addr_gen_mode(s_ip6);
        if (NM_IN_SET(addr_gen_mode,
                      NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
                      NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY))
            return addr_gen_mode;
    } else
        addr_gen_mode = NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT;

    nm_assert(NM_IN_SET(addr_gen_mode,
                        NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT_OR_EUI64,
                        NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT));

    c = nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                    NM_CON_DEFAULT("ipv6.addr-gen-mode"),
                                                    self,
                                                    NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
                                                    NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT,
                                                    -1);
    if (c != -1)
        addr_gen_mode = c;

    if (addr_gen_mode == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT)
        addr_gen_mode = NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY;
    else if (addr_gen_mode == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT_OR_EUI64)
        addr_gen_mode = NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64;

    nm_assert(NM_IN_SET(addr_gen_mode,
                        NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
                        NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY));

    return addr_gen_mode;
}

const char *
nm_device_prop_get_x_cloned_mac_address(NMDevice *self, NMConnection *connection, gboolean is_wifi)
{
    NMSetting  *setting;
    const char *addr = NULL;

    setting = nm_connection_get_setting(connection,
                                        is_wifi ? NM_TYPE_SETTING_WIRELESS : NM_TYPE_SETTING_WIRED);
    if (setting) {
        addr = is_wifi ? nm_setting_wireless_get_cloned_mac_address((NMSettingWireless *) setting)
                       : nm_setting_wired_get_cloned_mac_address((NMSettingWired *) setting);
    }

    if (!addr) {
        const char *a;

        a = nm_config_data_get_connection_default(
            NM_CONFIG_GET_DATA,
            is_wifi ? NM_CON_DEFAULT("wifi.cloned-mac-address")
                    : NM_CON_DEFAULT("ethernet.cloned-mac-address"),
            self);

        addr = NM_CLONED_MAC_PRESERVE;

        if (!a) {
            if (is_wifi) {
                NMSettingMacRandomization v;

                /* for backward compatibility, read the deprecated wifi.mac-address-randomization setting. */
                v = nm_config_data_get_connection_default_int64(
                    NM_CONFIG_GET_DATA,
                    NM_CON_DEFAULT("wifi.mac-address-randomization"),
                    self,
                    NM_SETTING_MAC_RANDOMIZATION_DEFAULT,
                    NM_SETTING_MAC_RANDOMIZATION_ALWAYS,
                    NM_SETTING_MAC_RANDOMIZATION_DEFAULT);
                if (v == NM_SETTING_MAC_RANDOMIZATION_ALWAYS)
                    addr = NM_CLONED_MAC_RANDOM;
            }
        } else if (NM_CLONED_MAC_IS_SPECIAL(a, is_wifi) || nm_utils_hwaddr_valid(a, ETH_ALEN))
            addr = a;
    }

    return addr;
}

const char *
nm_device_prop_get_x_generate_mac_address_mask(NMDevice     *self,
                                               NMConnection *connection,
                                               gboolean      is_wifi)
{
    NMSetting  *setting;
    const char *value;

    setting = nm_connection_get_setting(connection,
                                        is_wifi ? NM_TYPE_SETTING_WIRELESS : NM_TYPE_SETTING_WIRED);
    if (setting) {
        value =
            is_wifi
                ? nm_setting_wireless_get_generate_mac_address_mask((NMSettingWireless *) setting)
                : nm_setting_wired_get_generate_mac_address_mask((NMSettingWired *) setting);
        if (value)
            return value;
    }

    return nm_config_data_get_connection_default(
        NM_CONFIG_GET_DATA,
        is_wifi ? NM_CON_DEFAULT("wifi.generate-mac-address-mask")
                : NM_CON_DEFAULT("ethernet.generate-mac-address-mask"),
        self);
}
