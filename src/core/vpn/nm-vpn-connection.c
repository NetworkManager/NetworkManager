/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2005 - 2013 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-vpn-connection.h"

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "NetworkManagerUtils.h"
#include "dns/nm-dns-manager.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-glib-aux/nm-dbus-aux.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-std-aux/unaligned.h"
#include "nm-active-connection.h"
#include "nm-config.h"
#include "nm-dbus-manager.h"
#include "nm-dispatcher.h"
#include "nm-firewalld-manager.h"
#include "nm-ip-config.h"
#include "nm-l3-config-data.h"
#include "nm-netns.h"
#include "nm-pacrunner-manager.h"
#include "nm-vpn-manager.h"
#include "nm-vpn-plugin-info.h"
#include "settings/nm-agent-manager.h"
#include "settings/nm-settings-connection.h"

/* FIXME(l3cfg): Check that we handle it correctly if the parent device is VRF type. */

/* FIXME(l3cfg): Proxy settings are no longer configured. That needs to be handled by NML3Cfg. */

/*****************************************************************************/

#define DBUS_DEFAULT_TIMEOUT_MSEC 10000

typedef enum {
    L3CD_TYPE_GW_EXTERN,

    L3CD_TYPE_STATIC,
    L3CD_TYPE_GENERIC,
    L3CD_TYPE_IP_4,
    L3CD_TYPE_IP_6,

#define L3CD_TYPE_IP_X(IS_IPv4) ((IS_IPv4) ? L3CD_TYPE_IP_4 : L3CD_TYPE_IP_6)

    _L3CD_TYPE_NUM,
} L3CDType;

typedef enum {
    /* Only system secrets */
    SECRETS_REQ_SYSTEM = 0,
    /* All existing secrets including agent secrets */
    SECRETS_REQ_EXISTING = 1,
    /* New secrets required; ask an agent */
    SECRETS_REQ_NEW = 2,
    /* Plugin requests secrets interactively */
    SECRETS_REQ_INTERACTIVE = 3,
    /* Placeholder for bounds checking */
    SECRETS_REQ_LAST
} SecretsReq;

/* Internal VPN states, private to NMVpnConnection */
typedef enum {
    STATE_UNKNOWN = 0,
    STATE_WAITING,
    STATE_PREPARE,
    STATE_NEED_AUTH,
    STATE_CONNECT,
    STATE_IP_CONFIG_GET,
    STATE_PRE_UP,
    STATE_ACTIVATED,
    STATE_DEACTIVATING,
    STATE_DISCONNECTED,
    STATE_FAILED,
} VpnState;

enum {
    INTERNAL_STATE_CHANGED,
    INTERNAL_RETRY_AFTER_FAILURE,

    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = {0};

NM_GOBJECT_PROPERTIES_DEFINE(NMVpnConnection, PROP_VPN_STATE, PROP_BANNER,
#define PROP_IP4_CONFIG 2000
#define PROP_IP6_CONFIG 2001
#define PROP_MASTER     2002
#define PROP_CONTROLLER 2003
);

typedef struct {
    NMIPConfig *ip_config;

    NMIPAddr gw_internal;
    NMIPAddr gw_external;

    /* Whether VPN auto-configuration is enabled in the connection profile for
     * this address family. */
    bool method_auto : 1;

    /* Whether VPN auto-configuration is enabled, in the connection profile AND
     * in the configuration reported by the VPN. If not, then we won't have a
     * l3cd instance, but the activation for this address family is still
     * complete. */
    bool enabled : 1;
} IPData;

typedef struct {
    gboolean service_can_persist;
    gboolean connection_can_persist;

    NMSettingsConnectionCallId *secrets_id;
    SecretsReq                  secrets_idx;
    char                       *username;

    VpnState                      vpn_state;
    NMDispatcherCallId           *dispatcher_id;
    NMActiveConnectionStateReason failure_reason;

    NMVpnServiceState service_state;
    GSource          *start_timeout_source;
    NMVpnPluginInfo  *plugin_info;

    NMNetns *netns;

    NML3Cfg                 *l3cfg_if;
    NML3CfgCommitTypeHandle *l3cfg_commit_type_if;

    NML3Cfg                 *l3cfg_dev;
    NML3CfgCommitTypeHandle *l3cfg_commit_type_dev;

    struct {
        GDBusConnection *connection;
        char            *bus_name;
        char            *owner;
        guint            signal_id_vpn;
        guint            signal_id_name_changed;
        bool             name_owner_initialized : 1;
    } dbus;

    NMFirewalldManagerCallId *fw_call;

    union {
        const NML3ConfigData *const l3cds[_L3CD_TYPE_NUM];
        const NML3ConfigData       *l3cds_[_L3CD_TYPE_NUM];
    };

    /* This combines the l3cds of the VPN (basically, excluding l3cd_gw_extern which
     * is only about configuration for the parent device). This is used to configure
     * DNS. */
    const NML3ConfigData *l3cd_combined;

    union {
        struct {
            IPData ip_data_6;
            IPData ip_data_4;
        };
        IPData ip_data_x[2];
    };

    GSource           *init_fail_on_idle_source;
    GSource           *connect_timeout_source;
    GCancellable      *main_cancellable;
    GVariant          *connect_hash;
    char              *banner;
    NMPacrunnerConfId *pacrunner_conf_id;

    int ifindex_if;
    int ifindex_dev;

    guint32 mtu;

    bool wait_for_pre_up_state : 1;

    bool dbus_service_started : 1;

    bool generic_config_received : 1;

    bool l3cds_changed : 1;
} NMVpnConnectionPrivate;

struct _NMVpnConnection {
    NMActiveConnection     parent;
    NMVpnConnectionPrivate _priv;
};

struct _NMVpnConnectionClass {
    NMActiveConnectionClass parent;
};

G_DEFINE_TYPE(NMVpnConnection, nm_vpn_connection, NM_TYPE_ACTIVE_CONNECTION)

#define NM_VPN_CONNECTION_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMVpnConnection, NM_IS_VPN_CONNECTION, NMActiveConnection)

/*****************************************************************************/

static const NMDBusInterfaceInfoExtended interface_info_vpn_connection;
static const GDBusSignalInfo             signal_info_vpn_state_changed;

static NMSettingsConnection *_get_settings_connection(NMVpnConnection *self,
                                                      gboolean         allow_missing);

static void _secrets_get(NMVpnConnection *self, SecretsReq secrets_idx, const char *const *hints);

static guint32 get_route_table(NMVpnConnection *self, int addr_family, gboolean fallback_main);

static void _set_vpn_state(NMVpnConnection              *self,
                           VpnState                      vpn_state,
                           NMActiveConnectionStateReason reason,
                           gboolean                      quitting);

static void
_l3cfg_notify_cb(NML3Cfg *l3cfg, const NML3ConfigNotifyData *notify_data, NMVpnConnection *self);

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_VPN
#define _NMLOG_PREFIX_NAME "vpn"

#define __NMLOG_prefix_buf_len 128

static const char *
__LOG_create_prefix(char *buf, NMVpnConnection *self, NMSettingsConnection *con)
{
    NMVpnConnectionPrivate *priv;
    const char             *id;
    const char             *iface;
    char                    buf1[100];
    char                    buf2[100];

    if (!self)
        return _NMLOG_PREFIX_NAME;

    priv = NM_VPN_CONNECTION_GET_PRIVATE(self);
    id   = con ? nm_settings_connection_get_id(con) : NULL;

    iface = nm_vpn_connection_get_ip_iface(self, FALSE);

    g_snprintf(buf,
               __NMLOG_prefix_buf_len,
               "%s["
               "%p"       /*self*/
               "%s%s"     /*con-uuid*/
               "%s%s%s%s" /*con-id*/
               "%s"       /*ifindex_if*/
               "%s"       /*ifindex_dev*/
               "%s%s%s"   /*iface*/
               "]",
               _NMLOG_PREFIX_NAME,
               self,
               con ? "," : "--",
               con ? (nm_settings_connection_get_uuid(con) ?: "??") : "",
               con ? "," : "",
               NM_PRINT_FMT_QUOTED(id, "\"", id, "\"", con ? "??" : ""),
               priv->ifindex_if > 0 ? nm_sprintf_buf(buf1, ",if:%d", priv->ifindex_if) : "",
               priv->ifindex_dev > 0 ? nm_sprintf_buf(buf2, ",dev:%d", priv->ifindex_dev) : "",
               NM_PRINT_FMT_QUOTED(iface, ":(", iface, ")", ""));

    return buf;
}

#define _NMLOG(level, ...)                                                                   \
    G_STMT_START                                                                             \
    {                                                                                        \
        const NMLogLevel      _level = (level);                                              \
        NMSettingsConnection *_con   = (self) ? _get_settings_connection(self, TRUE) : NULL; \
                                                                                             \
        if (nm_logging_enabled(_level, _NMLOG_DOMAIN)) {                                     \
            char __prefix[__NMLOG_prefix_buf_len];                                           \
                                                                                             \
            _nm_log(_level,                                                                  \
                    _NMLOG_DOMAIN,                                                           \
                    0,                                                                       \
                    (self) ? nm_vpn_connection_get_ip_iface(self, FALSE) : NULL,             \
                    (_con) ? nm_settings_connection_get_uuid(_con) : NULL,                   \
                    "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                               \
                    __LOG_create_prefix(__prefix, (self), _con)                              \
                        _NM_UTILS_MACRO_REST(__VA_ARGS__));                                  \
        }                                                                                    \
    }                                                                                        \
    G_STMT_END

/*****************************************************************************/

static NM_UTILS_LOOKUP_STR_DEFINE(_l3cd_type_to_string,
                                  L3CDType,
                                  NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT(NULL),
                                  NM_UTILS_LOOKUP_ITEM_IGNORE_OTHER(),
                                  NM_UTILS_LOOKUP_STR_ITEM(L3CD_TYPE_GW_EXTERN, "gw-extern"),
                                  NM_UTILS_LOOKUP_STR_ITEM(L3CD_TYPE_STATIC, "static"),
                                  NM_UTILS_LOOKUP_STR_ITEM(L3CD_TYPE_GENERIC, "generic"),
                                  NM_UTILS_LOOKUP_STR_ITEM(L3CD_TYPE_IP_4, "ip-4"),
                                  NM_UTILS_LOOKUP_STR_ITEM(L3CD_TYPE_IP_6, "ip-6"), );

static NM_UTILS_LOOKUP_STR_DEFINE(
    _vpn_service_state_to_string,
    NMVpnServiceState,
    NM_UTILS_LOOKUP_DEFAULT(NULL),
    NM_UTILS_LOOKUP_STR_ITEM(NM_VPN_SERVICE_STATE_UNKNOWN, "unknown"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_VPN_SERVICE_STATE_INIT, "init"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_VPN_SERVICE_STATE_SHUTDOWN, "shutdown"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_VPN_SERVICE_STATE_STARTING, "starting"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_VPN_SERVICE_STATE_STARTED, "started"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_VPN_SERVICE_STATE_STOPPING, "stopping"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_VPN_SERVICE_STATE_STOPPED, "stopped"), );

#define vpn_service_state_to_string_a(state) \
    NM_UTILS_LOOKUP_STR_A(_vpn_service_state_to_string, state)

static NM_UTILS_LOOKUP_STR_DEFINE(_vpn_state_to_string,
                                  VpnState,
                                  NM_UTILS_LOOKUP_DEFAULT(NULL),
                                  NM_UTILS_LOOKUP_STR_ITEM(STATE_UNKNOWN, "unknown"),
                                  NM_UTILS_LOOKUP_STR_ITEM(STATE_WAITING, "waiting"),
                                  NM_UTILS_LOOKUP_STR_ITEM(STATE_PREPARE, "prepare"),
                                  NM_UTILS_LOOKUP_STR_ITEM(STATE_NEED_AUTH, "need-auth"),
                                  NM_UTILS_LOOKUP_STR_ITEM(STATE_CONNECT, "connect"),
                                  NM_UTILS_LOOKUP_STR_ITEM(STATE_IP_CONFIG_GET, "ip-config-get"),
                                  NM_UTILS_LOOKUP_STR_ITEM(STATE_PRE_UP, "pre-up"),
                                  NM_UTILS_LOOKUP_STR_ITEM(STATE_ACTIVATED, "activated"),
                                  NM_UTILS_LOOKUP_STR_ITEM(STATE_DEACTIVATING, "deactivating"),
                                  NM_UTILS_LOOKUP_STR_ITEM(STATE_DISCONNECTED, "disconnected"),
                                  NM_UTILS_LOOKUP_STR_ITEM(STATE_FAILED, "failed"), );

#define vpn_state_to_string_a(state) NM_UTILS_LOOKUP_STR_A(_vpn_state_to_string, state)

static NM_UTILS_LOOKUP_STR_DEFINE(
    _vpn_plugin_failure_to_string,
    NMVpnPluginFailure,
    NM_UTILS_LOOKUP_DEFAULT(NULL),
    NM_UTILS_LOOKUP_STR_ITEM(NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED, "login-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED, "connect-failed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG, "bad-ip-config"), );

#define vpn_plugin_failure_to_string_a(failure) \
    NM_UTILS_LOOKUP_STR_A(_vpn_plugin_failure_to_string, failure)

static NMVpnConnectionState
_state_to_nm_vpn_state(VpnState state)
{
    switch (state) {
    case STATE_WAITING:
    case STATE_PREPARE:
        return NM_VPN_CONNECTION_STATE_PREPARE;
    case STATE_NEED_AUTH:
        return NM_VPN_CONNECTION_STATE_NEED_AUTH;
    case STATE_CONNECT:
        return NM_VPN_CONNECTION_STATE_CONNECT;
    case STATE_IP_CONFIG_GET:
    case STATE_PRE_UP:
        return NM_VPN_CONNECTION_STATE_IP_CONFIG_GET;
    case STATE_ACTIVATED:
        return NM_VPN_CONNECTION_STATE_ACTIVATED;
    case STATE_DEACTIVATING:
    {
        /* Map DEACTIVATING to ACTIVATED to preserve external API behavior,
         * since our API has no DEACTIVATING state of its own.  Since this can
         * take some time, and the VPN isn't actually disconnected until it
         * hits the DISCONNECTED state, to clients it should still appear
         * connected.
         */
        return NM_VPN_CONNECTION_STATE_ACTIVATED;
    }
    case STATE_DISCONNECTED:
        return NM_VPN_CONNECTION_STATE_DISCONNECTED;
    case STATE_FAILED:
        return NM_VPN_CONNECTION_STATE_FAILED;
    default:
        return NM_VPN_CONNECTION_STATE_UNKNOWN;
    }
}

static NMActiveConnectionState
_state_to_ac_state(VpnState vpn_state)
{
    /* Set the NMActiveConnection state based on VPN state */
    switch (vpn_state) {
    case STATE_WAITING:
    case STATE_PREPARE:
    case STATE_NEED_AUTH:
    case STATE_CONNECT:
    case STATE_IP_CONFIG_GET:
    case STATE_PRE_UP:
        return NM_ACTIVE_CONNECTION_STATE_ACTIVATING;
    case STATE_ACTIVATED:
        return NM_ACTIVE_CONNECTION_STATE_ACTIVATED;
    case STATE_DEACTIVATING:
        return NM_ACTIVE_CONNECTION_STATE_DEACTIVATING;
    case STATE_DISCONNECTED:
    case STATE_FAILED:
        return NM_ACTIVE_CONNECTION_STATE_DEACTIVATED;
    default:
        break;
    }
    return NM_ACTIVE_CONNECTION_STATE_UNKNOWN;
}

/*****************************************************************************/

static NMSettingsConnection *
_get_settings_connection(NMVpnConnection *self, gboolean allow_missing)
{
    NMSettingsConnection *con;

    /* Currently, we operate on the assumption, that the settings-connection
     * never changes after it is set (though initially, it might be unset).
     * Later we might want to change that, but then we need fixes here too. */

    con = _nm_active_connection_get_settings_connection(NM_ACTIVE_CONNECTION(self));
    if (!con && !allow_missing)
        g_return_val_if_reached(NULL);
    return con;
}

static NMConnection *
_get_applied_connection(NMVpnConnection *connection)
{
    NMConnection *con;

    con = nm_active_connection_get_applied_connection(NM_ACTIVE_CONNECTION(connection));
    g_return_val_if_fail(con, NULL);
    return con;
}

/*****************************************************************************/

static void
_dbus_connection_call(NMVpnConnection    *self,
                      const char         *method_name,
                      GVariant           *parameters,
                      const GVariantType *reply_type,
                      GAsyncReadyCallback callback)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    g_return_if_fail(priv->dbus.bus_name);

    _LOGT("dbus: call %s on %s", method_name, priv->dbus.bus_name);
    g_dbus_connection_call(priv->dbus.connection,
                           priv->dbus.bus_name,
                           NM_VPN_DBUS_PLUGIN_PATH,
                           NM_VPN_DBUS_PLUGIN_INTERFACE,
                           method_name,
                           parameters,
                           reply_type,
                           G_DBUS_CALL_FLAGS_NONE,
                           DBUS_DEFAULT_TIMEOUT_MSEC,
                           priv->main_cancellable,
                           callback,
                           self);
}

static NML3ConfigMergeFlags
_l3cfg_get_merge_flags(NMVpnConnection *self, L3CDType l3cd_type)
{
    NMConnection        *applied;
    NMSettingIPConfig   *s_ip4;
    NMSettingIPConfig   *s_ip6;
    NML3ConfigMergeFlags merge_flags;

    merge_flags = NM_L3_CONFIG_MERGE_FLAGS_NONE;

    if (l3cd_type == L3CD_TYPE_IP_4) {
        applied = _get_applied_connection(self);
        s_ip4   = applied ? nm_connection_get_setting_ip_config(applied, AF_INET) : NULL;

        if (s_ip4 && nm_setting_ip_config_get_ignore_auto_routes(s_ip4))
            merge_flags |= NM_L3_CONFIG_MERGE_FLAGS_NO_ROUTES;
        if (s_ip4 && nm_setting_ip_config_get_never_default(s_ip4))
            merge_flags |= NM_L3_CONFIG_MERGE_FLAGS_NO_DEFAULT_ROUTES;
        if (s_ip4 && nm_setting_ip_config_get_ignore_auto_dns(s_ip4))
            merge_flags |= NM_L3_CONFIG_MERGE_FLAGS_NO_DNS;
    } else if (l3cd_type == L3CD_TYPE_IP_6) {
        applied = _get_applied_connection(self);
        s_ip6   = applied ? nm_connection_get_setting_ip_config(applied, AF_INET6) : NULL;

        if (s_ip6 && nm_setting_ip_config_get_ignore_auto_routes(s_ip6))
            merge_flags |= NM_L3_CONFIG_MERGE_FLAGS_NO_ROUTES;
        if (s_ip6 && nm_setting_ip_config_get_never_default(s_ip6))
            merge_flags |= NM_L3_CONFIG_MERGE_FLAGS_NO_DEFAULT_ROUTES;
        if (s_ip6 && nm_setting_ip_config_get_ignore_auto_dns(s_ip6))
            merge_flags |= NM_L3_CONFIG_MERGE_FLAGS_NO_DNS;
    }

    return merge_flags;
}

static NML3ConfigData *
_l3cfg_l3cd_new(NMVpnConnection *self, int ifindex)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    return nm_l3_config_data_new(nm_netns_get_multi_idx(priv->netns),
                                 ifindex,
                                 NM_IP_CONFIG_SOURCE_VPN);
}

/*****************************************************************************/

guint32
nm_vpn_connection_get_ip4_internal_gateway(NMVpnConnection *self)
{
    g_return_val_if_fail(NM_IS_VPN_CONNECTION(self), 0);

    return NM_VPN_CONNECTION_GET_PRIVATE(self)->ip_data_4.gw_internal.addr4;
}

struct in6_addr *
nm_vpn_connection_get_ip6_internal_gateway(NMVpnConnection *self)
{
    g_return_val_if_fail(NM_IS_VPN_CONNECTION(self), 0);

    return &NM_VPN_CONNECTION_GET_PRIVATE(self)->ip_data_6.gw_internal.addr6;
}

NMVpnConnectionState
nm_vpn_connection_get_vpn_state(NMVpnConnection *self)
{
    g_return_val_if_fail(NM_IS_VPN_CONNECTION(self), NM_VPN_CONNECTION_STATE_UNKNOWN);

    return _state_to_nm_vpn_state(NM_VPN_CONNECTION_GET_PRIVATE(self)->vpn_state);
}

const char *
nm_vpn_connection_get_banner(NMVpnConnection *self)
{
    g_return_val_if_fail(NM_IS_VPN_CONNECTION(self), NULL);

    return NM_VPN_CONNECTION_GET_PRIVATE(self)->banner;
}

const NML3ConfigData *
nm_vpn_connection_get_l3cd(NMVpnConnection *self)
{
    NMVpnConnectionPrivate *priv;

    g_return_val_if_fail(NM_IS_VPN_CONNECTION(self), NULL);

    priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    if (priv->l3cds_changed) {
        nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
        L3CDType                                l3cd_type;
        int                                     ifindex;

        priv->l3cds_changed = FALSE;

        ifindex = nm_vpn_connection_get_ip_ifindex(self, TRUE);

        if (ifindex > 0) {
            const int default_dns_priority_x[2] = {
                NM_DNS_PRIORITY_DEFAULT_VPN,
                NM_DNS_PRIORITY_DEFAULT_VPN,
            };
            guint32 default_route_table_x[2];
            guint32 default_route_metric_x[2];

            for (l3cd_type = 0; l3cd_type < _L3CD_TYPE_NUM; l3cd_type++) {
                if (l3cd_type == L3CD_TYPE_GW_EXTERN)
                    continue;
                if (!priv->l3cds[l3cd_type])
                    continue;

                if (!l3cd) {
                    default_route_table_x[0] = get_route_table(self, AF_INET6, TRUE);
                    default_route_table_x[1] = get_route_table(self, AF_INET, TRUE);
                    default_route_metric_x[0] =
                        nm_vpn_connection_get_ip_route_metric(self, AF_INET6);
                    default_route_metric_x[1] =
                        nm_vpn_connection_get_ip_route_metric(self, AF_INET);
                    l3cd = _l3cfg_l3cd_new(self, ifindex);
                }

                nm_l3_config_data_merge(l3cd,
                                        priv->l3cds[l3cd_type],
                                        _l3cfg_get_merge_flags(self, l3cd_type),
                                        default_route_table_x,
                                        default_route_metric_x,
                                        NULL,
                                        default_dns_priority_x,
                                        NULL,
                                        NULL);
            }
        }

        nm_l3_config_data_reset(&priv->l3cd_combined, l3cd);
    }

    return priv->l3cd_combined;
}

static int
_get_ifindex_for_device(NMVpnConnection *self)
{
    NMDevice *parent_dev;
    int       ifindex;

    nm_assert(NM_IS_VPN_CONNECTION(self));

    parent_dev = nm_active_connection_get_device(NM_ACTIVE_CONNECTION(self));
    if (!parent_dev)
        return 0;
    ifindex = nm_device_get_ip_ifindex(parent_dev);
    if (ifindex <= 0)
        return 0;

    return ifindex;
}

const char *
nm_vpn_connection_get_ip_iface(NMVpnConnection *self, gboolean fallback_device)
{
    NMVpnConnectionPrivate *priv;

    g_return_val_if_fail(NM_IS_VPN_CONNECTION(self), NULL);

    priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    if (priv->l3cfg_if)
        return nm_l3cfg_get_ifname(priv->l3cfg_if, TRUE);
    if (fallback_device && priv->l3cfg_dev)
        return nm_l3cfg_get_ifname(priv->l3cfg_dev, TRUE);
    return NULL;
}

int
nm_vpn_connection_get_ip_ifindex(NMVpnConnection *self, gboolean fallback_device)
{
    NMVpnConnectionPrivate *priv;

    g_return_val_if_fail(NM_IS_VPN_CONNECTION(self), 0);

    priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    if (priv->ifindex_if > 0)
        return priv->ifindex_if;
    if (fallback_device && priv->ifindex_dev > 0)
        return priv->ifindex_dev;
    return 0;
}

static guint32
_get_vpn_timeout(NMVpnConnection *self)
{
    guint32       timeout;
    NMSettingVpn *s_vpn;

    s_vpn = nm_connection_get_setting_vpn(_get_applied_connection(self));
    g_return_val_if_fail(s_vpn, 60);

    /* Timeout waiting for IP config signal from VPN service
     * It is a configured value or 60 seconds */
    timeout = nm_setting_vpn_get_timeout(s_vpn);
    if (timeout == 0) {
        timeout = nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                              NM_CON_DEFAULT("vpn.timeout"),
                                                              NULL,
                                                              1,
                                                              G_MAXUINT32,
                                                              60);
    }
    return timeout;
}

/*****************************************************************************/

static gboolean
_l3cfg_l3cd_set(NMVpnConnection *self, L3CDType l3cd_type, const NML3ConfigData *l3cd)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    if (nm_l3_config_data_equal(l3cd, priv->l3cds[l3cd_type]))
        return FALSE;

    if (_LOGT_ENABLED()) {
        if (l3cd) {
            char s_name[150];

            /* Seal hear, so that we don't log about an unsealed instance.
             * nm_l3_config_data_reset() anyway seals the instance too. */
            nm_l3_config_data_seal(l3cd);

            _LOGT("l3cd[%s]: set " NM_HASH_OBFUSCATE_PTR_FMT,
                  _l3cd_type_to_string(l3cd_type),
                  NM_HASH_OBFUSCATE_PTR(l3cd));
            nm_l3_config_data_log(
                l3cd,
                nm_sprintf_buf(s_name, "l3cd[%s]", _l3cd_type_to_string(l3cd_type)),
                "vpn-config: ",
                LOGL_TRACE,
                _NMLOG_DOMAIN);
        } else
            _LOGT("l3cd[%s]: unset", _l3cd_type_to_string(l3cd_type));
    }

    nm_l3_config_data_reset(&priv->l3cds_[l3cd_type], l3cd);
    priv->l3cds_changed = TRUE;
    return TRUE;
}

static void
_l3cfg_l3cd_update(NMVpnConnection *self, L3CDType l3cd_type)
{
    NMVpnConnectionPrivate      *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);
    NML3Cfg                     *l3cfg;
    const NML3ConfigData *const *p_l3cd;

    if (NM_IN_SET(l3cd_type, L3CD_TYPE_IP_4, L3CD_TYPE_IP_6, L3CD_TYPE_GENERIC, L3CD_TYPE_STATIC)) {
        l3cfg = priv->l3cfg_if;
        if (!l3cfg) {
            l3cfg = priv->l3cfg_dev;
        }
    } else {
        nm_assert(NM_IN_SET(l3cd_type, L3CD_TYPE_GW_EXTERN));
        l3cfg = priv->l3cfg_dev;
    }

    p_l3cd = &priv->l3cds[l3cd_type];

    if (!l3cfg)
        return;

    if (!*p_l3cd) {
        if (!nm_l3cfg_remove_config_all(l3cfg, p_l3cd))
            return;
        _LOGT("l3cd[%s]: remove-config " NM_HASH_OBFUSCATE_PTR_FMT,
              _l3cd_type_to_string(l3cd_type),
              NM_HASH_OBFUSCATE_PTR(*p_l3cd));
        goto handle_changed;
    }

    if (!nm_l3cfg_add_config(l3cfg,
                             p_l3cd,
                             TRUE,
                             *p_l3cd,
                             NM_L3CFG_CONFIG_PRIORITY_VPN,
                             get_route_table(self, AF_INET, TRUE),
                             get_route_table(self, AF_INET6, TRUE),
                             nm_vpn_connection_get_ip_route_metric(self, AF_INET),
                             nm_vpn_connection_get_ip_route_metric(self, AF_INET6),
                             0,
                             0,
                             NM_DNS_PRIORITY_DEFAULT_VPN,
                             NM_DNS_PRIORITY_DEFAULT_VPN,
                             NM_L3_ACD_DEFEND_TYPE_ONCE,
                             0,
                             NM_L3CFG_CONFIG_FLAGS_NONE,
                             _l3cfg_get_merge_flags(self, l3cd_type)))
        return;

    _LOGT("l3cd[%s]: add-config " NM_HASH_OBFUSCATE_PTR_FMT,
          _l3cd_type_to_string(l3cd_type),
          NM_HASH_OBFUSCATE_PTR(*p_l3cd));

handle_changed:
    nm_l3cfg_commit_on_idle_schedule(l3cfg, NM_L3_CFG_COMMIT_TYPE_AUTO);
}

static void
_l3cfg_l3cd_update_all(NMVpnConnection *self)
{
    L3CDType l3cd_type;

    for (l3cd_type = 0; l3cd_type < _L3CD_TYPE_NUM; l3cd_type++)
        _l3cfg_l3cd_update(self, l3cd_type);
}

static void
_l3cfg_l3cd_clear_all(NMVpnConnection *self)
{
    L3CDType l3cd_type;

    for (l3cd_type = 0; l3cd_type < _L3CD_TYPE_NUM; l3cd_type++)
        _l3cfg_l3cd_set(self, l3cd_type, NULL);

    _l3cfg_l3cd_update_all(self);
}

static void
_l3cfg_clear(NMVpnConnection *self, NML3Cfg *l3cfg)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);
    L3CDType                l3cd_type;
    gboolean                changed = FALSE;

    if (!l3cfg)
        return;

    g_signal_handlers_disconnect_by_func(l3cfg, G_CALLBACK(_l3cfg_notify_cb), self);

    for (l3cd_type = 0; l3cd_type < _L3CD_TYPE_NUM; l3cd_type++) {
        if (nm_l3cfg_remove_config_all(l3cfg, &priv->l3cds[l3cd_type]))
            changed = TRUE;
    }

    if (changed)
        nm_l3cfg_commit_on_idle_schedule(l3cfg, NM_L3_CFG_COMMIT_TYPE_AUTO);
}

/*****************************************************************************/

static void
cancel_get_secrets(NMVpnConnection *self)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    if (priv->secrets_id) {
        _LOGT("secrets: cancel request");
        nm_settings_connection_cancel_secrets(_get_settings_connection(self, FALSE),
                                              priv->secrets_id);
        nm_assert(!priv->secrets_id);
    }
}

static void
_l3cfg_notify_cb(NML3Cfg *l3cfg, const NML3ConfigNotifyData *notify_data, NMVpnConnection *self)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT) {
        if (l3cfg == (priv->l3cfg_if ?: priv->l3cfg_dev) && priv->wait_for_pre_up_state
            && priv->vpn_state < STATE_PRE_UP)
            _set_vpn_state(self, STATE_PRE_UP, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);
    }
}

static gboolean
_set_ip_ifindex(NMVpnConnection *self, int ifindex, gboolean is_if)
{
    NMVpnConnectionPrivate   *priv      = NM_VPN_CONNECTION_GET_PRIVATE(self);
    int                      *p_ifindex = is_if ? &priv->ifindex_if : &priv->ifindex_dev;
    NML3Cfg                 **p_l3cfg   = is_if ? &priv->l3cfg_if : &priv->l3cfg_dev;
    NML3CfgCommitTypeHandle **p_l3cfg_commit_type =
        is_if ? &priv->l3cfg_commit_type_if : &priv->l3cfg_commit_type_dev;
    gs_unref_object NML3Cfg *l3cfg_old = NULL;

    if (ifindex < 0)
        ifindex = nm_assert_unreachable_val(0);

    if (*p_ifindex == ifindex)
        return FALSE;

    _LOGD("set ip-ifindex-%s %d", is_if ? "if" : "dev", ifindex);

    *p_ifindex = ifindex;

    l3cfg_old = g_steal_pointer(p_l3cfg);
    nm_l3cfg_commit_type_clear(l3cfg_old, p_l3cfg_commit_type);
    _l3cfg_clear(self, l3cfg_old);

    if (ifindex > 0) {
        *p_l3cfg = nm_netns_l3cfg_acquire(priv->netns, ifindex);
        g_signal_connect(*p_l3cfg, NM_L3CFG_SIGNAL_NOTIFY, G_CALLBACK(_l3cfg_notify_cb), self);
        *p_l3cfg_commit_type =
            nm_l3cfg_commit_type_register(*p_l3cfg, NM_L3_CFG_COMMIT_TYPE_UPDATE, NULL, "vpn");
    }

    return TRUE;
}

static void
disconnect_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMVpnConnection           *self;
    gs_unref_variant GVariant *res   = NULL;
    gs_free_error GError      *error = NULL;

    res = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (nm_utils_error_is_cancelled(error))
        return;

    self = NM_VPN_CONNECTION(user_data);

    _LOGT("dbus: disconnected%s%s",
          NM_PRINT_FMT_QUOTED2(error, " failed: ", error->message, " with success"));
}

static void
fw_call_cleanup(NMVpnConnection *self)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    if (priv->fw_call) {
        nm_firewalld_manager_cancel_call(priv->fw_call);
        g_warn_if_fail(!priv->fw_call);
        priv->fw_call = NULL;
    }
}

static void
vpn_cleanup(NMVpnConnection *self, NMDevice *parent_dev)
{
    const char *iface;

    /* Remove zone from firewall */
    iface = nm_vpn_connection_get_ip_iface(self, FALSE);
    if (iface) {
        nm_firewalld_manager_remove_from_zone(nm_firewalld_manager_get(), iface, NULL, NULL, NULL);
    }

    /* Cancel pending firewall call */
    fw_call_cleanup(self);

    _l3cfg_l3cd_clear_all(self);
}

static void
dispatcher_pre_down_done(NMDispatcherCallId *call_id, gpointer user_data)
{
    NMVpnConnection        *self = NM_VPN_CONNECTION(user_data);
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    nm_assert(call_id);
    nm_assert(priv->dispatcher_id == call_id);

    priv->dispatcher_id = NULL;
    _set_vpn_state(self,
                   STATE_DISCONNECTED,
                   NM_ACTIVE_CONNECTION_STATE_REASON_USER_DISCONNECTED,
                   FALSE);
}

static void
dispatcher_pre_up_done(NMDispatcherCallId *call_id, gpointer user_data)
{
    NMVpnConnection        *self = NM_VPN_CONNECTION(user_data);
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    nm_assert(call_id);
    nm_assert(priv->dispatcher_id == call_id);

    priv->dispatcher_id = NULL;
    _set_vpn_state(self, STATE_ACTIVATED, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);
}

static void
dispatcher_cleanup(NMVpnConnection *self)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    if (priv->dispatcher_id)
        nm_dispatcher_call_cancel(g_steal_pointer(&priv->dispatcher_id));
}

static void
_set_vpn_state(NMVpnConnection              *self,
               VpnState                      vpn_state,
               NMActiveConnectionStateReason reason,
               gboolean                      quitting)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);
    VpnState                old_vpn_state;
    NMVpnConnectionState    new_external_state;
    NMVpnConnectionState    old_external_state;
    NMDevice     *parent_dev = nm_active_connection_get_device(NM_ACTIVE_CONNECTION(self));
    NMConnection *applied;

    if (vpn_state == priv->vpn_state)
        return;

    old_vpn_state   = priv->vpn_state;
    priv->vpn_state = vpn_state;

    _LOGD("set state: %s (was %s)",
          vpn_state_to_string_a(priv->vpn_state),
          vpn_state_to_string_a(old_vpn_state));

    /* The device gets destroyed by active connection when it enters
     * the deactivated state, so we need to ref it for usage below.
     */
    nm_g_object_ref(parent_dev);

    /* Update active connection base class state */
    nm_active_connection_set_state(NM_ACTIVE_CONNECTION(self),
                                   _state_to_ac_state(vpn_state),
                                   reason);

    /* Clear any in-progress secrets request */
    cancel_get_secrets(self);

    dispatcher_cleanup(self);

    /* The connection gets destroyed by the VPN manager when it enters the
     * disconnected/failed state, but we need to keep it around for a bit
     * to send out signals and handle the dispatcher.  So ref it.
     */
    g_object_ref(self);

    old_external_state = _state_to_nm_vpn_state(old_vpn_state);
    new_external_state = _state_to_nm_vpn_state(priv->vpn_state);
    if (new_external_state != old_external_state) {
        nm_dbus_object_emit_signal(NM_DBUS_OBJECT(self),
                                   &interface_info_vpn_connection,
                                   &signal_info_vpn_state_changed,
                                   "(uu)",
                                   (guint32) new_external_state,
                                   (guint32) reason);
        g_signal_emit(self,
                      signals[INTERNAL_STATE_CHANGED],
                      0,
                      (guint) new_external_state,
                      (guint) old_external_state,
                      (guint) reason);
        _notify(self, PROP_VPN_STATE);
    }

    switch (vpn_state) {
    case STATE_NEED_AUTH:
        /* Do nothing; not part of 'default' because we don't want to touch
         * priv->secrets_req as NEED_AUTH is re-entered during interactive
         * secrets.
         */
        break;
    case STATE_PRE_UP:
        if (!nm_dispatcher_call_vpn(NM_DISPATCHER_ACTION_VPN_PRE_UP,
                                    _get_settings_connection(self, FALSE),
                                    _get_applied_connection(self),
                                    parent_dev,
                                    nm_vpn_connection_get_ip_iface(self, FALSE),
                                    nm_vpn_connection_get_l3cd(self),
                                    dispatcher_pre_up_done,
                                    self,
                                    &priv->dispatcher_id)) {
            /* Just proceed on errors */
            dispatcher_pre_up_done(0, self);
        }
        break;
    case STATE_ACTIVATED:

        nm_clear_g_source_inst(&priv->start_timeout_source);

        applied = _get_applied_connection(self);

        /* Secrets no longer needed now that we're connected */
        nm_active_connection_clear_secrets(NM_ACTIVE_CONNECTION(self));

        /* Let dispatcher scripts know we're up and running */
        nm_dispatcher_call_vpn(NM_DISPATCHER_ACTION_VPN_UP,
                               _get_settings_connection(self, FALSE),
                               applied,
                               parent_dev,
                               nm_vpn_connection_get_ip_iface(self, FALSE),
                               nm_vpn_connection_get_l3cd(self),
                               NULL,
                               NULL,
                               NULL);
        break;
    case STATE_DEACTIVATING:
        applied = _get_applied_connection(self);
        if (quitting) {
            nm_dispatcher_call_vpn_sync(NM_DISPATCHER_ACTION_VPN_PRE_DOWN,
                                        _get_settings_connection(self, FALSE),
                                        applied,
                                        parent_dev,
                                        nm_vpn_connection_get_ip_iface(self, FALSE),
                                        nm_vpn_connection_get_l3cd(self));
        } else {
            if (!nm_dispatcher_call_vpn(NM_DISPATCHER_ACTION_VPN_PRE_DOWN,
                                        _get_settings_connection(self, FALSE),
                                        applied,
                                        parent_dev,
                                        nm_vpn_connection_get_ip_iface(self, FALSE),
                                        nm_vpn_connection_get_l3cd(self),
                                        dispatcher_pre_down_done,
                                        self,
                                        &priv->dispatcher_id)) {
                /* Just proceed on errors */
                dispatcher_pre_down_done(0, self);
            }
        }

        nm_pacrunner_manager_remove_clear(&priv->pacrunner_conf_id);
        break;
    case STATE_FAILED:
    case STATE_DISCONNECTED:
        if (old_vpn_state >= STATE_ACTIVATED && old_vpn_state <= STATE_DEACTIVATING) {
            /* Let dispatcher scripts know we're about to go down */
            if (quitting) {
                nm_dispatcher_call_vpn_sync(NM_DISPATCHER_ACTION_VPN_DOWN,
                                            _get_settings_connection(self, FALSE),
                                            _get_applied_connection(self),
                                            parent_dev,
                                            nm_vpn_connection_get_ip_iface(self, FALSE),
                                            NULL);
            } else {
                nm_dispatcher_call_vpn(NM_DISPATCHER_ACTION_VPN_DOWN,
                                       _get_settings_connection(self, FALSE),
                                       _get_applied_connection(self),
                                       parent_dev,
                                       nm_vpn_connection_get_ip_iface(self, FALSE),
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL);
            }
        }

        if (priv->dbus.bus_name)
            _dbus_connection_call(self, "Disconnect", NULL, G_VARIANT_TYPE("()"), disconnect_cb);

        vpn_cleanup(self, parent_dev);
        /* fall-through */
    default:
        priv->secrets_idx = SECRETS_REQ_SYSTEM;
        break;
    }

    g_object_unref(self);
    if (parent_dev)
        g_object_unref(parent_dev);
}

static gboolean
_service_and_connection_can_persist(NMVpnConnection *self)
{
    return NM_VPN_CONNECTION_GET_PRIVATE(self)->connection_can_persist
           && NM_VPN_CONNECTION_GET_PRIVATE(self)->service_can_persist;
}

static gboolean
_connection_only_can_persist(NMVpnConnection *self)
{
    return NM_VPN_CONNECTION_GET_PRIVATE(self)->connection_can_persist
           && !NM_VPN_CONNECTION_GET_PRIVATE(self)->service_can_persist;
}

static void
device_state_changed(NMActiveConnection *active,
                     NMDevice           *device,
                     NMDeviceState       new_state,
                     NMDeviceState       old_state)
{
    if (_service_and_connection_can_persist(NM_VPN_CONNECTION(active))) {
        if (new_state <= NM_DEVICE_STATE_DISCONNECTED || new_state == NM_DEVICE_STATE_FAILED) {
            nm_active_connection_set_device(active, NULL);
        }
        return;
    }

    if (new_state <= NM_DEVICE_STATE_DISCONNECTED) {
        _set_vpn_state(NM_VPN_CONNECTION(active),
                       STATE_DISCONNECTED,
                       NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED,
                       FALSE);
    } else if (new_state == NM_DEVICE_STATE_FAILED) {
        _set_vpn_state(NM_VPN_CONNECTION(active),
                       STATE_FAILED,
                       NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED,
                       FALSE);
    }

    /* FIXME: map device DEACTIVATING state to VPN DEACTIVATING state and
     * block device deactivation on VPN deactivation.
     */
}

static gboolean
_parent_device_l3cd_add_gateway_route(NML3ConfigData *l3cd,
                                      int             addr_family,
                                      NMDevice       *parent_device,
                                      const NMIPAddr *vpn_gw,
                                      NMPlatform     *platform)
{
    const int                       IS_IPv4        = NM_IS_IPv4(addr_family);
    NMIPAddr                        parent_gw      = NM_IP_ADDR_INIT;
    gboolean                        has_parent_gw  = FALSE;
    nm_auto_nmpobj const NMPObject *route_resolved = NULL;
    int                             ifindex;
    NMPlatformIPXRoute              route;
    int                             r;

    nm_assert(NM_IS_L3_CONFIG_DATA(l3cd));
    g_return_val_if_fail(vpn_gw, FALSE);

    if (nm_ip_addr_is_null(addr_family, vpn_gw))
        return FALSE;

    ifindex = nm_l3_config_data_get_ifindex(l3cd);

    nm_assert(ifindex > 0);

    if (parent_device && ifindex != nm_device_get_ip_ifindex(parent_device))
        parent_device = 0;

    /* Ask kernel how to reach @vpn_gw. We can only inject the route in
     * @parent_device, so whatever we resolve, it can only be on @ifindex. */
    r = nm_platform_ip_route_get(platform,
                                 addr_family,
                                 vpn_gw,
                                 ifindex,
                                 (NMPObject **) &route_resolved);
    if (r >= 0) {
        const NMPlatformIPXRoute *rx = NMP_OBJECT_CAST_IPX_ROUTE(route_resolved);
        const NMPObject          *obj;

        if (rx->rx.ifindex == ifindex && nm_platform_route_table_is_main(rx->rx.table_coerced)) {
            gconstpointer gw = nm_platform_ip_route_get_gateway(addr_family, &rx->rx);

            /* `ip route get` always resolves the route, even if the destination is unreachable.
             * In which case, it pretends the destination is directly reachable.
             *
             * So, only accept direct routes if @vpn_gw is a private network
             * or if the parent device also has a direct default route */
            if (!nm_ip_addr_is_null(addr_family, gw)) {
                nm_ip_addr_set(addr_family, &parent_gw, gw);
                has_parent_gw = TRUE;
            } else if (nm_ip_addr_is_site_local(addr_family, vpn_gw))
                has_parent_gw = TRUE;
            else if ((obj = nm_device_get_best_default_route(parent_device, addr_family))
                     && nm_ip_addr_is_null(
                         addr_family,
                         nm_platform_ip_route_get_gateway(addr_family,
                                                          NMP_OBJECT_CAST_IP_ROUTE(obj))))
                has_parent_gw = TRUE;
        }
    }

    if (!has_parent_gw)
        return FALSE;

    if (IS_IPv4) {
        route.r4 = (NMPlatformIP4Route){
            .ifindex    = ifindex,
            .network    = vpn_gw->addr4,
            .plen       = 32,
            .gateway    = parent_gw.addr4,
            .rt_source  = NM_IP_CONFIG_SOURCE_VPN,
            .metric_any = TRUE,
        };
    } else {
        route.r6 = (NMPlatformIP6Route){
            .ifindex    = ifindex,
            .network    = vpn_gw->addr6,
            .plen       = 128,
            .gateway    = parent_gw.addr6,
            .rt_source  = NM_IP_CONFIG_SOURCE_VPN,
            .metric_any = TRUE,
        };
    }
    nm_l3_config_data_add_route(l3cd, addr_family, NULL, &route.rx);

    if (!nm_ip_addr_is_null(addr_family, &parent_gw)) {
        /* Ensure there's a route to the parent device's gateway through the
         * parent device, since if the VPN claims the default route and the VPN
         * routes include a subnet that matches the parent device's subnet,
         * the parent device's gateway would get routed through the VPN and fail.
         */
        if (IS_IPv4) {
            route.r4 = (NMPlatformIP4Route){
                .network    = parent_gw.addr4,
                .plen       = 32,
                .rt_source  = NM_IP_CONFIG_SOURCE_VPN,
                .metric_any = TRUE,
            };
        } else {
            route.r6 = (NMPlatformIP6Route){
                .network    = parent_gw.addr6,
                .plen       = 128,
                .rt_source  = NM_IP_CONFIG_SOURCE_VPN,
                .metric_any = TRUE,
            };
        }
        nm_l3_config_data_add_route(l3cd, addr_family, NULL, &route.rx);
    }

    return TRUE;
}

static gboolean
_l3cfg_l3cd_gw_extern_update(NMVpnConnection *self)
{
    NMVpnConnectionPrivate                 *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    int                                     ifindex;
    gboolean                                changed;
    int                                     IS_IPv4;

    ifindex = priv->ifindex_dev;
    if (ifindex <= 0)
        goto set;

    l3cd = _l3cfg_l3cd_new(self, ifindex);

    changed = FALSE;
    for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
        const int          addr_family = IS_IPv4 ? AF_INET : AF_INET6;
        NMSettingIPConfig *s_ip;

        s_ip = nm_connection_get_setting_ip_config(_get_applied_connection(self), addr_family);
        if (s_ip && nm_setting_ip_config_get_auto_route_ext_gw(s_ip) == NM_TERNARY_FALSE) {
            _LOGD("IPv%c route to the external gateway have been deactivated via auto-route-ext-gw "
                  "setting",
                  nm_utils_addr_family_to_char(addr_family));
            continue;
        }

        if (_parent_device_l3cd_add_gateway_route(
                l3cd,
                IS_IPv4 ? AF_INET : AF_INET6,
                nm_active_connection_get_device(NM_ACTIVE_CONNECTION(self)),
                &priv->ip_data_x[IS_IPv4].gw_external,
                nm_netns_get_platform(priv->netns)))
            changed = TRUE;
    }
    if (!changed)
        nm_clear_pointer(&l3cd, nm_l3_config_data_unref);

set:
    if (!_l3cfg_l3cd_set(self, L3CD_TYPE_GW_EXTERN, l3cd))
        return FALSE;

    return TRUE;
}

const char *
nm_vpn_connection_get_service(NMVpnConnection *self)
{
    NMSettingVpn *s_vpn;

    s_vpn = nm_connection_get_setting_vpn(_get_applied_connection(self));
    return nm_setting_vpn_get_service_type(s_vpn);
}

static void
_apply_config(NMVpnConnection *self)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    _LOGT("apply-config");

    if (priv->ifindex_if > 0) {
        nm_platform_link_change_flags(nm_netns_get_platform(priv->netns),
                                      priv->ifindex_if,
                                      IFF_UP,
                                      TRUE);
    }

    if (priv->ifindex_dev > 0) {
        nm_platform_link_change_flags(nm_netns_get_platform(priv->netns),
                                      priv->ifindex_dev,
                                      IFF_UP,
                                      TRUE);
    }

    if (priv->ifindex_if > 0 && priv->ifindex_if != priv->ifindex_dev) {
        if (priv->mtu
            && priv->mtu
                   != nm_platform_link_get_mtu(nm_netns_get_platform(priv->netns),
                                               priv->ifindex_if))
            nm_platform_link_set_mtu(nm_netns_get_platform(priv->netns),
                                     priv->ifindex_if,
                                     priv->mtu);
    }

    priv->wait_for_pre_up_state = TRUE;

    _l3cfg_l3cd_update_all(self);
}

static void
fw_change_zone_cb(NMFirewalldManager       *firewalld_manager,
                  NMFirewalldManagerCallId *call_id,
                  GError                   *error,
                  gpointer                  user_data)
{
    NMVpnConnection        *self = user_data;
    NMVpnConnectionPrivate *priv;

    g_return_if_fail(NM_IS_VPN_CONNECTION(self));

    priv = NM_VPN_CONNECTION_GET_PRIVATE(self);
    g_return_if_fail(priv->fw_call == call_id);

    priv->fw_call = NULL;

    if (nm_utils_error_is_cancelled(error))
        return;

    _apply_config(self);
}

static void
_check_complete(NMVpnConnection *self, gboolean success)
{
    NMVpnConnectionPrivate                 *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    NMConnection                           *connection;
    NMSettingConnection                    *s_con;
    const char                             *zone;
    const char                             *iface;

    if (priv->vpn_state < STATE_IP_CONFIG_GET || priv->vpn_state > STATE_ACTIVATED)
        return;

    if (success) {
        if (!priv->generic_config_received
            || (priv->ip_data_4.enabled && !priv->l3cds[L3CD_TYPE_IP_4])
            || (priv->ip_data_6.enabled && !priv->l3cds[L3CD_TYPE_IP_6])) {
            /* Need to wait more config. */
            return;
        }
    }

    nm_clear_g_source_inst(&priv->connect_timeout_source);

    if (!success) {
        _LOGW("did not receive valid IP config information");
        _set_vpn_state(self,
                       STATE_FAILED,
                       NM_ACTIVE_CONNECTION_STATE_REASON_IP_CONFIG_INVALID,
                       FALSE);
        return;
    }

    connection = _get_applied_connection(self);

    l3cd = nm_l3_config_data_new_from_connection(nm_netns_get_multi_idx(priv->netns),
                                                 nm_vpn_connection_get_ip_ifindex(self, TRUE),
                                                 connection);
    _l3cfg_l3cd_set(self, L3CD_TYPE_STATIC, l3cd);

    _l3cfg_l3cd_gw_extern_update(self);

    iface = nm_vpn_connection_get_ip_iface(self, FALSE);

    /* Add the tunnel interface to the specified firewall zone */
    if (iface) {
        s_con = nm_connection_get_setting_connection(connection);
        zone  = nm_setting_connection_get_zone(s_con);

        fw_call_cleanup(self);
        priv->fw_call = nm_firewalld_manager_add_or_change_zone(nm_firewalld_manager_get(),
                                                                iface,
                                                                zone,
                                                                FALSE,
                                                                fw_change_zone_cb,
                                                                self);
        return;
    }

    _apply_config(self);
}

static gboolean
_vardict_to_addr(int addr_family, GVariant *dict, const char *key, gpointer dst)
{
    guint32 u32;

    if (!NM_IS_IPv4(addr_family)) {
        gs_unref_variant GVariant *v = NULL;

        if (g_variant_lookup(dict, key, "@ay", &v)) {
            if (nm_ip_addr_set_from_variant(AF_INET6, dst, v, NULL))
                return TRUE;
        }
        nm_ip_addr_set(AF_INET6, dst, &nm_ip_addr_zero.addr6);
        return FALSE;
    }

    /* The way we encode IPv4 addresses is not endianness safe. It works well enough
     * on the same host and as we know that the VPN plugin sends the address in the
     * same endianness that we expect.
     *
     * But we read a u32 (natively), and that happens to be already in the right
     * endianness to be used directly as IPv4 address. */
    if (g_variant_lookup(dict, key, "u", &u32)) {
        unaligned_write_ne32(dst, u32);
        return TRUE;
    }
    unaligned_write_ne32(dst, 0);
    return FALSE;
}

guint32
nm_vpn_connection_get_ip_route_metric(NMVpnConnection *self, int addr_family)
{
    gint64        route_metric = -1;
    NMConnection *applied;

    applied = _get_applied_connection(self);
    if (!applied)
        g_return_val_if_reached(NM_VPN_ROUTE_METRIC_DEFAULT);

    route_metric = nm_setting_ip_config_get_route_metric(
        nm_connection_get_setting_ip_config(applied, addr_family));
    return (route_metric >= 0) ? route_metric : NM_VPN_ROUTE_METRIC_DEFAULT;
}

static guint32
get_route_table(NMVpnConnection *self, int addr_family, gboolean fallback_main)
{
    NMConnection      *connection;
    NMSettingIPConfig *s_ip;
    guint32            route_table = 0;

    nm_assert(NM_IN_SET(addr_family, AF_INET, AF_INET6));

    connection = _get_applied_connection(self);
    if (connection) {
        s_ip = nm_connection_get_setting_ip_config(connection, addr_family);
        if (s_ip)
            route_table = nm_setting_ip_config_get_route_table(s_ip);
    }

    return route_table ?: (fallback_main ? RT_TABLE_MAIN : 0);
}

static gboolean
connect_timeout_cb(gpointer user_data)
{
    NMVpnConnection        *self = NM_VPN_CONNECTION(user_data);
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->connect_timeout_source);

    /* Cancel activation if it's taken too long */
    if (priv->vpn_state == STATE_CONNECT || priv->vpn_state == STATE_IP_CONFIG_GET) {
        _LOGW("connect timeout exceeded");
        _set_vpn_state(self,
                       STATE_FAILED,
                       NM_ACTIVE_CONNECTION_STATE_REASON_CONNECT_TIMEOUT,
                       FALSE);
    }

    return G_SOURCE_CONTINUE;
}

static void
connect_success(NMVpnConnection *self)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    priv->connect_timeout_source =
        nm_g_timeout_add_seconds_source(_get_vpn_timeout(self), connect_timeout_cb, self);

    nm_clear_pointer(&priv->connect_hash, g_variant_unref);
}

static void
connect_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMVpnConnection           *self;
    gs_unref_variant GVariant *res   = NULL;
    gs_free_error GError      *error = NULL;

    res = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (nm_utils_error_is_cancelled(error))
        return;

    self = NM_VPN_CONNECTION(user_data);

    if (error) {
        g_dbus_error_strip_remote_error(error);
        _LOGW("failed to connect: '%s'", error->message);
        _set_vpn_state(self,
                       STATE_FAILED,
                       NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED,
                       FALSE);
    } else
        connect_success(self);
}

static void
connect_interactive_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMVpnConnection           *self;
    NMVpnConnectionPrivate    *priv;
    gs_unref_variant GVariant *res   = NULL;
    gs_free_error GError      *error = NULL;

    res = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (nm_utils_error_is_cancelled(error))
        return;

    self = NM_VPN_CONNECTION(user_data);
    priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    if (g_error_matches(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_INTERACTIVE_NOT_SUPPORTED)
        && priv->dbus.bus_name) {
        _LOGD("connect: falling back to non-interactive connect");
        _dbus_connection_call(self,
                              "Connect",
                              g_variant_new("(@a{sa{sv}})", priv->connect_hash),
                              G_VARIANT_TYPE("()"),
                              connect_cb);
        return;
    }

    if (error) {
        _LOGW("connect: failed to connect interactively: '%s'", error->message);
        _set_vpn_state(self,
                       STATE_FAILED,
                       NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED,
                       FALSE);
        return;
    }

    _LOGD("connect: success from ConnectInteractive");
    connect_success(self);
}

/* Add a username to a hashed connection */
static GVariant *
_hash_with_username(NMConnection *connection, const char *username)
{
    gs_unref_object NMConnection *dup = NULL;
    NMSettingVpn                 *s_vpn;

    /* Shortcut if we weren't given a username or if there already was one in
     * the VPN setting; don't bother duplicating the connection and everything.
     */
    s_vpn = nm_connection_get_setting_vpn(connection);
    g_return_val_if_fail(s_vpn, NULL);

    if (!username || nm_setting_vpn_get_user_name(s_vpn))
        return nm_connection_to_dbus(connection, NM_CONNECTION_SERIALIZE_ALL);

    dup = nm_simple_connection_new_clone(connection);
    nm_assert(dup);

    s_vpn = nm_connection_get_setting_vpn(dup);
    g_return_val_if_fail(s_vpn, NULL);

    g_object_set(s_vpn, NM_SETTING_VPN_USER_NAME, username, NULL);

    return nm_connection_to_dbus(dup, NM_CONNECTION_SERIALIZE_ALL);
}

static void
really_activate(NMVpnConnection *self, const char *username)
{
    NMVpnConnectionPrivate *priv;
    GVariantBuilder         details;

    g_return_if_fail(NM_IS_VPN_CONNECTION(self));

    priv = NM_VPN_CONNECTION_GET_PRIVATE(self);
    g_return_if_fail(priv->vpn_state == STATE_NEED_AUTH);

    nm_clear_pointer(&priv->connect_hash, g_variant_unref);
    priv->connect_hash = _hash_with_username(_get_applied_connection(self), username);
    g_variant_ref_sink(priv->connect_hash);

    if (!priv->dbus.bus_name) {
        _set_vpn_state(self,
                       STATE_FAILED,
                       NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_STOPPED,
                       FALSE);
        return;
    }

    /* If at least one agent doesn't support VPN hints, then we can't use
     * ConnectInteractive(), because that agent won't be able to pass hints
     * from the VPN plugin's interactive secrets requests to the VPN authentication
     * dialog and we won't get the secrets we need.  In this case fall back to
     * the old Connect() call.
     */
    if (nm_agent_manager_all_agents_have_capability(
            nm_agent_manager_get(),
            nm_active_connection_get_subject(NM_ACTIVE_CONNECTION(self)),
            NM_SECRET_AGENT_CAPABILITY_VPN_HINTS)) {
        _LOGD("connect: allowing interactive secrets as all agents have that capability");
        g_variant_builder_init(&details, G_VARIANT_TYPE_VARDICT);
        _dbus_connection_call(self,
                              "ConnectInteractive",
                              g_variant_new("(@a{sa{sv}}a{sv})", priv->connect_hash, &details),
                              G_VARIANT_TYPE("()"),
                              connect_interactive_cb);
    } else {
        _LOGD(
            "connect: calling old Connect function as not all agents support interactive secrets");
        _dbus_connection_call(self,
                              "Connect",
                              g_variant_new("(@a{sa{sv}})", priv->connect_hash),
                              G_VARIANT_TYPE("()"),
                              connect_cb);
    }

    _set_vpn_state(self, STATE_CONNECT, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);
}

static void
_dbus_signal_failure_cb(NMVpnConnection *self, guint32 reason)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    _LOGW("dbus: failure: %s (%d)", vpn_plugin_failure_to_string_a(reason), reason);

    switch (reason) {
    case NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED:
        priv->failure_reason = NM_ACTIVE_CONNECTION_STATE_REASON_LOGIN_FAILED;
        break;
    case NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG:
        priv->failure_reason = NM_ACTIVE_CONNECTION_STATE_REASON_IP_CONFIG_INVALID;
        break;
    default:
        priv->failure_reason = NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN;
        break;
    }
}

static void
_dbus_signal_state_changed_cb(NMVpnConnection *self, guint32 new_service_state)
{
    NMVpnConnectionPrivate *priv              = NM_VPN_CONNECTION_GET_PRIVATE(self);
    NMVpnServiceState       old_service_state = priv->service_state;

    _LOGD("dbus: state changed: %s (%d)",
          vpn_service_state_to_string_a(new_service_state),
          new_service_state);
    priv->service_state = new_service_state;

    if (new_service_state == NM_VPN_SERVICE_STATE_STOPPED) {
        if ((priv->vpn_state >= STATE_WAITING) && (priv->vpn_state <= STATE_ACTIVATED)) {
            VpnState old_state = priv->vpn_state;

            _set_vpn_state(self, STATE_FAILED, priv->failure_reason, FALSE);

            /* Reset the failure reason */
            priv->failure_reason = NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN;

            /* If the connection failed, the service cannot persist, but the
             * connection can persist, ask listeners to re-activate the connection.
             */
            if (old_state == STATE_ACTIVATED && priv->vpn_state == STATE_FAILED
                && _connection_only_can_persist(self))
                g_signal_emit(self, signals[INTERNAL_RETRY_AFTER_FAILURE], 0);
        }
    } else if (new_service_state == NM_VPN_SERVICE_STATE_STARTING
               && old_service_state == NM_VPN_SERVICE_STATE_STARTED) {
        /* The VPN service got disconnected and is attempting to reconnect */
        _set_vpn_state(self,
                       STATE_CONNECT,
                       NM_ACTIVE_CONNECTION_STATE_REASON_CONNECT_TIMEOUT,
                       FALSE);
    }
}

static gboolean
_config_process_generic(NMVpnConnection *self, GVariant *dict)
{
    nm_auto_g_object_thaw_notify GObject   *self_thaw = NULL;
    NMVpnConnectionPrivate                 *priv      = NM_VPN_CONNECTION_GET_PRIVATE(self);
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd      = NULL;
    int                                     IS_IPv4;
    int                                     ip_ifindex = 0;
    const char                             *v_str;
    guint32                                 v_u32;
    gboolean                                v_b;

    if (g_variant_lookup(dict, NM_VPN_PLUGIN_CONFIG_TUNDEV, "&s", &v_str)) {
        const char *iface = NULL;

        /* Backwards compat with NM-openswan/libreswan */
        if (!NM_IN_STRSET(v_str, "", "_none_"))
            iface = v_str;

        if (iface) {
            NMPlatform *platform = nm_netns_get_platform(priv->netns);

            ip_ifindex = nm_platform_link_get_ifindex(platform, iface);
            if (ip_ifindex <= 0) {
                nm_platform_process_events(platform);
                ip_ifindex = nm_platform_link_get_ifindex(platform, iface);
            }
            if (ip_ifindex <= 0) {
                _LOGW("config: failed to look up VPN interface index for \"%s\"", iface);
                return FALSE;
            }
        }
    }

    self_thaw = nm_g_object_freeze_notify(self);

    _set_ip_ifindex(self, ip_ifindex, TRUE);
    _set_ip_ifindex(self, _get_ifindex_for_device(self), FALSE);

    ip_ifindex = nm_vpn_connection_get_ip_ifindex(self, TRUE);
    if (ip_ifindex <= 0) {
        _LOGW("config: no ip-ifindex for the VPN");
        return FALSE;
    }

    for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
        NML3Cfg                    *l3cfg        = priv->l3cfg_if ?: priv->l3cfg_dev;
        gs_unref_object NMIPConfig *ipconfig_old = NULL;

        ipconfig_old = g_steal_pointer(&priv->ip_data_x[IS_IPv4].ip_config);
        if (l3cfg) {
            priv->ip_data_x[IS_IPv4].ip_config =
                nm_l3cfg_ipconfig_acquire(l3cfg, IS_IPv4 ? AF_INET : AF_INET6);
        }
        g_object_notify(G_OBJECT(self),
                        IS_IPv4 ? NM_ACTIVE_CONNECTION_IP4_CONFIG
                                : NM_ACTIVE_CONNECTION_IP6_CONFIG);
    }

    if (g_variant_lookup(dict, NM_VPN_PLUGIN_CAN_PERSIST, "b", &v_b) && v_b) {
        /* Defaults to FALSE, so only let service indicate TRUE */
        priv->service_can_persist = TRUE;
    }

    if (!g_variant_lookup(dict, NM_VPN_PLUGIN_CONFIG_BANNER, "&s", &v_str))
        v_str = NULL;
    if (nm_strdup_reset(&priv->banner, v_str))
        _notify(self, PROP_BANNER);

    _vardict_to_addr(AF_INET, dict, NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, &priv->ip_data_4.gw_external);
    _vardict_to_addr(AF_INET6,
                     dict,
                     NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY,
                     &priv->ip_data_6.gw_external);

    if (nm_ip_addr_is_null(AF_INET, &priv->ip_data_4.gw_external)
        && nm_ip_addr_is_null(AF_INET6, &priv->ip_data_6.gw_external)) {
        _LOGW("config: no VPN gateway address received");
        return FALSE;
    }

    l3cd = _l3cfg_l3cd_new(self, ip_ifindex);

    if (g_variant_lookup(dict, NM_VPN_PLUGIN_CONFIG_PROXY_PAC, "&s", &v_str)) {
        nm_l3_config_data_set_proxy_method(l3cd, NM_PROXY_CONFIG_METHOD_AUTO);
        nm_l3_config_data_set_proxy_pac_url(l3cd, v_str);
    } else
        nm_l3_config_data_set_proxy_method(l3cd, NM_PROXY_CONFIG_METHOD_NONE);

    if (g_variant_lookup(dict, NM_VPN_PLUGIN_CONFIG_MTU, "u", &v_u32))
        priv->mtu = v_u32;
    else
        priv->mtu = 0;

    priv->generic_config_received = TRUE;

    nm_g_object_thaw_notify_clear(&self_thaw);

    _l3cfg_l3cd_set(self, L3CD_TYPE_GENERIC, l3cd);

    return TRUE;
}

static void
_dbus_signal_config_cb(NMVpnConnection *self, GVariant *dict)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);
    gboolean                v_b;

    g_return_if_fail(dict);

    if (!g_variant_is_of_type(dict, G_VARIANT_TYPE_VARDICT)) {
        _LOGD("config: ignore invalid configuration type");
        return;
    }

    if (priv->vpn_state < STATE_NEED_AUTH) {
        /* Only list to this signals during and after connection */
        _LOGD("config: ignore configuration before need-auth state");
        return;
    }

    if (g_variant_lookup(dict, NM_VPN_PLUGIN_CONFIG_HAS_IP4, "b", &v_b))
        priv->ip_data_4.enabled = v_b;
    else
        priv->ip_data_4.enabled = FALSE;

    if (g_variant_lookup(dict, NM_VPN_PLUGIN_CONFIG_HAS_IP6, "b", &v_b))
        priv->ip_data_6.enabled = v_b;
    else
        priv->ip_data_6.enabled = FALSE;

    _LOGD("config: reply received (IPv4:%s(%s), IPv6:%s(%s))",
          priv->ip_data_4.enabled ? "on" : "off",
          priv->ip_data_4.method_auto ? "auto" : "disabled",
          priv->ip_data_4.enabled ? "on" : "off",
          priv->ip_data_6.method_auto ? "auto" : "disabled");

    if (!priv->ip_data_4.method_auto)
        priv->ip_data_4.enabled = FALSE;
    if (!priv->ip_data_6.method_auto)
        priv->ip_data_6.enabled = FALSE;

    if (priv->vpn_state == STATE_CONNECT)
        _set_vpn_state(self, STATE_IP_CONFIG_GET, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);

    if (!_config_process_generic(self, dict)) {
        _check_complete(self, FALSE);
        return;
    }

    _check_complete(self, TRUE);
}

static void
_dbus_signal_ip_config_cb(NMVpnConnection *self, int addr_family, GVariant *dict)
{
    const int                               IS_IPv4 = NM_IS_IPv4(addr_family);
    NMVpnConnectionPrivate                 *priv    = NM_VPN_CONNECTION_GET_PRIVATE(self);
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd    = NULL;
    GVariantIter                           *var_iter;
    guint32                                 u32;
    const char                             *v_str;
    NMIPAddr                                v_addr;
    GVariant                               *v;
    gboolean                                v_b;
    int                                     ip_ifindex;
    guint32                                 mss = 0;
    gboolean                                never_default;
    NMPlatformIPXAddress                    address;

    g_return_if_fail(dict && g_variant_is_of_type(dict, G_VARIANT_TYPE_VARDICT));

    if (priv->vpn_state < STATE_NEED_AUTH) {
        _LOGD("config%c: ignoring, the connection is not in need-auth state",
              nm_utils_addr_family_to_char(addr_family));
        return;
    }

    if (priv->vpn_state > STATE_ACTIVATED) {
        _LOGD("config%c: ignoring, the connection is no longer active",
              nm_utils_addr_family_to_char(addr_family));
        return;
    }

    if (IS_IPv4) {
        if (priv->generic_config_received) {
            _LOGD("config4: reply received");

            if (g_variant_n_children(dict) == 0) {
                priv->ip_data_4.enabled = FALSE;
                _check_complete(self, TRUE);
                return;
            }
        } else {
            _LOGD("config4: reply received (old style)");

            /* In the old API, the generic and IPv4 configuration items
             * were mixed together.
             */
            if (!_config_process_generic(self, dict)) {
                _check_complete(self, FALSE);
                return;
            }

            if (priv->ip_data_4.method_auto)
                priv->ip_data_4.enabled = TRUE;
            priv->ip_data_6.enabled = FALSE;
        }
    } else {
        _LOGD("config6: reply received");

        if (g_variant_n_children(dict) == 0) {
            priv->ip_data_6.enabled = FALSE;
            _check_complete(self, TRUE);
            return;
        }
    }

    if (priv->vpn_state == STATE_CONNECT) {
        _set_vpn_state(self, STATE_IP_CONFIG_GET, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);
    }

    if (!priv->ip_data_x[IS_IPv4].enabled) {
        _check_complete(self, TRUE);
        return;
    }

    ip_ifindex = nm_vpn_connection_get_ip_ifindex(self, TRUE);
    if (ip_ifindex <= 0)
        g_return_if_reached();

    l3cd = _l3cfg_l3cd_new(self, ip_ifindex);

    nm_l3_config_data_set_dns_priority(l3cd, AF_INET, NM_DNS_PRIORITY_DEFAULT_VPN);

    if (IS_IPv4) {
        address.a4 = (NMPlatformIP4Address){
            .plen = 24,
        };
    } else {
        address.a6 = (NMPlatformIP6Address){
            .plen = 128,
        };
    }

    _vardict_to_addr(addr_family,
                     dict,
                     IS_IPv4 ? NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY
                             : NM_VPN_PLUGIN_IP6_CONFIG_INT_GATEWAY,
                     &priv->ip_data_x[IS_IPv4].gw_internal);

    _vardict_to_addr(addr_family,
                     dict,
                     IS_IPv4 ? NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS : NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS,
                     address.ax.address_ptr);

    if (!_vardict_to_addr(addr_family,
                          dict,
                          IS_IPv4 ? NM_VPN_PLUGIN_IP4_CONFIG_PTP : NM_VPN_PLUGIN_IP6_CONFIG_PTP,
                          nm_platform_ip_address_get_peer_address(addr_family, &address.ax))) {
        if (IS_IPv4)
            address.a4.peer_address = address.a4.address;
    }

    if (g_variant_lookup(dict,
                         IS_IPv4 ? NM_VPN_PLUGIN_IP4_CONFIG_PREFIX
                                 : NM_VPN_PLUGIN_IP6_CONFIG_PREFIX,
                         "u",
                         &u32))
        address.ax.plen = u32;

    if (address.ax.plen > 0 && address.ax.plen <= (IS_IPv4 ? 32 : 128)
        && !nm_ip_addr_is_null(addr_family, &address.ax.address_ptr)) {
        address.ax.addr_source = NM_IP_CONFIG_SOURCE_VPN;
        nm_l3_config_data_add_address(l3cd, addr_family, NULL, &address.ax);
    } else {
        _LOGW("invalid IP%c config received: no valid IP address/prefix",
              nm_utils_addr_family_to_char(addr_family));
        _check_complete(self, FALSE);
        return;
    }

    if (IS_IPv4) {
        if (g_variant_lookup(dict, NM_VPN_PLUGIN_IP4_CONFIG_DNS, "au", &var_iter)) {
            while (g_variant_iter_next(var_iter, "u", &u32))
                nm_l3_config_data_add_nameserver_detail(l3cd, addr_family, &u32, NULL);
            g_variant_iter_free(var_iter);
        }
    } else {
        if (g_variant_lookup(dict, NM_VPN_PLUGIN_IP6_CONFIG_DNS, "aay", &var_iter)) {
            while (g_variant_iter_next(var_iter, "@ay", &v)) {
                if (nm_ip_addr_set_from_variant(AF_INET6, &v_addr, v, NULL))
                    nm_l3_config_data_add_nameserver_detail(l3cd, addr_family, &v_addr, NULL);
                g_variant_unref(v);
            }
            g_variant_iter_free(var_iter);
        }
    }

    if (IS_IPv4) {
        if (g_variant_lookup(dict, NM_VPN_PLUGIN_IP4_CONFIG_NBNS, "au", &var_iter)) {
            while (g_variant_iter_next(var_iter, "u", &u32))
                nm_l3_config_data_add_wins(l3cd, u32);
            g_variant_iter_free(var_iter);
        }
    }

    if (g_variant_lookup(dict,
                         IS_IPv4 ? NM_VPN_PLUGIN_IP4_CONFIG_MSS : NM_VPN_PLUGIN_IP6_CONFIG_MSS,
                         "u",
                         &u32))
        mss = u32;

    if (g_variant_lookup(dict,
                         IS_IPv4 ? NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN
                                 : NM_VPN_PLUGIN_IP6_CONFIG_DOMAIN,
                         "&s",
                         &v_str))
        nm_l3_config_data_add_domain(l3cd, addr_family, v_str);

    if (g_variant_lookup(dict,
                         IS_IPv4 ? NM_VPN_PLUGIN_IP4_CONFIG_DOMAINS
                                 : NM_VPN_PLUGIN_IP6_CONFIG_DOMAINS,
                         "as",
                         &var_iter)) {
        while (g_variant_iter_next(var_iter, "&s", &v_str))
            nm_l3_config_data_add_domain(l3cd, addr_family, v_str);
        g_variant_iter_free(var_iter);
    }

    if (g_variant_lookup(dict,
                         IS_IPv4 ? NM_VPN_PLUGIN_IP4_CONFIG_PRESERVE_ROUTES
                                 : NM_VPN_PLUGIN_IP6_CONFIG_PRESERVE_ROUTES,
                         "b",
                         &v_b)
        && v_b) {
        if (priv->l3cds[L3CD_TYPE_IP_X(IS_IPv4)]) {
            NMDedupMultiIter ipconf_iter;
            const NMPObject *route;

            nm_l3_config_data_iter_obj_for_each (&ipconf_iter,
                                                 priv->l3cds[L3CD_TYPE_IP_X(IS_IPv4)],
                                                 &route,
                                                 NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4))
                nm_l3_config_data_add_route(l3cd, addr_family, route, NULL);
        }
    } else if (IS_IPv4 ? g_variant_lookup(dict, NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, "aau", &var_iter)
                       : g_variant_lookup(dict,
                                          NM_VPN_PLUGIN_IP6_CONFIG_ROUTES,
                                          "a(ayuayu)",
                                          &var_iter)) {
        _nm_unused nm_auto_free_variant_iter GVariantIter *var_iter_ref_owner = var_iter;
        NMPlatformIPXRoute                                 route              = {};
        guint32                                            plen;
        GVariant                                          *next_hop;
        GVariant                                          *dest;
        guint32                                            prefix;
        guint32                                            metric;

        if (IS_IPv4) {
            while (g_variant_iter_next(var_iter, "@au", &v)) {
                _nm_unused gs_unref_variant GVariant *v_ref_owner = v;

                switch (g_variant_n_children(v)) {
                case 5:
                    g_variant_get_child(v, 4, "u", &route.r4.pref_src);
                    /* fall-through */
                case 4:
                    g_variant_get_child(v, 0, "u", &route.r4.network);
                    g_variant_get_child(v, 1, "u", &plen);
                    g_variant_get_child(v, 2, "u", &route.r4.gateway);
                    /* 4th item is unused route metric */
                    route.r4.table_any  = TRUE;
                    route.r4.metric_any = TRUE;
                    route.r4.rt_source  = NM_IP_CONFIG_SOURCE_VPN;

                    if (plen > 32)
                        break;
                    route.r4.plen    = plen;
                    route.r4.network = nm_ip4_addr_clear_host_address(route.r4.network, plen);

                    if (priv->ip_data_4.gw_external.addr4
                        && route.r4.network == priv->ip_data_4.gw_external.addr4
                        && route.r4.plen == 32) {
                        /* Ignore host routes to the VPN gateway since NM adds one itself
                         * below.  Since NM knows more about the routing situation than
                         * the VPN server, we want to use the NM created route instead of
                         * whatever the server provides.
                         */
                        break;
                    }

                    nm_l3_config_data_add_route_4(l3cd, &route.r4);
                    break;
                default:
                    break;
                }
            }
        } else {
            while (
                g_variant_iter_next(var_iter, "(@ayu@ayu)", &dest, &prefix, &next_hop, &metric)) {
                _nm_unused gs_unref_variant GVariant *next_hop_ref_owner = next_hop;
                _nm_unused gs_unref_variant GVariant *dest_ref_owner     = dest;

                if (prefix > 128)
                    continue;

                route.r6 = (NMPlatformIP6Route){
                    .plen       = prefix,
                    .table_any  = TRUE,
                    .metric_any = TRUE,
                    .rt_source  = NM_IP_CONFIG_SOURCE_VPN,
                };

                if (!nm_ip_addr_set_from_variant(AF_INET6, &route.r6.network, dest, NULL))
                    continue;

                nm_ip_addr_set_from_variant(AF_INET6, &route.r6.gateway, next_hop, NULL);

                nm_ip6_addr_clear_host_address(&route.r6.network, &route.r6.network, route.r6.plen);

                if (!IN6_IS_ADDR_UNSPECIFIED(&priv->ip_data_6.gw_external.addr6)
                    && IN6_ARE_ADDR_EQUAL(&route.r6.network, &priv->ip_data_6.gw_external.addr6)
                    && route.r6.plen == 128) {
                    /* Ignore host routes to the VPN gateway since NM adds one itself.
                     * Since NM knows more about the routing situation than the VPN
                     * server, we want to use the NM created route instead of whatever
                     * the server provides.
                     */
                    continue;
                }

                nm_l3_config_data_add_route_6(l3cd, &route.r6);
            }
        }
    }

    if (g_variant_lookup(dict,
                         IS_IPv4 ? NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT
                                 : NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT,
                         "b",
                         &v_b))
        never_default = v_b;
    else
        never_default = FALSE;

    if (!never_default) {
        NMPlatformIPXRoute route;

        if (IS_IPv4) {
            route.r4 = (NMPlatformIP4Route){
                .ifindex    = ip_ifindex,
                .rt_source  = NM_IP_CONFIG_SOURCE_VPN,
                .gateway    = priv->ip_data_4.gw_internal.addr4,
                .table_any  = TRUE,
                .metric_any = TRUE,
                .mss        = mss,
            };
        } else {
            route.r6 = (NMPlatformIP6Route){
                .ifindex    = ip_ifindex,
                .rt_source  = NM_IP_CONFIG_SOURCE_VPN,
                .gateway    = priv->ip_data_6.gw_internal.addr6,
                .table_any  = TRUE,
                .metric_any = TRUE,
                .mss        = mss,
            };
        }
        nm_l3_config_data_add_route(l3cd, addr_family, NULL, &route.rx);
    }

    _l3cfg_l3cd_set(self, L3CD_TYPE_IP_X(IS_IPv4), l3cd);

    _check_complete(self, TRUE);
}

void
nm_vpn_connection_disconnect(NMVpnConnection              *self,
                             NMActiveConnectionStateReason reason,
                             gboolean                      quitting)
{
    g_return_if_fail(NM_IS_VPN_CONNECTION(self));

    _set_vpn_state(self, STATE_DISCONNECTED, reason, quitting);
}

gboolean
nm_vpn_connection_deactivate(NMVpnConnection              *self,
                             NMActiveConnectionStateReason reason,
                             gboolean                      quitting)
{
    NMVpnConnectionPrivate *priv;

    g_return_val_if_fail(NM_IS_VPN_CONNECTION(self), FALSE);

    priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    if (priv->vpn_state <= STATE_UNKNOWN || priv->vpn_state > STATE_DEACTIVATING)
        return FALSE;

    _set_vpn_state(self, STATE_DEACTIVATING, reason, quitting);
    return TRUE;
}

/*****************************************************************************/

static void
_secrets_dbus_need_secrets_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMVpnConnection           *self;
    NMVpnConnectionPrivate    *priv;
    gs_unref_variant GVariant *res   = NULL;
    gs_free_error GError      *error = NULL;
    const char                *setting_name;

    res = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (nm_utils_error_is_cancelled(error))
        return;

    self = NM_VPN_CONNECTION(user_data);
    priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    if (error) {
        _LOGW("plugin NeedSecrets request #%d failed: %s", priv->secrets_idx + 1, error->message);
        _set_vpn_state(self, STATE_FAILED, NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
        return;
    }

    g_variant_get(res, "(&s)", &setting_name);
    if (nm_str_is_empty(setting_name)) {
        /* No secrets required; we can start the VPN */
        _LOGD("service indicated no additional secrets required");
        really_activate(self, priv->username);
        return;
    }

    /* More secrets required */
    if (priv->secrets_idx == SECRETS_REQ_NEW) {
        _LOGW("final secrets request failed to provide sufficient secrets");
        _set_vpn_state(self, STATE_FAILED, NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
        return;
    }

    _LOGD("service indicated additional secrets required");
    _secrets_get(self, priv->secrets_idx + 1, NULL);
}

static void
_secrets_dbus_new_secrets_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMVpnConnection           *self;
    gs_unref_variant GVariant *res   = NULL;
    gs_free_error GError      *error = NULL;

    res = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (nm_utils_error_is_cancelled(error))
        return;

    self = NM_VPN_CONNECTION(user_data);

    if (error) {
        _LOGW("sending new secrets to the plugin failed: %s", error->message);
        _set_vpn_state(self, STATE_FAILED, NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
        return;
    }

    _set_vpn_state(self, STATE_CONNECT, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);
}

static void
_secrets_get_secrets_cb(NMSettingsConnection       *connection,
                        NMSettingsConnectionCallId *call_id,
                        const char                 *agent_username,
                        const char                 *setting_name,
                        GError                     *error,
                        gpointer                    user_data)
{
    NMVpnConnection        *self = NM_VPN_CONNECTION(user_data);
    NMVpnConnectionPrivate *priv;
    GVariant               *dict;

    g_return_if_fail(NM_IS_VPN_CONNECTION(self));

    priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    g_return_if_fail(connection && connection == _get_settings_connection(self, FALSE));
    g_return_if_fail(call_id == priv->secrets_id);

    priv->secrets_id = NULL;

    if (nm_utils_error_is_cancelled(error))
        return;

    if (error && priv->secrets_idx >= SECRETS_REQ_NEW) {
        _LOGW("secrets: failed to request VPN secrets #%d: %s",
              priv->secrets_idx + 1,
              error->message);
        _set_vpn_state(self, STATE_FAILED, NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
        return;
    }

    if (!priv->dbus.bus_name) {
        _set_vpn_state(self,
                       STATE_FAILED,
                       NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_STOPPED,
                       FALSE);
        return;
    }

    /* Cache the username for later */
    if (agent_username)
        nm_strdup_reset(&priv->username, agent_username);

    dict = _hash_with_username(_get_applied_connection(self), priv->username);

    if (priv->secrets_idx == SECRETS_REQ_INTERACTIVE) {
        _LOGD("secrets: sending secrets to the plugin");
        _dbus_connection_call(self,
                              "NewSecrets",
                              g_variant_new("(@a{sa{sv}})", dict),
                              G_VARIANT_TYPE("()"),
                              _secrets_dbus_new_secrets_cb);
        return;
    }

    _LOGD("secrets: asking service if additional secrets are required");
    _dbus_connection_call(self,
                          "NeedSecrets",
                          g_variant_new("(@a{sa{sv}})", dict),
                          G_VARIANT_TYPE("(s)"),
                          _secrets_dbus_need_secrets_cb);
}

static void
_secrets_get(NMVpnConnection *self, SecretsReq secrets_idx, const char *const *hints)
{
    NMVpnConnectionPrivate      *priv  = NM_VPN_CONNECTION_GET_PRIVATE(self);
    NMSecretAgentGetSecretsFlags flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE;

    g_return_if_fail(secrets_idx < SECRETS_REQ_LAST);

    priv->secrets_idx = secrets_idx;

    cancel_get_secrets(self);

    _LOGD("secrets: requesting VPN secrets pass #%d", priv->secrets_idx + 1);

    switch (priv->secrets_idx) {
    case SECRETS_REQ_SYSTEM:
        flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM;
        break;
    case SECRETS_REQ_EXISTING:
        flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE;
        break;
    case SECRETS_REQ_NEW:
    case SECRETS_REQ_INTERACTIVE:
        flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;
        break;
    default:
        g_return_if_reached();
    }

    if (nm_active_connection_get_user_requested(NM_ACTIVE_CONNECTION(self)))
        flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_USER_REQUESTED;

    priv->secrets_id = nm_settings_connection_get_secrets(
        _get_settings_connection(self, FALSE),
        _get_applied_connection(self),
        nm_active_connection_get_subject(NM_ACTIVE_CONNECTION(self)),
        NM_SETTING_VPN_SETTING_NAME,
        flags,
        hints,
        _secrets_get_secrets_cb,
        self);

    g_return_if_fail(priv->secrets_id);
}

static void
_dbus_signal_secrets_required_cb(NMVpnConnection   *self,
                                 const char        *message,
                                 const char *const *secrets)
{
    NMVpnConnectionPrivate *priv        = NM_VPN_CONNECTION_GET_PRIVATE(self);
    const gsize             secrets_len = NM_PTRARRAY_LEN(secrets);
    gsize                   i;
    gs_free const char    **hints        = NULL;
    gs_free char           *message_hint = NULL;

    if (!NM_IN_SET(priv->vpn_state, STATE_CONNECT, STATE_NEED_AUTH)) {
        _LOGD("secrets: request ignored in current state %s",
              vpn_state_to_string_a(priv->vpn_state));
        return;
    }

    _LOGD("secrets: request (state %s)", vpn_state_to_string_a(priv->vpn_state));

    priv->secrets_idx = SECRETS_REQ_INTERACTIVE;
    _set_vpn_state(self, STATE_NEED_AUTH, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);

    /* Copy hints and add message to the end */
    hints = g_new(const char *, secrets_len + 2);
    for (i = 0; i < secrets_len; i++)
        hints[i] = secrets[i];
    if (message) {
        message_hint = g_strdup_printf("x-vpn-message:%s", message);
        hints[i++]   = message_hint;
    }
    hints[i] = NULL;
    nm_assert(i < secrets_len + 2);

    _secrets_get(self, SECRETS_REQ_INTERACTIVE, hints);
}

/*****************************************************************************/

static int
_get_log_level(void)
{
    NMLogLevel level;

    /* curiously enough, nm-logging also uses syslog. But it
     * maps NMLogLevel differently to the syslog levels then we
     * do here.
     *
     * The reason is, that LOG_NOTICE is already something worth
     * highlighting in the journal, but we have 3 levels that are
     * lower then LOG_NOTICE (LOGL_TRACE, LOGL_DEBUG, LOGL_INFO),
     * On the other hand, syslog only defines LOG_DEBUG and LOG_INFO.
     * Thus, we must map them differently.
     *
     * Inside the VPN plugin, you might want to treat LOG_NOTICE as
     * as low severity, not worthy to be highlighted (like NM does). */

    level = nm_logging_get_level(LOGD_VPN_PLUGIN);
    if (level != _LOGL_OFF) {
        if (level <= LOGL_TRACE)
            return LOG_DEBUG;
        if (level <= LOGL_DEBUG)
            return LOG_INFO;
        if (level <= LOGL_INFO)
            return LOG_NOTICE;
        if (level <= LOGL_WARN)
            return LOG_WARNING;
        if (level <= LOGL_ERR)
            return LOG_ERR;
    }

    return LOG_EMERG;
}

static gboolean
nm_vpn_service_daemon_exec(NMVpnConnection *self, GError **error)
{
    NMVpnConnectionPrivate *priv;
    GPid                    pid;
    char                   *vpn_argv[4];
    gs_free char          **envp = NULL;
    char                    env_log_level[NM_STRLEN("NM_VPN_LOG_LEVEL=") + 100];
    char                    env_log_syslog[NM_STRLEN("NM_VPN_LOG_SYSLOG=") + 10];
    const gsize             N_ENVIRON_EXTRA = 3;
    char                  **p_environ;
    gsize                   n_environ;
    gsize                   i;
    gsize                   j;

    g_return_val_if_fail(NM_IS_VPN_CONNECTION(self), FALSE);

    priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    i             = 0;
    vpn_argv[i++] = (char *) nm_vpn_plugin_info_get_program(priv->plugin_info);
    g_return_val_if_fail(vpn_argv[0], FALSE);
    if (nm_vpn_plugin_info_supports_multiple(priv->plugin_info)) {
        vpn_argv[i++] = "--bus-name";
        vpn_argv[i++] = priv->dbus.bus_name;
    }
    vpn_argv[i++] = NULL;

    /* we include <unistd.h> and "config.h" defines _GNU_SOURCE for us. So, we have @environ. */
    p_environ = environ;
    n_environ = NM_PTRARRAY_LEN(p_environ);
    envp      = g_new(char *, n_environ + N_ENVIRON_EXTRA);
    for (i = 0, j = 0; j < n_environ; j++) {
        if (NM_STR_HAS_PREFIX(p_environ[j], "NM_VPN_LOG_LEVEL=")
            || NM_STR_HAS_PREFIX(p_environ[j], "NM_VPN_LOG_SYSLOG="))
            continue;
        envp[i++] = p_environ[j];
    }

    /* NM_VPN_LOG_LEVEL: the syslog logging level for the plugin. */
    envp[i++] = nm_sprintf_buf(env_log_level, "NM_VPN_LOG_LEVEL=%d", _get_log_level());

    /* NM_VPN_LOG_SYSLOG: whether to log to stdout or syslog. If NetworkManager itself runs in
     * foreground, we also want the plugin to log to stdout.
     * If the plugin runs in background, the plugin should prefer logging to syslog. Otherwise
     * logging messages will be lost (unless using journald, in which case it wouldn't matter). */
    envp[i++] = nm_sprintf_buf(env_log_syslog,
                               "NM_VPN_LOG_SYSLOG=%c",
                               nm_logging_syslog_enabled() ? '1' : '0');

    envp[i++] = NULL;
    nm_assert(i <= n_environ + N_ENVIRON_EXTRA);

    if (!g_spawn_async(NULL, vpn_argv, envp, 0, nm_utils_setpgid, NULL, &pid, error))
        return FALSE;

    _LOGD("starting: VPN service has PID %lld", (long long) pid);
    return TRUE;
}

/*****************************************************************************/

static gboolean
_start_timeout_cb(gpointer data)
{
    NMVpnConnection        *self = NM_VPN_CONNECTION(data);
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->start_timeout_source);

    if (priv->dbus_service_started)
        _LOGW("starting: timed out waiting for the service to start");
    else
        _LOGW("starting: timed out waiting for the VPN to activate");
    nm_vpn_connection_disconnect(self,
                                 NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT,
                                 FALSE);
    return G_SOURCE_CONTINUE;
}

/*****************************************************************************/

static void
_dbus_dispatch_cb(GDBusConnection *connection,
                  const char      *sender_name,
                  const char      *object_path,
                  const char      *interface_name,
                  const char      *signal_name,
                  GVariant        *parameters,
                  gpointer         user_data)
{
    NMVpnConnection        *self = user_data;
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);
    guint32                 v_u;

    nm_assert(nm_streq0(object_path, NM_VPN_DBUS_PLUGIN_PATH));
    nm_assert(nm_streq0(interface_name, NM_VPN_DBUS_PLUGIN_INTERFACE));
    nm_assert(signal_name);

    if (!nm_streq0(priv->dbus.owner, sender_name))
        return;

    if (nm_streq(signal_name, "Failure")) {
        if (nm_g_variant_tuple_get_u(parameters, &v_u))
            _dbus_signal_failure_cb(self, v_u);
    } else if (nm_streq(signal_name, "StateChanged")) {
        if (nm_g_variant_tuple_get_u(parameters, &v_u))
            _dbus_signal_state_changed_cb(self, v_u);
    } else if (nm_streq(signal_name, "SecretsRequired")) {
        if (g_variant_is_of_type(parameters, G_VARIANT_TYPE("(sas)"))) {
            const char          *v_s;
            gs_free const char **v_strv = NULL;

            g_variant_get(parameters, "(&s^a&s)", &v_s, &v_strv);
            _dbus_signal_secrets_required_cb(self, v_s, v_strv);
        }
    } else if (NM_IN_STRSET(signal_name, "Config", "Ip4Config", "Ip6Config")) {
        if (g_variant_is_of_type(parameters, G_VARIANT_TYPE("(a{sv})"))) {
            gs_unref_variant GVariant *v_var = NULL;

            g_variant_get(parameters, "(@a{sv})", &v_var);
            if (signal_name[0] == 'C')
                _dbus_signal_config_cb(self, v_var);
            else if (signal_name[2] == '4')
                _dbus_signal_ip_config_cb(self, AF_INET, v_var);
            else
                _dbus_signal_ip_config_cb(self, AF_INET6, v_var);
        }
    }
}

static void
_name_owner_changed(NMVpnConnection *self, const char *owner, gboolean initializing)
{
    _nm_unused gs_unref_object NMVpnConnection *self_keep_alive = g_object_ref(self);
    NMVpnConnectionPrivate                     *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    owner = nm_str_not_empty(owner);

    if (!owner && initializing) {
        gs_free_error GError *error = NULL;

        nm_assert(!priv->dbus.owner);
        _LOGT("dbus: no name owner for %s (start VPN service)", priv->dbus.bus_name);

        if (!nm_vpn_service_daemon_exec(self, &error)) {
            _LOGW("starting: failure to start VPN service: %s", error->message);
            nm_vpn_connection_disconnect(self,
                                         NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED,
                                         FALSE);
        }
        priv->start_timeout_source = nm_g_timeout_add_seconds_source(5, _start_timeout_cb, self);
        return;
    }

    if (!nm_strdup_reset(&priv->dbus.owner, owner))
        return;

    if (!priv->dbus.owner) {
        _LOGT("dbus: name owner for %s disappeared", priv->dbus.bus_name);

        /* We don't want to restart if the service re-appears. Disconnect the signal
         * so that cannot happen and we don't disconnect the VPN again. */
        nm_clear_g_dbus_connection_signal(priv->dbus.connection,
                                          &priv->dbus.signal_id_name_changed);

        nm_vpn_connection_disconnect(self,
                                     NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_STOPPED,
                                     FALSE);
        return;
    }

    _LOGT("dbus: name owner %s for %s", priv->dbus.owner, priv->dbus.bus_name);

    priv->dbus_service_started = TRUE;
    nm_clear_g_source_inst(&priv->start_timeout_source);
    priv->start_timeout_source =
        nm_g_timeout_add_seconds_source(_get_vpn_timeout(self) + 180, _start_timeout_cb, self);

    _set_vpn_state(self, STATE_NEED_AUTH, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);

    /* Kick off the secrets requests; first we get existing system secrets
     * and ask the plugin if these are sufficient, next we get all existing
     * secrets from system and from user agents and ask the plugin again,
     * and last we ask the user for new secrets if required.
     */
    _secrets_get(self, SECRETS_REQ_SYSTEM, NULL);
}

static void
_name_owner_changed_cb(GDBusConnection *connection,
                       const char      *sender_name,
                       const char      *object_path,
                       const char      *interface_name,
                       const char      *signal_name,
                       GVariant        *parameters,
                       gpointer         user_data)
{
    NMVpnConnection        *self = user_data;
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);
    const char             *new_owner;

    if (!priv->dbus.name_owner_initialized)
        return;

    if (!g_variant_is_of_type(parameters, G_VARIANT_TYPE("(sss)")))
        return;

    g_variant_get(parameters, "(&s&s&s)", NULL, NULL, &new_owner);

    _name_owner_changed(self, new_owner, FALSE);
}

static void
_name_owner_get_cb(const char *name_owner, GError *error, gpointer user_data)
{
    NMVpnConnection        *self;
    NMVpnConnectionPrivate *priv;

    if (nm_utils_error_is_cancelled(error))
        return;

    self = user_data;
    priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    priv->dbus.name_owner_initialized = TRUE;
    _name_owner_changed(self, name_owner, TRUE);
}

static gboolean
_init_fail_on_idle_cb(gpointer user_data)
{
    NMVpnConnection        *self = user_data;
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->init_fail_on_idle_source);
    _set_vpn_state(self,
                   STATE_FAILED,
                   NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED,
                   FALSE);
    return G_SOURCE_CONTINUE;
}

/*****************************************************************************/

void
nm_vpn_connection_activate(NMVpnConnection *self, NMVpnPluginInfo *plugin_info)
{
    NMVpnConnectionPrivate *priv;
    NMConnection           *connection;
    NMSettingVpn           *s_vpn;
    const char             *service;

    g_return_if_fail(NM_IS_VPN_CONNECTION(self));
    g_return_if_fail(NM_IS_VPN_PLUGIN_INFO(plugin_info));

    priv = NM_VPN_CONNECTION_GET_PRIVATE(self);
    g_return_if_fail(!priv->plugin_info);

    connection = _get_applied_connection(self);

    s_vpn = nm_connection_get_setting_vpn(connection);
    g_return_if_fail(s_vpn);

    service = nm_vpn_plugin_info_get_service(plugin_info);
    nm_assert(service);

    if (nm_vpn_plugin_info_supports_multiple(plugin_info)) {
        const char *path;

        path = nm_dbus_object_get_path(NM_DBUS_OBJECT(self));
        if (path)
            path = strrchr(path, '/');
        g_return_if_fail(path);

        priv->dbus.bus_name = g_strdup_printf("%s.Connection_%s", service, &path[1]);
    } else
        priv->dbus.bus_name = g_strdup(service);

    _LOGI("starting %s", nm_vpn_plugin_info_get_name(plugin_info));

    priv->ip_data_4.method_auto = nm_streq0(nm_utils_get_ip_config_method(connection, AF_INET),
                                            NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    priv->ip_data_6.method_auto = nm_streq0(nm_utils_get_ip_config_method(connection, AF_INET6),
                                            NM_SETTING_IP6_CONFIG_METHOD_AUTO);

    priv->connection_can_persist = nm_setting_vpn_get_persistent(s_vpn);
    priv->plugin_info            = g_object_ref(plugin_info);

    priv->main_cancellable = g_cancellable_new();

    priv->dbus.connection = nm_g_object_ref(NM_MAIN_DBUS_CONNECTION_GET);

    if (!priv->dbus.connection) {
        _LOGD("starting: no D-Bus connection (will fail)");
        priv->init_fail_on_idle_source = nm_g_idle_add_source(_init_fail_on_idle_cb, self);
        goto out;
    }

    _LOGD("starting: watch D-Bus service %s", priv->dbus.bus_name);
    priv->dbus.signal_id_name_changed =
        nm_dbus_connection_signal_subscribe_name_owner_changed(priv->dbus.connection,
                                                               priv->dbus.bus_name,
                                                               _name_owner_changed_cb,
                                                               self,
                                                               NULL);

    priv->dbus.signal_id_vpn = g_dbus_connection_signal_subscribe(priv->dbus.connection,
                                                                  priv->dbus.bus_name,
                                                                  NM_VPN_DBUS_PLUGIN_INTERFACE,
                                                                  NULL,
                                                                  NM_VPN_DBUS_PLUGIN_PATH,
                                                                  NULL,
                                                                  G_DBUS_SIGNAL_FLAGS_NONE,
                                                                  _dbus_dispatch_cb,
                                                                  self,
                                                                  NULL);

    nm_dbus_connection_call_get_name_owner(priv->dbus.connection,
                                           priv->dbus.bus_name,
                                           3000,
                                           priv->main_cancellable,
                                           _name_owner_get_cb,
                                           self);

out:
    _set_vpn_state(self, STATE_PREPARE, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);
}

/*****************************************************************************/

static void
device_changed(NMActiveConnection *active, NMDevice *new_device, NMDevice *old_device)
{
    NMVpnConnection         *self      = NM_VPN_CONNECTION(active);
    NMVpnConnectionPrivate  *priv      = NM_VPN_CONNECTION_GET_PRIVATE(active);
    gs_unref_object NML3Cfg *l3cfg_old = NULL;
    int                      ifindex;

    if (!priv->generic_config_received)
        return;
    if (priv->vpn_state > STATE_ACTIVATED)
        return;
    if (!_service_and_connection_can_persist(self))
        return;

    if (priv->ifindex_if <= 0) {
        /* Route-based VPNs must updvate their routing and send a new IP config
         * since all their routes need to be adjusted for new_device.
         */
        return;
    }

    ifindex = _get_ifindex_for_device(self);
    if (ifindex <= 0)
        return;
    if (priv->ifindex_dev == ifindex)
        return;

    _LOGD("set ip-ifindex-dev %d (was %d)", ifindex, priv->ifindex_dev);

    l3cfg_old = g_steal_pointer(&priv->l3cfg_dev);
    nm_l3cfg_commit_type_clear(l3cfg_old, &priv->l3cfg_commit_type_dev);
    _l3cfg_clear(self, l3cfg_old);

    priv->ifindex_dev = ifindex;

    priv->l3cfg_dev = nm_netns_l3cfg_acquire(priv->netns, ifindex);
    g_signal_connect(priv->l3cfg_dev, NM_L3CFG_SIGNAL_NOTIFY, G_CALLBACK(_l3cfg_notify_cb), self);
    priv->l3cfg_commit_type_dev =
        nm_l3cfg_commit_type_register(priv->l3cfg_dev, NM_L3_CFG_COMMIT_TYPE_UPDATE, NULL, "vpn");

    if (_l3cfg_l3cd_gw_extern_update(self))
        nm_l3cfg_commit_on_idle_schedule(priv->l3cfg_dev, NM_L3_CFG_COMMIT_TYPE_AUTO);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMVpnConnection        *self = NM_VPN_CONNECTION(object);
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_VPN_STATE:
        g_value_set_uint(value, _state_to_nm_vpn_state(priv->vpn_state));
        break;
    case PROP_BANNER:
        g_value_set_string(value, priv->banner ?: "");
        break;
    case PROP_IP4_CONFIG:
        nm_dbus_utils_g_value_set_object_path(value, priv->ip_data_4.ip_config);
        break;
    case PROP_IP6_CONFIG:
        nm_dbus_utils_g_value_set_object_path(value, priv->ip_data_6.ip_config);
        break;
    case PROP_CONTROLLER:
    case PROP_MASTER:
        nm_dbus_utils_g_value_set_object_path(
            value,
            nm_active_connection_get_device(NM_ACTIVE_CONNECTION(self)));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_vpn_connection_init(NMVpnConnection *self)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    priv->vpn_state   = STATE_WAITING;
    priv->secrets_idx = SECRETS_REQ_SYSTEM;
    priv->netns       = g_object_ref(nm_netns_get());
}

NMVpnConnection *
nm_vpn_connection_new(NMSettingsConnection  *settings_connection,
                      NMDevice              *parent_device,
                      const char            *specific_object,
                      NMActivationReason     activation_reason,
                      NMActivationStateFlags initial_state_flags,
                      NMAuthSubject         *subject)
{
    g_return_val_if_fail(!settings_connection || NM_IS_SETTINGS_CONNECTION(settings_connection),
                         NULL);
    g_return_val_if_fail(NM_IS_DEVICE(parent_device), NULL);
    g_return_val_if_fail(specific_object, NULL);

    return g_object_new(NM_TYPE_VPN_CONNECTION,
                        NM_ACTIVE_CONNECTION_INT_SETTINGS_CONNECTION,
                        settings_connection,
                        NM_ACTIVE_CONNECTION_INT_DEVICE,
                        parent_device,
                        NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT,
                        specific_object,
                        NM_ACTIVE_CONNECTION_INT_SUBJECT,
                        subject,
                        NM_ACTIVE_CONNECTION_INT_ACTIVATION_REASON,
                        activation_reason,
                        NM_ACTIVE_CONNECTION_VPN,
                        TRUE,
                        NM_ACTIVE_CONNECTION_STATE_FLAGS,
                        (guint) initial_state_flags,
                        NULL);
}

static void
dispose(GObject *object)
{
    NMVpnConnection        *self = NM_VPN_CONNECTION(object);
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    nm_clear_g_dbus_connection_signal(priv->dbus.connection, &priv->dbus.signal_id_vpn);
    nm_clear_g_dbus_connection_signal(priv->dbus.connection, &priv->dbus.signal_id_name_changed);

    nm_clear_g_source_inst(&priv->init_fail_on_idle_source);

    nm_clear_g_cancellable(&priv->main_cancellable);

    nm_clear_g_source_inst(&priv->start_timeout_source);

    nm_clear_pointer(&priv->connect_hash, g_variant_unref);

    nm_clear_g_source_inst(&priv->connect_timeout_source);

    if (nm_l3cfg_commit_type_clear(priv->l3cfg_if, &priv->l3cfg_commit_type_if))
        nm_l3cfg_commit_on_idle_schedule(priv->l3cfg_if, NM_L3_CFG_COMMIT_TYPE_AUTO);

    if (nm_l3cfg_commit_type_clear(priv->l3cfg_dev, &priv->l3cfg_commit_type_dev))
        nm_l3cfg_commit_on_idle_schedule(priv->l3cfg_dev, NM_L3_CFG_COMMIT_TYPE_AUTO);

    g_clear_object(&priv->ip_data_4.ip_config);
    g_clear_object(&priv->ip_data_6.ip_config);

    dispatcher_cleanup(self);

    cancel_get_secrets(self);

    fw_call_cleanup(self);

    nm_pacrunner_manager_remove_clear(&priv->pacrunner_conf_id);

    G_OBJECT_CLASS(nm_vpn_connection_parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
    NMVpnConnection        *self = NM_VPN_CONNECTION(object);
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    G_OBJECT_CLASS(nm_vpn_connection_parent_class)->finalize(object);

    g_free(priv->banner);
    g_free(priv->username);
    g_free(priv->dbus.bus_name);

    _l3cfg_l3cd_clear_all(self);
    _l3cfg_clear(self, priv->l3cfg_if);
    _l3cfg_clear(self, priv->l3cfg_dev);

    g_clear_object(&priv->plugin_info);
    g_clear_object(&priv->l3cfg_if);
    g_clear_object(&priv->l3cfg_dev);
    g_clear_object(&priv->netns);
    g_clear_object(&priv->dbus.connection);
}

static const GDBusSignalInfo signal_info_vpn_state_changed = NM_DEFINE_GDBUS_SIGNAL_INFO_INIT(
    "VpnStateChanged",
    .args = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("state", "u"),
                                      NM_DEFINE_GDBUS_ARG_INFO("reason", "u"), ), );

static const NMDBusInterfaceInfoExtended interface_info_vpn_connection = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_VPN_CONNECTION,
        .signals    = NM_DEFINE_GDBUS_SIGNAL_INFOS(&signal_info_vpn_state_changed, ),
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("VpnState",
                                                           "u",
                                                           NM_VPN_CONNECTION_VPN_STATE),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Banner",
                                                           "s",
                                                           NM_VPN_CONNECTION_BANNER), ), ),
};

static void
nm_vpn_connection_class_init(NMVpnConnectionClass *klass)
{
    GObjectClass            *object_class      = G_OBJECT_CLASS(klass);
    NMActiveConnectionClass *active_class      = NM_ACTIVE_CONNECTION_CLASS(klass);
    NMDBusObjectClass       *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_vpn_connection);

    object_class->get_property = get_property;
    object_class->dispose      = dispose;
    object_class->finalize     = finalize;

    active_class->device_state_changed = device_state_changed;
    active_class->device_changed       = device_changed;

    obj_properties[PROP_VPN_STATE] = g_param_spec_uint(NM_VPN_CONNECTION_VPN_STATE,
                                                       "",
                                                       "",
                                                       NM_VPN_CONNECTION_STATE_UNKNOWN,
                                                       NM_VPN_CONNECTION_STATE_DISCONNECTED,
                                                       NM_VPN_CONNECTION_STATE_UNKNOWN,
                                                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_BANNER] = g_param_spec_string(NM_VPN_CONNECTION_BANNER,
                                                      "",
                                                      "",
                                                      NULL,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    g_object_class_override_property(object_class,
                                     PROP_CONTROLLER,
                                     NM_ACTIVE_CONNECTION_CONTROLLER);
    g_object_class_override_property(object_class, PROP_MASTER, NM_ACTIVE_CONNECTION_MASTER);
    g_object_class_override_property(object_class,
                                     PROP_IP4_CONFIG,
                                     NM_ACTIVE_CONNECTION_IP4_CONFIG);
    g_object_class_override_property(object_class,
                                     PROP_IP6_CONFIG,
                                     NM_ACTIVE_CONNECTION_IP6_CONFIG);

    signals[INTERNAL_STATE_CHANGED] =
        g_signal_new(NM_VPN_CONNECTION_INTERNAL_STATE_CHANGED,
                     G_OBJECT_CLASS_TYPE(object_class),
                     G_SIGNAL_RUN_FIRST,
                     0,
                     NULL,
                     NULL,
                     NULL,
                     G_TYPE_NONE,
                     3,
                     G_TYPE_UINT, /* NMVpnConnectionState new_external_state */
                     G_TYPE_UINT, /* NMVpnConnectionState old_external_state */
                     G_TYPE_UINT /* NMActiveConnectionStateReason reason */);

    signals[INTERNAL_RETRY_AFTER_FAILURE] =
        g_signal_new(NM_VPN_CONNECTION_INTERNAL_RETRY_AFTER_FAILURE,
                     G_OBJECT_CLASS_TYPE(object_class),
                     G_SIGNAL_RUN_FIRST,
                     0,
                     NULL,
                     NULL,
                     NULL,
                     G_TYPE_NONE,
                     0);
}
