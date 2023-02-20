/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2009 - 2014 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-modem.h"

#include <fcntl.h>
#include <termios.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>

#include "NetworkManagerUtils.h"
#include "devices/nm-device-private.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-platform/nm-platform.h"
#include "nm-act-request.h"
#include "nm-l3-config-data.h"
#include "nm-netns.h"
#include "nm-setting-connection.h"
#include "ppp/nm-ppp-manager-call.h"
#include "ppp/nm-ppp-mgr.h"
#include "ppp/nm-ppp-status.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMModem,
                             PROP_CONTROL_PORT,
                             PROP_IP_IFINDEX,
                             PROP_PATH,
                             PROP_UID,
                             PROP_DRIVER,
                             PROP_STATE,
                             PROP_DEVICE_ID,
                             PROP_SIM_ID,
                             PROP_IP_TYPES,
                             PROP_SIM_OPERATOR_ID,
                             PROP_OPERATOR_CODE,
                             PROP_APN, );

enum {
    PPP_STATS,
    PPP_FAILED,
    PREPARE_RESULT,
    NEW_CONFIG,
    AUTH_REQUESTED,
    AUTH_RESULT,
    REMOVED,
    STATE_CHANGED,
    LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

typedef struct {
    GSource *stage3_on_idle_source;
    bool     stage3_started : 1;
} IPData;

typedef struct _NMModemPrivate {
    char *uid;
    char *path;
    char *driver;
    char *control_port;
    char *data_port;

    int             ip_ifindex;
    NMModemIPMethod ip4_method;
    NMModemIPMethod ip6_method;
    NMModemState    state;
    NMModemState    prev_state; /* revert to this state if enable/disable fails */
    char           *device_id;
    char           *sim_id;
    NMModemIPType   ip_types;
    char           *sim_operator_id;
    char           *operator_code;
    char           *apn;

    NMPPPManager *ppp_manager;
    NMPppMgr     *ppp_mgr;

    NMActRequest                 *act_req;
    NMDevice                     *device;
    guint32                       secrets_tries;
    NMActRequestGetSecretsCallId *secrets_id;

    guint mm_ip_timeout;

    bool claimed : 1;

    union {
        struct {
            IPData ip_data_6;
            IPData ip_data_4;
        };
        IPData ip_data_x[2];
    };

} NMModemPrivate;

G_DEFINE_TYPE(NMModem, nm_modem, G_TYPE_OBJECT)

#define NM_MODEM_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMModem, NM_IS_MODEM)

/*****************************************************************************/

#define _NMLOG_PREFIX_BUFLEN 64
#define _NMLOG_PREFIX_NAME   "modem"
#define _NMLOG_DOMAIN        LOGD_MB

static const char *
_nmlog_prefix(char *prefix, NMModem *self)
{
    const char *uuid;
    int         c;

    if (!self)
        return "";

    uuid = nm_modem_get_uid(self);

    if (uuid) {
        char pp[_NMLOG_PREFIX_BUFLEN - 5];

        c = g_snprintf(prefix, _NMLOG_PREFIX_BUFLEN, "[%s]", nm_strquote(pp, sizeof(pp), uuid));
    } else
        c = g_snprintf(prefix, _NMLOG_PREFIX_BUFLEN, "[%p]", self);
    nm_assert(c < _NMLOG_PREFIX_BUFLEN);

    return prefix;
}

#define _NMLOG(level, ...)                                                        \
    G_STMT_START                                                                  \
    {                                                                             \
        char _prefix[_NMLOG_PREFIX_BUFLEN];                                       \
                                                                                  \
        nm_log((level),                                                           \
               _NMLOG_DOMAIN,                                                     \
               NULL,                                                              \
               NULL,                                                              \
               "%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                       \
               _NMLOG_PREFIX_NAME,                                                \
               _nmlog_prefix(_prefix, (self)) _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    }                                                                             \
    G_STMT_END

/*****************************************************************************/

static void _set_ip_ifindex(NMModem *self, int ifindex);

/*****************************************************************************/
/* State/enabled/connected */

static const char *state_table[] = {
    [NM_MODEM_STATE_UNKNOWN]       = "unknown",
    [NM_MODEM_STATE_FAILED]        = "failed",
    [NM_MODEM_STATE_INITIALIZING]  = "initializing",
    [NM_MODEM_STATE_LOCKED]        = "locked",
    [NM_MODEM_STATE_DISABLED]      = "disabled",
    [NM_MODEM_STATE_DISABLING]     = "disabling",
    [NM_MODEM_STATE_ENABLING]      = "enabling",
    [NM_MODEM_STATE_ENABLED]       = "enabled",
    [NM_MODEM_STATE_SEARCHING]     = "searching",
    [NM_MODEM_STATE_REGISTERED]    = "registered",
    [NM_MODEM_STATE_DISCONNECTING] = "disconnecting",
    [NM_MODEM_STATE_CONNECTING]    = "connecting",
    [NM_MODEM_STATE_CONNECTED]     = "connected",
};

const char *
nm_modem_state_to_string(NMModemState state)
{
    if ((gsize) state < G_N_ELEMENTS(state_table))
        return state_table[state];
    return NULL;
}

/*****************************************************************************/

static NMPlatform *
_get_platform(NMModem *self)
{
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(self);

    if (!priv->device)
        return NULL;

    return nm_device_get_platform(priv->device);
}

/*****************************************************************************/

void
nm_modem_emit_signal_new_config(NMModem                  *self,
                                int                       addr_family,
                                const NML3ConfigData     *l3cd,
                                gboolean                  do_auto,
                                const NMUtilsIPv6IfaceId *iid,
                                NMDeviceStateReason       failure_reason,
                                GError                   *error)
{
    nm_assert(NM_IS_MODEM(self));
    nm_assert_addr_family(addr_family);
    nm_assert(!l3cd || NM_IS_L3_CONFIG_DATA(l3cd));
    nm_assert(!do_auto || addr_family == AF_INET6);
    nm_assert(!iid || addr_family == AF_INET6);
    nm_assert(!error || (!l3cd && !do_auto && !iid));

    if (error) {
        _LOGD("signal: new-config: IPv%c, failed '%s', %s",
              nm_utils_addr_family_to_char(addr_family),
              nm_device_state_reason_to_string_a(failure_reason),
              error->message);
    } else {
        gs_free char *str_to_free = NULL;

        _LOGD(
            "signal: new-config: IPv%c%s%s%s%s",
            nm_utils_addr_family_to_char(addr_family),
            l3cd ? ", has-l3cd" : "",
            do_auto ? ", do-auto" : "",
            NM_PRINT_FMT_QUOTED2(iid,
                                 ", iid=",
                                 nm_utils_bin2hexstr_a(iid, sizeof(*iid), ':', FALSE, &str_to_free),
                                 ""));
    }

    g_signal_emit(self,
                  signals[NEW_CONFIG],
                  0,
                  addr_family,
                  nm_l3_config_data_seal(l3cd),
                  do_auto,
                  iid,
                  (int) failure_reason,
                  error);
}

void
nm_modem_emit_signal_new_config_success(NMModem                  *self,
                                        int                       addr_family,
                                        const NML3ConfigData     *l3cd,
                                        gboolean                  do_auto,
                                        const NMUtilsIPv6IfaceId *iid)
{
    nm_modem_emit_signal_new_config(self,
                                    addr_family,
                                    l3cd,
                                    do_auto,
                                    iid,
                                    NM_DEVICE_STATE_REASON_NONE,
                                    NULL);
}

void
nm_modem_emit_signal_new_config_failure(NMModem            *self,
                                        int                 addr_family,
                                        NMDeviceStateReason failure_reason,
                                        GError             *error)
{
    nm_assert(error);
    nm_modem_emit_signal_new_config(self, addr_family, NULL, FALSE, NULL, failure_reason, error);
}

gboolean
nm_modem_is_claimed(NMModem *self)
{
    g_return_val_if_fail(NM_IS_MODEM(self), FALSE);

    return NM_MODEM_GET_PRIVATE(self)->claimed;
}

NMModem *
nm_modem_claim(NMModem *self)
{
    NMModemPrivate *priv;

    g_return_val_if_fail(NM_IS_MODEM(self), NULL);

    priv = NM_MODEM_GET_PRIVATE(self);

    g_return_val_if_fail(!priv->claimed, NULL);

    priv->claimed = TRUE;
    return g_object_ref(self);
}

void
nm_modem_unclaim(NMModem *self)
{
    NMModemPrivate *priv;

    g_return_if_fail(NM_IS_MODEM(self));

    priv = NM_MODEM_GET_PRIVATE(self);

    g_return_if_fail(priv->claimed);

    /* we don't actually unclaim the instance. This instance should not be re-used
     * by another owner, that is because we only claim modems as we receive them.
     * There is no mechanism that somebody else would later re-use them again.
     *
     * // priv->claimed = FALSE; */

    g_object_unref(self);
}

/*****************************************************************************/

NMModemState
nm_modem_get_state(NMModem *self)
{
    return NM_MODEM_GET_PRIVATE(self)->state;
}

void
nm_modem_set_state(NMModem *self, NMModemState new_state, const char *reason)
{
    NMModemPrivate *priv      = NM_MODEM_GET_PRIVATE(self);
    NMModemState    old_state = priv->state;

    priv->prev_state = NM_MODEM_STATE_UNKNOWN;

    if (new_state != old_state) {
        _LOGD("signal: modem state changed, '%s' --> '%s' (reason: %s%s%s)",
              nm_modem_state_to_string(old_state),
              nm_modem_state_to_string(new_state),
              NM_PRINT_FMT_QUOTE_STRING(reason));

        priv->state = new_state;
        _notify(self, PROP_STATE);
        g_signal_emit(self, signals[STATE_CHANGED], 0, (int) new_state, (int) old_state);
    }
}

void
nm_modem_set_prev_state(NMModem *self, const char *reason)
{
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(self);

    /* Reset modem to previous state if the state hasn't already changed */
    if (priv->prev_state != NM_MODEM_STATE_UNKNOWN)
        nm_modem_set_state(self, priv->prev_state, reason);
}

void
nm_modem_set_mm_enabled(NMModem *self, gboolean enabled)
{
    NMModemPrivate *priv       = NM_MODEM_GET_PRIVATE(self);
    NMModemState    prev_state = priv->state;

    /* Not all modem classes support set_mm_enabled */
    if (!NM_MODEM_GET_CLASS(self)->set_mm_enabled) {
        _LOGD("cannot enable modem: not implemented");
        return;
    }

    if (enabled && priv->state >= NM_MODEM_STATE_ENABLING) {
        _LOGD("cannot enable modem: already enabled");
        return;
    }
    if (!enabled && priv->state <= NM_MODEM_STATE_DISABLING) {
        _LOGD("cannot disable modem: already disabled");
        return;
    }

    if (priv->state <= NM_MODEM_STATE_INITIALIZING) {
        _LOGD("cannot enable/disable modem: initializing or failed");
        return;
    } else if (priv->state == NM_MODEM_STATE_LOCKED) {
        /* Don't try to enable if the modem is locked since that will fail */
        _LOGW("cannot enable/disable modem: locked");

        /* Try to unlock the modem if it's being enabled */
        if (enabled)
            nm_modem_emit_auth_requested(self);
        return;
    }

    NM_MODEM_GET_CLASS(self)->set_mm_enabled(self, enabled);

    /* Pre-empt the state change signal */
    nm_modem_set_state(self,
                       enabled ? NM_MODEM_STATE_ENABLING : NM_MODEM_STATE_DISABLING,
                       "user preference");
    priv->prev_state = prev_state;
}

void
nm_modem_emit_removed(NMModem *self)
{
    _LOGD("signal: removed");
    g_signal_emit(self, signals[REMOVED], 0);
}

void
nm_modem_emit_auth_requested(NMModem *self)
{
    _LOGD("signal: auth-requested");
    g_signal_emit(self, signals[AUTH_REQUESTED], 0);
}

void
nm_modem_emit_prepare_result(NMModem *self, gboolean success, NMDeviceStateReason reason)
{
    nm_assert(NM_IS_MODEM(self));

    _LOGD("signal: prepare-result: %s (%s)",
          success ? "success" : "failure",
          nm_device_state_reason_to_string_a(reason));
    g_signal_emit(self, signals[PREPARE_RESULT], 0, success, (guint) reason);
}

void
nm_modem_emit_ppp_failed(NMModem *self, NMDeviceStateReason reason)
{
    nm_assert(NM_IS_MODEM(self));

    _LOGD("signal: ppp-failed (%s)", nm_device_state_reason_to_string_a(reason));
    g_signal_emit(self, signals[PPP_FAILED], 0, (guint) reason);
}

NMModemIPType
nm_modem_get_supported_ip_types(NMModem *self)
{
    return NM_MODEM_GET_PRIVATE(self)->ip_types;
}

const char *
nm_modem_ip_type_to_string(NMModemIPType ip_type)
{
    switch (ip_type) {
    case NM_MODEM_IP_TYPE_IPV4:
        return "ipv4";
    case NM_MODEM_IP_TYPE_IPV6:
        return "ipv6";
    case NM_MODEM_IP_TYPE_IPV4V6:
        return "ipv4v6";
    default:
        g_return_val_if_reached("unknown");
    }
}

static GArray *
build_single_ip_type_array(NMModemIPType type)
{
    return g_array_append_val(g_array_sized_new(FALSE, FALSE, sizeof(NMModemIPType), 1), type);
}

/**
 * nm_modem_get_connection_ip_type:
 * @self: the #NMModem
 * @connection: the #NMConnection to determine IP type to use
 *
 * Given a modem and a connection, determine which #NMModemIPTypes to use
 * when connecting.
 *
 * Returns: an array of #NMModemIpType values, in the order in which they
 * should be tried.
 */
GArray *
nm_modem_get_connection_ip_type(NMModem *self, NMConnection *connection, GError **error)
{
    NMModemPrivate    *priv = NM_MODEM_GET_PRIVATE(self);
    NMSettingIPConfig *s_ip4, *s_ip6;
    const char        *method;
    gboolean           ip4 = TRUE, ip6 = TRUE;
    gboolean           ip4_may_fail = TRUE, ip6_may_fail = TRUE;

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    if (s_ip4) {
        method = nm_setting_ip_config_get_method(s_ip4);
        if (nm_streq0(method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED))
            ip4 = FALSE;
        ip4_may_fail = nm_setting_ip_config_get_may_fail(s_ip4);
    }

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    if (s_ip6) {
        method = nm_setting_ip_config_get_method(s_ip6);
        if (NM_IN_STRSET(method,
                         NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
                         NM_SETTING_IP6_CONFIG_METHOD_DISABLED))
            ip6 = FALSE;
        ip6_may_fail = nm_setting_ip_config_get_may_fail(s_ip6);
    }

    if (ip4 && !ip6) {
        if (!(priv->ip_types & NM_MODEM_IP_TYPE_IPV4)) {
            g_set_error_literal(error,
                                NM_DEVICE_ERROR,
                                NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
                                "Connection requested IPv4 but IPv4 is "
                                "unsupported by the modem.");
            return NULL;
        }
        return build_single_ip_type_array(NM_MODEM_IP_TYPE_IPV4);
    }

    if (ip6 && !ip4) {
        if (!(priv->ip_types & NM_MODEM_IP_TYPE_IPV6)) {
            g_set_error_literal(error,
                                NM_DEVICE_ERROR,
                                NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
                                "Connection requested IPv6 but IPv6 is "
                                "unsupported by the modem.");
            return NULL;
        }
        return build_single_ip_type_array(NM_MODEM_IP_TYPE_IPV6);
    }

    if (ip4 && ip6) {
        NMModemIPType type;
        GArray       *out;

        out = g_array_sized_new(FALSE, FALSE, sizeof(NMModemIPType), 3);

        /* Modem supports dual-stack? */
        if (priv->ip_types & NM_MODEM_IP_TYPE_IPV4V6) {
            type = NM_MODEM_IP_TYPE_IPV4V6;
            g_array_append_val(out, type);
        }

        /* If IPv6 may-fail=false, we should NOT try IPv4 as fallback */
        if ((priv->ip_types & NM_MODEM_IP_TYPE_IPV4) && ip6_may_fail) {
            type = NM_MODEM_IP_TYPE_IPV4;
            g_array_append_val(out, type);
        }

        /* If IPv4 may-fail=false, we should NOT try IPv6 as fallback */
        if ((priv->ip_types & NM_MODEM_IP_TYPE_IPV6) && ip4_may_fail) {
            type = NM_MODEM_IP_TYPE_IPV6;
            g_array_append_val(out, type);
        }

        if (out->len > 0)
            return out;

        /* Error... */
        g_array_unref(out);
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
                            "Connection requested both IPv4 and IPv6 "
                            "but dual-stack addressing is unsupported "
                            "by the modem.");
        return NULL;
    }

    g_set_error_literal(error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
                        "Connection specified no IP configuration!");
    return NULL;
}

/**
 * nm_modem_get_initial_eps_bearer_ip_type:
 * @connection_ip_types: the #NMModemIPType as returned by
 * nm_modem_get_connection_ip_type
 *
 * Given the connection IP types, this function returns which IP type to use when
 * configuring the initial EPS bearer.
 *
 * Returns: the #NMModemIpType value to use for the initial EPS bearer
 */
NMModemIPType
nm_modem_get_initial_eps_bearer_ip_type(const GArray *connection_ip_types)
{
    NMModemIPType ip_types = NM_MODEM_IP_TYPE_UNKNOWN;
    guint         i;

    nm_assert(connection_ip_types);

    for (i = 0; i < connection_ip_types->len; i++)
        ip_types |= nm_g_array_index(connection_ip_types, NMModemIPType, i);

    nm_assert(ip_types != NM_MODEM_IP_TYPE_UNKNOWN);

    if (ip_types & NM_MODEM_IP_TYPE_IPV4V6)
        return NM_MODEM_IP_TYPE_IPV4V6;
    if (ip_types & NM_MODEM_IP_TYPE_IPV4)
        return NM_MODEM_IP_TYPE_IPV4;

    return NM_MODEM_IP_TYPE_IPV6;
}

const char *
nm_modem_get_device_id(NMModem *self)
{
    return NM_MODEM_GET_PRIVATE(self)->device_id;
}

const char *
nm_modem_get_sim_id(NMModem *self)
{
    return NM_MODEM_GET_PRIVATE(self)->sim_id;
}

const char *
nm_modem_get_sim_operator_id(NMModem *self)
{
    return NM_MODEM_GET_PRIVATE(self)->sim_operator_id;
}

const char *
nm_modem_get_operator_code(NMModem *self)
{
    return NM_MODEM_GET_PRIVATE(self)->operator_code;
}

const char *
nm_modem_get_apn(NMModem *self)
{
    return NM_MODEM_GET_PRIVATE(self)->apn;
}

/*****************************************************************************/

static void
_ppp_mgr_cleanup(NMModem *self)
{
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(self);

    nm_clear_pointer(&priv->ppp_mgr, nm_ppp_mgr_destroy);
}

static void
_ppp_maybe_emit_new_config(NMModem *self, int addr_family)
{
    NMModemPrivate       *priv    = NM_MODEM_GET_PRIVATE(self);
    const int             IS_IPv4 = NM_IS_IPv4(addr_family);
    const NMPppMgrIPData *ip_data;
    gboolean              do_auto;

    ip_data = nm_ppp_mgr_get_ip_data(priv->ppp_mgr, addr_family);

    if (!ip_data->ip_received)
        return;

    if (IS_IPv4)
        do_auto = FALSE;
    else {
        do_auto = !ip_data->l3cd
                  || (!nm_l3_config_data_get_first_obj(ip_data->l3cd,
                                                       NMP_OBJECT_TYPE_IP6_ADDRESS,
                                                       nmp_object_ip6_address_is_not_link_local));
    }

    nm_assert(!IS_IPv4 || !ip_data->ipv6_iid);

    nm_modem_emit_signal_new_config_success(self,
                                            addr_family,
                                            ip_data->l3cd,
                                            do_auto,
                                            ip_data->ipv6_iid);
}

static void
_ppp_mgr_callback(NMPppMgr *ppp_mgr, const NMPppMgrCallbackData *callback_data, gpointer user_data)
{
    NMModem        *self = NM_MODEM(user_data);
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(self);
    int             IS_IPv4;

    switch (callback_data->callback_type) {
    case NM_PPP_MGR_CALLBACK_TYPE_STATE_CHANGED:

        if (callback_data->data.state >= _NM_PPP_MGR_STATE_FAILED_START) {
            nm_modem_emit_ppp_failed(self, callback_data->data.reason);
            return;
        }

        if (callback_data->data.state >= NM_PPP_MGR_STATE_HAVE_IFINDEX)
            _set_ip_ifindex(self, callback_data->data.ifindex);

        if (callback_data->data.state >= NM_PPP_MGR_STATE_HAVE_IP_CONFIG) {
            for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
                if (!priv->ip_data_x[IS_IPv4].stage3_started) {
                    /* stage3 didn't yet start. We don't emit the IP signal yet.
                     * We will emit it together with stage3. */
                    continue;
                }
                if (priv->ip_data_x[IS_IPv4].stage3_on_idle_source) {
                    /* We scheduled already a handler. Let it handle the new configuration. */
                    continue;
                }
                if (callback_data->data.ip_changed_x[IS_IPv4])
                    _ppp_maybe_emit_new_config(self, IS_IPv4 ? AF_INET : AF_INET6);
            }
        }
        return;

    case NM_PPP_MGR_CALLBACK_TYPE_STATS_CHANGED:
        g_signal_emit(self,
                      signals[PPP_STATS],
                      0,
                      (guint) callback_data->data.stats_data->in_bytes,
                      (guint) callback_data->data.stats_data->out_bytes);
        return;
    }

    nm_assert_not_reached();
}

/*****************************************************************************/

static gboolean
port_speed_is_zero(const char *port)
{
    struct termios    options;
    nm_auto_close int fd   = -1;
    gs_free char     *path = NULL;

    nm_assert(port);

    if (port[0] != '/') {
        if (!port[0] || strchr(port, '/') || NM_IN_STRSET(port, ".", ".."))
            return FALSE;
        path = g_build_path("/sys/class/tty", port, NULL);
        port = path;
    }

    fd = open(port, O_RDWR | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (fd < 0)
        return FALSE;

    memset(&options, 0, sizeof(struct termios));
    if (tcgetattr(fd, &options) != 0)
        return FALSE;

    return cfgetospeed(&options) == B0;
}

/*****************************************************************************/

static gboolean
_stage3_ip_config_start_on_idle(NMModem *self, int addr_family)
{
    const int             IS_IPv4 = NM_IS_IPv4(addr_family);
    NMModemPrivate       *priv    = NM_MODEM_GET_PRIVATE(self);
    NMModemIPMethod       ip_method;
    NMConnection         *connection;
    const char           *method;
    gs_free_error GError *error = NULL;
    NMDeviceStateReason   failure_reason;

    nm_clear_g_source_inst(&priv->ip_data_x[IS_IPv4].stage3_on_idle_source);

    connection = nm_act_request_get_applied_connection(priv->act_req);
    g_return_val_if_fail(connection, G_SOURCE_CONTINUE);

    method = nm_utils_get_ip_config_method(connection, addr_family);

    if (IS_IPv4 ? NM_IN_STRSET(method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)
                : NM_IN_STRSET(method,
                               NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
                               NM_SETTING_IP6_CONFIG_METHOD_DISABLED)) {
        nm_modem_emit_signal_new_config_success(self, addr_family, NULL, FALSE, NULL);
        return G_SOURCE_CONTINUE;
    }

    if (!nm_streq(method,
                  IS_IPv4 ? NM_SETTING_IP4_CONFIG_METHOD_AUTO
                          : NM_SETTING_IP6_CONFIG_METHOD_AUTO)) {
        failure_reason = NM_DEVICE_STATE_REASON_IP_METHOD_UNSUPPORTED;
        nm_utils_error_set(&error, NM_UTILS_ERROR_UNKNOWN, "ip method unsupported by modem");
        goto out_failure;
    }

    ip_method = IS_IPv4 ? priv->ip4_method : priv->ip6_method;

    switch (ip_method) {
    case NM_MODEM_IP_METHOD_PPP:
        _ppp_maybe_emit_new_config(self, addr_family);
        return G_SOURCE_CONTINUE;
    case NM_MODEM_IP_METHOD_STATIC:
    case NM_MODEM_IP_METHOD_AUTO:
        NM_MODEM_GET_CLASS(self)->stage3_ip_config_start(self, addr_family, ip_method);
        return G_SOURCE_CONTINUE;
    default:
        failure_reason = NM_DEVICE_STATE_REASON_IP_METHOD_UNSUPPORTED;
        nm_utils_error_set(&error, NM_UTILS_ERROR_UNKNOWN, "modem IP method unsupported");
        goto out_failure;
    }

    nm_assert_not_reached();

out_failure:
    nm_modem_emit_signal_new_config_failure(self, addr_family, failure_reason, error);
    return G_SOURCE_CONTINUE;
}

static gboolean
_stage3_ip_config_start_on_idle_4(gpointer user_data)
{
    return _stage3_ip_config_start_on_idle(user_data, AF_INET);
}

static gboolean
_stage3_ip_config_start_on_idle_6(gpointer user_data)
{
    return _stage3_ip_config_start_on_idle(user_data, AF_INET6);
}

gboolean
nm_modem_stage3_ip_config_start(NMModem *self, int addr_family, NMDevice *device)
{
    const int       IS_IPv4 = NM_IS_IPv4(addr_family);
    NMModemPrivate *priv;

    g_return_val_if_fail(NM_IS_MODEM(self), FALSE);
    g_return_val_if_fail(NM_IS_DEVICE(device), FALSE);

    priv = NM_MODEM_GET_PRIVATE(self);

    g_return_val_if_fail(priv->device == device, FALSE);

    if (priv->ip_data_x[IS_IPv4].stage3_started) {
        /* we already started. Nothing to do. */
        return FALSE;
    }

    nm_assert(!priv->ppp_mgr
              || nm_ppp_mgr_get_state(priv->ppp_mgr) >= NM_PPP_MGR_STATE_HAVE_IFINDEX);

    priv->ip_data_x[IS_IPv4].stage3_started = TRUE;

    priv->ip_data_x[IS_IPv4].stage3_on_idle_source = nm_g_idle_add_source(
        IS_IPv4 ? _stage3_ip_config_start_on_idle_4 : _stage3_ip_config_start_on_idle_6,
        self);
    return TRUE;
}

/*****************************************************************************/

guint32
nm_modem_get_configured_mtu(NMDevice *self, NMDeviceMtuSource *out_source, gboolean *out_force)
{
    NMConnection *connection;
    NMSetting    *setting;
    gint64        mtu_default;
    guint         mtu = 0;
    const char   *property_name;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(out_source);

    connection = nm_device_get_applied_connection(self);
    if (!connection)
        g_return_val_if_reached(0);

    setting = (NMSetting *) nm_connection_get_setting_gsm(connection);
    if (!setting)
        setting = (NMSetting *) nm_connection_get_setting_cdma(connection);

    if (setting) {
        g_object_get(setting, "mtu", &mtu, NULL);
        if (mtu) {
            *out_source = NM_DEVICE_MTU_SOURCE_CONNECTION;
            return mtu;
        }

        property_name = NM_IS_SETTING_GSM(setting) ? "gsm.mtu" : "cdma.mtu";
        mtu_default =
            nm_device_get_configured_mtu_from_connection_default(self, property_name, G_MAXUINT32);
        if (mtu_default >= 0) {
            *out_source = NM_DEVICE_MTU_SOURCE_CONNECTION;
            return (guint32) mtu_default;
        }
    }

    *out_source = NM_DEVICE_MTU_SOURCE_NONE;
    return 0;
}

/*****************************************************************************/

static void
cancel_get_secrets(NMModem *self)
{
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(self);

    if (priv->secrets_id)
        nm_act_request_cancel_secrets(priv->act_req, priv->secrets_id);
}

static void
modem_secrets_cb(NMActRequest                 *req,
                 NMActRequestGetSecretsCallId *call_id,
                 NMSettingsConnection         *connection,
                 GError                       *error,
                 gpointer                      user_data)
{
    NMModem        *self = NM_MODEM(user_data);
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(self);

    g_return_if_fail(call_id == priv->secrets_id);

    priv->secrets_id = NULL;

    if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)
        || g_error_matches(error, NM_AGENT_MANAGER_ERROR, NM_AGENT_MANAGER_ERROR_NO_SECRETS))
        return;

    if (error)
        _LOGW("modem-secrets: %s", error->message);

    _LOGD("signal: auth-result: %s%s",
          NM_PRINT_FMT_QUOTED2(error, "failed: ", error->message, "success"));
    g_signal_emit(self, signals[AUTH_RESULT], 0, error);
}

void
nm_modem_get_secrets(NMModem    *self,
                     const char *setting_name,
                     gboolean    request_new,
                     const char *hint)
{
    NMModemPrivate              *priv  = NM_MODEM_GET_PRIVATE(self);
    NMSecretAgentGetSecretsFlags flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;

    cancel_get_secrets(self);

    if (request_new)
        flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;
    priv->secrets_id = nm_act_request_get_secrets(priv->act_req,
                                                  FALSE,
                                                  setting_name,
                                                  flags,
                                                  NM_MAKE_STRV(hint),
                                                  modem_secrets_cb,
                                                  self);
    g_return_if_fail(priv->secrets_id);
    nm_modem_emit_auth_requested(self);
}

/*****************************************************************************/

static NMActStageReturn
modem_act_stage1_prepare(NMModem             *modem,
                         NMConnection        *connection,
                         NMDeviceStateReason *out_failure_reason)
{
    NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_UNKNOWN);
    return NM_ACT_STAGE_RETURN_FAILURE;
}

NMActStageReturn
nm_modem_act_stage1_prepare(NMModem             *self,
                            NMActRequest        *req,
                            NMDeviceStateReason *out_failure_reason)
{
    NMModemPrivate              *priv         = NM_MODEM_GET_PRIVATE(self);
    gs_unref_ptrarray GPtrArray *hints        = NULL;
    const char                  *setting_name = NULL;
    NMSecretAgentGetSecretsFlags flags        = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;
    NMConnection                *connection;
    NMDevice                    *device;

    g_return_val_if_fail(NM_IS_ACT_REQUEST(req), NM_ACT_STAGE_RETURN_FAILURE);

    nm_g_object_ref_set(&priv->act_req, req);
    device = nm_active_connection_get_device(NM_ACTIVE_CONNECTION(priv->act_req));
    g_return_val_if_fail(NM_IS_DEVICE(device), NM_ACT_STAGE_RETURN_FAILURE);

    connection = nm_act_request_get_applied_connection(req);
    g_return_val_if_fail(connection, NM_ACT_STAGE_RETURN_FAILURE);

    nm_g_object_ref_set(&priv->device, device);

    setting_name = nm_connection_need_secrets(connection, &hints);
    if (!setting_name) {
        nm_assert(!hints);
        return NM_MODEM_GET_CLASS(self)->modem_act_stage1_prepare(self,
                                                                  connection,
                                                                  out_failure_reason);
    }

    /* Secrets required... */
    if (priv->secrets_tries++)
        flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;

    if (hints)
        g_ptr_array_add(hints, NULL);

    priv->secrets_id = nm_act_request_get_secrets(req,
                                                  FALSE,
                                                  setting_name,
                                                  flags,
                                                  hints ? (const char *const *) hints->pdata : NULL,
                                                  modem_secrets_cb,
                                                  self);
    g_return_val_if_fail(priv->secrets_id, NM_ACT_STAGE_RETURN_FAILURE);
    nm_modem_emit_auth_requested(self);
    return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/

NMActStageReturn
nm_modem_act_stage2_config(NMModem *self, NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMModemPrivate *priv;
    gboolean        needs_ppp;

    g_return_val_if_fail(NM_IS_MODEM(self), NM_ACT_STAGE_RETURN_FAILURE);
    g_return_val_if_fail(NM_IS_DEVICE(device), NM_ACT_STAGE_RETURN_FAILURE);

    priv = NM_MODEM_GET_PRIVATE(self);

    g_return_val_if_fail(priv->device == device, NM_ACT_STAGE_RETURN_FAILURE);

    /* Clear secrets tries counter since secrets were successfully used
     * already if we get here.
     */
    priv->secrets_tries = 0;

    needs_ppp =
        (priv->ip4_method == NM_MODEM_IP_METHOD_PPP || priv->ip6_method == NM_MODEM_IP_METHOD_PPP);

    if (needs_ppp && !priv->ppp_mgr) {
        const char           *ppp_name = NULL;
        gs_free_error GError *error    = NULL;
        guint                 ip_timeout;
        guint                 baud_override;
        NMActRequest         *req;

        req = nm_device_get_act_request(device);
        g_return_val_if_fail(req, NM_ACT_STAGE_RETURN_FAILURE);

        if (NM_MODEM_GET_CLASS(self)->get_user_pass) {
            NMConnection *connection = nm_act_request_get_applied_connection(req);

            g_return_val_if_fail(connection, NM_ACT_STAGE_RETURN_FAILURE);
            if (!NM_MODEM_GET_CLASS(self)->get_user_pass(self, connection, &ppp_name, NULL))
                return NM_ACT_STAGE_RETURN_FAILURE;
        }

        if (!priv->data_port) {
            _LOGW("error starting PPP (no data port)");
            NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_PPP_START_FAILED);
            return NM_ACT_STAGE_RETURN_FAILURE;
        }

        /* Check if ModemManager requested a specific IP timeout to be used. If 0 reported,
         * use the default one (30s) */
        if (priv->mm_ip_timeout > 0) {
            _LOGI("using modem-specified IP timeout: %u seconds", priv->mm_ip_timeout);
            ip_timeout = priv->mm_ip_timeout;
        } else
            ip_timeout = 30;

        /* Some tty drivers and modems ignore port speed, but pppd requires the
         * port speed to be > 0 or it exits. If the port speed is 0 pass an
         * explicit speed to pppd to prevent the exit.
         * https://bugzilla.redhat.com/show_bug.cgi?id=1281731
         */
        if (port_speed_is_zero(priv->data_port))
            baud_override = 57600;
        else
            baud_override = 0;

        priv->ppp_mgr = nm_ppp_mgr_start(&((const NMPppMgrConfig){
                                             .netns         = nm_device_get_netns(device),
                                             .parent_iface  = priv->data_port,
                                             .callback      = _ppp_mgr_callback,
                                             .user_data     = self,
                                             .act_req       = req,
                                             .ppp_username  = ppp_name,
                                             .timeout_secs  = ip_timeout,
                                             .baud_override = baud_override,
                                         }),
                                         &error);
        if (!priv->ppp_mgr) {
            _LOGW("PPP failed to start: %s", error->message);
            *out_failure_reason = NM_DEVICE_STATE_REASON_PPP_START_FAILED;
            return NM_ACT_STAGE_RETURN_FAILURE;
        }

        return NM_ACT_STAGE_RETURN_POSTPONE;
    }

    if (needs_ppp && nm_ppp_mgr_get_state(priv->ppp_mgr) < NM_PPP_MGR_STATE_HAVE_IFINDEX)
        return NM_ACT_STAGE_RETURN_POSTPONE;

    return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*****************************************************************************/

gboolean
nm_modem_check_connection_compatible(NMModem *self, NMConnection *connection, GError **error)
{
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(self);

    if (nm_streq0(nm_connection_get_connection_type(connection), NM_SETTING_GSM_SETTING_NAME)) {
        NMSettingGsm *s_gsm;
        const char   *str;

        s_gsm = _nm_connection_check_main_setting(connection, NM_SETTING_GSM_SETTING_NAME, error);
        if (!s_gsm)
            return FALSE;

        str = nm_setting_gsm_get_device_id(s_gsm);
        if (str) {
            if (!priv->device_id) {
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                           "GSM profile has device-id, device does not");
                return FALSE;
            }
            if (!nm_streq(str, priv->device_id)) {
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                           "device has differing device-id than GSM profile");
                return FALSE;
            }
        }

        /* SIM properties may not be available before the SIM is unlocked, so
         * to ensure that autoconnect works, the connection's SIM properties
         * are only compared if present on the device.
         */

        if (priv->sim_id && (str = nm_setting_gsm_get_sim_id(s_gsm))) {
            if (!nm_streq(str, priv->sim_id)) {
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                           "device has differing sim-id than GSM profile");
                return FALSE;
            }
        }

        if (priv->sim_operator_id && (str = nm_setting_gsm_get_sim_operator_id(s_gsm))) {
            if (!nm_streq(str, priv->sim_operator_id)) {
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                           "device has differing sim-operator-id than GSM profile");
                return FALSE;
            }
        }
    }

    return NM_MODEM_GET_CLASS(self)->check_connection_compatible_with_modem(self,
                                                                            connection,
                                                                            error);
}

/*****************************************************************************/

gboolean
nm_modem_complete_connection(NMModem             *self,
                             const char          *iface,
                             NMConnection        *connection,
                             NMConnection *const *existing_connections,
                             GError             **error)
{
    NMModemClass *klass;

    klass = NM_MODEM_GET_CLASS(self);
    if (!klass->complete_connection) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_INVALID_CONNECTION,
                    "Modem class %s had no complete_connection method",
                    G_OBJECT_TYPE_NAME(self));
        return FALSE;
    }

    return klass->complete_connection(self, iface, connection, existing_connections, error);
}

/*****************************************************************************/

static void
deactivate_cleanup(NMModem *self, NMDevice *device, gboolean stop_ppp_manager)
{
    NMModemPrivate *priv;
    int             ifindex;
    int             IS_IPv4;

    g_return_if_fail(NM_IS_MODEM(self));

    priv = NM_MODEM_GET_PRIVATE(self);

    for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
        priv->ip_data_x[IS_IPv4].stage3_started = FALSE;
        nm_clear_g_source_inst(&priv->ip_data_x[IS_IPv4].stage3_on_idle_source);
    }

    priv->secrets_tries = 0;

    if (priv->act_req) {
        cancel_get_secrets(self);
        g_clear_object(&priv->act_req);
    }
    g_clear_object(&priv->device);

    _ppp_mgr_cleanup(self);

    if (device) {
        g_return_if_fail(NM_IS_DEVICE(device));

        if (priv->ip4_method == NM_MODEM_IP_METHOD_STATIC
            || priv->ip4_method == NM_MODEM_IP_METHOD_AUTO
            || priv->ip6_method == NM_MODEM_IP_METHOD_STATIC
            || priv->ip6_method == NM_MODEM_IP_METHOD_AUTO) {
            ifindex = nm_device_get_ip_ifindex(device);
            if (ifindex > 0) {
                NMPlatform *platform = nm_device_get_platform(device);

                nm_platform_ip_route_flush(platform, AF_UNSPEC, ifindex);
                nm_platform_ip_address_flush(platform, AF_UNSPEC, ifindex);
                nm_platform_link_change_flags(platform, ifindex, IFF_UP, FALSE);
            }
        }
    }

    nm_clear_g_free(&priv->data_port);
    priv->mm_ip_timeout = 0;
    priv->ip4_method    = NM_MODEM_IP_METHOD_UNKNOWN;
    priv->ip6_method    = NM_MODEM_IP_METHOD_UNKNOWN;
    _set_ip_ifindex(self, -1);
}

/*****************************************************************************/

typedef struct {
    NMModem                  *self;
    NMDevice                 *device;
    GCancellable             *cancellable;
    NMModemDeactivateCallback callback;
    gpointer                  callback_user_data;
} DeactivateContext;

static void
deactivate_context_complete(DeactivateContext *ctx, GError *error)
{
    NMModem *self = ctx->self;

    _LOGD("modem deactivation finished %s%s%s",
          NM_PRINT_FMT_QUOTED(error, "with failure: ", error->message, "", "successfully"));

    if (ctx->callback)
        ctx->callback(ctx->self, error, ctx->callback_user_data);
    nm_g_object_unref(ctx->cancellable);
    g_object_unref(ctx->device);
    g_object_unref(ctx->self);
    g_slice_free(DeactivateContext, ctx);
}

static void
_deactivate_call_disconnect_cb(NMModem *self, GError *error, gpointer user_data)
{
    deactivate_context_complete(user_data, error);
}

static void
_deactivate_call_disconnect(DeactivateContext *ctx)
{
    NM_MODEM_GET_CLASS(ctx->self)->disconnect(ctx->self,
                                              FALSE,
                                              ctx->cancellable,
                                              _deactivate_call_disconnect_cb,
                                              ctx);
}

static void
_deactivate_ppp_manager_stop_cb(NMPPPManager           *ppp_manager,
                                NMPPPManagerStopHandle *handle,
                                gboolean                was_cancelled,
                                gpointer                user_data)
{
    DeactivateContext *ctx = user_data;

    g_object_unref(ppp_manager);

    if (was_cancelled) {
        gs_free_error GError *error = NULL;

        if (!g_cancellable_set_error_if_cancelled(ctx->cancellable, &error))
            nm_assert_not_reached();
        deactivate_context_complete(ctx, error);
        return;
    }

    nm_assert(!g_cancellable_is_cancelled(ctx->cancellable));
    _deactivate_call_disconnect(ctx);
}

void
nm_modem_deactivate_async(NMModem                  *self,
                          NMDevice                 *device,
                          GCancellable             *cancellable,
                          NMModemDeactivateCallback callback,
                          gpointer                  user_data)
{
    NMModemPrivate    *priv = NM_MODEM_GET_PRIVATE(self);
    DeactivateContext *ctx;
    NMPPPManager      *ppp_manager;

    g_return_if_fail(NM_IS_MODEM(self));
    g_return_if_fail(NM_IS_DEVICE(device));
    g_return_if_fail(G_IS_CANCELLABLE(cancellable));

    ctx                     = g_slice_new(DeactivateContext);
    ctx->self               = g_object_ref(self);
    ctx->device             = g_object_ref(device);
    ctx->cancellable        = g_object_ref(cancellable);
    ctx->callback           = callback;
    ctx->callback_user_data = user_data;

    ppp_manager = nm_g_object_ref(priv->ppp_manager);

    NM_MODEM_GET_CLASS(self)->deactivate_cleanup(self, ctx->device, FALSE);

    if (ppp_manager) {
        /* If we have a PPP manager, stop it.
         *
         * Pass on the reference in @ppp_manager. */
        nm_ppp_manager_stop(ppp_manager, ctx->cancellable, _deactivate_ppp_manager_stop_cb, ctx);
        return;
    }

    _deactivate_call_disconnect(ctx);
}

/*****************************************************************************/

void
nm_modem_deactivate(NMModem *self, NMDevice *device)
{
    /* First cleanup */
    NM_MODEM_GET_CLASS(self)->deactivate_cleanup(self, device, TRUE);
    /* Then disconnect without waiting */
    NM_MODEM_GET_CLASS(self)->disconnect(self, FALSE, NULL, NULL, NULL);
}

/*****************************************************************************/

void
nm_modem_device_state_changed(NMModem *self, NMDeviceState new_state, NMDeviceState old_state)
{
    gboolean        was_connected = FALSE, warn = TRUE;
    NMModemPrivate *priv;

    g_return_if_fail(NM_IS_MODEM(self));

    if (old_state >= NM_DEVICE_STATE_PREPARE && old_state <= NM_DEVICE_STATE_DEACTIVATING)
        was_connected = TRUE;

    priv = NM_MODEM_GET_PRIVATE(self);

    /* Make sure we don't leave the serial device open */
    switch (new_state) {
    case NM_DEVICE_STATE_UNMANAGED:
    case NM_DEVICE_STATE_UNAVAILABLE:
    case NM_DEVICE_STATE_FAILED:
    case NM_DEVICE_STATE_DISCONNECTED:
        if (priv->act_req) {
            cancel_get_secrets(self);
            g_clear_object(&priv->act_req);
        }
        g_clear_object(&priv->device);

        if (was_connected) {
            /* Don't bother warning on FAILED since the modem is already gone */
            if (new_state == NM_DEVICE_STATE_FAILED || new_state == NM_DEVICE_STATE_DISCONNECTED)
                warn = FALSE;
            /* First cleanup */
            NM_MODEM_GET_CLASS(self)->deactivate_cleanup(self, NULL, TRUE);
            NM_MODEM_GET_CLASS(self)->disconnect(self, warn, NULL, NULL, NULL);
        }
        break;
    default:
        break;
    }
}

/*****************************************************************************/

const char *
nm_modem_get_uid(NMModem *self)
{
    g_return_val_if_fail(NM_IS_MODEM(self), NULL);

    return NM_MODEM_GET_PRIVATE(self)->uid;
}

const char *
nm_modem_get_path(NMModem *self)
{
    g_return_val_if_fail(NM_IS_MODEM(self), NULL);

    return NM_MODEM_GET_PRIVATE(self)->path;
}

const char *
nm_modem_get_driver(NMModem *self)
{
    g_return_val_if_fail(NM_IS_MODEM(self), NULL);

    return NM_MODEM_GET_PRIVATE(self)->driver;
}

const char *
nm_modem_get_control_port(NMModem *self)
{
    g_return_val_if_fail(NM_IS_MODEM(self), NULL);

    return NM_MODEM_GET_PRIVATE(self)->control_port;
}

int
nm_modem_get_ip_ifindex(NMModem *self)
{
    NMModemPrivate *priv;

    g_return_val_if_fail(NM_IS_MODEM(self), 0);

    priv = NM_MODEM_GET_PRIVATE(self);

    /* internally we track an unset ip_ifindex as -1.
     * For the caller of nm_modem_get_ip_ifindex(), this
     * shall be zero too. */
    return priv->ip_ifindex != -1 ? priv->ip_ifindex : 0;
}

static void
_set_ip_ifindex(NMModem *self, int ifindex)
{
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(self);

    nm_assert(ifindex >= -1);

    if (priv->ip_ifindex != ifindex) {
        _LOGD("signal: ifindex changed: %d", ifindex);
        priv->ip_ifindex = ifindex;
        _notify(self, PROP_IP_IFINDEX);
    }
}

gboolean
nm_modem_set_data_port(NMModem        *self,
                       NMPlatform     *platform,
                       const char     *data_port,
                       NMModemIPMethod ip4_method,
                       NMModemIPMethod ip6_method,
                       guint           timeout,
                       GError        **error)
{
    NMModemPrivate *priv;
    gboolean        is_ppp;
    int             ifindex = -1;

    g_return_val_if_fail(NM_IS_MODEM(self), FALSE);
    g_return_val_if_fail(NM_IS_PLATFORM(platform), FALSE);
    g_return_val_if_fail(!error || !*error, FALSE);

    priv = NM_MODEM_GET_PRIVATE(self);

    if (priv->ppp_manager || priv->data_port || priv->ip_ifindex != -1) {
        g_set_error_literal(error,
                            NM_UTILS_ERROR,
                            NM_UTILS_ERROR_UNKNOWN,
                            "cannot set data port in activated state");
        /* this really shouldn't happen. Assert. */
        g_return_val_if_reached(FALSE);
    }

    if (!data_port) {
        g_set_error_literal(error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN, "missing data port");
        return FALSE;
    }

    is_ppp = (ip4_method == NM_MODEM_IP_METHOD_PPP) || (ip6_method == NM_MODEM_IP_METHOD_PPP);
    if (is_ppp) {
        if (!NM_IN_SET(ip4_method, NM_MODEM_IP_METHOD_UNKNOWN, NM_MODEM_IP_METHOD_PPP)
            || !NM_IN_SET(ip6_method, NM_MODEM_IP_METHOD_UNKNOWN, NM_MODEM_IP_METHOD_PPP)) {
            g_set_error_literal(error,
                                NM_UTILS_ERROR,
                                NM_UTILS_ERROR_UNKNOWN,
                                "conflicting ip methods");
            return FALSE;
        }
    } else if (!NM_IN_SET(ip4_method,
                          NM_MODEM_IP_METHOD_UNKNOWN,
                          NM_MODEM_IP_METHOD_STATIC,
                          NM_MODEM_IP_METHOD_AUTO)
               || !NM_IN_SET(ip6_method,
                             NM_MODEM_IP_METHOD_UNKNOWN,
                             NM_MODEM_IP_METHOD_STATIC,
                             NM_MODEM_IP_METHOD_AUTO)
               || (ip4_method == NM_MODEM_IP_METHOD_UNKNOWN
                   && ip6_method == NM_MODEM_IP_METHOD_UNKNOWN)) {
        g_set_error_literal(error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN, "invalid ip methods");
        return FALSE;
    }

    if (!is_ppp) {
        ifindex = nm_platform_if_nametoindex(platform, data_port);
        if (ifindex <= 0) {
            g_set_error(error,
                        NM_UTILS_ERROR,
                        NM_UTILS_ERROR_UNKNOWN,
                        "cannot find network interface %s",
                        data_port);
            return FALSE;
        }
        if (!nm_platform_process_events_ensure_link(platform, ifindex, data_port)) {
            g_set_error(error,
                        NM_UTILS_ERROR,
                        NM_UTILS_ERROR_UNKNOWN,
                        "cannot find network interface %s in platform cache",
                        data_port);
            return FALSE;
        }
    }

    priv->mm_ip_timeout = timeout;
    priv->ip4_method    = ip4_method;
    priv->ip6_method    = ip6_method;
    if (is_ppp) {
        priv->data_port = g_strdup(data_port);
        _set_ip_ifindex(self, -1);
    } else {
        priv->data_port = NULL;
        _set_ip_ifindex(self, ifindex);
    }
    return TRUE;
}

gboolean
nm_modem_owns_port(NMModem *self, const char *iface)
{
    NMModemPrivate       *priv = NM_MODEM_GET_PRIVATE(self);
    NMPlatform           *platform;
    const NMPlatformLink *plink;

    g_return_val_if_fail(iface != NULL, FALSE);

    if (NM_MODEM_GET_CLASS(self)->owns_port)
        return NM_MODEM_GET_CLASS(self)->owns_port(self, iface);

    if (NM_IN_STRSET(iface, priv->data_port, priv->control_port))
        return TRUE;

    /* FIXME(parent-child-relationship): the whole notion of "owns-port" is wrong.
     * When we have a name (iface) it must be always clear what this name is (which
     * domain). Mixing data_port, control_port and devlink names is wrong. Looking
     * up devlinks by name is also wrong (use ifindex). */
    if (priv->ip_ifindex > 0 && (platform = _get_platform(self))
        && (plink = nm_platform_link_get(platform, priv->ip_ifindex))
        && nm_streq(iface, plink->name))
        return TRUE;

    return FALSE;
}

/*****************************************************************************/

void
nm_modem_get_capabilities(NMModem                   *self,
                          NMDeviceModemCapabilities *modem_caps,
                          NMDeviceModemCapabilities *current_caps)
{
    g_return_if_fail(NM_IS_MODEM(self));

    NM_MODEM_GET_CLASS(self)->get_capabilities(self, modem_caps, current_caps);
}

/*****************************************************************************/

void
_nm_modem_set_operator_code(NMModem *self, const char *operator_code)
{
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(self);

    if (!nm_streq0(priv->operator_code, operator_code)) {
        g_free(priv->operator_code);
        priv->operator_code = g_strdup(operator_code);
        _LOGD("signal: operator-code changed: %s%s%s", NM_PRINT_FMT_QUOTE_STRING(operator_code));
        _notify(self, PROP_OPERATOR_CODE);
    }
}

void
_nm_modem_set_apn(NMModem *self, const char *apn)
{
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(self);

    if (!nm_streq0(priv->apn, apn)) {
        g_free(priv->apn);
        priv->apn = g_strdup(apn);
        _LOGD("signal: apn changed: %s%s%s", NM_PRINT_FMT_QUOTE_STRING(apn));
        _notify(self, PROP_APN);
    }
}

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMModem        *self = NM_MODEM(object);
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_PATH:
        g_value_set_string(value, priv->path);
        break;
    case PROP_DRIVER:
        g_value_set_string(value, priv->driver);
        break;
    case PROP_CONTROL_PORT:
        g_value_set_string(value, priv->control_port);
        break;
    case PROP_IP_IFINDEX:
        g_value_set_int(value, nm_modem_get_ip_ifindex(self));
        break;
    case PROP_UID:
        g_value_set_string(value, priv->uid);
        break;
    case PROP_STATE:
        g_value_set_int(value, priv->state);
        break;
    case PROP_DEVICE_ID:
        g_value_set_string(value, priv->device_id);
        break;
    case PROP_SIM_ID:
        g_value_set_string(value, priv->sim_id);
        break;
    case PROP_IP_TYPES:
        g_value_set_uint(value, priv->ip_types);
        break;
    case PROP_SIM_OPERATOR_ID:
        g_value_set_string(value, priv->sim_operator_id);
        break;
    case PROP_OPERATOR_CODE:
        g_value_set_string(value, priv->operator_code);
        break;
    case PROP_APN:
        g_value_set_string(value, priv->apn);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(object);
    const char     *s;

    switch (prop_id) {
    case PROP_PATH:
        /* construct-only */
        priv->path = g_value_dup_string(value);
        g_return_if_fail(priv->path);
        break;
    case PROP_DRIVER:
        /* construct-only */
        priv->driver = g_value_dup_string(value);
        break;
    case PROP_CONTROL_PORT:
        /* construct-only */
        priv->control_port = g_value_dup_string(value);
        break;
    case PROP_UID:
        /* construct-only */
        priv->uid = g_value_dup_string(value);
        break;
    case PROP_STATE:
        /* construct-only */
        priv->state = g_value_get_int(value);
        break;
    case PROP_DEVICE_ID:
        /* construct-only */
        priv->device_id = g_value_dup_string(value);
        break;
    case PROP_SIM_ID:
        g_free(priv->sim_id);
        priv->sim_id = g_value_dup_string(value);
        break;
    case PROP_IP_TYPES:
        priv->ip_types = g_value_get_uint(value);
        break;
    case PROP_SIM_OPERATOR_ID:
        nm_clear_g_free(&priv->sim_operator_id);
        s = g_value_get_string(value);
        if (s && s[0])
            priv->sim_operator_id = g_strdup(s);
        break;
    case PROP_OPERATOR_CODE:
        /* construct-only */
        priv->operator_code = g_value_dup_string(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_modem_init(NMModem *self)
{
    NMModemPrivate *priv;

    self->_priv = G_TYPE_INSTANCE_GET_PRIVATE(self, NM_TYPE_MODEM, NMModemPrivate);
    priv        = self->_priv;

    priv->ip_ifindex = -1;
}

static void
constructed(GObject *object)
{
    NMModemPrivate *priv;

    G_OBJECT_CLASS(nm_modem_parent_class)->constructed(object);

    priv = NM_MODEM_GET_PRIVATE(NM_MODEM(object));

    g_return_if_fail(priv->control_port);
}

/*****************************************************************************/

static void
dispose(GObject *object)
{
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(object);

    g_clear_object(&priv->act_req);
    g_clear_object(&priv->device);

    G_OBJECT_CLASS(nm_modem_parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
    NMModemPrivate *priv = NM_MODEM_GET_PRIVATE(object);

    g_free(priv->uid);
    g_free(priv->path);
    g_free(priv->driver);
    g_free(priv->control_port);
    g_free(priv->data_port);
    g_free(priv->device_id);
    g_free(priv->sim_id);
    g_free(priv->sim_operator_id);
    g_free(priv->operator_code);
    g_free(priv->apn);

    G_OBJECT_CLASS(nm_modem_parent_class)->finalize(object);
}

static void
nm_modem_class_init(NMModemClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    g_type_class_add_private(object_class, sizeof(NMModemPrivate));

    object_class->constructed  = constructed;
    object_class->set_property = set_property;
    object_class->get_property = get_property;
    object_class->dispose      = dispose;
    object_class->finalize     = finalize;

    klass->modem_act_stage1_prepare = modem_act_stage1_prepare;
    klass->deactivate_cleanup       = deactivate_cleanup;

    obj_properties[PROP_UID] =
        g_param_spec_string(NM_MODEM_UID,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_PATH] =
        g_param_spec_string(NM_MODEM_PATH,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_DRIVER] =
        g_param_spec_string(NM_MODEM_DRIVER,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_CONTROL_PORT] =
        g_param_spec_string(NM_MODEM_CONTROL_PORT,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_IP_IFINDEX] = g_param_spec_int(NM_MODEM_IP_IFINDEX,
                                                       "",
                                                       "",
                                                       0,
                                                       G_MAXINT,
                                                       0,
                                                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_STATE] =
        g_param_spec_int(NM_MODEM_STATE,
                         "",
                         "",
                         NM_MODEM_STATE_UNKNOWN,
                         _NM_MODEM_STATE_LAST,
                         NM_MODEM_STATE_UNKNOWN,
                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_DEVICE_ID] =
        g_param_spec_string(NM_MODEM_DEVICE_ID,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_SIM_ID] =
        g_param_spec_string(NM_MODEM_SIM_ID,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_IP_TYPES] =
        g_param_spec_uint(NM_MODEM_IP_TYPES,
                          "IP Types",
                          "Supported IP types",
                          0,
                          G_MAXUINT32,
                          NM_MODEM_IP_TYPE_IPV4,
                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_SIM_OPERATOR_ID] =
        g_param_spec_string(NM_MODEM_SIM_OPERATOR_ID,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_OPERATOR_CODE] =
        g_param_spec_string(NM_MODEM_OPERATOR_CODE,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_APN] =
        g_param_spec_string(NM_MODEM_APN, "", "", NULL, G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    signals[PPP_STATS] = g_signal_new(NM_MODEM_PPP_STATS,
                                      G_OBJECT_CLASS_TYPE(object_class),
                                      G_SIGNAL_RUN_FIRST,
                                      0,
                                      NULL,
                                      NULL,
                                      NULL,
                                      G_TYPE_NONE,
                                      2,
                                      G_TYPE_UINT /*guint32 in_bytes*/,
                                      G_TYPE_UINT /*guint32 out_bytes*/);

    signals[PPP_FAILED] = g_signal_new(NM_MODEM_PPP_FAILED,
                                       G_OBJECT_CLASS_TYPE(object_class),
                                       G_SIGNAL_RUN_FIRST,
                                       0,
                                       NULL,
                                       NULL,
                                       NULL,
                                       G_TYPE_NONE,
                                       1,
                                       G_TYPE_UINT);

    /*
     * This signal is emitted when IP configuration has completed or failed.
     * If @error is set the configuration failed. If @l3cd is set, then
     * the details should be applied to the data port before any further
     * configuration (like SLAAC) is done. @do_auto indicates whether DHCPv4/SLAAC
     * should be started after applying @l3cd to the data port.
     */
    signals[NEW_CONFIG] = g_signal_new(NM_MODEM_NEW_CONFIG,
                                       G_OBJECT_CLASS_TYPE(object_class),
                                       G_SIGNAL_RUN_FIRST,
                                       0,
                                       NULL,
                                       NULL,
                                       NULL,
                                       G_TYPE_NONE,
                                       6,
                                       G_TYPE_INT,      /* int addr_family */
                                       G_TYPE_POINTER,  /* const NML3ConfigData *l3cd */
                                       G_TYPE_BOOLEAN,  /* gboolean do_auto */
                                       G_TYPE_POINTER,  /* const NMUtilsIPv6IfaceId *iid */
                                       G_TYPE_INT,      /* NMDeviceStateReason failure_reason */
                                       G_TYPE_POINTER); /* GError *error */

    signals[PREPARE_RESULT] = g_signal_new(NM_MODEM_PREPARE_RESULT,
                                           G_OBJECT_CLASS_TYPE(object_class),
                                           G_SIGNAL_RUN_FIRST,
                                           0,
                                           NULL,
                                           NULL,
                                           NULL,
                                           G_TYPE_NONE,
                                           2,
                                           G_TYPE_BOOLEAN,
                                           G_TYPE_UINT);

    signals[AUTH_REQUESTED] = g_signal_new(NM_MODEM_AUTH_REQUESTED,
                                           G_OBJECT_CLASS_TYPE(object_class),
                                           G_SIGNAL_RUN_FIRST,
                                           0,
                                           NULL,
                                           NULL,
                                           NULL,
                                           G_TYPE_NONE,
                                           0);

    signals[AUTH_RESULT] = g_signal_new(NM_MODEM_AUTH_RESULT,
                                        G_OBJECT_CLASS_TYPE(object_class),
                                        G_SIGNAL_RUN_FIRST,
                                        0,
                                        NULL,
                                        NULL,
                                        NULL,
                                        G_TYPE_NONE,
                                        1,
                                        G_TYPE_POINTER);

    signals[REMOVED] = g_signal_new(NM_MODEM_REMOVED,
                                    G_OBJECT_CLASS_TYPE(object_class),
                                    G_SIGNAL_RUN_FIRST,
                                    0,
                                    NULL,
                                    NULL,
                                    NULL,
                                    G_TYPE_NONE,
                                    0);

    signals[STATE_CHANGED] = g_signal_new(NM_MODEM_STATE_CHANGED,
                                          G_OBJECT_CLASS_TYPE(object_class),
                                          G_SIGNAL_RUN_FIRST,
                                          0,
                                          NULL,
                                          NULL,
                                          NULL,
                                          G_TYPE_NONE,
                                          2,
                                          G_TYPE_INT,
                                          G_TYPE_INT);
}
