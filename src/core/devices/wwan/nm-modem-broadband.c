/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2012 Aleksander Morgado <aleksander@gnu.org>
 */

#include "src/core/nm-default-daemon.h"

#include "nm-modem-broadband.h"
#include "nm-service-providers.h"

#include <arpa/inet.h>
#include <libmm-glib.h>

#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "NetworkManagerUtils.h"
#include "devices/nm-device-private.h"
#include "libnm-platform/nm-platform.h"
#include "nm-l3-config-data.h"

#define NM_MODEM_BROADBAND_MODEM "modem"

#define MM_SUPPORTS_INITIAL_EPS_BEARER_SETTINGS MM_CHECK_VERSION(1, 10, 0)

#if !MM_CHECK_VERSION(1, 14, 0)
#define MM_MODEM_CAPABILITY_5GNR ((MMModemCapability) (1 << 6))
#endif

#define MODEM_CAPS_3GPP(caps) \
    NM_FLAGS_ANY(             \
        caps,                 \
        (MM_MODEM_CAPABILITY_GSM_UMTS | MM_MODEM_CAPABILITY_LTE | MM_MODEM_CAPABILITY_5GNR))

#define MODEM_CAPS_3GPP2(caps) NM_FLAGS_ANY((caps), MM_MODEM_CAPABILITY_CDMA_EVDO)

/* Maximum time to keep the DBus call waiting for a connection result.
 * This value is greater than the default timeout in ModemManager (180s since
 * 1.16), so that whenever possible the timeout happens first there instead of
 * in NetworkManager. */
#define MODEM_CONNECT_TIMEOUT_SECS 200

/*****************************************************************************/

typedef enum {
    CONNECT_STEP_FIRST,
    CONNECT_STEP_WAIT_FOR_SIM,
    CONNECT_STEP_UNLOCK,
    CONNECT_STEP_WAIT_FOR_READY,
    CONNECT_STEP_INTIAL_EPS_BEARER,
    CONNECT_STEP_CONNECT,
    CONNECT_STEP_LAST,
} ConnectStep;

typedef struct {
    NMModemBroadband *self;
    ConnectStep       step;

    MMModemCapability          caps;
    NMConnection              *connection;
    GCancellable              *cancellable;
    MMSimpleConnectProperties *connect_properties;
    GArray                    *ip_types;
    guint                      ip_types_i;
    guint                      ip_type_tries;
    GError                    *first_error;
} ConnectContext;

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_MODEM, );

typedef struct {
    /* The modem object from dbus */
    MMObject *modem_object;
    /* Per-interface objects */
    MMModem       *modem_iface;
    MMModem3gpp   *modem_3gpp_iface;
    MMModemSimple *simple_iface;
    MMSim         *sim_iface;

    /* Connection setup */
    ConnectContext *ctx;

    MMBearer         *bearer;
    MMBearerIpConfig *ipv4_config;
    MMBearerIpConfig *ipv6_config;

    guint32 pin_tries;
} NMModemBroadbandPrivate;

struct _NMModemBroadband {
    NMModem                 parent;
    NMModemBroadbandPrivate _priv;
};

struct _NMModemBroadbandClass {
    NMModemClass parent;
};

G_DEFINE_TYPE(NMModemBroadband, nm_modem_broadband, NM_TYPE_MODEM)

#define NM_MODEM_BROADBAND_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMModemBroadband, NM_IS_MODEM_BROADBAND)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_MB
#define _NMLOG_PREFIX_NAME "modem-broadband"
#define _NMLOG(level, ...)                                                       \
    G_STMT_START                                                                 \
    {                                                                            \
        const NMLogLevel _level = (level);                                       \
                                                                                 \
        if (nm_logging_enabled(_level, (_NMLOG_DOMAIN))) {                       \
            NMModemBroadband *const __self = (self);                             \
            char                    __prefix_name[128];                          \
            const char             *__uid;                                       \
                                                                                 \
            _nm_log(_level,                                                      \
                    (_NMLOG_DOMAIN),                                             \
                    0,                                                           \
                    NULL,                                                        \
                    ((__self && __self->_priv.ctx)                               \
                         ? nm_connection_get_uuid(__self->_priv.ctx->connection) \
                         : NULL),                                                \
                    "%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                 \
                    _NMLOG_PREFIX_NAME,                                          \
                    (__self ? ({                                                 \
                        ((__uid = nm_modem_get_uid((NMModem *) __self))          \
                             ? nm_sprintf_buf(__prefix_name, "[%s]", __uid)      \
                             : "(null)");                                        \
                    })                                                           \
                            : "") _NM_UTILS_MACRO_REST(__VA_ARGS__));            \
        }                                                                        \
    }                                                                            \
    G_STMT_END

/*****************************************************************************/

static NMDeviceStateReason
translate_mm_error(NMModemBroadband *self, GError *error)
{
    NMDeviceStateReason reason;

    g_return_val_if_fail(error != NULL, NM_DEVICE_STATE_REASON_UNKNOWN);

    if (g_error_matches(error, MM_CONNECTION_ERROR, MM_CONNECTION_ERROR_NO_CARRIER))
        reason = NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER;
    else if (g_error_matches(error, MM_CONNECTION_ERROR, MM_CONNECTION_ERROR_NO_DIALTONE))
        reason = NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE;
    else if (g_error_matches(error, MM_CONNECTION_ERROR, MM_CONNECTION_ERROR_BUSY))
        reason = NM_DEVICE_STATE_REASON_MODEM_BUSY;
    else if (g_error_matches(error, MM_CONNECTION_ERROR, MM_CONNECTION_ERROR_NO_ANSWER))
        reason = NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT;
    else if (g_error_matches(error,
                             MM_MOBILE_EQUIPMENT_ERROR,
                             MM_MOBILE_EQUIPMENT_ERROR_NETWORK_NOT_ALLOWED))
        reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED;
    else if (g_error_matches(error,
                             MM_MOBILE_EQUIPMENT_ERROR,
                             MM_MOBILE_EQUIPMENT_ERROR_NETWORK_TIMEOUT))
        reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT;
    else if (g_error_matches(error,
                             MM_MOBILE_EQUIPMENT_ERROR,
                             MM_MOBILE_EQUIPMENT_ERROR_NO_NETWORK))
        reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING;
    else if (g_error_matches(error,
                             MM_MOBILE_EQUIPMENT_ERROR,
                             MM_MOBILE_EQUIPMENT_ERROR_SIM_NOT_INSERTED))
        reason = NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED;
    else if (g_error_matches(error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_SIM_PIN))
        reason = NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED;
    else if (g_error_matches(error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_SIM_PUK))
        reason = NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED;
    else if (g_error_matches(error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_SIM_WRONG))
        reason = NM_DEVICE_STATE_REASON_GSM_SIM_WRONG;
    else if (g_error_matches(error,
                             MM_MOBILE_EQUIPMENT_ERROR,
                             MM_MOBILE_EQUIPMENT_ERROR_INCORRECT_PASSWORD))
        reason = NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT;
    else {
        /* unable to map the ModemManager error to a NM_DEVICE_STATE_REASON */
        _LOGD("unmapped error detected: '%s'", error->message);
        reason = NM_DEVICE_STATE_REASON_UNKNOWN;
    }

    return reason;
}

/*****************************************************************************/

static void
get_capabilities(NMModem                   *_self,
                 NMDeviceModemCapabilities *modem_caps,
                 NMDeviceModemCapabilities *current_caps)
{
    NMModemBroadband          *self          = NM_MODEM_BROADBAND(_self);
    MMModemCapability          all_supported = MM_MODEM_CAPABILITY_NONE;
    gs_free MMModemCapability *supported     = NULL;
    guint                      n_supported;
    guint                      i;

    G_STATIC_ASSERT(MM_MODEM_CAPABILITY_POTS == (guint64) NM_DEVICE_MODEM_CAPABILITY_POTS);
    G_STATIC_ASSERT(MM_MODEM_CAPABILITY_CDMA_EVDO
                    == (guint64) NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO);
    G_STATIC_ASSERT(MM_MODEM_CAPABILITY_GSM_UMTS == (guint64) NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS);
    G_STATIC_ASSERT(MM_MODEM_CAPABILITY_LTE == (guint64) NM_DEVICE_MODEM_CAPABILITY_LTE);
    G_STATIC_ASSERT(MM_MODEM_CAPABILITY_5GNR == (guint64) NM_DEVICE_MODEM_CAPABILITY_5GNR);

    /* For now, we don't care about the capability combinations, just merge all
     * combinations in a single mask */
    if (mm_modem_get_supported_capabilities(self->_priv.modem_iface, &supported, &n_supported)) {
        for (i = 0; i < n_supported; i++)
            all_supported |= supported[i];
    }

    *modem_caps = (NMDeviceModemCapabilities) all_supported;
    *current_caps =
        (NMDeviceModemCapabilities) mm_modem_get_current_capabilities(self->_priv.modem_iface);
}

static gboolean
owns_port(NMModem *_self, const char *iface)
{
    NMModemBroadband      *self    = NM_MODEM_BROADBAND(_self);
    const MMModemPortInfo *ports   = NULL;
    guint                  n_ports = 0, i;

    mm_modem_peek_ports(self->_priv.modem_iface, &ports, &n_ports);
    for (i = 0; i < n_ports; i++) {
        if (nm_streq0(iface, ports[i].name))
            return TRUE;
    }
    return FALSE;
}

/*****************************************************************************/

static void
ask_for_pin(NMModemBroadband *self)
{
    guint32 tries;

    tries = self->_priv.pin_tries++;
    nm_modem_get_secrets(NM_MODEM(self),
                         NM_SETTING_GSM_SETTING_NAME,
                         tries ? TRUE : FALSE,
                         NM_SETTING_GSM_PIN);
}

static NMModemIPMethod
get_bearer_ip_method(MMBearerIpConfig *config)
{
    MMBearerIpMethod mm_method;

    mm_method = mm_bearer_ip_config_get_method(config);
    if (mm_method == MM_BEARER_IP_METHOD_PPP)
        return NM_MODEM_IP_METHOD_PPP;
    else if (mm_method == MM_BEARER_IP_METHOD_STATIC)
        return NM_MODEM_IP_METHOD_STATIC;
    else if (mm_method == MM_BEARER_IP_METHOD_DHCP)
        return NM_MODEM_IP_METHOD_AUTO;
    return NM_MODEM_IP_METHOD_UNKNOWN;
}

static MMSimpleConnectProperties *
create_cdma_connect_properties(NMConnection *connection)
{
    MMSimpleConnectProperties *properties;

    properties = mm_simple_connect_properties_new();

#if !MM_CHECK_VERSION(1, 9, 1)
    {
        NMSettingCdma *setting;
        const char    *str;

        setting = nm_connection_get_setting_cdma(connection);
        str     = nm_setting_cdma_get_number(setting);
        if (str)
            mm_simple_connect_properties_set_number(properties, str);
    }
#endif

    return properties;
}

static MMSimpleConnectProperties *
create_gsm_connect_properties(NMConnection *connection,
                              const char   *apn,
                              const char   *username,
                              const char   *password)
{
    NMSettingGsm              *setting;
    NMSettingPpp              *s_ppp;
    MMSimpleConnectProperties *properties;
    const char                *str;

    setting = nm_connection_get_setting_gsm(connection);

    properties = mm_simple_connect_properties_new();

    mm_simple_connect_properties_set_apn(properties, apn ?: "");
    if (username)
        mm_simple_connect_properties_set_user(properties, username);
    if (password)
        mm_simple_connect_properties_set_password(properties, password);

    str = nm_setting_gsm_get_network_id(setting);
    if (str)
        mm_simple_connect_properties_set_operator_id(properties, str);

    str = nm_setting_gsm_get_pin(setting);
    if (str)
        mm_simple_connect_properties_set_pin(properties, str);

    /* Roaming */
    if (nm_setting_gsm_get_home_only(setting))
        mm_simple_connect_properties_set_allow_roaming(properties, FALSE);

    /* For IpMethod == STATIC or DHCP */
    s_ppp = nm_connection_get_setting_ppp(connection);
    if (s_ppp) {
        MMBearerAllowedAuth allowed_auth = MM_BEARER_ALLOWED_AUTH_UNKNOWN;

        if (nm_setting_ppp_get_noauth(s_ppp))
            allowed_auth = MM_BEARER_ALLOWED_AUTH_NONE;
        if (!nm_setting_ppp_get_refuse_pap(s_ppp))
            allowed_auth |= MM_BEARER_ALLOWED_AUTH_PAP;
        if (!nm_setting_ppp_get_refuse_chap(s_ppp))
            allowed_auth |= MM_BEARER_ALLOWED_AUTH_CHAP;
        if (!nm_setting_ppp_get_refuse_mschap(s_ppp))
            allowed_auth |= MM_BEARER_ALLOWED_AUTH_MSCHAP;
        if (!nm_setting_ppp_get_refuse_mschapv2(s_ppp))
            allowed_auth |= MM_BEARER_ALLOWED_AUTH_MSCHAPV2;
        if (!nm_setting_ppp_get_refuse_eap(s_ppp))
            allowed_auth |= MM_BEARER_ALLOWED_AUTH_EAP;

        mm_simple_connect_properties_set_allowed_auth(properties, allowed_auth);
    }

    return properties;
}

static void
connect_context_clear(NMModemBroadband *self)
{
    if (self->_priv.ctx) {
        ConnectContext *ctx = self->_priv.ctx;

        g_clear_error(&ctx->first_error);
        nm_clear_pointer(&ctx->ip_types, g_array_unref);
        nm_clear_g_cancellable(&ctx->cancellable);
        g_clear_object(&ctx->connection);
        g_clear_object(&ctx->connect_properties);
        g_clear_object(&ctx->self);
        g_slice_free(ConnectContext, ctx);
        self->_priv.ctx = NULL;
    }
}

static void connect_context_step(NMModemBroadband *self);

static void
connect_ready(MMModemSimple *simple_iface, GAsyncResult *res, NMModemBroadband *self)
{
    ConnectContext           *ctx;
    GError                   *error      = NULL;
    NMModemIPMethod           ip4_method = NM_MODEM_IP_METHOD_UNKNOWN;
    NMModemIPMethod           ip6_method = NM_MODEM_IP_METHOD_UNKNOWN;
    gs_unref_object MMBearer *bearer     = NULL;

    bearer = mm_modem_simple_connect_finish(simple_iface, res, &error);

    if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
        g_error_free(error);
        return;
    }

    ctx = self->_priv.ctx;

    if (!ctx)
        return;

    self->_priv.bearer = g_steal_pointer(&bearer);

    if (!self->_priv.bearer) {
        if (g_error_matches(error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_SIM_PIN)
            || (g_error_matches(error, MM_CORE_ERROR, MM_CORE_ERROR_UNAUTHORIZED)
                && mm_modem_get_unlock_required(self->_priv.modem_iface)
                       == MM_MODEM_LOCK_SIM_PIN)) {
            g_error_free(error);

            /* Request PIN */
            ask_for_pin(self);
            connect_context_clear(self);
            return;
        }

        /* Save the error, if it's the first one */
        if (!ctx->first_error) {
            /* Strip remote error info before saving it */
            if (g_dbus_error_is_remote_error(error))
                g_dbus_error_strip_remote_error(error);
            ctx->first_error = error;
        } else
            g_clear_error(&error);

        if (ctx->ip_type_tries == 0 && g_error_matches(error, MM_CORE_ERROR, MM_CORE_ERROR_RETRY)) {
            /* Try one more time */
            ctx->ip_type_tries++;
        } else {
            /* If the modem/provider lies and the IP type we tried isn't supported,
             * retry with the next one, if any.
             */
            ctx->ip_types_i++;
            ctx->ip_type_tries = 0;
        }
        connect_context_step(self);
        return;
    }

    /* Grab IP configurations */
    self->_priv.ipv4_config = mm_bearer_get_ipv4_config(self->_priv.bearer);
    if (self->_priv.ipv4_config)
        ip4_method = get_bearer_ip_method(self->_priv.ipv4_config);

    self->_priv.ipv6_config = mm_bearer_get_ipv6_config(self->_priv.bearer);
    if (self->_priv.ipv6_config)
        ip6_method = get_bearer_ip_method(self->_priv.ipv6_config);

    if (!nm_modem_set_data_port(NM_MODEM(self),
                                NM_PLATFORM_GET,
                                mm_bearer_get_interface(self->_priv.bearer),
                                ip4_method,
                                ip6_method,
                                mm_bearer_get_ip_timeout(self->_priv.bearer),
                                &error)) {
        _LOGW("failed to connect modem: %s", error->message);
        g_error_free(error);
        nm_modem_emit_prepare_result(NM_MODEM(self), FALSE, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
        connect_context_clear(self);
        return;
    }

    ctx->step++;
    connect_context_step(self);
}

static void
send_pin_ready(MMSim *sim, GAsyncResult *result, NMModemBroadband *self)
{
    gs_free_error GError *error = NULL;

    mm_sim_send_pin_finish(sim, result, &error);

    if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        return;

    if (!self->_priv.ctx || self->_priv.ctx->step != CONNECT_STEP_UNLOCK)
        g_return_if_reached();

    if (error) {
        if (g_error_matches(error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_SIM_PIN)
            || (g_error_matches(error, MM_CORE_ERROR, MM_CORE_ERROR_UNAUTHORIZED)
                && mm_modem_get_unlock_required(self->_priv.modem_iface) == MM_MODEM_LOCK_SIM_PIN))
            ask_for_pin(self);
        else
            nm_modem_emit_prepare_result(NM_MODEM(self), FALSE, translate_mm_error(self, error));
        return;
    }

    self->_priv.ctx->step++;
    connect_context_step(self);
}

static void
find_gsm_apn_cb(const char   *apn,
                const char   *username,
                const char   *password,
                const char   *gateway,
                const char   *auth_method,
                const GSList *dns,
                GError       *error,
                gpointer      user_data)
{
    NMModemBroadband        *self = user_data;
    NMModemBroadbandPrivate *priv = NM_MODEM_BROADBAND_GET_PRIVATE(self);
    ConnectContext          *ctx  = priv->ctx;

    if (error) {
        _LOGW("failed to connect '%s': APN not found: %s",
              nm_connection_get_id(ctx->connection),
              error->message);

        nm_modem_emit_prepare_result(NM_MODEM(self), FALSE, NM_DEVICE_STATE_REASON_GSM_APN_FAILED);
        connect_context_clear(self);
        return;
    }

    /* Blank APN ("") means the default subscription APN */
    ctx->connect_properties =
        create_gsm_connect_properties(ctx->connection, apn, username, password);
    g_return_if_fail(ctx->connect_properties);
    connect_context_step(self);
}

static gboolean
try_create_connect_properties(NMModemBroadband *self)
{
    NMModemBroadbandPrivate *priv = NM_MODEM_BROADBAND_GET_PRIVATE(self);
    ConnectContext          *ctx  = priv->ctx;

    if (MODEM_CAPS_3GPP(ctx->caps)) {
        NMSettingGsm *s_gsm = nm_connection_get_setting_gsm(ctx->connection);

        if (!s_gsm || nm_setting_gsm_get_auto_config(s_gsm)) {
            gs_unref_object MMModem3gpp *modem_3gpp = NULL;
            const char                  *network_id = NULL;

            s_gsm = nm_connection_get_setting_gsm(ctx->connection);
            if (s_gsm)
                network_id = nm_setting_gsm_get_network_id(s_gsm);
            if (!network_id) {
                if (mm_modem_get_state(self->_priv.modem_iface) < MM_MODEM_STATE_REGISTERED)
                    return FALSE;
                modem_3gpp = mm_object_get_modem_3gpp(priv->modem_object);
                network_id = mm_modem_3gpp_get_operator_code(modem_3gpp);
            }
            if (!network_id) {
                _LOGW("failed to connect '%s': unable to determine the network id",
                      nm_connection_get_id(ctx->connection));
                goto out;
            }

            nm_service_providers_find_gsm_apn(MOBILE_BROADBAND_PROVIDER_INFO_DATABASE,
                                              network_id,
                                              ctx->cancellable,
                                              find_gsm_apn_cb,
                                              self);
        } else {
            ctx->connect_properties =
                create_gsm_connect_properties(ctx->connection,
                                              nm_setting_gsm_get_apn(s_gsm),
                                              nm_setting_gsm_get_username(s_gsm),
                                              nm_setting_gsm_get_password(s_gsm));
            g_return_val_if_fail(ctx->connect_properties, TRUE);
        }

        return TRUE;
    } else if (MODEM_CAPS_3GPP2(ctx->caps)) {
        ctx->connect_properties = create_cdma_connect_properties(ctx->connection);
        g_return_val_if_fail(ctx->connect_properties, FALSE);
        return TRUE;
    } else {
        _LOGW("failed to connect '%s': not a mobile broadband modem",
              nm_connection_get_id(ctx->connection));
    }

out:
    nm_modem_emit_prepare_result(NM_MODEM(self), FALSE, NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED);
    connect_context_clear(self);
    return TRUE;
}

#if MM_SUPPORTS_INITIAL_EPS_BEARER_SETTINGS
static void
set_initial_eps_bearer_settings_ready(MMModem3gpp      *modem_3gpp_iface,
                                      GAsyncResult     *res,
                                      NMModemBroadband *self)
{
    gs_free_error GError *error = NULL;

    if (!mm_modem_3gpp_set_initial_eps_bearer_settings_finish(modem_3gpp_iface, res, &error)) {
        if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
            return;

        if (!g_error_matches(error, MM_CORE_ERROR, MM_CORE_ERROR_UNSUPPORTED)) {
            _LOGW("failed to set initial EPS bearer settings: %s", error->message);
            nm_modem_emit_prepare_result(NM_MODEM(self),
                                         FALSE,
                                         NM_DEVICE_STATE_REASON_GSM_APN_FAILED);
            connect_context_clear(self);
            return;
        }

        _LOGD("failed to set initial EPS bearer settings due to lack of support: %s",
              error->message);
    }

    self->_priv.ctx->step++;
    connect_context_step(self);
}
#endif

static void
connect_context_step(NMModemBroadband *self)
{
    ConnectContext *ctx = self->_priv.ctx;

    switch (ctx->step) {
    case CONNECT_STEP_FIRST:
        ctx->step++;
        /* fall-through */

    case CONNECT_STEP_WAIT_FOR_SIM:
        if (MODEM_CAPS_3GPP(ctx->caps) && !self->_priv.sim_iface) {
            /* Have to wait for the SIM to show up */
            break;
        }
        ctx->step++;
        /* fall-through */

    case CONNECT_STEP_UNLOCK:
        if (MODEM_CAPS_3GPP(ctx->caps)
            && mm_modem_get_unlock_required(self->_priv.modem_iface) == MM_MODEM_LOCK_SIM_PIN) {
            NMSettingGsm *s_gsm = nm_connection_get_setting_gsm(ctx->connection);
            const char   *pin   = nm_setting_gsm_get_pin(s_gsm);

            /* If we have a PIN already, send it.  If we don't, get it. */
            if (pin) {
                mm_sim_send_pin(self->_priv.sim_iface,
                                pin,
                                ctx->cancellable,
                                (GAsyncReadyCallback) send_pin_ready,
                                self);
            } else {
                ask_for_pin(self);
            }
            break;
        }
        ctx->step++;
        /* fall-through */
    case CONNECT_STEP_WAIT_FOR_READY:
    {
        GError *error = NULL;

        if (mm_modem_get_state(self->_priv.modem_iface) <= MM_MODEM_STATE_LOCKED)
            break;

        if (!try_create_connect_properties(self))
            break;

        if (!self->_priv.ctx)
            break;

        /* Build up list of IP types that we need to use in the retries */
        ctx->ip_types = nm_modem_get_connection_ip_type(NM_MODEM(self), ctx->connection, &error);
        if (!ctx->ip_types) {
            _LOGW("failed to connect '%s': %s",
                  nm_connection_get_id(ctx->connection),
                  error->message);
            g_clear_error(&error);

            nm_modem_emit_prepare_result(NM_MODEM(self),
                                         FALSE,
                                         NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED);
            connect_context_clear(self);
            break;
        }

        ctx->step++;
    }
        /* fall-through */

    case CONNECT_STEP_INTIAL_EPS_BEARER:
        if (MODEM_CAPS_3GPP(ctx->caps)) {
            NMSettingGsm *s_gsm     = nm_connection_get_setting_gsm(ctx->connection);
            const char   *apn       = nm_setting_gsm_get_initial_eps_apn(s_gsm);
            gboolean      do_config = nm_setting_gsm_get_initial_eps_config(s_gsm);

            /* assume do_config is true if an APN is set */
            if (apn || do_config) {
#if MM_SUPPORTS_INITIAL_EPS_BEARER_SETTINGS
                gs_unref_object MMBearerProperties *config = NULL;
                NMModemIPType ip_type = nm_modem_get_initial_eps_bearer_ip_type(ctx->ip_types);

                config = mm_bearer_properties_new();
                switch (ip_type) {
                case NM_MODEM_IP_TYPE_IPV4:
                    mm_bearer_properties_set_ip_type(config, MM_BEARER_IP_FAMILY_IPV4);
                    break;
                case NM_MODEM_IP_TYPE_IPV6:
                    mm_bearer_properties_set_ip_type(config, MM_BEARER_IP_FAMILY_IPV6);
                    break;
                case NM_MODEM_IP_TYPE_IPV4V6:
                    mm_bearer_properties_set_ip_type(config, MM_BEARER_IP_FAMILY_IPV4V6);
                    break;
                default:
                    /* do nothing */
                    break;
                }
                if (apn)
                    mm_bearer_properties_set_apn(config, apn);

                /*
                 * Setting the initial EPS bearer settings is a no-op in
                 * ModemManager if the desired configuration is already active.
                 */
                mm_modem_3gpp_set_initial_eps_bearer_settings(
                    self->_priv.modem_3gpp_iface,
                    config,
                    ctx->cancellable,
                    (GAsyncReadyCallback) set_initial_eps_bearer_settings_ready,
                    self);
                break;
#else
                _LOGD("cannot set initial EPS bearer settings due to old ModemManager version");
#endif
            }
        }
        ctx->step++;
        /* fall-through */

    case CONNECT_STEP_CONNECT:
        if (!ctx->connect_properties)
            break;

        if (ctx->ip_types_i < ctx->ip_types->len) {
            NMModemIPType current;

            current = nm_g_array_index(ctx->ip_types, NMModemIPType, ctx->ip_types_i);

            if (current == NM_MODEM_IP_TYPE_IPV4)
                mm_simple_connect_properties_set_ip_type(ctx->connect_properties,
                                                         MM_BEARER_IP_FAMILY_IPV4);
            else if (current == NM_MODEM_IP_TYPE_IPV6)
                mm_simple_connect_properties_set_ip_type(ctx->connect_properties,
                                                         MM_BEARER_IP_FAMILY_IPV6);
            else if (current == NM_MODEM_IP_TYPE_IPV4V6)
                mm_simple_connect_properties_set_ip_type(ctx->connect_properties,
                                                         MM_BEARER_IP_FAMILY_IPV4V6);
            else
                g_return_if_reached();

            _nm_modem_set_apn(NM_MODEM(self),
                              mm_simple_connect_properties_get_apn(ctx->connect_properties));

            _LOGD("launching connection with ip type '%s' (try %d)",
                  nm_modem_ip_type_to_string(current),
                  ctx->ip_type_tries + 1);

            mm_modem_simple_connect(self->_priv.simple_iface,
                                    ctx->connect_properties,
                                    ctx->cancellable,
                                    (GAsyncReadyCallback) connect_ready,
                                    self);
            break;
        }

        ctx->step++;
        /* fall-through */

    case CONNECT_STEP_LAST:
        if (self->_priv.ipv4_config || self->_priv.ipv6_config)
            nm_modem_emit_prepare_result(NM_MODEM(self), TRUE, NM_DEVICE_STATE_REASON_NONE);
        else {
            /* If we have a saved error from a previous attempt, use it */
            if (!ctx->first_error)
                ctx->first_error = g_error_new_literal(NM_DEVICE_ERROR,
                                                       NM_DEVICE_ERROR_INVALID_CONNECTION,
                                                       "invalid bearer IP configuration");

            _LOGW("failed to connect modem: %s", ctx->first_error->message);
            nm_modem_emit_prepare_result(NM_MODEM(self),
                                         FALSE,
                                         translate_mm_error(self, ctx->first_error));
        }

        connect_context_clear(self);
        break;
    }
}

static NMActStageReturn
modem_act_stage1_prepare(NMModem             *_self,
                         NMConnection        *connection,
                         NMDeviceStateReason *out_failure_reason)
{
    NMModemBroadband *self = NM_MODEM_BROADBAND(_self);

    /* Make sure we can get the Simple interface from the modem */
    if (!self->_priv.simple_iface) {
        self->_priv.simple_iface = mm_object_get_modem_simple(self->_priv.modem_object);
        if (!self->_priv.simple_iface) {
            _LOGW("cannot access the Simple mobile broadband modem interface");
            NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED);
            return NM_ACT_STAGE_RETURN_FAILURE;
        }
    }

    connect_context_clear(self);

    /* Allocate new context for this connect stage attempt */
    self->_priv.ctx              = g_slice_new0(ConnectContext);
    self->_priv.ctx->caps        = mm_modem_get_current_capabilities(self->_priv.modem_iface);
    self->_priv.ctx->cancellable = g_cancellable_new();
    self->_priv.ctx->connection  = g_object_ref(connection);

    g_dbus_proxy_set_default_timeout(G_DBUS_PROXY(self->_priv.simple_iface),
                                     MODEM_CONNECT_TIMEOUT_SECS * 1000);
    connect_context_step(self);

    return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/

static gboolean
check_connection_compatible_with_modem(NMModem *_self, NMConnection *connection, GError **error)
{
    NMModemBroadband *self = NM_MODEM_BROADBAND(_self);
    MMModemCapability modem_caps;

    modem_caps = mm_modem_get_current_capabilities(self->_priv.modem_iface);

    if (MODEM_CAPS_3GPP(modem_caps)) {
        if (!_nm_connection_check_main_setting(connection, NM_SETTING_GSM_SETTING_NAME, error))
            return FALSE;

        return TRUE;
    }

    if (MODEM_CAPS_3GPP2(modem_caps)) {
        if (!_nm_connection_check_main_setting(connection, NM_SETTING_CDMA_SETTING_NAME, error))
            return FALSE;

        return TRUE;
    }

    if (!_nm_connection_check_main_setting(connection, NM_SETTING_GSM_SETTING_NAME, NULL)
        && !_nm_connection_check_main_setting(connection, NM_SETTING_CDMA_SETTING_NAME, NULL)) {
        nm_utils_error_set(error,
                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                           "connection type %s is not supported by modem",
                           nm_connection_get_connection_type(connection));
        return FALSE;
    }

    nm_utils_error_set(error,
                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                       "modem lacks capabilities for %s profile",
                       nm_connection_get_connection_type(connection));
    return FALSE;
}

/*****************************************************************************/

static gboolean
complete_connection(NMModem             *modem,
                    const char          *iface,
                    NMConnection        *connection,
                    NMConnection *const *existing_connections,
                    GError             **error)
{
    NMModemBroadband *self = NM_MODEM_BROADBAND(modem);
    MMModemCapability modem_caps;
    NMSettingPpp     *s_ppp;

    modem_caps = mm_modem_get_current_capabilities(self->_priv.modem_iface);

    /* PPP settings common to 3GPP and 3GPP2 */
    s_ppp = nm_connection_get_setting_ppp(connection);
    if (!s_ppp) {
        s_ppp = (NMSettingPpp *) nm_setting_ppp_new();
        g_object_set(G_OBJECT(s_ppp),
                     NM_SETTING_PPP_LCP_ECHO_FAILURE,
                     5,
                     NM_SETTING_PPP_LCP_ECHO_INTERVAL,
                     30,
                     NULL);
        nm_connection_add_setting(connection, NM_SETTING(s_ppp));
    }

    if (MODEM_CAPS_3GPP(modem_caps)) {
        NMSettingGsm *s_gsm;

        s_gsm = nm_connection_get_setting_gsm(connection);
        if (!s_gsm) {
            s_gsm = (NMSettingGsm *) nm_setting_gsm_new();
            nm_connection_add_setting(connection, NM_SETTING(s_gsm));
            g_object_set(G_OBJECT(s_gsm), NM_SETTING_GSM_AUTO_CONFIG, TRUE, NULL);
        }

        if (!nm_setting_gsm_get_device_id(s_gsm)) {
            g_object_set(G_OBJECT(s_gsm),
                         NM_SETTING_GSM_DEVICE_ID,
                         nm_modem_get_device_id(modem),
                         NULL);
        }

        nm_utils_complete_generic(NM_PLATFORM_GET,
                                  connection,
                                  NM_SETTING_GSM_SETTING_NAME,
                                  existing_connections,
                                  NULL,
                                  _("GSM connection"),
                                  NULL,
                                  NULL,
                                  FALSE); /* No IPv6 yet by default */

        return TRUE;
    }

    if (MODEM_CAPS_3GPP2(modem_caps)) {
        NMSettingCdma *s_cdma;

        s_cdma = _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_CDMA);

        if (!nm_setting_cdma_get_number(s_cdma))
            g_object_set(G_OBJECT(s_cdma), NM_SETTING_CDMA_NUMBER, "#777", NULL);

        nm_utils_complete_generic(NM_PLATFORM_GET,
                                  connection,
                                  NM_SETTING_CDMA_SETTING_NAME,
                                  existing_connections,
                                  NULL,
                                  _("CDMA connection"),
                                  NULL,
                                  iface,
                                  FALSE); /* No IPv6 yet by default */

        return TRUE;
    }

    g_set_error(error,
                NM_DEVICE_ERROR,
                NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
                "Device is not a mobile broadband modem");
    return FALSE;
}

/*****************************************************************************/

static gboolean
get_user_pass(NMModem *modem, NMConnection *connection, const char **user, const char **pass)
{
    NMSettingGsm  *s_gsm;
    NMSettingCdma *s_cdma;

    s_gsm  = nm_connection_get_setting_gsm(connection);
    s_cdma = nm_connection_get_setting_cdma(connection);
    if (!s_gsm && !s_cdma)
        return FALSE;

    if (user) {
        if (s_gsm)
            *user = nm_setting_gsm_get_username(s_gsm);
        else if (s_cdma)
            *user = nm_setting_cdma_get_username(s_cdma);
    }
    if (pass) {
        if (s_gsm)
            *pass = nm_setting_gsm_get_password(s_gsm);
        else if (s_cdma)
            *pass = nm_setting_cdma_get_password(s_cdma);
    }

    return TRUE;
}

/*****************************************************************************/
/* Query/Update enabled state */

static void
set_power_state_low_ready(MMModem *modem, GAsyncResult *result, NMModemBroadband *self)
{
    GError *error = NULL;

    if (!mm_modem_set_power_state_finish(modem, result, &error)) {
        /* Log but ignore errors; not all modems support low power state */
        _LOGD("failed to set modem low power state: %s", NM_G_ERROR_MSG(error));
        g_clear_error(&error);
    }

    /* Balance refcount */
    g_object_unref(self);
}

static void
modem_disable_ready(MMModem *modem_iface, GAsyncResult *res, NMModemBroadband *self)
{
    GError *error = NULL;

    if (mm_modem_disable_finish(modem_iface, res, &error)) {
        /* Once disabled, move to low-power mode */
        mm_modem_set_power_state(modem_iface,
                                 MM_MODEM_POWER_STATE_LOW,
                                 NULL,
                                 (GAsyncReadyCallback) set_power_state_low_ready,
                                 g_object_ref(self));
    } else {
        _LOGW("failed to disable modem: %s", NM_G_ERROR_MSG(error));
        nm_modem_set_prev_state(NM_MODEM(self), "disable failed");
        g_clear_error(&error);
    }

    /* Balance refcount */
    g_object_unref(self);
}

static void
modem_enable_ready(MMModem *modem_iface, GAsyncResult *res, NMModemBroadband *self)
{
    GError *error = NULL;

    if (!mm_modem_enable_finish(modem_iface, res, &error)) {
        _LOGW("failed to enable modem: %s", NM_G_ERROR_MSG(error));
        nm_modem_set_prev_state(NM_MODEM(self), "enable failed");
        g_clear_error(&error);
    }

    /* Balance refcount */
    g_object_unref(self);
}

static void
set_mm_enabled(NMModem *_self, gboolean enabled)
{
    NMModemBroadband *self = NM_MODEM_BROADBAND(_self);

    if (enabled) {
        mm_modem_enable(self->_priv.modem_iface,
                        NULL, /* cancellable */
                        (GAsyncReadyCallback) modem_enable_ready,
                        g_object_ref(self));
    } else {
        mm_modem_disable(self->_priv.modem_iface,
                         NULL, /* cancellable */
                         (GAsyncReadyCallback) modem_disable_ready,
                         g_object_ref(self));
    }
}

/*****************************************************************************/

static void
stage3_ip_config_start(NMModem *modem, int addr_family, NMModemIPMethod ip_method)
{
    const int                               IS_IPv4 = NM_IS_IPv4(addr_family);
    NMModemBroadband                       *self    = NM_MODEM_BROADBAND(modem);
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd    = NULL;
    char                                    sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    gs_free_error GError                   *error = NULL;
    const char                             *data_port;
    const char                             *address_string;
    const char                            **dns;
    guint                                   i;
    gboolean                                do_auto = FALSE;
    int                                     ifindex;
    NMUtilsIPv6IfaceId                      iid_data;
    const NMUtilsIPv6IfaceId               *iid = NULL;

    if (IS_IPv4) {
        g_return_if_fail(self->_priv.ipv4_config);
        g_return_if_fail(self->_priv.bearer);

        if (ip_method == NM_MODEM_IP_METHOD_AUTO) {
            do_auto = TRUE;
            goto out;
        }
    } else {
        g_return_if_fail(self->_priv.ipv6_config);
    }

    if (IS_IPv4) {
        guint32              address_network;
        guint32              gw = 0;
        NMPlatformIP4Address address;
        NMPlatformIP4Route   route;
        guint32              mtu_n;
        const char          *gw_string;

        _LOGI("IPv4 static configuration:");

        /* Fully fail if invalid IP address retrieved */
        address_string = mm_bearer_ip_config_get_address(self->_priv.ipv4_config);
        if (!address_string
            || !nm_inet_parse_bin(AF_INET, address_string, NULL, &address_network)) {
            g_set_error(&error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_INVALID_CONNECTION,
                        "(%s) retrieving IP4 configuration failed: invalid address given %s%s%s",
                        nm_modem_get_uid(NM_MODEM(self)),
                        NM_PRINT_FMT_QUOTE_STRING(address_string));
            goto out;
        }

        /* Missing gateway not a hard failure */
        gw_string = mm_bearer_ip_config_get_gateway(self->_priv.ipv4_config);
        if (gw_string && !nm_inet_parse_bin(AF_INET, gw_string, NULL, &gw)) {
            g_set_error(&error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_INVALID_CONNECTION,
                        "(%s) retrieving IP4 configuration failed: invalid gateway address \"%s\"",
                        nm_modem_get_uid(NM_MODEM(self)),
                        gw_string);
            goto out;
        }

        data_port = mm_bearer_get_interface(self->_priv.bearer);
        g_return_if_fail(data_port);

        ifindex = nm_platform_link_get_ifindex(NM_PLATFORM_GET, data_port);
        if (ifindex <= 0) {
            g_set_error(&error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_INVALID_CONNECTION,
                        "(%s) data port %s not found",
                        nm_modem_get_uid(NM_MODEM(self)),
                        data_port);
            goto out;
        }

        l3cd = nm_l3_config_data_new(nm_platform_get_multi_idx(NM_PLATFORM_GET),
                                     ifindex,
                                     NM_IP_CONFIG_SOURCE_WWAN);

        address = (NMPlatformIP4Address){
            .address      = address_network,
            .peer_address = address_network,
            .plen         = mm_bearer_ip_config_get_prefix(self->_priv.ipv4_config),
            .addr_source  = NM_IP_CONFIG_SOURCE_WWAN,
        };
        if (address.plen <= 32)
            nm_l3_config_data_add_address_4(l3cd, &address);

        _LOGI("  address %s", nm_platform_ip4_address_to_string(&address, sbuf, sizeof(sbuf)));

        route = (NMPlatformIP4Route){
            .rt_source     = NM_IP_CONFIG_SOURCE_WWAN,
            .gateway       = gw,
            .table_any     = TRUE,
            .table_coerced = 0,
            .metric_any    = TRUE,
            .metric        = 0,
        };
        nm_l3_config_data_add_route_4(l3cd, &route);
        _LOGI("  gateway %s", gw_string);

        dns = mm_bearer_ip_config_get_dns(self->_priv.ipv4_config);
        for (i = 0; dns && dns[i]; i++) {
            if (nm_inet_parse_bin(AF_INET, dns[i], NULL, &address_network) && address_network > 0) {
                nm_l3_config_data_add_nameserver_detail(l3cd, AF_INET, &address_network, NULL);
                _LOGI("  DNS %s", dns[i]);
            }
        }

#if MM_CHECK_VERSION(1, 4, 0)
        mtu_n = mm_bearer_ip_config_get_mtu(self->_priv.ipv4_config);
        if (mtu_n) {
            nm_l3_config_data_set_mtu(l3cd, mtu_n);
            _LOGI("  MTU %u", mtu_n);
        }
#endif
    } else {
        NMPlatformIP6Address address;

        address_string = mm_bearer_ip_config_get_address(self->_priv.ipv6_config);
        if (!address_string) {
            /* DHCP/SLAAC is allowed to skip addresses; other methods require it */
            if (ip_method != NM_MODEM_IP_METHOD_AUTO) {
                g_set_error(&error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INVALID_CONNECTION,
                            "(%s) retrieving IPv6 configuration failed: no address given",
                            nm_modem_get_uid(NM_MODEM(self)));
            }
            goto out;
        }

        address = (NMPlatformIP6Address){};

        if (!inet_pton(AF_INET6, address_string, &address.address)) {
            g_set_error(&error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_INVALID_CONNECTION,
                        "(%s) retrieving IPv6 configuration failed: invalid address given '%s'",
                        nm_modem_get_uid(NM_MODEM(self)),
                        address_string);
            goto out;
        }

        data_port = mm_bearer_get_interface(self->_priv.bearer);
        g_return_if_fail(data_port);

        ifindex = nm_platform_link_get_ifindex(NM_PLATFORM_GET, data_port);
        if (ifindex <= 0) {
            g_set_error(&error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_INVALID_CONNECTION,
                        "(%s) data port %s not found",
                        nm_modem_get_uid(NM_MODEM(self)),
                        data_port);
            goto out;
        }

        _LOGI("IPv6 base configuration:");

        l3cd    = nm_l3_config_data_new(nm_platform_get_multi_idx(NM_PLATFORM_GET),
                                     ifindex,
                                     NM_IP_CONFIG_SOURCE_WWAN);
        do_auto = TRUE;

        address.plen = mm_bearer_ip_config_get_prefix(self->_priv.ipv6_config);
        if (address.plen <= 128) {
            if (IN6_IS_ADDR_LINKLOCAL(&address.address)) {
                nm_utils_ipv6_interface_identifier_get_from_addr(&iid_data, &address.address);
                iid = &iid_data;
            } else
                do_auto = FALSE;
            nm_l3_config_data_add_address_6(l3cd, &address);
        }

        _LOGI("  address %s (slaac %s)",
              nm_platform_ip6_address_to_string(&address, sbuf, sizeof(sbuf)),
              do_auto ? "enabled" : "disabled");

        address_string = mm_bearer_ip_config_get_gateway(self->_priv.ipv6_config);
        if (address_string) {
            if (inet_pton(AF_INET6, address_string, &address.address) != 1) {
                g_set_error(&error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INVALID_CONNECTION,
                            "(%s) retrieving IPv6 configuration failed: invalid gateway given '%s'",
                            nm_modem_get_uid(NM_MODEM(self)),
                            address_string);
                goto out;
            }

            {
                const NMPlatformIP6Route r = {
                    .rt_source     = NM_IP_CONFIG_SOURCE_WWAN,
                    .gateway       = address.address,
                    .table_any     = TRUE,
                    .table_coerced = 0,
                    .metric_any    = TRUE,
                    .metric        = 0,
                };

                _LOGI("  gateway %s", address_string);
                nm_l3_config_data_add_route_6(l3cd, &r);
            }
        } else if (ip_method == NM_MODEM_IP_METHOD_STATIC) {
            /* Gateway required for the 'static' method */
            g_set_error(&error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_INVALID_CONNECTION,
                        "(%s) retrieving IPv6 configuration failed: missing gateway",
                        nm_modem_get_uid(NM_MODEM(self)));
            goto out;
        }

        dns = mm_bearer_ip_config_get_dns(self->_priv.ipv6_config);
        for (i = 0; dns && dns[i]; i++) {
            struct in6_addr addr;

            if (inet_pton(AF_INET6, dns[i], &addr)) {
                nm_l3_config_data_add_nameserver_detail(l3cd, AF_INET6, &addr, NULL);
                _LOGI("  DNS %s", dns[i]);
            }
        }
    }

out:
    if (error) {
        nm_modem_emit_signal_new_config_failure(modem,
                                                addr_family,
                                                NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE,
                                                error);
        return;
    }

    nm_modem_emit_signal_new_config_success(modem, addr_family, l3cd, do_auto, iid);
}

/*****************************************************************************/
/* Disconnect */

typedef struct {
    NMModemBroadband          *self;
    _NMModemDisconnectCallback callback;
    gpointer                   callback_user_data;
    GCancellable              *cancellable;
    gboolean                   warn;
} DisconnectContext;

static void
disconnect_context_complete(DisconnectContext *ctx, GError *error)
{
    if (ctx->callback)
        ctx->callback(NM_MODEM(ctx->self), error, ctx->callback_user_data);
    nm_g_object_unref(ctx->cancellable);
    g_object_unref(ctx->self);
    g_slice_free(DisconnectContext, ctx);
}

static void
disconnect_context_complete_on_idle(gpointer user_data, GCancellable *cancellable)
{
    DisconnectContext    *ctx             = user_data;
    gs_free_error GError *cancelled_error = NULL;

    g_cancellable_set_error_if_cancelled(cancellable, &cancelled_error);
    disconnect_context_complete(ctx, cancelled_error);
}

static void
simple_disconnect_ready(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    MMModemSimple        *modem_iface = MM_MODEM_SIMPLE(source_object);
    DisconnectContext    *ctx         = user_data;
    gs_free_error GError *error       = NULL;

    if (!mm_modem_simple_disconnect_finish(modem_iface, res, &error)) {
        if (ctx->warn && !g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN)) {
            NMModemBroadband *self = ctx->self;

            _LOGW("failed to disconnect modem: %s", error->message);
        }
    }

    disconnect_context_complete(ctx, error);
}

static void
disconnect(NMModem                   *modem,
           gboolean                   warn,
           GCancellable              *cancellable,
           _NMModemDisconnectCallback callback,
           gpointer                   user_data)
{
    NMModemBroadband  *self = NM_MODEM_BROADBAND(modem);
    DisconnectContext *ctx;

    connect_context_clear(self);
    _nm_modem_set_apn(NM_MODEM(self), NULL);

    ctx                     = g_slice_new0(DisconnectContext);
    ctx->self               = g_object_ref(self);
    ctx->cancellable        = nm_g_object_ref(cancellable);
    ctx->callback           = callback;
    ctx->callback_user_data = user_data;

    /* Don't bother warning on FAILED since the modem is already gone */
    ctx->warn = warn;

    /* Already cancelled or no simple-iface? We are done. */
    if (!ctx->self->_priv.simple_iface || g_cancellable_is_cancelled(cancellable)) {
        nm_utils_invoke_on_idle(cancellable, disconnect_context_complete_on_idle, ctx);
        return;
    }

    _LOGD("notifying ModemManager about the modem disconnection");
    mm_modem_simple_disconnect(self->_priv.simple_iface,
                               NULL, /* bearer path; if NULL given ALL get disconnected */
                               cancellable,
                               simple_disconnect_ready,
                               ctx);
}

/*****************************************************************************/

static void
deactivate_cleanup(NMModem *modem, NMDevice *device, gboolean stop_ppp_manager)
{
    NMModemBroadband *self = NM_MODEM_BROADBAND(modem);

    /* TODO: cancel SimpleConnect() if any */

    /* Cleanup IPv4 addresses and routes */
    g_clear_object(&self->_priv.ipv4_config);
    g_clear_object(&self->_priv.ipv6_config);
    g_clear_object(&self->_priv.bearer);

    self->_priv.pin_tries = 0;

    NM_MODEM_CLASS(nm_modem_broadband_parent_class)
        ->deactivate_cleanup(modem, device, stop_ppp_manager);
}

/*****************************************************************************/

#define MAP_STATE(name)         \
    case MM_MODEM_STATE_##name: \
        return NM_MODEM_STATE_##name;

static NMModemState
mm_state_to_nm(MMModemState mm_state)
{
    switch (mm_state) {
        MAP_STATE(UNKNOWN)
        MAP_STATE(FAILED)
        MAP_STATE(INITIALIZING)
        MAP_STATE(LOCKED)
        MAP_STATE(DISABLED)
        MAP_STATE(DISABLING)
        MAP_STATE(ENABLING)
        MAP_STATE(ENABLED)
        MAP_STATE(SEARCHING)
        MAP_STATE(REGISTERED)
        MAP_STATE(DISCONNECTING)
        MAP_STATE(CONNECTING)
        MAP_STATE(CONNECTED)
    }
    return NM_MODEM_STATE_UNKNOWN;
}

static void
modem_state_changed(MMModem                 *modem,
                    MMModemState             old_state,
                    MMModemState             new_state,
                    MMModemStateChangeReason reason,
                    NMModemBroadband        *self)
{
    /* After the SIM is unlocked MM1 will move the device to INITIALIZING which
     * is an unavailable state.  That makes state handling confusing here, so
     * suppress this state change and let the modem move from LOCKED to DISABLED.
     */
    if (new_state == MM_MODEM_STATE_INITIALIZING && old_state == MM_MODEM_STATE_LOCKED)
        return;

    nm_modem_set_state(NM_MODEM(self),
                       mm_state_to_nm(new_state),
                       mm_modem_state_change_reason_get_string(reason));

    if (self->_priv.ctx && self->_priv.ctx->step == CONNECT_STEP_WAIT_FOR_READY)
        connect_context_step(self);
}

/*****************************************************************************/

static NMModemIPType
mm_ip_family_to_nm(MMBearerIpFamily family)
{
    NMModemIPType nm_type = NM_MODEM_IP_TYPE_UNKNOWN;

    if (family & MM_BEARER_IP_FAMILY_IPV4)
        nm_type |= NM_MODEM_IP_TYPE_IPV4;
    if (family & MM_BEARER_IP_FAMILY_IPV6)
        nm_type |= NM_MODEM_IP_TYPE_IPV6;
    if (family & MM_BEARER_IP_FAMILY_IPV4V6)
        nm_type |= MM_BEARER_IP_FAMILY_IPV4V6;

    return nm_type;
}

static void
get_sim_ready(MMModem *modem, GAsyncResult *res, NMModemBroadband *self)
{
    GError *error = NULL;
    MMSim  *new_sim;

    new_sim = mm_modem_get_sim_finish(modem, res, &error);
    if (new_sim != self->_priv.sim_iface) {
        g_clear_object(&self->_priv.sim_iface);
        self->_priv.sim_iface = new_sim;
    } else
        g_clear_object(&new_sim);

    if (self->_priv.sim_iface) {
        g_object_set(G_OBJECT(self),
                     NM_MODEM_SIM_ID,
                     mm_sim_get_identifier(self->_priv.sim_iface),
                     NM_MODEM_SIM_OPERATOR_ID,
                     mm_sim_get_operator_identifier(self->_priv.sim_iface),
                     NULL);

        /* If we're waiting for the SIM during a connect, proceed with the connect */
        if (self->_priv.ctx && self->_priv.ctx->step == CONNECT_STEP_WAIT_FOR_SIM)
            connect_context_step(self);
    } else {
        _NMLOG(g_error_matches(error, MM_CORE_ERROR, MM_CORE_ERROR_NOT_FOUND) ? LOGL_INFO
                                                                              : LOGL_WARN,
               "failed to retrieve SIM object: %s",
               NM_G_ERROR_MSG(error));
    }
    g_clear_error(&error);
    g_object_unref(self);
}

static void
sim_changed(MMModem *modem, GParamSpec *pspec, gpointer user_data)
{
    NMModemBroadband *self = NM_MODEM_BROADBAND(user_data);

    g_return_if_fail(modem == self->_priv.modem_iface);

    if (mm_modem_get_sim_path(self->_priv.modem_iface)) {
        mm_modem_get_sim(self->_priv.modem_iface,
                         NULL, /* cancellable */
                         (GAsyncReadyCallback) get_sim_ready,
                         g_object_ref(self));
    } else
        g_object_set(G_OBJECT(self), NM_MODEM_SIM_ID, NULL, NM_MODEM_SIM_OPERATOR_ID, NULL, NULL);
}

static void
supported_ip_families_changed(MMModem *modem, GParamSpec *pspec, gpointer user_data)
{
    NMModemBroadband *self = NM_MODEM_BROADBAND(user_data);

    g_return_if_fail(modem == self->_priv.modem_iface);

    g_object_set(G_OBJECT(self),
                 NM_MODEM_IP_TYPES,
                 mm_ip_family_to_nm(mm_modem_get_supported_ip_families(modem)),
                 NULL);
}

static void
operator_code_changed(MMModem3gpp *modem_3gpp, GParamSpec *pspec, gpointer user_data)
{
    NMModemBroadband *self = NM_MODEM_BROADBAND(user_data);

    g_return_if_fail(modem_3gpp == self->_priv.modem_3gpp_iface);
    _nm_modem_set_operator_code(NM_MODEM(self), mm_modem_3gpp_get_operator_code(modem_3gpp));
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMModemBroadband *self = NM_MODEM_BROADBAND(object);

    switch (prop_id) {
    case PROP_MODEM:
        g_value_set_object(value, self->_priv.modem_object);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMModemBroadband *self = NM_MODEM_BROADBAND(object);

    switch (prop_id) {
    case PROP_MODEM:
        /* construct-only */
        self->_priv.modem_object = g_value_dup_object(value);
        self->_priv.modem_iface  = mm_object_get_modem(self->_priv.modem_object);
        g_return_if_fail(self->_priv.modem_iface);
        self->_priv.modem_3gpp_iface = mm_object_get_modem_3gpp(self->_priv.modem_object);

        g_signal_connect(self->_priv.modem_iface,
                         "state-changed",
                         G_CALLBACK(modem_state_changed),
                         self);
        g_signal_connect(self->_priv.modem_iface, "notify::sim", G_CALLBACK(sim_changed), self);
        sim_changed(self->_priv.modem_iface, NULL, self);
        g_signal_connect(self->_priv.modem_iface,
                         "notify::supported-ip-families",
                         G_CALLBACK(supported_ip_families_changed),
                         self);

        if (self->_priv.modem_3gpp_iface) {
            g_signal_connect(self->_priv.modem_3gpp_iface,
                             "notify::operator-code",
                             G_CALLBACK(operator_code_changed),
                             self);
        }

        /* Note: don't grab the Simple iface here; the Modem interface is the
         * only one assumed to be always valid and available */
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_modem_broadband_init(NMModemBroadband *self)
{}

NMModem *
nm_modem_broadband_new(GObject *object, GError **error)
{
    MMObject          *modem_object;
    MMModem           *modem_iface;
    MMModem3gpp       *modem_3gpp_iface;
    const char *const *drivers;
    const char        *operator_code = NULL;
    gs_free char      *driver        = NULL;

    g_return_val_if_fail(MM_IS_OBJECT(object), NULL);
    modem_object = MM_OBJECT(object);

    /* Ensure we have the 'Modem' interface and the primary port at least */
    modem_iface = mm_object_peek_modem(modem_object);
    g_return_val_if_fail(modem_iface, NULL);
    g_return_val_if_fail(mm_modem_get_primary_port(modem_iface), NULL);

    /* Build a single string with all drivers listed */
    drivers = mm_modem_get_drivers(modem_iface);
    if (drivers)
        driver = g_strjoinv(", ", (char **) drivers);

    modem_3gpp_iface = mm_object_peek_modem_3gpp(modem_object);
    if (modem_3gpp_iface)
        operator_code = mm_modem_3gpp_get_operator_code(modem_3gpp_iface);

    return g_object_new(NM_TYPE_MODEM_BROADBAND,
                        NM_MODEM_PATH,
                        mm_object_get_path(modem_object),
                        NM_MODEM_UID,
                        mm_modem_get_primary_port(modem_iface),
                        NM_MODEM_CONTROL_PORT,
                        mm_modem_get_primary_port(modem_iface),
                        NM_MODEM_IP_TYPES,
                        mm_ip_family_to_nm(mm_modem_get_supported_ip_families(modem_iface)),
                        NM_MODEM_STATE,
                        (int) mm_state_to_nm(mm_modem_get_state(modem_iface)),
                        NM_MODEM_DEVICE_ID,
                        mm_modem_get_device_identifier(modem_iface),
                        NM_MODEM_BROADBAND_MODEM,
                        modem_object,
                        NM_MODEM_DRIVER,
                        driver,
                        NM_MODEM_OPERATOR_CODE,
                        operator_code,
                        NULL);
}

static void
dispose(GObject *object)
{
    NMModemBroadband        *self = NM_MODEM_BROADBAND(object);
    NMModemBroadbandPrivate *priv = NM_MODEM_BROADBAND_GET_PRIVATE(self);

    connect_context_clear(self);
    g_clear_object(&priv->ipv4_config);
    g_clear_object(&priv->ipv6_config);
    g_clear_object(&priv->bearer);

    if (priv->modem_iface) {
        g_signal_handlers_disconnect_by_data(priv->modem_iface, self);
        g_clear_object(&priv->modem_iface);
    }

    if (priv->modem_3gpp_iface) {
        g_signal_handlers_disconnect_by_data(priv->modem_3gpp_iface, self);
        g_clear_object(&priv->modem_3gpp_iface);
    }

    g_clear_object(&priv->simple_iface);
    g_clear_object(&priv->sim_iface);
    g_clear_object(&priv->modem_object);

    G_OBJECT_CLASS(nm_modem_broadband_parent_class)->dispose(object);
}

static void
nm_modem_broadband_class_init(NMModemBroadbandClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);
    NMModemClass *modem_class  = NM_MODEM_CLASS(klass);

    object_class->dispose      = dispose;
    object_class->get_property = get_property;
    object_class->set_property = set_property;

    modem_class->get_capabilities                       = get_capabilities;
    modem_class->stage3_ip_config_start                 = stage3_ip_config_start;
    modem_class->disconnect                             = disconnect;
    modem_class->deactivate_cleanup                     = deactivate_cleanup;
    modem_class->set_mm_enabled                         = set_mm_enabled;
    modem_class->get_user_pass                          = get_user_pass;
    modem_class->check_connection_compatible_with_modem = check_connection_compatible_with_modem;
    modem_class->complete_connection                    = complete_connection;
    modem_class->modem_act_stage1_prepare               = modem_act_stage1_prepare;
    modem_class->owns_port                              = owns_port;

    obj_properties[PROP_MODEM] =
        g_param_spec_object(NM_MODEM_BROADBAND_MODEM,
                            "",
                            "",
                            MM_GDBUS_TYPE_OBJECT,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
