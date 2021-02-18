/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2012 Aleksander Morgado <aleksander@gnu.org>
 */

#include "src/core/nm-default-daemon.h"

#include "nm-modem-broadband.h"
#include "nm-service-providers.h"

#include <arpa/inet.h>
#include <libmm-glib.h>

#include "libnm-core-intern/nm-core-internal.h"
#include "NetworkManagerUtils.h"
#include "devices/nm-device-private.h"
#include "platform/nm-platform.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"

#define NM_MODEM_BROADBAND_MODEM "modem"

static gboolean
MODEM_CAPS_3GPP(MMModemCapability caps)
{
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS
    /* MM_MODEM_CAPABILITY_LTE_ADVANCED is marked as deprecated since ModemManager 1.14.0.
     *
     * The flag probably was never used, it certainly isn't used since 1.14.0.
     *
     * Still, just to be sure, there is no harm in checking it here. Suppress the
     * warning, it should have no bad effect.
     */
    return NM_FLAGS_ANY(caps,
                        (MM_MODEM_CAPABILITY_GSM_UMTS | MM_MODEM_CAPABILITY_LTE
                         | MM_MODEM_CAPABILITY_LTE_ADVANCED));
    G_GNUC_END_IGNORE_DEPRECATIONS
}

#define MODEM_CAPS_3GPP2(caps) (caps & (MM_MODEM_CAPABILITY_CDMA_EVDO))

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
    CONNECT_STEP_CONNECT,
    CONNECT_STEP_LAST,
} ConnectStep;

typedef struct {
    NMModemBroadband *self;
    ConnectStep       step;

    MMModemCapability          caps;
    NMConnection *             connection;
    GCancellable *             cancellable;
    MMSimpleConnectProperties *connect_properties;
    GArray *                   ip_types;
    guint                      ip_types_i;
    guint                      ip_type_tries;
    GError *                   first_error;
} ConnectContext;

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_MODEM, );

typedef struct {
    /* The modem object from dbus */
    MMObject *modem_object;
    /* Per-interface objects */
    MMModem *      modem_iface;
    MMModem3gpp *  modem_3gpp_iface;
    MMModemSimple *simple_iface;
    MMSim *        sim_iface;

    /* Connection setup */
    ConnectContext *ctx;

    MMBearer *        bearer;
    MMBearerIpConfig *ipv4_config;
    MMBearerIpConfig *ipv6_config;

    guint idle_id_ip4;
    guint idle_id_ip6;

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
            const char *            __uid;                                       \
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
get_capabilities(NMModem *                  _self,
                 NMDeviceModemCapabilities *modem_caps,
                 NMDeviceModemCapabilities *current_caps)
{
    NMModemBroadband * self          = NM_MODEM_BROADBAND(_self);
    MMModemCapability  all_supported = MM_MODEM_CAPABILITY_NONE;
    MMModemCapability *supported;
    guint              n_supported;

    /* For now, we don't care about the capability combinations, just merge all
     * combinations in a single mask */
    if (mm_modem_get_supported_capabilities(self->_priv.modem_iface, &supported, &n_supported)) {
        guint i;

        for (i = 0; i < n_supported; i++)
            all_supported |= supported[i];

        g_free(supported);
    }

    *modem_caps = (NMDeviceModemCapabilities) all_supported;
    *current_caps =
        (NMDeviceModemCapabilities) mm_modem_get_current_capabilities(self->_priv.modem_iface);
}

static gboolean
owns_port(NMModem *_self, const char *iface)
{
    NMModemBroadband *     self    = NM_MODEM_BROADBAND(_self);
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
        const char *   str;

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
                              const char *  apn,
                              const char *  username,
                              const char *  password)
{
    NMSettingGsm *             setting;
    NMSettingPpp *             s_ppp;
    MMSimpleConnectProperties *properties;
    const char *               str;

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
    ConnectContext *ctx;
    GError *        error      = NULL;
    NMModemIPMethod ip4_method = NM_MODEM_IP_METHOD_UNKNOWN;
    NMModemIPMethod ip6_method = NM_MODEM_IP_METHOD_UNKNOWN;
    MMBearer *      bearer;

    bearer = mm_modem_simple_connect_finish(simple_iface, res, &error);

    if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
        g_error_free(error);
        return;
    }

    ctx = self->_priv.ctx;

    if (!ctx)
        return;

    self->_priv.bearer = bearer;

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
find_gsm_apn_cb(const char *  apn,
                const char *  username,
                const char *  password,
                const char *  gateway,
                const char *  auth_method,
                const GSList *dns,
                GError *      error,
                gpointer      user_data)
{
    NMModemBroadband *       self = user_data;
    NMModemBroadbandPrivate *priv = NM_MODEM_BROADBAND_GET_PRIVATE(self);
    ConnectContext *         ctx  = priv->ctx;

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
    ConnectContext *         ctx  = priv->ctx;

    if (MODEM_CAPS_3GPP(ctx->caps)) {
        NMSettingGsm *s_gsm = nm_connection_get_setting_gsm(ctx->connection);

        if (!s_gsm || nm_setting_gsm_get_auto_config(s_gsm)) {
            gs_unref_object MMModem3gpp *modem_3gpp = NULL;
            const char *                 network_id = NULL;

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
            const char *  pin   = nm_setting_gsm_get_pin(s_gsm);

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
    case CONNECT_STEP_CONNECT:
        if (!ctx->connect_properties)
            break;

        if (ctx->ip_types_i < ctx->ip_types->len) {
            NMModemIPType current;

            current = g_array_index(ctx->ip_types, NMModemIPType, ctx->ip_types_i);

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
modem_act_stage1_prepare(NMModem *            _self,
                         NMConnection *       connection,
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
complete_connection(NMModem *            modem,
                    const char *         iface,
                    NMConnection *       connection,
                    NMConnection *const *existing_connections,
                    GError **            error)
{
    NMModemBroadband *self = NM_MODEM_BROADBAND(modem);
    MMModemCapability modem_caps;
    NMSettingPpp *    s_ppp;

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

        s_cdma = nm_connection_get_setting_cdma(connection);
        if (!s_cdma) {
            s_cdma = (NMSettingCdma *) nm_setting_cdma_new();
            nm_connection_add_setting(connection, NM_SETTING(s_cdma));
        }

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
    NMSettingGsm * s_gsm;
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
/* IPv4 method static */

static gboolean
static_stage3_ip4_done(NMModemBroadband *self)
{
    GError *        error               = NULL;
    gs_unref_object NMIP4Config *config = NULL;
    const char *                 data_port;
    const char *                 address_string;
    const char *                 gw_string;
    guint32                      address_network;
    guint32                      gw = 0;
    NMPlatformIP4Address         address;
    const char **                dns;
    guint                        i;
    guint32                      ip4_route_table, ip4_route_metric;
    NMPlatformIP4Route *         r;
    guint32                      mtu_n;

    g_return_val_if_fail(self->_priv.ipv4_config, FALSE);
    g_return_val_if_fail(self->_priv.bearer, FALSE);

    self->_priv.idle_id_ip4 = 0;

    _LOGI("IPv4 static configuration:");

    /* Fully fail if invalid IP address retrieved */
    address_string = mm_bearer_ip_config_get_address(self->_priv.ipv4_config);
    if (!address_string
        || !nm_utils_parse_inaddr_bin(AF_INET, address_string, NULL, &address_network)) {
        error =
            g_error_new(NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_INVALID_CONNECTION,
                        "(%s) retrieving IP4 configuration failed: invalid address given %s%s%s",
                        nm_modem_get_uid(NM_MODEM(self)),
                        NM_PRINT_FMT_QUOTE_STRING(address_string));
        goto out;
    }

    /* Missing gateway not a hard failure */
    gw_string = mm_bearer_ip_config_get_gateway(self->_priv.ipv4_config);
    if (gw_string && !nm_utils_parse_inaddr_bin(AF_INET, gw_string, NULL, &gw)) {
        error =
            g_error_new(NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_INVALID_CONNECTION,
                        "(%s) retrieving IP4 configuration failed: invalid gateway address \"%s\"",
                        nm_modem_get_uid(NM_MODEM(self)),
                        gw_string);
        goto out;
    }

    data_port = mm_bearer_get_interface(self->_priv.bearer);
    g_return_val_if_fail(data_port, FALSE);
    config = nm_ip4_config_new(nm_platform_get_multi_idx(NM_PLATFORM_GET),
                               nm_platform_link_get_ifindex(NM_PLATFORM_GET, data_port));

    memset(&address, 0, sizeof(address));
    address.address      = address_network;
    address.peer_address = address_network;
    address.plen         = mm_bearer_ip_config_get_prefix(self->_priv.ipv4_config);
    address.addr_source  = NM_IP_CONFIG_SOURCE_WWAN;
    if (address.plen <= 32)
        nm_ip4_config_add_address(config, &address);

    _LOGI("  address %s/%d", address_string, address.plen);

    nm_modem_get_route_parameters(NM_MODEM(self), &ip4_route_table, &ip4_route_metric, NULL, NULL);
    r = &(NMPlatformIP4Route){
        .rt_source     = NM_IP_CONFIG_SOURCE_WWAN,
        .gateway       = gw,
        .table_coerced = nm_platform_route_table_coerce(ip4_route_table),
        .metric        = ip4_route_metric,
    };
    nm_ip4_config_add_route(config, r, NULL);
    _LOGI("  gateway %s", gw_string);

    /* DNS servers */
    dns = mm_bearer_ip_config_get_dns(self->_priv.ipv4_config);
    for (i = 0; dns && dns[i]; i++) {
        if (nm_utils_parse_inaddr_bin(AF_INET, dns[i], NULL, &address_network)
            && address_network > 0) {
            nm_ip4_config_add_nameserver(config, address_network);
            _LOGI("  DNS %s", dns[i]);
        }
    }

#if MM_CHECK_VERSION(1, 4, 0)
    mtu_n = mm_bearer_ip_config_get_mtu(self->_priv.ipv4_config);
    if (mtu_n) {
        nm_ip4_config_set_mtu(config, mtu_n, NM_IP_CONFIG_SOURCE_WWAN);
        _LOGI("  MTU %u", mtu_n);
    }
#endif

out:
    g_signal_emit_by_name(self, NM_MODEM_IP4_CONFIG_RESULT, config, error);
    g_clear_error(&error);
    return FALSE;
}

static NMActStageReturn
static_stage3_ip4_config_start(NMModem *            modem,
                               NMActRequest *       req,
                               NMDeviceStateReason *out_failure_reason)
{
    NMModemBroadband *       self = NM_MODEM_BROADBAND(modem);
    NMModemBroadbandPrivate *priv = NM_MODEM_BROADBAND_GET_PRIVATE(self);

    /* We schedule it in an idle just to follow the same logic as in the
     * generic modem implementation. */
    nm_clear_g_source(&priv->idle_id_ip4);
    priv->idle_id_ip4 = g_idle_add((GSourceFunc) static_stage3_ip4_done, self);

    return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/
/* IPv6 method static */

static gboolean
stage3_ip6_done(NMModemBroadband *self)
{
    GError *             error  = NULL;
    NMIP6Config *        config = NULL;
    const char *         data_port;
    const char *         address_string;
    NMPlatformIP6Address address;
    NMModemIPMethod      ip_method;
    const char **        dns;
    guint                i;

    g_return_val_if_fail(self->_priv.ipv6_config, FALSE);

    self->_priv.idle_id_ip6 = 0;
    memset(&address, 0, sizeof(address));

    ip_method = get_bearer_ip_method(self->_priv.ipv6_config);

    address_string = mm_bearer_ip_config_get_address(self->_priv.ipv6_config);
    if (!address_string) {
        /* DHCP/SLAAC is allowed to skip addresses; other methods require it */
        if (ip_method != NM_MODEM_IP_METHOD_AUTO) {
            error = g_error_new(NM_DEVICE_ERROR,
                                NM_DEVICE_ERROR_INVALID_CONNECTION,
                                "(%s) retrieving IPv6 configuration failed: no address given",
                                nm_modem_get_uid(NM_MODEM(self)));
        }
        goto out;
    }

    /* Fail if invalid IP address retrieved */
    if (!inet_pton(AF_INET6, address_string, (void *) &(address.address))) {
        error = g_error_new(NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INVALID_CONNECTION,
                            "(%s) retrieving IPv6 configuration failed: invalid address given '%s'",
                            nm_modem_get_uid(NM_MODEM(self)),
                            address_string);
        goto out;
    }

    _LOGI("IPv6 base configuration:");

    data_port = mm_bearer_get_interface(self->_priv.bearer);
    g_return_val_if_fail(data_port, FALSE);

    config = nm_ip6_config_new(nm_platform_get_multi_idx(NM_PLATFORM_GET),
                               nm_platform_link_get_ifindex(NM_PLATFORM_GET, data_port));

    address.plen = mm_bearer_ip_config_get_prefix(self->_priv.ipv6_config);
    if (address.plen <= 128)
        nm_ip6_config_add_address(config, &address);

    _LOGI("  address %s/%d", address_string, address.plen);

    address_string = mm_bearer_ip_config_get_gateway(self->_priv.ipv6_config);
    if (address_string) {
        guint32 ip6_route_table, ip6_route_metric;

        if (inet_pton(AF_INET6, address_string, &address.address) != 1) {
            error =
                g_error_new(NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INVALID_CONNECTION,
                            "(%s) retrieving IPv6 configuration failed: invalid gateway given '%s'",
                            nm_modem_get_uid(NM_MODEM(self)),
                            address_string);
            goto out;
        }

        nm_modem_get_route_parameters(NM_MODEM(self),
                                      NULL,
                                      NULL,
                                      &ip6_route_table,
                                      &ip6_route_metric);
        {
            const NMPlatformIP6Route r = {
                .rt_source     = NM_IP_CONFIG_SOURCE_WWAN,
                .gateway       = address.address,
                .table_coerced = nm_platform_route_table_coerce(ip6_route_table),
                .metric        = ip6_route_metric,
            };

            _LOGI("  gateway %s", address_string);
            nm_ip6_config_add_route(config, &r, NULL);
        }
    } else if (ip_method == NM_MODEM_IP_METHOD_STATIC) {
        /* Gateway required for the 'static' method */
        error = g_error_new(NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INVALID_CONNECTION,
                            "(%s) retrieving IPv6 configuration failed: missing gateway",
                            nm_modem_get_uid(NM_MODEM(self)));
        goto out;
    }

    /* DNS servers */
    dns = mm_bearer_ip_config_get_dns(self->_priv.ipv6_config);
    for (i = 0; dns && dns[i]; i++) {
        struct in6_addr addr;

        if (inet_pton(AF_INET6, dns[i], &addr)) {
            nm_ip6_config_add_nameserver(config, &addr);
            _LOGI("  DNS %s", dns[i]);
        }
    }

out:
    nm_modem_emit_ip6_config_result(NM_MODEM(self), config, error);
    g_clear_object(&config);
    g_clear_error(&error);
    return FALSE;
}

static NMActStageReturn
stage3_ip6_config_request(NMModem *modem, NMDeviceStateReason *out_failure_reason)
{
    NMModemBroadband *       self = NM_MODEM_BROADBAND(modem);
    NMModemBroadbandPrivate *priv = NM_MODEM_BROADBAND_GET_PRIVATE(self);

    /* We schedule it in an idle just to follow the same logic as in the
     * generic modem implementation. */
    nm_clear_g_source(&priv->idle_id_ip6);
    priv->idle_id_ip6 = g_idle_add((GSourceFunc) stage3_ip6_done, self);

    return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/
/* Disconnect */

typedef struct {
    NMModemBroadband *         self;
    _NMModemDisconnectCallback callback;
    gpointer                   callback_user_data;
    GCancellable *             cancellable;
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
    DisconnectContext *ctx                = user_data;
    gs_free_error GError *cancelled_error = NULL;

    g_cancellable_set_error_if_cancelled(cancellable, &cancelled_error);
    disconnect_context_complete(ctx, cancelled_error);
}

static void
simple_disconnect_ready(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    MMModemSimple *    modem_iface = MM_MODEM_SIMPLE(source_object);
    DisconnectContext *ctx         = user_data;
    gs_free_error GError *error    = NULL;

    if (!mm_modem_simple_disconnect_finish(modem_iface, res, &error)) {
        if (ctx->warn && !g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN)) {
            NMModemBroadband *self = ctx->self;

            _LOGW("failed to disconnect modem: %s", error->message);
        }
    }

    disconnect_context_complete(ctx, error);
}

static void
disconnect(NMModem *                  modem,
           gboolean                   warn,
           GCancellable *             cancellable,
           _NMModemDisconnectCallback callback,
           gpointer                   user_data)
{
    NMModemBroadband * self = NM_MODEM_BROADBAND(modem);
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
modem_state_changed(MMModem *                modem,
                    MMModemState             old_state,
                    MMModemState             new_state,
                    MMModemStateChangeReason reason,
                    NMModemBroadband *       self)
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
    MMSim * new_sim;

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
    MMObject *         modem_object;
    MMModem *          modem_iface;
    MMModem3gpp *      modem_3gpp_iface;
    const char *const *drivers;
    const char *       operator_code = NULL;
    gs_free char *     driver        = NULL;

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
    NMModemBroadband *       self = NM_MODEM_BROADBAND(object);
    NMModemBroadbandPrivate *priv = NM_MODEM_BROADBAND_GET_PRIVATE(self);

    nm_clear_g_source(&priv->idle_id_ip4);
    nm_clear_g_source(&priv->idle_id_ip6);

    connect_context_clear(self);
    g_clear_object(&self->_priv.ipv4_config);
    g_clear_object(&self->_priv.ipv6_config);
    g_clear_object(&self->_priv.bearer);

    if (self->_priv.modem_iface) {
        g_signal_handlers_disconnect_by_data(self->_priv.modem_iface, self);
        g_clear_object(&self->_priv.modem_iface);
    }

    if (self->_priv.modem_3gpp_iface) {
        g_signal_handlers_disconnect_by_data(self->_priv.modem_3gpp_iface, self);
        g_clear_object(&self->_priv.modem_3gpp_iface);
    }

    g_clear_object(&self->_priv.simple_iface);
    g_clear_object(&self->_priv.sim_iface);
    g_clear_object(&self->_priv.modem_object);

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
    modem_class->static_stage3_ip4_config_start         = static_stage3_ip4_config_start;
    modem_class->stage3_ip6_config_request              = stage3_ip6_config_request;
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
