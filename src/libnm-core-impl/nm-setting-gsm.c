/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-gsm.h"

#include "nm-utils.h"
#include "nm-setting-private.h"
#include "nm-core-enum-types.h"

/**
 * SECTION:nm-setting-gsm
 * @short_description: Describes GSM/3GPP-based mobile broadband properties
 *
 * The #NMSettingGsm object is a #NMSetting subclass that describes
 * properties that allow connections to 3GPP-based mobile broadband
 * networks, including those using GPRS/EDGE and UMTS/HSPA technology.
 */

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_AUTO_CONFIG,
                                  PROP_NUMBER,
                                  PROP_USERNAME,
                                  PROP_PASSWORD,
                                  PROP_PASSWORD_FLAGS,
                                  PROP_APN,
                                  PROP_NETWORK_ID,
                                  PROP_PIN,
                                  PROP_PIN_FLAGS,
                                  PROP_HOME_ONLY,
                                  PROP_DEVICE_ID,
                                  PROP_SIM_ID,
                                  PROP_SIM_OPERATOR_ID,
                                  PROP_MTU,
                                  PROP_INITIAL_EPS_CONFIG,
                                  PROP_INITIAL_EPS_APN,
                                  PROP_INITIAL_EPS_USERNAME,
                                  PROP_INITIAL_EPS_PASSWORD,
                                  PROP_INITIAL_EPS_PASSWORD_FLAGS,
                                  PROP_INITIAL_EPS_NOAUTH,
                                  PROP_INITIAL_EPS_REFUSE_EAP,
                                  PROP_INITIAL_EPS_REFUSE_PAP,
                                  PROP_INITIAL_EPS_REFUSE_CHAP,
                                  PROP_INITIAL_EPS_REFUSE_MSCHAP,
                                  PROP_INITIAL_EPS_REFUSE_MSCHAPV2,
                                  PROP_DEVICE_UID, );

typedef struct {
    char   *number;
    char   *username;
    char   *password;
    char   *device_id;
    char   *sim_id;
    char   *sim_operator_id;
    char   *apn;
    char   *network_id;
    char   *pin;
    char   *initial_eps_apn;
    char   *initial_eps_username;
    char   *initial_eps_password;
    bool    initial_eps_noauth;
    bool    initial_eps_refuse_eap;
    bool    initial_eps_refuse_pap;
    bool    initial_eps_refuse_chap;
    bool    initial_eps_refuse_mschap;
    bool    initial_eps_refuse_mschapv2;
    guint   password_flags;
    guint   initial_eps_password_flags;
    guint   pin_flags;
    guint32 mtu;
    bool    auto_config;
    bool    home_only;
    bool    initial_eps_config;
    char   *device_uid;
} NMSettingGsmPrivate;

/**
 * NMSettingGsm:
 *
 * GSM-based Mobile Broadband Settings
 */
struct _NMSettingGsm {
    NMSetting           parent;
    NMSettingGsmPrivate _priv;
};

struct _NMSettingGsmClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingGsm, nm_setting_gsm, NM_TYPE_SETTING)

#define NM_SETTING_GSM_GET_PRIVATE(o) _NM_GET_PRIVATE(o, NMSettingGsm, NM_IS_SETTING_GSM, NMSetting)

/*****************************************************************************/

/**
 * nm_setting_gsm_get_auto_config:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:auto-config property of the setting
 *
 * Since: 1.22
 **/
gboolean
nm_setting_gsm_get_auto_config(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), FALSE);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->auto_config;
}

/**
 * nm_setting_gsm_get_number:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:number property of the setting
 *
 * Deprecated: 1.16: User-provided values for this setting are no longer used.
 **/
const char *
nm_setting_gsm_get_number(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NULL);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->number;
}

/**
 * nm_setting_gsm_get_username:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:username property of the setting
 **/
const char *
nm_setting_gsm_get_username(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NULL);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->username;
}

/**
 * nm_setting_gsm_get_password:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:password property of the setting
 **/
const char *
nm_setting_gsm_get_password(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NULL);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->password;
}

/**
 * nm_setting_gsm_get_password_flags:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingSecretFlags pertaining to the #NMSettingGsm:password
 **/
NMSettingSecretFlags
nm_setting_gsm_get_password_flags(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NM_SETTING_SECRET_FLAG_NONE);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->password_flags;
}

/**
 * nm_setting_gsm_get_apn:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:apn property of the setting
 **/
const char *
nm_setting_gsm_get_apn(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NULL);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->apn;
}

/**
 * nm_setting_gsm_get_network_id:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:network-id property of the setting
 **/
const char *
nm_setting_gsm_get_network_id(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NULL);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->network_id;
}

/**
 * nm_setting_gsm_get_pin:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:pin property of the setting
 **/
const char *
nm_setting_gsm_get_pin(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NULL);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->pin;
}

/**
 * nm_setting_gsm_get_pin_flags:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingSecretFlags pertaining to the #NMSettingGsm:pin
 **/
NMSettingSecretFlags
nm_setting_gsm_get_pin_flags(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NM_SETTING_SECRET_FLAG_NONE);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->pin_flags;
}

/**
 * nm_setting_gsm_get_home_only:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:home-only property of the setting
 **/
gboolean
nm_setting_gsm_get_home_only(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), FALSE);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->home_only;
}

/**
 * nm_setting_gsm_get_device_id:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:device-id property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_gsm_get_device_id(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NULL);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->device_id;
}

/**
 * nm_setting_gsm_get_sim_id:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:sim-id property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_gsm_get_sim_id(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NULL);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->sim_id;
}

/**
 * nm_setting_gsm_get_sim_operator_id:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:sim-operator-id property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_gsm_get_sim_operator_id(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NULL);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->sim_operator_id;
}

/**
 * nm_setting_gsm_get_mtu:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:mtu property of the setting
 *
 * Since: 1.8
 **/
guint32
nm_setting_gsm_get_mtu(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), 0);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->mtu;
}

/**
 * nm_setting_gsm_get_initial_eps_config:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:initial-eps-bearer-configure property of the setting
 *
 * Since: 1.44
 **/
gboolean
nm_setting_gsm_get_initial_eps_config(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), FALSE);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->initial_eps_config;
}

/**
 * nm_setting_gsm_get_initial_eps_apn:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:initial-eps-bearer-apn property of the setting
 *
 * Since: 1.44
 **/
const char *
nm_setting_gsm_get_initial_eps_apn(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NULL);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->initial_eps_apn;
}

/**
 * nm_setting_gsm_get_initial_eps_username:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:initial-eps-bearer-username property of the setting
 *
 * Since: 1.52
 **/
const char *
nm_setting_gsm_get_initial_eps_username(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NULL);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->initial_eps_username;
}

/**
 * nm_setting_gsm_get_initial_eps_password:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:initial-eps-bearer-password property of the setting
 *
 * Since: 1.52
 **/
const char *
nm_setting_gsm_get_initial_eps_password(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NULL);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->initial_eps_password;
}

/**
 * nm_setting_gsm_get_initial_eps_noauth:
 * @setting: the #NMSettingGsm
 *
 * Returns: For LTE modems, the #NMSettingGsm:initial-eps-noauth property of the setting
 *
 * Since: 1.52
 **/
gboolean
nm_setting_gsm_get_initial_eps_noauth(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), FALSE);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->initial_eps_noauth;
}

/**
 * nm_setting_gsm_get_initial_eps_refuse_eap:
 * @setting: the #NMSettingGsm
 *
 * Returns: For LTE modems, the #NMSettingGsm:initial-eps-refuse-eap property of the setting
 *
 * Since: 1.52
 **/
gboolean
nm_setting_gsm_get_initial_eps_refuse_eap(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), FALSE);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->initial_eps_refuse_eap;
}

/**
 * nm_setting_gsm_get_initial_eps_refuse_pap:
 * @setting: the #NMSettingGsm
 *
 * Returns: For LTE modems, the #NMSettingGsm:initial-eps-refuse-pap property of the setting
 *
 * Since: 1.52
 **/
gboolean
nm_setting_gsm_get_initial_eps_refuse_pap(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), FALSE);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->initial_eps_refuse_pap;
}

/**
 * nm_setting_gsm_get_initial_eps_refuse_chap:
 * @setting: the #NMSettingGsm
 *
 * Returns: For LTE modems, the #NMSettingGsm:initial-eps-refuse-chap property of the setting
 *
 * Since: 1.52
 **/
gboolean
nm_setting_gsm_get_initial_eps_refuse_chap(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), FALSE);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->initial_eps_refuse_chap;
}

/**
 * nm_setting_gsm_get_initial_eps_refuse_mschap:
 * @setting: the #NMSettingGsm
 *
 * Returns: For LTE modems, the #NMSettingGsm:initial-eps-refuse-mschap property of the setting
 *
 * Since: 1.52
 **/
gboolean
nm_setting_gsm_get_initial_eps_refuse_mschap(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), FALSE);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->initial_eps_refuse_mschap;
}

/**
 * nm_setting_gsm_get_initial_eps_refuse_mschapv2:
 * @setting: the #NMSettingGsm
 *
 * Returns: For LTE modems, the #NMSettingGsm:initial-eps-refuse-mschapv2 property of the setting
 *
 * Since: 1.52
 **/
gboolean
nm_setting_gsm_get_initial_eps_refuse_mschapv2(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), FALSE);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->initial_eps_refuse_mschapv2;
}

/**
 * nm_setting_gsm_get_device_uid:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:device-uid property of the setting
 *
 * Since: 1.56
 **/
const char *
nm_setting_gsm_get_device_uid(NMSettingGsm *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GSM(setting), NULL);

    return NM_SETTING_GSM_GET_PRIVATE(setting)->device_uid;
}

static gboolean
_verify_apn(const char *apn, gboolean allow_empty, const char *property_name, GError **error)
{
    gsize apn_len;
    gsize i;

    if (!apn)
        return TRUE;

    apn_len = strlen(apn);

    if (!allow_empty && apn_len == 0) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("property value is empty"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, property_name);
        return FALSE;
    }

    if (apn_len > 64) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("property value is too long (>64)"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, property_name);
        return FALSE;
    }

    /* APNs roughly follow the same rules as DNS domain names.  Allowed
     * characters are a-z, 0-9, . and -.  GSM 03.03 Section 9.1 states:
     *
     *   The syntax of the APN shall follow the Name Syntax defined in
     *   RFC 2181 [14] and RFC 1035 [15]. The APN consists of one or
     *   more labels. Each label is coded as one octet length field
     *   followed by that number of octets coded as 8 bit ASCII characters.
     *   Following RFC 1035 [15] the labels should consist only of the
     *   alphabetic characters (A-Z and a-z), digits (0-9) and the
     *   dash (-). The case of alphabetic characters is not significant.
     *
     * A dot (.) is commonly used to separate parts of the APN, and
     * apparently the underscore (_) is used as well.  RFC 2181 indicates
     * that no restrictions of any kind are placed on DNS labels, and thus
     * it would appear that none are placed on APNs either, but many modems
     * and networks will fail to accept APNs that include odd characters
     * like space ( ) and such.
     */
    for (i = 0; i < apn_len; i++) {
        if (g_ascii_isalnum(apn[i]))
            continue;
        if (NM_IN_SET(apn[i], '.', '_', '-'))
            continue;

        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' contains invalid char(s) (use [A-Za-z._-])"),
                    apn);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, property_name);
        return FALSE;
    }

    return TRUE;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingGsmPrivate *priv = NM_SETTING_GSM_GET_PRIVATE(setting);

    if (priv->number && !priv->number[0]) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is empty"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_NUMBER);
        return FALSE;
    }

    if (!_verify_apn(priv->apn, TRUE, NM_SETTING_GSM_APN, error))
        return FALSE;

    if (!_verify_apn(priv->initial_eps_apn, FALSE, NM_SETTING_GSM_INITIAL_EPS_BEARER_APN, error))
        return FALSE;

    if (priv->username && priv->username[0] == '\0') {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is empty"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_USERNAME);
        return FALSE;
    }

    if (priv->network_id) {
        gsize nid_len = strlen(priv->network_id);
        gsize i;

        /* Accept both 5 and 6 digit MCC/MNC codes */
        if ((nid_len < 5) || (nid_len > 6)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' length is invalid (should be 5 or 6 digits)"),
                        priv->network_id);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_GSM_SETTING_NAME,
                           NM_SETTING_GSM_NETWORK_ID);
            return FALSE;
        }

        for (i = 0; i < nid_len; i++) {
            if (!g_ascii_isdigit(priv->network_id[i])) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("'%s' is not a number"),
                            priv->network_id);
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_GSM_SETTING_NAME,
                               NM_SETTING_GSM_NETWORK_ID);
                return FALSE;
            }
        }
    }

    if (priv->device_id && !priv->device_id[0]) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is empty"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_DEVICE_ID);
        return FALSE;
    }

    if (priv->sim_id && !priv->sim_id[0]) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is empty"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_SIM_ID);
        return FALSE;
    }

    if (priv->sim_operator_id) {
        size_t      len = strlen(priv->sim_operator_id);
        const char *p   = priv->sim_operator_id;

        if (len == 0 || (len != 5 && len != 6)) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("property is empty or wrong size"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_GSM_SETTING_NAME,
                           NM_SETTING_GSM_SIM_OPERATOR_ID);
            return FALSE;
        }

        while (p && *p) {
            if (!g_ascii_isdigit(*p++)) {
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    _("property must contain only digits"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_GSM_SETTING_NAME,
                               NM_SETTING_GSM_SIM_OPERATOR_ID);
                return FALSE;
            }
        }
    }

    if (priv->auto_config && (priv->apn || priv->username || priv->password)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("can't be enabled when manual configuration is present"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_AUTO_CONFIG);
        return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
    }

    return TRUE;
}

static gboolean
verify_secrets(NMSetting *setting, NMConnection *connection, GError **error)
{
    return _nm_setting_verify_secret_string(NM_SETTING_GSM_GET_PRIVATE(setting)->password,
                                            NM_SETTING_GSM_SETTING_NAME,
                                            NM_SETTING_GSM_PASSWORD,
                                            error);
}

static GPtrArray *
need_secrets(NMSetting *setting, gboolean check_rerequest)
{
    NMSettingGsmPrivate *priv    = NM_SETTING_GSM_GET_PRIVATE(setting);
    GPtrArray           *secrets = NULL;

    if (!check_rerequest && priv->password && *priv->password)
        return NULL;

    if (priv->username) {
        if (!(priv->password_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
            secrets = g_ptr_array_sized_new(1);
            g_ptr_array_add(secrets, NM_SETTING_GSM_PASSWORD);
        }
    }

    return secrets;
}

/*****************************************************************************/

static void
nm_setting_gsm_init(NMSettingGsm *setting)
{}

/**
 * nm_setting_gsm_new:
 *
 * Creates a new #NMSettingGsm object with default values.
 *
 * Returns: the new empty #NMSettingGsm object
 **/
NMSetting *
nm_setting_gsm_new(void)
{
    return g_object_new(NM_TYPE_SETTING_GSM, NULL);
}

static void
nm_setting_gsm_class_init(NMSettingGsmClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify         = verify;
    setting_class->verify_secrets = verify_secrets;
    setting_class->need_secrets   = need_secrets;

    /**
     * NMSettingGsm:auto-config:
     *
     * When %TRUE, the settings such as APN, username, or password will
     * default to values that match the network the modem will register
     * to in the Mobile Broadband Provider database.
     *
     * Since: 1.22
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_GSM_AUTO_CONFIG,
                                               PROP_AUTO_CONFIG,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingGsmPrivate,
                                               auto_config);

    /**
     * NMSettingGsm:number:
     *
     * Legacy setting that used to help establishing PPP data sessions for
     * GSM-based modems.
     *
     * Deprecated: 1.16: User-provided values for this setting are no longer used.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_NUMBER,
                                              PROP_NUMBER,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingGsmPrivate,
                                              number,
                                              .is_deprecated             = TRUE,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingGsm:username:
     *
     * The username used to authenticate with the network, if required.  Many
     * providers do not require a username, or accept any username.  But if a
     * username is required, it is specified here.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_USERNAME,
                                              PROP_USERNAME,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingGsmPrivate,
                                              username,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingGsm:password:
     *
     * The password used to authenticate with the network, if required.  Many
     * providers do not require a password, or accept any password.  But if a
     * password is required, it is specified here.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_PASSWORD,
                                              PROP_PASSWORD,
                                              NM_SETTING_PARAM_SECRET,
                                              NMSettingGsmPrivate,
                                              password,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingGsm:password-flags:
     *
     * Flags indicating how to handle the #NMSettingGsm:password property.
     **/
    _nm_setting_property_define_direct_secret_flags(properties_override,
                                                    obj_properties,
                                                    NM_SETTING_GSM_PASSWORD_FLAGS,
                                                    PROP_PASSWORD_FLAGS,
                                                    NMSettingGsmPrivate,
                                                    password_flags);
    /**
     * NMSettingGsm:apn:
     *
     * The GPRS Access Point Name specifying the APN used when establishing a
     * data session with the GSM-based network.  The APN often determines how
     * the user will be billed for their network usage and whether the user has
     * access to the Internet or just a provider-specific walled-garden, so it
     * is important to use the correct APN for the user's mobile broadband plan.
     * The APN may only be composed of the characters a-z, 0-9, ., and - per GSM
     * 03.60 Section 14.9.
     *
     * If the APN is unset (the default) then it may be detected based on
     * "auto-config" setting. The property can be explicitly set to the
     * empty string to prevent that and use no APN.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_APN,
                                              PROP_APN,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingGsmPrivate,
                                              apn,
                                              .direct_set_string_strip   = TRUE,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingGsm:network-id:
     *
     * The Network ID (GSM LAI format, ie MCC-MNC) to force specific network
     * registration.  If the Network ID is specified, NetworkManager will
     * attempt to force the device to register only on the specified network.
     * This can be used to ensure that the device does not roam when direct
     * roaming control of the device is not otherwise possible.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_NETWORK_ID,
                                              PROP_NETWORK_ID,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingGsmPrivate,
                                              network_id,
                                              .direct_set_string_strip   = TRUE,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingGsm:pin:
     *
     * If the SIM is locked with a PIN it must be unlocked before any other
     * operations are requested.  Specify the PIN here to allow operation of the
     * device.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_PIN,
                                              PROP_PIN,
                                              NM_SETTING_PARAM_SECRET,
                                              NMSettingGsmPrivate,
                                              pin,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingGsm:pin-flags:
     *
     * Flags indicating how to handle the #NMSettingGsm:pin property.
     **/
    _nm_setting_property_define_direct_secret_flags(properties_override,
                                                    obj_properties,
                                                    NM_SETTING_GSM_PIN_FLAGS,
                                                    PROP_PIN_FLAGS,
                                                    NMSettingGsmPrivate,
                                                    pin_flags);

    /**
     * NMSettingGsm:home-only:
     *
     * When %TRUE, only connections to the home network will be allowed.
     * Connections to roaming networks will not be made.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_GSM_HOME_ONLY,
                                               PROP_HOME_ONLY,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingGsmPrivate,
                                               home_only);

    /**
     * NMSettingGsm:device-id:
     *
     * The device unique identifier (as given by the WWAN management service)
     * which this connection applies to.  If given, the connection will only
     * apply to the specified device.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_DEVICE_ID,
                                              PROP_DEVICE_ID,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingGsmPrivate,
                                              device_id,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingGsm:sim-id:
     *
     * The SIM card unique identifier (as given by the WWAN management service)
     * which this connection applies to.  If given, the connection will apply
     * to any device also allowed by #NMSettingGsm:device-id which contains a
     * SIM card matching the given identifier.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_SIM_ID,
                                              PROP_SIM_ID,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingGsmPrivate,
                                              sim_id,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingGsm:sim-operator-id:
     *
     * A MCC/MNC string like "310260" or "21601" identifying the specific
     * mobile network operator which this connection applies to.  If given,
     * the connection will apply to any device also allowed by
     * #NMSettingGsm:device-id and #NMSettingGsm:sim-id which contains a SIM
     * card provisioned by the given operator.
     *
     * Since: 1.2
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_SIM_OPERATOR_ID,
                                              PROP_SIM_OPERATOR_ID,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingGsmPrivate,
                                              sim_operator_id,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingGsm:mtu:
     *
     * If non-zero, only transmit packets of the specified size or smaller,
     * breaking larger packets up into multiple frames.
     *
     * Since: 1.8
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_MTU,
                                              PROP_MTU,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingGsmPrivate,
                                              mtu);

    /**
     * NMSettingGsm:initial-eps-bearer-configure:
     *
     * For LTE modems, this setting determines whether the initial EPS bearer
     * shall be configured when bringing up the connection.  It is inferred TRUE
     * if initial-eps-bearer-apn is set.
     *
     * Since: 1.44
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_GSM_INITIAL_EPS_BEARER_CONFIGURE,
                                               PROP_INITIAL_EPS_CONFIG,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingGsmPrivate,
                                               initial_eps_config);

    /**
     * NMSettingGsm:initial-eps-bearer-apn:
     *
     * For LTE modems, this sets the APN for the initial EPS bearer that is set
     * up when attaching to the network.  Setting this parameter implies
     * initial-eps-bearer-configure to be TRUE.
     *
     * Since: 1.44
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_INITIAL_EPS_BEARER_APN,
                                              PROP_INITIAL_EPS_APN,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingGsmPrivate,
                                              initial_eps_apn,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingGsm:initial-eps-bearer-username:
     *
     * For LTE modems, this sets the username for the initial EPS bearer that is set
     * up when attaching to the network.  Setting this parameter implies
     * initial-eps-bearer-configure to be TRUE.
     *
     * Since: 1.52
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_INITIAL_EPS_BEARER_USERNAME,
                                              PROP_INITIAL_EPS_USERNAME,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingGsmPrivate,
                                              initial_eps_username,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingGsm:initial-eps-bearer-password:
     *
     * For LTE modems, this sets the password for the initial EPS bearer that is set
     * up when attaching to the network.  Setting this parameter implies
     * initial-eps-bearer-configure to be TRUE.
     *
     * Since: 1.52
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_INITIAL_EPS_BEARER_PASSWORD,
                                              PROP_INITIAL_EPS_PASSWORD,
                                              NM_SETTING_PARAM_SECRET,
                                              NMSettingGsmPrivate,
                                              initial_eps_password,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingGsm:initial-eps-bearer-password-flags:
     *
     * Flags indicating how to handle the #NMSettingGsm:initial-eps-bearer-password property.
     *
     * Since: 1.52
     **/
    _nm_setting_property_define_direct_secret_flags(
        properties_override,
        obj_properties,
        NM_SETTING_GSM_INITIAL_EPS_BEARER_PASSWORD_FLAGS,
        PROP_INITIAL_EPS_PASSWORD_FLAGS,
        NMSettingGsmPrivate,
        initial_eps_password_flags);

    /**
     * NMSettingGsm:initial-eps-bearer-noauth:
     *
     * For LTE modems, this sets NOAUTH authentication method for the initial EPS bearer that is set
     * up when attaching to the network.
     * If %TRUE, do not require the other side to authenticate itself to the client.
     * If %FALSE, require authentication from the remote side.  In almost all cases,
     * this should be %TRUE.
     *
     * Since: 1.52
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_GSM_INITIAL_EPS_BEARER_NOAUTH,
                                               PROP_INITIAL_EPS_NOAUTH,
                                               TRUE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingGsmPrivate,
                                               initial_eps_noauth);

    /**
     * NMSettingGsm:initial-eps-bearer-refuse-eap:
     *
     * For LTE modems, this disables EAP authentication method for the initial EPS bearer that is set
     * up when attaching to the network.
     *
     * Since: 1.52
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_GSM_INITIAL_EPS_BEARER_REFUSE_EAP,
                                               PROP_INITIAL_EPS_REFUSE_EAP,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingGsmPrivate,
                                               initial_eps_refuse_eap);

    /**
     * NMSettingGsm:initial-eps-bearer-refuse-pap:
     *
     * For LTE modems, this disables PAP authentication method for the initial EPS bearer that is set
     * up when attaching to the network.
     *
     * Since: 1.52
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_GSM_INITIAL_EPS_BEARER_REFUSE_PAP,
                                               PROP_INITIAL_EPS_REFUSE_PAP,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingGsmPrivate,
                                               initial_eps_refuse_pap);

    /**
     * NMSettingGsm:initial-eps-bearer-refuse-chap:
     *
     * For LTE modems, this disables CHAP authentication method for the initial EPS bearer that is set
     * up when attaching to the network.
     *
     * Since: 1.52
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_GSM_INITIAL_EPS_BEARER_REFUSE_CHAP,
                                               PROP_INITIAL_EPS_REFUSE_CHAP,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingGsmPrivate,
                                               initial_eps_refuse_chap);

    /**
     * NMSettingGsm:initial-eps-bearer-refuse-mschap:
     *
     * For LTE modems, this disables MSCHAP authentication method for the initial EPS bearer that is set
     * up when attaching to the network.
     *
     * Since: 1.52
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_GSM_INITIAL_EPS_BEARER_REFUSE_MSCHAP,
                                               PROP_INITIAL_EPS_REFUSE_MSCHAP,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingGsmPrivate,
                                               initial_eps_refuse_mschap);

    /**
     * NMSettingGsm:initial-eps-bearer-refuse-mschapv2:
     *
     * For LTE modems, this disables MSCHAPV2 authentication method for the initial EPS bearer that is set
     * up when attaching to the network.
     *
     * Since: 1.52
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_GSM_INITIAL_EPS_BEARER_REFUSE_MSCHAPV2,
                                               PROP_INITIAL_EPS_REFUSE_MSCHAPV2,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingGsmPrivate,
                                               initial_eps_refuse_mschapv2);

    /**
     * NMSettingGsm:device-uid:
     *
     * The device UID (as given by the WWAN management service) which this
     * connection applies to. In contrast to #NMSettingGsm:device-id, which is
     * an inherent property of the connected device, this setting refers to
     * a property set by a UDEV-rule. Refer to the "Common udev tags" ->
     * "ID_MM_PHYSDEV_UID" documentation of ModemManager. If given, the
     * connection will only apply to the specified device.
     *
     * Since: 1.56
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GSM_DEVICE_UID,
                                              PROP_DEVICE_UID,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingGsmPrivate,
                                              device_uid);

    /* Ignore incoming deprecated properties */
    _nm_properties_override_dbus(properties_override,
                                 "allowed-bands",
                                 &nm_sett_info_propert_type_deprecated_ignore_u,
                                 .dbus_deprecated = TRUE, );
    _nm_properties_override_dbus(properties_override,
                                 "network-type",
                                 &nm_sett_info_propert_type_deprecated_ignore_i,
                                 .dbus_deprecated = TRUE, );

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_GSM,
                             NULL,
                             properties_override,
                             G_STRUCT_OFFSET(NMSettingGsm, _priv));
}
