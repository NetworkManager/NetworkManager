/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2009 - 2015 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nms-ifcfg-rh-writer.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#include "nm-glib-aux/nm-enum-utils.h"
#include "nm-glib-aux/nm-io-utils.h"
#include "nm-manager.h"
#include "nm-setting-connection.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-ethtool.h"
#include "nm-setting-8021x.h"
#include "nm-setting-proxy.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-vlan.h"
#include "nm-setting-user.h"
#include "nm-setting-team.h"
#include "nm-setting-team-port.h"
#include "nm-utils.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "NetworkManagerUtils.h"
#include "libnm-base/nm-ethtool-base.h"

#include "nms-ifcfg-rh-common.h"
#include "nms-ifcfg-rh-reader.h"
#include "nms-ifcfg-rh-utils.h"
#include "shvar.h"

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_SETTINGS
#define _NMLOG_PREFIX_NAME "ifcfg-rh"
#define _NMLOG(level, ...)                                                 \
    G_STMT_START                                                           \
    {                                                                      \
        nm_log((level),                                                    \
               (_NMLOG_DOMAIN),                                            \
               NULL,                                                       \
               NULL,                                                       \
               "%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                    \
               _NMLOG_PREFIX_NAME ": " _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    }                                                                      \
    G_STMT_END

/*****************************************************************************/

static void
save_secret_flags(shvarFile *ifcfg, const char *key, NMSettingSecretFlags flags)
{
    GString *str;

    g_return_if_fail(ifcfg != NULL);
    g_return_if_fail(key != NULL);

    if (flags == NM_SETTING_SECRET_FLAG_NONE)
        return;

    /* Convert flags bitfield into string representation */
    str = g_string_sized_new(20);
    if (flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED)
        g_string_append(str, SECRET_FLAG_AGENT);

    if (flags & NM_SETTING_SECRET_FLAG_NOT_SAVED) {
        if (str->len)
            g_string_append_c(str, ' ');
        g_string_append(str, SECRET_FLAG_NOT_SAVED);
    }

    if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED) {
        if (str->len)
            g_string_append_c(str, ' ');
        g_string_append(str, SECRET_FLAG_NOT_REQUIRED);
    }

    svSetValueStr(ifcfg, key, str->len ? str->str : NULL);
    g_string_free(str, TRUE);
}

static void
set_secret(shvarFile *          ifcfg,
           GHashTable *         secrets,
           const char *         key,
           const char *         value,
           const char *         flags_key,
           NMSettingSecretFlags flags)
{
    /* Save secret flags */
    save_secret_flags(ifcfg, flags_key, flags);

    /* Only write the secret if it's system owned and supposed to be saved */
    if (flags != NM_SETTING_SECRET_FLAG_NONE)
        value = NULL;

    g_hash_table_replace(secrets, g_strdup(key), g_strdup(value));
}

static gboolean
write_secrets(shvarFile *ifcfg, GHashTable *secrets, GError **error)
{
    nm_auto_shvar_file_close shvarFile *keyfile = NULL;
    gs_free NMUtilsNamedValue *secrets_arr_free = NULL;
    NMUtilsNamedValue          secrets_arr_static[30];
    const NMUtilsNamedValue *  secrets_arr;
    guint                      secrets_len;
    GError *                   local       = NULL;
    gboolean                   any_secrets = FALSE;
    guint                      i;

    keyfile = utils_get_keys_ifcfg(svFileGetName(ifcfg), TRUE);
    if (!keyfile) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Failure to create secrets file for '%s'",
                    svFileGetName(ifcfg));
        return FALSE;
    }

    secrets_arr = nm_utils_named_values_from_strdict(secrets,
                                                     &secrets_len,
                                                     secrets_arr_static,
                                                     &secrets_arr_free);
    for (i = 0; i < secrets_len; i++) {
        const char *k = secrets_arr[i].name;
        const char *v = secrets_arr[i].value_str;

        if (v) {
            svSetValueStr(keyfile, k, v);
            any_secrets = TRUE;
        }
    }

    if (!any_secrets)
        (void) unlink(svFileGetName(keyfile));
    else if (!svWriteFileWithoutDirtyWellknown(keyfile, 0600, &local)) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Failure to write secrets to '%s': %s",
                    svFileGetName(keyfile),
                    local->message);
        return FALSE;
    }

    return TRUE;
}

typedef struct {
    const NMSetting8021xSchemeVtable *vtable;
    const char *                      ifcfg_rh_key;
} Setting8021xSchemeVtable;

static const Setting8021xSchemeVtable setting_8021x_scheme_vtable[] = {
#define _D(_scheme_type, _ifcfg_rh_key)                                  \
    [(_scheme_type)] = {                                                 \
        .vtable       = &nm_setting_8021x_scheme_vtable[(_scheme_type)], \
        .ifcfg_rh_key = ""_ifcfg_rh_key                                  \
                        "",                                              \
    }
    _D(NM_SETTING_802_1X_SCHEME_TYPE_CA_CERT, "IEEE_8021X_CA_CERT"),
    _D(NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CA_CERT, "IEEE_8021X_INNER_CA_CERT"),
    _D(NM_SETTING_802_1X_SCHEME_TYPE_CLIENT_CERT, "IEEE_8021X_CLIENT_CERT"),
    _D(NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CLIENT_CERT, "IEEE_8021X_INNER_CLIENT_CERT"),
    _D(NM_SETTING_802_1X_SCHEME_TYPE_PRIVATE_KEY, "IEEE_8021X_PRIVATE_KEY"),
    _D(NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_PRIVATE_KEY, "IEEE_8021X_INNER_PRIVATE_KEY"),
#undef _D
};

static gboolean
write_object(NMSetting8021x *                s_8021x,
             shvarFile *                     ifcfg,
             GHashTable *                    secrets,
             GHashTable *                    blobs,
             const Setting8021xSchemeVtable *objtype,
             gboolean                        force_write,
             GError **                       error)
{
    NMSetting8021xCKScheme scheme;
    const char *           value    = NULL;
    GBytes *               blob     = NULL;
    const char *           password = NULL;
    NMSettingSecretFlags   flags    = NM_SETTING_SECRET_FLAG_NONE;
    char                   secret_name[100];
    char                   secret_flags[sizeof(secret_name) + NM_STRLEN("_FLAGS")];
    const char *           extension;
    char *                 standard_file;

    g_return_val_if_fail(ifcfg != NULL, FALSE);
    g_return_val_if_fail(objtype != NULL, FALSE);

    scheme = (*(objtype->vtable->scheme_func))(s_8021x);
    switch (scheme) {
    case NM_SETTING_802_1X_CK_SCHEME_UNKNOWN:
        break;
    case NM_SETTING_802_1X_CK_SCHEME_BLOB:
        blob = (*(objtype->vtable->blob_func))(s_8021x);
        break;
    case NM_SETTING_802_1X_CK_SCHEME_PATH:
        value = (*(objtype->vtable->path_func))(s_8021x);
        break;
    case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
        value = (*(objtype->vtable->uri_func))(s_8021x);
        break;
    default:
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Unhandled certificate object scheme");
        return FALSE;
    }

    /* Set the password for certificate/private key. */
    nm_sprintf_buf(secret_name, "%s_PASSWORD", objtype->ifcfg_rh_key);
    nm_sprintf_buf(secret_flags, "%s_PASSWORD_FLAGS", objtype->ifcfg_rh_key);
    password = (*(objtype->vtable->passwd_func))(s_8021x);
    flags    = (*(objtype->vtable->pwflag_func))(s_8021x);
    set_secret(ifcfg, secrets, secret_name, password, secret_flags, flags);

    if (!objtype->vtable->format_func)
        extension = "der";
    else if (objtype->vtable->format_func(s_8021x) == NM_SETTING_802_1X_CK_FORMAT_PKCS12)
        extension = "p12";
    else
        extension = "pem";

    /* If the object path was specified, prefer that over any raw cert data that
     * may have been sent.
     */
    if (value) {
        svSetValueStr(ifcfg, objtype->ifcfg_rh_key, value);
        return TRUE;
    }

    /* If it's raw certificate data, write the data out to the standard file */
    if (blob) {
        char *new_file;

        new_file = utils_cert_path(svFileGetName(ifcfg), objtype->vtable->file_suffix, extension);
        g_hash_table_replace(blobs, new_file, g_bytes_ref(blob));
        svSetValueStr(ifcfg, objtype->ifcfg_rh_key, new_file);
        return TRUE;
    }

    /* If certificate/private key wasn't sent, the connection may no longer be
     * 802.1x and thus we clear out the paths and certs.
     *
     * Since no cert/private key is now being used, delete any standard file
     * that was created for this connection, but leave other files alone.
     * Thus, for example,
     * /etc/sysconfig/network-scripts/ca-cert-Test_Write_Wifi_WPA_EAP-TLS.der
     * will be deleted, but /etc/pki/tls/cert.pem will not.
     */
    standard_file = utils_cert_path(svFileGetName(ifcfg), objtype->vtable->file_suffix, extension);
    g_hash_table_replace(blobs, standard_file, NULL);
    svSetValue(ifcfg, objtype->ifcfg_rh_key, force_write ? "" : NULL);
    return TRUE;
}

static gboolean
write_blobs(GHashTable *blobs, GError **error)
{
    GHashTableIter iter;
    const char *   filename;
    GBytes *       blob;

    if (!blobs)
        return TRUE;

    g_hash_table_iter_init(&iter, blobs);
    while (g_hash_table_iter_next(&iter, (gpointer *) &filename, (gpointer *) &blob)) {
        GError *write_error = NULL;

        if (!blob) {
            (void) unlink(filename);
            continue;
        }

        /* Write the raw certificate data out to the standard file so that we
         * can use paths from now on instead of pushing around the certificate
         * data itself.
         */
        if (!nm_utils_file_set_contents(filename,
                                        (const char *) g_bytes_get_data(blob, NULL),
                                        g_bytes_get_size(blob),
                                        0600,
                                        NULL,
                                        &write_error)) {
            g_set_error(error,
                        NM_SETTINGS_ERROR,
                        NM_SETTINGS_ERROR_FAILED,
                        "Could not write certificate to file \"%s\": %s",
                        filename,
                        write_error->message);
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
write_8021x_certs(NMSetting8021x *s_8021x,
                  GHashTable *    secrets,
                  GHashTable *    blobs,
                  gboolean        phase2,
                  shvarFile *     ifcfg,
                  GError **       error)
{
    const Setting8021xSchemeVtable *pk_otype      = NULL;
    gs_free char *                  value_to_free = NULL;

    /* CA certificate */
    if (!write_object(
            s_8021x,
            ifcfg,
            secrets,
            blobs,
            phase2 ? &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CA_CERT]
                   : &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_CA_CERT],
            FALSE,
            error))
        return FALSE;

    /* Private key */
    if (phase2)
        pk_otype = &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_PRIVATE_KEY];
    else
        pk_otype = &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PRIVATE_KEY];

    /* Save the private key */
    if (!write_object(s_8021x, ifcfg, secrets, blobs, pk_otype, FALSE, error))
        return FALSE;

    /* Save the client certificate.
     * If there is a private key, always write a property for the
     * client certificate even if it is empty, so that the reader
     * doesn't have to read the private key file to determine if it
     * is a PKCS #12 one which serves also as client certificate.
     */
    if (!write_object(
            s_8021x,
            ifcfg,
            secrets,
            blobs,
            phase2 ? &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CLIENT_CERT]
                   : &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_CLIENT_CERT],
            !!svGetValue(ifcfg, pk_otype->ifcfg_rh_key, &value_to_free),
            error))
        return FALSE;

    return TRUE;
}

static gboolean
write_8021x_setting(NMConnection *connection,
                    shvarFile *   ifcfg,
                    GHashTable *  secrets,
                    GHashTable *  blobs,
                    gboolean      wired,
                    GError **     error)
{
    NMSetting8021x *        s_8021x;
    NMSetting8021xAuthFlags auth_flags;
    const char *            value, *match;
    gconstpointer           ptr;
    GBytes *                bytes;
    char *                  tmp = NULL;
    GString *               phase2_auth;
    GString *               str;
    guint32                 i, num;
    gsize                   size;
    int                     vint;

    s_8021x = nm_connection_get_setting_802_1x(connection);
    if (!s_8021x)
        return TRUE;

    /* If wired, write KEY_MGMT */
    if (wired)
        svSetValueStr(ifcfg, "KEY_MGMT", "IEEE8021X");

    /* EAP method */
    if (nm_setting_802_1x_get_num_eap_methods(s_8021x)) {
        value = nm_setting_802_1x_get_eap_method(s_8021x, 0);
        if (value)
            tmp = g_ascii_strup(value, -1);
    }
    svSetValueStr(ifcfg, "IEEE_8021X_EAP_METHODS", tmp);
    g_free(tmp);

    svSetValueStr(ifcfg, "IEEE_8021X_IDENTITY", nm_setting_802_1x_get_identity(s_8021x));

    svSetValueStr(ifcfg,
                  "IEEE_8021X_ANON_IDENTITY",
                  nm_setting_802_1x_get_anonymous_identity(s_8021x));

    set_secret(ifcfg,
               secrets,
               "IEEE_8021X_PASSWORD",
               nm_setting_802_1x_get_password(s_8021x),
               "IEEE_8021X_PASSWORD_FLAGS",
               nm_setting_802_1x_get_password_flags(s_8021x));

    tmp   = NULL;
    bytes = nm_setting_802_1x_get_password_raw(s_8021x);
    if (bytes) {
        ptr = g_bytes_get_data(bytes, &size);
        tmp = nm_utils_bin2hexstr(ptr, size, -1);
    }
    set_secret(ifcfg,
               secrets,
               "IEEE_8021X_PASSWORD_RAW",
               tmp,
               "IEEE_8021X_PASSWORD_RAW_FLAGS",
               nm_setting_802_1x_get_password_raw_flags(s_8021x));
    g_free(tmp);

    svSetValueBoolean_cond_true(ifcfg,
                                "IEEE_8021X_SYSTEM_CA_CERTS",
                                nm_setting_802_1x_get_system_ca_certs(s_8021x));

    value = nm_setting_802_1x_get_phase1_peapver(s_8021x);
    svSetValueStr(ifcfg, "IEEE_8021X_PEAP_VERSION", value);

    svSetValueBoolean_cond_true(ifcfg,
                                "IEEE_8021X_PEAP_FORCE_NEW_LABEL",
                                nm_streq0(nm_setting_802_1x_get_phase1_peaplabel(s_8021x), "1"));

    svSetValueStr(ifcfg, "IEEE_8021X_PAC_FILE", nm_setting_802_1x_get_pac_file(s_8021x));

    /* FAST PAC provisioning */
    value = nm_setting_802_1x_get_phase1_fast_provisioning(s_8021x);
    if (value) {
        if (strcmp(value, "1") == 0)
            value = "allow-unauth";
        else if (strcmp(value, "2") == 0)
            value = "allow-auth";
        else if (strcmp(value, "3") == 0)
            value = "allow-unauth allow-auth";
        else
            value = NULL;
    }
    svSetValueStr(ifcfg, "IEEE_8021X_FAST_PROVISIONING", value);

    /* Phase2 auth methods */
    phase2_auth = g_string_new(NULL);

    value = nm_setting_802_1x_get_phase2_auth(s_8021x);
    if (value) {
        tmp = g_ascii_strup(value, -1);
        g_string_append(phase2_auth, tmp);
        g_free(tmp);
    }

    value = nm_setting_802_1x_get_phase2_autheap(s_8021x);
    if (value) {
        if (phase2_auth->len)
            g_string_append_c(phase2_auth, ' ');

        tmp = g_ascii_strup(value, -1);
        g_string_append_printf(phase2_auth, "EAP-%s", tmp);
        g_free(tmp);
    }

    auth_flags = nm_setting_802_1x_get_phase1_auth_flags(s_8021x);
    if (auth_flags != NM_SETTING_802_1X_AUTH_FLAGS_NONE) {
        svSetValueEnum(ifcfg,
                       "IEEE_8021X_PHASE1_AUTH_FLAGS",
                       nm_setting_802_1x_auth_flags_get_type(),
                       auth_flags);
    }

    svSetValueStr(ifcfg,
                  "IEEE_8021X_INNER_AUTH_METHODS",
                  phase2_auth->len ? phase2_auth->str : NULL);

    g_string_free(phase2_auth, TRUE);

    svSetValueStr(ifcfg, "IEEE_8021X_SUBJECT_MATCH", nm_setting_802_1x_get_subject_match(s_8021x));

    svSetValueStr(ifcfg,
                  "IEEE_8021X_PHASE2_SUBJECT_MATCH",
                  nm_setting_802_1x_get_phase2_subject_match(s_8021x));

    str = g_string_new(NULL);
    num = nm_setting_802_1x_get_num_altsubject_matches(s_8021x);
    for (i = 0; i < num; i++) {
        if (i > 0)
            g_string_append_c(str, ' ');
        match = nm_setting_802_1x_get_altsubject_match(s_8021x, i);
        g_string_append(str, match);
    }
    if (str->len > 0)
        svSetValueStr(ifcfg, "IEEE_8021X_ALTSUBJECT_MATCHES", str->str);
    g_string_free(str, TRUE);

    str = g_string_new(NULL);
    num = nm_setting_802_1x_get_num_phase2_altsubject_matches(s_8021x);
    for (i = 0; i < num; i++) {
        if (i > 0)
            g_string_append_c(str, ' ');
        match = nm_setting_802_1x_get_phase2_altsubject_match(s_8021x, i);
        g_string_append(str, match);
    }
    if (str->len > 0)
        svSetValueStr(ifcfg, "IEEE_8021X_PHASE2_ALTSUBJECT_MATCHES", str->str);
    g_string_free(str, TRUE);

    svSetValueStr(ifcfg,
                  "IEEE_8021X_DOMAIN_SUFFIX_MATCH",
                  nm_setting_802_1x_get_domain_suffix_match(s_8021x));
    svSetValueStr(ifcfg,
                  "IEEE_8021X_PHASE2_DOMAIN_SUFFIX_MATCH",
                  nm_setting_802_1x_get_phase2_domain_suffix_match(s_8021x));

    svSetValueStr(ifcfg, "IEEE_8021X_DOMAIN_MATCH", nm_setting_802_1x_get_domain_match(s_8021x));
    svSetValueStr(ifcfg,
                  "IEEE_8021X_PHASE2_DOMAIN_MATCH",
                  nm_setting_802_1x_get_phase2_domain_match(s_8021x));

    vint = nm_setting_802_1x_get_auth_timeout(s_8021x);
    svSetValueInt64_cond(ifcfg, "IEEE_8021X_AUTH_TIMEOUT", vint > 0, vint);

    svSetValueBoolean_cond_true(ifcfg,
                                "IEEE_8021X_OPTIONAL",
                                nm_setting_802_1x_get_optional(s_8021x));

    svSetValue(ifcfg, "IEEE_8021X_CA_PATH", nm_setting_802_1x_get_ca_path(s_8021x));
    svSetValue(ifcfg, "IEEE_8021X_PHASE2_CA_PATH", nm_setting_802_1x_get_phase2_ca_path(s_8021x));

    set_secret(ifcfg,
               secrets,
               "IEEE_8021X_PIN",
               nm_setting_802_1x_get_pin(s_8021x),
               "IEEE_8021X_PIN_FLAGS",
               nm_setting_802_1x_get_pin_flags(s_8021x));

    if (!write_8021x_certs(s_8021x, secrets, blobs, FALSE, ifcfg, error))
        return FALSE;

    /* phase2/inner certs */
    if (!write_8021x_certs(s_8021x, secrets, blobs, TRUE, ifcfg, error))
        return FALSE;

    return TRUE;
}

static gboolean
write_wireless_security_setting(NMConnection *connection,
                                shvarFile *   ifcfg,
                                GHashTable *  secrets,
                                gboolean      adhoc,
                                gboolean *    no_8021x,
                                GError **     error)
{
    NMSettingWirelessSecurity *        s_wsec;
    const char *                       key_mgmt, *auth_alg, *key, *proto, *cipher;
    const char *                       psk = NULL;
    gboolean                           wep = FALSE, wpa = FALSE, dynamic_wep = FALSE;
    NMSettingWirelessSecurityWpsMethod wps_method;
    char *                             tmp;
    guint32                            i, num;
    GString *                          str;

    s_wsec = nm_connection_get_setting_wireless_security(connection);
    if (!s_wsec) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Missing '%s' setting",
                    NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
        return FALSE;
    }

    key_mgmt = nm_setting_wireless_security_get_key_mgmt(s_wsec);
    nm_assert(key_mgmt);

    auth_alg = nm_setting_wireless_security_get_auth_alg(s_wsec);

    if (!strcmp(key_mgmt, "none")) {
        wep       = TRUE;
        *no_8021x = TRUE;
    } else if (!strcmp(key_mgmt, "wpa-psk")) {
        svSetValueStr(ifcfg, "KEY_MGMT", "WPA-PSK");
        wpa       = TRUE;
        *no_8021x = TRUE;
    } else if (!strcmp(key_mgmt, "sae")) {
        svSetValueStr(ifcfg, "KEY_MGMT", "SAE");
        wpa       = TRUE;
        *no_8021x = TRUE;
    } else if (!strcmp(key_mgmt, "owe")) {
        svSetValueStr(ifcfg, "KEY_MGMT", "OWE");
        wpa       = FALSE;
        *no_8021x = TRUE;
    } else if (!strcmp(key_mgmt, "ieee8021x")) {
        svSetValueStr(ifcfg, "KEY_MGMT", "IEEE8021X");
        dynamic_wep = TRUE;
    } else if (!strcmp(key_mgmt, "wpa-eap")) {
        svSetValueStr(ifcfg, "KEY_MGMT", "WPA-EAP");
        wpa = TRUE;
    } else if (!strcmp(key_mgmt, "wpa-eap-suite-b-192")) {
        svSetValueStr(ifcfg, "KEY_MGMT", "WPA-EAP-SUITE-B-192");
        wpa = TRUE;
    }

    if (auth_alg) {
        if (!strcmp(auth_alg, "shared"))
            svSetValueStr(ifcfg, "SECURITYMODE", "restricted");
        else if (!strcmp(auth_alg, "open"))
            svSetValueStr(ifcfg, "SECURITYMODE", "open");
        else if (!strcmp(auth_alg, "leap")) {
            svSetValueStr(ifcfg, "SECURITYMODE", "leap");
            svSetValueStr(ifcfg,
                          "IEEE_8021X_IDENTITY",
                          nm_setting_wireless_security_get_leap_username(s_wsec));
            set_secret(ifcfg,
                       secrets,
                       "IEEE_8021X_PASSWORD",
                       nm_setting_wireless_security_get_leap_password(s_wsec),
                       "IEEE_8021X_PASSWORD_FLAGS",
                       nm_setting_wireless_security_get_leap_password_flags(s_wsec));
            *no_8021x = TRUE;
        }
    }

    wps_method = nm_setting_wireless_security_get_wps_method(s_wsec);
    if (wps_method != NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT)
        svSetValueEnum(ifcfg,
                       "WPS_METHOD",
                       nm_setting_wireless_security_wps_method_get_type(),
                       wps_method);

    /* WEP keys */

    /* Clear any default key */
    set_secret(ifcfg, secrets, "KEY", NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE);

    /* Clear existing keys */
    for (i = 0; i < 4; i++) {
        char tag[64];

        numbered_tag(tag, "KEY_PASSPHRASE", i + 1);
        set_secret(ifcfg, secrets, tag, NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE);

        numbered_tag(tag, "KEY", i + 1);
        set_secret(ifcfg, secrets, tag, NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE);
    }

    /* And write the new ones out */
    if (wep) {
        NMWepKeyType key_type;
        const char * key_type_str = NULL;

        /* Default WEP TX key index */
        svSetValueInt64(ifcfg,
                        "DEFAULTKEY",
                        nm_setting_wireless_security_get_wep_tx_keyidx(s_wsec) + 1);

        key_type = nm_setting_wireless_security_get_wep_key_type(s_wsec);
        switch (key_type) {
        case NM_WEP_KEY_TYPE_KEY:
            key_type_str = "key";
            break;
        case NM_WEP_KEY_TYPE_PASSPHRASE:
            key_type_str = "passphrase";
            break;
        case NM_WEP_KEY_TYPE_UNKNOWN:
            break;
        }
        svSetValue(ifcfg, "KEY_TYPE", key_type_str);

        for (i = 0; i < 4; i++) {
            key = nm_setting_wireless_security_get_wep_key(s_wsec, i);
            if (key) {
                gs_free char *ascii_key = NULL;
                char          tag[64];
                gboolean      key_valid = TRUE;

                /* Passphrase needs a different ifcfg key since with WEP, there
                 * are some passphrases that are indistinguishable from WEP hex
                 * keys.
                 */
                if (key_type == NM_WEP_KEY_TYPE_UNKNOWN) {
                    if (nm_utils_wep_key_valid(key, NM_WEP_KEY_TYPE_KEY))
                        key_type = NM_WEP_KEY_TYPE_KEY;
                    else if (nm_utils_wep_key_valid(key, NM_WEP_KEY_TYPE_PASSPHRASE))
                        key_type = NM_WEP_KEY_TYPE_PASSPHRASE;
                }

                if (key_type == NM_WEP_KEY_TYPE_PASSPHRASE)
                    numbered_tag(tag, "KEY_PASSPHRASE", i + 1);
                else if (key_type == NM_WEP_KEY_TYPE_KEY) {
                    numbered_tag(tag, "KEY", i + 1);

                    /* Add 's:' prefix for ASCII keys */
                    if (strlen(key) == 5 || strlen(key) == 13) {
                        ascii_key = g_strdup_printf("s:%s", key);
                        key       = ascii_key;
                    }
                } else {
                    g_warn_if_reached();
                    key_valid = FALSE;
                }

                if (key_valid) {
                    set_secret(ifcfg,
                               secrets,
                               tag,
                               key,
                               "WEP_KEY_FLAGS",
                               nm_setting_wireless_security_get_wep_key_flags(s_wsec));
                }
            }
        }
    }

    /* WPA protos */
    num = nm_setting_wireless_security_get_num_protos(s_wsec);
    for (i = 0; i < num; i++) {
        proto = nm_setting_wireless_security_get_proto(s_wsec, i);
        if (proto && !strcmp(proto, "wpa"))
            svSetValueStr(ifcfg, "WPA_ALLOW_WPA", "yes");
        else if (proto && !strcmp(proto, "rsn"))
            svSetValueStr(ifcfg, "WPA_ALLOW_WPA2", "yes");
    }

    /* WPA Pairwise ciphers */
    str = g_string_new(NULL);
    num = nm_setting_wireless_security_get_num_pairwise(s_wsec);
    for (i = 0; i < num; i++) {
        if (i > 0)
            g_string_append_c(str, ' ');
        cipher = nm_setting_wireless_security_get_pairwise(s_wsec, i);

        /* Don't write out WEP40 or WEP104 if for some reason they are set; they
         * are not valid pairwise ciphers.
         */
        if (strcmp(cipher, "wep40") && strcmp(cipher, "wep104")) {
            tmp = g_ascii_strup(cipher, -1);
            g_string_append(str, tmp);
            g_free(tmp);
        }
    }
    if (strlen(str->str) && (dynamic_wep == FALSE))
        svSetValueStr(ifcfg, "CIPHER_PAIRWISE", str->str);
    g_string_free(str, TRUE);

    /* WPA Group ciphers */
    str = g_string_new(NULL);
    num = nm_setting_wireless_security_get_num_groups(s_wsec);
    for (i = 0; i < num; i++) {
        if (i > 0)
            g_string_append_c(str, ' ');
        cipher = nm_setting_wireless_security_get_group(s_wsec, i);
        tmp    = g_ascii_strup(cipher, -1);
        g_string_append(str, tmp);
        g_free(tmp);
    }
    if (strlen(str->str) && (dynamic_wep == FALSE))
        svSetValueStr(ifcfg, "CIPHER_GROUP", str->str);
    g_string_free(str, TRUE);

    if (wpa)
        psk = nm_setting_wireless_security_get_psk(s_wsec);

    set_secret(ifcfg,
               secrets,
               "WPA_PSK",
               psk,
               "WPA_PSK_FLAGS",
               wpa ? nm_setting_wireless_security_get_psk_flags(s_wsec)
                   : NM_SETTING_SECRET_FLAG_NONE);

    if (nm_setting_wireless_security_get_pmf(s_wsec) != NM_SETTING_WIRELESS_SECURITY_PMF_DEFAULT) {
        svSetValueEnum(ifcfg,
                       "PMF",
                       nm_setting_wireless_security_pmf_get_type(),
                       nm_setting_wireless_security_get_pmf(s_wsec));
    }

    if (nm_setting_wireless_security_get_fils(s_wsec)
        != NM_SETTING_WIRELESS_SECURITY_FILS_DEFAULT) {
        svSetValueEnum(ifcfg,
                       "FILS",
                       nm_setting_wireless_security_fils_get_type(),
                       nm_setting_wireless_security_get_fils(s_wsec));
    }

    return TRUE;
}

static gboolean
write_wireless_setting(NMConnection *connection,
                       shvarFile *   ifcfg,
                       GHashTable *  secrets,
                       gboolean *    no_8021x,
                       GError **     error)
{
    NMSettingWireless *s_wireless;
    GBytes *           ssid;
    const guint8 *     ssid_data;
    gsize              ssid_len;
    const char *       mode, *bssid;
    const char *       device_mac, *cloned_mac;
    guint32            mtu, chan, i;
    gboolean           adhoc = FALSE, hex_ssid = FALSE;
    const char *const *macaddr_blacklist;

    s_wireless = nm_connection_get_setting_wireless(connection);
    if (!s_wireless) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Missing '%s' setting",
                    NM_SETTING_WIRELESS_SETTING_NAME);
        return FALSE;
    }

    device_mac = nm_setting_wireless_get_mac_address(s_wireless);
    svSetValueStr(ifcfg, "HWADDR", device_mac);

    cloned_mac = nm_setting_wireless_get_cloned_mac_address(s_wireless);
    svSetValueStr(ifcfg, "MACADDR", cloned_mac);

    svSetValueStr(ifcfg,
                  "GENERATE_MAC_ADDRESS_MASK",
                  nm_setting_wireless_get_generate_mac_address_mask(s_wireless));

    macaddr_blacklist = nm_setting_wireless_get_mac_address_blacklist(s_wireless);
    if (macaddr_blacklist[0]) {
        gs_free char *blacklist_str = NULL;

        blacklist_str = g_strjoinv(" ", (char **) macaddr_blacklist);
        svSetValueStr(ifcfg, "HWADDR_BLACKLIST", blacklist_str);
    }

    mtu = nm_setting_wireless_get_mtu(s_wireless);
    svSetValueInt64_cond(ifcfg, "MTU", mtu != 0, mtu);

    ssid = nm_setting_wireless_get_ssid(s_wireless);
    if (!ssid) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Missing SSID in '%s' setting",
                    NM_SETTING_WIRELESS_SETTING_NAME);
        return FALSE;
    }
    ssid_data = g_bytes_get_data(ssid, &ssid_len);
    if (!ssid_len || ssid_len > 32) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Invalid SSID in '%s' setting",
                    NM_SETTING_WIRELESS_SETTING_NAME);
        return FALSE;
    }

    /* If the SSID contains any non-printable characters, we need to use the
     * hex notation of the SSID instead.
     */
    if (ssid_len > 2 && ssid_data[0] == '0' && ssid_data[1] == 'x') {
        hex_ssid = TRUE;
        for (i = 2; i < ssid_len; i++) {
            if (!g_ascii_isxdigit(ssid_data[i])) {
                hex_ssid = FALSE;
                break;
            }
        }
    }
    if (!hex_ssid) {
        for (i = 0; i < ssid_len; i++) {
            if (!g_ascii_isprint(ssid_data[i])) {
                hex_ssid = TRUE;
                break;
            }
        }
    }

    if (hex_ssid) {
        GString *str;

        /* Hex SSIDs don't get quoted */
        str = g_string_sized_new(ssid_len * 2 + 3);
        g_string_append(str, "0x");
        for (i = 0; i < ssid_len; i++)
            g_string_append_printf(str, "%02X", ssid_data[i]);
        svSetValueStr(ifcfg, "ESSID", str->str);
        g_string_free(str, TRUE);
    } else {
        char buf[33];

        nm_assert(ssid_len <= 32);
        memcpy(buf, ssid_data, ssid_len);
        buf[ssid_len] = '\0';
        svSetValueStr(ifcfg, "ESSID", buf);
    }

    mode = nm_setting_wireless_get_mode(s_wireless);
    if (!mode) {
        /* pass */
    } else if (nm_streq(mode, NM_SETTING_WIRELESS_MODE_INFRA))
        svSetValueStr(ifcfg, "MODE", "Managed");
    else if (nm_streq(mode, NM_SETTING_WIRELESS_MODE_ADHOC)) {
        svSetValueStr(ifcfg, "MODE", "Ad-Hoc");
        adhoc = TRUE;
    } else if (nm_streq(mode, NM_SETTING_WIRELESS_MODE_AP))
        svSetValueStr(ifcfg, "MODE", "Ap");
    else {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Invalid mode '%s' in '%s' setting",
                    mode,
                    NM_SETTING_WIRELESS_SETTING_NAME);
        return FALSE;
    }

    chan = nm_setting_wireless_get_channel(s_wireless);
    if (chan) {
        svSetValueInt64(ifcfg, "CHANNEL", chan);
    } else {
        /* Band only set if channel is not, since channel implies band */
        svSetValueStr(ifcfg, "BAND", nm_setting_wireless_get_band(s_wireless));
    }

    bssid = nm_setting_wireless_get_bssid(s_wireless);
    svSetValueStr(ifcfg, "BSSID", bssid);

    /* Ensure DEFAULTKEY and SECURITYMODE are cleared unless there's security;
     * otherwise there's no way to detect WEP vs. open when WEP keys aren't
     * saved.
     */

    if (nm_connection_get_setting_wireless_security(connection)) {
        if (!write_wireless_security_setting(connection, ifcfg, secrets, adhoc, no_8021x, error))
            return FALSE;
    } else {
        /* Clear out wifi security keys */
        set_secret(ifcfg,
                   secrets,
                   "IEEE_8021X_PASSWORD",
                   NULL,
                   "IEEE_8021X_PASSWORD_FLAGS",
                   NM_SETTING_SECRET_FLAG_NONE);

        /* Clear existing keys */
        set_secret(ifcfg, secrets, "KEY", NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE);
        for (i = 0; i < 4; i++) {
            char tag[64];

            numbered_tag(tag, "KEY_PASSPHRASE", i + 1);
            set_secret(ifcfg, secrets, tag, NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE);

            numbered_tag(tag, "KEY", i + 1);
            set_secret(ifcfg, secrets, tag, NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE);
        }

        set_secret(ifcfg, secrets, "WPA_PSK", NULL, "WPA_PSK_FLAGS", NM_SETTING_SECRET_FLAG_NONE);
    }

    svSetValueStr(ifcfg, "SSID_HIDDEN", nm_setting_wireless_get_hidden(s_wireless) ? "yes" : NULL);

    switch (nm_setting_wireless_get_powersave(s_wireless)) {
    case NM_SETTING_WIRELESS_POWERSAVE_IGNORE:
        svSetValueStr(ifcfg, "POWERSAVE", "ignore");
        break;
    case NM_SETTING_WIRELESS_POWERSAVE_DISABLE:
        svSetValueStr(ifcfg, "POWERSAVE", "disable");
        break;
    case NM_SETTING_WIRELESS_POWERSAVE_ENABLE:
        svSetValueStr(ifcfg, "POWERSAVE", "enable");
        break;
    default:
    case NM_SETTING_WIRELESS_POWERSAVE_DEFAULT:
        break;
    }

    switch (nm_setting_wireless_get_mac_address_randomization(s_wireless)) {
    case NM_SETTING_MAC_RANDOMIZATION_NEVER:
        svSetValueStr(ifcfg, "MAC_ADDRESS_RANDOMIZATION", "never");
        break;
    case NM_SETTING_MAC_RANDOMIZATION_ALWAYS:
        svSetValueStr(ifcfg, "MAC_ADDRESS_RANDOMIZATION", "always");
        break;
    case NM_SETTING_MAC_RANDOMIZATION_DEFAULT:
    default:
        svSetValueStr(ifcfg, "MAC_ADDRESS_RANDOMIZATION", "default");
        break;
    }

    svSetValueTernary(ifcfg, "AP_ISOLATION", nm_setting_wireless_get_ap_isolation(s_wireless));

    svSetValueStr(ifcfg, "TYPE", TYPE_WIRELESS);

    return TRUE;
}

static gboolean
write_infiniband_setting(NMConnection *connection, shvarFile *ifcfg, GError **error)
{
    NMSettingInfiniband *s_infiniband;
    const char *         mac, *transport_mode, *parent;
    guint32              mtu;
    int                  p_key;

    s_infiniband = nm_connection_get_setting_infiniband(connection);
    if (!s_infiniband) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Missing '%s' setting",
                    NM_SETTING_INFINIBAND_SETTING_NAME);
        return FALSE;
    }

    mac = nm_setting_infiniband_get_mac_address(s_infiniband);
    svSetValueStr(ifcfg, "HWADDR", mac);

    mtu = nm_setting_infiniband_get_mtu(s_infiniband);
    svSetValueInt64_cond(ifcfg, "MTU", mtu != 0, mtu);

    transport_mode = nm_setting_infiniband_get_transport_mode(s_infiniband);
    svSetValueBoolean(ifcfg, "CONNECTED_MODE", nm_streq(transport_mode, "connected"));

    p_key = nm_setting_infiniband_get_p_key(s_infiniband);
    if (p_key != -1) {
        svSetValueStr(ifcfg, "PKEY", "yes");
        svSetValueInt64(ifcfg, "PKEY_ID", p_key);

        parent = nm_setting_infiniband_get_parent(s_infiniband);
        if (parent)
            svSetValueStr(ifcfg, "PHYSDEV", parent);
    }

    svSetValueStr(ifcfg, "TYPE", TYPE_INFINIBAND);

    return TRUE;
}

static void
write_hostname_setting(NMConnection *connection, shvarFile *ifcfg)
{
    NMSettingHostname *s_hostname;
    NMTernary          t;

    s_hostname = _nm_connection_get_setting(connection, NM_TYPE_SETTING_HOSTNAME);
    if (!s_hostname)
        return;

    svSetValueInt64(ifcfg, "HOSTNAME_PRIORITY", nm_setting_hostname_get_priority(s_hostname));

    t = nm_setting_hostname_get_from_dhcp(s_hostname);
    svSetValueInt64_cond(ifcfg, "HOSTNAME_FROM_DHCP", t != NM_TERNARY_DEFAULT, t);

    t = nm_setting_hostname_get_from_dns_lookup(s_hostname);
    svSetValueInt64_cond(ifcfg, "HOSTNAME_FROM_DNS_LOOKUP", t != NM_TERNARY_DEFAULT, t);

    t = nm_setting_hostname_get_only_from_default(s_hostname);
    svSetValueInt64_cond(ifcfg, "HOSTNAME_ONLY_FROM_DEFAULT", t != NM_TERNARY_DEFAULT, t);
}

static gboolean
write_wired_setting(NMConnection *connection, shvarFile *ifcfg, GError **error)
{
    NMSettingWired *   s_wired;
    const char *const *s390_subchannels;
    guint32            mtu, num_opts, i;
    const char *const *macaddr_blacklist;

    s_wired = nm_connection_get_setting_wired(connection);
    if (!s_wired) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Missing '%s' setting",
                    NM_SETTING_WIRED_SETTING_NAME);
        return FALSE;
    }

    svSetValueStr(ifcfg, "HWADDR", nm_setting_wired_get_mac_address(s_wired));

    svSetValueStr(ifcfg, "MACADDR", nm_setting_wired_get_cloned_mac_address(s_wired));

    svSetValueStr(ifcfg,
                  "GENERATE_MAC_ADDRESS_MASK",
                  nm_setting_wired_get_generate_mac_address_mask(s_wired));

    macaddr_blacklist = nm_setting_wired_get_mac_address_blacklist(s_wired);
    if (macaddr_blacklist[0]) {
        gs_free char *blacklist_str = NULL;

        blacklist_str = g_strjoinv(" ", (char **) macaddr_blacklist);
        svSetValueStr(ifcfg, "HWADDR_BLACKLIST", blacklist_str);
    }

    mtu = nm_setting_wired_get_mtu(s_wired);
    svSetValueInt64_cond(ifcfg, "MTU", mtu != 0, mtu);

    s390_subchannels = nm_setting_wired_get_s390_subchannels(s_wired);

    {
        gs_free char *tmp = NULL;
        gsize         len = NM_PTRARRAY_LEN(s390_subchannels);

        if (len == 2) {
            tmp = g_strdup_printf("%s,%s", s390_subchannels[0], s390_subchannels[1]);
        } else if (len == 3) {
            tmp = g_strdup_printf("%s,%s,%s",
                                  s390_subchannels[0],
                                  s390_subchannels[1],
                                  s390_subchannels[2]);
        }

        svSetValueStr(ifcfg, "SUBCHANNELS", tmp);
    }

    svSetValueStr(ifcfg, "NETTYPE", nm_setting_wired_get_s390_nettype(s_wired));

    svSetValueStr(ifcfg, "PORTNAME", nm_setting_wired_get_s390_option_by_key(s_wired, "portname"));

    svSetValueStr(ifcfg, "CTCPROT", nm_setting_wired_get_s390_option_by_key(s_wired, "ctcprot"));

    num_opts = nm_setting_wired_get_num_s390_options(s_wired);
    if (s390_subchannels && num_opts) {
        nm_auto_free_gstring GString *tmp = NULL;

        for (i = 0; i < num_opts; i++) {
            const char *s390_key, *s390_val;

            nm_setting_wired_get_s390_option(s_wired, i, &s390_key, &s390_val);

            /* portname is handled separately */
            if (NM_IN_STRSET(s390_key, "portname", "ctcprot"))
                continue;

            if (strchr(s390_key, '=')) {
                /* this key cannot be expressed. But after all, it's not valid anyway
                 * and the connection shouldn't even verify. */
                continue;
            }

            if (!tmp)
                tmp = g_string_sized_new(30);
            else
                g_string_append_c(tmp, ' ');
            nm_utils_escaped_tokens_escape_gstr(s390_key, NM_ASCII_SPACES, tmp);
            g_string_append_c(tmp, '=');
            nm_utils_escaped_tokens_escape_gstr(s390_val, NM_ASCII_SPACES, tmp);
        }
        if (tmp)
            svSetValueStr(ifcfg, "OPTIONS", tmp->str);
    }

    svSetValueStr(ifcfg, "TYPE", TYPE_ETHERNET);

    return TRUE;
}

static void
_ethtool_gstring_prepare(GString **str, gboolean *is_first, char cmdline_flag, const char *iface)
{
    if (!*is_first) {
        nm_assert(*str && (*str)->len > 0);
        return;
    }

    if (!*str)
        *str = g_string_sized_new(30);
    else {
        nm_assert((*str)->len > 0);
        g_string_append(*str, " ; ");
    }
    g_string_append_printf(*str, "-%c %s", cmdline_flag, iface);
    *is_first = FALSE;
}

static gboolean
write_ethtool_setting(NMConnection *connection, shvarFile *ifcfg, GError **error)
{
    NMSettingWired *        s_wired;
    NMSettingEthtool *      s_ethtool;
    const char *            duplex;
    guint32                 speed;
    GString *               str = NULL;
    gboolean                auto_negotiate;
    NMSettingWiredWakeOnLan wol;
    const char *            wol_password;

    s_wired   = nm_connection_get_setting_wired(connection);
    s_ethtool = NM_SETTING_ETHTOOL(nm_connection_get_setting(connection, NM_TYPE_SETTING_ETHTOOL));

    if (!s_wired && !s_ethtool)
        return TRUE;

    if (s_wired) {
        auto_negotiate = nm_setting_wired_get_auto_negotiate(s_wired);
        speed          = nm_setting_wired_get_speed(s_wired);
        duplex         = nm_setting_wired_get_duplex(s_wired);

        /* autoneg off + speed 0 + duplex NULL, means we want NM
         * to skip link configuration which is default. So write
         * down link config only if we have auto-negotiate true or
         * a valid value for one among speed and duplex.
         */
        if (auto_negotiate) {
            str = g_string_sized_new(64);
            g_string_printf(str, "autoneg on");
        } else if (speed || duplex) {
            str = g_string_sized_new(64);
            g_string_printf(str, "autoneg off");
        }
        if (speed)
            g_string_append_printf(str, " speed %u", speed);
        if (duplex)
            g_string_append_printf(str, " duplex %s", duplex);

        wol          = nm_setting_wired_get_wake_on_lan(s_wired);
        wol_password = nm_setting_wired_get_wake_on_lan_password(s_wired);

        svSetValue(ifcfg,
                   "ETHTOOL_WAKE_ON_LAN",
                   wol == NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE ? "ignore" : NULL);
        if (!NM_IN_SET(wol,
                       NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE,
                       NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT)) {
            if (!str)
                str = g_string_sized_new(30);
            else
                g_string_append(str, " ");

            g_string_append(str, "wol ");

            if (NM_FLAGS_HAS(wol, NM_SETTING_WIRED_WAKE_ON_LAN_PHY))
                g_string_append(str, "p");
            if (NM_FLAGS_HAS(wol, NM_SETTING_WIRED_WAKE_ON_LAN_UNICAST))
                g_string_append(str, "u");
            if (NM_FLAGS_HAS(wol, NM_SETTING_WIRED_WAKE_ON_LAN_MULTICAST))
                g_string_append(str, "m");
            if (NM_FLAGS_HAS(wol, NM_SETTING_WIRED_WAKE_ON_LAN_BROADCAST))
                g_string_append(str, "b");
            if (NM_FLAGS_HAS(wol, NM_SETTING_WIRED_WAKE_ON_LAN_ARP))
                g_string_append(str, "a");
            if (NM_FLAGS_HAS(wol, NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC))
                g_string_append(str, "g");

            if (!NM_FLAGS_ANY(wol, NM_SETTING_WIRED_WAKE_ON_LAN_ALL))
                g_string_append(str, "d");

            if (wol_password && NM_FLAGS_HAS(wol, NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC))
                g_string_append_printf(str, "s sopass %s", wol_password);
        }
    }

    if (s_ethtool) {
        NMEthtoolID          ethtool_id;
        NMSettingConnection *s_con;
        const char *         iface;
        gboolean             is_first;
        guint32              u32;
        gboolean             b;

        s_con = nm_connection_get_setting_connection(connection);
        if (s_con) {
            iface = nm_setting_connection_get_interface_name(s_con);
            if (iface
                && (!iface[0]
                    || !NM_STRCHAR_ALL(iface,
                                       ch,
                                       (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
                                           || (ch >= '0' && ch <= '9') || NM_IN_SET(ch, '_'))))
                iface = NULL;
        } else
            iface = NULL;
        if (!iface)
            iface = "net0";

        is_first = TRUE;
        for (ethtool_id = _NM_ETHTOOL_ID_FEATURE_FIRST; ethtool_id <= _NM_ETHTOOL_ID_FEATURE_LAST;
             ethtool_id++) {
            nm_assert(nms_ifcfg_rh_utils_get_ethtool_name(ethtool_id));
            if (!nm_setting_option_get_boolean(NM_SETTING(s_ethtool),
                                               nm_ethtool_data[ethtool_id]->optname,
                                               &b))
                continue;

            _ethtool_gstring_prepare(&str, &is_first, 'K', iface);
            g_string_append_c(str, ' ');
            g_string_append(str, nms_ifcfg_rh_utils_get_ethtool_name(ethtool_id));
            g_string_append(str, b ? " on" : " off");
        }

        is_first = TRUE;
        for (ethtool_id = _NM_ETHTOOL_ID_COALESCE_FIRST; ethtool_id <= _NM_ETHTOOL_ID_COALESCE_LAST;
             ethtool_id++) {
            nm_assert(nms_ifcfg_rh_utils_get_ethtool_name(ethtool_id));
            if (!nm_setting_option_get_uint32(NM_SETTING(s_ethtool),
                                              nm_ethtool_data[ethtool_id]->optname,
                                              &u32))
                continue;

            _ethtool_gstring_prepare(&str, &is_first, 'C', iface);
            g_string_append_c(str, ' ');
            g_string_append(str, nms_ifcfg_rh_utils_get_ethtool_name(ethtool_id));
            g_string_append_printf(str, " %" G_GUINT32_FORMAT, u32);
        }

        is_first = TRUE;
        for (ethtool_id = _NM_ETHTOOL_ID_RING_FIRST; ethtool_id <= _NM_ETHTOOL_ID_RING_LAST;
             ethtool_id++) {
            nm_assert(nms_ifcfg_rh_utils_get_ethtool_name(ethtool_id));
            if (!nm_setting_option_get_uint32(NM_SETTING(s_ethtool),
                                              nm_ethtool_data[ethtool_id]->optname,
                                              &u32))
                continue;

            _ethtool_gstring_prepare(&str, &is_first, 'G', iface);
            g_string_append_c(str, ' ');
            g_string_append(str, nms_ifcfg_rh_utils_get_ethtool_name(ethtool_id));
            g_string_append_printf(str, " %" G_GUINT32_FORMAT, u32);
        }
    }

    if (str) {
        svSetValueStr(ifcfg, "ETHTOOL_OPTS", str->str);
        g_string_free(str, TRUE);
    }

    return TRUE;
}

static char *
vlan_priority_maplist_to_stringlist(NMSettingVlan *s_vlan, NMVlanPriorityMap map)
{
    char **strlist;
    char * value;

    if (map == NM_VLAN_INGRESS_MAP)
        g_object_get(G_OBJECT(s_vlan), NM_SETTING_VLAN_INGRESS_PRIORITY_MAP, &strlist, NULL);
    else if (map == NM_VLAN_EGRESS_MAP)
        g_object_get(G_OBJECT(s_vlan), NM_SETTING_VLAN_EGRESS_PRIORITY_MAP, &strlist, NULL);
    else
        return NULL;

    if (strlist[0])
        value = g_strjoinv(",", strlist);
    else
        value = NULL;
    g_strfreev(strlist);

    return value;
}

static gboolean
write_wired_for_virtual(NMConnection *connection, shvarFile *ifcfg)
{
    NMSettingWired *s_wired;
    gboolean        has_wired = FALSE;

    s_wired = nm_connection_get_setting_wired(connection);
    if (s_wired) {
        const char *device_mac, *cloned_mac;
        guint32     mtu;

        has_wired = TRUE;

        device_mac = nm_setting_wired_get_mac_address(s_wired);
        svSetValue(ifcfg, "HWADDR", device_mac ?: "");

        cloned_mac = nm_setting_wired_get_cloned_mac_address(s_wired);
        svSetValueStr(ifcfg, "MACADDR", cloned_mac);

        svSetValueStr(ifcfg,
                      "GENERATE_MAC_ADDRESS_MASK",
                      nm_setting_wired_get_generate_mac_address_mask(s_wired));

        mtu = nm_setting_wired_get_mtu(s_wired);
        svSetValueInt64_cond(ifcfg, "MTU", mtu != 0, mtu);
    }
    return has_wired;
}

static gboolean
write_vlan_setting(NMConnection *connection, shvarFile *ifcfg, gboolean *wired, GError **error)
{
    NMSettingVlan *s_vlan;
    char *         tmp;
    guint32        vlan_flags = 0;
    gsize          s_buf_len;
    char           s_buf[50], *s_buf_ptr;

    s_vlan = nm_connection_get_setting_vlan(connection);
    if (!s_vlan) {
        g_set_error_literal(error,
                            NM_SETTINGS_ERROR,
                            NM_SETTINGS_ERROR_FAILED,
                            "Missing VLAN setting");
        return FALSE;
    }

    svSetValueStr(ifcfg, "VLAN", "yes");
    svSetValueStr(ifcfg, "TYPE", TYPE_VLAN);
    svSetValueStr(ifcfg, "PHYSDEV", nm_setting_vlan_get_parent(s_vlan));
    svSetValueInt64(ifcfg, "VLAN_ID", nm_setting_vlan_get_id(s_vlan));

    vlan_flags = nm_setting_vlan_get_flags(s_vlan);
    svSetValueBoolean(ifcfg, "REORDER_HDR", NM_FLAGS_HAS(vlan_flags, NM_VLAN_FLAG_REORDER_HEADERS));
    svSetValueBoolean(ifcfg, "GVRP", NM_FLAGS_HAS(vlan_flags, NM_VLAN_FLAG_GVRP));

    nm_utils_strbuf_init(s_buf, &s_buf_ptr, &s_buf_len);

    if (NM_FLAGS_HAS(vlan_flags, NM_VLAN_FLAG_LOOSE_BINDING))
        nm_utils_strbuf_append_str(&s_buf_ptr, &s_buf_len, "LOOSE_BINDING");
    if (!NM_FLAGS_HAS(vlan_flags, NM_VLAN_FLAG_REORDER_HEADERS))
        nm_utils_strbuf_append(&s_buf_ptr, &s_buf_len, "%sNO_REORDER_HDR", s_buf[0] ? "," : "");

    svSetValueStr(ifcfg, "VLAN_FLAGS", s_buf);

    svSetValueBoolean(ifcfg, "MVRP", NM_FLAGS_HAS(vlan_flags, NM_VLAN_FLAG_MVRP));

    tmp = vlan_priority_maplist_to_stringlist(s_vlan, NM_VLAN_INGRESS_MAP);
    svSetValueStr(ifcfg, "VLAN_INGRESS_PRIORITY_MAP", tmp);
    g_free(tmp);

    tmp = vlan_priority_maplist_to_stringlist(s_vlan, NM_VLAN_EGRESS_MAP);
    svSetValueStr(ifcfg, "VLAN_EGRESS_PRIORITY_MAP", tmp);
    g_free(tmp);

    *wired = write_wired_for_virtual(connection, ifcfg);

    return TRUE;
}

static gboolean
write_bond_setting(NMConnection *connection, shvarFile *ifcfg, gboolean *wired, GError **error)
{
    NMSettingBond *s_bond;
    guint32        i, num_opts;

    s_bond = nm_connection_get_setting_bond(connection);
    if (!s_bond) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Missing '%s' setting",
                    NM_SETTING_BOND_SETTING_NAME);
        return FALSE;
    }

    num_opts = nm_setting_bond_get_num_options(s_bond);
    if (num_opts) {
        nm_auto_free_gstring GString *str = NULL;
        const char *                  name, *value;

        str = g_string_sized_new(64);
        for (i = 0; i < num_opts; i++) {
            if (str->len)
                g_string_append_c(str, ' ');
            nm_setting_bond_get_option(s_bond, i, &name, &value);
            g_string_append_printf(str, "%s=%s", name, value);
        }

        svSetValueStr(ifcfg, "BONDING_OPTS", str->str);
    }

    svSetValueStr(ifcfg, "TYPE", TYPE_BOND);
    svSetValueStr(ifcfg, "BONDING_MASTER", "yes");

    *wired = write_wired_for_virtual(connection, ifcfg);

    return TRUE;
}

static gboolean
write_team_setting(NMConnection *connection, shvarFile *ifcfg, gboolean *wired, GError **error)
{
    NMSettingTeam *s_team;
    const char *   config;

    s_team = nm_connection_get_setting_team(connection);
    if (!s_team) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Missing '%s' setting",
                    NM_SETTING_TEAM_SETTING_NAME);
        return FALSE;
    }

    config = nm_setting_team_get_config(s_team);
    svSetValueStr(ifcfg, "TEAM_CONFIG", config);

    *wired = write_wired_for_virtual(connection, ifcfg);

    return TRUE;
}

#define get_setting_default_checked_boolean(dflt, setting, prop)                       \
    ({                                                                                 \
        const gboolean _dflt = (dflt);                                                 \
                                                                                       \
        nm_assert(NM_G_PARAM_SPEC_GET_DEFAULT_BOOLEAN(                                 \
                      g_object_class_find_property(G_OBJECT_GET_CLASS(setting), prop)) \
                  == _dflt);                                                           \
        _dflt;                                                                         \
    })

#define get_setting_default_checked_uint(dflt, setting, prop)                          \
    ({                                                                                 \
        const guint _dflt = (dflt);                                                    \
                                                                                       \
        nm_assert(NM_G_PARAM_SPEC_GET_DEFAULT_UINT(                                    \
                      g_object_class_find_property(G_OBJECT_GET_CLASS(setting), prop)) \
                  == _dflt);                                                           \
        _dflt;                                                                         \
    })

#define get_setting_default_checked_uint64(dflt, setting, prop)                        \
    ({                                                                                 \
        const guint64 _dflt = (dflt);                                                  \
                                                                                       \
        nm_assert(NM_G_PARAM_SPEC_GET_DEFAULT_UINT64(                                  \
                      g_object_class_find_property(G_OBJECT_GET_CLASS(setting), prop)) \
                  == _dflt);                                                           \
        _dflt;                                                                         \
    })

static gboolean
write_bridge_vlans(NMSetting * setting,
                   const char *property_name,
                   shvarFile * ifcfg,
                   const char *key,
                   GError **   error)
{
    gs_unref_ptrarray GPtrArray *vlans = NULL;
    NMBridgeVlan *               vlan;
    GString *                    string;
    guint                        i;

    g_object_get(setting, property_name, &vlans, NULL);

    if (!vlans || !vlans->len)
        return TRUE;

    string = g_string_new("");
    for (i = 0; i < vlans->len; i++) {
        gs_free char *vlan_str = NULL;

        vlan     = vlans->pdata[i];
        vlan_str = nm_bridge_vlan_to_str(vlan, error);
        if (!vlan_str)
            return FALSE;
        if (string->len > 0)
            g_string_append(string, ",");
        nm_utils_escaped_tokens_escape_gstr_assert(vlan_str, ",", string);
    }

    svSetValueStr(ifcfg, key, string->str);
    g_string_free(string, TRUE);
    return TRUE;
}

static gboolean
write_bridge_setting(NMConnection *connection, shvarFile *ifcfg, gboolean *wired, GError **error)
{
    NMSettingBridge *s_bridge;
    guint32          u32;
    guint64          u64;
    guint            u;
    gboolean         b;
    const char *     s;
    GString *        opts;

    s_bridge = nm_connection_get_setting_bridge(connection);
    if (!s_bridge) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Missing '%s' setting",
                    NM_SETTING_BRIDGE_SETTING_NAME);
        return FALSE;
    }

    svSetValueBoolean(ifcfg, "STP", FALSE);

    s = nm_setting_bridge_get_mac_address(s_bridge);
    svSetValueStr(ifcfg, "BRIDGE_MACADDR", s);

    /* Bridge options */
    opts = g_string_sized_new(32);

    if (nm_setting_bridge_get_stp(s_bridge)) {
        svSetValueStr(ifcfg, "STP", "yes");

        u32 = nm_setting_bridge_get_forward_delay(s_bridge);
        if (u32
            != get_setting_default_checked_uint(NM_BRIDGE_FORWARD_DELAY_DEF,
                                                s_bridge,
                                                NM_SETTING_BRIDGE_FORWARD_DELAY))
            svSetValueInt64(ifcfg, "DELAY", u32);

        g_string_append_printf(opts, "priority=%u", nm_setting_bridge_get_priority(s_bridge));

        u32 = nm_setting_bridge_get_hello_time(s_bridge);
        if (u32
            != get_setting_default_checked_uint(NM_BRIDGE_HELLO_TIME_DEF,
                                                s_bridge,
                                                NM_SETTING_BRIDGE_HELLO_TIME)) {
            nm_gstring_add_space_delimiter(opts);
            g_string_append_printf(opts, "hello_time=%u", u32);
        }

        u32 = nm_setting_bridge_get_max_age(s_bridge);
        if (u32
            != get_setting_default_checked_uint(NM_BRIDGE_MAX_AGE_DEF,
                                                s_bridge,
                                                NM_SETTING_BRIDGE_MAX_AGE)) {
            nm_gstring_add_space_delimiter(opts);
            g_string_append_printf(opts, "max_age=%u", u32);
        }
    }

    u = nm_setting_bridge_get_ageing_time(s_bridge);
    if (u
        != get_setting_default_checked_uint(NM_BRIDGE_AGEING_TIME_DEF,
                                            s_bridge,
                                            NM_SETTING_BRIDGE_AGEING_TIME)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "ageing_time=%u", u);
    }

    s = nm_setting_bridge_get_group_address(s_bridge);
    if (s) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "group_address=%s", s);
    }

    u32 = nm_setting_bridge_get_group_forward_mask(s_bridge);
    if (u32
        != get_setting_default_checked_uint(0, s_bridge, NM_SETTING_BRIDGE_GROUP_FORWARD_MASK)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "group_fwd_mask=%u", u32);
    }

    u32 = nm_setting_bridge_get_multicast_hash_max(s_bridge);
    if (u32
        != get_setting_default_checked_uint(NM_BRIDGE_MULTICAST_HASH_MAX_DEF,
                                            s_bridge,
                                            NM_SETTING_BRIDGE_MULTICAST_HASH_MAX)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "multicast_hash_max=%u", u32);
    }

    u32 = nm_setting_bridge_get_multicast_last_member_count(s_bridge);
    if (u32
        != get_setting_default_checked_uint(NM_BRIDGE_MULTICAST_LAST_MEMBER_COUNT_DEF,
                                            s_bridge,
                                            NM_SETTING_BRIDGE_MULTICAST_LAST_MEMBER_COUNT)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "multicast_last_member_count=%u", u32);
    }

    u64 = nm_setting_bridge_get_multicast_last_member_interval(s_bridge);
    if (u64
        != get_setting_default_checked_uint64(NM_BRIDGE_MULTICAST_LAST_MEMBER_INTERVAL_DEF,
                                              s_bridge,
                                              NM_SETTING_BRIDGE_MULTICAST_LAST_MEMBER_INTERVAL)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "multicast_last_member_interval=%" G_GUINT64_FORMAT, u64);
    }

    u64 = nm_setting_bridge_get_multicast_membership_interval(s_bridge);
    if (u64
        != get_setting_default_checked_uint64(NM_BRIDGE_MULTICAST_MEMBERSHIP_INTERVAL_DEF,
                                              s_bridge,
                                              NM_SETTING_BRIDGE_MULTICAST_MEMBERSHIP_INTERVAL)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "multicast_membership_interval=%" G_GUINT64_FORMAT, u64);
    }

    b = nm_setting_bridge_get_multicast_querier(s_bridge);
    if (b
        != get_setting_default_checked_boolean(NM_BRIDGE_MULTICAST_QUERIER_DEF,
                                               s_bridge,
                                               NM_SETTING_BRIDGE_MULTICAST_QUERIER)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "multicast_querier=%u", (guint) b);
    }

    u64 = nm_setting_bridge_get_multicast_querier_interval(s_bridge);
    if (u64
        != get_setting_default_checked_uint64(NM_BRIDGE_MULTICAST_QUERIER_INTERVAL_DEF,
                                              s_bridge,
                                              NM_SETTING_BRIDGE_MULTICAST_QUERIER_INTERVAL)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "multicast_querier_interval=%" G_GUINT64_FORMAT, u64);
    }

    u64 = nm_setting_bridge_get_multicast_query_interval(s_bridge);
    if (u64
        != get_setting_default_checked_uint64(NM_BRIDGE_MULTICAST_QUERY_INTERVAL_DEF,
                                              s_bridge,
                                              NM_SETTING_BRIDGE_MULTICAST_QUERY_INTERVAL)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "multicast_query_interval=%" G_GUINT64_FORMAT, u64);
    }

    u64 = nm_setting_bridge_get_multicast_query_response_interval(s_bridge);
    if (u64
        != get_setting_default_checked_uint64(
            NM_BRIDGE_MULTICAST_QUERY_RESPONSE_INTERVAL_DEF,
            s_bridge,
            NM_SETTING_BRIDGE_MULTICAST_QUERY_RESPONSE_INTERVAL)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "multicast_query_response_interval=%" G_GUINT64_FORMAT, u64);
    }

    b = nm_setting_bridge_get_multicast_query_use_ifaddr(s_bridge);
    if (b
        != get_setting_default_checked_boolean(NM_BRIDGE_MULTICAST_QUERY_USE_IFADDR_DEF,
                                               s_bridge,
                                               NM_SETTING_BRIDGE_MULTICAST_QUERY_USE_IFADDR)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "multicast_query_use_ifaddr=%u", (guint) b);
    }

    b = nm_setting_bridge_get_multicast_snooping(s_bridge);
    if (b
        != get_setting_default_checked_boolean(NM_BRIDGE_MULTICAST_SNOOPING_DEF,
                                               s_bridge,
                                               NM_SETTING_BRIDGE_MULTICAST_SNOOPING)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "multicast_snooping=%u", (guint32) b);
    }

    u32 = nm_setting_bridge_get_multicast_startup_query_count(s_bridge);
    if (u32
        != get_setting_default_checked_uint(NM_BRIDGE_MULTICAST_STARTUP_QUERY_COUNT_DEF,
                                            s_bridge,
                                            NM_SETTING_BRIDGE_MULTICAST_STARTUP_QUERY_COUNT)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "multicast_startup_query_count=%u", u32);
    }

    u64 = nm_setting_bridge_get_multicast_startup_query_interval(s_bridge);
    if (u64
        != get_setting_default_checked_uint64(NM_BRIDGE_MULTICAST_STARTUP_QUERY_INTERVAL_DEF,
                                              s_bridge,
                                              NM_SETTING_BRIDGE_MULTICAST_STARTUP_QUERY_INTERVAL)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "multicast_startup_query_interval=%" G_GUINT64_FORMAT, u64);
    }

    s = nm_setting_bridge_get_multicast_router(s_bridge);
    if (s) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "multicast_router=%s", s);
    }

    b = nm_setting_bridge_get_vlan_filtering(s_bridge);
    if (b
        != get_setting_default_checked_boolean(FALSE, s_bridge, NM_SETTING_BRIDGE_VLAN_FILTERING)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "vlan_filtering=%u", (guint32) b);
    }

    u32 = nm_setting_bridge_get_vlan_default_pvid(s_bridge);
    if (u32
        != get_setting_default_checked_uint(NM_BRIDGE_VLAN_DEFAULT_PVID_DEF,
                                            s_bridge,
                                            NM_SETTING_BRIDGE_VLAN_DEFAULT_PVID)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "default_pvid=%u", u32);
    }

    s = nm_setting_bridge_get_vlan_protocol(s_bridge);
    if (s) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "vlan_protocol=%s", s);
    }

    b = nm_setting_bridge_get_vlan_stats_enabled(s_bridge);
    if (b
        != get_setting_default_checked_boolean(NM_BRIDGE_VLAN_STATS_ENABLED_DEF,
                                               s_bridge,
                                               NM_SETTING_BRIDGE_VLAN_STATS_ENABLED)) {
        nm_gstring_add_space_delimiter(opts);
        g_string_append_printf(opts, "vlan_stats_enabled=%u", (guint) b);
    }

    if (opts->len)
        svSetValueStr(ifcfg, "BRIDGING_OPTS", opts->str);
    g_string_free(opts, TRUE);

    if (!write_bridge_vlans((NMSetting *) s_bridge,
                            NM_SETTING_BRIDGE_VLANS,
                            ifcfg,
                            "BRIDGE_VLANS",
                            error))
        return FALSE;

    svSetValueStr(ifcfg, "TYPE", TYPE_BRIDGE);

    *wired = write_wired_for_virtual(connection, ifcfg);

    return TRUE;
}

static gboolean
write_bridge_port_setting(NMConnection *connection, shvarFile *ifcfg, GError **error)
{
    NMSettingBridgePort *s_port;
    guint32              u32;
    GString *            string;

    s_port = nm_connection_get_setting_bridge_port(connection);
    if (!s_port)
        return TRUE;

    /* Bridge options */
    string = g_string_sized_new(32);

    u32 = nm_setting_bridge_port_get_priority(s_port);
    if (u32
        != get_setting_default_checked_uint(NM_BRIDGE_PORT_PRIORITY_DEF,
                                            s_port,
                                            NM_SETTING_BRIDGE_PORT_PRIORITY))
        g_string_append_printf(string, "priority=%u", u32);

    u32 = nm_setting_bridge_port_get_path_cost(s_port);
    if (u32
        != get_setting_default_checked_uint(NM_BRIDGE_PORT_PATH_COST_DEF,
                                            s_port,
                                            NM_SETTING_BRIDGE_PORT_PATH_COST)) {
        if (string->len)
            g_string_append_c(string, ' ');
        g_string_append_printf(string, "path_cost=%u", u32);
    }

    if (nm_setting_bridge_port_get_hairpin_mode(s_port)) {
        if (string->len)
            g_string_append_c(string, ' ');
        g_string_append_printf(string, "hairpin_mode=1");
    }

    if (string->len)
        svSetValueStr(ifcfg, "BRIDGING_OPTS", string->str);
    g_string_free(string, TRUE);

    if (!write_bridge_vlans((NMSetting *) s_port,
                            NM_SETTING_BRIDGE_PORT_VLANS,
                            ifcfg,
                            "BRIDGE_PORT_VLANS",
                            error))
        return FALSE;

    return TRUE;
}

static gboolean
write_team_port_setting(NMConnection *connection, shvarFile *ifcfg, GError **error)
{
    NMSettingTeamPort *s_port;
    const char *       config;

    s_port = nm_connection_get_setting_team_port(connection);
    if (!s_port)
        return TRUE;

    config = nm_setting_team_port_get_config(s_port);
    svSetValueStr(ifcfg, "TEAM_PORT_CONFIG", config);

    return TRUE;
}

static void
write_dcb_flags(shvarFile *ifcfg, const char *tag, NMSettingDcbFlags flags)
{
    char prop[NM_STRLEN("DCB_xxxxxxxxxxxxxxxxxxxxxxx_yyyyyyyyyyyyyyyyyyyy")];

    nm_sprintf_buf(prop, "DCB_%s_ENABLE", tag);
    svSetValueStr(ifcfg, prop, (flags & NM_SETTING_DCB_FLAG_ENABLE) ? "yes" : NULL);

    nm_sprintf_buf(prop, "DCB_%s_ADVERTISE", tag);
    svSetValueStr(ifcfg, prop, (flags & NM_SETTING_DCB_FLAG_ADVERTISE) ? "yes" : NULL);

    nm_sprintf_buf(prop, "DCB_%s_WILLING", tag);
    svSetValueStr(ifcfg, prop, (flags & NM_SETTING_DCB_FLAG_WILLING) ? "yes" : NULL);
}

static void
write_dcb_app(shvarFile *ifcfg, const char *tag, NMSettingDcbFlags flags, int priority)
{
    char prop[NM_STRLEN("DCB_xxxxxxxxxxxxxxxxxxxxxxx_yyyyyyyyyyyyyyyyyyyy")];

    write_dcb_flags(ifcfg, tag, flags);

    if ((flags & NM_SETTING_DCB_FLAG_ENABLE) && (priority >= 0)) {
        nm_sprintf_buf(prop, "DCB_%s_PRIORITY", tag);
        svSetValueInt64(ifcfg, prop, priority);
    }
}

typedef gboolean (*DcbGetBoolFunc)(NMSettingDcb *, guint);

static void
write_dcb_bool_array(shvarFile *       ifcfg,
                     const char *      key,
                     NMSettingDcb *    s_dcb,
                     NMSettingDcbFlags flags,
                     DcbGetBoolFunc    get_func)
{
    char  str[9];
    guint i;

    if (!(flags & NM_SETTING_DCB_FLAG_ENABLE))
        return;

    str[8] = 0;
    for (i = 0; i < 8; i++)
        str[i] = get_func(s_dcb, i) ? '1' : '0';
    svSetValueStr(ifcfg, key, str);
}

typedef guint (*DcbGetUintFunc)(NMSettingDcb *, guint);

static void
write_dcb_uint_array(shvarFile *       ifcfg,
                     const char *      key,
                     NMSettingDcb *    s_dcb,
                     NMSettingDcbFlags flags,
                     DcbGetUintFunc    get_func)
{
    char  str[9];
    guint i, num;

    if (!(flags & NM_SETTING_DCB_FLAG_ENABLE))
        return;

    str[8] = 0;
    for (i = 0; i < 8; i++) {
        num = get_func(s_dcb, i);
        if (num < 10)
            str[i] = '0' + num;
        else if (num == 15)
            str[i] = 'f';
        else
            g_assert_not_reached();
    }
    svSetValueStr(ifcfg, key, str);
}

static void
write_dcb_percent_array(shvarFile *       ifcfg,
                        const char *      key,
                        NMSettingDcb *    s_dcb,
                        NMSettingDcbFlags flags,
                        DcbGetUintFunc    get_func)
{
    GString *str;
    guint    i;

    if (!(flags & NM_SETTING_DCB_FLAG_ENABLE))
        return;

    str = g_string_sized_new(30);
    for (i = 0; i < 8; i++) {
        if (str->len)
            g_string_append_c(str, ',');
        g_string_append_printf(str, "%d", get_func(s_dcb, i));
    }
    svSetValueStr(ifcfg, key, str->str);
    g_string_free(str, TRUE);
}

static gboolean
write_dcb_setting(NMConnection *connection, shvarFile *ifcfg, GError **error)
{
    NMSettingDcb *    s_dcb;
    NMSettingDcbFlags flags;

    s_dcb = nm_connection_get_setting_dcb(connection);
    if (!s_dcb)
        return TRUE;

    svSetValueStr(ifcfg, "DCB", "yes");

    write_dcb_app(ifcfg,
                  "APP_FCOE",
                  nm_setting_dcb_get_app_fcoe_flags(s_dcb),
                  nm_setting_dcb_get_app_fcoe_priority(s_dcb));
    if (nm_setting_dcb_get_app_fcoe_flags(s_dcb) & NM_SETTING_DCB_FLAG_ENABLE)
        svSetValueStr(ifcfg, KEY_DCB_APP_FCOE_MODE, nm_setting_dcb_get_app_fcoe_mode(s_dcb));

    write_dcb_app(ifcfg,
                  "APP_ISCSI",
                  nm_setting_dcb_get_app_iscsi_flags(s_dcb),
                  nm_setting_dcb_get_app_iscsi_priority(s_dcb));
    write_dcb_app(ifcfg,
                  "APP_FIP",
                  nm_setting_dcb_get_app_fip_flags(s_dcb),
                  nm_setting_dcb_get_app_fip_priority(s_dcb));

    write_dcb_flags(ifcfg, "PFC", nm_setting_dcb_get_priority_flow_control_flags(s_dcb));
    write_dcb_bool_array(ifcfg,
                         KEY_DCB_PFC_UP,
                         s_dcb,
                         nm_setting_dcb_get_priority_flow_control_flags(s_dcb),
                         nm_setting_dcb_get_priority_flow_control);

    flags = nm_setting_dcb_get_priority_group_flags(s_dcb);
    write_dcb_flags(ifcfg, "PG", flags);
    write_dcb_uint_array(ifcfg, KEY_DCB_PG_ID, s_dcb, flags, nm_setting_dcb_get_priority_group_id);
    write_dcb_percent_array(ifcfg,
                            KEY_DCB_PG_PCT,
                            s_dcb,
                            flags,
                            nm_setting_dcb_get_priority_group_bandwidth);
    write_dcb_percent_array(ifcfg,
                            KEY_DCB_PG_UPPCT,
                            s_dcb,
                            flags,
                            nm_setting_dcb_get_priority_bandwidth);
    write_dcb_bool_array(ifcfg,
                         KEY_DCB_PG_STRICT,
                         s_dcb,
                         flags,
                         nm_setting_dcb_get_priority_strict_bandwidth);
    write_dcb_uint_array(ifcfg,
                         KEY_DCB_PG_UP2TC,
                         s_dcb,
                         flags,
                         nm_setting_dcb_get_priority_traffic_class);

    return TRUE;
}

static void
write_connection_setting(NMSettingConnection *s_con, shvarFile *ifcfg)
{
    guint32              n, i;
    nm_auto_free_gstring GString *str = NULL;
    const char *                  master, *master_iface = NULL, *type;
    int                           vint;
    gint32                        vint32;
    NMSettingConnectionMdns       mdns;
    NMSettingConnectionLlmnr      llmnr;
    guint32                       vuint32;
    const char *                  tmp, *mud_url;

    svSetValueStr(ifcfg, "NAME", nm_setting_connection_get_id(s_con));
    svSetValueStr(ifcfg, "UUID", nm_setting_connection_get_uuid(s_con));
    svSetValueStr(ifcfg, "STABLE_ID", nm_setting_connection_get_stable_id(s_con));
    svSetValueStr(ifcfg, "DEVICE", nm_setting_connection_get_interface_name(s_con));
    svSetValueBoolean(ifcfg, "ONBOOT", nm_setting_connection_get_autoconnect(s_con));

    vint = nm_setting_connection_get_autoconnect_priority(s_con);
    svSetValueInt64_cond(ifcfg,
                         "AUTOCONNECT_PRIORITY",
                         vint != NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_DEFAULT,
                         vint);

    vint = nm_setting_connection_get_autoconnect_retries(s_con);
    svSetValueInt64_cond(ifcfg, "AUTOCONNECT_RETRIES", vint != -1, vint);

    vint = nm_setting_connection_get_multi_connect(s_con);
    svSetValueInt64_cond(ifcfg, "MULTI_CONNECT", vint != NM_CONNECTION_MULTI_CONNECT_DEFAULT, vint);

    /* Only save the value for master connections */
    type = nm_setting_connection_get_connection_type(s_con);
    if (_nm_connection_type_is_master(type)) {
        NMSettingConnectionAutoconnectSlaves autoconnect_slaves;
        autoconnect_slaves = nm_setting_connection_get_autoconnect_slaves(s_con);
        svSetValueStr(ifcfg,
                      "AUTOCONNECT_SLAVES",
                      autoconnect_slaves == NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_YES  ? "yes"
                      : autoconnect_slaves == NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_NO ? "no"
                                                                                          : NULL);
    }
    switch (nm_setting_connection_get_lldp(s_con)) {
    case NM_SETTING_CONNECTION_LLDP_ENABLE_RX:
        tmp = "rx";
        break;
    case NM_SETTING_CONNECTION_LLDP_DISABLE:
        tmp = "no";
        break;
    default:
        tmp = NULL;
    }
    svSetValueStr(ifcfg, "LLDP", tmp);

    /* Permissions */
    n = nm_setting_connection_get_num_permissions(s_con);
    if (n > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < n; i++) {
            const char *ptype = NULL;
            const char *puser = NULL;

            if (!nm_setting_connection_get_permission(s_con, i, &ptype, &puser, NULL))
                continue;
            if (!nm_streq(ptype, NM_SETTINGS_CONNECTION_PERMISSION_USER))
                continue;

            /* Items separated by space for consistency with eg
             * IPV6ADDR_SECONDARIES and DOMAIN.
             */
            if (str->len)
                g_string_append_c(str, ' ');

            g_string_append(str, puser);
        }
        svSetValueStr(ifcfg, "USERS", str->str);
    }

    svSetValueStr(ifcfg, "ZONE", nm_setting_connection_get_zone(s_con));

    svSetValueStr(ifcfg, "MASTER_UUID", NULL);
    svSetValueStr(ifcfg, "MASTER", NULL);
    svSetValueStr(ifcfg, "SLAVE", NULL);
    svSetValueStr(ifcfg, "BRIDGE_UUID", NULL);
    svSetValueStr(ifcfg, "BRIDGE", NULL);
    svSetValueStr(ifcfg, "TEAM_MASTER_UUID", NULL);
    svSetValueStr(ifcfg, "TEAM_MASTER", NULL);

    mud_url = nm_setting_connection_get_mud_url(s_con);
    svSetValue(ifcfg, "MUD_URL", mud_url);

    master = nm_setting_connection_get_master(s_con);
    if (master) {
        /* The reader prefers the *_UUID variants, however we still try to resolve
         * it into an interface name, so that legacy tooling is not confused. */
        if (!nm_utils_get_testing()) {
            /* This is conditional for easier testing. */
            master_iface = nm_manager_iface_for_uuid(NM_MANAGER_GET, master);
        }
        if (!master_iface) {
            master_iface = master;
            master       = NULL;
        }

        if (nm_setting_connection_is_slave_type(s_con, NM_SETTING_BOND_SETTING_NAME)) {
            svSetValueStr(ifcfg, "MASTER_UUID", master);
            svSetValueStr(ifcfg, "MASTER", master_iface);
            svSetValueStr(ifcfg, "SLAVE", "yes");
        } else if (nm_setting_connection_is_slave_type(s_con, NM_SETTING_BRIDGE_SETTING_NAME)) {
            svSetValueStr(ifcfg, "BRIDGE_UUID", master);
            svSetValueStr(ifcfg, "BRIDGE", master_iface);
        } else if (nm_setting_connection_is_slave_type(s_con, NM_SETTING_TEAM_SETTING_NAME)) {
            svSetValueStr(ifcfg, "TEAM_MASTER_UUID", master);
            svSetValueStr(ifcfg, "TEAM_MASTER", master_iface);
            if (NM_IN_STRSET(type, NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_VLAN_SETTING_NAME))
                svUnsetValue(ifcfg, "TYPE");
        } else if (nm_setting_connection_is_slave_type(s_con, NM_SETTING_OVS_PORT_SETTING_NAME)) {
            svSetValueStr(ifcfg, "OVS_PORT_UUID", master);
            svSetValueStr(ifcfg, "OVS_PORT", master_iface);
        } else if (nm_setting_connection_is_slave_type(s_con, NM_SETTING_VRF_SETTING_NAME)) {
            svSetValueStr(ifcfg, "VRF_UUID", master);
            svSetValueStr(ifcfg, "VRF", master_iface);
        } else {
            _LOGW("don't know how to set master for a %s slave",
                  nm_setting_connection_get_slave_type(s_con));
        }
    }

    if (nm_streq0(type, NM_SETTING_TEAM_SETTING_NAME))
        svSetValueStr(ifcfg, "DEVICETYPE", TYPE_TEAM);
    else if (master_iface
             && nm_setting_connection_is_slave_type(s_con, NM_SETTING_TEAM_SETTING_NAME))
        svSetValueStr(ifcfg, "DEVICETYPE", TYPE_TEAM_PORT);

    /* secondary connection UUIDs */
    n = nm_setting_connection_get_num_secondaries(s_con);
    if (n > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < n; i++) {
            const char *uuid;

            /* Items separated by space for consistency with eg
             * IPV6ADDR_SECONDARIES and DOMAIN.
             */
            if (!(uuid = nm_setting_connection_get_secondary(s_con, i)))
                continue;

            if (str->len)
                g_string_append_c(str, ' ');
            g_string_append(str, uuid);
        }
        svSetValueStr(ifcfg, "SECONDARY_UUIDS", str->str);
    }

    vuint32 = nm_setting_connection_get_gateway_ping_timeout(s_con);
    svSetValueInt64_cond(ifcfg, "GATEWAY_PING_TIMEOUT", vuint32 != 0, vuint32);

    switch (nm_setting_connection_get_metered(s_con)) {
    case NM_METERED_YES:
        svSetValueStr(ifcfg, "CONNECTION_METERED", "yes");
        break;
    case NM_METERED_NO:
        svSetValueStr(ifcfg, "CONNECTION_METERED", "no");
        break;
    case NM_METERED_UNKNOWN:
    case NM_METERED_GUESS_YES:
    case NM_METERED_GUESS_NO:
        break;
    }

    vint = nm_setting_connection_get_auth_retries(s_con);
    svSetValueInt64_cond(ifcfg, "AUTH_RETRIES", vint >= 0, vint);

    vint32 = nm_setting_connection_get_wait_device_timeout(s_con);
    if (vint32 == -1) {
        /* pass */
    } else if ((vint32 % 1000) == 0)
        svSetValueInt64(ifcfg, "DEVTIMEOUT", vint32 / 1000);
    else {
        char b[100];

        svSetValueStr(ifcfg, "DEVTIMEOUT", nm_sprintf_buf(b, "%.3f", ((double) vint) / 1000.0));
    }

    mdns = nm_setting_connection_get_mdns(s_con);
    if (mdns != NM_SETTING_CONNECTION_MDNS_DEFAULT) {
        svSetValueEnum(ifcfg, "MDNS", nm_setting_connection_mdns_get_type(), mdns);
    }

    llmnr = nm_setting_connection_get_llmnr(s_con);
    if (llmnr != NM_SETTING_CONNECTION_LLMNR_DEFAULT) {
        svSetValueEnum(ifcfg, "LLMNR", nm_setting_connection_llmnr_get_type(), llmnr);
    }
}

static char *
get_route_attributes_string(NMIPRoute *route, int family)
{
    gs_free const char **names = NULL;
    GVariant *           attr, *lock;
    GString *            str;
    guint                i, len;

    names = _nm_ip_route_get_attribute_names(route, TRUE, &len);
    if (!len)
        return NULL;

    str = g_string_new("");

    attr = nm_ip_route_get_attribute(route, NM_IP_ROUTE_ATTRIBUTE_TYPE);
    if (attr
        && nm_ip_route_attribute_validate(NM_IP_ROUTE_ATTRIBUTE_TYPE, attr, family, NULL, NULL))
        g_string_append_printf(str, "%s ", g_variant_get_string(attr, NULL));

    for (i = 0; i < len; i++) {
        if (nm_streq(names[i], NM_IP_ROUTE_ATTRIBUTE_TYPE))
            continue;

        attr = nm_ip_route_get_attribute(route, names[i]);

        if (!nm_ip_route_attribute_validate(names[i], attr, family, NULL, NULL))
            continue;

        if (NM_IN_STRSET(names[i],
                         NM_IP_ROUTE_ATTRIBUTE_WINDOW,
                         NM_IP_ROUTE_ATTRIBUTE_CWND,
                         NM_IP_ROUTE_ATTRIBUTE_INITCWND,
                         NM_IP_ROUTE_ATTRIBUTE_INITRWND,
                         NM_IP_ROUTE_ATTRIBUTE_MTU)) {
            char lock_name[256];

            nm_sprintf_buf(lock_name, "lock-%s", names[i]);
            lock = nm_ip_route_get_attribute(route, lock_name);

            g_string_append_printf(str,
                                   "%s %s%u",
                                   names[i],
                                   (lock && g_variant_get_boolean(lock)) ? "lock " : "",
                                   g_variant_get_uint32(attr));
        } else if (strstr(names[i], "lock-")) {
            const char *n = &(names[i])[NM_STRLEN("lock-")];

            attr = nm_ip_route_get_attribute(route, n);
            if (!attr) {
                g_string_append_printf(str, "%s lock 0", n);
            } else {
                /* we also have a corresponding attribute with the numeric value. The
                 * lock setting is handled above. */
            }
        } else if (nm_streq(names[i], NM_IP_ROUTE_ATTRIBUTE_SCOPE)) {
            g_string_append_printf(str, "%s %u", names[i], (unsigned) g_variant_get_byte(attr));
        } else if (nm_streq(names[i], NM_IP_ROUTE_ATTRIBUTE_TOS)) {
            g_string_append_printf(str, "%s 0x%02x", names[i], (unsigned) g_variant_get_byte(attr));
        } else if (nm_streq(names[i], NM_IP_ROUTE_ATTRIBUTE_TABLE)) {
            g_string_append_printf(str, "%s %u", names[i], (unsigned) g_variant_get_uint32(attr));
        } else if (nm_streq(names[i], NM_IP_ROUTE_ATTRIBUTE_ONLINK)) {
            if (g_variant_get_boolean(attr))
                g_string_append(str, "onlink");
        } else if (NM_IN_STRSET(names[i], NM_IP_ROUTE_ATTRIBUTE_SRC, NM_IP_ROUTE_ATTRIBUTE_FROM)) {
            char *arg = nm_streq(names[i], NM_IP_ROUTE_ATTRIBUTE_SRC) ? "src" : "from";

            g_string_append_printf(str, "%s %s", arg, g_variant_get_string(attr, NULL));
        } else {
            g_warn_if_reached();
            continue;
        }
        if (names[i + 1])
            g_string_append_c(str, ' ');
    }

    return g_string_free(str, FALSE);
}

static shvarFile *
write_route_file_svformat(const char *filename, NMSettingIPConfig *s_ip4)
{
    shvarFile *routefile;
    guint      i, num;

    routefile = utils_get_route_ifcfg(filename, TRUE);

    num = nm_setting_ip_config_get_num_routes(s_ip4);
    for (i = 0; i < num; i++) {
        char          buf[INET_ADDRSTRLEN];
        NMIPRoute *   route;
        guint32       netmask;
        gint64        metric;
        char          addr_key[64];
        char          gw_key[64];
        char          netmask_key[64];
        char          metric_key[64];
        char          options_key[64];
        gs_free char *options = NULL;

        numbered_tag(addr_key, "ADDRESS", i);
        numbered_tag(netmask_key, "NETMASK", i);
        numbered_tag(gw_key, "GATEWAY", i);

        route = nm_setting_ip_config_get_route(s_ip4, i);

        svSetValueStr(routefile, addr_key, nm_ip_route_get_dest(route));

        netmask = _nm_utils_ip4_prefix_to_netmask(nm_ip_route_get_prefix(route));
        svSetValueStr(routefile, netmask_key, _nm_utils_inet4_ntop(netmask, buf));

        svSetValueStr(routefile, gw_key, nm_ip_route_get_next_hop(route));

        metric = nm_ip_route_get_metric(route);
        if (metric != -1) {
            svSetValueInt64(routefile, numbered_tag(metric_key, "METRIC", i), metric);
        }

        options = get_route_attributes_string(route, AF_INET);
        if (options) {
            svSetValueStr(routefile, numbered_tag(options_key, "OPTIONS", i), options);
        }
    }

    return routefile;
}

static GString *
write_route_file(NMSettingIPConfig *s_ip)
{
    GString *  contents;
    NMIPRoute *route;
    guint32    i, num;
    int        addr_family;

    addr_family = nm_setting_ip_config_get_addr_family(s_ip);

    num = nm_setting_ip_config_get_num_routes(s_ip);
    if (num == 0)
        return NULL;

    contents = g_string_new("");

    for (i = 0; i < num; i++) {
        gs_free char *options = NULL;
        const char *  next_hop;
        gint64        metric;

        route    = nm_setting_ip_config_get_route(s_ip, i);
        next_hop = nm_ip_route_get_next_hop(route);
        metric   = nm_ip_route_get_metric(route);
        options  = get_route_attributes_string(route, addr_family);

        g_string_append_printf(contents,
                               "%s/%u",
                               nm_ip_route_get_dest(route),
                               nm_ip_route_get_prefix(route));
        if (next_hop)
            g_string_append_printf(contents, " via %s", next_hop);
        if (metric >= 0)
            g_string_append_printf(contents, " metric %u", (guint) metric);
        if (options) {
            g_string_append_c(contents, ' ');
            g_string_append(contents, options);
        }

        g_string_append_c(contents, '\n');
    }

    return contents;
}

static gboolean
write_proxy_setting(NMConnection *connection, shvarFile *ifcfg, GError **error)
{
    NMSettingProxy *     s_proxy;
    NMSettingProxyMethod method;
    const char *         pac_url, *pac_script;

    s_proxy = nm_connection_get_setting_proxy(connection);
    if (!s_proxy)
        return TRUE;

    method = nm_setting_proxy_get_method(s_proxy);
    switch (method) {
    case NM_SETTING_PROXY_METHOD_AUTO:
        svSetValueStr(ifcfg, "PROXY_METHOD", "auto");

        pac_url = nm_setting_proxy_get_pac_url(s_proxy);
        if (pac_url)
            svSetValueStr(ifcfg, "PAC_URL", pac_url);

        pac_script = nm_setting_proxy_get_pac_script(s_proxy);
        if (pac_script)
            svSetValueStr(ifcfg, "PAC_SCRIPT", pac_script);

        break;
    case NM_SETTING_PROXY_METHOD_NONE:
        svSetValueStr(ifcfg, "PROXY_METHOD", "none");
        break;
    }

    svSetValueBoolean(ifcfg, "BROWSER_ONLY", nm_setting_proxy_get_browser_only(s_proxy));

    return TRUE;
}

static gboolean
write_user_setting(NMConnection *connection, shvarFile *ifcfg, GError **error)
{
    NMSettingUser *    s_user;
    guint              i, len;
    const char *const *keys;

    s_user = NM_SETTING_USER(nm_connection_get_setting(connection, NM_TYPE_SETTING_USER));

    if (!s_user)
        return TRUE;

    keys = nm_setting_user_get_keys(s_user, &len);
    if (len) {
        nm_auto_free_gstring GString *str = g_string_sized_new(100);

        for (i = 0; i < len; i++) {
            const char *key = keys[i];

            g_string_set_size(str, 0);
            g_string_append(str, "NM_USER_");
            nms_ifcfg_rh_utils_user_key_encode(key, str);
            svSetValue(ifcfg, str->str, nm_setting_user_get_data(s_user, key));
        }
    }

    return TRUE;
}

static void
write_sriov_setting(NMConnection *connection, shvarFile *ifcfg)
{
    NMSettingSriov *s_sriov;
    guint           i, num = 0;
    NMTernary       b;
    NMSriovVF *     vf;
    char            key[32];
    char *          str;

    s_sriov = NM_SETTING_SRIOV(nm_connection_get_setting(connection, NM_TYPE_SETTING_SRIOV));
    if (!s_sriov) {
        return;
    }

    svSetValueInt64(ifcfg, "SRIOV_TOTAL_VFS", nm_setting_sriov_get_total_vfs(s_sriov));

    b = nm_setting_sriov_get_autoprobe_drivers(s_sriov);
    if (b != NM_TERNARY_DEFAULT)
        svSetValueInt64(ifcfg, "SRIOV_AUTOPROBE_DRIVERS", b);

    num = nm_setting_sriov_get_num_vfs(s_sriov);
    for (i = 0; i < num; i++) {
        vf = nm_setting_sriov_get_vf(s_sriov, i);
        nm_sprintf_buf(key, "SRIOV_VF%u", nm_sriov_vf_get_index(vf));
        str = nm_utils_sriov_vf_to_str(vf, TRUE, NULL);
        svSetValueStr(ifcfg, key, str);
        g_free(str);
    }
}

static gboolean
write_tc_setting(NMConnection *connection, shvarFile *ifcfg, GError **error)
{
    NMSettingTCConfig *s_tc;
    guint              i, num, n;
    char               tag[64];

    s_tc = nm_connection_get_setting_tc_config(connection);
    if (!s_tc)
        return TRUE;

    num = nm_setting_tc_config_get_num_qdiscs(s_tc);
    for (n = 1, i = 0; i < num; i++) {
        NMTCQdisc *   qdisc;
        gs_free char *str = NULL;

        qdisc = nm_setting_tc_config_get_qdisc(s_tc, i);
        str   = nm_utils_tc_qdisc_to_str(qdisc, error);
        if (!str)
            return FALSE;

        svSetValueStr(ifcfg, numbered_tag(tag, "QDISC", n), str);
        n++;
    }

    num = nm_setting_tc_config_get_num_tfilters(s_tc);
    for (n = 1, i = 0; i < num; i++) {
        NMTCTfilter * tfilter;
        gs_free char *str = NULL;

        tfilter = nm_setting_tc_config_get_tfilter(s_tc, i);
        str     = nm_utils_tc_tfilter_to_str(tfilter, error);
        if (!str)
            return FALSE;

        svSetValueStr(ifcfg, numbered_tag(tag, "FILTER", n), str);
        n++;
    }

    return TRUE;
}

static void
write_match_setting(NMConnection *connection, shvarFile *ifcfg)
{
    nm_auto_free_gstring GString *str = NULL;
    NMSettingMatch *              s_match;
    guint                         i, num;
    const char *                  name;

    s_match = (NMSettingMatch *) nm_connection_get_setting(connection, NM_TYPE_SETTING_MATCH);
    if (!s_match)
        return;

    num = nm_setting_match_get_num_drivers(s_match);
    if (num > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            name = nm_setting_match_get_driver(s_match, i);
            nm_gstring_add_space_delimiter(str);
            nm_utils_escaped_tokens_escape_gstr(name, NM_ASCII_SPACES, str);
        }
        svSetValueStr(ifcfg, "MATCH_DRIVER", str->str);
    }

    num = nm_setting_match_get_num_interface_names(s_match);
    if (num > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            name = nm_setting_match_get_interface_name(s_match, i);
            nm_gstring_add_space_delimiter(str);
            nm_utils_escaped_tokens_escape_gstr(name, NM_ASCII_SPACES, str);
        }
        svSetValueStr(ifcfg, "MATCH_INTERFACE_NAME", str->str);
    }

    num = nm_setting_match_get_num_kernel_command_lines(s_match);
    if (num > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            name = nm_setting_match_get_kernel_command_line(s_match, i);
            nm_gstring_add_space_delimiter(str);
            nm_utils_escaped_tokens_escape_gstr(name, NM_ASCII_SPACES, str);
        }
        svSetValueStr(ifcfg, "MATCH_KERNEL_COMMAND_LINE", str->str);
    }

    num = nm_setting_match_get_num_paths(s_match);
    if (num > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            name = nm_setting_match_get_path(s_match, i);
            nm_gstring_add_space_delimiter(str);
            nm_utils_escaped_tokens_escape_gstr(name, NM_ASCII_SPACES, str);
        }
        svSetValueStr(ifcfg, "MATCH_PATH", str->str);
    }
}

static void
write_res_options(shvarFile *ifcfg, NMSettingIPConfig *s_ip, const char *var)
{
    nm_auto_free_gstring GString *value = NULL;
    guint                         i, num_options;

    if (!nm_setting_ip_config_has_dns_options(s_ip))
        return;

    value       = g_string_new(NULL);
    num_options = nm_setting_ip_config_get_num_dns_options(s_ip);
    for (i = 0; i < num_options; i++) {
        if (i > 0)
            g_string_append_c(value, ' ');
        g_string_append(value, nm_setting_ip_config_get_dns_option(s_ip, i));
    }

    svSetValue(ifcfg, var, value->str);
}

static void
write_dns_setting(shvarFile *ifcfg, NMConnection *connection, int addr_family)
{
    NMSettingIPConfig *s_ip;
    NMSettingIPConfig *s_ip4;
    NMSettingIPConfig *s_ip6 = NULL;
    guint              num4;
    guint              num6 = 0;
    guint              num;
    guint              i;
    guint              offset;

    if (addr_family == AF_INET6) {
        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        num6  = s_ip6 ? nm_setting_ip_config_get_num_dns(s_ip6) : 0u;
    }

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    num4  = s_ip4 ? nm_setting_ip_config_get_num_dns(s_ip4) : 0u;

    if (addr_family == AF_INET6) {
        num    = num6;
        offset = num4;
        s_ip   = s_ip6;
    } else {
        num    = num4;
        offset = 0;
        s_ip   = s_ip4;
    }

    for (i = 0; i < num; i++) {
        char tag[64];

        svSetValueStr(ifcfg,
                      numbered_tag(tag, "DNS", offset + i + 1u),
                      nm_setting_ip_config_get_dns(s_ip, i));
    }
}

static gboolean
write_ip4_setting(NMConnection *connection,
                  shvarFile *   ifcfg,
                  shvarFile **  out_route_content_svformat,
                  GString **    out_route_content,
                  GError **     error)
{
    NMSettingIPConfig *    s_ip4;
    const char *           value;
    char *                 tmp;
    char                   tag[64];
    int                    j;
    guint                  i, num, n;
    gint64                 route_metric;
    NMIPRouteTableSyncMode route_table;
    int                    priority;
    int                    timeout;
    nm_auto_free_gstring GString *str    = NULL;
    const char *                  method = NULL;
    gboolean                      has_netmask;
    NMDhcpHostnameFlags           flags;
    const char *const *           strv;

    NM_SET_OUT(out_route_content_svformat, NULL);
    NM_SET_OUT(out_route_content, NULL);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    if (!s_ip4)
        return TRUE;

    method = nm_setting_ip_config_get_method(s_ip4);

    /* Missing IP4 setting is assumed to be DHCP */
    if (!method)
        method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;

    if (nm_streq(method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED))
        return TRUE;

    num = nm_setting_ip_config_get_num_addresses(s_ip4);

    if (!strcmp(method, NM_SETTING_IP4_CONFIG_METHOD_AUTO))
        svSetValueStr(ifcfg, "BOOTPROTO", "dhcp");
    else if (!strcmp(method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
        /* Preserve the archaic form of "static" if there actually
         * is static configuration. */
        if (g_strcmp0(svGetValue(ifcfg, "BOOTPROTO", &tmp), "static") || !num)
            svSetValueStr(ifcfg, "BOOTPROTO", "none");
        g_free(tmp);
    } else if (!strcmp(method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL))
        svSetValueStr(ifcfg, "BOOTPROTO", "autoip");
    else if (!strcmp(method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
        svSetValueStr(ifcfg, "BOOTPROTO", "shared");

    has_netmask = !!svFindFirstNumberedKey(ifcfg, "NETMASK");

    /* Write out IPADDR<n>, PREFIX<n>, GATEWAY<n> for current IP addresses
     * without labels. Unset obsolete NETMASK<n>.
     */
    for (i = n = 0; i < num; i++) {
        NMIPAddress *addr;
        guint        prefix;

        addr = nm_setting_ip_config_get_address(s_ip4, i);

        if (i > 0) {
            GVariant *label;

            label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
            if (label)
                continue;
        }

        if (n == 0) {
            /* Instead of index 0 use un-numbered variables.
             * It's needed for compatibility with ifup that only recognizes 'GATEAWAY'
             * See https://bugzilla.redhat.com/show_bug.cgi?id=771673
             * and https://bugzilla.redhat.com/show_bug.cgi?id=1105770
             */
            j = -1;
        } else
            j = n;

        svSetValueStr(ifcfg, numbered_tag(tag, "IPADDR", j), nm_ip_address_get_address(addr));

        prefix = nm_ip_address_get_prefix(addr);
        svSetValueInt64(ifcfg, numbered_tag(tag, "PREFIX", j), prefix);

        /* If the legacy "NETMASK" is present, keep it. */
        numbered_tag(tag, "NETMASK", j);
        if (has_netmask) {
            char buf[INET_ADDRSTRLEN];

            svSetValueStr(ifcfg,
                          tag,
                          _nm_utils_inet4_ntop(_nm_utils_ip4_prefix_to_netmask(prefix), buf));
        }

        n++;
    }

    svSetValueStr(ifcfg, "GATEWAY", nm_setting_ip_config_get_gateway(s_ip4));

    write_dns_setting(ifcfg, connection, AF_INET);

    num = nm_setting_ip_config_get_num_dns_searches(s_ip4);
    if (num > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            nm_gstring_add_space_delimiter(str);
            g_string_append(str, nm_setting_ip_config_get_dns_search(s_ip4, i));
        }
        svSetValueStr(ifcfg, "DOMAIN", str->str);
    }

    /* DEFROUTE; remember that it has the opposite meaning from never-default */
    svSetValueBoolean(ifcfg, "DEFROUTE", !nm_setting_ip_config_get_never_default(s_ip4));

    /* Missing PEERDNS means TRUE, so write it only when is FALSE */
    svSetValueStr(ifcfg, "PEERDNS", nm_setting_ip_config_get_ignore_auto_dns(s_ip4) ? "no" : NULL);
    /* Missing PEERROUTES means TRUE, so write it only when is FALSE */
    svSetValueStr(ifcfg,
                  "PEERROUTES",
                  nm_setting_ip_config_get_ignore_auto_routes(s_ip4) ? "no" : NULL);

    value = nm_setting_ip_config_get_dhcp_hostname(s_ip4);
    svSetValueStr(ifcfg, "DHCP_HOSTNAME", value);

    value = nm_setting_ip4_config_get_dhcp_fqdn(NM_SETTING_IP4_CONFIG(s_ip4));
    svSetValueStr(ifcfg, "DHCP_FQDN", value);

    flags = nm_setting_ip_config_get_dhcp_hostname_flags(s_ip4);
    svSetValueInt64_cond(ifcfg, "DHCP_HOSTNAME_FLAGS", flags != NM_DHCP_HOSTNAME_FLAG_NONE, flags);

    /* Missing DHCP_SEND_HOSTNAME means TRUE, and we prefer not write it explicitly
     * in that case, because it is NM-specific variable
     */
    svSetValueStr(ifcfg,
                  "DHCP_SEND_HOSTNAME",
                  nm_setting_ip_config_get_dhcp_send_hostname(s_ip4) ? NULL : "no");

    value = nm_setting_ip4_config_get_dhcp_client_id(NM_SETTING_IP4_CONFIG(s_ip4));
    svSetValueStr(ifcfg, "DHCP_CLIENT_ID", value);

    svSetValue(
        ifcfg,
        "DHCP_VENDOR_CLASS_IDENTIFIER",
        nm_setting_ip4_config_get_dhcp_vendor_class_identifier(NM_SETTING_IP4_CONFIG(s_ip4)));

    value = nm_setting_ip_config_get_dhcp_iaid(s_ip4);
    svSetValueStr(ifcfg, "DHCP_IAID", value);

    timeout = nm_setting_ip_config_get_dhcp_timeout(s_ip4);
    svSetValueInt64_cond(ifcfg, "IPV4_DHCP_TIMEOUT", timeout != 0, timeout);

    svSetValueBoolean(ifcfg, "IPV4_FAILURE_FATAL", !nm_setting_ip_config_get_may_fail(s_ip4));

    route_metric = nm_setting_ip_config_get_route_metric(s_ip4);
    svSetValueInt64_cond(ifcfg, "IPV4_ROUTE_METRIC", route_metric != -1, route_metric);

    route_table = nm_setting_ip_config_get_route_table(s_ip4);
    svSetValueInt64_cond(ifcfg, "IPV4_ROUTE_TABLE", route_table != 0, route_table);

    NM_SET_OUT(out_route_content_svformat, write_route_file_svformat(svFileGetName(ifcfg), s_ip4));
    NM_SET_OUT(out_route_content, write_route_file(s_ip4));

    timeout = nm_setting_ip_config_get_dad_timeout(s_ip4);
    if (timeout < 0) {
        /* pass */
    } else if (timeout == 0) {
        svSetValueStr(ifcfg, "ACD_TIMEOUT", "0");
        svSetValueStr(ifcfg, "ARPING_WAIT", "0");
    } else {
        svSetValueInt64(ifcfg, "ACD_TIMEOUT", timeout);
        /* Round the value up to next integer for initscripts */
        svSetValueInt64(ifcfg, "ARPING_WAIT", (timeout - 1) / 1000 + 1);
    }

    priority = nm_setting_ip_config_get_dns_priority(s_ip4);
    if (priority)
        svSetValueInt64(ifcfg, "IPV4_DNS_PRIORITY", priority);

    write_res_options(ifcfg, s_ip4, "RES_OPTIONS");

    strv = nm_setting_ip_config_get_dhcp_reject_servers(s_ip4, &num);
    if (num > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            nm_gstring_add_space_delimiter(str);
            nm_utils_escaped_tokens_escape_gstr(strv[i], NM_ASCII_SPACES, str);
        }
        svSetValueStr(ifcfg, "DHCP_REJECT_SERVERS", str->str);
    }

    return TRUE;
}

static void
write_ip4_aliases(NMConnection *connection, const char *base_ifcfg_path)
{
    NMSettingIPConfig *s_ip4;
    gs_free char *     base_ifcfg_dir = NULL, *base_ifcfg_name = NULL;
    const char *       base_name;
    int                i, num, base_ifcfg_name_len, base_name_len;
    GDir *             dir;

    base_ifcfg_dir      = g_path_get_dirname(base_ifcfg_path);
    base_ifcfg_name     = g_path_get_basename(base_ifcfg_path);
    base_ifcfg_name_len = strlen(base_ifcfg_name);
    if (!g_str_has_prefix(base_ifcfg_name, IFCFG_TAG))
        g_return_if_reached();
    base_name     = base_ifcfg_name + strlen(IFCFG_TAG);
    base_name_len = strlen(base_name);

    /* Remove all existing aliases for this file first */
    dir = g_dir_open(base_ifcfg_dir, 0, NULL);
    if (dir) {
        const char *item;

        while ((item = g_dir_read_name(dir))) {
            char *full_path;

            if (strncmp(item, base_ifcfg_name, base_ifcfg_name_len) != 0
                || item[base_ifcfg_name_len] != ':')
                continue;

            full_path = g_build_filename(base_ifcfg_dir, item, NULL);
            unlink(full_path);
            g_free(full_path);
        }

        g_dir_close(dir);
    }

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    if (!s_ip4) {
        /* slave-type: no alias files */
        return;
    }

    num = nm_setting_ip_config_get_num_addresses(s_ip4);
    for (i = 0; i < num; i++) {
        GVariant *   label_var;
        const char * label, *p;
        char *       path;
        NMIPAddress *addr;
        shvarFile *  ifcfg;

        addr = nm_setting_ip_config_get_address(s_ip4, i);

        label_var = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
        if (!label_var)
            continue;
        label = g_variant_get_string(label_var, NULL);
        if (strncmp(label, base_name, base_name_len) != 0 || label[base_name_len] != ':')
            continue;

        for (p = label; *p; p++) {
            if (!g_ascii_isalnum(*p) && *p != '_' && *p != ':')
                break;
        }
        if (*p)
            continue;

        path  = g_strdup_printf("%s%s", base_ifcfg_path, label + base_name_len);
        ifcfg = svCreateFile(path);
        g_free(path);

        svSetValueStr(ifcfg, "DEVICE", label);

        addr = nm_setting_ip_config_get_address(s_ip4, i);
        svSetValueStr(ifcfg, "IPADDR", nm_ip_address_get_address(addr));

        svSetValueInt64(ifcfg, "PREFIX", nm_ip_address_get_prefix(addr));

        svWriteFileWithoutDirtyWellknown(ifcfg, 0644, NULL);
        svCloseFile(ifcfg);
    }
}

static gboolean
write_ip6_setting(NMConnection *connection,
                  shvarFile *   ifcfg,
                  GString **    out_route6_content,
                  GError **     error)
{
    NMSettingIPConfig *           s_ip6;
    const char *                  value;
    guint                         i, num;
    int                           priority;
    NMIPAddress *                 addr;
    gint64                        route_metric;
    NMIPRouteTableSyncMode        route_table;
    GString *                     ip_str1, *ip_str2, *ip_ptr;
    NMSettingIP6ConfigAddrGenMode addr_gen_mode;
    NMDhcpHostnameFlags           flags;
    const char *                  hostname;
    int                           timeout;

    NM_SET_OUT(out_route6_content, NULL);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    if (!s_ip6)
        return TRUE;

    value = nm_setting_ip_config_get_method(s_ip6);
    g_assert(value);
    if (!strcmp(value, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)) {
        svSetValueStr(ifcfg, "IPV6INIT", "no");
        return TRUE;
    } else if (!strcmp(value, NM_SETTING_IP6_CONFIG_METHOD_DISABLED)) {
        svSetValueStr(ifcfg, "IPV6_DISABLED", "yes");
        svSetValueStr(ifcfg, "IPV6INIT", "no");
        return TRUE;
    } else if (!strcmp(value, NM_SETTING_IP6_CONFIG_METHOD_AUTO)) {
        svSetValueStr(ifcfg, "IPV6INIT", "yes");
        svSetValueStr(ifcfg, "IPV6_AUTOCONF", "yes");
    } else if (!strcmp(value, NM_SETTING_IP6_CONFIG_METHOD_DHCP)) {
        svSetValueStr(ifcfg, "IPV6INIT", "yes");
        svSetValueStr(ifcfg, "IPV6_AUTOCONF", "no");
        svSetValueStr(ifcfg, "DHCPV6C", "yes");
    } else if (!strcmp(value, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
        svSetValueStr(ifcfg, "IPV6INIT", "yes");
        svSetValueStr(ifcfg, "IPV6_AUTOCONF", "no");
    } else if (!strcmp(value, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL)) {
        svSetValueStr(ifcfg, "IPV6INIT", "yes");
        svSetValueStr(ifcfg, "IPV6_AUTOCONF", "no");
    } else if (!strcmp(value, NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {
        svSetValueStr(ifcfg, "IPV6INIT", "yes");
        svSetValueStr(ifcfg, "IPV6_AUTOCONF", "shared");
    }

    svSetValueStr(ifcfg,
                  "DHCPV6_DUID",
                  nm_setting_ip6_config_get_dhcp_duid(NM_SETTING_IP6_CONFIG(s_ip6)));
    svSetValueStr(ifcfg, "DHCPV6_IAID", nm_setting_ip_config_get_dhcp_iaid(s_ip6));

    hostname = nm_setting_ip_config_get_dhcp_hostname(s_ip6);
    svSetValueStr(ifcfg, "DHCPV6_HOSTNAME", hostname);

    /* Missing DHCPV6_SEND_HOSTNAME means TRUE, and we prefer not write it
     * explicitly in that case, because it is NM-specific variable
     */
    if (!nm_setting_ip_config_get_dhcp_send_hostname(s_ip6))
        svSetValueStr(ifcfg, "DHCPV6_SEND_HOSTNAME", "no");

    timeout = nm_setting_ip6_config_get_ra_timeout(NM_SETTING_IP6_CONFIG(s_ip6));
    svSetValueInt64_cond(ifcfg, "IPV6_RA_TIMEOUT", timeout != 0, timeout);

    timeout = nm_setting_ip_config_get_dhcp_timeout(s_ip6);
    svSetValueInt64_cond(ifcfg, "IPV6_DHCP_TIMEOUT", timeout != 0, timeout);

    flags = nm_setting_ip_config_get_dhcp_hostname_flags(s_ip6);
    svSetValueInt64_cond(ifcfg,
                         "DHCPV6_HOSTNAME_FLAGS",
                         flags != NM_DHCP_HOSTNAME_FLAG_NONE,
                         flags);

    /* Write out IP addresses */
    num     = nm_setting_ip_config_get_num_addresses(s_ip6);
    ip_str1 = g_string_new(NULL);
    ip_str2 = g_string_new(NULL);
    for (i = 0; i < num; i++) {
        if (i == 0)
            ip_ptr = ip_str1;
        else
            ip_ptr = ip_str2;

        addr = nm_setting_ip_config_get_address(s_ip6, i);

        if (i > 1)
            g_string_append_c(ip_ptr, ' '); /* separate addresses in IPV6ADDR_SECONDARIES */
        g_string_append_printf(ip_ptr,
                               "%s/%u",
                               nm_ip_address_get_address(addr),
                               nm_ip_address_get_prefix(addr));
    }
    svSetValueStr(ifcfg, "IPV6ADDR", ip_str1->str);
    svSetValueStr(ifcfg, "IPV6ADDR_SECONDARIES", ip_str2->str);
    svSetValueStr(ifcfg, "IPV6_DEFAULTGW", nm_setting_ip_config_get_gateway(s_ip6));
    g_string_free(ip_str1, TRUE);
    g_string_free(ip_str2, TRUE);

    write_dns_setting(ifcfg, connection, AF_INET6);

    /* Write out DNS domains */
    num = nm_setting_ip_config_get_num_dns_searches(s_ip6);
    if (num > 0) {
        nm_auto_free_gstring GString *searches = NULL;

        searches = g_string_new(NULL);
        for (i = 0; i < num; i++) {
            if (searches->len > 0)
                g_string_append_c(searches, ' ');
            g_string_append(searches, nm_setting_ip_config_get_dns_search(s_ip6, i));
        }
        svSetValueStr(ifcfg, "IPV6_DOMAIN", searches->str);
    }

    /* handle IPV6_DEFROUTE */
    /* IPV6_DEFROUTE has the opposite meaning from 'never-default' */
    svSetValueBoolean(ifcfg, "IPV6_DEFROUTE", !nm_setting_ip_config_get_never_default(s_ip6));

    svSetValueStr(ifcfg,
                  "IPV6_PEERDNS",
                  nm_setting_ip_config_get_ignore_auto_dns(s_ip6) ? "no" : NULL);

    svSetValueStr(ifcfg,
                  "IPV6_PEERROUTES",
                  nm_setting_ip_config_get_ignore_auto_routes(s_ip6) ? "no" : NULL);

    svSetValueStr(ifcfg,
                  "IPV6_FAILURE_FATAL",
                  nm_setting_ip_config_get_may_fail(s_ip6) ? "no" : "yes");

    route_metric = nm_setting_ip_config_get_route_metric(s_ip6);
    svSetValueInt64_cond(ifcfg, "IPV6_ROUTE_METRIC", route_metric != -1, route_metric);

    route_table = nm_setting_ip_config_get_route_table(s_ip6);
    svSetValueInt64_cond(ifcfg, "IPV6_ROUTE_TABLE", route_table != 0, route_table);

    /* IPv6 Privacy Extensions */
    switch (nm_setting_ip6_config_get_ip6_privacy(NM_SETTING_IP6_CONFIG(s_ip6))) {
    case NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED:
        svSetValueStr(ifcfg, "IPV6_PRIVACY", "no");
        break;
    case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR:
        svSetValueStr(ifcfg, "IPV6_PRIVACY", "rfc3041");
        svSetValueStr(ifcfg, "IPV6_PRIVACY_PREFER_PUBLIC_IP", "yes");
        break;
    case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR:
        svSetValueStr(ifcfg, "IPV6_PRIVACY", "rfc3041");
        break;
    default:
        break;
    }

    /* IPv6 Address generation mode */
    addr_gen_mode = nm_setting_ip6_config_get_addr_gen_mode(NM_SETTING_IP6_CONFIG(s_ip6));
    if (addr_gen_mode != NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64) {
        svSetValueEnum(ifcfg,
                       "IPV6_ADDR_GEN_MODE",
                       nm_setting_ip6_config_addr_gen_mode_get_type(),
                       addr_gen_mode);
    }

    /* IPv6 tokenized interface identifier */
    value = nm_setting_ip6_config_get_token(NM_SETTING_IP6_CONFIG(s_ip6));
    svSetValueStr(ifcfg, "IPV6_TOKEN", value);

    priority = nm_setting_ip_config_get_dns_priority(s_ip6);
    if (priority)
        svSetValueInt64(ifcfg, "IPV6_DNS_PRIORITY", priority);

    write_res_options(ifcfg, s_ip6, "IPV6_RES_OPTIONS");

    NM_SET_OUT(out_route6_content, write_route_file(s_ip6));

    return TRUE;
}

static void
write_ip_routing_rules(NMConnection *connection, shvarFile *ifcfg, gboolean route_ignore)
{
    gsize idx;
    int   is_ipv4;

    if (route_ignore)
        return;

    idx = 0;

    for (is_ipv4 = 1; is_ipv4 >= 0; is_ipv4--) {
        const int          addr_family = is_ipv4 ? AF_INET : AF_INET6;
        NMSettingIPConfig *s_ip;
        guint              i, num;

        s_ip = nm_connection_get_setting_ip_config(connection, addr_family);
        if (!s_ip)
            continue;

        num = nm_setting_ip_config_get_num_routing_rules(s_ip);
        for (i = 0; i < num; i++) {
            NMIPRoutingRule *   rule = nm_setting_ip_config_get_routing_rule(s_ip, i);
            gs_free const char *s    = NULL;
            char                key[64];

            s = nm_ip_routing_rule_to_string(rule,
                                             NM_IP_ROUTING_RULE_AS_STRING_FLAGS_NONE,
                                             NULL,
                                             NULL);
            if (!s)
                continue;

            if (is_ipv4)
                numbered_tag(key, "ROUTING_RULE_", ++idx);
            else
                numbered_tag(key, "ROUTING_RULE6_", ++idx);
            svSetValueStr(ifcfg, key, s);
        }
    }
}

static char *
escape_id(const char *id)
{
    char *escaped = g_strdup(id);
    char *p       = escaped;

    /* Escape random stuff */
    while (*p) {
        if (*p == ' ')
            *p = '_';
        else if (strchr("\\][|/=()!:", *p))
            *p = '-';
        p++;
    }

    return escaped;
}

static gboolean
do_write_construct(NMConnection *                  connection,
                   const char *                    ifcfg_dir,
                   const char *                    filename,
                   NMSIfcfgRHWriterAllowFilenameCb allow_filename_cb,
                   gpointer                        allow_filename_user_data,
                   shvarFile **                    out_ifcfg,
                   GHashTable **                   out_blobs,
                   GHashTable **                   out_secrets,
                   gboolean *                      out_route_ignore,
                   shvarFile **                    out_route_content_svformat,
                   GString **                      out_route_content,
                   GString **                      out_route6_content,
                   GError **                       error)
{
    NMSettingConnection *    s_con;
    nm_auto_shvar_file_close shvarFile *ifcfg       = NULL;
    gs_free char *                      ifcfg_name  = NULL;
    gs_free char *                      route_path  = NULL;
    gs_free char *                      route6_path = NULL;
    const char *                        type;
    gs_unref_hashtable GHashTable *blobs   = NULL;
    gs_unref_hashtable GHashTable *secrets = NULL;
    gboolean                       wired;
    gboolean                       no_8021x;
    gboolean                       route_path_is_svformat;
    gboolean                       has_complex_routes_v4;
    gboolean                       has_complex_routes_v6;
    gboolean                       route_ignore;
    nm_auto_shvar_file_close shvarFile *route_content_svformat = NULL;
    nm_auto_free_gstring GString *route_content                = NULL;
    nm_auto_free_gstring GString *route6_content               = NULL;

    nm_assert(NM_IS_CONNECTION(connection));
    nm_assert(_nm_connection_verify(connection, NULL) == NM_SETTING_VERIFY_SUCCESS);

    if (!nms_ifcfg_rh_writer_can_write_connection(connection, error))
        return FALSE;

    s_con = nm_connection_get_setting_connection(connection);

    if (filename) {
        /* For existing connections, 'filename' should be full path to ifcfg file */
        ifcfg = svOpenFile(filename, error);
        if (!ifcfg)
            return FALSE;

        ifcfg_name = g_strdup(filename);
    } else if (ifcfg_dir) {
        gs_free char *escaped = NULL;
        int           i_path;

        escaped = escape_id(nm_setting_connection_get_id(s_con));

        for (i_path = 0; i_path < 10000; i_path++) {
            gs_free char *path_candidate = NULL;

            if (i_path == 0)
                path_candidate = g_strdup_printf("%s/ifcfg-%s", ifcfg_dir, escaped);
            else
                path_candidate = g_strdup_printf("%s/ifcfg-%s-%d", ifcfg_dir, escaped, i_path);

            if (allow_filename_cb && !allow_filename_cb(path_candidate, allow_filename_user_data))
                continue;

            if (g_file_test(path_candidate, G_FILE_TEST_EXISTS))
                continue;

            ifcfg_name = g_steal_pointer(&path_candidate);
            break;
        }

        if (!ifcfg_name) {
            g_set_error_literal(error,
                                NM_SETTINGS_ERROR,
                                NM_SETTINGS_ERROR_FAILED,
                                "Failed to find usable ifcfg file name");
            return FALSE;
        }

        ifcfg = svCreateFile(ifcfg_name);
    } else
        ifcfg = svCreateFile("/tmp/ifcfg-dummy");

    route_path = utils_get_route_path(svFileGetName(ifcfg));
    if (!route_path) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Could not get route file path for '%s'",
                    svFileGetName(ifcfg));
        return FALSE;
    }

    route6_path = utils_get_route6_path(svFileGetName(ifcfg));
    if (!route6_path) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Could not get route6 file path for '%s'",
                    svFileGetName(ifcfg));
        return FALSE;
    }

    type = nm_setting_connection_get_connection_type(s_con);
    if (!type) {
        g_set_error(error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED, "Missing connection type!");
        return FALSE;
    }

    secrets = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, g_free);

    wired    = FALSE;
    no_8021x = FALSE;
    if (!strcmp(type, NM_SETTING_WIRED_SETTING_NAME)) {
        // FIXME: can't write PPPoE at this time
        if (nm_connection_get_setting_pppoe(connection)) {
            g_set_error(error,
                        NM_SETTINGS_ERROR,
                        NM_SETTINGS_ERROR_FAILED,
                        "Can't write connection type '%s'",
                        NM_SETTING_PPPOE_SETTING_NAME);
            return FALSE;
        }

        if (!write_wired_setting(connection, ifcfg, error))
            return FALSE;
        wired = TRUE;
    } else if (!strcmp(type, NM_SETTING_VLAN_SETTING_NAME)) {
        if (!write_vlan_setting(connection, ifcfg, &wired, error))
            return FALSE;
    } else if (!strcmp(type, NM_SETTING_WIRELESS_SETTING_NAME)) {
        if (!write_wireless_setting(connection, ifcfg, secrets, &no_8021x, error))
            return FALSE;
    } else if (!strcmp(type, NM_SETTING_INFINIBAND_SETTING_NAME)) {
        if (!write_infiniband_setting(connection, ifcfg, error))
            return FALSE;
    } else if (!strcmp(type, NM_SETTING_BOND_SETTING_NAME)) {
        if (!write_bond_setting(connection, ifcfg, &wired, error))
            return FALSE;
    } else if (!strcmp(type, NM_SETTING_TEAM_SETTING_NAME)) {
        if (!write_team_setting(connection, ifcfg, &wired, error))
            return FALSE;
    } else if (!strcmp(type, NM_SETTING_BRIDGE_SETTING_NAME)) {
        if (!write_bridge_setting(connection, ifcfg, &wired, error))
            return FALSE;
    } else {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "Can't write connection type '%s'",
                    type);
        return FALSE;
    }

    if (!no_8021x) {
        blobs =
            g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, (GDestroyNotify) g_bytes_unref);
        if (!write_8021x_setting(connection, ifcfg, secrets, blobs, wired, error))
            return FALSE;
    }

    if (!write_bridge_port_setting(connection, ifcfg, error))
        return FALSE;

    if (!write_team_port_setting(connection, ifcfg, error))
        return FALSE;

    if (!write_dcb_setting(connection, ifcfg, error))
        return FALSE;

    if (!write_proxy_setting(connection, ifcfg, error))
        return FALSE;

    if (!write_ethtool_setting(connection, ifcfg, error))
        return FALSE;

    if (!write_user_setting(connection, ifcfg, error))
        return FALSE;

    write_match_setting(connection, ifcfg);
    write_hostname_setting(connection, ifcfg);
    write_sriov_setting(connection, ifcfg);

    if (!write_tc_setting(connection, ifcfg, error))
        return FALSE;

    route_path_is_svformat = utils_has_route_file_new_syntax(route_path);

    has_complex_routes_v4 = utils_has_complex_routes(ifcfg_name, AF_INET);
    has_complex_routes_v6 = utils_has_complex_routes(ifcfg_name, AF_INET6);

    if (has_complex_routes_v4 || has_complex_routes_v6) {
        NMSettingIPConfig *s_ip4, *s_ip6;

        s_ip4 = nm_connection_get_setting_ip4_config(connection);
        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        if ((s_ip4 && nm_setting_ip_config_get_num_routes(s_ip4) > 0)
            || (s_ip6 && nm_setting_ip_config_get_num_routes(s_ip6) > 0)) {
            g_set_error(error,
                        NM_SETTINGS_ERROR,
                        NM_SETTINGS_ERROR_FAILED,
                        "Cannot configure static routes on a connection that has an associated "
                        "'rule%s-' file",
                        has_complex_routes_v4 ? "" : "6");
            return FALSE;
        }
        if ((s_ip4 && nm_setting_ip_config_get_route_table(s_ip4) != 0)
            || (s_ip6 && nm_setting_ip_config_get_route_table(s_ip6) != 0)) {
            g_set_error(error,
                        NM_SETTINGS_ERROR,
                        NM_SETTINGS_ERROR_FAILED,
                        "Cannot configure a route table for policy routing on a connection that "
                        "has an associated 'rule%s-' file",
                        has_complex_routes_v4 ? "" : "6");
            return FALSE;
        }
        if ((s_ip4 && nm_setting_ip_config_get_num_routing_rules(s_ip4) > 0)
            || (s_ip6 && nm_setting_ip_config_get_num_routing_rules(s_ip6) > 0)) {
            g_set_error(error,
                        NM_SETTINGS_ERROR,
                        NM_SETTINGS_ERROR_FAILED,
                        "Cannot configure routing rules on a connection that has an associated "
                        "'rule%s-' file",
                        has_complex_routes_v4 ? "" : "6");
            return FALSE;
        }
        route_ignore = TRUE;
    } else
        route_ignore = FALSE;

    if (!write_ip4_setting(connection,
                           ifcfg,
                           !route_ignore && route_path_is_svformat ? &route_content_svformat : NULL,
                           !route_ignore && route_path_is_svformat ? NULL : &route_content,
                           error))
        return FALSE;

    if (!write_ip6_setting(connection, ifcfg, !route_ignore ? &route6_content : NULL, error))
        return FALSE;

    write_ip_routing_rules(connection, ifcfg, route_ignore);

    write_connection_setting(s_con, ifcfg);

    NM_SET_OUT(out_ifcfg, g_steal_pointer(&ifcfg));
    NM_SET_OUT(out_blobs, g_steal_pointer(&blobs));
    NM_SET_OUT(out_secrets, g_steal_pointer(&secrets));
    NM_SET_OUT(out_route_ignore, route_ignore);
    NM_SET_OUT(out_route_content_svformat, g_steal_pointer(&route_content_svformat));
    NM_SET_OUT(out_route_content, g_steal_pointer(&route_content));
    NM_SET_OUT(out_route6_content, g_steal_pointer(&route6_content));
    return TRUE;
}

static gboolean
do_write_to_disk(NMConnection *connection,
                 shvarFile *   ifcfg,
                 GHashTable *  blobs,
                 GHashTable *  secrets,
                 gboolean      route_ignore,
                 shvarFile *   route_content_svformat,
                 GString *     route_content,
                 GString *     route6_content,
                 GError **     error)
{
    /* From here on, we persist data to disk. Before, it was all in-memory
     * only. But we loaded the ifcfg files from disk, and managled our
     * new settings (in-memory). */

    if (!svWriteFileWithoutDirtyWellknown(ifcfg, 0644, error))
        return FALSE;

    write_ip4_aliases(connection, svFileGetName(ifcfg));

    if (!write_blobs(blobs, error))
        return FALSE;

    if (!write_secrets(ifcfg, secrets, error))
        return FALSE;

    if (!route_ignore) {
        gs_free char *route_path = utils_get_route_path(svFileGetName(ifcfg));

        if (!route_content && !route_content_svformat)
            (void) unlink(route_path);
        else {
            nm_assert(route_content_svformat || route_content);
            if (route_content_svformat) {
                if (!svWriteFileWithoutDirtyWellknown(route_content_svformat, 0644, error))
                    return FALSE;
            } else {
                if (!g_file_set_contents(route_path,
                                         route_content->str,
                                         route_content->len,
                                         NULL)) {
                    g_set_error(error,
                                NM_SETTINGS_ERROR,
                                NM_SETTINGS_ERROR_FAILED,
                                "Writing route file '%s' failed",
                                route_path);
                    return FALSE;
                }
            }
        }
    }

    if (!route_ignore) {
        gs_free char *route6_path = utils_get_route6_path(svFileGetName(ifcfg));

        if (!route6_content)
            (void) unlink(route6_path);
        else {
            if (!g_file_set_contents(route6_path, route6_content->str, route6_content->len, NULL)) {
                g_set_error(error,
                            NM_SETTINGS_ERROR,
                            NM_SETTINGS_ERROR_FAILED,
                            "Writing route6 file '%s' failed",
                            route6_path);
                return FALSE;
            }
        }
    }

    return TRUE;
}

gboolean
nms_ifcfg_rh_writer_write_connection(NMConnection *                  connection,
                                     const char *                    ifcfg_dir,
                                     const char *                    filename,
                                     NMSIfcfgRHWriterAllowFilenameCb allow_filename_cb,
                                     gpointer                        allow_filename_user_data,
                                     char **                         out_filename,
                                     NMConnection **                 out_reread,
                                     gboolean *                      out_reread_same,
                                     GError **                       error)
{
    nm_auto_shvar_file_close shvarFile *ifcfg                  = NULL;
    nm_auto_free_gstring GString *route_content                = NULL;
    gboolean                      route_ignore                 = FALSE;
    nm_auto_shvar_file_close shvarFile *route_content_svformat = NULL;
    nm_auto_free_gstring GString *route6_content               = NULL;
    gs_unref_hashtable GHashTable *secrets                     = NULL;
    gs_unref_hashtable GHashTable *blobs                       = NULL;

    nm_assert(!out_reread || !*out_reread);

    if (!do_write_construct(connection,
                            ifcfg_dir,
                            filename,
                            allow_filename_cb,
                            allow_filename_user_data,
                            &ifcfg,
                            &blobs,
                            &secrets,
                            &route_ignore,
                            &route_content_svformat,
                            &route_content,
                            &route6_content,
                            error))
        return FALSE;

    _LOGT("write: write connection %s (%s) to file \"%s\"",
          nm_connection_get_id(connection),
          nm_connection_get_uuid(connection),
          svFileGetName(ifcfg));

    if (!do_write_to_disk(connection,
                          ifcfg,
                          blobs,
                          secrets,
                          route_ignore,
                          route_content_svformat,
                          route_content,
                          route6_content,
                          error))
        return FALSE;

    /* Note that we just wrote the connection to disk, and re-read it from there.
     * That is racy if somebody else modifies the connection.
     * That race is why we must not tread a failure to re-read the profile
     * as an error.
     *
     * FIXME: a much better solution might be, to re-read the connection only based
     * on the in-memory representation of what we collected above. But the reader
     * does not yet allow to inject the configuration. */
    if (out_reread || out_reread_same) {
        gs_unref_object NMConnection *reread      = NULL;
        gboolean                      reread_same = FALSE;
        gs_free_error GError *local               = NULL;
        gs_free char *        unhandled           = NULL;

        reread = connection_from_file(svFileGetName(ifcfg), &unhandled, &local, NULL);
        nm_assert((NM_IS_CONNECTION(reread) && !local) || (!reread && local));

        if (!reread) {
            _LOGW("write: failure to re-read connection \"%s\": %s",
                  svFileGetName(ifcfg),
                  local->message);
        } else if (unhandled) {
            g_clear_object(&reread);
            _LOGW("write: failure to re-read connection \"%s\": %s",
                  svFileGetName(ifcfg),
                  "connection is unhandled");
        } else {
            /* ifcfg-rh doesn't support the 'timestamp' property, let's add it here */
            g_object_set(nm_connection_get_setting_connection(reread),
                         NM_SETTING_CONNECTION_TIMESTAMP,
                         nm_setting_connection_get_timestamp(
                             nm_connection_get_setting_connection(connection)),
                         NULL);
            if (out_reread_same) {
                reread_same =
                    nm_connection_compare(reread, connection, NM_SETTING_COMPARE_FLAG_EXACT);
                if (!reread_same) {
                    _LOGD("write: connection %s (%s) was modified by persisting it to \"%s\" ",
                          nm_connection_get_id(connection),
                          nm_connection_get_uuid(connection),
                          svFileGetName(ifcfg));
                }
            }
        }

        NM_SET_OUT(out_reread, g_steal_pointer(&reread));
        NM_SET_OUT(out_reread_same, reread_same);
    }

    /* Only return the filename if this was a newly written ifcfg */
    if (out_filename && !filename)
        *out_filename = g_strdup(svFileGetName(ifcfg));

    return TRUE;
}

gboolean
nms_ifcfg_rh_writer_can_write_connection(NMConnection *connection, GError **error)
{
    const char *type, *id;

    type = nm_connection_get_connection_type(connection);
    if (NM_IN_STRSET(type,
                     NM_SETTING_VLAN_SETTING_NAME,
                     NM_SETTING_WIRELESS_SETTING_NAME,
                     NM_SETTING_INFINIBAND_SETTING_NAME,
                     NM_SETTING_BOND_SETTING_NAME,
                     NM_SETTING_TEAM_SETTING_NAME,
                     NM_SETTING_BRIDGE_SETTING_NAME))
        return TRUE;
    if (nm_streq0(type, NM_SETTING_WIRED_SETTING_NAME)
        && !nm_connection_get_setting_pppoe(connection))
        return TRUE;

    id = nm_connection_get_id(connection);
    g_set_error(error,
                NM_SETTINGS_ERROR,
                NM_SETTINGS_ERROR_FAILED,
                "The ifcfg-rh plugin cannot write the connection %s%s%s (type %s%s%s)",
                NM_PRINT_FMT_QUOTE_STRING(id),
                NM_PRINT_FMT_QUOTE_STRING(type));
    return FALSE;
}
