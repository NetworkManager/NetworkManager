/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-wifi-utils.h"

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <stdlib.h>

#include "nm-utils.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-core-aux-intern/nm-common-macros.h"
#include "libnm-base/nm-config-base.h"

static gboolean
verify_no_wep(NMSettingWirelessSecurity *s_wsec, const char *tag, GError **error)
{
    if (nm_setting_wireless_security_get_wep_key(s_wsec, 0)
        || nm_setting_wireless_security_get_wep_key(s_wsec, 1)
        || nm_setting_wireless_security_get_wep_key(s_wsec, 2)
        || nm_setting_wireless_security_get_wep_key(s_wsec, 3)
        || nm_setting_wireless_security_get_wep_tx_keyidx(s_wsec)
        || nm_setting_wireless_security_get_wep_key_type(s_wsec)) {
        /* Dynamic WEP cannot have any WEP keys set */
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_SETTING,
                    _("%s is incompatible with static WEP keys"),
                    tag);
        g_prefix_error(error, "%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
        return FALSE;
    }

    return TRUE;
}

static gboolean
verify_leap(NMSettingWirelessSecurity *s_wsec,
            NMSetting8021x *           s_8021x,
            gboolean                   adhoc,
            GError **                  error)
{
    const char *key_mgmt, *auth_alg, *leap_username;

    key_mgmt      = nm_setting_wireless_security_get_key_mgmt(s_wsec);
    auth_alg      = nm_setting_wireless_security_get_auth_alg(s_wsec);
    leap_username = nm_setting_wireless_security_get_leap_username(s_wsec);

    /* One (or both) of two things indicates we want LEAP:
     * 1) auth_alg == 'leap'
     * 2) valid leap_username
     *
     * LEAP always requires a LEAP username.
     */

    if (auth_alg) {
        if (!strcmp(auth_alg, "leap")) {
            /* LEAP authentication requires at least a LEAP username */
            if (!leap_username) {
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_MISSING_PROPERTY,
                                    _("LEAP authentication requires a LEAP username"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                               NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
                return FALSE;
            }
        } else if (leap_username) {
            /* Leap username requires 'leap' auth */
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("LEAP username requires 'leap' authentication"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                           NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
            return FALSE;
        }
    }

    if (leap_username) {
        if (key_mgmt && strcmp(key_mgmt, "ieee8021x")) {
            /* LEAP requires ieee8021x key management */
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("LEAP authentication requires IEEE 802.1x key management"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                           NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
            return FALSE;
        }
    }

    /* At this point if auth_alg is set it must be 'leap', and if key_mgmt
     * is set it must be 'ieee8021x'.
     */
    if (leap_username) {
        if (auth_alg)
            g_assert(strcmp(auth_alg, "leap") == 0);
        if (key_mgmt)
            g_assert(strcmp(key_mgmt, "ieee8021x") == 0);

        if (adhoc) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_SETTING,
                                _("LEAP authentication is incompatible with Ad-Hoc mode"));
            g_prefix_error(error, "%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
            return FALSE;
        }

        if (!verify_no_wep(s_wsec, "LEAP", error))
            return FALSE;

        if (s_8021x) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_SETTING,
                                _("LEAP authentication is incompatible with 802.1x setting"));
            g_prefix_error(error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
verify_no_wpa(NMSettingWirelessSecurity *s_wsec, const char *tag, GError **error)
{
    const char *key_mgmt;
    int         n, i;

    key_mgmt = nm_setting_wireless_security_get_key_mgmt(s_wsec);
    if (key_mgmt && !strncmp(key_mgmt, "wpa", 3)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("a connection using '%s' authentication cannot use WPA key management"),
                    tag);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                       NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
        return FALSE;
    }

    if (nm_setting_wireless_security_get_num_protos(s_wsec)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("a connection using '%s' authentication cannot specify WPA protocols"),
                    tag);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                       NM_SETTING_WIRELESS_SECURITY_PROTO);
        return FALSE;
    }

    n = nm_setting_wireless_security_get_num_pairwise(s_wsec);
    for (i = 0; i < n; i++) {
        const char *pw;

        pw = nm_setting_wireless_security_get_pairwise(s_wsec, i);
        if (!strcmp(pw, "tkip") || !strcmp(pw, "ccmp")) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("a connection using '%s' authentication cannot specify WPA ciphers"),
                        tag);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                           NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
            return FALSE;
        }
    }

    n = nm_setting_wireless_security_get_num_groups(s_wsec);
    for (i = 0; i < n; i++) {
        const char *gr;

        gr = nm_setting_wireless_security_get_group(s_wsec, i);
        if (strcmp(gr, "wep40") && strcmp(gr, "wep104")) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("a connection using '%s' authentication cannot specify WPA ciphers"),
                        tag);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                           NM_SETTING_WIRELESS_SECURITY_GROUP);
            return FALSE;
        }
    }

    if (nm_setting_wireless_security_get_psk(s_wsec)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("a connection using '%s' authentication cannot specify a WPA password"),
                    tag);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                       NM_SETTING_WIRELESS_SECURITY_PSK);
        return FALSE;
    }

    return TRUE;
}

static gboolean
verify_dynamic_wep(NMSettingWirelessSecurity *s_wsec,
                   NMSetting8021x *           s_8021x,
                   gboolean                   adhoc,
                   GError **                  error)
{
    const char *key_mgmt, *auth_alg, *leap_username;

    key_mgmt      = nm_setting_wireless_security_get_key_mgmt(s_wsec);
    auth_alg      = nm_setting_wireless_security_get_auth_alg(s_wsec);
    leap_username = nm_setting_wireless_security_get_leap_username(s_wsec);

    g_return_val_if_fail(leap_username == NULL, TRUE);

    if (key_mgmt) {
        if (!strcmp(key_mgmt, "ieee8021x")) {
            if (!s_8021x) {
                /* 802.1x key management requires an 802.1x setting */
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_MISSING_SETTING,
                                    _("Dynamic WEP requires an 802.1x setting"));
                g_prefix_error(error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
                return FALSE;
            }

            if (auth_alg && strcmp(auth_alg, "open")) {
                /* 802.1x key management must use "open" authentication */
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    _("Dynamic WEP requires 'open' authentication"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                               NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
                return FALSE;
            }

            /* Dynamic WEP incompatible with anything static WEP related */
            if (!verify_no_wep(s_wsec, "Dynamic WEP", error))
                return FALSE;
        } else if (!strcmp(key_mgmt, "none")) {
            if (s_8021x) {
                /* 802.1x setting requires 802.1x key management */
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    _("Dynamic WEP requires 'ieee8021x' key management"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                               NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
                return FALSE;
            }
        }
    } else if (s_8021x) {
        /* 802.1x setting incompatible with anything but 'open' auth */
        if (auth_alg && strcmp(auth_alg, "open")) {
            /* 802.1x key management must use "open" authentication */
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("Dynamic WEP requires 'open' authentication"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                           NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
            return FALSE;
        }

        /* Dynamic WEP incompatible with anything static WEP related */
        if (!verify_no_wep(s_wsec, "Dynamic WEP", error))
            return FALSE;
    }

    return TRUE;
}

static gboolean
verify_wpa_psk(NMSettingWirelessSecurity *s_wsec,
               NMSetting8021x *           s_8021x,
               gboolean                   adhoc,
               guint32                    wpa_flags,
               guint32                    rsn_flags,
               GError **                  error)
{
    const char *key_mgmt, *auth_alg;

    key_mgmt = nm_setting_wireless_security_get_key_mgmt(s_wsec);
    auth_alg = nm_setting_wireless_security_get_auth_alg(s_wsec);

    if (!nm_streq0(key_mgmt, "wpa-psk"))
        return TRUE;

    if (s_8021x) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_SETTING,
                            _("WPA-PSK authentication is incompatible with 802.1x"));
        g_prefix_error(error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
        return FALSE;
    }

    if (auth_alg && !nm_streq(auth_alg, "open")) {
        /* WPA must use "open" authentication */
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("WPA-PSK requires 'open' authentication"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                       NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
        return FALSE;
    }

    /* Make sure the AP's capabilities support WPA-PSK */
    if (!(wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
        && !(rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("Access point does not support PSK but setting requires it"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                       NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
        return FALSE;
    }

    if (adhoc) {
        /* Ad-Hoc RSN requires 'rsn' proto, 'ccmp' pairwise, and 'ccmp' group */
        if (nm_setting_wireless_security_get_num_protos(s_wsec) != 1
            || !nm_streq0(nm_setting_wireless_security_get_proto(s_wsec, 0), "rsn")) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("WPA Ad-Hoc authentication requires 'rsn' protocol"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                           NM_SETTING_WIRELESS_SECURITY_PROTO);
            return FALSE;
        }

        if (nm_setting_wireless_security_get_num_pairwise(s_wsec) != 1
            || !nm_streq0(nm_setting_wireless_security_get_pairwise(s_wsec, 0), "ccmp")) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("WPA Ad-Hoc authentication requires 'ccmp' pairwise cipher"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                           NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
            return FALSE;
        }

        if (nm_setting_wireless_security_get_num_groups(s_wsec) != 1
            || !nm_streq0(nm_setting_wireless_security_get_group(s_wsec, 0), "ccmp")) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("WPA Ad-Hoc requires 'ccmp' group cipher"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                           NM_SETTING_WIRELESS_SECURITY_GROUP);
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
verify_wpa_eap(NMSettingWirelessSecurity *s_wsec,
               NMSetting8021x *           s_8021x,
               guint32                    wpa_flags,
               guint32                    rsn_flags,
               GError **                  error)
{
    const char *key_mgmt, *auth_alg;
    gboolean    is_wpa_eap = FALSE;

    key_mgmt = nm_setting_wireless_security_get_key_mgmt(s_wsec);
    auth_alg = nm_setting_wireless_security_get_auth_alg(s_wsec);

    if (key_mgmt) {
        if (NM_IN_STRSET(key_mgmt, "wpa-eap", "wpa-eap-suite-b-192")) {
            if (!s_8021x) {
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_MISSING_SETTING,
                                    _("WPA-EAP authentication requires an 802.1x setting"));
                g_prefix_error(error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
                return FALSE;
            }

            if (auth_alg && strcmp(auth_alg, "open")) {
                /* WPA must use "open" authentication */
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    _("WPA-EAP requires 'open' authentication"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                               NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
                return FALSE;
            }

            is_wpa_eap = TRUE;
        } else if (s_8021x) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_SETTING,
                                _("802.1x setting requires 'wpa-eap' key management"));
            g_prefix_error(error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
            return FALSE;
        }
    }

    if (is_wpa_eap || s_8021x) {
        /* Make sure the AP's capabilities support WPA-EAP */
        if (!(wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
            && !(rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
            && !(rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_EAP_SUITE_B_192)) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_SETTING,
                                _("Access point does not support 802.1x but setting requires it"));
            g_prefix_error(error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
verify_adhoc(NMSettingWirelessSecurity *s_wsec,
             NMSetting8021x *           s_8021x,
             gboolean                   adhoc,
             GError **                  error)
{
    const char *key_mgmt = NULL, *leap_username = NULL, *auth_alg = NULL;

    if (!adhoc)
        return TRUE;

    if (s_wsec) {
        key_mgmt      = nm_setting_wireless_security_get_key_mgmt(s_wsec);
        auth_alg      = nm_setting_wireless_security_get_auth_alg(s_wsec);
        leap_username = nm_setting_wireless_security_get_leap_username(s_wsec);
    }

    if (key_mgmt && !NM_IN_STRSET(key_mgmt, "none", "wpa-psk")) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("Ad-Hoc mode requires 'none' or 'wpa-psk' key management"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                       NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
        return FALSE;
    }

    if (s_8021x) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_SETTING,
                            _("Ad-Hoc mode is incompatible with 802.1x security"));
        g_prefix_error(error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
        return FALSE;
    }

    if (leap_username) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("Ad-Hoc mode is incompatible with LEAP security"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                       NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
        return FALSE;
    }

    if (auth_alg && !nm_streq(auth_alg, "open")) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("Ad-Hoc mode requires 'open' authentication"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                       NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
        return FALSE;
    }

    return TRUE;
}

gboolean
nm_wifi_utils_complete_connection(GBytes *      ap_ssid,
                                  const char *  bssid,
                                  _NM80211Mode  ap_mode,
                                  guint32       ap_freq,
                                  guint32       ap_flags,
                                  guint32       ap_wpa_flags,
                                  guint32       ap_rsn_flags,
                                  NMConnection *connection,
                                  gboolean      lock_bssid,
                                  GError **     error)
{
    NMSettingWireless *        s_wifi;
    NMSettingWirelessSecurity *s_wsec;
    NMSetting8021x *           s_8021x;
    GBytes *                   ssid;
    const char *               mode, *key_mgmt, *auth_alg, *leap_username;
    gboolean                   adhoc = FALSE;
    gboolean                   mesh  = FALSE;

    s_wifi = nm_connection_get_setting_wireless(connection);
    g_assert(s_wifi);
    s_wsec  = nm_connection_get_setting_wireless_security(connection);
    s_8021x = nm_connection_get_setting_802_1x(connection);

    /* Fill in missing SSID */
    ssid = nm_setting_wireless_get_ssid(s_wifi);
    if (!ssid)
        g_object_set(G_OBJECT(s_wifi), NM_SETTING_WIRELESS_SSID, ap_ssid, NULL);
    else if (!ap_ssid || !g_bytes_equal(ssid, ap_ssid)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("connection does not match access point"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SETTING_NAME,
                       NM_SETTING_WIRELESS_SSID);
        return FALSE;
    }

    if (lock_bssid && !nm_setting_wireless_get_bssid(s_wifi))
        g_object_set(G_OBJECT(s_wifi), NM_SETTING_WIRELESS_BSSID, bssid, NULL);

    /* And mode */
    mode = nm_setting_wireless_get_mode(s_wifi);
    if (mode) {
        gboolean valid = FALSE;

        /* Make sure the supplied mode matches the AP's */
        if (!strcmp(mode, NM_SETTING_WIRELESS_MODE_INFRA)
            || !strcmp(mode, NM_SETTING_WIRELESS_MODE_AP)) {
            if (ap_mode == _NM_802_11_MODE_INFRA)
                valid = TRUE;
        } else if (!strcmp(mode, NM_SETTING_WIRELESS_MODE_ADHOC)) {
            if (ap_mode == _NM_802_11_MODE_ADHOC)
                valid = TRUE;
            adhoc = TRUE;
        } else if (!strcmp(mode, NM_SETTING_WIRELESS_MODE_MESH)) {
            if (ap_mode == _NM_802_11_MODE_MESH)
                valid = TRUE;
            mesh = TRUE;
        }

        if (valid == FALSE) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("connection does not match access point"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SETTING_NAME,
                           NM_SETTING_WIRELESS_MODE);
            return FALSE;
        }
    } else {
        mode = NM_SETTING_WIRELESS_MODE_INFRA;
        if (ap_mode == _NM_802_11_MODE_ADHOC) {
            mode  = NM_SETTING_WIRELESS_MODE_ADHOC;
            adhoc = TRUE;
        } else if (ap_mode == _NM_802_11_MODE_MESH) {
            mode = NM_SETTING_WIRELESS_MODE_MESH;
            mesh = TRUE;
        }
        g_object_set(G_OBJECT(s_wifi), NM_SETTING_WIRELESS_MODE, mode, NULL);
    }

    /* For now mesh requires channel and band, fill them only if both not present.
     * Do not check existing values against an existing ap/mesh point,
     * mesh join will start a new network if required */
    if (mesh) {
        const char *band;
        guint32     channel;
        gboolean    band_valid = TRUE;
        gboolean    chan_valid = TRUE;
        gboolean    valid;

        band    = nm_setting_wireless_get_band(s_wifi);
        channel = nm_setting_wireless_get_channel(s_wifi);

        valid = ((band == NULL) && (channel == 0)) || ((band != NULL) && (channel != 0));

        if ((band == NULL) && (channel == 0)) {
            channel = nm_utils_wifi_freq_to_channel(ap_freq);
            if (channel) {
                g_object_set(s_wifi, NM_SETTING_WIRELESS_CHANNEL, channel, NULL);
            } else {
                chan_valid = FALSE;
            }

            band = nm_utils_wifi_freq_to_band(ap_freq);
            if (band) {
                g_object_set(s_wifi, NM_SETTING_WIRELESS_BAND, band, NULL);
            } else {
                band_valid = FALSE;
            }
        }

        if (!valid || !chan_valid || !band_valid) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("connection does not match mesh point"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_WIRELESS_SETTING_NAME,
                           NM_SETTING_WIRELESS_MODE);
            return FALSE;
        }
    }

    /* Security */

    /* Open */
    if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY) && (ap_wpa_flags == NM_802_11_AP_SEC_NONE)
        && (ap_rsn_flags == NM_802_11_AP_SEC_NONE)) {
        /* Make sure the connection doesn't specify security */
        if (s_wsec || s_8021x) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_SETTING,
                                _("Access point is unencrypted but setting specifies security"));
            if (s_wsec)
                g_prefix_error(error, "%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
            else
                g_prefix_error(error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
            return FALSE;
        }
        return TRUE;
    }

    /* Everything else requires security */
    if (!s_wsec) {
        s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new();
        nm_connection_add_setting(connection, NM_SETTING(s_wsec));
    }

    key_mgmt      = nm_setting_wireless_security_get_key_mgmt(s_wsec);
    auth_alg      = nm_setting_wireless_security_get_auth_alg(s_wsec);
    leap_username = nm_setting_wireless_security_get_leap_username(s_wsec);

    /* Ad-Hoc checks */
    if (!verify_adhoc(s_wsec, s_8021x, adhoc, error))
        return FALSE;

    /* Static WEP, Dynamic WEP, or LEAP */
    if ((ap_flags & NM_802_11_AP_FLAGS_PRIVACY) && (ap_wpa_flags == NM_802_11_AP_SEC_NONE)
        && (ap_rsn_flags == NM_802_11_AP_SEC_NONE)) {
        const char *tag            = "WEP";
        gboolean    is_dynamic_wep = FALSE;

        if (!verify_leap(s_wsec, s_8021x, adhoc, error))
            return FALSE;

        if (leap_username) {
            tag = "LEAP";
        } else {
            /* Static or Dynamic WEP */
            if (!verify_dynamic_wep(s_wsec, s_8021x, adhoc, error))
                return FALSE;

            if (s_8021x || (key_mgmt && !strcmp(key_mgmt, "ieee8021x"))) {
                is_dynamic_wep = TRUE;
                tag            = "Dynamic WEP";
            }
        }

        /* Nothing WPA-related can be set */
        if (!verify_no_wpa(s_wsec, tag, error))
            return FALSE;

        if (leap_username) {
            /* LEAP */
            g_object_set(s_wsec,
                         NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
                         "ieee8021x",
                         NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
                         "leap",
                         NULL);
        } else if (is_dynamic_wep) {
            /* Dynamic WEP */
            g_object_set(s_wsec,
                         NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
                         "ieee8021x",
                         NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
                         "open",
                         NULL);

            if (s_8021x) {
                /* Dynamic WEP requires a valid 802.1x setting since we can't
                 * autocomplete 802.1x.
                 */
                if (!nm_setting_verify(NM_SETTING(s_8021x), NULL, error))
                    return FALSE;
            }
        } else {
            /* Static WEP */
            g_object_set(s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none", NULL);
        }

        return TRUE;
    }

    /* WPA/RSN */
    g_assert(ap_wpa_flags || ap_rsn_flags);

    /* Ensure key management is valid for WPA */
    if ((key_mgmt && !strcmp(key_mgmt, "ieee8021x")) || leap_username) {
        g_set_error_literal(
            error,
            NM_CONNECTION_ERROR,
            NM_CONNECTION_ERROR_INVALID_PROPERTY,
            _("WPA authentication is incompatible with non-EAP (original) LEAP or Dynamic WEP"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                       NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
        return FALSE;
    }

    /* 'shared' auth incompatible with any type of WPA */
    if (auth_alg && strcmp(auth_alg, "open")) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("WPA authentication is incompatible with Shared Key authentication"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                       NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
        return FALSE;
    }

    if (!verify_no_wep(s_wsec, "WPA", error))
        return FALSE;

    if (!verify_wpa_psk(s_wsec, s_8021x, adhoc, ap_wpa_flags, ap_rsn_flags, error))
        return FALSE;

    if (!adhoc && !verify_wpa_eap(s_wsec, s_8021x, ap_wpa_flags, ap_rsn_flags, error))
        return FALSE;

    if (adhoc) {
        g_object_set(s_wsec,
                     NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
                     "wpa-psk",
                     NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
                     "open",
                     NULL);
        nm_setting_wireless_security_add_proto(s_wsec, "rsn");
        nm_setting_wireless_security_add_pairwise(s_wsec, "ccmp");
        nm_setting_wireless_security_add_group(s_wsec, "ccmp");
    } else if (s_8021x) {
        g_object_set(s_wsec,
                     NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
                     "wpa-eap",
                     NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
                     "open",
                     NULL);
        /* Leave proto/pairwise/group as client set them; if they are unset the
         * supplicant will figure out the best combination at connect time.
         */

        /* 802.1x also requires the client to completely fill in the 8021x
         * setting.  Since there's so much configuration required for it, there's
         * no way it can be automatically completed.
         */
    } else if (nm_streq0(key_mgmt, "wpa-psk")
               || (ap_rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_SAE
                   && (ap_wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK
                       || ap_rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK))) {
        g_object_set(s_wsec,
                     NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
                     "wpa-psk",
                     NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
                     "open",
                     NULL);
    } else if (nm_streq0(key_mgmt, "sae") || (ap_rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_SAE)) {
        g_object_set(s_wsec,
                     NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
                     "sae",
                     NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
                     "open",
                     NULL);
    } else if (nm_streq0(key_mgmt, "owe")
               || NM_FLAGS_ANY(ap_rsn_flags,
                               NM_802_11_AP_SEC_KEY_MGMT_OWE | NM_802_11_AP_SEC_KEY_MGMT_OWE_TM)) {
        g_object_set(s_wsec,
                     NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
                     "owe",
                     NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
                     "open",
                     NULL);
    } else if (ap_wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK
               || ap_rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK) {
        g_object_set(s_wsec,
                     NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
                     "wpa-psk",
                     NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
                     "open",
                     NULL);
        /* Leave proto/pairwise/group as client set them; if they are unset the
         * supplicant will figure out the best combination at connect time.
         */
    } else if (nm_streq0(key_mgmt, "wpa-eap-suite-b-192")
               || (ap_rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_EAP_SUITE_B_192)) {
        g_object_set(s_wsec,
                     NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
                     "wpa-eap-suite-b-192",
                     NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
                     "open",
                     NULL);
    } else {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_FAILED,
                            _("Failed to determine AP security information"));
        return FALSE;
    }

    return TRUE;
}

gboolean
nm_wifi_utils_is_manf_default_ssid(GBytes *ssid)
{
    const guint8 *ssid_p;
    gsize         ssid_l;
    int           i;
    /*
     * List of manufacturer default SSIDs that are often unchanged by users.
     *
     * NOTE: this list should *not* contain networks that you would like to
     * automatically roam to like "Starbucks" or "AT&T" or "T-Mobile HotSpot".
     */
    static const char *manf_defaults[] = {
        "linksys",
        "linksys-a",
        "linksys-g",
        "default",
        "belkin54g",
        "NETGEAR",
        "o2DSL",
        "WLAN",
        "ALICE-WLAN",
        "Speedport W 501V",
        "TURBONETT",
    };

    ssid_p = g_bytes_get_data(ssid, &ssid_l);

    for (i = 0; i < G_N_ELEMENTS(manf_defaults); i++) {
        if (ssid_l == strlen(manf_defaults[i])) {
            if (memcmp(manf_defaults[i], ssid_p, ssid_l) == 0)
                return TRUE;
        }
    }
    return FALSE;
}

/* To be used for connections where the SSID has been validated before */
gboolean
nm_wifi_connection_get_iwd_ssid_and_security(NMConnection *        connection,
                                             char **               ssid,
                                             NMIwdNetworkSecurity *security)
{
    NMSettingWireless *        s_wireless;
    NMSettingWirelessSecurity *s_wireless_sec;
    const char *               key_mgmt = NULL;

    s_wireless = nm_connection_get_setting_wireless(connection);
    if (!s_wireless)
        return FALSE;

    if (ssid) {
        GBytes *    bytes = nm_setting_wireless_get_ssid(s_wireless);
        gsize       ssid_len;
        const char *ssid_str = (const char *) g_bytes_get_data(bytes, &ssid_len);

        nm_assert(bytes && g_utf8_validate(ssid_str, ssid_len, NULL));
        NM_SET_OUT(ssid, g_strndup(ssid_str, ssid_len));
    }

    if (!security)
        return TRUE;

    s_wireless_sec = nm_connection_get_setting_wireless_security(connection);
    if (!s_wireless_sec) {
        NM_SET_OUT(security, NM_IWD_NETWORK_SECURITY_OPEN);
        return TRUE;
    }

    key_mgmt = nm_setting_wireless_security_get_key_mgmt(s_wireless_sec);
    nm_assert(key_mgmt);

    if (NM_IN_STRSET(key_mgmt, "none", "ieee8021x"))
        NM_SET_OUT(security, NM_IWD_NETWORK_SECURITY_WEP);
    else if (nm_streq(key_mgmt, "owe"))
        NM_SET_OUT(security, NM_IWD_NETWORK_SECURITY_OPEN);
    else if (NM_IN_STRSET(key_mgmt, "wpa-psk", "sae"))
        NM_SET_OUT(security, NM_IWD_NETWORK_SECURITY_PSK);
    else if (nm_streq(key_mgmt, "wpa-eap"))
        NM_SET_OUT(security, NM_IWD_NETWORK_SECURITY_8021X);
    else
        return FALSE;

    return TRUE;
}

/*****************************************************************************/

/* Builds the IWD network configuration file name for a given SSID
 * and security type pair.  The SSID should be valid UTF-8 and in
 * any case must contain no NUL-bytes.  If @ssid is NUL-terminated,
 * @ssid_len can be -1 instead of actual SSID length.
 */
char *
nm_wifi_utils_get_iwd_config_filename(const char *         ssid,
                                      gssize               ssid_len,
                                      NMIwdNetworkSecurity security)
{
    const char *security_suffix;
    const char *ptr;
    gboolean    alnum_ssid = TRUE;

    for (ptr = ssid; ssid_len != 0 && *ptr != '\0'; ptr++, ssid_len--)
        if (!g_ascii_isalnum(*ptr) && !strchr("-_ ", *ptr))
            alnum_ssid = FALSE;

    g_return_val_if_fail(ptr != ssid && ptr - ssid <= NM_IW_ESSID_MAX_SIZE, NULL);

    switch (security) {
    case NM_IWD_NETWORK_SECURITY_OPEN:
        security_suffix = "open";
        break;
    case NM_IWD_NETWORK_SECURITY_PSK:
        security_suffix = "psk";
        break;
    case NM_IWD_NETWORK_SECURITY_8021X:
        security_suffix = "8021x";
        break;
    default:
        return NULL;
    }

    if (alnum_ssid) {
        return g_strdup_printf("%.*s.%s", (int) (ptr - ssid), ssid, security_suffix);
    } else {
        char ssid_buf[NM_IW_ESSID_MAX_SIZE * 2 + 1];

        return g_strdup_printf("=%s.%s",
                               nm_utils_bin2hexstr_full(ssid, ptr - ssid, '\0', FALSE, ssid_buf),
                               security_suffix);
    }
}

/*****************************************************************************/

#define SECRETS_DONT_STORE_FLAGS \
    (NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_SAVED)

static gboolean
psk_setting_to_iwd_config(GKeyFile *file, NMSettingWirelessSecurity *s_wsec, GError **error)
{
    NMSettingSecretFlags psk_flags = nm_setting_wireless_security_get_psk_flags(s_wsec);
    const char *         psk       = nm_setting_wireless_security_get_psk(s_wsec);
    gsize                psk_len;
    guint8               buffer[32];
    const char *         key_mgmt = nm_setting_wireless_security_get_key_mgmt(s_wsec);

    if (!psk || NM_FLAGS_ANY(psk_flags, SECRETS_DONT_STORE_FLAGS)) {
        if (NM_FLAGS_ANY(psk_flags, SECRETS_DONT_STORE_FLAGS)) {
            nm_log_info(
                LOGD_WIFI,
                "IWD network config is being created wihout the PSK but IWD will save the PSK on "
                "successful activation not honoring the psk-flags property");
        }
        return TRUE;
    }

    psk_len = strlen(psk);
    if (nm_streq0(key_mgmt, "sae")) {
        g_key_file_set_string(file, "Security", "Passphrase", psk);
    } else if (psk_len >= 8 && psk_len <= 63) {
        g_key_file_set_string(file, "Security", "Passphrase", psk);
    } else if (psk_len == 64 && nm_utils_hexstr2bin_buf(psk, FALSE, FALSE, NULL, buffer)) {
        g_key_file_set_string(file, "Security", "PreSharedKey", psk);
    } else {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "Unknown PSK format");
        return FALSE;
    }

    return TRUE;
}

static gboolean
eap_certs_to_iwd_config(GKeyFile *      file,
                        NMSetting8021x *s_8021x,
                        bool            phase2,
                        char *          iwd_prefix,
                        GError **       error)
{
    NMSetting8021xCKScheme ca_cert_scheme =
        phase2 ? nm_setting_802_1x_get_phase2_ca_cert_scheme(s_8021x)
               : nm_setting_802_1x_get_ca_cert_scheme(s_8021x);
    NMSetting8021xCKScheme client_cert_scheme =
        phase2 ? nm_setting_802_1x_get_phase2_client_cert_scheme(s_8021x)
               : nm_setting_802_1x_get_client_cert_scheme(s_8021x);
    NMSetting8021xCKScheme key_scheme;
    NMSettingSecretFlags   key_password_flags;
    const char *           ca_path = phase2 ? nm_setting_802_1x_get_phase2_ca_path(s_8021x)
                                            : nm_setting_802_1x_get_ca_path(s_8021x);
    const char *           cert_path;
    const char *           key_path = NULL;
    const char *           key_password;
    const char *           domain_suffix_match;
    const char *           domain_match;
    char                   setting_buf[128];

    /* TODO: should check that all certificates and the key are RSA */
    /* Note: up to IWD 1.9 only the PEM encoding was supported for certificates
     * and only PKCS#8 PEM for keys but we don't know the IWD version here.
     * From IWD 1.10 raw (DER) X.509 certificates and PKCS#12 are also supported
     * for certificates but a certificate list or chain still has to be PEM
     * (i.e. if it contains more than one certificate.)  Raw PKCS#12 and
     * old-style OpenSSL PEM formats are also supported for keys.  Hopefully
     * this is in practice the same set of file:// formats as supported by
     * nm_crypto_* / wpa_supplicant so we need no conversions here.
     */

    if (nm_setting_802_1x_get_system_ca_certs(s_8021x)) {
        /* Either overrides or is added to the certificates in (phase2-)ca-cert
         * and ca-path depending on whether it points to a file or a directory.
         * We can't ignore this property so it's an error if it is set.
         * Fortunately not used by nm-connection-editor.
         */
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "The system-ca-certs property is not supported");
        return FALSE;
    }

    if (ca_path) {
        /* To support this (and this could be applied to system-ca-certs as
         * well) we'd have to scan the directory, parse the certificates and
         * write a new certificate-list file to point to in the IWD config.
         * This is going to create issues of where to store these files, for
         * how long and with what permission bits.  Fortunately this doesn't
         * seem to be used by nm-connection-editor either.
         *
         * That file would also have to contain whatever the (phase2-)ca-cert
         * propterty points to because IWD has only one CACert setting per
         * phase.
         */
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "The (phase2-)ca-path property is not supported");
        return FALSE;
    }

    if (ca_cert_scheme != NM_SETTING_802_1X_CK_SCHEME_UNKNOWN) {
        if (ca_cert_scheme != NM_SETTING_802_1X_CK_SCHEME_PATH) {
            /* To support the blob scheme we'd have to either convert the
             * certificate data into a PEM payload and embed the PEM file in
             * the IWD config file, which is not supported by GKeyFile, or write
             * it into a new file to point to in the IWD config.  This is again
             * is going to create issues of where to store these files, for how
             * long and with what permission bits.  Fortunately this scheme isn't
             * used in nm-connection-editor either.
             *
             * PKCS#11 is not supported by IWD in any way so we don't need to
             * support the PKCS#11 URI scheme.
             *
             * If scheme is unknown, assume no value is set.
             */
            g_set_error_literal(
                error,
                NM_CONNECTION_ERROR,
                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                "(phase2-)ca-cert property schemes other than file:// not supported");
            return FALSE;
        }

        cert_path = phase2 ? nm_setting_802_1x_get_phase2_ca_cert_path(s_8021x)
                           : nm_setting_802_1x_get_ca_cert_path(s_8021x);
        if (cert_path)
            g_key_file_set_string(file,
                                  "Security",
                                  nm_sprintf_buf(setting_buf, "%s%s", iwd_prefix, "CACert"),
                                  cert_path);
    }

    if (client_cert_scheme == NM_SETTING_802_1X_CK_SCHEME_UNKNOWN)
        goto private_key_done;

    if (client_cert_scheme != NM_SETTING_802_1X_CK_SCHEME_PATH) {
        g_set_error_literal(
            error,
            NM_CONNECTION_ERROR,
            NM_CONNECTION_ERROR_INVALID_PROPERTY,
            "(phase2-)client-cert property schemes other than file:// not supported");
        return FALSE;
    }

    cert_path = phase2 ? nm_setting_802_1x_get_phase2_client_cert_path(s_8021x)
                       : nm_setting_802_1x_get_client_cert_path(s_8021x);
    if (!cert_path)
        goto private_key_done;
    g_key_file_set_string(file,
                          "Security",
                          nm_sprintf_buf(setting_buf, "%s%s", iwd_prefix, "ClientCert"),
                          cert_path);

    key_scheme = phase2 ? nm_setting_802_1x_get_phase2_private_key_scheme(s_8021x)
                        : nm_setting_802_1x_get_private_key_scheme(s_8021x);
    if (key_scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
        key_path = phase2 ? nm_setting_802_1x_get_phase2_private_key_path(s_8021x)
                          : nm_setting_802_1x_get_private_key_path(s_8021x);
    if (key_scheme != NM_SETTING_802_1X_CK_SCHEME_PATH || !key_path) {
        /* The same comments apply to writing the key into a temporary file
         * as for the certificates (above), except this is even more
         * sensitive.
         */
        g_set_error_literal(
            error,
            NM_CONNECTION_ERROR,
            NM_CONNECTION_ERROR_INVALID_PROPERTY,
            "(phase2-)private-key property schemes other than file:// not supported");
        return FALSE;
    }
    g_key_file_set_string(file,
                          "Security",
                          nm_sprintf_buf(setting_buf, "%s%s", iwd_prefix, "ClientKey"),
                          key_path);

    key_password       = phase2 ? nm_setting_802_1x_get_phase2_private_key_password(s_8021x)
                                : nm_setting_802_1x_get_private_key_password(s_8021x);
    key_password_flags = phase2 ? nm_setting_802_1x_get_phase2_private_key_password_flags(s_8021x)
                                : nm_setting_802_1x_get_private_key_password_flags(s_8021x);
    if (!key_password || NM_FLAGS_ANY(key_password_flags, SECRETS_DONT_STORE_FLAGS)) {
        g_key_file_set_comment(
            file,
            "Security",
            setting_buf,
            "ClientKeyPassphrase not to be saved, will be queried through the agent if needed",
            NULL);
        goto private_key_done;
    }
    g_key_file_set_string(file,
                          "Security",
                          nm_sprintf_buf(setting_buf, "%s%s", iwd_prefix, "ClientKeyPassphrase"),
                          key_password);

private_key_done:
    if (phase2 ? nm_setting_802_1x_get_phase2_subject_match(s_8021x)
               : nm_setting_802_1x_get_subject_match(s_8021x)) {
        g_set_error_literal(
            error,
            NM_CONNECTION_ERROR,
            NM_CONNECTION_ERROR_INVALID_PROPERTY,
            "(phase2-)subject-match not supported, use domain-match or domain-suffix-match");
        return FALSE;
    }

    if (phase2 ? nm_setting_802_1x_get_num_phase2_altsubject_matches(s_8021x)
               : nm_setting_802_1x_get_num_altsubject_matches(s_8021x)) {
        /* We could convert the "DNS:" entries into a ServerDomainMask but we'd
         * have to leave out the "EMAIL:" and "URI:" types or report error.
         * The interpretation still wouldn't be exactly the same as in
         * wpa_supplicant.
         */
        g_set_error_literal(
            error,
            NM_CONNECTION_ERROR,
            NM_CONNECTION_ERROR_INVALID_PROPERTY,
            "(phase2-)altsubject-matches not supported, use domain-match or domain-suffix-match");
        return FALSE;
    }

    domain_suffix_match = phase2 ? nm_setting_802_1x_get_phase2_domain_suffix_match(s_8021x)
                                 : nm_setting_802_1x_get_domain_suffix_match(s_8021x);
    domain_match        = phase2 ? nm_setting_802_1x_get_phase2_domain_match(s_8021x)
                                 : nm_setting_802_1x_get_domain_match(s_8021x);

    if (domain_suffix_match || domain_match) {
        GString *   s = g_string_sized_new(128);
        const char *ptr;
        const char *end;

        for (ptr = domain_suffix_match; ptr; ptr = *end == ';' ? end + 1 : NULL) {
            if (s->len)
                g_string_append_c(s, ';');
            end = strchrnul(ptr, ';');
            /* Use *.<suffix> to get the suffix match effect */
            g_string_append(s, "*.");
            g_string_append_len(s, ptr, end - ptr);
        }

        /* domain-match can be appended as-is */
        if (domain_match) {
            if (s->len)
                g_string_append_c(s, ';');
            g_string_append(s, domain_match);
        }

        g_key_file_set_string(file,
                              "Security",
                              nm_sprintf_buf(setting_buf, "%s%s", iwd_prefix, "ServerDomainMask"),
                              s->str);
        g_string_free(s, TRUE);
    }

    return TRUE;
}

static void
eap_method_name_to_iwd_config(GKeyFile *file, const char *iwd_prefix, const char *method)
{
    char setting_buf[128];

    g_key_file_set_string(file,
                          "Security",
                          nm_sprintf_buf(setting_buf, "%s%s", iwd_prefix, "Method"),
                          method);
}

static void
eap_optional_identity_to_iwd_config(GKeyFile *file, const char *iwd_prefix, const char *identity)
{
    char setting_buf[128];

    /* The identity is optional for some methods where an authenticator may
     * in theory not ask for it.  For our usage here we treat it as always
     * optional because it can be omitted in the config file if the user
     * wants IWD to query for it on every connection.
     */
    if (identity) {
        g_key_file_set_string(file,
                              "Security",
                              nm_sprintf_buf(setting_buf, "%s%s", iwd_prefix, "Identity"),
                              identity);
    } else {
        g_key_file_set_comment(
            file,
            "Security",
            nm_sprintf_buf(setting_buf, "%s%s", iwd_prefix, "Method"),
            "Identity not to be saved, will be queried through the agent if needed",
            NULL);
    }
}

static gboolean
eap_optional_password_to_iwd_config(GKeyFile *      file,
                                    const char *    iwd_prefix,
                                    NMSetting8021x *s_8021x,
                                    GError **       error)
{
    char                 setting_buf[128];
    const char *         password = nm_setting_802_1x_get_password(s_8021x);
    NMSettingSecretFlags flags    = nm_setting_802_1x_get_password_flags(s_8021x);

    if (!password && nm_setting_802_1x_get_password_raw(s_8021x)) {
        /* IWD doesn't support passwords that can't be encoded in the config
         * file, i.e. containing NUL characters.  Those that don't have NULs
         * could in theory be written to the config file but GKeyFile may not
         * like that if they're no UTF-8, and the password-raw property is
         * not written by nm-connection-editor anyway.
         */
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "Non-UTF-8 passwords are not supported, if the password is UTF-8 set "
                            "the \"password\" property");
        return FALSE;
    }
    if (!password || NM_FLAGS_ANY(flags, SECRETS_DONT_STORE_FLAGS)) {
        return g_key_file_set_comment(file,
                                      "Security",
                                      nm_sprintf_buf(setting_buf, "%s%s", iwd_prefix, "Method"),
                                      "Password not to be saved, will be queried through the agent",
                                      error);
    } else {
        g_key_file_set_string(file,
                              "Security",
                              nm_sprintf_buf(setting_buf, "%s%s", iwd_prefix, "Password"),
                              password);
        return TRUE;
    }
}

static void
eap_phase1_identity_to_iwd_config(GKeyFile *file, const char *iwd_prefix, NMSetting8021x *s_8021x)
{
    const char *phase1_identity = nm_setting_802_1x_get_anonymous_identity(s_8021x);

    if (!phase1_identity) {
        phase1_identity = nm_setting_802_1x_get_identity(s_8021x);

        if (phase1_identity) {
            nm_log_info(LOGD_WIFI,
                        "IWD network config will send the same EAP Identity string in "
                        "plaintext in phase 1 as in phase 2 (encrypted) to mimic legacy "
                        "behavior, set [%s].%s=anonymous to prevent exposing the value",
                        NM_SETTING_802_1X_SETTING_NAME,
                        NM_SETTING_802_1X_ANONYMOUS_IDENTITY);
        }
    }

    eap_optional_identity_to_iwd_config(file, iwd_prefix, phase1_identity);
}

static gboolean
eap_method_config_to_iwd_config(GKeyFile *      file,
                                NMSetting8021x *s_8021x,
                                gboolean        phase2,
                                const char *    method,
                                const char *    iwd_prefix,
                                GError **       error)
{
    char prefix_buf[128];

    if (nm_streq0(method, "tls")) {
        eap_method_name_to_iwd_config(file, iwd_prefix, "TLS");
        eap_optional_identity_to_iwd_config(file,
                                            iwd_prefix,
                                            nm_setting_802_1x_get_identity(s_8021x));

        return eap_certs_to_iwd_config(file,
                                       s_8021x,
                                       phase2,
                                       nm_sprintf_buf(prefix_buf, "%s%s", iwd_prefix, "TLS-"),
                                       error);
    } else if (nm_streq0(method, "ttls") && !phase2) {
        const char *noneap_method = nm_setting_802_1x_get_phase2_auth(s_8021x);

        eap_method_name_to_iwd_config(file, iwd_prefix, "TTLS");
        eap_phase1_identity_to_iwd_config(file, iwd_prefix, s_8021x);

        if (!eap_certs_to_iwd_config(file,
                                     s_8021x,
                                     phase2,
                                     nm_sprintf_buf(prefix_buf, "%s%s", iwd_prefix, "TTLS-"),
                                     error))
            return FALSE;

        nm_sprintf_buf(prefix_buf, "%s%s", iwd_prefix, "TTLS-Phase2-");

        if (nm_setting_802_1x_get_phase2_autheap(s_8021x)) {
            if (noneap_method) {
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    "Only one TTLS phase 2 method can be set");
                return FALSE;
            }
            return eap_method_config_to_iwd_config(file,
                                                   s_8021x,
                                                   TRUE,
                                                   nm_setting_802_1x_get_phase2_autheap(s_8021x),
                                                   prefix_buf,
                                                   error);
        }

        if (NM_IN_STRSET(noneap_method, "chap", "mschap", "mschapv2", "pap")) {
            const char *iwd_method;

            if (nm_streq0(noneap_method, "chap")) {
                iwd_method = "Tunneled-CHAP";
            } else if (nm_streq0(noneap_method, "mschap")) {
                iwd_method = "Tunneled-MSCHAP";
            } else if (nm_streq0(noneap_method, "mschapv2")) {
                iwd_method = "Tunneled-MSCHAPv2";
            } else {
                iwd_method = "Tunneled-PAP";
            }

            eap_method_name_to_iwd_config(file, prefix_buf, iwd_method);
            eap_optional_identity_to_iwd_config(file,
                                                prefix_buf,
                                                nm_setting_802_1x_get_identity(s_8021x));
            return eap_optional_password_to_iwd_config(file, prefix_buf, s_8021x, error);
        }

        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "Unsupported TTLS non-EAP inner method");
        return FALSE;
    } else if (nm_streq0(method, "peap") && !phase2) {
        eap_method_name_to_iwd_config(file, iwd_prefix, "PEAP");
        eap_phase1_identity_to_iwd_config(file, iwd_prefix, s_8021x);

        if (!eap_certs_to_iwd_config(file,
                                     s_8021x,
                                     phase2,
                                     nm_sprintf_buf(prefix_buf, "%s%s", iwd_prefix, "PEAP-"),
                                     error))
            return FALSE;

        if (nm_setting_802_1x_get_phase1_peapver(s_8021x)
            || nm_setting_802_1x_get_phase1_peaplabel(s_8021x))
            nm_log_info(LOGD_WIFI,
                        "IWD network config will not honour the PEAP version and label properties "
                        "in the 802.1x setting (unsupported)");

        if (!nm_setting_802_1x_get_phase2_auth(s_8021x)) {
            /* Apparently PEAP can be used without a phase 2 but this is not
             * supported by either NM or IWD.
             */
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                "PEAP without an inner method is unsupported");
            return FALSE;
        }

        return eap_method_config_to_iwd_config(
            file,
            s_8021x,
            TRUE,
            nm_setting_802_1x_get_phase2_auth(s_8021x),
            nm_sprintf_buf(prefix_buf, "%s%s", iwd_prefix, "PEAP-Phase2-"),
            error);
    } else if (nm_streq0(method, "md5") && phase2) {
        eap_method_name_to_iwd_config(file, iwd_prefix, "MD5");
        eap_optional_identity_to_iwd_config(file,
                                            iwd_prefix,
                                            nm_setting_802_1x_get_identity(s_8021x));
        return eap_optional_password_to_iwd_config(file, iwd_prefix, s_8021x, error);
    } else if (nm_streq0(method, "gtc") && phase2) {
        eap_method_name_to_iwd_config(file, iwd_prefix, "GTC");
        eap_optional_identity_to_iwd_config(file,
                                            iwd_prefix,
                                            nm_setting_802_1x_get_identity(s_8021x));
        return eap_optional_password_to_iwd_config(file, iwd_prefix, s_8021x, error);
    } else if (nm_streq0(method, "pwd")) {
        eap_method_name_to_iwd_config(file, iwd_prefix, "PWD");
        eap_optional_identity_to_iwd_config(file,
                                            iwd_prefix,
                                            nm_setting_802_1x_get_identity(s_8021x));
        return eap_optional_password_to_iwd_config(file, iwd_prefix, s_8021x, error);
    } else if (nm_streq0(method, "mschapv2")) {
        eap_method_name_to_iwd_config(file, iwd_prefix, "MSCHAPV2");
        eap_optional_identity_to_iwd_config(file,
                                            iwd_prefix,
                                            nm_setting_802_1x_get_identity(s_8021x));
        /* In this case we can support password-raw but would have to
         * MD4-hash it and set as <iwd_prefix>Password-Hash
         */
        return eap_optional_password_to_iwd_config(file, iwd_prefix, s_8021x, error);
    } else if (nm_streq0(method, "external")) {
        /* This may be a connection created by NMIwdManager in whch case there
         * may be no need to be convert it back to the IWD format.  Ideally we
         * would still rewrite the other sections/groups in the IWD settings
         * file and preserve the [Security] group -- TODO.  Possibly this should
         * also not be reported as an error.
         */
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "Connection contains no EAP method configuration");
        return FALSE;
    } else {
        /* Some methods are only allowed in phase 1 or only phase 2.
         * OTP, LEAP and FAST are not supported by IWD at all.
         */
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            phase2 ? "Unsupported phase 2 EAP method"
                                   : "Unsupported phase 1 EAP method");
        return FALSE;
    }

    return TRUE;
}

static gboolean
eap_setting_to_iwd_config(GKeyFile *file, NMSetting8021x *s_8021x, GError **error)
{
    const char *method;

    if (!s_8021x || nm_setting_802_1x_get_num_eap_methods(s_8021x) == 0) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "The 802.1x setting is missing or no EAP method set");
        return FALSE;
    }

    if (!nm_setting_verify(NM_SETTING(s_8021x), NULL, error))
        return FALSE;

    method = nm_setting_802_1x_get_eap_method(s_8021x, 0);

    if (nm_setting_802_1x_get_num_eap_methods(s_8021x) > 1)
        nm_log_info(LOGD_WIFI,
                    "IWD network config will only contain the first EAP method: %s",
                    method);

    if (nm_setting_802_1x_get_phase1_auth_flags(s_8021x))
        nm_log_info(LOGD_WIFI,
                    "IWD network config will not honour the TLSv1.x-disable flags in the 802.1x "
                    "setting (unsupported)");

    if (nm_setting_802_1x_get_auth_timeout(s_8021x))
        nm_log_info(LOGD_WIFI,
                    "IWD network config will not honour the auth-timeout property in the 802.1x "
                    "setting (unsupported)");

    return eap_method_config_to_iwd_config(file, s_8021x, FALSE, method, "EAP-", error);
}

static gboolean
ip4_config_to_iwd_config(GKeyFile *file, NMSettingIPConfig *s_ip, GError **error)
{
    guint          num;
    struct in_addr ip;

    /* These settings are not acutally used unless global
     * [General].EnableNetworkConfiguration is true, which we don't support.
     * We add them for sake of completness, although many NMSettingIPConfig
     * configurations can't be mapped to IWD configs and we simply ignore
     * them.  If they were to be used we'd need to add a few warnings.
     */

    if (!s_ip)
        return TRUE;

    num = nm_setting_ip_config_get_num_dns(s_ip);
    if (num) {
        nm_auto_free_gstring GString *s = g_string_sized_new(128);
        guint                         i;

        for (i = 0; i < num; i++) {
            if (s->len)
                g_string_append_c(s, ' ');
            g_string_append(s, nm_setting_ip_config_get_dns(s_ip, i));
        }
        /* It doesn't matter whether we add the DNS under [IPv4] or [IPv6]
         * except that with method=auto the list will override the
         * DNS addresses received over the DHCP version corresponing to
         * v4 or v6.
         * Note ignore-auto-dns=false isn't supported, this list always
         * overrides the DHCP DNSes.
         */
        g_key_file_set_string(file, "IPv4", "DNS", s->str);
    }

    if (!nm_streq0(nm_setting_ip_config_get_method(s_ip), NM_SETTING_IP4_CONFIG_METHOD_MANUAL))
        return TRUE;

    num = nm_setting_ip_config_get_num_addresses(s_ip);
    if (num) {
        NMIPAddress *addr    = nm_setting_ip_config_get_address(s_ip, 0);
        guint        prefix  = nm_ip_address_get_prefix(addr);
        in_addr_t    netmask = _nm_utils_ip4_prefix_to_netmask(prefix);
        char         buf[INET_ADDRSTRLEN];

        nm_ip_address_get_address_binary(addr, &ip);
        g_key_file_set_string(file, "IPv4", "Address", nm_ip_address_get_address(addr));
        g_key_file_set_string(file, "IPv4", "Netmask", _nm_utils_inet4_ntop(netmask, buf));
    } else {
        inet_pton(AF_INET, "10.42.0.100", &ip);
        g_key_file_set_string(file, "IPv4", "Address", "10.42.0.100");
    }

    if (nm_setting_ip_config_get_gateway(s_ip)) {
        g_key_file_set_string(file, "IPv4", "Gateway", nm_setting_ip_config_get_gateway(s_ip));
    } else {
        uint32_t val;
        char     buf[INET_ADDRSTRLEN];

        /* IWD won't enable static IP unless both Address and Gateway are
         * set so generate a gateway address if not known.
         */
        val = (ntohl(ip.s_addr) & 0xfffffff0) + 1;
        if (val == ntohl(ip.s_addr))
            val += 1;
        g_key_file_set_string(file, "IPv4", "Gateway", _nm_utils_inet4_ntop(htonl(val), buf));
    }

    return TRUE;
}

static gboolean
ip6_config_to_iwd_config(GKeyFile *file, NMSettingIPConfig *s_ip, GError **error)
{
    guint        num;
    NMIPAddress *addr;
    char         buf[INET6_ADDRSTRLEN + 10];

    if (!s_ip)
        return TRUE;

    num = nm_setting_ip_config_get_num_dns(s_ip);
    if (num) {
        nm_auto_free_gstring GString *s = g_string_sized_new(128);
        guint                         i;

        for (i = 0; i < num; i++) {
            if (s->len)
                g_string_append_c(s, ' ');
            g_string_append(s, nm_setting_ip_config_get_dns(s_ip, i));
        }
        g_key_file_set_string(file, "IPv6", "DNS", s->str);
    }

    if (!NM_IN_STRSET(nm_setting_ip_config_get_method(s_ip),
                      NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                      NM_SETTING_IP6_CONFIG_METHOD_DHCP,
                      NM_SETTING_IP6_CONFIG_METHOD_MANUAL))
        return TRUE;

    g_key_file_set_boolean(file, "IPv6", "Enabled", TRUE);

    if (!nm_streq0(nm_setting_ip_config_get_method(s_ip), NM_SETTING_IP6_CONFIG_METHOD_MANUAL))
        return TRUE;

    if (!nm_setting_ip_config_get_num_addresses(s_ip)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "IP address required for IPv6 manual config");
        return FALSE;
    }

    addr = nm_setting_ip_config_get_address(s_ip, 0);
    g_key_file_set_string(file,
                          "IPv6",
                          "Address",
                          nm_sprintf_buf(buf,
                                         "%s/%u",
                                         nm_ip_address_get_address(addr),
                                         nm_ip_address_get_prefix(addr)));
    if (nm_setting_ip_config_get_gateway(s_ip))
        g_key_file_set_string(file, "IPv6", "Gateway", nm_setting_ip_config_get_gateway(s_ip));
    return TRUE;
}

GKeyFile *
nm_wifi_utils_connection_to_iwd_config(NMConnection *connection,
                                       char **       out_filename,
                                       GError **     error)
{
    NMSettingConnection * s_conn = nm_connection_get_setting_connection(connection);
    NMSettingWireless *   s_wifi = nm_connection_get_setting_wireless(connection);
    GBytes *              ssid;
    const guint8 *        ssid_data;
    gsize                 ssid_len;
    NMIwdNetworkSecurity  security;
    const char *          cloned_mac_addr;
    gs_free char *        comment        = NULL;
    nm_auto_unref_keyfile GKeyFile *file = NULL;

    if (!s_conn || !s_wifi
        || !nm_streq(nm_setting_connection_get_connection_type(s_conn),
                     NM_SETTING_WIRELESS_SETTING_NAME)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "Connection and/or wireless settings are missing");
        return NULL;
    }

    if (!NM_IN_STRSET(nm_setting_wireless_get_mode(s_wifi), NULL, NM_SETTING_WIRELESS_MODE_INFRA)) {
        g_set_error_literal(
            error,
            NM_CONNECTION_ERROR,
            NM_CONNECTION_ERROR_INVALID_PROPERTY,
            "Non-infrastructure-mode connections don't have IWD profiles (or aren't supported)");
        return NULL;
    }

    ssid      = nm_setting_wireless_get_ssid(s_wifi);
    ssid_data = ssid ? g_bytes_get_data(ssid, &ssid_len) : NULL;
    if (!ssid_data || ssid_len <= 0 || ssid_len > NM_IW_ESSID_MAX_SIZE
        || !g_utf8_validate((const char *) ssid_data, ssid_len, NULL)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "Empty or non-UTF-8 SSIDs not supported by IWD");
        return NULL;
    }

    if (!nm_wifi_connection_get_iwd_ssid_and_security(connection, NULL, &security)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "Connection's security type unrecognised");
        return NULL;
    }

    file = g_key_file_new();

    comment = g_strdup_printf(" Auto-generated from NetworkManager connection \"%s\"\n"
                              " Changes to that connection overwrite this file when "
                              "enabled by NM's [%s].%s value",
                              nm_setting_connection_get_id(s_conn),
                              NM_CONFIG_KEYFILE_GROUP_MAIN,
                              NM_CONFIG_KEYFILE_KEY_MAIN_IWD_CONFIG_PATH);
    g_key_file_set_comment(file, NULL, NULL, comment, NULL);

    if (!nm_setting_connection_get_autoconnect(s_conn))
        g_key_file_set_boolean(file, "Settings", "AutoConnect", FALSE);

    if (nm_setting_wireless_get_hidden(s_wifi))
        g_key_file_set_boolean(file, "Settings", "Hidden", TRUE);

    /* Only effective if IWD's global [General].AddressRandomization is set
     * to "network".  "random" maps to [Settings].AlwaysRandomizeAddress=true,
     * "stable" is the default, specific address maps to
     * [Settings].AddressOverride set to that address.  "permanent" is not
     * supported and "preserve" can only be achieved using the global
     * [General].AddressRandomization=disabled setting.  We don't print
     * warnings when we can't map the value here because we don't know what
     * IWD's [General].AddressRandomization is set to.
     */
    cloned_mac_addr = nm_setting_wireless_get_cloned_mac_address(s_wifi);
    if (nm_streq0(cloned_mac_addr, NM_CLONED_MAC_RANDOM))
        g_key_file_set_boolean(file, "Settings", "AlwaysRandomizeAddress", TRUE);
    else if (cloned_mac_addr && nm_utils_hwaddr_valid(cloned_mac_addr, ETH_ALEN))
        g_key_file_set_string(file, "Settings", "AddressOverride", cloned_mac_addr);

    if (!ip4_config_to_iwd_config(
            file,
            NM_SETTING_IP_CONFIG(nm_connection_get_setting_ip4_config(connection)),
            error))
        return NULL;

    if (!ip6_config_to_iwd_config(
            file,
            NM_SETTING_IP_CONFIG(nm_connection_get_setting_ip6_config(connection)),
            error))
        return NULL;

    switch (security) {
    case NM_IWD_NETWORK_SECURITY_OPEN:
        break;
    case NM_IWD_NETWORK_SECURITY_PSK:
        if (!psk_setting_to_iwd_config(file,
                                       nm_connection_get_setting_wireless_security(connection),
                                       error))
            return NULL;

        break;
    case NM_IWD_NETWORK_SECURITY_8021X:
        if (!eap_setting_to_iwd_config(file, nm_connection_get_setting_802_1x(connection), error))
            return NULL;

        break;
    default:
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "Connection security type is not supported");
        return NULL;
    }

    if (out_filename)
        *out_filename =
            nm_wifi_utils_get_iwd_config_filename((const char *) ssid_data, ssid_len, security);

    return g_steal_pointer(&file);
}
