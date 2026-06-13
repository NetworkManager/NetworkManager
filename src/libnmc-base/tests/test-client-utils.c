/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2026 Red Hat, Inc.
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "libnmc-base/nm-client-utils.h"

#include "libnm-glib-aux/nm-test-utils.h"

/*****************************************************************************/

static void
_check_uri(const char *ssid,
           const char *key_mgmt,
           const char *psk,
           gboolean    hidden,
           const char *expected)
{
    gs_free char *uri = nmc_wifi_qr_uri_new(ssid, key_mgmt, psk, hidden);

    g_assert_cmpstr(uri, ==, expected);
}

static void
test_wifi_qr_uri_type(void)
{
    _check_uri("MyNet", NULL, NULL, FALSE, "WIFI:T:nopass;S:MyNet;;");
    _check_uri("MyNet", "none", NULL, FALSE, "WIFI:T:WEP;S:MyNet;;");
    _check_uri("MyNet", "ieee8021x", NULL, FALSE, "WIFI:T:WEP;S:MyNet;;");
    _check_uri("MyNet", "wpa-psk", "passXY", FALSE, "WIFI:T:WPA;S:MyNet;P:passXY;;");
    _check_uri("MyNet", "wpa-none", "passXY", FALSE, "WIFI:T:WPA;S:MyNet;P:passXY;;");
    _check_uri("MyNet", "sae", "passXY", FALSE, "WIFI:T:WPA;S:MyNet;P:passXY;;");
    _check_uri("MyNet", "owe", NULL, FALSE, "WIFI:T:nopass;S:MyNet;;");

    /* Unhandled key_mgmt: no T: tag is emitted. */
    _check_uri("MyNet", "wpa-eap", "passXY", FALSE, "WIFI:S:MyNet;P:passXY;;");
}

static void
test_wifi_qr_uri_hidden(void)
{
    _check_uri("MyNet", "wpa-psk", "passXY", TRUE, "WIFI:T:WPA;S:MyNet;P:passXY;H:true;;");
}

static void
test_wifi_qr_uri_escaping(void)
{
    /* Each of \ " : ; , is backslash-escaped. */
    _check_uri("a;b:c,d\\e\"f", NULL, NULL, FALSE, "WIFI:T:nopass;S:a\\;b\\:c\\,d\\\\e\\\"f;;");

    /* An all-hex value is wrapped in double quotes (per the MECARD format). */
    _check_uri("MyNet", "wpa-psk", "deadbeef", FALSE, "WIFI:T:WPA;S:MyNet;P:\"deadbeef\";;");

    /* A 64-hex-character PSK is also quoted. */
    _check_uri("MyNet",
               "wpa-psk",
               "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
               FALSE,
               "WIFI:T:WPA;S:MyNet;P:\"0123456789abcdef0123456789abcdef0123456789abcdef012345"
               "6789abcdef\";;");

    /* Mixing hex and non-hex disables quoting. */
    _check_uri("MyNet", "wpa-psk", "dead beef", FALSE, "WIFI:T:WPA;S:MyNet;P:dead beef;;");

    /* An empty value is not quoted (it is not "all-hex"). */
    _check_uri("", NULL, NULL, FALSE, "WIFI:T:nopass;S:;;");
}

/*****************************************************************************/

static void
test_wifi_qr_render(void)
{
    gs_free char      *qr    = nmc_wifi_qr_render_string("WIFI:T:WPA;S:MyNet;P:passXY;;");
    gs_strfreev char **lines = NULL;

    g_assert(qr);
    /* Multiple rows packed two modules per character. */
    lines = g_strsplit(qr, "\n", -1);
    g_assert_cmpint(g_strv_length(lines), >, 1);
}

static void
test_wifi_qr_render_too_long(void)
{
    /* Lowercase forces byte mode (capacity 2953 at version 40), so 4000 bytes
     * exceed it and encoding fails. */
    gs_free char *str = g_strnfill(4000, 'x');
    gs_free char *qr  = nmc_wifi_qr_render_string(str);

    g_assert(!qr);
}

static void
test_wifi_key_mgmt_uses_psk(void)
{
    g_assert(nmc_wifi_key_mgmt_uses_psk("wpa-psk"));
    g_assert(nmc_wifi_key_mgmt_uses_psk("sae"));
    g_assert(nmc_wifi_key_mgmt_uses_psk("wpa-none"));

    g_assert(!nmc_wifi_key_mgmt_uses_psk(NULL));
    g_assert(!nmc_wifi_key_mgmt_uses_psk("none"));
    g_assert(!nmc_wifi_key_mgmt_uses_psk("owe"));
    g_assert(!nmc_wifi_key_mgmt_uses_psk("wpa-eap"));
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/client-utils/wifi-qr/uri/type", test_wifi_qr_uri_type);
    g_test_add_func("/client-utils/wifi-qr/uri/hidden", test_wifi_qr_uri_hidden);
    g_test_add_func("/client-utils/wifi-qr/uri/escaping", test_wifi_qr_uri_escaping);
    g_test_add_func("/client-utils/wifi-qr/render", test_wifi_qr_render);
    g_test_add_func("/client-utils/wifi-qr/render-too-long", test_wifi_qr_render_too_long);
    g_test_add_func("/client-utils/wifi/key-mgmt-uses-psk", test_wifi_key_mgmt_uses_psk);

    return g_test_run();
}
