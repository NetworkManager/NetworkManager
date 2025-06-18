/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "libnm-core-aux-extern/nm-libnm-core-aux.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"

#include "libnm-glib-aux/nm-test-utils.h"

/*****************************************************************************/

static NMTeamLinkWatcher *
_team_link_watcher_from_string_impl(const char *str, gsize nextra, const char *const *vextra)
{
    NMTeamLinkWatcher    *watcher;
    gs_free char         *str1_free = NULL;
    gs_free_error GError *error     = NULL;
    gsize                 i;

    g_assert(str);

    watcher = nm_utils_team_link_watcher_from_string(str, &error);
    nmtst_assert_success(watcher, error);

    for (i = 0; i < 1 + nextra; i++) {
        nm_auto_unref_team_link_watcher NMTeamLinkWatcher *watcher1 = NULL;
        const char                                        *str1;

        if (i == 0) {
            str1_free = nm_utils_team_link_watcher_to_string(watcher);
            g_assert(str1_free);
            str1 = str1_free;
            g_assert_cmpstr(str, ==, str1);
        } else
            str1 = vextra[i - 1];

        watcher1 = nm_utils_team_link_watcher_from_string(str1, &error);
        nmtst_assert_success(watcher1, error);
        if (!nm_team_link_watcher_equal(watcher, watcher1)) {
            gs_free char *ss1 = NULL;
            gs_free char *ss2 = NULL;

            g_print(">>> watcher differs: \"%s\" vs. \"%s\"",
                    (ss1 = nm_utils_team_link_watcher_to_string(watcher)),
                    (ss2 = nm_utils_team_link_watcher_to_string(watcher1)));
            g_print(">>> ORIG: \"%s\" vs. \"%s\"", str, str1);
            g_assert_not_reached();
        }
        g_assert(nm_team_link_watcher_equal(watcher1, watcher));
    }

    return watcher;
}
#define _team_link_watcher_from_string(str, ...) \
    _team_link_watcher_from_string_impl((str), NM_NARG(__VA_ARGS__), NM_MAKE_STRV(__VA_ARGS__))

/*****************************************************************************/

static void
test_team_link_watcher_tofro_string(void)
{
    nm_auto_unref_team_link_watcher NMTeamLinkWatcher *w = NULL;

#define _team_link_watcher_cmp(watcher,                                                   \
                               name,                                                      \
                               delay_down,                                                \
                               delay_up,                                                  \
                               init_wait,                                                 \
                               interval,                                                  \
                               missed_max,                                                \
                               target_host,                                               \
                               source_host,                                               \
                               vlanid,                                                    \
                               arping_flags)                                              \
    G_STMT_START                                                                          \
    {                                                                                     \
        nm_auto_unref_team_link_watcher NMTeamLinkWatcher *_w = g_steal_pointer(watcher); \
                                                                                          \
        g_assert_cmpstr((name), ==, nm_team_link_watcher_get_name(_w));                   \
        g_assert_cmpint((delay_down), ==, nm_team_link_watcher_get_delay_down(_w));       \
        g_assert_cmpint((delay_up), ==, nm_team_link_watcher_get_delay_up(_w));           \
        g_assert_cmpint((init_wait), ==, nm_team_link_watcher_get_init_wait(_w));         \
        g_assert_cmpint((interval), ==, nm_team_link_watcher_get_interval(_w));           \
        g_assert_cmpint((missed_max), ==, nm_team_link_watcher_get_missed_max(_w));       \
        g_assert_cmpstr((target_host), ==, nm_team_link_watcher_get_target_host(_w));     \
        g_assert_cmpstr((source_host), ==, nm_team_link_watcher_get_source_host(_w));     \
        g_assert_cmpint((vlanid), ==, nm_team_link_watcher_get_vlanid(_w));               \
        g_assert_cmpint((arping_flags), ==, nm_team_link_watcher_get_flags(_w));          \
    }                                                                                     \
    G_STMT_END

    w = _team_link_watcher_from_string("name=ethtool",
                                       "delay-up=0   name=ethtool",
                                       "  delay-down=0   name=ethtool   ");
    _team_link_watcher_cmp(&w,
                           "ethtool",
                           0,
                           0,
                           -1,
                           -1,
                           -1,
                           NULL,
                           NULL,
                           -1,
                           NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);

    w = _team_link_watcher_from_string("name=ethtool delay-up=10",
                                       "   delay-down=0  delay-up=10   name=ethtool");
    _team_link_watcher_cmp(&w,
                           "ethtool",
                           0,
                           10,
                           -1,
                           -1,
                           -1,
                           NULL,
                           NULL,
                           -1,
                           NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);

    w = _team_link_watcher_from_string("name=ethtool delay-up=10 delay-down=11",
                                       "   delay-down=11  delay-up=10   name=ethtool");
    _team_link_watcher_cmp(&w,
                           "ethtool",
                           11,
                           10,
                           -1,
                           -1,
                           -1,
                           NULL,
                           NULL,
                           -1,
                           NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);

    w = _team_link_watcher_from_string(
        "name=nsna_ping target-host=xxx",
        "name=nsna_ping target-host=xxx",
        "  missed-max=3    target-host=xxx        name=nsna_ping   ");
    _team_link_watcher_cmp(&w,
                           "nsna_ping",
                           -1,
                           -1,
                           0,
                           0,
                           3,
                           "xxx",
                           NULL,
                           -1,
                           NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);

    w = _team_link_watcher_from_string("name=arp_ping target-host=xxx source-host=yzd",
                                       "  source-host=yzd target-host=xxx        name=arp_ping   ");
    _team_link_watcher_cmp(&w,
                           "arp_ping",
                           -1,
                           -1,
                           0,
                           0,
                           3,
                           "xxx",
                           "yzd",
                           -1,
                           NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);

    w = _team_link_watcher_from_string(
        "name=arp_ping missed-max=0 target-host=xxx vlanid=0 source-host=yzd");
    _team_link_watcher_cmp(&w,
                           "arp_ping",
                           -1,
                           -1,
                           0,
                           0,
                           0,
                           "xxx",
                           "yzd",
                           0,
                           NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);

    w = _team_link_watcher_from_string(
        "name=arp_ping target-host=xxx source-host=yzd validate-active=true",
        "source-host=yzd send-always=false name=arp_ping validate-active=true "
        "validate-inactive=false target-host=xxx",
        "  source-host=yzd target-host=xxx   validate-active=true      name=arp_ping   ");
    _team_link_watcher_cmp(&w,
                           "arp_ping",
                           -1,
                           -1,
                           0,
                           0,
                           3,
                           "xxx",
                           "yzd",
                           -1,
                           NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE);

    w = _team_link_watcher_from_string(
        "name=arp_ping target-host=xxx source-host=yzd validate-active=true validate-inactive=true "
        "send-always=true",
        "source-host=yzd send-always=true name=arp_ping validate-active=true "
        "validate-inactive=true target-host=xxx",
        "source-host=yzd send-always=true name=arp_ping validate-active=1 validate-inactive=yes "
        "target-host=xxx",
        "  source-host=yzd target-host=xxx   validate-inactive=true send-always=true    "
        "validate-active=true      name=arp_ping   ");
    _team_link_watcher_cmp(&w,
                           "arp_ping",
                           -1,
                           -1,
                           0,
                           0,
                           3,
                           "xxx",
                           "yzd",
                           -1,
                           NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE
                               | NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE
                               | NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS);

    w = _team_link_watcher_from_string(
        "name=arp_ping missed-max=0 target-host=xxx vlanid=0 source-host=yzd");
    _team_link_watcher_cmp(&w,
                           "arp_ping",
                           -1,
                           -1,
                           0,
                           0,
                           0,
                           "xxx",
                           "yzd",
                           0,
                           NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);
}

static void
test_wireguard_peer(void)
{
    guint i;
    struct {
        const char *input;
        const char *canonical; /* canonical string representation */

        gboolean    invalid;
        const char *pubkey;
        const char *endpoint;
        guint16     keepalive;
        guint       num_allowed_ips;
        const char *allowed_ips[2];
        const char *psk;
        int         psk_flags;
    } tests[] = {{
                     /* Public key only */
                     .input     = "MWEKYcE9MEh5RoGDuJYrJ2YgkoosONGhuHRBAC00e14=",
                     .canonical = "MWEKYcE9MEh5RoGDuJYrJ2YgkoosONGhuHRBAC00e14=",
                     .pubkey    = "MWEKYcE9MEh5RoGDuJYrJ2YgkoosONGhuHRBAC00e14=",
                 },
                 {
                     /* IPv4 endpoint */
                     .input     = "+DIX0qWKQ4E6hy7MWzsSRXjqAHCtffWrXTdJPe/xS04="
                                  " endpoint=1.2.3.4:5555",
                     .canonical = "+DIX0qWKQ4E6hy7MWzsSRXjqAHCtffWrXTdJPe/xS04="
                                  " endpoint=1.2.3.4:5555",
                     .pubkey    = "+DIX0qWKQ4E6hy7MWzsSRXjqAHCtffWrXTdJPe/xS04=",
                     .endpoint  = "1.2.3.4:5555",
                 },
                 {
                     /* IPv6 endpoint */
                     .input     = "aPsdPkeqH4l5Nax3g3e8A8f7g0hJk2l3m4N5p6q7R8s="
                                  " endpoint=[fd01:db8::1]:8080",
                     .canonical = "aPsdPkeqH4l5Nax3g3e8A8f7g0hJk2l3m4N5p6q7R8s="
                                  " endpoint=[fd01:db8::1]:8080",
                     .pubkey    = "aPsdPkeqH4l5Nax3g3e8A8f7g0hJk2l3m4N5p6q7R8s=",
                     .endpoint  = "[fd01:db8::1]:8080",
                 },
                 {
                     /* IPv6 endpoint, without brackets */
                     .input     = "+DIX0qWKQ4E6hy7MWzsSRXjqAHCtffWrXTdJPe/xS04="
                                  " endpoint=fd01::12:8080",
                     .canonical = "+DIX0qWKQ4E6hy7MWzsSRXjqAHCtffWrXTdJPe/xS04="
                                  " endpoint=fd01::12:8080",
                     .pubkey    = "+DIX0qWKQ4E6hy7MWzsSRXjqAHCtffWrXTdJPe/xS04=",
                     .endpoint  = "fd01::12:8080",
                 },
                 {
                     /* Single IPv4 allowed-ip */
                     .input           = "s4fmZZA3gMGVv8+0hkSwrmeLC6nNd+Pd6DlSaufLKhY="
                                        " allowed-ips=172.16.0.0/16",
                     .canonical       = "s4fmZZA3gMGVv8+0hkSwrmeLC6nNd+Pd6DlSaufLKhY="
                                        " allowed-ips=172.16.0.0/16",
                     .pubkey          = "s4fmZZA3gMGVv8+0hkSwrmeLC6nNd+Pd6DlSaufLKhY=",
                     .num_allowed_ips = 1,
                     .allowed_ips     = {"172.16.0.0/16"},
                 },
                 {
                     /* Multiple allowed-ips */
                     .input           = "V02J2zmCi2LHX2KMK+ZOgDNhZzK4JXjGNr7CYfz9DxQ="
                                        " allowed-ips=192.168.2.0/24;2001:db8:a::/48",
                     .canonical       = "V02J2zmCi2LHX2KMK+ZOgDNhZzK4JXjGNr7CYfz9DxQ="
                                        " allowed-ips=192.168.2.0/24;2001:db8:a::/48",
                     .pubkey          = "V02J2zmCi2LHX2KMK+ZOgDNhZzK4JXjGNr7CYfz9DxQ=",
                     .num_allowed_ips = 2,
                     .allowed_ips     = {"192.168.2.0/24", "2001:db8:a::/48"},
                 },
                 {
                     /* Persistent-keepalive */
                     .input     = "D1FTp8Wy1oJQI045yXo9EMdxJqjXHC3VhTCPTh3lSQM="
                                  " persistent-keepalive=25",
                     .canonical = "D1FTp8Wy1oJQI045yXo9EMdxJqjXHC3VhTCPTh3lSQM="
                                  " persistent-keepalive=25",
                     .pubkey    = "D1FTp8Wy1oJQI045yXo9EMdxJqjXHC3VhTCPTh3lSQM=",
                     .keepalive = 25,
                 },
                 {
                     /* Preshared-key without flags (should default to 0) */
                     .input     = "H5cWWgpWgJH+nHFhsuPS3adgZHuc6Z4cRzfiNRTinE0="
                                  " preshared-key=16uGwZvROnwyNGoW6Z3pvJB5GKbd6ncYROA/FFleLQA=",
                     .canonical = "H5cWWgpWgJH+nHFhsuPS3adgZHuc6Z4cRzfiNRTinE0="
                                  " preshared-key=16uGwZvROnwyNGoW6Z3pvJB5GKbd6ncYROA/FFleLQA="
                                  " preshared-key-flags=0",
                     .pubkey    = "H5cWWgpWgJH+nHFhsuPS3adgZHuc6Z4cRzfiNRTinE0=",
                     .psk       = "16uGwZvROnwyNGoW6Z3pvJB5GKbd6ncYROA/FFleLQA=",
                     .psk_flags = 0,
                 },
                 {
                     /* Preshared-key flags as string */
                     .input     = "H5cWWgpWgJH+nHFhsuPS3adgZHuc6Z4cRzfiNRTinE0="
                                  " preshared-key=16uGwZvROnwyNGoW6Z3pvJB5GKbd6ncYROA/FFleLQA="
                                  " preshared-key-flags=not-saved",
                     .canonical = "H5cWWgpWgJH+nHFhsuPS3adgZHuc6Z4cRzfiNRTinE0="
                                  " preshared-key=16uGwZvROnwyNGoW6Z3pvJB5GKbd6ncYROA/FFleLQA="
                                  " preshared-key-flags=2",
                     .pubkey    = "H5cWWgpWgJH+nHFhsuPS3adgZHuc6Z4cRzfiNRTinE0=",
                     .psk       = "16uGwZvROnwyNGoW6Z3pvJB5GKbd6ncYROA/FFleLQA=",
                     .psk_flags = 2,
                 },
                 {
                     /* Non-canonical order and extra whitespaces */
                     .input           = "gqQ9dUqKQNfz/KOqELJpS0MKBvRcYWL8sm/LGEWKKQY="
                                        "  preshared-key=EVVP8pOzn8R3nQtv62/hnGsXzyagEgykSboFe4EFhQc="
                                        " endpoint=vpn.example.com:51820  "
                                        " preshared-key-flags=1"
                                        " persistent-keepalive=45"
                                        " allowed-ips=0.0.0.0/0;::/0",
                     .canonical       = "gqQ9dUqKQNfz/KOqELJpS0MKBvRcYWL8sm/LGEWKKQY="
                                        " allowed-ips=0.0.0.0/0;::/0"
                                        " endpoint=vpn.example.com:51820"
                                        " persistent-keepalive=45"
                                        " preshared-key=EVVP8pOzn8R3nQtv62/hnGsXzyagEgykSboFe4EFhQc="
                                        " preshared-key-flags=1",
                     .pubkey          = "gqQ9dUqKQNfz/KOqELJpS0MKBvRcYWL8sm/LGEWKKQY=",
                     .endpoint        = "vpn.example.com:51820",
                     .keepalive       = 45,
                     .num_allowed_ips = 2,
                     .allowed_ips     = {"0.0.0.0/0", "::/0"},
                     .psk             = "EVVP8pOzn8R3nQtv62/hnGsXzyagEgykSboFe4EFhQc=",
                     .psk_flags       = 1,
                 },
                 {
                     /* Empty string */
                     .input   = "",
                     .invalid = TRUE,
                 },
                 {
                     /* Invalid public key*/
                     .input   = "aaaaaaaaaaaaaaaaaaaaaaa=",
                     .invalid = TRUE,
                 },
                 {
                     /* Missing value*/
                     .input   = "gqQ9dUqKQNfz/KOqELJpS0MKBvRcYWL8sm/LGEWKKQY= "
                                "persistent-keepalive=",
                     .invalid = TRUE,
                 },
                 {
                     /* Unknown attribute */
                     .input   = "gqQ9dUqKQNfz/KOqELJpS0MKBvRcYWL8sm/LGEWKKQY= "
                                "persistent-keepalive=12 foobarness=13",
                     .invalid = TRUE,
                 },
                 {
                     /* Invalid IPv4 allowed-ip*/
                     .input   = "gqQ9dUqKQNfz/KOqELJpS0MKBvRcYWL8sm/LGEWKKQY= "
                                "allowed-ips=192.168.10.256/32",
                     .invalid = TRUE,
                 },
                 {
                     /* Invalid IPv6 allowed-ip */
                     .input   = "gqQ9dUqKQNfz/KOqELJpS0MKBvRcYWL8sm/LGEWKKQY= "
                                "allowed-ips=fd01::1::3/64",
                     .invalid = TRUE,
                 },
                 {
                     /* Endpoint with no port */
                     .input   = "+DIX0qWKQ4E6hy7MWzsSRXjqAHCtffWrXTdJPe/xS04="
                                " endpoint=1.2.3.4",
                     .invalid = TRUE,
                 },
                 {
                     /* Invalid endpoint */
                     .input   = "+DIX0qWKQ4E6hy7MWzsSRXjqAHCtffWrXTdJPe/xS04="
                                " endpoint=1.2.3.5.6",
                     .invalid = TRUE,
                 },
                 {
                     /* Invalid persistent-keepalive */
                     .input   = "gqQ9dUqKQNfz/KOqELJpS0MKBvRcYWL8sm/LGEWKKQY= "
                                "persistent-keepalive=yes",
                     .invalid = TRUE,
                 },
                 {
                     /* Invalid PSK */
                     .input   = "gqQ9dUqKQNfz/KOqELJpS0MKBvRcYWL8sm/LGEWKKQY="
                                " preshared-key=pskpskpskpskpskpskpskpskpskpskpskpsk",
                     .invalid = TRUE,
                 }};

    for (i = 0; i < G_N_ELEMENTS(tests); i++) {
        nm_auto_unref_wgpeer NMWireGuardPeer *peer   = NULL;
        gs_free_error GError                 *error  = NULL;
        gs_free char                         *newstr = NULL;
        guint                                 j;

        peer = _nm_utils_wireguard_peer_from_string(tests[i].input, &error);
        if (tests[i].invalid) {
            g_assert(!peer);
            g_assert(error);
            continue;
        }
        g_assert_no_error(error);
        g_assert_nonnull(peer);

        newstr = _nm_utils_wireguard_peer_to_string(peer);
        g_assert_nonnull(newstr);
        g_assert_cmpstr(tests[i].canonical, ==, newstr);

        g_assert_cmpstr(tests[i].pubkey, ==, nm_wireguard_peer_get_public_key(peer));
        g_assert_cmpstr(tests[i].endpoint, ==, nm_wireguard_peer_get_endpoint(peer));

        g_assert_cmpint(tests[i].num_allowed_ips, ==, nm_wireguard_peer_get_allowed_ips_len(peer));
        for (j = 0; j < tests[i].num_allowed_ips; j++) {
            g_assert_cmpstr(tests[i].allowed_ips[j],
                            ==,
                            nm_wireguard_peer_get_allowed_ip(peer, j, NULL));
        }

        g_assert_cmpint(tests[i].keepalive, ==, nm_wireguard_peer_get_persistent_keepalive(peer));
        g_assert_cmpstr(tests[i].psk, ==, nm_wireguard_peer_get_preshared_key(peer));
        if (tests[i].psk) {
            g_assert_cmpint(tests[i].psk_flags,
                            ==,
                            nm_wireguard_peer_get_preshared_key_flags(peer));
        }
    }
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/libnm-core-aux/test_team_link_watcher_tofro_string",
                    test_team_link_watcher_tofro_string);
    g_test_add_func("/libnm-core-aux/test-wireguard-peer", test_wireguard_peer);

    return g_test_run();
}
