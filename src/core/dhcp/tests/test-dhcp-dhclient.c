/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2010 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#include "libnm-glib-aux/nm-dedup-multi.h"

#include "NetworkManagerUtils.h"
#include "dhcp/nm-dhcp-dhclient-utils.h"
#include "dhcp/nm-dhcp-utils.h"
#include "nm-utils.h"
#include "libnm-platform/nm-platform.h"

#include "nm-test-utils-core.h"

#define TEST_DIR    NM_BUILD_SRCDIR "/src/core/dhcp/tests"
#define TEST_MUDURL "https://example.com/mud.json"

static void
test_config(const char         *orig,
            const char         *expected,
            int                 addr_family,
            const char         *hostname,
            guint32             timeout,
            gboolean            use_fqdn,
            NMDhcpHostnameFlags hostname_flags,
            const char         *dhcp_client_id,
            GBytes             *expected_new_client_id,
            const char         *iface,
            const char         *anycast_addr,
            const char         *mud_url)
{
    gs_free char *new                     = NULL;
    gs_unref_bytes GBytes *client_id      = NULL;
    gs_unref_bytes GBytes *new_client_id  = NULL;
    gboolean               send_client_id = TRUE;

    if (nm_streq0(dhcp_client_id, "none")) {
        send_client_id = FALSE;
    } else if (dhcp_client_id) {
        client_id = nm_dhcp_utils_client_id_string_to_bytes(dhcp_client_id);
        g_assert(client_id);
    }

    new = nm_dhcp_dhclient_create_config(iface,
                                         addr_family,
                                         client_id,
                                         send_client_id,
                                         anycast_addr,
                                         hostname,
                                         timeout,
                                         use_fqdn,
                                         hostname_flags,
                                         mud_url,
                                         NULL,
                                         "/path/to/dhclient.conf",
                                         orig,
                                         &new_client_id);
    g_assert(new != NULL);

    if (!nm_streq(new, expected)) {
        g_message("\n* OLD ---------------------------------\n"
                  "%s"
                  "\n- NEW -----------------------------------\n"
                  "%s"
                  "\n+ EXPECTED ++++++++++++++++++++++++++++++\n"
                  "%s"
                  "\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n",
                  orig,
                  new,
                  expected);
    }
    g_assert_cmpstr(new, ==, expected);

    if (expected_new_client_id) {
        g_assert(new_client_id);
        g_assert(g_bytes_equal(new_client_id, expected_new_client_id));
    } else
        g_assert(new_client_id == NULL);
}

/*****************************************************************************/

static const char *orig_missing_expected =
    "# Created by NetworkManager\n"
    "\n\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_orig_missing(void)
{
    test_config(NULL,
                orig_missing_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                NULL,
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *orig_missing_add_mud_url_expected =
    "# Created by NetworkManager\n"
    "\n"
    "option mudurl code 161 = text;\n"
    "send mudurl \"https://example.com/mud.json\";\n\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_orig_missing_add_mud_url(void)
{
    test_config(NULL,
                orig_missing_add_mud_url_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                NULL,
                NULL,
                "eth0",
                NULL,
                TEST_MUDURL);
}

/*****************************************************************************/

static const char *override_client_id_orig = "send dhcp-client-identifier 00:30:04:20:7A:08;\n";

static const char *override_client_id_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n"
    "send dhcp-client-identifier 11:22:33:44:55:66; # added by NetworkManager\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_override_client_id(void)
{
    test_config(override_client_id_orig,
                override_client_id_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                "11:22:33:44:55:66",
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *quote_client_id_expected =
    "# Created by NetworkManager\n"
    "\n"
    "send dhcp-client-identifier \"\\x00abcd\"; # added by NetworkManager\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_quote_client_id(void)
{
    test_config(NULL,
                quote_client_id_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                "abcd",
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *quote_client_id_expected_2 =
    "# Created by NetworkManager\n"
    "\n"
    "send dhcp-client-identifier 00:61:5c:62:63; # added by NetworkManager\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_quote_client_id_2(void)
{
    test_config(NULL,
                quote_client_id_expected_2,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                "a\\bc",
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *hex_zero_client_id_expected =
    "# Created by NetworkManager\n"
    "\n"
    "send dhcp-client-identifier 00:11:22:33; # added by NetworkManager\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_hex_zero_client_id(void)
{
    test_config(NULL,
                hex_zero_client_id_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                "00:11:22:33",
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *ascii_client_id_expected =
    "# Created by NetworkManager\n"
    "\n"
    "send dhcp-client-identifier \"\\x00qb:cd:ef:12:34:56\"; # added by NetworkManager\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_ascii_client_id(void)
{
    test_config(NULL,
                ascii_client_id_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                "qb:cd:ef:12:34:56",
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *hex_single_client_id_expected =
    "# Created by NetworkManager\n"
    "\n"
    "send dhcp-client-identifier ab:cd:0e:12:34:56; # added by NetworkManager\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_hex_single_client_id(void)
{
    test_config(NULL,
                hex_single_client_id_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                "ab:cd:e:12:34:56",
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *existing_hex_client_id_orig = "send dhcp-client-identifier 10:30:04:20:7A:08;\n";

static const char *existing_hex_client_id_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n"
    "send dhcp-client-identifier 10:30:04:20:7A:08;\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_existing_hex_client_id(void)
{
    gs_unref_bytes GBytes *new_client_id = NULL;
    const guint8           bytes[]       = {0x10, 0x30, 0x04, 0x20, 0x7A, 0x08};

    new_client_id = g_bytes_new(bytes, sizeof(bytes));
    test_config(existing_hex_client_id_orig,
                existing_hex_client_id_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                NULL,
                new_client_id,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *existing_escaped_client_id_orig =
    "send dhcp-client-identifier \"\\044test\\xfe\";\n";

static const char *existing_escaped_client_id_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n"
    "send dhcp-client-identifier \"\\044test\\xfe\";\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_existing_escaped_client_id(void)
{
    gs_unref_bytes GBytes *new_client_id = NULL;

    new_client_id = g_bytes_new("$test\xfe", 6);
    test_config(existing_escaped_client_id_orig,
                existing_escaped_client_id_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                NULL,
                new_client_id,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

#define EACID "qb:cd:ef:12:34:56"

static const char *existing_ascii_client_id_orig =
    "send dhcp-client-identifier \"\\x00" EACID "\";\n";

static const char *existing_ascii_client_id_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n"
    "send dhcp-client-identifier \"\\x00" EACID "\";\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_existing_ascii_client_id(void)
{
    gs_unref_bytes GBytes *new_client_id             = NULL;
    char                   buf[NM_STRLEN(EACID) + 1] = {0};

    memcpy(buf + 1, EACID, NM_STRLEN(EACID));
    new_client_id = g_bytes_new(buf, sizeof(buf));
    test_config(existing_ascii_client_id_orig,
                existing_ascii_client_id_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                NULL,
                new_client_id,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *none_client_id_orig = "send dhcp-client-identifier 10:30:04:20:7A:08;\n";

static const char *none_client_id_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n"
    "send dhcp-client-identifier \"\"; # added by NetworkManager\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_none_client_id(void)
{
    const char            *connection_client_id = "none";
    gs_unref_bytes GBytes *expected_client_id   = NULL;

    test_config(none_client_id_orig,
                none_client_id_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                connection_client_id,
                expected_client_id,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *missing_client_id_orig = "";

static const char *missing_client_id_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_missing_client_id(void)
{
    const char            *connection_client_id = NULL;
    gs_unref_bytes GBytes *expected_client_id   = NULL;

    test_config(missing_client_id_orig,
                missing_client_id_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                connection_client_id,
                expected_client_id,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *fqdn_expected =
    "# Created by NetworkManager\n"
    "\n"
    "send fqdn.fqdn \"foo.bar.com\"; # added by NetworkManager\n"
    "send fqdn.encoded on;\n"
    "send fqdn.server-update off;\n"
    "send fqdn.no-client-update on;\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n\n";

static void
test_fqdn(void)
{
    test_config(NULL,
                fqdn_expected,
                AF_INET,
                "foo.bar.com",
                0,
                TRUE,
                NM_DHCP_HOSTNAME_FLAG_FQDN_ENCODED | NM_DHCP_HOSTNAME_FLAG_FQDN_NO_UPDATE,
                NULL,
                NULL,
                "eth0",
                NULL,
                NULL);
}

static const char *fqdn_options_override_orig =
    "\n"
    "send fqdn.fqdn \"foobar.com\"\n" /* NM must ignore this ... */
    "send fqdn.encoded off;\n"        /* ... and honor these */
    "send fqdn.server-update off;\n";

static const char *fqdn_options_override_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n"
    "send fqdn.fqdn \"example2.com\"; # added by NetworkManager\n"
    "send fqdn.encoded off;\n"
    "send fqdn.server-update on;\n"
    "send fqdn.no-client-update off;\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n"
    "# FQDN options from /path/to/dhclient.conf\n"
    "send fqdn.encoded off;\n"
    "send fqdn.server-update off;\n\n";

static void
test_fqdn_options_override(void)
{
    test_config(fqdn_options_override_orig,
                fqdn_options_override_expected,
                AF_INET,
                "example2.com",
                0,
                NM_DHCP_HOSTNAME_FLAG_FQDN_SERV_UPDATE,
                TRUE,
                NULL,
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *override_hostname_orig = "send host-name \"foobar\";\n";

static const char *override_hostname_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n"
    "send host-name \"blahblah\"; # added by NetworkManager\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_override_hostname(void)
{
    test_config(override_hostname_orig,
                override_hostname_expected,
                AF_INET,
                "blahblah",
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                NULL,
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *override_hostname6_orig = "send fqdn.fqdn \"foobar\";\n";

static const char *override_hostname6_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n"
    "send fqdn.fqdn \"blahblah.local\"; # added by NetworkManager\n"
    "send fqdn.server-update on;\n"
    "\n"
    "also request dhcp6.name-servers;\n"
    "also request dhcp6.domain-search;\n"
    "also request dhcp6.client-id;\n"
    "\n";

static void
test_override_hostname6(void)
{
    test_config(override_hostname6_orig,
                override_hostname6_expected,
                AF_INET6,
                "blahblah.local",
                0,
                TRUE,
                NM_DHCP_HOSTNAME_FLAG_FQDN_SERV_UPDATE,
                NULL,
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *nonfqdn_hostname6_expected =
    "# Created by NetworkManager\n"
    "\n"
    "send fqdn.fqdn \"blahblah\"; # added by NetworkManager\n"
    "send fqdn.no-client-update on;\n"
    "\n"
    "also request dhcp6.name-servers;\n"
    "also request dhcp6.domain-search;\n"
    "also request dhcp6.client-id;\n"
    "\n";

static void
test_nonfqdn_hostname6(void)
{
    /* Non-FQDN hostname can now be used with dhclient */
    test_config(NULL,
                nonfqdn_hostname6_expected,
                AF_INET6,
                "blahblah",
                0,
                TRUE,
                NM_DHCP_HOSTNAME_FLAG_FQDN_NO_UPDATE,
                NULL,
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *existing_alsoreq_orig = "also request something;\n"
                                           "also request another-thing;\n";

static const char *existing_alsoreq_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request something;\n"
    "also request another-thing;\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_existing_alsoreq(void)
{
    test_config(existing_alsoreq_orig,
                existing_alsoreq_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                NULL,
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *existing_req_orig = "request something;\n"
                                       "also request some-other-thing;\n"
                                       "request another-thing;\n"
                                       "also request yet-another-thing;\n";

static const char *existing_req_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "request; # override dhclient defaults\n"
    "also request another-thing;\n"
    "also request yet-another-thing;\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_existing_req(void)
{
    test_config(existing_req_orig,
                existing_req_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                NULL,
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *existing_multiline_alsoreq_orig =
    "also request something another-thing yet-another-thing\n"
    "    foobar baz blah;\n";

static const char *existing_multiline_alsoreq_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request something;\n"
    "also request another-thing;\n"
    "also request yet-another-thing;\n"
    "also request foobar;\n"
    "also request baz;\n"
    "also request blah;\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_existing_multiline_alsoreq(void)
{
    test_config(existing_multiline_alsoreq_orig,
                existing_multiline_alsoreq_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                NULL,
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static void
test_one_duid(const char *escaped, const guint8 *unescaped, guint len)
{
    gs_unref_bytes GBytes *t1 = NULL;
    gs_unref_bytes GBytes *t2 = NULL;
    gs_free char          *w  = NULL;

    t1 = nm_dhcp_dhclient_unescape_duid(escaped);
    g_assert(t1);
    g_assert(nm_g_bytes_equal_mem(t1, unescaped, len));

    t2 = g_bytes_new(unescaped, len);
    w  = nm_dhcp_dhclient_escape_duid(t2);
    g_assert(w);
    g_assert_cmpstr(escaped, ==, w);
}

static void
test_duids(void)
{
    const guint8 test1_u[] =
        {0x00, 0x01, 0x00, 0x01, 0x13, 0x6f, 0x13, 0x6e, 0x00, 0x22, 0xfa, 0x8c, 0xd6, 0xc2};
    const char *test1_s = "\\000\\001\\000\\001\\023o\\023n\\000\\\"\\372\\214\\326\\302";

    const guint8 test2_u[] =
        {0x00, 0x01, 0x00, 0x01, 0x17, 0x57, 0xee, 0x39, 0x00, 0x23, 0x15, 0x08, 0x7E, 0xac};
    const char *test2_s = "\\000\\001\\000\\001\\027W\\3569\\000#\\025\\010~\\254";

    const guint8 test3_u[] =
        {0x00, 0x01, 0x00, 0x01, 0x17, 0x58, 0xe8, 0x58, 0x00, 0x23, 0x15, 0x08, 0x7e, 0xac};
    const char *test3_s = "\\000\\001\\000\\001\\027X\\350X\\000#\\025\\010~\\254";

    const guint8 test4_u[] =
        {0x00, 0x01, 0x00, 0x01, 0x15, 0xd5, 0x31, 0x97, 0x00, 0x16, 0xeb, 0x04, 0x45, 0x18};
    const char *test4_s = "\\000\\001\\000\\001\\025\\3251\\227\\000\\026\\353\\004E\\030";

    const char *bad_s = "\\000\\001\\000\\001\\425\\3251\\227\\000\\026\\353\\004E\\030";

    test_one_duid(test1_s, test1_u, sizeof(test1_u));
    test_one_duid(test2_s, test2_u, sizeof(test2_u));
    test_one_duid(test3_s, test3_u, sizeof(test3_u));
    test_one_duid(test4_s, test4_u, sizeof(test4_u));

    /* Invalid octal digit */
    g_assert(nm_dhcp_dhclient_unescape_duid(bad_s) == NULL);
}

static void
test_read_duid_from_leasefile(void)
{
    const guint8 expected[] =
        {0x00, 0x01, 0x00, 0x01, 0x18, 0x79, 0xa6, 0x13, 0x60, 0x67, 0x20, 0xec, 0x4c, 0x70};
    gs_unref_bytes GBytes *duid  = NULL;
    GError                *error = NULL;

    duid = nm_dhcp_dhclient_read_duid(TEST_DIR "/test-dhclient-duid.leases", &error);
    nmtst_assert_success(duid, error);

    g_assert(nm_g_bytes_equal_mem(duid, expected, G_N_ELEMENTS(expected)));
}

static void
test_read_commented_duid_from_leasefile(void)
{
    GBytes *duid;
    GError *error = NULL;

    duid = nm_dhcp_dhclient_read_duid(TEST_DIR "/test-dhclient-commented-duid.leases", &error);
    g_assert_no_error(error);
    g_assert(duid == NULL);
}

/*****************************************************************************/

static void
_check_duid_impl(const guint8 *duid_bin,
                 gsize         duid_len,
                 gboolean      enforce_duid,
                 const char   *old_content,
                 const char   *new_content)
{
    gs_free_error GError  *error    = NULL;
    gs_free char          *contents = NULL;
    gboolean               success;
    const char            *path = NM_BUILD_BUILDDIR "/src/core/dhcp/tests/check-duid.lease";
    gs_unref_bytes GBytes *duid = NULL;
    gsize                  contents_len;

    g_assert(duid_bin);
    g_assert(duid_len > 0);

    if (!nm_str_is_empty(old_content) || nmtst_get_rand_bool()) {
        success = g_file_set_contents(path, old_content ?: "", -1, &error);
        nmtst_assert_success(success, error);
    } else
        nmtst_file_unlink_if_exists(path);

    duid = g_bytes_new(duid_bin, duid_len);

    success = nm_dhcp_dhclient_save_duid(path, duid, enforce_duid, &error);
    nmtst_assert_success(success, error);

    success = g_file_get_contents(path, &contents, &contents_len, &error);
    nmtst_assert_success(success, error);
    g_assert(contents);

    nmtst_file_unlink(path);

    if (!nm_streq0(new_content, contents))
        g_error("FAILING:\n\nEXPECTED:\n%s\nACTUAL:\n%s\n\n", new_content, contents);

    g_assert_cmpstr(new_content, ==, contents);
    g_assert_cmpint(contents_len, ==, strlen(contents));
}

#define _DUID(...) ((const guint8[]) {__VA_ARGS__})

#define _check_duid(duid, enforce_duid, old_content, new_content) \
    _check_duid_impl((duid), sizeof(duid), (enforce_duid), (old_content), (new_content))

static void
test_write_duid(void)
{
    _check_duid(_DUID(000, 001, 000, 001, 027, 'X', 0350, 'X', 0, '#', 025, 010, '~', 0254),
                FALSE,
                NULL,
                "default-duid \"\\000\\001\\000\\001\\027X\\350X\\000#\\025\\010~\\254\";\n");

    _check_duid(
        _DUID(000, 001, 000, 001, 023, 'o', 023, 'n', 000, '"', 0372, 0214, 0326, 0302),
        FALSE,
        "default-duid \"\\000\\001\\000\\001\\027X\\350X\\000#\\025\\010~\\254\";\n",
        "default-duid \"\\000\\001\\000\\001\\023o\\023n\\000\\\"\\372\\214\\326\\302\";\n");

    _check_duid(_DUID(000, 001, 000, 001, 023, 'o', 023, 'n', 000, '"', 0372, 0214, 0326, 0302),
                FALSE,
                "#default-duid \"\\000\\001\\000\\001\\027X\\350X\\000#\\025\\010~\\254\";\n",
                "default-duid "
                "\"\\000\\001\\000\\001\\023o\\023n\\000\\\"\\372\\214\\326\\302\";\n#default-duid "
                "\"\\000\\001\\000\\001\\027X\\350X\\000#\\025\\010~\\254\";\n");
    _check_duid(
        _DUID(000, 001, 000, 001, 023, 'o', 023, 'n', 000, '"', 0372, 0214, 0326, 0302),
        FALSE,
        "### Commented old DUID ###\n#default-duid "
        "\"\\000\\001\\000\\001\\027X\\350X\\000#\\025\\010~\\254\";\n",
        "default-duid \"\\000\\001\\000\\001\\023o\\023n\\000\\\"\\372\\214\\326\\302\";\n### "
        "Commented old DUID ###\n#default-duid "
        "\"\\000\\001\\000\\001\\027X\\350X\\000#\\025\\010~\\254\";\n");

    _check_duid(
        _DUID(0xaa, 0xb, 0xcc, 0xd, 0xee, 0xf),
        FALSE,
        "default-duid \"\\252\\013\\314\\015\\356\\017\";\nlease6 {\n  interface \"eth1\";\n "
        " ia-na f1:ce:00:01 {\n    starts 1671015678;\n    renew 60;\n    rebind 105;\n    "
        "iaaddr 192:168:121::1:112c {\n      starts 1671015678;\n      preferred-life 120;\n "
        "     max-life 120;\n    }\n  }\n  option fqdn.encoded true;\n  option "
        "fqdn.server-update true;\n  option fqdn.no-client-update false;\n  option fqdn.fqdn "
        "\"dff6de4fcb0f\";\n  option fqdn.hostname \"dff6de4fcb0f\";\n  option dhcp6.client-id "
        "aa:b:cc:d:ee:f;\n  option dhcp6.server-id 0:1:0:1:2b:2c:4d:1d:0:0:0:0:0:0;\n  option "
        "dhcp6.name-servers 192:168:121:0:ce0f:f1ff:fece:1;\n  option dhcp6.fqdn "
        "1:c:64:66:66:36:64:65:34:66:63:62:30:66;\n  option dhcp6.status-code success "
        "\"success\";\n}\n",
        "default-duid \"\\252\\013\\314\\015\\356\\017\";\nlease6 {\n  interface \"eth1\";\n "
        " ia-na f1:ce:00:01 {\n    starts 1671015678;\n    renew 60;\n    rebind 105;\n    "
        "iaaddr 192:168:121::1:112c {\n      starts 1671015678;\n      preferred-life 120;\n "
        "     max-life 120;\n    }\n  }\n  option fqdn.encoded true;\n  option "
        "fqdn.server-update true;\n  option fqdn.no-client-update false;\n  option fqdn.fqdn "
        "\"dff6de4fcb0f\";\n  option fqdn.hostname \"dff6de4fcb0f\";\n  option dhcp6.client-id "
        "aa:b:cc:d:ee:f;\n  option dhcp6.server-id 0:1:0:1:2b:2c:4d:1d:0:0:0:0:0:0;\n  option "
        "dhcp6.name-servers 192:168:121:0:ce0f:f1ff:fece:1;\n  option dhcp6.fqdn "
        "1:c:64:66:66:36:64:65:34:66:63:62:30:66;\n  option dhcp6.status-code success "
        "\"success\";\n}\n");

    _check_duid(
        _DUID(0xaa, 0xb, 0xcc, 0xd, 0xee, 0xf),
        FALSE,
        "default-duid \"\\252\\013\\314\\015\\356\\017\";\nlease6 {\n  interface \"eth1\";\n "
        " ia-na f1:ce:00:01 {\n    starts 1671015678;\n    renew 60;\n    rebind 105;\n    "
        "iaaddr 192:168:121::1:112c {\n      starts 1671015678;\n      preferred-life 120;\n "
        "     max-life 120;\n    }\n  }\n  option fqdn.encoded true;\n  option "
        "fqdn.server-update true;\n  option fqdn.no-client-update false;\n  option fqdn.fqdn "
        "\"dff6de4fcb0f\";\n  option fqdn.hostname \"dff6de4fcb0f\";\n  option dhcp6.client-id "
        "aa:b:cc:d:ee:f;\n  option dhcp6.server-id 0:1:0:1:2b:2c:4d:1d:0:0:0:0:0:0;\n  option "
        "dhcp6.name-servers 192:168:121:0:ce0f:f1ff:fece:1;\n  option dhcp6.fqdn "
        "1:c:64:66:66:36:64:65:34:66:63:62:30:66;\n  option dhcp6.status-code success "
        "\"success\";\r\n}\n",
        "default-duid \"\\252\\013\\314\\015\\356\\017\";\nlease6 {\n  interface \"eth1\";\n "
        " ia-na f1:ce:00:01 {\n    starts 1671015678;\n    renew 60;\n    rebind 105;\n    "
        "iaaddr 192:168:121::1:112c {\n      starts 1671015678;\n      preferred-life 120;\n "
        "     max-life 120;\n    }\n  }\n  option fqdn.encoded true;\n  option "
        "fqdn.server-update true;\n  option fqdn.no-client-update false;\n  option fqdn.fqdn "
        "\"dff6de4fcb0f\";\n  option fqdn.hostname \"dff6de4fcb0f\";\n  option dhcp6.client-id "
        "aa:b:cc:d:ee:f;\n  option dhcp6.server-id 0:1:0:1:2b:2c:4d:1d:0:0:0:0:0:0;\n  option "
        "dhcp6.name-servers 192:168:121:0:ce0f:f1ff:fece:1;\n  option dhcp6.fqdn "
        "1:c:64:66:66:36:64:65:34:66:63:62:30:66;\n  option dhcp6.status-code success "
        "\"success\";\r\n}\n");

    _check_duid(
        _DUID(0xaa, 0xb, 0xcc, 0xd, 0xee, 0xe),
        FALSE,
        "default-duid \"\\252\\013\\314\\015\\356\\017\";\nlease6 {\n  interface \"eth1\";\n "
        " ia-na f1:ce:00:01 {\n    starts 1671015678;\n    renew 60;\n    rebind 105;\n    "
        "iaaddr 192:168:121::1:112c {\n      starts 1671015678;\n      preferred-life 120;\n "
        "     max-life 120;\n    }\n  }\n  option fqdn.encoded true;\n  option "
        "fqdn.server-update true;\n  option fqdn.no-client-update false;\n  option fqdn.fqdn "
        "\"dff6de4fcb0f\";\n  option fqdn.hostname \"dff6de4fcb0f\";\n  option dhcp6.client-id "
        "aa:b:cc:d:ee:f;\n  option dhcp6.server-id 0:1:0:1:2b:2c:4d:1d:0:0:0:0:0:0;\n  option "
        "dhcp6.name-servers 192:168:121:0:ce0f:f1ff:fece:1;\n  option dhcp6.fqdn "
        "1:c:64:66:66:36:64:65:34:66:63:62:30:66;\n  option dhcp6.status-code success "
        "\"success\";\r\n}\n",
        "default-duid \"\\252\\013\\314\\015\\356\\016\";\nlease6 {\n  interface \"eth1\";\n "
        " ia-na f1:ce:00:01 {\n    starts 1671015678;\n    renew 60;\n    rebind 105;\n    "
        "iaaddr 192:168:121::1:112c {\n      starts 1671015678;\n      preferred-life 120;\n "
        "     max-life 120;\n    }\n  }\n  option fqdn.encoded true;\n  option "
        "fqdn.server-update true;\n  option fqdn.no-client-update false;\n  option fqdn.fqdn "
        "\"dff6de4fcb0f\";\n  option fqdn.hostname \"dff6de4fcb0f\";\n  option dhcp6.client-id "
        "aa:b:cc:d:ee:f;\n  option dhcp6.server-id 0:1:0:1:2b:2c:4d:1d:0:0:0:0:0:0;\n  option "
        "dhcp6.name-servers 192:168:121:0:ce0f:f1ff:fece:1;\n  option dhcp6.fqdn "
        "1:c:64:66:66:36:64:65:34:66:63:62:30:66;\n  option dhcp6.status-code success "
        "\"success\";\r\n}\n");

    _check_duid(
        _DUID(0xaa, 0xb, 0xcc, 0xd, 0xee, 0xe),
        TRUE,
        "default-duid \"\\252\\013\\314\\015\\356\\017\";\nlease6 {\n  interface \"eth1\";\n "
        " ia-na f1:ce:00:01 {\n    starts 1671015678;\n    renew 60;\n    rebind 105;\n    "
        "iaaddr 192:168:121::1:112c {\n      starts 1671015678;\n      preferred-life 120;\n "
        "     max-life 120;\n    }\n  }\n  option fqdn.encoded true;\n  option "
        "fqdn.server-update true;\n  option fqdn.no-client-update false;\n  option fqdn.fqdn "
        "\"dff6de4fcb0f\";\n  option fqdn.hostname \"dff6de4fcb0f\";\n  option dhcp6.client-id "
        "aa:b:cc:d:ee:f;\n  option dhcp6.server-id 0:1:0:1:2b:2c:4d:1d:0:0:0:0:0:0;\n  option "
        "dhcp6.name-servers 192:168:121:0:ce0f:f1ff:fece:1;\n  option dhcp6.fqdn "
        "1:c:64:66:66:36:64:65:34:66:63:62:30:66;\n  option dhcp6.status-code success "
        "\"success\";\n}\n",
        "default-duid \"\\252\\013\\314\\015\\356\\016\";\nlease6 {\n  interface \"eth1\";\n "
        " ia-na f1:ce:00:01 {\n    starts 1671015678;\n    renew 60;\n    rebind 105;\n    "
        "iaaddr 192:168:121::1:112c {\n      starts 1671015678;\n      preferred-life 120;\n "
        "     max-life 120;\n    }\n  }\n  option fqdn.encoded true;\n  option "
        "fqdn.server-update true;\n  option fqdn.no-client-update false;\n  option fqdn.fqdn "
        "\"dff6de4fcb0f\";\n  option fqdn.hostname \"dff6de4fcb0f\";\n  option dhcp6.client-id "
        "aa:b:cc:d:ee:e;\n  option dhcp6.server-id 0:1:0:1:2b:2c:4d:1d:0:0:0:0:0:0;\n  option "
        "dhcp6.name-servers 192:168:121:0:ce0f:f1ff:fece:1;\n  option dhcp6.fqdn "
        "1:c:64:66:66:36:64:65:34:66:63:62:30:66;\n  option dhcp6.status-code success "
        "\"success\";\n}\n");
}

/*****************************************************************************/

static const char *interface1_orig = "interface \"eth0\" {\n"
                                     "\talso request my-option;\n"
                                     "\tinitial-delay 5;\n"
                                     "}\n"
                                     "interface \"eth1\" {\n"
                                     "\talso request another-option;\n"
                                     "\tinitial-delay 0;\n"
                                     "}\n"
                                     "\n"
                                     "also request yet-another-option;\n";

static const char *interface1_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n"
    "initial-delay 5;\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "also request my-option;\n"
    "also request yet-another-option;\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_interface1(void)
{
    test_config(interface1_orig,
                interface1_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                NULL,
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

static const char *interface2_orig = "interface eth0 {\n"
                                     "\talso request my-option;\n"
                                     "\tinitial-delay 5;\n"
                                     " }\n"
                                     "interface eth1 {\n"
                                     "\tinitial-delay 0;\n"
                                     "\trequest another-option;\n"
                                     " } \n"
                                     "\n"
                                     "also request yet-another-option;\n";

static const char *interface2_expected =
    "# Created by NetworkManager\n"
    "# Merged from /path/to/dhclient.conf\n"
    "\n"
    "initial-delay 0;\n"
    "\n"
    "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
    "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
    "option wpad code 252 = string;\n"
    "\n"
    "request; # override dhclient defaults\n"
    "also request another-option;\n"
    "also request yet-another-option;\n"
    "also request rfc3442-classless-static-routes;\n"
    "also request ms-classless-static-routes;\n"
    "also request static-routes;\n"
    "also request wpad;\n"
    "also request ntp-servers;\n"
    "also request root-path;\n"
    "\n";

static void
test_interface2(void)
{
    test_config(interface2_orig,
                interface2_expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                NULL,
                NULL,
                "eth1",
                NULL,
                NULL);
}

static void
test_structured(void)
{
    gs_unref_bytes GBytes *new_client_id = NULL;
    const guint8           bytes[]       = "sad-and-useless";

    static const char *const orig =
        "interface \"eth0\"   {  \n"
        "    send host-name \"useless.example.com\";\n"
        "    hardware ethernet de:ad:80:86:ba:be;\n"
        "    send dhcp-client-identifier \"sad-and-useless\";\n"
        "    script \"/bin/useless\";\n"
        "    send dhcp-lease-time 8086;\n"
        "    request subnet-mask, broadcast-address, time-offset, routers,\n"
        "        domain-search, domain-name, host-name;\n"
        "    require subnet-mask;\n"
        "}  \n"
        "\n"
        "    interface \"eth1\"   {  \n"
        "    send host-name \"sad.example.com\";\n"
        "    hardware ethernet de:ca:f6:66:ca:fe;\n"
        "    send dhcp-client-identifier \"useless-and-miserable\";\n"
        "    script \"/bin/miserable\";\n"
        "    send dhcp-lease-time 1337;\n"
        "    request subnet-mask, broadcast-address, time-offset, routers,\n"
        "        domain-search, domain-name, domain-name-servers, host-name;\n"
        "    require subnet-mask, domain-name-servers;\n"
        "    if not option domain-name = \"example.org\" {\n"
        "        prepend domain-name-servers 127.0.0.1;\n"
        "    } else {\n"
        "        prepend domain-name-servers 127.0.0.2;\n"
        "    }  \n"
        "    }  \n"
        "\n"
        "pseudo \"secondary\" \"eth0\"   {  \n"
        "    send dhcp-client-identifier \"sad-useless-and-secondary\";\n"
        "    script \"/bin/secondary\";\n"
        "    send host-name \"secondary.useless.example.com\";\n"
        "    send dhcp-lease-time 666;\n"
        "    request routers;\n"
        "    require routers;\n"
        "    }  \n"
        "\n"
        "    pseudo \"tertiary\" \"eth0\"   {  \n"
        "   send dhcp-client-identifier \"sad-useless-and-tertiary\";\n"
        "  script \"/bin/tertiary\";\n"
        " send host-name \"tertiary.useless.example.com\";\n"
        "}  \n"
        "\n"
        "  alias{  \n"
        "    interface \"eth0\";\n"
        "    fixed-address 192.0.2.1;\n"
        "    option subnet-mask 255.255.255.0;\n"
        "  }  \n"
        "  lease   {  \n"
        "    interface \"eth0\";\n"
        "    fixed-address 192.0.2.2;\n"
        "    option subnet-mask 255.255.255.0;\n"
        "  }  \n"
        "if not option domain-name = \"example.org\" {\n"
        "  prepend domain-name-servers 127.0.0.1;\n"
        "  if not option domain-name = \"useless.example.com\" {\n"
        "    prepend domain-name-servers 127.0.0.2;\n"
        "  }\n"
        "}\n";

    static const char *const expected =
        "# Created by NetworkManager\n"
        "# Merged from /path/to/dhclient.conf\n"
        "\n"
        "send host-name \"useless.example.com\";\n"
        "hardware ethernet de:ad:80:86:ba:be;\n"
        "send dhcp-client-identifier \"sad-and-useless\";\n"
        "send dhcp-lease-time 8086;\n"
        "require subnet-mask;\n"
        "if not option domain-name = \"example.org\" {\n"
        "prepend domain-name-servers 127.0.0.1;\n"
        "if not option domain-name = \"useless.example.com\" {\n"
        "prepend domain-name-servers 127.0.0.2;\n"
        "}\n"
        "}\n"
        "\n"
        "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
        "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
        "option wpad code 252 = string;\n"
        "\n"
        "request; # override dhclient defaults\n"
        "also request subnet-mask;\n"
        "also request broadcast-address;\n"
        "also request time-offset;\n"
        "also request routers;\n"
        "also request domain-search;\n"
        "also request domain-name;\n"
        "also request host-name;\n"
        "also request rfc3442-classless-static-routes;\n"
        "also request ms-classless-static-routes;\n"
        "also request static-routes;\n"
        "also request wpad;\n"
        "also request ntp-servers;\n"
        "also request root-path;\n"
        "\n";

    new_client_id = g_bytes_new(bytes, sizeof(bytes) - 1);
    test_config(orig,
                expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                NULL,
                new_client_id,
                "eth0",
                NULL,
                NULL);
}

static void
test_config_req_intf(void)
{
    static const char *const orig = "request subnet-mask, broadcast-address, routers,\n"
                                    "\trfc3442-classless-static-routes,\n"
                                    "\tinterface-mtu, host-name, domain-name, domain-search,\n"
                                    "\tdomain-name-servers, nis-domain, nis-servers,\n"
                                    "\tnds-context, nds-servers, nds-tree-name,\n"
                                    "\tnetbios-name-servers, netbios-dd-server,\n"
                                    "\tnetbios-node-type, netbios-scope, ntp-servers;\n"
                                    "";
    static const char *const expected =
        "# Created by NetworkManager\n"
        "# Merged from /path/to/dhclient.conf\n"
        "\n"
        "\n"
        "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
        "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
        "option wpad code 252 = string;\n"
        "\n"
        "request; # override dhclient defaults\n"
        "also request subnet-mask;\n"
        "also request broadcast-address;\n"
        "also request routers;\n"
        "also request rfc3442-classless-static-routes;\n"
        "also request interface-mtu;\n"
        "also request host-name;\n"
        "also request domain-name;\n"
        "also request domain-search;\n"
        "also request domain-name-servers;\n"
        "also request nis-domain;\n"
        "also request nis-servers;\n"
        "also request nds-context;\n"
        "also request nds-servers;\n"
        "also request nds-tree-name;\n"
        "also request netbios-name-servers;\n"
        "also request netbios-dd-server;\n"
        "also request netbios-node-type;\n"
        "also request netbios-scope;\n"
        "also request ntp-servers;\n"
        "also request ms-classless-static-routes;\n"
        "also request static-routes;\n"
        "also request wpad;\n"
        "also request root-path;\n"
        "\n";

    test_config(orig,
                expected,
                AF_INET,
                NULL,
                0,
                FALSE,
                NM_DHCP_HOSTNAME_FLAG_NONE,
                NULL,
                NULL,
                "eth0",
                NULL,
                NULL);
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init_with_logging(&argc, &argv, NULL, "DEFAULT");

    g_test_add_func("/dhcp/dhclient/orig_missing", test_orig_missing);
    g_test_add_func("/dhcp/dhclient/orig_missing_add_mud_url", test_orig_missing_add_mud_url);
    g_test_add_func("/dhcp/dhclient/override_client_id", test_override_client_id);
    g_test_add_func("/dhcp/dhclient/quote_client_id/1", test_quote_client_id);
    g_test_add_func("/dhcp/dhclient/quote_client_id/2", test_quote_client_id_2);
    g_test_add_func("/dhcp/dhclient/hex_zero_client_id", test_hex_zero_client_id);
    g_test_add_func("/dhcp/dhclient/ascii_client_id", test_ascii_client_id);
    g_test_add_func("/dhcp/dhclient/hex_single_client_id", test_hex_single_client_id);
    g_test_add_func("/dhcp/dhclient/existing-hex-client-id", test_existing_hex_client_id);
    g_test_add_func("/dhcp/dhclient/existing-client-id", test_existing_escaped_client_id);
    g_test_add_func("/dhcp/dhclient/existing-ascii-client-id", test_existing_ascii_client_id);
    g_test_add_func("/dhcp/dhclient/none-client-id", test_none_client_id);
    g_test_add_func("/dhcp/dhclient/missing-client-id", test_missing_client_id);
    g_test_add_func("/dhcp/dhclient/fqdn", test_fqdn);
    g_test_add_func("/dhcp/dhclient/fqdn_options_override", test_fqdn_options_override);
    g_test_add_func("/dhcp/dhclient/override_hostname", test_override_hostname);
    g_test_add_func("/dhcp/dhclient/override_hostname6", test_override_hostname6);
    g_test_add_func("/dhcp/dhclient/nonfqdn_hostname6", test_nonfqdn_hostname6);
    g_test_add_func("/dhcp/dhclient/existing_req", test_existing_req);
    g_test_add_func("/dhcp/dhclient/existing_alsoreq", test_existing_alsoreq);
    g_test_add_func("/dhcp/dhclient/existing_multiline_alsoreq", test_existing_multiline_alsoreq);
    g_test_add_func("/dhcp/dhclient/duids", test_duids);
    g_test_add_func("/dhcp/dhclient/interface/1", test_interface1);
    g_test_add_func("/dhcp/dhclient/interface/2", test_interface2);
    g_test_add_func("/dhcp/dhclient/config/req_intf", test_config_req_intf);
    g_test_add_func("/dhcp/dhclient/structured", test_structured);

    g_test_add_func("/dhcp/dhclient/read_duid_from_leasefile", test_read_duid_from_leasefile);
    g_test_add_func("/dhcp/dhclient/read_commented_duid_from_leasefile",
                    test_read_commented_duid_from_leasefile);

    g_test_add_func("/dhcp/dhclient/test_write_duid", test_write_duid);

    return g_test_run();
}
