/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2008 - 2017 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include <linux/pkt_sched.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_infiniband.h>

#include "libnm-glib-aux/nm-uuid.h"
#include "libnm-glib-aux/nm-json-aux.h"
#include "libnm-base/nm-ethtool-utils-base.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-setting-8021x.h"
#include "nm-setting-bond.h"
#include "nm-setting-dcb.h"
#include "nm-setting-ethtool.h"
#include "nm-setting-team.h"
#include "nm-setting-team-port.h"
#include "nm-setting-tc-config.h"
#include "nm-setting-dummy.h"
#include "nm-connection.h"
#include "nm-simple-connection.h"
#include "nm-setting-connection.h"
#include "nm-errors.h"
#include "libnm-core-intern/nm-keyfile-internal.h"

#include "libnm-glib-aux/nm-test-utils.h"

#define TEST_CERT_DIR NM_BUILD_SRCDIR "/src/libnm-core-impl/tests/certs"

/*****************************************************************************/

/* converts @dict to a connection. In this case, @dict must be good, without warnings, so that
 * NM_SETTING_PARSE_FLAGS_STRICT and NM_SETTING_PARSE_FLAGS_BEST_EFFORT yield the exact same results. */
static NMConnection *
_connection_new_from_dbus_strict(GVariant *dict, gboolean normalize)
{
    gs_unref_object NMConnection *con_x_0 = NULL;
    gs_unref_object NMConnection *con_x_s = NULL;
    gs_unref_object NMConnection *con_x_e = NULL;
    gs_unref_object NMConnection *con_n_0 = NULL;
    gs_unref_object NMConnection *con_n_s = NULL;
    gs_unref_object NMConnection *con_n_e = NULL;
    gs_free_error GError         *error   = NULL;
    guint                         i;

    g_assert(g_variant_is_of_type(dict, NM_VARIANT_TYPE_CONNECTION));

    con_x_0 = _nm_simple_connection_new_from_dbus(dict, NM_SETTING_PARSE_FLAGS_NONE, &error);
    nmtst_assert_success(NM_IS_CONNECTION(con_x_0), error);

    con_x_s = _nm_simple_connection_new_from_dbus(dict, NM_SETTING_PARSE_FLAGS_STRICT, &error);
    nmtst_assert_success(NM_IS_CONNECTION(con_x_s), error);

    con_x_e = _nm_simple_connection_new_from_dbus(dict, NM_SETTING_PARSE_FLAGS_BEST_EFFORT, &error);
    nmtst_assert_success(NM_IS_CONNECTION(con_x_e), error);

    con_n_0 = _nm_simple_connection_new_from_dbus(dict, NM_SETTING_PARSE_FLAGS_NORMALIZE, &error);
    nmtst_assert_success(NM_IS_CONNECTION(con_n_0), error);

    con_n_s = _nm_simple_connection_new_from_dbus(dict,
                                                  NM_SETTING_PARSE_FLAGS_STRICT
                                                      | NM_SETTING_PARSE_FLAGS_NORMALIZE,
                                                  &error);
    nmtst_assert_success(NM_IS_CONNECTION(con_n_s), error);

    con_n_e = _nm_simple_connection_new_from_dbus(dict,
                                                  NM_SETTING_PARSE_FLAGS_BEST_EFFORT
                                                      | NM_SETTING_PARSE_FLAGS_NORMALIZE,
                                                  &error);
    nmtst_assert_success(NM_IS_CONNECTION(con_n_e), error);

    nmtst_assert_connection_verifies(con_x_0);
    nmtst_assert_connection_verifies(con_x_e);
    nmtst_assert_connection_verifies(con_x_s);

    nmtst_assert_connection_verifies_without_normalization(con_n_0);
    nmtst_assert_connection_verifies_without_normalization(con_n_e);
    nmtst_assert_connection_verifies_without_normalization(con_n_s);

    /* randomly compare some pairs that we created. They must all be equal,
     * after accounting for normalization. */
    for (i = 0; i < 10; i++) {
        NMConnection *cons[] = {con_x_0, con_x_s, con_x_e, con_n_0, con_n_s, con_n_e};
        guint         idx_a  = (nmtst_get_rand_uint32() % G_N_ELEMENTS(cons));
        guint         idx_b  = (nmtst_get_rand_uint32() % G_N_ELEMENTS(cons));
        gboolean      normalize_a, normalize_b;

        if (idx_a <= 2 && idx_b <= 2) {
            normalize_a = nmtst_get_rand_bool();
            normalize_b = normalize_a;
        } else if (idx_a > 2 && idx_b > 2) {
            normalize_a = nmtst_get_rand_bool();
            normalize_b = nmtst_get_rand_bool();
        } else {
            normalize_a = (idx_a <= 2) ? TRUE : nmtst_get_rand_bool();
            normalize_b = (idx_b <= 2) ? TRUE : nmtst_get_rand_bool();
        }
        nmtst_assert_connection_equals(cons[idx_a], normalize_a, cons[idx_b], normalize_b);
    }

    return (normalize) ? g_steal_pointer(&con_x_0) : g_steal_pointer(&con_n_0);
}

/*****************************************************************************/

static void
test_nm_meta_setting_types_by_priority(void)
{
    gs_unref_ptrarray GPtrArray *arr = NULL;
    int                          i;
    int                          j;

    G_STATIC_ASSERT_EXPR(_NM_META_SETTING_TYPE_NUM
                         == G_N_ELEMENTS(nm_meta_setting_types_by_priority));

    arr = g_ptr_array_new_with_free_func(g_object_unref);

    for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
        const NMMetaSettingType  meta_type = nm_meta_setting_types_by_priority[i];
        const NMMetaSettingInfo *setting_info;
        NMSetting               *setting;

        g_assert(_NM_INT_NOT_NEGATIVE(meta_type));
        g_assert(meta_type < _NM_META_SETTING_TYPE_NUM);

        setting_info = &nm_meta_setting_infos[meta_type];
        g_assert(setting_info);
        _nm_assert_setting_info(setting_info, 0);

        for (j = 0; j < i; j++)
            g_assert_cmpint(nm_meta_setting_types_by_priority[j], !=, meta_type);

        setting = g_object_new(setting_info->get_setting_gtype(), NULL);
        g_assert(NM_IS_SETTING(setting));

        g_ptr_array_add(arr, setting);
    }

    for (i = 1; i < _NM_META_SETTING_TYPE_NUM; i++) {
        NMSetting *setting = arr->pdata[i];

        for (j = 0; j < i; j++) {
            NMSetting *other = arr->pdata[j];

            if (_nm_setting_sort_for_nm_assert(other, setting) >= 0) {
                g_error("sort order for nm_meta_setting_types_by_priority[%d vs %d] is wrong: %s "
                        "should be before %s",
                        j,
                        i,
                        nm_setting_get_name(setting),
                        nm_setting_get_name(other));
            }
        }
    }
}

/*****************************************************************************/

static char *
_create_random_ipaddr(int addr_family, gboolean as_service)
{
    char delimiter = as_service ? ':' : '/';
    int  num;

    if (addr_family == AF_UNSPEC)
        addr_family = nmtst_rand_select(AF_INET, AF_INET6);

    g_assert(NM_IN_SET(addr_family, AF_INET, AF_INET6));

    if (as_service)
        num = (nmtst_get_rand_uint32() % 1000) + 30000;
    else
        num = addr_family == AF_INET ? 32 : 128;

    if (addr_family == AF_INET)
        return g_strdup_printf("192.168.%u.%u%c%d",
                               nmtst_get_rand_uint32() % 256,
                               nmtst_get_rand_uint32() % 256,
                               delimiter,
                               num);
    else
        return g_strdup_printf("a:b:c::%02x:%02x%c%d",
                               nmtst_get_rand_uint32() % 256,
                               nmtst_get_rand_uint32() % 256,
                               delimiter,
                               num);
}

/*****************************************************************************/

static void
compare_blob_data(const char *test, const char *key_path, GBytes *key)
{
    gs_free char *contents = NULL;
    gsize         len      = 0;
    GError       *error    = NULL;
    gboolean      success;

    g_assert(key && g_bytes_get_size(key) > 0);

    success = g_file_get_contents(key_path, &contents, &len, &error);
    nmtst_assert_success(success, error);

    g_assert_cmpmem(contents, len, g_bytes_get_data(key, NULL), g_bytes_get_size(key));
}

static void
check_scheme_path(GBytes *value, const char *path)
{
    const guint8 *p;
    gsize         l;

    g_assert(value);

    p = g_bytes_get_data(value, &l);
    g_assert_cmpint(l, ==, strlen(path) + NM_STRLEN(NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH) + 1);
    g_assert(memcmp(p,
                    NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH,
                    strlen(NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH))
             == 0);
    p += strlen(NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH);
    g_assert(memcmp(p, path, strlen(path)) == 0);
    p += strlen(path);
    g_assert(*p == '\0');
}

static void
test_private_key_import(const char *path, const char *password, NMSetting8021xCKScheme scheme)
{
    NMSetting8021x        *s_8021x;
    gboolean               success;
    NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
    NMSetting8021xCKFormat tmp_fmt;
    GError                *error   = NULL;
    GBytes                *tmp_key = NULL, *client_cert = NULL;
    const char            *pw;

    s_8021x = (NMSetting8021x *) nm_setting_802_1x_new();
    g_assert(s_8021x);

    success = nm_setting_802_1x_set_private_key(s_8021x, path, password, scheme, &format, &error);
    nmtst_assert_success(success, error);
    g_assert(format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
    tmp_fmt = nm_setting_802_1x_get_private_key_format(s_8021x);
    g_assert(tmp_fmt == format);

    /* Make sure the password is what we expect */
    pw = nm_setting_802_1x_get_private_key_password(s_8021x);
    g_assert(pw != NULL);
    g_assert_cmpstr(pw, ==, password);

    if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
        tmp_key = nm_setting_802_1x_get_private_key_blob(s_8021x);
        compare_blob_data("private-key-import", path, tmp_key);
    } else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
        g_object_get(s_8021x, NM_SETTING_802_1X_PRIVATE_KEY, &tmp_key, NULL);
        check_scheme_path(tmp_key, path);
        g_bytes_unref(tmp_key);
    } else
        g_assert_not_reached();

    /* If it's PKCS#12 ensure the client cert is the same value */
    if (format == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
        g_object_get(s_8021x, NM_SETTING_802_1X_PRIVATE_KEY, &tmp_key, NULL);
        g_assert(tmp_key);

        g_object_get(s_8021x, NM_SETTING_802_1X_CLIENT_CERT, &client_cert, NULL);
        g_assert(client_cert);

        /* make sure they are the same */
        g_assert(g_bytes_equal(tmp_key, client_cert));

        g_bytes_unref(tmp_key);
        g_bytes_unref(client_cert);
    }

    g_object_unref(s_8021x);
}

/*****************************************************************************/

static void
_do_test_connection_uuid(NMConnection *con, const char *uuid, const char *expected_uuid)
{
    NMSettingConnection *s_con;
    gs_free char        *uuid_old = NULL;
    gboolean             success;
    gboolean             is_normalized;
    char                 uuid_normalized[37];

    nmtst_assert_connection_verifies_without_normalization(con);

    s_con = NM_SETTING_CONNECTION(nm_connection_get_setting(con, NM_TYPE_SETTING_CONNECTION));
    g_assert(NM_IS_SETTING_CONNECTION(s_con));

    g_assert(uuid);

    uuid_old = g_strdup(nm_setting_connection_get_uuid(s_con));

    g_assert(nm_utils_is_uuid(uuid_old));

    g_object_set(s_con, NM_SETTING_CONNECTION_UUID, uuid, NULL);

    g_assert_cmpstr(uuid, ==, nm_setting_connection_get_uuid(s_con));

    if (nm_streq0(uuid, expected_uuid)) {
        nmtst_assert_connection_verifies_without_normalization(con);
        g_assert(nm_utils_is_uuid(uuid));
        g_assert(nm_uuid_is_valid(uuid));
        g_assert(nm_uuid_is_valid_nm(uuid, &is_normalized, NULL));
        g_assert(!is_normalized);
    } else if (!expected_uuid) {
        gs_free_error GError *error = NULL;

        success = nm_connection_verify(con, &error);
        nmtst_assert_no_success(success, error);
        g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);

        g_assert(!nm_utils_is_uuid(uuid));
        g_assert(!nm_uuid_is_valid(uuid));
        g_assert(!nm_uuid_is_valid_nmlegacy(uuid));
        g_assert(!nm_uuid_is_valid_nm(uuid, NULL, NULL));
    } else {
        gs_free_error GError *error = NULL;

        nmtst_assert_connection_verifies_and_normalizable(con);

        success = nm_connection_verify(con, &error);
        nmtst_assert_success(success, error);

        if (!nmtst_connection_normalize(con))
            g_assert_not_reached();

        g_assert_cmpstr(expected_uuid, ==, nm_setting_connection_get_uuid(s_con));
        g_assert(nm_uuid_is_valid(expected_uuid));

        g_assert(nm_utils_is_uuid(uuid));
        g_assert(nm_uuid_is_valid_nmlegacy(uuid));
        g_assert(nm_uuid_is_valid_nm(uuid, &is_normalized, uuid_normalized));

        g_assert_cmpstr(expected_uuid, ==, uuid_normalized);
    }

    g_object_set(s_con, NM_SETTING_CONNECTION_UUID, uuid_old, NULL);
    nmtst_assert_connection_verifies_without_normalization(con);

    if (expected_uuid && !nm_streq(expected_uuid, uuid))
        _do_test_connection_uuid(con, expected_uuid, expected_uuid);
}

static void
test_connection_uuid(void)
{
    gs_unref_object NMConnection *con = NULL;

    con = nmtst_create_minimal_connection("test-uuid", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);

    nmtst_connection_normalize(con);

#define _do_test_connection_uuid_bad(con, uuid) _do_test_connection_uuid((con), "" uuid "", NULL)

#define _do_test_connection_uuid_good(con, uuid) \
    _do_test_connection_uuid((con), "" uuid "", "" uuid "")

#define _do_test_connection_uuid_norm(con, uuid, expected_uuid) \
    _do_test_connection_uuid((con), "" uuid "", "" expected_uuid "")

    _do_test_connection_uuid_bad(con, "x1e775e3-a316-4eb2-b4d8-4b0f2bcaea53");
    _do_test_connection_uuid_bad(con, "1e775e3aa3164eb2b4d84b0f2bcaea53abcdabc");
    _do_test_connection_uuid_bad(con, "1e775e3aa3164eb2b4d84b0f2bcaea53abcdabcdd");

    _do_test_connection_uuid_good(con, "a1e775e3-a316-4eb2-b4d8-4b0f2bcaea53");

    _do_test_connection_uuid_norm(con,
                                  "A1E775e3-a316-4eb2-b4d8-4b0f2bcaea53",
                                  "a1e775e3-a316-4eb2-b4d8-4b0f2bcaea53");
    _do_test_connection_uuid_norm(con,
                                  "A1E775E3-A316-4EB2-B4D8-4B0F2BCAEA53",
                                  "a1e775e3-a316-4eb2-b4d8-4b0f2bcaea53");
    _do_test_connection_uuid_norm(con,
                                  "-1e775e3aa316-4eb2-b4d8-4b0f2bcaea53",
                                  "bdd73688-5c87-5454-917d-f5c3faed39c0");
    _do_test_connection_uuid_norm(con,
                                  "----1e775e3aa3164eb2b4d84b0f2bcaea53",
                                  "8a232814-c6cf-54c9-9384-71a60011d0b2");
    _do_test_connection_uuid_norm(con,
                                  "1e775e3aa3164eb2b4d84b0f2bcaea53abcdabcd",
                                  "ae35a4a8-4029-5770-9fa4-d79a672874c3");
    _do_test_connection_uuid_norm(con,
                                  "1e775e3Aa3164eb2b4d84b0f2bcaea53abcdabcd",
                                  "ae35a4a8-4029-5770-9fa4-d79a672874c3");
    _do_test_connection_uuid_norm(con,
                                  "1E775E3AA3164EB2B4D84B0F2BCAEA53ABCDABCD",
                                  "ae35a4a8-4029-5770-9fa4-d79a672874c3");
}

/*****************************************************************************/

static void
test_phase2_private_key_import(const char            *path,
                               const char            *password,
                               NMSetting8021xCKScheme scheme)
{
    NMSetting8021x        *s_8021x;
    gboolean               success;
    NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
    NMSetting8021xCKFormat tmp_fmt;
    GError                *error   = NULL;
    GBytes                *tmp_key = NULL, *client_cert = NULL;
    const char            *pw;

    s_8021x = (NMSetting8021x *) nm_setting_802_1x_new();
    g_assert(s_8021x);

    success =
        nm_setting_802_1x_set_phase2_private_key(s_8021x, path, password, scheme, &format, &error);
    nmtst_assert_success(success, error);
    g_assert(format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
    tmp_fmt = nm_setting_802_1x_get_phase2_private_key_format(s_8021x);
    g_assert(tmp_fmt == format);

    /* Make sure the password is what we expect */
    pw = nm_setting_802_1x_get_phase2_private_key_password(s_8021x);
    g_assert(pw);
    g_assert_cmpstr(pw, ==, password);

    if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
        tmp_key = nm_setting_802_1x_get_phase2_private_key_blob(s_8021x);
        compare_blob_data("phase2-private-key-import", path, tmp_key);
    } else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
        g_object_get(s_8021x, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, &tmp_key, NULL);
        check_scheme_path(tmp_key, path);
        g_bytes_unref(tmp_key);
    } else
        g_assert_not_reached();

    /* If it's PKCS#12 ensure the client cert is the same value */
    if (format == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
        g_object_get(s_8021x, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, &tmp_key, NULL);
        g_assert(tmp_key);

        g_object_get(s_8021x, NM_SETTING_802_1X_PHASE2_CLIENT_CERT, &client_cert, NULL);
        g_assert(client_cert);

        /* make sure they are the same */
        g_assert(g_bytes_equal(tmp_key, client_cert));

        g_bytes_unref(tmp_key);
        g_bytes_unref(client_cert);
    }

    g_object_unref(s_8021x);
}

static void
test_wrong_password_keeps_data(const char *path, const char *password)
{
    NMSetting8021x        *s_8021x;
    gboolean               success;
    NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
    GError                *error  = NULL;
    const char            *pw;

    s_8021x = (NMSetting8021x *) nm_setting_802_1x_new();
    g_assert(s_8021x);

    success = nm_setting_802_1x_set_private_key(s_8021x,
                                                path,
                                                password,
                                                NM_SETTING_802_1X_CK_SCHEME_BLOB,
                                                &format,
                                                &error);
    nmtst_assert_success(success, error);
    g_assert(format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);

    /* Now try to set it to something that's not a certificate */
    format  = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
    success = nm_setting_802_1x_set_private_key(s_8021x,
                                                "Makefile.am",
                                                password,
                                                NM_SETTING_802_1X_CK_SCHEME_BLOB,
                                                &format,
                                                &error);
    nmtst_assert_no_success(success, error);
    g_assert(format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
    g_clear_error(&error);

    /* Make sure the password hasn't changed */
    pw = nm_setting_802_1x_get_private_key_password(s_8021x);
    g_assert(pw);
    g_assert_cmpstr(pw, ==, password);

    g_object_unref(s_8021x);
}

static void
test_clear_private_key(const char *path, const char *password)
{
    NMSetting8021x        *s_8021x;
    gboolean               success;
    NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
    GError                *error  = NULL;
    const char            *pw;

    s_8021x = (NMSetting8021x *) nm_setting_802_1x_new();
    g_assert(s_8021x);

    success = nm_setting_802_1x_set_private_key(s_8021x,
                                                path,
                                                password,
                                                NM_SETTING_802_1X_CK_SCHEME_BLOB,
                                                &format,
                                                &error);
    nmtst_assert_success(success, error);
    g_assert(format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);

    /* Make sure the password is what we expect */
    pw = nm_setting_802_1x_get_private_key_password(s_8021x);
    g_assert(pw);
    g_assert_cmpstr(pw, ==, password);

    /* Now clear it */
    success = nm_setting_802_1x_set_private_key(s_8021x,
                                                NULL,
                                                NULL,
                                                NM_SETTING_802_1X_CK_SCHEME_BLOB,
                                                NULL,
                                                &error);
    nmtst_assert_success(success, error);

    /* Ensure the password is also now clear */
    g_assert(!nm_setting_802_1x_get_private_key_password(s_8021x));

    g_object_unref(s_8021x);
}

static void
test_wrong_phase2_password_keeps_data(const char *path, const char *password)
{
    NMSetting8021x        *s_8021x;
    gboolean               success;
    NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
    GError                *error  = NULL;
    const char            *pw;

    s_8021x = (NMSetting8021x *) nm_setting_802_1x_new();
    g_assert(s_8021x);

    success = nm_setting_802_1x_set_phase2_private_key(s_8021x,
                                                       path,
                                                       password,
                                                       NM_SETTING_802_1X_CK_SCHEME_BLOB,
                                                       &format,
                                                       &error);
    nmtst_assert_success(success, error);
    g_assert(format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);

    /* Now try to set it to something that's not a certificate */
    format  = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
    success = nm_setting_802_1x_set_phase2_private_key(s_8021x,
                                                       "Makefile.am",
                                                       password,
                                                       NM_SETTING_802_1X_CK_SCHEME_BLOB,
                                                       &format,
                                                       &error);
    nmtst_assert_no_success(success, error);
    g_assert(format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
    g_clear_error(&error);

    /* Make sure the password hasn't changed */
    pw = nm_setting_802_1x_get_phase2_private_key_password(s_8021x);
    g_assert(pw);
    g_assert_cmpstr(pw, ==, password);

    g_object_unref(s_8021x);
}

static void
test_clear_phase2_private_key(const char *path, const char *password)
{
    NMSetting8021x        *s_8021x;
    gboolean               success;
    NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
    GError                *error  = NULL;
    const char            *pw;

    s_8021x = (NMSetting8021x *) nm_setting_802_1x_new();
    g_assert(s_8021x);

    success = nm_setting_802_1x_set_phase2_private_key(s_8021x,
                                                       path,
                                                       password,
                                                       NM_SETTING_802_1X_CK_SCHEME_BLOB,
                                                       &format,
                                                       &error);
    nmtst_assert_success(success, error);
    g_assert(format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);

    /* Make sure the password is what we expect */
    pw = nm_setting_802_1x_get_phase2_private_key_password(s_8021x);
    g_assert(pw);
    g_assert_cmpstr(pw, ==, password);

    /* Now clear it */
    success = nm_setting_802_1x_set_phase2_private_key(s_8021x,
                                                       NULL,
                                                       NULL,
                                                       NM_SETTING_802_1X_CK_SCHEME_BLOB,
                                                       NULL,
                                                       &error);
    nmtst_assert_success(success, error);

    /* Ensure the password is also now clear */
    g_assert(!nm_setting_802_1x_get_phase2_private_key_password(s_8021x));

    g_object_unref(s_8021x);
}

static void
test_8021x(gconstpointer test_data)
{
    char **parts, *path, *password;

    parts = g_strsplit((const char *) test_data, ", ", -1);
    g_assert_cmpint(g_strv_length(parts), ==, 2);

    path     = g_build_filename(TEST_CERT_DIR, parts[0], NULL);
    password = parts[1];

    /* Test phase1 and phase2 path scheme */
    test_private_key_import(path, password, NM_SETTING_802_1X_CK_SCHEME_PATH);
    test_phase2_private_key_import(path, password, NM_SETTING_802_1X_CK_SCHEME_PATH);

    /* Test phase1 and phase2 blob scheme */
    test_private_key_import(path, password, NM_SETTING_802_1X_CK_SCHEME_BLOB);
    test_phase2_private_key_import(path, password, NM_SETTING_802_1X_CK_SCHEME_BLOB);

    /* Test that using a wrong password does not change existing data */
    test_wrong_password_keeps_data(path, password);
    test_wrong_phase2_password_keeps_data(path, password);

    /* Test clearing the private key */
    test_clear_private_key(path, password);
    test_clear_phase2_private_key(path, password);

    g_free(path);
    g_strfreev(parts);
}

/*****************************************************************************/

static void
create_bond_connection(NMConnection **con, NMSettingBond **s_bond)
{
    NMSettingConnection *s_con;

    g_assert(con);
    g_assert(s_bond);

    *con = nmtst_create_minimal_connection("bond", NULL, NM_SETTING_BOND_SETTING_NAME, &s_con);

    g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "bond0", NULL);

    *s_bond = (NMSettingBond *) nm_setting_bond_new();
    g_assert(*s_bond);

    nm_connection_add_setting(*con, NM_SETTING(*s_bond));
}

#define test_verify_options(exp, ...) _test_verify_options(exp, NM_MAKE_STRV(__VA_ARGS__))

static void
_test_verify_options(gboolean expected_result, const char *const *options)
{
    gs_unref_object NMConnection *con = NULL;
    NMSettingBond                *s_bond;
    const char *const            *option;

    g_assert(NM_PTRARRAY_LEN(options) % 2 == 0);

    create_bond_connection(&con, &s_bond);

    for (option = options; option[0]; option += 2)
        g_assert(nm_setting_bond_add_option(s_bond, option[0], option[1]));

    if (expected_result) {
        nmtst_assert_connection_verifies_and_normalizable(con);
    } else {
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_INVALID_PROPERTY);
    }
}

static void
test_bond_verify(void)
{
    test_verify_options(TRUE, "mode", "3", "arp_interval", "0");
    test_verify_options(FALSE,
                        /* arp_interval not supported in balance-alb mode */
                        "mode",
                        "balance-alb",
                        "arp_interval",
                        "1",
                        "arp_ip_target",
                        "1.2.3.4");
    test_verify_options(FALSE,
                        /* arp_ip_target requires arp_interval */
                        "mode",
                        "balance-rr",
                        "arp_ip_target",
                        "1.2.3.4");
    test_verify_options(TRUE,
                        "mode",
                        "balance-rr",
                        "arp_interval",
                        "1",
                        "arp_ip_target",
                        "1.2.3.4");
    test_verify_options(FALSE,
                        /* num_grat_arp, num_unsol_na cannot be different */
                        "mode",
                        "balance-rr",
                        "num_grat_arp",
                        "3",
                        "num_unsol_na",
                        "4");
    test_verify_options(TRUE, "mode", "balance-rr", "num_grat_arp", "5", "num_unsol_na", "5");
    test_verify_options(TRUE, "mode", "active-backup", "primary", "eth0");
    test_verify_options(FALSE,
                        /* primary requires mode=active-backup */
                        "mode",
                        "802.3ad",
                        "primary",
                        "eth0");
    test_verify_options(TRUE, "mode", "802.3ad", "lacp_rate", "fast");
    test_verify_options(FALSE,
                        /* lacp_rate=fast requires mode=802.3ad */
                        "mode",
                        "balance-rr",
                        "lacp_rate",
                        "fast");
    test_verify_options(TRUE, "mode", "802.3ad", "ad_actor_system", "ae:00:11:33:44:55");
    test_verify_options(TRUE, "mode", "0", "miimon", "0", "updelay", "0", "downdelay", "0");
    test_verify_options(TRUE, "mode", "0", "downdelay", "0", "updelay", "0");
    test_verify_options(TRUE,
                        "mode",
                        "0",
                        "miimon",
                        "100",
                        "arp_ip_target",
                        "1.1.1.1",
                        "arp_interval",
                        "200");
    test_verify_options(TRUE,
                        "mode",
                        "0",
                        "downdelay",
                        "100",
                        "arp_ip_target",
                        "1.1.1.1",
                        "arp_interval",
                        "200");
}

static void
test_bond_compare_options(gboolean exp_res, const char **opts1, const char **opts2)
{
    gs_unref_object NMSettingBond *s_bond1 = NULL, *s_bond2 = NULL;
    const char                   **p;

    s_bond1 = (NMSettingBond *) nm_setting_bond_new();
    g_assert(s_bond1);
    s_bond2 = (NMSettingBond *) nm_setting_bond_new();
    g_assert(s_bond2);

    for (p = opts1; p[0] && p[1]; p += 2)
        g_assert(nm_setting_bond_add_option(s_bond1, p[0], p[1]));

    for (p = opts2; p[0] && p[1]; p += 2)
        g_assert(nm_setting_bond_add_option(s_bond2, p[0], p[1]));

    g_assert_cmpint(nm_setting_compare((NMSetting *) s_bond1,
                                       (NMSetting *) s_bond2,
                                       NM_SETTING_COMPARE_FLAG_EXACT),
                    ==,
                    exp_res);
}

static void
test_bond_compare(void)
{
    test_bond_compare_options(TRUE,
                              ((const char *[]) {"mode", "balance-rr", "miimon", "1", NULL}),
                              ((const char *[]) {"mode", "balance-rr", "miimon", "1", NULL}));
    test_bond_compare_options(FALSE,
                              ((const char *[]) {"mode", "balance-rr", "miimon", "1", NULL}),
                              ((const char *[]) {"mode", "balance-rr", "miimon", "2", NULL}));

    test_bond_compare_options(FALSE,
                              ((const char *[]) {"miimon", "1", NULL}),
                              ((const char *[]) {"miimon", "1", "updelay", "0", NULL}));

    test_bond_compare_options(FALSE,
                              ((const char *[]) {"num_grat_arp", "2", NULL}),
                              ((const char *[]) {"num_grat_arp", "1", NULL}));
    test_bond_compare_options(FALSE,
                              ((const char *[]) {"num_grat_arp", "3", NULL}),
                              ((const char *[]) {"num_unsol_na", "3", NULL}));
    test_bond_compare_options(FALSE,
                              ((const char *[]) {"num_grat_arp", "4", NULL}),
                              ((const char *[]) {"num_unsol_na", "4", "num_grat_arp", "4", NULL}));

    test_bond_compare_options(FALSE,
                              ((const char *[]) {"mode", "balance-rr", "miimon", "100", NULL}),
                              ((const char *[]) {"mode", "balance-rr", NULL}));
}

static void
test_bond_normalize_options(const char **opts1, const char **opts2)
{
    gs_unref_object NMConnection *con = NULL;
    NMSettingBond                *s_bond;
    GError                       *error = NULL;
    gboolean                      success;
    const char                  **p;
    int                           num = 0;

    create_bond_connection(&con, &s_bond);

    for (p = opts1; p[0] && p[1]; p += 2)
        g_assert(nm_setting_bond_add_option(s_bond, p[0], p[1]));

    nmtst_assert_connection_verifies_and_normalizable(con);
    nmtst_connection_normalize(con);
    success = nm_setting_verify((NMSetting *) s_bond, con, &error);
    nmtst_assert_success(success, error);

    for (p = opts2; p[0] && p[1]; p += 2) {
        g_assert_cmpstr(nm_setting_bond_get_option_by_name(s_bond, p[0]), ==, p[1]);
        num++;
    }

    g_assert_cmpint(num, ==, nm_setting_bond_get_num_options(s_bond));
}

static void
test_bond_normalize(void)
{
    test_bond_normalize_options(
        ((const char *[]) {"mode", "802.3ad", "ad_actor_system", "00:02:03:04:05:06", NULL}),
        ((const char *[]) {"mode", "802.3ad", "ad_actor_system", "00:02:03:04:05:06", NULL}));
    test_bond_normalize_options(((const char *[]) {"mode", "1", "miimon", "1", NULL}),
                                ((const char *[]) {"mode", "active-backup", "miimon", "1", NULL}));
    test_bond_normalize_options(
        ((const char *[]) {"mode", "balance-alb", "tlb_dynamic_lb", "1", NULL}),
        ((const char *[]) {"mode", "balance-alb", "tlb_dynamic_lb", "1", NULL}));
    test_bond_normalize_options(
        ((const char *[]) {"mode", "balance-tlb", "tlb_dynamic_lb", "1", NULL}),
        ((const char *[]) {"mode", "balance-tlb", "tlb_dynamic_lb", "1", NULL}));
    test_bond_normalize_options(
        ((const char *[]) {"mode",
                           "balance-rr",
                           "ad_actor_sys_prio",
                           "4",
                           "packets_per_slave",
                           "3",
                           NULL}),
        ((const char *[]) {"mode", "balance-rr", "packets_per_slave", "3", NULL}));
}

/*****************************************************************************/

static void
test_dummy_normalize(void)
{
    gs_unref_object NMConnection *connection = NULL;
    NMSettingConnection          *s_con;

    connection = nm_simple_connection_new();
    s_con      = NM_SETTING_CONNECTION(nm_setting_connection_new());
    nm_connection_add_setting(connection, NM_SETTING(s_con));

    g_object_set(s_con,
                 NM_SETTING_CONNECTION_ID,
                 "dummy-test",
                 NM_SETTING_CONNECTION_UUID,
                 nm_uuid_generate_random_str_a(),
                 NM_SETTING_CONNECTION_TYPE,
                 NM_SETTING_DUMMY_SETTING_NAME,
                 NULL);

    nmtst_assert_connection_unnormalizable(connection, 0, 0);

    g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "dummy1", NULL);

    nmtst_connection_normalize(connection);
}

/*****************************************************************************/

#define DCB_FLAGS_ALL \
    (NM_SETTING_DCB_FLAG_ENABLE | NM_SETTING_DCB_FLAG_ADVERTISE | NM_SETTING_DCB_FLAG_WILLING)

static void
test_dcb_flags_valid(void)
{
    gs_unref_object NMSettingDcb *s_dcb = NULL;
    GError                       *error = NULL;
    gboolean                      success;
    guint                         i;

    s_dcb = (NMSettingDcb *) nm_setting_dcb_new();
    g_assert(s_dcb);

    g_assert_cmpint(nm_setting_dcb_get_app_fcoe_flags(s_dcb), ==, 0);
    g_assert_cmpint(nm_setting_dcb_get_app_iscsi_flags(s_dcb), ==, 0);
    g_assert_cmpint(nm_setting_dcb_get_app_fip_flags(s_dcb), ==, 0);
    g_assert_cmpint(nm_setting_dcb_get_priority_flow_control_flags(s_dcb), ==, 0);
    g_assert_cmpint(nm_setting_dcb_get_priority_group_flags(s_dcb), ==, 0);

    g_object_set(G_OBJECT(s_dcb),
                 NM_SETTING_DCB_APP_FCOE_FLAGS,
                 DCB_FLAGS_ALL,
                 NM_SETTING_DCB_APP_ISCSI_FLAGS,
                 DCB_FLAGS_ALL,
                 NM_SETTING_DCB_APP_FIP_FLAGS,
                 DCB_FLAGS_ALL,
                 NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS,
                 DCB_FLAGS_ALL,
                 NM_SETTING_DCB_PRIORITY_GROUP_FLAGS,
                 DCB_FLAGS_ALL,
                 NULL);
    /* Priority Group Bandwidth must total 100% */
    for (i = 0; i < 7; i++)
        nm_setting_dcb_set_priority_group_bandwidth(s_dcb, i, 12);
    nm_setting_dcb_set_priority_group_bandwidth(s_dcb, 7, 16);

    success = nm_setting_verify(NM_SETTING(s_dcb), NULL, &error);
    g_assert_no_error(error);
    g_assert(success);

    g_assert_cmpint(nm_setting_dcb_get_app_fcoe_flags(s_dcb), ==, DCB_FLAGS_ALL);
    g_assert_cmpint(nm_setting_dcb_get_app_iscsi_flags(s_dcb), ==, DCB_FLAGS_ALL);
    g_assert_cmpint(nm_setting_dcb_get_app_fip_flags(s_dcb), ==, DCB_FLAGS_ALL);
    g_assert_cmpint(nm_setting_dcb_get_priority_flow_control_flags(s_dcb), ==, DCB_FLAGS_ALL);
    g_assert_cmpint(nm_setting_dcb_get_priority_group_flags(s_dcb), ==, DCB_FLAGS_ALL);
}

#define TEST_FLAG(p, f, v)                                                           \
    {                                                                                \
        /* GObject property min/max should ensure the property does not get set to \
     * the invalid value, so we ensure the value we just tried to set is 0 and \
     * that verify is successful since the property never got set. \
     */ \
        g_object_set(G_OBJECT(s_dcb), p, v, NULL);                                   \
        g_assert_cmpint(f(s_dcb), ==, 0);                                            \
        success = nm_setting_verify(NM_SETTING(s_dcb), NULL, &error);                \
        g_assert_no_error(error);                                                    \
        g_assert(success);                                                           \
    }

static void
test_dcb_flags_invalid(void)
{
    gs_unref_object NMSettingDcb *s_dcb = NULL;
    GError                       *error = NULL;
    gboolean                      success;

    s_dcb = (NMSettingDcb *) nm_setting_dcb_new();
    g_assert(s_dcb);

    NMTST_EXPECT("GLib-GObject", NMTST_EXPECT_GOBJECT_ASSERT_LEVEL, "*invalid or out of range*");
    TEST_FLAG(NM_SETTING_DCB_APP_FCOE_FLAGS, nm_setting_dcb_get_app_fcoe_flags, 0x332523);
    g_test_assert_expected_messages();

    NMTST_EXPECT("GLib-GObject", NMTST_EXPECT_GOBJECT_ASSERT_LEVEL, "*invalid or out of range*");
    TEST_FLAG(NM_SETTING_DCB_APP_ISCSI_FLAGS, nm_setting_dcb_get_app_iscsi_flags, 0xFF);
    g_test_assert_expected_messages();

    NMTST_EXPECT("GLib-GObject", NMTST_EXPECT_GOBJECT_ASSERT_LEVEL, "*invalid or out of range*");
    TEST_FLAG(NM_SETTING_DCB_APP_FIP_FLAGS, nm_setting_dcb_get_app_fip_flags, 0x1111);
    g_test_assert_expected_messages();

    NMTST_EXPECT("GLib-GObject", NMTST_EXPECT_GOBJECT_ASSERT_LEVEL, "*invalid or out of range*");
    TEST_FLAG(NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS,
              nm_setting_dcb_get_priority_flow_control_flags,
              G_MAXUINT32);
    g_test_assert_expected_messages();

    NMTST_EXPECT("GLib-GObject", NMTST_EXPECT_GOBJECT_ASSERT_LEVEL, "*invalid or out of range*");
    TEST_FLAG(
        NM_SETTING_DCB_PRIORITY_GROUP_FLAGS,
        nm_setting_dcb_get_priority_group_flags,
        (NM_SETTING_DCB_FLAG_ENABLE | NM_SETTING_DCB_FLAG_ADVERTISE | NM_SETTING_DCB_FLAG_WILLING)
            + 1);
    g_test_assert_expected_messages();
}

#define TEST_APP_PRIORITY(lcprop, ucprop, v)                                                   \
    {                                                                                          \
        g_object_set(G_OBJECT(s_dcb),                                                          \
                     NM_SETTING_DCB_APP_##ucprop##_FLAGS,                                      \
                     NM_SETTING_DCB_FLAG_NONE,                                                 \
                     NULL);                                                                    \
                                                                                               \
        g_object_set(G_OBJECT(s_dcb), NM_SETTING_DCB_APP_##ucprop##_PRIORITY, v, NULL);        \
        g_assert_cmpint(nm_setting_dcb_get_app_##lcprop##_priority(s_dcb), ==, v);             \
                                                                                               \
        /* Assert that the setting is invalid while the app is disabled unless v is default */ \
        success = nm_setting_verify(NM_SETTING(s_dcb), NULL, &error);                          \
        if (v >= 0) {                                                                          \
            g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);  \
            g_assert(success == FALSE);                                                        \
        } else {                                                                               \
            g_assert_no_error(error);                                                          \
            g_assert(success);                                                                 \
        }                                                                                      \
        g_clear_error(&error);                                                                 \
                                                                                               \
        /* Set the enable flag and re-verify, this time it should be valid */                  \
        g_object_set(G_OBJECT(s_dcb),                                                          \
                     NM_SETTING_DCB_APP_##ucprop##_FLAGS,                                      \
                     NM_SETTING_DCB_FLAG_ENABLE,                                               \
                     NULL);                                                                    \
        success = nm_setting_verify(NM_SETTING(s_dcb), NULL, &error);                          \
        g_assert_no_error(error);                                                              \
        g_assert(success);                                                                     \
                                                                                               \
        g_object_set(G_OBJECT(s_dcb), NM_SETTING_DCB_APP_##ucprop##_PRIORITY, 0, NULL);        \
    }

static void
test_dcb_app_priorities(void)
{
    gs_unref_object NMSettingDcb *s_dcb = NULL;
    GError                       *error = NULL;
    gboolean                      success;

    s_dcb = (NMSettingDcb *) nm_setting_dcb_new();
    g_assert(s_dcb);

    /* Defaults */
    g_assert_cmpint(nm_setting_dcb_get_app_fcoe_priority(s_dcb), ==, -1);
    g_assert_cmpint(nm_setting_dcb_get_app_iscsi_priority(s_dcb), ==, -1);
    g_assert_cmpint(nm_setting_dcb_get_app_fip_priority(s_dcb), ==, -1);

    TEST_APP_PRIORITY(fcoe, FCOE, 6);
    TEST_APP_PRIORITY(iscsi, ISCSI, 5);
    TEST_APP_PRIORITY(fip, FIP, 4);

    TEST_APP_PRIORITY(fcoe, FCOE, -1);
    TEST_APP_PRIORITY(iscsi, ISCSI, -1);
    TEST_APP_PRIORITY(fip, FIP, -1);
}

#define TEST_PRIORITY_VALID(fn, id, val, flagsprop, verify)                                       \
    {                                                                                             \
        /* Assert that setting the value gets the same value back out */                          \
        nm_setting_dcb_set_priority_##fn(s_dcb, id, val);                                         \
        g_assert_cmpint(nm_setting_dcb_get_priority_##fn(s_dcb, id), ==, val);                    \
                                                                                                  \
        if (verify) {                                                                             \
            if (val != 0) {                                                                       \
                /* Assert that verify fails because the flags do not include 'enabled' \
             * and a value has been set. \
             */          \
                success = nm_setting_verify(NM_SETTING(s_dcb), NULL, &error);                     \
                g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY); \
                g_assert(success == FALSE);                                                       \
                g_clear_error(&error);                                                            \
            }                                                                                     \
                                                                                                  \
            /* Assert that adding the 'enabled' flag verifies the setting */                      \
            g_object_set(G_OBJECT(s_dcb),                                                         \
                         NM_SETTING_DCB_PRIORITY_##flagsprop##_FLAGS,                             \
                         NM_SETTING_DCB_FLAG_ENABLE,                                              \
                         NULL);                                                                   \
            success = nm_setting_verify(NM_SETTING(s_dcb), NULL, &error);                         \
            g_assert_no_error(error);                                                             \
            g_assert(success);                                                                    \
        }                                                                                         \
                                                                                                  \
        /* Reset everything */                                                                    \
        g_object_set(G_OBJECT(s_dcb),                                                             \
                     NM_SETTING_DCB_PRIORITY_##flagsprop##_FLAGS,                                 \
                     NM_SETTING_DCB_FLAG_NONE,                                                    \
                     NULL);                                                                       \
        nm_setting_dcb_set_priority_##fn(s_dcb, id, 0);                                           \
    }

/* If Priority Groups are enabled, PG bandwidth must equal 100% */
#define SET_VALID_PRIORITY_GROUP_BANDWIDTH                             \
    {                                                                  \
        guint x;                                                       \
        for (x = 0; x < 7; x++)                                        \
            nm_setting_dcb_set_priority_group_bandwidth(s_dcb, x, 12); \
        nm_setting_dcb_set_priority_group_bandwidth(s_dcb, 7, 16);     \
    }

static void
test_dcb_priorities_valid(void)
{
    gs_unref_object NMSettingDcb *s_dcb = NULL;
    GError                       *error = NULL;
    gboolean                      success;
    guint                         i;

    s_dcb = (NMSettingDcb *) nm_setting_dcb_new();
    g_assert(s_dcb);

    for (i = 0; i < 8; i++)
        TEST_PRIORITY_VALID(flow_control, i, TRUE, FLOW_CONTROL, TRUE);

    SET_VALID_PRIORITY_GROUP_BANDWIDTH
    for (i = 0; i < 8; i++) {
        TEST_PRIORITY_VALID(group_id, i, i, GROUP, TRUE);
        TEST_PRIORITY_VALID(group_id, i, 7 - i, GROUP, TRUE);
    }

    /* Clear PG bandwidth from earlier tests */
    for (i = 0; i < 8; i++)
        nm_setting_dcb_set_priority_group_bandwidth(s_dcb, i, 0);

    /* Priority Group Bandwidth must add up to 100% if enabled, which requires
     * some dancing for verifying individual values here.
     */
    for (i = 0; i < 8; i++) {
        guint other = 7 - (i % 8);

        /* Set another priority group to the remaining bandwidth */
        nm_setting_dcb_set_priority_group_bandwidth(s_dcb, other, 100 - i);
        TEST_PRIORITY_VALID(group_bandwidth, i, i, GROUP, TRUE);

        /* Set another priority group to the remaining bandwidth */
        nm_setting_dcb_set_priority_group_bandwidth(s_dcb, other, 100 - (7 - i));
        TEST_PRIORITY_VALID(group_bandwidth, i, 7 - i, GROUP, TRUE);

        /* Clear remaining bandwidth */
        nm_setting_dcb_set_priority_group_bandwidth(s_dcb, other, 0);
    }

    SET_VALID_PRIORITY_GROUP_BANDWIDTH
    for (i = 0; i < 8; i++) {
        TEST_PRIORITY_VALID(bandwidth, i, i, GROUP, TRUE);
        TEST_PRIORITY_VALID(bandwidth, i, 7 - i, GROUP, TRUE);
    }

    SET_VALID_PRIORITY_GROUP_BANDWIDTH
    for (i = 0; i < 8; i++)
        TEST_PRIORITY_VALID(strict_bandwidth, i, TRUE, GROUP, TRUE);

    SET_VALID_PRIORITY_GROUP_BANDWIDTH
    for (i = 0; i < 8; i++) {
        TEST_PRIORITY_VALID(traffic_class, i, i, GROUP, TRUE);
        TEST_PRIORITY_VALID(traffic_class, i, 7 - i, GROUP, TRUE);
    }
}

static void
test_dcb_bandwidth_sums(void)
{
    gs_unref_object NMSettingDcb *s_dcb = NULL;
    GError                       *error = NULL;
    gboolean                      success;

    s_dcb = (NMSettingDcb *) nm_setting_dcb_new();
    g_assert(s_dcb);

    /* Assert that setting the value gets the same value back out */
    nm_setting_dcb_set_priority_group_bandwidth(s_dcb, 0, 9);
    nm_setting_dcb_set_priority_group_bandwidth(s_dcb, 1, 10);
    nm_setting_dcb_set_priority_group_bandwidth(s_dcb, 2, 11);
    nm_setting_dcb_set_priority_group_bandwidth(s_dcb, 3, 12);
    nm_setting_dcb_set_priority_group_bandwidth(s_dcb, 4, 13);
    nm_setting_dcb_set_priority_group_bandwidth(s_dcb, 5, 14);
    nm_setting_dcb_set_priority_group_bandwidth(s_dcb, 6, 15);
    nm_setting_dcb_set_priority_group_bandwidth(s_dcb, 7, 16);

    /* Assert verify success when sums total 100% */
    g_object_set(G_OBJECT(s_dcb),
                 NM_SETTING_DCB_PRIORITY_GROUP_FLAGS,
                 NM_SETTING_DCB_FLAG_ENABLE,
                 NULL);
    success = nm_setting_verify(NM_SETTING(s_dcb), NULL, &error);
    g_assert_no_error(error);
    g_assert(success);

    /* Assert verify fails when sums do not total 100% */
    nm_setting_dcb_set_priority_group_bandwidth(s_dcb, 4, 20);
    success = nm_setting_verify(NM_SETTING(s_dcb), NULL, &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(success == FALSE);
    g_clear_error(&error);
}

/*****************************************************************************/

static void
test_nm_json(void)
{
    g_assert(NM_IN_SET(WITH_JANSSON, 0, 1));

#if WITH_JANSSON
    g_assert(nm_json_vt());
#else
    g_assert(!nm_json_vt());
#endif

#if WITH_JANSSON != defined(JANSSON_SONAME)
#error "WITH_JANSON and JANSSON_SONAME are defined inconsistently."
#endif
}

/*****************************************************************************/

static void
_test_team_config_sync(const char *team_config,
                       int         notify_peer_count,
                       int         notify_peers_interval,
                       int         mcast_rejoin_count,
                       int         mcast_rejoin_interval,
                       char       *runner,
                       char       *runner_hwaddr_policy,        /* activebackup */
                       GPtrArray  *runner_tx_hash,              /* lacp, loadbalance */
                       char       *runner_tx_balancer,          /* lacp, loadbalance */
                       int         runner_tx_balancer_interval, /* lacp, loadbalance */
                       gboolean    runner_active,               /* lacp */
                       gboolean    runner_fast_rate,            /* lacp */
                       int         runner_sys_prio,             /* lacp */
                       int         runner_min_ports,            /* lacp */
                       char       *runner_agg_select_policy,    /* lacp */
                       GPtrArray  *link_watchers)
{
    gs_unref_object NMSettingTeam *s_team = NULL;
    guint                          i, j;
    gboolean                       found;

    if (!nm_json_vt()) {
        g_test_skip("team test requires JSON validation");
        return;
    }

    s_team = (NMSettingTeam *) nm_setting_team_new();
    g_assert(s_team);

    g_object_set(s_team, NM_SETTING_TEAM_CONFIG, team_config, NULL);
    g_assert_cmpint(nm_setting_team_get_notify_peers_count(s_team), ==, notify_peer_count);
    g_assert_cmpint(nm_setting_team_get_notify_peers_interval(s_team), ==, notify_peers_interval);
    g_assert_cmpint(nm_setting_team_get_mcast_rejoin_count(s_team), ==, mcast_rejoin_count);
    g_assert_cmpint(nm_setting_team_get_mcast_rejoin_interval(s_team), ==, mcast_rejoin_interval);
    g_assert_cmpint(nm_setting_team_get_runner_tx_balancer_interval(s_team),
                    ==,
                    runner_tx_balancer_interval);
    g_assert_cmpint(nm_setting_team_get_runner_active(s_team), ==, runner_active);
    g_assert_cmpint(nm_setting_team_get_runner_fast_rate(s_team), ==, runner_fast_rate);
    g_assert_cmpint(nm_setting_team_get_runner_sys_prio(s_team), ==, runner_sys_prio);
    g_assert_cmpint(nm_setting_team_get_runner_min_ports(s_team), ==, runner_min_ports);
    g_assert_cmpstr(nm_setting_team_get_runner(s_team), ==, runner);
    g_assert_cmpstr(nm_setting_team_get_runner_hwaddr_policy(s_team), ==, runner_hwaddr_policy);
    g_assert_cmpstr(nm_setting_team_get_runner_tx_balancer(s_team), ==, runner_tx_balancer);
    g_assert_cmpstr(nm_setting_team_get_runner_agg_select_policy(s_team),
                    ==,
                    runner_agg_select_policy);

    if (runner_tx_hash) {
        g_assert_cmpint(runner_tx_hash->len, ==, nm_setting_team_get_num_runner_tx_hash(s_team));
        for (i = 0; i < runner_tx_hash->len; i++) {
            found = FALSE;
            for (j = 0; j < nm_setting_team_get_num_runner_tx_hash(s_team); j++) {
                if (nm_streq0(nm_setting_team_get_runner_tx_hash(s_team, j),
                              runner_tx_hash->pdata[i])) {
                    found = TRUE;
                    break;
                }
            }
            g_assert(found);
        }
    }

    if (link_watchers) {
        g_assert_cmpint(link_watchers->len, ==, nm_setting_team_get_num_link_watchers(s_team));
        for (i = 0; i < link_watchers->len; i++) {
            found = FALSE;
            for (j = 0; j < nm_setting_team_get_num_link_watchers(s_team); j++) {
                if (nm_team_link_watcher_equal(link_watchers->pdata[i],
                                               nm_setting_team_get_link_watcher(s_team, j))) {
                    found = TRUE;
                    break;
                }
            }
            g_assert(found);
        }
    }

    g_assert(nm_setting_verify((NMSetting *) s_team, NULL, NULL));
}

static void
test_runner_roundrobin_sync_from_config(void)
{
    _test_team_config_sync("",
                           -1,
                           -1,
                           -1,
                           -1,
                           NULL,
                           NULL,
                           NULL,
                           NULL,
                           -1,
                           TRUE,
                           FALSE,
                           -1,
                           -1,
                           NULL,
                           NULL);
}

static void
test_runner_broadcast_sync_from_config(void)
{
    _test_team_config_sync("{\"runner\": {\"name\": \"broadcast\"}}",
                           -1,
                           -1,
                           -1,
                           -1,
                           NM_SETTING_TEAM_RUNNER_BROADCAST,
                           NULL,
                           NULL,
                           NULL,
                           -1,
                           TRUE,
                           FALSE,
                           -1,
                           -1,
                           NULL,
                           NULL);
}

static void
test_runner_random_sync_from_config(void)
{
    _test_team_config_sync("{\"runner\": {\"name\": \"random\"}}",
                           -1,
                           -1,
                           -1,
                           -1,
                           NM_SETTING_TEAM_RUNNER_RANDOM,
                           NULL,
                           NULL,
                           NULL,
                           -1,
                           TRUE,
                           FALSE,
                           -1,
                           -1,
                           NULL,
                           NULL);
}

static void
test_runner_activebackup_sync_from_config(void)
{
    _test_team_config_sync("{\"runner\": {\"name\": \"activebackup\"}}",
                           -1,
                           -1,
                           -1,
                           -1,
                           NM_SETTING_TEAM_RUNNER_ACTIVEBACKUP,
                           NULL,
                           NULL,
                           NULL,
                           -1,
                           TRUE,
                           FALSE,
                           -1,
                           -1,
                           NULL,
                           NULL);
}

static void
test_runner_loadbalance_sync_from_config(void)
{
    gs_unref_ptrarray GPtrArray *tx_hash = NULL;

    tx_hash = g_ptr_array_new_with_free_func(g_free);
    g_ptr_array_add(tx_hash, g_strdup("eth"));
    g_ptr_array_add(tx_hash, g_strdup("ipv4"));
    g_ptr_array_add(tx_hash, g_strdup("ipv6"));

    _test_team_config_sync("{\"runner\": {\"name\": \"loadbalance\"}}",
                           -1,
                           -1,
                           -1,
                           -1,
                           NM_SETTING_TEAM_RUNNER_LOADBALANCE,
                           NULL,
                           NULL,
                           NULL,
                           -1,
                           TRUE,
                           FALSE,
                           -1,
                           -1,
                           NULL,
                           NULL);

    _test_team_config_sync("{\"runner\": {\"name\": \"loadbalance\", "
                           "\"tx_hash\": [\"eth\", \"ipv4\", \"ipv6\"]}}",
                           -1,
                           -1,
                           -1,
                           -1,
                           NM_SETTING_TEAM_RUNNER_LOADBALANCE,
                           NULL,
                           tx_hash,
                           NULL,
                           -1,
                           TRUE,
                           FALSE,
                           -1,
                           -1,
                           NULL,
                           NULL);

    _test_team_config_sync(
        "{\"runner\": {\"name\": \"loadbalance\", \"tx_hash\": [\"eth\", \"ipv4\", \"ipv6\"], "
        "\"tx_balancer\": {\"name\": \"basic\", \"balancing_interval\": 30}}}",
        -1,
        -1,
        -1,
        -1,
        NM_SETTING_TEAM_RUNNER_LOADBALANCE,
        NULL,
        tx_hash,
        "basic",
        30,
        TRUE,
        FALSE,
        -1,
        -1,
        NULL,
        NULL);
}

static void
test_runner_lacp_sync_from_config(void)
{
    gs_unref_ptrarray GPtrArray *tx_hash = NULL;

    tx_hash = g_ptr_array_new_with_free_func(g_free);
    g_ptr_array_add(tx_hash, g_strdup("eth"));
    g_ptr_array_add(tx_hash, g_strdup("ipv4"));
    g_ptr_array_add(tx_hash, g_strdup("ipv6"));

    _test_team_config_sync(
        "{\"runner\": {\"name\": \"lacp\", \"tx_hash\": [\"eth\", \"ipv4\", \"ipv6\"]}}",
        -1,
        -1,
        -1,
        -1,
        NM_SETTING_TEAM_RUNNER_LACP,
        NULL,
        tx_hash,
        NULL,
        -1,
        TRUE,
        FALSE,
        -1,
        -1,
        NULL,
        NULL);

    _test_team_config_sync(
        "{\"runner\": {\"name\": \"lacp\", \"tx_hash\": [\"eth\", \"ipv4\", \"ipv6\"], "
        "\"active\": false, \"fast_rate\": true, \"sys_prio\": 10, \"min_ports\": 5, "
        "\"agg_select_policy\": \"port_config\"}}",
        -1,
        -1,
        -1,
        -1,
        NM_SETTING_TEAM_RUNNER_LACP,
        NULL,
        tx_hash,
        NULL,
        -1,
        FALSE,
        TRUE,
        10,
        5,
        "port_config",
        NULL);
}

static void
test_watcher_ethtool_sync_from_config(void)
{
    gs_unref_ptrarray GPtrArray *link_watchers = NULL;

    link_watchers = g_ptr_array_new_with_free_func((GDestroyNotify) nm_team_link_watcher_unref);
    g_ptr_array_add(link_watchers, nm_team_link_watcher_new_ethtool(0, 0, NULL));
    _test_team_config_sync("{\"link_watch\": {\"name\": \"ethtool\"}}",
                           -1,
                           -1,
                           -1,
                           -1,
                           NULL,
                           NULL,
                           NULL,
                           NULL,
                           -1,
                           TRUE,
                           FALSE,
                           -1,
                           -1,
                           NULL,
                           link_watchers);
}

static void
test_watcher_nsna_ping_sync_from_config(void)
{
    gs_unref_ptrarray GPtrArray *link_watchers = NULL;

    link_watchers = g_ptr_array_new_with_free_func((GDestroyNotify) nm_team_link_watcher_unref);
    g_ptr_array_add(link_watchers,
                    nm_team_link_watcher_new_nsna_ping(0, 0, 3, "target.host", NULL));
    _test_team_config_sync(
        "{\"link_watch\": {\"name\": \"nsna_ping\", \"target_host\": \"target.host\"}}",
        -1,
        -1,
        -1,
        -1,
        NULL,
        NULL,
        NULL,
        NULL,
        -1,
        TRUE,
        FALSE,
        -1,
        -1,
        NULL,
        link_watchers);
}

static void
test_watcher_arp_ping_sync_from_config(void)
{
    gs_unref_ptrarray GPtrArray *link_watchers = NULL;

    link_watchers = g_ptr_array_new_with_free_func((GDestroyNotify) nm_team_link_watcher_unref);
    g_ptr_array_add(
        link_watchers,
        nm_team_link_watcher_new_arp_ping(0, 0, 3, "target.host", "source.host", 0, NULL));
    _test_team_config_sync(
        "{\"link_watch\": {\"name\": \"arp_ping\", \"target_host\": \"target.host\", "
        "\"source_host\": \"source.host\"}}",
        -1,
        -1,
        -1,
        -1,
        NULL,
        NULL,
        NULL,
        NULL,
        -1,
        TRUE,
        FALSE,
        -1,
        -1,
        NULL,
        link_watchers);
}

static void
test_multiple_watchers_sync_from_config(void)
{
    gs_unref_ptrarray GPtrArray *link_watchers = NULL;

    link_watchers = g_ptr_array_new_with_free_func((GDestroyNotify) nm_team_link_watcher_unref);
    g_ptr_array_add(link_watchers, nm_team_link_watcher_new_ethtool(2, 4, NULL));
    g_ptr_array_add(link_watchers,
                    nm_team_link_watcher_new_nsna_ping(3, 6, 9, "target.host", NULL));
    g_ptr_array_add(
        link_watchers,
        nm_team_link_watcher_new_arp_ping(5,
                                          10,
                                          15,
                                          "target.host",
                                          "source.host",
                                          NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE
                                              | NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE
                                              | NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS,
                                          NULL));
    _test_team_config_sync(
        "{\"link_watch\": ["
        "{\"name\": \"ethtool\", \"delay_up\": 2, \"delay_down\": 4}, "
        "{\"name\": \"arp_ping\", \"init_wait\": 5, \"interval\": 10, \"missed_max\": 15, "
        "\"target_host\": \"target.host\", \"source_host\": \"source.host\", "
        "\"validate_active\": true, \"validate_inactive\": true, \"send_always\": true}, "
        "{\"name\": \"nsna_ping\", \"init_wait\": 3, \"interval\": 6, \"missed_max\": 9, "
        "\"target_host\": \"target.host\"}]}",
        -1,
        -1,
        -1,
        -1,
        NULL,
        NULL,
        NULL,
        NULL,
        -1,
        TRUE,
        FALSE,
        -1,
        -1,
        NULL,
        link_watchers);
}

/*****************************************************************************/

static void
_test_team_port_config_sync(const char *team_port_config,
                            int         queue_id,
                            int         prio,
                            gboolean    sticky,
                            int         lacp_prio,
                            int         lacp_key,
                            GPtrArray  *link_watchers)
{
    gs_unref_object NMSettingTeamPort *s_team_port = NULL;
    guint                              i, j;
    gboolean                           found;

    if (!nm_json_vt()) {
        g_test_skip("team test requires JSON validation");
        return;
    }

    s_team_port = (NMSettingTeamPort *) nm_setting_team_port_new();
    g_assert(s_team_port);

    g_object_set(s_team_port, NM_SETTING_TEAM_CONFIG, team_port_config, NULL);
    g_assert(nm_setting_team_port_get_queue_id(s_team_port) == queue_id);
    g_assert(nm_setting_team_port_get_prio(s_team_port) == prio);
    g_assert(nm_setting_team_port_get_sticky(s_team_port) == sticky);
    g_assert(nm_setting_team_port_get_lacp_prio(s_team_port) == lacp_prio);
    g_assert(nm_setting_team_port_get_lacp_key(s_team_port) == lacp_key);

    if (link_watchers) {
        g_assert(link_watchers->len == nm_setting_team_port_get_num_link_watchers(s_team_port));
        for (i = 0; i < link_watchers->len; i++) {
            found = FALSE;
            for (j = 0; j < nm_setting_team_port_get_num_link_watchers(s_team_port); j++) {
                if (nm_team_link_watcher_equal(
                        link_watchers->pdata[i],
                        nm_setting_team_port_get_link_watcher(s_team_port, j))) {
                    found = TRUE;
                    break;
                }
            }
            g_assert(found);
        }
    }

    g_assert(nm_setting_verify((NMSetting *) s_team_port, NULL, NULL));
}

static void
test_team_port_default(void)
{
    _test_team_port_config_sync("", -1, 0, FALSE, -1, -1, NULL);
}

static void
test_team_port_queue_id(void)
{
    _test_team_port_config_sync("{\"queue_id\": 3}", 3, 0, FALSE, -1, -1, NULL);
    _test_team_port_config_sync("{\"queue_id\": 0}", 0, 0, FALSE, -1, -1, NULL);
}

static void
test_team_port_prio(void)
{
    _test_team_port_config_sync("{\"prio\": 6}", -1, 6, FALSE, -1, -1, NULL);
    _test_team_port_config_sync("{\"prio\": 0}", -1, 0, FALSE, -1, -1, NULL);
}

static void
test_team_port_sticky(void)
{
    _test_team_port_config_sync("{\"sticky\": true}", -1, 0, TRUE, -1, -1, NULL);
    _test_team_port_config_sync("{\"sticky\": false}", -1, 0, FALSE, -1, -1, NULL);
}

static void
test_team_port_lacp_prio(void)
{
    _test_team_port_config_sync("{\"lacp_prio\": 9}", -1, 0, FALSE, 9, -1, NULL);
    _test_team_port_config_sync("{\"lacp_prio\": 0}", -1, 0, FALSE, 0, -1, NULL);
}

static void
test_team_port_lacp_key(void)
{
    _test_team_port_config_sync("{\"lacp_key\": 12}", -1, 0, FALSE, -1, 12, NULL);
    _test_team_port_config_sync("{\"lacp_key\": 0}", -1, 0, FALSE, -1, 0, NULL);
}

static void
test_team_port_full_config(void)
{
    gs_unref_ptrarray GPtrArray *link_watchers = NULL;

    link_watchers = g_ptr_array_new_with_free_func((GDestroyNotify) nm_team_link_watcher_unref);
    g_ptr_array_add(
        link_watchers,
        nm_team_link_watcher_new_arp_ping(0,
                                          3,
                                          3,
                                          "1.2.3.2",
                                          "1.2.3.1",
                                          NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE,
                                          NULL));
    g_ptr_array_add(
        link_watchers,
        nm_team_link_watcher_new_arp_ping(1,
                                          1,
                                          0,
                                          "1.2.3.4",
                                          "1.2.3.1",
                                          NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS,
                                          NULL));

    _test_team_port_config_sync(
        "{\"queue_id\": 10, \"prio\": 20, \"sticky\": true, \"lacp_prio\": 30, "
        "\"lacp_key\": 40, \"link_watch\": ["
        "{\"name\": \"arp_ping\", \"interval\": 3, \"target_host\": \"1.2.3.2\", "
        "\"source_host\": \"1.2.3.1\", \"validate_inactive\": true}, "
        "{\"name\": \"arp_ping\", \"init_wait\": 1, \"interval\": 1, "
        "\"target_host\": \"1.2.3.4\", \"source_host\": \"1.2.3.1\", "
        "\"send_always\": true}]}",
        10,
        20,
        true,
        30,
        40,
        NULL);
}

/*****************************************************************************/

static void
_check_team_setting(NMSetting *setting)
{
    gs_unref_object NMSetting *setting2      = NULL;
    gs_unref_object NMSetting *setting_clone = NULL;
    gboolean                   is_port       = NM_IS_SETTING_TEAM_PORT(setting);
    gs_unref_variant GVariant *variant2      = NULL;
    gs_unref_variant GVariant *variant3      = NULL;

    g_assert(NM_IS_SETTING_TEAM(setting) || is_port);

    setting2 = g_object_new(G_OBJECT_TYPE(setting),
                            is_port ? NM_SETTING_TEAM_PORT_CONFIG : NM_SETTING_TEAM_CONFIG,
                            is_port ? nm_setting_team_port_get_config(NM_SETTING_TEAM_PORT(setting))
                                    : nm_setting_team_get_config(NM_SETTING_TEAM(setting)),
                            NULL);

    if (nm_json_vt())
        nmtst_assert_setting_is_equal(setting, setting2, NM_SETTING_COMPARE_FLAG_EXACT);

    g_clear_object(&setting2);

    nmtst_assert_setting_dbus_roundtrip(setting);

    /* OK, now parse the setting only from the D-Bus variant, but removing the JSON config.
     * For that, we have to "drop" the JSON and we do that by resetting the property.
     * This causes JSON to be regenerated and it's in a normalized form that will compare
     * equal. */
    setting_clone = nm_setting_duplicate(setting);
    setting       = setting_clone;
    if (is_port) {
        g_object_set(setting,
                     NM_SETTING_TEAM_PORT_STICKY,
                     nm_setting_team_port_get_sticky(NM_SETTING_TEAM_PORT(setting)),
                     NULL);
    } else {
        g_object_set(setting,
                     NM_SETTING_TEAM_RUNNER_SYS_PRIO,
                     nm_setting_team_get_runner_sys_prio(NM_SETTING_TEAM(setting)),
                     NULL);
    }
    variant2 = _nm_setting_to_dbus(setting, NULL, NM_CONNECTION_SERIALIZE_ALL, NULL);
    variant3 = nm_utils_gvariant_vardict_filter_drop_one(variant2, "config");
    setting2 = nmtst_assert_setting_dbus_new(G_OBJECT_TYPE(setting), variant3);
    nmtst_assert_setting_is_equal(setting, setting2, NM_SETTING_COMPARE_FLAG_EXACT);
}

static void
test_team_setting(void)
{
    gs_unref_variant GVariant *variant = nmtst_variant_from_string(
        G_VARIANT_TYPE_VARDICT,
        "{'config': <'{\"link_watch\": {\"name\": \"ethtool\"}}'>, 'interface-name': <'nm-team'>, "
        "'link-watchers': <[{'name': <'ethtool'>}]>}");
    gs_free_error GError                              *error   = NULL;
    gs_unref_object NMSetting                         *setting = NULL;
    nm_auto_unref_team_link_watcher NMTeamLinkWatcher *watcher1 =
        nm_team_link_watcher_new_nsna_ping(1, 3, 4, "bbb", NULL);
    nm_auto_unref_team_link_watcher NMTeamLinkWatcher *watcher2 =
        nm_team_link_watcher_new_arp_ping2(1, 3, 4, -1, "ccc", "ddd", 0, NULL);

    g_assert(watcher1);
    g_assert(watcher2);

    setting = _nm_setting_new_from_dbus(NM_TYPE_SETTING_TEAM,
                                        variant,
                                        NULL,
                                        NM_SETTING_PARSE_FLAGS_STRICT,
                                        &error);
    nmtst_assert_success(setting, error);
    _check_team_setting(setting);

    g_assert_cmpstr(nm_setting_team_get_config(NM_SETTING_TEAM(setting)),
                    ==,
                    "{\"link_watch\": {\"name\": \"ethtool\"}}");
    g_assert_cmpint(nm_setting_team_get_num_link_watchers(NM_SETTING_TEAM(setting)), ==, 1);

    g_object_set(setting, NM_SETTING_TEAM_RUNNER_SYS_PRIO, (int) 10, NULL);

    _check_team_setting(setting);
    g_assert_cmpint(nm_setting_team_get_num_link_watchers(NM_SETTING_TEAM(setting)), ==, 1);
    g_assert_cmpstr(
        nm_setting_team_get_config(NM_SETTING_TEAM(setting)),
        ==,
        "{ \"runner\": { \"sys_prio\": 10 }, \"link_watch\": { \"name\": \"ethtool\" } }");

    nm_setting_team_remove_link_watcher(NM_SETTING_TEAM(setting), 0);

    _check_team_setting(setting);
    g_assert_cmpint(nm_setting_team_get_num_link_watchers(NM_SETTING_TEAM(setting)), ==, 0);
    g_assert_cmpstr(nm_setting_team_get_config(NM_SETTING_TEAM(setting)),
                    ==,
                    "{ \"runner\": { \"sys_prio\": 10 } }");

    nm_setting_team_add_link_watcher(NM_SETTING_TEAM(setting), watcher1);
    _check_team_setting(setting);
    g_assert_cmpstr(
        nm_setting_team_get_config(NM_SETTING_TEAM(setting)),
        ==,
        "{ \"runner\": { \"sys_prio\": 10 }, \"link_watch\": { \"name\": \"nsna_ping\", "
        "\"interval\": 3, \"init_wait\": 1, \"missed_max\": 4, \"target_host\": \"bbb\" } }");

    nm_setting_team_add_link_watcher(NM_SETTING_TEAM(setting), watcher2);
    _check_team_setting(setting);
    g_assert_cmpstr(
        nm_setting_team_get_config(NM_SETTING_TEAM(setting)),
        ==,
        "{ \"runner\": { \"sys_prio\": 10 }, \"link_watch\": [ { \"name\": \"nsna_ping\", "
        "\"interval\": 3, \"init_wait\": 1, \"missed_max\": 4, \"target_host\": \"bbb\" }, { "
        "\"name\": \"arp_ping\", \"interval\": 3, \"init_wait\": 1, \"missed_max\": 4, "
        "\"source_host\": \"ddd\", \"target_host\": \"ccc\" } ] }");

    nm_setting_team_remove_link_watcher(NM_SETTING_TEAM(setting), 0);
    nm_setting_team_remove_link_watcher(NM_SETTING_TEAM(setting), 0);
    g_object_set(setting, NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL, (int) 5, NULL);
    g_assert_cmpstr(
        nm_setting_team_get_config(NM_SETTING_TEAM(setting)),
        ==,
        "{ \"runner\": { \"tx_balancer\": { \"balancing_interval\": 5 }, \"sys_prio\": 10 } }");

    g_object_set(setting, NM_SETTING_TEAM_RUNNER, NULL, NULL);
    _check_team_setting(setting);
    g_assert_cmpstr(
        nm_setting_team_get_config(NM_SETTING_TEAM(setting)),
        ==,
        "{ \"runner\": { \"tx_balancer\": { \"balancing_interval\": 5 }, \"sys_prio\": 10 } }");

    g_object_set(setting,
                 NM_SETTING_TEAM_CONFIG,
                 "{ \"runner\": { \"tx_hash\": [ \"eth\", \"l3\" ] } }",
                 NULL);
    _check_team_setting(setting);
}

/*****************************************************************************/

static void
_setting_ethtool_set_feature(NMSettingEthtool *s_ethtool, const char *opt_name, NMTernary value)
{
    g_assert(NM_IS_SETTING_ETHTOOL(s_ethtool));

    if (nmtst_get_rand_bool()) {
        nm_setting_ethtool_set_feature(s_ethtool, opt_name, value);
        return;
    }

    if (value == NM_TERNARY_DEFAULT) {
        nm_setting_option_set(NM_SETTING(s_ethtool), opt_name, NULL);
        return;
    }

    if (nmtst_get_rand_bool())
        nm_setting_option_set_boolean(NM_SETTING(s_ethtool), opt_name, value);
    else
        nm_setting_option_set(NM_SETTING(s_ethtool), opt_name, g_variant_new_boolean(value));
}

static NMTernary
_setting_ethtool_get_feature(NMSettingEthtool *s_ethtool, const char *opt_name)
{
    GVariant *v;
    gboolean  b;

    switch (nmtst_get_rand_uint32() % 3) {
    case 0:
        return nm_setting_ethtool_get_feature(s_ethtool, opt_name);
    case 1:
        if (!nm_setting_option_get_boolean(NM_SETTING(s_ethtool), opt_name, &b))
            return NM_TERNARY_DEFAULT;
        return b;
    default:
        v = nm_setting_option_get(NM_SETTING(s_ethtool), opt_name);
        if (!v || !g_variant_is_of_type(v, G_VARIANT_TYPE_BOOLEAN))
            return NM_TERNARY_DEFAULT;
        return g_variant_get_boolean(v);
    }
}

static void
test_ethtool_features(void)
{
    gs_unref_object NMConnection   *con     = NULL;
    gs_unref_object NMConnection   *con2    = NULL;
    gs_unref_object NMConnection   *con3    = NULL;
    gs_unref_variant GVariant      *variant = NULL;
    gs_free_error GError           *error   = NULL;
    nm_auto_unref_keyfile GKeyFile *keyfile = NULL;
    NMSettingConnection            *s_con;
    NMSettingEthtool               *s_ethtool;
    NMSettingEthtool               *s_ethtool2;
    NMSettingEthtool               *s_ethtool3;

    con = nmtst_create_minimal_connection("ethtool-1", NULL, NM_SETTING_WIRED_SETTING_NAME, &s_con);
    s_ethtool = NM_SETTING_ETHTOOL(nm_setting_ethtool_new());
    nm_connection_add_setting(con, NM_SETTING(s_ethtool));

    _setting_ethtool_set_feature(s_ethtool, NM_ETHTOOL_OPTNAME_FEATURE_RX, NM_TERNARY_TRUE);
    _setting_ethtool_set_feature(s_ethtool, NM_ETHTOOL_OPTNAME_FEATURE_LRO, NM_TERNARY_FALSE);

    g_assert_cmpint(_setting_ethtool_get_feature(s_ethtool, NM_ETHTOOL_OPTNAME_FEATURE_RX),
                    ==,
                    NM_TERNARY_TRUE);
    g_assert_cmpint(_setting_ethtool_get_feature(s_ethtool, NM_ETHTOOL_OPTNAME_FEATURE_LRO),
                    ==,
                    NM_TERNARY_FALSE);
    g_assert_cmpint(_setting_ethtool_get_feature(s_ethtool, NM_ETHTOOL_OPTNAME_FEATURE_SG),
                    ==,
                    NM_TERNARY_DEFAULT);

    nmtst_connection_normalize(con);

    variant = nm_connection_to_dbus(con, NM_CONNECTION_SERIALIZE_ALL);

    con2 = nm_simple_connection_new_from_dbus(variant, &error);
    nmtst_assert_success(con2, error);

    s_ethtool2 = NM_SETTING_ETHTOOL(nm_connection_get_setting(con2, NM_TYPE_SETTING_ETHTOOL));

    g_assert_cmpint(_setting_ethtool_get_feature(s_ethtool2, NM_ETHTOOL_OPTNAME_FEATURE_RX),
                    ==,
                    NM_TERNARY_TRUE);
    g_assert_cmpint(_setting_ethtool_get_feature(s_ethtool2, NM_ETHTOOL_OPTNAME_FEATURE_LRO),
                    ==,
                    NM_TERNARY_FALSE);
    g_assert_cmpint(_setting_ethtool_get_feature(s_ethtool2, NM_ETHTOOL_OPTNAME_FEATURE_SG),
                    ==,
                    NM_TERNARY_DEFAULT);

    nmtst_assert_connection_verifies_without_normalization(con2);

    nmtst_assert_connection_equals(con, FALSE, con2, FALSE);

    keyfile = nm_keyfile_write(con, NM_KEYFILE_HANDLER_FLAGS_NONE, NULL, NULL, &error);
    nmtst_assert_success(keyfile, error);

    con3 = nm_keyfile_read(keyfile,
                           "/ignored/current/working/directory/for/loading/relative/paths",
                           NM_KEYFILE_HANDLER_FLAGS_NONE,
                           NULL,
                           NULL,
                           &error);
    nmtst_assert_success(con3, error);

    nm_keyfile_read_ensure_id(con3, "unused-because-already-has-id");
    nm_keyfile_read_ensure_uuid(con3, "unused-because-already-has-uuid");

    nmtst_connection_normalize(con3);

    nmtst_assert_connection_equals(con, FALSE, con3, FALSE);

    s_ethtool3 = NM_SETTING_ETHTOOL(nm_connection_get_setting(con3, NM_TYPE_SETTING_ETHTOOL));

    g_assert_cmpint(_setting_ethtool_get_feature(s_ethtool3, NM_ETHTOOL_OPTNAME_FEATURE_RX),
                    ==,
                    NM_TERNARY_TRUE);
    g_assert_cmpint(_setting_ethtool_get_feature(s_ethtool3, NM_ETHTOOL_OPTNAME_FEATURE_LRO),
                    ==,
                    NM_TERNARY_FALSE);
    g_assert_cmpint(_setting_ethtool_get_feature(s_ethtool3, NM_ETHTOOL_OPTNAME_FEATURE_SG),
                    ==,
                    NM_TERNARY_DEFAULT);
}

static void
test_ethtool_coalesce(void)
{
    gs_unref_object NMConnection   *con     = NULL;
    gs_unref_object NMConnection   *con2    = NULL;
    gs_unref_object NMConnection   *con3    = NULL;
    gs_unref_variant GVariant      *variant = NULL;
    gs_free_error GError           *error   = NULL;
    nm_auto_unref_keyfile GKeyFile *keyfile = NULL;
    NMSettingConnection            *s_con;
    NMSettingEthtool               *s_ethtool;
    NMSettingEthtool               *s_ethtool2;
    NMSettingEthtool               *s_ethtool3;
    guint32                         u32;

    con       = nmtst_create_minimal_connection("ethtool-coalesce",
                                          NULL,
                                          NM_SETTING_WIRED_SETTING_NAME,
                                          &s_con);
    s_ethtool = NM_SETTING_ETHTOOL(nm_setting_ethtool_new());
    nm_connection_add_setting(con, NM_SETTING(s_ethtool));

    nm_setting_option_set_uint32(NM_SETTING(s_ethtool), NM_ETHTOOL_OPTNAME_COALESCE_RX_FRAMES, 4);

    g_assert_true(nm_setting_option_get_uint32(NM_SETTING(s_ethtool),
                                               NM_ETHTOOL_OPTNAME_COALESCE_RX_FRAMES,
                                               &u32));
    g_assert_cmpuint(u32, ==, 4);

    nmtst_connection_normalize(con);

    variant = nm_connection_to_dbus(con, NM_CONNECTION_SERIALIZE_ALL);

    con2 = nm_simple_connection_new_from_dbus(variant, &error);
    nmtst_assert_success(con2, error);

    s_ethtool2 = NM_SETTING_ETHTOOL(nm_connection_get_setting(con2, NM_TYPE_SETTING_ETHTOOL));

    g_assert_true(nm_setting_option_get_uint32(NM_SETTING(s_ethtool2),
                                               NM_ETHTOOL_OPTNAME_COALESCE_RX_FRAMES,
                                               &u32));
    g_assert_cmpuint(u32, ==, 4);

    nmtst_assert_connection_verifies_without_normalization(con2);

    nmtst_assert_connection_equals(con, FALSE, con2, FALSE);

    keyfile = nm_keyfile_write(con, NM_KEYFILE_HANDLER_FLAGS_NONE, NULL, NULL, &error);
    nmtst_assert_success(keyfile, error);

    con3 = nm_keyfile_read(keyfile,
                           "/ignored/current/working/directory/for/loading/relative/paths",
                           NM_KEYFILE_HANDLER_FLAGS_NONE,
                           NULL,
                           NULL,
                           &error);
    nmtst_assert_success(con3, error);

    nm_keyfile_read_ensure_id(con3, "unused-because-already-has-id");
    nm_keyfile_read_ensure_uuid(con3, "unused-because-already-has-uuid");

    nmtst_connection_normalize(con3);

    nmtst_assert_connection_equals(con, FALSE, con3, FALSE);

    s_ethtool3 = NM_SETTING_ETHTOOL(nm_connection_get_setting(con3, NM_TYPE_SETTING_ETHTOOL));

    g_assert_true(nm_setting_option_get_uint32(NM_SETTING(s_ethtool3),
                                               NM_ETHTOOL_OPTNAME_COALESCE_RX_FRAMES,
                                               &u32));
    g_assert_cmpuint(u32, ==, 4);

    nm_setting_option_set(NM_SETTING(s_ethtool), NM_ETHTOOL_OPTNAME_COALESCE_RX_FRAMES, NULL);
    g_assert_false(nm_setting_option_get_uint32(NM_SETTING(s_ethtool),
                                                NM_ETHTOOL_OPTNAME_COALESCE_RX_FRAMES,
                                                NULL));

    nm_setting_option_set_uint32(NM_SETTING(s_ethtool), NM_ETHTOOL_OPTNAME_COALESCE_TX_FRAMES, 8);

    g_assert_true(nm_setting_option_get_uint32(NM_SETTING(s_ethtool),
                                               NM_ETHTOOL_OPTNAME_COALESCE_TX_FRAMES,
                                               &u32));
    g_assert_cmpuint(u32, ==, 8);

    nm_setting_option_clear_by_name(NM_SETTING(s_ethtool), nm_ethtool_optname_is_coalesce);
    g_assert_false(nm_setting_option_get_uint32(NM_SETTING(s_ethtool),
                                                NM_ETHTOOL_OPTNAME_COALESCE_RX_FRAMES,
                                                NULL));
    g_assert_false(nm_setting_option_get_uint32(NM_SETTING(s_ethtool),
                                                NM_ETHTOOL_OPTNAME_COALESCE_TX_FRAMES,
                                                NULL));
    g_assert_false(nm_setting_option_get_uint32(NM_SETTING(s_ethtool),
                                                NM_ETHTOOL_OPTNAME_COALESCE_TX_USECS,
                                                NULL));
}

static void
test_ethtool_ring(void)
{
    gs_unref_object NMConnection   *con     = NULL;
    gs_unref_object NMConnection   *con2    = NULL;
    gs_unref_object NMConnection   *con3    = NULL;
    gs_unref_variant GVariant      *variant = NULL;
    gs_free_error GError           *error   = NULL;
    nm_auto_unref_keyfile GKeyFile *keyfile = NULL;
    NMSettingConnection            *s_con;
    NMSettingEthtool               *s_ethtool;
    NMSettingEthtool               *s_ethtool2;
    NMSettingEthtool               *s_ethtool3;
    guint32                         out_value;

    con       = nmtst_create_minimal_connection("ethtool-ring",
                                          NULL,
                                          NM_SETTING_WIRED_SETTING_NAME,
                                          &s_con);
    s_ethtool = NM_SETTING_ETHTOOL(nm_setting_ethtool_new());
    nm_connection_add_setting(con, NM_SETTING(s_ethtool));

    nm_setting_option_set_uint32(NM_SETTING(s_ethtool), NM_ETHTOOL_OPTNAME_RING_RX_JUMBO, 4);

    g_assert_true(nm_setting_option_get_uint32(NM_SETTING(s_ethtool),
                                               NM_ETHTOOL_OPTNAME_RING_RX_JUMBO,
                                               &out_value));
    g_assert_cmpuint(out_value, ==, 4);

    nmtst_connection_normalize(con);

    variant = nm_connection_to_dbus(con, NM_CONNECTION_SERIALIZE_ALL);

    con2 = nm_simple_connection_new_from_dbus(variant, &error);
    nmtst_assert_success(con2, error);

    s_ethtool2 = NM_SETTING_ETHTOOL(nm_connection_get_setting(con2, NM_TYPE_SETTING_ETHTOOL));

    g_assert_true(nm_setting_option_get_uint32(NM_SETTING(s_ethtool2),
                                               NM_ETHTOOL_OPTNAME_RING_RX_JUMBO,
                                               &out_value));
    g_assert_cmpuint(out_value, ==, 4);

    nmtst_assert_connection_verifies_without_normalization(con2);

    nmtst_assert_connection_equals(con, FALSE, con2, FALSE);

    keyfile = nm_keyfile_write(con, NM_KEYFILE_HANDLER_FLAGS_NONE, NULL, NULL, &error);
    nmtst_assert_success(keyfile, error);

    con3 = nm_keyfile_read(keyfile,
                           "/ignored/current/working/directory/for/loading/relative/paths",
                           NM_KEYFILE_HANDLER_FLAGS_NONE,
                           NULL,
                           NULL,
                           &error);
    nmtst_assert_success(con3, error);

    nm_keyfile_read_ensure_id(con3, "unused-because-already-has-id");
    nm_keyfile_read_ensure_uuid(con3, "unused-because-already-has-uuid");

    nmtst_connection_normalize(con3);

    nmtst_assert_connection_equals(con, FALSE, con3, FALSE);

    s_ethtool3 = NM_SETTING_ETHTOOL(nm_connection_get_setting(con3, NM_TYPE_SETTING_ETHTOOL));

    g_assert_true(nm_setting_option_get_uint32(NM_SETTING(s_ethtool3),
                                               NM_ETHTOOL_OPTNAME_RING_RX_JUMBO,
                                               &out_value));
    g_assert_cmpuint(out_value, ==, 4);

    nm_setting_option_set(NM_SETTING(s_ethtool), NM_ETHTOOL_OPTNAME_RING_RX_JUMBO, NULL);
    g_assert_false(nm_setting_option_get_uint32(NM_SETTING(s_ethtool),
                                                NM_ETHTOOL_OPTNAME_RING_RX_JUMBO,
                                                NULL));

    nm_setting_option_set_uint32(NM_SETTING(s_ethtool), NM_ETHTOOL_OPTNAME_RING_RX_JUMBO, 8);

    g_assert_true(nm_setting_option_get_uint32(NM_SETTING(s_ethtool),
                                               NM_ETHTOOL_OPTNAME_RING_RX_JUMBO,
                                               &out_value));
    g_assert_cmpuint(out_value, ==, 8);

    nm_setting_option_clear_by_name(NM_SETTING(s_ethtool), nm_ethtool_optname_is_ring);
    g_assert_false(nm_setting_option_get_uint32(NM_SETTING(s_ethtool),
                                                NM_ETHTOOL_OPTNAME_RING_RX_JUMBO,
                                                NULL));
    g_assert_false(
        nm_setting_option_get_uint32(NM_SETTING(s_ethtool), NM_ETHTOOL_OPTNAME_RING_RX, NULL));
    g_assert_false(
        nm_setting_option_get_uint32(NM_SETTING(s_ethtool), NM_ETHTOOL_OPTNAME_RING_TX, NULL));
}

static void
test_ethtool_pause(void)
{
    gs_unref_object NMConnection   *con     = NULL;
    gs_unref_object NMConnection   *con2    = NULL;
    gs_unref_object NMConnection   *con3    = NULL;
    gs_unref_variant GVariant      *variant = NULL;
    gs_free_error GError           *error   = NULL;
    nm_auto_unref_keyfile GKeyFile *keyfile = NULL;
    NMSettingConnection            *s_con;
    NMSettingEthtool               *s_ethtool;
    NMSettingEthtool               *s_ethtool2;
    NMSettingEthtool               *s_ethtool3;
    gboolean                        out_value;

    con       = nmtst_create_minimal_connection("ethtool-pause",
                                          NULL,
                                          NM_SETTING_WIRED_SETTING_NAME,
                                          &s_con);
    s_ethtool = NM_SETTING_ETHTOOL(nm_setting_ethtool_new());
    nm_connection_add_setting(con, NM_SETTING(s_ethtool));

    nm_setting_option_set_boolean(NM_SETTING(s_ethtool), NM_ETHTOOL_OPTNAME_PAUSE_AUTONEG, FALSE);
    nm_setting_option_set_boolean(NM_SETTING(s_ethtool), NM_ETHTOOL_OPTNAME_PAUSE_RX, TRUE);
    nm_setting_option_set_boolean(NM_SETTING(s_ethtool), NM_ETHTOOL_OPTNAME_PAUSE_TX, TRUE);

    g_assert_true(nm_setting_option_get_boolean(NM_SETTING(s_ethtool),
                                                NM_ETHTOOL_OPTNAME_PAUSE_AUTONEG,
                                                &out_value));
    g_assert_true(!out_value);
    g_assert_true(nm_setting_option_get_boolean(NM_SETTING(s_ethtool),
                                                NM_ETHTOOL_OPTNAME_PAUSE_RX,
                                                &out_value));
    g_assert_true(out_value);
    g_assert_true(nm_setting_option_get_boolean(NM_SETTING(s_ethtool),
                                                NM_ETHTOOL_OPTNAME_PAUSE_TX,
                                                &out_value));
    g_assert_true(out_value);

    nmtst_connection_normalize(con);

    variant = nm_connection_to_dbus(con, NM_CONNECTION_SERIALIZE_ALL);

    con2 = nm_simple_connection_new_from_dbus(variant, &error);
    nmtst_assert_success(con2, error);

    s_ethtool2 = NM_SETTING_ETHTOOL(nm_connection_get_setting(con2, NM_TYPE_SETTING_ETHTOOL));

    g_assert_true(nm_setting_option_get_boolean(NM_SETTING(s_ethtool2),
                                                NM_ETHTOOL_OPTNAME_PAUSE_AUTONEG,
                                                &out_value));
    g_assert_true(!out_value);

    nmtst_assert_connection_verifies_without_normalization(con2);

    nmtst_assert_connection_equals(con, FALSE, con2, FALSE);

    con2 = nm_simple_connection_new_from_dbus(variant, &error);
    nmtst_assert_success(con2, error);

    keyfile = nm_keyfile_write(con, NM_KEYFILE_HANDLER_FLAGS_NONE, NULL, NULL, &error);
    nmtst_assert_success(keyfile, error);

    con3 = nm_keyfile_read(keyfile,
                           "/ignored/current/working/directory/for/loading/relative/paths",
                           NM_KEYFILE_HANDLER_FLAGS_NONE,
                           NULL,
                           NULL,
                           &error);
    nmtst_assert_success(con3, error);

    nm_keyfile_read_ensure_id(con3, "unused-because-already-has-id");
    nm_keyfile_read_ensure_uuid(con3, "unused-because-already-has-uuid");

    nmtst_connection_normalize(con3);

    nmtst_assert_connection_equals(con, FALSE, con3, FALSE);

    s_ethtool3 = NM_SETTING_ETHTOOL(nm_connection_get_setting(con3, NM_TYPE_SETTING_ETHTOOL));

    g_assert_true(nm_setting_option_get_boolean(NM_SETTING(s_ethtool3),
                                                NM_ETHTOOL_OPTNAME_PAUSE_AUTONEG,
                                                &out_value));
    g_assert_true(!out_value);
    g_assert_true(nm_setting_option_get_boolean(NM_SETTING(s_ethtool3),
                                                NM_ETHTOOL_OPTNAME_PAUSE_RX,
                                                &out_value));
    g_assert_true(out_value);
    g_assert_true(nm_setting_option_get_boolean(NM_SETTING(s_ethtool3),
                                                NM_ETHTOOL_OPTNAME_PAUSE_TX,
                                                &out_value));
    g_assert_true(out_value);
}

static void
test_ethtool_eee(void)
{
    gs_unref_object NMConnection   *con     = NULL;
    gs_unref_object NMConnection   *con2    = NULL;
    gs_unref_object NMConnection   *con3    = NULL;
    gs_unref_variant GVariant      *variant = NULL;
    gs_free_error GError           *error   = NULL;
    nm_auto_unref_keyfile GKeyFile *keyfile = NULL;
    NMSettingConnection            *s_con;
    NMSettingEthtool               *s_ethtool;
    NMSettingEthtool               *s_ethtool2;
    NMSettingEthtool               *s_ethtool3;
    gboolean                        out_value;

    con =
        nmtst_create_minimal_connection("ethtool-eee", NULL, NM_SETTING_WIRED_SETTING_NAME, &s_con);
    s_ethtool = NM_SETTING_ETHTOOL(nm_setting_ethtool_new());
    nm_connection_add_setting(con, NM_SETTING(s_ethtool));

    nm_setting_option_set_boolean(NM_SETTING(s_ethtool), NM_ETHTOOL_OPTNAME_EEE_ENABLED, FALSE);

    g_assert_true(nm_setting_option_get_boolean(NM_SETTING(s_ethtool),
                                                NM_ETHTOOL_OPTNAME_EEE_ENABLED,
                                                &out_value));
    g_assert_true(!out_value);

    nmtst_connection_normalize(con);

    variant = nm_connection_to_dbus(con, NM_CONNECTION_SERIALIZE_ALL);

    con2 = nm_simple_connection_new_from_dbus(variant, &error);
    nmtst_assert_success(con2, error);

    s_ethtool2 = NM_SETTING_ETHTOOL(nm_connection_get_setting(con2, NM_TYPE_SETTING_ETHTOOL));

    g_assert_true(nm_setting_option_get_boolean(NM_SETTING(s_ethtool2),
                                                NM_ETHTOOL_OPTNAME_EEE_ENABLED,
                                                &out_value));
    g_assert_true(!out_value);

    nmtst_assert_connection_verifies_without_normalization(con2);

    nmtst_assert_connection_equals(con, FALSE, con2, FALSE);

    con2 = nm_simple_connection_new_from_dbus(variant, &error);
    nmtst_assert_success(con2, error);

    keyfile = nm_keyfile_write(con, NM_KEYFILE_HANDLER_FLAGS_NONE, NULL, NULL, &error);
    nmtst_assert_success(keyfile, error);

    con3 = nm_keyfile_read(keyfile,
                           "/ignored/current/working/directory/for/loading/relative/paths",
                           NM_KEYFILE_HANDLER_FLAGS_NONE,
                           NULL,
                           NULL,
                           &error);
    nmtst_assert_success(con3, error);

    nm_keyfile_read_ensure_id(con3, "unused-because-already-has-id");
    nm_keyfile_read_ensure_uuid(con3, "unused-because-already-has-uuid");

    nmtst_connection_normalize(con3);

    nmtst_assert_connection_equals(con, FALSE, con3, FALSE);

    s_ethtool3 = NM_SETTING_ETHTOOL(nm_connection_get_setting(con3, NM_TYPE_SETTING_ETHTOOL));

    g_assert_true(nm_setting_option_get_boolean(NM_SETTING(s_ethtool3),
                                                NM_ETHTOOL_OPTNAME_EEE_ENABLED,
                                                &out_value));
    g_assert_true(!out_value);
}
/*****************************************************************************/

static void
test_ethtool_fec(void)
{
    gs_unref_object NMConnection   *con     = NULL;
    gs_unref_object NMConnection   *con2    = NULL;
    gs_unref_object NMConnection   *con3    = NULL;
    gs_unref_variant GVariant      *variant = NULL;
    gs_free_error GError           *error   = NULL;
    nm_auto_unref_keyfile GKeyFile *keyfile = NULL;
    NMSettingConnection            *s_con;
    NMSettingEthtool               *s_ethtool;
    NMSettingEthtool               *s_ethtool2;
    NMSettingEthtool               *s_ethtool3;
    guint32                         out_value;
    guint32                         expected_fec_mode =
        NM_SETTING_ETHTOOL_FEC_MODE_AUTO | NM_SETTING_ETHTOOL_FEC_MODE_BASER;

    con =
        nmtst_create_minimal_connection("ethtool-fec", NULL, NM_SETTING_WIRED_SETTING_NAME, &s_con);
    s_ethtool = NM_SETTING_ETHTOOL(nm_setting_ethtool_new());
    nm_connection_add_setting(con, NM_SETTING(s_ethtool));

    nm_setting_option_set_uint32(NM_SETTING(s_ethtool),
                                 NM_ETHTOOL_OPTNAME_FEC_MODE,
                                 expected_fec_mode);

    g_assert_true(nm_setting_option_get_uint32(NM_SETTING(s_ethtool),
                                               NM_ETHTOOL_OPTNAME_FEC_MODE,
                                               &out_value));
    g_assert_true(out_value == expected_fec_mode);

    nmtst_connection_normalize(con);

    variant = nm_connection_to_dbus(con, NM_CONNECTION_SERIALIZE_ALL);

    con2 = nm_simple_connection_new_from_dbus(variant, &error);
    nmtst_assert_success(con2, error);

    s_ethtool2 = NM_SETTING_ETHTOOL(nm_connection_get_setting(con2, NM_TYPE_SETTING_ETHTOOL));

    g_assert_true(nm_setting_option_get_uint32(NM_SETTING(s_ethtool2),
                                               NM_ETHTOOL_OPTNAME_FEC_MODE,
                                               &out_value));
    g_assert_true(out_value == expected_fec_mode);

    nmtst_assert_connection_verifies_without_normalization(con2);

    nmtst_assert_connection_equals(con, FALSE, con2, FALSE);

    con2 = nm_simple_connection_new_from_dbus(variant, &error);
    nmtst_assert_success(con2, error);

    keyfile = nm_keyfile_write(con, NM_KEYFILE_HANDLER_FLAGS_NONE, NULL, NULL, &error);
    nmtst_assert_success(keyfile, error);

    con3 = nm_keyfile_read(keyfile,
                           "/ignored/current/working/directory/for/loading/relative/paths",
                           NM_KEYFILE_HANDLER_FLAGS_NONE,
                           NULL,
                           NULL,
                           &error);
    nmtst_assert_success(con3, error);

    nm_keyfile_read_ensure_id(con3, "unused-because-already-has-id");
    nm_keyfile_read_ensure_uuid(con3, "unused-because-already-has-uuid");

    nmtst_connection_normalize(con3);

    nmtst_assert_connection_equals(con, FALSE, con3, FALSE);

    s_ethtool3 = NM_SETTING_ETHTOOL(nm_connection_get_setting(con3, NM_TYPE_SETTING_ETHTOOL));

    g_assert_true(nm_setting_option_get_uint32(NM_SETTING(s_ethtool3),
                                               NM_ETHTOOL_OPTNAME_FEC_MODE,
                                               &out_value));
    g_assert_true(out_value == expected_fec_mode);
}
/*****************************************************************************/

static void
test_sriov_vf(void)
{
    NMSriovVF *vf1, *vf2;
    GError    *error = NULL;
    char      *str;

    vf1 = nm_sriov_vf_new(1);
    nm_sriov_vf_set_attribute(vf1,
                              NM_SRIOV_VF_ATTRIBUTE_MAC,
                              g_variant_new_string("00:11:22:33:44:55"));
    nm_sriov_vf_set_attribute(vf1, NM_SRIOV_VF_ATTRIBUTE_SPOOF_CHECK, g_variant_new_boolean(TRUE));
    nm_sriov_vf_set_attribute(vf1, NM_SRIOV_VF_ATTRIBUTE_TRUST, g_variant_new_boolean(FALSE));
    nm_sriov_vf_set_attribute(vf1, NM_SRIOV_VF_ATTRIBUTE_MIN_TX_RATE, g_variant_new_uint32(100));
    nm_sriov_vf_set_attribute(vf1, NM_SRIOV_VF_ATTRIBUTE_MAX_TX_RATE, g_variant_new_uint32(500));

    str = nm_utils_sriov_vf_to_str(vf1, FALSE, &error);
    g_assert_no_error(error);
    g_assert_cmpstr(
        str,
        ==,
        "1 mac=00:11:22:33:44:55 max-tx-rate=500 min-tx-rate=100 spoof-check=true trust=false");
    g_free(str);

    vf2 = nm_utils_sriov_vf_from_str(" 1  mac=00:11:22:33:44:55  max-tx-rate=500 min-tx-rate=100",
                                     &error);
    nmtst_assert_success(vf2, error);
    nm_sriov_vf_set_attribute(vf2, NM_SRIOV_VF_ATTRIBUTE_SPOOF_CHECK, g_variant_new_boolean(FALSE));
    nm_sriov_vf_set_attribute(vf2, NM_SRIOV_VF_ATTRIBUTE_SPOOF_CHECK, g_variant_new_boolean(TRUE));
    nm_sriov_vf_set_attribute(vf2, NM_SRIOV_VF_ATTRIBUTE_TRUST, g_variant_new_boolean(TRUE));
    nm_sriov_vf_set_attribute(vf2, NM_SRIOV_VF_ATTRIBUTE_TRUST, NULL);
    nm_sriov_vf_set_attribute(vf2, NM_SRIOV_VF_ATTRIBUTE_TRUST, g_variant_new_boolean(FALSE));

    g_assert(nm_sriov_vf_equal(vf1, vf2));

    nm_sriov_vf_unref(vf1);
    nm_sriov_vf_unref(vf2);
}

static void
test_sriov_vf_dup(void)
{
    NMSriovVF *vf1, *vf2;

    vf1 = nm_sriov_vf_new(1);
    nm_sriov_vf_set_attribute(vf1, NM_SRIOV_VF_ATTRIBUTE_MAC, g_variant_new_string("foobar"));
    nm_sriov_vf_set_attribute(vf1, NM_SRIOV_VF_ATTRIBUTE_TRUST, g_variant_new_boolean(FALSE));
    nm_sriov_vf_set_attribute(vf1, NM_SRIOV_VF_ATTRIBUTE_MIN_TX_RATE, g_variant_new_uint32(10));
    nm_sriov_vf_set_attribute(vf1, NM_SRIOV_VF_ATTRIBUTE_MAX_TX_RATE, g_variant_new_uint32(1000));
    nm_sriov_vf_add_vlan(vf1, 80);
    nm_sriov_vf_set_vlan_qos(vf1, 80, NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD);

    vf2 = nm_sriov_vf_dup(vf1);
    g_assert(nm_sriov_vf_equal(vf1, vf2));

    nm_sriov_vf_unref(vf1);
    nm_sriov_vf_unref(vf2);
}

static void
test_sriov_vf_vlan(void)
{
    NMSriovVF    *vf;
    const guint  *vlan_ids;
    guint         num;
    GError       *error = NULL;
    gs_free char *str   = NULL;

    vf = nm_sriov_vf_new(19);
    nm_sriov_vf_set_attribute(vf, NM_SRIOV_VF_ATTRIBUTE_MAC, g_variant_new_string("00:11:22"));
    g_assert(nm_sriov_vf_add_vlan(vf, 80));
    g_assert(!nm_sriov_vf_add_vlan(vf, 80));
    g_assert(nm_sriov_vf_add_vlan(vf, 82));
    g_assert(nm_sriov_vf_add_vlan(vf, 83));
    g_assert(nm_sriov_vf_add_vlan(vf, 81));
    g_assert(!nm_sriov_vf_remove_vlan(vf, 100));
    g_assert(nm_sriov_vf_remove_vlan(vf, 82));
    nm_sriov_vf_set_vlan_qos(vf, 81, 0xabba);
    nm_sriov_vf_set_vlan_protocol(vf, 81, NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD);

    vlan_ids = nm_sriov_vf_get_vlan_ids(vf, &num);
    g_assert(vlan_ids);
    g_assert_cmpint(num, ==, 3);
    g_assert_cmpint(vlan_ids[0], ==, 80);
    g_assert_cmpint(vlan_ids[1], ==, 81);
    g_assert_cmpint(vlan_ids[2], ==, 83);
    g_assert_cmpint(nm_sriov_vf_get_vlan_qos(vf, 80), ==, 0x0);
    g_assert_cmpint(nm_sriov_vf_get_vlan_protocol(vf, 80), ==, NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);
    g_assert_cmpint(nm_sriov_vf_get_vlan_qos(vf, 81), ==, 0xabba);
    g_assert_cmpint(nm_sriov_vf_get_vlan_protocol(vf, 81), ==, NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD);

    nm_sriov_vf_unref(vf);

    vf = nm_utils_sriov_vf_from_str("20 spoof-check=false vlans=85.0.q;4000.0x20.ad;81.10;83",
                                    &error);
    nmtst_assert_success(vf, error);
    vlan_ids = nm_sriov_vf_get_vlan_ids(vf, &num);
    g_assert(vlan_ids);
    g_assert_cmpint(num, ==, 4);
    g_assert_cmpint(vlan_ids[0], ==, 81);
    g_assert_cmpint(nm_sriov_vf_get_vlan_qos(vf, 81), ==, 10);
    g_assert_cmpint(nm_sriov_vf_get_vlan_protocol(vf, 81), ==, NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);
    g_assert_cmpint(vlan_ids[1], ==, 83);
    g_assert_cmpint(nm_sriov_vf_get_vlan_qos(vf, 83), ==, 0);
    g_assert_cmpint(nm_sriov_vf_get_vlan_protocol(vf, 83), ==, NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);
    g_assert_cmpint(vlan_ids[2], ==, 85);
    g_assert_cmpint(nm_sriov_vf_get_vlan_qos(vf, 85), ==, 0);
    g_assert_cmpint(nm_sriov_vf_get_vlan_protocol(vf, 85), ==, NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);
    g_assert_cmpint(vlan_ids[3], ==, 4000);
    g_assert_cmpint(nm_sriov_vf_get_vlan_qos(vf, 4000), ==, 0x20);
    g_assert_cmpint(nm_sriov_vf_get_vlan_protocol(vf, 4000), ==, NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD);

    str = nm_utils_sriov_vf_to_str(vf, FALSE, &error);
    nmtst_assert_success(str, error);
    g_assert_cmpstr(str, ==, "20 spoof-check=false vlans=81.10;83;85;4000.32.ad");

    nm_sriov_vf_unref(vf);
}

static void
test_sriov_setting(void)
{
    gs_unref_object NMConnection *con = NULL;
    NMSettingConnection          *s_con;
    NMSettingSriov               *s_sriov = NULL;
    NMSriovVF                    *vf1, *vf2, *vf3;
    GError                       *error = NULL;
    gboolean                      success;

    con = nm_simple_connection_new();

    s_con = (NMSettingConnection *) nm_setting_connection_new();
    nm_connection_add_setting(con, NM_SETTING(s_con));

    g_object_set(s_con,
                 NM_SETTING_CONNECTION_ID,
                 "Test SR-IOV connection",
                 NM_SETTING_CONNECTION_UUID,
                 nm_uuid_generate_random_str_a(),
                 NM_SETTING_CONNECTION_AUTOCONNECT,
                 TRUE,
                 NM_SETTING_CONNECTION_INTERFACE_NAME,
                 "eth0",
                 NM_SETTING_CONNECTION_TYPE,
                 NM_SETTING_WIRED_SETTING_NAME,
                 NULL);

    nm_connection_add_setting(con, nm_setting_wired_new());

    s_sriov = (NMSettingSriov *) nm_setting_sriov_new();
    nm_connection_add_setting(con, NM_SETTING(s_sriov));

    g_object_set(s_sriov, NM_SETTING_SRIOV_TOTAL_VFS, 16, NULL);
    nm_setting_sriov_add_vf(s_sriov, (vf1 = nm_sriov_vf_new(0)));
    nm_setting_sriov_add_vf(s_sriov, (vf2 = nm_sriov_vf_new(4)));
    nm_setting_sriov_add_vf(s_sriov, (vf3 = nm_sriov_vf_new(10)));
    g_assert(nm_setting_sriov_remove_vf_by_index(s_sriov, 4));
    nm_sriov_vf_unref(vf2);
    nm_setting_sriov_add_vf(s_sriov, (vf2 = nm_sriov_vf_new(2)));

    nmtst_assert_connection_verifies_and_normalizable(con);
    nmtst_connection_normalize(con);
    success = nm_setting_verify((NMSetting *) s_sriov, con, &error);
    nmtst_assert_success(success, error);

    g_assert_cmpint(nm_setting_sriov_get_num_vfs(s_sriov), ==, 3);
    g_assert_cmpint(nm_sriov_vf_get_index(nm_setting_sriov_get_vf(s_sriov, 0)), ==, 0);
    g_assert_cmpint(nm_sriov_vf_get_index(nm_setting_sriov_get_vf(s_sriov, 1)), ==, 2);
    g_assert_cmpint(nm_sriov_vf_get_index(nm_setting_sriov_get_vf(s_sriov, 2)), ==, 10);

    nm_sriov_vf_unref(vf1);
    nm_sriov_vf_unref(vf2);
    nm_sriov_vf_unref(vf3);
}

typedef struct {
    guint id;
    guint qos;
    bool  proto_ad;
} VlanData;

static void
_test_sriov_parse_vlan_one(const char *string, gboolean exp_res, VlanData *data, guint data_length)
{
    NMSriovVF   *vf;
    gboolean     res;
    guint        i, num_vlans;
    const guint *vlan_ids;

    vf = nm_sriov_vf_new(1);
    g_assert(vf);

    res = _nm_sriov_vf_parse_vlans(vf, string, NULL);
    g_assert_cmpint(res, ==, exp_res);

    if (exp_res) {
        vlan_ids = nm_sriov_vf_get_vlan_ids(vf, &num_vlans);
        g_assert_cmpint(num_vlans, ==, data_length);
        for (i = 0; i < num_vlans; i++) {
            g_assert_cmpint(vlan_ids[i], ==, data[i].id);
            g_assert_cmpint(nm_sriov_vf_get_vlan_qos(vf, vlan_ids[i]), ==, data[i].qos);
            g_assert_cmpint(nm_sriov_vf_get_vlan_protocol(vf, vlan_ids[i]),
                            ==,
                            data[i].proto_ad ? NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD
                                             : NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);
        }
    }

    nm_sriov_vf_unref(vf);
}

#define test_sriov_parse_vlan_one(string, result, ...)              \
    {                                                               \
        VlanData _data[] = {__VA_ARGS__};                           \
        guint    _length = G_N_ELEMENTS(_data);                     \
                                                                    \
        _test_sriov_parse_vlan_one(string, result, _data, _length); \
    }

static void
test_sriov_parse_vlans(void)
{
    test_sriov_parse_vlan_one("", FALSE, {});
    test_sriov_parse_vlan_one("1", TRUE, {1, 0, 0});
    test_sriov_parse_vlan_one("1;2", TRUE, {1, 0, 0}, {2, 0, 0});
    test_sriov_parse_vlan_one("4095;;2", TRUE, {2, 0, 0}, {4095, 0, 0});
    test_sriov_parse_vlan_one("1 2", FALSE, {});
    test_sriov_parse_vlan_one("4096", FALSE, {});
    test_sriov_parse_vlan_one("1.10", TRUE, {1, 10, 0});
    test_sriov_parse_vlan_one("1.20.ad", TRUE, {1, 20, 1});
    test_sriov_parse_vlan_one("1.21.q", TRUE, {1, 21, 0});
    test_sriov_parse_vlan_one("9.20.foo", FALSE, {});
    test_sriov_parse_vlan_one("1.20.ad.12", FALSE, {});
    test_sriov_parse_vlan_one("1;1.10", FALSE, {});
    test_sriov_parse_vlan_one("1..1;2", FALSE, {});
    test_sriov_parse_vlan_one("1..ad;2", FALSE, {});
    test_sriov_parse_vlan_one("1.2.ad;2.0.q;5;3", TRUE, {1, 2, 1}, {2, 0, 0}, {3, 0, 0}, {5, 0, 0});
}

static void
test_bridge_vlans(void)
{
    NMBridgeVlan *v1, *v2;
    GError       *error = NULL;
    guint16       vid_start, vid_end;
    char         *str;

    v1 = nm_bridge_vlan_from_str("1 foobar", &error);
    nmtst_assert_no_success(v1, error);
    g_clear_error(&error);

    v1 = nm_bridge_vlan_from_str("4095", &error);
    nmtst_assert_no_success(v1, error);
    g_clear_error(&error);

    /* test ranges */
    v1 = nm_bridge_vlan_from_str("2-1000 untagged", &error);
    nmtst_assert_success(v1, error);
    g_assert_cmpint(nm_bridge_vlan_get_vid_range(v1, &vid_start, &vid_end), ==, TRUE);
    g_assert_cmpuint(vid_start, ==, 2);
    g_assert_cmpuint(vid_end, ==, 1000);
    g_assert_cmpint(nm_bridge_vlan_is_pvid(v1), ==, FALSE);
    g_assert_cmpint(nm_bridge_vlan_is_untagged(v1), ==, TRUE);
    nm_bridge_vlan_unref(v1);

    /* test comparison (1) */
    v1 = nm_bridge_vlan_from_str("10 untagged", &error);
    nmtst_assert_success(v1, error);

    g_assert_cmpint(nm_bridge_vlan_get_vid_range(v1, &vid_start, &vid_end), ==, FALSE);
    g_assert_cmpuint(vid_start, ==, 10);
    g_assert_cmpuint(vid_end, ==, 10);
    g_assert_cmpint(nm_bridge_vlan_is_sealed(v1), ==, FALSE);
    g_assert_cmpint(nm_bridge_vlan_is_pvid(v1), ==, FALSE);
    g_assert_cmpint(nm_bridge_vlan_is_untagged(v1), ==, TRUE);

    nm_bridge_vlan_set_pvid(v1, TRUE);
    nm_bridge_vlan_set_untagged(v1, FALSE);
    nm_bridge_vlan_seal(v1);

    g_assert_cmpint(nm_bridge_vlan_is_sealed(v1), ==, TRUE);
    g_assert_cmpint(nm_bridge_vlan_is_pvid(v1), ==, TRUE);
    g_assert_cmpint(nm_bridge_vlan_is_untagged(v1), ==, FALSE);

    str = nm_bridge_vlan_to_str(v1, &error);
    nmtst_assert_success(str, error);
    g_assert_cmpstr(str, ==, "10 pvid");
    nm_clear_g_free(&str);

    v2 = nm_bridge_vlan_from_str("  10  pvid  ", &error);
    nmtst_assert_success(v2, error);

    g_assert_cmpint(nm_bridge_vlan_cmp(v1, v2), ==, 0);

    nm_bridge_vlan_unref(v1);
    nm_bridge_vlan_unref(v2);

    /* test comparison (2) */
    v1 = nm_bridge_vlan_from_str("10", &error);
    nmtst_assert_success(v1, error);
    v2 = nm_bridge_vlan_from_str("20", &error);
    nmtst_assert_success(v2, error);

    g_assert_cmpint(nm_bridge_vlan_cmp(v1, v2), <, 0);

    nm_bridge_vlan_unref(v1);
    nm_bridge_vlan_unref(v2);
}

static void
create_bridge_connection(NMConnection **con, NMSettingBridge **s_bridge)
{
    NMSettingConnection *s_con;

    g_assert(con);
    g_assert(s_bridge);

    *con = nmtst_create_minimal_connection("bridge", NULL, NM_SETTING_BOND_SETTING_NAME, &s_con);

    g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "bridge0", NULL);

    *s_bridge = (NMSettingBridge *) nm_setting_bridge_new();
    g_assert(*s_bridge);

    nm_connection_add_setting(*con, NM_SETTING(*s_bridge));
}

#define test_verify_options_bridge(exp, ...) \
    _test_verify_options_bridge(exp, NM_MAKE_STRV(__VA_ARGS__))

static void
_test_verify_options_bridge(gboolean expected_result, const char *const *options)
{
    gs_unref_object NMConnection *con = NULL;
    NMSettingBridge              *s_bridge;
    const char *const            *option;

    g_assert(NM_PTRARRAY_LEN(options) % 2 == 0);

    create_bridge_connection(&con, &s_bridge);

    for (option = options; option[0]; option += 2) {
        const char *option_key = option[0];
        const char *option_val = option[1];
        GParamSpec *pspec = g_object_class_find_property(G_OBJECT_GET_CLASS(s_bridge), option_key);

        g_assert(pspec);
        g_assert(option_val);

        switch (G_PARAM_SPEC_VALUE_TYPE(pspec)) {
        case G_TYPE_UINT:
        {
            guint uvalue;

            uvalue = _nm_utils_ascii_str_to_uint64(option_val, 10, 0, G_MAXUINT, -1);
            g_assert(errno == 0);
            g_object_set(s_bridge, option_key, uvalue, NULL);
        } break;
        case G_TYPE_BOOLEAN:
        {
            int bvalue;

            bvalue = _nm_utils_ascii_str_to_bool(option_val, -1);
            g_assert(bvalue != -1);
            g_object_set(s_bridge, option_key, bvalue, NULL);
        } break;
        case G_TYPE_STRING:
            g_object_set(s_bridge, option_key, option_val, NULL);
            break;
        default:
            g_assert_not_reached();
            break;
        }
    }

    if (expected_result)
        nmtst_assert_connection_verifies_and_normalizable(con);
    else {
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_INVALID_PROPERTY);
    }
}

static void
test_bridge_verify(void)
{
    /* group-address */
    test_verify_options_bridge(FALSE, "group-address", "nonsense");
    test_verify_options_bridge(FALSE, "group-address", "FF:FF:FF:FF:FF:FF");
    test_verify_options_bridge(FALSE, "group-address", "01:02:03:04:05:06");
    test_verify_options_bridge(TRUE, "group-address", "01:80:C2:00:00:00");
    test_verify_options_bridge(FALSE, "group-address", "01:80:C2:00:00:02");
    test_verify_options_bridge(FALSE, "group-address", "01:80:C2:00:00:03");
    test_verify_options_bridge(TRUE, "group-address", "01:80:C2:00:00:00");
    test_verify_options_bridge(TRUE, "group-address", "01:80:C2:00:00:0A");
    /* vlan-protocol */
    test_verify_options_bridge(FALSE, "vlan-protocol", "nonsense124");
    test_verify_options_bridge(FALSE, "vlan-protocol", "802.11");
    test_verify_options_bridge(FALSE, "vlan-protocol", "802.1Q1");
    test_verify_options_bridge(TRUE, "vlan-protocol", "802.1Q");
    test_verify_options_bridge(TRUE, "vlan-protocol", "802.1ad");
    /* multicast-router */
    test_verify_options_bridge(FALSE, "multicast-router", "nonsense");
    test_verify_options_bridge(TRUE, "multicast-snooping", "no", "multicast-router", "auto");
    test_verify_options_bridge(TRUE, "multicast-snooping", "no", "multicast-router", "enabled");
    test_verify_options_bridge(TRUE, "multicast-snooping", "no", "multicast-router", "disabled");
    test_verify_options_bridge(TRUE, "multicast-snooping", "yes", "multicast-router", "enabled");
    test_verify_options_bridge(TRUE, "multicast-snooping", "yes", "multicast-router", "auto");
    test_verify_options_bridge(TRUE, "multicast-snooping", "yes", "multicast-router", "disabled");
    /* multicast-hash-max */
    test_verify_options_bridge(TRUE, "multicast-hash-max", "1024");
    test_verify_options_bridge(TRUE, "multicast-hash-max", "8192");
    test_verify_options_bridge(FALSE, "multicast-hash-max", "3");
}

/*****************************************************************************/

static void
test_tc_config_qdisc(void)
{
    NMTCQdisc *qdisc1, *qdisc2;
    char      *str;
    GError    *error = NULL;
    GVariant  *variant;

    qdisc1 = nm_tc_qdisc_new("fq_codel", TC_H_ROOT, &error);
    nmtst_assert_success(qdisc1, error);

    qdisc2 = nm_tc_qdisc_new("fq_codel", TC_H_ROOT, &error);
    nmtst_assert_success(qdisc2, error);

    g_assert(nm_tc_qdisc_equal(qdisc1, qdisc2));

    nm_tc_qdisc_unref(qdisc2);
    qdisc2 = nm_tc_qdisc_dup(qdisc1);

    g_assert(nm_tc_qdisc_equal(qdisc1, qdisc2));

    g_assert_cmpstr(nm_tc_qdisc_get_kind(qdisc1), ==, "fq_codel");
    g_assert(nm_tc_qdisc_get_handle(qdisc1) == TC_H_UNSPEC);
    g_assert(nm_tc_qdisc_get_parent(qdisc1) == TC_H_ROOT);

    str = nm_utils_tc_qdisc_to_str(qdisc1, &error);
    nmtst_assert_success(str, error);
    g_assert_cmpstr(str, ==, "root fq_codel");
    g_free(str);

    nm_tc_qdisc_unref(qdisc1);
    qdisc1 = nm_tc_qdisc_new("ingress", TC_H_INGRESS, &error);
    nmtst_assert_success(qdisc1, error);

    g_assert(!nm_tc_qdisc_equal(qdisc1, qdisc2));

    str = nm_utils_tc_qdisc_to_str(qdisc1, &error);
    nmtst_assert_success(str, error);
    g_assert_cmpstr(str, ==, "ingress");
    g_free(str);

    nm_tc_qdisc_unref(qdisc1);
    qdisc1 = nm_utils_tc_qdisc_from_str("narodil sa kristus pan", &error);
    nmtst_assert_no_success(qdisc1, error);
    g_clear_error(&error);

    qdisc1 = nm_utils_tc_qdisc_from_str("handle 1234 parent fff1:1 pfifo_fast", &error);
    nmtst_assert_success(qdisc1, error);

    g_assert_cmpstr(nm_tc_qdisc_get_kind(qdisc1), ==, "pfifo_fast");
    g_assert(nm_tc_qdisc_get_handle(qdisc1) == TC_H_MAKE(0x1234u << 16, 0x0000u));
    g_assert(nm_tc_qdisc_get_parent(qdisc1) == TC_H_MAKE(0xfff1u << 16, 0x0001u));

    str = nm_utils_tc_qdisc_to_str(qdisc1, &error);
    nmtst_assert_success(str, error);
    g_assert_cmpstr(str, ==, "parent fff1:1 handle 1234: pfifo_fast");
    g_free(str);

    nm_tc_qdisc_unref(qdisc2);
    str = nm_utils_tc_qdisc_to_str(qdisc1, &error);
    nmtst_assert_success(str, error);
    qdisc2 = nm_utils_tc_qdisc_from_str(str, &error);
    nmtst_assert_success(qdisc2, error);
    g_free(str);

    g_assert(nm_tc_qdisc_equal(qdisc1, qdisc2));

    nm_tc_qdisc_unref(qdisc1);
    nm_tc_qdisc_unref(qdisc2);

    qdisc1 = nm_utils_tc_qdisc_from_str("clsact", &error);
    nmtst_assert_success(qdisc1, error);
    str = nm_utils_tc_qdisc_to_str(qdisc1, &error);
    nmtst_assert_success(str, error);
    g_assert_cmpstr(str, ==, "clsact");
    nm_tc_qdisc_unref(qdisc1);
    g_free(str);

#define CHECK_ATTRIBUTE(qdisc, name, vtype, type, value) \
    variant = nm_tc_qdisc_get_attribute(qdisc, name);    \
    g_assert(variant);                                   \
    g_assert(g_variant_is_of_type(variant, vtype));      \
    g_assert_cmpint(g_variant_get_##type(variant), ==, value);

    qdisc1 = nm_utils_tc_qdisc_from_str("handle 1235 root sfq perturb 10 quantum 1480 "
                                        "limit 9000 flows 1024 divisor 500 depth 12",
                                        &error);
    nmtst_assert_success(qdisc1, error);

    g_assert_cmpstr(nm_tc_qdisc_get_kind(qdisc1), ==, "sfq");
    g_assert(nm_tc_qdisc_get_handle(qdisc1) == TC_H_MAKE(0x1235u << 16, 0x0000u));
    g_assert(nm_tc_qdisc_get_parent(qdisc1) == TC_H_ROOT);
    CHECK_ATTRIBUTE(qdisc1, "perturb", G_VARIANT_TYPE_INT32, int32, 10);
    CHECK_ATTRIBUTE(qdisc1, "quantum", G_VARIANT_TYPE_UINT32, uint32, 1480);
    CHECK_ATTRIBUTE(qdisc1, "limit", G_VARIANT_TYPE_UINT32, uint32, 9000);
    CHECK_ATTRIBUTE(qdisc1, "flows", G_VARIANT_TYPE_UINT32, uint32, 1024);
    CHECK_ATTRIBUTE(qdisc1, "divisor", G_VARIANT_TYPE_UINT32, uint32, 500);
    CHECK_ATTRIBUTE(qdisc1, "depth", G_VARIANT_TYPE_UINT32, uint32, 12);
    nm_tc_qdisc_unref(qdisc1);

    qdisc1 = nm_utils_tc_qdisc_from_str("handle 1235 root tbf rate 1000000 burst 5000 limit 10000",
                                        &error);
    nmtst_assert_success(qdisc1, error);

    g_assert_cmpstr(nm_tc_qdisc_get_kind(qdisc1), ==, "tbf");
    g_assert(nm_tc_qdisc_get_handle(qdisc1) == TC_H_MAKE(0x1235u << 16, 0x0000u));
    g_assert(nm_tc_qdisc_get_parent(qdisc1) == TC_H_ROOT);
    CHECK_ATTRIBUTE(qdisc1, "rate", G_VARIANT_TYPE_UINT64, uint64, 1000000);
    CHECK_ATTRIBUTE(qdisc1, "burst", G_VARIANT_TYPE_UINT32, uint32, 5000);
    CHECK_ATTRIBUTE(qdisc1, "limit", G_VARIANT_TYPE_UINT32, uint32, 10000);
    nm_tc_qdisc_unref(qdisc1);

#undef CHECK_ATTRIBUTE
}

static void
test_tc_config_action(void)
{
    NMTCAction *action1, *action2;
    char       *str;
    GError     *error = NULL;

    action1 = nm_tc_action_new("drop", &error);
    nmtst_assert_success(action1, error);
    action2 = nm_tc_action_new("drop", &error);
    nmtst_assert_success(action2, error);

    g_assert(nm_tc_action_equal(action1, action2));
    g_assert_cmpstr(nm_tc_action_get_kind(action1), ==, "drop");

    nm_tc_action_unref(action1);
    action1 = nm_tc_action_new("simple", &error);
    nmtst_assert_success(action1, error);
    nm_tc_action_set_attribute(action1, "sdata", g_variant_new_bytestring("Hello"));

    g_assert(!nm_tc_action_equal(action1, action2));

    str = nm_utils_tc_action_to_str(action1, &error);
    nmtst_assert_success(str, error);
    g_assert_cmpstr(str, ==, "simple sdata Hello");
    g_free(str);

    str = nm_utils_tc_action_to_str(action2, &error);
    nmtst_assert_success(str, error);
    g_assert_cmpstr(str, ==, "drop");
    g_free(str);

    nm_tc_action_unref(action2);
    action2 = nm_tc_action_dup(action1);

    g_assert(nm_tc_action_equal(action1, action2));

    nm_tc_action_unref(action1);
    action1 = nm_utils_tc_action_from_str("narodil sa kristus pan", &error);
    nmtst_assert_no_success(action1, error);
    g_clear_error(&error);

    action1 = nm_utils_tc_action_from_str("simple sdata Hello", &error);
    nmtst_assert_success(action1, error);

    g_assert_cmpstr(nm_tc_action_get_kind(action1), ==, "simple");
    g_assert_cmpstr(g_variant_get_bytestring(nm_tc_action_get_attribute(action1, "sdata")),
                    ==,
                    "Hello");

    nm_tc_action_unref(action1);
    nm_tc_action_unref(action2);
}

static void
test_tc_config_tfilter_matchall_sdata(void)
{
    NMTCAction  *action1;
    NMTCTfilter *tfilter1, *tfilter2;
    char        *str;
    GError      *error = NULL;

    tfilter1 = nm_tc_tfilter_new("matchall", TC_H_MAKE(0x1234u << 16, 0x0000u), &error);
    nmtst_assert_success(tfilter1, error);

    tfilter2 = nm_tc_tfilter_new("matchall", TC_H_MAKE(0x1234u << 16, 0x0000u), &error);
    nmtst_assert_success(tfilter2, error);

    g_assert(nm_tc_tfilter_equal(tfilter1, tfilter2));

    action1 = nm_tc_action_new("simple", &error);
    nmtst_assert_success(action1, error);
    nm_tc_action_set_attribute(action1, "sdata", g_variant_new_bytestring("Hello"));
    nm_tc_tfilter_set_action(tfilter1, action1);
    nm_tc_action_unref(action1);

    g_assert(!nm_tc_tfilter_equal(tfilter1, tfilter2));

    str = nm_utils_tc_tfilter_to_str(tfilter1, &error);
    nmtst_assert_success(str, error);
    g_assert_cmpstr(str, ==, "parent 1234: matchall action simple sdata Hello");
    g_free(str);

    nm_tc_tfilter_unref(tfilter2);
    tfilter2 = nm_tc_tfilter_dup(tfilter1);

    g_assert(nm_tc_tfilter_equal(tfilter1, tfilter2));

    nm_tc_tfilter_unref(tfilter1);
    tfilter1 = nm_utils_tc_tfilter_from_str("narodil sa kristus pan", &error);
    nmtst_assert_no_success(tfilter1, error);
    g_clear_error(&error);

    str = nm_utils_tc_tfilter_to_str(tfilter2, &error);
    nmtst_assert_success(str, error);
    tfilter1 = nm_utils_tc_tfilter_from_str(str, &error);
    nmtst_assert_success(tfilter1, error);
    g_free(str);

    g_assert(nm_tc_tfilter_equal(tfilter1, tfilter2));

    nm_tc_tfilter_unref(tfilter1);
    nm_tc_tfilter_unref(tfilter2);
}

static void
test_tc_config_tfilter_matchall_mirred(void)
{
    NMTCAction        *action;
    NMTCTfilter       *tfilter1;
    GError            *error      = NULL;
    gs_strfreev char **attr_names = NULL;
    gs_free char      *str        = NULL;
    GVariant          *variant;

    tfilter1 =
        nm_utils_tc_tfilter_from_str("parent ffff: matchall action mirred ingress mirror dev eth0",
                                     &error);
    nmtst_assert_success(tfilter1, error);
    g_assert_cmpint(nm_tc_tfilter_get_parent(tfilter1), ==, TC_H_MAKE(0xffff << 16, 0));
    g_assert_cmpstr(nm_tc_tfilter_get_kind(tfilter1), ==, "matchall");

    action = nm_tc_tfilter_get_action(tfilter1);
    nm_assert(action);
    g_assert_cmpstr(nm_tc_action_get_kind(action), ==, "mirred");
    attr_names = nm_tc_action_get_attribute_names(action);
    g_assert(attr_names);
    g_assert_cmpint(g_strv_length(attr_names), ==, 3);

    variant = nm_tc_action_get_attribute(action, "ingress");
    g_assert(variant);
    g_assert(g_variant_is_of_type(variant, G_VARIANT_TYPE_BOOLEAN));
    g_assert(g_variant_get_boolean(variant));

    variant = nm_tc_action_get_attribute(action, "mirror");
    g_assert(variant);
    g_assert(g_variant_is_of_type(variant, G_VARIANT_TYPE_BOOLEAN));
    g_assert(g_variant_get_boolean(variant));

    variant = nm_tc_action_get_attribute(action, "dev");
    g_assert(variant);
    g_assert(g_variant_is_of_type(variant, G_VARIANT_TYPE_STRING));
    g_assert_cmpstr(g_variant_get_string(variant, NULL), ==, "eth0");

    str = nm_utils_tc_tfilter_to_str(tfilter1, &error);
    nmtst_assert_success(str, error);
    g_assert_cmpstr(str, ==, "parent ffff: matchall action mirred dev eth0 ingress mirror");

    nm_tc_tfilter_unref(tfilter1);
}

static void
test_tc_config_setting_valid(void)
{
    gs_unref_object NMSettingTCConfig *s_tc = NULL;
    NMTCQdisc                         *qdisc1, *qdisc2;
    GError                            *error = NULL;

    s_tc = (NMSettingTCConfig *) nm_setting_tc_config_new();

    qdisc1 = nm_tc_qdisc_new("fq_codel", TC_H_ROOT, &error);
    nmtst_assert_success(qdisc1, error);

    qdisc2 = nm_tc_qdisc_new("pfifo_fast", TC_H_MAKE(0xfff1u << 16, 0x0001u), &error);
    nmtst_assert_success(qdisc2, error);
    nm_tc_qdisc_set_handle(qdisc2, TC_H_MAKE(0x1234u << 16, 0x0000u));

    g_assert(nm_setting_tc_config_get_num_qdiscs(s_tc) == 0);
    g_assert(nm_setting_tc_config_add_qdisc(s_tc, qdisc1) == TRUE);
    g_assert(nm_setting_tc_config_get_num_qdiscs(s_tc) == 1);
    g_assert(nm_setting_tc_config_get_qdisc(s_tc, 0) != NULL);
    g_assert(nm_setting_tc_config_remove_qdisc_by_value(s_tc, qdisc2) == FALSE);
    g_assert(nm_setting_tc_config_add_qdisc(s_tc, qdisc2) == TRUE);
    g_assert(nm_setting_tc_config_get_num_qdiscs(s_tc) == 2);
    g_assert(nm_setting_tc_config_remove_qdisc_by_value(s_tc, qdisc1) == TRUE);
    g_assert(nm_setting_tc_config_get_num_qdiscs(s_tc) == 1);
    nm_setting_tc_config_clear_qdiscs(s_tc);
    g_assert(nm_setting_tc_config_get_num_qdiscs(s_tc) == 0);

    nm_tc_qdisc_unref(qdisc1);
    nm_tc_qdisc_unref(qdisc2);
}

static void
test_tc_config_setting_duplicates(void)
{
    gs_unref_ptrarray GPtrArray *qdiscs   = NULL;
    gs_unref_ptrarray GPtrArray *tfilters = NULL;
    NMSettingConnection         *s_con;
    NMConnection                *con;
    NMSetting                   *s_tc;
    NMTCQdisc                   *qdisc;
    NMTCTfilter                 *tfilter;
    GError                      *error = NULL;

    con = nmtst_create_minimal_connection("dummy", NULL, NM_SETTING_DUMMY_SETTING_NAME, &s_con);
    g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "dummy1", NULL);

    s_tc = nm_setting_tc_config_new();
    nm_connection_add_setting(con, s_tc);
    qdiscs   = g_ptr_array_new_with_free_func((GDestroyNotify) nm_tc_qdisc_unref);
    tfilters = g_ptr_array_new_with_free_func((GDestroyNotify) nm_tc_tfilter_unref);

    /* 1. add duplicate qdiscs */
    qdisc = nm_utils_tc_qdisc_from_str("handle 1234 parent fff1:1 pfifo_fast", &error);
    nmtst_assert_success(qdisc, error);
    g_ptr_array_add(qdiscs, qdisc);

    qdisc = nm_utils_tc_qdisc_from_str("handle 1234 parent fff1:1 pfifo_fast", &error);
    nmtst_assert_success(qdisc, error);
    g_ptr_array_add(qdiscs, qdisc);

    g_object_set(s_tc, NM_SETTING_TC_CONFIG_QDISCS, qdiscs, NULL);
    nmtst_assert_connection_unnormalizable(con,
                                           NM_CONNECTION_ERROR,
                                           NM_CONNECTION_ERROR_INVALID_PROPERTY);

    /* 2. make qdiscs unique */
    g_ptr_array_remove_index(qdiscs, 0);
    g_object_set(s_tc, NM_SETTING_TC_CONFIG_QDISCS, qdiscs, NULL);
    nmtst_assert_connection_verifies_and_normalizable(con);

    /* 3. add duplicate filters */
    tfilter =
        nm_utils_tc_tfilter_from_str("parent 1234: matchall action simple sdata Hello", &error);
    nmtst_assert_success(tfilter, error);
    g_ptr_array_add(tfilters, tfilter);

    tfilter =
        nm_utils_tc_tfilter_from_str("parent 1234: matchall action simple sdata Hello", &error);
    nmtst_assert_success(tfilter, error);
    g_ptr_array_add(tfilters, tfilter);

    g_object_set(s_tc, NM_SETTING_TC_CONFIG_TFILTERS, tfilters, NULL);
    nmtst_assert_connection_unnormalizable(con,
                                           NM_CONNECTION_ERROR,
                                           NM_CONNECTION_ERROR_INVALID_PROPERTY);

    /* 4. make filters unique */
    g_ptr_array_remove_index(tfilters, 0);
    g_object_set(s_tc, NM_SETTING_TC_CONFIG_TFILTERS, tfilters, NULL);
    nmtst_assert_connection_verifies_and_normalizable(con);
}

static void
test_tc_config_dbus(void)
{
    NMConnection *connection1, *connection2;
    NMSetting    *s_tc;
    NMTCQdisc    *qdisc1, *qdisc2;
    NMTCTfilter  *tfilter1, *tfilter2;
    NMTCAction   *action;
    GVariant     *dbus, *tc_dbus, *var1, *var2;
    GError       *error = NULL;
    gboolean      success;

    connection1 =
        nmtst_create_minimal_connection("dummy", NULL, NM_SETTING_DUMMY_SETTING_NAME, NULL);

    s_tc = nm_setting_tc_config_new();

    qdisc1 = nm_tc_qdisc_new("fq_codel", TC_H_ROOT, &error);
    nmtst_assert_success(qdisc1, error);
    nm_tc_qdisc_set_handle(qdisc1, TC_H_MAKE(0x1234u << 16, 0x0000u));
    nm_setting_tc_config_add_qdisc(NM_SETTING_TC_CONFIG(s_tc), qdisc1);

    qdisc2 = nm_tc_qdisc_new("ingress", TC_H_INGRESS, &error);
    nmtst_assert_success(qdisc2, error);
    nm_tc_qdisc_set_handle(qdisc2, TC_H_MAKE(TC_H_INGRESS, 0u));
    nm_setting_tc_config_add_qdisc(NM_SETTING_TC_CONFIG(s_tc), qdisc2);

    tfilter1 = nm_tc_tfilter_new("matchall", TC_H_MAKE(0x1234u << 16, 0x0000u), &error);
    nmtst_assert_success(tfilter1, error);
    action = nm_tc_action_new("drop", &error);
    nmtst_assert_success(action, error);
    nm_tc_tfilter_set_action(tfilter1, action);
    nm_tc_action_unref(action);
    nm_setting_tc_config_add_tfilter(NM_SETTING_TC_CONFIG(s_tc), tfilter1);
    nm_tc_tfilter_unref(tfilter1);

    tfilter2 = nm_tc_tfilter_new("matchall", TC_H_MAKE(TC_H_INGRESS, 0u), &error);
    nmtst_assert_success(tfilter2, error);
    action = nm_tc_action_new("simple", &error);
    nmtst_assert_success(action, error);
    nm_tc_action_set_attribute(action, "sdata", g_variant_new_bytestring("Hello"));
    nm_tc_tfilter_set_action(tfilter2, action);
    nm_tc_action_unref(action);
    nm_setting_tc_config_add_tfilter(NM_SETTING_TC_CONFIG(s_tc), tfilter2);
    nm_tc_tfilter_unref(tfilter2);

    nm_connection_add_setting(connection1, s_tc);

    dbus = nm_connection_to_dbus(connection1, NM_CONNECTION_SERIALIZE_ALL);

    tc_dbus = g_variant_lookup_value(dbus, "tc", G_VARIANT_TYPE_VARDICT);
    g_assert(tc_dbus);

    var1 = g_variant_lookup_value(tc_dbus, "qdiscs", G_VARIANT_TYPE("aa{sv}"));
    var2 = g_variant_new_parsed("[{'kind':   <'fq_codel'>,"
                                "  'handle': <uint32 0x12340000>,"
                                "  'parent': <uint32 0xffffffff>},"
                                " {'kind':   <'ingress'>,"
                                "  'handle': <uint32 0xffff0000>,"
                                "  'parent': <uint32 0xfffffff1>}]");
    g_assert(g_variant_equal(var1, var2));
    g_variant_unref(var1);
    g_variant_unref(var2);

    var1 = g_variant_lookup_value(tc_dbus, "tfilters", G_VARIANT_TYPE("aa{sv}"));
    var2 = g_variant_new_parsed("[{'kind':   <'matchall'>,"
                                "  'handle': <uint32 0>,"
                                "  'parent': <uint32 0x12340000>,"
                                "  'action': <{'kind': <'drop'>}>},"
                                " {'kind':   <'matchall'>,"
                                "  'handle': <uint32 0>,"
                                "  'parent': <uint32 0xffff0000>,"
                                "  'action': <{'kind':  <'simple'>,"
                                "              'sdata': <b'Hello'>}>}]");
    g_variant_unref(var1);
    g_variant_unref(var2);

    g_variant_unref(tc_dbus);

    connection2 = nm_simple_connection_new();
    success     = nm_connection_replace_settings(connection2, dbus, &error);
    nmtst_assert_success(success, error);

    g_assert(nm_connection_diff(connection1, connection2, NM_SETTING_COMPARE_FLAG_EXACT, NULL));

    g_variant_unref(dbus);

    nm_tc_qdisc_unref(qdisc1);
    nm_tc_qdisc_unref(qdisc2);

    g_object_unref(connection1);
    g_object_unref(connection2);
}

/*****************************************************************************/

static void
_rndt_wired_add_s390_options(NMSettingWired *s_wired, char **out_keyfile_entries)
{
    gsize                         n_opts;
    gsize                         i, j;
    const char *const            *option_names;
    gs_free const char          **opt_keys  = NULL;
    gs_strfreev char            **opt_vals  = NULL;
    gs_free bool                 *opt_found = NULL;
    GString                      *keyfile_entries;
    nm_auto_free_gstring GString *str_tmp = NULL;

    option_names = nm_setting_wired_get_valid_s390_options(nmtst_get_rand_bool() ? NULL : s_wired);

    n_opts   = NM_PTRARRAY_LEN(option_names);
    opt_keys = g_new(const char *, (n_opts + 1));
    nmtst_rand_perm(NULL, opt_keys, option_names, sizeof(const char *), n_opts);
    n_opts           = nmtst_get_rand_uint32() % (n_opts + 1);
    opt_keys[n_opts] = NULL;

    opt_vals  = g_new0(char *, n_opts + 1);
    opt_found = g_new0(bool, n_opts + 1);
    for (i = 0; i < n_opts; i++) {
        if (nm_streq(opt_keys[i], "bridge_role"))
            opt_vals[i] = g_strdup(nmtst_rand_select_str("primary", "secondary", "none"));
        else {
            guint p = nmtst_get_rand_uint32() % 1000;
            if (p < 200)
                opt_vals[i] = nm_strdup_int(i);
            else {
                opt_vals[i] = g_strdup_printf("%s%s%s%s-%zu",
                                              ((p % 5) % 2) ? "\n" : "",
                                              ((p % 7) % 2) ? "\t" : "",
                                              ((p % 11) % 2) ? "x" : "",
                                              ((p % 13) % 2) ? "=" : "",
                                              i);
            }
        }
    }

    if (nmtst_get_rand_bool()) {
        gs_unref_hashtable GHashTable *hash = NULL;

        hash = g_hash_table_new(nm_str_hash, g_str_equal);
        for (i = 0; i < n_opts; i++)
            g_hash_table_insert(hash, (char *) opt_keys[i], opt_vals[i]);
        g_object_set(s_wired, NM_SETTING_WIRED_S390_OPTIONS, hash, NULL);
    } else {
        _nm_setting_wired_clear_s390_options(s_wired);
        for (i = 0; i < n_opts; i++) {
            if (!nm_setting_wired_add_s390_option(s_wired, opt_keys[i], opt_vals[i]))
                g_assert_not_reached();
        }
    }

    g_assert_cmpint(nm_setting_wired_get_num_s390_options(s_wired), ==, n_opts);

    keyfile_entries = g_string_new(NULL);
    str_tmp         = g_string_new(NULL);
    if (n_opts > 0)
        g_string_append_printf(keyfile_entries, "[ethernet-s390-options]\n");
    for (i = 0; i < n_opts; i++) {
        gssize      idx;
        const char *k, *v;

        nm_setting_wired_get_s390_option(s_wired, i, &k, &v);
        g_assert(k);
        g_assert(v);

        idx = nm_strv_find_first(opt_keys, n_opts, k);
        g_assert(idx >= 0);
        g_assert(!opt_found[idx]);
        opt_found[idx] = TRUE;
        g_assert_cmpstr(opt_keys[idx], ==, k);
        g_assert_cmpstr(opt_vals[idx], ==, v);

        g_string_truncate(str_tmp, 0);
        for (j = 0; v[j] != '\0'; j++) {
            if (v[j] == '\n')
                g_string_append(str_tmp, "\\n");
            else if (v[j] == '\t')
                g_string_append(str_tmp, "\\t");
            else
                g_string_append_c(str_tmp, v[j]);
        }

        g_string_append_printf(keyfile_entries, "%s=%s\n", k, str_tmp->str);
    }
    for (i = 0; i < n_opts; i++)
        g_assert(opt_found[i]);
    if (n_opts > 0)
        g_string_append_printf(keyfile_entries, "\n");
    *out_keyfile_entries = g_string_free(keyfile_entries, FALSE);
}

static GPtrArray *
_rndt_wg_peers_create(void)
{
    GPtrArray *wg_peers;
    guint      i, n;

    wg_peers = g_ptr_array_new_with_free_func((GDestroyNotify) nm_wireguard_peer_unref);

    n = nmtst_get_rand_uint32() % 10;
    for (i = 0; i < n; i++) {
        NMWireGuardPeer *peer;
        guint8           public_key_buf[NM_WIREGUARD_PUBLIC_KEY_LEN];
        guint8           preshared_key_buf[NM_WIREGUARD_SYMMETRIC_KEY_LEN];
        gs_free char    *public_key    = NULL;
        gs_free char    *preshared_key = NULL;
        gs_free char    *s_endpoint    = NULL;
        guint            i_aip, n_aip;

        /* we don't bother to create a valid curve25519 public key. Of course, libnm cannot
         * check whether the public key is bogus or not. Hence, for our purpose a random
         * bogus key is good enough. */
        public_key = g_base64_encode(nmtst_rand_buf(NULL, public_key_buf, sizeof(public_key_buf)),
                                     sizeof(public_key_buf));

        preshared_key =
            g_base64_encode(nmtst_rand_buf(NULL, preshared_key_buf, sizeof(preshared_key_buf)),
                            sizeof(preshared_key_buf));

        s_endpoint = _create_random_ipaddr(AF_UNSPEC, TRUE);

        peer = nm_wireguard_peer_new();
        if (!nm_wireguard_peer_set_public_key(peer, public_key, TRUE))
            g_assert_not_reached();

        if (!nm_wireguard_peer_set_preshared_key(peer,
                                                 nmtst_rand_select(NULL, preshared_key),
                                                 TRUE))
            g_assert_not_reached();

        nm_wireguard_peer_set_preshared_key_flags(
            peer,
            nmtst_rand_select(NM_SETTING_SECRET_FLAG_NONE,
                              NM_SETTING_SECRET_FLAG_NOT_SAVED,
                              NM_SETTING_SECRET_FLAG_AGENT_OWNED));

        nm_wireguard_peer_set_persistent_keepalive(
            peer,
            nmtst_rand_select((guint32) 0, nmtst_get_rand_uint32()));

        if (!nm_wireguard_peer_set_endpoint(peer, nmtst_rand_select(s_endpoint, NULL), TRUE))
            g_assert_not_reached();

        n_aip = nmtst_rand_select(0, nmtst_get_rand_uint32() % 10);
        for (i_aip = 0; i_aip < n_aip; i_aip++) {
            gs_free char *aip = NULL;

            aip = _create_random_ipaddr(AF_UNSPEC, FALSE);
            if (!nm_wireguard_peer_append_allowed_ip(peer, aip, FALSE))
                g_assert_not_reached();
        }

        g_assert(nm_wireguard_peer_is_valid(peer, TRUE, TRUE, NULL));

        nm_wireguard_peer_seal(peer);
        g_ptr_array_add(wg_peers, peer);
    }

    return wg_peers;
}

static const char *
_rndt_wg_peers_to_keyfile(GPtrArray *wg_peers, gboolean strict, char **out_str)
{
    nm_auto_free_gstring GString *gstr     = NULL;
    nm_auto_free_gstring GString *gstr_aip = NULL;
    guint                         i, j;

    g_assert(wg_peers);
    g_assert(out_str && !*out_str);

    nm_gstring_prepare(&gstr);
    for (i = 0; i < wg_peers->len; i++) {
        const NMWireGuardPeer *peer                   = wg_peers->pdata[i];
        gs_free char          *s_endpoint             = NULL;
        gs_free char          *s_preshared_key        = NULL;
        gs_free char          *s_preshared_key_flags  = NULL;
        gs_free char          *s_persistent_keepalive = NULL;
        gs_free char          *s_allowed_ips          = NULL;

        if (nm_wireguard_peer_get_endpoint(peer))
            s_endpoint = g_strdup_printf("endpoint=%s\n", nm_wireguard_peer_get_endpoint(peer));
        else if (!strict)
            s_endpoint = g_strdup_printf("endpoint=\n");

        if (nm_wireguard_peer_get_preshared_key(peer) || !strict) {
            if (nm_wireguard_peer_get_preshared_key_flags(peer) == NM_SETTING_SECRET_FLAG_NONE)
                s_preshared_key = g_strdup_printf("preshared-key=%s\n",
                                                  nm_wireguard_peer_get_preshared_key(peer) ?: "");
        }

        if (nm_wireguard_peer_get_preshared_key_flags(peer) != NM_SETTING_SECRET_FLAG_NOT_REQUIRED
            || !strict)
            s_preshared_key_flags =
                g_strdup_printf("preshared-key-flags=%d\n",
                                (int) nm_wireguard_peer_get_preshared_key_flags(peer));

        if (nm_wireguard_peer_get_persistent_keepalive(peer) != 0 || !strict)
            s_persistent_keepalive =
                g_strdup_printf("persistent-keepalive=%u\n",
                                nm_wireguard_peer_get_persistent_keepalive(peer));

        if (nm_wireguard_peer_get_allowed_ips_len(peer) > 0 || !strict) {
            nm_gstring_prepare(&gstr_aip);
            for (j = 0; j < nm_wireguard_peer_get_allowed_ips_len(peer); j++)
                g_string_append_printf(gstr_aip,
                                       "%s;",
                                       nm_wireguard_peer_get_allowed_ip(peer, j, NULL));
            s_allowed_ips = g_strdup_printf("allowed-ips=%s\n", gstr_aip->str);
        }

        if (!s_endpoint && !s_preshared_key && !s_preshared_key_flags && !s_persistent_keepalive
            && !s_allowed_ips)
            s_endpoint = g_strdup_printf("endpoint=\n");

        g_string_append_printf(gstr,
                               "\n"
                               "[wireguard-peer.%s]\n"
                               "%s" /* endpoint */
                               "%s" /* preshared-key */
                               "%s" /* preshared-key-flags */
                               "%s" /* persistent-keepalive */
                               "%s" /* allowed-ips */
                               "",
                               nm_wireguard_peer_get_public_key(peer),
                               s_endpoint ?: "",
                               s_preshared_key ?: "",
                               s_preshared_key_flags ?: "",
                               s_persistent_keepalive ?: "",
                               s_allowed_ips ?: "");
    }

    return (*out_str = g_string_free(g_steal_pointer(&gstr), FALSE));
}

static void
_rndt_wg_peers_assert_equal(NMSettingWireGuard *s_wg,
                            GPtrArray          *peers,
                            gboolean            consider_persistent_secrets,
                            gboolean            consider_all_secrets,
                            gboolean            expect_no_secrets)
{
    guint i;

    g_assert(NM_IS_SETTING_WIREGUARD(s_wg));
    g_assert(peers);

    g_assert_cmpint(peers->len, ==, nm_setting_wireguard_get_peers_len(s_wg));

    for (i = 0; i < peers->len; i++) {
        const NMWireGuardPeer *a = peers->pdata[i];
        const NMWireGuardPeer *b = nm_setting_wireguard_get_peer(s_wg, i);
        gboolean               consider_secrets;

        g_assert(a);
        g_assert(b);

        g_assert_cmpint(nm_wireguard_peer_cmp(a, b, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS), ==, 0);

        if (consider_all_secrets || !nm_wireguard_peer_get_preshared_key(a))
            consider_secrets = TRUE;
        else if (nm_wireguard_peer_get_preshared_key(b))
            consider_secrets = TRUE;
        else if (consider_persistent_secrets
                 && nm_wireguard_peer_get_preshared_key_flags(b) == NM_SETTING_SECRET_FLAG_NONE)
            consider_secrets = TRUE;
        else
            consider_secrets = FALSE;

        if (consider_secrets) {
            g_assert_cmpstr(nm_wireguard_peer_get_preshared_key(a),
                            ==,
                            nm_wireguard_peer_get_preshared_key(b));
            g_assert_cmpint(nm_wireguard_peer_cmp(a, b, NM_SETTING_COMPARE_FLAG_EXACT), ==, 0);
        }

        if (expect_no_secrets)
            g_assert_cmpstr(nm_wireguard_peer_get_preshared_key(b), ==, NULL);
    }
}

static void
_rndt_wg_peers_fix_secrets(NMSettingWireGuard *s_wg, GPtrArray *peers)
{
    guint i;

    g_assert(NM_IS_SETTING_WIREGUARD(s_wg));
    g_assert(peers);

    g_assert_cmpint(peers->len, ==, nm_setting_wireguard_get_peers_len(s_wg));

    for (i = 0; i < peers->len; i++) {
        const NMWireGuardPeer                *a       = peers->pdata[i];
        const NMWireGuardPeer                *b       = nm_setting_wireguard_get_peer(s_wg, i);
        nm_auto_unref_wgpeer NMWireGuardPeer *b_clone = NULL;

        g_assert(a);
        g_assert(b);

        g_assert_cmpint(nm_wireguard_peer_get_preshared_key_flags(a),
                        ==,
                        nm_wireguard_peer_get_preshared_key_flags(b));
        g_assert_cmpint(nm_wireguard_peer_cmp(a, b, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS), ==, 0);

        if (!nm_streq0(nm_wireguard_peer_get_preshared_key(a),
                       nm_wireguard_peer_get_preshared_key(b))) {
            g_assert_cmpstr(nm_wireguard_peer_get_preshared_key(a), !=, NULL);
            g_assert_cmpstr(nm_wireguard_peer_get_preshared_key(b), ==, NULL);
            g_assert(NM_IN_SET(nm_wireguard_peer_get_preshared_key_flags(a),
                               NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                               NM_SETTING_SECRET_FLAG_NOT_SAVED));
            b_clone = nm_wireguard_peer_new_clone(b, TRUE);
            if (!nm_wireguard_peer_set_preshared_key(b_clone,
                                                     nm_wireguard_peer_get_preshared_key(a),
                                                     TRUE))
                g_assert_not_reached();
            nm_setting_wireguard_set_peer(s_wg, b_clone, i);
            b = nm_setting_wireguard_get_peer(s_wg, i);
            g_assert(b == b_clone);
        } else {
            if (nm_wireguard_peer_get_preshared_key(a)) {
                g_assert(NM_IN_SET(nm_wireguard_peer_get_preshared_key_flags(a),
                                   NM_SETTING_SECRET_FLAG_NONE,
                                   NM_SETTING_SECRET_FLAG_NOT_REQUIRED));
            } else {
                g_assert(NM_IN_SET(nm_wireguard_peer_get_preshared_key_flags(a),
                                   NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                   NM_SETTING_SECRET_FLAG_NONE,
                                   NM_SETTING_SECRET_FLAG_NOT_SAVED,
                                   NM_SETTING_SECRET_FLAG_NOT_REQUIRED));
            }
        }

        g_assert_cmpstr(nm_wireguard_peer_get_preshared_key(a),
                        ==,
                        nm_wireguard_peer_get_preshared_key(b));
        g_assert_cmpint(nm_wireguard_peer_cmp(a, b, NM_SETTING_COMPARE_FLAG_EXACT), ==, 0);
    }
}

static void
test_roundtrip_conversion(gconstpointer test_data)
{
    const int   MODE           = GPOINTER_TO_INT(test_data);
    const char *ID             = nm_sprintf_bufa(100, "roundtrip-conversion-%d", MODE);
    const char *UUID           = "63376701-b61e-4318-bf7e-664a1c1eeaab";
    const char *INTERFACE_NAME = nm_sprintf_bufa(100, "ifname%d", MODE);
    guint32     ETH_MTU        = nmtst_rand_select((guint32) 0u, nmtst_get_rand_uint32());
    const char *WG_PRIVATE_KEY =
        nmtst_get_rand_bool() ? "yGXGK+5bVnxSJUejH4vbpXbq+ZtaG4NB8IHRK/aVtE0=" : NULL;
    const NMSettingSecretFlags WG_PRIVATE_KEY_FLAGS =
        nmtst_rand_select(NM_SETTING_SECRET_FLAG_NONE,
                          NM_SETTING_SECRET_FLAG_NOT_SAVED,
                          NM_SETTING_SECRET_FLAG_AGENT_OWNED);
    const guint WG_LISTEN_PORT = nmtst_rand_select(0u, nmtst_get_rand_uint32() % 0x10000);
    const guint WG_FWMARK      = nmtst_rand_select(0u, nmtst_get_rand_uint32());
    gs_unref_ptrarray GPtrArray         *kf_data_arr = g_ptr_array_new_with_free_func(g_free);
    gs_unref_ptrarray GPtrArray         *wg_peers    = NULL;
    const NMConnectionSerializationFlags dbus_serialization_flags[] = {
        NM_CONNECTION_SERIALIZE_ALL,
        NM_CONNECTION_SERIALIZE_WITH_NON_SECRET,
        NM_CONNECTION_SERIALIZE_WITH_SECRETS,
    };
    guint                         dbus_serialization_flags_idx;
    gs_unref_object NMConnection *con     = NULL;
    gs_free_error GError         *error   = NULL;
    gs_free char                 *tmp_str = NULL;
    guint                         kf_data_idx;
    NMSettingConnection          *s_con = NULL;
    NMSettingWired               *s_eth = NULL;
    NMSettingWireGuard           *s_wg  = NULL;
    union {
        struct {
            NMSettingIPConfig *s_6;
            NMSettingIPConfig *s_4;
        };
        NMSettingIPConfig *s_x[2];
    } s_ip;
    int           is_ipv4;
    guint         i;
    gboolean      success;
    gs_free char *s390_keyfile_entries = NULL;

    switch (MODE) {
    case 0:
        con = nmtst_create_minimal_connection(ID, UUID, NM_SETTING_WIRED_SETTING_NAME, &s_con);
        g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, INTERFACE_NAME, NULL);
        nmtst_connection_normalize(con);

        s_eth = NM_SETTING_WIRED(nm_connection_get_setting(con, NM_TYPE_SETTING_WIRED));
        g_assert(NM_IS_SETTING_WIRED(s_eth));

        g_object_set(s_eth, NM_SETTING_WIRED_MTU, ETH_MTU, NULL);

        _rndt_wired_add_s390_options(s_eth, &s390_keyfile_entries);

        g_ptr_array_add(
            kf_data_arr,
            g_strdup_printf("[connection]\n"
                            "id=%s\n"
                            "uuid=%s\n"
                            "type=ethernet\n"
                            "interface-name=%s\n"
                            "\n"
                            "[ethernet]\n"
                            "%s" /* mtu */
                            "\n"
                            "%s" /* [ethernet-s390-options] */
                            "[ipv4]\n"
                            "method=auto\n"
                            "\n"
                            "[ipv6]\n"
                            "addr-gen-mode=default\n"
                            "method=auto\n"
                            "\n"
                            "[proxy]\n"
                            "",
                            ID,
                            UUID,
                            INTERFACE_NAME,
                            (ETH_MTU != 0) ? nm_sprintf_bufa(100, "mtu=%u\n", ETH_MTU) : "",
                            s390_keyfile_entries));

        g_ptr_array_add(
            kf_data_arr,
            g_strdup_printf("[connection]\n"
                            "id=%s\n"
                            "uuid=%s\n"
                            "type=ethernet\n"
                            "interface-name=%s\n"
                            "\n"
                            "[ethernet]\n"
                            "%s" /* mtu */
                            "\n"
                            "%s" /* [ethernet-s390-options] */
                            "[ipv4]\n"
                            "method=auto\n"
                            "\n"
                            "[ipv6]\n"
                            "addr-gen-mode=default\n"
                            "method=auto\n"
                            "",
                            ID,
                            UUID,
                            INTERFACE_NAME,
                            (ETH_MTU != 0) ? nm_sprintf_bufa(100, "mtu=%d\n", (int) ETH_MTU) : "",
                            s390_keyfile_entries));

        break;

    case 1:
        con = nmtst_create_minimal_connection(ID, UUID, "wireguard", &s_con);
        g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, INTERFACE_NAME, NULL);
        nmtst_connection_normalize(con);

        s_wg = NM_SETTING_WIREGUARD(nm_connection_get_setting(con, NM_TYPE_SETTING_WIREGUARD));

        s_ip.s_4 = NM_SETTING_IP_CONFIG(nm_connection_get_setting(con, NM_TYPE_SETTING_IP4_CONFIG));
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip.s_4), ==, "disabled");

        s_ip.s_6 = NM_SETTING_IP_CONFIG(nm_connection_get_setting(con, NM_TYPE_SETTING_IP6_CONFIG));
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip.s_6), ==, "disabled");

        g_ptr_array_add(kf_data_arr,
                        g_strdup_printf("[connection]\n"
                                        "id=%s\n"
                                        "uuid=%s\n"
                                        "type=wireguard\n"
                                        "interface-name=%s\n"
                                        "\n"
                                        "[wireguard]\n"
                                        "\n"
                                        "[ipv4]\n"
                                        "method=disabled\n"
                                        "\n"
                                        "[ipv6]\n"
                                        "addr-gen-mode=default\n"
                                        "method=disabled\n"
                                        "\n"
                                        "[proxy]\n"
                                        "",
                                        ID,
                                        UUID,
                                        INTERFACE_NAME));
        break;

    case 2:
        con = nmtst_create_minimal_connection(ID, UUID, "wireguard", &s_con);
        g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, INTERFACE_NAME, NULL);
        nmtst_connection_normalize(con);

        s_wg = NM_SETTING_WIREGUARD(nm_connection_get_setting(con, NM_TYPE_SETTING_WIREGUARD));
        g_object_set(s_wg,
                     NM_SETTING_WIREGUARD_PRIVATE_KEY,
                     WG_PRIVATE_KEY,
                     NM_SETTING_WIREGUARD_PRIVATE_KEY_FLAGS,
                     WG_PRIVATE_KEY_FLAGS,
                     NM_SETTING_WIREGUARD_LISTEN_PORT,
                     WG_LISTEN_PORT,
                     NM_SETTING_WIREGUARD_FWMARK,
                     WG_FWMARK,
                     NULL);

        wg_peers = _rndt_wg_peers_create();

        for (i = 0; i < wg_peers->len; i++)
            nm_setting_wireguard_append_peer(s_wg, wg_peers->pdata[i]);

        nm_clear_g_free(&tmp_str);

        g_ptr_array_add(
            kf_data_arr,
            g_strdup_printf(
                "[connection]\n"
                "id=%s\n"
                "uuid=%s\n"
                "type=wireguard\n"
                "interface-name=%s\n"
                "\n"
                "[wireguard]\n"
                "%s" /* fwmark */
                "%s" /* listen-port */
                "%s" /* private-key-flags */
                "%s" /* private-key */
                "%s" /* [wireguard-peers*] */
                "\n"
                "[ipv4]\n"
                "method=disabled\n"
                "\n"
                "[ipv6]\n"
                "addr-gen-mode=default\n"
                "method=disabled\n"
                "\n"
                "[proxy]\n"
                "",
                ID,
                UUID,
                INTERFACE_NAME,
                ((WG_FWMARK != 0) ? nm_sprintf_bufa(100, "fwmark=%u\n", WG_FWMARK) : ""),
                ((WG_LISTEN_PORT != 0) ? nm_sprintf_bufa(100, "listen-port=%u\n", WG_LISTEN_PORT)
                                       : ""),
                ((WG_PRIVATE_KEY_FLAGS != NM_SETTING_SECRET_FLAG_NONE)
                     ? nm_sprintf_bufa(100, "private-key-flags=%u\n", (guint) WG_PRIVATE_KEY_FLAGS)
                     : ""),
                ((WG_PRIVATE_KEY && WG_PRIVATE_KEY_FLAGS == NM_SETTING_SECRET_FLAG_NONE)
                     ? nm_sprintf_bufa(100, "private-key=%s\n", WG_PRIVATE_KEY)
                     : ""),
                _rndt_wg_peers_to_keyfile(wg_peers, TRUE, &tmp_str)));

        _rndt_wg_peers_assert_equal(s_wg, wg_peers, TRUE, TRUE, FALSE);
        break;

    case 3:
        con = nmtst_create_minimal_connection(ID, UUID, NM_SETTING_WIRED_SETTING_NAME, &s_con);
        g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, INTERFACE_NAME, NULL);
        nmtst_connection_normalize(con);

        s_eth = NM_SETTING_WIRED(nm_connection_get_setting(con, NM_TYPE_SETTING_WIRED));
        g_assert(NM_IS_SETTING_WIRED(s_eth));

        g_object_set(s_eth, NM_SETTING_WIRED_MTU, ETH_MTU, NULL);

        s_ip.s_4 = NM_SETTING_IP_CONFIG(nm_connection_get_setting(con, NM_TYPE_SETTING_IP4_CONFIG));
        g_assert(NM_IS_SETTING_IP4_CONFIG(s_ip.s_4));

        s_ip.s_6 = NM_SETTING_IP_CONFIG(nm_connection_get_setting(con, NM_TYPE_SETTING_IP6_CONFIG));
        g_assert(NM_IS_SETTING_IP6_CONFIG(s_ip.s_6));

        for (is_ipv4 = 0; is_ipv4 < 2; is_ipv4++) {
            g_assert(NM_IS_SETTING_IP_CONFIG(s_ip.s_x[is_ipv4]));
            for (i = 0; i < 3; i++) {
                char addrstr[NM_INET_ADDRSTRLEN];

                nm_auto_unref_ip_routing_rule NMIPRoutingRule *rr = NULL;

                rr = nm_ip_routing_rule_new(is_ipv4 ? AF_INET : AF_INET6);
                nm_ip_routing_rule_set_priority(rr, i + 1);
                if (i > 0) {
                    if (is_ipv4)
                        nm_sprintf_buf(addrstr, "192.168.%u.0", i);
                    else
                        nm_sprintf_buf(addrstr, "1:2:3:%x::", 10 + i);
                    nm_ip_routing_rule_set_from(rr, addrstr, is_ipv4 ? 24 + i : 64 + i);
                }
                nm_ip_routing_rule_set_table(rr, 1000 + i);

                success = nm_ip_routing_rule_validate(rr, &error);
                nmtst_assert_success(success, error);

                nm_setting_ip_config_add_routing_rule(s_ip.s_x[is_ipv4], rr);
            }
        }

        g_ptr_array_add(
            kf_data_arr,
            g_strdup_printf("[connection]\n"
                            "id=%s\n"
                            "uuid=%s\n"
                            "type=ethernet\n"
                            "interface-name=%s\n"
                            "\n"
                            "[ethernet]\n"
                            "%s" /* mtu */
                            "\n"
                            "[ipv4]\n"
                            "method=auto\n"
                            "routing-rule1=priority 1 from 0.0.0.0/0 table 1000\n"
                            "routing-rule2=priority 2 from 192.168.1.0/25 table 1001\n"
                            "routing-rule3=priority 3 from 192.168.2.0/26 table 1002\n"
                            "\n"
                            "[ipv6]\n"
                            "addr-gen-mode=default\n"
                            "method=auto\n"
                            "routing-rule1=priority 1 from ::/0 table 1000\n"
                            "routing-rule2=priority 2 from 1:2:3:b::/65 table 1001\n"
                            "routing-rule3=priority 3 from 1:2:3:c::/66 table 1002\n"
                            "\n"
                            "[proxy]\n"
                            "",
                            ID,
                            UUID,
                            INTERFACE_NAME,
                            (ETH_MTU != 0) ? nm_sprintf_bufa(100, "mtu=%u\n", ETH_MTU) : ""));

        break;

    default:
        g_assert_not_reached();
    }

    /* the first kf_data_arr entry is special: it is the exact result of what we expect
     * when converting @con to keyfile. Write @con to keyfile and compare the expected result
     * literally. */
    {
        nm_auto_unref_keyfile GKeyFile *kf = NULL;

        kf = nm_keyfile_write(con, NM_KEYFILE_HANDLER_FLAGS_NONE, NULL, NULL, &error);
        nmtst_assert_success(kf, error);

        /* the first kf_data_arr entry is special: it must be what the writer would
         * produce again. */
        nmtst_keyfile_assert_data(kf, kf_data_arr->pdata[0], -1);
    }

    /* check that reading any of kf_data_arr yields the same result that we expect. */
    for (kf_data_idx = 0; kf_data_idx < kf_data_arr->len; kf_data_idx++) {
        gs_unref_object NMConnection *con2   = NULL;
        NMSettingWireGuard           *s_wg2  = NULL;
        NMSettingWired               *s_eth2 = NULL;

        con2 = nmtst_create_connection_from_keyfile(kf_data_arr->pdata[kf_data_idx],
                                                    "/no/where/file.nmconnection");

        switch (MODE) {
        case 0:
            s_eth2 = NM_SETTING_WIRED(nm_connection_get_setting(con2, NM_TYPE_SETTING_WIRED));
            g_assert(NM_IS_SETTING_WIRED(s_eth2));

            if (ETH_MTU > (guint32) G_MAXINT && kf_data_idx == 1) {
                /* older versions wrote values > 2^21 as signed integers, but the reader would
                 * always reject such negative values for G_TYPE_UINT.
                 *
                 * The test case kf_data_idx #1 still writes the values in the old style.
                 * The behavior was fixed, but such values are still rejected as invalid.
                 *
                 * Patch the setting so that the comparison below succeeds are usual. */
                g_assert_cmpint(nm_setting_wired_get_mtu(s_eth2), ==, 0);
                g_object_set(s_eth2, NM_SETTING_WIRED_MTU, ETH_MTU, NULL);
            }

            g_assert_cmpint(nm_setting_wired_get_mtu(s_eth), ==, ETH_MTU);
            g_assert_cmpint(nm_setting_wired_get_mtu(s_eth2), ==, ETH_MTU);

            g_assert_cmpint(nm_setting_wired_get_num_s390_options(s_eth2),
                            ==,
                            nm_setting_wired_get_num_s390_options(s_eth));

            break;

        case 1:
            s_wg2 =
                NM_SETTING_WIREGUARD(nm_connection_get_setting(con2, NM_TYPE_SETTING_WIREGUARD));
            g_assert(NM_IS_SETTING_WIREGUARD(s_wg2));

            g_assert_cmpstr(nm_setting_wireguard_get_private_key(s_wg), ==, NULL);
            g_assert_cmpstr(nm_setting_wireguard_get_private_key(s_wg2), ==, NULL);
            break;

        case 2:
            s_wg2 =
                NM_SETTING_WIREGUARD(nm_connection_get_setting(con2, NM_TYPE_SETTING_WIREGUARD));
            g_assert(NM_IS_SETTING_WIREGUARD(s_wg2));

            /* the private key was lost due to the secret-flags. Patch it. */
            if (WG_PRIVATE_KEY_FLAGS != NM_SETTING_SECRET_FLAG_NONE) {
                g_assert_cmpstr(nm_setting_wireguard_get_private_key(s_wg2), ==, NULL);
                g_object_set(s_wg2, NM_SETTING_WIREGUARD_PRIVATE_KEY, WG_PRIVATE_KEY, NULL);
            }

            g_assert_cmpstr(nm_setting_wireguard_get_private_key(s_wg), ==, WG_PRIVATE_KEY);
            g_assert_cmpstr(nm_setting_wireguard_get_private_key(s_wg2), ==, WG_PRIVATE_KEY);

            _rndt_wg_peers_assert_equal(s_wg2, wg_peers, TRUE, FALSE, FALSE);
            _rndt_wg_peers_fix_secrets(s_wg2, wg_peers);
            _rndt_wg_peers_assert_equal(s_wg2, wg_peers, TRUE, TRUE, FALSE);
            break;
        }

        nmtst_assert_connection_equals(con, nmtst_get_rand_bool(), con2, nmtst_get_rand_bool());
    }

    for (dbus_serialization_flags_idx = 0;
         dbus_serialization_flags_idx < G_N_ELEMENTS(dbus_serialization_flags);
         dbus_serialization_flags_idx++) {
        NMConnectionSerializationFlags flag =
            dbus_serialization_flags[dbus_serialization_flags_idx];
        gs_unref_variant GVariant    *con_var = NULL;
        gs_unref_object NMConnection *con2    = NULL;
        NMSettingWireGuard           *s_wg2   = NULL;

        con_var = nm_connection_to_dbus(con, flag);
        g_assert(g_variant_is_of_type(con_var, NM_VARIANT_TYPE_CONNECTION));
        g_assert(g_variant_is_floating(con_var));
        g_variant_ref_sink(con_var);

        if (flag == NM_CONNECTION_SERIALIZE_ALL) {
            con2 = _connection_new_from_dbus_strict(con_var, TRUE);
            nmtst_assert_connection_equals(con, nmtst_get_rand_bool(), con2, nmtst_get_rand_bool());

            {
                nm_auto_unref_keyfile GKeyFile *kf = NULL;

                kf = nm_keyfile_write(con2, NM_KEYFILE_HANDLER_FLAGS_NONE, NULL, NULL, &error);
                nmtst_assert_success(kf, error);
                nmtst_keyfile_assert_data(kf, kf_data_arr->pdata[0], -1);
            }
        }

        switch (MODE) {
        case 2:
            if (flag == NM_CONNECTION_SERIALIZE_ALL) {
                s_wg2 = NM_SETTING_WIREGUARD(
                    nm_connection_get_setting(con2, NM_TYPE_SETTING_WIREGUARD));

                if (flag == NM_CONNECTION_SERIALIZE_ALL)
                    _rndt_wg_peers_assert_equal(s_wg2, wg_peers, TRUE, TRUE, FALSE);
                else if (flag == NM_CONNECTION_SERIALIZE_WITH_NON_SECRET)
                    _rndt_wg_peers_assert_equal(s_wg2, wg_peers, FALSE, FALSE, TRUE);
                else
                    g_assert_not_reached();
            }
            break;
        }
    }
}

/*****************************************************************************/

static NMIPRoutingRule *
_rr_from_str_get_impl(const char *str, const char *const *aliases)
{
    nm_auto_unref_ip_routing_rule NMIPRoutingRule *rr    = NULL;
    gs_free_error GError                          *error = NULL;
    gboolean                                       vbool;
    int                                            addr_family;
    int                                            i;
    NMIPRoutingRuleAsStringFlags                   to_string_flags;

    rr = nm_ip_routing_rule_from_string(str,
                                        NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE,
                                        NULL,
                                        &error);
    nmtst_assert_success(rr, error);

    addr_family = nm_ip_routing_rule_get_addr_family(rr);
    g_assert(NM_IN_SET(addr_family, AF_INET, AF_INET6));

    if (addr_family == AF_INET)
        to_string_flags = NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET;
    else
        to_string_flags = NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET6;

    for (i = 0; TRUE; i++) {
        nm_auto_unref_ip_routing_rule NMIPRoutingRule *rr2      = NULL;
        gs_free char                                  *str1     = NULL;
        gs_unref_variant GVariant                     *variant1 = NULL;
        const char                                    *cstr1;

        switch (i) {
        case 0:
            rr2 = nm_ip_routing_rule_ref(rr);
            break;

        case 1:
            rr2 = nm_ip_routing_rule_from_string(
                str,
                NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE
                    | (nmtst_get_rand_bool() ? to_string_flags
                                             : NM_IP_ROUTING_RULE_AS_STRING_FLAGS_NONE),
                NULL,
                &error);
            nmtst_assert_success(rr, error);
            break;

        case 2:
            str1 = nm_ip_routing_rule_to_string(
                rr,
                NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE
                    | (nmtst_get_rand_bool() ? to_string_flags
                                             : NM_IP_ROUTING_RULE_AS_STRING_FLAGS_NONE),
                NULL,
                &error);
            nmtst_assert_success(str1 && str1[0], error);

            g_assert_cmpstr(str, ==, str1);

            rr2 = nm_ip_routing_rule_from_string(
                str1,
                NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE
                    | (nmtst_get_rand_bool() ? to_string_flags
                                             : NM_IP_ROUTING_RULE_AS_STRING_FLAGS_NONE),
                NULL,
                &error);
            nmtst_assert_success(rr, error);
            break;

        case 3:
            variant1 = nm_ip_routing_rule_to_dbus(rr);
            g_assert(variant1);
            g_assert(g_variant_is_floating(variant1));
            g_assert(g_variant_is_of_type(variant1, G_VARIANT_TYPE_VARDICT));

            rr2 = nm_ip_routing_rule_from_dbus(variant1, TRUE, &error);
            nmtst_assert_success(rr, error);
            break;

        default:
            if (!aliases || !aliases[0])
                goto done;
            cstr1 = (aliases++)[0];
            rr2   = nm_ip_routing_rule_from_string(
                cstr1,
                NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE
                    | (nmtst_get_rand_bool() ? to_string_flags
                                               : NM_IP_ROUTING_RULE_AS_STRING_FLAGS_NONE),
                NULL,
                &error);
            nmtst_assert_success(rr, error);
            break;
        }

        g_assert(rr2);
        vbool = nm_ip_routing_rule_validate(rr, &error);
        nmtst_assert_success(vbool, error);
        vbool = nm_ip_routing_rule_validate(rr2, &error);
        nmtst_assert_success(vbool, error);

        g_assert_cmpint(nm_ip_routing_rule_cmp(rr, rr2), ==, 0);
        g_assert_cmpint(nm_ip_routing_rule_cmp(rr2, rr), ==, 0);
    }

done:
    return g_steal_pointer(&rr);
}
#define _rr_from_str_get(a, ...) _rr_from_str_get_impl(a, &(NM_MAKE_STRV(NULL, ##__VA_ARGS__))[1])

#define _rr_from_str(...)                                          \
    G_STMT_START                                                   \
    {                                                              \
        nm_auto_unref_ip_routing_rule NMIPRoutingRule *_rr = NULL; \
                                                                   \
        _rr = _rr_from_str_get(__VA_ARGS__);                       \
        g_assert(_rr);                                             \
    }                                                              \
    G_STMT_END

static void
test_routing_rule(gconstpointer test_data)
{
    nm_auto_unref_ip_routing_rule NMIPRoutingRule *rr1 = NULL;
    gboolean                                       success;
    char                                           ifname_buf[16];
    gs_free_error GError                          *error = NULL;

    _rr_from_str("priority 5 from 0.0.0.0 table 1", "  from 0.0.0.0  priority  5 lookup 1 ");
    _rr_from_str("priority 5 from 0.0.0.0/0 table 4");
    _rr_from_str("priority 5 to 0.0.0.0 table 6");
    _rr_from_str("priority 5 to 0.0.0.0 table 254", "priority 5 to 0.0.0.0/32");
    _rr_from_str("priority 5 from 1.2.3.4 table 15",
                 "priority 5 from 1.2.3.4/32 table  0xF ",
                 "priority 5 from 1.2.3.4/32 to 0.0.0.0/0 lookup 15 ");
    _rr_from_str("priority 5 from 1.2.3.4 to 0.0.0.0 table 8");
    _rr_from_str("priority 5 to a:b:c:: tos 0x16 table 25",
                 "priority 5 to a:b:c::/128 table 0x19 tos 16",
                 "priority 5 to a:b:c::/128 lookup 0x19 dsfield 16",
                 "priority 5 to a:b:c::/128 lookup 0x19 dsfield 16 fwmark 0/0x00",
                 "priority 5 to a:b:c:: from all lookup 0x19 dsfield 16 fwmark 0x0/0");
    _rr_from_str("priority 5 from :: fwmark 0 table 25",
                 "priority 5 from ::/128 to all table 0x19 fwmark 0/0xFFFFFFFF",
                 "priority 5 from :: to ::/0 table 0x19 fwmark 0x00/4294967295");
    _rr_from_str("priority 5 from :: iif aab table 25");
    _rr_from_str("priority 5 from :: iif aab oif er table 25",
                 "priority 5 from :: table 0x19 dev aab oif er");
    _rr_from_str("priority 5 from :: iif a\\\\303b table 25");
    _rr_from_str("priority 5 to 0.0.0.0 sport 10 table 6",
                 "priority 5 to 0.0.0.0 sport 10-10 table 6");
    _rr_from_str("priority 5 not to 0.0.0.0 dport 10-133 table 6",
                 "not priority 5 to 0.0.0.0 dport 10-133 table 6",
                 "not priority 5 not to 0.0.0.0 dport 10-133 table 6",
                 "priority 5 to 0.0.0.0 not dport 10-133 not table 6",
                 "priority 5 to 0.0.0.0 not dport 10-\\ 133 not table 6");
    _rr_from_str("priority 5 to 0.0.0.0 ipproto 10 sport 10 table 6");
    _rr_from_str("priority 5 to 0.0.0.0 type blackhole", "priority 5 to 0.0.0.0 blackhole");

    rr1 = _rr_from_str_get("priority 5 from :: iif aab table 25");
    g_assert_cmpstr(nm_ip_routing_rule_get_iifname(rr1), ==, "aab");
    success = nm_ip_routing_rule_get_xifname_bin(rr1, FALSE, ifname_buf);
    g_assert(!success);
    success = nm_ip_routing_rule_get_xifname_bin(rr1, TRUE, ifname_buf);
    g_assert_cmpstr(ifname_buf, ==, "aab");
    g_assert(success);
    nm_clear_pointer(&rr1, nm_ip_routing_rule_unref);

    rr1 = _rr_from_str_get("priority 5 from :: iif a\\\\303\\\\261xb table 254");
    g_assert_cmpstr(nm_ip_routing_rule_get_iifname(rr1), ==, "a\\303\\261xb");
    success = nm_ip_routing_rule_get_xifname_bin(rr1, FALSE, ifname_buf);
    g_assert(!success);
    success = nm_ip_routing_rule_get_xifname_bin(rr1, TRUE, ifname_buf);
    g_assert_cmpstr(ifname_buf, ==, "a\303\261xb");
    g_assert(success);
    nm_clear_pointer(&rr1, nm_ip_routing_rule_unref);

    rr1 = _rr_from_str_get("priority 5 from :: oif \\\\101=\\\\303\\\\261xb table 7");
    g_assert_cmpstr(nm_ip_routing_rule_get_oifname(rr1), ==, "\\101=\\303\\261xb");
    success = nm_ip_routing_rule_get_xifname_bin(rr1, FALSE, ifname_buf);
    g_assert_cmpstr(ifname_buf, ==, "A=\303\261xb");
    g_assert(success);
    success = nm_ip_routing_rule_get_xifname_bin(rr1, TRUE, ifname_buf);
    g_assert(!success);
    nm_clear_pointer(&rr1, nm_ip_routing_rule_unref);

    rr1 = _rr_from_str_get("priority 5 to 0.0.0.0 tos 0x10 table 7");
    g_assert_cmpstr(NULL, ==, nm_ip_routing_rule_get_from(rr1));
    g_assert(!nm_ip_routing_rule_get_from_bin(rr1));
    g_assert_cmpint(0, ==, nm_ip_routing_rule_get_from_len(rr1));
    g_assert_cmpstr("0.0.0.0", ==, nm_ip_routing_rule_get_to(rr1));
    g_assert(nm_ip_addr_is_null(AF_INET, nm_ip_routing_rule_get_to_bin(rr1)));
    g_assert_cmpint(32, ==, nm_ip_routing_rule_get_to_len(rr1));
    g_assert_cmpint(7, ==, nm_ip_routing_rule_get_table(rr1));
    g_assert_cmpint(0x10, ==, nm_ip_routing_rule_get_tos(rr1));
    nm_clear_pointer(&rr1, nm_ip_routing_rule_unref);

    rr1 = _rr_from_str_get("priority 5 from :: iif a\\\\303\\\\261,x;b table 254",
                           "priority 5 from :: iif a\\\\303\\\\261,x;b table 254");
    g_assert_cmpstr(nm_ip_routing_rule_get_iifname(rr1), ==, "a\\303\\261,x;b");
    success = nm_ip_routing_rule_get_xifname_bin(rr1, FALSE, ifname_buf);
    g_assert(!success);
    success = nm_ip_routing_rule_get_xifname_bin(rr1, TRUE, ifname_buf);
    g_assert_cmpstr(ifname_buf, ==, "a\303\261,x;b");
    g_assert(success);
    nm_clear_pointer(&rr1, nm_ip_routing_rule_unref);

    rr1 = nm_ip_routing_rule_from_string("priority   6 blackhole",
                                         NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET,
                                         NULL,
                                         &error);
    nmtst_assert_success(rr1, error);
    nm_clear_pointer(&rr1, nm_ip_routing_rule_unref);
    nm_clear_error(&error);

    rr1 = nm_ip_routing_rule_from_string("priority   6 bogus",
                                         NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET,
                                         NULL,
                                         &error);
    nmtst_assert_no_success(rr1, error);
    nm_clear_pointer(&rr1, nm_ip_routing_rule_unref);
    nm_clear_error(&error);
}

/*****************************************************************************/

static void
test_ranges(void)
{
    GError  *error = NULL;
    NMRange *r1;
    NMRange *r2;
    guint64  start;
    guint64  end;
    char    *str  = NULL;
    char    *str2 = NULL;

    r1 = nm_range_from_str("99", &error);
    nmtst_assert_success(r1, error);
    nm_range_get_range(r1, &start, &end);
    g_assert_cmpint(start, ==, 99);
    g_assert_cmpint(end, ==, 99);
    str = nm_range_to_str(r1);
    g_assert_cmpstr(str, ==, "99");
    nm_clear_g_free(&str);
    nm_range_unref(r1);

    r1 = nm_range_from_str("1000-2000", &error);
    nmtst_assert_success(r1, error);
    nm_range_get_range(r1, &start, &end);
    g_assert_cmpint(start, ==, 1000);
    g_assert_cmpint(end, ==, 2000);
    str = nm_range_to_str(r1);
    g_assert_cmpstr(str, ==, "1000-2000");
    nm_clear_g_free(&str);
    nm_range_unref(r1);

    r1 = nm_range_from_str("0", &error);
    nmtst_assert_success(r1, error);
    nm_range_unref(r1);

    r1 = nm_range_from_str("-1", &error);
    nmtst_assert_no_success(r1, error);
    g_clear_error(&error);

    r1 = nm_range_from_str("foobar", &error);
    nmtst_assert_no_success(r1, error);
    g_clear_error(&error);

    r1 = nm_range_from_str("200-100", &error);
    nmtst_assert_no_success(r1, error);
    g_clear_error(&error);

    r1 = nm_range_from_str("100-200", &error);
    nmtst_assert_success(r1, error);
    r2 = nm_range_from_str("100-200", &error);
    nmtst_assert_success(r2, error);
    g_assert_cmpint(nm_range_cmp(r1, r2), ==, 0);
    nm_range_unref(r1);
    nm_range_unref(r2);

    r1 = nm_range_from_str("100-200", &error);
    nmtst_assert_success(r1, error);
    r2 = nm_range_from_str("1", &error);
    nmtst_assert_success(r2, error);
    g_assert_cmpint(nm_range_cmp(r1, r2), ==, 1);
    nm_range_ref(r1);
    nm_range_unref(r1);
    nm_range_unref(r1);
    nm_range_unref(r2);

    r1 = nm_range_new(G_MAXUINT64 - 1, G_MAXUINT64);
    g_assert(r1);
    str = nm_range_to_str(r1);
    g_assert_cmpstr(str, ==, "18446744073709551614-18446744073709551615");
    r2 = nm_range_from_str(str, &error);
    nmtst_assert_success(r2, error);
    str2 = nm_range_to_str(r2);
    g_assert_cmpstr(str, ==, str2);
    g_assert_cmpint(nm_range_cmp(r1, r2), ==, 0);
    nm_range_unref(r1);
    nm_range_unref(r2);
    nm_clear_g_free(&str);
    nm_clear_g_free(&str2);
}

/*****************************************************************************/

static void
test_parse_tc_handle(void)
{
#define _parse_tc_handle(str, exp)                                              \
    G_STMT_START                                                                \
    {                                                                           \
        gs_free_error GError *_error  = NULL;                                   \
        GError              **_perror = nmtst_get_rand_bool() ? &_error : NULL; \
        guint32               _v;                                               \
        const guint32         _v_exp = (exp);                                   \
                                                                                \
        _v = _nm_utils_parse_tc_handle("" str "", _perror);                     \
                                                                                \
        if (_v != _v_exp)                                                       \
            g_error("%s:%d: \"%s\" gave %08x but %08x expected.",               \
                    __FILE__,                                                   \
                    __LINE__,                                                   \
                    "" str "",                                                  \
                    _v,                                                         \
                    _v_exp);                                                    \
                                                                                \
        if (_v == TC_H_UNSPEC)                                                  \
            g_assert(!_perror || *_perror);                                     \
        else                                                                    \
            g_assert(!_perror || !*_perror);                                    \
    }                                                                           \
    G_STMT_END

#define _parse_tc_handle_inval(str) _parse_tc_handle(str, TC_H_UNSPEC)
#define _parse_tc_handle_valid(str, maj, min) \
    _parse_tc_handle(str, TC_H_MAKE(((guint32) (maj)) << 16, ((guint16) (min))))

    _parse_tc_handle_inval("");
    _parse_tc_handle_inval(" ");
    _parse_tc_handle_inval(" \n");
    _parse_tc_handle_valid("1", 1, 0);
    _parse_tc_handle_valid(" 1 ", 1, 0);
    _parse_tc_handle_valid("1:", 1, 0);
    _parse_tc_handle_valid("1:  ", 1, 0);
    _parse_tc_handle_valid("1:0", 1, 0);
    _parse_tc_handle_valid("1   :0", 1, 0);
    _parse_tc_handle_valid("1   \t\n\f\r:0", 1, 0);
    _parse_tc_handle_inval("1   \t\n\f\r\v:0");
    _parse_tc_handle_valid(" 1 : 0  ", 1, 0);
    _parse_tc_handle_inval(" \t\v\n1: 0");
    _parse_tc_handle_valid("1:2", 1, 2);
    _parse_tc_handle_valid("01:02", 1, 2);
    _parse_tc_handle_inval("0x01:0x02");
    _parse_tc_handle_valid("  01:   02", 1, 2);
    _parse_tc_handle_valid("019:   020", 0x19, 0x20);
    _parse_tc_handle_valid("FFFF:   020", 0xFFFF, 0x20);
    _parse_tc_handle_valid("FfFF:   ffff", 0xFFFF, 0xFFFF);
    _parse_tc_handle_valid("FFFF", 0xFFFF, 0);
    _parse_tc_handle_inval("0xFFFF");
    _parse_tc_handle_inval("10000");
    _parse_tc_handle_valid("\t\n\f\r FFFF", 0xFFFF, 0);
    _parse_tc_handle_inval("\t\n\f\r \vFFFF");
}

/*****************************************************************************/

static void
test_empty_setting(void)
{
    gs_unref_object NMConnection   *con  = NULL;
    gs_unref_object NMConnection   *con2 = NULL;
    NMSettingBluetooth             *s_bt;
    NMSettingGsm                   *s_gsm;
    nm_auto_unref_keyfile GKeyFile *kf    = NULL;
    gs_free_error GError           *error = NULL;

    con = nmtst_create_minimal_connection("bt-empty-gsm",
                                          "dca3192a-f2dc-48eb-b806-d0ff788f122c",
                                          NM_SETTING_BLUETOOTH_SETTING_NAME,
                                          NULL);

    s_bt = _nm_connection_get_setting(con, NM_TYPE_SETTING_BLUETOOTH);
    g_object_set(s_bt,
                 NM_SETTING_BLUETOOTH_TYPE,
                 "dun",
                 NM_SETTING_BLUETOOTH_BDADDR,
                 "aa:bb:cc:dd:ee:ff",
                 NULL);

    s_gsm = NM_SETTING_GSM(nm_setting_gsm_new());
    nm_connection_add_setting(con, NM_SETTING(s_gsm));

    nmtst_connection_normalize(con);

    nmtst_assert_connection_verifies_without_normalization(con);

    kf = nm_keyfile_write(con, NM_KEYFILE_HANDLER_FLAGS_NONE, NULL, NULL, &error);
    nmtst_assert_success(kf, error);

    g_assert(g_key_file_has_group(kf, "gsm"));
    g_assert_cmpint(nmtst_keyfile_get_num_keys(kf, "gsm"), ==, 0);

    con2 = nm_keyfile_read(kf,
                           "/ignored/current/working/directory/for/loading/relative/paths",
                           NM_KEYFILE_HANDLER_FLAGS_NONE,
                           NULL,
                           NULL,
                           &error);
    nmtst_assert_success(con2, error);

    g_assert(nm_connection_get_setting(con2, NM_TYPE_SETTING_GSM));

    nmtst_assert_connection_verifies_without_normalization(con2);
}

/*****************************************************************************/

static guint
_PROP_IDX_PACK(NMMetaSettingType meta_type, guint idx)
{
    return (((guint) meta_type) & 0xFFu) | (idx << 8);
}

static const char *
_PROP_IDX_OWNER(GHashTable *h_property_types, const NMSettInfoPropertType *property_type)
{
    const NMSettInfoSetting *sett_info_settings = nmtst_sett_info_settings();
    const NMSettInfoSetting *sis;
    const NMMetaSettingInfo *msi;
    GArray                  *arr;
    guint                    idx;
    NMMetaSettingType        meta_type;
    guint                    prop_idx;
    char                     sbuf[300];

    g_assert(h_property_types);
    g_assert(property_type);

    arr = g_hash_table_lookup(h_property_types, property_type);

    g_assert(arr);
    g_assert(arr->len > 0);

    idx = nm_g_array_first(arr, guint);

    meta_type = (idx & 0xFFu);
    prop_idx  = idx >> 8;

    g_assert(meta_type < _NM_META_SETTING_TYPE_NUM);

    sis = &sett_info_settings[meta_type];
    msi = &nm_meta_setting_infos[meta_type];

    g_assert(prop_idx < sis->property_infos_len);

    nm_sprintf_buf(sbuf, "%s.%s", msi->setting_name, sis->property_infos[prop_idx].name);

    return g_intern_string(sbuf);
}

static void
test_setting_metadata(void)
{
    const NMSettInfoSetting       *sett_info_settings = nmtst_sett_info_settings();
    NMMetaSettingType              meta_type;
    gs_unref_hashtable GHashTable *h_property_types = NULL;

    G_STATIC_ASSERT(_NM_META_SETTING_TYPE_NUM == NM_META_SETTING_TYPE_UNKNOWN);

    h_property_types =
        g_hash_table_new_full(nm_direct_hash, NULL, NULL, (GDestroyNotify) g_array_unref);

    for (meta_type = 0; meta_type < _NM_META_SETTING_TYPE_NUM; meta_type++) {
        const NMMetaSettingInfo                 *msi   = &nm_meta_setting_infos[meta_type];
        nm_auto_unref_gtypeclass NMSettingClass *klass = NULL;
        GType                                    gtype;

        g_assert(msi->setting_name);
        g_assert(msi->get_setting_gtype);
        g_assert(msi->meta_type == meta_type);
        g_assert(msi->setting_priority >= NM_SETTING_PRIORITY_CONNECTION);
        g_assert(msi->setting_priority <= NM_SETTING_PRIORITY_USER);

        if (meta_type > 0)
            g_assert_cmpint(
                strcmp(nm_meta_setting_infos[meta_type - 1].setting_name, msi->setting_name),
                <,
                0);

        gtype = msi->get_setting_gtype();

        g_assert(g_type_is_a(gtype, NM_TYPE_SETTING));
        g_assert(gtype != NM_TYPE_SETTING);

        klass = g_type_class_ref(gtype);
        g_assert(klass);
        g_assert(NM_IS_SETTING_CLASS(klass));

        g_assert(msi == klass->setting_info);
    }

    g_assert(sett_info_settings);

    for (meta_type = 0; meta_type < _NM_META_SETTING_TYPE_NUM; meta_type++) {
        const NMSettInfoSetting       *sis          = &sett_info_settings[meta_type];
        const NMMetaSettingInfo       *msi          = &nm_meta_setting_infos[meta_type];
        gs_unref_hashtable GHashTable *h_properties = NULL;
        GType                          gtype;
        gs_unref_object NMSetting     *setting = NULL;
        guint                          prop_idx;
        gs_free GParamSpec           **property_specs = NULL;
        guint                          n_property_specs;
        guint                          n_param_spec;
        guint                          i;
        guint                          j;

        g_assert(sis);

        g_assert(NM_IS_SETTING_CLASS(sis->setting_class));

        gtype = msi->get_setting_gtype();

        g_assert(G_TYPE_FROM_CLASS(sis->setting_class) == gtype);

        setting = g_object_new(gtype, NULL);

        g_assert(NM_IS_SETTING(setting));

        g_assert_cmpint(sis->property_infos_len, >, 0);
        g_assert(sis->property_infos);

        {
            int offset;

            if (sis->private_offset < 0) {
                offset = g_type_class_get_instance_private_offset(sis->setting_class);
                g_assert_cmpint(sis->private_offset, ==, offset);
            } else {
                /* it would be nice to assert that this class has no private data.
                 * But we cannot. */
            }
        }

        h_properties = g_hash_table_new(nm_str_hash, g_str_equal);

        n_param_spec = 0;

        for (prop_idx = 0; prop_idx < sis->property_infos_len; prop_idx++) {
            const NMSettInfoProperty *sip = &sis->property_infos[prop_idx];
            GArray                   *property_types_data;
            guint                     prop_idx_val;
            gboolean                  can_set_including_default = FALSE;
            gboolean                  can_have_direct_data      = FALSE;
            int                       n_special_options;

            g_assert(sip->name);

            if (sip->param_spec)
                n_param_spec++;

            if (prop_idx > 0)
                g_assert_cmpint(strcmp(sis->property_infos[prop_idx - 1].name, sip->name), <, 0);

            g_assert(sip->property_type);
            g_assert(sip->property_type->dbus_type);
            g_assert(g_variant_type_string_is_valid((const char *) sip->property_type->dbus_type));

            if (sip->property_type->direct_type == NM_VALUE_TYPE_NONE) {
                g_assert_cmpint(sip->direct_offset, ==, 0);
            } else if (sip->property_type->direct_type == NM_VALUE_TYPE_BOOL) {
                g_assert(sip->property_type == &nm_sett_info_propert_type_direct_boolean);
                g_assert(g_variant_type_equal(sip->property_type->dbus_type, "b"));
                g_assert(sip->property_type->to_dbus_fcn
                         == _nm_setting_property_to_dbus_fcn_direct);
                g_assert(sip->param_spec);
                g_assert(sip->param_spec->value_type == G_TYPE_BOOLEAN);
                can_set_including_default = TRUE;
            } else if (sip->property_type->direct_type == NM_VALUE_TYPE_INT32) {
                const GParamSpecInt *pspec;

                g_assert(sip->property_type == &nm_sett_info_propert_type_direct_int32);
                g_assert(g_variant_type_equal(sip->property_type->dbus_type, "i"));
                g_assert(sip->property_type->to_dbus_fcn
                         == _nm_setting_property_to_dbus_fcn_direct);
                g_assert(sip->param_spec);
                g_assert(sip->param_spec->value_type == G_TYPE_INT);

                pspec = NM_G_PARAM_SPEC_CAST_INT(sip->param_spec);
                g_assert_cmpint(pspec->minimum, <=, pspec->maximum);
                g_assert_cmpint(pspec->default_value, >=, pspec->minimum);
                g_assert_cmpint(pspec->default_value, <=, pspec->maximum);

                g_assert_cmpint(pspec->minimum, >=, (gint64) G_MININT32);
                g_assert_cmpint(pspec->maximum, <=, (gint64) G_MAXINT32);

                can_set_including_default = TRUE;
            } else if (sip->property_type->direct_type == NM_VALUE_TYPE_UINT32) {
                const GParamSpecUInt *pspec;

                g_assert(sip->property_type == &nm_sett_info_propert_type_direct_uint32);
                g_assert(g_variant_type_equal(sip->property_type->dbus_type, "u"));
                g_assert(sip->property_type->to_dbus_fcn
                         == _nm_setting_property_to_dbus_fcn_direct);
                g_assert(sip->param_spec);
                g_assert(sip->param_spec->value_type == G_TYPE_UINT);

                pspec = NM_G_PARAM_SPEC_CAST_UINT(sip->param_spec);
                g_assert_cmpint(pspec->minimum, <=, pspec->maximum);
                g_assert_cmpint(pspec->default_value, >=, pspec->minimum);
                g_assert_cmpint(pspec->default_value, <=, pspec->maximum);

                g_assert_cmpint(pspec->maximum, <=, (guint64) G_MAXUINT32);

                can_set_including_default = TRUE;
            } else if (sip->property_type->direct_type == NM_VALUE_TYPE_INT64) {
                const GParamSpecInt64 *pspec;

                g_assert(sip->property_type == &nm_sett_info_propert_type_direct_int64);
                g_assert(g_variant_type_equal(sip->property_type->dbus_type, "x"));
                g_assert(sip->property_type->to_dbus_fcn
                         == _nm_setting_property_to_dbus_fcn_direct);
                g_assert(sip->param_spec);
                g_assert(sip->param_spec->value_type == G_TYPE_INT64);

                pspec = NM_G_PARAM_SPEC_CAST_INT64(sip->param_spec);
                g_assert_cmpint(pspec->minimum, <=, pspec->maximum);
                g_assert_cmpint(pspec->default_value, >=, pspec->minimum);
                g_assert_cmpint(pspec->default_value, <=, pspec->maximum);

                can_set_including_default = TRUE;
            } else if (sip->property_type->direct_type == NM_VALUE_TYPE_UINT64) {
                const GParamSpecUInt64 *pspec;

                g_assert(sip->property_type == &nm_sett_info_propert_type_direct_uint64);
                g_assert(g_variant_type_equal(sip->property_type->dbus_type, "t"));
                g_assert(sip->property_type->to_dbus_fcn
                         == _nm_setting_property_to_dbus_fcn_direct);
                g_assert(sip->param_spec);
                g_assert(sip->param_spec->value_type == G_TYPE_UINT64);

                pspec = NM_G_PARAM_SPEC_CAST_UINT64(sip->param_spec);
                g_assert_cmpuint(pspec->minimum, <=, pspec->maximum);
                g_assert_cmpuint(pspec->default_value, >=, pspec->minimum);
                g_assert_cmpuint(pspec->default_value, <=, pspec->maximum);

                g_assert_cmpuint(pspec->maximum, <=, G_MAXUINT64);

                can_set_including_default = TRUE;
            } else if (sip->property_type->direct_type == NM_VALUE_TYPE_ENUM) {
                nm_auto_unref_gtypeclass GEnumClass *enum_class = NULL;
                int                                  default_value;

                g_assert(_nm_setting_property_is_valid_direct_enum(sip));
                g_assert(G_TYPE_IS_ENUM(sip->direct_data.enum_gtype));
                g_assert(g_variant_type_equal(sip->property_type->dbus_type, "i"));
                g_assert(sip->param_spec);

                if (G_TYPE_IS_ENUM(sip->param_spec->value_type)) {
                    const GParamSpecEnum *pspec = NM_G_PARAM_SPEC_CAST_ENUM(sip->param_spec);

                    g_assert(sip->param_spec->value_type != G_TYPE_ENUM);
                    g_assert(G_TYPE_FROM_CLASS(pspec->enum_class) == sip->param_spec->value_type);
                    g_assert(sip->param_spec->value_type == sip->direct_data.enum_gtype);

                    default_value = pspec->default_value;
                } else if (sip->param_spec->value_type == G_TYPE_INT) {
                    const GParamSpecInt *pspec = NM_G_PARAM_SPEC_CAST_INT(sip->param_spec);

                    default_value = pspec->default_value;
                } else {
                    g_assert_not_reached();
                }

                enum_class = g_type_class_ref(sip->direct_data.enum_gtype);
                g_assert(g_enum_get_value(enum_class, default_value));

                can_set_including_default = TRUE;
                can_have_direct_data      = TRUE;
            } else if (sip->property_type->direct_type == NM_VALUE_TYPE_FLAGS) {
                const GParamSpecFlags *pspec;

                g_assert(sip->property_type == &nm_sett_info_propert_type_direct_flags);
                g_assert(g_variant_type_equal(sip->property_type->dbus_type, "u"));
                g_assert(sip->property_type->to_dbus_fcn
                         == _nm_setting_property_to_dbus_fcn_direct);
                g_assert(sip->param_spec);
                g_assert(g_type_is_a(sip->param_spec->value_type, G_TYPE_FLAGS));
                g_assert(sip->param_spec->value_type != G_TYPE_FLAGS);

                pspec = NM_G_PARAM_SPEC_CAST_FLAGS(sip->param_spec);
                g_assert_cmpint(pspec->flags_class->mask, !=, 0);
                g_assert_cmpint(pspec->default_value,
                                ==,
                                pspec->flags_class->mask & pspec->default_value);

                can_set_including_default = TRUE;
            } else if (sip->property_type->direct_type == NM_VALUE_TYPE_STRING) {
                if (sip->property_type == &nm_sett_info_propert_type_direct_mac_address) {
                    g_assert(g_variant_type_equal(sip->property_type->dbus_type, "ay"));
                    g_assert(sip->property_type->to_dbus_fcn
                             == _nm_setting_property_to_dbus_fcn_direct_mac_address);
                    g_assert(NM_IN_SET((guint) sip->direct_set_string_mac_address_len,
                                       ETH_ALEN,
                                       8,
                                       INFINIBAND_ALEN));
                } else {
                    g_assert(g_variant_type_equal(sip->property_type->dbus_type, "s"));
                    can_have_direct_data = TRUE;
                }
                g_assert(sip->param_spec);
                g_assert(sip->param_spec->value_type == G_TYPE_STRING);
            } else if (sip->property_type->direct_type == NM_VALUE_TYPE_BYTES) {
                g_assert(g_variant_type_equal(sip->property_type->dbus_type, "ay"));
                g_assert(sip->property_type->to_dbus_fcn
                         == _nm_setting_property_to_dbus_fcn_direct);
                g_assert(sip->param_spec);
                g_assert(sip->param_spec->value_type == G_TYPE_BYTES);
            } else if (sip->property_type->direct_type == NM_VALUE_TYPE_STRV) {
                g_assert(g_variant_type_equal(sip->property_type->dbus_type, "as"));
                g_assert(NM_IN_SET(sip->property_type->to_dbus_fcn,
                                   _nm_setting_property_to_dbus_fcn_direct,
                                   _nm_setting_wireless_mac_denylist_to_dbus,
                                   _nm_setting_wired_mac_denylist_to_dbus));
                g_assert(sip->param_spec);
                g_assert(sip->param_spec->value_type == G_TYPE_STRV);
            } else
                g_assert_not_reached();

            if (sip->direct_set_string_ascii_strdown)
                g_assert(sip->property_type->direct_type == NM_VALUE_TYPE_STRING);
            if (sip->direct_set_string_strip)
                g_assert(sip->property_type->direct_type == NM_VALUE_TYPE_STRING);
            if (sip->direct_string_is_refstr) {
                g_assert(sip->property_type->direct_type == NM_VALUE_TYPE_STRING);
                g_assert(sip->param_spec);
                g_assert(!NM_FLAGS_HAS(sip->param_spec->flags, NM_SETTING_PARAM_SECRET));
            }
            if (sip->direct_strv_preserve_empty)
                g_assert(sip->property_type->direct_type == NM_VALUE_TYPE_STRV);
            if (sip->direct_string_allow_empty) {
                g_assert(sip->property_type->direct_type == NM_VALUE_TYPE_STRING);
            }

            if (sip->direct_set_string_mac_address_len != 0) {
                g_assert(NM_IN_SET(sip->property_type,
                                   &nm_sett_info_propert_type_direct_string,
                                   &nm_sett_info_propert_type_direct_mac_address));
                g_assert(sip->property_type->direct_type == NM_VALUE_TYPE_STRING);
            }

            if (!can_have_direct_data)
                g_assert(!sip->direct_data.set_string);

            if (sip->property_type->direct_type == NM_VALUE_TYPE_NONE)
                g_assert(!sip->direct_also_notify);
            else {
                if (sip->direct_also_notify) {
                    guint prop_idx2;
                    guint cnt = 0;

                    for (prop_idx2 = 0; prop_idx2 < sis->property_infos_len; prop_idx2++) {
                        const NMSettInfoProperty *sip2 = &sis->property_infos[prop_idx2];

                        if (sip2->param_spec == sip->direct_also_notify)
                            cnt++;
                    }
                    g_assert_cmpint(cnt, ==, 1u);
                    g_assert(sip->param_spec != sip->direct_also_notify);
                }
            }

            n_special_options = (sip->direct_set_string_mac_address_len != 0)
                                + (!!sip->direct_set_string_strip)
                                + (!!sip->direct_set_string_ascii_strdown)
                                + (sip->direct_set_string_ip_address_addr_family != 0)
                                + (!!sip->direct_string_is_refstr);

            G_STATIC_ASSERT_EXPR(AF_UNSPEC + 1 != 0);
            g_assert(NM_IN_SET((int) sip->direct_set_string_ip_address_addr_family,
                               0,
                               AF_UNSPEC + 1,
                               AF_INET + 1,
                               AF_INET6 + 1));

            if (sip->direct_set_string_ip_address_addr_family == 0)
                g_assert(!sip->direct_set_string_ip_address_addr_family_map_zero_to_null);

            /* currently, we have no cases where special options are mixed. There is no problem to support
             * that, but as it's not needed, don't do it for now. */
            g_assert_cmpint(n_special_options, <=, 1);

            if (n_special_options > 0) {
                /* currently, special options are only relevant for string properties. */
                g_assert(sip->property_type->direct_type == NM_VALUE_TYPE_STRING);
            }

            if (sip->param_spec && NM_FLAGS_HAS(sip->param_spec->flags, NM_SETTING_PARAM_SECRET)) {
                /* Currently, special options are not supported for secrets. */
                g_assert_cmpint(n_special_options, ==, 0);
            }

            if (!sip->property_type->to_dbus_fcn) {
                /* it's allowed to have no to_dbus_fcn(), to ignore a property. But such
                 * properties must not have a param_spec. */
                g_assert(!sip->param_spec);
            } else if (sip->property_type->to_dbus_fcn == _nm_setting_property_to_dbus_fcn_gprop) {
                g_assert(sip->param_spec);
                switch (sip->property_type->typdata_to_dbus.gprop_type) {
                case NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_GARRAY_UINT:
                    g_assert(sip->param_spec->value_type == G_TYPE_ARRAY);
                    goto check_done;
                case NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_STRDICT:
                    g_assert(sip->param_spec->value_type == G_TYPE_HASH_TABLE);
                    goto check_done;
                case NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_DEFAULT:
                    goto check_done;
                }
                g_assert_not_reached();
check_done:;
                can_set_including_default = TRUE;
            }

            if (!can_set_including_default)
                g_assert(!sip->to_dbus_including_default);

            g_assert(sip->property_type->from_dbus_fcn || !sip->param_spec);
            if (sip->property_type->typdata_from_dbus.gprop_fcn) {
                g_assert(sip->property_type->from_dbus_fcn
                         == _nm_setting_property_from_dbus_fcn_gprop);
            }
            if (sip->property_type->from_dbus_direct_allow_transform) {
                g_assert(sip->property_type->from_dbus_fcn
                         == _nm_setting_property_from_dbus_fcn_direct);
            }
            if (sip->property_type->from_dbus_fcn == _nm_setting_property_from_dbus_fcn_direct) {
                /* for the moment, all direct properties allow transformation. */
                if (NM_IN_SET(sip->property_type->direct_type,
                              NM_VALUE_TYPE_BYTES,
                              NM_VALUE_TYPE_STRV))
                    g_assert(!sip->property_type->from_dbus_direct_allow_transform);
                else
                    g_assert(sip->property_type->from_dbus_direct_allow_transform);
            }

            if (sip->property_type->from_dbus_fcn == _nm_setting_property_from_dbus_fcn_gprop)
                g_assert(sip->param_spec);

            g_assert(sip->property_type->from_dbus_is_full
                     == NM_IN_SET(sip->property_type->from_dbus_fcn,
                                  _nm_setting_property_from_dbus_fcn_direct,
                                  _nm_setting_property_from_dbus_fcn_gprop,
                                  _nm_setting_property_from_dbus_fcn_ignore));

            if (!g_hash_table_insert(h_properties, (char *) sip->name, sip->param_spec))
                g_assert_not_reached();

            if (sip->property_type->compare_fcn == _nm_setting_property_compare_fcn_default) {
                g_assert(sip->param_spec);
                g_assert_cmpstr(sip->name, !=, NM_SETTING_NAME);
            } else if (sip->property_type->compare_fcn == _nm_setting_property_compare_fcn_direct) {
                g_assert(sip->param_spec);
                g_assert(sip->property_type->direct_type != NM_VALUE_TYPE_NONE);
            } else if (sip->property_type->compare_fcn == _nm_setting_property_compare_fcn_ignore) {
                if (NM_IN_SET(sip->property_type,
                              &nm_sett_info_propert_type_deprecated_ignore_i,
                              &nm_sett_info_propert_type_deprecated_ignore_u,
                              &nm_sett_info_propert_type_assigned_mac_address)) {
                    /* pass */
                } else if (!sip->param_spec) {
                    /* pass */
                } else if (nm_streq(sip->name, NM_SETTING_NAME)) {
                    /* pass */
                } else {
                    /* ignoring a property for comparison make only sense in very specific cases. */
                    g_assert_not_reached();
                }
            } else if (sip->property_type->compare_fcn) {
                /* pass */
            } else {
                g_assert_not_reached();
            }
            g_assert((sip->property_type->compare_fcn != _nm_setting_property_compare_fcn_direct)
                     || (sip->property_type->direct_type != NM_VALUE_TYPE_NONE));

            property_types_data = g_hash_table_lookup(h_property_types, sip->property_type);
            if (!property_types_data) {
                property_types_data = g_array_new(FALSE, FALSE, sizeof(guint));
                if (!g_hash_table_insert(h_property_types,
                                         (gpointer) sip->property_type,
                                         property_types_data))
                    g_assert_not_reached();
            }
            prop_idx_val = _PROP_IDX_PACK(meta_type, prop_idx);
            g_array_append_val(property_types_data, prop_idx_val);

            if (sip->param_spec) {
                /* All "direct" properties use G_PARAM_EXPLICIT_NOTIFY.
                 *
                 * Warning: this is potentially dangerous, because implementations MUST remember
                 * to notify the property change in set_property(). Optimally, the property uses
                 * _nm_setting_property_set_property_direct(), which takes care of that.
                 */
                if (sip->property_type->direct_type != NM_VALUE_TYPE_NONE)
                    g_assert(NM_FLAGS_HAS(sip->param_spec->flags, G_PARAM_EXPLICIT_NOTIFY));
            }

            if (sip->param_spec) {
                nm_auto_unset_gvalue GValue val = G_VALUE_INIT;

                g_assert_cmpstr(sip->name, ==, sip->param_spec->name);

                g_assert(NM_FLAGS_HAS(sip->param_spec->flags, G_PARAM_WRITABLE)
                         != nm_streq(sip->name, NM_SETTING_NAME));
                g_assert((sip->property_type == &nm_sett_info_propert_type_setting_name)
                         == nm_streq(sip->name, NM_SETTING_NAME));

                g_value_init(&val, sip->param_spec->value_type);
                g_object_get_property(G_OBJECT(setting), sip->name, &val);

                if (sip->param_spec->value_type == G_TYPE_STRING) {
                    /* String properties should all have a default value of NULL. Otherwise,
                     * it's ugly. */
                    g_assert_cmpstr(((const GParamSpecString *) sip->param_spec)->default_value,
                                    ==,
                                    NULL);
                    g_assert(!NM_G_PARAM_SPEC_GET_DEFAULT_STRING(sip->param_spec));

                    if (nm_streq(sip->name, NM_SETTING_NAME)) {
                        g_assert_cmpstr(g_value_get_string(&val), ==, msi->setting_name);
                        g_assert(sip->property_type == &nm_sett_info_propert_type_setting_name);
                    } else
                        g_assert_cmpstr(g_value_get_string(&val), ==, NULL);
                }

                if (NM_FLAGS_HAS(sip->param_spec->flags, NM_SETTING_PARAM_TO_DBUS_IGNORE_FLAGS))
                    g_assert(sip->property_type->to_dbus_fcn);

                g_assert(!NM_FLAGS_HAS(sip->param_spec->flags, G_PARAM_CONSTRUCT));
                g_assert(!NM_FLAGS_HAS(sip->param_spec->flags, G_PARAM_CONSTRUCT_ONLY));

                if (NM_FLAGS_HAS(sip->param_spec->flags, NM_SETTING_PARAM_SECRET)) {
                    if (sip->param_spec->value_type == G_TYPE_STRING) {
                        g_assert_cmpstr(NM_G_PARAM_SPEC_GET_DEFAULT_STRING(sip->param_spec),
                                        ==,
                                        NULL);
                    } else if (sip->param_spec->value_type == G_TYPE_BYTES) {
                        /* pass */
                    } else if (sip->param_spec->value_type == G_TYPE_HASH_TABLE) {
                        g_assert(NM_IS_SETTING_VPN(setting));
                        g_assert_cmpstr(sip->name, ==, NM_SETTING_VPN_SECRETS);
                    } else {
                        NM_PRAGMA_WARNING_DISABLE_DANGLING_POINTER
                        g_error("secret %s.%s is of unexpected property type %s",
                                nm_setting_get_name(setting),
                                sip->name,
                                g_type_name(sip->param_spec->value_type));
                        NM_PRAGMA_WARNING_REENABLE
                    }
                }
            }
        }

        /* check that all GObject based properties are tracked by the settings. */
        property_specs =
            g_object_class_list_properties(G_OBJECT_CLASS(sis->setting_class), &n_property_specs);
        g_assert(property_specs);
        g_assert_cmpint(n_property_specs, >, 0);
        for (prop_idx = 0; prop_idx < n_property_specs; prop_idx++) {
            const GParamSpec *pip = property_specs[prop_idx];

            g_assert(g_hash_table_lookup(h_properties, pip->name) == pip);
        }

        /* check that property_infos_sorted is as expected. */
        if (sis->property_infos_sorted) {
            gs_unref_hashtable GHashTable *h = g_hash_table_new(nm_direct_hash, NULL);

            /* property_infos_sorted is only implemented for [connection] type */
            g_assert_cmpint(meta_type, ==, NM_META_SETTING_TYPE_CONNECTION);

            /* ensure that there are no duplicates, and that all properties are also
             * tracked by sis->property_infos. */
            for (prop_idx = 0; prop_idx < sis->property_infos_len; prop_idx++) {
                const NMSettInfoProperty *sip = sis->property_infos_sorted[prop_idx];

                if (!g_hash_table_add(h, (gpointer) sip))
                    g_assert_not_reached();
            }
            for (prop_idx = 0; prop_idx < sis->property_infos_len; prop_idx++) {
                const NMSettInfoProperty *sip = &sis->property_infos[prop_idx];

                g_assert(g_hash_table_contains(h, sip));
            }
        } else
            g_assert_cmpint(meta_type, !=, NM_META_SETTING_TYPE_CONNECTION);

        /* consistency check for gendata-info. */
        if (sis->detail.gendata_info) {
            g_assert_cmpint(meta_type, ==, NM_META_SETTING_TYPE_ETHTOOL);
            g_assert(sis->detail.gendata_info->get_variant_type);

            /* the gendata info based setting has only one regular property: the "name". */
            g_assert_cmpint(sis->property_infos_len, ==, 1);
            g_assert_cmpstr(sis->property_infos[0].name, ==, NM_SETTING_NAME);
        } else
            g_assert_cmpint(meta_type, !=, NM_META_SETTING_TYPE_ETHTOOL);

        g_assert_cmpint(n_param_spec, >, 0);
        g_assert_cmpint(n_param_spec, ==, sis->property_lookup_by_param_spec_len);
        g_assert(sis->property_lookup_by_param_spec);
        for (i = 0; i < sis->property_lookup_by_param_spec_len; i++) {
            const NMSettInfoPropertLookupByParamSpec *p = &sis->property_lookup_by_param_spec[i];
            guint                                     n_found;

            if (i > 0) {
                g_assert_cmpint(sis->property_lookup_by_param_spec[i - 1].param_spec_as_uint,
                                <,
                                p->param_spec_as_uint);
            }
            g_assert(p->property_info);
            g_assert(p->property_info >= sis->property_infos);
            g_assert(p->property_info < &sis->property_infos[sis->property_infos_len]);
            g_assert(p->property_info
                     == &sis->property_infos[p->property_info - sis->property_infos]);

            g_assert(p->property_info->param_spec);
            g_assert(p->param_spec_as_uint
                     == ((uintptr_t) ((gpointer) p->property_info->param_spec)));

            g_assert(_nm_sett_info_property_lookup_by_param_spec(sis, p->property_info->param_spec)
                     == p->property_info);

            n_found = 0;
            for (j = 0; j < sis->property_infos_len; j++) {
                const NMSettInfoProperty *pip2 = &sis->property_infos[j];

                if (pip2->param_spec
                    && p->param_spec_as_uint == ((uintptr_t) ((gpointer) pip2->param_spec))) {
                    g_assert(pip2 == p->property_info);
                    n_found++;
                }
            }
            g_assert(n_found == 1);
        }
    }

    {
        gs_free NMSettInfoPropertType **a_property_types = NULL;
        guint                           a_property_types_len;
        guint                           prop_idx;
        guint                           prop_idx_2;

        a_property_types =
            (NMSettInfoPropertType **) g_hash_table_get_keys_as_array(h_property_types,
                                                                      &a_property_types_len);

        for (prop_idx = 0; prop_idx < a_property_types_len; prop_idx++) {
            const NMSettInfoPropertType *pt = a_property_types[prop_idx];

            for (prop_idx_2 = prop_idx + 1; prop_idx_2 < a_property_types_len; prop_idx_2++) {
                const NMSettInfoPropertType *pt_2 = a_property_types[prop_idx_2];

                if (!g_variant_type_equal(pt->dbus_type, pt_2->dbus_type)
                    || pt->direct_type != pt_2->direct_type || pt->to_dbus_fcn != pt_2->to_dbus_fcn
                    || pt->from_dbus_fcn != pt_2->from_dbus_fcn
                    || pt->compare_fcn != pt_2->compare_fcn
                    || pt->missing_from_dbus_fcn != pt_2->missing_from_dbus_fcn
                    || memcmp(&pt->typdata_from_dbus,
                              &pt_2->typdata_from_dbus,
                              sizeof(pt->typdata_from_dbus))
                           != 0
                    || memcmp(&pt->typdata_to_dbus,
                              &pt_2->typdata_to_dbus,
                              sizeof(pt->typdata_to_dbus))
                           != 0)
                    continue;

                /* the property-types with same content should all be shared. Here we have two that
                 * are the same content, but different instances. Bug. */
                NM_PRAGMA_WARNING_DISABLE_DANGLING_POINTER
                g_error("The identical property type for D-Bus type \"%s\" is used by: %s and %s. "
                        "If a NMSettInfoPropertType is identical, it should be shared by creating "
                        "a common instance of the property type",
                        (const char *) pt->dbus_type,
                        _PROP_IDX_OWNER(h_property_types, pt),
                        _PROP_IDX_OWNER(h_property_types, pt_2));
                NM_PRAGMA_WARNING_REENABLE
            }
        }
    }
}

/*****************************************************************************/

static void
test_setting_connection_empty_address_and_route(void)
{
    NMSettingIPConfig            *s_ip4;
    NMIPRoute                    *route;
    NMIPAddress                  *addr;
    gs_unref_object NMConnection *con   = NULL;
    gs_free_error GError         *error = NULL;
    gboolean                      success;

    /* IP4 setting */
    con   = nmtst_create_minimal_connection("wired", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
    s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new();
    nm_connection_add_setting(con, NM_SETTING(s_ip4));
    g_object_set(s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL, NULL);
    g_assert(s_ip4 != NULL);
    g_assert(NM_IS_SETTING_IP4_CONFIG(s_ip4));
    success = nm_setting_verify((NMSetting *) s_ip4, con, &error);
    nmtst_assert_no_success(success, error);
    nm_clear_error(&error);

    route = nm_ip_route_new(AF_INET, "192.168.12.0", 24, NULL, 0, NULL);
    nm_setting_ip_config_add_route(s_ip4, route);
    success = nm_setting_verify((NMSetting *) s_ip4, con, &error);
    nmtst_assert_success(success, error);
    nm_clear_error(&error);

    nm_setting_ip_config_clear_routes(s_ip4);
    addr = nm_ip_address_new(AF_INET, "1.1.1.3", 24, NULL);
    nm_setting_ip_config_add_address(s_ip4, addr);
    success = nm_setting_verify((NMSetting *) s_ip4, con, &error);
    nmtst_assert_success(success, error);
    nm_clear_error(&error);

    nm_setting_ip_config_add_route(s_ip4, route);
    success = nm_setting_verify((NMSetting *) s_ip4, con, &error);
    nmtst_assert_success(success, error);
    nm_ip_address_unref(addr);
    nm_ip_route_unref(route);
    nm_clear_error(&error);
}

/*****************************************************************************/

static void
test_setting_connection_secondaries_verify(void)
{
    gs_unref_object NMConnection *con = NULL;
    NMSettingConnection          *s_con;
    guint                         i_run;
    guint                         i_word;

    con = nmtst_create_minimal_connection("test-sec", NULL, NM_SETTING_WIRED_SETTING_NAME, &s_con);
    nmtst_connection_normalize(con);

    for (i_run = 0; i_run < 100; i_run++) {
        guint                        word_len = nmtst_get_rand_word_length(NULL);
        gs_unref_ptrarray GPtrArray *arr      = NULL;
        gs_unref_ptrarray GPtrArray *arr_norm = NULL;
        gboolean                     was_normalized;
        gboolean                     was_normalized2;

        /* create a random list of invalid, normalizable and normalized UUIDs. */
        arr = g_ptr_array_new();
        for (i_word = 0; i_word < word_len; i_word++) {
            g_ptr_array_add(arr,
                            (char *) nmtst_rand_select((const char *) "",
                                                       "52c3feb9-3aa2-46f6-a07b-1765918699eb",
                                                       "52C3feb9-3aa2-46f6-a07b-1765918699eb",
                                                       "52C3feb9-3aa2-46f6-a07b-1765918699eb",
                                                       "f86dfb13df764894ab3836b7cdb9d82dde8b27c4",
                                                       "52C3feb93-aa2-46f6-a07b-1765918699eb",
                                                       "bogus"));
        }
        g_ptr_array_add(arr, NULL);

        /* set the new list of secondaries, and assert that the result is as expected. */

        nmtst_assert_connection_verifies_without_normalization(con);

        g_object_set(s_con, NM_SETTING_CONNECTION_SECONDARIES, arr->pdata, NULL);

#define _assert_secondaries(s_con, expected)                                                       \
    G_STMT_START                                                                                   \
    {                                                                                              \
        NMSettingConnection *const _s_con    = (s_con);                                            \
        const char *const         *_expected = (expected);                                         \
        GArray                    *_secondaries;                                                   \
        const guint                _expected_len = NM_PTRARRAY_LEN(_expected);                     \
        gs_strfreev char         **_sec_strv     = NULL;                                           \
        guint                      _i;                                                             \
                                                                                                   \
        g_assert(_expected);                                                                       \
                                                                                                   \
        if (nmtst_get_rand_bool()) {                                                               \
            _secondaries = _nm_setting_connection_get_secondaries(_s_con);                         \
            g_assert_cmpint(_expected_len, ==, nm_g_array_len(_secondaries));                      \
            g_assert((_expected_len == 0) == (!_secondaries));                                     \
            g_assert(nm_strv_equal(_expected, nm_strvarray_get_strv_notnull(_secondaries, NULL))); \
        }                                                                                          \
                                                                                                   \
        if (nmtst_get_rand_bool()) {                                                               \
            g_object_get(_s_con, NM_SETTING_CONNECTION_SECONDARIES, &_sec_strv, NULL);             \
            g_assert_cmpint(_expected_len, ==, NM_PTRARRAY_LEN(_sec_strv));                        \
            g_assert((_expected_len == 0) == (!_sec_strv));                                        \
            g_assert(nm_strv_equal(_expected, _sec_strv ?: NM_STRV_EMPTY()));                      \
        }                                                                                          \
                                                                                                   \
        g_assert_cmpint(nm_setting_connection_get_num_secondaries(_s_con), ==, _expected_len);     \
        if (nmtst_get_rand_bool()) {                                                               \
            for (_i = 0; _i < _expected_len; _i++) {                                               \
                g_assert_cmpstr(nm_setting_connection_get_secondary(_s_con, _i),                   \
                                ==,                                                                \
                                _expected[_i]);                                                    \
            }                                                                                      \
            g_assert_null(nm_setting_connection_get_secondary(_s_con, _expected_len));             \
        }                                                                                          \
    }                                                                                              \
    G_STMT_END

        _assert_secondaries(s_con, (const char *const *) arr->pdata);

        /* reimplement the normalization that we expect to happen and
         * create an array @arr_norm with the expected result after normalization. */
        arr_norm = g_ptr_array_new_with_free_func(g_free);
        for (i_word = 0; i_word < word_len; i_word++) {
            const char *s = arr->pdata[i_word];
            gboolean    is_normalized;
            char        uuid_normalized[37];

            if (!nm_uuid_is_valid_nm(s, &is_normalized, uuid_normalized))
                continue;

            if (is_normalized)
                s = uuid_normalized;

            if (nm_strv_ptrarray_find_first(arr_norm, s) >= 0)
                continue;

            g_ptr_array_add(arr_norm, g_strdup(s));
        }
        g_ptr_array_add(arr_norm, NULL);

        was_normalized = !nm_strv_equal((char **) arr->pdata, (char **) arr_norm->pdata);

        if (was_normalized)
            nmtst_assert_connection_verifies_and_normalizable(con);
        else
            nmtst_assert_connection_verifies_without_normalization(con);

        if (was_normalized || nmtst_get_rand_bool()) {
            was_normalized2 = nmtst_connection_normalize(con);
            g_assert(was_normalized == was_normalized2);
        }

        _assert_secondaries(s_con, (const char *const *) arr_norm->pdata);
    }
}

/*****************************************************************************/

static void
test_6lowpan_1(void)
{
    gs_unref_object NMConnection *con = NULL;
    NMSetting6Lowpan             *s_6low;
    gs_free char                 *value = NULL;

    con = nmtst_create_minimal_connection("test-sec", NULL, NM_SETTING_6LOWPAN_SETTING_NAME, NULL);

    s_6low = NM_SETTING_6LOWPAN(nm_connection_get_setting(con, NM_TYPE_SETTING_6LOWPAN));
    g_assert(s_6low);

    g_assert_cmpstr(nm_setting_6lowpan_get_parent(s_6low), ==, NULL);
    g_object_get(s_6low, NM_SETTING_6LOWPAN_PARENT, &value, NULL);
    g_assert_cmpstr(value, ==, NULL);
    nm_clear_g_free(&value);

    g_object_set(s_6low, NM_SETTING_6LOWPAN_PARENT, "hello", NULL);
    g_assert_cmpstr(nm_setting_6lowpan_get_parent(s_6low), ==, "hello");
    g_object_get(s_6low, NM_SETTING_6LOWPAN_PARENT, &value, NULL);
    g_assert_cmpstr(value, ==, "hello");
    nm_clear_g_free(&value);

    g_object_set(s_6low, NM_SETTING_6LOWPAN_PARENT, "world", NULL);
    g_assert_cmpstr(nm_setting_6lowpan_get_parent(s_6low), ==, "world");
    g_object_get(s_6low, NM_SETTING_6LOWPAN_PARENT, &value, NULL);
    g_assert_cmpstr(value, ==, "world");
    nm_clear_g_free(&value);
}

/*****************************************************************************/

static void
test_settings_dns(void)
{
    int i_run;

    for (i_run = 0; i_run < 10; i_run++) {
        gs_unref_object NMConnection *con1 = NULL;
        gs_unref_object NMConnection *con2 = NULL;
        int                           IS_IPv4;
        guint                         n_dns;
        guint                         i;
        gboolean                      same = TRUE;

        con1 =
            nmtst_create_minimal_connection("test-dns", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
        nmtst_connection_normalize(con1);

        con2 = nmtst_connection_duplicate_and_normalize(con1);

        nmtst_assert_connection_equals(con1, nmtst_get_rand_bool(), con2, nmtst_get_rand_bool());

        for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
            const char *nameservers[2][7] = {
                [0] =
                    {
                        "11:22::b:0",
                        "11:22::b:1#hello1",
                        "11:22::b:2",
                        "11:22::b:3#hello2",
                        "11:22::b:4",
                        "11:22::b:5",
                        "bogus6",
                    },
                [1] =
                    {
                        "1.1.1.0",
                        "1.1.1.1#foo1",
                        "1.1.1.2",
                        "1.1.1.3#foo2",
                        "1.1.1.4",
                        "1.1.1.5",
                        "bogus4",
                    },
            };
            GType gtype = IS_IPv4 ? NM_TYPE_SETTING_IP4_CONFIG : NM_TYPE_SETTING_IP6_CONFIG;
            NMSettingIPConfig *s_ip1 = _nm_connection_get_setting(con1, gtype);
            NMSettingIPConfig *s_ip2 = _nm_connection_get_setting(con2, gtype);

            n_dns = nmtst_get_rand_uint32() % G_N_ELEMENTS(nameservers[0]);
            for (i = 0; i < n_dns; i++) {
                const char *d =
                    nameservers[IS_IPv4][nmtst_get_rand_uint32() % G_N_ELEMENTS(nameservers[0])];

                if (!nmtst_get_rand_one_case_in(4))
                    nm_setting_ip_config_add_dns(s_ip1, d);
                if (!nmtst_get_rand_one_case_in(4))
                    nm_setting_ip_config_add_dns(s_ip2, d);
            }

            if (nm_strv_ptrarray_cmp(_nm_setting_ip_config_get_dns_array(s_ip1),
                                     _nm_setting_ip_config_get_dns_array(s_ip2))
                != 0)
                same = FALSE;
        }

        _nm_utils_is_manager_process = nmtst_get_rand_bool();
        if (same) {
            nmtst_assert_connection_equals(con1, FALSE, con2, FALSE);
            g_assert(nm_connection_compare(con1, con2, NM_SETTING_COMPARE_FLAG_EXACT));
        } else {
            g_assert(!nm_connection_compare(con1, con2, NM_SETTING_COMPARE_FLAG_EXACT));
        }
        _nm_utils_is_manager_process = FALSE;
    }
}

static void
_assert_dns_searches(gboolean valid, ...)
{
    NMConnection      *con;
    NMSettingIPConfig *ip4, *ip6;
    const char        *dns_search;
    va_list            args;

    con = nmtst_create_minimal_connection("test-dns-search",
                                          NULL,
                                          NM_SETTING_WIRED_SETTING_NAME,
                                          NULL);
    nmtst_connection_normalize(con);
    ip4 = nm_connection_get_setting_ip4_config(con);
    ip6 = nm_connection_get_setting_ip6_config(con);

    va_start(args, valid);
    while ((dns_search = va_arg(args, const char *))) {
        nm_setting_ip_config_add_dns_search(ip4, dns_search);
        nm_setting_ip_config_add_dns_search(ip6, dns_search);
    }
    va_end(args);

    g_assert(valid == nm_setting_verify((NMSetting *) ip4, con, NULL));
    g_assert(valid == nm_setting_verify((NMSetting *) ip6, con, NULL));
}

static void
test_settings_dns_search_domains(void)
{
    _assert_dns_searches(TRUE, "example.com", NULL);
    _assert_dns_searches(TRUE, "sub.example.com", NULL);
    _assert_dns_searches(TRUE, "example.com", "sub.example.com", NULL);
    _assert_dns_searches(FALSE, "example.com,sub.example.com", NULL);
    _assert_dns_searches(FALSE, "example.com;sub.example.com", NULL);
    _assert_dns_searches(FALSE, "example.com sub.example.com", NULL);
}

/*****************************************************************************/

static void
test_bond_meta(void)
{
    gs_unref_object NMConnection *con = NULL;
    NMSettingBond                *set;
    char                          sbuf[200];

    create_bond_connection(&con, &set);

    g_assert_cmpstr(nm_setting_bond_get_option_normalized(set, NM_SETTING_BOND_OPTION_MODE),
                    ==,
                    "balance-rr");

#define _A(_nm_setting_bond_opt_value_as_xxx, set, opt, value, errsv)                  \
    G_STMT_START                                                                       \
    {                                                                                  \
        g_assert_cmpint(_nm_setting_bond_opt_value_as_xxx((set), (opt)), ==, (value)); \
        g_assert_cmpint(errno, ==, (errsv));                                           \
    }                                                                                  \
    G_STMT_END

    _A(_nm_setting_bond_opt_value_as_u32, set, NM_SETTING_BOND_OPTION_MIIMON, 100, 0);
    _A(_nm_setting_bond_opt_value_as_u32, set, NM_SETTING_BOND_OPTION_UPDELAY, 0, 0);
    _A(_nm_setting_bond_opt_value_as_u32, set, NM_SETTING_BOND_OPTION_DOWNDELAY, 0, 0);
    _A(_nm_setting_bond_opt_value_as_u32, set, NM_SETTING_BOND_OPTION_ARP_INTERVAL, 0, 0);
    _A(_nm_setting_bond_opt_value_as_u32, set, NM_SETTING_BOND_OPTION_RESEND_IGMP, 1, 0);
    _A(_nm_setting_bond_opt_value_as_u32, set, NM_SETTING_BOND_OPTION_MIN_LINKS, 0, 0);
    _A(_nm_setting_bond_opt_value_as_u32, set, NM_SETTING_BOND_OPTION_LP_INTERVAL, 1, 0);
    _A(_nm_setting_bond_opt_value_as_u32, set, NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE, 1, 0);
    _A(_nm_setting_bond_opt_value_as_u32, set, NM_SETTING_BOND_OPTION_PEER_NOTIF_DELAY, 0, 0);
    _A(_nm_setting_bond_opt_value_as_u16, set, NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO, 0, EINVAL);
    _A(_nm_setting_bond_opt_value_as_u16, set, NM_SETTING_BOND_OPTION_AD_USER_PORT_KEY, 0, EINVAL);
    _A(_nm_setting_bond_opt_value_as_u8, set, NM_SETTING_BOND_OPTION_NUM_GRAT_ARP, 1, 0);
    _A(_nm_setting_bond_opt_value_as_u8, set, NM_SETTING_BOND_OPTION_ARP_MISSED_MAX, 0, 0);
    _A(_nm_setting_bond_opt_value_as_u8, set, NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE, 0, 0);
    _A(_nm_setting_bond_opt_value_as_intbool, set, NM_SETTING_BOND_OPTION_USE_CARRIER, 1, 0);
    _A(_nm_setting_bond_opt_value_as_intbool,
       set,
       NM_SETTING_BOND_OPTION_TLB_DYNAMIC_LB,
       0,
       EINVAL);

    nm_setting_bond_add_option(set, NM_SETTING_BOND_OPTION_ARP_INTERVAL, "5");
    _A(_nm_setting_bond_opt_value_as_u32, set, NM_SETTING_BOND_OPTION_ARP_INTERVAL, 5, 0);

    nm_setting_bond_add_option(set,
                               NM_SETTING_BOND_OPTION_ARP_INTERVAL,
                               nm_sprintf_buf(sbuf, "%d", G_MAXINT));
    _A(_nm_setting_bond_opt_value_as_u32, set, NM_SETTING_BOND_OPTION_ARP_INTERVAL, G_MAXINT, 0);

    nm_setting_bond_add_option(set, NM_SETTING_BOND_OPTION_MODE, "802.3ad");
    _A(_nm_setting_bond_opt_value_as_u16, set, NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO, 65535, 0);
    _A(_nm_setting_bond_opt_value_as_u16, set, NM_SETTING_BOND_OPTION_AD_USER_PORT_KEY, 0, 0);

    nm_setting_bond_add_option(set, NM_SETTING_BOND_OPTION_MODE, "balance-tlb");
    _A(_nm_setting_bond_opt_value_as_intbool, set, NM_SETTING_BOND_OPTION_TLB_DYNAMIC_LB, 1, 0);
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/libnm/test_connection_uuid", test_connection_uuid);

    g_test_add_func("/libnm/settings/test_nm_meta_setting_types_by_priority",
                    test_nm_meta_setting_types_by_priority);

    g_test_add_data_func("/libnm/setting-8021x/key-and-cert",
                         "test_key_and_cert.pem, test",
                         test_8021x);
    g_test_add_data_func("/libnm/setting-8021x/key-only", "test-key-only.pem, test", test_8021x);
    g_test_add_data_func("/libnm/setting-8021x/pkcs8-enc-key",
                         "pkcs8-enc-key.pem, 1234567890",
                         test_8021x);
    g_test_add_data_func("/libnm/setting-8021x/pkcs12", "test-cert.p12, test", test_8021x);

    g_test_add_func("/libnm/settings/test_setting_connection_empty_address_and_route",
                    test_setting_connection_empty_address_and_route);
    g_test_add_func("/libnm/settings/test_setting_connection_secondaries_verify",
                    test_setting_connection_secondaries_verify);

    g_test_add_func("/libnm/settings/bond/verify", test_bond_verify);
    g_test_add_func("/libnm/settings/bond/compare", test_bond_compare);
    g_test_add_func("/libnm/settings/bond/normalize", test_bond_normalize);

    g_test_add_func("/libnm/settings/dummy/normalize", test_dummy_normalize);

    g_test_add_func("/libnm/settings/dcb/flags-valid", test_dcb_flags_valid);
    g_test_add_func("/libnm/settings/dcb/flags-invalid", test_dcb_flags_invalid);
    g_test_add_func("/libnm/settings/dcb/app-priorities", test_dcb_app_priorities);
    g_test_add_func("/libnm/settings/dcb/priorities", test_dcb_priorities_valid);
    g_test_add_func("/libnm/settings/dcb/bandwidth-sums", test_dcb_bandwidth_sums);

    g_test_add_func("/libnm/settings/ethtool/features", test_ethtool_features);
    g_test_add_func("/libnm/settings/ethtool/coalesce", test_ethtool_coalesce);
    g_test_add_func("/libnm/settings/ethtool/ring", test_ethtool_ring);
    g_test_add_func("/libnm/settings/ethtool/pause", test_ethtool_pause);
    g_test_add_func("/libnm/settings/ethtool/eee", test_ethtool_eee);
    g_test_add_func("/libnm/settings/ethtool/fec", test_ethtool_fec);

    g_test_add_func("/libnm/settings/6lowpan/1", test_6lowpan_1);

    g_test_add_func("/libnm/settings/dns", test_settings_dns);
    g_test_add_func("/libnm/settings/dns_search_domain", test_settings_dns_search_domains);

    g_test_add_func("/libnm/settings/sriov/vf", test_sriov_vf);
    g_test_add_func("/libnm/settings/sriov/vf-dup", test_sriov_vf_dup);
    g_test_add_func("/libnm/settings/sriov/vf-vlan", test_sriov_vf_vlan);
    g_test_add_func("/libnm/settings/sriov/setting", test_sriov_setting);
    g_test_add_func("/libnm/settings/sriov/vlans", test_sriov_parse_vlans);

    g_test_add_func("/libnm/settings/tc_config/qdisc", test_tc_config_qdisc);
    g_test_add_func("/libnm/settings/tc_config/action", test_tc_config_action);
    g_test_add_func("/libnm/settings/tc_config/tfilter/matchall_sdata",
                    test_tc_config_tfilter_matchall_sdata);
    g_test_add_func("/libnm/settings/tc_config/tfilter/matchall_mirred",
                    test_tc_config_tfilter_matchall_mirred);
    g_test_add_func("/libnm/settings/tc_config/setting/valid", test_tc_config_setting_valid);
    g_test_add_func("/libnm/settings/tc_config/setting/duplicates",
                    test_tc_config_setting_duplicates);
    g_test_add_func("/libnm/settings/tc_config/dbus", test_tc_config_dbus);

    g_test_add_func("/libnm/settings/bridge/vlans", test_bridge_vlans);
    g_test_add_func("/libnm/settings/bridge/verify", test_bridge_verify);

    g_test_add_func("/libnm/test_nm_json", test_nm_json);
    g_test_add_func("/libnm/settings/team/sync_runner_from_config_roundrobin",
                    test_runner_roundrobin_sync_from_config);
    g_test_add_func("/libnm/settings/team/sync_runner_from_config_broadcast",
                    test_runner_broadcast_sync_from_config);
    g_test_add_func("/libnm/settings/team/sync_runner_from_config_random",
                    test_runner_random_sync_from_config);
    g_test_add_func("/libnm/settings/team/sync_runner_from_config_activebackup",
                    test_runner_activebackup_sync_from_config);
    g_test_add_func("/libnm/settings/team/sync_runner_from_config_loadbalance",
                    test_runner_loadbalance_sync_from_config);
    g_test_add_func("/libnm/settings/team/sync_runner_from_config_lacp",
                    test_runner_lacp_sync_from_config);
    g_test_add_func("/libnm/settings/team/sync_watcher_from_config_ethtool",
                    test_watcher_ethtool_sync_from_config);
    g_test_add_func("/libnm/settings/team/sync_watcher_from_config_nsna_ping",
                    test_watcher_nsna_ping_sync_from_config);
    g_test_add_func("/libnm/settings/team/sync_watcher_from_config_arp_ping",
                    test_watcher_arp_ping_sync_from_config);
    g_test_add_func("/libnm/settings/team/sync_watcher_from_config_all",
                    test_multiple_watchers_sync_from_config);

    g_test_add_func("/libnm/settings/team-port/sync_from_config_defaults", test_team_port_default);
    g_test_add_func("/libnm/settings/team-port/sync_from_config_queue_id", test_team_port_queue_id);
    g_test_add_func("/libnm/settings/team-port/sync_from_config_prio", test_team_port_prio);
    g_test_add_func("/libnm/settings/team-port/sync_from_config_sticky", test_team_port_sticky);
    g_test_add_func("/libnm/settings/team-port/sync_from_config_lacp_prio",
                    test_team_port_lacp_prio);
    g_test_add_func("/libnm/settings/team-port/sync_from_config_lacp_key", test_team_port_lacp_key);
    g_test_add_func("/libnm/settings/team-port/sycn_from_config_full", test_team_port_full_config);

    g_test_add_data_func("/libnm/settings/roundtrip-conversion/general/0",
                         GINT_TO_POINTER(0),
                         test_roundtrip_conversion);
    g_test_add_data_func("/libnm/settings/roundtrip-conversion/wireguard/1",
                         GINT_TO_POINTER(1),
                         test_roundtrip_conversion);
    g_test_add_data_func("/libnm/settings/roundtrip-conversion/wireguard/2",
                         GINT_TO_POINTER(2),
                         test_roundtrip_conversion);
    g_test_add_data_func("/libnm/settings/roundtrip-conversion/general/3",
                         GINT_TO_POINTER(3),
                         test_roundtrip_conversion);

    g_test_add_data_func("/libnm/settings/routing-rule/1", GINT_TO_POINTER(0), test_routing_rule);

    g_test_add_func("/libnm/settings/ranges", test_ranges);

    g_test_add_func("/libnm/parse-tc-handle", test_parse_tc_handle);

    g_test_add_func("/libnm/test_team_setting", test_team_setting);

    g_test_add_func("/libnm/test_empty_setting", test_empty_setting);

    g_test_add_func("/libnm/test_setting_metadata", test_setting_metadata);

    g_test_add_func("/libnm/test_bond_meta", test_bond_meta);

    return g_test_run();
}
