/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "libnm/nm-default-client.h"

#include "nm-meta-setting-access.h"
#include "nm-vpn-helpers.h"
#include "nm-client-utils.h"

#include "nm-utils/nm-test-utils.h"

/*****************************************************************************/

static void
test_client_meta_check(void)
{
    const NMMetaSettingInfoEditor *const *infos_p;
    NMMetaSettingType                     m;
    guint                                 p;

    G_STATIC_ASSERT(G_STRUCT_OFFSET(NMMetaAbstractInfo, meta_type)
                    == G_STRUCT_OFFSET(NMMetaSettingInfoEditor, meta_type));
    G_STATIC_ASSERT(G_STRUCT_OFFSET(NMMetaAbstractInfo, meta_type)
                    == G_STRUCT_OFFSET(NMMetaPropertyInfo, meta_type));

    for (m = 0; m < _NM_META_SETTING_TYPE_NUM; m++) {
        const NMMetaSettingInfo *info = &nm_meta_setting_infos[m];
        GType                    gtype;

        g_assert(info);
        g_assert(info->meta_type == m);
        g_assert(info->setting_name);
        g_assert(info->get_setting_gtype);

        gtype = info->get_setting_gtype();
        g_assert(gtype != NM_TYPE_SETTING);

        {
            nm_auto_unref_gtypeclass GTypeClass *gclass = g_type_class_ref(gtype);

            g_assert(G_TYPE_CHECK_CLASS_TYPE(gclass, gtype));
        }
        {
            gs_unref_object NMSetting *setting = g_object_new(gtype, NULL);

            g_assert(NM_IS_SETTING(setting));
            g_assert(G_TYPE_CHECK_INSTANCE_TYPE(setting, gtype));
            g_assert_cmpstr(nm_setting_get_name(setting), ==, info->setting_name);
        }
    }

    for (m = 0; m < _NM_META_SETTING_TYPE_NUM; m++) {
        const NMMetaSettingInfoEditor *info = &nm_meta_setting_infos_editor[m];
        GType                          gtype;
        NMSettingPriority              base_priority;
        gboolean                       is_base_type;

        g_assert(info);
        g_assert(info->meta_type == &nm_meta_type_setting_info_editor);
        g_assert(info->general);
        g_assert(info->general == &nm_meta_setting_infos[m]);

        g_assert_cmpstr(info->general->setting_name,
                        ==,
                        info->meta_type->get_name((const NMMetaAbstractInfo *) info, FALSE));
        g_assert_cmpstr("name",
                        ==,
                        info->meta_type->get_name((const NMMetaAbstractInfo *) info, TRUE));

        g_assert(info->properties_num == NM_PTRARRAY_LEN(info->properties));

        if (info->properties_num) {
            gs_unref_hashtable GHashTable *property_names =
                g_hash_table_new(nm_str_hash, g_str_equal);

            g_assert(info->properties);
            for (p = 0; p < info->properties_num; p++) {
                const NMMetaPropertyInfo *pi = info->properties[p];

                g_assert(pi);
                g_assert(pi->meta_type == &nm_meta_type_property_info);
                g_assert(pi->setting_info == info);
                g_assert(pi->property_name);

                g_assert(g_hash_table_add(property_names, (gpointer) pi->property_name));

                g_assert_cmpstr(pi->property_name,
                                ==,
                                pi->meta_type->get_name((const NMMetaAbstractInfo *) pi, FALSE));
                g_assert_cmpstr(pi->property_name,
                                ==,
                                pi->meta_type->get_name((const NMMetaAbstractInfo *) pi, TRUE));

                g_assert(pi->property_type);
                g_assert(pi->property_type->get_fcn);
            }
            g_assert(!info->properties[info->properties_num]);
        } else
            g_assert(!info->properties);

        gtype         = info->general->get_setting_gtype();
        base_priority = _nm_setting_type_get_base_type_priority(gtype);
        is_base_type  = (base_priority != NM_SETTING_PRIORITY_INVALID);
        g_assert((!!info->valid_parts) == is_base_type);

        if (info->valid_parts) {
            gsize              i, l;
            gs_unref_hashtable GHashTable *dup = g_hash_table_new(nm_direct_hash, NULL);

            l = NM_PTRARRAY_LEN(info->valid_parts);
            g_assert(l >= 2);

            for (i = 0; info->valid_parts[i]; i++) {
                g_assert(info->valid_parts[i]->setting_info);
                g_assert(g_hash_table_add(dup, (gpointer) info->valid_parts[i]->setting_info));

                if (i == 0) {
                    g_assert(info->valid_parts[i]->setting_info
                             == &nm_meta_setting_infos_editor[NM_META_SETTING_TYPE_CONNECTION]);
                    g_assert(info->valid_parts[i]->mandatory);
                }
                if (i == 1) {
                    g_assert(info->valid_parts[i]->setting_info
                             == &nm_meta_setting_infos_editor[m]);
                    g_assert(info->valid_parts[i]->mandatory);
                }
            }
            g_assert(i == l);
        }
    }

    for (m = 0; m < _NM_META_SETTING_TYPE_NUM; m++) {
        const NMMetaSettingInfoEditor *info = &nm_meta_setting_infos_editor[m];

        g_assert(nm_meta_setting_info_editor_find_by_name(info->general->setting_name, FALSE)
                 == info);
        g_assert(nm_meta_setting_info_editor_find_by_gtype(info->general->get_setting_gtype())
                 == info);

        for (p = 0; p < info->properties_num; p++) {
            const NMMetaPropertyInfo *pi = info->properties[p];

            g_assert(nm_meta_setting_info_editor_get_property_info(info, pi->property_name) == pi);
            g_assert(
                nm_meta_property_info_find_by_name(info->general->setting_name, pi->property_name)
                == pi);
        }
    }

    infos_p = nm_meta_setting_infos_editor_p();
    g_assert(infos_p);
    for (m = 0; m < _NM_META_SETTING_TYPE_NUM; m++)
        g_assert(infos_p[m] == &nm_meta_setting_infos_editor[m]);
    g_assert(!infos_p[m]);
}

/*****************************************************************************/

static void
test_client_import_wireguard_test0(void)
{
    gs_unref_object NMConnection *connection;
    NMSettingWireGuard *          s_wg;
    NMSettingIPConfig *           s_ip4;
    NMSettingIPConfig *           s_ip6;
    NMWireGuardPeer *             peer;
    gs_free_error GError *error = NULL;

    connection =
        nm_vpn_wireguard_import(NM_BUILD_SRCDIR "/clients/common/tests/wg-test0.conf", &error);

    g_assert_no_error(error);

    g_assert_cmpstr(nm_connection_get_id(connection), ==, "wg-test0");
    g_assert_cmpstr(nm_connection_get_interface_name(connection), ==, "wg-test0");
    g_assert_cmpstr(nm_connection_get_connection_type(connection),
                    ==,
                    NM_SETTING_WIREGUARD_SETTING_NAME);

    s_wg = NM_SETTING_WIREGUARD(nm_connection_get_setting(connection, NM_TYPE_SETTING_WIREGUARD));

    g_assert_cmpint(nm_setting_wireguard_get_listen_port(s_wg), ==, 51820);
    g_assert_cmpstr(nm_setting_wireguard_get_private_key(s_wg),
                    ==,
                    "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=");

    g_assert_cmpint(nm_setting_wireguard_get_peers_len(s_wg), ==, 3);

    peer = nm_setting_wireguard_get_peer(s_wg, 0);
    g_assert_cmpstr(nm_wireguard_peer_get_public_key(peer),
                    ==,
                    "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=");
    g_assert_cmpstr(nm_wireguard_peer_get_endpoint(peer), ==, "192.95.5.67:1234");
    g_assert_cmpint(nm_wireguard_peer_get_allowed_ips_len(peer), ==, 2);
    g_assert_cmpstr(nm_wireguard_peer_get_allowed_ip(peer, 0, NULL), ==, "10.192.122.3/32");
    g_assert_cmpstr(nm_wireguard_peer_get_allowed_ip(peer, 1, NULL), ==, "10.192.124.1/24");

    peer = nm_setting_wireguard_get_peer(s_wg, 1);
    g_assert_cmpstr(nm_wireguard_peer_get_public_key(peer),
                    ==,
                    "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=");
    g_assert_cmpstr(nm_wireguard_peer_get_endpoint(peer), ==, "[2607:5300:60:6b0::c05f:543]:2468");
    g_assert_cmpint(nm_wireguard_peer_get_allowed_ips_len(peer), ==, 2);
    g_assert_cmpstr(nm_wireguard_peer_get_allowed_ip(peer, 0, NULL), ==, "10.192.122.4/32");
    g_assert_cmpstr(nm_wireguard_peer_get_allowed_ip(peer, 1, NULL), ==, "192.168.0.0/16");

    peer = nm_setting_wireguard_get_peer(s_wg, 2);
    g_assert_cmpstr(nm_wireguard_peer_get_public_key(peer),
                    ==,
                    "gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=");
    g_assert_cmpstr(nm_wireguard_peer_get_endpoint(peer), ==, "test.wireguard.com:18981");
    g_assert_cmpint(nm_wireguard_peer_get_allowed_ips_len(peer), ==, 1);
    g_assert_cmpstr(nm_wireguard_peer_get_allowed_ip(peer, 0, NULL), ==, "10.10.10.230/32");

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    s_ip6 = nm_connection_get_setting_ip6_config(connection);

    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 1);
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip6), ==, 0);

    g_assert_cmpint(nm_setting_ip_config_get_num_dns_searches(s_ip4), ==, 1);
    g_assert_cmpint(nm_setting_ip_config_get_num_dns_searches(s_ip6), ==, 0);

    g_assert_cmpstr(nm_setting_ip_config_get_dns_search(s_ip4, 0), ==, "~");
}

static void
test_client_import_wireguard_test1(void)
{
    gs_free_error GError *error = NULL;

    nm_vpn_wireguard_import(NM_BUILD_SRCDIR "/clients/common/tests/wg-test1.conf", &error);
    g_assert_error(error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
    g_assert(g_str_has_prefix(error->message, "invalid secret 'PrivateKey'"));
    g_assert(g_str_has_suffix(error->message, "wg-test1.conf:2"));
}

static void
test_client_import_wireguard_test2(void)
{
    gs_free_error GError *error = NULL;

    nm_vpn_wireguard_import(NM_BUILD_SRCDIR "/clients/common/tests/wg-test2.conf", &error);

    g_assert_error(error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
    g_assert(g_str_has_prefix(error->message, "unrecognized line at"));
    g_assert(g_str_has_suffix(error->message, "wg-test2.conf:5"));
}

static void
test_client_import_wireguard_test3(void)
{
    gs_free_error GError *error = NULL;

    nm_vpn_wireguard_import(NM_BUILD_SRCDIR "/clients/common/tests/wg-test3.conf", &error);
    g_assert_error(error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
    g_assert(g_str_has_prefix(error->message, "invalid value for 'ListenPort'"));
    g_assert(g_str_has_suffix(error->message, "wg-test3.conf:3"));
}

static void
test_client_import_wireguard_missing(void)
{
    gs_free_error GError *error = NULL;

    nm_vpn_wireguard_import(NM_BUILD_SRCDIR "/clients/common/tests/wg-missing.conf", &error);
    g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_NOENT);
}

/*****************************************************************************/

#define _do_test_parse_passwd_file(contents, success, exp_error_line, ...)                   \
    G_STMT_START                                                                             \
    {                                                                                        \
        static const NMUtilsNamedValue _values[] = {__VA_ARGS__};                            \
        gs_free char *                 _contents = g_strndup(contents, NM_STRLEN(contents)); \
        gs_unref_hashtable GHashTable *_secrets  = NULL;                                     \
        gs_free_error GError *_local             = NULL;                                     \
        gssize                _error_line;                                                   \
        GError **             _p_local        = nmtst_get_rand_bool() ? &_local : NULL;      \
        gssize *              _p_error_line   = nmtst_get_rand_bool() ? &_error_line : NULL; \
        gboolean              _success        = !!(success);                                 \
        gssize                _exp_error_line = (exp_error_line);                            \
        int                   _i;                                                            \
                                                                                             \
        g_assert(_success || (G_N_ELEMENTS(_values) == 0));                                  \
                                                                                             \
        _secrets = nmc_utils_parse_passwd_file(_contents, _p_error_line, _p_local);          \
                                                                                             \
        g_assert(_success == (!!_secrets));                                                  \
        if (!_success) {                                                                     \
            if (_p_error_line)                                                               \
                g_assert_cmpint(_exp_error_line, ==, *_p_error_line);                        \
            if (_p_local)                                                                    \
                g_assert(_local);                                                            \
        } else {                                                                             \
            if (_p_error_line)                                                               \
                g_assert_cmpint(-1, ==, *_p_error_line);                                     \
            g_assert(!_local);                                                               \
                                                                                             \
            for (_i = 0; _i < (int) G_N_ELEMENTS(_values); _i++) {                           \
                const NMUtilsNamedValue *_n = &_values[_i];                                  \
                const char *             _v;                                                 \
                                                                                             \
                _v = g_hash_table_lookup(_secrets, _n->name);                                \
                if (!_v)                                                                     \
                    g_error("cannot find key \"%s\"", _n->name);                             \
                g_assert_cmpstr(_v, ==, _n->value_str);                                      \
            }                                                                                \
                                                                                             \
            g_assert_cmpint(g_hash_table_size(_secrets), ==, G_N_ELEMENTS(_values));         \
        }                                                                                    \
    }                                                                                        \
    G_STMT_END

#define _do_test_parse_passwd_file_bad(contents, exp_error_line) \
    _do_test_parse_passwd_file(contents, FALSE, exp_error_line)
#define _do_test_parse_passwd_file_good(contents, ...) \
    _do_test_parse_passwd_file(contents, TRUE, -1, __VA_ARGS__)

static void
test_nmc_utils_parse_passwd_file(void)
{
    _do_test_parse_passwd_file_good("");
    _do_test_parse_passwd_file_bad("x", 1);
    _do_test_parse_passwd_file_bad("\r\rx", 3);
    _do_test_parse_passwd_file_good(
        "wifi.psk=abc",
        NM_UTILS_NAMED_VALUE_INIT("802-11-wireless-security.psk", "abc"));
    _do_test_parse_passwd_file_good(
        "wifi.psk:ABC\r"
        "wifi-sec.psk = abc ",
        NM_UTILS_NAMED_VALUE_INIT("802-11-wireless-security.psk", "abc"));
    _do_test_parse_passwd_file_good(
        "wifi.psk:  abc\r"
        "wifi-sec.psk2 = d\\145f\r\n"
        "  wifi.psk3 = e\\  \n"
        "  #wifi-sec.psk2 = \r\n"
        "  wifi-sec.psk4:",
        NM_UTILS_NAMED_VALUE_INIT("802-11-wireless-security.psk", "abc"),
        NM_UTILS_NAMED_VALUE_INIT("802-11-wireless-security.psk2", "def"),
        NM_UTILS_NAMED_VALUE_INIT("802-11-wireless-security.psk3", "e "),
        NM_UTILS_NAMED_VALUE_INIT("802-11-wireless-security.psk4", ""));
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/client/meta/check", test_client_meta_check);
    g_test_add_func("/client/import/wireguard/test0", test_client_import_wireguard_test0);
    g_test_add_func("/client/import/wireguard/test1", test_client_import_wireguard_test1);
    g_test_add_func("/client/import/wireguard/test2", test_client_import_wireguard_test2);
    g_test_add_func("/client/import/wireguard/test3", test_client_import_wireguard_test3);
    g_test_add_func("/client/import/wireguard/missing", test_client_import_wireguard_missing);
    g_test_add_func("/client/test_nmc_utils_parse_passwd_file", test_nmc_utils_parse_passwd_file);

    return g_test_run();
}
