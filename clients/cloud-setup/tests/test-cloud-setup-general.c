/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "libnm/nm-default-client.h"

#include "nm-cloud-setup-utils.h"
#include "nm-libnm-core-intern/nm-libnm-core-utils.h"

#include "nm-utils/nm-test-utils.h"

/*****************************************************************************/

static NMSettingIPConfig *
_ri4a_new_s_ip(const char *const *addrs)
{
    NMSettingIPConfig *s_ip;

    s_ip = NM_SETTING_IP_CONFIG(nm_setting_ip4_config_new());

    for (; addrs && addrs[0]; addrs++) {
        nm_auto_unref_ip_address NMIPAddress *a = nmtst_ip_address_new(AF_INET, addrs[0]);

        nm_setting_ip_config_add_address(s_ip, a);
    }
    return s_ip;
}

static GPtrArray *
_ri4a_new_arr(const char *const *addrs)
{
    GPtrArray *arr;

    arr = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);

    for (; addrs && addrs[0]; addrs++)
        g_ptr_array_add(arr, nmtst_ip_address_new(AF_INET, addrs[0]));

    return arr;
}

static void
_test_ri4a(const char *const *addrs_before, const char *const *addrs_new)
{
    gs_unref_object NMSettingIPConfig *s_ip = NULL;
    gs_unref_ptrarray GPtrArray *arr        = NULL;
    const gsize                  n          = NM_PTRARRAY_LEN(addrs_new);
    gboolean                     changed;
    gsize                        i;

    s_ip = _ri4a_new_s_ip(addrs_before);
    arr  = _ri4a_new_arr(addrs_new);

    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip),
                    ==,
                    NM_PTRARRAY_LEN(addrs_before));
    g_assert_cmpint(arr->len, ==, n);

    changed = nmcs_setting_ip_replace_ipv4_addresses(s_ip, (NMIPAddress **) arr->pdata, arr->len);

    g_assert_cmpint(changed, !=, nm_utils_strv_equal(addrs_before, addrs_new));
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip), ==, n);

    for (i = 0; i < n; i++) {
        NMIPAddress *a = arr->pdata[i];
        NMIPAddress *b = nm_setting_ip_config_get_address(s_ip, i);

        if (nmtst_get_rand_bool())
            NM_SWAP(&a, &b);

        g_assert(nm_ip_address_cmp_full(a, b, NM_IP_ADDRESS_CMP_FLAGS_WITH_ATTRS) == 0);
    }
}

static void
test_replace_ipv4_addresses(void)
{
    const char *const *const LISTS[] = {
        NM_MAKE_STRV(),
        NM_MAKE_STRV("192.168.5.1/24"),
        NM_MAKE_STRV("192.168.5.1/24", "192.168.5.2/24"),
        NM_MAKE_STRV("192.168.5.1/24", "192.168.5.2/24", "192.168.5.3/24"),
        NM_MAKE_STRV("192.168.5.1/24", "192.168.5.2/24", "192.168.5.3/24", "192.168.5.4/24"),
    };
    int i_run;

    for (i_run = 0; i_run < 20; i_run++) {
        gs_free const char **addrs_before = NULL;
        gs_free const char **addrs_new    = NULL;

        addrs_before = nmtst_rand_perm_strv(LISTS[nmtst_get_rand_uint32() % G_N_ELEMENTS(LISTS)]);
        addrs_new    = nmtst_rand_perm_strv(LISTS[nmtst_get_rand_uint32() % G_N_ELEMENTS(LISTS)]);

        _test_ri4a(addrs_before, addrs_new);
    }

    _test_ri4a(NM_MAKE_STRV(), NM_MAKE_STRV());
    _test_ri4a(NM_MAKE_STRV(), NM_MAKE_STRV("192.168.5.1/24"));
    _test_ri4a(NM_MAKE_STRV(), NM_MAKE_STRV("192.168.5.1/24", "192.168.5.2/24"));
    _test_ri4a(NM_MAKE_STRV("192.168.5.1/24"), NM_MAKE_STRV());
    _test_ri4a(NM_MAKE_STRV("192.168.5.1/24"), NM_MAKE_STRV("192.168.5.1/24"));
    _test_ri4a(NM_MAKE_STRV("192.168.5.1/24", "192.168.5.2/24"), NM_MAKE_STRV());
    _test_ri4a(NM_MAKE_STRV("192.168.5.1/24", "192.168.5.2/24"), NM_MAKE_STRV("192.168.5.1/24"));
    _test_ri4a(NM_MAKE_STRV("192.168.5.1/24", "192.168.5.2/24"), NM_MAKE_STRV("192.168.5.2/24"));
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/cloud-setup/general/replace-ipv4-addresses", test_replace_ipv4_addresses);

    return g_test_run();
}
