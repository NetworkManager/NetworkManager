/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Advantech Czech s.r.o.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-prog.h"
#include "libnm-glib-aux/nm-test-utils.h"

#include "nm-libnm-core-utils.h"
#include "nm-errors.h"

static void
empty_range_valid_for_null_addresses(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    result = nm_utils_validate_shared_dhcp_range("", addresses, &error);

    g_assert(result);
    g_assert_null(error);
}

static void
empty_range_valid_for_empty_addresses(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    addresses = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);

    result = nm_utils_validate_shared_dhcp_range("", addresses, &error);

    g_assert(result);
    g_assert_null(error);
}

static void
valid_range_for_single_address(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    addresses = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);
    g_ptr_array_add(addresses, nm_ip_address_new(AF_INET, "192.168.0.1", 24, NULL));

    result = nm_utils_validate_shared_dhcp_range("192.168.0.2,192.168.0.254", addresses, &error);

    g_assert(result);
    g_assert_null(error);
}

static void
valid_range_for_second_address(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    addresses = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);
    g_ptr_array_add(addresses, nm_ip_address_new(AF_INET, "192.168.0.1", 24, &error));
    g_ptr_array_add(addresses, nm_ip_address_new(AF_INET, "192.168.1.254", 24, &error));

    result = nm_utils_validate_shared_dhcp_range("192.168.1.2,192.168.1.254", addresses, &error);

    g_assert(result);
    g_assert_null(error);
}

static void
invalid_null_range_for_null_addresses(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    result = nm_utils_validate_shared_dhcp_range(NULL, addresses, &error);

    g_assert_false(result);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static void
invalid_null_range_for_empty_addresses(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    addresses = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);

    result = nm_utils_validate_shared_dhcp_range("192.168.1.2,192.168.1.254", addresses, &error);

    g_assert_false(result);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static void
any_range_invalid_for_null_addresses(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    result = nm_utils_validate_shared_dhcp_range("192.168.1.2,192.168.1.254", addresses, &error);

    g_assert_false(result);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static void
any_range_invalid_for_empty_addresses(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    addresses = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);

    result = nm_utils_validate_shared_dhcp_range("192.168.1.2,192.168.1.254", addresses, &error);

    g_assert_false(result);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static void
invalid_range_xyz(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    addresses = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);
    g_ptr_array_add(addresses, nm_ip_address_new(AF_INET, "192.168.0.1", 24, NULL));

    result = nm_utils_validate_shared_dhcp_range("xyz", addresses, &error);

    g_assert_false(result);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static void
invalid_range_single_comma(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    addresses = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);
    g_ptr_array_add(addresses, nm_ip_address_new(AF_INET, "192.168.0.1", 24, NULL));

    result = nm_utils_validate_shared_dhcp_range(",", addresses, &error);

    g_assert_false(result);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static void
invalid_first_address_of_range(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    addresses = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);
    g_ptr_array_add(addresses, nm_ip_address_new(AF_INET, "192.168.0.1", 24, NULL));

    result = nm_utils_validate_shared_dhcp_range("xyz,192.168.0.100", addresses, &error);

    g_assert_false(result);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static void
invalid_second_address_of_range(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    addresses = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);
    g_ptr_array_add(addresses, nm_ip_address_new(AF_INET, "192.168.0.1", 24, NULL));

    result = nm_utils_validate_shared_dhcp_range("192.168.0.100,xyz", addresses, &error);

    g_assert_false(result);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static void
invalid_inverted_range(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    addresses = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);
    g_ptr_array_add(addresses, nm_ip_address_new(AF_INET, "192.168.0.1", 24, NULL));

    result = nm_utils_validate_shared_dhcp_range("192.168.0.200,192.168.0.100", addresses, &error);

    g_assert_false(result);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static void
invalid_range_outside_address_space(void)
{
    gs_unref_ptrarray GPtrArray *addresses = NULL;
    gs_free_error GError        *error     = NULL;
    gboolean                     result;

    addresses = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);
    g_ptr_array_add(addresses, nm_ip_address_new(AF_INET, "192.168.0.1", 24, NULL));

    result = nm_utils_validate_shared_dhcp_range("192.168.1.2,192.168.1.100", addresses, &error);

    g_assert_false(result);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

/*****************************************************************************/

static void
valid_zero_lease_time(void)
{
    gs_free_error GError *error = NULL;
    gboolean              result;

    result = nm_utils_validate_shared_dhcp_lease_time(0, &error);

    g_assert(result);
    g_assert_null(error);
}

static void
minimal_valid_lease_time(void)
{
    gs_free_error GError *error = NULL;
    gboolean              result;

    result = nm_utils_validate_shared_dhcp_lease_time(NM_MIN_FINITE_LEASE_TIME, &error);

    g_assert(result);
    g_assert_null(error);
}

static void
middle_valid_lease_time(void)
{
    gs_free_error GError *error = NULL;
    gboolean              result;

    result = nm_utils_validate_shared_dhcp_lease_time(
        (NM_MIN_FINITE_LEASE_TIME + NM_MAX_FINITE_LEASE_TIME) / 2,
        &error);

    g_assert(result);
    g_assert_null(error);
}

static void
maximal_valid_lease_time(void)
{
    gs_free_error GError *error = NULL;
    gboolean              result;

    result = nm_utils_validate_shared_dhcp_lease_time(NM_MAX_FINITE_LEASE_TIME, &error);

    g_assert(result);
    g_assert_null(error);
}

static void
infinite_lease_time(void)
{
    gs_free_error GError *error = NULL;
    gboolean              result;

    result = nm_utils_validate_shared_dhcp_lease_time(G_MAXINT32, &error);

    g_assert(result);
    g_assert_null(error);
}

static void
too_small_lease_time(void)
{
    gs_free_error GError *error = NULL;
    gboolean              result;

    result = nm_utils_validate_shared_dhcp_lease_time(1, &error);

    g_assert_false(result);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static void
too_large_lease_time(void)
{
    gs_free_error GError *error = NULL;
    gboolean              result;

    result = nm_utils_validate_shared_dhcp_lease_time(NM_MAX_FINITE_LEASE_TIME + 1, &error);

    g_assert_false(result);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/core/utils/shared_dhcp_range/empty_range_valid_for_null_addresses",
                    empty_range_valid_for_null_addresses);
    g_test_add_func("/core/utils/shared_dhcp_range/empty_range_valid_for_empty_addresses",
                    empty_range_valid_for_empty_addresses);
    g_test_add_func("/core/utils/shared_dhcp_range/valid_range_for_single_address",
                    valid_range_for_single_address);
    g_test_add_func("/core/utils/shared_dhcp_range/valid_range_for_second_address",
                    valid_range_for_second_address);
    g_test_add_func("/core/utils/shared_dhcp_range/invalid_null_range_for_null_addresses",
                    invalid_null_range_for_null_addresses);
    g_test_add_func("/core/utils/shared_dhcp_range/invalid_null_range_for_empty_addresses",
                    invalid_null_range_for_empty_addresses);
    g_test_add_func("/core/utils/shared_dhcp_range/any_range_invalid_for_null_addresses",
                    any_range_invalid_for_null_addresses);
    g_test_add_func("/core/utils/shared_dhcp_range/any_range_invalid_for_empty_addresses",
                    any_range_invalid_for_empty_addresses);
    g_test_add_func("/core/utils/shared_dhcp_range/invalid_range_xyz", invalid_range_xyz);
    g_test_add_func("/core/utils/shared_dhcp_range/invalid_range_single_comma",
                    invalid_range_single_comma);
    g_test_add_func("/core/utils/shared_dhcp_range/invalid_first_address_of_range",
                    invalid_first_address_of_range);
    g_test_add_func("/core/utils/shared_dhcp_range/invalid_second_address_of_range",
                    invalid_second_address_of_range);
    g_test_add_func("/core/utils/shared_dhcp_range/invalid_inverted_range", invalid_inverted_range);
    g_test_add_func("/core/utils/shared_dhcp_range/invalid_range_outside_address_space",
                    invalid_range_outside_address_space);

    g_test_add_func("/core/utils/shared_dhcp_lease_time/valid_zero_lease_time",
                    valid_zero_lease_time);
    g_test_add_func("/core/utils/shared_dhcp_lease_time/minimal_valid_lease_time",
                    minimal_valid_lease_time);
    g_test_add_func("/core/utils/shared_dhcp_lease_time/middle_valid_lease_time",
                    middle_valid_lease_time);
    g_test_add_func("/core/utils/shared_dhcp_lease_time/maximal_valid_lease_time",
                    maximal_valid_lease_time);
    g_test_add_func("/core/utils/shared_dhcp_lease_time/infinite_lease_time", infinite_lease_time);
    g_test_add_func("/core/utils/shared_dhcp_lease_time/too_small_lease_time",
                    too_small_lease_time);
    g_test_add_func("/core/utils/shared_dhcp_lease_time/too_large_lease_time",
                    too_large_lease_time);

    return g_test_run();
}
