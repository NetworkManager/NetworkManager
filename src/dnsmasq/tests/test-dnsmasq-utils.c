/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2013 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <arpa/inet.h>

#include "dnsmasq/nm-dnsmasq-utils.h"

#include "nm-test-utils-core.h"

static void
test_address_ranges (void)
{
#define _test_address_range(addr, plen, expected_first, expected_last) \
	G_STMT_START { \
		char *_error_desc = NULL; \
		char _first[INET_ADDRSTRLEN]; \
		char _last[INET_ADDRSTRLEN]; \
		\
		if (!nm_dnsmasq_utils_get_range (nmtst_platform_ip4_address ((addr""), NULL, (plen)), \
		                                 _first, _last, &_error_desc)) \
			g_assert_not_reached (); \
		g_assert (!_error_desc); \
		g_assert_cmpstr (_first, ==, (expected_first"")); \
		g_assert_cmpstr (_last, ==, (expected_last"")); \
		g_assert_cmpint ((ntohl (nmtst_inet4_from_string (_last)) - ntohl (nmtst_inet4_from_string (_first))), <=, 244); \
	} G_STMT_END

#define _test_address_range_fail(addr, plen) \
	G_STMT_START { \
		char *_error_desc = NULL; \
		char _first[INET_ADDRSTRLEN]; \
		char _last[INET_ADDRSTRLEN]; \
		\
		if (nm_dnsmasq_utils_get_range (nmtst_platform_ip4_address ((addr""), NULL, (plen)), \
		                                _first, _last, &_error_desc)) \
			g_assert_not_reached (); \
		g_assert (_error_desc); \
		g_free (_error_desc); \
	} G_STMT_END

	_test_address_range_fail ("1.2.3.1", 31);

	_test_address_range ("0.0.0.0", 30, "0.0.0.2",  "0.0.0.2");
	_test_address_range ("0.0.0.1", 30, "0.0.0.2",  "0.0.0.2");
	_test_address_range ("0.0.0.2", 30, "0.0.0.1",  "0.0.0.1");
	_test_address_range ("0.0.0.3", 30, "0.0.0.1",  "0.0.0.1");
	_test_address_range ("1.2.3.0", 30, "1.2.3.2",  "1.2.3.2");
	_test_address_range ("1.2.3.1", 30, "1.2.3.2",  "1.2.3.2");
	_test_address_range ("1.2.3.2", 30, "1.2.3.1",  "1.2.3.1");
	_test_address_range ("1.2.3.3", 30, "1.2.3.1",  "1.2.3.1");
	_test_address_range ("1.2.3.4", 30, "1.2.3.6",  "1.2.3.6");
	_test_address_range ("1.2.3.5", 30, "1.2.3.6",  "1.2.3.6");
	_test_address_range ("1.2.3.6", 30, "1.2.3.5",  "1.2.3.5");
	_test_address_range ("1.2.3.7", 30, "1.2.3.5",  "1.2.3.5");
	_test_address_range ("1.2.3.8", 30, "1.2.3.10", "1.2.3.10");
	_test_address_range ("1.2.3.9", 30, "1.2.3.10", "1.2.3.10");
	_test_address_range ("255.255.255.0", 30, "255.255.255.2",  "255.255.255.2");
	_test_address_range ("255.255.255.1", 30, "255.255.255.2",  "255.255.255.2");
	_test_address_range ("255.255.255.2", 30, "255.255.255.1",  "255.255.255.1");
	_test_address_range ("255.255.255.3", 30, "255.255.255.1",  "255.255.255.1");
	_test_address_range ("255.255.255.248", 30, "255.255.255.250",  "255.255.255.250");
	_test_address_range ("255.255.255.249", 30, "255.255.255.250",  "255.255.255.250");
	_test_address_range ("255.255.255.250", 30, "255.255.255.249",  "255.255.255.249");
	_test_address_range ("255.255.255.251", 30, "255.255.255.249",  "255.255.255.249");
	_test_address_range ("255.255.255.252", 30, "255.255.255.254",  "255.255.255.254");
	_test_address_range ("255.255.255.253", 30, "255.255.255.254",  "255.255.255.254");
	_test_address_range ("255.255.255.254", 30, "255.255.255.253",  "255.255.255.253");
	_test_address_range ("255.255.255.255", 30, "255.255.255.253",  "255.255.255.253");

	_test_address_range ("0.0.0.0", 29, "0.0.0.2",  "0.0.0.6");
	_test_address_range ("0.0.0.1", 29, "0.0.0.2",  "0.0.0.6");
	_test_address_range ("0.0.0.2", 29, "0.0.0.3",  "0.0.0.6");
	_test_address_range ("0.0.0.3", 29, "0.0.0.4",  "0.0.0.6");
	_test_address_range ("0.0.0.4", 29, "0.0.0.1",  "0.0.0.3");
	_test_address_range ("0.0.0.5", 29, "0.0.0.1",  "0.0.0.4");
	_test_address_range ("0.0.0.6", 29, "0.0.0.1",  "0.0.0.5");
	_test_address_range ("0.0.0.7", 29, "0.0.0.1",  "0.0.0.5");
	_test_address_range ("0.0.0.8", 29, "0.0.0.10", "0.0.0.14");
	_test_address_range ("0.0.0.9", 29, "0.0.0.10", "0.0.0.14");
	_test_address_range ("1.2.3.0", 29, "1.2.3.2",  "1.2.3.6");
	_test_address_range ("1.2.3.1", 29, "1.2.3.2",  "1.2.3.6");
	_test_address_range ("1.2.3.2", 29, "1.2.3.3",  "1.2.3.6");
	_test_address_range ("1.2.3.3", 29, "1.2.3.4",  "1.2.3.6");
	_test_address_range ("1.2.3.4", 29, "1.2.3.1",  "1.2.3.3");
	_test_address_range ("1.2.3.5", 29, "1.2.3.1",  "1.2.3.4");
	_test_address_range ("1.2.3.6", 29, "1.2.3.1",  "1.2.3.5");
	_test_address_range ("1.2.3.7", 29, "1.2.3.1",  "1.2.3.5");
	_test_address_range ("1.2.3.8", 29, "1.2.3.10", "1.2.3.14");
	_test_address_range ("1.2.3.9", 29, "1.2.3.10", "1.2.3.14");
	_test_address_range ("255.255.255.248", 29, "255.255.255.250",  "255.255.255.254");
	_test_address_range ("255.255.255.249", 29, "255.255.255.250",  "255.255.255.254");
	_test_address_range ("255.255.255.250", 29, "255.255.255.251",  "255.255.255.254");
	_test_address_range ("255.255.255.251", 29, "255.255.255.252",  "255.255.255.254");
	_test_address_range ("255.255.255.252", 29, "255.255.255.249",  "255.255.255.251");
	_test_address_range ("255.255.255.253", 29, "255.255.255.249",  "255.255.255.252");
	_test_address_range ("255.255.255.254", 29, "255.255.255.249",  "255.255.255.253");
	_test_address_range ("255.255.255.255", 29, "255.255.255.249",  "255.255.255.253");

	_test_address_range ("1.2.3.1", 29, "1.2.3.2", "1.2.3.6");
	_test_address_range ("1.2.3.1", 28, "1.2.3.3", "1.2.3.14");
	_test_address_range ("1.2.3.1", 26, "1.2.3.8", "1.2.3.62");

	_test_address_range ("192.167.255.255", 24, "192.167.255.1", "192.167.255.245");
	_test_address_range ("192.168.0.0",     24, "192.168.0.10",  "192.168.0.254");
	_test_address_range ("192.168.0.1",     24, "192.168.0.10",  "192.168.0.254");
	_test_address_range ("192.168.0.2",     24, "192.168.0.11",  "192.168.0.254");
	_test_address_range ("192.168.0.99",    24, "192.168.0.108", "192.168.0.254");
	_test_address_range ("192.168.0.126",   24, "192.168.0.135", "192.168.0.254");
	_test_address_range ("192.168.0.127",   24, "192.168.0.136", "192.168.0.254");
	_test_address_range ("192.168.0.128",   24, "192.168.0.1",   "192.168.0.119");
	_test_address_range ("192.168.0.129",   24, "192.168.0.1",   "192.168.0.120");
	_test_address_range ("192.168.0.130",   24, "192.168.0.1",   "192.168.0.121");
	_test_address_range ("192.168.0.254",   24, "192.168.0.1",   "192.168.0.245");
	_test_address_range ("192.168.0.255",   24, "192.168.0.1",   "192.168.0.245");
	_test_address_range ("192.168.1.0",     24, "192.168.1.10",  "192.168.1.254");
	_test_address_range ("192.168.1.1",     24, "192.168.1.10",  "192.168.1.254");
	_test_address_range ("192.168.1.2",     24, "192.168.1.11",  "192.168.1.254");
	_test_address_range ("192.168.1.10",    24, "192.168.1.19",  "192.168.1.254");
	_test_address_range ("192.168.15.253",  24, "192.168.15.1",  "192.168.15.244");
	_test_address_range ("192.168.15.254",  24, "192.168.15.1",  "192.168.15.245");
	_test_address_range ("192.168.15.255",  24, "192.168.15.1",  "192.168.15.245");
	_test_address_range ("192.168.16.0",    24, "192.168.16.10", "192.168.16.254");
	_test_address_range ("192.168.16.1",    24, "192.168.16.10", "192.168.16.254");

	_test_address_range ("192.167.255.255", 20, "192.167.255.1", "192.167.255.245");
	_test_address_range ("192.168.0.0",     20, "192.168.0.10",  "192.168.0.254");
	_test_address_range ("192.168.0.1",     20, "192.168.0.10",  "192.168.0.254");
	_test_address_range ("192.168.0.2",     20, "192.168.0.11",  "192.168.0.254");
	_test_address_range ("192.168.0.126",   20, "192.168.0.135", "192.168.0.254");
	_test_address_range ("192.168.0.127",   20, "192.168.0.136", "192.168.0.254");
	_test_address_range ("192.168.0.128",   20, "192.168.0.1",   "192.168.0.119");
	_test_address_range ("192.168.0.129",   20, "192.168.0.1",   "192.168.0.120");
	_test_address_range ("192.168.0.130",   20, "192.168.0.1",   "192.168.0.121");
	_test_address_range ("192.168.0.254",   20, "192.168.0.1",   "192.168.0.245");
	_test_address_range ("192.168.0.255",   20, "192.168.0.1",   "192.168.0.245");
	_test_address_range ("192.168.1.0",     20, "192.168.1.10",  "192.168.1.254");
	_test_address_range ("192.168.1.1",     20, "192.168.1.10",  "192.168.1.254");
	_test_address_range ("192.168.1.2",     20, "192.168.1.11",  "192.168.1.254");
	_test_address_range ("192.168.1.10",    20, "192.168.1.19",  "192.168.1.254");
	_test_address_range ("192.168.15.253",  20, "192.168.15.1",  "192.168.15.244");
	_test_address_range ("192.168.15.254",  20, "192.168.15.1",  "192.168.15.245");
	_test_address_range ("192.168.15.255",  20, "192.168.15.1",  "192.168.15.245");
	_test_address_range ("192.168.16.0",    20, "192.168.16.10", "192.168.16.254");
	_test_address_range ("192.168.16.1",    20, "192.168.16.10", "192.168.16.254");
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	g_test_add_func ("/dnsmasq/address-ranges", test_address_ranges);

	return g_test_run ();
}

