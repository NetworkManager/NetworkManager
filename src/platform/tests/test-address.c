/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager audit support
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * Copyright 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "test-common.h"

#define IP4_ADDRESS "192.0.2.1"
#define IP4_ADDRESS_PEER "192.0.2.2"
#define IP4_ADDRESS_PEER2 "192.0.3.1"
#define IP4_PLEN 24
#define IP6_ADDRESS "2001:db8:a:b:1:2:3:4"
#define IP6_PLEN 64

#define DEVICE_IFINDEX NMTSTP_ENV1_IFINDEX
#define EX             NMTSTP_ENV1_EX

/*****************************************************************************/

static void
ip4_address_callback (NMPlatform *platform, NMPObjectType obj_type, int ifindex, NMPlatformIP4Address *received, NMPlatformSignalChangeType change_type, SignalData *data)
{
	g_assert (received);
	g_assert_cmpint (received->ifindex, ==, ifindex);
	g_assert (data && data->name);
	g_assert_cmpstr (data->name, ==, NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED);

	if (data->ifindex && data->ifindex != received->ifindex)
		return;
	if (data->change_type != change_type)
		return;

	if (data->loop)
		g_main_loop_quit (data->loop);

	data->received_count++;
	_LOGD ("Received signal '%s' %dth time.", data->name, data->received_count);
}

static void
ip6_address_callback (NMPlatform *platform, NMPObjectType obj_type, int ifindex, NMPlatformIP6Address *received, NMPlatformSignalChangeType change_type, SignalData *data)
{
	g_assert (received);
	g_assert_cmpint (received->ifindex, ==, ifindex);
	g_assert (data && data->name);
	g_assert_cmpstr (data->name, ==, NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED);

	if (data->ifindex && data->ifindex != received->ifindex)
		return;
	if (data->change_type != change_type)
		return;

	if (data->loop)
		g_main_loop_quit (data->loop);

	data->received_count++;
	_LOGD ("Received signal '%s' %dth time.", data->name, data->received_count);
}

/*****************************************************************************/

static void
test_ip4_address_general (void)
{
	const int ifindex = DEVICE_IFINDEX;
	SignalData *address_added = add_signal_ifindex (NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_ADDED, ip4_address_callback, ifindex);
	SignalData *address_changed = add_signal_ifindex (NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_CHANGED, ip4_address_callback, ifindex);
	SignalData *address_removed = add_signal_ifindex (NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, ip4_address_callback, ifindex);
	GArray *addresses;
	NMPlatformIP4Address *address;
	in_addr_t addr;
	guint32 lifetime = 2000;
	guint32 preferred = 1000;

	inet_pton (AF_INET, IP4_ADDRESS, &addr);

	/* Add address */
	g_assert (!nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, addr));
	nmtstp_ip4_address_add (NULL, EX, ifindex, addr, IP4_PLEN, addr, lifetime, preferred, 0, NULL);
	g_assert (nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, addr));
	accept_signal (address_added);

	/* Add address again (aka update) */
	nmtstp_ip4_address_add (NULL, EX, ifindex, addr, IP4_PLEN, addr, lifetime + 100, preferred + 50, 0, NULL);
	accept_signals (address_changed, 0, 1);

	/* Test address listing */
	addresses = nmtstp_platform_ip4_address_get_all (NM_PLATFORM_GET, ifindex);
	g_assert (addresses);
	g_assert_cmpint (addresses->len, ==, 1);
	address = &g_array_index (addresses, NMPlatformIP4Address, 0);
	g_assert_cmpint (address->ifindex, ==, ifindex);
	g_assert_cmphex (address->address, ==, addr);
	g_assert_cmphex (address->peer_address, ==, addr);
	g_assert_cmpint (address->plen, ==, IP4_PLEN);
	g_array_unref (addresses);

	/* Remove address */
	nmtstp_ip4_address_del (NULL, EX, ifindex, addr, IP4_PLEN, addr);
	g_assert (!nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, addr));
	accept_signal (address_removed);

	/* Remove address again */
	nmtstp_ip4_address_del (NULL, EX, ifindex, addr, IP4_PLEN, addr);

	free_signal (address_added);
	free_signal (address_changed);
	free_signal (address_removed);
}

static void
test_ip6_address_general (void)
{
	const int ifindex = DEVICE_IFINDEX;
	SignalData *address_added = add_signal_ifindex (NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_ADDED, ip6_address_callback, ifindex);
	SignalData *address_changed = add_signal_ifindex (NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_CHANGED, ip6_address_callback, ifindex);
	SignalData *address_removed = add_signal_ifindex (NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, ip6_address_callback, ifindex);
	GArray *addresses;
	NMPlatformIP6Address *address;
	struct in6_addr addr;
	guint32 lifetime = 2000;
	guint32 preferred = 1000;
	guint flags = 0;

	inet_pton (AF_INET6, IP6_ADDRESS, &addr);

	/* Add address */
	g_assert (!nm_platform_ip6_address_get (NM_PLATFORM_GET, ifindex, addr));
	nmtstp_ip6_address_add (NULL, EX, ifindex, addr, IP6_PLEN, in6addr_any, lifetime, preferred, flags);
	g_assert (nm_platform_ip6_address_get (NM_PLATFORM_GET, ifindex, addr));
	accept_signal (address_added);

	/* Add address again (aka update) */
	nmtstp_ip6_address_add (NULL, EX, ifindex, addr, IP6_PLEN, in6addr_any, lifetime, preferred, flags);
	accept_signals (address_changed, 0, 1);

	/* Test address listing */
	addresses = nmtstp_platform_ip6_address_get_all (NM_PLATFORM_GET, ifindex);
	g_assert (addresses);
	g_assert_cmpint (addresses->len, ==, 1);
	address = &g_array_index (addresses, NMPlatformIP6Address, 0);
	g_assert_cmpint (address->ifindex, ==, ifindex);
	g_assert (!memcmp (&address->address, &addr, sizeof (addr)));
	g_assert_cmpint (address->plen, ==, IP6_PLEN);
	g_array_unref (addresses);

	/* Remove address */
	nmtstp_ip6_address_del (NULL, EX, ifindex, addr, IP6_PLEN);
	g_assert (!nm_platform_ip6_address_get (NM_PLATFORM_GET, ifindex, addr));
	accept_signal (address_removed);

	/* Remove address again */
	nmtstp_ip6_address_del (NULL, EX, ifindex, addr, IP6_PLEN);

	/* ensure not pending signal. */
	accept_signals (address_changed, 0, 1);

	free_signal (address_added);
	free_signal (address_changed);
	free_signal (address_removed);
}

static void
test_ip4_address_general_2 (void)
{
	const int ifindex = DEVICE_IFINDEX;
	SignalData *address_added = add_signal (NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_ADDED, ip4_address_callback);
	SignalData *address_removed = add_signal (NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, ip4_address_callback);
	in_addr_t addr;
	guint32 lifetime = 2000;
	guint32 preferred = 1000;

	inet_pton (AF_INET, IP4_ADDRESS, &addr);
	g_assert (ifindex > 0);

	/* Looks like addresses are not announced by kerenl when the interface
	 * is down. Link-local IPv6 address is automatically added.
	 */
	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, DEVICE_IFINDEX, NULL));

	/* Add/delete notification */
	nmtstp_ip4_address_add (NULL, EX, ifindex, addr, IP4_PLEN, addr, lifetime, preferred, 0, NULL);
	accept_signal (address_added);
	g_assert (nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, addr));
	nmtstp_ip4_address_del (NULL, EX, ifindex, addr, IP4_PLEN, addr);
	accept_signal (address_removed);
	g_assert (!nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, addr));

	/* Add/delete conflict */
	nmtstp_ip4_address_add (NULL, EX, ifindex, addr, IP4_PLEN, addr, lifetime, preferred, 0, NULL);
	g_assert (nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, addr));
	accept_signal (address_added);

	free_signal (address_added);
	free_signal (address_removed);
}

static void
test_ip6_address_general_2 (void)
{
	const int ifindex = DEVICE_IFINDEX;
	SignalData *address_added = add_signal (NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_ADDED, ip6_address_callback);
	SignalData *address_removed = add_signal (NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, ip6_address_callback);
	struct in6_addr addr;
	guint32 lifetime = 2000;
	guint32 preferred = 1000;
	guint flags = 0;

	inet_pton (AF_INET6, IP6_ADDRESS, &addr);

	/* Add/delete notification */
	nmtstp_ip6_address_add (NULL, EX, ifindex, addr, IP6_PLEN, in6addr_any, lifetime, preferred, 0);
	accept_signal (address_added);
	g_assert (nm_platform_ip6_address_get (NM_PLATFORM_GET, ifindex, addr));

	nmtstp_ip6_address_del (NULL, EX, ifindex, addr, IP6_PLEN);
	accept_signal (address_removed);
	g_assert (!nm_platform_ip6_address_get (NM_PLATFORM_GET, ifindex, addr));

	/* Add/delete conflict */
	nmtstp_ip6_address_add (NULL, EX, ifindex, addr, IP6_PLEN, in6addr_any, lifetime, preferred, 0);
	accept_signal (address_added);
	g_assert (nm_platform_ip6_address_get (NM_PLATFORM_GET, ifindex, addr));

	nmtstp_ip6_address_add (NULL, EX, ifindex, addr, IP6_PLEN, in6addr_any, lifetime, preferred, flags);
	ensure_no_signal (address_added);
	g_assert (nm_platform_ip6_address_get (NM_PLATFORM_GET, ifindex, addr));

	free_signal (address_added);
	free_signal (address_removed);
}

/*****************************************************************************/

static void
test_ip4_address_peer (void)
{
	const int ifindex = DEVICE_IFINDEX;
	SignalData *address_added = add_signal (NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_ADDED, ip4_address_callback);
	SignalData *address_removed = add_signal (NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, ip4_address_callback);
	in_addr_t addr, addr_peer, addr_peer2;
	guint32 lifetime = 2000;
	guint32 preferred = 1000;
	const NMPlatformIP4Address *a;

	inet_pton (AF_INET, IP4_ADDRESS, &addr);
	inet_pton (AF_INET, IP4_ADDRESS_PEER, &addr_peer);
	inet_pton (AF_INET, IP4_ADDRESS_PEER2, &addr_peer2);
	g_assert (ifindex > 0);

	g_assert (addr != addr_peer);

	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, ifindex, NULL));
	accept_signals (address_removed, 0, G_MAXINT);
	accept_signals (address_added, 0, G_MAXINT);

	/* Add/delete notification */
	nmtstp_ip4_address_add (NULL, EX, ifindex, addr, IP4_PLEN, addr_peer, lifetime, preferred, 0, NULL);
	accept_signal (address_added);
	a = nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, addr_peer);
	g_assert (a);
	g_assert (!nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, addr_peer2));

	nmtstp_ip_address_assert_lifetime ((NMPlatformIPAddress *) a, -1, lifetime, preferred);

	nmtstp_ip4_address_add (NULL, EX, ifindex, addr, IP4_PLEN, addr_peer2, lifetime, preferred, 0, NULL);
	accept_signal (address_added);
	g_assert (nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, addr_peer));
	a = nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, addr_peer2);
	g_assert (a);

	nmtstp_ip_address_assert_lifetime ((NMPlatformIPAddress *) a, -1, lifetime, preferred);

	g_assert (addr != addr_peer);
	nmtstp_ip4_address_del (NULL, EX, ifindex, addr, IP4_PLEN, addr_peer);
	accept_signal (address_removed);
	g_assert (!nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, addr_peer));
	g_assert (nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, addr_peer2));

	free_signal (address_added);
	free_signal (address_removed);
}

/*****************************************************************************/

static void
test_ip4_address_peer_zero (void)
{
	const int ifindex = DEVICE_IFINDEX;
	in_addr_t addr, addr_peer;
	guint32 lifetime = 2000;
	guint32 preferred = 1000;
	const gint8 plen = 24;
	const char *label = NULL;
	in_addr_t peers[3], r_peers[3];
	int i;
	GArray *addrs;

	g_assert (ifindex > 0);

	inet_pton (AF_INET, "192.168.5.2", &addr);
	inet_pton (AF_INET, "192.168.6.2", &addr_peer);
	peers[0] = addr;
	peers[1] = addr_peer;
	peers[2] = 0;

	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, ifindex, NULL));

	nmtst_rand_perm (NULL, r_peers, peers, sizeof (peers[0]), G_N_ELEMENTS (peers));
	for (i = 0; i < G_N_ELEMENTS (peers); i++) {
		g_assert (!nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, plen, r_peers[i]));

		nmtstp_ip4_address_add (NULL, EX, ifindex, addr, plen, r_peers[i], lifetime, preferred, 0, label);

		addrs = nmtstp_platform_ip4_address_get_all (NM_PLATFORM_GET, ifindex);
		g_assert (addrs);
		g_assert_cmpint (addrs->len, ==, i + 1);
		g_array_unref (addrs);
	}

	if (nmtst_is_debug () && nmtstp_is_root_test ())
		nmtstp_run_command_check ("ip address show dev %s", DEVICE_NAME);

	nmtst_rand_perm (NULL, r_peers, peers, sizeof (peers[0]), G_N_ELEMENTS (peers));
	for (i = 0; i < G_N_ELEMENTS (peers); i++) {
		g_assert (nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, addr, plen, r_peers[i]));

		nmtstp_ip4_address_del (NULL, EX, ifindex, addr, plen, r_peers[i]);

		addrs = nmtstp_platform_ip4_address_get_all (NM_PLATFORM_GET, ifindex);
		g_assert (addrs);
		g_assert_cmpint (addrs->len, ==, G_N_ELEMENTS (peers) - i - 1);
		g_array_unref (addrs);
	}
}

/*****************************************************************************/

NMTstpSetupFunc const _nmtstp_setup_platform_func = SETUP;

void
_nmtstp_init_tests (int *argc, char ***argv)
{
	nmtst_init_with_logging (argc, argv, NULL, "ALL");
}

/*****************************************************************************
 * SETUP TESTS
 *****************************************************************************/

void
_nmtstp_setup_tests (void)
{
#define add_test_func(testpath, test_func) nmtstp_env1_add_test_func(testpath, test_func, FALSE)
	add_test_func ("/address/ipv4/general", test_ip4_address_general);
	add_test_func ("/address/ipv6/general", test_ip6_address_general);

	add_test_func ("/address/ipv4/general-2", test_ip4_address_general_2);
	add_test_func ("/address/ipv6/general-2", test_ip6_address_general_2);

	add_test_func ("/address/ipv4/peer", test_ip4_address_peer);
	add_test_func ("/address/ipv4/peer/zero", test_ip4_address_peer_zero);
}
