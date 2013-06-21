#include "test-common.h"

#define DEVICE_NAME "nm-test-device"
#define IP4_ADDRESS "192.0.2.1"
#define IP4_PLEN 24
#define IP6_ADDRESS "2001:db8:a:b:1:2:3:4"
#define IP6_PLEN 64

static void
ip4_address_callback (NMPlatform *platform, int ifindex, NMPlatformIP4Address *received, SignalData *data)
{
	g_assert (received);
	g_assert_cmpint (received->ifindex, ==, ifindex);

	if (data->ifindex && data->ifindex != received->ifindex)
		return;

	if (data->loop)
		g_main_loop_quit (data->loop);

	if (data->received)
		g_error ("Received signal '%s' a second time.", data->name);

	data->received = TRUE;
}

static void
ip6_address_callback (NMPlatform *platform, int ifindex, NMPlatformIP6Address *received, SignalData *data)
{
	g_assert (received);
	g_assert_cmpint (received->ifindex, ==, ifindex);

	if (data->ifindex && data->ifindex != received->ifindex)
		return;

	if (data->loop)
		g_main_loop_quit (data->loop);

	if (data->received)
		g_error ("Received signal '%s' a second time.", data->name);

	data->received = TRUE;
}

static void
test_ip4_address (void)
{
	SignalData *address_added = add_signal (NM_PLATFORM_IP4_ADDRESS_ADDED, ip4_address_callback);
	SignalData *address_removed = add_signal (NM_PLATFORM_IP4_ADDRESS_REMOVED, ip4_address_callback);
	int ifindex = nm_platform_link_get_ifindex (DEVICE_NAME);
	GArray *addresses;
	NMPlatformIP4Address addrs[2];
	in_addr_t addr;

	inet_pton (AF_INET, IP4_ADDRESS, &addr);

	/* Add address */
	g_assert (!nm_platform_ip4_address_exists (ifindex, addr, IP4_PLEN));
	no_error ();
	g_assert (nm_platform_ip4_address_add (ifindex, addr, IP4_PLEN));
	no_error ();
	g_assert (nm_platform_ip4_address_exists (ifindex, addr, IP4_PLEN));
	no_error ();
	accept_signal (address_added);

	/* Add address again */
	g_assert (!nm_platform_ip4_address_add (ifindex, addr, IP4_PLEN));
	error (NM_PLATFORM_ERROR_EXISTS);

	/* Test address listing */
	addresses = nm_platform_ip4_address_get_all (ifindex);
	g_assert (addresses);
	no_error ();
	memset (addrs, 0, sizeof (addrs));
	addrs[0].ifindex = ifindex;
	addrs[0].address = addr;
	addrs[0].plen = IP4_PLEN;
	g_assert_cmpint (addresses->len, ==, 1);
	g_assert (!memcmp (addresses->data, addrs, sizeof (addrs)));
	g_array_unref (addresses);

	/* Remove address */
	g_assert (nm_platform_ip4_address_delete (ifindex, addr, IP4_PLEN));
	no_error ();
	g_assert (!nm_platform_ip4_address_exists (ifindex, addr, IP4_PLEN));
	accept_signal (address_removed);

	/* Remove address again */
	g_assert (!nm_platform_ip4_address_delete (ifindex, addr, IP4_PLEN));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	free_signal (address_added);
	free_signal (address_removed);
}

static void
test_ip6_address (void)
{
	SignalData *address_added = add_signal (NM_PLATFORM_IP6_ADDRESS_ADDED, ip6_address_callback);
	SignalData *address_removed = add_signal (NM_PLATFORM_IP6_ADDRESS_REMOVED, ip6_address_callback);
	int ifindex = nm_platform_link_get_ifindex (DEVICE_NAME);
	GArray *addresses;
	NMPlatformIP6Address addrs[2];
	struct in6_addr addr;

	inet_pton (AF_INET6, IP6_ADDRESS, &addr);

	/* Add address */
	g_assert (!nm_platform_ip6_address_exists (ifindex, addr, IP6_PLEN));
	no_error ();
	g_assert (nm_platform_ip6_address_add (ifindex, addr, IP6_PLEN));
	no_error ();
	g_assert (nm_platform_ip6_address_exists (ifindex, addr, IP6_PLEN));
	no_error ();
	accept_signal (address_added);

	/* Add address again */
	g_assert (!nm_platform_ip6_address_add (ifindex, addr, IP6_PLEN));
	error (NM_PLATFORM_ERROR_EXISTS);

	/* Test address listing */
	addresses = nm_platform_ip6_address_get_all (ifindex);
	g_assert (addresses);
	no_error ();
	memset (addrs, 0, sizeof (addrs));
	addrs[0].ifindex = ifindex;
	addrs[0].address = addr;
	addrs[0].plen = IP6_PLEN;
	g_assert_cmpint (addresses->len, ==, 1);
	g_assert (!memcmp (addresses->data, addrs, sizeof (addrs)));
	g_array_unref (addresses);

	/* Remove address */
	g_assert (nm_platform_ip6_address_delete (ifindex, addr, IP6_PLEN));
	no_error ();
	g_assert (!nm_platform_ip6_address_exists (ifindex, addr, IP6_PLEN));
	accept_signal (address_removed);

	/* Remove address again */
	g_assert (!nm_platform_ip6_address_delete (ifindex, addr, IP6_PLEN));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	free_signal (address_added);
	free_signal (address_removed);
}

static void
test_ip4_address_external (void)
{
	SignalData *address_added = add_signal (NM_PLATFORM_IP4_ADDRESS_ADDED, ip4_address_callback);
	SignalData *address_removed = add_signal (NM_PLATFORM_IP4_ADDRESS_REMOVED, ip4_address_callback);
	int ifindex = nm_platform_link_get_ifindex (DEVICE_NAME);
	in_addr_t addr;

	inet_pton (AF_INET, IP4_ADDRESS, &addr);
	g_assert (ifindex > 0);

	/* Looks like addresses are not announced by kerenl when the interface
	 * is down. Link-local IPv6 address is automatically added.
	 */
	g_assert (nm_platform_link_set_up (nm_platform_link_get_ifindex (DEVICE_NAME)));

	/* Add/delete notification */
	run_command ("ip address add %s/%d dev %s", IP4_ADDRESS, IP4_PLEN, DEVICE_NAME);
	wait_signal (address_added);
	g_assert (nm_platform_ip4_address_exists (ifindex, addr, IP4_PLEN));
	run_command ("ip address delete %s/%d dev %s", IP4_ADDRESS, IP4_PLEN, DEVICE_NAME);
	wait_signal (address_removed);
	g_assert (!nm_platform_ip4_address_exists (ifindex, addr, IP4_PLEN));

	/* Add/delete conflict */
	run_command ("ip address add %s/%d dev %s", IP4_ADDRESS, IP4_PLEN, DEVICE_NAME);
	g_assert (nm_platform_ip4_address_add (ifindex, addr, IP4_PLEN));
	no_error ();
	g_assert (nm_platform_ip4_address_exists (ifindex, addr, IP4_PLEN));
	accept_signal (address_added);
	/*run_command ("ip address delete %s/%d dev %s", IP4_ADDRESS, IP4_PLEN, DEVICE_NAME);
	g_assert (nm_platform_ip4_address_delete (ifindex, addr, IP4_PLEN));
	no_error ();
	g_assert (!nm_platform_ip4_address_exists (ifindex, addr, IP4_PLEN));
	accept_signal (address_removed);*/

	free_signal (address_added);
	free_signal (address_removed);
}

static void
test_ip6_address_external (void)
{
	SignalData *address_added = add_signal (NM_PLATFORM_IP6_ADDRESS_ADDED, ip6_address_callback);
	SignalData *address_removed = add_signal (NM_PLATFORM_IP6_ADDRESS_REMOVED, ip6_address_callback);
	int ifindex = nm_platform_link_get_ifindex (DEVICE_NAME);
	struct in6_addr addr;

	inet_pton (AF_INET6, IP6_ADDRESS, &addr);

	/* Add/delete notification */
	run_command ("ip address add %s/%d dev %s", IP6_ADDRESS, IP6_PLEN, DEVICE_NAME);
	wait_signal (address_added);
	g_assert (nm_platform_ip6_address_exists (ifindex, addr, IP6_PLEN));
	run_command ("ip address delete %s/%d dev %s", IP6_ADDRESS, IP6_PLEN, DEVICE_NAME);
	wait_signal (address_removed);
	g_assert (!nm_platform_ip6_address_exists (ifindex, addr, IP6_PLEN));

	/* Add/delete conflict */
	run_command ("ip address add %s/%d dev %s", IP6_ADDRESS, IP6_PLEN, DEVICE_NAME);
	g_assert (nm_platform_ip6_address_add (ifindex, addr, IP6_PLEN));
	no_error ();
	g_assert (nm_platform_ip6_address_exists (ifindex, addr, IP6_PLEN));
	accept_signal (address_added);
	/*run_command ("ip address delete %s/%d dev %s", IP6_ADDRESS, IP6_PLEN, DEVICE_NAME);
	g_assert (nm_platform_ip6_address_delete (ifindex, addr, IP6_PLEN));
	no_error ();
	g_assert (!nm_platform_ip6_address_exists (ifindex, addr, IP6_PLEN));
	wait_signal (address_removed);*/

	free_signal (address_added);
	free_signal (address_removed);
}

void
setup_tests (void)
{
	nm_platform_link_delete_by_name (DEVICE_NAME);
	g_assert (!nm_platform_link_exists (DEVICE_NAME));
	nm_platform_dummy_add (DEVICE_NAME);

	g_test_add_func ("/address/internal/ip4", test_ip4_address);
	g_test_add_func ("/address/internal/ip6", test_ip6_address);

	if (strcmp (g_type_name (G_TYPE_FROM_INSTANCE (nm_platform_get ())), "NMFakePlatform")) {
		g_test_add_func ("/address/external/ip4", test_ip4_address_external);
		g_test_add_func ("/address/external/ip6", test_ip6_address_external);
	}
}
