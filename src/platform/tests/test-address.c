#include "config.h"

#include "test-common.h"

#define DEVICE_NAME "nm-test-device"
#define IP4_ADDRESS "192.0.2.1"
#define IP4_PLEN 24
#define IP6_ADDRESS "2001:db8:a:b:1:2:3:4"
#define IP6_PLEN 64

static void
ip4_address_callback (NMPlatform *platform, int ifindex, NMPlatformIP4Address *received, NMPlatformSignalChangeType change_type, NMPlatformReason reason, SignalData *data)
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
	debug ("Received signal '%s' %dth time.", data->name, data->received_count);
}

static void
ip6_address_callback (NMPlatform *platform, int ifindex, NMPlatformIP6Address *received, NMPlatformSignalChangeType change_type, NMPlatformReason reason, SignalData *data)
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
	debug ("Received signal '%s' %dth time.", data->name, data->received_count);
}

static void
test_ip4_address (void)
{
	int ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
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
	g_assert (!nm_platform_ip4_address_exists (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN));
	no_error ();
	g_assert (nm_platform_ip4_address_add (NM_PLATFORM_GET, ifindex, addr, 0, IP4_PLEN, lifetime, preferred, NULL));
	no_error ();
	g_assert (nm_platform_ip4_address_exists (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN));
	no_error ();
	accept_signal (address_added);

	/* Add address again (aka update) */
	g_assert (nm_platform_ip4_address_add (NM_PLATFORM_GET, ifindex, addr, 0, IP4_PLEN, lifetime, preferred, NULL));
	no_error ();
	accept_signals (address_changed, 0, 1);

	/* Test address listing */
	addresses = nm_platform_ip4_address_get_all (NM_PLATFORM_GET, ifindex);
	g_assert (addresses);
	no_error ();
	g_assert_cmpint (addresses->len, ==, 1);
	address = &g_array_index (addresses, NMPlatformIP4Address, 0);
	g_assert_cmpint (address->ifindex, ==, ifindex);
	g_assert_cmphex (address->address, ==, addr);
	g_assert_cmpint (address->plen, ==, IP4_PLEN);
	g_array_unref (addresses);

	/* Remove address */
	g_assert (nm_platform_ip4_address_delete (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, 0));
	no_error ();
	g_assert (!nm_platform_ip4_address_exists (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN));
	accept_signal (address_removed);

	/* Remove address again */
	g_assert (nm_platform_ip4_address_delete (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN, 0));
	no_error ();

	free_signal (address_added);
	free_signal (address_changed);
	free_signal (address_removed);
}

static void
test_ip6_address (void)
{
	int ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
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
	g_assert (!nm_platform_ip6_address_exists (NM_PLATFORM_GET, ifindex, addr, IP6_PLEN));
	no_error ();
	g_assert (nm_platform_ip6_address_add (NM_PLATFORM_GET, ifindex, addr, in6addr_any, IP6_PLEN, lifetime, preferred, flags));
	no_error ();
	g_assert (nm_platform_ip6_address_exists (NM_PLATFORM_GET, ifindex, addr, IP6_PLEN));
	no_error ();
	accept_signal (address_added);

	/* Add address again (aka update) */
	g_assert (nm_platform_ip6_address_add (NM_PLATFORM_GET, ifindex, addr, in6addr_any, IP6_PLEN, lifetime, preferred, flags));
	no_error ();
	accept_signals (address_changed, 0, 1);

	/* Test address listing */
	addresses = nm_platform_ip6_address_get_all (NM_PLATFORM_GET, ifindex);
	g_assert (addresses);
	no_error ();
	g_assert_cmpint (addresses->len, ==, 1);
	address = &g_array_index (addresses, NMPlatformIP6Address, 0);
	g_assert_cmpint (address->ifindex, ==, ifindex);
	g_assert (!memcmp (&address->address, &addr, sizeof (addr)));
	g_assert_cmpint (address->plen, ==, IP6_PLEN);
	g_array_unref (addresses);

	/* Remove address */
	g_assert (nm_platform_ip6_address_delete (NM_PLATFORM_GET, ifindex, addr, IP6_PLEN));
	no_error ();
	g_assert (!nm_platform_ip6_address_exists (NM_PLATFORM_GET, ifindex, addr, IP6_PLEN));
	accept_signal (address_removed);

	/* Remove address again */
	g_assert (nm_platform_ip6_address_delete (NM_PLATFORM_GET, ifindex, addr, IP6_PLEN));
	no_error ();

	free_signal (address_added);
	free_signal (address_changed);
	free_signal (address_removed);
}

static void
test_ip4_address_external (void)
{
	SignalData *address_added = add_signal (NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_ADDED, ip4_address_callback);
	SignalData *address_removed = add_signal (NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, ip4_address_callback);
	int ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	in_addr_t addr;
	guint32 lifetime = 2000;
	guint32 preferred = 1000;

	inet_pton (AF_INET, IP4_ADDRESS, &addr);
	g_assert (ifindex > 0);

	/* Looks like addresses are not announced by kerenl when the interface
	 * is down. Link-local IPv6 address is automatically added.
	 */
	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME)));

	/* Add/delete notification */
	run_command ("ip address add %s/%d dev %s valid_lft %d preferred_lft %d",
			IP4_ADDRESS, IP4_PLEN, DEVICE_NAME, lifetime, preferred);
	wait_signal (address_added);
	g_assert (nm_platform_ip4_address_exists (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN));
	run_command ("ip address delete %s/%d dev %s", IP4_ADDRESS, IP4_PLEN, DEVICE_NAME);
	wait_signal (address_removed);
	g_assert (!nm_platform_ip4_address_exists (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN));

	/* Add/delete conflict */
	run_command ("ip address add %s/%d dev %s valid_lft %d preferred_lft %d",
			IP4_ADDRESS, IP4_PLEN, DEVICE_NAME, lifetime, preferred);
	g_assert (nm_platform_ip4_address_add (NM_PLATFORM_GET, ifindex, addr, 0, IP4_PLEN, lifetime, preferred, NULL));
	no_error ();
	g_assert (nm_platform_ip4_address_exists (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN));
	accept_signal (address_added);
	/*run_command ("ip address delete %s/%d dev %s", IP4_ADDRESS, IP4_PLEN, DEVICE_NAME);
	g_assert (nm_platform_ip4_address_delete (ifindex, addr, IP4_PLEN, 0));
	no_error ();
	g_assert (!nm_platform_ip4_address_exists (NM_PLATFORM_GET, ifindex, addr, IP4_PLEN));
	accept_signal (address_removed);*/

	free_signal (address_added);
	free_signal (address_removed);
}

static void
test_ip6_address_external (void)
{
	SignalData *address_added = add_signal (NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_ADDED, ip6_address_callback);
	SignalData *address_removed = add_signal (NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, ip6_address_callback);
	int ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	struct in6_addr addr;
	guint32 lifetime = 2000;
	guint32 preferred = 1000;
	guint flags = 0;

	inet_pton (AF_INET6, IP6_ADDRESS, &addr);

	/* Add/delete notification */
	run_command ("ip address add %s/%d dev %s valid_lft %d preferred_lft %d",
			IP6_ADDRESS, IP6_PLEN, DEVICE_NAME, lifetime, preferred);
	wait_signal (address_added);
	g_assert (nm_platform_ip6_address_exists (NM_PLATFORM_GET, ifindex, addr, IP6_PLEN));
	run_command ("ip address delete %s/%d dev %s", IP6_ADDRESS, IP6_PLEN, DEVICE_NAME);
	wait_signal (address_removed);
	g_assert (!nm_platform_ip6_address_exists (NM_PLATFORM_GET, ifindex, addr, IP6_PLEN));

	/* Add/delete conflict */
	run_command ("ip address add %s/%d dev %s valid_lft %d preferred_lft %d",
			IP6_ADDRESS, IP6_PLEN, DEVICE_NAME, lifetime, preferred);
	g_assert (nm_platform_ip6_address_add (NM_PLATFORM_GET, ifindex, addr, in6addr_any, IP6_PLEN, lifetime, preferred, flags));
	no_error ();
	g_assert (nm_platform_ip6_address_exists (NM_PLATFORM_GET, ifindex, addr, IP6_PLEN));
	accept_signal (address_added);
	/*run_command ("ip address delete %s/%d dev %s", IP6_ADDRESS, IP6_PLEN, DEVICE_NAME);
	g_assert (nm_platform_ip6_address_delete (NM_PLATFORM_GET, ifindex, addr, IP6_PLEN));
	no_error ();
	g_assert (!nm_platform_ip6_address_exists (NM_PLATFORM_GET, ifindex, addr, IP6_PLEN));
	wait_signal (address_removed);*/

	free_signal (address_added);
	free_signal (address_removed);
}

void
init_tests (int *argc, char ***argv)
{
	nmtst_init_with_logging (argc, argv, NULL, "ALL");
}

void
setup_tests (void)
{
	SignalData *link_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_ADDED, link_callback, DEVICE_NAME);

	nm_platform_link_delete (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME));
	g_assert (!nm_platform_link_exists (NM_PLATFORM_GET, DEVICE_NAME));
	g_assert (nm_platform_dummy_add (NM_PLATFORM_GET, DEVICE_NAME, NULL) == NM_PLATFORM_ERROR_SUCCESS);
	accept_signal (link_added);
	free_signal (link_added);

	g_test_add_func ("/address/internal/ip4", test_ip4_address);
	g_test_add_func ("/address/internal/ip6", test_ip6_address);

	if (strcmp (g_type_name (G_TYPE_FROM_INSTANCE (nm_platform_get ())), "NMFakePlatform")) {
		g_test_add_func ("/address/external/ip4", test_ip4_address_external);
		g_test_add_func ("/address/external/ip6", test_ip6_address_external);
	}
}
