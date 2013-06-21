#include "test-common.h"

#define DEVICE_NAME "nm-test-device"

static void
ip4_route_callback (NMPlatform *platform, int ifindex, NMPlatformIP4Route *received, SignalData *data)
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
ip6_route_callback (NMPlatform *platform, int ifindex, NMPlatformIP6Route *received, SignalData *data)
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
test_ip4_route ()
{
	SignalData *route_added = add_signal (NM_PLATFORM_IP4_ROUTE_ADDED, ip4_route_callback);
	SignalData *route_removed = add_signal (NM_PLATFORM_IP4_ROUTE_REMOVED, ip4_route_callback);
	int ifindex = nm_platform_link_get_ifindex (DEVICE_NAME);
	GArray *routes;
	NMPlatformIP4Route rts[4];
	in_addr_t network;
	int plen = 24;
	in_addr_t gateway;
	int metric = 20;
	int mss = 1000;

	inet_pton (AF_INET, "192.0.3.0", &network);
	inet_pton (AF_INET, "198.51.100.1", &gateway);

	/* Add route to gateway */
	g_assert (nm_platform_ip4_route_add (ifindex, gateway, 32, INADDR_ANY, metric, mss)); no_error ();
	accept_signal (route_added);

	/* Add route */
	g_assert (!nm_platform_ip4_route_exists (ifindex, network, plen, metric)); no_error ();
	g_assert (nm_platform_ip4_route_add (ifindex, network, plen, gateway, metric, mss)); no_error ();
	g_assert (nm_platform_ip4_route_exists (ifindex, network, plen, metric)); no_error ();
	accept_signal (route_added);

	/* Add route again */
	g_assert (!nm_platform_ip4_route_add (ifindex, network, plen, gateway, metric, mss));
	error (NM_PLATFORM_ERROR_EXISTS);

	/* Add default route */
	g_assert (!nm_platform_ip4_route_exists (ifindex, 0, 0, metric)); no_error ();
	g_assert (nm_platform_ip4_route_add (ifindex, 0, 0, gateway, metric, mss)); no_error ();
	g_assert (nm_platform_ip4_route_exists (ifindex, 0, 0, metric)); no_error ();
	accept_signal (route_added);

	/* Add default route again */
	g_assert (!nm_platform_ip4_route_add (ifindex, 0, 0, gateway, metric, mss));
	error (NM_PLATFORM_ERROR_EXISTS);

	/* Test route listing */
	routes = nm_platform_ip4_route_get_all (ifindex);
	memset (rts, 0, sizeof (rts));
	rts[0].network = gateway;
	rts[0].plen = 32;
	rts[0].ifindex = ifindex;
	rts[0].gateway = INADDR_ANY;
	rts[0].metric = metric;
	rts[0].mss = mss;
	rts[1].network = network;
	rts[1].plen = plen;
	rts[1].ifindex = ifindex;
	rts[1].gateway = gateway;
	rts[1].metric = metric;
	rts[1].mss = mss;
	rts[2].network = 0;
	rts[2].plen = 0;
	rts[2].ifindex = ifindex;
	rts[2].gateway = gateway;
	rts[2].metric = metric;
	rts[2].mss = mss;
	g_assert_cmpint (routes->len, ==, 3);
	g_assert (!memcmp (routes->data, rts, sizeof (rts)));
	g_array_unref (routes);

	/* Remove route */
	g_assert (nm_platform_ip4_route_delete (ifindex, network, plen, metric)); no_error ();
	g_assert (!nm_platform_ip4_route_exists (ifindex, network, plen, metric));
	accept_signal (route_removed);

	/* Remove route again */
	g_assert (!nm_platform_ip4_route_delete (ifindex, network, plen, metric));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	free_signal (route_added);
	free_signal (route_removed);
}

static void
test_ip6_route ()
{
	SignalData *route_added = add_signal (NM_PLATFORM_IP6_ROUTE_ADDED, ip6_route_callback);
	SignalData *route_removed = add_signal (NM_PLATFORM_IP6_ROUTE_REMOVED, ip6_route_callback);
	int ifindex = nm_platform_link_get_ifindex (DEVICE_NAME);
	GArray *routes;
	NMPlatformIP6Route rts[4];
	struct in6_addr network;
	int plen = 64;
	struct in6_addr gateway;
	int metric = 20;
	int mss = 1000;

	inet_pton (AF_INET6, "2001:db8:a:b:0:0:0:0", &network);
	inet_pton (AF_INET6, "2001:db8:c:d:1:2:3:4", &gateway);

	/* Add route to gateway */
	g_assert (nm_platform_ip6_route_add (ifindex, gateway, 128, in6addr_any, metric, mss)); no_error ();
	accept_signal (route_added);

	/* Add route */
	g_assert (!nm_platform_ip6_route_exists (ifindex, network, plen, metric)); no_error ();
	g_assert (nm_platform_ip6_route_add (ifindex, network, plen, gateway, metric, mss)); no_error ();
	g_assert (nm_platform_ip6_route_exists (ifindex, network, plen, metric)); no_error ();
	accept_signal (route_added);

	/* Add route again */
	g_assert (!nm_platform_ip6_route_add (ifindex, network, plen, gateway, metric, mss));
	error (NM_PLATFORM_ERROR_EXISTS);

	/* Add default route */
	g_assert (!nm_platform_ip6_route_exists (ifindex, in6addr_any, 0, metric)); no_error ();
	g_assert (nm_platform_ip6_route_add (ifindex, in6addr_any, 0, gateway, metric, mss)); no_error ();
	g_assert (nm_platform_ip6_route_exists (ifindex, in6addr_any, 0, metric)); no_error ();
	accept_signal (route_added);

	/* Add default route again */
	g_assert (!nm_platform_ip6_route_add (ifindex, in6addr_any, 0, gateway, metric, mss));
	error (NM_PLATFORM_ERROR_EXISTS);

	/* Test route listing */
	routes = nm_platform_ip6_route_get_all (ifindex);
	memset (rts, 0, sizeof (rts));
	rts[0].network = gateway;
	rts[0].plen = 128;
	rts[0].ifindex = ifindex;
	rts[0].gateway = in6addr_any;
	rts[0].metric = metric;
	rts[0].mss = mss;
	rts[1].network = network;
	rts[1].plen = plen;
	rts[1].ifindex = ifindex;
	rts[1].gateway = gateway;
	rts[1].metric = metric;
	rts[1].mss = mss;
	rts[2].network = in6addr_any;
	rts[2].plen = 0;
	rts[2].ifindex = ifindex;
	rts[2].gateway = gateway;
	rts[2].metric = metric;
	rts[2].mss = mss;
	g_assert_cmpint (routes->len, ==, 3);
	g_assert (!memcmp (routes->data, rts, sizeof (rts)));
	g_array_unref (routes);

	/* Remove route */
	g_assert (nm_platform_ip6_route_delete (ifindex, network, plen, metric)); no_error ();
	g_assert (!nm_platform_ip6_route_exists (ifindex, network, plen, metric));
	accept_signal (route_removed);

	/* Remove route again */
	g_assert (!nm_platform_ip6_route_delete (ifindex, network, plen, metric));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	free_signal (route_added);
	free_signal (route_removed);
}

void
setup_tests (void)
{
	nm_platform_link_delete_by_name (DEVICE_NAME);
	g_assert (!nm_platform_link_exists (DEVICE_NAME));
	g_assert (nm_platform_dummy_add (DEVICE_NAME));
	g_assert (nm_platform_link_set_up (nm_platform_link_get_ifindex (DEVICE_NAME)));

	g_test_add_func ("/route/ip4", test_ip4_route);
	g_test_add_func ("/route/ip6", test_ip6_route);
}
