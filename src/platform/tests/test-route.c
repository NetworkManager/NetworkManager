#include "test-common.h"
#include "nm-test-utils.h"

#define DEVICE_NAME "nm-test-device"

static void
ip4_route_callback (NMPlatform *platform, int ifindex, NMPlatformIP4Route *received, NMPlatformSignalChangeType change_type, NMPlatformReason reason, SignalData *data)
{
	g_assert (received);
	g_assert_cmpint (received->ifindex, ==, ifindex);
	g_assert (data && data->name);
	g_assert_cmpstr (data->name, ==, NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED);

	if (data->ifindex && data->ifindex != received->ifindex)
		return;
	if (data->change_type != change_type)
		return;

	if (data->loop)
		g_main_loop_quit (data->loop);

	if (data->received)
		g_error ("Received signal '%s' a second time.", data->name);

	data->received = TRUE;
}

static void
ip6_route_callback (NMPlatform *platform, int ifindex, NMPlatformIP6Route *received, NMPlatformSignalChangeType change_type, NMPlatformReason reason, SignalData *data)
{
	g_assert (received);
	g_assert_cmpint (received->ifindex, ==, ifindex);
	g_assert (data && data->name);
	g_assert_cmpstr (data->name, ==, NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED);

	if (data->ifindex && data->ifindex != received->ifindex)
		return;
	if (data->change_type != change_type)
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
	int ifindex = nm_platform_link_get_ifindex (DEVICE_NAME);
	SignalData *route_added = add_signal (NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_ADDED, ip4_route_callback);
	SignalData *route_changed = add_signal (NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_CHANGED, ip4_route_callback);
	SignalData *route_removed = add_signal (NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, ip4_route_callback);
	GArray *routes;
	NMPlatformIP4Route rts[3];
	in_addr_t network;
	int plen = 24;
	in_addr_t gateway;
	int metric = 20;
	int mss = 1000;

	inet_pton (AF_INET, "192.0.3.0", &network);
	inet_pton (AF_INET, "198.51.100.1", &gateway);

	/* Add route to gateway */
	g_assert (nm_platform_ip4_route_add (ifindex, NM_PLATFORM_SOURCE_USER, gateway, 32, INADDR_ANY, metric, mss));
	no_error ();
	accept_signal (route_added);

	/* Add route */
	g_assert (!nm_platform_ip4_route_exists (ifindex, network, plen, metric));
	no_error ();
	g_assert (nm_platform_ip4_route_add (ifindex, NM_PLATFORM_SOURCE_USER, network, plen, gateway, metric, mss));
	no_error ();
	g_assert (nm_platform_ip4_route_exists (ifindex, network, plen, metric));
	no_error ();
	accept_signal (route_added);

	/* Add route again */
	g_assert (nm_platform_ip4_route_add (ifindex, NM_PLATFORM_SOURCE_USER, network, plen, gateway, metric, mss));
	no_error ();
	accept_signal (route_changed);

	/* Add default route */
	g_assert (!nm_platform_ip4_route_exists (ifindex, 0, 0, metric));
	no_error ();
	g_assert (nm_platform_ip4_route_add (ifindex, NM_PLATFORM_SOURCE_USER, 0, 0, gateway, metric, mss));
	no_error ();
	g_assert (nm_platform_ip4_route_exists (ifindex, 0, 0, metric));
	no_error ();
	accept_signal (route_added);

	/* Add default route again */
	g_assert (nm_platform_ip4_route_add (ifindex, NM_PLATFORM_SOURCE_USER, 0, 0, gateway, metric, mss));
	no_error ();
	accept_signal (route_changed);

	/* Test route listing */
	routes = nm_platform_ip4_route_get_all (ifindex, TRUE);
	memset (rts, 0, sizeof (rts));
	rts[0].source = NM_PLATFORM_SOURCE_USER;
	rts[0].network = gateway;
	rts[0].plen = 32;
	rts[0].ifindex = ifindex;
	rts[0].gateway = INADDR_ANY;
	rts[0].metric = metric;
	rts[0].mss = mss;
	rts[1].source = NM_PLATFORM_SOURCE_USER;
	rts[1].network = network;
	rts[1].plen = plen;
	rts[1].ifindex = ifindex;
	rts[1].gateway = gateway;
	rts[1].metric = metric;
	rts[1].mss = mss;
	rts[2].source = NM_PLATFORM_SOURCE_USER;
	rts[2].network = 0;
	rts[2].plen = 0;
	rts[2].ifindex = ifindex;
	rts[2].gateway = gateway;
	rts[2].metric = metric;
	rts[2].mss = mss;
	g_assert_cmpint (routes->len, ==, 3);
	g_assert (!memcmp (routes->data, rts, sizeof (rts)));
	nmtst_platform_ip4_routes_equal ((NMPlatformIP4Route *) routes->data, rts, routes->len);
	g_array_unref (routes);

	/* Remove route */
	g_assert (nm_platform_ip4_route_delete (ifindex, network, plen, metric));
	no_error ();
	g_assert (!nm_platform_ip4_route_exists (ifindex, network, plen, metric));
	accept_signal (route_removed);

	/* Remove route again */
	g_assert (nm_platform_ip4_route_delete (ifindex, network, plen, metric));
	no_error ();

	free_signal (route_added);
	free_signal (route_changed);
	free_signal (route_removed);
}

static void
test_ip6_route ()
{
	int ifindex = nm_platform_link_get_ifindex (DEVICE_NAME);
	SignalData *route_added = add_signal (NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_ADDED, ip6_route_callback);
	SignalData *route_changed = add_signal (NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_CHANGED, ip6_route_callback);
	SignalData *route_removed = add_signal (NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, ip6_route_callback);
	GArray *routes;
	NMPlatformIP6Route rts[3];
	struct in6_addr network;
	int plen = 64;
	struct in6_addr gateway;
	int metric = 20;
	int mss = 1000;

	inet_pton (AF_INET6, "2001:db8:a:b:0:0:0:0", &network);
	inet_pton (AF_INET6, "2001:db8:c:d:1:2:3:4", &gateway);

	/* Add route to gateway */
	g_assert (nm_platform_ip6_route_add (ifindex, NM_PLATFORM_SOURCE_USER, gateway, 128, in6addr_any, metric, mss));
	no_error ();
	accept_signal (route_added);

	/* Add route */
	g_assert (!nm_platform_ip6_route_exists (ifindex, network, plen, metric));
	no_error ();
	g_assert (nm_platform_ip6_route_add (ifindex, NM_PLATFORM_SOURCE_USER, network, plen, gateway, metric, mss));
	no_error ();
	g_assert (nm_platform_ip6_route_exists (ifindex, network, plen, metric));
	no_error ();
	accept_signal (route_added);

	/* Add route again */
	g_assert (nm_platform_ip6_route_add (ifindex, NM_PLATFORM_SOURCE_USER, network, plen, gateway, metric, mss));
	no_error ();
	accept_signal (route_changed);

	/* Add default route */
	g_assert (!nm_platform_ip6_route_exists (ifindex, in6addr_any, 0, metric));
	no_error ();
	g_assert (nm_platform_ip6_route_add (ifindex, NM_PLATFORM_SOURCE_USER, in6addr_any, 0, gateway, metric, mss));
	no_error ();
	g_assert (nm_platform_ip6_route_exists (ifindex, in6addr_any, 0, metric));
	no_error ();
	accept_signal (route_added);

	/* Add default route again */
	g_assert (nm_platform_ip6_route_add (ifindex, NM_PLATFORM_SOURCE_USER, in6addr_any, 0, gateway, metric, mss));
	no_error ();
	accept_signal (route_changed);

	/* Test route listing */
	routes = nm_platform_ip6_route_get_all (ifindex, TRUE);
	memset (rts, 0, sizeof (rts));
	rts[0].source = NM_PLATFORM_SOURCE_USER;
	rts[0].network = gateway;
	rts[0].plen = 128;
	rts[0].ifindex = ifindex;
	rts[0].gateway = in6addr_any;
	rts[0].metric = metric;
	rts[0].mss = mss;
	rts[1].source = NM_PLATFORM_SOURCE_USER;
	rts[1].network = network;
	rts[1].plen = plen;
	rts[1].ifindex = ifindex;
	rts[1].gateway = gateway;
	rts[1].metric = metric;
	rts[1].mss = mss;
	rts[2].source = NM_PLATFORM_SOURCE_USER;
	rts[2].network = in6addr_any;
	rts[2].plen = 0;
	rts[2].ifindex = ifindex;
	rts[2].gateway = gateway;
	rts[2].metric = metric;
	rts[2].mss = mss;
	g_assert_cmpint (routes->len, ==, 3);
	g_assert (!memcmp (routes->data, rts, sizeof (rts)));
	nmtst_platform_ip6_routes_equal ((NMPlatformIP6Route *) routes->data, rts, routes->len);
	g_array_unref (routes);

	/* Remove route */
	g_assert (nm_platform_ip6_route_delete (ifindex, network, plen, metric));
	no_error ();
	g_assert (!nm_platform_ip6_route_exists (ifindex, network, plen, metric));
	accept_signal (route_removed);

	/* Remove route again */
	g_assert (nm_platform_ip6_route_delete (ifindex, network, plen, metric));
	no_error ();

	free_signal (route_added);
	free_signal (route_changed);
	free_signal (route_removed);
}

void
setup_tests (void)
{
	SignalData *link_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_ADDED, link_callback, DEVICE_NAME);

	nm_platform_link_delete (nm_platform_link_get_ifindex (DEVICE_NAME));
	g_assert (!nm_platform_link_exists (DEVICE_NAME));
	g_assert (nm_platform_dummy_add (DEVICE_NAME));
	accept_signal (link_added);
	free_signal (link_added);

	g_assert (nm_platform_link_set_up (nm_platform_link_get_ifindex (DEVICE_NAME)));

	g_test_add_func ("/route/ip4", test_ip4_route);
	g_test_add_func ("/route/ip6", test_ip6_route);
}
