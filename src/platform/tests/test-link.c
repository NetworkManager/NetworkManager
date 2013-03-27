#include "test-common.h"

#define LO_INDEX 1
#define LO_NAME "lo"

#define DEVICE_NAME "nm-test-device"
#define BOGUS_NAME "nm-bogus-device"
#define BOGUS_IFINDEX INT_MAX

static void
link_callback (NMPlatform *platform, NMPlatformLink *received, SignalData *data)
{
	
	GArray *links;
	NMPlatformLink *cached;
	int i;

	g_assert (received);

	if (data->ifindex && data->ifindex != received->ifindex)
		return;

	if (data->loop)
		g_main_loop_quit (data->loop);

	if (data->received)
		g_error ("Received signal '%s' a second time.", data->name);

	data->received = TRUE;

	/* Check the data */
	g_assert (received->ifindex > 0);
	links = nm_platform_link_get_all ();
	for (i = 0; i < links->len; i++) {
		cached = &g_array_index (links, NMPlatformLink, i);
		if (cached->ifindex == received->ifindex) {
			g_assert (!memcmp (cached, received, sizeof (*cached)));
			if (!g_strcmp0 (data->name, NM_PLATFORM_LINK_REMOVED)) {
				g_error ("Deleted link still found in the local cache.");
			}
			g_array_unref (links);
			return;
		}
	}
	g_array_unref (links);

	if (g_strcmp0 (data->name, NM_PLATFORM_LINK_REMOVED))
		g_error ("Added/changed link not found in the local cache.");
}

static void
test_bogus(void)
{
	g_assert (!nm_platform_link_exists (BOGUS_NAME));
	no_error ();
	g_assert (!nm_platform_link_delete (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_delete_by_name (BOGUS_NAME));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_get_ifindex (BOGUS_NAME));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_get_name (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_get_type (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	g_assert (!nm_platform_link_set_up (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_set_down (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_set_arp (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_set_noarp (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_is_up (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_is_connected (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_uses_arp (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	g_assert (!nm_platform_link_supports_carrier_detect (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_supports_vlans (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
}

static void
test_loopback (void)
{
	g_assert (nm_platform_link_exists (LO_NAME));
	g_assert (nm_platform_link_get_type (LO_INDEX) == NM_LINK_TYPE_LOOPBACK);
	g_assert (nm_platform_link_get_ifindex (LO_NAME) == LO_INDEX);
	g_assert (!g_strcmp0 (nm_platform_link_get_name (LO_INDEX), LO_NAME));

	g_assert (nm_platform_link_supports_carrier_detect (LO_INDEX));
	g_assert (!nm_platform_link_supports_vlans (LO_INDEX));
}

static void
test_internal (void)
{
	SignalData *link_added = add_signal (NM_PLATFORM_LINK_ADDED, link_callback);
	SignalData *link_changed = add_signal (NM_PLATFORM_LINK_CHANGED, link_callback);
	SignalData *link_removed = add_signal (NM_PLATFORM_LINK_REMOVED, link_callback);
	int ifindex;

	/* Check the functions for non-existent devices */
	g_assert (!nm_platform_link_exists (DEVICE_NAME)); no_error ();
	g_assert (!nm_platform_link_get_ifindex (DEVICE_NAME));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	/* Add device */
	g_assert (nm_platform_dummy_add (DEVICE_NAME));
	no_error ();
	accept_signal (link_added);

	/* Try to add again */
	g_assert (!nm_platform_dummy_add (DEVICE_NAME));
	error (NM_PLATFORM_ERROR_EXISTS);

	/* Check device index, name and type */
	ifindex = nm_platform_link_get_ifindex (DEVICE_NAME);
	g_assert (ifindex > 0);
	g_assert (!g_strcmp0 (nm_platform_link_get_name (ifindex), DEVICE_NAME));
	g_assert (nm_platform_link_get_type (ifindex) == NM_LINK_TYPE_DUMMY);

	/* Up/connected */
	g_assert (!nm_platform_link_is_up (ifindex)); no_error ();
	g_assert (!nm_platform_link_is_connected (ifindex)); no_error ();
	g_assert (nm_platform_link_set_up (ifindex)); no_error ();
	g_assert (nm_platform_link_is_up (ifindex)); no_error ();
	g_assert (nm_platform_link_is_connected (ifindex)); no_error ();
	accept_signal (link_changed);
	g_assert (nm_platform_link_set_down (ifindex)); no_error ();
	g_assert (!nm_platform_link_is_up (ifindex)); no_error ();
	g_assert (!nm_platform_link_is_connected (ifindex)); no_error ();
	accept_signal (link_changed);

	/* arp/noarp */
	g_assert (!nm_platform_link_uses_arp (ifindex));
	g_assert (nm_platform_link_set_arp (ifindex));
	g_assert (nm_platform_link_uses_arp (ifindex));
	accept_signal (link_changed);
	g_assert (nm_platform_link_set_noarp (ifindex));
	g_assert (!nm_platform_link_uses_arp (ifindex));
	accept_signal (link_changed);

	/* Features */
	g_assert (!nm_platform_link_supports_carrier_detect (ifindex));
	g_assert (nm_platform_link_supports_vlans (ifindex));

	/* Delete device */
	g_assert (nm_platform_link_delete (ifindex));
	no_error ();
	accept_signal (link_removed);

	/* Try to delete again */
	g_assert (!nm_platform_link_delete (ifindex));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	/* Add back */
	g_assert (nm_platform_dummy_add (DEVICE_NAME));
	no_error ();
	accept_signal (link_added);

	/* Delete device by name */
	g_assert (nm_platform_link_delete_by_name (DEVICE_NAME));
	no_error ();
	accept_signal (link_removed);

	/* Try to delete again */
	g_assert (!nm_platform_link_delete_by_name (DEVICE_NAME));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	free_signal (link_added);
	free_signal (link_changed);
	free_signal (link_removed);
}

static void
test_external (void)
{
	SignalData *link_added = add_signal (NM_PLATFORM_LINK_ADDED, link_callback);
	SignalData *link_changed = add_signal (NM_PLATFORM_LINK_CHANGED, link_callback);
	SignalData *link_removed = add_signal (NM_PLATFORM_LINK_REMOVED, link_callback);
	int ifindex;

	run_command ("ip link add %s type %s", DEVICE_NAME, "dummy");
	wait_signal (link_added);
	g_assert (nm_platform_link_exists (DEVICE_NAME));
	ifindex = nm_platform_link_get_ifindex (DEVICE_NAME);
	g_assert (ifindex > 0);
	g_assert (!g_strcmp0 (nm_platform_link_get_name (ifindex), DEVICE_NAME));
	g_assert (nm_platform_link_get_type (ifindex) == NM_LINK_TYPE_DUMMY);

	/* Up/connected/arp */
	g_assert (!nm_platform_link_is_up (ifindex));
	g_assert (!nm_platform_link_is_connected (ifindex));
	g_assert (!nm_platform_link_uses_arp (ifindex));
	run_command ("ip link set %s up", DEVICE_NAME);
	wait_signal (link_changed);
	g_assert (nm_platform_link_is_up (ifindex));
	g_assert (nm_platform_link_is_connected (ifindex));
	run_command ("ip link set %s down", DEVICE_NAME);
	wait_signal (link_changed);
	g_assert (!nm_platform_link_is_up (ifindex));
	g_assert (!nm_platform_link_is_connected (ifindex));
	/* This test doesn't trigger a netlink event at least on
	 * 3.8.2-206.fc18.x86_64. Disabling the waiting and checking code
	 * because of that.
	 */
	run_command ("ip link set %s arp on", DEVICE_NAME);
#if 0
	wait_signal (link_changed);
	g_assert (nm_platform_link_uses_arp (ifindex));
#endif
	run_command ("ip link set %s arp off", DEVICE_NAME);
#if 0
	wait_signal (link_changed);
	g_assert (!nm_platform_link_uses_arp (ifindex));
#endif

	run_command ("ip link del %s", DEVICE_NAME);
	wait_signal (link_removed);
	g_assert (!nm_platform_link_exists (DEVICE_NAME));

	free_signal (link_added);
	free_signal (link_changed);
	free_signal (link_removed);
}

int
main (int argc, char **argv)
{
	int result;

	openlog (G_LOG_DOMAIN, LOG_CONS | LOG_PERROR, LOG_DAEMON);
	g_type_init ();
	g_test_init (&argc, &argv, NULL);
	/* Enable debug messages if called with --debug */
	for (; *argv; argv++) {
		if (!g_strcmp0 (*argv, "--debug")) {
			nm_logging_setup ("debug", NULL, NULL);
		}
	}

	SETUP ();

	/* Clean up */
	nm_platform_link_delete_by_name (DEVICE_NAME);
	g_assert (!nm_platform_link_exists (DEVICE_NAME));

	g_test_add_func ("/link/bogus", test_bogus);
	g_test_add_func ("/link/loopback", test_loopback);
	g_test_add_func ("/link/internal", test_internal);

	if (strcmp (g_type_name (G_TYPE_FROM_INSTANCE (nm_platform_get ())), "NMFakePlatform"))
		g_test_add_func ("/link/external", test_external);

	result = g_test_run ();

	nm_platform_free ();
	return result;
}
