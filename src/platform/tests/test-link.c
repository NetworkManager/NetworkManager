#include "test-common.h"

#define LO_INDEX 1
#define LO_NAME "lo"
#define LO_TYPEDESC "loopback"

#define DEVICE_NAME "nm-test-device"
#define DUMMY_TYPEDESC "dummy"
#define BOGUS_NAME "nm-bogus-device"
#define BOGUS_IFINDEX INT_MAX
#define SLAVE_NAME "nm-test-slave"
#define PARENT_NAME "nm-test-parent"
#define VLAN_ID 4077
#define VLAN_FLAGS 0
#define MTU 1357

static void
link_callback (NMPlatform *platform, int ifindex, NMPlatformLink *received, SignalData *data)
{
	
	GArray *links;
	NMPlatformLink *cached;
	int i;

	g_assert (received);
	g_assert_cmpint (received->ifindex, ==, ifindex);

	if (data->ifindex && data->ifindex != received->ifindex)
		return;
	if (data->ifname && g_strcmp0 (data->ifname, nm_platform_link_get_name (ifindex)) != 0)
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
	size_t addrlen;

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
	g_assert (!nm_platform_link_get_type_name (BOGUS_IFINDEX));
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

	g_assert (!nm_platform_link_get_address (BOGUS_IFINDEX, &addrlen));
	g_assert (!addrlen);
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_get_address (BOGUS_IFINDEX, NULL));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_set_mtu (BOGUS_IFINDEX, MTU));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_get_mtu (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	g_assert (!nm_platform_link_supports_carrier_detect (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_supports_vlans (BOGUS_IFINDEX));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	g_assert (!nm_platform_vlan_get_info (BOGUS_IFINDEX, NULL, NULL));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_vlan_set_ingress_map (BOGUS_IFINDEX, 0, 0));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_vlan_set_egress_map (BOGUS_IFINDEX, 0, 0));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
}

static void
test_loopback (void)
{
	g_assert (nm_platform_link_exists (LO_NAME));
	g_assert_cmpint (nm_platform_link_get_type (LO_INDEX), ==, NM_LINK_TYPE_LOOPBACK);
	g_assert_cmpint (nm_platform_link_get_ifindex (LO_NAME), ==, LO_INDEX);
	g_assert_cmpstr (nm_platform_link_get_name (LO_INDEX), ==, LO_NAME);
	g_assert_cmpstr (nm_platform_link_get_type_name (LO_INDEX), ==, LO_TYPEDESC);

	g_assert (nm_platform_link_supports_carrier_detect (LO_INDEX));
	g_assert (!nm_platform_link_supports_vlans (LO_INDEX));
}

static int
software_add (NMLinkType link_type, const char *name)
{
	switch (link_type) {
	case NM_LINK_TYPE_DUMMY:
		return nm_platform_dummy_add (name);
	case NM_LINK_TYPE_BRIDGE:
		return nm_platform_bridge_add (name);
	case NM_LINK_TYPE_BOND:
		{
			gboolean bond0_exists = nm_platform_link_exists ("bond0");
			gboolean result = nm_platform_bond_add (name);
			NMPlatformError error = nm_platform_get_error ();

			/* Check that bond0 is *not* automatically created. */
			if (!bond0_exists)
				g_assert (!nm_platform_link_exists ("bond0"));

			nm_platform_set_error (error);
			return result;
		}
	case NM_LINK_TYPE_TEAM:
		return nm_platform_team_add (name);
	case NM_LINK_TYPE_VLAN: {
		SignalData *parent_added;
		SignalData *parent_changed;

		/* Don't call link_callback for the bridge interface */
		parent_added = add_signal_ifname ("link-added", link_callback, PARENT_NAME);
		if (nm_platform_bridge_add (PARENT_NAME))
			wait_signal (parent_added);
		free_signal (parent_added);

		parent_changed = add_signal_ifname ("link-changed", link_callback, PARENT_NAME);
		g_assert (nm_platform_link_set_up (nm_platform_link_get_ifindex (PARENT_NAME)));
		accept_signal (parent_changed);
		free_signal (parent_changed);

		return nm_platform_vlan_add (name,
			nm_platform_link_get_ifindex (PARENT_NAME),
			VLAN_ID, 0);
	}
	default:
		g_error ("Link type %d unhandled.", link_type);
	}
}

static void
test_slave (int master, int type, SignalData *master_changed, SignalData *link_removed)
{
	int ifindex;
	SignalData *link_changed = add_signal_ifname ("link-changed", link_callback, SLAVE_NAME);
	SignalData *link_added;
	char *value;

	link_added = add_signal_ifname ("link-added", link_callback, SLAVE_NAME);
	g_assert (software_add (type, SLAVE_NAME));
	ifindex = nm_platform_link_get_ifindex (SLAVE_NAME);
	g_assert (ifindex > 0);
	wait_signal (link_added);
	free_signal (link_added);

	/* Set the slave up to see whether master's IFF_LOWER_UP is set correctly.
	 *
	 * See https://bugzilla.redhat.com/show_bug.cgi?id=910348
	 */
	g_assert (nm_platform_link_set_down (ifindex));
	g_assert (!nm_platform_link_is_up (ifindex));
	accept_signal (link_changed);

	/* Enslave */
	link_changed->ifindex = ifindex;
	g_assert (nm_platform_link_enslave (master, ifindex)); no_error ();
	g_assert_cmpint (nm_platform_link_get_master (ifindex), ==, master); no_error ();
	accept_signal (link_changed);
	accept_signal (master_changed);

	/* Set master up */
	g_assert (nm_platform_link_set_up (master));
	accept_signal (master_changed);

	/* Master with a disconnected slave is disconnected
	 *
	 * For some reason, bonding and teaming slaves are automatically set up. We
	 * need to set them back down for this test.
	 */
	switch (nm_platform_link_get_type (master)) {
	case NM_LINK_TYPE_BOND:
	case NM_LINK_TYPE_TEAM:
		g_assert (nm_platform_link_set_down (ifindex));
		accept_signal (link_changed);
		accept_signal (master_changed);
		break;
	default:
		break;
	}
	g_assert (!nm_platform_link_is_up (ifindex));
	g_assert (!nm_platform_link_is_connected (ifindex));
	g_assert (!nm_platform_link_is_connected (master));

	/* Set slave up and see if master gets up too */
	g_assert (nm_platform_link_set_up (ifindex)); no_error ();
	g_assert (nm_platform_link_is_connected (ifindex));
	g_assert (nm_platform_link_is_connected (master));
	accept_signal (link_changed);
	accept_signal (master_changed);

	/* Enslave again
	 *
	 * Gracefully succeed if already enslaved.
	 */
	g_assert (nm_platform_link_enslave (master, ifindex)); no_error ();
	accept_signal (link_changed);
	accept_signal (master_changed);

	/* Set slave option */
	switch (type) {
	case NM_LINK_TYPE_BRIDGE:
		g_assert (nm_platform_slave_set_option (ifindex, "priority", "789"));
		no_error ();
		value = nm_platform_slave_get_option (ifindex, "priority");
		no_error ();
		g_assert_cmpstr (value, ==, "789");
		g_free (value);
		break;
	default:
		break;
	}

	/* Release */
	g_assert (nm_platform_link_release (master, ifindex));
	g_assert_cmpint (nm_platform_link_get_master (ifindex), ==, 0); no_error ();
	accept_signal (link_changed);
	accept_signal (master_changed);

	/* Release again */
	g_assert (!nm_platform_link_release (master, ifindex));
	error (NM_PLATFORM_ERROR_NOT_SLAVE);

	/* Remove */
	g_assert (nm_platform_link_delete (ifindex));
	no_error ();
	accept_signal (link_removed);

	free_signal (link_changed);
}

static void
test_software (NMLinkType link_type, const char *link_typename)
{
	int ifindex;
	char *value;
	int vlan_parent, vlan_id;

	SignalData *link_added;
	SignalData *link_changed;
	SignalData *link_removed = add_signal ("link-removed", link_callback);

	/* Add */
	link_added = add_signal_ifname ("link-added", link_callback, DEVICE_NAME);
	g_assert (software_add (link_type, DEVICE_NAME));
	no_error ();
	g_assert (nm_platform_link_exists (DEVICE_NAME));
	ifindex = nm_platform_link_get_ifindex (DEVICE_NAME);
	g_assert (ifindex >= 0);
	g_assert_cmpint (nm_platform_link_get_type (ifindex), ==, link_type);
	g_assert_cmpstr (nm_platform_link_get_type_name (ifindex), ==, link_typename);
	if (link_type == NM_LINK_TYPE_VLAN) {
		g_assert (nm_platform_vlan_get_info (ifindex, &vlan_parent, &vlan_id));
		g_assert_cmpint (vlan_parent, ==, nm_platform_link_get_ifindex (PARENT_NAME));
		g_assert_cmpint (vlan_id, ==, VLAN_ID);
		no_error ();
	}
	wait_signal (link_added);

	/* Add again */
	g_assert (!software_add (link_type, DEVICE_NAME));
	error (NM_PLATFORM_ERROR_EXISTS);

	/* Set ARP/NOARP */
	link_changed = add_signal ("link-changed", link_callback);
	link_changed->ifindex = ifindex;
	g_assert (nm_platform_link_uses_arp (ifindex));
	g_assert (nm_platform_link_set_noarp (ifindex));
	g_assert (!nm_platform_link_uses_arp (ifindex));
	accept_signal (link_changed);
	g_assert (nm_platform_link_set_arp (ifindex));
	g_assert (nm_platform_link_uses_arp (ifindex));
	accept_signal (link_changed);

	/* Set master option */
	switch (link_type) {
	case NM_LINK_TYPE_BRIDGE:
		g_assert (nm_platform_master_set_option (ifindex, "forward_delay", "789"));
		no_error ();
		value = nm_platform_master_get_option (ifindex, "forward_delay");
		no_error ();
		g_assert_cmpstr (value, ==, "789");
		g_free (value);
		break;
	case NM_LINK_TYPE_BOND:
		g_assert (nm_platform_master_set_option (ifindex, "mode", "active-backup"));
		no_error ();
		value = nm_platform_master_get_option (ifindex, "mode");
		no_error ();
		/* When reading back, the output looks slightly different. */
		g_assert (g_str_has_prefix (value, "active-backup"));
		g_free (value);
		break;
	default:
		break;
	}

	/* Enslave and release */
	switch (link_type) {
	case NM_LINK_TYPE_BRIDGE:
	case NM_LINK_TYPE_BOND:
	case NM_LINK_TYPE_TEAM:
		link_changed->ifindex = ifindex;
		test_slave (ifindex, NM_LINK_TYPE_DUMMY, link_changed, link_removed);
		link_changed->ifindex = 0;
		break;
	default:
		break;
	}

	/* Delete */
	g_assert (nm_platform_link_delete_by_name (DEVICE_NAME));
	no_error ();
	g_assert (!nm_platform_link_exists (DEVICE_NAME)); no_error ();
	g_assert_cmpint (nm_platform_link_get_type (ifindex), ==, NM_LINK_TYPE_NONE);
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	g_assert (!nm_platform_link_get_type (ifindex));
	error (NM_PLATFORM_ERROR_NOT_FOUND);
	accept_signal (link_removed);

	/* Delete again */
	g_assert (!nm_platform_link_delete_by_name (DEVICE_NAME));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	/* VLAN: Delete parent */
	if (link_type == NM_LINK_TYPE_VLAN) {
		g_assert (nm_platform_link_delete_by_name (PARENT_NAME));
		accept_signal (link_removed);
	}

	/* No pending signal */
	free_signal (link_added);
	free_signal (link_changed);
	free_signal (link_removed);
}

static void
test_bridge (void)
{
	test_software (NM_LINK_TYPE_BRIDGE, "bridge");
}

static void
test_bond (void)
{
	test_software (NM_LINK_TYPE_BOND, "bond");
}

static void
test_team (void)
{
	test_software (NM_LINK_TYPE_TEAM, "team");
}

static void
test_vlan ()
{
	test_software (NM_LINK_TYPE_VLAN, "vlan");
}

static void
test_internal (void)
{
	SignalData *link_added;
	SignalData *link_changed = add_signal (NM_PLATFORM_LINK_CHANGED, link_callback);
	SignalData *link_removed = add_signal (NM_PLATFORM_LINK_REMOVED, link_callback);
	const char mac[6] = { 0x00, 0xff, 0x11, 0xee, 0x22, 0xdd };
	const char *address;
	size_t addrlen;
	int ifindex;

	/* Check the functions for non-existent devices */
	g_assert (!nm_platform_link_exists (DEVICE_NAME)); no_error ();
	g_assert (!nm_platform_link_get_ifindex (DEVICE_NAME));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	/* Add device */
	link_added = add_signal_ifname (NM_PLATFORM_LINK_ADDED, link_callback, DEVICE_NAME);
	g_assert (nm_platform_dummy_add (DEVICE_NAME));
	no_error ();
	wait_signal (link_added);

	/* Try to add again */
	g_assert (!nm_platform_dummy_add (DEVICE_NAME));
	error (NM_PLATFORM_ERROR_EXISTS);

	/* Check device index, name and type */
	ifindex = nm_platform_link_get_ifindex (DEVICE_NAME);
	g_assert (ifindex > 0);
	g_assert_cmpstr (nm_platform_link_get_name (ifindex), ==, DEVICE_NAME);
	g_assert_cmpint (nm_platform_link_get_type (ifindex), ==, NM_LINK_TYPE_DUMMY);
	g_assert_cmpstr (nm_platform_link_get_type_name (ifindex), ==, DUMMY_TYPEDESC);

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

	/* Set MAC address */
	g_assert (nm_platform_link_set_address (ifindex, mac, sizeof (mac)));
	address = nm_platform_link_get_address (ifindex, &addrlen);
	g_assert (addrlen == sizeof(mac));
	g_assert (!memcmp (address, mac, addrlen));
	address = nm_platform_link_get_address (ifindex, NULL);
	g_assert (!memcmp (address, mac, addrlen));
	accept_signal (link_changed);

	/* Set MTU */
	g_assert (nm_platform_link_set_mtu (ifindex, MTU));
	no_error ();
	g_assert_cmpint (nm_platform_link_get_mtu (ifindex), ==, MTU);
	accept_signal (link_changed);

	/* Delete device */
	g_assert (nm_platform_link_delete (ifindex));
	no_error ();
	accept_signal (link_removed);

	/* Try to delete again */
	g_assert (!nm_platform_link_delete (ifindex));
	error (NM_PLATFORM_ERROR_NOT_FOUND);

	/* Add back */
	g_assert_cmpstr (link_added->ifname, ==, DEVICE_NAME);
	g_assert (nm_platform_dummy_add (DEVICE_NAME));
	no_error ();
	wait_signal (link_added);

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
	SignalData *link_added;
	SignalData *link_changed = add_signal (NM_PLATFORM_LINK_CHANGED, link_callback);
	SignalData *link_removed = add_signal (NM_PLATFORM_LINK_REMOVED, link_callback);
	int ifindex;

	link_added = add_signal_ifname (NM_PLATFORM_LINK_ADDED, link_callback, DEVICE_NAME);
	run_command ("ip link add %s type %s", DEVICE_NAME, "dummy");
	wait_signal (link_added);
	g_assert (nm_platform_link_exists (DEVICE_NAME));
	ifindex = nm_platform_link_get_ifindex (DEVICE_NAME);
	g_assert (ifindex > 0);
	g_assert_cmpstr (nm_platform_link_get_name (ifindex), ==, DEVICE_NAME);
	g_assert_cmpint (nm_platform_link_get_type (ifindex), ==, NM_LINK_TYPE_DUMMY);
	g_assert_cmpstr (nm_platform_link_get_type_name (ifindex), ==, DUMMY_TYPEDESC);

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

void
setup_tests (void)
{
	nm_platform_link_delete_by_name (DEVICE_NAME);
	nm_platform_link_delete_by_name (SLAVE_NAME);
	nm_platform_link_delete_by_name (PARENT_NAME);
	g_assert (!nm_platform_link_exists (DEVICE_NAME));
	g_assert (!nm_platform_link_exists (SLAVE_NAME));
	g_assert (!nm_platform_link_exists (PARENT_NAME));

	g_test_add_func ("/link/bogus", test_bogus);
	g_test_add_func ("/link/loopback", test_loopback);
	g_test_add_func ("/link/internal", test_internal);
	g_test_add_func ("/link/software/bridge", test_bridge);
	g_test_add_func ("/link/software/bond", test_bond);
	g_test_add_func ("/link/software/team", test_team);
	g_test_add_func ("/link/software/vlan", test_vlan);

	if (strcmp (g_type_name (G_TYPE_FROM_INSTANCE (nm_platform_get ())), "NMFakePlatform"))
		g_test_add_func ("/link/external", test_external);
}
