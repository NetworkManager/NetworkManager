#include "config.h"

#include "test-common.h"
#include "nm-test-utils.h"

#define LO_INDEX 1
#define LO_NAME "lo"
#define LO_TYPEDESC "loopback"

#define DUMMY_TYPEDESC "dummy"
#define BOGUS_NAME "nm-bogus-device"
#define BOGUS_IFINDEX INT_MAX
#define SLAVE_NAME "nm-test-slave"
#define PARENT_NAME "nm-test-parent"
#define VLAN_ID 4077
#define VLAN_FLAGS 0
#define MTU 1357

static void
test_bogus(void)
{
	size_t addrlen;

	g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, BOGUS_NAME));
	g_assert (!nm_platform_link_delete (NM_PLATFORM_GET, BOGUS_IFINDEX));
	g_assert (!nm_platform_link_get_ifindex (NM_PLATFORM_GET, BOGUS_NAME));
	g_assert (!nm_platform_link_get_name (NM_PLATFORM_GET, BOGUS_IFINDEX));
	g_assert (!nm_platform_link_get_type (NM_PLATFORM_GET, BOGUS_IFINDEX));
	g_assert (!nm_platform_link_get_type_name (NM_PLATFORM_GET, BOGUS_IFINDEX));

	g_assert (!nm_platform_link_set_up (NM_PLATFORM_GET, BOGUS_IFINDEX, NULL));
	g_assert (!nm_platform_link_set_down (NM_PLATFORM_GET, BOGUS_IFINDEX));
	g_assert (!nm_platform_link_set_arp (NM_PLATFORM_GET, BOGUS_IFINDEX));
	g_assert (!nm_platform_link_set_noarp (NM_PLATFORM_GET, BOGUS_IFINDEX));
	g_assert (!nm_platform_link_is_up (NM_PLATFORM_GET, BOGUS_IFINDEX));
	g_assert (!nm_platform_link_is_connected (NM_PLATFORM_GET, BOGUS_IFINDEX));
	g_assert (!nm_platform_link_uses_arp (NM_PLATFORM_GET, BOGUS_IFINDEX));

	g_assert (!nm_platform_link_get_address (NM_PLATFORM_GET, BOGUS_IFINDEX, &addrlen));
	g_assert (!addrlen);
	g_assert (!nm_platform_link_get_address (NM_PLATFORM_GET, BOGUS_IFINDEX, NULL));
	g_assert (!nm_platform_link_set_mtu (NM_PLATFORM_GET, BOGUS_IFINDEX, MTU));
	g_assert (!nm_platform_link_get_mtu (NM_PLATFORM_GET, BOGUS_IFINDEX));

	g_assert (!nm_platform_link_supports_carrier_detect (NM_PLATFORM_GET, BOGUS_IFINDEX));
	g_assert (!nm_platform_link_supports_vlans (NM_PLATFORM_GET, BOGUS_IFINDEX));

	g_assert (!nm_platform_vlan_get_info (NM_PLATFORM_GET, BOGUS_IFINDEX, NULL, NULL));
	g_assert (!nm_platform_vlan_set_ingress_map (NM_PLATFORM_GET, BOGUS_IFINDEX, 0, 0));
	g_assert (!nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, BOGUS_IFINDEX, 0, 0));
}

static void
test_loopback (void)
{
	g_assert (nm_platform_link_get_by_ifname (NM_PLATFORM_GET, LO_NAME));
	g_assert_cmpint (nm_platform_link_get_type (NM_PLATFORM_GET, LO_INDEX), ==, NM_LINK_TYPE_LOOPBACK);
	g_assert_cmpint (nm_platform_link_get_ifindex (NM_PLATFORM_GET, LO_NAME), ==, LO_INDEX);
	g_assert_cmpstr (nm_platform_link_get_name (NM_PLATFORM_GET, LO_INDEX), ==, LO_NAME);
	g_assert_cmpstr (nm_platform_link_get_type_name (NM_PLATFORM_GET, LO_INDEX), ==, LO_TYPEDESC);

	g_assert (nm_platform_link_supports_carrier_detect (NM_PLATFORM_GET, LO_INDEX));
	g_assert (!nm_platform_link_supports_vlans (NM_PLATFORM_GET, LO_INDEX));
}

static gboolean
software_add (NMLinkType link_type, const char *name)
{
	switch (link_type) {
	case NM_LINK_TYPE_DUMMY:
		return nm_platform_dummy_add (NM_PLATFORM_GET, name, NULL) == NM_PLATFORM_ERROR_SUCCESS;
	case NM_LINK_TYPE_BRIDGE:
		return nm_platform_bridge_add (NM_PLATFORM_GET, name, NULL, 0, NULL) == NM_PLATFORM_ERROR_SUCCESS;
	case NM_LINK_TYPE_BOND:
		{
			gboolean bond0_exists = !!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "bond0");
			NMPlatformError plerr;

			plerr = nm_platform_bond_add (NM_PLATFORM_GET, name, NULL);

			/* Check that bond0 is *not* automatically created. */
			if (!bond0_exists)
				g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "bond0"));
			return plerr == NM_PLATFORM_ERROR_SUCCESS;
		}
	case NM_LINK_TYPE_TEAM:
		return nm_platform_team_add (NM_PLATFORM_GET, name, NULL) == NM_PLATFORM_ERROR_SUCCESS;
	case NM_LINK_TYPE_VLAN: {
		SignalData *parent_added;
		SignalData *parent_changed;

		/* Don't call link_callback for the bridge interface */
		parent_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_ADDED, link_callback, PARENT_NAME);
		if (nm_platform_bridge_add (NM_PLATFORM_GET, PARENT_NAME, NULL, 0, NULL) == NM_PLATFORM_ERROR_SUCCESS)
			accept_signal (parent_added);
		free_signal (parent_added);

		{
			int parent_ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, PARENT_NAME);
			gboolean was_up = nm_platform_link_is_up (NM_PLATFORM_GET, parent_ifindex);

			parent_changed = add_signal_ifindex (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_CHANGED, link_callback, parent_ifindex);
			g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, parent_ifindex, NULL));
			if (was_up) {
				/* when NM is running in the background, it will mess with addrgenmode which might cause additional signals. */
				accept_signals (parent_changed, 0, 1);
			} else
				accept_signal (parent_changed);
			free_signal (parent_changed);

			return nm_platform_vlan_add (NM_PLATFORM_GET, name, parent_ifindex, VLAN_ID, 0, NULL) == NM_PLATFORM_ERROR_SUCCESS;
		}
	}
	default:
		g_error ("Link type %d unhandled.", link_type);
	}
	g_assert_not_reached ();
}

static void
test_slave (int master, int type, SignalData *master_changed)
{
	int ifindex;
	SignalData *link_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_ADDED, link_callback, SLAVE_NAME);
	SignalData *link_changed, *link_removed;
	char *value;
	NMLinkType link_type = nm_platform_link_get_type (NM_PLATFORM_GET, master);

	g_assert (NM_IN_SET (link_type, NM_LINK_TYPE_TEAM, NM_LINK_TYPE_BOND, NM_LINK_TYPE_BRIDGE));

	g_assert (software_add (type, SLAVE_NAME));
	ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, SLAVE_NAME);
	g_assert (ifindex > 0);
	link_changed = add_signal_ifindex (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_CHANGED, link_callback, ifindex);
	link_removed = add_signal_ifindex (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, link_callback, ifindex);
	accept_signal (link_added);

	/* Set the slave up to see whether master's IFF_LOWER_UP is set correctly.
	 *
	 * See https://bugzilla.redhat.com/show_bug.cgi?id=910348
	 */
	g_assert (!nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));
	g_assert (nm_platform_link_set_down (NM_PLATFORM_GET, ifindex));
	g_assert (!nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));
	ensure_no_signal (link_changed);

	/* Enslave */
	link_changed->ifindex = ifindex;
	g_assert (nm_platform_link_enslave (NM_PLATFORM_GET, master, ifindex));
	g_assert_cmpint (nm_platform_link_get_master (NM_PLATFORM_GET, ifindex), ==, master);

	accept_signals (link_changed, 1, 3);
	accept_signals (master_changed, 0, 1);

	/* enslaveing brings put the slave */
	if (NM_IN_SET (link_type, NM_LINK_TYPE_BOND, NM_LINK_TYPE_TEAM))
		g_assert (nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));
	else
		g_assert (!nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));

	/* Set master up */
	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, master, NULL));
	g_assert (nm_platform_link_is_up (NM_PLATFORM_GET, master));
	accept_signals (master_changed, 1, 2);

	/* Master with a disconnected slave is disconnected
	 *
	 * For some reason, bonding and teaming slaves are automatically set up. We
	 * need to set them back down for this test.
	 */
	switch (nm_platform_link_get_type (NM_PLATFORM_GET, master)) {
	case NM_LINK_TYPE_BOND:
	case NM_LINK_TYPE_TEAM:
		g_assert (nm_platform_link_set_down (NM_PLATFORM_GET, ifindex));
		accept_signal (link_changed);
		accept_signals (master_changed, 0, 2);
		break;
	default:
		break;
	}
	g_assert (!nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));
	g_assert (!nm_platform_link_is_connected (NM_PLATFORM_GET, ifindex));
	if (nm_platform_link_is_connected (NM_PLATFORM_GET, master)) {
		if (nm_platform_link_get_type (NM_PLATFORM_GET, master) == NM_LINK_TYPE_TEAM) {
			/* Older team versions (e.g. Fedora 17) have a bug that team master stays
			 * IFF_LOWER_UP even if its slave is down. Double check it with iproute2 and if
			 * `ip link` also claims master to be up, accept it. */
			char *stdout_str = NULL;

			nmtst_spawn_sync (NULL, &stdout_str, NULL, 0, "/sbin/ip", "link", "show", "dev", nm_platform_link_get_name (NM_PLATFORM_GET, master));

			g_assert (strstr (stdout_str, "LOWER_UP"));
			g_free (stdout_str);
		} else
			g_assert_not_reached ();
	}

	/* Set slave up and see if master gets up too */
	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, ifindex, NULL));
	g_assert (nm_platform_link_is_connected (NM_PLATFORM_GET, ifindex));
	g_assert (nm_platform_link_is_connected (NM_PLATFORM_GET, master));
	accept_signals (link_changed, 1, 3);
	/* NM running, can cause additional change of addrgenmode */
	accept_signals (master_changed, 1, 2);

	/* Enslave again
	 *
	 * Gracefully succeed if already enslaved.
	 */
	ensure_no_signal (link_changed);
	g_assert (nm_platform_link_enslave (NM_PLATFORM_GET, master, ifindex));
	accept_signals (link_changed, 0, 2);
	ensure_no_signal (master_changed);

	/* Set slave option */
	switch (type) {
	case NM_LINK_TYPE_BRIDGE:
		if (nmtst_platform_is_sysfs_writable ()) {
			g_assert (nm_platform_slave_set_option (NM_PLATFORM_GET, ifindex, "priority", "789"));
			value = nm_platform_slave_get_option (NM_PLATFORM_GET, ifindex, "priority");
			g_assert_cmpstr (value, ==, "789");
			g_free (value);
		}
		break;
	default:
		break;
	}

	/* Release */
	ensure_no_signal (link_changed);
	g_assert (nm_platform_link_release (NM_PLATFORM_GET, master, ifindex));
	g_assert_cmpint (nm_platform_link_get_master (NM_PLATFORM_GET, ifindex), ==, 0);
	accept_signals (link_changed, 1, 3);
	accept_signals (master_changed, 1, 2);

	ensure_no_signal (master_changed);

	/* Release again */
	ensure_no_signal (link_changed);
	g_assert (!nm_platform_link_release (NM_PLATFORM_GET, master, ifindex));

	ensure_no_signal (master_changed);

	/* Remove */
	ensure_no_signal (link_changed);
	g_assert (nm_platform_link_delete (NM_PLATFORM_GET, ifindex));
	accept_signals (master_changed, 0, 1);
	accept_signals (link_changed, 0, 1);
	accept_signal (link_removed);

	free_signal (link_added);
	free_signal (link_changed);
	free_signal (link_removed);
}

static void
test_software (NMLinkType link_type, const char *link_typename)
{
	int ifindex;
	char *value;
	int vlan_parent, vlan_id;

	SignalData *link_added, *link_changed, *link_removed;

	/* Add */
	link_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_ADDED, link_callback, DEVICE_NAME);
	g_assert (software_add (link_type, DEVICE_NAME));
	accept_signal (link_added);
	g_assert (nm_platform_link_get_by_ifname (NM_PLATFORM_GET, DEVICE_NAME));
	ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	g_assert (ifindex >= 0);
	g_assert_cmpint (nm_platform_link_get_type (NM_PLATFORM_GET, ifindex), ==, link_type);
	g_assert_cmpstr (nm_platform_link_get_type_name (NM_PLATFORM_GET, ifindex), ==, link_typename);
	link_changed = add_signal_ifindex (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_CHANGED, link_callback, ifindex);
	link_removed = add_signal_ifindex (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, link_callback, ifindex);
	if (link_type == NM_LINK_TYPE_VLAN) {
		g_assert (nm_platform_vlan_get_info (NM_PLATFORM_GET, ifindex, &vlan_parent, &vlan_id));
		g_assert_cmpint (vlan_parent, ==, nm_platform_link_get_ifindex (NM_PLATFORM_GET, PARENT_NAME));
		g_assert_cmpint (vlan_id, ==, VLAN_ID);
	}

	/* Add again */
	g_assert (!software_add (link_type, DEVICE_NAME));

	/* Set ARP/NOARP */
	g_assert (nm_platform_link_uses_arp (NM_PLATFORM_GET, ifindex));
	g_assert (nm_platform_link_set_noarp (NM_PLATFORM_GET, ifindex));
	g_assert (!nm_platform_link_uses_arp (NM_PLATFORM_GET, ifindex));
	accept_signals (link_changed, 1, 2);
	g_assert (nm_platform_link_set_arp (NM_PLATFORM_GET, ifindex));
	g_assert (nm_platform_link_uses_arp (NM_PLATFORM_GET, ifindex));
	accept_signal (link_changed);

	/* Set master option */
	switch (link_type) {
	case NM_LINK_TYPE_BRIDGE:
		if (nmtst_platform_is_sysfs_writable ()) {
			g_assert (nm_platform_master_set_option (NM_PLATFORM_GET, ifindex, "forward_delay", "789"));
			value = nm_platform_master_get_option (NM_PLATFORM_GET, ifindex, "forward_delay");
			g_assert_cmpstr (value, ==, "789");
			g_free (value);
		}
		break;
	case NM_LINK_TYPE_BOND:
		if (nmtst_platform_is_sysfs_writable ()) {
			g_assert (nm_platform_master_set_option (NM_PLATFORM_GET, ifindex, "mode", "active-backup"));
			value = nm_platform_master_get_option (NM_PLATFORM_GET, ifindex, "mode");
			/* When reading back, the output looks slightly different. */
			g_assert (g_str_has_prefix (value, "active-backup"));
			g_free (value);
		}
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
		test_slave (ifindex, NM_LINK_TYPE_DUMMY, link_changed);
		link_changed->ifindex = 0;
		break;
	default:
		break;
	}
	free_signal (link_changed);

	/* Delete */
	g_assert (nm_platform_link_delete (NM_PLATFORM_GET, ifindex));
	g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, DEVICE_NAME));
	g_assert_cmpint (nm_platform_link_get_type (NM_PLATFORM_GET, ifindex), ==, NM_LINK_TYPE_NONE);
	g_assert (!nm_platform_link_get_type (NM_PLATFORM_GET, ifindex));
	accept_signal (link_removed);

	/* Delete again */
	g_assert (!nm_platform_link_delete (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME)));

	/* VLAN: Delete parent */
	if (link_type == NM_LINK_TYPE_VLAN) {
		SignalData *link_removed_parent = add_signal_ifindex (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, link_callback, vlan_parent);

		g_assert (nm_platform_link_delete (NM_PLATFORM_GET, vlan_parent));
		accept_signal (link_removed_parent);
		free_signal (link_removed_parent);
	}

	/* No pending signal */
	free_signal (link_added);
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
	if (nmtst_platform_is_root_test () &&
	    !g_file_test ("/proc/1/net/bonding", G_FILE_TEST_IS_DIR) &&
	    system("modprobe --show bonding") != 0) {
		g_test_skip ("Skipping test for bonding: bonding module not available");
		return;
	}

	test_software (NM_LINK_TYPE_BOND, "bond");
}

static void
test_team (void)
{
	test_software (NM_LINK_TYPE_TEAM, "team");
}

static void
test_vlan (void)
{
	test_software (NM_LINK_TYPE_VLAN, "vlan");
}

static void
test_internal (void)
{
	SignalData *link_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_ADDED, link_callback, DEVICE_NAME);
	SignalData *link_changed, *link_removed;
	const char mac[6] = { 0x00, 0xff, 0x11, 0xee, 0x22, 0xdd };
	const char *address;
	size_t addrlen;
	int ifindex;

	/* Check the functions for non-existent devices */
	g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, DEVICE_NAME));
	g_assert (!nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME));

	/* Add device */
	g_assert (nm_platform_dummy_add (NM_PLATFORM_GET, DEVICE_NAME, NULL) == NM_PLATFORM_ERROR_SUCCESS);
	accept_signal (link_added);

	/* Try to add again */
	g_assert (nm_platform_dummy_add (NM_PLATFORM_GET, DEVICE_NAME, NULL) == NM_PLATFORM_ERROR_EXISTS);

	/* Check device index, name and type */
	ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	g_assert (ifindex > 0);
	g_assert_cmpstr (nm_platform_link_get_name (NM_PLATFORM_GET, ifindex), ==, DEVICE_NAME);
	g_assert_cmpint (nm_platform_link_get_type (NM_PLATFORM_GET, ifindex), ==, NM_LINK_TYPE_DUMMY);
	g_assert_cmpstr (nm_platform_link_get_type_name (NM_PLATFORM_GET, ifindex), ==, DUMMY_TYPEDESC);
	link_changed = add_signal_ifindex (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_CHANGED, link_callback, ifindex);
	link_removed = add_signal_ifindex (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, link_callback, ifindex);

	/* Up/connected */
	g_assert (!nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));
	g_assert (!nm_platform_link_is_connected (NM_PLATFORM_GET, ifindex));
	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, ifindex, NULL));
	g_assert (nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));
	g_assert (nm_platform_link_is_connected (NM_PLATFORM_GET, ifindex));
	accept_signal (link_changed);
	g_assert (nm_platform_link_set_down (NM_PLATFORM_GET, ifindex));
	g_assert (!nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));
	g_assert (!nm_platform_link_is_connected (NM_PLATFORM_GET, ifindex));
	accept_signal (link_changed);

	/* arp/noarp */
	g_assert (!nm_platform_link_uses_arp (NM_PLATFORM_GET, ifindex));
	g_assert (nm_platform_link_set_arp (NM_PLATFORM_GET, ifindex));
	g_assert (nm_platform_link_uses_arp (NM_PLATFORM_GET, ifindex));
	accept_signal (link_changed);
	g_assert (nm_platform_link_set_noarp (NM_PLATFORM_GET, ifindex));
	g_assert (!nm_platform_link_uses_arp (NM_PLATFORM_GET, ifindex));
	accept_signal (link_changed);

	/* Features */
	g_assert (!nm_platform_link_supports_carrier_detect (NM_PLATFORM_GET, ifindex));
	g_assert (nm_platform_link_supports_vlans (NM_PLATFORM_GET, ifindex));

	/* Set MAC address */
	g_assert (nm_platform_link_set_address (NM_PLATFORM_GET, ifindex, mac, sizeof (mac)));
	address = nm_platform_link_get_address (NM_PLATFORM_GET, ifindex, &addrlen);
	g_assert (addrlen == sizeof(mac));
	g_assert (!memcmp (address, mac, addrlen));
	address = nm_platform_link_get_address (NM_PLATFORM_GET, ifindex, NULL);
	g_assert (!memcmp (address, mac, addrlen));
	accept_signal (link_changed);

	/* Set MTU */
	g_assert (nm_platform_link_set_mtu (NM_PLATFORM_GET, ifindex, MTU));
	g_assert_cmpint (nm_platform_link_get_mtu (NM_PLATFORM_GET, ifindex), ==, MTU);
	accept_signal (link_changed);

	/* Delete device */
	g_assert (nm_platform_link_delete (NM_PLATFORM_GET, ifindex));
	accept_signal (link_removed);

	/* Try to delete again */
	g_assert (!nm_platform_link_delete (NM_PLATFORM_GET, ifindex));

	free_signal (link_added);
	free_signal (link_changed);
	free_signal (link_removed);
}

static void
test_external (void)
{
	const NMPlatformLink *pllink;
	SignalData *link_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_ADDED, link_callback, DEVICE_NAME);
	SignalData *link_changed, *link_removed;
	int ifindex;

	run_command ("ip link add %s type %s", DEVICE_NAME, "dummy");
	wait_signal (link_added);

	g_assert (nm_platform_link_get_by_ifname (NM_PLATFORM_GET, DEVICE_NAME));
	ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	g_assert (ifindex > 0);
	g_assert_cmpstr (nm_platform_link_get_name (NM_PLATFORM_GET, ifindex), ==, DEVICE_NAME);
	g_assert_cmpint (nm_platform_link_get_type (NM_PLATFORM_GET, ifindex), ==, NM_LINK_TYPE_DUMMY);
	g_assert_cmpstr (nm_platform_link_get_type_name (NM_PLATFORM_GET, ifindex), ==, DUMMY_TYPEDESC);
	link_changed = add_signal_ifindex (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_CHANGED, link_callback, ifindex);
	link_removed = add_signal_ifindex (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, link_callback, ifindex);

	pllink = nm_platform_link_get (NM_PLATFORM_GET, ifindex);
	g_assert (pllink);
	if (!pllink->initialized) {
		/* we still lack the notification via UDEV. Expect another link changed signal. */
		wait_signal (link_changed);
	}

	/* Up/connected/arp */
	g_assert (!nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));
	g_assert (!nm_platform_link_is_connected (NM_PLATFORM_GET, ifindex));
	g_assert (!nm_platform_link_uses_arp (NM_PLATFORM_GET, ifindex));

	run_command ("ip link set %s up", DEVICE_NAME);
	wait_signal (link_changed);

	g_assert (nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));
	g_assert (nm_platform_link_is_connected (NM_PLATFORM_GET, ifindex));
	run_command ("ip link set %s down", DEVICE_NAME);
	wait_signal (link_changed);
	g_assert (!nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));
	g_assert (!nm_platform_link_is_connected (NM_PLATFORM_GET, ifindex));

	run_command ("ip link set %s arp on", DEVICE_NAME);
	wait_signal (link_changed);
	g_assert (nm_platform_link_uses_arp (NM_PLATFORM_GET, ifindex));
	run_command ("ip link set %s arp off", DEVICE_NAME);
	wait_signal (link_changed);
	g_assert (!nm_platform_link_uses_arp (NM_PLATFORM_GET, ifindex));

	run_command ("ip link del %s", DEVICE_NAME);
	wait_signal (link_removed);
	accept_signals (link_changed, 0, 1);
	g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, DEVICE_NAME));

	free_signal (link_added);
	free_signal (link_changed);
	free_signal (link_removed);
}

void
init_tests (int *argc, char ***argv)
{
	nmtst_init_with_logging (argc, argv, NULL, "ALL");
}

void
setup_tests (void)
{
	nm_platform_link_delete (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME));
	nm_platform_link_delete (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, SLAVE_NAME));
	nm_platform_link_delete (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, PARENT_NAME));
	g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, DEVICE_NAME));
	g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, SLAVE_NAME));
	g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, PARENT_NAME));

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
