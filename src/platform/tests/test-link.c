#include "config.h"

#include "nmp-object.h"

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

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING, "*failure changing link: netlink error (No such device*");
	g_assert (!nm_platform_link_set_up (NM_PLATFORM_GET, BOGUS_IFINDEX, NULL));

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING, "*failure changing link: netlink error (No such device*");
	g_assert (!nm_platform_link_set_down (NM_PLATFORM_GET, BOGUS_IFINDEX));

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING, "*failure changing link: netlink error (No such device*");
	g_assert (!nm_platform_link_set_arp (NM_PLATFORM_GET, BOGUS_IFINDEX));

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING, "*failure changing link: netlink error (No such device*");
	g_assert (!nm_platform_link_set_noarp (NM_PLATFORM_GET, BOGUS_IFINDEX));

	g_assert (!nm_platform_link_is_up (NM_PLATFORM_GET, BOGUS_IFINDEX));
	g_assert (!nm_platform_link_is_connected (NM_PLATFORM_GET, BOGUS_IFINDEX));
	g_assert (!nm_platform_link_uses_arp (NM_PLATFORM_GET, BOGUS_IFINDEX));

	g_assert (!nm_platform_link_get_address (NM_PLATFORM_GET, BOGUS_IFINDEX, &addrlen));
	g_assert (!addrlen);
	g_assert (!nm_platform_link_get_address (NM_PLATFORM_GET, BOGUS_IFINDEX, NULL));

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING, "*failure changing link: netlink error (No such device*");
	g_assert (!nm_platform_link_set_mtu (NM_PLATFORM_GET, BOGUS_IFINDEX, MTU));

	g_assert (!nm_platform_link_get_mtu (NM_PLATFORM_GET, BOGUS_IFINDEX));

	g_assert (!nm_platform_link_supports_carrier_detect (NM_PLATFORM_GET, BOGUS_IFINDEX));
	g_assert (!nm_platform_link_supports_vlans (NM_PLATFORM_GET, BOGUS_IFINDEX));

	g_assert (!nm_platform_link_get_lnk_vlan (NM_PLATFORM_GET, BOGUS_IFINDEX, NULL));
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
test_link_changed_signal_cb (NMPlatform *platform,
                             NMPObjectType obj_type,
                             int ifindex,
                             const NMPlatformIP4Route *route,
                             NMPlatformSignalChangeType change_type,
                             NMPlatformReason reason,
                             gboolean *p_test_link_changed_signal_arg)
{
	/* test invocation of platform signals with multiple listeners
	 * connected to the signal. Platform signals have enum-typed
	 * arguments and there seem to be an issue with invoking such
	 * signals on s390x and ppc64 archs.
	 * https://bugzilla.redhat.com/show_bug.cgi?id=1260577
	 *
	 * As the test shows, the failure is not reproducible for
	 * platform signals.
	 */
	g_assert (NM_IS_PLATFORM (platform));
	g_assert (platform == NM_PLATFORM_GET);

	g_assert (ifindex > 0);
	g_assert (route);

	g_assert_cmpint (obj_type, ==, NMP_OBJECT_TYPE_LINK);

	g_assert_cmpint ((gint64) change_type, !=, (gint64) 0);
	g_assert_cmpint (change_type, !=, NM_PLATFORM_SIGNAL_NONE);

	g_assert_cmpint ((gint64) reason, !=, (gint64) 0);
	g_assert_cmpint (reason, !=, NM_PLATFORM_REASON_NONE);

	*p_test_link_changed_signal_arg = TRUE;
}

static void
test_slave (int master, int type, SignalData *master_changed)
{
	int ifindex;
	SignalData *link_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_ADDED, link_callback, SLAVE_NAME);
	SignalData *link_changed, *link_removed;
	char *value;
	NMLinkType link_type = nm_platform_link_get_type (NM_PLATFORM_GET, master);
	gboolean test_link_changed_signal_arg1;
	gboolean test_link_changed_signal_arg2;

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

	test_link_changed_signal_arg1 = FALSE;
	test_link_changed_signal_arg2 = FALSE;
	g_signal_connect (NM_PLATFORM_GET, NM_PLATFORM_SIGNAL_LINK_CHANGED, G_CALLBACK (test_link_changed_signal_cb), &test_link_changed_signal_arg1);
	g_signal_connect (NM_PLATFORM_GET, NM_PLATFORM_SIGNAL_LINK_CHANGED, G_CALLBACK (test_link_changed_signal_cb), &test_link_changed_signal_arg2);

	/* Set master up */
	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, master, NULL));
	g_assert (nm_platform_link_is_up (NM_PLATFORM_GET, master));
	accept_signals (master_changed, 1, 2);

	g_signal_handlers_disconnect_by_func (NM_PLATFORM_GET, G_CALLBACK (test_link_changed_signal_cb), &test_link_changed_signal_arg1);
	g_signal_handlers_disconnect_by_func (NM_PLATFORM_GET, G_CALLBACK (test_link_changed_signal_cb), &test_link_changed_signal_arg2);
	g_assert (test_link_changed_signal_arg1);
	g_assert (test_link_changed_signal_arg2);

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
		if (nmtstp_is_sysfs_writable ()) {
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
	int vlan_parent = -1, vlan_id;

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
		const NMPlatformLink *plink;
		const NMPlatformLnkVlan *plnk;

		plnk = nm_platform_link_get_lnk_vlan (NM_PLATFORM_GET, ifindex, &plink);
		g_assert (plnk);
		g_assert (plink);

		vlan_parent = plink->parent;
		vlan_id = plnk->id;
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
		if (nmtstp_is_sysfs_writable ()) {
			g_assert (nm_platform_master_set_option (NM_PLATFORM_GET, ifindex, "forward_delay", "789"));
			value = nm_platform_master_get_option (NM_PLATFORM_GET, ifindex, "forward_delay");
			g_assert_cmpstr (value, ==, "789");
			g_free (value);
		}
		break;
	case NM_LINK_TYPE_BOND:
		if (nmtstp_is_sysfs_writable ()) {
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
	if (nmtstp_is_root_test () &&
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

/*****************************************************************************/

static void
test_bridge_addr (void)
{
	char addr[ETH_ALEN];
	NMPlatformLink link;
	const NMPlatformLink *plink;

	nm_utils_hwaddr_aton ("de:ad:be:ef:00:11", addr, sizeof (addr));

	g_assert_cmpint (nm_platform_bridge_add (NM_PLATFORM_GET, DEVICE_NAME, addr, sizeof (addr), &link), ==, NM_PLATFORM_ERROR_SUCCESS);
	g_assert_cmpstr (link.name, ==, DEVICE_NAME);

	g_assert_cmpint (link.addr.len, ==, sizeof (addr));
	g_assert (!memcmp (link.addr.data, addr, sizeof (addr)));

	plink = nm_platform_link_get (NM_PLATFORM_GET, link.ifindex);
	g_assert (plink);

	if (nm_platform_check_support_user_ipv6ll (NM_PLATFORM_GET)) {
		g_assert (!nm_platform_link_get_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex));
		g_assert_cmpint (_nm_platform_uint8_inv (plink->inet6_addr_gen_mode_inv), ==, NM_IN6_ADDR_GEN_MODE_EUI64);

		g_assert (nm_platform_link_set_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex, TRUE));
		g_assert (nm_platform_link_get_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex));
		plink = nm_platform_link_get (NM_PLATFORM_GET, link.ifindex);
		g_assert (plink);
		g_assert_cmpint (_nm_platform_uint8_inv (plink->inet6_addr_gen_mode_inv), ==, NM_IN6_ADDR_GEN_MODE_NONE);

		g_assert (nm_platform_link_set_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex, FALSE));
		g_assert (!nm_platform_link_get_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex));
		plink = nm_platform_link_get (NM_PLATFORM_GET, link.ifindex);
		g_assert (plink);
		g_assert_cmpint (_nm_platform_uint8_inv (plink->inet6_addr_gen_mode_inv), ==, NM_IN6_ADDR_GEN_MODE_EUI64);
	}

	g_assert_cmpint (plink->addr.len, ==, sizeof (addr));
	g_assert (!memcmp (plink->addr.data, addr, sizeof (addr)));

	g_assert (nm_platform_link_delete (NM_PLATFORM_GET, link.ifindex));
	g_assert (!nm_platform_link_get (NM_PLATFORM_GET, link.ifindex));
}

/*****************************************************************************/

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

/*****************************************************************************/

static void
test_external (void)
{
	const NMPlatformLink *pllink;
	SignalData *link_added, *link_changed, *link_removed;
	int ifindex;

	link_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_ADDED, link_callback, DEVICE_NAME);

	nmtstp_run_command_check ("ip link add %s type %s", DEVICE_NAME, "dummy");
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

	nmtstp_run_command_check ("ip link set %s up", DEVICE_NAME);
	wait_signal (link_changed);

	g_assert (nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));
	g_assert (nm_platform_link_is_connected (NM_PLATFORM_GET, ifindex));
	nmtstp_run_command_check ("ip link set %s down", DEVICE_NAME);
	wait_signal (link_changed);
	g_assert (!nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));
	g_assert (!nm_platform_link_is_connected (NM_PLATFORM_GET, ifindex));

	nmtstp_run_command_check ("ip link set %s arp on", DEVICE_NAME);
	wait_signal (link_changed);
	g_assert (nm_platform_link_uses_arp (NM_PLATFORM_GET, ifindex));
	nmtstp_run_command_check ("ip link set %s arp off", DEVICE_NAME);
	wait_signal (link_changed);
	g_assert (!nm_platform_link_uses_arp (NM_PLATFORM_GET, ifindex));

	nmtstp_run_command_check ("ip link del %s", DEVICE_NAME);
	wait_signal (link_removed);
	accept_signals (link_changed, 0, 1);
	g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, DEVICE_NAME));

	free_signal (link_added);
	free_signal (link_changed);
	free_signal (link_removed);
}

/*****************************************************************************/

typedef struct {
	NMLinkType link_type;
	int test_mode;
} TestAddSoftwareDetectData;

static void
test_software_detect (gconstpointer user_data)
{
	const TestAddSoftwareDetectData *test_data = user_data;
	int ifindex, ifindex_parent;
	const NMPlatformLink *plink;
	const NMPObject *lnk;
	guint i_step;
	int exit_code;

	nmtstp_run_command_check ("ip link add %s type dummy", PARENT_NAME);
	ifindex_parent = nmtstp_assert_wait_for_link (PARENT_NAME, NM_LINK_TYPE_DUMMY, 100)->ifindex;

	switch (test_data->link_type) {
	case NM_LINK_TYPE_GRE: {
		gboolean gracefully_skip = FALSE;

		if (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "gre0")) {
			/* Seems that the ip_gre module is not loaded... try to load it. */
			gracefully_skip = nm_utils_modprobe (NULL, TRUE, "ip_gre", NULL) != 0;
		}
		exit_code = nmtstp_run_command ("ip tunnel add %s mode gre remote 172.168.10.25 local 192.168.233.204 ttl 174", DEVICE_NAME);
		if (exit_code != 0) {
			if (gracefully_skip) {
				g_test_skip ("Cannot create gre tunnel because of missing ip_gre module (modprobe ip_gre)");
				goto out_delete_parent;
			}
			g_error ("Failed adding GRE tunnel: exit code %d", exit_code);
		}
		break;
	}
	case NM_LINK_TYPE_MACVLAN:
		nmtstp_run_command_check ("ip link add name %s link %s type macvlan", DEVICE_NAME, PARENT_NAME);
		break;
	case NM_LINK_TYPE_VLAN:
		nmtstp_run_command_check ("ip link add name %s link %s type vlan id 1242", DEVICE_NAME, PARENT_NAME);
		break;
	case NM_LINK_TYPE_VXLAN:
		switch (test_data->test_mode) {
		case 0:
			nmtstp_run_command_check ("ip link add %s type vxlan id 42 local 23.1.2.164 group 239.1.2.134 dev %s ageing 1245 dstport 4789", DEVICE_NAME, PARENT_NAME);
			break;
		case 1:
			nmtstp_run_command_check ("ip link add %s type vxlan id 11214423 local 1:2:3:4:334:23::23 group ff0e::115 dev %s ageing 3245 dstport 57412", DEVICE_NAME, PARENT_NAME);
			break;
		}
		break;
	default:
		g_assert_not_reached ();
	}

	ifindex = nmtstp_assert_wait_for_link (DEVICE_NAME, test_data->link_type, 100)->ifindex;

	nmtstp_link_set_updown (-1, ifindex_parent, TRUE);

	for (i_step = 0; i_step < 5; i_step++) {

		_LOGD ("test-software-detect: step %u", i_step);
		if (nmtst_is_debug ())
			nmtstp_run_command_check ("ip -d link show %s", DEVICE_NAME);

		if (i_step > 0) {
			gboolean set_up = (i_step % 2) == 1;

			if (   test_data->link_type == NM_LINK_TYPE_VXLAN
			    && set_up) {
				/* On RHEL-7, we need to add a tiny sleep here, otherwise,
				 * upping the vxlan device fails with EADDRINUSE.
				 * https://bugzilla.redhat.com/show_bug.cgi?id=1277131 */
				g_usleep (1);
			}
			nmtstp_link_set_updown (-1, ifindex, set_up);
		}

		lnk = nm_platform_link_get_lnk (NM_PLATFORM_GET, ifindex, test_data->link_type, &plink);
		g_assert (plink);
		g_assert_cmpint (plink->ifindex, ==, ifindex);
		g_assert (lnk);

		switch (test_data->link_type) {
		case NM_LINK_TYPE_GRE: {
			const NMPlatformLnkGre *plnk = &lnk->lnk_gre;

			g_assert (plnk == nm_platform_link_get_lnk_gre (NM_PLATFORM_GET, ifindex, NULL));
			g_assert_cmpint (plnk->parent_ifindex, ==, 0);
			g_assert_cmpint (plnk->input_flags, ==, 0);
			g_assert_cmpint (plnk->output_flags, ==, 0);
			g_assert_cmpint (plnk->input_key, ==, 0);
			g_assert_cmpint (plnk->output_key, ==, 0);
			nmtst_assert_ip4_address (plnk->local, "192.168.233.204");
			nmtst_assert_ip4_address (plnk->remote, "172.168.10.25");
			g_assert_cmpint (plnk->ttl, ==, 174);
			g_assert_cmpint (plnk->tos, ==, 0);
			g_assert_cmpint (plnk->path_mtu_discovery, ==, TRUE);
			break;
		}
		case NM_LINK_TYPE_MACVLAN: {
			const NMPlatformLnkMacvlan *plnk = &lnk->lnk_macvlan;

			g_assert (plnk == nm_platform_link_get_lnk_macvlan (NM_PLATFORM_GET, ifindex, NULL));
			g_assert_cmpint (plnk->no_promisc, ==, FALSE);
			g_assert_cmpstr (plnk->mode, ==, "vepa");
			break;
		}
		case NM_LINK_TYPE_VLAN: {
			const NMPlatformLnkVlan *plnk = &lnk->lnk_vlan;

			g_assert (plnk == nm_platform_link_get_lnk_vlan (NM_PLATFORM_GET, ifindex, NULL));
			g_assert_cmpint (plnk->id, ==, 1242);
			break;
		}
		case NM_LINK_TYPE_VXLAN: {
			const NMPlatformLnkVxlan *plnk = &lnk->lnk_vxlan;

			g_assert (plnk == nm_platform_link_get_lnk_vxlan (NM_PLATFORM_GET, ifindex, NULL));
			g_assert_cmpint (plnk->parent_ifindex, !=, 0);
			g_assert_cmpint (plnk->tos, ==, 0);
			g_assert_cmpint (plnk->ttl, ==, 0);
			g_assert_cmpint (plnk->learning, ==, TRUE);
			g_assert_cmpint (plnk->limit, ==, 0);
			g_assert_cmpint (plnk->src_port_min, ==, 0);
			g_assert_cmpint (plnk->src_port_max, ==, 0);
			g_assert_cmpint (plnk->proxy, ==, FALSE);
			g_assert_cmpint (plnk->rsc, ==, FALSE);
			g_assert_cmpint (plnk->l2miss, ==, FALSE);
			g_assert_cmpint (plnk->l3miss, ==, FALSE);

			switch (test_data->test_mode) {
			case 0:
				g_assert_cmpint (plnk->id, ==, 42);
				nmtst_assert_ip4_address (plnk->local, "23.1.2.164");
				nmtst_assert_ip4_address (plnk->group, "239.1.2.134");
				nmtst_assert_ip6_address (&plnk->group6, "::");
				nmtst_assert_ip6_address (&plnk->local6, "::");
				g_assert_cmpint (plnk->ageing, ==, 1245);
				g_assert_cmpint (plnk->dst_port, ==, 4789);
				break;
			case 1:
				g_assert_cmpint (plnk->id, ==, 11214423);
				nmtst_assert_ip4_address (plnk->local, "0.0.0.0");
				nmtst_assert_ip4_address (plnk->group, "0.0.0.0");
				nmtst_assert_ip6_address (&plnk->group6, "ff0e::115");
				nmtst_assert_ip6_address (&plnk->local6, "1:2:3:4:334:23::23");
				g_assert_cmpint (plnk->ageing, ==, 3245);
				g_assert_cmpint (plnk->dst_port, ==, 57412);
				break;
			}
			break;
		}
		default:
			g_assert_not_reached ();
		}
	}

	g_assert (nm_platform_link_delete (NM_PLATFORM_GET, ifindex));
out_delete_parent:
	g_assert (nm_platform_link_delete (NM_PLATFORM_GET, ifindex_parent));
}

static void
test_software_detect_add (const char *testpath,
                          NMLinkType link_type,
                          int test_mode)
{
	TestAddSoftwareDetectData *test_data;

	test_data = g_new0 (TestAddSoftwareDetectData, 1);
	test_data->link_type = link_type;
	test_data->test_mode = test_mode;

	g_test_add_data_func_full (testpath, test_data, test_software_detect, g_free);
}

/*****************************************************************************/

static void
_assert_xgress_qos_mappings_impl (int ifindex,
                                  gboolean is_ingress_map ,
                                  int n_entries,
                                  int n,
                                  ...)
{
	const NMPlatformLink *plink;
	const NMPObject *lnk;
	guint n_map;
	const NMVlanQosMapping *map;
	va_list ap;
	guint i;

	lnk = nm_platform_link_get_lnk (NM_PLATFORM_GET, ifindex, NM_LINK_TYPE_VLAN, &plink);

	g_assert (plink);
	g_assert_cmpint (plink->ifindex, ==, ifindex);
	g_assert (lnk);
	g_assert (&lnk->lnk_vlan == nm_platform_link_get_lnk_vlan (NM_PLATFORM_GET, ifindex, NULL));

	if (nmtst_is_debug ())
		nmtstp_run_command_check ("ip -d link show %s", plink->name);

	if (is_ingress_map) {
		map = lnk->_lnk_vlan.ingress_qos_map;
		n_map = lnk->_lnk_vlan.n_ingress_qos_map;
	} else {
		map = lnk->_lnk_vlan.egress_qos_map;
		n_map = lnk->_lnk_vlan.n_egress_qos_map;
	}

	if (n_entries != -1)
		g_assert_cmpint (n_map, ==, n_entries);

	for (i = 0; i < n_map; i++) {
		if (is_ingress_map) {
			g_assert_cmpint (map[i].from, >=, 0);
			g_assert_cmpint (map[i].from, <=, 7);
		}
		if (i > 0)
			g_assert_cmpint (map[i - 1].from, <, map[i].from);
	}

	va_start (ap, n);
	for (; n > 0; n--) {
		gboolean found = FALSE;
		guint from = va_arg (ap, guint);
		guint to = va_arg (ap, guint);

		for (i = 0; i < n_map; i++) {
			if (map[i].from == from) {
				g_assert (!found);
				found = TRUE;

				g_assert (map[i].to == to);
			}
		}
		g_assert (found);
	}
	va_end (ap);
}
#define _assert_xgress_qos_mappings(ifindex, is_ingress_map, n_entries, ...) \
	_assert_xgress_qos_mappings_impl ((ifindex), (is_ingress_map), (n_entries), \
	                                  (G_STATIC_ASSERT_EXPR ((NM_NARG (__VA_ARGS__) % 2) == 0), NM_NARG (__VA_ARGS__) / 2), \
	                                  __VA_ARGS__)
#define _assert_ingress_qos_mappings(ifindex, n_entries, ...) _assert_xgress_qos_mappings (ifindex, TRUE, n_entries, __VA_ARGS__)
#define _assert_egress_qos_mappings(ifindex, n_entries, ...)  _assert_xgress_qos_mappings (ifindex, FALSE, n_entries, __VA_ARGS__)

static void
_assert_vlan_flags (int ifindex, NMVlanFlags flags)
{
	const NMPlatformLnkVlan *plnk;

	plnk = nm_platform_link_get_lnk_vlan (NM_PLATFORM_GET, ifindex, NULL);
	g_assert (plnk);
	g_assert_cmpint (plnk->flags, ==, flags);
}

static void
test_vlan_set_xgress (void)
{
	int ifindex, ifindex_parent;

	nmtstp_run_command_check ("ip link add %s type dummy", PARENT_NAME);
	ifindex_parent = nmtstp_assert_wait_for_link (PARENT_NAME, NM_LINK_TYPE_DUMMY, 100)->ifindex;

	nmtstp_run_command_check ("ip link add name %s link %s type vlan id 1245", DEVICE_NAME, PARENT_NAME);
	ifindex = nmtstp_assert_wait_for_link (DEVICE_NAME, NM_LINK_TYPE_VLAN, 100)->ifindex;

	/* ingress-qos-map */

	g_assert (nm_platform_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 4, 5));
	_assert_ingress_qos_mappings (ifindex, 1,
	                              4, 5);

	g_assert (nm_platform_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 3, 7));
	_assert_ingress_qos_mappings (ifindex, 2,
	                              3, 7,
	                              4, 5);

	g_assert (nm_platform_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 3, 8));
	_assert_ingress_qos_mappings (ifindex, 2,
	                              3, 8,
	                              4, 5);

	g_assert (nm_platform_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 0, 4));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, 4,
	                              3, 8,
	                              4, 5);

	g_assert (nm_platform_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 0, G_MAXUINT32));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, G_MAXUINT32,
	                              3, 8,
	                              4, 5);

	g_assert (nm_platform_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 0, G_MAXUINT32 - 1));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, G_MAXUINT32 - 1,
	                              3, 8,
	                              4, 5);

	g_assert (nm_platform_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 0, 5));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, 5,
	                              3, 8,
	                              4, 5);

	g_assert (nm_platform_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 0, 5));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, 5,
	                              3, 8,
	                              4, 5);

	/* Set invalid values: */
	g_assert (nm_platform_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 8, 3));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, 5,
	                              3, 8,
	                              4, 5);

	g_assert (nm_platform_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 9, 4));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, 5,
	                              3, 8,
	                              4, 5);

	/* egress-qos-map */

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 7, 3));
	_assert_egress_qos_mappings (ifindex, 1,
	                             7, 3);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 8, 4));
	_assert_egress_qos_mappings (ifindex, 2,
	                             7, 3,
	                             8, 4);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 0, 4));
	_assert_egress_qos_mappings (ifindex, 3,
	                             0, 4,
	                             7, 3,
	                             8, 4);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 1, 4));
	_assert_egress_qos_mappings (ifindex, 4,
	                             0, 4,
	                             1, 4,
	                             7, 3,
	                             8, 4);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 1, 5));
	_assert_egress_qos_mappings (ifindex, 4,
	                             0, 4,
	                             1, 5,
	                             7, 3,
	                             8, 4);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 9, 5));
	_assert_egress_qos_mappings (ifindex, 5,
	                             0, 4,
	                             1, 5,
	                             7, 3,
	                             8, 4,
	                             9, 5);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 8, 5));
	_assert_egress_qos_mappings (ifindex, 5,
	                             0, 4,
	                             1, 5,
	                             7, 3,
	                             8, 5,
	                             9, 5);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 8, 0));
	_assert_egress_qos_mappings (ifindex, 4,
	                             0, 4,
	                             1, 5,
	                             7, 3,
	                             9, 5);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 0, 0));
	_assert_egress_qos_mappings (ifindex, 3,
	                             1, 5,
	                             7, 3,
	                             9, 5);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 100, 4));
	_assert_egress_qos_mappings (ifindex, 4,
	                             1, 5,
	                             7, 3,
	                             9, 5,
	                             100, 4);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, G_MAXUINT32, 4));
	_assert_egress_qos_mappings (ifindex, 5,
	                             1, 5,
	                             7, 3,
	                             9, 5,
	                             100, 4,
	                             G_MAXUINT32, 4);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, G_MAXUINT32, 8));
	_assert_egress_qos_mappings (ifindex, 5,
	                             1, 5,
	                             7, 3,
	                             9, 5,
	                             100, 4,
	                             G_MAXUINT32, 4);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, G_MAXUINT32, 0));
	_assert_egress_qos_mappings (ifindex, 4,
	                             1, 5,
	                             7, 3,
	                             9, 5,
	                             100, 4);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 100, 0));
	_assert_egress_qos_mappings (ifindex, 3,
	                             1, 5,
	                             7, 3,
	                             9, 5);

	g_assert (nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 1, 0));
	_assert_egress_qos_mappings (ifindex, 2,
	                             7, 3,
	                             9, 5);

	{
		const NMVlanQosMapping ingress_map[] = {
			{ .from = 1, .to = 5 },
		};

		g_assert (nm_platform_link_vlan_change (NM_PLATFORM_GET,
		                                        ifindex,
		                                        0,
		                                        0,
		                                        TRUE,
		                                        ingress_map,
		                                        G_N_ELEMENTS (ingress_map),
		                                        FALSE,
		                                        NULL,
		                                        0));
		_assert_ingress_qos_mappings (ifindex, 1,
		                              1, 5);
	}

	{
		const NMVlanQosMapping ingress_map[] = {
			{ .from = 3, .to = 5 },
			{ .from = 7, .to = 1655 },
			{ .from = 7, .to = 17655 },
			{ .from = 5, .to = 754 },
			{ .from = 4, .to = 12 },
		};

		g_assert (nm_platform_link_vlan_change (NM_PLATFORM_GET,
		                                        ifindex,
		                                        0,
		                                        0,
		                                        TRUE,
		                                        ingress_map,
		                                        G_N_ELEMENTS (ingress_map),
		                                        FALSE,
		                                        NULL,
		                                        0));
		_assert_ingress_qos_mappings (ifindex, 4,
		                              3, 5,
		                              4, 12,
		                              7, 17655,
		                              5, 754);
	}

	{
		const NMVlanQosMapping ingress_map[] = {
			{ .from = 3, .to = 18 },
			{ .from = 6, .to = 121 },
		};

		g_assert (nm_platform_link_vlan_change (NM_PLATFORM_GET,
		                                        ifindex,
		                                        0,
		                                        0,
		                                        FALSE,
		                                        ingress_map,
		                                        G_N_ELEMENTS (ingress_map),
		                                        FALSE,
		                                        NULL,
		                                        0));
		_assert_ingress_qos_mappings (ifindex, 5,
		                              3, 18,
		                              4, 12,
		                              6, 121,
		                              7, 17655,
		                              5, 754);
	}

	{
		const NMVlanQosMapping ingress_map[] = {
			{ .from = 3, .to = 0 },
			{ .from = 6, .to = 7 },
		};

		g_assert (nm_platform_link_vlan_change (NM_PLATFORM_GET,
		                                        ifindex,
		                                        0,
		                                        0,
		                                        TRUE,
		                                        ingress_map,
		                                        G_N_ELEMENTS (ingress_map),
		                                        FALSE,
		                                        NULL,
		                                        0));
		_assert_ingress_qos_mappings (ifindex, 1,
		                              6, 7);
	}


	{
		const NMVlanQosMapping ingress_map[] = {
			{ .from = 1, .to = 5 },
		};

		g_assert (nm_platform_link_vlan_change (NM_PLATFORM_GET,
		                                        ifindex,
		                                        0,
		                                        0,
		                                        TRUE,
		                                        ingress_map,
		                                        G_N_ELEMENTS (ingress_map),
		                                        FALSE,
		                                        NULL,
		                                        0));
		_assert_ingress_qos_mappings (ifindex, 1,
		                              1, 5);
	}

	{
		const NMVlanQosMapping egress_map[] = {
			{ .from = 5, .to = 1 },
		};

		g_assert (nm_platform_link_vlan_change (NM_PLATFORM_GET,
		                                        ifindex,
		                                        0,
		                                        0,
		                                        FALSE,
		                                        NULL,
		                                        0,
		                                        TRUE,
		                                        egress_map,
		                                        G_N_ELEMENTS (egress_map)));
		_assert_egress_qos_mappings (ifindex, 1,
		                             5, 1);
	}

	{
		const NMVlanQosMapping egress_map[] = {
			{ .from = 5, .to = 3 },
			{ .from = 1655, .to = 5 },
			{ .from = 1655, .to = 7 },
			{ .from = G_MAXUINT32, .to = 6 },
			{ .from = G_MAXUINT32, .to = 8 },
			{ .from = 754, .to = 4 },
			{ .from = 3, .to = 2 },
		};

		g_assert (nm_platform_link_vlan_change (NM_PLATFORM_GET,
		                                        ifindex,
		                                        0,
		                                        0,
		                                        FALSE,
		                                        NULL,
		                                        0,
		                                        TRUE,
		                                        egress_map,
		                                        G_N_ELEMENTS (egress_map)));
		_assert_egress_qos_mappings (ifindex, 5,
		                             3, 2,
		                             5, 3,
		                             754, 4,
		                             1655, 7,
		                             G_MAXUINT32, 6);
	}

	{
		const NMVlanQosMapping egress_map[] = {
			{ .from = 754, .to = 3 },
			{ .from = 755, .to = 8 },
			{ .from = 1655, .to = 0 },
			{ .from = 6, .to = 1 },
		};

		g_assert (nm_platform_link_vlan_change (NM_PLATFORM_GET,
		                                        ifindex,
		                                        0,
		                                        0,
		                                        FALSE,
		                                        NULL,
		                                        0,
		                                        FALSE,
		                                        egress_map,
		                                        G_N_ELEMENTS (egress_map)));
		_assert_egress_qos_mappings (ifindex, 5,
		                             3, 2,
		                             5, 3,
		                             6, 1,
		                             754, 3,
		                             G_MAXUINT32, 6);
	}

	{
		const NMVlanQosMapping egress_map[] = {
			{ .from = 6, .to = 0 },
			{ .from = 3, .to = 4 },
		};

		g_assert (nm_platform_link_vlan_change (NM_PLATFORM_GET,
		                                        ifindex,
		                                        0,
		                                        0,
		                                        FALSE,
		                                        NULL,
		                                        0,
		                                        TRUE,
		                                        egress_map,
		                                        G_N_ELEMENTS (egress_map)));
		_assert_egress_qos_mappings (ifindex, 1,
		                             3, 4);
	}

	{
		const NMVlanQosMapping egress_map[] = {
			{ .from = 1, .to = 5 },
		};

		g_assert (nm_platform_link_vlan_change (NM_PLATFORM_GET,
		                                        ifindex,
		                                        0,
		                                        0,
		                                        FALSE,
		                                        NULL,
		                                        0,
		                                        TRUE,
		                                        egress_map,
		                                        G_N_ELEMENTS (egress_map)));
		_assert_egress_qos_mappings (ifindex, 1,
		                             1, 5);
	}

	{
		const NMVlanQosMapping ingress_map[] = {
			{ .from = 6, .to = 145 },
			{ .from = 4, .to = 1 },
			{ .from = 6, .to = 12 },
		};
		const NMVlanQosMapping egress_map[] = {
			{ .from = 1, .to = 5 },
			{ .from = 3232, .to = 7 },
		};

		g_assert (nm_platform_link_vlan_change (NM_PLATFORM_GET,
		                                        ifindex,
		                                        NM_VLAN_FLAG_REORDER_HEADERS | NM_VLAN_FLAG_GVRP,
		                                        NM_VLAN_FLAG_REORDER_HEADERS,
		                                        TRUE,
		                                        ingress_map,
		                                        G_N_ELEMENTS (ingress_map),
		                                        TRUE,
		                                        egress_map,
		                                        G_N_ELEMENTS (egress_map)));
		_assert_ingress_qos_mappings (ifindex, 2,
		                             4, 1,
		                             6, 12);
		_assert_egress_qos_mappings (ifindex, 2,
		                             1, 5,
		                             3232, 7);
		_assert_vlan_flags (ifindex, NM_VLAN_FLAG_REORDER_HEADERS);
	}

	{
		const NMVlanQosMapping ingress_map[] = {
			{ .from = 6, .to = 145 },
			{ .from = 4, .to = 1 },
			{ .from = 6, .to = 12 },
		};
		const NMVlanQosMapping egress_map[] = {
			{ .from = 1, .to = 7 },
			{ .from = 64, .to = 10 },
			{ .from = 64, .to = 10 },
			{ .from = 64, .to = 10 },
			{ .from = 64, .to = 10 },
			{ .from = 3232, .to = 0 },
			{ .from = 64, .to = 4 },
		};

		g_assert (nm_platform_link_vlan_change (NM_PLATFORM_GET,
		                                        ifindex,
		                                        NM_VLAN_FLAG_GVRP,
		                                        NM_VLAN_FLAG_GVRP,
		                                        FALSE,
		                                        ingress_map,
		                                        G_N_ELEMENTS (ingress_map),
		                                        FALSE,
		                                        egress_map,
		                                        G_N_ELEMENTS (egress_map)));
		_assert_ingress_qos_mappings (ifindex, 2,
		                             4, 1,
		                             6, 12);
		_assert_egress_qos_mappings (ifindex, 2,
		                             1, 7,
		                             64, 4);
		_assert_vlan_flags (ifindex, NM_VLAN_FLAG_REORDER_HEADERS | NM_VLAN_FLAG_GVRP);
	}

	g_assert (nm_platform_link_delete (NM_PLATFORM_GET, ifindex));
	g_assert (nm_platform_link_delete (NM_PLATFORM_GET, ifindex_parent));
}

/*****************************************************************************/

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
	g_test_add_func ("/link/software/bridge/addr", test_bridge_addr);

	if (nmtstp_is_root_test ()) {
		g_test_add_func ("/link/external", test_external);

		test_software_detect_add ("/link/software/detect/gre", NM_LINK_TYPE_GRE, 0);
		test_software_detect_add ("/link/software/detect/macvlan", NM_LINK_TYPE_MACVLAN, 0);
		test_software_detect_add ("/link/software/detect/vlan", NM_LINK_TYPE_VLAN, 0);
		test_software_detect_add ("/link/software/detect/vxlan/0", NM_LINK_TYPE_VXLAN, 0);
		test_software_detect_add ("/link/software/detect/vxlan/1", NM_LINK_TYPE_VXLAN, 1);

		g_test_add_func ("/link/software/vlan/set-xgress", test_vlan_set_xgress);
	}
}
