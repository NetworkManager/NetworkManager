/*
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
 * Copyright 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/if_tun.h>

#include "nm-glib-aux/nm-io-utils.h"
#include "platform/nmp-object.h"
#include "platform/nmp-netns.h"
#include "platform/nm-platform-utils.h"

#include "test-common.h"
#include "nm-test-utils-core.h"

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

#define _ADD_DUMMY(platform, name) \
	g_assert (NMTST_NM_ERR_SUCCESS (nm_platform_link_dummy_add ((platform), (name), NULL)))

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

	g_assert (!NMTST_NM_ERR_SUCCESS (nm_platform_link_set_mtu (NM_PLATFORM_GET, BOGUS_IFINDEX, MTU)));

	g_assert (!nm_platform_link_get_mtu (NM_PLATFORM_GET, BOGUS_IFINDEX));

	g_assert (!nm_platform_link_supports_carrier_detect (NM_PLATFORM_GET, BOGUS_IFINDEX));
	g_assert (!nm_platform_link_supports_vlans (NM_PLATFORM_GET, BOGUS_IFINDEX));

	g_assert (!nm_platform_link_get_lnk_vlan (NM_PLATFORM_GET, BOGUS_IFINDEX, NULL));
	g_assert (!nm_platform_link_vlan_set_ingress_map (NM_PLATFORM_GET, BOGUS_IFINDEX, 0, 0));
	g_assert (!nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, BOGUS_IFINDEX, 0, 0));
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
		return NMTST_NM_ERR_SUCCESS (nm_platform_link_dummy_add (NM_PLATFORM_GET, name, NULL));
	case NM_LINK_TYPE_BRIDGE:
		return NMTST_NM_ERR_SUCCESS (nm_platform_link_bridge_add (NM_PLATFORM_GET, name, NULL, 0, NULL));
	case NM_LINK_TYPE_BOND:
		{
			gboolean bond0_exists = !!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "bond0");
			int r;

			r = nm_platform_link_bond_add (NM_PLATFORM_GET, name, NULL);

			/* Check that bond0 is *not* automatically created. */
			if (!bond0_exists)
				g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "bond0"));
			return r >= 0;
		}
	case NM_LINK_TYPE_TEAM:
		return NMTST_NM_ERR_SUCCESS (nm_platform_link_team_add (NM_PLATFORM_GET, name, NULL));
	case NM_LINK_TYPE_VLAN: {
		SignalData *parent_added;
		SignalData *parent_changed;

		/* Don't call link_callback for the bridge interface */
		parent_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_ADDED, link_callback, PARENT_NAME);
		if (NMTST_NM_ERR_SUCCESS (nm_platform_link_bridge_add (NM_PLATFORM_GET, PARENT_NAME, NULL, 0, NULL)))
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
				accept_signals (parent_changed, 1, 2);
			free_signal (parent_changed);

			return NMTST_NM_ERR_SUCCESS (nm_platform_link_vlan_add (NM_PLATFORM_GET, name, parent_ifindex, VLAN_ID, 0, NULL));
		}
	}
	default:
		g_error ("Link type %d unhandled.", link_type);
	}
	g_assert_not_reached ();
}

static void
test_link_changed_signal_cb (NMPlatform *platform,
                             int obj_type_i,
                             int ifindex,
                             const NMPlatformIP4Route *route,
                             int change_type_i,
                             gboolean *p_test_link_changed_signal_arg)
{
	const NMPObjectType obj_type = obj_type_i;
	const NMPlatformSignalChangeType change_type = change_type_i;

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
	accept_signals (master_changed, 0, 2);

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
	accept_signals (master_changed, 1, 3);

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
		accept_signals (master_changed, 0, 3);
		break;
	default:
		break;
	}
	g_assert (!nm_platform_link_is_up (NM_PLATFORM_GET, ifindex));
	g_assert (!nm_platform_link_is_connected (NM_PLATFORM_GET, ifindex));
	if (   nmtstp_is_root_test ()
	    && nm_platform_link_is_connected (NM_PLATFORM_GET, master)) {
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
	accept_signals (master_changed, 0, 3);

	/* Enslave again
	 *
	 * Gracefully succeed if already enslaved.
	 */
	ensure_no_signal (link_changed);
	g_assert (nm_platform_link_enslave (NM_PLATFORM_GET, master, ifindex));
	accept_signals (link_changed, 0, 2);
	accept_signals (master_changed, 0, 2);

	/* Set slave option */
	switch (type) {
	case NM_LINK_TYPE_BRIDGE:
		if (nmtstp_is_sysfs_writable ()) {
			g_assert (nm_platform_sysctl_slave_set_option (NM_PLATFORM_GET, ifindex, "priority", "614"));
			value = nm_platform_sysctl_slave_get_option (NM_PLATFORM_GET, ifindex, "priority");
			g_assert_cmpstr (value, ==, "614");
			g_free (value);
		}
		break;
	default:
		break;
	}

	/* Release */
	ensure_no_signal (link_added);
	ensure_no_signal (link_changed);
	ensure_no_signal (link_removed);
	g_assert (nm_platform_link_release (NM_PLATFORM_GET, master, ifindex));
	g_assert_cmpint (nm_platform_link_get_master (NM_PLATFORM_GET, ifindex), ==, 0);
	if (link_changed->received_count > 0) {
		accept_signals (link_added, 0, 1);
		accept_signals (link_changed, 1, 5);
		accept_signals (link_removed, 0, 1);
	} else {
		/* Due to https://bugzilla.redhat.com/show_bug.cgi?id=1285719 , kernel might send a
		 * wrong RTM_DELLINK message so that we instead see an removed+added signal. */
		accept_signal (link_added);
		ensure_no_signal (link_changed);
		accept_signal (link_removed);
	}
	accept_signals (master_changed, 0, 3);

	ensure_no_signal (master_changed);

	/* Release again */
	ensure_no_signal (link_changed);
	g_assert (!nm_platform_link_release (NM_PLATFORM_GET, master, ifindex));

	ensure_no_signal (master_changed);

	/* Remove */
	ensure_no_signal (link_added);
	ensure_no_signal (link_changed);
	ensure_no_signal (link_removed);
	nmtstp_link_delete (NULL, -1, ifindex, NULL, TRUE);
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
	if (nmtstp_is_root_test ()) {
		switch (link_type) {
		case NM_LINK_TYPE_BRIDGE:
			if (nmtstp_is_sysfs_writable ()) {
				g_assert (nm_platform_sysctl_master_set_option (NM_PLATFORM_GET, ifindex, "forward_delay", "628"));
				value = nm_platform_sysctl_master_get_option (NM_PLATFORM_GET, ifindex, "forward_delay");
				g_assert_cmpstr (value, ==, "628");
				g_free (value);
			}
			break;
		case NM_LINK_TYPE_BOND:
			if (nmtstp_is_sysfs_writable ()) {
				g_assert (nm_platform_sysctl_master_set_option (NM_PLATFORM_GET, ifindex, "mode", "active-backup"));
				value = nm_platform_sysctl_master_get_option (NM_PLATFORM_GET, ifindex, "mode");
				/* When reading back, the output looks slightly different. */
				g_assert (g_str_has_prefix (value, "active-backup"));
				g_free (value);
			}
			break;
		default:
			break;
		}
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
	nmtstp_link_delete (NULL, -1, ifindex, DEVICE_NAME, TRUE);
	accept_signal (link_removed);

	/* Delete again */
	g_assert (nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME) <= 0);
	g_assert (!nm_platform_link_delete (NM_PLATFORM_GET, ifindex));

	/* VLAN: Delete parent */
	if (link_type == NM_LINK_TYPE_VLAN) {
		SignalData *link_removed_parent = add_signal_ifindex (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, link_callback, vlan_parent);

		nmtstp_link_delete (NULL, -1, vlan_parent, NULL, TRUE);
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

static int
_system (const char *cmd)
{
	/* some gcc version really want to warn on -Werror=unused-result. Add a bogus wrapper
	 * function. */
	return system (cmd);
}

static void
test_bond (void)
{
	if (nmtstp_is_root_test () &&
	    !g_file_test ("/proc/1/net/bonding", G_FILE_TEST_IS_DIR) &&
	    _system("modprobe --show bonding") != 0) {
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
	const NMPlatformLink *plink = NULL;

	nm_utils_hwaddr_aton ("de:ad:be:ef:00:11", addr, sizeof (addr));

	g_assert (NMTST_NM_ERR_SUCCESS (nm_platform_link_bridge_add (NM_PLATFORM_GET, DEVICE_NAME, addr, sizeof (addr), &plink)));
	g_assert (plink);
	link = *plink;
	g_assert_cmpstr (link.name, ==, DEVICE_NAME);

	g_assert_cmpint (link.l_address.len, ==, sizeof (addr));
	g_assert (!memcmp (link.l_address.data, addr, sizeof (addr)));

	plink = nm_platform_link_get (NM_PLATFORM_GET, link.ifindex);
	g_assert (plink);

	if (nm_platform_kernel_support_get (NM_PLATFORM_KERNEL_SUPPORT_TYPE_USER_IPV6LL)) {
		g_assert (!nm_platform_link_get_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex));
		g_assert_cmpint (_nm_platform_uint8_inv (plink->inet6_addr_gen_mode_inv), ==, NM_IN6_ADDR_GEN_MODE_EUI64);

		g_assert (NMTST_NM_ERR_SUCCESS (nm_platform_link_set_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex, TRUE)));
		g_assert (nm_platform_link_get_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex));
		plink = nm_platform_link_get (NM_PLATFORM_GET, link.ifindex);
		g_assert (plink);
		g_assert_cmpint (_nm_platform_uint8_inv (plink->inet6_addr_gen_mode_inv), ==, NM_IN6_ADDR_GEN_MODE_NONE);

		g_assert (NMTST_NM_ERR_SUCCESS (nm_platform_link_set_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex, FALSE)));
		g_assert (!nm_platform_link_get_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex));
		plink = nm_platform_link_get (NM_PLATFORM_GET, link.ifindex);
		g_assert (plink);
		g_assert_cmpint (_nm_platform_uint8_inv (plink->inet6_addr_gen_mode_inv), ==, NM_IN6_ADDR_GEN_MODE_EUI64);
	}

	g_assert_cmpint (plink->l_address.len, ==, sizeof (addr));
	g_assert (!memcmp (plink->l_address.data, addr, sizeof (addr)));

	nmtstp_link_delete (NULL, -1, link.ifindex, link.name, TRUE);
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
	g_assert (NMTST_NM_ERR_SUCCESS (nm_platform_link_dummy_add (NM_PLATFORM_GET, DEVICE_NAME, NULL)));
	accept_signal (link_added);

	/* Try to add again */
	g_assert (nm_platform_link_dummy_add (NM_PLATFORM_GET, DEVICE_NAME, NULL) == -NME_PL_EXISTS);

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
	accept_signals (link_changed, 1, 2);
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
	g_assert (NMTST_NM_ERR_SUCCESS (nm_platform_link_set_address (NM_PLATFORM_GET, ifindex, mac, sizeof (mac))));
	address = nm_platform_link_get_address (NM_PLATFORM_GET, ifindex, &addrlen);
	g_assert (addrlen == sizeof(mac));
	g_assert (!memcmp (address, mac, addrlen));
	address = nm_platform_link_get_address (NM_PLATFORM_GET, ifindex, NULL);
	g_assert (!memcmp (address, mac, addrlen));
	accept_signal (link_changed);

	/* Set MTU */
	g_assert (NMTST_NM_ERR_SUCCESS (nm_platform_link_set_mtu (NM_PLATFORM_GET, ifindex, MTU)));
	g_assert_cmpint (nm_platform_link_get_mtu (NM_PLATFORM_GET, ifindex), ==, MTU);
	accept_signal (link_changed);

	/* Delete device */
	nmtstp_link_delete (NULL, -1, ifindex, DEVICE_NAME, TRUE);
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

static guint8 *
_copy_base64 (guint8 *dst, gsize dst_len, const char *base64_src)
{
	g_assert (dst);
	g_assert (dst_len > 0);

	if (!base64_src)
		memset (dst, 0, dst_len);
	else {
		gs_free guint8 *b = NULL;
		gsize l;

		b = g_base64_decode (base64_src, &l);
		g_assert (b);
		g_assert (l == dst_len);

		memcpy (dst, b, dst_len);
	}
	return dst;
}

typedef struct {
	const char *pri;
	const char *pub;
	const char *pre;
} KeyPair;

static void
_test_wireguard_change (NMPlatform *platform,
                        int ifindex,
                        int test_mode)
{
	const KeyPair self_key =
		{ "yOWEsaXFxX9/DOkQPzqB9RufZOpfSP4LZZCErP0N0Xo=", "s6pVT2xPwktor9O5bVOSzcPqBu9uzQOUzPQHXLU2jmk=" };
	const KeyPair keys[100] = {
		{ "+BDHMh11bkheGfvlQpqt8P/H7N1sPXtVi05XraZS0E8=", "QItu7PJadBVXFXGv55CMtVnbRHdrI6E2CGlu2N5oGx4=", "2IvZnKTzbF1UlChznWSsEYtGbPjhYSTT41GXO6zLxvk=" },
		{ "qGZyV2BO1nyY/FGYd6elBPirwJC9QyZwqbm2OJAgLkY=", "v8L1FEitO0xo+wW/CVVUnALlw0zGveApSFdlITi/5lI=", "/R2c0JmBNGJzT594NQ0mBJ2XJjxt2QUSo+ZiqeY0EQA=" },
		{ "YDgsIb0oe+9NcxIx2r0HEEPQpRMxmRN0ALoLm9Sh40Q=", "nFPs1HaU7uFBvE9xZCMF8oOAjzLpZ49AzDHOluY1O2E=", "zsYED2Ef7zIHJoRBPcen+w4ktrRsLPEfYwZhWIuXfds=" },
		{ "kHkosM503LWu43tdYXbNwVOpRrtPgd9XFqcN7k4t6G4=", "b8e092WT+eNmnxCr5WE2QC/MXAjDagfG1g03cs2mBC0=", "VXz0ShGWT7H0CBCg2awfatmOJF15ZtaSMPhMsp+hc3A=" },
		{ "4C2w5CEnxH59Y2aa6CJXgLdDtWoNMS2UJounRCM1Jkk=", "gC/R9umlnEQL+Qsz/Y64AlsdMge4ECe5/u/JHZCMWSs=", "2bmL5ISr+V5a7l7xFJ695BLIJyBgx8xnxzybkxiRHOg=" },
		{ "KHJSzFGkXcZf/wbH2rr99SYtGKWbL680wA2AcDE94lo=", "BsN23h4aOi458Q3EgMQsodsWQxd9h/RxqskAUpsXfgg=", "nK4Zv34YKEhjuexhq1SgK4oTd4MZJT5gcpYvEuPjc7Q=" },
		{ "QGMulXJ9e3AVxtpi8+UUVqPOr/YBWvCNFVsWS9IUnUA=", "kjVclP5Ifi6og2BBCEHKS/aa/WktArB4+ig06lYaVlg=", "0+mmceDPcSRK3vFnYqHd9iAfY+Nyjzf/1KgDeYGlRkQ=" },
		{ "AOJiDD4y6GA7P7gugjjQG9Cctvc5Y27fajHz6aU3gU4=", "gEnHn6euHtcMEwZBlX6HANPeN9Of+voBDtltS38xDUw=", "wIH1OxgX6GLxx/bnR+t3fbmjGZDTU3WMxp7t1XGezqM=" },
		{ "COsls2BlCltaIrrq1+FU51cWddlmoPPppSeIDunOxGA=", "+n6WuV8Tb1/iZArTrHsyNqkRHABbavBQt9Me72K2KEc=", "t4baiprSO9ZbKD2/RutOY9cr+yCajQWZGCTnQdrFQj0=" },
		{ "uHawQq2BRyJlsTPoCa+MfBVnv4MwtRoS+S9FEpFOEVg=", "8lcmr27afeb6iI3BQCaDtvalF2Cl7gxRZgs+nyJ/fEg=", "Eh9o/6W60iujBLIHuRfNrPhOWAn7PambT2JRln9iwA0=" },
		{ "yL7hmoE/JfRGAotRzx9xOpjfrDA3BFlPEemFiQw40Wk=", "BHK0PHi5kp7rOfQ46oc9xlVpB+pZeZYXTtH7EXr5TwU=", "BS2h2ZZyW0BlYMmLR29xyHEcZ4jtO7rgj1jkz/EEaxU=" },
		{ "ON8YrTHQgoC5e0mAR9FakZ8hZ/9I7ysuE21sG546J1Y=", "Bm3l5I6iH1tDrv6EgdZU9PzHqp0H26Z6ggmmIypwxy8=", "qKVfbCnK1EI3eC28SsL+jyBnEnIF/nRJQJzDevBFdNQ=" },
		{ "KGLO0RI0VlQFCG+ETUqk25HdaKUnUPXKOKkTh/w8BXU=", "sBDBwQFC7k8UMdMzuavKBkBjYYKigzvYmGF5rm6muQc=", "BNfZF9d7540pUGGOQCh3iDxAZcPBqX4qqM00GSLPBek=" },
		{ "KGdWyEodIn7KKI2e4EFK9tT6Bt3bNMFBRFVTKjjJm2E=", "lrbjU/Xn9wDCZQiU8E5fY6igTSozghvo47QeVIIWaUk=", "LczqW48MW8qDQIZYRELsz/VCzVDc5niROvk7OqrTxR0=" },
		{ "wO3xinUGABgEmX+RJZbBbOtAmBuPPFG6oVdimvoo90w=", "dCIvTzR6EerOOsRKnWly1a9WGzbJ4qc+6t3SSzLgWFk=", "wFj0zpr5PadBoBy0couLuZ1qudZbXLbV/j3UT+AyKeo=" },
		{ "+JNOBlO4tp9vvQk6UO4r3sILyEgjl+BBoWketZufyn0=", "Q6LSv9y7YQkJEzQ/1mpjJEgOrO8GYPUTgcizjh7Cm34=", "kg7AG9MuN04xPJ5Z0IcNZ4a8d1b/n4GsGIeyA4FaaSE=" },
		{ "+EJcThLRwjZ+h1CNNFu15HWzznf4u/lPVw8hifTm2Ec=", "Kkn2jFqwBzyIFQfD0OpmePFSmBYmhKagv4pGgkqsWgE=", "jYpxojj8WKYe/XIXMP+uv1Fv0+TKrs83tqfzP0AGdcI=" },
		{ "+DKFqSMNFmxriEFj3qatuzYeTJ9+xWYspZ4ydL3eC0Q=", "3o37bsg6HhRg/M9+fTlLcFYc2w/Bz9rLQySvvYCKbRE=", "Jb9qoDIBat1EexlgfpRbXa7OflptME8/zt93bldkiVE=" },
		{ "EH3MjFOMqRoDFQz+hSlJpntWBeH3lTk6WPjTIQjr42o=", "PbPewED/nxSBLdM7AXMj7uS3bCgAAg8M6F4iPLd0b1U=", "pj4+UgOGkpJwlRvX5BRXZzmzAUnDtUtJsS7LzbcJWzw=" },
		{ "kL6M2KvO+vPBLEc/a0DpEHTibQ1bwaMRT9b9SkzeP0Y=", "pS3G2bHHlkOE6UHP0qVitDuxXgjEaZTviTjNc55RbVs=", "ZVZpWOtYqhX3CpF1kATg/38J6pvUJo8AS1sVYjs3rUE=" },
		{ "sFlcRLDn36fnew2Ld92IHJwnKifdS3aF1MWRPs6K3Wg=", "OpjUOTiWExaDYULTINB4yQFqc3mnU3RjQzGRV+KtdFY=", "of0V/uoFRNljv/XTt/tXgoquLRH93Ty0KNiaPUpEi2w=" },
		{ "UJ8hjDsg3jfsnnfPH8Gw9FnCb6taTuviurAfZu+kEFg=", "3byjHksUOv8CNjGGKvHvvrJDURBhCIL5UtfZbgyVWCE=", "9f7dbWif51gGrE7R9LeuewQSrvGFGTOB3ceJC67jSkI=" },
		{ "iFFPKGIfqeUKY/w72KAZSjd/PGTqCakHYBV10xMDfnI=", "ehneHATNSXtsJTOiPjVSc0QARkihgcfcvoXKFWKfQnI=", "yKdqDBcRwA7RCg4GiY/b5IsWcExPleOBde/hjxc36a4=" },
		{ "GDGocdPJTPUAllxQo7SpXZKqMPn7lpxQELQUX9ETHmE=", "n0ScNEou4ekfrXRRXvcADLu2Afj8g5D3TuDP/I4KrnY=", "8QhswqAhi/ehhcmCwQF5aSh80TvIGC/gRL5jBn5wOH8=" },
		{ "UCcrlN8fX2ZdNdhaEBNwktwL+H0ZO7fhaj7rgdUutmw=", "LF8J728ilXs4TphnrgR6r0p7W3912DYnsXkGMEPQnRE=", "cYfMjxl2REYir7frGeB0u+NHAaFYF02ysgpBhOL5ygc=" },
		{ "SH0657XuIiHidVmViXZF30RUWtkuWXcWWHmKZHTiOG8=", "7k6j49W1u5qgLE5MQUc1osPVW1oPPhzjrGvJ7o9YamY=", "dV2+7rNk/3LR2IcwYg/c+Wvzep1yjY7/u1I+nnlTQ00=" },
		{ "qFQWs6jzrscV42pGISQyA7JDvFFAvEQCWJi584VHD2g=", "AT63nHKLC17yUvkR4lOVPxCr4DD3QhXmcmecOTn+Amc=", "2Qe2fwJbFcu1CmKpktElOFkSQMqlyvlV3ZUIAd/Dcts=" },
		{ "6J+yLxgPwWtUbk9I3zbeD8RuK6XkQjJ0wTJ1zSVhflQ=", "NJzMBYyPZjk3eLmgdKaOeWyNER5YZF1mR8Umeiu9f28=", "pp+4+XHw5ZmHGJ7WbZ1xLYRsnTI17QIbb0bzHzYZrBs=" },
		{ "KJGoWYNVDUWcEMg+E4tljv1LiWAbdRw2QVapYqdFa1Y=", "M2SGk9WVnzYNGnT777G/JE8uUsY2f7mszTwlue73UDE=", "Jg8N7GbhbYB400foFP+OH0v+hCaL1jW61bajSA6EZqc=" },
		{ "uAgrgppPyIvk8S1CHUmaCaORsgFFfBreB8pxXmbSdXw=", "dJ22bER4fD3qF2/yIGWQ7SgmZ990sy/SbANjmUMkzws=", "mKkd0OoAR9sClmD+k3fL9weBsoCy5GQGz9BP0kAQIjc=" },
		{ "EI3Q8gePNPrtFyoMcv7hOihQgroF/dfjzPn8yvpGPWQ=", "Y9QhJFeiyuuIZNPU56B6U//ZK+XTTe4EP7h/p3Q+dE8=", "qBVUYw9rTWaxn55nUd55NpCWtxOUSWLt4WJGusiDS8Q=" },
		{ "oEQvdRm/yHkx+JvlhHGT5RUFrFEUleKb9DCT55EqZ30=", "8hsh/UHwWADTHntOJq4dy0o7ahcNAAlo2rDpjzzrVXk=", "/GF2inW2mPtA26IgFdgOEBbBEerT740wWuP/8NyANdc=" },
		{ "6OWrGKZKNsgfRezSUw29EnHymcgKyEKvX5/pZQlLmWs=", "oaJeO6YSS2dodNEf97DvgWrYnFFelG5daEdN84jVVGw=", "T5wvTdyVxK0LY96kouLjs06oUfhGChfty8OUL1Mddro=" },
		{ "mPmzQbh2R+r1DC5hSquzKM1SDrxUdfnBPRPJrpqrgkE=", "BtUHAnYWjDjBI42qBf9dJqezTUikYsF96o6PKEWPrVo=", "MxU8EMmq+vVHpuK/AkFZrZDF2b+VbSqukZLPbNsCcgo=" },
		{ "8GVxuoo1Veyr+nqxr5Q4vmsMf5qfiXwSlQ4q3+BU60g=", "uSOLe/E9/OjIgUOk0NMBHB45E0+q4Rd+IUO2UOxmKlM=", "+30F+56OE0Sr3wY2clKw4kgE+2XiucMg7xjK6EemXuk=" },
		{ "qORPKb+qFuU/9TpFbRUupHsqm9iyk9pa6cpik+EVDkg=", "bMZxxd+Z9I0XA1h9U8JEY+/mRxWGnvbXDZ5Dxz7YzS0=", "SmkkqOz4OhHuSL6cxuRm9+Mlt50Sfd0sMDFTC78gqOE=" },
		{ "2Ko3IYhXKcdOMIJGNpASk9saNSZsI64lyJPOoxpQ2kI=", "xVOc9PxY1VFaZfemmKi+Ei2liHhmeTu+JMa+rS00gnA=", "+398DlW8kWeI2aRaC4QfcrEjwqPKCohyDeWdaI1wvv0=" },
		{ "CPioGCVpxnym62nH/QoCt1RiiaaxUcuFjvh5kRhjqHA=", "W0XxlBLrZgFKhggMvvv6oFf/RJbfs92qv8JK9e+5i2o=", "bsK2U6CRAUv1uVgYQ7NpqjWWswFIDiDPDEtU1XQygSA=" },
		{ "AF17siKaeiO85hikYN0IWCMGWqPm1UOoCkXMltJGUVk=", "B+PFos9aN2S5bLxzGZHljRZj41j3rIx8RWu0vDUzq1w=", "Qb8d6iDYv3m1h7PE8j0Exl2cSwpHkim/fJ1S4P7MYvY=" },
		{ "wMFDBTJzx5tDCBhMkrptYJ8w9EeURjc4xeDQpevxAWo=", "4ec439EXE5WQzvtV9reSX+aMmdq5k7o9Ayt8oQp+RhQ=", "jwQlvdNH5WtSSU10H+fh/JisOlaBaohDPEp/BYnTt1Q=" },
		{ "4GaJpIFigNDwd31O84pLIMM/o2qhp0ydlI/ydD/2a2Q=", "r/LdkCoK5/BPGdq2+XJO8sCRhI+8ULFmg0887V43PAI=", "Da+3ZZvEJdx4TYFMIDUlbkmytILnSTNxTKX+sQdjMd4=" },
		{ "gMnojGqCLmMfGp2m31xlKZ/rIV2b8ockw9DPahRyu0c=", "H6tKCTosnM4BXKqflXrkTdJyNlCIZhQ3ZRxfrvSdrDk=", "4Z6K3LKIMV89plcjMb9CzSzJl03SWRe/++geBMZcOtY=" },
		{ "wKCg22aNNoHnDJ0oAKE46FcSSsREW4AaGn5WxCSeXUs=", "9NDTFC0iPt4HbbWepLHhN5poNTN2fdxJKNadsNT7qzY=", "GSVTOCnfLpJ1VCOLHaKSjCMv7/OlcnQiP5+5woqkud8=" },
		{ "oCoykq7pcJcg2X2V5TBRzGwn8hzzHC05WUreuotdznY=", "DxfwnbMqr5Wn5SAyFolfEmNQT6l84Oq69ngpg6H6Iio=", "p1RHBuqhuDa1MAQ2lbqmUQFu0CTwYlf73fWZSj9tQhA=" },
		{ "UO7YVyRUVkcKr7c63VWWV2zj36XD3HyDfLZCqvrZmFc=", "360lzYtIyHq5lv/QXSCe4bL4G2J1jBXFJ8yS+Ycr7Bc=", "RRPQ1XWF1HN8Us4dtfn2eemdjgtWm7U8r7mM3y00NOk=" },
		{ "eCGFYV/NuGP4H552E8Of1xU+3IvZxGyX+p5UFGW8iHI=", "LqhZ4AS9dQ/MhsQnE5Oy7Q8INXY+P+mrfGY5dtg9SlE=", "SICfqs8T5wP6IzATDCT4ovamBKPdkZ7JP4Cfsb3izec=" },
		{ "oI3HBZknoIMMZw1BuYMkTBylt25reX7AbCqtWQv8cno=", "B7dUgLgvQhi0RGmvaMrmf26WdjEVrhaiBclVkCKd4AA=", "5O9K9pLXwxFAt5lfMWh4qGbwX1BM7sz0QGYxAnR77dk=" },
		{ "sBfYn14EFVIS2M/E1aahP7mOmRNbNtyDChDMS1s6aGs=", "FLYv0ZvzxMkc9A7OzhC4P1ZRu1aKIQd7u6gqfdekC3c=", "kaYLcNCXnCLgiB8fleMQuboUJsj5u3YAmXL9x3ywV0M=" },
		{ "qFwZESU/XYZXUtxwrGsFU9qPAFTzjm7EhTS1Q6ajGlM=", "hraQQaqJCkS2yQXv+ccMOVh9V9a/qgSZJgdMAhrt8ms=", "72oDfnWOn39gdk/ncw8Lv267I0I+m73SwxrpYojpWYk=" },
		{ "YHhp6Zf/miuc2QXeI2lTezy0lL0pTv2b+nWNkmjYQWI=", "UhNO5arLzF0WlZSgNOx7+IjWN+GSxDdQxZRp8uIwsyI=", "1Q39Nzv2NGI9zWKWMpYLURAMZUg+FP+OboHHzFU8Anc=" },
		{ "mLBBXKaCJ+7qeBZpS3wxGi/SQ4kLzun+K+QwwdwfJVQ=", "gIq/nh7NwCJ36MvRnyrWHaRWu8lTmwfN2NvsjVl6SXQ=", "AahcNR91GDyJBIP+vC8ZuIV8ukqjSGtd8s+cmjVC2Ao=" },
		{ "OJG4LZlNNngFtAEQdbVVWVm6QAjOOauGcMZGbQrb40M=", "pFHAC6HaWAOtvTRRVfSHvzG05mp4SJZXKsN/tkSF0kM=", "IoXT3wIqWNxQhYuHWl12ODq/P7RM9LwaqglhmjKg+0g=" },
		{ "OOwBFOQNhepiqDf04DehQLh1gpBNOluDF1ia752Yfng=", "u715uJ/XhdjXjThCTJ9w6zzXnIhp3VCxhtso1wk+oBQ=", "5x1Ip3Ym0KzDjGhiYjmpeWWr+dgrZlYwfr02GngPOTM=" },
		{ "eNPFnwkQy1qw+IjFAlrDA6+sIsxbWDlzbNSsBW8R1UA=", "OaOXaAfPb1MRpWadawFje8YZ0oxJgdCIDIP8c5X+r1U=", "NtfaRRD0GqujnaQQoNoBbtovgO4dfVwEmEQx/YgnDpw=" },
		{ "OLdaZItbtxH3mGqItkibIJp7KV27FrQavjhd5zq6s3Q=", "SLSmAYxkMCGj0DO35cMLkC3NVAqK2VmVFndbOZEdA24=", "SnBO68XQTDjxYbmYaAeEHgLwD2u4D+BPT86raRuUQZM=" },
		{ "UBQOEz08izwr4eEK/SnQUpkt+TxCjo6Sya/XOGMLOE0=", "wQwrwezI9LzKevGsJJCBHDG8noR0yIEtOK5Rig97SSo=", "DpyS+0d7lrlFWkztsniG2v/j44vcuvWz3sPeghRyb5A=" },
		{ "mN98iuqUKh67ggUdq9ZIQNZCZM90fgycTVqYKEo+DkY=", "GYdXVW1jpS0dN1q9zMehubP7LfYqs34kszN0bXQqxxA=", "AJPIHffB4uvvJJki4xCG0VORVBbF6bc2mZQqUx+idPc=" },
		{ "OEd/1it8C3o+NOWxDI3DfLMXVBHJQg15N3E8F8d99l8=", "QL1NcuUkoXxDy7M9VjGslCejcUlnUDHRghFVnr+8fmA=", "nven9Dicl8U6QXuDO8rRNtjd4NYaa90SU+Gmv435XKY=" },
		{ "AFMCGDu2oAP68miucsi4fmYX2KeRZnsEGv8tQm8JEng=", "1sNxvk8uZhFsBUgxOXmuCMjDAgBbjVeWe9oaFk5Osy0=", "t5iI5XXd56S5q0Y9HC91gzgF9uGjL9FIy6NUaKqkydo=" },
		{ "CIAwfJghQHHr4YlztN9at6/iWkrEVCGFAxNVuQCuT3I=", "zpUOF1h17g7RpBzrVlN7oTRz6e+dxcDL8OsAtHwgLC8=", "kOSwC1p6Uoti9E9Eg7ViPZwCytuvp5Fr5Buw677aogU=" },
		{ "sC8vrAVBU0zvhWDRfzfySjvopXm2/cTMkTLmioyO3Es=", "p6H7GWm8NfgyO5OCX/COjvVT4MAnTs9ZUj4uZMK8XHA=", "9Tzqo57V/h7+6nSNAHSBKdmU7ultlvZbAnNKSRlrLi4=" },
		{ "eI63gjxCZGnzqZxPEi/ifYphXhxIRI2ZxK8jzqo3mmU=", "XyNzEuU9x37fxFCnrZH89Krs5/UqGVx5wNkGfQCAYz0=", "vZ2fTlRPnJQ+q33YdS5p1aweqPGj/kTMc4Uq80FtFjI=" },
		{ "aNJlGtm79/RS4SQ/PC4YM6LFo9zAqDr2/RjLqk/z/1A=", "lgZ9akPrABmfHQMlfNFnnpAJzGtcsaU9mUjEYKfzZHc=", "d0Xt1Bcgphd1HMI0RneA4VdBbMZL1qNGJAvFhb080eA=" },
		{ "oONSnHirNh3cuH93Ty0C9AXKebGY+cdF3R0DtPzIQlo=", "TuREKfA8EVQiYWsPx8veUzjN2cz/b72limSLWlrCWxw=", "vEqqKbpZf0EM6EApMUaUH65r3Zr81Y/DSODhE4H7U3Y=" },
		{ "+D6RyLEaHJ9YF9WDyOlwh87KaNJcc6lqX8Arp6yqHF0=", "EpecjfIo1/EEbmsgUtzEDqLu2ut+SMmzqaBL9Z/MlCA=", "oYfO6/7XQgEYT9zmr4sqFrk0muK/fEv3FfD8MzZzjkE=" },
		{ "OCmW5KQql2PRMJnsMYQjXlr6TSYUbxJBknqZtXJPSHM=", "ZZR2ghHlCwAJu/XlsEZuNS6XiGPwuXzyMPPywYFapVM=", "fqSCXq+pKJJ6yNvlOi+tyQ9E4Y6kc4kblGrVqN2WuXA=" },
		{ "APWXDAe8d2ia1CUbf/IzSPXOUjR8TVuJgmISiWw0/EY=", "jrT5P5YCkG+U7cfNTvCKy0GSEgsjwmJtHg+8HBP6ZCA=", "t75aUjZXMPir8Ao0yhVClh9/BdWxSL+11CjK3iELNWk=" },
		{ "8Nw4sRis7M/6Om+3w5YHXthyMzLGuP48teqdzbHNPlA=", "lj3q3ZYij3ZJ/QunK8n9I00cv/Z+O1TU1kFFl8x3DTE=", "adqB79P7gbXEYYnSd1/UPCwFffTAPXa9kHWynRBYcGo=" },
		{ "yOupps5XbjV0fIZKnGhrpcxB7yDQzbBILC0UMJyVS1c=", "+MDV/t9UCIdgm3IkH3BZlxaRPJ3lejRmrm4UPApq4mk=", "AOJPmQxsU6hjOd+9mHnF0VL7Afih3P1Fr625xFT4FtY=" },
		{ "cD2DEl4MBwONuTV0db5XreoVjQAUZFNXqIeFEU3KFkE=", "2CeHrjN7tBX48k4Sgv5fIHG06e57q/ucCL+8DIRmfXw=", "3EUo6MRzs6rSoY/7AFs8wiBiTXPcHzerLh6Xp3aMGKo=" },
		{ "EA+S3a9ZeOLiRbhTxaT2wkpyDheAmai+UJa6SFGzSm8=", "GGByUKZx/FPa2OkJoqVTHXx+6jrIpIw5rf0rp43MHko=", "BXoDA3yn0JcMV7hHVzEqhlwAORvhToFO1qG00nas92A=" },
		{ "eBeJi/imBiV52WEqrwAprUQggqdQmvTTmWtLq8pDDkM=", "zCX26ZTOZHLpq5x5aIUL1XhIVoXJLp/zcXwnmFA3jBo=", "Dm/DCxXWYXEsmQgxAD3KREK2PF0bUSnV5WRAaya8s1I=" },
		{ "8C7p+EQO+CnWUSjHVu3PpeWpUIbLy48zpftZu021plM=", "DxpnF/IbKAh6kmWC5Jpj8iw387EDkrvjsjOb9fbTSng=", "bGrk0OshJB+0oQOK0QGKU8+lotnIDz3oeUnMZGienyM=" },
		{ "COIez7YcBJiOJCLxxWV5UGLW5/o009YI0aszlD/PiUc=", "eD9USWV37LFIOxlDSHyOmfFqNJFpORRlzEI+HoF/czI=", "n+/ra86gUSF2pNZS51nt2JgrzXnQJl+dWswOq/Ahs94=" },
		{ "iBBSTG9VLC+T9+ahNaQ4umZoig8o7w1DaeOw+cD2BGc=", "XnAxqDlvGnQ6aakv8ABGHVj07qVQfk4NChZbstTMBxg=", "7KKSwu/4yWr1UzFmNMGtiaSwdYMhP/HKbrQLlABL4UE=" },
		{ "eNmwattflehr9+KsVqTuwt1YaAc5ONkaIaTQt9Gkhn8=", "1NNVvm++YTTGMKyAXfGOCZ4aDDdFFH5Um3vAg4XimDo=", "bXNrnDTP0pBay9ytZe7xpiKoSi12F7WUXqoIeI++Xvo=" },
		{ "QJotpmZINx9eptKpkh9j3JlEDcHdWnjEbicdBS7gPXM=", "3gLYKeoruVZ/AYjym0gciDvRHj45UIWyHhNjWj2Wj28=", "NwuUkkE5yOWT7wed7bltgAk71miz3cSooiIDAdv6kKw=" },
		{ "OAYGuxH70OPQvhVIX4BhSCWUyzAI5H2IkYxKgC/AO0M=", "Rj9iNF/FagkXfdLPqc9LHfaoGR8GlvY3gun2FilE508=", "hkNXLVMlBRsMEaQKkSzevcEK2sMu0AShGKQJMNqdzWM=" },
		{ "uBrgZ7wLHrOV/0dNiEqo7FjY9VnJqL5eUDHJWAc9QXg=", "3Hnln8ZHfSaK4OzESJe5U6NcLaW56wzfZICzvzefnSo=", "DhXsehe5FAmbUidXT5ZpZIAuu1eF9rkU6cF3FBoKwOE=" },
		{ "sJknn3CHvx/812EWU3ddLdLLZFBKsc+wx35GXyiRsHY=", "qqa2dNSt0jWozGyqpokP392H5/DOAUUZmUpyZDaUEEE=", "1Dyz8CvmF17oKT/wG2fu3vRzPzgQv8/OY9GJYew4FG8=" },
		{ "yOumS9HN68ZwIm+5hZol3jFQ0DB4SKuW/ld3y8wioGk=", "6PowsbKj/fKSzXZMAfaSkP3fE+4AThL9xm6ysQzMDxg=", "vF8cKu9X9FxgCjyVZ5RG7nuue8RelF5Qsb8Efme4M4A=" },
		{ "mISm5vQfPdK72SsaHh6O1/ARvaWCtm+KZNcpTsyt500=", "YCORDQDpb1U8vADdstBgXkg0N7QaAc5VoXJ4QFuA/UY=", "JlrBmfaCgbfEVD9YQq3c03WwwsHWc1nBwp1JkFORC3A=" },
		{ "cPyu3Qry6qbsiOJKFGRziZ9LJWJ47k3ZSXiGkQXuQm0=", "/cmBZTbqEp8sababPAxGb3OvDAEE7MlwPOwEFHE+7yM=", "lp0Hhc/rVtpT5FtLLccChqDl3El48XtP6Wm6JwjI7jo=" },
		{ "YKsMYU0SINbPwWw4RDCJV6GnzDlSp1ZNwUw2euGWi0A=", "/KmBReATQbFnLg8YKV0jwhqKeishRoWvlVtMX3550Vk=", "7fXpPSMo1Fw2sOXtjTtvFU+DbZvS/FWB9wAsywWx6R4=" },
		{ "WD0YI3y71eIp/GXw9i+7scEiQKSBkGihZWE+s6fGmWo=", "RdthAL/qPnAZFb3xBgRMiAtGHNjgokzoKX9iO2K5qhc=", "4dk4HGkT9dBmomGNorDE/hLr/HEFhljtl4zz3M4sG58=" },
		{ "oD8KWhJYZVhutJRb0kZlZnB22QUXzi2FfPRD0ll65UM=", "MYTBGHh4Ukj97pKj6qcfWmxGNQzmU3/aBOX2f1tfhG0=", "VT1gC+a9nRJzYMi/TPvRVnn3IQlaop/jKmmxZePEME0=" },
		{ "0Ns/1SOiqR2CpHRG03QNzJJd5gxTm1XJmSkFlugjQ3k=", "KvQAI+ekNOa2xfEvfyc9JGcS+CTUrnnhsKrlyJGJixg=", "J8LmSX6zElX3S9q4PNvh2NKUtAiQ3oHiYjSJ7yErPlY=" },
		{ "mD6TeF4ezSPXN/csN1OhoAREFSXllI+zl4DUOInVq2Q=", "WmLJ9ep2EqFcSftnYFJsmWyUxqL0zzuSzVEv94PcISM=", "U2+ILy2NDmmfgSW78C8dl8GyHESUc1lXPHPpg5F+gr8=" },
		{ "SMJoXOYgHz8HSzY+ByeWLcSP5qFwv7YjRe0bcKesRnM=", "DEsNSOY3TEs9J2YgqroQ4xKq8T8xNJQjvvE4UrTItQw=", "Bws1Hk2+lO+JQ7ME16EbwAdsBkWsGvti0Gb6LY2Lrms=" },
		{ "iGhXF0Hg0tqZmpwAMiolxvbvTPClQ7LlBAspSSyFEHE=", "7Xxzpwl7yRWehHNWTYVtFkdChJdXhtY4Mtw1fA9QcCg=", "Swjfv0PjuaE8Oq3a17BVno5I+q49dZlPwKK1bPUoKNI=" },
		{ "MIazjx3qTi6Qz3WzhtCPw3i4Q2uZBHcuMoh++ZGFYUk=", "oni8pbFqk9Ya+Fx+911Nl1SN0FD/hR1jwb2RH3t/pRk=", "ZYAFcj67LkbNURYbSnCCWGxAG8QLDGWwbl968mA6ZA4=" },
		{ "MAadYdiFM2cPuJF19q20Yoo5KJabuR9TUQ9jG5nvA1w=", "5OcE8XV+UPoBVbgqBQdVF62GZCW9DOQEdxrQsktPPBA=", "FCZsEFXouy+xtxv8X7VroXtvPG1Z1HFHL724tz1jcUI=" },
		{ "+GwxMmD2dee5+QmvXNI0NdP+rNWoSXTN42otbp0aZ24=", "Y0N44baz9ihclCUnv6rRbDqCYu4BxQlBfNnTz3NNe2A=", "/LqSgkVQNkQ/oBiZSgpM9Rw7BJv0RvRpEQpvlizvHy0=" },
		{ "8FREpCtncOcT7+W2nW4aYSjmSbADtVSH9rIliQZZUH4=", "fTNSd0JeREhXmPfjrmrAu6Lu/yHkB9GyxR3SyO4kZ28=", "262KN/iG/iJEaZeerFm1yVtvhFVGgQFwSvtxTcjZzeg=" },
		{ "EDhaRQGtscjoSE9wJOnSXoQVtVruIqyzknty+x/vDWo=", "eMmMgws6ZxDIxZ6QSwGjZO1Mx/r5T+fJjSTKGMBk/BU=", "0CyaJV6AG9bZ0C4yeZ/RDsOs9BdNqZpUxAsD30WmJO4=" },
		{ "CJV0UB2YdvVDG1cs4oiJgHAS+f1FocGr/vGCfiovsWQ=", "9/O9GWZEOXVm7On8lftL27PffRORju8OKl6gZd/74CA=", "A+kXRVNOwIrA5DUa+3v7dpRC+Gbxm23LTiYmOUAXUyY=" },
		{ "gCjDsJUwZGA7BjYVoCQsvdIgN9Q4lBHlSyKwUrl751A=", "HRwS8T9y2qPYk7JVU/8Y+6cS+Bk8XCLCXxwN/ttbQiI=", "iFotjA6rhUfkDv4S/wspJgEWunEmrlGSGsXcJ0+8laQ=" },
		{ "6N5pL4gsuK+shHpDxirTnAGdyKXIlYHyfIhtB0njJGA=", "CVZvW7NaN2XMEEKHodghBA9hLCwee/jrmttiWh/CmEg=", "OpPEd3Sp8r6KdjNDTN4bVHETlGJ92BCK74FCdEaDe9g=" },
		{ "UIPPTUdvhlg8qEDv6JRxM4/8F5ORjJz4ud82QZrgeEY=", "7Nd13z5EpB3ChytvQC1CxvDY7n0H8r2Y7lzLEY8hdEk=", "b22PvgU0M2QfNC7ZGN+RXNe5fjOzMsY32IcHTwLNIqw=" },
		{ "oBn53Q5fmxKX02PgI6F47Rb+XoLeFQO07ok2tYhk0lE=", "e0gtPDKXCZSoNW1uHqBPQXLfiYgyeqPMU2zZJgPXACI=", "wmjW2wDT2EzFkyaGui7YWNLTRu8Q4eD/GVKM2utZkEs=" },
	};
	gs_unref_ptrarray GPtrArray *allowed_ips_keep_alive = NULL;
	gs_unref_array GArray *peers = NULL;
	NMPlatformLnkWireGuard lnk_wireguard;
	int r;
	guint i;

	allowed_ips_keep_alive = g_ptr_array_new_with_free_func (g_free);

	peers = g_array_new (FALSE, TRUE, sizeof (NMPWireGuardPeer));

	lnk_wireguard = (NMPlatformLnkWireGuard) {
		.listen_port = 50754,
		.fwmark = 0x1102,
	};
	_copy_base64 (lnk_wireguard.private_key, sizeof (lnk_wireguard.private_key), self_key.pri);
	_copy_base64 (lnk_wireguard.public_key,  sizeof (lnk_wireguard.public_key),  self_key.pub);

	if (test_mode == 0) {
		/* no peers. */
	} else if (NM_IN_SET (test_mode, 1, 2)) {
		guint num_peers = (test_mode == 1) ? 1 : G_N_ELEMENTS (keys);

		for (i = 0; i < num_peers; i++) {
			NMPWireGuardPeer peer;
			char s_addr[NM_UTILS_INET_ADDRSTRLEN];
			NMSockAddrUnion endpoint;
			guint i_allowed_ips, n_allowed_ips;
			NMPWireGuardAllowedIP *allowed_ips;

			if ((i % 2) == 1) {
				endpoint = (NMSockAddrUnion) {
					.in = {
						.sin_family      = AF_INET,
						.sin_addr.s_addr = nmtst_inet4_from_string (nm_sprintf_buf (s_addr, "192.168.7.%d", i)),
						.sin_port        = htons (14000 + i),
					},
				};
			} else {
				endpoint = (NMSockAddrUnion) {
					.in6 = {
						.sin6_family = AF_INET6,
						.sin6_addr   = *nmtst_inet6_from_string (nm_sprintf_buf (s_addr, "a:b:c:e::1:%d", i)),
						.sin6_port   = htons (16000 + i),
					},
				};
			}

			if (test_mode == 1)
				n_allowed_ips = 1;
			else
				n_allowed_ips = i % 10;
			allowed_ips = g_new0 (NMPWireGuardAllowedIP, n_allowed_ips);
			g_ptr_array_add (allowed_ips_keep_alive, allowed_ips);
			for (i_allowed_ips = 0; i_allowed_ips < n_allowed_ips; i_allowed_ips++) {
				NMPWireGuardAllowedIP *aip = &allowed_ips[i_allowed_ips];

				aip->family = (i_allowed_ips % 2) ? AF_INET : AF_INET6;
				if (aip->family == AF_INET) {
					aip->addr.addr4 = nmtst_inet4_from_string (nm_sprintf_buf (s_addr, "10.%u.%u.0", i, i_allowed_ips));
					aip->mask = 32 - (i_allowed_ips % 8);
				} else {
					aip->addr.addr6 = *nmtst_inet6_from_string (nm_sprintf_buf (s_addr, "a:d:f:%02x:%02x::", i, i_allowed_ips));
					aip->mask = 128 - (i_allowed_ips % 10);
				}
			}

			peer = (NMPWireGuardPeer) {
				.persistent_keepalive_interval = 60+i,
				.endpoint                      = endpoint,
				.allowed_ips                   = n_allowed_ips > 0 ? allowed_ips : NULL,
				.allowed_ips_len               = n_allowed_ips,
			};
			_copy_base64 (peer.public_key, sizeof (peer.public_key), keys[i].pub);
			_copy_base64 (peer.preshared_key, sizeof (peer.preshared_key), (i % 3) ? NULL : keys[i].pre);

			g_array_append_val (peers, peer);
		}
	} else
		g_assert_not_reached ();

	r = nm_platform_link_wireguard_change (platform,
	                                       ifindex,
	                                       &lnk_wireguard,
	                                       (const NMPWireGuardPeer *) peers->data,
	                                       NULL,
	                                       peers->len,
	                                         NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_PRIVATE_KEY
	                                       | NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_LISTEN_PORT
	                                       | NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_FWMARK
	                                       | NM_PLATFORM_WIREGUARD_CHANGE_FLAG_REPLACE_PEERS);
	g_assert (NMTST_NM_ERR_SUCCESS (r));
}

/*****************************************************************************/

typedef struct {
	NMLinkType link_type;
	int test_mode;
	gboolean external_command;
} TestAddSoftwareDetectData;

static void
test_software_detect (gconstpointer user_data)
{
	const TestAddSoftwareDetectData *test_data = user_data;
	int ifindex, ifindex_parent;
	const NMPlatformLink *plink;
	const NMPObject *lnk;
	int r;
	guint i_step;
	const gboolean ext = test_data->external_command;
	NMPlatformLnkTun lnk_tun;
	NMPlatformLnkGre lnk_gre = { };
	nm_auto_close int tun_fd = -1;

	nmtstp_run_command_check ("ip link add %s type dummy", PARENT_NAME);
	ifindex_parent = nmtstp_assert_wait_for_link (NM_PLATFORM_GET, PARENT_NAME, NM_LINK_TYPE_DUMMY, 100)->ifindex;

	switch (test_data->link_type) {
	case NM_LINK_TYPE_GRE: {
		gboolean gracefully_skip = FALSE;

		lnk_gre.local = nmtst_inet4_from_string ("192.168.233.204");
		lnk_gre.remote = nmtst_inet4_from_string ("172.168.10.25");
		lnk_gre.parent_ifindex = ifindex_parent;
		lnk_gre.ttl = 174;
		lnk_gre.tos = 37;
		lnk_gre.path_mtu_discovery = TRUE;

		if (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "gre0")) {
			/* Seems that the ip_gre module is not loaded... try to load it. */
			gracefully_skip = nm_utils_modprobe (NULL, TRUE, "ip_gre", NULL) != 0;
		}

		if (!nmtstp_link_gre_add (NULL, ext, DEVICE_NAME, &lnk_gre)) {
			if (gracefully_skip) {
				g_test_skip ("Cannot create gre tunnel because of missing ip_gre module (modprobe ip_gre)");
				goto out_delete_parent;
			}
			g_error ("Failed adding GRE tunnel");
		}
		break;
	}
	case NM_LINK_TYPE_GRETAP: {
		gboolean gracefully_skip = FALSE;

		lnk_gre.local = nmtst_inet4_from_string ("192.168.1.133");
		lnk_gre.remote = nmtst_inet4_from_string ("172.168.101.2");
		lnk_gre.parent_ifindex = ifindex_parent;
		lnk_gre.ttl = 39;
		lnk_gre.tos = 12;
		lnk_gre.path_mtu_discovery = FALSE;
		lnk_gre.is_tap = TRUE;

		if (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "gretap0")) {
			/* Seems that the ip_gre module is not loaded... try to load it. */
			gracefully_skip = nm_utils_modprobe (NULL, TRUE, "ip_gre", NULL) != 0;
		}

		if (!nmtstp_link_gre_add (NULL, ext, DEVICE_NAME, &lnk_gre)) {
			if (gracefully_skip) {
				g_test_skip ("Cannot create gretap tunnel because of missing ip_gre module (modprobe ip_gre)");
				goto out_delete_parent;
			}
			g_error ("Failed adding GRETAP tunnel");
		}
		break;
	}
	case NM_LINK_TYPE_IPIP: {
		NMPlatformLnkIpIp lnk_ipip = { };
		gboolean gracefully_skip = FALSE;

		if (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "tunl0")) {
			/* Seems that the ipip module is not loaded... try to load it. */
			gracefully_skip = nm_utils_modprobe (NULL, TRUE, "ipip", NULL) != 0;
		}

		lnk_ipip.local = nmtst_inet4_from_string ("1.2.3.4");
		lnk_ipip.remote = nmtst_inet4_from_string ("5.6.7.8");
		lnk_ipip.parent_ifindex = ifindex_parent;
		lnk_ipip.tos = 32;
		lnk_ipip.path_mtu_discovery = FALSE;

		if (!nmtstp_link_ipip_add (NULL, ext, DEVICE_NAME, &lnk_ipip)) {
			if (gracefully_skip) {
				g_test_skip ("Cannot create ipip tunnel because of missing ipip module (modprobe ipip)");
				goto out_delete_parent;
			}
			g_error ("Failed adding IPIP tunnel");
		}
		break;
	}
	case NM_LINK_TYPE_IP6TNL: {
		NMPlatformLnkIp6Tnl lnk_ip6tnl = { };
		gboolean gracefully_skip = FALSE;

		if (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "ip6tnl0")) {
			/* Seems that the ip6_tunnel module is not loaded... try to load it. */
			gracefully_skip = nm_utils_modprobe (NULL, TRUE, "ip6_tunnel", NULL) != 0;
		}

		switch (test_data->test_mode) {
		case 0:
			lnk_ip6tnl.local = *nmtst_inet6_from_string ("fd01::15");
			lnk_ip6tnl.remote = *nmtst_inet6_from_string ("fd01::16");
			lnk_ip6tnl.parent_ifindex = ifindex_parent;
			lnk_ip6tnl.tclass = 20;
			lnk_ip6tnl.encap_limit = 6;
			lnk_ip6tnl.flow_label = 1337;
			lnk_ip6tnl.proto = IPPROTO_IPV6;
			break;
		case 1:
			lnk_ip6tnl.local = *nmtst_inet6_from_string ("fd01::17");
			lnk_ip6tnl.remote = *nmtst_inet6_from_string ("fd01::18");
			lnk_ip6tnl.parent_ifindex = ifindex_parent;
			lnk_ip6tnl.tclass = 0;
			lnk_ip6tnl.encap_limit = 0;
			lnk_ip6tnl.flow_label = 1338;
			lnk_ip6tnl.proto = IPPROTO_IPV6;
			lnk_ip6tnl.flags = IP6_TNL_F_IGN_ENCAP_LIMIT | IP6_TNL_F_USE_ORIG_TCLASS;
			break;
		}

		if (!nmtstp_link_ip6tnl_add (NULL, ext, DEVICE_NAME, &lnk_ip6tnl)) {
			if (gracefully_skip) {
				g_test_skip ("Cannot create ip6tnl tunnel because of missing ip6_tunnel module (modprobe ip6_tunnel)");
				goto out_delete_parent;
			}
			g_error ("Failed adding IP6TNL tunnel");
		}
		break;
	}
	case NM_LINK_TYPE_IP6GRE: {
		NMPlatformLnkIp6Tnl lnk_ip6tnl = { };
		gboolean gracefully_skip = FALSE;

		if (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "ip6gre0")) {
			/* Seems that the ip6_tunnel module is not loaded... try to load it. */
			gracefully_skip = nm_utils_modprobe (NULL, TRUE, "ip6_gre", NULL) != 0;
		}

		lnk_ip6tnl.local = *nmtst_inet6_from_string ("fd01::42");
		lnk_ip6tnl.remote = *nmtst_inet6_from_string ("fd01::aaaa");
		lnk_ip6tnl.parent_ifindex = ifindex_parent;
		lnk_ip6tnl.tclass = 21;
		lnk_ip6tnl.flow_label = 1338;
		lnk_ip6tnl.is_gre = TRUE;

		if (!nmtstp_link_ip6gre_add (NULL, ext, DEVICE_NAME, &lnk_ip6tnl)) {
			if (gracefully_skip) {
				g_test_skip ("Cannot create ip6gre tunnel because of missing ip6_gre module (modprobe ip6_gre)");
				goto out_delete_parent;
			}
			g_error ("Failed adding IP6GRE tunnel");
		}
		break;
	}
	case NM_LINK_TYPE_IP6GRETAP: {
		NMPlatformLnkIp6Tnl lnk_ip6tnl = { };
		gboolean gracefully_skip = FALSE;

		if (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "ip6gre0")) {
			/* Seems that the ip6_tunnel module is not loaded... try to load it. */
			gracefully_skip = nm_utils_modprobe (NULL, TRUE, "ip6_gre", NULL) != 0;
		}

		lnk_ip6tnl.local = *nmtst_inet6_from_string ("fe80::abcd");
		lnk_ip6tnl.remote = *nmtst_inet6_from_string ("fc01::bbbb");
		lnk_ip6tnl.parent_ifindex = ifindex_parent;
		lnk_ip6tnl.ttl = 10;
		lnk_ip6tnl.tclass = 22;
		lnk_ip6tnl.flow_label = 1339;
		lnk_ip6tnl.is_gre = TRUE;
		lnk_ip6tnl.is_tap = TRUE;

		if (!nmtstp_link_ip6gre_add (NULL, ext, DEVICE_NAME, &lnk_ip6tnl)) {
			if (gracefully_skip) {
				g_test_skip ("Cannot create ip6gretap tunnel because of missing ip6_gre module (modprobe ip6_gre)");
				goto out_delete_parent;
			}
			g_error ("Failed adding IP6GRETAP tunnel");
		}
		break;
	}
	case NM_LINK_TYPE_MACVLAN: {
		NMPlatformLnkMacvlan lnk_macvlan = { };
		const NMPlatformLink *dummy;
		char buf[256];
		int i;

		lnk_macvlan.mode = MACVLAN_MODE_BRIDGE;
		lnk_macvlan.no_promisc = FALSE;
		lnk_macvlan.tap = FALSE;

		/* Since in old kernel versions sysfs files for macvtaps are not
		 * namespaced, the creation can fail if a macvtap in another namespace
		 * has the same index. Try to detect this situation and skip already
		 * used indexes.
		 * The fix (17af2bce) is included kernel 4.7, dated 24 July, 2016.
		 */
		for (i = ifindex_parent + 1; i < ifindex_parent + 100; i++) {
			snprintf (buf, sizeof (buf), "/sys/class/macvtap/tap%d", i);
			if (!g_file_test (buf, G_FILE_TEST_IS_SYMLINK))
				break;

			_LOGD ("skipping ifindex %d as already used by a macvtap", i);

			dummy = nmtstp_link_dummy_add (NM_PLATFORM_GET, FALSE, "dummy-tmp");
			g_assert_cmpint (dummy->ifindex, ==, i);
			nmtstp_link_delete (NM_PLATFORM_GET, FALSE, dummy->ifindex, NULL, TRUE);
		}

		if (!nmtstp_link_macvlan_add (NULL, ext, DEVICE_NAME, ifindex_parent, &lnk_macvlan))
			g_error ("Failed adding MACVLAN interface");
		break;
	}
	case NM_LINK_TYPE_MACVTAP: {
		NMPlatformLnkMacvtap lnk_macvtap = { };

		lnk_macvtap.mode = MACVLAN_MODE_PRIVATE;
		lnk_macvtap.no_promisc = FALSE;
		lnk_macvtap.tap = TRUE;

		if (!nmtstp_link_macvlan_add (NULL, ext, DEVICE_NAME, ifindex_parent, &lnk_macvtap))
			g_error ("Failed adding MACVTAP interface");
		break;
	}
	case NM_LINK_TYPE_SIT: {
		NMPlatformLnkSit lnk_sit = { };
		gboolean gracefully_skip = FALSE;

		lnk_sit.local = nmtst_inet4_from_string ("192.168.200.1");
		lnk_sit.remote = nmtst_inet4_from_string ("172.25.100.14");
		lnk_sit.parent_ifindex = ifindex_parent;
		lnk_sit.ttl = 0;
		lnk_sit.tos = 31;
		lnk_sit.path_mtu_discovery = FALSE;

		if (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "sit0")) {
			/* Seems that the sit module is not loaded... try to load it. */
			gracefully_skip = nm_utils_modprobe (NULL, TRUE, "sit", NULL) != 0;
		}

		if (!nmtstp_link_sit_add (NULL, ext, DEVICE_NAME, &lnk_sit)) {
			if (gracefully_skip) {
				g_test_skip ("Cannot create sit tunnel because of missing sit module (modprobe sit)");
				goto out_delete_parent;
			}
			g_error ("Failed adding SIT tunnel");
		}
		break;
	}
	case NM_LINK_TYPE_VLAN:
		nmtstp_run_command_check ("ip link add name %s link %s type vlan id 1242", DEVICE_NAME, PARENT_NAME);
		break;
	case NM_LINK_TYPE_VXLAN: {
		NMPlatformLnkVxlan lnk_vxlan = { };

		switch (test_data->test_mode) {
		case 0:
			lnk_vxlan.parent_ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, PARENT_NAME);
			lnk_vxlan.id = 42;
			lnk_vxlan.local = nmtst_inet4_from_string ("23.1.2.164");
			lnk_vxlan.group = nmtst_inet4_from_string ("239.1.2.134");
			lnk_vxlan.dst_port = 4789;
			lnk_vxlan.learning = TRUE;
			lnk_vxlan.ageing = 1245;
			break;
		case 1:
			lnk_vxlan.parent_ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, PARENT_NAME);
			lnk_vxlan.id = 11214423;
			lnk_vxlan.local6 = *nmtst_inet6_from_string ("1:2:3:4:334:23::23");
			lnk_vxlan.group6 = *nmtst_inet6_from_string ("ff0e::115");
			lnk_vxlan.ttl = 32;
			lnk_vxlan.dst_port = 57412;
			lnk_vxlan.src_port_min = 1000;
			lnk_vxlan.src_port_max = 1003;
			lnk_vxlan.learning = TRUE;
			lnk_vxlan.ageing = 3245;
			break;
		}

		g_assert (nmtstp_link_vxlan_add (NULL, ext, DEVICE_NAME, &lnk_vxlan));
		break;
	}
	case NM_LINK_TYPE_TUN: {
		gboolean owner_valid = nmtst_get_rand_bool ();
		gboolean group_valid = nmtst_get_rand_bool ();

		switch (test_data->test_mode) {
		case 0:
			lnk_tun = (NMPlatformLnkTun) {
				.type = nmtst_get_rand_bool () ? IFF_TUN : IFF_TAP,
				.owner = owner_valid ? getuid () : 0,
				.owner_valid = owner_valid,
				.group = group_valid ? getgid () : 0,
				.group_valid = group_valid,
				.pi = nmtst_get_rand_bool (),
				.vnet_hdr = nmtst_get_rand_bool (),
				.multi_queue = nmtst_get_rand_bool (),

				/* if we add the device via iproute2 (external), we can only
				 * create persistent devices. */
				.persist = (ext == 1) ? TRUE : nmtst_get_rand_bool (),
			};
			break;
		default:
			g_assert_not_reached ();
			break;
		}

		g_assert (nmtstp_link_tun_add (NULL, ext, DEVICE_NAME, &lnk_tun,
		                               (!lnk_tun.persist || nmtst_get_rand_bool ())
		                                 ? &tun_fd
		                                 : NULL));
		break;
	}
	case NM_LINK_TYPE_WIREGUARD: {
		const NMPlatformLink *link;

		r = nm_platform_link_wireguard_add (NM_PLATFORM_GET, DEVICE_NAME, &link);
		if (r == -EOPNOTSUPP) {
			g_test_skip ("wireguard not supported (modprobe wireguard?)");
			goto out_delete_parent;
		}

		g_assert (NMTST_NM_ERR_SUCCESS (r));
		g_assert (NMP_OBJECT_GET_TYPE (NMP_OBJECT_UP_CAST (link)) == NMP_OBJECT_TYPE_LINK);
		break;
	}
	default:
		g_assert_not_reached ();
	}

	ifindex = nmtstp_assert_wait_for_link (NM_PLATFORM_GET, DEVICE_NAME, test_data->link_type, 100)->ifindex;

	nmtstp_link_set_updown (NULL, -1, ifindex_parent, TRUE);

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
			nmtstp_link_set_updown (NULL, -1, ifindex, set_up);
		}

		lnk = nm_platform_link_get_lnk (NM_PLATFORM_GET, ifindex, test_data->link_type, &plink);
		g_assert (plink);
		g_assert_cmpint (plink->ifindex, ==, ifindex);

		if (   !lnk
		    && test_data->link_type == NM_LINK_TYPE_TUN) {
			/* this is ok. Kernel apparently does not support tun properties via netlink. We
			 * fetch them from sysfs below. */
		} else
			g_assert (lnk);

		switch (test_data->link_type) {
		case NM_LINK_TYPE_GRE: {
			const NMPlatformLnkGre *plnk = &lnk->lnk_gre;

			g_assert (plnk == nm_platform_link_get_lnk_gre (NM_PLATFORM_GET, ifindex, NULL));
			g_assert (nm_platform_lnk_gre_cmp (plnk, &lnk_gre) == 0);

			break;
		}
		case NM_LINK_TYPE_GRETAP: {
			const NMPlatformLnkGre *plnk = &lnk->lnk_gre;

			g_assert (plnk == nm_platform_link_get_lnk_gretap (NM_PLATFORM_GET, ifindex, NULL));
			g_assert (nm_platform_lnk_gre_cmp (plnk, &lnk_gre) == 0);
			break;
		}
		case NM_LINK_TYPE_IP6TNL: {
			const NMPlatformLnkIp6Tnl *plnk = &lnk->lnk_ip6tnl;

			switch (test_data->test_mode) {
			case 0:
				g_assert (plnk == nm_platform_link_get_lnk_ip6tnl (NM_PLATFORM_GET, ifindex, NULL));
				g_assert_cmpint (plnk->parent_ifindex, ==, ifindex_parent);
				nmtst_assert_ip6_address (&plnk->local, "fd01::15");
				nmtst_assert_ip6_address (&plnk->remote, "fd01::16");
				g_assert_cmpint (plnk->ttl, ==, 0);
				g_assert_cmpint (plnk->tclass, ==, 20);
				g_assert_cmpint (plnk->encap_limit, ==, 6);
				g_assert_cmpint (plnk->flow_label, ==, 1337);
				g_assert_cmpint (plnk->proto, ==, IPPROTO_IPV6);
				break;
			case 1:
				g_assert (plnk == nm_platform_link_get_lnk_ip6tnl (NM_PLATFORM_GET, ifindex, NULL));
				g_assert_cmpint (plnk->parent_ifindex, ==, ifindex_parent);
				nmtst_assert_ip6_address (&plnk->local, "fd01::17");
				nmtst_assert_ip6_address (&plnk->remote, "fd01::18");
				g_assert_cmpint (plnk->ttl, ==, 0);
				g_assert_cmpint (plnk->flow_label, ==, 1338);
				g_assert_cmpint (plnk->proto, ==, IPPROTO_IPV6);
				g_assert_cmpint (plnk->flags & 0xFFFF, /* ignore kernel internal flags */
				                 ==,
				                 IP6_TNL_F_IGN_ENCAP_LIMIT | IP6_TNL_F_USE_ORIG_TCLASS);
				break;
			}
			break;
		}
		case NM_LINK_TYPE_IP6GRE: {
			const NMPlatformLnkIp6Tnl *plnk = &lnk->lnk_ip6tnl;

			g_assert (plnk == nm_platform_link_get_lnk_ip6gre (NM_PLATFORM_GET, ifindex, NULL));
			g_assert_cmpint (plnk->parent_ifindex, ==, ifindex_parent);
			nmtst_assert_ip6_address (&plnk->local, "fd01::42");
			nmtst_assert_ip6_address (&plnk->remote, "fd01::aaaa");
			g_assert_cmpint (plnk->tclass, ==, 21);
			g_assert_cmpint (plnk->flow_label, ==, 1338);
			g_assert_cmpint (plnk->is_gre, ==, TRUE);
			g_assert_cmpint (plnk->is_tap, ==, FALSE);
			break;
		}
		case NM_LINK_TYPE_IP6GRETAP: {
			const NMPlatformLnkIp6Tnl *plnk = &lnk->lnk_ip6tnl;

			g_assert (plnk == nm_platform_link_get_lnk_ip6gretap (NM_PLATFORM_GET, ifindex, NULL));
			g_assert_cmpint (plnk->parent_ifindex, ==, ifindex_parent);
			nmtst_assert_ip6_address (&plnk->local, "fe80::abcd");
			nmtst_assert_ip6_address (&plnk->remote, "fc01::bbbb");
			g_assert_cmpint (plnk->ttl, ==, 10);
			g_assert_cmpint (plnk->tclass, ==, 22);
			g_assert_cmpint (plnk->flow_label, ==, 1339);
			g_assert_cmpint (plnk->is_gre, ==, TRUE);
			g_assert_cmpint (plnk->is_tap, ==, TRUE);
			break;
		}
		case NM_LINK_TYPE_IPIP: {
			const NMPlatformLnkIpIp *plnk = &lnk->lnk_ipip;

			g_assert (plnk == nm_platform_link_get_lnk_ipip (NM_PLATFORM_GET, ifindex, NULL));
			g_assert_cmpint (plnk->parent_ifindex, ==, ifindex_parent);
			nmtst_assert_ip4_address (plnk->local, "1.2.3.4");
			nmtst_assert_ip4_address (plnk->remote, "5.6.7.8");
			g_assert_cmpint (plnk->ttl, ==, 0);
			g_assert_cmpint (plnk->tos, ==, 32);
			g_assert_cmpint (plnk->path_mtu_discovery, ==, FALSE);
			break;
		}
		case NM_LINK_TYPE_MACVLAN: {
			const NMPlatformLnkMacvlan *plnk = &lnk->lnk_macvlan;

			g_assert (plnk == nm_platform_link_get_lnk_macvlan (NM_PLATFORM_GET, ifindex, NULL));
			g_assert_cmpint (plnk->no_promisc, ==, FALSE);
			g_assert_cmpint (plnk->mode, ==, MACVLAN_MODE_BRIDGE);
			break;
		}
		case NM_LINK_TYPE_MACVTAP: {
			const NMPlatformLnkMacvtap *plnk = &lnk->lnk_macvlan;

			g_assert (plnk == nm_platform_link_get_lnk_macvtap (NM_PLATFORM_GET, ifindex, NULL));
			g_assert_cmpint (plnk->no_promisc, ==, FALSE);
			g_assert_cmpint (plnk->mode, ==, MACVLAN_MODE_PRIVATE);
			break;
		}
		case NM_LINK_TYPE_SIT: {
			const NMPlatformLnkSit *plnk = &lnk->lnk_sit;

			g_assert (plnk == nm_platform_link_get_lnk_sit (NM_PLATFORM_GET, ifindex, NULL));
			g_assert_cmpint (plnk->parent_ifindex, ==, ifindex_parent);
			nmtst_assert_ip4_address (plnk->local, "192.168.200.1");
			nmtst_assert_ip4_address (plnk->remote, "172.25.100.14");
			g_assert_cmpint (plnk->ttl, ==, 0);
			g_assert_cmpint (plnk->tos, ==, 31);
			g_assert_cmpint (plnk->path_mtu_discovery, ==, FALSE);
			break;
		}
		case NM_LINK_TYPE_TUN: {
			const NMPlatformLnkTun *plnk;
			NMPlatformLnkTun lnk_tun2;

			g_assert ((lnk ? &lnk->lnk_tun : NULL) == nm_platform_link_get_lnk_tun (NM_PLATFORM_GET, ifindex, NULL));

			/* kernel might not expose tun options via netlink. Either way, try
			 * to read them (either from platform cache, or fallback to sysfs).
			 * See also: rh#1547213. */
			if (!nm_platform_link_tun_get_properties (NM_PLATFORM_GET,
			                                          ifindex,
			                                          &lnk_tun2))
				g_assert_not_reached ();

			plnk = lnk ? &lnk->lnk_tun : &lnk_tun2;
			if (lnk)
				g_assert (memcmp (plnk, &lnk_tun2, sizeof (NMPlatformLnkTun)) == 0);

			if (i_step == 0) {
				/* Before we upped the device for the first time the kernel didn't notify
				 * us of the owner set after the link creation:
				 * https://bugzilla.redhat.com/show_bug.cgi?id=1566062
				 */
				break;
			}

			g_assert (nm_platform_lnk_tun_cmp (plnk, &lnk_tun) == 0);
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
			g_assert_cmpint (plnk->learning, ==, TRUE);
			g_assert_cmpint (plnk->limit, ==, 0);
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
				g_assert_cmpint (plnk->ttl, ==, 0);
				g_assert_cmpint (plnk->ageing, ==, 1245);
				g_assert_cmpint (plnk->dst_port, ==, 4789);
				if (   plnk->src_port_min != 0
				    || plnk->src_port_max != 0) {
					/* on some kernels, omitting the port range results in setting
					 * following default port range. */
					g_assert_cmpint (plnk->src_port_min, ==, 32768);
					g_assert_cmpint (plnk->src_port_max, ==, 61000);
				}
				break;
			case 1:
				g_assert_cmpint (plnk->id, ==, 11214423);
				nmtst_assert_ip4_address (plnk->local, "0.0.0.0");
				nmtst_assert_ip4_address (plnk->group, "0.0.0.0");
				nmtst_assert_ip6_address (&plnk->group6, "ff0e::115");
				nmtst_assert_ip6_address (&plnk->local6, "1:2:3:4:334:23::23");
				g_assert_cmpint (plnk->ageing, ==, 3245);
				g_assert_cmpint (plnk->dst_port, ==, 57412);
				g_assert_cmpint (plnk->ttl, ==, 32);
				g_assert_cmpint (plnk->src_port_min, ==, 1000);
				g_assert_cmpint (plnk->src_port_max, ==, 1003);
				break;
			}
			break;
		}
		case NM_LINK_TYPE_WIREGUARD: {
			const NMPlatformLnkWireGuard *plnk = &lnk->lnk_wireguard;

			g_assert (plnk == nm_platform_link_get_lnk_wireguard (NM_PLATFORM_GET, ifindex, NULL));

			if (plink->n_ifi_flags & IFF_UP) {
				_test_wireguard_change (NM_PLATFORM_GET, plink->ifindex, test_data->test_mode);
				if (_LOGD_ENABLED ())
					_system ("WG_HIDE_KEYS=never wg show all");
			}
			break;
		}
		default:
			g_assert_not_reached ();
		}
	}

	nmtstp_link_delete (NULL, -1, ifindex, DEVICE_NAME, TRUE);
out_delete_parent:
	nmtstp_link_delete (NULL, -1, ifindex_parent, PARENT_NAME, TRUE);
}

static void
test_software_detect_add (const char *testpath,
                          NMLinkType link_type,
                          int test_mode)
{
	TestAddSoftwareDetectData *test_data;
	char *path;

	test_data = g_new0 (TestAddSoftwareDetectData, 1);
	test_data->link_type = link_type;
	test_data->test_mode = test_mode;
	test_data->external_command = TRUE;

	path = g_strdup_printf ("%s/external", testpath);
	g_test_add_data_func_full (path, test_data, test_software_detect, g_free);
	g_free (path);

	test_data = g_new0 (TestAddSoftwareDetectData, 1);
	test_data->link_type = link_type;
	test_data->test_mode = test_mode;
	test_data->external_command = FALSE;

	path = g_strdup_printf ("%s/platform", testpath);
	g_test_add_data_func_full (path, test_data, test_software_detect, g_free);
	g_free (path);

	test_data = g_new0 (TestAddSoftwareDetectData, 1);
	test_data->link_type = link_type;
	test_data->test_mode = test_mode;
	test_data->external_command = -1;

	path = g_strdup_printf ("%s/random", testpath);
	g_test_add_data_func_full (path, test_data, test_software_detect, g_free);
	g_free (path);
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
	ifindex_parent = nmtstp_assert_wait_for_link (NM_PLATFORM_GET, PARENT_NAME, NM_LINK_TYPE_DUMMY, 100)->ifindex;

	nmtstp_run_command_check ("ip link add name %s link %s type vlan id 1245", DEVICE_NAME, PARENT_NAME);
	ifindex = nmtstp_assert_wait_for_link (NM_PLATFORM_GET, DEVICE_NAME, NM_LINK_TYPE_VLAN, 100)->ifindex;

	/* ingress-qos-map */

	g_assert (nm_platform_link_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 4, 5));
	_assert_ingress_qos_mappings (ifindex, 1,
	                              4, 5);

	g_assert (nm_platform_link_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 3, 7));
	_assert_ingress_qos_mappings (ifindex, 2,
	                              3, 7,
	                              4, 5);

	g_assert (nm_platform_link_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 3, 8));
	_assert_ingress_qos_mappings (ifindex, 2,
	                              3, 8,
	                              4, 5);

	g_assert (nm_platform_link_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 0, 4));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, 4,
	                              3, 8,
	                              4, 5);

	g_assert (nm_platform_link_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 0, G_MAXUINT32));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, G_MAXUINT32,
	                              3, 8,
	                              4, 5);

	g_assert (nm_platform_link_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 0, G_MAXUINT32 - 1));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, G_MAXUINT32 - 1,
	                              3, 8,
	                              4, 5);

	g_assert (nm_platform_link_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 0, 5));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, 5,
	                              3, 8,
	                              4, 5);

	g_assert (nm_platform_link_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 0, 5));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, 5,
	                              3, 8,
	                              4, 5);

	/* Set invalid values: */
	g_assert (nm_platform_link_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 8, 3));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, 5,
	                              3, 8,
	                              4, 5);

	g_assert (nm_platform_link_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, 9, 4));
	_assert_ingress_qos_mappings (ifindex, 3,
	                              0, 5,
	                              3, 8,
	                              4, 5);

	/* egress-qos-map */

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 7, 3));
	_assert_egress_qos_mappings (ifindex, 1,
	                             7, 3);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 8, 4));
	_assert_egress_qos_mappings (ifindex, 2,
	                             7, 3,
	                             8, 4);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 0, 4));
	_assert_egress_qos_mappings (ifindex, 3,
	                             0, 4,
	                             7, 3,
	                             8, 4);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 1, 4));
	_assert_egress_qos_mappings (ifindex, 4,
	                             0, 4,
	                             1, 4,
	                             7, 3,
	                             8, 4);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 1, 5));
	_assert_egress_qos_mappings (ifindex, 4,
	                             0, 4,
	                             1, 5,
	                             7, 3,
	                             8, 4);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 9, 5));
	_assert_egress_qos_mappings (ifindex, 5,
	                             0, 4,
	                             1, 5,
	                             7, 3,
	                             8, 4,
	                             9, 5);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 8, 5));
	_assert_egress_qos_mappings (ifindex, 5,
	                             0, 4,
	                             1, 5,
	                             7, 3,
	                             8, 5,
	                             9, 5);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 8, 0));
	_assert_egress_qos_mappings (ifindex, 4,
	                             0, 4,
	                             1, 5,
	                             7, 3,
	                             9, 5);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 0, 0));
	_assert_egress_qos_mappings (ifindex, 3,
	                             1, 5,
	                             7, 3,
	                             9, 5);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 100, 4));
	_assert_egress_qos_mappings (ifindex, 4,
	                             1, 5,
	                             7, 3,
	                             9, 5,
	                             100, 4);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, G_MAXUINT32, 4));
	_assert_egress_qos_mappings (ifindex, 5,
	                             1, 5,
	                             7, 3,
	                             9, 5,
	                             100, 4,
	                             G_MAXUINT32, 4);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, G_MAXUINT32, 8));
	_assert_egress_qos_mappings (ifindex, 5,
	                             1, 5,
	                             7, 3,
	                             9, 5,
	                             100, 4,
	                             G_MAXUINT32, 4);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, G_MAXUINT32, 0));
	_assert_egress_qos_mappings (ifindex, 4,
	                             1, 5,
	                             7, 3,
	                             9, 5,
	                             100, 4);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 100, 0));
	_assert_egress_qos_mappings (ifindex, 3,
	                             1, 5,
	                             7, 3,
	                             9, 5);

	g_assert (nm_platform_link_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, 1, 0));
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

	nmtstp_link_delete (NULL, -1, ifindex, DEVICE_NAME, TRUE);
	nmtstp_link_delete (NULL, -1, ifindex_parent, PARENT_NAME, TRUE);
}

/*****************************************************************************/

static void
test_create_many_links_do (guint n_devices)
{
	gint64 time, start_time = nm_utils_get_monotonic_timestamp_ns ();
	guint i;
	char name[64];
	const NMPlatformLink *pllink;
	gs_unref_array GArray *ifindexes = g_array_sized_new (FALSE, FALSE, sizeof (int), n_devices);
	const int EX = ((int) (nmtst_get_rand_uint32 () % 4)) - 1;

	g_assert (EX >= -1 && EX <= 2);

	_LOGI (">>> create devices (EX=%d)...", EX);

	for (i = 0; i < n_devices; i++) {
		nm_sprintf_buf (name, "t-%05u", i);
		if (EX == 2) {
			/* This mode is different from letting nmtstp_link_dummy_add()
			 * because in this case we don't process any platform events
			 * while adding all the links. */
			nmtstp_run_command_check ("ip link add %s type dummy", name);
		} else
			nmtstp_link_dummy_add (NULL, EX, name);
	}

	_LOGI (">>> process events after creating devices...");

	nm_platform_process_events (NM_PLATFORM_GET);

	_LOGI (">>> check devices...");

	for (i = 0; i < n_devices; i++) {
		nm_sprintf_buf (name, "t-%05u", i);

		pllink = nm_platform_link_get_by_ifname (NM_PLATFORM_GET, name);
		g_assert (pllink);
		g_assert_cmpint (pllink->type, ==, NM_LINK_TYPE_DUMMY);
		g_assert_cmpstr (pllink->name, ==, name);

		g_array_append_val (ifindexes, pllink->ifindex);
	}

	_LOGI (">>> delete devices...");

	g_assert_cmpint (ifindexes->len, ==, n_devices);
	for (i = 0; i < n_devices; i++) {
		nm_sprintf_buf (name, "t-%05u", i);

		if (EX == 2)
			nmtstp_run_command_check ("ip link delete %s", name);
		else
			nmtstp_link_delete (NULL, EX, g_array_index (ifindexes, int, i), name, TRUE);
	}

	_LOGI (">>> process events after deleting devices...");
	nm_platform_process_events (NM_PLATFORM_GET);

	time = nm_utils_get_monotonic_timestamp_ns () - start_time;
	_LOGI (">>> finished in %ld.%09ld seconds", (long) (time / NM_UTILS_NS_PER_SECOND), (long) (time % NM_UTILS_NS_PER_SECOND));
}

static void
test_create_many_links (gconstpointer user_data)
{
	guint n_devices = GPOINTER_TO_UINT (user_data);

	if (n_devices > 100 && nmtst_test_quick ()) {
		g_print ("Skipping test: don't run long running test %s (NMTST_DEBUG=slow)\n", g_get_prgname () ?: "test-link-linux");
		g_test_skip ("Skip long running test");
		return;
	}

	test_create_many_links_do (n_devices);
}

/*****************************************************************************/

static void
test_nl_bugs_veth (void)
{
	const char *IFACE_VETH0 = "nm-test-veth0";
	const char *IFACE_VETH1 = "nm-test-veth1";
	int ifindex_veth0, ifindex_veth1;
	int i;
	const NMPlatformLink *pllink_veth0, *pllink_veth1;
	gs_free_error GError *error = NULL;
	NMTstpNamespaceHandle *ns_handle = NULL;

	/* create veth pair. */
	ifindex_veth0 = nmtstp_link_veth_add (NM_PLATFORM_GET, -1, IFACE_VETH0, IFACE_VETH1)->ifindex;
	ifindex_veth1 = nmtstp_link_get_typed (NM_PLATFORM_GET, -1, IFACE_VETH1, NM_LINK_TYPE_VETH)->ifindex;

	/* assert that nm_platform_link_veth_get_properties() returns the expected peer ifindexes. */
	g_assert (nm_platform_link_veth_get_properties (NM_PLATFORM_GET, ifindex_veth0, &i));
	g_assert_cmpint (i, ==, ifindex_veth1);

	g_assert (nm_platform_link_veth_get_properties (NM_PLATFORM_GET, ifindex_veth1, &i));
	g_assert_cmpint (i, ==, ifindex_veth0);

	/* assert that NMPlatformLink.parent is the peer-ifindex. */
	pllink_veth0 = nm_platform_link_get (NM_PLATFORM_GET, ifindex_veth0);
	g_assert (pllink_veth0);
	if (pllink_veth0->parent == 0) {
		/* Kernels prior to 4.1 dated 21 June, 2015 don't support exposing the veth peer
		 * as IFA_LINK. skip the remainder of the test. */
		goto out;
	}
	g_assert_cmpint (pllink_veth0->parent, ==, ifindex_veth1);

	/* The following tests whether we have a workaround for kernel bug
	 * https://bugzilla.redhat.com/show_bug.cgi?id=1285827 in place. */
	pllink_veth1 = nm_platform_link_get (NM_PLATFORM_GET, ifindex_veth1);
	g_assert (pllink_veth1);
	g_assert_cmpint (pllink_veth1->parent, ==, ifindex_veth0);

	/* move one veth peer to another namespace and check that the
	 * parent/IFLA_LINK of the remaining peer properly updates
	 * (https://bugzilla.redhat.com/show_bug.cgi?id=1262908). */
	ns_handle = nmtstp_namespace_create (CLONE_NEWNET, &error);
	g_assert_no_error (error);
	g_assert (ns_handle);

	nmtstp_run_command_check ("ip link set %s netns %ld", IFACE_VETH1, (long) nmtstp_namespace_handle_get_pid (ns_handle));
	NMTST_WAIT_ASSERT (100, {
		nmtstp_wait_for_signal (NM_PLATFORM_GET, 50);
		nm_platform_process_events (NM_PLATFORM_GET);

		pllink_veth1 = nm_platform_link_get (NM_PLATFORM_GET, ifindex_veth1);
		pllink_veth0 = nm_platform_link_get (NM_PLATFORM_GET, ifindex_veth0);
		if (   !pllink_veth1
		    && pllink_veth0
		    && pllink_veth0->parent == NM_PLATFORM_LINK_OTHER_NETNS) {
			break;
		}
	});

out:
	nmtstp_link_delete (NULL, -1, ifindex_veth0, IFACE_VETH0, TRUE);
	g_assert (!nmtstp_link_get (NM_PLATFORM_GET, ifindex_veth0, IFACE_VETH0));
	g_assert (!nmtstp_link_get (NM_PLATFORM_GET, ifindex_veth1, IFACE_VETH1));
	nmtstp_namespace_handle_release (ns_handle);
}

/*****************************************************************************/

static void
test_nl_bugs_spuroius_newlink (void)
{
	const char *IFACE_BOND0 = "nm-test-bond0";
	const char *IFACE_DUMMY0 = "nm-test-dummy0";
	int ifindex_bond0, ifindex_dummy0;
	const NMPlatformLink *pllink;
	gboolean wait_for_settle;

	/* see https://bugzilla.redhat.com/show_bug.cgi?id=1285719 */

	nmtstp_run_command_check ("ip link add %s type dummy", IFACE_DUMMY0);
	ifindex_dummy0 = nmtstp_assert_wait_for_link (NM_PLATFORM_GET, IFACE_DUMMY0, NM_LINK_TYPE_DUMMY, 100)->ifindex;

	nmtstp_run_command_check ("ip link add %s type bond", IFACE_BOND0);
	ifindex_bond0 = nmtstp_assert_wait_for_link (NM_PLATFORM_GET, IFACE_BOND0, NM_LINK_TYPE_BOND, 100)->ifindex;

	nmtstp_link_set_updown (NULL, -1, ifindex_bond0, TRUE);

	nmtstp_run_command_check ("ip link set %s master %s", IFACE_DUMMY0, IFACE_BOND0);
	NMTST_WAIT_ASSERT (100, {
		nmtstp_wait_for_signal (NM_PLATFORM_GET, 50);

		pllink = nm_platform_link_get (NM_PLATFORM_GET, ifindex_dummy0);
		g_assert (pllink);
		if (pllink->master == ifindex_bond0)
			break;
	});

	nmtstp_run_command_check ("ip link del %s",  IFACE_BOND0);

	wait_for_settle = TRUE;
	nmtstp_wait_for_signal (NM_PLATFORM_GET, 50);
again:
	nm_platform_process_events (NM_PLATFORM_GET);
	pllink = nm_platform_link_get (NM_PLATFORM_GET, ifindex_bond0);
	g_assert (!pllink);

	if (wait_for_settle) {
		wait_for_settle = FALSE;
		NMTST_WAIT (300, { nmtstp_wait_for_signal (NM_PLATFORM_GET, 50); });
		goto again;
	}

	g_assert (!nmtstp_link_get (NM_PLATFORM_GET, ifindex_bond0, IFACE_BOND0));
	nmtstp_link_delete (NULL, -1, ifindex_dummy0, IFACE_DUMMY0, TRUE);
}

/*****************************************************************************/

static void
test_nl_bugs_spuroius_dellink (void)
{
	const char *IFACE_BRIDGE0 = "nm-test-bridge0";
	const char *IFACE_DUMMY0 = "nm-test-dummy0";
	int ifindex_bridge0, ifindex_dummy0;
	const NMPlatformLink *pllink;
	gboolean wait_for_settle;

	/* see https://bugzilla.redhat.com/show_bug.cgi?id=1285719 */

	nmtstp_run_command_check ("ip link add %s type dummy", IFACE_DUMMY0);
	ifindex_dummy0 = nmtstp_assert_wait_for_link (NM_PLATFORM_GET, IFACE_DUMMY0, NM_LINK_TYPE_DUMMY, 100)->ifindex;

	nmtstp_run_command_check ("ip link add %s type bridge", IFACE_BRIDGE0);
	ifindex_bridge0 = nmtstp_assert_wait_for_link (NM_PLATFORM_GET, IFACE_BRIDGE0, NM_LINK_TYPE_BRIDGE, 100)->ifindex;

	nmtstp_link_set_updown (NULL, -1, ifindex_bridge0, TRUE);

	nmtstp_run_command_check ("ip link set %s master %s", IFACE_DUMMY0, IFACE_BRIDGE0);
	NMTST_WAIT_ASSERT (100, {
		nmtstp_wait_for_signal (NM_PLATFORM_GET, 50);

		pllink = nm_platform_link_get (NM_PLATFORM_GET, ifindex_dummy0);
		g_assert (pllink);
		if (pllink->master == ifindex_bridge0)
			break;
	});

	nm_platform_process_events (NM_PLATFORM_GET);

	nmtstp_run_command_check ("ip link set %s nomaster",  IFACE_DUMMY0);

	wait_for_settle = TRUE;
	nmtstp_wait_for_signal (NM_PLATFORM_GET, 50);
again:
	nm_platform_process_events (NM_PLATFORM_GET);
	pllink = nm_platform_link_get (NM_PLATFORM_GET, ifindex_bridge0);
	g_assert (pllink);
	pllink = nm_platform_link_get (NM_PLATFORM_GET, ifindex_dummy0);
	g_assert (pllink);
	g_assert_cmpint (pllink->parent, ==, 0);

	if (wait_for_settle) {
		wait_for_settle = FALSE;
		NMTST_WAIT (300, { nmtstp_wait_for_signal (NM_PLATFORM_GET, 50); });
		goto again;
	}

	nmtstp_link_delete (NULL, -1, ifindex_bridge0, IFACE_BRIDGE0, TRUE);
	nmtstp_link_delete (NULL, -1, ifindex_dummy0, IFACE_DUMMY0, TRUE);
}

/*****************************************************************************/

static void
_test_netns_setup (gpointer fixture, gconstpointer test_data)
{
	/* the singleton platform instance has netns support disabled.
	 * Destroy the instance before the test and re-create it afterwards. */
	g_object_unref (NM_PLATFORM_GET);
}

static void
_test_netns_teardown (gpointer fixture, gconstpointer test_data)
{
	nmtstp_setup_platform ();
}

static NMPlatform *
_test_netns_create_platform (void)
{
	NMPNetns *netns;
	NMPlatform *platform;

	netns = nmp_netns_new ();
	g_assert (NMP_IS_NETNS (netns));

	platform = nm_linux_platform_new (TRUE, TRUE);
	g_assert (NM_IS_LINUX_PLATFORM (platform));

	nmp_netns_pop (netns);
	g_object_unref (netns);

	return platform;
}

static gboolean
_test_netns_check_skip (void)
{
	static int support = -1;
	static int support_errsv = 0;
	NMPNetns *netns;
	gs_unref_object NMPNetns *netns2 = NULL;

	netns = nmp_netns_get_current ();
	if (!netns) {
		g_test_skip ("No netns support");
		return TRUE;
	}

	g_assert (nmp_netns_get_fd_net (netns) > 0);

	if (support == -1) {
		support = (setns (nmp_netns_get_fd_net (netns), CLONE_NEWNET) == 0);
		if (!support)
			support_errsv = errno;
	}
	if (!support) {
		_LOGD ("setns() failed with \"%s\". This indicates missing support (valgrind?)", nm_strerror_native (support_errsv));
		g_test_skip ("No netns support (setns failed)");
		return TRUE;
	}

	netns2 = nmp_netns_new ();
	if (!netns2) {
		/* skip tests for https://bugzilla.gnome.org/show_bug.cgi?id=790214 */
		g_assert_cmpint (errno, ==, EINVAL);
		g_test_skip ("No netns support to create another netns");
		return TRUE;
	}
	nmp_netns_pop (netns2);

	return FALSE;
}

static gboolean
_check_sysctl_skip (void)
{
	if (access ("/proc/sys/net/ipv4/ip_forward", W_OK) == -1) {
		g_test_skip ("Can not write sysctls");
		return TRUE;
	}

	return FALSE;
}

/*****************************************************************************/

#define _sysctl_assert_eq(plat, path, value) \
	G_STMT_START { \
		gs_free char *_val = NULL; \
		\
		_val = nm_platform_sysctl_get (plat, NMP_SYSCTL_PATHID_ABSOLUTE (path)); \
		g_assert_cmpstr (_val, ==, value); \
	} G_STMT_END

static void
test_netns_general (gpointer fixture, gconstpointer test_data)
{
	gs_unref_object NMPlatform *platform_1 = NULL;
	gs_unref_object NMPlatform *platform_2 = NULL;
	NMPNetns *netns_tmp;
	char sbuf[100];
	int i, j, k;
	gboolean ethtool_support;
	NMPUtilsEthtoolDriverInfo driver_info;

	if (_test_netns_check_skip ())
		return;

	if (_check_sysctl_skip ())
		return;

	platform_1 = nm_linux_platform_new (TRUE, TRUE);
	platform_2 = _test_netns_create_platform ();

	/* add some dummy devices. The "other-*" devices are there to bump the ifindex */
	for (k = 0; k < 2; k++) {
		NMPlatform *p = (k == 0 ? platform_1 : platform_2);
		const char *id = (k == 0 ? "a" : "b");

		for (i = 0, j = nmtst_get_rand_uint32 () % 5; i < j; i++)
			_ADD_DUMMY (p, nm_sprintf_buf (sbuf, "other-a-%s-%02d", id, i));

		_ADD_DUMMY (p, "dummy1_");

		for (i = 0, j = nmtst_get_rand_uint32 () % 5; i < j; i++)
			_ADD_DUMMY (p, nm_sprintf_buf (sbuf, "other-b-%s-%02d", id, i));

		_ADD_DUMMY (p, nm_sprintf_buf (sbuf, "dummy2%s", id));

		for (i = 0, j = nmtst_get_rand_uint32 () % 5; i < j; i++)
			_ADD_DUMMY (p, nm_sprintf_buf (sbuf, "other-c-%s-%02d", id, i));
	}

	_sysctl_assert_eq (platform_1,"/sys/devices/virtual/net/dummy1_/ifindex",
	                   nm_sprintf_buf (sbuf, "%d", nmtstp_link_get_typed (platform_1, 0, "dummy1_", NM_LINK_TYPE_DUMMY)->ifindex));
	_sysctl_assert_eq (platform_1, "/sys/devices/virtual/net/dummy2a/ifindex",
	                   nm_sprintf_buf (sbuf, "%d", nmtstp_link_get_typed (platform_1, 0, "dummy2a", NM_LINK_TYPE_DUMMY)->ifindex));
	_sysctl_assert_eq (platform_1, "/sys/devices/virtual/net/dummy2b/ifindex",
	                   NULL);

	_sysctl_assert_eq (platform_2, "/sys/devices/virtual/net/dummy1_/ifindex",
	                   nm_sprintf_buf (sbuf, "%d", nmtstp_link_get_typed (platform_2, 0, "dummy1_", NM_LINK_TYPE_DUMMY)->ifindex));
	_sysctl_assert_eq (platform_2, "/sys/devices/virtual/net/dummy2a/ifindex",
	                   NULL);
	_sysctl_assert_eq (platform_2, "/sys/devices/virtual/net/dummy2b/ifindex",
	                   nm_sprintf_buf (sbuf, "%d", nmtstp_link_get_typed (platform_2, 0, "dummy2b", NM_LINK_TYPE_DUMMY)->ifindex));

	for (i = 0; i < 10; i++) {
		NMPlatform *pl;
		const char *path;

		j = nmtst_get_rand_uint32 () % 2;

		if (nmtst_get_rand_uint32 () % 2) {
			pl = platform_1;
			if (nmtst_get_rand_uint32 () % 2)
				path = "/proc/sys/net/ipv6/conf/dummy1_/disable_ipv6";
			else
				path = "/proc/sys/net/ipv6/conf/dummy2a/disable_ipv6";
		} else {
			pl = platform_2;
			if (nmtst_get_rand_uint32 () % 2)
				path = "/proc/sys/net/ipv6/conf/dummy1_/disable_ipv6";
			else
				path = "/proc/sys/net/ipv6/conf/dummy2b/disable_ipv6";
		}
		g_assert (nm_platform_sysctl_set (pl, NMP_SYSCTL_PATHID_ABSOLUTE (path), nm_sprintf_buf (sbuf, "%d", j)));
		_sysctl_assert_eq (pl, path, nm_sprintf_buf (sbuf, "%d", j));
	}

	_sysctl_assert_eq (platform_1, "/proc/sys/net/ipv6/conf/dummy2b/disable_ipv6", NULL);
	_sysctl_assert_eq (platform_2, "/proc/sys/net/ipv6/conf/dummy2a/disable_ipv6", NULL);

	/* Kernels prior to 3.19 dated 8 February, 2015 don't support ethtool -i for dummy devices.
	 * Work around that and skip asserts that are known to fail. */
	ethtool_support = nmtstp_run_command ("ethtool -i dummy1_ > /dev/null") == 0;
	if (ethtool_support) {
		g_assert (nmp_utils_ethtool_get_driver_info (nmtstp_link_get_typed (platform_1, 0, "dummy1_", NM_LINK_TYPE_DUMMY)->ifindex, &driver_info));
		g_assert (nmp_utils_ethtool_get_driver_info (nmtstp_link_get_typed (platform_1, 0, "dummy2a", NM_LINK_TYPE_DUMMY)->ifindex, &driver_info));
		g_assert_cmpint (nmtstp_run_command ("ethtool -i dummy1_ > /dev/null"), ==, 0);
		g_assert_cmpint (nmtstp_run_command ("ethtool -i dummy2a > /dev/null"), ==, 0);
		g_assert_cmpint (nmtstp_run_command ("ethtool -i dummy2b 2> /dev/null"), !=, 0);
	}

	g_assert (nm_platform_netns_push (platform_2, &netns_tmp));

	if (ethtool_support) {
		g_assert (nmp_utils_ethtool_get_driver_info (nmtstp_link_get_typed (platform_2, 0, "dummy1_", NM_LINK_TYPE_DUMMY)->ifindex, &driver_info));
		g_assert (nmp_utils_ethtool_get_driver_info (nmtstp_link_get_typed (platform_2, 0, "dummy2b", NM_LINK_TYPE_DUMMY)->ifindex, &driver_info));
		g_assert_cmpint (nmtstp_run_command ("ethtool -i dummy1_ > /dev/null"), ==, 0);
		g_assert_cmpint (nmtstp_run_command ("ethtool -i dummy2a 2> /dev/null"), !=, 0);
		g_assert_cmpint (nmtstp_run_command ("ethtool -i dummy2b > /dev/null"), ==, 0);
	}

	nmp_netns_pop (netns_tmp);
}

/*****************************************************************************/

static void
test_netns_set_netns (gpointer fixture, gconstpointer test_data)
{
	NMPlatform *platforms[3];
	gs_unref_object NMPlatform *platform_0 = NULL;
	gs_unref_object NMPlatform *platform_1 = NULL;
	gs_unref_object NMPlatform *platform_2 = NULL;
	nm_auto_pop_netns NMPNetns *netns_pop = NULL;

	if (_test_netns_check_skip ())
		return;

	platforms[0] = platform_0 = nm_linux_platform_new (TRUE, TRUE);
	platforms[1] = platform_1 = _test_netns_create_platform ();
	platforms[2] = platform_2 = _test_netns_create_platform ();

	nmtstp_netns_select_random (platforms, G_N_ELEMENTS (platforms), &netns_pop);

#define LINK_MOVE_NAME "link-move"
	g_assert (!nm_platform_link_get_by_ifname (platform_1, LINK_MOVE_NAME));
	g_assert (!nm_platform_link_get_by_ifname (platform_2, LINK_MOVE_NAME));
	_ADD_DUMMY (platform_1, LINK_MOVE_NAME);
	g_assert ( nm_platform_link_get_by_ifname (platform_1, LINK_MOVE_NAME));
	g_assert (!nm_platform_link_get_by_ifname (platform_2, LINK_MOVE_NAME));
	g_assert (nm_platform_link_set_netns (platform_1,
	                                      nm_platform_link_get_by_ifname (platform_1, LINK_MOVE_NAME)->ifindex,
	                                      nmp_netns_get_fd_net (nm_platform_netns_get (platform_2))));
	g_assert (!nm_platform_link_get_by_ifname (platform_1, LINK_MOVE_NAME));
	g_assert (!nm_platform_link_get_by_ifname (platform_2, LINK_MOVE_NAME));
	nmtstp_assert_wait_for_link (platform_2, LINK_MOVE_NAME, NM_LINK_TYPE_DUMMY, 100);
	g_assert (!nm_platform_link_get_by_ifname (platform_1, LINK_MOVE_NAME));
	g_assert ( nm_platform_link_get_by_ifname (platform_2, LINK_MOVE_NAME));
}

/*****************************************************************************/

static char *
_get_current_namespace_id (int ns_type)
{
	const char *p;
	GError *error = NULL;
	char *id;

	switch (ns_type) {
	case CLONE_NEWNET:
		p = "/proc/self/ns/net";
		break;
	case CLONE_NEWNS:
		p = "/proc/self/ns/mnt";
		break;
	default:
		g_assert_not_reached ();
	}

	id = g_file_read_link (p, &error);
	g_assert_no_error (error);
	g_assert (id);
	return id;
}

static char *
_get_sysctl_value (const char *path)
{
	char *data = NULL;
	gs_free_error GError *error = NULL;

	if (!g_file_get_contents (path, &data, NULL, &error)) {
		nmtst_assert_error (error, G_FILE_ERROR, G_FILE_ERROR_NOENT, NULL);
		g_assert (!data);
	} else {
		g_assert_no_error (error);
		g_assert (data);
		g_strstrip (data);
	}
	return data;
}

static void
test_netns_push (gpointer fixture, gconstpointer test_data)
{
	gs_unref_object NMPlatform *platform_0 = NULL;
	gs_unref_object NMPlatform *platform_1 = NULL;
	gs_unref_object NMPlatform *platform_2 = NULL;
	nm_auto_pop_netns NMPNetns *netns_pop = NULL;
	gs_unref_ptrarray GPtrArray *device_names = g_ptr_array_new_with_free_func (g_free);
	int i, j;
	const int ns_types_list[] = { CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWNET | CLONE_NEWNS };
	const int ns_types_test[] = { CLONE_NEWNET, CLONE_NEWNS };
	typedef struct {
		NMPlatform *platform;
		const char *device_name;
		const char *sysctl_path;
		const char *sysctl_value;
		const char *ns_net;
		const char *ns_mnt;
	} PlatformData;
	PlatformData pl[3] = { };
	PlatformData *pl_base;
	struct {
		PlatformData *pl;
		int ns_types;
	} stack[6] = { };
	int nstack;

	if (_test_netns_check_skip ())
		return;

	if (_check_sysctl_skip ())
		return;

	pl[0].platform = platform_0 = nm_linux_platform_new (TRUE, TRUE);
	pl[1].platform = platform_1 = _test_netns_create_platform ();
	pl[2].platform = platform_2 = _test_netns_create_platform ();

	pl_base = &pl[0];
	i = nmtst_get_rand_uint32 () % (G_N_ELEMENTS (pl) + 1);
	if (i < G_N_ELEMENTS (pl)) {
		pl_base = &pl[i];
		g_assert (nm_platform_netns_push (pl[i].platform, &netns_pop));
	}

	for (i = 0; i < G_N_ELEMENTS (pl); i++) {
		nm_auto_pop_netns NMPNetns *netns_free = NULL;
		char *tmp;

		g_assert (nm_platform_netns_push (pl[i].platform, &netns_free));

		tmp = g_strdup_printf ("nmtst-dev-%d", i);
		g_ptr_array_add (device_names, tmp);
		pl[i].device_name = tmp;

		tmp = g_strdup_printf ("/proc/sys/net/ipv6/conf/%s/disable_ipv6", pl[i].device_name);
		g_ptr_array_add (device_names, tmp);
		pl[i].sysctl_path = tmp;

		pl[i].sysctl_value = nmtst_get_rand_uint32 () % 2 ? "1" : "0";

		_ADD_DUMMY (pl[i].platform, pl[i].device_name);

		g_assert (nm_platform_sysctl_set (pl[i].platform, NMP_SYSCTL_PATHID_ABSOLUTE (pl[i].sysctl_path), pl[i].sysctl_value));

		tmp = _get_current_namespace_id (CLONE_NEWNET);
		g_ptr_array_add (device_names, tmp);
		pl[i].ns_net = tmp;

		tmp = _get_current_namespace_id (CLONE_NEWNS);
		g_ptr_array_add (device_names, tmp);
		pl[i].ns_mnt = tmp;
	}

	nstack = nmtst_get_rand_uint32 () % (G_N_ELEMENTS (stack) + 1);
	for (i = 0; i < nstack; i++) {
		stack[i].pl = &pl[nmtst_get_rand_uint32 () % G_N_ELEMENTS (pl)];
		stack[i].ns_types = ns_types_list[nmtst_get_rand_uint32 () % G_N_ELEMENTS (ns_types_list)];

		nmp_netns_push_type (nm_platform_netns_get (stack[i].pl->platform), stack[i].ns_types);
	}

	/* pop some again. */
	for (i = nmtst_get_rand_uint32 () % (nstack + 1); i > 0; i--) {
		g_assert (nstack > 0);
		nstack--;
		nmp_netns_pop (nm_platform_netns_get (stack[nstack].pl->platform));
	}

	for (i = 0; i < G_N_ELEMENTS (ns_types_test); i++) {
		int ns_type = ns_types_test[i];
		PlatformData *p;
		gs_free char *current_namespace_id = NULL;

		p = pl_base;
		for (j = nstack; j >= 1; ) {
			j--;
			if (NM_FLAGS_ANY (stack[j].ns_types, ns_type)) {
				p = stack[j].pl;
				break;
			}
		}

		current_namespace_id = _get_current_namespace_id (ns_type);

		if (ns_type == CLONE_NEWNET) {
			g_assert_cmpstr (current_namespace_id, ==, p->ns_net);
			for (j = 0; j < G_N_ELEMENTS (pl); j++) {
				gs_free char *data = NULL;

				if (p == &pl[j])
					g_assert_cmpint (nmtstp_run_command ("ip link show %s 1>/dev/null", pl[j].device_name), ==, 0);
				else
					g_assert_cmpint (nmtstp_run_command ("ip link show %s 2>/dev/null", pl[j].device_name), !=, 0);

				data = _get_sysctl_value (pl[j].sysctl_path);
				if (p == &pl[j])
					g_assert_cmpstr (data, ==, pl[j].sysctl_value);
				else
					g_assert (!data);
			}
		} else if (ns_type == CLONE_NEWNS) {
			g_assert_cmpstr (current_namespace_id, ==, p->ns_mnt);
			for (j = 0; j < G_N_ELEMENTS (pl); j++) {
				char path[600];
				gs_free char *data = NULL;

				nm_sprintf_buf (path, "/sys/devices/virtual/net/%s/ifindex", pl[j].device_name);

				data = _get_sysctl_value (path);
				if (p == &pl[j])
					g_assert_cmpstr (data, ==, nm_sprintf_buf (path, "%d", nmtstp_link_get_typed (p->platform, 0, p->device_name, NM_LINK_TYPE_DUMMY)->ifindex));
				else
					g_assert (!data);
			}
		} else
			g_assert_not_reached ();
	}

	for (i = nstack; i >= 1; ) {
		i--;
		nmp_netns_pop (nm_platform_netns_get (stack[i].pl->platform));
	}
}

/*****************************************************************************/

static void
test_netns_bind_to_path (gpointer fixture, gconstpointer test_data)
{
#define P_VAR_RUN                "/run"
#define P_VAR_RUN_NETNS          "/run/netns"
#define P_VAR_RUN_NETNS_BINDNAME "/run/netns/"P_NETNS_BINDNAME
#define P_NETNS_BINDNAME         "nmtst-iproute2-netns"
	gs_unref_object NMPlatform *platform_0 = NULL;
	gs_unref_object NMPlatform *platform_1 = NULL;
	gs_unref_object NMPlatform *platform_2 = NULL;
	nm_auto_pop_netns NMPNetns *netns_pop = NULL;
	NMPlatform *platforms[3];
	NMPNetns *netns;
	int i;

	if (_test_netns_check_skip ())
		return;

	platforms[0] = platform_0 = nm_linux_platform_new (TRUE, TRUE);
	platforms[1] = platform_1 = _test_netns_create_platform ();
	platforms[2] = platform_2 = _test_netns_create_platform ();

	nmtstp_netns_select_random (platforms, G_N_ELEMENTS (platforms), &netns_pop);

	g_assert_cmpint (mount ("tmpfs", P_VAR_RUN, "tmpfs", MS_NOATIME | MS_NODEV | MS_NOSUID, "mode=0755,size=32K"), ==, 0);
	g_assert_cmpint (mkdir (P_VAR_RUN_NETNS, 755), ==, 0);

	i = (nmtst_get_rand_uint32 () % 2) + 1;
	netns = nm_platform_netns_get (platforms[i]);

	_ADD_DUMMY (platforms[i], "dummy2b");

	g_assert (!g_file_test (P_VAR_RUN_NETNS_BINDNAME, G_FILE_TEST_EXISTS));
	g_assert_cmpint (nmtstp_run_command ("ip netns exec "P_NETNS_BINDNAME" true 2>/dev/null"), !=, 0);

	g_assert (nmp_netns_bind_to_path (netns, P_VAR_RUN_NETNS_BINDNAME, NULL));

	g_assert (g_file_test (P_VAR_RUN_NETNS_BINDNAME, G_FILE_TEST_EXISTS));
	g_assert_cmpint (nmtstp_run_command ("ip netns exec "P_NETNS_BINDNAME" true"), ==, 0);
	g_assert_cmpint (nmtstp_run_command ("ip netns exec "P_NETNS_BINDNAME" ip link show dummy2b 1>/dev/null"), ==, 0);

	g_assert (nmp_netns_bind_to_path_destroy (netns, P_VAR_RUN_NETNS_BINDNAME));

	g_assert (!g_file_test (P_VAR_RUN_NETNS_BINDNAME, G_FILE_TEST_EXISTS));
	g_assert_cmpint (nmtstp_run_command ("ip netns exec "P_NETNS_BINDNAME" true 2>/dev/null"), !=, 0);

	g_assert_cmpint (umount (P_VAR_RUN), ==, 0);
}

/*****************************************************************************/

static void
test_sysctl_rename (void)
{
	NMPlatform *const PL = NM_PLATFORM_GET;
	const char *const IFNAME[3] = {
		"nm-dummy-0",
		"nm-dummy-1",
		"nm-dummy-2",
	};
	int ifindex[G_N_ELEMENTS (IFNAME)] = { 0 };
	nm_auto_close int dirfd = -1;
	int i;
	char ifname_buf[IFNAMSIZ];
	char *s;
	const NMPlatformLink *pllink;

	ifindex[0] = nmtstp_link_dummy_add (PL, -1, IFNAME[0])->ifindex;
	ifindex[1] = nmtstp_link_dummy_add (PL, -1, IFNAME[1])->ifindex;

	s = (nmtst_get_rand_uint32 () % 2) ? NULL : ifname_buf;

	if (nmtst_get_rand_uint32 () % 2) {
		/* bring the platform cache out of sync */
		nmtstp_run_command_check ("ip link set %s name %s", IFNAME[0], IFNAME[2]);
		nm_platform_process_events (PL);
		nmtstp_run_command_check ("ip link set %s name %s", IFNAME[2], IFNAME[0]);

		pllink = nm_platform_link_get_by_ifname (PL, IFNAME[2]);
		g_assert (pllink && pllink->ifindex == ifindex[0]);
		pllink = nm_platform_link_get_by_ifname (PL, IFNAME[0]);
		g_assert (!pllink);
	}

	/* open dirfd for IFNAME[0] */
	i = nmtst_get_rand_uint32 () % (2 + G_N_ELEMENTS (IFNAME));
	if (i == 0) {
		dirfd = nm_platform_sysctl_open_netdir (PL,
		                                        ifindex[0],
		                                        s);
	} else {
		const char *ifname_guess;

		/* provide a wrong or no guess. */
		ifname_guess = i == 1 ? NULL : IFNAME[i - 2];
		dirfd = nmp_utils_sysctl_open_netdir (ifindex[0],
		                                       ifname_guess,
		                                       s);
	}
	g_assert (dirfd >= 0);
	if (s)
		g_assert_cmpstr (s, ==, IFNAME[0]);

	/* possibly rename the interfaces. */
	switch (nmtst_get_rand_uint32 () % 4) {
	case 0:
		break;
	case 1:
		nmtstp_run_command_check ("ip link set %s name %s", IFNAME[0], IFNAME[2]);
		break;
	case 2:
		nmtstp_run_command_check ("ip link set %s name %s", IFNAME[0], IFNAME[2]);
		nmtstp_run_command_check ("ip link set %s name %s", IFNAME[1], IFNAME[0]);
		break;
	}

	/* possibly, resync platform cache (should make no difference). */
	if (nmtst_get_rand_uint32 () % 2)
		nm_platform_process_events (PL);

	/* check that we still read the same file. */
	switch (nmtst_get_rand_uint32 () % 2) {
	case 0: {
		gs_free char *c = NULL;

		if (nm_utils_file_get_contents (dirfd, "ifindex", 1*1024*1024,
		                                NM_UTILS_FILE_GET_CONTENTS_FLAG_NONE,
		                                &c, NULL, NULL) < 0)
			g_assert_not_reached();
		g_assert_cmpint (ifindex[0], ==, (int) _nm_utils_ascii_str_to_int64 (c, 10, 0, G_MAXINT, -1));
		break;
	}
	case 1: {
		g_assert_cmpint (ifindex[0], ==, (gint32) nm_platform_sysctl_get_int32 (PL, NMP_SYSCTL_PATHID_NETDIR (dirfd, s ?: "<unknown>", "ifindex"), -1));
		break;
	}
	}

	nm_platform_process_events (PL);
	nmtstp_link_delete (PL, -1, ifindex[0], NULL, TRUE);
	nmtstp_link_delete (PL, -1, ifindex[1], NULL, TRUE);
}

/*****************************************************************************/

static void
test_sysctl_netns_switch (void)
{
	const char *const IFNAME = "nm-dummy-0";
	int ifindex, ifindex_tmp;
	nm_auto_close int dirfd = -1;
	char ifname_buf[IFNAMSIZ];
	char *s;
	gs_unref_object NMPlatform *platform_0 = NULL;
	gs_unref_object NMPlatform *platform_1 = NULL;
	gs_unref_object NMPlatform *platform_2 = NULL;
	nm_auto_pop_netns NMPNetns *netns_pop_1 = NULL;
	nm_auto_pop_netns NMPNetns *netns_pop_2 = NULL;
	nm_auto_pop_netns NMPNetns *netns_pop_3 = NULL;
	NMPlatform *PL;
	NMPlatform *platforms[3];

	if (_test_netns_check_skip ())
		return;

	platforms[0] = platform_0 = nm_linux_platform_new (TRUE, TRUE);
	platforms[1] = platform_1 = _test_netns_create_platform ();
	platforms[2] = platform_2 = _test_netns_create_platform ();
	PL = platforms[nmtst_get_rand_uint32 () % 3];

	nmtstp_netns_select_random (platforms, G_N_ELEMENTS (platforms), &netns_pop_1);

	ifindex = nmtstp_link_dummy_add (PL, FALSE, IFNAME)->ifindex;

	nmtstp_netns_select_random (platforms, G_N_ELEMENTS (platforms), &netns_pop_2);

	s = (nmtst_get_rand_uint32 () % 2) ? NULL : ifname_buf;
	dirfd = nm_platform_sysctl_open_netdir (PL,
	                                        ifindex,
	                                        s);
	g_assert (dirfd >= 0);
	if (s)
		g_assert_cmpstr (s, ==, IFNAME);

	nmtstp_netns_select_random (platforms, G_N_ELEMENTS (platforms), &netns_pop_3);

	/* even if we switch to other namespaces, we can still lookup the path correctly,
	 * either using dirfd or via the platform instance (which switches namespace as needed). */
	{
		gs_free char *c = NULL;

		if (nm_utils_file_get_contents (dirfd, "ifindex", 0,
		                                NM_UTILS_FILE_GET_CONTENTS_FLAG_NONE,
		                                &c, NULL, NULL) < 0)
			g_assert_not_reached();
		g_assert_cmpint (ifindex, ==, (int) _nm_utils_ascii_str_to_int64 (c, 10, 0, G_MAXINT, -1));
	}
	g_assert_cmpint (ifindex, ==, (gint32) nm_platform_sysctl_get_int32 (PL, NMP_SYSCTL_PATHID_NETDIR (dirfd, s ?: "<unknown>", "ifindex"), -1));
	g_assert_cmpint (ifindex, ==, (gint32) nm_platform_sysctl_get_int32 (PL, NMP_SYSCTL_PATHID_ABSOLUTE (nm_sprintf_bufa (100, "/sys/class/net/%s/ifindex", IFNAME)), -1));

	/* also test that nm_platform_sysctl_get() sets errno to ENOENT for non-existing paths. */
	{
		gint64 i64;
		int errsv;
		char *v;

		errno = ESRCH;
		v = nm_platform_sysctl_get (PL, NMP_SYSCTL_PATHID_ABSOLUTE ("/sys/devices/virtual/net/not-existing/ifindex"));
		errsv = errno;
		g_assert (!v);
		g_assert_cmpint (errsv, ==, ENOENT);

		errno = ESRCH;
		i64 = nm_platform_sysctl_get_int_checked (PL, NMP_SYSCTL_PATHID_ABSOLUTE ("/sys/devices/virtual/net/not-existing/ifindex"), 10, 1, G_MAXINT, -1);
		errsv = errno;
		g_assert_cmpint (i64, ==, -1);
		g_assert_cmpint (errsv, ==, ENOENT);

		errno = ESRCH;
		v = nm_platform_sysctl_get (PL, NMP_SYSCTL_PATHID_ABSOLUTE ("/sys/devices/virtual/net/lo/not-existing"));
		errsv = errno;
		g_assert (!v);
		g_assert_cmpint (errsv, ==, ENOENT);

		errno = ESRCH;
		i64 = nm_platform_sysctl_get_int_checked (PL, NMP_SYSCTL_PATHID_ABSOLUTE ("/sys/devices/virtual/net/lo/not-existing"), 10, 1, G_MAXINT, -1);
		errsv = errno;
		g_assert_cmpint (i64, ==, -1);
		g_assert_cmpint (errsv, ==, ENOENT);
	}

	/* accessing the path directly, only succeeds iff the current namespace happens to be the namespace
	 * in which we created the link. */
	{
		gs_free char *c = NULL;

		if (nm_utils_file_get_contents (-1,
		                                nm_sprintf_bufa (100, "/sys/class/net/%s/ifindex", IFNAME),
		                                0,
		                                NM_UTILS_FILE_GET_CONTENTS_FLAG_NONE,
		                                &c, NULL, NULL) < 0)
			ifindex_tmp = -1;
		else
			ifindex_tmp = _nm_utils_ascii_str_to_int64 (c, 10, 0, G_MAXINT, -2);
	}
	if (nmp_netns_get_current () == nm_platform_netns_get (PL))
		g_assert_cmpint (ifindex_tmp, ==, ifindex);
	else
		g_assert_cmpint (ifindex_tmp, ==, -1);

	nmtstp_link_delete (PL, FALSE, ifindex, NULL, TRUE);
}

static void
sysctl_set_async_cb_assert_success (GError *error, gpointer data)
{
	g_assert_no_error (error);
	g_main_loop_quit (data);
}

static void
sysctl_set_async_cb_assert_failure (GError *error, gpointer data)
{
	g_assert (error);
	g_main_loop_quit (data);
}

static void
test_sysctl_set_async (void)
{
	NMPlatform *const PL = NM_PLATFORM_GET;
	const char *const IFNAME = "nm-dummy-0";
	const char *const PATH = "/proc/sys/net/ipv4/conf/nm-dummy-0/rp_filter";
	gs_free GMainLoop *loop = NULL;
	gs_unref_object GCancellable *cancellable = NULL;
	int ifindex;

	ifindex = nmtstp_link_dummy_add (PL, -1, IFNAME)->ifindex;
	loop = g_main_loop_new (NULL, FALSE);
	cancellable = g_cancellable_new ();

	nm_platform_sysctl_set_async (PL,
	                              NMP_SYSCTL_PATHID_ABSOLUTE (PATH),
	                              (const char *[]) { "2", NULL},
	                              sysctl_set_async_cb_assert_success,
	                              loop,
	                              cancellable);

	if (!nmtst_main_loop_run (loop, 1000))
		g_assert_not_reached ();

	g_assert_cmpint (nm_platform_sysctl_get_int32 (PL, NMP_SYSCTL_PATHID_ABSOLUTE (PATH), -1),
	                 ==,
	                 2);

	nm_platform_sysctl_set_async (PL,
	                              NMP_SYSCTL_PATHID_ABSOLUTE (PATH),
	                              (const char *[]) { "2", "0", "1", "0", "1", NULL},
	                              sysctl_set_async_cb_assert_success,
	                              loop,
	                              cancellable);

	if (!nmtst_main_loop_run (loop, 2000))
		g_assert_not_reached ();

	g_assert_cmpint (nm_platform_sysctl_get_int32 (PL, NMP_SYSCTL_PATHID_ABSOLUTE (PATH), -1),
	                 ==,
	                 1);

	nmtstp_link_delete (NULL, -1, ifindex, IFNAME, TRUE);
}

static void
test_sysctl_set_async_fail (void)
{
	NMPlatform *const PL = NM_PLATFORM_GET;
	const char *const IFNAME = "nm-dummy-0";
	const char *const PATH = "/proc/sys/net/ipv4/conf/nm-dummy-0/does-not-exist";
	gs_free GMainLoop *loop = NULL;
	gs_unref_object GCancellable *cancellable = NULL;
	int ifindex;

	ifindex = nmtstp_link_dummy_add (PL, -1, IFNAME)->ifindex;
	loop = g_main_loop_new (NULL, FALSE);
	cancellable = g_cancellable_new ();

	nm_platform_sysctl_set_async (PL,
	                              NMP_SYSCTL_PATHID_ABSOLUTE (PATH),
	                              (const char *[]) { "2", NULL},
	                              sysctl_set_async_cb_assert_failure,
	                              loop,
	                              cancellable);

	if (!nmtst_main_loop_run (loop, 1000))
		g_assert_not_reached ();

	nmtstp_link_delete (NULL, -1, ifindex, IFNAME, TRUE);
}

/*****************************************************************************/

static gpointer
_test_netns_mt_thread (gpointer data)
{
	NMPNetns *netns1 = data;
	gs_unref_object NMPNetns *netns2 = NULL;
	NMPNetns *netns_bottom;
	NMPNetns *initial;

	netns_bottom = nmp_netns_get_initial ();
	g_assert (netns_bottom);

	/* I don't know why, but we need to create a new netns here at least once.
	 * Otherwise, setns(, CLONE_NEWNS) below fails with EINVAL (???).
	 *
	 * Something is not right here, but what?  */
	netns2 = nmp_netns_new ();
	nmp_netns_pop (netns2);
	g_clear_object (&netns2);

	nmp_netns_push (netns1);
	nmp_netns_push_type (netns_bottom, CLONE_NEWNET);
	nmp_netns_push_type (netns_bottom, CLONE_NEWNS);
	nmp_netns_push_type (netns1, CLONE_NEWNS);
	nmp_netns_pop (netns1);
	nmp_netns_pop (netns_bottom);
	nmp_netns_pop (netns_bottom);
	nmp_netns_pop (netns1);

	initial = nmp_netns_get_initial ();
	g_assert (NMP_IS_NETNS (initial));
	return g_object_ref (initial);
}

static void
test_netns_mt (void)
{
	gs_unref_object NMPNetns *netns1 = NULL;
	NMPNetns *initial_from_other_thread;
	GThread *th;

	if (_test_netns_check_skip ())
		return;

	netns1 = nmp_netns_new ();
	g_assert (NMP_NETNS (netns1));
	nmp_netns_pop (netns1);

	th = g_thread_new ("nm-test-netns-mt", _test_netns_mt_thread, netns1);
	initial_from_other_thread = g_thread_join (th);
	g_assert (NMP_IS_NETNS (initial_from_other_thread));

	if (nmtst_get_rand_bool ()) {
		nmp_netns_push (initial_from_other_thread);
		nmp_netns_pop (initial_from_other_thread);
	}

	g_object_add_weak_pointer (G_OBJECT (initial_from_other_thread), (gpointer *) &initial_from_other_thread);
	g_object_unref (initial_from_other_thread);
	g_assert (initial_from_other_thread == NULL);
}

/*****************************************************************************/

static void
ethtool_features_dump (const NMEthtoolFeatureStates *features)
{
	guint i, j;

	g_assert (features);

	_LOGT (">>> %u features (%u ss-features)", features->n_states, features->n_ss_features);

	for (i = 0; i < features->n_states; i++) {
		const NMEthtoolFeatureState *s = &features->states_list[i];

		_LOGT (">>> feature-list[%3u]: %3d = %-32s (%3u) | %s %s %s %s",
		       i,
		       (int) s->info->ethtool_id,
		       s->info->kernel_names[s->idx_kernel_name],
		       s->idx_ss_features,
		       s->active ? "ACT" : "act",
		       s->available ? "AVA" : "ava",
		       s->never_changed ? "NCH" : "nch",
		       s->requested ? "REQ" : "req");
	}
	for (i = 0; i < _NM_ETHTOOL_ID_FEATURE_NUM; i++) {
		_LOGT (">>> feature-idx [%3u]: %-32s = %u features",
		       i + (guint) _NM_ETHTOOL_ID_FEATURE_FIRST,
		       nm_ethtool_data[i + _NM_ETHTOOL_ID_FEATURE_FIRST]->optname,
		       (guint) NM_PTRARRAY_LEN (features->states_indexed[i]));
		for (j = 0; features->states_indexed[i] && features->states_indexed[i][j]; j++) {
			const NMEthtoolFeatureState *s = features->states_indexed[i][j];

			_LOGT (">>>  %3u: %-32s | %s %s %s %s",
			       j,
			       s->info->kernel_names[s->idx_kernel_name],
			       s->active ? "ACT" : "act",
			       s->available ? "AVA" : "ava",
			       s->never_changed ? "NCH" : "nch",
			       s->requested ? "REQ" : "req");
		}
	}
}

static void
test_ethtool_features_get (void)
{
	gs_unref_ptrarray GPtrArray *gfree_keeper = g_ptr_array_new_with_free_func (g_free);
	const int IFINDEX = 1;
	guint i;
	guint i_run;

	for (i_run = 0; i_run < 5; i_run++) {
		NMEthtoolFeatureStates *features;
		NMTernary *requested;
		gboolean do_set = TRUE;

		requested = g_new (NMTernary, _NM_ETHTOOL_ID_FEATURE_NUM);
		for (i = 0; i < _NM_ETHTOOL_ID_FEATURE_NUM; i++)
			requested[i] = NM_TERNARY_DEFAULT;
		g_ptr_array_add (gfree_keeper, requested);

		if (i_run == 0) {
			requested[NM_ETHTOOL_ID_FEATURE_RX]                    = NM_TERNARY_FALSE;
			requested[NM_ETHTOOL_ID_FEATURE_TSO]                   = NM_TERNARY_FALSE;
			requested[NM_ETHTOOL_ID_FEATURE_TX_TCP6_SEGMENTATION]  = NM_TERNARY_FALSE;
		} else if (i_run == 1)
			do_set = FALSE;
		else if (i_run == 2) {
			requested[NM_ETHTOOL_ID_FEATURE_TSO]                   = NM_TERNARY_FALSE;
			requested[NM_ETHTOOL_ID_FEATURE_TX_TCP6_SEGMENTATION]  = NM_TERNARY_TRUE;
		} else if (i_run == 3)
			do_set = FALSE;

		_LOGT (">>> ethtool-features-get RUN %u (do-set=%s", i_run, do_set ? "set" : "reset");

		features = nmp_utils_ethtool_get_features (IFINDEX);
		g_ptr_array_add (gfree_keeper, features);

		ethtool_features_dump (features);

		if (_LOGT_ENABLED ())
			_system ("ethtool -k lo");

		if (!do_set) {
			requested = gfree_keeper->pdata[i_run * 2 - 2];
			features = gfree_keeper->pdata[i_run * 2 - 1];
		}

		nmp_utils_ethtool_set_features (IFINDEX, features, requested, do_set);
	}
}

/*****************************************************************************/

NMTstpSetupFunc const _nmtstp_setup_platform_func = SETUP;

void
_nmtstp_init_tests (int *argc, char ***argv)
{
	nmtst_init_with_logging (argc, argv, NULL, "ALL");
}

void
_nmtstp_setup_tests (void)
{
	nmtstp_link_delete (NM_PLATFORM_GET, -1, -1, DEVICE_NAME, FALSE);
	nmtstp_link_delete (NM_PLATFORM_GET, -1, -1, SLAVE_NAME, FALSE);
	nmtstp_link_delete (NM_PLATFORM_GET, -1, -1, PARENT_NAME, FALSE);
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
		test_software_detect_add ("/link/software/detect/gretap", NM_LINK_TYPE_GRETAP, 0);
		test_software_detect_add ("/link/software/detect/ip6tnl/0", NM_LINK_TYPE_IP6TNL, 0);
		test_software_detect_add ("/link/software/detect/ip6tnl/1", NM_LINK_TYPE_IP6TNL, 1);
		test_software_detect_add ("/link/software/detect/ip6gre", NM_LINK_TYPE_IP6GRE, 0);
		test_software_detect_add ("/link/software/detect/ip6gretap", NM_LINK_TYPE_IP6GRETAP, 0);
		test_software_detect_add ("/link/software/detect/ipip", NM_LINK_TYPE_IPIP, 0);
		test_software_detect_add ("/link/software/detect/macvlan", NM_LINK_TYPE_MACVLAN, 0);
		test_software_detect_add ("/link/software/detect/macvtap", NM_LINK_TYPE_MACVTAP, 0);
		test_software_detect_add ("/link/software/detect/sit", NM_LINK_TYPE_SIT, 0);
		test_software_detect_add ("/link/software/detect/tun", NM_LINK_TYPE_TUN, 0);
		test_software_detect_add ("/link/software/detect/vlan", NM_LINK_TYPE_VLAN, 0);
		test_software_detect_add ("/link/software/detect/vxlan/0", NM_LINK_TYPE_VXLAN, 0);
		test_software_detect_add ("/link/software/detect/vxlan/1", NM_LINK_TYPE_VXLAN, 1);
		test_software_detect_add ("/link/software/detect/wireguard/0", NM_LINK_TYPE_WIREGUARD, 0);
		test_software_detect_add ("/link/software/detect/wireguard/1", NM_LINK_TYPE_WIREGUARD, 1);
		test_software_detect_add ("/link/software/detect/wireguard/2", NM_LINK_TYPE_WIREGUARD, 2);

		g_test_add_func ("/link/software/vlan/set-xgress", test_vlan_set_xgress);

		g_test_add_data_func ("/link/create-many-links/20", GUINT_TO_POINTER (20), test_create_many_links);
		g_test_add_data_func ("/link/create-many-links/1000", GUINT_TO_POINTER (1000), test_create_many_links);

		g_test_add_func ("/link/nl-bugs/veth", test_nl_bugs_veth);
		g_test_add_func ("/link/nl-bugs/spurious-newlink", test_nl_bugs_spuroius_newlink);
		g_test_add_func ("/link/nl-bugs/spurious-dellink", test_nl_bugs_spuroius_dellink);

		g_test_add_vtable ("/general/netns/general", 0, NULL, _test_netns_setup, test_netns_general, _test_netns_teardown);
		g_test_add_vtable ("/general/netns/set-netns", 0, NULL, _test_netns_setup, test_netns_set_netns, _test_netns_teardown);
		g_test_add_vtable ("/general/netns/push", 0, NULL, _test_netns_setup, test_netns_push, _test_netns_teardown);
		g_test_add_vtable ("/general/netns/bind-to-path", 0, NULL, _test_netns_setup, test_netns_bind_to_path, _test_netns_teardown);

		g_test_add_func ("/general/netns/mt", test_netns_mt);

		g_test_add_func ("/general/sysctl/rename", test_sysctl_rename);
		g_test_add_func ("/general/sysctl/netns-switch", test_sysctl_netns_switch);
		g_test_add_func ("/general/sysctl/set-async", test_sysctl_set_async);
		g_test_add_func ("/general/sysctl/set-async-fail", test_sysctl_set_async_fail);

		g_test_add_func ("/link/ethtool/features/get", test_ethtool_features_get);
	}
}
