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
 * Copyright 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

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
	g_assert_cmpint (nm_platform_link_dummy_add ((platform), (name), NULL), ==, NM_PLATFORM_ERROR_SUCCESS)

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

	g_assert (nm_platform_link_set_mtu (NM_PLATFORM_GET, BOGUS_IFINDEX, MTU) != NM_PLATFORM_ERROR_SUCCESS);

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
		return nm_platform_link_dummy_add (NM_PLATFORM_GET, name, NULL) == NM_PLATFORM_ERROR_SUCCESS;
	case NM_LINK_TYPE_BRIDGE:
		return nm_platform_link_bridge_add (NM_PLATFORM_GET, name, NULL, 0, NULL) == NM_PLATFORM_ERROR_SUCCESS;
	case NM_LINK_TYPE_BOND:
		{
			gboolean bond0_exists = !!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "bond0");
			NMPlatformError plerr;

			plerr = nm_platform_link_bond_add (NM_PLATFORM_GET, name, NULL);

			/* Check that bond0 is *not* automatically created. */
			if (!bond0_exists)
				g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "bond0"));
			return plerr == NM_PLATFORM_ERROR_SUCCESS;
		}
	case NM_LINK_TYPE_TEAM:
		return nm_platform_link_team_add (NM_PLATFORM_GET, name, NULL) == NM_PLATFORM_ERROR_SUCCESS;
	case NM_LINK_TYPE_VLAN: {
		SignalData *parent_added;
		SignalData *parent_changed;

		/* Don't call link_callback for the bridge interface */
		parent_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_ADDED, link_callback, PARENT_NAME);
		if (nm_platform_link_bridge_add (NM_PLATFORM_GET, PARENT_NAME, NULL, 0, NULL) == NM_PLATFORM_ERROR_SUCCESS)
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

			return nm_platform_link_vlan_add (NM_PLATFORM_GET, name, parent_ifindex, VLAN_ID, 0, NULL) == NM_PLATFORM_ERROR_SUCCESS;
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
	accept_signals (master_changed, 0, 2);

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
	accept_signals (master_changed, 0, 2);

	ensure_no_signal (master_changed);

	/* Release again */
	ensure_no_signal (link_changed);
	g_assert (!nm_platform_link_release (NM_PLATFORM_GET, master, ifindex));

	ensure_no_signal (master_changed);

	/* Remove */
	ensure_no_signal (link_added);
	ensure_no_signal (link_changed);
	ensure_no_signal (link_removed);
	nmtstp_link_del (NULL, -1, ifindex, NULL);
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
	nmtstp_link_del (NULL, -1, ifindex, DEVICE_NAME);
	accept_signal (link_removed);

	/* Delete again */
	g_assert (!nm_platform_link_delete (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME)));
	g_assert (!nm_platform_link_delete (NM_PLATFORM_GET, ifindex));

	/* VLAN: Delete parent */
	if (link_type == NM_LINK_TYPE_VLAN) {
		SignalData *link_removed_parent = add_signal_ifindex (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, link_callback, vlan_parent);

		nmtstp_link_del (NULL, -1, vlan_parent, NULL);
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
	const NMPlatformLink *plink = NULL;

	nm_utils_hwaddr_aton ("de:ad:be:ef:00:11", addr, sizeof (addr));

	g_assert_cmpint (nm_platform_link_bridge_add (NM_PLATFORM_GET, DEVICE_NAME, addr, sizeof (addr), &plink), ==, NM_PLATFORM_ERROR_SUCCESS);
	g_assert (plink);
	link = *plink;
	g_assert_cmpstr (link.name, ==, DEVICE_NAME);

	g_assert_cmpint (link.addr.len, ==, sizeof (addr));
	g_assert (!memcmp (link.addr.data, addr, sizeof (addr)));

	plink = nm_platform_link_get (NM_PLATFORM_GET, link.ifindex);
	g_assert (plink);

	if (nm_platform_check_kernel_support (NM_PLATFORM_GET,
	                                      NM_PLATFORM_KERNEL_SUPPORT_USER_IPV6LL)) {
		g_assert (!nm_platform_link_get_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex));
		g_assert_cmpint (_nm_platform_uint8_inv (plink->inet6_addr_gen_mode_inv), ==, NM_IN6_ADDR_GEN_MODE_EUI64);

		g_assert (nm_platform_link_set_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex, TRUE) == NM_PLATFORM_ERROR_SUCCESS);
		g_assert (nm_platform_link_get_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex));
		plink = nm_platform_link_get (NM_PLATFORM_GET, link.ifindex);
		g_assert (plink);
		g_assert_cmpint (_nm_platform_uint8_inv (plink->inet6_addr_gen_mode_inv), ==, NM_IN6_ADDR_GEN_MODE_NONE);

		g_assert (nm_platform_link_set_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex, FALSE) == NM_PLATFORM_ERROR_SUCCESS);
		g_assert (!nm_platform_link_get_user_ipv6ll_enabled (NM_PLATFORM_GET, link.ifindex));
		plink = nm_platform_link_get (NM_PLATFORM_GET, link.ifindex);
		g_assert (plink);
		g_assert_cmpint (_nm_platform_uint8_inv (plink->inet6_addr_gen_mode_inv), ==, NM_IN6_ADDR_GEN_MODE_EUI64);
	}

	g_assert_cmpint (plink->addr.len, ==, sizeof (addr));
	g_assert (!memcmp (plink->addr.data, addr, sizeof (addr)));

	nmtstp_link_del (NULL, -1, link.ifindex, link.name);
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
	g_assert (nm_platform_link_dummy_add (NM_PLATFORM_GET, DEVICE_NAME, NULL) == NM_PLATFORM_ERROR_SUCCESS);
	accept_signal (link_added);

	/* Try to add again */
	g_assert (nm_platform_link_dummy_add (NM_PLATFORM_GET, DEVICE_NAME, NULL) == NM_PLATFORM_ERROR_EXISTS);

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
	g_assert (nm_platform_link_set_address (NM_PLATFORM_GET, ifindex, mac, sizeof (mac)) == NM_PLATFORM_ERROR_SUCCESS);
	address = nm_platform_link_get_address (NM_PLATFORM_GET, ifindex, &addrlen);
	g_assert (addrlen == sizeof(mac));
	g_assert (!memcmp (address, mac, addrlen));
	address = nm_platform_link_get_address (NM_PLATFORM_GET, ifindex, NULL);
	g_assert (!memcmp (address, mac, addrlen));
	accept_signal (link_changed);

	/* Set MTU */
	g_assert (nm_platform_link_set_mtu (NM_PLATFORM_GET, ifindex, MTU) == NM_PLATFORM_ERROR_SUCCESS);
	g_assert_cmpint (nm_platform_link_get_mtu (NM_PLATFORM_GET, ifindex), ==, MTU);
	accept_signal (link_changed);

	/* Delete device */
	nmtstp_link_del (NULL, -1, ifindex, DEVICE_NAME);
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
	gboolean external_command;
} TestAddSoftwareDetectData;

static void
test_software_detect (gconstpointer user_data)
{
	const TestAddSoftwareDetectData *test_data = user_data;
	int ifindex, ifindex_parent;
	const NMPlatformLink *plink;
	const NMPObject *lnk;
	guint i_step;
	const gboolean ext = test_data->external_command;

	nmtstp_run_command_check ("ip link add %s type dummy", PARENT_NAME);
	ifindex_parent = nmtstp_assert_wait_for_link (NM_PLATFORM_GET, PARENT_NAME, NM_LINK_TYPE_DUMMY, 100)->ifindex;

	switch (test_data->link_type) {
	case NM_LINK_TYPE_GRE: {
		NMPlatformLnkGre lnk_gre = { };
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

		lnk_ip6tnl.local = *nmtst_inet6_from_string ("fd01::15");
		lnk_ip6tnl.remote = *nmtst_inet6_from_string ("fd01::16");
		lnk_ip6tnl.parent_ifindex = ifindex_parent;
		lnk_ip6tnl.tclass = 20;
		lnk_ip6tnl.encap_limit = 6;
		lnk_ip6tnl.flow_label = 1337;
		lnk_ip6tnl.proto = IPPROTO_IPV6;

		if (!nmtstp_link_ip6tnl_add (NULL, ext, DEVICE_NAME, &lnk_ip6tnl)) {
			if (gracefully_skip) {
				g_test_skip ("Cannot create ip6tnl tunnel because of missing ip6_tunnel module (modprobe ip6_tunnel)");
				goto out_delete_parent;
			}
			g_error ("Failed adding IP6TNL tunnel");
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
			nmtstp_link_del (NM_PLATFORM_GET, FALSE, dummy->ifindex, NULL);
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
		g_assert (lnk);

		switch (test_data->link_type) {
		case NM_LINK_TYPE_GRE: {
			const NMPlatformLnkGre *plnk = &lnk->lnk_gre;

			g_assert (plnk == nm_platform_link_get_lnk_gre (NM_PLATFORM_GET, ifindex, NULL));
			g_assert_cmpint (plnk->parent_ifindex, ==, ifindex_parent);
			g_assert_cmpint (plnk->input_flags, ==, 0);
			g_assert_cmpint (plnk->output_flags, ==, 0);
			g_assert_cmpint (plnk->input_key, ==, 0);
			g_assert_cmpint (plnk->output_key, ==, 0);
			nmtst_assert_ip4_address (plnk->local, "192.168.233.204");
			nmtst_assert_ip4_address (plnk->remote, "172.168.10.25");
			g_assert_cmpint (plnk->ttl, ==, 174);
			g_assert_cmpint (plnk->tos, ==, 37);
			g_assert_cmpint (plnk->path_mtu_discovery, ==, TRUE);
			break;
		}
		case NM_LINK_TYPE_IP6TNL: {
			const NMPlatformLnkIp6Tnl *plnk = &lnk->lnk_ip6tnl;

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
					/* on some kernels, omiting the port range results in setting
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
		default:
			g_assert_not_reached ();
		}
	}

	nmtstp_link_del (NULL, -1, ifindex, DEVICE_NAME);
out_delete_parent:
	nmtstp_link_del (NULL, -1, ifindex_parent, PARENT_NAME);
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

	nmtstp_link_del (NULL, -1, ifindex, DEVICE_NAME);
	nmtstp_link_del (NULL, -1, ifindex_parent, PARENT_NAME);
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
	const gint EX = ((int) (nmtst_get_rand_int () % 4)) - 1;

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
			nmtstp_link_del (NULL, EX, g_array_index (ifindexes, int, i), name);
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
	nmtstp_link_del (NULL, -1, ifindex_veth0, IFACE_VETH0);
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
	nmtstp_link_del (NULL, -1, ifindex_dummy0, IFACE_DUMMY0);
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

	nmtstp_link_del (NULL, -1, ifindex_bridge0, IFACE_BRIDGE0);
	nmtstp_link_del (NULL, -1, ifindex_dummy0, IFACE_DUMMY0);
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
		_LOGD ("setns() failed with \"%s\". This indicates missing support (valgrind?)", g_strerror (support_errsv));
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

		for (i = 0, j = nmtst_get_rand_int () % 5; i < j; i++)
			_ADD_DUMMY (p, nm_sprintf_buf (sbuf, "other-a-%s-%02d", id, i));

		_ADD_DUMMY (p, "dummy1_");

		for (i = 0, j = nmtst_get_rand_int () % 5; i < j; i++)
			_ADD_DUMMY (p, nm_sprintf_buf (sbuf, "other-b-%s-%02d", id, i));

		_ADD_DUMMY (p, nm_sprintf_buf (sbuf, "dummy2%s", id));

		for (i = 0, j = nmtst_get_rand_int () % 5; i < j; i++)
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

		j = nmtst_get_rand_int () % 2;

		if (nmtst_get_rand_int () % 2) {
			pl = platform_1;
			if (nmtst_get_rand_int () % 2)
				path = "/proc/sys/net/ipv6/conf/dummy1_/disable_ipv6";
			else
				path = "/proc/sys/net/ipv6/conf/dummy2a/disable_ipv6";
		} else {
			pl = platform_2;
			if (nmtst_get_rand_int () % 2)
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
	i = nmtst_get_rand_int () % (G_N_ELEMENTS (pl) + 1);
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

		pl[i].sysctl_value = nmtst_get_rand_int () % 2 ? "1" : "0";

		_ADD_DUMMY (pl[i].platform, pl[i].device_name);

		g_assert (nm_platform_sysctl_set (pl[i].platform, NMP_SYSCTL_PATHID_ABSOLUTE (pl[i].sysctl_path), pl[i].sysctl_value));

		tmp = _get_current_namespace_id (CLONE_NEWNET);
		g_ptr_array_add (device_names, tmp);
		pl[i].ns_net = tmp;

		tmp = _get_current_namespace_id (CLONE_NEWNS);
		g_ptr_array_add (device_names, tmp);
		pl[i].ns_mnt = tmp;
	}

	nstack = nmtst_get_rand_int () % (G_N_ELEMENTS (stack) + 1);
	for (i = 0; i < nstack; i++) {
		stack[i].pl = &pl[nmtst_get_rand_int () % G_N_ELEMENTS (pl)];
		stack[i].ns_types = ns_types_list[nmtst_get_rand_int () % G_N_ELEMENTS (ns_types_list)];

		nmp_netns_push_type (nm_platform_netns_get (stack[i].pl->platform), stack[i].ns_types);
	}

	/* pop some again. */
	for (i = nmtst_get_rand_int () % (nstack + 1); i > 0; i--) {
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
			if (NM_FLAGS_HAS (stack[j].ns_types, ns_type)) {
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
#define P_VAR_RUN                "/var/run"
#define P_VAR_RUN_NETNS          "/var/run/netns"
#define P_VAR_RUN_NETNS_BINDNAME "/var/run/netns/"P_NETNS_BINDNAME
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

	i = (nmtst_get_rand_int () % 2) + 1;
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

	s = (nmtst_get_rand_int () % 2) ? NULL : ifname_buf;

	if (nmtst_get_rand_int () % 2) {
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
	i = nmtst_get_rand_int () % (2 + G_N_ELEMENTS (IFNAME));
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
	switch (nmtst_get_rand_int () % 4) {
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
	if (nmtst_get_rand_int () % 2)
		nm_platform_process_events (PL);

	/* check that we still read the same file. */
	switch (nmtst_get_rand_int () % 2) {
	case 0: {
		gs_free char *c = NULL;

		if (nm_utils_file_get_contents (dirfd, "ifindex", 1*1024*1024, &c, NULL, NULL) < 0)
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
	nmtstp_link_del (PL, -1, ifindex[0], NULL);
	nmtstp_link_del (PL, -1, ifindex[1], NULL);
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
	PL = platforms[nmtst_get_rand_int () % 3];

	nmtstp_netns_select_random (platforms, G_N_ELEMENTS (platforms), &netns_pop_1);

	ifindex = nmtstp_link_dummy_add (PL, FALSE, IFNAME)->ifindex;

	nmtstp_netns_select_random (platforms, G_N_ELEMENTS (platforms), &netns_pop_2);

	s = (nmtst_get_rand_int () % 2) ? NULL : ifname_buf;
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

		if (nm_utils_file_get_contents (dirfd, "ifindex", 0, &c, NULL, NULL) < 0)
			g_assert_not_reached();
		g_assert_cmpint (ifindex, ==, (int) _nm_utils_ascii_str_to_int64 (c, 10, 0, G_MAXINT, -1));
	}
	g_assert_cmpint (ifindex, ==, (gint32) nm_platform_sysctl_get_int32 (PL, NMP_SYSCTL_PATHID_NETDIR (dirfd, s ?: "<unknown>", "ifindex"), -1));
	g_assert_cmpint (ifindex, ==, (gint32) nm_platform_sysctl_get_int32 (PL, NMP_SYSCTL_PATHID_ABSOLUTE (nm_sprintf_bufa (100, "/sys/class/net/%s/ifindex", IFNAME)), -1));

	/* accessing the path directly, only succeeds iff the current namespace happens to be the namespace
	 * in which we created the link. */
	{
		gs_free char *c = NULL;

		if (nm_utils_file_get_contents (-1, nm_sprintf_bufa (100, "/sys/class/net/%s/ifindex", IFNAME), 0, &c, NULL, NULL) < 0)
			ifindex_tmp = -1;
		else
			ifindex_tmp = _nm_utils_ascii_str_to_int64 (c, 10, 0, G_MAXINT, -2);
	}
	if (nmp_netns_get_current () == nm_platform_netns_get (PL))
		g_assert_cmpint (ifindex_tmp, ==, ifindex);
	else
		g_assert_cmpint (ifindex_tmp, ==, -1);

	nmtstp_link_del (PL, FALSE, ifindex, NULL);
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
		test_software_detect_add ("/link/software/detect/ip6tnl", NM_LINK_TYPE_IP6TNL, 0);
		test_software_detect_add ("/link/software/detect/ipip", NM_LINK_TYPE_IPIP, 0);
		test_software_detect_add ("/link/software/detect/macvlan", NM_LINK_TYPE_MACVLAN, 0);
		test_software_detect_add ("/link/software/detect/macvtap", NM_LINK_TYPE_MACVTAP, 0);
		test_software_detect_add ("/link/software/detect/sit", NM_LINK_TYPE_SIT, 0);
		test_software_detect_add ("/link/software/detect/vlan", NM_LINK_TYPE_VLAN, 0);
		test_software_detect_add ("/link/software/detect/vxlan/0", NM_LINK_TYPE_VXLAN, 0);
		test_software_detect_add ("/link/software/detect/vxlan/1", NM_LINK_TYPE_VXLAN, 1);

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

		g_test_add_func ("/general/sysctl/rename", test_sysctl_rename);
		g_test_add_func ("/general/sysctl/netns-switch", test_sysctl_netns_switch);
	}
}
