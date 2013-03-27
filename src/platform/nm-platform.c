/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-platform.c - Handle runtime kernel networking configuration
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2012 Red Hat, Inc.
 */

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "nm-platform.h"
#include "nm-logging.h"

#define debug(...) nm_log_dbg (LOGD_PLATFORM, __VA_ARGS__)

#define NM_PLATFORM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_PLATFORM, NMPlatformPrivate))

G_DEFINE_TYPE (NMPlatform, nm_platform, G_TYPE_OBJECT)

/* NMPlatform signals */
enum {
	LINK_ADDED,
	LINK_CHANGED,
	LINK_REMOVED,
	IP4_ADDRESS_ADDED,
	IP4_ADDRESS_CHANGED,
	IP4_ADDRESS_REMOVED,
	IP6_ADDRESS_ADDED,
	IP6_ADDRESS_CHANGED,
	IP6_ADDRESS_REMOVED,
	IP4_ROUTE_ADDED,
	IP4_ROUTE_CHANGED,
	IP4_ROUTE_REMOVED,
	IP6_ROUTE_ADDED,
	IP6_ROUTE_CHANGED,
	IP6_ROUTE_REMOVED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/******************************************************************/

/* Singleton NMPlatform subclass instance and cached class object */
static NMPlatform *platform = NULL;
static NMPlatformClass *klass = NULL;

/**
 * nm_platform_setup:
 * @type: The #GType for a subclass of #NMPlatform
 *
 * Do not use this function directly, it is intended to be called by
 * NMPlatform subclasses. For the linux platform initialization use
 * nm_linux_platform_setup() instead.
 *
 * Failing to set up #NMPlatform singleton results in a fatal error,
 * as well as trying to initialize it multiple times without freeing
 * it.
 *
 * NetworkManager will typically use only one platform object during
 * its run. Test programs might want to switch platform implementations,
 * though. This is done with a combination of nm_platform_free() and
 * nm_*_platform_setup().
 */
void
nm_platform_setup (GType type)
{
	gboolean status;

	g_assert (platform == NULL);

	platform = g_object_new (type, NULL);
	g_assert (NM_IS_PLATFORM (platform));

	klass = NM_PLATFORM_GET_CLASS (platform);
	g_assert (klass->setup);

	status = klass->setup (platform);
	g_assert (status);
}

/**
 * nm_platform_free:
 *
 * Free #NMPlatform singleton created by nm_*_platform_setup().
 */
void
nm_platform_free (void)
{
	g_assert (platform);

	g_object_unref (platform);
	platform = NULL;
}

/**
 * nm_platform_get:
 *
 * Retrieve #NMPlatform singleton. Use this whenever you want to connect to
 * #NMPlatform signals. It is an error to call it before nm_*_platform_setup()
 * or after nm_platform_free().
 *
 * Returns: (transfer none): The #NMPlatform singleton reference.
 */
NMPlatform *
nm_platform_get (void)
{
	g_assert (platform);

	return platform;
}

/******************************************************************/

/**
 * nm_platform_set_error:
 * @error: The error code
 *
 * Convenience function to falsify platform->error. It can be used for example
 * by functions that want to save the error, execute some operations and
 * restore it.
 */
void nm_platform_set_error (NMPlatformError error)
{
	platform->error = error;
}

/**
 * nm_platform_get_error:
 *
 * Convenience function to quickly retrieve the error code of the last
 * operation.
 *
 * Returns: Integer error code.
 */
NMPlatformError
nm_platform_get_error (void)
{
	g_assert (platform);

	return platform->error;
}

/**
 * nm_platform_get_error_message:
 *
 * Returns: Static human-readable string for the error. Don't free.
 */
const char *
nm_platform_get_error_msg (void)
{
	g_assert (platform);

	switch (platform->error) {
	case NM_PLATFORM_ERROR_NONE:
		return "unknown error";
	case NM_PLATFORM_ERROR_NOT_FOUND:
		return "object not found";
	case NM_PLATFORM_ERROR_EXISTS:
		return "object already exists";
	default:
		return "invalid error number";
	}
}

static void
reset_error (void)
{
	g_assert (platform);
	platform->error = NM_PLATFORM_ERROR_NONE;
}

/******************************************************************/

/**
 * nm_platform_sysctl_set:
 * @path: Absolute option path
 * @value: Value to write
 *
 * This function is intended to be used for writing values to sysctl-style
 * virtual runtime configuration files. This includes not only /proc/sys
 * but also for example /sys/class.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_sysctl_set (const char *path, const char *value)
{
	reset_error ();

	g_return_val_if_fail (path, FALSE);
	g_return_val_if_fail (value, FALSE);
	g_return_val_if_fail (klass->sysctl_set, FALSE);

	/* Don't write outside known locations */
	g_assert (g_str_has_prefix (path, "/proc/sys")
			|| g_str_has_prefix (path, "/sys"));
	/* Don't write to suspicious locations */
	g_assert (!strstr (path, ".."));

	return klass->sysctl_set (platform, path, value);
}

/**
 * nm_platform_sysctl_get:
 * @path: Absolute path to sysctl
 *
 * Returns: (transfer full): Contents of the virtual sysctl file.
 */
char *
nm_platform_sysctl_get (const char *path)
{
	reset_error ();

	g_return_val_if_fail (path, NULL);
	g_return_val_if_fail (klass->sysctl_get, NULL);

	return klass->sysctl_get (platform, path);
}

/******************************************************************/

/**
 * nm_platform_link_get_all:
 *
 * Retrieve a snapshot of configuration for all links at once. The result is
 * owned by the caller and should be freed with g_array_unref().
 */
GArray *
nm_platform_link_get_all ()
{
	reset_error ();

	g_return_val_if_fail (klass->link_get_all, NULL);

	return klass->link_get_all (platform);
}

/**
 * nm_platform_link_add:
 * @name: Interface name
 * @type: Interface type
 *
 * Add a software interface. Sets platform->error to NM_PLATFORM_ERROR_EXISTS
 * if interface is already already exists.
 */
static gboolean
nm_platform_link_add (const char *name, NMLinkType type)
{
	reset_error ();

	g_return_val_if_fail (name, FALSE);
	g_return_val_if_fail (klass->link_add, FALSE);

	if (nm_platform_link_exists (name)) {
		debug ("link: already exists");
		platform->error = NM_PLATFORM_ERROR_EXISTS;
		return FALSE;
	}

	return klass->link_add (platform, name, type);
}

/**
 * nm_platform_dummy_add:
 * @name: New interface name
 *
 * Create a software ethernet-like interface
 */
gboolean
nm_platform_dummy_add (const char *name)
{
	g_return_val_if_fail (name, FALSE);

	debug ("link: adding dummy '%s'", name);
	return nm_platform_link_add (name, NM_LINK_TYPE_DUMMY);
}

/**
 * nm_platform_link_exists:
 * @name: Interface name
 *
 * Returns: %TRUE if an interface of this name exists, %FALSE otherwise.
 */
gboolean
nm_platform_link_exists (const char *name)
{
	int ifindex = nm_platform_link_get_ifindex (name);

	reset_error();
	return ifindex > 0;
}

/**
 * nm_platform_link_delete:
 * @ifindex: Interface index
 *
 * Delete a software interface. Sets platform->error to
 * NM_PLATFORM_ERROR_NOT_FOUND if ifindex not available.
 */
gboolean
nm_platform_link_delete (int ifindex)
{
	const char *name;

	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (klass->link_delete, FALSE);

	name = nm_platform_link_get_name (ifindex);

	if (!name)
		return FALSE;

	debug ("link: deleting '%s' (%d)", name, ifindex);
	return klass->link_delete (platform, ifindex);
}

/**
 * nm_platform_link_delete_by_name:
 * @name: Interface name
 *
 * Delete a software interface.
 */
gboolean
nm_platform_link_delete_by_name (const char *name)
{
	int ifindex = nm_platform_link_get_ifindex (name);

	if (!ifindex)
		return FALSE;

	return nm_platform_link_delete (ifindex);
}

/**
 * nm_platform_link_get_index:
 * @name: Interface name
 *
 * Returns: The interface index corresponding to the given interface name
 * or 0. Inteface name is owned by #NMPlatform, don't free it.
 */
int
nm_platform_link_get_ifindex (const char *name)
{
	int ifindex;

	reset_error ();

	g_return_val_if_fail (name, 0);
	g_return_val_if_fail (klass->link_get_ifindex, 0);

	ifindex = klass->link_get_ifindex (platform, name);

	if (!ifindex) {
		debug ("link not found: %s", name);
		platform->error = NM_PLATFORM_ERROR_NOT_FOUND;
	}

	return ifindex;
}

/**
 * nm_platform_link_get_name:
 * @name: Interface name
 *
 * Returns: The interface name corresponding to the given interface index
 * or %NULL.
 */
const char *
nm_platform_link_get_name (int ifindex)
{
	const char *name;

	reset_error ();

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (klass->link_get_name, NULL);

	name = klass->link_get_name (platform, ifindex);

	if (!name) {
		debug ("link not found: %d", ifindex);
		platform->error = NM_PLATFORM_ERROR_NOT_FOUND;
		return FALSE;
	}

	return name;
}

/**
 * nm_platform_link_get_type:
 * @ifindex: Interface index.
 *
 * Returns: Link type constant as defined in nm-platform.h. On error,
 * NM_LINK_TYPE_NONE is returned.
 */
NMLinkType
nm_platform_link_get_type (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (klass->link_get_type, NM_LINK_TYPE_NONE);

	return klass->link_get_type (platform, ifindex);
}

/**
 * nm_platform_link_get_type_name:
 * @ifindex: Interface index.
 *
 * Returns: A string describing the type of link. In some cases this
 * may be more specific than nm_platform_link_get_type(), but in
 * other cases it may not. On error, %NULL is returned.
 */
const char *
nm_platform_link_get_type_name (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (klass->link_get_type_name, NULL);

	return klass->link_get_type_name (platform, ifindex);
}


/**
 * nm_platform_link_is_up:
 * @ifindex: Interface index
 *
 * Check if the interface is up.
 */
gboolean
nm_platform_link_is_up (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_is_up, FALSE);

	return klass->link_is_up (platform, ifindex);
}

/**
 * nm_platform_link_is_connected:
 * @ifindex: Interface index
 *
 * Check if the interface is connected.
 */
gboolean
nm_platform_link_is_connected (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_is_connected, FALSE);

	return klass->link_is_connected (platform, ifindex);
}

/**
 * nm_platform_link_uses_arp:
 * @ifindex: Interface index
 *
 * Check if the interface is configured to use ARP.
 */
gboolean
nm_platform_link_uses_arp (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_uses_arp, FALSE);

	return klass->link_uses_arp (platform, ifindex);
}

/**
 * nm_platform_link_set_address:
 * @ifindex: Interface index
 * @address: The new MAC address
 *
 * Set interface MAC address.
 */
gboolean
nm_platform_link_set_address (int ifindex, gconstpointer address, size_t length)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (address, FALSE);
	g_return_val_if_fail (length > 0, FALSE);
	g_return_val_if_fail (klass->link_set_address, FALSE);

	debug ("link: setting '%s' (%d) hardware address", nm_platform_link_get_name (ifindex), ifindex);
	return klass->link_set_address (platform, ifindex, address, length);
}

/**
 * nm_platform_link_get_address:
 * @ifindex: Interface index
 * @length: Pointer to a variable to store address length
 *
 * Saves interface hardware address to @address.
 */
gconstpointer
nm_platform_link_get_address (int ifindex, size_t *length)
{
	reset_error ();

	if (length)
		*length = 0;

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (klass->link_get_address, NULL);

	return klass->link_get_address (platform, ifindex, length);
}

gboolean
nm_platform_link_supports_carrier_detect (int ifindex)
{
	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_supports_carrier_detect, FALSE);

	return klass->link_supports_carrier_detect (platform, ifindex);
}

gboolean
nm_platform_link_supports_vlans (int ifindex)
{
	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_supports_vlans, FALSE);

	return klass->link_supports_vlans (platform, ifindex);
}

/**
 * nm_platform_link_set_up:
 * @ifindex: Interface index
 *
 * Bring the interface up.
 */
gboolean
nm_platform_link_set_up (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (klass->link_set_up, FALSE);

	debug ("link: setting up '%s' (%d)", nm_platform_link_get_name (ifindex), ifindex);
	return klass->link_set_up (platform, ifindex);
}

/**
 * nm_platform_link_set_down:
 * @ifindex: Interface index
 *
 * Take the interface down.
 */
gboolean
nm_platform_link_set_down (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (klass->link_set_down, FALSE);

	debug ("link: setting down '%s' (%d)", nm_platform_link_get_name (ifindex), ifindex);
	return klass->link_set_down (platform, ifindex);
}

/**
 * nm_platform_link_set_arp:
 * @ifindex: Interface index
 *
 * Enable ARP on the interface.
 */
gboolean
nm_platform_link_set_arp (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_set_arp, FALSE);

	debug ("link: setting arp '%s' (%d)", nm_platform_link_get_name (ifindex), ifindex);
	return klass->link_set_arp (platform, ifindex);
}

/**
 * nm_platform_link_set_noarp:
 * @ifindex: Interface index
 *
 * Disable ARP on the interface.
 */
gboolean
nm_platform_link_set_noarp (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_set_noarp, FALSE);

	debug ("link: setting noarp '%s' (%d)", nm_platform_link_get_name (ifindex), ifindex);
	return klass->link_set_noarp (platform, ifindex);
}

/**
 * nm_platform_link_enslave:
 * @master: Interface index of the master
 * @slave: Interface index of the slave
 *
 * Enslave @slave to @master.
 */
gboolean
nm_platform_link_enslave (int master, int slave)
{
	reset_error ();

	g_assert (platform);
	g_return_val_if_fail (master > 0, FALSE);
	g_return_val_if_fail (slave> 0, FALSE);
	g_return_val_if_fail (klass->link_enslave, FALSE);

	debug ("link: enslaving '%s' (%d) to master '%s' (%d)",
		nm_platform_link_get_name (slave), slave,
		nm_platform_link_get_name (master), master);
	return klass->link_enslave (platform, master, slave);
}

/**
 * nm_platform_link_release:
 * @master: Interface index of the master
 * @slave: Interface index of the slave
 *
 * Release @slave from @master.
 */
gboolean
nm_platform_link_release (int master, int slave)
{
	reset_error ();

	g_assert (platform);
	g_return_val_if_fail (master > 0, FALSE);
	g_return_val_if_fail (slave > 0, FALSE);
	g_return_val_if_fail (klass->link_release, FALSE);

	if (nm_platform_link_get_master (slave) != master) {
		platform->error = NM_PLATFORM_ERROR_NOT_SLAVE;
		return FALSE;
	}

	debug ("link: releasing '%s' (%d) from master '%s' (%d)",
		nm_platform_link_get_name (slave), slave,
		nm_platform_link_get_name (master), master);
	return klass->link_release (platform, master, slave);
}

/**
 * nm_platform_link_get_master:
 * @slave: Interface index of the slave.
 *
 * Returns: Interfase index of the slave's master.
 */
int
nm_platform_link_get_master (int slave)
{
	reset_error ();

	g_assert (platform);
	g_return_val_if_fail (slave >= 0, FALSE);
	g_return_val_if_fail (klass->link_get_master, FALSE);

	if (!nm_platform_link_get_name (slave)) {
		platform->error = NM_PLATFORM_ERROR_NOT_FOUND;
		return 0;
	}
	return klass->link_get_master (platform, slave);
}

/**
 * nm_platform_bridge_add:
 * @name: New interface name
 *
 * Create a virtual bridge.
 */
gboolean
nm_platform_bridge_add (const char *name)
{
	debug ("link: adding bridge '%s'", name);
	return nm_platform_link_add (name, NM_LINK_TYPE_BRIDGE);
}

/**
 * nm_platform_bond_add:
 * @name: New interface name
 *
 * Create a virtual bonding device.
 */
gboolean
nm_platform_bond_add (const char *name)
{
	debug ("link: adding bond '%s'", name);
	return nm_platform_link_add (name, NM_LINK_TYPE_BOND);
}

/**
 * nm_platform_team_add:
 * @name: New interface name
 *
 * Create a virtual teaming device.
 */
gboolean
nm_platform_team_add (const char *name)
{
	debug ("link: adding team '%s'", name);
	return nm_platform_link_add (name, NM_LINK_TYPE_TEAM);
}

/**
 * nm_platform_vlan_add:
 * @name: New interface name
 * @vlanid: VLAN identifier
 * @vlanflags: VLAN flags from libnm-util
 *
 * Create a software VLAN device.
 */
gboolean
nm_platform_vlan_add (const char *name, int parent, int vlanid, guint32 vlanflags)
{
	reset_error ();

	g_assert (platform);
	g_return_val_if_fail (parent >= 0, FALSE);
	g_return_val_if_fail (vlanid >= 0, FALSE);
	g_return_val_if_fail (name, FALSE);
	g_return_val_if_fail (klass->vlan_add, FALSE);

	if (nm_platform_link_exists (name)) {
		debug ("link already exists: %s", name);
		platform->error = NM_PLATFORM_ERROR_EXISTS;
		return FALSE;
	}

	debug ("link: adding vlan '%s' parent %d vlanid %d vlanflags %x",
		name, parent, vlanid, vlanflags);
	return klass->vlan_add (platform, name, parent, vlanid, vlanflags);
}

gboolean
nm_platform_master_set_option (int ifindex, const char *option, const char *value)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);
	g_return_val_if_fail (value, FALSE);
	g_return_val_if_fail (klass->master_set_option, FALSE);

	return klass->master_set_option (platform, ifindex, option, value);
}

char *
nm_platform_master_get_option (int ifindex, const char *option)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);
	g_return_val_if_fail (klass->master_set_option, FALSE);

	return klass->master_get_option (platform, ifindex, option);
}

gboolean
nm_platform_slave_set_option (int ifindex, const char *option, const char *value)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);
	g_return_val_if_fail (value, FALSE);
	g_return_val_if_fail (klass->slave_set_option, FALSE);

	return klass->slave_set_option (platform, ifindex, option, value);
}

char *
nm_platform_slave_get_option (int ifindex, const char *option)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);
	g_return_val_if_fail (klass->slave_set_option, FALSE);

	return klass->slave_get_option (platform, ifindex, option);
}

gboolean
nm_platform_vlan_get_info (int ifindex, int *parent, int *vlanid)
{
	reset_error ();

	g_assert (platform);
	g_return_val_if_fail (klass->vlan_get_info, FALSE);

	if (parent)
		*parent = 0;
	if (vlanid)
		*vlanid = 0;

	if (nm_platform_link_get_type (ifindex) != NM_LINK_TYPE_VLAN)
		return FALSE;

	return klass->vlan_get_info (platform, ifindex, parent, vlanid);
}

gboolean
nm_platform_vlan_set_ingress_map (int ifindex, int from, int to)
{
	reset_error ();

	g_assert (platform);
	g_return_val_if_fail (klass->vlan_set_ingress_map, FALSE);

	debug ("link: setting vlan ingress map for %d from %d to %d", ifindex, from, to);
	return klass->vlan_set_ingress_map (platform, ifindex, from, to);
}

gboolean
nm_platform_vlan_set_egress_map (int ifindex, int from, int to)
{
	reset_error ();

	g_assert (platform);
	g_return_val_if_fail (klass->vlan_set_egress_map, FALSE);

	debug ("link: setting vlan egress map for %d from %d to %d", ifindex, from, to);
	return klass->vlan_set_egress_map (platform, ifindex, from, to);
}

/******************************************************************/

GArray *
nm_platform_ip4_address_get_all (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (klass->ip4_address_get_all, NULL);

	return klass->ip4_address_get_all (platform, ifindex);
}

GArray *
nm_platform_ip6_address_get_all (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (klass->ip6_address_get_all, NULL);

	return klass->ip6_address_get_all (platform, ifindex);
}

gboolean
nm_platform_ip4_address_add (int ifindex, in_addr_t address, int plen)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (klass->ip4_address_add, FALSE);

	if (nm_platform_ip4_address_exists (ifindex, address, plen)) {
		debug ("address already exists");
		platform->error = NM_PLATFORM_ERROR_EXISTS;
		return FALSE;
	}

	debug ("address: adding IPv4 address");
	return klass->ip4_address_add (platform, ifindex, address, plen);
}

gboolean
nm_platform_ip6_address_add (int ifindex, struct in6_addr address, int plen)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (klass->ip6_address_add, FALSE);

	if (nm_platform_ip6_address_exists (ifindex, address, plen)) {
		debug ("address already exists");
		platform->error = NM_PLATFORM_ERROR_EXISTS;
		return FALSE;
	}

	debug ("address: adding IPv6 address");
	return klass->ip6_address_add (platform, ifindex, address, plen);
}

gboolean
nm_platform_ip4_address_delete (int ifindex, in_addr_t address, int plen)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (klass->ip4_address_delete, FALSE);

	if (!nm_platform_ip4_address_exists (ifindex, address, plen)) {
		debug ("address doesn't exists");
		platform->error = NM_PLATFORM_ERROR_NOT_FOUND;
		return FALSE;
	}

	debug ("address: deleting IPv4 address");
	return klass->ip4_address_delete (platform, ifindex, address, plen);
}

gboolean
nm_platform_ip6_address_delete (int ifindex, struct in6_addr address, int plen)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (klass->ip6_address_delete, FALSE);

	if (!nm_platform_ip6_address_exists (ifindex, address, plen)) {
		debug ("address doesn't exists");
		platform->error = NM_PLATFORM_ERROR_NOT_FOUND;
		return FALSE;
	}

	debug ("address: deleting IPv6 address");
	return klass->ip6_address_delete (platform, ifindex, address, plen);
}

gboolean
nm_platform_ip4_address_exists (int ifindex, in_addr_t address, int plen)
{
	reset_error ();

	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (klass->ip4_address_exists, FALSE);

	return klass->ip4_address_exists (platform, ifindex, address, plen);
}

gboolean
nm_platform_ip6_address_exists (int ifindex, struct in6_addr address, int plen)
{
	reset_error ();

	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (klass->ip6_address_exists, FALSE);

	return klass->ip6_address_exists (platform, ifindex, address, plen);
}

GArray *
nm_platform_ip4_route_get_all (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (klass->ip4_route_get_all, NULL);

	return klass->ip4_route_get_all (platform, ifindex);
}

GArray *
nm_platform_ip6_route_get_all (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (klass->ip6_route_get_all, NULL);

	return klass->ip6_route_get_all (platform, ifindex);
}

gboolean
nm_platform_ip4_route_add (int ifindex,
		in_addr_t network, int plen,
		in_addr_t gateway, int metric, int mss)
{
	reset_error ();

	g_return_val_if_fail (platform, FALSE);
	g_return_val_if_fail (0 <= plen && plen <= 32, FALSE);
	g_return_val_if_fail (metric >= 0, FALSE);
	g_return_val_if_fail (mss >= 0, FALSE);
	g_return_val_if_fail (klass->ip4_route_add, FALSE);

	if (nm_platform_ip4_route_exists (ifindex, network, plen, metric)) {
		debug ("route already exists");
		platform->error = NM_PLATFORM_ERROR_EXISTS;
		return FALSE;
	}

	return klass->ip4_route_add (platform, ifindex, network, plen, gateway, metric, mss);
}

gboolean
nm_platform_ip6_route_add (int ifindex,
		struct in6_addr network, int plen, struct in6_addr gateway, int metric, int mss)
{
	g_return_val_if_fail (platform, FALSE);
	g_return_val_if_fail (0 <= plen && plen <= 128, FALSE);
	g_return_val_if_fail (metric >= 0, FALSE);
	g_return_val_if_fail (mss >= 0, FALSE);
	g_return_val_if_fail (klass->ip6_route_add, FALSE);

	if (nm_platform_ip6_route_exists (ifindex, network, plen, metric)) {
		debug ("route already exists");
		platform->error = NM_PLATFORM_ERROR_EXISTS;
		return FALSE;
	}

	return klass->ip6_route_add (platform, ifindex, network, plen, gateway, metric, mss);
}

gboolean
nm_platform_ip4_route_delete (int ifindex, in_addr_t network, int plen, int metric)
{
	reset_error ();

	g_return_val_if_fail (platform, FALSE);
	g_return_val_if_fail (klass->ip4_route_delete, FALSE);

	if (!nm_platform_ip4_route_exists (ifindex, network, plen, metric)) {
		debug ("route not found");
		platform->error = NM_PLATFORM_ERROR_NOT_FOUND;
		return FALSE;
	}

	return klass->ip4_route_delete (platform, ifindex, network, plen, metric);
}

gboolean
nm_platform_ip6_route_delete (int ifindex,
		struct in6_addr network, int plen, int metric)
{
	reset_error ();

	g_return_val_if_fail (platform, FALSE);
	g_return_val_if_fail (klass->ip6_route_delete, FALSE);

	if (!nm_platform_ip6_route_exists (ifindex, network, plen, metric)) {
		debug ("route not found");
		platform->error = NM_PLATFORM_ERROR_NOT_FOUND;
		return FALSE;
	}

	return klass->ip6_route_delete (platform, ifindex, network, plen, metric);
}

gboolean
nm_platform_ip4_route_exists (int ifindex, in_addr_t network, int plen, int metric)
{
	reset_error ();

	g_return_val_if_fail (platform, FALSE);
	g_return_val_if_fail (klass->ip4_route_exists, FALSE);

	return klass->ip4_route_exists (platform,ifindex, network, plen, metric);
}

gboolean
nm_platform_ip6_route_exists (int ifindex, struct in6_addr network, int plen, int metric)
{
	reset_error ();

	g_return_val_if_fail (platform, FALSE);
	g_return_val_if_fail (klass->ip6_route_exists, FALSE);

	return klass->ip6_route_exists (platform, ifindex, network, plen, metric);
}

/******************************************************************/

static void
log_link_added (NMPlatform *p, int ifindex, NMPlatformLink *info, gpointer user_data)
{
	debug ("signal: link address: '%s' (%d)", info->name, ifindex);
}

static void
log_link_changed (NMPlatform *p, int ifindex, NMPlatformLink *info, gpointer user_data)
{
	debug ("signal: link changed: '%s' (%d)", info->name, ifindex);
}

static void
log_link_removed (NMPlatform *p, int ifindex, NMPlatformLink *info, gpointer user_data)
{
	debug ("signal: link removed: '%s' (%d)", info->name, ifindex);
}

static void
log_ip4_address (NMPlatformIP4Address *address, const char *change_type)
{
	char addr[INET_ADDRSTRLEN];
	int plen = address->plen;
	const char *name = nm_platform_link_get_name (address->ifindex);

	inet_ntop (AF_INET, &address->address, addr, sizeof (addr));

	debug ("signal: address %s: %s/%d dev %s", change_type, addr, plen, name);
}

static void
log_ip4_address_added (NMPlatform *p, int ifindex, NMPlatformIP4Address *address, gpointer user_data)
{
	log_ip4_address (address, "added");
}

static void
log_ip4_address_changed (NMPlatform *p, int ifindex, NMPlatformIP4Address *address, gpointer user_data)
{
	log_ip4_address (address, "changed");
}

static void
log_ip4_address_removed (NMPlatform *p, int ifindex, NMPlatformIP4Address *address, gpointer user_data)
{
	log_ip4_address (address, "removed");
}

static void
log_ip6_address (NMPlatformIP6Address *address, const char *change_type)
{
	char addr[INET6_ADDRSTRLEN];
	int plen = address->plen;
	const char *name = nm_platform_link_get_name (address->ifindex);

	inet_ntop (AF_INET6, &address->address, addr, sizeof (addr));

	debug ("signal: address %s: %s/%d dev %s", change_type, addr, plen, name);
}

static void
log_ip6_address_added (NMPlatform *p, int ifindex, NMPlatformIP6Address *address, gpointer user_data)
{
	log_ip6_address (address, "added");
}

static void
log_ip6_address_changed (NMPlatform *p, int ifindex, NMPlatformIP6Address *address, gpointer user_data)
{
	log_ip6_address (address, "changed");
}

static void
log_ip6_address_removed (NMPlatform *p, int ifindex, NMPlatformIP6Address *address, gpointer user_data)
{
	log_ip6_address (address, "removed");
}

static void
log_ip4_route (NMPlatformIP4Route *route, const char *change_type)
{
	char network[INET_ADDRSTRLEN];
	char gateway[INET_ADDRSTRLEN];
	int plen = route->plen;
	const char *name = nm_platform_link_get_name (route->ifindex);

	inet_ntop (AF_INET, &route->network, network, sizeof (network));
	inet_ntop (AF_INET, &route->gateway, gateway, sizeof (gateway));

	debug ("signal: route %s: %s/%d via %s dev %s", change_type, network, plen, gateway, name);
}

static void
log_ip4_route_added (NMPlatform *p, int ifindex, NMPlatformIP4Route *route, gpointer user_data)
{
	log_ip4_route (route, "added");
}

static void
log_ip4_route_changed (NMPlatform *p, int ifindex, NMPlatformIP4Route *route, gpointer user_data)
{
	log_ip4_route (route, "changed");
}

static void
log_ip4_route_removed (NMPlatform *p, int ifindex, NMPlatformIP4Route *route, gpointer user_data)
{
	log_ip4_route (route, "removed");
}

static void
log_ip6_route (NMPlatformIP6Route *route, const char *change_type)
{
	char network[INET6_ADDRSTRLEN];
	char gateway[INET6_ADDRSTRLEN];
	int plen = route->plen;
	const char *name = nm_platform_link_get_name (route->ifindex);

	inet_ntop (AF_INET6, &route->network, network, sizeof (network));
	inet_ntop (AF_INET6, &route->gateway, gateway, sizeof (gateway));

	debug ("signal: route %s: %s/%d via %s dev %s", change_type, network, plen, gateway, name);
}

static void
log_ip6_route_added (NMPlatform *p, int ifindex, NMPlatformIP6Route *route, gpointer user_data)
{
	log_ip6_route (route, "added");
}

static void
log_ip6_route_changed (NMPlatform *p, int ifindex, NMPlatformIP6Route *route, gpointer user_data)
{
	log_ip6_route (route, "changed");
}

static void
log_ip6_route_removed (NMPlatform *p, int ifindex, NMPlatformIP6Route *route, gpointer user_data)
{
	log_ip6_route (route, "removed");
}

/******************************************************************/

static void
nm_platform_init (NMPlatform *object)
{
}

#define SIGNAL(signal_id, method) signals[signal_id] = \
	g_signal_new_class_handler (NM_PLATFORM_ ## signal_id, \
		G_OBJECT_CLASS_TYPE (object_class), \
		G_SIGNAL_RUN_FIRST, \
		G_CALLBACK (method), \
		NULL, NULL, NULL, \
		G_TYPE_NONE, 2, G_TYPE_INT, G_TYPE_POINTER); \

static void
nm_platform_class_init (NMPlatformClass *platform_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (platform_class);

	/* Signals */
	SIGNAL (LINK_ADDED, log_link_added)
	SIGNAL (LINK_CHANGED, log_link_changed)
	SIGNAL (LINK_REMOVED, log_link_removed)
	SIGNAL (IP4_ADDRESS_ADDED, log_ip4_address_added)
	SIGNAL (IP4_ADDRESS_CHANGED, log_ip4_address_changed)
	SIGNAL (IP4_ADDRESS_REMOVED, log_ip4_address_removed)
	SIGNAL (IP6_ADDRESS_ADDED, log_ip6_address_added)
	SIGNAL (IP6_ADDRESS_CHANGED, log_ip6_address_changed)
	SIGNAL (IP6_ADDRESS_REMOVED, log_ip6_address_removed)
	SIGNAL (IP4_ROUTE_ADDED, log_ip4_route_added)
	SIGNAL (IP4_ROUTE_CHANGED, log_ip4_route_changed)
	SIGNAL (IP4_ROUTE_REMOVED, log_ip4_route_removed)
	SIGNAL (IP6_ROUTE_ADDED, log_ip6_route_added)
	SIGNAL (IP6_ROUTE_CHANGED, log_ip6_route_changed)
	SIGNAL (IP6_ROUTE_REMOVED, log_ip6_route_removed)
}
