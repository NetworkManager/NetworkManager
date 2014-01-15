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
#include <netlink/route/addr.h>

#include "nm-platform.h"
#include "NetworkManagerUtils.h"
#include "nm-logging.h"
#include "nm-enum-types.h"

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
	case NM_PLATFORM_ERROR_WRONG_TYPE:
		return "object is wrong type";
	case NM_PLATFORM_ERROR_NOT_SLAVE:
		return "link not a slave";
	case NM_PLATFORM_ERROR_NO_FIRMWARE:
		return "firmware not found";
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

/**
 * nm_platform_sysctl_get_int32:
 * @path: Absolute path to sysctl
 * @fallback: default value, if the content of path could not be read
 * as decimal integer.
 *
 * Returns: contents of the sysctl file parsed as s32 integer, or
 * @fallback on error. Also, on error, @errno will be set to a non-zero
 * value.
 */
gint32
nm_platform_sysctl_get_int32 (const char *path, gint32 fallback)
{
	char *value = NULL;
	gint32 ret;

	g_return_val_if_fail (path, fallback);

	if (path)
		value = nm_platform_sysctl_get (path);

	if (!value) {
		errno = EINVAL;
		return fallback;
	}

	ret = nm_utils_ascii_str_to_int64 (value, 10, G_MININT32, G_MAXINT32, fallback);
	g_free (value);
	return ret;
}

/******************************************************************/

/**
 * nm_platform_query_devices:
 *
 * Emit #NMPlatform:link-added signals for all currently-known links.
 * Should only be called at startup.
 */
void
nm_platform_query_devices (void)
{
	GArray *links_array;
	NMPlatformLink *links;
	int i;

	links_array = nm_platform_link_get_all ();
	links = (NMPlatformLink *) links_array->data;
	for (i = 0; i < links_array->len; i++) {
		g_signal_emit (platform, signals[LINK_ADDED], 0,
		               links[i].ifindex, &links[i], NM_PLATFORM_REASON_INTERNAL);
	}
	g_array_unref (links_array);
}

/**
 * nm_platform_link_get_all:
 *
 * Retrieve a snapshot of configuration for all links at once. The result is
 * owned by the caller and should be freed with g_array_unref().
 */
GArray *
nm_platform_link_get_all (void)
{
	GArray *links, *result;
	guint i, j, nresult;
	GHashTable *unseen;
	NMPlatformLink *item;

	reset_error ();

	g_return_val_if_fail (klass->link_get_all, NULL);

	links = klass->link_get_all (platform);

	if (!links || links->len == 0)
		return links;

	unseen = g_hash_table_new (g_direct_hash, g_direct_equal);
	for (i = 0; i < links->len; i++) {
		item = &g_array_index (links, NMPlatformLink, i);

		if (item->ifindex <= 0 || g_hash_table_contains (unseen, GINT_TO_POINTER (item->ifindex))) {
			g_warn_if_reached ();
			item->ifindex = 0;
			continue;
		}

		g_hash_table_insert (unseen, GINT_TO_POINTER (item->ifindex), NULL);
	}

#ifndef G_DISABLE_ASSERT
	/* Ensure that link_get_all returns a consistent and valid result. */
	for (i = 0; i < links->len; i++) {
		item = &g_array_index (links, NMPlatformLink, i);

		if (!item->ifindex)
			continue;
		if (item->master != 0) {
			g_warn_if_fail (item->master > 0);
			g_warn_if_fail (item->master != item->ifindex);
			g_warn_if_fail (g_hash_table_contains (unseen, GINT_TO_POINTER (item->master)));
		}
		if (item->parent != 0) {
			g_warn_if_fail (item->parent > 0);
			g_warn_if_fail (item->parent != item->ifindex);
			g_warn_if_fail (g_hash_table_contains (unseen, GINT_TO_POINTER (item->parent)));
		}
	}
#endif

	/* Re-order the links list such that children/slaves come after all ancestors */
	nresult = g_hash_table_size (unseen);
	result = g_array_sized_new (TRUE, TRUE, sizeof (NMPlatformLink), nresult);
	g_array_set_size (result, nresult);

	j = 0;
	do {
		gboolean found_something = FALSE;
		guint first_idx = G_MAXUINT;

		for (i = 0; i < links->len; i++) {
			item = &g_array_index (links, NMPlatformLink, i);

			if (!item->ifindex)
				continue;

			if (first_idx == G_MAXUINT)
				first_idx = i;

			g_assert (g_hash_table_contains (unseen, GINT_TO_POINTER (item->ifindex)));

			if (item->master > 0 && g_hash_table_contains (unseen, GINT_TO_POINTER (item->master)))
				continue;
			if (item->parent > 0 && g_hash_table_contains (unseen, GINT_TO_POINTER (item->parent)))
				continue;

			g_hash_table_remove (unseen, GINT_TO_POINTER (item->ifindex));
			g_array_index (result, NMPlatformLink, j++) = *item;
			item->ifindex = 0;
			found_something = TRUE;
		}

		if (!found_something) {
			/* there is a circle, pop the first (remaining) element from the list */
			g_warn_if_reached ();
			item = &g_array_index (links, NMPlatformLink, first_idx);

			g_hash_table_remove (unseen, GINT_TO_POINTER (item->ifindex));
			g_array_index (result, NMPlatformLink, j++) = *item;
			item->ifindex = 0;
		}
	} while (j < nresult);

	g_hash_table_destroy (unseen);
	g_array_free (links, TRUE);

	return result;
}

/**
 * nm_platform_link_add:
 * @name: Interface name
 * @type: Interface type
 *
 * Add a software interface. Sets platform->error to NM_PLATFORM_ERROR_EXISTS
 * if interface is already already exists.  Any link-added signal will be
 * emitted from an idle handler and not within this function.
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

	g_return_val_if_fail (klass->link_delete, FALSE);

	name = nm_platform_link_get_name (ifindex);

	if (!name)
		return FALSE;

	debug ("link: deleting '%s' (%d)", name, ifindex);
	return klass->link_delete (platform, ifindex);
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
 * nm_platform_link_is_software:
 * @ifindex: Interface index.
 *
 * Returns: %TRUE if ifindex belongs to a software interface, not backed by
 * a physical device.
 */
gboolean
nm_platform_link_is_software (int ifindex)
{
	return (nm_platform_link_get_type (ifindex) & 0x10000);
}

/**
 * nm_platform_link_supports_slaves:
 * @ifindex: Interface index.
 *
 * Returns: %TRUE if ifindex belongs to an interface capable of enslaving
 * other interfaces.
 */
gboolean
nm_platform_link_supports_slaves (int ifindex)
{
	return (nm_platform_link_get_type (ifindex) & 0x20000);
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
 * nm_platform_link_set_mtu:
 * @ifindex: Interface index
 * @mtu: The new MTU value
 *
 * Set interface MTU.
 */
gboolean
nm_platform_link_set_mtu (int ifindex, guint32 mtu)
{
	reset_error ();

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (mtu > 0, FALSE);
	g_return_val_if_fail (klass->link_set_mtu, FALSE);

	debug ("link: setting '%s' (%d) mtu %d", nm_platform_link_get_name (ifindex), ifindex, mtu);
	return klass->link_set_mtu (platform, ifindex, mtu);
}

/**
 * nm_platform_link_get_mtu:
 * @ifindex: Interface index
 *
 * Returns: MTU value for the interface or 0 on error.
 */
guint32
nm_platform_link_get_mtu (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (ifindex >= 0, 0);
	g_return_val_if_fail (klass->link_get_mtu, 0);

	return klass->link_get_mtu (platform, ifindex);
}

/**
 * nm_platform_link_get_mtu:
 * @ifindex: Interface index
 *
 * Returns: physical port ID for the interface, or %NULL on error
 * or if the interface has no physical port ID.
 */
char *
nm_platform_link_get_physical_port_id (int ifindex)
{
	reset_error ();

	g_return_val_if_fail (ifindex >= 0, NULL);
	g_return_val_if_fail (klass->link_get_physical_port_id, NULL);

	return klass->link_get_physical_port_id (platform, ifindex);
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
 * Create a software bridge.
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
 * Create a software bonding device.
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
 * Create a software teaming device.
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

gboolean
nm_platform_infiniband_partition_add (int parent, int p_key)
{
	const char *parent_name;
	char *name;

	reset_error ();

	g_return_val_if_fail (parent >= 0, FALSE);
	g_return_val_if_fail (p_key >= 0, FALSE);
	g_return_val_if_fail (klass->infiniband_partition_add, FALSE);

	if (nm_platform_link_get_type (parent) != NM_LINK_TYPE_INFINIBAND) {
		platform->error = NM_PLATFORM_ERROR_WRONG_TYPE;
		return FALSE;
	}

	parent_name = nm_platform_link_get_name (parent);
	name = g_strdup_printf ("%s.%04x", parent_name, p_key);
	if (nm_platform_link_exists (name)) {
		debug ("infiniband: already exists");
		platform->error = NM_PLATFORM_ERROR_EXISTS;
		g_free (name);
		return FALSE;
	}
	g_free (name);

	return klass->infiniband_partition_add (platform, parent, p_key);
}

gboolean
nm_platform_veth_get_properties (int ifindex, NMPlatformVethProperties *props)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	return klass->veth_get_properties (platform, ifindex, props);
}

gboolean
nm_platform_tun_get_properties (int ifindex, NMPlatformTunProperties *props)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	return klass->tun_get_properties (platform, ifindex, props);
}

gboolean
nm_platform_macvlan_get_properties (int ifindex, NMPlatformMacvlanProperties *props)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	return klass->macvlan_get_properties (platform, ifindex, props);
}

gboolean
nm_platform_gre_get_properties (int ifindex, NMPlatformGreProperties *props)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	return klass->gre_get_properties (platform, ifindex, props);
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
nm_platform_ip4_address_add (int ifindex,
                             in_addr_t address,
                             in_addr_t peer_address,
                             int plen,
                             guint32 lifetime,
                             guint32 preferred)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (lifetime > 0, FALSE);
	g_return_val_if_fail (klass->ip4_address_add, FALSE);

	debug ("address: adding or updating IPv4 address");
	return klass->ip4_address_add (platform, ifindex, address, peer_address, plen, lifetime, preferred);
}

gboolean
nm_platform_ip6_address_add (int ifindex,
                             struct in6_addr address,
                             struct in6_addr peer_address,
                             int plen,
                             guint32 lifetime,
                             guint32 preferred,
                             guint flags)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (lifetime > 0, FALSE);
	g_return_val_if_fail (klass->ip6_address_add, FALSE);

	debug ("address: adding or updating IPv6 address");
	return klass->ip6_address_add (platform, ifindex, address, peer_address, plen, lifetime, preferred, flags);
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

static gboolean
array_contains_ip4_address (const GArray *addresses, const NMPlatformIP4Address *address)
{
	guint len = addresses ? addresses->len : 0;
	guint i;

	for (i = 0; i < len; i++) {
		NMPlatformIP4Address *candidate = &g_array_index (addresses, NMPlatformIP4Address, i);

		if (candidate->address == address->address && candidate->plen == address->plen)
			return TRUE;
	}

	return FALSE;
}

static gboolean
array_contains_ip6_address (const GArray *addresses, const NMPlatformIP6Address *address)
{
	guint len = addresses ? addresses->len : 0;
	guint i;

	for (i = 0; i < len; i++) {
		NMPlatformIP6Address *candidate = &g_array_index (addresses, NMPlatformIP6Address, i);

		if (IN6_ARE_ADDR_EQUAL (&candidate->address, &address->address) && candidate->plen == address->plen)
			return TRUE;
	}

	return FALSE;
}

static guint32
get_time (void)
{
	struct timespec tp;

	clock_gettime (CLOCK_MONOTONIC, &tp);

	return tp.tv_sec;
}

/* Compute (a - b) in an overflow-safe manner. */
static guint32
subtract_guint32 (guint32 a, guint32 b)
{
	if (a == G_MAXUINT32)
		return G_MAXUINT32;

	return a > b ? a - b : 0;
}

/**
 * nm_platform_ip4_address_sync:
 * @ifindex: Interface index
 * @known_addresses: List of addresses
 *
 * A convenience function to synchronize addresses for a specific interface
 * with the least possible disturbance. It simply removes addresses that are
 * not listed and adds addresses that are.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_ip4_address_sync (int ifindex, const GArray *known_addresses)
{
	GArray *addresses;
	NMPlatformIP4Address *address;
	guint32 now = get_time ();
	int i;

	/* Delete unknown addresses */
	addresses = nm_platform_ip4_address_get_all (ifindex);
	for (i = 0; i < addresses->len; i++) {
		address = &g_array_index (addresses, NMPlatformIP4Address, i);

		if (!array_contains_ip4_address (known_addresses, address))
			nm_platform_ip4_address_delete (ifindex, address->address, address->plen);
	}
	g_array_free (addresses, TRUE);

	if (!known_addresses)
		return TRUE;

	/* Add missing addresses */
	for (i = 0; i < known_addresses->len; i++) {
		const NMPlatformIP4Address *known_address = &g_array_index (known_addresses, NMPlatformIP4Address, i);
		guint32 lifetime, preferred;

		if (known_address->lifetime) {
			/* Pad the timestamp by 5 seconds to avoid potential races. */
			guint32 shift = subtract_guint32 (now, known_address->timestamp + 5);

			lifetime = subtract_guint32 (known_address->lifetime, shift);
			preferred = subtract_guint32 (known_address->lifetime, shift);
		} else
			lifetime = preferred = NM_PLATFORM_LIFETIME_PERMANENT;

		if (!nm_platform_ip4_address_add (ifindex, known_address->address, known_address->peer_address, known_address->plen, lifetime, preferred))
			return FALSE;
	}

	return TRUE;
}

/**
 * nm_platform_ip6_address_sync:
 * @ifindex: Interface index
 * @known_addresses: List of addresses
 *
 * A convenience function to synchronize addresses for a specific interface
 * with the least possible disturbance. It simply removes addresses that are
 * not listed and adds addresses that are.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_ip6_address_sync (int ifindex, const GArray *known_addresses)
{
	GArray *addresses;
	NMPlatformIP6Address *address;
	guint32 now = get_time ();
	int i;

	/* Delete unknown addresses */
	addresses = nm_platform_ip6_address_get_all (ifindex);
	for (i = 0; i < addresses->len; i++) {
		address = &g_array_index (addresses, NMPlatformIP6Address, i);

		/* Leave link local address management to the kernel */
		if (IN6_IS_ADDR_LINKLOCAL (&address->address))
			continue;

		if (!array_contains_ip6_address (known_addresses, address))
			nm_platform_ip6_address_delete (ifindex, address->address, address->plen);
	}
	g_array_free (addresses, TRUE);

	if (!known_addresses)
		return TRUE;

	/* Add missing addresses */
	for (i = 0; i < known_addresses->len; i++) {
		const NMPlatformIP6Address *known_address = &g_array_index (known_addresses, NMPlatformIP6Address, i);
		guint32 lifetime, preferred;

		if (known_address->lifetime) {
			/* Pad the timestamp by 5 seconds to avoid potential races. */
			guint32 shift = subtract_guint32 (now, known_address->timestamp + 5);

			lifetime = subtract_guint32 (known_address->lifetime, shift);
			preferred = subtract_guint32 (known_address->lifetime, shift);
		} else
			lifetime = preferred = NM_PLATFORM_LIFETIME_PERMANENT;

		if (!nm_platform_ip6_address_add (ifindex, known_address->address,
		                                  known_address->peer_address, known_address->plen,
		                                  lifetime, preferred, known_address->flags))
			return FALSE;
	}

	return TRUE;
}

gboolean
nm_platform_address_flush (int ifindex)
{
	return nm_platform_ip4_address_sync (ifindex, NULL)
			&& nm_platform_ip6_address_sync (ifindex, NULL);
}

/******************************************************************/

GArray *
nm_platform_ip4_route_get_all (int ifindex, gboolean include_default)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (klass->ip4_route_get_all, NULL);

	return klass->ip4_route_get_all (platform, ifindex, include_default);
}

GArray *
nm_platform_ip6_route_get_all (int ifindex, gboolean include_default)
{
	reset_error ();

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (klass->ip6_route_get_all, NULL);

	return klass->ip6_route_get_all (platform, ifindex, include_default);
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

static gboolean
array_contains_ip4_route (const GArray *routes, const NMPlatformIP4Route *route)
{
	guint len = routes ? routes->len : 0;
	guint i;

	for (i = 0; i < len; i++) {
		NMPlatformIP4Route *c = &g_array_index (routes, NMPlatformIP4Route, i);

		if (route->network == c->network &&
		    route->plen == c->plen &&
		    route->gateway == c->gateway &&
		    route->metric == c->metric)
			return TRUE;
	}

	return FALSE;
}

static gboolean
array_contains_ip6_route (const GArray *routes, const NMPlatformIP6Route *route)
{
	guint len = routes ? routes->len : 0;
	guint i;

	for (i = 0; i < len; i++) {
		NMPlatformIP6Route *c = &g_array_index (routes, NMPlatformIP6Route, i);

		if (IN6_ARE_ADDR_EQUAL (&route->network, &c->network) &&
		    route->plen == c->plen &&
		    IN6_ARE_ADDR_EQUAL (&route->gateway, &c->gateway) &&
		    route->metric == c->metric)
			return TRUE;
	}

	return FALSE;
}

/**
 * nm_platform_ip4_route_sync:
 * @ifindex: Interface index
 * @known_routes: List of routes
 *
 * A convenience function to synchronize routes for a specific interface
 * with the least possible disturbance. It simply removes routes that are
 * not listed and adds routes that are.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_ip4_route_sync (int ifindex, const GArray *known_routes)
{
	GArray *routes;
	NMPlatformIP4Route *route;
	const NMPlatformIP4Route *known_route;
	gboolean success;
	int i;

	/* Delete unknown routes */
	routes = nm_platform_ip4_route_get_all (ifindex, FALSE);
	for (i = 0; i < routes->len; i++) {
		route = &g_array_index (routes, NMPlatformIP4Route, i);

		if (!array_contains_ip4_route (known_routes, route))
			nm_platform_ip4_route_delete (ifindex, route->network, route->plen, route->metric);
	}

	if (!known_routes) {
		g_array_free (routes, TRUE);
		return TRUE;
	}

	/* Add missing routes */
	for (i = 0, success = TRUE; i < known_routes->len && success; i++) {
		known_route = &g_array_index (known_routes, NMPlatformIP4Route, i);

		/* Ignore routes that already exist */
		if (!array_contains_ip4_route (routes, known_route)) {
			success = nm_platform_ip4_route_add (ifindex,
			                                     known_route->network,
			                                     known_route->plen,
			                                     known_route->gateway,
			                                     known_route->metric,
			                                     known_route->mss);
			if (!success && known_route->source < NM_PLATFORM_SOURCE_USER) {
				nm_log_dbg (LOGD_PLATFORM, "ignore error adding IPv4 route to kernel: %s",
				                           nm_platform_ip4_route_to_string (known_route));
				success = TRUE;
			}
		}
	}

	g_array_free (routes, TRUE);
	return success;
}

/**
 * nm_platform_ip6_route_sync:
 * @ifindex: Interface index
 * @known_routes: List of routes
 *
 * A convenience function to synchronize routes for a specific interface
 * with the least possible disturbance. It simply removes routes that are
 * not listed and adds routes that are.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_ip6_route_sync (int ifindex, const GArray *known_routes)
{
	GArray *routes;
	NMPlatformIP6Route *route;
	const NMPlatformIP6Route *known_route;
	gboolean success;
	int i;

	/* Delete unknown routes */
	routes = nm_platform_ip6_route_get_all (ifindex, FALSE);
	for (i = 0; i < routes->len; i++) {
		route = &g_array_index (routes, NMPlatformIP6Route, i);
		route->ifindex = 0;

		if (!array_contains_ip6_route (known_routes, route))
			nm_platform_ip6_route_delete (ifindex, route->network, route->plen, route->metric);
	}

	if (!known_routes) {
		g_array_free (routes, TRUE);
		return TRUE;
	}

	/* Add missing routes */
	for (i = 0, success = TRUE; i < known_routes->len && success; i++) {
		known_route = &g_array_index (known_routes, NMPlatformIP6Route, i);

		/* Ignore routes that already exist */
		if (!array_contains_ip6_route (routes, known_route)) {
			success = nm_platform_ip6_route_add (ifindex,
			                                     known_route->network,
			                                     known_route->plen,
			                                     known_route->gateway,
			                                     known_route->metric,
			                                     known_route->mss);
			if (!success && known_route->source < NM_PLATFORM_SOURCE_USER) {
				nm_log_dbg (LOGD_PLATFORM, "ignore error adding IPv6 route to kernel: %s",
				                           nm_platform_ip6_route_to_string (known_route));
				success = TRUE;
			}
		}
	}

	g_array_free (routes, TRUE);
	return success;
}

gboolean
nm_platform_route_flush (int ifindex)
{
	return nm_platform_ip4_route_sync (ifindex, NULL)
			&& nm_platform_ip6_route_sync (ifindex, NULL);
}

/******************************************************************/

static const char *
source_to_string (NMPlatformSource source)
{
	switch (source) {
	case NM_PLATFORM_SOURCE_KERNEL:
		return "kernel";
	case NM_PLATFORM_SOURCE_SHARED:
		return "shared";
	case NM_PLATFORM_SOURCE_IP4LL:
		return "ipv4ll";
	case NM_PLATFORM_SOURCE_PPP:
		return "ppp";
	case NM_PLATFORM_SOURCE_WWAN:
		return "wwan";
	case NM_PLATFORM_SOURCE_VPN:
		return "vpn";
	case NM_PLATFORM_SOURCE_DHCP:
		return "dhcp";
	case NM_PLATFORM_SOURCE_RDISC:
		return "rdisc";
	case NM_PLATFORM_SOURCE_USER:
		return "user";
	default:
		break;
	}
	return "unknown";
}

/**
 * nm_platform_ip4_address_to_string:
 * @route: pointer to NMPlatformIP4Address address structure
 *
 * A method for converting an address struct into a string representation.
 *
 * Example output: ""
 *
 * Returns: a string representation of the address. The returned string
 * is an internal buffer, so do not keep or free the returned string.
 * Also, this function is not thread safe.
 */
const char *
nm_platform_ip4_address_to_string (const NMPlatformIP4Address *address)
{
	static char buffer[256];
	char s_address[INET_ADDRSTRLEN];
	char s_peer[INET_ADDRSTRLEN];
	const char *s_dev;
	char *str_dev;
	char *str_peer = NULL;

	g_return_val_if_fail (address, "(unknown)");

	inet_ntop (AF_INET, &address->address, s_address, sizeof (s_address));

	if (address->peer_address) {
		inet_ntop (AF_INET, &address->peer_address, s_peer, sizeof (s_peer));
		str_peer = g_strconcat (" ptp ", s_peer, NULL);
	}

	s_dev = address->ifindex > 0 ? nm_platform_link_get_name (address->ifindex) : NULL;
	str_dev = s_dev ? g_strconcat (" dev ", s_dev, NULL) : NULL;

	g_snprintf (buffer, sizeof (buffer), "%s/%d lft %u pref %u time %u%s%s src %s",
	            s_address, address->plen, (guint)address->lifetime, (guint)address->preferred,
	            (guint)address->timestamp,
	            str_peer ? str_peer : "",
	            str_dev ? str_dev : "",
	            source_to_string (address->source));
	g_free (str_dev);
	g_free (str_peer);
	return buffer;
}

/**
 * nm_platform_ip6_address_to_string:
 * @route: pointer to NMPlatformIP6Address address structure
 *
 * A method for converting an address struct into a string representation.
 *
 * Example output: "2001:db8:0:f101::1/64 lft 4294967295 pref 4294967295 time 16922666 on dev em1"
 *
 * Returns: a string representation of the address. The returned string
 * is an internal buffer, so do not keep or free the returned string.
 * Also, this function is not thread safe.
 */
const char *
nm_platform_ip6_address_to_string (const NMPlatformIP6Address *address)
{
	static char buffer[256];
	char s_flags[256];
	char s_address[INET6_ADDRSTRLEN];
	char s_peer[INET6_ADDRSTRLEN];
	const char *s_dev;
	char *str_flags;
	char *str_dev;
	char *str_peer = NULL;

	g_return_val_if_fail (address, "(unknown)");

	inet_ntop (AF_INET6, &address->address, s_address, sizeof (s_address));

	if (!IN6_IS_ADDR_UNSPECIFIED (&address->peer_address)) {
		inet_ntop (AF_INET6, &address->peer_address, s_peer, sizeof (s_peer));
		str_peer = g_strconcat (" ptp ", s_peer, NULL);
	}

	s_dev = address->ifindex > 0 ? nm_platform_link_get_name (address->ifindex) : NULL;
	str_dev = s_dev ? g_strconcat (" dev ", s_dev, NULL) : NULL;

	rtnl_addr_flags2str(address->flags, s_flags, sizeof(s_flags));
	str_flags = s_flags[0] ? g_strconcat (" flags ", s_flags, NULL) : NULL;

	g_snprintf (buffer, sizeof (buffer), "%s/%d lft %u pref %u time %u%s%s%s src %s",
	            s_address, address->plen, (guint)address->lifetime, (guint)address->preferred,
	            (guint)address->timestamp,
	            str_peer ? str_peer : "",
	            str_dev ? str_dev : "",
	            str_flags ? str_flags : "",
	            source_to_string (address->source));
	g_free (str_flags);
	g_free (str_dev);
	g_free (str_peer);
	return buffer;
}

/**
 * nm_platform_ip4_route_to_string:
 * @route: pointer to NMPlatformIP4Route route structure
 *
 * A method for converting a route struct into a string representation.
 *
 * Example output: "192.168.1.0/24 via 0.0.0.0 dev em1 metric 0 mss 0"
 *
 * Returns: a string representation of the route. The returned string
 * is an internal buffer, so do not keep or free the returned string.
 * Also, this function is not thread safe.
 */
const char *
nm_platform_ip4_route_to_string (const NMPlatformIP4Route *route)
{
	static char buffer[256];
	char s_network[INET_ADDRSTRLEN], s_gateway[INET_ADDRSTRLEN];
	const char *s_dev;
	char *str_dev;

	g_return_val_if_fail (route, "(unknown)");

	inet_ntop (AF_INET, &route->network, s_network, sizeof(s_network));
	inet_ntop (AF_INET, &route->gateway, s_gateway, sizeof(s_gateway));

	s_dev = route->ifindex > 0 ? nm_platform_link_get_name (route->ifindex) : NULL;
	str_dev = s_dev ? g_strconcat (" dev ", s_dev, NULL) : NULL;

	g_snprintf (buffer, sizeof (buffer), "%s/%d via %s%s metric %u mss %u src %s",
	            s_network, route->plen, s_gateway,
	            str_dev ? str_dev : "",
	            route->metric, route->mss,
	            source_to_string (route->source));
	g_free (str_dev);
	return buffer;
}

/**
 * nm_platform_ip6_route_to_string:
 * @route: pointer to NMPlatformIP6Route route structure
 *
 * A method for converting a route struct into a string representation.
 *
 * Example output: "ff02::fb/128 via :: dev em1 metric 0"
 *
 * Returns: a string representation of the route. The returned string
 * is an internal buffer, so do not keep or free the returned string.
 * Also, this function is not thread safe.
 */
const char *
nm_platform_ip6_route_to_string (const NMPlatformIP6Route *route)
{
	static char buffer[256];
	char s_network[INET6_ADDRSTRLEN], s_gateway[INET6_ADDRSTRLEN];
	const char *s_dev;
	char *str_dev;

	g_return_val_if_fail (route, "(unknown)");

	inet_ntop (AF_INET6, &route->network, s_network, sizeof(s_network));
	inet_ntop (AF_INET6, &route->gateway, s_gateway, sizeof(s_gateway));

	s_dev = route->ifindex > 0 ? nm_platform_link_get_name (route->ifindex) : NULL;
	str_dev = s_dev ? g_strconcat (" dev ", s_dev, NULL) : NULL;

	g_snprintf (buffer, sizeof (buffer), "%s/%d via %s%s metric %u mss %u src %s",
	            s_network, route->plen, s_gateway,
	            str_dev ? str_dev : "",
	            route->metric, route->mss,
	            source_to_string (route->source));
	g_free (str_dev);
	return buffer;
}

#define _CMP_POINTER(a, b)                                  \
    G_STMT_START {                                          \
        if ((a) == (b))                                     \
            return 0;                                       \
        if (!(a))                                           \
            return -1;                                      \
        if (!(b))                                           \
            return 1;                                       \
    } G_STMT_END

#define _CMP_FIELD(a, b, field)                             \
    G_STMT_START {                                          \
        if (((a)->field) != ((b)->field))                   \
            return (((a)->field) < ((b)->field)) ? -1 : 1;  \
    } G_STMT_END

#define _CMP_FIELD_MEMCMP(a, b, field)                      \
    G_STMT_START {                                          \
        int c = memcmp (&((a)->field), &((b)->field),       \
                        sizeof ((a)->field));               \
        if (c != 0)                                         \
            return c < 0 ? -1 : 1;                          \
    } G_STMT_END

int
nm_platform_ip4_address_cmp (const NMPlatformIP4Address *a, const NMPlatformIP4Address *b)
{
	_CMP_POINTER (a, b);
	_CMP_FIELD (a, b, ifindex);
	_CMP_FIELD (a, b, source);
	_CMP_FIELD (a, b, address);
	_CMP_FIELD (a, b, peer_address);
	_CMP_FIELD (a, b, plen);
	_CMP_FIELD (a, b, timestamp);
	_CMP_FIELD (a, b, lifetime);
	_CMP_FIELD (a, b, preferred);
	return 0;
}

int
nm_platform_ip6_address_cmp (const NMPlatformIP6Address *a, const NMPlatformIP6Address *b)
{
	_CMP_POINTER (a, b);
	_CMP_FIELD (a, b, ifindex);
	_CMP_FIELD (a, b, source);
	_CMP_FIELD_MEMCMP (a, b, address);
	_CMP_FIELD_MEMCMP (a, b, peer_address);
	_CMP_FIELD (a, b, plen);
	_CMP_FIELD (a, b, timestamp);
	_CMP_FIELD (a, b, lifetime);
	_CMP_FIELD (a, b, preferred);
	_CMP_FIELD (a, b, flags);
	return 0;
}

int
nm_platform_ip4_route_cmp (const NMPlatformIP4Route *a, const NMPlatformIP4Route *b)
{
	_CMP_POINTER (a, b);
	_CMP_FIELD (a, b, ifindex);
	_CMP_FIELD (a, b, source);
	_CMP_FIELD (a, b, network);
	_CMP_FIELD (a, b, plen);
	_CMP_FIELD (a, b, gateway);
	_CMP_FIELD (a, b, metric);
	_CMP_FIELD (a, b, mss);
	return 0;
}

int
nm_platform_ip6_route_cmp (const NMPlatformIP6Route *a, const NMPlatformIP6Route *b)
{
	_CMP_POINTER (a, b);
	_CMP_FIELD (a, b, ifindex);
	_CMP_FIELD (a, b, source);
	_CMP_FIELD_MEMCMP (a, b, network);
	_CMP_FIELD (a, b, plen);
	_CMP_FIELD_MEMCMP (a, b, gateway);
	_CMP_FIELD (a, b, metric);
	_CMP_FIELD (a, b, mss);
	return 0;
}

#undef _CMP_POINTER
#undef _CMP_FIELD
#undef _CMP_FIELD_MEMCMP


static void
log_link (NMPlatformLink *device, const char *change_type)
{
	debug ("signal: link %s: %s (%d)", change_type, device->name, device->ifindex);
}

static void
log_link_added (NMPlatform *p, int ifindex, NMPlatformLink *device, gpointer user_data)
{
	log_link (device, "added");
}

static void
log_link_changed (NMPlatform *p, int ifindex, NMPlatformLink *device, gpointer user_data)
{
	log_link (device, "changed");
}

static void
log_link_removed (NMPlatform *p, int ifindex, NMPlatformLink *device, gpointer user_data)
{
	log_link (device, "removed");
}

static void
log_ip4_address (NMPlatformIP4Address *address, const char *change_type)
{
	const char *name = nm_platform_link_get_name (address->ifindex);

	debug ("(%s) signal: address %s: %s", name, change_type, nm_platform_ip4_address_to_string (address));
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
	const char *name = nm_platform_link_get_name (address->ifindex);

	debug ("(%s) signal: address %s: %s", name, change_type, nm_platform_ip6_address_to_string (address));
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
	debug ("signal: route %s: %s", change_type, nm_platform_ip4_route_to_string (route));
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
	debug ("signal: route %s: %s", change_type, nm_platform_ip6_route_to_string (route));
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
		G_TYPE_NONE, 3, G_TYPE_INT, G_TYPE_POINTER, NM_TYPE_PLATFORM_REASON);

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
