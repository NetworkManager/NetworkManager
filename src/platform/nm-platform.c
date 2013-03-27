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
 * nm_platform_get_error:
 *
 * Convenience function to quickly retrieve the error code of the last
 * operation.
 *
 * Returns: Integer error code.
 */
int
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
 * or NULL.
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

/******************************************************************/

static void
log_link_added (NMPlatform *p, NMPlatformLink *info, gpointer user_data)
{
	debug ("signal: link address: '%s' (%d)", info->name, info->ifindex);
}

static void
log_link_changed (NMPlatform *p, NMPlatformLink *info, gpointer user_data)
{
	debug ("signal: link changed: '%s' (%d)", info->name, info->ifindex);
}

static void
log_link_removed (NMPlatform *p, NMPlatformLink *info, gpointer user_data)
{
	debug ("signal: link removed: '%s' (%d)", info->name, info->ifindex);
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
log_ip4_address_added (NMPlatform *p, NMPlatformIP4Address *address, gpointer user_data)
{
	log_ip4_address (address, "added");
}

static void
log_ip4_address_changed (NMPlatform *p, NMPlatformIP4Address *address, gpointer user_data)
{
	log_ip4_address (address, "changed");
}

static void
log_ip4_address_removed (NMPlatform *p, NMPlatformIP4Address *address, gpointer user_data)
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
log_ip6_address_added (NMPlatform *p, NMPlatformIP6Address *address, gpointer user_data)
{
	log_ip6_address (address, "added");
}

static void
log_ip6_address_changed (NMPlatform *p, NMPlatformIP6Address *address, gpointer user_data)
{
	log_ip6_address (address, "changed");
}

static void
log_ip6_address_removed (NMPlatform *p, NMPlatformIP6Address *address, gpointer user_data)
{
	log_ip6_address (address, "removed");
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
		NULL, NULL, \
		g_cclosure_marshal_VOID__POINTER, \
		G_TYPE_NONE, 1, G_TYPE_POINTER); \

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
}
