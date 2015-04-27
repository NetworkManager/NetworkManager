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

#include "config.h"

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netlink/route/addr.h>
#include <netlink/route/rtnl.h>

#include "gsystem-local-alloc.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-platform.h"
#include "NetworkManagerUtils.h"
#include "nm-logging.h"
#include "nm-enum-types.h"
#include "nm-core-internal.h"

G_STATIC_ASSERT (sizeof ( ((NMPlatformLink *) NULL)->addr.data ) == NM_UTILS_HWADDR_LEN_MAX);

#define debug(...) nm_log_dbg (LOGD_PLATFORM, __VA_ARGS__)

#define NM_PLATFORM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_PLATFORM, NMPlatformPrivate))

G_DEFINE_TYPE (NMPlatform, nm_platform, G_TYPE_OBJECT)

/* NMPlatform signals */
enum {
	SIGNAL_LINK_CHANGED,
	SIGNAL_IP4_ADDRESS_CHANGED,
	SIGNAL_IP6_ADDRESS_CHANGED,
	SIGNAL_IP4_ROUTE_CHANGED,
	SIGNAL_IP6_ROUTE_CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/******************************************************************/

/* Singleton NMPlatform subclass instance and cached class object */
NM_DEFINE_SINGLETON_INSTANCE (NMPlatform);

NM_DEFINE_SINGLETON_WEAK_REF (NMPlatform);

/* Just always initialize a @klass instance. NM_PLATFORM_GET_CLASS()
 * is only a plain read on the self instance, which the compiler
 * like can optimize out.
 */
#define _CHECK_SELF_VOID(self, klass) \
	NMPlatformClass *klass; \
	do { \
		g_return_if_fail (NM_IS_PLATFORM (self)); \
		klass = NM_PLATFORM_GET_CLASS (self); \
		(void) klass; \
	} while (0)

#define _CHECK_SELF(self, klass, err_val) \
	NMPlatformClass *klass; \
	do { \
		g_return_val_if_fail (NM_IS_PLATFORM (self), err_val); \
		klass = NM_PLATFORM_GET_CLASS (self); \
		(void) klass; \
	} while (0)

/**
 * nm_platform_setup:
 * @instance: the #NMPlatform instance
 *
 * Failing to set up #NMPlatform singleton results in a fatal error,
 * as well as trying to initialize it multiple times without freeing
 * it.
 *
 * NetworkManager will typically use only one platform object during
 * its run. Test programs might want to switch platform implementations,
 * though.
 */
void
nm_platform_setup (NMPlatform *instance)
{
	g_return_if_fail (NM_IS_PLATFORM (instance));
	g_return_if_fail (!singleton_instance);

	singleton_instance = instance;

	nm_singleton_instance_weak_ref_register ();

	nm_log_dbg (LOGD_CORE, "setup NMPlatform singleton (%p, %s)", instance,  G_OBJECT_TYPE_NAME (instance));
}

/**
 * nm_platform_get:
 * @self: platform instance
 *
 * Retrieve #NMPlatform singleton. Use this whenever you want to connect to
 * #NMPlatform signals. It is an error to call it before nm_platform_setup().
 *
 * Returns: (transfer none): The #NMPlatform singleton reference.
 */
NMPlatform *
nm_platform_get ()
{
	g_assert (singleton_instance);

	return singleton_instance;
}

NMPlatform *
nm_platform_try_get (void)
{
	return singleton_instance;
}

/******************************************************************/

/**
 * nm_platform_set_error:
 * @self: platform instance
 * @error: The error code
 *
 * Convenience function to falsify self->error. It can be used for example
 * by functions that want to save the error, execute some operations and
 * restore it.
 */
void nm_platform_set_error (NMPlatform *self, NMPlatformError error)
{
	_CHECK_SELF_VOID (self, klass);

	self->error = error;
}

/**
 * nm_platform_get_error:
 * @self: platform instance
 *
 * Convenience function to quickly retrieve the error code of the last
 * operation.
 *
 * Returns: Integer error code.
 */
NMPlatformError
nm_platform_get_error (NMPlatform *self)
{
	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_NONE);

	return self->error;
}

/**
 * nm_platform_get_error_message:
 * @self: platform instance
 *
 * Returns: Static human-readable string for the error. Don't free.
 */
const char *
nm_platform_get_error_msg (NMPlatform *self)
{
	_CHECK_SELF (self, klass, NULL);

	switch (self->error) {
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
reset_error (NMPlatform *self)
{
	g_assert (self);
	self->error = NM_PLATFORM_ERROR_NONE;
}

#define IFA_F_MANAGETEMPADDR_STR "mngtmpaddr"
#define IFA_F_NOPREFIXROUTE_STR "noprefixroute"
gboolean
nm_platform_check_support_libnl_extended_ifa_flags ()
{
	static int supported = -1;

	/* support for extended ifa-flags was added together
	 * with the IFA_F_MANAGETEMPADDR flag. So, check if libnl
	 * is able to parse this flag. */
	if (supported == -1)
		supported = rtnl_addr_str2flags (IFA_F_MANAGETEMPADDR_STR) == IFA_F_MANAGETEMPADDR;

	return supported;
}

gboolean
nm_platform_check_support_kernel_extended_ifa_flags (NMPlatform *self)
{
	_CHECK_SELF (self, klass, FALSE);

	if (!klass->check_support_kernel_extended_ifa_flags)
		return FALSE;

	return klass->check_support_kernel_extended_ifa_flags (self);
}

gboolean
nm_platform_check_support_user_ipv6ll (NMPlatform *self)
{
	static int supported = -1;

	_CHECK_SELF (self, klass, FALSE);

	if (!klass->check_support_user_ipv6ll)
		return FALSE;

	if (supported < 0)
		supported = klass->check_support_user_ipv6ll (self) ? 1 : 0;
	return !!supported;
}

/******************************************************************/

/**
 * nm_platform_sysctl_set:
 * @self: platform instance
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
nm_platform_sysctl_set (NMPlatform *self, const char *path, const char *value)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (path, FALSE);
	g_return_val_if_fail (value, FALSE);
	g_return_val_if_fail (klass->sysctl_set, FALSE);

	reset_error (self);

	return klass->sysctl_set (self, path, value);
}

gboolean
nm_platform_sysctl_set_ip6_hop_limit_safe (NMPlatform *self, const char *iface, int value)
{
	const char *path;
	gint64 cur;

	/* the hop-limit provided via RA is uint8. */
	if (value > 0xFF)
		return FALSE;

	/* don't allow unreasonable small values */
	if (value < 10)
		return FALSE;

	path = nm_utils_ip6_property_path (iface, "hop_limit");
	cur = nm_platform_sysctl_get_int_checked (self, path, 10, 1, G_MAXINT32, -1);

	/* only allow increasing the hop-limit to avoid DOS by an attacker
	 * setting a low hop-limit (CVE-2015-2924, rh#1209902) */

	if (value < cur)
		return FALSE;
	if (value != cur) {
		char svalue[20];

		sprintf (svalue, "%d", value);
		nm_platform_sysctl_set (self, path, svalue);
	}

	return TRUE;
}

/**
 * nm_platform_sysctl_get:
 * @self: platform instance
 * @path: Absolute path to sysctl
 *
 * Returns: (transfer full): Contents of the virtual sysctl file.
 */
char *
nm_platform_sysctl_get (NMPlatform *self, const char *path)
{
	_CHECK_SELF (self, klass, NULL);

	g_return_val_if_fail (path, NULL);
	g_return_val_if_fail (klass->sysctl_get, NULL);

	reset_error (self);

	return klass->sysctl_get (self, path);
}

/**
 * nm_platform_sysctl_get_int32:
 * @self: platform instance
 * @path: Absolute path to sysctl
 * @fallback: default value, if the content of path could not be read
 * as decimal integer.
 *
 * Returns: contents of the sysctl file parsed as s32 integer, or
 * @fallback on error. On error, %errno will be set to a non-zero
 * value, on success %errno will be set to zero.
 */
gint32
nm_platform_sysctl_get_int32 (NMPlatform *self, const char *path, gint32 fallback)
{
	return nm_platform_sysctl_get_int_checked (self, path, 10, G_MININT32, G_MAXINT32, fallback);
}

/**
 * nm_platform_sysctl_get_int_checked:
 * @self: platform instance
 * @path: Absolute path to sysctl
 * @base: base of numeric conversion
 * @min: minimal value that is still valid
 * @max: maximal value that is still valid
 * @fallback: default value, if the content of path could not be read
 * as valid integer.
 *
 * Returns: contents of the sysctl file parsed as s64 integer, or
 * @fallback on error. On error, %errno will be set to a non-zero
 * value. On success, %errno will be set to zero. The returned value
 * will always be in the range between @min and @max
 * (inclusive) or @fallback.
 */
gint64
nm_platform_sysctl_get_int_checked (NMPlatform *self, const char *path, guint base, gint64 min, gint64 max, gint64 fallback)
{
	char *value = NULL;
	gint32 ret;

	_CHECK_SELF (self, klass, fallback);

	g_return_val_if_fail (path, fallback);

	if (path)
		value = nm_platform_sysctl_get (self, path);

	if (!value) {
		errno = EINVAL;
		return fallback;
	}

	ret = _nm_utils_ascii_str_to_int64 (value, base, min, max, fallback);
	g_free (value);
	return ret;
}

/******************************************************************/

/**
 * nm_platform_link_get_all:
 * self: platform instance
 *
 * Retrieve a snapshot of configuration for all links at once. The result is
 * owned by the caller and should be freed with g_array_unref().
 */
GArray *
nm_platform_link_get_all (NMPlatform *self)
{
	GArray *links, *result;
	guint i, j, nresult;
	GHashTable *unseen;
	NMPlatformLink *item;

	_CHECK_SELF (self, klass, NULL);
	reset_error (self);

	g_return_val_if_fail (klass->link_get_all, NULL);

	links = klass->link_get_all (self);

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
 * nm_platform_link_get:
 * @self: platform instance
 * @ifindex: ifindex of the link
 * @link: (out): output NMPlatformLink structure.
 *
 * If a link with given @ifindex exists, fill the given NMPlatformLink
 * structure.
 *
 * Returns: %TRUE, if such a link exists, %FALSE otherwise.
 * If the link does not exist, the content of @link is undefined.
 **/
gboolean
nm_platform_link_get (NMPlatform *self, int ifindex, NMPlatformLink *link)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);

	g_return_val_if_fail (klass->link_get, FALSE);
	return !!klass->link_get (self, ifindex, link);
}

/**
 * nm_platform_link_get_by_address:
 * @self: platform instance
 * @address: a pointer to the binary hardware address
 * @length: the size of @address in bytes
 * @link: (out): output NMPlatformLink structure.
 *
 * If a link with given @address exists, fill the given NMPlatformLink
 * structure.
 *
 * Returns: %TRUE, if such a link exists, %FALSE otherwise.
 * If the link does not exist, the content of @link is undefined.
 **/
gboolean
nm_platform_link_get_by_address (NMPlatform *self,
                                 gconstpointer address,
                                 size_t length,
                                 NMPlatformLink *link)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (address != NULL, FALSE);
	g_return_val_if_fail (length > 0, FALSE);
	g_return_val_if_fail (link, FALSE);

	g_return_val_if_fail (klass->link_get_by_address, FALSE);
	return !!klass->link_get_by_address (self, address, length, link);
}

/**
 * nm_platform_link_add:
 * @self: platform instance
 * @name: Interface name
 * @type: Interface type
 * @address: (allow-none): set the mac address of the link
 * @address_len: the length of the @address
 * @out_link: on success, the link object
 *
 * Add a software interface.  If the interface already exists and is of type
 * @type, sets platform->error to NM_PLATFORM_ERROR_EXISTS and returns the link
 * in @out_link.  If the interface already exists and is not of type @type,
 * sets platform->error to NM_PLATFORM_ERROR_WRONG_TYPE.  Any link-changed ADDED
 * signal will be emitted directly, before this function finishes.
 */
static gboolean
nm_platform_link_add (NMPlatform *self,
                      const char *name,
                      NMLinkType type,
                      const void *address,
                      size_t address_len,
                      NMPlatformLink *out_link)
{
	int ifindex;

	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (name, FALSE);
	g_return_val_if_fail (klass->link_add, FALSE);
	g_return_val_if_fail ( (address != NULL) ^ (address_len == 0) , FALSE);

	ifindex = nm_platform_link_get_ifindex (self, name);
	if (ifindex > 0) {
		debug ("link: already exists");
		if (nm_platform_link_get_type (self, ifindex) != type)
			self->error = NM_PLATFORM_ERROR_WRONG_TYPE;
		else {
			self->error = NM_PLATFORM_ERROR_EXISTS;
			(void) nm_platform_link_get (self, ifindex, out_link);
		}
		return FALSE;
	}

	reset_error(self);
	return klass->link_add (self, name, type, address, address_len, out_link);
}

/**
 * nm_platform_dummy_add:
 * @self: platform instance
 * @name: New interface name
 * @out_link: on success, the link object
 *
 * Create a software ethernet-like interface
 */
gboolean
nm_platform_dummy_add (NMPlatform *self, const char *name, NMPlatformLink *out_link)
{
	g_return_val_if_fail (name, FALSE);

	debug ("link: adding dummy '%s'", name);
	return nm_platform_link_add (self, name, NM_LINK_TYPE_DUMMY, NULL, 0, out_link);
}

/**
 * nm_platform_link_exists:
 * @self: platform instance
 * @name: Interface name
 *
 * Returns: %TRUE if an interface of this name exists, %FALSE otherwise.
 */
gboolean
nm_platform_link_exists (NMPlatform *self, const char *name)
{
	int ifindex;

	_CHECK_SELF (self, klass, FALSE);

	ifindex = nm_platform_link_get_ifindex (self, name);

	reset_error (self);
	return ifindex > 0;
}

/**
 * nm_platform_link_delete:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Delete a software interface. Sets self->error to
 * NM_PLATFORM_ERROR_NOT_FOUND if ifindex not available.
 */
gboolean
nm_platform_link_delete (NMPlatform *self, int ifindex)
{
	const char *name;

	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (klass->link_delete, FALSE);

	name = nm_platform_link_get_name (self, ifindex);

	if (!name)
		return FALSE;

	debug ("link: deleting '%s' (%d)", name, ifindex);
	return klass->link_delete (self, ifindex);
}

/**
 * nm_platform_link_get_index:
 * @self: platform instance
 * @name: Interface name
 *
 * Returns: The interface index corresponding to the given interface name
 * or 0. Inteface name is owned by #NMPlatform, don't free it.
 */
int
nm_platform_link_get_ifindex (NMPlatform *self, const char *name)
{
	int ifindex;

	_CHECK_SELF (self, klass, 0);
	reset_error (self);

	g_return_val_if_fail (name, 0);
	g_return_val_if_fail (klass->link_get_ifindex, 0);

	ifindex = klass->link_get_ifindex (self, name);

	if (!ifindex) {
		debug ("link not found: %s", name);
		self->error = NM_PLATFORM_ERROR_NOT_FOUND;
	}

	return ifindex;
}

/**
 * nm_platform_link_get_name:
 * @self: platform instance
 * @name: Interface name
 *
 * Returns: The interface name corresponding to the given interface index
 * or %NULL.
 */
const char *
nm_platform_link_get_name (NMPlatform *self, int ifindex)
{
	const char *name;

	_CHECK_SELF (self, klass, NULL);
	reset_error (self);

	g_return_val_if_fail (klass->link_get_name, NULL);

	name = klass->link_get_name (self, ifindex);

	if (!name) {
		debug ("link not found: %d", ifindex);
		self->error = NM_PLATFORM_ERROR_NOT_FOUND;
		return FALSE;
	}

	return name;
}

/**
 * nm_platform_link_get_type:
 * @self: platform instance
 * @ifindex: Interface index.
 *
 * Returns: Link type constant as defined in nm-platform.h. On error,
 * NM_LINK_TYPE_NONE is returned.
 */
NMLinkType
nm_platform_link_get_type (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, NM_LINK_TYPE_NONE);
	reset_error (self);

	g_return_val_if_fail (klass->link_get_type, NM_LINK_TYPE_NONE);

	return klass->link_get_type (self, ifindex);
}

/**
 * nm_platform_link_get_type_name:
 * @self: platform instance
 * @ifindex: Interface index.
 *
 * Returns: A string describing the type of link. In some cases this
 * may be more specific than nm_platform_link_get_type(), but in
 * other cases it may not. On error, %NULL is returned.
 */
const char *
nm_platform_link_get_type_name (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, NULL);
	reset_error (self);

	g_return_val_if_fail (klass->link_get_type_name, NULL);

	return klass->link_get_type_name (self, ifindex);
}

/**
 * nm_platform_link_get_unmanaged:
 * @self: platform instance
 * @ifindex: Interface index.
 * @managed: Management status in case %TRUE is returned
 *
 * Returns: %TRUE if platform overrides whether the device ought
 * to be managed by default. %FALSE with @managed unmodified
 * otherwise.
 */
gboolean
nm_platform_link_get_unmanaged (NMPlatform *self, int ifindex, gboolean *managed)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (klass->link_get_unmanaged, FALSE);

	return klass->link_get_unmanaged (self, ifindex, managed);
}

/**
 * nm_platform_link_is_software:
 * @self: platform instance
 * @ifindex: Interface index.
 *
 * Returns: %TRUE if ifindex belongs to a software interface, not backed by
 * a physical device.
 */
gboolean
nm_platform_link_is_software (NMPlatform *self, int ifindex)
{
	return (nm_platform_link_get_type (self, ifindex) & 0x10000);
}

/**
 * nm_platform_link_supports_slaves:
 * @self: platform instance
 * @ifindex: Interface index.
 *
 * Returns: %TRUE if ifindex belongs to an interface capable of enslaving
 * other interfaces.
 */
gboolean
nm_platform_link_supports_slaves (NMPlatform *self, int ifindex)
{
	return (nm_platform_link_get_type (self, ifindex) & 0x20000);
}

/**
 * nm_platform_link_refresh:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Reload the cache for ifindex synchronously.
 */
gboolean
nm_platform_link_refresh (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);

	if (klass->link_refresh)
		return klass->link_refresh (self, ifindex);

	return TRUE;
}

/**
 * nm_platform_link_is_up:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Check if the interface is up.
 */
gboolean
nm_platform_link_is_up (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_is_up, FALSE);

	return klass->link_is_up (self, ifindex);
}

/**
 * nm_platform_link_is_connected:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Check if the interface is connected.
 */
gboolean
nm_platform_link_is_connected (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_is_connected, FALSE);

	return klass->link_is_connected (self, ifindex);
}

/**
 * nm_platform_link_uses_arp:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Check if the interface is configured to use ARP.
 */
gboolean
nm_platform_link_uses_arp (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_uses_arp, FALSE);

	return klass->link_uses_arp (self, ifindex);
}

/**
 * nm_platform_link_get_ipv6_token:
 * @self: platform instance
 * @ifindex: Interface index
 * @iid: Tokenized interface identifier
 *
 * Returns IPv6 tokenized interface identifier. If the platform or OS doesn't
 * support IPv6 tokenized interface identifiers, or the token is not set
 * this call will fail and return %FALSE.
 *
 * Returns: %TRUE a tokenized identifier was available
 */
gboolean
nm_platform_link_get_ipv6_token (NMPlatform *self, int ifindex, NMUtilsIPv6IfaceId *iid)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (iid, FALSE);

	if (klass->link_get_ipv6_token)
		return klass->link_get_ipv6_token (self, ifindex, iid);
	return FALSE;
}


/**
 * nm_platform_link_get_user_ip6vll_enabled:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Check whether NM handles IPv6LL address creation for the link.  If the
 * platform or OS doesn't support changing the IPv6LL address mode, this call
 * will fail and return %FALSE.
 *
 * Returns: %TRUE if NM handles the IPv6LL address for @ifindex
 */
gboolean
nm_platform_link_get_user_ipv6ll_enabled (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->check_support_user_ipv6ll, FALSE);

	if (klass->link_get_user_ipv6ll_enabled)
		return klass->link_get_user_ipv6ll_enabled (self, ifindex);
	return FALSE;
}

/**
 * nm_platform_link_set_user_ip6vll_enabled:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Set whether NM handles IPv6LL address creation for the link.  If the
 * platform or OS doesn't support changing the IPv6LL address mode, this call
 * will fail and return %FALSE.
 *
 * Returns: %TRUE if the operation was successful, %FALSE if it failed.
 */
gboolean
nm_platform_link_set_user_ipv6ll_enabled (NMPlatform *self, int ifindex, gboolean enabled)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->check_support_user_ipv6ll, FALSE);

	if (klass->link_set_user_ipv6ll_enabled)
		return klass->link_set_user_ipv6ll_enabled (self, ifindex, enabled);
	return FALSE;
}

/**
 * nm_platform_link_set_address:
 * @self: platform instance
 * @ifindex: Interface index
 * @address: The new MAC address
 *
 * Set interface MAC address.
 */
gboolean
nm_platform_link_set_address (NMPlatform *self, int ifindex, gconstpointer address, size_t length)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (address, FALSE);
	g_return_val_if_fail (length > 0, FALSE);
	g_return_val_if_fail (klass->link_set_address, FALSE);

	debug ("link: setting '%s' (%d) hardware address", nm_platform_link_get_name (self, ifindex), ifindex);
	return klass->link_set_address (self, ifindex, address, length);
}

/**
 * nm_platform_link_get_address:
 * @self: platform instance
 * @ifindex: Interface index
 * @length: Pointer to a variable to store address length
 *
 * Returns: the interface hardware address as an array of bytes of
 * length @length.
 */
gconstpointer
nm_platform_link_get_address (NMPlatform *self, int ifindex, size_t *length)
{
	_CHECK_SELF (self, klass, NULL);
	reset_error (self);

	if (length)
		*length = 0;

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (klass->link_get_address, NULL);

	return klass->link_get_address (self, ifindex, length);
}

/**
 * nm_platform_link_get_permanent_address:
 * @self: platform instance
 * @ifindex: Interface index
 * @buf: buffer of at least %NM_UTILS_HWADDR_LEN_MAX bytes, on success
 * the permanent hardware address
 * @length: Pointer to a variable to store address length
 *
 * Returns: %TRUE on success, %FALSE on failure to read the permanent hardware
 * address.
 */
gboolean
nm_platform_link_get_permanent_address (NMPlatform *self, int ifindex, guint8 *buf, size_t *length)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	if (length)
		*length = 0;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (klass->link_get_permanent_address, FALSE);
	g_return_val_if_fail (buf, FALSE);
	g_return_val_if_fail (length, FALSE);

	return klass->link_get_permanent_address (self, ifindex, buf, length);
}

gboolean
nm_platform_link_supports_carrier_detect (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_supports_carrier_detect, FALSE);

	return klass->link_supports_carrier_detect (self, ifindex);
}

gboolean
nm_platform_link_supports_vlans (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_supports_vlans, FALSE);

	return klass->link_supports_vlans (self, ifindex);
}

/**
 * nm_platform_link_set_up:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Bring the interface up.
 */
gboolean
nm_platform_link_set_up (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (klass->link_set_up, FALSE);

	debug ("link: setting up '%s' (%d)", nm_platform_link_get_name (self, ifindex), ifindex);
	return klass->link_set_up (self, ifindex);
}

/**
 * nm_platform_link_set_down:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Take the interface down.
 */
gboolean
nm_platform_link_set_down (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (klass->link_set_down, FALSE);

	debug ("link: setting down '%s' (%d)", nm_platform_link_get_name (self, ifindex), ifindex);
	return klass->link_set_down (self, ifindex);
}

/**
 * nm_platform_link_set_arp:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Enable ARP on the interface.
 */
gboolean
nm_platform_link_set_arp (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_set_arp, FALSE);

	debug ("link: setting arp '%s' (%d)", nm_platform_link_get_name (self, ifindex), ifindex);
	return klass->link_set_arp (self, ifindex);
}

/**
 * nm_platform_link_set_noarp:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Disable ARP on the interface.
 */
gboolean
nm_platform_link_set_noarp (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_set_noarp, FALSE);

	debug ("link: setting noarp '%s' (%d)", nm_platform_link_get_name (self, ifindex), ifindex);
	return klass->link_set_noarp (self, ifindex);
}

/**
 * nm_platform_link_set_mtu:
 * @self: platform instance
 * @ifindex: Interface index
 * @mtu: The new MTU value
 *
 * Set interface MTU.
 */
gboolean
nm_platform_link_set_mtu (NMPlatform *self, int ifindex, guint32 mtu)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (mtu > 0, FALSE);
	g_return_val_if_fail (klass->link_set_mtu, FALSE);

	debug ("link: setting '%s' (%d) mtu %"G_GUINT32_FORMAT, nm_platform_link_get_name (self, ifindex), ifindex, mtu);
	return klass->link_set_mtu (self, ifindex, mtu);
}

/**
 * nm_platform_link_get_mtu:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Returns: MTU value for the interface or 0 on error.
 */
guint32
nm_platform_link_get_mtu (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, 0);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, 0);
	g_return_val_if_fail (klass->link_get_mtu, 0);

	return klass->link_get_mtu (self, ifindex);
}

/**
 * nm_platform_link_get_physical_port_id:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * The physical port ID, if present, indicates some unique identifier of
 * the parent interface (eg, the physical port of which this link is a child).
 * Two links that report the same physical port ID can be assumed to be
 * children of the same physical port and may share resources that limit
 * their abilities.
 *
 * Returns: physical port ID for the interface, or %NULL on error
 * or if the interface has no physical port ID.
 */
char *
nm_platform_link_get_physical_port_id (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, NULL);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, NULL);
	g_return_val_if_fail (klass->link_get_physical_port_id, NULL);

	return klass->link_get_physical_port_id (self, ifindex);
}

/**
 * nm_platform_link_get_dev_id:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * In contrast to the physical device ID (which indicates which parent a
 * child has) the device ID differentiates sibling devices that may share
 * the same MAC address.
 *
 * Returns: device ID for the interface, or 0 on error or if the
 * interface has no device ID.
 */
guint
nm_platform_link_get_dev_id (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, 0);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, 0);
	g_return_val_if_fail (klass->link_get_dev_id, 0);

	return klass->link_get_dev_id (self, ifindex);
}

/**
 * nm_platform_link_get_wake_onlan:
 * @self: platform instance
 * @ifindex: Interface index
 *
 * Returns: the "Wake-on-LAN" status for @ifindex.
 */
gboolean
nm_platform_link_get_wake_on_lan (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_get_wake_on_lan, FALSE);

	return klass->link_get_wake_on_lan (self, ifindex);
}

/**
 * nm_platform_link_get_driver_info:
 * @self: platform instance
 * @ifindex: Interface index
 * @out_driver_name: (transfer full): on success, the driver name if available
 * @out_driver_version: (transfer full): on success, the driver version if available
 * @out_fw_version: (transfer full): on success, the firmware version if available
 *
 * Returns: %TRUE on success (though @out_driver_name, @out_driver_version and
 * @out_fw_version can be %NULL if no information was available), %FALSE on
 * failure.
 */
gboolean
nm_platform_link_get_driver_info (NMPlatform *self,
                                  int ifindex,
                                  char **out_driver_name,
                                  char **out_driver_version,
                                  char **out_fw_version)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_get_driver_info, FALSE);

	return klass->link_get_driver_info (self,
	                                    ifindex,
	                                    out_driver_name,
	                                    out_driver_version,
	                                    out_fw_version);
}

/**
 * nm_platform_link_enslave:
 * @self: platform instance
 * @master: Interface index of the master
 * @slave: Interface index of the slave
 *
 * Enslave @slave to @master.
 */
gboolean
nm_platform_link_enslave (NMPlatform *self, int master, int slave)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (master > 0, FALSE);
	g_return_val_if_fail (slave> 0, FALSE);
	g_return_val_if_fail (klass->link_enslave, FALSE);

	debug ("link: enslaving '%s' (%d) to master '%s' (%d)",
	       nm_platform_link_get_name (self, slave), slave,
	       nm_platform_link_get_name (self, master), master);
	return klass->link_enslave (self, master, slave);
}

/**
 * nm_platform_link_release:
 * @self: platform instance
 * @master: Interface index of the master
 * @slave: Interface index of the slave
 *
 * Release @slave from @master.
 */
gboolean
nm_platform_link_release (NMPlatform *self, int master, int slave)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (master > 0, FALSE);
	g_return_val_if_fail (slave > 0, FALSE);
	g_return_val_if_fail (klass->link_release, FALSE);

	if (nm_platform_link_get_master (self, slave) != master) {
		self->error = NM_PLATFORM_ERROR_NOT_SLAVE;
		return FALSE;
	}

	debug ("link: releasing '%s' (%d) from master '%s' (%d)",
	       nm_platform_link_get_name (self, slave), slave,
	       nm_platform_link_get_name (self, master), master);
	return klass->link_release (self, master, slave);
}

/**
 * nm_platform_link_get_master:
 * @self: platform instance
 * @slave: Interface index of the slave.
 *
 * Returns: Interfase index of the slave's master.
 */
int
nm_platform_link_get_master (NMPlatform *self, int slave)
{
	_CHECK_SELF (self, klass, 0);
	reset_error (self);

	g_return_val_if_fail (slave >= 0, FALSE);
	g_return_val_if_fail (klass->link_get_master, FALSE);

	if (!nm_platform_link_get_name (self, slave)) {
		self->error = NM_PLATFORM_ERROR_NOT_FOUND;
		return 0;
	}
	return klass->link_get_master (self, slave);
}

/**
 * nm_platform_bridge_add:
 * @self: platform instance
 * @name: New interface name
 * @address: (allow-none): set the mac address of the new bridge
 * @address_len: the length of the @address
 * @out_link: on success, the link object
 *
 * Create a software bridge.
 */
gboolean
nm_platform_bridge_add (NMPlatform *self,
                        const char *name,
                        const void *address,
                        size_t address_len,
                        NMPlatformLink *out_link)
{
	debug ("link: adding bridge '%s'", name);
	return nm_platform_link_add (self, name, NM_LINK_TYPE_BRIDGE, address, address_len, out_link);
}

/**
 * nm_platform_bond_add:
 * @self: platform instance
 * @name: New interface name
 * @out_link: on success, the link object
 *
 * Create a software bonding device.
 */
gboolean
nm_platform_bond_add (NMPlatform *self, const char *name, NMPlatformLink *out_link)
{
	debug ("link: adding bond '%s'", name);
	return nm_platform_link_add (self, name, NM_LINK_TYPE_BOND, NULL, 0, out_link);
}

/**
 * nm_platform_team_add:
 * @self: platform instance
 * @name: New interface name
 * @out_link: on success, the link object
 *
 * Create a software teaming device.
 */
gboolean
nm_platform_team_add (NMPlatform *self, const char *name, NMPlatformLink *out_link)
{
	debug ("link: adding team '%s'", name);
	return nm_platform_link_add (self, name, NM_LINK_TYPE_TEAM, NULL, 0, out_link);
}

/**
 * nm_platform_vlan_add:
 * @self: platform instance
 * @name: New interface name
 * @vlanid: VLAN identifier
 * @vlanflags: VLAN flags from libnm
 * @out_link: on success, the link object
 *
 * Create a software VLAN device.
 */
gboolean
nm_platform_vlan_add (NMPlatform *self,
                      const char *name,
                      int parent,
                      int vlanid,
                      guint32 vlanflags,
                      NMPlatformLink *out_link)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (parent >= 0, FALSE);
	g_return_val_if_fail (vlanid >= 0, FALSE);
	g_return_val_if_fail (name, FALSE);
	g_return_val_if_fail (klass->vlan_add, FALSE);

	if (nm_platform_link_exists (self, name)) {
		debug ("link already exists: %s", name);
		self->error = NM_PLATFORM_ERROR_EXISTS;
		return FALSE;
	}

	debug ("link: adding vlan '%s' parent %d vlanid %d vlanflags %x",
		name, parent, vlanid, vlanflags);
	return klass->vlan_add (self, name, parent, vlanid, vlanflags, out_link);
}

gboolean
nm_platform_master_set_option (NMPlatform *self, int ifindex, const char *option, const char *value)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);
	g_return_val_if_fail (value, FALSE);
	g_return_val_if_fail (klass->master_set_option, FALSE);

	return klass->master_set_option (self, ifindex, option, value);
}

char *
nm_platform_master_get_option (NMPlatform *self, int ifindex, const char *option)
{
	_CHECK_SELF (self, klass, NULL);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);
	g_return_val_if_fail (klass->master_set_option, FALSE);

	return klass->master_get_option (self, ifindex, option);
}

gboolean
nm_platform_slave_set_option (NMPlatform *self, int ifindex, const char *option, const char *value)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);
	g_return_val_if_fail (value, FALSE);
	g_return_val_if_fail (klass->slave_set_option, FALSE);

	return klass->slave_set_option (self, ifindex, option, value);
}

char *
nm_platform_slave_get_option (NMPlatform *self, int ifindex, const char *option)
{
	_CHECK_SELF (self, klass, NULL);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);
	g_return_val_if_fail (klass->slave_set_option, FALSE);

	return klass->slave_get_option (self, ifindex, option);
}

gboolean
nm_platform_vlan_get_info (NMPlatform *self, int ifindex, int *parent, int *vlanid)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (klass->vlan_get_info, FALSE);

	if (parent)
		*parent = 0;
	if (vlanid)
		*vlanid = 0;

	if (nm_platform_link_get_type (self, ifindex) != NM_LINK_TYPE_VLAN)
		return FALSE;

	return klass->vlan_get_info (self, ifindex, parent, vlanid);
}

gboolean
nm_platform_vlan_set_ingress_map (NMPlatform *self, int ifindex, int from, int to)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (klass->vlan_set_ingress_map, FALSE);

	debug ("link: setting vlan ingress map for %d from %d to %d", ifindex, from, to);
	return klass->vlan_set_ingress_map (self, ifindex, from, to);
}

gboolean
nm_platform_vlan_set_egress_map (NMPlatform *self, int ifindex, int from, int to)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (klass->vlan_set_egress_map, FALSE);

	debug ("link: setting vlan egress map for %d from %d to %d", ifindex, from, to);
	return klass->vlan_set_egress_map (self, ifindex, from, to);
}

gboolean
nm_platform_infiniband_partition_add (NMPlatform *self, int parent, int p_key, NMPlatformLink *out_link)
{
	const char *parent_name;
	char *name;

	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (parent >= 0, FALSE);
	g_return_val_if_fail (p_key >= 0, FALSE);
	g_return_val_if_fail (klass->infiniband_partition_add, FALSE);

	if (nm_platform_link_get_type (self, parent) != NM_LINK_TYPE_INFINIBAND) {
		self->error = NM_PLATFORM_ERROR_WRONG_TYPE;
		return FALSE;
	}

	parent_name = nm_platform_link_get_name (self, parent);
	name = g_strdup_printf ("%s.%04x", parent_name, p_key);
	if (nm_platform_link_exists (self, name)) {
		debug ("infiniband: already exists");
		self->error = NM_PLATFORM_ERROR_EXISTS;
		g_free (name);
		return FALSE;
	}
	g_free (name);

	return klass->infiniband_partition_add (self, parent, p_key, out_link);
}

gboolean
nm_platform_infiniband_get_info (NMPlatform *self,
                                 int ifindex,
                                 int *parent,
                                 int *p_key,
                                 const char **mode)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (klass->infiniband_get_info, FALSE);

	return klass->infiniband_get_info (self, ifindex, parent, p_key, mode);
}

gboolean
nm_platform_veth_get_properties (NMPlatform *self, int ifindex, NMPlatformVethProperties *props)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	return klass->veth_get_properties (self, ifindex, props);
}

gboolean
nm_platform_tun_get_properties (NMPlatform *self, int ifindex, NMPlatformTunProperties *props)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	return klass->tun_get_properties (self, ifindex, props);
}

gboolean
nm_platform_macvlan_get_properties (NMPlatform *self, int ifindex, NMPlatformMacvlanProperties *props)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	return klass->macvlan_get_properties (self, ifindex, props);
}

gboolean
nm_platform_vxlan_get_properties (NMPlatform *self, int ifindex, NMPlatformVxlanProperties *props)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	return klass->vxlan_get_properties (self, ifindex, props);
}

gboolean
nm_platform_gre_get_properties (NMPlatform *self, int ifindex, NMPlatformGreProperties *props)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	return klass->gre_get_properties (self, ifindex, props);
}

gboolean
nm_platform_wifi_get_capabilities (NMPlatform *self, int ifindex, NMDeviceWifiCapabilities *caps)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);

	return klass->wifi_get_capabilities (self, ifindex, caps);
}

gboolean
nm_platform_wifi_get_bssid (NMPlatform *self, int ifindex, guint8 *bssid)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);

	return klass->wifi_get_bssid (self, ifindex, bssid);
}

guint32
nm_platform_wifi_get_frequency (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, 0);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, 0);

	return klass->wifi_get_frequency (self, ifindex);
}

int
nm_platform_wifi_get_quality (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, 0);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, 0);

	return klass->wifi_get_quality (self, ifindex);
}

guint32
nm_platform_wifi_get_rate (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, 0);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, 0);

	return klass->wifi_get_rate (self, ifindex);
}

NM80211Mode
nm_platform_wifi_get_mode (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, NM_802_11_MODE_UNKNOWN);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, NM_802_11_MODE_UNKNOWN);

	return klass->wifi_get_mode (self, ifindex);
}

void
nm_platform_wifi_set_mode (NMPlatform *self, int ifindex, NM80211Mode mode)
{
	_CHECK_SELF_VOID (self, klass);
	reset_error (self);

	g_return_if_fail (ifindex > 0);

	klass->wifi_set_mode (self, ifindex, mode);
}

static void
wifi_set_powersave (NMPlatform *p, int ifindex, guint32 powersave)
{
	/* empty */
}

void
nm_platform_wifi_set_powersave (NMPlatform *self, int ifindex, guint32 powersave)
{
	_CHECK_SELF_VOID (self, klass);
	reset_error (self);

	g_return_if_fail (ifindex > 0);

	klass->wifi_set_powersave (self, ifindex, powersave);
}

guint32
nm_platform_wifi_find_frequency (NMPlatform *self, int ifindex, const guint32 *freqs)
{
	_CHECK_SELF (self, klass, 0);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, 0);
	g_return_val_if_fail (freqs != NULL, 0);

	return klass->wifi_find_frequency (self, ifindex, freqs);
}

void
nm_platform_wifi_indicate_addressing_running (NMPlatform *self, int ifindex, gboolean running)
{
	_CHECK_SELF_VOID (self, klass);
	reset_error (self);

	g_return_if_fail (ifindex > 0);

	klass->wifi_indicate_addressing_running (self, ifindex, running);
}

guint32
nm_platform_mesh_get_channel (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, 0);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, 0);

	return klass->mesh_get_channel (self, ifindex);
}

gboolean
nm_platform_mesh_set_channel (NMPlatform *self, int ifindex, guint32 channel)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);

	return klass->mesh_set_channel (self, ifindex, channel);
}

gboolean
nm_platform_mesh_set_ssid (NMPlatform *self, int ifindex, const guint8 *ssid, gsize len)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (ssid != NULL, FALSE);

	return klass->mesh_set_ssid (self, ifindex, ssid, len);
}

#define TO_STRING_DEV_BUF_SIZE (5+15+1)
static const char *
_to_string_dev (NMPlatform *self, int ifindex, char *buf, size_t size)
{
	g_assert (buf && size >= TO_STRING_DEV_BUF_SIZE);

	if (ifindex) {
		const char *name = ifindex > 0 && self ? nm_platform_link_get_name (self, ifindex) : NULL;
		char *buf2;

		strcpy (buf, " dev ");
		buf2 = buf + 5;
		size -= 5;

		if (name)
			g_strlcpy (buf2, name, size);
		else
			g_snprintf (buf2, size, "%d", ifindex);
	} else
		buf[0] = 0;

	return buf;
}

/******************************************************************/

GArray *
nm_platform_ip4_address_get_all (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, NULL);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (klass->ip4_address_get_all, NULL);

	return klass->ip4_address_get_all (self, ifindex);
}

GArray *
nm_platform_ip6_address_get_all (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, NULL);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (klass->ip6_address_get_all, NULL);

	return klass->ip6_address_get_all (self, ifindex);
}

gboolean
nm_platform_ip4_address_add (NMPlatform *self,
	                         int ifindex,
                             in_addr_t address,
                             in_addr_t peer_address,
                             int plen,
                             guint32 lifetime,
                             guint32 preferred,
                             const char *label)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (lifetime > 0, FALSE);
	g_return_val_if_fail (preferred <= lifetime, FALSE);
	g_return_val_if_fail (klass->ip4_address_add, FALSE);
	g_return_val_if_fail (!label || strlen (label) < sizeof (((NMPlatformIP4Address *) NULL)->label), FALSE);

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM)) {
		NMPlatformIP4Address addr = { 0 };

		addr.ifindex = ifindex;
		addr.address = address;
		addr.peer_address = peer_address;
		addr.plen = plen;
		addr.timestamp = 0; /* set it at zero, which to_string will treat as *now* */
		addr.lifetime = lifetime;
		addr.preferred = preferred;
		if (label)
			g_strlcpy (addr.label, label, sizeof (addr.label));

		debug ("address: adding or updating IPv4 address: %s", nm_platform_ip4_address_to_string (&addr));
	}
	return klass->ip4_address_add (self, ifindex, address, peer_address, plen, lifetime, preferred, label);
}

gboolean
nm_platform_ip6_address_add (NMPlatform *self,
                             int ifindex,
                             struct in6_addr address,
                             struct in6_addr peer_address,
                             int plen,
                             guint32 lifetime,
                             guint32 preferred,
                             guint flags)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (lifetime > 0, FALSE);
	g_return_val_if_fail (preferred <= lifetime, FALSE);
	g_return_val_if_fail (klass->ip6_address_add, FALSE);

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM)) {
		NMPlatformIP6Address addr = { 0 };

		addr.ifindex = ifindex;
		addr.address = address;
		addr.peer_address = peer_address;
		addr.plen = plen;
		addr.timestamp = 0; /* set it to zero, which to_string will treat as *now* */
		addr.lifetime = lifetime;
		addr.preferred = preferred;
		addr.flags = flags;

		debug ("address: adding or updating IPv6 address: %s", nm_platform_ip6_address_to_string (&addr));
	}
	return klass->ip6_address_add (self, ifindex, address, peer_address, plen, lifetime, preferred, flags);
}

gboolean
nm_platform_ip4_address_delete (NMPlatform *self, int ifindex, in_addr_t address, int plen, in_addr_t peer_address)
{
	char str_dev[TO_STRING_DEV_BUF_SIZE];
	char str_peer[NM_UTILS_INET_ADDRSTRLEN];

	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (klass->ip4_address_delete, FALSE);

	debug ("address: deleting IPv4 address %s/%d, %s%s%sifindex %d%s",
	       nm_utils_inet4_ntop (address, NULL), plen,
	       peer_address ? "peer " : "",
	       peer_address ? nm_utils_inet4_ntop (peer_address, str_peer) : "",
	       peer_address ? ", " : "",
	       ifindex,
	       _to_string_dev (self, ifindex, str_dev, sizeof (str_dev)));
	return klass->ip4_address_delete (self, ifindex, address, plen, peer_address);
}

gboolean
nm_platform_ip6_address_delete (NMPlatform *self, int ifindex, struct in6_addr address, int plen)
{
	char str_dev[TO_STRING_DEV_BUF_SIZE];

	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (klass->ip6_address_delete, FALSE);

	debug ("address: deleting IPv6 address %s/%d, ifindex %d%s",
	       nm_utils_inet6_ntop (&address, NULL), plen, ifindex,
	       _to_string_dev (self, ifindex, str_dev, sizeof (str_dev)));
	return klass->ip6_address_delete (self, ifindex, address, plen);
}

gboolean
nm_platform_ip4_address_exists (NMPlatform *self, int ifindex, in_addr_t address, int plen)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (klass->ip4_address_exists, FALSE);

	return klass->ip4_address_exists (self, ifindex, address, plen);
}

gboolean
nm_platform_ip6_address_exists (NMPlatform *self, int ifindex, struct in6_addr address, int plen)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (klass->ip6_address_exists, FALSE);

	return klass->ip6_address_exists (self, ifindex, address, plen);
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

/**
 * Takes a pair @timestamp and @duration, and returns the remaining duration based
 * on the new timestamp @now.
 */
static guint32
_rebase_relative_time_on_now (guint32 timestamp, guint32 duration, guint32 now, guint32 padding)
{
	gint64 t;

	if (duration == NM_PLATFORM_LIFETIME_PERMANENT)
		return NM_PLATFORM_LIFETIME_PERMANENT;

	if (timestamp == 0) {
		/* if the @timestamp is zero, assume it was just left unset and that the relative
		 * @duration starts counting from @now. This is convenient to construct an address
		 * and print it in nm_platform_ip4_address_to_string().
		 *
		 * In general it does not make sense to set the @duration without anchoring at
		 * @timestamp because you don't know the absolute expiration time when looking
		 * at the address at a later moment. */
		timestamp = now;
	}

	/* For timestamp > now, just accept it and calculate the expected(?) result. */
	t = (gint64) timestamp + (gint64) duration - (gint64) now;

	/* Optional padding to avoid potential races. */
	t += (gint64) padding;

	if (t <= 0)
		return 0;
	if (t >= NM_PLATFORM_LIFETIME_PERMANENT)
		return NM_PLATFORM_LIFETIME_PERMANENT - 1;
	return t;
}

static gboolean
_address_get_lifetime (const NMPlatformIPAddress *address, guint32 now, guint32 padding, guint32 *out_lifetime, guint32 *out_preferred)
{
	guint32 lifetime, preferred;

	if (address->lifetime == 0) {
		*out_lifetime = NM_PLATFORM_LIFETIME_PERMANENT;
		*out_preferred = NM_PLATFORM_LIFETIME_PERMANENT;

		/* We treat lifetime==0 as permanent addresses to allow easy creation of such addresses
		 * (without requiring to set the lifetime fields to NM_PLATFORM_LIFETIME_PERMANENT).
		 * In that case we also expect that the other fields (timestamp and preferred) are left unset. */
		g_return_val_if_fail (address->timestamp == 0 && address->preferred == 0, TRUE);
	} else {
		lifetime = _rebase_relative_time_on_now (address->timestamp, address->lifetime, now, padding);
		if (!lifetime)
			return FALSE;
		preferred = _rebase_relative_time_on_now (address->timestamp, address->preferred, now, padding);

		*out_lifetime = lifetime;
		*out_preferred = MIN (preferred, lifetime);

		/* Assert that non-permanent addresses have a (positive) @timestamp. _rebase_relative_time_on_now()
		 * treats addresses with timestamp 0 as *now*. Addresses passed to _address_get_lifetime() always
		 * should have a valid @timestamp, otherwise on every re-sync, their lifetime will be extended anew.
		 */
		g_return_val_if_fail (   address->timestamp != 0
		                      || (   address->lifetime  == NM_PLATFORM_LIFETIME_PERMANENT
		                          && address->preferred == NM_PLATFORM_LIFETIME_PERMANENT), TRUE);
		g_return_val_if_fail (preferred <= lifetime, TRUE);
	}
	return TRUE;
}

gboolean
nm_platform_ip4_check_reinstall_device_route (NMPlatform *self, int ifindex, const NMPlatformIP4Address *address, guint32 device_route_metric)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	if (   ifindex <= 0
	    || address->plen <= 0
	    || address->plen >= 32)
		return FALSE;

	if (device_route_metric == NM_PLATFORM_ROUTE_METRIC_IP4_DEVICE_ROUTE) {
		/* The automatically added route would be already our desired priority.
		 * Nothing to do. */
		return FALSE;
	}

	return klass->ip4_check_reinstall_device_route (self, ifindex, address, device_route_metric);
}

/**
 * nm_platform_ip4_address_sync:
 * @self: platform instance
 * @ifindex: Interface index
 * @known_addresses: List of addresses
 * @device_route_metric: the route metric for adding subnet routes (replaces
 *   the kernel added routes).
 *
 * A convenience function to synchronize addresses for a specific interface
 * with the least possible disturbance. It simply removes addresses that are
 * not listed and adds addresses that are.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_ip4_address_sync (NMPlatform *self, int ifindex, const GArray *known_addresses, guint32 device_route_metric)
{
	GArray *addresses;
	NMPlatformIP4Address *address;
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	int i;

	_CHECK_SELF (self, klass, FALSE);

	/* Delete unknown addresses */
	addresses = nm_platform_ip4_address_get_all (self, ifindex);
	for (i = 0; i < addresses->len; i++) {
		address = &g_array_index (addresses, NMPlatformIP4Address, i);

		if (!array_contains_ip4_address (known_addresses, address))
			nm_platform_ip4_address_delete (self, ifindex, address->address, address->plen, address->peer_address);
	}
	g_array_free (addresses, TRUE);

	if (!known_addresses)
		return TRUE;

	/* Add missing addresses */
	for (i = 0; i < known_addresses->len; i++) {
		const NMPlatformIP4Address *known_address = &g_array_index (known_addresses, NMPlatformIP4Address, i);
		guint32 lifetime, preferred;
		guint32 network;
		gboolean reinstall_device_route = FALSE;

		/* add a padding of 5 seconds to avoid potential races. */
		if (!_address_get_lifetime ((NMPlatformIPAddress *) known_address, now, 5, &lifetime, &preferred))
			continue;

		if (nm_platform_ip4_check_reinstall_device_route (self, ifindex, known_address, device_route_metric))
			reinstall_device_route = TRUE;

		if (!nm_platform_ip4_address_add (self, ifindex, known_address->address, known_address->peer_address, known_address->plen, lifetime, preferred, known_address->label))
			return FALSE;

		if (reinstall_device_route) {
			/* Kernel automatically adds a device route for us with metric 0. That is not what we want.
			 * Remove it, and re-add it.
			 *
			 * In face of having the same subnets on two different interfaces with the same metric,
			 * this is a problem. Surprisingly, kernel is able to add two routes for the same subnet/prefix,metric
			 * to different interfaces. We cannot. Adding one, would replace the other. This is avoided
			 * by the above nm_platform_ip4_check_reinstall_device_route() check.
			 */
			network = nm_utils_ip4_address_clear_host_address (known_address->address, known_address->plen);
			(void) nm_platform_ip4_route_add (self, ifindex, NM_IP_CONFIG_SOURCE_KERNEL, network, known_address->plen,
			                                  0, known_address->address, device_route_metric, 0);
			(void) nm_platform_ip4_route_delete (self, ifindex, network, known_address->plen,
			                                     NM_PLATFORM_ROUTE_METRIC_IP4_DEVICE_ROUTE);
		}
	}

	return TRUE;
}

/**
 * nm_platform_ip6_address_sync:
 * @self: platform instance
 * @ifindex: Interface index
 * @known_addresses: List of addresses
 * @keep_link_local: Don't remove link-local address
 *
 * A convenience function to synchronize addresses for a specific interface
 * with the least possible disturbance. It simply removes addresses that are
 * not listed and adds addresses that are.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_ip6_address_sync (NMPlatform *self, int ifindex, const GArray *known_addresses, gboolean keep_link_local)
{
	GArray *addresses;
	NMPlatformIP6Address *address;
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	int i;

	/* Delete unknown addresses */
	addresses = nm_platform_ip6_address_get_all (self, ifindex);
	for (i = 0; i < addresses->len; i++) {
		address = &g_array_index (addresses, NMPlatformIP6Address, i);

		/* Leave link local address management to the kernel */
		if (keep_link_local && IN6_IS_ADDR_LINKLOCAL (&address->address))
			continue;

		if (!array_contains_ip6_address (known_addresses, address))
			nm_platform_ip6_address_delete (self, ifindex, address->address, address->plen);
	}
	g_array_free (addresses, TRUE);

	if (!known_addresses)
		return TRUE;

	/* Add missing addresses */
	for (i = 0; i < known_addresses->len; i++) {
		const NMPlatformIP6Address *known_address = &g_array_index (known_addresses, NMPlatformIP6Address, i);
		guint32 lifetime, preferred;

		/* add a padding of 5 seconds to avoid potential races. */
		if (!_address_get_lifetime ((NMPlatformIPAddress *) known_address, now, 5, &lifetime, &preferred))
			continue;

		if (!nm_platform_ip6_address_add (self, ifindex, known_address->address,
		                                  known_address->peer_address, known_address->plen,
		                                  lifetime, preferred, known_address->flags))
			return FALSE;
	}

	return TRUE;
}

gboolean
nm_platform_address_flush (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);

	return nm_platform_ip4_address_sync (self, ifindex, NULL, 0)
			&& nm_platform_ip6_address_sync (self, ifindex, NULL, FALSE);
}

/******************************************************************/

GArray *
nm_platform_ip4_route_get_all (NMPlatform *self, int ifindex, NMPlatformGetRouteMode mode)
{
	_CHECK_SELF (self, klass, NULL);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, NULL);
	g_return_val_if_fail (klass->ip4_route_get_all, NULL);

	return klass->ip4_route_get_all (self, ifindex, mode);
}

GArray *
nm_platform_ip6_route_get_all (NMPlatform *self, int ifindex, NMPlatformGetRouteMode mode)
{
	_CHECK_SELF (self, klass, NULL);
	reset_error (self);

	g_return_val_if_fail (ifindex >= 0, NULL);
	g_return_val_if_fail (klass->ip6_route_get_all, NULL);

	return klass->ip6_route_get_all (self, ifindex, mode);
}

gboolean
nm_platform_ip4_route_add (NMPlatform *self,
                           int ifindex, NMIPConfigSource source,
                           in_addr_t network, int plen,
                           in_addr_t gateway, guint32 pref_src,
                           guint32 metric, guint32 mss)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (0 <= plen && plen <= 32, FALSE);
	g_return_val_if_fail (klass->ip4_route_add, FALSE);

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM)) {
		NMPlatformIP4Route route = { 0 };
		char pref_src_buf[NM_UTILS_INET_ADDRSTRLEN];

		route.ifindex = ifindex;
		route.source = source;
		route.network = network;
		route.plen = plen;
		route.gateway = gateway;
		route.metric = metric;
		route.mss = mss;

		debug ("route: adding or updating IPv4 route: %s%s%s%s", nm_platform_ip4_route_to_string (&route),
		       pref_src ? " (src: " : "",
		       pref_src ? nm_utils_inet4_ntop (pref_src, pref_src_buf) : "",
		       pref_src ? ")" : "");
	}
	return klass->ip4_route_add (self, ifindex, source, network, plen, gateway, pref_src, metric, mss);
}

gboolean
nm_platform_ip6_route_add (NMPlatform *self,
                           int ifindex, NMIPConfigSource source,
                           struct in6_addr network, int plen, struct in6_addr gateway,
                           guint32 metric, guint32 mss)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (0 <= plen && plen <= 128, FALSE);
	g_return_val_if_fail (klass->ip6_route_add, FALSE);

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM)) {
		NMPlatformIP6Route route = { 0 };

		route.ifindex = ifindex;
		route.source = source;
		route.network = network;
		route.plen = plen;
		route.gateway = gateway;
		route.metric = metric;
		route.mss = mss;

		debug ("route: adding or updating IPv6 route: %s", nm_platform_ip6_route_to_string (&route));
	}
	return klass->ip6_route_add (self, ifindex, source, network, plen, gateway, metric, mss);
}

gboolean
nm_platform_ip4_route_delete (NMPlatform *self, int ifindex, in_addr_t network, int plen, guint32 metric)
{
	char str_dev[TO_STRING_DEV_BUF_SIZE];

	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (klass->ip4_route_delete, FALSE);

	debug ("route: deleting IPv4 route %s/%d, metric=%"G_GUINT32_FORMAT", ifindex %d%s",
	       nm_utils_inet4_ntop (network, NULL), plen, metric, ifindex,
	       _to_string_dev (self, ifindex, str_dev, sizeof (str_dev)));
	return klass->ip4_route_delete (self, ifindex, network, plen, metric);
}

gboolean
nm_platform_ip6_route_delete (NMPlatform *self, int ifindex, struct in6_addr network, int plen, guint32 metric)
{
	char str_dev[TO_STRING_DEV_BUF_SIZE];

	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (klass->ip6_route_delete, FALSE);

	debug ("route: deleting IPv6 route %s/%d, metric=%"G_GUINT32_FORMAT", ifindex %d%s",
	       nm_utils_inet6_ntop (&network, NULL), plen, metric, ifindex,
	       _to_string_dev (self, ifindex, str_dev, sizeof (str_dev)));
	return klass->ip6_route_delete (self, ifindex, network, plen, metric);
}

gboolean
nm_platform_ip4_route_exists (NMPlatform *self, int ifindex, in_addr_t network, int plen, guint32 metric)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (klass->ip4_route_exists, FALSE);

	return klass->ip4_route_exists (self ,ifindex, network, plen, metric);
}

gboolean
nm_platform_ip6_route_exists (NMPlatform *self, int ifindex, struct in6_addr network, int plen, guint32 metric)
{
	_CHECK_SELF (self, klass, FALSE);
	reset_error (self);

	g_return_val_if_fail (klass->ip6_route_exists, FALSE);

	return klass->ip6_route_exists (self, ifindex, network, plen, metric);
}

/******************************************************************/

static const char *
source_to_string (NMIPConfigSource source)
{
	switch (source) {
	case NM_IP_CONFIG_SOURCE_KERNEL:
		return "kernel";
	case NM_IP_CONFIG_SOURCE_SHARED:
		return "shared";
	case NM_IP_CONFIG_SOURCE_IP4LL:
		return "ipv4ll";
	case NM_IP_CONFIG_SOURCE_PPP:
		return "ppp";
	case NM_IP_CONFIG_SOURCE_WWAN:
		return "wwan";
	case NM_IP_CONFIG_SOURCE_VPN:
		return "vpn";
	case NM_IP_CONFIG_SOURCE_DHCP:
		return "dhcp";
	case NM_IP_CONFIG_SOURCE_RDISC:
		return "rdisc";
	case NM_IP_CONFIG_SOURCE_USER:
		return "user";
	default:
		break;
	}
	return "unknown";
}

static const char *
_lifetime_to_string (guint32 timestamp, guint32 lifetime, gint32 now, char *buf, size_t buf_size)
{
	if (lifetime == NM_PLATFORM_LIFETIME_PERMANENT)
		return "forever";

	g_snprintf (buf, buf_size, "%usec",
	            _rebase_relative_time_on_now (timestamp, lifetime, now, 0));
	return buf;
}


static const char *
_lifetime_summary_to_string (gint32 now, guint32 timestamp, guint32 preferred, guint32 lifetime, char *buf, size_t buf_size)
{
	g_snprintf (buf, buf_size, " lifetime %d-%u[%u,%u]",
	            (signed) now, (unsigned) timestamp, (unsigned) preferred, (unsigned) lifetime);
	return buf;
}

char _nm_platform_to_string_buffer[256];

const char *
nm_platform_link_to_string (const NMPlatformLink *link)
{
	char master[20];
	char parent[20];
	char str_flags[64];
	char *driver, *udi;
	char str_vlan[16];
	GString *str;

	if (!link)
		return "(unknown link)";

	str = g_string_new (NULL);
	if (!link->arp)
		g_string_append (str, "NOARP,");
	if (link->up)
		g_string_append (str, "UP");
	else
		g_string_append (str, "DOWN");
	if (link->connected)
		g_string_append (str, ",LOWER_UP");

	if (link->flags) {
		rtnl_link_flags2str (link->flags, str_flags, sizeof (str_flags));
		g_string_append_printf (str, ";%s", str_flags);
	}

	if (link->master)
		g_snprintf (master, sizeof (master), " master %d", link->master);
	else
		master[0] = 0;

	if (link->parent)
		g_snprintf (parent, sizeof (master), "@%d", link->parent);
	else
		parent[0] = 0;

	if (link->vlan_id)
		g_snprintf (str_vlan, sizeof (str_vlan), " vlan %u", (guint) link->vlan_id);
	else
		str_vlan[0] = '\0';

	driver = link->driver ? g_strdup_printf (" driver '%s'", link->driver) : NULL;
	udi = link->udi ? g_strdup_printf (" udi '%s'", link->udi) : NULL;

	g_snprintf (_nm_platform_to_string_buffer, sizeof (_nm_platform_to_string_buffer), "%d: %s%s <%s> mtu %d%s "
	            "%s" /* link->type */
	            "%s%s" /* kind */
	            "%s" /* vlan */
	            "%s%s",
	            link->ifindex, link->name, parent, str->str,
	            link->mtu, master,
	            nm_link_type_to_string (link->type),
	            link->type != NM_LINK_TYPE_UNKNOWN && link->kind ? " kind " : "",
	            link->type != NM_LINK_TYPE_UNKNOWN && link->kind ? link->kind : "",
	            str_vlan,
	            driver ? driver : "", udi ? udi : "");
	g_string_free (str, TRUE);
	g_free (driver);
	g_free (udi);
	return _nm_platform_to_string_buffer;
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
	char s_address[INET_ADDRSTRLEN];
	char s_peer[INET_ADDRSTRLEN];
	char str_dev[TO_STRING_DEV_BUF_SIZE];
	char str_label[32];
	char str_lft[30], str_pref[30], str_time[50];
	char *str_peer = NULL;
	const char *str_lft_p, *str_pref_p, *str_time_p;
	gint32 now = nm_utils_get_monotonic_timestamp_s ();

	g_return_val_if_fail (address, "(unknown)");

	inet_ntop (AF_INET, &address->address, s_address, sizeof (s_address));

	if (address->peer_address) {
		inet_ntop (AF_INET, &address->peer_address, s_peer, sizeof (s_peer));
		str_peer = g_strconcat (" ptp ", s_peer, NULL);
	}

	_to_string_dev (NULL, address->ifindex, str_dev, sizeof (str_dev));

	if (*address->label)
		g_snprintf (str_label, sizeof (str_label), " label %s", address->label);
	else
		str_label[0] = 0;

	str_lft_p = _lifetime_to_string (address->timestamp,
	                                 address->lifetime ? address->lifetime : NM_PLATFORM_LIFETIME_PERMANENT,
	                                 now, str_lft, sizeof (str_lft)),
	str_pref_p = (address->lifetime == address->preferred)
	             ? str_lft_p
	             : ( _lifetime_to_string (address->timestamp,
	                                      address->lifetime ? MIN (address->preferred, address->lifetime) : NM_PLATFORM_LIFETIME_PERMANENT,
	                                      now, str_pref, sizeof (str_pref)) );
	str_time_p = _lifetime_summary_to_string (now, address->timestamp, address->preferred, address->lifetime, str_time, sizeof (str_time));

	g_snprintf (_nm_platform_to_string_buffer, sizeof (_nm_platform_to_string_buffer), "%s/%d lft %s pref %s%s%s%s%s src %s",
	            s_address, address->plen, str_lft_p, str_pref_p, str_time_p,
	            str_peer ? str_peer : "",
	            str_dev,
	            str_label,
	            source_to_string (address->source));
	g_free (str_peer);
	return _nm_platform_to_string_buffer;
}

/**
 * nm_platform_addr_flags2str: wrapper for rtnl_addr_flags2str(),
 * which might not yet support some recent address flags.
 **/
void
nm_platform_addr_flags2str (int flags, char *buf, size_t size)
{
	rtnl_addr_flags2str(flags, buf, size);

	/* There are two recent flags IFA_F_MANAGETEMPADDR and IFA_F_NOPREFIXROUTE.
	 * If libnl does not yet support them, add them by hand.
	 * These two flags were introduced together with the extended ifa_flags,
	 * so, check for that.
	 */
	if ((flags & IFA_F_MANAGETEMPADDR) && !nm_platform_check_support_libnl_extended_ifa_flags ()) {
		strncat (buf, buf[0] ? "," IFA_F_MANAGETEMPADDR_STR : IFA_F_MANAGETEMPADDR_STR,
		         size - strlen (buf) - 1);
	}
	if ((flags & IFA_F_NOPREFIXROUTE) && !nm_platform_check_support_libnl_extended_ifa_flags ()) {
		strncat (buf, buf[0] ? "," IFA_F_NOPREFIXROUTE_STR : IFA_F_NOPREFIXROUTE_STR,
		         size - strlen (buf) - 1);
	}
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
	char s_flags[256];
	char s_address[INET6_ADDRSTRLEN];
	char s_peer[INET6_ADDRSTRLEN];
	char str_lft[30], str_pref[30], str_time[50];
	char str_dev[TO_STRING_DEV_BUF_SIZE];
	char *str_flags;
	char *str_peer = NULL;
	const char *str_lft_p, *str_pref_p, *str_time_p;
	gint32 now = nm_utils_get_monotonic_timestamp_s ();

	g_return_val_if_fail (address, "(unknown)");

	inet_ntop (AF_INET6, &address->address, s_address, sizeof (s_address));

	if (!IN6_IS_ADDR_UNSPECIFIED (&address->peer_address)) {
		inet_ntop (AF_INET6, &address->peer_address, s_peer, sizeof (s_peer));
		str_peer = g_strconcat (" ptp ", s_peer, NULL);
	}

	_to_string_dev (NULL, address->ifindex, str_dev, sizeof (str_dev));

	nm_platform_addr_flags2str (address->flags, s_flags, sizeof (s_flags));

	str_flags = s_flags[0] ? g_strconcat (" flags ", s_flags, NULL) : NULL;

	str_lft_p = _lifetime_to_string (address->timestamp,
	                                 address->lifetime ? address->lifetime : NM_PLATFORM_LIFETIME_PERMANENT,
	                                 now, str_lft, sizeof (str_lft)),
	str_pref_p = (address->lifetime == address->preferred)
	             ? str_lft_p
	             : ( _lifetime_to_string (address->timestamp,
	                                      address->lifetime ? MIN (address->preferred, address->lifetime) : NM_PLATFORM_LIFETIME_PERMANENT,
	                                      now, str_pref, sizeof (str_pref)) );
	str_time_p = _lifetime_summary_to_string (now, address->timestamp, address->preferred, address->lifetime, str_time, sizeof (str_time));

	g_snprintf (_nm_platform_to_string_buffer, sizeof (_nm_platform_to_string_buffer), "%s/%d lft %s pref %s%s%s%s%s src %s",
	            s_address, address->plen, str_lft_p, str_pref_p, str_time_p,
	            str_peer ? str_peer : "",
	            str_dev,
	            str_flags ? str_flags : "",
	            source_to_string (address->source));
	g_free (str_flags);
	g_free (str_peer);
	return _nm_platform_to_string_buffer;
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
	char s_network[INET_ADDRSTRLEN], s_gateway[INET_ADDRSTRLEN];
	char str_dev[TO_STRING_DEV_BUF_SIZE];
	char str_scope[30];

	g_return_val_if_fail (route, "(unknown)");

	inet_ntop (AF_INET, &route->network, s_network, sizeof(s_network));
	inet_ntop (AF_INET, &route->gateway, s_gateway, sizeof(s_gateway));

	_to_string_dev (NULL, route->ifindex, str_dev, sizeof (str_dev));

	g_snprintf (_nm_platform_to_string_buffer, sizeof (_nm_platform_to_string_buffer), "%s/%d via %s%s metric %"G_GUINT32_FORMAT" mss %"G_GUINT32_FORMAT" src %s%s%s",
	            s_network, route->plen, s_gateway,
	            str_dev,
	            route->metric, route->mss,
	            source_to_string (route->source),
	            route->scope_inv ? " scope " : "",
	            route->scope_inv ? (rtnl_scope2str (nm_platform_route_scope_inv (route->scope_inv), str_scope, sizeof (str_scope))) : "");
	return _nm_platform_to_string_buffer;
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
	char s_network[INET6_ADDRSTRLEN], s_gateway[INET6_ADDRSTRLEN];
	char str_dev[TO_STRING_DEV_BUF_SIZE];

	g_return_val_if_fail (route, "(unknown)");

	inet_ntop (AF_INET6, &route->network, s_network, sizeof(s_network));
	inet_ntop (AF_INET6, &route->gateway, s_gateway, sizeof(s_gateway));

	_to_string_dev (NULL, route->ifindex, str_dev, sizeof (str_dev));

	g_snprintf (_nm_platform_to_string_buffer, sizeof (_nm_platform_to_string_buffer), "%s/%d via %s%s metric %"G_GUINT32_FORMAT" mss %"G_GUINT32_FORMAT" src %s",
	            s_network, route->plen, s_gateway,
	            str_dev,
	            route->metric, route->mss,
	            source_to_string (route->source));
	return _nm_platform_to_string_buffer;
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

#define _CMP_FIELD_BOOL(a, b, field)                        \
    G_STMT_START {                                          \
        if ((!((a)->field)) != (!((b)->field)))                 \
            return ((!((a)->field)) < (!((b)->field))) ? -1 : 1; \
    } G_STMT_END

#define _CMP_FIELD_STR(a, b, field)                         \
    G_STMT_START {                                          \
        int c = strcmp ((a)->field, (b)->field);            \
        if (c != 0)                                         \
            return c < 0 ? -1 : 1;                          \
    } G_STMT_END

#define _CMP_FIELD_STR_INTERNED(a, b, field)                \
    G_STMT_START {                                          \
        if (((a)->field) != ((b)->field)) {                 \
            /* just to be sure, also do a strcmp() if the pointers don't match */ \
            int c = g_strcmp0 ((a)->field, (b)->field);     \
            if (c != 0)                                     \
                return c < 0 ? -1 : 1;                      \
        } \
    } G_STMT_END

#define _CMP_FIELD_STR0(a, b, field)                        \
    G_STMT_START {                                          \
        int c = g_strcmp0 ((a)->field, (b)->field);         \
        if (c != 0)                                         \
            return c < 0 ? -1 : 1;                          \
    } G_STMT_END

#define _CMP_FIELD_MEMCMP_LEN(a, b, field, len)             \
    G_STMT_START {                                          \
        int c = memcmp (&((a)->field), &((b)->field),       \
                        MIN (len, sizeof ((a)->field)));    \
        if (c != 0)                                         \
            return c < 0 ? -1 : 1;                          \
    } G_STMT_END

#define _CMP_FIELD_MEMCMP(a, b, field)                      \
    G_STMT_START {                                          \
        int c = memcmp (&((a)->field), &((b)->field),       \
                        sizeof ((a)->field));               \
        if (c != 0)                                         \
            return c < 0 ? -1 : 1;                          \
    } G_STMT_END

int
nm_platform_link_cmp (const NMPlatformLink *a, const NMPlatformLink *b)
{
	_CMP_POINTER (a, b);
	_CMP_FIELD (a, b, ifindex);
	_CMP_FIELD (a, b, type);
	_CMP_FIELD_STR (a, b, name);
	_CMP_FIELD (a, b, master);
	_CMP_FIELD (a, b, parent);
	_CMP_FIELD (a, b, up);
	_CMP_FIELD (a, b, vlan_id);
	_CMP_FIELD (a, b, flags);
	_CMP_FIELD (a, b, connected);
	_CMP_FIELD (a, b, arp);
	_CMP_FIELD (a, b, mtu);
	_CMP_FIELD_BOOL (a, b, initialized);
	_CMP_FIELD (a, b, arptype);
	_CMP_FIELD (a, b, addr.len);
	_CMP_FIELD (a, b, inet6_addr_gen_mode_inv);
	_CMP_FIELD (a, b, inet6_token.is_valid);
	_CMP_FIELD_STR_INTERNED (a, b, kind);
	_CMP_FIELD_STR0 (a, b, udi);
	_CMP_FIELD_STR_INTERNED (a, b, driver);
	if (a->addr.len)
		_CMP_FIELD_MEMCMP_LEN (a, b, addr.data, a->addr.len);
	if (a->inet6_token.is_valid)
		_CMP_FIELD_MEMCMP (a, b, inet6_token.iid);
	return 0;
}

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
	_CMP_FIELD_STR (a, b, label);
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
	_CMP_FIELD (a, b, scope_inv);
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

#undef _CMP_FIELD
#undef _CMP_FIELD_MEMCMP

/**
 * nm_platform_ip_address_cmp_expiry:
 * @a: a NMPlatformIPAddress to compare
 * @b: the other NMPlatformIPAddress to compare
 *
 * Compares two addresses and returns which one has a longer remaining lifetime.
 * If both addresses have the same lifetime, look at the remaining preferred time.
 *
 * For comparison, only the timestamp, lifetime and preferred fields are considered.
 * If they compare equal (== 0), their other fields were not considered.
 *
 * Returns: -1, 0, or 1 according to the comparison
 **/
int
nm_platform_ip_address_cmp_expiry (const NMPlatformIPAddress *a, const NMPlatformIPAddress *b)
{
	gint64 ta = 0, tb = 0;

	_CMP_POINTER (a, b);

	if (a->lifetime == NM_PLATFORM_LIFETIME_PERMANENT || a->lifetime == 0)
		ta = G_MAXINT64;
	else if (a->timestamp)
		ta = ((gint64) a->timestamp) + a->lifetime;

	if (b->lifetime == NM_PLATFORM_LIFETIME_PERMANENT || b->lifetime == 0)
		tb = G_MAXINT64;
	else if (b->timestamp)
		tb = ((gint64) b->timestamp) + b->lifetime;

	if (ta == tb) {
		/* if the lifetime is equal, compare the preferred time. */
		ta = tb = 0;

		if (a->preferred == NM_PLATFORM_LIFETIME_PERMANENT || a->lifetime == 0 /* liftime==0 means permanent! */)
			ta = G_MAXINT64;
		else if (a->timestamp)
			ta = ((gint64) a->timestamp) + a->preferred;

		if (b->preferred == NM_PLATFORM_LIFETIME_PERMANENT|| b->lifetime == 0)
			tb = G_MAXINT64;
		else if (b->timestamp)
			tb = ((gint64) b->timestamp) + b->preferred;

		if (ta == tb)
			return 0;
	}

	return ta < tb ? -1 : 1;
}

#undef _CMP_POINTER

const char *
nm_platform_signal_change_type_to_string (NMPlatformSignalChangeType change_type)
{
	switch (change_type) {
	case NM_PLATFORM_SIGNAL_ADDED:
		return "added";
	case NM_PLATFORM_SIGNAL_CHANGED:
		return "changed";
	case NM_PLATFORM_SIGNAL_REMOVED:
		return "removed";
	default:
		g_return_val_if_reached ("UNKNOWN");
	}
}

static void
log_link (NMPlatform *p, int ifindex, NMPlatformLink *device, NMPlatformSignalChangeType change_type, gpointer user_data)
{

	debug ("signal: link %7s: %s", nm_platform_signal_change_type_to_string (change_type), nm_platform_link_to_string (device));
}

static void
log_ip4_address (NMPlatform *p, int ifindex, NMPlatformIP4Address *address, NMPlatformSignalChangeType change_type, gpointer user_data)
{
	debug ("signal: address 4 %7s: %s", nm_platform_signal_change_type_to_string (change_type), nm_platform_ip4_address_to_string (address));
}

static void
log_ip6_address (NMPlatform *p, int ifindex, NMPlatformIP6Address *address, NMPlatformSignalChangeType change_type, gpointer user_data)
{
	debug ("signal: address 6 %7s: %s", nm_platform_signal_change_type_to_string (change_type), nm_platform_ip6_address_to_string (address));
}

static void
log_ip4_route (NMPlatform *p, int ifindex, NMPlatformIP4Route *route, NMPlatformSignalChangeType change_type, gpointer user_data)
{
	debug ("signal: route   4 %7s: %s", nm_platform_signal_change_type_to_string (change_type), nm_platform_ip4_route_to_string (route));
}

static void
log_ip6_route (NMPlatform *p, int ifindex, NMPlatformIP6Route *route, NMPlatformSignalChangeType change_type, gpointer user_data)
{
	debug ("signal: route   6 %7s: %s", nm_platform_signal_change_type_to_string (change_type), nm_platform_ip6_route_to_string (route));
}

/******************************************************************/

static gboolean
_vtr_v4_route_add (NMPlatform *self, int ifindex, const NMPlatformIPXRoute *route, guint32 v4_pref_src)
{
	return nm_platform_ip4_route_add (self,
	                                  ifindex > 0 ? ifindex : route->rx.ifindex,
	                                  route->rx.source,
	                                  route->r4.network,
	                                  route->rx.plen,
	                                  route->r4.gateway,
	                                  v4_pref_src,
	                                  route->rx.metric,
	                                  route->rx.mss);
}

static gboolean
_vtr_v6_route_add (NMPlatform *self, int ifindex, const NMPlatformIPXRoute *route, guint32 v4_pref_src)
{
	return nm_platform_ip6_route_add (self,
	                                  ifindex > 0 ? ifindex : route->rx.ifindex,
	                                  route->rx.source,
	                                  route->r6.network,
	                                  route->rx.plen,
	                                  route->r6.gateway,
	                                  route->rx.metric,
	                                  route->rx.mss);
}

static gboolean
_vtr_v4_route_delete (NMPlatform *self, int ifindex, const NMPlatformIPXRoute *route)
{
	return nm_platform_ip4_route_delete (self,
	                                     ifindex > 0 ? ifindex : route->rx.ifindex,
	                                     route->r4.network,
	                                     route->rx.plen,
	                                     route->rx.metric);
}

static gboolean
_vtr_v6_route_delete (NMPlatform *self, int ifindex, const NMPlatformIPXRoute *route)
{
	return nm_platform_ip6_route_delete (self,
	                                     ifindex > 0 ? ifindex : route->rx.ifindex,
	                                     route->r6.network,
	                                     route->rx.plen,
	                                     route->rx.metric);
}

static guint32
_vtr_v4_metric_normalize (guint32 metric)
{
	return metric;
}

static gboolean
_vtr_v4_route_delete_default (NMPlatform *self, int ifindex, guint32 metric)
{
	return nm_platform_ip4_route_delete (self, ifindex, 0, 0, metric);
}

static gboolean
_vtr_v6_route_delete_default (NMPlatform *self, int ifindex, guint32 metric)
{
	return nm_platform_ip6_route_delete (self, ifindex, in6addr_any, 0, metric);
}

/******************************************************************/

const NMPlatformVTableRoute nm_platform_vtable_route_v4 = {
	.is_ip4                         = TRUE,
	.addr_family                    = AF_INET,
	.sizeof_route                   = sizeof (NMPlatformIP4Route),
	.route_cmp                      = (int (*) (const NMPlatformIPXRoute *a, const NMPlatformIPXRoute *b)) nm_platform_ip4_route_cmp,
	.route_to_string                = (const char *(*) (const NMPlatformIPXRoute *route)) nm_platform_ip4_route_to_string,
	.route_get_all                  = nm_platform_ip4_route_get_all,
	.route_add                      = _vtr_v4_route_add,
	.route_delete                   = _vtr_v4_route_delete,
	.route_delete_default           = _vtr_v4_route_delete_default,
	.metric_normalize               = _vtr_v4_metric_normalize,
};

const NMPlatformVTableRoute nm_platform_vtable_route_v6 = {
	.is_ip4                         = FALSE,
	.addr_family                    = AF_INET6,
	.sizeof_route                   = sizeof (NMPlatformIP6Route),
	.route_cmp                      = (int (*) (const NMPlatformIPXRoute *a, const NMPlatformIPXRoute *b)) nm_platform_ip6_route_cmp,
	.route_to_string                = (const char *(*) (const NMPlatformIPXRoute *route)) nm_platform_ip6_route_to_string,
	.route_get_all                  = nm_platform_ip6_route_get_all,
	.route_add                      = _vtr_v6_route_add,
	.route_delete                   = _vtr_v6_route_delete,
	.route_delete_default           = _vtr_v6_route_delete_default,
	.metric_normalize               = nm_utils_ip6_route_metric_normalize,
};

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
		G_TYPE_NONE, 4, G_TYPE_INT, G_TYPE_POINTER, NM_TYPE_PLATFORM_SIGNAL_CHANGE_TYPE, NM_TYPE_PLATFORM_REASON);

static void
nm_platform_class_init (NMPlatformClass *platform_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (platform_class);

	platform_class->wifi_set_powersave = wifi_set_powersave;

	/* Signals */
	SIGNAL (SIGNAL_LINK_CHANGED, log_link)
	SIGNAL (SIGNAL_IP4_ADDRESS_CHANGED, log_ip4_address)
	SIGNAL (SIGNAL_IP6_ADDRESS_CHANGED, log_ip6_address)
	SIGNAL (SIGNAL_IP4_ROUTE_CHANGED, log_ip4_route)
	SIGNAL (SIGNAL_IP6_ROUTE_CHANGED, log_ip6_route)
}
