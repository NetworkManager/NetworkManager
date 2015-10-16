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
#include <linux/ip.h>
#include <linux/if_tun.h>
#include <linux/if_tunnel.h>

#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-platform.h"
#include "nm-platform-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-default.h"
#include "nm-enum-types.h"
#include "nm-core-internal.h"

#define ADDRESS_LIFETIME_PADDING 5

G_STATIC_ASSERT (sizeof ( ((NMPlatformLink *) NULL)->addr.data ) == NM_UTILS_HWADDR_LEN_MAX);
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMPlatformIPAddress, address_ptr) == G_STRUCT_OFFSET (NMPlatformIP4Address, address));
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMPlatformIPAddress, address_ptr) == G_STRUCT_OFFSET (NMPlatformIP6Address, address));
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMPlatformIPRoute, network_ptr) == G_STRUCT_OFFSET (NMPlatformIP4Route, network));
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMPlatformIPRoute, network_ptr) == G_STRUCT_OFFSET (NMPlatformIP6Route, network));

#define _NMLOG_DOMAIN           LOGD_PLATFORM
#define _NMLOG_PREFIX_NAME      "platform"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        \
        if (nm_logging_enabled (__level, _NMLOG_DOMAIN)) { \
            char __prefix[32]; \
            const char *__p_prefix = _NMLOG_PREFIX_NAME; \
            const void *const __self = (self); \
            \
            if (__self && __self != nm_platform_try_get ()) { \
                g_snprintf (__prefix, sizeof (__prefix), "%s[%p]", _NMLOG_PREFIX_NAME, __self); \
                __p_prefix = __prefix; \
            } \
            _nm_log (__level, _NMLOG_DOMAIN, 0, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     __p_prefix _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

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

enum {
	PROP_0,
	PROP_REGISTER_SINGLETON,
	LAST_PROP,
};

typedef struct {
	gboolean register_singleton;
} NMPlatformPrivate;

/******************************************************************/

/* Singleton NMPlatform subclass instance and cached class object */
NM_DEFINE_SINGLETON_INSTANCE (NMPlatform);

NM_DEFINE_SINGLETON_REGISTER (NMPlatform);

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

	nm_singleton_instance_register ();

	nm_log_dbg (LOGD_CORE, "setup %s singleton (%p, %s)", "NMPlatform", singleton_instance, G_OBJECT_TYPE_NAME (instance));
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
 * nm_platform_error_to_string:
 * @error_code: the error code to stringify.
 *
 * Returns: A string representation of the error.
 * For negative numbers, this function interprets
 * the code as -errno.
 */
const char *
nm_platform_error_to_string (NMPlatformError error)
{
	switch (error) {
	case NM_PLATFORM_ERROR_SUCCESS:
		return "success";
	case NM_PLATFORM_ERROR_BUG:
		return "bug";
	case NM_PLATFORM_ERROR_UNSPECIFIED:
		return "unspecified";
	case NM_PLATFORM_ERROR_NOT_FOUND:
		return "not-found";
	case NM_PLATFORM_ERROR_EXISTS:
		return "exists";
	case NM_PLATFORM_ERROR_WRONG_TYPE:
		return "wrong-type";
	case NM_PLATFORM_ERROR_NOT_SLAVE:
		return "not-slave";
	case NM_PLATFORM_ERROR_NO_FIRMWARE:
		return "no-firmware";
	default:
		if (error < 0)
			return g_strerror (- ((int) error));
		return "unknown";
	}
}

/******************************************************************/

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

/**
 * nm_platform_process_events:
 * @self: platform instance
 *
 * Process pending events or handle pending delayed-actions.
 * Effectively, this reads the netlink socket and processes
 * new netlink messages. Possibly it will raise change signals.
 */
void
nm_platform_process_events (NMPlatform *self)
{
	_CHECK_SELF_VOID (self, klass);

	if (klass->process_events)
		klass->process_events (self);
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

	return klass->sysctl_set (self, path, value);
}

gboolean
nm_platform_sysctl_set_ip6_hop_limit_safe (NMPlatform *self, const char *iface, int value)
{
	const char *path;
	gint64 cur;

	_CHECK_SELF (self, klass, FALSE);

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

	g_return_val_if_fail (klass->link_get_all, NULL);

	links = klass->link_get_all (self);

	if (!links || links->len == 0)
		return links;

	unseen = g_hash_table_new (g_direct_hash, g_direct_equal);
	for (i = 0; i < links->len; i++) {
		item = &g_array_index (links, NMPlatformLink, i);

		_LOGT ("link-get: %3d: %s", i, nm_platform_link_to_string (item, NULL, 0));

		nm_assert (item->ifindex > 0 && !g_hash_table_contains (unseen, GINT_TO_POINTER (item->ifindex)));

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
			if (item->parent != NM_PLATFORM_LINK_OTHER_NETNS) {
				g_warn_if_fail (item->parent > 0);
				g_warn_if_fail (item->parent != item->ifindex);
				g_warn_if_fail (g_hash_table_contains (unseen, GINT_TO_POINTER (item->parent)));
			}
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

			_LOGT ("link-get: add %3d -> %3d: %s", i, j, nm_platform_link_to_string (item, NULL, 0));

			g_hash_table_remove (unseen, GINT_TO_POINTER (item->ifindex));
			g_array_index (result, NMPlatformLink, j++) = *item;
			item->ifindex = 0;
			found_something = TRUE;
		}

		if (!found_something) {
			/* There is a loop, pop the first (remaining) element from the list.
			 * This can happen for veth pairs where each peer is parent of the other end. */
			item = &g_array_index (links, NMPlatformLink, first_idx);

			_LOGT ("link-get: add (loop) %3d -> %3d: %s", first_idx, j, nm_platform_link_to_string (item, NULL, 0));

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
 *
 * Lookup the internal NMPlatformLink object.
 *
 * Returns: %NULL, if such a link exists or the internal
 * platform link object. Do not modify the returned value.
 * Also, be aware that any subsequent platform call might
 * invalidated/modify the returned instance.
 **/
const NMPlatformLink *
nm_platform_link_get (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, NULL);

	if (ifindex > 0)
		return klass->link_get (self, ifindex);
	return NULL;
}

/**
 * nm_platform_link_get_by_ifname:
 * @self: platform instance
 * @ifname: the ifname
 *
 * Returns: the first #NMPlatformLink instance with the given name.
 **/
const NMPlatformLink *
nm_platform_link_get_by_ifname (NMPlatform *self, const char *ifname)
{
	_CHECK_SELF (self, klass, NULL);

	if (ifname && *ifname)
		return klass->link_get_by_ifname (self, ifname);
	return NULL;
}

/**
 * nm_platform_link_get_by_address:
 * @self: platform instance
 * @address: a pointer to the binary hardware address
 * @length: the size of @address in bytes
 *
 * Returns: the first #NMPlatformLink object with a matching
 * address.
 **/
const NMPlatformLink *
nm_platform_link_get_by_address (NMPlatform *self,
                                 gconstpointer address,
                                 size_t length)
{
	_CHECK_SELF (self, klass, NULL);

	g_return_val_if_fail (length == 0 || address, NULL);
	if (length > 0) {
		if (length > NM_UTILS_HWADDR_LEN_MAX)
			g_return_val_if_reached (NULL);
		return klass->link_get_by_address (self, address, length);
	}
	return NULL;
}

static NMPlatformError
_link_add_check_existing (NMPlatform *self, const char *name, NMLinkType type, NMPlatformLink *out_link)
{
	const NMPlatformLink *pllink;

	pllink = nm_platform_link_get_by_ifname (self, name);
	if (pllink) {
		gboolean wrong_type;

		wrong_type = type != NM_LINK_TYPE_NONE && pllink->type != type;
		_LOGD ("link: skip adding link due to existing interface '%s' of type %s%s%s",
		       name,
		       nm_link_type_to_string (pllink->type),
		       wrong_type ? ", expected " : "",
		       wrong_type ? nm_link_type_to_string (type) : "");
		if (out_link)
			*out_link = *pllink;
		if (wrong_type)
			return NM_PLATFORM_ERROR_WRONG_TYPE;
		return NM_PLATFORM_ERROR_EXISTS;
	}
	return NM_PLATFORM_ERROR_SUCCESS;
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
 * @type, return NM_PLATFORM_ERROR_EXISTS and returns the link
 * in @out_link.  If the interface already exists and is not of type @type,
 * return NM_PLATFORM_ERROR_WRONG_TYPE.
 *
 * Any link-changed ADDED signal will be emitted directly, before this
 * function finishes.
 *
 * Returns: the error reason or NM_PLATFORM_ERROR_SUCCESS.
 */
static NMPlatformError
nm_platform_link_add (NMPlatform *self,
                      const char *name,
                      NMLinkType type,
                      const void *address,
                      size_t address_len,
                      NMPlatformLink *out_link)
{
	NMPlatformError plerr;

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (name, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (klass->link_add, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail ( (address != NULL) ^ (address_len == 0) , NM_PLATFORM_ERROR_BUG);

	plerr = _link_add_check_existing (self, name, type, out_link);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS)
		return plerr;

	_LOGD ("link: adding %s '%s'", nm_link_type_to_string (type), name);
	if (!klass->link_add (self, name, type, address, address_len, out_link))
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return NM_PLATFORM_ERROR_SUCCESS;
}

/**
 * nm_platform_dummy_add:
 * @self: platform instance
 * @name: New interface name
 * @out_link: on success, the link object
 *
 * Create a software ethernet-like interface
 */
NMPlatformError
nm_platform_dummy_add (NMPlatform *self, const char *name, NMPlatformLink *out_link)
{
	return nm_platform_link_add (self, name, NM_LINK_TYPE_DUMMY, NULL, 0, out_link);
}

/**
 * nm_platform_link_delete:
 * @self: platform instance
 * @ifindex: Interface index
 */
gboolean
nm_platform_link_delete (NMPlatform *self, int ifindex)
{
	const NMPlatformLink *pllink;

	_CHECK_SELF (self, klass, FALSE);

	pllink = nm_platform_link_get (self, ifindex);
	if (!pllink)
		return FALSE;

	_LOGD ("link: deleting '%s' (%d)", pllink->name, ifindex);
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
	const NMPlatformLink *pllink;

	pllink = nm_platform_link_get_by_ifname (self, name);
	return pllink ? pllink->ifindex : 0;
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
	const NMPlatformLink *pllink;

	_CHECK_SELF (self, klass, NULL);

	pllink = nm_platform_link_get (self, ifindex);
	return pllink ? pllink->name : NULL;
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
	const NMPlatformLink *pllink;

	_CHECK_SELF (self, klass, NM_LINK_TYPE_NONE);

	pllink = nm_platform_link_get (self, ifindex);
	return pllink ? pllink->type : NM_LINK_TYPE_NONE;
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

	g_return_val_if_fail (klass->link_get_type_name, NULL);

	return klass->link_get_type_name (self, ifindex);
}

/**
 * nm_platform_link_get_unmanaged:
 * @self: platform instance
 * @ifindex: interface index
 * @unmanaged: management status (in case %TRUE is returned)
 *
 * Returns: %TRUE if platform overrides NM default-unmanaged status,
 * %FALSE otherwise (with @unmanaged unmodified).
 */
gboolean
nm_platform_link_get_unmanaged (NMPlatform *self, int ifindex, gboolean *unmanaged)
{
	_CHECK_SELF (self, klass, FALSE);

	if (klass->link_get_unmanaged)
		return klass->link_get_unmanaged (self, ifindex, unmanaged);
	return FALSE;
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

	g_return_val_if_fail (ifindex > 0, FALSE);

	if (klass->link_refresh)
		return klass->link_refresh (self, ifindex);

	return TRUE;
}

static guint32
_link_get_flags (NMPlatform *self, int ifindex)
{
	const NMPlatformLink *pllink;

	pllink = nm_platform_link_get (self, ifindex);
	return pllink ? pllink->flags : IFF_NOARP;
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

	return NM_FLAGS_HAS (_link_get_flags (self, ifindex), IFF_UP);
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
	const NMPlatformLink *pllink;

	_CHECK_SELF (self, klass, FALSE);

	pllink = nm_platform_link_get (self, ifindex);
	return pllink ? pllink->connected : FALSE;
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

	return !NM_FLAGS_HAS (_link_get_flags (self, ifindex), IFF_NOARP);
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

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (iid, FALSE);

#if HAVE_LIBNL_INET6_TOKEN
	{
		const NMPlatformLink *pllink;

		pllink = nm_platform_link_get (self, ifindex);
		if (pllink && pllink->inet6_token.is_valid) {
			*iid = pllink->inet6_token.iid;
			return TRUE;
		}
	}
#endif
	return FALSE;
}

const char *
nm_platform_link_get_udi (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex >= 0, NULL);

	if (klass->link_get_udi)
		return klass->link_get_udi (self, ifindex);
	return NULL;
}

GObject *
nm_platform_link_get_udev_device (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex >= 0, NULL);

	if (klass->link_get_udev_device)
		return klass->link_get_udev_device (self, ifindex);
	return NULL;
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
	const NMPlatformLink *pllink;

	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex >= 0, FALSE);

	pllink = nm_platform_link_get (self, ifindex);
	if (pllink && pllink->inet6_addr_gen_mode_inv)
		return _nm_platform_uint8_inv (pllink->inet6_addr_gen_mode_inv) == NM_IN6_ADDR_GEN_MODE_NONE;
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

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (address, FALSE);
	g_return_val_if_fail (length > 0, FALSE);
	g_return_val_if_fail (klass->link_set_address, FALSE);

	_LOGD ("link: setting '%s' (%d) hardware address", nm_platform_link_get_name (self, ifindex), ifindex);
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
	const NMPlatformLink *pllink;
	gconstpointer a = NULL;
	guint8 l = 0;

	_CHECK_SELF (self, klass, NULL);

	if (length)
		*length = 0;

	g_return_val_if_fail (ifindex > 0, NULL);

	pllink = nm_platform_link_get (self, ifindex);
	if (pllink && pllink->addr.len > 0) {
		if (pllink->addr.len > NM_UTILS_HWADDR_LEN_MAX) {
			if (length)
				*length = 0;
			g_return_val_if_reached (NULL);
		}
		a = pllink->addr.data;
		l = pllink->addr.len;
	}

	if (length)
		*length = l;
	return a;
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

	if (length)
		*length = 0;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (buf, FALSE);
	g_return_val_if_fail (length, FALSE);

	if (klass->link_get_permanent_address)
		return klass->link_get_permanent_address (self, ifindex, buf, length);
	return FALSE;
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
 * @out_no_firmware: (allow-none): if the failure reason is due to missing firmware.
 *
 * Bring the interface up.
 */
gboolean
nm_platform_link_set_up (NMPlatform *self, int ifindex, gboolean *out_no_firmware)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (klass->link_set_up, FALSE);

	_LOGD ("link: setting up '%s' (%d)", nm_platform_link_get_name (self, ifindex), ifindex);
	return klass->link_set_up (self, ifindex, out_no_firmware);
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

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (klass->link_set_down, FALSE);

	_LOGD ("link: setting down '%s' (%d)", nm_platform_link_get_name (self, ifindex), ifindex);
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

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_set_arp, FALSE);

	_LOGD ("link: setting arp '%s' (%d)", nm_platform_link_get_name (self, ifindex), ifindex);
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

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (klass->link_set_noarp, FALSE);

	_LOGD ("link: setting noarp '%s' (%d)", nm_platform_link_get_name (self, ifindex), ifindex);
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

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (mtu > 0, FALSE);
	g_return_val_if_fail (klass->link_set_mtu, FALSE);

	_LOGD ("link: setting '%s' (%d) mtu %"G_GUINT32_FORMAT, nm_platform_link_get_name (self, ifindex), ifindex, mtu);
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
	const NMPlatformLink *pllink;

	_CHECK_SELF (self, klass, 0);

	pllink = nm_platform_link_get (self, ifindex);
	return pllink ? pllink->mtu : 0;
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

	g_return_val_if_fail (ifindex >= 0, NULL);

	if (klass->link_get_physical_port_id)
		return klass->link_get_physical_port_id (self, ifindex);
	return NULL;
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

	g_return_val_if_fail (ifindex >= 0, 0);

	if (klass->link_get_dev_id)
		return klass->link_get_dev_id (self, ifindex);
	return 0;
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

	g_return_val_if_fail (ifindex >= 0, FALSE);

	if (klass->link_get_wake_on_lan)
		return klass->link_get_wake_on_lan (self, ifindex);
	return FALSE;
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

	g_return_val_if_fail (master > 0, FALSE);
	g_return_val_if_fail (slave> 0, FALSE);
	g_return_val_if_fail (klass->link_enslave, FALSE);

	_LOGD ("link: enslaving '%s' (%d) to master '%s' (%d)",
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

	g_return_val_if_fail (master > 0, FALSE);
	g_return_val_if_fail (slave > 0, FALSE);
	g_return_val_if_fail (klass->link_release, FALSE);

	if (nm_platform_link_get_master (self, slave) != master)
		return FALSE;

	_LOGD ("link: releasing '%s' (%d) from master '%s' (%d)",
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
	const NMPlatformLink *pllink;

	_CHECK_SELF (self, klass, 0);

	g_return_val_if_fail (slave >= 0, FALSE);

	pllink = nm_platform_link_get (self, slave);
	return pllink ? pllink->master : 0;
}

/*****************************************************************************/

gconstpointer
nm_platform_link_get_lnk (NMPlatform *self, int ifindex, NMLinkType link_type, const NMPlatformLink **out_link)
{
	_CHECK_SELF (self, klass, FALSE);

	NM_SET_OUT (out_link, NULL);

	g_return_val_if_fail (ifindex > 0, NULL);

	return klass->link_get_lnk (self, ifindex, link_type, out_link);
}

const NMPlatformLnkGre *
nm_platform_link_get_lnk_gre (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return nm_platform_link_get_lnk (self, ifindex, NM_LINK_TYPE_GRE, out_link);
}

const NMPlatformLnkInfiniband *
nm_platform_link_get_lnk_infiniband (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return nm_platform_link_get_lnk (self, ifindex, NM_LINK_TYPE_INFINIBAND, out_link);
}

const NMPlatformLnkMacvlan *
nm_platform_link_get_lnk_macvlan (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return nm_platform_link_get_lnk (self, ifindex, NM_LINK_TYPE_MACVLAN, out_link);
}

const NMPlatformLnkVlan *
nm_platform_link_get_lnk_vlan (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return nm_platform_link_get_lnk (self, ifindex, NM_LINK_TYPE_VLAN, out_link);
}

const NMPlatformLnkVxlan *
nm_platform_link_get_lnk_vxlan (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return nm_platform_link_get_lnk (self, ifindex, NM_LINK_TYPE_VXLAN, out_link);
}

/*****************************************************************************/

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
NMPlatformError
nm_platform_bridge_add (NMPlatform *self,
                        const char *name,
                        const void *address,
                        size_t address_len,
                        NMPlatformLink *out_link)
{
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
NMPlatformError
nm_platform_bond_add (NMPlatform *self, const char *name, NMPlatformLink *out_link)
{
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
NMPlatformError
nm_platform_team_add (NMPlatform *self, const char *name, NMPlatformLink *out_link)
{
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
NMPlatformError
nm_platform_vlan_add (NMPlatform *self,
                      const char *name,
                      int parent,
                      int vlanid,
                      guint32 vlanflags,
                      NMPlatformLink *out_link)
{
	NMPlatformError plerr;

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (parent >= 0, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (vlanid >= 0, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (name, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (klass->vlan_add, NM_PLATFORM_ERROR_BUG);

	plerr = _link_add_check_existing (self, name, NM_LINK_TYPE_VLAN, out_link);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS)
		return plerr;

	_LOGD ("link: adding vlan '%s' parent %d vlanid %d vlanflags %x",
	       name, parent, vlanid, vlanflags);
	if (!klass->vlan_add (self, name, parent, vlanid, vlanflags, out_link))
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return NM_PLATFORM_ERROR_SUCCESS;
}

gboolean
nm_platform_master_set_option (NMPlatform *self, int ifindex, const char *option, const char *value)
{
	_CHECK_SELF (self, klass, FALSE);

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

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);
	g_return_val_if_fail (klass->master_set_option, FALSE);

	return klass->master_get_option (self, ifindex, option);
}

gboolean
nm_platform_slave_set_option (NMPlatform *self, int ifindex, const char *option, const char *value)
{
	_CHECK_SELF (self, klass, FALSE);

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

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);
	g_return_val_if_fail (klass->slave_set_option, FALSE);

	return klass->slave_get_option (self, ifindex, option);
}

gboolean
nm_platform_vlan_set_ingress_map (NMPlatform *self, int ifindex, int from, int to)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (klass->vlan_set_ingress_map, FALSE);

	_LOGD ("link: setting vlan ingress map for %d from %d to %d", ifindex, from, to);
	return klass->vlan_set_ingress_map (self, ifindex, from, to);
}

gboolean
nm_platform_vlan_set_egress_map (NMPlatform *self, int ifindex, int from, int to)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (klass->vlan_set_egress_map, FALSE);

	_LOGD ("link: setting vlan egress map for %d from %d to %d", ifindex, from, to);
	return klass->vlan_set_egress_map (self, ifindex, from, to);
}

NMPlatformError
nm_platform_infiniband_partition_add (NMPlatform *self, int parent, int p_key, NMPlatformLink *out_link)
{
	gs_free char *parent_name = NULL;
	gs_free char *name = NULL;
	NMPlatformError plerr;

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (parent >= 0, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (p_key >= 0, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (klass->infiniband_partition_add, NM_PLATFORM_ERROR_BUG);

	parent_name = g_strdup (nm_platform_link_get_name (self, parent));
	if (   !parent_name
	    || nm_platform_link_get_type (self, parent) != NM_LINK_TYPE_INFINIBAND)
		return NM_PLATFORM_ERROR_WRONG_TYPE;

	name = g_strdup_printf ("%s.%04x", parent_name, p_key);
	plerr = _link_add_check_existing (self, name, NM_LINK_TYPE_INFINIBAND, out_link);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS)
		return plerr;

	_LOGD ("link: adding infiniband partition %s for parent '%s' (%d), key %d",
	       name, parent_name, parent, p_key);
	if (!klass->infiniband_partition_add (self, parent, p_key, out_link))
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return NM_PLATFORM_ERROR_SUCCESS;
}

gboolean
nm_platform_infiniband_get_info (NMPlatform *self,
                                 int ifindex,
                                 int *out_parent,
                                 int *out_p_key,
                                 const char **out_mode)
{
	const NMPlatformLnkInfiniband *plnk;
	const NMPlatformLink *plink;
	const char *iface;
	char *path, *contents;
	const char *mode;
	int p_key = 0;

	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);

	plnk = nm_platform_link_get_lnk_infiniband (self, ifindex, &plink);

	if (   !plink
	    || plink->type != NM_LINK_TYPE_INFINIBAND)
		return FALSE;

	if (plnk) {
		NM_SET_OUT (out_parent, plink->parent);
		NM_SET_OUT (out_p_key, plnk->p_key);
		NM_SET_OUT (out_mode, plnk->mode);
		return TRUE;
	}

	/* Could not get the link information via netlink. To support older kernels,
	 * fallback to reading sysfs. */

	iface = ASSERT_VALID_PATH_COMPONENT (plink->name);

	/* Fall back to reading sysfs */
	path = g_strdup_printf ("/sys/class/net/%s/mode", iface);
	contents = nm_platform_sysctl_get (self, path);
	g_free (path);
	if (!contents)
		return FALSE;

	if (strstr (contents, "datagram"))
		mode = "datagram";
	else if (strstr (contents, "connected"))
		mode = "connected";
	else
		mode = NULL;
	g_free (contents);

	path = g_strdup_printf ("/sys/class/net/%s/pkey", iface);
	contents = nm_platform_sysctl_get (self, path);
	g_free (path);
	if (!contents)
		return FALSE;
	p_key = (int) _nm_utils_ascii_str_to_int64 (contents, 16, 0, 0xFFFF, -1);
	g_free (contents);
	if (p_key < 0)
		return FALSE;

	NM_SET_OUT (out_parent, plink->parent);
	NM_SET_OUT (out_p_key, p_key);
	NM_SET_OUT (out_mode, mode);
	return TRUE;
}

gboolean
nm_platform_veth_get_properties (NMPlatform *self, int ifindex, int *out_peer_ifindex)
{
	const NMPlatformLink *plink;
	int peer_ifindex;
	_CHECK_SELF (self, klass, FALSE);

	plink = nm_platform_link_get (self, ifindex);

	if (!plink)
		return FALSE;
	if (plink->type != NM_LINK_TYPE_VETH)
		return FALSE;

	if (plink->parent != 0) {
		NM_SET_OUT (out_peer_ifindex, plink->parent);
		return TRUE;
	}

	/* Pre-4.1 kernel did not expose the peer_ifindex as IFA_LINK. Lookup via ethtool. */
	if (out_peer_ifindex) {
		peer_ifindex = nmp_utils_ethtool_get_peer_ifindex (plink->name);
		if (peer_ifindex <= 0)
			return FALSE;

		*out_peer_ifindex = peer_ifindex;
	}
	return TRUE;
}

gboolean
nm_platform_tun_get_properties_ifname (NMPlatform *self, const char *ifname, NMPlatformTunProperties *props)
{
	char *path, *val;
	gboolean success = TRUE;

	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (props, FALSE);

	memset (props, 0, sizeof (*props));
	props->owner = -1;
	props->group = -1;

	if (!ifname || !nm_utils_iface_valid_name (ifname))
		return FALSE;
	ifname = ASSERT_VALID_PATH_COMPONENT (ifname);

	path = g_strdup_printf ("/sys/class/net/%s/owner", ifname);
	val = nm_platform_sysctl_get (self, path);
	g_free (path);
	if (val) {
		props->owner = _nm_utils_ascii_str_to_int64 (val, 10, -1, G_MAXINT64, -1);
		if (errno)
			success = FALSE;
		g_free (val);
	} else
		success = FALSE;

	path = g_strdup_printf ("/sys/class/net/%s/group", ifname);
	val = nm_platform_sysctl_get (self, path);
	g_free (path);
	if (val) {
		props->group = _nm_utils_ascii_str_to_int64 (val, 10, -1, G_MAXINT64, -1);
		if (errno)
			success = FALSE;
		g_free (val);
	} else
		success = FALSE;

	path = g_strdup_printf ("/sys/class/net/%s/tun_flags", ifname);
	val = nm_platform_sysctl_get (self, path);
	g_free (path);
	if (val) {
		gint64 flags;

		flags = _nm_utils_ascii_str_to_int64 (val, 16, 0, G_MAXINT64, 0);
		if (!errno) {
#ifndef IFF_MULTI_QUEUE
			const int IFF_MULTI_QUEUE = 0x0100;
#endif
			props->mode = ((flags & (IFF_TUN | IFF_TAP)) == IFF_TUN) ? "tun" : "tap";
			props->no_pi = !!(flags & IFF_NO_PI);
			props->vnet_hdr = !!(flags & IFF_VNET_HDR);
			props->multi_queue = !!(flags & IFF_MULTI_QUEUE);
		} else
			success = FALSE;
		g_free (val);
	} else
		success = FALSE;

	return success;
}

gboolean
nm_platform_tun_get_properties (NMPlatform *self, int ifindex, NMPlatformTunProperties *props)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	return nm_platform_tun_get_properties_ifname (self, nm_platform_link_get_name (self, ifindex), props);
}

gboolean
nm_platform_wifi_get_capabilities (NMPlatform *self, int ifindex, NMDeviceWifiCapabilities *caps)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);

	return klass->wifi_get_capabilities (self, ifindex, caps);
}

gboolean
nm_platform_wifi_get_bssid (NMPlatform *self, int ifindex, guint8 *bssid)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);

	return klass->wifi_get_bssid (self, ifindex, bssid);
}

guint32
nm_platform_wifi_get_frequency (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, 0);

	g_return_val_if_fail (ifindex > 0, 0);

	return klass->wifi_get_frequency (self, ifindex);
}

int
nm_platform_wifi_get_quality (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, 0);

	g_return_val_if_fail (ifindex > 0, 0);

	return klass->wifi_get_quality (self, ifindex);
}

guint32
nm_platform_wifi_get_rate (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, 0);

	g_return_val_if_fail (ifindex > 0, 0);

	return klass->wifi_get_rate (self, ifindex);
}

NM80211Mode
nm_platform_wifi_get_mode (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, NM_802_11_MODE_UNKNOWN);

	g_return_val_if_fail (ifindex > 0, NM_802_11_MODE_UNKNOWN);

	return klass->wifi_get_mode (self, ifindex);
}

void
nm_platform_wifi_set_mode (NMPlatform *self, int ifindex, NM80211Mode mode)
{
	_CHECK_SELF_VOID (self, klass);

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

	g_return_if_fail (ifindex > 0);

	klass->wifi_set_powersave (self, ifindex, powersave);
}

guint32
nm_platform_wifi_find_frequency (NMPlatform *self, int ifindex, const guint32 *freqs)
{
	_CHECK_SELF (self, klass, 0);

	g_return_val_if_fail (ifindex > 0, 0);
	g_return_val_if_fail (freqs != NULL, 0);

	return klass->wifi_find_frequency (self, ifindex, freqs);
}

void
nm_platform_wifi_indicate_addressing_running (NMPlatform *self, int ifindex, gboolean running)
{
	_CHECK_SELF_VOID (self, klass);

	g_return_if_fail (ifindex > 0);

	klass->wifi_indicate_addressing_running (self, ifindex, running);
}

guint32
nm_platform_mesh_get_channel (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, 0);

	g_return_val_if_fail (ifindex > 0, 0);

	return klass->mesh_get_channel (self, ifindex);
}

gboolean
nm_platform_mesh_set_channel (NMPlatform *self, int ifindex, guint32 channel)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);

	return klass->mesh_set_channel (self, ifindex, channel);
}

gboolean
nm_platform_mesh_set_ssid (NMPlatform *self, int ifindex, const guint8 *ssid, gsize len)
{
	_CHECK_SELF (self, klass, FALSE);

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

in_addr_t
nm_platform_ip4_address_get_peer (const NMPlatformIP4Address *addr)
{
	return addr->peer_address ?: addr->address;
}

const struct in6_addr *
nm_platform_ip6_address_get_peer (const NMPlatformIP6Address *addr)
{
	if (   IN6_IS_ADDR_UNSPECIFIED (&addr->peer_address)
	    || IN6_ARE_ADDR_EQUAL (&addr->peer_address, &addr->address))
		return &addr->address;
	return &addr->peer_address;
}

in_addr_t
nm_platform_ip4_address_get_peer_net (const NMPlatformIP4Address *addr)
{
	return (addr->peer_address ?: addr->address) & nm_utils_ip4_prefix_to_netmask (addr->plen);
}

gboolean
nm_platform_ip4_address_equal_peer_net (const NMPlatformIP4Address *addr1, const NMPlatformIP4Address *addr2)
{
	guint32 a1, a2;

	if (addr1->plen != addr2->plen)
		return FALSE;

	/* For kernel, if the peer address is unset, that effectively means that
	 * the peer address equals the local address. */
	a1 = addr1->peer_address ? addr1->peer_address : addr1->address;
	a2 = addr2->peer_address ? addr2->peer_address : addr2->address;

	return ((a1 ^ a2) & nm_utils_ip4_prefix_to_netmask (addr1->plen)) == 0;
}

GArray *
nm_platform_ip4_address_get_all (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, NULL);

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (klass->ip4_address_get_all, NULL);

	return klass->ip4_address_get_all (self, ifindex);
}

GArray *
nm_platform_ip6_address_get_all (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, NULL);

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (klass->ip6_address_get_all, NULL);

	return klass->ip6_address_get_all (self, ifindex);
}

gboolean
nm_platform_ip4_address_add (NMPlatform *self,
                             int ifindex,
                             in_addr_t address,
                             int plen,
                             in_addr_t peer_address,
                             guint32 lifetime,
                             guint32 preferred,
                             const char *label)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (lifetime > 0, FALSE);
	g_return_val_if_fail (preferred <= lifetime, FALSE);
	g_return_val_if_fail (klass->ip4_address_add, FALSE);
	g_return_val_if_fail (!label || strlen (label) < sizeof (((NMPlatformIP4Address *) NULL)->label), FALSE);

	if (_LOGD_ENABLED ()) {
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

		_LOGD ("address: adding or updating IPv4 address: %s", nm_platform_ip4_address_to_string (&addr, NULL, 0));
	}
	return klass->ip4_address_add (self, ifindex, address, plen, peer_address, lifetime, preferred, label);
}

gboolean
nm_platform_ip6_address_add (NMPlatform *self,
                             int ifindex,
                             struct in6_addr address,
                             int plen,
                             struct in6_addr peer_address,
                             guint32 lifetime,
                             guint32 preferred,
                             guint flags)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (lifetime > 0, FALSE);
	g_return_val_if_fail (preferred <= lifetime, FALSE);
	g_return_val_if_fail (klass->ip6_address_add, FALSE);

	if (_LOGD_ENABLED ()) {
		NMPlatformIP6Address addr = { 0 };

		addr.ifindex = ifindex;
		addr.address = address;
		addr.peer_address = peer_address;
		addr.plen = plen;
		addr.timestamp = 0; /* set it to zero, which to_string will treat as *now* */
		addr.lifetime = lifetime;
		addr.preferred = preferred;
		addr.flags = flags;

		_LOGD ("address: adding or updating IPv6 address: %s", nm_platform_ip6_address_to_string (&addr, NULL, 0));
	}
	return klass->ip6_address_add (self, ifindex, address, plen, peer_address, lifetime, preferred, flags);
}

gboolean
nm_platform_ip4_address_delete (NMPlatform *self, int ifindex, in_addr_t address, int plen, in_addr_t peer_address)
{
	char str_dev[TO_STRING_DEV_BUF_SIZE];
	char str_peer[NM_UTILS_INET_ADDRSTRLEN];

	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (klass->ip4_address_delete, FALSE);

	_LOGD ("address: deleting IPv4 address %s/%d, %s%s%sifindex %d%s",
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

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen > 0, FALSE);
	g_return_val_if_fail (klass->ip6_address_delete, FALSE);

	_LOGD ("address: deleting IPv6 address %s/%d, ifindex %d%s",
	       nm_utils_inet6_ntop (&address, NULL), plen, ifindex,
	       _to_string_dev (self, ifindex, str_dev, sizeof (str_dev)));
	return klass->ip6_address_delete (self, ifindex, address, plen);
}

const NMPlatformIP4Address *
nm_platform_ip4_address_get (NMPlatform *self, int ifindex, in_addr_t address, int plen, guint32 peer_address)
{
	_CHECK_SELF (self, klass, NULL);

	g_return_val_if_fail (plen > 0, NULL);

	return klass->ip4_address_get (self, ifindex, address, plen, peer_address);
}

const NMPlatformIP6Address *
nm_platform_ip6_address_get (NMPlatform *self, int ifindex, struct in6_addr address, int plen)
{
	_CHECK_SELF (self, klass, NULL);

	g_return_val_if_fail (plen > 0, NULL);

	return klass->ip6_address_get (self, ifindex, address, plen);
}

static gboolean
array_contains_ip4_address (const GArray *addresses, const NMPlatformIP4Address *address, gint64 now, guint32 padding)
{
	guint len = addresses ? addresses->len : 0;
	guint i;

	for (i = 0; i < len; i++) {
		NMPlatformIP4Address *candidate = &g_array_index (addresses, NMPlatformIP4Address, i);

		if (   candidate->address == address->address
		    && candidate->plen == address->plen
		    && nm_platform_ip4_address_equal_peer_net (candidate, address)) {
			guint32 lifetime, preferred;

			if (nmp_utils_lifetime_get (candidate->timestamp, candidate->lifetime, candidate->preferred,
			                            now, padding, &lifetime, &preferred))
				return TRUE;
		}
	}

	return FALSE;
}

static gboolean
array_contains_ip6_address (const GArray *addresses, const NMPlatformIP6Address *address, gint64 now, guint32 padding)
{
	guint len = addresses ? addresses->len : 0;
	guint i;

	for (i = 0; i < len; i++) {
		NMPlatformIP6Address *candidate = &g_array_index (addresses, NMPlatformIP6Address, i);

		if (IN6_ARE_ADDR_EQUAL (&candidate->address, &address->address) && candidate->plen == address->plen) {
			guint32 lifetime, preferred;

			if (nmp_utils_lifetime_get (candidate->timestamp, candidate->lifetime, candidate->preferred,
			                            now, padding, &lifetime, &preferred))
				return TRUE;
		}
	}

	return FALSE;
}

/**
 * nm_platform_ip4_address_sync:
 * @self: platform instance
 * @ifindex: Interface index
 * @known_addresses: List of addresses
 * @out_added_addresses: (out): (allow-none): if not %NULL, return a #GPtrArray
 *   with the addresses added. The pointers point into @known_addresses.
 *   It possibly does not contain all addresses from @known_address because
 *   some addresses might be expired.
 *
 * A convenience function to synchronize addresses for a specific interface
 * with the least possible disturbance. It simply removes addresses that are
 * not listed and adds addresses that are.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_ip4_address_sync (NMPlatform *self, int ifindex, const GArray *known_addresses, GPtrArray **out_added_addresses)
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

		if (!array_contains_ip4_address (known_addresses, address, now, ADDRESS_LIFETIME_PADDING))
			nm_platform_ip4_address_delete (self, ifindex, address->address, address->plen, address->peer_address);
	}
	g_array_free (addresses, TRUE);

	if (out_added_addresses)
		*out_added_addresses = NULL;

	if (!known_addresses)
		return TRUE;

	/* Add missing addresses */
	for (i = 0; i < known_addresses->len; i++) {
		const NMPlatformIP4Address *known_address = &g_array_index (known_addresses, NMPlatformIP4Address, i);
		guint32 lifetime, preferred;

		if (!nmp_utils_lifetime_get (known_address->timestamp, known_address->lifetime, known_address->preferred,
		                             now, ADDRESS_LIFETIME_PADDING, &lifetime, &preferred))
			continue;

		if (!nm_platform_ip4_address_add (self, ifindex, known_address->address, known_address->plen, known_address->peer_address, lifetime, preferred, known_address->label))
			return FALSE;

		if (out_added_addresses) {
			if (!*out_added_addresses)
				*out_added_addresses = g_ptr_array_new ();
			g_ptr_array_add (*out_added_addresses, (gpointer) known_address);
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

		if (!array_contains_ip6_address (known_addresses, address, now, ADDRESS_LIFETIME_PADDING))
			nm_platform_ip6_address_delete (self, ifindex, address->address, address->plen);
	}
	g_array_free (addresses, TRUE);

	if (!known_addresses)
		return TRUE;

	/* Add missing addresses */
	for (i = 0; i < known_addresses->len; i++) {
		const NMPlatformIP6Address *known_address = &g_array_index (known_addresses, NMPlatformIP6Address, i);
		guint32 lifetime, preferred;

		if (!nmp_utils_lifetime_get (known_address->timestamp, known_address->lifetime, known_address->preferred,
		                             now, ADDRESS_LIFETIME_PADDING, &lifetime, &preferred))
			continue;

		if (!nm_platform_ip6_address_add (self, ifindex, known_address->address,
		                                  known_address->plen, known_address->peer_address,
		                                  lifetime, preferred, known_address->flags))
			return FALSE;
	}

	return TRUE;
}

gboolean
nm_platform_address_flush (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);

	return    nm_platform_ip4_address_sync (self, ifindex, NULL, NULL)
	       && nm_platform_ip6_address_sync (self, ifindex, NULL, FALSE);
}

/******************************************************************/

GArray *
nm_platform_ip4_route_get_all (NMPlatform *self, int ifindex, NMPlatformGetRouteFlags flags)
{
	_CHECK_SELF (self, klass, NULL);

	g_return_val_if_fail (ifindex >= 0, NULL);

	return klass->ip4_route_get_all (self, ifindex, flags);
}

GArray *
nm_platform_ip6_route_get_all (NMPlatform *self, int ifindex, NMPlatformGetRouteFlags flags)
{
	_CHECK_SELF (self, klass, NULL);

	g_return_val_if_fail (ifindex >= 0, NULL);

	return klass->ip6_route_get_all (self, ifindex, flags);
}

gboolean
nm_platform_ip4_route_add (NMPlatform *self,
                           int ifindex, NMIPConfigSource source,
                           in_addr_t network, int plen,
                           in_addr_t gateway, in_addr_t pref_src,
                           guint32 metric, guint32 mss)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (0 <= plen && plen <= 32, FALSE);
	g_return_val_if_fail (klass->ip4_route_add, FALSE);

	if (_LOGD_ENABLED ()) {
		NMPlatformIP4Route route = { 0 };

		route.ifindex = ifindex;
		route.source = source;
		route.network = network;
		route.plen = plen;
		route.gateway = gateway;
		route.metric = metric;
		route.mss = mss;
		route.pref_src = pref_src;

		_LOGD ("route: adding or updating IPv4 route: %s", nm_platform_ip4_route_to_string (&route, NULL, 0));
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

	g_return_val_if_fail (0 <= plen && plen <= 128, FALSE);
	g_return_val_if_fail (klass->ip6_route_add, FALSE);

	if (_LOGD_ENABLED ()) {
		NMPlatformIP6Route route = { 0 };

		route.ifindex = ifindex;
		route.source = source;
		route.network = network;
		route.plen = plen;
		route.gateway = gateway;
		route.metric = metric;
		route.mss = mss;

		_LOGD ("route: adding or updating IPv6 route: %s", nm_platform_ip6_route_to_string (&route, NULL, 0));
	}
	return klass->ip6_route_add (self, ifindex, source, network, plen, gateway, metric, mss);
}

gboolean
nm_platform_ip4_route_delete (NMPlatform *self, int ifindex, in_addr_t network, int plen, guint32 metric)
{
	char str_dev[TO_STRING_DEV_BUF_SIZE];

	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (klass->ip4_route_delete, FALSE);

	_LOGD ("route: deleting IPv4 route %s/%d, metric=%"G_GUINT32_FORMAT", ifindex %d%s",
	       nm_utils_inet4_ntop (network, NULL), plen, metric, ifindex,
	       _to_string_dev (self, ifindex, str_dev, sizeof (str_dev)));
	return klass->ip4_route_delete (self, ifindex, network, plen, metric);
}

gboolean
nm_platform_ip6_route_delete (NMPlatform *self, int ifindex, struct in6_addr network, int plen, guint32 metric)
{
	char str_dev[TO_STRING_DEV_BUF_SIZE];

	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (klass->ip6_route_delete, FALSE);

	_LOGD ("route: deleting IPv6 route %s/%d, metric=%"G_GUINT32_FORMAT", ifindex %d%s",
	       nm_utils_inet6_ntop (&network, NULL), plen, metric, ifindex,
	       _to_string_dev (self, ifindex, str_dev, sizeof (str_dev)));
	return klass->ip6_route_delete (self, ifindex, network, plen, metric);
}

const NMPlatformIP4Route *
nm_platform_ip4_route_get (NMPlatform *self, int ifindex, in_addr_t network, int plen, guint32 metric)
{
	_CHECK_SELF (self, klass, FALSE);

	return klass->ip4_route_get (self ,ifindex, network, plen, metric);
}

const NMPlatformIP6Route *
nm_platform_ip6_route_get (NMPlatform *self, int ifindex, struct in6_addr network, int plen, guint32 metric)
{
	_CHECK_SELF (self, klass, FALSE);

	return klass->ip6_route_get (self, ifindex, network, plen, metric);
}

/******************************************************************/

static const char *
source_to_string (NMIPConfigSource source)
{
	switch (source) {
	case NM_IP_CONFIG_SOURCE_RTPROT_KERNEL:
		return "rtprot-kernel";
	case _NM_IP_CONFIG_SOURCE_RTM_F_CLONED:
		return "rtm-f-cloned";
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
	            nmp_utils_lifetime_rebase_relative_time_on_now (timestamp, lifetime, now, 0));
	return buf;
}


static const char *
_lifetime_summary_to_string (gint32 now, guint32 timestamp, guint32 preferred, guint32 lifetime, char *buf, size_t buf_size)
{
	g_snprintf (buf, buf_size, " lifetime %d-%u[%u,%u]",
	            (signed) now, (unsigned) timestamp, (unsigned) preferred, (unsigned) lifetime);
	return buf;
}

char _nm_platform_to_string_buffer[];

static gboolean
_to_string_buffer_init (gconstpointer obj, char **buf, gsize *len)
{
	if (!*buf) {
		*buf = _nm_platform_to_string_buffer;
		*len = sizeof (_nm_platform_to_string_buffer);
	}
	if (!obj) {
		g_strlcpy (*buf, "(null)", *len);
		return FALSE;
	}
	return TRUE;
}

/**
 * nm_platform_link_to_string:
 * @route: pointer to NMPlatformLink address structure
 * @buf: (allow-none): an optional buffer. If %NULL, a static buffer is used.
 * @len: the size of the @buf. If @buf is %NULL, this argument is ignored.
 *
 * A method for converting an link struct into a string representation.
 *
 * Returns: a string representation of the link.
 */
const char *
nm_platform_link_to_string (const NMPlatformLink *link, char *buf, gsize len)
{
	char master[20];
	char parent[20];
	GString *str_flags;
	char str_addrmode[30];
	gs_free char *str_addr = NULL;
	gs_free char *str_inet6_token = NULL;
	const char *str_link_type;

	if (!_to_string_buffer_init (link, &buf, &len))
		return buf;

	str_flags = g_string_new (NULL);
	if (NM_FLAGS_HAS (link->flags, IFF_NOARP))
		g_string_append (str_flags, "NOARP,");
	if (NM_FLAGS_HAS (link->flags, IFF_UP))
		g_string_append (str_flags, "UP");
	else
		g_string_append (str_flags, "DOWN");
	if (link->connected)
		g_string_append (str_flags, ",LOWER_UP");

	if (link->flags) {
		char str_flags_buf[64];

		rtnl_link_flags2str (link->flags, str_flags_buf, sizeof (str_flags_buf));
		g_string_append_printf (str_flags, ";%s", str_flags_buf);
	}

	if (link->master)
		g_snprintf (master, sizeof (master), " master %d", link->master);
	else
		master[0] = 0;

	if (link->parent > 0)
		g_snprintf (parent, sizeof (parent), "@%d", link->parent);
	else if (link->parent == NM_PLATFORM_LINK_OTHER_NETNS)
		g_strlcpy (parent, "@other-netns", sizeof (parent));
	else
		parent[0] = 0;

	if (link->inet6_addr_gen_mode_inv) {
		switch (_nm_platform_uint8_inv (link->inet6_addr_gen_mode_inv)) {
			case 0:
				g_snprintf (str_addrmode, sizeof (str_addrmode), " addrgenmode eui64");
				break;
			case 1:
				g_snprintf (str_addrmode, sizeof (str_addrmode), " addrgenmode none");
				break;
			default:
				g_snprintf (str_addrmode, sizeof (str_addrmode), " addrgenmode %d", _nm_platform_uint8_inv (link->inet6_addr_gen_mode_inv));
				break;
		}
	} else
		str_addrmode[0] = '\0';

	if (link->addr.len)
		str_addr = nm_utils_hwaddr_ntoa (link->addr.data, MIN (link->addr.len, sizeof (link->addr.data)));
	if (link->inet6_token.is_valid)
		str_inet6_token = nm_utils_hwaddr_ntoa (&link->inet6_token.iid, sizeof (link->inet6_token.iid));

	str_link_type = nm_link_type_to_string (link->type);

	g_snprintf (buf, len,
	            "%d: " /* ifindex */
	            "%s" /* name */
	            "%s" /* parent */
	            " <%s>" /* flags */
	            " mtu %d"
	            "%s" /* master */
	            " arp %u" /* arptype */
	            "%s%s" /* link->type */
	            "%s%s" /* kind */
	            "%s" /* is-in-udev */
	            "%s" /* addr-gen-mode */
	            "%s%s" /* addr */
	            "%s%s" /* inet6_token */
	            "%s%s" /* driver */
	            ,
	            link->ifindex,
	            link->name,
	            parent,
	            str_flags->str,
	            link->mtu, master,
	            link->arptype,
	            str_link_type ? " " : "",
	            str_if_set (str_link_type, "???"),
	            link->kind ? (g_strcmp0 (str_link_type, link->kind) ? "/" : "*") : "",
	            link->kind && g_strcmp0 (str_link_type, link->kind) ? link->kind : "",
	            link->initialized ? " init" : " not-init",
	            str_addrmode,
	            str_addr ? " addr " : "",
	            str_addr ? str_addr : "",
	            str_inet6_token ? " inet6token " : "",
	            str_inet6_token ? str_inet6_token : "",
	            link->driver ? " driver " : "",
	            link->driver ? link->driver : "");
	g_string_free (str_flags, TRUE);
	return buf;
}

const char *
nm_platform_lnk_gre_to_string (const NMPlatformLnkGre *lnk, char *buf, gsize len)
{
	char str_local[30];
	char str_local1[NM_UTILS_INET_ADDRSTRLEN];
	char str_remote[30];
	char str_remote1[NM_UTILS_INET_ADDRSTRLEN];
	char str_ttl[30];
	char str_tos[30];
	char str_parent_ifindex[30];
	char str_input_flags[30];
	char str_output_flags[30];
	char str_input_key[30];
	char str_input_key1[NM_UTILS_INET_ADDRSTRLEN];
	char str_output_key[30];
	char str_output_key1[NM_UTILS_INET_ADDRSTRLEN];

	if (!_to_string_buffer_init (lnk, &buf, &len))
		return buf;

	g_snprintf (buf, len,
	            "gre"
	            "%s" /* remote */
	            "%s" /* local */
	            "%s" /* parent_ifindex */
	            "%s" /* ttl */
	            "%s" /* tos */
	            "%s" /* path_mtu_discovery */
	            "%s" /* iflags */
	            "%s" /* oflags */
	            "%s" /* ikey */
	            "%s" /* okey */
	            "",
	            lnk->remote ? nm_sprintf_buf (str_remote, " remote %s", nm_utils_inet4_ntop (lnk->remote, str_remote1)) : "",
	            lnk->local ? nm_sprintf_buf (str_local, " local %s", nm_utils_inet4_ntop (lnk->local, str_local1)) : "",
	            lnk->parent_ifindex ? nm_sprintf_buf (str_parent_ifindex, " dev %d", lnk->parent_ifindex) : "",
	            lnk->ttl ? nm_sprintf_buf (str_ttl, " ttl %u", lnk->ttl) : " ttl inherit",
	            lnk->tos ? (lnk->tos == 1 ? " tos inherit" : nm_sprintf_buf (str_tos, " tos 0x%x", lnk->tos)) : "",
	            lnk->path_mtu_discovery ? "" : " nopmtudisc",
	            lnk->input_flags ? nm_sprintf_buf (str_input_flags, " iflags 0x%x", lnk->input_flags) : "",
	            lnk->output_flags ? nm_sprintf_buf (str_output_flags, " oflags 0x%x", lnk->output_flags) : "",
	            NM_FLAGS_HAS (lnk->input_flags, GRE_KEY) || lnk->input_key ? nm_sprintf_buf (str_input_key, " ikey %s", nm_utils_inet4_ntop (lnk->input_key, str_input_key1)) : "",
	            NM_FLAGS_HAS (lnk->output_flags, GRE_KEY) || lnk->output_key ? nm_sprintf_buf (str_output_key, " okey %s", nm_utils_inet4_ntop (lnk->output_key, str_output_key1)) : "");
	return buf;
}

const char *
nm_platform_lnk_infiniband_to_string (const NMPlatformLnkInfiniband *lnk, char *buf, gsize len)
{
	char str_p_key[64];

	if (!_to_string_buffer_init (lnk, &buf, &len))
		return buf;

	g_snprintf (buf, len,
	            "infiniband"
	            "%s" /* p_key */
	            "%s%s" /* mode */
	            "",
	            lnk->p_key ? nm_sprintf_buf (str_p_key, " pkey %d", lnk->p_key) : "",
	            lnk->mode ? " mode " : "",
	            lnk->mode ?: "");
	return buf;
}

const char *
nm_platform_lnk_macvlan_to_string (const NMPlatformLnkMacvlan *lnk, char *buf, gsize len)
{
	if (!_to_string_buffer_init (lnk, &buf, &len))
		return buf;

	g_snprintf (buf, len,
	            "macvlan%s%s%s",
	            lnk->mode ? " mode " : "",
	            lnk->mode ?: "",
	            lnk->no_promisc ? " not-promisc" : " promisc");
	return buf;
}

const char *
nm_platform_lnk_vlan_to_string (const NMPlatformLnkVlan *lnk, char *buf, gsize len)
{
	if (!_to_string_buffer_init (lnk, &buf, &len))
		return buf;

	g_snprintf (buf, len, "vlan %u", (guint) lnk->id);
	return buf;
}

const char *
nm_platform_lnk_vxlan_to_string (const NMPlatformLnkVxlan *lnk, char *buf, gsize len)
{
	char str_group[100];
	char str_group6[100];
	char str_local[100];
	char str_local6[100];
	char str_dev[25];
	char str_limit[25];
	char str_src_port[35];
	char str_dst_port[25];
	char str_tos[25];
	char str_ttl[25];

	if (!_to_string_buffer_init (lnk, &buf, &len))
		return buf;

	if (lnk->group == 0)
		str_group[0] = '\0';
	else {
		g_snprintf (str_group, sizeof (str_group),
		            " %s %s",
		            IN_MULTICAST (ntohl (lnk->group)) ? "group" : "remote",
		            nm_utils_inet4_ntop (lnk->group, NULL));
	}
	if (IN6_IS_ADDR_UNSPECIFIED (&lnk->group6))
		str_group6[0] = '\0';
	else {
		g_snprintf (str_group6, sizeof (str_group6),
		            " %s%s %s",
		            IN6_IS_ADDR_MULTICAST (&lnk->group6) ? "group" : "remote",
		            str_group[0] ? "6" : "", /* usually, a vxlan has either v4 or v6 only. */
		            nm_utils_inet6_ntop (&lnk->group6, NULL));
	}

	if (lnk->local == 0)
		str_local[0] = '\0';
	else {
		g_snprintf (str_local, sizeof (str_local),
		            " local %s",
		            nm_utils_inet4_ntop (lnk->local, NULL));
	}
	if (IN6_IS_ADDR_UNSPECIFIED (&lnk->local6))
		str_local6[0] = '\0';
	else {
		g_snprintf (str_local6, sizeof (str_local6),
		            " local%s %s",
		            str_local[0] ? "6" : "", /* usually, a vxlan has either v4 or v6 only. */
		            nm_utils_inet6_ntop (&lnk->local6, NULL));
	}

	g_snprintf (buf, len,
	            "vxlan"
	            " id %u" /* id */
	            "%s%s" /* group/group6 */
	            "%s%s" /* local/local6 */
	            "%s" /* dev */
	            "%s" /* src_port_min/src_port_max */
	            "%s" /* dst_port */
	            "%s" /* learning */
	            "%s" /* proxy */
	            "%s" /* rsc */
	            "%s" /* l2miss */
	            "%s" /* l3miss */
	            "%s" /* tos */
	            "%s" /* ttl */
	            " ageing %u" /* ageing */
	            "%s" /* limit */
	            "",
	            (guint) lnk->id,
	            str_group, str_group6,
	            str_local, str_local6,
	            lnk->parent_ifindex ? nm_sprintf_buf (str_dev, " dev %d", lnk->parent_ifindex) : "",
	            lnk->src_port_min || lnk->src_port_max ? nm_sprintf_buf (str_src_port, " srcport %u %u", lnk->src_port_min, lnk->src_port_max) : "",
	            lnk->dst_port ? nm_sprintf_buf (str_dst_port, " dstport %u", lnk->dst_port) : "",
	            !lnk->learning ? " nolearning" : "",
	            lnk->proxy ? " proxy" : "",
	            lnk->rsc ? " rsc" : "",
	            lnk->l2miss ? " l2miss" : "",
	            lnk->l3miss ? " l3miss" : "",
	            lnk->tos == 1 ? " tos inherit" : nm_sprintf_buf (str_tos, " tos %#x", lnk->tos),
	            lnk->ttl ? nm_sprintf_buf (str_ttl, " ttl %u", lnk->ttl) : "",
	            lnk->ageing,
	            lnk->limit ? nm_sprintf_buf (str_limit, " maxaddr %u", lnk->limit) : "");
	return buf;
}

/**
 * nm_platform_ip4_address_to_string:
 * @route: pointer to NMPlatformIP4Address address structure
 * @buf: (allow-none): an optional buffer. If %NULL, a static buffer is used.
 * @len: the size of the @buf. If @buf is %NULL, this argument is ignored.
 *
 * A method for converting an address struct into a string representation.
 *
 * Example output: ""
 *
 * Returns: a string representation of the address.
 */
const char *
nm_platform_ip4_address_to_string (const NMPlatformIP4Address *address, char *buf, gsize len)
{
	char s_address[INET_ADDRSTRLEN];
	char s_peer[INET_ADDRSTRLEN];
	char str_dev[TO_STRING_DEV_BUF_SIZE];
	char str_label[32];
	char str_lft[30], str_pref[30], str_time[50];
	char *str_peer = NULL;
	const char *str_lft_p, *str_pref_p, *str_time_p;
	gint32 now = nm_utils_get_monotonic_timestamp_s ();

	if (!_to_string_buffer_init (address, &buf, &len))
		return buf;

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

	g_snprintf (buf, len,
	            "%s/%d lft %s pref %s%s%s%s%s src %s",
	            s_address, address->plen, str_lft_p, str_pref_p, str_time_p,
	            str_peer ? str_peer : "",
	            str_dev,
	            str_label,
	            source_to_string (address->source));
	g_free (str_peer);
	return buf;
}

/**
 * nm_platform_addr_flags2str: wrapper for rtnl_addr_flags2str(),
 * which might not yet support some recent address flags.
 **/
void
nm_platform_addr_flags2str (int flags, char *buf, size_t size)
{
	if (   !NM_FLAGS_ANY (flags, IFA_F_MANAGETEMPADDR | IFA_F_NOPREFIXROUTE)
	    || nm_platform_check_support_libnl_extended_ifa_flags ())
		rtnl_addr_flags2str (flags, buf, size);
	else {
		/* There are two recent flags IFA_F_MANAGETEMPADDR and IFA_F_NOPREFIXROUTE.
		 * If libnl does not yet support them, add them by hand.
		 * These two flags were introduced together with the extended ifa_flags
		 * so check for nm_platform_check_support_libnl_extended_ifa_flags (). */
		gboolean has_other_unknown_flags = FALSE;
		size_t len;

		/* if there are unknown flags to rtnl_addr_flags2str(), libnl appends ','
		 * to indicate them. We want to keep this behavior, if there are other
		 * unknown flags present. */

		rtnl_addr_flags2str (flags & ~(IFA_F_MANAGETEMPADDR | IFA_F_NOPREFIXROUTE), buf, size);

		len = strlen (buf);
		if (len > 0) {
			has_other_unknown_flags = (buf[len - 1] == ',');
			if (!has_other_unknown_flags)
				g_strlcat (buf, ",", size);
		}

		if (NM_FLAGS_ALL (flags, IFA_F_MANAGETEMPADDR | IFA_F_NOPREFIXROUTE))
			g_strlcat (buf, IFA_F_MANAGETEMPADDR_STR","IFA_F_NOPREFIXROUTE_STR, size);
		else if (NM_FLAGS_HAS (flags, IFA_F_MANAGETEMPADDR))
			g_strlcat (buf, IFA_F_MANAGETEMPADDR_STR, size);
		else
			g_strlcat (buf, IFA_F_NOPREFIXROUTE_STR, size);

		if (has_other_unknown_flags)
			g_strlcat (buf, ",", size);
	}
}

/**
 * nm_platform_ip6_address_to_string:
 * @route: pointer to NMPlatformIP6Address address structure
 * @buf: (allow-none): an optional buffer. If %NULL, a static buffer is used.
 * @len: the size of the @buf. If @buf is %NULL, this argument is ignored.
 *
 * A method for converting an address struct into a string representation.
 *
 * Example output: "2001:db8:0:f101::1/64 lft 4294967295 pref 4294967295 time 16922666 on dev em1"
 *
 * Returns: a string representation of the address.
 */
const char *
nm_platform_ip6_address_to_string (const NMPlatformIP6Address *address, char *buf, gsize len)
{
#define S_FLAGS_PREFIX " flags "
	char s_flags[256];
	char s_address[INET6_ADDRSTRLEN];
	char s_peer[INET6_ADDRSTRLEN];
	char str_lft[30], str_pref[30], str_time[50];
	char str_dev[TO_STRING_DEV_BUF_SIZE];
	char *str_peer = NULL;
	const char *str_lft_p, *str_pref_p, *str_time_p;
	gint32 now = nm_utils_get_monotonic_timestamp_s ();

	if (!_to_string_buffer_init (address, &buf, &len))
		return buf;

	inet_ntop (AF_INET6, &address->address, s_address, sizeof (s_address));

	if (!IN6_IS_ADDR_UNSPECIFIED (&address->peer_address)) {
		inet_ntop (AF_INET6, &address->peer_address, s_peer, sizeof (s_peer));
		str_peer = g_strconcat (" ptp ", s_peer, NULL);
	}

	_to_string_dev (NULL, address->ifindex, str_dev, sizeof (str_dev));

	nm_platform_addr_flags2str (address->flags, &s_flags[STRLEN (S_FLAGS_PREFIX)], sizeof (s_flags) - STRLEN (S_FLAGS_PREFIX));
	if (s_flags[STRLEN (S_FLAGS_PREFIX)] == '\0')
		s_flags[0] = '\0';
	else
		memcpy (s_flags, S_FLAGS_PREFIX, STRLEN (S_FLAGS_PREFIX));

	str_lft_p = _lifetime_to_string (address->timestamp,
	                                 address->lifetime ? address->lifetime : NM_PLATFORM_LIFETIME_PERMANENT,
	                                 now, str_lft, sizeof (str_lft)),
	str_pref_p = (address->lifetime == address->preferred)
	             ? str_lft_p
	             : ( _lifetime_to_string (address->timestamp,
	                                      address->lifetime ? MIN (address->preferred, address->lifetime) : NM_PLATFORM_LIFETIME_PERMANENT,
	                                      now, str_pref, sizeof (str_pref)) );
	str_time_p = _lifetime_summary_to_string (now, address->timestamp, address->preferred, address->lifetime, str_time, sizeof (str_time));

	g_snprintf (buf, len,
	            "%s/%d lft %s pref %s%s%s%s%s src %s",
	            s_address, address->plen, str_lft_p, str_pref_p, str_time_p,
	            str_peer ? str_peer : "",
	            str_dev,
	            s_flags,
	            source_to_string (address->source));
	g_free (str_peer);
	return buf;
}

/**
 * nm_platform_ip4_route_to_string:
 * @route: pointer to NMPlatformIP4Route route structure
 * @buf: (allow-none): an optional buffer. If %NULL, a static buffer is used.
 * @len: the size of the @buf. If @buf is %NULL, this argument is ignored.
 *
 * A method for converting a route struct into a string representation.
 *
 * Example output: "192.168.1.0/24 via 0.0.0.0 dev em1 metric 0 mss 0"
 *
 * Returns: a string representation of the route.
 */
const char *
nm_platform_ip4_route_to_string (const NMPlatformIP4Route *route, char *buf, gsize len)
{
	char s_network[INET_ADDRSTRLEN], s_gateway[INET_ADDRSTRLEN];
	char s_pref_src[INET_ADDRSTRLEN];
	char str_dev[TO_STRING_DEV_BUF_SIZE];
	char str_scope[30];

	if (!_to_string_buffer_init (route, &buf, &len))
		return buf;

	inet_ntop (AF_INET, &route->network, s_network, sizeof(s_network));
	inet_ntop (AF_INET, &route->gateway, s_gateway, sizeof(s_gateway));

	_to_string_dev (NULL, route->ifindex, str_dev, sizeof (str_dev));

	g_snprintf (buf, len,
	            "%s/%d"
	            " via %s"
	            "%s"
	            " metric %"G_GUINT32_FORMAT
	            " mss %"G_GUINT32_FORMAT
	            " src %s" /* source */
	            "%s%s" /* scope */
	            "%s%s" /* pref-src */
	            "",
	            s_network, route->plen,
	            s_gateway,
	            str_dev,
	            route->metric,
	            route->mss,
	            source_to_string (route->source),
	            route->scope_inv ? " scope " : "",
	            route->scope_inv ? (rtnl_scope2str (nm_platform_route_scope_inv (route->scope_inv), str_scope, sizeof (str_scope))) : "",
	            route->pref_src ? " pref-src " : "",
	            route->pref_src ? inet_ntop (AF_INET, &route->pref_src, s_pref_src, sizeof(s_pref_src)) : "");
	return buf;
}

/**
 * nm_platform_ip6_route_to_string:
 * @route: pointer to NMPlatformIP6Route route structure
 * @buf: (allow-none): an optional buffer. If %NULL, a static buffer is used.
 * @len: the size of the @buf. If @buf is %NULL, this argument is ignored.
 *
 * A method for converting a route struct into a string representation.
 *
 * Example output: "ff02::fb/128 via :: dev em1 metric 0"
 *
 * Returns: a string representation of the route.
 */
const char *
nm_platform_ip6_route_to_string (const NMPlatformIP6Route *route, char *buf, gsize len)
{
	char s_network[INET6_ADDRSTRLEN], s_gateway[INET6_ADDRSTRLEN];
	char str_dev[TO_STRING_DEV_BUF_SIZE];

	if (!_to_string_buffer_init (route, &buf, &len))
		return buf;

	inet_ntop (AF_INET6, &route->network, s_network, sizeof(s_network));
	inet_ntop (AF_INET6, &route->gateway, s_gateway, sizeof(s_gateway));

	_to_string_dev (NULL, route->ifindex, str_dev, sizeof (str_dev));

	g_snprintf (buf, len,
	            "%s/%d"
	            " via %s"
	            "%s"
	            " metric %"G_GUINT32_FORMAT
	            " mss %"G_GUINT32_FORMAT
	            " src %s" /* source */
	            "",
	            s_network, route->plen,
	            s_gateway,
	            str_dev,
	            route->metric,
	            route->mss,
	            source_to_string (route->source));
	return buf;
}

#define _CMP_SELF(a, b)                                     \
    G_STMT_START {                                          \
        if ((a) == (b))                                     \
            return 0;                                       \
        if (!(a))                                           \
            return -1;                                      \
        if (!(b))                                           \
            return 1;                                       \
    } G_STMT_END

#define _CMP_DIRECT(a, b)                                   \
    G_STMT_START {                                          \
        if ((a) != (b))                                     \
            return ((a) < (b)) ? -1 : 1;                    \
    } G_STMT_END

#define _CMP_DIRECT_MEMCMP(a, b, size)                      \
    G_STMT_START {                                          \
        int c = memcmp ((a), (b), (size));                  \
        if (c != 0)                                         \
            return c < 0 ? -1 : 1;                          \
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
	_CMP_SELF (a, b);
	_CMP_FIELD (a, b, ifindex);
	_CMP_FIELD (a, b, type);
	_CMP_FIELD_STR (a, b, name);
	_CMP_FIELD (a, b, master);
	_CMP_FIELD (a, b, parent);
	_CMP_FIELD (a, b, flags);
	_CMP_FIELD (a, b, connected);
	_CMP_FIELD (a, b, mtu);
	_CMP_FIELD_BOOL (a, b, initialized);
	_CMP_FIELD (a, b, arptype);
	_CMP_FIELD (a, b, addr.len);
	_CMP_FIELD (a, b, inet6_addr_gen_mode_inv);
	_CMP_FIELD (a, b, inet6_token.is_valid);
	_CMP_FIELD_STR_INTERNED (a, b, kind);
	_CMP_FIELD_STR_INTERNED (a, b, driver);
	if (a->addr.len)
		_CMP_FIELD_MEMCMP_LEN (a, b, addr.data, a->addr.len);
	if (a->inet6_token.is_valid)
		_CMP_FIELD_MEMCMP (a, b, inet6_token.iid);
	return 0;
}

int
nm_platform_lnk_gre_cmp (const NMPlatformLnkGre *a, const NMPlatformLnkGre *b)
{
	_CMP_SELF (a, b);
	_CMP_FIELD (a, b, parent_ifindex);
	_CMP_FIELD (a, b, input_flags);
	_CMP_FIELD (a, b, output_flags);
	_CMP_FIELD (a, b, input_key);
	_CMP_FIELD (a, b, output_key);
	_CMP_FIELD (a, b, local);
	_CMP_FIELD (a, b, remote);
	_CMP_FIELD (a, b, ttl);
	_CMP_FIELD (a, b, tos);
	_CMP_FIELD_BOOL (a, b, path_mtu_discovery);
	return 0;
}

int
nm_platform_lnk_infiniband_cmp (const NMPlatformLnkInfiniband *a, const NMPlatformLnkInfiniband *b)
{
	_CMP_SELF (a, b);
	_CMP_FIELD (a, b, p_key);
	_CMP_FIELD_STR_INTERNED (a, b, mode);
	return 0;
}

int
nm_platform_lnk_macvlan_cmp (const NMPlatformLnkMacvlan *a, const NMPlatformLnkMacvlan *b)
{
	_CMP_SELF (a, b);
	_CMP_FIELD_STR_INTERNED (a, b, mode);
	_CMP_FIELD_BOOL (a, b, no_promisc);
	return 0;
}

int
nm_platform_lnk_vlan_cmp (const NMPlatformLnkVlan *a, const NMPlatformLnkVlan *b)
{
	_CMP_SELF (a, b);
	_CMP_FIELD (a, b, id);
	return 0;
}

int
nm_platform_lnk_vxlan_cmp (const NMPlatformLnkVxlan *a, const NMPlatformLnkVxlan *b)
{
	_CMP_SELF (a, b);
	_CMP_FIELD (a, b, parent_ifindex);
	_CMP_FIELD (a, b, id);
	_CMP_FIELD (a, b, group);
	_CMP_FIELD (a, b, local);
	_CMP_FIELD_MEMCMP (a, b, group6);
	_CMP_FIELD_MEMCMP (a, b, local6);
	_CMP_FIELD (a, b, tos);
	_CMP_FIELD (a, b, ttl);
	_CMP_FIELD_BOOL (a, b, learning);
	_CMP_FIELD (a, b, ageing);
	_CMP_FIELD (a, b, limit);
	_CMP_FIELD (a, b, dst_port);
	_CMP_FIELD (a, b, src_port_min);
	_CMP_FIELD (a, b, src_port_max);
	_CMP_FIELD_BOOL (a, b, proxy);
	_CMP_FIELD_BOOL (a, b, rsc);
	_CMP_FIELD_BOOL (a, b, l2miss);
	_CMP_FIELD_BOOL (a, b, l3miss);
	return 0;
}

int
nm_platform_ip4_address_cmp (const NMPlatformIP4Address *a, const NMPlatformIP4Address *b)
{
	in_addr_t p_a, p_b;

	_CMP_SELF (a, b);
	_CMP_FIELD (a, b, ifindex);
	_CMP_FIELD (a, b, source);
	_CMP_FIELD (a, b, address);
	_CMP_FIELD (a, b, plen);

	/* a peer-address of zero is the same as setting it to address.
	 * Here we consider the full address, including the host-part. */
	p_a = nm_platform_ip4_address_get_peer (a);
	p_b = nm_platform_ip4_address_get_peer (b);
	_CMP_DIRECT (p_a, p_b);

	_CMP_FIELD (a, b, timestamp);
	_CMP_FIELD (a, b, lifetime);
	_CMP_FIELD (a, b, preferred);
	_CMP_FIELD_STR (a, b, label);
	return 0;
}

int
nm_platform_ip6_address_cmp (const NMPlatformIP6Address *a, const NMPlatformIP6Address *b)
{
	const struct in6_addr *p_a, *p_b;

	_CMP_SELF (a, b);
	_CMP_FIELD (a, b, ifindex);
	_CMP_FIELD (a, b, source);
	_CMP_FIELD_MEMCMP (a, b, address);

	p_a = nm_platform_ip6_address_get_peer (a);
	p_b = nm_platform_ip6_address_get_peer (b);
	_CMP_DIRECT_MEMCMP (p_a, p_b, sizeof (*p_a));

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
	_CMP_SELF (a, b);
	_CMP_FIELD (a, b, ifindex);
	_CMP_FIELD (a, b, source);
	_CMP_FIELD (a, b, network);
	_CMP_FIELD (a, b, plen);
	_CMP_FIELD (a, b, gateway);
	_CMP_FIELD (a, b, metric);
	_CMP_FIELD (a, b, mss);
	_CMP_FIELD (a, b, scope_inv);
	_CMP_FIELD (a, b, pref_src);
	return 0;
}

int
nm_platform_ip6_route_cmp (const NMPlatformIP6Route *a, const NMPlatformIP6Route *b)
{
	_CMP_SELF (a, b);
	_CMP_FIELD (a, b, ifindex);
	_CMP_FIELD (a, b, source);
	_CMP_FIELD_MEMCMP (a, b, network);
	_CMP_FIELD (a, b, plen);
	_CMP_FIELD_MEMCMP (a, b, gateway);
	_CMP_FIELD (a, b, metric);
	_CMP_FIELD (a, b, mss);
	return 0;
}

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

	_CMP_SELF (a, b);

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
log_link (NMPlatform *self, NMPObjectType obj_type, int ifindex, NMPlatformLink *device, NMPlatformSignalChangeType change_type, gpointer user_data)
{

	_LOGD ("signal: link %7s: %s", nm_platform_signal_change_type_to_string (change_type), nm_platform_link_to_string (device, NULL, 0));
}

static void
log_ip4_address (NMPlatform *self, NMPObjectType obj_type, int ifindex, NMPlatformIP4Address *address, NMPlatformSignalChangeType change_type, gpointer user_data)
{
	_LOGD ("signal: address 4 %7s: %s", nm_platform_signal_change_type_to_string (change_type), nm_platform_ip4_address_to_string (address, NULL, 0));
}

static void
log_ip6_address (NMPlatform *self, NMPObjectType obj_type, int ifindex, NMPlatformIP6Address *address, NMPlatformSignalChangeType change_type, gpointer user_data)
{
	_LOGD ("signal: address 6 %7s: %s", nm_platform_signal_change_type_to_string (change_type), nm_platform_ip6_address_to_string (address, NULL, 0));
}

static void
log_ip4_route (NMPlatform *self, NMPObjectType obj_type, int ifindex, NMPlatformIP4Route *route, NMPlatformSignalChangeType change_type, gpointer user_data)
{
	_LOGD ("signal: route   4 %7s: %s", nm_platform_signal_change_type_to_string (change_type), nm_platform_ip4_route_to_string (route, NULL, 0));
}

static void
log_ip6_route (NMPlatform *self, NMPObjectType obj_type, int ifindex, NMPlatformIP6Route *route, NMPlatformSignalChangeType change_type, gpointer user_data)
{
	_LOGD ("signal: route   6 %7s: %s", nm_platform_signal_change_type_to_string (change_type), nm_platform_ip6_route_to_string (route, NULL, 0));
}

/******************************************************************/

static gboolean
_vtr_v4_route_add (NMPlatform *self, int ifindex, const NMPlatformIPXRoute *route, gint64 metric)
{
	return nm_platform_ip4_route_add (self,
	                                  ifindex > 0 ? ifindex : route->rx.ifindex,
	                                  route->rx.source,
	                                  route->r4.network,
	                                  route->rx.plen,
	                                  route->r4.gateway,
	                                  route->r4.pref_src,
	                                  metric >= 0 ? (guint32) metric : route->rx.metric,
	                                  route->rx.mss);
}

static gboolean
_vtr_v6_route_add (NMPlatform *self, int ifindex, const NMPlatformIPXRoute *route, gint64 metric)
{
	return nm_platform_ip6_route_add (self,
	                                  ifindex > 0 ? ifindex : route->rx.ifindex,
	                                  route->rx.source,
	                                  route->r6.network,
	                                  route->rx.plen,
	                                  route->r6.gateway,
	                                  metric >= 0 ? (guint32) metric : route->rx.metric,
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
	.route_to_string                = (const char *(*) (const NMPlatformIPXRoute *route, char *buf, gsize len)) nm_platform_ip4_route_to_string,
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
	.route_to_string                = (const char *(*) (const NMPlatformIPXRoute *route, char *buf, gsize len)) nm_platform_ip6_route_to_string,
	.route_get_all                  = nm_platform_ip6_route_get_all,
	.route_add                      = _vtr_v6_route_add,
	.route_delete                   = _vtr_v6_route_delete,
	.route_delete_default           = _vtr_v6_route_delete_default,
	.metric_normalize               = nm_utils_ip6_route_metric_normalize,
};

/******************************************************************/

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMPlatformPrivate *priv =  NM_PLATFORM_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_REGISTER_SINGLETON:
		/* construct-only */
		priv->register_singleton = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
constructed (GObject *object)
{
	NMPlatform *self = NM_PLATFORM (object);
	NMPlatformPrivate *priv =  NM_PLATFORM_GET_PRIVATE (self);

	G_OBJECT_CLASS (nm_platform_parent_class)->constructed (object);

	if (priv->register_singleton)
		nm_platform_setup (self);
}

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
		G_TYPE_NONE, 5, NM_TYPE_POBJECT_TYPE, G_TYPE_INT, G_TYPE_POINTER, NM_TYPE_PLATFORM_SIGNAL_CHANGE_TYPE, NM_TYPE_PLATFORM_REASON);

static void
nm_platform_class_init (NMPlatformClass *platform_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (platform_class);

	g_type_class_add_private (object_class, sizeof (NMPlatformPrivate));

	object_class->set_property = set_property;
	object_class->constructed = constructed;

	platform_class->wifi_set_powersave = wifi_set_powersave;

	g_object_class_install_property
	 (object_class, PROP_REGISTER_SINGLETON,
	     g_param_spec_boolean (NM_PLATFORM_REGISTER_SINGLETON, "", "",
	                           FALSE,
	                           G_PARAM_WRITABLE |
	                           G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS));

	/* Signals */
	SIGNAL (SIGNAL_LINK_CHANGED, log_link)
	SIGNAL (SIGNAL_IP4_ADDRESS_CHANGED, log_ip4_address)
	SIGNAL (SIGNAL_IP6_ADDRESS_CHANGED, log_ip6_address)
	SIGNAL (SIGNAL_IP4_ROUTE_CHANGED, log_ip4_route)
	SIGNAL (SIGNAL_IP6_ROUTE_CHANGED, log_ip6_route)
}
