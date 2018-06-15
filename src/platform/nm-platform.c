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
 * Copyright (C) 2012 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-platform.h"

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/if_tun.h>
#include <linux/if_tunnel.h>
#include <linux/rtnetlink.h>
#include <libudev.h>

#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nm-utils/nm-dedup-multi.h"
#include "nm-utils/nm-udev-utils.h"

#include "nm-core-utils.h"
#include "nm-platform-utils.h"
#include "nm-platform-private.h"
#include "nmp-object.h"
#include "nmp-netns.h"

/*****************************************************************************/

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
            const NMPlatform *const __self = (self); \
            \
            if (__self && NM_PLATFORM_GET_PRIVATE (__self)->log_with_ptr) { \
                g_snprintf (__prefix, sizeof (__prefix), "%s[%p]", _NMLOG_PREFIX_NAME, __self); \
                __p_prefix = __prefix; \
            } \
            _nm_log (__level, _NMLOG_DOMAIN, 0, NULL, NULL, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     __p_prefix _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

#define LOG_FMT_IP_TUNNEL "adding %s '%s' parent %u local %s remote %s"

/*****************************************************************************/

static guint signals[_NM_PLATFORM_SIGNAL_ID_LAST] = { 0 };

enum {
	PROP_0,
	PROP_NETNS_SUPPORT,
	PROP_USE_UDEV,
	PROP_LOG_WITH_PTR,
	LAST_PROP,
};

typedef struct _NMPlatformPrivate {
	bool use_udev:1;
	bool log_with_ptr:1;

	NMPlatformKernelSupportFlags support_checked;
	NMPlatformKernelSupportFlags support_present;

	guint ip4_dev_route_blacklist_check_id;
	guint ip4_dev_route_blacklist_gc_timeout_id;
	GHashTable *ip4_dev_route_blacklist_hash;
	NMDedupMultiIndex *multi_idx;
	NMPCache *cache;
} NMPlatformPrivate;

G_DEFINE_TYPE (NMPlatform, nm_platform, G_TYPE_OBJECT)

#define NM_PLATFORM_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR (self, NMPlatform, NM_IS_PLATFORM)

/*****************************************************************************/

static void _ip4_dev_route_blacklist_schedule (NMPlatform *self);

/*****************************************************************************/

gboolean
nm_platform_get_use_udev (NMPlatform *self)
{
	return NM_PLATFORM_GET_PRIVATE (self)->use_udev;
}

gboolean
nm_platform_get_log_with_ptr (NMPlatform *self)
{
	return NM_PLATFORM_GET_PRIVATE (self)->log_with_ptr;
}

/*****************************************************************************/

guint
_nm_platform_signal_id_get (NMPlatformSignalIdType signal_type)
{
	nm_assert (   signal_type > 0
	           && signal_type != NM_PLATFORM_SIGNAL_ID_NONE
	           && signal_type < _NM_PLATFORM_SIGNAL_ID_LAST);

	return signals[signal_type];
}

/*****************************************************************************/

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

#define _CHECK_SELF_NETNS(self, klass, netns, err_val) \
	nm_auto_pop_netns NMPNetns *netns = NULL; \
	NMPlatformClass *klass; \
	do { \
		g_return_val_if_fail (NM_IS_PLATFORM (self), err_val); \
		klass = NM_PLATFORM_GET_CLASS (self); \
		(void) klass; \
		if (!nm_platform_netns_push (self, &netns)) \
			return (err_val); \
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

/*****************************************************************************/

NMDedupMultiIndex *
nm_platform_get_multi_idx (NMPlatform *self)
{
	g_return_val_if_fail (NM_IS_PLATFORM (self), NULL);

	return NM_PLATFORM_GET_PRIVATE (self)->multi_idx;
}

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_nm_platform_error_to_string, NMPlatformError,
	NM_UTILS_LOOKUP_DEFAULT (NULL),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_ERROR_SUCCESS,     "success"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_ERROR_BUG,         "bug"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_ERROR_UNSPECIFIED, "unspecified"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_ERROR_NOT_FOUND,   "not-found"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_ERROR_EXISTS,      "exists"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_ERROR_WRONG_TYPE,  "wrong-type"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_ERROR_NOT_SLAVE,   "not-slave"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_ERROR_NO_FIRMWARE, "no-firmware"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_ERROR_OPNOTSUPP,   "not-supported"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_ERROR_NETLINK,     "netlink"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_ERROR_CANT_SET_MTU, "cant-set-mtu"),
	NM_UTILS_LOOKUP_ITEM_IGNORE (_NM_PLATFORM_ERROR_MININT),
);

/**
 * nm_platform_error_to_string:
 * @error_code: the error code to stringify.
 * @buf: (allow-none): buffer
 * @buf_len: size of buffer
 *
 * Returns: A string representation of the error.
 * For negative numbers, this function interprets
 * the code as -errno.
 * For invalid (positive) numbers it returns NULL.
 */
const char *
nm_platform_error_to_string (NMPlatformError error_code, char *buf, gsize buf_len)
{
	const char *s;

	if (error_code < 0) {
		int errsv = -((int) error_code);

		nm_utils_to_string_buffer_init (&buf, &buf_len);
		g_snprintf (buf, buf_len, "%s (%d)", g_strerror (errsv), errsv);
	} else {
		s = _nm_platform_error_to_string (error_code);
		if (s) {
			if (!buf)
				return s;
			g_strlcpy (buf, s, buf_len);
		} else {
			nm_utils_to_string_buffer_init (&buf, &buf_len);
			g_snprintf (buf, buf_len, "(%d)", (int) error_code);
		}
	}

	return buf;
}

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_nmp_nlm_flag_to_string_lookup, NMPNlmFlags,
	NM_UTILS_LOOKUP_DEFAULT (NULL),
	NM_UTILS_LOOKUP_ITEM (NMP_NLM_FLAG_ADD,     "add"),
	NM_UTILS_LOOKUP_ITEM (NMP_NLM_FLAG_CHANGE,  "change"),
	NM_UTILS_LOOKUP_ITEM (NMP_NLM_FLAG_REPLACE, "replace"),
	NM_UTILS_LOOKUP_ITEM (NMP_NLM_FLAG_PREPEND, "prepend"),
	NM_UTILS_LOOKUP_ITEM (NMP_NLM_FLAG_APPEND,  "append"),
	NM_UTILS_LOOKUP_ITEM (NMP_NLM_FLAG_TEST,    "test"),
	NM_UTILS_LOOKUP_ITEM_IGNORE (NMP_NLM_FLAG_F_APPEND),
	NM_UTILS_LOOKUP_ITEM_IGNORE (NMP_NLM_FLAG_FMASK),
	NM_UTILS_LOOKUP_ITEM_IGNORE (NMP_NLM_FLAG_SUPPRESS_NETLINK_FAILURE),
);

#define _nmp_nlm_flag_to_string(flags) \
	({ \
		NMPNlmFlags _flags = (flags); \
		\
		_nmp_nlm_flag_to_string_lookup (flags) ?: nm_sprintf_bufa (100, "new[0x%x]", (unsigned) _flags); \
	})

/*****************************************************************************/

NMPlatformKernelSupportFlags
nm_platform_check_kernel_support (NMPlatform *self,
                                  NMPlatformKernelSupportFlags request_flags)
{
	NMPlatformPrivate *priv;

	_CHECK_SELF (self, klass, TRUE);

	priv = NM_PLATFORM_GET_PRIVATE (self);

	/* we cache the response from subclasses and only request it once.
	 * This probably gives better performance, but more importantly,
	 * we are guaranteed that the answer for a certain request_flag
	 * is always the same. */
	if (G_UNLIKELY (!NM_FLAGS_ALL (priv->support_checked, request_flags))) {
		NMPlatformKernelSupportFlags checked, response;

		checked = request_flags & ~priv->support_checked;
		nm_assert (checked);

		if (klass->check_kernel_support)
			response = klass->check_kernel_support (self, checked);
		else {
			/* fake platform. Pretend no support for anything. */
			response = 0;
		}

		priv->support_checked |= checked;
		priv->support_present = (priv->support_present & ~checked) | (response & checked);
	}

	return priv->support_present & request_flags;
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

const NMPlatformLink *
nm_platform_process_events_ensure_link (NMPlatform *self,
                                        int ifindex,
                                        const char *ifname)
{
	const NMPObject *obj;
	gboolean refreshed = FALSE;

	g_return_val_if_fail (NM_IS_PLATFORM (self), NULL);

	if (ifindex <= 0 && !ifname)
		return NULL;

	/* we look into the cache, whether a link for given ifindex/ifname
	 * exits. If not, we poll the netlink socket, maybe the event
	 * with the link is waiting.
	 *
	 * Then we try again to find the object.
	 *
	 * If the link is already cached the first time, we avoid polling
	 * the netlink socket. */
again:
	obj = nmp_cache_lookup_link_full (nm_platform_get_cache (self),
	                                  ifindex,
	                                  ifname,
	                                  FALSE, /* also invisible. We don't care here whether udev is ready */
	                                  NM_LINK_TYPE_NONE,
	                                  NULL, NULL);
	if (obj)
		return NMP_OBJECT_CAST_LINK (obj);
	if (!refreshed) {
		refreshed = TRUE;
		nm_platform_process_events (self);
		goto again;
	}

	return NULL;
}

/*****************************************************************************/

/**
 * nm_platform_sysctl_open_netdir:
 * @self: platform instance
 * @ifindex: the ifindex for which to open /sys/class/net/%s
 * @out_ifname: optional output argument of the found ifname.
 *
 * Wraps nmp_utils_sysctl_open_netdir() by first changing into the right
 * network-namespace.
 *
 * Returns: on success, the open file descriptor to the /sys/class/net/%s
 *   directory.
 */
int
nm_platform_sysctl_open_netdir (NMPlatform *self, int ifindex, char *out_ifname)
{
	const char*ifname_guess;
	_CHECK_SELF_NETNS (self, klass, netns, -1);

	g_return_val_if_fail (ifindex > 0, -1);

	/* we don't have an @ifname_guess argument to make the API nicer.
	 * But still do a cache-lookup first. Chances are good that we have
	 * the right ifname cached and save if_indextoname() */
	ifname_guess = nm_platform_link_get_name (self, ifindex);

	return nmp_utils_sysctl_open_netdir (ifindex, ifname_guess, out_ifname);
}

/**
 * nm_platform_sysctl_set:
 * @self: platform instance
 * @pathid: if @dirfd is present, this must be the full path that is looked up.
 *   It is required for logging.
 * @dirfd: optional file descriptor for parent directory for openat()
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
nm_platform_sysctl_set (NMPlatform *self, const char *pathid, int dirfd, const char *path, const char *value)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (path, FALSE);
	g_return_val_if_fail (value, FALSE);

	return klass->sysctl_set (self, pathid, dirfd, path, value);
}

gboolean
nm_platform_sysctl_set_ip6_hop_limit_safe (NMPlatform *self, const char *iface, int value)
{
	const char *path;
	gint64 cur;
	char buf[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];

	_CHECK_SELF (self, klass, FALSE);

	/* the hop-limit provided via RA is uint8. */
	if (value > 0xFF)
		return FALSE;

	/* don't allow unreasonable small values */
	if (value < 10)
		return FALSE;

	path = nm_utils_sysctl_ip_conf_path (AF_INET6, buf, iface, "hop_limit");
	cur = nm_platform_sysctl_get_int_checked (self, NMP_SYSCTL_PATHID_ABSOLUTE (path), 10, 1, G_MAXINT32, -1);

	/* only allow increasing the hop-limit to avoid DOS by an attacker
	 * setting a low hop-limit (CVE-2015-2924, rh#1209902) */

	if (value < cur)
		return FALSE;
	if (value != cur) {
		char svalue[20];

		sprintf (svalue, "%d", value);
		nm_platform_sysctl_set (self, NMP_SYSCTL_PATHID_ABSOLUTE (path), svalue);
	}

	return TRUE;
}

/**
 * nm_platform_sysctl_get:
 * @self: platform instance
 * @dirfd: if non-negative, used to lookup the path via openat().
 * @pathid: if @dirfd is present, this must be the full path that is looked up.
 *   It is required for logging.
 * @path: Absolute path to sysctl
 *
 * Returns: (transfer full): Contents of the virtual sysctl file.
 */
char *
nm_platform_sysctl_get (NMPlatform *self, const char *pathid, int dirfd, const char *path)
{
	_CHECK_SELF (self, klass, NULL);

	g_return_val_if_fail (path, NULL);

	return klass->sysctl_get (self, pathid, dirfd, path);
}

/**
 * nm_platform_sysctl_get_int32:
 * @self: platform instance
 * @pathid: if @dirfd is present, this must be the full path that is looked up.
 *   It is required for logging.
 * @dirfd: if non-negative, used to lookup the path via openat().
 * @path: Absolute path to sysctl
 * @fallback: default value, if the content of path could not be read
 * as decimal integer.
 *
 * Returns: contents of the sysctl file parsed as s32 integer, or
 * @fallback on error. On error, %errno will be set to a non-zero
 * value, on success %errno will be set to zero.
 */
gint32
nm_platform_sysctl_get_int32 (NMPlatform *self, const char *pathid, int dirfd, const char *path, gint32 fallback)
{
	return nm_platform_sysctl_get_int_checked (self, pathid, dirfd, path, 10, G_MININT32, G_MAXINT32, fallback);
}

/**
 * nm_platform_sysctl_get_int_checked:
 * @self: platform instance
 * @pathid: if @dirfd is present, this must be the full path that is looked up.
 *   It is required for logging.
 * @dirfd: if non-negative, used to lookup the path via openat().
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
nm_platform_sysctl_get_int_checked (NMPlatform *self, const char *pathid, int dirfd, const char *path, guint base, gint64 min, gint64 max, gint64 fallback)
{
	char *value = NULL;
	gint32 ret;
	int errsv;

	_CHECK_SELF (self, klass, fallback);

	g_return_val_if_fail (path, fallback);

	if (path)
		value = nm_platform_sysctl_get (self, pathid, dirfd, path);

	if (!value) {
		errno = EINVAL;
		return fallback;
	}

	ret = _nm_utils_ascii_str_to_int64 (value, base, min, max, fallback);
	errsv = errno;
	g_free (value);
	errno = errsv;
	return ret;
}

/*****************************************************************************/

static int
_link_get_all_presort (gconstpointer  p_a,
                       gconstpointer  p_b,
                       gpointer       sort_by_name)
{
	const NMPlatformLink *a = NMP_OBJECT_CAST_LINK (*((const NMPObject **) p_a));
	const NMPlatformLink *b = NMP_OBJECT_CAST_LINK (*((const NMPObject **) p_b));

	/* Loopback always first */
	if (a->ifindex == 1)
		return -1;
	if (b->ifindex == 1)
		return 1;

	if (GPOINTER_TO_INT (sort_by_name)) {
		/* Initialized links first */
		if (a->initialized > b->initialized)
			return -1;
		if (a->initialized < b->initialized)
			return 1;

		return strcmp (a->name, b->name);
	} else
		return a->ifindex - b->ifindex;
}

/**
 * nm_platform_link_get_all:
 * @self: platform instance
 * @sort_by_name: whether to sort by name or ifindex.
 *
 * Retrieve a snapshot of configuration for all links at once. The result is
 * owned by the caller and should be freed with g_ptr_array_unref().
 */
GPtrArray *
nm_platform_link_get_all (NMPlatform *self, gboolean sort_by_name)
{
	gs_unref_ptrarray GPtrArray *links = NULL;
	GPtrArray *result;
	guint i, nresult;
	gs_unref_hashtable GHashTable *unseen = NULL;
	const NMPlatformLink *item;
	NMPLookup lookup;

	_CHECK_SELF (self, klass, NULL);

	nmp_lookup_init_obj_type (&lookup, NMP_OBJECT_TYPE_LINK);
	links = nm_dedup_multi_objs_to_ptr_array_head (nm_platform_lookup (self, &lookup),
	                                               NULL, NULL);
	if (!links)
		return NULL;

	for (i = 0; i < links->len; ) {
		if (!nmp_object_is_visible (links->pdata[i]))
			g_ptr_array_remove_index_fast (links, i);
		else
			i++;
	}

	if (links->len == 0)
		return NULL;

	/* first sort the links by their ifindex or name. Below we will sort
	 * further by moving children/slaves to the end. */
	g_ptr_array_sort_with_data (links, _link_get_all_presort, GINT_TO_POINTER (sort_by_name));

	unseen = g_hash_table_new (nm_direct_hash, NULL);
	for (i = 0; i < links->len; i++) {
		item = NMP_OBJECT_CAST_LINK (links->pdata[i]);
		nm_assert (item->ifindex > 0);
		if (!g_hash_table_insert (unseen, GINT_TO_POINTER (item->ifindex), NULL))
			nm_assert_not_reached ();
	}

#if NM_MORE_ASSERTS
	/* Ensure that link_get_all returns a consistent and valid result. */
	for (i = 0; i < links->len; i++) {
		item = NMP_OBJECT_CAST_LINK (links->pdata[i]);

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
	nm_assert (g_hash_table_size (unseen) == links->len);
	nresult = links->len;
	result = g_ptr_array_new_full (nresult, (GDestroyNotify) nmp_object_unref);

	while (TRUE) {
		gboolean found_something = FALSE;
		guint first_idx = G_MAXUINT;

		for (i = 0; i < links->len; i++) {
			item = NMP_OBJECT_CAST_LINK (links->pdata[i]);

			if (!item)
				continue;

			g_assert (g_hash_table_contains (unseen, GINT_TO_POINTER (item->ifindex)));

			if (item->master > 0 && g_hash_table_contains (unseen, GINT_TO_POINTER (item->master)))
				goto skip;
			if (item->parent > 0 && g_hash_table_contains (unseen, GINT_TO_POINTER (item->parent)))
				goto skip;

			g_hash_table_remove (unseen, GINT_TO_POINTER (item->ifindex));
			g_ptr_array_add (result, links->pdata[i]);
			links->pdata[i] = NULL;
			found_something = TRUE;
			continue;
skip:
			if (first_idx == G_MAXUINT)
				first_idx = i;
		}

		if (found_something) {
			if (first_idx == G_MAXUINT)
				break;
		} else {
			nm_assert (first_idx != G_MAXUINT);
			/* There is a loop, pop the first (remaining) element from the list.
			 * This can happen for veth pairs where each peer is parent of the other end. */
			item = NMP_OBJECT_CAST_LINK (links->pdata[first_idx]);
			nm_assert (item);
			g_hash_table_remove (unseen, GINT_TO_POINTER (item->ifindex));
			g_ptr_array_add (result, links->pdata[first_idx]);
			links->pdata[first_idx] = NULL;
		}
		nm_assert (result->len < nresult);
	}
	nm_assert (result->len == nresult);

	return result;
}

/*****************************************************************************/

const NMPObject *
nm_platform_link_get_obj (NMPlatform *self,
                          int ifindex,
                          gboolean visible_only)
{
	const NMPObject *obj_cache;

	obj_cache = nmp_cache_lookup_link (nm_platform_get_cache (self), ifindex);
	if (   !obj_cache
	    || (   visible_only
	        && !nmp_object_is_visible (obj_cache)))
		return NULL;
	return obj_cache;
}

/*****************************************************************************/

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
 * invalidate/modify the returned instance.
 **/
const NMPlatformLink *
nm_platform_link_get (NMPlatform *self, int ifindex)
{
	const NMPObject *obj;

	_CHECK_SELF (self, klass, NULL);

	if (ifindex <= 0)
		return NULL;

	obj = nm_platform_link_get_obj (self, ifindex, TRUE);
	return NMP_OBJECT_CAST_LINK (obj);
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
	const NMPObject *obj;

	_CHECK_SELF (self, klass, NULL);

	if (!ifname || !*ifname)
		return NULL;

	obj = nmp_cache_lookup_link_full (nm_platform_get_cache (self),
	                                  0, ifname, TRUE, NM_LINK_TYPE_NONE, NULL, NULL);
	return NMP_OBJECT_CAST_LINK (obj);
}

struct _nm_platform_link_get_by_address_data {
	gconstpointer address;
	guint8 length;
};

static gboolean
_nm_platform_link_get_by_address_match_link (const NMPObject *obj, struct _nm_platform_link_get_by_address_data *d)
{
	return obj->link.addr.len == d->length && !memcmp (obj->link.addr.data, d->address, d->length);
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
	const NMPObject *obj;
	struct _nm_platform_link_get_by_address_data d = {
		.address = address,
		.length = length,
	};

	_CHECK_SELF (self, klass, NULL);

	if (length == 0)
		return NULL;

	if (length > NM_UTILS_HWADDR_LEN_MAX)
		g_return_val_if_reached (NULL);
	if (!address)
		g_return_val_if_reached (NULL);

	obj = nmp_cache_lookup_link_full (nm_platform_get_cache (self),
	                                  0, NULL, TRUE, NM_LINK_TYPE_NONE,
	                                  (NMPObjectMatchFn) _nm_platform_link_get_by_address_match_link, &d);
	return NMP_OBJECT_CAST_LINK (obj);
}

static NMPlatformError
_link_add_check_existing (NMPlatform *self, const char *name, NMLinkType type, const NMPlatformLink **out_link)
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
			*out_link = pllink;
		if (wrong_type)
			return NM_PLATFORM_ERROR_WRONG_TYPE;
		return NM_PLATFORM_ERROR_EXISTS;
	}
	if (out_link)
		*out_link = NULL;
	return NM_PLATFORM_ERROR_SUCCESS;
}

/**
 * nm_platform_link_add:
 * @self: platform instance
 * @name: Interface name
 * @type: Interface type
 * @veth_peer: For veths, the peer name
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
                      const char *veth_peer,
                      const void *address,
                      size_t address_len,
                      const NMPlatformLink **out_link)
{
	NMPlatformError plerr;
	char addr_buf[NM_UTILS_HWADDR_LEN_MAX * 3];

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (name, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail ((address != NULL) ^ (address_len == 0) , NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (address_len <= NM_UTILS_HWADDR_LEN_MAX, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail ((!!veth_peer) == (type == NM_LINK_TYPE_VETH), NM_PLATFORM_ERROR_BUG);

	plerr = _link_add_check_existing (self, name, type, out_link);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS)
		return plerr;

	_LOGD ("link: adding link '%s' of type '%s' (%d)"
	       "%s%s" /* address */
	       "%s%s" /* veth peer */
	       "",
	       name,
	       nm_link_type_to_string (type),
	       (int) type,
	       address ? ", address: " : "",
	       address ? nm_utils_hwaddr_ntoa_buf (address, address_len, FALSE, addr_buf, sizeof (addr_buf)) : "",
	       veth_peer ? ", veth-peer: " : "",
	       veth_peer ?: "");

	if (!klass->link_add (self, name, type, veth_peer, address, address_len, out_link))
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return NM_PLATFORM_ERROR_SUCCESS;
}

NMPlatformError
nm_platform_link_veth_add (NMPlatform *self,
                            const char *name,
                            const char *peer,
                            const NMPlatformLink **out_link)
{
	return nm_platform_link_add (self, name, NM_LINK_TYPE_VETH, peer, NULL, 0, out_link);
}

/**
 * nm_platform_link_dummy_add:
 * @self: platform instance
 * @name: New interface name
 * @out_link: on success, the link object
 *
 * Create a software ethernet-like interface
 */
NMPlatformError
nm_platform_link_dummy_add (NMPlatform *self,
                            const char *name,
                            const NMPlatformLink **out_link)
{
	return nm_platform_link_add (self, name, NM_LINK_TYPE_DUMMY, NULL, NULL, 0, out_link);
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
 * nm_platform_link_set_netns:
 * @self: platform instance
 * @ifindex: Interface index
 * @netns_fd: the file descriptor for the new netns.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_link_set_netns (NMPlatform *self, int ifindex, int netns_fd)
{
	const NMPlatformLink *pllink;

	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (netns_fd > 0, FALSE);

	pllink = nm_platform_link_get (self, ifindex);
	if (!pllink)
		return FALSE;

	_LOGD ("link: ifindex %d changing network namespace to %d", ifindex, netns_fd);
	return klass->link_set_netns (self, ifindex, netns_fd);
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

const char *
nm_platform_if_indextoname (NMPlatform *self, int ifindex, char *out_ifname/* of size IFNAMSIZ */)
{
	_CHECK_SELF_NETNS (self, klass, netns, FALSE);

	return nmp_utils_if_indextoname (ifindex, out_ifname);
}

int
nm_platform_if_nametoindex (NMPlatform *self, const char *ifname)
{
	_CHECK_SELF_NETNS (self, klass, netns, FALSE);

	return nmp_utils_if_nametoindex (ifname);
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
	const NMPObject *obj;

	_CHECK_SELF (self, klass, NULL);

	obj = nm_platform_link_get_obj (self, ifindex, TRUE);

	if (!obj)
		return NULL;

	if (obj->link.type != NM_LINK_TYPE_UNKNOWN) {
		/* We could detect the @link_type. In this case the function returns
		 * our internel module names, which differs from rtnl_link_get_type():
		 *   - NM_LINK_TYPE_INFINIBAND (gives "infiniband", instead of "ipoib")
		 *   - NM_LINK_TYPE_TAP (gives "tap", instead of "tun").
		 * Note that this functions is only used by NMDeviceGeneric to
		 * set type_description. */
		return nm_link_type_to_string (obj->link.type);
	}
	/* Link type not detected. Fallback to rtnl_link_get_type()/IFLA_INFO_KIND. */
	return obj->link.kind ?: "unknown";
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
	const NMPObject *link;
	struct udev_device *udevice = NULL;
	const char *uproperty;

	_CHECK_SELF (self, klass, FALSE);

	link = nmp_cache_lookup_link (nm_platform_get_cache (self), ifindex);
	if (!link)
		return FALSE;

	udevice = link->_link.udev.device;
	if (!udevice)
		return FALSE;

	uproperty = udev_device_get_property_value (udevice, "NM_UNMANAGED");
	if (!uproperty)
		return FALSE;

	*unmanaged = nm_udev_utils_property_as_boolean (uproperty);
	return TRUE;
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
 * nm_platform_refresh_all:
 * @self: platform instance
 * @obj_type: The object type to request.
 *
 * Resync and re-request all objects from kernel of a certain @obj_type.
 */
void
nm_platform_refresh_all (NMPlatform *self, NMPObjectType obj_type)
{
	_CHECK_SELF_VOID (self, klass);

	klass->refresh_all (self, obj_type);
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

static guint
_link_get_flags (NMPlatform *self, int ifindex)
{
	const NMPlatformLink *pllink;

	pllink = nm_platform_link_get (self, ifindex);
	return pllink ? pllink->n_ifi_flags : IFF_NOARP;
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
 * nm_platform_link_set_ipv6_token:
 * @self: platform instance
 * @ifindex: Interface index
 * @iid: Tokenized interface identifier
 *
 * Sets then IPv6 tokenized interface identifier.
 *
 * Returns: %TRUE a tokenized identifier was available
 */
gboolean
nm_platform_link_set_ipv6_token (NMPlatform *self, int ifindex, NMUtilsIPv6IfaceId iid)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (iid.id, FALSE);

	if (klass->link_set_token)
		return klass->link_set_token (self, ifindex, iid);
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

struct udev_device *
nm_platform_link_get_udev_device (NMPlatform *self, int ifindex)
{
	const NMPObject *obj_cache;

	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex >= 0, NULL);

	obj_cache = nm_platform_link_get_obj (self, ifindex, FALSE);
	return obj_cache ? obj_cache->_link.udev.device : NULL;
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
 * Returns: %NM_PLATFORM_ERROR_SUCCESS if the operation was successful or an error code otherwise.
 */
NMPlatformError
nm_platform_link_set_user_ipv6ll_enabled (NMPlatform *self, int ifindex, gboolean enabled)
{
	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (ifindex > 0, NM_PLATFORM_ERROR_BUG);

	return klass->link_set_user_ipv6ll_enabled (self, ifindex, enabled);
}

/**
 * nm_platform_link_set_address:
 * @self: platform instance
 * @ifindex: Interface index
 * @address: The new MAC address
 *
 * Set interface MAC address.
 */
NMPlatformError
nm_platform_link_set_address (NMPlatform *self, int ifindex, gconstpointer address, size_t length)
{
	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (ifindex > 0, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (address, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (length > 0, NM_PLATFORM_ERROR_BUG);

	_LOGD ("link: setting %s (%d) hardware address",
	       nm_strquote_a (20, nm_platform_link_get_name (self, ifindex)),
	       ifindex);
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

	_CHECK_SELF (self, klass, NULL);

	g_return_val_if_fail (ifindex > 0, NULL);

	pllink = nm_platform_link_get (self, ifindex);

	if (   !pllink
	    || pllink->addr.len <= 0) {
		NM_SET_OUT (length, 0);
		return NULL;
	}

	if (pllink->addr.len > NM_UTILS_HWADDR_LEN_MAX) {
		NM_SET_OUT (length, 0);
		g_return_val_if_reached (NULL);
	}

	NM_SET_OUT (length, pllink->addr.len);
	return pllink->addr.data;
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

	return klass->link_supports_carrier_detect (self, ifindex);
}

gboolean
nm_platform_link_supports_vlans (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex >= 0, FALSE);

	return klass->link_supports_vlans (self, ifindex);
}

gboolean
nm_platform_link_supports_sriov (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex >= 0, FALSE);

	return klass->link_supports_sriov (self, ifindex);
}

gboolean
nm_platform_link_set_sriov_num_vfs (NMPlatform *self, int ifindex, guint num_vfs)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);

	_LOGD ("link: setting %u VFs for %s (%d)",
	       num_vfs,
	       nm_strquote_a (25, nm_platform_link_get_name (self, ifindex)),
	       ifindex);
	return klass->link_set_sriov_num_vfs (self, ifindex, num_vfs);
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

	_LOGD ("link: setting up %s (%d)", nm_strquote_a (25, nm_platform_link_get_name (self, ifindex)), ifindex);
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

	_LOGD ("link: setting down %s (%d)", nm_strquote_a (25, nm_platform_link_get_name (self, ifindex)), ifindex);
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

	_LOGD ("link: setting arp %s (%d)", nm_strquote_a (25, nm_platform_link_get_name (self, ifindex)), ifindex);
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
NMPlatformError
nm_platform_link_set_mtu (NMPlatform *self, int ifindex, guint32 mtu)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (mtu > 0, FALSE);

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
 * nm_platform_link_set_name:
 * @self: platform instance
 * @ifindex: Interface index
 * @name: The new interface name
 *
 * Set interface name.
 */
gboolean
nm_platform_link_set_name (NMPlatform *self, int ifindex, const char *name)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex >= 0, FALSE);
	g_return_val_if_fail (name, FALSE);

	_LOGD ("link: setting '%s' (%d) name %s", nm_platform_link_get_name (self, ifindex), ifindex, name);

	if (strlen (name) + 1 > IFNAMSIZ)
		return FALSE;

	return klass->link_set_name (self, ifindex, name);
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
 * Returns: Interface index of the slave's master.
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

gboolean
nm_platform_link_can_assume (NMPlatform *self, int ifindex)
{
	_CHECK_SELF (self, klass, FALSE);

	if (klass->link_can_assume)
		return klass->link_can_assume (self, ifindex);
	g_return_val_if_reached (FALSE);
}

/*****************************************************************************/

/**
 * nm_platform_link_get_lnk:
 * @self: the platform instance
 * @ifindex: the link ifindex to lookup
 * @link_type: filter by link-type.
 * @out_link: (allow-none): returns the platform link instance
 *
 * If the function returns %NULL, that could mean that no such ifindex
 * exists, of that the link has no lnk data. You can find that out
 * by checking @out_link. @out_link will always be set if a link
 * with @ifindex exists.
 *
 * If @link_type is %NM_LINK_TYPE_NONE, the function returns the lnk
 * object if it is present. If you set link-type, you can be sure
 * that only a link type of the matching type is returned (or %NULL).
 *
 * Returns: the internal link lnk object. The returned object
 * is owned by the platform cache and must not be modified. Note
 * however, that the object is guaranteed to be immutable, so
 * you can savely take a reference and keep it for yourself
 * (but don't modify it).
 */
const NMPObject *
nm_platform_link_get_lnk (NMPlatform *self, int ifindex, NMLinkType link_type, const NMPlatformLink **out_link)
{
	const NMPObject *obj;

	_CHECK_SELF (self, klass, FALSE);

	NM_SET_OUT (out_link, NULL);

	g_return_val_if_fail (ifindex > 0, NULL);

	obj = nm_platform_link_get_obj (self, ifindex, TRUE);
	if (!obj)
		return NULL;

	NM_SET_OUT (out_link, &obj->link);

	if (!obj->_link.netlink.lnk)
		return NULL;
	if (   link_type != NM_LINK_TYPE_NONE
	    && (   link_type != obj->link.type
	        || link_type != NMP_OBJECT_GET_CLASS (obj->_link.netlink.lnk)->lnk_link_type))
		return NULL;

	return obj->_link.netlink.lnk;
}

static gconstpointer
_link_get_lnk (NMPlatform *self, int ifindex, NMLinkType link_type, const NMPlatformLink **out_link)
{
	const NMPObject *lnk;

	lnk = nm_platform_link_get_lnk (self, ifindex, link_type, out_link);
	return lnk ? &lnk->object : NULL;
}

const NMPlatformLnkGre *
nm_platform_link_get_lnk_gre (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return _link_get_lnk (self, ifindex, NM_LINK_TYPE_GRE, out_link);
}

const NMPlatformLnkInfiniband *
nm_platform_link_get_lnk_infiniband (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return _link_get_lnk (self, ifindex, NM_LINK_TYPE_INFINIBAND, out_link);
}

const NMPlatformLnkIp6Tnl *
nm_platform_link_get_lnk_ip6tnl (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return _link_get_lnk (self, ifindex, NM_LINK_TYPE_IP6TNL, out_link);
}

const NMPlatformLnkIpIp *
nm_platform_link_get_lnk_ipip (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return _link_get_lnk (self, ifindex, NM_LINK_TYPE_IPIP, out_link);
}

const NMPlatformLnkMacsec *
nm_platform_link_get_lnk_macsec (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return _link_get_lnk (self, ifindex, NM_LINK_TYPE_MACSEC, out_link);
}

const NMPlatformLnkMacvlan *
nm_platform_link_get_lnk_macvlan (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return _link_get_lnk (self, ifindex, NM_LINK_TYPE_MACVLAN, out_link);
}

const NMPlatformLnkMacvtap *
nm_platform_link_get_lnk_macvtap (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return _link_get_lnk (self, ifindex, NM_LINK_TYPE_MACVTAP, out_link);
}

const NMPlatformLnkSit *
nm_platform_link_get_lnk_sit (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return _link_get_lnk (self, ifindex, NM_LINK_TYPE_SIT, out_link);
}

const NMPlatformLnkTun *
nm_platform_link_get_lnk_tun (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return _link_get_lnk (self, ifindex, NM_LINK_TYPE_TUN, out_link);
}

const NMPlatformLnkVlan *
nm_platform_link_get_lnk_vlan (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return _link_get_lnk (self, ifindex, NM_LINK_TYPE_VLAN, out_link);
}

const NMPlatformLnkVxlan *
nm_platform_link_get_lnk_vxlan (NMPlatform *self, int ifindex, const NMPlatformLink **out_link)
{
	return _link_get_lnk (self, ifindex, NM_LINK_TYPE_VXLAN, out_link);
}

/*****************************************************************************/

/**
 * nm_platform_link_bridge_add:
 * @self: platform instance
 * @name: New interface name
 * @address: (allow-none): set the mac address of the new bridge
 * @address_len: the length of the @address
 * @out_link: on success, the link object
 *
 * Create a software bridge.
 */
NMPlatformError
nm_platform_link_bridge_add (NMPlatform *self,
                             const char *name,
                             const void *address,
                             size_t address_len,
                             const NMPlatformLink **out_link)
{
	return nm_platform_link_add (self, name, NM_LINK_TYPE_BRIDGE, NULL, address, address_len, out_link);
}

/**
 * nm_platform_link_bond_add:
 * @self: platform instance
 * @name: New interface name
 * @out_link: on success, the link object
 *
 * Create a software bonding device.
 */
NMPlatformError
nm_platform_link_bond_add (NMPlatform *self,
                           const char *name,
                           const NMPlatformLink **out_link)
{
	return nm_platform_link_add (self, name, NM_LINK_TYPE_BOND, NULL, NULL, 0, out_link);
}

/**
 * nm_platform_link_team_add:
 * @self: platform instance
 * @name: New interface name
 * @out_link: on success, the link object
 *
 * Create a software teaming device.
 */
NMPlatformError
nm_platform_link_team_add (NMPlatform *self,
                           const char *name,
                           const NMPlatformLink **out_link)
{
	return nm_platform_link_add (self, name, NM_LINK_TYPE_TEAM, NULL, NULL, 0, out_link);
}

/**
 * nm_platform_link_vlan_add:
 * @self: platform instance
 * @name: New interface name
 * @vlanid: VLAN identifier
 * @vlanflags: VLAN flags from libnm
 * @out_link: on success, the link object
 *
 * Create a software VLAN device.
 */
NMPlatformError
nm_platform_link_vlan_add (NMPlatform *self,
                           const char *name,
                           int parent,
                           int vlanid,
                           guint32 vlanflags,
                           const NMPlatformLink **out_link)
{
	NMPlatformError plerr;

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (parent >= 0, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (vlanid >= 0, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (name, NM_PLATFORM_ERROR_BUG);

	plerr = _link_add_check_existing (self, name, NM_LINK_TYPE_VLAN, out_link);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS)
		return plerr;

	_LOGD ("link: adding vlan '%s' parent %d vlanid %d vlanflags %x",
	       name, parent, vlanid, vlanflags);
	if (!klass->vlan_add (self, name, parent, vlanid, vlanflags, out_link))
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return NM_PLATFORM_ERROR_SUCCESS;
}

/**
 * nm_platform_link_vxlan_add:
 * @self: platform instance
 * @name: New interface name
 * @props: properties of the new link
 * @out_link: on success, the link object
 *
 * Create a VXLAN device.
 */
NMPlatformError
nm_platform_link_vxlan_add (NMPlatform *self,
                            const char *name,
                            const NMPlatformLnkVxlan *props,
                            const NMPlatformLink **out_link)
{
	NMPlatformError plerr;

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (props, NM_PLATFORM_ERROR_BUG);

	plerr = _link_add_check_existing (self, name, NM_LINK_TYPE_VXLAN, out_link);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS)
		return plerr;

	_LOGD ("link: adding vxlan '%s' parent %d id %d",
	       name, props->parent_ifindex, props->id);
	if (!klass->link_vxlan_add (self, name, props, out_link))
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return NM_PLATFORM_ERROR_SUCCESS;
}

/**
 * nm_platform_link_tun_add:
 * @self: platform instance
 * @name: new interface name
 * @tap: whether the interface is a TAP
 * @owner: interface owner or -1
 * @group: interface group or -1
 * @pi: whether to clear the IFF_NO_PI flag
 * @vnet_hdr: whether to set the IFF_VNET_HDR flag
 * @multi_queue: whether to set the IFF_MULTI_QUEUE flag
 * @out_link: on success, the link object
 * @out_fd: (allow-none): if give, return the file descriptor for the
 *   created device. Note that when creating a non-persistent device,
 *   this argument is mandatory, otherwise it makes no sense
 *   to create such an interface.
 *   The caller is responsible for closing this file descriptor.
 *
 * Create a TUN or TAP interface.
 */
NMPlatformError
nm_platform_link_tun_add (NMPlatform *self,
                          const char *name,
                          const NMPlatformLnkTun *props,
                          const NMPlatformLink **out_link,
                          int *out_fd)
{
	char b[255];
	NMPlatformError plerr;

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (name, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (props, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (NM_IN_SET (props->type, IFF_TUN, IFF_TAP), NM_PLATFORM_ERROR_BUG);

	/* creating a non-persistant device requires that the caller handles
	 * the file descriptor. */
	g_return_val_if_fail (props->persist || out_fd, NM_PLATFORM_ERROR_BUG);

	NM_SET_OUT (out_fd, -1);

	plerr = _link_add_check_existing (self, name, NM_LINK_TYPE_TUN, out_link);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS)
		return plerr;

	_LOGD ("link: adding tun '%s' %s",
	       name, nm_platform_lnk_tun_to_string (props, b, sizeof (b)));
	if (!klass->link_tun_add (self, name, props, out_link, out_fd))
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return NM_PLATFORM_ERROR_SUCCESS;
}

/*****************************************************************************/

static gboolean
link_set_option (NMPlatform *self, int ifindex, const char *category, const char *option, const char *value)
{
	nm_auto_close int dirfd = -1;
	char ifname_verified[IFNAMSIZ];
	const char *path;

	if (!category || !option)
		return FALSE;

	dirfd = nm_platform_sysctl_open_netdir (self, ifindex, ifname_verified);
	if (dirfd < 0)
		return FALSE;

	path = nm_sprintf_bufa (strlen (category) + strlen (option) + 2,
	                        "%s/%s",
	                        category, option);
	return nm_platform_sysctl_set (self, NMP_SYSCTL_PATHID_NETDIR_unsafe (dirfd, ifname_verified, path), value);
}

static char *
link_get_option (NMPlatform *self, int ifindex, const char *category, const char *option)
{
	nm_auto_close int dirfd = -1;
	char ifname_verified[IFNAMSIZ];
	const char *path;

	if (!category || !option)
		return NULL;

	dirfd = nm_platform_sysctl_open_netdir (self, ifindex, ifname_verified);
	if (dirfd < 0)
		return NULL;

	path = nm_sprintf_bufa (strlen (category) + strlen (option) + 2,
	                        "%s/%s",
	                        category, option);
	return nm_platform_sysctl_get (self, NMP_SYSCTL_PATHID_NETDIR_unsafe (dirfd, ifname_verified, path));
}

static const char *
master_category (NMPlatform *self, int master)
{
	switch (nm_platform_link_get_type (self, master)) {
	case NM_LINK_TYPE_BRIDGE:
		return "bridge";
	case NM_LINK_TYPE_BOND:
		return "bonding";
	default:
		return NULL;
	}
}

static const char *
slave_category (NMPlatform *self, int slave)
{
	int master = nm_platform_link_get_master (self, slave);

	if (master <= 0)
		return NULL;

	switch (nm_platform_link_get_type (self, master)) {
	case NM_LINK_TYPE_BRIDGE:
		return "brport";
	default:
		return NULL;
	}
}

gboolean
nm_platform_sysctl_master_set_option (NMPlatform *self, int ifindex, const char *option, const char *value)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);
	g_return_val_if_fail (value, FALSE);

	return link_set_option (self, ifindex, master_category (self, ifindex), option, value);
}

char *
nm_platform_sysctl_master_get_option (NMPlatform *self, int ifindex, const char *option)
{
	_CHECK_SELF (self, klass, NULL);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);

	return link_get_option (self, ifindex, master_category (self, ifindex), option);
}

gboolean
nm_platform_sysctl_slave_set_option (NMPlatform *self, int ifindex, const char *option, const char *value)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);
	g_return_val_if_fail (value, FALSE);

	return link_set_option (self, ifindex, slave_category (self, ifindex), option, value);
}

char *
nm_platform_sysctl_slave_get_option (NMPlatform *self, int ifindex, const char *option)
{
	_CHECK_SELF (self, klass, NULL);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (option, FALSE);

	return link_get_option (self, ifindex, slave_category (self, ifindex), option);
}

/*****************************************************************************/

gboolean
nm_platform_link_vlan_change (NMPlatform *self,
                              int ifindex,
                              NMVlanFlags flags_mask,
                              NMVlanFlags flags_set,
                              gboolean ingress_reset_all,
                              const NMVlanQosMapping *ingress_map,
                              gsize n_ingress_map,
                              gboolean egress_reset_all,
                              const NMVlanQosMapping *egress_map,
                              gsize n_egress_map)
{
	_CHECK_SELF (self, klass, FALSE);

	nm_assert (klass->link_vlan_change);

	g_return_val_if_fail (!n_ingress_map || ingress_map, FALSE);
	g_return_val_if_fail (!n_egress_map || egress_map, FALSE);

	flags_set &= flags_mask;

	if (_LOGD_ENABLED ()) {
		char buf[512];
		char *b = buf;
		gsize len, i;

		b[0] = '\0';
		len = sizeof (buf);

		if (flags_mask)
			nm_utils_strbuf_append (&b, &len, " flags 0x%x/0x%x", (unsigned) flags_set, (unsigned) flags_mask);

		if (ingress_reset_all || n_ingress_map) {
			nm_utils_strbuf_append_str (&b, &len, " ingress-qos-map");
			nm_platform_vlan_qos_mapping_to_string ("", ingress_map, n_ingress_map, b, len);
			i = strlen (b);
			b += i;
			len -= i;
			if (ingress_reset_all)
				nm_utils_strbuf_append_str (&b, &len, " (reset-all)");
		}

		if (egress_reset_all || n_egress_map) {
			nm_utils_strbuf_append_str (&b, &len, " egress-qos-map");
			nm_platform_vlan_qos_mapping_to_string ("", egress_map, n_egress_map, b, len);
			i = strlen (b);
			b += i;
			len -= i;
			if (egress_reset_all)
				nm_utils_strbuf_append_str (&b, &len, " (reset-all)");
		}

		_LOGD ("link: change vlan %d:%s", ifindex, buf);
	}
	return klass->link_vlan_change (self,
	                                ifindex,
	                                flags_mask,
	                                flags_set,
	                                ingress_reset_all,
	                                ingress_map,
	                                n_ingress_map,
	                                egress_reset_all,
	                                egress_map,
	                                n_egress_map);
}

gboolean
nm_platform_link_vlan_set_ingress_map (NMPlatform *self, int ifindex, int from, int to)
{
	NMVlanQosMapping map = {
		.from = from,
		.to = to,
	};

	return nm_platform_link_vlan_change (self, ifindex, 0, 0, FALSE, &map, 1, FALSE, NULL, 0);
}

gboolean
nm_platform_link_vlan_set_egress_map (NMPlatform *self, int ifindex, int from, int to)
{
	NMVlanQosMapping map = {
		.from = from,
		.to = to,
	};

	return nm_platform_link_vlan_change (self, ifindex, 0, 0, FALSE, NULL, 0, FALSE, &map, 1);
}

/**
 * nm_platform_link_gre_add:
 * @self: platform instance
 * @name: name of the new interface
 * @props: interface properties
 * @out_link: on success, the link object
 *
 * Create a software GRE device.
 */
NMPlatformError
nm_platform_link_gre_add (NMPlatform *self,
                          const char *name,
                          const NMPlatformLnkGre *props,
                          const NMPlatformLink **out_link)
{
	NMPlatformError plerr;
	char buffer[INET_ADDRSTRLEN];

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (props, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (name, NM_PLATFORM_ERROR_BUG);

	plerr = _link_add_check_existing (self, name, NM_LINK_TYPE_GRE, out_link);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS)
		return plerr;

	_LOGD (LOG_FMT_IP_TUNNEL,
	       "gre",
	       name,
	       props->parent_ifindex,
	       nm_utils_inet4_ntop (props->local, NULL),
	       nm_utils_inet4_ntop (props->remote, buffer));

	if (!klass->link_gre_add (self, name, props, out_link))
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return NM_PLATFORM_ERROR_SUCCESS;
}

static NMPlatformError
_infiniband_add_add_or_delete (NMPlatform *self,
                               int parent,
                               int p_key,
                               gboolean add,
                               const NMPlatformLink **out_link)
{
	char name[IFNAMSIZ];
	const NMPlatformLink *parent_link;
	NMPlatformError plerr;

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (parent >= 0, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (p_key >= 0 && p_key <= 0xffff, NM_PLATFORM_ERROR_BUG);

	/* the special keys 0x0000 and 0x8000 are not allowed. */
	if (NM_IN_SET (p_key, 0, 0x8000))
		return NM_PLATFORM_ERROR_UNSPECIFIED;

	parent_link = nm_platform_link_get (self, parent);
	if (!parent_link)
		return NM_PLATFORM_ERROR_NOT_FOUND;

	if (parent_link->type != NM_LINK_TYPE_INFINIBAND)
		return NM_PLATFORM_ERROR_WRONG_TYPE;

	nm_utils_new_infiniband_name (name, parent_link->name, p_key);

	if (add) {
		plerr = _link_add_check_existing (self, name, NM_LINK_TYPE_INFINIBAND, out_link);
		if (plerr != NM_PLATFORM_ERROR_SUCCESS)
			return plerr;

		_LOGD ("link: adding infiniband partition %s for parent '%s' (%d), key %d",
		       name, parent_link->name, parent, p_key);
		if (!klass->infiniband_partition_add (self, parent, p_key, out_link))
			return NM_PLATFORM_ERROR_UNSPECIFIED;
	} else {
		if (!klass->infiniband_partition_delete (self, parent, p_key))
			return NM_PLATFORM_ERROR_UNSPECIFIED;
	}

	return NM_PLATFORM_ERROR_SUCCESS;
}

NMPlatformError
nm_platform_link_infiniband_add (NMPlatform *self,
                                 int parent,
                                 int p_key,
                                 const NMPlatformLink **out_link)
{
	return _infiniband_add_add_or_delete (self, parent, p_key, TRUE, out_link);
}

NMPlatformError
nm_platform_link_infiniband_delete (NMPlatform *self,
                                   int parent,
                                   int p_key)
{
	return _infiniband_add_add_or_delete (self, parent, p_key, FALSE, NULL);
}

gboolean
nm_platform_link_infiniband_get_properties (NMPlatform *self,
                                            int ifindex,
                                            int *out_parent,
                                            int *out_p_key,
                                            const char **out_mode)
{
	nm_auto_close int dirfd = -1;
	char ifname_verified[IFNAMSIZ];
	const NMPlatformLnkInfiniband *plnk;
	const NMPlatformLink *plink;
	char *contents;
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

	dirfd = nm_platform_sysctl_open_netdir (self, ifindex, ifname_verified);
	if (dirfd < 0)
		return FALSE;

	contents = nm_platform_sysctl_get (self, NMP_SYSCTL_PATHID_NETDIR (dirfd, ifname_verified, "mode"));
	if (!contents)
		return FALSE;
	if (strstr (contents, "datagram"))
		mode = "datagram";
	else if (strstr (contents, "connected"))
		mode = "connected";
	else
		mode = NULL;
	g_free (contents);

	p_key = nm_platform_sysctl_get_int_checked (self, NMP_SYSCTL_PATHID_NETDIR (dirfd, ifname_verified, "pkey"), 16, 0, 0xFFFF, -1);
	if (p_key < 0)
		return FALSE;

	NM_SET_OUT (out_parent, plink->parent);
	NM_SET_OUT (out_p_key, p_key);
	NM_SET_OUT (out_mode, mode);
	return TRUE;
}

/**
 * nm_platform_ip6tnl_add:
 * @self: platform instance
 * @name: name of the new interface
 * @props: interface properties
 * @out_link: on success, the link object
 *
 * Create an IPv6 tunnel.
 */
NMPlatformError
nm_platform_link_ip6tnl_add (NMPlatform *self,
                             const char *name,
                             const NMPlatformLnkIp6Tnl *props,
                             const NMPlatformLink **out_link)
{
	NMPlatformError plerr;
	char buffer[INET6_ADDRSTRLEN];

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (props, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (name, NM_PLATFORM_ERROR_BUG);

	plerr = _link_add_check_existing (self, name, NM_LINK_TYPE_IP6TNL, out_link);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS)
		return plerr;

	_LOGD (LOG_FMT_IP_TUNNEL,
	       "ip6tnl",
	       name,
	       props->parent_ifindex,
	       nm_utils_inet6_ntop (&props->local, NULL),
	       nm_utils_inet6_ntop (&props->remote, buffer));

	if (!klass->link_ip6tnl_add (self, name, props, out_link))
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return NM_PLATFORM_ERROR_SUCCESS;
}

/**
 * nm_platform_ipip_add:
 * @self: platform instance
 * @name: name of the new interface
 * @props: interface properties
 * @out_link: on success, the link object
 *
 * Create an IPIP tunnel.
 */
NMPlatformError
nm_platform_link_ipip_add (NMPlatform *self,
                           const char *name,
                           const NMPlatformLnkIpIp *props,
                           const NMPlatformLink **out_link)
{
	NMPlatformError plerr;
	char buffer[INET_ADDRSTRLEN];

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (props, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (name, NM_PLATFORM_ERROR_BUG);

	plerr = _link_add_check_existing (self, name, NM_LINK_TYPE_IPIP, out_link);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS)
		return plerr;

	_LOGD (LOG_FMT_IP_TUNNEL,
	       "ipip",
	       name,
		   props->parent_ifindex,
	       nm_utils_inet4_ntop (props->local, NULL),
	       nm_utils_inet4_ntop (props->remote, buffer));

	if (!klass->link_ipip_add (self, name, props, out_link))
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return NM_PLATFORM_ERROR_SUCCESS;
}

/**
 * nm_platform_macsec_add:
 * @self: platform instance
 * @name: name of the new interface
 * @props: interface properties
 * @out_link: on success, the link object
 *
 * Create a MACsec interface.
 */
NMPlatformError
nm_platform_link_macsec_add (NMPlatform *self,
                             const char *name,
                             int parent,
                             const NMPlatformLnkMacsec *props,
                             const NMPlatformLink **out_link)
{
	NMPlatformError plerr;

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (props, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (name, NM_PLATFORM_ERROR_BUG);

	plerr = _link_add_check_existing (self, name, NM_LINK_TYPE_MACSEC, out_link);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS)
		return plerr;

	_LOGD ("adding macsec '%s' parent %u sci %llx",
	       name,
	       parent,
	       (unsigned long long) props->sci);

	if (!klass->link_macsec_add (self, name, parent, props, out_link))
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return NM_PLATFORM_ERROR_SUCCESS;
}

/**
 * nm_platform_macvlan_add:
 * @self: platform instance
 * @name: name of the new interface
 * @props: interface properties
 * @out_link: on success, the link object
 *
 * Create a MACVLAN or MACVTAP device.
 */
NMPlatformError
nm_platform_link_macvlan_add (NMPlatform *self,
                              const char *name,
                              int parent,
                              const NMPlatformLnkMacvlan *props,
                              const NMPlatformLink **out_link)
{
	NMPlatformError plerr;
	NMLinkType type;

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (props, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (name, NM_PLATFORM_ERROR_BUG);

	type = props->tap ? NM_LINK_TYPE_MACVTAP : NM_LINK_TYPE_MACVLAN;

	plerr = _link_add_check_existing (self, name, type, out_link);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS)
		return plerr;

	_LOGD ("adding %s '%s' parent %u mode %u",
	       props->tap ? "macvtap" : "macvlan",
	       name,
	       parent,
	       props->mode);

	if (!klass->link_macvlan_add (self, name, parent, props, out_link))
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return NM_PLATFORM_ERROR_SUCCESS;
}

/**
 * nm_platform_sit_add:
 * @self: platform instance
 * @name: name of the new interface
 * @props: interface properties
 * @out_link: on success, the link object
 *
 * Create a software SIT device.
 */
NMPlatformError
nm_platform_link_sit_add (NMPlatform *self,
                          const char *name,
                          const NMPlatformLnkSit *props,
                          const NMPlatformLink **out_link)
{
	NMPlatformError plerr;
	char buffer[INET_ADDRSTRLEN];

	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	g_return_val_if_fail (props, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (name, NM_PLATFORM_ERROR_BUG);

	plerr = _link_add_check_existing (self, name, NM_LINK_TYPE_SIT, out_link);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS)
		return plerr;

	_LOGD (LOG_FMT_IP_TUNNEL,
	       "sit",
	       name,
	       props->parent_ifindex,
	       nm_utils_inet4_ntop (props->local, NULL),
	       nm_utils_inet4_ntop (props->remote, buffer));

	if (!klass->link_sit_add (self, name, props, out_link))
		return NM_PLATFORM_ERROR_UNSPECIFIED;
	return NM_PLATFORM_ERROR_SUCCESS;
}

gboolean
nm_platform_link_veth_get_properties (NMPlatform *self, int ifindex, int *out_peer_ifindex)
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
		nm_auto_pop_netns NMPNetns *netns = NULL;

		if (!nm_platform_netns_push (self, &netns))
			return FALSE;
		peer_ifindex = nmp_utils_ethtool_get_peer_ifindex (plink->ifindex);
		if (peer_ifindex <= 0)
			return FALSE;

		*out_peer_ifindex = peer_ifindex;
	}
	return TRUE;
}

/**
 * nm_platform_link_tun_get_properties:
 * @self: the #NMPlatform instance
 * @ifindex: the ifindex to look up
 * @out_properties: (out): (allow-none): return the read properties
 *
 * Only recent versions of kernel export tun properties via netlink.
 * So, if that's the case, then we have the NMPlatformLnkTun instance
 * in the platform cache ready to return. Otherwise, this function
 * falls back reading sysctl to obtain the tun properties. That
 * is racy, because querying sysctl means that the object might
 * be already removed from cache (while NM didn't yet process the
 * netlink message).
 *
 * Hence, to lookup the tun properties, you always need to use this
 * function, and use it with care knowing that it might obtain its
 * data by reading sysctl. Note that we don't want to add this workaround
 * to the platform cache itself, because the cache should (mainly)
 * contain data from netlink. To access the sysctl side channel, the
 * user needs to do explicitly.
 *
 * Returns: #TRUE, if the properties could be read. */
gboolean
nm_platform_link_tun_get_properties (NMPlatform *self,
                                     int ifindex,
                                     NMPlatformLnkTun *out_properties)
{
	const NMPObject *plobj;
	const NMPObject *pllnk;
	char ifname[IFNAMSIZ];
	gint64 owner;
	gint64 group;
	gint64 flags;

	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);

	/* we consider also invisible links (those that are not yet in udev). */
	plobj = nm_platform_link_get_obj (self, ifindex, FALSE);
	if (!plobj)
		return FALSE;
	if (NMP_OBJECT_CAST_LINK (plobj)->type != NM_LINK_TYPE_TUN)
		return FALSE;

	pllnk = plobj->_link.netlink.lnk;
	if (pllnk) {
		nm_assert (NMP_OBJECT_GET_TYPE (pllnk) == NMP_OBJECT_TYPE_LNK_TUN);
		nm_assert (NMP_OBJECT_GET_CLASS (pllnk)->lnk_link_type == NM_LINK_TYPE_TUN);

		/* recent kernels expose tun properties via netlink and thus we have them
		 * in the platform cache. */
		NM_SET_OUT (out_properties, pllnk->lnk_tun);
		return TRUE;
	}

	/* fallback to reading sysctl. */
	{
		nm_auto_close int dirfd = -1;

		dirfd = nm_platform_sysctl_open_netdir (self, ifindex, ifname);
		if (dirfd < 0)
			return FALSE;

		owner = nm_platform_sysctl_get_int_checked (self, NMP_SYSCTL_PATHID_NETDIR (dirfd, ifname, "owner"), 10, -1, G_MAXUINT32, -2);
		if (owner == -2)
			return FALSE;

		group = nm_platform_sysctl_get_int_checked (self, NMP_SYSCTL_PATHID_NETDIR (dirfd, ifname, "group"), 10, -1, G_MAXUINT32, -2);
		if (group == -2)
			return FALSE;

		flags = nm_platform_sysctl_get_int_checked (self, NMP_SYSCTL_PATHID_NETDIR (dirfd, ifname, "tun_flags"), 16, 0, G_MAXINT64, -1);
		if (flags == -1)
			return FALSE;
	}

	if (out_properties) {
		memset (out_properties, 0, sizeof (*out_properties));
		if (owner != -1) {
			out_properties->owner_valid = TRUE;
			out_properties->owner = owner;
		}
		if (group != -1) {
			out_properties->group_valid = TRUE;
			out_properties->group = group;
		}
		out_properties->type = (flags & TUN_TYPE_MASK);
		out_properties->pi = !(flags & IFF_NO_PI);
		out_properties->vnet_hdr = !!(flags & IFF_VNET_HDR);
		out_properties->multi_queue = !!(flags & NM_IFF_MULTI_QUEUE);
		out_properties->persist = !!(flags & IFF_PERSIST);
	}
	return TRUE;
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

gboolean
nm_platform_wifi_set_wake_on_wlan (NMPlatform *self, int ifindex, NMSettingWirelessWakeOnWLan wowl)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);

	return klass->wifi_set_wake_on_wlan (self, ifindex, wowl);
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

#define TO_STRING_IFA_FLAGS_BUF_SIZE 256

static const char *
_to_string_ifa_flags (guint32 ifa_flags, char *buf, gsize size)
{
#define S_FLAGS_PREFIX " flags "
	nm_assert (buf && size >= TO_STRING_IFA_FLAGS_BUF_SIZE && size > NM_STRLEN (S_FLAGS_PREFIX));

	if (!ifa_flags)
		buf[0] = '\0';
	else {
		nm_platform_addr_flags2str (ifa_flags, &buf[NM_STRLEN (S_FLAGS_PREFIX)], size - NM_STRLEN (S_FLAGS_PREFIX));
		if (buf[NM_STRLEN (S_FLAGS_PREFIX)] == '\0')
			buf[0] = '\0';
		else
			memcpy (buf, S_FLAGS_PREFIX, NM_STRLEN (S_FLAGS_PREFIX));
	}
	return buf;
}

/*****************************************************************************/

gboolean
nm_platform_ethtool_set_wake_on_lan (NMPlatform *self, int ifindex, NMSettingWiredWakeOnLan wol, const char *wol_password)
{
	_CHECK_SELF_NETNS (self, klass, netns, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);

	return nmp_utils_ethtool_set_wake_on_lan (ifindex, wol, wol_password);
}

gboolean
nm_platform_ethtool_set_link_settings (NMPlatform *self, int ifindex, gboolean autoneg, guint32 speed, NMPlatformLinkDuplexType duplex)
{
	_CHECK_SELF_NETNS (self, klass, netns, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);

	return nmp_utils_ethtool_set_link_settings (ifindex, autoneg, speed, duplex);
}

gboolean
nm_platform_ethtool_get_link_settings (NMPlatform *self, int ifindex, gboolean *out_autoneg, guint32 *out_speed,  NMPlatformLinkDuplexType *out_duplex)
{
	_CHECK_SELF_NETNS (self, klass, netns, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);

	return nmp_utils_ethtool_get_link_settings (ifindex, out_autoneg, out_speed, out_duplex);
}

NM_UTILS_LOOKUP_STR_DEFINE (nm_platform_link_duplex_type_to_string, NMPlatformLinkDuplexType,
	NM_UTILS_LOOKUP_DEFAULT_WARN (NULL),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_LINK_DUPLEX_UNKNOWN, "unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_LINK_DUPLEX_FULL,    "full"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_PLATFORM_LINK_DUPLEX_HALF,    "half"),
);

/*****************************************************************************/

const NMDedupMultiHeadEntry *
nm_platform_lookup_all (NMPlatform *platform,
                        NMPCacheIdType cache_id_type,
                        const NMPObject *obj)
{
	return nmp_cache_lookup_all (nm_platform_get_cache (platform),
	                             cache_id_type,
	                             obj);
}

const NMDedupMultiEntry *
nm_platform_lookup_entry (NMPlatform *platform,
                          NMPCacheIdType cache_id_type,
                          const NMPObject *obj)
{
	return nmp_cache_lookup_entry_with_idx_type (nm_platform_get_cache (platform),
	                                             cache_id_type,
	                                             obj);
}

const NMDedupMultiHeadEntry *
nm_platform_lookup (NMPlatform *self,
                    const NMPLookup *lookup)
{
	return nmp_cache_lookup (nm_platform_get_cache (self),
	                         lookup);
}

gboolean
nm_platform_lookup_predicate_routes_main (const NMPObject *obj,
                                          gpointer user_data)
{
	nm_assert (NM_IN_SET (NMP_OBJECT_GET_TYPE (obj), NMP_OBJECT_TYPE_IP4_ROUTE,
	                                                 NMP_OBJECT_TYPE_IP6_ROUTE));
	return nm_platform_route_table_is_main (obj->ip_route.table_coerced);
}

gboolean
nm_platform_lookup_predicate_routes_main_skip_rtprot_kernel (const NMPObject *obj,
                                                             gpointer user_data)
{
	nm_assert (NM_IN_SET (NMP_OBJECT_GET_TYPE (obj), NMP_OBJECT_TYPE_IP4_ROUTE,
	                                                 NMP_OBJECT_TYPE_IP6_ROUTE));
	return    nm_platform_route_table_is_main (obj->ip_route.table_coerced)
	       && obj->ip_route.rt_source != NM_IP_CONFIG_SOURCE_RTPROT_KERNEL;
}

/**
 * nm_platform_lookup_clone:
 * @self:
 * @lookup:
 * @predicate: if given, only objects for which @predicate returns %TRUE are included
 *   in the result.
 * @user_data: user data for @predicate
 *
 * Returns the result of lookup in a GPtrArray. The result array contains
 * references objects from the cache, its destroy function will unref them.
 *
 * The user must unref the GPtrArray, which will also unref the NMPObject
 * elements.
 *
 * The elements in the array *must* not be modified.
 *
 * Returns: the result of the lookup.
 */
GPtrArray *
nm_platform_lookup_clone (NMPlatform *self,
                          const NMPLookup *lookup,
                          NMPObjectPredicateFunc predicate,
                          gpointer user_data)
{
	return nm_dedup_multi_objs_to_ptr_array_head (nm_platform_lookup (self, lookup),
	                                              (NMDedupMultiFcnSelectPredicate) predicate,
	                                              user_data);
}

void
nm_platform_ip4_address_set_addr (NMPlatformIP4Address *addr, in_addr_t address, guint8 plen)
{
	nm_assert (plen <= 32);

	addr->address = address;
	addr->peer_address = address;
	addr->plen = plen;
}

const struct in6_addr *
nm_platform_ip6_address_get_peer (const NMPlatformIP6Address *addr)
{
	if (   IN6_IS_ADDR_UNSPECIFIED (&addr->peer_address)
	    || IN6_ARE_ADDR_EQUAL (&addr->peer_address, &addr->address))
		return &addr->address;
	return &addr->peer_address;
}

gboolean
nm_platform_ip4_address_add (NMPlatform *self,
                             int ifindex,
                             in_addr_t address,
                             guint8 plen,
                             in_addr_t peer_address,
                             guint32 lifetime,
                             guint32 preferred,
                             guint32 flags,
                             const char *label)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen <= 32, FALSE);
	g_return_val_if_fail (lifetime > 0, FALSE);
	g_return_val_if_fail (preferred <= lifetime, FALSE);
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
		addr.n_ifa_flags = flags;
		if (label)
			g_strlcpy (addr.label, label, sizeof (addr.label));

		_LOGD ("address: adding or updating IPv4 address: %s", nm_platform_ip4_address_to_string (&addr, NULL, 0));
	}
	return klass->ip4_address_add (self, ifindex, address, plen, peer_address, lifetime, preferred, flags, label);
}

gboolean
nm_platform_ip6_address_add (NMPlatform *self,
                             int ifindex,
                             struct in6_addr address,
                             guint8 plen,
                             struct in6_addr peer_address,
                             guint32 lifetime,
                             guint32 preferred,
                             guint32 flags)
{
	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen <= 128, FALSE);
	g_return_val_if_fail (lifetime > 0, FALSE);
	g_return_val_if_fail (preferred <= lifetime, FALSE);

	if (_LOGD_ENABLED ()) {
		NMPlatformIP6Address addr = { 0 };

		addr.ifindex = ifindex;
		addr.address = address;
		addr.peer_address = peer_address;
		addr.plen = plen;
		addr.timestamp = 0; /* set it to zero, which to_string will treat as *now* */
		addr.lifetime = lifetime;
		addr.preferred = preferred;
		addr.n_ifa_flags = flags;

		_LOGD ("address: adding or updating IPv6 address: %s", nm_platform_ip6_address_to_string (&addr, NULL, 0));
	}
	return klass->ip6_address_add (self, ifindex, address, plen, peer_address, lifetime, preferred, flags);
}

gboolean
nm_platform_ip4_address_delete (NMPlatform *self, int ifindex, in_addr_t address, guint8 plen, in_addr_t peer_address)
{
	char str_dev[TO_STRING_DEV_BUF_SIZE];
	char str_peer2[NM_UTILS_INET_ADDRSTRLEN];
	char str_peer[100];

	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen <= 32, FALSE);

	_LOGD ("address: deleting IPv4 address %s/%d, %sifindex %d%s",
	       nm_utils_inet4_ntop (address, NULL), plen,
	       peer_address != address
	           ? nm_sprintf_buf (str_peer, "peer %s, ", nm_utils_inet4_ntop (peer_address, str_peer2)) : "",
	       ifindex,
	       _to_string_dev (self, ifindex, str_dev, sizeof (str_dev)));
	return klass->ip4_address_delete (self, ifindex, address, plen, peer_address);
}

gboolean
nm_platform_ip6_address_delete (NMPlatform *self, int ifindex, struct in6_addr address, guint8 plen)
{
	char str_dev[TO_STRING_DEV_BUF_SIZE];

	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (plen <= 128, FALSE);

	_LOGD ("address: deleting IPv6 address %s/%d, ifindex %d%s",
	       nm_utils_inet6_ntop (&address, NULL), plen, ifindex,
	       _to_string_dev (self, ifindex, str_dev, sizeof (str_dev)));
	return klass->ip6_address_delete (self, ifindex, address, plen);
}

const NMPlatformIP4Address *
nm_platform_ip4_address_get (NMPlatform *self, int ifindex, in_addr_t address, guint8 plen, guint32 peer_address)
{
	NMPObject obj_id;
	const NMPObject *obj;

	_CHECK_SELF (self, klass, NULL);

	g_return_val_if_fail (plen <= 32, NULL);

	nmp_object_stackinit_id_ip4_address (&obj_id, ifindex, address, plen, peer_address);
	obj = nmp_cache_lookup_obj (nm_platform_get_cache (self), &obj_id);
	nm_assert (!obj || nmp_object_is_visible (obj));
	return NMP_OBJECT_CAST_IP4_ADDRESS (obj);
}

const NMPlatformIP6Address *
nm_platform_ip6_address_get (NMPlatform *self, int ifindex, struct in6_addr address)
{
	NMPObject obj_id;
	const NMPObject *obj;

	_CHECK_SELF (self, klass, NULL);

	nmp_object_stackinit_id_ip6_address (&obj_id, ifindex, &address);
	obj = nmp_cache_lookup_obj (nm_platform_get_cache (self), &obj_id);
	nm_assert (!obj || nmp_object_is_visible (obj));
	return NMP_OBJECT_CAST_IP6_ADDRESS (obj);
}

static gboolean
_addr_array_clean_expired (int addr_family, int ifindex, GPtrArray *array, guint32 now, GHashTable **idx)
{
	guint i;
	gboolean any_addrs = FALSE;

	nm_assert_addr_family (addr_family);
	nm_assert (ifindex > 0);
	nm_assert (now > 0);

	if (!array)
		return FALSE;

	/* remove all addresses that are already expired. */
	for (i = 0; i < array->len; i++) {
		const NMPlatformIPAddress *a = NMP_OBJECT_CAST_IP_ADDRESS (array->pdata[i]);

#if NM_MORE_ASSERTS > 10
		nm_assert (a);
		nm_assert (a->ifindex == ifindex);
		{
			const NMPObject *o = NMP_OBJECT_UP_CAST (a);
			guint j;

			nm_assert (NMP_OBJECT_GET_CLASS (o)->addr_family == addr_family);
			for (j = i + 1; j < array->len; j++) {
				const NMPObject *o2 = array->pdata[j];

				nm_assert (NMP_OBJECT_GET_TYPE (o) == NMP_OBJECT_GET_TYPE (o2));
				nm_assert (!nmp_object_id_equal (o, o2));
			}
		}
#endif

		if (   addr_family == AF_INET6
		    && NM_FLAGS_HAS (a->n_ifa_flags, IFA_F_TEMPORARY)) {
			/* temporary addresses are never added explicitly by NetworkManager but
			 * kernel adds them via mngtempaddr flag.
			 *
			 * We drop them from this list. */
			goto clear_and_next;
		}

		if (!nm_utils_lifetime_get (a->timestamp, a->lifetime, a->preferred,
		                            now, NULL))
			goto clear_and_next;

		if (idx) {
			if (G_UNLIKELY (!*idx)) {
				*idx = g_hash_table_new ((GHashFunc) nmp_object_id_hash,
				                         (GEqualFunc) nmp_object_id_equal);
			}
			if (!g_hash_table_add (*idx, (gpointer) NMP_OBJECT_UP_CAST (a)))
				nm_assert_not_reached ();
		}
		any_addrs = TRUE;
		continue;

clear_and_next:
		nmp_object_unref (g_steal_pointer (&array->pdata[i]));
	}

	return any_addrs;
}

static gboolean
ip4_addr_subnets_is_plain_address (const GPtrArray *addresses, gconstpointer needle)
{
	return    needle >= (gconstpointer) &addresses->pdata[0]
	       && needle <  (gconstpointer) &addresses->pdata[addresses->len];
}

static const NMPObject **
ip4_addr_subnets_addr_list_get (const GPtrArray *addr_list, guint idx)
{
	nm_assert (addr_list);
	nm_assert (addr_list->len > 1);
	nm_assert (idx < addr_list->len);
	nm_assert (addr_list->pdata[idx]);
	nm_assert (   !(*((gpointer *) addr_list->pdata[idx]))
	           || NMP_OBJECT_CAST_IP4_ADDRESS (*((gpointer *) addr_list->pdata[idx])));
	nm_assert (idx == 0 || ip4_addr_subnets_addr_list_get (addr_list, idx - 1));
	return addr_list->pdata[idx];
}

static void
ip4_addr_subnets_destroy_index (GHashTable *subnets, const GPtrArray *addresses)
{
	GHashTableIter iter;
	gpointer p;

	if (!subnets)
		return;

	g_hash_table_iter_init (&iter, subnets);
	while (g_hash_table_iter_next (&iter, NULL, &p)) {
		if (!ip4_addr_subnets_is_plain_address (addresses, p))
			g_ptr_array_free ((GPtrArray *) p, TRUE);
	}

	g_hash_table_unref (subnets);
}

static GHashTable *
ip4_addr_subnets_build_index (const GPtrArray *addresses,
                              gboolean consider_flags,
                              gboolean full_index)
{
	GHashTable *subnets;
	guint i;

	nm_assert (addresses && addresses->len);

	subnets = g_hash_table_new (nm_direct_hash, NULL);

	/* Build a hash table of all addresses per subnet */
	for (i = 0; i < addresses->len; i++) {
		const NMPlatformIP4Address *address;
		gpointer p_address;
		GPtrArray *addr_list;
		guint32 net;
		int position;
		gpointer p;

		if (!addresses->pdata[i])
			continue;

		p_address = &addresses->pdata[i];
		address = NMP_OBJECT_CAST_IP4_ADDRESS (addresses->pdata[i]);

		net = address->address & _nm_utils_ip4_prefix_to_netmask (address->plen);
		if (!g_hash_table_lookup_extended (subnets, GUINT_TO_POINTER (net), NULL, &p)) {
			g_hash_table_insert (subnets, GUINT_TO_POINTER (net), p_address);
			continue;
		}
		nm_assert (p);

		if (full_index) {
			if (ip4_addr_subnets_is_plain_address (addresses, p)) {
				addr_list = g_ptr_array_new ();
				g_hash_table_insert (subnets, GUINT_TO_POINTER (net), addr_list);
				g_ptr_array_add (addr_list, p);
			} else
				addr_list = p;

			if (   !consider_flags
			    || NM_FLAGS_HAS (address->n_ifa_flags, IFA_F_SECONDARY))
				position = -1; /* append */
			else
				position = 0; /* prepend */
			g_ptr_array_insert (addr_list, position, p_address);
		} else {
			/* we only care about the primary. No need to track the secondaries
			 * as a GPtrArray. */
			nm_assert (ip4_addr_subnets_is_plain_address (addresses, p));
			if (   consider_flags
			    && !NM_FLAGS_HAS (address->n_ifa_flags, IFA_F_SECONDARY)) {
				g_hash_table_insert (subnets, GUINT_TO_POINTER (net), p_address);
			}
		}
	}

	return subnets;
}

/**
 * ip4_addr_subnets_is_secondary:
 * @address: an address
 * @subnets: the hash table mapping subnets to addresses
 * @addresses: array of addresses in the hash table
 * @out_addr_list: array of addresses belonging to the same subnet
 *
 * Checks whether @address is secondary and returns in @out_addr_list the list of addresses
 * belonging to the same subnet, if it contains other elements.
 *
 * Returns: %TRUE if the address is secondary, %FALSE otherwise
 */
static gboolean
ip4_addr_subnets_is_secondary (const NMPObject *address,
                               GHashTable *subnets,
                               const GPtrArray *addresses,
                               const GPtrArray **out_addr_list)
{
	const NMPlatformIP4Address *a;
	const GPtrArray *addr_list;
	gconstpointer p;
	guint32 net;
	const NMPObject **o;

	a = NMP_OBJECT_CAST_IP4_ADDRESS (address);

	net = a->address & _nm_utils_ip4_prefix_to_netmask (a->plen);
	p = g_hash_table_lookup (subnets, GUINT_TO_POINTER (net));
	nm_assert (p);
	if (!ip4_addr_subnets_is_plain_address (addresses, p)) {
		addr_list = p;
		nm_assert (addr_list->len > 1);
		NM_SET_OUT (out_addr_list, addr_list);
		o = ip4_addr_subnets_addr_list_get (addr_list, 0);
		nm_assert (o && *o);
		if (*o != address)
			return TRUE;
	} else {
		NM_SET_OUT (out_addr_list, NULL);
		return address != *((gconstpointer *) p);
	}
	return FALSE;
}

/**
 * nm_platform_ip4_address_sync:
 * @self: platform instance
 * @ifindex: Interface index
 * @known_addresses: List of addresses. The list will be modified and only
 *   addresses that were successfully added will be kept in the list.
 *   That means, expired addresses and addresses that could not be added
 *   will be dropped.
 *   Hence, the input argument @known_addresses is also an output argument
 *   telling which addresses were succesfully added.
 *   Addresses are removed by unrefing the instance via nmp_object_unref()
 *   and leaving a NULL tombstone.
 *
 * A convenience function to synchronize addresses for a specific interface
 * with the least possible disturbance. It simply removes addresses that are
 * not listed and adds addresses that are.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_ip4_address_sync (NMPlatform *self,
                              int ifindex,
                              GPtrArray *known_addresses)
{
	gs_unref_ptrarray GPtrArray *plat_addresses = NULL;
	const NMPlatformIP4Address *known_address;
	gint32 now = nm_utils_get_monotonic_timestamp_s ();
	GHashTable *plat_subnets = NULL;
	GHashTable *known_subnets = NULL;
	gs_unref_hashtable GHashTable *known_addresses_idx = NULL;
	guint i, j, len;
	NMPLookup lookup;
	guint32 lifetime, preferred;
	guint32 ifa_flags;

	_CHECK_SELF (self, klass, FALSE);

	if (!_addr_array_clean_expired (AF_INET, ifindex, known_addresses, now, &known_addresses_idx))
		known_addresses = NULL;

	plat_addresses = nm_platform_lookup_clone (self,
	                                           nmp_lookup_init_object (&lookup,
	                                                                   NMP_OBJECT_TYPE_IP4_ADDRESS,
	                                                                   ifindex),
	                                           NULL, NULL);
	if (plat_addresses)
		plat_subnets = ip4_addr_subnets_build_index (plat_addresses, TRUE, TRUE);

	/* Delete unknown addresses */
	len = plat_addresses ? plat_addresses->len : 0;
	for (i = 0; i < len; i++) {
		const NMPObject *plat_obj;
		const NMPlatformIP4Address *plat_address;
		const GPtrArray *addr_list;

		plat_obj = plat_addresses->pdata[i];
		if (!plat_obj) {
			/* Already deleted */
			continue;
		}

		plat_address = NMP_OBJECT_CAST_IP4_ADDRESS (plat_obj);

		if (known_addresses) {
			const NMPObject *o;

			o = g_hash_table_lookup (known_addresses_idx, plat_obj);
			if (o) {
				gboolean secondary;

				if (!known_subnets)
					known_subnets = ip4_addr_subnets_build_index (known_addresses, FALSE, FALSE);

				secondary = ip4_addr_subnets_is_secondary (o, known_subnets, known_addresses, NULL);
				if (secondary == NM_FLAGS_HAS (plat_address->n_ifa_flags, IFA_F_SECONDARY)) {
					/* if we have an existing known-address, with matching secondary role,
					 * do not delete the platform-address. */
					continue;
				}
			}
		}

		nm_platform_ip4_address_delete (self, ifindex,
		                                plat_address->address,
		                                plat_address->plen,
		                                plat_address->peer_address);

		if (   !ip4_addr_subnets_is_secondary (plat_obj, plat_subnets, plat_addresses, &addr_list)
		    && addr_list) {
			/* If we just deleted a primary addresses and there were
			 * secondary ones the kernel can do two things, depending on
			 * version and sysctl setting: delete also secondary addresses
			 * or promote a secondary to primary. Ensure that secondary
			 * addresses are deleted, so that we can start with a clean
			 * slate and add addresses in the right order. */
			for (j = 1; j < addr_list->len; j++) {
				const NMPObject **o;

				o = ip4_addr_subnets_addr_list_get (addr_list, j);
				nm_assert (o);

				if (*o) {
					const NMPlatformIP4Address *a;

					a = NMP_OBJECT_CAST_IP4_ADDRESS (*o);
					nm_platform_ip4_address_delete (self, ifindex,
					                                a->address,
					                                a->plen,
					                                a->peer_address);
					nmp_object_unref (*o);
					*o = NULL;
				}
			}
		}
	}
	ip4_addr_subnets_destroy_index (plat_subnets, plat_addresses);
	ip4_addr_subnets_destroy_index (known_subnets, known_addresses);

	if (!known_addresses)
		return TRUE;

	ifa_flags =   nm_platform_check_kernel_support (self, NM_PLATFORM_KERNEL_SUPPORT_EXTENDED_IFA_FLAGS)
	            ? IFA_F_NOPREFIXROUTE
	            : 0;

	/* Add missing addresses */
	for (i = 0; i < known_addresses->len; i++) {
		const NMPObject *o;

		o = known_addresses->pdata[i];
		if (!o)
			continue;

		known_address = NMP_OBJECT_CAST_IP4_ADDRESS (o);

		lifetime = nm_utils_lifetime_get (known_address->timestamp, known_address->lifetime, known_address->preferred,
		                                  now, &preferred);
		if (!lifetime)
			goto delete_and_next2;

		if (!nm_platform_ip4_address_add (self, ifindex, known_address->address, known_address->plen,
		                                  known_address->peer_address, lifetime, preferred,
		                                  ifa_flags,
		                                  known_address->label))
			goto delete_and_next2;

		continue;
delete_and_next2:
		nmp_object_unref (o);
		known_addresses->pdata[i] = NULL;
	}

	return TRUE;
}

static guint
ip6_address_scope_priority (const struct in6_addr *addr)
{
	if (IN6_IS_ADDR_LINKLOCAL (addr))
		return 1;
	if (IN6_IS_ADDR_SITELOCAL (addr))
		return 2;
	return 3;
}

static gint
ip6_address_scope_cmp (gconstpointer a, gconstpointer b)
{
	const NMPlatformIP6Address *x = NMP_OBJECT_CAST_IP6_ADDRESS (*(const void **) a);
	const NMPlatformIP6Address *y = NMP_OBJECT_CAST_IP6_ADDRESS (*(const void **) b);

	return ip6_address_scope_priority (&x->address) - ip6_address_scope_priority (&y->address);
}

/**
 * nm_platform_ip6_address_sync:
 * @self: platform instance
 * @ifindex: Interface index
 * @known_addresses: List of addresses. The list will be modified and only
 *   addresses that were successfully added will be kept in the list.
 *   That means, expired addresses and addresses that could not be added
 *   will be dropped.
 *   Hence, the input argument @known_addresses is also an output argument
 *   telling which addresses were succesfully added.
 *   Addresses are removed by unrefing the instance via nmp_object_unref()
 *   and leaving a NULL tombstone.
 * @full_sync: Also remove link-local and temporary addresses.
 *
 * A convenience function to synchronize addresses for a specific interface
 * with the least possible disturbance. It simply removes addresses that are
 * not listed and adds addresses that are.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_ip6_address_sync (NMPlatform *self,
                              int ifindex,
                              GPtrArray *known_addresses,
                              gboolean full_sync)
{
	gs_unref_ptrarray GPtrArray *plat_addresses = NULL;
	gint32 now = nm_utils_get_monotonic_timestamp_s ();
	guint i_plat, i_know;
	gs_unref_hashtable GHashTable *known_addresses_idx = NULL;
	NMPLookup lookup;
	guint32 ifa_flags;

	/* The order we want to enforce is only among addresses with the same
	 * scope, as the kernel keeps addresses sorted by scope. Therefore,
	 * apply the same sorting to known addresses, so that we don't try to
	 * unnecessary change the order of addresses with different scopes. */
	if (known_addresses)
		g_ptr_array_sort (known_addresses, ip6_address_scope_cmp);

	if (!_addr_array_clean_expired (AF_INET6, ifindex, known_addresses, now, &known_addresses_idx))
		known_addresses = NULL;

	/* @plat_addresses is in decreasing priority order (highest priority addresses first), contrary to
	 * @known_addresses which is in increasing priority order (lowest priority addresses first). */
	plat_addresses = nm_platform_lookup_clone (self,
	                                           nmp_lookup_init_object (&lookup,
	                                                                   NMP_OBJECT_TYPE_IP6_ADDRESS,
	                                                                   ifindex),
	                                           NULL, NULL);

	if (plat_addresses) {
		guint known_addresses_len;

		known_addresses_len = known_addresses ? known_addresses->len : 0;

		/* First, compare every address whether it is still a "known address", that is, whether
		 * to keep it or to delete it.
		 *
		 * If we don't find a matching valid address in @known_addresses, we will delete
		 * plat_addr.
		 *
		 * Certain addresses, like temporary addresses, are ignored by this function
		 * if not run with full_sync. These addresses are usually not managed by NetworkManager
		 * directly, or at least, they are not managed via nm_platform_ip6_address_sync().
		 * Only in full_sync mode, we really want to get rid of them (usually, when we take
		 * the interface down).
		 *
		 * Note that we mark handled addresses by setting it to %NULL in @plat_addresses array. */
		for (i_plat = 0; i_plat < plat_addresses->len; i_plat++) {
			const NMPObject *plat_obj = plat_addresses->pdata[i_plat];
			const NMPObject *know_obj;
			const NMPlatformIP6Address *plat_addr = NMP_OBJECT_CAST_IP6_ADDRESS (plat_obj);

			if (NM_FLAGS_HAS (plat_addr->n_ifa_flags, IFA_F_TEMPORARY)) {
				if (!full_sync) {
					/* just mark as handled, without actually deleting the address. */
					goto clear_and_next;
				}
			} else if (known_addresses_idx) {
				know_obj = g_hash_table_lookup (known_addresses_idx, plat_obj);
				if (   know_obj
				    && plat_addr->plen == NMP_OBJECT_CAST_IP6_ADDRESS (know_obj)->plen) {
					/* technically, plen is not part of the ID for IPv6 addresses and thus
					 * @plat_addr is essentially the same address as @know_addr (regrading
					 * its identity, not its other attributes).
					 * However, we cannot modify an existing addresses' plen without
					 * removing and readding it. Thus, only keep plat_addr, if the plen
					 * matches.
					 *
					 * keep this one, and continue */
					continue;
				}
			}

			nm_platform_ip6_address_delete (self, ifindex, plat_addr->address, plat_addr->plen);
clear_and_next:
			nmp_object_unref (g_steal_pointer (&plat_addresses->pdata[i_plat]));
		}

		/* Next, we must preserve the priority of the routes. That is, source address
		 * selection will choose addresses in the order as they are reported by kernel.
		 * Note that the order in @plat_addresses of the remaining matches is highest
		 * priority first.
		 * We need to compare this to the order in @known_addresses (which has lowest
		 * priority first).
		 *
		 * If we find a first discrepancy, we need to delete all remaining addresses
		 * from that point on, because below we must re-add all the addresses in the
		 * right order to get their priority right. */
		i_plat = plat_addresses->len;
		i_know = 0;
		while (i_plat > 0) {
			const NMPlatformIP6Address *plat_addr = NMP_OBJECT_CAST_IP6_ADDRESS (plat_addresses->pdata[--i_plat]);

			if (!plat_addr)
				continue;

			for (; i_know < known_addresses_len; i_know++) {
				const NMPlatformIP6Address *know_addr = NMP_OBJECT_CAST_IP6_ADDRESS (known_addresses->pdata[i_know]);

				if (!know_addr)
					continue;

				if (IN6_ARE_ADDR_EQUAL (&plat_addr->address, &know_addr->address)) {
					/* we have a match. Mark address as handled. */
					i_know++;
					goto next_plat;
				}

				/* all remainging addresses need to be removed as well, so that we can
				 * re-add them in the correct order. Signal that, by setting @i_know
				 * so that the next @i_plat iteration, we won't enter the loop and
				 * delete the address right away */
				i_know = known_addresses_len;
				break;
			}

			nm_platform_ip6_address_delete (self, ifindex, plat_addr->address, plat_addr->plen);
next_plat:
			;
		}
	}

	if (!known_addresses)
		return TRUE;

	ifa_flags =   nm_platform_check_kernel_support (self, NM_PLATFORM_KERNEL_SUPPORT_EXTENDED_IFA_FLAGS)
	            ? IFA_F_NOPREFIXROUTE
	            : 0;

	/* Add missing addresses. New addresses are added by kernel with top
	 * priority.
	 */
	for (i_know = 0; i_know < known_addresses->len; i_know++) {
		const NMPlatformIP6Address *known_address = NMP_OBJECT_CAST_IP6_ADDRESS (known_addresses->pdata[i_know]);
		guint32 lifetime, preferred;

		if (!known_address)
			continue;

		lifetime = nm_utils_lifetime_get (known_address->timestamp, known_address->lifetime, known_address->preferred,
		                                  now, &preferred);

		if (!nm_platform_ip6_address_add (self, ifindex, known_address->address,
		                                  known_address->plen, known_address->peer_address,
		                                  lifetime, preferred,
		                                  ifa_flags | known_address->n_ifa_flags))
			return FALSE;
	}

	return TRUE;
}

gboolean
nm_platform_ip_address_flush (NMPlatform *self,
                              int addr_family,
                              int ifindex)
{
	gboolean success = TRUE;

	_CHECK_SELF (self, klass, FALSE);

	nm_assert (NM_IN_SET (addr_family, AF_UNSPEC,
	                                   AF_INET,
	                                   AF_INET6));

	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET))
		success &= nm_platform_ip4_address_sync (self, ifindex, NULL);
	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET6))
		success &= nm_platform_ip6_address_sync (self, ifindex, NULL, TRUE);
	return success;
}

/*****************************************************************************/

static gboolean
_err_inval_due_to_ipv6_tentative_pref_src (NMPlatform *self, const NMPObject *obj)
{
	const NMPlatformIP6Route *r;
	const NMPlatformIP6Address *a;

	nm_assert (NM_IS_PLATFORM (self));
	nm_assert (NMP_OBJECT_IS_VALID (obj));

	/* trying to add an IPv6 route with pref-src fails, if the address is
	 * still tentative (rh#1452684). We need to hack around that.
	 *
	 * Detect it, by guessing whether that's the case. */

	if (NMP_OBJECT_GET_TYPE (obj) != NMP_OBJECT_TYPE_IP6_ROUTE)
		return FALSE;

	r = NMP_OBJECT_CAST_IP6_ROUTE (obj);

	/* we only allow this workaround for routes added manually by the user. */
	if (r->rt_source != NM_IP_CONFIG_SOURCE_USER)
		return FALSE;

	if (IN6_IS_ADDR_UNSPECIFIED (&r->pref_src))
		return FALSE;

	a = nm_platform_ip6_address_get (self, r->ifindex, r->pref_src);
	if (!a)
		return FALSE;
	if (   !NM_FLAGS_HAS (a->n_ifa_flags, IFA_F_TENTATIVE)
	    || NM_FLAGS_HAS (a->n_ifa_flags, IFA_F_DADFAILED))
		return FALSE;

	return TRUE;
}

GPtrArray *
nm_platform_ip_route_get_prune_list (NMPlatform *self,
                                     int addr_family,
                                     int ifindex,
                                     NMIPRouteTableSyncMode route_table_sync)
{
	NMPLookup lookup;
	GPtrArray *routes_prune;
	const NMDedupMultiHeadEntry *head_entry;
	CList *iter;

	nm_assert (NM_IS_PLATFORM (self));
	nm_assert (NM_IN_SET (addr_family, AF_INET, AF_INET6));
	nm_assert (NM_IN_SET (route_table_sync, NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN,
	                                        NM_IP_ROUTE_TABLE_SYNC_MODE_FULL,
	                                        NM_IP_ROUTE_TABLE_SYNC_MODE_ALL));

	nmp_lookup_init_object (&lookup,
	                        addr_family == AF_INET
	                          ? NMP_OBJECT_TYPE_IP4_ROUTE
	                          : NMP_OBJECT_TYPE_IP6_ROUTE,
	                        ifindex);
	head_entry = nm_platform_lookup (self, &lookup);
	if (!head_entry)
		return NULL;

	routes_prune = g_ptr_array_new_full (head_entry->len,
	                                     (GDestroyNotify) nm_dedup_multi_obj_unref);

	c_list_for_each (iter, &head_entry->lst_entries_head) {
		const NMPObject *obj = c_list_entry (iter, NMDedupMultiEntry, lst_entries)->obj;

		if (route_table_sync == NM_IP_ROUTE_TABLE_SYNC_MODE_FULL) {
			if (nm_platform_route_table_uncoerce (NMP_OBJECT_CAST_IP_ROUTE (obj)->table_coerced, TRUE) == RT_TABLE_LOCAL)
				continue;
		} else if (route_table_sync == NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN) {
			if (!nm_platform_route_table_is_main (NMP_OBJECT_CAST_IP_ROUTE (obj)->table_coerced))
				continue;
		} else
			nm_assert (route_table_sync == NM_IP_ROUTE_TABLE_SYNC_MODE_ALL);

		g_ptr_array_add (routes_prune, (gpointer) nmp_object_ref (obj));
	}

	if (routes_prune->len == 0) {
		g_ptr_array_unref (routes_prune);
		return NULL;
	}
	return routes_prune;
}

/**
 * nm_platform_ip_route_sync:
 * @self: the #NMPlatform instance.
 * @addr_family: AF_INET or AF_INET6.
 * @ifindex: the @ifindex for which the routes are to be added.
 * @routes: (allow-none): a list of routes to configure. Must contain
 *   NMPObject instances of routes, according to @addr_family.
 * @routes_prune: (allow-none): the list of routes to delete.
 *   If platform has such a route configured, it will be deleted
 *   at the end of the operation. Note that if @routes contains
 *   the same route, then it will not be deleted. @routes overrules
 *   @routes_prune list.
 * @out_temporary_not_available: (allow-none): (out): routes that could
 *   currently not be synced. The caller shall keep them and try later again.
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_platform_ip_route_sync (NMPlatform *self,
                           int addr_family,
                           int ifindex,
                           GPtrArray *routes,
                           GPtrArray *routes_prune,
                           GPtrArray **out_temporary_not_available)
{
	const NMPlatformVTableRoute *vt;
	gs_unref_hashtable GHashTable *routes_idx = NULL;
	const NMPObject *conf_o;
	const NMDedupMultiEntry *plat_entry;
	guint i;
	int i_type;
	gboolean success = TRUE;
	char sbuf1[sizeof (_nm_utils_to_string_buffer)];
	char sbuf2[sizeof (_nm_utils_to_string_buffer)];
	char sbuf_err[60];

	nm_assert (NM_IS_PLATFORM (self));
	nm_assert (NM_IN_SET (addr_family, AF_INET, AF_INET6));
	nm_assert (ifindex > 0);

	vt = addr_family == AF_INET
	     ? &nm_platform_vtable_route_v4
	     : &nm_platform_vtable_route_v6;

	for (i_type = 0; routes && i_type < 2; i_type++) {
		for (i = 0; i < routes->len; i++) {
			NMPlatformError plerr, plerr2;
			gboolean gateway_route_added = FALSE;

			conf_o = routes->pdata[i];

#define VTABLE_IS_DEVICE_ROUTE(vt, o) (vt->is_ip4 \
                                         ? (NMP_OBJECT_CAST_IP4_ROUTE (o)->gateway == 0) \
                                         : IN6_IS_ADDR_UNSPECIFIED (&NMP_OBJECT_CAST_IP6_ROUTE (o)->gateway) )

			if (   (i_type == 0 && !VTABLE_IS_DEVICE_ROUTE (vt, conf_o))
			    || (i_type == 1 &&  VTABLE_IS_DEVICE_ROUTE (vt, conf_o))) {
				/* we add routes in two runs over @i_type.
				 *
				 * First device routes, then gateway routes. */
				continue;
			}

			if (!routes_idx) {
				routes_idx = g_hash_table_new ((GHashFunc) nmp_object_id_hash,
				                               (GEqualFunc) nmp_object_id_equal);
			}
			if (!g_hash_table_insert (routes_idx, (gpointer) conf_o, (gpointer) conf_o)) {
				_LOGD ("route-sync: skip adding duplicate route %s",
				       nmp_object_to_string (conf_o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf1, sizeof (sbuf1)));
				continue;
			}

			plat_entry = nm_platform_lookup_entry (self,
			                                       NMP_CACHE_ID_TYPE_OBJECT_TYPE,
			                                       conf_o);
			if (plat_entry) {
				const NMPObject *plat_o;

				plat_o = plat_entry->obj;

				if (vt->route_cmp (NMP_OBJECT_CAST_IPX_ROUTE (conf_o),
				                   NMP_OBJECT_CAST_IPX_ROUTE (plat_o),
				                   NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) == 0)
					continue;

				/* we need to replace the existing route with a (slightly) differnt
				 * one. Delete it first. */
				if (!nm_platform_object_delete (self, plat_o)) {
					/* ignore error. */
				}
			}

sync_route_add:
			plerr = nm_platform_ip_route_add (self,
			                                    NMP_NLM_FLAG_APPEND
			                                  | NMP_NLM_FLAG_SUPPRESS_NETLINK_FAILURE,
			                                  conf_o);
			if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
				if (-((int) plerr) == EEXIST) {
					/* Don't fail for EEXIST. It's not clear that the existing route
					 * is identical to the one that we were about to add. However,
					 * above we should have deleted conflicting (non-identical) routes. */
					if (_LOGD_ENABLED ()) {
						plat_entry = nm_platform_lookup_entry (self,
						                                       NMP_CACHE_ID_TYPE_OBJECT_TYPE,
						                                       conf_o);
						if (!plat_entry) {
							_LOGD ("route-sync: adding route %s failed with EEXIST, however we cannot find such a route",
							       nmp_object_to_string (conf_o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf1, sizeof (sbuf1)));
						} else if (vt->route_cmp (NMP_OBJECT_CAST_IPX_ROUTE (conf_o),
						                          NMP_OBJECT_CAST_IPX_ROUTE (plat_entry->obj),
						                          NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) != 0) {
							_LOGD ("route-sync: adding route %s failed due to existing (different!) route %s",
							       nmp_object_to_string (conf_o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf1, sizeof (sbuf1)),
							       nmp_object_to_string (plat_entry->obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf2, sizeof (sbuf2)));
						}
					}
				} else if (NMP_OBJECT_CAST_IP_ROUTE (conf_o)->rt_source < NM_IP_CONFIG_SOURCE_USER) {
					_LOGD ("route-sync: ignore failure to add IPv%c route: %s: %s",
					       vt->is_ip4 ? '4' : '6',
					       nmp_object_to_string (conf_o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf1, sizeof (sbuf1)),
					       nm_platform_error_to_string (plerr, sbuf_err, sizeof (sbuf_err)));
				} else if (   -((int) plerr) == EINVAL
				           && out_temporary_not_available
				           && _err_inval_due_to_ipv6_tentative_pref_src (self, conf_o)) {
					_LOGD ("route-sync: ignore failure to add IPv6 route with tentative IPv6 pref-src: %s: %s",
					       nmp_object_to_string (conf_o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf1, sizeof (sbuf1)),
					       nm_platform_error_to_string (plerr, sbuf_err, sizeof (sbuf_err)));
					if (!*out_temporary_not_available)
						*out_temporary_not_available = g_ptr_array_new_full (0, (GDestroyNotify) nmp_object_unref);
					g_ptr_array_add (*out_temporary_not_available, (gpointer) nmp_object_ref (conf_o));
				} else if (   !gateway_route_added
				           && (   (   -((int) plerr) == ENETUNREACH
				                   && vt->is_ip4
				                   && !!NMP_OBJECT_CAST_IP4_ROUTE (conf_o)->gateway)
				               || (   -((int) plerr) == EHOSTUNREACH
				                   && !vt->is_ip4
				                   && !IN6_IS_ADDR_UNSPECIFIED (&NMP_OBJECT_CAST_IP6_ROUTE (conf_o)->gateway)))) {
					NMPObject oo;

					if (vt->is_ip4) {
						const NMPlatformIP4Route *r = NMP_OBJECT_CAST_IP4_ROUTE (conf_o);

						nmp_object_stackinit (&oo,
						                      NMP_OBJECT_TYPE_IP4_ROUTE,
						                      &((NMPlatformIP4Route) {
						                          .ifindex = r->ifindex,
						                          .network = r->gateway,
						                          .plen = 32,
						                          .metric = r->metric,
						                          .rt_source = r->rt_source,
						                          .table_coerced = r->table_coerced,
						                      }));
					} else {
						const NMPlatformIP6Route *r = NMP_OBJECT_CAST_IP6_ROUTE (conf_o);

						nmp_object_stackinit (&oo,
						                      NMP_OBJECT_TYPE_IP6_ROUTE,
						                      &((NMPlatformIP6Route) {
						                          .ifindex = r->ifindex,
						                          .network = r->gateway,
						                          .plen = 128,
						                          .metric = r->metric,
						                          .rt_source = r->rt_source,
						                          .table_coerced = r->table_coerced,
						                      }));
					}

					_LOGD ("route-sync: failure to add IPv%c route: %s: %s; try adding direct route to gateway %s",
					       vt->is_ip4 ? '4' : '6',
					       nmp_object_to_string (conf_o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf1, sizeof (sbuf1)),
					       nm_platform_error_to_string (plerr, sbuf_err, sizeof (sbuf_err)),
					       nmp_object_to_string (&oo, NMP_OBJECT_TO_STRING_PUBLIC, sbuf2, sizeof (sbuf2)));

					plerr2 = nm_platform_ip_route_add (self,
					                                     NMP_NLM_FLAG_APPEND
					                                   | NMP_NLM_FLAG_SUPPRESS_NETLINK_FAILURE,
					                                   &oo);

					if (plerr2 != NM_PLATFORM_ERROR_SUCCESS) {
						_LOGD ("route-sync: failure to add gateway IPv%c route: %s: %s",
						       vt->is_ip4 ? '4' : '6',
						       nmp_object_to_string (conf_o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf1, sizeof (sbuf1)),
						       nm_platform_error_to_string (plerr, sbuf_err, sizeof (sbuf_err)));
					}

					gateway_route_added = TRUE;
					goto sync_route_add;
				} else {
					_LOGW ("route-sync: failure to add IPv%c route: %s: %s",
					       vt->is_ip4 ? '4' : '6',
					       nmp_object_to_string (conf_o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf1, sizeof (sbuf1)),
					       nm_platform_error_to_string (plerr, sbuf_err, sizeof (sbuf_err)));
					success = FALSE;
				}
			}
		}
	}

	if (routes_prune) {
		for (i = 0; i < routes_prune->len; i++) {
			const NMPObject *prune_o;

			prune_o = routes_prune->pdata[i];

			nm_assert (   (addr_family == AF_INET  && NMP_OBJECT_GET_TYPE (prune_o) == NMP_OBJECT_TYPE_IP4_ROUTE)
			           || (addr_family == AF_INET6 && NMP_OBJECT_GET_TYPE (prune_o) == NMP_OBJECT_TYPE_IP6_ROUTE));

			if (   routes_idx
			    && g_hash_table_lookup (routes_idx, prune_o))
				continue;

			if (!nm_platform_lookup_entry (self,
			                               NMP_CACHE_ID_TYPE_OBJECT_TYPE,
			                               prune_o))
				continue;

			if (!nm_platform_object_delete (self, prune_o)) {
				/* ignore error... */
			}
		}
	}

	return success;
}

gboolean
nm_platform_ip_route_flush (NMPlatform *self,
                            int addr_family,
                            int ifindex)
{
	gboolean success = TRUE;

	_CHECK_SELF (self, klass, FALSE);

	nm_assert (NM_IN_SET (addr_family, AF_UNSPEC,
	                                   AF_INET,
	                                   AF_INET6));

	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET)) {
		gs_unref_ptrarray GPtrArray *routes_prune = NULL;

		routes_prune = nm_platform_ip_route_get_prune_list (self,
		                                                    AF_INET,
		                                                    ifindex,
		                                                    NM_IP_ROUTE_TABLE_SYNC_MODE_ALL);
		success &= nm_platform_ip_route_sync (self, AF_INET, ifindex, NULL, routes_prune, NULL);
	}
	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET6)) {
		gs_unref_ptrarray GPtrArray *routes_prune = NULL;

		routes_prune = nm_platform_ip_route_get_prune_list (self,
		                                                    AF_INET6,
		                                                    ifindex,
		                                                    NM_IP_ROUTE_TABLE_SYNC_MODE_ALL);
		success &= nm_platform_ip_route_sync (self, AF_INET6, ifindex, NULL, routes_prune, NULL);
	}
	return success;
}

/*****************************************************************************/

static guint8
_ip_route_scope_inv_get_normalized (const NMPlatformIP4Route *route)
{
	/* in kernel, you cannot set scope to RT_SCOPE_NOWHERE (255).
	 * That means, in NM, we treat RT_SCOPE_NOWHERE as unset, and detect
	 * it based on the presence of the gateway. In other words, when adding
	 * a route with scope RT_SCOPE_NOWHERE (in NetworkManager) to kernel,
	 * the resulting scope will be either "link" or "universe" (depending
	 * on the gateway).
	 *
	 * Note that internally, we track @scope_inv is the inverse of scope,
	 * so that the default equals zero (~(RT_SCOPE_NOWHERE)).
	 **/
	if (route->scope_inv == 0) {
		return nm_platform_route_scope_inv (!route->gateway
		                                    ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSE);
	}
	return route->scope_inv;
}

static guint8
_route_pref_normalize (guint8 pref)
{
	/* for kernel (and ICMPv6) pref can only have one of 3 values. Normalize. */
	return NM_IN_SET (pref, NM_ICMPV6_ROUTER_PREF_LOW,
	                        NM_ICMPV6_ROUTER_PREF_HIGH)
	       ? pref
	       : NM_ICMPV6_ROUTER_PREF_MEDIUM;
}

/**
 * nm_platform_ip_route_normalize:
 * @addr_family: AF_INET or AF_INET6
 * @route: an NMPlatformIP4Route or NMPlatformIP6Route instance, depending on @addr_family.
 *
 * Adding a route to kernel via nm_platform_ip_route_add() will normalize/coerce some
 * properties of the route. This function modifies (normalizes) the route like it
 * would be done by adding the route in kernel.
 *
 * Note that this function is related to NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY
 * in that if two routes compare semantically equal, after normalizing they also shall
 * compare equal with NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL.
 */
void
nm_platform_ip_route_normalize (int addr_family,
                                NMPlatformIPRoute *route)
{
	NMPlatformIP4Route *r4;
	NMPlatformIP6Route *r6;

	switch (addr_family) {
	case AF_INET:
		r4 = (NMPlatformIP4Route *) route;
		r4->table_coerced = nm_platform_route_table_coerce (nm_platform_route_table_uncoerce (r4->table_coerced, TRUE));
		r4->network = nm_utils_ip4_address_clear_host_address (r4->network, r4->plen);
		r4->rt_source = nmp_utils_ip_config_source_round_trip_rtprot (r4->rt_source);
		r4->scope_inv = _ip_route_scope_inv_get_normalized (r4);
		break;
	case AF_INET6:
		r6 = (NMPlatformIP6Route *) route;
		r6->table_coerced = nm_platform_route_table_coerce (nm_platform_route_table_uncoerce (r6->table_coerced, TRUE));
		nm_utils_ip6_address_clear_host_address (&r6->network, &r6->network, r6->plen);
		r6->rt_source = nmp_utils_ip_config_source_round_trip_rtprot (r6->rt_source),
		r6->metric = nm_utils_ip6_route_metric_normalize (r6->metric);
		nm_utils_ip6_address_clear_host_address (&r6->src, &r6->src, r6->src_plen);
		break;
	default:
		nm_assert_not_reached ();
		break;
	}
}

static NMPlatformError
_ip_route_add (NMPlatform *self,
               NMPNlmFlags flags,
               int addr_family,
               gconstpointer route)
{
	char sbuf[sizeof (_nm_utils_to_string_buffer)];

	_CHECK_SELF (self, klass, FALSE);

	nm_assert (route);
	nm_assert (NM_IN_SET (addr_family, AF_INET, AF_INET6));

	_LOGD ("route: %-10s IPv%c route: %s",
	       _nmp_nlm_flag_to_string (flags & NMP_NLM_FLAG_FMASK),
	       nm_utils_addr_family_to_char (addr_family),
	       addr_family == AF_INET
	         ? nm_platform_ip4_route_to_string (route, sbuf, sizeof (sbuf))
	         : nm_platform_ip6_route_to_string (route, sbuf, sizeof (sbuf)));

	return klass->ip_route_add (self, flags, addr_family, route);
}

NMPlatformError
nm_platform_ip_route_add (NMPlatform *self,
                          NMPNlmFlags flags,
                          const NMPObject *route)
{
	int addr_family;

	switch (NMP_OBJECT_GET_TYPE (route)) {
	case NMP_OBJECT_TYPE_IP4_ROUTE:
		addr_family = AF_INET;
		break;
	case NMP_OBJECT_TYPE_IP6_ROUTE:
		addr_family = AF_INET6;
		break;
	default:
		g_return_val_if_reached (FALSE);
	}

	return _ip_route_add (self, flags, addr_family, NMP_OBJECT_CAST_IP_ROUTE (route));
}

NMPlatformError
nm_platform_ip4_route_add (NMPlatform *self,
                           NMPNlmFlags flags,
                           const NMPlatformIP4Route *route)
{
	return _ip_route_add (self, flags, AF_INET, route);
}

NMPlatformError
nm_platform_ip6_route_add (NMPlatform *self,
                           NMPNlmFlags flags,
                           const NMPlatformIP6Route *route)
{
	return _ip_route_add (self, flags, AF_INET6, route);
}

gboolean
nm_platform_object_delete (NMPlatform *self,
                           const NMPObject *obj)
{
	_CHECK_SELF (self, klass, FALSE);

	if (!NM_IN_SET (NMP_OBJECT_GET_TYPE (obj), NMP_OBJECT_TYPE_IP4_ROUTE,
	                                           NMP_OBJECT_TYPE_IP6_ROUTE,
	                                           NMP_OBJECT_TYPE_QDISC,
	                                           NMP_OBJECT_TYPE_TFILTER))
		g_return_val_if_reached (FALSE);

	_LOGD ("%s: delete %s",
	       NMP_OBJECT_GET_CLASS (obj)->obj_type_name,
	       nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));

	return klass->object_delete (self, obj);
}

/*****************************************************************************/

NMPlatformError
nm_platform_ip_route_get (NMPlatform *self,
                          int addr_family,
                          gconstpointer address /* in_addr_t or struct in6_addr */,
                          int oif_ifindex,
                          NMPObject **out_route)
{
	nm_auto_nmpobj NMPObject *route = NULL;
	NMPlatformError result;
	char buf[NM_UTILS_INET_ADDRSTRLEN];
	char buf_err[200];
	char buf_oif[64];

	_CHECK_SELF (self, klass, FALSE);

	g_return_val_if_fail (address, NM_PLATFORM_ERROR_BUG);
	g_return_val_if_fail (NM_IN_SET (addr_family, AF_INET,
	                                              AF_INET6), NM_PLATFORM_ERROR_BUG);

	_LOGT ("route: get IPv%c route for: %s%s",
	       nm_utils_addr_family_to_char (addr_family),
	       inet_ntop (addr_family, address, buf, sizeof (buf)),
	       oif_ifindex > 0 ? nm_sprintf_buf (buf_oif, " oif %d", oif_ifindex) : "");

	if (!klass->ip_route_get)
		result = NM_PLATFORM_ERROR_OPNOTSUPP;
	else {
		result = klass->ip_route_get (self,
		                              addr_family,
		                              address,
		                              oif_ifindex,
		                              &route);
	}

	if (result != NM_PLATFORM_ERROR_SUCCESS) {
		nm_assert (!route);
		_LOGW ("route: get IPv%c route for: %s failed with %s",
		       nm_utils_addr_family_to_char (addr_family),
		       inet_ntop (addr_family, address, buf, sizeof (buf)),
		       nm_platform_error_to_string (result, buf_err, sizeof (buf_err)));
	} else {
		nm_assert (NM_IN_SET (NMP_OBJECT_GET_TYPE (route), NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE));
		nm_assert (!NMP_OBJECT_IS_STACKINIT (route));
		nm_assert (route->parent._ref_count == 1);
		_LOGD ("route: get IPv%c route for: %s succeeded: %s",
		       nm_utils_addr_family_to_char (addr_family),
		       inet_ntop (addr_family, address, buf, sizeof (buf)),
		       nmp_object_to_string (route, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));
		NM_SET_OUT (out_route, g_steal_pointer (&route));
	}
	return result;
}

/*****************************************************************************/

#define IP4_DEV_ROUTE_BLACKLIST_TIMEOUT_MS   ((int) 1500)
#define IP4_DEV_ROUTE_BLACKLIST_GC_TIMEOUT_S ((int) (((IP4_DEV_ROUTE_BLACKLIST_TIMEOUT_MS + 999) * 3) / 1000))

static gint64
_ip4_dev_route_blacklist_timeout_ms_get (gint64 timeout_ms)
{
	return timeout_ms >> 1;
}

static gint64
_ip4_dev_route_blacklist_timeout_ms_marked (gint64 timeout_ms)
{
	return !!(timeout_ms & ((gint64) 1));
}

static gboolean
_ip4_dev_route_blacklist_check_cb (gpointer user_data)
{
	NMPlatform *self = user_data;
	NMPlatformPrivate *priv = NM_PLATFORM_GET_PRIVATE (self);
	GHashTableIter iter;
	const NMPObject *p_obj;
	gint64 *p_timeout_ms;
	gint64 now_ms;

	priv->ip4_dev_route_blacklist_check_id = 0;

again:
	if (!priv->ip4_dev_route_blacklist_hash)
		goto out;

	now_ms = nm_utils_get_monotonic_timestamp_ms ();

	g_hash_table_iter_init (&iter, priv->ip4_dev_route_blacklist_hash);
	while (g_hash_table_iter_next (&iter, (gpointer *) &p_obj, (gpointer *) &p_timeout_ms)) {
		if (!_ip4_dev_route_blacklist_timeout_ms_marked (*p_timeout_ms))
			continue;

		/* unmark because we checked it. */
		*p_timeout_ms = *p_timeout_ms & ~((gint64) 1);

		if (now_ms > _ip4_dev_route_blacklist_timeout_ms_get (*p_timeout_ms))
			continue;

		if (!nm_platform_lookup_entry (self,
		                               NMP_CACHE_ID_TYPE_OBJECT_TYPE,
		                               p_obj))
			continue;

		_LOGT ("ip4-dev-route: delete %s",
		       nmp_object_to_string (p_obj, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));
		nm_platform_object_delete (self, p_obj);
		goto again;
	}

out:
	return G_SOURCE_REMOVE;
}

static void
_ip4_dev_route_blacklist_check_schedule (NMPlatform *self)
{
	NMPlatformPrivate *priv = NM_PLATFORM_GET_PRIVATE (self);

	if (!priv->ip4_dev_route_blacklist_check_id) {
		priv->ip4_dev_route_blacklist_check_id = g_idle_add_full (G_PRIORITY_HIGH,
		                                                          _ip4_dev_route_blacklist_check_cb,
		                                                          self,
		                                                          NULL);
	}
}

static void
_ip4_dev_route_blacklist_notify_route (NMPlatform *self,
                                       const NMPObject *obj)
{
	NMPlatformPrivate *priv;
	const NMPObject *p_obj;
	gint64 *p_timeout_ms;
	gint64 now_ms;

	nm_assert (NM_IS_PLATFORM (self));
	nm_assert (NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_IP4_ROUTE);

	priv = NM_PLATFORM_GET_PRIVATE (self);

	nm_assert (priv->ip4_dev_route_blacklist_gc_timeout_id);

	if (!g_hash_table_lookup_extended (priv->ip4_dev_route_blacklist_hash,
	                                   obj,
	                                   (gpointer *) &p_obj,
	                                   (gpointer *) &p_timeout_ms))
		return;

	now_ms = nm_utils_get_monotonic_timestamp_ms ();
	if (now_ms > _ip4_dev_route_blacklist_timeout_ms_get (*p_timeout_ms)) {
		/* already expired. Wait for gc. */
		return;
	}

	if (_ip4_dev_route_blacklist_timeout_ms_marked (*p_timeout_ms)) {
		nm_assert (priv->ip4_dev_route_blacklist_check_id);
		return;
	}

	/* We cannot delete it right away because we are in the process of receiving netlink messages.
	 * It may be possible to do so, but complicated and error prone.
	 *
	 * Instead, we mark the entry and schedule an idle action (with high priority). */
	*p_timeout_ms = (*p_timeout_ms) | ((gint64) 1);
	_ip4_dev_route_blacklist_check_schedule (self);
}

static gboolean
_ip4_dev_route_blacklist_gc_timeout_handle (gpointer user_data)
{
	NMPlatform *self = user_data;
	NMPlatformPrivate *priv = NM_PLATFORM_GET_PRIVATE (self);
	GHashTableIter iter;
	const NMPObject *p_obj;
	gint64 *p_timeout_ms;
	gint64 now_ms;

	nm_assert (priv->ip4_dev_route_blacklist_gc_timeout_id);

	now_ms = nm_utils_get_monotonic_timestamp_ms ();

	g_hash_table_iter_init (&iter, priv->ip4_dev_route_blacklist_hash);
	while (g_hash_table_iter_next (&iter, (gpointer *) &p_obj, (gpointer *) &p_timeout_ms)) {
		if (now_ms > _ip4_dev_route_blacklist_timeout_ms_get (*p_timeout_ms)) {
			_LOGT ("ip4-dev-route: cleanup %s",
			       nmp_object_to_string (p_obj, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));
			g_hash_table_iter_remove (&iter);
		}
	}

	_ip4_dev_route_blacklist_schedule (self);
	return G_SOURCE_CONTINUE;
}

static void
_ip4_dev_route_blacklist_schedule (NMPlatform *self)
{
	NMPlatformPrivate *priv = NM_PLATFORM_GET_PRIVATE (self);

	if (   !priv->ip4_dev_route_blacklist_hash
	    || g_hash_table_size (priv->ip4_dev_route_blacklist_hash) == 0) {
		g_clear_pointer (&priv->ip4_dev_route_blacklist_hash, g_hash_table_unref);
		nm_clear_g_source (&priv->ip4_dev_route_blacklist_gc_timeout_id);
	} else {
		if (!priv->ip4_dev_route_blacklist_gc_timeout_id) {
			/* this timeout is only to garbage collect the expired entries from priv->ip4_dev_route_blacklist_hash.
			 * It can run infrequently, and it doesn't hurt if expired entries linger around a bit
			 * longer then necessary. */
			priv->ip4_dev_route_blacklist_gc_timeout_id = g_timeout_add_seconds (IP4_DEV_ROUTE_BLACKLIST_GC_TIMEOUT_S,
			                                                                     _ip4_dev_route_blacklist_gc_timeout_handle,
			                                                                     self);
		}
	}
}

/**
 * nm_platform_ip4_dev_route_blacklist_set:
 * @self:
 * @ifindex:
 * @ip4_dev_route_blacklist:
 *
 * When adding an IP address, kernel automatically adds a device route.
 * This can be suppressed via the IFA_F_NOPREFIXROUTE address flag. For proper
 * IPv6 support, we require kernel support for IFA_F_NOPREFIXROUTE and always
 * add the device route manually.
 *
 * For IPv4, this flag is rather new and we don't rely on it yet. We want to use
 * it (but currently still don't). So, for IPv4, kernel possibly adds a device
 * route, however it has a wrong metric of zero. We add our own device route (with
 * proper metric), but need to delete the route that kernel adds.
 *
 * The problem is, that kernel does not immidiately add the route, when adding
 * the address. It only shows up some time later. So, we register here a list
 * of blacklisted routes, and when they show up within a time out, we assume it's
 * the kernel generated one, and we delete it.
 *
 * Eventually, we want to get rid of this and use IFA_F_NOPREFIXROUTE for IPv4
 * routes as well.
 */
void
nm_platform_ip4_dev_route_blacklist_set (NMPlatform *self,
                                         int ifindex,
                                         GPtrArray *ip4_dev_route_blacklist)
{
	NMPlatformPrivate *priv;
	GHashTableIter iter;
	const NMPObject *p_obj;
	guint i;
	gint64 timeout_ms;
	gint64 timeout_ms_val;
	gint64 *p_timeout_ms;
	gboolean needs_check = FALSE;

	nm_assert (NM_IS_PLATFORM (self));
	nm_assert (ifindex > 0);

	priv = NM_PLATFORM_GET_PRIVATE (self);

	/* first, expire all for current ifindex... */
	if (priv->ip4_dev_route_blacklist_hash) {
		g_hash_table_iter_init (&iter, priv->ip4_dev_route_blacklist_hash);
		while (g_hash_table_iter_next (&iter, (gpointer *) &p_obj, (gpointer *) &p_timeout_ms)) {
			if (NMP_OBJECT_CAST_IP4_ROUTE (p_obj)->ifindex == ifindex) {
				/* we could g_hash_table_iter_remove(&iter) the current entry.
				 * Instead, just expire it and let _ip4_dev_route_blacklist_gc_timeout_handle()
				 * handle it.
				 *
				 * The assumption is, that ip4_dev_route_blacklist contains the very same entry
				 * again, with a new timeout. So, we can un-expire it below. */
				*p_timeout_ms = 0;
			}
		}
	}

	if (   ip4_dev_route_blacklist
	    && ip4_dev_route_blacklist->len > 0) {

		if (!priv->ip4_dev_route_blacklist_hash) {
			priv->ip4_dev_route_blacklist_hash = g_hash_table_new_full ((GHashFunc) nmp_object_id_hash,
			                                                            (GEqualFunc) nmp_object_id_equal,
			                                                            (GDestroyNotify) nmp_object_unref,
			                                                            nm_g_slice_free_fcn_gint64);
		}

		timeout_ms = nm_utils_get_monotonic_timestamp_ms () + IP4_DEV_ROUTE_BLACKLIST_TIMEOUT_MS;
		timeout_ms_val = (timeout_ms << 1) | ((gint64) 1);
		for (i = 0; i < ip4_dev_route_blacklist->len; i++) {
			const NMPObject *o;

			needs_check = TRUE;
			o = ip4_dev_route_blacklist->pdata[i];
			if (g_hash_table_lookup_extended (priv->ip4_dev_route_blacklist_hash,
			                                  o,
			                                  (gpointer *) &p_obj,
			                                  (gpointer *) &p_timeout_ms)) {
				if (nmp_object_equal (p_obj, o)) {
					/* un-expire and reuse the entry. */
					_LOGT ("ip4-dev-route: register %s (update)",
					       nmp_object_to_string (p_obj, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));
					*p_timeout_ms = timeout_ms_val;
					continue;
				}
			}

			_LOGT ("ip4-dev-route: register %s",
			       nmp_object_to_string (o, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));
			p_timeout_ms = g_slice_new (gint64);
			*p_timeout_ms = timeout_ms_val;
			g_hash_table_replace (priv->ip4_dev_route_blacklist_hash,
			                      (gpointer) nmp_object_ref (o),
			                      p_timeout_ms);
		}
	}

	_ip4_dev_route_blacklist_schedule (self);

	if (needs_check)
		_ip4_dev_route_blacklist_check_schedule (self);
}

/*****************************************************************************/

NMPlatformError
nm_platform_qdisc_add (NMPlatform *self,
                       NMPNlmFlags flags,
                       const NMPlatformQdisc *qdisc)
{
	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	_LOGD ("adding or updating a qdisc: %s", nm_platform_qdisc_to_string (qdisc, NULL, 0));
	return klass->qdisc_add (self, flags, qdisc);
}

gboolean
nm_platform_qdisc_sync (NMPlatform *self,
                        int ifindex,
                        GPtrArray *known_qdiscs)
{
	gs_unref_ptrarray GPtrArray *plat_qdiscs = NULL;
	NMPLookup lookup;
	guint i;
	gboolean success = TRUE;
	gs_unref_hashtable GHashTable *known_qdiscs_idx = NULL;

	nm_assert (NM_IS_PLATFORM (self));
	nm_assert (ifindex > 0);

	known_qdiscs_idx = g_hash_table_new ((GHashFunc) nmp_object_id_hash,
	                                     (GEqualFunc) nmp_object_id_equal);

	if (known_qdiscs) {
		for (i = 0; i < known_qdiscs->len; i++) {
			const NMPObject *q = g_ptr_array_index (known_qdiscs, i);

			g_hash_table_insert (known_qdiscs_idx, (gpointer) q, (gpointer) q);
		}
	}

	plat_qdiscs = nm_platform_lookup_clone (self,
	                                        nmp_lookup_init_object (&lookup,
	                                                                NMP_OBJECT_TYPE_QDISC,
	                                                                ifindex),
	                                        NULL, NULL);

	if (plat_qdiscs) {
		for (i = 0; i < plat_qdiscs->len; i++) {
			const NMPObject *q = g_ptr_array_index (plat_qdiscs, i);

			if (!g_hash_table_lookup (known_qdiscs_idx, q))
				success &= nm_platform_object_delete (self, q);
		}
	}

	if (known_qdiscs) {
		for (i = 0; i < known_qdiscs->len; i++) {
			const NMPObject *q = g_ptr_array_index (known_qdiscs, i);

			success &= (nm_platform_qdisc_add (self, NMP_NLM_FLAG_ADD,
			                                   NMP_OBJECT_CAST_QDISC (q)) == NM_PLATFORM_ERROR_SUCCESS);
		}
	}

	return success;
}

/*****************************************************************************/

NMPlatformError
nm_platform_tfilter_add (NMPlatform *self,
                         NMPNlmFlags flags,
                         const NMPlatformTfilter *tfilter)
{
	_CHECK_SELF (self, klass, NM_PLATFORM_ERROR_BUG);

	_LOGD ("adding or updating a tfilter: %s", nm_platform_tfilter_to_string (tfilter, NULL, 0));
	return klass->tfilter_add (self, flags, tfilter);
}

gboolean
nm_platform_tfilter_sync (NMPlatform *self,
                          int ifindex,
                          GPtrArray *known_tfilters)
{
	gs_unref_ptrarray GPtrArray *plat_tfilters = NULL;
	NMPLookup lookup;
	guint i;
	gboolean success = TRUE;
	gs_unref_hashtable GHashTable *known_tfilters_idx = NULL;

	nm_assert (NM_IS_PLATFORM (self));
	nm_assert (ifindex > 0);

	known_tfilters_idx = g_hash_table_new ((GHashFunc) nmp_object_id_hash,
	                                       (GEqualFunc) nmp_object_id_equal);

	if (known_tfilters) {
		for (i = 0; i < known_tfilters->len; i++) {
			const NMPObject *q = g_ptr_array_index (known_tfilters, i);

			g_hash_table_insert (known_tfilters_idx, (gpointer) q, (gpointer) q);
		}
	}

	plat_tfilters = nm_platform_lookup_clone (self,
	                                          nmp_lookup_init_object (&lookup,
	                                                                  NMP_OBJECT_TYPE_TFILTER,
	                                                                  ifindex),
	                                          NULL, NULL);

	if (plat_tfilters) {
		for (i = 0; i < plat_tfilters->len; i++) {
			const NMPObject *q = g_ptr_array_index (plat_tfilters, i);

			if (!g_hash_table_lookup (known_tfilters_idx, q))
				success &= nm_platform_object_delete (self, q);
		}
	}

	if (known_tfilters) {
		for (i = 0; i < known_tfilters->len; i++) {
			const NMPObject *q = g_ptr_array_index (known_tfilters, i);

			success &= (nm_platform_tfilter_add (self, NMP_NLM_FLAG_ADD,
			                                     NMP_OBJECT_CAST_TFILTER (q)) == NM_PLATFORM_ERROR_SUCCESS);
		}
	}

	return success;
}

/*****************************************************************************/

const char *
nm_platform_vlan_qos_mapping_to_string (const char *name,
                                        const NMVlanQosMapping *map,
                                        gsize n_map,
                                        char *buf,
                                        gsize len)
{
	gsize i;
	char *b;

	nm_utils_to_string_buffer_init (&buf, &len);

	if (!n_map) {
		nm_utils_strbuf_append_str (&buf, &len, "");
		return buf;
	}

	if (!map)
		g_return_val_if_reached ("");

	b = buf;

	if (name) {
		nm_utils_strbuf_append_str (&b, &len, name);
		nm_utils_strbuf_append_str (&b, &len, " {");
	} else
		nm_utils_strbuf_append_c (&b, &len, '{');

	for (i = 0; i < n_map; i++)
		nm_utils_strbuf_append (&b, &len, " %u:%u", map[i].from, map[i].to);
	nm_utils_strbuf_append_str (&b, &len, " }");
	return buf;
}

static const char *
_lifetime_to_string (guint32 timestamp, guint32 lifetime, gint32 now, char *buf, size_t buf_size)
{
	if (lifetime == NM_PLATFORM_LIFETIME_PERMANENT)
		return "forever";

	g_snprintf (buf, buf_size, "%usec",
	            nm_utils_lifetime_rebase_relative_time_on_now (timestamp, lifetime, now));
	return buf;
}

static const char *
_lifetime_summary_to_string (gint32 now, guint32 timestamp, guint32 preferred, guint32 lifetime, char *buf, size_t buf_size)
{
	g_snprintf (buf, buf_size, " lifetime %d-%u[%u,%u]",
	            (signed) now, (unsigned) timestamp, (unsigned) preferred, (unsigned) lifetime);
	return buf;
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
	char str_inet6_token[NM_UTILS_INET_ADDRSTRLEN];
	const char *str_link_type;

	if (!nm_utils_to_string_buffer_init_null (link, &buf, &len))
		return buf;

	str_flags = g_string_new (NULL);
	if (NM_FLAGS_HAS (link->n_ifi_flags, IFF_NOARP))
		g_string_append (str_flags, "NOARP,");
	if (NM_FLAGS_HAS (link->n_ifi_flags, IFF_UP))
		g_string_append (str_flags, "UP");
	else
		g_string_append (str_flags, "DOWN");
	if (link->connected)
		g_string_append (str_flags, ",LOWER_UP");

	if (link->n_ifi_flags) {
		char str_flags_buf[64];

		nm_platform_link_flags2str (link->n_ifi_flags, str_flags_buf, sizeof (str_flags_buf));
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

	if (link->addr.len)
		str_addr = nm_utils_hwaddr_ntoa (link->addr.data, MIN (link->addr.len, sizeof (link->addr.data)));

	str_link_type = nm_link_type_to_string (link->type);

	g_snprintf (buf, len,
	            "%d: " /* ifindex */
	            "%s" /* name */
	            "%s" /* parent */
	            " <%s>" /* flags */
	            " mtu %d"
	            "%s" /* master */
	            " arp %u" /* arptype */
	            " %s" /* link->type */
	            "%s%s" /* kind */
	            "%s" /* is-in-udev */
	            "%s%s" /* addr-gen-mode */
	            "%s%s" /* addr */
	            "%s%s" /* inet6_token */
	            "%s%s" /* driver */
	            " rx:%"G_GUINT64_FORMAT",%"G_GUINT64_FORMAT
	            " tx:%"G_GUINT64_FORMAT",%"G_GUINT64_FORMAT
	            ,
	            link->ifindex,
	            link->name,
	            parent,
	            str_flags->str,
	            link->mtu, master,
	            link->arptype,
	            str_link_type ?: "???",
	            link->kind ? (g_strcmp0 (str_link_type, link->kind) ? "/" : "*") : "?",
	            link->kind && g_strcmp0 (str_link_type, link->kind) ? link->kind : "",
	            link->initialized ? " init" : " not-init",
	            link->inet6_addr_gen_mode_inv ? " addrgenmode " : "",
	            link->inet6_addr_gen_mode_inv ? nm_platform_link_inet6_addrgenmode2str (_nm_platform_uint8_inv (link->inet6_addr_gen_mode_inv), str_addrmode, sizeof (str_addrmode)) : "",
	            str_addr ? " addr " : "",
	            str_addr ?: "",
	            link->inet6_token.id ? " inet6token " : "",
	            link->inet6_token.id ? nm_utils_inet6_interface_identifier_to_token (link->inet6_token, str_inet6_token) : "",
	            link->driver ? " driver " : "",
	            link->driver ?: "",
	            link->rx_packets, link->rx_bytes,
	            link->tx_packets, link->tx_bytes);
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

	if (!nm_utils_to_string_buffer_init_null (lnk, &buf, &len))
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

	if (!nm_utils_to_string_buffer_init_null (lnk, &buf, &len))
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
nm_platform_lnk_ip6tnl_to_string (const NMPlatformLnkIp6Tnl *lnk, char *buf, gsize len)
{
	char str_local[30];
	char str_local1[NM_UTILS_INET_ADDRSTRLEN];
	char str_remote[30];
	char str_remote1[NM_UTILS_INET_ADDRSTRLEN];
	char str_ttl[30];
	char str_tclass[30];
	char str_flow[30];
	char str_encap[30];
	char str_proto[30];
	char str_parent_ifindex[30];

	if (!nm_utils_to_string_buffer_init_null (lnk, &buf, &len))
		return buf;

	g_snprintf (buf, len,
	            "ip6tnl"
	            "%s" /* remote */
	            "%s" /* local */
	            "%s" /* parent_ifindex */
	            "%s" /* ttl */
	            "%s" /* tclass */
	            "%s" /* encap limit */
	            "%s" /* flow label */
	            "%s" /* proto */
	            " flags 0x%x"
	            "",
	            nm_sprintf_buf (str_remote, " remote %s", nm_utils_inet6_ntop (&lnk->remote, str_remote1)),
	            nm_sprintf_buf (str_local, " local %s", nm_utils_inet6_ntop (&lnk->local, str_local1)),
	            lnk->parent_ifindex ? nm_sprintf_buf (str_parent_ifindex, " dev %d", lnk->parent_ifindex) : "",
	            lnk->ttl ? nm_sprintf_buf (str_ttl, " ttl %u", lnk->ttl) : " ttl inherit",
	            lnk->tclass == 1 ? " tclass inherit" : nm_sprintf_buf (str_tclass, " tclass 0x%x", lnk->tclass),
	            nm_sprintf_buf (str_encap, " encap-limit %u", lnk->encap_limit),
	            nm_sprintf_buf (str_flow, " flow-label 0x05%x", lnk->flow_label),
	            nm_sprintf_buf (str_proto, " proto %u", lnk->proto),
	            (guint) lnk->flags);
	return buf;
}

const char *
nm_platform_lnk_ipip_to_string (const NMPlatformLnkIpIp *lnk, char *buf, gsize len)
{
	char str_local[30];
	char str_local1[NM_UTILS_INET_ADDRSTRLEN];
	char str_remote[30];
	char str_remote1[NM_UTILS_INET_ADDRSTRLEN];
	char str_ttl[30];
	char str_tos[30];
	char str_parent_ifindex[30];

	if (!nm_utils_to_string_buffer_init_null (lnk, &buf, &len))
		return buf;

	g_snprintf (buf, len,
	            "ipip"
	            "%s" /* remote */
	            "%s" /* local */
	            "%s" /* parent_ifindex */
	            "%s" /* ttl */
	            "%s" /* tos */
	            "%s" /* path_mtu_discovery */
	            "",
	            lnk->remote ? nm_sprintf_buf (str_remote, " remote %s", nm_utils_inet4_ntop (lnk->remote, str_remote1)) : "",
	            lnk->local ? nm_sprintf_buf (str_local, " local %s", nm_utils_inet4_ntop (lnk->local, str_local1)) : "",
	            lnk->parent_ifindex ? nm_sprintf_buf (str_parent_ifindex, " dev %d", lnk->parent_ifindex) : "",
	            lnk->ttl ? nm_sprintf_buf (str_ttl, " ttl %u", lnk->ttl) : " ttl inherit",
	            lnk->tos ? (lnk->tos == 1 ? " tos inherit" : nm_sprintf_buf (str_tos, " tos 0x%x", lnk->tos)) : "",
	            lnk->path_mtu_discovery ? "" : " nopmtudisc");
	return buf;
}

const char *
nm_platform_lnk_macsec_to_string (const NMPlatformLnkMacsec *lnk, char *buf, gsize len)
{
	if (!nm_utils_to_string_buffer_init_null (lnk, &buf, &len))
		return buf;

	g_snprintf (buf, len,
	            "macsec "
	            "sci %016llx "
	            "protect %s "
	            "cipher %016llx "
	            "icvlen %u "
	            "encodingsa %u "
	            "validate %u "
	            "encrypt %s "
	            "send_sci %s "
	            "end_station %s "
	            "scb %s "
	            "replay %s",
	            (unsigned long long) lnk->sci,
	            lnk->protect ? "on" : "off",
	            (unsigned long long) lnk->cipher_suite,
	            lnk->icv_length,
	            lnk->encoding_sa,
	            lnk->validation,
	            lnk->encrypt ? "on" : "off",
	            lnk->include_sci ? "on" : "off",
	            lnk->es ? "on" : "off",
	            lnk->scb ? "on" : "off",
	            lnk->replay_protect ? "on" : "off");
	return buf;
}

const char *
nm_platform_lnk_macvlan_to_string (const NMPlatformLnkMacvlan *lnk, char *buf, gsize len)
{
	if (!nm_utils_to_string_buffer_init_null (lnk, &buf, &len))
		return buf;

	g_snprintf (buf, len,
	            "macvlan mode %u %s",
	            lnk->mode,
	            lnk->no_promisc ? "not-promisc" : "promisc");
	return buf;
}

const char *
nm_platform_lnk_sit_to_string (const NMPlatformLnkSit *lnk, char *buf, gsize len)
{
	char str_local[30];
	char str_local1[NM_UTILS_INET_ADDRSTRLEN];
	char str_remote[30];
	char str_remote1[NM_UTILS_INET_ADDRSTRLEN];
	char str_ttl[30];
	char str_tos[30];
	char str_flags[30];
	char str_proto[30];
	char str_parent_ifindex[30];

	if (!nm_utils_to_string_buffer_init_null (lnk, &buf, &len))
		return buf;

	g_snprintf (buf, len,
	            "sit"
	            "%s" /* remote */
	            "%s" /* local */
	            "%s" /* parent_ifindex */
	            "%s" /* ttl */
	            "%s" /* tos */
	            "%s" /* path_mtu_discovery */
	            "%s" /* flags */
	            "%s" /* proto */
	            "",
	            lnk->remote ? nm_sprintf_buf (str_remote, " remote %s", nm_utils_inet4_ntop (lnk->remote, str_remote1)) : "",
	            lnk->local ? nm_sprintf_buf (str_local, " local %s", nm_utils_inet4_ntop (lnk->local, str_local1)) : "",
	            lnk->parent_ifindex ? nm_sprintf_buf (str_parent_ifindex, " dev %d", lnk->parent_ifindex) : "",
	            lnk->ttl ? nm_sprintf_buf (str_ttl, " ttl %u", lnk->ttl) : " ttl inherit",
	            lnk->tos ? (lnk->tos == 1 ? " tos inherit" : nm_sprintf_buf (str_tos, " tos 0x%x", lnk->tos)) : "",
	            lnk->path_mtu_discovery ? "" : " nopmtudisc",
	            lnk->flags ? nm_sprintf_buf (str_flags, " flags 0x%x", lnk->flags) : "",
	            lnk->proto ? nm_sprintf_buf (str_proto, " proto 0x%x", lnk->proto) : "");
	return buf;
}

const char *
nm_platform_lnk_tun_to_string (const NMPlatformLnkTun *lnk, char *buf, gsize len)
{
	char str_owner[50];
	char str_group[50];
	char str_type[50];
	const char *type;

	if (!nm_utils_to_string_buffer_init_null (lnk, &buf, &len))
		return buf;

	if (lnk->type == IFF_TUN)
		type = "tun";
	else if (lnk->type == IFF_TAP)
		type = "tap";
	else
		type = nm_sprintf_buf (str_type, "tun type %u", (guint) lnk->type);

	g_snprintf (buf, len,
	            "%s" /* type */
	            "%s" /* pi */
	            "%s" /* vnet_hdr */
	            "%s" /* multi_queue */
	            "%s" /* persist */
	            "%s" /* owner */
	            "%s" /* group */
	            "",
	            type,
	            lnk->pi ? " pi" : "",
	            lnk->vnet_hdr ? " vnet_hdr" : "",
	            lnk->multi_queue ? " multi_queue" : "",
	            lnk->persist ? " persist" : "",
	            lnk->owner_valid ? nm_sprintf_buf (str_owner, " owner %u", (guint) lnk->owner) : "",
	            lnk->group_valid ? nm_sprintf_buf (str_group, " group %u", (guint) lnk->group) : "");
	return buf;
}

const char *
nm_platform_lnk_vlan_to_string (const NMPlatformLnkVlan *lnk, char *buf, gsize len)
{
	char *b;

	if (!nm_utils_to_string_buffer_init_null (lnk, &buf, &len))
		return buf;

	b = buf;

	nm_utils_strbuf_append (&b, &len, "vlan %u", lnk->id);
	if (lnk->flags)
		nm_utils_strbuf_append (&b, &len, " flags 0x%x", lnk->flags);
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

	if (!nm_utils_to_string_buffer_init_null (lnk, &buf, &len))
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
	char s_flags[TO_STRING_IFA_FLAGS_BUF_SIZE];
	char s_address[INET_ADDRSTRLEN];
	char s_peer[INET_ADDRSTRLEN];
	char str_dev[TO_STRING_DEV_BUF_SIZE];
	char str_label[32];
	char str_lft[30], str_pref[30], str_time[50], s_source[50];
	char *str_peer = NULL;
	const char *str_lft_p, *str_pref_p, *str_time_p;
	gint32 now = nm_utils_get_monotonic_timestamp_s ();

	if (!nm_utils_to_string_buffer_init_null (address, &buf, &len))
		return buf;

	inet_ntop (AF_INET, &address->address, s_address, sizeof (s_address));

	if (address->peer_address != address->address) {
		inet_ntop (AF_INET, &address->peer_address, s_peer, sizeof (s_peer));
		str_peer = g_strconcat (" ptp ", s_peer, NULL);
	}

	_to_string_dev (NULL, address->ifindex, str_dev, sizeof (str_dev));

	if (*address->label)
		g_snprintf (str_label, sizeof (str_label), " label %s", address->label);
	else
		str_label[0] = 0;

	str_lft_p = _lifetime_to_string (address->timestamp,
	                                 address->lifetime ?: NM_PLATFORM_LIFETIME_PERMANENT,
	                                 now, str_lft, sizeof (str_lft)),
	str_pref_p = (address->lifetime == address->preferred)
	             ? str_lft_p
	             : ( _lifetime_to_string (address->timestamp,
	                                      address->lifetime ? MIN (address->preferred, address->lifetime) : NM_PLATFORM_LIFETIME_PERMANENT,
	                                      now, str_pref, sizeof (str_pref)) );
	str_time_p = _lifetime_summary_to_string (now, address->timestamp, address->preferred, address->lifetime, str_time, sizeof (str_time));

	g_snprintf (buf, len,
	            "%s/%d lft %s pref %s%s%s%s%s%s src %s",
	            s_address, address->plen, str_lft_p, str_pref_p, str_time_p,
	            str_peer ?: "",
	            str_dev,
	            _to_string_ifa_flags (address->n_ifa_flags, s_flags, sizeof (s_flags)),
	            str_label,
	            nmp_utils_ip_config_source_to_string (address->addr_source, s_source, sizeof (s_source)));
	g_free (str_peer);
	return buf;
}

NM_UTILS_FLAGS2STR_DEFINE (nm_platform_link_flags2str, unsigned,
	NM_UTILS_FLAGS2STR (IFF_LOOPBACK, "loopback"),
	NM_UTILS_FLAGS2STR (IFF_BROADCAST, "broadcast"),
	NM_UTILS_FLAGS2STR (IFF_POINTOPOINT, "pointopoint"),
	NM_UTILS_FLAGS2STR (IFF_MULTICAST, "multicast"),
	NM_UTILS_FLAGS2STR (IFF_NOARP, "noarp"),
	NM_UTILS_FLAGS2STR (IFF_ALLMULTI, "allmulti"),
	NM_UTILS_FLAGS2STR (IFF_PROMISC, "promisc"),
	NM_UTILS_FLAGS2STR (IFF_MASTER, "master"),
	NM_UTILS_FLAGS2STR (IFF_SLAVE, "slave"),
	NM_UTILS_FLAGS2STR (IFF_DEBUG, "debug"),
	NM_UTILS_FLAGS2STR (IFF_DYNAMIC, "dynamic"),
	NM_UTILS_FLAGS2STR (IFF_AUTOMEDIA, "automedia"),
	NM_UTILS_FLAGS2STR (IFF_PORTSEL, "portsel"),
	NM_UTILS_FLAGS2STR (IFF_NOTRAILERS, "notrailers"),
	NM_UTILS_FLAGS2STR (IFF_UP, "up"),
	NM_UTILS_FLAGS2STR (IFF_RUNNING, "running"),
	NM_UTILS_FLAGS2STR (IFF_LOWER_UP, "lowerup"),
	NM_UTILS_FLAGS2STR (IFF_DORMANT, "dormant"),
	NM_UTILS_FLAGS2STR (IFF_ECHO, "echo"),
);

NM_UTILS_ENUM2STR_DEFINE (nm_platform_link_inet6_addrgenmode2str, guint8,
	NM_UTILS_ENUM2STR (NM_IN6_ADDR_GEN_MODE_NONE, "none"),
	NM_UTILS_ENUM2STR (NM_IN6_ADDR_GEN_MODE_EUI64, "eui64"),
	NM_UTILS_ENUM2STR (NM_IN6_ADDR_GEN_MODE_STABLE_PRIVACY, "stable-privacy"),
	NM_UTILS_ENUM2STR (NM_IN6_ADDR_GEN_MODE_RANDOM, "random"),
);

NM_UTILS_FLAGS2STR_DEFINE (nm_platform_addr_flags2str, unsigned,
	NM_UTILS_FLAGS2STR (IFA_F_SECONDARY, "secondary"),
	NM_UTILS_FLAGS2STR (IFA_F_NODAD, "nodad"),
	NM_UTILS_FLAGS2STR (IFA_F_OPTIMISTIC, "optimistic"),
	NM_UTILS_FLAGS2STR (IFA_F_HOMEADDRESS, "homeaddress"),
	NM_UTILS_FLAGS2STR (IFA_F_DEPRECATED, "deprecated"),
	NM_UTILS_FLAGS2STR (IFA_F_PERMANENT, "permanent"),
	NM_UTILS_FLAGS2STR (IFA_F_MANAGETEMPADDR, "mngtmpaddr"),
	NM_UTILS_FLAGS2STR (IFA_F_NOPREFIXROUTE, "noprefixroute"),
	NM_UTILS_FLAGS2STR (IFA_F_TENTATIVE, "tentative"),
);

NM_UTILS_ENUM2STR_DEFINE (nm_platform_route_scope2str, int,
	NM_UTILS_ENUM2STR (RT_SCOPE_NOWHERE, "nowhere"),
	NM_UTILS_ENUM2STR (RT_SCOPE_HOST, "host"),
	NM_UTILS_ENUM2STR (RT_SCOPE_LINK, "link"),
	NM_UTILS_ENUM2STR (RT_SCOPE_SITE, "site"),
	NM_UTILS_ENUM2STR (RT_SCOPE_UNIVERSE, "global"),
);

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
	char s_flags[TO_STRING_IFA_FLAGS_BUF_SIZE];
	char s_address[INET6_ADDRSTRLEN];
	char s_peer[INET6_ADDRSTRLEN];
	char str_lft[30], str_pref[30], str_time[50], s_source[50];
	char str_dev[TO_STRING_DEV_BUF_SIZE];
	char *str_peer = NULL;
	const char *str_lft_p, *str_pref_p, *str_time_p;
	gint32 now = nm_utils_get_monotonic_timestamp_s ();

	if (!nm_utils_to_string_buffer_init_null (address, &buf, &len))
		return buf;

	inet_ntop (AF_INET6, &address->address, s_address, sizeof (s_address));

	if (!IN6_IS_ADDR_UNSPECIFIED (&address->peer_address)) {
		inet_ntop (AF_INET6, &address->peer_address, s_peer, sizeof (s_peer));
		str_peer = g_strconcat (" ptp ", s_peer, NULL);
	}

	_to_string_dev (NULL, address->ifindex, str_dev, sizeof (str_dev));

	str_lft_p = _lifetime_to_string (address->timestamp,
	                                 address->lifetime ?: NM_PLATFORM_LIFETIME_PERMANENT,
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
	            str_peer ?: "",
	            str_dev,
	            _to_string_ifa_flags (address->n_ifa_flags, s_flags, sizeof (s_flags)),
	            nmp_utils_ip_config_source_to_string (address->addr_source, s_source, sizeof (s_source)));
	g_free (str_peer);
	return buf;
}

NM_UTILS_FLAGS2STR_DEFINE_STATIC (_rtm_flags_to_string, unsigned,
	NM_UTILS_FLAGS2STR (RTNH_F_DEAD,                   "dead"),
	NM_UTILS_FLAGS2STR (RTNH_F_PERVASIVE,              "pervasive"),
	NM_UTILS_FLAGS2STR (RTNH_F_ONLINK,                 "onlink"),
	NM_UTILS_FLAGS2STR (8  /*RTNH_F_OFFLOAD*/,         "offload"),
	NM_UTILS_FLAGS2STR (16 /*RTNH_F_LINKDOWN*/,        "linkdown"),
	NM_UTILS_FLAGS2STR (32 /*RTNH_F_UNRESOLVED*/,      "unresolved"),

	NM_UTILS_FLAGS2STR (RTM_F_NOTIFY,                  "notify"),
	NM_UTILS_FLAGS2STR (RTM_F_CLONED,                  "cloned"),
	NM_UTILS_FLAGS2STR (RTM_F_EQUALIZE,                "equalize"),
	NM_UTILS_FLAGS2STR (RTM_F_PREFIX,                  "prefix"),
	NM_UTILS_FLAGS2STR (0x1000 /*RTM_F_LOOKUP_TABLE*/, "lookup-table"),
	NM_UTILS_FLAGS2STR (0x2000 /*RTM_F_FIB_MATCH*/,    "fib-match"),
);

#define _RTM_FLAGS_TO_STRING_MAXLEN 200

static const char *
_rtm_flags_to_string_full (char *buf, gsize buf_size, unsigned rtm_flags)
{
	const char *buf0 = buf;

	nm_assert (buf_size >= _RTM_FLAGS_TO_STRING_MAXLEN);

	if (!rtm_flags)
		return "";

	nm_utils_strbuf_append_str (&buf, &buf_size, " rtm_flags ");
	_rtm_flags_to_string (rtm_flags, buf, buf_size);
	nm_assert (strlen (buf) < buf_size);
	return buf0;
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
	char str_table[30];
	char str_scope[30], s_source[50];
	char str_tos[32], str_window[32], str_cwnd[32], str_initcwnd[32], str_initrwnd[32], str_mtu[32];
	char str_rtm_flags[_RTM_FLAGS_TO_STRING_MAXLEN];

	if (!nm_utils_to_string_buffer_init_null (route, &buf, &len))
		return buf;

	inet_ntop (AF_INET, &route->network, s_network, sizeof(s_network));
	inet_ntop (AF_INET, &route->gateway, s_gateway, sizeof(s_gateway));

	_to_string_dev (NULL, route->ifindex, str_dev, sizeof (str_dev));

	g_snprintf (buf, len,
	            "%s" /* table */
	            "%s/%d"
	            " via %s"
	            "%s"
	            " metric %"G_GUINT32_FORMAT
	            " mss %"G_GUINT32_FORMAT
	            " rt-src %s" /* protocol */
	            "%s" /* rtm_flags */
	            "%s%s" /* scope */
	            "%s%s" /* pref-src */
	            "%s" /* tos */
	            "%s" /* window */
	            "%s" /* cwnd */
	            "%s" /* initcwnd */
	            "%s" /* initrwnd */
	            "%s" /* mtu */
	            "",
	            route->table_coerced ? nm_sprintf_buf (str_table, "table %u ", nm_platform_route_table_uncoerce (route->table_coerced, FALSE)) : "",
	            s_network,
	            route->plen,
	            s_gateway,
	            str_dev,
	            route->metric,
	            route->mss,
	            nmp_utils_ip_config_source_to_string (route->rt_source, s_source, sizeof (s_source)),
	            _rtm_flags_to_string_full (str_rtm_flags, sizeof (str_rtm_flags), route->r_rtm_flags),
	            route->scope_inv ? " scope " : "",
	            route->scope_inv ? (nm_platform_route_scope2str (nm_platform_route_scope_inv (route->scope_inv), str_scope, sizeof (str_scope))) : "",
	            route->pref_src ? " pref-src " : "",
	            route->pref_src ? inet_ntop (AF_INET, &route->pref_src, s_pref_src, sizeof(s_pref_src)) : "",
	            route->tos ? nm_sprintf_buf (str_tos, " tos 0x%x", (unsigned) route->tos) : "",
	            route->window   || route->lock_window   ? nm_sprintf_buf (str_window,   " window %s%"G_GUINT32_FORMAT,   route->lock_window   ? "lock " : "", route->window)   : "",
	            route->cwnd     || route->lock_cwnd     ? nm_sprintf_buf (str_cwnd,     " cwnd %s%"G_GUINT32_FORMAT,     route->lock_cwnd     ? "lock " : "", route->cwnd)     : "",
	            route->initcwnd || route->lock_initcwnd ? nm_sprintf_buf (str_initcwnd, " initcwnd %s%"G_GUINT32_FORMAT, route->lock_initcwnd ? "lock " : "", route->initcwnd) : "",
	            route->initrwnd || route->lock_initrwnd ? nm_sprintf_buf (str_initrwnd, " initrwnd %s%"G_GUINT32_FORMAT, route->lock_initrwnd ? "lock " : "", route->initrwnd) : "",
	            route->mtu      || route->lock_mtu      ? nm_sprintf_buf (str_mtu,      " mtu %s%"G_GUINT32_FORMAT,      route->lock_mtu      ? "lock " : "", route->mtu)      : "");
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
	char s_network[INET6_ADDRSTRLEN], s_gateway[INET6_ADDRSTRLEN], s_pref_src[INET6_ADDRSTRLEN];
	char s_src_all[INET6_ADDRSTRLEN + 40], s_src[INET6_ADDRSTRLEN];
	char str_table[30];
	char str_pref[40];
	char str_pref2[30];
	char str_dev[TO_STRING_DEV_BUF_SIZE], s_source[50];
	char str_window[32], str_cwnd[32], str_initcwnd[32], str_initrwnd[32], str_mtu[32];
	char str_rtm_flags[_RTM_FLAGS_TO_STRING_MAXLEN];

	if (!nm_utils_to_string_buffer_init_null (route, &buf, &len))
		return buf;

	inet_ntop (AF_INET6, &route->network, s_network, sizeof (s_network));
	inet_ntop (AF_INET6, &route->gateway, s_gateway, sizeof (s_gateway));

	if (IN6_IS_ADDR_UNSPECIFIED (&route->pref_src))
		s_pref_src[0] = 0;
	else
		inet_ntop (AF_INET6, &route->pref_src, s_pref_src, sizeof (s_pref_src));

	_to_string_dev (NULL, route->ifindex, str_dev, sizeof (str_dev));

	g_snprintf (buf, len,
	            "%s" /* table */
	            "%s/%d"
	            " via %s"
	            "%s"
	            " metric %"G_GUINT32_FORMAT
	            " mss %"G_GUINT32_FORMAT
	            " rt-src %s" /* protocol */
	            "%s" /* source */
	            "%s" /* rtm_flags */
	            "%s%s" /* pref-src */
	            "%s" /* window */
	            "%s" /* cwnd */
	            "%s" /* initcwnd */
	            "%s" /* initrwnd */
	            "%s" /* mtu */
	            "%s" /* pref */
	            "",
	            route->table_coerced ? nm_sprintf_buf (str_table, "table %u ", nm_platform_route_table_uncoerce (route->table_coerced, FALSE)) : "",
	            s_network,
	            route->plen,
	            s_gateway,
	            str_dev,
	            route->metric,
	            route->mss,
	            nmp_utils_ip_config_source_to_string (route->rt_source, s_source, sizeof (s_source)),
	            route->src_plen || !IN6_IS_ADDR_UNSPECIFIED (&route->src)
	              ? nm_sprintf_buf (s_src_all, " src %s/%u", nm_utils_inet6_ntop (&route->src, s_src), (unsigned) route->src_plen)
	              : "",
	            _rtm_flags_to_string_full (str_rtm_flags, sizeof (str_rtm_flags), route->r_rtm_flags),
	            s_pref_src[0] ? " pref-src " : "",
	            s_pref_src[0] ? s_pref_src : "",
	            route->window   || route->lock_window   ? nm_sprintf_buf (str_window,   " window %s%"G_GUINT32_FORMAT,   route->lock_window   ? "lock " : "", route->window)   : "",
	            route->cwnd     || route->lock_cwnd     ? nm_sprintf_buf (str_cwnd,     " cwnd %s%"G_GUINT32_FORMAT,     route->lock_cwnd     ? "lock " : "", route->cwnd)     : "",
	            route->initcwnd || route->lock_initcwnd ? nm_sprintf_buf (str_initcwnd, " initcwnd %s%"G_GUINT32_FORMAT, route->lock_initcwnd ? "lock " : "", route->initcwnd) : "",
	            route->initrwnd || route->lock_initrwnd ? nm_sprintf_buf (str_initrwnd, " initrwnd %s%"G_GUINT32_FORMAT, route->lock_initrwnd ? "lock " : "", route->initrwnd) : "",
	            route->mtu      || route->lock_mtu      ? nm_sprintf_buf (str_mtu,      " mtu %s%"G_GUINT32_FORMAT,      route->lock_mtu      ? "lock " : "", route->mtu)      : "",
	            route->rt_pref ? nm_sprintf_buf (str_pref, " pref %s", nm_icmpv6_router_pref_to_string (route->rt_pref, str_pref2, sizeof (str_pref2))) : "");

	return buf;
}

const char *
nm_platform_qdisc_to_string (const NMPlatformQdisc *qdisc, char *buf, gsize len)
{
	char str_dev[TO_STRING_DEV_BUF_SIZE];

	if (!nm_utils_to_string_buffer_init_null (qdisc, &buf, &len))
		return buf;

	g_snprintf (buf, len, "%s%s family %d handle %x parent %x info %x",
	            qdisc->kind,
	            _to_string_dev (NULL, qdisc->ifindex, str_dev, sizeof (str_dev)),
	            qdisc->addr_family,
	            qdisc->handle,
	            qdisc->parent,
	            qdisc->info);

	return buf;
}

void
nm_platform_qdisc_hash_update (const NMPlatformQdisc *obj, NMHashState *h)
{
	nm_hash_update_str0 (h, obj->kind);
	nm_hash_update_vals (h,
	                     obj->ifindex,
	                     obj->addr_family,
	                     obj->handle,
	                     obj->parent,
	                     obj->info);
}

int
nm_platform_qdisc_cmp (const NMPlatformQdisc *a, const NMPlatformQdisc *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, ifindex);
	NM_CMP_FIELD (a, b, parent);
	NM_CMP_FIELD_STR_INTERNED (a, b, kind);
	NM_CMP_FIELD (a, b, addr_family);
	NM_CMP_FIELD (a, b, handle);
	NM_CMP_FIELD (a, b, info);

	return 0;
}

const char *
nm_platform_tfilter_to_string (const NMPlatformTfilter *tfilter, char *buf, gsize len)
{
	char str_dev[TO_STRING_DEV_BUF_SIZE];
	char act_buf[300];
	char *p;
	gsize l;

	if (!nm_utils_to_string_buffer_init_null (tfilter, &buf, &len))
		return buf;

	if (tfilter->action.kind) {
		p = act_buf;
		l = sizeof (act_buf);

		nm_utils_strbuf_append (&p, &l, " \"%s\"", tfilter->action.kind);
		if (nm_streq (tfilter->action.kind, NM_PLATFORM_ACTION_KIND_SIMPLE)) {
			gs_free char *t = NULL;

			nm_utils_strbuf_append (&p, &l,
			                        " (\"%s\")",
			                        nm_utils_str_utf8safe_escape (tfilter->action.kind,
			                                                        NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL
			                                                      | NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII,
			                                                      &t));
		}
	} else
		act_buf[0] = '\0';

	g_snprintf (buf, len, "%s%s family %d handle %x parent %x info %x%s",
	            tfilter->kind,
	            _to_string_dev (NULL, tfilter->ifindex, str_dev, sizeof (str_dev)),
	            tfilter->addr_family,
	            tfilter->handle,
	            tfilter->parent,
	            tfilter->info,
	            act_buf);

	return buf;
}

void
nm_platform_tfilter_hash_update (const NMPlatformTfilter *obj, NMHashState *h)
{
	nm_hash_update_str0 (h, obj->kind);
	nm_hash_update_vals (h,
	                     obj->ifindex,
	                     obj->addr_family,
	                     obj->handle,
	                     obj->parent,
	                     obj->info);
	if (obj->action.kind) {
		nm_hash_update_str (h, obj->action.kind);
		if (nm_streq (obj->action.kind, NM_PLATFORM_ACTION_KIND_SIMPLE))
			nm_hash_update_strarr (h, obj->action.simple.sdata);
	}
}

int
nm_platform_tfilter_cmp (const NMPlatformTfilter *a, const NMPlatformTfilter *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, ifindex);
	NM_CMP_FIELD (a, b, parent);
	NM_CMP_FIELD_STR_INTERNED (a, b, kind);
	NM_CMP_FIELD (a, b, addr_family);
	NM_CMP_FIELD (a, b, handle);
	NM_CMP_FIELD (a, b, info);

	NM_CMP_FIELD_STR_INTERNED (a, b, action.kind);
	if (a->action.kind) {
		if (nm_streq (a->action.kind, NM_PLATFORM_ACTION_KIND_SIMPLE))
			NM_CMP_FIELD_STR (a, b, action.simple.sdata);
	}

	return 0;
}

void
nm_platform_link_hash_update (const NMPlatformLink *obj, NMHashState *h)
{
	nm_hash_update_vals (h,
	                     obj->ifindex,
	                     obj->master,
	                     obj->parent,
	                     obj->n_ifi_flags,
	                     obj->mtu,
	                     obj->type,
	                     obj->arptype,
	                     obj->inet6_addr_gen_mode_inv,
	                     obj->inet6_token,
	                     obj->rx_packets,
	                     obj->rx_bytes,
	                     obj->tx_packets,
	                     obj->tx_bytes,
	                     NM_HASH_COMBINE_BOOLS (guint8,
	                                            obj->connected,
	                                            obj->initialized));
	nm_hash_update_strarr (h, obj->name);
	nm_hash_update_str0 (h, obj->kind);
	nm_hash_update_str0 (h, obj->driver);
	/* nm_hash_update_mem() also hashes the length obj->addr.len */
	nm_hash_update_mem (h, obj->addr.data, obj->addr.len);
}

int
nm_platform_link_cmp (const NMPlatformLink *a, const NMPlatformLink *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, ifindex);
	NM_CMP_FIELD (a, b, type);
	NM_CMP_FIELD_STR (a, b, name);
	NM_CMP_FIELD (a, b, master);
	NM_CMP_FIELD (a, b, parent);
	NM_CMP_FIELD (a, b, n_ifi_flags);
	NM_CMP_FIELD_UNSAFE (a, b, connected);
	NM_CMP_FIELD (a, b, mtu);
	NM_CMP_FIELD_BOOL (a, b, initialized);
	NM_CMP_FIELD (a, b, arptype);
	NM_CMP_FIELD (a, b, addr.len);
	NM_CMP_FIELD (a, b, inet6_addr_gen_mode_inv);
	NM_CMP_FIELD_STR_INTERNED (a, b, kind);
	NM_CMP_FIELD_STR_INTERNED (a, b, driver);
	if (a->addr.len)
		NM_CMP_FIELD_MEMCMP_LEN (a, b, addr.data, a->addr.len);
	NM_CMP_FIELD_MEMCMP (a, b, inet6_token);
	NM_CMP_FIELD (a, b, rx_packets);
	NM_CMP_FIELD (a, b, rx_bytes);
	NM_CMP_FIELD (a, b, tx_packets);
	NM_CMP_FIELD (a, b, tx_bytes);
	return 0;
}

void
nm_platform_lnk_gre_hash_update (const NMPlatformLnkGre *obj, NMHashState *h)
{
	nm_hash_update_vals (h,
	                     obj->local,
	                     obj->remote,
	                     obj->parent_ifindex,
	                     obj->input_flags,
	                     obj->output_flags,
	                     obj->input_key,
	                     obj->output_key,
	                     obj->ttl,
	                     obj->tos,
	                     (bool) obj->path_mtu_discovery);
}

int
nm_platform_lnk_gre_cmp (const NMPlatformLnkGre *a, const NMPlatformLnkGre *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, parent_ifindex);
	NM_CMP_FIELD (a, b, input_flags);
	NM_CMP_FIELD (a, b, output_flags);
	NM_CMP_FIELD (a, b, input_key);
	NM_CMP_FIELD (a, b, output_key);
	NM_CMP_FIELD (a, b, local);
	NM_CMP_FIELD (a, b, remote);
	NM_CMP_FIELD (a, b, ttl);
	NM_CMP_FIELD (a, b, tos);
	NM_CMP_FIELD_BOOL (a, b, path_mtu_discovery);
	return 0;
}

void
nm_platform_lnk_infiniband_hash_update (const NMPlatformLnkInfiniband *obj, NMHashState *h)
{
	nm_hash_update_val (h, obj->p_key);
	nm_hash_update_str0 (h, obj->mode);
}

int
nm_platform_lnk_infiniband_cmp (const NMPlatformLnkInfiniband *a, const NMPlatformLnkInfiniband *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, p_key);
	NM_CMP_FIELD_STR_INTERNED (a, b, mode);
	return 0;
}

void
nm_platform_lnk_ip6tnl_hash_update (const NMPlatformLnkIp6Tnl *obj, NMHashState *h)
{
	nm_hash_update_vals (h,
	                     obj->local,
	                     obj->remote,
	                     obj->parent_ifindex,
	                     obj->ttl,
	                     obj->tclass,
	                     obj->encap_limit,
	                     obj->proto,
	                     obj->flow_label,
	                     obj->flags);
}

int
nm_platform_lnk_ip6tnl_cmp (const NMPlatformLnkIp6Tnl *a, const NMPlatformLnkIp6Tnl *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, parent_ifindex);
	NM_CMP_FIELD_MEMCMP (a, b, local);
	NM_CMP_FIELD_MEMCMP (a, b, remote);
	NM_CMP_FIELD (a, b, ttl);
	NM_CMP_FIELD (a, b, tclass);
	NM_CMP_FIELD (a, b, encap_limit);
	NM_CMP_FIELD (a, b, flow_label);
	NM_CMP_FIELD (a, b, proto);
	NM_CMP_FIELD (a, b, flags);
	return 0;
}

void
nm_platform_lnk_ipip_hash_update (const NMPlatformLnkIpIp *obj, NMHashState *h)
{
	nm_hash_update_vals (h,
	                     obj->local,
	                     obj->remote,
	                     obj->parent_ifindex,
	                     obj->ttl,
	                     obj->tos,
	                     (bool) obj->path_mtu_discovery);
}

int
nm_platform_lnk_ipip_cmp (const NMPlatformLnkIpIp *a, const NMPlatformLnkIpIp *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, parent_ifindex);
	NM_CMP_FIELD (a, b, local);
	NM_CMP_FIELD (a, b, remote);
	NM_CMP_FIELD (a, b, ttl);
	NM_CMP_FIELD (a, b, tos);
	NM_CMP_FIELD_BOOL (a, b, path_mtu_discovery);
	return 0;
}

void
nm_platform_lnk_macsec_hash_update (const NMPlatformLnkMacsec *obj, NMHashState *h)
{
	nm_hash_update_vals (h,
	                     obj->parent_ifindex,
	                     obj->sci,
	                     obj->cipher_suite,
	                     obj->window,
	                     obj->icv_length,
	                     obj->encoding_sa,
	                     obj->validation,
	                     NM_HASH_COMBINE_BOOLS (guint8,
	                                            obj->encrypt,
	                                            obj->protect,
	                                            obj->include_sci,
	                                            obj->es,
	                                            obj->scb,
	                                            obj->replay_protect));
}

int
nm_platform_lnk_macsec_cmp (const NMPlatformLnkMacsec *a, const NMPlatformLnkMacsec *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, parent_ifindex);
	NM_CMP_FIELD (a, b, sci);
	NM_CMP_FIELD (a, b, icv_length);
	NM_CMP_FIELD (a, b, cipher_suite);
	NM_CMP_FIELD (a, b, window);
	NM_CMP_FIELD (a, b, encoding_sa);
	NM_CMP_FIELD (a, b, validation);
	NM_CMP_FIELD_UNSAFE (a, b, encrypt);
	NM_CMP_FIELD_UNSAFE (a, b, protect);
	NM_CMP_FIELD_UNSAFE (a, b, include_sci);
	NM_CMP_FIELD_UNSAFE (a, b, es);
	NM_CMP_FIELD_UNSAFE (a, b, scb);
	NM_CMP_FIELD_UNSAFE (a, b, replay_protect);
	return 0;
}

void
nm_platform_lnk_macvlan_hash_update (const NMPlatformLnkMacvlan *obj, NMHashState *h )
{
	nm_hash_update_vals (h,
	                     obj->mode,
	                     NM_HASH_COMBINE_BOOLS (guint8,
	                                            obj->no_promisc,
	                                            obj->tap));
}

int
nm_platform_lnk_macvlan_cmp (const NMPlatformLnkMacvlan *a, const NMPlatformLnkMacvlan *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, mode);
	NM_CMP_FIELD_UNSAFE (a, b, no_promisc);
	NM_CMP_FIELD_UNSAFE (a, b, tap);
	return 0;
}

void
nm_platform_lnk_sit_hash_update (const NMPlatformLnkSit *obj, NMHashState *h)
{
	nm_hash_update_vals (h,
	                     obj->local,
	                     obj->remote,
	                     obj->parent_ifindex,
	                     obj->flags,
	                     obj->ttl,
	                     obj->tos,
	                     obj->proto,
	                     (bool) obj->path_mtu_discovery);
}

int
nm_platform_lnk_sit_cmp (const NMPlatformLnkSit *a, const NMPlatformLnkSit *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, parent_ifindex);
	NM_CMP_FIELD (a, b, local);
	NM_CMP_FIELD (a, b, remote);
	NM_CMP_FIELD (a, b, ttl);
	NM_CMP_FIELD (a, b, tos);
	NM_CMP_FIELD_BOOL (a, b, path_mtu_discovery);
	NM_CMP_FIELD (a, b, flags);
	NM_CMP_FIELD (a, b, proto);
	return 0;
}

void
nm_platform_lnk_tun_hash_update (const NMPlatformLnkTun *obj, NMHashState *h)
{
	nm_hash_update_vals (h,
	                     obj->type,
	                     obj->owner,
	                     obj->group,
	                     NM_HASH_COMBINE_BOOLS (guint8,
	                                            obj->owner_valid,
	                                            obj->group_valid,
	                                            obj->pi,
	                                            obj->vnet_hdr,
	                                            obj->multi_queue,
	                                            obj->persist));
}

int
nm_platform_lnk_tun_cmp (const NMPlatformLnkTun *a, const NMPlatformLnkTun *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, type);
	NM_CMP_FIELD (a, b, owner);
	NM_CMP_FIELD (a, b, group);
	NM_CMP_FIELD_BOOL (a, b, owner_valid);
	NM_CMP_FIELD_BOOL (a, b, group_valid);
	NM_CMP_FIELD_BOOL (a, b, pi);
	NM_CMP_FIELD_BOOL (a, b, vnet_hdr);
	NM_CMP_FIELD_BOOL (a, b, multi_queue);
	NM_CMP_FIELD_BOOL (a, b, persist);
	return 0;
}

void
nm_platform_lnk_vlan_hash_update (const NMPlatformLnkVlan *obj, NMHashState *h)
{
	nm_hash_update_vals (h,
	                     obj->id,
	                     obj->flags);
}

int
nm_platform_lnk_vlan_cmp (const NMPlatformLnkVlan *a, const NMPlatformLnkVlan *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, id);
	NM_CMP_FIELD (a, b, flags);
	return 0;
}

void
nm_platform_lnk_vxlan_hash_update (const NMPlatformLnkVxlan *obj, NMHashState *h)
{
	nm_hash_update_vals (h,
	                     obj->group6,
	                     obj->local6,
	                     obj->group,
	                     obj->local,
	                     obj->parent_ifindex,
	                     obj->id,
	                     obj->ageing,
	                     obj->limit,
	                     obj->dst_port,
	                     obj->src_port_min,
	                     obj->src_port_max,
	                     obj->tos,
	                     obj->ttl,
	                     NM_HASH_COMBINE_BOOLS (guint8,
	                                            obj->learning,
	                                            obj->proxy,
	                                            obj->rsc,
	                                            obj->l2miss,
	                                            obj->l3miss));
}

int
nm_platform_lnk_vxlan_cmp (const NMPlatformLnkVxlan *a, const NMPlatformLnkVxlan *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, parent_ifindex);
	NM_CMP_FIELD (a, b, id);
	NM_CMP_FIELD (a, b, group);
	NM_CMP_FIELD (a, b, local);
	NM_CMP_FIELD_MEMCMP (a, b, group6);
	NM_CMP_FIELD_MEMCMP (a, b, local6);
	NM_CMP_FIELD (a, b, tos);
	NM_CMP_FIELD (a, b, ttl);
	NM_CMP_FIELD_BOOL (a, b, learning);
	NM_CMP_FIELD (a, b, ageing);
	NM_CMP_FIELD (a, b, limit);
	NM_CMP_FIELD (a, b, dst_port);
	NM_CMP_FIELD (a, b, src_port_min);
	NM_CMP_FIELD (a, b, src_port_max);
	NM_CMP_FIELD_BOOL (a, b, proxy);
	NM_CMP_FIELD_BOOL (a, b, rsc);
	NM_CMP_FIELD_BOOL (a, b, l2miss);
	NM_CMP_FIELD_BOOL (a, b, l3miss);
	return 0;
}

void
nm_platform_ip4_address_hash_update (const NMPlatformIP4Address *obj, NMHashState *h)
{
	nm_hash_update_vals (h,
	                     obj->ifindex,
	                     obj->addr_source,
	                     obj->timestamp,
	                     obj->lifetime,
	                     obj->preferred,
	                     obj->n_ifa_flags,
	                     obj->plen,
	                     obj->address,
	                     obj->peer_address);
	nm_hash_update_strarr (h, obj->label);
}

int
nm_platform_ip4_address_cmp (const NMPlatformIP4Address *a, const NMPlatformIP4Address *b)
{
	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, ifindex);
	NM_CMP_FIELD (a, b, address);
	NM_CMP_FIELD (a, b, plen);
	NM_CMP_FIELD (a, b, peer_address);
	NM_CMP_FIELD (a, b, addr_source);
	NM_CMP_FIELD (a, b, timestamp);
	NM_CMP_FIELD (a, b, lifetime);
	NM_CMP_FIELD (a, b, preferred);
	NM_CMP_FIELD (a, b, n_ifa_flags);
	NM_CMP_FIELD_STR (a, b, label);
	return 0;
}

void
nm_platform_ip6_address_hash_update (const NMPlatformIP6Address *obj, NMHashState *h)
{
	nm_hash_update_vals (h,
	                     obj->ifindex,
	                     obj->addr_source,
	                     obj->timestamp,
	                     obj->lifetime,
	                     obj->preferred,
	                     obj->n_ifa_flags,
	                     obj->plen,
	                     obj->address,
	                     obj->peer_address);
}

int
nm_platform_ip6_address_cmp (const NMPlatformIP6Address *a, const NMPlatformIP6Address *b)
{
	const struct in6_addr *p_a, *p_b;

	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, ifindex);
	NM_CMP_FIELD_MEMCMP (a, b, address);
	NM_CMP_FIELD (a, b, plen);
	p_a = nm_platform_ip6_address_get_peer (a);
	p_b = nm_platform_ip6_address_get_peer (b);
	NM_CMP_DIRECT_MEMCMP (p_a, p_b, sizeof (*p_a));
	NM_CMP_FIELD (a, b, addr_source);
	NM_CMP_FIELD (a, b, timestamp);
	NM_CMP_FIELD (a, b, lifetime);
	NM_CMP_FIELD (a, b, preferred);
	NM_CMP_FIELD (a, b, n_ifa_flags);
	return 0;
}

void
nm_platform_ip4_route_hash_update (const NMPlatformIP4Route *obj, NMPlatformIPRouteCmpType cmp_type, NMHashState *h)
{
	switch (cmp_type) {
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID:
		nm_hash_update_vals (h,
		                     nm_platform_route_table_uncoerce (obj->table_coerced, TRUE),
		                     nm_utils_ip4_address_clear_host_address (obj->network, obj->plen),
		                     obj->plen,
		                     obj->metric,
		                     obj->tos);
		break;
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID:
		nm_hash_update_vals (h,
		                     nm_platform_route_table_uncoerce (obj->table_coerced, TRUE),
		                     nm_utils_ip4_address_clear_host_address (obj->network, obj->plen),
		                     obj->plen,
		                     obj->metric,
		                     obj->tos,
		                     /* on top of WEAK_ID: */
		                     obj->ifindex,
		                     nmp_utils_ip_config_source_round_trip_rtprot (obj->rt_source),
		                     _ip_route_scope_inv_get_normalized (obj),
		                     obj->gateway,
		                     obj->mss,
		                     obj->pref_src,
		                     obj->window,
		                     obj->cwnd,
		                     obj->initcwnd,
		                     obj->initrwnd,
		                     obj->mtu,
		                     obj->r_rtm_flags & RTNH_F_ONLINK,
		                     NM_HASH_COMBINE_BOOLS (guint8,
		                                            obj->lock_window,
		                                            obj->lock_cwnd,
		                                            obj->lock_initcwnd,
		                                            obj->lock_initrwnd,
		                                            obj->lock_mtu));
		break;
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY:
		nm_hash_update_vals (h,
		                     nm_platform_route_table_uncoerce (obj->table_coerced, TRUE),
		                     obj->ifindex,
		                     nm_utils_ip4_address_clear_host_address (obj->network, obj->plen),
		                     obj->plen,
		                     obj->metric,
		                     obj->gateway,
		                     nmp_utils_ip_config_source_round_trip_rtprot (obj->rt_source),
		                     _ip_route_scope_inv_get_normalized (obj),
		                     obj->tos,
		                     obj->mss,
		                     obj->pref_src,
		                     obj->window,
		                     obj->cwnd,
		                     obj->initcwnd,
		                     obj->initrwnd,
		                     obj->mtu,
		                     obj->r_rtm_flags & (RTM_F_CLONED | RTNH_F_ONLINK),
		                     NM_HASH_COMBINE_BOOLS (guint8,
		                                            obj->lock_window,
		                                            obj->lock_cwnd,
		                                            obj->lock_initcwnd,
		                                            obj->lock_initrwnd,
		                                            obj->lock_mtu));
		break;
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL:
		nm_hash_update_vals (h,
		                     obj->table_coerced,
		                     obj->ifindex,
		                     obj->network,
		                     obj->plen,
		                     obj->metric,
		                     obj->gateway,
		                     obj->rt_source,
		                     obj->scope_inv,
		                     obj->tos,
		                     obj->mss,
		                     obj->pref_src,
		                     obj->window,
		                     obj->cwnd,
		                     obj->initcwnd,
		                     obj->initrwnd,
		                     obj->mtu,
		                     obj->r_rtm_flags,
		                     NM_HASH_COMBINE_BOOLS (guint8,
		                                            obj->lock_window,
		                                            obj->lock_cwnd,
		                                            obj->lock_initcwnd,
		                                            obj->lock_initrwnd,
		                                            obj->lock_mtu));
		break;
	}
}

int
nm_platform_ip4_route_cmp (const NMPlatformIP4Route *a, const NMPlatformIP4Route *b, NMPlatformIPRouteCmpType cmp_type)
{
	NM_CMP_SELF (a, b);
	switch (cmp_type) {
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID:
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID:
		NM_CMP_DIRECT (nm_platform_route_table_uncoerce (a->table_coerced, TRUE),
		               nm_platform_route_table_uncoerce (b->table_coerced, TRUE));
		NM_CMP_DIRECT_IN4ADDR_SAME_PREFIX (a->network, b->network, MIN (a->plen, b->plen));
		NM_CMP_FIELD (a, b, plen);
		NM_CMP_FIELD (a, b, metric);
		NM_CMP_FIELD (a, b, tos);
		if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID) {
			NM_CMP_FIELD (a, b, ifindex);
			NM_CMP_DIRECT (nmp_utils_ip_config_source_round_trip_rtprot (a->rt_source),
			               nmp_utils_ip_config_source_round_trip_rtprot (b->rt_source));
			NM_CMP_DIRECT (_ip_route_scope_inv_get_normalized (a),
			               _ip_route_scope_inv_get_normalized (b));
			NM_CMP_FIELD (a, b, gateway);
			NM_CMP_FIELD (a, b, mss);
			NM_CMP_FIELD (a, b, pref_src);
			NM_CMP_FIELD (a, b, window);
			NM_CMP_FIELD (a, b, cwnd);
			NM_CMP_FIELD (a, b, initcwnd);
			NM_CMP_FIELD (a, b, initrwnd);
			NM_CMP_FIELD (a, b, mtu);
			NM_CMP_DIRECT (a->r_rtm_flags & RTNH_F_ONLINK,
			               b->r_rtm_flags & RTNH_F_ONLINK);
			NM_CMP_FIELD_UNSAFE (a, b, lock_window);
			NM_CMP_FIELD_UNSAFE (a, b, lock_cwnd);
			NM_CMP_FIELD_UNSAFE (a, b, lock_initcwnd);
			NM_CMP_FIELD_UNSAFE (a, b, lock_initrwnd);
			NM_CMP_FIELD_UNSAFE (a, b, lock_mtu);
		}
		break;
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY:
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL:
		if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) {
			NM_CMP_DIRECT (nm_platform_route_table_uncoerce (a->table_coerced, TRUE),
			               nm_platform_route_table_uncoerce (b->table_coerced, TRUE));
		} else
			NM_CMP_FIELD (a, b, table_coerced);
		NM_CMP_FIELD (a, b, ifindex);
		if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
			NM_CMP_DIRECT_IN4ADDR_SAME_PREFIX (a->network, b->network, MIN (a->plen, b->plen));
		else
			NM_CMP_FIELD (a, b, network);
		NM_CMP_FIELD (a, b, plen);
		NM_CMP_FIELD (a, b, metric);
		NM_CMP_FIELD (a, b, gateway);
		if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) {
			NM_CMP_DIRECT (nmp_utils_ip_config_source_round_trip_rtprot (a->rt_source),
			               nmp_utils_ip_config_source_round_trip_rtprot (b->rt_source));
			NM_CMP_DIRECT (_ip_route_scope_inv_get_normalized (a),
			               _ip_route_scope_inv_get_normalized (b));
		} else {
			NM_CMP_FIELD (a, b, rt_source);
			NM_CMP_FIELD (a, b, scope_inv);
		}
		NM_CMP_FIELD (a, b, mss);
		NM_CMP_FIELD (a, b, pref_src);
		if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) {
			NM_CMP_DIRECT (a->r_rtm_flags & (RTM_F_CLONED | RTNH_F_ONLINK),
			               b->r_rtm_flags & (RTM_F_CLONED | RTNH_F_ONLINK));
		} else
			NM_CMP_FIELD (a, b, r_rtm_flags);
		NM_CMP_FIELD (a, b, tos);
		NM_CMP_FIELD_UNSAFE (a, b, lock_window);
		NM_CMP_FIELD_UNSAFE (a, b, lock_cwnd);
		NM_CMP_FIELD_UNSAFE (a, b, lock_initcwnd);
		NM_CMP_FIELD_UNSAFE (a, b, lock_initrwnd);
		NM_CMP_FIELD_UNSAFE (a, b, lock_mtu);
		NM_CMP_FIELD (a, b, window);
		NM_CMP_FIELD (a, b, cwnd);
		NM_CMP_FIELD (a, b, initcwnd);
		NM_CMP_FIELD (a, b, initrwnd);
		NM_CMP_FIELD (a, b, mtu);
		break;
	}
	return 0;
}

void
nm_platform_ip6_route_hash_update (const NMPlatformIP6Route *obj, NMPlatformIPRouteCmpType cmp_type, NMHashState *h)
{
	struct in6_addr a1, a2;

	switch (cmp_type) {
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID:
		nm_hash_update_vals (h,
		                     nm_platform_route_table_uncoerce (obj->table_coerced, TRUE),
		                     *nm_utils_ip6_address_clear_host_address (&a1, &obj->network, obj->plen),
		                     obj->plen,
		                     nm_utils_ip6_route_metric_normalize (obj->metric),
		                     *nm_utils_ip6_address_clear_host_address (&a2, &obj->src, obj->src_plen),
		                     obj->src_plen);
		break;
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID:
		nm_hash_update_vals (h,
		                     nm_platform_route_table_uncoerce (obj->table_coerced, TRUE),
		                     *nm_utils_ip6_address_clear_host_address (&a1, &obj->network, obj->plen),
		                     obj->plen,
		                     nm_utils_ip6_route_metric_normalize (obj->metric),
		                     *nm_utils_ip6_address_clear_host_address (&a2, &obj->src, obj->src_plen),
		                     obj->src_plen,
		                     /* on top of WEAK_ID: */
		                     obj->ifindex,
		                     obj->gateway);
		break;
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY:
		nm_hash_update_vals (h,
		                     nm_platform_route_table_uncoerce (obj->table_coerced, TRUE),
		                     obj->ifindex,
		                     *nm_utils_ip6_address_clear_host_address (&a1, &obj->network, obj->plen),
		                     obj->plen,
		                     nm_utils_ip6_route_metric_normalize (obj->metric),
		                     obj->gateway,
		                     obj->pref_src,
		                     *nm_utils_ip6_address_clear_host_address (&a2, &obj->src, obj->src_plen),
		                     obj->src_plen,
		                     nmp_utils_ip_config_source_round_trip_rtprot (obj->rt_source),
		                     obj->mss,
		                     obj->r_rtm_flags & RTM_F_CLONED,
		                     NM_HASH_COMBINE_BOOLS (guint8,
		                                            obj->lock_window,
		                                            obj->lock_cwnd,
		                                            obj->lock_initcwnd,
		                                            obj->lock_initrwnd,
		                                            obj->lock_mtu),
		                     obj->window,
		                     obj->cwnd,
		                     obj->initcwnd,
		                     obj->initrwnd,
		                     obj->mtu,
		                     _route_pref_normalize (obj->rt_pref));
		break;
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL:
		nm_hash_update_vals (h,
		                     obj->table_coerced,
		                     obj->ifindex,
		                     obj->network,
		                     obj->plen,
		                     obj->metric,
		                     obj->gateway,
		                     obj->pref_src,
		                     obj->src,
		                     obj->src_plen,
		                     obj->rt_source,
		                     obj->mss,
		                     obj->r_rtm_flags,
		                     NM_HASH_COMBINE_BOOLS (guint8,
		                                            obj->lock_window,
		                                            obj->lock_cwnd,
		                                            obj->lock_initcwnd,
		                                            obj->lock_initrwnd,
		                                            obj->lock_mtu),
		                     obj->window,
		                     obj->cwnd,
		                     obj->initcwnd,
		                     obj->initrwnd,
		                     obj->mtu,
		                     obj->rt_pref);
		break;
	}
}

int
nm_platform_ip6_route_cmp (const NMPlatformIP6Route *a, const NMPlatformIP6Route *b, NMPlatformIPRouteCmpType cmp_type)
{
	NM_CMP_SELF (a, b);
	switch (cmp_type) {
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID:
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID:
		NM_CMP_DIRECT (nm_platform_route_table_uncoerce (a->table_coerced, TRUE),
		               nm_platform_route_table_uncoerce (b->table_coerced, TRUE));
		NM_CMP_DIRECT_IN6ADDR_SAME_PREFIX (&a->network, &b->network, MIN (a->plen, b->plen));
		NM_CMP_FIELD (a, b, plen);
		NM_CMP_DIRECT (nm_utils_ip6_route_metric_normalize (a->metric), nm_utils_ip6_route_metric_normalize (b->metric));
		NM_CMP_DIRECT_IN6ADDR_SAME_PREFIX (&a->src, &b->src, MIN (a->src_plen, b->src_plen));
		NM_CMP_FIELD (a, b, src_plen);
		if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID) {
			NM_CMP_FIELD (a, b, ifindex);
			NM_CMP_FIELD_IN6ADDR (a, b, gateway);
		}
		break;
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY:
	case NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL:
		if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) {
			NM_CMP_DIRECT (nm_platform_route_table_uncoerce (a->table_coerced, TRUE),
			               nm_platform_route_table_uncoerce (b->table_coerced, TRUE));
		} else
			NM_CMP_FIELD (a, b, table_coerced);
		NM_CMP_FIELD (a, b, ifindex);
		if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
			NM_CMP_DIRECT_IN6ADDR_SAME_PREFIX (&a->network, &b->network, MIN (a->plen, b->plen));
		else
			NM_CMP_FIELD_IN6ADDR (a, b, network);
		NM_CMP_FIELD (a, b, plen);
		if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
			NM_CMP_DIRECT (nm_utils_ip6_route_metric_normalize (a->metric), nm_utils_ip6_route_metric_normalize (b->metric));
		else
			NM_CMP_FIELD (a, b, metric);
		NM_CMP_FIELD_IN6ADDR (a, b, gateway);
		NM_CMP_FIELD_IN6ADDR (a, b, pref_src);
		if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) {
			NM_CMP_DIRECT_IN6ADDR_SAME_PREFIX (&a->src, &b->src, MIN (a->src_plen, b->src_plen));
			NM_CMP_FIELD (a, b, src_plen);
			NM_CMP_DIRECT (nmp_utils_ip_config_source_round_trip_rtprot (a->rt_source),
			               nmp_utils_ip_config_source_round_trip_rtprot (b->rt_source));
		} else {
			NM_CMP_FIELD_IN6ADDR (a, b, src);
			NM_CMP_FIELD (a, b, src_plen);
			NM_CMP_FIELD (a, b, rt_source);
		}
		NM_CMP_FIELD (a, b, mss);
		if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY) {
			NM_CMP_DIRECT (a->r_rtm_flags & RTM_F_CLONED,
			               b->r_rtm_flags & RTM_F_CLONED);
		} else
			NM_CMP_FIELD (a, b, r_rtm_flags);
		NM_CMP_FIELD_UNSAFE (a, b, lock_window);
		NM_CMP_FIELD_UNSAFE (a, b, lock_cwnd);
		NM_CMP_FIELD_UNSAFE (a, b, lock_initcwnd);
		NM_CMP_FIELD_UNSAFE (a, b, lock_initrwnd);
		NM_CMP_FIELD_UNSAFE (a, b, lock_mtu);
		NM_CMP_FIELD (a, b, window);
		NM_CMP_FIELD (a, b, cwnd);
		NM_CMP_FIELD (a, b, initcwnd);
		NM_CMP_FIELD (a, b, initrwnd);
		NM_CMP_FIELD (a, b, mtu);
		if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY)
			NM_CMP_DIRECT (_route_pref_normalize (a->rt_pref), _route_pref_normalize (b->rt_pref));
		else
			NM_CMP_FIELD (a, b, rt_pref);
		break;
	}
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

	NM_CMP_SELF (a, b);

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

static void
log_qdisc (NMPlatform *self, NMPObjectType obj_type, int ifindex, NMPlatformQdisc *qdisc, NMPlatformSignalChangeType change_type, gpointer user_data)
{
	_LOGD ("signal: qdisc %7s: %s", nm_platform_signal_change_type_to_string (change_type), nm_platform_qdisc_to_string (qdisc, NULL, 0));
}

static void
log_tfilter (NMPlatform *self, NMPObjectType obj_type, int ifindex, NMPlatformTfilter *tfilter, NMPlatformSignalChangeType change_type, gpointer user_data)
{
	_LOGD ("signal: tfilter %7s: %s", nm_platform_signal_change_type_to_string (change_type), nm_platform_tfilter_to_string (tfilter, NULL, 0));
}

/*****************************************************************************/

void
nm_platform_cache_update_emit_signal (NMPlatform *self,
                                      NMPCacheOpsType cache_op,
                                      const NMPObject *obj_old,
                                      const NMPObject *obj_new)
{
	gboolean visible_new;
	gboolean visible_old;
	const NMPObject *o;
	const NMPClass *klass;

	nm_assert (NM_IN_SET ((NMPlatformSignalChangeType) cache_op, NM_PLATFORM_SIGNAL_NONE,
	                                                             NM_PLATFORM_SIGNAL_ADDED,
	                                                             NM_PLATFORM_SIGNAL_CHANGED,
	                                                             NM_PLATFORM_SIGNAL_REMOVED));

	ASSERT_nmp_cache_ops (nm_platform_get_cache (self), cache_op, obj_old, obj_new);

	NMTST_ASSERT_PLATFORM_NETNS_CURRENT (self);

	switch (cache_op) {
	case NMP_CACHE_OPS_ADDED:
		if (!nmp_object_is_visible (obj_new))
			return;
		o = obj_new;
		break;
	case NMP_CACHE_OPS_UPDATED:
		visible_old = nmp_object_is_visible (obj_old);
		visible_new = nmp_object_is_visible (obj_new);
		if (!visible_old && visible_new) {
			o = obj_new;
			cache_op = NMP_CACHE_OPS_ADDED;
		} else if (visible_old && !visible_new) {
			o = obj_old;
			cache_op = NMP_CACHE_OPS_REMOVED;
		} else if (!visible_new) {
			/* it was invisible and stayed invisible. Nothing to do. */
			return;
		} else
			o = obj_new;
		break;
	case NMP_CACHE_OPS_REMOVED:
		if (!nmp_object_is_visible (obj_old))
			return;
		o = obj_old;
		break;
	default:
		nm_assert (cache_op == NMP_CACHE_OPS_UNCHANGED);
		return;
	}

	klass = NMP_OBJECT_GET_CLASS (o);

	if (   klass->obj_type == NMP_OBJECT_TYPE_IP4_ROUTE
	    && NM_PLATFORM_GET_PRIVATE (self)->ip4_dev_route_blacklist_gc_timeout_id
	    && NM_IN_SET (cache_op, NMP_CACHE_OPS_ADDED, NMP_CACHE_OPS_UPDATED))
		_ip4_dev_route_blacklist_notify_route (self, o);

	_LOGt ("emit signal %s %s: %s",
	       klass->signal_type,
	       nm_platform_signal_change_type_to_string ((NMPlatformSignalChangeType) cache_op),
	       nmp_object_to_string (o, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));

	nmp_object_ref (o);
	g_signal_emit (self,
	               _nm_platform_signal_id_get (klass->signal_type_id),
	               0,
	               (int) klass->obj_type,
	               o->object.ifindex,
	               &o->object,
	               (int) cache_op);
	nmp_object_unref (o);
}

/*****************************************************************************/

NMPCache *
nm_platform_get_cache (NMPlatform *self)
{
	return NM_PLATFORM_GET_PRIVATE (self)->cache;
}

NMPNetns *
nm_platform_netns_get (NMPlatform *self)
{
	_CHECK_SELF (self, klass, NULL);

	return self->_netns;
}

gboolean
nm_platform_netns_push (NMPlatform *self, NMPNetns **netns)
{
	g_return_val_if_fail (NM_IS_PLATFORM (self), FALSE);

	if (   self->_netns
	    && !nmp_netns_push (self->_netns)) {
		NM_SET_OUT (netns, NULL);
		return FALSE;
	}

	NM_SET_OUT (netns, self->_netns);
	return TRUE;
}

/*****************************************************************************/

static guint32
_vtr_v4_metric_normalize (guint32 metric)
{
	return metric;
}

/*****************************************************************************/

const NMPlatformVTableRoute nm_platform_vtable_route_v4 = {
	.is_ip4                         = TRUE,
	.obj_type                       = NMP_OBJECT_TYPE_IP4_ROUTE,
	.addr_family                    = AF_INET,
	.sizeof_route                   = sizeof (NMPlatformIP4Route),
	.route_cmp                      = (int (*) (const NMPlatformIPXRoute *a, const NMPlatformIPXRoute *b, NMPlatformIPRouteCmpType cmp_type)) nm_platform_ip4_route_cmp,
	.route_to_string                = (const char *(*) (const NMPlatformIPXRoute *route, char *buf, gsize len)) nm_platform_ip4_route_to_string,
	.metric_normalize               = _vtr_v4_metric_normalize,
};

const NMPlatformVTableRoute nm_platform_vtable_route_v6 = {
	.is_ip4                         = FALSE,
	.obj_type                       = NMP_OBJECT_TYPE_IP6_ROUTE,
	.addr_family                    = AF_INET6,
	.sizeof_route                   = sizeof (NMPlatformIP6Route),
	.route_cmp                      = (int (*) (const NMPlatformIPXRoute *a, const NMPlatformIPXRoute *b, NMPlatformIPRouteCmpType cmp_type)) nm_platform_ip6_route_cmp,
	.route_to_string                = (const char *(*) (const NMPlatformIPXRoute *route, char *buf, gsize len)) nm_platform_ip6_route_to_string,
	.metric_normalize               = nm_utils_ip6_route_metric_normalize,
};

/*****************************************************************************/

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMPlatform *self = NM_PLATFORM (object);
	NMPlatformPrivate *priv =  NM_PLATFORM_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_NETNS_SUPPORT:
		/* construct-only */
		if (g_value_get_boolean (value)) {
			NMPNetns *netns;

			netns = nmp_netns_get_current ();
			if (netns)
				self->_netns = g_object_ref (netns);
		}
		break;
	case PROP_USE_UDEV:
		/* construct-only */
		priv->use_udev = g_value_get_boolean (value);
		break;
	case PROP_LOG_WITH_PTR:
		/* construct-only */
		priv->log_with_ptr = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_platform_init (NMPlatform *self)
{
	self->_priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_PLATFORM, NMPlatformPrivate);
}

static GObject *
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMPlatform *self;
	NMPlatformPrivate *priv;

	object = G_OBJECT_CLASS (nm_platform_parent_class)->constructor (type,
	                                                                 n_construct_params,
	                                                                 construct_params);
	self = NM_PLATFORM (object);
	priv = NM_PLATFORM_GET_PRIVATE (self);

	priv->multi_idx = nm_dedup_multi_index_new ();

	priv->cache = nmp_cache_new (nm_platform_get_multi_idx (self),
	                             priv->use_udev);
	return object;
}

static void
finalize (GObject *object)
{
	NMPlatform *self = NM_PLATFORM (object);
	NMPlatformPrivate *priv = NM_PLATFORM_GET_PRIVATE (self);

	nm_clear_g_source (&priv->ip4_dev_route_blacklist_check_id);
	nm_clear_g_source (&priv->ip4_dev_route_blacklist_gc_timeout_id);
	g_clear_pointer (&priv->ip4_dev_route_blacklist_hash, g_hash_table_unref);
	g_clear_object (&self->_netns);
	nm_dedup_multi_index_unref (priv->multi_idx);
	nmp_cache_free (priv->cache);
}

static void
nm_platform_class_init (NMPlatformClass *platform_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (platform_class);

	g_type_class_add_private (object_class, sizeof (NMPlatformPrivate));

	object_class->constructor = constructor;
	object_class->set_property = set_property;
	object_class->finalize = finalize;

	platform_class->wifi_set_powersave = wifi_set_powersave;

	g_object_class_install_property
	 (object_class, PROP_NETNS_SUPPORT,
	     g_param_spec_boolean (NM_PLATFORM_NETNS_SUPPORT, "", "",
	                           NM_PLATFORM_NETNS_SUPPORT_DEFAULT,
	                           G_PARAM_WRITABLE |
	                           G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	 (object_class, PROP_USE_UDEV,
	     g_param_spec_boolean (NM_PLATFORM_USE_UDEV, "", "",
	                           FALSE,
	                           G_PARAM_WRITABLE |
	                           G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	 (object_class, PROP_LOG_WITH_PTR,
	     g_param_spec_boolean (NM_PLATFORM_LOG_WITH_PTR, "", "",
	                           TRUE,
	                           G_PARAM_WRITABLE |
	                           G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS));

#define SIGNAL(signal, signal_id, method) \
	G_STMT_START { \
		signals[signal] = \
			g_signal_new_class_handler (""signal_id"", \
			                            G_OBJECT_CLASS_TYPE (object_class), \
			                            G_SIGNAL_RUN_FIRST, \
			                            G_CALLBACK (method), \
			                            NULL, NULL, NULL, \
			                            G_TYPE_NONE, 4, \
			                            G_TYPE_INT, /* (int) NMPObjectType */ \
			                            G_TYPE_INT, /* ifindex */ \
			                            G_TYPE_POINTER /* const NMPObject * */, \
			                            G_TYPE_INT /* (int) NMPlatformSignalChangeType */ \
			                            ); \
	} G_STMT_END

	/* Signals */
	SIGNAL (NM_PLATFORM_SIGNAL_ID_LINK,        NM_PLATFORM_SIGNAL_LINK_CHANGED,        log_link);
	SIGNAL (NM_PLATFORM_SIGNAL_ID_IP4_ADDRESS, NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, log_ip4_address);
	SIGNAL (NM_PLATFORM_SIGNAL_ID_IP6_ADDRESS, NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED, log_ip6_address);
	SIGNAL (NM_PLATFORM_SIGNAL_ID_IP4_ROUTE,   NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED,   log_ip4_route);
	SIGNAL (NM_PLATFORM_SIGNAL_ID_IP6_ROUTE,   NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED,   log_ip6_route);
	SIGNAL (NM_PLATFORM_SIGNAL_ID_QDISC,       NM_PLATFORM_SIGNAL_QDISC_CHANGED,       log_qdisc);
	SIGNAL (NM_PLATFORM_SIGNAL_ID_TFILTER,     NM_PLATFORM_SIGNAL_TFILTER_CHANGED,     log_tfilter);
}
