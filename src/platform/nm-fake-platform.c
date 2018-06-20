/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-platform-fake.c - Fake platform interaction code for testing NetworkManager
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
 * Copyright (C) 2012–2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-fake-platform.h"

#include <errno.h>
#include <unistd.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <linux/rtnetlink.h>

#include "nm-utils.h"

#include "nm-core-utils.h"
#include "nm-platform-utils.h"
#include "nm-platform-private.h"
#include "nmp-object.h"

#include "nm-test-utils-core.h"

/*****************************************************************************/

typedef struct {
	const NMPObject *obj;
	char *udi;
	struct in6_addr ip6_lladdr;
} NMFakePlatformLink;

typedef struct {
	GHashTable *options;
	GArray *links;
} NMFakePlatformPrivate;

struct _NMFakePlatform {
	NMPlatform parent;
	NMFakePlatformPrivate _priv;
};

struct _NMFakePlatformClass {
	NMPlatformClass parent;
};

G_DEFINE_TYPE (NMFakePlatform, nm_fake_platform, NM_TYPE_PLATFORM)

#define NM_FAKE_PLATFORM_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMFakePlatform, NM_IS_FAKE_PLATFORM)

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME                "platform-fake"
#define _NMLOG_DOMAIN                     LOGD_PLATFORM
#define _NMLOG(level, ...)                _LOG(level, _NMLOG_DOMAIN,  platform, __VA_ARGS__)

#define _LOG(level, domain, self, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        const NMLogDomain __domain = (domain); \
        \
        if (nm_logging_enabled (__level, __domain)) { \
            char __prefix[32]; \
            const char *__p_prefix = _NMLOG_PREFIX_NAME; \
            NMPlatform *const __self = (self); \
            \
            if (__self && nm_platform_get_log_with_ptr (self)) { \
                g_snprintf (__prefix, sizeof (__prefix), "%s[%p]", _NMLOG_PREFIX_NAME, __self); \
                __p_prefix = __prefix; \
            } \
            _nm_log (__level, __domain, 0, NULL, NULL, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     __p_prefix _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

static void link_changed (NMPlatform *platform,
                          NMFakePlatformLink *device,
                          NMPCacheOpsType cache_op,
                          const NMPObject *obj_old);

static gboolean ipx_address_delete (NMPlatform *platform,
                                    int addr_family,
                                    int ifindex,
                                    gconstpointer addr,
                                    const guint8 *plen,
                                    gconstpointer peer_addr);

static gboolean ipx_route_delete (NMPlatform *platform,
                                  int addr_family,
                                  int ifindex,
                                  const NMPObject *obj);

static gboolean ip6_address_add (NMPlatform *platform,
                                 int ifindex,
                                 struct in6_addr addr,
                                 guint8 plen,
                                 struct in6_addr peer_addr,
                                 guint32 lifetime,
                                 guint32 preferred,
                                 guint flags);
static gboolean ip6_address_delete (NMPlatform *platform, int ifindex, struct in6_addr addr, guint8 plen);

/*****************************************************************************/

#define ASSERT_SYSCTL_ARGS(pathid, dirfd, path) \
	G_STMT_START { \
		const char *const _pathid = (pathid); \
		const int _dirfd = (dirfd); \
		const char *const _path = (path); \
		\
		g_assert (_path && _path[0]); \
		g_assert (!strstr (_path, "/../")); \
		if (_dirfd < 0) { \
			g_assert (!_pathid); \
			g_assert (_path[0] == '/'); \
			g_assert (   g_str_has_prefix (_path, "/proc/sys/") \
			          || g_str_has_prefix (_path, "/sys/")); \
		} else { \
			g_assert_not_reached (); \
		} \
	} G_STMT_END

static gboolean
sysctl_set (NMPlatform *platform, const char *pathid, int dirfd, const char *path, const char *value)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE ((NMFakePlatform *) platform);

	ASSERT_SYSCTL_ARGS (pathid, dirfd, path);

	g_hash_table_insert (priv->options, g_strdup (path), g_strdup (value));

	return TRUE;
}

static char *
sysctl_get (NMPlatform *platform, const char *pathid, int dirfd, const char *path)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE ((NMFakePlatform *) platform);

	ASSERT_SYSCTL_ARGS (pathid, dirfd, path);

	return g_strdup (g_hash_table_lookup (priv->options, path));
}

static NMFakePlatformLink *
link_get (NMPlatform *platform, int ifindex)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE ((NMFakePlatform *) platform);
	NMFakePlatformLink *device;
	int idx;

	if (ifindex <= 0)
		g_return_val_if_reached (NULL);

	idx = ifindex - 1;
	if (idx >= priv->links->len)
		goto not_found;

	device = &g_array_index (priv->links, NMFakePlatformLink, idx);
	if (!device->obj)
		goto not_found;

	g_assert (ifindex == NMP_OBJECT_CAST_LINK (device->obj)->ifindex);
	g_assert (device->obj == nm_platform_link_get_obj (platform, ifindex, FALSE));

	return device;
not_found:
	_LOGD ("link not found: %d", ifindex);
	return NULL;
}

static void
link_add_prepare (NMPlatform *platform,
                  NMFakePlatformLink *device,
                  NMPObject *obj_tmp)
{
	gboolean connected;

	/* we must clear the driver, because platform cache want's to set it */
	g_assert (obj_tmp->link.driver == g_intern_string (obj_tmp->link.driver));
	obj_tmp->link.driver = NULL;

	if (NM_IN_SET (obj_tmp->link.type, NM_LINK_TYPE_BRIDGE,
	                                   NM_LINK_TYPE_BOND)) {
		connected = FALSE;
		if (NM_FLAGS_HAS (obj_tmp->link.n_ifi_flags, IFF_UP)) {
			NMPLookup lookup;
			NMDedupMultiIter iter;
			const NMPObject *slave_candidate = NULL;

			nmp_cache_iter_for_each (&iter,
			                         nmp_cache_lookup (nm_platform_get_cache (platform),
			                                           nmp_lookup_init_obj_type (&lookup,
			                                                                     NMP_OBJECT_TYPE_LINK)),
			                         &slave_candidate) {
				if (nmp_cache_link_connected_for_slave (obj_tmp->link.ifindex, slave_candidate)) {
					connected = TRUE;
					break;
				}
			}
		}
	} else
		connected = NM_FLAGS_HAS (obj_tmp->link.n_ifi_flags, IFF_UP);

	obj_tmp->link.n_ifi_flags = NM_FLAGS_ASSIGN (obj_tmp->link.n_ifi_flags, IFF_LOWER_UP, connected);
	obj_tmp->link.connected = connected;
}

static NMFakePlatformLink *
link_add_pre (NMPlatform *platform,
              const char *name,
              NMLinkType type,
              const void *address,
              size_t address_len)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE ((NMFakePlatform *) platform);
	NMFakePlatformLink *device;
	int ifindex;
	NMPObject *o;
	NMPlatformLink *link;
	gs_free char *ip6_lladdr = NULL;

	g_assert (!name || strlen (name) < IFNAMSIZ);

	g_array_set_size (priv->links, priv->links->len + 1);
	device = &g_array_index (priv->links, NMFakePlatformLink, priv->links->len - 1);
	ifindex = priv->links->len;

	memset (device, 0, sizeof (*device));

	o = nmp_object_new_link (ifindex);
	link = NMP_OBJECT_CAST_LINK (o);

	ip6_lladdr = ifindex > 0 ? g_strdup_printf ("fe80::fa1e:%0x:%0x", ifindex / 256, ifindex % 256) : NULL;

	link->ifindex = name ? ifindex : 0;
	link->type = type;
	link->kind = g_intern_string (nm_link_type_to_string (type));
	link->initialized = TRUE;
	if (name)
		strcpy (link->name, name);
	switch (link->type) {
	case NM_LINK_TYPE_DUMMY:
		link->n_ifi_flags = NM_FLAGS_SET (link->n_ifi_flags, IFF_NOARP);
		break;
	default:
		link->n_ifi_flags = NM_FLAGS_UNSET (link->n_ifi_flags, IFF_NOARP);
		break;
	}

	o->_link.netlink.is_in_netlink = TRUE;

	if (address) {
		g_assert (address_len > 0 && address_len <= sizeof (link->addr.data));
		memcpy (link->addr.data, address, address_len);
		link->addr.len = address_len;
	} else
		g_assert (address_len == 0);

	device->obj = o;
	device->udi = g_strdup_printf ("fake:%d", ifindex);
	device->ip6_lladdr = *nmtst_inet6_from_string (ip6_lladdr);

	return device;
}

static gboolean
link_add (NMPlatform *platform,
          const char *name,
          NMLinkType type,
          const char *veth_peer,
          const void *address,
          size_t address_len,
          const NMPlatformLink **out_link)
{
	NMFakePlatformLink *device;
	NMFakePlatformLink *device_veth = NULL;
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	nm_auto_nmpobj const NMPObject *obj_new = NULL;
	nm_auto_nmpobj const NMPObject *obj_old_veth = NULL;
	nm_auto_nmpobj const NMPObject *obj_new_veth = NULL;
	NMPCacheOpsType cache_op;
	NMPCacheOpsType cache_op_veth = NMP_CACHE_OPS_UNCHANGED;

	device = link_add_pre (platform, name, type, address, address_len);

	if (veth_peer) {
		g_assert (type == NM_LINK_TYPE_VETH);
		device_veth = link_add_pre (platform, veth_peer, type, NULL, 0);
	} else
		g_assert (type != NM_LINK_TYPE_VETH);

	link_add_prepare (platform, device, (NMPObject *) device->obj);
	cache_op = nmp_cache_update_netlink (nm_platform_get_cache (platform),
	                                     (NMPObject *) device->obj,
	                                     FALSE,
	                                     &obj_old, &obj_new);
	g_assert (cache_op == NMP_CACHE_OPS_ADDED);
	nmp_object_unref (device->obj);
	device->obj = nmp_object_ref (obj_new);
	if (veth_peer) {
		link_add_prepare (platform, device_veth, (NMPObject *) device_veth->obj);
		cache_op_veth = nmp_cache_update_netlink (nm_platform_get_cache (platform),
		                                          (NMPObject *) device_veth->obj,
		                                          FALSE,
		                                          &obj_old_veth, &obj_new_veth);
		g_assert (cache_op == NMP_CACHE_OPS_ADDED);
		nmp_object_unref (device->obj);
		device->obj = nmp_object_ref (obj_new);
	}

	if (out_link)
		*out_link = NMP_OBJECT_CAST_LINK (device->obj);

	link_changed (platform, device, cache_op, NULL);
	if (veth_peer)
		link_changed (platform, device_veth, cache_op_veth, NULL);

	return TRUE;
}

static NMFakePlatformLink *
link_add_one (NMPlatform *platform,
              const char *name,
              NMLinkType link_type,
              void (*prepare_fcn) (NMPlatform *platform, NMFakePlatformLink *device, gconstpointer user_data),
              gconstpointer user_data,
              const NMPlatformLink **out_link)
{
	NMFakePlatformLink *device;
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	nm_auto_nmpobj const NMPObject *obj_new = NULL;
	NMPCacheOpsType cache_op;
	int ifindex;

	device = link_add_pre (platform, name, NM_LINK_TYPE_VLAN, NULL, 0);

	ifindex = NMP_OBJECT_CAST_LINK (device->obj)->ifindex;

	if (prepare_fcn)
		prepare_fcn (platform, device, user_data);

	link_add_prepare (platform, device, (NMPObject *) device->obj);
	cache_op = nmp_cache_update_netlink (nm_platform_get_cache (platform),
	                                     (NMPObject *) device->obj,
	                                     FALSE,
	                                     &obj_old, &obj_new);
	g_assert (cache_op == NMP_CACHE_OPS_ADDED);
	nmp_object_unref (device->obj);
	device->obj = nmp_object_ref (obj_new);

	link_changed (platform, device, cache_op, obj_old);

	device = link_get (platform, ifindex);
	if (!device)
		g_assert_not_reached ();

	NM_SET_OUT (out_link, NMP_OBJECT_CAST_LINK (device->obj));
	return device;
}

static gboolean
link_delete (NMPlatform *platform, int ifindex)
{
	NMFakePlatformLink *device = link_get (platform, ifindex);
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	nm_auto_nmpobj const NMPObject *obj_old2 = NULL;
	NMPCacheOpsType cache_op;

	if (!device)
		return FALSE;

	obj_old = g_steal_pointer (&device->obj);
	g_clear_pointer (&device->udi, g_free);

	cache_op = nmp_cache_remove (nm_platform_get_cache (platform),
	                             obj_old,
	                             FALSE,
	                             FALSE,
	                             &obj_old2);
	g_assert (cache_op == NMP_CACHE_OPS_REMOVED);
	g_assert (obj_old2);
	g_assert (obj_old == obj_old2);

	/* Remove addresses and routes which belong to the deleted interface */
	ipx_address_delete (platform, AF_INET, ifindex, NULL, NULL, NULL);
	ipx_address_delete (platform, AF_INET6, ifindex, NULL, NULL, NULL);
	ipx_route_delete (platform, AF_INET, ifindex, NULL);
	ipx_route_delete (platform, AF_INET6, ifindex, NULL);

	nm_platform_cache_update_emit_signal (platform,
	                                      cache_op,
	                                      obj_old2,
	                                      NULL);
	return TRUE;
}

static void
link_set_obj (NMPlatform *platform,
              NMFakePlatformLink *device,
              NMPObject *obj_tmp)
{
	nm_auto_nmpobj const NMPObject *obj_new = NULL;
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	nm_auto_nmpobj NMPObject *obj_tmp_tmp = NULL;
	NMPCacheOpsType cache_op;

	g_assert (device);
	g_assert (NMP_OBJECT_GET_TYPE (device->obj) == NMP_OBJECT_TYPE_LINK);

	if (!obj_tmp) {
		obj_tmp_tmp = nmp_object_clone (device->obj, FALSE);
		obj_tmp = obj_tmp_tmp;
	}

	g_assert (NMP_OBJECT_GET_TYPE (obj_tmp) == NMP_OBJECT_TYPE_LINK);

	link_add_prepare (platform, device, obj_tmp);
	cache_op = nmp_cache_update_netlink (nm_platform_get_cache (platform),
	                                     obj_tmp,
	                                     FALSE,
	                                     &obj_old, &obj_new);
	g_assert (NM_IN_SET (cache_op, NMP_CACHE_OPS_UNCHANGED,
	                               NMP_CACHE_OPS_UPDATED));
	g_assert (obj_old == device->obj);
	g_assert (obj_new);

	nmp_object_unref (device->obj);
	device->obj = nmp_object_ref (obj_new);

	link_changed (platform, device, cache_op, obj_old);
}

static void
link_set_flags (NMPlatform *platform,
                NMFakePlatformLink *device,
                guint n_ifi_flags)
{
	nm_auto_nmpobj NMPObject *obj_tmp = NULL;

	g_assert (device);
	g_assert (NMP_OBJECT_GET_TYPE (device->obj) == NMP_OBJECT_TYPE_LINK);

	obj_tmp = nmp_object_clone (device->obj, FALSE);
	obj_tmp->link.n_ifi_flags = n_ifi_flags;
	link_set_obj (platform, device, obj_tmp);
}

static void
link_changed (NMPlatform *platform,
              NMFakePlatformLink *device,
              NMPCacheOpsType cache_op,
              const NMPObject *obj_old)
{
	g_assert (device->obj);

	g_assert (!nmp_cache_link_connected_needs_toggle (nm_platform_get_cache (platform),
	                                                  device->obj, NULL, NULL));

	nm_platform_cache_update_emit_signal (platform,
	                                      cache_op,
	                                      obj_old,
	                                      device->obj);

	if (!IN6_IS_ADDR_UNSPECIFIED (&device->ip6_lladdr)) {
		if (device->obj->link.connected)
			ip6_address_add (platform, device->obj->link.ifindex, device->ip6_lladdr, 64, in6addr_any, NM_PLATFORM_LIFETIME_PERMANENT, NM_PLATFORM_LIFETIME_PERMANENT, 0);
		else
			ip6_address_delete (platform, device->obj->link.ifindex, device->ip6_lladdr, 64);
	}

	if (device->obj->link.master) {
		NMFakePlatformLink *master;

		master = link_get (platform, device->obj->link.master);
		link_set_obj (platform, master, NULL);
	}
}

static gboolean
link_set_up (NMPlatform *platform, int ifindex, gboolean *out_no_firmware)
{
	NMFakePlatformLink *device = link_get (platform, ifindex);

	if (out_no_firmware)
		*out_no_firmware = FALSE;

	if (!device) {
		_LOGE ("failure changing link: netlink error (No such device)");
		return FALSE;
	}

	link_set_flags (platform,
	                device,
	                NM_FLAGS_ASSIGN (device->obj->link.n_ifi_flags, IFF_UP, TRUE));
	return TRUE;
}

static gboolean
link_set_down (NMPlatform *platform, int ifindex)
{
	NMFakePlatformLink *device = link_get (platform, ifindex);

	if (!device) {
		_LOGE ("failure changing link: netlink error (No such device)");
		return FALSE;
	}

	link_set_flags (platform,
	                device,
	                NM_FLAGS_UNSET (device->obj->link.n_ifi_flags, IFF_UP));
	return TRUE;
}

static gboolean
link_set_arp (NMPlatform *platform, int ifindex)
{
	NMFakePlatformLink *device = link_get (platform, ifindex);

	if (!device) {
		_LOGE ("failure changing link: netlink error (No such device)");
		return FALSE;
	}

	link_set_flags (platform,
	                device,
	                NM_FLAGS_UNSET (device->obj->link.n_ifi_flags, IFF_NOARP));
	return TRUE;
}

static gboolean
link_set_noarp (NMPlatform *platform, int ifindex)
{
	NMFakePlatformLink *device = link_get (platform, ifindex);

	if (!device) {
		_LOGE ("failure changing link: netlink error (No such device)");
		return FALSE;
	}

	link_set_flags (platform,
	                device,
	                NM_FLAGS_SET (device->obj->link.n_ifi_flags, IFF_NOARP));
	return TRUE;
}

static NMPlatformError
link_set_address (NMPlatform *platform, int ifindex, gconstpointer addr, size_t len)
{
	NMFakePlatformLink *device = link_get (platform, ifindex);
	nm_auto_nmpobj NMPObject *obj_tmp = NULL;

	if (   len == 0
	    || len > NM_UTILS_HWADDR_LEN_MAX
	    || !addr)
		g_return_val_if_reached (NM_PLATFORM_ERROR_BUG);

	if (!device)
		return NM_PLATFORM_ERROR_EXISTS;

	obj_tmp = nmp_object_clone (device->obj, FALSE);
	obj_tmp->link.addr.len = len;
	memset (obj_tmp->link.addr.data, 0, sizeof (obj_tmp->link.addr.data));
	memcpy (obj_tmp->link.addr.data, addr, len);

	link_set_obj (platform, device, obj_tmp);
	return NM_PLATFORM_ERROR_SUCCESS;
}

static NMPlatformError
link_set_mtu (NMPlatform *platform, int ifindex, guint32 mtu)
{
	NMFakePlatformLink *device = link_get (platform, ifindex);
	nm_auto_nmpobj NMPObject *obj_tmp = NULL;

	if (!device) {
		_LOGE ("failure changing link: netlink error (No such device)");
		return NM_PLATFORM_ERROR_EXISTS;
	}

	obj_tmp = nmp_object_clone (device->obj, FALSE);
	obj_tmp->link.mtu = mtu;
	link_set_obj (platform, device, obj_tmp);
	return NM_PLATFORM_ERROR_SUCCESS;
}

static gboolean
link_set_sriov_num_vfs (NMPlatform *platform, int ifindex, guint num_vfs)
{
	return TRUE;
}

static const char *
link_get_udi (NMPlatform *platform, int ifindex)
{
	NMFakePlatformLink *device = link_get (platform, ifindex);

	if (!device)
		return NULL;
	return device->udi;
}

static gboolean
link_get_driver_info (NMPlatform *platform,
                      int ifindex,
                      char **out_driver_name,
                      char **out_driver_version,
                      char **out_fw_version)
{
	if (out_driver_name)
		*out_driver_name = NULL;
	if (out_driver_version)
		*out_driver_version = NULL;
	if (out_fw_version)
		*out_fw_version = NULL;

	return TRUE;
}

static gboolean
link_supports_carrier_detect (NMPlatform *platform, int ifindex)
{
	NMFakePlatformLink *device = link_get (platform, ifindex);

	if (!device)
		return FALSE;

	switch (device->obj->link.type) {
	case NM_LINK_TYPE_DUMMY:
		return FALSE;
	default:
		return TRUE;
	}
}

static gboolean
link_supports_vlans (NMPlatform *platform, int ifindex)
{
	NMFakePlatformLink *device = link_get (platform, ifindex);

	if (!device)
		return FALSE;

	switch (device->obj->link.type) {
	case NM_LINK_TYPE_LOOPBACK:
		return FALSE;
	default:
		return TRUE;
	}
}

static gboolean
link_supports_sriov (NMPlatform *platform, int ifindex)
{
	NMFakePlatformLink *device = link_get (platform, ifindex);

	if (!device)
		return FALSE;

	switch (device->obj->link.type) {
	case NM_LINK_TYPE_LOOPBACK:
		return FALSE;
	default:
		return TRUE;
	}
}

static gboolean
link_enslave (NMPlatform *platform, int master, int slave)
{
	NMFakePlatformLink *device = link_get (platform, slave);
	NMFakePlatformLink *master_device = link_get (platform, master);

	g_return_val_if_fail (device, FALSE);
	g_return_val_if_fail (master_device, FALSE);

	if (device->obj->link.master != master) {
		nm_auto_nmpobj NMPObject *obj_tmp = NULL;

		obj_tmp = nmp_object_clone (device->obj, FALSE);
		obj_tmp->link.master = master;
		if (NM_IN_SET (master_device->obj->link.type, NM_LINK_TYPE_BOND, NM_LINK_TYPE_TEAM))
			obj_tmp->link.n_ifi_flags = NM_FLAGS_SET (device->obj->link.n_ifi_flags, IFF_UP);
		link_set_obj (platform, device, obj_tmp);
	}

	return TRUE;
}

static gboolean
link_release (NMPlatform *platform, int master_idx, int slave_idx)
{
	NMFakePlatformLink *master = link_get (platform, master_idx);
	NMFakePlatformLink *slave = link_get (platform, slave_idx);
	nm_auto_nmpobj NMPObject *obj_tmp = NULL;

	g_return_val_if_fail (master, FALSE);
	g_return_val_if_fail (slave, FALSE);

	if (slave->obj->link.master != master->obj->link.ifindex)
		return FALSE;

	obj_tmp = nmp_object_clone (slave->obj, FALSE);
	obj_tmp->link.master = 0;
	link_set_obj (platform, slave, obj_tmp);
	return TRUE;
}

struct vlan_add_data {
	guint32 vlan_flags;
	int parent;
	int vlan_id;
};

static void
_vlan_add_prepare (NMPlatform *platform,
                   NMFakePlatformLink *device,
                   gconstpointer user_data)
{
	const struct vlan_add_data *d = user_data;
	NMPObject *obj_tmp;
	NMPObject *lnk;

	obj_tmp = (NMPObject *) device->obj;

	lnk = nmp_object_new (NMP_OBJECT_TYPE_LNK_VLAN, NULL);
	lnk->lnk_vlan.id = d->vlan_id;
	lnk->lnk_vlan.flags = d->vlan_flags;

	obj_tmp->link.parent = d->parent;
	obj_tmp->_link.netlink.lnk = lnk;
}

static gboolean
vlan_add (NMPlatform *platform, const char *name, int parent, int vlan_id, guint32 vlan_flags, const NMPlatformLink **out_link)
{
	const struct vlan_add_data d = {
		.parent = parent,
		.vlan_id = vlan_id,
		.vlan_flags = vlan_flags,
	};

	link_add_one (platform, name, NM_LINK_TYPE_VLAN,
	              _vlan_add_prepare, &d, out_link);
	return TRUE;
}

static gboolean
link_vlan_change (NMPlatform *platform,
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
	return FALSE;
}

static void
_vxlan_add_prepare (NMPlatform *platform,
                    NMFakePlatformLink *device,
                    gconstpointer user_data)
{
	const NMPlatformLnkVxlan *props = user_data;
	NMPObject *obj_tmp;
	NMPObject *lnk;

	obj_tmp = (NMPObject *) device->obj;

	lnk = nmp_object_new (NMP_OBJECT_TYPE_LNK_VXLAN, NULL);
	lnk->lnk_vxlan = *props;

	obj_tmp->link.parent = props->parent_ifindex;
	obj_tmp->_link.netlink.lnk = lnk;
}

static gboolean
link_vxlan_add (NMPlatform *platform,
                const char *name,
                const NMPlatformLnkVxlan *props,
                const NMPlatformLink **out_link)
{
	link_add_one (platform, name, NM_LINK_TYPE_VXLAN,
	              _vxlan_add_prepare, props, out_link);
	return TRUE;
}

struct infiniband_add_data {
	int parent;
	int p_key;
};

static void
_infiniband_add_prepare (NMPlatform *platform,
                         NMFakePlatformLink *device,
                         gconstpointer user_data)
{
	const struct infiniband_add_data *d = user_data;
	NMPObject *obj_tmp;
	NMPObject *lnk;

	obj_tmp = (NMPObject *) device->obj;

	lnk = nmp_object_new (NMP_OBJECT_TYPE_LNK_INFINIBAND, NULL);
	lnk->lnk_infiniband.p_key = d->p_key;
	lnk->lnk_infiniband.mode = "datagram";

	obj_tmp->link.parent = d->parent;
	obj_tmp->_link.netlink.lnk = lnk;
}

static gboolean
infiniband_partition_add (NMPlatform *platform, int parent, int p_key, const NMPlatformLink **out_link)
{
	NMFakePlatformLink *parent_device;
	char name[IFNAMSIZ];
	const struct infiniband_add_data d = {
		.parent = parent,
		.p_key = p_key,
	};

	parent_device = link_get (platform, parent);
	g_return_val_if_fail (parent_device != NULL, FALSE);

	nm_utils_new_infiniband_name (name, parent_device->obj->link.name, p_key);

	link_add_one (platform, name, NM_LINK_TYPE_INFINIBAND,
	              _infiniband_add_prepare, &d, out_link);
	return TRUE;
}

static gboolean
infiniband_partition_delete (NMPlatform *platform, int parent, int p_key)
{
	NMFakePlatformLink *parent_device;
	gs_free char *name = NULL;

	parent_device = link_get (platform, parent);
	g_return_val_if_fail (parent_device != NULL, FALSE);

	nm_utils_new_infiniband_name (name, parent_device->obj->link.name, p_key);
	return link_delete (platform, nm_platform_link_get_ifindex (platform, name));
}

static gboolean
wifi_get_capabilities (NMPlatform *platform, int ifindex, NMDeviceWifiCapabilities *caps)
{
	NMFakePlatformLink *device = link_get (platform, ifindex);

	g_return_val_if_fail (device, FALSE);

	if (device->obj->link.type != NM_LINK_TYPE_WIFI)
		return FALSE;

	if (caps) {
		*caps = (  NM_WIFI_DEVICE_CAP_CIPHER_WEP40
		         | NM_WIFI_DEVICE_CAP_CIPHER_WEP104
		         | NM_WIFI_DEVICE_CAP_CIPHER_TKIP
		         | NM_WIFI_DEVICE_CAP_CIPHER_CCMP
		         | NM_WIFI_DEVICE_CAP_WPA
		         | NM_WIFI_DEVICE_CAP_RSN
		         | NM_WIFI_DEVICE_CAP_AP
		         | NM_WIFI_DEVICE_CAP_ADHOC);
	}
	return TRUE;
}

static gboolean
wifi_get_bssid (NMPlatform *platform, int ifindex, guint8 *bssid)
{
	return FALSE;
}

static GByteArray *
wifi_get_ssid (NMPlatform *platform, int ifindex)
{
	return NULL;
}

static guint32
wifi_get_frequency (NMPlatform *platform, int ifindex)
{
	return 0;
}

static int
wifi_get_quality (NMPlatform *platform, int ifindex)
{
	return 0;
}

static guint32
wifi_get_rate (NMPlatform *platform, int ifindex)
{
	return 0;
}

static NM80211Mode
wifi_get_mode (NMPlatform *platform, int ifindex)
{
	return NM_802_11_MODE_UNKNOWN;
}

static void
wifi_set_mode (NMPlatform *platform, int ifindex, NM80211Mode mode)
{
	;
}

static guint32
wifi_find_frequency (NMPlatform *platform, int ifindex, const guint32 *freqs)
{
	return freqs[0];
}

static void
wifi_indicate_addressing_running (NMPlatform *platform, int ifindex, gboolean running)
{
}

static guint32
mesh_get_channel (NMPlatform *platform, int ifindex)
{
	return 0;
}

static gboolean
mesh_set_channel (NMPlatform *platform, int ifindex, guint32 channel)
{
	return FALSE;
}

static gboolean
mesh_set_ssid (NMPlatform *platform, int ifindex, const guint8 *ssid, gsize len)
{
	return FALSE;
}

/*****************************************************************************/

static gboolean
ipx_address_add (NMPlatform *platform, int addr_family, const NMPlatformObject *address)
{
	nm_auto_nmpobj NMPObject *obj = NULL;
	NMPCacheOpsType cache_op;
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	nm_auto_nmpobj const NMPObject *obj_new = NULL;
	NMPCache *cache = nm_platform_get_cache (platform);

	g_assert (NM_IN_SET (addr_family, AF_INET, AF_INET6));

	obj = nmp_object_new (addr_family == AF_INET
	                        ? NMP_OBJECT_TYPE_IP4_ADDRESS
	                        : NMP_OBJECT_TYPE_IP6_ADDRESS,
	                      address);

	cache_op = nmp_cache_update_netlink (cache, obj, FALSE, &obj_old, &obj_new);
	nm_platform_cache_update_emit_signal (platform, cache_op, obj_old, obj_new);
	return TRUE;
}

static gboolean
ip4_address_add (NMPlatform *platform,
                 int ifindex,
                 in_addr_t addr,
                 guint8 plen,
                 in_addr_t peer_addr,
                 guint32 lifetime,
                 guint32 preferred,
                 guint32 flags,
                 const char *label)
{
	NMPlatformIP4Address address;

	memset (&address, 0, sizeof (address));
	address.addr_source = NM_IP_CONFIG_SOURCE_KERNEL;
	address.ifindex = ifindex;
	address.address = addr;
	address.peer_address = peer_addr;
	address.plen = plen;
	address.timestamp = nm_utils_get_monotonic_timestamp_s ();
	address.lifetime = lifetime;
	address.preferred = preferred;
	address.n_ifa_flags = flags;
	if (label)
		g_strlcpy (address.label, label, sizeof (address.label));

	return ipx_address_add (platform, AF_INET, (const NMPlatformObject *) &address);
}

static gboolean
ip6_address_add (NMPlatform *platform,
                 int ifindex,
                 struct in6_addr addr,
                 guint8 plen,
                 struct in6_addr peer_addr,
                 guint32 lifetime,
                 guint32 preferred,
                 guint32 flags)
{
	NMPlatformIP6Address address;

	memset (&address, 0, sizeof (address));
	address.addr_source = NM_IP_CONFIG_SOURCE_KERNEL;
	address.ifindex = ifindex;
	address.address = addr;
	address.peer_address = (IN6_IS_ADDR_UNSPECIFIED (&peer_addr) || IN6_ARE_ADDR_EQUAL (&addr, &peer_addr)) ? in6addr_any : peer_addr;
	address.plen = plen;
	address.timestamp = nm_utils_get_monotonic_timestamp_s ();
	address.lifetime = lifetime;
	address.preferred = preferred;
	address.n_ifa_flags = flags;

	return ipx_address_add (platform, AF_INET6, (const NMPlatformObject *) &address);
}

static gboolean
ipx_address_delete (NMPlatform *platform,
                    int addr_family,
                    int ifindex,
                    gconstpointer addr,
                    const guint8 *plen,
                    gconstpointer peer_addr)
{
	gs_unref_ptrarray GPtrArray *objs = g_ptr_array_new_with_free_func ((GDestroyNotify) nmp_object_unref);
	NMDedupMultiIter iter;
	const NMPObject *o = NULL;
	guint i;
	guint32 peer_addr_i;

	g_assert (NM_IN_SET (addr_family, AF_INET, AF_INET6));

	peer_addr_i = peer_addr ? *((guint32 *) peer_addr) : 0;

	nmp_cache_iter_for_each (&iter,
	                         nm_platform_lookup_object (platform,
	                                                    addr_family == AF_INET
	                                                      ? NMP_OBJECT_TYPE_IP4_ADDRESS
	                                                      : NMP_OBJECT_TYPE_IP6_ADDRESS,
	                                                    0),
	                         &o) {
		const NMPObject *obj_old = NULL;

		if (addr_family == AF_INET) {
			const NMPlatformIP4Address *address = NMP_OBJECT_CAST_IP4_ADDRESS (o);

			if (   address->ifindex != ifindex
			    || (addr && address->address != *((guint32 *) addr))
			    || (plen && address->plen != *plen)
			    || (   peer_addr
			        && (((peer_addr_i ^ address->peer_address) & _nm_utils_ip4_prefix_to_netmask (address->plen)) != 0)))
				continue;
		} else {
			const NMPlatformIP6Address *address = NMP_OBJECT_CAST_IP6_ADDRESS (o);

			g_assert (!peer_addr);
			if (   address->ifindex != ifindex
			    || (addr && !IN6_ARE_ADDR_EQUAL (&address->address, addr))
			    || (plen && address->plen != *plen))
				continue;
		}

		if (nmp_cache_remove (nm_platform_get_cache (platform),
		                      o,
		                      TRUE,
		                      FALSE,
		                      &obj_old) != NMP_CACHE_OPS_REMOVED)
			g_assert_not_reached ();
		g_assert (obj_old);
		g_ptr_array_add (objs, (gpointer) obj_old);
	}

	for (i = 0; i < objs->len; i++) {
		nm_platform_cache_update_emit_signal (platform,
		                                      NMP_CACHE_OPS_REMOVED,
		                                      objs->pdata[i],
		                                      NULL);
	}
	return TRUE;
}

static gboolean
ip4_address_delete (NMPlatform *platform, int ifindex, in_addr_t addr, guint8 plen, in_addr_t peer_address)
{
	return ipx_address_delete (platform, AF_INET, ifindex, &addr, &plen, &peer_address);
}

static gboolean
ip6_address_delete (NMPlatform *platform, int ifindex, struct in6_addr addr, guint8 plen)
{
	return ipx_address_delete (platform, AF_INET6, ifindex, &addr, &plen, NULL);
}

/*****************************************************************************/

static gboolean
ipx_route_delete (NMPlatform *platform,
                  int addr_family,
                  int ifindex,
                  const NMPObject *obj)
{
	gs_unref_ptrarray GPtrArray *objs = g_ptr_array_new_with_free_func ((GDestroyNotify) nmp_object_unref);
	NMDedupMultiIter iter;
	const NMPObject *o = NULL;
	guint i;
	NMPObjectType obj_type;

	if (addr_family == AF_UNSPEC) {
		g_assert (NM_IN_SET (NMP_OBJECT_GET_TYPE (obj), NMP_OBJECT_TYPE_IP4_ROUTE,
		                                                NMP_OBJECT_TYPE_IP6_ROUTE));
		g_assert (ifindex == -1);
		ifindex = obj->object.ifindex;
		obj_type = NMP_OBJECT_GET_TYPE (obj);
	} else {
		g_assert (NM_IN_SET (addr_family, AF_INET, AF_INET6));
		g_assert (!obj);
		g_assert (ifindex > 0);
		obj_type =   addr_family == AF_INET
	               ? NMP_OBJECT_TYPE_IP4_ROUTE
	               : NMP_OBJECT_TYPE_IP6_ROUTE;
	}

	nmp_cache_iter_for_each (&iter,
	                         nm_platform_lookup_object (platform,
	                                                    obj_type,
	                                                    ifindex),
	                         &o) {
		const NMPObject *obj_old = NULL;

		if (obj) {
			if (obj_type == NMP_OBJECT_TYPE_IP4_ROUTE) {
				const NMPlatformIP4Route *route = NMP_OBJECT_CAST_IP4_ROUTE (o);
				const NMPlatformIP4Route *r = NMP_OBJECT_CAST_IP4_ROUTE (obj);

				if (   route->network != r->network
				    || route->plen != r->plen
				    || route->metric != r->metric)
					continue;
			} else {
				const NMPlatformIP6Route *route = NMP_OBJECT_CAST_IP6_ROUTE (o);
				const NMPlatformIP6Route *r = NMP_OBJECT_CAST_IP6_ROUTE (obj);

				if (   !IN6_ARE_ADDR_EQUAL (&route->network, &r->network)
				    || route->plen != r->plen
				    || route->metric != r->metric)
					continue;
			}
		}

		if (nmp_cache_remove (nm_platform_get_cache (platform),
		                      o,
		                      TRUE,
		                      FALSE,
		                      &obj_old) != NMP_CACHE_OPS_REMOVED)
			g_assert_not_reached ();
		g_assert (obj_old);
		g_ptr_array_add (objs, (gpointer) obj_old);
	}

	for (i = 0; i < objs->len; i++) {
		nm_platform_cache_update_emit_signal (platform,
		                                      NMP_CACHE_OPS_REMOVED,
		                                      objs->pdata[i],
		                                      NULL);
	}
	return TRUE;
}

static gboolean
object_delete (NMPlatform *platform, const NMPObject *obj)
{
	g_assert (NM_IS_FAKE_PLATFORM (platform));
	g_assert (NM_IN_SET (NMP_OBJECT_GET_TYPE (obj), NMP_OBJECT_TYPE_IP4_ROUTE,
	                                                NMP_OBJECT_TYPE_IP6_ROUTE));

	return ipx_route_delete (platform, AF_UNSPEC, -1, obj);
}

static NMPlatformError
ip_route_add (NMPlatform *platform,
              NMPNlmFlags flags,
              int addr_family,
              const NMPlatformIPRoute *route)
{
	NMDedupMultiIter iter;
	nm_auto_nmpobj NMPObject *obj = NULL;
	NMPCacheOpsType cache_op;
	const NMPObject *o = NULL;
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	nm_auto_nmpobj const NMPObject *obj_new = NULL;
	nm_auto_nmpobj const NMPObject *obj_replace = NULL;
	NMPCache *cache = nm_platform_get_cache (platform);
	gboolean has_gateway = FALSE;
	NMPlatformIPRoute *r = NULL;
	NMPlatformIP4Route *r4 = NULL;
	NMPlatformIP6Route *r6 = NULL;
	gboolean has_same_weak_id;
	gboolean only_dirty;
	guint16 nlmsgflags;

	g_assert (NM_IN_SET (addr_family, AF_INET, AF_INET6));

	flags = NM_FLAGS_UNSET (flags, NMP_NLM_FLAG_SUPPRESS_NETLINK_FAILURE);

	/* currently, only replace is implemented. */
	g_assert (flags == NMP_NLM_FLAG_REPLACE);

	obj = nmp_object_new (addr_family == AF_INET
	                        ? NMP_OBJECT_TYPE_IP4_ROUTE
	                        : NMP_OBJECT_TYPE_IP6_ROUTE,
	                      (const NMPlatformObject *) route);
	r = NMP_OBJECT_CAST_IP_ROUTE (obj);
	nm_platform_ip_route_normalize (addr_family, r);

	switch (addr_family) {
	case AF_INET:
		r4 = NMP_OBJECT_CAST_IP4_ROUTE (obj);
		if (r4->gateway)
			has_gateway = TRUE;
		break;
	case AF_INET6:
		r6 = NMP_OBJECT_CAST_IP6_ROUTE (obj);
		if (!IN6_IS_ADDR_UNSPECIFIED (&r6->gateway))
			has_gateway = TRUE;
		break;
	default:
		nm_assert_not_reached ();
	}

	if (has_gateway) {
		gboolean has_route_to_gw = FALSE;

		nmp_cache_iter_for_each (&iter,
		                         nm_platform_lookup_object (platform,
		                                                    NMP_OBJECT_GET_TYPE (obj),
		                                                    0),
		                         &o) {
			if (addr_family == AF_INET) {
				const NMPlatformIP4Route *item = NMP_OBJECT_CAST_IP4_ROUTE (o);
				guint32 n = nm_utils_ip4_address_clear_host_address (item->network, item->plen);
				guint32 g = nm_utils_ip4_address_clear_host_address (r4->gateway, item->plen);

				if (   r->ifindex == item->ifindex
				    && n == g) {
					has_route_to_gw = TRUE;
					break;
				}
			} else {
				const NMPlatformIP6Route *item = NMP_OBJECT_CAST_IP6_ROUTE (o);

				if (   r->ifindex == item->ifindex
				    && nm_utils_ip6_address_same_prefix (&r6->gateway, &item->network, item->plen)) {
					has_route_to_gw = TRUE;
					break;
				}
			}
		}
		if (!has_route_to_gw) {
			if (addr_family == AF_INET) {
				nm_log_warn (LOGD_PLATFORM, "Fake platform: failure adding ip4-route '%d: %s/%d %d': Network Unreachable",
				             r->ifindex, nm_utils_inet4_ntop (r4->network, NULL), r->plen, r->metric);
			} else {
				nm_log_warn (LOGD_PLATFORM, "Fake platform: failure adding ip6-route '%d: %s/%d %d': Network Unreachable",
				             r->ifindex, nm_utils_inet6_ntop (&r6->network, NULL), r->plen, r->metric);
			}
			return NM_PLATFORM_ERROR_UNSPECIFIED;
		}
	}

	has_same_weak_id = FALSE;
	nmp_cache_iter_for_each (&iter,
	                         nm_platform_lookup_all (platform,
	                                                 NMP_CACHE_ID_TYPE_ROUTES_BY_WEAK_ID,
	                                                 obj),
	                         &o) {
		if (addr_family == AF_INET) {
			if (nm_platform_ip4_route_cmp (NMP_OBJECT_CAST_IP4_ROUTE (o), r4, NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID) == 0)
				continue;
		} else {
			if (nm_platform_ip6_route_cmp (NMP_OBJECT_CAST_IP6_ROUTE (o), r6, NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID) == 0)
				continue;
		}
		has_same_weak_id = TRUE;
	}

	nlmsgflags = 0;
	if (has_same_weak_id) {
		switch (flags) {
		case NMP_NLM_FLAG_REPLACE:
			nlmsgflags = NLM_F_REPLACE;
			break;
		default:
			g_assert_not_reached ();
			break;
		}
	}

	/* we manipulate the cache the same was as NMLinuxPlatform does it. */
	cache_op = nmp_cache_update_netlink_route (cache,
	                                           obj,
	                                           FALSE,
	                                           nlmsgflags,
	                                           &obj_old,
	                                           &obj_new,
	                                           &obj_replace,
	                                           NULL);
	only_dirty = FALSE;
	if (cache_op != NMP_CACHE_OPS_UNCHANGED) {
		if (obj_replace) {
			const NMDedupMultiEntry *entry_replace;

			entry_replace = nmp_cache_lookup_entry (cache, obj_replace);
			nm_assert (entry_replace && entry_replace->obj == obj_replace);
			nm_dedup_multi_entry_set_dirty (entry_replace, TRUE);
			only_dirty = TRUE;
		}
		nm_platform_cache_update_emit_signal (platform, cache_op, obj_old, obj_new);
	}

	if (obj_replace) {
		cache_op = nmp_cache_remove (cache, obj_replace, TRUE, only_dirty, NULL);
		if (cache_op != NMP_CACHE_OPS_UNCHANGED) {
			nm_assert (cache_op == NMP_CACHE_OPS_REMOVED);
			nm_platform_cache_update_emit_signal (platform, cache_op, obj_replace, NULL);
		}
	}

	return NM_PLATFORM_ERROR_SUCCESS;
}

/*****************************************************************************/

static void
nm_fake_platform_init (NMFakePlatform *fake_platform)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (fake_platform);

	priv->options = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_free);
	priv->links = g_array_new (TRUE, TRUE, sizeof (NMFakePlatformLink));
}

void
nm_fake_platform_setup (void)
{
	NMPlatform *platform;

	platform = g_object_new (NM_TYPE_FAKE_PLATFORM,
	                         NM_PLATFORM_LOG_WITH_PTR, FALSE,
	                         NULL);

	nm_platform_setup (platform);

	/* add loopback interface */
	link_add (platform, "lo", NM_LINK_TYPE_LOOPBACK, NULL, NULL, 0, NULL);

	/* add some ethernets */
	link_add (platform, "eth0", NM_LINK_TYPE_ETHERNET, NULL, NULL, 0, NULL);
	link_add (platform, "eth1", NM_LINK_TYPE_ETHERNET, NULL, NULL, 0, NULL);
	link_add (platform, "eth2", NM_LINK_TYPE_ETHERNET, NULL, NULL, 0, NULL);
}

static void
finalize (GObject *object)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE ((NMFakePlatform *) object);
	int i;

	g_hash_table_unref (priv->options);
	for (i = 0; i < priv->links->len; i++) {
		NMFakePlatformLink *device = &g_array_index (priv->links, NMFakePlatformLink, i);

		g_free (device->udi);
		g_clear_pointer (&device->obj, nmp_object_unref);
	}
	g_array_unref (priv->links);

	G_OBJECT_CLASS (nm_fake_platform_parent_class)->finalize (object);
}

static void
nm_fake_platform_class_init (NMFakePlatformClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMPlatformClass *platform_class = NM_PLATFORM_CLASS (klass);

	object_class->finalize = finalize;

	platform_class->sysctl_set = sysctl_set;
	platform_class->sysctl_get = sysctl_get;

	platform_class->link_add = link_add;
	platform_class->link_delete = link_delete;

	platform_class->link_get_udi = link_get_udi;

	platform_class->link_set_up = link_set_up;
	platform_class->link_set_down = link_set_down;
	platform_class->link_set_arp = link_set_arp;
	platform_class->link_set_noarp = link_set_noarp;

	platform_class->link_set_address = link_set_address;
	platform_class->link_set_mtu = link_set_mtu;
	platform_class->link_set_sriov_num_vfs = link_set_sriov_num_vfs;

	platform_class->link_get_driver_info = link_get_driver_info;

	platform_class->link_supports_carrier_detect = link_supports_carrier_detect;
	platform_class->link_supports_vlans = link_supports_vlans;
	platform_class->link_supports_sriov = link_supports_sriov;

	platform_class->link_enslave = link_enslave;
	platform_class->link_release = link_release;

	platform_class->vlan_add = vlan_add;
	platform_class->link_vlan_change = link_vlan_change;
	platform_class->link_vxlan_add = link_vxlan_add;

	platform_class->infiniband_partition_add = infiniband_partition_add;
	platform_class->infiniband_partition_delete = infiniband_partition_delete;

	platform_class->wifi_get_capabilities = wifi_get_capabilities;
	platform_class->wifi_get_bssid = wifi_get_bssid;
	platform_class->wifi_get_ssid = wifi_get_ssid;
	platform_class->wifi_get_frequency = wifi_get_frequency;
	platform_class->wifi_get_quality = wifi_get_quality;
	platform_class->wifi_get_rate = wifi_get_rate;
	platform_class->wifi_get_mode = wifi_get_mode;
	platform_class->wifi_set_mode = wifi_set_mode;
	platform_class->wifi_find_frequency = wifi_find_frequency;
	platform_class->wifi_indicate_addressing_running = wifi_indicate_addressing_running;

	platform_class->mesh_get_channel = mesh_get_channel;
	platform_class->mesh_set_channel = mesh_set_channel;
	platform_class->mesh_set_ssid = mesh_set_ssid;

	platform_class->ip4_address_add = ip4_address_add;
	platform_class->ip6_address_add = ip6_address_add;
	platform_class->ip4_address_delete = ip4_address_delete;
	platform_class->ip6_address_delete = ip6_address_delete;

	platform_class->ip_route_add = ip_route_add;
	platform_class->object_delete = object_delete;
}
