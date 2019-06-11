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
 * Copyright (C) 2015 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include <libudev.h>
#include <linux/pkt_sched.h>

#include "platform/nmp-object.h"
#include "nm-udev-aux/nm-udev-utils.h"

#include "nm-test-utils-core.h"

struct {
	GList *udev_devices;
} global;

/*****************************************************************************/

static void
test_obj_base (void)
{
	static const union {
		GObject g;
		NMPObject k;
	} x = { };
	static const union {
		GTypeClass k;
		NMPClass c;
	} l = { };
	static const GObject *g = &x.g;
	static const GTypeClass *k = &l.k;
	static const NMPObject *o = &x.k;
	static const NMPClass *c = &l.c;

	NMObjBaseInst *obj;
	gs_unref_object GCancellable *obj_cancellable = g_cancellable_new ();
	nm_auto_nmpobj NMPObject *obj_link = nmp_object_new_link (10);

	g_assert (&g->g_type_instance              == (void *) &o->_class);
	g_assert (&g->g_type_instance.g_class      == (void *) &o->_class);

	g_assert (sizeof (o->parent.parent)        == sizeof (GTypeInstance));

	g_assert (&c->parent                       == (void *) c);
	g_assert (&c->parent.parent.g_type_class   == (void *) c);
	g_assert (&c->parent.parent.g_type         == (void *) c);
	g_assert (&c->parent.parent.g_type         == &k->g_type);

	g_assert (sizeof (c->parent.parent)        == sizeof (GTypeClass));

	g_assert (&o->parent                       == (void *) o);
	g_assert (&o->parent.klass                 == (void *) &o->_class);

	obj = (NMObjBaseInst *) obj_cancellable;
	g_assert (!NMP_CLASS_IS_VALID ((NMPClass *) obj->klass));
	g_assert (G_TYPE_CHECK_INSTANCE_TYPE (obj, G_TYPE_CANCELLABLE));

	obj = (NMObjBaseInst *) obj_link;
	g_assert (NMP_CLASS_IS_VALID ((NMPClass *) obj->klass));
	g_assert (!G_TYPE_CHECK_INSTANCE_TYPE (obj, G_TYPE_CANCELLABLE));

}

/*****************************************************************************/

static gboolean
_nmp_object_id_equal (const NMPObject *a, const NMPObject *b)
{
	gboolean a_b = nmp_object_id_equal (a, b);

	g_assert (NM_IN_SET (a_b, FALSE, TRUE) && a_b == nmp_object_id_equal (b, a));
	return a_b;
}
#define nmp_object_id_equal _nmp_object_id_equal

static gboolean
_nmp_object_equal (const NMPObject *a, const NMPObject *b)
{
	gboolean a_b = nmp_object_equal (a, b);

	g_assert (NM_IN_SET (a_b, FALSE, TRUE) && a_b == nmp_object_equal (b, a));
	return a_b;
}
#define nmp_object_equal _nmp_object_equal

/*****************************************************************************/

static void
_assert_cache_multi_lookup_contains (const NMPCache *cache, const NMDedupMultiHeadEntry *head_entry, const NMPObject *obj, gboolean visible_only, gboolean contains)
{
	NMDedupMultiIter iter;
	gboolean found;
	guint i, len;
	const NMPObject *o;

	g_assert (NMP_OBJECT_IS_VALID (obj));

	g_assert (nmp_cache_lookup_obj (cache, obj) == obj);
	g_assert (!head_entry || (head_entry->len > 0 && c_list_length (&head_entry->lst_entries_head) == head_entry->len));

	len = head_entry ? head_entry->len : 0;

	found = FALSE;
	i = 0;
	nmp_cache_iter_for_each (&iter,
	                         head_entry,
	                         &o) {
		g_assert (NMP_OBJECT_IS_VALID (o));
		if (obj == o) {
			if (   !visible_only
			    || nmp_object_is_visible (o)) {
				g_assert (!found);
				found = TRUE;
			}
		}
		i++;
	}

	g_assert (len == i);
	g_assert (!!contains == found);
}

static void
_assert_cache_multi_lookup_contains_link (const NMPCache *cache,
                                          gboolean visible_only,
                                          const NMPObject *obj,
                                          gboolean contains)
{
	const NMDedupMultiHeadEntry *head_entry;
	NMPLookup lookup;

	g_assert (cache);

	nmp_lookup_init_obj_type (&lookup, NMP_OBJECT_TYPE_LINK);
	head_entry = nmp_cache_lookup (cache, &lookup);
	_assert_cache_multi_lookup_contains (cache, head_entry, obj, visible_only, contains);
}

/*****************************************************************************/

static void
ops_post_check (NMPCache *cache,
                NMPCacheOpsType ops_type,
                const NMPObject *obj_old,
                const NMPObject *obj_new,
                const NMPObject *obj_new_expected,
                NMPCacheOpsType expected_ops_type)
{
	g_assert (cache);

	g_assert_cmpint (expected_ops_type, ==, ops_type);

	switch (ops_type) {
	case NMP_CACHE_OPS_ADDED:
		g_assert (!obj_old);
		g_assert (NMP_OBJECT_IS_VALID (obj_new));
		g_assert (nmp_object_is_alive (obj_new));
		g_assert (nmp_object_id_equal (obj_new_expected, obj_new));
		g_assert (nmp_object_equal (obj_new_expected, obj_new));
		break;
	case NMP_CACHE_OPS_UPDATED:
		g_assert (obj_old != obj_new);
		g_assert (NMP_OBJECT_IS_VALID (obj_old));
		g_assert (NMP_OBJECT_IS_VALID (obj_new));
		g_assert (nmp_object_is_alive (obj_old));
		g_assert (nmp_object_is_alive (obj_new));
		g_assert (nmp_object_id_equal (obj_new_expected, obj_new));
		g_assert (nmp_object_id_equal (obj_new_expected, obj_old));
		g_assert (nmp_object_id_equal (obj_old, obj_new));
		g_assert (nmp_object_equal (obj_new_expected, obj_new));
		g_assert (!nmp_object_equal (obj_new_expected, obj_old));
		g_assert (!nmp_object_equal (obj_old, obj_new));
		break;
	case NMP_CACHE_OPS_REMOVED:
		g_assert (!obj_new);
		g_assert (NMP_OBJECT_IS_VALID (obj_old));
		g_assert (nmp_object_is_alive (obj_old));
		if (obj_new_expected)
			g_assert (nmp_object_id_equal (obj_new_expected, obj_old));
		break;
	case NMP_CACHE_OPS_UNCHANGED:
		g_assert (obj_old == obj_new);
		if (obj_old) {
			g_assert (NMP_OBJECT_IS_VALID (obj_old));
			g_assert (nmp_object_is_alive (obj_old));
			g_assert (nmp_object_equal (obj_old, obj_new));
			g_assert (nmp_object_id_equal (obj_new_expected, obj_new));
		} else
			g_assert (!obj_new_expected);
		break;
	default:
		g_assert_not_reached ();
	}
}

static void
_nmp_cache_update_netlink (NMPCache *cache, NMPObject *obj, const NMPObject **out_obj_old, const NMPObject **out_obj_new, NMPCacheOpsType expected_ops_type)
{
	NMPCacheOpsType ops_type;
	const NMPObject *obj_prev;
	const NMPObject *obj_old;
	const NMPObject *obj_new;
	nm_auto_nmpobj NMPObject *obj_new_expected = NULL;

	g_assert (cache);
	g_assert (NMP_OBJECT_IS_VALID (obj));

	obj_prev = nmp_cache_lookup_link (cache, NMP_OBJECT_CAST_LINK (obj)->ifindex);
	obj_new_expected = nmp_object_clone (obj, FALSE);
	if (obj_prev && obj_prev->_link.udev.device)
		obj_new_expected->_link.udev.device = udev_device_ref (obj_prev->_link.udev.device);
	_nmp_object_fixup_link_udev_fields (&obj_new_expected, NULL, nmp_cache_use_udev_get (cache));

	ops_type = nmp_cache_update_netlink (cache, obj, FALSE, &obj_old, &obj_new);
	ops_post_check (cache, ops_type, obj_old, obj_new,
	                nmp_object_is_alive (obj_new_expected) ? obj_new_expected : NULL,
	                expected_ops_type);

	if (out_obj_new)
		*out_obj_new = obj_new;
	else
		nmp_object_unref (obj_new);
	if (out_obj_old)
		*out_obj_old = obj_old;
	else
		nmp_object_unref (obj_old);
}

static const NMPlatformLink pl_link_2 = {
	.ifindex = 2,
	.name = "eth0",
	.type = NM_LINK_TYPE_ETHERNET,
};

static const NMPlatformLink pl_link_3 = {
	.ifindex = 3,
	.name = "wlan0",
	.type = NM_LINK_TYPE_WIFI,
};

static void
test_cache_link (void)
{
	NMPCache *cache;
	NMPObject *objm1;
	const NMPObject *obj_old, *obj_new;
	NMPObject objs1;
	struct udev_device *udev_device_2 = g_list_nth_data (global.udev_devices, 0);
	struct udev_device *udev_device_3 = g_list_nth_data (global.udev_devices, 0);
	NMPCacheOpsType ops_type;
	nm_auto_unref_dedup_multi_index NMDedupMultiIndex *multi_idx = NULL;
	gboolean use_udev = nmtst_get_rand_uint32 () % 2;

	multi_idx = nm_dedup_multi_index_new ();

	cache = nmp_cache_new (multi_idx, use_udev);

	/* if we have a link, and don't set is_in_netlink, adding it has no effect. */
	objm1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_2);
	g_assert (NMP_OBJECT_UP_CAST (&objm1->object) == objm1);
	g_assert (!nmp_object_is_alive (objm1));
	_nmp_cache_update_netlink (cache, objm1, &obj_old, &obj_new, NMP_CACHE_OPS_UNCHANGED);
	ASSERT_nmp_cache_is_consistent (cache);
	g_assert (!obj_old);
	g_assert (!obj_new);
	g_assert (!nmp_cache_lookup_obj (cache, objm1));
	g_assert (!nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)));
	nmp_object_unref (objm1);

	/* Only when setting @is_in_netlink the link is added. */
	objm1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_2);
	objm1->_link.netlink.is_in_netlink = TRUE;
	g_assert (nmp_object_is_alive (objm1));
	_nmp_cache_update_netlink (cache, objm1, &obj_old, &obj_new, NMP_CACHE_OPS_ADDED);
	ASSERT_nmp_cache_is_consistent (cache);
	g_assert (!obj_old);
	g_assert (obj_new);
	g_assert (objm1 == obj_new);
	g_assert (nmp_object_equal (objm1, obj_new));
	g_assert (nmp_cache_lookup_obj (cache, objm1) == obj_new);
	g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)) == obj_new);
	g_assert (nmp_object_is_visible (obj_new));
	_assert_cache_multi_lookup_contains_link (cache, FALSE, obj_new, TRUE);
	_assert_cache_multi_lookup_contains_link (cache, TRUE, obj_new, TRUE);
	nmp_object_unref (objm1);
	nmp_object_unref (obj_new);

	/* updating the same link with identical value, has no effect. */
	objm1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_2);
	objm1->_link.netlink.is_in_netlink = TRUE;
	g_assert (nmp_object_is_alive (objm1));
	_nmp_cache_update_netlink (cache, objm1, &obj_old, &obj_new, NMP_CACHE_OPS_UNCHANGED);
	ASSERT_nmp_cache_is_consistent (cache);
	g_assert (obj_old);
	g_assert (obj_new);
	g_assert (obj_new != objm1);
	g_assert (nmp_object_equal (objm1, obj_new));
	g_assert (nmp_cache_lookup_obj (cache, objm1) == obj_new);
	g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)) == obj_new);
	nmp_object_unref (objm1);
	nmp_object_unref (obj_new);
	nmp_object_unref (obj_new);

	/* remove the link from netlink */
	objm1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_2);
	g_assert (!nmp_object_is_alive (objm1));
	_nmp_cache_update_netlink (cache, objm1, &obj_old, &obj_new, NMP_CACHE_OPS_REMOVED);
	ASSERT_nmp_cache_is_consistent (cache);
	g_assert (obj_old);
	g_assert (!obj_new);
	g_assert (!nmp_cache_lookup_obj (cache, objm1));
	g_assert (!nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)));
	nmp_object_unref (objm1);
	nmp_object_unref (obj_old);
	nmp_object_unref (obj_new);

	if (udev_device_2) {
		/* now add the link only with aspect UDEV. */
		ops_type = nmp_cache_update_link_udev (cache, pl_link_2.ifindex, udev_device_2, &obj_old, &obj_new);
		ASSERT_nmp_cache_is_consistent (cache);
		g_assert_cmpint (ops_type, ==, NMP_CACHE_OPS_ADDED);
		g_assert (!obj_old);
		g_assert (obj_new);
		g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)) == obj_new);
		g_assert (!nmp_object_is_visible (obj_new));
		_assert_cache_multi_lookup_contains_link (cache, TRUE, obj_new, FALSE);
		_assert_cache_multi_lookup_contains_link (cache, FALSE, obj_new, TRUE);
		nmp_object_unref (obj_new);
	}

	/* add it in netlink too. */
	objm1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_2);
	objm1->_link.netlink.is_in_netlink = TRUE;
	g_assert (nmp_object_is_alive (objm1));
	_nmp_cache_update_netlink (cache, objm1, &obj_old, &obj_new, udev_device_2 ? NMP_CACHE_OPS_UPDATED : NMP_CACHE_OPS_ADDED);
	ASSERT_nmp_cache_is_consistent (cache);
	if (udev_device_2) {
		g_assert (obj_old);
		g_assert (!nmp_object_is_visible (obj_old));
	} else
		g_assert (!obj_old);
	g_assert (nmp_object_equal (objm1, obj_new));
	g_assert (nmp_cache_lookup_obj (cache, objm1) == obj_new);
	g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)) == obj_new);
	g_assert (nmp_object_is_visible (obj_new));
	_assert_cache_multi_lookup_contains_link (cache, TRUE, obj_new, TRUE);
	_assert_cache_multi_lookup_contains_link (cache, FALSE, obj_new, TRUE);
	nmp_object_unref (objm1);
	nmp_object_unref (obj_old);
	nmp_object_unref (obj_new);

	/* remove again from netlink. */
	objm1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_2);
	objm1->_link.netlink.is_in_netlink = FALSE;
	g_assert (!nmp_object_is_alive (objm1));
	_nmp_cache_update_netlink (cache, objm1, &obj_old, &obj_new, udev_device_2 ? NMP_CACHE_OPS_UPDATED : NMP_CACHE_OPS_REMOVED);
	ASSERT_nmp_cache_is_consistent (cache);
	if (udev_device_2)
		g_assert (obj_new == objm1);
	else
		g_assert (!obj_new);
	g_assert (obj_old);
	g_assert (nmp_object_is_alive (obj_old));
	if (udev_device_2) {
		g_assert (nmp_cache_lookup_obj (cache, objm1) == obj_new);
		g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)) == obj_new);
		g_assert (!nmp_object_is_visible (obj_new));
		_assert_cache_multi_lookup_contains_link (cache, TRUE, obj_new, FALSE);
		_assert_cache_multi_lookup_contains_link (cache, FALSE, obj_new, TRUE);
	} else {
		g_assert (nmp_cache_lookup_obj (cache, objm1) == NULL);
		g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)) == NULL);
		g_assert (!nmp_object_is_alive (obj_new));
		g_assert (!nmp_object_is_visible (obj_new));
	}
	nmp_object_unref (objm1);
	nmp_object_unref (obj_old);
	nmp_object_unref (obj_new);

	/* now another link only with aspect UDEV. */
	if (udev_device_3) {
		/* now add the link only with aspect UDEV. */
		ops_type = nmp_cache_update_link_udev (cache, pl_link_3.ifindex, udev_device_3, &obj_old, &obj_new);
		g_assert_cmpint (ops_type, ==, NMP_CACHE_OPS_ADDED);
		ASSERT_nmp_cache_is_consistent (cache);
		g_assert (NMP_OBJECT_IS_VALID (obj_new));
		g_assert (!obj_old);
		g_assert (!nmp_object_is_visible (obj_new));
		g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_3.ifindex)) == obj_new);
		_assert_cache_multi_lookup_contains_link (cache, TRUE, obj_new, FALSE);
		_assert_cache_multi_lookup_contains_link (cache, FALSE, obj_new, TRUE);
		g_assert_cmpint (obj_new->_link.netlink.is_in_netlink, ==, FALSE);
		g_assert_cmpint (obj_new->link.initialized, ==, FALSE);
		nmp_object_unref (obj_new);

		/* add it in netlink too. */
		objm1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_3);
		objm1->_link.netlink.is_in_netlink = TRUE;
		g_assert (nmp_object_is_alive (objm1));
		_nmp_cache_update_netlink (cache, objm1, &obj_old, &obj_new, NMP_CACHE_OPS_UPDATED);
		ASSERT_nmp_cache_is_consistent (cache);
		g_assert (obj_old);
		g_assert (obj_new == objm1);
		g_assert (nmp_object_equal (objm1, obj_new));
		g_assert (!obj_old || !nmp_object_is_visible (obj_old));
		g_assert (nmp_cache_lookup_obj (cache, objm1) == obj_new);
		g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_3.ifindex)) == obj_new);
		g_assert (nmp_object_is_visible (obj_new));
		_assert_cache_multi_lookup_contains_link (cache, TRUE, obj_new, TRUE);
		_assert_cache_multi_lookup_contains_link (cache, FALSE, obj_new, TRUE);
		g_assert_cmpint (obj_new->_link.netlink.is_in_netlink, ==, TRUE);
		g_assert_cmpint (obj_new->link.initialized, ==, TRUE);
		nmp_object_unref (objm1);
		nmp_object_unref (obj_old);
		nmp_object_unref (obj_new);

		/* remove UDEV. */
		ops_type = nmp_cache_update_link_udev (cache, pl_link_3.ifindex, NULL, &obj_old, &obj_new);
		g_assert_cmpint (ops_type, ==, NMP_CACHE_OPS_UPDATED);
		ASSERT_nmp_cache_is_consistent (cache);
		g_assert (obj_old && nmp_object_is_visible (obj_old));
		g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_3.ifindex)) == obj_new);
		g_assert (nmp_object_is_visible (obj_new));
		_assert_cache_multi_lookup_contains_link (cache, TRUE, obj_new, TRUE);
		_assert_cache_multi_lookup_contains_link (cache, FALSE, obj_new, TRUE);
		g_assert_cmpint (obj_new->_link.netlink.is_in_netlink, ==, TRUE);
		g_assert_cmpint (obj_new->link.initialized, ==, !nmp_cache_use_udev_get (cache));
		nmp_object_unref (obj_new);
		nmp_object_unref (obj_old);
	}

	nmp_cache_free (cache);
}

const char noqueue[] = "noqueue";
const char fq_codel[] = "fq_codel";
const char ingress[] = "ingress";

static const NMPlatformQdisc pl_qdisc_1a = {
	.ifindex = 1,
	.kind = noqueue,
	.addr_family = AF_UNSPEC,
	.handle = 0,
	.parent = TC_H_ROOT,
	.info = 0,
};

static const NMPlatformQdisc pl_qdisc_1b = {
	.ifindex = 1,
	.kind = fq_codel,
	.addr_family = AF_UNSPEC,
	.handle = 0,
	.parent = TC_H_ROOT,
	.info = 0,
};

static const NMPlatformQdisc pl_qdisc_1c = {
	.ifindex = 1,
	.kind = ingress,
	.addr_family = AF_UNSPEC,
	.handle = TC_H_MAKE(TC_H_INGRESS, 0),
	.parent = TC_H_INGRESS,
	.info = 0,
};

static const NMPlatformQdisc pl_qdisc_2 = {
	.ifindex = 2,
	.kind = fq_codel,
	.addr_family = AF_UNSPEC,
	.handle = 0,
	.parent = TC_H_ROOT,
	.info = 0,
};

static void
test_cache_qdisc (void)
{
	NMPCache *cache;
	nm_auto_unref_dedup_multi_index NMDedupMultiIndex *multi_idx = NULL;
	NMPLookup lookup;
	const NMDedupMultiHeadEntry *head_entry;
	nm_auto_nmpobj NMPObject *obj1a = nmp_object_new (NMP_OBJECT_TYPE_QDISC, (NMPlatformObject *) &pl_qdisc_1a);
	nm_auto_nmpobj NMPObject *obj1b = nmp_object_new (NMP_OBJECT_TYPE_QDISC, (NMPlatformObject *) &pl_qdisc_1b);
	nm_auto_nmpobj NMPObject *obj1c = nmp_object_new (NMP_OBJECT_TYPE_QDISC, (NMPlatformObject *) &pl_qdisc_1c);
	nm_auto_nmpobj NMPObject *obj2 = nmp_object_new (NMP_OBJECT_TYPE_QDISC, (NMPlatformObject *) &pl_qdisc_2);

	multi_idx = nm_dedup_multi_index_new ();
	cache = nmp_cache_new (multi_idx, nmtst_get_rand_uint32 () % 2);

	g_assert (nmp_cache_lookup_obj (cache, obj1a) == NULL);

	g_assert (nmp_cache_update_netlink (cache, obj1a, FALSE, NULL, NULL) == NMP_CACHE_OPS_ADDED);
	g_assert (nmp_cache_lookup_obj (cache, obj1a) == obj1a);
	g_assert (nmp_cache_lookup_obj (cache, obj1b) == obj1a);
	g_assert (nmp_cache_lookup_obj (cache, obj2) == NULL);

	g_assert (nmp_cache_update_netlink (cache, obj1b, FALSE, NULL, NULL) == NMP_CACHE_OPS_UPDATED);
	g_assert (nmp_cache_lookup_obj (cache, obj1a) == obj1b);
	g_assert (nmp_cache_lookup_obj (cache, obj1b) == obj1b);
	g_assert (nmp_cache_lookup_obj (cache, obj2) == NULL);

	g_assert (nmp_cache_update_netlink (cache, obj1c, FALSE, NULL, NULL) == NMP_CACHE_OPS_ADDED);
	g_assert (nmp_cache_lookup_obj (cache, obj1a) == obj1b);
	g_assert (nmp_cache_lookup_obj (cache, obj1b) == obj1b);
	g_assert (nmp_cache_lookup_obj (cache, obj1c) == obj1c);
	g_assert (nmp_cache_lookup_obj (cache, obj2) == NULL);

	g_assert (nmp_cache_update_netlink (cache, obj2, FALSE, NULL, NULL) == NMP_CACHE_OPS_ADDED);
	g_assert (nmp_cache_lookup_obj (cache, obj1a) == obj1b);
	g_assert (nmp_cache_lookup_obj (cache, obj1b) == obj1b);
	g_assert (nmp_cache_lookup_obj (cache, obj2) == obj2);

	head_entry = nmp_cache_lookup (cache,
	                               nmp_lookup_init_object (&lookup,
	                                                       NMP_OBJECT_TYPE_QDISC,
	                                                       1));
	g_assert (head_entry->len == 2);

	nmp_cache_free (cache);
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	int result;
	NMUdevClient *udev_client;

	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	udev_client = nm_udev_client_new ((const char *[]) { "net", NULL },
	                                  NULL, NULL);
	{
		struct udev_enumerate *enumerator;
		struct udev_list_entry *devices, *l;

		enumerator = nm_udev_client_enumerate_new (udev_client);

		/* Demand that the device is initialized (udev rules ran,
		 * device has a stable name now) in case udev is running
		 * (not in a container). */
		if (access ("/sys", W_OK) == 0)
			udev_enumerate_add_match_is_initialized (enumerator);

		udev_enumerate_scan_devices (enumerator);

		devices = udev_enumerate_get_list_entry (enumerator);
		for (l = devices; l != NULL; l = udev_list_entry_get_next (l)) {
			struct udev_device *udevice;

			udevice = udev_device_new_from_syspath (udev_enumerate_get_udev (enumerator),
			                                        udev_list_entry_get_name (l));
			if (udevice == NULL)
				continue;

			global.udev_devices = g_list_prepend (global.udev_devices, udevice);
		}
		global.udev_devices = g_list_reverse (global.udev_devices);

		udev_enumerate_unref (enumerator);
	}

	g_test_add_func ("/nmp-object/obj-base", test_obj_base);
	g_test_add_func ("/nmp-object/cache_link", test_cache_link);
	g_test_add_func ("/nmp-object/cache_qdisc", test_cache_qdisc);

	result = g_test_run ();

	while (global.udev_devices) {
		udev_device_unref (global.udev_devices->data);
		global.udev_devices = g_list_delete_link (global.udev_devices, global.udev_devices);
	}

	nm_udev_client_unref (udev_client);

	return result;
}

