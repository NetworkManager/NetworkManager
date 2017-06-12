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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include <libudev.h>

#include "platform/nmp-object.h"
#include "nm-utils/nm-udev-utils.h"

#include "nm-test-utils-core.h"

struct {
	GList *udev_devices;
} global;

/*****************************************************************************/

static void
test_obj_base (void)
{
	static const GObject *g = NULL;
	static const GTypeClass *k = NULL;
	static const NMPObject *o = NULL;
	static const NMPClass *c = NULL;

	NMObjBaseInst *obj;
	gs_unref_object GCancellable *obj_cancellable = g_cancellable_new ();
	nm_auto_nmpobj NMPObject *obj_link = nmp_object_new_link (10);

#define STATIC_ASSERT(cond) \
	G_STMT_START { \
		G_STATIC_ASSERT (cond); \
		G_STATIC_ASSERT_EXPR (cond); \
		g_assert (cond); \
	} G_STMT_END

	STATIC_ASSERT (&g->g_type_instance              == (void *) &o->_class);
	STATIC_ASSERT (&g->g_type_instance.g_class      == (void *) &o->_class);
	STATIC_ASSERT (&g->ref_count                    == (void *) &o->_ref_count);

	STATIC_ASSERT (sizeof (o->parent)               == sizeof (GTypeInstance));

	STATIC_ASSERT (&c->parent                       == (void *) c);
	STATIC_ASSERT (&c->parent.parent.g_type_class   == (void *) c);
	STATIC_ASSERT (&c->parent.parent.g_type         == (void *) c);
	STATIC_ASSERT (&c->parent.parent.g_type         == &k->g_type);

	STATIC_ASSERT (sizeof (c->parent.parent)        == sizeof (GTypeClass));

	STATIC_ASSERT (&o->parent                       == (void *) o);
	STATIC_ASSERT (&o->parent.klass                 == (void *) &o->_class);

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
_assert_cache_multi_lookup_contains (const NMPCache *cache, const NMPCacheId *cache_id, const NMPObject *obj, gboolean contains)
{
	const NMPlatformObject *const *objects;
	guint i, len;
	gboolean found;

	g_assert (cache_id);
	g_assert (NMP_OBJECT_IS_VALID (obj));

	g_assert (nmp_cache_lookup_obj (cache, obj) == obj);

	objects = nmp_cache_lookup_multi (cache, cache_id, &len);

	g_assert ((len == 0 && !objects) || (len > 0 && objects && !objects[len]));

	found = FALSE;
	for (i = 0; i < len; i++) {
		NMPObject *o;

		g_assert (objects[i]);
		o = NMP_OBJECT_UP_CAST (objects[i]);
		g_assert (NMP_OBJECT_IS_VALID (o));

		if (obj == o) {
			g_assert (!found);
			found = TRUE;
		}
	}

	g_assert (!!contains == found);
}

/*****************************************************************************/

typedef struct {
	NMPCache *cache;
	NMPCacheOpsType expected_ops_type;
	const NMPObject *obj_clone;
	NMPObject *new_clone;
	gboolean was_visible;
	gboolean called;
} _NMPCacheUpdateData;

static void
_nmp_cache_update_hook (NMPCache *cache, const NMPObject *old, const NMPObject *new, NMPCacheOpsType ops_type, gpointer user_data)
{
	_NMPCacheUpdateData *data = user_data;

	g_assert (data);
	g_assert (!data->called);
	g_assert (data->cache == cache);

	g_assert_cmpint (data->expected_ops_type, ==, ops_type);

	switch (ops_type) {
	case NMP_CACHE_OPS_ADDED:
		g_assert (!old);
		g_assert (NMP_OBJECT_IS_VALID (new));
		g_assert (nmp_object_is_alive (new));
		g_assert (nmp_object_id_equal (data->obj_clone, new));
		g_assert (nmp_object_equal (data->obj_clone, new));
		break;
	case NMP_CACHE_OPS_UPDATED:
		g_assert (NMP_OBJECT_IS_VALID (old));
		g_assert (NMP_OBJECT_IS_VALID (new));
		g_assert (nmp_object_is_alive (old));
		g_assert (nmp_object_is_alive (new));
		g_assert (nmp_object_id_equal (data->obj_clone, new));
		g_assert (nmp_object_id_equal (data->obj_clone, old));
		g_assert (nmp_object_id_equal (old, new));
		g_assert (nmp_object_equal (data->obj_clone, new));
		g_assert (!nmp_object_equal (data->obj_clone, old));
		g_assert (!nmp_object_equal (old, new));
		break;
	case NMP_CACHE_OPS_REMOVED:
		g_assert (!new);
		g_assert (NMP_OBJECT_IS_VALID (old));
		g_assert (nmp_object_is_alive (old));
		g_assert (nmp_object_id_equal (data->obj_clone, old));
		break;
	default:
		g_assert_not_reached ();
	}

	data->was_visible = old ? nmp_object_is_visible (old) : FALSE;
	data->new_clone = new ? nmp_object_clone (new, FALSE) : NULL;
	data->called = TRUE;
}

static void
_nmp_cache_update_netlink (NMPCache *cache, NMPObject *obj, NMPObject **out_obj, gboolean *out_was_visible, NMPCacheOpsType expected_ops_type)
{
	NMPCacheOpsType ops_type;
	NMPObject *obj2;
	gboolean was_visible;
	nm_auto_nmpobj NMPObject *obj_clone = nmp_object_clone (obj, FALSE);
	nm_auto_nmpobj NMPObject *new_clone = NULL;
	const NMPObject *obj_old;
	_NMPCacheUpdateData data = {
		.cache = cache,
		.expected_ops_type = expected_ops_type,
		.obj_clone = obj_clone,
	};

	obj_old = nmp_cache_lookup_link (cache, obj->object.ifindex);
	if (obj_old && obj_old->_link.udev.device)
		obj_clone->_link.udev.device = udev_device_ref (obj_old->_link.udev.device);
	_nmp_object_fixup_link_udev_fields (obj_clone, nmp_cache_use_udev_get (cache));

	g_assert (cache);
	g_assert (NMP_OBJECT_IS_VALID (obj));

	ops_type = nmp_cache_update_netlink (cache, obj, &obj2, &was_visible, _nmp_cache_update_hook, &data);

	new_clone = data.new_clone;

	g_assert_cmpint (ops_type, ==, expected_ops_type);

	if (ops_type != NMP_CACHE_OPS_UNCHANGED) {
		g_assert (NMP_OBJECT_IS_VALID (obj2));
		g_assert (data.called);
		g_assert_cmpint (data.was_visible, ==, was_visible);

		if (ops_type == NMP_CACHE_OPS_REMOVED)
			g_assert (!data.new_clone);
		else {
			g_assert (data.new_clone);
			g_assert (nmp_object_equal (obj2, data.new_clone));
		}
	} else {
		g_assert (!data.called);
		g_assert (!obj2 || was_visible == nmp_object_is_visible (obj2));
	}

	g_assert (!obj2 || nmp_object_id_equal (obj, obj2));
	if (ops_type != NMP_CACHE_OPS_REMOVED && obj2)
		g_assert (nmp_object_equal (obj, obj2));

	if (out_obj)
		*out_obj = obj2;
	else
		nmp_object_unref (obj2);
	if (out_was_visible)
		*out_was_visible = was_visible;
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
	NMPObject *obj1, *obj2;
	NMPObject objs1;
	gboolean was_visible;
	NMPCacheId cache_id_storage;
	struct udev_device *udev_device_2 = g_list_nth_data (global.udev_devices, 0);
	struct udev_device *udev_device_3 = g_list_nth_data (global.udev_devices, 0);
	NMPCacheOpsType ops_type;

	cache = nmp_cache_new (nmtst_get_rand_int () % 2);

	/* if we have a link, and don't set is_in_netlink, adding it has no effect. */
	obj1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_2);
	g_assert (NMP_OBJECT_UP_CAST (&obj1->object) == obj1);
	g_assert (!nmp_object_is_alive (obj1));
	_nmp_cache_update_netlink (cache, obj1, &obj2, &was_visible, NMP_CACHE_OPS_UNCHANGED);
	ASSERT_nmp_cache_is_consistent (cache);
	g_assert (!obj2);
	g_assert (!was_visible);
	g_assert (!nmp_cache_lookup_obj (cache, obj1));
	g_assert (!nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)));
	nmp_object_unref (obj1);

	/* Only when setting @is_in_netlink the link is added. */
	obj1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_2);
	obj1->_link.netlink.is_in_netlink = TRUE;
	g_assert (nmp_object_is_alive (obj1));
	_nmp_cache_update_netlink (cache, obj1, &obj2, &was_visible, NMP_CACHE_OPS_ADDED);
	ASSERT_nmp_cache_is_consistent (cache);
	g_assert (nmp_object_equal (obj1, obj2));
	g_assert (!was_visible);
	g_assert (nmp_cache_lookup_obj (cache, obj1) == obj2);
	g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)) == obj2);
	g_assert (nmp_object_is_visible (obj2));
	_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, TRUE), obj2, TRUE);
	_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, FALSE), obj2, TRUE);
	nmp_object_unref (obj1);
	nmp_object_unref (obj2);

	/* updating the same link with identical value, has no effect. */
	obj1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_2);
	obj1->_link.netlink.is_in_netlink = TRUE;
	g_assert (nmp_object_is_alive (obj1));
	_nmp_cache_update_netlink (cache, obj1, &obj2, &was_visible, NMP_CACHE_OPS_UNCHANGED);
	ASSERT_nmp_cache_is_consistent (cache);
	g_assert (obj2 != obj1);
	g_assert (nmp_object_equal (obj1, obj2));
	g_assert (was_visible);
	g_assert (nmp_cache_lookup_obj (cache, obj1) == obj2);
	g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)) == obj2);
	nmp_object_unref (obj1);
	nmp_object_unref (obj2);

	/* remove the link from netlink */
	obj1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_2);
	g_assert (!nmp_object_is_alive (obj1));
	_nmp_cache_update_netlink (cache, obj1, &obj2, &was_visible, NMP_CACHE_OPS_REMOVED);
	ASSERT_nmp_cache_is_consistent (cache);
	g_assert (obj2 != obj1);
	g_assert (was_visible);
	g_assert (!nmp_cache_lookup_obj (cache, obj1));
	g_assert (!nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)));
	nmp_object_unref (obj1);
	nmp_object_unref (obj2);

	if (udev_device_2) {
		/* now add the link only with aspect UDEV. */
		ops_type = nmp_cache_update_link_udev (cache, pl_link_2.ifindex, udev_device_2, &obj2, &was_visible, NULL, NULL);
		ASSERT_nmp_cache_is_consistent (cache);
		g_assert_cmpint (ops_type, ==, NMP_CACHE_OPS_ADDED);
		g_assert (!was_visible);
		g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)) == obj2);
		g_assert (!nmp_object_is_visible (obj2));
		_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, TRUE), obj2, FALSE);
		_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, FALSE), obj2, TRUE);
		nmp_object_unref (obj2);
	}

	/* add it in netlink too. */
	obj1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_2);
	obj1->_link.netlink.is_in_netlink = TRUE;
	g_assert (nmp_object_is_alive (obj1));
	_nmp_cache_update_netlink (cache, obj1, &obj2, &was_visible, udev_device_2 ? NMP_CACHE_OPS_UPDATED : NMP_CACHE_OPS_ADDED);
	ASSERT_nmp_cache_is_consistent (cache);
	g_assert (nmp_object_equal (obj1, obj2));
	g_assert (!was_visible);
	g_assert (nmp_cache_lookup_obj (cache, obj1) == obj2);
	g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)) == obj2);
	g_assert (nmp_object_is_visible (obj2));
	_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, TRUE), obj2, TRUE);
	_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, FALSE), obj2, TRUE);
	nmp_object_unref (obj1);
	nmp_object_unref (obj2);

	/* remove again from netlink. */
	obj1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_2);
	obj1->_link.netlink.is_in_netlink = FALSE;
	g_assert (!nmp_object_is_alive (obj1));
	_nmp_cache_update_netlink (cache, obj1, &obj2, &was_visible, udev_device_2 ? NMP_CACHE_OPS_UPDATED : NMP_CACHE_OPS_REMOVED);
	ASSERT_nmp_cache_is_consistent (cache);
	g_assert (obj2 != obj1);
	g_assert (was_visible);
	if (udev_device_2) {
		g_assert (nmp_cache_lookup_obj (cache, obj1) == obj2);
		g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)) == obj2);
		g_assert (!nmp_object_is_visible (obj2));
		_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, TRUE), obj2, FALSE);
		_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, FALSE), obj2, TRUE);
	} else {
		g_assert (nmp_cache_lookup_obj (cache, obj1) == NULL);
		g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_2.ifindex)) == NULL);
		g_assert (nmp_object_is_visible (obj2));
	}
	nmp_object_unref (obj1);
	nmp_object_unref (obj2);

	/* now another link only with aspect UDEV. */
	if (udev_device_3) {
		/* now add the link only with aspect UDEV. */
		ops_type = nmp_cache_update_link_udev (cache, pl_link_3.ifindex, udev_device_3, &obj2, &was_visible, NULL, NULL);
		g_assert_cmpint (ops_type, ==, NMP_CACHE_OPS_ADDED);
		ASSERT_nmp_cache_is_consistent (cache);
		g_assert (NMP_OBJECT_IS_VALID (obj2));
		g_assert (!was_visible);
		g_assert (!nmp_object_is_visible (obj2));
		g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_3.ifindex)) == obj2);
		_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, TRUE), obj2, FALSE);
		_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, FALSE), obj2, TRUE);
		g_assert_cmpint (obj2->_link.netlink.is_in_netlink, ==, FALSE);
		g_assert_cmpint (obj2->link.initialized, ==, FALSE);
		nmp_object_unref (obj2);

		/* add it in netlink too. */
		obj1 = nmp_object_new (NMP_OBJECT_TYPE_LINK, (NMPlatformObject *) &pl_link_3);
		obj1->_link.netlink.is_in_netlink = TRUE;
		g_assert (nmp_object_is_alive (obj1));
		_nmp_cache_update_netlink (cache, obj1, &obj2, &was_visible, NMP_CACHE_OPS_UPDATED);
		ASSERT_nmp_cache_is_consistent (cache);
		g_assert (obj2 != obj1);
		g_assert (nmp_object_equal (obj1, obj2));
		g_assert (!was_visible);
		g_assert (nmp_cache_lookup_obj (cache, obj1) == obj2);
		g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_3.ifindex)) == obj2);
		g_assert (nmp_object_is_visible (obj2));
		_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, TRUE), obj2, TRUE);
		_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, FALSE), obj2, TRUE);
		g_assert_cmpint (obj2->_link.netlink.is_in_netlink, ==, TRUE);
		g_assert_cmpint (obj2->link.initialized, ==, TRUE);
		nmp_object_unref (obj1);
		nmp_object_unref (obj2);

		/* remove UDEV. */
		ops_type = nmp_cache_update_link_udev (cache, pl_link_3.ifindex, NULL, &obj2, &was_visible, NULL, NULL);
		g_assert_cmpint (ops_type, ==, NMP_CACHE_OPS_UPDATED);
		ASSERT_nmp_cache_is_consistent (cache);
		g_assert (was_visible);
		g_assert (nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&objs1, pl_link_3.ifindex)) == obj2);
		g_assert (nmp_object_is_visible (obj2));
		_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, TRUE), obj2, TRUE);
		_assert_cache_multi_lookup_contains (cache, nmp_cache_id_init_object_type (&cache_id_storage, NMP_OBJECT_TYPE_LINK, FALSE), obj2, TRUE);
		g_assert_cmpint (obj2->_link.netlink.is_in_netlink, ==, TRUE);
		g_assert_cmpint (obj2->link.initialized, ==, !nmp_cache_use_udev_get (cache));
		nmp_object_unref (obj2);
	}

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

	result = g_test_run ();

	while (global.udev_devices) {
		udev_device_unref (global.udev_devices->data);
		global.udev_devices = g_list_remove (global.udev_devices, global.udev_devices->data);
	}

	nm_udev_client_unref (udev_client);

	return result;
}

