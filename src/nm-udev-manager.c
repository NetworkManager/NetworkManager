/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2009 Red Hat, Inc.
 */

#include <signal.h>
#include <string.h>
#include <stdlib.h>

#define G_UDEV_API_IS_SUBJECT_TO_CHANGE
#include <gudev/gudev.h>

#include "nm-udev-manager.h"
#include "nm-marshal.h"
#include "nm-utils.h"

typedef struct {
	GUdevClient *client;

	/* Authoritative rfkill state (RFKILL_* enum)
	 */
	RfKillState rfkill_state;
	GSList *killswitches;

	gboolean disposed;
} NMUdevManagerPrivate;

#define NM_UDEV_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_UDEV_MANAGER, NMUdevManagerPrivate))

G_DEFINE_TYPE (NMUdevManager, nm_udev_manager, G_TYPE_OBJECT)

enum {
	RFKILL_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


typedef struct {
	char *name;
	guint64 seqnum;
	char *path;
	char *driver;
	gint state;
} Killswitch;

RfKillState
nm_udev_manager_get_rfkill_state (NMUdevManager *self)
{
	g_return_val_if_fail (self != NULL, RFKILL_UNBLOCKED);

	return NM_UDEV_MANAGER_GET_PRIVATE (self)->rfkill_state;
}

static Killswitch *
killswitch_new (GUdevDevice *device)
{
	Killswitch *ks;
	GUdevDevice *parent = NULL;
	const char *driver;

	ks = g_malloc0 (sizeof (Killswitch));
	ks->name = g_strdup (g_udev_device_get_name (device));
	ks->seqnum = g_udev_device_get_seqnum (device);
	ks->path = g_strdup (g_udev_device_get_sysfs_path (device));

	driver = g_udev_device_get_property (device, "DRIVER");
	if (!driver) {
		parent = g_udev_device_get_parent (device);
		if (parent)
			driver = g_udev_device_get_property (parent, "DRIVER");
	}
	if (driver)
		ks->driver = g_strdup (driver);

	if (parent)
		g_object_unref (parent);

	return ks;
}

static void
killswitch_destroy (Killswitch *ks)
{
	g_return_if_fail (ks != NULL);

	g_free (ks->name);
	g_free (ks->path);
	g_free (ks->driver);
	memset (ks, 0, sizeof (Killswitch));
	g_free (ks);
}

NMUdevManager *
nm_udev_manager_new (void)
{
	return NM_UDEV_MANAGER (g_object_new (NM_TYPE_UDEV_MANAGER, NULL));
}

static RfKillState
sysfs_state_to_nm_state (gint sysfs_state)
{
	switch (sysfs_state) {
	case 0:
		return RFKILL_HARD_BLOCKED;
	case 1:
		return RFKILL_UNBLOCKED;
	case 2:
		return RFKILL_SOFT_BLOCKED;
	default:
		g_warning ("%s: Unhandled rfkill state %d", __func__, sysfs_state);
		break;
	}
	return RFKILL_UNBLOCKED;
}

static void
recheck_killswitches (NMUdevManager *self)
{
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);
	GSList *iter;
	RfKillState poll_state = RFKILL_UNBLOCKED;

	for (iter = priv->killswitches; iter; iter = g_slist_next (iter)) {
		Killswitch *ks = iter->data;
		GUdevDevice *device;
		RfKillState dev_state;

		device = g_udev_client_query_by_subsystem_and_name (priv->client, "rfkill", ks->name);
		if (!device)
			continue;

		dev_state = sysfs_state_to_nm_state (g_udev_device_get_property_as_int (device, "RFKILL_STATE"));
		if (dev_state > poll_state)
			poll_state = dev_state;

		g_object_unref (device);
	}

	if (poll_state != priv->rfkill_state) {
		priv->rfkill_state = poll_state;
		g_signal_emit (self, signals[RFKILL_CHANGED], 0, priv->rfkill_state);
	}
}

static Killswitch *
killswitch_find_by_name (NMUdevManager *self, const char *name)
{
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	g_return_val_if_fail (name != NULL, NULL);

	for (iter = priv->killswitches; iter; iter = g_slist_next (iter)) {
		Killswitch *candidate = iter->data;

		if (!strcmp (name, candidate->name))
			return candidate;
	}
	return NULL;
}

static void
add_one_killswitch (NMUdevManager *self, GUdevDevice *device)
{
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);
	const char *type;
	Killswitch *ks;

	type = g_udev_device_get_property (device, "RFKILL_TYPE");
	if (!type || strcmp (type, "wlan"))
		return;

	ks = killswitch_new (device);
	priv->killswitches = g_slist_prepend (priv->killswitches, ks);

	nm_info ("Found radio killswitch %s (at %s) (driver %s)",
	         ks->name,
	         ks->path,
	         ks->driver ? ks->driver : "<unknown>");
}

static void
handle_uevent (GUdevClient *client,
               const char *action,
               GUdevDevice *device,
               gpointer user_data)
{
	NMUdevManager *self = NM_UDEV_MANAGER (user_data);
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);
	const char *name, *subsys;

	g_return_if_fail (action != NULL);

	name = g_udev_device_get_name (device);
	g_return_if_fail (name != NULL);

	/* A bit paranoid */
	subsys = g_udev_device_get_subsystem (device);
	g_return_if_fail (subsys && !strcmp (subsys, "rfkill"));

	if (!strcmp (action, "add")) {
		if (!killswitch_find_by_name (self, name))
			add_one_killswitch (self, device);
	} else if (!strcmp (action, "remove")) {
		GSList *iter;

		for (iter = priv->killswitches; iter; iter = g_slist_next (iter)) {
			Killswitch *ks = iter->data;

			if (!strcmp (ks->name, name)) {
				nm_info ("Radio killswitch %s disappeared", ks->path);
				priv->killswitches = g_slist_remove (priv->killswitches, iter);
				killswitch_destroy (iter->data);
				g_slist_free (iter);
				break;
			}
		}
	}

	// FIXME: check sequence #s to ensure events don't arrive out of order

	recheck_killswitches (self);
}

static void
nm_udev_manager_init (NMUdevManager *self)
{
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);
	const char *subsys[2] = { "rfkill", NULL };
	GList *switches, *iter;

	priv->rfkill_state = RFKILL_UNBLOCKED;
	priv->client = g_udev_client_new (subsys);
	g_signal_connect (priv->client, "uevent", G_CALLBACK (handle_uevent), self);

	switches = g_udev_client_query_by_subsystem (priv->client, "rfkill");
	for (iter = switches; iter; iter = g_list_next (iter)) {
		add_one_killswitch (self, G_UDEV_DEVICE (iter->data));
		g_object_unref (G_UDEV_DEVICE (iter->data));
	}
	g_list_free (switches);

	recheck_killswitches (self);
}

static void
dispose (GObject *object)
{
	NMUdevManager *self = NM_UDEV_MANAGER (object);
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_udev_manager_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	g_object_unref (priv->client);

	g_slist_foreach (priv->killswitches, (GFunc) killswitch_destroy, NULL);
	g_slist_free (priv->killswitches);

	G_OBJECT_CLASS (nm_udev_manager_parent_class)->dispose (object);	
}

static void
nm_udev_manager_class_init (NMUdevManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMUdevManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	/* Signals */
	signals[RFKILL_CHANGED] =
		g_signal_new ("rfkill-changed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMUdevManagerClass, rfkill_changed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__UINT,
					  G_TYPE_NONE, 1,
					  G_TYPE_UINT);
}

