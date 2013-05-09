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
 * Copyright (C) 2009 - 2013 Red Hat, Inc.
 */

#include <config.h>

#include <gudev/gudev.h>

#include "nm-udev-manager.h"
#include "nm-logging.h"
#include "nm-platform.h"
#include "nm-system.h"

typedef struct {
	GUdevClient *client;

} NMUdevManagerPrivate;

#define NM_UDEV_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_UDEV_MANAGER, NMUdevManagerPrivate))

G_DEFINE_TYPE (NMUdevManager, nm_udev_manager, G_TYPE_OBJECT)

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

NMUdevManager *
nm_udev_manager_new (void)
{
	return NM_UDEV_MANAGER (g_object_new (NM_TYPE_UDEV_MANAGER, NULL));
}

static gboolean
dev_get_attrs (GUdevDevice *udev_device,
               const char **out_ifname,
               const char **out_path,
               char **out_driver,
               int *out_ifindex)
{
	GUdevDevice *parent = NULL, *grandparent = NULL;
	const char *ifname, *driver, *path, *subsys;
	gint ifindex = -1;

	g_return_val_if_fail (udev_device != NULL, FALSE);
	g_return_val_if_fail (out_ifname != NULL, FALSE);
	g_return_val_if_fail (out_path != NULL, FALSE);
	g_return_val_if_fail (out_driver != NULL, FALSE);
	g_return_val_if_fail (out_ifindex != NULL, FALSE);

	ifname = g_udev_device_get_name (udev_device);
	if (!ifname) {
		nm_log_dbg (LOGD_HW, "failed to get device's interface");
		return FALSE;
	}

	path = g_udev_device_get_sysfs_path (udev_device);
	if (!path) {
		nm_log_warn (LOGD_HW, "couldn't determine device path; ignoring...");
		return FALSE;
	}

	driver = g_udev_device_get_driver (udev_device);
	if (!driver) {
		/* Try the parent */
		parent = g_udev_device_get_parent (udev_device);
		if (parent) {
			driver = g_udev_device_get_driver (parent);
			if (!driver) {
				/* try the grandparent if it's an ibmebus device or if the
				 * subsys is NULL which usually indicates some sort of
				 * platform device like a 'gadget' net interface.
				 */
				subsys = g_udev_device_get_subsystem (parent);
				if (   (g_strcmp0 (subsys, "ibmebus") == 0)
				    || (subsys == NULL)) {
					grandparent = g_udev_device_get_parent (parent);
					if (grandparent)
						driver = g_udev_device_get_driver (grandparent);
				}
			}
		}
	}

	if (g_udev_device_get_sysfs_attr (udev_device, "ifindex"))
		ifindex = g_udev_device_get_sysfs_attr_as_int (udev_device, "ifindex");

	if (!driver) {
		switch (nm_platform_link_get_type (ifindex)) {
		case NM_LINK_TYPE_BOND:
			driver = "bonding";
			break;
		case NM_LINK_TYPE_BRIDGE:
			driver = "bridge";
			break;
		case NM_LINK_TYPE_VLAN:
			driver = "8021q";
			break;
		default:
			if (g_str_has_prefix (ifname, "easytether"))
				driver = "easytether";
			break;
		}
	}

	*out_ifname = ifname;
	*out_path = path;
	*out_driver = g_strdup (driver);
	*out_ifindex = ifindex;

	if (grandparent)
		g_object_unref (grandparent);
	if (parent)
		g_object_unref (parent);

	return TRUE;
}

static void
net_add (NMUdevManager *self, GUdevDevice *udev_device)
{
	gint ifindex = -1;
	const char *ifname = NULL, *path = NULL, *tmp;
	char *driver = NULL;

	g_return_if_fail (udev_device != NULL);

	if (!dev_get_attrs (udev_device, &ifname, &path, &driver, &ifindex))
		return;

	if (ifindex < 0) {
		nm_log_warn (LOGD_HW, "%s: device had invalid ifindex %d; ignoring...", path, ifindex);
		goto out;
	}

	/* Not all ethernet devices are immediately usable; newer mobile broadband
	 * devices (Ericsson, Option, Sierra) require setup on the tty before the
	 * ethernet device is usable.  2.6.33 and later kernels set the 'DEVTYPE'
	 * uevent variable which we can use to ignore the interface as a NMDevice
	 * subclass.  ModemManager will pick it up though and so we'll handle it
	 * through the mobile broadband stuff.
	 */
	tmp = g_udev_device_get_property (udev_device, "DEVTYPE");
	if (g_strcmp0 (tmp, "wwan") == 0) {
		nm_log_dbg (LOGD_HW, "(%s): ignoring interface with devtype '%s'", ifname, tmp);
		goto out;
	}

	g_signal_emit (self, signals[DEVICE_ADDED], 0, udev_device, ifname, path, driver, ifindex);

out:
	g_free (driver);
}

static void
net_remove (NMUdevManager *self, GUdevDevice *device)
{
	g_signal_emit (self, signals[DEVICE_REMOVED], 0, device);
}

static void
adsl_add (NMUdevManager *self, GUdevDevice *udev_device)
{
	gint ifindex = -1;
	const char *ifname = NULL, *path = NULL;
	char *driver = NULL;

	g_return_if_fail (udev_device != NULL);

	nm_log_dbg (LOGD_HW, "adsl_add: ATM Device detected from udev. Adding ..");

	if (dev_get_attrs (udev_device, &ifname, &path, &driver, &ifindex))
		g_signal_emit (self, signals[DEVICE_ADDED], 0, udev_device, ifname, path, driver, ifindex);
	g_free (driver);
}

static void
adsl_remove (NMUdevManager *self, GUdevDevice *device)
{
	nm_log_dbg (LOGD_HW, "adsl_remove: Removing ATM Device");

	g_signal_emit (self, signals[DEVICE_REMOVED], 0, device);
}

void
nm_udev_manager_query_devices (NMUdevManager *self)
{
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);
	GUdevEnumerator *enumerator;
	GList *devices, *iter;

	g_return_if_fail (NM_IS_UDEV_MANAGER (self));

	enumerator = g_udev_enumerator_new (priv->client);
	g_udev_enumerator_add_match_subsystem (enumerator, "net");
	g_udev_enumerator_add_match_is_initialized (enumerator);

	devices = g_udev_enumerator_execute (enumerator);
	for (iter = devices; iter; iter = g_list_next (iter)) {
		net_add (self, G_UDEV_DEVICE (iter->data));
		g_object_unref (G_UDEV_DEVICE (iter->data));
	}
	g_list_free (devices);
	g_object_unref (enumerator);


	enumerator = g_udev_enumerator_new (priv->client);
	g_udev_enumerator_add_match_subsystem (enumerator, "atm");
	g_udev_enumerator_add_match_is_initialized (enumerator);
	devices = g_udev_enumerator_execute (enumerator);
	for (iter = devices; iter; iter = g_list_next (iter)) {
		adsl_add (self, G_UDEV_DEVICE (iter->data));
		g_object_unref (G_UDEV_DEVICE (iter->data));
	}
	g_list_free (devices);
	g_object_unref (enumerator);
}

static void
handle_uevent (GUdevClient *client,
               const char *action,
               GUdevDevice *device,
               gpointer user_data)
{
	NMUdevManager *self = NM_UDEV_MANAGER (user_data);
	const char *subsys;

	g_return_if_fail (action != NULL);

	/* A bit paranoid */
	subsys = g_udev_device_get_subsystem (device);
	g_return_if_fail (subsys != NULL);

	nm_log_dbg (LOGD_HW, "UDEV event: action '%s' subsys '%s' device '%s'",
	            action, subsys, g_udev_device_get_name (device));

	g_return_if_fail (!strcmp (subsys, "net") || !strcmp (subsys, "atm"));

	if (!strcmp (action, "add")) {
		if (!strcmp (subsys, "net"))
			net_add (self, device);
		else if (!strcmp (subsys, "atm"))
			adsl_add (self, device);
	} else if (!strcmp (action, "remove")) {
		if (!strcmp (subsys, "net"))
			net_remove (self, device);
		else if (!strcmp (subsys, "atm"))
			adsl_remove (self, device);
	}
}

static void
nm_udev_manager_init (NMUdevManager *self)
{
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);
	const char *subsys[] = { "net", "atm", NULL };

	priv->client = g_udev_client_new (subsys);
	g_signal_connect (priv->client, "uevent", G_CALLBACK (handle_uevent), self);
}

static void
dispose (GObject *object)
{
	NMUdevManager *self = NM_UDEV_MANAGER (object);
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->client);

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
	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMUdevManagerClass, device_added),
					  NULL, NULL, NULL, 
					  G_TYPE_NONE, 5, G_TYPE_POINTER, G_TYPE_POINTER, G_TYPE_POINTER, G_TYPE_POINTER, G_TYPE_INT);

	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMUdevManagerClass, device_removed),
					  NULL, NULL, NULL,
					  G_TYPE_NONE, 1, G_TYPE_POINTER);
}

