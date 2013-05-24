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

#include <string.h>
#include <gudev/gudev.h>

#include "nm-atm-manager.h"
#include "nm-logging.h"

typedef struct {
	GUdevClient *client;

} NMAtmManagerPrivate;

#define NM_ATM_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ATM_MANAGER, NMAtmManagerPrivate))

G_DEFINE_TYPE (NMAtmManager, nm_atm_manager, G_TYPE_OBJECT)

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

NMAtmManager *
nm_atm_manager_new (void)
{
	return NM_ATM_MANAGER (g_object_new (NM_TYPE_ATM_MANAGER, NULL));
}

static gboolean
dev_get_attrs (GUdevDevice *udev_device,
               const char **out_ifname,
               const char **out_path,
               char **out_driver)
{
	GUdevDevice *parent = NULL;
	const char *ifname, *driver, *path;

	g_return_val_if_fail (udev_device != NULL, FALSE);
	g_return_val_if_fail (out_ifname != NULL, FALSE);
	g_return_val_if_fail (out_path != NULL, FALSE);
	g_return_val_if_fail (out_driver != NULL, FALSE);

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
			g_object_unref (parent);
		}
	}

	*out_ifname = ifname;
	*out_path = path;
	*out_driver = g_strdup (driver);

	return TRUE;
}

static void
adsl_add (NMAtmManager *self, GUdevDevice *udev_device)
{
	const char *ifname = NULL, *path = NULL;
	char *driver = NULL;

	g_return_if_fail (udev_device != NULL);

	nm_log_dbg (LOGD_HW, "adsl_add: ATM Device detected from udev. Adding ..");

	if (dev_get_attrs (udev_device, &ifname, &path, &driver))
		g_signal_emit (self, signals[DEVICE_ADDED], 0, ifname, path, driver);
	g_free (driver);
}

static void
adsl_remove (NMAtmManager *self, GUdevDevice *device)
{
	nm_log_dbg (LOGD_HW, "adsl_remove: Removing ATM Device");

	g_signal_emit (self, signals[DEVICE_REMOVED], 0, g_udev_device_get_name (device));
}

void
nm_atm_manager_query_devices (NMAtmManager *self)
{
	NMAtmManagerPrivate *priv = NM_ATM_MANAGER_GET_PRIVATE (self);
	GUdevEnumerator *enumerator;
	GList *devices, *iter;

	g_return_if_fail (NM_IS_ATM_MANAGER (self));

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
	NMAtmManager *self = NM_ATM_MANAGER (user_data);
	const char *subsys;

	g_return_if_fail (action != NULL);

	/* A bit paranoid */
	subsys = g_udev_device_get_subsystem (device);
	g_return_if_fail (!g_strcmp0 (subsys, "atm"));

	nm_log_dbg (LOGD_HW, "UDEV event: action '%s' subsys '%s' device '%s'",
	            action, subsys, g_udev_device_get_name (device));

	if (!strcmp (action, "add"))
		adsl_add (self, device);
	else if (!strcmp (action, "remove"))
		adsl_remove (self, device);
}

static void
nm_atm_manager_init (NMAtmManager *self)
{
	NMAtmManagerPrivate *priv = NM_ATM_MANAGER_GET_PRIVATE (self);
	const char *subsys[] = { "atm", NULL };

	priv->client = g_udev_client_new (subsys);
	g_signal_connect (priv->client, "uevent", G_CALLBACK (handle_uevent), self);
}

static void
dispose (GObject *object)
{
	NMAtmManager *self = NM_ATM_MANAGER (object);
	NMAtmManagerPrivate *priv = NM_ATM_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->client);

	G_OBJECT_CLASS (nm_atm_manager_parent_class)->dispose (object);	
}

static void
nm_atm_manager_class_init (NMAtmManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMAtmManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	/* Signals */
	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMAtmManagerClass, device_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMAtmManagerClass, device_removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_STRING);
}
