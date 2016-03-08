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

#include "nm-default.h"

#include <string.h>
#include <gudev/gudev.h>
#include <gmodule.h>

#include "nm-atm-manager.h"
#include "nm-setting-adsl.h"
#include "nm-device-adsl.h"
#include "nm-device-factory.h"
#include "nm-platform.h"

typedef struct {
	GUdevClient *client;
	GSList *devices;
} NMAtmManagerPrivate;

#define NM_ATM_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ATM_MANAGER, NMAtmManagerPrivate))

static GType nm_atm_manager_get_type (void);

static void device_factory_interface_init (NMDeviceFactoryInterface *factory_iface);

G_DEFINE_TYPE_EXTENDED (NMAtmManager, nm_atm_manager, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_DEVICE_FACTORY, device_factory_interface_init))

/**************************************************************************/

G_MODULE_EXPORT NMDeviceFactory *
nm_device_factory_create (GError **error)
{
	return (NMDeviceFactory *) g_object_new (NM_TYPE_ATM_MANAGER, NULL);
}

/************************************************************************/

static gboolean
dev_get_attrs (GUdevDevice *udev_device,
               const char **out_path,
               char **out_driver)
{
	GUdevDevice *parent = NULL;
	const char *driver, *path;

	g_return_val_if_fail (udev_device != NULL, FALSE);
	g_return_val_if_fail (out_path != NULL, FALSE);
	g_return_val_if_fail (out_driver != NULL, FALSE);

	path = g_udev_device_get_sysfs_path (udev_device);
	if (!path) {
		nm_log_warn (LOGD_HW, "couldn't determine device path; ignoring...");
		return FALSE;
	}

	driver = g_udev_device_get_driver (udev_device);
	if (!driver) {
		/* Try the parent */
		parent = g_udev_device_get_parent (udev_device);
		if (parent)
			driver = g_udev_device_get_driver (parent);
	}

	*out_path = path;
	*out_driver = g_strdup (driver);

	g_clear_object (&parent);
	return TRUE;
}

static void
device_destroyed (gpointer user_data, GObject *dead)
{
	NMAtmManager *self = NM_ATM_MANAGER (user_data);
	NMAtmManagerPrivate *priv = NM_ATM_MANAGER_GET_PRIVATE (self);

	priv->devices = g_slist_remove (priv->devices, dead);
}

static void
adsl_add (NMAtmManager *self, GUdevDevice *udev_device)
{
	NMAtmManagerPrivate *priv = NM_ATM_MANAGER_GET_PRIVATE (self);
	const char *ifname, *sysfs_path = NULL;
	char *driver = NULL;
	gs_free char *atm_index_path = NULL;
	int atm_index;
	NMDevice *device;

	g_return_if_fail (udev_device != NULL);

	ifname = g_udev_device_get_name (udev_device);
	if (!ifname) {
		nm_log_warn (LOGD_HW, "failed to get device's interface name");
		return;
	}

	nm_log_dbg (LOGD_HW, "(%s): found ATM device", ifname);

	atm_index_path = g_strdup_printf ("/sys/class/atm/%s/atmindex",
	                                  NM_ASSERT_VALID_PATH_COMPONENT (ifname));
	atm_index = (int) nm_platform_sysctl_get_int_checked (NM_PLATFORM_GET,
	                                                      atm_index_path,
	                                                      10, 0, G_MAXINT,
	                                                      -1);
	if (atm_index < 0) {
		nm_log_warn (LOGD_HW, "(%s): failed to get ATM index", ifname);
		return;
	}

	if (!dev_get_attrs (udev_device, &sysfs_path, &driver)) {
		nm_log_warn (LOGD_HW, "(%s): failed to get ATM attributes", ifname);
		return;
	}

	g_assert (sysfs_path);

	device = nm_device_adsl_new (sysfs_path, ifname, driver, atm_index);
	g_assert (device);

	priv->devices = g_slist_prepend (priv->devices, device);
	g_object_weak_ref (G_OBJECT (device), device_destroyed, self);

	g_signal_emit_by_name (self, NM_DEVICE_FACTORY_DEVICE_ADDED, device);
	g_object_unref (device);

	g_free (driver);
}

static void
adsl_remove (NMAtmManager *self, GUdevDevice *udev_device)
{
	NMAtmManagerPrivate *priv = NM_ATM_MANAGER_GET_PRIVATE (self);
	const char *iface = g_udev_device_get_name (udev_device);
	GSList *iter;

	nm_log_dbg (LOGD_HW, "(%s): removing ATM device", iface);

	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *device = iter->data;

		/* Match 'iface' not 'ip_iface' to the ATM device instead of the
		 * NAS bridge interface or PPPoE interface.
		 */
		if (g_strcmp0 (nm_device_get_iface (device), iface) != 0)
			continue;

		g_object_weak_unref (G_OBJECT (iter->data), device_destroyed, self);
		priv->devices = g_slist_remove (priv->devices, device);
		g_signal_emit_by_name (device, NM_DEVICE_REMOVED);
		break;
	}
}

static void
start (NMDeviceFactory *factory)
{
	NMAtmManager *self = NM_ATM_MANAGER (factory);
	NMAtmManagerPrivate *priv = NM_ATM_MANAGER_GET_PRIVATE (self);
	GUdevEnumerator *enumerator;
	GList *devices, *iter;

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
	const char *ifindex;
	guint64 seqnum;

	g_return_if_fail (action != NULL);

	/* A bit paranoid */
	subsys = g_udev_device_get_subsystem (device);
	g_return_if_fail (!g_strcmp0 (subsys, "atm"));

	ifindex = g_udev_device_get_property (device, "IFINDEX");
	seqnum = g_udev_device_get_seqnum (device);
	nm_log_dbg (LOGD_HW, "UDEV event: action '%s' subsys '%s' device '%s' (%s); seqnum=%" G_GUINT64_FORMAT,
	            action, subsys, g_udev_device_get_name (device), ifindex ? ifindex : "unknown", seqnum);

	if (!strcmp (action, "add"))
		adsl_add (self, device);
	else if (!strcmp (action, "remove"))
		adsl_remove (self, device);
}

NM_DEVICE_FACTORY_DECLARE_TYPES (
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_ADSL_SETTING_NAME)
)

/*********************************************************************/

static void
nm_atm_manager_init (NMAtmManager *self)
{
	NMAtmManagerPrivate *priv = NM_ATM_MANAGER_GET_PRIVATE (self);
	const char *subsys[] = { "atm", NULL };

	priv->client = g_udev_client_new (subsys);
	g_signal_connect (priv->client, "uevent", G_CALLBACK (handle_uevent), self);
}

static void
device_factory_interface_init (NMDeviceFactoryInterface *factory_iface)
{
	factory_iface->get_supported_types = get_supported_types;
	factory_iface->start = start;
}

static void
dispose (GObject *object)
{
	NMAtmManager *self = NM_ATM_MANAGER (object);
	NMAtmManagerPrivate *priv = NM_ATM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	if (priv->client)
		g_signal_handlers_disconnect_by_func (priv->client, handle_uevent, self);
	g_clear_object (&priv->client);

	for (iter = priv->devices; iter; iter = iter->next)
		g_object_weak_unref (G_OBJECT (iter->data), device_destroyed, self);
	g_clear_pointer (&priv->devices, g_slist_free);

	G_OBJECT_CLASS (nm_atm_manager_parent_class)->dispose (object);
}

static void
nm_atm_manager_class_init (NMAtmManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMAtmManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
}
