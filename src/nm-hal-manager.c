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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <libhal.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "nm-glib-compat.h"
#include "nm-hal-manager.h"
#include "nm-marshal.h"
#include "nm-dbus-manager.h"
#include "nm-utils.h"
#include "nm-device-wifi.h"
#include "nm-device-ethernet.h"

#define HAL_DBUS_SERVICE "org.freedesktop.Hal"

typedef struct {
	LibHalContext *hal_ctx;
	NMDBusManager *dbus_mgr;
	GSList *device_creators;

	gboolean disposed;
} NMHalManagerPrivate;

#define NM_HAL_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_HAL_MANAGER, NMHalManagerPrivate))

G_DEFINE_TYPE (NMHalManager, nm_hal_manager, G_TYPE_OBJECT)

enum {
	UDI_ADDED,
	UDI_REMOVED,
	HAL_REAPPEARED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


/* Device creators */

typedef struct {
	GType device_type;
	char *capability_str;
	char *category;
	gboolean (*is_device_fn) (NMHalManager *self, const char *udi);
	NMDeviceCreatorFn creator_fn;
} DeviceCreator;

static DeviceCreator *
get_creator (NMHalManager *self, const char *udi)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	DeviceCreator *creator;
	GSList *iter;

	for (iter = priv->device_creators; iter; iter = g_slist_next (iter)) {
		creator = (DeviceCreator *) iter->data;

		if (libhal_device_query_capability (priv->hal_ctx, udi, creator->capability_str, NULL) && 
		    creator->is_device_fn (self, udi))
			return creator;
	}

	return NULL;
}

/* end of device creators */

/* Common helpers for built-in device creators */

static char *
hal_get_subsystem (LibHalContext *ctx, const char *udi)
{
	char *subsys;

	subsys = libhal_device_get_property_string (ctx, udi, "info.subsystem", NULL);
	if (!subsys) {
		/* info.bus is deprecated */
		subsys = libhal_device_get_property_string (ctx, udi, "info.bus", NULL);
	}
	return subsys;
}

static char *
nm_get_device_driver_name (LibHalContext *ctx, const char *origdev_udi)
{
	char *driver_name = NULL, *subsystem, *drv, *od_parent = NULL;

	if (!origdev_udi)
		return NULL;

	/* s390 driver name is on the grandparent of the net device */
	subsystem = hal_get_subsystem (ctx, origdev_udi);
	if (subsystem && !strcmp (subsystem, "ibmebus")) {
		od_parent = libhal_device_get_property_string (ctx, origdev_udi, "info.parent", NULL);
		origdev_udi = (const char *) od_parent;
	}

	drv = libhal_device_get_property_string (ctx, origdev_udi, "info.linux.driver", NULL);
	if (drv)
		driver_name = g_strdup (drv);

	libhal_free_string (drv);
	libhal_free_string (od_parent);
	libhal_free_string (subsystem);
	return driver_name;
}

/* Wired device creator */

static gboolean
is_wired_device (NMHalManager *self, const char *udi)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	char *category;
	gboolean is_wired = FALSE;

	if (libhal_device_property_exists (priv->hal_ctx, udi, "net.linux.ifindex", NULL) &&
		libhal_device_property_exists (priv->hal_ctx, udi, "info.category", NULL)) {

		category = libhal_device_get_property_string (priv->hal_ctx, udi, "info.category", NULL);
		if (category) {
			is_wired = strcmp (category, "net.80203") == 0;
			libhal_free_string (category);
		}
	}

	return is_wired;
}

static GObject *
wired_device_creator (NMHalManager *self,
                      const char *udi,
                      const char *origdev_udi,
                      gboolean managed)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	GObject *device;
	char *iface;
	char *driver;

	iface = libhal_device_get_property_string (priv->hal_ctx, udi, "net.interface", NULL);
	if (!iface) {
		nm_warning ("Couldn't get interface for %s, ignoring.", udi);
		return NULL;
	}

	driver = nm_get_device_driver_name (priv->hal_ctx, origdev_udi);
	device = (GObject *) nm_device_ethernet_new (udi, iface, driver, managed);

	libhal_free_string (iface);
	g_free (driver);

	return device;
}

/* Wireless device creator */

static gboolean
is_wireless_device (NMHalManager *self, const char *udi)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	char *category;
	gboolean is_wireless = FALSE;

	if (libhal_device_property_exists (priv->hal_ctx, udi, "net.linux.ifindex", NULL) &&
		libhal_device_property_exists (priv->hal_ctx, udi, "info.category", NULL)) {

		category = libhal_device_get_property_string (priv->hal_ctx, udi, "info.category", NULL);
		if (category) {
			is_wireless = strcmp (category, "net.80211") == 0;
			libhal_free_string (category);
		}
	}

	return is_wireless;
}

static GObject *
wireless_device_creator (NMHalManager *self,
                         const char *udi,
                         const char *origdev_udi,
                         gboolean managed)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	GObject *device;
	char *iface;
	char *driver;

	iface = libhal_device_get_property_string (priv->hal_ctx, udi, "net.interface", NULL);
	if (!iface) {
		nm_warning ("Couldn't get interface for %s, ignoring.", udi);
		return NULL;
	}

	driver = nm_get_device_driver_name (priv->hal_ctx, origdev_udi);
	device = (GObject *) nm_device_wifi_new (udi, iface, driver, managed);

	libhal_free_string (iface);
	g_free (driver);

	return device;
}

static void
register_built_in_creators (NMHalManager *self)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	DeviceCreator *creator;

	/* Wired device */
	creator = g_slice_new0 (DeviceCreator);
	creator->device_type = NM_TYPE_DEVICE_ETHERNET;
	creator->capability_str = g_strdup ("net.80203");
	creator->category = g_strdup ("net");
	creator->is_device_fn = is_wired_device;
	creator->creator_fn = wired_device_creator;
	priv->device_creators = g_slist_append (priv->device_creators, creator);

	/* Wireless device */
	creator = g_slice_new0 (DeviceCreator);
	creator->device_type = NM_TYPE_DEVICE_WIFI;
	creator->capability_str = g_strdup ("net.80211");
	creator->category = g_strdup ("net");
	creator->is_device_fn = is_wireless_device;
	creator->creator_fn = wireless_device_creator;
	priv->device_creators = g_slist_append (priv->device_creators, creator);
}

static void
emit_udi_added (NMHalManager *self, const char *udi, DeviceCreator *creator)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	char *od, *tmp;

	g_return_if_fail (self != NULL);
	g_return_if_fail (udi != NULL);
	g_return_if_fail (creator != NULL);

	tmp = g_strdup_printf ("%s.originating_device", creator->category);
	od = libhal_device_get_property_string (priv->hal_ctx, udi, tmp, NULL);
	g_free (tmp);

	if (!od) {
		/* Older HAL uses 'physical_device' */
		tmp = g_strdup_printf ("%s.physical_device", creator->category);
		od = libhal_device_get_property_string (priv->hal_ctx, udi, tmp, NULL);
		g_free (tmp);
	}

	g_signal_emit (self, signals[UDI_ADDED], 0,
	               udi,
	               od,
	               GSIZE_TO_POINTER (creator->device_type),
	               creator->creator_fn);

	libhal_free_string (od);
}

static void
device_added (LibHalContext *ctx, const char *udi)
{
	NMHalManager *self = NM_HAL_MANAGER (libhal_ctx_get_user_data (ctx));
	DeviceCreator *creator;

	/* If not all the device's properties are set up yet (like net.interface),
	 * the device will actually get added later when HAL signals new device
	 * capabilties.
	 */
	creator = get_creator (self, udi);
	if (creator)
		emit_udi_added (self, udi, creator);
}

static void
device_removed (LibHalContext *ctx, const char *udi)
{
	NMHalManager *self = NM_HAL_MANAGER (libhal_ctx_get_user_data (ctx));

	g_signal_emit (self, signals[UDI_REMOVED], 0, udi);
}

static void
device_new_capability (LibHalContext *ctx, const char *udi, const char *capability)
{
	NMHalManager *self = NM_HAL_MANAGER (libhal_ctx_get_user_data (ctx));
	DeviceCreator *creator;

	creator = get_creator (self, udi);
	if (creator)
		emit_udi_added (self, udi, creator);
}

static void
add_initial_devices (NMHalManager *self)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	DeviceCreator *creator;
	GSList *iter;
	char **devices;
	int num_devices;
	int i;
	DBusError err;

	for (iter = priv->device_creators; iter; iter = g_slist_next (iter)) {
		creator = (DeviceCreator *) iter->data;

		dbus_error_init (&err);
		devices = libhal_find_device_by_capability (priv->hal_ctx,
		                                            creator->capability_str,
		                                            &num_devices,
		                                            &err);
		if (dbus_error_is_set (&err)) {
			nm_warning ("could not find existing devices: %s", err.message);
			dbus_error_free (&err);
			continue;
		}
		if (!devices)
			continue;

		for (i = 0; i < num_devices; i++) {
			if (creator->is_device_fn (self, devices[i]))
				emit_udi_added (self, devices[i], creator);
		}

		libhal_free_string_array (devices);
	}
}

static gboolean
hal_init (NMHalManager *self)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	DBusError error;
	DBusGConnection *connection; 

	priv->hal_ctx = libhal_ctx_new ();
	if (!priv->hal_ctx) {
		nm_warning ("Could not get connection to the HAL service.");
		return FALSE;
	}

	connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	libhal_ctx_set_dbus_connection (priv->hal_ctx,
									dbus_g_connection_get_connection (connection));

	dbus_error_init (&error);
	if (!libhal_ctx_init (priv->hal_ctx, &error)) {
		nm_warning ("libhal_ctx_init() failed: %s\n"
				    "Make sure the hal daemon is running?", 
				    error.message);
		goto error;
	}

	libhal_ctx_set_user_data (priv->hal_ctx, self);
	libhal_ctx_set_device_added (priv->hal_ctx, device_added);
	libhal_ctx_set_device_removed (priv->hal_ctx, device_removed);
	libhal_ctx_set_device_new_capability (priv->hal_ctx, device_new_capability);

	libhal_device_property_watch_all (priv->hal_ctx, &error);
	if (dbus_error_is_set (&error)) {
		nm_error ("libhal_device_property_watch_all(): %s", error.message);
		libhal_ctx_shutdown (priv->hal_ctx, NULL);
		goto error;
	}

	return TRUE;

error:
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	if (priv->hal_ctx) {
		libhal_ctx_free (priv->hal_ctx);
		priv->hal_ctx = NULL;
	}
	return FALSE;
}

static void
hal_deinit (NMHalManager *self)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	DBusError error;

	if (!priv->hal_ctx)
		return;

	dbus_error_init (&error);
	libhal_ctx_shutdown (priv->hal_ctx, &error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("libhal shutdown failed - %s", error.message);
		dbus_error_free (&error);
	}

	libhal_ctx_free (priv->hal_ctx);
	priv->hal_ctx = NULL;
}

static void
name_owner_changed (NMDBusManager *dbus_mgr,
					const char *name,
					const char *old,
					const char *new,
					gpointer user_data)
{
	NMHalManager *self = NM_HAL_MANAGER (user_data);
	gboolean old_owner_good = (old && (strlen (old) > 0));
	gboolean new_owner_good = (new && (strlen (new) > 0));

	/* Only care about signals from HAL */
	if (strcmp (name, HAL_DBUS_SERVICE))
		return;

	if (!old_owner_good && new_owner_good) {
		nm_info ("HAL re-appeared");
		/* HAL just appeared */
		if (!hal_init (self))
			nm_warning ("Could not re-connect to HAL!!");
		else
			g_signal_emit (self, signals[HAL_REAPPEARED], 0);
	} else if (old_owner_good && !new_owner_good) {
		/* HAL went away. Bad HAL. */
		nm_info ("HAL disappeared");
		hal_deinit (self);
	}
}

static void
connection_changed (NMDBusManager *dbus_mgr,
					DBusGConnection *connection,
					gpointer user_data)
{
	NMHalManager *self = NM_HAL_MANAGER (user_data);

	if (!connection) {
		hal_deinit (self);
		return;
	}

	if (nm_dbus_manager_name_has_owner (dbus_mgr, HAL_DBUS_SERVICE)) {
		if (!hal_init (self))
			nm_warning ("Could not re-connect to HAL!!");
	}
}

void
nm_hal_manager_query_devices (NMHalManager *self)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);

	/* Find hardware we care about */
	if (priv->hal_ctx)
		add_initial_devices (self);
}

gboolean
nm_hal_manager_udi_exists (NMHalManager *self, const char *udi)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);

	return libhal_device_property_exists (priv->hal_ctx, udi, "info.udi", NULL);
}

NMHalManager *
nm_hal_manager_new (void)
{
	NMHalManager *self;
	NMHalManagerPrivate *priv;

	self = NM_HAL_MANAGER (g_object_new (NM_TYPE_HAL_MANAGER, NULL));

	priv = NM_HAL_MANAGER_GET_PRIVATE (self);
 	if (!nm_dbus_manager_name_has_owner (priv->dbus_mgr, HAL_DBUS_SERVICE)) {
		nm_info ("Waiting for HAL to start...");
		return self;
	}

	if (!hal_init (self)) {
		g_object_unref (self);
		self = NULL;
	}

	return self;
}

static void
nm_hal_manager_init (NMHalManager *self)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);

	priv->dbus_mgr = nm_dbus_manager_get ();

	register_built_in_creators (self);

	g_signal_connect (priv->dbus_mgr,
	                  "name-owner-changed",
	                  G_CALLBACK (name_owner_changed),
	                  self);
	g_signal_connect (priv->dbus_mgr,
	                  "dbus-connection-changed",
	                  G_CALLBACK (connection_changed),
	                  self);
}

static void
destroy_creator (gpointer data, gpointer user_data)
{
	DeviceCreator *creator = (DeviceCreator *) data;

	g_free (creator->capability_str);
	g_free (creator->category);
	g_slice_free (DeviceCreator, data);
}

static void
dispose (GObject *object)
{
	NMHalManager *self = NM_HAL_MANAGER (object);
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_hal_manager_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	g_object_unref (priv->dbus_mgr);

	g_slist_foreach (priv->device_creators, destroy_creator, NULL);
	g_slist_free (priv->device_creators);

	hal_deinit (self);

	G_OBJECT_CLASS (nm_hal_manager_parent_class)->dispose (object);	
}

static void
nm_hal_manager_class_init (NMHalManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMHalManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	/* Signals */
	signals[UDI_ADDED] =
		g_signal_new ("udi-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMHalManagerClass, udi_added),
					  NULL, NULL,
					  _nm_marshal_VOID__STRING_STRING_POINTER_POINTER,
					  G_TYPE_NONE, 4,
					  G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER, G_TYPE_POINTER);

	signals[UDI_REMOVED] =
		g_signal_new ("udi-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMHalManagerClass, udi_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__STRING,
					  G_TYPE_NONE, 1,
					  G_TYPE_STRING);

	signals[HAL_REAPPEARED] =
		g_signal_new ("hal-reappeared",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMHalManagerClass, hal_reappeared),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__VOID,
					  G_TYPE_NONE, 0);
}

