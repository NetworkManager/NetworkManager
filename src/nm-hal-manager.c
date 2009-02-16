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

#include "config.h"

#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <libhal.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#if HAVE_LIBUDEV
#define LIBUDEV_I_KNOW_THE_API_IS_SUBJECT_TO_CHANGE
#include <libudev.h>
#endif /* HAVE_LIBUDEV */

#include "nm-glib-compat.h"
#include "nm-hal-manager.h"
#include "nm-marshal.h"
#include "nm-dbus-manager.h"
#include "nm-utils.h"
#include "nm-device-wifi.h"
#include "nm-device-ethernet.h"
#include "nm-gsm-device.h"
#include "nm-hso-gsm-device.h"
#include "nm-cdma-device.h"

/* Killswitch poll frequency in seconds */
#define RFKILL_POLL_FREQUENCY 6

#define HAL_DBUS_SERVICE "org.freedesktop.Hal"

typedef struct {
	LibHalContext *hal_ctx;
	NMDBusManager *dbus_mgr;
	GSList *device_creators;
	gboolean rfkilled;  /* Authoritative rfkill state */

	/* Killswitch handling */
	GSList *killswitch_list;
	guint32 killswitch_poll_id;
	char *kswitch_err;
	gboolean poll_rfkilled;
	guint32 pending_polls;
	GSList *poll_proxies;

	gboolean disposed;
} NMHalManagerPrivate;

#define NM_HAL_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_HAL_MANAGER, NMHalManagerPrivate))

G_DEFINE_TYPE (NMHalManager, nm_hal_manager, G_TYPE_OBJECT)

enum {
	UDI_ADDED,
	UDI_REMOVED,
	RFKILL_CHANGED,
	HAL_REAPPEARED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


static gboolean poll_killswitches (gpointer user_data);

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
nm_get_device_driver_name (LibHalContext *ctx, const char *origdev_udi)
{
	char *driver_name = NULL;

	if (origdev_udi && libhal_device_property_exists (ctx, origdev_udi, "info.linux.driver", NULL)) {
		char *drv = libhal_device_get_property_string (ctx, origdev_udi, "info.linux.driver", NULL);
		driver_name = g_strdup (drv);
		libhal_free_string (drv);
	}
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

/* Modem device creator */

static gboolean
is_modem_device (NMHalManager *self, const char *udi)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	gboolean is_modem = FALSE;

	if (libhal_device_property_exists (priv->hal_ctx, udi, "info.category", NULL)) {
		char *category;

		category = libhal_device_get_property_string (priv->hal_ctx, udi, "info.category", NULL);
		if (category) {
			is_modem = strcmp (category, "serial") == 0;
			libhal_free_string (category);
		}
	}

	return is_modem;
}

static char *
get_hso_netdev (LibHalContext *ctx, const char *udi)
{
	char *serial_parent, *netdev = NULL;
	char **netdevs;
	int num, i;

	/* Get the serial interface's originating device UDI, used to find the
	 * originating device's netdev.
	 */
	serial_parent = libhal_device_get_property_string (ctx, udi, "serial.originating_device", NULL);
	if (!serial_parent)
		serial_parent = libhal_device_get_property_string (ctx, udi, "info.parent", NULL);
	if (!serial_parent)
		return NULL;

	/* Look for the originating device's netdev */
	netdevs = libhal_find_device_by_capability (ctx, "net", &num, NULL);
	for (i = 0; netdevs && !netdev && (i < num); i++) {
		char *netdev_parent, *tmp;

		netdev_parent = libhal_device_get_property_string (ctx, netdevs[i], "net.originating_device", NULL);
		if (!netdev_parent)
			netdev_parent = libhal_device_get_property_string (ctx, netdevs[i], "net.physical_device", NULL);
		if (!netdev_parent)
			continue;

		if (!strcmp (netdev_parent, serial_parent)) {
			/* We found it */
			tmp = libhal_device_get_property_string (ctx, netdevs[i], "net.interface", NULL);
			if (tmp) {
				netdev = g_strdup (tmp);
				libhal_free_string (tmp);
			}
		}

		libhal_free_string (netdev_parent);
	}
	libhal_free_string_array (netdevs);
	libhal_free_string (serial_parent);

	return netdev;
}

#define PROP_GSM   "ID_MODEM_GSM"
#define PROP_CDMA  "ID_MODEM_IS707_A"
#define PROP_EVDO1 "ID_MODEM_IS856"
#define PROP_EVDOA "ID_MODEM_IS856_A"

#if HAVE_LIBUDEV

typedef struct {
	gboolean gsm;
	gboolean cdma;
} UdevIterData;

#if UDEV_VERSION >= 129
static const char *
get_udev_property (struct udev_device *device, const char *name)
{
	struct udev_list_entry *entry;

	udev_list_entry_foreach (entry, udev_device_get_properties_list_entry (device)) {
		if (strcmp (udev_list_entry_get_name (entry), name) == 0)
			return udev_list_entry_get_value (entry);
	}

	return NULL;
}
#else
static int udev_device_prop_iter(struct udev_device *udev_device,
                                 const char *key,
                                 const char *value,
                                 void *data)
{
	UdevIterData *types = data;

	if (!strcmp (key, PROP_GSM) && !strcmp (value, "1"))
		types->gsm = TRUE;
	if (!strcmp (key, PROP_CDMA) && !strcmp (value, "1"))
		types->cdma = TRUE;
	if (!strcmp (key, PROP_EVDO1) && !strcmp (value, "1"))
		types->cdma = TRUE;
	if (!strcmp (key, PROP_EVDOA) && !strcmp (value, "1"))
		types->cdma = TRUE;

	/* Return 0 to continue looking */
	return types->gsm && types->cdma;
}
#endif

static gboolean
libudev_get_modem_capabilities (const char *sysfs_path,
                                gboolean *gsm,
                                gboolean *cdma)
{
	struct udev *udev;
	struct udev_device *device;

	g_return_val_if_fail (sysfs_path != NULL, FALSE);
	g_return_val_if_fail (gsm != NULL, FALSE);
	g_return_val_if_fail (*gsm == FALSE, FALSE);
	g_return_val_if_fail (cdma != NULL, FALSE);
	g_return_val_if_fail (*cdma == FALSE, FALSE);

	udev = udev_new ();
	if (!udev)
		return FALSE;

#if UDEV_VERSION >= 129
	device = udev_device_new_from_syspath (udev, sysfs_path);
#else
	/* udev_device_new_from_devpath() requires the sysfs mount point to be
	 * stripped off the path.
	 */
	if (!strncmp (sysfs_path, "/sys", 4))
		sysfs_path += 4;
	device = udev_device_new_from_devpath (udev, sysfs_path);
#endif
	if (!device) {
		udev_unref (udev);
		nm_warning ("couldn't inspect device '%s' with libudev", sysfs_path);
		return FALSE;
	}

#if UDEV_VERSION >= 129
	{
		const char *gsm_val = get_udev_property (device, PROP_GSM);
		const char *cdma_val = get_udev_property (device, PROP_CDMA);
		const char *evdo1_val = get_udev_property (device, PROP_EVDO1);
		const char *evdoa_val = get_udev_property (device, PROP_EVDOA);

		if (gsm_val && !strcmp (gsm_val, "1"))
			*gsm = TRUE;
		if (cdma_val && !strcmp (cdma_val, "1"))
			*cdma = TRUE;
		if (evdo1_val && !strcmp (evdo1_val, "1"))
			*cdma = TRUE;
		if (evdoa_val && !strcmp (evdoa_val, "1"))
			*cdma = TRUE;
	}
#else
	{
		UdevIterData iterdata = { FALSE, FALSE };

		udev_device_get_properties (device, udev_device_prop_iter, &iterdata);
		*gsm = iterdata.gsm;
		*cdma = iterdata.cdma;
	}
#endif

	udev_device_unref (device);
	udev_unref (udev);
	return TRUE;
}
#else
static gboolean
udevadm_get_modem_capabilities (const char *sysfs_path,
                                gboolean *gsm,
                                gboolean *cdma)
{
	char *udevadm_argv[] = { "/sbin/udevadm", "info", "--query=env", NULL, NULL };
	char *syspath_arg = NULL;
	char *udevadm_stdout = NULL;
	int exitcode;
	GError *error = NULL;
	char **lines = NULL, **iter;
	gboolean success = FALSE;

	g_return_val_if_fail (sysfs_path != NULL, FALSE);
	g_return_val_if_fail (gsm != NULL, FALSE);
	g_return_val_if_fail (*gsm == FALSE, FALSE);
	g_return_val_if_fail (cdma != NULL, FALSE);
	g_return_val_if_fail (*cdma == FALSE, FALSE);

	udevadm_argv[3] = syspath_arg = g_strdup_printf ("--path=%s", sysfs_path);
	if (g_spawn_sync ("/", udevadm_argv, NULL, 0, NULL, NULL,
			  &udevadm_stdout,
			  NULL,
			  &exitcode,
			  &error) != TRUE) {
		nm_warning ("could not run udevadm to get modem capabilities for '%s': %s",
		            sysfs_path,
		            (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
		goto error;
	}

	if (exitcode != 0) {
		nm_warning ("udevadm error while getting modem capabilities for '%s': %d",
		            sysfs_path, WEXITSTATUS (exitcode));
		goto error;
	}

	lines = g_strsplit_set (udevadm_stdout, "\n\r", -1);
	for (iter = lines; *iter; iter++) {
		if (!strcmp (*iter, PROP_GSM "=1")) {
			*gsm = TRUE;
			break;
		} else if (   !strcmp (*iter, PROP_CDMA "=1")
		           || !strcmp (*iter, PROP_EVDO1 "=1")
		           || !strcmp (*iter, PROP_EVDOA "=1")) {
			*cdma = TRUE;
			break;
		}
	}
	success = TRUE;

error:
	if (lines)
		g_strfreev (lines);
	g_free (udevadm_stdout);
	g_free (syspath_arg);
	return success;
}
#endif

static gboolean
hal_get_modem_capabilities (LibHalContext *ctx,
                            const char *udi,
                            gboolean *gsm,
                            gboolean *cdma)
{
	char **capabilities, **iter;

	g_return_val_if_fail (ctx != NULL, FALSE);
	g_return_val_if_fail (udi != NULL, FALSE);
	g_return_val_if_fail (gsm != NULL, FALSE);
	g_return_val_if_fail (*gsm == FALSE, FALSE);
	g_return_val_if_fail (cdma != NULL, FALSE);
	g_return_val_if_fail (*cdma == FALSE, FALSE);

	/* Make sure it has the 'modem' capability first */
	if (!libhal_device_query_capability (ctx, udi, "modem", NULL))
		return TRUE;

	capabilities = libhal_device_get_property_strlist (ctx, udi, "modem.command_sets", NULL);
	/* 'capabilites' may be NULL */
	for (iter = capabilities; iter && *iter; iter++) {
		if (!strcmp (*iter, "GSM-07.07")) {
			*gsm = TRUE;
			break;
		}
		if (!strcmp (*iter, "IS-707-A")) {
			*cdma = TRUE;
			break;
		}
	}
	g_strfreev (capabilities);

	/* Compatiblity with the pre-specification bits */
	if (!*gsm && !*cdma) {
		capabilities = libhal_device_get_property_strlist (ctx, udi, "info.capabilities", NULL);
		for (iter = capabilities; *iter; iter++) {
			if (!strcmp (*iter, "gsm")) {
				*gsm = TRUE;
				break;
			}
			if (!strcmp (*iter, "cdma")) {
				*cdma = TRUE;
				break;
			}
		}
	}

	if (capabilities)
		g_strfreev (capabilities);
	return TRUE;
}

static GObject *
modem_device_creator (NMHalManager *self,
                      const char *udi,
                      const char *origdev_udi,
                      gboolean managed)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	char *serial_device;
	char *sysfs_path;
	char *driver = NULL;
	GObject *device = NULL;
	gboolean type_gsm = FALSE;
	gboolean type_cdma = FALSE;
	char *netdev = NULL;

	serial_device = libhal_device_get_property_string (priv->hal_ctx, udi, "serial.device", NULL);
	driver = nm_get_device_driver_name (priv->hal_ctx, origdev_udi);
	if (!serial_device || !driver)
		goto out;

	/* Try udev first */
	sysfs_path = libhal_device_get_property_string (priv->hal_ctx, udi, "linux.sysfs_path", NULL);
	if (!sysfs_path) {
		nm_warning ("could not determine sysfs path for '%s'", serial_device);
		goto out;
	}
#if HAVE_LIBUDEV
	libudev_get_modem_capabilities (sysfs_path, &type_gsm, &type_cdma);
#else
	udevadm_get_modem_capabilities (sysfs_path, &type_gsm, &type_cdma);
#endif
	libhal_free_string (sysfs_path);

	/* If udev didn't know anything, try deprecated HAL modem capabilities */
	if (!type_gsm && !type_cdma)
		hal_get_modem_capabilities (priv->hal_ctx, udi, &type_gsm, &type_cdma);

	/* Special handling of 'hso' cards (until punted out to a modem manager) */
	if (type_gsm && !strcmp (driver, "hso"))
		netdev = get_hso_netdev (priv->hal_ctx, udi);

	if (type_gsm) {
		if (netdev)
			device = (GObject *) nm_hso_gsm_device_new (udi, serial_device + strlen ("/dev/"), NULL, netdev, driver, managed);
		else
			device = (GObject *) nm_gsm_device_new (udi, serial_device + strlen ("/dev/"), NULL, driver, managed);
	} else if (type_cdma)
		device = (GObject *) nm_cdma_device_new (udi, serial_device + strlen ("/dev/"), NULL, driver, managed);

out:
	libhal_free_string (serial_device);
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

	/* Modem */
	creator = g_slice_new0 (DeviceCreator);
	creator->device_type = NM_TYPE_SERIAL_DEVICE;
	creator->capability_str = g_strdup ("serial");
	creator->category = g_strdup ("serial");
	creator->is_device_fn = is_modem_device;
	creator->creator_fn = modem_device_creator;
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

static void
killswitch_poll_cleanup (NMHalManager *self)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);

	if (priv->poll_proxies) {
		g_slist_foreach (priv->poll_proxies, (GFunc) g_object_unref, NULL);
		g_slist_free (priv->poll_proxies);
		priv->poll_proxies = NULL;
	}

	priv->pending_polls = 0;
	priv->poll_rfkilled = FALSE;
}

static void
killswitch_getpower_done (gpointer user_data)
{
	NMHalManager *self = NM_HAL_MANAGER (user_data);
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);

	priv->pending_polls--;

	if (priv->pending_polls > 0)
		return;

	if (priv->poll_rfkilled != priv->rfkilled) {
		priv->rfkilled = priv->poll_rfkilled;
		g_signal_emit (self, signals[RFKILL_CHANGED], 0, priv->rfkilled);
	}

	killswitch_poll_cleanup (self);

	/* Schedule next poll */
	priv->killswitch_poll_id = g_timeout_add_seconds (RFKILL_POLL_FREQUENCY,
	                                          poll_killswitches,
	                                          self);
}

static void 
killswitch_getpower_reply (DBusGProxy *proxy,
					  DBusGProxyCall *call_id,
					  gpointer user_data)
{
	NMHalManager *self = NM_HAL_MANAGER (user_data);
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	int power = 1;
	GError *err = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &err,
	                           G_TYPE_INT, &power,
	                           G_TYPE_INVALID)) {
		if (power == 0)
			priv->poll_rfkilled = TRUE;
	} else {
		if (err->message) {
			/* Only print the error if we haven't seen it before */
		    if (!priv->kswitch_err || strcmp (priv->kswitch_err, err->message) != 0) {
				nm_warning ("Error getting killswitch power: %s.", err->message);
				g_free (priv->kswitch_err);
				priv->kswitch_err = g_strdup (err->message);

				/* If there was an error talking to HAL, treat that as rfkilled.
				 * See rh #448889.  On some Dell laptops, dellWirelessCtl
				 * may not be present, but HAL still advertises a killswitch,
				 * and calls to GetPower() will fail.  Thus we cannot assume
				 * that a failure of GetPower() automatically means the wireless
				 * is rfkilled, because in this situation NM would never bring
				 * the radio up.  Only assume failures between NM and HAL should
				 * block the radio, not failures of the HAL killswitch callout
				 * itself.
				 */
				if (strstr (err->message, "Did not receive a reply")) {
					nm_warning ("HAL did not reply to killswitch power request;"
					            " assuming radio is blocked.");
					priv->poll_rfkilled = TRUE;
				}
			}
		}
		g_error_free (err);
	}
}

static void
poll_one_killswitch (gpointer data, gpointer user_data)
{
	NMHalManager *self = NM_HAL_MANAGER (user_data);
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	DBusGProxy *proxy;

	proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (priv->dbus_mgr),
								"org.freedesktop.Hal",
								(char *) data,
								"org.freedesktop.Hal.Device.KillSwitch");

	dbus_g_proxy_begin_call (proxy, "GetPower",
						killswitch_getpower_reply,
						self,
						killswitch_getpower_done,
						G_TYPE_INVALID);
	priv->pending_polls++;
	priv->poll_proxies = g_slist_prepend (priv->poll_proxies, proxy);
}

static gboolean
poll_killswitches (gpointer user_data)
{
	NMHalManager *self = NM_HAL_MANAGER (user_data);
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);

	killswitch_poll_cleanup (self);

	g_slist_foreach (priv->killswitch_list, poll_one_killswitch, self);
	return FALSE;
}

static void
add_killswitch_device (NMHalManager *self, const char *udi)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	char *type;
	GSList *iter;

	type = libhal_device_get_property_string (priv->hal_ctx, udi, "killswitch.type", NULL);
	if (!type)
		return;

	if (strcmp (type, "wlan"))
		goto out;

	/* see if it's already in the list */
	for (iter = priv->killswitch_list; iter; iter = iter->next) {
		const char *list_udi = (const char *) iter->data;
		if (!strcmp (list_udi, udi))
			goto out;
	}

	/* Poll switches if this is the first switch we've found */
	if (!priv->killswitch_list)
		priv->killswitch_poll_id = g_idle_add (poll_killswitches, self);

	priv->killswitch_list = g_slist_append (priv->killswitch_list, g_strdup (udi));
	nm_info ("Found radio killswitch %s", udi);

out:
	libhal_free_string (type);
}

static void
add_killswitch_devices (NMHalManager *self)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	char **udis;
	int num_udis;
	int i;
	DBusError	err;

	dbus_error_init (&err);
	udis = libhal_find_device_by_capability (priv->hal_ctx, "killswitch", &num_udis, &err);
	if (!udis)
		return;

	if (dbus_error_is_set (&err)) {
		nm_warning ("Could not find killswitch devices: %s", err.message);
		dbus_error_free (&err);
		return;
	}

	for (i = 0; i < num_udis; i++)
		add_killswitch_device (self, udis[i]);

	libhal_free_string_array (udis);
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

	if (priv->killswitch_poll_id) {
		g_source_remove (priv->killswitch_poll_id);
		priv->killswitch_poll_id = 0;
	}
	killswitch_poll_cleanup (self);

	if (priv->killswitch_list) {
		g_slist_foreach (priv->killswitch_list, (GFunc) g_free, NULL);
		g_slist_free (priv->killswitch_list);
		priv->killswitch_list = NULL;
	}

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
	if (priv->hal_ctx) {
		add_killswitch_devices (self);
		add_initial_devices (self);
	}
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

	priv->rfkilled = FALSE;

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
finalize (GObject *object)
{
	NMHalManager *self = NM_HAL_MANAGER (object);
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);

	g_free (priv->kswitch_err);

	G_OBJECT_CLASS (nm_hal_manager_parent_class)->finalize (object);
}

static void
nm_hal_manager_class_init (NMHalManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMHalManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	object_class->finalize = finalize;

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

	signals[RFKILL_CHANGED] =
		g_signal_new ("rfkill-changed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMHalManagerClass, rfkill_changed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__BOOLEAN,
					  G_TYPE_NONE, 1,
					  G_TYPE_BOOLEAN);

	signals[HAL_REAPPEARED] =
		g_signal_new ("hal-reappeared",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMHalManagerClass, hal_reappeared),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__VOID,
					  G_TYPE_NONE, 0);
}

