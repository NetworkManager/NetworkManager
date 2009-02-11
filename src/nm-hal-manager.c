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

/* Killswitch poll frequency in seconds */
#define RFKILL_POLL_FREQUENCY 6

#define HAL_DBUS_SERVICE "org.freedesktop.Hal"

typedef struct {
	char *udi;
	gboolean polled;
	RfKillState state;

	/* For polling */
	DBusGProxy *proxy;

	NMHalManager *self;
} Killswitch;

typedef struct {
	LibHalContext *hal_ctx;
	NMDBusManager *dbus_mgr;
	GSList *device_creators;

	/* Authoritative rfkill state (RFKILL_* enum)
	 */
	RfKillState rfkill_state;

	/* Killswitch handling:
	 * There are two types of killswitches:
	 *  a) old-style: require polling
	 *  b) new-style: requires hal 0.5.12 as of 2008-11-19, and 2.6.27 kernel
	 *       or later; emit PropertyChanged for the 'state' property when the
	 *       rfkill status changes
	 *
	 * If new-style switches are found, they are used.  Otherwise, old-style
	 * switches are used.
	 */
	GSList *killswitches;

	/* Old-style killswitch polling stuff */
	guint32 killswitch_poll_id;
	char *kswitch_err;

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
	char *device_type_name;
	char *capability_str;
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
nm_get_device_driver_name (LibHalContext *ctx, const char *udi)
{
	char *origdev_udi;
	char *driver_name = NULL;

	origdev_udi = libhal_device_get_property_string (ctx, udi, "net.originating_device", NULL);
	if (!origdev_udi) {
		/* Older HAL uses 'physical_device' */
		origdev_udi = libhal_device_get_property_string (ctx, udi, "net.physical_device", NULL);
	}

	if (origdev_udi && libhal_device_property_exists (ctx, origdev_udi, "info.linux.driver", NULL)) {
		char *drv = libhal_device_get_property_string (ctx, origdev_udi, "info.linux.driver", NULL);
		driver_name = g_strdup (drv);
		libhal_free_string (drv);
	}
	libhal_free_string (origdev_udi);

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
wired_device_creator (NMHalManager *self, const char *udi, gboolean managed)
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

	driver = nm_get_device_driver_name (priv->hal_ctx, udi);
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
wireless_device_creator (NMHalManager *self, const char *udi, gboolean managed)
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

	driver = nm_get_device_driver_name (priv->hal_ctx, udi);
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
	creator->device_type_name = g_strdup ("Ethernet");
	creator->capability_str = g_strdup ("net.80203");
	creator->is_device_fn = is_wired_device;
	creator->creator_fn = wired_device_creator;
	priv->device_creators = g_slist_append (priv->device_creators, creator);

	/* Wireless device */
	creator = g_slice_new0 (DeviceCreator);
	creator->device_type_name = g_strdup ("802.11 WiFi");
	creator->capability_str = g_strdup ("net.80211");
	creator->is_device_fn = is_wireless_device;
	creator->creator_fn = wireless_device_creator;
	priv->device_creators = g_slist_append (priv->device_creators, creator);
}

static void
device_added (LibHalContext *ctx, const char *udi)
{
	NMHalManager *self = NM_HAL_MANAGER (libhal_ctx_get_user_data (ctx));
	DeviceCreator *creator;

//	nm_debug ("New device added (hal udi is '%s').", udi );

	/* Sometimes the device's properties (like net.interface) are not set up yet,
	 * so this call will fail, and it will actually be added when hal sets the device's
	 * capabilities a bit later on.
	 */
	creator = get_creator (self, udi);
	if (creator)
		g_signal_emit (self, signals[UDI_ADDED], 0, udi, creator->device_type_name, creator->creator_fn);
}

static void
device_removed (LibHalContext *ctx, const char *udi)
{
	NMHalManager *self = NM_HAL_MANAGER (libhal_ctx_get_user_data (ctx));

//	nm_debug ("Device removed (hal udi is '%s').", udi );

	g_signal_emit (self, signals[UDI_REMOVED], 0, udi);
}

static void
device_new_capability (LibHalContext *ctx, const char *udi, const char *capability)
{
	NMHalManager *self = NM_HAL_MANAGER (libhal_ctx_get_user_data (ctx));
	DeviceCreator *creator;

//	nm_debug ("nm_hal_device_new_capability() called with udi = %s, capability = %s", udi, capability );

	creator = get_creator (self, udi);
	if (creator)
		g_signal_emit (self, signals[UDI_ADDED], 0, udi, creator->device_type_name, creator->creator_fn);
}

static RfKillState
hal_to_nm_rfkill_state (int hal_state)
{
	switch (hal_state) {
	case 0:
		return RFKILL_SOFT_BLOCKED;
	case 2:
		return RFKILL_HARD_BLOCKED;
	case 1:
	default:
		return RFKILL_UNBLOCKED;
	}
}

static void
device_property_changed (LibHalContext *ctx,
                         const char *udi,
                         const char *key,
                         dbus_bool_t is_removed,
                         dbus_bool_t is_added)
{
	NMHalManager *self = NM_HAL_MANAGER (libhal_ctx_get_user_data (ctx));
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	GSList *iter;
	gboolean found = FALSE;
	DBusError error;
	int state;
	RfKillState new_state = RFKILL_UNBLOCKED;

	/* Ignore event if it's not a killswitch state change */
	if (strcmp (key, "killswitch.state") || is_removed)
		return;

	/* Check all killswitches, and if any switch is blocked, the new rfkill
	 * state becomes blocked.
	 */
	for (iter = priv->killswitches; iter; iter = iter->next) {
		Killswitch *ks = iter->data;

		if (!strcmp (ks->udi, udi)) {
			found = TRUE;

			/* Get switch state */
			dbus_error_init (&error);
			state = libhal_device_get_property_int (ctx, ks->udi, "killswitch.state", &error);
			if (dbus_error_is_set (&error)) {
				nm_warning ("(%s) Error reading killswitch state: %s.",
				            ks->udi,
				            error.message ? error.message : "unknown");
				dbus_error_free (&error);
			} else
				ks->state = hal_to_nm_rfkill_state (state);
		}

		/* If any switch is blocked, overall state is blocked */
		if (ks->state > new_state)
			new_state = ks->state;
	}

	/* Notify of new rfkill state change; but only if the killswitch which
	 * this event is for was one we care about
	 */
	if (found && (new_state != priv->rfkill_state)) {
		priv->rfkill_state = new_state;
		g_signal_emit (self, signals[RFKILL_CHANGED], 0, priv->rfkill_state);
	}
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
		}

		if (devices) {
			for (i = 0; i < num_devices; i++) {
				if (!creator->is_device_fn (self, devices[i]))
					continue;
				g_signal_emit (self, signals[UDI_ADDED], 0, devices[i], creator->device_type_name, creator->creator_fn);
			}
		}

		libhal_free_string_array (devices);
	}
}

static void
killswitch_getpower_done (gpointer user_data)
{
	Killswitch *ks = user_data;
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (ks->self);
	GSList *iter;
	RfKillState new_state = RFKILL_UNBLOCKED;

	if (ks->proxy) {
		g_object_unref (ks->proxy);
		ks->proxy = NULL;
	}

	/* Check all killswitches, and if any switch is blocked, the new rfkill
	 * state becomes blocked.  But emit final state until the last killswitch
	 * has been updated.
	 */
	for (iter = priv->killswitches; iter; iter = g_slist_next (iter)) {
		Killswitch *candidate = iter->data;

		/* If any GetPower call has yet to complete; don't emit final state */
		if (candidate->proxy)
			return;

		if (candidate->state > new_state)
			new_state = candidate->state;
	}

	if (new_state != priv->rfkill_state) {
		priv->rfkill_state = new_state;
		g_signal_emit (ks->self, signals[RFKILL_CHANGED], 0, priv->rfkill_state);
	}

	/* Schedule next poll */
	priv->killswitch_poll_id = g_timeout_add_seconds (RFKILL_POLL_FREQUENCY,
	                                                  poll_killswitches,
	                                                  ks->self);
}

static void 
killswitch_getpower_reply (DBusGProxy *proxy,
                           DBusGProxyCall *call_id,
                           gpointer user_data)
{
	Killswitch *ks = user_data;
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (ks->self);
	int power = 1;
	GError *err = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &err,
	                           G_TYPE_INT, &power,
	                           G_TYPE_INVALID)) {
		if (power == 0)
			ks->state = RFKILL_HARD_BLOCKED;
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
					ks->state = RFKILL_HARD_BLOCKED;
				}
			}
		}
		g_error_free (err);
	}
}

static gboolean
poll_killswitches (gpointer user_data)
{
	NMHalManager *self = NM_HAL_MANAGER (user_data);
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->killswitches; iter; iter = g_slist_next (iter)) {
		Killswitch *ks = iter->data;

		ks->state = RFKILL_UNBLOCKED;
		ks->proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (priv->dbus_mgr),
		                                       "org.freedesktop.Hal",
		                                       ks->udi,
		                                       "org.freedesktop.Hal.Device.KillSwitch");
		dbus_g_proxy_begin_call (ks->proxy, "GetPower",
		                         killswitch_getpower_reply,
		                         ks,
		                         killswitch_getpower_done,
		                         G_TYPE_INVALID);
	}
	return FALSE;
}

static Killswitch *
killswitch_new (const char *udi,
                int state,
                gboolean polled,
                NMHalManager *self)
{
	Killswitch *ks;

	ks = g_malloc0 (sizeof (Killswitch));
	ks->udi = g_strdup (udi);
	ks->state = state;
	ks->self = self;
	ks->polled = polled;

	return ks;
}

static void
killswitch_free (gpointer user_data)
{
	Killswitch *ks = user_data;

	if (ks->proxy)
		g_object_unref (ks->proxy);
	g_free (ks->udi);
	g_free (ks);
}

static void
add_killswitch_devices (NMHalManager *self)
{
	NMHalManagerPrivate *priv = NM_HAL_MANAGER_GET_PRIVATE (self);
	char **udis;
	int num_udis, i;
	DBusError err;
	GSList *polled = NULL, *active = NULL, *iter;

	dbus_error_init (&err);
	udis = libhal_find_device_by_capability (priv->hal_ctx, "killswitch", &num_udis, &err);
	if (!udis)
		return;

	if (dbus_error_is_set (&err)) {
		nm_warning ("Could not find killswitch devices: %s", err.message);
		dbus_error_free (&err);
		return;
	}

	/* filter switches we care about */
	for (i = 0; i < num_udis; i++) {
		Killswitch *ks;
		char *type;
		int state;
		gboolean found = FALSE;

		type = libhal_device_get_property_string (priv->hal_ctx, udis[i], "killswitch.type", NULL);
		if (!type)
			continue;

		/* Only care about WLAN for now */
		if (strcmp (type, "wlan")) {
			libhal_free_string (type);
			continue;
		}

		/* see if it's already in the list */
		for (iter = priv->killswitches; iter; iter = g_slist_next (iter)) {
			ks = iter->data;
			if (!strcmp (udis[i], ks->udi)) {
				found = TRUE;
				break;
			}
		}
		if (found)
			continue;

		dbus_error_init (&err);
		state = libhal_device_get_property_int (priv->hal_ctx, udis[i], "killswitch.state", &err);
		if (dbus_error_is_set (&err)) {
			dbus_error_free (&err);
			nm_info ("Found radio killswitch %s (polled)", udis[i]);
			ks = killswitch_new (udis[i], RFKILL_UNBLOCKED, TRUE, self);
			polled = g_slist_append (polled, ks);
		} else {
			nm_info ("Found radio killswitch %s (monitored)", udis[i]);
			ks = killswitch_new (udis[i], hal_to_nm_rfkill_state (state), FALSE, self);
			active = g_slist_append (active, ks);
		}
	}

	/* Active killswitches are used in preference to polled killswitches */
	if (active) {
		for (iter = active; iter; iter = g_slist_next (iter))
			priv->killswitches = g_slist_append (priv->killswitches, iter->data);

		if (priv->killswitches)
			nm_info ("Watching killswitches for radio status");

		/* Dispose of any polled killswitches found */
		g_slist_foreach (polled, (GFunc) killswitch_free, NULL);
	} else {
		for (iter = polled; iter; iter = g_slist_next (iter))
			priv->killswitches = g_slist_append (priv->killswitches, iter->data);

		/* Poll switches if this is the first switch we've found */
		if (priv->killswitches) {
			if (!priv->killswitch_poll_id)
				priv->killswitch_poll_id = g_idle_add (poll_killswitches, self);
			nm_info ("Polling killswitches for radio status");
		}
	}

	g_slist_free (active);
	g_slist_free (polled);
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
	libhal_ctx_set_device_property_modified (priv->hal_ctx, device_property_changed);

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

	if (priv->killswitches) {
		g_slist_foreach (priv->killswitches, (GFunc) killswitch_free, NULL);
		g_slist_free (priv->killswitches);
		priv->killswitches = NULL;
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

	priv->rfkill_state = RFKILL_UNBLOCKED;

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

	g_free (creator->device_type_name);
	g_free (creator->capability_str);
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
					  _nm_marshal_VOID__STRING_STRING_POINTER,
					  G_TYPE_NONE, 3,
					  G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER);

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
					  g_cclosure_marshal_VOID__UINT,
					  G_TYPE_NONE, 1,
					  G_TYPE_UINT);

	signals[HAL_REAPPEARED] =
		g_signal_new ("hal-reappeared",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMHalManagerClass, hal_reappeared),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__VOID,
					  G_TYPE_NONE, 0);
}

