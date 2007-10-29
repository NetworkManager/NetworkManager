/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <libhal.h>
#include "nm-hal-manager.h"
#include "nm-dbus-manager.h"
#include "nm-utils.h"
#include "nm-device-802-11-wireless.h"
#include "nm-device-802-3-ethernet.h"

/* Killswitch poll frequency in seconds */
#define NM_HAL_MANAGER_KILLSWITCH_POLL_FREQUENCY 6

struct _NMHalManager {
	LibHalContext *hal_ctx;
	NMDBusManager *dbus_mgr;
	NMManager *nm_manager;
	GSList *device_creators;

	gboolean nm_sleeping;

	/* Killswitch handling */
	GSList *killswitch_list;
	guint32 killswitch_poll_id;
	char *kswitch_err;
};

/* Device creators */

typedef NMDevice *(*NMDeviceCreatorFn) (NMHalManager *manager,
										const char *udi);

typedef struct {
	char *capability_str;
	gboolean (*is_device_fn) (NMHalManager *manager, const char *udi);
	NMDeviceCreatorFn creator_fn;
} DeviceCreator;

static NMDeviceCreatorFn
get_creator (NMHalManager *manager, const char *udi)
{
	DeviceCreator *creator;
	GSList *iter;

	for (iter = manager->device_creators; iter; iter = iter->next) {
		creator = (DeviceCreator *) iter->data;

		if (creator->is_device_fn (manager, udi))
			return creator->creator_fn;
	}

	return NULL;
}

/* end of device creators */

/* Common helpers for built-in device creators */

static int
get_device_index_from_hal (LibHalContext *ctx, const char *udi)
{
	int idx = -1;

	if (libhal_device_property_exists (ctx, udi, "net.linux.ifindex", NULL) && 
		libhal_device_property_exists (ctx, udi, "info.category", NULL)) {

		char *category = libhal_device_get_property_string (ctx, udi, "info.category", NULL);
		if (category && (!strcmp (category, "net.80203") || !strcmp (category, "net.80211"))) {
			idx = libhal_device_get_property_int (ctx, udi, "net.linux.ifindex", NULL);
		}
		libhal_free_string (category);
	}

	return idx;
}

static char *
nm_get_device_driver_name (LibHalContext *ctx, const char *udi)
{
	char *physdev_udi;
	char *driver_name = NULL;

	physdev_udi = libhal_device_get_property_string (ctx, udi, "net.physical_device", NULL);
	if (physdev_udi && libhal_device_property_exists (ctx, physdev_udi, "info.linux.driver", NULL)) {
		char *drv = libhal_device_get_property_string (ctx, physdev_udi, "info.linux.driver", NULL);
		driver_name = g_strdup (drv);
		g_free (drv);
	}
	libhal_free_string (physdev_udi);

	return driver_name;
}

/* Wired device creator */

static gboolean
is_wired_device (NMHalManager *manager, const char *udi)
{
	char *category;
	gboolean is_wired = FALSE;

	if (libhal_device_property_exists (manager->hal_ctx, udi, "net.linux.ifindex", NULL) &&
		libhal_device_property_exists (manager->hal_ctx, udi, "info.category", NULL)) {

		category = libhal_device_get_property_string (manager->hal_ctx, udi, "info.category", NULL);
		if (category) {
			is_wired = strcmp (category, "net.80203") == 0;
			libhal_free_string (category);
		}
	}

	return is_wired;
}

static NMDevice *
wired_device_creator (NMHalManager *manager, const char *udi)
{
	NMDevice *device;
	int idx;
	char *driver;

	idx = get_device_index_from_hal (manager->hal_ctx, udi);
	if (idx < 0) {
		nm_warning ("Couldn't get interface index for %s, ignoring.", udi);
		return NULL;
	}

	driver = nm_get_device_driver_name (manager->hal_ctx, udi);
	device = (NMDevice *) nm_device_802_3_ethernet_new (idx, udi, driver, FALSE);
	g_free (driver);

	return device;
}

/* Wireless device creator */

static gboolean
is_wireless_device (NMHalManager *manager, const char *udi)
{
	char *category;
	gboolean is_wireless = FALSE;

	if (libhal_device_property_exists (manager->hal_ctx, udi, "net.linux.ifindex", NULL) &&
		libhal_device_property_exists (manager->hal_ctx, udi, "info.category", NULL)) {

		category = libhal_device_get_property_string (manager->hal_ctx, udi, "info.category", NULL);
		if (category) {
			is_wireless = strcmp (category, "net.80211") == 0;
			libhal_free_string (category);
		}
	}

	return is_wireless;
}

static NMDevice *
wireless_device_creator (NMHalManager *manager, const char *udi)
{
	NMDevice *device;
	int idx;
	char *driver;

	idx = get_device_index_from_hal (manager->hal_ctx, udi);
	if (idx < 0) {
		nm_warning ("Couldn't get interface index for %s, ignoring.", udi);
		return NULL;
	}

	driver = nm_get_device_driver_name (manager->hal_ctx, udi);
	device = (NMDevice *) nm_device_802_11_wireless_new (idx, udi, driver, FALSE);
	g_free (driver);

	return device;
}

static void
register_built_in_creators (NMHalManager *manager)
{
	DeviceCreator *creator;

	/* Wired device */
	creator = g_slice_new0 (DeviceCreator);
	creator->capability_str = g_strdup ("net");
	creator->is_device_fn = is_wired_device;
	creator->creator_fn = wired_device_creator;
	manager->device_creators = g_slist_append (manager->device_creators, creator);

	/* Wireless device */
	creator = g_slice_new0 (DeviceCreator);
	creator->capability_str = g_strdup ("net");
	creator->is_device_fn = is_wireless_device;
	creator->creator_fn = wireless_device_creator;
	manager->device_creators = g_slist_append (manager->device_creators, creator);
}

static NMDevice *
create_device_and_add_to_list (NMHalManager *manager,
							   NMDeviceCreatorFn creator_fn,
							   const char *udi)
{
	NMDevice *dev = NULL;
	char *usb_test = NULL;

	/* Make sure the device is not already in the device list */
	if ((dev = nm_manager_get_device_by_udi (manager->nm_manager, udi)))
		return NULL;

	/* Ignore Ethernet-over-USB devices too for the moment (Red Hat #135722) */
	if (libhal_device_property_exists (manager->hal_ctx, udi, "usb.interface.class", NULL)
		&& (usb_test = libhal_device_get_property_string (manager->hal_ctx, udi, "usb.interface.class", NULL))) {

		libhal_free_string (usb_test);
		return NULL;
	}

	dev = creator_fn (manager, udi);
	if (dev) {
		nm_info ("Now managing %s device '%s'.",
				 NM_IS_DEVICE_802_11_WIRELESS (dev) ? "wireless (802.11)" : "wired Ethernet (802.3)",
				 nm_device_get_iface (dev));

		nm_manager_add_device (manager->nm_manager, dev);
		g_object_unref (dev);
	}

	return dev;
}

static void
device_added (LibHalContext *ctx, const char *udi)
{
	NMHalManager *manager = (NMHalManager *) libhal_ctx_get_user_data (ctx);
	NMDeviceCreatorFn creator_fn;

//	nm_debug ("New device added (hal udi is '%s').", udi );

	/* Ignore device additions while asleep, all devices will
	 * be found and set up again on wake.
	 */
	if (nm_manager_get_state (manager->nm_manager) == NM_STATE_ASLEEP)
		return;

	/* Sometimes the device's properties (like net.interface) are not set up yet,
	 * so this call will fail, and it will actually be added when hal sets the device's
	 * capabilities a bit later on.
	 */
	creator_fn = get_creator (manager, udi);
	if (creator_fn)
		create_device_and_add_to_list (manager, creator_fn, udi);
}

static void
device_removed (LibHalContext *ctx, const char *udi)
{
	NMHalManager *manager = (NMHalManager *) libhal_ctx_get_user_data (ctx);
	NMDevice *dev;

//	nm_debug ("Device removed (hal udi is '%s').", udi );

	if ((dev = nm_manager_get_device_by_udi (manager->nm_manager, udi)))
		nm_manager_remove_device (manager->nm_manager, dev, TRUE);
}

static void
device_new_capability (LibHalContext *ctx, const char *udi, const char *capability)
{
	NMHalManager *manager = (NMHalManager *) libhal_ctx_get_user_data (ctx);
	NMDeviceCreatorFn creator_fn;

	/*nm_debug ("nm_hal_device_new_capability() called with udi = %s, capability = %s", udi, capability );*/

	/* Ignore device additions while asleep, all devices will
	 * be found and set up again on wake.
	 */
	if (nm_manager_get_state (manager->nm_manager) == NM_STATE_ASLEEP)
		return;

	creator_fn = get_creator (manager, udi);
	if (creator_fn)
		create_device_and_add_to_list (manager, creator_fn, udi);
}

static void
add_initial_devices (NMHalManager *manager)
{
	DeviceCreator *creator;
	GSList *iter;
	char **devices;
	int num_devices;
	int i;
	DBusError err;

	for (iter = manager->device_creators; iter; iter = iter->next) {
		creator = (DeviceCreator *) iter->data;

		dbus_error_init (&err);
		devices = libhal_find_device_by_capability (manager->hal_ctx,
													creator->capability_str,
													&num_devices,
													&err);

		if (dbus_error_is_set (&err)) {
			nm_warning ("could not find existing devices: %s", err.message);
			dbus_error_free (&err);
		}

		if (devices) {
			for (i = 0; i < num_devices; i++) {
				if (creator->is_device_fn (manager, devices[i]))
					create_device_and_add_to_list (manager, creator->creator_fn, devices[i]);
			}
		}

		libhal_free_string_array (devices);
	}
}

typedef struct {
	NMHalManager *manager;
	gboolean initial_state;
	gboolean changed;
	guint32 pending_polls;
	GSList *proxies;
} NMKillswitchPollInfo;

static void
killswitch_getpower_done (gpointer user_data)
{
	NMKillswitchPollInfo *info = (NMKillswitchPollInfo *) user_data;

	info->pending_polls--;

	if (info->pending_polls == 0) {
		g_slist_foreach (info->proxies, (GFunc) g_object_unref, NULL);
		g_slist_free (info->proxies);
		info->proxies = NULL;

		if (info->changed)
			nm_manager_set_wireless_hardware_enabled (info->manager->nm_manager, !info->initial_state);
	}
}

static void 
killswitch_getpower_reply (DBusGProxy *proxy,
					  DBusGProxyCall *call_id,
					  gpointer user_data)
{
	NMKillswitchPollInfo *info = (NMKillswitchPollInfo *) user_data;
	int status;
	GError *err = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &err,
						  G_TYPE_INT, &status,
						  G_TYPE_INVALID)) {
		if (!info->changed && info->initial_state != (status == 0) ? FALSE : TRUE)
			info->changed = TRUE;
	} else {
		const char *prev_err = info->manager->kswitch_err;

		/* Only print the error if we haven't seen it before */
		if (   err->message
		    && (!prev_err || strcmp (prev_err, err->message) != 0)) {
			nm_warning ("Error getting killswitch power: %s.", err->message);
			g_free (info->manager->kswitch_err);
			info->manager->kswitch_err = g_strdup (err->message);
		}
		g_error_free (err);
	}
}

static void
poll_killswitches_real (gpointer data, gpointer user_data)
{
	NMKillswitchPollInfo *info = (NMKillswitchPollInfo *) user_data;
	DBusGProxy *proxy;

	proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (info->manager->dbus_mgr),
								"org.freedesktop.Hal",
								(char *) data,
								"org.freedesktop.Hal.Device.KillSwitch");

	dbus_g_proxy_begin_call (proxy, "GetPower",
						killswitch_getpower_reply,
						info,
						killswitch_getpower_done,
						G_TYPE_INVALID);
	info->pending_polls++;
	info->proxies = g_slist_prepend (info->proxies, proxy);
}

static gboolean
poll_killswitches (gpointer user_data)
{
	NMKillswitchPollInfo *info = (NMKillswitchPollInfo *) user_data;

	info->initial_state = nm_manager_wireless_hardware_enabled (info->manager->nm_manager);
	info->changed = FALSE;
	info->pending_polls = 0;

	g_slist_foreach (info->manager->killswitch_list, poll_killswitches_real, info);
	return TRUE;
}

static void
killswitch_poll_destroy (gpointer data)
{
	NMKillswitchPollInfo *info = (NMKillswitchPollInfo *) data;

	if (info->proxies) {
		g_slist_foreach (info->proxies, (GFunc) g_object_unref, NULL);
		g_slist_free (info->proxies);
	}
	g_slice_free (NMKillswitchPollInfo, info);
}

static void
add_killswitch_device (NMHalManager *manager, const char *udi)
{
	char *type;
	GSList *iter;

	type = libhal_device_get_property_string (manager->hal_ctx, udi, "killswitch.type", NULL);
	if (!type)
		return;

	if (strcmp (type, "wlan"))
		goto out;

	/* see if it's already in the list */
	for (iter = manager->killswitch_list; iter; iter = iter->next) {
		const char *list_udi = (const char *) iter->data;
		if (!strcmp (list_udi, udi))
			goto out;
	}

	/* Start polling switches if this is the first switch we've found */
	if (!manager->killswitch_list) {
		NMKillswitchPollInfo *info;

		info = g_slice_new0 (NMKillswitchPollInfo);
		info->manager = manager;

		manager->killswitch_poll_id = g_timeout_add_full (G_PRIORITY_DEFAULT,
												NM_HAL_MANAGER_KILLSWITCH_POLL_FREQUENCY * 1000,
												poll_killswitches,
												info,
												killswitch_poll_destroy);
	}

	manager->killswitch_list = g_slist_append (manager->killswitch_list, g_strdup (udi));
	nm_info ("Found radio killswitch %s", udi);

out:
	libhal_free_string (type);
}

static void
add_killswitch_devices (NMHalManager *manager)
{
	char **udis;
	int num_udis;
	int i;
	DBusError	err;

	dbus_error_init (&err);
	udis = libhal_find_device_by_capability (manager->hal_ctx, "killswitch", &num_udis, &err);
	if (!udis)
		return;

	if (dbus_error_is_set (&err)) {
		nm_warning ("Could not find killswitch devices: %s", err.message);
		dbus_error_free (&err);
		return;
	}

	for (i = 0; i < num_udis; i++)
		add_killswitch_device (manager, udis[i]);

	libhal_free_string_array (udis);
}

static gboolean
hal_init (NMHalManager *manager)
{
	DBusError error;
	DBusGConnection *connection; 
	gboolean success = FALSE;

	manager->hal_ctx = libhal_ctx_new ();
	if (!manager->hal_ctx) {
		nm_warning ("Could not get connection to the HAL service.");
		return FALSE;
	}

	connection = nm_dbus_manager_get_connection (manager->dbus_mgr);
	libhal_ctx_set_dbus_connection (manager->hal_ctx,
									dbus_g_connection_get_connection (connection));

	dbus_error_init (&error);
	if (!libhal_ctx_init (manager->hal_ctx, &error)) {
		nm_error ("libhal_ctx_init() failed: %s\n"
				  "Make sure the hal daemon is running?", 
				  error.message);
		goto out;
	}

	libhal_ctx_set_user_data (manager->hal_ctx, manager);
	libhal_ctx_set_device_added (manager->hal_ctx, device_added);
	libhal_ctx_set_device_removed (manager->hal_ctx, device_removed);
	libhal_ctx_set_device_new_capability (manager->hal_ctx, device_new_capability);

	libhal_device_property_watch_all (manager->hal_ctx, &error);
	if (dbus_error_is_set (&error)) {
		nm_error ("libhal_device_property_watch_all(): %s", error.message);
		libhal_ctx_shutdown (manager->hal_ctx, NULL);
		goto out;
	}

	/* Add any devices we know about */
	add_killswitch_devices (manager);
	add_initial_devices (manager);
	success = TRUE;

out:
	if (!success) {
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		if (manager->hal_ctx) {
			libhal_ctx_free (manager->hal_ctx);
			manager->hal_ctx = NULL;
		}
	}

	return success;
}

static void
hal_deinit (NMHalManager *manager)
{
	DBusError error;

	if (manager->killswitch_poll_id) {
		g_source_remove (manager->killswitch_poll_id);
		manager->killswitch_poll_id = 0;
	}

	if (manager->killswitch_list) {
		g_slist_foreach (manager->killswitch_list, (GFunc) g_free, NULL);
		g_slist_free (manager->killswitch_list);
		manager->killswitch_list = NULL;
	}

	if (!manager->hal_ctx)
		return;

	dbus_error_init (&error);
	libhal_ctx_shutdown (manager->hal_ctx, &error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("libhal shutdown failed - %s", error.message);
		dbus_error_free (&error);
	}

	libhal_ctx_free (manager->hal_ctx);
	manager->hal_ctx = NULL;
}

static void
name_owner_changed (NMDBusManager *dbus_mgr,
					const char *name,
					const char *old,
					const char *new,
					gpointer user_data)
{
	NMHalManager *manager = (NMHalManager *) user_data;
	gboolean old_owner_good = (old && (strlen (old) > 0));
	gboolean new_owner_good = (new && (strlen (new) > 0));

	/* Only care about signals from HAL */
	if (strcmp (name, "org.freedesktop.Hal"))
		return;

	if (!old_owner_good && new_owner_good) {
		/* HAL just appeared */
		if (!hal_init (manager))
			exit (1);
	} else if (old_owner_good && !new_owner_good) {
		/* HAL went away. Bad HAL. */
		hal_deinit (manager);
	}
}

static void
connection_changed (NMDBusManager *dbus_mgr,
					DBusGConnection *connection,
					gpointer user_data)
{
	NMHalManager *manager = (NMHalManager *) user_data;
	char *owner;

	if (!connection) {
		hal_deinit (manager);
		return;
	}

	if ((owner = nm_dbus_manager_get_name_owner (dbus_mgr, "org.freedesktop.Hal"))) {
		if (!hal_init (manager))
			exit (1);
		g_free (owner);
	}
}

static void
nm_manager_state_changed (NMManager *nm_manager, NMState state, gpointer user_data)
{
	NMHalManager *manager = (NMHalManager *) user_data;

	if (state == NM_STATE_ASLEEP) {
		/* Save the sleep state */
		manager->nm_sleeping = TRUE;
	} else if (manager->nm_sleeping) {
		/* If the previous state was sleep, the next one means we just woke up */
		manager->nm_sleeping = FALSE;
		add_initial_devices (manager);
	}
}

NMHalManager *
nm_hal_manager_new (NMManager *nm_manager)
{
	NMHalManager *manager;
	NMDBusManager *dbus_mgr;

	g_return_val_if_fail (NM_IS_MANAGER (nm_manager), NULL);

	dbus_mgr = nm_dbus_manager_get ();
	if (!nm_dbus_manager_name_has_owner (dbus_mgr, "org.freedesktop.Hal")) {
		nm_warning ("Could not initialize connection to the HAL daemon.");
		return NULL;
	}

	manager = g_slice_new0 (NMHalManager);
	manager->nm_manager = g_object_ref (nm_manager);
	manager->dbus_mgr = dbus_mgr;

	register_built_in_creators (manager);

	g_signal_connect (manager->dbus_mgr,
	                  "name-owner-changed",
	                  G_CALLBACK (name_owner_changed),
	                  manager);
	g_signal_connect (manager->dbus_mgr,
	                  "dbus-connection-changed",
	                  G_CALLBACK (connection_changed),
	                  manager);

	g_signal_connect (nm_manager,
					  "state-change",
					  G_CALLBACK (nm_manager_state_changed),
					  manager);

	hal_init (manager);

	return manager;
}

static void
destroy_creator (gpointer data, gpointer user_data)
{
	g_free (((DeviceCreator *) data)->capability_str);
	g_slice_free (DeviceCreator, data);
}

void
nm_hal_manager_destroy (NMHalManager *manager)
{
	if (!manager)
		return;

	g_free (manager->kswitch_err);

	g_slist_foreach (manager->device_creators, destroy_creator, NULL);
	g_slist_free (manager->device_creators);

	hal_deinit (manager);
	g_object_unref (manager->nm_manager);
	g_slice_free (NMHalManager, manager);
}
