#include <string.h>
#include <stdlib.h>
#include <libhal.h>
#include "nm-hal-manager.h"
#include "nm-dbus-manager.h"
#include "nm-utils.h"
#include "nm-device-802-11-wireless.h"
#include "nm-device-802-3-ethernet.h"

struct _NMHalManager {
	LibHalContext *hal_ctx;
	NMDBusManager *dbus_mgr;
	NMManager *nm_manager;
	NMData *nm_data;

	gboolean nm_sleeping;
};

static char *
get_device_interface_from_hal (LibHalContext *ctx, const char *udi)
{
	char *iface = NULL;

	if (libhal_device_property_exists (ctx, udi, "net.interface", NULL)) {
		/* Only use Ethernet and Wireless devices at the moment */
		if (libhal_device_property_exists (ctx, udi, "info.category", NULL)) {
			char *category = libhal_device_get_property_string (ctx, udi, "info.category", NULL);
			if (category && (!strcmp (category, "net.80203") || !strcmp (category, "net.80211"))) {
				char *temp = libhal_device_get_property_string (ctx, udi, "net.interface", NULL);
				iface = g_strdup (temp);
				libhal_free_string (temp);
			}
			libhal_free_string (category);
		}
	}

	return iface;
}

static NMDeviceType
discover_device_type (LibHalContext *ctx, const char *udi)
{
	char *category = NULL;

	if (libhal_device_property_exists (ctx, udi, "info.category", NULL))
		category = libhal_device_get_property_string (ctx, udi, "info.category", NULL);
	if (category && (!strcmp (category, "net.80211")))
		return DEVICE_TYPE_802_11_WIRELESS;
	else if (category && (!strcmp (category, "net.80203")))
		return DEVICE_TYPE_802_3_ETHERNET;

	return DEVICE_TYPE_UNKNOWN;
}

/*
 * nm_get_device_driver_name
 *
 * Get the device's driver name from HAL.
 *
 */
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

static NMDevice *
create_nm_device (LibHalContext *ctx,
				  NMData *nm_data,
				  const char *iface,
				  const char *udi)
{
	NMDevice *dev;
	char *driver;
	NMDeviceType type;

	type = discover_device_type (ctx, udi);
	driver = nm_get_device_driver_name (ctx, udi);

	switch (type) {
	case DEVICE_TYPE_802_11_WIRELESS:
		dev = (NMDevice *) nm_device_802_11_wireless_new (iface, udi, driver, FALSE, nm_data);
		break;
	case DEVICE_TYPE_802_3_ETHERNET:
		dev = (NMDevice *) nm_device_802_3_ethernet_new (iface, udi, driver, FALSE, nm_data);
		break;

	default:
		g_assert_not_reached ();
	}

	g_free (driver);

	return dev;
}

static NMDevice *
create_device_and_add_to_list (NMHalManager *manager, const char *udi, const char *iface,
							   gboolean test_device, NMDeviceType test_device_type)
{
	NMDevice *dev = NULL;
	char *usb_test = NULL;

	/* Make sure the device is not already in the device list */
	if ((dev = nm_manager_get_device_by_iface (manager->nm_manager, iface)))
		return NULL;

	/* Ignore Ethernet-over-USB devices too for the moment (Red Hat #135722) */
	if (libhal_device_property_exists (manager->hal_ctx, udi, "usb.interface.class", NULL)
		&& (usb_test = libhal_device_get_property_string (manager->hal_ctx, udi, "usb.interface.class", NULL))) {

		libhal_free_string (usb_test);
		return NULL;
	}

	if ((dev = create_nm_device (manager->hal_ctx, manager->nm_data, iface, udi))) {
		nm_info ("Now managing %s device '%s'.",
				 NM_IS_DEVICE_802_11_WIRELESS (dev) ? "wireless (802.11)" : "wired Ethernet (802.3)",
				 nm_device_get_iface (dev));

		nm_manager_add_device (manager->nm_manager, dev);
	}

	return dev;
}

static void
device_added (LibHalContext *ctx, const char *udi)
{
	NMHalManager *manager = (NMHalManager *) libhal_ctx_get_user_data (ctx);
	char *iface;

	nm_debug ("New device added (hal udi is '%s').", udi );

	/* Sometimes the device's properties (like net.interface) are not set up yet,
	 * so this call will fail, and it will actually be added when hal sets the device's
	 * capabilities a bit later on.
	 */
	if ((iface = get_device_interface_from_hal (manager->hal_ctx, udi))) {
		create_device_and_add_to_list (manager, udi, iface, FALSE, DEVICE_TYPE_UNKNOWN);
		g_free (iface);
	}
}

static void
device_removed (LibHalContext *ctx, const char *udi)
{
	NMHalManager *manager = (NMHalManager *) libhal_ctx_get_user_data (ctx);
	NMDevice *dev;

	nm_debug ("Device removed (hal udi is '%s').", udi );

	if ((dev = nm_manager_get_device_by_udi (manager->nm_manager, udi)))
		nm_manager_remove_device (manager->nm_manager, dev);
}

static void
device_new_capability (LibHalContext *ctx, const char *udi, const char *capability)
{
	NMHalManager *manager = (NMHalManager *) libhal_ctx_get_user_data (ctx);

	/*nm_debug ("nm_hal_device_new_capability() called with udi = %s, capability = %s", udi, capability );*/

	if (capability && ((strcmp (capability, "net.80203") == 0) || (strcmp (capability, "net.80211") == 0))) {
		char *iface;

		if ((iface = get_device_interface_from_hal (manager->hal_ctx, udi))) {
			create_device_and_add_to_list (manager, udi, iface, FALSE, DEVICE_TYPE_UNKNOWN);
			g_free (iface);
		}
	}
}

static void
add_initial_devices (NMHalManager *manager)
{
	char **net_devices;
	int num_net_devices;
	int i;
	DBusError error;

	dbus_error_init (&error);
	/* Grab a list of network devices */
	net_devices = libhal_find_device_by_capability (manager->hal_ctx, "net", &num_net_devices, &error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("could not find existing networking devices: %s", error.message);
		dbus_error_free (&error);
	}

	if (net_devices) {
		for (i = 0; i < num_net_devices; i++) {
			char *iface;

			if ((iface = get_device_interface_from_hal (manager->hal_ctx, net_devices[i]))) {
				create_device_and_add_to_list (manager, net_devices[i], iface, FALSE, DEVICE_TYPE_UNKNOWN);
				g_free (iface);
			}
		}
	}

	libhal_free_string_array (net_devices);
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
					DBusGConnection *connection,
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
			exit (EXIT_FAILURE);
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
			exit (EXIT_FAILURE);
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
nm_hal_manager_new (NMManager *nm_manager, NMData *nm_data)
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
	manager->nm_data = nm_data;

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
	add_initial_devices (manager);

	return manager;
}

void
nm_hal_manager_destroy (NMHalManager *manager)
{
	if (manager) {
		hal_deinit (manager);
		g_object_unref (manager->nm_manager);
		g_slice_free (NMHalManager, manager);
	}
}
