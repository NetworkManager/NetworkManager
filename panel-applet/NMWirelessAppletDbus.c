/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include "NMWirelessAppletDbus.h"
#include "NMWirelessApplet.h"

#define	DBUS_NO_SERVICE_ERROR			"org.freedesktop.DBus.Error.ServiceDoesNotExist"


/* dbus doesn't define a DBUS_TYPE_STRING_ARRAY so we fake one here for consistency */
#define	DBUS_TYPE_STRING_ARRAY		((int) '$')

/*
 * nm_null_safe_strcmp
 *
 * Doesn't freaking segfault if s1/s2 are NULL
 *
 */
int nm_null_safe_strcmp (const char *s1, const char *s2)
{
	if (!s1 && !s2)
		return 0;
	if (!s1 && s2)
		return -1;
	if (s1 && !s2)
		return 1;
		
	return (strcmp (s1, s2));
}


/*
 * nmwa_dbus_call_nm_method
 *
 * Do a method call on NetworkManager.
 *
 * Returns:	RETURN_SUCCESS on success
 *			RETURN_FAILURE on failure
 *			RETURN_NO_NM if NetworkManager service no longer exists
 */
static int nmwa_dbus_call_nm_method (DBusConnection *con, const char *path, const char *method, int arg_type, void **arg, int *item_count)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;
	char			*dbus_string = NULL;
	int			 dbus_int = 0;
	gboolean		 dbus_bool = FALSE;
	char			**dbus_string_array = NULL;
	int			 num_items = 0;
	dbus_bool_t	 ret = TRUE;

	g_return_val_if_fail (con != NULL, RETURN_FAILURE);
	g_return_val_if_fail (path != NULL, RETURN_FAILURE);
	g_return_val_if_fail (method != NULL, RETURN_FAILURE);
	g_return_val_if_fail (((arg_type == DBUS_TYPE_STRING) || (arg_type == DBUS_TYPE_INT32) || (arg_type == DBUS_TYPE_UINT32) || (arg_type == DBUS_TYPE_BOOLEAN) || (arg_type == DBUS_TYPE_STRING_ARRAY)), RETURN_FAILURE);
	g_return_val_if_fail (arg != NULL, RETURN_FAILURE);

	if ((arg_type == DBUS_TYPE_STRING) || (arg_type == DBUS_TYPE_STRING_ARRAY))
		g_return_val_if_fail (*arg == NULL, RETURN_FAILURE);

	if (arg_type == DBUS_TYPE_STRING_ARRAY)
	{
		g_return_val_if_fail (item_count != NULL, RETURN_FAILURE);
		*item_count = 0;
		*((char **)arg) = NULL;
	}

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, path, NM_DBUS_INTERFACE, method)))
	{
		fprintf (stderr, "nmwa_dbus_call_nm_method(): Couldn't allocate the dbus message\n");
		return (RETURN_FAILURE);
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (con, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		int	ret = RETURN_FAILURE;

		if (!strcmp (error.name, DBUS_NO_SERVICE_ERROR))
			ret = RETURN_NO_NM;
		else if (!strcmp (error.name, NM_DBUS_NO_ACTIVE_NET_ERROR))
			ret = RETURN_SUCCESS;
		else if (!strcmp (error.name, NM_DBUS_NO_ACTIVE_DEVICE_ERROR))
			ret = RETURN_SUCCESS;
		else if (!strcmp (error.name, NM_DBUS_NO_NETWORKS_ERROR))
			ret = RETURN_SUCCESS;

		if ((ret != RETURN_SUCCESS) && (ret != RETURN_NO_NM))
			fprintf (stderr, "nmwa_dbus_call_nm_method(): %s raised:\n %s\n\n", error.name, error.message);

		dbus_error_free (&error);
		return (ret);
	}

	if (reply == NULL)
	{
		fprintf (stderr, "nmwa_dbus_call_nm_method(): dbus reply message was NULL\n" );
		return (RETURN_FAILURE);
	}

	dbus_error_init (&error);
	switch (arg_type)
	{
		case DBUS_TYPE_STRING:
			ret = dbus_message_get_args (reply, &error, DBUS_TYPE_STRING, &dbus_string, DBUS_TYPE_INVALID);
			break;
		case DBUS_TYPE_STRING_ARRAY:
			ret = dbus_message_get_args (reply, &error, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &dbus_string_array, &num_items, DBUS_TYPE_INVALID);
			break;
		case DBUS_TYPE_INT32:
			ret = dbus_message_get_args (reply, &error, DBUS_TYPE_INT32, &dbus_int, DBUS_TYPE_INVALID);
			break;
		case DBUS_TYPE_UINT32:
			ret = dbus_message_get_args (reply, &error, DBUS_TYPE_UINT32, &dbus_int, DBUS_TYPE_INVALID);
			break;
		case DBUS_TYPE_BOOLEAN:
			ret = dbus_message_get_args (reply, &error, DBUS_TYPE_BOOLEAN, &dbus_bool, DBUS_TYPE_INVALID);
			break;
		default:
			fprintf (stderr, "nmwa_dbus_call_nm_method(): Unknown argument type!\n");
			ret = FALSE;
			break;
	}

	if (!ret)
	{
		fprintf (stderr, "nmwa_dbus_call_nm_method(): error while getting args: name='%s' message='%s'\n", error.name, error.message);
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		dbus_message_unref (reply);
		return (RETURN_FAILURE);
	}

	switch (arg_type)
	{
		case DBUS_TYPE_STRING:
			*((char **)(arg)) = g_strdup (dbus_string);
			break;
		case DBUS_TYPE_STRING_ARRAY:
			*((char ***)(arg)) = g_strdupv (dbus_string_array);
			*item_count = num_items;
			break;
		case DBUS_TYPE_INT32:
		case DBUS_TYPE_UINT32:
			*((int *)(arg)) = dbus_int;
			break;
		case DBUS_TYPE_BOOLEAN:
			*((gboolean *)(arg)) = dbus_bool;
			break;
		default:
			g_assert_not_reached ();
			break;
	}

	dbus_message_unref (reply);
	return (RETURN_SUCCESS);
}


/*
 * nmwa_dbus_get_active_device
 *
 * Returns the object_path of the currently active device, if any.
 *
 */
static char * nmwa_dbus_get_active_device (NMWirelessApplet *applet, AppletState failure_state)
{
	char *active_device = NULL;

	switch (nmwa_dbus_call_nm_method (applet->connection, NM_DBUS_PATH, "getActiveDevice", DBUS_TYPE_STRING, (void **)(&active_device), NULL))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		case (RETURN_FAILURE):
			if (failure_state != APPLET_STATE_IGNORE)
				applet->applet_state = failure_state;
			break;

		default:
			break;			
	}

	return (active_device);
}


/*
 * nmwa_dbus_get_active_network
 *
 * Returns the object_path of the currently active network of the active device.
 *
 */
static char * nmwa_dbus_get_active_network (NMWirelessApplet *applet, char *dev_path, AppletState failure_state)
{
	char *network = NULL;

	switch (nmwa_dbus_call_nm_method (applet->connection, dev_path, "getActiveNetwork", DBUS_TYPE_STRING, (void **)(&network), NULL))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		case (RETURN_FAILURE):
			if (failure_state != APPLET_STATE_IGNORE)
				applet->applet_state = failure_state;
			break;

		default:
			break;			
	}

	return (network);
}


/*
 * nmwa_dbus_get_device_type
 *
 * Returns the device type of the specified device.
 *
 */
static int nmwa_dbus_get_device_type (NMWirelessApplet *applet, char *path, AppletState failure_state)
{
	int	type = -1;

	switch (nmwa_dbus_call_nm_method (applet->connection, path, "getType", DBUS_TYPE_INT32, (void **)(&type), NULL))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		case (RETURN_FAILURE):
			applet->applet_state = failure_state;
			break;

		default:
			break;			
	}

	return (type);
}


/*
 * nmwa_dbus_get_device_link_active
 *
 * Returns the device's link status
 *
 */
static gboolean nmwa_dbus_get_device_link_active (NMWirelessApplet *applet, char *net_path)
{
	gboolean	link = FALSE;

	switch (nmwa_dbus_call_nm_method (applet->connection, net_path, "getLinkActive", DBUS_TYPE_BOOLEAN, (void **)(&link), NULL))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		default:
			break;
	}

	return (link);
}


/*
 * nmwa_dbus_get_device_driver_support_level
 *
 * Returns whether or not the device supports carrier detection.
 *
 */
static gboolean nmwa_dbus_get_device_driver_support_level (NMWirelessApplet *applet, char *net_path)
{
	guint32	driver_support_level = FALSE;

	switch (nmwa_dbus_call_nm_method (applet->connection, net_path, "getDriverSupportLevel",
				DBUS_TYPE_UINT32, (void **)(&driver_support_level), NULL))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		default:
			break;			
	}

	return (driver_support_level);
}


/*
 * nmwa_dbus_get_hw_addr
 *
 * Return the hardware address of a given device
 *
 */
static char * nmwa_dbus_get_hw_addr (NMWirelessApplet *applet, char *dev_path)
{
	char *addr = NULL;

	switch (nmwa_dbus_call_nm_method (applet->connection, dev_path, "getHWAddress", DBUS_TYPE_STRING, (void **)(&addr), NULL))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		default:
			break;			
	}

	return (addr);
}


/*
 * nmwa_dbus_get_object_strength
 *
 * Returns the strength of a given object (device or wireless network)
 *
 */
static gint8 nmwa_dbus_get_object_strength (NMWirelessApplet *applet, char *path)
{
	int	strength = -1;

	switch (nmwa_dbus_call_nm_method (applet->connection, path, "getStrength", DBUS_TYPE_INT32, (void **)(&strength), NULL))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		default:
			break;			
	}

	return (strength);
}


/*
 * nmwa_dbus_get_nm_status
 *
 * Returns NetworkManager's status
 *
 */
static char * nmwa_dbus_get_nm_status (NMWirelessApplet *applet, AppletState failure_state)
{
	char *status = NULL;

	switch (nmwa_dbus_call_nm_method (applet->connection, NM_DBUS_PATH, "status", DBUS_TYPE_STRING, (void **)(&status), NULL))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		case (RETURN_FAILURE):
			applet->applet_state = failure_state;
			break;

		default:
			break;			
	}
	return (status);
}


/*
 * nmwa_dbus_get_object_name
 *
 * Returns the name of a specified object (wireless network, device, etc)
 *
 */
static char * nmwa_dbus_get_object_name (NMWirelessApplet *applet, const char *path)
{
	char *name = NULL;

	switch (nmwa_dbus_call_nm_method (applet->connection, path, "getName", DBUS_TYPE_STRING, (void **)(&name), NULL))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		default:
			break;			
	}

	return (name);
}


/*
 * nmwa_dbus_get_object_mode
 *
 * Returns the mode (ie Ad-Hoc, Infrastructure) of a specified object (wireless network, device, etc)
 *
 */
static NMNetworkMode nmwa_dbus_get_object_mode (NMWirelessApplet *applet, char *path)
{
	NMNetworkMode	mode = NETWORK_MODE_INFRA;

	switch (nmwa_dbus_call_nm_method (applet->connection, path, "getMode", DBUS_TYPE_UINT32, (void **)(&mode), NULL))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		default:
			break;			
	}

	return (mode);
}


/*
 * nmwa_dbus_get_device_udi
 *
 * Returns the HAL udi of a network device
 *
 */
static char * nmwa_dbus_get_device_udi (NMWirelessApplet *applet, char *dev_path)
{
	char *udi = NULL;

	switch (nmwa_dbus_call_nm_method (applet->connection, dev_path, "getHalUdi", DBUS_TYPE_STRING, (void **)(&udi), NULL))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		default:
			break;			
	}

	return (udi);
}


/*
 * nmwa_dbus_get_network_encrypted
 *
 * Returns whether or not the specified network is encrypted
 *
 */
static gboolean nmwa_dbus_get_network_encrypted (NMWirelessApplet *applet, char *net_path)
{
	gboolean	enc = FALSE;

	switch (nmwa_dbus_call_nm_method (applet->connection, net_path, "getEncrypted", DBUS_TYPE_BOOLEAN, (void **)(&enc), NULL))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		default:
			break;			
	}

	return (enc);
}


/*
 * nmwa_dbus_get_wireless_enabled
 */
static gboolean nmwa_dbus_get_wireless_enabled (NMWirelessApplet *applet)
{
	gboolean	enabled = FALSE;

	switch (nmwa_dbus_call_nm_method (applet->connection, NM_DBUS_PATH, "getWirelessEnabled", DBUS_TYPE_BOOLEAN, (void **)(&enabled), NULL))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		default:
			break;			
	}

	return (enabled);
}


/*
 * nmwa_dbus_get_device_networks
 *
 * Returns an array of wireless networks that the specified device knows about.
 *
 */
static char **nmwa_dbus_get_device_networks (NMWirelessApplet *applet, char *path, int *num_items, AppletState failure_state)
{
	char **array = NULL;
	int	  items;

	switch (nmwa_dbus_call_nm_method (applet->connection, path, "getNetworks", DBUS_TYPE_STRING_ARRAY, (void **)(&array), &items))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		case (RETURN_FAILURE):
			applet->applet_state = failure_state;
			break;

		case (RETURN_SUCCESS):
			*num_items = items;
			break;

		default:
			break;			
	}

	return (array);
}


/*
 * nmwa_dbus_get_hal_device_string_property
 *
 * Get a string property from a device
 *
 */
static char *nmwa_dbus_get_hal_device_string_property (DBusConnection *connection, const char *udi, const char *property_name)
{
	DBusError		 error;
	DBusMessage	*message;
	DBusMessage	*reply;
	char			*dbus_property = NULL;
	char			*property = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (udi != NULL, NULL);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi, "org.freedesktop.Hal.Device", "GetPropertyString");
	if (!message)
		return (NULL);

	dbus_error_init (&error);
	dbus_message_append_args (message, DBUS_TYPE_STRING, property_name, DBUS_TYPE_INVALID);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "nmwa_dbus_get_hal_device_string_property(): %s raised:\n %s\n\n", error.name, error.message);
		dbus_error_free (&error);
		return (NULL);
	}

	if (reply == NULL)
	{
		fprintf (stderr, "nmwa_dbus_get_hal_device_string_property(): dbus reply message was NULL\n" );
		return (NULL);
	}

	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_STRING, &dbus_property, DBUS_TYPE_INVALID))
	{
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		dbus_property = NULL;
	}
	else
		property = g_strdup (dbus_property);

	dbus_message_unref (reply);	
	return (property);
}


/*
 * nmwa_dbus_get_hal_device_info
 *
 * Grab the info.product tag from hal for a specific UDI
 *
 */
static char *nmwa_dbus_get_hal_device_info (DBusConnection *connection, const char *udi)
{
	DBusError		 error;
	DBusMessage	*message;
	DBusMessage	*reply;
	gboolean		 exists = FALSE;
	char			*info = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (udi != NULL, NULL);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi, "org.freedesktop.Hal.Device", "PropertyExists");
	if (!message)
		return (NULL);

	dbus_error_init (&error);
	dbus_message_append_args (message, DBUS_TYPE_STRING, "info.product", DBUS_TYPE_INVALID);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "nmwa_dbus_get_hal_device_info(): %s raised:\n %s\n\n", error.name, error.message);
		dbus_error_free (&error);
		return (NULL);
	}

	if (reply == NULL)
	{
		fprintf (stderr, "nmwa_dbus_get_hal_device_info(): dbus reply message was NULL\n" );
		return (NULL);
	}

	dbus_error_init (&error);
	if (dbus_message_get_args (reply, &error, DBUS_TYPE_BOOLEAN, &exists, DBUS_TYPE_INVALID))
	{
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		info = nmwa_dbus_get_hal_device_string_property (connection, udi, "info.product");
	}

	dbus_message_unref (reply);
	
	return (info);
}


/*
 * nmwa_dbus_set_device
 *
 * Tell NetworkManager to use a specific network device that the user picked, and
 * possibly a specific wireless network too.
 *
 */
void nmwa_dbus_set_device (DBusConnection *connection, const NetworkDevice *dev, const WirelessNetwork *network,
						NMEncKeyType key_type, const char *passphrase)
{
	DBusMessage	*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);

	if ((dev->type == DEVICE_TYPE_WIRED_ETHERNET) && !passphrase && (key_type != -1))
		return;

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "setActiveDevice")))
	{
		if ((dev->type == DEVICE_TYPE_WIRELESS_ETHERNET) && network && network->essid)
		{
			fprintf (stderr, "Forcing device '%s' and network '%s' %s passphrase\n", dev->nm_device, network->essid, passphrase ? "with" : "without");
			dbus_message_append_args (message, DBUS_TYPE_STRING, dev->nm_device,
									DBUS_TYPE_STRING, network->essid,
									DBUS_TYPE_STRING, (passphrase ? passphrase : ""),
									DBUS_TYPE_INT32, key_type,
									DBUS_TYPE_INVALID);
		}
		else
		{
			fprintf (stderr, "Forcing device '%s'\n", dev->nm_device);
			dbus_message_append_args (message, DBUS_TYPE_STRING, dev->nm_device, DBUS_TYPE_INVALID);
		}
		dbus_connection_send (connection, message, NULL);
	}
	else
		fprintf (stderr, "nm_dbus_set_device(): Couldn't allocate the dbus message\n");
}


/*
 * nmwa_dbus_create_network
 *
 * Tell NetworkManager to create an Ad-Hoc wireless network
 *
 */
void nmwa_dbus_create_network (DBusConnection *connection, const NetworkDevice *dev, const WirelessNetwork *network,
						NMEncKeyType key_type, const char *passphrase)
{
	DBusMessage	*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->type == DEVICE_TYPE_WIRELESS_ETHERNET);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "createWirelessNetwork")))
	{
		if (network && network->essid)
		{
			fprintf (stderr, "Creating network '%s' %s passphrase on device '%s'.\n", network->essid, passphrase ? "with" : "without", dev->nm_device);
			dbus_message_append_args (message, DBUS_TYPE_STRING, dev->nm_device,
									DBUS_TYPE_STRING, network->essid,
									DBUS_TYPE_STRING, (passphrase ? passphrase : ""),
									DBUS_TYPE_INT32, key_type,
									DBUS_TYPE_INVALID);
		}
		dbus_connection_send (connection, message, NULL);
	}
	else
		fprintf (stderr, "nm_dbus_set_device(): Couldn't allocate the dbus message\n");
}


/*
 * nmwa_dbus_enable_wireless
 *
 * Tell NetworkManager to enabled or disable all wireless devices.
 *
 */
void nmwa_dbus_enable_wireless (NMWirelessApplet *applet, gboolean enabled)
{
	DBusMessage	*message;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (applet->connection != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "setWirelessEnabled")))
	{
		dbus_message_append_args (message, DBUS_TYPE_BOOLEAN, enabled, DBUS_TYPE_INVALID);
		dbus_connection_send (applet->connection, message, NULL);
		applet->wireless_enabled = nmwa_dbus_get_wireless_enabled (applet);
	}
}


/*
 * wireless_network_ref
 *
 * Increment the reference count of the wireless network
 *
 */
void wireless_network_ref (WirelessNetwork *net)
{
	g_return_if_fail (net != NULL);

	net->refcount++;
}


/*
 * wireless_network_unref
 *
 * Unrefs (and possibly frees) the representation of a wireless network
 *
 */
void wireless_network_unref (WirelessNetwork *net)
{
	g_return_if_fail (net != NULL);

	net->refcount--;
	if (net->refcount < 1)
	{
		g_free (net->nm_name);
		g_free (net->essid);
		g_free (net);
	}
}


/*
 * wireless_network_new
 *
 * Create a new wireless network structure
 *
 */
WirelessNetwork *wireless_network_new (void)
{
	WirelessNetwork *net = NULL;

	if ((net = g_new0 (WirelessNetwork, 1)))
		wireless_network_ref (net);

	return (net);
}


/*
 * wireless_network_new_with_essid
 *
 * Create a new wireless network structure
 *
 */
WirelessNetwork *wireless_network_new_with_essid (const char *essid)
{
	WirelessNetwork *net = NULL;

	g_return_val_if_fail (essid != NULL, NULL);

	if ((net = wireless_network_new()))
		net->essid = g_strdup (essid);

	return (net);
}


/*
 * wireless_network_copy
 *
 * Create a new wireless network structure from an existing one
 *
 */
WirelessNetwork *wireless_network_copy (WirelessNetwork *src)
{
	WirelessNetwork *net = NULL;

	g_return_val_if_fail (src != NULL, NULL);

	if ((net = g_new0 (WirelessNetwork, 1)))
	{
		wireless_network_ref (net);
		net->nm_name = g_strdup (src->nm_name);
		net->essid = g_strdup (src->essid);
		net->active = src->active;
		net->encrypted = src->encrypted;
		net->strength = src->strength;
	}

	return (net);
}


/*
 * network_device_free_wireless_network_list
 *
 */
static void network_device_free_wireless_network_list (NetworkDevice *dev)
{
	g_return_if_fail (dev != NULL);

	g_slist_foreach (dev->networks, (GFunc) wireless_network_unref, NULL);
	g_slist_free (dev->networks);
	dev->networks = NULL;	
}


/*
 * network_device_remove_wireless_network
 *
 * Remove one wireless network from the wireless network list
 *
 */
void network_device_remove_wireless_network (NetworkDevice *dev, WirelessNetwork *net)
{
	GSList	*elt;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (net != NULL);

	for (elt = dev->networks; elt; elt = g_slist_next (elt))
	{
		if (elt->data == net)
		{
			dev->networks = g_slist_remove_link (dev->networks, elt);
			wireless_network_unref ((WirelessNetwork *)elt->data);
			g_slist_free (elt);
			break;
		}
	}
}

/*
 * network_device_ref
 *
 * Increment the reference count of the network device
 *
 */
void network_device_ref (NetworkDevice *dev)
{
	g_return_if_fail (dev != NULL);

	dev->refcount++;
}


/*
 * network_device_unref
 *
 * Unrefs (and possibly frees) the representation of a network device
 *
 */
void network_device_unref (NetworkDevice *dev)
{
	g_return_if_fail (dev != NULL);

	dev->refcount--;
	if (dev->refcount < 1)
	{
		network_device_free_wireless_network_list (dev);
		g_free (dev->nm_device);
		g_free (dev->nm_name);
		g_free (dev->udi);
		g_free (dev->hal_name);
		g_free (dev->addr);
		g_free (dev);
		memset (dev, 0, sizeof (NetworkDevice));
	}
}


/*
 * network_device_new
 *
 * Create a new network device representation
 *
 */
NetworkDevice *network_device_new (void)
{
	NetworkDevice *dev = NULL;

	if ((dev = g_malloc0 (sizeof (NetworkDevice))))
		network_device_ref (dev);

	return (dev);
}


/*
 * network_device_copy
 *
 * Create a new network device representation, filling its
 * data in from an already existing one.  Deep-copies the
 * wireless networks too.
 *
 */
NetworkDevice *network_device_copy (NetworkDevice *src)
{
	NetworkDevice *dev = NULL;

	g_return_val_if_fail (src != NULL, NULL);

	if ((dev = g_malloc0 (sizeof (NetworkDevice))))
	{
		GSList	*elt;

		network_device_ref (dev);
		dev->nm_device = g_strdup (src->nm_device);
		dev->type = src->type;
		dev->link = src->link;
		dev->addr = g_strdup (src->addr);
		dev->driver_support_level = src->driver_support_level;
		dev->nm_name = g_strdup (src->nm_name);
		dev->hal_name = g_strdup (src->hal_name);
		dev->udi = g_strdup (src->udi);
		dev->strength = src->strength;

		for (elt = src->networks; elt; elt = g_slist_next (elt))
		{
			WirelessNetwork *net = (WirelessNetwork *)elt->data;
			if (net)
			{
				WirelessNetwork *copy = wireless_network_copy (net);
				dev->networks = g_slist_append (dev->networks, copy);
			}
		}
	}

	return (dev);
}


/*
 * network_device_add_wireless_network
 *
 * Adds a wireless network to the network device's network list
 *
 */
void network_device_add_wireless_network (NetworkDevice *dev, WirelessNetwork *net)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (net != NULL);

	wireless_network_ref (net);
	dev->networks = g_slist_append (dev->networks, net);
}


static int sort_networks_function (WirelessNetwork *a, WirelessNetwork *b)
{
	const char *name_a = a->essid;
	const char *name_b = b->essid;

	if (name_a && !name_b)
		return -1;
	else if (!name_a && name_b)
		return 1;
	else if (!name_a && !name_b)
		return 0;
	else
		return strcasecmp (name_a, name_b);
}

/*
 * network_device_sort_wireless_networks
 *
 * Alphabetize the wireless networks list
 *
 */
void network_device_sort_wireless_networks (NetworkDevice *dev)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->type == DEVICE_TYPE_WIRELESS_ETHERNET);

	dev->networks = g_slist_sort (dev->networks, (GCompareFunc) sort_networks_function);
}


/*
 * nmwa_dbus_get_one_wireless_network
 *
 * Returns a new wireless network filled with info from NM
 *
 */
WirelessNetwork *nmwa_dbus_get_one_wireless_network (NMWirelessApplet *applet, NetworkDevice *dev,
					const char *net_path, const char *active_network)
{
	char				*name = NULL;
	WirelessNetwork	*net = NULL;

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (net_path != NULL, NULL);

	if (!(name = nmwa_dbus_get_object_name (applet, net_path)))
		goto out;

	if (strlen (name))
	{
		if (!(net = wireless_network_new ()))
			goto out;
		net->nm_name = g_strdup (net_path);
		net->essid = g_strdup (name);
		net->active = active_network ? (strcmp (net->nm_name, active_network) == 0) : FALSE;
		net->encrypted = nmwa_dbus_get_network_encrypted (applet, net->nm_name);
		net->strength = nmwa_dbus_get_object_strength (applet, net->nm_name);
	}

out:
	g_free (name);
	return net;
}


/*
 * nmwa_dbus_device_update_all_networks
 *
 * Query NetworkManager for the wireless networks a particular device
 * knows about, if the active device is wireless.
 *
 * NOTE: caller must lock device list if necessary
 *
 */
static void nmwa_dbus_device_update_all_networks (NetworkDevice *dev, NMWirelessApplet *applet)
{
	char		 *active_network = NULL;
	char		**networks = NULL;
	int		  num_items = 0;
	int		  i;
	g_return_if_fail (dev != NULL);

	/* Clear out existing entries in the list */
	if (dev->networks)
		network_device_free_wireless_network_list (dev);

	if (dev->type != DEVICE_TYPE_WIRELESS_ETHERNET)
		goto out;

	if (dev == applet->dbus_active_device)
		active_network = nmwa_dbus_get_active_network (applet, dev->nm_device, APPLET_STATE_IGNORE);
	if (applet->applet_state == APPLET_STATE_NO_NM)
		goto out;	/* Don't proceed if NetworkManager died during the call to get the active network */

	networks = nmwa_dbus_get_device_networks (applet, dev->nm_device, &num_items, APPLET_STATE_NO_CONNECTION);
	if (!networks || (applet->applet_state == APPLET_STATE_NO_NM))
		goto out;

	for (i = 0; i < num_items; i++)
	{
		WirelessNetwork *tmp_net = nmwa_get_net_for_nm_net (dev, networks[i]);

		/* Only add the network if its not already in the device's network list.  We
		 * don't want duplicates.
		 */
		if (!tmp_net)
		{
			WirelessNetwork	*net;

			if ((net = nmwa_dbus_get_one_wireless_network (applet, dev, networks[i], active_network)))
			{
				network_device_add_wireless_network (dev, net);
				wireless_network_unref (net);
			}
		}
	}

out:
	g_free (active_network);
	g_strfreev (networks);
}



void nmwa_free_gui_data_model (NMWirelessApplet *applet)
{
	g_return_if_fail (applet != NULL);

	if (applet->gui_device_list)
	{
		g_slist_foreach (applet->gui_device_list, (GFunc) network_device_unref, NULL);
		g_slist_free (applet->gui_device_list);
		applet->gui_device_list = NULL;
	}
	if (applet->gui_active_device)
	{
		network_device_unref (applet->gui_active_device);
		applet->gui_active_device = NULL;
	}
	if (applet->gui_nm_status)
	{
		g_free (applet->gui_nm_status);
		applet->gui_nm_status = NULL;
	}
}


void nmwa_free_dbus_data_model (NMWirelessApplet *applet)
{
	g_return_if_fail (applet != NULL);

	if (applet->dbus_device_list)
	{
		g_slist_foreach (applet->dbus_device_list, (GFunc) network_device_unref, NULL);
		g_slist_free (applet->dbus_device_list);
		applet->dbus_device_list = NULL;
	}
	if (applet->dbus_active_device)
	{
		network_device_unref (applet->dbus_active_device);
		applet->dbus_active_device = NULL;
	}
	if (applet->dbus_nm_status)
	{
		g_free (applet->dbus_nm_status);
		applet->dbus_nm_status = NULL;
	}
}


/*
 * nmwa_copy_data_model
 *
 * Copy the dbus data model over to the gui data model
 *
 */
void nmwa_copy_data_model (NMWirelessApplet *applet)
{
	GSList		*elt;
	NetworkDevice	*act_dev = NULL;

	g_return_if_fail (applet != NULL);

	/* Free the existing GUI data model. */
	nmwa_free_gui_data_model (applet);

	/* Deep-copy network devices to GUI data model */
	for (elt = applet->dbus_device_list; elt; elt = g_slist_next (elt))
	{
		NetworkDevice	*src = (NetworkDevice *)(elt->data);
		NetworkDevice	*dst = NULL;

		if (src->type == DEVICE_TYPE_WIRELESS_ETHERNET)
			network_device_sort_wireless_networks (src);

		if ((dst = network_device_copy (src)))
		{
			/* Transfer ownership of device to list, don't need to unref it */
			applet->gui_device_list = g_slist_append (applet->gui_device_list, dst);

			/* Make sure we get the right active device for the gui data model */
			if (applet->dbus_active_device == src)
			{
				network_device_ref (dst);
				act_dev = dst;
			}
		}
	}

	/* active_device is just a pointer into the device list, no need to deep-copy it */
	applet->gui_active_device = act_dev;
	applet->gui_nm_status = g_strdup (applet->dbus_nm_status);
}


/*
 * nmwa_dbus_update_active_device_strength
 *
 * Update the active device's current wireless network strength
 *
 */
static gboolean nmwa_dbus_update_active_device_strength (gpointer user_data)
{
	NMWirelessApplet *applet;

	g_return_val_if_fail (user_data != NULL, FALSE);

	applet = (NMWirelessApplet *)user_data;

	if (applet->applet_state == APPLET_STATE_NO_NM)
		return TRUE;

	if (applet->gui_active_device && (applet->gui_active_device->type == DEVICE_TYPE_WIRELESS_ETHERNET))
	{
		guint8	strength = nmwa_dbus_get_object_strength (applet, applet->gui_active_device->nm_device);

		applet->gui_active_device->strength = strength;
		if (applet->gui_active_device == applet->dbus_active_device)
			applet->dbus_active_device->strength = strength;
	}

	return (TRUE);
}


/*
 * nmwa_dbus_device_update_one_network
 *
 * Update one wireless network
 *
 */
static void nmwa_dbus_device_update_one_network (NMWirelessApplet *applet, DBusMessage *message)
{
	char				*dev_path = NULL;
	char				*net_path = NULL;
	NMNetworkStatus	 status;
	guint8			 strength = -1;
	DBusError			 error;
	gboolean			 success = TRUE;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (message != NULL);

	dbus_error_init (&error);
	/* Try first time with strength, which is only passed for NETWORK_STATUS_STRENGTH_CHANGED */
	if (!dbus_message_get_args (message, &error,
					DBUS_TYPE_STRING, &dev_path,
					DBUS_TYPE_STRING, &net_path,
					DBUS_TYPE_UINT32, &status,
					DBUS_TYPE_INT32, &strength,
					DBUS_TYPE_INVALID))
	{
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		dbus_error_init (&error);

		/* Try without strength */
		if (!dbus_message_get_args (message, &error,
					DBUS_TYPE_STRING, &dev_path,
					DBUS_TYPE_STRING, &net_path,
					DBUS_TYPE_UINT32, &status,
					DBUS_TYPE_INVALID))
		{
			if (dbus_error_is_set (&error))
				dbus_error_free (&error);
			success = FALSE;
		}
		/* If the signal is NETWORK_STATUS_STRENGTH_CHANGED but we didn't get passed
		 * a strength in the arguments, we can't use the signal.
		 */
		if (status == NETWORK_STATUS_STRENGTH_CHANGED)
			success = FALSE;
	}

	if (success)
	{
		NetworkDevice		*dev = nmwa_get_device_for_nm_device (applet->dbus_device_list, dev_path);
		WirelessNetwork	*net = dev ? nmwa_get_net_for_nm_net (dev, net_path) : NULL;
		gboolean			 changed = FALSE;

		switch (status)
		{
			case NETWORK_STATUS_DISAPPEARED:
				if (!dev || !net)
					break;
				network_device_remove_wireless_network (dev, net);
				changed = TRUE;
				break;

			case NETWORK_STATUS_APPEARED:
				if (!dev)
					break;
				/* Add it if it doesn't already exist in the device's network list */
				if (!net)
				{
					WirelessNetwork	*tmp_net;
					char				*active_network = NULL;

					if (dev == applet->dbus_active_device)
						active_network = nmwa_dbus_get_active_network (applet, dev->nm_device, APPLET_STATE_IGNORE);
					if (applet->applet_state == APPLET_STATE_NO_NM)
						break;

					if ((tmp_net = nmwa_dbus_get_one_wireless_network (applet, dev, net_path, active_network)))
					{
						network_device_add_wireless_network (dev, tmp_net);
						wireless_network_unref (tmp_net);
						changed = TRUE;
					}
					g_free (active_network);
				}
				break;

			case NETWORK_STATUS_STRENGTH_CHANGED:
				g_return_if_fail (net != NULL);
				net->strength = strength;
				changed = TRUE;
				break;

			default:
				break;
		}

		if (changed)
		{
			/* Now move the data over to the GUI side */
			g_mutex_lock (applet->data_mutex);
			nmwa_copy_data_model (applet);
			g_mutex_unlock (applet->data_mutex);
			nmwa_dbus_update_active_device_strength (applet);
		}
	}
}


/*
 * nmwa_dbus_schedule_driver_notification
 *
 * Schedule the driver notification routine to run in the main loop.
 *
 */
void nmwa_dbus_schedule_driver_notification (NMWirelessApplet *applet, NetworkDevice *dev)
{
	DriverNotifyCBData	*cb_data;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (dev != NULL);

	cb_data = g_malloc0 (sizeof (DriverNotifyCBData));
	cb_data->applet = applet;
	cb_data->dev = dev;

	g_idle_add (nmwa_driver_notify, (gpointer)cb_data);
}


/*
 * nmwa_dbus_check_drivers
 *
 * If a device got added, we notify the user if the device's driver
 * has any problems (no carrier detect, no wireless scanning, etc).
 *
 */
void nmwa_dbus_check_drivers (NMWirelessApplet *applet)
{
	GSList	*elt;

	g_return_if_fail (applet != NULL);

	/* For every device that's in the dbus data model but not in
	 * the gui data model, signal the user.
	 */
	for (elt = applet->dbus_device_list; elt; elt = g_slist_next (elt))
	{
		NetworkDevice	*dbus_dev = (NetworkDevice *)(elt->data);
		GSList		*elt2;
		gboolean		 found = FALSE;
		
		for (elt2 = applet->gui_device_list; elt2; elt2 = g_slist_next (elt2))
		{
			NetworkDevice	*gui_dev = (NetworkDevice *)(elt2->data);

			if (    !nm_null_safe_strcmp (dbus_dev->nm_device, gui_dev->nm_device)
				&& !nm_null_safe_strcmp (dbus_dev->addr, gui_dev->addr)
				&& !nm_null_safe_strcmp (dbus_dev->udi, gui_dev->udi))
			{
				found = TRUE;
				break;
			}
		}

		if (    !found
			&& (    (dbus_dev->driver_support_level == NM_DRIVER_NO_CARRIER_DETECT)
				|| (dbus_dev->driver_support_level == NM_DRIVER_NO_WIRELESS_SCAN)))
		{
			network_device_ref (dbus_dev);
			nmwa_dbus_schedule_driver_notification (applet, dbus_dev);
		}
	}
}


/*
 * sort_devices_function
 *
 * Sort the devices for display...  Wired devices at the top.
 *
 */
static int
sort_devices_function (gconstpointer a, gconstpointer b)
{
	NetworkDevice *dev_a = (NetworkDevice *) a;
	NetworkDevice *dev_b = (NetworkDevice *) b;
	char *name_a;
	char *name_b;

	if (dev_a->hal_name)
		name_a = dev_a->hal_name;
	else if (dev_a->nm_name)
		name_a = dev_a->nm_name;
	else
		name_a = "";

	if (dev_b->hal_name)
		name_b = dev_b->hal_name;
	else if (dev_b->nm_name)
		name_b = dev_b->nm_name;
	else
		name_b = "";

	if (dev_a->type == dev_b->type)
	{
		return strcmp (name_a, name_b);
	}
	if (dev_a->type == DEVICE_TYPE_WIRED_ETHERNET)
		return -1;
	if (dev_b->type == DEVICE_TYPE_WIRED_ETHERNET)
		return 1;
	if (dev_a->type == DEVICE_TYPE_WIRELESS_ETHERNET)
		return -1;
	if (dev_b->type == DEVICE_TYPE_WIRELESS_ETHERNET)
		return 1;

	/* Unknown device types.  Sort by name only at this point. */
	return strcmp (name_a, name_b);
}


/*
 * nmwa_dbus_update_devices
 *
 * Get a device list from NetworkManager
 *
 */
static void nmwa_dbus_update_devices (NMWirelessApplet *applet)
{
	char			**devices = NULL;
	int			  num_items = 0;
	int			  i;
	gboolean		  adhoc = FALSE;
	char			 *nm_act_dev;
	char			 *nm_status;

	g_return_if_fail (applet->data_mutex != NULL);

	if (!(nm_status = nmwa_dbus_get_nm_status (applet, APPLET_STATE_NO_CONNECTION)))
		return;

	switch (nmwa_dbus_call_nm_method (applet->connection, NM_DBUS_PATH, "getDevices", DBUS_TYPE_STRING_ARRAY, (void **)(&devices), &num_items))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		default:
			break;
	}

	if (!devices)
	{
		dbus_free (nm_status);
		return;
	}

	nmwa_free_dbus_data_model (applet);
	applet->dbus_nm_status = nm_status;

	nm_act_dev = nmwa_dbus_get_active_device (applet, APPLET_STATE_IGNORE);

	for (i = 0; i < num_items; i++)
	{
		char	*name = nmwa_dbus_get_object_name (applet, devices [i]);

		if (name && strlen (name))
		{
			NetworkDevice	*dev;

			if ((dev = network_device_new ()))
			{
				dev->nm_device = g_strdup (devices[i]);
				dev->type = nmwa_dbus_get_device_type (applet, devices[i], APPLET_STATE_NO_CONNECTION);
				dev->driver_support_level = nmwa_dbus_get_device_driver_support_level (applet, devices[i]);
				dev->addr = nmwa_dbus_get_hw_addr (applet, devices[i]);
				dev->link = nmwa_dbus_get_device_link_active (applet, devices[i]);
				dev->nm_name = g_strdup (name);
				dev->udi = nmwa_dbus_get_device_udi (applet, devices[i]);
				dev->hal_name = nmwa_dbus_get_hal_device_info (applet->connection, dev->udi);

				/* Ensure valid device information */
				if (!dev->nm_device || !dev->nm_name || !dev->udi || (dev->type == -1))
					network_device_unref (dev);
				else
				{
					applet->dbus_device_list = g_slist_append (applet->dbus_device_list, dev);
					if (nm_act_dev && (strcmp (nm_act_dev, devices[i]) == 0))
					{
						/* ref the current active device */
						network_device_ref (dev);
						applet->dbus_active_device = dev;
						if (dev->type == DEVICE_TYPE_WIRELESS_ETHERNET)
							adhoc = (nmwa_dbus_get_object_mode (applet, nm_act_dev) == NETWORK_MODE_ADHOC);
					}
					nmwa_dbus_device_update_all_networks (dev, applet);
				}
			}
		}
		dbus_free (name);
	}
	g_free (nm_act_dev);
	g_strfreev (devices);

	/* Sort the devices for display */
	applet->dbus_device_list = g_slist_sort (applet->dbus_device_list, sort_devices_function);

	/* Notify user of issues with certain cards/drivers */
	nmwa_dbus_check_drivers (applet);

	/* Now copy the data over to the GUI side */
	g_mutex_lock (applet->data_mutex);

	nmwa_copy_data_model (applet);
	applet->is_adhoc = adhoc;
	applet->wireless_enabled = nmwa_dbus_get_wireless_enabled (applet);

	g_mutex_unlock (applet->data_mutex);
}


/*
 * nmwa_dbus_filter
 *
 */
static DBusHandlerResult nmwa_dbus_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMWirelessApplet	*applet = (NMWirelessApplet *)user_data;
	gboolean			 handled = TRUE;
	DBusError			 error;

	g_return_val_if_fail (applet != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	dbus_error_init (&error);

#if (DBUS_VERSION_MAJOR == 0 && DBUS_VERSION_MINOR == 22)
	/* Old signal names for dbus <= 0.22 */
	if (dbus_message_is_signal (message, DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS, "ServiceCreated"))
	{
		char 	*service;

		if (    dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &service, DBUS_TYPE_INVALID)
			&& (strcmp (service, NM_DBUS_SERVICE) == 0) && (applet->applet_state == APPLET_STATE_NO_NM))
			applet->applet_state = APPLET_STATE_NO_CONNECTION;
	}
	else if (dbus_message_is_signal (message, DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS, "ServiceDeleted"))
	{
		char 	*service;

		if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &service, DBUS_TYPE_INVALID))
		{
			if (strcmp (service, NM_DBUS_SERVICE) == 0)
				applet->applet_state = APPLET_STATE_NO_NM;
			else if (strcmp (service, NMI_DBUS_SERVICE) == 0)
				gtk_main_quit ();	/* Just die if NetworkManagerInfo dies */
		}
	}
#elif (DBUS_VERSION_MAJOR == 0 && DBUS_VERSION_MINOR == 23)
	if (dbus_message_is_signal (message, DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS, "ServiceOwnerChanged"))
	{
		/* New signal for dbus 0.23... */
		char 	*service;
		char		*old_owner;
		char		*new_owner;

		if (    dbus_message_get_args (message, &error,
									DBUS_TYPE_STRING, &service,
									DBUS_TYPE_STRING, &old_owner,
									DBUS_TYPE_STRING, &new_owner,
									DBUS_TYPE_INVALID))
		{
			gboolean old_owner_good = (old_owner && (strlen (old_owner) > 0));
			gboolean new_owner_good = (new_owner && (strlen (new_owner) > 0));

			if (    (strcmp (service, NM_DBUS_SERVICE) == 0)
				&& (!old_owner_good && new_owner_good)	/* Equivalent to old ServiceCreated signal */
				&& (applet->applet_state == APPLET_STATE_NO_NM))
			{
				/* NetworkManager started up */
				applet->applet_state = APPLET_STATE_NO_CONNECTION;
			}
			else if (old_owner_good && !new_owner_good)	/* Equivalent to old ServiceDeleted signal */
			{
				if (strcmp (service, NM_DBUS_SERVICE) == 0)
					applet->applet_state = APPLET_STATE_NO_NM;
				else if (strcmp (service, NMI_DBUS_SERVICE) == 0)
					gtk_main_quit ();	/* Die if NetworkManagerInfo dies */
			}
		}
	}
#else
#error "Unrecognized version of DBUS."
#endif
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "WirelessNetworkUpdate"))
		nmwa_dbus_device_update_one_network (applet, message);
	else if (    dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNowActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNoLongerActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceActivating")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceStatusChanged")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DevicesChanged"))
	{
		nmwa_dbus_update_devices (applet);
	}
	else
		handled = FALSE;

	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nmwa_dbus_nm_is_running
 *
 * Ask dbus whether or not NetworkManager is running
 *
 */
static gboolean nmwa_dbus_nm_is_running (DBusConnection *connection)
{
	DBusError		error;
	gboolean		exists;

	g_return_val_if_fail (connection != NULL, FALSE);

	dbus_error_init (&error);
	exists = dbus_bus_service_exists (connection, NM_DBUS_SERVICE, &error);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	return (exists);
}


/*
 * nmwa_dbus_init
 *
 * Initialize a connection to NetworkManager if we can get one
 *
 */
static DBusConnection * nmwa_dbus_init (NMWirelessApplet *applet, GMainContext *context)
{
	DBusConnection	*connection = NULL;
	DBusError		 error;

	g_return_val_if_fail (applet != NULL, NULL);

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);

	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_error_free (&error);
		return (NULL);
	}

	if (!dbus_connection_add_filter (connection, nmwa_dbus_filter, applet, NULL))
		return (NULL);

	dbus_connection_set_exit_on_disconnect (connection, FALSE);
	dbus_connection_setup_with_g_main (connection, context);

	dbus_bus_add_match(connection,
				"type='signal',"
				"interface='" DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS "',"
				"sender='" DBUS_SERVICE_ORG_FREEDESKTOP_DBUS "'",
				&error);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	dbus_bus_add_match(connection,
				"type='signal',"
				"interface='" NM_DBUS_INTERFACE "',"
				"path='" NM_DBUS_PATH "',"
				"sender='" NM_DBUS_SERVICE "'",
				&error);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	return (connection);
}


/*
 * nmwa_dbus_timeout_worker
 *
 * Timer to update our state from NetworkManager
 *
 */
static gboolean nmwa_dbus_timeout_worker (gpointer user_data)
{
	NMWirelessApplet	*applet = (NMWirelessApplet *)user_data;

	g_return_val_if_fail (applet != NULL, TRUE);

	if (!applet->connection)
	{
		/* After our first connection, update the state.  After that, we listen
		 * for signals from NetworkManager to trigger state updates.
		 */
		if ((applet->connection = nmwa_dbus_init (applet, applet->thread_context)))
		{
			applet->applet_state = APPLET_STATE_NO_CONNECTION;
			nmwa_dbus_update_devices (applet);
		}
	}

	return (TRUE);
}


/*
 * nmwa_dbus_worker
 *
 * Thread worker function that periodically grabs the NetworkManager state
 * and updates our local applet state to reflect that.
 *
 */
gpointer nmwa_dbus_worker (gpointer user_data)
{
	NMWirelessApplet	*applet = (NMWirelessApplet *)user_data;
	guint			 timeout_id;
	GSource			*timeout_source;
	guint			 strength_id;
	GSource			*strength_source;

	g_return_val_if_fail (applet != NULL, NULL);

	dbus_g_thread_init ();

	if (!(applet->thread_context = g_main_context_new ()))
		return (NULL);
	if (!(applet->thread_loop = g_main_loop_new (applet->thread_context, FALSE)))
		return (NULL);

	applet->connection = nmwa_dbus_init (applet, applet->thread_context);

	timeout_source = g_timeout_source_new (2000);
	g_source_set_callback (timeout_source, nmwa_dbus_timeout_worker, applet, NULL);
	timeout_id = g_source_attach (timeout_source, applet->thread_context);

	strength_source = g_timeout_source_new (2000);
	g_source_set_callback (strength_source, nmwa_dbus_update_active_device_strength, applet, NULL);
	strength_id = g_source_attach (strength_source, applet->thread_context);

	if (applet->connection && nmwa_dbus_nm_is_running (applet->connection))
	{
		applet->applet_state = APPLET_STATE_NO_CONNECTION;
		nmwa_dbus_update_devices (applet);
	}
	else
		applet->applet_state = APPLET_STATE_NO_NM;

	g_main_loop_run (applet->thread_loop);

	g_source_destroy (timeout_source);
	g_source_destroy (strength_source);

	return NULL;
}
