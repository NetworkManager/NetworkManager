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
	DBusMessageIter iter;

	g_return_val_if_fail (con != NULL, RETURN_FAILURE);
	g_return_val_if_fail (path != NULL, RETURN_FAILURE);
	g_return_val_if_fail (method != NULL, RETURN_FAILURE);
	g_return_val_if_fail (((arg_type == DBUS_TYPE_STRING) || (arg_type == DBUS_TYPE_INT32) || (arg_type == DBUS_TYPE_BOOLEAN) || (arg_type == DBUS_TYPE_STRING_ARRAY)), RETURN_FAILURE);
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
			dbus_message_iter_init (reply, &iter);
			ret = dbus_message_iter_get_string_array (&iter, &dbus_string_array, &num_items);
			break;
		case DBUS_TYPE_INT32:
			ret = dbus_message_get_args (reply, &error, DBUS_TYPE_INT32, &dbus_int, DBUS_TYPE_INVALID);
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
	dbus_message_unref (reply);

	switch (arg_type)
	{
		case DBUS_TYPE_STRING:
			*((char **)(arg)) = dbus_string;
			break;
		case DBUS_TYPE_STRING_ARRAY:
			*((char ***)(arg)) = dbus_string_array;
			*item_count = num_items;
			break;
		case DBUS_TYPE_INT32:
			*((int *)(arg)) = dbus_int;
			break;
		case DBUS_TYPE_BOOLEAN:
			*((gboolean *)(arg)) = dbus_bool;
			break;
		default:
			g_assert_not_reached ();
			break;
	}

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
static char * nmwa_dbus_get_object_name (NMWirelessApplet *applet, char *path)
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

	switch (nmwa_dbus_call_nm_method (applet->connection, path, "getMode", DBUS_TYPE_INT32, (void **)(&mode), NULL))
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
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_STRING, &property, DBUS_TYPE_INVALID))
	{
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		property = NULL;
	}

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
		dbus_free (dev->udi);
		dbus_free (dev->hal_name);
		g_free (dev);
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

	if ((dev = g_new0 (NetworkDevice, 1)))
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

	if ((dev = g_new0 (NetworkDevice, 1)))
	{
		GSList	*elem;

		network_device_ref (dev);
		dev->nm_device = g_strdup (src->nm_device);
		dev->type = src->type;
		dev->nm_name = g_strdup (src->nm_name);
		dev->hal_name = g_strdup (src->hal_name);
		dev->udi = g_strdup (src->udi);
		dev->strength = src->strength;

		elem = src->networks;
		while (elem)
		{
			WirelessNetwork *net = (WirelessNetwork *)elem->data;
			if (net)
			{
				WirelessNetwork *copy = wireless_network_copy (net);
				dev->networks = g_slist_append (dev->networks, copy);
			}

			elem = g_slist_next (elem);
		}
	}

	return (dev);
}


/*
 * nmwa_dbus_update_device_wireless_networks
 *
 * Query NetworkManager for the wireless networks a particular device
 * knows about, if the active device is wireless.
 *
 * NOTE: caller must lock device list if necessary
 *
 */
static void nmwa_dbus_update_device_wireless_networks (NetworkDevice *dev, gboolean active_dev, NMWirelessApplet *applet)
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

	if (active_dev)
		active_network = nmwa_dbus_get_active_network (applet, dev->nm_device, APPLET_STATE_IGNORE);

	if (applet->applet_state == APPLET_STATE_NO_NM)
		goto out;	/* Don't proceed if NetworkManager died during the call to get the active network */

	/* Get each of the networks in turn and add them to the menu */
	networks = nmwa_dbus_get_device_networks (applet, dev->nm_device, &num_items, APPLET_STATE_NO_CONNECTION);
	if (!networks || (applet->applet_state == APPLET_STATE_NO_NM))
		goto out;

	for (i = 0; i < num_items; i++)
	{
		char		*name = NULL;

		if (!(name = nmwa_dbus_get_object_name (applet, networks[i])))
			break;

		if (strlen (name))
		{
			gboolean	 		 found = FALSE;
			int		 		 j;
			WirelessNetwork	*net = NULL;

			/* Only show one menu item per network.  NetworkManager really passes back a list
			 * of access points, and there may be more than one that have the same ESSID.  Filter
			 * them here.
			 */
			for (j = 0; j < i; j++)
				if ((found = (networks[j] && (strcmp (networks[i], networks[j]) == 0))))
					break;
			if (found)
				continue;
						
			net = wireless_network_new ();
			/* FIXME: what if net == NULL? */			
			net->nm_name = g_strdup (networks[i]);
			net->essid = g_strdup (name);
			net->active = active_network ? (strcmp (net->nm_name, active_network) == 0) : FALSE;
			net->encrypted = nmwa_dbus_get_network_encrypted (applet, net->nm_name);
			net->strength = nmwa_dbus_get_object_strength (applet, net->nm_name);

			dev->networks = g_slist_append (dev->networks, net);
		}
		dbus_free (name);
	}

out:
	dbus_free (active_network);	
	dbus_free_string_array (networks);
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
	if (applet->dbus_active_device && (applet->active_device->type == DEVICE_TYPE_WIRELESS_ETHERNET))
		applet->dbus_active_device->strength = nmwa_dbus_get_object_strength (applet, applet->dbus_active_device->nm_device);

	return (TRUE);
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
	char			 *nm_act_dev = NULL;
	GSList		 *device_list = NULL;
	NetworkDevice	 *active_device = NULL;
	char			 *nm_status = NULL;
	gboolean		  adhoc = FALSE;

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
		return;

	if (applet->dbus_active_device)
		network_device_unref (applet->dbus_active_device);
	applet->dbus_active_device = NULL;

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
				dev->nm_name = g_strdup (name);
				dev->udi = nmwa_dbus_get_device_udi (applet, devices[i]);
				dev->hal_name = nmwa_dbus_get_hal_device_info (applet->connection, dev->udi);

				/* Ensure valid device information */
				if (!dev->nm_device || !dev->nm_name || !dev->udi || (dev->type == -1))
					network_device_unref (dev);
				else
				{
					device_list = g_slist_append (device_list, dev);
					if (nm_act_dev && !strcmp (nm_act_dev, devices[i]))
					{
						active_device = dev;
						network_device_ref (dev);
						applet->dbus_active_device = dev;
						network_device_ref (dev);
						if (dev->type == DEVICE_TYPE_WIRELESS_ETHERNET)
						{
							adhoc = (nmwa_dbus_get_object_mode (applet, nm_act_dev) == NETWORK_MODE_ADHOC);
							nmwa_dbus_update_device_wireless_networks (dev, TRUE, applet);
						}
					}
					else
						nmwa_dbus_update_device_wireless_networks (dev, FALSE, applet);
				}
			}
		}
		dbus_free (name);
	}
	dbus_free (nm_act_dev);
	dbus_free_string_array (devices);

	/* Now move the data over to the GUI side */
	g_mutex_lock (applet->data_mutex);
	if (applet->device_list)
	{
		g_slist_foreach (applet->device_list, (GFunc) network_device_unref, NULL);
		g_slist_free (applet->device_list);
	}
	if (applet->active_device)
		network_device_unref (applet->active_device);
	if (applet->nm_status)
		g_free (applet->nm_status);

	applet->device_list = device_list;
	applet->active_device = active_device;
	applet->nm_status = nm_status;
	applet->is_adhoc = adhoc;

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

	g_return_val_if_fail (applet != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_is_signal (message, DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS, "ServiceCreated"))
	{
		char 	*service;
		DBusError	 error;

		dbus_error_init (&error);
		if (    dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &service, DBUS_TYPE_INVALID)
			&& (strcmp (service, NM_DBUS_SERVICE) == 0) && (applet->applet_state == APPLET_STATE_NO_NM))
			applet->applet_state = APPLET_STATE_NO_CONNECTION;
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
	}
	else if (dbus_message_is_signal (message, DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS, "ServiceDeleted"))
	{
		char 	*service;
		DBusError	 error;

		dbus_error_init (&error);
		if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &service, DBUS_TYPE_INVALID))
		{
			if (strcmp (service, NM_DBUS_SERVICE) == 0)
				applet->applet_state = APPLET_STATE_NO_NM;
			else if (strcmp (service, NMI_DBUS_SERVICE) == 0)
				gtk_main_quit ();	/* Just die if NetworkManagerInfo dies */
		}
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
	}
	else if (    dbus_message_is_signal (message, NM_DBUS_INTERFACE, "WirelessNetworkAppeared")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "WirelessNetworkDisappeared"))
	{
		nmwa_dbus_update_devices (applet);
	}
	else if (    dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNowActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNoLongerActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceActivating"))
	{
		nmwa_dbus_update_devices (applet);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DevicesChanged"))
	{
		nmwa_dbus_update_devices (applet);
	}
	else
		handled = FALSE;

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
	GMainLoop			*thread_loop;
	guint			 timeout_id;
	GSource			*timeout_source;
	guint			 strength_id;
	GSource			*strength_source;

	g_return_val_if_fail (applet != NULL, NULL);

	if (!(applet->thread_context = g_main_context_new ()))
		return (NULL);
	if (!(thread_loop = g_main_loop_new (applet->thread_context, FALSE)))
		return (NULL);

	applet->connection = nmwa_dbus_init (applet, applet->thread_context);

	timeout_source = g_timeout_source_new (2000);
	g_source_set_callback (timeout_source, nmwa_dbus_timeout_worker, applet, NULL);
	timeout_id = g_source_attach (timeout_source, applet->thread_context);

	strength_source = g_timeout_source_new (1000);
	g_source_set_callback (strength_source, nmwa_dbus_update_active_device_strength, applet, NULL);
	strength_id = g_source_attach (strength_source, applet->thread_context);

	if (applet->connection && nmwa_dbus_nm_is_running (applet->connection))
	{
		applet->applet_state = APPLET_STATE_NO_CONNECTION;
		nmwa_dbus_update_devices (applet);
	}
	else
		applet->applet_state = APPLET_STATE_NO_NM;

	g_main_loop_run (thread_loop);

	g_source_destroy (timeout_source);
	g_source_destroy (strength_source);

	return NULL;
}
