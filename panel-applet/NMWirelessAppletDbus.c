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

#define	NM_DBUS_SERVICE			"org.freedesktop.NetworkManager"

#define	NM_DBUS_PATH				"/org/freedesktop/NetworkManager"
#define	NM_DBUS_INTERFACE			"org.freedesktop.NetworkManager"
#define	NM_DBUS_PATH_DEVICES		"/org/freedesktop/NetworkManager/Devices"
#define	NM_DBUS_INTERFACE_DEVICES	"org.freedesktop.NetworkManager.Devices"

#define	NMI_DBUS_SERVICE			"org.freedesktop.NetworkManagerInfo"
#define	NMI_DBUS_PATH				"/org/freedesktop/NetworkManagerInfo"
#define	NMI_DBUS_INTERFACE			"org.freedesktop.NetworkManagerInfo"

#define	DBUS_NO_SERVICE_ERROR		"org.freedesktop.DBus.Error.ServiceDoesNotExist"
#define	NM_DBUS_NO_ACTIVE_NET_ERROR	"org.freedesktop.NetworkManager.NoActiveNetwork"


/*
 * nmwa_dbus_get_string
 *
 * NOTE: caller MUST free the returned string
 *
 * Returns:	RETURN_SUCCESS on success
 *			RETURN_FAILURE on failure
 *			RETURN_NO_NM if NetworkManager service no longer exists
 *
 */
static int nmwa_dbus_get_string (DBusConnection *connection, const char *path, const char *method, char **string)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;
	char			*dbus_string = NULL;

	g_return_val_if_fail (connection != NULL, RETURN_FAILURE);
	g_return_val_if_fail (path != NULL, RETURN_FAILURE);
	g_return_val_if_fail (method != NULL, RETURN_FAILURE);
	g_return_val_if_fail (string != NULL, RETURN_FAILURE);
	g_return_val_if_fail (*string == NULL, RETURN_FAILURE);

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, path, NM_DBUS_INTERFACE, method)))
	{
		fprintf (stderr, "nmwa_dbus_get_string(): Couldn't allocate the dbus message\n");
		return (RETURN_FAILURE);
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		int	ret = RETURN_FAILURE;

		fprintf (stderr, "nmwa_dbus_get_string(): %s raised:\n %s\n\n", error.name, error.message);
		if (strcmp (error.name, DBUS_NO_SERVICE_ERROR) == 0)
			ret = RETURN_NO_NM;
		else if (strcmp (error.name, NM_DBUS_NO_ACTIVE_NET_ERROR) == 0)
			ret = RETURN_SUCCESS;

		dbus_error_free (&error);
		return (ret);
	}

	if (reply == NULL)
	{
		fprintf (stderr, "nmwa_dbus_get_string(): dbus reply message was NULL\n" );
		return (RETURN_FAILURE);
	}

	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_STRING, &dbus_string, DBUS_TYPE_INVALID))
	{
		fprintf (stderr, "nmwa_dbus_get_string(): error while getting args: name='%s' message='%s'\n", error.name, error.message);
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		dbus_message_unref (reply);
		return (RETURN_FAILURE);
	}
	dbus_message_unref (reply);

	*string = dbus_string;
	return (RETURN_SUCCESS);
}


/*
 * nmwa_dbus_get_int
 *
 * Returns:	RETURN_SUCCESS on success
 *			RETURN_FAILURE on failure
 *			RETURN_NO_NM if NetworkManager service no longer exists
 *
 */
static int nmwa_dbus_get_int (DBusConnection *connection, const char *path, const char *method, gint32 *num)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;
	int			 dbus_num;

	g_return_val_if_fail (connection != NULL, RETURN_FAILURE);
	g_return_val_if_fail (path != NULL, RETURN_FAILURE);
	g_return_val_if_fail (method != NULL, RETURN_FAILURE);
	g_return_val_if_fail (num != NULL, RETURN_FAILURE);

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, path, NM_DBUS_INTERFACE, method)))
	{
		fprintf (stderr, "nmwa_dbus_get_int(): Couldn't allocate the dbus message\n");
		return (RETURN_FAILURE);
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		int	ret = RETURN_FAILURE;

		fprintf (stderr, "nmwa_dbus_get_int(): %s raised:\n %s\n\n", error.name, error.message);
		if (strcmp (error.name, DBUS_NO_SERVICE_ERROR) == 0)
			ret = RETURN_NO_NM;

		dbus_error_free (&error);
		return (ret);
	}

	if (reply == NULL)
	{
		fprintf( stderr, "nmwa_dbus_get_int(): dbus reply message was NULL\n" );
		return (RETURN_FAILURE);
	}

	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_INT32, &dbus_num, DBUS_TYPE_INVALID))
	{
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		dbus_message_unref (reply);
		return (RETURN_FAILURE);
	}	

	dbus_message_unref (reply);
	*num = dbus_num;
	return (RETURN_SUCCESS);
}


/*
 * nmwa_dbus_get_bool
 *
 * Returns:	RETURN_SUCCESS on success
 *			RETURN_FAILURE on failure
 *			RETURN_NO_NM if NetworkManager service no longer exists
 *
 */
static int nmwa_dbus_get_bool (DBusConnection *connection, const char *path, const char *method, gboolean *val)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;

	g_return_val_if_fail (connection != NULL, RETURN_FAILURE);
	g_return_val_if_fail (path != NULL, RETURN_FAILURE);
	g_return_val_if_fail (method != NULL, RETURN_FAILURE);
	g_return_val_if_fail (val != NULL, RETURN_FAILURE);

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, path, NM_DBUS_INTERFACE, method)))
	{
		fprintf (stderr, "nmwa_dbus_get_bool(): Couldn't allocate the dbus message\n");
		return (RETURN_FAILURE);
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		int	ret = RETURN_FAILURE;

		fprintf (stderr, "nmwa_dbus_get_bool(): %s raised:\n %s\n\n", error.name, error.message);
		if (strcmp (error.name, DBUS_NO_SERVICE_ERROR) == 0)
			ret = RETURN_NO_NM;

		dbus_error_free (&error);
		return (ret);
	}

	if (reply == NULL)
	{
		fprintf( stderr, "nmwa_dbus_get_bool(): dbus reply message was NULL\n" );
		return (RETURN_FAILURE);
	}

	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_BOOLEAN, val, DBUS_TYPE_INVALID))
	{
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		dbus_message_unref (reply);
		return (RETURN_FAILURE);
	}

	dbus_message_unref (reply);
	return (RETURN_SUCCESS);
}



/*
 * nmwa_dbus_get_string_array
 *
 * NOTE: caller MUST free the returned string array
 *
 * Returns:	RETURN_SUCCESS on success
 *			RETURN_FAILURE on failure
 *			RETURN_NO_NM if NetworkManager service no longer exists
 *
 */
static int nmwa_dbus_get_string_array (DBusConnection *connection, const char *path, const char *method,
							int *num_items, char ***string_array)
{
	DBusMessage 	 *message;
	DBusMessage 	 *reply;
	DBusMessageIter  iter;
	DBusError		  error;
	char			**array = NULL;
	int			  items = 0;

	g_return_val_if_fail (connection != NULL, RETURN_FAILURE);
	g_return_val_if_fail (path != NULL, RETURN_FAILURE);
	g_return_val_if_fail (method != NULL, RETURN_FAILURE);
	g_return_val_if_fail (num_items != NULL, RETURN_FAILURE);
	g_return_val_if_fail (string_array != NULL, RETURN_FAILURE);

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, path, NM_DBUS_INTERFACE, method)))
	{
		fprintf (stderr, "nmwa_dbus_get_string_array(): Couldn't allocate the dbus message\n");
		return (RETURN_FAILURE);
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		int	ret = RETURN_FAILURE;

		fprintf (stderr, "nmwa_dbus_get_string_array(): %s raised:\n %s\n\n", error.name, error.message);
		if (strcmp (error.name, DBUS_NO_SERVICE_ERROR) == 0)
			ret = RETURN_NO_NM;
		else if (strcmp (error.name, "NoNetworks") == 0)
		{
			*string_array = NULL;
			*num_items = 0;
			ret = RETURN_SUCCESS;
		}

		dbus_error_free (&error);
		return (ret);
	}

	if (reply == NULL)
	{
		fprintf( stderr, "nmwa_dbus_get_string_array(): dbus reply message was NULL\n" );
		return (RETURN_FAILURE);
	}

	/* now analyze reply */
	dbus_message_iter_init (reply, &iter);
	if (!dbus_message_iter_get_string_array (&iter, &array, &items))
	{
		dbus_message_unref (reply);
		return (RETURN_FAILURE);
	}

	dbus_message_unref (reply);
	*num_items = items;
	*string_array = array;
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

	switch (nmwa_dbus_get_string (applet->connection, NM_DBUS_PATH, "getActiveDevice", &active_device))
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

	switch (nmwa_dbus_get_string (applet->connection, dev_path, "getActiveNetwork", &network))
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

	switch (nmwa_dbus_get_int (applet->connection, path, "getType", &type))
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

	switch (nmwa_dbus_get_int (applet->connection, path, "getStrength", &strength))
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

	switch (nmwa_dbus_get_string (applet->connection, NM_DBUS_PATH, "status", &status))
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
 * nmwa_dbus_get_network_name
 *
 * Returns the name of a specified wireless network
 *
 */
static char * nmwa_dbus_get_network_name (NMWirelessApplet *applet, char *net_path)
{
	char *name = NULL;

	switch (nmwa_dbus_get_string (applet->connection, net_path, "getName", &name))
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
 * nmwa_dbus_get_device_name
 *
 * Returns the name of a specified network device
 *
 */
static char * nmwa_dbus_get_device_name (NMWirelessApplet *applet, char *dev_path)
{
	char *name = NULL;

	switch (nmwa_dbus_get_string (applet->connection, dev_path, "getName", &name))
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
 * nmwa_dbus_get_device_udi
 *
 * Returns the HAL udi of a network device
 *
 */
static char * nmwa_dbus_get_device_udi (NMWirelessApplet *applet, char *dev_path)
{
	char *udi = NULL;

	switch (nmwa_dbus_get_string (applet->connection, dev_path, "getHalUdi", &udi))
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

	switch (nmwa_dbus_get_bool (applet->connection, net_path, "getEncrypted", &enc))
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

	switch (nmwa_dbus_get_string_array (applet->connection, path, "getNetworks", &items, &array))
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
		fprintf( stderr, "nmwa_dbus_get_hal_device_string_property(): dbus reply message was NULL\n" );
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
		fprintf( stderr, "nmwa_dbus_get_hal_device_info(): dbus reply message was NULL\n" );
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
void nmwa_dbus_set_device (DBusConnection *connection, const NetworkDevice *dev, const WirelessNetwork *network)
{
	DBusMessage	*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "setActiveDevice")))
	{
		if ((dev->type == DEVICE_TYPE_WIRELESS_ETHERNET) && network && network->essid)
		{
fprintf( stderr, "Forcing device '%s' and network '%s'\n", dev->nm_device, network->essid);
			dbus_message_append_args (message, DBUS_TYPE_STRING, dev->nm_device,
									DBUS_TYPE_STRING, network->essid, DBUS_TYPE_INVALID);
		}
		else
{
fprintf( stderr, "Forcing device '%s'\n", dev->nm_device);
			dbus_message_append_args (message, DBUS_TYPE_STRING, dev->nm_device, DBUS_TYPE_INVALID);
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
static void nmwa_dbus_update_device_wireless_networks (NetworkDevice *dev, NMWirelessApplet *applet)
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

		if (!(name = nmwa_dbus_get_network_name (applet, networks[i])))
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
 * nmwa_dbus_update_network_state
 *
 * Update our state based on what NetworkManager's network state is
 *
 */
static void nmwa_dbus_update_network_state (NMWirelessApplet *applet)
{
	char		*nm_status = NULL;

	g_return_if_fail (applet != NULL);

	/* Grab NetworkManager's status */
	if (!(nm_status = nmwa_dbus_get_nm_status (applet, APPLET_STATE_NO_CONNECTION)))
		return;

	if (strcmp (nm_status, "scanning") == 0)
	{
		applet->applet_state = APPLET_STATE_WIRELESS_SCANNING;
		goto out;
	}
	
	if (strcmp (nm_status, "disconnected") == 0)
	{
		applet->applet_state = APPLET_STATE_NO_CONNECTION;
		goto out;
	}
	
	if (!applet->active_device)
	{
		applet->applet_state = APPLET_STATE_NO_CONNECTION;
		goto out;
	}

	/* If the device is not 802.x, we don't show state for it (yet) */
	if (    (applet->active_device->type != DEVICE_TYPE_WIRED_ETHERNET)
		&& (applet->active_device->type != DEVICE_TYPE_WIRELESS_ETHERNET))
	{
		applet->applet_state = APPLET_STATE_NO_CONNECTION;
		goto out;
	}
	else if (applet->active_device->type == DEVICE_TYPE_WIRED_ETHERNET)
	{
		if (strcmp (nm_status, "connecting") == 0)
			applet->applet_state = APPLET_STATE_WIRED_CONNECTING;
		else if (strcmp (nm_status, "connected") == 0)
			applet->applet_state = APPLET_STATE_WIRED;
	}
	else if (applet->active_device->type == DEVICE_TYPE_WIRELESS_ETHERNET)
	{
		if (strcmp (nm_status, "connecting") == 0)
			applet->applet_state = APPLET_STATE_WIRELESS_CONNECTING;
		else if (strcmp (nm_status, "connected") == 0)
			applet->applet_state = APPLET_STATE_WIRELESS;
	}

out:
	dbus_free (nm_status);
}


/*
 * nmwa_dbus_update_active_device
 *
 * Get the active device from NetworkManager
 *
 */
static void nmwa_dbus_update_active_device (NMWirelessApplet *applet)
{
	GSList	*element;
	char		*nm_act_dev;

	g_return_if_fail (applet != NULL);

	nm_act_dev = nmwa_dbus_get_active_device (applet, APPLET_STATE_IGNORE);

	g_mutex_lock (applet->data_mutex);
	if (applet->active_device)
		network_device_unref (applet->active_device);
	applet->active_device = NULL;

	if (nm_act_dev)
	{
		element = applet->devices;
		while (element)
		{
			NetworkDevice	*dev = (NetworkDevice *)(element->data);
			if (dev)
			{
				if (strcmp (dev->nm_device, nm_act_dev) == 0)
				{
					applet->active_device = dev;
					network_device_ref (applet->active_device);
					break;
				}
			}
			element = g_slist_next (element);
		}
	}

	g_mutex_unlock (applet->data_mutex);
	dbus_free (nm_act_dev);
}


/*
 * nmwa_dbus_update_active_device_strength
 *
 * Update the active device's current wireless network strength
 *
 */
void nmwa_dbus_update_active_device_strength (NMWirelessApplet *applet)
{
	g_return_if_fail (applet != NULL);

	g_mutex_lock (applet->data_mutex);
	if (!applet->active_device)
	{
		g_mutex_unlock (applet->data_mutex);
		return;
	}

	if (applet->active_device->type == DEVICE_TYPE_WIRELESS_ETHERNET)
		applet->active_device->strength = nmwa_dbus_get_object_strength (applet, applet->active_device->nm_device);

	g_mutex_unlock (applet->data_mutex);
}


/*
 * nmwa_dbus_update_devices
 *
 * Get a device list from NetworkManager
 *
 */
static void nmwa_dbus_update_devices (NMWirelessApplet *applet)
{
	char	**devices = NULL;
	int	  num_items = 0;
	int	  i;

	g_return_if_fail (applet->data_mutex != NULL);

	switch (nmwa_dbus_get_string_array (applet->connection, NM_DBUS_PATH, "getDevices", &num_items, &devices))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		default:
			break;
	}

	if (!devices)
		return;

	/* Clear out existing device list */
	g_mutex_lock (applet->data_mutex);
	g_slist_foreach (applet->devices, (GFunc) network_device_unref, NULL);
	g_slist_free (applet->devices);
	if (applet->active_device)
		network_device_unref (applet->active_device);
	applet->active_device = NULL;
	applet->devices = NULL;

	for (i = 0; i < num_items; i++)
	{
		char	*name = nmwa_dbus_get_device_name (applet, devices [i]);

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
					applet->devices = g_slist_append (applet->devices, dev);
					nmwa_dbus_update_device_wireless_networks (dev, applet);
				}
			}
		}
		dbus_free (name);
	}

	g_mutex_unlock (applet->data_mutex);
	dbus_free_string_array (devices);
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
		char		*nm_device = NULL;
		char		*network = NULL;
		DBusError	 error;

		dbus_error_init (&error);
		if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &nm_device,
				DBUS_TYPE_STRING, &network, DBUS_TYPE_INVALID))
		{
			NetworkDevice	*dev;

			if ((dev = nmwa_get_device_for_nm_device (applet, nm_device)))
			{
				g_mutex_lock (applet->data_mutex);
				nmwa_dbus_update_device_wireless_networks (dev, applet);
				g_mutex_unlock (applet->data_mutex);
			}
		}

		if (dbus_error_is_set (&error))
			dbus_error_free (&error);

		dbus_free (nm_device);
		dbus_free (network);
	}
	else if (    dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNowActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNoLongerActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceActivating"))
	{
		nmwa_dbus_update_devices (applet);
		nmwa_dbus_update_active_device (applet);
		nmwa_dbus_update_network_state (applet);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DevicesChanged"))
	{
		nmwa_dbus_update_devices (applet);
		nmwa_dbus_update_active_device (applet);
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
			nmwa_dbus_update_active_device (applet);
			nmwa_dbus_update_network_state (applet);
		}
	}
	else
	{
		nmwa_dbus_update_active_device_strength (applet);
		/* FIXME: update wireless networks strength in real-time */
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

	g_return_val_if_fail (applet != NULL, NULL);

	if (!(applet->thread_context = g_main_context_new ()))
		return (NULL);
	if (!(thread_loop = g_main_loop_new (applet->thread_context, FALSE)))
		return (NULL);

	applet->connection = nmwa_dbus_init (applet, applet->thread_context);

	timeout_source = g_timeout_source_new (2000);
	g_source_set_callback (timeout_source, nmwa_dbus_timeout_worker, applet, NULL);
	timeout_id = g_source_attach (timeout_source, applet->thread_context);

	if (applet->connection && nmwa_dbus_nm_is_running (applet->connection))
	{
		applet->applet_state = APPLET_STATE_NO_CONNECTION;
		nmwa_dbus_update_devices (applet);
		nmwa_dbus_update_active_device (applet);
		nmwa_dbus_update_network_state (applet);
	}
	else
		applet->applet_state = APPLET_STATE_NO_NM;

	g_main_loop_run (thread_loop);

	g_source_destroy (timeout_source);

	return NULL;
}
