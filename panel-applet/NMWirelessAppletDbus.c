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
int nmwa_dbus_get_string (DBusConnection *connection, const char *path, const char *method, char **string)
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
int nmwa_dbus_get_int (DBusConnection *connection, const char *path, const char *method, gint32 *num)
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
int nmwa_dbus_get_bool (DBusConnection *connection, const char *path, const char *method, gboolean *val)
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

		return (ret);
	}

	if (reply == NULL)
	{
		fprintf( stderr, "nmwa_dbus_get_bool(): dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return (RETURN_FAILURE);
	}

	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_BOOLEAN, val, DBUS_TYPE_INVALID))
	{
		dbus_message_unref (reply);
		return (RETURN_FAILURE);
	}

	dbus_message_unref (reply);
	return (RETURN_SUCCESS);
}


/*
 * nmwa_dbus_get_double
 *
 */
double nmwa_dbus_get_double (DBusConnection *connection, const char *path, const char *method)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;
	double		 num;

	g_return_val_if_fail (connection != NULL, 0);
	g_return_val_if_fail (path != NULL, 0);
	g_return_val_if_fail (method != NULL, 0);

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, path, NM_DBUS_INTERFACE, method)))
	{
		fprintf (stderr, "nmwa_dbus_get_double(): Couldn't allocate the dbus message\n");
		return (0);
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "nmwa_dbus_get_double(): %s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return (0);
	}

	if (reply == NULL)
	{
		fprintf( stderr, "nmwa_dbus_get_double(): dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return (0);
	}

	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_DOUBLE, &num, DBUS_TYPE_INVALID))
		num = 0;

	dbus_message_unref (reply);
	dbus_message_unref (message);

	return (num);
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
int nmwa_dbus_get_string_array (DBusConnection *connection, const char *path, const char *method,
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
char * nmwa_dbus_get_active_device (NMWirelessApplet *applet, AppletState failure_state)
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
char * nmwa_dbus_get_active_network (NMWirelessApplet *applet, char *dev_path, AppletState failure_state)
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
int nmwa_dbus_get_device_type (NMWirelessApplet *applet, char *path, AppletState failure_state)
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
 * nmwa_dbus_get_network_quality
 *
 * Returns the quality of a given wireless network
 *
 */
guint8 nmwa_dbus_get_network_quality (NMWirelessApplet *applet, char *path)
{
	int	qual = 0;

	switch (nmwa_dbus_get_int (applet->connection, path, "getQuality", &qual))
	{
		case (RETURN_NO_NM):
			applet->applet_state = APPLET_STATE_NO_NM;
			break;

		default:
			break;			
	}

	return (qual);
}


/*
 * nmwa_dbus_get_nm_status
 *
 * Returns NetworkManager's status
 *
 */
char * nmwa_dbus_get_nm_status (NMWirelessApplet *applet, AppletState failure_state)
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
char * nmwa_dbus_get_network_name (NMWirelessApplet *applet, char *net_path)
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
char * nmwa_dbus_get_device_name (NMWirelessApplet *applet, char *dev_path)
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
char * nmwa_dbus_get_device_udi (NMWirelessApplet *applet, char *dev_path)
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
gboolean nmwa_dbus_get_network_encrypted (NMWirelessApplet *applet, char *net_path)
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
char **nmwa_dbus_get_device_networks (NMWirelessApplet *applet, char *path, int *num_items, AppletState failure_state)
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
char *nmwa_dbus_get_hal_device_string_property (DBusConnection *connection, const char *udi, const char *property_name)
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
		return (NULL);
	}

	if (reply == NULL)
	{
		fprintf( stderr, "nmwa_dbus_get_hal_device_string_property(): dbus reply message was NULL\n" );
		return (NULL);
	}

	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_STRING, &property, DBUS_TYPE_INVALID))
		property = NULL;

	dbus_message_unref (reply);	
	return (property);
}


/*
 * nmwa_dbus_get_hal_device_info
 *
 * Grab the info.product tag from hal for a specific UDI
 *
 */
char *nmwa_dbus_get_hal_device_info (DBusConnection *connection, const char *udi)
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
		return (NULL);
	}

	if (reply == NULL)
	{
		fprintf( stderr, "nmwa_dbus_get_hal_device_info(): dbus reply message was NULL\n" );
		return (NULL);
	}

	dbus_error_init (&error);
	if (dbus_message_get_args (reply, &error, DBUS_TYPE_BOOLEAN, &exists, DBUS_TYPE_INVALID))
		info = nmwa_dbus_get_hal_device_string_property (connection, udi, "info.product");

	dbus_message_unref (reply);
	
	return (info);
}


/*
 * nmwa_dbus_set_network
 *
 * Tell NetworkManager to use a specific network that the user picked.
 *
 */
void nmwa_dbus_set_network (DBusConnection *connection, char *network)
{
	DBusMessage	*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (network != NULL);

	message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "setNetwork");
	if (message)
	{
		dbus_message_append_args (message, DBUS_TYPE_STRING, network, DBUS_TYPE_INVALID);
		dbus_connection_send (connection, message, NULL);
	}
	else
		fprintf (stderr, "nm_dbus_set_network(): Couldn't allocate the dbus message\n");
}


/*
 * nmwa_dbus_set_device
 *
 * Tell NetworkManager to use a specific network device that the user picked.
 *
 */
void nmwa_dbus_set_device (DBusConnection *connection, char *device)
{
	DBusMessage	*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (device != NULL);

	message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "setActiveDevice");
	if (message)
	{
		dbus_message_append_args (message, DBUS_TYPE_STRING, device, DBUS_TYPE_INVALID);
		dbus_connection_send (connection, message, NULL);
	}
	else
		fprintf (stderr, "nm_dbus_set_device(): Couldn't allocate the dbus message\n");
}


/*
 * wireless_network_free
 *
 * Frees the representation of a wireless network
 *
 */
static void wireless_network_free (void *element, void *user_data)
{
	WirelessNetwork	*net = (WirelessNetwork *)(element);

	if (net)	g_free (net->essid);
	g_free (net);
}


/*
 * nmwa_dbus_update_wireless_network_list
 *
 * Query NetworkManager for the wireless networks the active device
 * knows about, if the active device is wireless.
 *
 */
void nmwa_dbus_update_wireless_network_list (NMWirelessApplet *applet)
{
	char 	 *active_device = NULL;
	char		 *active_network = NULL;
	int		  dev_type;
	char		**networks = NULL;
	int		  num_items = 0;
	int		  i;

	/* Grab the lock for the network list. */
	g_mutex_lock (applet->data_mutex);

	/* Clear out existing entries in the list */
	if (applet->networks)
	{
		g_slist_foreach (applet->networks, wireless_network_free, NULL);
		g_slist_free (applet->networks);
		applet->networks = NULL;
	}
	g_mutex_unlock (applet->data_mutex);

	if (    (applet->applet_state != APPLET_STATE_WIRELESS)
		&& (applet->applet_state != APPLET_STATE_WIRELESS_CONNECTING))
		return;

	if (!(active_device = nmwa_dbus_get_active_device (applet, APPLET_STATE_NO_CONNECTION)))
		goto out;

	if (    ((dev_type = nmwa_dbus_get_device_type (applet, active_device, APPLET_STATE_NO_CONNECTION)) == -1)
		|| (dev_type != DEVICE_TYPE_WIRELESS_ETHERNET))
		goto out;

	active_network = nmwa_dbus_get_active_network (applet, active_device, APPLET_STATE_IGNORE);
	if (applet->applet_state == APPLET_STATE_NO_NM)
		goto out;	/* Don't proceed if NetworkManager died during the call to get the active network */

	/* Get each of the networks in turn and add them to the menu */
	networks = nmwa_dbus_get_device_networks (applet, active_device, &num_items, APPLET_STATE_NO_CONNECTION);
	if ((applet->applet_state != APPLET_STATE_WIRELESS) && (applet->applet_state != APPLET_STATE_WIRELESS_CONNECTING))
		goto out;

	if (!networks)
		goto out;

	g_mutex_lock (applet->data_mutex);

	for (i = 0; i < num_items; i++)
	{
		char		*name = NULL;

		if (!(name = nmwa_dbus_get_network_name (applet, networks[i])))
			break;

		if (name && strlen (name))
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
						
			net = g_new0 (WirelessNetwork, 1);
			net->essid = g_strdup (name);
			net->active = active_network ? (strcmp (networks[i], active_network) == 0) : FALSE;
			net->encrypted = nmwa_dbus_get_network_encrypted (applet, networks[i]);
			net->quality = nmwa_dbus_get_network_quality (applet, networks[i]);

			fprintf( stderr, "Adding '%s' active (%d), enc (%d)\n", name, net->active, net->encrypted);
			applet->networks = g_slist_append (applet->networks, net);
		}
		dbus_free (name);
	}
	g_mutex_unlock (applet->data_mutex);

out:
	dbus_free (active_device);
	dbus_free (active_network);	
	dbus_free_string_array (networks);
}


/*
 * nmwa_dbus_update_network_state
 *
 * Update our state based on what NetworkManager's network state is
 *
 */
void nmwa_dbus_update_network_state (NMWirelessApplet *applet)
{
	char		*active_device = NULL;
	char		*nm_status = NULL;
	int		 dev_type = -1;

	g_return_if_fail (applet != NULL);

	/* Grab NetworkManager's status */
	if (!(nm_status = nmwa_dbus_get_nm_status (applet, APPLET_STATE_NO_CONNECTION)))
		return;

	if (strcmp (nm_status, "disconnected") == 0)
	{
		applet->applet_state = APPLET_STATE_NO_CONNECTION;
		goto out;
	}
	
	if (!(active_device = nmwa_dbus_get_active_device (applet, APPLET_STATE_NO_CONNECTION)))
		goto out;

	if ((dev_type = nmwa_dbus_get_device_type (applet, active_device, APPLET_STATE_NO_CONNECTION)) == -1)
		goto out;

	/* If the device is not 802.x, we don't show state for it (yet) */
	if ((dev_type != DEVICE_TYPE_WIRED_ETHERNET) && (dev_type != DEVICE_TYPE_WIRELESS_ETHERNET))
	{
		applet->applet_state = APPLET_STATE_NO_CONNECTION;
		goto out;
	}
	else if (dev_type == DEVICE_TYPE_WIRED_ETHERNET)
	{
		if (strcmp (nm_status, "connecting") == 0)
			applet->applet_state = APPLET_STATE_WIRED_CONNECTING;
		else if (strcmp (nm_status, "connected") == 0)
			applet->applet_state = APPLET_STATE_WIRED;
	}
	else if (dev_type == DEVICE_TYPE_WIRELESS_ETHERNET)
	{
		if (strcmp (nm_status, "connecting") == 0)
			applet->applet_state = APPLET_STATE_WIRELESS_CONNECTING;
		else if (strcmp (nm_status, "connected") == 0)
			applet->applet_state = APPLET_STATE_WIRELESS;
	}

out:
	dbus_free (nm_status);
	dbus_free (active_device);
}


/*
 * network_device_free
 *
 * Frees the representation of a network device
 *
 */
static void network_device_free (void *element, void *user_data)
{
	NetworkDevice	*dev = (NetworkDevice *)(element);

	if (dev)
	{
		g_free (dev->nm_device);
		g_free (dev->nm_name);
		dbus_free (dev->udi);
		dbus_free (dev->hal_name);
	}
	g_free (dev);
}


/*
 * nmwa_dbus_update_active_device
 *
 * Get the active device from NetworkManager
 *
 */
void nmwa_dbus_update_active_device (NMWirelessApplet *applet)
{
	g_return_if_fail (applet != NULL);

	g_mutex_lock (applet->data_mutex);
	if (applet->active_device)
		dbus_free (applet->active_device);
	applet->active_device = nmwa_dbus_get_active_device (applet, APPLET_STATE_IGNORE);
	g_mutex_unlock (applet->data_mutex);
}


/*
 * nmwa_dbus_update_devices
 *
 * Get a device list from NetworkManager
 *
 */
void nmwa_dbus_update_devices (NMWirelessApplet *applet)
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
	g_slist_foreach (applet->devices, network_device_free, NULL);
	g_slist_free (applet->devices);
	applet->devices = NULL;

	for (i = 0; i < num_items; i++)
	{
		char	*name = nmwa_dbus_get_device_name (applet, devices [i]);

		if (name && strlen (name))
		{
			NetworkDevice	*dev;

			if ((dev = g_new0 (NetworkDevice, 1)))
			{
				dev->nm_device = g_strdup (devices[i]);
				dev->type = nmwa_dbus_get_device_type (applet, devices[i], APPLET_STATE_NO_CONNECTION);
				dev->nm_name = g_strdup (name);
				dev->udi = nmwa_dbus_get_device_udi (applet, devices[i]);
				dev->hal_name = nmwa_dbus_get_hal_device_info (applet->connection, dev->udi);

				/* Ensure valid device information */
				if (!dev->nm_device || !dev->nm_name || !dev->udi || (dev->type == -1))
					network_device_free (dev, NULL);
				else
				{
					applet->devices = g_slist_append (applet->devices, dev);
					fprintf( stderr, "Got device '%s', udi '%s'\n", dev->nm_name, dev->udi);
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
	}
	else if (dbus_message_is_signal (message, DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS, "ServiceDeleted"))
	{
		char 	*service;
		DBusError	 error;

		dbus_error_init (&error);
		if (    dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &service, DBUS_TYPE_INVALID)
			&& (strcmp (service, NM_DBUS_SERVICE) == 0))
			applet->applet_state = APPLET_STATE_NO_NM;
	}
	else if (    dbus_message_is_signal (message, NM_DBUS_INTERFACE, "WirelessNetworkAppeared")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "WirelessNetworkDisappeared"))
	{
		nmwa_dbus_update_wireless_network_list (applet);
	}
	else if (    dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNowActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNoLongerActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceActivating"))
	{
		nmwa_dbus_update_network_state (applet);
		nmwa_dbus_update_active_device (applet);
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
gboolean nmwa_dbus_nm_is_running (DBusConnection *connection)
{
	DBusError		error;
	gboolean		exists;

	g_return_val_if_fail (connection != NULL, FALSE);

	dbus_error_init (&error);
	exists = dbus_bus_service_exists (connection, NM_DBUS_SERVICE, &error);
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

	dbus_bus_add_match(connection,
				"type='signal',"
				"interface='" NM_DBUS_INTERFACE "',"
				"path='" NM_DBUS_PATH "',"
				"sender='" NM_DBUS_SERVICE "'",
				&error);

fprintf( stderr, "returning good DBUS connection\n");
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
			nmwa_dbus_update_network_state (applet);
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
		nmwa_dbus_update_network_state (applet);
		if ((applet->applet_state == APPLET_STATE_WIRELESS) || (applet->applet_state == APPLET_STATE_WIRELESS_CONNECTING))
			nmwa_dbus_update_wireless_network_list (applet);
		nmwa_dbus_update_devices (applet);
		nmwa_dbus_update_active_device (applet);
	}
	else
		applet->applet_state = APPLET_STATE_NO_NM;

	g_main_loop_run (thread_loop);

	g_source_destroy (timeout_source);

	return NULL;
}
