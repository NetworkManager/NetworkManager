/* NetworkManager -- Network link manager
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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include "NetworkManagerDevice.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerAP.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerUtils.h"
#include "nm-dbus-dhcp.h"
#include "dhcpcd/dhcpcd.h"

static int nm_dbus_dhcp_element_type (int id)
{
	switch (dhcp_option_element_type (id))
	{
		case DHCP_OPT_INVALID:
			return DBUS_TYPE_INVALID;
		case DHCP_OPT_ADDRESS:
		case DHCP_OPT_TIME:
		case DHCP_OPT_COUNT:
		case DHCP_OPT_NUMBER:
			return DBUS_TYPE_UINT32;
		case DHCP_OPT_STRING:
			return DBUS_TYPE_STRING;
		case DHCP_OPT_TOGGLE:
			return DBUS_TYPE_BOOLEAN;
		case DHCP_OPT_BLOB:
			return DBUS_TYPE_BYTE;
	}
	g_assert_not_reached();
	return DBUS_TYPE_INVALID;
}

#define DBUS_REPLY_BYTYPE(Dtype, Ctype, as_blob) do {														\
		int	__len;																				\
																								\
		if (dhcp_interface_option_present (dhcp_iface, data->opt_id)										\
		 && (sizeof (Ctype) >= (__len = dhcp_option_element_len (data->opt_id)))								\
		 && ((reply = dbus_message_new_method_return (message)) != NULL))									\
		{																						\
			Ctype *__blob;																			\
			int	__count;																			\
																								\
			__blob = dhcp_interface_option_payload (dhcp_iface, data->opt_id);								\
			__count = as_blob ? __len : (dhcp_interface_option_len (dhcp_iface, data->opt_id) / __len); 			\
			dbus_message_append_args (reply, DBUS_TYPE_ARRAY, Dtype, &__blob, __count, DBUS_TYPE_INVALID);			\
		}																						\
	} while (0)

#define DBUS_REPLY_STRING(Dtype, Ctype) do {																\
		int	__len;																				\
																								\
		if (dhcp_interface_option_present (dhcp_iface, data->opt_id)										\
		 && ((__len = dhcp_option_element_len (data->opt_id)) == 1)											\
		 && ((reply = dbus_message_new_method_return (message)) != NULL))									\
		{																						\
			Ctype __val;																			\
			Ctype* __ptr = &__val;																	\
																								\
			__val = (Ctype)dhcp_interface_option_payload (dhcp_iface, data->opt_id);							\
			/* We always return an array even if there's only 1 element */									\
			dbus_message_append_args (reply, DBUS_TYPE_ARRAY, Dtype, &__ptr, 1, DBUS_TYPE_INVALID);				\
		}																						\
	} while (0)


/*
 * nm_dbus_dhcp_get_element_type
 *
 * Gets the length of individual elements within the specified DHCP option.
 *
 */
static DBusMessage *nm_dbus_dhcp_get_element_type (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	if ((reply = dbus_message_new_method_return (message)) != NULL)
	{
		dbus_uint32_t type = nm_dbus_dhcp_element_type (data->opt_id);
		dbus_message_append_args (reply, DBUS_TYPE_UINT32, &type, DBUS_TYPE_INVALID);
	}

	return reply;
}


static DBusMessage *nm_dbus_dhcp_get_boolean (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	DBUS_REPLY_BYTYPE (DBUS_TYPE_BOOLEAN, dbus_bool_t, FALSE);

	return reply;
}


static DBusMessage *nm_dbus_dhcp_get_byte (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	DBUS_REPLY_BYTYPE (DBUS_TYPE_BYTE, unsigned char, FALSE);

	return reply;
}


static DBusMessage *nm_dbus_dhcp_get_integer (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	DBUS_REPLY_BYTYPE (DBUS_TYPE_UINT32, dbus_uint32_t, FALSE);

	return reply;
}


static DBusMessage *nm_dbus_dhcp_get_string (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	DBUS_REPLY_STRING (DBUS_TYPE_STRING, const char *);

	return reply;
}

static DBusMessage *nm_dbus_dhcp_get_blob (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	DBUS_REPLY_BYTYPE (DBUS_TYPE_BYTE, unsigned char, TRUE);

	return reply;
}

static DBusMessage *nm_dbus_dhcp_get_generic (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	switch (nm_dbus_dhcp_element_type (data->opt_id))
	{
		case DBUS_TYPE_BOOLEAN:
			DBUS_REPLY_BYTYPE (DBUS_TYPE_BOOLEAN, dbus_bool_t, FALSE);
			break;
		case DBUS_TYPE_BYTE:
			DBUS_REPLY_BYTYPE (DBUS_TYPE_BYTE, unsigned char, FALSE);
			break;
		case DBUS_TYPE_UINT32:
			DBUS_REPLY_BYTYPE(DBUS_TYPE_UINT32, dbus_uint32_t, FALSE);
			break;
		case DBUS_TYPE_STRING:
			DBUS_REPLY_STRING (DBUS_TYPE_STRING, const char *);
			break;
	}

	return reply;
}


static DBusMessage *nm_dbus_dhcp_get_name (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);

	if ((reply = dbus_message_new_method_return (message)) != NULL)
	{
		const char *name;
		name = dhcp_option_name (data->opt_id);
		dbus_message_append_args (reply, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
	}

	return reply;
}


/*
 * nm_dbus_dhcp_validate
 *
 * Grab an option name or ID from the message and make sure its valid
 *
 */
static DBusMessage *nm_dbus_dhcp_validate (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	DBusError		 error;
	int			 id;
	char			*attribute = NULL;
	gboolean		 success = FALSE;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	/* Caller can ask for DHCP option by either name or ID.  Try name first, then ID. */
	dbus_error_init (&error);
	if (!dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &attribute, DBUS_TYPE_INVALID) || (attribute == NULL))
	{
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		dbus_error_init (&error);
		if (dbus_message_get_args (message, &error, DBUS_TYPE_UINT32, &id, DBUS_TYPE_INVALID) && (id >= 0))
			success = TRUE;
	}
	else if (isdigit (*attribute) && ((id = atoi (attribute)) == 0) && (*attribute != '0'))
	{
		/* If user passed a DHCP option name, find that option's ID */
		if ((id = dhcp_option_id_by_name (attribute)) != -1)
			success = TRUE;
	}

	if (success == TRUE)
	{
		if (!data->data->active_device || !(dhcp_iface = nm_device_get_dhcp_iface (data->data->active_device)))
		{
			reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DhcpOptionsNotAvailable",
							"DhcpOptions are not available at this time.");
			success = FALSE;
		}
		else if (!dhcp_interface_option_present (dhcp_iface, id))
		{
			reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DhcpOptionNotPresent",
							"The DhcpOption requested was not present.");
			success = FALSE;
		}
	}

	if (success)
	{
		data->opt_id = id;
		/* We're gonna need some locking here for dhcp_iface, right now we
		 * just hope it never goes away between the validate and the
		 * dispatch functions.  ie, device gets deactivated, removed, etc.
		 */
		data->dhcp_iface = dhcp_iface;
	}
	else
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "OptionNotFound",
						"The requested DHCP option does not exist.");
	}

	return reply;
}


/*
 * nm_dbus_dhcp_methods_setup
 *
 * Register handlers for dbus methods on the
 * org.freedesktop.NetworkManager.DhcpOptions object.
 *
 */
NMDbusMethodList *nm_dbus_dhcp_methods_setup (void)
{
	NMDbusMethodList	*list = nm_dbus_method_list_new (nm_dbus_dhcp_validate);

	nm_dbus_method_list_add_method (list, "getElementType",	nm_dbus_dhcp_get_element_type);
	nm_dbus_method_list_add_method (list, "getBoolean",		nm_dbus_dhcp_get_boolean);
	nm_dbus_method_list_add_method (list, "getByte",			nm_dbus_dhcp_get_byte);
	nm_dbus_method_list_add_method (list, "getBlob",			nm_dbus_dhcp_get_blob);
	nm_dbus_method_list_add_method (list, "getInteger",		nm_dbus_dhcp_get_integer);
	nm_dbus_method_list_add_method (list, "getString",		nm_dbus_dhcp_get_string);
	nm_dbus_method_list_add_method (list, "get",				nm_dbus_dhcp_get_generic);
	nm_dbus_method_list_add_method (list, "getName",			nm_dbus_dhcp_get_name);

	return (list);
}
