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

static int nm_dbus_dhcp_record_type (int id)
{
	switch (dhcp_option_record_type (id))
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

#define DBUS_REPLY_BYTYPE(Dtype, Ctype) do {																\
		int	__DBUS_REPLY_BYTYPE_len;																	\
																								\
		if (dhcp_interface_option_present (dhcp_iface, data->opt_id)										\
		 && (sizeof (Ctype) >= (__DBUS_REPLY_BYTYPE_len = dhcp_option_record_len (data->opt_id)))					\
		 && ((reply = dbus_message_new_method_return (message)) != NULL))									\
		{																						\
			Ctype __DBUS_REPLY_BYTYPE_val;															\
			void	*__DBUS_REPLY_BYTYPE_blob;															\
																								\
			__DBUS_REPLY_BYTYPE_blob = dhcp_interface_option_payload (dhcp_iface, data->opt_id);					\
			if (__DBUS_REPLY_BYTYPE_len == 1)															\
				__DBUS_REPLY_BYTYPE_val = ((unsigned char *)__DBUS_REPLY_BYTYPE_blob)[0];						\
			else if (__DBUS_REPLY_BYTYPE_len == 2)														\
				__DBUS_REPLY_BYTYPE_val = ((dbus_uint16_t *)__DBUS_REPLY_BYTYPE_blob)[0];						\
			else																					\
				__DBUS_REPLY_BYTYPE_val = ((dbus_uint32_t *)__DBUS_REPLY_BYTYPE_blob)[0];						\
			dbus_message_append_args (reply, Dtype, __DBUS_REPLY_BYTYPE_val, DBUS_TYPE_INVALID);					\
		}																						\
	} while (0)

#define DBUS_REPLY_BYTYPEV(Dtype, Ctype, Dappend) do {														\
		int	__DBUS_REPLY_BYTYPE_len;																	\
																								\
		if (dhcp_interface_option_present (dhcp_iface, data->opt_id)										\
		 && (sizeof (Ctype) >= (__DBUS_REPLY_BYTYPE_len = dhcp_option_record_len (data->opt_id)))					\
		 && ((reply = dbus_message_new_method_return (message)) != NULL))									\
		{																						\
			DBusMessageIter	__DBUS_REPLY_BYTYPE_iter, __DBUS_REPLY_BYTYPE_sub;							\
			void	*__DBUS_REPLY_BYTYPE_blob;															\
			int	__DBUS_REPLY_BYTYPE_i, __DBUS_REPLY_BYTYPE_count;											\
																								\
			__DBUS_REPLY_BYTYPE_blob = dhcp_interface_option_payload (dhcp_iface, data->opt_id);					\
			__DBUS_REPLY_BYTYPE_count = dhcp_interface_option_len (dhcp_iface, data->opt_id) / __DBUS_REPLY_BYTYPE_len; \
			dbus_message_iter_init (reply, &__DBUS_REPLY_BYTYPE_iter);										\
			dbus_message_iter_append_array (&__DBUS_REPLY_BYTYPE_iter, &__DBUS_REPLY_BYTYPE_sub, Dtype);			\
			for (__DBUS_REPLY_BYTYPE_i = 0; __DBUS_REPLY_BYTYPE_i < __DBUS_REPLY_BYTYPE_count; __DBUS_REPLY_BYTYPE_i++) \
			{																					\
				Ctype __DBUS_REPLY_BYTYPE_val;														\
																								\
				if (__DBUS_REPLY_BYTYPE_len == 1)														\
					__DBUS_REPLY_BYTYPE_val = ((unsigned char *)__DBUS_REPLY_BYTYPE_blob)[__DBUS_REPLY_BYTYPE_i];	\
				else if (__DBUS_REPLY_BYTYPE_len == 2)													\
					__DBUS_REPLY_BYTYPE_val = ((dbus_uint16_t *)__DBUS_REPLY_BYTYPE_blob)[__DBUS_REPLY_BYTYPE_i];	\
				else																				\
					__DBUS_REPLY_BYTYPE_val = ((dbus_uint32_t *)__DBUS_REPLY_BYTYPE_blob)[__DBUS_REPLY_BYTYPE_i];	\
				/*dbus_message_iter_append_basic (&__DBUS_REPLY_BYTYPE_sub, Dtype, __DBUS_REPLY_BYTYPE_val);*/		\
				dbus_message_iter_append_ ## Dappend (&__DBUS_REPLY_BYTYPE_sub, __DBUS_REPLY_BYTYPE_val);			\
			}																					\
		}																						\
	} while (0)

#define DBUS_REPLY_STRING(Dtype, Ctype) do {																\
		int	__DBUS_REPLY_BYTYPE_len;																	\
																								\
		if (dhcp_interface_option_present (dhcp_iface, data->opt_id)										\
		 && ((__DBUS_REPLY_BYTYPE_len = dhcp_option_record_len (data->opt_id)) == 1)							\
		 && ((reply = dbus_message_new_method_return (message)) != NULL))									\
		{																						\
			Ctype __DBUS_REPLY_BYTYPE_val;															\
																								\
			__DBUS_REPLY_BYTYPE_val = (Ctype)dhcp_interface_option_payload (dhcp_iface, data->opt_id);			\
			dbus_message_append_args (reply, Dtype, __DBUS_REPLY_BYTYPE_val, DBUS_TYPE_INVALID);					\
		}																						\
	} while (0)


/*
 * nm_dbus_dhcp_get_len
 *
 * Gets the total length of the specified DHCP option.
 *
 */
static DBusMessage *nm_dbus_dhcp_get_len (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	if ((reply = dbus_message_new_method_return (message)) != NULL)
		dbus_message_append_args (reply, DBUS_TYPE_UINT32, dhcp_interface_option_len (dhcp_iface, data->opt_id), DBUS_TYPE_INVALID);

	return reply;
}

/*
 * nm_dbus_dhcp_get_type
 *
 * Gets the type of the DHCP option.
 *
 */
static DBusMessage *nm_dbus_dhcp_get_type (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	if ((reply = dbus_message_new_method_return (message)) != NULL)
	{
		if (nm_dbus_dhcp_record_type (data->opt_id) == DBUS_TYPE_STRING)
			dbus_message_append_args (reply, DBUS_TYPE_UINT32, DBUS_TYPE_STRING, DBUS_TYPE_INVALID);
		else if (dhcp_interface_option_len (dhcp_iface, data->opt_id) != dhcp_option_record_len (data->opt_id))
			dbus_message_append_args (reply, DBUS_TYPE_UINT32, DBUS_TYPE_ARRAY, DBUS_TYPE_INVALID);
		else
			dbus_message_append_args (reply, DBUS_TYPE_UINT32, nm_dbus_dhcp_record_type (data->opt_id), DBUS_TYPE_INVALID);
	}

	return reply;
}


/*
 * nm_dbus_dhcp_get_record_type
 *
 * Gets the length of individual records within the specified DHCP option.
 *
 */
static DBusMessage *nm_dbus_dhcp_get_record_type (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	if ((reply = dbus_message_new_method_return (message)) != NULL)
		dbus_message_append_args (reply, DBUS_TYPE_UINT32, nm_dbus_dhcp_record_type (data->opt_id), DBUS_TYPE_INVALID);

	return reply;
}


static DBusMessage *nm_dbus_dhcp_get_boolean (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	DBUS_REPLY_BYTYPE (DBUS_TYPE_BOOLEAN, dbus_bool_t);

	return reply;
}


static DBusMessage *nm_dbus_dhcp_get_booleanv (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	DBUS_REPLY_BYTYPEV (DBUS_TYPE_BOOLEAN, dbus_bool_t, boolean);

	return reply;
}

static DBusMessage *nm_dbus_dhcp_get_byte (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	DBUS_REPLY_BYTYPE (DBUS_TYPE_BYTE, unsigned char);

	return reply;
}


static DBusMessage *nm_dbus_dhcp_get_bytev (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	DBUS_REPLY_BYTYPEV (DBUS_TYPE_BYTE, unsigned char, byte);

	return reply;
}


static DBusMessage *nm_dbus_dhcp_get_integer (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	DBUS_REPLY_BYTYPE (DBUS_TYPE_UINT32, dbus_uint32_t);

	return reply;
}


static DBusMessage *nm_dbus_dhcp_get_integerv (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	DBUS_REPLY_BYTYPEV (DBUS_TYPE_UINT32, dbus_uint32_t, uint32);

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


static DBusMessage *nm_dbus_dhcp_get_generic (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage			*reply = NULL;
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);
	dhcp_iface = data->dhcp_iface;

	switch (nm_dbus_dhcp_record_type (data->opt_id))
	{
		case DBUS_TYPE_BOOLEAN:
			if (dhcp_interface_option_len (dhcp_iface, data->opt_id) == dhcp_option_record_len (data->opt_id))
				DBUS_REPLY_BYTYPE (DBUS_TYPE_BOOLEAN, dbus_bool_t);
			else
				DBUS_REPLY_BYTYPEV (DBUS_TYPE_BOOLEAN, dbus_bool_t, boolean);
			break;
		case DBUS_TYPE_BYTE:
			if (dhcp_interface_option_len (dhcp_iface, data->opt_id) == dhcp_option_record_len (data->opt_id))
				DBUS_REPLY_BYTYPE (DBUS_TYPE_BYTE, unsigned char);
			else
				DBUS_REPLY_BYTYPEV (DBUS_TYPE_BYTE, unsigned char, byte);
			break;
		case DBUS_TYPE_UINT32:
			if (dhcp_interface_option_len (dhcp_iface, data->opt_id) == dhcp_option_record_len (data->opt_id))
				DBUS_REPLY_BYTYPE(DBUS_TYPE_UINT32, dbus_uint32_t);
			else
				DBUS_REPLY_BYTYPEV (DBUS_TYPE_UINT32, dbus_uint32_t, uint32);
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
	struct dhcp_interface	*dhcp_iface;

	g_return_val_if_fail (data && data->data && (data->opt_id >= 0) && (data->dhcp_iface != NULL) && connection && message, NULL);

	if ((reply = dbus_message_new_method_return (message)) != NULL)
		dbus_message_append_args (reply, DBUS_TYPE_STRING, dhcp_option_name (data->opt_id), DBUS_TYPE_INVALID);

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
	NMDevice		*dev;
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

	nm_dbus_method_list_add_method (list, "getLen",			nm_dbus_dhcp_get_len);
	nm_dbus_method_list_add_method (list, "getType",			nm_dbus_dhcp_get_type);
	nm_dbus_method_list_add_method (list, "getRecordType",		nm_dbus_dhcp_get_record_type);
	nm_dbus_method_list_add_method (list, "getBoolean",		nm_dbus_dhcp_get_boolean);
	nm_dbus_method_list_add_method (list, "getBooleanv",		nm_dbus_dhcp_get_booleanv);
	nm_dbus_method_list_add_method (list, "getByte",			nm_dbus_dhcp_get_byte);
	nm_dbus_method_list_add_method (list, "getBytev",			nm_dbus_dhcp_get_bytev);
	nm_dbus_method_list_add_method (list, "getBlob",			nm_dbus_dhcp_get_bytev);	/* getBlob is an alias for getBytev */
	nm_dbus_method_list_add_method (list, "getInteger",		nm_dbus_dhcp_get_integer);
	nm_dbus_method_list_add_method (list, "getIntegerv",		nm_dbus_dhcp_get_integerv);
	nm_dbus_method_list_add_method (list, "getString",		nm_dbus_dhcp_get_string);
	nm_dbus_method_list_add_method (list, "get",				nm_dbus_dhcp_get_generic);
	nm_dbus_method_list_add_method (list, "getName",			nm_dbus_dhcp_get_name);

	return (list);
}
