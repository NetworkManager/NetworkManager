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

#include <syslog.h>
#include "NetworkManagerDbusUtils.h"


struct NMDbusMethodList
{
	NMDbusMethod	 validate_method;
	GHashTable	*methods;
};


NMDbusMethodList * nm_dbus_method_list_new (NMDbusMethod validate_method)
{
	NMDbusMethodList	*list = g_malloc0 (sizeof (NMDbusMethodList));

	list->validate_method = validate_method;
	list->methods = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	return list;	
}


void nm_dbus_method_list_add_method (NMDbusMethodList *list, const char *method, NMDbusMethod callback)
{
	g_return_if_fail (list != NULL);
	g_return_if_fail (list->methods != NULL);
	g_return_if_fail (method != NULL);
	g_return_if_fail (callback != NULL);

	g_hash_table_insert (list->methods, g_strdup (method), callback);
}


gboolean nm_dbus_method_dispatch (NMDbusMethodList *list, DBusConnection *connection, DBusMessage *message, gpointer user_data, DBusMessage **reply)
{
	NMDbusMethod	 callback = NULL;
	const char	*method;
	DBusMessage	*temp_reply = NULL;

	if (reply)
		*reply = NULL;

	g_return_val_if_fail (list != NULL, FALSE);
	g_return_val_if_fail (list->methods != NULL, FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);

	if (!(method = dbus_message_get_member (message)))
		return FALSE;
	
	if (!(callback = g_hash_table_lookup (list->methods, method)))
		return FALSE;

	/* Call the optional validate method first, if it returns NULL then we
	 * actually dispatch the call.
	 */
	if (list->validate_method)
		temp_reply = (*(list->validate_method)) (connection, message, (NMDbusCBData *)user_data);
	if (!temp_reply)
		temp_reply = (*callback) (connection, message, (NMDbusCBData *)user_data);

	if (reply)
		*reply = temp_reply;

	return (TRUE);
}


void nm_dbus_method_list_free (NMDbusMethodList *list)
{
	if (list)
	{
		g_hash_table_destroy (list->methods);
		g_free (list);
	}
}
