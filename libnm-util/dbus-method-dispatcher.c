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

#include <glib.h>
#include <string.h>
#include "dbus-method-dispatcher.h"


struct DBusMethodDispatcher
{
	int				refcount;

	DBusMethodCallback	validate_method;
	GHashTable *		methods;
};


DBusMethodDispatcher *
dbus_method_dispatcher_new (DBusMethodCallback validate_method)
{
	DBusMethodDispatcher * dispatcher = g_malloc0 (sizeof (DBusMethodDispatcher));

	dispatcher->refcount = 1;
	dispatcher->validate_method = validate_method;
	dispatcher->methods = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	return dispatcher;	
}

void
dbus_method_dispatcher_ref (DBusMethodDispatcher *dispatcher)
{
	g_return_if_fail (dispatcher != NULL);
	g_return_if_fail (dispatcher->refcount >= 1);

	dispatcher->refcount++;
}

void
dbus_method_dispatcher_unref (DBusMethodDispatcher *dispatcher)
{
	g_return_if_fail (dispatcher != NULL);
	g_return_if_fail (dispatcher->refcount >= 1);

	dispatcher->refcount--;
	if (dispatcher->refcount <= 0)
	{
		g_hash_table_destroy (dispatcher->methods);
		memset (dispatcher, 0, sizeof (DBusMethodDispatcher));
		g_free (dispatcher);
	}
}


void
dbus_method_dispatcher_register_method (DBusMethodDispatcher *dispatcher,
                                        const char *method,
                                        DBusMethodCallback callback)
{
	g_return_if_fail (dispatcher != NULL);
	g_return_if_fail (dispatcher->refcount >= 1);
	g_return_if_fail (method != NULL);
	g_return_if_fail (callback != NULL);

	g_assert (dispatcher->methods);

	g_hash_table_insert (dispatcher->methods, g_strdup (method), callback);
}


dbus_bool_t
dbus_method_dispatcher_dispatch (DBusMethodDispatcher *dispatcher,
                                 DBusConnection *connection,
                                 DBusMessage *message,
                                 DBusMessage **reply,
                                 void * user_data)
{
	DBusMethodCallback	callback = NULL;
	const char *		method;
	DBusMessage *		temp_reply = NULL;

	g_return_val_if_fail (dispatcher != NULL, FALSE);
	g_return_val_if_fail (dispatcher->refcount >= 1, FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);

	g_assert (dispatcher->methods);

	if (reply)
		g_return_val_if_fail (*reply == NULL, FALSE);

	if (!(method = dbus_message_get_member (message)))
		return FALSE;

	if (!(callback = g_hash_table_lookup (dispatcher->methods, method)))
		return FALSE;

	/* Call the optional validate method first, if it returns NULL then we
	 * actually dispatch the call.
	 */
	if (dispatcher->validate_method)
		temp_reply = (*(dispatcher->validate_method)) (connection, message, user_data);
	if (!temp_reply)
		temp_reply = (*callback) (connection, message, user_data);

	if (reply)
		*reply = temp_reply;

	return TRUE;
}

