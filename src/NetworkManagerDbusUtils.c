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
#include <string.h>
#include "NetworkManagerDbusUtils.h"


struct NMDbusMethodList
{
	guint32							refcount;
	GHashTable *					methods;

	char *							path;
	gboolean						is_fallback;

	DBusObjectPathMessageFunction	handler_func;
	gpointer						user_data;
	DBusFreeFunction				user_data_free_func;
};


/**
 * @param path DBus object path for which the handler applies
 * @param is_fallback whether the handlers should be registered as a fallback
 */
NMDbusMethodList *
nm_dbus_method_list_new (const char *path,
                         gboolean is_fallback,
                         gpointer user_data,
                         DBusFreeFunction user_data_free_func)
{
	NMDbusMethodList *	list;

	g_return_val_if_fail (path != NULL, NULL);

	list = g_slice_new0 (NMDbusMethodList);

	list->refcount = 1;
	list->path = g_strdup (path);
	list->is_fallback = is_fallback;
	list->user_data = user_data;
	list->user_data_free_func = user_data_free_func;
	list->methods = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	return list;	
}

void
nm_dbus_method_list_ref (NMDbusMethodList *list)
{
	g_return_if_fail (list != NULL);

	list->refcount += 1;
}

void
nm_dbus_method_list_unref (NMDbusMethodList *list)
{
	g_return_if_fail (list != NULL);
	g_return_if_fail (list->refcount >= 1);

	list->refcount -= 1;
	if (list->refcount <= 0) {
		if (list->user_data && list->user_data_free_func)
			(*list->user_data_free_func)(list->user_data);
		g_hash_table_destroy (list->methods);
		memset (list, 0, sizeof (NMDbusMethodList));
		g_slice_free (NMDbusMethodList, list);
	}
}

DBusObjectPathMessageFunction
nm_dbus_method_list_get_custom_handler_func (NMDbusMethodList *list)
{
	g_return_val_if_fail (list != NULL, NULL);

	return list->handler_func;
}

gpointer
nm_dbus_method_list_get_user_data (NMDbusMethodList *list)
{
	g_return_val_if_fail (list != NULL, NULL);

	return list->user_data;
}

/**
 * @param handler_func NULL, or handler function which overrides the default one
 */
void
nm_dbus_method_list_set_custom_handler_func (NMDbusMethodList *list,
                                             DBusObjectPathMessageFunction handler_func)
{
	g_return_if_fail (list != NULL);
	g_return_if_fail (handler_func != NULL);
	g_return_if_fail (list->handler_func == NULL);
	
	list->handler_func = handler_func;
}

void
nm_dbus_method_list_add_method (NMDbusMethodList *list,
                                const char *method,
                                NMDBusHandleMessageFunc callback)
{
	g_return_if_fail (list != NULL);
	g_return_if_fail (list->methods != NULL);
	g_return_if_fail (method != NULL);
	g_return_if_fail (callback != NULL);

	g_hash_table_insert (list->methods, g_strdup (method), callback);
}


gboolean
nm_dbus_method_list_dispatch (NMDbusMethodList *list,
                              DBusConnection *connection,
                              DBusMessage *message,
                              gpointer user_data,
                              DBusMessage **reply)
{
	NMDBusHandleMessageFunc	callback = NULL;
	const char *			method;

	g_return_val_if_fail (list != NULL, FALSE);
	g_return_val_if_fail (list->methods != NULL, FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);

	if (reply)
		*reply = NULL;

	if (!(method = dbus_message_get_member (message)))
		return FALSE;
	
	if (!(callback = g_hash_table_lookup (list->methods, method)))
		return FALSE;

	/* Dispatch the method call */
	*reply = (*callback) (connection, message, user_data);

	return TRUE;
}

gboolean
nm_dbus_method_list_get_is_fallback (NMDbusMethodList *list)
{
	g_return_val_if_fail (list != NULL, FALSE);

	return list->is_fallback;
}

const char *
nm_dbus_method_list_get_path (NMDbusMethodList *list)
{
	g_return_val_if_fail (list != NULL, NULL);

	return list->path;
}

