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

#ifndef DBUS_METHOD_DISPATCHER_H
#define DBUS_METHOD_DISPATCHER_H

#include <dbus/dbus.h>


/* Type of method callback functions */
typedef DBusMessage* (*DBusMethodCallback) (DBusConnection *, DBusMessage *, void *);


typedef struct DBusMethodDispatcher DBusMethodDispatcher;

DBusMethodDispatcher *	dbus_method_dispatcher_new (DBusMethodCallback validate_method);

void					dbus_method_dispatcher_ref (DBusMethodDispatcher *dispatcher);

void					dbus_method_dispatcher_unref (DBusMethodDispatcher *dispatcher);

void					dbus_method_dispatcher_register_method (DBusMethodDispatcher *dispatcher,
                                                          const char *method,
                                                          DBusMethodCallback callback);

dbus_bool_t			dbus_method_dispatcher_dispatch (DBusMethodDispatcher *dispatcher,
                                                          DBusConnection *connection,
                                                          DBusMessage *message,
                                                          DBusMessage **reply,
                                                          void * user_data);


#endif	/* DBUS_METHOD_DISPATCHER_H */
