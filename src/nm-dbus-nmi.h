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

#ifndef NM_DBUS_NMI_H
#define NM_DBUS_NMI_H

#include "NetworkManager.h"
#include "NetworkManagerAP.h"

void			nm_dbus_get_user_key_for_network		(DBusConnection *connection, NMActRequest *req, const gboolean new_key);

void			nm_dbus_cancel_get_user_key_for_network	(DBusConnection *connection, NMActRequest *req);

NMAccessPoint *nm_dbus_get_network_object			(DBusConnection *connection, NMNetworkType type, const char *network);

gboolean		nm_dbus_update_network_info			(DBusConnection *connection, NMAccessPoint *ap, const gboolean user_requested);

void			nm_dbus_update_one_allowed_network		(DBusConnection *connection, const char *network, NMData *data);

void			nm_dbus_update_allowed_networks		(DBusConnection *connection, NMAccessPointList *list, NMData *data);


#endif	/* NM_DBUS_NMI_H */
