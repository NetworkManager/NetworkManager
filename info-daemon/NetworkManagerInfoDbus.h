/* NetworkManagerInfo -- Manage allowed access points and provide a UI
 *                         for WEP key entry
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

#ifndef NETWORK_MANAGER_INFO_DBUS_SERVICE_H
#define NETWORK_MANAGER_INFO_DBUS_SERVICE_H

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include "NetworkManager.h"
#include "NetworkManagerInfo.h"


int			nmi_dbus_service_init				(DBusConnection *dbus_connection, NMIAppInfo *info);

const char *	nmi_dbus_nm_get_network_essid			(DBusConnection *connection, const char *ap_path);

gboolean		nmi_dbus_nm_get_network_encrypted		(DBusConnection *connection, const char *ap_path);

void 		nmi_dbus_return_user_key				(DBusConnection *connection, const char *device,
											 const char *network, const char *passphrase, const int key_type);

void			nmi_dbus_signal_update_network 		(DBusConnection *connection, const char *network, NMNetworkType type);

#endif
