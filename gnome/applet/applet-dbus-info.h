/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
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
 * (C) Copyright 2004-2005 Red Hat, Inc.
 */

#ifndef APPLET_DBUS_INFO_H
#define APPLET_DBUS_INFO_H

#include <dbus/dbus.h>
#include "nm-device.h"
#include "wireless-network.h"
#include "NetworkManager.h"

DBusHandlerResult		nmi_dbus_info_message_handler			(DBusConnection *connection, DBusMessage *message, void *user_data);

void					nmi_dbus_return_user_key				(DBusConnection *connection, DBusMessage *message, const char *passphrase, const NMEncKeyType key_type);

void					nmi_dbus_signal_update_scan_method		(DBusConnection *connection);

void					nmi_dbus_signal_update_network		(DBusConnection *connection, const char *network, NMNetworkType type);

void					nmi_dbus_signal_update_vpn_connection	(DBusConnection *connection, const char *name);

#endif
