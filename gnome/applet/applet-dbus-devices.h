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

#ifndef APPLET_DBUS_DEVICES_H
#define APPLET_DBUS_DEVICES_H

#include <glib.h>
#include <dbus/dbus.h>
#include "NetworkManager.h"
#include "applet.h"
#include "nm-device.h"
#include "wireless-network.h"

void			nmwa_dbus_update_one_vpn_connection		(DBusConnection *connection, const char *name, NMWirelessApplet *applet, gboolean is_active);
void			nmwa_dbus_update_vpn_connections			(NMWirelessApplet *applet);
gboolean		nmwa_dbus_update_active_device_strength		(NMWirelessApplet *applet);

void			nmwa_dbus_update_nm_state				(NMWirelessApplet *applet);

void			nmwa_dbus_get_active_device				(NMWirelessApplet *applet);
void			nmwa_dbus_update_devices					(NMWirelessApplet *applet);
void			nmwa_dbus_device_update_one_device			(NMWirelessApplet *applet, const char *dev_path);
void			nmwa_dbus_device_remove_one_device			(NMWirelessApplet *applet, const char *dev_path);

void			nmwa_dbus_device_update_one_network		(NMWirelessApplet *applet, const char *dev_path, const char *net_path, const char *active_net_path);
void			nmwa_dbus_device_remove_one_network		(NMWirelessApplet *applet, const char *dev_path, const char *net_path);

void			nmwa_dbus_set_device					(DBusConnection *connection, NetworkDevice *dev, WirelessNetwork *net, NMEncKeyType key_type, const char *passphrase);
void			nmwa_dbus_create_network					(DBusConnection *connection, NetworkDevice *dev, const char *essid, NMEncKeyType key_type, const char *passphrase);

#endif
