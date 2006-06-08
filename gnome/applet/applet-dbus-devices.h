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
#include "wireless-security-option.h"

void			nma_dbus_update_one_vpn_connection		(DBusConnection *connection, const char *name, NMApplet *applet, gboolean is_active);
void			nma_dbus_update_vpn_connections			(NMApplet *applet);
gboolean		nma_dbus_update_device_strength			(NMApplet *applet);

void			nma_dbus_update_nm_state				(NMApplet *applet);

void			nma_dbus_update_devices					(NMApplet *applet);
void			nma_dbus_update_dialup					(NMApplet *applet);
void			nma_dbus_dialup_activate_connection		(NMApplet *applet, const char *name);
void			nma_dbus_dialup_deactivate_connection		(NMApplet *applet, const char *name);
void			nma_dbus_device_update_one_device			(NMApplet *applet, const char *dev_path);
void			nma_dbus_device_activated				(NMApplet *applet, const char *dev_path, const char *essid);
void			nma_dbus_device_deactivated				(NMApplet *applet, const char *dev_path);
void			nma_dbus_device_remove_one_device			(NMApplet *applet, const char *dev_path);

void			nma_dbus_device_update_one_network		(NMApplet *applet, const char *dev_path, const char *net_path, const char *active_net_path);
void			nma_dbus_device_remove_one_network		(NMApplet *applet, const char *dev_path, const char *net_path);
void			nma_dbus_update_strength				(NMApplet *applet, const char *dev_path, const char *net_path, int strength);
void			nma_dbus_set_device					(DBusConnection *connection, NetworkDevice *dev, const char *essid, gboolean fallback, WirelessSecurityOption *opt);
void			nma_dbus_create_network					(DBusConnection *connection, NetworkDevice *dev, const char *essid, WirelessSecurityOption *opt);

void			nma_free_data_model					(NMApplet *applet);

#endif
