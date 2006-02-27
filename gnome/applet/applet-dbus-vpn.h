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

#ifndef APPLET_DBUS_VPN_H
#define APPLET_DBUS_VPN_H

#include <glib.h>
#include <dbus/dbus.h>
#include "vpn-connection.h"

void		nma_dbus_vpn_set_last_attempt_status			(NMApplet *applet, const char *vpn_name, gboolean last_attempt_success);

void		nma_dbus_vpn_update_one_vpn_connection			(NMApplet *applet, const char *vpn_name);
void		nma_dbus_vpn_update_vpn_connections			(NMApplet *applet);
void		nma_dbus_vpn_remove_one_vpn_connection			(NMApplet *applet, const char *vpn_name);

void		nma_dbus_vpn_activate_connection				(DBusConnection *connection, const char *name, GSList *passwords);
void		nma_dbus_vpn_deactivate_connection			(DBusConnection *connection);
void		nma_dbus_vpn_update_vpn_connection_stage		(NMApplet *applet, const char *vpn_name, NMVPNActStage vpn_state);

#endif
