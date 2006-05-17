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

#ifndef WIRELESS_NETWORK_H
#define WIRELESS_NETWORK_H

typedef struct WirelessNetwork WirelessNetwork;

WirelessNetwork *	wireless_network_new			(const char *essid, const char *nm_path);
WirelessNetwork *	wireless_network_copy			(WirelessNetwork *src);

void				wireless_network_ref			(WirelessNetwork *net);
void				wireless_network_unref			(WirelessNetwork *net);

gboolean			wireless_network_get_active		(WirelessNetwork *net);
void				wireless_network_set_active		(WirelessNetwork *net, gboolean active);

const char *		wireless_network_get_essid		(WirelessNetwork *net);

const char *		wireless_network_get_nm_path		(WirelessNetwork *net);

int				wireless_network_get_capabilities	(WirelessNetwork *net);
void				wireless_network_set_capabilities	(WirelessNetwork *net, int capabilities);

int				wireless_network_get_mode		(WirelessNetwork *net);
void				wireless_network_set_mode		(WirelessNetwork *net, int mode);

gint8			wireless_network_get_strength		(WirelessNetwork *net);
void				wireless_network_set_strength		(WirelessNetwork *net, gint8 strength);

#endif
