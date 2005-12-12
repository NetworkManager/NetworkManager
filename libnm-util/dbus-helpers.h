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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#ifndef DBUS_HELPERS_H
#define DBUS_HELPERS_H

#include <dbus/dbus.h>

#include "cipher.h"

dbus_bool_t	nmu_dbus_message_append_wep_args (DBusMessage *message, IEEE_802_11_Cipher *cipher,
					const char *ssid, const char *input, int auth_alg);

dbus_bool_t	nmu_dbus_message_append_wpa_psk_args (DBusMessage *message, IEEE_802_11_Cipher *cipher,
					const char *ssid, const char *input, int wpa_version, int key_mgt);


#endif	/* DBUS_HELPERS_H */
