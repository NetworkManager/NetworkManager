/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef NM_MODEM_OLD_TYPES_H
#define NM_MODEM_OLD_TYPES_H

#define MM_OLD_DBUS_SERVICE                     "org.freedesktop.ModemManager"
#define MM_OLD_DBUS_PATH                        "/org/freedesktop/ModemManager"
#define MM_OLD_DBUS_INTERFACE                   "org.freedesktop.ModemManager"
#define MM_OLD_DBUS_INTERFACE_MODEM             "org.freedesktop.ModemManager.Modem"
#define MM_OLD_DBUS_INTERFACE_MODEM_SIMPLE      "org.freedesktop.ModemManager.Modem.Simple"
#define MM_OLD_DBUS_INTERFACE_MODEM_CDMA        "org.freedesktop.ModemManager.Modem.Cdma"
#define MM_OLD_DBUS_INTERFACE_MODEM_GSM_CARD    "org.freedesktop.ModemManager.Modem.Gsm.Card"
#define MM_OLD_DBUS_INTERFACE_MODEM_GSM_NETWORK "org.freedesktop.ModemManager.Modem.Gsm.Network"

#define MM_OLD_MODEM_TYPE_UNKNOWN  0
#define MM_OLD_MODEM_TYPE_GSM      1
#define MM_OLD_MODEM_TYPE_CDMA     2

/* Errors */

#define MM_OLD_MODEM_CONNECT_ERROR_NO_CARRIER  MM_OLD_DBUS_INTERFACE_MODEM ".NoCarrier"
#define MM_OLD_MODEM_CONNECT_ERROR_NO_DIALTONE MM_OLD_DBUS_INTERFACE_MODEM ".NoDialtone"
#define MM_OLD_MODEM_CONNECT_ERROR_BUSY        MM_OLD_DBUS_INTERFACE_MODEM ".Busy"
#define MM_OLD_MODEM_CONNECT_ERROR_NO_ANSWER   MM_OLD_DBUS_INTERFACE_MODEM ".NoAnswer"

#define MM_OLD_MODEM_ERROR "org.freedesktop.ModemManager.Modem.Gsm"

#define MM_OLD_MODEM_ERROR_NETWORK_NOT_ALLOWED MM_OLD_MODEM_ERROR ".NetworkNotAllowed"
#define MM_OLD_MODEM_ERROR_NETWORK_TIMEOUT     MM_OLD_MODEM_ERROR ".NetworkTimeout"
#define MM_OLD_MODEM_ERROR_NO_NETWORK          MM_OLD_MODEM_ERROR ".NoNetwork"
#define MM_OLD_MODEM_ERROR_SIM_NOT_INSERTED    MM_OLD_MODEM_ERROR ".SimNotInserted"
#define MM_OLD_MODEM_ERROR_SIM_PIN             MM_OLD_MODEM_ERROR ".SimPinRequired"
#define MM_OLD_MODEM_ERROR_SIM_PUK             MM_OLD_MODEM_ERROR ".SimPukRequired"
#define MM_OLD_MODEM_ERROR_SIM_WRONG           MM_OLD_MODEM_ERROR ".SimWrong"
#define MM_OLD_MODEM_ERROR_WRONG_PASSWORD      MM_OLD_MODEM_ERROR ".IncorrectPassword"

typedef enum {
    MM_OLD_MODEM_STATE_UNKNOWN = 0,
    MM_OLD_MODEM_STATE_DISABLED = 10,
    MM_OLD_MODEM_STATE_DISABLING = 20,
    MM_OLD_MODEM_STATE_ENABLING = 30,
    MM_OLD_MODEM_STATE_ENABLED = 40,
    MM_OLD_MODEM_STATE_SEARCHING = 50,
    MM_OLD_MODEM_STATE_REGISTERED = 60,
    MM_OLD_MODEM_STATE_DISCONNECTING = 70,
    MM_OLD_MODEM_STATE_CONNECTING = 80,
    MM_OLD_MODEM_STATE_CONNECTED = 90,

    MM_OLD_MODEM_STATE_LAST = MM_OLD_MODEM_STATE_CONNECTED
} MMOldModemState;

#endif /* NM_MODEM_OLD_TYPES_H */
