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

#ifndef NM_MODEM_TYPES_H
#define NM_MODEM_TYPES_H

#define MM_DBUS_SERVICE              "org.freedesktop.ModemManager"
#define MM_DBUS_PATH                 "/org/freedesktop/ModemManager"
#define MM_DBUS_INTERFACE            "org.freedesktop.ModemManager"
#define MM_DBUS_INTERFACE_MODEM      "org.freedesktop.ModemManager.Modem"
#define MM_DBUS_INTERFACE_MODEM_SIMPLE "org.freedesktop.ModemManager.Modem.Simple"
#define MM_DBUS_INTERFACE_MODEM_CDMA "org.freedesktop.ModemManager.Modem.Cdma"

#define MM_DBUS_INTERFACE_MODEM_GSM_CARD    "org.freedesktop.ModemManager.Modem.Gsm.Card"
#define MM_DBUS_INTERFACE_MODEM_GSM_NETWORK "org.freedesktop.ModemManager.Modem.Gsm.Network"

#define MM_MODEM_TYPE_UNKNOWN  0
#define MM_MODEM_TYPE_GSM      1
#define MM_MODEM_TYPE_CDMA     2

#define MM_MODEM_IP_METHOD_PPP    0
#define MM_MODEM_IP_METHOD_STATIC 1
#define MM_MODEM_IP_METHOD_DHCP   2

/* Errors */

#define MM_SERIAL_OPEN_FAILED MM_DBUS_INTERFACE_MODEM ".SerialOpenFailed"
#define MM_SERIAL_SEND_FAILED MM_DBUS_INTERFACE_MODEM ".SerialSendFailed"
#define MM_SERIAL_RESPONSE_TIMEOUT MM_DBUS_INTERFACE_MODEM ".SerialResponseTimeout"

#define MM_MODEM_ERROR_GENERAL MM_DBUS_INTERFACE_MODEM ".General"
#define MM_MODEM_ERROR_OPERATION_NOT_SUPPORTED MM_DBUS_INTERFACE_MODEM ".OperationNotSupported"

#define MM_MODEM_CONNECT_ERROR_NO_CARRIER MM_DBUS_INTERFACE_MODEM ".NoCarrier"
#define MM_MODEM_CONNECT_ERROR_NO_DIALTONE MM_DBUS_INTERFACE_MODEM ".NoDialtone"
#define MM_MODEM_CONNECT_ERROR_BUSY MM_DBUS_INTERFACE_MODEM ".Busy"
#define MM_MODEM_CONNECT_ERROR_NO_ANSWER MM_DBUS_INTERFACE_MODEM ".NoAnswer"

#define MM_MODEM_ERROR "org.freedesktop.ModemManager.Modem.Gsm"

#define MM_MODEM_ERROR_PHONE_FAILURE MM_MODEM_ERROR ".PhoneFailure"
#define MM_MODEM_ERROR_NO_CONNECTION MM_MODEM_ERROR ".NoConnection"
#define MM_MODEM_ERROR_LINK_RESERVED MM_MODEM_ERROR ".LinkReserved"
#define MM_MODEM_ERROR_NOT_ALLOWED MM_MODEM_ERROR ".OperationNotAllowed"
#define MM_MODEM_ERROR_NOT_SUPPORTED MM_MODEM_ERROR ".OperationNotSupported"
#define MM_MODEM_ERROR_PH_SIM_PIN MM_MODEM_ERROR ".PhSimPinRequired"
#define MM_MODEM_ERROR_PH_FSIM_PIN MM_MODEM_ERROR ".PhFSimPinRequired"
#define MM_MODEM_ERROR_PH_FSIM_PUK MM_MODEM_ERROR ".PhFPukRequired"
#define MM_MODEM_ERROR_SIM_NOT_INSERTED MM_MODEM_ERROR ".SimNotInserted"
#define MM_MODEM_ERROR_SIM_PIN MM_MODEM_ERROR ".SimPinRequired"
#define MM_MODEM_ERROR_SIM_PUK MM_MODEM_ERROR ".SimPukRequired"
#define MM_MODEM_ERROR_SIM_FAILURE MM_MODEM_ERROR ".SimFailure"
#define MM_MODEM_ERROR_SIM_BUSY MM_MODEM_ERROR ".SimBusy"
#define MM_MODEM_ERROR_SIM_WRONG MM_MODEM_ERROR ".SimWrong"
#define MM_MODEM_ERROR_WRONG_PASSWORD MM_MODEM_ERROR ".IncorrectPassword"
#define MM_MODEM_ERROR_SIM_PIN2 MM_MODEM_ERROR ".SimPin2Required"
#define MM_MODEM_ERROR_SIM_PUK2 MM_MODEM_ERROR ".SimPuk2Required"
#define MM_MODEM_ERROR_MEMORY_FULL MM_MODEM_ERROR ".MemoryFull"
#define MM_MODEM_ERROR_INVALID_INDEX MM_MODEM_ERROR ".InvalidIndex"
#define MM_MODEM_ERROR_NOT_FOUND MM_MODEM_ERROR ".NotFound"
#define MM_MODEM_ERROR_MEMORY_FAILURE MM_MODEM_ERROR ".MemoryFailure"
#define MM_MODEM_ERROR_TEXT_TOO_LONG MM_MODEM_ERROR ".TextTooLong"
#define MM_MODEM_ERROR_INVALID_CHARS MM_MODEM_ERROR ".InvalidChars"
#define MM_MODEM_ERROR_DIAL_STRING_TOO_LONG MM_MODEM_ERROR ".DialStringTooLong"
#define MM_MODEM_ERROR_DIAL_STRING_INVALID MM_MODEM_ERROR ".InvalidDialString"
#define MM_MODEM_ERROR_NO_NETWORK MM_MODEM_ERROR ".NoNetwork"
#define MM_MODEM_ERROR_NETWORK_TIMEOUT MM_MODEM_ERROR ".NetworkTimeout"
#define MM_MODEM_ERROR_NETWORK_NOT_ALLOWED MM_MODEM_ERROR ".NetworkNotAllowed"
#define MM_MODEM_ERROR_NETWORK_PIN MM_MODEM_ERROR ".NetworkPinRequired"
#define MM_MODEM_ERROR_NETWORK_PUK MM_MODEM_ERROR ".NetworkPukRequired"
#define MM_MODEM_ERROR_NETWORK_SUBSET_PIN MM_MODEM_ERROR ".NetworkSubsetPinRequired"
#define MM_MODEM_ERROR_NETWORK_SUBSET_PUK MM_MODEM_ERROR ".NetworkSubsetPukRequired"
#define MM_MODEM_ERROR_SERVICE_PIN MM_MODEM_ERROR ".ServicePinRequired"
#define MM_MODEM_ERROR_SERVICE_PUK MM_MODEM_ERROR ".ServicePukRequired"
#define MM_MODEM_ERROR_CORP_PIN MM_MODEM_ERROR ".CorporatePinRequired"
#define MM_MODEM_ERROR_CORP_PUK MM_MODEM_ERROR ".CorporatePukRequired"
#define MM_MODEM_ERROR_HIDDEN_KEY MM_MODEM_ERROR ".HiddenKeyRequired"
#define MM_MODEM_ERROR_EAP_NOT_SUPPORTED MM_MODEM_ERROR ".EapMethodNotSupported"
#define MM_MODEM_ERROR_INCORRECT_PARAMS MM_MODEM_ERROR ".IncorrectParams"
#define MM_MODEM_ERROR_UNKNOWN MM_MODEM_ERROR ".Unknown"
#define MM_MODEM_ERROR_GPRS_ILLEGAL_MS MM_MODEM_ERROR ".GprsIllegalMs"
#define MM_MODEM_ERROR_GPRS_ILLEGAL_ME MM_MODEM_ERROR ".GprsIllegalMe"
#define MM_MODEM_ERROR_GPRS_SERVICE_NOT_ALLOWED  MM_MODEM_ERROR ".GprsServiceNotAllowed"
#define MM_MODEM_ERROR_GPRS_PLMN_NOT_ALLOWED MM_MODEM_ERROR ".GprsPlmnNotAllowed"
#define MM_MODEM_ERROR_GPRS_LOCATION_NOT_ALLOWED MM_MODEM_ERROR ".GprsLocationNotAllowed"
#define MM_MODEM_ERROR_GPRS_ROAMING_NOT_ALLOWED MM_MODEM_ERROR ".GprsRoamingNotAllowed"
#define MM_MODEM_ERROR_GPRS_OPTION_NOT_SUPPORTED MM_MODEM_ERROR ".GprsOptionNotSupported"
#define MM_MODEM_ERROR_GPRS_NOT_SUBSCRIBED MM_MODEM_ERROR ".GprsNotSubscribed"
#define MM_MODEM_ERROR_GPRS_OUT_OF_ORDER MM_MODEM_ERROR ".GprsOutOfOrder"
#define MM_MODEM_ERROR_GPRS_PDP_AUTH_FAILURE MM_MODEM_ERROR ".GprsPdpAuthFailure"
#define MM_MODEM_ERROR_GPRS_UNKNOWN MM_MODEM_ERROR ".GprsUnspecified"
#define MM_MODEM_ERROR_GPRS_INVALID_CLASS MM_MODEM_ERROR ".GprsInvalidClass"

#endif /* NM_MODEM_TYPES_H */
