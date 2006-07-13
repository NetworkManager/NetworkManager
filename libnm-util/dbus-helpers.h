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

#ifdef __cplusplus
extern "C" {
#endif

dbus_bool_t	nmu_security_serialize_wep (DBusMessageIter *iter,
                                        const char *key,
                                        int auth_alg);

dbus_bool_t	nmu_security_deserialize_wep (DBusMessageIter *iter,
                                        char **key,
                                        int *key_len,
                                        int *auth_alg);

dbus_bool_t	nmu_security_serialize_none_with_cipher (DBusMessage *message);

dbus_bool_t	nmu_security_serialize_wep_with_cipher (DBusMessage *message,
                                        IEEE_802_11_Cipher *cipher,
                                        const char *ssid,
                                        const char *input,
                                        int auth_alg);

dbus_bool_t	nmu_security_serialize_wpa_psk (DBusMessageIter *iter,
                                        const char *key,
                                        int wpa_version,
                                        int key_mgt);

dbus_bool_t	nmu_security_deserialize_wpa_psk (DBusMessageIter *iter,
                                        char **key,
                                        int *key_len,
                                        int *wpa_version,
                                        int *key_mgt);

dbus_bool_t	nmu_security_serialize_wpa_psk_with_cipher (DBusMessage *message,
                                        IEEE_802_11_Cipher *cipher,
                                        const char *ssid,
                                        const char *input,
                                        int wpa_version,
                                        int key_mgt);

dbus_bool_t	nmu_security_serialize_wpa_eap (DBusMessageIter *iter,
								int eap_method,
								int key_type,
								const char *identity,
								const char *passwd,
								const char *anon_identity,
								const char *private_key_passwd,
								const char *private_key_file,
								const char *client_cert_file,
								const char *ca_cert_file,
								int wpa_version);

dbus_bool_t	nmu_security_serialize_wpa_eap_with_cipher (DBusMessageIter *iter,
								int eap_method,
								int key_type,
								const char *identity,
								const char *passwd,
								const char *anon_identity,
								const char *private_key_passwd,
								const char *private_key_file,
								const char *client_cert_file,
								const char *ca_cert_file,
								int wpa_version);

dbus_bool_t	nmu_security_deserialize_wpa_eap (DBusMessageIter *iter,
								int *eap_method,
								int *key_type,
								char **identity,
								char **passwd,
								char **anon_identity,
								char **private_key_passwd,
								char **private_key_file,
								char **client_cert_file,
								char **ca_cert_file,
								int *wpa_version);
dbus_bool_t	nmu_security_serialize_leap (DBusMessageIter *iter,
								const char *username,
								const char *passwd,
								const char *key_mgmt);

dbus_bool_t	nmu_security_serialize_leap_with_cipher (DBusMessageIter *iter,
								const char *username,
								const char *passwd,
								const char *key_mgmt);

dbus_bool_t	nmu_security_deserialize_leap (DBusMessageIter *iter,
								char **username,
								char **passwd,
								char **key_mgmt);

DBusMessage *	nmu_create_dbus_error_message (DBusMessage *message,
                                        const char *exception_namespace,
                                        const char *exception,
                                        const char *format,
                                        ...);

#ifdef __cplusplus
}
#endif

#endif	/* DBUS_HELPERS_H */
