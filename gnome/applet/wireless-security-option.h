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

#ifndef WIRELESS_SECURITY_OPTION_H
#define WIRELESS_SECURITY_OPTION_H

typedef struct WirelessSecurityOption WirelessSecurityOption;

WirelessSecurityOption * wso_none_new (const char *glade_file);
WirelessSecurityOption * wso_wep_passphrase_new (const char *glade_file);
WirelessSecurityOption * wso_wep_hex_new (const char *glade_file);
WirelessSecurityOption * wso_wep_ascii_new (const char *glade_file);
WirelessSecurityOption * wso_wpa_psk_passphrase_new (const char *glade_file);

const char * wso_get_name (WirelessSecurityOption * opt);
GtkWidget * wso_get_widget (WirelessSecurityOption * opt, GtkSignalFunc validate_cb, gpointer user_data);
gboolean wso_is_wso_widget (GtkWidget * widget);
gboolean wso_validate_input (WirelessSecurityOption * opt, const char * ssid);
void wso_free (WirelessSecurityOption * opt);



#endif	/* WIRELESS_SECURITY_OPTION_H */
