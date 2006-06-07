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

#ifndef WIRELESS_SECURITY_OPTION_PRIVATE_H
#define WIRELESS_SECURITY_OPTION_PRIVATE_H

#include <glib.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <dbus/dbus.h>

#include "cipher.h"

#define WS_TAG_MAGIC	0xa7f4
#define WS_TAG_NAME		"ws-tag"

typedef struct OptData OptData;

struct WirelessSecurityOption
{
	/* Human readable name for the option */
	char *		name;

	/* Corresponding IEEE_802_11_Cipher objects */
	GSList *		ciphers;

	/* Notebook widget for this option */
	const char *	widget_name;
	GtkWidget *	widget;

	/* The Glade UI for this option */
	GladeXML *	uixml;

	/* Option-specific data */
	OptData *		data;

	/* Option-specific data free function */
	void			(*data_free_func)(WirelessSecurityOption *opt);

	/* Validate the option's input */
	gboolean		(*validate_input_func)(WirelessSecurityOption *opt, const char *ssid, IEEE_802_11_Cipher ** out_cipher);

	/* Widget creation function */
	GtkWidget *	(*widget_create_func)(WirelessSecurityOption *opt, GtkSignalFunc validate_cb, gpointer user_data);

	/* DBUS params append function for building up a suitable
	 * dbus message describing this particular security option
	 */
	gboolean		(*append_dbus_params_func)(WirelessSecurityOption *opt, const char *ssid, DBusMessage *message);
};


gboolean		wso_validate_helper (WirelessSecurityOption *opt, const char *ssid, const char *input, IEEE_802_11_Cipher ** out_cipher);
GtkWidget *	wso_widget_helper (WirelessSecurityOption *opt);

void			wso_wep_auth_combo_setup (WirelessSecurityOption *opt, GtkComboBox * combo);
int			wso_wep_auth_combo_get_auth_alg (WirelessSecurityOption *opt, GtkComboBox * combo);
void			wso_wep_auth_combo_cleanup (WirelessSecurityOption *opt, GtkComboBox * combo);

#define WPA_KEY_TYPE_NAME_COL		0
#define WPA_KEY_TYPE_CIPHER_COL	1

GtkTreeModel *	wso_wpa_create_key_type_model (int capabilities, gboolean wpa_eap, int *num_added);


#endif	/* WIRELESS_SECURITY_OPTION_PRIVATE_H */
