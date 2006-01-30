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

#ifndef WIRELESS_SECURITY_MANAGER_H
#define WIRELESS_SECURITY_MANAGER_H

#include <gtk/gtk.h>
#include "wireless-security-option.h"
#include "wireless-network.h"

typedef struct WirelessSecurityManager WirelessSecurityManager;


WirelessSecurityManager *	wsm_new (const char * glade_file);

void						wsm_free (WirelessSecurityManager *wsm);

gboolean						wsm_set_capabilities (WirelessSecurityManager *wsm, guint32 capabilities);

void						wsm_update_combo (WirelessSecurityManager *wsm, GtkComboBox *combo);

GtkWidget *				wsm_get_widget_for_active (WirelessSecurityManager *wsm, GtkComboBox *combo,
								GtkSignalFunc validate_cb, gpointer user_data);

gboolean					wsm_validate_active (WirelessSecurityManager *wsm, GtkComboBox *combo,
								const char *ssid);

WirelessSecurityOption *		wsm_get_option_for_active (WirelessSecurityManager *wsm, GtkComboBox *combo);

#endif	/* WIRELESS_SECURITY_MANAGER_H */
