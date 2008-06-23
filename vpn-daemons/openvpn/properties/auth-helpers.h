/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * nm-openvpn.c : GNOME UI dialogs for configuring openvpn VPN connections
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 **************************************************************************/

#ifndef _AUTH_HELPERS_H_
#define _AUTH_HELPERS_H_

#include <glib.h>
#include <gtk/gtk.h>
#include <gtk/gtkfilefilter.h>
#include <glade/glade.h>

#include <nm-setting-vpn-properties.h>

typedef void (*ChangedCallback) (GtkWidget *widget, gpointer user_data);

void tls_pw_init_auth_widget (GladeXML *xml,
                              GtkSizeGroup *group,
                              NMSettingVPNProperties *s_vpn_props,
                              gint contype,
                              const char *prefix,
                              ChangedCallback changed_cb,
                              gpointer user_data);

void sk_init_auth_widget (GladeXML *xml,
                          GtkSizeGroup *group,
                          NMSettingVPNProperties *s_vpn_props,
                          ChangedCallback changed_cb,
                          gpointer user_data);

gboolean auth_widget_check_validity (GladeXML *xml, gint contype, GError **error);

gboolean auth_widget_update_connection (GladeXML *xml,
                                        gint contype,
                                        NMSettingVPNProperties *s_vpn_props);

GtkFileFilter *tls_file_chooser_filter_new (void);

GtkFileFilter *sk_file_chooser_filter_new (void);

#endif
