/***************************************************************************
 * CVSID: $Id$
 *
 * gnome-generic-auth-widget.h : Public interface for generic auth widgets
 *
 * Copyright (C) 2006 Antony J Mee, <eemynotna at gmail dot com>
 *
 * === 
 * NOTE NOTE NOTE: All source for nm-vpn-properties is licensed to you
 * under your choice of the Academic Free License version 2.0, or the
 * GNU General Public License version 2.
 * ===
 *
 * Licensed under the Academic Free License version 2.0
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
 **************************************************************************/

#ifndef GNOME_GENERIC_AUTH_MODULE_H
#define GNOME_GENERIC_AUTH_MODULE_H

#ifndef GNOME_GENERIC_AUTH_MODULE_SUBJECT_TO_CHANGE
#error "Please define GNOME_GENERIC_AUTH_MODULE_SUBJECT_TO_CHANGE to acknowledge your understanding that NetworkManager hasn't reached 1.0 and is subject to protocol and API churn. See the README for a full explanation."

#endif

	
	
#include <gnome-keyring.h>
#include <gtk/gtk.h>

struct _GnomeGenericAuthModule;
typedef struct _GnomeGenericAuthModule GnomeGenericAuthModule;

typedef void (*GnomeGenericAuthModuleValidityCallback) (GnomeGenericAuthModule *self,
							   gboolean is_valid, 
							   gpointer user_data);

struct _GnomeGenericAuthModule {
	const char *(*get_display_name) (GnomeGenericAuthModule *self);
	const char *(*get_auth_type) (GnomeGenericAuthModule *self);
	const char *(*get_domain) (GnomeGenericAuthModule *self);
	const char *(*get_server) (GnomeGenericAuthModule *self);
	const char *(*get_protocol) (GnomeGenericAuthModule *self);
	const char *(*get_user) (GnomeGenericAuthModule *self);
	GSList     *(*get_secrets) (GnomeGenericAuthModule *self);
	guint32     (*get_port) (GnomeGenericAuthModule *self);

	gboolean (*set_domain) (GnomeGenericAuthModule *self, const char *domain);
	gboolean (*set_user) (GnomeGenericAuthModule *self, const char *user);
	gboolean (*set_server) (GnomeGenericAuthModule *self, const char *server);
	gboolean (*set_protocol) (GnomeGenericAuthModule *self, const char *protocol);
	gboolean (*set_port) (GnomeGenericAuthModule *self, guint32 port);
	gboolean (*set_secret) (GnomeGenericAuthModule *self, const char *object, const char *secret);

	GtkWidget *(*get_widget) (GnomeGenericAuthModule *self);

    gboolean override_user;
    gboolean override_domain;
    gboolean override_server;
    gboolean override_protocol;
    gboolean override_port;


//	void (*set_validity_changed_callback) (GnomeGenericAuthModule *self, 
//					       GnomeGenericAuthModuleValidityCallback cb,
//					       gpointer user_data);

//	gboolean (*is_valid) (GnomeGenericAuthModule *self);

	/*
	 * get_confirmation_details:
	 * retval is allocated and must be freed
	 */
//	void (*get_confirmation_details)(GnomeGenericAuthModule *self, gchar **retval);

//	char *(*get_connection_name) (GnomeGenericAuthModule *self);

//	GSList *(*get_properties) (GnomeGenericAuthModule *self);

//	GSList *(*get_routes) (GnomeGenericAuthModule *self);

//	gboolean (*can_export) (GnomeGenericAuthModule *self);

//	gboolean (*import_file) (GnomeGenericAuthModule *self, const char *path);

//	gboolean (*export) (GnomeGenericAuthModule *self, GSList *properties, GSList *routes, const char *connection_name);

	gpointer data;
};

#endif /* GNOME_GENERIC_AUTH_MODULE_H */

