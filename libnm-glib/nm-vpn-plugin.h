/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#ifndef NM_VPN_PLUGIN_H
#define NM_VPN_PLUGIN_H

#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include <NetworkManagerVPN.h>
#include <nm-connection.h>

G_BEGIN_DECLS

#define NM_TYPE_VPN_PLUGIN            (nm_vpn_plugin_get_type ())
#define NM_VPN_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_PLUGIN, NMVPNPlugin))
#define NM_VPN_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_PLUGIN, NMVPNPluginClass))
#define NM_IS_VPN_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_PLUGIN))
#define NM_IS_VPN_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_VPN_PLUGIN))
#define NM_VPN_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_PLUGIN, NMVPNPluginClass))

#define NM_VPN_PLUGIN_DBUS_SERVICE_NAME "service-name"
#define NM_VPN_PLUGIN_STATE             "state"

typedef enum {
	NM_VPN_PLUGIN_ERROR_GENERAL,
	NM_VPN_PLUGIN_ERROR_STARTING_IN_PROGRESS,
	NM_VPN_PLUGIN_ERROR_ALREADY_STARTED,
	NM_VPN_PLUGIN_ERROR_STOPPING_IN_PROGRESS,
	NM_VPN_PLUGIN_ERROR_ALREADY_STOPPED,
	NM_VPN_PLUGIN_ERROR_WRONG_STATE,
	NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
	NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
	NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
} NMVPNPluginError;

#define NM_VPN_PLUGIN_ERROR      (nm_vpn_plugin_error_quark ())
#define NM_TYPE_VPN_PLUGIN_ERROR (nm_vpn_plugin_error_get_type ()) 

typedef struct {
	GObject parent;
} NMVPNPlugin;

typedef struct {
	GObjectClass parent;

	/* virtual methods */
	gboolean (*connect)    (NMVPNPlugin   *plugin,
					    NMConnection  *connection,
					    GError       **err);

	gboolean (*need_secrets) (NMVPNPlugin *plugin,
	                              NMConnection *connection,
	                              char **setting_name,
	                              GError **error);

	gboolean (*disconnect) (NMVPNPlugin   *plugin,
					    GError       **err);

	/* Signals */
	void (*state_changed)  (NMVPNPlugin *plugin,
					    NMVPNServiceState state);

	void (*ip4_config)     (NMVPNPlugin *plugin,
					    GHashTable  *ip4_config);

	void (*login_banner)   (NMVPNPlugin *plugin,
					    const char *banner);

	void (*failure)        (NMVPNPlugin *plugin,
					    NMVPNPluginFailure reason);

	void (*quit)           (NMVPNPlugin *plugin);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMVPNPluginClass;

GType  nm_vpn_plugin_get_type       (void);
GQuark nm_vpn_plugin_error_quark    (void);
GType  nm_vpn_plugin_error_get_type (void);

DBusGConnection   *nm_vpn_plugin_get_connection (NMVPNPlugin *plugin);
NMVPNServiceState  nm_vpn_plugin_get_state      (NMVPNPlugin *plugin);
void               nm_vpn_plugin_set_state      (NMVPNPlugin *plugin,
									    NMVPNServiceState state);

void               nm_vpn_plugin_set_login_banner (NMVPNPlugin *plugin,
										 const char *banner);

void               nm_vpn_plugin_failure        (NMVPNPlugin *plugin,
									    NMVPNPluginFailure reason);

void               nm_vpn_plugin_set_ip4_config (NMVPNPlugin *plugin,
									    GHashTable *ip4_config);

gboolean           nm_vpn_plugin_disconnect     (NMVPNPlugin *plugin,
									    GError **err);

G_END_DECLS

#endif /* NM_VPN_PLUGIN_H */
