/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2013 Red Hat, Inc.
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
#define NM_IS_VPN_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_VPN_PLUGIN))
#define NM_VPN_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_PLUGIN, NMVPNPluginClass))

#define NM_VPN_PLUGIN_DBUS_SERVICE_NAME "service-name"
#define NM_VPN_PLUGIN_STATE             "state"

/**
 * NMVPNPluginError:
 * @NM_VPN_PLUGIN_ERROR_GENERAL: general failure
 * @NM_VPN_PLUGIN_ERROR_STARTING_IN_PROGRESS: the plugin is already starting,
 *  and another connect request was received
 * @NM_VPN_PLUGIN_ERROR_ALREADY_STARTED: the plugin is already connected, and
 *  another connect request was received
 * @NM_VPN_PLUGIN_ERROR_STOPPING_IN_PROGRESS: the plugin is already stopping,
 *  and another stop request was received
 * @NM_VPN_PLUGIN_ERROR_ALREADY_STOPPED: the plugin is already stopped, and
 *  another disconnect request was received
 * @NM_VPN_PLUGIN_ERROR_WRONG_STATE: the operation could not be performed in
 *  this state
 * @NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS: the operation could not be performed as
 *  the request contained malformed arguments, or arguments of unexpected type.
 *  Usually means that one of the VPN setting data items or secrets was not of
 *  the expected type (ie int, string, bool, etc).
 * @NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED: a child process failed to launch
 * @NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID: the operation could not be performed
 *  because the connection was invalid.  Usually means that the connection's
 *  VPN setting was missing some required data item or secret.
 * @NM_VPN_PLUGIN_ERROR_INTERACTIVE_NOT_SUPPORTED: the operation could not be
 *  performed as the plugin does not support interactive operations, such as
 *  ConnectInteractive() or NewSecrets()
 *
 * Returned by the VPN service plugin to indicate errors.
 **/
typedef enum {
	NM_VPN_PLUGIN_ERROR_GENERAL,                   /*< nick=General >*/
	NM_VPN_PLUGIN_ERROR_STARTING_IN_PROGRESS,      /*< nick=StartingInProgress >*/
	NM_VPN_PLUGIN_ERROR_ALREADY_STARTED,           /*< nick=AlreadyStarted >*/
	NM_VPN_PLUGIN_ERROR_STOPPING_IN_PROGRESS,      /*< nick=StoppingInProgress >*/
	NM_VPN_PLUGIN_ERROR_ALREADY_STOPPED,           /*< nick=AlreadyStopped >*/
	NM_VPN_PLUGIN_ERROR_WRONG_STATE,               /*< nick=WrongState >*/
	NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,             /*< nick=BadArguments >*/
	NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,             /*< nick=LaunchFailed >*/
	NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,        /*< nick=ConnectionInvalid >*/
	NM_VPN_PLUGIN_ERROR_INTERACTIVE_NOT_SUPPORTED  /*< nick=InteractiveNotSupported >*/
} NMVPNPluginError;

#define NM_VPN_PLUGIN_ERROR      (nm_vpn_plugin_error_quark ())

typedef struct {
	GObject parent;
} NMVPNPlugin;

typedef struct {
	GObjectClass parent;

	/* virtual methods */
	gboolean (*connect)      (NMVPNPlugin   *plugin,
	                          NMConnection  *connection,
	                          GError       **err);

	gboolean (*need_secrets) (NMVPNPlugin *plugin,
	                          NMConnection *connection,
	                          char **setting_name,
	                          GError **error);

	gboolean (*disconnect)   (NMVPNPlugin   *plugin,
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

	void (*config)         (NMVPNPlugin *plugin,
	                        GHashTable  *config);

	void (*ip6_config)     (NMVPNPlugin *plugin,
	                        GHashTable  *config);

	/* more methods */
	gboolean (*new_secrets)  (NMVPNPlugin *plugin,
	                          NMConnection *connection,
	                          GError **error);

	gboolean (*connect_interactive) (NMVPNPlugin *plugin,
	                                 NMConnection *connection,
	                                 GHashTable *details,
	                                 GError **error);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
} NMVPNPluginClass;

GType  nm_vpn_plugin_get_type       (void);
GQuark nm_vpn_plugin_error_quark    (void);
GType  nm_vpn_plugin_error_get_type (void);

DBusGConnection   *nm_vpn_plugin_get_connection (NMVPNPlugin *plugin);
NMVPNServiceState  nm_vpn_plugin_get_state      (NMVPNPlugin *plugin);
void               nm_vpn_plugin_set_state      (NMVPNPlugin *plugin,
                                                 NMVPNServiceState state);

NM_AVAILABLE_IN_0_9_10
void               nm_vpn_plugin_secrets_required (NMVPNPlugin *plugin,
                                                   const char *message,
                                                   const char **hints);

void               nm_vpn_plugin_set_login_banner (NMVPNPlugin *plugin,
                                                   const char *banner);

void               nm_vpn_plugin_failure        (NMVPNPlugin *plugin,
                                                 NMVPNPluginFailure reason);

void               nm_vpn_plugin_set_config     (NMVPNPlugin *plugin,
                                                 GHashTable *config);

void               nm_vpn_plugin_set_ip4_config (NMVPNPlugin *plugin,
                                                 GHashTable *ip4_config);

void               nm_vpn_plugin_set_ip6_config (NMVPNPlugin *plugin,
                                                 GHashTable *ip6_config);

gboolean           nm_vpn_plugin_disconnect     (NMVPNPlugin *plugin,
                                                 GError **err);

G_END_DECLS

#endif /* NM_VPN_PLUGIN_H */
