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
#define NM_VPN_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_PLUGIN, NMVpnPlugin))
#define NM_VPN_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_PLUGIN, NMVpnPluginClass))
#define NM_IS_VPN_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_PLUGIN))
#define NM_IS_VPN_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_VPN_PLUGIN))
#define NM_VPN_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_PLUGIN, NMVpnPluginClass))

#define NM_VPN_PLUGIN_DBUS_SERVICE_NAME "service-name"
#define NM_VPN_PLUGIN_STATE             "state"

/**
 * NMVpnPluginError:
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
} NMVpnPluginError;

#define NM_VPN_PLUGIN_ERROR      (nm_vpn_plugin_error_quark ())

typedef struct {
	GObject parent;
} NMVpnPlugin;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*state_changed)  (NMVpnPlugin *plugin,
	                        NMVpnServiceState state);

	void (*ip4_config)     (NMVpnPlugin *plugin,
	                        GHashTable  *ip4_config);

	void (*login_banner)   (NMVpnPlugin *plugin,
	                        const char *banner);

	void (*failure)        (NMVpnPlugin *plugin,
	                        NMVpnPluginFailure reason);

	void (*quit)           (NMVpnPlugin *plugin);

	void (*config)         (NMVpnPlugin *plugin,
	                        GHashTable  *config);

	void (*ip6_config)     (NMVpnPlugin *plugin,
	                        GHashTable  *config);

	/* virtual methods */
	gboolean (*connect)      (NMVpnPlugin   *plugin,
	                          NMConnection  *connection,
	                          GError       **err);

	gboolean (*need_secrets) (NMVpnPlugin *plugin,
	                          NMConnection *connection,
	                          char **setting_name,
	                          GError **error);

	gboolean (*disconnect)   (NMVpnPlugin   *plugin,
	                          GError       **err);

	gboolean (*new_secrets)  (NMVpnPlugin *plugin,
	                          NMConnection *connection,
	                          GError **error);

	gboolean (*connect_interactive) (NMVpnPlugin *plugin,
	                                 NMConnection *connection,
	                                 GHashTable *details,
	                                 GError **error);

	/*< private >*/
	gpointer padding[8];
} NMVpnPluginClass;

GType  nm_vpn_plugin_get_type       (void);
GQuark nm_vpn_plugin_error_quark    (void);
GType  nm_vpn_plugin_error_get_type (void);

DBusGConnection   *nm_vpn_plugin_get_connection (NMVpnPlugin *plugin);
NMVpnServiceState  nm_vpn_plugin_get_state      (NMVpnPlugin *plugin);
void               nm_vpn_plugin_set_state      (NMVpnPlugin *plugin,
                                                 NMVpnServiceState state);

void               nm_vpn_plugin_secrets_required (NMVpnPlugin *plugin,
                                                   const char *message,
                                                   const char **hints);

void               nm_vpn_plugin_set_login_banner (NMVpnPlugin *plugin,
                                                   const char *banner);

void               nm_vpn_plugin_failure        (NMVpnPlugin *plugin,
                                                 NMVpnPluginFailure reason);

void               nm_vpn_plugin_set_config     (NMVpnPlugin *plugin,
                                                 GHashTable *config);

void               nm_vpn_plugin_set_ip4_config (NMVpnPlugin *plugin,
                                                 GHashTable *ip4_config);

void               nm_vpn_plugin_set_ip6_config (NMVpnPlugin *plugin,
                                                 GHashTable *ip6_config);

gboolean           nm_vpn_plugin_disconnect     (NMVpnPlugin *plugin,
                                                 GError **err);

G_END_DECLS

#endif /* NM_VPN_PLUGIN_H */
