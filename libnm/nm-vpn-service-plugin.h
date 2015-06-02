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
 * Copyright 2007 - 2015 Red Hat, Inc.
 */

#ifndef __NM_VPN_SERVICE_PLUGIN_H__
#define __NM_VPN_SERVICE_PLUGIN_H__

#include <gio/gio.h>
#include <nm-vpn-dbus-interface.h>
#include <nm-connection.h>

G_BEGIN_DECLS

#define NM_TYPE_VPN_SERVICE_PLUGIN            (nm_vpn_service_plugin_get_type ())
#define NM_VPN_SERVICE_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_SERVICE_PLUGIN, NMVpnServicePlugin))
#define NM_VPN_SERVICE_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_SERVICE_PLUGIN, NMVpnServicePluginClass))
#define NM_IS_VPN_SERVICE_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_SERVICE_PLUGIN))
#define NM_IS_VPN_SERVICE_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_VPN_SERVICE_PLUGIN))
#define NM_VPN_SERVICE_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_SERVICE_PLUGIN, NMVpnServicePluginClass))

#define NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME "service-name"
#define NM_VPN_SERVICE_PLUGIN_STATE             "state"

typedef struct {
	GObject parent;
} NMVpnServicePlugin;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*state_changed)  (NMVpnServicePlugin *plugin,
	                        NMVpnServiceState state);

	void (*ip4_config)     (NMVpnServicePlugin *plugin,
	                        GVariant  *ip4_config);

	void (*login_banner)   (NMVpnServicePlugin *plugin,
	                        const char *banner);

	void (*failure)        (NMVpnServicePlugin *plugin,
	                        NMVpnPluginFailure reason);

	void (*quit)           (NMVpnServicePlugin *plugin);

	void (*config)         (NMVpnServicePlugin *plugin,
	                        GVariant  *config);

	void (*ip6_config)     (NMVpnServicePlugin *plugin,
	                        GVariant  *config);

	/* virtual methods */
	gboolean (*connect)      (NMVpnServicePlugin   *plugin,
	                          NMConnection  *connection,
	                          GError       **err);

	gboolean (*need_secrets) (NMVpnServicePlugin *plugin,
	                          NMConnection *connection,
	                          const char **setting_name,
	                          GError **error);

	gboolean (*disconnect)   (NMVpnServicePlugin   *plugin,
	                          GError       **err);

	gboolean (*new_secrets)  (NMVpnServicePlugin *plugin,
	                          NMConnection *connection,
	                          GError **error);

	gboolean (*connect_interactive) (NMVpnServicePlugin *plugin,
	                                 NMConnection *connection,
	                                 GVariant *details,
	                                 GError **error);

	/*< private >*/
	gpointer padding[8];
} NMVpnServicePluginClass;

GType  nm_vpn_service_plugin_get_type       (void);

GDBusConnection   *nm_vpn_service_plugin_get_connection (NMVpnServicePlugin *plugin);
NMVpnServiceState  nm_vpn_service_plugin_get_state      (NMVpnServicePlugin *plugin);
void               nm_vpn_service_plugin_set_state      (NMVpnServicePlugin *plugin,
                                                         NMVpnServiceState state);

void               nm_vpn_service_plugin_secrets_required (NMVpnServicePlugin *plugin,
                                                           const char *message,
                                                           const char **hints);

void               nm_vpn_service_plugin_set_login_banner (NMVpnServicePlugin *plugin,
                                                           const char *banner);

void               nm_vpn_service_plugin_failure        (NMVpnServicePlugin *plugin,
                                                         NMVpnPluginFailure reason);

void               nm_vpn_service_plugin_set_config     (NMVpnServicePlugin *plugin,
                                                         GVariant *config);

void               nm_vpn_service_plugin_set_ip4_config (NMVpnServicePlugin *plugin,
                                                         GVariant *ip4_config);

void               nm_vpn_service_plugin_set_ip6_config (NMVpnServicePlugin *plugin,
                                                         GVariant *ip6_config);

gboolean           nm_vpn_service_plugin_disconnect     (NMVpnServicePlugin *plugin,
                                                         GError **err);

/* Utility functions */

gboolean nm_vpn_service_plugin_read_vpn_details (int fd,
                                                 GHashTable **out_data,
                                                 GHashTable **out_secrets);

gboolean nm_vpn_service_plugin_get_secret_flags (GHashTable *data,
                                                 const char *secret_name,
                                                 NMSettingSecretFlags *out_flags);

G_END_DECLS

#endif /* __NM_VPN_SERVICE_PLUGIN_H__ */
