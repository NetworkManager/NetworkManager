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

#ifndef __NM_VPN_PLUGIN_OLD_H__
#define __NM_VPN_PLUGIN_OLD_H__

#include <gio/gio.h>
#include <nm-vpn-dbus-interface.h>
#include <nm-connection.h>

G_BEGIN_DECLS

#define NM_TYPE_VPN_PLUGIN_OLD            (nm_vpn_plugin_old_get_type ())
#define NM_VPN_PLUGIN_OLD(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_PLUGIN_OLD, NMVpnPluginOld))
#define NM_VPN_PLUGIN_OLD_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_PLUGIN_OLD, NMVpnPluginOldClass))
#define NM_IS_VPN_PLUGIN_OLD(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_PLUGIN_OLD))
#define NM_IS_VPN_PLUGIN_OLD_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_VPN_PLUGIN_OLD))
#define NM_VPN_PLUGIN_OLD_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_PLUGIN_OLD, NMVpnPluginOldClass))

#define NM_VPN_PLUGIN_OLD_DBUS_SERVICE_NAME "service-name"
#define NM_VPN_PLUGIN_OLD_STATE             "state"

typedef struct {
	NM_DEPRECATED_IN_1_2
	GObject parent;
} NMVpnPluginOld NM_DEPRECATED_IN_1_2;

typedef struct {
	NM_DEPRECATED_IN_1_2
	GObjectClass parent;

	/* Signals */
	NM_DEPRECATED_IN_1_2
	void (*state_changed)  (NMVpnPluginOld *plugin,
	                        NMVpnServiceState state);

	NM_DEPRECATED_IN_1_2
	void (*ip4_config)     (NMVpnPluginOld *plugin,
	                        GVariant  *ip4_config);

	NM_DEPRECATED_IN_1_2
	void (*login_banner)   (NMVpnPluginOld *plugin,
	                        const char *banner);

	NM_DEPRECATED_IN_1_2
	void (*failure)        (NMVpnPluginOld *plugin,
	                        NMVpnPluginFailure reason);

	NM_DEPRECATED_IN_1_2
	void (*quit)           (NMVpnPluginOld *plugin);

	NM_DEPRECATED_IN_1_2
	void (*config)         (NMVpnPluginOld *plugin,
	                        GVariant  *config);

	NM_DEPRECATED_IN_1_2
	void (*ip6_config)     (NMVpnPluginOld *plugin,
	                        GVariant  *config);

	/* virtual methods */
	NM_DEPRECATED_IN_1_2
	gboolean (*connect)      (NMVpnPluginOld   *plugin,
	                          NMConnection  *connection,
	                          GError       **err);

	NM_DEPRECATED_IN_1_2
	gboolean (*need_secrets) (NMVpnPluginOld *plugin,
	                          NMConnection *connection,
	                          const char **setting_name,
	                          GError **error);

	NM_DEPRECATED_IN_1_2
	gboolean (*disconnect)   (NMVpnPluginOld   *plugin,
	                          GError       **err);

	NM_DEPRECATED_IN_1_2
	gboolean (*new_secrets)  (NMVpnPluginOld *plugin,
	                          NMConnection *connection,
	                          GError **error);

	NM_DEPRECATED_IN_1_2
	gboolean (*connect_interactive) (NMVpnPluginOld *plugin,
	                                 NMConnection *connection,
	                                 GVariant *details,
	                                 GError **error);

	/*< private >*/
	NM_DEPRECATED_IN_1_2
	gpointer padding[8];
} NMVpnPluginOldClass NM_DEPRECATED_IN_1_2;

NM_DEPRECATED_IN_1_2
GType  nm_vpn_plugin_old_get_type       (void);

NM_DEPRECATED_IN_1_2
GDBusConnection   *nm_vpn_plugin_old_get_connection (NMVpnPluginOld *plugin);
NM_DEPRECATED_IN_1_2
NMVpnServiceState  nm_vpn_plugin_old_get_state      (NMVpnPluginOld *plugin);
NM_DEPRECATED_IN_1_2
void               nm_vpn_plugin_old_set_state      (NMVpnPluginOld *plugin,
                                                     NMVpnServiceState state);

NM_DEPRECATED_IN_1_2
void               nm_vpn_plugin_old_secrets_required (NMVpnPluginOld *plugin,
                                                       const char *message,
                                                       const char **hints);

NM_DEPRECATED_IN_1_2
void               nm_vpn_plugin_old_set_login_banner (NMVpnPluginOld *plugin,
                                                       const char *banner);

NM_DEPRECATED_IN_1_2
void               nm_vpn_plugin_old_failure        (NMVpnPluginOld *plugin,
                                                     NMVpnPluginFailure reason);

NM_DEPRECATED_IN_1_2
void               nm_vpn_plugin_old_set_config     (NMVpnPluginOld *plugin,
                                                     GVariant *config);

NM_DEPRECATED_IN_1_2
void               nm_vpn_plugin_old_set_ip4_config (NMVpnPluginOld *plugin,
                                                     GVariant *ip4_config);

NM_DEPRECATED_IN_1_2
void               nm_vpn_plugin_old_set_ip6_config (NMVpnPluginOld *plugin,
                                                     GVariant *ip6_config);

NM_DEPRECATED_IN_1_2
gboolean           nm_vpn_plugin_old_disconnect     (NMVpnPluginOld *plugin,
                                                     GError **err);

/* Utility functions */

NM_DEPRECATED_IN_1_2
gboolean nm_vpn_plugin_old_read_vpn_details (int fd,
                                             GHashTable **out_data,
                                             GHashTable **out_secrets);

NM_DEPRECATED_IN_1_2
gboolean nm_vpn_plugin_old_get_secret_flags (GHashTable *data,
                                             const char *secret_name,
                                             NMSettingSecretFlags *out_flags);

G_END_DECLS

#endif /* __NM_VPN_PLUGIN_OLD_H__ */
