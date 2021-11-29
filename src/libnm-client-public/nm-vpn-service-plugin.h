/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2015 Red Hat, Inc.
 */

#ifndef __NM_VPN_SERVICE_PLUGIN_H__
#define __NM_VPN_SERVICE_PLUGIN_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <gio/gio.h>
#include "nm-vpn-dbus-interface.h"
#include "nm-connection.h"

G_BEGIN_DECLS

#define NM_TYPE_VPN_SERVICE_PLUGIN (nm_vpn_service_plugin_get_type())
#define NM_VPN_SERVICE_PLUGIN(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_VPN_SERVICE_PLUGIN, NMVpnServicePlugin))
#define NM_VPN_SERVICE_PLUGIN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_VPN_SERVICE_PLUGIN, NMVpnServicePluginClass))
#define NM_IS_VPN_SERVICE_PLUGIN(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_VPN_SERVICE_PLUGIN))
#define NM_IS_VPN_SERVICE_PLUGIN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_VPN_SERVICE_PLUGIN))
#define NM_VPN_SERVICE_PLUGIN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_VPN_SERVICE_PLUGIN, NMVpnServicePluginClass))

#define NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME "service-name"
#define NM_VPN_SERVICE_PLUGIN_DBUS_WATCH_PEER   "watch-peer"
#define NM_VPN_SERVICE_PLUGIN_STATE             "state"

/**
 * NMVpnServicePlugin:
 */
typedef struct {
    NM_AVAILABLE_IN_1_2
    GObject parent;
} NMVpnServicePlugin NM_AVAILABLE_IN_1_2;

typedef struct {
    NM_AVAILABLE_IN_1_2
    GObjectClass parent;

    /* Signals */
    NM_AVAILABLE_IN_1_2
    void (*state_changed)(NMVpnServicePlugin *plugin, NMVpnServiceState state);

    NM_AVAILABLE_IN_1_2
    void (*ip4_config)(NMVpnServicePlugin *plugin, GVariant *ip4_config);

    NM_AVAILABLE_IN_1_2
    void (*login_banner)(NMVpnServicePlugin *plugin, const char *banner);

    NM_AVAILABLE_IN_1_2
    void (*failure)(NMVpnServicePlugin *plugin, NMVpnPluginFailure reason);

    NM_AVAILABLE_IN_1_2
    void (*quit)(NMVpnServicePlugin *plugin);

    NM_AVAILABLE_IN_1_2
    void (*config)(NMVpnServicePlugin *plugin, GVariant *config);

    NM_AVAILABLE_IN_1_2
    void (*ip6_config)(NMVpnServicePlugin *plugin, GVariant *config);

    /* virtual methods */
    NM_AVAILABLE_IN_1_2
    gboolean (*connect)(NMVpnServicePlugin *plugin, NMConnection *connection, GError **err);

    NM_AVAILABLE_IN_1_2
    gboolean (*need_secrets)(NMVpnServicePlugin *plugin,
                             NMConnection       *connection,
                             const char        **setting_name,
                             GError            **error);

    NM_AVAILABLE_IN_1_2
    gboolean (*disconnect)(NMVpnServicePlugin *plugin, GError **err);

    NM_AVAILABLE_IN_1_2
    gboolean (*new_secrets)(NMVpnServicePlugin *plugin, NMConnection *connection, GError **error);

    NM_AVAILABLE_IN_1_2
    gboolean (*connect_interactive)(NMVpnServicePlugin *plugin,
                                    NMConnection       *connection,
                                    GVariant           *details,
                                    GError            **error);

    /*< private >*/
    NM_AVAILABLE_IN_1_2
    gpointer padding[8];
} NMVpnServicePluginClass NM_AVAILABLE_IN_1_2;

NM_AVAILABLE_IN_1_2
GType nm_vpn_service_plugin_get_type(void);

NM_AVAILABLE_IN_1_2
GDBusConnection *nm_vpn_service_plugin_get_connection(NMVpnServicePlugin *plugin);

NM_AVAILABLE_IN_1_2
void nm_vpn_service_plugin_secrets_required(NMVpnServicePlugin *plugin,
                                            const char         *message,
                                            const char        **hints);

NM_AVAILABLE_IN_1_2
void nm_vpn_service_plugin_set_login_banner(NMVpnServicePlugin *plugin, const char *banner);

NM_AVAILABLE_IN_1_2
void nm_vpn_service_plugin_failure(NMVpnServicePlugin *plugin, NMVpnPluginFailure reason);

NM_AVAILABLE_IN_1_2
void nm_vpn_service_plugin_set_config(NMVpnServicePlugin *plugin, GVariant *config);

NM_AVAILABLE_IN_1_2
void nm_vpn_service_plugin_set_ip4_config(NMVpnServicePlugin *plugin, GVariant *ip4_config);

NM_AVAILABLE_IN_1_2
void nm_vpn_service_plugin_set_ip6_config(NMVpnServicePlugin *plugin, GVariant *ip6_config);

NM_AVAILABLE_IN_1_2
gboolean nm_vpn_service_plugin_disconnect(NMVpnServicePlugin *plugin, GError **err);

NM_AVAILABLE_IN_1_12
void nm_vpn_service_plugin_shutdown(NMVpnServicePlugin *plugin);

/* Utility functions */

NM_AVAILABLE_IN_1_2
gboolean
nm_vpn_service_plugin_read_vpn_details(int fd, GHashTable **out_data, GHashTable **out_secrets);

NM_AVAILABLE_IN_1_2
gboolean nm_vpn_service_plugin_get_secret_flags(GHashTable           *data,
                                                const char           *secret_name,
                                                NMSettingSecretFlags *out_flags);

G_END_DECLS

#endif /* __NM_VPN_SERVICE_PLUGIN_H__ */
