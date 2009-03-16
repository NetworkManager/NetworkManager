/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-dhcp-manager.c - Handle the DHCP daemon for NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2005 - 2008 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef NM_DHCP_MANAGER_H
#define NM_DHCP_MANAGER_H

#include <glib.h>
#include <glib-object.h>

#include <nm-setting-ip4-config.h>

#include "nm-ip4-config.h"
#include "nm-dhcp4-config.h"
#include "nm-hostname-provider.h"

#define NM_DHCP_MANAGER_RUN_DIR		LOCALSTATEDIR "/run"

#define NM_TYPE_DHCP_MANAGER            (nm_dhcp_manager_get_type ())
#define NM_DHCP_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_MANAGER, NMDHCPManager))
#define NM_DHCP_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_MANAGER, NMDHCPManagerClass))
#define NM_IS_DHCP_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_MANAGER))
#define NM_IS_DHCP_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DHCP_MANAGER))
#define NM_DHCP_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_MANAGER, NMDHCPManagerClass))

typedef enum {
	DHC_NBI=0,		/* no broadcast interfaces found */
	DHC_PREINIT,		/* configuration started */
	DHC_BOUND,		/* lease obtained */
	DHC_IPV4LL,		/* IPv4LL address obtained */
	DHC_RENEW,		/* lease renewed */
	DHC_REBOOT,		/* have valid lease, but now obtained a different one */
	DHC_REBIND,		/* new, different lease */
	DHC_STOP,		/* remove old lease */
	DHC_MEDIUM,		/* media selection begun */
	DHC_TIMEOUT,		/* timed out contacting DHCP server */
	DHC_FAIL,		/* all attempts to contact server timed out, sleeping */
	DHC_EXPIRE,		/* lease has expired, renewing */
	DHC_RELEASE,		/* releasing lease */
	DHC_START,		/* sent when dhclient started OK */
	DHC_ABEND,		/* dhclient exited abnormally */
	DHC_END,		/* dhclient exited normally */
	DHC_END_OPTIONS,	/* last option in subscription sent */
} NMDHCPState;

typedef struct {
	GObject parent;
} NMDHCPManager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*state_changed) (NMDHCPManager *manager, char *iface, NMDHCPState state);
	void (*timeout)       (NMDHCPManager *manager, char *iface);
} NMDHCPManagerClass;

typedef struct {
        char *			iface;
        guchar			state;
        GPid			pid;
        char *			pid_file;
        char *			conf_file;
        char *			lease_file;
        guint			timeout_id;
        guint			watch_id;
        NMDHCPManager *		manager;
        GHashTable *		options;
} NMDHCPDevice;

GType nm_dhcp_manager_get_type (void);

NMDHCPManager *nm_dhcp_manager_get                  (void);
void           nm_dhcp_manager_set_hostname_provider(NMDHCPManager *manager,
													 NMHostnameProvider *provider);

gboolean       nm_dhcp_manager_begin_transaction    (NMDHCPManager *manager,
                                                     const char *iface,
                                                     NMSettingIP4Config *s_ip4,
                                                     guint32 timeout);
void           nm_dhcp_manager_cancel_transaction   (NMDHCPManager *manager,
                                                     const char *iface);
NMIP4Config *  nm_dhcp_manager_get_ip4_config       (NMDHCPManager *manager, const char *iface);
NMDHCPState    nm_dhcp_manager_get_state_for_device (NMDHCPManager *manager, const char *iface);

gboolean       nm_dhcp_manager_foreach_dhcp4_option (NMDHCPManager *self,
                                                     const char *iface,
                                                     GHFunc func,
                                                     gpointer user_data);

/* The following are implemented by the DHCP client backends */
GPid           nm_dhcp_client_start                 (NMDHCPDevice *device, NMSettingIP4Config *s_ip4);
void           nm_dhcp_client_stop                  (NMDHCPDevice *device, pid_t pid);

gboolean       nm_dhcp_client_process_classless_routes (GHashTable *options,
                                                        NMIP4Config *ip4_config,
                                                        guint32 *gwaddr);

/* Test functions */
NMIP4Config *nm_dhcp_manager_options_to_ip4_config (const char *iface,
                                                    GHashTable *options);

#endif /* NM_DHCP_MANAGER_H */
