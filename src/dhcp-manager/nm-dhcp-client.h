/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 */

#ifndef NM_DHCP_CLIENT_H
#define NM_DHCP_CLIENT_H

#include <glib.h>
#include <glib-object.h>

#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-ip4-config.h>
#include <nm-ip6-config.h>

#define NM_TYPE_DHCP_CLIENT            (nm_dhcp_client_get_type ())
#define NM_DHCP_CLIENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_CLIENT, NMDHCPClient))
#define NM_DHCP_CLIENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_CLIENT, NMDHCPClientClass))
#define NM_IS_DHCP_CLIENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_CLIENT))
#define NM_IS_DHCP_CLIENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP_CLIENT))
#define NM_DHCP_CLIENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_CLIENT, NMDHCPClientClass))

#define NM_DHCP_CLIENT_INTERFACE "iface"
#define NM_DHCP_CLIENT_HWADDR    "hwaddr"
#define NM_DHCP_CLIENT_IPV6      "ipv6"
#define NM_DHCP_CLIENT_UUID      "uuid"
#define NM_DHCP_CLIENT_PRIORITY  "priority"
#define NM_DHCP_CLIENT_TIMEOUT   "timeout"

#define NM_DHCP_CLIENT_SIGNAL_TIMEOUT       "timeout"
#define NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED "state-changed"
#define NM_DHCP_CLIENT_SIGNAL_REMOVE        "remove"

typedef enum {
	DHC_NBI = 0,     /* no broadcast interfaces found */
	DHC_PREINIT,     /* configuration started */
	DHC_PREINIT6,    /* configuration started */
	DHC_BOUND4,      /* IPv4 lease obtained */
	DHC_BOUND6,      /* IPv6 lease obtained */
	DHC_IPV4LL,      /* IPv4LL address obtained */
	DHC_RENEW4,      /* IPv4 lease renewed */
	DHC_RENEW6,      /* IPv6 lease renewed */
	DHC_REBOOT,      /* have valid lease, but now obtained a different one */
	DHC_REBIND4,     /* IPv4 new/different lease */
	DHC_REBIND6,     /* IPv6 new/different lease */
	DHC_DEPREF6,     /* IPv6 lease depreferred */
	DHC_STOP,        /* remove old lease */
	DHC_STOP6,       /* remove old lease */
	DHC_MEDIUM,      /* media selection begun */
	DHC_TIMEOUT,     /* timed out contacting DHCP server */
	DHC_FAIL,        /* all attempts to contact server timed out, sleeping */
	DHC_EXPIRE,      /* lease has expired, renewing */
	DHC_EXPIRE6,     /* lease has expired, renewing */
	DHC_RELEASE,     /* releasing lease */
	DHC_RELEASE6,    /* releasing lease */
	DHC_START,       /* sent when dhclient started OK */
	DHC_ABEND,       /* dhclient exited abnormally */
	DHC_END,         /* dhclient exited normally */
	DHC_END_OPTIONS, /* last option in subscription sent */
} NMDHCPState;

typedef struct {
	GObject parent;
} NMDHCPClient;

typedef struct {
	GObjectClass parent;

	/* Methods */

	GPid (*ip4_start)     (NMDHCPClient *self,
	                       const char *dhcp_client_id,
	                       GByteArray *anycast_addr,
	                       const char *hostname);

	GPid (*ip6_start)     (NMDHCPClient *self,
	                       GByteArray *anycast_addr,
	                       const char *hostname,
	                       gboolean info_only,
	                       const GByteArray *duid);

	void (*stop)          (NMDHCPClient *self,
	                       gboolean release,
	                       const GByteArray *duid);

	/**
	 * get_duid:
	 * @self: the #NMDHCPClient
	 *
	 * Attempts to find an existing DHCPv6 DUID for this client in the DHCP
	 * client's persistent configuration.  Returned DUID should be the binary
	 * representation of the DUID.  If no DUID is found, %NULL should be
	 * returned.
	 */
	GByteArray * (*get_duid) (NMDHCPClient *self);

	/* Signals */
	void (*state_changed) (NMDHCPClient *self, NMDHCPState state);
	void (*timeout)       (NMDHCPClient *self);
	void (*remove)        (NMDHCPClient *self);
} NMDHCPClientClass;

GType nm_dhcp_client_get_type (void);

GPid nm_dhcp_client_get_pid (NMDHCPClient *self);

const char *nm_dhcp_client_get_iface (NMDHCPClient *self);

gboolean nm_dhcp_client_get_ipv6 (NMDHCPClient *self);

const char *nm_dhcp_client_get_uuid (NMDHCPClient *self);

gboolean nm_dhcp_client_start_ip4 (NMDHCPClient *self,
                                   const char *dhcp_client_id,
                                   GByteArray *dhcp_anycast_addr,
                                   const char *hostname);

gboolean nm_dhcp_client_start_ip6 (NMDHCPClient *self,
                                   GByteArray *dhcp_anycast_addr,
                                   const char *hostname,
                                   gboolean info_only);

void nm_dhcp_client_stop (NMDHCPClient *self, gboolean release);

void nm_dhcp_client_new_options (NMDHCPClient *self,
                                 GHashTable *options,
                                 const char *reason);

gboolean nm_dhcp_client_foreach_option (NMDHCPClient *self,
                                        GHFunc func,
                                        gpointer user_data);

NMIP4Config *nm_dhcp_client_get_ip4_config   (NMDHCPClient *self, gboolean test);

NMIP6Config *nm_dhcp_client_get_ip6_config   (NMDHCPClient *self, gboolean test);

/* Backend helpers */
void nm_dhcp_client_stop_existing (const char *pid_file, const char *binary_name);

void nm_dhcp_client_stop_pid (GPid pid, const char *iface);

#endif /* NM_DHCP_CLIENT_H */

