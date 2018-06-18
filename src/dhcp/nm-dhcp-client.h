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

#ifndef __NETWORKMANAGER_DHCP_CLIENT_H__
#define __NETWORKMANAGER_DHCP_CLIENT_H__

#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-dhcp-utils.h"

#define NM_DHCP_TIMEOUT_DEFAULT ((guint32) 45) /* default DHCP timeout, in seconds */
#define NM_DHCP_TIMEOUT_INFINITY G_MAXINT32

#define NM_TYPE_DHCP_CLIENT            (nm_dhcp_client_get_type ())
#define NM_DHCP_CLIENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_CLIENT, NMDhcpClient))
#define NM_DHCP_CLIENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_CLIENT, NMDhcpClientClass))
#define NM_IS_DHCP_CLIENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_CLIENT))
#define NM_IS_DHCP_CLIENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP_CLIENT))
#define NM_DHCP_CLIENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_CLIENT, NMDhcpClientClass))

#define NM_DHCP_CLIENT_ADDR_FAMILY  "addr-family"
#define NM_DHCP_CLIENT_FLAGS        "flags"
#define NM_DHCP_CLIENT_HWADDR       "hwaddr"
#define NM_DHCP_CLIENT_IFINDEX      "ifindex"
#define NM_DHCP_CLIENT_INTERFACE    "iface"
#define NM_DHCP_CLIENT_MULTI_IDX    "multi-idx"
#define NM_DHCP_CLIENT_ROUTE_METRIC "route-metric"
#define NM_DHCP_CLIENT_ROUTE_TABLE  "route-table"
#define NM_DHCP_CLIENT_TIMEOUT      "timeout"
#define NM_DHCP_CLIENT_UUID         "uuid"

#define NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED "state-changed"
#define NM_DHCP_CLIENT_SIGNAL_PREFIX_DELEGATED "prefix-delegated"

typedef enum {
	NM_DHCP_STATE_UNKNOWN = 0,
	NM_DHCP_STATE_BOUND,        /* new lease or lease changed */
	NM_DHCP_STATE_TIMEOUT,      /* timed out contacting server */
	NM_DHCP_STATE_DONE,         /* client quit or stopped */
	NM_DHCP_STATE_EXPIRE,       /* lease expired or NAKed */
	NM_DHCP_STATE_FAIL,         /* failed for some reason */
	__NM_DHCP_STATE_MAX,
	NM_DHCP_STATE_MAX = __NM_DHCP_STATE_MAX - 1,
} NMDhcpState;

struct _NMDhcpClientPrivate;

typedef struct {
	GObject parent;
	struct _NMDhcpClientPrivate *_priv;
	CList dhcp_client_lst;
} NMDhcpClient;

typedef enum {
	NM_DHCP_CLIENT_FLAGS_INFO_ONLY = (1LL <<  0),
	NM_DHCP_CLIENT_FLAGS_USE_FQDN  = (1LL <<  1),
} NMDhcpClientFlags;

typedef struct {
	GObjectClass parent;

	/* Methods */

	gboolean (*ip4_start)     (NMDhcpClient *self,
	                           const char *anycast_addr,
	                           const char *last_ip4_address);

	gboolean (*ip6_start)     (NMDhcpClient *self,
	                           const char *anycast_addr,
	                           const struct in6_addr *ll_addr,
	                           NMSettingIP6ConfigPrivacy privacy,
	                           GBytes *duid,
	                           guint needed_prefixes);

	void (*stop)              (NMDhcpClient *self,
	                           gboolean release,
	                           GBytes *duid);

	/**
	 * get_duid:
	 * @self: the #NMDhcpClient
	 *
	 * Attempts to find an existing DHCPv6 DUID for this client in the DHCP
	 * client's persistent configuration.  Returned DUID should be the binary
	 * representation of the DUID.  If no DUID is found, %NULL should be
	 * returned.
	 */
	GBytes *(*get_duid) (NMDhcpClient *self);

	/* Signals */
	void (*state_changed) (NMDhcpClient *self,
	                       NMDhcpState state,
	                       GObject *ip_config,
	                       GHashTable *options);
} NMDhcpClientClass;

GType nm_dhcp_client_get_type (void);

struct _NMDedupMultiIndex *nm_dhcp_client_get_multi_idx (NMDhcpClient *self);

pid_t nm_dhcp_client_get_pid (NMDhcpClient *self);

int nm_dhcp_client_get_addr_family (NMDhcpClient *self);

const char *nm_dhcp_client_get_iface (NMDhcpClient *self);

int         nm_dhcp_client_get_ifindex (NMDhcpClient *self);

const char *nm_dhcp_client_get_uuid (NMDhcpClient *self);

GBytes *nm_dhcp_client_get_duid (NMDhcpClient *self);

GBytes *nm_dhcp_client_get_hw_addr (NMDhcpClient *self);

guint32 nm_dhcp_client_get_route_table (NMDhcpClient *self);

guint32 nm_dhcp_client_get_route_metric (NMDhcpClient *self);

guint32 nm_dhcp_client_get_timeout (NMDhcpClient *self);

GBytes *nm_dhcp_client_get_client_id (NMDhcpClient *self);

const char *nm_dhcp_client_get_hostname (NMDhcpClient *self);

gboolean nm_dhcp_client_get_info_only (NMDhcpClient *self);

gboolean nm_dhcp_client_get_use_fqdn (NMDhcpClient *self);

gboolean nm_dhcp_client_start_ip4 (NMDhcpClient *self,
                                   GBytes *client_id,
                                   const char *dhcp_anycast_addr,
                                   const char *hostname,
                                   const char *last_ip4_address);

gboolean nm_dhcp_client_start_ip6 (NMDhcpClient *self,
                                   GBytes *client_id,
                                   gboolean enforce_duid,
                                   const char *dhcp_anycast_addr,
                                   const struct in6_addr *ll_addr,
                                   const char *hostname,
                                   NMSettingIP6ConfigPrivacy privacy,
                                   guint needed_prefixes);

void nm_dhcp_client_stop (NMDhcpClient *self, gboolean release);

/* Backend helpers for subclasses */
void nm_dhcp_client_stop_existing (const char *pid_file, const char *binary_name);

void nm_dhcp_client_stop_pid (pid_t pid, const char *iface);

void nm_dhcp_client_start_timeout (NMDhcpClient *self);

void nm_dhcp_client_watch_child (NMDhcpClient *self, pid_t pid);

void nm_dhcp_client_set_state (NMDhcpClient *self,
                               NMDhcpState new_state,
                               NMIPConfig *ip_config,
                               GHashTable *options); /* str:str hash */

gboolean nm_dhcp_client_handle_event (gpointer unused,
                                      const char *iface,
                                      gint pid,
                                      GVariant *options,
                                      const char *reason,
                                      NMDhcpClient *self);

void nm_dhcp_client_set_client_id (NMDhcpClient *self,
                                   GBytes *client_id);
void nm_dhcp_client_set_client_id_bin (NMDhcpClient *self,
                                       guint8 type,
                                       const guint8 *client_id,
                                       gsize len);

/*****************************************************************************
 * Client data
 *****************************************************************************/

typedef struct {
	GType (*get_type)(void);
	const char *name;
	const char *(*get_path) (void);
} NMDhcpClientFactory;

extern const NMDhcpClientFactory _nm_dhcp_client_factory_dhcpcanon;
extern const NMDhcpClientFactory _nm_dhcp_client_factory_dhclient;
extern const NMDhcpClientFactory _nm_dhcp_client_factory_dhcpcd;
extern const NMDhcpClientFactory _nm_dhcp_client_factory_internal;

#endif /* __NETWORKMANAGER_DHCP_CLIENT_H__ */
