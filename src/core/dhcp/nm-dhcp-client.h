/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP_CLIENT_H__
#define __NETWORKMANAGER_DHCP_CLIENT_H__

#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-dhcp-utils.h"

#define NM_DHCP_TIMEOUT_DEFAULT  ((guint32) 45) /* default DHCP timeout, in seconds */
#define NM_DHCP_TIMEOUT_INFINITY ((guint32) G_MAXINT32)

#define NM_TYPE_DHCP_CLIENT (nm_dhcp_client_get_type())
#define NM_DHCP_CLIENT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DHCP_CLIENT, NMDhcpClient))
#define NM_DHCP_CLIENT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DHCP_CLIENT, NMDhcpClientClass))
#define NM_IS_DHCP_CLIENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DHCP_CLIENT))
#define NM_IS_DHCP_CLIENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DHCP_CLIENT))
#define NM_DHCP_CLIENT_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DHCP_CLIENT, NMDhcpClientClass))

#define NM_DHCP_CLIENT_ADDR_FAMILY             "addr-family"
#define NM_DHCP_CLIENT_ANYCAST_ADDRESS         "anycast-address"
#define NM_DHCP_CLIENT_FLAGS                   "flags"
#define NM_DHCP_CLIENT_HWADDR                  "hwaddr"
#define NM_DHCP_CLIENT_BROADCAST_HWADDR        "broadcast-hwaddr"
#define NM_DHCP_CLIENT_IFINDEX                 "ifindex"
#define NM_DHCP_CLIENT_INTERFACE               "iface"
#define NM_DHCP_CLIENT_MULTI_IDX               "multi-idx"
#define NM_DHCP_CLIENT_HOSTNAME                "hostname"
#define NM_DHCP_CLIENT_MUD_URL                 "mud-url"
#define NM_DHCP_CLIENT_ROUTE_METRIC            "route-metric"
#define NM_DHCP_CLIENT_ROUTE_TABLE             "route-table"
#define NM_DHCP_CLIENT_TIMEOUT                 "timeout"
#define NM_DHCP_CLIENT_UUID                    "uuid"
#define NM_DHCP_CLIENT_IAID                    "iaid"
#define NM_DHCP_CLIENT_IAID_EXPLICIT           "iaid-explicit"
#define NM_DHCP_CLIENT_HOSTNAME_FLAGS          "hostname-flags"
#define NM_DHCP_CLIENT_VENDOR_CLASS_IDENTIFIER "vendor-class-identifier"
#define NM_DHCP_CLIENT_REJECT_SERVERS          "reject-servers"

#define NM_DHCP_CLIENT_NOTIFY "dhcp-notify"

typedef enum {
    NM_DHCP_STATE_UNKNOWN = 0,
    NM_DHCP_STATE_BOUND,      /* new lease */
    NM_DHCP_STATE_EXTENDED,   /* lease extended */
    NM_DHCP_STATE_TIMEOUT,    /* timed out contacting server */
    NM_DHCP_STATE_DONE,       /* client reported it's stopping */
    NM_DHCP_STATE_EXPIRE,     /* lease expired or NAKed */
    NM_DHCP_STATE_FAIL,       /* failed for some reason */
    NM_DHCP_STATE_TERMINATED, /* client is no longer running */
    NM_DHCP_STATE_NOOP,       /* state is a non operation for NetworkManager */
} NMDhcpState;

typedef enum _nm_packed {
    NM_DHCP_CLIENT_NOTIFY_TYPE_STATE_CHANGED,
    NM_DHCP_CLIENT_NOTIFY_TYPE_PREFIX_DELEGATED,
} NMDhcpClientNotifyType;

typedef struct {
    NMDhcpClientNotifyType notify_type;
    union {
        struct {
            NMIPConfig *ip_config;
            GHashTable *options;
            NMDhcpState dhcp_state;
        } state_changed;
        struct {
            const NMPlatformIP6Address *prefix;
        } prefix_delegated;
    };
} NMDhcpClientNotifyData;

const char *nm_dhcp_state_to_string(NMDhcpState state);

struct _NMDhcpClientPrivate;

typedef struct {
    GObject                      parent;
    struct _NMDhcpClientPrivate *_priv;
} NMDhcpClient;

typedef enum _nm_packed {
    NM_DHCP_CLIENT_FLAGS_NONE = 0,

    NM_DHCP_CLIENT_FLAGS_INFO_ONLY         = (1LL << 0),
    NM_DHCP_CLIENT_FLAGS_USE_FQDN          = (1LL << 1),
    NM_DHCP_CLIENT_FLAGS_REQUEST_BROADCAST = (1LL << 2),

    _NM_DHCP_CLIENT_FLAGS_LAST,
    NM_DHCP_CLIENT_FLAGS_ALL = ((_NM_DHCP_CLIENT_FLAGS_LAST - 1) << 1) - 1,
} NMDhcpClientFlags;

typedef struct {
    GObjectClass parent;

    gboolean (*ip4_start)(NMDhcpClient *self, const char *last_ip4_address, GError **error);

    gboolean (*accept)(NMDhcpClient *self, GError **error);

    gboolean (*decline)(NMDhcpClient *self, const char *error_message, GError **error);

    gboolean (*ip6_start)(NMDhcpClient *            self,
                          const struct in6_addr *   ll_addr,
                          NMSettingIP6ConfigPrivacy privacy,
                          guint                     needed_prefixes,
                          GError **                 error);

    void (*stop)(NMDhcpClient *self, gboolean release);

    /**
     * get_duid:
     * @self: the #NMDhcpClient
     *
     * Attempts to find an existing DHCPv6 DUID for this client in the DHCP
     * client's persistent configuration.  Returned DUID should be the binary
     * representation of the DUID.  If no DUID is found, %NULL should be
     * returned.
     */
    GBytes *(*get_duid)(NMDhcpClient *self);
} NMDhcpClientClass;

GType nm_dhcp_client_get_type(void);

struct _NMDedupMultiIndex *nm_dhcp_client_get_multi_idx(NMDhcpClient *self);

pid_t nm_dhcp_client_get_pid(NMDhcpClient *self);

int nm_dhcp_client_get_addr_family(NMDhcpClient *self);

const char *nm_dhcp_client_get_iface(NMDhcpClient *self);

int nm_dhcp_client_get_ifindex(NMDhcpClient *self);

const char *nm_dhcp_client_get_uuid(NMDhcpClient *self);

GBytes *nm_dhcp_client_get_duid(NMDhcpClient *self);

GBytes *nm_dhcp_client_get_hw_addr(NMDhcpClient *self);

GBytes *nm_dhcp_client_get_broadcast_hw_addr(NMDhcpClient *self);

const char *nm_dhcp_client_get_anycast_address(NMDhcpClient *self);

guint32 nm_dhcp_client_get_route_table(NMDhcpClient *self);

void nm_dhcp_client_set_route_table(NMDhcpClient *self, guint32 route_table);

guint32 nm_dhcp_client_get_route_metric(NMDhcpClient *self);

void nm_dhcp_client_set_route_metric(NMDhcpClient *self, guint32 route_metric);

guint32 nm_dhcp_client_get_timeout(NMDhcpClient *self);

guint32 nm_dhcp_client_get_iaid(NMDhcpClient *self);

gboolean nm_dhcp_client_get_iaid_explicit(NMDhcpClient *self);

GBytes *nm_dhcp_client_get_client_id(NMDhcpClient *self);

const char *       nm_dhcp_client_get_hostname(NMDhcpClient *self);
const char *       nm_dhcp_client_get_mud_url(NMDhcpClient *self);
const char *const *nm_dhcp_client_get_reject_servers(NMDhcpClient *self);

NMDhcpHostnameFlags nm_dhcp_client_get_hostname_flags(NMDhcpClient *self);

NMDhcpClientFlags nm_dhcp_client_get_client_flags(NMDhcpClient *self);

GBytes *nm_dhcp_client_get_vendor_class_identifier(NMDhcpClient *self);

gboolean nm_dhcp_client_start_ip4(NMDhcpClient *self,
                                  GBytes *      client_id,
                                  const char *  last_ip4_address,
                                  GError **     error);

gboolean nm_dhcp_client_start_ip6(NMDhcpClient *            self,
                                  GBytes *                  client_id,
                                  gboolean                  enforce_duid,
                                  const struct in6_addr *   ll_addr,
                                  NMSettingIP6ConfigPrivacy privacy,
                                  guint                     needed_prefixes,
                                  GError **                 error);

gboolean nm_dhcp_client_accept(NMDhcpClient *self, GError **error);
gboolean nm_dhcp_client_can_accept(NMDhcpClient *self);

gboolean nm_dhcp_client_decline(NMDhcpClient *self, const char *error_message, GError **error);

void nm_dhcp_client_stop(NMDhcpClient *self, gboolean release);

/* Backend helpers for subclasses */
void nm_dhcp_client_stop_existing(const char *pid_file, const char *binary_name);

void nm_dhcp_client_stop_pid(pid_t pid, const char *iface);

void nm_dhcp_client_start_timeout(NMDhcpClient *self);

void nm_dhcp_client_watch_child(NMDhcpClient *self, pid_t pid);

void nm_dhcp_client_stop_watch_child(NMDhcpClient *self, pid_t pid);

void nm_dhcp_client_set_state(NMDhcpClient *self,
                              NMDhcpState   new_state,
                              NMIPConfig *  ip_config,
                              GHashTable *  options); /* str:str hash */

gboolean nm_dhcp_client_handle_event(gpointer      unused,
                                     const char *  iface,
                                     int           pid,
                                     GVariant *    options,
                                     const char *  reason,
                                     NMDhcpClient *self);

void nm_dhcp_client_set_client_id(NMDhcpClient *self, GBytes *client_id);
void nm_dhcp_client_set_client_id_bin(NMDhcpClient *self,
                                      guint8        type,
                                      const guint8 *client_id,
                                      gsize         len);

void nm_dhcp_client_emit_ipv6_prefix_delegated(NMDhcpClient *              self,
                                               const NMPlatformIP6Address *prefix);

gboolean nm_dhcp_client_server_id_is_rejected(NMDhcpClient *self, gconstpointer addr);

/*****************************************************************************
 * Client data
 *****************************************************************************/

typedef struct {
    GType (*get_type_4)(void);
    GType (*get_type_6)(void);
    const char *name;
    const char *(*get_path)(void);

    /* whether this plugin is an undocumented, internal plugin. */
    bool undocumented : 1;
} NMDhcpClientFactory;

GType nm_dhcp_nettools_get_type(void);

extern const NMDhcpClientFactory _nm_dhcp_client_factory_dhcpcanon;
extern const NMDhcpClientFactory _nm_dhcp_client_factory_dhclient;
extern const NMDhcpClientFactory _nm_dhcp_client_factory_dhcpcd;
extern const NMDhcpClientFactory _nm_dhcp_client_factory_internal;
extern const NMDhcpClientFactory _nm_dhcp_client_factory_systemd;
extern const NMDhcpClientFactory _nm_dhcp_client_factory_nettools;

#endif /* __NETWORKMANAGER_DHCP_CLIENT_H__ */
