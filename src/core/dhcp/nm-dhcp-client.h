/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP_CLIENT_H__
#define __NETWORKMANAGER_DHCP_CLIENT_H__

#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
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

#define NM_DHCP_CLIENT_CONFIG "config"

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
    NM_DHCP_CLIENT_NOTIFY_TYPE_LEASE_UPDATE,

    /* When NM_DHCP_CLIENT_NO_LEASE_TIMEOUT expired and the state
     * switched from NM_DHCP_CLIENT_STATE_NO_LEASE to
     * NM_DHCP_CLIENT_STATE_NO_LEASE_WITH_TIMEOUT. */
    NM_DHCP_CLIENT_NOTIFY_TYPE_NO_LEASE_TIMEOUT,

    /* NMDhcpClient will indefinitely try to get/renew the lease.
     * As such, it's never officially in a non-recoverable state.
     * However, there are cases when it really looks like we won't
     * be able to get a lease. For example, if the underlying interface
     * is layer 3 only, if we have no IPv6 link local address for a prolonged
     * time, or if dhclient is not installed.
     * But even these cases are potentially recoverable. This is only
     * a hint to the user (which they might ignore).
     *
     * In particular, NM_DHCP_CLIENT_NOTIFY_TYPE_NO_LEASE_TIMEOUT might mean
     * that the DHCP is currently not running, but that could change
     * at any moment and from client's side, it does not look bad. */
    NM_DHCP_CLIENT_NOTIFY_TYPE_IT_LOOKS_BAD,

    NM_DHCP_CLIENT_NOTIFY_TYPE_PREFIX_DELEGATED,
} NMDhcpClientNotifyType;

typedef struct {
    NMDhcpClientNotifyType notify_type;
    union {
        struct {
            /* This is either the new lease information we just received,
             * or NULL (if a previous lease timed out). It can also be the
             * previous lease, that was injected. */
            const NML3ConfigData *l3cd;
            bool                  accepted;
        } lease_update;
        struct {
            const NMPlatformIP6Address *prefix;
        } prefix_delegated;
        struct {
            const char *reason;
        } it_looks_bad;
    };
} NMDhcpClientNotifyData;

const char *nm_dhcp_state_to_string(NMDhcpState state);

/* FIXME(l3cfg:dhcp:config): nm_dhcp_manager_start_ip[46]() has a gazillion of parameters,
 * those get passed on as CONSTRUCT_ONLY properties to the NMDhcpClient. Drop
 * all these parameters, and let the caller provide one NMDhcpClientConfig
 * instance. There will be only one GObject property (NM_DHCP_CLIENT_CONFIG),
 * which is CONSTRUCT_ONLY and takes a (mandatory) G_TYPE_POINTER for the
 * configuration.
 *
 * Since NMDhcpClientConfig has an addr_family, we also don't need separate
 * nm_dhcp_manager_start_ip[46]() methods. */
typedef struct {
    int addr_family;

    /* The NML3Cfg instance is the manager object for the ifindex on which
     * NMDhcpClient is supposed to run. */
    NML3Cfg *l3cfg;

    /* FIXME(l3cfg:dhcp:previous-lease): most parameters of NMDhcpClient are immutable,
     * so to change them (during reapply), we need to create and start
     * a new NMDhcpClient instance.
     *
     * However, while the restart happens, we want to stick to the previous
     * lease (if any). Allow the caller to provide such a previous lease,
     * and if present, the instance starts by pretending that it just received
     * this lease, before really starting. */
    const NML3ConfigData *previous_lease;

    const char *iface;

    /* The hardware address */
    GBytes *hwaddr;

    /* The broadcast hardware address */
    GBytes *bcast_hwaddr;

    /* Timeout in seconds before reporting failure */
    guint32 timeout;

    /* Flags for the hostname and FQDN DHCP options */
    NMDhcpHostnameFlags hostname_flags;

    /* The UUID of the connection. Used mainly to build
     * lease file names. */
    const char *uuid;

    /* Set to reduce the number of broadcast packets when the
	 * anycast hardware address of the DHCP service is known. */
    const char *anycast_address;

    /* The hostname or FQDN to send. */
    const char *hostname;

    /* The Manufacturer Usage Description (RFC 8520) URL to send */
    const char *mud_url;

    /* The value for the Vendor Class Identifier option */
    GBytes *vendor_class_identifier;

    /* A list of servers from which offers should be rejected */
    const char *const *reject_servers;

    /* The client identifier (DHCPv4) or DUID (DHCPv6) to send */
    GBytes *client_id;

    /* Whether to send the hostname or FQDN option */
    bool send_hostname : 1;

    /* Whether to send the hostname as HOSTNAME option or FQDN.
     * For DHCPv6 this is always TRUE. */
    bool use_fqdn : 1;

    union {
        struct {
            /* Set BOOTP broadcast flag in request packets, so that servers
             * will always broadcast replies. */
            bool request_broadcast : 1;

            /* The address from the previous lease */
            const char *last_address;
        } v4;
        struct {
            /* If set, the DUID from the connection is used; otherwise
             * the one from an existing lease is used. */
            gboolean enforce_duid;

            /* The IAID to use */
            guint32 iaid;

            /* Whether the IAID was explicitly set in the connection or
             * as global default */
            gboolean iaid_explicit;

            /* Number to prefixes (IA_PD) to request */
            guint needed_prefixes;

            /* Use Information-request to get stateless configuration
             * parameters (don't request a IA_NA) */
            bool info_only : 1;
        } v6;
    };
} NMDhcpClientConfig;

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

    gboolean (*ip4_start)(NMDhcpClient *self, GError **error);

    gboolean (*accept)(NMDhcpClient *self, GError **error);

    gboolean (*decline)(NMDhcpClient *self, const char *error_message, GError **error);

    gboolean (*ip6_start)(NMDhcpClient *self, const struct in6_addr *ll_addr, GError **error);

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

gboolean nm_dhcp_client_start_ip4(NMDhcpClient *self, GError **error);
gboolean nm_dhcp_client_start_ip6(NMDhcpClient *self, GError **error);

const NMDhcpClientConfig *nm_dhcp_client_get_config(NMDhcpClient *self);

pid_t nm_dhcp_client_get_pid(NMDhcpClient *self);

static inline const NML3ConfigData *
nm_dhcp_client_get_lease(NMDhcpClient *self)
{
    /* FIXME(l3cfg:dhcp:previous-lease): this function returns the currently
     * valid, exposed lease.
     *
     * Note that NMDhcpClient should accept as construct argument a *previous* lease,
     * and (if that lease is still valid), pretend that it's good to use. The point is
     * so that during reapply we keep using the current address, until a new lease
     * was received. */
    return NULL;
}

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

void
nm_dhcp_client_set_state(NMDhcpClient *self, NMDhcpState new_state, const NML3ConfigData *l3cd);

gboolean nm_dhcp_client_handle_event(gpointer      unused,
                                     const char   *iface,
                                     int           pid,
                                     GVariant     *options,
                                     const char   *reason,
                                     NMDhcpClient *self);

void nm_dhcp_client_emit_ipv6_prefix_delegated(NMDhcpClient               *self,
                                               const NMPlatformIP6Address *prefix);

gboolean nm_dhcp_client_server_id_is_rejected(NMDhcpClient *self, gconstpointer addr);

int                nm_dhcp_client_get_addr_family(NMDhcpClient *self);
const char        *nm_dhcp_client_get_iface(NMDhcpClient *self);
NMDedupMultiIndex *nm_dhcp_client_get_multi_idx(NMDhcpClient *self);
int                nm_dhcp_client_get_ifindex(NMDhcpClient *self);

void    nm_dhcp_client_set_effective_client_id(NMDhcpClient *self, GBytes *client_id);
GBytes *nm_dhcp_client_get_effective_client_id(NMDhcpClient *self);

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
