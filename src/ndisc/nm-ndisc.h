/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-ndisc.h - Perform IPv6 neighbor discovery
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
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_NDISC_H__
#define __NETWORKMANAGER_NDISC_H__

#include <stdlib.h>
#include <netinet/in.h>
#include <linux/if_addr.h>

#include "nm-setting-ip6-config.h"
#include "NetworkManagerUtils.h"

#include "platform/nm-platform.h"
#include "platform/nmp-object.h"

#define NM_TYPE_NDISC            (nm_ndisc_get_type ())
#define NM_NDISC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_NDISC, NMNDisc))
#define NM_NDISC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_NDISC, NMNDiscClass))
#define NM_IS_NDISC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_NDISC))
#define NM_IS_NDISC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_NDISC))
#define NM_NDISC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_NDISC, NMNDiscClass))

#define NM_NDISC_PLATFORM       "platform"
#define NM_NDISC_IFINDEX        "ifindex"
#define NM_NDISC_IFNAME         "ifname"
#define NM_NDISC_NETWORK_ID     "network-id"
#define NM_NDISC_ADDR_GEN_MODE  "addr-gen-mode"
#define NM_NDISC_STABLE_TYPE    "stable-type"
#define NM_NDISC_NODE_TYPE      "node-type"
#define NM_NDISC_MAX_ADDRESSES  "max-addresses"
#define NM_NDISC_ROUTER_SOLICITATIONS "router-solicitations"
#define NM_NDISC_ROUTER_SOLICITATION_INTERVAL "router-solicitation-interval"

#define NM_NDISC_CONFIG_RECEIVED "config-received"
#define NM_NDISC_RA_TIMEOUT      "ra-timeout"

typedef enum {
	NM_NDISC_DHCP_LEVEL_UNKNOWN,
	NM_NDISC_DHCP_LEVEL_NONE,
	NM_NDISC_DHCP_LEVEL_OTHERCONF,
	NM_NDISC_DHCP_LEVEL_MANAGED
} NMNDiscDHCPLevel;

/* we rely on the fact that NM_NDISC_INFINITY is the largest possible
 * time duration (G_MAXUINT32) and that the range of finite values
 * goes from 0 to G_MAXUINT32-1. */
#define NM_NDISC_INFINITY  G_MAXUINT32

struct _NMNDiscGateway {
	struct in6_addr address;
	guint32 timestamp;
	guint32 lifetime;
	NMIcmpv6RouterPref preference;
};
typedef struct _NMNDiscGateway NMNDiscGateway;

struct _NMNDiscAddress {
	struct in6_addr address;
	guint8 dad_counter;
	guint32 timestamp;
	guint32 lifetime;
	guint32 preferred;
};
typedef struct _NMNDiscAddress NMNDiscAddress;

struct _NMNDiscRoute {
	struct in6_addr network;
	guint8 plen;
	struct in6_addr gateway;
	guint32 timestamp;
	guint32 lifetime;
	NMIcmpv6RouterPref preference;
};
typedef struct _NMNDiscRoute NMNDiscRoute;

typedef struct {
	struct in6_addr address;
	guint32 timestamp;
	guint32 lifetime;
} NMNDiscDNSServer;

typedef struct {
	char *domain;
	guint32 timestamp;
	guint32 lifetime;
} NMNDiscDNSDomain;

typedef enum {
	NM_NDISC_CONFIG_NONE                                = 0,
	NM_NDISC_CONFIG_DHCP_LEVEL                          = 1 << 0,
	NM_NDISC_CONFIG_GATEWAYS                            = 1 << 1,
	NM_NDISC_CONFIG_ADDRESSES                           = 1 << 2,
	NM_NDISC_CONFIG_ROUTES                              = 1 << 3,
	NM_NDISC_CONFIG_DNS_SERVERS                         = 1 << 4,
	NM_NDISC_CONFIG_DNS_DOMAINS                         = 1 << 5,
	NM_NDISC_CONFIG_HOP_LIMIT                           = 1 << 6,
	NM_NDISC_CONFIG_MTU                                 = 1 << 7,
} NMNDiscConfigMap;

typedef enum {
	NM_NDISC_NODE_TYPE_INVALID,
	NM_NDISC_NODE_TYPE_HOST,
	NM_NDISC_NODE_TYPE_ROUTER,
} NMNDiscNodeType;

#define NM_NDISC_MAX_ADDRESSES_DEFAULT 16
#define NM_NDISC_ROUTER_SOLICITATIONS_DEFAULT 3          /* RFC4861 MAX_RTR_SOLICITATIONS */
#define NM_NDISC_ROUTER_SOLICITATION_INTERVAL_DEFAULT 4  /* RFC4861 RTR_SOLICITATION_INTERVAL */
#define NM_NDISC_ROUTER_ADVERTISEMENTS_DEFAULT 3         /* RFC4861 MAX_INITIAL_RTR_ADVERTISEMENTS */
#define NM_NDISC_ROUTER_ADVERT_DELAY 3                   /* RFC4861 MIN_DELAY_BETWEEN_RAS */
#define NM_NDISC_ROUTER_ADVERT_INITIAL_INTERVAL 16       /* RFC4861 MAX_INITIAL_RTR_ADVERT_INTERVAL */
#define NM_NDISC_ROUTER_ADVERT_DELAY_MS 500              /* RFC4861 MAX_RA_DELAY_TIME */
#define NM_NDISC_ROUTER_ADVERT_MAX_INTERVAL 600          /* RFC4861 MaxRtrAdvInterval default */
#define NM_NDISC_ROUTER_LIFETIME 900                     /* 1.5 * NM_NDISC_ROUTER_ADVERT_MAX_INTERVAL */

struct _NMNDiscPrivate;
struct _NMNDiscDataInternal;

typedef struct {
	NMNDiscDHCPLevel dhcp_level;
	guint32 mtu;
	int hop_limit;

	guint gateways_n;
	guint addresses_n;
	guint routes_n;
	guint dns_servers_n;
	guint dns_domains_n;

	const NMNDiscGateway *gateways;
	const NMNDiscAddress *addresses;
	const NMNDiscRoute *routes;
	const NMNDiscDNSServer *dns_servers;
	const NMNDiscDNSDomain *dns_domains;
} NMNDiscData;

/**
 * NMNDisc:
 *
 * Interface-specific structure that handles incoming router advertisements,
 * caches advertised items and removes them when they are obsolete.
 */
typedef struct {
	GObject parent;
	union {
		struct _NMNDiscPrivate *_priv;
		struct _NMNDiscDataInternal *rdata;
	};
} NMNDisc;

typedef struct {
	GObjectClass parent;

	void (*start) (NMNDisc *ndisc);
	gboolean (*send_rs) (NMNDisc *ndisc, GError **error);
	gboolean (*send_ra) (NMNDisc *ndisc, GError **error);
} NMNDiscClass;

GType nm_ndisc_get_type (void);

void nm_ndisc_emit_config_change (NMNDisc *self, NMNDiscConfigMap changed);

int nm_ndisc_get_ifindex (NMNDisc *self);
const char *nm_ndisc_get_ifname (NMNDisc *self);
NMNDiscNodeType nm_ndisc_get_node_type (NMNDisc *self);

gboolean nm_ndisc_set_iid (NMNDisc *ndisc, const NMUtilsIPv6IfaceId iid);
void nm_ndisc_start (NMNDisc *ndisc);
NMNDiscConfigMap nm_ndisc_dad_failed (NMNDisc *ndisc,
                                      const struct in6_addr *address,
                                      gboolean emit_changed_signal);
void nm_ndisc_set_config (NMNDisc *ndisc,
                          const GArray *addresses,
                          const GArray *dns_servers,
                          const GArray *dns_domains);

NMPlatform *nm_ndisc_get_platform (NMNDisc *self);
NMPNetns *nm_ndisc_netns_get (NMNDisc *self);
gboolean nm_ndisc_netns_push (NMNDisc *self, NMPNetns **netns);

static inline gboolean
nm_ndisc_dad_addr_is_fail_candidate_event (NMPlatformSignalChangeType change_type,
                                           const NMPlatformIP6Address *addr)
{
	return    !NM_FLAGS_HAS (addr->n_ifa_flags, IFA_F_TEMPORARY)
	       && (   (change_type == NM_PLATFORM_SIGNAL_CHANGED && addr->n_ifa_flags & IFA_F_DADFAILED)
	           || (change_type == NM_PLATFORM_SIGNAL_REMOVED && addr->n_ifa_flags & IFA_F_TENTATIVE));
}

static inline gboolean
nm_ndisc_dad_addr_is_fail_candidate (NMPlatform *platform,
                                     const NMPObject *obj)
{
	const NMPlatformIP6Address *addr;

	addr = NMP_OBJECT_CAST_IP6_ADDRESS (nm_platform_lookup_obj (platform,
	                                                            NMP_CACHE_ID_TYPE_OBJECT_TYPE,
	                                                            obj));
	if (   addr
	    && (   NM_FLAGS_HAS (addr->n_ifa_flags, IFA_F_TEMPORARY)
	        || !NM_FLAGS_HAS (addr->n_ifa_flags, IFA_F_DADFAILED))) {
		/* the address still/again exists and is not in DADFAILED state. Skip it. */
		return FALSE;
	}

	return TRUE;
}

#endif /* __NETWORKMANAGER_NDISC_H__ */
