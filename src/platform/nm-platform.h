/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-platform.c - Handle runtime kernel networking configuration
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
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
 */

#ifndef NM_PLATFORM_H
#define NM_PLATFORM_H

#include <glib-object.h>
#include "nm-glib-compat.h"
#include <netinet/in.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <linux/if_addr.h>

#include <NetworkManager.h>

#define NM_TYPE_PLATFORM            (nm_platform_get_type ())
#define NM_PLATFORM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PLATFORM, NMPlatform))
#define NM_PLATFORM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PLATFORM, NMPlatformClass))
#define NM_IS_PLATFORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PLATFORM))
#define NM_IS_PLATFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_PLATFORM))
#define NM_PLATFORM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PLATFORM, NMPlatformClass))

/******************************************************************/

/* workaround for older libnl version, that does not define these flags. */
#ifndef IFA_F_MANAGETEMPADDR
#define IFA_F_MANAGETEMPADDR 0x100
#endif
#ifndef IFA_F_NOPREFIXROUTE
#define IFA_F_NOPREFIXROUTE 0x200
#endif

typedef enum {
	/* no error specified, sometimes this means the arguments were wrong */
	NM_PLATFORM_ERROR_NONE,
	/* object was not found */
	NM_PLATFORM_ERROR_NOT_FOUND,
	/* object already exists */
	NM_PLATFORM_ERROR_EXISTS,
	/* object is wrong type */
	NM_PLATFORM_ERROR_WRONG_TYPE,
	/* object is not a slave */
	NM_PLATFORM_ERROR_NOT_SLAVE,
	/* firmware is not found */
	NM_PLATFORM_ERROR_NO_FIRMWARE
} NMPlatformError;

typedef enum {
	NM_PLATFORM_REASON_NONE,
	/* Event was requested by NetworkManager. */
	NM_PLATFORM_REASON_INTERNAL,
	/* Event came from the kernel. */
	NM_PLATFORM_REASON_EXTERNAL,
	/* Event is a result of cache checking and cleanups. */
	NM_PLATFORM_REASON_CACHE_CHECK
} NMPlatformReason;

typedef enum {
	/* Please don't interpret type numbers outside nm-platform and use functions
	 * like nm_platform_link_is_software() and nm_platform_supports_slaves().
	 *
	 * type & 0x10000 -> Software device type
	 * type & 0x20000 -> Type supports slaves
	 */

	/* No type, used as error value */
	NM_LINK_TYPE_NONE,

	/* Unknown type  */
	NM_LINK_TYPE_UNKNOWN,

	/* Hardware types */
	NM_LINK_TYPE_ETHERNET,
	NM_LINK_TYPE_INFINIBAND,
	NM_LINK_TYPE_OLPC_MESH,
	NM_LINK_TYPE_WIFI,
	NM_LINK_TYPE_WWAN_ETHERNET,   /* WWAN pseudo-ethernet */
	NM_LINK_TYPE_WIMAX,

	/* Software types */
	NM_LINK_TYPE_DUMMY = 0x10000,
	NM_LINK_TYPE_GRE,
	NM_LINK_TYPE_GRETAP,
	NM_LINK_TYPE_IFB,
	NM_LINK_TYPE_LOOPBACK,
	NM_LINK_TYPE_MACVLAN,
	NM_LINK_TYPE_MACVTAP,
	NM_LINK_TYPE_OPENVSWITCH,
	NM_LINK_TYPE_TAP,
	NM_LINK_TYPE_TUN,
	NM_LINK_TYPE_VETH,
	NM_LINK_TYPE_VLAN,
	NM_LINK_TYPE_VXLAN,

	/* Software types with slaves */
	NM_LINK_TYPE_BRIDGE = 0x10000 | 0x20000,
	NM_LINK_TYPE_BOND,
	NM_LINK_TYPE_TEAM,
} NMLinkType;

#define __NMPlatformObject_COMMON \
	int ifindex; \
	;

typedef struct {
	__NMPlatformObject_COMMON;
	char name[IFNAMSIZ];
	NMLinkType type;
	const char *type_name;
	const char *udi;
	const char *driver;
	int master;
	int parent;
	gboolean up;
	gboolean connected;
	gboolean arp;
	guint mtu;
} NMPlatformLink;

typedef enum {
	NM_PLATFORM_SIGNAL_ADDED,
	NM_PLATFORM_SIGNAL_CHANGED,
	NM_PLATFORM_SIGNAL_REMOVED,
} NMPlatformSignalChangeType;

#define NM_PLATFORM_LIFETIME_PERMANENT G_MAXUINT32

typedef enum {
	/* In priority order; higher number == higher priority */
	NM_PLATFORM_SOURCE_UNKNOWN,
	NM_PLATFORM_SOURCE_KERNEL,
	NM_PLATFORM_SOURCE_SHARED,
	NM_PLATFORM_SOURCE_IP4LL,
	NM_PLATFORM_SOURCE_PPP,
	NM_PLATFORM_SOURCE_WWAN,
	NM_PLATFORM_SOURCE_VPN,
	NM_PLATFORM_SOURCE_DHCP,
	NM_PLATFORM_SOURCE_RDISC,
	NM_PLATFORM_SOURCE_USER,
} NMPlatformSource;


typedef struct {
	__NMPlatformObject_COMMON;
} NMPlatformObject;


#define __NMPlatformIPAddress_COMMON \
	__NMPlatformObject_COMMON; \
	NMPlatformSource source; \
	\
	/* Timestamp in seconds in the reference system of nm_utils_get_monotonic_timestamp_*().
	 *
	 * The rules are:
	 * 1 @lifetime==0: @timestamp and @preferred is irrelevant (but mostly set to 0 too). Such addresses
	 *   are permanent. This rule is so that unset addresses (calloc) are permanent by default.
	 * 2 @lifetime==@preferred==NM_PLATFORM_LIFETIME_PERMANENT: @timestamp is irrelevant (but mostly
	 *   set to 0). Such addresses are permanent.
	 * 3 Non permanent addreses should (almost) always have @timestamp > 0. 0 is not a valid timestamp
	 *   and never returned by nm_utils_get_monotonic_timestamp_s(). In this case @valid/@preferred
	 *   is anchored at @timestamp.
	 * 4 Non permanent addresses with @timestamp == 0 are implicitely anchored at *now*, thus the time
	 *   moves as time goes by. This is usually not useful, except e.g. nm_platform_ip[46]_address_add().
	 *
	 * Non permanent addresses from DHCP/RA might have the @timestamp set to the moment of when the
	 * lease was received. Addresses from kernel might have the @timestamp based on the last modification
	 * time of the addresses. But don't rely on this behaviour, the @timestamp is only defined for anchoring
	 * @lifetime and @preferred.
	 */ \
	guint32 timestamp; \
	guint32 lifetime;   /* seconds since timestamp */ \
	guint32 preferred;  /* seconds since timestamp */ \
	int plen; \
	;

/**
 * NMPlatformIPAddress:
 *
 * Common parts of NMPlatformIP4Address and NMPlatformIP6Address.
 **/
typedef struct {
	__NMPlatformIPAddress_COMMON;
	union {
		guint8 address_ptr[1];
		guint32 __dummy_for_32bit_alignment;
	};
} NMPlatformIPAddress;

/**
 * NMPlatformIP4Address:
 * @timestamp: timestamp as returned by nm_utils_get_monotonic_timestamp_s()
 **/
typedef struct {
	__NMPlatformIPAddress_COMMON;
	in_addr_t address;
	in_addr_t peer_address;  /* PTP peer address */
	char label[IFNAMSIZ];
} NMPlatformIP4Address;
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMPlatformIPAddress, address_ptr) == G_STRUCT_OFFSET (NMPlatformIP4Address, address));

/**
 * NMPlatformIP6Address:
 * @timestamp: timestamp as returned by nm_utils_get_monotonic_timestamp_s()
 **/
typedef struct {
	__NMPlatformIPAddress_COMMON;
	struct in6_addr address;
	struct in6_addr peer_address;
	guint flags; /* ifa_flags from <linux/if_addr.h>, field type "unsigned int" is as used in rtnl_addr_get_flags. */
} NMPlatformIP6Address;
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMPlatformIPAddress, address_ptr) == G_STRUCT_OFFSET (NMPlatformIP6Address, address));

#undef __NMPlatformIPAddress_COMMON


#define NM_PLATFORM_ROUTE_METRIC_DEFAULT 1024

#define __NMPlatformIPRoute_COMMON \
	__NMPlatformObject_COMMON; \
	NMPlatformSource source; \
	int plen; \
	guint metric; \
	guint mss; \
	;

typedef struct {
	__NMPlatformIPRoute_COMMON;
	union {
		guint8 network_ptr[1];
		guint32 __dummy_for_32bit_alignment;
	};
} NMPlatformIPRoute;

#define NM_PLATFORM_IP_ROUTE_IS_DEFAULT(route) \
	( ((const NMPlatformIPRoute *) (route))->plen <= 0 )

typedef struct {
	__NMPlatformIPRoute_COMMON;
	in_addr_t network;
	in_addr_t gateway;
} NMPlatformIP4Route;
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMPlatformIPRoute, network_ptr) == G_STRUCT_OFFSET (NMPlatformIP4Route, network));

typedef struct {
	__NMPlatformIPRoute_COMMON;
	struct in6_addr network;
	struct in6_addr gateway;
} NMPlatformIP6Route;
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMPlatformIPRoute, network_ptr) == G_STRUCT_OFFSET (NMPlatformIP6Route, network));

#undef __NMPlatformIPRoute_COMMON


#undef __NMPlatformObject_COMMON


typedef struct {
	int peer;
} NMPlatformVethProperties;

typedef struct {
	gint64 owner;
	gint64 group;
	const char *mode;
	gboolean no_pi;
	gboolean vnet_hdr;
	gboolean multi_queue;
} NMPlatformTunProperties;

typedef struct {
	int parent_ifindex;
	const char *mode;
	gboolean no_promisc;
} NMPlatformMacvlanProperties;

typedef struct {
	int parent_ifindex;
	guint32 id;
	in_addr_t group;
	in_addr_t local;
	struct in6_addr group6;
	struct in6_addr local6;
	guint8 tos;
	guint8 ttl;
	gboolean learning;
	guint32 ageing;
	guint32 limit;
	guint16 dst_port;
	guint16 src_port_min;
	guint16 src_port_max;
	gboolean proxy;
	gboolean rsc;
	gboolean l2miss;
	gboolean l3miss;
} NMPlatformVxlanProperties;

typedef struct {
	int parent_ifindex;
	guint16 input_flags;
	guint16 output_flags;
	guint32 input_key;
	guint32 output_key;
	in_addr_t local;
	in_addr_t remote;
	guint8 ttl;
	guint8 tos;
	gboolean path_mtu_discovery;
} NMPlatformGreProperties;

/******************************************************************/

/* NMPlatform abstract class and its implementations provide a layer between
 * networkmanager's device management classes and the operating system kernel.
 *
 * How it works, is best seen in tests/nm-platform-test.c source file.
 *
 * NMPlatform provides interface to configure kernel interfaces and receive
 * notifications about both internal and external configuration changes. It
 * respects the following rules:
 *
 * 1) Every change made through NMPlatform is readily available and the respective
 * signals are called synchronously.
 *
 * 2) State of an object retrieved from NMPlatform (through functions or events)
 * is at least as recent than the state retrieved before.
 *
 * Any failure of the above rules should be fixed in NMPlatform implementations
 * and tested in nm-platform-test. Synchronization hacks should never be put
 * to any other code. That's why NMPlatform was created and that's why the
 * testing code was written for it.
 *
 * In future, parts of linux platform implementation may be moved to the libnl
 * library.
 *
 * If you have any problems related to NMPlatform on your system, you should
 * always first run tests/nm-linux-platform-test as root and with all
 * network configuration daemons stopped. Look at the code first.
 */

typedef struct {
	GObject parent;

	NMPlatformError error;
} NMPlatform;

typedef struct {
	GObjectClass parent;

	gboolean (*setup) (NMPlatform *);

	gboolean (*sysctl_set) (NMPlatform *, const char *path, const char *value);
	char * (*sysctl_get) (NMPlatform *, const char *path);

	gboolean (*link_get) (NMPlatform *platform, int ifindex, NMPlatformLink *link);
	GArray *(*link_get_all) (NMPlatform *);
	gboolean (*link_add) (NMPlatform *, const char *name, NMLinkType type, const void *address, size_t address_len);
	gboolean (*link_delete) (NMPlatform *, int ifindex);
	int (*link_get_ifindex) (NMPlatform *, const char *name);
	const char *(*link_get_name) (NMPlatform *, int ifindex);
	NMLinkType (*link_get_type) (NMPlatform *, int ifindex);
	const char *(*link_get_type_name) (NMPlatform *, int ifindex);

	gboolean (*link_refresh) (NMPlatform *, int ifindex);

	gboolean (*link_set_up) (NMPlatform *, int ifindex);
	gboolean (*link_set_down) (NMPlatform *, int ifindex);
	gboolean (*link_set_arp) (NMPlatform *, int ifindex);
	gboolean (*link_set_noarp) (NMPlatform *, int ifindex);
	gboolean (*link_is_up) (NMPlatform *, int ifindex);
	gboolean (*link_is_connected) (NMPlatform *, int ifindex);
	gboolean (*link_uses_arp) (NMPlatform *, int ifindex);

	gconstpointer (*link_get_address) (NMPlatform *, int ifindex, size_t *length);
	gboolean (*link_set_address) (NMPlatform *, int ifindex, gconstpointer address, size_t length);
	guint32 (*link_get_mtu) (NMPlatform *, int ifindex);
	gboolean (*link_set_mtu) (NMPlatform *, int ifindex, guint32 mtu);

	char * (*link_get_physical_port_id) (NMPlatform *, int ifindex);
	gboolean (*link_get_wake_on_lan) (NMPlatform *, int ifindex);

	gboolean (*link_supports_carrier_detect) (NMPlatform *, int ifindex);
	gboolean (*link_supports_vlans) (NMPlatform *, int ifindex);

	gboolean (*link_enslave) (NMPlatform *, int master, int slave);
	gboolean (*link_release) (NMPlatform *, int master, int slave);
	gboolean (*link_get_master) (NMPlatform *, int slave);
	gboolean (*master_set_option) (NMPlatform *, int ifindex, const char *option, const char *value);
	char * (*master_get_option) (NMPlatform *, int ifindex, const char *option);
	gboolean (*slave_set_option) (NMPlatform *, int ifindex, const char *option, const char *value);
	char * (*slave_get_option) (NMPlatform *, int ifindex, const char *option);

	gboolean (*vlan_add) (NMPlatform *, const char *name, int parent, int vlanid, guint32 vlanflags);
	gboolean (*vlan_get_info) (NMPlatform *, int ifindex, int *parent, int *vlan_id);
	gboolean (*vlan_set_ingress_map) (NMPlatform *, int ifindex, int from, int to);
	gboolean (*vlan_set_egress_map) (NMPlatform *, int ifindex, int from, int to);

	gboolean (*infiniband_partition_add) (NMPlatform *, int parent, int p_key);

	gboolean (*veth_get_properties) (NMPlatform *, int ifindex, NMPlatformVethProperties *properties);
	gboolean (*tun_get_properties) (NMPlatform *, int ifindex, NMPlatformTunProperties *properties);
	gboolean (*macvlan_get_properties) (NMPlatform *, int ifindex, NMPlatformMacvlanProperties *props);
	gboolean (*vxlan_get_properties) (NMPlatform *, int ifindex, NMPlatformVxlanProperties *props);
	gboolean (*gre_get_properties) (NMPlatform *, int ifindex, NMPlatformGreProperties *props);

	gboolean    (*wifi_get_capabilities) (NMPlatform *, int ifindex, NMDeviceWifiCapabilities *caps);
	gboolean    (*wifi_get_bssid)        (NMPlatform *, int ifindex, struct ether_addr *bssid);
	GByteArray *(*wifi_get_ssid)         (NMPlatform *, int ifindex);
	guint32     (*wifi_get_frequency)    (NMPlatform *, int ifindex);
	int         (*wifi_get_quality)      (NMPlatform *, int ifindex);
	guint32     (*wifi_get_rate)         (NMPlatform *, int ifindex);
	NM80211Mode (*wifi_get_mode)         (NMPlatform *, int ifindex);
	void        (*wifi_set_mode)         (NMPlatform *, int ifindex, NM80211Mode mode);
	guint32     (*wifi_find_frequency)   (NMPlatform *, int ifindex, const guint32 *freqs);
	void        (*wifi_indicate_addressing_running) (NMPlatform *, int ifindex, gboolean running);

	guint32     (*mesh_get_channel)      (NMPlatform *, int ifindex);
	gboolean    (*mesh_set_channel)      (NMPlatform *, int ifindex, guint32 channel);
	gboolean    (*mesh_set_ssid)         (NMPlatform *, int ifindex, const GByteArray *ssid);

	GArray * (*ip4_address_get_all) (NMPlatform *, int ifindex);
	GArray * (*ip6_address_get_all) (NMPlatform *, int ifindex);
	gboolean (*ip4_address_add) (NMPlatform *, int ifindex,
	                             in_addr_t address, in_addr_t peer_address, int plen,
	                             guint32 lifetime, guint32 preferred_lft,
	                             const char *label);
	gboolean (*ip6_address_add) (NMPlatform *, int ifindex,
	                             struct in6_addr address, struct in6_addr peer_address, int plen,
	                             guint32 lifetime, guint32 preferred_lft, guint flags);
	gboolean (*ip4_address_delete) (NMPlatform *, int ifindex, in_addr_t address, int plen);
	gboolean (*ip6_address_delete) (NMPlatform *, int ifindex, struct in6_addr address, int plen);
	gboolean (*ip4_address_exists) (NMPlatform *, int ifindex, in_addr_t address, int plen);
	gboolean (*ip6_address_exists) (NMPlatform *, int ifindex, struct in6_addr address, int plen);

	GArray * (*ip4_route_get_all) (NMPlatform *, int ifindex, gboolean include_default);
	GArray * (*ip6_route_get_all) (NMPlatform *, int ifindex, gboolean include_default);
	gboolean (*ip4_route_add) (NMPlatform *, int ifindex, NMPlatformSource source,
	                           in_addr_t network, int plen, in_addr_t gateway,
	                           int prio, int mss);
	gboolean (*ip6_route_add) (NMPlatform *, int ifindex, NMPlatformSource source,
	                           struct in6_addr network, int plen, struct in6_addr gateway,
	                           int prio, int mss);
	gboolean (*ip4_route_delete) (NMPlatform *, int ifindex, in_addr_t network, int plen, int metric);
	gboolean (*ip6_route_delete) (NMPlatform *, int ifindex, struct in6_addr network, int plen, int metric);
	gboolean (*ip4_route_exists) (NMPlatform *, int ifindex, in_addr_t network, int plen, int metric);
	gboolean (*ip6_route_exists) (NMPlatform *, int ifindex, struct in6_addr network, int plen, int metric);

	gboolean (*check_support_kernel_extended_ifa_flags) (NMPlatform *);
} NMPlatformClass;

/* NMPlatform signals
 *
 * Each signal handler is called with a type-specific object that provides
 * key attributes that constitute identity of the object. They may also
 * provide additional attributes for convenience.
 *
 * The object only intended to be used by the signal handler to determine
 * the current values. It is no longer valid after the signal handler exits
 * but you are free to copy the provided information and use it for later
 * reference.
 */
#define NM_PLATFORM_SIGNAL_LINK_CHANGED "link-changed"
#define NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED "ip4-address-changed"
#define NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED "ip6-address-changed"
#define NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED "ip4-route-changed"
#define NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED "ip6-route-changed"

/******************************************************************/

GType nm_platform_get_type (void);

void nm_platform_setup (GType type);
NMPlatform *nm_platform_get (void);
void nm_platform_free (void);

/******************************************************************/

void nm_platform_set_error (NMPlatformError error);
NMPlatformError nm_platform_get_error (void);
const char *nm_platform_get_error_msg (void);

void nm_platform_query_devices (void);

gboolean nm_platform_sysctl_set (const char *path, const char *value);
char *nm_platform_sysctl_get (const char *path);
gint32 nm_platform_sysctl_get_int32 (const char *path, gint32 fallback);
gint64 nm_platform_sysctl_get_int_checked (const char *path, guint base, gint64 min, gint64 max, gint64 fallback);

gboolean nm_platform_link_get (int ifindex, NMPlatformLink *link);
GArray *nm_platform_link_get_all (void);
gboolean nm_platform_dummy_add (const char *name);
gboolean nm_platform_bridge_add (const char *name, const void *address, size_t address_len);
gboolean nm_platform_bond_add (const char *name);
gboolean nm_platform_team_add (const char *name);
gboolean nm_platform_link_exists (const char *name);
gboolean nm_platform_link_delete (int ifindex);
int nm_platform_link_get_ifindex (const char *name);
const char *nm_platform_link_get_name (int ifindex);
NMLinkType nm_platform_link_get_type (int ifindex);
const char *nm_platform_link_get_type_name (int ifindex);
gboolean nm_platform_link_is_software (int ifindex);
gboolean nm_platform_link_supports_slaves (int ifindex);

gboolean nm_platform_link_refresh (int ifindex);

gboolean nm_platform_link_set_up (int ifindex);
gboolean nm_platform_link_set_down (int ifindex);
gboolean nm_platform_link_set_arp (int ifindex);
gboolean nm_platform_link_set_noarp (int ifindex);
gboolean nm_platform_link_is_up (int ifindex);
gboolean nm_platform_link_is_connected (int ifindex);
gboolean nm_platform_link_uses_arp (int ifindex);

gconstpointer nm_platform_link_get_address (int ifindex, size_t *length);
gboolean nm_platform_link_set_address (int ifindex, const void *address, size_t length);
guint32 nm_platform_link_get_mtu (int ifindex);
gboolean nm_platform_link_set_mtu (int ifindex, guint32 mtu);

char    *nm_platform_link_get_physical_port_id (int ifindex);
gboolean nm_platform_link_get_wake_on_lan (int ifindex);

gboolean nm_platform_link_supports_carrier_detect (int ifindex);
gboolean nm_platform_link_supports_vlans (int ifindex);

gboolean nm_platform_link_enslave (int master, int slave);
gboolean nm_platform_link_release (int master, int slave);
int nm_platform_link_get_master (int slave);
gboolean nm_platform_master_set_option (int ifindex, const char *option, const char *value);
char *nm_platform_master_get_option (int ifindex, const char *option);
gboolean nm_platform_slave_set_option (int ifindex, const char *option, const char *value);
char *nm_platform_slave_get_option (int ifindex, const char *option);

gboolean nm_platform_vlan_add (const char *name, int parent, int vlanid, guint32 vlanflags);
gboolean nm_platform_vlan_get_info (int ifindex, int *parent, int *vlanid);
gboolean nm_platform_vlan_set_ingress_map (int ifindex, int from, int to);
gboolean nm_platform_vlan_set_egress_map (int ifindex, int from, int to);

gboolean nm_platform_infiniband_partition_add (int parent, int p_key);

gboolean nm_platform_veth_get_properties (int ifindex, NMPlatformVethProperties *properties);
gboolean nm_platform_tun_get_properties (int ifindex, NMPlatformTunProperties *properties);
gboolean nm_platform_macvlan_get_properties (int ifindex, NMPlatformMacvlanProperties *props);
gboolean nm_platform_vxlan_get_properties (int ifindex, NMPlatformVxlanProperties *props);
gboolean nm_platform_gre_get_properties (int ifindex, NMPlatformGreProperties *props);

gboolean    nm_platform_wifi_get_capabilities (int ifindex, NMDeviceWifiCapabilities *caps);
gboolean    nm_platform_wifi_get_bssid        (int ifindex, struct ether_addr *bssid);
GByteArray *nm_platform_wifi_get_ssid         (int ifindex);
guint32     nm_platform_wifi_get_frequency    (int ifindex);
int         nm_platform_wifi_get_quality      (int ifindex);
guint32     nm_platform_wifi_get_rate         (int ifindex);
NM80211Mode nm_platform_wifi_get_mode         (int ifindex);
void        nm_platform_wifi_set_mode         (int ifindex, NM80211Mode mode);
guint32     nm_platform_wifi_find_frequency   (int ifindex, const guint32 *freqs);
void        nm_platform_wifi_indicate_addressing_running (int ifindex, gboolean running);

guint32     nm_platform_mesh_get_channel      (int ifindex);
gboolean    nm_platform_mesh_set_channel      (int ifindex, guint32 channel);
gboolean    nm_platform_mesh_set_ssid         (int ifindex, const GByteArray *ssid);

GArray *nm_platform_ip4_address_get_all (int ifindex);
GArray *nm_platform_ip6_address_get_all (int ifindex);
gboolean nm_platform_ip4_address_add (int ifindex,
                                      in_addr_t address, in_addr_t peer_address, int plen,
                                      guint32 lifetime, guint32 preferred_lft,
                                      const char *label);
gboolean nm_platform_ip6_address_add (int ifindex,
                                      struct in6_addr address, struct in6_addr peer_address, int plen,
                                      guint32 lifetime, guint32 preferred_lft, guint flags);
gboolean nm_platform_ip4_address_delete (int ifindex, in_addr_t address, int plen);
gboolean nm_platform_ip6_address_delete (int ifindex, struct in6_addr address, int plen);
gboolean nm_platform_ip4_address_exists (int ifindex, in_addr_t address, int plen);
gboolean nm_platform_ip6_address_exists (int ifindex, struct in6_addr address, int plen);
gboolean nm_platform_ip4_address_sync (int ifindex, const GArray *known_addresses);
gboolean nm_platform_ip6_address_sync (int ifindex, const GArray *known_addresses);
gboolean nm_platform_address_flush (int ifindex);

GArray *nm_platform_ip4_route_get_all (int ifindex, gboolean include_default);
GArray *nm_platform_ip6_route_get_all (int ifindex, gboolean include_default);
gboolean nm_platform_route_set_metric (int ifindex, int metric);
gboolean nm_platform_ip4_route_add (int ifindex, NMPlatformSource source,
                                    in_addr_t network, int plen, in_addr_t gateway,
                                    int metric, int mss);
gboolean nm_platform_ip6_route_add (int ifindex, NMPlatformSource source,
                                    struct in6_addr network, int plen, struct in6_addr gateway,
                                    int metric, int mss);
gboolean nm_platform_ip4_route_delete (int ifindex, in_addr_t network, int plen, int metric);
gboolean nm_platform_ip6_route_delete (int ifindex, struct in6_addr network, int plen, int metric);
gboolean nm_platform_ip4_route_exists (int ifindex, in_addr_t network, int plen, int metric);
gboolean nm_platform_ip6_route_exists (int ifindex, struct in6_addr network, int plen, int metric);
gboolean nm_platform_ip4_route_sync (int ifindex, const GArray *known_routes);
gboolean nm_platform_ip6_route_sync (int ifindex, const GArray *known_routes);
gboolean nm_platform_route_flush (int ifindex);

const char *nm_platform_link_to_string (const NMPlatformLink *link);
const char *nm_platform_ip4_address_to_string (const NMPlatformIP4Address *address);
const char *nm_platform_ip6_address_to_string (const NMPlatformIP6Address *address);
const char *nm_platform_ip4_route_to_string (const NMPlatformIP4Route *route);
const char *nm_platform_ip6_route_to_string (const NMPlatformIP6Route *route);

int nm_platform_link_cmp (const NMPlatformLink *a, const NMPlatformLink *b);
int nm_platform_ip4_address_cmp (const NMPlatformIP4Address *a, const NMPlatformIP4Address *b);
int nm_platform_ip6_address_cmp (const NMPlatformIP6Address *a, const NMPlatformIP6Address *b);
int nm_platform_ip4_route_cmp (const NMPlatformIP4Route *a, const NMPlatformIP4Route *b);
int nm_platform_ip6_route_cmp (const NMPlatformIP6Route *a, const NMPlatformIP6Route *b);

gboolean nm_platform_check_support_libnl_extended_ifa_flags (void);
gboolean nm_platform_check_support_kernel_extended_ifa_flags (void);

void nm_platform_addr_flags2str (int flags, char *buf, size_t size);

int nm_platform_ip_address_cmp_expiry (const NMPlatformIPAddress *a, const NMPlatformIPAddress *b);

#define auto_g_free __attribute__((cleanup(put_g_free)))
static void __attribute__((unused))
put_g_free (void *ptr)
{
	g_clear_pointer ((gpointer *) ptr, g_free);
}

#endif /* NM_PLATFORM_H */
