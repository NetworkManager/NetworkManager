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

#ifndef __NETWORKMANAGER_PLATFORM_H__
#define __NETWORKMANAGER_PLATFORM_H__

#include <glib-object.h>
#include "nm-glib-compat.h"
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_addr.h>

#include <nm-dbus-interface.h>
#include "nm-types.h"
#include "NetworkManagerUtils.h"

#define NM_TYPE_PLATFORM            (nm_platform_get_type ())
#define NM_PLATFORM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PLATFORM, NMPlatform))
#define NM_PLATFORM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PLATFORM, NMPlatformClass))
#define NM_IS_PLATFORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PLATFORM))
#define NM_IS_PLATFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_PLATFORM))
#define NM_PLATFORM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PLATFORM, NMPlatformClass))

/******************************************************************/

#define NM_PLATFORM_REGISTER_SINGLETON "register-singleton"

/******************************************************************/

typedef struct _NMPlatform NMPlatform;

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
	NM_PLATFORM_REASON_CACHE_CHECK,

	/* Internal reason to suppress announcing change events */
	_NM_PLATFORM_REASON_CACHE_CHECK_INTERNAL,
} NMPlatformReason;

#define __NMPlatformObject_COMMON \
	int ifindex; \
	;

struct _NMPlatformLink {
	__NMPlatformObject_COMMON;
	char name[IFNAMSIZ];
	NMLinkType type;

	/* rtnl_link_get_type(), IFLA_INFO_KIND. */
	/* NMPlatform initializes this field with a static string. */
	const char *kind;

	/* Beware: NMPlatform initializes this string with an allocated string
	 * (NMRefString). Handle it properly (i.e. don't keep a reference to it
	 * without incrementing the ref-counter).
	 * This property depends on @initialized. */
	const char *udi;

	/* NMPlatform initializes this field with a static string. */
	const char *driver;

	gboolean initialized;
	int master;
	int parent;

	/* rtnl_link_get_arptype(), ifinfomsg.ifi_type. */
	guint32 arptype;

	/* rtnl_link_get_addr() */
	struct {
		guint8 data[20]; /* NM_UTILS_HWADDR_LEN_MAX */
		guint8 len;
	} addr;

	/* rtnl_link_inet6_get_token() */
	struct {
		NMUtilsIPv6IfaceId iid;
		guint8 is_valid;
	} inet6_token;

	/* The bitwise inverse of rtnl_link_inet6_get_addr_gen_mode(). It is inverse
	 * to have a default of 0 -- meaning: unspecified. That way, a struct
	 * initialized with memset(0) has and unset value.*/
	guint8 inet6_addr_gen_mode_inv;

	/* rtnl_link_vlan_get_id(), IFLA_VLAN_ID */
	guint16 vlan_id;

	/* IFF_* flags as u32. Note that ifi_flags in 'struct ifinfomsg' is declared as 'unsigned',
	 * but libnl stores the flag internally as u32.  */
	guint32 flags;

	/* @connected is mostly identical to (@flags & IFF_UP). Except for bridge/bond masters,
	 * where we coerce the link as disconnect if it has no slaves. */
	gboolean connected;

	guint mtu;
};

typedef enum {
	NM_PLATFORM_SIGNAL_NONE,
	NM_PLATFORM_SIGNAL_ADDED,
	NM_PLATFORM_SIGNAL_CHANGED,
	NM_PLATFORM_SIGNAL_REMOVED,
} NMPlatformSignalChangeType;

#define NM_PLATFORM_LIFETIME_PERMANENT G_MAXUINT32

typedef enum {
	NM_PLATFORM_GET_ROUTE_MODE_ALL,
	NM_PLATFORM_GET_ROUTE_MODE_NO_DEFAULT,
	NM_PLATFORM_GET_ROUTE_MODE_ONLY_DEFAULT,
} NMPlatformGetRouteMode;

typedef struct {
	__NMPlatformObject_COMMON;
} NMPlatformObject;


#define __NMPlatformIPAddress_COMMON \
	__NMPlatformObject_COMMON; \
	NMIPConfigSource source; \
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
struct _NMPlatformIP4Address {
	__NMPlatformIPAddress_COMMON;
	in_addr_t address;
	in_addr_t peer_address;  /* PTP peer address */
	char label[IFNAMSIZ];
};
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMPlatformIPAddress, address_ptr) == G_STRUCT_OFFSET (NMPlatformIP4Address, address));

/**
 * NMPlatformIP6Address:
 * @timestamp: timestamp as returned by nm_utils_get_monotonic_timestamp_s()
 **/
struct _NMPlatformIP6Address {
	__NMPlatformIPAddress_COMMON;
	struct in6_addr address;
	struct in6_addr peer_address;
	guint flags; /* ifa_flags from <linux/if_addr.h>, field type "unsigned int" is as used in rtnl_addr_get_flags. */
};
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMPlatformIPAddress, address_ptr) == G_STRUCT_OFFSET (NMPlatformIP6Address, address));

typedef union {
	NMPlatformIPAddress  ax;
	NMPlatformIP4Address a4;
	NMPlatformIP6Address a6;
} NMPlatformIPXAddress;

#undef __NMPlatformIPAddress_COMMON


/* Default value for adding an IPv4 route. This is also what iproute2 does.
 * Note that contrary to IPv6, you can add routes with metric 0 and it is even
 * the default.
 */
#define NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4 0

/* Default value for adding an IPv6 route. This is also what iproute2 does.
 * Adding an IPv6 route with metric 0, kernel translates to IP6_RT_PRIO_USER (1024). */
#define NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6 1024

/* For IPv4, kernel adds a device route (subnet routes) with metric 0 when user
 * configures addresses. */
#define NM_PLATFORM_ROUTE_METRIC_IP4_DEVICE_ROUTE 0

#define __NMPlatformIPRoute_COMMON \
	__NMPlatformObject_COMMON; \
	NMIPConfigSource source; \
	int plen; \
	guint32 metric; \
	guint32 mss; \
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

struct _NMPlatformIP4Route {
	__NMPlatformIPRoute_COMMON;
	in_addr_t network;
	in_addr_t gateway;

	/* The bitwise inverse of the route scope. It is inverted so that the
	 * default value (RT_SCOPE_NOWHERE) is nul. */
	guint8 scope_inv;
};
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMPlatformIPRoute, network_ptr) == G_STRUCT_OFFSET (NMPlatformIP4Route, network));

struct _NMPlatformIP6Route {
	__NMPlatformIPRoute_COMMON;
	struct in6_addr network;
	struct in6_addr gateway;
};
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMPlatformIPRoute, network_ptr) == G_STRUCT_OFFSET (NMPlatformIP6Route, network));

typedef union {
	NMPlatformIPRoute  rx;
	NMPlatformIP4Route r4;
	NMPlatformIP6Route r6;
} NMPlatformIPXRoute;

#undef __NMPlatformIPRoute_COMMON


#undef __NMPlatformObject_COMMON


typedef struct {
	gboolean is_ip4;
	int addr_family;
	gsize sizeof_route;
	int (*route_cmp) (const NMPlatformIPXRoute *a, const NMPlatformIPXRoute *b);
	const char *(*route_to_string) (const NMPlatformIPXRoute *route);
	GArray *(*route_get_all) (NMPlatform *self, int ifindex, NMPlatformGetRouteMode mode);
	gboolean (*route_add) (NMPlatform *self, int ifindex, const NMPlatformIPXRoute *route, guint32 v4_pref_src);
	gboolean (*route_delete) (NMPlatform *self, int ifindex, const NMPlatformIPXRoute *route);
	gboolean (*route_delete_default) (NMPlatform *self, int ifindex, guint32 metric);
	guint32 (*metric_normalize) (guint32 metric);
} NMPlatformVTableRoute;

extern const NMPlatformVTableRoute nm_platform_vtable_route_v4;
extern const NMPlatformVTableRoute nm_platform_vtable_route_v6;

extern char _nm_platform_to_string_buffer[256];

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

struct _NMPlatform {
	GObject parent;

	NMPlatformError error;
};

typedef struct {
	GObjectClass parent;

	gboolean (*sysctl_set) (NMPlatform *, const char *path, const char *value);
	char * (*sysctl_get) (NMPlatform *, const char *path);

	gboolean (*link_get) (NMPlatform *platform, int ifindex, NMPlatformLink *link);
	gboolean (*link_get_by_address) (NMPlatform *platform, gconstpointer address, size_t length, NMPlatformLink *link);
	GArray *(*link_get_all) (NMPlatform *);
	gboolean (*link_add) (NMPlatform *,
	                      const char *name,
	                      NMLinkType type,
	                      const void *address,
	                      size_t address_len,
	                      NMPlatformLink *out_link);
	gboolean (*link_delete) (NMPlatform *, int ifindex);
	int (*link_get_ifindex) (NMPlatform *, const char *name);
	const char *(*link_get_name) (NMPlatform *, int ifindex);
	NMLinkType (*link_get_type) (NMPlatform *, int ifindex);
	const char *(*link_get_type_name) (NMPlatform *, int ifindex);
	gboolean (*link_get_unmanaged) (NMPlatform *, int ifindex, gboolean *managed);

	gboolean (*link_refresh) (NMPlatform *, int ifindex);

	gboolean (*link_set_up) (NMPlatform *, int ifindex);
	gboolean (*link_set_down) (NMPlatform *, int ifindex);
	gboolean (*link_set_arp) (NMPlatform *, int ifindex);
	gboolean (*link_set_noarp) (NMPlatform *, int ifindex);
	gboolean (*link_is_up) (NMPlatform *, int ifindex);
	gboolean (*link_is_connected) (NMPlatform *, int ifindex);
	gboolean (*link_uses_arp) (NMPlatform *, int ifindex);

	gboolean (*link_get_ipv6_token) (NMPlatform *, int ifindex, NMUtilsIPv6IfaceId *iid);

	gboolean (*link_get_user_ipv6ll_enabled) (NMPlatform *, int ifindex);
	gboolean (*link_set_user_ipv6ll_enabled) (NMPlatform *, int ifindex, gboolean enabled);

	gconstpointer (*link_get_address) (NMPlatform *, int ifindex, size_t *length);
	gboolean (*link_get_permanent_address) (NMPlatform *,
	                                        int ifindex,
	                                        guint8 *buf,
	                                        size_t *length);
	gboolean (*link_set_address) (NMPlatform *, int ifindex, gconstpointer address, size_t length);
	guint32 (*link_get_mtu) (NMPlatform *, int ifindex);
	gboolean (*link_set_mtu) (NMPlatform *, int ifindex, guint32 mtu);

	char *   (*link_get_physical_port_id) (NMPlatform *, int ifindex);
	guint    (*link_get_dev_id) (NMPlatform *, int ifindex);
	gboolean (*link_get_wake_on_lan) (NMPlatform *, int ifindex);
	gboolean (*link_get_driver_info) (NMPlatform *,
	                                  int ifindex,
	                                  char **out_driver_name,
	                                  char **out_driver_version,
	                                  char **out_fw_version);

	gboolean (*link_supports_carrier_detect) (NMPlatform *, int ifindex);
	gboolean (*link_supports_vlans) (NMPlatform *, int ifindex);

	gboolean (*link_enslave) (NMPlatform *, int master, int slave);
	gboolean (*link_release) (NMPlatform *, int master, int slave);
	gboolean (*link_get_master) (NMPlatform *, int slave);
	gboolean (*master_set_option) (NMPlatform *, int ifindex, const char *option, const char *value);
	char * (*master_get_option) (NMPlatform *, int ifindex, const char *option);
	gboolean (*slave_set_option) (NMPlatform *, int ifindex, const char *option, const char *value);
	char * (*slave_get_option) (NMPlatform *, int ifindex, const char *option);

	gboolean (*vlan_add) (NMPlatform *, const char *name, int parent, int vlanid, guint32 vlanflags, NMPlatformLink *out_link);
	gboolean (*vlan_get_info) (NMPlatform *, int ifindex, int *parent, int *vlan_id);
	gboolean (*vlan_set_ingress_map) (NMPlatform *, int ifindex, int from, int to);
	gboolean (*vlan_set_egress_map) (NMPlatform *, int ifindex, int from, int to);

	gboolean (*infiniband_partition_add) (NMPlatform *, int parent, int p_key, NMPlatformLink *out_link);
	gboolean (*infiniband_get_info)      (NMPlatform *,
	                                      int ifindex,
	                                      int *parent,
	                                      int *p_key,
	                                      const char **mode);

	gboolean (*veth_get_properties) (NMPlatform *, int ifindex, NMPlatformVethProperties *properties);
	gboolean (*tun_get_properties) (NMPlatform *, int ifindex, NMPlatformTunProperties *properties);
	gboolean (*macvlan_get_properties) (NMPlatform *, int ifindex, NMPlatformMacvlanProperties *props);
	gboolean (*vxlan_get_properties) (NMPlatform *, int ifindex, NMPlatformVxlanProperties *props);
	gboolean (*gre_get_properties) (NMPlatform *, int ifindex, NMPlatformGreProperties *props);

	gboolean    (*wifi_get_capabilities) (NMPlatform *, int ifindex, NMDeviceWifiCapabilities *caps);
	gboolean    (*wifi_get_bssid)        (NMPlatform *, int ifindex, guint8 *bssid);
	GByteArray *(*wifi_get_ssid)         (NMPlatform *, int ifindex);
	guint32     (*wifi_get_frequency)    (NMPlatform *, int ifindex);
	int         (*wifi_get_quality)      (NMPlatform *, int ifindex);
	guint32     (*wifi_get_rate)         (NMPlatform *, int ifindex);
	NM80211Mode (*wifi_get_mode)         (NMPlatform *, int ifindex);
	void        (*wifi_set_mode)         (NMPlatform *, int ifindex, NM80211Mode mode);
	void        (*wifi_set_powersave)    (NMPlatform *, int ifindex, guint32 powersave);
	guint32     (*wifi_find_frequency)   (NMPlatform *, int ifindex, const guint32 *freqs);
	void        (*wifi_indicate_addressing_running) (NMPlatform *, int ifindex, gboolean running);

	guint32     (*mesh_get_channel)      (NMPlatform *, int ifindex);
	gboolean    (*mesh_set_channel)      (NMPlatform *, int ifindex, guint32 channel);
	gboolean    (*mesh_set_ssid)         (NMPlatform *, int ifindex, const guint8 *ssid, gsize len);

	GArray * (*ip4_address_get_all) (NMPlatform *, int ifindex);
	GArray * (*ip6_address_get_all) (NMPlatform *, int ifindex);
	gboolean (*ip4_address_add) (NMPlatform *, int ifindex,
	                             in_addr_t address, in_addr_t peer_address, int plen,
	                             guint32 lifetime, guint32 preferred_lft,
	                             const char *label);
	gboolean (*ip6_address_add) (NMPlatform *, int ifindex,
	                             struct in6_addr address, struct in6_addr peer_address, int plen,
	                             guint32 lifetime, guint32 preferred_lft, guint flags);
	gboolean (*ip4_address_delete) (NMPlatform *, int ifindex, in_addr_t address, int plen, in_addr_t peer_address);
	gboolean (*ip6_address_delete) (NMPlatform *, int ifindex, struct in6_addr address, int plen);
	gboolean (*ip4_address_exists) (NMPlatform *, int ifindex, in_addr_t address, int plen);
	gboolean (*ip6_address_exists) (NMPlatform *, int ifindex, struct in6_addr address, int plen);

	gboolean (*ip4_check_reinstall_device_route) (NMPlatform *, int ifindex, const NMPlatformIP4Address *address, guint32 device_route_metric);

	GArray * (*ip4_route_get_all) (NMPlatform *, int ifindex, NMPlatformGetRouteMode mode);
	GArray * (*ip6_route_get_all) (NMPlatform *, int ifindex, NMPlatformGetRouteMode mode);
	gboolean (*ip4_route_add) (NMPlatform *, int ifindex, NMIPConfigSource source,
	                           in_addr_t network, int plen, in_addr_t gateway,
	                           guint32 pref_src, guint32 metric, guint32 mss);
	gboolean (*ip6_route_add) (NMPlatform *, int ifindex, NMIPConfigSource source,
	                           struct in6_addr network, int plen, struct in6_addr gateway,
	                           guint32 metric, guint32 mss);
	gboolean (*ip4_route_delete) (NMPlatform *, int ifindex, in_addr_t network, int plen, guint32 metric);
	gboolean (*ip6_route_delete) (NMPlatform *, int ifindex, struct in6_addr network, int plen, guint32 metric);
	gboolean (*ip4_route_exists) (NMPlatform *, int ifindex, in_addr_t network, int plen, guint32 metric);
	gboolean (*ip6_route_exists) (NMPlatform *, int ifindex, struct in6_addr network, int plen, guint32 metric);

	gboolean (*check_support_kernel_extended_ifa_flags) (NMPlatform *);
	gboolean (*check_support_user_ipv6ll) (NMPlatform *);
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

const char *nm_platform_signal_change_type_to_string (NMPlatformSignalChangeType change_type);

/******************************************************************/

GType nm_platform_get_type (void);

void nm_platform_setup (NMPlatform *instance);
NMPlatform *nm_platform_get (void);
NMPlatform *nm_platform_try_get (void);

#define NM_PLATFORM_GET (nm_platform_get ())

/******************************************************************/

/**
 * nm_platform_route_scope_inv:
 * @scope: the route scope, either its original value, or its inverse.
 *
 * This function is useful, because the constants such as RT_SCOPE_NOWHERE
 * are 'int', so ~scope also gives an 'int'. This function gets the type
 * casts to guint8 right.
 *
 * Returns: the bitwise inverse of the route scope.
 * */
static inline guint8
nm_platform_route_scope_inv (guint8 scope)
{
	return (guint8) ~scope;
}

const char *nm_link_type_to_string (NMLinkType link_type);

void nm_platform_set_error (NMPlatform *self, NMPlatformError error);
NMPlatformError nm_platform_get_error (NMPlatform *self);
const char *nm_platform_get_error_msg (NMPlatform *self);

gboolean nm_platform_sysctl_set (NMPlatform *self, const char *path, const char *value);
char *nm_platform_sysctl_get (NMPlatform *self, const char *path);
gint32 nm_platform_sysctl_get_int32 (NMPlatform *self, const char *path, gint32 fallback);
gint64 nm_platform_sysctl_get_int_checked (NMPlatform *self, const char *path, guint base, gint64 min, gint64 max, gint64 fallback);

gboolean nm_platform_sysctl_set_ip6_hop_limit_safe (NMPlatform *self, const char *iface, int value);

gboolean nm_platform_link_get (NMPlatform *self, int ifindex, NMPlatformLink *link);
GArray *nm_platform_link_get_all (NMPlatform *self);
gboolean nm_platform_link_get_by_address (NMPlatform *self, gconstpointer address, size_t length, NMPlatformLink *link);
gboolean nm_platform_dummy_add (NMPlatform *self, const char *name, NMPlatformLink *out_link);
gboolean nm_platform_bridge_add (NMPlatform *self, const char *name, const void *address, size_t address_len, NMPlatformLink *out_link);
gboolean nm_platform_bond_add (NMPlatform *self, const char *name, NMPlatformLink *out_link);
gboolean nm_platform_team_add (NMPlatform *self, const char *name, NMPlatformLink *out_link);
gboolean nm_platform_link_exists (NMPlatform *self, const char *name);
gboolean nm_platform_link_delete (NMPlatform *self, int ifindex);
int nm_platform_link_get_ifindex (NMPlatform *self, const char *name);
const char *nm_platform_link_get_name (NMPlatform *self, int ifindex);
NMLinkType nm_platform_link_get_type (NMPlatform *self, int ifindex);
const char *nm_platform_link_get_type_name (NMPlatform *self, int ifindex);
gboolean nm_platform_link_get_unmanaged (NMPlatform *self, int ifindex, gboolean *managed);
gboolean nm_platform_link_is_software (NMPlatform *self, int ifindex);
gboolean nm_platform_link_supports_slaves (NMPlatform *self, int ifindex);

gboolean nm_platform_link_refresh (NMPlatform *self, int ifindex);

gboolean nm_platform_link_set_up (NMPlatform *self, int ifindex);
gboolean nm_platform_link_set_down (NMPlatform *self, int ifindex);
gboolean nm_platform_link_set_arp (NMPlatform *self, int ifindex);
gboolean nm_platform_link_set_noarp (NMPlatform *self, int ifindex);
gboolean nm_platform_link_is_up (NMPlatform *self, int ifindex);
gboolean nm_platform_link_is_connected (NMPlatform *self, int ifindex);
gboolean nm_platform_link_uses_arp (NMPlatform *self, int ifindex);

gboolean nm_platform_link_get_ipv6_token (NMPlatform *self, int ifindex, NMUtilsIPv6IfaceId *iid);

gboolean nm_platform_link_get_user_ipv6ll_enabled (NMPlatform *self, int ifindex);
gboolean nm_platform_link_set_user_ipv6ll_enabled (NMPlatform *self, int ifindex, gboolean enabled);

gconstpointer nm_platform_link_get_address (NMPlatform *self, int ifindex, size_t *length);
gboolean nm_platform_link_get_permanent_address (NMPlatform *self, int ifindex, guint8 *buf, size_t *length);
gboolean nm_platform_link_set_address (NMPlatform *self, int ifindex, const void *address, size_t length);
guint32 nm_platform_link_get_mtu (NMPlatform *self, int ifindex);
gboolean nm_platform_link_set_mtu (NMPlatform *self, int ifindex, guint32 mtu);

char    *nm_platform_link_get_physical_port_id (NMPlatform *self, int ifindex);
guint    nm_platform_link_get_dev_id (NMPlatform *self, int ifindex);
gboolean nm_platform_link_get_wake_on_lan (NMPlatform *self, int ifindex);
gboolean nm_platform_link_get_driver_info (NMPlatform *self,
                                           int ifindex,
                                           char **out_driver_name,
                                           char **out_driver_version,
                                           char **out_fw_version);

gboolean nm_platform_link_supports_carrier_detect (NMPlatform *self, int ifindex);
gboolean nm_platform_link_supports_vlans (NMPlatform *self, int ifindex);

gboolean nm_platform_link_enslave (NMPlatform *self, int master, int slave);
gboolean nm_platform_link_release (NMPlatform *self, int master, int slave);
int nm_platform_link_get_master (NMPlatform *self, int slave);
gboolean nm_platform_master_set_option (NMPlatform *self, int ifindex, const char *option, const char *value);
char *nm_platform_master_get_option (NMPlatform *self, int ifindex, const char *option);
gboolean nm_platform_slave_set_option (NMPlatform *self, int ifindex, const char *option, const char *value);
char *nm_platform_slave_get_option (NMPlatform *self, int ifindex, const char *option);

gboolean nm_platform_vlan_add (NMPlatform *self, const char *name, int parent, int vlanid, guint32 vlanflags, NMPlatformLink *out_link);
gboolean nm_platform_vlan_get_info (NMPlatform *self, int ifindex, int *parent, int *vlanid);
gboolean nm_platform_vlan_set_ingress_map (NMPlatform *self, int ifindex, int from, int to);
gboolean nm_platform_vlan_set_egress_map (NMPlatform *self, int ifindex, int from, int to);

gboolean nm_platform_infiniband_partition_add (NMPlatform *self, int parent, int p_key, NMPlatformLink *out_link);
gboolean nm_platform_infiniband_get_info (NMPlatform *self, int ifindex, int *parent, int *p_key, const char **mode);

gboolean nm_platform_veth_get_properties        (NMPlatform *self, int ifindex, NMPlatformVethProperties *properties);
gboolean nm_platform_tun_get_properties         (NMPlatform *self, int ifindex, NMPlatformTunProperties *properties);
gboolean nm_platform_macvlan_get_properties     (NMPlatform *self, int ifindex, NMPlatformMacvlanProperties *props);
gboolean nm_platform_vxlan_get_properties       (NMPlatform *self, int ifindex, NMPlatformVxlanProperties *props);
gboolean nm_platform_gre_get_properties         (NMPlatform *self, int ifindex, NMPlatformGreProperties *props);

gboolean    nm_platform_wifi_get_capabilities (NMPlatform *self, int ifindex, NMDeviceWifiCapabilities *caps);
gboolean    nm_platform_wifi_get_bssid        (NMPlatform *self, int ifindex, guint8 *bssid);
guint32     nm_platform_wifi_get_frequency    (NMPlatform *self, int ifindex);
int         nm_platform_wifi_get_quality      (NMPlatform *self, int ifindex);
guint32     nm_platform_wifi_get_rate         (NMPlatform *self, int ifindex);
NM80211Mode nm_platform_wifi_get_mode         (NMPlatform *self, int ifindex);
void        nm_platform_wifi_set_mode         (NMPlatform *self, int ifindex, NM80211Mode mode);
void        nm_platform_wifi_set_powersave    (NMPlatform *self, int ifindex, guint32 powersave);
guint32     nm_platform_wifi_find_frequency   (NMPlatform *self, int ifindex, const guint32 *freqs);
void        nm_platform_wifi_indicate_addressing_running (NMPlatform *self, int ifindex, gboolean running);

guint32     nm_platform_mesh_get_channel      (NMPlatform *self, int ifindex);
gboolean    nm_platform_mesh_set_channel      (NMPlatform *self, int ifindex, guint32 channel);
gboolean    nm_platform_mesh_set_ssid         (NMPlatform *self, int ifindex, const guint8 *ssid, gsize len);

GArray *nm_platform_ip4_address_get_all (NMPlatform *self, int ifindex);
GArray *nm_platform_ip6_address_get_all (NMPlatform *self, int ifindex);
gboolean nm_platform_ip4_address_add (NMPlatform *self, int ifindex,
                                      in_addr_t address, in_addr_t peer_address, int plen,
                                      guint32 lifetime, guint32 preferred_lft,
                                      const char *label);
gboolean nm_platform_ip6_address_add (NMPlatform *self, int ifindex,
                                      struct in6_addr address, struct in6_addr peer_address, int plen,
                                      guint32 lifetime, guint32 preferred_lft, guint flags);
gboolean nm_platform_ip4_address_delete (NMPlatform *self, int ifindex, in_addr_t address, int plen, in_addr_t peer_address);
gboolean nm_platform_ip6_address_delete (NMPlatform *self, int ifindex, struct in6_addr address, int plen);
gboolean nm_platform_ip4_address_exists (NMPlatform *self, int ifindex, in_addr_t address, int plen);
gboolean nm_platform_ip6_address_exists (NMPlatform *self, int ifindex, struct in6_addr address, int plen);
gboolean nm_platform_ip4_address_sync (NMPlatform *self, int ifindex, const GArray *known_addresses, guint32 device_route_metric);
gboolean nm_platform_ip6_address_sync (NMPlatform *self, int ifindex, const GArray *known_addresses, gboolean keep_link_local);
gboolean nm_platform_address_flush (NMPlatform *self, int ifindex);

gboolean nm_platform_ip4_check_reinstall_device_route (NMPlatform *self, int ifindex, const NMPlatformIP4Address *address, guint32 device_route_metric);

GArray *nm_platform_ip4_route_get_all (NMPlatform *self, int ifindex, NMPlatformGetRouteMode mode);
GArray *nm_platform_ip6_route_get_all (NMPlatform *self, int ifindex, NMPlatformGetRouteMode mode);
gboolean nm_platform_ip4_route_add (NMPlatform *self, int ifindex, NMIPConfigSource source,
                                    in_addr_t network, int plen, in_addr_t gateway,
                                    guint32 pref_src, guint32 metric, guint32 mss);
gboolean nm_platform_ip6_route_add (NMPlatform *self, int ifindex, NMIPConfigSource source,
                                    struct in6_addr network, int plen, struct in6_addr gateway,
                                    guint32 metric, guint32 mss);
gboolean nm_platform_ip4_route_delete (NMPlatform *self, int ifindex, in_addr_t network, int plen, guint32 metric);
gboolean nm_platform_ip6_route_delete (NMPlatform *self, int ifindex, struct in6_addr network, int plen, guint32 metric);
gboolean nm_platform_ip4_route_exists (NMPlatform *self, int ifindex, in_addr_t network, int plen, guint32 metric);
gboolean nm_platform_ip6_route_exists (NMPlatform *self, int ifindex, struct in6_addr network, int plen, guint32 metric);

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
gboolean nm_platform_check_support_kernel_extended_ifa_flags (NMPlatform *self);
gboolean nm_platform_check_support_user_ipv6ll (NMPlatform *self);

void nm_platform_addr_flags2str (int flags, char *buf, size_t size);

int nm_platform_ip_address_cmp_expiry (const NMPlatformIPAddress *a, const NMPlatformIPAddress *b);

#endif /* __NETWORKMANAGER_PLATFORM_H__ */
