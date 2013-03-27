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
#include <netinet/in.h>
#include <linux/if.h>

#define NM_TYPE_PLATFORM            (nm_platform_get_type ())
#define NM_PLATFORM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PLATFORM, NMPlatform))
#define NM_PLATFORM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PLATFORM, NMPlatformClass))
#define NM_IS_PLATFORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PLATFORM))
#define NM_IS_PLATFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_PLATFORM))
#define NM_PLATFORM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PLATFORM, NMPlatformClass))

/******************************************************************/

typedef enum {
	/* no error specified, sometimes this means the arguments were wrong */
	NM_PLATFORM_ERROR_NONE,
	/* object was not found */
	NM_PLATFORM_ERROR_NOT_FOUND,
	/* object already exists */
	NM_PLATFORM_ERROR_EXISTS,
	/* object is not a slave */
	NM_PLATFORM_ERROR_NOT_SLAVE
} NMPlatformError;

typedef enum {
	NM_LINK_TYPE_NONE,
	NM_LINK_TYPE_UNKNOWN,
	NM_LINK_TYPE_GENERIC,
	NM_LINK_TYPE_LOOPBACK,
	NM_LINK_TYPE_ETHERNET,
	NM_LINK_TYPE_DUMMY,
	NM_LINK_TYPE_BRIDGE,
	NM_LINK_TYPE_BOND,
	NM_LINK_TYPE_TEAM,
	NM_LINK_TYPE_VLAN,
} NMLinkType;

typedef struct {
	int ifindex;
	char name[IFNAMSIZ];
	NMLinkType type;
	const char *type_name;
	int master;
	gboolean up;
	gboolean connected;
	gboolean arp;
} NMPlatformLink;

typedef struct {
	int ifindex;
	in_addr_t address;
	int plen;
} NMPlatformIP4Address;

typedef struct {
	int ifindex;
	struct in6_addr address;
	int plen;
} NMPlatformIP6Address;

typedef struct {
	int ifindex;
	in_addr_t network;
	int plen;
	in_addr_t gateway;
	guint metric;
	guint mss;
} NMPlatformIP4Route;

typedef struct {
	int ifindex;
	struct in6_addr network;
	int plen;
	struct in6_addr gateway;
	guint metric;
	guint mss;
} NMPlatformIP6Route;

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

	GArray *(*link_get_all) (NMPlatform *);
	gboolean (*link_add) (NMPlatform *, const char *name, NMLinkType type);
	gboolean (*link_delete) (NMPlatform *, int ifindex);
	int (*link_get_ifindex) (NMPlatform *, const char *name);
	const char *(*link_get_name) (NMPlatform *, int ifindex);
	NMLinkType (*link_get_type) (NMPlatform *, int ifindex);
	const char *(*link_get_type_name) (NMPlatform *, int ifindex);

	gboolean (*link_set_up) (NMPlatform *, int ifindex);
	gboolean (*link_set_down) (NMPlatform *, int ifindex);
	gboolean (*link_set_arp) (NMPlatform *, int ifindex);
	gboolean (*link_set_noarp) (NMPlatform *, int ifindex);
	gboolean (*link_is_up) (NMPlatform *, int ifindex);
	gboolean (*link_is_connected) (NMPlatform *, int ifindex);
	gboolean (*link_uses_arp) (NMPlatform *, int ifindex);

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

	GArray * (*ip4_address_get_all) (NMPlatform *, int ifindex);
	GArray * (*ip6_address_get_all) (NMPlatform *, int ifindex);
	gboolean (*ip4_address_add) (NMPlatform *, int ifindex, in_addr_t address, int plen);
	gboolean (*ip6_address_add) (NMPlatform *, int ifindex, struct in6_addr address, int plen);
	gboolean (*ip4_address_delete) (NMPlatform *, int ifindex, in_addr_t address, int plen);
	gboolean (*ip6_address_delete) (NMPlatform *, int ifindex, struct in6_addr address, int plen);
	gboolean (*ip4_address_exists) (NMPlatform *, int ifindex, in_addr_t address, int plen);
	gboolean (*ip6_address_exists) (NMPlatform *, int ifindex, struct in6_addr address, int plen);

	GArray * (*ip4_route_get_all) (NMPlatform *, int ifindex);
	GArray * (*ip6_route_get_all) (NMPlatform *, int ifindex);
	gboolean (*ip4_route_add) (NMPlatform *, int ifindex,
		in_addr_t network, int plen, in_addr_t gateway, int prio, int mss);
	gboolean (*ip6_route_add) (NMPlatform *, int ifindex,
		struct in6_addr network, int plen, struct in6_addr gateway, int prio, int mss);
	gboolean (*ip4_route_delete) (NMPlatform *, int ifindex, in_addr_t network, int plen, int metric);
	gboolean (*ip6_route_delete) (NMPlatform *, int ifindex, struct in6_addr network, int plen, int metric);
	gboolean (*ip4_route_exists) (NMPlatform *, int ifindex, in_addr_t network, int plen, int metric);
	gboolean (*ip6_route_exists) (NMPlatform *, int ifindex, struct in6_addr network, int plen, int metric);
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
#define NM_PLATFORM_LINK_ADDED "link-added"
#define NM_PLATFORM_LINK_CHANGED "link-changed"
#define NM_PLATFORM_LINK_REMOVED "link-removed"
#define NM_PLATFORM_IP4_ADDRESS_ADDED "ip4-address-added"
#define NM_PLATFORM_IP4_ADDRESS_CHANGED "ip4-address-changed"
#define NM_PLATFORM_IP4_ADDRESS_REMOVED "ip4-address-removed"
#define NM_PLATFORM_IP6_ADDRESS_ADDED "ip6-address-added"
#define NM_PLATFORM_IP6_ADDRESS_CHANGED "ip6-address-changed"
#define NM_PLATFORM_IP6_ADDRESS_REMOVED "ip6-address-removed"
#define NM_PLATFORM_IP4_ROUTE_ADDED "ip4-route-added"
#define NM_PLATFORM_IP4_ROUTE_CHANGED "ip4-route-changed"
#define NM_PLATFORM_IP4_ROUTE_REMOVED "ip4-route-removed"
#define NM_PLATFORM_IP6_ROUTE_ADDED "ip6-route-added"
#define NM_PLATFORM_IP6_ROUTE_CHANGED "ip6-route-changed"
#define NM_PLATFORM_IP6_ROUTE_REMOVED "ip6-route-removed"

/******************************************************************/

GType nm_platform_get_type (void);

void nm_platform_setup (GType type);
NMPlatform *nm_platform_get (void);
void nm_platform_free (void);

/******************************************************************/

void nm_platform_set_error (NMPlatformError error);
NMPlatformError nm_platform_get_error (void);
const char *nm_platform_get_error_msg (void);

gboolean nm_platform_sysctl_set (const char *path, const char *value);
char *nm_platform_sysctl_get (const char *path);

GArray *nm_platform_link_get_all (void);
gboolean nm_platform_dummy_add (const char *name);
gboolean nm_platform_bridge_add (const char *name);
gboolean nm_platform_bond_add (const char *name);
gboolean nm_platform_team_add (const char *name);
gboolean nm_platform_link_exists (const char *name);
gboolean nm_platform_link_delete (int ifindex);
gboolean nm_platform_link_delete_by_name (const char *ifindex);
int nm_platform_link_get_ifindex (const char *name);
const char *nm_platform_link_get_name (int ifindex);
NMLinkType nm_platform_link_get_type (int ifindex);
const char *nm_platform_link_get_type_name (int ifindex);

gboolean nm_platform_link_set_up (int ifindex);
gboolean nm_platform_link_set_down (int ifindex);
gboolean nm_platform_link_set_arp (int ifindex);
gboolean nm_platform_link_set_noarp (int ifindex);
gboolean nm_platform_link_is_up (int ifindex);
gboolean nm_platform_link_is_connected (int ifindex);
gboolean nm_platform_link_uses_arp (int ifindex);

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

GArray *nm_platform_ip4_address_get_all (int ifindex);
GArray *nm_platform_ip6_address_get_all (int ifindex);
gboolean nm_platform_ip4_address_add (int ifindex, in_addr_t address, int plen);
gboolean nm_platform_ip6_address_add (int ifindex, struct in6_addr address, int plen);
gboolean nm_platform_ip4_address_delete (int ifindex, in_addr_t address, int plen);
gboolean nm_platform_ip6_address_delete (int ifindex, struct in6_addr address, int plen);
gboolean nm_platform_ip4_address_exists (int ifindex, in_addr_t address, int plen);
gboolean nm_platform_ip6_address_exists (int ifindex, struct in6_addr address, int plen);

GArray *nm_platform_ip4_route_get_all (int ifindex);
GArray *nm_platform_ip6_route_get_all (int ifindex);
gboolean nm_platform_route_set_metric (int ifindex, int metric);
gboolean nm_platform_ip4_route_add (int ifindex,
		in_addr_t network, int plen, in_addr_t gateway, int metric, int mss);
gboolean nm_platform_ip6_route_add (int ifindex,
		struct in6_addr network, int plen, struct in6_addr gateway, int metric, int mss);
gboolean nm_platform_ip4_route_delete (int ifindex, in_addr_t network, int plen, int metric);
gboolean nm_platform_ip6_route_delete (int ifindex, struct in6_addr network, int plen, int metric);
gboolean nm_platform_ip4_route_exists (int ifindex, in_addr_t network, int plen, int metric);
gboolean nm_platform_ip6_route_exists (int ifindex, struct in6_addr network, int plen, int metric);

#define auto_g_free __attribute__((cleanup(put_g_free)))
static void __attribute__((unused))
put_g_free (void *ptr)
{
	gpointer *object = ptr;

	if (object && *object) {
		g_free (*object);
		*object = NULL;
	}
}

#endif /* NM_PLATFORM_H */
