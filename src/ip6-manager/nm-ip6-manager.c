/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-ip6-manager.c - Handle IPv6 address configuration for NetworkManager
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
 * Copyright (C) 2009 Red Hat, Inc.
 */

#include <errno.h>
#include <netinet/icmp6.h>

#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>

#include "nm-ip6-manager.h"
#include "nm-netlink-listener.h"
#include "NetworkManagerUtils.h"
#include "nm-marshal.h"
#include "nm-utils.h"

/* Pre-DHCP addrconf timeout, in seconds */
#define NM_IP6_TIMEOUT 10

/* FIXME? Stolen from the kernel sources */
#define IF_RA_OTHERCONF 0x80
#define IF_RA_MANAGED   0x40
#define IF_RA_RCVD      0x20
#define IF_RS_SENT      0x10

typedef struct {
	NMNetlinkListener *netlink;
	GHashTable *devices_by_iface, *devices_by_index;

	struct nl_handle *nlh;
	struct nl_cache *addr_cache, *route_cache;
} NMIP6ManagerPrivate;

#define NM_IP6_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IP6_MANAGER, NMIP6ManagerPrivate))

typedef enum {
	NM_IP6_DEVICE_UNCONFIGURED,
	NM_IP6_DEVICE_GOT_LINK_LOCAL,
	NM_IP6_DEVICE_GOT_ROUTER_ADVERTISEMENT,
	NM_IP6_DEVICE_GOT_ADDRESS,
	NM_IP6_DEVICE_WAITING_FOR_DHCP,
	NM_IP6_DEVICE_GOT_DHCP,
	NM_IP6_DEVICE_TIMED_OUT
} NMIP6DeviceState;

typedef struct {
	struct in6_addr addr;
	time_t expires;
} NMIP6RDNSS;

typedef struct {
	NMIP6Manager *manager;
	char *iface;
	int index;

	char *accept_ra_path;
	gboolean accept_ra_save_valid;
	guint32 accept_ra_save;

	guint finish_addrconf_id;
	guint config_changed_id;

	NMIP6DeviceState state;
	NMIP6DeviceState target_state;
	gboolean want_signal;

	GArray *rdnss_servers;
	guint rdnss_timeout_id;
} NMIP6Device;

G_DEFINE_TYPE (NMIP6Manager, nm_ip6_manager, G_TYPE_OBJECT)

enum {
	ADDRCONF_COMPLETE,
	CONFIG_CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static NMIP6Manager *nm_ip6_manager_new (void);

static void netlink_notification (NMNetlinkListener *listener, struct nl_msg *msg, gpointer user_data);

static void nm_ip6_device_destroy (NMIP6Device *device);

NMIP6Manager *
nm_ip6_manager_get (void)
{
	static NMIP6Manager *singleton = NULL;

	if (!singleton)
		singleton = nm_ip6_manager_new ();
	g_assert (singleton);

	return g_object_ref (singleton);
}

static void
nm_ip6_manager_init (NMIP6Manager *manager)
{
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (manager);

	priv->devices_by_iface = g_hash_table_new_full (g_str_hash, g_str_equal,
													NULL,
													(GDestroyNotify) nm_ip6_device_destroy);
	priv->devices_by_index = g_hash_table_new (NULL, NULL);

	priv->netlink = nm_netlink_listener_get ();
	g_signal_connect (priv->netlink, "notification",
					  G_CALLBACK (netlink_notification), manager);
	nm_netlink_listener_subscribe (priv->netlink, RTNLGRP_IPV6_IFADDR, NULL);
	nm_netlink_listener_subscribe (priv->netlink, RTNLGRP_IPV6_PREFIX, NULL);
	nm_netlink_listener_subscribe (priv->netlink, RTNLGRP_ND_USEROPT, NULL);

	priv->nlh = nm_netlink_get_default_handle ();
	priv->addr_cache = rtnl_addr_alloc_cache (priv->nlh);
	priv->route_cache = rtnl_route_alloc_cache (priv->nlh);
}

static void
finalize (GObject *object)
{
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (object);

	g_hash_table_destroy (priv->devices_by_iface);
	g_hash_table_destroy (priv->devices_by_index);
	g_object_unref (priv->netlink);
	nl_cache_free (priv->addr_cache);
	nl_cache_free (priv->route_cache);

	G_OBJECT_CLASS (nm_ip6_manager_parent_class)->finalize (object);
}

static void
nm_ip6_manager_class_init (NMIP6ManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMIP6ManagerPrivate));

	/* virtual methods */
	object_class->finalize = finalize;

	/* signals */
	signals[ADDRCONF_COMPLETE] =
		g_signal_new ("addrconf-complete",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMIP6ManagerClass, addrconf_complete),
					  NULL, NULL,
					  _nm_marshal_VOID__STRING_BOOLEAN,
					  G_TYPE_NONE, 2,
					  G_TYPE_STRING,
					  G_TYPE_BOOLEAN);

	signals[CONFIG_CHANGED] =
		g_signal_new ("config-changed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMIP6ManagerClass, config_changed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__STRING,
					  G_TYPE_NONE, 1,
					  G_TYPE_STRING);
}

static void
nm_ip6_device_destroy (NMIP6Device *device)
{
	g_return_if_fail (device != NULL);

	/* reset the saved RA value */
	if (device->accept_ra_save_valid) {
		nm_utils_do_sysctl (device->accept_ra_path,
		                    device->accept_ra_save ? "1\n" : "0\n");
	}

	if (device->finish_addrconf_id)
		g_source_remove (device->finish_addrconf_id);
	if (device->config_changed_id)
		g_source_remove (device->config_changed_id);
	g_free (device->iface);
	if (device->rdnss_servers)
		g_array_free (device->rdnss_servers, TRUE);
	if (device->rdnss_timeout_id)
		g_source_remove (device->rdnss_timeout_id);

	g_free (device->accept_ra_path);
	g_slice_free (NMIP6Device, device);
}

static NMIP6Manager *
nm_ip6_manager_new (void)
{
	NMIP6Manager *manager;
	NMIP6ManagerPrivate *priv;

	manager = g_object_new (NM_TYPE_IP6_MANAGER, NULL);
	priv = NM_IP6_MANAGER_GET_PRIVATE (manager);

	if (!priv->devices_by_iface || !priv->devices_by_index) {
		nm_warning ("Error: not enough memory to initialize IP6 manager tables");
		g_object_unref (manager);
		manager = NULL;
	}

	return manager;
}

static NMIP6Device *
nm_ip6_manager_get_device (NMIP6Manager *manager, int ifindex)
{
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (manager);

	return g_hash_table_lookup (priv->devices_by_index,
								GINT_TO_POINTER (ifindex));
}

static gboolean
finish_addrconf (gpointer user_data)
{
	NMIP6Device *device = user_data;
	NMIP6Manager *manager = device->manager;
	char *iface_copy;

	device->finish_addrconf_id = 0;
	device->want_signal = FALSE;

	if (device->state >= device->target_state) {
		g_signal_emit (manager, signals[ADDRCONF_COMPLETE], 0,
					   device->iface, TRUE);
	} else {
		nm_info ("Device '%s' IP6 addrconf timed out or failed.",
				 device->iface);

		iface_copy = g_strdup (device->iface);

		nm_ip6_manager_cancel_addrconf (manager, device->iface);
		g_signal_emit (manager, signals[ADDRCONF_COMPLETE], 0,
					   iface_copy, FALSE);

		g_free (iface_copy);
	}

	return FALSE;
}

static gboolean
emit_config_changed (gpointer user_data)
{
	NMIP6Device *device = user_data;
	NMIP6Manager *manager = device->manager;

	device->config_changed_id = 0;
	g_signal_emit (manager, signals[CONFIG_CHANGED], 0, device->iface);
	return FALSE;
}

static void set_rdnss_timeout (NMIP6Device *device);

static gboolean
rdnss_expired (gpointer user_data)
{
	NMIP6Device *device = user_data;

	set_rdnss_timeout (device);
	emit_config_changed (device);
	return FALSE;
}

static void
set_rdnss_timeout (NMIP6Device *device)
{
	time_t expires = 0, now = time (NULL);
	NMIP6RDNSS *rdnss;
	int i;

	if (device->rdnss_timeout_id) {
		g_source_remove (device->rdnss_timeout_id);
		device->rdnss_timeout_id = 0;
	}

	/* Find the soonest expiration time. */
	for (i = 0; i < device->rdnss_servers->len; i++) {
		rdnss = &g_array_index (device->rdnss_servers, NMIP6RDNSS, i);
		if (rdnss->expires == 0)
			continue;

		/* If the entry has already expired, remove it; the "+ 1" is
		 * because g_timeout_add_seconds() might fudge the timing a
		 * bit.
		 */
		if (rdnss->expires <= now + 1) {
			g_array_remove_index_fast (device->rdnss_servers, i--);
			continue;
		}

		if (!expires || rdnss->expires < expires)
			expires = rdnss->expires;
	}

	if (expires) {
		device->rdnss_timeout_id = g_timeout_add_seconds (expires - now,
														  rdnss_expired,
														  device);
	}
}

static void
nm_ip6_device_sync_from_netlink (NMIP6Device *device, gboolean config_changed)
{
	NMIP6Manager *manager = device->manager;
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (manager);
	struct rtnl_addr *rtnladdr;
	struct nl_addr *nladdr;
	struct in6_addr *addr;
	struct rtnl_link *link;
	guint flags;

	for (rtnladdr = (struct rtnl_addr *)nl_cache_get_first (priv->addr_cache);
		 rtnladdr;
		 rtnladdr = (struct rtnl_addr *)nl_cache_get_next ((struct nl_object *)rtnladdr)) {
		if (rtnl_addr_get_ifindex (rtnladdr) != device->index)
			continue;

		nladdr = rtnl_addr_get_local (rtnladdr);
		if (!nladdr || nl_addr_get_family (nladdr) != AF_INET6)
			continue;

		addr = nl_addr_get_binary_addr (nladdr);
		if (IN6_IS_ADDR_LINKLOCAL (addr)) {
			if (device->state == NM_IP6_DEVICE_UNCONFIGURED)
				device->state = NM_IP6_DEVICE_GOT_LINK_LOCAL;
		} else {
			if (device->state < NM_IP6_DEVICE_GOT_ADDRESS)
				device->state = NM_IP6_DEVICE_GOT_ADDRESS;
		}
	}

	/* Note: we don't want to keep a cache of links, because the
	 * kernel doesn't send notifications when the flags change, so the
	 * cached rtnl_links would have out-of-date flags.
	 */
	link = nm_netlink_index_to_rtnl_link (device->index);
	flags = rtnl_link_get_flags (link);
	rtnl_link_put (link);

	if ((flags & IF_RA_RCVD) && device->state < NM_IP6_DEVICE_GOT_ROUTER_ADVERTISEMENT)
		device->state = NM_IP6_DEVICE_GOT_ROUTER_ADVERTISEMENT;

//	if (flags & (IF_RA_MANAGED | IF_RA_OTHERCONF))
//		device->need_dhcp = TRUE;

	if (device->want_signal) {
		if (device->state >= device->target_state ||
			device->state == NM_IP6_DEVICE_GOT_ROUTER_ADVERTISEMENT) {
			/* device->finish_addrconf_id may currently be a timeout
			 * rather than an idle, so we remove the existing source.
			 */
			if (device->finish_addrconf_id)
				g_source_remove (device->finish_addrconf_id);
			device->finish_addrconf_id = g_idle_add (finish_addrconf,
													 device);
		}
	} else if (config_changed) {
		if (!device->config_changed_id) {
			device->config_changed_id = g_idle_add (emit_config_changed,
													device);
		}
	}
}

static void
ref_object (struct nl_object *obj, void *data)
{
	struct nl_object **out = data;

	nl_object_get (obj);
	*out = obj;
}

static NMIP6Device *
process_addr (NMIP6Manager *manager, struct nl_msg *msg)
{
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (manager);
	NMIP6Device *device;
	struct rtnl_addr *rtnladdr;
	int old_size;

	rtnladdr = NULL;
	nl_msg_parse (msg, ref_object, &rtnladdr);
	if (!rtnladdr)
		return NULL;

	device = nm_ip6_manager_get_device (manager, rtnl_addr_get_ifindex (rtnladdr));

	old_size = nl_cache_nitems (priv->addr_cache);
	nl_cache_include (priv->addr_cache, (struct nl_object *)rtnladdr, NULL);
	rtnl_addr_put (rtnladdr);

	/* The kernel will re-notify us of automatically-added addresses
	 * every time it gets another router advertisement. We only want
	 * to notify higher levels if we actually changed something.
	 */
	if (nl_cache_nitems (priv->addr_cache) == old_size)
		return NULL;

	return device;
}

static NMIP6Device *
process_route (NMIP6Manager *manager, struct nl_msg *msg)
{
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (manager);
	NMIP6Device *device;
	struct rtnl_route *rtnlroute;
	int old_size;

	rtnlroute = NULL;
	nl_msg_parse (msg, ref_object, &rtnlroute);
	if (!rtnlroute)
		return NULL;

	device = nm_ip6_manager_get_device (manager, rtnl_route_get_oif (rtnlroute));

	old_size = nl_cache_nitems (priv->route_cache);
	nl_cache_include (priv->route_cache, (struct nl_object *)rtnlroute, NULL);
	rtnl_route_put (rtnlroute);

	/* As above in process_addr */
	if (nl_cache_nitems (priv->route_cache) == old_size)
		return NULL;

	return device;
}

static NMIP6Device *
process_prefix (NMIP6Manager *manager, struct nl_msg *msg)
{
	struct prefixmsg *pmsg;
	NMIP6Device *device;

	/* We don't care about the prefix itself, but if we receive a
	 * router advertisement telling us to use DHCP, we might not
	 * get any RTM_NEWADDRs or RTM_NEWROUTEs, so this is our only
	 * way to notice immediately that an RA was received.
	 */

	pmsg = (struct prefixmsg *) NLMSG_DATA (nlmsg_hdr (msg));
	device = nm_ip6_manager_get_device (manager, pmsg->prefix_ifindex);

	if (!device || !device->want_signal)
		return NULL;

	return device;
}

/* RDNSS parsing code based on rdnssd, Copyright 2007 Pierre Ynard,
 * Rémi Denis-Courmont. GPLv2/3
 */

#define ND_OPT_RDNSS 25
struct nd_opt_rdnss {
	uint8_t nd_opt_rdnss_type;
	uint8_t nd_opt_rdnss_len;
	uint16_t nd_opt_rdnss_reserved1;
	uint32_t nd_opt_rdnss_lifetime;
	/* followed by one or more IPv6 addresses */
};

static NMIP6Device *
process_nduseropt (NMIP6Manager *manager, struct nl_msg *msg)
{
	NMIP6Device *device;
	struct nduseroptmsg *ndmsg;
	struct nd_opt_hdr *opt;
	guint opts_len, i;
	time_t now = time (NULL);
	struct nd_opt_rdnss *rdnss_opt;
	struct in6_addr *addr;
	GArray *servers;
	NMIP6RDNSS server, *sa, *sb;
	gboolean changed;

	ndmsg = (struct nduseroptmsg *) NLMSG_DATA (nlmsg_hdr (msg));

	if (ndmsg->nduseropt_family != AF_INET6 ||
		ndmsg->nduseropt_icmp_type != ND_ROUTER_ADVERT ||
		ndmsg->nduseropt_icmp_code != 0)
		return NULL;

	device = nm_ip6_manager_get_device (manager, ndmsg->nduseropt_ifindex);
	if (!device)
		return NULL;

	servers = g_array_new (FALSE, FALSE, sizeof (NMIP6RDNSS));

	opt = (struct nd_opt_hdr *) (ndmsg + 1);
	opts_len = ndmsg->nduseropt_opts_len;

	while (opts_len >= sizeof (struct nd_opt_hdr)) {
		size_t nd_opt_len = opt->nd_opt_len;

		if (nd_opt_len == 0 || opts_len < (nd_opt_len << 3))
			break;

		if (opt->nd_opt_type != ND_OPT_RDNSS)
			goto next;

		if (nd_opt_len < 3 || (nd_opt_len & 1) == 0)
			goto next;

		rdnss_opt = (struct nd_opt_rdnss *) opt;

		server.expires = now + ntohl (rdnss_opt->nd_opt_rdnss_lifetime);
		for (addr = (struct in6_addr *) (rdnss_opt + 1); nd_opt_len >= 2; addr++, nd_opt_len -= 2) {
			server.addr = *addr;
			g_array_append_val (servers, server);
		}

	next:
		opts_len -= opt->nd_opt_len << 3;
		opt = (struct nd_opt_hdr *) ((uint8_t *) opt + (opt->nd_opt_len << 3));
	}

	/* See if anything (other than expiration time) changed */
	if (servers->len != device->rdnss_servers->len)
		changed = TRUE;
	else {
		for (i = 0; i < servers->len; i++) {
			sa = &(g_array_index (servers, NMIP6RDNSS, i));
			sb = &(g_array_index (device->rdnss_servers, NMIP6RDNSS, i));
			if (memcmp (&sa->addr, &sb->addr, sizeof (struct in6_addr)) != 0) {
				changed = TRUE;
				break;
			}
		}
		changed = FALSE;
	}

	if (changed) {
		g_array_free (device->rdnss_servers, TRUE);
		device->rdnss_servers = servers;
	} else
		g_array_free (servers, TRUE);

	/* Timeouts may have changed even if IPs didn't */
	set_rdnss_timeout (device);

	if (changed)
		return device;
	else
		return NULL;
}

static void
netlink_notification (NMNetlinkListener *listener, struct nl_msg *msg, gpointer user_data)
{
	NMIP6Manager *manager = (NMIP6Manager *) user_data;
	NMIP6Device *device;
	struct nlmsghdr *hdr;
	gboolean config_changed = FALSE;

	hdr = nlmsg_hdr (msg);
	switch (hdr->nlmsg_type) {
	case RTM_NEWADDR:
	case RTM_DELADDR:
		device = process_addr (manager, msg);
		config_changed = TRUE;
		break;

	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		device = process_route (manager, msg);
		config_changed = TRUE;
		break;

	case RTM_NEWPREFIX:
		device = process_prefix (manager, msg);
		break;

	case RTM_NEWNDUSEROPT:
		device = process_nduseropt (manager, msg);
		config_changed = TRUE;
		break;

	default:
		return;
	}

	if (device)
		nm_ip6_device_sync_from_netlink (device, config_changed);
}

static NMIP6Device *
nm_ip6_device_new (NMIP6Manager *manager, const char *iface)
{
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (manager);
	NMIP6Device *device;
	GError *error = NULL;
	char *contents = NULL;

	device = g_slice_new0 (NMIP6Device);
	if (!device) {
		nm_warning ("%s: Out of memory creating IP6 addrconf object.", iface);
		return NULL;
	}

	device->iface = g_strdup (iface);
	if (!device->iface) {
		nm_warning ("%s: Out of memory creating IP6 addrconf object "
		            "property 'iface'.",
		            iface);
		goto error;
	}
	device->index = nm_netlink_iface_to_index (iface);

	device->accept_ra_path = g_strdup_printf ("/proc/sys/net/ipv6/conf/%s/accept_ra", iface);
	if (!device->accept_ra_path) {
		nm_warning ("%s: Out of memory creating IP6 addrconf object "
		            "property 'accept_ra_path'.",
		            iface);
		goto error;
	}

	device->manager = manager;

	device->rdnss_servers = g_array_new (FALSE, FALSE, sizeof (NMIP6RDNSS));

	g_hash_table_replace (priv->devices_by_iface, device->iface, device);
	g_hash_table_replace (priv->devices_by_index, GINT_TO_POINTER (device->index), device);

	/* Grab the original value of "accept_ra" so we can restore it when the
	 * device is taken down.
	 */
	if (!g_file_get_contents (device->accept_ra_path, &contents, NULL, &error)) {
		nm_warning ("%s: error reading %s: (%d) %s",
		            iface, device->accept_ra_path,
		            error ? error->code : -1,
		            error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	} else {
		long int tmp;

		errno = 0;
		tmp = strtol (contents, NULL, 10);
		if ((errno == 0) && (tmp == 0 || tmp == 1)) {
			device->accept_ra_save = (guint32) tmp;
			device->accept_ra_save_valid = TRUE;
		}
		g_free (contents);
	}

	return device;

error:
	nm_ip6_device_destroy (device);
	return NULL;
}

void
nm_ip6_manager_prepare_interface (NMIP6Manager *manager,
								  const char *iface,
								  NMSettingIP6Config *s_ip6)
{
	NMIP6ManagerPrivate *priv;
	NMIP6Device *device;
	const char *method = NULL;

	g_return_if_fail (NM_IS_IP6_MANAGER (manager));
	g_return_if_fail (iface != NULL);

	priv = NM_IP6_MANAGER_GET_PRIVATE (manager);

	device = nm_ip6_device_new (manager, iface);

	if (s_ip6)
		method = nm_setting_ip6_config_get_method (s_ip6);
	if (!method)
		method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;

	if (   !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)
		|| !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL))
		device->target_state = NM_IP6_DEVICE_GOT_LINK_LOCAL;
	else
		device->target_state = NM_IP6_DEVICE_GOT_ADDRESS;

	g_return_if_fail (strchr (iface, '/') == NULL &&
					  strcmp (iface, "all") != 0 &&
					  strcmp (iface, "default") != 0);

	/* Turn router advertisement acceptance on or off... */
	nm_utils_do_sysctl (device->accept_ra_path,
	                    device->target_state >= NM_IP6_DEVICE_GOT_ADDRESS ? "1\n" : "0\n");
}

void
nm_ip6_manager_begin_addrconf (NMIP6Manager *manager,
							   const char *iface)
{
	NMIP6ManagerPrivate *priv;
	NMIP6Device *device;

	g_return_if_fail (NM_IS_IP6_MANAGER (manager));
	g_return_if_fail (iface != NULL);

	priv = NM_IP6_MANAGER_GET_PRIVATE (manager);

	device = (NMIP6Device *) g_hash_table_lookup (priv->devices_by_iface, iface);
	g_return_if_fail (device != NULL);

	nm_info ("Activation (%s) Beginning IP6 addrconf.", iface);

	/* Set up a timeout on the transaction to kill it after the timeout */
	device->finish_addrconf_id = g_timeout_add_seconds (NM_IP6_TIMEOUT,
														finish_addrconf,
														device);

	/* Sync flags, etc, from netlink; this will also notice if the
	 * device is already fully configured and schedule the
	 * ADDRCONF_COMPLETE signal in that case.
	 */
	nm_ip6_device_sync_from_netlink (device, FALSE);
}

void
nm_ip6_manager_cancel_addrconf (NMIP6Manager *manager,
								const char *iface)
{
	NMIP6ManagerPrivate *priv;
	NMIP6Device *device;

	g_return_if_fail (NM_IS_IP6_MANAGER (manager));
	g_return_if_fail (iface != NULL);

	priv = NM_IP6_MANAGER_GET_PRIVATE (manager);

	device = g_hash_table_lookup (priv->devices_by_iface, iface);
	if (device) {
		g_hash_table_remove (priv->devices_by_index, GINT_TO_POINTER (device->index));
		g_hash_table_remove (priv->devices_by_iface, iface);
	}
}

NMIP6Config *
nm_ip6_manager_get_ip6_config (NMIP6Manager *manager,
							   const char *iface)
{
	NMIP6ManagerPrivate *priv;
	NMIP6Device *device;
	NMIP6Config *config;
	struct rtnl_addr *rtnladdr;
	struct nl_addr *nladdr;
	struct in6_addr *addr;
	NMIP6Address *ip6addr;
	struct rtnl_route *rtnlroute;
	struct nl_addr *nldest, *nlgateway;
	struct in6_addr *dest, *gateway;
	uint32_t metric;
	NMIP6Route *ip6route;
	int i;

	g_return_val_if_fail (NM_IS_IP6_MANAGER (manager), NULL);
	g_return_val_if_fail (iface != NULL, NULL);

	priv = NM_IP6_MANAGER_GET_PRIVATE (manager);

	device = (NMIP6Device *) g_hash_table_lookup (priv->devices_by_iface, iface);
	if (!device) {
		nm_warning ("Device '%s' addrconf not started.", iface);
		return NULL;
	}

	config = nm_ip6_config_new ();
	if (!config) {
		nm_warning ("%s: Out of memory creating IP6 config object.",
		            iface);
		return NULL;
	}

	/* Add addresses */
	for (rtnladdr = (struct rtnl_addr *)nl_cache_get_first (priv->addr_cache);
		 rtnladdr;
		 rtnladdr = (struct rtnl_addr *)nl_cache_get_next ((struct nl_object *)rtnladdr)) {
		if (rtnl_addr_get_ifindex (rtnladdr) != device->index)
			continue;

		nladdr = rtnl_addr_get_local (rtnladdr);
		if (!nladdr || nl_addr_get_family (nladdr) != AF_INET6)
			continue;

		addr = nl_addr_get_binary_addr (nladdr);
		ip6addr = nm_ip6_address_new ();
		nm_ip6_address_set_prefix (ip6addr, rtnl_addr_get_prefixlen (rtnladdr));
		nm_ip6_address_set_address (ip6addr, addr);
		nm_ip6_config_take_address (config, ip6addr);
	}

	/* Add routes */
	for (rtnlroute = (struct rtnl_route *)nl_cache_get_first (priv->route_cache);
		 rtnlroute;
		 rtnlroute = (struct rtnl_route *)nl_cache_get_next ((struct nl_object *)rtnlroute)) {
		if (rtnl_route_get_oif (rtnlroute) != device->index)
			continue;

		nldest = rtnl_route_get_dst (rtnlroute);
		if (!nldest || nl_addr_get_family (nldest) != AF_INET6)
			continue;
		dest = nl_addr_get_binary_addr (nldest);

		nlgateway = rtnl_route_get_gateway (rtnlroute);
		if (!nlgateway || nl_addr_get_family (nlgateway) != AF_INET6)
			continue;
		gateway = nl_addr_get_binary_addr (nlgateway);

		ip6route = nm_ip6_route_new ();
		nm_ip6_route_set_dest (ip6route, dest);
		nm_ip6_route_set_prefix (ip6route, rtnl_route_get_dst_len (rtnlroute));
		nm_ip6_route_set_next_hop (ip6route, gateway);
		metric = rtnl_route_get_metric (rtnlroute, 1);
		if (metric != UINT_MAX)
			nm_ip6_route_set_metric (ip6route, metric);
		nm_ip6_config_take_route (config, ip6route);
	}

	/* Add DNS servers */
	if (device->rdnss_servers) {
		NMIP6RDNSS *rdnss = (NMIP6RDNSS *)(device->rdnss_servers->data);

		for (i = 0; i < device->rdnss_servers->len; i++)
			nm_ip6_config_add_nameserver (config, &rdnss[i].addr);
	}

	return config;
}
