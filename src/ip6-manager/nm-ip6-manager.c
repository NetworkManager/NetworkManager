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
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
 */

#define _GNU_SOURCE /* for struct in6_pktinfo */

#include <errno.h>
#include <unistd.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

#include <netlink/route/addr.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>

#include "nm-ip6-manager.h"
#include "nm-netlink-monitor.h"
#include "NetworkManagerUtils.h"
#include "nm-logging.h"
#include "nm-utils.h"
#include "nm-platform.h"

/* Pre-DHCP addrconf timeout, in seconds */
#define NM_IP6_TIMEOUT 20

/* FIXME? Stolen from the kernel sources */
#define IF_RA_OTHERCONF 0x80
#define IF_RA_MANAGED   0x40
#define IF_RA_RCVD      0x20
#define IF_RS_SENT      0x10

typedef struct {
	NMNetlinkMonitor *monitor;
	GHashTable *devices;

	guint request_ip6_info_id;

	struct nl_sock *nlh;
	struct nl_cache *addr_cache, *route_cache;

	guint netlink_id;
} NMIP6ManagerPrivate;

#define NM_IP6_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IP6_MANAGER, NMIP6ManagerPrivate))

G_DEFINE_TYPE (NMIP6Manager, nm_ip6_manager, G_TYPE_OBJECT)

enum {
	ADDRCONF_COMPLETE,
	CONFIG_CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef enum {
	NM_IP6_DEVICE_UNCONFIGURED,
	NM_IP6_DEVICE_GOT_LINK_LOCAL,
	NM_IP6_DEVICE_GOT_ROUTER_ADVERTISEMENT,
	NM_IP6_DEVICE_GOT_ADDRESS,
	NM_IP6_DEVICE_TIMED_OUT
} NMIP6DeviceState;

typedef struct {
	struct in6_addr addr;
	time_t expires;
} NMIP6RDNSS;

typedef struct {
	char domain[256];
	time_t expires;
} NMIP6DNSSL;

/******************************************************************/

typedef struct {
	NMIP6Manager *manager;
	char *iface;
	int ifindex;
	/* +7 since this field is used directly by stuff that expects
	 * padding to multiples of 8 bytes.
	 */
	guint8 hwaddr[NM_UTILS_HWADDR_LEN_MAX + 7];
	guint hwaddr_len;

	gboolean has_linklocal;
	gboolean has_nonlinklocal;
	guint dhcp_opts;

	char *disable_ip6_path;
	gboolean disable_ip6_save_valid;
	gint32 disable_ip6_save;

	guint finish_addrconf_id;
	guint config_changed_id;

	NMIP6DeviceState state;
	NMIP6DeviceState target_state;
	gboolean addrconf_complete;

	guint sync_from_netlink_id;

	GArray *rdnss_servers;
	guint rdnss_timeout_id;
	guint32 rdnss_timeout;

	GArray *dnssl_domains;
	guint dnssl_timeout_id;
	guint32 dnssl_timeout;

	time_t last_solicitation;

	guint32 ra_flags;
} NMIP6Device;

static void
clear_config_changed (NMIP6Device *device)
{
	if (device->config_changed_id)
		g_source_remove (device->config_changed_id);
	device->config_changed_id = 0;
}

static void
nm_ip6_device_destroy (NMIP6Device *device)
{
	g_return_if_fail (device != NULL);

	/* reset the saved IPv6 value */
	if (device->disable_ip6_save_valid) {
		nm_utils_do_sysctl (device->disable_ip6_path,
		                    device->disable_ip6_save ? "1" : "0");
	}

	if (device->finish_addrconf_id)
		g_source_remove (device->finish_addrconf_id);

	clear_config_changed (device);

	g_free (device->iface);
	if (device->sync_from_netlink_id)
		g_source_remove (device->sync_from_netlink_id);
	if (device->rdnss_servers)
		g_array_free (device->rdnss_servers, TRUE);
	if (device->rdnss_timeout_id)
		g_source_remove (device->rdnss_timeout_id);
	if (device->dnssl_domains)
		g_array_free (device->dnssl_domains, TRUE);
	if (device->dnssl_timeout_id)
		g_source_remove (device->dnssl_timeout_id);

	g_slice_free (NMIP6Device, device);
}

static NMIP6Device *
nm_ip6_device_new (NMIP6Manager *manager,
                   int ifindex,
                   const guint8 *hwaddr,
                   guint hwaddr_len)
{
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (manager);
	NMIP6Device *device;

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (hwaddr != NULL, NULL);
	g_return_val_if_fail (hwaddr_len > 0, NULL);
	g_return_val_if_fail (hwaddr_len <= NM_UTILS_HWADDR_LEN_MAX, NULL);

	device = g_slice_new0 (NMIP6Device);
	device->ifindex = ifindex;
	device->iface = g_strdup (nm_platform_link_get_name (ifindex));
	if (!device->iface) {
		nm_log_err (LOGD_IP6, "(%d): could not find interface name from index.",
		            ifindex);
		goto error;
	}

	memcpy (device->hwaddr, hwaddr, hwaddr_len);
	device->hwaddr_len = hwaddr_len;

	device->manager = manager;

	device->rdnss_servers = g_array_new (FALSE, FALSE, sizeof (NMIP6RDNSS));

	device->dnssl_domains = g_array_new (FALSE, FALSE, sizeof (NMIP6DNSSL));

	g_hash_table_replace (priv->devices, GINT_TO_POINTER (device->ifindex), device);

	/* and the original value of IPv6 enable/disable */
	device->disable_ip6_path = g_strdup_printf ("/proc/sys/net/ipv6/conf/%s/disable_ipv6",
	                                            device->iface);
	g_assert (device->disable_ip6_path);
	device->disable_ip6_save_valid = nm_utils_get_proc_sys_net_value_with_bounds (device->disable_ip6_path,
	                                                                              device->iface,
	                                                                              &device->disable_ip6_save,
	                                                                              0, 1);

	return device;

error:
	nm_ip6_device_destroy (device);
	return NULL;
}

static NMIP6Device *
nm_ip6_manager_get_device (NMIP6Manager *manager, int ifindex)
{
	NMIP6ManagerPrivate *priv;

	g_return_val_if_fail (NM_IS_IP6_MANAGER (manager), NULL);

	priv = NM_IP6_MANAGER_GET_PRIVATE (manager);
	return g_hash_table_lookup (priv->devices, GINT_TO_POINTER (ifindex));
}

static void
device_send_router_solicitation (NMIP6Device *device, const char *why)
{
	int sock, hops;
	struct sockaddr_in6 sin6;
	struct nd_router_solicit rs;
	struct nd_opt_hdr lladdr_hdr;
	static const guint8 local_routers_addr[] =
		{ 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
	struct msghdr mhdr;
	struct iovec iov[3];
	struct cmsghdr *cmsg;
	struct in6_pktinfo *ipi;
	guint8 cmsgbuf[128];
	int cmsglen = 0;
	time_t now;

	now = time (NULL);
	if (device->last_solicitation > now - 5)
		return;
	device->last_solicitation = now;

	nm_log_dbg (LOGD_IP6, "(%s): %s: sending router solicitation",
	            device->iface, why);

	sock = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (sock < 0) {
		nm_log_dbg (LOGD_IP6, "(%s): could not create ICMPv6 socket: %s",
		            device->iface, g_strerror (errno));
		return;
	}

	hops = 255;
	if (   setsockopt (sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof (hops)) == -1
	    || setsockopt (sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof (hops)) == -1) {
		nm_log_dbg (LOGD_IP6, "(%s): could not set hop limit on ICMPv6 socket: %s",
		            device->iface, g_strerror (errno));
		close (sock);
		return;
	}

	/* Use the "all link-local routers" multicast address */
	memset (&sin6, 0, sizeof (sin6));
	memcpy (&sin6.sin6_addr, local_routers_addr, sizeof (sin6.sin6_addr));
	mhdr.msg_name = &sin6;
	mhdr.msg_namelen = sizeof (sin6);

	/* Build the router solicitation */
	mhdr.msg_iov = iov;
	memset (&rs, 0, sizeof (rs));
	rs.nd_rs_type = ND_ROUTER_SOLICIT;
	iov[0].iov_len  = sizeof (rs);
	iov[0].iov_base = &rs;

	if (device->hwaddr_len > 0) {
		memset (&lladdr_hdr, 0, sizeof (lladdr_hdr));
		lladdr_hdr.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
		lladdr_hdr.nd_opt_len = (sizeof (lladdr_hdr) + device->hwaddr_len + 7) % 8;
		iov[1].iov_len  = sizeof (lladdr_hdr);
		iov[1].iov_base = &lladdr_hdr;

		iov[2].iov_len  = (lladdr_hdr.nd_opt_len * 8) - 2;
		iov[2].iov_base = device->hwaddr;

		mhdr.msg_iovlen = 3;
	} else
		mhdr.msg_iovlen = 1;

	/* Force this to go on the right device */
	memset (cmsgbuf, 0, sizeof (cmsgbuf));
	cmsg = (struct cmsghdr *) cmsgbuf;
	cmsglen = CMSG_SPACE (sizeof (*ipi));
	cmsg->cmsg_len = CMSG_LEN (sizeof (*ipi));
	cmsg->cmsg_level = SOL_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	ipi = (struct in6_pktinfo *) CMSG_DATA (cmsg);
	ipi->ipi6_ifindex = device->ifindex;

	mhdr.msg_control = cmsg;
	mhdr.msg_controllen = cmsglen;

	if (sendmsg (sock, &mhdr, 0) == -1) {
		nm_log_dbg (LOGD_IP6, "(%s): could not send router solicitation: %s",
		            device->iface, g_strerror (errno));
	}

	close (sock);
}

static char *
device_get_iface (NMIP6Device *device)
{
	return device ? device->iface : "unknown";
}

static const char *
state_to_string (NMIP6DeviceState state)
{
	switch (state) {
	case NM_IP6_DEVICE_UNCONFIGURED:
		return "unconfigured";
	case NM_IP6_DEVICE_GOT_LINK_LOCAL:
		return "got-link-local";
	case NM_IP6_DEVICE_GOT_ROUTER_ADVERTISEMENT:
		return "got-router-advertisement";
	case NM_IP6_DEVICE_GOT_ADDRESS:
		return "got-address";
	case NM_IP6_DEVICE_TIMED_OUT:
		return "timed-out";
	default:
		return "unknown";
	}
}

static gboolean
device_set_state (NMIP6Device *device, NMIP6DeviceState state)
{
	NMIP6DeviceState old_state;

	g_return_val_if_fail (device != NULL, FALSE);

	if (state == device->state)
		return FALSE;

	old_state = device->state;
	device->state = state;
	nm_log_dbg (LOGD_IP6, "(%s) IP6 device state: %s -> %s",
	            device_get_iface (device),
	            state_to_string (old_state),
	            state_to_string (state));
	return TRUE;
}

static char *
ra_flags_to_string (guint32 ra_flags)
{
	GString *s = g_string_sized_new (20);

	g_string_append (s, " (");
	if (ra_flags & IF_RS_SENT)
		g_string_append_c (s, 'S');

	if (ra_flags & IF_RA_RCVD)
		g_string_append_c (s, 'R');

	if (ra_flags & IF_RA_MANAGED)
		g_string_append_c (s, 'M');

	if (ra_flags & IF_RA_OTHERCONF)
		g_string_append_c (s, 'O');

	g_string_append_c (s, ')');
	return g_string_free (s, FALSE);
}

static gboolean
device_set_ra_flags (NMIP6Device *device, guint ra_flags)
{
	guint old_ra_flags;
	gchar *ra_flags_str, *old_ra_flags_str;

	g_return_val_if_fail (device != NULL, FALSE);

	if (ra_flags == device->ra_flags)
		return FALSE;

	old_ra_flags = device->ra_flags;
	device->ra_flags = ra_flags;

	if (nm_logging_level_enabled (LOGL_DEBUG)) {
		ra_flags_str = ra_flags_to_string (ra_flags);
		old_ra_flags_str = ra_flags_to_string (old_ra_flags);
		nm_log_dbg (LOGD_IP6, "(%s) IP6 device ra_flags: 0x%08x %s -> 0x%08x %s",
		            device_get_iface (device),
		            old_ra_flags, old_ra_flags_str,
		            ra_flags, ra_flags_str);
		g_free (ra_flags_str);
		g_free (old_ra_flags_str);
	}

	return TRUE;
}

/******************************************************************/

typedef struct {
	NMIP6Device *device;
	gboolean success;
} CallbackInfo;

static gboolean
finish_addrconf (gpointer user_data)
{
	CallbackInfo *info = user_data;
	NMIP6Device *device = info->device;
	NMIP6Manager *manager = device->manager;
	int ifindex;

	device->finish_addrconf_id = 0;
	device->addrconf_complete = TRUE;
	ifindex = device->ifindex;

	/* And tell listeners that addrconf is complete */
	if (info->success) {
		g_signal_emit (manager, signals[ADDRCONF_COMPLETE], 0,
		               ifindex, device->dhcp_opts, TRUE);
	} else {
		nm_log_info (LOGD_IP6, "(%s): IP6 addrconf timed out or failed.",
		             device->iface);

		nm_ip6_manager_cancel_addrconf (manager, ifindex);
		g_signal_emit (manager, signals[ADDRCONF_COMPLETE], 0,
		               ifindex, IP6_DHCP_OPT_NONE, FALSE);
	}

	return FALSE;
}

static gboolean
emit_config_changed (gpointer user_data)
{
	CallbackInfo *info = user_data;
	NMIP6Device *device = info->device;
	NMIP6Manager *manager = device->manager;

	device->config_changed_id = 0;
	g_signal_emit (manager, signals[CONFIG_CHANGED], 0,
	               device->ifindex,
	               device->dhcp_opts,
	               info->success);
	return FALSE;
}

static void set_rdnss_timeout (NMIP6Device *device);

static gboolean
rdnss_expired (gpointer user_data)
{
	NMIP6Device *device = user_data;
	CallbackInfo info = { device, FALSE };

	nm_log_dbg (LOGD_IP6, "(%s): IPv6 RDNSS information expired", device->iface);

	set_rdnss_timeout (device);
	clear_config_changed (device);
	emit_config_changed (&info);
	return FALSE;
}

static gboolean
rdnss_needs_refresh (gpointer user_data)
{
	NMIP6Device *device = user_data;
	gchar *msg;

	msg = g_strdup_printf ("IPv6 RDNSS due to expire in %d seconds",
	                       device->rdnss_timeout);
	device_send_router_solicitation (device, msg);
	g_free (msg);

	set_rdnss_timeout (device);

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
			char buf[INET6_ADDRSTRLEN + 1];

			if (inet_ntop (AF_INET6, &(rdnss->addr), buf, sizeof (buf)) > 0) {
				nm_log_dbg (LOGD_IP6, "(%s): removing expired RA-provided nameserver %s",
				            device->iface, buf);
			}
			g_array_remove_index (device->rdnss_servers, i--);
			continue;
		}

		if (!expires || rdnss->expires < expires)
			expires = rdnss->expires;
	}

	if (expires) {
		gchar *msg;

		device->rdnss_timeout = MIN (expires - now, G_MAXUINT32 - 1);

		if (device->rdnss_timeout <= 5) {
			msg = g_strdup_printf ("IPv6 RDNSS about to expire in %d seconds",
			                       device->rdnss_timeout);
			device_send_router_solicitation (device, msg);
			g_free (msg);
			device->rdnss_timeout_id = g_timeout_add_seconds (device->rdnss_timeout,
			                                                  rdnss_expired,
			                                                  device);
		} else {
			device->rdnss_timeout_id = g_timeout_add_seconds (device->rdnss_timeout / 2,
			                                                  rdnss_needs_refresh,
			                                                  device);
		}
	}
}

static void set_dnssl_timeout (NMIP6Device *device);

static gboolean
dnssl_expired (gpointer user_data)
{
	NMIP6Device *device = user_data;
	CallbackInfo info = { device, FALSE };

	nm_log_dbg (LOGD_IP6, "(%s): IPv6 DNSSL information expired", device->iface);

	set_dnssl_timeout (device);
	clear_config_changed (device);
	emit_config_changed (&info);
	return FALSE;
}

static gboolean
dnssl_needs_refresh (gpointer user_data)
{
	NMIP6Device *device = user_data;
	gchar *msg;

	msg = g_strdup_printf ("IPv6 DNSSL due to expire in %d seconds",
	                       device->dnssl_timeout);
	device_send_router_solicitation (device, msg);
	g_free (msg);

	set_dnssl_timeout (device);

	return FALSE;
}

static void
set_dnssl_timeout (NMIP6Device *device)
{
	time_t expires = 0, now = time (NULL);
	NMIP6DNSSL *dnssl;
	int i;

	if (device->dnssl_timeout_id) {
		g_source_remove (device->dnssl_timeout_id);
		device->dnssl_timeout_id = 0;
	}

	/* Find the soonest expiration time. */
	for (i = 0; i < device->dnssl_domains->len; i++) {
		dnssl = &g_array_index (device->dnssl_domains, NMIP6DNSSL, i);
		if (dnssl->expires == 0)
			continue;

		/* If the entry has already expired, remove it; the "+ 1" is
		 * because g_timeout_add_seconds() might fudge the timing a
		 * bit.
		 */
		if (dnssl->expires <= now + 1) {
			nm_log_dbg (LOGD_IP6, "(%s): removing expired RA-provided domain %s",
			            device->iface, dnssl->domain);
			g_array_remove_index (device->dnssl_domains, i--);
			continue;
		}

		if (!expires || dnssl->expires < expires)
			expires = dnssl->expires;
	}

	if (expires) {
		gchar *msg;

		device->dnssl_timeout = MIN (expires - now, G_MAXUINT32 - 1);

		if (device->dnssl_timeout <= 5) {
			msg = g_strdup_printf ("IPv6 DNSSL about to expire in %d seconds",
			                       device->dnssl_timeout);
			device_send_router_solicitation (device, msg);
			g_free (msg);
			device->dnssl_timeout_id = g_timeout_add_seconds (device->dnssl_timeout,
			                                                  dnssl_expired,
			                                                  device);
		} else {
			device->dnssl_timeout_id = g_timeout_add_seconds (device->dnssl_timeout / 2,
			                                                  dnssl_needs_refresh,
			                                                  device);
		}
	}
}

static CallbackInfo *
callback_info_new (NMIP6Device *device, gboolean success)
{
	CallbackInfo *info;

	info = g_malloc0 (sizeof (CallbackInfo));
	info->device = device;
	info->success = success;
	return info;
}

static void
check_addresses (NMIP6Device *device)
{
	NMIP6Manager *manager = device->manager;
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (manager);
	struct rtnl_addr *rtnladdr;
	struct nl_addr *nladdr;
	struct in6_addr *addr;

	/* Reset address information */
	device->has_linklocal = FALSE;
	device->has_nonlinklocal = FALSE;

	/* Look for any IPv6 addresses the kernel may have set for the device */
	for (rtnladdr = (struct rtnl_addr *) nl_cache_get_first (priv->addr_cache);
		 rtnladdr;
		 rtnladdr = (struct rtnl_addr *) nl_cache_get_next ((struct nl_object *) rtnladdr)) {

		if (rtnl_addr_get_ifindex (rtnladdr) != device->ifindex)
			continue;

		nladdr = rtnl_addr_get_local (rtnladdr);
		if (!nladdr || nl_addr_get_family (nladdr) != AF_INET6)
			continue;

		addr = nl_addr_get_binary_addr (nladdr);

		if (IN6_IS_ADDR_LINKLOCAL (addr)) {
			if (device->state == NM_IP6_DEVICE_UNCONFIGURED)
				device_set_state (device, NM_IP6_DEVICE_GOT_LINK_LOCAL);
			device->has_linklocal = TRUE;
		} else {
			if (device->state < NM_IP6_DEVICE_GOT_ADDRESS)
				device_set_state (device, NM_IP6_DEVICE_GOT_ADDRESS);
			device->has_nonlinklocal = TRUE;
		}
	}

	/* There might be a LL address hanging around on the interface from
	 * before in the initial run, but if it goes away later, make sure we
	 * regress from GOT_LINK_LOCAL back to UNCONFIGURED.
	 */
	if ((device->state == NM_IP6_DEVICE_GOT_LINK_LOCAL) && !device->has_linklocal)
		device_set_state (device, NM_IP6_DEVICE_UNCONFIGURED);
}

static void
check_ra_flags (NMIP6Device *device)
{
	device->dhcp_opts = IP6_DHCP_OPT_NONE;

	/* We only care about router advertisements if we want a real IPv6 address */
	if (   (device->target_state == NM_IP6_DEVICE_GOT_ADDRESS)
	    && (device->ra_flags & IF_RA_RCVD)) {

		if (device->state < NM_IP6_DEVICE_GOT_ROUTER_ADVERTISEMENT)
			device_set_state (device, NM_IP6_DEVICE_GOT_ROUTER_ADVERTISEMENT);

		if (device->ra_flags & IF_RA_MANAGED) {
			device->dhcp_opts = IP6_DHCP_OPT_MANAGED;
			nm_log_dbg (LOGD_IP6, "router advertisement deferred to DHCPv6");
		} else if (device->ra_flags & IF_RA_OTHERCONF) {
			device->dhcp_opts = IP6_DHCP_OPT_OTHERCONF;
			nm_log_dbg (LOGD_IP6, "router advertisement requests parallel DHCPv6");
		}
	}
}

static void
check_addrconf_complete (NMIP6Device *device)
{
	CallbackInfo *info;

	if (!device->addrconf_complete) {
		/* Managed mode (ie DHCP only) short-circuits automatic addrconf, so
		 * we don't bother waiting for the device's target state to be reached
		 * when the RA requests managed mode.
		 */
		if (   (device->state >= device->target_state)
		    || (device->dhcp_opts == IP6_DHCP_OPT_MANAGED)) {
			/* device->finish_addrconf_id may currently be a timeout
			 * rather than an idle, so we remove the existing source.
			 */
			if (device->finish_addrconf_id)
				g_source_remove (device->finish_addrconf_id);

			nm_log_dbg (LOGD_IP6, "(%s): reached target state or Managed-mode requested (dhcp opts 0x%X)",
			            device->iface,
			            device->dhcp_opts);

			info = callback_info_new (device, TRUE);
			device->finish_addrconf_id = g_idle_add_full (G_PRIORITY_DEFAULT_IDLE,
			                                              finish_addrconf,
			                                              info,
			                                              (GDestroyNotify) g_free);
		}
	} else {
		if (!device->config_changed_id) {
			gboolean success = TRUE;

			/* If for some reason an RA-provided address disappeared, we need
			 * to make sure we fail the connection as it's no longer valid.
			 */
			if (   (device->state == NM_IP6_DEVICE_GOT_ADDRESS)
			    && (device->target_state == NM_IP6_DEVICE_GOT_ADDRESS)
			    && !device->has_nonlinklocal) {
				nm_log_dbg (LOGD_IP6, "(%s): RA-provided address no longer found",
				            device->iface);
				success = FALSE;
			}

			info = callback_info_new (device, success);
			device->config_changed_id = g_idle_add_full (G_PRIORITY_DEFAULT_IDLE,
			                                             emit_config_changed,
			                                             info,
			                                             (GDestroyNotify) g_free);
		}
	}
}

static gboolean
device_sync_from_netlink (gpointer user_data)
{
	NMIP6Device *device = (NMIP6Device *) user_data;

	nm_log_dbg (LOGD_IP6, "(%s): syncing from netlink", device->iface);

	check_addresses (device);
	check_ra_flags (device);
	check_addrconf_complete (device);

	device->sync_from_netlink_id = 0;
	return FALSE;
}

static void
ref_object (struct nl_object *obj, void *data)
{
	struct nl_object **out = data;

	nl_object_get (obj);
	*out = obj;
}

static void
dump_address_change (NMIP6Device *device, struct nlmsghdr *hdr, struct rtnl_addr *rtnladdr)
{
	char *event;
	struct nl_addr *addr;
	char addr_str[40] = "none";

	event = hdr->nlmsg_type == RTM_NEWADDR ? "new" : "lost";
	addr = rtnl_addr_get_local (rtnladdr);
	if (addr)
		nl_addr2str (addr, addr_str, 40);

	nm_log_dbg (LOGD_IP6, "(%s) %s address: %s", device_get_iface (device), event, addr_str);
}

static void
dump_route_change (NMIP6Device *device, struct nlmsghdr *hdr, struct rtnl_route *rtnlroute)
{
	char *event;
	struct nl_addr *dst;
	char dst_str[40] = "none";
	struct nl_addr *gateway;
	char gateway_str[40] = "none";

	event = hdr->nlmsg_type == RTM_NEWROUTE ? "new" : "lost";
	dst = rtnl_route_get_dst (rtnlroute);
	gateway = rtnl_route_nh_get_gateway (rtnl_route_nexthop_n (rtnlroute, 0));
	if (dst)
		nl_addr2str (dst, dst_str, 40);
	if (gateway)
		nl_addr2str (gateway, gateway_str, 40);

	nm_log_dbg (LOGD_IP6, "(%s) %s route: %s via %s",device_get_iface (device), event, dst_str, gateway_str);
}

static NMIP6Device *
process_address_change (NMIP6Manager *manager, struct nl_msg *msg)
{
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (manager);
	NMIP6Device *device;
	struct nlmsghdr *hdr;
	struct rtnl_addr *rtnladdr;
	int old_size;

	hdr = nlmsg_hdr (msg);
	rtnladdr = NULL;
	nl_msg_parse (msg, ref_object, &rtnladdr);
	if (!rtnladdr) {
		nm_log_dbg (LOGD_IP6, "error processing netlink new/del address message");
		return NULL;
	}

	device = nm_ip6_manager_get_device (manager, rtnl_addr_get_ifindex (rtnladdr));

	old_size = nl_cache_nitems (priv->addr_cache);
	nl_cache_include (priv->addr_cache, (struct nl_object *)rtnladdr, NULL, NULL);

	/* The kernel will re-notify us of automatically-added addresses
	 * every time it gets another router advertisement. We only want
	 * to notify higher levels if we actually changed something.
	 */
	nm_log_dbg (LOGD_IP6, "(%s): address cache size: %d -> %d:",
		    device_get_iface (device), old_size, nl_cache_nitems (priv->addr_cache));
	dump_address_change (device, hdr, rtnladdr);
	rtnl_addr_put (rtnladdr);
	if (nl_cache_nitems (priv->addr_cache) == old_size)
		return NULL;

	return device;
}

static NMIP6Device *
process_route_change (NMIP6Manager *manager, struct nl_msg *msg)
{
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (manager);
	NMIP6Device *device;
	struct nlmsghdr *hdr;
	struct rtnl_route *rtnlroute;
	int old_size;
	int ifindex;

	hdr = nlmsg_hdr (msg);
	rtnlroute = NULL;
	nl_msg_parse (msg, ref_object, &rtnlroute);
	if (!rtnlroute) {
		nm_log_dbg (LOGD_IP6, "error processing netlink new/del route message");
		return NULL;
	}

	/* Cached/cloned routes are created by the kernel for specific operations
	 * and aren't part of the interface's permanent routing configuration.
	 */
	if (rtnl_route_get_flags (rtnlroute) & RTM_F_CLONED) {
		rtnl_route_put (rtnlroute);
		return NULL;
	}

	/* Only care about single-nexthop routes. */
	if (rtnl_route_get_nnexthops (rtnlroute) != 1) {
		rtnl_route_put (rtnlroute);
		return NULL;
	}

	ifindex = rtnl_route_nh_get_ifindex (rtnl_route_nexthop_n (rtnlroute, 0));
	device = nm_ip6_manager_get_device (manager, ifindex);

	old_size = nl_cache_nitems (priv->route_cache);
	nl_cache_include (priv->route_cache, (struct nl_object *)rtnlroute, NULL, NULL);

	/* As above in process_address_change */
	nm_log_dbg (LOGD_IP6, "(%s): route cache size: %d -> %d:",
		    device_get_iface (device), old_size, nl_cache_nitems (priv->route_cache));
	dump_route_change (device, hdr, rtnlroute);
	rtnl_route_put (rtnlroute);
	if (nl_cache_nitems (priv->route_cache) == old_size)
		return NULL;

	return device;
}

/* RDNSS parsing code based on rdnssd, Copyright 2007 Pierre Ynard,
 * Rémi Denis-Courmont. GPLv2/3
 */

#define ND_OPT_RDNSS 25
#define ND_OPT_DNSSL 31

struct nd_opt_rdnss {
	uint8_t nd_opt_rdnss_type;
	uint8_t nd_opt_rdnss_len;
	uint16_t nd_opt_rdnss_reserved1;
	uint32_t nd_opt_rdnss_lifetime;
	/* followed by one or more IPv6 addresses */
} __attribute__ ((packed));

struct nd_opt_dnssl {
	uint8_t nd_opt_dnssl_type;
	uint8_t nd_opt_dnssl_len;
	uint16_t nd_opt_dnssl_reserved1;
	uint32_t nd_opt_dnssl_lifetime;
	/* followed by one or more suffixes */
} __attribute__ ((packed));

static gboolean
process_nduseropt_rdnss (NMIP6Device *device, struct nd_opt_hdr *opt)
{
	size_t opt_len;
	struct nd_opt_rdnss *rdnss_opt;
	time_t now = time (NULL);
	struct in6_addr *addr;
	GArray *new_servers;
	NMIP6RDNSS server, *cur_server;
	gboolean changed = FALSE;
	guint i;

	opt_len = opt->nd_opt_len;

	if (opt_len < 3 || (opt_len & 1) == 0)
		return FALSE;

	rdnss_opt = (struct nd_opt_rdnss *) opt;

	new_servers = g_array_new (FALSE, FALSE, sizeof (NMIP6RDNSS));

	/* Pad the DNS server expiry somewhat to give a bit of slack in cases
	 * where one RA gets lost or something (which can happen on unreliable
	 * links like WiFi where certain types of frames are not retransmitted).
	 * Note that 0 has special meaning and is therefore not adjusted.
	 */
	server.expires = ntohl (rdnss_opt->nd_opt_rdnss_lifetime);
	if (server.expires > 0)
		if (server.expires < 7200)
			server.expires = 7200;
		server.expires += now;

	for (addr = (struct in6_addr *) (rdnss_opt + 1); opt_len >= 2; addr++, opt_len -= 2) {
		char buf[INET6_ADDRSTRLEN + 1];

		if (!inet_ntop (AF_INET6, addr, buf, sizeof (buf))) {
			nm_log_warn (LOGD_IP6, "(%s): received invalid RA-provided nameserver", device->iface);
			continue;
		}

		/* Update the cached timeout if we already saw this server */
		for (i = 0; i < device->rdnss_servers->len; i++) {
			cur_server = &(g_array_index (device->rdnss_servers, NMIP6RDNSS, i));

			if (!IN6_ARE_ADDR_EQUAL (addr, &cur_server->addr))
				continue;

			cur_server->expires = server.expires;

			if (server.expires > 0) {
				nm_log_dbg (LOGD_IP6, "(%s): refreshing RA-provided nameserver %s (expires in %ld seconds)",
				            device->iface, buf,
				            server.expires - now);
				break;
			}

			nm_log_dbg (LOGD_IP6, "(%s): removing RA-provided nameserver %s on router request",
			            device->iface, buf);

			g_array_remove_index (device->rdnss_servers, i);
			changed = TRUE;
			break;
		}

		if (server.expires == 0)
			continue;
		if (i < device->rdnss_servers->len)
			continue;

		nm_log_dbg (LOGD_IP6, "(%s): found RA-provided nameserver %s (expires in %ld seconds)",
		            device->iface, buf, server.expires - now);

		server.addr = *addr;
		g_array_append_val (new_servers, server);
	}

	/* New servers must be added in the order they are listed in the
	 * RA option and before any existing servers.
	 *
	 * Note: This is the place to remove servers if we want to cap the
	 *       number of resolvers. The RFC states that the one to expire
	 *       first of the existing servers should be removed.
	 */
	if (new_servers->len) {
		g_array_prepend_vals (device->rdnss_servers,
		                      new_servers->data, new_servers->len);
		changed = TRUE;
	}

	g_array_free (new_servers, TRUE);

	/* Timeouts may have changed even if IPs didn't */
	set_rdnss_timeout (device);

	return changed;
}

static const char *
parse_dnssl_domain (const unsigned char *buffer, size_t maxlen)
{
	static char domain[256];
	size_t label_len;

	domain[0] = '\0';

	while (maxlen > 0) {
		label_len = *buffer;
		buffer++;
		maxlen--;

		if (label_len == 0)
			return domain;

		if (label_len > maxlen)
			return NULL;
		if ((sizeof (domain) - strlen (domain)) < (label_len + 2))
			return NULL;

		if (domain[0] != '\0')
			strcat (domain, ".");
		strncat (domain, (const char *)buffer, label_len);
		buffer += label_len;
		maxlen -= label_len;
	}

	return NULL;
}

static gboolean
process_nduseropt_dnssl (NMIP6Device *device, struct nd_opt_hdr *opt)
{
	size_t opt_len;
	struct nd_opt_dnssl *dnssl_opt;
	unsigned char *opt_ptr;
	time_t now = time (NULL);
	GArray *new_domains;
	NMIP6DNSSL domain, *cur_domain;
	gboolean changed;
	guint i;

	opt_len = opt->nd_opt_len;

	if (opt_len < 2)
		return FALSE;

	dnssl_opt = (struct nd_opt_dnssl *) opt;

	opt_ptr = (unsigned char *)(dnssl_opt + 1);
	opt_len = (opt_len - 1) * 8; /* prefer bytes for later handling */

	new_domains = g_array_new (FALSE, FALSE, sizeof (NMIP6DNSSL));

	changed = FALSE;

	/* Pad the DNS server expiry somewhat to give a bit of slack in cases
	 * where one RA gets lost or something (which can happen on unreliable
	 * links like wifi where certain types of frames are not retransmitted).
	 * Note that 0 has special meaning and is therefore not adjusted.
	 */
	domain.expires = ntohl (dnssl_opt->nd_opt_dnssl_lifetime);
	if (domain.expires > 0)
		if (domain.expires < 7200)
			domain.expires = 7200;
		domain.expires += now;

	while (opt_len) {
		const char *domain_str;

		domain_str = parse_dnssl_domain (opt_ptr, opt_len);
		if (domain_str == NULL) {
			nm_log_dbg (LOGD_IP6, "(%s): invalid DNSSL option, parsing aborted",
			            device->iface);
			break;
		}

		/* The DNSSL encoding of domains happen to occupy the same size
		 * as the length of the resulting string, including terminating
		 * null. */
		opt_ptr += strlen (domain_str) + 1;
		opt_len -= strlen (domain_str) + 1;

		/* Ignore empty domains. They're probably just padding... */
		if (domain_str[0] == '\0')
			continue;

		/* Update cached domain information if we've seen this domain before */
		for (i = 0; i < device->dnssl_domains->len; i++) {
			cur_domain = &(g_array_index (device->dnssl_domains, NMIP6DNSSL, i));

			if (strcmp (domain_str, cur_domain->domain) != 0)
				continue;

			cur_domain->expires = domain.expires;

			if (domain.expires > 0) {
				nm_log_dbg (LOGD_IP6, "(%s): refreshing RA-provided domain %s (expires in %ld seconds)",
				            device->iface, domain_str,
				            domain.expires - now);
				break;
			}

			nm_log_dbg (LOGD_IP6, "(%s): removing RA-provided domain %s on router request",
			            device->iface, domain_str);

			g_array_remove_index (device->dnssl_domains, i);
			changed = TRUE;
			break;
		}

		if (domain.expires == 0)
			continue;
		if (i < device->dnssl_domains->len)
			continue;

		nm_log_dbg (LOGD_IP6, "(%s): found RA-provided domain %s (expires in %ld seconds)",
		            device->iface, domain_str, domain.expires - now);

		g_assert (strlen (domain_str) < sizeof (domain.domain));
		strcpy (domain.domain, domain_str);
		g_array_append_val (new_domains, domain);
	}

	/* New domains must be added in the order they are listed in the
	 * RA option and before any existing domains.
	 *
	 * Note: This is the place to remove domains if we want to cap the
	 *       number of domains. The RFC states that the one to expire
	 *       first of the existing domains should be removed.
	 */
	if (new_domains->len) {
		g_array_prepend_vals (device->dnssl_domains,
		                      new_domains->data, new_domains->len);
		changed = TRUE;
	}

	g_array_free (new_domains, TRUE);

	/* Timeouts may have changed even if domains didn't */
	set_dnssl_timeout (device);

	return changed;
}

static NMIP6Device *
process_nduseropt (NMIP6Manager *manager, struct nl_msg *msg)
{
	NMIP6Device *device;
	struct nduseroptmsg *ndmsg;
	struct nd_opt_hdr *opt;
	guint opts_len;
	gboolean changed = FALSE;

	nm_log_dbg (LOGD_IP6, "processing netlink nduseropt message");

	ndmsg = (struct nduseroptmsg *) NLMSG_DATA (nlmsg_hdr (msg));

	if (!nlmsg_valid_hdr (nlmsg_hdr (msg), sizeof (*ndmsg)) ||
	    nlmsg_datalen (nlmsg_hdr (msg)) <
		(ndmsg->nduseropt_opts_len + sizeof (*ndmsg))) {
		nm_log_dbg (LOGD_IP6, "ignoring invalid nduseropt message");
		return NULL;
	}

	if (ndmsg->nduseropt_family != AF_INET6 ||
		ndmsg->nduseropt_icmp_type != ND_ROUTER_ADVERT ||
		ndmsg->nduseropt_icmp_code != 0) {
		nm_log_dbg (LOGD_IP6, "ignoring non-Router Advertisement message");
		return NULL;
	}

	device = nm_ip6_manager_get_device (manager, ndmsg->nduseropt_ifindex);
	if (!device) {
		nm_log_dbg (LOGD_IP6, "ignoring message for unknown device");
		return NULL;
	}

	opt = (struct nd_opt_hdr *) (ndmsg + 1);
	opts_len = ndmsg->nduseropt_opts_len;

	while (opts_len >= sizeof (struct nd_opt_hdr)) {
		size_t nd_opt_len = opt->nd_opt_len;

		if (nd_opt_len == 0 || opts_len < (nd_opt_len << 3))
			break;

		switch (opt->nd_opt_type) {
		case ND_OPT_RDNSS:
			changed = process_nduseropt_rdnss (device, opt);
			break;
		case ND_OPT_DNSSL:
			changed = process_nduseropt_dnssl (device, opt);
			break;
		}

		opts_len -= opt->nd_opt_len << 3;
		opt = (struct nd_opt_hdr *) ((uint8_t *) opt + (opt->nd_opt_len << 3));
	}

	if (changed)
		return device;
	else
		return NULL;
}

static struct nla_policy link_policy[IFLA_MAX + 1] = {
	[IFLA_PROTINFO] = { .type = NLA_NESTED },
};

static struct nla_policy link_prot_policy[IFLA_INET6_MAX + 1] = {
	[IFLA_INET6_FLAGS]	= { .type = NLA_U32 },
};

static NMIP6Device *
process_newlink (NMIP6Manager *manager, struct nl_msg *msg)
{
	struct nlmsghdr *hdr = nlmsg_hdr (msg);
	struct ifinfomsg *ifi;
	NMIP6Device *device;
	struct nlattr *tb[IFLA_MAX + 1];
	struct nlattr *pi[IFLA_INET6_MAX + 1];
	int err;

	/* FIXME: we have to do this manually for now since libnl doesn't yet
	 * support the IFLA_PROTINFO attribute of NEWLINK messages.  When it does,
	 * we can get rid of this function and just grab IFLA_PROTINFO from
	 * nm_ip6_device_sync_from_netlink(), then get the IFLA_INET6_FLAGS out of
	 * the PROTINFO.
	 */
	err = nlmsg_parse (hdr, sizeof (*ifi), tb, IFLA_MAX, link_policy);
	if (err < 0) {
		nm_log_dbg (LOGD_IP6, "ignoring invalid newlink netlink message "
				      "while parsing PROTINFO attribute");
		return NULL;
	}

	ifi = nlmsg_data (hdr);
	if (ifi->ifi_family != AF_INET6) {
		nm_log_dbg (LOGD_IP6, "ignoring netlink message family %d", ifi->ifi_family);
		return NULL;
	}

	device = nm_ip6_manager_get_device (manager, ifi->ifi_index);
	if (!device || device->addrconf_complete) {
		nm_log_dbg (LOGD_IP6, "(%s): ignoring unknown or completed device",
		            device ? device->iface : "(none)");
		return NULL;
	}

	if (!tb[IFLA_PROTINFO]) {
		nm_log_dbg (LOGD_IP6, "(%s): message had no PROTINFO attribute", device->iface);
		return NULL;
	}

	err = nla_parse_nested (pi, IFLA_INET6_MAX, tb[IFLA_PROTINFO], link_prot_policy);
	if (err < 0) {
		nm_log_dbg (LOGD_IP6, "(%s): error parsing PROTINFO flags", device->iface);
		return NULL;
	}
	if (!pi[IFLA_INET6_FLAGS]) {
		nm_log_dbg (LOGD_IP6, "(%s): message had no PROTINFO flags", device->iface);
		return NULL;
	}

	device_set_ra_flags (device, nla_get_u32 (pi[IFLA_INET6_FLAGS]));

	return device;
}

static gboolean
manager_request_ip6_info (gpointer user_data)
{
	NMIP6Manager *manager = user_data;
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (manager);

	priv->request_ip6_info_id = 0;
	nm_netlink_monitor_request_ip6_info (priv->monitor, NULL);
	return FALSE;
}

static void
netlink_notification (NMNetlinkMonitor *monitor, struct nl_msg *msg, gpointer user_data)
{
	NMIP6Manager *manager = NM_IP6_MANAGER (user_data);
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (manager);
	NMIP6Device *device;
	struct nlmsghdr *hdr;

	hdr = nlmsg_hdr (msg);
	nm_log_dbg (LOGD_HW, "netlink event type %d", hdr->nlmsg_type);
	switch (hdr->nlmsg_type) {
	case RTM_NEWADDR:
	case RTM_DELADDR:
		device = process_address_change (manager, msg);
		break;
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		device = process_route_change (manager, msg);
		/* Once we have received an RTM_NEWROUTE, the IPv6 flags might have been
		 * set. But we need to request an RTM_NEWLINK to find out what they actually are.
		 */
		if (priv->request_ip6_info_id == 0)
			priv->request_ip6_info_id = g_idle_add (manager_request_ip6_info, manager);
		break;
	case RTM_NEWNDUSEROPT:
		device = process_nduseropt (manager, msg);
		break;
	case RTM_NEWLINK:
		device = process_newlink (manager, msg);
		break;
	default:
		return;
	}

	if (device && device->sync_from_netlink_id == 0)
		device->sync_from_netlink_id = g_idle_add (device_sync_from_netlink, device);
}

gboolean
nm_ip6_manager_prepare_interface (NMIP6Manager *manager,
                                  int ifindex,
                                  const guint8 *hwaddr,
                                  guint hwaddr_len,
                                  NMSettingIP6Config *s_ip6,
                                  const char *accept_ra_path)
{
	NMIP6ManagerPrivate *priv;
	NMIP6Device *device;
	const char *method = NULL;

	g_return_val_if_fail (NM_IS_IP6_MANAGER (manager), FALSE);
	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (hwaddr != NULL, FALSE);
	g_return_val_if_fail (hwaddr_len > 0, FALSE);
	g_return_val_if_fail (hwaddr_len <= NM_UTILS_HWADDR_LEN_MAX, FALSE);

	priv = NM_IP6_MANAGER_GET_PRIVATE (manager);

	device = nm_ip6_device_new (manager, ifindex, hwaddr, hwaddr_len);
	g_return_val_if_fail (device != NULL, FALSE);
	g_return_val_if_fail (   strchr (device->iface, '/') == NULL
	                      && strcmp (device->iface, "all") != 0
	                      && strcmp (device->iface, "default") != 0,
	                      FALSE);

	if (s_ip6)
		method = nm_setting_ip6_config_get_method (s_ip6);
	if (!method)
		method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;

	/* Establish target state and turn router advertisement acceptance on or off */
	if (!strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL)) {
		device->target_state = NM_IP6_DEVICE_GOT_LINK_LOCAL;
		nm_utils_do_sysctl (accept_ra_path, "0");
	} else {
		device->target_state = NM_IP6_DEVICE_GOT_ADDRESS;
		nm_utils_do_sysctl (accept_ra_path, "2");
	}

	nm_log_dbg (LOGD_IP6, "(%s) IP6 device target state: %s",
	            device_get_iface (device), state_to_string (device->target_state));

	return TRUE;
}

void
nm_ip6_manager_begin_addrconf (NMIP6Manager *manager, int ifindex)
{
	NMIP6ManagerPrivate *priv;
	NMIP6Device *device;
	CallbackInfo *info;

	g_return_if_fail (NM_IS_IP6_MANAGER (manager));
	g_return_if_fail (ifindex > 0);

	priv = NM_IP6_MANAGER_GET_PRIVATE (manager);

	device = (NMIP6Device *) g_hash_table_lookup (priv->devices, GINT_TO_POINTER (ifindex));
	g_return_if_fail (device != NULL);

	nm_log_info (LOGD_IP6, "Activation (%s) Beginning IP6 addrconf.", device->iface);

	device->addrconf_complete = FALSE;
	device->ra_flags = 0;

	/* Set up a timeout on the transaction to kill it after the timeout */
	info = callback_info_new (device, FALSE);
	device->finish_addrconf_id = g_timeout_add_seconds_full (G_PRIORITY_DEFAULT,
	                                                         NM_IP6_TIMEOUT,
	                                                         finish_addrconf,
	                                                         info,
	                                                         (GDestroyNotify) g_free);

	/* Bounce IPv6 on the interface to ensure the kernel will start looking for
	 * new RAs; there doesn't seem to be a better way to do this right now.
	 */
	if (device->target_state >= NM_IP6_DEVICE_GOT_ADDRESS) {
		nm_utils_do_sysctl (device->disable_ip6_path, "1");
		g_usleep (200);
		nm_utils_do_sysctl (device->disable_ip6_path, "0");
	}

	/* Kick off the initial IPv6 flags request */
	nm_netlink_monitor_request_ip6_info (priv->monitor, NULL);

	/* Sync flags, etc, from netlink; this will also notice if the
	 * device is already fully configured and schedule the
	 * ADDRCONF_COMPLETE signal in that case.
	 */
	device_sync_from_netlink (device);
}

void
nm_ip6_manager_cancel_addrconf (NMIP6Manager *manager, int ifindex)
{
	g_return_if_fail (NM_IS_IP6_MANAGER (manager));
	g_return_if_fail (ifindex > 0);

	g_hash_table_remove (NM_IP6_MANAGER_GET_PRIVATE (manager)->devices,
	                     GINT_TO_POINTER (ifindex));
}

#define FIRST_ROUTE(m) ((struct rtnl_route *) nl_cache_get_first (m))
#define NEXT_ROUTE(m) ((struct rtnl_route *) nl_cache_get_next ((struct nl_object *) m))

#define FIRST_ADDR(m) ((struct rtnl_addr *) nl_cache_get_first (m))
#define NEXT_ADDR(m) ((struct rtnl_addr *) nl_cache_get_next ((struct nl_object *) m))

NMIP6Config *
nm_ip6_manager_get_ip6_config (NMIP6Manager *manager, int ifindex)
{
	NMIP6ManagerPrivate *priv;
	NMIP6Device *device;
	NMIP6Config *config;
	struct rtnl_addr *rtnladdr;
	struct nl_addr *nladdr;
	struct in6_addr *addr;
	NMIP6Address *ip6addr;
	struct rtnl_route *rtnlroute;
	struct rtnl_nexthop *nexthop;
	struct nl_addr *nldest, *nlgateway;
	const struct in6_addr *dest, *gateway;
	int plen;
	uint32_t metric;
	NMIP6Route *ip6route;
	int i;

	g_return_val_if_fail (NM_IS_IP6_MANAGER (manager), NULL);
	g_return_val_if_fail (ifindex > 0, NULL);

	priv = NM_IP6_MANAGER_GET_PRIVATE (manager);

	device = (NMIP6Device *) g_hash_table_lookup (priv->devices,
	                                              GINT_TO_POINTER (ifindex));
	if (!device) {
		nm_log_warn (LOGD_IP6, "(%d): addrconf not started.", ifindex);
		return NULL;
	}

	config = nm_ip6_config_new ();

	/* Make sure we refill the route and address caches, otherwise we won't get
	 * up-to-date information here since the netlink route/addr change messages
	 * may be lagging a bit.
	 */
	nl_cache_refill (priv->nlh, priv->route_cache);
	nl_cache_refill (priv->nlh, priv->addr_cache);

	/* Add routes */
	for (rtnlroute = FIRST_ROUTE (priv->route_cache); rtnlroute; rtnlroute = NEXT_ROUTE (rtnlroute)) {
		/* Only care about single-nexthop routes */
		if (rtnl_route_get_nnexthops (rtnlroute) != 1)
			continue;
		nexthop = rtnl_route_nexthop_n (rtnlroute, 0);

		/* Make sure it's an IPv6 route for this device */
		if (rtnl_route_get_family (rtnlroute) != AF_INET6)
			continue;
		if (rtnl_route_nh_get_ifindex (nexthop) != device->ifindex)
			continue;

		/* And ignore cache/cloned routes as they aren't part of the interface's
		 * permanent routing configuration.
		 */
		if (rtnl_route_get_flags (rtnlroute) & RTM_F_CLONED)
			continue;

		nldest = rtnl_route_get_dst (rtnlroute);
		if (!nldest || nl_addr_get_family (nldest) != AF_INET6)
			continue;
		dest = nl_addr_get_binary_addr (nldest);
		plen = nl_addr_get_prefixlen (nldest);

		nlgateway = rtnl_route_nh_get_gateway (nexthop);
		if (!nlgateway || nl_addr_get_family (nlgateway) != AF_INET6)
			continue;
		gateway = nl_addr_get_binary_addr (nlgateway);

		if (plen == 0) {
			/* Default gateway route; cache the router's address for later */
			if (!nm_ip6_config_get_gateway (config))
				nm_ip6_config_set_gateway (config, gateway);
			continue;
		}

		/* Also ignore link-local routes where the destination and gateway are
		 * the same, which apparently get added by the kernel but return -EINVAL
		 * when we try to add them via netlink.
		 */
		if (gateway && IN6_ARE_ADDR_EQUAL (dest, gateway))
			continue;

		ip6route = nm_ip6_route_new ();
		nm_ip6_route_set_dest (ip6route, dest);
		nm_ip6_route_set_prefix (ip6route, plen);
		nm_ip6_route_set_next_hop (ip6route, gateway);
		rtnl_route_get_metric(rtnlroute, 1, &metric);
		if (metric != UINT_MAX)
			nm_ip6_route_set_metric (ip6route, metric);
		nm_ip6_config_take_route (config, ip6route);
	}

	/* Add addresses */
	for (rtnladdr = FIRST_ADDR (priv->addr_cache); rtnladdr; rtnladdr = NEXT_ADDR (rtnladdr)) {
		if (rtnl_addr_get_ifindex (rtnladdr) != device->ifindex)
			continue;

		nladdr = rtnl_addr_get_local (rtnladdr);
		if (!nladdr || nl_addr_get_family (nladdr) != AF_INET6)
			continue;

		addr = nl_addr_get_binary_addr (nladdr);
		ip6addr = nm_ip6_address_new ();
		nm_ip6_address_set_prefix (ip6addr, rtnl_addr_get_prefixlen (rtnladdr));
		nm_ip6_address_set_address (ip6addr, addr);
		nm_ip6_config_take_address (config, ip6addr);
		gateway = nm_ip6_config_get_gateway (config);
		if (gateway)
			nm_ip6_address_set_gateway (ip6addr, gateway);
	}

	/* Add DNS servers */
	if (device->rdnss_servers) {
		NMIP6RDNSS *rdnss = (NMIP6RDNSS *)(device->rdnss_servers->data);

		for (i = 0; i < device->rdnss_servers->len; i++)
			nm_ip6_config_add_nameserver (config, &rdnss[i].addr);
	}

	/* Add DNS domains */
	if (device->dnssl_domains) {
		NMIP6DNSSL *dnssl = (NMIP6DNSSL *)(device->dnssl_domains->data);

		for (i = 0; i < device->dnssl_domains->len; i++)
			nm_ip6_config_add_domain (config, dnssl[i].domain);
	}

	return config;
}

/******************************************************************/

static NMIP6Manager *
nm_ip6_manager_new (void)
{
	return g_object_new (NM_TYPE_IP6_MANAGER, NULL);
}

static NMIP6Manager *singleton = NULL;

NMIP6Manager *
nm_ip6_manager_get (void)
{
	if (!singleton) {
		singleton = nm_ip6_manager_new ();
		g_assert (singleton);
	} else
		g_object_ref (singleton);

	return singleton;
}

static void
nm_ip6_manager_init (NMIP6Manager *manager)
{
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (manager);

	priv->devices = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                       NULL,
	                                       (GDestroyNotify) nm_ip6_device_destroy);

	priv->monitor = nm_netlink_monitor_get ();
	nm_netlink_monitor_subscribe (priv->monitor, RTNLGRP_IPV6_IFADDR, NULL);
	nm_netlink_monitor_subscribe (priv->monitor, RTNLGRP_IPV6_ROUTE, NULL);
	nm_netlink_monitor_subscribe (priv->monitor, RTNLGRP_ND_USEROPT, NULL);
	nm_netlink_monitor_subscribe (priv->monitor, RTNLGRP_LINK, NULL);

	priv->netlink_id = g_signal_connect (priv->monitor, "notification",
	                                     G_CALLBACK (netlink_notification), manager);

	priv->nlh = nm_netlink_get_default_handle ();
	g_assert (priv->nlh);
	rtnl_addr_alloc_cache (priv->nlh, &priv->addr_cache);
	g_assert (priv->addr_cache);
	rtnl_route_alloc_cache (priv->nlh, AF_UNSPEC, 0, &priv->route_cache);
	g_assert (priv->route_cache);

}

static void
finalize (GObject *object)
{
	NMIP6ManagerPrivate *priv = NM_IP6_MANAGER_GET_PRIVATE (object);

	if (priv->request_ip6_info_id)
		g_source_remove (priv->request_ip6_info_id);

	g_signal_handler_disconnect (priv->monitor, priv->netlink_id);

	g_hash_table_destroy (priv->devices);
	nl_cache_free (priv->addr_cache);
	nl_cache_free (priv->route_cache);

	singleton = NULL;

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
					  NULL, NULL, NULL,
					  G_TYPE_NONE, 3, G_TYPE_INT, G_TYPE_UINT, G_TYPE_BOOLEAN);

	signals[CONFIG_CHANGED] =
		g_signal_new ("config-changed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMIP6ManagerClass, config_changed),
					  NULL, NULL, NULL,
					  G_TYPE_NONE, 3, G_TYPE_INT, G_TYPE_UINT, G_TYPE_BOOLEAN);
}

