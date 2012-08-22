/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * Copyright (C) 2004 - 2012 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include <config.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#include "nm-policy.h"
#include "NetworkManagerUtils.h"
#include "nm-wifi-ap.h"
#include "nm-activation-request.h"
#include "nm-logging.h"
#include "nm-device.h"
#include "nm-dbus-manager.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-connection.h"
#include "nm-system.h"
#include "nm-dns-manager.h"
#include "nm-vpn-manager.h"
#include "nm-policy-hostname.h"
#include "nm-manager-auth.h"
#include "nm-firewall-manager.h"
#include "nm-dispatcher.h"
#include "nm-utils.h"

struct NMPolicy {
	NMManager *manager;
	guint update_state_id;
	GSList *pending_activation_checks;
	GSList *manager_ids;
	GSList *settings_ids;
	GSList *dev_ids;

	GSList *pending_secondaries;

	NMFirewallManager *fw_manager;
	gulong fw_started_id;

	NMSettings *settings;

	NMDevice *default_device4;
	NMDevice *default_device6;

	HostnameThread *lookup;

	gint reset_retries_id;  /* idle handler for resetting the retries count */

	char *orig_hostname; /* hostname at NM start time */
	char *cur_hostname;  /* hostname we want to assign */
	gboolean hostname_changed;  /* TRUE if NM ever set the hostname */
};

#define RETRIES_TAG "autoconnect-retries"
#define RETRIES_DEFAULT	4
#define RESET_RETRIES_TIMESTAMP_TAG "reset-retries-timestamp-tag"
#define RESET_RETRIES_TIMER 300
#define FAILURE_REASON_TAG "failure-reason"

static void schedule_activate_all (NMPolicy *policy);


static NMDevice *
get_best_ip4_device (NMManager *manager)
{
	GSList *devices, *iter;
	NMDevice *best = NULL;
	int best_prio = G_MAXINT;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	devices = nm_manager_get_devices (manager);
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *dev = NM_DEVICE (iter->data);
		NMDeviceType devtype = nm_device_get_device_type (dev);
		NMActRequest *req;
		NMConnection *connection;
		NMIP4Config *ip4_config;
		NMSettingIP4Config *s_ip4;
		int prio;
		guint i;
		gboolean can_default = FALSE;
		const char *method = NULL;

		if (   nm_device_get_state (dev) != NM_DEVICE_STATE_ACTIVATED
		    && nm_device_get_state (dev) != NM_DEVICE_STATE_SECONDARIES)
			continue;

		ip4_config = nm_device_get_ip4_config (dev);
		if (!ip4_config)
			continue;

		req = nm_device_get_act_request (dev);
		g_assert (req);
		connection = nm_act_request_get_connection (req);
		g_assert (connection);

		/* Never set the default route through an IPv4LL-addressed device */
		s_ip4 = nm_connection_get_setting_ip4_config (connection);
		if (s_ip4)
			method = nm_setting_ip4_config_get_method (s_ip4);

		if (s_ip4 && !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL))
			continue;

		/* Make sure at least one of this device's IP addresses has a gateway */
		for (i = 0; i < nm_ip4_config_get_num_addresses (ip4_config); i++) {
			NMIP4Address *addr;

			addr = nm_ip4_config_get_address (ip4_config, i);
			if (nm_ip4_address_get_gateway (addr)) {
				can_default = TRUE;
				break;
			}
		}

		if (!can_default && (devtype != NM_DEVICE_TYPE_MODEM))
			continue;

		/* 'never-default' devices can't ever be the default */
		if (   (s_ip4 && nm_setting_ip4_config_get_never_default (s_ip4))
		    || nm_ip4_config_get_never_default (ip4_config))
			continue;

		prio = nm_device_get_priority (dev);
		if (prio > 0 && prio < best_prio) {
			best = dev;
			best_prio = prio;
		}
	}

	return best;
}

static NMDevice *
get_best_ip6_device (NMManager *manager)
{
	GSList *devices, *iter;
	NMDevice *best = NULL;
	int best_prio = G_MAXINT;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	devices = nm_manager_get_devices (manager);
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *dev = NM_DEVICE (iter->data);
		NMDeviceType devtype = nm_device_get_device_type (dev);
		NMActRequest *req;
		NMConnection *connection;
		NMIP6Config *ip6_config;
		NMSettingIP6Config *s_ip6;
		int prio;
		guint i;
		gboolean can_default = FALSE;
		const char *method = NULL;

		if (   nm_device_get_state (dev) != NM_DEVICE_STATE_ACTIVATED
		    && nm_device_get_state (dev) != NM_DEVICE_STATE_SECONDARIES)
			continue;

		ip6_config = nm_device_get_ip6_config (dev);
		if (!ip6_config)
			continue;

		req = nm_device_get_act_request (dev);
		g_assert (req);
		connection = nm_act_request_get_connection (req);
		g_assert (connection);

		/* Never set the default route through an IPv4LL-addressed device */
		s_ip6 = nm_connection_get_setting_ip6_config (connection);
		if (s_ip6)
			method = nm_setting_ip6_config_get_method (s_ip6);

		if (method && !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL))
			continue;

		/* Make sure at least one of this device's IP addresses has a gateway */
		for (i = 0; i < nm_ip6_config_get_num_addresses (ip6_config); i++) {
			NMIP6Address *addr;

			addr = nm_ip6_config_get_address (ip6_config, i);
			if (nm_ip6_address_get_gateway (addr)) {
				can_default = TRUE;
				break;
			}
		}

		if (!can_default && (devtype != NM_DEVICE_TYPE_MODEM))
			continue;

		/* 'never-default' devices can't ever be the default */
		if (s_ip6 && nm_setting_ip6_config_get_never_default (s_ip6))
			continue;

		prio = nm_device_get_priority (dev);
		if (prio > 0 && prio < best_prio) {
			best = dev;
			best_prio = prio;
		}
	}

	return best;
}

static void
_set_hostname (NMPolicy *policy,
               const char *new_hostname,
               const char *msg)
{
	NMDnsManager *dns_mgr;

	/* The incoming hostname *can* be NULL, which will get translated to
	 * 'localhost.localdomain' or such in the hostname policy code, but we
	 * keep cur_hostname = NULL in the case because we need to know that
	 * there was no valid hostname to start with.
	 */

	/* Don't change the hostname or update DNS this is the first time we're
	 * trying to change the hostname, and it's not actually changing.
	 */
	if (   policy->orig_hostname
	    && (policy->hostname_changed == FALSE)
	    && g_strcmp0 (policy->orig_hostname, new_hostname) == 0)
		return;

	/* Don't change the hostname or update DNS if the hostname isn't actually
	 * going to change.
	 */
	if (g_strcmp0 (policy->cur_hostname, new_hostname) == 0)
		return;

	g_free (policy->cur_hostname);
	policy->cur_hostname = g_strdup (new_hostname);
	policy->hostname_changed = TRUE;

	dns_mgr = nm_dns_manager_get (NULL);
	nm_dns_manager_set_hostname (dns_mgr, policy->cur_hostname);
	g_object_unref (dns_mgr);

	if (nm_policy_set_system_hostname (policy->cur_hostname, msg))
		nm_dispatcher_call (DISPATCHER_ACTION_HOSTNAME, NULL, NULL, NULL, NULL);
}

static void
lookup_callback (HostnameThread *thread,
                 int result,
                 const char *hostname,
                 gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	char *msg;

	/* Update the hostname if the calling lookup thread is the in-progress one */
	if (!hostname_thread_is_dead (thread) && (thread == policy->lookup)) {
		policy->lookup = NULL;
		if (!hostname) {
			/* Fall back to localhost.localdomain */
			msg = g_strdup_printf ("address lookup failed: %d", result);
			_set_hostname (policy, NULL, msg);
			g_free (msg);
		} else
			_set_hostname (policy, hostname, "from address lookup");
	}
	hostname_thread_free (thread);
}

static void
update_system_hostname (NMPolicy *policy, NMDevice *best4, NMDevice *best6)
{
	char *configured_hostname = NULL;
	const char *dhcp_hostname, *p;

	g_return_if_fail (policy != NULL);

	if (policy->lookup) {
		hostname_thread_kill (policy->lookup);
		policy->lookup = NULL;
	}

	/* Hostname precedence order:
	 *
	 * 1) a configured hostname (from settings)
	 * 2) automatic hostname from the default device's config (DHCP, VPN, etc)
	 * 3) the original hostname when NM started
	 * 4) reverse-DNS of the best device's IPv4 address
	 *
	 */

	/* Try a persistent hostname first */
	g_object_get (G_OBJECT (policy->manager), NM_MANAGER_HOSTNAME, &configured_hostname, NULL);
	if (configured_hostname) {
		_set_hostname (policy, configured_hostname, "from system configuration");
		g_free (configured_hostname);
		return;
	}

	/* Try automatically determined hostname from the best device's IP config */
	if (!best4)
		best4 = get_best_ip4_device (policy->manager);
	if (!best6)
		best6 = get_best_ip6_device (policy->manager);

	if (!best4 && !best6) {
		/* No best device; fall back to original hostname or if there wasn't
		 * one, 'localhost.localdomain'
		 */
		_set_hostname (policy, policy->orig_hostname, "no default device");
		return;
	}

	if (best4) {
		NMDHCP4Config *dhcp4_config;

		/* Grab a hostname out of the device's DHCP4 config */
		dhcp4_config = nm_device_get_dhcp4_config (best4);
		if (dhcp4_config) {
			p = dhcp_hostname = nm_dhcp4_config_get_option (dhcp4_config, "host_name");
			if (dhcp_hostname && strlen (dhcp_hostname)) {
				/* Sanity check; strip leading spaces */
				while (*p) {
					if (!g_ascii_isspace (*p++)) {
						_set_hostname (policy, p-1, "from DHCPv4");
						return;
					}
				}
				nm_log_warn (LOGD_DNS, "DHCPv4-provided hostname '%s' looks invalid; ignoring it",
				             dhcp_hostname);
			}
		}
	} else if (best6) {
		NMDHCP6Config *dhcp6_config;

		/* Grab a hostname out of the device's DHCP6 config */
		dhcp6_config = nm_device_get_dhcp6_config (best6);
		if (dhcp6_config) {
			p = dhcp_hostname = nm_dhcp6_config_get_option (dhcp6_config, "host_name");
			if (dhcp_hostname && strlen (dhcp_hostname)) {
				/* Sanity check; strip leading spaces */
				while (*p) {
					if (!g_ascii_isspace (*p++)) {
						_set_hostname (policy, p-1, "from DHCPv6");
						return;
					}
				}
				nm_log_warn (LOGD_DNS, "DHCPv6-provided hostname '%s' looks invalid; ignoring it",
				             dhcp_hostname);
			}
		}
	}

	/* If no automatically-configured hostname, try using the hostname from
	 * when NM started up.
	 */
	if (policy->orig_hostname) {
		_set_hostname (policy, policy->orig_hostname, "from system startup");
		return;
	}

	/* No configured hostname, no automatically determined hostname, and no
	 * bootup hostname. Start reverse DNS of the current IPv4 or IPv6 address.
	 */
	if (best4) {
		NMIP4Config *ip4_config;
		NMIP4Address *addr4;

		ip4_config = nm_device_get_ip4_config (best4);
		if (   !ip4_config
		    || (nm_ip4_config_get_num_nameservers (ip4_config) == 0)
		    || (nm_ip4_config_get_num_addresses (ip4_config) == 0)) {
			/* No valid IP4 config (!!); fall back to localhost.localdomain */
			_set_hostname (policy, NULL, "no IPv4 config");
			return;
		}

		addr4 = nm_ip4_config_get_address (ip4_config, 0);
		g_assert (addr4); /* checked for > 1 address above */

		/* Start the hostname lookup thread */
		policy->lookup = hostname4_thread_new (nm_ip4_address_get_address (addr4), lookup_callback, policy);
	} else if (best6) {
		NMIP6Config *ip6_config;
		NMIP6Address *addr6;

		ip6_config = nm_device_get_ip6_config (best6);
		if (   !ip6_config
		    || (nm_ip6_config_get_num_nameservers (ip6_config) == 0)
		    || (nm_ip6_config_get_num_addresses (ip6_config) == 0)) {
			/* No valid IP6 config (!!); fall back to localhost.localdomain */
			_set_hostname (policy, NULL, "no IPv6 config");
			return;
		}

		addr6 = nm_ip6_config_get_address (ip6_config, 0);
		g_assert (addr6); /* checked for > 1 address above */

		/* Start the hostname lookup thread */
		policy->lookup = hostname6_thread_new (nm_ip6_address_get_address (addr6), lookup_callback, policy);
	}

	if (!policy->lookup) {
		/* Fall back to 'localhost.localdomain' */
		_set_hostname (policy, NULL, "error starting hostname thread");
	}
}

static void
update_default_ac (NMPolicy *policy,
                   NMActiveConnection *best,
                   void (*set_active_func)(NMActiveConnection*, gboolean))
{
	const GSList *connections, *iter;

	/* Clear the 'default[6]' flag on all active connections that aren't the new
	 * default active connection.  We'll set the new default after; this ensures
	 * we don't ever have two marked 'default[6]' simultaneously.
	 */
	connections = nm_manager_get_active_connections (policy->manager);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		if (NM_ACTIVE_CONNECTION (iter->data) != best)
			set_active_func (NM_ACTIVE_CONNECTION (iter->data), FALSE);
	}

	/* Mark new default active connection */
	if (best)
		set_active_func (best, TRUE);
}

static NMIP4Config *
get_best_ip4_config (NMPolicy *policy,
                     gboolean ignore_never_default,
                     const char **out_ip_iface,
                     int *out_ip_ifindex,
                     NMActiveConnection **out_ac,
                     NMDevice **out_device,
                     NMVPNConnection **out_vpn)
{
	const GSList *connections, *iter;
	NMDevice *device;
	NMActRequest *req = NULL;
	NMIP4Config *ip4_config = NULL;

	/* If a VPN connection is active, it is preferred */
	connections = nm_manager_get_active_connections (policy->manager);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMActiveConnection *active = NM_ACTIVE_CONNECTION (iter->data);
		NMVPNConnection *candidate;
		NMIP4Config *vpn_ip4;
		NMConnection *tmp;
		NMSettingIP4Config *s_ip4;
		NMVPNConnectionState vpn_state;

		if (!NM_IS_VPN_CONNECTION (active))
			continue;

		candidate = NM_VPN_CONNECTION (active);

		tmp = nm_active_connection_get_connection (active);
		g_assert (tmp);

		vpn_state = nm_vpn_connection_get_vpn_state (candidate);
		if (vpn_state != NM_VPN_CONNECTION_STATE_ACTIVATED)
			continue;

		vpn_ip4 = nm_vpn_connection_get_ip4_config (candidate);
		if (!vpn_ip4)
			continue;

		if (ignore_never_default == FALSE) {
			/* Check for a VPN-provided config never-default */
			if (nm_ip4_config_get_never_default (vpn_ip4))
				continue;

			/* Check the user's preference from the NMConnection */
			s_ip4 = nm_connection_get_setting_ip4_config (tmp);
			if (s_ip4 && nm_setting_ip4_config_get_never_default (s_ip4))
				continue;
		}

		ip4_config = vpn_ip4;
		if (out_vpn)
			*out_vpn = candidate;
		if (out_ac)
			*out_ac = active;
		if (out_ip_iface)
			*out_ip_iface = nm_vpn_connection_get_ip_iface (candidate);
		if (out_ip_ifindex)
			*out_ip_ifindex = nm_vpn_connection_get_ip_ifindex (candidate);
		break;
	}

	/* If no VPN connections, we use the best device instead */
	if (!ip4_config) {
		device = get_best_ip4_device (policy->manager);
		if (device) {
			ip4_config = nm_device_get_ip4_config (device);
			g_assert (ip4_config);
			req = nm_device_get_act_request (device);
			g_assert (req);

			if (out_device)
				*out_device = device;
			if (out_ac)
				*out_ac = NM_ACTIVE_CONNECTION (req);
			if (out_ip_iface)
				*out_ip_iface = nm_device_get_ip_iface (device);
			if (out_ip_ifindex)
				*out_ip_ifindex = nm_device_get_ip_ifindex (device);
		}
	}

	return ip4_config;
}

static void
update_ip4_dns (NMPolicy *policy, NMDnsManager *dns_mgr)
{
	NMIP4Config *ip4_config;
	const char *ip_iface = NULL;
	NMVPNConnection *vpn = NULL;
	NMDnsIPConfigType dns_type = NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE;

	ip4_config = get_best_ip4_config (policy, TRUE, &ip_iface, NULL, NULL, NULL, &vpn);
	if (ip4_config) {
		if (vpn)
			dns_type = NM_DNS_IP_CONFIG_TYPE_VPN;

		/* Tell the DNS manager this config is preferred by re-adding it with
		 * a different IP config type.
		 */
		nm_dns_manager_add_ip4_config (dns_mgr, ip_iface, ip4_config, dns_type);
	}
}

static void
update_ip4_routing (NMPolicy *policy, gboolean force_update)
{
	NMDevice *best = NULL, *parent;
	NMConnection *connection = NULL;
	NMVPNConnection *vpn = NULL;
	NMActiveConnection *best_ac = NULL;
	NMIP4Config *ip4_config = NULL, *parent_ip4;
	const char *ip_iface = NULL;
	int ip_ifindex = -1;
	guint32 gw_addr = 0, parent_mss;
	guint32 i;

	/* Note that we might have an IPv4 VPN tunneled over an IPv6-only device,
	 * so we can get (vpn != NULL && best == NULL).
	 */
	ip4_config = get_best_ip4_config (policy, FALSE, &ip_iface, &ip_ifindex, &best_ac, &best, &vpn);
	if (!ip4_config) {
		policy->default_device4 = NULL;
		return;
	}
	g_assert ((best || vpn) && best_ac);

	if (!force_update && best && (best == policy->default_device4))
		return;

	/* We set the default route to the first gateway we find.  If we don't find
	 * a gateway (WWAN, point-to-point, etc) then we just use 0.0.0.0
	 */
	for (i = 0; i < nm_ip4_config_get_num_addresses (ip4_config); i++) {
		NMIP4Address *addr;

		addr = nm_ip4_config_get_address (ip4_config, i);
		if (nm_ip4_address_get_gateway (addr)) {
			gw_addr = nm_ip4_address_get_gateway (addr);
			break;
		}
	}

	if (vpn) {
		parent = nm_vpn_connection_get_parent_device (vpn);
		parent_ip4 = nm_device_get_ip4_config (parent);
		parent_mss = parent_ip4 ? nm_ip4_config_get_mss (parent_ip4) : 0;

		nm_system_replace_default_ip4_route_vpn (ip_ifindex,
		                                         gw_addr,
		                                         nm_vpn_connection_get_ip4_internal_gateway (vpn),
		                                         nm_ip4_config_get_mss (ip4_config),
		                                         nm_device_get_ip_ifindex (parent),
		                                         parent_mss);
	} else {
		nm_system_replace_default_ip4_route (ip_ifindex,
		                                     gw_addr,
		                                     nm_ip4_config_get_mss (ip4_config));
	}

	update_default_ac (policy, best_ac, nm_active_connection_set_default);
	policy->default_device4 = best;

	connection = nm_active_connection_get_connection (best_ac);
	nm_log_info (LOGD_CORE, "Policy set '%s' (%s) as default for IPv4 routing and DNS.",
	             nm_connection_get_id (connection), ip_iface);
}

static NMIP6Config *
get_best_ip6_config (NMPolicy *policy,
                     gboolean ignore_never_default,
                     const char **out_ip_iface,
                     int *out_ip_ifindex,
                     NMActiveConnection **out_ac,
                     NMDevice **out_device,
                     NMVPNConnection **out_vpn)
{
	const GSList *connections, *iter;
	NMDevice *device;
	NMActRequest *req = NULL;
	NMIP6Config *ip6_config = NULL;

	/* If a VPN connection is active, it is preferred */
	connections = nm_manager_get_active_connections (policy->manager);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMActiveConnection *active = NM_ACTIVE_CONNECTION (iter->data);
		NMVPNConnection *candidate;
		NMIP6Config *vpn_ip6;
		NMConnection *tmp;
		NMSettingIP6Config *s_ip6;
		NMVPNConnectionState vpn_state;

		if (!NM_IS_VPN_CONNECTION (active))
			continue;

		candidate = NM_VPN_CONNECTION (active);

		tmp = nm_active_connection_get_connection (active);
		g_assert (tmp);

		vpn_state = nm_vpn_connection_get_vpn_state (candidate);
		if (vpn_state != NM_VPN_CONNECTION_STATE_ACTIVATED)
			continue;

		vpn_ip6 = nm_vpn_connection_get_ip6_config (candidate);
		if (!vpn_ip6)
			continue;

		if (ignore_never_default == FALSE) {
			/* Check for a VPN-provided config never-default */
			if (nm_ip6_config_get_never_default (vpn_ip6))
				continue;

			/* Check the user's preference from the NMConnection */
			s_ip6 = nm_connection_get_setting_ip6_config (tmp);
			if (s_ip6 && nm_setting_ip6_config_get_never_default (s_ip6))
				continue;
		}

		ip6_config = vpn_ip6;
		if (out_vpn)
			*out_vpn = candidate;
		if (out_ac)
			*out_ac = NM_ACTIVE_CONNECTION (candidate);
		if (out_ip_iface)
			*out_ip_iface = nm_vpn_connection_get_ip_iface (candidate);
		if (out_ip_ifindex)
			*out_ip_ifindex = nm_vpn_connection_get_ip_ifindex (candidate);
		break;
	}

	/* If no VPN connections, we use the best device instead */
	if (!ip6_config) {
		device = get_best_ip6_device (policy->manager);
		if (device) {
			req = nm_device_get_act_request (device);
			g_assert (req);
			ip6_config = nm_device_get_ip6_config (device);
			g_assert (ip6_config);

			if (out_device)
				*out_device = device;
			if (out_ac)
				*out_ac = NM_ACTIVE_CONNECTION (req);
			if (out_ip_iface)
				*out_ip_iface = nm_device_get_ip_iface (device);
			if (out_ip_ifindex)
				*out_ip_ifindex = nm_device_get_ip_ifindex (device);
		}
	}

	return ip6_config;
}

static void
update_ip6_dns (NMPolicy *policy, NMDnsManager *dns_mgr)
{
	NMIP6Config *ip6_config;
	const char *ip_iface = NULL;
	NMVPNConnection *vpn = NULL;
	NMDnsIPConfigType dns_type = NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE;

	ip6_config = get_best_ip6_config (policy, TRUE, &ip_iface, NULL, NULL, NULL, &vpn);
	if (ip6_config) {
		if (vpn)
			dns_type = NM_DNS_IP_CONFIG_TYPE_VPN;

		/* Tell the DNS manager this config is preferred by re-adding it with
		 * a different IP config type.
		 */
		nm_dns_manager_add_ip6_config (dns_mgr, ip_iface, ip6_config, dns_type);
	}
}

static void
update_ip6_routing (NMPolicy *policy, gboolean force_update)
{
	NMDevice *best = NULL, *parent;
	NMConnection *connection = NULL;
	NMVPNConnection *vpn = NULL;
	NMActiveConnection *best_ac = NULL;
	NMIP6Config *ip6_config = NULL, *parent_ip6;
	const char *ip_iface = NULL;
	int ip_ifindex = -1;
	guint32 parent_mss;
	guint32 i;
	const struct in6_addr *gw_addr;

	/* Note that we might have an IPv6 VPN tunneled over an IPv4-only device,
	 * so we can get (vpn != NULL && best == NULL).
	 */
	ip6_config = get_best_ip6_config (policy, FALSE, &ip_iface, &ip_ifindex, &best_ac, &best, &vpn);
	if (!ip6_config) {
		policy->default_device6 = NULL;
		return;
	}
	g_assert ((best || vpn) && best_ac);

	if (!force_update && best && (best == policy->default_device6))
		return;

	/* If no better gateway is found, use ::; not all configurations will
	 * have a gateway, especially WWAN/Point-to-Point connections.
	 */
	gw_addr = &in6addr_any;

	/* Look for a gateway paired with one of the addresses */
	for (i = 0; i < nm_ip6_config_get_num_addresses (ip6_config); i++) {
		NMIP6Address *addr;

		addr = nm_ip6_config_get_address (ip6_config, i);
		if (nm_ip6_address_get_gateway (addr)) {
			gw_addr = nm_ip6_address_get_gateway (addr);
			break;
		}
	}

	/* If we don't find a paired gateway, try the generic IPv6 gateway */
	if (   IN6_IS_ADDR_UNSPECIFIED (gw_addr)
	    && nm_ip6_config_get_gateway (ip6_config))
		gw_addr = nm_ip6_config_get_gateway (ip6_config);

	if (vpn) {
		parent = nm_vpn_connection_get_parent_device (vpn);
		parent_ip6 = nm_device_get_ip6_config (parent);
		parent_mss = parent_ip6 ? nm_ip6_config_get_mss (parent_ip6) : 0;

		nm_system_replace_default_ip6_route_vpn (ip_ifindex,
		                                         gw_addr,
		                                         nm_vpn_connection_get_ip6_internal_gateway (vpn),
		                                         nm_ip6_config_get_mss (ip6_config),
		                                         nm_device_get_ip_ifindex (parent),
		                                         parent_mss);
	} else {
		if (gw_addr)
			nm_system_replace_default_ip6_route (ip_ifindex, gw_addr);
		else
			nm_log_dbg (LOGD_IP6, "missing default IPv6 gateway");
	}

	update_default_ac (policy, best_ac, nm_active_connection_set_default6);
	policy->default_device6 = best;

	connection = nm_active_connection_get_connection (best_ac);
	nm_log_info (LOGD_CORE, "Policy set '%s' (%s) as default for IPv6 routing and DNS.",
	             nm_connection_get_id (connection), ip_iface);
}

static void
update_routing_and_dns (NMPolicy *policy, gboolean force_update)
{
	NMDnsManager *mgr;

	mgr = nm_dns_manager_get (NULL);
	nm_dns_manager_begin_updates (mgr, __func__);

	update_ip4_dns (policy, mgr);
	update_ip6_dns (policy, mgr);

	update_ip4_routing (policy, force_update);
	update_ip6_routing (policy, force_update);

	/* Update the system hostname */
	update_system_hostname (policy, policy->default_device4, policy->default_device6);

	nm_dns_manager_end_updates (mgr, __func__);
	g_object_unref (mgr);
}

static void
set_connection_auto_retries (NMConnection *connection, guint retries)
{
	/* add +1 so that the tag still exists if the # retries is 0 */
	g_object_set_data (G_OBJECT (connection), RETRIES_TAG, GUINT_TO_POINTER (retries + 1));
}

static guint32
get_connection_auto_retries (NMConnection *connection)
{
	/* subtract 1 to handle the +1 from set_connection_auto_retries() */
	return GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), RETRIES_TAG)) - 1;
}

typedef struct {
	NMPolicy *policy;
	NMDevice *device;
	guint id;
} ActivateData;

static void
activate_data_free (ActivateData *data)
{
	if (data->id)
		g_source_remove (data->id);
	g_object_unref (data->device);
	memset (data, 0, sizeof (*data));
	g_free (data);
}

static gboolean
auto_activate_device (gpointer user_data)
{
	ActivateData *data = (ActivateData *) user_data;
	NMPolicy *policy;
	NMConnection *best_connection;
	char *specific_object = NULL;
	GSList *connections, *iter;

	g_assert (data);
	policy = data->policy;

	data->id = 0;
	policy->pending_activation_checks = g_slist_remove (policy->pending_activation_checks, data);

	// FIXME: if a device is already activating (or activated) with a connection
	// but another connection now overrides the current one for that device,
	// deactivate the device and activate the new connection instead of just
	// bailing if the device is already active
	if (nm_device_get_act_request (data->device))
		goto out;

	iter = connections = nm_settings_get_connections (policy->settings);

	/* Remove connections that shouldn't be auto-activated */
	while (iter) {
		NMSettingsConnection *candidate = NM_SETTINGS_CONNECTION (iter->data);
		gboolean remove_it = FALSE;
		const char *permission;

		/* Grab next item before we possibly delete the current item */
		iter = g_slist_next (iter);

		/* Ignore connections that were tried too many times or are not visible
		 * to any logged-in users.  Also ignore shared wifi connections for
		 * which no user has the shared wifi permission.
		 */
		if (   get_connection_auto_retries (NM_CONNECTION (candidate)) == 0
		    || nm_settings_connection_is_visible (candidate) == FALSE)
			remove_it = TRUE;
		else {
			permission = nm_utils_get_shared_wifi_permission (NM_CONNECTION (candidate));
			if (permission) {
				if (nm_settings_connection_check_permission (candidate, permission) == FALSE)
					remove_it = TRUE;
			}
		}

		if (remove_it)
			connections = g_slist_remove (connections, candidate);
	}

	best_connection = nm_device_get_best_auto_connection (data->device, connections, &specific_object);
	if (best_connection) {
		GError *error = NULL;

		nm_log_info (LOGD_DEVICE, "Auto-activating connection '%s'.",
		             nm_connection_get_id (best_connection));
		if (!nm_manager_activate_connection (policy->manager,
		                                     best_connection,
		                                     specific_object,
		                                     nm_device_get_path (data->device),
		                                     NULL,
		                                     &error)) {
			nm_log_info (LOGD_DEVICE, "Connection '%s' auto-activation failed: (%d) %s",
			             nm_connection_get_id (best_connection),
			             error ? error->code : -1,
			             error ? error->message : "(none)");
			g_error_free (error);
		}
	}

	g_slist_free (connections);

 out:
	activate_data_free (data);
	return FALSE;
}

static ActivateData *
activate_data_new (NMPolicy *policy, NMDevice *device, guint delay_seconds)
{
	ActivateData *data;

	data = g_malloc0 (sizeof (ActivateData));
	data->policy = policy;
	data->device = g_object_ref (device);
	if (delay_seconds > 0)
		data->id = g_timeout_add_seconds (delay_seconds, auto_activate_device, data);
	else
		data->id = g_idle_add (auto_activate_device, data);
	return data;
}

static ActivateData *
find_pending_activation (GSList *list, NMDevice *device)
{
	GSList *iter;

	for (iter = list; iter; iter = g_slist_next (iter)) {
		if (((ActivateData *) iter->data)->device == device)
			return iter->data;
	}
	return NULL;
}

/*****************************************************************************/

typedef struct {
	NMDevice *device;
	GSList *secondaries;
} PendingSecondaryData;

static PendingSecondaryData *
pending_secondary_data_new (NMDevice *device, GSList *secondaries)
{
	PendingSecondaryData *data;

	data = g_malloc0 (sizeof (PendingSecondaryData));
	data->device = g_object_ref (device);
	data->secondaries = secondaries;
	return data;
}

static void
pending_secondary_data_free (PendingSecondaryData *data)
{
	g_object_unref (data->device);
	nm_utils_slist_free (data->secondaries, g_free);
	memset (data, 0, sizeof (*data));
	g_free (data);
}

static void
process_secondaries (NMPolicy *policy,
                     NMActiveConnection *active,
                     gboolean connected)
{
	NMDevice *device = NULL;
	const char *ac_path;
	GSList *iter, *iter2;

	nm_log_dbg (LOGD_DEVICE, "Secondary connection '%s' %s; active path '%s'",
	            nm_active_connection_get_name (active),
	            connected ? "SUCCEEDED" : "FAILED",
	            nm_active_connection_get_path (active));

	ac_path = nm_active_connection_get_path (active);

	if (NM_IS_VPN_CONNECTION (active))
		device = nm_vpn_connection_get_parent_device (NM_VPN_CONNECTION (active));

	for (iter = policy->pending_secondaries; iter; iter = g_slist_next (iter)) {
		PendingSecondaryData *secondary_data = (PendingSecondaryData *) iter->data;
		NMDevice *item_device = secondary_data->device;

		if (!device || item_device == device) {
			for (iter2 = secondary_data->secondaries; iter2; iter2 = g_slist_next (iter2)) {
				char *list_ac_path = (char *) iter2->data;

				if (g_strcmp0 (ac_path, list_ac_path) == 0) {
					if (connected) {
						/* Secondary connection activated */
						secondary_data->secondaries = g_slist_remove (secondary_data->secondaries, list_ac_path);
						g_free (list_ac_path);
						if (!secondary_data->secondaries) {
							/* None secondary UUID remained -> remove the secondary data item */
							policy->pending_secondaries = g_slist_remove (policy->pending_secondaries, secondary_data);
							pending_secondary_data_free (secondary_data);
							nm_device_state_changed (item_device, NM_DEVICE_STATE_ACTIVATED, NM_DEVICE_STATE_REASON_NONE);
							return;
						}
					} else {
						/* Secondary connection failed -> do not watch other connections */
						policy->pending_secondaries = g_slist_remove (policy->pending_secondaries, secondary_data);
						pending_secondary_data_free (secondary_data);
						nm_device_state_changed (item_device, NM_DEVICE_STATE_FAILED,
						                                      NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED);
						return;
					}
				}
			}
			return;
		}
	}
}

static void
global_state_changed (NMManager *manager, NMState state, gpointer user_data)
{
}

static void
hostname_changed (NMManager *manager, GParamSpec *pspec, gpointer user_data)
{
	update_system_hostname ((NMPolicy *) user_data, NULL, NULL);
}

static void
reset_retries_all (NMSettings *settings, NMDevice *device)
{
	GSList *connections, *iter;
	GError *error = NULL;

	connections = nm_settings_get_connections (settings);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		if (!device || nm_device_check_connection_compatible (device, iter->data, &error))
			set_connection_auto_retries (NM_CONNECTION (iter->data), RETRIES_DEFAULT);
		g_clear_error (&error);
	}
	g_slist_free (connections);
}

static void
reset_retries_for_failed_secrets (NMSettings *settings)
{
	GSList *connections, *iter;

	connections = nm_settings_get_connections (settings);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMDeviceStateReason reason = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (iter->data), FAILURE_REASON_TAG));

		if (reason == NM_DEVICE_STATE_REASON_NO_SECRETS) {
			set_connection_auto_retries (NM_CONNECTION (iter->data), RETRIES_DEFAULT);
			g_object_set_data (G_OBJECT (iter->data), FAILURE_REASON_TAG, GUINT_TO_POINTER (0));
		}
	}
	g_slist_free (connections);
}

static void
sleeping_changed (NMManager *manager, GParamSpec *pspec, gpointer user_data)
{
	NMPolicy *policy = user_data;
	gboolean sleeping = FALSE, enabled = FALSE;

	g_object_get (G_OBJECT (manager), NM_MANAGER_SLEEPING, &sleeping, NULL);
	g_object_get (G_OBJECT (manager), NM_MANAGER_NETWORKING_ENABLED, &enabled, NULL);

	/* Reset retries on all connections so they'll checked on wakeup */
	if (sleeping || !enabled)
		reset_retries_all (policy->settings, NULL);
}

static void
schedule_activate_check (NMPolicy *policy, NMDevice *device, guint delay_seconds)
{
	ActivateData *data;
	NMDeviceState state;

	if (nm_manager_get_state (policy->manager) == NM_STATE_ASLEEP)
		return;

	state = nm_device_get_state (device);
	if (state < NM_DEVICE_STATE_DISCONNECTED)
		return;

	if (!nm_device_get_enabled (device))
		return;

	if (!nm_device_autoconnect_allowed (device))
		return;

	/* Schedule an auto-activation if there isn't one already for this device */
	if (find_pending_activation (policy->pending_activation_checks, device) == NULL) {
		data = activate_data_new (policy, device, delay_seconds);
		policy->pending_activation_checks = g_slist_append (policy->pending_activation_checks, data);
	}
}

static gboolean
reset_connections_retries (gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	GSList *connections, *iter;
	time_t con_stamp, min_stamp, now;
	gboolean changed = FALSE;

	policy->reset_retries_id = 0;

	min_stamp = now = time (NULL);
	connections = nm_settings_get_connections (policy->settings);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		con_stamp = GPOINTER_TO_SIZE (g_object_get_data (G_OBJECT (iter->data), RESET_RETRIES_TIMESTAMP_TAG));
		if (con_stamp == 0)
			continue;
		if (con_stamp + RESET_RETRIES_TIMER <= now) {
			set_connection_auto_retries (NM_CONNECTION (iter->data), RETRIES_DEFAULT);
			g_object_set_data (G_OBJECT (iter->data), RESET_RETRIES_TIMESTAMP_TAG, GSIZE_TO_POINTER (0));
			changed = TRUE;
			continue;
		}
		if (con_stamp < min_stamp)
			min_stamp = con_stamp;
	}
	g_slist_free (connections);

	/* Schedule the handler again if there are some stamps left */
	if (min_stamp != now)
		policy->reset_retries_id = g_timeout_add_seconds (RESET_RETRIES_TIMER - (now - min_stamp), reset_connections_retries, policy);

	/* If anything changed, try to activate the newly re-enabled connections */
	if (changed)
		schedule_activate_all (policy);

	return FALSE;
}

static void schedule_activate_all (NMPolicy *policy);

static void
activate_slave_connections (NMPolicy *policy, NMConnection *connection,
                            NMDevice *device)
{
	const char *master_device;
	GSList *connections, *iter;

	master_device = nm_device_get_iface (device);
	g_assert (master_device);

	connections = nm_settings_get_connections (policy->settings);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *slave;
		NMSettingConnection *s_slave_con;

		slave = NM_CONNECTION (iter->data);
		g_assert (slave);

		s_slave_con = nm_connection_get_setting_connection (slave);
		g_assert (s_slave_con);

		if (!g_strcmp0 (nm_setting_connection_get_master (s_slave_con), master_device))
			set_connection_auto_retries (slave, RETRIES_DEFAULT);
	}

	g_slist_free (connections);

	schedule_activate_all (policy);
}

static gboolean
activate_secondary_connections (NMPolicy *policy,
                                NMConnection *connection,
                                NMDevice *device)
{
	NMSettingConnection *s_con;
	NMSettingsConnection *settings_con;
	NMActiveConnection *ac;
	PendingSecondaryData *secondary_data;
	GSList *secondary_ac_list = NULL;
	GError *error = NULL;
	guint32 i;
	gboolean success = TRUE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	for (i = 0; i < nm_setting_connection_get_num_secondaries (s_con); i++) {
		const char *sec_uuid = nm_setting_connection_get_secondary (s_con, i);

		settings_con = nm_settings_get_connection_by_uuid (policy->settings, sec_uuid);
		if (settings_con) {
			NMActRequest *req = nm_device_get_act_request (device);
			g_assert (req);

			nm_log_dbg (LOGD_DEVICE, "Activating secondary connection '%s (%s)' for base connection '%s (%s)'",
			            nm_connection_get_id (NM_CONNECTION (settings_con)), sec_uuid,
			            nm_connection_get_id (connection), nm_connection_get_uuid (connection));
			ac = nm_manager_activate_connection (policy->manager,
			                                     NM_CONNECTION (settings_con),
			                                     nm_active_connection_get_path (NM_ACTIVE_CONNECTION (req)),
			                                     nm_device_get_path (device),
			                                     nm_act_request_get_dbus_sender (req),
			                                     &error);
			if (ac) {
				secondary_ac_list = g_slist_append (secondary_ac_list,
				                                    g_strdup (nm_active_connection_get_path (ac)));
			} else {
				nm_log_warn (LOGD_DEVICE, "Secondary connection '%s' auto-activation failed: (%d) %s",
				             sec_uuid,
				             error ? error->code : 0,
				             (error && error->message) ? error->message : "unknown");
				g_clear_error (&error);
				success = FALSE;
				break;
			}
		} else {
			nm_log_warn (LOGD_DEVICE, "Secondary connection '%s' auto-activation failed: The connection doesn't exist.",
			             sec_uuid);
			success = FALSE;
			break;
		}
	}

	if (success && secondary_ac_list != NULL) {
		secondary_data = pending_secondary_data_new (device, secondary_ac_list);
		policy->pending_secondaries = g_slist_append (policy->pending_secondaries, secondary_data);
	} else
		nm_utils_slist_free (secondary_ac_list, g_free);

	return success;
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	NMConnection *connection = nm_device_get_connection (device);
	const char *ip_iface = nm_device_get_ip_iface (device);
	NMIP4Config *ip4_config;
	NMIP6Config *ip6_config;
	NMSettingConnection *s_con;
	NMDnsManager *dns_mgr;

	if (connection)
		g_object_set_data (G_OBJECT (connection), FAILURE_REASON_TAG, GUINT_TO_POINTER (0));

	switch (new_state) {
	case NM_DEVICE_STATE_FAILED:
		/* Mark the connection invalid if it failed during activation so that
		 * it doesn't get automatically chosen over and over and over again.
		 */
		if (   connection
		    && old_state >= NM_DEVICE_STATE_PREPARE
		    && old_state <= NM_DEVICE_STATE_ACTIVATED) {
			guint32 tries = get_connection_auto_retries (connection);

			if (reason == NM_DEVICE_STATE_REASON_NO_SECRETS) {
				/* If the connection couldn't get the secrets it needed (ex because
				 * the user canceled, or no secrets exist), there's no point in
				 * automatically retrying because it's just going to fail anyway.
				 */
				set_connection_auto_retries (connection, 0);

				/* Mark the connection as failed due to missing secrets so that we can reset
				 * RETRIES_TAG and automatically re-try when an secret agent registers.
				 */
				g_object_set_data (G_OBJECT (connection), FAILURE_REASON_TAG, GUINT_TO_POINTER (NM_DEVICE_STATE_REASON_NO_SECRETS));
			} else if (tries > 0) {
				/* Otherwise if it's a random failure, just decrease the number
				 * of automatic retries so that the connection gets tried again
				 * if it still has a retry count.
				 */
				set_connection_auto_retries (connection, tries - 1);
			}

			if (get_connection_auto_retries (connection) == 0) {
				nm_log_info (LOGD_DEVICE, "Marking connection '%s' invalid.", nm_connection_get_id (connection));
				/* Schedule a handler to reset retries count */
				g_object_set_data (G_OBJECT (connection), RESET_RETRIES_TIMESTAMP_TAG, GSIZE_TO_POINTER ((gsize) time (NULL)));
				if (!policy->reset_retries_id)
					policy->reset_retries_id = g_timeout_add_seconds (RESET_RETRIES_TIMER, reset_connections_retries, policy);
			}
			nm_connection_clear_secrets (connection);
		}
		schedule_activate_check (policy, device, 3);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		if (connection) {
			/* Reset auto retries back to default since connection was successful */
			set_connection_auto_retries (connection, RETRIES_DEFAULT);

			/* And clear secrets so they will always be requested from the
			 * settings service when the next connection is made.
			 */
			nm_connection_clear_secrets (connection);
		}

		/* Add device's new IPv4 and IPv6 configs to DNS */

		dns_mgr = nm_dns_manager_get (NULL);
		nm_dns_manager_begin_updates (dns_mgr, __func__);

		ip4_config = nm_device_get_ip4_config (device);
		if (ip4_config)
			nm_dns_manager_add_ip4_config (dns_mgr, ip_iface, ip4_config, NM_DNS_IP_CONFIG_TYPE_DEFAULT);
		ip6_config = nm_device_get_ip6_config (device);
		if (ip6_config)
			nm_dns_manager_add_ip6_config (dns_mgr, ip_iface, ip6_config, NM_DNS_IP_CONFIG_TYPE_DEFAULT);

		update_routing_and_dns (policy, FALSE);

		nm_dns_manager_end_updates (dns_mgr, __func__);
		g_object_unref (dns_mgr);
		break;
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
		if (old_state > NM_DEVICE_STATE_DISCONNECTED)
			update_routing_and_dns (policy, FALSE);
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		/* Reset RETRIES_TAG when carrier on. If cable was unplugged
		 * and plugged again, we should try to reconnect */
		if (reason == NM_DEVICE_STATE_REASON_CARRIER && old_state == NM_DEVICE_STATE_UNAVAILABLE)
			reset_retries_all (policy->settings, device);

		if (old_state > NM_DEVICE_STATE_DISCONNECTED)
			update_routing_and_dns (policy, FALSE);

		/* Device is now available for auto-activation */
		schedule_activate_check (policy, device, 0);
		break;

	case NM_DEVICE_STATE_PREPARE:
		/* Reset auto-connect retries of all slaves and schedule them for
		 * activation. */
		activate_slave_connections (policy, connection, device);
		break;
	case NM_DEVICE_STATE_SECONDARIES:
		s_con = nm_connection_get_setting_connection (connection);
		if (s_con && nm_setting_connection_get_num_secondaries (s_con) > 0) {
			/* Make routes and DNS up-to-date before activating dependent connections */
			update_routing_and_dns (policy, FALSE);

			/* Activate secondary (VPN) connections */
			if (!activate_secondary_connections (policy, connection, device))
				nm_device_queue_state (device, NM_DEVICE_STATE_FAILED,
				                       NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED);
		} else
			nm_device_queue_state (device, NM_DEVICE_STATE_ACTIVATED,
			                       NM_DEVICE_STATE_REASON_NONE);
		break;

	default:
		break;
	}
}

static void
device_ip4_config_changed (NMDevice *device,
                           NMIP4Config *new_config,
                           NMIP4Config *old_config,
                           gpointer user_data)
{
	NMPolicy *policy = user_data;
	NMDnsManager *dns_mgr;
	const char *ip_iface = nm_device_get_ip_iface (device);
	NMIP4ConfigCompareFlags diff = NM_IP4_COMPARE_FLAG_ALL;

	dns_mgr = nm_dns_manager_get (NULL);
	nm_dns_manager_begin_updates (dns_mgr, __func__);

	/* Old configs get removed immediately */
	if (old_config)
		nm_dns_manager_remove_ip4_config (dns_mgr, ip_iface, old_config);

	/* Ignore IP config changes while the device is activating, because we'll
	 * catch all the changes when the device moves to ACTIVATED state.
	 * Prevents unecessary changes to DNS information.
	 */
	if (!nm_device_is_activating (device)) {
		if (new_config)
			nm_dns_manager_add_ip4_config (dns_mgr, ip_iface, new_config, NM_DNS_IP_CONFIG_TYPE_DEFAULT);
		update_ip4_dns (policy, dns_mgr);

		/* Only change routing if something actually changed */
		diff = nm_ip4_config_diff (new_config, old_config);
		if (diff & (NM_IP4_COMPARE_FLAG_ADDRESSES | NM_IP4_COMPARE_FLAG_PTP_ADDRESS | NM_IP4_COMPARE_FLAG_ROUTES))
			update_ip4_routing (policy, TRUE);
	}

	nm_dns_manager_end_updates (dns_mgr, __func__);
	g_object_unref (dns_mgr);
}

static void
device_ip6_config_changed (NMDevice *device,
                           NMIP6Config *new_config,
                           NMIP6Config *old_config,
                           gpointer user_data)
{
	NMPolicy *policy = user_data;
	NMDnsManager *dns_mgr;
	const char *ip_iface = nm_device_get_ip_iface (device);
	NMIP4ConfigCompareFlags diff = NM_IP4_COMPARE_FLAG_ALL;

	dns_mgr = nm_dns_manager_get (NULL);
	nm_dns_manager_begin_updates (dns_mgr, __func__);

	/* Old configs get removed immediately */
	if (old_config)
		nm_dns_manager_remove_ip6_config (dns_mgr, ip_iface, old_config);

	/* Ignore IP config changes while the device is activating, because we'll
	 * catch all the changes when the device moves to ACTIVATED state.
	 * Prevents unecessary changes to DNS information.
	 */
	if (!nm_device_is_activating (device)) {
		if (new_config)
			nm_dns_manager_add_ip6_config (dns_mgr, ip_iface, new_config, NM_DNS_IP_CONFIG_TYPE_DEFAULT);
		update_ip6_dns (policy, dns_mgr);

		/* Only change routing if something actually changed */
		diff = nm_ip6_config_diff (new_config, old_config);
		if (diff & (NM_IP6_COMPARE_FLAG_ADDRESSES | NM_IP6_COMPARE_FLAG_PTP_ADDRESS | NM_IP6_COMPARE_FLAG_ROUTES))
			update_ip6_routing (policy, TRUE);
	}

	nm_dns_manager_end_updates (dns_mgr, __func__);
	g_object_unref (dns_mgr);
}

static void
device_autoconnect_changed (NMDevice *device,
                            GParamSpec *pspec,
                            gpointer user_data)
{
	if (nm_device_get_autoconnect (device))
		schedule_activate_check ((NMPolicy *) user_data, device, 0);
}

static void
wireless_networks_changed (NMDevice *device, GObject *ap, gpointer user_data)
{
	schedule_activate_check ((NMPolicy *) user_data, device, 0);
}

static void
nsps_changed (NMDevice *device, GObject *nsp, gpointer user_data)
{
	schedule_activate_check ((NMPolicy *) user_data, device, 0);
}

static void
modem_enabled_changed (NMDevice *device, gpointer user_data)
{
	schedule_activate_check ((NMPolicy *) (user_data), device, 0);
}

typedef struct {
	gulong id;
	NMDevice *device;
} DeviceSignalId;

static void
_connect_device_signal (NMPolicy *policy, NMDevice *device, const char *name, gpointer callback)
{
	DeviceSignalId *data;

	data = g_slice_new0 (DeviceSignalId);
	g_assert (data);
	data->id = g_signal_connect (device, name, callback, policy);
	data->device = device;
	policy->dev_ids = g_slist_prepend (policy->dev_ids, data);
}

static void
device_added (NMManager *manager, NMDevice *device, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	_connect_device_signal (policy, device, "state-changed", device_state_changed);
	_connect_device_signal (policy, device, NM_DEVICE_IP4_CONFIG_CHANGED, device_ip4_config_changed);
	_connect_device_signal (policy, device, NM_DEVICE_IP6_CONFIG_CHANGED, device_ip6_config_changed);
	_connect_device_signal (policy, device, "notify::" NM_DEVICE_AUTOCONNECT, device_autoconnect_changed);

	switch (nm_device_get_device_type (device)) {
	case NM_DEVICE_TYPE_WIFI:
		_connect_device_signal (policy, device, "access-point-added", wireless_networks_changed);
		_connect_device_signal (policy, device, "access-point-removed", wireless_networks_changed);
		break;
	case NM_DEVICE_TYPE_WIMAX:
		_connect_device_signal (policy, device, "nsp-added", nsps_changed);
		_connect_device_signal (policy, device, "nsp-removed", nsps_changed);
		break;
	case NM_DEVICE_TYPE_MODEM:
		_connect_device_signal (policy, device, "enable-changed", modem_enabled_changed);
		break;
	default:
		break;
	}
}

static void
device_removed (NMManager *manager, NMDevice *device, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	ActivateData *tmp;
	GSList *iter;

	/* Clear any idle callbacks for this device */
	tmp = find_pending_activation (policy->pending_activation_checks, device);
	if (tmp) {
		policy->pending_activation_checks = g_slist_remove (policy->pending_activation_checks, tmp);
		activate_data_free (tmp);
	}

	/* Clear any signal handlers for this device */
	iter = policy->dev_ids;
	while (iter) {
		DeviceSignalId *data = iter->data;
		GSList *next = g_slist_next (iter);

		if (data->device == device) {
			g_signal_handler_disconnect (data->device, data->id);
			g_slice_free (DeviceSignalId, data);
			policy->dev_ids = g_slist_delete_link (policy->dev_ids, iter);
		}
		iter = next;
	}

	/* Don't update routing and DNS here as we've already handled that
	 * for devices that need it when the device's state changed to UNMANAGED.
	 */
}

/**************************************************************************/

static void
vpn_connection_activated (NMPolicy *policy, NMVPNConnection *vpn)
{
	NMDnsManager *mgr;
	NMIP4Config *ip4_config;
	NMIP6Config *ip6_config;
	const char *ip_iface;

	mgr = nm_dns_manager_get (NULL);
	nm_dns_manager_begin_updates (mgr, __func__);

	ip_iface = nm_vpn_connection_get_ip_iface (vpn);

	/* Add the VPN connection's IP configs from DNS */

	ip4_config = nm_vpn_connection_get_ip4_config (vpn);
	if (ip4_config)
		nm_dns_manager_add_ip4_config (mgr, ip_iface, ip4_config, NM_DNS_IP_CONFIG_TYPE_VPN);

	ip6_config = nm_vpn_connection_get_ip6_config (vpn);
	if (ip6_config)
		nm_dns_manager_add_ip6_config (mgr, ip_iface, ip6_config, NM_DNS_IP_CONFIG_TYPE_VPN);

	update_routing_and_dns (policy, TRUE);

	nm_dns_manager_end_updates (mgr, __func__);

	process_secondaries (policy, NM_ACTIVE_CONNECTION (vpn), TRUE);
}

static void
vpn_connection_deactivated (NMPolicy *policy, NMVPNConnection *vpn)
{
	NMDnsManager *mgr;
	NMIP4Config *ip4_config, *parent_ip4 = NULL;
	NMIP6Config *ip6_config, *parent_ip6 = NULL;
	const char *ip_iface;
	NMDevice *parent;

	mgr = nm_dns_manager_get (NULL);
	nm_dns_manager_begin_updates (mgr, __func__);

	ip_iface = nm_vpn_connection_get_ip_iface (vpn);
	parent = nm_vpn_connection_get_parent_device (vpn);

	ip4_config = nm_vpn_connection_get_ip4_config (vpn);
	if (ip4_config) {
		/* Remove the VPN connection's IP4 config from DNS */
		nm_dns_manager_remove_ip4_config (mgr, ip_iface, ip4_config);

		/* Re-apply routes and addresses of the VPN connection's parent interface,
		 * which the VPN might have overridden.
		 */
		if (parent) {
			parent_ip4 = nm_device_get_ip4_config (parent);
			if (parent_ip4) {
				if (!nm_system_apply_ip4_config (nm_device_get_ip_ifindex (parent),
				                                 parent_ip4,
				                                 nm_device_get_priority (parent),
				                                 NM_IP4_COMPARE_FLAG_ADDRESSES | NM_IP4_COMPARE_FLAG_ROUTES)) {
					nm_log_err (LOGD_VPN, "failed to re-apply VPN parent device IPv4 addresses and routes.");
				}
			}
		}
	}

	ip6_config = nm_vpn_connection_get_ip6_config (vpn);
	if (ip6_config) {
		/* Remove the VPN connection's IP6 config from DNS */
		nm_dns_manager_remove_ip6_config (mgr, ip_iface, ip6_config);

		/* Re-apply routes and addresses of the VPN connection's parent interface,
		 * which the VPN might have overridden.
		 */
		if (parent) {
			parent_ip6 = nm_device_get_ip6_config (parent);
			if (parent_ip6) {
				if (!nm_system_apply_ip6_config (nm_device_get_ip_ifindex (parent),
				                                 parent_ip6,
				                                 nm_device_get_priority (parent),
				                                 NM_IP6_COMPARE_FLAG_ADDRESSES | NM_IP6_COMPARE_FLAG_ROUTES)) {
					nm_log_err (LOGD_VPN, "failed to re-apply VPN parent device IPv6 addresses and routes.");
				}
			}
		}
	}

	update_routing_and_dns (policy, TRUE);

	nm_dns_manager_end_updates (mgr, __func__);

	process_secondaries (policy, NM_ACTIVE_CONNECTION (vpn), FALSE);
}

static void
active_connection_state_changed (NMActiveConnection *active,
                                 GParamSpec *pspec,
                                 NMPolicy *policy)
{
	switch (nm_active_connection_get_state (active)) {
	case NM_ACTIVE_CONNECTION_STATE_ACTIVATED:
		if (NM_IS_VPN_CONNECTION (active))
			vpn_connection_activated (policy, NM_VPN_CONNECTION (active));
		break;
	case NM_ACTIVE_CONNECTION_STATE_DEACTIVATED:
		if (NM_IS_VPN_CONNECTION (active))
			vpn_connection_deactivated (policy, NM_VPN_CONNECTION (active));
		break;
	default:
		break;
	}
}

static void
active_connection_added (NMManager *manager,
                         NMActiveConnection *active,
                         gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	g_signal_connect (active, "notify::" NM_ACTIVE_CONNECTION_STATE,
	                  G_CALLBACK (active_connection_state_changed),
	                  policy);
}

static void
active_connection_removed (NMManager *manager,
                           NMActiveConnection *active,
                           gpointer user_data)
{
	g_signal_handlers_disconnect_by_func (active,
	                                      active_connection_state_changed,
	                                      (NMPolicy *) user_data);
}

/**************************************************************************/

static void
schedule_activate_all (NMPolicy *policy)
{
	GSList *iter, *devices;

	devices = nm_manager_get_devices (policy->manager);
	for (iter = devices; iter; iter = g_slist_next (iter))
		schedule_activate_check (policy, NM_DEVICE (iter->data), 0);
}

static void
connection_added (NMSettings *settings,
                  NMConnection *connection,
                  gpointer user_data)
{
	set_connection_auto_retries (connection, RETRIES_DEFAULT);
	schedule_activate_all ((NMPolicy *) user_data);
}

static void
connections_loaded (NMSettings *settings, gpointer user_data)
{
	// FIXME: "connections-loaded" signal is emmitted *before* we connect to it
	// in nm_policy_new(). So this function is never called. Currently we work around
	// that by calling reset_retries_all() in nm_policy_new()
	
	/* Initialize connections' auto-retries */
	reset_retries_all (settings, NULL);

	schedule_activate_all ((NMPolicy *) user_data);
}

static void
add_or_change_zone_cb (GError *error, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	if (error) {
		/* FIXME: what do we do here? */
	}

	g_object_unref (device);
}

static void
firewall_update_zone (NMPolicy *policy, NMConnection *connection)
{
	NMSettingConnection *s_con = nm_connection_get_setting_connection (connection);
	GSList *iter, *devices;

	devices = nm_manager_get_devices (policy->manager);
	/* find dev with passed connection and change zone its interface belongs to */
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *dev = NM_DEVICE (iter->data);

		if (   (nm_device_get_connection (dev) == connection)
		    && (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED)) {
			nm_firewall_manager_add_or_change_zone (policy->fw_manager,
			                                        nm_device_get_ip_iface (dev),
			                                        nm_setting_connection_get_zone (s_con),
			                                        FALSE, /* change zone */
			                                        add_or_change_zone_cb,
			                                        g_object_ref (dev));
		}
	}
}

static void
firewall_started (NMFirewallManager *manager,
                  gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	NMConnection *connection;
	NMSettingConnection *s_con;
	GSList *iter, *devices;

	devices = nm_manager_get_devices (policy->manager);
	/* add interface of each device to correct zone */
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *dev = NM_DEVICE (iter->data);

		connection = nm_device_get_connection (dev);
		s_con = nm_connection_get_setting_connection (connection);
		if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED) {
			nm_firewall_manager_add_or_change_zone (policy->fw_manager,
			                                        nm_device_get_ip_iface (dev),
			                                        nm_setting_connection_get_zone (s_con),
			                                        TRUE, /* add zone */
			                                        add_or_change_zone_cb,
			                                        g_object_ref (dev));
		}
	}
}

static void
connection_updated (NMSettings *settings,
                    NMConnection *connection,
                    gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	firewall_update_zone (policy, connection);

	/* Reset auto retries back to default since connection was updated */
	set_connection_auto_retries (connection, RETRIES_DEFAULT);

	schedule_activate_all (policy);
}

static void
_deactivate_if_active (NMManager *manager, NMConnection *connection)
{
	const GSList *active, *iter;

	active = nm_manager_get_active_connections (manager);
	for (iter = active; iter; iter = g_slist_next (iter)) {
		NMActiveConnection *ac = iter->data;
		GError *error = NULL;

		if (nm_active_connection_get_connection (ac) == connection) {
			if (!nm_manager_deactivate_connection (manager,
			                                       nm_active_connection_get_path (ac),
			                                       NM_DEVICE_STATE_REASON_CONNECTION_REMOVED,
			                                       &error)) {
				nm_log_warn (LOGD_DEVICE, "Connection '%s' disappeared, but error deactivating it: (%d) %s",
					         nm_connection_get_id (connection),
					         error ? error->code : -1,
					         error ? error->message : "(unknown)");
				g_clear_error (&error);
			}
		}
	}
}

static void
connection_removed (NMSettings *settings,
                    NMConnection *connection,
                    gpointer user_data)
{
	NMPolicy *policy = user_data;

	_deactivate_if_active (policy->manager, connection);
}

static void
connection_visibility_changed (NMSettings *settings,
                               NMSettingsConnection *connection,
                               gpointer user_data)
{
	NMPolicy *policy = user_data;

	if (nm_settings_connection_is_visible (connection))
		schedule_activate_all (policy);
	else
		_deactivate_if_active (policy->manager, NM_CONNECTION (connection));
}

static void
secret_agent_registered (NMSettings *settings,
                         NMSecretAgent *agent,
                         gpointer user_data)
{
	/* The registered secret agent may provide some missing secrets. Thus we
	 * reset retries count here and schedule activation, so that the
	 * connections failed due to missing secrets may re-try auto-connection.
	 */
	reset_retries_for_failed_secrets (settings);
	schedule_activate_all ((NMPolicy *) user_data);
}

static void
_connect_manager_signal (NMPolicy *policy, const char *name, gpointer callback)
{
	guint id;

	id = g_signal_connect (policy->manager, name, callback, policy);
	policy->manager_ids = g_slist_prepend (policy->manager_ids, GUINT_TO_POINTER (id));
}

static void
_connect_settings_signal (NMPolicy *policy, const char *name, gpointer callback)
{
	guint id;

	id = g_signal_connect (policy->settings, name, callback, policy);
	policy->settings_ids = g_slist_prepend (policy->settings_ids, GUINT_TO_POINTER (id));
}

NMPolicy *
nm_policy_new (NMManager *manager, NMSettings *settings)
{
	NMPolicy *policy;
	static gboolean initialized = FALSE;
	gulong id;
	char hostname[HOST_NAME_MAX + 2];

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (initialized == FALSE, NULL);

	policy = g_malloc0 (sizeof (NMPolicy));
	policy->manager = g_object_ref (manager);
	policy->settings = g_object_ref (settings);
	policy->update_state_id = 0;

	/* Grab hostname on startup and use that if nothing provides one */
	memset (hostname, 0, sizeof (hostname));
	if (gethostname (&hostname[0], HOST_NAME_MAX) == 0) {
		/* only cache it if it's a valid hostname */
		if (   strlen (hostname)
		    && strcmp (hostname, "localhost")
		    && strcmp (hostname, "localhost.localdomain")
		    && strcmp (hostname, "(none)"))
			policy->orig_hostname = g_strdup (hostname);
	}

	policy->fw_manager = nm_firewall_manager_get();
	id = g_signal_connect (policy->fw_manager, "started",
	                       G_CALLBACK (firewall_started), policy);
	policy->fw_started_id = id;

	_connect_manager_signal (policy, "state-changed", global_state_changed);
	_connect_manager_signal (policy, "notify::" NM_MANAGER_HOSTNAME, hostname_changed);
	_connect_manager_signal (policy, "notify::" NM_MANAGER_SLEEPING, sleeping_changed);
	_connect_manager_signal (policy, "notify::" NM_MANAGER_NETWORKING_ENABLED, sleeping_changed);
	_connect_manager_signal (policy, "device-added", device_added);
	_connect_manager_signal (policy, "device-removed", device_removed);
	_connect_manager_signal (policy, NM_MANAGER_ACTIVE_CONNECTION_ADDED, active_connection_added);
	_connect_manager_signal (policy, NM_MANAGER_ACTIVE_CONNECTION_REMOVED, active_connection_removed);

	_connect_settings_signal (policy, NM_SETTINGS_SIGNAL_CONNECTIONS_LOADED, connections_loaded);
	_connect_settings_signal (policy, NM_SETTINGS_SIGNAL_CONNECTION_ADDED, connection_added);
	_connect_settings_signal (policy, NM_SETTINGS_SIGNAL_CONNECTION_UPDATED, connection_updated);
	_connect_settings_signal (policy, NM_SETTINGS_SIGNAL_CONNECTION_REMOVED, connection_removed);
	_connect_settings_signal (policy, NM_SETTINGS_SIGNAL_CONNECTION_VISIBILITY_CHANGED,
	                          connection_visibility_changed);
	_connect_settings_signal (policy, NM_SETTINGS_SIGNAL_AGENT_REGISTERED, secret_agent_registered);

	/* Initialize connections' auto-retries */
	reset_retries_all (policy->settings, NULL);

	initialized = TRUE;
	return policy;
}

void
nm_policy_destroy (NMPolicy *policy)
{
	const GSList *connections, *iter;

	g_return_if_fail (policy != NULL);

	/* Tell any existing hostname lookup thread to die, it'll get cleaned up
	 * by the lookup thread callback.
	  */
	if (policy->lookup) {
		hostname_thread_kill (policy->lookup);
		policy->lookup = NULL;
	}

	g_slist_foreach (policy->pending_activation_checks, (GFunc) activate_data_free, NULL);
	g_slist_free (policy->pending_activation_checks);

	g_slist_foreach (policy->pending_secondaries, (GFunc) pending_secondary_data_free, NULL);
	g_slist_free (policy->pending_secondaries);

	g_signal_handler_disconnect (policy->fw_manager, policy->fw_started_id);
	g_object_unref (policy->fw_manager);

	for (iter = policy->manager_ids; iter; iter = g_slist_next (iter))
		g_signal_handler_disconnect (policy->manager, GPOINTER_TO_UINT (iter->data));
	g_slist_free (policy->manager_ids);

	for (iter = policy->settings_ids; iter; iter = g_slist_next (iter))
		g_signal_handler_disconnect (policy->settings, GPOINTER_TO_UINT (iter->data));
	g_slist_free (policy->settings_ids);

	for (iter = policy->dev_ids; iter; iter = g_slist_next (iter)) {
		DeviceSignalId *data = iter->data;

		g_signal_handler_disconnect (data->device, data->id);
		g_slice_free (DeviceSignalId, data);
	}
	g_slist_free (policy->dev_ids);

	connections = nm_manager_get_active_connections (policy->manager);
	for (iter = connections; iter; iter = g_slist_next (iter))
		active_connection_removed (policy->manager, NM_ACTIVE_CONNECTION (iter->data), policy);

	if (policy->reset_retries_id)
		g_source_remove (policy->reset_retries_id);

	g_free (policy->orig_hostname);
	g_free (policy->cur_hostname);

	g_object_unref (policy->settings);
	g_object_unref (policy->manager);
	g_free (policy);
}

