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
 * Copyright (C) 2004 - 2010 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>

#include "nm-policy.h"
#include "NetworkManagerUtils.h"
#include "nm-wifi-ap.h"
#include "nm-activation-request.h"
#include "nm-logging.h"
#include "nm-device-interface.h"
#include "nm-device.h"
#include "nm-device-wifi.h"
#include "nm-device-ethernet.h"
#include "nm-device-modem.h"
#include "nm-dbus-manager.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-connection.h"
#include "nm-system.h"
#include "nm-named-manager.h"
#include "nm-vpn-manager.h"
#include "nm-policy-hosts.h"
#include "nm-policy-hostname.h"

struct NMPolicy {
	NMManager *manager;
	guint update_state_id;
	GSList *pending_activation_checks;
	GSList *signal_ids;
	GSList *dev_signal_ids;

	NMVPNManager *vpn_manager;
	gulong vpn_activated_id;
	gulong vpn_deactivated_id;

	NMDevice *default_device4;
	NMDevice *default_device6;

	HostnameThread *lookup;

	char *orig_hostname; /* hostname at NM start time */
	char *cur_hostname;  /* hostname we want to assign */
};

#define INVALID_TAG "invalid"

static const char *
get_connection_id (NMConnection *connection)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	g_return_val_if_fail (s_con != NULL, NULL);

	return nm_setting_connection_get_id (s_con);
}

static NMDevice *
get_best_ip4_device (NMManager *manager, NMActRequest **out_req)
{
	GSList *devices, *iter;
	NMDevice *best = NULL;
	int best_prio = G_MAXINT;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (out_req != NULL, NULL);
	g_return_val_if_fail (*out_req == NULL, NULL);

	devices = nm_manager_get_devices (manager);
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *dev = NM_DEVICE (iter->data);
		NMActRequest *req;
		NMConnection *connection;
		NMIP4Config *ip4_config;
		NMSettingIP4Config *s_ip4;
		int prio;
		guint i;
		gboolean can_default = FALSE;
		const char *method = NULL;

		if (nm_device_get_state (dev) != NM_DEVICE_STATE_ACTIVATED)
			continue;

		ip4_config = nm_device_get_ip4_config (dev);
		if (!ip4_config)
			continue;

		req = nm_device_get_act_request (dev);
		g_assert (req);
		connection = nm_act_request_get_connection (req);
		g_assert (connection);

		/* Never set the default route through an IPv4LL-addressed device */
		s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
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

		if (!can_default && !NM_IS_DEVICE_MODEM (dev))
			continue;

		/* 'never-default' devices can't ever be the default */
		if (s_ip4 && nm_setting_ip4_config_get_never_default (s_ip4))
			continue;

		prio = nm_device_get_priority (dev);
		if (prio > 0 && prio < best_prio) {
			best = dev;
			best_prio = prio;
			*out_req = req;
		}
	}

	return best;
}

static NMDevice *
get_best_ip6_device (NMManager *manager, NMActRequest **out_req)
{
	GSList *devices, *iter;
	NMDevice *best = NULL;
	int best_prio = G_MAXINT;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (out_req != NULL, NULL);
	g_return_val_if_fail (*out_req == NULL, NULL);

	devices = nm_manager_get_devices (manager);
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *dev = NM_DEVICE (iter->data);
		NMActRequest *req;
		NMConnection *connection;
		NMIP6Config *ip6_config;
		NMSettingIP6Config *s_ip6;
		int prio;
		guint i;
		gboolean can_default = FALSE;
		const char *method = NULL;

		if (nm_device_get_state (dev) != NM_DEVICE_STATE_ACTIVATED)
			continue;

		ip6_config = nm_device_get_ip6_config (dev);
		if (!ip6_config)
			continue;

		req = nm_device_get_act_request (dev);
		g_assert (req);
		connection = nm_act_request_get_connection (req);
		g_assert (connection);

		/* Never set the default route through an IPv4LL-addressed device */
		s_ip6 = (NMSettingIP6Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG);
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

		if (!can_default && !NM_IS_DEVICE_MODEM (dev))
			continue;

		/* 'never-default' devices can't ever be the default */
		if (s_ip6 && nm_setting_ip6_config_get_never_default (s_ip6))
			continue;

		prio = nm_device_get_priority (dev);
		if (prio > 0 && prio < best_prio) {
			best = dev;
			best_prio = prio;
			*out_req = req;
		}
	}

	return best;
}

static void
_set_hostname (NMPolicy *policy,
               gboolean change_hostname,
               const char *new_hostname,
               const char *msg)
{
	char ip4_addr[INET_ADDRSTRLEN + 1];
	char ip6_addr[INET6_ADDRSTRLEN + 1];

	if (change_hostname) {
		NMNamedManager *named_mgr;

		g_free (policy->cur_hostname);
		policy->cur_hostname = g_strdup (new_hostname);

		named_mgr = nm_named_manager_get ();
		nm_named_manager_set_hostname (named_mgr, policy->cur_hostname);
		g_object_unref (named_mgr);
	}

	/* Get the default IPv4 and IPv6 addresses so we can assign
	 * the hostname to them in /etc/hosts.
	 */
	memset (ip4_addr, 0, sizeof (ip4_addr));
	if (policy->default_device4) {
		NMIP4Config *config = NULL;
		NMIP4Address *addr = NULL;

		config = nm_device_get_ip4_config (policy->default_device4);
		if (config)
			addr = nm_ip4_config_get_address (config, 0);

		if (addr) {
			struct in_addr tmp;

			tmp.s_addr = nm_ip4_address_get_address (addr);
			inet_ntop (AF_INET, &tmp, ip4_addr, sizeof (ip4_addr));
		}
	}

	memset (ip6_addr, 0, sizeof (ip6_addr));
	if (policy->default_device6) {
		NMIP6Config *config = NULL;
		NMIP6Address *addr = NULL;

		config = nm_device_get_ip6_config (policy->default_device6);
		if (config)
			addr = nm_ip6_config_get_address (config, 0);

		if (addr)
			inet_ntop (AF_INET6, nm_ip6_address_get_address (addr), ip6_addr, sizeof (ip6_addr));
	}

	if (nm_policy_set_system_hostname (policy->cur_hostname,
	                                   strlen (ip4_addr) ? ip4_addr : NULL,
	                                   strlen (ip6_addr) ? ip6_addr : NULL,
	                                   msg))
		nm_utils_call_dispatcher ("hostname", NULL, NULL, NULL);
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
			_set_hostname (policy, TRUE, NULL, msg);
			g_free (msg);
		} else
			_set_hostname (policy, TRUE, hostname, "from address lookup");
	}
	hostname_thread_free (thread);
}

static void
update_system_hostname (NMPolicy *policy, NMDevice *best4, NMDevice *best6)
{
	char *configured_hostname = NULL;
	NMActRequest *best_req4 = NULL;
	NMActRequest *best_req6 = NULL;
	const char *dhcp_hostname, *p;

	g_return_if_fail (policy != NULL);

	if (policy->lookup) {
		hostname_thread_kill (policy->lookup);
		policy->lookup = NULL;
	}

	/* Hostname precedence order:
	 *
	 * 1) a configured hostname (from system-settings)
	 * 2) automatic hostname from the default device's config (DHCP, VPN, etc)
	 * 3) the original hostname when NM started
	 * 4) reverse-DNS of the best device's IPv4 address
	 *
	 */

	/* Try a persistent hostname first */
	g_object_get (G_OBJECT (policy->manager), NM_MANAGER_HOSTNAME, &configured_hostname, NULL);
	if (configured_hostname) {
		_set_hostname (policy, TRUE, configured_hostname, "from system configuration");
		g_free (configured_hostname);
		return;
	}

	/* Try automatically determined hostname from the best device's IP config */
	if (!best4)
		best4 = get_best_ip4_device (policy->manager, &best_req4);
	if (!best6)
		best6 = get_best_ip6_device (policy->manager, &best_req6);

	if (!best4 && !best6) {
		/* No best device; fall back to original hostname or if there wasn't
		 * one, 'localhost.localdomain'
		 */
		_set_hostname (policy, TRUE, policy->orig_hostname, "no default device");
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
					if (!isblank (*p++)) {
						_set_hostname (policy, TRUE, dhcp_hostname, "from DHCPv4");
						return;
					}
				}
				nm_log_warn (LOGD_DNS, "DHCPv4-provided hostname '%s' looks invalid; ignoring it",
					         dhcp_hostname);
			}
		}
	} else if (best6) {
		NMDHCP6Config *dhcp6_config;

		/* Grab a hostname out of the device's DHCP4 config */
		dhcp6_config = nm_device_get_dhcp6_config (best6);
		if (dhcp6_config) {
			p = dhcp_hostname = nm_dhcp6_config_get_option (dhcp6_config, "host_name");
			if (dhcp_hostname && strlen (dhcp_hostname)) {
				/* Sanity check; strip leading spaces */
				while (*p) {
					if (!isblank (*p++)) {
						_set_hostname (policy, TRUE, dhcp_hostname, "from DHCPv6");
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
		_set_hostname (policy, TRUE, policy->orig_hostname, "from system startup");
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
			_set_hostname (policy, TRUE, NULL, "no IPv4 config");
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
			_set_hostname (policy, TRUE, NULL, "no IPv6 config");
			return;
		}

		addr6 = nm_ip6_config_get_address (ip6_config, 0);
		g_assert (addr6); /* checked for > 1 address above */

		/* Start the hostname lookup thread */
		policy->lookup = hostname6_thread_new (nm_ip6_address_get_address (addr6), lookup_callback, policy);
	}

	if (!policy->lookup) {
		/* Fall back to 'localhost.localdomain' */
		_set_hostname (policy, TRUE, NULL, "error starting hostname thread");
	}
}

static void
update_ip4_routing_and_dns (NMPolicy *policy, gboolean force_update)
{
	NMNamedIPConfigType dns_type = NM_NAMED_IP_CONFIG_TYPE_BEST_DEVICE;
	NMDevice *best = NULL;
	NMActRequest *best_req = NULL;
	NMNamedManager *named_mgr;
	GSList *devices = NULL, *iter, *vpns;
	NMIP4Config *ip4_config = NULL;
	NMIP4Address *addr;
	const char *ip_iface = NULL;
	NMConnection *connection = NULL;
	NMSettingConnection *s_con = NULL;
	const char *connection_id;

	best = get_best_ip4_device (policy->manager, &best_req);
	if (!best)
		goto out;
	if (!force_update && (best == policy->default_device4))
		goto out;

	/* If a VPN connection is active, it is preferred */
	vpns = nm_vpn_manager_get_active_connections (policy->vpn_manager);
	for (iter = vpns; iter; iter = g_slist_next (iter)) {
		NMVPNConnection *candidate = NM_VPN_CONNECTION (iter->data);
		NMConnection *vpn_connection;
		NMSettingIP4Config *s_ip4;
		gboolean can_default = TRUE;
		NMVPNConnectionState vpn_state;

		/* If it's marked 'never-default', don't make it default */
		vpn_connection = nm_vpn_connection_get_connection (candidate);
		g_assert (vpn_connection);
		s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (vpn_connection, NM_TYPE_SETTING_IP4_CONFIG);
		if (s_ip4 && nm_setting_ip4_config_get_never_default (s_ip4))
			can_default = FALSE;

		vpn_state = nm_vpn_connection_get_vpn_state (candidate);
		if (can_default && (vpn_state == NM_VPN_CONNECTION_STATE_ACTIVATED)) {
			NMIP4Config *parent_ip4;
			NMDevice *parent;

			ip_iface = nm_vpn_connection_get_ip_iface (candidate);
			connection = nm_vpn_connection_get_connection (candidate);
			ip4_config = nm_vpn_connection_get_ip4_config (candidate);
			addr = nm_ip4_config_get_address (ip4_config, 0);

			parent = nm_vpn_connection_get_parent_device (candidate);
			parent_ip4 = nm_device_get_ip4_config (parent);

			nm_system_replace_default_ip4_route_vpn (ip_iface,
			                                         nm_ip4_address_get_gateway (addr),
			                                         nm_vpn_connection_get_ip4_internal_gateway (candidate),
			                                         nm_ip4_config_get_mss (ip4_config),
			                                         nm_device_get_ip_iface (parent),
			                                         nm_ip4_config_get_mss (parent_ip4));

			dns_type = NM_NAMED_IP_CONFIG_TYPE_VPN;
		}
		g_object_unref (candidate);
	}
	g_slist_free (vpns);

	/* The best device gets the default route if a VPN connection didn't */
	if (!ip_iface || !ip4_config) {
		connection = nm_act_request_get_connection (best_req);
		ip_iface = nm_device_get_ip_iface (best);
		ip4_config = nm_device_get_ip4_config (best);
		g_assert (ip4_config);
		addr = nm_ip4_config_get_address (ip4_config, 0);

		nm_system_replace_default_ip4_route (ip_iface, nm_ip4_address_get_gateway (addr), nm_ip4_config_get_mss (ip4_config));

		dns_type = NM_NAMED_IP_CONFIG_TYPE_BEST_DEVICE;
	}

	if (!ip_iface || !ip4_config) {
		nm_log_warn (LOGD_CORE, "couldn't determine IP interface (%p) or IPv4 config (%p)!",
		             ip_iface, ip4_config);
		goto out;
	}

	/* Update the default active connection.  Only mark the new default
	 * active connection after setting default = FALSE on all other connections
	 * first.  The order is important, we don't want two connections marked
	 * default at the same time ever.
	 */
	devices = nm_manager_get_devices (policy->manager);
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *dev = NM_DEVICE (iter->data);
		NMActRequest *req;

		req = nm_device_get_act_request (dev);
		if (req && (req != best_req))
			nm_act_request_set_default (req, FALSE);
	}

	named_mgr = nm_named_manager_get ();
	nm_named_manager_add_ip4_config (named_mgr, ip_iface, ip4_config, dns_type);
	g_object_unref (named_mgr);

	/* Now set new default active connection _after_ updating DNS info, so that
	 * if the connection is shared dnsmasq picks up the right stuff.
	 */
	if (best_req)
		nm_act_request_set_default (best_req, TRUE);

	if (connection)
		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);

	connection_id = s_con ? nm_setting_connection_get_id (s_con) : NULL;
	if (connection_id) {
		nm_log_info (LOGD_CORE, "Policy set '%s' (%s) as default for IPv4 routing and DNS.", connection_id, ip_iface);
	} else {
		nm_log_info (LOGD_CORE, "Policy set (%s) as default for IPv4 routing and DNS.", ip_iface);
	}

out:
	policy->default_device4 = best;
}

static void
update_ip6_routing_and_dns (NMPolicy *policy, gboolean force_update)
{
	NMNamedIPConfigType dns_type = NM_NAMED_IP_CONFIG_TYPE_BEST_DEVICE;
	NMDevice *best = NULL;
	NMActRequest *best_req = NULL;
	NMNamedManager *named_mgr;
	GSList *devices = NULL, *iter;
#if NOT_YET
	GSList *vpns;
#endif
	NMIP6Config *ip6_config = NULL;
	NMIP6Address *addr;
	const char *ip_iface = NULL;
	NMConnection *connection = NULL;
	NMSettingConnection *s_con = NULL;
	const char *connection_id;

	best = get_best_ip6_device (policy->manager, &best_req);
	if (!best)
		goto out;
	if (!force_update && (best == policy->default_device6))
		goto out;

#if NOT_YET
	/* If a VPN connection is active, it is preferred */
	vpns = nm_vpn_manager_get_active_connections (policy->vpn_manager);
	for (iter = vpns; iter; iter = g_slist_next (iter)) {
		NMVPNConnection *candidate = NM_VPN_CONNECTION (iter->data);
		NMConnection *vpn_connection;
		NMSettingIP6Config *s_ip6;
		gboolean can_default = TRUE;
		NMVPNConnectionState vpn_state;

		/* If it's marked 'never-default', don't make it default */
		vpn_connection = nm_vpn_connection_get_connection (candidate);
		g_assert (vpn_connection);
		s_ip6 = (NMSettingIP6Config *) nm_connection_get_setting (vpn_connection, NM_TYPE_SETTING_IP6_CONFIG);
		if (s_ip6 && nm_setting_ip6_config_get_never_default (s_ip6))
			can_default = FALSE;

		vpn_state = nm_vpn_connection_get_vpn_state (candidate);
		if (can_default && (vpn_state == NM_VPN_CONNECTION_STATE_ACTIVATED)) {
			NMIP6Config *parent_ip6;
			NMDevice *parent;

			ip_iface = nm_vpn_connection_get_ip_iface (candidate);
			connection = nm_vpn_connection_get_connection (candidate);
			ip6_config = nm_vpn_connection_get_ip6_config (candidate);
			addr = nm_ip6_config_get_address (ip6_config, 0);

			parent = nm_vpn_connection_get_parent_device (candidate);
			parent_ip6 = nm_device_get_ip6_config (parent);

			nm_system_replace_default_ip6_route_vpn (ip_iface,
			                                         nm_ip6_address_get_gateway (addr),
			                                         nm_vpn_connection_get_ip4_internal_gateway (candidate),
			                                         nm_ip6_config_get_mss (ip4_config),
			                                         nm_device_get_ip_iface (parent),
			                                         nm_ip6_config_get_mss (parent_ip4));

			dns_type = NM_NAMED_IP_CONFIG_TYPE_VPN;
		}
		g_object_unref (candidate);
	}
	g_slist_free (vpns);
#endif

	/* The best device gets the default route if a VPN connection didn't */
	if (!ip_iface || !ip6_config) {
		connection = nm_act_request_get_connection (best_req);
		ip_iface = nm_device_get_ip_iface (best);
		ip6_config = nm_device_get_ip6_config (best);
		g_assert (ip6_config);
		addr = nm_ip6_config_get_address (ip6_config, 0);

		nm_system_replace_default_ip6_route (ip_iface, nm_ip6_address_get_gateway (addr));

		dns_type = NM_NAMED_IP_CONFIG_TYPE_BEST_DEVICE;
	}

	if (!ip_iface || !ip6_config) {
		nm_log_warn (LOGD_CORE, "couldn't determine IP interface (%p) or IPv6 config (%p)!",
		             ip_iface, ip6_config);
		goto out;
	}

	/* Update the default active connection.  Only mark the new default
	 * active connection after setting default = FALSE on all other connections
	 * first.  The order is important, we don't want two connections marked
	 * default at the same time ever.
	 */
	devices = nm_manager_get_devices (policy->manager);
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *dev = NM_DEVICE (iter->data);
		NMActRequest *req;

		req = nm_device_get_act_request (dev);
		if (req && (req != best_req))
			nm_act_request_set_default6 (req, FALSE);
	}

	named_mgr = nm_named_manager_get ();
	nm_named_manager_add_ip6_config (named_mgr, ip_iface, ip6_config, dns_type);
	g_object_unref (named_mgr);

	/* Now set new default active connection _after_ updating DNS info, so that
	 * if the connection is shared dnsmasq picks up the right stuff.
	 */
	if (best_req)
		nm_act_request_set_default6 (best_req, TRUE);

	if (connection)
		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);

	connection_id = s_con ? nm_setting_connection_get_id (s_con) : NULL;
	if (connection_id) {
		nm_log_info (LOGD_CORE, "Policy set '%s' (%s) as default for IPv6 routing and DNS.", connection_id, ip_iface);
	} else {
		nm_log_info (LOGD_CORE, "Policy set (%s) as default for IPv6 routing and DNS.", ip_iface);
	}

out:
	policy->default_device6 = best;
}

static void
update_routing_and_dns (NMPolicy *policy, gboolean force_update)
{
	update_ip4_routing_and_dns (policy, force_update);
	update_ip6_routing_and_dns (policy, force_update);

	/* Update the system hostname */
	update_system_hostname (policy, policy->default_device4, policy->default_device6);
}

typedef struct {
	NMPolicy *policy;
	NMDevice *device;
	guint id;
} ActivateData;

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

	// FIXME: if a device is already activating (or activated) with a connection
	// but another connection now overrides the current one for that device,
	// deactivate the device and activate the new connection instead of just
	// bailing if the device is already active
	if (nm_device_get_act_request (data->device))
		goto out;

	/* System connections first, then user connections */
	connections = nm_manager_get_connections (policy->manager, NM_CONNECTION_SCOPE_SYSTEM);
	if (nm_manager_auto_user_connections_allowed (policy->manager))
		connections = g_slist_concat (connections, nm_manager_get_connections (policy->manager, NM_CONNECTION_SCOPE_USER));

	/* Remove connections that are in the invalid list. */
	iter = connections;
	while (iter) {
		NMConnection *iter_connection = NM_CONNECTION (iter->data);
		GSList *next = g_slist_next (iter);

		if (g_object_get_data (G_OBJECT (iter_connection), INVALID_TAG)) {
			connections = g_slist_remove_link (connections, iter);
			g_object_unref (iter_connection);
			g_slist_free (iter);
		}
		iter = next;
	}

	best_connection = nm_device_get_best_auto_connection (data->device, connections, &specific_object);
	if (best_connection) {
		GError *error = NULL;

		if (!nm_manager_activate_connection (policy->manager,
		                                     best_connection,
		                                     specific_object,
		                                     nm_device_get_path (data->device),
		                                     FALSE,
		                                     &error)) {
			NMSettingConnection *s_con;

			s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (best_connection, NM_TYPE_SETTING_CONNECTION));
			g_assert (s_con);

			nm_log_info (LOGD_DEVICE, "Connection '%s' auto-activation failed: (%d) %s",
			             nm_setting_connection_get_id (s_con), error->code, error->message);
			g_error_free (error);
		}
	}

	g_slist_foreach (connections, (GFunc) g_object_unref, NULL);
	g_slist_free (connections);

 out:
	/* Remove this call's handler ID */
	policy->pending_activation_checks = g_slist_remove (policy->pending_activation_checks, data);
	g_object_unref (data->device);
	g_free (data);

	return FALSE;
}

/*****************************************************************************/

static void
vpn_connection_activated (NMVPNManager *manager,
                          NMVPNConnection *vpn,
                          gpointer user_data)
{
	update_routing_and_dns ((NMPolicy *) user_data, TRUE);
}

static void
vpn_connection_deactivated (NMVPNManager *manager,
                            NMVPNConnection *vpn,
                            NMVPNConnectionState state,
                            NMVPNConnectionStateReason reason,
                            gpointer user_data)
{
	update_routing_and_dns ((NMPolicy *) user_data, TRUE);
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
sleeping_changed (NMManager *manager, GParamSpec *pspec, gpointer user_data)
{
	gboolean sleeping = FALSE, enabled = FALSE;
	GSList *connections, *iter;

	g_object_get (G_OBJECT (manager), NM_MANAGER_SLEEPING, &sleeping, NULL);
	g_object_get (G_OBJECT (manager), NM_MANAGER_NETWORKING_ENABLED, &enabled, NULL);

	/* Clear the invalid flag on all connections so they'll get retried on wakeup */
	if (sleeping || !enabled) {
		connections = nm_manager_get_connections (manager, NM_CONNECTION_SCOPE_SYSTEM);
		connections = g_slist_concat (connections, nm_manager_get_connections (manager, NM_CONNECTION_SCOPE_USER));
		for (iter = connections; iter; iter = g_slist_next (iter))
			g_object_set_data (G_OBJECT (iter->data), INVALID_TAG, NULL);
		g_slist_free (connections);
	}
}

static void
schedule_activate_check (NMPolicy *policy, NMDevice *device, guint delay_seconds)
{
	ActivateData *data;
	GSList *iter;
	NMDeviceState state;

	if (nm_manager_get_state (policy->manager) == NM_STATE_ASLEEP)
		return;

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (device));
	if (state < NM_DEVICE_STATE_DISCONNECTED)
		return;

	if (!nm_device_autoconnect_allowed (device))
		return;

	for (iter = policy->pending_activation_checks; iter; iter = g_slist_next (iter)) {
		/* Only one pending activation check at a time */
		if (((ActivateData *) iter->data)->device == device)
			return;
	}

	data = g_malloc0 (sizeof (ActivateData));
	g_return_if_fail (data != NULL);

	data->policy = policy;
	data->device = g_object_ref (device);
	data->id = delay_seconds ? g_timeout_add_seconds (delay_seconds, auto_activate_device, data) : g_idle_add (auto_activate_device, data);
	policy->pending_activation_checks = g_slist_append (policy->pending_activation_checks, data);
}

static NMConnection *
get_device_connection (NMDevice *device)
{
	NMActRequest *req;

	req = nm_device_get_act_request (device);
	if (!req)
		return NULL;

	return nm_act_request_get_connection (req);
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	NMConnection *connection = get_device_connection (device);

	switch (new_state) {
	case NM_DEVICE_STATE_FAILED:
		/* Mark the connection invalid if it failed during activation so that
		 * it doesn't get automatically chosen over and over and over again.
		 */
		if (connection && IS_ACTIVATING_STATE (old_state)) {
			g_object_set_data (G_OBJECT (connection), INVALID_TAG, GUINT_TO_POINTER (TRUE));
			nm_log_info (LOGD_DEVICE, "Marking connection '%s' invalid.", get_connection_id (connection));
			nm_connection_clear_secrets (connection);
		}
		schedule_activate_check (policy, device, 3);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		if (connection) {
			/* Clear the invalid tag on the connection */
			g_object_set_data (G_OBJECT (connection), INVALID_TAG, NULL);

			/* And clear secrets so they will always be requested from the
			 * settings service when the next connection is made.
			 */
			nm_connection_clear_secrets (connection);
		}

		update_routing_and_dns (policy, FALSE);
		break;
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_DISCONNECTED:
		update_routing_and_dns (policy, FALSE);
		schedule_activate_check (policy, device, 0);
		break;
	default:
		break;
	}
}

static void
device_ip_config_changed (NMDevice *device,
                          GParamSpec *pspec,
                          gpointer user_data)
{
	update_routing_and_dns ((NMPolicy *) user_data, TRUE);
}

static void
wireless_networks_changed (NMDeviceWifi *device, NMAccessPoint *ap, gpointer user_data)
{
	schedule_activate_check ((NMPolicy *) user_data, NM_DEVICE (device), 0);
}

typedef struct {
	gulong id;
	NMDevice *device;
} DeviceSignalID;

static GSList *
add_device_signal_id (GSList *list, gulong id, NMDevice *device)
{
	DeviceSignalID *data;

	data = g_malloc0 (sizeof (DeviceSignalID));
	if (!data)
		return list;

	data->id = id;
	data->device = device;
	return g_slist_append (list, data);
}

static void
device_added (NMManager *manager, NMDevice *device, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	gulong id;

	id = g_signal_connect (device, "state-changed",
	                       G_CALLBACK (device_state_changed),
	                       policy);
	policy->dev_signal_ids = add_device_signal_id (policy->dev_signal_ids, id, device);

	id = g_signal_connect (device, "notify::" NM_DEVICE_INTERFACE_IP4_CONFIG,
	                       G_CALLBACK (device_ip_config_changed),
	                       policy);
	policy->dev_signal_ids = add_device_signal_id (policy->dev_signal_ids, id, device);

	id = g_signal_connect (device, "notify::" NM_DEVICE_INTERFACE_IP6_CONFIG,
	                       G_CALLBACK (device_ip_config_changed),
	                       policy);
	policy->dev_signal_ids = add_device_signal_id (policy->dev_signal_ids, id, device);

	if (NM_IS_DEVICE_WIFI (device)) {
		id = g_signal_connect (device, "access-point-added",
		                       G_CALLBACK (wireless_networks_changed),
		                       policy);
		policy->dev_signal_ids = add_device_signal_id (policy->dev_signal_ids, id, device);

		id = g_signal_connect (device, "access-point-removed",
		                       G_CALLBACK (wireless_networks_changed),
		                       policy);
		policy->dev_signal_ids = add_device_signal_id (policy->dev_signal_ids, id, device);
	}
}

static void
device_removed (NMManager *manager, NMDevice *device, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	GSList *iter;

	/* Clear any idle callbacks for this device */
	iter = policy->pending_activation_checks;
	while (iter) {
		ActivateData *data = (ActivateData *) iter->data;
		GSList *next = g_slist_next (iter);

		if (data->device == device) {
			g_source_remove (data->id);
			g_object_unref (data->device);
			g_free (data);
			policy->pending_activation_checks = g_slist_delete_link (policy->pending_activation_checks, iter);
		}
		iter = next;
	}

	/* Clear any signal handlers for this device */
	iter = policy->dev_signal_ids;
	while (iter) {
		DeviceSignalID *data = (DeviceSignalID *) iter->data;
		GSList *next = g_slist_next (iter);

		if (data->device == device) {
			g_signal_handler_disconnect (data->device, data->id);
			g_free (data);
			policy->dev_signal_ids = g_slist_delete_link (policy->dev_signal_ids, iter);
		}
		iter = next;
	}

	update_routing_and_dns (policy, FALSE);
}

static void
schedule_activate_all (NMPolicy *policy)
{
	GSList *iter, *devices;

	devices = nm_manager_get_devices (policy->manager);
	for (iter = devices; iter; iter = g_slist_next (iter))
		schedule_activate_check (policy, NM_DEVICE (iter->data), 0);
}

static void
connections_added (NMManager *manager,
                   NMConnectionScope scope,
                   gpointer user_data)
{
	schedule_activate_all ((NMPolicy *) user_data);
}

static void
connection_added (NMManager *manager,
                  NMConnection *connection,
                  NMConnectionScope scope,
                  gpointer user_data)
{
	schedule_activate_all ((NMPolicy *) user_data);
}

static void
connection_updated (NMManager *manager,
                    NMConnection *connection,
                    NMConnectionScope scope,
                    gpointer user_data)
{
	/* Clear the invalid tag on the connection if it got updated. */
	g_object_set_data (G_OBJECT (connection), INVALID_TAG, NULL);

	schedule_activate_all ((NMPolicy *) user_data);
}

static void
connection_removed (NMManager *manager,
                    NMConnection *connection,
                    NMConnectionScope scope,
                    gpointer user_data)
{
	NMSettingConnection *s_con;
	GPtrArray *list;
	int i;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	if (!s_con)
		return;

	list = nm_manager_get_active_connections_by_connection (manager, connection);
	if (!list)
		return;

	for (i = 0; i < list->len; i++) {
		char *path = g_ptr_array_index (list, i);
		GError *error = NULL;

		if (!nm_manager_deactivate_connection (manager, path, NM_DEVICE_STATE_REASON_CONNECTION_REMOVED, &error)) {
			nm_log_warn (LOGD_DEVICE, "Connection '%s' disappeared, but error deactivating it: (%d) %s",
			             nm_setting_connection_get_id (s_con), error->code, error->message);
			g_error_free (error);
		}
		g_free (path);
	}
	g_ptr_array_free (list, TRUE);
}

static void
manager_user_permissions_changed (NMManager *manager, NMPolicy *policy)
{
	schedule_activate_all (policy);
}

NMPolicy *
nm_policy_new (NMManager *manager, NMVPNManager *vpn_manager)
{
	NMPolicy *policy;
	static gboolean initialized = FALSE;
	gulong id;
	char hostname[HOST_NAME_MAX + 2];

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (initialized == FALSE, NULL);

	policy = g_malloc0 (sizeof (NMPolicy));
	policy->manager = g_object_ref (manager);
	policy->update_state_id = 0;

	/* Grab hostname on startup and use that if nothing provides one */
	memset (hostname, 0, sizeof (hostname));
	if (gethostname (&hostname[0], HOST_NAME_MAX) == 0) {
		/* only cache it if it's a valid hostname */
		if (strlen (hostname) && strcmp (hostname, "localhost") && strcmp (hostname, "localhost.localdomain"))
			policy->orig_hostname = g_strdup (hostname);
	}

	policy->vpn_manager = g_object_ref (vpn_manager);
	id = g_signal_connect (policy->vpn_manager, "connection-activated",
	                       G_CALLBACK (vpn_connection_activated), policy);
	policy->vpn_activated_id = id;
	id = g_signal_connect (policy->vpn_manager, "connection-deactivated",
	                       G_CALLBACK (vpn_connection_deactivated), policy);
	policy->vpn_deactivated_id = id;

	id = g_signal_connect (manager, "state-changed",
	                       G_CALLBACK (global_state_changed), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	id = g_signal_connect (manager, "notify::" NM_MANAGER_HOSTNAME,
	                       G_CALLBACK (hostname_changed), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	id = g_signal_connect (manager, "notify::" NM_MANAGER_SLEEPING,
	                       G_CALLBACK (sleeping_changed), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	id = g_signal_connect (manager, "notify::" NM_MANAGER_NETWORKING_ENABLED,
	                       G_CALLBACK (sleeping_changed), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	id = g_signal_connect (manager, "device-added",
	                       G_CALLBACK (device_added), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	id = g_signal_connect (manager, "device-removed",
	                       G_CALLBACK (device_removed), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	/* Large batch of connections added, manager doesn't want us to
	 * process each one individually.
	 */
	id = g_signal_connect (manager, "connections-added",
	                       G_CALLBACK (connections_added), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	/* Single connection added */
	id = g_signal_connect (manager, "connection-added",
	                       G_CALLBACK (connection_added), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	id = g_signal_connect (manager, "connection-updated",
	                       G_CALLBACK (connection_updated), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	id = g_signal_connect (manager, "connection-removed",
	                       G_CALLBACK (connection_removed), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	id = g_signal_connect (manager, "user-permissions-changed",
	                       G_CALLBACK (manager_user_permissions_changed), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	return policy;
}

void
nm_policy_destroy (NMPolicy *policy)
{
	GSList *iter;

	g_return_if_fail (policy != NULL);

	/* Tell any existing hostname lookup thread to die, it'll get cleaned up
	 * by the lookup thread callback.
	  */
	if (policy->lookup) {
		hostname_thread_kill (policy->lookup);
		policy->lookup = NULL;
	}

	for (iter = policy->pending_activation_checks; iter; iter = g_slist_next (iter)) {
		ActivateData *data = (ActivateData *) iter->data;

		g_source_remove (data->id);
		g_object_unref (data->device);
		g_free (data);
	}
	g_slist_free (policy->pending_activation_checks);

	g_signal_handler_disconnect (policy->vpn_manager, policy->vpn_activated_id);
	g_signal_handler_disconnect (policy->vpn_manager, policy->vpn_deactivated_id);

	for (iter = policy->signal_ids; iter; iter = g_slist_next (iter))
		g_signal_handler_disconnect (policy->manager, (gulong) iter->data);
	g_slist_free (policy->signal_ids);

	for (iter = policy->dev_signal_ids; iter; iter = g_slist_next (iter)) {
		DeviceSignalID *data = (DeviceSignalID *) iter->data;

		g_signal_handler_disconnect (data->device, data->id);
		g_free (data);
	}
	g_slist_free (policy->dev_signal_ids);

	g_free (policy->orig_hostname);
	g_free (policy->cur_hostname);

	g_object_unref (policy->manager);
	g_free (policy);
}

