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
 * Copyright (C) 2004 - 2013 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "config.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>


#include "nm-default.h"
#include "nm-policy.h"
#include "NetworkManagerUtils.h"
#include "nm-activation-request.h"
#include "nm-device.h"
#include "nm-default-route-manager.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-connection.h"
#include "nm-platform.h"
#include "nm-dns-manager.h"
#include "nm-vpn-manager.h"
#include "nm-auth-utils.h"
#include "nm-firewall-manager.h"
#include "nm-dispatcher.h"
#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nm-manager.h"
#include "nm-settings.h"
#include "nm-settings-connection.h"
#include "nm-dhcp4-config.h"
#include "nm-dhcp6-config.h"

typedef struct {
	NMManager *manager;
	NMFirewallManager *firewall_manager;
	guint update_state_id;
	GSList *pending_activation_checks;
	GSList *manager_ids;
	GSList *settings_ids;
	GSList *dev_ids;

	GSList *pending_secondaries;

	gulong fw_started_id;

	NMSettings *settings;

	NMDevice *default_device4, *activating_device4;
	NMDevice *default_device6, *activating_device6;

	GResolver *resolver;
	GInetAddress *lookup_addr;
	GCancellable *lookup_cancellable;
	NMDnsManager *dns_manager;
	gulong config_changed_id;

	gint reset_retries_id;  /* idle handler for resetting the retries count */

	char *orig_hostname; /* hostname at NM start time */
	char *cur_hostname;  /* hostname we want to assign */
	gboolean hostname_changed;  /* TRUE if NM ever set the hostname */
} NMPolicyPrivate;

#define NM_POLICY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_POLICY, NMPolicyPrivate))

G_DEFINE_TYPE (NMPolicy, nm_policy, G_TYPE_OBJECT)

enum {
	PROP_0,

	PROP_DEFAULT_IP4_DEVICE,
	PROP_DEFAULT_IP6_DEVICE,
	PROP_ACTIVATING_IP4_DEVICE,
	PROP_ACTIVATING_IP6_DEVICE
};

static void schedule_activate_all (NMPolicy *policy);


static NMDevice *
get_best_ip4_device (NMPolicy *self, gboolean fully_activated)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);

	return nm_default_route_manager_ip4_get_best_device (nm_default_route_manager_get (),
	                                                     nm_manager_get_devices (priv->manager),
	                                                     fully_activated,
	                                                     priv->default_device4);
}

static NMDevice *
get_best_ip6_device (NMPolicy *self, gboolean fully_activated)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);

	return nm_default_route_manager_ip6_get_best_device (nm_default_route_manager_get (),
	                                                     nm_manager_get_devices (priv->manager),
	                                                     fully_activated,
	                                                     priv->default_device6);
}

#define FALLBACK_HOSTNAME4 "localhost.localdomain"

static gboolean
set_system_hostname (const char *new_hostname, const char *msg)
{
	char old_hostname[HOST_NAME_MAX + 1];
	const char *name;
	int ret;

	if (new_hostname)
		g_warn_if_fail (strlen (new_hostname));

	old_hostname[HOST_NAME_MAX] = '\0';
	errno = 0;
	ret = gethostname (old_hostname, HOST_NAME_MAX);
	if (ret != 0) {
		nm_log_warn (LOGD_DNS, "couldn't get the system hostname: (%d) %s",
		             errno, strerror (errno));
	} else {
		/* Don't set the hostname if it isn't actually changing */
		if (   (new_hostname && !strcmp (old_hostname, new_hostname))
		       || (!new_hostname && !strcmp (old_hostname, FALLBACK_HOSTNAME4)))
			return FALSE;
	}

	name = (new_hostname && strlen (new_hostname)) ? new_hostname : FALLBACK_HOSTNAME4;

	nm_log_info (LOGD_DNS, "Setting system hostname to '%s' (%s)", name, msg);
	ret = sethostname (name, strlen (name));
	if (ret != 0) {
		nm_log_warn (LOGD_DNS, "couldn't set the system hostname to '%s': (%d) %s",
		             name, errno, strerror (errno));
	}

	return (ret == 0);
}

static void
_set_hostname (NMPolicy *policy,
               const char *new_hostname,
               const char *msg)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);

	/* The incoming hostname *can* be NULL, which will get translated to
	 * 'localhost.localdomain' or such in the hostname policy code, but we
	 * keep cur_hostname = NULL in the case because we need to know that
	 * there was no valid hostname to start with.
	 */

	/* Clear lookup addresses if we have a hostname, so that we don't
	 * restart the reverse lookup thread later.
	 */
	if (new_hostname)
		g_clear_object (&priv->lookup_addr);

	/* Don't change the hostname or update DNS this is the first time we're
	 * trying to change the hostname, and it's not actually changing.
	 */
	if (   priv->orig_hostname
	    && (priv->hostname_changed == FALSE)
	    && g_strcmp0 (priv->orig_hostname, new_hostname) == 0)
		return;

	/* Don't change the hostname or update DNS if the hostname isn't actually
	 * going to change.
	 */
	if (g_strcmp0 (priv->cur_hostname, new_hostname) == 0)
		return;

	g_free (priv->cur_hostname);
	priv->cur_hostname = g_strdup (new_hostname);
	priv->hostname_changed = TRUE;

	nm_dns_manager_set_hostname (priv->dns_manager, priv->cur_hostname);

	if (set_system_hostname (priv->cur_hostname, msg))
		nm_dispatcher_call (DISPATCHER_ACTION_HOSTNAME, NULL, NULL, NULL, NULL, NULL, NULL);
}

static void
lookup_callback (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	const char *hostname;
	GError *error = NULL;

	hostname = g_resolver_lookup_by_address_finish (G_RESOLVER (source), result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		/* Don't touch policy; it may have been freed already */
		g_error_free (error);
		return;
	}

	if (hostname)
		_set_hostname (policy, hostname, "from address lookup");
	else {
		_set_hostname (policy, NULL, error->message);
		g_error_free (error);
	}

	g_clear_object (&priv->lookup_cancellable);
}

static void
update_system_hostname (NMPolicy *policy, NMDevice *best4, NMDevice *best6)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	char *configured_hostname = NULL;
	const char *dhcp_hostname, *p;
	NMIP4Config *ip4_config;
	NMIP6Config *ip6_config;

	g_return_if_fail (policy != NULL);

	if (priv->lookup_cancellable) {
		g_cancellable_cancel (priv->lookup_cancellable);
		g_clear_object (&priv->lookup_cancellable);
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
	g_object_get (G_OBJECT (priv->manager), NM_MANAGER_HOSTNAME, &configured_hostname, NULL);
	if (configured_hostname && nm_utils_is_specific_hostname (configured_hostname)) {
		_set_hostname (policy, configured_hostname, "from system configuration");
		g_free (configured_hostname);
		return;
	}
	g_free (configured_hostname);

	/* Try automatically determined hostname from the best device's IP config */
	if (!best4)
		best4 = get_best_ip4_device (policy, TRUE);
	if (!best6)
		best6 = get_best_ip6_device (policy, TRUE);

	if (!best4 && !best6) {
		/* No best device; fall back to original hostname or if there wasn't
		 * one, 'localhost.localdomain'
		 */
		_set_hostname (policy, priv->orig_hostname, "no default device");
		return;
	}

	if (best4) {
		NMDhcp4Config *dhcp4_config;

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
		NMDhcp6Config *dhcp6_config;

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
	if (priv->orig_hostname) {
		_set_hostname (policy, priv->orig_hostname, "from system startup");
		return;
	}

	/* No configured hostname, no automatically determined hostname, and no
	 * bootup hostname. Start reverse DNS of the current IPv4 or IPv6 address.
	 */
	ip4_config = best4 ? nm_device_get_ip4_config (best4) : NULL;
	ip6_config = best6 ? nm_device_get_ip6_config (best6) : NULL;

	if (ip4_config && nm_ip4_config_get_num_addresses (ip4_config) > 0) {
		const NMPlatformIP4Address *addr4;

		addr4 = nm_ip4_config_get_address (ip4_config, 0);
		g_clear_object (&priv->lookup_addr);
		priv->lookup_addr = g_inet_address_new_from_bytes ((guint8 *) &addr4->address,
		                                                   G_SOCKET_FAMILY_IPV4);
	} else if (ip6_config && nm_ip6_config_get_num_addresses (ip6_config) > 0) {
		const NMPlatformIP6Address *addr6;

		addr6 = nm_ip6_config_get_address (ip6_config, 0);
		g_clear_object (&priv->lookup_addr);
		priv->lookup_addr = g_inet_address_new_from_bytes ((guint8 *) &addr6->address,
		                                                   G_SOCKET_FAMILY_IPV6);
	} else {
		/* No valid IP config; fall back to localhost.localdomain */
		_set_hostname (policy, NULL, "no IP config");
		return;
	}

	priv->lookup_cancellable = g_cancellable_new ();
	g_resolver_lookup_by_address_async (priv->resolver,
	                                    priv->lookup_addr,
	                                    priv->lookup_cancellable,
	                                    lookup_callback, policy);
}

static void
update_default_ac (NMPolicy *policy,
                   NMActiveConnection *best,
                   void (*set_active_func)(NMActiveConnection*, gboolean))
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	const GSList *connections, *iter;

	/* Clear the 'default[6]' flag on all active connections that aren't the new
	 * default active connection.  We'll set the new default after; this ensures
	 * we don't ever have two marked 'default[6]' simultaneously.
	 */
	connections = nm_manager_get_active_connections (priv->manager);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		if (NM_ACTIVE_CONNECTION (iter->data) != best)
			set_active_func (NM_ACTIVE_CONNECTION (iter->data), FALSE);
	}

	/* Mark new default active connection */
	if (best)
		set_active_func (best, TRUE);
}

static NMIP4Config *
get_best_ip4_config (NMPolicy *self,
                     gboolean ignore_never_default,
                     const char **out_ip_iface,
                     NMActiveConnection **out_ac,
                     NMDevice **out_device,
                     NMVpnConnection **out_vpn)
{
	return nm_default_route_manager_ip4_get_best_config (nm_default_route_manager_get (),
	                                                     ignore_never_default,
	                                                     out_ip_iface,
	                                                     out_ac,
	                                                     out_device,
	                                                     out_vpn);
}

static void
update_ip4_dns (NMPolicy *policy, NMDnsManager *dns_mgr)
{
	NMIP4Config *ip4_config;
	const char *ip_iface = NULL;
	NMVpnConnection *vpn = NULL;
	NMDnsIPConfigType dns_type = NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE;

	ip4_config = get_best_ip4_config (policy, TRUE, &ip_iface, NULL, NULL, &vpn);
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
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	NMDevice *best = NULL, *default_device;
	NMConnection *connection = NULL;
	NMVpnConnection *vpn = NULL;
	NMActiveConnection *best_ac = NULL;
	const char *ip_iface = NULL;

	/* Note that we might have an IPv4 VPN tunneled over an IPv6-only device,
	 * so we can get (vpn != NULL && best == NULL).
	 */
	if (!get_best_ip4_config (policy, FALSE, &ip_iface, &best_ac, &best, &vpn)) {
		gboolean changed;

		changed = (priv->default_device4 != NULL);
		priv->default_device4 = NULL;
		if (changed)
			g_object_notify (G_OBJECT (policy), NM_POLICY_DEFAULT_IP4_DEVICE);

		return;
	}
	g_assert ((best || vpn) && best_ac);

	if (!force_update && best && (best == priv->default_device4))
		return;

	if (best) {
		const GSList *connections, *iter;

		connections = nm_manager_get_active_connections (priv->manager);
		for (iter = connections; iter; iter = g_slist_next (iter)) {
			NMActiveConnection *active = iter->data;

			if (   NM_IS_VPN_CONNECTION (active)
			    && nm_vpn_connection_get_ip4_config (NM_VPN_CONNECTION (active))
			    && !nm_active_connection_get_device (active))
				nm_active_connection_set_device (active, best);
		}
	}

	if (vpn)
		default_device = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (vpn));
	else
		default_device = best;

	update_default_ac (policy, best_ac, nm_active_connection_set_default);

	if (default_device == priv->default_device4)
		return;

	priv->default_device4 = default_device;
	connection = nm_active_connection_get_applied_connection (best_ac);
	nm_log_info (LOGD_CORE, "Policy set '%s' (%s) as default for IPv4 routing and DNS.",
	             nm_connection_get_id (connection), ip_iface);
	g_object_notify (G_OBJECT (policy), NM_POLICY_DEFAULT_IP4_DEVICE);
}

static NMIP6Config *
get_best_ip6_config (NMPolicy *self,
                     gboolean ignore_never_default,
                     const char **out_ip_iface,
                     NMActiveConnection **out_ac,
                     NMDevice **out_device,
                     NMVpnConnection **out_vpn)
{
	return nm_default_route_manager_ip6_get_best_config (nm_default_route_manager_get (),
	                                                     ignore_never_default,
	                                                     out_ip_iface,
	                                                     out_ac,
	                                                     out_device,
	                                                     out_vpn);
}

static void
update_ip6_dns (NMPolicy *policy, NMDnsManager *dns_mgr)
{
	NMIP6Config *ip6_config;
	const char *ip_iface = NULL;
	NMVpnConnection *vpn = NULL;
	NMDnsIPConfigType dns_type = NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE;

	ip6_config = get_best_ip6_config (policy, TRUE, &ip_iface, NULL, NULL, &vpn);
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
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	NMDevice *best = NULL, *default_device6;
	NMConnection *connection = NULL;
	NMVpnConnection *vpn = NULL;
	NMActiveConnection *best_ac = NULL;
	const char *ip_iface = NULL;

	/* Note that we might have an IPv6 VPN tunneled over an IPv4-only device,
	 * so we can get (vpn != NULL && best == NULL).
	 */
	if (!get_best_ip6_config (policy, FALSE, &ip_iface, &best_ac, &best, &vpn)) {
		gboolean changed;

		changed = (priv->default_device6 != NULL);
		priv->default_device6 = NULL;
		if (changed)
			g_object_notify (G_OBJECT (policy), NM_POLICY_DEFAULT_IP6_DEVICE);

		return;
	}
	g_assert ((best || vpn) && best_ac);

	if (!force_update && best && (best == priv->default_device6))
		return;

	if (best) {
		const GSList *connections, *iter;

		connections = nm_manager_get_active_connections (priv->manager);
		for (iter = connections; iter; iter = g_slist_next (iter)) {
			NMActiveConnection *active = iter->data;

			if (   NM_IS_VPN_CONNECTION (active)
			    && nm_vpn_connection_get_ip6_config (NM_VPN_CONNECTION (active))
			    && !nm_active_connection_get_device (active))
				nm_active_connection_set_device (active, best);
		}
	}

	if (vpn)
		default_device6 = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (vpn));
	else
		default_device6 = best;

	update_default_ac (policy, best_ac, nm_active_connection_set_default6);

	if (default_device6 == priv->default_device6)
		return;

	priv->default_device6 = default_device6;
	connection = nm_active_connection_get_applied_connection (best_ac);
	nm_log_info (LOGD_CORE, "Policy set '%s' (%s) as default for IPv6 routing and DNS.",
	             nm_connection_get_id (connection), ip_iface);
	g_object_notify (G_OBJECT (policy), NM_POLICY_DEFAULT_IP6_DEVICE);
}

static void
update_routing_and_dns (NMPolicy *policy, gboolean force_update)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);

	nm_dns_manager_begin_updates (priv->dns_manager, __func__);

	update_ip4_dns (policy, priv->dns_manager);
	update_ip6_dns (policy, priv->dns_manager);

	update_ip4_routing (policy, force_update);
	update_ip6_routing (policy, force_update);

	/* Update the system hostname */
	update_system_hostname (policy, priv->default_device4, priv->default_device6);

	nm_dns_manager_end_updates (priv->dns_manager, __func__);
}

static void
check_activating_devices (NMPolicy *policy)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	GObject *object = G_OBJECT (policy);
	NMDevice *best4, *best6 = NULL;

	best4 = get_best_ip4_device (policy, FALSE);
	best6 = get_best_ip6_device (policy, FALSE);

	g_object_freeze_notify (object);

	if (best4 != priv->activating_device4) {
		priv->activating_device4 = best4;
		g_object_notify (object, NM_POLICY_ACTIVATING_IP4_DEVICE);
	}
	if (best6 != priv->activating_device6) {
		priv->activating_device6 = best6;
		g_object_notify (object, NM_POLICY_ACTIVATING_IP6_DEVICE);
	}

	g_object_thaw_notify (object);
}

typedef struct {
	NMPolicy *policy;
	NMDevice *device;
	guint autoactivate_id;
} ActivateData;

static void
activate_data_free (ActivateData *data)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (data->policy);

	nm_device_remove_pending_action (data->device, "autoactivate", TRUE);
	priv->pending_activation_checks = g_slist_remove (priv->pending_activation_checks, data);

	if (data->autoactivate_id)
		g_source_remove (data->autoactivate_id);
	g_object_unref (data->device);
	g_free (data);
}

static gboolean
auto_activate_device (gpointer user_data)
{
	ActivateData *data = (ActivateData *) user_data;
	NMPolicy *policy;
	NMPolicyPrivate *priv;
	NMSettingsConnection *best_connection;
	char *specific_object = NULL;
	GPtrArray *connections;
	GSList *connection_list;
	guint i;

	g_assert (data);
	policy = data->policy;
	priv = NM_POLICY_GET_PRIVATE (policy);

	data->autoactivate_id = 0;

	// FIXME: if a device is already activating (or activated) with a connection
	// but another connection now overrides the current one for that device,
	// deactivate the device and activate the new connection instead of just
	// bailing if the device is already active
	if (nm_device_get_act_request (data->device))
		goto out;

	connection_list = nm_manager_get_activatable_connections (priv->manager);
	if (!connection_list)
		goto out;

	connections = _nm_utils_copy_slist_to_array (connection_list, NULL, NULL);
	g_slist_free (connection_list);

	/* sort is stable (which is important at this point) so that connections
	 * with same priority are still sorted by last-connected-timestamp. */
	g_ptr_array_sort (connections, (GCompareFunc) nm_utils_cmp_connection_by_autoconnect_priority);

	/* Find the first connection that should be auto-activated */
	best_connection = NULL;
	for (i = 0; i < connections->len; i++) {
		NMSettingsConnection *candidate = NM_SETTINGS_CONNECTION (connections->pdata[i]);

		if (!nm_settings_connection_can_autoconnect (candidate))
			continue;
		if (nm_device_can_auto_connect (data->device, (NMConnection *) candidate, &specific_object)) {
			best_connection = candidate;
			break;
		}
	}
	g_ptr_array_free (connections, TRUE);

	if (best_connection) {
		GError *error = NULL;
		NMAuthSubject *subject;

		nm_log_info (LOGD_DEVICE, "Auto-activating connection '%s'.",
		             nm_settings_connection_get_id (best_connection));
		subject = nm_auth_subject_new_internal ();
		if (!nm_manager_activate_connection (priv->manager,
		                                     best_connection,
		                                     specific_object,
		                                     data->device,
		                                     subject,
		                                     &error)) {
			nm_log_info (LOGD_DEVICE, "Connection '%s' auto-activation failed: (%d) %s",
			             nm_settings_connection_get_id (best_connection),
			             error ? error->code : -1,
			             error ? error->message : "(none)");
			g_error_free (error);
		}
		g_object_unref (subject);
	}

 out:
	activate_data_free (data);
	return G_SOURCE_REMOVE;
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
	g_slist_free_full (data->secondaries, g_object_unref);
	memset (data, 0, sizeof (*data));
	g_free (data);
}

static void
process_secondaries (NMPolicy *policy,
                     NMActiveConnection *active,
                     gboolean connected)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	GSList *iter, *iter2;

	/* Loop through devices waiting for secondary connections to activate */
	for (iter = priv->pending_secondaries; iter; iter = g_slist_next (iter)) {
		PendingSecondaryData *secondary_data = (PendingSecondaryData *) iter->data;
		NMDevice *item_device = secondary_data->device;

		/* Look for 'active' in each device's secondary connections list */
		for (iter2 = secondary_data->secondaries; iter2; iter2 = g_slist_next (iter2)) {
			NMActiveConnection *secondary_active = NM_ACTIVE_CONNECTION (iter2->data);

			if (active != secondary_active)
				continue;

			if (connected) {
				nm_log_dbg (LOGD_DEVICE, "Secondary connection '%s' SUCCEEDED; active path '%s'",
				            nm_active_connection_get_settings_connection_id (active),
				            nm_exported_object_get_path (NM_EXPORTED_OBJECT (active)));

				/* Secondary connection activated */
				secondary_data->secondaries = g_slist_remove (secondary_data->secondaries, secondary_active);
				g_object_unref (secondary_active);
				if (!secondary_data->secondaries) {
					/* No secondary UUID remained -> remove the secondary data item */
					priv->pending_secondaries = g_slist_remove (priv->pending_secondaries, secondary_data);
					pending_secondary_data_free (secondary_data);
					if (nm_device_get_state (item_device) == NM_DEVICE_STATE_SECONDARIES)
						nm_device_state_changed (item_device, NM_DEVICE_STATE_ACTIVATED, NM_DEVICE_STATE_REASON_NONE);
					break;
				}
			} else {
				nm_log_dbg (LOGD_DEVICE, "Secondary connection '%s' FAILED; active path '%s'",
				            nm_active_connection_get_settings_connection_id (active),
				            nm_exported_object_get_path (NM_EXPORTED_OBJECT (active)));

				/* Secondary connection failed -> do not watch other connections */
				priv->pending_secondaries = g_slist_remove (priv->pending_secondaries, secondary_data);
				pending_secondary_data_free (secondary_data);
				if (   nm_device_get_state (item_device) == NM_DEVICE_STATE_SECONDARIES
				    || nm_device_get_state (item_device) == NM_DEVICE_STATE_ACTIVATED)
					nm_device_state_changed (item_device, NM_DEVICE_STATE_FAILED,
					                                      NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED);
				break;
			}
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
reset_autoconnect_all (NMPolicy *policy, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	GSList *connections, *iter;

	if (device) {
		nm_log_dbg (LOGD_DEVICE, "Re-enabling autoconnect for all connections on %s",
		            nm_device_get_iface (device));
	} else
		nm_log_dbg (LOGD_DEVICE, "Re-enabling autoconnect for all connections");

	connections = nm_settings_get_connections (priv->settings);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		if (!device || nm_device_check_connection_compatible (device, iter->data)) {
			nm_settings_connection_reset_autoconnect_retries (iter->data);
			nm_settings_connection_set_autoconnect_blocked_reason (iter->data, NM_DEVICE_STATE_REASON_NONE);
		}
	}
	g_slist_free (connections);
}

static void
reset_autoconnect_for_failed_secrets (NMPolicy *policy)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	GSList *connections, *iter;

	nm_log_dbg (LOGD_DEVICE, "Re-enabling autoconnect for all connections with failed secrets");

	connections = nm_settings_get_connections (priv->settings);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMSettingsConnection *connection = NM_SETTINGS_CONNECTION (iter->data);

		if (nm_settings_connection_get_autoconnect_blocked_reason (connection) == NM_DEVICE_STATE_REASON_NO_SECRETS) {
			nm_settings_connection_reset_autoconnect_retries (connection);
			nm_settings_connection_set_autoconnect_blocked_reason (connection, NM_DEVICE_STATE_REASON_NONE);
		}
	}
	g_slist_free (connections);
}

static void
block_autoconnect_for_device (NMPolicy *policy, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	GSList *connections, *iter;

	nm_log_dbg (LOGD_DEVICE, "Blocking autoconnect for all connections on %s",
	            nm_device_get_iface (device));

	/* NMDevice keeps its own autoconnect-able-ness state; we only need to
	 * explicitly block connections for software devices, where the NMDevice
	 * might be destroyed and recreated later.
	 */
	if (!nm_device_is_software (device))
		return;

	connections = nm_settings_get_connections (priv->settings);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		if (nm_device_check_connection_compatible (device, iter->data)) {
			nm_settings_connection_set_autoconnect_blocked_reason (NM_SETTINGS_CONNECTION (iter->data),
			                                                       NM_DEVICE_STATE_REASON_USER_REQUESTED);
		}
	}
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
		reset_autoconnect_all (policy, NULL);
}

static void
schedule_activate_check (NMPolicy *policy, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	ActivateData *data;
	const GSList *active_connections, *iter;

	if (nm_manager_get_state (priv->manager) == NM_STATE_ASLEEP)
		return;

	if (!nm_device_get_enabled (device))
		return;

	if (!nm_device_autoconnect_allowed (device))
		return;

	if (find_pending_activation (priv->pending_activation_checks, device))
		return;

	active_connections = nm_manager_get_active_connections (priv->manager);
	for (iter = active_connections; iter; iter = iter->next) {
		if (nm_active_connection_get_device (NM_ACTIVE_CONNECTION (iter->data)) == device)
			return;
	}

	nm_device_add_pending_action (device, "autoactivate", TRUE);

	data = g_malloc0 (sizeof (ActivateData));
	data->policy = policy;
	data->device = g_object_ref (device);
	data->autoactivate_id = g_idle_add (auto_activate_device, data);
	priv->pending_activation_checks = g_slist_append (priv->pending_activation_checks, data);
}

static void
clear_pending_activate_check (NMPolicy *policy, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	ActivateData *data;

	data = find_pending_activation (priv->pending_activation_checks, device);
	if (data && data->autoactivate_id)
		activate_data_free (data);
}

static gboolean
reset_connections_retries (gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	GSList *connections, *iter;
	gint32 con_stamp, min_stamp, now;
	gboolean changed = FALSE;

	priv->reset_retries_id = 0;

	min_stamp = 0;
	now = nm_utils_get_monotonic_timestamp_s ();
	connections = nm_settings_get_connections (priv->settings);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMSettingsConnection *connection = NM_SETTINGS_CONNECTION (iter->data);

		con_stamp = nm_settings_connection_get_autoconnect_retry_time (connection);
		if (con_stamp == 0)
			continue;

		if (con_stamp <= now) {
			nm_settings_connection_reset_autoconnect_retries (connection);
			changed = TRUE;
		} else if (min_stamp == 0 || min_stamp > con_stamp)
			min_stamp = con_stamp;
	}
	g_slist_free (connections);

	/* Schedule the handler again if there are some stamps left */
	if (min_stamp != 0)
		priv->reset_retries_id = g_timeout_add_seconds (min_stamp - now, reset_connections_retries, policy);

	/* If anything changed, try to activate the newly re-enabled connections */
	if (changed)
		schedule_activate_all (policy);

	return FALSE;
}

static void schedule_activate_all (NMPolicy *policy);

static void
activate_slave_connections (NMPolicy *policy, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	const char *master_device, *master_uuid_settings = NULL, *master_uuid_applied = NULL;
	GSList *connections, *iter;
	NMActRequest *req;

	master_device = nm_device_get_iface (device);
	g_assert (master_device);

	req = nm_device_get_act_request (device);
	if (req) {
		NMConnection *con;

		con = nm_active_connection_get_applied_connection (NM_ACTIVE_CONNECTION (req));
		if (con)
			master_uuid_applied = nm_connection_get_uuid (con);
		con = NM_CONNECTION (nm_active_connection_get_settings_connection (NM_ACTIVE_CONNECTION (req)));
		if (con) {
			master_uuid_settings = nm_connection_get_uuid (con);
			if (!g_strcmp0 (master_uuid_settings, master_uuid_applied))
				master_uuid_settings = NULL;
		}
	}

	connections = nm_settings_get_connections (priv->settings);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *slave;
		NMSettingConnection *s_slave_con;
		const char *slave_master;

		slave = NM_CONNECTION (iter->data);
		g_assert (slave);

		s_slave_con = nm_connection_get_setting_connection (slave);
		g_assert (s_slave_con);
		slave_master = nm_setting_connection_get_master (s_slave_con);
		if (!slave_master)
			continue;

		if (   !g_strcmp0 (slave_master, master_device)
		    || !g_strcmp0 (slave_master, master_uuid_applied)
		    || !g_strcmp0 (slave_master, master_uuid_settings))
			nm_settings_connection_reset_autoconnect_retries (NM_SETTINGS_CONNECTION (slave));
	}

	g_slist_free (connections);

	schedule_activate_all (policy);
}

static gboolean
activate_secondary_connections (NMPolicy *policy,
                                NMConnection *connection,
                                NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
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
		NMActRequest *req;

		settings_con = nm_settings_get_connection_by_uuid (priv->settings, sec_uuid);
		if (!settings_con) {
			nm_log_warn (LOGD_DEVICE, "Secondary connection '%s' auto-activation failed: The connection doesn't exist.",
			             sec_uuid);
			success = FALSE;
			break;
		}
		if (!nm_connection_is_type (NM_CONNECTION (settings_con), NM_SETTING_VPN_SETTING_NAME)) {
			nm_log_warn (LOGD_DEVICE, "Secondary connection '%s (%s)' auto-activation failed: The connection is not a VPN.",
			             nm_settings_connection_get_id (settings_con), sec_uuid);
			success = FALSE;
			break;
		}

		req = nm_device_get_act_request (device);
		g_assert (req);

		nm_log_dbg (LOGD_DEVICE, "Activating secondary connection '%s (%s)' for base connection '%s (%s)'",
		            nm_settings_connection_get_id (settings_con), sec_uuid,
		            nm_connection_get_id (connection), nm_connection_get_uuid (connection));
		ac = nm_manager_activate_connection (priv->manager,
		                                     settings_con,
		                                     nm_exported_object_get_path (NM_EXPORTED_OBJECT (req)),
		                                     device,
		                                     nm_active_connection_get_subject (NM_ACTIVE_CONNECTION (req)),
		                                     &error);
		if (ac)
			secondary_ac_list = g_slist_append (secondary_ac_list, g_object_ref (ac));
		else {
			nm_log_warn (LOGD_DEVICE, "Secondary connection '%s (%s)' auto-activation failed: (%d) %s",
			             nm_settings_connection_get_id (settings_con), sec_uuid,
			             error ? error->code : 0,
			             (error && error->message) ? error->message : "unknown");
			g_clear_error (&error);
			success = FALSE;
			break;
		}
	}

	if (success && secondary_ac_list != NULL) {
		secondary_data = pending_secondary_data_new (device, secondary_ac_list);
		priv->pending_secondaries = g_slist_append (priv->pending_secondaries, secondary_data);
	} else
		g_slist_free_full (secondary_ac_list, g_object_unref);

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
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);

	NMSettingsConnection *connection = nm_device_get_settings_connection (device);

	const char *ip_iface = nm_device_get_ip_iface (device);
	NMIP4Config *ip4_config;
	NMIP6Config *ip6_config;
	NMSettingConnection *s_con = NULL;

	switch (new_state) {
	case NM_DEVICE_STATE_FAILED:
		/* Mark the connection invalid if it failed during activation so that
		 * it doesn't get automatically chosen over and over and over again.
		 */
		if (   connection
		    && old_state >= NM_DEVICE_STATE_PREPARE
		    && old_state <= NM_DEVICE_STATE_ACTIVATED) {
			guint32 tries = nm_settings_connection_get_autoconnect_retries (connection);

			if (reason == NM_DEVICE_STATE_REASON_NO_SECRETS) {
				nm_log_dbg (LOGD_DEVICE, "Connection '%s' now blocked from autoconnect due to no secrets",
				            nm_settings_connection_get_id (connection));

				nm_settings_connection_set_autoconnect_blocked_reason (connection, NM_DEVICE_STATE_REASON_NO_SECRETS);
			} else if (tries > 0) {
				nm_log_dbg (LOGD_DEVICE, "Connection '%s' failed to autoconnect; %d tries left",
				            nm_settings_connection_get_id (connection), tries);
				nm_settings_connection_set_autoconnect_retries (connection, tries - 1);
			}

			if (nm_settings_connection_get_autoconnect_retries (connection) == 0) {
				nm_log_info (LOGD_DEVICE, "Disabling autoconnect for connection '%s'.",
				             nm_settings_connection_get_id (connection));
				/* Schedule a handler to reset retries count */
				if (!priv->reset_retries_id) {
					gint32 retry_time = nm_settings_connection_get_autoconnect_retry_time (connection);

					g_warn_if_fail (retry_time != 0);
					priv->reset_retries_id = g_timeout_add_seconds (MAX (0, retry_time - nm_utils_get_monotonic_timestamp_s ()), reset_connections_retries, policy);
				}
			}
			nm_connection_clear_secrets (NM_CONNECTION (connection));
		}
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		if (connection) {
			/* Reset auto retries back to default since connection was successful */
			nm_settings_connection_reset_autoconnect_retries (connection);

			/* And clear secrets so they will always be requested from the
			 * settings service when the next connection is made.
			 */

			nm_connection_clear_secrets (NM_CONNECTION (connection));
		}

		/* Add device's new IPv4 and IPv6 configs to DNS */

		nm_dns_manager_begin_updates (priv->dns_manager, __func__);

		ip4_config = nm_device_get_ip4_config (device);
		if (ip4_config)
			nm_dns_manager_add_ip4_config (priv->dns_manager, ip_iface, ip4_config, NM_DNS_IP_CONFIG_TYPE_DEFAULT);
		ip6_config = nm_device_get_ip6_config (device);
		if (ip6_config)
			nm_dns_manager_add_ip6_config (priv->dns_manager, ip_iface, ip6_config, NM_DNS_IP_CONFIG_TYPE_DEFAULT);

		update_routing_and_dns (policy, FALSE);

		nm_dns_manager_end_updates (priv->dns_manager, __func__);
		break;
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
		if (old_state > NM_DEVICE_STATE_DISCONNECTED)
			update_routing_and_dns (policy, FALSE);
		break;
	case NM_DEVICE_STATE_DEACTIVATING:
		if (reason == NM_DEVICE_STATE_REASON_USER_REQUESTED) {
			if (!nm_device_get_autoconnect (device)) {
				/* The device was disconnected; block all connections on it */
				block_autoconnect_for_device (policy, device);
			} else {
				if (connection) {
					/* The connection was deactivated, so block just this connection */
					nm_log_dbg (LOGD_DEVICE, "Blocking autoconnect of connection '%s' by user request",
					            nm_settings_connection_get_id (connection));
					nm_settings_connection_set_autoconnect_blocked_reason (connection,
					                                                       NM_DEVICE_STATE_REASON_USER_REQUESTED);
				}
			}
		}
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		/* Reset retry counts for a device's connections when carrier on; if cable
		 * was unplugged and plugged in again, we should try to reconnect.
		 */
		if (reason == NM_DEVICE_STATE_REASON_CARRIER && old_state == NM_DEVICE_STATE_UNAVAILABLE)
			reset_autoconnect_all (policy, device);

		if (old_state > NM_DEVICE_STATE_DISCONNECTED)
			update_routing_and_dns (policy, FALSE);

		/* Device is now available for auto-activation */
		schedule_activate_check (policy, device);
		break;

	case NM_DEVICE_STATE_PREPARE:
		/* Reset auto-connect retries of all slaves and schedule them for
		 * activation. */
		activate_slave_connections (policy, device);
		break;
	case NM_DEVICE_STATE_IP_CONFIG:
		/* We must have secrets if we got here. */
		if (connection)
			nm_settings_connection_set_autoconnect_blocked_reason (connection, NM_DEVICE_STATE_REASON_NONE);
		break;
	case NM_DEVICE_STATE_SECONDARIES:
		if (connection)
			s_con = nm_connection_get_setting_connection (NM_CONNECTION (connection));
		if (s_con && nm_setting_connection_get_num_secondaries (s_con) > 0) {
			/* Make routes and DNS up-to-date before activating dependent connections */
			update_routing_and_dns (policy, FALSE);

			/* Activate secondary (VPN) connections */
			if (!activate_secondary_connections (policy, NM_CONNECTION (connection), device))
				nm_device_queue_state (device, NM_DEVICE_STATE_FAILED,
				                       NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED);
		} else
			nm_device_queue_state (device, NM_DEVICE_STATE_ACTIVATED,
			                       NM_DEVICE_STATE_REASON_NONE);
		break;

	default:
		break;
	}

	check_activating_devices (policy);
}

static void
device_ip4_config_changed (NMDevice *device,
                           NMIP4Config *new_config,
                           NMIP4Config *old_config,
                           gpointer user_data)
{
	NMPolicy *policy = user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	const char *ip_iface = nm_device_get_ip_iface (device);

	nm_dns_manager_begin_updates (priv->dns_manager, __func__);

	/* Ignore IP config changes while the device is activating, because we'll
	 * catch all the changes when the device moves to ACTIVATED state.
	 * Prevents unecessary changes to DNS information.
	 */
	if (!nm_device_is_activating (device)) {
		if (old_config != new_config) {
			if (old_config)
				nm_dns_manager_remove_ip4_config (priv->dns_manager, old_config);
			if (new_config)
				nm_dns_manager_add_ip4_config (priv->dns_manager, ip_iface, new_config, NM_DNS_IP_CONFIG_TYPE_DEFAULT);
		}
		update_ip4_dns (policy, priv->dns_manager);
		update_ip4_routing (policy, TRUE);
	} else {
		/* Old configs get removed immediately */
		if (old_config)
			nm_dns_manager_remove_ip4_config (priv->dns_manager, old_config);
	}

	nm_dns_manager_end_updates (priv->dns_manager, __func__);
}

static void
device_ip6_config_changed (NMDevice *device,
                           NMIP6Config *new_config,
                           NMIP6Config *old_config,
                           gpointer user_data)
{
	NMPolicy *policy = user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	const char *ip_iface = nm_device_get_ip_iface (device);

	nm_dns_manager_begin_updates (priv->dns_manager, __func__);

	/* Ignore IP config changes while the device is activating, because we'll
	 * catch all the changes when the device moves to ACTIVATED state.
	 * Prevents unecessary changes to DNS information.
	 */
	if (!nm_device_is_activating (device)) {
		if (old_config != new_config) {
			if (old_config)
				nm_dns_manager_remove_ip6_config (priv->dns_manager, old_config);
			if (new_config)
				nm_dns_manager_add_ip6_config (priv->dns_manager, ip_iface, new_config, NM_DNS_IP_CONFIG_TYPE_DEFAULT);
		}
		update_ip6_dns (policy, priv->dns_manager);
		update_ip6_routing (policy, TRUE);
	} else {
		/* Old configs get removed immediately */
		if (old_config)
			nm_dns_manager_remove_ip6_config (priv->dns_manager, old_config);
	}

	nm_dns_manager_end_updates (priv->dns_manager, __func__);
}

static void
device_autoconnect_changed (NMDevice *device,
                            GParamSpec *pspec,
                            gpointer user_data)
{
	if (nm_device_autoconnect_allowed (device))
		schedule_activate_check ((NMPolicy *) user_data, device);
}

static void
device_recheck_auto_activate (NMDevice *device, gpointer user_data)
{
	schedule_activate_check (NM_POLICY (user_data), device);
}

typedef struct {
	gulong id;
	NMDevice *device;
} DeviceSignalId;

static void
_connect_device_signal (NMPolicy *policy,
                        NMDevice *device,
                        const char *name,
                        gpointer callback,
                        gboolean after)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	DeviceSignalId *data;

	data = g_slice_new0 (DeviceSignalId);
	g_assert (data);
	if (after)
		data->id = g_signal_connect_after (device, name, callback, policy);
	else
		data->id = g_signal_connect (device, name, callback, policy);
	data->device = device;
	priv->dev_ids = g_slist_prepend (priv->dev_ids, data);
}

static void
device_added (NMManager *manager, NMDevice *device, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	/* Connect state-changed with _after, so that the handler is invoked after other handlers. */
	_connect_device_signal (policy, device, "state-changed", device_state_changed, TRUE);
	_connect_device_signal (policy, device, NM_DEVICE_IP4_CONFIG_CHANGED, device_ip4_config_changed, FALSE);
	_connect_device_signal (policy, device, NM_DEVICE_IP6_CONFIG_CHANGED, device_ip6_config_changed, FALSE);
	_connect_device_signal (policy, device, "notify::" NM_DEVICE_AUTOCONNECT, device_autoconnect_changed, FALSE);
	_connect_device_signal (policy, device, NM_DEVICE_RECHECK_AUTO_ACTIVATE, device_recheck_auto_activate, FALSE);
}

static void
device_removed (NMManager *manager, NMDevice *device, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	GSList *iter;

	/* Clear any idle callbacks for this device */
	clear_pending_activate_check (policy, device);

	/* Clear any signal handlers for this device */
	iter = priv->dev_ids;
	while (iter) {
		DeviceSignalId *data = iter->data;
		GSList *next = g_slist_next (iter);

		if (data->device == device) {
			g_signal_handler_disconnect (data->device, data->id);
			g_slice_free (DeviceSignalId, data);
			priv->dev_ids = g_slist_delete_link (priv->dev_ids, iter);
		}
		iter = next;
	}

	/* Don't update routing and DNS here as we've already handled that
	 * for devices that need it when the device's state changed to UNMANAGED.
	 */
}

/**************************************************************************/

static void
vpn_connection_activated (NMPolicy *policy, NMVpnConnection *vpn)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	NMIP4Config *ip4_config;
	NMIP6Config *ip6_config;
	const char *ip_iface;

	nm_dns_manager_begin_updates (priv->dns_manager, __func__);

	ip_iface = nm_vpn_connection_get_ip_iface (vpn);

	/* Add the VPN connection's IP configs from DNS */

	ip4_config = nm_vpn_connection_get_ip4_config (vpn);
	if (ip4_config)
		nm_dns_manager_add_ip4_config (priv->dns_manager, ip_iface, ip4_config, NM_DNS_IP_CONFIG_TYPE_VPN);

	ip6_config = nm_vpn_connection_get_ip6_config (vpn);
	if (ip6_config)
		nm_dns_manager_add_ip6_config (priv->dns_manager, ip_iface, ip6_config, NM_DNS_IP_CONFIG_TYPE_VPN);

	update_routing_and_dns (policy, TRUE);

	nm_dns_manager_end_updates (priv->dns_manager, __func__);
}

static void
vpn_connection_deactivated (NMPolicy *policy, NMVpnConnection *vpn)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	NMIP4Config *ip4_config;
	NMIP6Config *ip6_config;

	nm_dns_manager_begin_updates (priv->dns_manager, __func__);

	ip4_config = nm_vpn_connection_get_ip4_config (vpn);
	if (ip4_config) {
		/* Remove the VPN connection's IP4 config from DNS */
		nm_dns_manager_remove_ip4_config (priv->dns_manager, ip4_config);
	}

	ip6_config = nm_vpn_connection_get_ip6_config (vpn);
	if (ip6_config) {
		/* Remove the VPN connection's IP6 config from DNS */
		nm_dns_manager_remove_ip6_config (priv->dns_manager, ip6_config);
	}

	update_routing_and_dns (policy, TRUE);

	nm_dns_manager_end_updates (priv->dns_manager, __func__);
}

static void
vpn_connection_state_changed (NMVpnConnection *vpn,
                              NMVpnConnectionState new_state,
                              NMVpnConnectionState old_state,
                              NMVpnConnectionStateReason reason,
                              NMPolicy *policy)
{
	if (new_state == NM_VPN_CONNECTION_STATE_ACTIVATED)
		vpn_connection_activated (policy, vpn);
	else if (new_state >= NM_VPN_CONNECTION_STATE_FAILED) {
		/* Only clean up IP/DNS if the connection ever got past IP_CONFIG */
		if (old_state >= NM_VPN_CONNECTION_STATE_IP_CONFIG_GET &&
		    old_state <= NM_VPN_CONNECTION_STATE_ACTIVATED)
			vpn_connection_deactivated (policy, vpn);
	}
}

static void
vpn_connection_retry_after_failure (NMVpnConnection *vpn, NMPolicy *policy)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	NMActiveConnection *ac = NM_ACTIVE_CONNECTION (vpn);
	NMSettingsConnection *connection = nm_active_connection_get_settings_connection (ac);
	GError *error = NULL;

	/* Attempt to reconnect VPN connections that failed after being connected */
	if (!nm_manager_activate_connection (priv->manager,
	                                     connection,
	                                     NULL,
	                                     NULL,
	                                     nm_active_connection_get_subject (ac),
	                                     &error)) {
		nm_log_warn (LOGD_DEVICE, "VPN '%s' reconnect failed: %s",
		             nm_settings_connection_get_id (connection),
		             error->message ? error->message : "unknown");
		g_clear_error (&error);
	}
}

static void
active_connection_state_changed (NMActiveConnection *active,
                                 GParamSpec *pspec,
                                 NMPolicy *policy)
{
	NMActiveConnectionState state = nm_active_connection_get_state (active);

	if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
		process_secondaries (policy, active, TRUE);
	else if (state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
		process_secondaries (policy, active, FALSE);
}

static void
active_connection_added (NMManager *manager,
                         NMActiveConnection *active,
                         gpointer user_data)
{
	NMPolicy *policy = NM_POLICY (user_data);

	if (NM_IS_VPN_CONNECTION (active)) {
		g_signal_connect (active, NM_VPN_CONNECTION_INTERNAL_STATE_CHANGED,
		                  G_CALLBACK (vpn_connection_state_changed),
		                  policy);
		g_signal_connect (active, NM_VPN_CONNECTION_INTERNAL_RETRY_AFTER_FAILURE,
		                  G_CALLBACK (vpn_connection_retry_after_failure),
		                  policy);
	}

	g_signal_connect (active, "notify::" NM_ACTIVE_CONNECTION_STATE,
	                  G_CALLBACK (active_connection_state_changed),
	                  policy);
}

static void
active_connection_removed (NMManager *manager,
                           NMActiveConnection *active,
                           gpointer user_data)
{
	NMPolicy *policy = NM_POLICY (user_data);

	g_signal_handlers_disconnect_by_func (active,
	                                      vpn_connection_state_changed,
	                                      policy);
	g_signal_handlers_disconnect_by_func (active,
	                                      vpn_connection_retry_after_failure,
	                                      policy);
	g_signal_handlers_disconnect_by_func (active,
	                                      active_connection_state_changed,
	                                      policy);
}

/**************************************************************************/

static void
schedule_activate_all (NMPolicy *policy)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	const GSList *iter;

	for (iter = nm_manager_get_devices (priv->manager); iter; iter = g_slist_next (iter))
		schedule_activate_check (policy, NM_DEVICE (iter->data));
}

static void
connection_added (NMSettings *settings,
                  NMSettingsConnection *connection,
                  gpointer user_data)
{
	NMPolicy *policy = NM_POLICY (user_data);

	schedule_activate_all (policy);
}

static void
firewall_started (NMFirewallManager *manager,
                  gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	const GSList *iter;

	/* add interface of each device to correct zone */
	for (iter = nm_manager_get_devices (priv->manager); iter; iter = g_slist_next (iter))
		nm_device_update_firewall_zone (iter->data);
}

static void
dns_config_changed (NMDnsManager *dns_manager, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);

	/* Restart a thread for reverse-DNS lookup after we are signalled that
	 * DNS changed. Because the result from a previous run may not be right
	 * (race in updating DNS and doing the reverse lookup).
	 */

	/* Stop a lookup thread if any. */
	if (priv->lookup_cancellable) {
		g_cancellable_cancel (priv->lookup_cancellable);
		g_clear_object (&priv->lookup_cancellable);
	}

	/* Re-start the hostname lookup thread if we don't have hostname yet. */
	if (priv->lookup_addr) {
		char *str = NULL;

		nm_log_dbg (LOGD_DNS, "restarting reverse-lookup thread for address %s",
		            (str = g_inet_address_to_string (priv->lookup_addr)));
		g_free (str);

		priv->lookup_cancellable = g_cancellable_new ();
		g_resolver_lookup_by_address_async (priv->resolver,
		                                    priv->lookup_addr,
		                                    priv->lookup_cancellable,
		                                    lookup_callback, policy);
	}
}

static void
connection_updated (NMSettings *settings,
                    NMConnection *connection,
                    gpointer user_data)
{
	schedule_activate_all ((NMPolicy *) user_data);
}

static void
connection_updated_by_user (NMSettings *settings,
                            NMSettingsConnection *connection,
                            gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	const GSList *iter;
	NMDevice *device = NULL;

	/* find device with given connection */
	for (iter = nm_manager_get_devices (priv->manager); iter; iter = g_slist_next (iter)) {
		NMDevice *dev = NM_DEVICE (iter->data);

		if (nm_device_get_settings_connection (dev) == connection) {
			device = dev;
			break;
		}
	}

	if (device)
		nm_device_reapply_settings_immediately (device);

	/* Reset auto retries back to default since connection was updated */
	nm_settings_connection_reset_autoconnect_retries (connection);
}

static void
_deactivate_if_active (NMManager *manager, NMSettingsConnection *connection)
{
	const GSList *active, *iter;

	active = nm_manager_get_active_connections (manager);
	for (iter = active; iter; iter = g_slist_next (iter)) {
		NMActiveConnection *ac = iter->data;
		NMActiveConnectionState state = nm_active_connection_get_state (ac);
		GError *error = NULL;

		if (nm_active_connection_get_settings_connection (ac) == connection &&
		    (state <= NM_ACTIVE_CONNECTION_STATE_ACTIVATED)) {
			if (!nm_manager_deactivate_connection (manager,
			                                       nm_exported_object_get_path (NM_EXPORTED_OBJECT (ac)),
			                                       NM_DEVICE_STATE_REASON_CONNECTION_REMOVED,
			                                       &error)) {
				nm_log_warn (LOGD_DEVICE, "Connection '%s' disappeared, but error deactivating it: (%d) %s",
					         nm_settings_connection_get_id (connection),
					         error ? error->code : -1,
					         error ? error->message : "(unknown)");
				g_clear_error (&error);
			}
		}
	}
}

static void
connection_removed (NMSettings *settings,
                    NMSettingsConnection *connection,
                    gpointer user_data)
{
	NMPolicy *policy = user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);

	_deactivate_if_active (priv->manager, connection);
}

static void
connection_visibility_changed (NMSettings *settings,
                               NMSettingsConnection *connection,
                               gpointer user_data)
{
	NMPolicy *policy = user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);

	if (nm_settings_connection_is_visible (connection))
		schedule_activate_all (policy);
	else
		_deactivate_if_active (priv->manager, connection);
}

static void
secret_agent_registered (NMSettings *settings,
                         NMSecretAgent *agent,
                         gpointer user_data)
{
	NMPolicy *policy = NM_POLICY (user_data);

	/* The registered secret agent may provide some missing secrets. Thus we
	 * reset retries count here and schedule activation, so that the
	 * connections failed due to missing secrets may re-try auto-connection.
	 */
	reset_autoconnect_for_failed_secrets (policy);
	schedule_activate_all (policy);
}

static void
_connect_manager_signal (NMPolicy *policy, const char *name, gpointer callback)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	guint id;

	id = g_signal_connect (priv->manager, name, callback, policy);
	priv->manager_ids = g_slist_prepend (priv->manager_ids, GUINT_TO_POINTER (id));
}

static void
_connect_settings_signal (NMPolicy *policy, const char *name, gpointer callback)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	guint id;

	id = g_signal_connect (priv->settings, name, callback, policy);
	priv->settings_ids = g_slist_prepend (priv->settings_ids, GUINT_TO_POINTER (id));
}

NMPolicy *
nm_policy_new (NMManager *manager, NMSettings *settings)
{
	NMPolicy *policy;
	NMPolicyPrivate *priv;
	static gboolean initialized = FALSE;
	char hostname[HOST_NAME_MAX + 2];

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (initialized == FALSE, NULL);

	policy = g_object_new (NM_TYPE_POLICY, NULL);
	priv = NM_POLICY_GET_PRIVATE (policy);
	priv->manager = manager;
	priv->settings = g_object_ref (settings);
	priv->update_state_id = 0;

	/* Grab hostname on startup and use that if nothing provides one */
	memset (hostname, 0, sizeof (hostname));
	if (gethostname (&hostname[0], HOST_NAME_MAX) == 0) {
		/* only cache it if it's a valid hostname */
		if (*hostname && nm_utils_is_specific_hostname (hostname))
			priv->orig_hostname = g_strdup (hostname);
	}

	priv->firewall_manager = g_object_ref (nm_firewall_manager_get ());

	priv->fw_started_id = g_signal_connect (priv->firewall_manager, "started",
	                                        G_CALLBACK (firewall_started), policy);

	priv->dns_manager = g_object_ref (nm_dns_manager_get ());
	nm_dns_manager_set_initial_hostname (priv->dns_manager, priv->orig_hostname);
	priv->config_changed_id = g_signal_connect (priv->dns_manager, "config-changed",
	                                            G_CALLBACK (dns_config_changed), policy);

	priv->resolver = g_resolver_get_default ();

	_connect_manager_signal (policy, "state-changed", global_state_changed);
	_connect_manager_signal (policy, "notify::" NM_MANAGER_HOSTNAME, hostname_changed);
	_connect_manager_signal (policy, "notify::" NM_MANAGER_SLEEPING, sleeping_changed);
	_connect_manager_signal (policy, "notify::" NM_MANAGER_NETWORKING_ENABLED, sleeping_changed);
	_connect_manager_signal (policy, "device-added", device_added);
	_connect_manager_signal (policy, "device-removed", device_removed);
	_connect_manager_signal (policy, NM_MANAGER_ACTIVE_CONNECTION_ADDED, active_connection_added);
	_connect_manager_signal (policy, NM_MANAGER_ACTIVE_CONNECTION_REMOVED, active_connection_removed);

	_connect_settings_signal (policy, NM_SETTINGS_SIGNAL_CONNECTION_ADDED, connection_added);
	_connect_settings_signal (policy, NM_SETTINGS_SIGNAL_CONNECTION_UPDATED, connection_updated);
	_connect_settings_signal (policy, NM_SETTINGS_SIGNAL_CONNECTION_UPDATED_BY_USER, connection_updated_by_user);
	_connect_settings_signal (policy, NM_SETTINGS_SIGNAL_CONNECTION_REMOVED, connection_removed);
	_connect_settings_signal (policy, NM_SETTINGS_SIGNAL_CONNECTION_VISIBILITY_CHANGED,
	                          connection_visibility_changed);
	_connect_settings_signal (policy, NM_SETTINGS_SIGNAL_AGENT_REGISTERED, secret_agent_registered);

	initialized = TRUE;
	return policy;
}

NMDevice *
nm_policy_get_default_ip4_device (NMPolicy *policy)
{
	return NM_POLICY_GET_PRIVATE (policy)->default_device4;
}

NMDevice *
nm_policy_get_default_ip6_device (NMPolicy *policy)
{
	return NM_POLICY_GET_PRIVATE (policy)->default_device6;
}

NMDevice *
nm_policy_get_activating_ip4_device (NMPolicy *policy)
{
	return NM_POLICY_GET_PRIVATE (policy)->activating_device4;
}

NMDevice *
nm_policy_get_activating_ip6_device (NMPolicy *policy)
{
	return NM_POLICY_GET_PRIVATE (policy)->activating_device6;
}

static void
nm_policy_init (NMPolicy *policy)
{
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMPolicy *policy = NM_POLICY (object);
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);

	switch (prop_id) {
	case PROP_DEFAULT_IP4_DEVICE:
		g_value_set_object (value, priv->default_device4);
		break;
	case PROP_DEFAULT_IP6_DEVICE:
		g_value_set_object (value, priv->default_device6);
		break;
	case PROP_ACTIVATING_IP4_DEVICE:
		g_value_set_object (value, priv->activating_device4);
		break;
	case PROP_ACTIVATING_IP6_DEVICE:
		g_value_set_object (value, priv->activating_device6);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMPolicy *policy = NM_POLICY (object);
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (policy);
	const GSList *connections, *iter;

	/* Tell any existing hostname lookup thread to die. */
	if (priv->lookup_cancellable) {
		g_cancellable_cancel (priv->lookup_cancellable);
		g_clear_object (&priv->lookup_cancellable);
	}
	g_clear_object (&priv->lookup_addr);
	g_clear_object (&priv->resolver);

	while (priv->pending_activation_checks)
		activate_data_free (priv->pending_activation_checks->data);

	g_slist_free_full (priv->pending_secondaries, (GDestroyNotify) pending_secondary_data_free);
	priv->pending_secondaries = NULL;

	if (priv->firewall_manager) {
		g_assert (priv->fw_started_id);
		g_signal_handler_disconnect (priv->firewall_manager, priv->fw_started_id);
		priv->fw_started_id = 0;
		g_clear_object (&priv->firewall_manager);
	}

	if (priv->dns_manager) {
		g_signal_handler_disconnect (priv->dns_manager, priv->config_changed_id);
		g_clear_object (&priv->dns_manager);
	}

	for (iter = priv->manager_ids; iter; iter = g_slist_next (iter))
		g_signal_handler_disconnect (priv->manager, GPOINTER_TO_UINT (iter->data));
	g_clear_pointer (&priv->manager_ids, g_slist_free);

	for (iter = priv->settings_ids; iter; iter = g_slist_next (iter))
		g_signal_handler_disconnect (priv->settings, GPOINTER_TO_UINT (iter->data));
	g_clear_pointer (&priv->settings_ids, g_slist_free);

	for (iter = priv->dev_ids; iter; iter = g_slist_next (iter)) {
		DeviceSignalId *data = iter->data;

		g_signal_handler_disconnect (data->device, data->id);
		g_slice_free (DeviceSignalId, data);
	}
	g_clear_pointer (&priv->dev_ids, g_slist_free);

	/* The manager should have disposed of ActiveConnections already, which
	 * will have called active_connection_removed() and thus we don't need
	 * to clean anything up.  Assert that this is TRUE.
	 */
	connections = nm_manager_get_active_connections (priv->manager);
	g_assert (connections == NULL);

	if (priv->reset_retries_id) {
		g_source_remove (priv->reset_retries_id);
		priv->reset_retries_id = 0;
	}

	g_clear_pointer (&priv->orig_hostname, g_free);
	g_clear_pointer (&priv->cur_hostname, g_free);

	g_clear_object (&priv->settings);

	G_OBJECT_CLASS (nm_policy_parent_class)->dispose (object);
}

static void
nm_policy_class_init (NMPolicyClass *policy_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (policy_class);

	g_type_class_add_private (policy_class, sizeof (NMPolicyPrivate));

	object_class->get_property = get_property;
	object_class->dispose = dispose;

	g_object_class_install_property
		(object_class, PROP_DEFAULT_IP4_DEVICE,
		 g_param_spec_object (NM_POLICY_DEFAULT_IP4_DEVICE, "", "",
		                      NM_TYPE_DEVICE,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_DEFAULT_IP6_DEVICE,
		 g_param_spec_object (NM_POLICY_DEFAULT_IP6_DEVICE, "", "",
		                      NM_TYPE_DEVICE,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_ACTIVATING_IP4_DEVICE,
		 g_param_spec_object (NM_POLICY_ACTIVATING_IP4_DEVICE, "", "",
		                      NM_TYPE_DEVICE,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_ACTIVATING_IP6_DEVICE,
		 g_param_spec_object (NM_POLICY_ACTIVATING_IP6_DEVICE, "", "",
		                      NM_TYPE_DEVICE,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
}
