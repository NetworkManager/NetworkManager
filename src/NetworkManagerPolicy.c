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
 * Copyright (C) 2004 - 2008 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>

#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerAP.h"
#include "nm-activation-request.h"
#include "nm-utils.h"
#include "nm-device-interface.h"
#include "nm-device.h"
#include "nm-device-wifi.h"
#include "nm-device-ethernet.h"
#include "nm-hso-gsm-device.h"
#include "nm-gsm-device.h"
#include "nm-cdma-device.h"
#include "nm-dbus-manager.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-connection.h"
#include "NetworkManagerSystem.h"
#include "nm-named-manager.h"
#include "nm-vpn-manager.h"

typedef struct LookupThread LookupThread;

typedef void (*LookupCallback) (LookupThread *thread, gpointer user_data);

struct LookupThread {
	GThread *thread;

	GMutex *lock;
	gboolean die;
	int ret;

	guint32 ip4_addr;
	char hostname[NI_MAXHOST + 1];

	LookupCallback callback;
	gpointer user_data;
};

struct NMPolicy {
	NMManager *manager;
	guint update_state_id;
	GSList *pending_activation_checks;
	GSList *signal_ids;
	GSList *dev_signal_ids;

	NMVPNManager *vpn_manager;
	gulong vpn_activated_id;
	gulong vpn_deactivated_id;

	NMDevice *default_device;

	LookupThread *lookup;
};

static gboolean
lookup_thread_run_cb (gpointer user_data)
{
	LookupThread *thread = (LookupThread *) user_data;

	(*thread->callback) (thread, thread->user_data);
	return FALSE;
}

static gpointer
lookup_thread_worker (gpointer data)
{
	LookupThread *thread = (LookupThread *) data;
	struct sockaddr_in addr;

	g_mutex_lock (thread->lock);
	if (thread->die) {
		g_mutex_unlock (thread->lock);
		return (gpointer) NULL;
	}
	g_mutex_unlock (thread->lock);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = thread->ip4_addr;

	thread->ret = getnameinfo ((struct sockaddr *) &addr, sizeof (struct sockaddr_in),
	                           thread->hostname, NI_MAXHOST, NULL, 0,
	                           NI_NAMEREQD);
	if (thread->ret == 0) {
		int i;

		for (i = 0; i < strlen (thread->hostname); i++)
			thread->hostname[i] = tolower (thread->hostname[i]);
	}

	/* Don't track the idle handler ID because by the time the g_idle_add()
	 * returns the ID, the handler may already have run and freed the
	 * LookupThread.
	 */
	g_idle_add (lookup_thread_run_cb, thread);
	return (gpointer) TRUE;
}

static void
lookup_thread_free (LookupThread *thread)
{
	g_return_if_fail (thread != NULL);

	g_mutex_free (thread->lock);
	memset (thread, 0, sizeof (LookupThread));
	g_free (thread);
}

static LookupThread *
lookup_thread_new (guint32 ip4_addr, LookupCallback callback, gpointer user_data)
{
	LookupThread *thread;

	thread = g_malloc0 (sizeof (LookupThread));
	if (!thread)
		return NULL;

	thread->lock = g_mutex_new ();
	thread->callback = callback;
	thread->user_data = user_data;
	thread->ip4_addr = ip4_addr;

	thread->thread = g_thread_create (lookup_thread_worker, thread, FALSE, NULL);
	if (!thread->thread) {
		lookup_thread_free (thread);
		return NULL;
	}

	return thread;
}

static void
lookup_thread_die (LookupThread *thread)
{
	g_return_if_fail (thread != NULL);

	g_mutex_lock (thread->lock);
	thread->die = TRUE;
	g_mutex_unlock (thread->lock);
}

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
get_best_device (NMManager *manager, NMActRequest **out_req)
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

		/* 'hso' devices never get a gateway from the remote end */
		if (!can_default && !NM_IS_HSO_GSM_DEVICE (dev))
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

#define FALLBACK_HOSTNAME "localhost.localdomain"

static gboolean
update_etc_hosts (const char *hostname)
{
	char *contents = NULL;
	char **lines = NULL, **line;
	GError *error = NULL;
	gboolean initial_comments = TRUE;
	gboolean added = FALSE;
	gsize contents_len = 0;
	GString *new_contents;
	gboolean success = FALSE;

	g_return_val_if_fail (hostname != NULL, FALSE);

	if (!g_file_get_contents (SYSCONFDIR "/hosts", &contents, &contents_len, &error)) {
		nm_warning ("%s: couldn't read " SYSCONFDIR "/hosts: (%d) %s",
		            __func__, error ? error->code : 0,
		            (error && error->message) ? error->message : "(unknown)");
		if (error)
			g_error_free (error);
	} else {
		lines = g_strsplit_set (contents, "\n\r", 0);
		g_free (contents);
	}

	new_contents = g_string_sized_new (contents_len ? contents_len + 100 : 200);
	if (!new_contents) {
		nm_warning ("%s: not enough memory to update " SYSCONFDIR "/hosts", __func__);
		return FALSE;
	}

	/* Replace any 127.0.0.1 entry that is at the beginning of the file or right
	 * after initial comments.  If there is no 127.0.0.1 entry at the beginning
	 * or after initial comments, add one there and ignore any other 127.0.0.1
	 * entries.
	 */
	for (line = lines; lines && *line; line++) {
		gboolean add_line = TRUE;

		/* This is the first line after the initial comments */
		if (initial_comments && (*line[0] != '#')) {
			initial_comments = FALSE;
			g_string_append_printf (new_contents, "127.0.0.1\t%s", hostname);
			if (strcmp (hostname, FALLBACK_HOSTNAME))
				g_string_append_printf (new_contents, "\t" FALLBACK_HOSTNAME);
			g_string_append (new_contents, "\tlocalhost\n");
			added = TRUE;

			/* Don't add the entry if it's supposed to be the actual localhost reverse mapping */
			if (!strncmp (*line, "127.0.0.1", strlen ("127.0.0.1")) && strstr (*line, "localhost"))
				add_line = FALSE;
		}

		if (add_line) {
			g_string_append (new_contents, *line);
			/* Only append the new line if this isn't the last line in the file */
			if (*(line+1))
				g_string_append_c (new_contents, '\n');
		}
	}

	/* Hmm, /etc/hosts was empty for some reason */
	if (!added) {
		g_string_append (new_contents, "# Do not remove the following line, or various programs");
		g_string_append (new_contents, "# that require network functionality will fail.");
		g_string_append (new_contents, "127.0.0.1\t" FALLBACK_HOSTNAME "\tlocalhost");
	}

	error = NULL;
	if (!g_file_set_contents (SYSCONFDIR "/hosts", new_contents->str, -1, &error)) {
		nm_warning ("%s: couldn't update " SYSCONFDIR "/hosts: (%d) %s",
		            __func__, error ? error->code : 0,
		            (error && error->message) ? error->message : "(unknown)");
		if (error)
			g_error_free (error);
	} else
		success = TRUE;

	g_string_free (new_contents, TRUE);
	return success;
}

static void
set_system_hostname (const char *new_hostname, const char *msg)
{
	char old_hostname[HOST_NAME_MAX + 1];
	int ret = 0;
	const char *name = new_hostname ? new_hostname : FALLBACK_HOSTNAME;

	old_hostname[HOST_NAME_MAX] = '\0';
	errno = 0;
	ret = gethostname (old_hostname, HOST_NAME_MAX);
	if (ret != 0) {
		nm_warning ("%s: couldn't get the system hostname: (%d) %s",
		            __func__, errno, strerror (errno));
	} else {
		/* Do nothing if the hostname isn't actually changing */
		if (   (new_hostname && !strcmp (old_hostname, new_hostname))
		    || (!new_hostname && !strcmp (old_hostname, FALLBACK_HOSTNAME)))
			return;
	}

	nm_info ("Setting system hostname to '%s' (%s)", name, msg);

	ret = sethostname (name, strlen (name));
	if (ret == 0) {
		if (!update_etc_hosts (name)) {
			/* error updating /etc/hosts; fallback to localhost.localdomain */
			nm_info ("Setting system hostname to '" FALLBACK_HOSTNAME "' (error updating /etc/hosts)");
			ret = sethostname (FALLBACK_HOSTNAME, strlen (FALLBACK_HOSTNAME));
			if (ret != 0) {
				nm_warning ("%s: couldn't set the fallback system hostname (%s): (%d) %s",
				            __func__, FALLBACK_HOSTNAME, errno, strerror (errno));
			}
		}
		nm_utils_call_dispatcher ("hostname", NULL, NULL, NULL);
	} else {
		nm_warning ("%s: couldn't set the system hostname to '%s': (%d) %s",
		            __func__, name, errno, strerror (errno));
	}
}

static void
lookup_callback (LookupThread *thread, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	/* If the thread was told to die or it's not the current in-progress
	 * hostname lookup, nothing to do.
	 */
	if (thread->die || (thread != policy->lookup))
		goto done;

	policy->lookup = NULL;
	if (!strlen (thread->hostname)) {
		char *msg;

		/* No valid IP4 config (!!); fall back to localhost.localdomain */
		msg = g_strdup_printf ("address lookup failed: %d", thread->ret);
		set_system_hostname (NULL, msg);
		g_free (msg);
	} else
		set_system_hostname (thread->hostname, "from address lookup");

done:
	lookup_thread_free (thread);
}

static void
update_system_hostname (NMPolicy *policy, NMDevice *best)
{
	char *configured_hostname = NULL;
	NMActRequest *best_req = NULL;
	NMDHCP4Config *dhcp4_config;
	NMIP4Config *ip4_config;
	NMIP4Address *addr;

	g_return_if_fail (policy != NULL);

	if (policy->lookup) {
		lookup_thread_die (policy->lookup);
		policy->lookup = NULL;
	}

	/* A configured hostname (via the system-settings service) overrides
	 * all automatic hostname determination.  If there is no configured hostname,
	 * the best device's automatically determined hostname (from DHCP, VPN, PPP,
	 * etc) is used.  If there is no automatically determined hostname, reverse
	 * DNS lookup using the best device's IP address is started to determined the
	 * the hostname.
	 */

	/* Try a configured hostname first */
	g_object_get (G_OBJECT (policy->manager), NM_MANAGER_HOSTNAME, &configured_hostname, NULL);
	if (configured_hostname) {
		set_system_hostname (configured_hostname, "from system configuration");
		g_free (configured_hostname);
		return;
	}

	/* Try automatically determined hostname from the best device's IP config */
	if (!best)
		best = get_best_device (policy->manager, &best_req);

	if (!best) {
		/* No best device; fall back to localhost.localdomain */
		set_system_hostname (NULL, "no default device");
		return;
	}

	/* Grab a hostname out of the device's DHCP4 config */
	dhcp4_config = nm_device_get_dhcp4_config (best);
	if (dhcp4_config) {
		const char *dhcp4_hostname;

		dhcp4_hostname = nm_dhcp4_config_get_option (dhcp4_config, "host_name");
		if (dhcp4_hostname && strlen (dhcp4_hostname)) {
			set_system_hostname (dhcp4_hostname, "from DHCP");
			return;
		}
	}

	/* No configured hostname, no automatically determined hostname either. Start
	 * reverse DNS of the current IP address to try and find it.
	 */
	ip4_config = nm_device_get_ip4_config (best);
	if (   !ip4_config
	    || (nm_ip4_config_get_num_nameservers (ip4_config) == 0)
	    || (nm_ip4_config_get_num_addresses (ip4_config) == 0)) {
		/* No valid IP4 config (!!); fall back to localhost.localdomain */
		set_system_hostname (NULL, "no IPv4 config");
		return;
	}

	addr = nm_ip4_config_get_address (ip4_config, 0);
	g_assert (addr); /* checked for > 1 address above */

	/* Start the hostname lookup thread */
	policy->lookup = lookup_thread_new (nm_ip4_address_get_address (addr), lookup_callback, policy);
	if (!policy->lookup) {
		/* Fall back to 'localhost.localdomain' */
		set_system_hostname (NULL, "error starting hostname thread");
	}
}

static void
update_routing_and_dns (NMPolicy *policy, gboolean force_update)
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

	best = get_best_device (policy->manager, &best_req);
	if (!best)
		goto out;
	if (!force_update && (best == policy->default_device))
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
		nm_warning ("%s: couldn't determine IP interface (%p) or IPv4 config (%p)!",
		            __func__, ip_iface, ip4_config);
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
	if (connection_id)
		nm_info ("Policy set '%s' (%s) as default for routing and DNS.", connection_id, ip_iface);
	else
		nm_info ("Policy set (%s) as default for routing and DNS.", ip_iface);

out:
	/* Update the system hostname */
	update_system_hostname (policy, best);

	policy->default_device = best;	
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
		const char *device_path;

		device_path = nm_device_get_udi (data->device);
		if (!nm_manager_activate_connection (policy->manager,
		                                     best_connection,
		                                     specific_object,
		                                     device_path,
		                                     FALSE,
		                                     &error)) {
			NMSettingConnection *s_con;

			s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (best_connection, NM_TYPE_SETTING_CONNECTION));
			g_assert (s_con);

			nm_warning ("Connection '%s' auto-activation failed: (%d) %s",
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
	update_system_hostname ((NMPolicy *) user_data, NULL);
}

static void
schedule_activate_check (NMPolicy *policy, NMDevice *device)
{
	ActivateData *data;
	GSList *iter;
	NMDeviceState state;

	if (nm_manager_get_state (policy->manager) == NM_STATE_ASLEEP)
		return;

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (device));
	if (state < NM_DEVICE_STATE_DISCONNECTED)
		return;

	if (!nm_device_can_activate (device))
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
	data->id = g_idle_add (auto_activate_device, data);
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
		/* Mark the connection invalid so it doesn't get automatically chosen */
		if (connection) {
			g_object_set_data (G_OBJECT (connection), INVALID_TAG, GUINT_TO_POINTER (TRUE));
			nm_info ("Marking connection '%s' invalid.", get_connection_id (connection));
			nm_connection_clear_secrets (connection);
		}
		schedule_activate_check (policy, device);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		/* Clear the invalid tag on the connection */
		if (connection)
			g_object_set_data (G_OBJECT (connection), INVALID_TAG, NULL);

		update_routing_and_dns (policy, FALSE);
		break;
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_DISCONNECTED:
		update_routing_and_dns (policy, FALSE);
		schedule_activate_check (policy, device);
		break;
	default:
		break;
	}
}

static void
device_ip4_config_changed (NMDevice *device,
                           GParamSpec *pspec,
                           gpointer user_data)
{
	update_routing_and_dns ((NMPolicy *) user_data, TRUE);
}

static void
wireless_networks_changed (NMDeviceWifi *device, NMAccessPoint *ap, gpointer user_data)
{
	schedule_activate_check ((NMPolicy *) user_data, NM_DEVICE (device));
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
	                       G_CALLBACK (device_ip4_config_changed),
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
	GSList *iter = policy->dev_signal_ids;

	/* Clear any signal handlers for this device */
	while (iter) {
		DeviceSignalID *data = (DeviceSignalID *) iter->data;
		GSList *next = g_slist_next (iter);

		if (data->device == device) {
			policy->dev_signal_ids = g_slist_remove_link (policy->dev_signal_ids, iter);
			
			g_signal_handler_disconnect (data->device, data->id);
			g_free (data);
			g_slist_free (iter);
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
		schedule_activate_check (policy, NM_DEVICE (iter->data));
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
			nm_warning ("Connection '%s' disappeared, but error deactivating it: (%d) %s",
			            nm_setting_connection_get_id (s_con), error->code, error->message);
			g_error_free (error);
		}
		g_free (path);
	}
	g_ptr_array_free (list, TRUE);
}

NMPolicy *
nm_policy_new (NMManager *manager, NMVPNManager *vpn_manager)
{
	NMPolicy *policy;
	static gboolean initialized = FALSE;
	gulong id;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (initialized == FALSE, NULL);

	policy = g_malloc0 (sizeof (NMPolicy));
	policy->manager = g_object_ref (manager);
	policy->update_state_id = 0;

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

	id = g_signal_connect (manager, "notify::hostname",
	                       G_CALLBACK (hostname_changed), policy);
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
		lookup_thread_die (policy->lookup);
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

	g_object_unref (policy->manager);
	g_free (policy);
}

