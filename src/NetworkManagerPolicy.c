/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/select.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerAP.h"
#include "nm-activation-request.h"
#include "nm-utils.h"
#include "nm-device-interface.h"
#include "nm-device.h"
#include "nm-device-wifi.h"
#include "nm-device-ethernet.h"
#include "nm-gsm-device.h"
#include "nm-cdma-device.h"
#include "nm-dbus-manager.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-connection.h"
#include "NetworkManagerSystem.h"
#include "nm-named-manager.h"

struct NMPolicy {
	NMManager *manager;
	guint update_state_id;
	GSList *pending_activation_checks;
	GSList *signal_ids;
	GSList *dev_signal_ids;

	NMDevice *default_device;
};

#define INVALID_TAG "invalid"

static const char *
get_connection_id (NMConnection *connection)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	g_return_val_if_fail (s_con != NULL, NULL);

	return s_con->id;
}

static void
update_default_route (NMPolicy *policy, NMDevice *new)
{
	const char *ip_iface;

	/* FIXME: Not sure if the following makes any sense. */
	/* If iface and ip_iface are the same, it's a regular network device and we
	   treat it as such. However, if they differ, it's most likely something like
	   a serial device with ppp interface, so route all the traffic to it. */
	ip_iface = nm_device_get_ip_iface (new);
	if (strcmp (ip_iface, nm_device_get_iface (new))) {
		nm_system_device_replace_default_ip4_route (ip_iface, 0, 0);
	} else {
		NMIP4Config *config;
		const NMSettingIP4Address *def_addr;

		config = nm_device_get_ip4_config (new);
		def_addr = nm_ip4_config_get_address (config, 0);
		nm_system_device_replace_default_ip4_route (ip_iface, def_addr->gateway, nm_ip4_config_get_mss (config));
	}
}

static guint32
get_device_priority (NMDevice *dev)
{
	if (NM_IS_CDMA_DEVICE (dev))
		return 2;

	if (NM_IS_GSM_DEVICE (dev))
		return 3;

	if (NM_IS_DEVICE_WIFI (dev))
		return 4;

	if (NM_IS_DEVICE_ETHERNET (dev))
		return 5;

	return 1;
}

static void
update_routing_and_dns (NMPolicy *policy, gboolean force_update)
{
	NMDevice *best = NULL;
	guint32 best_prio = 0;
	NMActRequest *best_req = NULL;
	GSList *devices, *iter;
	NMNamedManager *named_mgr;
	NMIP4Config *config;

	devices = nm_manager_get_devices (policy->manager);
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *dev = NM_DEVICE (iter->data);
		NMActRequest *req;
		NMConnection *connection;
		NMIP4Config *ip4_config;
		NMSettingIP4Config *s_ip4;
		guint32 prio;
		guint i;
		gboolean have_gateway = FALSE;
		
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
		if (s_ip4 && !strcmp (s_ip4->method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL))
			continue;

		/* Make sure at least one of this device's IP addresses has a gateway */
		for (i = 0; i < nm_ip4_config_get_num_addresses (ip4_config); i++) {
			const NMSettingIP4Address *addr;

			addr = nm_ip4_config_get_address (ip4_config, i);
			if (addr->gateway) {
				have_gateway = TRUE;
				break;
			}
		}

		if (!have_gateway)
			continue;

		prio = get_device_priority (dev);
		if (prio > best_prio) {
			best = dev;
			best_prio = prio;
			best_req = req;
		}
	}

	if (!best)
		goto out;
	if (!force_update && (best == policy->default_device))
		goto out;

	update_default_route (policy, best);
	
	/* Update the default active connection.  Only mark the new default
	 * active connection after setting default = FALSE on all other connections
	 * first.  The order is important, we don't want two connections marked
	 * default at the same time ever.
	 */
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *dev = NM_DEVICE (iter->data);
		NMActRequest *req;

		req = nm_device_get_act_request (dev);
		if (req && (req != best_req))
			nm_act_request_set_default (req, FALSE);
	}

	named_mgr = nm_named_manager_get ();
	config = nm_device_get_ip4_config (best);
	nm_named_manager_add_ip4_config (named_mgr, config, NM_NAMED_IP_CONFIG_TYPE_BEST_DEVICE);
	g_object_unref (named_mgr);

	/* Now set new default active connection _after_ updating DNS info, so that
	 * if the connection is shared dnsmasq picks up the right stuff.
	 */
	if (best_req)
			nm_act_request_set_default (best_req, TRUE);

	nm_info ("Policy set (%s) as default device for routing and DNS.",
	         nm_device_get_iface (best));

out:
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
			            s_con->id, error->code, error->message);
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
global_state_changed (NMManager *manager, NMState state, gpointer user_data)
{
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

static gboolean
do_cmd (const char *fmt, ...)
{
	va_list args;
	char *cmd;
	int ret;

	va_start (args, fmt);
	cmd = g_strdup_vprintf (fmt, args);
	va_end (args);

	nm_info ("Executing: %s", cmd);
	ret = system (cmd);
	g_free (cmd);

	if (ret == -1) {
		nm_info ("** Error executing command.");
		return FALSE;
	} else if (WEXITSTATUS (ret)) {
		nm_info ("** Command returned exit status %d.", WEXITSTATUS (ret));
		return FALSE;
	}

	return TRUE;
}

static void
sharing_init (void)
{
	do_cmd ("echo \"1\" > /proc/sys/net/ipv4/ip_forward");
	do_cmd ("echo \"1\" > /proc/sys/net/ipv4/ip_dynaddr");
	do_cmd ("/sbin/modprobe ip_tables iptable_nat ip_nat_ftp ip_nat_irc");
	do_cmd ("/sbin/iptables -P INPUT ACCEPT");
	do_cmd ("/sbin/iptables -F INPUT");
	do_cmd ("/sbin/iptables -P OUTPUT ACCEPT");
	do_cmd ("/sbin/iptables -F OUTPUT");
	do_cmd ("/sbin/iptables -P FORWARD DROP");
	do_cmd ("/sbin/iptables -F FORWARD");
	do_cmd ("/sbin/iptables -t nat -F");
}

static void
sharing_stop (NMActRequest *req)
{
	do_cmd ("/sbin/iptables -F INPUT");
	do_cmd ("/sbin/iptables -F OUTPUT");
	do_cmd ("/sbin/iptables -P FORWARD DROP");
	do_cmd ("/sbin/iptables -F FORWARD");
	do_cmd ("/sbin/iptables -F -t nat");

	// Delete all User-specified chains
	do_cmd ("/sbin/iptables -X");

	// Reset all IPTABLES counters
	do_cmd ("/sbin/iptables -Z");

	nm_act_request_set_shared (req, FALSE);
}

/* Given a default activation request, start NAT-ing if there are any shared
 * connections.
 */
static void
sharing_restart (NMPolicy *policy, NMActRequest *req)
{
	GSList *devices, *iter;
	const char *extif;
	gboolean have_shared = FALSE;

	if (nm_act_request_get_shared (req))
		sharing_stop (req);

	extif = nm_device_get_ip_iface (NM_DEVICE (nm_act_request_get_device (req)));
	g_assert (extif);

	/* Start NAT-ing every 'shared' connection */
	devices = nm_manager_get_devices (policy->manager);
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = NM_DEVICE (iter->data);
		NMSettingIP4Config *s_ip4;
		NMConnection *connection;
		const char *intif;

		if (nm_device_get_state (candidate) != NM_DEVICE_STATE_ACTIVATED)
			continue;

		connection = get_device_connection (candidate);
		g_assert (connection);

		s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
		if (!s_ip4 || strcmp (s_ip4->method, "shared"))
			continue;

		/* Init sharing if there's a shared connection to NAT */
		if (!have_shared) {
			sharing_init ();
			have_shared = TRUE;
		}

		// FWD: Allow all connections OUT and only existing and related ones IN
		intif = nm_device_get_ip_iface (candidate);
		g_assert (intif);
		do_cmd ("/sbin/iptables -A FORWARD -i %s -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT", extif, intif);
		do_cmd ("/sbin/iptables -A FORWARD -i %s -o %s -j ACCEPT", extif, intif);
		do_cmd ("/sbin/iptables -A FORWARD -i %s -o %s -j ACCEPT", intif, extif);
	}

	if (have_shared) {
		// Enabling SNAT (MASQUERADE) functionality on $EXTIF
		do_cmd ("/sbin/iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", extif);

		nm_act_request_set_shared (req, TRUE);
	}
}

static void
check_sharing (NMPolicy *policy, NMDevice *device, NMConnection *connection)
{
	NMSettingIP4Config *s_ip4;
	GSList *devices, *iter;
	NMActRequest *default_req = NULL;

	if (!connection)
		return;

	/* We only care about 'shared' connections going up or down */
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (!s_ip4 || strcmp (s_ip4->method, "shared"))
		return;

	/* Find the default connection, if any */
	devices = nm_manager_get_devices (policy->manager);
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = NM_DEVICE (iter->data);
		NMActRequest *req = nm_device_get_act_request (candidate);

		if (req && nm_act_request_get_default (req)) {
			default_req = req;
			break;
		}
	}

	/* Restart sharing if there's a default active connection */
	if (default_req)
		sharing_restart (policy, default_req);
}

static void
active_connection_default_changed (NMActRequest *req,
                                   GParamSpec *pspec,
                                   NMPolicy *policy)
{
	gboolean is_default = nm_act_request_get_default (req);

	if (is_default) {
		if (nm_act_request_get_shared (req)) {
			/* Already shared, shouldn't get here */
			nm_warning ("%s: Active connection '%s' already shared.",
			            __func__, nm_act_request_get_active_connection_path (req));
			return;
		}

		sharing_restart (policy, req);
	} else {
		if (!nm_act_request_get_shared (req))
			return;  /* Don't care about non-shared connections */

		/* Tear down all NAT-ing */
		sharing_stop (req);
	}
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
		}
		schedule_activate_check (policy, device);
		check_sharing (policy, device, connection);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		/* Clear the invalid tag on the connection */
		if (connection)
			g_object_set_data (G_OBJECT (connection), INVALID_TAG, NULL);

		g_signal_connect (G_OBJECT (nm_device_get_act_request (device)),
		                  "notify::default",
		                  G_CALLBACK (active_connection_default_changed),
		                  policy);

		update_routing_and_dns (policy, FALSE);
		check_sharing (policy, device, connection);
		break;
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_DISCONNECTED:
		update_routing_and_dns (policy, FALSE);
		schedule_activate_check (policy, device);
		check_sharing (policy, device, connection);
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

		if (!nm_manager_deactivate_connection (manager, path, &error)) {
			nm_warning ("Connection '%s' disappeared, but error deactivating it: (%d) %s",
			            s_con->id, error->code, error->message);
			g_error_free (error);
		}
		g_free (path);
	}
	g_ptr_array_free (list, TRUE);
}

NMPolicy *
nm_policy_new (NMManager *manager)
{
	NMPolicy *policy;
	static gboolean initialized = FALSE;
	gulong id;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (initialized == FALSE, NULL);

	policy = g_malloc0 (sizeof (NMPolicy));
	policy->manager = g_object_ref (manager);
	policy->update_state_id = 0;

	id = g_signal_connect (manager, "state-changed",
	                       G_CALLBACK (global_state_changed), policy);
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

	for (iter = policy->pending_activation_checks; iter; iter = g_slist_next (iter)) {
		ActivateData *data = (ActivateData *) iter->data;

		g_source_remove (data->id);
		g_object_unref (data->device);
		g_free (data);
	}
	g_slist_free (policy->pending_activation_checks);

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

