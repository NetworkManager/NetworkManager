/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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

#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerAP.h"
#include "nm-activation-request.h"
#include "nm-utils.h"
#include "nm-device-interface.h"
#include "nm-device.h"
#include "nm-device-802-11-wireless.h"
#include "nm-device-802-3-ethernet.h"
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
		nm_system_device_replace_default_route (ip_iface, 0, 0);
	} else {
		NMIP4Config *config;

		config = nm_device_get_ip4_config (new);
		nm_system_device_replace_default_route (ip_iface, nm_ip4_config_get_gateway (config),
		                                        nm_ip4_config_get_mss (config));
	}
}

static guint32
get_device_priority (NMDevice *dev)
{
	if (NM_IS_CDMA_DEVICE (dev))
		return 2;

	if (NM_IS_GSM_DEVICE (dev))
		return 3;

	if (NM_IS_DEVICE_802_11_WIRELESS (dev))
		return 4;

	if (NM_IS_DEVICE_802_3_ETHERNET (dev))
		return 5;

	return 1;
}

static void
update_routing_and_dns (NMPolicy *policy, gboolean force_update)
{
	NMDevice *best = NULL;
	guint32 best_prio = 0;
	GSList *devices, *iter;
	NMNamedManager *named_mgr;
	NMIP4Config *config;

	devices = nm_manager_get_devices (policy->manager);
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *dev = NM_DEVICE (iter->data);
		NMActRequest *req;
		NMConnection *connection;
		NMSettingIP4Config *s_ip4;
		guint32 prio;
		
		if (   (nm_device_get_state (dev) != NM_DEVICE_STATE_ACTIVATED)
		    || !nm_device_get_ip4_config (dev))
			continue;

		req = nm_device_get_act_request (dev);
		g_assert (req);
		connection = nm_act_request_get_connection (req);
		g_assert (connection);

		/* Never set the default route through an IPv4LL-addressed device */
		s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
		if (s_ip4 && !strcmp (s_ip4->method, NM_SETTING_IP4_CONFIG_METHOD_AUTOIP))
			continue;

		prio = get_device_priority (dev);
		if (prio > best_prio) {
			best = dev;
			best_prio = prio;
		}
	}

	if (!best)
		goto out;
	if (!force_update && (best == policy->default_device))
		goto out;

	update_default_route (policy, best);

	named_mgr = nm_named_manager_get ();
	config = nm_device_get_ip4_config (best);
	nm_named_manager_add_ip4_config (named_mgr, config, NM_NAMED_IP_CONFIG_TYPE_BEST_DEVICE);
	g_object_unref (named_mgr);

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

		if (!nm_manager_activate_device (policy->manager,
		                                 data->device,
		                                 best_connection,
		                                 specific_object,
		                                 FALSE,
		                                 &error)) {
			nm_warning ("Failed to automatically activate device %s: (%d) %s",
			            nm_device_get_iface (data->device),
			            error->code,
			            error->message);
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
	if (state == NM_STATE_CONNECTED)
		nm_system_restart_mdns_responder ();
}

static void
schedule_activate_check (NMPolicy *policy, NMDevice *device)
{
	ActivateData *data;
	GSList *iter;
	gboolean wireless_enabled;

	if (nm_manager_get_state (policy->manager) == NM_STATE_ASLEEP)
		return;

	// FIXME: kind of a hack, but devices don't have access to the manager
	// object directly
	wireless_enabled = nm_manager_wireless_enabled (policy->manager);
	if (!nm_device_can_activate (device, wireless_enabled))
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
device_state_changed (NMDevice *device, NMDeviceState state, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	NMConnection *connection = get_device_connection (device);

	if ((state == NM_DEVICE_STATE_FAILED) || (state == NM_DEVICE_STATE_CANCELLED)) {
		/* Mark the connection invalid so it doesn't get automatically chosen */
		if (connection) {
			g_object_set_data (G_OBJECT (connection), INVALID_TAG, GUINT_TO_POINTER (TRUE));
			nm_info ("Marking connection '%s' invalid.", get_connection_id (connection));
		}

		if (state == NM_DEVICE_STATE_CANCELLED)
			schedule_activate_check (policy, device);
	} else if (state == NM_DEVICE_STATE_ACTIVATED) {
		/* Clear the invalid tag on the connection */
		if (connection)
			g_object_set_data (G_OBJECT (connection), INVALID_TAG, NULL);

		update_routing_and_dns (policy, FALSE);
	} else if (state == NM_DEVICE_STATE_DISCONNECTED) {
		update_routing_and_dns (policy, FALSE);

		schedule_activate_check (policy, device);
	}
}

static void
device_carrier_changed (NMDevice8023Ethernet *device,
                        GParamSpec *pspec,
                        gpointer user_data)
{
	const char *prop = g_param_spec_get_name (pspec);

	g_return_if_fail (strcmp (prop, NM_DEVICE_802_3_ETHERNET_CARRIER) == 0);

	if (!nm_device_802_3_ethernet_get_carrier (device))
		nm_device_interface_deactivate (NM_DEVICE_INTERFACE (device));
	else
		schedule_activate_check ((NMPolicy *) user_data, NM_DEVICE (device));
}

static void
device_ip4_config_changed (NMDevice *device,
                           GParamSpec *pspec,
                           gpointer user_data)
{
	update_routing_and_dns ((NMPolicy *) user_data, TRUE);
}

static void
wireless_networks_changed (NMDevice80211Wireless *device, NMAccessPoint *ap, gpointer user_data)
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

	if (NM_IS_DEVICE_802_11_WIRELESS (device)) {
		id = g_signal_connect (device, "access-point-added",
		                       G_CALLBACK (wireless_networks_changed),
		                       policy);
		policy->dev_signal_ids = add_device_signal_id (policy->dev_signal_ids, id, device);

		id = g_signal_connect (device, "access-point-removed",
		                       G_CALLBACK (wireless_networks_changed),
		                       policy);
		policy->dev_signal_ids = add_device_signal_id (policy->dev_signal_ids, id, device);
	}

	if (NM_IS_DEVICE_802_3_ETHERNET (device)) {
		id = g_signal_connect (device, "notify::" NM_DEVICE_802_3_ETHERNET_CARRIER,
		                       G_CALLBACK (device_carrier_changed),
		                       policy);
		policy->dev_signal_ids = add_device_signal_id (policy->dev_signal_ids, id, device);
	}

	schedule_activate_check (policy, device);
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
	GSList *iter;

	/* If the connection just removed was active, deactive it */
	for (iter = nm_manager_get_devices (manager); iter; iter = g_slist_next (iter)) {
		NMDevice *device = NM_DEVICE (iter->data);
		NMActRequest *req = nm_device_get_act_request (device);
		NMConnection *dev_connection;

		if (!req)
			continue;

		dev_connection = nm_act_request_get_connection (req);
		if (dev_connection == connection) {
			nm_device_interface_deactivate (NM_DEVICE_INTERFACE (device));
			schedule_activate_check ((NMPolicy *) user_data, device);
		}
	}
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

