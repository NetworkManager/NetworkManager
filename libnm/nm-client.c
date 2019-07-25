/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-client.h"

#include <libudev.h>

#include "nm-utils.h"
#include "nm-manager.h"
#include "nm-dns-manager.h"
#include "nm-remote-settings.h"
#include "nm-device-ethernet.h"
#include "nm-device-wifi.h"
#include "nm-core-internal.h"
#include "nm-active-connection.h"
#include "nm-vpn-connection.h"
#include "nm-remote-connection.h"
#include "nm-dbus-helpers.h"
#include "nm-wimax-nsp.h"
#include "nm-object-private.h"

#include "introspection/org.freedesktop.NetworkManager.h"
#include "introspection/org.freedesktop.NetworkManager.Device.Wireless.h"
#include "introspection/org.freedesktop.NetworkManager.Device.WifiP2P.h"
#include "introspection/org.freedesktop.NetworkManager.Device.h"
#include "introspection/org.freedesktop.NetworkManager.DnsManager.h"
#include "introspection/org.freedesktop.NetworkManager.Settings.h"
#include "introspection/org.freedesktop.NetworkManager.Settings.Connection.h"
#include "introspection/org.freedesktop.NetworkManager.VPN.Connection.h"
#include "introspection/org.freedesktop.NetworkManager.Connection.Active.h"

#include "nm-access-point.h"
#include "nm-active-connection.h"
#include "nm-checkpoint.h"
#include "nm-device-6lowpan.h"
#include "nm-device-adsl.h"
#include "nm-device-bond.h"
#include "nm-device-bridge.h"
#include "nm-device-bt.h"
#include "nm-device-dummy.h"
#include "nm-device-ethernet.h"
#include "nm-device-generic.h"
#include "nm-device-infiniband.h"
#include "nm-device-ip-tunnel.h"
#include "nm-device-macsec.h"
#include "nm-device-macvlan.h"
#include "nm-device-modem.h"
#include "nm-device-olpc-mesh.h"
#include "nm-device-ovs-bridge.h"
#include "nm-device-ovs-interface.h"
#include "nm-device-ovs-port.h"
#include "nm-device-ppp.h"
#include "nm-device-team.h"
#include "nm-device-tun.h"
#include "nm-device-vlan.h"
#include "nm-device-vxlan.h"
#include "nm-device-wifi-p2p.h"
#include "nm-device-wifi.h"
#include "nm-device-wimax.h"
#include "nm-device-wireguard.h"
#include "nm-device-wpan.h"
#include "nm-dhcp-config.h"
#include "nm-dhcp4-config.h"
#include "nm-dhcp6-config.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-manager.h"
#include "nm-wifi-p2p-peer.h"
#include "nm-remote-connection.h"
#include "nm-remote-settings.h"
#include "nm-vpn-connection.h"

void _nm_device_wifi_set_wireless_enabled (NMDeviceWifi *device, gboolean enabled);

static void nm_client_initable_iface_init (GInitableIface *iface);
static void nm_client_async_initable_iface_init (GAsyncInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (NMClient, nm_client, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_client_initable_iface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_client_async_initable_iface_init);
                         )

#define NM_CLIENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CLIENT, NMClientPrivate))

typedef struct {
	NMClient *client;
	GCancellable *cancellable;
	GSimpleAsyncResult *result;
	int pending_init;
} NMClientInitData;

typedef struct {
	NMManager *manager;
	NMRemoteSettings *settings;
	NMDnsManager *dns_manager;
	GDBusObjectManager *object_manager;
	GCancellable *new_object_manager_cancellable;
	struct udev *udev;
	bool udev_inited:1;
} NMClientPrivate;

enum {
	PROP_0,
	PROP_VERSION,
	PROP_STATE,
	PROP_STARTUP,
	PROP_NM_RUNNING,
	PROP_NETWORKING_ENABLED,
	PROP_WIRELESS_ENABLED,
	PROP_WIRELESS_HARDWARE_ENABLED,
	PROP_WWAN_ENABLED,
	PROP_WWAN_HARDWARE_ENABLED,
	PROP_WIMAX_ENABLED,
	PROP_WIMAX_HARDWARE_ENABLED,
	PROP_ACTIVE_CONNECTIONS,
	PROP_CONNECTIVITY,
	PROP_CONNECTIVITY_CHECK_AVAILABLE,
	PROP_CONNECTIVITY_CHECK_ENABLED,
	PROP_PRIMARY_CONNECTION,
	PROP_ACTIVATING_CONNECTION,
	PROP_DEVICES,
	PROP_ALL_DEVICES,
	PROP_CONNECTIONS,
	PROP_HOSTNAME,
	PROP_CAN_MODIFY,
	PROP_METERED,
	PROP_DNS_MODE,
	PROP_DNS_RC_MANAGER,
	PROP_DNS_CONFIGURATION,
	PROP_CHECKPOINTS,

	LAST_PROP
};

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	ANY_DEVICE_ADDED,
	ANY_DEVICE_REMOVED,
	PERMISSION_CHANGED,
	CONNECTION_ADDED,
	CONNECTION_REMOVED,
	ACTIVE_CONNECTION_ADDED,
	ACTIVE_CONNECTION_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static const GPtrArray empty = { 0, };

/*****************************************************************************/

/**
 * nm_client_error_quark:
 *
 * Registers an error quark for #NMClient if necessary.
 *
 * Returns: the error quark used for #NMClient errors.
 **/
NM_CACHED_QUARK_FCN ("nm-client-error-quark", nm_client_error_quark)

/*****************************************************************************/

static void
nm_client_init (NMClient *client)
{
}

static gboolean
_nm_client_check_nm_running (NMClient *client, GError **error)
{
	if (nm_client_get_nm_running (client))
		return TRUE;
	else {
		g_set_error_literal (error,
		                     NM_CLIENT_ERROR,
		                     NM_CLIENT_ERROR_MANAGER_NOT_RUNNING,
		                     "NetworkManager is not running");
		return FALSE;
	}
}

/**
 * nm_client_get_version:
 * @client: a #NMClient
 *
 * Gets NetworkManager version.
 *
 * Returns: string with the version (or %NULL if NetworkManager is not running)
 **/
const char *
nm_client_get_version (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	if (!nm_client_get_nm_running (client))
		return NULL;

	return nm_manager_get_version (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_get_state:
 * @client: a #NMClient
 *
 * Gets the current daemon state.
 *
 * Returns: the current %NMState
 **/
NMState
nm_client_get_state (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NM_STATE_UNKNOWN);

	if (!nm_client_get_nm_running (client))
		return NM_STATE_UNKNOWN;

	return nm_manager_get_state (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_get_startup:
 * @client: a #NMClient
 *
 * Tests whether the daemon is still in the process of activating
 * connections at startup.
 *
 * Returns: whether the daemon is still starting up
 **/
gboolean
nm_client_get_startup (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	if (!nm_client_get_nm_running (client))
		return FALSE;

	return nm_manager_get_startup (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_get_nm_running:
 * @client: a #NMClient
 *
 * Determines whether the daemon is running.
 *
 * Returns: %TRUE if the daemon is running
 **/
gboolean
nm_client_get_nm_running (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->manager != NULL;
}

/**
 * nm_client_networking_get_enabled:
 * @client: a #NMClient
 *
 * Whether networking is enabled or disabled.
 *
 * Returns: %TRUE if networking is enabled, %FALSE if networking is disabled
 **/
gboolean
nm_client_networking_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	if (!nm_client_get_nm_running (client))
		return FALSE;

	return nm_manager_networking_get_enabled (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_networking_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to set networking enabled, %FALSE to set networking disabled
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Enables or disables networking.  When networking is disabled, all controlled
 * interfaces are disconnected and deactivated.  When networking is enabled,
 * all controlled interfaces are available for activation.
 *
 * Returns: %TRUE on success, %FALSE otherwise
 **/
gboolean
nm_client_networking_set_enabled (NMClient *client, gboolean enable, GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	if (!_nm_client_check_nm_running (client, error))
		return FALSE;

	return nm_manager_networking_set_enabled (NM_CLIENT_GET_PRIVATE (client)->manager,
	                                          enable, error);
}

/**
 * nm_client_wireless_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether the wireless is enabled.
 *
 * Returns: %TRUE if wireless is enabled
 **/
gboolean
nm_client_wireless_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	if (!nm_client_get_nm_running (client))
		return FALSE;

	return nm_manager_wireless_get_enabled (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_wireless_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to enable wireless
 *
 * Enables or disables wireless devices.
 **/
void
nm_client_wireless_set_enabled (NMClient *client, gboolean enabled)
{
	g_return_if_fail (NM_IS_CLIENT (client));

	if (!nm_client_get_nm_running (client))
		return;

	nm_manager_wireless_set_enabled (NM_CLIENT_GET_PRIVATE (client)->manager, enabled);
}

/**
 * nm_client_wireless_hardware_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether the wireless hardware is enabled.
 *
 * Returns: %TRUE if the wireless hardware is enabled
 **/
gboolean
nm_client_wireless_hardware_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	if (!nm_client_get_nm_running (client))
		return FALSE;

	return nm_manager_wireless_hardware_get_enabled (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_wwan_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether WWAN is enabled.
 *
 * Returns: %TRUE if WWAN is enabled
 **/
gboolean
nm_client_wwan_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	if (!nm_client_get_nm_running (client))
		return FALSE;

	return nm_manager_wwan_get_enabled (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_wwan_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to enable WWAN
 *
 * Enables or disables WWAN devices.
 **/
void
nm_client_wwan_set_enabled (NMClient *client, gboolean enabled)
{
	g_return_if_fail (NM_IS_CLIENT (client));

	if (!_nm_client_check_nm_running (client, NULL))
		return;

	nm_manager_wwan_set_enabled (NM_CLIENT_GET_PRIVATE (client)->manager, enabled);
}

/**
 * nm_client_wwan_hardware_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether the WWAN hardware is enabled.
 *
 * Returns: %TRUE if the WWAN hardware is enabled
 **/
gboolean
nm_client_wwan_hardware_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	if (!nm_client_get_nm_running (client))
		return FALSE;

	return nm_manager_wwan_hardware_get_enabled (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_wimax_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether WiMAX is enabled.
 *
 * Returns: %TRUE if WiMAX is enabled
 **/
gboolean
nm_client_wimax_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	if (!nm_client_get_nm_running (client))
		return FALSE;

	return nm_manager_wimax_get_enabled (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_wimax_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to enable WiMAX
 *
 * Enables or disables WiMAX devices.
 **/
void
nm_client_wimax_set_enabled (NMClient *client, gboolean enabled)
{
	g_return_if_fail (NM_IS_CLIENT (client));

	if (!nm_client_get_nm_running (client))
		return;

	nm_manager_wimax_set_enabled (NM_CLIENT_GET_PRIVATE (client)->manager, enabled);
}

/**
 * nm_client_wimax_hardware_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether the WiMAX hardware is enabled.
 *
 * Returns: %TRUE if the WiMAX hardware is enabled
 **/
gboolean
nm_client_wimax_hardware_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	if (!nm_client_get_nm_running (client))
		return FALSE;

	return nm_manager_wimax_hardware_get_enabled (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_connectivity_check_get_available:
 * @client: a #NMClient
 *
 * Determine whether connectivity checking is available.  This
 * requires that the URI of a connectivity service has been set in the
 * configuration file.
 *
 * Returns: %TRUE if connectivity checking is available.
 *
 * Since: 1.10
 */
gboolean
nm_client_connectivity_check_get_available (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	if (!nm_client_get_nm_running (client))
		return FALSE;

	return nm_manager_connectivity_check_get_available (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_connectivity_check_get_enabled:
 * @client: a #NMClient
 *
 * Determine whether connectivity checking is enabled.
 *
 * Returns: %TRUE if connectivity checking is enabled.
 *
 * Since: 1.10
 */
gboolean
nm_client_connectivity_check_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	if (!nm_client_get_nm_running (client))
		return FALSE;

	return nm_manager_connectivity_check_get_enabled (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_connectivity_check_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to enable connectivity checking
 *
 * Enable or disable connectivity checking.  Note that if a
 * connectivity checking URI has not been configured, this will not
 * have any effect.
 *
 * Since: 1.10
 */
void
nm_client_connectivity_check_set_enabled (NMClient *client, gboolean enabled)
{
	g_return_if_fail (NM_IS_CLIENT (client));

	if (!nm_client_get_nm_running (client))
		return;

	nm_manager_connectivity_check_set_enabled (NM_CLIENT_GET_PRIVATE (client)->manager, enabled);
}

/**
 * nm_client_connectivity_check_get_uri:
 * @client: a #NMClient
 *
 * Get the URI that will be queried to determine if there is internet
 * connectivity.
 *
 * Returns: (transfer none): the connectivity URI in use
 *
 * Since: 1.20
 */
const char *
nm_client_connectivity_check_get_uri (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	if (!nm_client_get_nm_running (client))
		return NULL;

	return nm_manager_connectivity_check_get_uri (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_get_logging:
 * @client: a #NMClient
 * @level: (allow-none): return location for logging level string
 * @domains: (allow-none): return location for log domains string. The string is
 *   a list of domains separated by ","
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Gets NetworkManager current logging level and domains.
 *
 * Returns: %TRUE on success, %FALSE otherwise
 **/
gboolean
nm_client_get_logging (NMClient *client, char **level, char **domains, GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (level == NULL || *level == NULL, FALSE);
	g_return_val_if_fail (domains == NULL || *domains == NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!_nm_client_check_nm_running (client, error))
		return FALSE;

	return nm_manager_get_logging (NM_CLIENT_GET_PRIVATE (client)->manager,
	                               level, domains, error);
}

/**
 * nm_client_set_logging:
 * @client: a #NMClient
 * @level: (allow-none): logging level to set (%NULL or an empty string for no change)
 * @domains: (allow-none): logging domains to set. The string should be a list of log
 *   domains separated by ",". (%NULL or an empty string for no change)
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Sets NetworkManager logging level and/or domains.
 *
 * Returns: %TRUE on success, %FALSE otherwise
 **/
gboolean
nm_client_set_logging (NMClient *client, const char *level, const char *domains, GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!_nm_client_check_nm_running (client, error))
		return FALSE;

	return nm_manager_set_logging (NM_CLIENT_GET_PRIVATE (client)->manager,
	                               level, domains, error);
}

/**
 * nm_client_get_permission_result:
 * @client: a #NMClient
 * @permission: the permission for which to return the result, one of #NMClientPermission
 *
 * Requests the result of a specific permission, which indicates whether the
 * client can or cannot perform the action the permission represents
 *
 * Returns: the permission's result, one of #NMClientPermissionResult
 **/
NMClientPermissionResult
nm_client_get_permission_result (NMClient *client, NMClientPermission permission)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NM_CLIENT_PERMISSION_RESULT_UNKNOWN);

	if (!nm_client_get_nm_running (client))
		return NM_CLIENT_PERMISSION_RESULT_UNKNOWN;

	return nm_manager_get_permission_result (NM_CLIENT_GET_PRIVATE (client)->manager, permission);
}

/**
 * nm_client_get_connectivity:
 * @client: an #NMClient
 *
 * Gets the current network connectivity state. Contrast
 * nm_client_check_connectivity() and
 * nm_client_check_connectivity_async(), which re-check the
 * connectivity state first before returning any information.
 *
 * Returns: the current connectivity state
 */
NMConnectivityState
nm_client_get_connectivity (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NM_CONNECTIVITY_UNKNOWN);

	if (!nm_client_get_nm_running (client))
		return NM_CONNECTIVITY_UNKNOWN;

	return nm_manager_get_connectivity (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_check_connectivity:
 * @client: an #NMClient
 * @cancellable: a #GCancellable
 * @error: return location for a #GError
 *
 * Updates the network connectivity state and returns the (new)
 * current state. Contrast nm_client_get_connectivity(), which returns
 * the most recent known state without re-checking.
 *
 * This is a blocking call; use nm_client_check_connectivity_async()
 * if you do not want to block.
 *
 * Returns: the (new) current connectivity state
 */
NMConnectivityState
nm_client_check_connectivity (NMClient *client,
                              GCancellable *cancellable,
                              GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NM_CONNECTIVITY_UNKNOWN);

	if (!_nm_client_check_nm_running (client, error))
		return NM_CONNECTIVITY_UNKNOWN;

	return nm_manager_check_connectivity (NM_CLIENT_GET_PRIVATE (client)->manager,
	                                      cancellable, error);
}

static void
check_connectivity_cb (GObject *object,
                       GAsyncResult *result,
                       gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	NMConnectivityState connectivity;
	GError *error = NULL;

	connectivity = nm_manager_check_connectivity_finish (NM_MANAGER (object),
	                                                     result, &error);
	if (!error)
		g_simple_async_result_set_op_res_gssize (simple, connectivity);
	else
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

/**
 * nm_client_check_connectivity_async:
 * @client: an #NMClient
 * @cancellable: a #GCancellable
 * @callback: callback to call with the result
 * @user_data: data for @callback.
 *
 * Asynchronously updates the network connectivity state and invokes
 * @callback when complete. Contrast nm_client_get_connectivity(),
 * which (immediately) returns the most recent known state without
 * re-checking, and nm_client_check_connectivity(), which blocks.
 */
void
nm_client_check_connectivity_async (NMClient *client,
                                    GCancellable *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));

	if (!_nm_client_check_nm_running (client, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (client), callback, user_data, error);
		return;
	}

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_check_connectivity_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nm_manager_check_connectivity_async (NM_CLIENT_GET_PRIVATE (client)->manager,
	                                     cancellable, check_connectivity_cb, simple);
}

/**
 * nm_client_check_connectivity_finish:
 * @client: an #NMClient
 * @result: the #GAsyncResult
 * @error: return location for a #GError
 *
 * Retrieves the result of an nm_client_check_connectivity_async()
 * call.
 *
 * Returns: the (new) current connectivity state
 */
NMConnectivityState
nm_client_check_connectivity_finish (NMClient *client,
                                     GAsyncResult *result,
                                     GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (NM_IS_CLIENT (client), NM_CONNECTIVITY_UNKNOWN);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), NM_CONNECTIVITY_UNKNOWN);

	simple = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (simple, error))
		return NM_CONNECTIVITY_UNKNOWN;
	return (NMConnectivityState) g_simple_async_result_get_op_res_gssize (simple);
}

/**
 * nm_client_save_hostname:
 * @client: the %NMClient
 * @hostname: (allow-none): the new persistent hostname to set, or %NULL to
 *   clear any existing persistent hostname
 * @cancellable: a #GCancellable, or %NULL
 * @error: return location for #GError
 *
 * Requests that the machine's persistent hostname be set to the specified value
 * or cleared.
 *
 * Returns: %TRUE if the request was successful, %FALSE if it failed
 **/
gboolean
nm_client_save_hostname (NMClient *client,
                         const char *hostname,
                         GCancellable *cancellable,
                         GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	if (!_nm_client_check_nm_running (client, error))
		return FALSE;

	return nm_remote_settings_save_hostname (NM_CLIENT_GET_PRIVATE (client)->settings,
	                                         hostname, cancellable, error);
}

static void
save_hostname_cb (GObject *object,
                  GAsyncResult *result,
                  gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nm_remote_settings_save_hostname_finish (NM_REMOTE_SETTINGS (object), result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

/**
 * nm_client_save_hostname_async:
 * @client: the %NMClient
 * @hostname: (allow-none): the new persistent hostname to set, or %NULL to
 *   clear any existing persistent hostname
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Requests that the machine's persistent hostname be set to the specified value
 * or cleared.
 **/
void
nm_client_save_hostname_async (NMClient *client,
                               const char *hostname,
                               GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));

	if (!_nm_client_check_nm_running (client, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (client), callback, user_data, error);
		return;
	}

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_save_hostname_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nm_remote_settings_save_hostname_async (NM_CLIENT_GET_PRIVATE (client)->settings,
	                                        hostname,
	                                        cancellable, save_hostname_cb, simple);
}

/**
 * nm_client_save_hostname_finish:
 * @client: the %NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: return location for #GError
 *
 * Gets the result of an nm_client_save_hostname_async() call.
 *
 * Returns: %TRUE if the request was successful, %FALSE if it failed
 **/
gboolean
nm_client_save_hostname_finish (NMClient *client,
                                GAsyncResult *result,
                                GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
}

/*****************************************************************************/
/* Devices                                                      */
/*****************************************************************************/

/**
 * nm_client_get_devices:
 * @client: a #NMClient
 *
 * Gets all the known network devices.  Use nm_device_get_type() or the
 * <literal>NM_IS_DEVICE_XXXX</literal> functions to determine what kind of
 * device member of the returned array is, and then you may use device-specific
 * methods such as nm_device_ethernet_get_hw_address().
 *
 * Returns: (transfer none) (element-type NMDevice): a #GPtrArray
 * containing all the #NMDevices.  The returned array is owned by the
 * #NMClient object and should not be modified.
 **/
const GPtrArray *
nm_client_get_devices (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	if (!nm_client_get_nm_running (client))
		return &empty;

	return nm_manager_get_devices (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_get_all_devices:
 * @client: a #NMClient
 *
 * Gets both real devices and device placeholders (eg, software devices which
 * do not currently exist, but could be created automatically by NetworkManager
 * if one of their NMDevice::ActivatableConnections was activated).  Use
 * nm_device_is_real() to determine whether each device is a real device or
 * a placeholder.
 *
 * Use nm_device_get_type() or the NM_IS_DEVICE_XXXX() functions to determine
 * what kind of device each member of the returned array is, and then you may
 * use device-specific methods such as nm_device_ethernet_get_hw_address().
 *
 * Returns: (transfer none) (element-type NMDevice): a #GPtrArray
 * containing all the #NMDevices.  The returned array is owned by the
 * #NMClient object and should not be modified.
 *
 * Since: 1.2
 **/
const GPtrArray *
nm_client_get_all_devices (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	if (!nm_client_get_nm_running (client))
		return &empty;

	return nm_manager_get_all_devices (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_get_device_by_path:
 * @client: a #NMClient
 * @object_path: the object path to search for
 *
 * Gets a #NMDevice from a #NMClient.
 *
 * Returns: (transfer none): the #NMDevice for the given @object_path or %NULL if none is found.
 **/
NMDevice *
nm_client_get_device_by_path (NMClient *client, const char *object_path)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (object_path, NULL);

	if (!nm_client_get_nm_running (client))
		return NULL;

	return nm_manager_get_device_by_path (NM_CLIENT_GET_PRIVATE (client)->manager, object_path);
}

/**
 * nm_client_get_device_by_iface:
 * @client: a #NMClient
 * @iface: the interface name to search for
 *
 * Gets a #NMDevice from a #NMClient.
 *
 * Returns: (transfer none): the #NMDevice for the given @iface or %NULL if none is found.
 **/
NMDevice *
nm_client_get_device_by_iface (NMClient *client, const char *iface)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (iface, NULL);

	if (!nm_client_get_nm_running (client))
		return NULL;

	return nm_manager_get_device_by_iface (NM_CLIENT_GET_PRIVATE (client)->manager, iface);
}

/*****************************************************************************/
/* Active Connections                                           */
/*****************************************************************************/

/**
 * nm_client_get_active_connections:
 * @client: a #NMClient
 *
 * Gets the active connections.
 *
 * Returns: (transfer none) (element-type NMActiveConnection): a #GPtrArray
 *  containing all the active #NMActiveConnections.
 * The returned array is owned by the client and should not be modified.
 **/
const GPtrArray *
nm_client_get_active_connections (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	if (!nm_client_get_nm_running (client))
		return &empty;

	return nm_manager_get_active_connections (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_get_primary_connection:
 * @client: an #NMClient
 *
 * Gets the #NMActiveConnection corresponding to the primary active
 * network device.
 *
 * In particular, when there is no VPN active, or the VPN does not
 * have the default route, this returns the active connection that has
 * the default route. If there is a VPN active with the default route,
 * then this function returns the active connection that contains the
 * route to the VPN endpoint.
 *
 * If there is no default route, or the default route is over a
 * non-NetworkManager-recognized device, this will return %NULL.
 *
 * Returns: (transfer none): the appropriate #NMActiveConnection, if
 * any
 */
NMActiveConnection *
nm_client_get_primary_connection (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	if (!nm_client_get_nm_running (client))
		return NULL;

	return nm_manager_get_primary_connection (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_get_activating_connection:
 * @client: an #NMClient
 *
 * Gets the #NMActiveConnection corresponding to a
 * currently-activating connection that is expected to become the new
 * #NMClient:primary-connection upon successful activation.
 *
 * Returns: (transfer none): the appropriate #NMActiveConnection, if
 * any.
 */
NMActiveConnection *
nm_client_get_activating_connection (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	if (!nm_client_get_nm_running (client))
		return NULL;

	return nm_manager_get_activating_connection (NM_CLIENT_GET_PRIVATE (client)->manager);
}

static void
activate_cb (GObject *object,
             GAsyncResult *result,
             gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	NMActiveConnection *ac;
	GError *error = NULL;

	ac = nm_manager_activate_connection_finish (NM_MANAGER (object), result, &error);
	if (ac)
		g_simple_async_result_set_op_res_gpointer (simple, ac, g_object_unref);
	else
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

/**
 * nm_client_activate_connection_async:
 * @client: a #NMClient
 * @connection: (allow-none): an #NMConnection
 * @device: (allow-none): the #NMDevice
 * @specific_object: (allow-none): the object path of a connection-type-specific
 *   object this activation should use. This parameter is currently ignored for
 *   wired and mobile broadband connections, and the value of %NULL should be used
 *   (ie, no specific object).  For Wi-Fi or WiMAX connections, pass the object
 *   path of a #NMAccessPoint or #NMWimaxNsp owned by @device, which you can
 *   get using nm_object_get_path(), and which will be used to complete the
 *   details of the newly added connection.
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the activation has started
 * @user_data: caller-specific data passed to @callback
 *
 * Asynchronously starts a connection to a particular network using the
 * configuration settings from @connection and the network device @device.
 * Certain connection types also take a "specific object" which is the object
 * path of a connection- specific object, like an #NMAccessPoint for Wi-Fi
 * connections, or an #NMWimaxNsp for WiMAX connections, to which you wish to
 * connect.  If the specific object is not given, NetworkManager can, in some
 * cases, automatically determine which network to connect to given the settings
 * in @connection.
 *
 * If @connection is not given for a device-based activation, NetworkManager
 * picks the best available connection for the device and activates it.
 *
 * Note that the callback is invoked when NetworkManager has started activating
 * the new connection, not when it finishes. You can use the returned
 * #NMActiveConnection object (in particular, #NMActiveConnection:state) to
 * track the activation to its completion.
 **/
void
nm_client_activate_connection_async (NMClient *client,
                                     NMConnection *connection,
                                     NMDevice *device,
                                     const char *specific_object,
                                     GCancellable *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data)
{
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));
	if (device)
		g_return_if_fail (NM_IS_DEVICE (device));
	if (connection)
		g_return_if_fail (NM_IS_CONNECTION (connection));

	if (!_nm_client_check_nm_running (client, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (client), callback, user_data, error);
		return;
	}

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_activate_connection_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nm_manager_activate_connection_async (NM_CLIENT_GET_PRIVATE (client)->manager,
	                                      connection, device, specific_object,
	                                      cancellable, activate_cb, simple);
}

/**
 * nm_client_activate_connection_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_activate_connection_async().
 *
 * Returns: (transfer full): the new #NMActiveConnection on success, %NULL on
 *   failure, in which case @error will be set.
 **/
NMActiveConnection *
nm_client_activate_connection_finish (NMClient *client,
                                      GAsyncResult *result,
                                      GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));
}

static void
add_activate_cb (GObject *object,
                 GAsyncResult *result,
                 gpointer user_data)
{
	gs_unref_object GSimpleAsyncResult *simple = user_data;
	gs_unref_variant GVariant *result_data = NULL;
	gs_unref_object NMActiveConnection *ac = NULL;
	GError *error = NULL;

	ac = nm_manager_add_and_activate_connection_finish (NM_MANAGER (object), result, &result_data, &error);
	if (ac) {
		g_simple_async_result_set_op_res_gpointer (simple,
		                                           _nm_activate_result_new (ac, result_data),
		                                           (GDestroyNotify) _nm_activate_result_free);
	} else
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
}

/**
 * nm_client_add_and_activate_connection_async:
 * @client: a #NMClient
 * @partial: (allow-none): an #NMConnection to add; the connection may be
 *   partially filled (or even %NULL) and will be completed by NetworkManager
 *   using the given @device and @specific_object before being added
 * @device: the #NMDevice
 * @specific_object: (allow-none): the object path of a connection-type-specific
 *   object this activation should use. This parameter is currently ignored for
 *   wired and mobile broadband connections, and the value of %NULL should be used
 *   (ie, no specific object).  For Wi-Fi or WiMAX connections, pass the object
 *   path of a #NMAccessPoint or #NMWimaxNsp owned by @device, which you can
 *   get using nm_object_get_path(), and which will be used to complete the
 *   details of the newly added connection.
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the activation has started
 * @user_data: caller-specific data passed to @callback
 *
 * Adds a new connection using the given details (if any) as a template,
 * automatically filling in missing settings with the capabilities of the given
 * device and specific object.  The new connection is then asynchronously
 * activated as with nm_client_activate_connection_async(). Cannot be used for
 * VPN connections at this time.
 *
 * Note that the callback is invoked when NetworkManager has started activating
 * the new connection, not when it finishes. You can used the returned
 * #NMActiveConnection object (in particular, #NMActiveConnection:state) to
 * track the activation to its completion.
 **/
void
nm_client_add_and_activate_connection_async (NMClient *client,
                                             NMConnection *partial,
                                             NMDevice *device,
                                             const char *specific_object,
                                             GCancellable *cancellable,
                                             GAsyncReadyCallback callback,
                                             gpointer user_data)
{
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (NM_IS_DEVICE (device));
	if (partial)
		g_return_if_fail (NM_IS_CONNECTION (partial));

	if (!_nm_client_check_nm_running (client, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (client), callback, user_data, error);
		return;
	}

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_add_and_activate_connection_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nm_manager_add_and_activate_connection_async (NM_CLIENT_GET_PRIVATE (client)->manager,
	                                              partial,
	                                              device,
	                                              specific_object,
	                                              NULL,
	                                              FALSE,
	                                              cancellable,
	                                              add_activate_cb,
	                                              simple);
}

/**
 * nm_client_add_and_activate_connection_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_add_and_activate_connection_async().
 *
 * You can call nm_active_connection_get_connection() on the returned
 * #NMActiveConnection to find the path of the created #NMConnection.
 *
 * Returns: (transfer full): the new #NMActiveConnection on success, %NULL on
 *   failure, in which case @error will be set.
 **/
NMActiveConnection *
nm_client_add_and_activate_connection_finish (NMClient *client,
                                              GAsyncResult *result,
                                              GError **error)
{
	GSimpleAsyncResult *simple;
	_NMActivateResult *r;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	r = g_simple_async_result_get_op_res_gpointer (simple);
	return g_object_ref (r->active);
}

/**
 * nm_client_add_and_activate_connection2:
 * @client: a #NMClient
 * @partial: (allow-none): an #NMConnection to add; the connection may be
 *   partially filled (or even %NULL) and will be completed by NetworkManager
 *   using the given @device and @specific_object before being added
 * @device: the #NMDevice
 * @specific_object: (allow-none): the object path of a connection-type-specific
 *   object this activation should use. This parameter is currently ignored for
 *   wired and mobile broadband connections, and the value of %NULL should be used
 *   (ie, no specific object).  For Wi-Fi or WiMAX connections, pass the object
 *   path of a #NMAccessPoint or #NMWimaxNsp owned by @device, which you can
 *   get using nm_object_get_path(), and which will be used to complete the
 *   details of the newly added connection.
 * @options: a #GVariant containing a dictionary with options, or %NULL
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the activation has started
 * @user_data: caller-specific data passed to @callback
 *
 * Adds a new connection using the given details (if any) as a template,
 * automatically filling in missing settings with the capabilities of the given
 * device and specific object.  The new connection is then asynchronously
 * activated as with nm_client_activate_connection_async(). Cannot be used for
 * VPN connections at this time.
 *
 * Note that the callback is invoked when NetworkManager has started activating
 * the new connection, not when it finishes. You can used the returned
 * #NMActiveConnection object (in particular, #NMActiveConnection:state) to
 * track the activation to its completion.
 *
 * This is identitcal to nm_client_add_and_activate_connection_async() but takes
 * a further @options parameter. Currently the following options are supported
 * by the daemon:
 *  * "persist": A string describing how the connection should be stored.
 *               The default is "disk", but it can be modified to "memory" (until
 *               the daemon quits) or "volatile" (will be deleted on disconnect).
 *  * "bind-activation": Bind the connection lifetime to something. The default is "none",
 *            meaning an explicit disconnect is needed. The value "dbus-client"
 *            means the connection will automatically be deactivated when the calling
 *            DBus client disappears from the system bus.
 *
 * Since: 1.16
 **/
void
nm_client_add_and_activate_connection2 (NMClient *client,
                                        NMConnection *partial,
                                        NMDevice *device,
                                        const char *specific_object,
                                        GVariant *options,
                                        GCancellable *cancellable,
                                        GAsyncReadyCallback callback,
                                        gpointer user_data)
{
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (NM_IS_DEVICE (device));
	if (partial)
		g_return_if_fail (NM_IS_CONNECTION (partial));

	if (!_nm_client_check_nm_running (client, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (client), callback, user_data, error);
		return;
	}

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_add_and_activate_connection2);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nm_manager_add_and_activate_connection_async (NM_CLIENT_GET_PRIVATE (client)->manager,
	                                              partial,
	                                              device,
	                                              specific_object,
	                                              options,
	                                              TRUE,
	                                              cancellable,
	                                              add_activate_cb,
	                                              simple);
}

/**
 * nm_client_add_and_activate_connection2_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 * @out_result: (allow-none) (transfer full): the output result
 *   of type "a{sv}" returned by D-Bus' AddAndActivate2 call. Currently no
 *   output is implemented yet.
 *
 * Gets the result of a call to nm_client_add_and_activate_connection2().
 *
 * You can call nm_active_connection_get_connection() on the returned
 * #NMActiveConnection to find the path of the created #NMConnection.
 *
 * Returns: (transfer full): the new #NMActiveConnection on success, %NULL on
 *   failure, in which case @error will be set.
 **/
NMActiveConnection *
nm_client_add_and_activate_connection2_finish (NMClient *client,
                                               GAsyncResult *result,
                                               GVariant **out_result,
                                               GError **error)
{
	GSimpleAsyncResult *simple;
	_NMActivateResult *r;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error)) {
		NM_SET_OUT (out_result, NULL);
		return NULL;
	}
	r = g_simple_async_result_get_op_res_gpointer (simple);
	NM_SET_OUT (out_result, nm_g_variant_ref (r->add_and_activate_output));
	return g_object_ref (r->active);
}

/**
 * nm_client_deactivate_connection:
 * @client: a #NMClient
 * @active: the #NMActiveConnection to deactivate
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Deactivates an active #NMActiveConnection.
 *
 * Returns: success or failure
 **/
gboolean
nm_client_deactivate_connection (NMClient *client,
                                 NMActiveConnection *active,
                                 GCancellable *cancellable,
                                 GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (active), FALSE);

	if (!nm_client_get_nm_running (client))
		return TRUE;

	return nm_manager_deactivate_connection (NM_CLIENT_GET_PRIVATE (client)->manager,
	                                         active, cancellable, error);
}

static void
deactivated_cb (GObject *object,
                GAsyncResult *result,
                gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nm_manager_deactivate_connection_finish (NM_MANAGER (object), result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else
		g_simple_async_result_take_error (simple, error);
	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

/**
 * nm_client_deactivate_connection_async:
 * @client: a #NMClient
 * @active: the #NMActiveConnection to deactivate
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the deactivation has completed
 * @user_data: caller-specific data passed to @callback
 *
 * Asynchronously deactivates an active #NMActiveConnection.
 **/
void
nm_client_deactivate_connection_async (NMClient *client,
                                       NMActiveConnection *active,
                                       GCancellable *cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (active));

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_deactivate_connection_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	if (!_nm_client_check_nm_running (client, NULL)) {
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
		g_simple_async_result_complete_in_idle (simple);
		g_object_unref (simple);
		return;
	}

	nm_manager_deactivate_connection_async (NM_CLIENT_GET_PRIVATE (client)->manager,
	                                        active,
	                                        cancellable, deactivated_cb, simple);
}

/**
 * nm_client_deactivate_connection_finish:
 * @client: a #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_deactivate_connection_async().
 *
 * Returns: success or failure
 **/
gboolean
nm_client_deactivate_connection_finish (NMClient *client,
                                        GAsyncResult *result,
                                        GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
}

/*****************************************************************************/
/* Connections                                                  */
/*****************************************************************************/

/**
 * nm_client_get_connections:
 * @client: the %NMClient
 *
 * Returns: (transfer none) (element-type NMRemoteConnection): an array
 * containing all connections provided by the remote settings service.  The
 * returned array is owned by the #NMClient object and should not be modified.
 *
 * The connections are as received from D-Bus and might not validate according
 * to nm_connection_verify().
 **/
const GPtrArray *
nm_client_get_connections (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	if (!nm_client_get_nm_running (client))
		return &empty;

	return nm_remote_settings_get_connections (NM_CLIENT_GET_PRIVATE (client)->settings);
}

/**
 * nm_client_get_connection_by_id:
 * @client: the %NMClient
 * @id: the id of the remote connection
 *
 * Returns the first matching %NMRemoteConnection matching a given @id.
 *
 * Returns: (transfer none): the remote connection object on success, or %NULL if no
 *  matching object was found.
 *
 * The connection is as received from D-Bus and might not validate according
 * to nm_connection_verify().
 **/
NMRemoteConnection *
nm_client_get_connection_by_id (NMClient *client, const char *id)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (id != NULL, NULL);

	if (!nm_client_get_nm_running (client))
		return NULL;

	return nm_remote_settings_get_connection_by_id (NM_CLIENT_GET_PRIVATE (client)->settings, id);
}

/**
 * nm_client_get_connection_by_path:
 * @client: the %NMClient
 * @path: the D-Bus object path of the remote connection
 *
 * Returns the %NMRemoteConnection representing the connection at @path.
 *
 * Returns: (transfer none): the remote connection object on success, or %NULL if the object was
 *  not known
 *
 * The connection is as received from D-Bus and might not validate according
 * to nm_connection_verify().
 **/
NMRemoteConnection *
nm_client_get_connection_by_path (NMClient *client, const char *path)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	if (!nm_client_get_nm_running (client))
		return NULL;

	return nm_remote_settings_get_connection_by_path (NM_CLIENT_GET_PRIVATE (client)->settings, path);
}

/**
 * nm_client_get_connection_by_uuid:
 * @client: the %NMClient
 * @uuid: the UUID of the remote connection
 *
 * Returns the %NMRemoteConnection identified by @uuid.
 *
 * Returns: (transfer none): the remote connection object on success, or %NULL if the object was
 *  not known
 *
 * The connection is as received from D-Bus and might not validate according
 * to nm_connection_verify().
 **/
NMRemoteConnection *
nm_client_get_connection_by_uuid (NMClient *client, const char *uuid)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	if (!nm_client_get_nm_running (client))
		return NULL;

	return nm_remote_settings_get_connection_by_uuid (NM_CLIENT_GET_PRIVATE (client)->settings, uuid);
}

typedef struct {
	NMRemoteConnection *connection;
	GVariant *results;
} AddConnection2CbData;

static void
add_connection2_cb_data_destroy (gpointer user_data)
{
	AddConnection2CbData *data = user_data;

	g_object_unref (data->connection);
	nm_g_variant_unref (data->results);
	nm_g_slice_free (data);
}

static void
add_connection2_cb (NMRemoteSettings *self,
                    NMRemoteConnection *connection,
                    GVariant *results,
                    GError *error,
                    gpointer user_data)
{
	gs_unref_object GSimpleAsyncResult *simple = user_data;

	if (error) {
		g_simple_async_result_take_error (simple,
		                                  g_error_new_literal (error->domain,
		                                                       error->code,
		                                                       error->message));
	} else if (g_simple_async_result_get_source_tag (simple) == nm_client_add_connection_async) {
		g_simple_async_result_set_op_res_gpointer (simple,
		                                           g_object_ref (connection),
		                                           g_object_unref);
	} else {
		AddConnection2CbData *data;

		nm_assert (g_simple_async_result_get_source_tag (simple) == nm_client_add_connection2);

		data = g_slice_new (AddConnection2CbData);
		*data = (AddConnection2CbData) {
			.connection = g_object_ref (connection),
			.results    = nm_g_variant_ref (results),
		};
		g_simple_async_result_set_op_res_gpointer (simple,
		                                           data,
		                                           add_connection2_cb_data_destroy);
	}

	g_simple_async_result_complete (simple);
}

/**
 * nm_client_add_connection_async:
 * @client: the %NMClient
 * @connection: the connection to add. Note that this object's settings will be
 *   added, not the object itself
 * @save_to_disk: whether to immediately save the connection to disk
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Requests that the remote settings service add the given settings to a new
 * connection.  If @save_to_disk is %TRUE, the connection is immediately written
 * to disk; otherwise it is initially only stored in memory, but may be saved
 * later by calling the connection's nm_remote_connection_commit_changes()
 * method.
 *
 * @connection is untouched by this function and only serves as a template of
 * the settings to add.  The #NMRemoteConnection object that represents what
 * NetworkManager actually added is returned to @callback when the addition
 * operation is complete.
 *
 * Note that the #NMRemoteConnection returned in @callback may not contain
 * identical settings to @connection as NetworkManager may perform automatic
 * completion and/or normalization of connection properties.
 **/
void
nm_client_add_connection_async (NMClient *client,
                                NMConnection *connection,
                                gboolean save_to_disk,
                                GCancellable *cancellable,
                                GAsyncReadyCallback callback,
                                gpointer user_data)
{
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	if (!_nm_client_check_nm_running (client, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (client), callback, user_data, error);
		return;
	}

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_add_connection_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	nm_remote_settings_add_connection2 (NM_CLIENT_GET_PRIVATE (client)->settings,
	                                    nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL),
	                                    save_to_disk
	                                    ? NM_SETTINGS_ADD_CONNECTION2_FLAG_TO_DISK
	                                    : NM_SETTINGS_ADD_CONNECTION2_FLAG_IN_MEMORY,
	                                    NULL,
	                                    TRUE,
	                                    cancellable,
	                                    add_connection2_cb,
	                                    simple);
}

/**
 * nm_client_add_connection_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_add_connection_async().
 *
 * Returns: (transfer full): the new #NMRemoteConnection on success, %NULL on
 *   failure, in which case @error will be set.
 **/
NMRemoteConnection *
nm_client_add_connection_finish (NMClient *client,
                                 GAsyncResult *result,
                                 GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (client), nm_client_add_connection_async), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	return g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));
}

/**
 * nm_client_add_connection2:
 * @client: the %NMClient
 * @settings: the "a{sa{sv}}" #GVariant with the content of the setting.
 * @flags: the %NMSettingsAddConnection2Flags argument.
 * @args: (allow-none): the "a{sv}" #GVariant with extra argument or %NULL
 *   for no extra arguments.
 * @ignore_out_result: this function wraps AddConnection2(), which has an
 *   additional result "a{sv}" output parameter. By setting this to %TRUE,
 *   you signal that you are not interested in that output parameter.
 *   This allows the function to fall back to AddConnection() and AddConnectionUnsaved(),
 *   which is interesting if you run against an older server version that does
 *   not yet provide AddConnection2(). By setting this to %FALSE, the function
 *   under the hood always calls AddConnection2().
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Call AddConnection2() D-Bus API asynchronously.
 *
 * Since: 1.20
 **/
void
nm_client_add_connection2 (NMClient *client,
                           GVariant *settings,
                           NMSettingsAddConnection2Flags flags,
                           GVariant *args,
                           gboolean ignore_out_result,
                           GCancellable *cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (g_variant_is_of_type (settings, G_VARIANT_TYPE ("a{sa{sv}}")));
	g_return_if_fail (!args || g_variant_is_of_type (args, G_VARIANT_TYPE ("a{sv}")));

	if (!_nm_client_check_nm_running (client, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (client), callback, user_data, error);
		return;
	}

	simple = g_simple_async_result_new (G_OBJECT (client),
	                                    callback,
	                                    user_data,
	                                    nm_client_add_connection2);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	nm_remote_settings_add_connection2 (NM_CLIENT_GET_PRIVATE (client)->settings,
	                                    settings,
	                                    flags,
	                                    args,
	                                    ignore_out_result,
	                                    cancellable,
	                                    add_connection2_cb,
	                                    simple);
}

/**
 * nm_client_add_connection2_finish:
 * @client: the #NMClient
 * @result: the #GAsyncResult
 * @out_result: (allow-none) (transfer full) (out): the output #GVariant
 *   from AddConnection2().
 *   If you care about the output result, then the "ignore_out_result"
 *   parameter of nm_client_add_connection2() must not be set to %TRUE.
 * @error: (allow-none): the error argument.
 *
 * Returns: (transfer full): on success, a pointer to the added
 *   #NMRemoteConnection.
 *
 * Since: 1.20
 */
NMRemoteConnection *
nm_client_add_connection2_finish (NMClient *client,
                                  GAsyncResult *result,
                                  GVariant **out_result,
                                  GError **error)
{
	GSimpleAsyncResult *simple;
	AddConnection2CbData *data;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (client), nm_client_add_connection2), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error)) {
		NM_SET_OUT (out_result, NULL);
		return NULL;
	}

	data = g_simple_async_result_get_op_res_gpointer (simple);
	NM_SET_OUT (out_result, g_variant_ref (data->results));
	return g_object_ref (data->connection);
}

/**
 * nm_client_load_connections:
 * @client: the %NMClient
 * @filenames: (array zero-terminated=1): %NULL-terminated array of filenames to load
 * @failures: (out) (transfer full): on return, a %NULL-terminated array of
 *   filenames that failed to load
 * @cancellable: a #GCancellable, or %NULL
 * @error: return location for #GError
 *
 * Requests that the remote settings service load or reload the given files,
 * adding or updating the connections described within.
 *
 * The changes to the indicated files will not yet be reflected in
 * @client's connections array when the function returns.
 *
 * If all of the indicated files were successfully loaded, the
 * function will return %TRUE, and @failures will be set to %NULL. If
 * NetworkManager tried to load the files, but some (or all) failed,
 * then @failures will be set to a %NULL-terminated array of the
 * filenames that failed to load.
 *
 * Returns: %TRUE if NetworkManager at least tried to load @filenames,
 * %FALSE if an error occurred (eg, permission denied).
 **/
gboolean
nm_client_load_connections (NMClient *client,
                            char **filenames,
                            char ***failures,
                            GCancellable *cancellable,
                            GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (filenames != NULL, FALSE);

	if (!_nm_client_check_nm_running (client, error))
		return FALSE;

	return nm_remote_settings_load_connections (NM_CLIENT_GET_PRIVATE (client)->settings,
	                                            filenames, failures,
	                                            cancellable, error);
}

static void
load_connections_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;
	char **failures = NULL;

	if (nm_remote_settings_load_connections_finish (NM_REMOTE_SETTINGS (object),
	                                                &failures, result, &error))
		g_simple_async_result_set_op_res_gpointer (simple, failures, (GDestroyNotify) g_strfreev);
	else
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

/**
 * nm_client_load_connections_async:
 * @client: the %NMClient
 * @filenames: (array zero-terminated=1): %NULL-terminated array of filenames to load
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Requests that the remote settings service asynchronously load or reload the
 * given files, adding or updating the connections described within.
 *
 * See nm_client_load_connections() for more details.
 **/
void
nm_client_load_connections_async (NMClient *client,
                                  char **filenames,
                                  GCancellable *cancellable,
                                  GAsyncReadyCallback callback,
                                  gpointer user_data)
{
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (filenames != NULL);

	if (!_nm_client_check_nm_running (client, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (client), callback, user_data, error);
		return;
	}

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_load_connections_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nm_remote_settings_load_connections_async (NM_CLIENT_GET_PRIVATE (client)->settings,
	                                           filenames,
	                                           cancellable, load_connections_cb, simple);
}

/**
 * nm_client_load_connections_finish:
 * @client: the %NMClient
 * @failures: (out) (transfer full) (array zero-terminated=1): on return, a
 *    %NULL-terminated array of filenames that failed to load
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of an nm_client_load_connections_async() call.

 * See nm_client_load_connections() for more details.
 *
 * Returns: %TRUE if NetworkManager at least tried to load @filenames,
 * %FALSE if an error occurred (eg, permission denied).
 **/
gboolean
nm_client_load_connections_finish (NMClient *client,
                                   char ***failures,
                                   GAsyncResult *result,
                                   GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else {
		if (failures)
			*failures = g_strdupv (g_simple_async_result_get_op_res_gpointer (simple));
		return TRUE;
	}
}

/**
 * nm_client_reload_connections:
 * @client: the #NMClient
 * @cancellable: a #GCancellable, or %NULL
 * @error: return location for #GError
 *
 * Requests that the remote settings service reload all connection
 * files from disk, adding, updating, and removing connections until
 * the in-memory state matches the on-disk state.
 *
 * Return value: %TRUE on success, %FALSE on failure
 **/
gboolean
nm_client_reload_connections (NMClient *client,
                              GCancellable *cancellable,
                              GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	if (!_nm_client_check_nm_running (client, error))
		return FALSE;

	return nm_remote_settings_reload_connections (NM_CLIENT_GET_PRIVATE (client)->settings,
	                                              cancellable, error);
}

static void
reload_connections_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nm_remote_settings_reload_connections_finish (NM_REMOTE_SETTINGS (object),
	                                                  result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

/**
 * nm_client_reload_connections_async:
 * @client: the #NMClient
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the reload operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Requests that the remote settings service begin reloading all connection
 * files from disk, adding, updating, and removing connections until the
 * in-memory state matches the on-disk state.
 **/
void
nm_client_reload_connections_async (NMClient *client,
                                    GCancellable *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));

	if (!_nm_client_check_nm_running (client, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (client), callback, user_data, error);
		return;
	}

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_reload_connections_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nm_remote_settings_reload_connections_async (NM_CLIENT_GET_PRIVATE (client)->settings,
	                                             cancellable, reload_connections_cb, simple);
}

/**
 * nm_client_reload_connections_finish:
 * @client: the #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: return location for #GError
 *
 * Gets the result of an nm_client_reload_connections_async() call.
 *
 * Return value: %TRUE on success, %FALSE on failure
 **/
gboolean
nm_client_reload_connections_finish (NMClient *client,
                                     GAsyncResult *result,
                                     GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
}

/*****************************************************************************/

/**
 * nm_client_get_dns_mode:
 * @client: the #NMClient
 *
 * Gets the current DNS processing mode.
 *
 * Return value: the DNS processing mode, or %NULL in case the
 *   value is not available.
 *
 * Since: 1.6
 **/
const char *
nm_client_get_dns_mode (NMClient *client)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	priv = NM_CLIENT_GET_PRIVATE (client);

	if (priv->dns_manager)
		return nm_dns_manager_get_mode (priv->dns_manager);
	else
		return NULL;
}

/**
 * nm_client_get_dns_rc_manager:
 * @client: the #NMClient
 *
 * Gets the current DNS resolv.conf manager.
 *
 * Return value: the resolv.conf manager or %NULL in case the
 *   value is not available.
 *
 * Since: 1.6
 **/
const char *
nm_client_get_dns_rc_manager (NMClient *client)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	priv = NM_CLIENT_GET_PRIVATE (client);

	if (priv->dns_manager)
		return nm_dns_manager_get_rc_manager (priv->dns_manager);
	else
		return NULL;
}

/**
 * nm_client_get_dns_configuration:
 * @client: a #NMClient
 *
 * Gets the current DNS configuration
 *
 * Returns: (transfer none) (element-type NMDnsEntry): a #GPtrArray
 * containing #NMDnsEntry elements or %NULL in case the value is not
 * available.  The returned array is owned by the #NMClient object
 * and should not be modified.
 *
 * Since: 1.6
 **/
const GPtrArray *
nm_client_get_dns_configuration (NMClient *client)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	priv = NM_CLIENT_GET_PRIVATE (client);

	if (priv->dns_manager)
		return nm_dns_manager_get_configuration (priv->dns_manager);
	else
		return NULL;
}

/*****************************************************************************/

/**
 * nm_client_new:
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Creates a new #NMClient.
 *
 * Note that this will do blocking D-Bus calls to initialize the
 * client. You can use nm_client_new_async() if you want to avoid
 * that.
 *
 * Returns: a new #NMClient or NULL on an error
 **/
NMClient *
nm_client_new (GCancellable  *cancellable,
               GError       **error)
{
	return g_initable_new (NM_TYPE_CLIENT, cancellable, error,
	                       NULL);
}

static void
client_inited (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (!g_async_initable_new_finish (G_ASYNC_INITABLE (source), result, &error))
		g_simple_async_result_take_error (simple, error);
	else
		g_simple_async_result_set_op_res_gpointer (simple, source, g_object_unref);
	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

/**
 * nm_client_new_async:
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to call when the client is created
 * @user_data: data for @callback
 *
 * Creates a new #NMClient and begins asynchronously initializing it.
 * @callback will be called when it is done; use
 * nm_client_new_finish() to get the result. Note that on an error,
 * the callback can be invoked with two first parameters as NULL.
 **/
void
nm_client_new_async (GCancellable *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
	GSimpleAsyncResult *simple;

	simple = g_simple_async_result_new (NULL, callback, user_data, nm_client_new_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	g_async_initable_new_async (NM_TYPE_CLIENT, G_PRIORITY_DEFAULT,
	                            cancellable, client_inited, simple,
	                            NULL);
}

/**
 * nm_client_new_finish:
 * @result: a #GAsyncResult
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of an nm_client_new_async() call.
 *
 * Returns: a new #NMClient, or %NULL on error
 **/
NMClient *
nm_client_new_finish (GAsyncResult *result, GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL, nm_client_new_async), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));
}

static void
subobject_notify (GObject *object,
                  GParamSpec *pspec,
                  gpointer client)
{
	if (!g_str_has_suffix (pspec->name, "-internal"))
		g_object_notify (client, pspec->name);
}

static void
manager_device_added (NMManager *manager,
                      NMDevice *device,
                      gpointer client)
{
	g_signal_emit (client, signals[DEVICE_ADDED], 0, device);
}

static void
manager_device_removed (NMManager *manager,
                        NMDevice *device,
                        gpointer client)
{
	g_signal_emit (client, signals[DEVICE_REMOVED], 0, device);
}

static void
manager_any_device_added (NMManager *manager,
                          NMDevice *device,
                          gpointer client)
{
	g_signal_emit (client, signals[ANY_DEVICE_ADDED], 0, device);
}

static void
manager_any_device_removed (NMManager *manager,
                            NMDevice *device,
                            gpointer client)
{
	g_signal_emit (client, signals[ANY_DEVICE_REMOVED], 0, device);
}

static void
manager_permission_changed (NMManager *manager,
                            NMClientPermission permission,
                            NMClientPermissionResult result,
                            gpointer client)
{
	g_signal_emit (client, signals[PERMISSION_CHANGED], 0, permission, result);
}

static void
settings_connection_added (NMRemoteSettings *manager,
                           NMRemoteConnection *connection,
                           gpointer client)
{
	g_signal_emit (client, signals[CONNECTION_ADDED], 0, connection);
}
static void
settings_connection_removed (NMRemoteSettings *manager,
                             NMRemoteConnection *connection,
                             gpointer client)
{
	g_signal_emit (client, signals[CONNECTION_REMOVED], 0, connection);
}

static void
manager_active_connection_added (NMManager *manager,
                                 NMActiveConnection *active_connection,
                                 gpointer client)
{
	g_signal_emit (client, signals[ACTIVE_CONNECTION_ADDED], 0, active_connection);
}

static void
manager_active_connection_removed (NMManager *manager,
                                   NMActiveConnection *active_connection,
                                   gpointer client)
{
	g_signal_emit (client, signals[ACTIVE_CONNECTION_REMOVED], 0, active_connection);
}

static void
dns_notify (GObject *object,
            GParamSpec *pspec,
            gpointer client)
{
	char pname[128];

	if (NM_IN_STRSET (pspec->name,
	                  NM_DNS_MANAGER_MODE,
	                  NM_DNS_MANAGER_RC_MANAGER,
	                  NM_DNS_MANAGER_CONFIGURATION)) {
		nm_sprintf_buf (pname, "dns-%s", pspec->name);
		g_object_notify (client, pname);
	}
}

static void
checkpoint_create_cb (GObject *object,
                      GAsyncResult *result,
                      gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	NMCheckpoint *checkpoint;
	GError *error = NULL;

	checkpoint = nm_manager_checkpoint_create_finish (NM_MANAGER (object), result, &error);
	if (checkpoint)
		g_simple_async_result_set_op_res_gpointer (simple, checkpoint, g_object_unref);
	else
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

/**
 * nm_client_get_checkpoints:
 * @client: a #NMClient
 *
 * Gets all the active checkpoints.
 *
 * Returns: (transfer none) (element-type NMCheckpoint): a #GPtrArray
 * containing all the #NMCheckpoint.  The returned array is owned by the
 * #NMClient object and should not be modified.
 *
 * Since: 1.12
 **/
const GPtrArray *
nm_client_get_checkpoints (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	if (!nm_client_get_nm_running (client))
		return &empty;

	return nm_manager_get_checkpoints (NM_CLIENT_GET_PRIVATE (client)->manager);
}

/**
 * nm_client_checkpoint_create:
 * @client: the %NMClient
 * @devices: (element-type NMDevice): a list of devices for which a
 *   checkpoint should be created.
 * @rollback_timeout: the rollback timeout in seconds
 * @flags: creation flags
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Creates a checkpoint of the current networking configuration
 * for given interfaces. An empty @devices argument means all
 * devices. If @rollback_timeout is not zero, a rollback is
 * automatically performed after the given timeout.
 *
 * Since: 1.12
 **/
void
nm_client_checkpoint_create (NMClient *client,
                             const GPtrArray *devices,
                             guint32 rollback_timeout,
                             NMCheckpointCreateFlags flags,
                             GCancellable *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));

	if (!_nm_client_check_nm_running (client, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (client), callback, user_data, error);
		return;
	}

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_checkpoint_create);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nm_manager_checkpoint_create (NM_CLIENT_GET_PRIVATE (client)->manager,
	                              devices, rollback_timeout, flags,
	                              cancellable, checkpoint_create_cb, simple);
}

/**
 * nm_client_checkpoint_create_finish:
 * @client: the #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_checkpoint_create().
 *
 * Returns: (transfer full): the new #NMCheckpoint on success, %NULL on
 *   failure, in which case @error will be set.
 *
 * Since: 1.12
 **/
NMCheckpoint *
nm_client_checkpoint_create_finish (NMClient *client,
                                    GAsyncResult *result,
                                    GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));
}

static void
checkpoint_destroy_cb (GObject *object,
                       GAsyncResult *result,
                       gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nm_manager_checkpoint_destroy_finish (NM_MANAGER (object), result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

/**
 * nm_client_checkpoint_destroy:
 * @client: the %NMClient
 * @checkpoint_path: the D-Bus path for the checkpoint
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Destroys an existing checkpoint without performing a rollback.
 *
 * Since: 1.12
 **/
void
nm_client_checkpoint_destroy (NMClient *client,
                              const char *checkpoint_path,
                              GCancellable *cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (checkpoint_path && checkpoint_path[0] == '/');

	if (!_nm_client_check_nm_running (client, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (client), callback, user_data, error);
		return;
	}

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_checkpoint_destroy);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nm_manager_checkpoint_destroy (NM_CLIENT_GET_PRIVATE (client)->manager,
	                               checkpoint_path,
	                               cancellable, checkpoint_destroy_cb, simple);
}

/**
 * nm_client_checkpoint_destroy_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_checkpoint_destroy().
 *
 * Returns: %TRUE on success or %FALSE on failure, in which case
 *   @error will be set.
 *
 * Since: 1.12
 **/
gboolean
nm_client_checkpoint_destroy_finish (NMClient *client,
                                     GAsyncResult *result,
                                     GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
}

static void
checkpoint_rollback_cb (GObject *object,
                        GAsyncResult *result,
                        gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GHashTable *hash;
	GError *error = NULL;

	hash = nm_manager_checkpoint_rollback_finish (NM_MANAGER (object), result, &error);
	if (hash)
		g_simple_async_result_set_op_res_gpointer (simple, hash, (GDestroyNotify) g_hash_table_unref);
	else
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

/**
 * nm_client_checkpoint_rollback:
 * @client: the %NMClient
 * @checkpoint_path: the D-Bus path to the checkpoint
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Performs the rollback of a checkpoint before the timeout is reached.
 *
 * Since: 1.12
 **/
void
nm_client_checkpoint_rollback (NMClient *client,
                               const char *checkpoint_path,
                               GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (checkpoint_path && checkpoint_path[0] == '/');

	if (!_nm_client_check_nm_running (client, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (client), callback, user_data, error);
		return;
	}

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_checkpoint_rollback);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nm_manager_checkpoint_rollback (NM_CLIENT_GET_PRIVATE (client)->manager,
	                                checkpoint_path,
	                                cancellable, checkpoint_rollback_cb, simple);
}

/**
 * nm_client_checkpoint_rollback_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_checkpoint_rollback().
 *
 * Returns: (transfer full) (element-type utf8 guint32): an hash table of
 *   devices and results. Devices are represented by their original
 *   D-Bus path; each result is a #NMRollbackResult.
 *
 * Since: 1.12
 **/
GHashTable *
nm_client_checkpoint_rollback_finish (NMClient *client,
                                      GAsyncResult *result,
                                      GError **error)
{
	GSimpleAsyncResult *simple;
	GHashTable *hash;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else {
		hash = g_simple_async_result_get_op_res_gpointer (simple);
		return g_hash_table_ref (hash);
	}
}

static void
checkpoint_adjust_rollback_timeout_cb (GObject *object,
                                       GAsyncResult *result,
                                       gpointer user_data)
{
	gs_unref_object GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nm_manager_checkpoint_adjust_rollback_timeout_finish (NM_MANAGER (object), result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
}

/**
 * nm_client_checkpoint_adjust_rollback_timeout:
 * @client: the %NMClient
 * @checkpoint_path: a D-Bus path to a checkpoint
 * @add_timeout: the timeout in seconds counting from now.
 *   Set to zero, to disable the timeout.
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Resets the timeout for the checkpoint with path @checkpoint_path
 * to @timeout_add.
 *
 * Since: 1.12
 **/
void
nm_client_checkpoint_adjust_rollback_timeout (NMClient *client,
                                              const char *checkpoint_path,
                                              guint32 add_timeout,
                                              GCancellable *cancellable,
                                              GAsyncReadyCallback callback,
                                              gpointer user_data)
{
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (checkpoint_path && checkpoint_path[0] == '/');

	if (!_nm_client_check_nm_running (client, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (client), callback, user_data, error);
		return;
	}

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_checkpoint_rollback);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nm_manager_checkpoint_adjust_rollback_timeout (NM_CLIENT_GET_PRIVATE (client)->manager,
	                                               checkpoint_path, add_timeout,
	                                               cancellable, checkpoint_adjust_rollback_timeout_cb, simple);
}

/**
 * nm_client_checkpoint_adjust_rollback_timeout_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_checkpoint_adjust_rollback_timeout().
 *
 * Returns: %TRUE on success or %FALSE on failure.
 *
 * Since: 1.12
 **/
gboolean
nm_client_checkpoint_adjust_rollback_timeout_finish (NMClient *client,
                                                     GAsyncResult *result,
                                                     GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), FALSE);

	return !g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result),
	                                               error);
}

/****************************************************************/
/* Object Initialization                                        */
/****************************************************************/

static GType
proxy_type (GDBusObjectManagerClient *manager,
            const char *object_path,
            const char *interface_name,
            gpointer user_data)
{
	/* ObjectManager asks us for an object proxy. Unfortunately, we can't
	 * decide that by interface name and GDBusObjectManager doesn't allow
	 * us to look at the known interface list. Thus we need to create a
	 * generic GDBusObject and only couple a NMObject subclass later. */
	if (!interface_name)
		return G_TYPE_DBUS_OBJECT_PROXY;

	/* An interface proxy */
	if (strcmp (interface_name, NM_DBUS_INTERFACE) == 0)
		return NMDBUS_TYPE_MANAGER_PROXY;
	else if (strcmp (interface_name, NM_DBUS_INTERFACE_DEVICE_WIRELESS) == 0)
		return NMDBUS_TYPE_DEVICE_WIFI_PROXY;
	else if (strcmp (interface_name, NM_DBUS_INTERFACE_DEVICE_WIFI_P2P) == 0)
		return NMDBUS_TYPE_DEVICE_WIFI_P2P_PROXY;
	else if (strcmp (interface_name, NM_DBUS_INTERFACE_DEVICE) == 0)
		return NMDBUS_TYPE_DEVICE_PROXY;
	else if (strcmp (interface_name, NM_DBUS_INTERFACE_SETTINGS_CONNECTION) == 0)
		return NMDBUS_TYPE_SETTINGS_CONNECTION_PROXY;
	else if (strcmp (interface_name, NM_DBUS_INTERFACE_SETTINGS) == 0)
		return NMDBUS_TYPE_SETTINGS_PROXY;
	else if (strcmp (interface_name, NM_DBUS_INTERFACE_DNS_MANAGER) == 0)
		return NMDBUS_TYPE_DNS_MANAGER_PROXY;
	else if (strcmp (interface_name, NM_DBUS_INTERFACE_VPN_CONNECTION) == 0)
		return NMDBUS_TYPE_VPN_CONNECTION_PROXY;
	else if (strcmp (interface_name, NM_DBUS_INTERFACE_ACTIVE_CONNECTION) == 0)
		return NMDBUS_TYPE_ACTIVE_CONNECTION_PROXY;

	/* Use a generic D-Bus Proxy whenever we can. The typed GDBusProxy
	 * subclasses actually use quite some memory, so they're better avoided. */
	return G_TYPE_DBUS_PROXY;
}

static NMObject *
obj_nm_for_gdbus_object (NMClient *self, GDBusObject *object, GDBusObjectManager *object_manager)
{
	NMClientPrivate *priv;
	GList *interfaces;
	GList *l;
	GType type = G_TYPE_INVALID;
	NMObject *obj_nm;

	g_return_val_if_fail (G_IS_DBUS_OBJECT_PROXY (object), NULL);

	interfaces = g_dbus_object_get_interfaces (object);
	for (l = interfaces; l; l = l->next) {
		GDBusProxy *proxy = G_DBUS_PROXY (l->data);
		const char *ifname = g_dbus_proxy_get_interface_name (proxy);

		/* This is a performance/scalability hack. It makes sense to call it
		 * from here, since this is in the common object creation path. */
		_nm_dbus_proxy_replace_match (proxy);

		if (strcmp (ifname, NM_DBUS_INTERFACE) == 0)
			type = NM_TYPE_MANAGER;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_ACCESS_POINT) == 0)
			type = NM_TYPE_ACCESS_POINT;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_ACTIVE_CONNECTION) == 0 && type != NM_TYPE_VPN_CONNECTION)
			type = NM_TYPE_ACTIVE_CONNECTION;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_6LOWPAN) == 0)
			type = NM_TYPE_DEVICE_6LOWPAN;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_ADSL) == 0)
			type = NM_TYPE_DEVICE_ADSL;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_BOND) == 0)
			type = NM_TYPE_DEVICE_BOND;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_BRIDGE) == 0)
			type = NM_TYPE_DEVICE_BRIDGE;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_BLUETOOTH) == 0)
			type = NM_TYPE_DEVICE_BT;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_DUMMY) == 0)
			type = NM_TYPE_DEVICE_DUMMY;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_WIRED) == 0)
			type = NM_TYPE_DEVICE_ETHERNET;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_GENERIC) == 0)
			type = NM_TYPE_DEVICE_GENERIC;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_INFINIBAND) == 0)
			type = NM_TYPE_DEVICE_INFINIBAND;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_IP_TUNNEL) == 0)
			type = NM_TYPE_DEVICE_IP_TUNNEL;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_MACSEC) == 0)
			type = NM_TYPE_DEVICE_MACSEC;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_MACVLAN) == 0)
			type = NM_TYPE_DEVICE_MACVLAN;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_MODEM) == 0)
			type = NM_TYPE_DEVICE_MODEM;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_OLPC_MESH) == 0)
			type = NM_TYPE_DEVICE_OLPC_MESH;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_OVS_INTERFACE) == 0)
			type = NM_TYPE_DEVICE_OVS_INTERFACE;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_OVS_PORT) == 0)
			type = NM_TYPE_DEVICE_OVS_PORT;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_OVS_BRIDGE) == 0)
			type = NM_TYPE_DEVICE_OVS_BRIDGE;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_WIFI_P2P) == 0)
			type = NM_TYPE_DEVICE_WIFI_P2P;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_PPP) == 0)
			type = NM_TYPE_DEVICE_PPP;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_TEAM) == 0)
			type = NM_TYPE_DEVICE_TEAM;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_TUN) == 0)
			type = NM_TYPE_DEVICE_TUN;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_VLAN) == 0)
			type = NM_TYPE_DEVICE_VLAN;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_WPAN) == 0)
			type = NM_TYPE_DEVICE_WPAN;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_VXLAN) == 0)
			type = NM_TYPE_DEVICE_VXLAN;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_WIRELESS) == 0)
			type = NM_TYPE_DEVICE_WIFI;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_WIMAX) == 0)
			type = NM_TYPE_DEVICE_WIMAX;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DEVICE_WIREGUARD) == 0)
			type = NM_TYPE_DEVICE_WIREGUARD;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DHCP4_CONFIG) == 0)
			type = NM_TYPE_DHCP4_CONFIG;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DHCP6_CONFIG) == 0)
			type = NM_TYPE_DHCP6_CONFIG;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_IP4_CONFIG) == 0)
			type = NM_TYPE_IP4_CONFIG;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_IP6_CONFIG) == 0)
			type = NM_TYPE_IP6_CONFIG;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_WIFI_P2P_PEER) == 0)
			type = NM_TYPE_WIFI_P2P_PEER;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_SETTINGS_CONNECTION) == 0)
			type = NM_TYPE_REMOTE_CONNECTION;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_SETTINGS) == 0)
			type = NM_TYPE_REMOTE_SETTINGS;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_DNS_MANAGER) == 0)
			type = NM_TYPE_DNS_MANAGER;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_VPN_CONNECTION) == 0)
			type = NM_TYPE_VPN_CONNECTION;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_WIMAX_NSP) == 0)
			type = NM_TYPE_WIMAX_NSP;
		else if (strcmp (ifname, NM_DBUS_INTERFACE_CHECKPOINT) == 0)
			type = NM_TYPE_CHECKPOINT;

		if (type != G_TYPE_INVALID)
			break;
	}

	g_list_free_full (interfaces, g_object_unref);
	if (type == G_TYPE_INVALID)
		return NULL;

	obj_nm = g_object_new (type,
	                       NM_OBJECT_DBUS_OBJECT, object,
	                       NM_OBJECT_DBUS_OBJECT_MANAGER, object_manager,
	                       NULL);
	if (NM_IS_DEVICE (obj_nm)) {
		priv = NM_CLIENT_GET_PRIVATE (self);
		if (G_UNLIKELY (!priv->udev_inited)) {
			priv->udev_inited = TRUE;
			/* for testing, we don't want to use udev in libnm. */
			if (!nm_streq0 (g_getenv ("LIBNM_USE_NO_UDEV"), "1"))
				priv->udev = udev_new ();
		}
		if (priv->udev)
			_nm_device_set_udev (NM_DEVICE (obj_nm), priv->udev);
	}
	g_object_set_qdata_full (G_OBJECT (object), _nm_object_obj_nm_quark (),
	                         obj_nm, g_object_unref);
	return obj_nm;
}

static void
obj_nm_inited (GObject *object, GAsyncResult *result, gpointer user_data)
{
	if (!g_async_initable_init_finish (G_ASYNC_INITABLE (object), result, NULL)) {
		/* This is a can-not-happen situation, the NMObject subclasses are not
		 * supposed to fail initialization. */
		g_warn_if_reached ();
	}
}

static void
object_added (GDBusObjectManager *object_manager, GDBusObject *object, gpointer user_data)
{
	NMClient *client = user_data;
	NMObject *obj_nm;

	obj_nm = obj_nm_for_gdbus_object (client, object, object_manager);
	if (obj_nm) {
		g_async_initable_init_async (G_ASYNC_INITABLE (obj_nm),
		                             G_PRIORITY_DEFAULT, NULL,
		                             obj_nm_inited, NULL);
	}
}

static void
object_removed (GDBusObjectManager *object_manager, GDBusObject *object, gpointer user_data)
{
	g_object_set_qdata (G_OBJECT (object), _nm_object_obj_nm_quark (), NULL);
}

static gboolean
objects_created (NMClient *client, GDBusObjectManager *object_manager, GError **error)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	gs_unref_object GDBusObject *manager = NULL;
	gs_unref_object GDBusObject *settings = NULL;
	gs_unref_object GDBusObject *dns_manager = NULL;
	NMObject *obj_nm;
	GList *objects, *iter;

	/* First just ensure all the NMObjects for known GDBusObjects exist. */
	objects = g_dbus_object_manager_get_objects (object_manager);
	for (iter = objects; iter; iter = iter->next)
		obj_nm_for_gdbus_object (client, iter->data, object_manager);
	g_list_free_full (objects, g_object_unref);

	manager = g_dbus_object_manager_get_object (object_manager, NM_DBUS_PATH);
	if (!manager) {
		g_set_error_literal (error,
		                     NM_CLIENT_ERROR,
		                     NM_CLIENT_ERROR_MANAGER_NOT_RUNNING,
		                     "Manager object not found");
		return FALSE;
	}

	obj_nm = g_object_get_qdata (G_OBJECT (manager), _nm_object_obj_nm_quark ());
	if (!obj_nm) {
		g_set_error_literal (error,
		                     NM_CLIENT_ERROR,
		                     NM_CLIENT_ERROR_MANAGER_NOT_RUNNING,
		                     "Manager object lacks the proper interface");
		return FALSE;
	}

	priv->manager = NM_MANAGER (g_object_ref (obj_nm));

	g_signal_connect (priv->manager, "notify",
	                  G_CALLBACK (subobject_notify), client);
	g_signal_connect (priv->manager, "device-added",
	                  G_CALLBACK (manager_device_added), client);
	g_signal_connect (priv->manager, "device-removed",
	                  G_CALLBACK (manager_device_removed), client);
	g_signal_connect (priv->manager, "any-device-added",
	                  G_CALLBACK (manager_any_device_added), client);
	g_signal_connect (priv->manager, "any-device-removed",
	                  G_CALLBACK (manager_any_device_removed), client);
	g_signal_connect (priv->manager, "permission-changed",
	                  G_CALLBACK (manager_permission_changed), client);
	g_signal_connect (priv->manager, "active-connection-added",
	                  G_CALLBACK (manager_active_connection_added), client);
	g_signal_connect (priv->manager, "active-connection-removed",
	                  G_CALLBACK (manager_active_connection_removed), client);

	settings = g_dbus_object_manager_get_object (object_manager, NM_DBUS_PATH_SETTINGS);
	if (!settings) {
		g_set_error_literal (error,
		                     NM_CLIENT_ERROR,
		                     NM_CLIENT_ERROR_MANAGER_NOT_RUNNING,
		                     "Settings object not found");
		return FALSE;
	}

	obj_nm = g_object_get_qdata (G_OBJECT (settings), _nm_object_obj_nm_quark ());
	if (!obj_nm) {
		g_set_error_literal (error,
		                     NM_CLIENT_ERROR,
		                     NM_CLIENT_ERROR_MANAGER_NOT_RUNNING,
		                     "Settings object lacks the proper interface");
		return FALSE;
	}

	priv->settings = NM_REMOTE_SETTINGS (g_object_ref (obj_nm));

	g_signal_connect (priv->settings, "notify",
	                  G_CALLBACK (subobject_notify), client);
	g_signal_connect (priv->settings, "connection-added",
	                  G_CALLBACK (settings_connection_added), client);
	g_signal_connect (priv->settings, "connection-removed",
	                  G_CALLBACK (settings_connection_removed), client);

	dns_manager = g_dbus_object_manager_get_object (object_manager, NM_DBUS_PATH_DNS_MANAGER);
	if (dns_manager) {
		obj_nm = g_object_get_qdata (G_OBJECT (dns_manager), _nm_object_obj_nm_quark ());
		if (!obj_nm) {
			g_set_error_literal (error,
			                     NM_CLIENT_ERROR,
			                     NM_CLIENT_ERROR_MANAGER_NOT_RUNNING,
			                     "DNS manager object lacks the proper interface");
			return FALSE;
		}
		priv->dns_manager = NM_DNS_MANAGER (g_object_ref (obj_nm));

		g_signal_connect (priv->dns_manager, "notify",
		                  G_CALLBACK (dns_notify), client);
	}

	/* The handlers don't really use the client instance. However
	 * it makes it convenient to unhook them by data. */
	g_signal_connect (object_manager, "object-added",
	                  G_CALLBACK (object_added), client);
	g_signal_connect (object_manager, "object-removed",
	                  G_CALLBACK (object_removed), client);

	return TRUE;
}

/* Synchronous initialization. */

static void name_owner_changed (GObject *object, GParamSpec *pspec, gpointer user_data);

static gboolean
_om_has_name_owner (GDBusObjectManager *object_manager)
{
	gs_free char *name_owner = NULL;

	nm_assert (G_IS_DBUS_OBJECT_MANAGER_CLIENT (object_manager));

	name_owner = g_dbus_object_manager_client_get_name_owner (G_DBUS_OBJECT_MANAGER_CLIENT (object_manager));
	return !!name_owner;
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMClient *client = NM_CLIENT (initable);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	GList *objects, *iter;

	priv->object_manager = g_dbus_object_manager_client_new_for_bus_sync (_nm_dbus_bus_type (),
	                                                                      G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_DO_NOT_AUTO_START,
	                                                                      "org.freedesktop.NetworkManager",
	                                                                      "/org/freedesktop",
	                                                                      proxy_type, NULL, NULL,
	                                                                      cancellable, error);

	if (!priv->object_manager)
		return FALSE;

	if (_om_has_name_owner (priv->object_manager)) {
		if (!objects_created (client, priv->object_manager, error))
			return FALSE;

		objects = g_dbus_object_manager_get_objects (priv->object_manager);
		for (iter = objects; iter; iter = iter->next) {
			NMObject *obj_nm;

			obj_nm = g_object_get_qdata (iter->data, _nm_object_obj_nm_quark ());
			if (!obj_nm)
				continue;

			if (!g_initable_init (G_INITABLE (obj_nm), cancellable, NULL)) {
				/* This is a can-not-happen situation, the NMObject subclasses are not
				 * supposed to fail initialization. */
				g_warn_if_reached ();
			}
		}
		g_list_free_full (objects, g_object_unref);
	}

	g_signal_connect (priv->object_manager, "notify::name-owner",
	                  G_CALLBACK (name_owner_changed), client);

	return TRUE;
}

/* Asynchronous initialization. */

static void
init_async_complete (NMClientInitData *init_data)
{
	if (init_data->pending_init > 0)
		return;
	g_simple_async_result_complete (init_data->result);
	g_object_unref (init_data->result);
	g_clear_object (&init_data->cancellable);
	g_slice_free (NMClientInitData, init_data);
}

static void
async_inited_obj_nm (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMClientInitData *init_data = user_data;
	GError *error = NULL;

	nm_assert (init_data && init_data->pending_init > 0);

	if (!g_async_initable_init_finish (G_ASYNC_INITABLE (object), result, &error))
		g_simple_async_result_take_error (init_data->result, error);

	init_data->pending_init--;
	init_async_complete (init_data);
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data);

static void
unhook_om (NMClient *self)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	GList *objects, *iter;

	if (priv->manager) {
		const GPtrArray *active_connections;
		const GPtrArray *devices;
		int i;

		active_connections = nm_manager_get_active_connections (priv->manager);
		for (i = 0; i < active_connections->len; i++)
			g_signal_emit (self, signals[ACTIVE_CONNECTION_REMOVED], 0, active_connections->pdata[i]);

		devices = nm_manager_get_all_devices (priv->manager);
		for (i = 0; i < devices->len; i++)
			g_signal_emit (self, signals[DEVICE_REMOVED], 0, devices->pdata[i]);

		g_signal_handlers_disconnect_by_data (priv->manager, self);
		g_clear_object (&priv->manager);
		g_object_notify (G_OBJECT (self), NM_CLIENT_ACTIVE_CONNECTIONS);
		g_object_notify (G_OBJECT (self), NM_CLIENT_NM_RUNNING);
	}
	if (priv->settings) {
		const GPtrArray *connections;
		guint i;

		connections = nm_remote_settings_get_connections (priv->settings);
		for (i = 0; i < connections->len; i++)
			g_signal_emit (self, signals[CONNECTION_REMOVED], 0, connections->pdata[i]);

		g_signal_handlers_disconnect_by_data (priv->settings, self);
		g_clear_object (&priv->settings);
		g_object_notify (G_OBJECT (self), NM_CLIENT_CONNECTIONS);
		g_object_notify (G_OBJECT (self), NM_CLIENT_HOSTNAME);
		g_object_notify (G_OBJECT (self), NM_CLIENT_CAN_MODIFY);
	}
	if (priv->dns_manager) {
		g_signal_handlers_disconnect_by_data (priv->dns_manager, self);
		g_clear_object (&priv->dns_manager);
	}

	objects = g_dbus_object_manager_get_objects (priv->object_manager);
	for (iter = objects; iter; iter = iter->next)
		g_object_set_qdata (iter->data, _nm_object_obj_nm_quark (), NULL);
	g_list_free_full (objects, g_object_unref);
}

static void
new_object_manager (GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	NMClient *self = NM_CLIENT (user_data);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	g_clear_object (&priv->new_object_manager_cancellable);
	g_object_notify (G_OBJECT (user_data), NM_CLIENT_NM_RUNNING);
}

static void
got_object_manager (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMClientInitData *init_data = user_data;
	NMClient *client;
	NMClientPrivate *priv;
	GList *objects, *iter;
	GError *error = NULL;
	GDBusObjectManager *object_manager;

	object_manager = g_dbus_object_manager_client_new_for_bus_finish (result, &error);
	if (object_manager == NULL) {
		g_simple_async_result_take_error (init_data->result, error);
		init_async_complete (init_data);
		return;
	}

	client = init_data->client;
	priv = NM_CLIENT_GET_PRIVATE (client);
	priv->object_manager = object_manager;

	if (_om_has_name_owner (priv->object_manager)) {
		if (!objects_created (client, priv->object_manager, &error)) {
			g_simple_async_result_take_error (init_data->result, error);
			init_async_complete (init_data);
			return;
		}

		objects = g_dbus_object_manager_get_objects (priv->object_manager);
		for (iter = objects; iter; iter = iter->next) {
			NMObject *obj_nm;

			obj_nm = g_object_get_qdata (iter->data, _nm_object_obj_nm_quark ());
			if (!obj_nm)
				continue;

			init_data->pending_init++;
			g_async_initable_init_async (G_ASYNC_INITABLE (obj_nm),
			                             G_PRIORITY_DEFAULT, init_data->cancellable,
			                             async_inited_obj_nm, init_data);
		}
		g_list_free_full (objects, g_object_unref);
	}

	init_async_complete (init_data);

	g_signal_connect (priv->object_manager, "notify::name-owner",
	                  G_CALLBACK (name_owner_changed), client);
}

static void
prepare_object_manager (NMClient *client,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	NMClientInitData *init_data;

	init_data = g_slice_new0 (NMClientInitData);
	init_data->client = client;
	init_data->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	init_data->result = g_simple_async_result_new (G_OBJECT (client), callback,
	                                               user_data, init_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (init_data->result, cancellable);
	g_simple_async_result_set_op_res_gboolean (init_data->result, TRUE);

	g_dbus_object_manager_client_new_for_bus (_nm_dbus_bus_type (),
	                                          G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_DO_NOT_AUTO_START,
	                                          "org.freedesktop.NetworkManager",
	                                          "/org/freedesktop",
	                                          proxy_type, NULL, NULL,
	                                          init_data->cancellable,
	                                          got_object_manager,
	                                          init_data);
}

static void
name_owner_changed (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMClient *self = user_data;
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	GDBusObjectManager *object_manager = G_DBUS_OBJECT_MANAGER (object);

	nm_assert (object_manager == priv->object_manager);

	if (_om_has_name_owner (object_manager)) {
		g_signal_handlers_disconnect_by_data (priv->object_manager, self);
		g_clear_object (&priv->object_manager);
		nm_clear_g_cancellable (&priv->new_object_manager_cancellable);
		priv->new_object_manager_cancellable = g_cancellable_new ();
		prepare_object_manager (self, priv->new_object_manager_cancellable,
		                        new_object_manager, self);
	} else {
		g_signal_handlers_disconnect_by_func (object_manager, object_added, self);
		unhook_om (self);
	}
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	prepare_object_manager (NM_CLIENT (initable), cancellable, callback, user_data);
}

static gboolean
init_finish (GAsyncInitable *initable, GAsyncResult *result, GError **error)
{
	GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return TRUE;
}

static void
dispose (GObject *object)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);

	nm_clear_g_cancellable (&priv->new_object_manager_cancellable);

	if (priv->manager) {
		g_signal_handlers_disconnect_by_data (priv->manager, object);
		g_clear_object (&priv->manager);
	}

	if (priv->settings) {
		g_signal_handlers_disconnect_by_data (priv->settings, object);
		g_clear_object (&priv->settings);
	}

	if (priv->dns_manager) {
		g_signal_handlers_disconnect_by_data (priv->dns_manager, object);
		g_clear_object (&priv->dns_manager);
	}

	if (priv->object_manager) {
		GList *objects, *iter;

		/* Unhook the NM objects. */
		objects = g_dbus_object_manager_get_objects (priv->object_manager);
		for (iter = objects; iter; iter = iter->next)
			g_object_set_qdata (G_OBJECT (iter->data), _nm_object_obj_nm_quark (), NULL);
		g_list_free_full (objects, g_object_unref);

		g_signal_handlers_disconnect_by_data (priv->object_manager, object);
		g_clear_object (&priv->object_manager);
	}

	G_OBJECT_CLASS (nm_client_parent_class)->dispose (object);

	if (priv->udev) {
		udev_unref (priv->udev);
		priv->udev = NULL;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_NETWORKING_ENABLED:
	case PROP_WIRELESS_ENABLED:
	case PROP_WWAN_ENABLED:
	case PROP_WIMAX_ENABLED:
	case PROP_CONNECTIVITY_CHECK_ENABLED:
		if (priv->manager)
			g_object_set_property (G_OBJECT (priv->manager), pspec->name, value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMClient *self = NM_CLIENT (object);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_NM_RUNNING:
		g_value_set_boolean (value, nm_client_get_nm_running (self));
		break;

	/* Manager properties. */
	case PROP_VERSION:
		g_value_set_string (value, nm_client_get_version (self));
		break;
	case PROP_STATE:
		g_value_set_enum (value, nm_client_get_state (self));
		break;
	case PROP_STARTUP:
		g_value_set_boolean (value, nm_client_get_startup (self));
		break;
	case PROP_NETWORKING_ENABLED:
		g_value_set_boolean (value, nm_client_networking_get_enabled (self));
		break;
	case PROP_WIRELESS_ENABLED:
		g_value_set_boolean (value, nm_client_wireless_get_enabled (self));
		break;
	case PROP_WIRELESS_HARDWARE_ENABLED:
		if (priv->manager)
			g_object_get_property (G_OBJECT (priv->manager), pspec->name, value);
		else
			g_value_set_boolean (value, FALSE);
		break;
	case PROP_WWAN_ENABLED:
		g_value_set_boolean (value, nm_client_wwan_get_enabled (self));
		break;
	case PROP_WWAN_HARDWARE_ENABLED:
		if (priv->manager)
			g_object_get_property (G_OBJECT (priv->manager), pspec->name, value);
		else
			g_value_set_boolean (value, FALSE);
		break;
	case PROP_WIMAX_ENABLED:
		g_value_set_boolean (value, nm_client_wimax_get_enabled (self));
		break;
	case PROP_WIMAX_HARDWARE_ENABLED:
		if (priv->manager)
			g_object_get_property (G_OBJECT (priv->manager), pspec->name, value);
		else
			g_value_set_boolean (value, FALSE);
		break;
	case PROP_ACTIVE_CONNECTIONS:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_client_get_active_connections (self)));
		break;
	case PROP_CONNECTIVITY:
		g_value_set_enum (value, nm_client_get_connectivity (self));
		break;
	case PROP_CONNECTIVITY_CHECK_AVAILABLE:
		g_value_set_boolean (value, nm_client_connectivity_check_get_available (self));
		break;
	case PROP_CONNECTIVITY_CHECK_ENABLED:
		g_value_set_boolean (value, nm_client_connectivity_check_get_enabled (self));
		break;
	case PROP_PRIMARY_CONNECTION:
		g_value_set_object (value, nm_client_get_primary_connection (self));
		break;
	case PROP_ACTIVATING_CONNECTION:
		g_value_set_object (value, nm_client_get_activating_connection (self));
		break;
	case PROP_DEVICES:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_client_get_devices (self)));
		break;
	case PROP_METERED:
		if (priv->manager)
			g_object_get_property (G_OBJECT (priv->manager), pspec->name, value);
		else
			g_value_set_uint (value, NM_METERED_UNKNOWN);
		break;
	case PROP_ALL_DEVICES:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_client_get_all_devices (self)));
		break;
	case PROP_CHECKPOINTS:
		if (priv->manager)
			g_object_get_property (G_OBJECT (priv->manager), pspec->name, value);
		else
			g_value_take_boxed (value, g_ptr_array_new ());
		break;

	/* Settings properties. */
	case PROP_CONNECTIONS:
		if (priv->settings)
			g_object_get_property (G_OBJECT (priv->settings), pspec->name, value);
		else
			g_value_take_boxed (value, _nm_utils_copy_object_array (&empty));
		break;
	case PROP_HOSTNAME:
		if (priv->settings)
			g_object_get_property (G_OBJECT (priv->settings), pspec->name, value);
		else
			g_value_set_string (value, NULL);
		break;
	case PROP_CAN_MODIFY:
		if (priv->settings)
			g_object_get_property (G_OBJECT (priv->settings), pspec->name, value);
		else
			g_value_set_boolean (value, FALSE);
		break;

	/* DNS properties */
	case PROP_DNS_MODE:
	case PROP_DNS_RC_MANAGER:
		g_return_if_fail (pspec->name && strlen (pspec->name) > NM_STRLEN ("dns-"));
		if (priv->dns_manager)
			g_object_get_property (G_OBJECT (priv->dns_manager),
			                       &pspec->name[NM_STRLEN ("dns-")], value);
		else
			g_value_set_string (value, NULL);
		break;
	case PROP_DNS_CONFIGURATION:
		if (priv->dns_manager) {
			g_object_get_property (G_OBJECT (priv->dns_manager),
			                       NM_DNS_MANAGER_CONFIGURATION,
			                       value);
		} else
			g_value_take_boxed (value, NULL);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_client_class_init (NMClientClass *client_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (client_class);

	g_type_class_add_private (client_class, sizeof (NMClientPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	/* properties */

	/**
	 * NMClient:version:
	 *
	 * The NetworkManager version.
	 **/
	g_object_class_install_property
		(object_class, PROP_VERSION,
		 g_param_spec_string (NM_CLIENT_VERSION, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:state:
	 *
	 * The current daemon state.
	 **/
	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_enum (NM_CLIENT_STATE, "", "",
		                    NM_TYPE_STATE,
		                    NM_STATE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:startup:
	 *
	 * Whether the daemon is still starting up.
	 **/
	g_object_class_install_property
		(object_class, PROP_STARTUP,
		 g_param_spec_boolean (NM_CLIENT_STARTUP, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:nm-running:
	 *
	 * Whether the daemon is running.
	 **/
	g_object_class_install_property
		(object_class, PROP_NM_RUNNING,
		 g_param_spec_boolean (NM_CLIENT_NM_RUNNING, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:networking-enabled:
	 *
	 * Whether networking is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_NETWORKING_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_NETWORKING_ENABLED, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:wireless-enabled:
	 *
	 * Whether wireless is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WIRELESS_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WIRELESS_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:wireless-hardware-enabled:
	 *
	 * Whether the wireless hardware is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WIRELESS_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WIRELESS_HARDWARE_ENABLED, "", "",
		                       TRUE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:wwan-enabled:
	 *
	 * Whether WWAN functionality is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WWAN_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WWAN_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:wwan-hardware-enabled:
	 *
	 * Whether the WWAN hardware is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WWAN_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WWAN_HARDWARE_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:wimax-enabled:
	 *
	 * Whether WiMAX functionality is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WIMAX_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WIMAX_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:wimax-hardware-enabled:
	 *
	 * Whether the WiMAX hardware is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WIMAX_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WIMAX_HARDWARE_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:active-connections: (type GPtrArray(NMActiveConnection))
	 *
	 * The active connections.
	 **/
	g_object_class_install_property
		(object_class, PROP_ACTIVE_CONNECTIONS,
		 g_param_spec_boxed (NM_CLIENT_ACTIVE_CONNECTIONS, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:connectivity:
	 *
	 * The network connectivity state.
	 */
	g_object_class_install_property
		(object_class, PROP_CONNECTIVITY,
		 g_param_spec_enum (NM_CLIENT_CONNECTIVITY, "", "",
		                    NM_TYPE_CONNECTIVITY_STATE,
		                    NM_CONNECTIVITY_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient::connectivity-check-available
	 *
	 * Whether a connectivity checking service has been configured.
	 *
	 * Since: 1.10
	 */
	g_object_class_install_property
		(object_class, PROP_CONNECTIVITY_CHECK_AVAILABLE,
		 g_param_spec_boolean (NM_CLIENT_CONNECTIVITY_CHECK_AVAILABLE, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient::connectivity-check-enabled
	 *
	 * Whether a connectivity checking service has been enabled.
	 *
	 * Since: 1.10
	 */
	g_object_class_install_property
		(object_class, PROP_CONNECTIVITY_CHECK_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_CONNECTIVITY_CHECK_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:primary-connection:
	 *
	 * The #NMActiveConnection of the device with the default route;
	 * see nm_client_get_primary_connection() for more details.
	 **/
	g_object_class_install_property
		(object_class, PROP_PRIMARY_CONNECTION,
		 g_param_spec_object (NM_CLIENT_PRIMARY_CONNECTION, "", "",
		                      NM_TYPE_ACTIVE_CONNECTION,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:activating-connection:
	 *
	 * The #NMActiveConnection of the activating connection that is
	 * likely to become the new #NMClient:primary-connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_ACTIVATING_CONNECTION,
		 g_param_spec_object (NM_CLIENT_ACTIVATING_CONNECTION, "", "",
		                      NM_TYPE_ACTIVE_CONNECTION,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:devices: (type GPtrArray(NMDevice))
	 *
	 * List of real network devices.  Does not include placeholder devices.
	 **/
	g_object_class_install_property
		(object_class, PROP_DEVICES,
		 g_param_spec_boxed (NM_CLIENT_DEVICES, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:all-devices: (type GPtrArray(NMDevice))
	 *
	 * List of both real devices and device placeholders.
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_ALL_DEVICES,
		 g_param_spec_boxed (NM_CLIENT_ALL_DEVICES, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:connections: (type GPtrArray(NMRemoteConnection))
	 *
	 * The list of configured connections that are available to the user. (Note
	 * that this differs from the underlying D-Bus property, which may also
	 * contain the object paths of connections that the user does not have
	 * permission to read the details of.)
	 */
	g_object_class_install_property
		(object_class, PROP_CONNECTIONS,
		 g_param_spec_boxed (NM_CLIENT_CONNECTIONS, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:hostname:
	 *
	 * The machine hostname stored in persistent configuration. This can be
	 * modified by calling nm_client_save_hostname().
	 */
	g_object_class_install_property
		(object_class, PROP_HOSTNAME,
		 g_param_spec_string (NM_CLIENT_HOSTNAME, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:can-modify:
	 *
	 * If %TRUE, adding and modifying connections is supported.
	 */
	g_object_class_install_property
		(object_class, PROP_CAN_MODIFY,
		 g_param_spec_boolean (NM_CLIENT_CAN_MODIFY, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:metered:
	 *
	 * Whether the connectivity is metered.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_METERED,
		 g_param_spec_uint (NM_CLIENT_METERED, "", "",
		                    0, G_MAXUINT32, NM_METERED_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:dns-mode:
	 *
	 * The current DNS processing mode.
	 *
	 * Since: 1.6
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS_MODE,
		 g_param_spec_string (NM_CLIENT_DNS_MODE, "", "",
		                      "",
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:dns-rc-manager:
	 *
	 * The current resolv.conf management mode.
	 *
	 * Since: 1.6
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS_RC_MANAGER,
		 g_param_spec_string (NM_CLIENT_DNS_RC_MANAGER, "", "",
		                      "",
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:dns-configuration: (type GPtrArray(NMDnsEntry))
	 *
	 * The current DNS configuration, represented as an array
	 * of #NMDnsEntry objects.
	 *
	 * Since: 1.6
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS_CONFIGURATION,
		 g_param_spec_boxed (NM_CLIENT_DNS_CONFIGURATION, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:checkpoints: (type GPtrArray(NMCheckpoint))
	 *
	 * The list of active checkpoints.
	 *
	 * Since: 1.12
	 */
	g_object_class_install_property
		(object_class, PROP_CHECKPOINTS,
		 g_param_spec_boxed (NM_MANAGER_CHECKPOINTS, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/* signals */

	/**
	 * NMClient::device-added:
	 * @client: the client that received the signal
	 * @device: (type NMDevice): the new device
	 *
	 * Notifies that a #NMDevice is added.  This signal is not emitted for
	 * placeholder devices.
	 **/
	signals[DEVICE_ADDED] =
		g_signal_new (NM_CLIENT_DEVICE_ADDED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMClientClass, device_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	/**
	 * NMClient::device-removed:
	 * @client: the client that received the signal
	 * @device: (type NMDevice): the removed device
	 *
	 * Notifies that a #NMDevice is removed.  This signal is not emitted for
	 * placeholder devices.
	 **/
	signals[DEVICE_REMOVED] =
		g_signal_new (NM_CLIENT_DEVICE_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMClientClass, device_removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	/**
	 * NMClient::any-device-added:
	 * @client: the client that received the signal
	 * @device: (type NMDevice): the new device
	 *
	 * Notifies that a #NMDevice is added.  This signal is emitted for both
	 * regular devices and placeholder devices.
	 **/
	signals[ANY_DEVICE_ADDED] =
		g_signal_new (NM_CLIENT_ANY_DEVICE_ADDED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMClientClass, any_device_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	/**
	 * NMClient::any-device-removed:
	 * @client: the client that received the signal
	 * @device: (type NMDevice): the removed device
	 *
	 * Notifies that a #NMDevice is removed.  This signal is emitted for both
	 * regular devices and placeholder devices.
	 **/
	signals[ANY_DEVICE_REMOVED] =
		g_signal_new (NM_CLIENT_ANY_DEVICE_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMClientClass, any_device_removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	/**
	 * NMClient::permission-changed:
	 * @client: the client that received the signal
	 * @permission: a permission from #NMClientPermission
	 * @result: the permission's result, one of #NMClientPermissionResult
	 *
	 * Notifies that a permission has changed
	 **/
	signals[PERMISSION_CHANGED] =
		g_signal_new (NM_CLIENT_PERMISSION_CHANGED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);
	/**
	 * NMClient::connection-added:
	 * @client: the settings object that received the signal
	 * @connection: the new connection
	 *
	 * Notifies that a #NMConnection has been added.
	 **/
	signals[CONNECTION_ADDED] =
		g_signal_new (NM_CLIENT_CONNECTION_ADDED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMClientClass, connection_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              NM_TYPE_REMOTE_CONNECTION);

	/**
	 * NMClient::connection-removed:
	 * @client: the settings object that received the signal
	 * @connection: the removed connection
	 *
	 * Notifies that a #NMConnection has been removed.
	 **/
	signals[CONNECTION_REMOVED] =
		g_signal_new (NM_CLIENT_CONNECTION_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMClientClass, connection_removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              NM_TYPE_REMOTE_CONNECTION);

	/**
	 * NMClient::active-connection-added:
	 * @client: the settings object that received the signal
	 * @active_connection: the new active connection
	 *
	 * Notifies that a #NMActiveConnection has been added.
	 **/
	signals[ACTIVE_CONNECTION_ADDED] =
		g_signal_new (NM_CLIENT_ACTIVE_CONNECTION_ADDED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              NM_TYPE_ACTIVE_CONNECTION);

	/**
	 * NMClient::active-connection-removed:
	 * @client: the settings object that received the signal
	 * @active_connection: the removed active connection
	 *
	 * Notifies that a #NMActiveConnection has been removed.
	 **/
	signals[ACTIVE_CONNECTION_REMOVED] =
		g_signal_new (NM_CLIENT_ACTIVE_CONNECTION_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              NM_TYPE_ACTIVE_CONNECTION);
}

static void
nm_client_initable_iface_init (GInitableIface *iface)
{
	iface->init = init_sync;
}

static void
nm_client_async_initable_iface_init (GAsyncInitableIface *iface)
{
	iface->init_async = init_async;
	iface->init_finish = init_finish;
}

/*****************************************************************************
 * Backported symbols. Usually, new API is only added in new major versions
 * of NetworkManager (that is, on "master" branch). Sometimes however, we might
 * have to backport some API to an older stable branch. In that case, we backport
 * the symbols with a different version corresponding to the minor API.
 *
 * To allow upgrading from such a extended minor-release, "master" contains these
 * backported symbols too.
 *
 * For example, 1.2.0 added nm_setting_connection_autoconnect_slaves_get_type.
 * This was backported for 1.0.4 as nm_setting_connection_autoconnect_slaves_get_type@libnm_1_0_4
 * To allow an application that was linked against 1.0.4 to seamlessly upgrade to
 * a newer major version, the same symbols is also exposed on "master". Note, that
 * a user can only seamlessly upgrade to a newer major version, that is released
 * *after* 1.0.4 is out. In this example, 1.2.0 was released after 1.4.0, and thus
 * a 1.0.4 user can upgrade to 1.2.0 ABI.
 *****************************************************************************/

NM_BACKPORT_SYMBOL (libnm_1_0_4, NMSettingConnectionAutoconnectSlaves, nm_setting_connection_get_autoconnect_slaves, (NMSettingConnection *setting), (setting));

NM_BACKPORT_SYMBOL (libnm_1_0_4, GType, nm_setting_connection_autoconnect_slaves_get_type, (void), ());

NM_BACKPORT_SYMBOL (libnm_1_0_6, NMMetered, nm_setting_connection_get_metered, (NMSettingConnection *setting), (setting));

NM_BACKPORT_SYMBOL (libnm_1_0_6, GType, nm_metered_get_type, (void), ());

NM_BACKPORT_SYMBOL (libnm_1_0_6, NMSettingWiredWakeOnLan, nm_setting_wired_get_wake_on_lan,
                    (NMSettingWired *setting), (setting));

NM_BACKPORT_SYMBOL (libnm_1_0_6, const char *, nm_setting_wired_get_wake_on_lan_password,
                    (NMSettingWired *setting), (setting));

NM_BACKPORT_SYMBOL (libnm_1_0_6, GType, nm_setting_wired_wake_on_lan_get_type, (void), ());

NM_BACKPORT_SYMBOL (libnm_1_0_6, const guint *, nm_utils_wifi_2ghz_freqs, (void), ());

NM_BACKPORT_SYMBOL (libnm_1_0_6, const guint *, nm_utils_wifi_5ghz_freqs, (void), ());

NM_BACKPORT_SYMBOL (libnm_1_0_6, char *, nm_utils_enum_to_str,
                    (GType type, int value), (type, value));

NM_BACKPORT_SYMBOL (libnm_1_0_6, gboolean, nm_utils_enum_from_str,
                    (GType type, const char *str, int *out_value, char **err_token),
                    (type, str, out_value, err_token));

NM_BACKPORT_SYMBOL (libnm_1_2_4, int, nm_setting_ip_config_get_dns_priority, (NMSettingIPConfig *setting), (setting));

NM_BACKPORT_SYMBOL (libnm_1_10_14, NMSettingConnectionMdns, nm_setting_connection_get_mdns,
                    (NMSettingConnection *setting), (setting));
NM_BACKPORT_SYMBOL (libnm_1_10_14, GType, nm_setting_connection_mdns_get_type, (void), ());
