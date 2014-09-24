/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright 2007 - 2014 Red Hat, Inc.
 */

#include <string.h>
#include <nm-utils.h>

#include "nm-client.h"
#include "nm-manager.h"
#include "nm-device-ethernet.h"
#include "nm-device-wifi.h"
#include "nm-device-private.h"
#include "nm-core-internal.h"
#include "nm-active-connection.h"
#include "nm-vpn-connection.h"
#include "nm-object-cache.h"
#include "nm-glib-compat.h"
#include "nm-dbus-helpers.h"

void _nm_device_wifi_set_wireless_enabled (NMDeviceWifi *device, gboolean enabled);

static void nm_client_initable_iface_init (GInitableIface *iface);
static void nm_client_async_initable_iface_init (GAsyncInitableIface *iface);
static GInitableIface *nm_client_parent_initable_iface;
static GAsyncInitableIface *nm_client_parent_async_initable_iface;

G_DEFINE_TYPE_WITH_CODE (NMClient, nm_client, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_client_initable_iface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_client_async_initable_iface_init);
                         )

#define NM_CLIENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CLIENT, NMClientPrivate))

typedef struct {
	NMManager *manager;
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
	PROP_PRIMARY_CONNECTION,
	PROP_ACTIVATING_CONNECTION,
	PROP_DEVICES,

	LAST_PROP
};

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	PERMISSION_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/**********************************************************************/

/**
 * nm_client_error_quark:
 *
 * Registers an error quark for #NMClient if necessary.
 *
 * Returns: the error quark used for #NMClient errors.
 **/
GQuark
nm_client_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-client-error-quark");
	return quark;
}

/**********************************************************************/

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
	g_return_val_if_fail (NM_IS_CLIENT (client), NM_STATE_UNKNOWN);

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

	return nm_manager_get_nm_running (NM_CLIENT_GET_PRIVATE (client)->manager);
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

	if (!_nm_client_check_nm_running (client, NULL))
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

	if (!_nm_client_check_nm_running (client, NULL))
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

	return nm_manager_wimax_hardware_get_enabled (NM_CLIENT_GET_PRIVATE (client)->manager);
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
	g_return_val_if_fail (NM_IS_CLIENT (client), NM_STATE_UNKNOWN);

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

/****************************************************************/
/* Devices                                                      */
/****************************************************************/

/**
 * nm_client_get_devices:
 * @client: a #NMClient
 *
 * Gets all the known network devices.  Use nm_device_get_type() or the
 * NM_IS_DEVICE_XXXX() functions to determine what kind of device member of the
 * returned array is, and then you may use device-specific methods such as
 * nm_device_ethernet_get_hw_address().
 *
 * Returns: (transfer none) (element-type NMDevice): a #GPtrArray
 * containing all the #NMDevices.  The returned array is owned by the
 * #NMClient object and should not be modified.
 **/
const GPtrArray *
nm_client_get_devices (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return nm_manager_get_devices (NM_CLIENT_GET_PRIVATE (client)->manager);
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

	return nm_manager_get_device_by_iface (NM_CLIENT_GET_PRIVATE (client)->manager, iface);
}

/****************************************************************/
/* Active Connections                                           */
/****************************************************************/

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
 * the new connection, not when it finishes. You can used the returned
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
	GSimpleAsyncResult *simple = user_data;
	NMActiveConnection *ac;
	GError *error = NULL;

	ac = nm_manager_add_and_activate_connection_finish (NM_MANAGER (object), result, &error);
	if (ac)
		g_simple_async_result_set_op_res_gpointer (simple, ac, g_object_unref);
	else
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
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
	nm_manager_add_and_activate_connection_async (NM_CLIENT_GET_PRIVATE (client)->manager,
	                                              partial, device, specific_object,
	                                              cancellable, add_activate_cb, simple);
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

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));
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

	if (!_nm_client_check_nm_running (client, NULL))
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

/****************************************************************/

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
 * NOTE: #NMClient provides information about devices and a mechanism to
 * control them.  To access and modify network configuration data, use the
 * #NMRemoteSettings object.
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
 *
 * NOTE: #NMClient provides information about devices and a mechanism to
 * control them.  To access and modify network configuration data, use the
 * #NMRemoteSettings object.
 **/
void
nm_client_new_async (GCancellable *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
	GSimpleAsyncResult *simple;

	simple = g_simple_async_result_new (NULL, callback, user_data, nm_client_new_async);

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

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!result) {
		g_set_error_literal (error,
		                     NM_CLIENT_ERROR,
		                     NM_CLIENT_ERROR_UNKNOWN,
		                     "NMClient initialization failed (or you passed NULL 'result' by mistake)");
		return NULL;
	}

	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL, nm_client_new_async), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));
}

static void
manager_notify (GObject *object,
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
manager_permission_changed (NMManager *manager,
                            NMClientPermission permission,
                            NMClientPermissionResult result,
                            gpointer client)
{
	g_signal_emit (client, signals[PERMISSION_CHANGED], 0, permission, result);
}

static void
constructed (GObject *object)
{
	NMClient *client = NM_CLIENT (object);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);

	priv->manager = g_object_new (NM_TYPE_MANAGER,
	                              NM_OBJECT_PATH, NM_DBUS_PATH,
	                              NULL);

	g_signal_connect (priv->manager, "notify",
	                  G_CALLBACK (manager_notify), client);
	g_signal_connect (priv->manager, "device-added",
	                  G_CALLBACK (manager_device_added), client);
	g_signal_connect (priv->manager, "device-removed",
	                  G_CALLBACK (manager_device_removed), client);
	g_signal_connect (priv->manager, "permission-changed",
	                  G_CALLBACK (manager_permission_changed), client);

	G_OBJECT_CLASS (nm_client_parent_class)->constructed (object);
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMClient *client = NM_CLIENT (initable);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);

	if (!g_initable_init (G_INITABLE (priv->manager), cancellable, error))
		return FALSE;

	return TRUE;
}

typedef struct {
	NMClient *client;
	GCancellable *cancellable;
	GSimpleAsyncResult *result;
} NMClientInitData;

static void
init_async_complete (NMClientInitData *init_data)
{
	g_simple_async_result_complete (init_data->result);
	g_object_unref (init_data->result);
	g_clear_object (&init_data->cancellable);
	g_slice_free (NMClientInitData, init_data);
}

static void
init_async_inited_manager (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMClientInitData *init_data = user_data;
	GError *error = NULL;

	if (g_async_initable_init_finish (G_ASYNC_INITABLE (object), result, &error))
		g_simple_async_result_set_op_res_gboolean (init_data->result, TRUE);
	else
		g_simple_async_result_take_error (init_data->result, error);

	init_async_complete (init_data);
}

static void
init_async_parent_inited (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMClientInitData *init_data = user_data;
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (init_data->client);
	GError *error = NULL;

	if (!nm_client_parent_async_initable_iface->init_finish (G_ASYNC_INITABLE (source), result, &error)) {
		g_simple_async_result_take_error (init_data->result, error);
		init_async_complete (init_data);
		return;
	}

	g_async_initable_init_async (G_ASYNC_INITABLE (priv->manager),
	                             G_PRIORITY_DEFAULT, init_data->cancellable,
	                             init_async_inited_manager, init_data);
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMClientInitData *init_data;
	GError *error = NULL;

	if (!nm_utils_init (&error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (initable),
		                                           callback, user_data, error);
		return;
	}

	init_data = g_slice_new0 (NMClientInitData);
	init_data->client = NM_CLIENT (initable);
	init_data->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	init_data->result = g_simple_async_result_new (G_OBJECT (initable), callback,
	                                               user_data, init_async);
	g_simple_async_result_set_op_res_gboolean (init_data->result, TRUE);

	nm_client_parent_async_initable_iface->init_async (initable, io_priority, cancellable,
	                                                   init_async_parent_inited, init_data);
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

	g_clear_object (&priv->manager);

	G_OBJECT_CLASS (nm_client_parent_class)->dispose (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_NETWORKING_ENABLED:
	case PROP_WIRELESS_ENABLED:
	case PROP_WWAN_ENABLED:
	case PROP_WIMAX_ENABLED:
		g_object_set_property (G_OBJECT (NM_CLIENT_GET_PRIVATE (object)->manager),
		                       pspec->name, value);
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
	switch (prop_id) {
	case PROP_VERSION:
	case PROP_STATE:
	case PROP_STARTUP:
	case PROP_NM_RUNNING:
	case PROP_NETWORKING_ENABLED:
	case PROP_WIRELESS_ENABLED:
	case PROP_WIRELESS_HARDWARE_ENABLED:
	case PROP_WWAN_ENABLED:
	case PROP_WWAN_HARDWARE_ENABLED:
	case PROP_WIMAX_ENABLED:
	case PROP_WIMAX_HARDWARE_ENABLED:
	case PROP_ACTIVE_CONNECTIONS:
	case PROP_CONNECTIVITY:
	case PROP_PRIMARY_CONNECTION:
	case PROP_ACTIVATING_CONNECTION:
	case PROP_DEVICES:
		g_object_get_property (G_OBJECT (NM_CLIENT_GET_PRIVATE (object)->manager),
		                       pspec->name, value);
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
	object_class->constructed = constructed;
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
	 * NMClient:active-connections:
	 *
	 * The active connections.
	 *
	 * Element-type: NMActiveConnection
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
	 * NMClient:devices:
	 *
	 * List of known network devices.
	 *
	 * Element-type: NMDevice
	 **/
	g_object_class_install_property
		(object_class, PROP_DEVICES,
		 g_param_spec_boxed (NM_CLIENT_DEVICES, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/* signals */

	/**
	 * NMClient::device-added:
	 * @client: the client that received the signal
	 * @device: (type NMDevice): the new device
	 *
	 * Notifies that a #NMDevice is added.
	 **/
	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
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
	 * Notifies that a #NMDevice is removed.
	 **/
	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMClientClass, device_removed),
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
		g_signal_new ("permission-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);
}

static void
nm_client_initable_iface_init (GInitableIface *iface)
{
	nm_client_parent_initable_iface = g_type_interface_peek_parent (iface);

	iface->init = init_sync;
}

static void
nm_client_async_initable_iface_init (GAsyncInitableIface *iface)
{
	nm_client_parent_async_initable_iface = g_type_interface_peek_parent (iface);

	iface->init_async = init_async;
	iface->init_finish = init_finish;
}
