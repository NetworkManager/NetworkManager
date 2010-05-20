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
 * Copyright (C) 2009 Novell, Inc.
 */

#include <string.h>
#include <WiMaxAPI.h>
#include <WiMaxAPIEx.h>

#include "nm-wimax-device.h"
#include "nm-wimax-util.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-system.h"
#include "NetworkManagerUtils.h"
#include "nm-properties-changed-signal.h"
#include "nm-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-wimax.h"
#include "nm-utils.h"

static gboolean impl_device_get_nsp_list (NMWimaxDevice *device, GPtrArray **list, GError **error);

#include "nm-wimax-device-glue.h"

static void device_interface_init (NMDeviceInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (NMWimaxDevice, nm_wimax_device, NM_TYPE_DEVICE, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_DEVICE_INTERFACE, device_interface_init))

enum {
	PROP_0,
	PROP_INDEX,
	PROP_HW_ADDRESS,
	PROP_ACTIVE_NSP,

	LAST_PROP
};

enum {
	NSP_ADDED,
	NSP_REMOVED,
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

#define GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_WIMAX_DEVICE, NMWimaxDevicePrivate))

typedef struct {
	WIMAX_API_DEVICE_ID device_id;
	NMWimaxDevice *object;

	gboolean enabled;
	struct ether_addr hw_addr;
	guint activation_timeout_id;

	GSList *nsp_list;
	NMWimaxNsp *current_nsp;
	guint rf_update_id;
} NMWimaxDevicePrivate;

static void nm_wimax_api_close (NMWimaxDevice *self);
static gboolean nm_wimax_api_open (NMWimaxDevice *self);
static void real_update_hw_address (NMDevice *device);

typedef enum
{
	NM_WIMAX_ERROR_CONNECTION_NOT_WIMAX = 0,
	NM_WIMAX_ERROR_CONNECTION_INVALID,
	NM_WIMAX_ERROR_CONNECTION_INCOMPATIBLE,
} NMWimaxError;

#define NM_WIMAX_ERROR (nm_wimax_error_quark ())
#define NM_TYPE_WIMAX_ERROR (nm_wimax_error_get_type ()) 

static GQuark
nm_wimax_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-wimax-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_wimax_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Connection was not a wired connection. */
			ENUM_ENTRY (NM_WIMAX_ERROR_CONNECTION_NOT_WIMAX, "ConnectionNotWimax"),
			/* Connection was not a valid wired connection. */
			ENUM_ENTRY (NM_WIMAX_ERROR_CONNECTION_INVALID, "ConnectionInvalid"),
			/* Connection does not apply to this device. */
			ENUM_ENTRY (NM_WIMAX_ERROR_CONNECTION_INCOMPATIBLE, "ConnectionIncompatible"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMWimaxError", values);
	}
	return etype;
}


NMDevice *
nm_wimax_device_new (const char *udi,
					 const char *iface,
					 const char *driver,
					 guchar wimax_device_index)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);
	g_return_val_if_fail (wimax_device_index != 0, NULL);

	return NM_DEVICE (g_object_new (NM_TYPE_WIMAX_DEVICE,
									NM_DEVICE_INTERFACE_UDI, udi,
									NM_DEVICE_INTERFACE_IFACE, iface,
									NM_DEVICE_INTERFACE_DRIVER, driver,
									NM_DEVICE_INTERFACE_TYPE_DESC, "WiMAX",
									NM_DEVICE_INTERFACE_DEVICE_TYPE, NM_DEVICE_TYPE_WIMAX,
									NM_WIMAX_DEVICE_INDEX, wimax_device_index,
									NULL));
}

void
nm_wimax_device_get_hw_address (NMWimaxDevice *self, struct ether_addr *addr)
{
	g_return_if_fail (NM_IS_WIMAX_DEVICE (self));
	g_return_if_fail (addr != NULL);

	memcpy (addr, &(GET_PRIVATE (self)->hw_addr), sizeof (struct ether_addr));
}

static gboolean
rf_state_update (NMWimaxDevice *self)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (self);
	WIMAX_API_DEVICE_STATUS status;
	WIMAX_API_CONNECTION_PROGRESS_INFO pi;
	WIMAX_API_RET result;
	gboolean enable;

	priv->rf_update_id = 0;

	enable = priv->enabled;
	if (enable) {
		if (nm_device_interface_get_state (NM_DEVICE_INTERFACE (self)) < NM_DEVICE_STATE_UNAVAILABLE)
			enable = FALSE;
	}

	result = GetDeviceStatus (&priv->device_id, &status, &pi);
	if (result != WIMAX_API_RET_SUCCESS)
		nm_wimax_util_error (&priv->device_id, "Reading WiMax device status failed", result);

	switch (status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
		/* Can not enable the device */
		if (enable)
			nm_warning ("Can not enable the WiMAX device, it's RF killed");
		goto out;
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		if (!enable)
			/* Already matches */
			goto out;
		break;
	case WIMAX_API_DEVICE_STATUS_Ready:
	case WIMAX_API_DEVICE_STATUS_Scanning:
	case WIMAX_API_DEVICE_STATUS_Connecting:
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
		if (enable)
			/* Already matches */
			goto out;
		break;
	default:
		nm_warning ("Unhandled WiMAX device state");
		goto out;
	}

	g_debug ("Changing wimax device RF state: %d", enable);
	result = CmdControlPowerManagement (&priv->device_id, enable ? WIMAX_API_RF_ON : WIMAX_API_RF_OFF);
	if (result != WIMAX_API_RET_SUCCESS)
		nm_wimax_util_error (&priv->device_id, "WiMax device RF change failed", result);

 out:
	return FALSE;
}

static void
schedule_rf_state_update (NMWimaxDevice *self)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (self);

	/* This is scheduled because on startup we get nm_device_interface_set_enabled()
	   while the device state is still unmanaged. It'll change to unavailable right
	   after it, so it would result in enabling RF kill, followed by disabling it again.
	   Pretty lame.
	*/

	if (priv->rf_update_id == 0)
		priv->rf_update_id = g_idle_add ((GSourceFunc) rf_state_update, self);
}

GSList *
nm_wimax_device_get_nsps (NMWimaxDevice *self)
{
	g_return_val_if_fail (NM_IS_WIMAX_DEVICE (self), NULL);

	return GET_PRIVATE (self)->nsp_list;
}

static gboolean
impl_device_get_nsp_list (NMWimaxDevice *device, GPtrArray **nsps, GError **error)
{
	GSList *list;
	GSList *iter;

	list = nm_wimax_device_get_nsps (device);
	*nsps = g_ptr_array_sized_new (g_slist_length (list));
	for (iter = list; iter; iter = iter->next) {
		const char *path;

		path = nm_wimax_nsp_get_dbus_path (NM_WIMAX_NSP (iter->data));
		if (path)
			g_ptr_array_add (*nsps, g_strdup (path));
	}

	return TRUE;
}

static void
set_current_nsp (NMWimaxDevice *self, NMWimaxNsp *new_nsp)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (self);
	NMWimaxNsp *old_nsp;
	char *old_path = NULL;

	old_nsp = priv->current_nsp;
	if (old_nsp) {
		old_path = g_strdup (nm_wimax_nsp_get_dbus_path (old_nsp));
		priv->current_nsp = NULL;
	}

	if (new_nsp)
		priv->current_nsp = g_object_ref (new_nsp);

	if (old_nsp)
		g_object_unref (old_nsp);

	/* Only notify if it's really changed */
	if ((!old_path && new_nsp)
		|| (old_path && !new_nsp)
	    || (old_path && new_nsp && strcmp (old_path, nm_wimax_nsp_get_dbus_path (new_nsp))))
		g_object_notify (G_OBJECT (self), NM_WIMAX_DEVICE_ACTIVE_NSP);

	g_free (old_path);
}

NMWimaxNsp *
nm_wimax_device_get_active_nsp (NMWimaxDevice *self)
{
	g_return_val_if_fail (NM_IS_WIMAX_DEVICE (self), NULL);

	return GET_PRIVATE (self)->current_nsp;
}

static gboolean
activation_timed_out (gpointer data)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (data);

	priv->activation_timeout_id = 0;
	nm_device_state_changed (NM_DEVICE (data), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_CONFIG_FAILED);

	return FALSE;
}

static void
wimax_status_change_cb (WIMAX_API_DEVICE_ID *device_id,
						WIMAX_API_DEVICE_STATUS status,
						WIMAX_API_STATUS_REASON reason,
						WIMAX_API_CONNECTION_PROGRESS_INFO progress)
{
	NMWimaxDevicePrivate *priv = (NMWimaxDevicePrivate *) device_id;
	NMWimaxDevice *self = priv->object;
	NMDeviceState device_state;

	device_state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (self));
	g_debug ("wimax status changed: %s (device state %d)", nm_wimax_util_device_status_to_str (status), device_state);

	switch (status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		priv->enabled = FALSE;
		if (device_state >= NM_DEVICE_STATE_DISCONNECTED)
			nm_device_state_changed (NM_DEVICE (self),
									 NM_DEVICE_STATE_UNAVAILABLE,
									 NM_DEVICE_STATE_REASON_NONE);
		break;
	case WIMAX_API_DEVICE_STATUS_Ready:
	case WIMAX_API_DEVICE_STATUS_Scanning:
	case WIMAX_API_DEVICE_STATUS_Connecting:
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
		priv->enabled = TRUE;
		if (device_state < NM_DEVICE_STATE_DISCONNECTED)
			nm_device_state_changed (NM_DEVICE (self),
									 NM_DEVICE_STATE_DISCONNECTED,
									 NM_DEVICE_STATE_REASON_NONE);
		break;
	default:
		nm_warning ("Unhandled WiMAX device state");
	}
}

static void
remove_all_nsps (NMWimaxDevice *self)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (self);

	while (g_slist_length (priv->nsp_list)) {
		NMWimaxNsp *nsp = NM_WIMAX_NSP (priv->nsp_list->data);

		priv->nsp_list = g_slist_remove (priv->nsp_list, nsp);
		g_signal_emit (self, signals[NSP_REMOVED], 0, nsp);
		g_object_unref (nsp);
	}

	g_slist_free (priv->nsp_list);
	priv->nsp_list = NULL;
}

static void
remove_outdated_nsps (NMWimaxDevice *self,
					  WIMAX_API_NSP_INFO_EX *nsp_list,
					  guint32 list_size)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (self);
	GSList *iter;
	GSList *to_remove = NULL;

	for (iter = priv->nsp_list; iter; iter = iter->next) {
		NMWimaxNsp *nsp = NM_WIMAX_NSP (iter->data);
		int i;
		gboolean found = FALSE;

		for (i = 0; i < list_size; i++) {
			WIMAX_API_NSP_INFO_EX *info = &nsp_list[i];

			if (!g_strcmp0 (nm_wimax_nsp_get_name (nsp), (char *) info->NSPName)) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			to_remove = g_slist_prepend (to_remove, nsp);
	}

	for (iter = to_remove; iter; iter = iter->next) {
		NMWimaxNsp *nsp = NM_WIMAX_NSP (iter->data);

		g_signal_emit (self, signals[NSP_REMOVED], 0, nsp);
		priv->nsp_list = g_slist_remove (priv->nsp_list, nsp);
		g_object_unref (nsp);
	}

	g_slist_free (to_remove);
}

static NMWimaxNsp *
get_nsp_by_name (NMWimaxDevice *self, const char *name)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->nsp_list; iter; iter = iter->next) {
		NMWimaxNsp *nsp = NM_WIMAX_NSP (iter->data);
	
		if (!g_strcmp0 (nm_wimax_nsp_get_name (nsp), name))
			return nsp;
	}

	return NULL;
}

static void
wimax_scan_cb (WIMAX_API_DEVICE_ID *device_id,
			   WIMAX_API_NSP_INFO_EX *nsp_list,
			   guint32 list_size,
			   guint32 progress)
{
	NMWimaxDevicePrivate *priv = (NMWimaxDevicePrivate *) device_id;
	NMWimaxDevice *self = NM_WIMAX_DEVICE (priv->object);
	int i;

	remove_outdated_nsps (self, nsp_list, list_size);

	for (i = 0; i < list_size; i++) {
		WIMAX_API_NSP_INFO_EX *info = &nsp_list[i];
		NMWimaxNsp *nsp;
		gboolean new_nsp;
		guint32 quality;
	
		nsp = get_nsp_by_name (self, (char *) info->NSPName);
		new_nsp = nsp == NULL;
		if (new_nsp)
			nsp = nm_wimax_nsp_new ((char *) info->NSPName);

		quality = info->linkQuality;
		if (quality == 0) {
			/* This is borrowed from connman */
			quality = nm_wimax_util_cinr_to_percentage (info->CINR - 10);
		}

		g_object_set (nsp,
					  NM_WIMAX_NSP_SIGNAL_QUALITY, quality,
					  NM_WIMAX_NSP_NETWORK_TYPE, nm_wimax_util_convert_network_type (info->networkType),
					  NULL);

		if (new_nsp) {
			priv->nsp_list = g_slist_append (priv->nsp_list, nsp);
			nm_wimax_nsp_export_to_dbus (nsp);
			g_signal_emit (self, signals[NSP_ADDED], 0, nsp);
		}
	}
}

static void
wimax_wide_scan_cb (WIMAX_API_DEVICE_ID *device_id,
					WIMAX_API_NSP_INFO_EX *nsp_list,
					guint32 list_size)
{
	wimax_scan_cb (device_id, nsp_list, list_size, 0);
}

static void
wimax_connect_cb (WIMAX_API_DEVICE_ID *device_id,
				  WIMAX_API_NETWORK_CONNECTION_RESP response)
{
	NMWimaxDevicePrivate *priv = (NMWimaxDevicePrivate *) device_id;
	NMWimaxDevice *self = NM_WIMAX_DEVICE (priv->object);

	if (priv->activation_timeout_id == 0) {
		g_warning ("WiMax device activated from outside");
		return;
	}

	g_source_remove (priv->activation_timeout_id);
	priv->activation_timeout_id = 0;

	if (response == WIMAX_API_CONNECTION_SUCCESS)
		nm_device_activate_schedule_stage3_ip_config_start (NM_DEVICE (self));
	else
		nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
}

static void
wimax_disconnect_cb (WIMAX_API_DEVICE_ID *device_id,
					 WIMAX_API_NETWORK_CONNECTION_RESP response)
{
	if (response == WIMAX_API_CONNECTION_SUCCESS) {
	} else {
		g_warning ("WiMax device disconnect failed");
	}
}

static void
nm_wimax_api_close (NMWimaxDevice *self)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (self);

	nm_debug ("Closing wimax device API");

	UnsubscribeDisconnectToNetwork (&priv->device_id);
	UnsubscribeConnectToNetwork (&priv->device_id);
	UnsubscribeNetworkSearchWideScanEx (&priv->device_id);
	UnsubscribeNetworkSearchEx (&priv->device_id);
	UnsubscribeDeviceStatusChange (&priv->device_id);
	WiMaxDeviceClose (&priv->device_id);
}

static gboolean
nm_wimax_api_open (NMWimaxDevice *self)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (self);
	WIMAX_API_RET result;
	gboolean success = FALSE;

	nm_debug ("Opening wimax device API");

	result = WiMaxDeviceOpen (&priv->device_id);
	if (result != WIMAX_API_RET_SUCCESS) {
		nm_wimax_util_error (&priv->device_id, "WiMax device open failed", result);
		goto err;
	}

	result = SetConnectionMode (&priv->device_id, WIMAX_API_CONNECTION_AUTO_SCAN_MANUAL_CONNECT);
	if (result != WIMAX_API_RET_SUCCESS) {
		nm_wimax_util_error (&priv->device_id, "WiMax device connection mode setting failed", result);
		goto err;
	}

	result = SubscribeDeviceStatusChange (&priv->device_id, wimax_status_change_cb);
	if (result != WIMAX_API_RET_SUCCESS) {
		nm_wimax_util_error (&priv->device_id, "WiMax subscription to device status changes failed", result);
		goto err;
	}

	result = SubscribeNetworkSearchEx (&priv->device_id, wimax_scan_cb);
	if (result != WIMAX_API_RET_SUCCESS) {
		nm_wimax_util_error (&priv->device_id, "WiMax subscription to network scanning failed", result);
		goto err;
	}

	result = SubscribeNetworkSearchWideScanEx (&priv->device_id, wimax_wide_scan_cb);
	if (result != WIMAX_API_RET_SUCCESS) {
		nm_wimax_util_error (&priv->device_id, "WiMax subscription to wide network scanning failed", result);
		goto err;
	}

	result = SubscribeConnectToNetwork (&priv->device_id, wimax_connect_cb);
	if (result != WIMAX_API_RET_SUCCESS) {
		nm_wimax_util_error (&priv->device_id, "WiMax subscription to connected messages failed", result);
		goto err;
	}

	result = SubscribeDisconnectToNetwork (&priv->device_id, wimax_disconnect_cb);
	if (result != WIMAX_API_RET_SUCCESS) {
		nm_wimax_util_error (&priv->device_id, "WiMax subscription to disconnected messages failed", result);
		goto err;
	}

	success = TRUE;

 err:
	if (!success)
		nm_wimax_api_close (self);

	return success;
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMWimaxDevice *self = NM_WIMAX_DEVICE (device);

	switch (new_state) {
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_DISCONNECTED:
		remove_all_nsps (self);
		schedule_rf_state_update (self);
		break;
	default:
		break;
	}
}

/* NMDeviceInterface interface */

static void
real_set_enabled (NMDeviceInterface *device, gboolean enabled)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (device);

	if (priv->enabled == enabled)
		return;

	priv->enabled = enabled;
	schedule_rf_state_update (NM_WIMAX_DEVICE (device));
}

/* NMDevice methods */

static void
real_take_down (NMDevice *device)
{
	NMWimaxDevice *self = NM_WIMAX_DEVICE (device);

	set_current_nsp (self, NULL);
	remove_all_nsps (self);
}

static gboolean
real_hw_is_up (NMDevice *device)
{
	return nm_system_device_is_up (device);
}

static gboolean
real_hw_bring_up (NMDevice *dev, gboolean *no_firmware)
{
	return nm_system_device_set_up_down (dev, TRUE, no_firmware);
}

static void
real_hw_take_down (NMDevice *dev)
{
	nm_system_device_set_up_down (dev, FALSE, NULL);
}

static void
real_update_hw_address (NMDevice *device)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (device);
	WIMAX_API_DEVICE_INFO info = { 0, };
    WIMAX_API_RET result;

    result = GetDeviceInformation (&priv->device_id, &info);
    if (result != WIMAX_API_RET_SUCCESS)
		nm_wimax_util_error (&priv->device_id, "Could not read WiMax device hardware address", result);

	if (memcmp (&priv->hw_addr, info.macAddress, sizeof (struct ether_addr))) {
		memcpy (&priv->hw_addr, info.macAddress, sizeof (struct ether_addr));
		g_object_notify (G_OBJECT (device), NM_WIMAX_DEVICE_HW_ADDRESS);
	}
}

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (device);
	NMSettingConnection *s_con;
	NMSettingWimax *s_wimax;
	const char *connection_type;
	const GByteArray *mac;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	connection_type = nm_setting_connection_get_connection_type (s_con);
	if (strcmp (connection_type, NM_SETTING_WIMAX_SETTING_NAME)) {
		g_set_error (error,
		             NM_WIMAX_ERROR, NM_WIMAX_ERROR_CONNECTION_NOT_WIMAX,
		             "The connection was not a WiMAX connection.");
		return FALSE;
	}

	s_wimax = (NMSettingWimax *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIMAX);
	if (!s_wimax) {
		g_set_error (error,
		             NM_WIMAX_ERROR, NM_WIMAX_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid WiMAX connection.");
		return FALSE;
	}

	mac = nm_setting_wimax_get_mac_address (s_wimax);
	if (mac && memcmp (mac->data, &(priv->hw_addr.ether_addr_octet), ETH_ALEN)) {
		g_set_error (error,
					 NM_WIMAX_ERROR, NM_WIMAX_ERROR_CONNECTION_INCOMPATIBLE,
					 "The connection's MAC address did not match this device.");
		return FALSE;
	}

	return TRUE;
}

static NMConnection *
real_get_best_auto_connection (NMDevice *device,
                               GSList *connections,
                               char **specific_object)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (device);
	GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;
		NMSettingWimax *s_wimax;
		const char *connection_type;
		const GByteArray *mac;

		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);

		if (!nm_setting_connection_get_autoconnect (s_con))
			continue;

		connection_type = nm_setting_connection_get_connection_type (s_con);
		if (strcmp (connection_type, NM_SETTING_WIMAX_SETTING_NAME))
			continue;

		s_wimax = (NMSettingWimax *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIMAX);
		if (!s_wimax)
			continue;

		mac = nm_setting_wimax_get_mac_address (s_wimax);
		if (mac && memcmp (mac->data, priv->hw_addr.ether_addr_octet, ETH_ALEN))
			continue;

		for (iter = priv->nsp_list; iter; iter = iter->next) {
			NMWimaxNsp *nsp = NM_WIMAX_NSP (iter->data);

			if (nm_wimax_nsp_check_compatible (nsp, connection)) {
				*specific_object = (char *) nm_wimax_nsp_get_dbus_path (nsp);
				return connection;
			}
		}
	}

	return NULL;
}

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_NM_SUPPORTED;
}

static gboolean
real_is_available (NMDevice *device)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (device);
	WIMAX_API_DEVICE_STATUS status;
	WIMAX_API_CONNECTION_PROGRESS_INFO pi;
	WIMAX_API_RET result;

	if (!priv->enabled)
		return FALSE;

	result = GetDeviceStatus (&priv->device_id, &status, &pi);
	if (result != WIMAX_API_RET_SUCCESS) {
		nm_wimax_util_error (&priv->device_id, "Reading WiMax device status failed", result);
		return FALSE;
	}

	return status >= WIMAX_API_DEVICE_STATUS_Ready;
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (device);
	NMActRequest *req;
	GSList *iter;
	const char *path;

	req = nm_device_get_act_request (device);
	if (!req)
		goto err;

	path = nm_act_request_get_specific_object (req);
	if (!path)
		goto err;

	for (iter = priv->nsp_list; iter; iter = iter->next) {
		NMWimaxNsp *nsp = NM_WIMAX_NSP (iter->data);

		if (!strcmp (path, nm_wimax_nsp_get_dbus_path (nsp))) {
			set_current_nsp (NM_WIMAX_DEVICE (device), nsp);
			return NM_ACT_STAGE_RETURN_SUCCESS;
		}
	}

 err:
	*reason = NM_DEVICE_STATE_REASON_NONE;
	return NM_ACT_STAGE_RETURN_FAILURE;
}

static NMActStageReturn
real_act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (device);
	NMConnection *connection;
	NMSettingWimax *s_wimax;
	WIMAX_API_RET result;

	connection = nm_act_request_get_connection (nm_device_get_act_request (device));
	g_assert (connection);

	s_wimax = NM_SETTING_WIMAX (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIMAX));
	g_assert (s_wimax);

	result = CmdConnectToNetwork (&priv->device_id,
								  (WIMAX_API_WSTRING) nm_setting_wimax_get_network_name (s_wimax),
								  0, NULL);

	if (result != WIMAX_API_RET_SUCCESS) {
		nm_wimax_util_error (&priv->device_id, "WiMax connect to network failed", result);
		*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	/* FIXME: Is 60 seconds good estimation? I have no idea */
	priv->activation_timeout_id = g_timeout_add_seconds (60, activation_timed_out, device);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static void
real_deactivate_quickly (NMDevice *device)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (device);
	WIMAX_API_DEVICE_STATUS status;
	WIMAX_API_CONNECTION_PROGRESS_INFO pi;
	WIMAX_API_RET result;

	if (priv->activation_timeout_id) {
		g_source_remove (priv->activation_timeout_id);
		priv->activation_timeout_id = 0;
	}

	set_current_nsp (NM_WIMAX_DEVICE (device), NULL);

	result = GetDeviceStatus (&priv->device_id, &status, &pi);
	if (result != WIMAX_API_RET_SUCCESS)
		nm_wimax_util_error (&priv->device_id, "Reading WiMax device status failed", result);

	if (status == WIMAX_API_DEVICE_STATUS_Connecting ||
		status == WIMAX_API_DEVICE_STATUS_Data_Connected) {

		result = CmdDisconnectFromNetwork (&priv->device_id);
		if (result != WIMAX_API_RET_SUCCESS)
			nm_wimax_util_error (&priv->device_id, "WiMax disconnect from network failed", result);
	}
}

/* GObject methods */

static void
device_interface_init (NMDeviceInterface *iface_class)
{
    iface_class->set_enabled = real_set_enabled;
}

static void
nm_wimax_device_init (NMWimaxDevice *self)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (self);

	priv->object = self;
	priv->device_id.structureSize = sizeof (NMWimaxDevicePrivate);
	priv->device_id.privilege = WIMAX_API_PRIVILEGE_READ_WRITE;

	g_signal_connect (self, "state-changed", G_CALLBACK (device_state_changed), NULL);
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMWimaxDevicePrivate *priv;

	object = G_OBJECT_CLASS (nm_wimax_device_parent_class)->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	priv = GET_PRIVATE (object);
	if (priv->device_id.deviceIndex == 0) {
		g_warning ("Invalid or missing constructor arguments");
		g_object_unref (object);
		object = NULL;
	}

	if (!nm_wimax_api_open (NM_WIMAX_DEVICE (object))) {
		g_object_unref (object);
		object = NULL;
	}

	return object;
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	NMWimaxDevicePrivate *priv = GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_INDEX:
		priv->device_id.deviceIndex = g_value_get_uchar (value);
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
	NMWimaxDevice *self = NM_WIMAX_DEVICE (object);
	NMWimaxDevicePrivate *priv = GET_PRIVATE (self);
	struct ether_addr hw_addr;

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		nm_wimax_device_get_hw_address (self, &hw_addr);
		g_value_take_string (value, nm_ether_ntop (&hw_addr));
		break;
	case PROP_ACTIVE_NSP:
		if (priv->current_nsp)
			g_value_set_boxed (value, nm_wimax_nsp_get_dbus_path (priv->current_nsp));
		else
			g_value_set_boxed (value, "/");
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMWimaxDevice *self = NM_WIMAX_DEVICE (object);
	NMWimaxDevicePrivate *priv = GET_PRIVATE (self);

	if (priv->rf_update_id)
		g_source_remove (priv->rf_update_id);

	set_current_nsp (self, NULL);

	g_slist_foreach (priv->nsp_list, (GFunc) g_object_unref, NULL);
	g_slist_free (priv->nsp_list);

	nm_wimax_api_close (self);

	G_OBJECT_CLASS (nm_wimax_device_parent_class)->finalize (object);
}

static void
nm_wimax_device_class_init (NMWimaxDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMWimaxDevicePrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	device_class->take_down = real_take_down;
	device_class->hw_is_up = real_hw_is_up;
	device_class->hw_bring_up = real_hw_bring_up;
	device_class->hw_take_down = real_hw_take_down;
	device_class->update_hw_address = real_update_hw_address;
	device_class->check_connection_compatible = real_check_connection_compatible;
	device_class->get_best_auto_connection = real_get_best_auto_connection;
	device_class->get_generic_capabilities = real_get_generic_capabilities;
	device_class->is_available = real_is_available;
	device_class->act_stage1_prepare = real_act_stage1_prepare;
	device_class->act_stage2_config = real_act_stage2_config;
	device_class->deactivate_quickly = real_deactivate_quickly;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_INDEX,
		 g_param_spec_uchar (NM_WIMAX_DEVICE_INDEX,
							 "Index",
							 "Index",
							 0, 1, 0,
							 G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | NM_PROPERTY_PARAM_NO_EXPORT));

	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_WIMAX_DEVICE_HW_ADDRESS,
							  "MAC Address",
							  "Hardware MAC address",
							  NULL,
							  G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_ACTIVE_NSP,
		g_param_spec_boxed (NM_WIMAX_DEVICE_ACTIVE_NSP,
		                    "Active NSP",
		                    "Currently active NSP",
		                    DBUS_TYPE_G_OBJECT_PATH,
		                    G_PARAM_READABLE));

	/* Signals */
	signals[NSP_ADDED] =
		g_signal_new ("nsp-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMWimaxDeviceClass, nsp_added),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[NSP_REMOVED] =
		g_signal_new ("nsp-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMWimaxDeviceClass, nsp_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class, G_STRUCT_OFFSET (NMWimaxDeviceClass, properties_changed));


	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_wimax_device_object_info);

	dbus_g_error_domain_register (NM_WIMAX_ERROR, NULL, NM_TYPE_WIMAX_ERROR);
}
