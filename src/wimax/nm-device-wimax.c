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
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>

#include <WiMaxAPI.h>
#include <WiMaxAPIEx.h>

#include "nm-device-wimax.h"
#include "nm-wimax-util.h"
#include "nm-logging.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-system.h"
#include "NetworkManagerUtils.h"
#include "nm-properties-changed-signal.h"
#include "nm-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-wimax.h"
#include "nm-utils.h"
#include "nm-rfkill.h"
#include "iwmxsdk.h"

static gboolean impl_device_get_nsp_list (NMDeviceWimax *device, GPtrArray **list, GError **error);

#include "nm-device-wimax-glue.h"

static void device_interface_init (NMDeviceInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (NMDeviceWimax, nm_device_wimax, NM_TYPE_DEVICE, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_DEVICE_INTERFACE, device_interface_init))

enum {
	PROP_0,
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

#define NM_DEVICE_WIMAX_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                        NM_TYPE_DEVICE_WIMAX, \
                                        NMDeviceWimaxPrivate))

typedef struct {
	gboolean disposed;

	struct wmxsdk *sdk;
	WIMAX_API_DEVICE_STATUS status;
	gboolean connect_failed;

	gboolean enabled;
	gboolean wimaxd_enabled;
	struct ether_addr hw_addr;
	guint activation_timeout_id;

	guint sdk_action_defer_id;

	guint link_timeout_id;

	GSList *nsp_list;
	NMWimaxNsp *current_nsp;
} NMDeviceWimaxPrivate;

/***********************************************************/

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

/***********************************************************/

void
nm_device_wimax_get_hw_address (NMDeviceWimax *self, struct ether_addr *addr)
{
	NMDeviceWimaxPrivate *priv;

	g_return_if_fail (NM_IS_DEVICE_WIMAX (self));
	g_return_if_fail (addr != NULL);

	priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	memcpy (addr, &(priv->hw_addr), sizeof (struct ether_addr));
}

static gboolean
impl_device_get_nsp_list (NMDeviceWimax *self, GPtrArray **nsps, GError **error)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	GSList *iter;

	*nsps = g_ptr_array_sized_new (g_slist_length (priv->nsp_list));
	for (iter = priv->nsp_list; iter; iter = iter->next) {
		const char *path;

		path = nm_wimax_nsp_get_dbus_path (NM_WIMAX_NSP (iter->data));
		if (path)
			g_ptr_array_add (*nsps, g_strdup (path));
	}

	return TRUE;
}

static void
set_current_nsp (NMDeviceWimax *self, NMWimaxNsp *new_nsp)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
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
	if (   (!old_path && new_nsp)
		|| (old_path && !new_nsp)
	    || (old_path && new_nsp && strcmp (old_path, nm_wimax_nsp_get_dbus_path (new_nsp))))
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIMAX_ACTIVE_NSP);

	g_free (old_path);
}

NMWimaxNsp *
nm_device_wimax_get_active_nsp (NMDeviceWimax *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (self), NULL);

	return NM_DEVICE_WIMAX_GET_PRIVATE (self)->current_nsp;
}

static gboolean
activation_timed_out (gpointer data)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (data);

	priv->activation_timeout_id = 0;
	nm_device_state_changed (NM_DEVICE (data), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_CONFIG_FAILED);

	return FALSE;
}

static void
remove_all_nsps (NMDeviceWimax *self)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	while (g_slist_length (priv->nsp_list)) {
		NMWimaxNsp *nsp = NM_WIMAX_NSP (priv->nsp_list->data);

		priv->nsp_list = g_slist_remove (priv->nsp_list, nsp);
		g_signal_emit (self, signals[NSP_REMOVED], 0, nsp);
		g_object_unref (nsp);
	}

	g_slist_free (priv->nsp_list);
	priv->nsp_list = NULL;
}

static NMWimaxNsp *
get_nsp_by_name (NMDeviceWimax *self, const char *name)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->nsp_list; iter; iter = iter->next) {
		NMWimaxNsp *nsp = NM_WIMAX_NSP (iter->data);

		if (!g_strcmp0 (nm_wimax_nsp_get_name (nsp), name))
			return nsp;
	}

	return NULL;
}

static gboolean
update_availability (NMDeviceWimax *self, gboolean old_available)
{
	NMDevice *device = NM_DEVICE (self);
	NMDeviceState state;
	gboolean new_available, changed = FALSE;

	new_available = nm_device_is_available (device);
nm_log_dbg (LOGD_WIMAX, "old_avail %d, new_avail %d", old_available, new_available);
	if (new_available == old_available)
		return FALSE;

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (self));
	if (state == NM_DEVICE_STATE_UNAVAILABLE) {
		if (new_available == TRUE) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_DISCONNECTED,
			                         NM_DEVICE_STATE_REASON_NONE);
			changed = TRUE;
		}
	} else if (state >= NM_DEVICE_STATE_DISCONNECTED) {
		if (new_available == FALSE) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_UNAVAILABLE,
			                         NM_DEVICE_STATE_REASON_NONE);
			changed = TRUE;
		}
	}

	return changed;
}

/* NMDeviceInterface interface */

static void
real_set_enabled (NMDeviceInterface *device, gboolean enabled)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (device);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	gboolean old_available;
	int ret;

nm_log_dbg (LOGD_WIMAX, "setting wimax enabled %d (was %d)", enabled, priv->enabled);
	if (priv->enabled == enabled)
		return;

	old_available = nm_device_is_available (NM_DEVICE (device));
	priv->enabled = enabled;
nm_log_dbg (LOGD_WIMAX, "wimax enabled changed to %d", priv->enabled);

	/* Set the WiMAX device RF state to the current user-specified enabled state */
	if (priv->sdk) {
		ret = iwmx_sdk_rf_state_set (priv->sdk,
		                             enabled ? WIMAX_API_RF_ON : WIMAX_API_RF_OFF);
		if (ret < 0 && ret != -EINPROGRESS) {
			nm_log_warn (LOGD_WIMAX, "failed to %s WiMAX radio",
			             priv->enabled ? "enable" : "disable");
		}
	}

	update_availability (self, old_available);
}

/* NMDevice methods */

static void
real_take_down (NMDevice *device)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (device);

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
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (dev);

	if (!priv->enabled || !priv->wimaxd_enabled)
		return FALSE;

	return nm_system_device_set_up_down (dev, TRUE, no_firmware);
}

static void
real_hw_take_down (NMDevice *dev)
{
	nm_system_device_set_up_down (dev, FALSE, NULL);
}

static void
real_update_hw_address (NMDevice *dev)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (dev);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	struct ifreq req;
	int fd;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_warn (LOGD_HW, "couldn't open control socket.");
		return;
	}

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), IFNAMSIZ);

	errno = 0;
	if (ioctl (fd, SIOCGIFHWADDR, &req) < 0) {
		nm_log_err (LOGD_HW | LOGD_WIMAX,
		            "(%s) failed to read hardware address (error %d)",
		            nm_device_get_iface (dev), errno);
	} else {
		memcpy (&priv->hw_addr, &req.ifr_hwaddr.sa_data, ETH_ALEN);
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIMAX_HW_ADDRESS);
	}

	close (fd);
}

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (device);
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
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (device);
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
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (device);
	const char *iface = nm_device_get_iface (device);

	if (!priv->enabled) {
		nm_log_dbg (LOGD_WIMAX, "(%s): not available because not enabled", iface);
		return FALSE;
	}

	if (!priv->wimaxd_enabled) {
		nm_log_dbg (LOGD_WIMAX, "(%s): not available because not enabled in wimaxd", iface);
		return FALSE;
	}

	if (!nm_wimax_util_sdk_is_initialized ()) {
		nm_log_dbg (LOGD_WIMAX, "(%s): not available because WiMAX SDK not initialized", iface);
		return FALSE;
	}

	if (!priv->sdk) {
		nm_log_dbg (LOGD_WIMAX, "(%s): not available because not known to WiMAX SDK", iface);
		return FALSE;
	}

	return iwmxsdk_status_get (priv->sdk) >= WIMAX_API_DEVICE_STATUS_Ready;
}

static void
clear_activation_timeout (NMDeviceWimax *self)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	if (priv->activation_timeout_id) {
		g_source_remove (priv->activation_timeout_id);
		priv->activation_timeout_id = 0;
	}

	priv->connect_failed = FALSE;
}

static void
clear_link_timeout (NMDeviceWimax *self)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	if (priv->link_timeout_id) {
		g_source_remove (priv->link_timeout_id);
		priv->link_timeout_id = 0;
	}
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (device);
	NMActRequest *req;
	GSList *iter;
	const char *path;

	clear_link_timeout (NM_DEVICE_WIMAX (device));

	req = nm_device_get_act_request (device);
	if (!req)
		goto err;

	path = nm_act_request_get_specific_object (req);
	if (!path)
		goto err;

	for (iter = priv->nsp_list; iter; iter = iter->next) {
		NMWimaxNsp *nsp = NM_WIMAX_NSP (iter->data);

		if (!strcmp (path, nm_wimax_nsp_get_dbus_path (nsp))) {
			set_current_nsp (NM_DEVICE_WIMAX (device), nsp);
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
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (device);
	NMConnection *connection;
	NMSettingWimax *s_wimax;
	const char *nsp;
	int ret;

	connection = nm_act_request_get_connection (nm_device_get_act_request (device));
	g_assert (connection);

	s_wimax = NM_SETTING_WIMAX (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIMAX));
	g_assert (s_wimax);

	nsp = nm_setting_wimax_get_network_name (s_wimax);
	g_assert (nsp);

	priv->connect_failed = FALSE;
	ret = iwmx_sdk_connect (priv->sdk, nsp);
	if (ret < 0 && ret != -EINPROGRESS) {
		nm_log_err (LOGD_WIMAX, "Failed to connect to NSP '%s'", nsp);
		*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	/* FIXME: Is 40 seconds good estimation? I have no idea */
	priv->activation_timeout_id = g_timeout_add_seconds (40, activation_timed_out, device);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static void
force_disconnect (struct wmxsdk *sdk)
{
	WIMAX_API_DEVICE_STATUS status;
	int ret;

	g_return_if_fail (sdk != NULL);

	status = iwmxsdk_status_get (sdk);
	if ((int) status < 0) {
		nm_log_err (LOGD_WIMAX, "Failed to read WiMAX device status: %d", status);
		return;
	}

	if (   status == WIMAX_API_DEVICE_STATUS_Connecting
	    || status == WIMAX_API_DEVICE_STATUS_Data_Connected) {
		ret = iwmx_sdk_disconnect (sdk);
		if (ret < 0 && ret != -EINPROGRESS) {
			nm_log_err (LOGD_WIMAX, "Failed to disconnect WiMAX device: %d", ret);
		}
	}
}

static void
real_deactivate_quickly (NMDevice *device)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (device);

	clear_activation_timeout (NM_DEVICE_WIMAX (device));
	clear_link_timeout (NM_DEVICE_WIMAX (device));

	set_current_nsp (NM_DEVICE_WIMAX (device), NULL);

	if (priv->sdk) {
		/* Read explicit status here just to make sure we have the most
		 * up-to-date status and to ensure we disconnect if needed.
		 */
		force_disconnect (priv->sdk);
	}
}

/*************************************************************************/

static void
wmx_state_change_cb (struct wmxsdk *wmxsdk,
                     WIMAX_API_DEVICE_STATUS new_status,
                     WIMAX_API_DEVICE_STATUS old_status,
                     WIMAX_API_STATUS_REASON reason,
                     void *user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (user_data);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	NMDeviceState state;
	const char *iface;
	gboolean old_available = FALSE;
	const char *nsp_name = NULL;

	if (new_status == old_status)
		return;

	iface = nm_device_get_iface (NM_DEVICE (self));
	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (self));
	old_available = nm_device_is_available (NM_DEVICE (self));

	priv->status = new_status;
	if (priv->current_nsp)
		nsp_name = nm_wimax_nsp_get_name (priv->current_nsp);

	nm_log_dbg (LOGD_WIMAX, "(%s): wimax state change %s -> %s (reason %d)",
	            iface,
	            iwmx_sdk_dev_status_to_str (old_status),
	            iwmx_sdk_dev_status_to_str (new_status),
	            reason);

	switch (new_status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		if (priv->wimaxd_enabled) {
			priv->wimaxd_enabled = FALSE;
			if (update_availability (self, old_available))
				return;
		}
		break;
	case WIMAX_API_DEVICE_STATUS_Connecting:
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
		/* If for some reason we're initially connected, force a disconnect here */
		if (state < NM_DEVICE_STATE_DISCONNECTED)
			force_disconnect (wmxsdk);
		/* Fall through */
	case WIMAX_API_DEVICE_STATUS_Ready:
	case WIMAX_API_DEVICE_STATUS_Scanning:
		if (priv->wimaxd_enabled == FALSE) {
			priv->wimaxd_enabled = TRUE;
			if (update_availability (self, old_available))
				return;
		}
		break;
	default:
		nm_log_warn (LOGD_WIMAX, "(%s): unhandled WiMAX device state %d",
		             iface, new_status);
		break;
	}

	/* Handle activation success and failure */
	if (IS_ACTIVATING_STATE (state)) {
	    if (new_status == WIMAX_API_DEVICE_STATUS_Data_Connected) {
			/* Success */
			clear_activation_timeout (self);

			nm_log_info (LOGD_WIMAX, "(%s): connected to '%s'",
			             iface, nsp_name);
			nm_device_activate_schedule_stage3_ip_config_start (NM_DEVICE (self));
			return;
		}

		if (priv->connect_failed) {
			/* Connection attempt failed */
			nm_log_info (LOGD_WIMAX, "(%s): connection to '%s' failed: (%d) %s",
			             iface, nsp_name, reason, iwmx_sdk_reason_to_str (reason));
			nm_device_state_changed (NM_DEVICE (self),
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_CONFIG_FAILED);
			return;
		}
	}

	/* Handle disconnection */
	if (state == NM_DEVICE_STATE_ACTIVATED) {
		if (   old_status == WIMAX_API_DEVICE_STATUS_Data_Connected
			&& new_status < WIMAX_API_DEVICE_STATUS_Connecting) {

			nm_log_info (LOGD_WIMAX, "(%s): disconnected from '%s': (%d) %s",
				         iface, nsp_name, reason, iwmx_sdk_reason_to_str (reason));

			nm_device_state_changed (NM_DEVICE (self),
				                     NM_DEVICE_STATE_FAILED,
				                     NM_DEVICE_STATE_REASON_CONFIG_FAILED);
		}
	}
}

static gboolean
link_timeout_cb (gpointer user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (user_data);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	priv->link_timeout_id = 0;

	nm_device_state_changed (NM_DEVICE (self),
		                     NM_DEVICE_STATE_FAILED,
		                     NM_DEVICE_STATE_REASON_CARRIER);

	return FALSE;
}

static void
wmx_media_status_cb (struct wmxsdk *wmxsdk,
                     WIMAX_API_MEDIA_STATUS new_status,
                     void *user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (user_data);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	NMDeviceState state;
	const char *iface;

	iface = nm_device_get_iface (NM_DEVICE (self));
	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (self));

	nm_log_dbg (LOGD_WIMAX, "(%s): media status change to %d",
	            iface, iwmx_sdk_media_status_to_str (new_status));

	/* We only care about media events while activated */
	if (state != NM_DEVICE_STATE_ACTIVATED)
		return;

	clear_link_timeout (self);

	switch (new_status) {
	case WIMAX_API_MEDIA_STATUS_LINK_UP:
		break;
	case WIMAX_API_MEDIA_STATUS_LINK_DOWN:
		priv->link_timeout_id = g_timeout_add (15, link_timeout_cb, self);
		break;
	case WIMAX_API_MEDIA_STATUS_LINK_RENEW:
		break;
	default:
		nm_log_err (LOGD_WIMAX, "(%s): unhandled media status %d", iface, new_status);
		break;
	}
}

static void
wmx_connect_result_cb (struct wmxsdk *wmxsdk,
                       WIMAX_API_NETWORK_CONNECTION_RESP result,
                       void *user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (user_data);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	NMDeviceState state;

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (self));
	if (IS_ACTIVATING_STATE (state)) {
		priv->connect_failed = (result == WIMAX_API_CONNECTION_SUCCESS);
		/* Wait for the state change so we can get the reason code; we
		 * cache the connect failure so we don't have to wait for the
		 * activation timeout.
		 */
	}
}

static void
remove_outdated_nsps (NMDeviceWimax *self,
					  WIMAX_API_NSP_INFO_EX *nsp_list,
					  guint32 list_size)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	GSList *iter;
	GSList *to_remove = NULL;

	for (iter = priv->nsp_list; iter; iter = iter->next) {
		NMWimaxNsp *nsp = NM_WIMAX_NSP (iter->data);
		gboolean found = FALSE;
		int i;

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

static void
wmx_scan_result_cb (struct wmxsdk *wmxsdk,
                    WIMAX_API_NSP_INFO_EX *nsps,
                    guint num_nsps,
                    void *user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (user_data);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	const char *iface = nm_device_get_iface (NM_DEVICE (self));
	int i;

	remove_outdated_nsps (self, nsps, num_nsps);

	/* Add new NSPs and update existing ones */
	for (i = 0; i < num_nsps; i++) {
		WIMAX_API_NSP_INFO_EX *sdk_nsp = &nsps[i];
		const char *nsp_name = (const char *) sdk_nsp->NSPName;
		NMWimaxNspNetworkType net_type;
		NMWimaxNsp *nsp;
		gboolean new_nsp;

		nsp = get_nsp_by_name (self, nsp_name);
		new_nsp = (nsp == NULL);
		if (new_nsp) {
			nsp = nm_wimax_nsp_new (nsp_name);
			nm_log_dbg (LOGD_WIMAX, "(%s): new WiMAX NSP '%s'", iface, nsp_name);
		}

		net_type = nm_wimax_util_convert_network_type (sdk_nsp->networkType);
		g_object_set (nsp,
					  NM_WIMAX_NSP_SIGNAL_QUALITY, sdk_nsp->linkQuality,
					  NM_WIMAX_NSP_NETWORK_TYPE, net_type,
					  NULL);

		nm_log_dbg (LOGD_WIMAX, "(%s): WiMAX NSP '%s' quality %d%% type %d",
			        iface, nsp_name, sdk_nsp->linkQuality, net_type);

		if (new_nsp) {
			priv->nsp_list = g_slist_append (priv->nsp_list, nsp);
			nm_wimax_nsp_export_to_dbus (nsp);
			g_signal_emit (self, signals[NSP_ADDED], 0, nsp);
		}
	}
}

static void
wmx_removed_cb (struct wmxsdk *wmxsdk, void *user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (user_data);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	if (priv->sdk) {
		/* Clear callbacks just in case we don't hold the last reference */
		iwmx_sdk_set_callbacks (priv->sdk, NULL, NULL, NULL, NULL, NULL, NULL);

		wmxsdk_unref (priv->sdk);
		priv->sdk = NULL;

		priv->status = WIMAX_API_DEVICE_STATUS_UnInitialized;
		nm_device_state_changed (NM_DEVICE (self),
								 NM_DEVICE_STATE_UNAVAILABLE,
								 NM_DEVICE_STATE_REASON_NONE);
	}
}

/*************************************************************************/

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (device);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	if (new_state < NM_DEVICE_STATE_DISCONNECTED)
		remove_all_nsps (self);

	/* Request initial NSP list */
	if (   new_state == NM_DEVICE_STATE_DISCONNECTED
	    && old_state < NM_DEVICE_STATE_DISCONNECTED) {
		if (priv->sdk)
			iwmx_sdk_get_networks (priv->sdk);
	}

	if (new_state == NM_DEVICE_STATE_FAILED || new_state <= NM_DEVICE_STATE_DISCONNECTED)
		clear_activation_timeout (self);

	if (new_state != NM_DEVICE_STATE_ACTIVATED)
		clear_link_timeout (self);
}

/*************************************************************************/

static gboolean
sdk_action_defer_cb (gpointer user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (user_data);
	gboolean old_available = nm_device_is_available (NM_DEVICE (self));

	NM_DEVICE_WIMAX_GET_PRIVATE (self)->sdk_action_defer_id = 0;
	update_availability (self, old_available);
	return FALSE;
}

static void
wmx_new_sdk_cb (struct wmxsdk *sdk, void *user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (user_data);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	/* If we now have the SDK, schedule an idle handler to start the device up */
	if (!priv->sdk) {
		priv->sdk = wmxsdk_ref (sdk);
		iwmx_sdk_set_callbacks(priv->sdk,
		                       wmx_state_change_cb,
		                       wmx_media_status_cb,
		                       wmx_connect_result_cb,
		                       wmx_scan_result_cb,
		                       wmx_removed_cb,
		                       self);

		if (!priv->sdk_action_defer_id)
			priv->sdk_action_defer_id = g_idle_add (sdk_action_defer_cb, self);
	}
}

/*************************************************************************/

NMDevice *
nm_device_wimax_new (const char *udi,
					 const char *iface,
					 const char *driver)
{
	NMDevice *device;

	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	device = (NMDevice *) g_object_new (NM_TYPE_DEVICE_WIMAX,
	                                    NM_DEVICE_INTERFACE_UDI, udi,
	                                    NM_DEVICE_INTERFACE_IFACE, iface,
	                                    NM_DEVICE_INTERFACE_DRIVER, driver,
	                                    NM_DEVICE_INTERFACE_TYPE_DESC, "WiMAX",
	                                    NM_DEVICE_INTERFACE_DEVICE_TYPE, NM_DEVICE_TYPE_WIMAX,
	                                    NM_DEVICE_INTERFACE_RFKILL_TYPE, RFKILL_TYPE_WIMAX,
	                                    NULL);
	if (device) {
		struct wmxsdk *sdk;

		nm_wimax_util_sdk_ref ();
		g_signal_connect (device, "state-changed", G_CALLBACK (device_state_changed), NULL);

		/* See if the SDK already knows about this interface */
		sdk = iwmx_sdk_get_wmxsdk_for_iface (iface);
		if (sdk)
			wmx_new_sdk_cb (sdk, device);

		/* If it doesn't, we want to be notified when it does */
		iwmx_sdk_new_callback_register (wmx_new_sdk_cb, device);
	}

	return device;
}

static void
device_interface_init (NMDeviceInterface *iface_class)
{
    iface_class->set_enabled = real_set_enabled;
}

static void
nm_device_wimax_init (NMDeviceWimax *self)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	priv->status = WIMAX_API_DEVICE_STATUS_UnInitialized;
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (object);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	struct ether_addr hw_addr;

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		nm_device_wimax_get_hw_address (self, &hw_addr);
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
dispose (GObject *object)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (object);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	if (priv->disposed)
		goto done;

	priv->disposed = TRUE;

	clear_activation_timeout (self);
	clear_link_timeout (self);

	if (priv->sdk_action_defer_id)
		g_source_remove (priv->sdk_action_defer_id);

	if (priv->sdk) {
		iwmx_sdk_set_callbacks (priv->sdk, NULL, NULL, NULL, NULL, NULL, NULL);
		wmxsdk_unref (priv->sdk);
	}

	set_current_nsp (self, NULL);

	g_slist_foreach (priv->nsp_list, (GFunc) g_object_unref, NULL);
	g_slist_free (priv->nsp_list);

	iwmx_sdk_new_callback_unregister (wmx_new_sdk_cb, self);
	nm_wimax_util_sdk_unref ();

done:
	G_OBJECT_CLASS (nm_device_wimax_parent_class)->dispose (object);
}

static void
nm_device_wimax_class_init (NMDeviceWimaxClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceWimaxPrivate));

	/* Virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

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
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_WIMAX_HW_ADDRESS,
							  "MAC Address",
							  "Hardware MAC address",
							  NULL,
							  G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_ACTIVE_NSP,
		g_param_spec_boxed (NM_DEVICE_WIMAX_ACTIVE_NSP,
		                    "Active NSP",
		                    "Currently active NSP",
		                    DBUS_TYPE_G_OBJECT_PATH,
		                    G_PARAM_READABLE));

	/* Signals */
	signals[NSP_ADDED] =
		g_signal_new ("nsp-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDeviceWimaxClass, nsp_added),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[NSP_REMOVED] =
		g_signal_new ("nsp-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDeviceWimaxClass, nsp_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class, G_STRUCT_OFFSET (NMDeviceWimaxClass, properties_changed));


	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_device_wimax_object_info);

	dbus_g_error_domain_register (NM_WIMAX_ERROR, NULL, NM_TYPE_WIMAX_ERROR);
}
