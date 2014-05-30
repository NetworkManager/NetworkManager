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
 * Copyright (C) 2010 - 2011 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/ether.h>

#include <WiMaxAPI.h>
#include <WiMaxAPIEx.h>

#include "nm-device-wimax.h"
#include "nm-wimax-util.h"
#include "nm-logging.h"
#include "nm-device-private.h"
#include "NetworkManagerUtils.h"
#include "nm-dbus-manager.h"
#include "nm-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-wimax.h"
#include "nm-utils.h"
#include "nm-rfkill-manager.h"
#include "iwmxsdk.h"
#include "nm-enum-types.h"
#include "nm-dbus-glib-types.h"

static gboolean impl_device_get_nsp_list (NMDeviceWimax *device, GPtrArray **list, GError **error);

#include "nm-device-wimax-glue.h"

G_DEFINE_TYPE (NMDeviceWimax, nm_device_wimax, NM_TYPE_DEVICE)

enum {
	PROP_0,
	PROP_NSPS,
	PROP_ACTIVE_NSP,
	PROP_CENTER_FREQ,
	PROP_RSSI,
	PROP_CINR,
	PROP_TX_POWER,
	PROP_BSID,

	LAST_PROP
};

enum {
	NSP_ADDED,
	NSP_REMOVED,

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
	guint activation_timeout_id;

	/* Track whether stage1 (Prepare) is completed yet or not */
	gboolean prepare_done;

	guint sdk_action_defer_id;

	guint link_timeout_id;
	guint poll_id;

	GSList *nsp_list;
	NMWimaxNsp *current_nsp;

	/* interesting stuff when connected */
	guint center_freq;
	gint rssi;
	gint cinr;
	gint tx_power;
	char *bsid;
} NMDeviceWimaxPrivate;

/***********************************************************/

#define NM_WIMAX_ERROR (nm_wimax_error_quark ())

static GQuark
nm_wimax_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-wimax-error");
	return quark;
}

/***********************************************************/

static gboolean
impl_device_get_nsp_list (NMDeviceWimax *self, GPtrArray **nsps, GError **error)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	GSList *iter;

	*nsps = g_ptr_array_sized_new (4);
	for (iter = priv->nsp_list; iter; iter = iter->next)
		g_ptr_array_add (*nsps, g_strdup (nm_wimax_nsp_get_dbus_path (NM_WIMAX_NSP (iter->data))));

	return TRUE;
}

static void
set_current_nsp (NMDeviceWimax *self, NMWimaxNsp *new_nsp)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	NMWimaxNsp *old_nsp;
	gboolean path_changed = FALSE;

	old_nsp = priv->current_nsp;
	priv->current_nsp = NULL;

	if (new_nsp)
		priv->current_nsp = g_object_ref (new_nsp);

	if (old_nsp && new_nsp) {
		path_changed = (g_strcmp0 (nm_wimax_nsp_get_dbus_path (old_nsp),
		                           nm_wimax_nsp_get_dbus_path (new_nsp)) != 0);
	}

	/* Only notify if it's really changed */
	if (old_nsp != new_nsp || path_changed)
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIMAX_ACTIVE_NSP);

	if (old_nsp)
		g_object_unref (old_nsp);
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
emit_nsp_added_removed (NMDeviceWimax *self,
                        guint signum,
                        NMWimaxNsp *nsp,
                        gboolean recheck_available_connections)
{
	g_signal_emit (self, signals[signum], 0, nsp);
	g_object_notify (G_OBJECT (self), NM_DEVICE_WIMAX_NSPS);
	nm_device_emit_recheck_auto_activate (NM_DEVICE (self));
	if (recheck_available_connections)
		nm_device_recheck_available_connections (NM_DEVICE (self));
}

static void
remove_all_nsps (NMDeviceWimax *self)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	set_current_nsp (self, NULL);

	while (priv->nsp_list) {
		NMWimaxNsp *nsp = NM_WIMAX_NSP (priv->nsp_list->data);

		priv->nsp_list = g_slist_remove (priv->nsp_list, nsp);
		emit_nsp_added_removed (self, NSP_REMOVED, nsp, FALSE);
		g_object_unref (nsp);
	}

	nm_device_recheck_available_connections (NM_DEVICE (self));
}

static NMWimaxNsp *
get_nsp_by_name (NMDeviceWimax *self, const char *name)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	GSList *iter;

	g_return_val_if_fail (name, NULL);

	for (iter = priv->nsp_list; iter; iter = iter->next) {
		NMWimaxNsp *nsp = NM_WIMAX_NSP (iter->data);

		if (!g_strcmp0 (nm_wimax_nsp_get_name (nsp), name))
			return nsp;
	}

	return NULL;
}

static NMWimaxNsp *
get_nsp_by_path (NMDeviceWimax *self, const char *path)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	GSList *iter;

	g_return_val_if_fail (path, NULL);

	for (iter = priv->nsp_list; iter; iter = iter->next) {
		NMWimaxNsp *nsp = NM_WIMAX_NSP (iter->data);

		if (!strcmp (nm_wimax_nsp_get_dbus_path (nsp), path))
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
	if (new_available == old_available)
		return FALSE;

	state = nm_device_get_state (device);
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
set_enabled (NMDevice *device, gboolean enabled)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (device);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	gboolean old_available;
	int ret;
	const char *iface;

	iface = nm_device_get_iface (NM_DEVICE (self));

	nm_log_dbg (LOGD_WIMAX, "(%s): setting radio enabled %d -> %d",
	            iface, priv->enabled, enabled);
	if (priv->enabled == enabled)
		return;

	old_available = nm_device_is_available (NM_DEVICE (device));
	priv->enabled = enabled;

	nm_log_dbg (LOGD_WIMAX, "(%s): radio now %s",
	            iface, priv->enabled ? "enabled" : "disabled");

	/* Set the WiMAX device RF state to the current user-specified enabled state */
	if (priv->sdk) {
		ret = iwmx_sdk_rf_state_set (priv->sdk,
		                             enabled ? WIMAX_API_RF_ON : WIMAX_API_RF_OFF);
		if (ret < 0 && ret != -EINPROGRESS) {
			nm_log_warn (LOGD_WIMAX, "(%s): failed to %s radio",
			             iface, priv->enabled ? "enable" : "disable");
		}
	}

	update_availability (self, old_available);
}

/* NMDevice methods */

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMSettingConnection *s_con;
	NMSettingWimax *s_wimax;
	const char *connection_type;
	const GByteArray *mac;

	if (!NM_DEVICE_CLASS (nm_device_wimax_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	connection_type = nm_setting_connection_get_connection_type (s_con);
	if (strcmp (connection_type, NM_SETTING_WIMAX_SETTING_NAME))
		return FALSE;

	s_wimax = nm_connection_get_setting_wimax (connection);
	if (!s_wimax)
		return FALSE;

	mac = nm_setting_wimax_get_mac_address (s_wimax);
	if (mac && memcmp (mac->data, nm_device_get_hw_address (device, NULL), ETH_ALEN))
		return FALSE;

	return TRUE;
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            const char *specific_object)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (device);
	const GSList *ns_iter = NULL;
	NMWimaxNsp *nsp;

	if (specific_object) {
		nsp = get_nsp_by_path (NM_DEVICE_WIMAX (device), specific_object);
		return nsp ? nm_wimax_nsp_check_compatible (nsp, connection) : FALSE;
	}

	/* Ensure the connection applies to an NSP in the scan list */
	for (ns_iter = priv->nsp_list; ns_iter; ns_iter = ns_iter->next) {
		if (nm_wimax_nsp_check_compatible (NM_WIMAX_NSP (ns_iter->data), connection))
			return TRUE;
	}

	return FALSE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (device);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	NMSettingWimax *s_wimax;
	const GByteArray *setting_mac;
	const guint8 *hw_address;
	char *format;
	const char *nsp_name = NULL;
	NMWimaxNsp *nsp = NULL;
	GSList *iter;

	s_wimax = nm_connection_get_setting_wimax (connection);

	if (!specific_object) {
		/* If not given a specific object, we need at minimum an NSP name */
		if (!s_wimax) {
			g_set_error_literal (error,
			                     NM_WIMAX_ERROR,
			                     NM_WIMAX_ERROR_CONNECTION_INVALID,
			                     "A 'wimax' setting is required if no NSP path was given.");
			return FALSE;
		}

		nsp_name = nm_setting_wimax_get_network_name (s_wimax);
		if (!nsp_name || !strlen (nsp_name)) {
			g_set_error_literal (error,
			                     NM_WIMAX_ERROR,
			                     NM_WIMAX_ERROR_CONNECTION_INVALID,
			                     "A 'wimax' setting with a valid network name is required if no NSP path was given.");
			return FALSE;
		}

		/* Find a compatible NSP in the list */
		nsp = get_nsp_by_name (self, nsp_name);

		/* If we still don't have an NSP, then the WiMAX settings needs to be
		 * fully specified by the client.  Might not be able to find the NSP
		 * if the scan didn't find the NSP yet.
		 */
		if (!nsp) {
			if (!nm_setting_verify (NM_SETTING (s_wimax), NULL, error))
				return FALSE;
		}
	} else {
		/* Find a compatible NSP in the list */
		for (iter = priv->nsp_list; iter; iter = g_slist_next (iter)) {
			if (!strcmp (specific_object, nm_wimax_nsp_get_dbus_path (NM_WIMAX_NSP (iter->data)))) {
				nsp = NM_WIMAX_NSP (iter->data);
				break;
			}
		}

		if (!nsp) {
			g_set_error (error,
			             NM_WIMAX_ERROR,
			             NM_WIMAX_ERROR_NSP_NOT_FOUND,
			             "The NSP %s was not in the scan list.",
			             specific_object);
			return FALSE;
		}

		nsp_name = nm_wimax_nsp_get_name (nsp);
	}

	/* Add a WiMAX setting if one doesn't exist */
	if (!s_wimax) {
		s_wimax = (NMSettingWimax *) nm_setting_wimax_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wimax));
	}

	g_assert (nsp_name);
	format = g_strdup_printf ("%s %%d", nsp_name);
	nm_utils_complete_generic (connection,
	                           NM_SETTING_WIMAX_SETTING_NAME,
	                           existing_connections,
	                           format,
	                           nsp_name,
	                           TRUE);
	g_free (format);
	g_object_set (G_OBJECT (s_wimax), NM_SETTING_WIMAX_NETWORK_NAME, nsp_name, NULL);

	setting_mac = nm_setting_wimax_get_mac_address (s_wimax);
	hw_address = nm_device_get_hw_address (device, NULL);
	if (setting_mac) {
		/* Make sure the setting MAC (if any) matches the device's permanent MAC */
		if (memcmp (setting_mac->data, hw_address, ETH_ALEN)) {
			g_set_error (error,
				         NM_SETTING_WIMAX_ERROR,
				         NM_SETTING_WIMAX_ERROR_INVALID_PROPERTY,
				         NM_SETTING_WIMAX_MAC_ADDRESS);
			return FALSE;
		}
	} else {
		GByteArray *mac;
		const guint8 null_mac[ETH_ALEN] = { 0, 0, 0, 0, 0, 0 };

		/* Lock the connection to this device by default */
		if (memcmp (hw_address, null_mac, ETH_ALEN)) {
			mac = g_byte_array_sized_new (ETH_ALEN);
			g_byte_array_append (mac, hw_address, ETH_ALEN);
			g_object_set (G_OBJECT (s_wimax), NM_SETTING_WIMAX_MAC_ADDRESS, mac, NULL);
			g_byte_array_free (mac, TRUE);
		}
	}

	return TRUE;
}

static gboolean
can_auto_connect (NMDevice *device,
                  NMConnection *connection,
                  char **specific_object)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (device);
	GSList *iter;

	if (!NM_DEVICE_CLASS (nm_device_wimax_parent_class)->can_auto_connect (device, connection, specific_object))
		return FALSE;

	for (iter = priv->nsp_list; iter; iter = iter->next) {
		NMWimaxNsp *nsp = NM_WIMAX_NSP (iter->data);

		if (nm_wimax_nsp_check_compatible (nsp, connection)) {
			*specific_object = (char *) nm_wimax_nsp_get_dbus_path (nsp);
			return TRUE;
		}
	}

	return FALSE;
}

static gboolean
is_available (NMDevice *device)
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

static void
clear_connected_poll (NMDeviceWimax *self)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	if (priv->poll_id) {
		g_source_remove (priv->poll_id);
		priv->poll_id = 0;
	}
}

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (device);
	NMActRequest *req;
	GSList *iter;
	const char *path;
	NMWimaxNsp *nsp = NULL;

	clear_link_timeout (NM_DEVICE_WIMAX (device));

	*reason = NM_DEVICE_STATE_REASON_NONE;

	req = nm_device_get_act_request (device);
	if (!req)
		return NM_ACT_STAGE_RETURN_FAILURE;

	path = nm_active_connection_get_specific_object (NM_ACTIVE_CONNECTION (req));
	if (!path)
		return NM_ACT_STAGE_RETURN_FAILURE;

	/* Find the NSP in the scan list */
	for (iter = priv->nsp_list; iter; iter = iter->next) {
		NMWimaxNsp *candidate = NM_WIMAX_NSP (iter->data);

		if (!strcmp (path, nm_wimax_nsp_get_dbus_path (candidate))) {
			nsp = candidate;
			break;
		}
	}

	/* Couldn't find the NSP for some reason */
	if (nsp == NULL)
		return NM_ACT_STAGE_RETURN_FAILURE;

	set_current_nsp (NM_DEVICE_WIMAX (device), nsp);

	priv->prepare_done = TRUE;

	/* If the device is scanning, it won't connect, so we have to wait until
	 * it's not scanning to proceed to stage 2.
	 */
	if (priv->status == WIMAX_API_DEVICE_STATUS_Scanning)
		return NM_ACT_STAGE_RETURN_POSTPONE;

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (device);
	NMConnection *connection;
	NMSettingWimax *s_wimax;
	const char *nsp_name, *iface;
	int ret;

	iface = nm_device_get_iface (device);
	g_assert (iface);

	connection = nm_device_get_connection (device);
	g_assert (connection);

	s_wimax = nm_connection_get_setting_wimax (connection);
	g_assert (s_wimax);

	nsp_name = nm_setting_wimax_get_network_name (s_wimax);
	g_assert (nsp_name);

	nm_log_info (LOGD_WIMAX, "(%s): connecting to NSP '%s'",
	             iface, nsp_name);

	priv->connect_failed = FALSE;
	ret = iwmx_sdk_connect (priv->sdk, nsp_name);
	if (ret < 0 && ret != -EINPROGRESS) {
		nm_log_err (LOGD_WIMAX, "(%s): failed to connect to NSP '%s'",
		            iface, nsp_name);
		*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	/* FIXME: Is 40 seconds good estimation? I have no idea */
	priv->activation_timeout_id = g_timeout_add_seconds (40, activation_timed_out, device);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static void
force_disconnect (NMDeviceWimax *self, struct wmxsdk *sdk)
{
	WIMAX_API_DEVICE_STATUS status;
	int ret;
	const char *iface;

	g_return_if_fail (sdk != NULL);

	iface = nm_device_get_iface (NM_DEVICE (self));

	status = iwmxsdk_status_get (sdk);
	if ((int) status < 0) {
		nm_log_err (LOGD_WIMAX, "(%s): failed to read WiMAX device status: %d",
		            iface, status);
		return;
	}

	if (   status == WIMAX_API_DEVICE_STATUS_Connecting
	    || status == WIMAX_API_DEVICE_STATUS_Data_Connected) {
		nm_log_dbg (LOGD_WIMAX, "(%s): requesting disconnect", iface);
		ret = iwmx_sdk_disconnect (sdk);
		if (ret < 0 && ret != -EINPROGRESS) {
			nm_log_err (LOGD_WIMAX, "(%s): failed to disconnect WiMAX device: %d",
			            iface, ret);
		}
	}
}

static void
deactivate (NMDevice *device)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (device);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	clear_activation_timeout (self);
	clear_link_timeout (self);
	clear_connected_poll (self);

	set_current_nsp (self, NULL);

	if (priv->sdk) {
		/* Read explicit status here just to make sure we have the most
		 * up-to-date status and to ensure we disconnect if needed.
		 */
		force_disconnect (self, priv->sdk);
	}
}

/*************************************************************************/

static void
wmx_state_change_cb (struct wmxsdk *wmxsdk,
                     WIMAX_API_DEVICE_STATUS new_status,
                     WIMAX_API_DEVICE_STATUS old_status,
                     WIMAX_API_STATUS_REASON reason,
                     WIMAX_API_CONNECTION_PROGRESS_INFO progress,
                     void *user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (user_data);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	NMDeviceState state;
	const char *iface;
	gboolean old_available = FALSE;
	const char *nsp_name = NULL;

	iface = nm_device_get_iface (NM_DEVICE (self));
	nm_log_info (LOGD_WIMAX, "(%s): wimax state change %s -> %s (%s (%d))",
	             iface,
	             iwmx_sdk_dev_status_to_str (old_status),
	             iwmx_sdk_dev_status_to_str (new_status),
	             iwmx_sdk_con_progress_to_str (progress),
	             progress);

	if (new_status == old_status)
		return;

	state = nm_device_get_state (NM_DEVICE (self));
	old_available = nm_device_is_available (NM_DEVICE (self));

	priv->status = new_status;
	if (priv->current_nsp)
		nsp_name = nm_wimax_nsp_get_name (priv->current_nsp);

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
			force_disconnect (self, wmxsdk);
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
	if (nm_device_is_activating (NM_DEVICE (self))) {
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

		/* If stage2 was postponed because the device was scanning or something,
		 * then check if we need to move to stage2 now that the device might be
		 * ready.
		 */
		if (state == NM_DEVICE_STATE_PREPARE && priv->prepare_done) {
			if (   new_status == WIMAX_API_DEVICE_STATUS_Ready
			    || new_status == WIMAX_API_DEVICE_STATUS_Connecting) {
				nm_device_activate_schedule_stage2_device_config (NM_DEVICE (self));
				return;
			}
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

	nm_log_dbg (LOGD_WIMAX, "(%s): link timed out", nm_device_get_iface (NM_DEVICE (self)));
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
	state = nm_device_get_state (NM_DEVICE (self));

	nm_log_dbg (LOGD_WIMAX, "(%s): media status change to %s",
	            iface, iwmx_sdk_media_status_to_str (new_status));

	/* We only care about media events while activated */
	if (state != NM_DEVICE_STATE_ACTIVATED)
		return;

	clear_link_timeout (self);

	switch (new_status) {
	case WIMAX_API_MEDIA_STATUS_LINK_UP:
		break;
	case WIMAX_API_MEDIA_STATUS_LINK_DOWN:
		nm_log_dbg (LOGD_WIMAX, "(%s): starting link timeout", iface);
		priv->link_timeout_id = g_timeout_add_seconds (15, link_timeout_cb, self);
		break;
	case WIMAX_API_MEDIA_STATUS_LINK_RENEW:
		nm_log_dbg (LOGD_WIMAX, "(%s): renewing DHCP lease", iface);
		if (!nm_device_dhcp4_renew (NM_DEVICE (self), TRUE)) {
			nm_device_state_changed (NM_DEVICE (self),
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_DHCP_FAILED);
		}
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

	if (nm_device_is_activating (NM_DEVICE (self))) {
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

		emit_nsp_added_removed (self, NSP_REMOVED, nsp, FALSE);
		priv->nsp_list = g_slist_remove (priv->nsp_list, nsp);
		g_object_unref (nsp);
	}

	if (g_slist_length(to_remove) > 0)
	    nm_device_recheck_available_connections (NM_DEVICE (self));

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
		guint signalq;
		NMWimaxNsp *nsp;
		gboolean new_nsp;

		nsp = get_nsp_by_name (self, nsp_name);
		new_nsp = (nsp == NULL);
		if (new_nsp) {
			nsp = nm_wimax_nsp_new (nsp_name);
			nm_log_dbg (LOGD_WIMAX, "(%s): new WiMAX NSP '%s'", iface, nsp_name);
		}

		net_type = nm_wimax_util_convert_network_type (sdk_nsp->networkType);
		if (net_type != nm_wimax_nsp_get_network_type (nsp))
			g_object_set (nsp, NM_WIMAX_NSP_NETWORK_TYPE, net_type, NULL);

		signalq = CLAMP (sdk_nsp->linkQuality, 0, 100);
		if (signalq != nm_wimax_nsp_get_signal_quality (nsp))
			g_object_set (nsp, NM_WIMAX_NSP_SIGNAL_QUALITY, signalq, NULL);

		nm_log_dbg (LOGD_WIMAX, "(%s): WiMAX NSP '%s' quality %d%% type %d",
			        iface, nsp_name, sdk_nsp->linkQuality, net_type);

		if (new_nsp) {
			priv->nsp_list = g_slist_append (priv->nsp_list, nsp);
			nm_wimax_nsp_export_to_dbus (nsp);
			emit_nsp_added_removed (self, NSP_ADDED, nsp, TRUE);
		}
	}
}

static void
wmx_removed_cb (struct wmxsdk *wmxsdk, void *user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (user_data);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	if (!priv->sdk) {
		nm_log_dbg (LOGD_WIMAX, "(%s): removed unhandled WiMAX interface", wmxsdk->ifname);
		return;
	}

	nm_log_dbg (LOGD_WIMAX, "(%s): removed WiMAX interface", wmxsdk->ifname);

	/* Clear callbacks just in case we don't hold the last reference */
	iwmx_sdk_set_callbacks (priv->sdk, NULL, NULL, NULL, NULL, NULL, NULL);
	wmxsdk_unref (priv->sdk);
	priv->sdk = NULL;

	priv->status = WIMAX_API_DEVICE_STATUS_UnInitialized;
	nm_device_state_changed (NM_DEVICE (self),
							 NM_DEVICE_STATE_UNAVAILABLE,
							 NM_DEVICE_STATE_REASON_NONE);
}

/*************************************************************************/

static inline gint
sdk_rssi_to_dbm (guint raw_rssi)
{
	/* Values range from 0x00 to 0x53, where -123dBm is encoded as 0x00 and
	 * -40dBm encoded as 0x53 in 1dB increments.
	 */
	return raw_rssi - 123;
}

static inline gint
sdk_cinr_to_db (guint raw_cinr)
{
	/* Values range from 0x00 to 0x3F, where -10dB is encoded as 0x00 and
	 * 53dB encoded as 0x3F in 1dB increments.
	 */
	return raw_cinr - 10;
}

static inline gint
sdk_tx_pow_to_dbm (guint raw_tx_pow)
{
	/* Values range from 0x00 to 0xFF, where -84dBm is encoded as 0x00 and
	 * 43.5dBm is encoded as 0xFF in 0.5dB increments.  Normalize so that
	 * 0 dBm == 0.
	 */
	return (int) (((double) raw_tx_pow / 2.0) - 84) * 2;
}

static void
set_link_status (NMDeviceWimax *self, WIMAX_API_LINK_STATUS_INFO_EX *link_status)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	guint center_freq = 0;
	gint conv_rssi = 0, conv_cinr = 0, conv_tx_pow = 0;
	char *new_bsid = NULL;

	if (link_status) {
		center_freq = link_status->centerFrequency;
		conv_rssi = sdk_rssi_to_dbm (link_status->RSSI);
		conv_cinr = sdk_cinr_to_db (link_status->CINR);
		conv_tx_pow = sdk_tx_pow_to_dbm (link_status->txPWR);
		new_bsid = nm_utils_hwaddr_ntoa_len (link_status->bsId, 6);
	}

	if (priv->center_freq != center_freq) {
		priv->center_freq = center_freq;
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIMAX_CENTER_FREQUENCY);
	}

	if (priv->rssi != conv_rssi) {
		priv->rssi = conv_rssi;
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIMAX_RSSI);
	}

	if (priv->cinr != conv_cinr) {
		priv->cinr = conv_cinr;
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIMAX_CINR);
	}

	if (priv->tx_power != conv_tx_pow) {
		priv->tx_power = conv_tx_pow;
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIMAX_TX_POWER);
	}

	if (g_strcmp0 (priv->bsid, new_bsid) != 0) {
		g_free (priv->bsid);
		priv->bsid = new_bsid;
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIMAX_BSID);
	} else
		g_free (new_bsid);
}

static gboolean
connected_poll_cb (gpointer user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (user_data);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	WIMAX_API_CONNECTED_NSP_INFO_EX *sdk_nsp;
	WIMAX_API_LINK_STATUS_INFO_EX *link_status;

	g_return_val_if_fail (priv->sdk != NULL, FALSE);

	/* Get details of the connected NSP */
	sdk_nsp = iwmx_sdk_get_connected_network (priv->sdk);
	if (sdk_nsp) {
		const char *nsp_name = (const char *) sdk_nsp->NSPName;
		NMWimaxNsp *nsp;

		nsp = get_nsp_by_name (self, nsp_name);
		if (nsp) {
			NMWimaxNspNetworkType net_type;
			guint signalq;

			net_type = nm_wimax_util_convert_network_type (sdk_nsp->networkType);
			if (net_type != nm_wimax_nsp_get_network_type (nsp))
				g_object_set (nsp, NM_WIMAX_NSP_NETWORK_TYPE, net_type, NULL);

			signalq = sdk_nsp->linkQuality;
			if (signalq != nm_wimax_nsp_get_signal_quality (nsp))
				g_object_set (nsp, NM_WIMAX_NSP_SIGNAL_QUALITY, signalq, NULL);

			nm_log_dbg (LOGD_WIMAX, "(%s): WiMAX NSP '%s' quality %d%% type %d",
					    nm_device_get_iface (NM_DEVICE (self)),
					    nsp_name, sdk_nsp->linkQuality, net_type);
		}
		free (sdk_nsp);
	}

	/* Get details of the current radio link */
	link_status = iwmx_sdk_get_link_status_info (priv->sdk);
	if (link_status) {
		set_link_status (self, link_status);
		free (link_status);
	}

	return TRUE; /* reschedule */
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (device);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

	/* Reset our stage1 (Prepare) done marker since it's only valid while in stage1 */
	priv->prepare_done = FALSE;

	if (new_state < NM_DEVICE_STATE_DISCONNECTED)
		remove_all_nsps (self);

	/* Request initial NSP list when device is first started */
	if (   new_state == NM_DEVICE_STATE_DISCONNECTED
	    && old_state < NM_DEVICE_STATE_DISCONNECTED) {
		if (priv->sdk)
			iwmx_sdk_get_networks (priv->sdk);
	}

	if (new_state == NM_DEVICE_STATE_FAILED || new_state <= NM_DEVICE_STATE_DISCONNECTED) {
		set_current_nsp (self, NULL);
		clear_activation_timeout (self);
	}

	if (new_state == NM_DEVICE_STATE_ACTIVATED) {
		/* poll link quality and BSID */
		clear_connected_poll (self);
		priv->poll_id = g_timeout_add_seconds (10, connected_poll_cb, self);
		connected_poll_cb (self);
	} else {
		clear_link_timeout (self);
		clear_connected_poll (self);
		set_link_status (self, NULL);
	}
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

	/* We only track one wmxsdk at a time because the WiMAX SDK is pretty stupid */
	if (priv->sdk) {
		nm_log_dbg (LOGD_WIMAX, "(%s): WiMAX interface already known", sdk->ifname);
		return;
	}

	nm_log_dbg (LOGD_WIMAX, "(%s): new WiMAX interface (%s)", sdk->ifname, sdk->name);

	/* Now that we have an SDK, schedule an idle handler to start the device up */
	priv->sdk = wmxsdk_ref (sdk);
	iwmx_sdk_set_callbacks(priv->sdk,
	                       wmx_state_change_cb,
	                       wmx_media_status_cb,
	                       wmx_connect_result_cb,
	                       wmx_scan_result_cb,
	                       wmx_removed_cb,
	                       self);
	iwmx_sdk_set_fast_reconnect_enabled (priv->sdk, 0);

	if (!priv->sdk_action_defer_id)
		priv->sdk_action_defer_id = g_idle_add (sdk_action_defer_cb, self);
}

/*************************************************************************/

NMDevice *
nm_device_wimax_new (NMPlatformLink *platform_device)
{
	NMDevice *device;

	g_return_val_if_fail (platform_device != NULL, NULL);

	device = (NMDevice *) g_object_new (NM_TYPE_DEVICE_WIMAX,
	                                    NM_DEVICE_PLATFORM_DEVICE, platform_device,
	                                    NM_DEVICE_TYPE_DESC, "WiMAX",
	                                    NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_WIMAX,
	                                    NM_DEVICE_RFKILL_TYPE, RFKILL_TYPE_WIMAX,
	                                    NULL);
	if (device) {
		struct wmxsdk *sdk;

		nm_wimax_util_sdk_ref ();

		/* See if the SDK already knows about this interface */
		sdk = iwmx_sdk_get_wmxsdk_for_iface (platform_device->name);
		if (sdk)
			wmx_new_sdk_cb (sdk, device);

		/* If it doesn't, we want to be notified when it does */
		iwmx_sdk_new_callback_register (wmx_new_sdk_cb, device);
	}

	return device;
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
	GPtrArray *array;
	GSList *iter;

	switch (prop_id) {
	case PROP_NSPS:
		array = g_ptr_array_sized_new (4);
		for (iter = priv->nsp_list; iter; iter = g_slist_next (iter))
			g_ptr_array_add (array, g_strdup (nm_wimax_nsp_get_dbus_path (NM_WIMAX_NSP (iter->data))));
		g_value_take_boxed (value, array);
		break;
	case PROP_ACTIVE_NSP:
		if (priv->current_nsp)
			g_value_set_boxed (value, nm_wimax_nsp_get_dbus_path (priv->current_nsp));
		else
			g_value_set_boxed (value, "/");
		break;
	case PROP_CENTER_FREQ:
		g_value_set_uint (value, priv->center_freq);
		break;
	case PROP_RSSI:
		g_value_set_int (value, priv->rssi);
		break;
	case PROP_CINR:
		g_value_set_int (value, priv->cinr);
		break;
	case PROP_TX_POWER:
		g_value_set_int (value, priv->tx_power);
		break;
	case PROP_BSID:
		g_value_set_string (value, priv->bsid);
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
	clear_connected_poll (self);

	if (priv->sdk_action_defer_id)
		g_source_remove (priv->sdk_action_defer_id);

	if (priv->sdk) {
		iwmx_sdk_set_callbacks (priv->sdk, NULL, NULL, NULL, NULL, NULL, NULL);
		wmxsdk_unref (priv->sdk);
	}

	g_free (priv->bsid);

	set_current_nsp (self, NULL);

	g_slist_free_full (priv->nsp_list, g_object_unref);

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

	device_class->check_connection_compatible = check_connection_compatible;
	device_class->check_connection_available = check_connection_available;
	device_class->complete_connection = complete_connection;
	device_class->can_auto_connect = can_auto_connect;
	device_class->is_available = is_available;
	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->act_stage2_config = act_stage2_config;
	device_class->deactivate = deactivate;
	device_class->set_enabled = set_enabled;

	device_class->state_changed = device_state_changed;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_NSPS,
		 g_param_spec_boxed (NM_DEVICE_WIMAX_NSPS,
		                     "Network access points",
		                     "Network access points",
		                     DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
		                     G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_ACTIVE_NSP,
		g_param_spec_boxed (NM_DEVICE_WIMAX_ACTIVE_NSP,
		                    "Active NSP",
		                    "Currently active NSP",
		                    DBUS_TYPE_G_OBJECT_PATH,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CENTER_FREQ,
		 g_param_spec_uint (NM_DEVICE_WIMAX_CENTER_FREQUENCY,
		                    "Center frequency",
		                    "Center frequency",
		                    0, G_MAXUINT, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_RSSI,
		 g_param_spec_int (NM_DEVICE_WIMAX_RSSI,
		                   "RSSI",
		                   "RSSI",
		                   G_MININT, G_MAXINT, 0,
		                   G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CINR,
		 g_param_spec_int (NM_DEVICE_WIMAX_CINR,
		                   "CINR",
		                   "CINR",
		                   G_MININT, G_MAXINT, 0,
		                   G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_TX_POWER,
		 g_param_spec_int (NM_DEVICE_WIMAX_TX_POWER,
		                   "TX Power",
		                   "TX Power",
		                   G_MININT, G_MAXINT, 0,
		                   G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_BSID,
		 g_param_spec_string (NM_DEVICE_WIMAX_BSID,
		                      "BSID",
		                      "BSID",
		                      NULL,
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

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_device_wimax_object_info);

	dbus_g_error_domain_register (NM_WIMAX_ERROR, NULL, NM_TYPE_WIMAX_ERROR);
}
