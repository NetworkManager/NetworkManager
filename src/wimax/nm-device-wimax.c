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

typedef enum
{
	NM_WIMAX_ERROR_CONNECTION_NOT_WIMAX = 0,
	NM_WIMAX_ERROR_CONNECTION_INVALID,
	NM_WIMAX_ERROR_CONNECTION_INCOMPATIBLE,
	NM_WIMAX_ERROR_NSP_NOT_FOUND,
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
			/* NSP not found in the scan list. */
			ENUM_ENTRY (NM_WIMAX_ERROR_NSP_NOT_FOUND, "NspNotFound"),
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

guint32
nm_device_wimax_get_center_frequency (NMDeviceWimax *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (self), 0);

	return NM_DEVICE_WIMAX_GET_PRIVATE (self)->center_freq;
}

gint
nm_device_wimax_get_rssi (NMDeviceWimax *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (self), 0);

	return NM_DEVICE_WIMAX_GET_PRIVATE (self)->rssi;
}

gint
nm_device_wimax_get_cinr (NMDeviceWimax *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (self), 0);

	return NM_DEVICE_WIMAX_GET_PRIVATE (self)->cinr;
}

gint
nm_device_wimax_get_tx_power (NMDeviceWimax *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (self), 0);

	return NM_DEVICE_WIMAX_GET_PRIVATE (self)->tx_power;
}

const char *
nm_device_wimax_get_bsid (NMDeviceWimax *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_WIMAX (self), NULL);

	return NM_DEVICE_WIMAX_GET_PRIVATE (self)->bsid;
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

	set_current_nsp (self, NULL);

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
	const char *iface;

	iface = nm_device_get_iface (dev);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_warn (LOGD_HW, "(%s): couldn't open control socket.", iface);
		return;
	}

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), IFNAMSIZ);

	errno = 0;
	if (ioctl (fd, SIOCGIFHWADDR, &req) < 0) {
		nm_log_err (LOGD_HW | LOGD_WIMAX,
		            "(%s): failed to read hardware address (error %d)",
		            iface, errno);
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

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	connection_type = nm_setting_connection_get_connection_type (s_con);
	if (strcmp (connection_type, NM_SETTING_WIMAX_SETTING_NAME)) {
		g_set_error (error,
		             NM_WIMAX_ERROR, NM_WIMAX_ERROR_CONNECTION_NOT_WIMAX,
		             "The connection was not a WiMAX connection.");
		return FALSE;
	}

	s_wimax = nm_connection_get_setting_wimax (connection);
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

static gboolean
real_complete_connection (NMDevice *device,
                          NMConnection *connection,
                          const char *specific_object,
                          const GSList *existing_connections,
                          GError **error)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (device);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);
	NMSettingWimax *s_wimax;
	const GByteArray *setting_mac;
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
	if (setting_mac) {
		/* Make sure the setting MAC (if any) matches the device's permanent MAC */
		if (memcmp (setting_mac->data, &priv->hw_addr.ether_addr_octet, ETH_ALEN)) {
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
		if (memcmp (&priv->hw_addr.ether_addr_octet, null_mac, ETH_ALEN)) {
			mac = g_byte_array_sized_new (ETH_ALEN);
			g_byte_array_append (mac, priv->hw_addr.ether_addr_octet, ETH_ALEN);
			g_object_set (G_OBJECT (s_wimax), NM_SETTING_WIMAX_MAC_ADDRESS, mac, NULL);
			g_byte_array_free (mac, TRUE);
		}
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

		s_con = nm_connection_get_setting_connection (connection);
		g_assert (s_con);

		if (!nm_setting_connection_get_autoconnect (s_con))
			continue;

		connection_type = nm_setting_connection_get_connection_type (s_con);
		if (strcmp (connection_type, NM_SETTING_WIMAX_SETTING_NAME))
			continue;

		s_wimax = nm_connection_get_setting_wimax (connection);
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
real_act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
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

	path = nm_act_request_get_specific_object (req);
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

	/* If the device is scanning, it won't connect, so we have to wait until
	 * it's not scanning to proceed to stage 2.
	 */
	if (priv->status == WIMAX_API_DEVICE_STATUS_Scanning)
		return NM_ACT_STAGE_RETURN_POSTPONE;

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
real_act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (device);
	NMConnection *connection;
	NMSettingWimax *s_wimax;
	const char *nsp_name, *iface;
	int ret;

	iface = nm_device_get_iface (device);
	g_assert (iface);

	connection = nm_act_request_get_connection (nm_device_get_act_request (device));
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
real_deactivate (NMDevice *device)
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

	nm_log_info (LOGD_WIMAX, "(%s): wimax state change %s -> %s (reason %d)",
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

		/* If stage2 was postponed because the device was scanning or something,
		 * then check if we need to move to stage2 now that the device might be
		 * ready.
		 */
		if (state == NM_DEVICE_STATE_PREPARE) {
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
	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (self));

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
		priv->link_timeout_id = g_timeout_add (15, link_timeout_cb, self);
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
		new_bsid = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
		                            link_status->bsId[0], link_status->bsId[1],
		                            link_status->bsId[2], link_status->bsId[3],
		                            link_status->bsId[4], link_status->bsId[5]);
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
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceWimax *self = NM_DEVICE_WIMAX (device);
	NMDeviceWimaxPrivate *priv = NM_DEVICE_WIMAX_GET_PRIVATE (self);

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
		iwmx_sdk_set_fast_reconnect_enabled (priv->sdk, 0);

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
	device_class->complete_connection = real_complete_connection;
	device_class->get_best_auto_connection = real_get_best_auto_connection;
	device_class->get_generic_capabilities = real_get_generic_capabilities;
	device_class->is_available = real_is_available;
	device_class->act_stage1_prepare = real_act_stage1_prepare;
	device_class->act_stage2_config = real_act_stage2_config;
	device_class->deactivate = real_deactivate;

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

	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class, G_STRUCT_OFFSET (NMDeviceWimaxClass, properties_changed));


	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_device_wimax_object_info);

	dbus_g_error_domain_register (NM_WIMAX_ERROR, NULL, NM_TYPE_WIMAX_ERROR);
}
