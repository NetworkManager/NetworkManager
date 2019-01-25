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
 * Copyright (C) 2017 Intel Corporation
 */

#include "nm-default.h"

#include "nm-device-iwd.h"

#include "nm-common-macros.h"
#include "devices/nm-device.h"
#include "devices/nm-device-private.h"
#include "nm-utils.h"
#include "nm-act-request.h"
#include "nm-setting-connection.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"
#include "settings/nm-settings-connection.h"
#include "settings/nm-settings.h"
#include "nm-wifi-utils.h"
#include "nm-wifi-common.h"
#include "nm-core-internal.h"
#include "nm-config.h"
#include "nm-iwd-manager.h"
#include "nm-dbus-manager.h"
#include "nm-dbus-compat.h"

#include "devices/nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceIwd);

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceIwd,
	PROP_MODE,
	PROP_BITRATE,
	PROP_ACCESS_POINTS,
	PROP_ACTIVE_ACCESS_POINT,
	PROP_CAPABILITIES,
	PROP_SCANNING,
	PROP_LAST_SCAN,
);

enum {
	SCANNING_PROHIBITED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	GDBusObject *   dbus_obj;
	GDBusProxy *    dbus_device_proxy;
	GDBusProxy *    dbus_station_proxy;
	GDBusProxy *    dbus_ap_proxy;
	GDBusProxy *    dbus_adhoc_proxy;
	CList           aps_lst_head;
	NMWifiAP *      current_ap;
	GCancellable *  cancellable;
	NMDeviceWifiCapabilities capabilities;
	NMActRequestGetSecretsCallId *wifi_secrets_id;
	guint           periodic_scan_id;
	bool            enabled:1;
	bool            can_scan:1;
	bool            can_connect:1;
	bool            scanning:1;
	bool            scan_requested:1;
	bool            act_mode_switch:1;
	gint64          last_scan;
} NMDeviceIwdPrivate;

struct _NMDeviceIwd {
	NMDevice parent;
	NMDeviceIwdPrivate _priv;
};

struct _NMDeviceIwdClass {
	NMDeviceClass parent;

	/* Signals */
	gboolean (*scanning_prohibited) (NMDeviceIwd *device, gboolean periodic);
};

/*****************************************************************************/

G_DEFINE_TYPE (NMDeviceIwd, nm_device_iwd, NM_TYPE_DEVICE)

#define NM_DEVICE_IWD_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceIwd, NM_IS_DEVICE_IWD)

/*****************************************************************************/

static void schedule_periodic_scan (NMDeviceIwd *self,
                                    gboolean initial_scan);

/*****************************************************************************/

static void
_ap_dump (NMDeviceIwd *self,
          NMLogLevel log_level,
          const NMWifiAP *ap,
          const char *prefix,
          gint32 now_s)
{
	char buf[1024];

	buf[0] = '\0';
	_NMLOG (log_level, LOGD_WIFI_SCAN, "wifi-ap: %-7s %s",
	        prefix,
	        nm_wifi_ap_to_string (ap, buf, sizeof (buf), now_s));
}

/* Callers ensure we're not removing current_ap */
static void
ap_add_remove (NMDeviceIwd *self,
               gboolean is_adding, /* or else is removing */
               NMWifiAP *ap,
               gboolean recheck_available_connections)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	if (is_adding) {
		g_object_ref (ap);
		ap->wifi_device = NM_DEVICE (self);
		c_list_link_tail (&priv->aps_lst_head, &ap->aps_lst);
		nm_dbus_object_export (NM_DBUS_OBJECT (ap));
		_ap_dump (self, LOGL_DEBUG, ap, "added", 0);
		nm_device_wifi_emit_signal_access_point (NM_DEVICE (self), ap, TRUE);
	} else {
		ap->wifi_device = NULL;
		c_list_unlink (&ap->aps_lst);
		_ap_dump (self, LOGL_DEBUG, ap, "removed", 0);
	}

	_notify (self, PROP_ACCESS_POINTS);

	if (!is_adding) {
		nm_device_wifi_emit_signal_access_point (NM_DEVICE (self), ap, FALSE);
		nm_dbus_object_clear_and_unexport (&ap);
	}

	nm_device_emit_recheck_auto_activate (NM_DEVICE (self));
	if (recheck_available_connections)
		nm_device_recheck_available_connections (NM_DEVICE (self));
}

static void
set_current_ap (NMDeviceIwd *self, NMWifiAP *new_ap, gboolean recheck_available_connections)
{
	NMDeviceIwdPrivate *priv;
	NMWifiAP *old_ap;

	g_return_if_fail (NM_IS_DEVICE_IWD (self));

	priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	old_ap = priv->current_ap;

	if (old_ap == new_ap)
		return;

	if (new_ap)
		priv->current_ap = g_object_ref (new_ap);
	else
		priv->current_ap = NULL;

	if (old_ap) {
		if (nm_wifi_ap_get_fake (old_ap))
			ap_add_remove (self, FALSE, old_ap, recheck_available_connections);
		g_object_unref (old_ap);
	}

	_notify (self, PROP_ACTIVE_ACCESS_POINT);
	_notify (self, PROP_MODE);
}

static void
remove_all_aps (NMDeviceIwd *self)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMWifiAP *ap, *ap_safe;

	if (c_list_is_empty (&priv->aps_lst_head))
		return;

	set_current_ap (self, NULL, FALSE);

	c_list_for_each_entry_safe (ap, ap_safe, &priv->aps_lst_head, aps_lst)
		ap_add_remove (self, FALSE, ap, FALSE);

	nm_device_emit_recheck_auto_activate (NM_DEVICE (self));
	nm_device_recheck_available_connections (NM_DEVICE (self));
}

static GVariant *
vardict_from_network_type (const char *type)
{
	GVariantBuilder builder;
	const char *key_mgmt = "";
	const char *pairwise = "ccmp";

	if (!strcmp (type, "psk"))
		key_mgmt = "wpa-psk";
	else if (!strcmp (type, "8021x"))
		key_mgmt = "wpa-eap";
	else
		return NULL;

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&builder, "{sv}", "KeyMgmt",
	                       g_variant_new_strv (&key_mgmt, 1));
	g_variant_builder_add (&builder, "{sv}", "Pairwise",
	                       g_variant_new_strv (&pairwise, 1));
	g_variant_builder_add (&builder, "{sv}", "Group",
	                       g_variant_new_string ("ccmp"));
	return g_variant_new ("a{sv}", &builder);
}

static void
insert_ap_from_network (NMDeviceIwd *self,
                        GHashTable *aps,
                        const char *path,
                        int16_t signal,
                        uint32_t ap_id)
{
	gs_unref_object GDBusProxy *network_proxy = NULL;
	gs_unref_variant GVariant *name_value = NULL, *type_value = NULL;
	const char *name, *type;
	GVariantBuilder builder;
	gs_unref_variant GVariant *props = NULL;
	GVariant *rsn;
	uint8_t bssid[6];
	NMWifiAP *ap;

	if (g_hash_table_lookup (aps, path)) {
		_LOGD (LOGD_WIFI, "Duplicate network at %s", path);
		return;
	}

	network_proxy = nm_iwd_manager_get_dbus_interface (nm_iwd_manager_get (),
	                                                   path,
	                                                   NM_IWD_NETWORK_INTERFACE);
	if (!network_proxy)
		return;

	name_value = g_dbus_proxy_get_cached_property (network_proxy, "Name");
	type_value = g_dbus_proxy_get_cached_property (network_proxy, "Type");
	if (   !name_value
	    || !g_variant_is_of_type (name_value, G_VARIANT_TYPE_STRING)
	    || !type_value
	    || !g_variant_is_of_type (type_value, G_VARIANT_TYPE_STRING))
		return;

	name = g_variant_get_string (name_value, NULL);
	type = g_variant_get_string (type_value, NULL);

	/* What we get from IWD are networks, or ESSs, that may contain
	 * multiple APs, or BSSs, each.  We don't get information about any
	 * specific BSSs within an ESS but we can safely present each ESS
	 * as an individual BSS to NM, which will be seen as ESSs comprising
	 * a single BSS each.  NM won't be able to handle roaming but IWD
	 * already does that.  We fake the BSSIDs as they don't play any
	 * role either.
	 */
	bssid[0] = 0x00;
	bssid[1] = 0x01;
	bssid[2] = 0x02;
	bssid[3] = ap_id >> 16;
	bssid[4] = ap_id >> 8;
	bssid[5] = ap_id;

	/* WEP not supported */
	if (nm_streq (type, "wep"))
		return;

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&builder, "{sv}", "BSSID",
	                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, bssid, 6, 1));
	g_variant_builder_add (&builder, "{sv}", "Mode",
	                       g_variant_new_string ("infrastructure"));

	rsn = vardict_from_network_type (type);
	if (rsn)
		g_variant_builder_add (&builder, "{sv}", "RSN", rsn);

	props = g_variant_new ("a{sv}", &builder);

	ap = nm_wifi_ap_new_from_properties (path, props);

	nm_wifi_ap_set_ssid_arr (ap,
	                         (const guint8 *) name,
	                         NM_MIN (32, strlen (name)));

	nm_wifi_ap_set_strength (ap, nm_wifi_utils_level_to_quality (signal / 100));
	nm_wifi_ap_set_freq (ap, 2417);
	nm_wifi_ap_set_max_bitrate (ap, 65000);
	g_hash_table_insert (aps, (gpointer) nm_wifi_ap_get_supplicant_path (ap), ap);
}

static void
get_ordered_networks_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	NMDeviceIwdPrivate *priv;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *variant = NULL;
	GVariantIter *networks;
	const char *path, *name, *type;
	int16_t signal;
	NMWifiAP *ap, *ap_safe, *new_ap;
	gboolean changed = FALSE;
	GHashTableIter ap_iter;
	gs_unref_hashtable GHashTable *new_aps = NULL;
	gboolean compat;
	const char *return_sig;
	static uint32_t ap_id = 0;

	variant = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), res, &error);
	if (!variant) {
		_LOGE (LOGD_WIFI, "Station.GetOrderedNetworks failed: %s",
		       error->message);
		return;
	}

	priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	/* Depending on whether we're using the Station interface or the Device
	 * interface for compatibility with IWD <= 0.7, the return signature of
	 * GetOrderedNetworks will be different.
	 */
	compat = priv->dbus_station_proxy == priv->dbus_device_proxy;
	return_sig = compat ? "(a(osns))" : "(a(on))";

	if (!g_variant_is_of_type (variant, G_VARIANT_TYPE (return_sig))) {
		_LOGE (LOGD_WIFI, "Station.GetOrderedNetworks returned type %s instead of %s",
		       g_variant_get_type_string (variant), return_sig);
		return;
	}

	new_aps = g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, g_object_unref);

	g_variant_get (variant, return_sig, &networks);

	if (compat) {
		while (g_variant_iter_next (networks, "(&o&sn&s)", &path, &name, &signal, &type))
			insert_ap_from_network (self, new_aps, path, signal, ap_id++);
	} else {
		while (g_variant_iter_next (networks, "(&on)", &path, &signal))
			insert_ap_from_network (self, new_aps, path, signal, ap_id++);
	}

	g_variant_iter_free (networks);

	c_list_for_each_entry_safe (ap, ap_safe, &priv->aps_lst_head, aps_lst) {

		new_ap = g_hash_table_lookup (new_aps,
		                              nm_wifi_ap_get_supplicant_path (ap));
		if (new_ap) {
			if (nm_wifi_ap_set_strength (ap, nm_wifi_ap_get_strength (new_ap))) {
				_ap_dump (self, LOGL_TRACE, ap, "updated", 0);
				changed = TRUE;
			}
			g_hash_table_remove (new_aps,
			                     nm_wifi_ap_get_supplicant_path (ap));
			continue;
		}

		if (ap == priv->current_ap) {
			/* Normally IWD will prevent the current AP from being
			 * removed from the list and set a low signal strength,
			 * but just making sure.
			 */
			continue;
		}

		ap_add_remove (self, FALSE, ap, FALSE);
		changed = TRUE;
	}

	g_hash_table_iter_init (&ap_iter, new_aps);
	while (g_hash_table_iter_next (&ap_iter, NULL, (gpointer) &ap)) {
		ap_add_remove (self, TRUE, ap, FALSE);
		g_hash_table_iter_remove (&ap_iter);
		changed = TRUE;
	}

	if (changed) {
		nm_device_emit_recheck_auto_activate (NM_DEVICE (self));
		nm_device_recheck_available_connections (NM_DEVICE (self));
	}
}

static void
update_aps (NMDeviceIwd *self)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	if (!priv->cancellable)
		priv->cancellable = g_cancellable_new ();

	g_dbus_proxy_call (priv->dbus_station_proxy, "GetOrderedNetworks",
	                   NULL, G_DBUS_CALL_FLAGS_NONE,
	                   2000, priv->cancellable,
	                   get_ordered_networks_cb, self);
}

static void
send_disconnect (NMDeviceIwd *self)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	g_dbus_proxy_call (priv->dbus_station_proxy, "Disconnect",
	                   NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
}

static void
wifi_secrets_cancel (NMDeviceIwd *self)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	if (priv->wifi_secrets_id)
		nm_act_request_cancel_secrets (NULL, priv->wifi_secrets_id);
	nm_assert (!priv->wifi_secrets_id);
}

static void
cleanup_association_attempt (NMDeviceIwd *self, gboolean disconnect)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	wifi_secrets_cancel (self);

	set_current_ap (self, NULL, TRUE);

	if (disconnect && priv->dbus_station_proxy)
		send_disconnect (self);
}

static void
reset_mode (NMDeviceIwd *self,
            GCancellable *cancellable,
            GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	g_dbus_proxy_call (priv->dbus_device_proxy,
	                   DBUS_INTERFACE_PROPERTIES ".Set",
	                   g_variant_new ("(ssv)", NM_IWD_DEVICE_INTERFACE,
	                                  "Mode",
	                                  g_variant_new_string ("station")),
	                   G_DBUS_CALL_FLAGS_NONE, 2000,
	                   cancellable,
	                   callback,
	                   user_data);
}

static void
deactivate (NMDevice *device)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	if (!priv->dbus_obj)
		return;

	cleanup_association_attempt (self, TRUE);
	priv->act_mode_switch = FALSE;

	if (!priv->dbus_station_proxy)
		reset_mode (self, NULL, NULL, NULL);
}

static void
disconnect_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	gs_unref_object NMDeviceIwd *self = NULL;
	NMDeviceDeactivateCallback callback;
	gpointer callback_user_data;
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;

	nm_utils_user_data_unpack (user_data, &self, &callback, &callback_user_data);

	variant = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), res, &error);
	callback (NM_DEVICE (self), error, callback_user_data);
}

static void
disconnect_cb_on_idle (gpointer user_data,
                       GCancellable *cancellable)
{
	gs_unref_object NMDeviceIwd *self = NULL;
	NMDeviceDeactivateCallback callback;
	gpointer callback_user_data;
	gs_free_error GError *cancelled_error = NULL;

	nm_utils_user_data_unpack (user_data, &self, &callback, &callback_user_data);

	g_cancellable_set_error_if_cancelled (cancellable, &cancelled_error);
	callback (NM_DEVICE (self), cancelled_error, callback_user_data);
}

static void
deactivate_async (NMDevice *device,
                  GCancellable *cancellable,
                  NMDeviceDeactivateCallback callback,
                  gpointer callback_user_data)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	gpointer user_data;

	nm_assert (G_IS_CANCELLABLE (cancellable));
	nm_assert (callback);

	user_data = nm_utils_user_data_pack (g_object_ref (self), callback, callback_user_data);

	if (!priv->dbus_obj) {
		nm_utils_invoke_on_idle (disconnect_cb_on_idle, user_data, cancellable);
		return;
	}

	cleanup_association_attempt (self, FALSE);
	priv->act_mode_switch = FALSE;

	if (priv->dbus_station_proxy) {
		g_dbus_proxy_call (priv->dbus_station_proxy,
		                   "Disconnect",
		                   NULL,
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   cancellable,
		                   disconnect_cb,
		                   user_data);
	} else
		reset_mode (self, cancellable, disconnect_cb, user_data);
}

static gboolean
is_connection_known_network (NMConnection *connection)
{
	NMSettingWireless *s_wireless;
	NMIwdNetworkSecurity security;
	gboolean security_ok;
	GBytes *ssid;
	gs_free char *ssid_utf8 = NULL;

	s_wireless = nm_connection_get_setting_wireless (connection);
	if (!s_wireless)
		return FALSE;

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	if (!ssid)
		return FALSE;

	ssid_utf8 = _nm_utils_ssid_to_utf8 (ssid);

	security = nm_wifi_connection_get_iwd_security (connection, &security_ok);
	if (!security_ok)
		return FALSE;

	return nm_iwd_manager_is_known_network (nm_iwd_manager_get (),
	                                        ssid_utf8, security);
}

static gboolean
is_ap_known_network (NMWifiAP *ap)
{
	GDBusProxy *network_proxy;
	gs_unref_variant GVariant *known_network = NULL;

	network_proxy = nm_iwd_manager_get_dbus_interface (nm_iwd_manager_get (),
	                                                   nm_wifi_ap_get_supplicant_path (ap),
	                                                   NM_IWD_NETWORK_INTERFACE);
	if (!network_proxy)
		return FALSE;

	known_network = g_dbus_proxy_get_cached_property (network_proxy, "KnownNetwork");
	g_object_unref (network_proxy);

	return    known_network
	       && g_variant_is_of_type (known_network, G_VARIANT_TYPE_OBJECT_PATH);
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMSettingWireless *s_wireless;
	const char *mac;
	const char * const *mac_blacklist;
	int i;
	const char *perm_hw_addr;
	const char *mode;
	NMIwdNetworkSecurity security;
	gboolean mapped;

	if (!NM_DEVICE_CLASS (nm_device_iwd_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	s_wireless = nm_connection_get_setting_wireless (connection);

	perm_hw_addr = nm_device_get_permanent_hw_address (device);
	mac = nm_setting_wireless_get_mac_address (s_wireless);
	if (perm_hw_addr) {
		if (mac && !nm_utils_hwaddr_matches (mac, -1, perm_hw_addr, -1)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "device MAC address does not match the profile");
			return FALSE;
		}

		/* Check for MAC address blacklist */
		mac_blacklist = nm_setting_wireless_get_mac_address_blacklist (s_wireless);
		for (i = 0; mac_blacklist[i]; i++) {
			nm_assert (nm_utils_hwaddr_valid (mac_blacklist[i], ETH_ALEN));

			if (nm_utils_hwaddr_matches (mac_blacklist[i], -1, perm_hw_addr, -1)) {
				nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
				                            "MAC address blacklisted");
				return FALSE;
			}
		}
	} else if (mac) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "device has no valid MAC address as required by profile");
		return FALSE;
	}

	/* Hidden SSIDs not supported in any mode (client or AP) */
	if (nm_setting_wireless_get_hidden (s_wireless)) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "hidden networks not supported by the IWD backend");
		return FALSE;
	}

	security = nm_wifi_connection_get_iwd_security (connection, &mapped);
	if (!mapped) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "connection authentication type not supported by IWD backend");
		return FALSE;
	}

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (NM_IN_STRSET (mode, NULL, NM_SETTING_WIRELESS_MODE_INFRA)) {
		/* 8021x networks can only be used if they've been provisioned on the IWD side and
		 * thus are Known Networks.
		 */
		if (security == NM_IWD_NETWORK_SECURITY_8021X) {
			if (!is_connection_known_network (connection)) {
				nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
				                            "802.1x connections must have IWD provisioning files");
				return FALSE;
			}
		} else if (!NM_IN_SET (security, NM_IWD_NETWORK_SECURITY_NONE, NM_IWD_NETWORK_SECURITY_PSK)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "IWD backend only supports Open, PSK and 802.1x network "
			                            "authentication in Infrastructure mode");
			return FALSE;
		}
	} else if (nm_streq (mode, NM_SETTING_WIRELESS_MODE_AP)) {
		if (!(priv->capabilities & NM_WIFI_DEVICE_CAP_AP)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "device does not support Access Point mode");
			return FALSE;
		}

		if (!NM_IN_SET (security, NM_IWD_NETWORK_SECURITY_PSK)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "IWD backend only supports PSK authentication in AP mode");
			return FALSE;
		}
	} else if (nm_streq (mode, NM_SETTING_WIRELESS_MODE_ADHOC)) {
		if (!(priv->capabilities & NM_WIFI_DEVICE_CAP_ADHOC)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "device does not support Ad-Hoc mode");
			return FALSE;
		}

		if (!NM_IN_SET (security, NM_IWD_NETWORK_SECURITY_NONE, NM_IWD_NETWORK_SECURITY_PSK)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "IWD backend only supports Open and PSK authentication in Ad-Hoc mode");
			return FALSE;
		}
	} else {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "%s type profiles not supported by IWD backend");
		return FALSE;
	}

	return TRUE;
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object,
                            GError **error)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMSettingWireless *s_wifi;
	const char *mode;
	NMWifiAP *ap = NULL;

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wifi, FALSE);

	/* a connection that is available for a certain @specific_object, MUST
	 * also be available in general (without @specific_object). */

	if (specific_object) {
		ap = nm_wifi_ap_lookup_for_device (NM_DEVICE (self), specific_object);
		if (!ap) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "requested access point not found");
			return FALSE;
		}
		if (!nm_wifi_ap_check_compatible (ap, connection)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "requested access point is not compatible with profile");
			return FALSE;
		}
	}

	/* AP and Ad-Hoc connections can be activated independent of the scan list */
	mode = nm_setting_wireless_get_mode (s_wifi);
	if (NM_IN_STRSET (mode, NM_SETTING_WIRELESS_MODE_AP, NM_SETTING_WIRELESS_MODE_ADHOC))
		return TRUE;

	if (NM_FLAGS_HAS (flags, _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_IGNORE_AP))
		return TRUE;

	if (!ap)
		ap = nm_wifi_aps_find_first_compatible (&priv->aps_lst_head, connection);

	if (!ap) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "no compatible access point found");
		return FALSE;
	}

	/* 8021x networks can only be used if they've been provisioned on the IWD side and
	 * thus are Known Networks.
	 */
	if (nm_wifi_connection_get_iwd_security (connection, NULL) == NM_IWD_NETWORK_SECURITY_8021X) {
		if (!is_ap_known_network (ap)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "802.1x network is not an IWD Known Network (missing provisioning file?)");
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     NMConnection *const*existing_connections,
                     GError **error)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMSettingWireless *s_wifi;
	const char *setting_mac;
	gs_free char *ssid_utf8 = NULL;
	NMWifiAP *ap;
	GBytes *ssid;
	GBytes *setting_ssid = NULL;
	const char *perm_hw_addr;
	const char *mode;

	s_wifi = nm_connection_get_setting_wireless (connection);

	mode = s_wifi ? nm_setting_wireless_get_mode (s_wifi) : NULL;

	if (nm_streq0 (mode, NM_SETTING_WIRELESS_MODE_AP)) {
		if (!nm_setting_verify (NM_SETTING (s_wifi), connection, error))
			return FALSE;
		ap = NULL;
	} else if (!specific_object) {
		/* If not given a specific object, we need at minimum an SSID */
		if (!s_wifi) {
			g_set_error_literal (error,
			                     NM_DEVICE_ERROR,
			                     NM_DEVICE_ERROR_INVALID_CONNECTION,
			                     "A 'wireless' setting is required if no AP path was given.");
			return FALSE;
		}

		setting_ssid = nm_setting_wireless_get_ssid (s_wifi);
		if (!setting_ssid || g_bytes_get_size (setting_ssid) == 0) {
			g_set_error_literal (error,
			                     NM_DEVICE_ERROR,
			                     NM_DEVICE_ERROR_INVALID_CONNECTION,
			                     "A 'wireless' setting with a valid SSID is required if no AP path was given.");
			return FALSE;
		}

		/* Find a compatible AP in the scan list */
		ap = nm_wifi_aps_find_first_compatible (&priv->aps_lst_head, connection);
		if (!ap) {
			if (!nm_streq0 (mode, NM_SETTING_WIRELESS_MODE_ADHOC)) {
				g_set_error_literal (error,
				                     NM_DEVICE_ERROR,
				                     NM_DEVICE_ERROR_INVALID_CONNECTION,
				                     "No compatible AP in the scan list and hidden SSIDs not supported.");
				return FALSE;
			}

			if (!nm_setting_verify (NM_SETTING (s_wifi), connection, error))
				return FALSE;
		}
	} else {
		ap = nm_wifi_ap_lookup_for_device (NM_DEVICE (self), specific_object);
		if (!ap) {
			g_set_error (error,
			             NM_DEVICE_ERROR,
			             NM_DEVICE_ERROR_SPECIFIC_OBJECT_NOT_FOUND,
			             "The access point %s was not in the scan list.",
			             specific_object);
			return FALSE;
		}
	}

	/* Add a wifi setting if one doesn't exist yet */
	if (!s_wifi) {
		s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wifi));
	}

	ssid = nm_setting_wireless_get_ssid (s_wifi);
	if (!ssid && ap)
		ssid = nm_wifi_ap_get_ssid (ap);

	if (!ssid) {
		g_set_error_literal (error,
		                     NM_DEVICE_ERROR,
		                     NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "A 'wireless' setting with a valid SSID is required.");
		return FALSE;
	}

	if (ap) {
		if (!nm_wifi_ap_complete_connection (ap,
		                                     connection,
		                                     nm_wifi_utils_is_manf_default_ssid (ssid),
		                                     error))
			return FALSE;
	}

	ssid_utf8 = _nm_utils_ssid_to_utf8 (ssid);
	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
	                           NM_SETTING_WIRELESS_SETTING_NAME,
	                           existing_connections,
	                           ssid_utf8,
	                           ssid_utf8,
	                           NULL,
	                           TRUE);

	perm_hw_addr = nm_device_get_permanent_hw_address (device);
	if (perm_hw_addr) {
		setting_mac = nm_setting_wireless_get_mac_address (s_wifi);
		if (setting_mac) {
			/* Make sure the setting MAC (if any) matches the device's permanent MAC */
			if (!nm_utils_hwaddr_matches (setting_mac, -1, perm_hw_addr, -1)) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     "connection does not match device");
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_MAC_ADDRESS);
				return FALSE;
			}
		} else {
			guint8 tmp[ETH_ALEN];

			/* Lock the connection to this device by default if it uses a
			 * permanent MAC address (ie not a 'locally administered' one)
			 */
			nm_utils_hwaddr_aton (perm_hw_addr, tmp, ETH_ALEN);
			if (!(tmp[0] & 0x02)) {
				g_object_set (G_OBJECT (s_wifi),
				              NM_SETTING_WIRELESS_MAC_ADDRESS, perm_hw_addr,
				              NULL);
			}
		}
	}

	return TRUE;
}

static gboolean
get_variant_boolean (GVariant *v, const char *property)
{
	if (!v || !g_variant_is_of_type (v, G_VARIANT_TYPE_BOOLEAN)) {
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Property %s not cached or not boolean type", property);

		return FALSE;
	}

	return g_variant_get_boolean (v);
}

static const char *
get_variant_state (GVariant *v)
{
	if (!v || !g_variant_is_of_type (v, G_VARIANT_TYPE_STRING)) {
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "State property not cached or not a string");

		return "unknown";
	}

	return g_variant_get_string (v, NULL);
}

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMDeviceState state = nm_device_get_state (device);

	/* Available if either the device is UP and in station mode
	 * or in AP/Ad-Hoc modes while activating or activated.  Device
	 * may be temporarily DOWN while activating or deactivating and
	 * we don't want it to be marked unavailable because of this.
	 *
	 * For reference:
	 * We call nm_device_queue_recheck_available whenever
	 * priv->enabled changes or priv->dbus_station_proxy changes.
	 */
	return    priv->dbus_obj
	       && priv->enabled
	       && (   priv->dbus_station_proxy
	           || (state >= NM_DEVICE_STATE_CONFIG && state <= NM_DEVICE_STATE_DEACTIVATING));
}

static gboolean
get_autoconnect_allowed (NMDevice *device)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (NM_DEVICE_IWD (device));

	return priv->can_connect;
}

static gboolean
can_auto_connect (NMDevice *device,
                  NMSettingsConnection *sett_conn,
                  char **specific_object)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	NMWifiAP *ap;
	const char *mode;
	guint64 timestamp = 0;

	nm_assert (!specific_object || !*specific_object);

	if (!NM_DEVICE_CLASS (nm_device_iwd_parent_class)->can_auto_connect (device, sett_conn, NULL))
		return FALSE;

	connection = nm_settings_connection_get_connection (sett_conn);

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wifi, FALSE);

	/* Don't auto-activate AP or Ad-Hoc connections.
	 * Note the wpa_supplicant backend has the opposite policy.
	 */
	mode = nm_setting_wireless_get_mode (s_wifi);
	if (mode && g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_INFRA) != 0)
		return FALSE;

	/* Don't autoconnect to networks that have been tried at least once
	 * but haven't been successful, since these are often accidental choices
	 * from the menu and the user may not know the password.
	 */
	if (nm_settings_connection_get_timestamp (sett_conn, &timestamp)) {
		if (timestamp == 0)
			return FALSE;
	}

	ap = nm_wifi_aps_find_first_compatible (&priv->aps_lst_head, connection);
	if (ap) {
		/* All good; connection is usable */
		NM_SET_OUT (specific_object, g_strdup (nm_dbus_object_get_path (NM_DBUS_OBJECT (ap))));
		return TRUE;
	}

	return FALSE;
}

const CList *
_nm_device_iwd_get_aps (NMDeviceIwd *self)
{
	return &NM_DEVICE_IWD_GET_PRIVATE (self)->aps_lst_head;
}

static gboolean
check_scanning_prohibited (NMDeviceIwd *self, gboolean periodic)
{
	gboolean prohibited = FALSE;

	g_signal_emit (self, signals[SCANNING_PROHIBITED], 0, periodic, &prohibited);
	return prohibited;
}

static void
scan_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	NMDeviceIwdPrivate *priv;
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;

	variant = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), res, &error);
	if (!variant && nm_utils_error_is_cancelled (error, FALSE))
		return;

	priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	priv->scan_requested = FALSE;
	priv->last_scan = nm_utils_get_monotonic_timestamp_ms ();
	_notify (self, PROP_LAST_SCAN);

	/* On success, priv->scanning becomes true right before or right
	 * after this callback, so the next automatic scan will be
	 * scheduled when priv->scanning goes back to false.  On error,
	 * schedule a retry now.
	 */
	if (error && !priv->scanning)
		schedule_periodic_scan (self, FALSE);
}

static void
dbus_request_scan_cb (NMDevice *device,
                      GDBusMethodInvocation *context,
                      NMAuthSubject *subject,
                      GError *error,
                      gpointer user_data)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv;
	gs_unref_variant GVariant *scan_options = user_data;

	if (error) {
		g_dbus_method_invocation_return_gerror (context, error);
		return;
	}

	if (check_scanning_prohibited (self, FALSE)) {
		g_dbus_method_invocation_return_error_literal (context,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_ALLOWED,
		                                               "Scanning not allowed at this time");
		return;
	}

	priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	if (!priv->can_scan) {
		g_dbus_method_invocation_return_error_literal (context,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_ALLOWED,
		                                               "Scanning not allowed while unavailable");
		return;
	}

	if (scan_options) {
		gs_unref_variant GVariant *val = g_variant_lookup_value (scan_options, "ssids", NULL);

		if (val) {
			g_dbus_method_invocation_return_error_literal (context,
			                                               NM_DEVICE_ERROR,
			                                               NM_DEVICE_ERROR_NOT_ALLOWED,
			                                               "'ssid' scan option not supported");
			return;
		}
	}

	if (!priv->scanning && !priv->scan_requested) {
		g_dbus_proxy_call (priv->dbus_station_proxy, "Scan",
		                   NULL, G_DBUS_CALL_FLAGS_NONE, -1,
		                   priv->cancellable, scan_cb, self);
		priv->scan_requested = TRUE;
	}

	g_dbus_method_invocation_return_value (context, NULL);
}

void
_nm_device_iwd_request_scan (NMDeviceIwd *self,
                             GVariant *options,
                             GDBusMethodInvocation *invocation)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);

	if (!priv->can_scan) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_ALLOWED,
		                                               "Scanning not allowed while unavailable");
		return;
	}

	g_signal_emit_by_name (device,
	                       NM_DEVICE_AUTH_REQUEST,
	                       invocation,
	                       NULL,
	                       NM_AUTH_PERMISSION_WIFI_SCAN,
	                       TRUE,
	                       dbus_request_scan_cb,
	                       options ? g_variant_ref (options) : NULL);
}

static gboolean
scanning_prohibited (NMDeviceIwd *self, gboolean periodic)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	g_return_val_if_fail (priv->dbus_obj != NULL, TRUE);

	switch (nm_device_get_state (NM_DEVICE (self))) {
	case NM_DEVICE_STATE_UNKNOWN:
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_IP_CHECK:
	case NM_DEVICE_STATE_SECONDARIES:
	case NM_DEVICE_STATE_DEACTIVATING:
		/* Prohibit scans when unusable or activating */
		return TRUE;
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_FAILED:
	case NM_DEVICE_STATE_ACTIVATED:
		break;
	}

	/* Prohibit scans if IWD is busy */
	return !priv->can_scan;
}

/*
 * try_reply_agent_request
 *
 * Check if the connection settings already have the secrets corresponding
 * to the IWD agent method that was invoked.  If they do, send the method reply
 * with the appropriate secrets.  Otherwise return the missing secret's setting
 * name and key so the caller can send a NM secrets request with this data.
 * Return TRUE in either case, return FALSE if an error is detected.
 */
static gboolean
try_reply_agent_request (NMDeviceIwd *self,
                         NMConnection *connection,
                         GDBusMethodInvocation *invocation,
                         const char **setting_name,
                         const char **setting_key,
                         gboolean *replied)
{
	const char *method_name = g_dbus_method_invocation_get_method_name (invocation);
	NMSettingWirelessSecurity *s_wireless_sec;
	NMSetting8021x *s_8021x;

	s_wireless_sec = nm_connection_get_setting_wireless_security (connection);
	s_8021x = nm_connection_get_setting_802_1x (connection);

	*replied = FALSE;

	if (!strcmp (method_name, "RequestPassphrase")) {
		const char *psk;

		if (!s_wireless_sec)
			return FALSE;

		psk = nm_setting_wireless_security_get_psk (s_wireless_sec);
		if (psk) {
			_LOGD (LOGD_DEVICE | LOGD_WIFI,
			       "Returning the PSK to the IWD Agent");

			g_dbus_method_invocation_return_value (invocation,
			                                       g_variant_new ("(s)", psk));
			*replied = TRUE;
			return TRUE;
		}

		*setting_name = NM_SETTING_WIRELESS_SECURITY_SETTING_NAME;
		*setting_key = NM_SETTING_WIRELESS_SECURITY_PSK;
		return TRUE;
	} else if (!strcmp (method_name, "RequestPrivateKeyPassphrase")) {
		const char *password;

		if (!s_8021x)
			return FALSE;

		password = nm_setting_802_1x_get_private_key_password (s_8021x);
		if (password) {
			_LOGD (LOGD_DEVICE | LOGD_WIFI,
			       "Returning the private key password to the IWD Agent");

			g_dbus_method_invocation_return_value (invocation,
			                                       g_variant_new ("(s)", password));
			*replied = TRUE;
			return TRUE;
		}

		*setting_name = NM_SETTING_802_1X_SETTING_NAME;
		*setting_key = NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD;
		return TRUE;
	} else if (!strcmp (method_name, "RequestUserNameAndPassword")) {
		const char *identity, *password;

		if (!s_8021x)
			return FALSE;

		identity = nm_setting_802_1x_get_identity (s_8021x);
		password = nm_setting_802_1x_get_password (s_8021x);
		if (identity && password) {
			_LOGD (LOGD_DEVICE | LOGD_WIFI,
			       "Returning the username and password to the IWD Agent");

			g_dbus_method_invocation_return_value (invocation,
			                                       g_variant_new ("(ss)", identity, password));
			*replied = TRUE;
			return TRUE;
		}

		*setting_name = NM_SETTING_802_1X_SETTING_NAME;
		if (!identity)
			*setting_key = NM_SETTING_802_1X_IDENTITY;
		else
			*setting_key = NM_SETTING_802_1X_PASSWORD;
		return TRUE;
	} else if (!strcmp (method_name, "RequestUserPassword")) {
		const char *password;

		if (!s_8021x)
			return FALSE;

		password = nm_setting_802_1x_get_password (s_8021x);
		if (password) {
			_LOGD (LOGD_DEVICE | LOGD_WIFI,
			       "Returning the user password to the IWD Agent");

			g_dbus_method_invocation_return_value (invocation,
			                                       g_variant_new ("(s)", password));
			*replied = TRUE;
			return TRUE;
		}

		*setting_name = NM_SETTING_802_1X_SETTING_NAME;
		*setting_key = NM_SETTING_802_1X_PASSWORD;
		return TRUE;
	} else
		return FALSE;
}

static void
wifi_secrets_get_one (NMDeviceIwd *self,
                      const char *setting_name,
                      NMSecretAgentGetSecretsFlags flags,
                      const char *setting_key,
                      GDBusMethodInvocation *invocation);

static void
wifi_secrets_cb (NMActRequest *req,
                 NMActRequestGetSecretsCallId *call_id,
                 NMSettingsConnection *s_connection,
                 GError *error,
                 gpointer user_data)
{
	NMDeviceIwd *self;
	NMDeviceIwdPrivate *priv;
	NMDevice *device;
	GDBusMethodInvocation *invocation;
	const char *setting_name;
	const char *setting_key;
	gboolean replied;
	NMSecretAgentGetSecretsFlags get_secret_flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;

	nm_utils_user_data_unpack (user_data, &self, &invocation);

	g_return_if_fail (NM_IS_DEVICE_IWD (self));

	priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	device = NM_DEVICE (self);

	g_return_if_fail (priv->wifi_secrets_id == call_id);

	priv->wifi_secrets_id = NULL;

	if (nm_utils_error_is_cancelled (error, FALSE)) {
		g_dbus_method_invocation_return_error_literal (invocation, NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_INVALID_CONNECTION,
		                                               "NM secrets request cancelled");
		return;
	}

	g_return_if_fail (req == nm_device_get_act_request (device));
	g_return_if_fail (nm_act_request_get_settings_connection (req) == s_connection);

	if (nm_device_get_state (device) != NM_DEVICE_STATE_NEED_AUTH)
		goto secrets_error;

	if (error) {
		_LOGW (LOGD_WIFI, "%s", error->message);
		goto secrets_error;
	}

	if (!try_reply_agent_request (self, nm_act_request_get_applied_connection (req),
	                              invocation, &setting_name, &setting_key,
	                              &replied))
		goto secrets_error;

	if (replied) {
		/* Change state back to what it was before NEED_AUTH */
		nm_device_state_changed (device, NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_REASON_NONE);
		return;
	}

	if (nm_settings_connection_get_timestamp (nm_act_request_get_settings_connection (req),
	                                          NULL))
		get_secret_flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;

	/* Request further secrets if we still need something */
	wifi_secrets_get_one (self, setting_name, get_secret_flags,
	                      setting_key, invocation);
	return;

secrets_error:
	g_dbus_method_invocation_return_error_literal (invocation, NM_DEVICE_ERROR,
	                                               NM_DEVICE_ERROR_INVALID_CONNECTION,
	                                               "NM secrets request failed");
	/* Now wait for the Connect callback to update device state */
}

static void
wifi_secrets_get_one (NMDeviceIwd *self,
                      const char *setting_name,
                      NMSecretAgentGetSecretsFlags flags,
                      const char *setting_key,
                      GDBusMethodInvocation *invocation)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMActRequest *req;

	wifi_secrets_cancel (self);

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	priv->wifi_secrets_id = nm_act_request_get_secrets (req,
	                                                    TRUE,
	                                                    setting_name,
	                                                    flags,
	                                                    NM_MAKE_STRV (setting_key),
	                                                    wifi_secrets_cb,
	                                                    nm_utils_user_data_pack (self, invocation));
}

static void
network_connect_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	NMDevice *device = NM_DEVICE (self);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	GBytes *ssid;
	gs_free char *ssid_utf8 = NULL;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED;
	GVariant *value;

	variant = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), res, &error);
	if (!variant) {
		gs_free char *dbus_error = NULL;

		/* Connection failed; radio problems or if the network wasn't
		 * open, the passwords or certificates may be wrong.
		 */

		_LOGE (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) Network.Connect failed: %s",
		       error->message);

		if (nm_utils_error_is_cancelled (error, FALSE))
			return;

		if (!NM_IN_SET (nm_device_get_state (device), NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_NEED_AUTH))
			return;

		connection = nm_device_get_applied_connection (device);
		if (!connection)
			goto failed;

		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_DBUS_ERROR))
			dbus_error = g_dbus_error_get_remote_error (error);

		if (nm_streq0 (dbus_error, "net.connman.iwd.Failed")) {
			nm_connection_clear_secrets (connection);

			/* If secrets were wrong, we'd be getting a net.connman.iwd.Failed */
			reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
		} else if (nm_streq0 (dbus_error, "net.connman.iwd.Aborted")) {
			/* If agent call was cancelled we'd be getting a net.connman.iwd.Aborted */
			reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
		}

		goto failed;
	}

	nm_assert (nm_device_get_state (device) == NM_DEVICE_STATE_CONFIG);

	connection = nm_device_get_applied_connection (device);
	if (!connection)
		goto failed;

	s_wifi = nm_connection_get_setting_wireless (connection);
	if (!s_wifi)
		goto failed;

	ssid = nm_setting_wireless_get_ssid (s_wifi);
	if (!ssid)
		goto failed;

	ssid_utf8 = _nm_utils_ssid_to_utf8 (ssid);

	_LOGI (LOGD_DEVICE | LOGD_WIFI,
	       "Activation: (wifi) Stage 2 of 5 (Device Configure) successful.  Connected to '%s'.",
	       ssid_utf8);
	nm_device_activate_schedule_stage3_ip_config_start (device);

	return;

failed:
	/* Call Disconnect to make sure IWD's autoconnect is disabled */
	cleanup_association_attempt (self, TRUE);

	nm_device_queue_state (device, NM_DEVICE_STATE_FAILED, reason);

	value = g_dbus_proxy_get_cached_property (priv->dbus_station_proxy, "State");
	if (!priv->can_connect && nm_streq0 (get_variant_state (value), "disconnected")) {
		priv->can_connect = true;
		nm_device_emit_recheck_auto_activate (device);
	}
	g_variant_unref (value);
}

static void
act_failed_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	NMDevice *device = NM_DEVICE (self);
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;

	variant = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), res, &error);
	if (!variant && nm_utils_error_is_cancelled (error, FALSE))
		return;

	/* Change state to FAILED unless already done by state_changed
	 * which may have been triggered by the station interface
	 * appearing on DBus.
	 */
	if (nm_device_get_state (device) == NM_DEVICE_STATE_CONFIG)
		nm_device_queue_state (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
}

static void
act_start_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;
	NMSettingWireless *s_wireless;
	GBytes *ssid;
	gs_free char *ssid_utf8 = NULL;

	variant = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), res, &error);
	if (!variant) {
		_LOGE (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) Network.Connect failed: %s",
		       error->message);

		if (nm_utils_error_is_cancelled (error, FALSE))
			return;

		if (!NM_IN_SET (nm_device_get_state (device), NM_DEVICE_STATE_CONFIG))
			return;

		goto error;
	}

	nm_assert (nm_device_get_state (device) == NM_DEVICE_STATE_CONFIG);

	s_wireless = nm_device_get_applied_setting (device, NM_TYPE_SETTING_WIRELESS);
	if (!s_wireless)
		goto error;

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	if (!ssid)
		goto error;

	ssid_utf8 = _nm_utils_ssid_to_utf8 (ssid);

	_LOGI (LOGD_DEVICE | LOGD_WIFI,
	       "Activation: (wifi) Stage 2 of 5 (Device Configure) successful.  Started '%s'.",
	       ssid_utf8);

	nm_device_activate_schedule_stage3_ip_config_start (device);
	return;

error:
	reset_mode (self, priv->cancellable, act_failed_cb, self);
}

/* Check if we're activating an AP/AdHoc connection and if the target
 * DBus interface has appeared already.  If so proceed to call Start or
 * StartOpen on that interface.
 */
static void
act_check_interface (NMDeviceIwd *self)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;
	GDBusProxy *proxy = NULL;
	GBytes *ssid;
	gs_free char *ssid_utf8 = NULL;
	const char *mode;

	if (!priv->act_mode_switch)
		return;

	s_wireless = (NMSettingWireless *) nm_device_get_applied_setting (device, NM_TYPE_SETTING_WIRELESS);

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (nm_streq0 (mode, NM_SETTING_WIRELESS_MODE_AP))
		proxy = priv->dbus_ap_proxy;
	else if (nm_streq0 (mode, NM_SETTING_WIRELESS_MODE_ADHOC))
		proxy = priv->dbus_adhoc_proxy;

	if (!proxy)
		return;

	priv->act_mode_switch = FALSE;

	if (!NM_IN_SET (nm_device_get_state (device), NM_DEVICE_STATE_CONFIG))
		return;

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	if (!ssid)
		goto failed;

	ssid_utf8 = _nm_utils_ssid_to_utf8 (ssid);

	s_wireless_sec = (NMSettingWirelessSecurity *) nm_device_get_applied_setting (device, NM_TYPE_SETTING_WIRELESS_SECURITY);

	if (!s_wireless_sec) {
		g_dbus_proxy_call (proxy, "StartOpen",
		                   g_variant_new ("(s)", ssid_utf8),
		                   G_DBUS_CALL_FLAGS_NONE, G_MAXINT,
		                   priv->cancellable, act_start_cb, self);
	} else {
		const char *psk = nm_setting_wireless_security_get_psk (s_wireless_sec);

		if (!psk) {
			_LOGE (LOGD_DEVICE | LOGD_WIFI,
			       "Activation: (wifi) No PSK for '%s'.",
			       ssid_utf8);
			goto failed;
		}

		g_dbus_proxy_call (proxy, "Start",
		                   g_variant_new ("(ss)", ssid_utf8, psk),
		                   G_DBUS_CALL_FLAGS_NONE, G_MAXINT,
		                   priv->cancellable, act_start_cb, self);
	}

	_LOGD (LOGD_DEVICE | LOGD_WIFI,
	       "Activation: (wifi) Called Start('%s').",
	       ssid_utf8);
	return;

failed:
	reset_mode (self, priv->cancellable, act_failed_cb, self);
}

static void
act_set_mode_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;

	variant = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), res, &error);
	if (!variant) {
		_LOGE (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) Setting Device.Mode failed: %s",
		       error->message);

		if (nm_utils_error_is_cancelled (error, FALSE))
			return;

		if (   !NM_IN_SET (nm_device_get_state (device), NM_DEVICE_STATE_CONFIG)
		    || !priv->act_mode_switch)
			return;

		priv->act_mode_switch = FALSE;
		nm_device_queue_state (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		return;
	}

	_LOGD (LOGD_DEVICE | LOGD_WIFI, "Activation: (wifi) IWD Device.Mode set successfully");

	act_check_interface (self);
}

static void
act_set_mode (NMDeviceIwd *self)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	const char *iwd_mode;
	const char *mode;
	NMSettingWireless *s_wireless;

	s_wireless = (NMSettingWireless *) nm_device_get_applied_setting (device, NM_TYPE_SETTING_WIRELESS);
	mode = nm_setting_wireless_get_mode (s_wireless);

	/* We need to first set interface mode (Device.Mode) to ap or ad-hoc.
	 * We can't directly queue a call to the Start/StartOpen method on
	 * the DBus interface that's going to be created after the property
	 * set call returns.
	 */
	iwd_mode = nm_streq (mode, NM_SETTING_WIRELESS_MODE_AP) ? "ap" : "ad-hoc";

	if (!priv->cancellable)
		priv->cancellable = g_cancellable_new ();

	g_dbus_proxy_call (priv->dbus_device_proxy,
	                   DBUS_INTERFACE_PROPERTIES ".Set",
	                   g_variant_new ("(ssv)", NM_IWD_DEVICE_INTERFACE,
	                                  "Mode",
	                                  g_variant_new ("s", iwd_mode)),
	                   G_DBUS_CALL_FLAGS_NONE, 2000,
	                   priv->cancellable, act_set_mode_cb, self);
	priv->act_mode_switch = TRUE;
}

static void
act_psk_cb (NMActRequest *req,
            NMActRequestGetSecretsCallId *call_id,
            NMSettingsConnection *s_connection,
            GError *error,
            gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	NMDeviceIwdPrivate *priv;
	NMDevice *device;

	if (nm_utils_error_is_cancelled (error, FALSE))
		return;

	priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	device = NM_DEVICE (self);

	g_return_if_fail (priv->wifi_secrets_id == call_id);
	priv->wifi_secrets_id = NULL;

	g_return_if_fail (req == nm_device_get_act_request (device));
	g_return_if_fail (nm_act_request_get_settings_connection (req) == s_connection);

	if (nm_device_get_state (device) != NM_DEVICE_STATE_NEED_AUTH)
		goto secrets_error;

	if (error) {
		_LOGW (LOGD_WIFI, "%s", error->message);
		goto secrets_error;
	}

	_LOGD (LOGD_DEVICE | LOGD_WIFI, "Activation: (wifi) missing PSK request completed");

	/* Change state back to what it was before NEED_AUTH */
	nm_device_state_changed (device, NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_REASON_NONE);
	act_set_mode (self);
	return;

secrets_error:
	nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NO_SECRETS);
	cleanup_association_attempt (self, FALSE);
}

static void
set_powered (NMDeviceIwd *self, gboolean powered)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	g_dbus_proxy_call (priv->dbus_device_proxy,
	                   DBUS_INTERFACE_PROPERTIES ".Set",
	                   g_variant_new ("(ssv)", NM_IWD_DEVICE_INTERFACE,
	                                  "Powered",
	                                  g_variant_new ("b", powered)),
	                   G_DBUS_CALL_FLAGS_NONE, 2000,
	                   NULL, NULL, NULL);
}

/*****************************************************************************/

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMActStageReturn ret;
	NMWifiAP *ap = NULL;
	NMActRequest *req;
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	const char *mode;
	const char *ap_path;

	ret = NM_DEVICE_CLASS (nm_device_iwd_parent_class)->act_stage1_prepare (device, out_failure_reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	req = nm_device_get_act_request (device);
	g_return_val_if_fail (req, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_act_request_get_applied_connection (req);
	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wireless, NM_ACT_STAGE_RETURN_FAILURE);

	/* AP mode never uses a specific object or existing scanned AP */
	mode = nm_setting_wireless_get_mode (s_wireless);
	if (nm_streq0 (mode, NM_SETTING_WIRELESS_MODE_AP))
		goto add_new;

	ap_path = nm_active_connection_get_specific_object (NM_ACTIVE_CONNECTION (req));
	ap = ap_path ? nm_wifi_ap_lookup_for_device (NM_DEVICE (self), ap_path) : NULL;
	if (ap) {
		set_current_ap (self, ap, TRUE);
		return NM_ACT_STAGE_RETURN_SUCCESS;
	}

	ap = nm_wifi_aps_find_first_compatible (&priv->aps_lst_head, connection);
	if (ap) {
		nm_active_connection_set_specific_object (NM_ACTIVE_CONNECTION (req),
		                                          nm_dbus_object_get_path (NM_DBUS_OBJECT (ap)));
		set_current_ap (self, ap, TRUE);
		return NM_ACT_STAGE_RETURN_SUCCESS;
	}

	if (nm_streq0 (mode, NM_SETTING_WIRELESS_MODE_INFRA)) {
		/* Hidden networks not supported at this time */
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

add_new:
	/* If the user is trying to connect to an AP that NM doesn't yet know about
	 * (hidden network or something) or starting a Hotspot, create an fake AP
	 * from the security settings in the connection.  This "fake" AP gets used
	 * until the real one is found in the scan list (Ad-Hoc or Hidden), or until
	 * the device is deactivated (Ad-Hoc or Hotspot).
	 */
	ap = nm_wifi_ap_new_fake_from_connection (connection);
	g_return_val_if_fail (ap != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	if (nm_wifi_ap_is_hotspot (ap))
		nm_wifi_ap_set_address (ap, nm_device_get_hw_address (device));

	g_object_freeze_notify (G_OBJECT (self));
	ap_add_remove (self, TRUE, ap, FALSE);
	g_object_thaw_notify (G_OBJECT (self));
	set_current_ap (self, ap, FALSE);
	nm_active_connection_set_specific_object (NM_ACTIVE_CONNECTION (req),
	                                          nm_dbus_object_get_path (NM_DBUS_OBJECT (ap)));
	g_object_unref (ap);
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMActRequest *req;
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	const char *mode;

	req = nm_device_get_act_request (device);
	g_return_val_if_fail (req, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_act_request_get_applied_connection (req);
	g_assert (connection);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wireless, NM_ACT_STAGE_RETURN_FAILURE);

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (NM_IN_STRSET (mode, NULL, NM_SETTING_WIRELESS_MODE_INFRA)) {
		GDBusProxy *network_proxy;
		NMWifiAP *ap = priv->current_ap;

		if (!ap) {
			NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
			goto out;
		}

		/* 802.1x networks that are not IWD Known Networks will definitely
		 * fail, for other combinations we will let the Connect call fail
		 * or ask us for any missing secrets through the Agent.
		 */
		if (   nm_connection_get_setting_802_1x (connection)
		    && !is_ap_known_network (ap)) {
			_LOGI (LOGD_DEVICE | LOGD_WIFI,
			       "Activation: (wifi) access point '%s' has 802.1x security but is not configured in IWD.",
			       nm_connection_get_id (connection));

			NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_NO_SECRETS);
			goto out;
		}

		network_proxy = nm_iwd_manager_get_dbus_interface (nm_iwd_manager_get (),
		                                                   nm_wifi_ap_get_supplicant_path (ap),
		                                                   NM_IWD_NETWORK_INTERFACE);
		if (!network_proxy) {
			_LOGE (LOGD_DEVICE | LOGD_WIFI,
			       "Activation: (wifi) could not get Network interface proxy for %s",
			       nm_wifi_ap_get_supplicant_path (ap));
			NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
			goto out;
		}

		if (!priv->cancellable)
			priv->cancellable = g_cancellable_new ();

		/* Call Network.Connect.  No timeout because IWD already handles
		 * timeouts.
		 */
		g_dbus_proxy_call (network_proxy, "Connect",
		                   NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT,
		                   priv->cancellable, network_connect_cb, self);

		g_object_unref (network_proxy);
	} else if (NM_IN_STRSET (mode, NM_SETTING_WIRELESS_MODE_AP, NM_SETTING_WIRELESS_MODE_ADHOC)) {
		NMSettingWirelessSecurity *s_wireless_sec;

		s_wireless_sec = nm_connection_get_setting_wireless_security (connection);
		if (s_wireless_sec && !nm_setting_wireless_security_get_psk (s_wireless_sec)) {
			/* PSK is missing from the settings, have to request it */

			wifi_secrets_cancel (self);

			priv->wifi_secrets_id = nm_act_request_get_secrets (req,
			                                                    TRUE,
			                                                    NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
			                                                    NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION,
			                                                    NM_MAKE_STRV (NM_SETTING_WIRELESS_SECURITY_PSK),
			                                                    act_psk_cb,
			                                                    self);
			nm_device_state_changed (device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);
		} else
			act_set_mode (self);
	}

	/* We'll get stage3 started when the supplicant connects */
	ret = NM_ACT_STAGE_RETURN_POSTPONE;

out:
	if (ret == NM_ACT_STAGE_RETURN_FAILURE)
		cleanup_association_attempt (self, FALSE);

	return ret;
}

static guint32
get_configured_mtu (NMDevice *device, NMDeviceMtuSource *out_source)
{
	return nm_device_get_configured_mtu_from_connection (device,
	                                                     NM_TYPE_SETTING_WIRELESS,
	                                                     out_source);
}

static gboolean
periodic_scan_timeout_cb (gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	priv->periodic_scan_id = 0;

	if (priv->scanning || priv->scan_requested)
		return FALSE;

	g_dbus_proxy_call (priv->dbus_station_proxy, "Scan",
	                   NULL, G_DBUS_CALL_FLAGS_NONE, -1,
	                   priv->cancellable, scan_cb, self);
	priv->scan_requested = TRUE;

	return FALSE;
}

static void
schedule_periodic_scan (NMDeviceIwd *self, gboolean initial_scan)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	GVariant *value;
	gboolean disconnected;
	guint interval;

	if (!priv->can_scan || priv->scan_requested)
		return;

	value = g_dbus_proxy_get_cached_property (priv->dbus_station_proxy, "State");
	disconnected = nm_streq0 (get_variant_state (value), "disconnected");
	g_variant_unref (value);

	/* Start scan immediately after a disconnect, mode change or
	 * device UP, otherwise wait a period dependent on the current
	 * state.
	 *
	 * (initial_scan && disconnected) override priv->scanning below
	 * because of an IWD quirk where a device will often be in the
	 * autoconnect state and scanning at the time of our initial_scan,
	 * but our logic will the send it a Disconnect() causeing IWD to
	 * exit autoconnect and interrupt the ongoing scan, meaning that
	 * we still want a new scan ASAP.
	 */
	if (initial_scan && disconnected)
		interval = 0;
	else if (!priv->periodic_scan_id && !priv->scanning)
		interval = disconnected ? 10 : 20;
	else
		return;

	nm_clear_g_source (&priv->periodic_scan_id);
	priv->periodic_scan_id = g_timeout_add_seconds (interval,
	                                                periodic_scan_timeout_cb,
	                                                self);
}

static void
set_can_scan (NMDeviceIwd *self, gboolean can_scan)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	if (priv->can_scan == can_scan)
		return;

	priv->can_scan = can_scan;

	schedule_periodic_scan (self, TRUE);
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	switch (new_state) {
	case NM_DEVICE_STATE_UNMANAGED:
		break;
	case NM_DEVICE_STATE_UNAVAILABLE:
		/*
		 * If the device is enabled and the IWD manager is ready,
		 * transition to DISCONNECTED because the device is now
		 * ready to use.
		 */
		if (priv->enabled && priv->dbus_station_proxy) {
			nm_device_queue_recheck_available (device,
			                                   NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
			                                   NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		}
		break;
	case NM_DEVICE_STATE_NEED_AUTH:
		break;
	case NM_DEVICE_STATE_IP_CHECK:
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		break;
	case NM_DEVICE_STATE_FAILED:
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		break;
	default:
		break;
	}
}

static gboolean
get_enabled (NMDevice *device)
{
	return NM_DEVICE_IWD_GET_PRIVATE ((NMDeviceIwd *) device)->enabled;
}

static void
set_enabled (NMDevice *device, gboolean enabled)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMDeviceState state;

	enabled = !!enabled;

	if (priv->enabled == enabled)
		return;

	priv->enabled = enabled;

	_LOGD (LOGD_WIFI, "device now %s", enabled ? "enabled" : "disabled");

	state = nm_device_get_state (device);
	if (state < NM_DEVICE_STATE_UNAVAILABLE) {
		_LOGD (LOGD_WIFI, "(%s): device blocked by UNMANAGED state",
		       enabled ? "enable" : "disable");
		return;
	}

	if (priv->dbus_obj)
		set_powered (self, enabled);

	if (enabled) {
		if (state != NM_DEVICE_STATE_UNAVAILABLE)
			_LOGW (LOGD_CORE, "not in expected unavailable state!");

		if (priv->dbus_station_proxy) {
			nm_device_queue_recheck_available (device,
			                                   NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
			                                   NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		}
	} else {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_UNAVAILABLE,
		                         NM_DEVICE_STATE_REASON_NONE);
	}
}

static gboolean
can_reapply_change (NMDevice *device,
                    const char *setting_name,
                    NMSetting *s_old,
                    NMSetting *s_new,
                    GHashTable *diffs,
                    GError **error)
{
	NMDeviceClass *device_class;

	/* Only handle wireless setting here, delegate other settings to parent class */
	if (nm_streq (setting_name, NM_SETTING_WIRELESS_SETTING_NAME)) {
		return nm_device_hash_check_invalid_keys (diffs,
		                                          NM_SETTING_WIRELESS_SETTING_NAME,
		                                          error,
		                                          NM_SETTING_WIRELESS_MTU); /* reapplied with IP config */
	}

	device_class = NM_DEVICE_CLASS (nm_device_iwd_parent_class);
	return device_class->can_reapply_change (device,
	                                         setting_name,
	                                         s_old,
	                                         s_new,
	                                         diffs,
	                                         error);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (object);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	const char **list;

	switch (prop_id) {
	case PROP_MODE:
		if (!priv->current_ap)
			g_value_set_uint (value, NM_802_11_MODE_UNKNOWN);
		else if (nm_wifi_ap_is_hotspot (priv->current_ap))
			g_value_set_uint (value, NM_802_11_MODE_AP);
		else
			g_value_set_uint (value, nm_wifi_ap_get_mode (priv->current_ap));

		break;
	case PROP_BITRATE:
		g_value_set_uint (value, 65000);
		break;
	case PROP_CAPABILITIES:
		g_value_set_uint (value, priv->capabilities);
		break;
	case PROP_ACCESS_POINTS:
		list = nm_wifi_aps_get_paths (&priv->aps_lst_head, TRUE);
		g_value_take_boxed (value, nm_utils_strv_make_deep_copied (list));
		break;
	case PROP_ACTIVE_ACCESS_POINT:
		nm_dbus_utils_g_value_set_object_path (value, priv->current_ap);
		break;
	case PROP_SCANNING:
		g_value_set_boolean (value, priv->scanning);
		break;
	case PROP_LAST_SCAN:
		g_value_set_int64 (value,
		                   priv->last_scan > 0
		                       ? nm_utils_monotonic_timestamp_as_boottime (priv->last_scan, NM_UTILS_NS_PER_MSEC)
		                       : (gint64) -1);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
state_changed (NMDeviceIwd *self, const char *new_state)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	NMDeviceState dev_state = nm_device_get_state (device);
	gboolean iwd_connection = FALSE;
	gboolean can_connect = priv->can_connect;

	_LOGI (LOGD_DEVICE | LOGD_WIFI, "new IWD device state is %s", new_state);

	if (   dev_state >= NM_DEVICE_STATE_CONFIG
	    && dev_state <= NM_DEVICE_STATE_ACTIVATED)
		iwd_connection = TRUE;

	/* Don't allow scanning while connecting, disconnecting or roaming */
	set_can_scan (self, NM_IN_STRSET (new_state, "connected", "disconnected"));

	priv->can_connect = FALSE;

	if (NM_IN_STRSET (new_state, "connecting", "connected", "roaming")) {
		/* If we were connecting, do nothing, the confirmation of
		 * a connection success is handled in the Device.Connect
		 * method return callback.  Otherwise IWD must have connected
		 * without Network Manager's will so for simplicity force a
		 * disconnect.
		 */
		if (iwd_connection)
			return;

		_LOGW (LOGD_DEVICE | LOGD_WIFI,
		       "Unsolicited connection success, asking IWD to disconnect");
		send_disconnect (self);
	} else if (NM_IN_STRSET (new_state, "disconnecting", "disconnected")) {
		/* Call Disconnect on the IWD device object to make sure it
		 * disables its own autoconnect.
		 */
		send_disconnect (self);

		/*
		 * If IWD is still handling the Connect call, let our Connect
		 * callback for the dbus method handle the failure.  The main
		 * reason we can't handle the failure here is because the method
		 * callback will have more information on the specific failure
		 * reason.
		 */
		if (NM_IN_SET (dev_state, NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_NEED_AUTH))
			return;

		if (iwd_connection)
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
	} else if (!nm_streq (new_state, "unknown")) {
		_LOGE (LOGD_WIFI, "State %s unknown", new_state);
		return;
	}

	/* Don't allow new connection until iwd exits disconnecting and no
	 * Connect callback is pending.
	 */
	if (NM_IN_STRSET (new_state, "disconnected")) {
		priv->can_connect = TRUE;
		if (!can_connect)
			nm_device_emit_recheck_auto_activate (device);
	}
}

static void
scanning_changed (NMDeviceIwd *self, gboolean new_scanning)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	if (new_scanning == priv->scanning)
		return;

	priv->scanning = new_scanning;

	_notify (self, PROP_SCANNING);

	if (!priv->scanning) {
		update_aps (self);

		if (!priv->scan_requested)
			schedule_periodic_scan (self, FALSE);
	}
}

static void
station_properties_changed (GDBusProxy *proxy, GVariant *changed_properties,
                            GStrv invalidate_properties, gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	const char *new_str;
	gboolean new_bool;

	if (g_variant_lookup (changed_properties, "State", "&s", &new_str))
		state_changed (self, new_str);

	if (g_variant_lookup (changed_properties, "Scanning", "b", &new_bool))
		scanning_changed (self, new_bool);
}

static void
ap_adhoc_properties_changed (GDBusProxy *proxy, GVariant *changed_properties,
                             GStrv invalidate_properties, gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	gboolean new_bool;

	if (g_variant_lookup (changed_properties, "Started", "b", &new_bool))
		_LOGI (LOGD_DEVICE | LOGD_WIFI, "IWD AP/AdHoc state is now %s", new_bool ? "Started" : "Stopped");
}

static void
powered_changed (NMDeviceIwd *self, gboolean new_powered)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	GDBusInterface *interface;
	GVariant *value;

	nm_device_queue_recheck_available (NM_DEVICE (self),
	                                   NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
	                                   NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);

	interface = new_powered ? g_dbus_object_get_interface (priv->dbus_obj, NM_IWD_AP_INTERFACE) : NULL;

	if (priv->dbus_ap_proxy) {
		g_signal_handlers_disconnect_by_func (priv->dbus_ap_proxy,
		                                      ap_adhoc_properties_changed, self);
		g_clear_object (&priv->dbus_ap_proxy);
	}

	if (interface) {
		priv->dbus_ap_proxy = G_DBUS_PROXY (interface);
		g_signal_connect (priv->dbus_ap_proxy, "g-properties-changed",
		                  G_CALLBACK (ap_adhoc_properties_changed), self);

		if (priv->act_mode_switch)
			act_check_interface (self);
		else
			reset_mode (self, NULL, NULL, NULL);
	}

	interface = new_powered ? g_dbus_object_get_interface (priv->dbus_obj, NM_IWD_ADHOC_INTERFACE) : NULL;

	if (priv->dbus_adhoc_proxy) {
		g_signal_handlers_disconnect_by_func (priv->dbus_adhoc_proxy,
		                                      ap_adhoc_properties_changed, self);
		g_clear_object (&priv->dbus_adhoc_proxy);
	}

	if (interface) {
		priv->dbus_adhoc_proxy = G_DBUS_PROXY (interface);
		g_signal_connect (priv->dbus_adhoc_proxy, "g-properties-changed",
		                  G_CALLBACK (ap_adhoc_properties_changed), self);

		if (priv->act_mode_switch)
			act_check_interface (self);
		else
			reset_mode (self, NULL, NULL, NULL);
	}

	/* We expect one of the three interfaces to always be present when
	 * device is Powered so if AP and AdHoc are not present we should
	 * be in station mode.
	 */
	if (new_powered && !priv->dbus_ap_proxy && !priv->dbus_adhoc_proxy) {
		interface = g_dbus_object_get_interface (priv->dbus_obj, NM_IWD_STATION_INTERFACE);
		if (!interface) {
			/* No Station interface on the device object.  Check if the
			 * "State" property is present on the Device interface, that
			 * would mean we're dealing with an IWD version from before the
			 * Device/Station split (0.7 or earlier) and we can easily
			 * handle that by making priv->dbus_device_proxy and
			 * priv->dbus_station_proxy both point at the Device interface.
			 */
			value = g_dbus_proxy_get_cached_property (priv->dbus_device_proxy, "State");
			if (value) {
				g_variant_unref (value);
				interface = g_object_ref (G_DBUS_INTERFACE (priv->dbus_device_proxy));
			} else {
				_LOGE (LOGD_WIFI, "Interface %s not found on obj %s",
				       NM_IWD_STATION_INTERFACE,
				       g_dbus_object_get_object_path (priv->dbus_obj));
				interface = NULL;
			}

		}
	} else
		interface = NULL;

	if (priv->dbus_station_proxy) {
		g_signal_handlers_disconnect_by_func (priv->dbus_station_proxy,
		                                      station_properties_changed, self);
		g_clear_object (&priv->dbus_station_proxy);
	}

	if (interface) {
		priv->dbus_station_proxy = G_DBUS_PROXY (interface);
		g_signal_connect (priv->dbus_station_proxy, "g-properties-changed",
		                  G_CALLBACK (station_properties_changed), self);

		value = g_dbus_proxy_get_cached_property (priv->dbus_station_proxy, "Scanning");
		priv->scanning = get_variant_boolean (value, "Scanning");
		g_variant_unref (value);

		value = g_dbus_proxy_get_cached_property (priv->dbus_station_proxy, "State");
		state_changed (self, get_variant_state (value));
		g_variant_unref (value);

		update_aps (self);
	} else {
		set_can_scan (self, FALSE);
		nm_clear_g_source (&priv->periodic_scan_id);
		priv->scanning = FALSE;
		priv->scan_requested = FALSE;
		priv->can_connect = FALSE;
		cleanup_association_attempt (self, FALSE);
		remove_all_aps (self);
	}
}

static void
device_properties_changed (GDBusProxy *proxy, GVariant *changed_properties,
                           GStrv invalidate_properties, gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	gboolean new_bool;

	if (g_variant_lookup (changed_properties, "Powered", "b", &new_bool))
		powered_changed (self, new_bool);
}

void
nm_device_iwd_set_dbus_object (NMDeviceIwd *self, GDBusObject *object)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	GDBusInterface *interface;
	gs_unref_variant GVariant *value = NULL;
	gs_unref_object GDBusProxy *adapter_proxy = NULL;
	GVariantIter *iter;
	const char *mode;
	gboolean powered;
	NMDeviceWifiCapabilities capabilities;

	if (!nm_g_object_ref_set (&priv->dbus_obj, object))
		return;

	if (priv->dbus_device_proxy) {
		g_signal_handlers_disconnect_by_func (priv->dbus_device_proxy,
		                                      device_properties_changed, self);
		g_clear_object (&priv->dbus_device_proxy);

		powered_changed (self, FALSE);

		priv->act_mode_switch = FALSE;
	}

	if (!object)
		return;

	interface = g_dbus_object_get_interface (object, NM_IWD_DEVICE_INTERFACE);
	if (!interface) {
		_LOGE (LOGD_WIFI, "Interface %s not found on obj %s",
		       NM_IWD_DEVICE_INTERFACE,
		       g_dbus_object_get_object_path (object));
		g_clear_object (&priv->dbus_obj);
		return;
	}

	priv->dbus_device_proxy = G_DBUS_PROXY (interface);

	g_signal_connect (priv->dbus_device_proxy, "g-properties-changed",
	                  G_CALLBACK (device_properties_changed), self);

	/* Parse list of interface modes supported by adapter (wiphy) */

	value = g_dbus_proxy_get_cached_property (priv->dbus_device_proxy, "Adapter");
	if (!value || !g_variant_is_of_type (value, G_VARIANT_TYPE_OBJECT_PATH)) {
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Adapter property not cached or not an object path");
		goto error;
	}

	adapter_proxy = nm_iwd_manager_get_dbus_interface (nm_iwd_manager_get (),
	                                                   g_variant_get_string (value, NULL),
	                                                   NM_IWD_WIPHY_INTERFACE);
	if (!adapter_proxy) {
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Can't get DBus proxy for IWD Adapter for IWD Device");
		goto error;
	}

	g_variant_unref (value);
	value = g_dbus_proxy_get_cached_property (adapter_proxy, "SupportedModes");
	if (!value || !g_variant_is_of_type (value, G_VARIANT_TYPE_STRING_ARRAY)) {
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "SupportedModes property not cached or not a string array");
		goto error;
	}

	capabilities = NM_WIFI_DEVICE_CAP_CIPHER_CCMP | NM_WIFI_DEVICE_CAP_RSN;

	g_variant_get (value, "as", &iter);
	while (g_variant_iter_next (iter, "&s", &mode)) {
		if (nm_streq (mode, "ap"))
			capabilities |= NM_WIFI_DEVICE_CAP_AP;
		else if (nm_streq (mode, "ad-hoc"))
			capabilities |= NM_WIFI_DEVICE_CAP_ADHOC;
	}
	g_variant_iter_free (iter);

	if (priv->capabilities != capabilities) {
		priv->capabilities = capabilities;
		_notify (self, PROP_CAPABILITIES);
	}

	g_variant_unref (value);
	value = g_dbus_proxy_get_cached_property (priv->dbus_device_proxy, "Powered");
	powered = get_variant_boolean (value, "Powered");

	if (powered != priv->enabled)
		set_powered (self, priv->enabled);
	else if (powered)
		powered_changed (self, TRUE);

	return;

error:
	g_signal_handlers_disconnect_by_func (priv->dbus_device_proxy,
	                                      device_properties_changed, self);
	g_clear_object (&priv->dbus_device_proxy);
}

gboolean
nm_device_iwd_agent_query (NMDeviceIwd *self,
                           GDBusMethodInvocation *invocation)
{
	NMActRequest *req;
	const char *setting_name;
	const char *setting_key;
	gboolean replied;
	NMSecretAgentGetSecretsFlags get_secret_flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;

	req = nm_device_get_act_request (NM_DEVICE (self));
	if (!req)
		return FALSE;

	if (!try_reply_agent_request (self, nm_act_request_get_applied_connection (req),
	                              invocation, &setting_name, &setting_key,
	                              &replied))
		return FALSE;

	if (replied)
		return TRUE;

	/* Normally require new secrets every time IWD asks for them.
	 * IWD only queries us if it has not saved the secrets (e.g. by policy)
	 * or a previous attempt has failed with current secrets so it wants
	 * a fresh set.  However if this is a new connection it may include
	 * all of the needed settings already so allow using these, too.
	 * Connection timestamp is set after activation or after first
	 * activation failure (to 0).
	 */
	if (nm_settings_connection_get_timestamp (nm_act_request_get_settings_connection (req),
	                                          NULL))
		get_secret_flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH,
	                         NM_DEVICE_STATE_REASON_NO_SECRETS);
	wifi_secrets_get_one (self, setting_name, get_secret_flags,
	                      setting_key, invocation);

	return TRUE;
}

/*****************************************************************************/

static const char *
get_type_description (NMDevice *device)
{
	nm_assert (NM_IS_DEVICE_IWD (device));

	return "wifi";
}

/*****************************************************************************/

static void
nm_device_iwd_init (NMDeviceIwd *self)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	c_list_init (&priv->aps_lst_head);

	/* Make sure the manager is running */
	(void) nm_iwd_manager_get ();
}

NMDevice *
nm_device_iwd_new (const char *iface)
{
	return g_object_new (NM_TYPE_DEVICE_IWD,
	                     NM_DEVICE_IFACE, iface,
	                     NM_DEVICE_TYPE_DESC, "802.11 Wi-Fi",
	                     NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_WIFI,
	                     NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_WIFI,
	                     NM_DEVICE_RFKILL_TYPE, RFKILL_TYPE_WLAN,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (object);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	nm_clear_g_cancellable (&priv->cancellable);

	nm_clear_g_source (&priv->periodic_scan_id);

	cleanup_association_attempt (self, TRUE);

	g_clear_object (&priv->dbus_device_proxy);
	g_clear_object (&priv->dbus_station_proxy);
	g_clear_object (&priv->dbus_ap_proxy);
	g_clear_object (&priv->dbus_adhoc_proxy);
	g_clear_object (&priv->dbus_obj);

	remove_all_aps (self);

	G_OBJECT_CLASS (nm_device_iwd_parent_class)->dispose (object);

	nm_assert (c_list_is_empty (&priv->aps_lst_head));
}

static void
nm_device_iwd_class_init (NMDeviceIwdClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;
	object_class->dispose = dispose;

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&nm_interface_info_device_wireless);

	device_class->connection_type_supported = NM_SETTING_WIRELESS_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_WIRELESS_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_WIFI);

	device_class->can_auto_connect = can_auto_connect;
	device_class->is_available = is_available;
	device_class->get_autoconnect_allowed = get_autoconnect_allowed;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->check_connection_available = check_connection_available;
	device_class->complete_connection = complete_connection;
	device_class->get_enabled = get_enabled;
	device_class->set_enabled = set_enabled;
	device_class->get_type_description = get_type_description;

	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->act_stage2_config = act_stage2_config;
	device_class->get_configured_mtu = get_configured_mtu;
	device_class->deactivate = deactivate;
	device_class->deactivate_async = deactivate_async;
	device_class->can_reapply_change = can_reapply_change;

	device_class->state_changed = device_state_changed;

	klass->scanning_prohibited = scanning_prohibited;

	obj_properties[PROP_MODE] =
	    g_param_spec_uint (NM_DEVICE_IWD_MODE, "", "",
	                       NM_802_11_MODE_UNKNOWN,
	                       NM_802_11_MODE_AP,
	                       NM_802_11_MODE_INFRA,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_BITRATE] =
	    g_param_spec_uint (NM_DEVICE_IWD_BITRATE, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ACCESS_POINTS] =
	    g_param_spec_boxed (NM_DEVICE_IWD_ACCESS_POINTS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ACTIVE_ACCESS_POINT] =
	    g_param_spec_string (NM_DEVICE_IWD_ACTIVE_ACCESS_POINT, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CAPABILITIES] =
	    g_param_spec_uint (NM_DEVICE_IWD_CAPABILITIES, "", "",
	                       0, G_MAXUINT32, NM_WIFI_DEVICE_CAP_NONE,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_SCANNING] =
	    g_param_spec_boolean (NM_DEVICE_IWD_SCANNING, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_LAST_SCAN] =
	    g_param_spec_int64 (NM_DEVICE_IWD_LAST_SCAN, "", "",
	                        -1, G_MAXINT64, -1,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[SCANNING_PROHIBITED] =
	    g_signal_new (NM_DEVICE_IWD_SCANNING_PROHIBITED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (NMDeviceIwdClass, scanning_prohibited),
	                  NULL, NULL, NULL,
	                  G_TYPE_BOOLEAN, 1, G_TYPE_BOOLEAN);
}
