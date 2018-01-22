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

#include <string.h>

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
#include "nm-core-internal.h"
#include "nm-config.h"
#include "nm-iwd-manager.h"

#include "introspection/org.freedesktop.NetworkManager.Device.Wireless.h"

#include "devices/nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceIwd);

static NM_CACHED_QUARK_FCN ("wireless-secrets-tries", wireless_secrets_tries_quark)

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceIwd,
	PROP_MODE,
	PROP_BITRATE,
	PROP_ACCESS_POINTS,
	PROP_ACTIVE_ACCESS_POINT,
	PROP_CAPABILITIES,
	PROP_SCANNING,
);

enum {
	ACCESS_POINT_ADDED,
	ACCESS_POINT_REMOVED,
	SCANNING_PROHIBITED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	GDBusObject *   dbus_obj;
	GDBusProxy *    dbus_proxy;
	GHashTable *    aps;
	GHashTable *    new_aps;
	NMWifiAP *      current_ap;
	GCancellable *  cancellable;
	NMDeviceWifiCapabilities capabilities;
	NMActRequestGetSecretsCallId *wifi_secrets_id;
	guint           periodic_scan_id;
	bool            enabled:1;
	bool            can_scan:1;
	bool            scanning:1;
	bool            scan_requested:1;
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
                                    NMDeviceState current_state);

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
               guint signum,
               NMWifiAP *ap,
               gboolean recheck_available_connections)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	nm_assert (NM_IN_SET (signum, ACCESS_POINT_ADDED, ACCESS_POINT_REMOVED));

	if (signum == ACCESS_POINT_ADDED) {
		g_hash_table_insert (priv->aps,
		                     (gpointer) nm_exported_object_export ((NMExportedObject *) ap),
		                     g_object_ref (ap));
		_ap_dump (self, LOGL_DEBUG, ap, "added", 0);
	} else
		_ap_dump (self, LOGL_DEBUG, ap, "removed", 0);

	g_signal_emit (self, signals[signum], 0, ap);

	if (signum == ACCESS_POINT_REMOVED) {
		g_hash_table_remove (priv->aps, nm_exported_object_get_path ((NMExportedObject *) ap));
		nm_exported_object_unexport ((NMExportedObject *) ap);
		g_object_unref (ap);
	}

	_notify (self, PROP_ACCESS_POINTS);

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
			ap_add_remove (self, ACCESS_POINT_REMOVED, old_ap, recheck_available_connections);
		g_object_unref (old_ap);
	}

	_notify (self, PROP_ACTIVE_ACCESS_POINT);
	_notify (self, PROP_MODE);
}

static gboolean
update_ap_func (gpointer key, gpointer value, gpointer user_data)
{
	NMWifiAP *ap = value;
	NMDeviceIwd *self = user_data;
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMWifiAP *new_ap = NULL;

	if (priv->new_aps)
		new_ap = g_hash_table_lookup (priv->new_aps,
		                              nm_wifi_ap_get_supplicant_path (ap));

	if (new_ap) {
		g_hash_table_steal (priv->new_aps,
		                    nm_wifi_ap_get_supplicant_path (ap));

		if (nm_wifi_ap_set_strength (ap, nm_wifi_ap_get_strength (new_ap)))
			_ap_dump (self, LOGL_TRACE, ap, "updated", 0);

		g_object_unref (new_ap);
		return FALSE;
	}

	if (ap == priv->current_ap)
		/* Normally IWD will prevent the current AP from being
		 * removed from the list and set a low signal strength,
		 * but just making sure.
		 */
		return FALSE;

	_ap_dump (self, LOGL_DEBUG, ap, "removed", 0);

	g_signal_emit (self, signals[ACCESS_POINT_REMOVED], 0, ap);

	nm_exported_object_unexport ((NMExportedObject *) ap);
	g_object_unref (ap);

	return TRUE;
}

static void
remove_all_aps (NMDeviceIwd *self)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	if (!g_hash_table_size (priv->aps))
		return;

	set_current_ap (self, NULL, FALSE);

	g_hash_table_foreach_remove (priv->aps, update_ap_func, self);

	_notify (self, PROP_ACCESS_POINTS);
	nm_device_emit_recheck_auto_activate (NM_DEVICE (self));
	nm_device_recheck_available_connections (NM_DEVICE (self));
}

static GVariant *
vardict_from_network_type (const gchar *type)
{
	GVariantBuilder builder;
	const gchar *key_mgmt = "";
	const gchar *pairwise = "ccmp";

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
get_ordered_networks_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *variant = NULL;
	GVariantIter *networks;
	const gchar *path, *name, *type;
	int16_t signal;
	NMWifiAP *ap;
	gboolean changed = FALSE;
	GHashTableIter ap_iter;

	variant = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (source), res,
	                                      G_VARIANT_TYPE ("(a(osns))"),
	                                      &error);
	if (!variant) {
		_LOGE (LOGD_WIFI, "Device.GetOrderedNetworks failed: %s",
		       error->message);
		return;
	}

	priv->new_aps = g_hash_table_new (nm_str_hash, g_str_equal);

	g_variant_get (variant, "(a(osns))", &networks);

	while (g_variant_iter_next (networks, "(&o&sn&s)", &path, &name, &signal, &type)) {
		GVariantBuilder builder;
		gs_unref_variant GVariant *props = NULL;
		GVariant *rsn;
		static uint32_t ap_id = 0;
		uint8_t bssid[6];

		/*
		 * What we get from IWD are networks, or ESSs, that may
		 * contain multiple APs, or BSSs, each.  We don't get
		 * information about any specific BSSs within an ESS but
		 * we can safely present each ESS as an individual BSS to
		 * NM, which will be seen as ESSs comprising a single BSS
		 * each.  NM won't be able to handle roaming but IWD already
		 * does that.  We fake the BSSIDs as they don't play any
		 * role either.
		 */
		bssid[0] = 0x00;
		bssid[1] = 0x01;
		bssid[2] = 0x02;
		bssid[3] = ap_id >> 16;
		bssid[4] = ap_id >> 8;
		bssid[5] = ap_id++;

		/* WEP not supported */
		if (!strcmp (type, "wep"))
			continue;

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
		nm_wifi_ap_set_ssid (ap, (const guint8 *) name, strlen (name));
		nm_wifi_ap_set_strength (ap, nm_wifi_utils_level_to_quality (signal / 100));
		nm_wifi_ap_set_freq (ap, 2417);
		nm_wifi_ap_set_max_bitrate (ap, 65000);
		g_hash_table_insert (priv->new_aps,
		                     (gpointer) nm_wifi_ap_get_supplicant_path (ap),
		                     ap);
	}

	g_variant_iter_free (networks);

	if (g_hash_table_foreach_remove (priv->aps, update_ap_func, self))
		changed = TRUE;

	g_hash_table_iter_init (&ap_iter, priv->new_aps);
	while (g_hash_table_iter_next (&ap_iter, NULL, (gpointer) &ap)) {
		ap_add_remove (self, ACCESS_POINT_ADDED, ap, FALSE);
		changed = TRUE;
	}

	g_hash_table_destroy (priv->new_aps);
	priv->new_aps = NULL;

	if (changed) {
		_notify (self, PROP_ACCESS_POINTS);
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

	g_dbus_proxy_call (priv->dbus_proxy, "GetOrderedNetworks",
	                   g_variant_new ("()"), G_DBUS_CALL_FLAGS_NONE,
	                   2000, priv->cancellable,
	                   get_ordered_networks_cb, self);
}

static void
send_disconnect (NMDeviceIwd *self)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	g_dbus_proxy_call (priv->dbus_proxy, "Disconnect", g_variant_new ("()"),
	                   G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
}

static void
cleanup_association_attempt (NMDeviceIwd *self, gboolean disconnect)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	set_current_ap (self, NULL, TRUE);

	if (disconnect && priv->dbus_obj)
		send_disconnect (self);
}

static void
deactivate (NMDevice *device)
{
	cleanup_association_attempt (NM_DEVICE_IWD (device), TRUE);
}

static gboolean
deactivate_async_finish (NMDevice *device, GAsyncResult *res, GError **error)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (NM_DEVICE_IWD (device));
	gs_unref_variant GVariant *variant;

	variant = g_dbus_proxy_call_finish (priv->dbus_proxy, res, error);

	return variant != NULL;
}

typedef struct {
	NMDeviceIwd *self;
	GAsyncReadyCallback callback;
	gpointer user_data;
} DeactivateContext;

static void
disconnect_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	DeactivateContext *ctx = user_data;

	ctx->callback (G_OBJECT (ctx->self), res, ctx->user_data);

	g_object_unref (ctx->self);
	g_slice_free (DeactivateContext, ctx);
}

static void
deactivate_async (NMDevice *device,
                  GCancellable *cancellable,
                  GAsyncReadyCallback callback,
                  gpointer user_data)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	DeactivateContext *ctx;

	ctx = g_slice_new0 (DeactivateContext);
	ctx->self = g_object_ref (self);
	ctx->callback = callback;
	ctx->user_data = user_data;

	g_dbus_proxy_call (priv->dbus_proxy, "Disconnect", g_variant_new ("()"),
	                   G_DBUS_CALL_FLAGS_NONE, -1, cancellable, disconnect_cb, ctx);
}

static NMIwdNetworkSecurity
get_connection_iwd_security (NMConnection *connection)
{
	NMSettingWirelessSecurity *s_wireless_sec;
	const char *key_mgmt = NULL;

	s_wireless_sec = nm_connection_get_setting_wireless_security (connection);
	if (!s_wireless_sec)
		return NM_IWD_NETWORK_SECURITY_NONE;

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wireless_sec);
	nm_assert (key_mgmt);

	if (!strcmp (key_mgmt, "none") || !strcmp (key_mgmt, "ieee8021x"))
		return NM_IWD_NETWORK_SECURITY_WEP;

	if (!strcmp (key_mgmt, "wpa-psk"))
		return NM_IWD_NETWORK_SECURITY_PSK;

	nm_assert (!strcmp (key_mgmt, "wpa-eap"));
	return NM_IWD_NETWORK_SECURITY_8021X;
}

static gboolean
is_connection_known_network (NMConnection *connection)
{
	NMSettingWireless *s_wireless;
	GBytes *ssid;
	gs_free gchar *str_ssid = NULL;

	s_wireless = nm_connection_get_setting_wireless (connection);
	if (!s_wireless)
		return FALSE;

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	if (!ssid)
		return FALSE;

	str_ssid = nm_utils_ssid_to_utf8 (g_bytes_get_data (ssid, NULL),
	                                  g_bytes_get_size (ssid));

	return nm_iwd_manager_is_known_network (nm_iwd_manager_get (),
	                                        str_ssid,
	                                        get_connection_iwd_security (connection));
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	const char *mac;
	const char * const *mac_blacklist;
	int i;
	const char *mode;
	const char *perm_hw_addr;

	if (!NM_DEVICE_CLASS (nm_device_iwd_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_WIRELESS_SETTING_NAME))
		return FALSE;

	s_wireless = nm_connection_get_setting_wireless (connection);
	if (!s_wireless)
		return FALSE;

	perm_hw_addr = nm_device_get_permanent_hw_address (device);
	mac = nm_setting_wireless_get_mac_address (s_wireless);
	if (perm_hw_addr) {
		if (mac && !nm_utils_hwaddr_matches (mac, -1, perm_hw_addr, -1))
			return FALSE;

		/* Check for MAC address blacklist */
		mac_blacklist = nm_setting_wireless_get_mac_address_blacklist (s_wireless);
		for (i = 0; mac_blacklist[i]; i++) {
			if (!nm_utils_hwaddr_valid (mac_blacklist[i], ETH_ALEN)) {
				g_warn_if_reached ();
				return FALSE;
			}

			if (nm_utils_hwaddr_matches (mac_blacklist[i], -1, perm_hw_addr, -1))
				return FALSE;
		}
	} else if (mac)
		return FALSE;

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_INFRA) != 0)
		return FALSE;

	/* 8021x networks can only be used if they've been provisioned on the IWD side and
	 * thus are Known Networks.
	 */
	if (get_connection_iwd_security (connection) == NM_IWD_NETWORK_SECURITY_8021X) {
		if (!is_connection_known_network (connection))
			return FALSE;
	}

	return TRUE;
}

static NMWifiAP *
get_ap_by_path (NMDeviceIwd *self, const char *path)
{
	g_return_val_if_fail (path != NULL, NULL);
	return g_hash_table_lookup (NM_DEVICE_IWD_GET_PRIVATE (self)->aps, path);
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMSettingWireless *s_wifi;
	const char *mode;

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wifi, FALSE);

	/* Only Infrastrusture mode at this time */
	mode = nm_setting_wireless_get_mode (s_wifi);
	if (g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_INFRA) != 0)
		return FALSE;

	/* Hidden SSIDs not supported yet */
	if (nm_setting_wireless_get_hidden (s_wifi))
		return FALSE;

	/* 8021x networks can only be used if they've been provisioned on the IWD side and
	 * thus are Known Networks.
	 */
	if (get_connection_iwd_security (connection) == NM_IWD_NETWORK_SECURITY_8021X) {
		if (!is_connection_known_network (connection))
			return FALSE;
	}

	/* a connection that is available for a certain @specific_object, MUST
	 * also be available in general (without @specific_object). */

	if (specific_object) {
		NMWifiAP *ap;

		ap = get_ap_by_path (self, specific_object);
		return ap ? nm_wifi_ap_check_compatible (ap, connection) : FALSE;
	}

	if (NM_FLAGS_HAS (flags, _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_IGNORE_AP))
		return TRUE;

	/* Check at least one AP is compatible with this connection */
	return !!nm_wifi_aps_find_first_compatible (priv->aps, connection, TRUE);
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMSettingWireless *s_wifi;
	const char *setting_mac;
	char *str_ssid = NULL;
	NMWifiAP *ap;
	const GByteArray *ssid = NULL;
	GByteArray *tmp_ssid = NULL;
	GBytes *setting_ssid = NULL;
	const char *perm_hw_addr;
	const char *mode;

	s_wifi = nm_connection_get_setting_wireless (connection);

	mode = s_wifi ? nm_setting_wireless_get_mode (s_wifi) : NULL;

	if (s_wifi && !nm_streq0 (mode, NM_SETTING_WIRELESS_MODE_INFRA)) {
		g_set_error_literal (error,
		                     NM_DEVICE_ERROR,
		                     NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "Only Infrastructure mode is supported.");
		return FALSE;
	}

	if (!specific_object) {
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
		ap = nm_wifi_aps_find_first_compatible (priv->aps, connection, FALSE);
		if (!ap) {
			g_set_error_literal (error,
			                     NM_DEVICE_ERROR,
			                     NM_DEVICE_ERROR_INVALID_CONNECTION,
			                     "No compatible AP in the scan list and hidden SSIDs not supported.");
			return FALSE;
		}
	} else {
		ap = get_ap_by_path (self, specific_object);
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

	ssid = nm_wifi_ap_get_ssid (ap);

	if (ssid == NULL) {
		g_set_error_literal (error,
		                     NM_DEVICE_ERROR,
		                     NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "A 'wireless' setting with a valid SSID is required.");
		return FALSE;
	}

	if (!nm_wifi_ap_complete_connection (ap,
	                                     connection,
	                                     nm_wifi_utils_is_manf_default_ssid (ssid),
	                                     error)) {
		if (tmp_ssid)
			g_byte_array_unref (tmp_ssid);
		return FALSE;
	}

	str_ssid = nm_utils_ssid_to_utf8 (ssid->data, ssid->len);

	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
	                           NM_SETTING_WIRELESS_SETTING_NAME,
	                           existing_connections,
	                           str_ssid,
	                           str_ssid,
	                           NULL,
	                           TRUE);
	g_free (str_ssid);
	if (tmp_ssid)
		g_byte_array_unref (tmp_ssid);

	/* 8021x networks can only be used if they've been provisioned on the IWD side and
	 * thus are Known Networks.
	 */
	if (get_connection_iwd_security (connection) == NM_IWD_NETWORK_SECURITY_8021X) {
		if (!is_connection_known_network (connection)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_DEVICE_ERROR_INVALID_CONNECTION,
			                     "This 8021x network has not been provisioned on this machine");
			return FALSE;
		}
	}

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
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	return priv->enabled && priv->dbus_obj;
}

static gboolean
can_auto_connect (NMDevice *device,
                  NMConnection *connection,
                  char **specific_object)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMSettingWireless *s_wifi;
	NMWifiAP *ap;
	const char *mode;
	guint64 timestamp = 0;

	nm_assert (!specific_object || !*specific_object);

	if (!NM_DEVICE_CLASS (nm_device_iwd_parent_class)->can_auto_connect (device, connection, NULL))
		return FALSE;

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wifi, FALSE);

	/* Only Infrastrusture mode */
	mode = nm_setting_wireless_get_mode (s_wifi);
	if (g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_INFRA) != 0)
		return FALSE;

	/* Don't autoconnect to networks that have been tried at least once
	 * but haven't been successful, since these are often accidental choices
	 * from the menu and the user may not know the password.
	 */
	if (nm_settings_connection_get_timestamp (NM_SETTINGS_CONNECTION (connection), &timestamp)) {
		if (timestamp == 0)
			return FALSE;
	}

	/* 8021x networks can only be used if they've been provisioned on the IWD side and
	 * thus are Known Networks.
	 */
	if (get_connection_iwd_security (connection) == NM_IWD_NETWORK_SECURITY_8021X) {
		if (!is_connection_known_network (connection))
			return FALSE;
	}

	ap = nm_wifi_aps_find_first_compatible (priv->aps, connection, FALSE);
	if (ap) {
		/* All good; connection is usable */
		NM_SET_OUT (specific_object, g_strdup (nm_exported_object_get_path (NM_EXPORTED_OBJECT (ap))));
		return TRUE;
	}

	return FALSE;
}

static void
impl_device_iwd_get_access_points (NMDeviceIwd *self,
                                    GDBusMethodInvocation *context)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	gs_free const char **list = NULL;
	GVariant *v;

	list = nm_wifi_aps_get_sorted_paths (priv->aps, FALSE);
	v = g_variant_new_objv (list, -1);
	g_dbus_method_invocation_return_value (context, g_variant_new_tuple (&v, 1));
}

static void
impl_device_iwd_get_all_access_points (NMDeviceIwd *self,
                                        GDBusMethodInvocation *context)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	gs_free const char **list = NULL;
	GVariant *v;

	list = nm_wifi_aps_get_sorted_paths (priv->aps, TRUE);
	v = g_variant_new_objv (list, -1);
	g_dbus_method_invocation_return_value (context, g_variant_new_tuple (&v, 1));
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
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMDeviceState state = nm_device_get_state (NM_DEVICE (self));
	gs_free_error GError *error = NULL;

	priv->scan_requested = FALSE;

	/* On success, priv->scanning becomes true right before or right
	 * after this callback, so the next automatic scan will be
	 * scheduled when priv->scanning goes back to false.  On error,
	 * schedule a retry now.
	 */
	if (   !_nm_dbus_proxy_call_finish (G_DBUS_PROXY (source), res,
	                                    G_VARIANT_TYPE ("()"), &error)
	    && !priv->scanning)
		schedule_periodic_scan (self, state);
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

	if (   !priv->enabled
	    || !priv->dbus_obj
	    || nm_device_get_state (device) < NM_DEVICE_STATE_DISCONNECTED
	    || nm_device_is_activating (device)) {
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
		g_dbus_proxy_call (priv->dbus_proxy, "Scan",
		                   g_variant_new ("()"),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   priv->cancellable, scan_cb, self);
		priv->scan_requested = TRUE;
	}

	g_dbus_method_invocation_return_value (context, NULL);
}

static void
impl_device_iwd_request_scan (NMDeviceIwd *self,
                               GDBusMethodInvocation *context,
                               GVariant *options)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);

	if (   !priv->enabled
	    || !priv->dbus_obj
	    || nm_device_get_state (device) < NM_DEVICE_STATE_DISCONNECTED
	    || nm_device_is_activating (device)) {
		g_dbus_method_invocation_return_error_literal (context,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_ALLOWED,
		                                               "Scanning not allowed while unavailable");
		return;
	}

	/* Ask the manager to authenticate this request for us */
	g_signal_emit_by_name (device,
	                       NM_DEVICE_AUTH_REQUEST,
	                       context,
	                       NULL,
	                       NM_AUTH_PERMISSION_NETWORK_CONTROL,
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
		/* Can always scan when disconnected */
		return FALSE;
	case NM_DEVICE_STATE_ACTIVATED:
		break;
	}

	/* Prohibit scans if IWD is busy */
	return !priv->can_scan;
}

static void
wifi_secrets_cb (NMActRequest *req,
                 NMActRequestGetSecretsCallId *call_id,
                 NMSettingsConnection *connection,
                 GError *error,
                 gpointer user_data)
{
	NMDevice *device = user_data;
	NMDeviceIwd *self = user_data;
	NMDeviceIwdPrivate *priv;

	g_return_if_fail (NM_IS_DEVICE_IWD (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	g_return_if_fail (priv->wifi_secrets_id == call_id);

	priv->wifi_secrets_id = NULL;

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	g_return_if_fail (req == nm_device_get_act_request (device));
	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);
	g_return_if_fail (nm_act_request_get_settings_connection (req) == connection);

	if (error) {
		_LOGW (LOGD_WIFI, "%s", error->message);

		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_NO_SECRETS);
	} else
		nm_device_activate_schedule_stage1_device_prepare (device);
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
wifi_secrets_get_secrets (NMDeviceIwd *self,
                          const char *setting_name,
                          NMSecretAgentGetSecretsFlags flags)
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
	                                                    NULL,
	                                                    wifi_secrets_cb,
	                                                    self);
	g_return_if_fail (priv->wifi_secrets_id);
}

static gboolean
need_new_8021x_secrets (NMDeviceIwd *self,
                        const char **setting_name)
{
	NMSetting8021x *s_8021x;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;
	NMConnection *connection;

	g_assert (setting_name != NULL);

	connection = nm_device_get_applied_connection (NM_DEVICE (self));
	g_return_val_if_fail (connection != NULL, FALSE);

	/* If it's an 802.1x or LEAP connection with "always ask"/unsaved secrets
	 * then we need to ask again because it might be an OTP token and the PIN
	 * may have changed.
	 */

	s_8021x = nm_connection_get_setting_802_1x (connection);
	if (s_8021x) {
		if (!nm_setting_get_secret_flags (NM_SETTING (s_8021x),
		                                  NM_SETTING_802_1X_PASSWORD,
		                                  &secret_flags,
		                                  NULL))
			g_assert_not_reached ();
		if (secret_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
			*setting_name = NM_SETTING_802_1X_SETTING_NAME;
		return *setting_name ? TRUE : FALSE;
	}

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (s_wsec) {
		if (!nm_setting_get_secret_flags (NM_SETTING (s_wsec),
		                                  NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
		                                  &secret_flags,
		                                  NULL))
			g_assert_not_reached ();
		if (secret_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
			*setting_name = NM_SETTING_WIRELESS_SECURITY_SETTING_NAME;
		return *setting_name ? TRUE : FALSE;
	}

	/* Not a LEAP or 802.1x connection */
	return FALSE;
}

static gboolean
need_new_wpa_psk (NMDeviceIwd *self,
                  const char **setting_name)
{
	NMSettingWirelessSecurity *s_wsec;
	NMConnection *connection;
	const char *key_mgmt = NULL;

	g_assert (setting_name != NULL);

	connection = nm_device_get_applied_connection (NM_DEVICE (self));
	g_return_val_if_fail (connection != NULL, FALSE);

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (s_wsec)
		key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);

	if (g_strcmp0 (key_mgmt, "wpa-psk") == 0) {
		/* We don't have any data from IWD about the disconnect
		 * reason or association state when the disconnect happened
		 * so just assume it was a bad password.
		 */
		*setting_name = NM_SETTING_WIRELESS_SECURITY_SETTING_NAME;
		return TRUE;
	}

	/* Not a WPA-PSK connection */
	return FALSE;
}

static gboolean
handle_8021x_or_psk_auth_fail (NMDeviceIwd *self)
{
	NMDevice *device = NM_DEVICE (self);
	NMActRequest *req;
	const char *setting_name = NULL;
	gboolean handled = FALSE;
	NMConnection *connection;

	req = nm_device_get_act_request (device);
	g_return_val_if_fail (req != NULL, FALSE);

	/* If this is an IWD Known Network, even if the failure was caused by bad secrets,
	 * IWD won't ask our agent for new secrets until we call ForgetNetwork.  For 8021x
	 * this is not a good idea since the IWD network config file is assumed to be
	 * provisioned by the system admin and the admin needs to intervene anyway.  For
	 * PSK we may want to do this here (TODO).
	 */
	connection = nm_act_request_get_applied_connection (req);
	if (is_connection_known_network (connection)) {
		_LOGI (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) disconnected during association to an IWD Known Network, giving up");

		return FALSE;
	}

	if (   need_new_8021x_secrets (self, &setting_name)
	    || need_new_wpa_psk (self, &setting_name)) {
		nm_act_request_clear_secrets (req);

		_LOGI (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) disconnected during association, asking for new key");

		cleanup_association_attempt (self, FALSE);
		nm_device_state_changed (device, NM_DEVICE_STATE_NEED_AUTH,
		                         NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
		wifi_secrets_get_secrets (self,
		                          setting_name,
		                          NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION
		                            | NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW);
		handled = TRUE;
	}

	return handled;
}

static void
network_connect_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	NMDevice *device = NM_DEVICE (self);
	gs_free_error GError *error = NULL;
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	GBytes *ssid;
	gs_free gchar *str_ssid = NULL;

	if (!_nm_dbus_proxy_call_finish (G_DBUS_PROXY (source), res,
	                                 G_VARIANT_TYPE ("()"),
	                                 &error)) {
		gs_free gchar *dbus_error = NULL;

		/* Connection failed; radio problems or if the network wasn't
		 * open, the passwords or certificates may be wrong.
		 */

		_LOGE (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) Network.Connect failed: %s",
		       error->message);

		connection = nm_device_get_applied_connection (device);
		if (!connection || nm_connection_get_setting_wireless_security (connection))
			goto failed;

		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_DBUS_ERROR))
			dbus_error = g_dbus_error_get_remote_error (error);

		/* If secrets were wrong, we'd be getting a net.connman.iwd.Failed */
		if (nm_streq0 (dbus_error, "net.connman.iwd.Failed")) {
			if (handle_8021x_or_psk_auth_fail (self)) {
				_LOGW (LOGD_DEVICE | LOGD_WIFI, "Activation: (wifi) asking for new secrets");
			} else {
				cleanup_association_attempt (self, FALSE);
				nm_device_state_changed (device, NM_DEVICE_STATE_FAILED,
				                         NM_DEVICE_STATE_REASON_NO_SECRETS);
			}
		} else if (   !nm_utils_error_is_cancelled (error, TRUE)
		           && nm_device_is_activating (device))
			goto failed;

		/* Call Disconnect to make sure IWD's autoconnect is disabled */
		cleanup_association_attempt (self, TRUE);

		return;
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

	str_ssid = nm_utils_ssid_to_utf8 (g_bytes_get_data (ssid, NULL),
	                                  g_bytes_get_size (ssid));

	_LOGI (LOGD_DEVICE | LOGD_WIFI,
	       "Activation: (wifi) Stage 2 of 5 (Device Configure) successful.  Connected to '%s'.",
	       str_ssid);
	nm_device_activate_schedule_stage3_ip_config_start (device);

	nm_iwd_manager_network_connected (nm_iwd_manager_get (), str_ssid,
	                                  get_connection_iwd_security (connection));

	return;

failed:
	cleanup_association_attempt (self, FALSE);
	nm_device_queue_state (device, NM_DEVICE_STATE_FAILED,
	                       NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
}

static gboolean
handle_auth_or_fail (NMDeviceIwd *self,
                     NMActRequest *req,
                     gboolean new_secrets)
{
	const char *setting_name;
	guint32 tries;
	NMConnection *applied_connection;
	NMSecretAgentGetSecretsFlags get_secret_flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;

	g_return_val_if_fail (NM_IS_DEVICE_IWD (self), FALSE);

	applied_connection = nm_act_request_get_applied_connection (req);

	tries = GPOINTER_TO_UINT (g_object_get_qdata (G_OBJECT (applied_connection), wireless_secrets_tries_quark ()));
	if (tries > 3)
		return FALSE;

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);

	nm_act_request_clear_secrets (req);
	setting_name = nm_connection_need_secrets (applied_connection, NULL);
	if (!setting_name) {
		_LOGW (LOGD_DEVICE, "Cleared secrets, but setting didn't need any secrets.");
		return FALSE;
	}

	if (new_secrets)
		get_secret_flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;
	wifi_secrets_get_secrets (self, setting_name, get_secret_flags);
	g_object_set_qdata (G_OBJECT (applied_connection), wireless_secrets_tries_quark (), GUINT_TO_POINTER (++tries));
	return TRUE;
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

	ap_path = nm_active_connection_get_specific_object (NM_ACTIVE_CONNECTION (req));
	ap = ap_path ? get_ap_by_path (self, ap_path) : NULL;
	if (!ap) {
		ap = nm_wifi_aps_find_first_compatible (priv->aps, connection, FALSE);

		/* TODO: assuming hidden networks aren't supported do we need
		 * to consider the case of APs that are not in the scan list
		 * yet, for which nm-device-wifi.c creates the temporary fake
		 * AP object?
		 */

		nm_active_connection_set_specific_object (NM_ACTIVE_CONNECTION (req),
	                                                  nm_exported_object_get_path (NM_EXPORTED_OBJECT (ap)));
	}

	set_current_ap (self, ap, FALSE);
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMActRequest *req;
	NMWifiAP *ap;
	NMConnection *connection;
	const char *setting_name;
	NMSettingWireless *s_wireless;
	GError *error = NULL;
	GDBusProxy *network_proxy;

	req = nm_device_get_act_request (device);
	g_return_val_if_fail (req, NM_ACT_STAGE_RETURN_FAILURE);

	ap = priv->current_ap;
	if (!ap) {
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		goto out;
	}

	connection = nm_act_request_get_applied_connection (req);
	g_assert (connection);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* If we need secrets, get them.  If a network is an IWD Known Network the secrets
	 * will have been stored by IWD and we don't require any secrets here.
	 */
	if (!is_connection_known_network (connection))
		setting_name = nm_connection_need_secrets (connection, NULL);
	else
		setting_name = NULL;

	if (setting_name) {
		_LOGI (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) access point '%s' has security, but secrets are required.",
		       nm_connection_get_id (connection));

		if (handle_auth_or_fail (self, req, FALSE))
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
		else {
			NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_NO_SECRETS);
			ret = NM_ACT_STAGE_RETURN_FAILURE;
		}
		goto out;
	}

	/* Have secrets or no secrets required */
	if (nm_connection_get_setting_wireless_security (connection)) {
		_LOGI (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) connection '%s' has security, and secrets exist.  No new secrets needed.",
		       nm_connection_get_id (connection));
	} else {
		_LOGI (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) connection '%s' requires no security.  No secrets needed.",
		       nm_connection_get_id (connection));
	}

	/* Locate the IWD Network object */
	network_proxy = g_dbus_proxy_new_for_bus_sync (NM_IWD_BUS_TYPE,
	                                               G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                               G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                                               NULL,
	                                               NM_IWD_SERVICE,
	                                               nm_wifi_ap_get_supplicant_path (ap),
	                                               NM_IWD_NETWORK_INTERFACE,
	                                               NULL, &error);
	if (!network_proxy) {
		_LOGE (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) could not get Network interface proxy for %s: %s",
		       nm_wifi_ap_get_supplicant_path (ap),
		       error->message);
		g_clear_error (&error);
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		goto out;
	}

	if (!priv->cancellable)
		priv->cancellable = g_cancellable_new ();

	/* Call Network.Connect.  No timeout because IWD already handles
	 * timeouts.
	 */
	g_dbus_proxy_call (network_proxy, "Connect",
	                   g_variant_new ("()"),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   priv->cancellable, network_connect_cb, self);

	g_object_unref (network_proxy);

	/* We'll get stage3 started when the supplicant connects */
	ret = NM_ACT_STAGE_RETURN_POSTPONE;

out:
	if (ret == NM_ACT_STAGE_RETURN_FAILURE)
		cleanup_association_attempt (self, FALSE);

	return ret;
}

static guint32
get_configured_mtu (NMDevice *device, gboolean *out_is_user_config)
{
	NMSettingWireless *setting;
	gint64 mtu_default;
	guint32 mtu;

	nm_assert (NM_IS_DEVICE (device));
	nm_assert (out_is_user_config);

	setting = NM_SETTING_WIRELESS (nm_device_get_applied_setting (device, NM_TYPE_SETTING_WIRELESS));
	if (!setting)
		g_return_val_if_reached (0);

	mtu = nm_setting_wireless_get_mtu (setting);
	if (mtu == 0) {
		mtu_default = nm_device_get_configured_mtu_from_connection_default (device, "wifi.mtu");
		if (mtu_default >= 0) {
			*out_is_user_config = TRUE;
			return (guint32) mtu_default;
		}
	}
	*out_is_user_config = (mtu != 0);
	return mtu;
}

static void
activation_success_handler (NMDevice *device)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMActRequest *req;
	NMConnection *applied_connection;

	req = nm_device_get_act_request (device);
	g_assert (req);

	applied_connection = nm_act_request_get_applied_connection (req);

	/* Clear wireless secrets tries on success */
	g_object_set_qdata (G_OBJECT (applied_connection), wireless_secrets_tries_quark (), NULL);

	/* There should always be a current AP */
	g_warn_if_fail (priv->current_ap);
}

static void
activation_failure_handler (NMDevice *device)
{
	NMConnection *applied_connection;

	applied_connection = nm_device_get_applied_connection (device);
	g_assert (applied_connection);

	/* Clear wireless secrets tries on failure */
	g_object_set_qdata (G_OBJECT (applied_connection), wireless_secrets_tries_quark (), NULL);
}

static gboolean
periodic_scan_timeout_cb (gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	priv->periodic_scan_id = 0;

	if (priv->scanning || priv->scan_requested)
		return FALSE;

	g_dbus_proxy_call (priv->dbus_proxy, "Scan", g_variant_new ("()"),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   priv->cancellable, scan_cb, self);
	priv->scan_requested = TRUE;

	return FALSE;
}

static void
schedule_periodic_scan (NMDeviceIwd *self, NMDeviceState current_state)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	guint interval;

	if (current_state <= NM_DEVICE_STATE_UNAVAILABLE)
		return;

	if (current_state == NM_DEVICE_STATE_DISCONNECTED)
		interval = 10;
	else
		interval = 20;

	if (priv->periodic_scan_id)
		g_source_remove (priv->periodic_scan_id);

	priv->periodic_scan_id = g_timeout_add_seconds (interval,
	                                                periodic_scan_timeout_cb,
	                                                self);
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (device);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	if (new_state <= NM_DEVICE_STATE_UNAVAILABLE) {
		remove_all_aps (self);
		nm_clear_g_source (&priv->periodic_scan_id);
	} else if (old_state <= NM_DEVICE_STATE_UNAVAILABLE) {
		update_aps (self);
		schedule_periodic_scan (self, new_state);
	}

	switch (new_state) {
	case NM_DEVICE_STATE_UNMANAGED:
		break;
	case NM_DEVICE_STATE_UNAVAILABLE:
		/*
		 * If the device is enabled and the IWD manager is ready,
		 * transition to DISCONNECTED because the device is now
		 * ready to use.
		 */
		if (priv->enabled && priv->dbus_obj) {
			nm_device_queue_recheck_available (device,
			                                   NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
			                                   NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		}
		break;
	case NM_DEVICE_STATE_NEED_AUTH:
		send_disconnect (self);
		break;
	case NM_DEVICE_STATE_IP_CHECK:
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		activation_success_handler (device);
		break;
	case NM_DEVICE_STATE_FAILED:
		activation_failure_handler (device);
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

	if (enabled) {
		if (state != NM_DEVICE_STATE_UNAVAILABLE)
			_LOGW (LOGD_CORE, "not in expected unavailable state!");

		if (priv->dbus_obj)
			nm_device_queue_recheck_available (device,
			                                   NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
			                                   NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
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
	gsize i;
	char **list;

	switch (prop_id) {
	case PROP_MODE:
		if (priv->current_ap)
			g_value_set_uint (value, NM_802_11_MODE_INFRA);
		else
			g_value_set_uint (value, NM_802_11_MODE_UNKNOWN);
		break;
	case PROP_BITRATE:
		g_value_set_uint (value, 65000);
		break;
	case PROP_CAPABILITIES:
		g_value_set_uint (value, priv->capabilities);
		break;
	case PROP_ACCESS_POINTS:
		list = (char **) nm_wifi_aps_get_sorted_paths (priv->aps, TRUE);
		for (i = 0; list[i]; i++)
			list[i] = g_strdup (list[i]);
		g_value_take_boxed (value, list);
		break;
	case PROP_ACTIVE_ACCESS_POINT:
		nm_utils_g_value_set_object_path (value, priv->current_ap);
		break;
	case PROP_SCANNING:
		g_value_set_boolean (value, priv->scanning);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMDeviceIwd *device = NM_DEVICE_IWD (object);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (device);

	switch (prop_id) {
	case PROP_CAPABILITIES:
		/* construct-only */
		priv->capabilities = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
state_changed (NMDeviceIwd *self, const gchar *new_state)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	NMDeviceState dev_state = nm_device_get_state (device);
	gboolean iwd_connection = FALSE;

	_LOGI (LOGD_DEVICE | LOGD_WIFI, "new IWD device state is %s", new_state);

	if (   dev_state >= NM_DEVICE_STATE_CONFIG
	    && dev_state <= NM_DEVICE_STATE_ACTIVATED
	    && dev_state != NM_DEVICE_STATE_NEED_AUTH)
		iwd_connection = TRUE;

	/* Don't allow scanning while connecting, disconnecting or roaming */
	priv->can_scan = NM_IN_STRSET (new_state, "connected", "disconnected");

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

		return;
	} else if (NM_IN_STRSET (new_state, "disconnecting", "disconnected")) {
		if (!iwd_connection)
			return;

		/* Call Disconnect on the IWD device object to make sure it
		 * disables its own autoconnect.
		 *
		 * Note we could instead call net.connman.iwd.KnownNetworks.ForgetNetwork
		 * and leave the device in autoconnect.  This way if NetworkManager
		 * changes any settings for this connection, they'd be taken into
		 * account on the next connection attempt.  But both methods are
		 * a hack, we'll perhaps need an IWD API to "connect once" without
		 * storing anything.
		 */
		send_disconnect (self);

		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
	                                 NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);

		return;
	}

	_LOGE (LOGD_WIFI, "State %s unknown", new_state);
}

static void
scanning_changed (NMDeviceIwd *self, gboolean new_scanning)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	NMDeviceState state = nm_device_get_state (NM_DEVICE (self));

	if (new_scanning == priv->scanning)
		return;

	priv->scanning = new_scanning;

	_notify (self, PROP_SCANNING);

	if (!priv->scanning) {
		update_aps (self);

		if (!priv->scan_requested)
			schedule_periodic_scan (self, state);
	}
}

static void
properties_changed (GDBusProxy *proxy, GVariant *changed_properties,
                    GStrv invalidate_properties, gpointer user_data)
{
	NMDeviceIwd *self = user_data;
	GVariantIter *iter;
	const gchar *key;
	GVariant *value;

	g_variant_get (changed_properties, "a{sv}", &iter);
	while (g_variant_iter_next (iter, "{&sv}", &key, &value)) {
		if (!strcmp (key, "State"))
			state_changed (self, g_variant_get_string (value, NULL));

		if (!strcmp (key, "Scanning"))
			scanning_changed (self, g_variant_get_boolean (value));

		g_variant_unref (value);
	}

	g_variant_iter_free (iter);
}

void
nm_device_iwd_set_dbus_object (NMDeviceIwd *self, GDBusObject *object)
{
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);
	GDBusInterface *interface;

	if (!nm_g_object_ref_set ((GObject **) &priv->dbus_obj, (GObject *) object))
		return;

	if (priv->dbus_proxy) {
		g_signal_handlers_disconnect_by_func (priv->dbus_proxy,
		                                      properties_changed, self);

		g_clear_object (&priv->dbus_proxy);
	}

	if (priv->enabled)
		nm_device_queue_recheck_available (NM_DEVICE (self),
		                                   NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
		                                   NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);

	if (!object) {
		priv->can_scan = FALSE;

		cleanup_association_attempt (self, FALSE);
		return;
	}

	interface = g_dbus_object_get_interface (object, NM_IWD_DEVICE_INTERFACE);
	priv->dbus_proxy = G_DBUS_PROXY (interface);

	g_signal_connect (priv->dbus_proxy, "g-properties-changed",
	                  G_CALLBACK (properties_changed), self);

	/* Call Disconnect to make sure IWD's autoconnect is disabled.  We've
	 * most likely just brought the device UP so it would be in
	 * autoconnect by default.
	 */
	send_disconnect (self);
}

const gchar *
nm_device_iwd_agent_psk_query (NMDeviceIwd *self)
{
	NMActRequest *req;
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;

	req = nm_device_get_act_request (NM_DEVICE (self));
	if (!req)
		return NULL;

	connection = nm_act_request_get_applied_connection (req);
	if (!connection)
		return NULL;

	s_wireless = nm_connection_get_setting_wireless (connection);
	if (!s_wireless)
		return NULL;

	s_wireless_sec = nm_connection_get_setting_wireless_security (connection);
	if (!s_wireless_sec)
		return NULL;

	return nm_setting_wireless_security_get_psk (s_wireless_sec);
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

	priv->aps = g_hash_table_new (nm_str_hash, g_str_equal);

	/* Make sure the manager is running */
	(void) nm_iwd_manager_get ();
}

NMDevice *
nm_device_iwd_new (const char *iface, NMDeviceWifiCapabilities capabilities)
{
	return g_object_new (NM_TYPE_DEVICE_IWD,
	                     NM_DEVICE_IFACE, iface,
	                     NM_DEVICE_TYPE_DESC, "802.11 WiFi",
	                     NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_WIFI,
	                     NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_WIFI,
	                     NM_DEVICE_RFKILL_TYPE, RFKILL_TYPE_WLAN,
	                     NM_DEVICE_IWD_CAPABILITIES, (guint) capabilities,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (object);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	nm_clear_g_cancellable (&priv->cancellable);

	nm_clear_g_source (&priv->periodic_scan_id);

	wifi_secrets_cancel (self);

	cleanup_association_attempt (self, TRUE);

	g_clear_object (&priv->dbus_proxy);
	g_clear_object (&priv->dbus_obj);

	remove_all_aps (self);

	G_OBJECT_CLASS (nm_device_iwd_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceIwd *self = NM_DEVICE_IWD (object);
	NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE (self);

	nm_assert (g_hash_table_size (priv->aps) == 0);

	g_hash_table_unref (priv->aps);

	G_OBJECT_CLASS (nm_device_iwd_parent_class)->finalize (object);
}

static void
nm_device_iwd_class_init (NMDeviceIwdClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NM_SETTING_WIRELESS_SETTING_NAME, NM_LINK_TYPE_WIFI)

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	parent_class->can_auto_connect = can_auto_connect;
	parent_class->is_available = is_available;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->check_connection_available = check_connection_available;
	parent_class->complete_connection = complete_connection;
	parent_class->get_enabled = get_enabled;
	parent_class->set_enabled = set_enabled;
	parent_class->get_type_description = get_type_description;

	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->act_stage2_config = act_stage2_config;
	parent_class->get_configured_mtu = get_configured_mtu;
	parent_class->deactivate = deactivate;
	parent_class->deactivate_async = deactivate_async;
	parent_class->deactivate_async_finish = deactivate_async_finish;
	parent_class->can_reapply_change = can_reapply_change;

	parent_class->state_changed = device_state_changed;

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
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_SCANNING] =
	    g_param_spec_boolean (NM_DEVICE_IWD_SCANNING, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[ACCESS_POINT_ADDED] =
	    g_signal_new (NM_DEVICE_IWD_ACCESS_POINT_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1,
	                  NM_TYPE_WIFI_AP);

	signals[ACCESS_POINT_REMOVED] =
	    g_signal_new (NM_DEVICE_IWD_ACCESS_POINT_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1,
	                  NM_TYPE_WIFI_AP);

	signals[SCANNING_PROHIBITED] =
	    g_signal_new (NM_DEVICE_IWD_SCANNING_PROHIBITED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (NMDeviceIwdClass, scanning_prohibited),
	                  NULL, NULL, NULL,
	                  G_TYPE_BOOLEAN, 1, G_TYPE_BOOLEAN);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_WIFI_SKELETON,
	                                        "GetAccessPoints", impl_device_iwd_get_access_points,
	                                        "GetAllAccessPoints", impl_device_iwd_get_all_access_points,
	                                        "RequestScan", impl_device_iwd_request_scan,
	                                        NULL);
}
