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
 * Copyright (C) 2005 - 2017 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-device-wifi.h"

#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "nm-wifi-ap.h"
#include "nm-common-macros.h"
#include "devices/nm-device.h"
#include "devices/nm-device-private.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-act-request.h"
#include "supplicant/nm-supplicant-manager.h"
#include "supplicant/nm-supplicant-interface.h"
#include "supplicant/nm-supplicant-config.h"
#include "nm-setting-connection.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"
#include "nm-setting-ip4-config.h"
#include "nm-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "platform/nm-platform.h"
#include "nm-auth-utils.h"
#include "settings/nm-settings-connection.h"
#include "settings/nm-settings.h"
#include "nm-wifi-utils.h"
#include "nm-wifi-common.h"
#include "nm-core-internal.h"
#include "nm-config.h"

#include "devices/nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceWifi);

/* All of these are in seconds */
#define SCAN_INTERVAL_MIN 3
#define SCAN_INTERVAL_STEP 20
#define SCAN_INTERVAL_MAX 120

#define SCAN_RAND_MAC_ADDRESS_EXPIRE_MIN 5

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceWifi,
	PROP_MODE,
	PROP_BITRATE,
	PROP_ACCESS_POINTS,
	PROP_ACTIVE_ACCESS_POINT,
	PROP_CAPABILITIES,
	PROP_SCANNING,
);

enum {
	SCANNING_PROHIBITED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	gint8             invalid_strength_counter;

	GHashTable *      aps;
	NMWifiAP *        current_ap;
	guint32           rate;
	bool              enabled:1; /* rfkilled or not */
	bool              requested_scan:1;
	bool              ssid_found:1;
	bool              is_scanning:1;

	gint32            last_scan;
	gint32            scheduled_scan_time;
	guint8            scan_interval; /* seconds */
	guint             pending_scan_id;
	guint             ap_dump_id;

	NMSupplicantManager   *sup_mgr;
	NMSupplicantInterface *sup_iface;
	guint                  sup_timeout_id; /* supplicant association timeout */

	NM80211Mode       mode;

	NMActRequestGetSecretsCallId *wifi_secrets_id;

	guint             periodic_source_id;
	guint             link_timeout_id;
	guint32           failed_iface_count;
	guint             reacquire_iface_id;

	NMDeviceWifiCapabilities capabilities;

	gint32 hw_addr_scan_expire;

	guint             wps_timeout_id;
} NMDeviceWifiPrivate;

struct _NMDeviceWifi
{
	NMDevice parent;
	NMDeviceWifiPrivate _priv;
};

struct _NMDeviceWifiClass
{
	NMDeviceClass parent;

	/* Signals */
	gboolean (*scanning_prohibited) (NMDeviceWifi *device, gboolean periodic);
};

/*****************************************************************************/

G_DEFINE_TYPE (NMDeviceWifi, nm_device_wifi, NM_TYPE_DEVICE)

#define NM_DEVICE_WIFI_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceWifi, NM_IS_DEVICE_WIFI)

/*****************************************************************************/

static gboolean check_scanning_prohibited (NMDeviceWifi *self, gboolean periodic);

static void schedule_scan (NMDeviceWifi *self, gboolean backoff);

static void cleanup_association_attempt (NMDeviceWifi * self,
                                         gboolean disconnect);

static void supplicant_iface_state_cb (NMSupplicantInterface *iface,
                                       int new_state_i,
                                       int old_state_i,
                                       int disconnect_reason,
                                       gpointer user_data);

static void supplicant_iface_bss_updated_cb (NMSupplicantInterface *iface,
                                             const char *object_path,
                                             GVariant *properties,
                                             NMDeviceWifi *self);

static void supplicant_iface_bss_removed_cb (NMSupplicantInterface *iface,
                                             const char *object_path,
                                             NMDeviceWifi *self);

static void supplicant_iface_scan_done_cb (NMSupplicantInterface * iface,
                                           gboolean success,
                                           NMDeviceWifi * self);

static void supplicant_iface_wps_credentials_cb (NMSupplicantInterface *iface,
                                                 GVariant *credentials,
                                                 NMDeviceWifi *self);

static void supplicant_iface_notify_scanning_cb (NMSupplicantInterface * iface,
                                                 GParamSpec * pspec,
                                                 NMDeviceWifi * self);

static void supplicant_iface_notify_current_bss (NMSupplicantInterface *iface,
                                                 GParamSpec *pspec,
                                                 NMDeviceWifi *self);

static void request_wireless_scan (NMDeviceWifi *self,
                                   gboolean periodic,
                                   gboolean force_if_scanning,
                                   const GPtrArray *ssids);

static void ap_add_remove (NMDeviceWifi *self,
                           gboolean is_adding,
                           NMWifiAP *ap,
                           gboolean recheck_available_connections);

static void _hw_addr_set_scanning (NMDeviceWifi *self, gboolean do_reset);

/*****************************************************************************/

static void
_ap_dump (NMDeviceWifi *self,
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

static void
_notify_scanning (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	gboolean scanning;

	scanning =    priv->sup_iface
	           && nm_supplicant_interface_get_scanning (priv->sup_iface);

	if (scanning == priv->is_scanning)
		return;

	_LOGD (LOGD_WIFI, "wifi-scan: scanning-state: %s", scanning ? "scanning" : "idle");
	priv->is_scanning = scanning;
	_notify (self, PROP_SCANNING);
}

static gboolean
unmanaged_on_quit (NMDevice *self)
{
	/* Wi-Fi devices cannot be assumed and are always taken down.
	 * However, also when being disconnected, we scan and thus
	 * set the MAC address to a random value.
	 *
	 * We must restore the original MAC address when quitting, thus
	 * signal to unmanage the device. */
	return TRUE;
}

static gboolean
supplicant_interface_acquire (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (!priv->sup_iface, TRUE);

	priv->sup_iface = nm_supplicant_manager_create_interface (priv->sup_mgr,
	                                                          nm_device_get_iface (NM_DEVICE (self)),
	                                                          NM_SUPPLICANT_DRIVER_WIRELESS);
	if (!priv->sup_iface) {
		_LOGE (LOGD_WIFI, "Couldn't initialize supplicant interface");
		return FALSE;
	}

	if (nm_supplicant_interface_get_state (priv->sup_iface) < NM_SUPPLICANT_INTERFACE_STATE_READY)
		nm_device_add_pending_action (NM_DEVICE (self), NM_PENDING_ACTION_WAITING_FOR_SUPPLICANT, FALSE);

	g_signal_connect (priv->sup_iface,
	                  NM_SUPPLICANT_INTERFACE_STATE,
	                  G_CALLBACK (supplicant_iface_state_cb),
	                  self);
	g_signal_connect (priv->sup_iface,
	                  NM_SUPPLICANT_INTERFACE_BSS_UPDATED,
	                  G_CALLBACK (supplicant_iface_bss_updated_cb),
	                  self);
	g_signal_connect (priv->sup_iface,
	                  NM_SUPPLICANT_INTERFACE_BSS_REMOVED,
	                  G_CALLBACK (supplicant_iface_bss_removed_cb),
	                  self);
	g_signal_connect (priv->sup_iface,
	                  NM_SUPPLICANT_INTERFACE_SCAN_DONE,
	                  G_CALLBACK (supplicant_iface_scan_done_cb),
	                  self);
	g_signal_connect (priv->sup_iface,
	                  NM_SUPPLICANT_INTERFACE_WPS_CREDENTIALS,
	                  G_CALLBACK (supplicant_iface_wps_credentials_cb),
	                  self);
	g_signal_connect (priv->sup_iface,
	                  "notify::"NM_SUPPLICANT_INTERFACE_SCANNING,
	                  G_CALLBACK (supplicant_iface_notify_scanning_cb),
	                  self);
	g_signal_connect (priv->sup_iface,
	                  "notify::" NM_SUPPLICANT_INTERFACE_CURRENT_BSS,
	                  G_CALLBACK (supplicant_iface_notify_current_bss),
	                  self);

	_notify_scanning (self);

	return TRUE;
}

static void
_requested_scan_set (NMDeviceWifi *self, gboolean value)
{
	NMDeviceWifiPrivate *priv;

	value = !!value;

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	if (priv->requested_scan == value)
		return;

	priv->requested_scan = value;
	if (value)
		nm_device_add_pending_action ((NMDevice *) self, NM_PENDING_ACTION_WIFI_SCAN, TRUE);
	else {
		nm_device_emit_recheck_auto_activate (NM_DEVICE (self));
		nm_device_remove_pending_action ((NMDevice *) self, NM_PENDING_ACTION_WIFI_SCAN, TRUE);
	}
}

static void
supplicant_interface_release (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;

	g_return_if_fail (self != NULL);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	_requested_scan_set (self, FALSE);

	nm_clear_g_source (&priv->pending_scan_id);

	/* Reset the scan interval to be pretty frequent when disconnected */
	priv->scan_interval = SCAN_INTERVAL_MIN + SCAN_INTERVAL_STEP;
	_LOGD (LOGD_WIFI, "wifi-scan: reset interval to %u seconds",
	       (unsigned) priv->scan_interval);

	nm_clear_g_source (&priv->ap_dump_id);

	if (priv->sup_iface) {
		/* Clear supplicant interface signal handlers */
		g_signal_handlers_disconnect_by_data (priv->sup_iface, self);

		/* Tell the supplicant to disconnect from the current AP */
		nm_supplicant_interface_disconnect (priv->sup_iface);

		g_clear_object (&priv->sup_iface);
	}

	_notify_scanning (self);
}

static NMWifiAP *
get_ap_by_path (NMDeviceWifi *self, const char *path)
{
	g_return_val_if_fail (path != NULL, NULL);
	return g_hash_table_lookup (NM_DEVICE_WIFI_GET_PRIVATE (self)->aps, path);

}

static NMWifiAP *
get_ap_by_supplicant_path (NMDeviceWifi *self, const char *path)
{
	GHashTableIter iter;
	NMWifiAP *ap;

	g_return_val_if_fail (path != NULL, NULL);

	g_hash_table_iter_init (&iter, NM_DEVICE_WIFI_GET_PRIVATE (self)->aps);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &ap)) {
		if (g_strcmp0 (path, nm_wifi_ap_get_supplicant_path (ap)) == 0)
			return ap;
	}
	return NULL;
}

static void
update_seen_bssids_cache (NMDeviceWifi *self, NMWifiAP *ap)
{
	g_return_if_fail (NM_IS_DEVICE_WIFI (self));

	if (ap == NULL)
		return;

	/* Don't cache the BSSID for Ad-Hoc APs */
	if (nm_wifi_ap_get_mode (ap) != NM_802_11_MODE_INFRA)
		return;

	if (   nm_device_get_state (NM_DEVICE (self)) == NM_DEVICE_STATE_ACTIVATED
	    && nm_device_has_unmodified_applied_connection (NM_DEVICE (self), NM_SETTING_COMPARE_FLAG_NONE)) {
		nm_settings_connection_add_seen_bssid (nm_device_get_settings_connection (NM_DEVICE (self)),
		                                       nm_wifi_ap_get_address (ap));
	}
}

static void
set_current_ap (NMDeviceWifi *self, NMWifiAP *new_ap, gboolean recheck_available_connections)
{
	NMDeviceWifiPrivate *priv;
	NMWifiAP *old_ap;

	g_return_if_fail (NM_IS_DEVICE_WIFI (self));

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	old_ap = priv->current_ap;

	if (old_ap == new_ap)
		return;

	if (new_ap) {
		priv->current_ap = g_object_ref (new_ap);

		/* Update seen BSSIDs cache */
		update_seen_bssids_cache (self, priv->current_ap);
	} else
		priv->current_ap = NULL;

	if (old_ap) {
		NM80211Mode mode = nm_wifi_ap_get_mode (old_ap);

		/* Remove any AP from the internal list if it was created by NM or isn't known to the supplicant */
		if (mode == NM_802_11_MODE_ADHOC || mode == NM_802_11_MODE_AP || nm_wifi_ap_get_fake (old_ap))
			ap_add_remove (self, FALSE, old_ap, recheck_available_connections);
		g_object_unref (old_ap);
	}

	_notify (self, PROP_ACTIVE_ACCESS_POINT);
}

static void
periodic_update (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	int ifindex = nm_device_get_ifindex (NM_DEVICE (self));
	guint32 new_rate;
	int percent;
	NMDeviceState state;
	NMSupplicantInterfaceState supplicant_state;

	/* BSSID and signal strength have meaningful values only if the device
	 * is activated and not scanning.
	 */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state != NM_DEVICE_STATE_ACTIVATED)
		return;

	/* Only update current AP if we're actually talking to something, otherwise
	 * assume the old one (if any) is still valid until we're told otherwise or
	 * the connection fails.
	 */
	supplicant_state = nm_supplicant_interface_get_state (priv->sup_iface);
	if (   supplicant_state < NM_SUPPLICANT_INTERFACE_STATE_AUTHENTICATING
	    || supplicant_state > NM_SUPPLICANT_INTERFACE_STATE_COMPLETED
	    || nm_supplicant_interface_get_scanning (priv->sup_iface))
		return;

	/* In AP mode we currently have nothing to do. */
	if (priv->mode == NM_802_11_MODE_AP)
		return;

	if (priv->current_ap) {
		/* Smooth out the strength to work around crappy drivers */
		percent = nm_platform_wifi_get_quality (nm_device_get_platform (NM_DEVICE (self)), ifindex);
		if (percent >= 0 || ++priv->invalid_strength_counter > 3) {
			if (nm_wifi_ap_set_strength (priv->current_ap, (gint8) percent)) {
#ifdef NM_MORE_LOGGING
				_ap_dump (self, LOGL_TRACE, priv->current_ap, "updated", 0);
#endif
			}
			priv->invalid_strength_counter = 0;
		}
	}

	new_rate = nm_platform_wifi_get_rate (nm_device_get_platform (NM_DEVICE (self)), ifindex);
	if (new_rate != priv->rate) {
		priv->rate = new_rate;
		_notify (self, PROP_BITRATE);
	}
}

static gboolean
periodic_update_cb (gpointer user_data)
{
	periodic_update (NM_DEVICE_WIFI (user_data));
	return TRUE;
}

static void
ap_add_remove (NMDeviceWifi *self,
               gboolean is_adding, /* or else removing */
               NMWifiAP *ap,
               gboolean recheck_available_connections)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (is_adding) {
		g_hash_table_insert (priv->aps,
		                     (gpointer) nm_dbus_object_export (NM_DBUS_OBJECT (ap)),
		                     g_object_ref (ap));
		_ap_dump (self, LOGL_DEBUG, ap, "added", 0);
	} else
		_ap_dump (self, LOGL_DEBUG, ap, "removed", 0);

	nm_dbus_object_emit_signal (NM_DBUS_OBJECT (self),
	                            &nm_interface_info_device_wireless,
	                            is_adding
	                              ? &nm_signal_info_wireless_access_point_added
	                              : &nm_signal_info_wireless_access_point_removed,
	                            "(o)",
	                            nm_dbus_object_get_path (NM_DBUS_OBJECT (ap)));

	if (!is_adding) {
		g_hash_table_remove (priv->aps, nm_dbus_object_get_path (NM_DBUS_OBJECT (ap)));
		nm_dbus_object_clear_and_unexport (&ap);
	}

	_notify (self, PROP_ACCESS_POINTS);

	nm_device_emit_recheck_auto_activate (NM_DEVICE (self));
	if (recheck_available_connections)
		nm_device_recheck_available_connections (NM_DEVICE (self));
}

static void
remove_all_aps (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	GHashTableIter iter;
	NMWifiAP *ap;

	if (!g_hash_table_size (priv->aps))
		return;

	set_current_ap (self, NULL, FALSE);

again:
	g_hash_table_iter_init (&iter, priv->aps);
	if (g_hash_table_iter_next (&iter, NULL, (gpointer) &ap)) {
		ap_add_remove (self, FALSE, ap, FALSE);
		goto again;
	}

	nm_device_recheck_available_connections (NM_DEVICE (self));
}

static void
deactivate (NMDevice *device)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	int ifindex = nm_device_get_ifindex (device);
	NM80211Mode old_mode = priv->mode;

	nm_clear_g_source (&priv->periodic_source_id);

	cleanup_association_attempt (self, TRUE);

	priv->rate = 0;

	set_current_ap (self, NULL, TRUE);

	/* Clear any critical protocol notification in the Wi-Fi stack */
	nm_platform_wifi_indicate_addressing_running (nm_device_get_platform (device), ifindex, FALSE);

	/* Ensure we're in infrastructure mode after deactivation; some devices
	 * (usually older ones) don't scan well in adhoc mode.
	 */
	if (nm_platform_wifi_get_mode (nm_device_get_platform (device), ifindex) != NM_802_11_MODE_INFRA) {
		nm_device_take_down (NM_DEVICE (self), TRUE);
		nm_platform_wifi_set_mode (nm_device_get_platform (device), ifindex, NM_802_11_MODE_INFRA);
		nm_device_bring_up (NM_DEVICE (self), TRUE, NULL);
	}

	if (priv->mode != NM_802_11_MODE_INFRA) {
		priv->mode = NM_802_11_MODE_INFRA;
		_notify (self, PROP_MODE);
	}

	/* Ensure we trigger a scan after deactivating a Hotspot */
	if (old_mode == NM_802_11_MODE_AP)
		request_wireless_scan (self, FALSE, FALSE, NULL);
}

static void
deactivate_reset_hw_addr (NMDevice *device)
{
	_hw_addr_set_scanning ((NMDeviceWifi *) device, TRUE);
}

static gboolean
is_adhoc_wpa (NMConnection *connection)
{
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	const char *mode, *key_mgmt;

	/* The kernel doesn't support Ad-Hoc WPA connections well at this time,
	 * and turns them into open networks.  It's been this way since at least
	 * 2.6.30 or so; until that's fixed, disable WPA-protected Ad-Hoc networks.
	 */

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wifi != NULL, FALSE);

	mode = nm_setting_wireless_get_mode (s_wifi);
	if (g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_ADHOC) != 0)
		return FALSE;

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (!s_wsec)
		return FALSE;

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	if (g_strcmp0 (key_mgmt, "wpa-none") != 0)
		return FALSE;

	return TRUE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	const char *mac;
	const char * const *mac_blacklist;
	int i;
	const char *mode;
	const char *perm_hw_addr;

	if (!NM_DEVICE_CLASS (nm_device_wifi_parent_class)->check_connection_compatible (device, connection))
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

	if (is_adhoc_wpa (connection))
		return FALSE;

	/* Early exit if supplicant or device doesn't support requested mode */
	mode = nm_setting_wireless_get_mode (s_wireless);
	if (g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_ADHOC) == 0) {
		if (!(priv->capabilities & NM_WIFI_DEVICE_CAP_ADHOC))
			return FALSE;
	} else if (g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_AP) == 0) {
		if (!(priv->capabilities & NM_WIFI_DEVICE_CAP_AP))
			return FALSE;

		if (priv->sup_iface) {
			if (nm_supplicant_interface_get_ap_support (priv->sup_iface) == NM_SUPPLICANT_FEATURE_NO)
				return FALSE;
		}
	}

	// FIXME: check channel/freq/band against bands the hardware supports
	// FIXME: check encryption against device capabilities
	// FIXME: check bitrate against device capabilities

	return TRUE;
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSettingWireless *s_wifi;
	const char *mode;

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wifi, FALSE);

	/* a connection that is available for a certain @specific_object, MUST
	 * also be available in general (without @specific_object). */

	if (specific_object) {
		NMWifiAP *ap;

		ap = get_ap_by_path (self, specific_object);
		return ap ? nm_wifi_ap_check_compatible (ap, connection) : FALSE;
	}

	/* Ad-Hoc and AP connections are always available because they may be
	 * started at any time.
	 */
	mode = nm_setting_wireless_get_mode (s_wifi);
	if (   g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_ADHOC) == 0
	    || g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_AP) == 0)
		return TRUE;

	/* Hidden SSIDs obviously don't always appear in the scan list either.
	 *
	 * For an explict user-activation-request, a connection is considered
	 * available because for hidden Wi-Fi, clients didn't consistently
	 * set the 'hidden' property to indicate hidden SSID networks.  If
	 * activating but the network isn't available let the device recheck
	 * availability.
	 */
	if (nm_setting_wireless_get_hidden (s_wifi) || NM_FLAGS_HAS (flags, _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_IGNORE_AP))
		return TRUE;

	/* check at least one AP is compatible with this connection */
	return !!nm_wifi_aps_find_first_compatible (priv->aps, connection, TRUE);
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSettingWireless *s_wifi;
	const char *setting_mac;
	char *str_ssid = NULL;
	NMWifiAP *ap;
	const GByteArray *ssid = NULL;
	GByteArray *tmp_ssid = NULL;
	GBytes *setting_ssid = NULL;
	gboolean hidden = FALSE;
	const char *perm_hw_addr;
	const char *mode;

	s_wifi = nm_connection_get_setting_wireless (connection);

	mode = s_wifi ? nm_setting_wireless_get_mode (s_wifi) : NULL;

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

		if (!nm_streq0 (mode, NM_SETTING_WIRELESS_MODE_AP)) {
			/* Find a compatible AP in the scan list */
			ap = nm_wifi_aps_find_first_compatible (priv->aps, connection, FALSE);

			/* If we still don't have an AP, then the WiFI settings needs to be
			 * fully specified by the client.  Might not be able to find an AP
			 * if the network isn't broadcasting the SSID for example.
			 */
			if (!ap) {
				if (!nm_setting_verify (NM_SETTING (s_wifi), connection, error))
					return FALSE;

				hidden = TRUE;
			}
		} else {
			if (!nm_setting_verify (NM_SETTING (s_wifi), connection, error))
				return FALSE;
			ap = NULL;
		}
	} else if (nm_streq0 (mode, NM_SETTING_WIRELESS_MODE_AP)) {
		if (!nm_setting_verify (NM_SETTING (s_wifi), connection, error))
			return FALSE;
		ap = NULL;
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

	if (ap)
		ssid = nm_wifi_ap_get_ssid (ap);
	if (ssid == NULL) {
		/* The AP must be hidden.  Connecting to a WiFi AP requires the SSID
		 * as part of the initial handshake, so check the connection details
		 * for the SSID.  The AP object will still be used for encryption
		 * settings and such.
		 */
		setting_ssid = nm_setting_wireless_get_ssid (s_wifi);
		if (setting_ssid) {
			ssid = tmp_ssid = g_byte_array_new ();
			g_byte_array_append (tmp_ssid,
			                     g_bytes_get_data (setting_ssid, NULL),
			                     g_bytes_get_size (setting_ssid));
		}
	}

	if (ssid == NULL) {
		/* If there's no SSID on the AP itself, and no SSID in the
		 * connection data, then we cannot connect at all.  Return an error.
		 */
		g_set_error_literal (error,
		                     NM_DEVICE_ERROR,
		                     NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     ap
		                         ? "A 'wireless' setting with a valid SSID is required for hidden access points."
		                         : "Cannot create 'wireless' setting due to missing SSID.");
		return FALSE;
	}

	if (ap) {
		/* If the SSID is a well-known SSID, lock the connection to the AP's
		 * specific BSSID so NM doesn't autoconnect to some random wifi net.
		 */
		if (!nm_wifi_ap_complete_connection (ap,
		                                     connection,
		                                     nm_wifi_utils_is_manf_default_ssid (ssid),
		                                     error)) {
			if (tmp_ssid)
				g_byte_array_unref (tmp_ssid);
			return FALSE;
		}
	}

	/* The kernel doesn't support Ad-Hoc WPA connections well at this time,
	 * and turns them into open networks.  It's been this way since at least
	 * 2.6.30 or so; until that's fixed, disable WPA-protected Ad-Hoc networks.
	 */
	if (is_adhoc_wpa (connection)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_SETTING,
		                     _("WPA Ad-Hoc disabled due to kernel bugs"));
		g_prefix_error (error, "%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
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

	if (hidden)
		g_object_set (s_wifi, NM_SETTING_WIRELESS_HIDDEN, TRUE, NULL);

	perm_hw_addr = nm_device_get_permanent_hw_address (device);
	if (perm_hw_addr) {
		setting_mac = nm_setting_wireless_get_mac_address (s_wifi);
		if (setting_mac) {
			/* Make sure the setting MAC (if any) matches the device's permanent MAC */
			if (!nm_utils_hwaddr_matches (setting_mac, -1, perm_hw_addr, -1)) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("connection does not match device"));
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
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSupplicantInterfaceState supplicant_state;

	if (!priv->enabled)
		return FALSE;

	if (!priv->sup_iface)
		return FALSE;

	supplicant_state = nm_supplicant_interface_get_state (priv->sup_iface);
	if (   supplicant_state < NM_SUPPLICANT_INTERFACE_STATE_READY
	    || supplicant_state > NM_SUPPLICANT_INTERFACE_STATE_COMPLETED)
		return FALSE;

	return TRUE;
}

static gboolean
get_autoconnect_allowed (NMDevice *device)
{
	NMDeviceWifiPrivate *priv;

	priv = NM_DEVICE_WIFI_GET_PRIVATE (NM_DEVICE_WIFI (device));
	return !priv->requested_scan;
}

static gboolean
can_auto_connect (NMDevice *device,
                  NMConnection *connection,
                  char **specific_object)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSettingWireless *s_wifi;
	NMWifiAP *ap;
	const char *method, *mode;
	guint64 timestamp = 0;

	nm_assert (!specific_object || !*specific_object);

	if (!NM_DEVICE_CLASS (nm_device_wifi_parent_class)->can_auto_connect (device, connection, NULL))
		return FALSE;

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wifi, FALSE);

	/* Always allow autoconnect for AP and non-autoconf Ad-Hoc */
	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	mode = nm_setting_wireless_get_mode (s_wifi);
	if (g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_AP) == 0)
		return TRUE;
	else if (   g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_ADHOC) == 0
	         && g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) != 0)
		return TRUE;

	/* Don't autoconnect to networks that have been tried at least once
	 * but haven't been successful, since these are often accidental choices
	 * from the menu and the user may not know the password.
	 */
	if (nm_settings_connection_get_timestamp (NM_SETTINGS_CONNECTION (connection), &timestamp)) {
		if (timestamp == 0)
			return FALSE;
	}

	ap = nm_wifi_aps_find_first_compatible (priv->aps, connection, FALSE);
	if (ap) {
		/* All good; connection is usable */
		NM_SET_OUT (specific_object, g_strdup (nm_dbus_object_get_path (NM_DBUS_OBJECT (ap))));
		return TRUE;
	}

	return FALSE;
}

GHashTable *
_nm_device_wifi_get_aps (NMDeviceWifi *self)
{
	return NM_DEVICE_WIFI_GET_PRIVATE (self)->aps;
}

static void
_hw_addr_set_scanning (NMDeviceWifi *self, gboolean do_reset)
{
	NMDevice *device = (NMDevice *) self;
	NMDeviceWifiPrivate *priv;
	guint32 now;
	gboolean randomize;

	g_return_if_fail (NM_IS_DEVICE_WIFI (self));

	if (   nm_device_is_activating (device)
	    || nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED)
		return;

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	randomize = nm_config_data_get_device_config_boolean (NM_CONFIG_GET_DATA,
	                                                      NM_CONFIG_KEYFILE_KEY_DEVICE_WIFI_SCAN_RAND_MAC_ADDRESS,
	                                                      device,
	                                                      TRUE, TRUE);

	if (!randomize) {
		/* expire the temporary MAC address used during scanning */
		priv->hw_addr_scan_expire = 0;

		if (do_reset)
			nm_device_hw_addr_reset (device, "scanning");
		return;
	}

	now = nm_utils_get_monotonic_timestamp_s ();

	if (now >= priv->hw_addr_scan_expire) {
		gs_free char *generate_mac_address_mask = NULL;
		gs_free char *hw_addr_scan = NULL;

		/* the random MAC address for scanning expires after a while.
		 *
		 * We don't bother with to update the MAC address exactly when
		 * it expires, instead on the next scan request, we will generate
		 * a new one.*/
		priv->hw_addr_scan_expire = now + (SCAN_RAND_MAC_ADDRESS_EXPIRE_MIN * 60);

		generate_mac_address_mask = nm_config_data_get_device_config (NM_CONFIG_GET_DATA,
		                                                              "wifi.scan-generate-mac-address-mask",
		                                                              device,
		                                                              NULL);

		hw_addr_scan = nm_utils_hw_addr_gen_random_eth (nm_device_get_initial_hw_address (device),
		                                                generate_mac_address_mask);
		nm_device_hw_addr_set (device, hw_addr_scan, "scanning", TRUE);
	}
}

static GPtrArray *
ssids_options_to_ptrarray (GVariant *value, GError **error)
{
	GPtrArray *ssids = NULL;
	GByteArray *ssid_array;
	GVariant *v;
	const guint8 *bytes;
	gsize len;
	int num_ssids, i;

	num_ssids = g_variant_n_children (value);
	if (num_ssids > 32) {
		g_set_error_literal (error,
		                     NM_DEVICE_ERROR,
		                     NM_DEVICE_ERROR_NOT_ALLOWED,
		                     "too many SSIDs requested to scan");
		return NULL;
	}

	if (num_ssids) {
		ssids = g_ptr_array_new_full (num_ssids, (GDestroyNotify) g_byte_array_unref);
		for (i = 0; i < num_ssids; i++) {
			v = g_variant_get_child_value (value, i);
			bytes = g_variant_get_fixed_array (v, &len, sizeof (guint8));
			if (len > 32) {
				g_set_error (error,
				             NM_DEVICE_ERROR,
				             NM_DEVICE_ERROR_NOT_ALLOWED,
				             "SSID at index %d more than 32 bytes", i);
				g_ptr_array_unref (ssids);
				return NULL;
			}

			ssid_array = g_byte_array_new ();
			g_byte_array_append (ssid_array, bytes, len);
			g_ptr_array_add (ssids, ssid_array);
		}
	}
	return ssids;
}

static void
dbus_request_scan_cb (NMDevice *device,
                      GDBusMethodInvocation *context,
                      NMAuthSubject *subject,
                      GError *error,
                      gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	gs_unref_variant GVariant *scan_options = user_data;
	gs_unref_ptrarray GPtrArray *ssids = NULL;

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

	if (scan_options) {
		gs_unref_variant GVariant *val = g_variant_lookup_value (scan_options, "ssids", NULL);

		if (val) {
			gs_free_error GError *ssid_error = NULL;

			if (!g_variant_is_of_type (val, G_VARIANT_TYPE ("aay"))) {
				g_dbus_method_invocation_return_error_literal (context,
				                                               NM_DEVICE_ERROR,
				                                               NM_DEVICE_ERROR_NOT_ALLOWED,
				                                               "Invalid 'ssid' scan option");
				return;
			}

			ssids = ssids_options_to_ptrarray (val, &ssid_error);
			if (ssid_error) {
				g_dbus_method_invocation_return_gerror (context, ssid_error);
				return;
			}
		}
	}

	request_wireless_scan (self, FALSE, FALSE, ssids);
	g_dbus_method_invocation_return_value (context, NULL);
}

void
_nm_device_wifi_request_scan (NMDeviceWifi *self,
                              GVariant *options,
                              GDBusMethodInvocation *invocation)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	gint32 last_scan;

	if (   !priv->enabled
	    || !priv->sup_iface
	    || nm_device_get_state (device) < NM_DEVICE_STATE_DISCONNECTED
	    || nm_device_is_activating (device)) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_ALLOWED,
		                                               "Scanning not allowed while unavailable or activating");
		return;
	}

	if (nm_supplicant_interface_get_scanning (priv->sup_iface)) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_ALLOWED,
		                                               "Scanning not allowed while already scanning");
		return;
	}

	last_scan = nm_supplicant_interface_get_last_scan_time (priv->sup_iface);
	if (last_scan && (nm_utils_get_monotonic_timestamp_s () - last_scan) < 10) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_ALLOWED,
		                                               "Scanning not allowed immediately following previous scan");
		return;
	}

	g_signal_emit_by_name (device,
	                       NM_DEVICE_AUTH_REQUEST,
	                       invocation,
	                       NULL,
	                       NM_AUTH_PERMISSION_NETWORK_CONTROL,
	                       TRUE,
	                       dbus_request_scan_cb,
	                       options ? g_variant_ref (options) : NULL);
}

static gboolean
scanning_prohibited (NMDeviceWifi *self, gboolean periodic)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSupplicantInterfaceState supplicant_state;

	g_return_val_if_fail (priv->sup_iface != NULL, TRUE);

	/* Don't scan when a an AP or Ad-Hoc connection is active as it will
	 * disrupt connected clients or peers.
	 */
	if (priv->mode == NM_802_11_MODE_ADHOC || priv->mode == NM_802_11_MODE_AP)
		return TRUE;

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
		/* Prohibit periodic scans when connected; we ask the supplicant to
		 * background scan for us, unless the connection is locked to a specifc
		 * BSSID.
		 */
		if (periodic)
			return TRUE;
		break;
	}

	/* Prohibit scans if the supplicant is busy */
	supplicant_state = nm_supplicant_interface_get_state (priv->sup_iface);
	if (   supplicant_state == NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING
	    || supplicant_state == NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED
	    || supplicant_state == NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE
	    || supplicant_state == NM_SUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE
	    || nm_supplicant_interface_get_scanning (priv->sup_iface))
		return TRUE;

	/* Allow the scan */
	return FALSE;
}

static gboolean
check_scanning_prohibited (NMDeviceWifi *self, gboolean periodic)
{
	gboolean prohibited = FALSE;

	g_signal_emit (self, signals[SCANNING_PROHIBITED], 0, periodic, &prohibited);
	return prohibited;
}

static gboolean
hidden_filter_func (NMSettings *settings,
                    NMSettingsConnection *connection,
                    gpointer user_data)
{
	NMSettingWireless *s_wifi;

	if (!nm_connection_is_type (NM_CONNECTION (connection), NM_SETTING_WIRELESS_SETTING_NAME))
		return FALSE;
	s_wifi = nm_connection_get_setting_wireless (NM_CONNECTION (connection));
	if (!s_wifi)
		return FALSE;
	if (nm_streq0 (nm_setting_wireless_get_mode (s_wifi), NM_SETTING_WIRELESS_MODE_AP))
		return FALSE;
	return nm_setting_wireless_get_hidden (s_wifi);
}

static GPtrArray *
build_hidden_probe_list (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	guint max_scan_ssids = nm_supplicant_interface_get_max_scan_ssids (priv->sup_iface);
	gs_free NMSettingsConnection **connections = NULL;
	guint i, len;
	GPtrArray *ssids = NULL;
	static GByteArray *nullssid = NULL;

	/* Need at least two: wildcard SSID and one or more hidden SSIDs */
	if (max_scan_ssids < 2)
		return NULL;

	connections = nm_settings_get_connections_clone (nm_device_get_settings ((NMDevice *) self),
	                                                 &len,
	                                                 hidden_filter_func, NULL,
	                                                 NULL, NULL);
	if (!connections[0])
		return NULL;

	g_qsort_with_data (connections, len, sizeof (NMSettingsConnection *), nm_settings_connection_cmp_timestamp_p_with_data, NULL);

	ssids = g_ptr_array_new_full (max_scan_ssids, (GDestroyNotify) g_byte_array_unref);

	/* Add wildcard SSID using a static wildcard SSID used for every scan */
	if (G_UNLIKELY (nullssid == NULL))
		nullssid = g_byte_array_new ();
	g_ptr_array_add (ssids, g_byte_array_ref (nullssid));

	for (i = 0; connections[i]; i++) {
		NMSettingWireless *s_wifi;
		GBytes *ssid;
		GByteArray *ssid_array;

		if (i >= max_scan_ssids - 1)
			break;

		s_wifi = (NMSettingWireless *) nm_connection_get_setting_wireless (NM_CONNECTION (connections[i]));
		g_assert (s_wifi);
		ssid = nm_setting_wireless_get_ssid (s_wifi);
		g_assert (ssid);
		ssid_array = g_byte_array_new ();
		g_byte_array_append (ssid_array,
		                     g_bytes_get_data (ssid, NULL),
		                     g_bytes_get_size (ssid));
		g_ptr_array_add (ssids, ssid_array);
	}

	return ssids;
}

static void
request_wireless_scan (NMDeviceWifi *self,
                       gboolean periodic,
                       gboolean force_if_scanning,
                       const GPtrArray *ssids)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	gboolean request_started = FALSE;

	nm_clear_g_source (&priv->pending_scan_id);

	if (!force_if_scanning && priv->requested_scan) {
		/* There's already a scan in progress */
		return;
	}

	if (!check_scanning_prohibited (self, periodic)) {
		gs_unref_ptrarray GPtrArray *hidden_ssids = NULL;

		_LOGD (LOGD_WIFI, "wifi-scan: scanning requested");

		if (!ssids) {
			ssids = hidden_ssids = build_hidden_probe_list (self);
		}

		if (_LOGD_ENABLED (LOGD_WIFI)) {
			if (ssids) {
				const GByteArray *ssid;
				guint i;
				char *foo;

				for (i = 0; i < ssids->len; i++) {
					ssid = g_ptr_array_index (ssids, i);
					foo = ssid->len > 0
					      ? nm_utils_ssid_to_utf8 (ssid->data, ssid->len)
					      : NULL;
					_LOGD (LOGD_WIFI, "wifi-scan: (%u) probe scanning SSID %s%s%s",
					       i, NM_PRINT_FMT_QUOTED (foo, "\"", foo, "\"", "*any*"));
					g_free (foo);
				}
			} else
				_LOGD (LOGD_WIFI, "wifi-scan: no SSIDs to probe scan");
		}

		_hw_addr_set_scanning (self, FALSE);

		nm_supplicant_interface_request_scan (priv->sup_iface, ssids);
		request_started = TRUE;
	} else
		_LOGD (LOGD_WIFI, "wifi-scan: scanning requested but not allowed at this time");

	_requested_scan_set (self, request_started);

	schedule_scan (self, request_started);
}

static gboolean
request_wireless_scan_periodic (gpointer user_data)
{
	NMDeviceWifi *self = user_data;
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	priv->pending_scan_id = 0;
	request_wireless_scan (self, TRUE, FALSE, NULL);
	return G_SOURCE_REMOVE;
}

/*
 * schedule_scan
 *
 * Schedule a wireless scan.
 *
 */
static void
schedule_scan (NMDeviceWifi *self, gboolean backoff)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	gint32 now = nm_utils_get_monotonic_timestamp_s ();

	/* Cancel the pending scan if it would happen later than (now + the scan_interval) */
	if (priv->pending_scan_id) {
		if (now + priv->scan_interval < priv->scheduled_scan_time)
			nm_clear_g_source (&priv->pending_scan_id);
	}

	if (!priv->pending_scan_id) {
		guint factor = 2, next_scan = priv->scan_interval;

		if (    nm_device_is_activating (NM_DEVICE (self))
		    || (nm_device_get_state (NM_DEVICE (self)) == NM_DEVICE_STATE_ACTIVATED))
			factor = 1;

		priv->pending_scan_id = g_timeout_add_seconds (next_scan,
		                                               request_wireless_scan_periodic,
		                                               self);

		priv->scheduled_scan_time = now + priv->scan_interval;
		if (backoff && (priv->scan_interval < (SCAN_INTERVAL_MAX / factor))) {
				priv->scan_interval += (SCAN_INTERVAL_STEP / factor);
				/* Ensure the scan interval will never be less than 20s... */
				priv->scan_interval = MAX(priv->scan_interval, SCAN_INTERVAL_MIN + SCAN_INTERVAL_STEP);
				/* ... or more than 120s */
				priv->scan_interval = MIN(priv->scan_interval, SCAN_INTERVAL_MAX);
		} else if (!backoff && (priv->scan_interval == 0)) {
			/* Invalid combination; would cause continual rescheduling of
			 * the scan and hog CPU.  Reset to something minimally sane.
			 */
			priv->scan_interval = 5;
		}

		_LOGD (LOGD_WIFI, "wifi-scan: scheduled in %d seconds (interval now %d seconds)",
		       next_scan, priv->scan_interval);
	}
}

static void
supplicant_iface_scan_done_cb (NMSupplicantInterface *iface,
                               gboolean success,
                               NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	_LOGD (LOGD_WIFI, "wifi-scan: scan-done callback: %s", success ? "successful" : "failed");

	priv->last_scan = nm_utils_get_monotonic_timestamp_s ();
	schedule_scan (self, success);

	_requested_scan_set (self, FALSE);
}

/****************************************************************************
 * WPA Supplicant control stuff
 *
 */

static gboolean
ap_list_dump (gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	priv->ap_dump_id = 0;

	if (_LOGD_ENABLED (LOGD_WIFI_SCAN)) {
		gs_free NMWifiAP **list = NULL;
		gsize i;
		gint32 now_s = nm_utils_get_monotonic_timestamp_s ();

		_LOGD (LOGD_WIFI_SCAN, "APs: [now:%u last:%u next:%u]",
		       now_s,
		       priv->last_scan,
		       priv->scheduled_scan_time);
		list = nm_wifi_aps_get_sorted (priv->aps, TRUE);
		for (i = 0; list[i]; i++)
			_ap_dump (self, LOGL_DEBUG, list[i], "dump", now_s);
	}
	return G_SOURCE_REMOVE;
}

static void
schedule_ap_list_dump (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (   !priv->ap_dump_id
	    && _LOGD_ENABLED (LOGD_WIFI_SCAN))
		priv->ap_dump_id = g_timeout_add_seconds (1, ap_list_dump, self);
}

static void
try_fill_ssid_for_hidden_ap (NMDeviceWifi *self,
                             NMWifiAP *ap)
{
	const char *bssid;
	NMSettingsConnection *const*connections;
	guint i;

	g_return_if_fail (nm_wifi_ap_get_ssid (ap) == NULL);

	bssid = nm_wifi_ap_get_address (ap);
	g_return_if_fail (bssid);

	/* Look for this AP's BSSID in the seen-bssids list of a connection,
	 * and if a match is found, copy over the SSID */
	connections = nm_settings_get_connections (nm_device_get_settings ((NMDevice *) self), NULL);
	for (i = 0; connections[i]; i++) {
		NMConnection *connection = (NMConnection *) connections[i];
		NMSettingWireless *s_wifi;

		s_wifi = nm_connection_get_setting_wireless (connection);
		if (s_wifi) {
			if (nm_settings_connection_has_seen_bssid (NM_SETTINGS_CONNECTION (connection), bssid)) {
				GBytes *ssid = nm_setting_wireless_get_ssid (s_wifi);

				nm_wifi_ap_set_ssid (ap,
				                     g_bytes_get_data (ssid, NULL),
				                     g_bytes_get_size (ssid));
				break;
			}
		}
	}
}

static void
supplicant_iface_bss_updated_cb (NMSupplicantInterface *iface,
                                 const char *object_path,
                                 GVariant *properties,
                                 NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMDeviceState state;
	NMWifiAP *found_ap = NULL;
	const GByteArray *ssid;

	g_return_if_fail (self != NULL);
	g_return_if_fail (properties != NULL);
	g_return_if_fail (iface != NULL);

	/* Ignore new APs when unavailable, unmanaged, or in AP mode */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state <= NM_DEVICE_STATE_UNAVAILABLE)
		return;
	if (NM_DEVICE_WIFI_GET_PRIVATE (self)->mode == NM_802_11_MODE_AP)
		return;

	found_ap = get_ap_by_supplicant_path (self, object_path);
	if (found_ap) {
		if (!nm_wifi_ap_update_from_properties (found_ap, object_path, properties))
			return;
		_ap_dump (self, LOGL_DEBUG, found_ap, "updated", 0);
	} else {
		gs_unref_object NMWifiAP *ap = NULL;

		ap = nm_wifi_ap_new_from_properties (object_path, properties);
		if (!ap) {
			_LOGD (LOGD_WIFI, "invalid AP properties received for %s", object_path);
			return;
		}

		/* Let the manager try to fill in the SSID from seen-bssids lists */
		ssid = nm_wifi_ap_get_ssid (ap);
		if (!ssid || nm_utils_is_empty_ssid (ssid->data, ssid->len)) {
			/* Try to fill the SSID from the AP database */
			try_fill_ssid_for_hidden_ap (self, ap);

			ssid = nm_wifi_ap_get_ssid (ap);
			if (ssid && (nm_utils_is_empty_ssid (ssid->data, ssid->len) == FALSE)) {
				/* Yay, matched it, no longer treat as hidden */
				_LOGD (LOGD_WIFI, "matched hidden AP %s => '%s'",
				       nm_wifi_ap_get_address (ap), nm_utils_escape_ssid (ssid->data, ssid->len));
			} else {
				/* Didn't have an entry for this AP in the database */
				_LOGD (LOGD_WIFI, "failed to match hidden AP %s",
				       nm_wifi_ap_get_address (ap));
			}
		}

		ap_add_remove (self, TRUE, ap, TRUE);
	}

	/* Update the current AP if the supplicant notified a current BSS change
	 * before it sent the current BSS's scan result.
	 */
	if (g_strcmp0 (nm_supplicant_interface_get_current_bss (iface), object_path) == 0)
		supplicant_iface_notify_current_bss (priv->sup_iface, NULL, self);

	schedule_ap_list_dump (self);
}

static void
supplicant_iface_bss_removed_cb (NMSupplicantInterface *iface,
                                 const char *object_path,
                                 NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;
	NMWifiAP *ap;

	g_return_if_fail (self != NULL);
	g_return_if_fail (object_path != NULL);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	ap = get_ap_by_supplicant_path (self, object_path);
	if (!ap)
		return;

	if (ap == priv->current_ap) {
		/* The current AP cannot be removed (to prevent NM indicating that
		 * it is connected, but to nothing), but it must be removed later
		 * when the current AP is changed or cleared.  Set 'fake' to
		 * indicate that this AP is now unknown to the supplicant.
		 */
		if (nm_wifi_ap_set_fake (ap, TRUE))
			_ap_dump (self, LOGL_DEBUG, ap, "updated", 0);
	} else {
		ap_add_remove (self, FALSE, ap, TRUE);
		schedule_ap_list_dump (self);
	}
}

static void
cleanup_association_attempt (NMDeviceWifi *self, gboolean disconnect)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	nm_clear_g_source (&priv->sup_timeout_id);
	nm_clear_g_source (&priv->link_timeout_id);
	nm_clear_g_source (&priv->wps_timeout_id);
	if (disconnect && priv->sup_iface)
		nm_supplicant_interface_disconnect (priv->sup_iface);
}

static void
cleanup_supplicant_failures (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	nm_clear_g_source (&priv->reacquire_iface_id);
	priv->failed_iface_count = 0;
}

static void
wifi_secrets_cb (NMActRequest *req,
                 NMActRequestGetSecretsCallId *call_id,
                 NMSettingsConnection *connection,
                 GError *error,
                 gpointer user_data)
{
	NMDevice *device = user_data;
	NMDeviceWifi *self = user_data;
	NMDeviceWifiPrivate *priv;

	g_return_if_fail (NM_IS_DEVICE_WIFI (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	g_return_if_fail (priv->wifi_secrets_id == call_id);

	priv->wifi_secrets_id = NULL;

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	g_return_if_fail (req == nm_device_get_act_request (device));
	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);
	g_return_if_fail (nm_act_request_get_settings_connection (req) == connection);

	if (error) {
		_LOGW (LOGD_WIFI, "%s", error->message);

		if (g_error_matches (error, NM_AGENT_MANAGER_ERROR,
		                     NM_AGENT_MANAGER_ERROR_USER_CANCELED)) {
			/* Don't wait for WPS timeout on an explicit cancel. */
			nm_clear_g_source (&priv->wps_timeout_id);
		}

		if (!priv->wps_timeout_id) {
			/* Fail the device only if the WPS period is over too. */
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_NO_SECRETS);
		}
	} else
		nm_device_activate_schedule_stage1_device_prepare (device);
}

static void
wifi_secrets_cancel (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->wifi_secrets_id)
		nm_act_request_cancel_secrets (NULL, priv->wifi_secrets_id);
	nm_assert (!priv->wifi_secrets_id);
}

static void
supplicant_iface_wps_credentials_cb (NMSupplicantInterface *iface,
                                     GVariant *credentials,
                                     NMDeviceWifi *self)
{
	NMActRequest *req;
	GVariant *val, *secrets = NULL;
	const char *array;
	gsize psk_len = 0;
	GError *error = NULL;

	if (nm_device_get_state (NM_DEVICE (self)) != NM_DEVICE_STATE_NEED_AUTH) {
		_LOGI (LOGD_DEVICE | LOGD_WIFI, "WPS: The connection can't be updated with credentials");
		return;
	}

	_LOGI (LOGD_DEVICE | LOGD_WIFI, "WPS: Updating the connection with credentials");

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	val = g_variant_lookup_value (credentials, "Key", G_VARIANT_TYPE_BYTESTRING);
	if (val) {
		char psk[64];

		array = g_variant_get_fixed_array (val, &psk_len, 1);
		if (psk_len >= 8 && psk_len <= 63) {
			memcpy (psk, array, psk_len);
			psk[psk_len] = '\0';
			if (g_utf8_validate (psk, psk_len, NULL)) {
				secrets = g_variant_new_parsed ("[{%s, [{%s, <%s>}]}]",
				                                NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
				                                NM_SETTING_WIRELESS_SECURITY_PSK, psk);
				g_variant_ref_sink (secrets);
			}
		}
		if (!secrets)
			_LOGW (LOGD_DEVICE | LOGD_WIFI, "WPS: ignore invalid PSK");
		g_variant_unref (val);
	}
	if (secrets) {
		if (nm_settings_connection_new_secrets (nm_act_request_get_settings_connection (req),
		                                         nm_act_request_get_applied_connection (req),
		                                         NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
		                                         secrets, &error)) {
			wifi_secrets_cancel (self);
			nm_device_activate_schedule_stage1_device_prepare (NM_DEVICE (self));
		} else {
			_LOGW (LOGD_DEVICE | LOGD_WIFI, "WPS: Could not update the connection with credentials: %s", error->message);
			g_error_free (error);
		}
		g_variant_unref (secrets);
	}
}

static gboolean
wps_timeout_cb (gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	priv->wps_timeout_id = 0;
	if (!priv->wifi_secrets_id) {
		/* Fail only if the secrets are not being requested. */
		nm_device_state_changed (NM_DEVICE (self),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_NO_SECRETS);
	}

	return G_SOURCE_REMOVE;
}

static void
wifi_secrets_get_secrets (NMDeviceWifi *self,
                          const char *setting_name,
                          NMSecretAgentGetSecretsFlags flags)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
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

/*
 * link_timeout_cb
 *
 * Called when the link to the access point has been down for a specified
 * period of time.
 */
static gboolean
link_timeout_cb (gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	_LOGW (LOGD_WIFI, "link timed out.");

	priv->link_timeout_id = 0;

	/* Disconnect event while activated; the supplicant hasn't been able
	 * to reassociate within the timeout period, so the connection must
	 * fail.
	 */
	if (nm_device_get_state (device) != NM_DEVICE_STATE_ACTIVATED)
		return FALSE;

	set_current_ap (self, NULL, TRUE);

	nm_device_state_changed (device,
	                         NM_DEVICE_STATE_FAILED,
	                         priv->ssid_found ? NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT :
	                                            NM_DEVICE_STATE_REASON_SSID_NOT_FOUND);
	return FALSE;
}

static gboolean
need_new_8021x_secrets (NMDeviceWifi *self,
                        NMSupplicantInterfaceState old_state,
                        const char **setting_name)
{
	NMSetting8021x *s_8021x;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;
	NMConnection *connection;

	g_assert (setting_name != NULL);

	connection = nm_device_get_applied_connection (NM_DEVICE (self));
	g_return_val_if_fail (connection != NULL, FALSE);

	/* 802.1x stuff only happens in the supplicant's ASSOCIATED state when it's
	 * attempting to authenticate with the AP.
	 */
	if (old_state != NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED)
		return FALSE;

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
need_new_wpa_psk (NMDeviceWifi *self,
                  NMSupplicantInterfaceState old_state,
                  gint disconnect_reason,
                  const char **setting_name)
{
	NMSettingWirelessSecurity *s_wsec;
	NMConnection *connection;
	const char *key_mgmt = NULL;

	g_assert (setting_name != NULL);

	connection = nm_device_get_applied_connection (NM_DEVICE (self));
	g_return_val_if_fail (connection != NULL, FALSE);

	/* A bad PSK will cause the supplicant to disconnect during the 4-way handshake */
	if (old_state != NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE)
		return FALSE;

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (s_wsec)
		key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);

	if (g_strcmp0 (key_mgmt, "wpa-psk") == 0) {
		/* -4 (locally-generated WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY) usually
		 * means the driver missed beacons from the AP.  This usually happens
		 * due to driver bugs or faulty power-save management.  It doesn't
		 * indicate that the PSK is wrong.
		 */
		#define LOCAL_WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY -4
		if (disconnect_reason == LOCAL_WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY)
			return FALSE;

		*setting_name = NM_SETTING_WIRELESS_SECURITY_SETTING_NAME;
		return TRUE;
	}

	/* Not a WPA-PSK connection */
	return FALSE;
}

static gboolean
handle_8021x_or_psk_auth_fail (NMDeviceWifi *self,
                               NMSupplicantInterfaceState new_state,
                               NMSupplicantInterfaceState old_state,
                               int disconnect_reason)
{
	NMDevice *device = NM_DEVICE (self);
	NMActRequest *req;
	const char *setting_name = NULL;
	gboolean handled = FALSE;

	g_return_val_if_fail (new_state == NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED, FALSE);

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_val_if_fail (req != NULL, FALSE);

	if (   need_new_8021x_secrets (self, old_state, &setting_name)
	    || need_new_wpa_psk (self, old_state, disconnect_reason, &setting_name)) {

		nm_act_request_clear_secrets (req);

		_LOGI (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) disconnected during association, asking for new key");

		cleanup_association_attempt (self, TRUE);
		nm_device_state_changed (device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
		wifi_secrets_get_secrets (self,
		                          setting_name,
		                          NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION
		                            | NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW);
		handled = TRUE;
	}

	return handled;
}

static gboolean
reacquire_interface_cb (gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	priv->reacquire_iface_id = 0;
	priv->failed_iface_count++;

	_LOGW (LOGD_WIFI, "re-acquiring supplicant interface (#%d).", priv->failed_iface_count);

	if (!priv->sup_iface)
		supplicant_interface_acquire (self);

	return G_SOURCE_REMOVE;
}

static void
supplicant_iface_state_cb (NMSupplicantInterface *iface,
                           int new_state_i,
                           int old_state_i,
                           int disconnect_reason,
                           gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	NMDeviceState devstate;
	gboolean scanning;
	NMSupplicantInterfaceState new_state = new_state_i;
	NMSupplicantInterfaceState old_state = old_state_i;

	if (new_state == old_state)
		return;

	_LOGI (LOGD_DEVICE | LOGD_WIFI,
	       "supplicant interface state: %s -> %s",
	       nm_supplicant_interface_state_to_string (old_state),
	       nm_supplicant_interface_state_to_string (new_state));

	devstate = nm_device_get_state (device);
	scanning = nm_supplicant_interface_get_scanning (iface);

	/* In these states we know the supplicant is actually talking to something */
	if (   new_state >= NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING
	    && new_state <= NM_SUPPLICANT_INTERFACE_STATE_COMPLETED)
		priv->ssid_found = TRUE;

	switch (new_state) {
	case NM_SUPPLICANT_INTERFACE_STATE_READY:
		_LOGD (LOGD_WIFI, "supplicant ready");
		nm_device_queue_recheck_available (NM_DEVICE (device),
		                                   NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
		                                   NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		priv->scan_interval = SCAN_INTERVAL_MIN;
		if (old_state < NM_SUPPLICANT_INTERFACE_STATE_READY)
			nm_device_remove_pending_action (device, NM_PENDING_ACTION_WAITING_FOR_SUPPLICANT, TRUE);
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_COMPLETED:
		nm_clear_g_source (&priv->sup_timeout_id);
		nm_clear_g_source (&priv->link_timeout_id);
		nm_clear_g_source (&priv->wps_timeout_id);

		/* If this is the initial association during device activation,
		 * schedule the next activation stage.
		 */
		if (devstate == NM_DEVICE_STATE_CONFIG) {
			NMConnection *connection;
			NMSettingWireless *s_wifi;
			GBytes *ssid;

			connection = nm_device_get_applied_connection (NM_DEVICE (self));
			g_return_if_fail (connection);

			s_wifi = nm_connection_get_setting_wireless (connection);
			g_return_if_fail (s_wifi);

			ssid = nm_setting_wireless_get_ssid (s_wifi);
			g_return_if_fail (ssid);

			_LOGI (LOGD_DEVICE | LOGD_WIFI,
			       "Activation: (wifi) Stage 2 of 5 (Device Configure) successful.  %s '%s'.",
			       priv->mode == NM_802_11_MODE_AP ? "Started Wi-Fi Hotspot" :
			       "Connected to wireless network",
			       ssid ? nm_utils_escape_ssid (g_bytes_get_data (ssid, NULL),
			                                    g_bytes_get_size (ssid)) : "(none)");
			nm_device_activate_schedule_stage3_ip_config_start (device);
		} else if (devstate == NM_DEVICE_STATE_ACTIVATED)
			periodic_update (self);
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED:
		if ((devstate == NM_DEVICE_STATE_ACTIVATED) || nm_device_is_activating (device)) {
			/* Disconnect of an 802.1x/LEAP connection during authentication,
			 * or disconnect of a WPA-PSK connection during the 4-way handshake,
			 * often means secrets are wrong. Not always the case, but until we
			 * have more information from wpa_supplicant about why the
			 * disconnect happened this is the best we can do.
			 */
			if (handle_8021x_or_psk_auth_fail (self, new_state, old_state, disconnect_reason))
				break;
		}

		/* Otherwise it might be a stupid driver or some transient error, so
		 * let the supplicant try to reconnect a few more times.  Give it more
		 * time if a scan is in progress since the link might be dropped during
		 * the scan but will be re-established when the scan is done.
		 */
		if (devstate == NM_DEVICE_STATE_ACTIVATED) {
			if (priv->link_timeout_id == 0) {
				priv->link_timeout_id = g_timeout_add_seconds (scanning ? 30 : 15, link_timeout_cb, self);
				priv->ssid_found = FALSE;
			}
		}
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_DOWN:
		nm_device_queue_recheck_available (NM_DEVICE (device),
		                                   NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
		                                   NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		cleanup_association_attempt (self, FALSE);

		if (old_state < NM_SUPPLICANT_INTERFACE_STATE_READY)
			nm_device_remove_pending_action (device, NM_PENDING_ACTION_WAITING_FOR_SUPPLICANT, TRUE);

		/* If the device is already in UNAVAILABLE state then the state change
		 * is a NOP and the interface won't be re-acquired in the device state
		 * change handler.  So ensure we have a new one here so that we're
		 * ready if the supplicant comes back.
		 */
		supplicant_interface_release (self);
		if (priv->failed_iface_count < 5)
			priv->reacquire_iface_id = g_timeout_add_seconds (10, reacquire_interface_cb, self);
		else
			_LOGI (LOGD_DEVICE | LOGD_WIFI, "supplicant interface keeps failing, giving up");
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_INACTIVE:
		/* we would clear _requested_scan_set() and trigger a new scan.
		 * However, we don't want to cancel the current pending action, so force
		 * a new scan request. */
		request_wireless_scan (self, FALSE, TRUE, NULL);
		break;
	default:
		break;
	}

	/* Signal scanning state changes */
	if (   new_state == NM_SUPPLICANT_INTERFACE_STATE_SCANNING
	    || old_state == NM_SUPPLICANT_INTERFACE_STATE_SCANNING)
		_notify_scanning (self);
}

static void
supplicant_iface_assoc_cb (NMSupplicantInterface *iface,
                           GError *error,
                           gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDevice *device = NM_DEVICE (self);

	if (   error && !nm_utils_error_is_cancelled (error, TRUE)
	    && nm_device_is_activating (device)) {
		cleanup_association_attempt (self, TRUE);
		nm_device_queue_state (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
	}
}

static void
supplicant_iface_notify_scanning_cb (NMSupplicantInterface *iface,
                                     GParamSpec *pspec,
                                     NMDeviceWifi *self)
{
	_notify_scanning (self);

	/* Run a quick update of current AP when coming out of a scan */
	if (   !NM_DEVICE_WIFI_GET_PRIVATE (self)->is_scanning
	    && nm_device_get_state (NM_DEVICE (self)) == NM_DEVICE_STATE_ACTIVATED)
		periodic_update (self);
}

static void
supplicant_iface_notify_current_bss (NMSupplicantInterface *iface,
                                     GParamSpec *pspec,
                                     NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	const char *current_bss;
	NMWifiAP *new_ap = NULL;

	current_bss = nm_supplicant_interface_get_current_bss (iface);
	if (current_bss)
		new_ap = get_ap_by_supplicant_path (self, current_bss);

	if (new_ap != priv->current_ap) {
		const char *new_bssid = NULL;
		const GByteArray *new_ssid = NULL;
		const char *old_bssid = NULL;
		const GByteArray *old_ssid = NULL;

		/* Don't ever replace a "fake" current AP if we don't know about the
		 * supplicant's current BSS yet.  It'll get replaced when we receive
		 * the current BSS's scan result.
		 */
		if (new_ap == NULL && nm_wifi_ap_get_fake (priv->current_ap))
			return;

		if (new_ap) {
			new_bssid = nm_wifi_ap_get_address (new_ap);
			new_ssid = nm_wifi_ap_get_ssid (new_ap);
		}

		if (priv->current_ap) {
			old_bssid = nm_wifi_ap_get_address (priv->current_ap);
			old_ssid = nm_wifi_ap_get_ssid (priv->current_ap);
		}

		_LOGD (LOGD_WIFI, "roamed from BSSID %s (%s) to %s (%s)",
		       old_bssid ? old_bssid : "(none)",
		       old_ssid ? nm_utils_escape_ssid (old_ssid->data, old_ssid->len) : "(none)",
		       new_bssid ? new_bssid : "(none)",
		       new_ssid ? nm_utils_escape_ssid (new_ssid->data, new_ssid->len) : "(none)");

		set_current_ap (self, new_ap, TRUE);
	}
}

static gboolean
handle_auth_or_fail (NMDeviceWifi *self,
                     NMActRequest *req,
                     gboolean new_secrets)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	const char *setting_name;
	NMConnection *applied_connection;
	NMSettingWirelessSecurity *s_wsec;
	const char *bssid = NULL;
	NM80211ApFlags ap_flags;
	NMSettingWirelessSecurityWpsMethod wps_method;
	const char *type;
	NMSecretAgentGetSecretsFlags get_secret_flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (self), FALSE);

	if (!req) {
		req = nm_device_get_act_request (NM_DEVICE (self));
		g_return_val_if_fail (req, FALSE);
	}

	if (!nm_device_auth_retries_try_next (NM_DEVICE (self)))
		return FALSE;

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);

	applied_connection = nm_act_request_get_applied_connection (req);
	s_wsec = nm_connection_get_setting_wireless_security (applied_connection);
	wps_method = nm_setting_wireless_security_get_wps_method (s_wsec);

	/* Negotiate the WPS method */
	if (wps_method == NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT)
		wps_method = NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_AUTO;

	if (   wps_method & NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_AUTO
	    && priv->current_ap) {
		/* Determine the method to use from AP capabilities. */
		ap_flags = nm_wifi_ap_get_flags (priv->current_ap);
		if (ap_flags & NM_802_11_AP_FLAGS_WPS_PBC)
			wps_method |= NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_PBC;
		if (ap_flags & NM_802_11_AP_FLAGS_WPS_PIN)
			wps_method |= NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_PIN;
		if (   ap_flags & NM_802_11_AP_FLAGS_WPS
		    && wps_method == NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_AUTO) {
			/* The AP doesn't specify which methods are supported. Allow all. */
			wps_method |= NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_PBC;
			wps_method |= NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_PIN;
		}
	}

	if (wps_method & NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_PBC) {
		get_secret_flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_WPS_PBC_ACTIVE;
		type = "pbc";
	} else if (wps_method & NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_PIN) {
		type = "pin";
	} else
		type = NULL;

	if (type) {
		priv->wps_timeout_id = g_timeout_add_seconds (30, wps_timeout_cb, self);
		if (priv->current_ap)
			bssid = nm_wifi_ap_get_address (priv->current_ap);
		nm_supplicant_interface_enroll_wps (priv->sup_iface, type, bssid, NULL);
	}

	nm_act_request_clear_secrets (req);
	setting_name = nm_connection_need_secrets (applied_connection, NULL);
	if (!setting_name) {
		_LOGW (LOGD_DEVICE, "Cleared secrets, but setting didn't need any secrets.");
		return FALSE;
	}

	if (new_secrets)
		get_secret_flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;
	wifi_secrets_get_secrets (self, setting_name, get_secret_flags);
	return TRUE;
}

/*
 * supplicant_connection_timeout_cb
 *
 * Called when the supplicant has been unable to connect to an access point
 * within a specified period of time.
 */
static gboolean
supplicant_connection_timeout_cb (gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMActRequest *req;
	NMConnection *connection;

	cleanup_association_attempt (self, TRUE);

	if (!nm_device_is_activating (device))
		return FALSE;

	/* Timed out waiting for a successful connection to the AP; if the AP's
	 * security requires network-side authentication (like WPA or 802.1x)
	 * and the connection attempt timed out then it's likely the authentication
	 * information (passwords, pin codes, etc) are wrong.
	 */

	req = nm_device_get_act_request (device);
	g_assert (req);

	connection = nm_act_request_get_applied_connection (req);
	g_assert (connection);

	if (   priv->mode == NM_802_11_MODE_ADHOC
	    || priv->mode == NM_802_11_MODE_AP) {
		/* In Ad-Hoc and AP modes there's nothing to check the encryption key
		 * (if any), so supplicant timeouts here are almost certainly the wifi
		 * driver being really stupid.
		 */
		_LOGW (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) %s network creation took too long, failing activation",
		       priv->mode == NM_802_11_MODE_ADHOC ? "Ad-Hoc" : "Hotspot");
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT);
		return FALSE;
	}

	g_assert (priv->mode == NM_802_11_MODE_INFRA);

	if (priv->ssid_found && nm_connection_get_setting_wireless_security (connection)) {
		guint64 timestamp = 0;
		gboolean new_secrets = TRUE;

		/* Connection failed; either driver problems, the encryption key is
		 * wrong, or the passwords or certificates were wrong.
		 */
		_LOGW (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) association took too long");

		/* Ask for new secrets only if we've never activated this connection
		 * before.  If we've connected before, don't bother the user with
		 * dialogs, just retry or fail, and if we never connect the user can
		 * fix the password somewhere else.
		 */
		if (nm_settings_connection_get_timestamp (nm_act_request_get_settings_connection (req), &timestamp))
			new_secrets = !timestamp;

		if (handle_auth_or_fail (self, req, new_secrets))
			_LOGW (LOGD_DEVICE | LOGD_WIFI, "Activation: (wifi) asking for new secrets");
		else {
			nm_device_state_changed (device, NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_NO_SECRETS);
		}
	} else {
		_LOGW (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) association took too long, failing activation");
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED,
		                         priv->ssid_found ? NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT :
		                                            NM_DEVICE_STATE_REASON_SSID_NOT_FOUND);
	}

	return FALSE;
}

static NMSupplicantConfig *
build_supplicant_config (NMDeviceWifi *self,
                         NMConnection *connection,
                         guint32 fixed_freq,
                         GError **error)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSupplicantConfig *config = NULL;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;
	NMSettingWirelessSecurityPmf pmf;
	NMSettingWirelessSecurityFils fils;
	gs_free char *value = NULL;

	g_return_val_if_fail (priv->sup_iface, NULL);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wireless != NULL, NULL);

	config = nm_supplicant_config_new (
		nm_supplicant_interface_get_pmf_support (priv->sup_iface) == NM_SUPPLICANT_FEATURE_YES,
		nm_supplicant_interface_get_fils_support (priv->sup_iface) == NM_SUPPLICANT_FEATURE_YES);

	/* Warn if AP mode may not be supported */
	if (   g_strcmp0 (nm_setting_wireless_get_mode (s_wireless), NM_SETTING_WIRELESS_MODE_AP) == 0
	    && nm_supplicant_interface_get_ap_support (priv->sup_iface) == NM_SUPPLICANT_FEATURE_UNKNOWN) {
		_LOGW (LOGD_WIFI, "Supplicant may not support AP mode; connection may time out.");
	}

	if (!nm_supplicant_config_add_setting_wireless (config,
	                                                s_wireless,
	                                                fixed_freq,
	                                                error)) {
		g_prefix_error (error, "802-11-wireless: ");
		goto error;
	}

	if (!nm_supplicant_config_add_bgscan (config, connection, error)) {
		g_prefix_error (error, "bgscan: ");
		goto error;
	}

	s_wireless_sec = nm_connection_get_setting_wireless_security (connection);
	if (s_wireless_sec) {
		NMSetting8021x *s_8021x;
		const char *con_uuid = nm_connection_get_uuid (connection);
		guint32 mtu = nm_platform_link_get_mtu (nm_device_get_platform (NM_DEVICE (self)),
		                                        nm_device_get_ifindex (NM_DEVICE (self)));

		g_assert (con_uuid);

		/* Configure PMF (802.11w) */
		pmf = nm_setting_wireless_security_get_pmf (s_wireless_sec);
		if (pmf == NM_SETTING_WIRELESS_SECURITY_PMF_DEFAULT) {
			value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
			                                               "wifi-sec.pmf",
			                                               NM_DEVICE (self));
			pmf = _nm_utils_ascii_str_to_int64 (value, 10,
			                                    NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE,
			                                    NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED,
			                                    NM_SETTING_WIRELESS_SECURITY_PMF_OPTIONAL);
		}

		/* Configure FILS (802.11ai) */
		fils = nm_setting_wireless_security_get_fils (s_wireless_sec);
		if (fils == NM_SETTING_WIRELESS_SECURITY_FILS_DEFAULT) {
			value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
			                                               "wifi-sec.fils",
			                                               NM_DEVICE (self));
			fils = _nm_utils_ascii_str_to_int64 (value, 10,
			                                     NM_SETTING_WIRELESS_SECURITY_FILS_DISABLE,
			                                     NM_SETTING_WIRELESS_SECURITY_FILS_REQUIRED,
			                                     NM_SETTING_WIRELESS_SECURITY_FILS_OPTIONAL);
		}

		s_8021x = nm_connection_get_setting_802_1x (connection);
		if (!nm_supplicant_config_add_setting_wireless_security (config,
		                                                         s_wireless_sec,
		                                                         s_8021x,
		                                                         con_uuid,
		                                                         mtu,
		                                                         pmf,
		                                                         fils,
		                                                         error)) {
			g_prefix_error (error, "802-11-wireless-security: ");
			goto error;
		}
	} else {
		if (!nm_supplicant_config_add_no_security (config, error)) {
			g_prefix_error (error, "unsecured-option: ");
			goto error;
		}
	}

	return config;

error:
	g_object_unref (config);
	return NULL;
}

/*****************************************************************************/

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMActStageReturn ret;
	NMWifiAP *ap = NULL;
	NMActRequest *req;
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	const char *mode;
	const char *ap_path;

	ret = NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage1_prepare (device, out_failure_reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_val_if_fail (req, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_act_request_get_applied_connection (req);
	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wireless, NM_ACT_STAGE_RETURN_FAILURE);

	nm_supplicant_interface_cancel_wps (priv->sup_iface);

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_INFRA) == 0)
		priv->mode = NM_802_11_MODE_INFRA;
	else if (g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_ADHOC) == 0)
		priv->mode = NM_802_11_MODE_ADHOC;
	else if (g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_AP) == 0) {
		priv->mode = NM_802_11_MODE_AP;

		/* Scanning not done in AP mode; clear the scan list */
		remove_all_aps (self);
	}
	_notify (self, PROP_MODE);

	/* The kernel doesn't support Ad-Hoc WPA connections well at this time,
	 * and turns them into open networks.  It's been this way since at least
	 * 2.6.30 or so; until that's fixed, disable WPA-protected Ad-Hoc networks.
	 */
	if (is_adhoc_wpa (connection)) {
		_LOGW (LOGD_WIFI, "Ad-Hoc WPA disabled due to kernel bugs");
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	/* expire the temporary MAC address used during scanning */
	priv->hw_addr_scan_expire = 0;

	/* Set spoof MAC to the interface */
	if (!nm_device_hw_addr_set_cloned (device, connection, TRUE))
		return NM_ACT_STAGE_RETURN_FAILURE;

	/* AP mode never uses a specific object or existing scanned AP */
	if (priv->mode != NM_802_11_MODE_AP) {
		ap_path = nm_active_connection_get_specific_object (NM_ACTIVE_CONNECTION (req));
		ap = ap_path ? get_ap_by_path (self, ap_path) : NULL;
		if (ap)
			goto done;

		ap = nm_wifi_aps_find_first_compatible (priv->aps, connection, FALSE);
	}

	if (ap) {
		nm_active_connection_set_specific_object (NM_ACTIVE_CONNECTION (req),
		                                          nm_dbus_object_get_path (NM_DBUS_OBJECT (ap)));
		goto done;
	}

	/* If the user is trying to connect to an AP that NM doesn't yet know about
	 * (hidden network or something) or starting a Hotspot, create an fake AP
	 * from the security settings in the connection.  This "fake" AP gets used
	 * until the real one is found in the scan list (Ad-Hoc or Hidden), or until
	 * the device is deactivated (Hotspot).
	 */
	ap = nm_wifi_ap_new_fake_from_connection (connection);
	g_return_val_if_fail (ap != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	if (nm_wifi_ap_is_hotspot (ap))
		nm_wifi_ap_set_address (ap, nm_device_get_hw_address (device));

	g_object_freeze_notify (G_OBJECT (self));
	ap_add_remove (self, TRUE, ap, TRUE);
	g_object_thaw_notify (G_OBJECT (self));
	set_current_ap (self, ap, FALSE);
	nm_active_connection_set_specific_object (NM_ACTIVE_CONNECTION (req),
	                                          nm_dbus_object_get_path (NM_DBUS_OBJECT (ap)));
	return NM_ACT_STAGE_RETURN_SUCCESS;

done:
	set_current_ap (self, ap, TRUE);
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
ensure_hotspot_frequency (NMDeviceWifi *self,
                          NMSettingWireless *s_wifi,
                          NMWifiAP *ap)
{
	NMDevice *device = NM_DEVICE (self);
	const char *band = nm_setting_wireless_get_band (s_wifi);
	const guint32 a_freqs[] = { 5180, 5200, 5220, 5745, 5765, 5785, 5805, 0 };
	const guint32 bg_freqs[] = { 2412, 2437, 2462, 2472, 0 };
	guint32 freq = 0;

	g_assert (ap);

	if (nm_wifi_ap_get_freq (ap))
		return;

	if (g_strcmp0 (band, "a") == 0)
		freq = nm_platform_wifi_find_frequency (nm_device_get_platform (device), nm_device_get_ifindex (device), a_freqs);
	else
		freq = nm_platform_wifi_find_frequency (nm_device_get_platform (device), nm_device_get_ifindex (device), bg_freqs);

	if (!freq)
		freq = (g_strcmp0 (band, "a") == 0) ? 5180 : 2462;

	if (nm_wifi_ap_set_freq (ap, freq))
		_ap_dump (self, LOGL_DEBUG, ap, "updated", 0);
}

static void
set_powersave (NMDevice *device)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMSettingWireless *s_wireless;
	NMSettingWirelessPowersave powersave;
	gs_free char *value = NULL;

	s_wireless = (NMSettingWireless *) nm_device_get_applied_setting (device, NM_TYPE_SETTING_WIRELESS);
	g_return_if_fail (s_wireless);

	powersave = nm_setting_wireless_get_powersave (s_wireless);
	if (powersave == NM_SETTING_WIRELESS_POWERSAVE_DEFAULT) {
		value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
		                                               "wifi.powersave",
		                                               device);
		powersave = _nm_utils_ascii_str_to_int64 (value, 10,
		                                          NM_SETTING_WIRELESS_POWERSAVE_IGNORE,
		                                          NM_SETTING_WIRELESS_POWERSAVE_ENABLE,
		                                          NM_SETTING_WIRELESS_POWERSAVE_IGNORE);
	}

	_LOGT (LOGD_WIFI, "powersave is set to %u", (unsigned) powersave);

	if (powersave == NM_SETTING_WIRELESS_POWERSAVE_IGNORE)
		return;

	nm_platform_wifi_set_powersave (nm_device_get_platform (device),
	                                nm_device_get_ifindex (device),
	                                powersave == NM_SETTING_WIRELESS_POWERSAVE_ENABLE);
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMSupplicantConfig *config = NULL;
	NMActRequest *req;
	NMWifiAP *ap;
	NMConnection *connection;
	const char *setting_name;
	NMSettingWireless *s_wireless;
	GError *error = NULL;
	guint timeout;

	nm_clear_g_source (&priv->sup_timeout_id);
	nm_clear_g_source (&priv->link_timeout_id);
	nm_clear_g_source (&priv->wps_timeout_id);

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

	/* If we need secrets, get them */
	setting_name = nm_connection_need_secrets (connection, NULL);
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

	/* have secrets, or no secrets required */
	if (nm_connection_get_setting_wireless_security (connection)) {
		_LOGI (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) connection '%s' has security, and secrets exist.  No new secrets needed.",
		       nm_connection_get_id (connection));
	} else {
		_LOGI (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) connection '%s' requires no security.  No secrets needed.",
		       nm_connection_get_id (connection));
	}

	priv->ssid_found = FALSE;

	/* Supplicant requires an initial frequency for Ad-Hoc and Hotspot; if the user
	 * didn't specify one and we didn't find an AP that matched the connection,
	 * just pick a frequency the device supports.
	 */
	if ((nm_wifi_ap_get_mode (ap) == NM_802_11_MODE_ADHOC) || nm_wifi_ap_is_hotspot (ap))
		ensure_hotspot_frequency (self, s_wireless, ap);

	if (nm_wifi_ap_get_mode (ap) == NM_802_11_MODE_INFRA)
		set_powersave (device);

	/* Build up the supplicant configuration */
	config = build_supplicant_config (self, connection, nm_wifi_ap_get_freq (ap), &error);
	if (config == NULL) {
		_LOGE (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) couldn't build wireless configuration: %s",
		       error->message);
		g_clear_error (&error);
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED);
		goto out;
	}

	nm_supplicant_interface_assoc (priv->sup_iface, config,
	                               supplicant_iface_assoc_cb, self);

	/* Set up a timeout on the association attempt */
	timeout = nm_device_get_supplicant_timeout (NM_DEVICE (self));
	priv->sup_timeout_id = g_timeout_add_seconds (timeout,
	                                              supplicant_connection_timeout_cb,
	                                              self);

	if (!priv->periodic_source_id)
		priv->periodic_source_id = g_timeout_add_seconds (6, periodic_update_cb, self);

	/* We'll get stage3 started when the supplicant connects */
	ret = NM_ACT_STAGE_RETURN_POSTPONE;

out:
	if (ret == NM_ACT_STAGE_RETURN_FAILURE)
		cleanup_association_attempt (self, TRUE);

	if (config) {
		/* Supplicant interface object refs the config; we no longer care about
		 * it after this function.
		 */
		g_object_unref (config);
	}
	return ret;
}

static NMActStageReturn
act_stage3_ip4_config_start (NMDevice *device,
                             NMIP4Config **out_config,
                             NMDeviceStateReason *out_failure_reason)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	const char *method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;

	connection = nm_device_get_applied_connection (device);
	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (s_ip4)
		method = nm_setting_ip_config_get_method (s_ip4);

	/* Indicate that a critical protocol is about to start */
	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0)
		nm_platform_wifi_indicate_addressing_running (nm_device_get_platform (device), nm_device_get_ifindex (device), TRUE);

	return NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage3_ip4_config_start (device, out_config, out_failure_reason);
}

static NMActStageReturn
act_stage3_ip6_config_start (NMDevice *device,
                             NMIP6Config **out_config,
                             NMDeviceStateReason *out_failure_reason)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip6;
	const char *method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;

	connection = nm_device_get_applied_connection (device);
	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (s_ip6)
		method = nm_setting_ip_config_get_method (s_ip6);

	/* Indicate that a critical protocol is about to start */
	if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0 ||
	    strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP) == 0)
		nm_platform_wifi_indicate_addressing_running (nm_device_get_platform (device), nm_device_get_ifindex (device), TRUE);

	return NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage3_ip6_config_start (device, out_config, out_failure_reason);
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

static gboolean
is_static_wep (NMConnection *connection)
{
	NMSettingWirelessSecurity *s_wsec;
	const char *str;

	g_return_val_if_fail (connection != NULL, FALSE);

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (!s_wsec)
		return FALSE;

	str = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	if (g_strcmp0 (str, "none") != 0)
		return FALSE;

	str = nm_setting_wireless_security_get_auth_alg (s_wsec);
	if (g_strcmp0 (str, "leap") == 0)
		return FALSE;

	return TRUE;
}

static NMActStageReturn
handle_ip_config_timeout (NMDeviceWifi *self,
                          NMConnection *connection,
                          gboolean may_fail,
                          gboolean *chain_up,
                          NMDeviceStateReason *out_failure_reason)
{
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	g_return_val_if_fail (connection != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	if (NM_DEVICE_WIFI_GET_PRIVATE (self)->mode == NM_802_11_MODE_AP) {
		*chain_up = TRUE;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	/* If IP configuration times out and it's a static WEP connection, that
	 * usually means the WEP key is wrong.  WEP's Open System auth mode has
	 * no provision for figuring out if the WEP key is wrong, so you just have
	 * to wait for DHCP to fail to figure it out.  For all other WiFi security
	 * types (open, WPA, 802.1x, etc) if the secrets/certs were wrong the
	 * connection would have failed before IP configuration.
	 */
	if (!may_fail && is_static_wep (connection)) {
		/* Activation failed, we must have bad encryption key */
		_LOGW (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) could not get IP configuration for connection '%s'.",
		       nm_connection_get_id (connection));

		if (handle_auth_or_fail (self, NULL, TRUE)) {
			_LOGI (LOGD_DEVICE | LOGD_WIFI,
			       "Activation: (wifi) asking for new secrets");
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
		} else {
			NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_NO_SECRETS);
			ret = NM_ACT_STAGE_RETURN_FAILURE;
		}
	} else {
		/* Not static WEP or failure allowed; let superclass handle it */
		*chain_up = TRUE;
	}

	return ret;
}


static NMActStageReturn
act_stage4_ip4_config_timeout (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	gboolean may_fail = FALSE, chain_up = FALSE;
	NMActStageReturn ret;

	connection = nm_device_get_applied_connection (device);
	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	may_fail = nm_setting_ip_config_get_may_fail (s_ip4);

	ret = handle_ip_config_timeout (NM_DEVICE_WIFI (device), connection, may_fail, &chain_up, out_failure_reason);
	if (chain_up)
		ret = NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage4_ip4_config_timeout (device, out_failure_reason);

	return ret;
}

static NMActStageReturn
act_stage4_ip6_config_timeout (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip6;
	gboolean may_fail = FALSE, chain_up = FALSE;
	NMActStageReturn ret;

	connection = nm_device_get_applied_connection (device);
	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	may_fail = nm_setting_ip_config_get_may_fail (s_ip6);

	ret = handle_ip_config_timeout (NM_DEVICE_WIFI (device), connection, may_fail, &chain_up, out_failure_reason);
	if (chain_up)
		ret = NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage4_ip6_config_timeout (device, out_failure_reason);

	return ret;
}

static void
activation_success_handler (NMDevice *device)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	int ifindex = nm_device_get_ifindex (device);
	NMActRequest *req;

	req = nm_device_get_act_request (device);
	g_assert (req);

	/* Clear any critical protocol notification in the wifi stack */
	nm_platform_wifi_indicate_addressing_running (nm_device_get_platform (device), ifindex, FALSE);

	/* There should always be a current AP, either a fake one because we haven't
	 * seen a scan result for the activated AP yet, or a real one from the
	 * supplicant's scan list.
	 */
	g_warn_if_fail (priv->current_ap);
	if (priv->current_ap) {
		if (nm_wifi_ap_get_fake (priv->current_ap)) {
			gboolean ap_changed = FALSE;

			/* If the activation AP hasn't been seen by the supplicant in a scan
			 * yet, it will be "fake".  This usually happens for Ad-Hoc and
			 * AP-mode connections.  Fill in the details from the device itself
			 * until the supplicant sends the scan result.
			 */
			if (!nm_wifi_ap_get_address (priv->current_ap)) {
				guint8 bssid[ETH_ALEN] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
				gs_free char *bssid_str = NULL;

				if (   nm_platform_wifi_get_bssid (nm_device_get_platform (device), ifindex, bssid)
				    && nm_ethernet_address_is_valid (bssid, ETH_ALEN)) {
					bssid_str = nm_utils_hwaddr_ntoa (bssid, ETH_ALEN);
					ap_changed |= nm_wifi_ap_set_address (priv->current_ap, bssid_str);
				}
			}
			if (!nm_wifi_ap_get_freq (priv->current_ap))
				ap_changed |= nm_wifi_ap_set_freq (priv->current_ap, nm_platform_wifi_get_frequency (nm_device_get_platform (device), ifindex));
			if (!nm_wifi_ap_get_max_bitrate (priv->current_ap))
				ap_changed |= nm_wifi_ap_set_max_bitrate (priv->current_ap, nm_platform_wifi_get_rate (nm_device_get_platform (device), ifindex));

			if (ap_changed)
				_ap_dump (self, LOGL_DEBUG, priv->current_ap, "updated", 0);
		}

		nm_active_connection_set_specific_object (NM_ACTIVE_CONNECTION (req),
		                                          nm_dbus_object_get_path (NM_DBUS_OBJECT (priv->current_ap)));
	}

	periodic_update (self);

	update_seen_bssids_cache (self, priv->current_ap);

	/* Reset scan interval to something reasonable */
	priv->scan_interval = SCAN_INTERVAL_MIN + (SCAN_INTERVAL_STEP * 2);
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	gboolean clear_aps = FALSE;

	if (new_state > NM_DEVICE_STATE_ACTIVATED)
		wifi_secrets_cancel (self);

	if (new_state <= NM_DEVICE_STATE_UNAVAILABLE) {
		/* Clean up the supplicant interface because in these states the
		 * device cannot be used.
		 */
		if (priv->sup_iface)
			supplicant_interface_release (self);

		nm_clear_g_source (&priv->periodic_source_id);

		cleanup_association_attempt (self, TRUE);
		cleanup_supplicant_failures (self);
		remove_all_aps (self);
	}

	switch (new_state) {
	case NM_DEVICE_STATE_UNMANAGED:
		clear_aps = TRUE;
		break;
	case NM_DEVICE_STATE_UNAVAILABLE:
		/* If the device is enabled and the supplicant manager is ready,
		 * acquire a supplicant interface and transition to DISCONNECTED because
		 * the device is now ready to use.
		 */
		if (priv->enabled && (nm_device_get_firmware_missing (device) == FALSE)) {
			if (!priv->sup_iface)
				supplicant_interface_acquire (self);
		}
		clear_aps = TRUE;
		break;
	case NM_DEVICE_STATE_NEED_AUTH:
		if (priv->sup_iface)
			nm_supplicant_interface_disconnect (priv->sup_iface);
		break;
	case NM_DEVICE_STATE_IP_CHECK:
		/* Clear any critical protocol notification in the wifi stack */
		nm_platform_wifi_indicate_addressing_running (nm_device_get_platform (device), nm_device_get_ifindex (device), FALSE);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		activation_success_handler (device);
		break;
	case NM_DEVICE_STATE_FAILED:
		/* Clear any critical protocol notification in the wifi stack */
		nm_platform_wifi_indicate_addressing_running (nm_device_get_platform (device), nm_device_get_ifindex (device), FALSE);
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		/* Kick off a scan to get latest results */
		priv->scan_interval = SCAN_INTERVAL_MIN;
		request_wireless_scan (self, FALSE, FALSE, NULL);
		break;
	default:
		break;
	}

	if (clear_aps)
		remove_all_aps (self);
}

static gboolean
get_enabled (NMDevice *device)
{
	return NM_DEVICE_WIFI_GET_PRIVATE ((NMDeviceWifi *) device)->enabled;
}

static void
set_enabled (NMDevice *device, gboolean enabled)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMDeviceState state;

	enabled = !!enabled;

	if (priv->enabled == enabled)
		return;

	priv->enabled = enabled;

	_LOGD (LOGD_WIFI, "device now %s", enabled ? "enabled" : "disabled");

	state = nm_device_get_state (NM_DEVICE (self));
	if (state < NM_DEVICE_STATE_UNAVAILABLE) {
		_LOGD (LOGD_WIFI, "(%s): device blocked by UNMANAGED state",
		       enabled ? "enable" : "disable");
		return;
	}

	if (enabled) {
		gboolean no_firmware = FALSE;

		if (state != NM_DEVICE_STATE_UNAVAILABLE)
			_LOGW (LOGD_CORE, "not in expected unavailable state!");

		if (!nm_device_bring_up (NM_DEVICE (self), TRUE, &no_firmware)) {
			_LOGD (LOGD_WIFI, "enable blocked by failure to bring device up");

			if (no_firmware)
				nm_device_set_firmware_missing (NM_DEVICE (device), TRUE);
			else {
				/* The device sucks, or the kernel was lying to us about the killswitch state */
				priv->enabled = FALSE;
			}
			return;
		}

		/* Re-initialize the supplicant interface and wait for it to be ready */
		cleanup_supplicant_failures (self);
		if (priv->sup_iface)
			supplicant_interface_release (self);
		supplicant_interface_acquire (self);

		_LOGD (LOGD_WIFI, "enable waiting on supplicant state");
	} else {
		nm_device_state_changed (NM_DEVICE (self),
		                         NM_DEVICE_STATE_UNAVAILABLE,
		                         NM_DEVICE_STATE_REASON_NONE);
		nm_device_take_down (NM_DEVICE (self), TRUE);
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

	device_class = NM_DEVICE_CLASS (nm_device_wifi_parent_class);
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
	NMDeviceWifi *self = NM_DEVICE_WIFI (object);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	gsize i;
	char **list;

	switch (prop_id) {
	case PROP_MODE:
		g_value_set_uint (value, priv->mode);
		break;
	case PROP_BITRATE:
		g_value_set_uint (value, priv->rate);
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
		nm_dbus_utils_g_value_set_object_path (value, priv->current_ap);
		break;
	case PROP_SCANNING:
		g_value_set_boolean (value, priv->is_scanning);
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
	NMDeviceWifi *device = NM_DEVICE_WIFI (object);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);

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
nm_device_wifi_init (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	priv->mode = NM_802_11_MODE_INFRA;
	priv->aps = g_hash_table_new (nm_str_hash, g_str_equal);
}

static void
constructed (GObject *object)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (object);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	G_OBJECT_CLASS (nm_device_wifi_parent_class)->constructed (object);

	if (priv->capabilities & NM_WIFI_DEVICE_CAP_AP)
		_LOGI (LOGD_PLATFORM | LOGD_WIFI, "driver supports Access Point (AP) mode");

	/* Connect to the supplicant manager */
	priv->sup_mgr = g_object_ref (nm_supplicant_manager_get ());
}

NMDevice *
nm_device_wifi_new (const char *iface, NMDeviceWifiCapabilities capabilities)
{
	return g_object_new (NM_TYPE_DEVICE_WIFI,
	                     NM_DEVICE_IFACE, iface,
	                     NM_DEVICE_TYPE_DESC, "802.11 WiFi",
	                     NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_WIFI,
	                     NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_WIFI,
	                     NM_DEVICE_RFKILL_TYPE, RFKILL_TYPE_WLAN,
	                     NM_DEVICE_WIFI_CAPABILITIES, (guint) capabilities,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (object);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	nm_clear_g_source (&priv->periodic_source_id);

	wifi_secrets_cancel (self);

	cleanup_association_attempt (self, TRUE);
	supplicant_interface_release (self);
	cleanup_supplicant_failures (self);

	g_clear_object (&priv->sup_mgr);

	remove_all_aps (self);

	G_OBJECT_CLASS (nm_device_wifi_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (object);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	nm_assert (g_hash_table_size (priv->aps) == 0);

	g_hash_table_unref (priv->aps);

	G_OBJECT_CLASS (nm_device_wifi_parent_class)->finalize (object);
}

static void
nm_device_wifi_class_init (NMDeviceWifiClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NM_SETTING_WIRELESS_SETTING_NAME, NM_LINK_TYPE_WIFI)

	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&nm_interface_info_device_wireless);

	parent_class->can_auto_connect = can_auto_connect;
	parent_class->get_autoconnect_allowed = get_autoconnect_allowed;
	parent_class->is_available = is_available;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->check_connection_available = check_connection_available;
	parent_class->complete_connection = complete_connection;
	parent_class->get_enabled = get_enabled;
	parent_class->set_enabled = set_enabled;

	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->act_stage2_config = act_stage2_config;
	parent_class->get_configured_mtu = get_configured_mtu;
	parent_class->act_stage3_ip4_config_start = act_stage3_ip4_config_start;
	parent_class->act_stage3_ip6_config_start = act_stage3_ip6_config_start;
	parent_class->act_stage4_ip4_config_timeout = act_stage4_ip4_config_timeout;
	parent_class->act_stage4_ip6_config_timeout = act_stage4_ip6_config_timeout;
	parent_class->deactivate = deactivate;
	parent_class->deactivate_reset_hw_addr = deactivate_reset_hw_addr;
	parent_class->unmanaged_on_quit = unmanaged_on_quit;
	parent_class->can_reapply_change = can_reapply_change;

	parent_class->state_changed = device_state_changed;

	klass->scanning_prohibited = scanning_prohibited;

	obj_properties[PROP_MODE] =
	    g_param_spec_uint (NM_DEVICE_WIFI_MODE, "", "",
	                       NM_802_11_MODE_UNKNOWN,
	                       NM_802_11_MODE_AP,
	                       NM_802_11_MODE_INFRA,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_BITRATE] =
	    g_param_spec_uint (NM_DEVICE_WIFI_BITRATE, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ACCESS_POINTS] =
	    g_param_spec_boxed (NM_DEVICE_WIFI_ACCESS_POINTS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ACTIVE_ACCESS_POINT] =
	    g_param_spec_string (NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CAPABILITIES] =
	    g_param_spec_uint (NM_DEVICE_WIFI_CAPABILITIES, "", "",
	                       0, G_MAXUINT32, NM_WIFI_DEVICE_CAP_NONE,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_SCANNING] =
	    g_param_spec_boolean (NM_DEVICE_WIFI_SCANNING, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[SCANNING_PROHIBITED] =
	    g_signal_new (NM_DEVICE_WIFI_SCANNING_PROHIBITED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (NMDeviceWifiClass, scanning_prohibited),
	                  NULL, NULL, NULL,
	                  G_TYPE_BOOLEAN, 1, G_TYPE_BOOLEAN);
}
