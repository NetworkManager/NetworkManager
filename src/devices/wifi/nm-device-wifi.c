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
 * Copyright (C) 2005 - 2012 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "config.h"

#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "nm-default.h"
#include "nm-device.h"
#include "nm-device-wifi.h"
#include "nm-device-private.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-activation-request.h"
#include "nm-supplicant-manager.h"
#include "nm-supplicant-interface.h"
#include "nm-supplicant-config.h"
#include "nm-setting-connection.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"
#include "nm-setting-ip4-config.h"
#include "nm-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-platform.h"
#include "nm-auth-utils.h"
#include "nm-settings-connection.h"
#include "nm-enum-types.h"
#include "nm-wifi-enum-types.h"
#include "nm-connection-provider.h"
#include "nm-core-internal.h"

#include "nmdbus-device-wifi.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceWifi);

/* All of these are in seconds */
#define SCAN_INTERVAL_MIN 3
#define SCAN_INTERVAL_STEP 20
#define SCAN_INTERVAL_MAX 120

#define WIRELESS_SECRETS_TRIES "wireless-secrets-tries"

G_DEFINE_TYPE (NMDeviceWifi, nm_device_wifi, NM_TYPE_DEVICE)

#define NM_DEVICE_WIFI_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_WIFI, NMDeviceWifiPrivate))


enum {
	PROP_0,
	PROP_PERM_HW_ADDRESS,
	PROP_MODE,
	PROP_BITRATE,
	PROP_ACCESS_POINTS,
	PROP_ACTIVE_ACCESS_POINT,
	PROP_CAPABILITIES,
	PROP_SCANNING,

	LAST_PROP
};

enum {
	ACCESS_POINT_ADDED,
	ACCESS_POINT_REMOVED,
	SCANNING_ALLOWED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct _NMDeviceWifiPrivate {
	gint8             invalid_strength_counter;

	GHashTable *      aps;
	NMAccessPoint *   current_ap;
	guint32           rate;
	gboolean          enabled; /* rfkilled or not */

	gint32            last_scan;
	gint32            scheduled_scan_time;
	guint8            scan_interval; /* seconds */
	guint             pending_scan_id;
	guint             ap_dump_id;
	gboolean          requested_scan;

	NMSupplicantManager   *sup_mgr;
	NMSupplicantInterface *sup_iface;
	guint                  sup_timeout_id; /* supplicant association timeout */

	gboolean          ssid_found;
	NM80211Mode       mode;

	guint32           failed_link_count;
	guint             periodic_source_id;
	guint             link_timeout_id;

	NMDeviceWifiCapabilities capabilities;
};

static gboolean check_scanning_allowed (NMDeviceWifi *self);

static void schedule_scan (NMDeviceWifi *self, gboolean backoff);

static void cancel_pending_scan (NMDeviceWifi *self);

static void cleanup_association_attempt (NMDeviceWifi * self,
                                         gboolean disconnect);

static void supplicant_iface_state_cb (NMSupplicantInterface *iface,
                                       guint32 new_state,
                                       guint32 old_state,
                                       int disconnect_reason,
                                       gpointer user_data);

static void supplicant_iface_new_bss_cb (NMSupplicantInterface * iface,
                                         const char *object_path,
                                         GVariant *properties,
                                         NMDeviceWifi * self);

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

static void supplicant_iface_notify_scanning_cb (NMSupplicantInterface * iface,
                                                 GParamSpec * pspec,
                                                 NMDeviceWifi * self);

static void supplicant_iface_notify_current_bss (NMSupplicantInterface *iface,
                                                 GParamSpec *pspec,
                                                 NMDeviceWifi *self);

static void request_wireless_scan (NMDeviceWifi *self, GVariant *scan_options);

static void emit_ap_added_removed (NMDeviceWifi *self,
                                   guint signum,
                                   NMAccessPoint *ap,
                                   gboolean recheck_available_connections);

static void remove_supplicant_interface_error_handler (NMDeviceWifi *self);

/*****************************************************************/

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	GObjectClass *klass;
	NMDeviceWifi *self;
	NMDeviceWifiPrivate *priv;

	klass = G_OBJECT_CLASS (nm_device_wifi_parent_class);
	object = klass->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	self = NM_DEVICE_WIFI (object);
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (!nm_platform_wifi_get_capabilities (NM_PLATFORM_GET,
	                                        nm_device_get_ifindex (NM_DEVICE (self)),
	                                        &priv->capabilities)) {
		_LOGW (LOGD_HW | LOGD_WIFI, "failed to initialize WiFi driver");
		g_object_unref (object);
		return NULL;
	}

	if (priv->capabilities & NM_WIFI_DEVICE_CAP_AP)
		_LOGI (LOGD_HW | LOGD_WIFI, "driver supports Access Point (AP) mode");

	/* Connect to the supplicant manager */
	priv->sup_mgr = g_object_ref (nm_supplicant_manager_get ());

	return object;
}

static gboolean
supplicant_interface_acquire (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	g_return_val_if_fail (self != NULL, FALSE);
	/* interface already acquired? */
	g_return_val_if_fail (priv->sup_iface == NULL, TRUE);

	priv->sup_iface = nm_supplicant_manager_iface_get (priv->sup_mgr,
	                                                   nm_device_get_iface (NM_DEVICE (self)),
	                                                   TRUE);
	if (priv->sup_iface == NULL) {
		_LOGE (LOGD_WIFI, "Couldn't initialize supplicant interface");
		return FALSE;
	}

	if (nm_supplicant_interface_get_state (priv->sup_iface) < NM_SUPPLICANT_INTERFACE_STATE_READY)
		nm_device_add_pending_action (NM_DEVICE (self), "waiting for supplicant", FALSE);

	g_signal_connect (priv->sup_iface,
	                  NM_SUPPLICANT_INTERFACE_STATE,
	                  G_CALLBACK (supplicant_iface_state_cb),
	                  self);
	g_signal_connect (priv->sup_iface,
	                  NM_SUPPLICANT_INTERFACE_NEW_BSS,
	                  G_CALLBACK (supplicant_iface_new_bss_cb),
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
	                  "notify::scanning",
	                  G_CALLBACK (supplicant_iface_notify_scanning_cb),
	                  self);
	g_signal_connect (priv->sup_iface,
	                  "notify::" NM_SUPPLICANT_INTERFACE_CURRENT_BSS,
	                  G_CALLBACK (supplicant_iface_notify_current_bss),
	                  self);

	return TRUE;
}

static void
supplicant_interface_release (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;

	g_return_if_fail (self != NULL);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	cancel_pending_scan (self);

	/* Reset the scan interval to be pretty frequent when disconnected */
	priv->scan_interval = SCAN_INTERVAL_MIN + SCAN_INTERVAL_STEP;
	_LOGD (LOGD_WIFI_SCAN, "reset scanning interval to %d seconds",
	       priv->scan_interval);

	nm_clear_g_source (&priv->ap_dump_id);

	if (priv->sup_iface) {
		remove_supplicant_interface_error_handler (self);

		/* Clear supplicant interface signal handlers */
		g_signal_handlers_disconnect_by_data (priv->sup_iface, self);

		/* Tell the supplicant to disconnect from the current AP */
		nm_supplicant_interface_disconnect (priv->sup_iface);

		nm_supplicant_manager_iface_release (priv->sup_mgr, priv->sup_iface);
		priv->sup_iface = NULL;
	}
}

static NMAccessPoint *
get_ap_by_path (NMDeviceWifi *self, const char *path)
{
	g_return_val_if_fail (path != NULL, NULL);
	return g_hash_table_lookup (NM_DEVICE_WIFI_GET_PRIVATE (self)->aps, path);

}

static NMAccessPoint *
get_ap_by_supplicant_path (NMDeviceWifi *self, const char *path)
{
	GHashTableIter iter;
	NMAccessPoint *ap;

	g_return_val_if_fail (path != NULL, NULL);

	g_hash_table_iter_init (&iter, NM_DEVICE_WIFI_GET_PRIVATE (self)->aps);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &ap)) {
		if (g_strcmp0 (path, nm_ap_get_supplicant_path (ap)) == 0)
			return ap;
	}
	return NULL;
}

static void
update_seen_bssids_cache (NMDeviceWifi *self, NMAccessPoint *ap)
{
	NMConnection *connection;

	g_return_if_fail (NM_IS_DEVICE_WIFI (self));

	if (ap == NULL)
		return;

	/* Don't cache the BSSID for Ad-Hoc APs */
	if (nm_ap_get_mode (ap) != NM_802_11_MODE_INFRA)
		return;

	if (nm_device_get_state (NM_DEVICE (self)) == NM_DEVICE_STATE_ACTIVATED) {
		connection = nm_device_get_connection (NM_DEVICE (self));
		if (connection) {
			nm_settings_connection_add_seen_bssid (NM_SETTINGS_CONNECTION (connection),
			                                       nm_ap_get_address (ap));
		}
	}
}

static void
set_current_ap (NMDeviceWifi *self, NMAccessPoint *new_ap, gboolean recheck_available_connections, gboolean force_remove_old_ap)
{
	NMDeviceWifiPrivate *priv;
	NMAccessPoint *old_ap;

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
		NM80211Mode mode = nm_ap_get_mode (old_ap);

		if (force_remove_old_ap || mode == NM_802_11_MODE_ADHOC || mode == NM_802_11_MODE_AP || nm_ap_get_fake (old_ap)) {
			emit_ap_added_removed (self, ACCESS_POINT_REMOVED, old_ap, FALSE);
			g_hash_table_remove (priv->aps, nm_exported_object_get_path (NM_EXPORTED_OBJECT (old_ap)));
			if (recheck_available_connections)
				nm_device_recheck_available_connections (NM_DEVICE (self));
		}
		g_object_unref (old_ap);
	}

	g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT);
}

static void
periodic_update (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	int ifindex = nm_device_get_ifindex (NM_DEVICE (self));
	guint32 new_rate;
	int percent;
	NMDeviceState state;
	guint32 supplicant_state;

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
		percent = nm_platform_wifi_get_quality (NM_PLATFORM_GET, ifindex);
		if (percent >= 0 || ++priv->invalid_strength_counter > 3) {
			nm_ap_set_strength (priv->current_ap, (gint8) percent);
			priv->invalid_strength_counter = 0;
		}
	}

	new_rate = nm_platform_wifi_get_rate (NM_PLATFORM_GET, ifindex);
	if (new_rate != priv->rate) {
		priv->rate = new_rate;
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_BITRATE);
	}
}

static gboolean
periodic_update_cb (gpointer user_data)
{
	periodic_update (NM_DEVICE_WIFI (user_data));
	return TRUE;
}

static void
setup (NMDevice *device, NMPlatformLink *plink)
{
	NM_DEVICE_CLASS (nm_device_wifi_parent_class)->setup (device, plink);

	g_object_notify (G_OBJECT (device), NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS);
}

static gboolean
bring_up (NMDevice *device, gboolean *no_firmware)
{
	if (!NM_DEVICE_WIFI_GET_PRIVATE (device)->enabled)
		return FALSE;

	return NM_DEVICE_CLASS (nm_device_wifi_parent_class)->bring_up (device, no_firmware);
}

static void
emit_ap_added_removed (NMDeviceWifi *self,
                       guint signum,
                       NMAccessPoint *ap,
                       gboolean recheck_available_connections)
{
	g_signal_emit (self, signals[signum], 0, ap);
	g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_ACCESS_POINTS);
	nm_device_emit_recheck_auto_activate (NM_DEVICE (self));
	if (recheck_available_connections)
		nm_device_recheck_available_connections (NM_DEVICE (self));
}

static void
remove_all_aps (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	GHashTableIter iter;
	NMAccessPoint *ap;

	if (g_hash_table_size (priv->aps)) {
		set_current_ap (self, NULL, FALSE, FALSE);

		g_hash_table_iter_init (&iter, priv->aps);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer) &ap)) {
			emit_ap_added_removed (self, ACCESS_POINT_REMOVED, ap, FALSE);
			g_hash_table_iter_remove (&iter);
		}
		nm_device_recheck_available_connections (NM_DEVICE (self));
	}
}

static void
deactivate (NMDevice *device)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	int ifindex = nm_device_get_ifindex (device);
	NMConnection *connection;
	NM80211Mode old_mode = priv->mode;

	connection = nm_device_get_connection (device);
	if (connection) {
		/* Clear wireless secrets tries when deactivating */
		g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, NULL);
	}

	if (priv->periodic_source_id) {
		g_source_remove (priv->periodic_source_id);
		priv->periodic_source_id = 0;
	}

	cleanup_association_attempt (self, TRUE);

	priv->rate = 0;

	/* If the AP is 'fake', i.e. it wasn't actually found from
	 * a scan but the user tried to connect to it manually (maybe it
	 * was non-broadcasting or something) get rid of it, because 'fake'
	 * APs should only live for as long as we're connected to them.
	 **/
	set_current_ap (self, NULL, TRUE, FALSE);

	/* Clear any critical protocol notification in the Wi-Fi stack */
	nm_platform_wifi_indicate_addressing_running (NM_PLATFORM_GET, ifindex, FALSE);

	/* Reset MAC address back to initial address */
	if (nm_device_get_initial_hw_address (device))
		nm_device_set_hw_addr (device, nm_device_get_initial_hw_address (device), "reset", LOGD_WIFI);

	nm_platform_wifi_set_powersave (NM_PLATFORM_GET, ifindex, 0);

	/* Ensure we're in infrastructure mode after deactivation; some devices
	 * (usually older ones) don't scan well in adhoc mode.
	 */
	if (nm_platform_wifi_get_mode (NM_PLATFORM_GET, ifindex) != NM_802_11_MODE_INFRA) {
		nm_device_take_down (NM_DEVICE (self), TRUE);
		nm_platform_wifi_set_mode (NM_PLATFORM_GET, ifindex, NM_802_11_MODE_INFRA);
		nm_device_bring_up (NM_DEVICE (self), TRUE, NULL);
	}

	if (priv->mode != NM_802_11_MODE_INFRA) {
		priv->mode = NM_802_11_MODE_INFRA;
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_MODE);
	}

	/* Ensure we trigger a scan after deactivating a Hotspot */
	if (old_mode == NM_802_11_MODE_AP) {
		cancel_pending_scan (self);
		request_wireless_scan (self, NULL);
	}
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
			if (nm_supplicant_interface_get_ap_support (priv->sup_iface) == AP_SUPPORT_NO)
				return FALSE;
		}
	}

	// FIXME: check channel/freq/band against bands the hardware supports
	// FIXME: check encryption against device capabilities
	// FIXME: check bitrate against device capabilities

	return TRUE;
}

static NMAccessPoint *
find_first_compatible_ap (NMDeviceWifi *self,
                          NMConnection *connection,
                          gboolean allow_unstable_order)
{
	GHashTableIter iter;
	NMAccessPoint *ap;
	NMAccessPoint *cand_ap = NULL;

	g_return_val_if_fail (connection != NULL, NULL);

	g_hash_table_iter_init (&iter, NM_DEVICE_WIFI_GET_PRIVATE (self)->aps);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &ap)) {
		if (!nm_ap_check_compatible (ap, connection))
			continue;
		if (allow_unstable_order)
			return ap;
		if (!cand_ap || (nm_ap_get_id (cand_ap) < nm_ap_get_id (ap)))
			cand_ap = ap;
	}
	return cand_ap;
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object)
{
	NMSettingWireless *s_wifi;
	const char *mode;

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wifi, FALSE);

	/* a connection that is available for a certain @specific_object, MUST
	 * also be available in general (without @specific_object). */

	if (specific_object) {
		NMAccessPoint *ap;

		ap = get_ap_by_path (NM_DEVICE_WIFI (device), specific_object);
		return ap ? nm_ap_check_compatible (ap, connection) : FALSE;
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
	return !!find_first_compatible_ap (NM_DEVICE_WIFI (device), connection, TRUE);
}

/*
 * List of manufacturer default SSIDs that are often unchanged by users.
 *
 * NOTE: this list should *not* contain networks that you would like to
 * automatically roam to like "Starbucks" or "AT&T" or "T-Mobile HotSpot".
 */
static const char *
manf_defaults[] = {
	"linksys",
	"linksys-a",
	"linksys-g",
	"default",
	"belkin54g",
	"NETGEAR",
	"o2DSL",
	"WLAN",
	"ALICE-WLAN",
	"Speedport W 501V",
};

#define ARRAY_SIZE(a)  (sizeof (a) / sizeof (a[0]))

static gboolean
is_manf_default_ssid (const GByteArray *ssid)
{
	int i;

	for (i = 0; i < ARRAY_SIZE (manf_defaults); i++) {
		if (ssid->len == strlen (manf_defaults[i])) {
			if (memcmp (manf_defaults[i], ssid->data, ssid->len) == 0)
				return TRUE;
		}
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
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSetting8021x *s_8021x;
	const char *setting_mac;
	char *str_ssid = NULL;
	NMAccessPoint *ap = NULL;
	const GByteArray *ssid = NULL;
	GByteArray *tmp_ssid = NULL;
	GBytes *setting_ssid = NULL;
	gboolean hidden = FALSE;
	const char *perm_hw_addr;

	s_wifi = nm_connection_get_setting_wireless (connection);
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	s_8021x = nm_connection_get_setting_802_1x (connection);

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
		ap = find_first_compatible_ap (self, connection, FALSE);

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
		ssid = nm_ap_get_ssid (ap);
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
		if (!nm_ap_complete_connection (ap,
		                                connection,
		                                is_manf_default_ssid (ssid),
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

	nm_utils_complete_generic (connection,
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
	guint32 state;

	if (!priv->enabled)
		return FALSE;

	if (!priv->sup_iface)
		return FALSE;

	state = nm_supplicant_interface_get_state (priv->sup_iface);
	if (   state < NM_SUPPLICANT_INTERFACE_STATE_READY
	    || state > NM_SUPPLICANT_INTERFACE_STATE_COMPLETED)
		return FALSE;

	return TRUE;
}

static gboolean
can_auto_connect (NMDevice *device,
                  NMConnection *connection,
                  char **specific_object)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMAccessPoint *ap;
	const char *method = NULL;
	guint64 timestamp = 0;

	if (!NM_DEVICE_CLASS (nm_device_wifi_parent_class)->can_auto_connect (device, connection, specific_object))
		return FALSE;

	/* Don't autoconnect to networks that have been tried at least once
	 * but haven't been successful, since these are often accidental choices
	 * from the menu and the user may not know the password.
	 */
	if (nm_settings_connection_get_timestamp (NM_SETTINGS_CONNECTION (connection), &timestamp)) {
		if (timestamp == 0)
			return FALSE;
	}

	/* Use the connection if it's a shared connection */
	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
		return TRUE;

	ap = find_first_compatible_ap (self, connection, FALSE);
	if (ap) {
		/* All good; connection is usable */
		*specific_object = (char *) nm_exported_object_get_path (NM_EXPORTED_OBJECT (ap));
		return TRUE;
	}

	return FALSE;
}

static gint
ap_id_compare (NMAccessPoint *a, NMAccessPoint *b)
{
	guint32 a_id = nm_ap_get_id (a);
	guint32 b_id = nm_ap_get_id (b);

	return a_id < b_id ? -1 : (a_id == b_id ? 0 : 1);
}

static GSList *
get_sorted_ap_list (NMDeviceWifi *self)
{
	GSList *sorted = NULL;
	GHashTableIter iter;
	NMAccessPoint *ap;

	g_hash_table_iter_init (&iter, NM_DEVICE_WIFI_GET_PRIVATE (self)->aps);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &ap))
		sorted = g_slist_prepend (sorted, ap);
	return g_slist_sort (sorted, (GCompareFunc) ap_id_compare);
}

static void
impl_device_wifi_get_access_points (NMDeviceWifi *self,
                                    GDBusMethodInvocation *context)
{
	GSList *sorted, *iter;
	GPtrArray *paths;

	paths = g_ptr_array_new ();
	sorted = get_sorted_ap_list (self);
	for (iter = sorted; iter; iter = iter->next) {
		NMAccessPoint *ap = NM_AP (iter->data);

		if (nm_ap_get_ssid (ap))
			g_ptr_array_add (paths, g_strdup (nm_exported_object_get_path (NM_EXPORTED_OBJECT (ap))));
	}
	g_ptr_array_add (paths, NULL);
	g_slist_free (sorted);

	g_dbus_method_invocation_return_value (context, g_variant_new ("(^ao)", (char **) paths->pdata));
	g_ptr_array_unref (paths);
}

static void
impl_device_wifi_get_all_access_points (NMDeviceWifi *self,
                                        GDBusMethodInvocation *context)
{
	GSList *sorted, *iter;
	GPtrArray *paths;

	paths = g_ptr_array_new ();
	sorted = get_sorted_ap_list (self);
	for (iter = sorted; iter; iter = iter->next)
		g_ptr_array_add (paths, g_strdup (nm_exported_object_get_path (NM_EXPORTED_OBJECT (iter->data))));
	g_ptr_array_add (paths, NULL);
	g_slist_free (sorted);

	g_dbus_method_invocation_return_value (context, g_variant_new ("(^ao)", (char **) paths->pdata));
	g_ptr_array_unref (paths);
}

static void
request_scan_cb (NMDevice *device,
                 GDBusMethodInvocation *context,
                 NMAuthSubject *subject,
                 GError *error,
                 gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	gs_unref_variant GVariant *new_scan_options = user_data;

	if (error) {
		g_dbus_method_invocation_return_gerror (context, error);
		return;
	}

	if (!check_scanning_allowed (self)) {
		g_dbus_method_invocation_return_error_literal (context,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_ALLOWED,
		                                               "Scanning not allowed at this time");
		return;
	}

	cancel_pending_scan (self);
	request_wireless_scan (self, new_scan_options);
	g_dbus_method_invocation_return_value (context, NULL);
}

static void
impl_device_wifi_request_scan (NMDeviceWifi *self,
                               GDBusMethodInvocation *context,
                               GVariant *options)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	gint32 last_scan;

	if (   !priv->enabled
	    || !priv->sup_iface
	    || nm_device_get_state (device) < NM_DEVICE_STATE_DISCONNECTED
	    || nm_device_is_activating (device)) {
		g_dbus_method_invocation_return_error_literal (context,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_ALLOWED,
		                                               "Scanning not allowed while unavailable or activating");
		return;
	}

	if (nm_supplicant_interface_get_scanning (priv->sup_iface)) {
		g_dbus_method_invocation_return_error_literal (context,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_ALLOWED,
		                                               "Scanning not allowed while already scanning");
		return;
	}

	last_scan = nm_supplicant_interface_get_last_scan_time (priv->sup_iface);
	if (last_scan && (nm_utils_get_monotonic_timestamp_s () - last_scan) < 10) {
		g_dbus_method_invocation_return_error_literal (context,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_ALLOWED,
		                                               "Scanning not allowed immediately following previous scan");
		return;
	}

	/* Ask the manager to authenticate this request for us */
	g_signal_emit_by_name (device,
	                       NM_DEVICE_AUTH_REQUEST,
	                       context,
	                       NULL,
	                       NM_AUTH_PERMISSION_NETWORK_CONTROL,
	                       TRUE,
	                       request_scan_cb,
	                       options ? g_variant_ref (options) : NULL);
}

static gboolean
scanning_allowed (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	guint32 sup_state;
	NMConnection *connection;

	g_return_val_if_fail (priv->sup_iface != NULL, FALSE);

	/* Scanning not done in AP mode */
	if (priv->mode == NM_802_11_MODE_AP)
		return FALSE;

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
		/* Don't scan when unusable or activating */
		return FALSE;
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_FAILED:
		/* Can always scan when disconnected */
		return TRUE;
	case NM_DEVICE_STATE_ACTIVATED:
		/* Need to do further checks when activated */
		break;
	}

	/* Don't scan if the supplicant is busy */
	sup_state = nm_supplicant_interface_get_state (priv->sup_iface);
	if (   sup_state == NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING
	    || sup_state == NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED
	    || sup_state == NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE
	    || sup_state == NM_SUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE
	    || nm_supplicant_interface_get_scanning (priv->sup_iface))
		return FALSE;

	connection = nm_device_get_connection (NM_DEVICE (self));
	if (connection) {
		NMSettingWireless *s_wifi;
		const char *ip4_method = NULL;

		/* Don't scan when a shared connection is active; it makes drivers mad */
		ip4_method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);

		if (!strcmp (ip4_method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
			return FALSE;

		/* Don't scan when the connection is locked to a specifc AP, since
		 * intra-ESS roaming (which requires periodic scanning) isn't being
		 * used due to the specific AP lock. (bgo #513820)
		 */
		s_wifi = nm_connection_get_setting_wireless (connection);
		g_assert (s_wifi);
		if (nm_setting_wireless_get_bssid (s_wifi))
			return FALSE;
	}

	return TRUE;
}

static gboolean
scanning_allowed_accumulator (GSignalInvocationHint *ihint,
                              GValue *return_accu,
                              const GValue *handler_return,
                              gpointer data)
{
	if (!g_value_get_boolean (handler_return))
		g_value_set_boolean (return_accu, FALSE);
	return TRUE;
}

static gboolean
check_scanning_allowed (NMDeviceWifi *self)
{
	GValue instance = G_VALUE_INIT;
	GValue retval = G_VALUE_INIT;

	g_value_init (&instance, G_TYPE_OBJECT);
	g_value_take_object (&instance, self);

	g_value_init (&retval, G_TYPE_BOOLEAN);
	g_value_set_boolean (&retval, TRUE);

	/* Use g_signal_emitv() rather than g_signal_emit() to avoid the return
	 * value being changed if no handlers are connected */
	g_signal_emitv (&instance, signals[SCANNING_ALLOWED], 0, &retval);

	return g_value_get_boolean (&retval);
}

static gboolean
hidden_filter_func (NMConnectionProvider *provider,
                    NMConnection *connection,
                    gpointer user_data)
{
	NMSettingWireless *s_wifi;

	s_wifi = (NMSettingWireless *) nm_connection_get_setting_wireless (connection);
	return s_wifi ? nm_setting_wireless_get_hidden (s_wifi) : FALSE;
}

static GPtrArray *
build_hidden_probe_list (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	guint max_scan_ssids = nm_supplicant_interface_get_max_scan_ssids (priv->sup_iface);
	GSList *connections, *iter;
	GPtrArray *ssids = NULL;
	static GByteArray *nullssid = NULL;

	/* Need at least two: wildcard SSID and one or more hidden SSIDs */
	if (max_scan_ssids < 2)
		return NULL;

	/* Static wildcard SSID used for every scan */
	if (G_UNLIKELY (nullssid == NULL))
		nullssid = g_byte_array_new ();

	connections = nm_connection_provider_get_best_connections (nm_connection_provider_get (),
	                                                           max_scan_ssids - 1,
	                                                           NM_SETTING_WIRELESS_SETTING_NAME,
	                                                           NULL,
	                                                           hidden_filter_func,
	                                                           NULL);
	if (connections && connections->data) {
		ssids = g_ptr_array_new_full (max_scan_ssids - 1, (GDestroyNotify) g_byte_array_unref);
		g_ptr_array_add (ssids, g_byte_array_ref (nullssid));  /* Add wildcard SSID */
	}

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = iter->data;
		NMSettingWireless *s_wifi;
		GBytes *ssid;
		GByteArray *ssid_array;

		s_wifi = (NMSettingWireless *) nm_connection_get_setting_wireless (connection);
		g_assert (s_wifi);
		ssid = nm_setting_wireless_get_ssid (s_wifi);
		g_assert (ssid);
		ssid_array = g_byte_array_new ();
		g_byte_array_append (ssid_array,
		                     g_bytes_get_data (ssid, NULL),
		                     g_bytes_get_size (ssid));
		g_ptr_array_add (ssids, ssid_array);
	}
	g_slist_free (connections);

	return ssids;
}

static GPtrArray *
ssids_options_to_ptrarray (GVariant *value)
{
	GPtrArray *ssids = NULL;
	GByteArray *ssid_array;
	GVariant *v;
	const guint8 *bytes;
	gsize len;
	int num_ssids, i;

	num_ssids = g_variant_n_children (value);
	if (num_ssids) {
		ssids = g_ptr_array_new_full (num_ssids, (GDestroyNotify) g_byte_array_unref);
		for (i = 0; i < num_ssids; i++) {
			v = g_variant_get_child_value (value, i);
			bytes = g_variant_get_fixed_array (v, &len, sizeof (guint8));
			ssid_array = g_byte_array_new ();
			g_byte_array_append (ssid_array, bytes, len);
			g_ptr_array_add (ssids, ssid_array);
		}
	}
	return ssids;
}

static void
request_wireless_scan (NMDeviceWifi *self, GVariant *scan_options)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	gboolean backoff = FALSE;
	GPtrArray *ssids = NULL;

	if (priv->requested_scan) {
		/* There's already a scan in progress */
		return;
	}

	if (check_scanning_allowed (self)) {
		_LOGD (LOGD_WIFI_SCAN, "scanning requested");

		if (scan_options) {
			GVariant *val = g_variant_lookup_value (scan_options, "ssids", NULL);

			if (val) {
				if (g_variant_is_of_type (val, G_VARIANT_TYPE ("aay")))
					ssids = ssids_options_to_ptrarray (val);
				else
					_LOGD (LOGD_WIFI_SCAN, "ignoring invalid 'ssids' scan option");
				g_variant_unref (val);
			}
		}
		if (!ssids)
			ssids = build_hidden_probe_list (self);

		if (nm_logging_enabled (LOGL_DEBUG, LOGD_WIFI_SCAN)) {
			if (ssids) {
				const GByteArray *ssid;
				guint i;
				char *foo;

				for (i = 0; i < ssids->len; i++) {
					ssid = g_ptr_array_index (ssids, i);
					foo = ssid->len > 0
					      ? nm_utils_ssid_to_utf8 (ssid->data, ssid->len)
					      : NULL;
					_LOGD (LOGD_WIFI_SCAN, "(%d) probe scanning SSID '%s'",
					            i, foo ? foo : "<hidden>");
					g_free (foo);
				}
			} else
				_LOGD (LOGD_WIFI_SCAN, "no SSIDs to probe scan");
		}

		if (nm_supplicant_interface_request_scan (priv->sup_iface, ssids)) {
			/* success */
			backoff = TRUE;
			priv->requested_scan = TRUE;
			nm_device_add_pending_action (NM_DEVICE (self), "scan", TRUE);
		}

		if (ssids)
			g_ptr_array_unref (ssids);
	} else
		_LOGD (LOGD_WIFI_SCAN, "scan requested but not allowed at this time");

	priv->pending_scan_id = 0;
	schedule_scan (self, backoff);
}

static gboolean
request_wireless_scan_periodic (gpointer user_data)
{
	request_wireless_scan (user_data, NULL);
	return FALSE;
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
			cancel_pending_scan (self);
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

		_LOGD (LOGD_WIFI_SCAN, "scheduled scan in %d seconds (interval now %d seconds)",
		       next_scan, priv->scan_interval);
	}
}


static void
cancel_pending_scan (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->pending_scan_id) {
		g_source_remove (priv->pending_scan_id);
		priv->pending_scan_id = 0;
	}
}

static void
supplicant_iface_scan_done_cb (NMSupplicantInterface *iface,
                               gboolean success,
                               NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	_LOGD (LOGD_WIFI_SCAN, "scan %s", success ? "successful" : "failed");

	priv->last_scan = nm_utils_get_monotonic_timestamp_s ();
	schedule_scan (self, success);

	if (priv->requested_scan) {
		priv->requested_scan = FALSE;
		nm_device_remove_pending_action (NM_DEVICE (self), "scan", TRUE);
	}
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
	GSList *sorted, *iter;

	priv->ap_dump_id = 0;
	_LOGD (LOGD_WIFI_SCAN, "APs: [now:%u last:%u next:%u]",
	       nm_utils_get_monotonic_timestamp_s (),
	       priv->last_scan,
	       priv->scheduled_scan_time);
	sorted = get_sorted_ap_list (self);
	for (iter = sorted; iter; iter = iter->next)
		nm_ap_dump (NM_AP (iter->data), "  ", nm_device_get_iface (NM_DEVICE (self)));
	g_slist_free (sorted);
	return G_SOURCE_REMOVE;
}

static void
schedule_ap_list_dump (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (!nm_logging_enabled (LOGL_DEBUG, LOGD_WIFI_SCAN))
		return;
	nm_clear_g_source (&priv->ap_dump_id);
	priv->ap_dump_id = g_timeout_add_seconds (1, ap_list_dump, self);
}

static void
try_fill_ssid_for_hidden_ap (NMAccessPoint *ap)
{
	const char *bssid;
	const GSList *connections, *iter;

	g_return_if_fail (nm_ap_get_ssid (ap) == NULL);

	bssid = nm_ap_get_address (ap);
	g_assert (bssid);

	/* Look for this AP's BSSID in the seen-bssids list of a connection,
	 * and if a match is found, copy over the SSID */
	connections = nm_connection_provider_get_connections (nm_connection_provider_get ());
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingWireless *s_wifi;

		s_wifi = nm_connection_get_setting_wireless (connection);
		if (s_wifi) {
			if (nm_settings_connection_has_seen_bssid (NM_SETTINGS_CONNECTION (connection), bssid)) {
				GBytes *ssid = nm_setting_wireless_get_ssid (s_wifi);

				nm_ap_set_ssid (ap,
				                g_bytes_get_data (ssid, NULL),
				                g_bytes_get_size (ssid));
				break;
			}
		}
	}
}

static void
supplicant_iface_new_bss_cb (NMSupplicantInterface *iface,
                             const char *object_path,
                             GVariant *properties,
                             NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMDeviceState state;
	NMAccessPoint *ap;
	NMAccessPoint *found_ap = NULL;
	const GByteArray *ssid;
	const char *bssid, *ap_path;

	g_return_if_fail (self != NULL);
	g_return_if_fail (properties != NULL);
	g_return_if_fail (iface != NULL);

	/* Ignore new APs when unavailable, unmanaged, or in AP mode */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state <= NM_DEVICE_STATE_UNAVAILABLE)
		return;
	if (NM_DEVICE_WIFI_GET_PRIVATE (self)->mode == NM_802_11_MODE_AP)
		return;

	ap = nm_ap_new_from_properties (object_path, properties);
	if (!ap) {
		_LOGW (LOGD_WIFI_SCAN, "invalid AP properties received");
		return;
	}

	/* Let the manager try to fill in the SSID from seen-bssids lists */
	bssid = nm_ap_get_address (ap);
	ssid = nm_ap_get_ssid (ap);
	if (!ssid || nm_utils_is_empty_ssid (ssid->data, ssid->len)) {
		/* Try to fill the SSID from the AP database */
		try_fill_ssid_for_hidden_ap (ap);

		ssid = nm_ap_get_ssid (ap);
		if (ssid && (nm_utils_is_empty_ssid (ssid->data, ssid->len) == FALSE)) {
			/* Yay, matched it, no longer treat as hidden */
			_LOGD (LOGD_WIFI_SCAN, "matched hidden AP %s => '%s'",
			       str_if_set (bssid, "(none)"), nm_utils_escape_ssid (ssid->data, ssid->len));
		} else {
			/* Didn't have an entry for this AP in the database */
			_LOGD (LOGD_WIFI_SCAN, "failed to match hidden AP %s",
			       str_if_set (bssid, "(none)"));
		}
	}

	found_ap = get_ap_by_supplicant_path (self, object_path);
	if (found_ap) {
		nm_ap_dump (ap, "updated ", nm_device_get_iface (NM_DEVICE (self)));
		nm_ap_update_from_properties (found_ap, object_path, properties);
	} else {
		nm_ap_dump (ap, "added   ", nm_device_get_iface (NM_DEVICE (self)));
		ap_path = nm_exported_object_export (NM_EXPORTED_OBJECT (ap));
		g_hash_table_insert (priv->aps, (gpointer) ap_path, g_object_ref (ap));
		emit_ap_added_removed (self, ACCESS_POINT_ADDED, ap, TRUE);
	}

	g_object_unref (ap);

	/* Update the current AP if the supplicant notified a current BSS change
	 * before it sent the current BSS's scan result.
	 */
	if (g_strcmp0 (nm_supplicant_interface_get_current_bss (iface), object_path) == 0)
		supplicant_iface_notify_current_bss (priv->sup_iface, NULL, self);

	schedule_ap_list_dump (self);
}

static void
supplicant_iface_bss_updated_cb (NMSupplicantInterface *iface,
                                 const char *object_path,
                                 GVariant *properties,
                                 NMDeviceWifi *self)
{
	NMDeviceState state;
	NMAccessPoint *ap;

	g_return_if_fail (self != NULL);
	g_return_if_fail (object_path != NULL);
	g_return_if_fail (properties != NULL);

	/* Ignore new APs when unavailable or unmanaged */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state <= NM_DEVICE_STATE_UNAVAILABLE)
		return;

	ap = get_ap_by_supplicant_path (self, object_path);
	if (ap) {
		nm_ap_dump (ap, "updated ", nm_device_get_iface (NM_DEVICE (self)));
		nm_ap_update_from_properties (ap, object_path, properties);
		schedule_ap_list_dump (self);
	}
}

static void
supplicant_iface_bss_removed_cb (NMSupplicantInterface *iface,
                                 const char *object_path,
                                 NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;
	NMAccessPoint *ap;

	g_return_if_fail (self != NULL);
	g_return_if_fail (object_path != NULL);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	ap = get_ap_by_supplicant_path (self, object_path);
	if (ap) {
		if (ap == priv->current_ap) {
			/* The current AP cannot be removed (to prevent NM indicating that
			 * it is connected, but to nothing), but it must be removed later
			 * when the current AP is changed or cleared.  Set 'fake' to
			 * indicate that this AP is now unknown to the supplicant.
			 */
			nm_ap_set_fake (ap, TRUE);
		} else {
			nm_ap_dump (ap, "removed ", nm_device_get_iface (NM_DEVICE (self)));
			emit_ap_added_removed (self, ACCESS_POINT_REMOVED, ap, TRUE);
			g_hash_table_remove (priv->aps, nm_exported_object_get_path (NM_EXPORTED_OBJECT (ap)));
			schedule_ap_list_dump (self);
		}
	}
}

static void
remove_supplicant_timeouts (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->sup_timeout_id) {
		g_source_remove (priv->sup_timeout_id);
		priv->sup_timeout_id = 0;
	}

	if (priv->link_timeout_id) {
		g_source_remove (priv->link_timeout_id);
		priv->link_timeout_id = 0;
	}
}

static void
cleanup_association_attempt (NMDeviceWifi *self, gboolean disconnect)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	remove_supplicant_interface_error_handler (self);
	remove_supplicant_timeouts (self);
	if (disconnect && priv->sup_iface)
		nm_supplicant_interface_disconnect (priv->sup_iface);
}

static void
wifi_secrets_cb (NMActRequest *req,
                 NMActRequestGetSecretsCallId call_id,
                 NMConnection *connection,
                 GError *error,
                 gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);

	g_return_if_fail (req == nm_device_get_act_request (device));
	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);
	g_return_if_fail (nm_act_request_get_connection (req) == connection);

	if (error) {
		_LOGW (LOGD_WIFI, "%s", error->message);
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_NO_SECRETS);
	} else
		nm_device_activate_schedule_stage1_device_prepare (device);
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

	/* If the access point failed, and wasn't found by the supplicant when it
	 * attempted to reconnect, then it's probably out of range or turned off.
	 * Remove it from the list and if it's actually still present, it'll be
	 * found in the next scan.
	 */
	if (priv->ssid_found == FALSE && priv->current_ap)
		set_current_ap (self, NULL, TRUE, TRUE);

	nm_device_state_changed (device,
	                         NM_DEVICE_STATE_FAILED,
	                         priv->ssid_found ? NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT :
	                                            NM_DEVICE_STATE_REASON_SSID_NOT_FOUND);
	return FALSE;
}

static gboolean
need_new_8021x_secrets (NMDeviceWifi *self,
                        guint32 old_state,
                        const char **setting_name)
{
	NMSetting8021x *s_8021x;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;
	NMConnection *connection;

	g_assert (setting_name != NULL);

	connection = nm_device_get_connection (NM_DEVICE (self));
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
                  guint32 old_state,
                  const char **setting_name)
{
	NMSettingWirelessSecurity *s_wsec;
	NMConnection *connection;
	const char *key_mgmt = NULL;

	g_assert (setting_name != NULL);

	connection = nm_device_get_connection (NM_DEVICE (self));
	g_return_val_if_fail (connection != NULL, FALSE);

	/* A bad PSK will cause the supplicant to disconnect during the 4-way handshake */
	if (old_state != NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE)
		return FALSE;

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (s_wsec)
		key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);

	if (g_strcmp0 (key_mgmt, "wpa-psk") == 0) {
		*setting_name = NM_SETTING_WIRELESS_SECURITY_SETTING_NAME;
		return TRUE;
	}

	/* Not a WPA-PSK connection */
	return FALSE;
}

static gboolean
handle_8021x_or_psk_auth_fail (NMDeviceWifi *self,
                               guint32 new_state,
                               guint32 old_state,
                               int disconnect_reason)
{
	NMDevice *device = NM_DEVICE (self);
	NMActRequest *req;
	NMConnection *connection;
	const char *setting_name = NULL;
	gboolean handled = FALSE;

	g_return_val_if_fail (new_state == NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED, FALSE);

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_val_if_fail (req != NULL, FALSE);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	if (   need_new_8021x_secrets (self, old_state, &setting_name)
	    || need_new_wpa_psk (self, old_state, &setting_name)) {

		nm_connection_clear_secrets (connection);

		_LOGI (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) disconnected during association, asking for new key");

		cleanup_association_attempt (self, TRUE);
		nm_device_state_changed (device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
		nm_act_request_get_secrets (req,
		                            setting_name,
		                            NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION
		                              | NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW,
		                            NULL,
		                            wifi_secrets_cb,
		                            self);
		handled = TRUE;
	}

	return handled;
}

static void
supplicant_iface_state_cb (NMSupplicantInterface *iface,
                           guint32 new_state,
                           guint32 old_state,
                           int disconnect_reason,
                           gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	NMDeviceState devstate;
	gboolean scanning;
	gboolean recheck_available = FALSE;

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
		_LOGD (LOGD_WIFI_SCAN, "supplicant ready");
		recheck_available = TRUE;
		priv->scan_interval = SCAN_INTERVAL_MIN;
		if (old_state < NM_SUPPLICANT_INTERFACE_STATE_READY)
			nm_device_remove_pending_action (device, "waiting for supplicant", TRUE);
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_COMPLETED:
		remove_supplicant_interface_error_handler (self);
		remove_supplicant_timeouts (self);

		/* If this is the initial association during device activation,
		 * schedule the next activation stage.
		 */
		if (devstate == NM_DEVICE_STATE_CONFIG) {
			NMConnection *connection;
			NMSettingWireless *s_wifi;
			GBytes *ssid;

			connection = nm_device_get_connection (NM_DEVICE (self));
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
		recheck_available = TRUE;
		cleanup_association_attempt (self, FALSE);

		if (old_state < NM_SUPPLICANT_INTERFACE_STATE_READY)
			nm_device_remove_pending_action (device, "waiting for supplicant", TRUE);

		/* If the device is already in UNAVAILABLE state then the state change
		 * is a NOP and the interface won't be re-acquired in the device state
		 * change handler.  So ensure we have a new one here so that we're
		 * ready if the supplicant comes back.
		 */
		supplicant_interface_release (self);
		supplicant_interface_acquire (self);
		break;
	default:
		break;
	}

	if (recheck_available) {
		nm_device_queue_recheck_available (NM_DEVICE (device),
		                                   NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
		                                   NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
	}

	/* Signal scanning state changes */
	if (   new_state == NM_SUPPLICANT_INTERFACE_STATE_SCANNING
	    || old_state == NM_SUPPLICANT_INTERFACE_STATE_SCANNING)
		g_object_notify (G_OBJECT (self), "scanning");
}

static void
supplicant_iface_connection_error_cb (NMSupplicantInterface *iface,
                                      const char *name,
                                      const char *message,
                                      NMDeviceWifi *self)
{
	NMDevice *device = NM_DEVICE (self);

	if (nm_device_is_activating (device)) {
		_LOGW (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) supplicant association failed: %s - %s",
		       name, message);

		cleanup_association_attempt (self, TRUE);
		nm_device_queue_state (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
	}
}

static void
remove_supplicant_interface_error_handler (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->sup_iface) {
		g_signal_handlers_disconnect_by_func (priv->sup_iface,
		                                      supplicant_iface_connection_error_cb,
		                                      self);
	}
}

static void
supplicant_iface_notify_scanning_cb (NMSupplicantInterface *iface,
                                     GParamSpec *pspec,
                                     NMDeviceWifi *self)
{
	NMDeviceState state;
	gboolean scanning;

	scanning = nm_supplicant_interface_get_scanning (iface);
	_LOGD (LOGD_WIFI_SCAN, "now %s", scanning ? "scanning" : "idle");

	g_object_notify (G_OBJECT (self), "scanning");

	/* Run a quick update of current AP when coming out of a scan */
	state = nm_device_get_state (NM_DEVICE (self));
	if (!scanning && state == NM_DEVICE_STATE_ACTIVATED)
		periodic_update (self);
}

static void
supplicant_iface_notify_current_bss (NMSupplicantInterface *iface,
                                     GParamSpec *pspec,
                                     NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	const char *current_bss;
	NMAccessPoint *new_ap = NULL;

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
		if (new_ap == NULL && nm_ap_get_fake (priv->current_ap))
			return;

		if (new_ap) {
			new_bssid = nm_ap_get_address (new_ap);
			new_ssid = nm_ap_get_ssid (new_ap);
		}

		if (priv->current_ap) {
			old_bssid = nm_ap_get_address (priv->current_ap);
			old_ssid = nm_ap_get_ssid (priv->current_ap);
		}

		_LOGD (LOGD_WIFI, "roamed from BSSID %s (%s) to %s (%s)",
		       old_bssid ? old_bssid : "(none)",
		       old_ssid ? nm_utils_escape_ssid (old_ssid->data, old_ssid->len) : "(none)",
		       new_bssid ? new_bssid : "(none)",
		       new_ssid ? nm_utils_escape_ssid (new_ssid->data, new_ssid->len) : "(none)");

		set_current_ap (self, new_ap, TRUE, FALSE);
	}
}

static NMActStageReturn
handle_auth_or_fail (NMDeviceWifi *self,
                     NMActRequest *req,
                     gboolean new_secrets)
{
	const char *setting_name;
	guint32 tries;
	NMConnection *connection;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (self), NM_ACT_STAGE_RETURN_FAILURE);

	if (!req) {
		req = nm_device_get_act_request (NM_DEVICE (self));
		g_assert (req);
	}

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	tries = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES));
	if (tries > 3)
		return NM_ACT_STAGE_RETURN_FAILURE;

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);

	nm_connection_clear_secrets (connection);
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		NMSecretAgentGetSecretsFlags flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;

		if (new_secrets)
			flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;
		nm_act_request_get_secrets (req, setting_name, flags, NULL, wifi_secrets_cb, self);

		g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, GUINT_TO_POINTER (++tries));
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else
		_LOGW (LOGD_DEVICE, "Cleared secrets, but setting didn't need any secrets.");

	return ret;
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

	connection = nm_act_request_get_connection (req);
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
		if (nm_settings_connection_get_timestamp (NM_SETTINGS_CONNECTION (connection), &timestamp))
			new_secrets = !timestamp;

		if (handle_auth_or_fail (self, req, new_secrets) == NM_ACT_STAGE_RETURN_POSTPONE)
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
                         guint32 fixed_freq)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSupplicantConfig *config = NULL;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;

	g_return_val_if_fail (self != NULL, NULL);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wireless != NULL, NULL);

	config = nm_supplicant_config_new ();
	if (!config)
		return NULL;

	/* Warn if AP mode may not be supported */
	if (   g_strcmp0 (nm_setting_wireless_get_mode (s_wireless), NM_SETTING_WIRELESS_MODE_AP) == 0
	    && nm_supplicant_interface_get_ap_support (priv->sup_iface) == AP_SUPPORT_UNKNOWN) {
		_LOGW (LOGD_WIFI, "Supplicant may not support AP mode; connection may time out.");
	}

	if (!nm_supplicant_config_add_setting_wireless (config,
	                                                s_wireless,
	                                                fixed_freq)) {
		_LOGE (LOGD_WIFI, "Couldn't add 802-11-wireless setting to supplicant config.");
		goto error;
	}

	s_wireless_sec = nm_connection_get_setting_wireless_security (connection);
	if (s_wireless_sec) {
		NMSetting8021x *s_8021x;
		const char *con_uuid = nm_connection_get_uuid (connection);

		g_assert (con_uuid);
		s_8021x = nm_connection_get_setting_802_1x (connection);
		if (!nm_supplicant_config_add_setting_wireless_security (config,
		                                                         s_wireless_sec,
		                                                         s_8021x,
		                                                         con_uuid)) {
			_LOGE (LOGD_WIFI, "Couldn't add 802-11-wireless-security setting to supplicant config.");
			goto error;
		}
	} else {
		if (!nm_supplicant_config_add_no_security (config)) {
			_LOGE (LOGD_WIFI, "Couldn't add unsecured option to supplicant config.");
			goto error;
		}
	}

	return config;

error:
	g_object_unref (config);
	return NULL;
}

/****************************************************************************/

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMActStageReturn ret;
	NMAccessPoint *ap = NULL;
	NMActRequest *req;
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	const char *cloned_mac;
	const char *mode;
	const char *ap_path;

	ret = NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage1_prepare (device, reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_val_if_fail (req != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_act_request_get_connection (req);
	g_return_val_if_fail (connection != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

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
	g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_MODE);

	/* The kernel doesn't support Ad-Hoc WPA connections well at this time,
	 * and turns them into open networks.  It's been this way since at least
	 * 2.6.30 or so; until that's fixed, disable WPA-protected Ad-Hoc networks.
	 */
	if (is_adhoc_wpa (connection)) {
		_LOGW (LOGD_WIFI, "Ad-Hoc WPA disabled due to kernel bugs");
		*reason = NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	/* Set spoof MAC to the interface */
	cloned_mac = nm_setting_wireless_get_cloned_mac_address (s_wireless);
	if (cloned_mac)
		nm_device_set_hw_addr (device, cloned_mac, "set", LOGD_WIFI);

	/* AP mode never uses a specific object or existing scanned AP */
	if (priv->mode != NM_802_11_MODE_AP) {
		ap_path = nm_active_connection_get_specific_object (NM_ACTIVE_CONNECTION (req));
		ap = ap_path ? get_ap_by_path (self, ap_path) : NULL;
		if (ap)
			goto done;

		ap = find_first_compatible_ap (self, connection, FALSE);
	}

	if (ap) {
		nm_active_connection_set_specific_object (NM_ACTIVE_CONNECTION (req),
		                                          nm_exported_object_get_path (NM_EXPORTED_OBJECT (ap)));
		goto done;
	}

	/* If the user is trying to connect to an AP that NM doesn't yet know about
	 * (hidden network or something) or starting a Hotspot, create an fake AP
	 * from the security settings in the connection.  This "fake" AP gets used
	 * until the real one is found in the scan list (Ad-Hoc or Hidden), or until
	 * the device is deactivated (Hotspot).
	 */
	ap = nm_ap_new_fake_from_connection (connection);
	g_return_val_if_fail (ap != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	if (nm_ap_is_hotspot (ap))
		nm_ap_set_address (ap, nm_device_get_hw_address (device));

	ap_path = nm_exported_object_export (NM_EXPORTED_OBJECT (ap));
	g_hash_table_insert (priv->aps, (gpointer) ap_path, ap);
	g_object_freeze_notify (G_OBJECT (self));
	set_current_ap (self, ap, FALSE, FALSE);
	emit_ap_added_removed (self, ACCESS_POINT_ADDED, ap, TRUE);
	g_object_thaw_notify (G_OBJECT (self));
	nm_active_connection_set_specific_object (NM_ACTIVE_CONNECTION (req), ap_path);
	return NM_ACT_STAGE_RETURN_SUCCESS;

done:
	set_current_ap (self, ap, TRUE, FALSE);
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
ensure_hotspot_frequency (NMDeviceWifi *self,
                          NMSettingWireless *s_wifi,
                          NMAccessPoint *ap)
{
	const char *band = nm_setting_wireless_get_band (s_wifi);
	const guint32 a_freqs[] = { 5180, 5200, 5220, 5745, 5765, 5785, 5805, 0 };
	const guint32 bg_freqs[] = { 2412, 2437, 2462, 2472, 0 };
	guint32 freq = 0;

	g_assert (ap);

	if (nm_ap_get_freq (ap))
		return;

	if (g_strcmp0 (band, "a") == 0)
		freq = nm_platform_wifi_find_frequency (NM_PLATFORM_GET, nm_device_get_ifindex (NM_DEVICE (self)), a_freqs);
	else
		freq = nm_platform_wifi_find_frequency (NM_PLATFORM_GET, nm_device_get_ifindex (NM_DEVICE (self)), bg_freqs);

	if (!freq)
		freq = (g_strcmp0 (band, "a") == 0) ? 5180 : 2462;

	nm_ap_set_freq (ap, freq);
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMSupplicantConfig *config = NULL;
	NMActRequest *req;
	NMAccessPoint *ap;
	NMConnection *connection;
	const char *setting_name;
	NMSettingWireless *s_wireless;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	remove_supplicant_timeouts (self);

	req = nm_device_get_act_request (device);
	g_assert (req);

	ap = priv->current_ap;
	if (!ap) {
		*reason = NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED;
		goto out;
	}

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* If we need secrets, get them */
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		_LOGI (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) access point '%s' has security, but secrets are required.",
		       nm_connection_get_id (connection));

		ret = handle_auth_or_fail (self, req, FALSE);
		if (ret == NM_ACT_STAGE_RETURN_FAILURE)
			*reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
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
	if ((nm_ap_get_mode (ap) == NM_802_11_MODE_ADHOC) || nm_ap_is_hotspot (ap))
		ensure_hotspot_frequency (self, s_wireless, ap);

	if (nm_ap_get_mode (ap) == NM_802_11_MODE_INFRA) {
		nm_platform_wifi_set_powersave (NM_PLATFORM_GET,
		                                nm_device_get_ifindex (device),
		                                nm_setting_wireless_get_powersave (s_wireless));
	}

	/* Build up the supplicant configuration */
	config = build_supplicant_config (self, connection, nm_ap_get_freq (ap));
	if (config == NULL) {
		_LOGE (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) couldn't build wireless configuration.");
		*reason = NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED;
		goto out;
	}

	/* Hook up error signal handler to capture association errors */
	g_signal_connect (priv->sup_iface,
	                  NM_SUPPLICANT_INTERFACE_CONNECTION_ERROR,
	                  G_CALLBACK (supplicant_iface_connection_error_cb),
	                  self);

	if (!nm_supplicant_interface_set_config (priv->sup_iface, config)) {
		_LOGE (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: (wifi) couldn't send wireless configuration to the supplicant.");
		*reason = NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED;
		goto out;
	}

	/* Set up a timeout on the association attempt to fail after 25 seconds */
	priv->sup_timeout_id = g_timeout_add_seconds (25, supplicant_connection_timeout_cb, self);

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
                             NMDeviceStateReason *reason)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	const char *method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;

	connection = nm_device_get_connection (device);
	g_assert (connection);
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (s_ip4)
		method = nm_setting_ip_config_get_method (s_ip4);

	/* Indicate that a critical protocol is about to start */
	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0)
		nm_platform_wifi_indicate_addressing_running (NM_PLATFORM_GET, nm_device_get_ifindex (device), TRUE);

	return NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage3_ip4_config_start (device, out_config, reason);
}

static NMActStageReturn
act_stage3_ip6_config_start (NMDevice *device,
                             NMIP6Config **out_config,
                             NMDeviceStateReason *reason)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip6;
	const char *method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;

	connection = nm_device_get_connection (device);
	g_assert (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (s_ip6)
		method = nm_setting_ip_config_get_method (s_ip6);

	/* Indicate that a critical protocol is about to start */
	if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0 ||
	    strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP) == 0)
		nm_platform_wifi_indicate_addressing_running (NM_PLATFORM_GET, nm_device_get_ifindex (device), TRUE);

	return NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage3_ip6_config_start (device, out_config, reason);
}

static void
ip4_config_pre_commit (NMDevice *device, NMIP4Config *config)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	guint32 mtu;

	connection = nm_device_get_connection (device);
	g_assert (connection);
	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	/* MTU override */
	mtu = nm_setting_wireless_get_mtu (s_wifi);
	if (mtu)
		nm_ip4_config_set_mtu (config, mtu, NM_IP_CONFIG_SOURCE_USER);
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
                          NMDeviceStateReason *reason)
{
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	g_return_val_if_fail (connection != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	if (NM_DEVICE_WIFI_GET_PRIVATE (self)->mode == NM_802_11_MODE_AP) {
		*chain_up = TRUE;
		return ret;
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

		ret = handle_auth_or_fail (self, NULL, TRUE);
		if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
			_LOGI (LOGD_DEVICE | LOGD_WIFI,
			       "Activation: (wifi) asking for new secrets");
		} else {
			*reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
		}
	} else {
		/* Not static WEP or failure allowed; let superclass handle it */
		*chain_up = TRUE;
	}

	return ret;
}


static NMActStageReturn
act_stage4_ip4_config_timeout (NMDevice *device, NMDeviceStateReason *reason)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	gboolean may_fail = FALSE, chain_up = FALSE;
	NMActStageReturn ret;

	connection = nm_device_get_connection (device);
	g_assert (connection);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	may_fail = nm_setting_ip_config_get_may_fail (s_ip4);

	ret = handle_ip_config_timeout (NM_DEVICE_WIFI (device), connection, may_fail, &chain_up, reason);
	if (chain_up)
		ret = NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage4_ip4_config_timeout (device, reason);

	return ret;
}

static NMActStageReturn
act_stage4_ip6_config_timeout (NMDevice *device, NMDeviceStateReason *reason)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip6;
	gboolean may_fail = FALSE, chain_up = FALSE;
	NMActStageReturn ret;

	connection = nm_device_get_connection (device);
	g_assert (connection);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	may_fail = nm_setting_ip_config_get_may_fail (s_ip6);

	ret = handle_ip_config_timeout (NM_DEVICE_WIFI (device), connection, may_fail, &chain_up, reason);
	if (chain_up)
		ret = NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage4_ip6_config_timeout (device, reason);

	return ret;
}

static void
activation_success_handler (NMDevice *device)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	int ifindex = nm_device_get_ifindex (device);
	NMActRequest *req;
	NMConnection *connection;

	req = nm_device_get_act_request (device);
	g_assert (req);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	/* Clear any critical protocol notification in the wifi stack */
	nm_platform_wifi_indicate_addressing_running (NM_PLATFORM_GET, ifindex, FALSE);

	/* Clear wireless secrets tries on success */
	g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, NULL);

	/* There should always be a current AP, either a fake one because we haven't
	 * seen a scan result for the activated AP yet, or a real one from the
	 * supplicant's scan list.
	 */
	g_warn_if_fail (priv->current_ap);
	if (priv->current_ap) {
		if (nm_ap_get_fake (priv->current_ap)) {
			/* If the activation AP hasn't been seen by the supplicant in a scan
			 * yet, it will be "fake".  This usually happens for Ad-Hoc and
			 * AP-mode connections.  Fill in the details from the device itself
			 * until the supplicant sends the scan result.
			 */
			if (!nm_ap_get_address (priv->current_ap)) {
				guint8 bssid[ETH_ALEN] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
				gs_free char *bssid_str = NULL;

				if (   nm_platform_wifi_get_bssid (NM_PLATFORM_GET, ifindex, bssid)
				    && nm_ethernet_address_is_valid (bssid, ETH_ALEN)) {
					bssid_str = nm_utils_hwaddr_ntoa (bssid, ETH_ALEN);
					nm_ap_set_address (priv->current_ap, bssid_str);
				}
			}
			if (!nm_ap_get_freq (priv->current_ap))
				nm_ap_set_freq (priv->current_ap, nm_platform_wifi_get_frequency (NM_PLATFORM_GET, ifindex));
			if (!nm_ap_get_max_bitrate (priv->current_ap))
				nm_ap_set_max_bitrate (priv->current_ap, nm_platform_wifi_get_rate (NM_PLATFORM_GET, ifindex));
		}

		nm_active_connection_set_specific_object (NM_ACTIVE_CONNECTION (req),
		                                          nm_exported_object_get_path (NM_EXPORTED_OBJECT (priv->current_ap)));
	}

	periodic_update (self);

	/* Reset scan interval to something reasonable */
	priv->scan_interval = SCAN_INTERVAL_MIN + (SCAN_INTERVAL_STEP * 2);
}

static void
activation_failure_handler (NMDevice *device)
{
	NMConnection *connection;

	connection = nm_device_get_connection (device);
	g_assert (connection);

	/* Clear wireless secrets tries on failure */
	g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, NULL);

	/* Clear any critical protocol notification in the wifi stack */
	nm_platform_wifi_indicate_addressing_running (NM_PLATFORM_GET, nm_device_get_ifindex (device), FALSE);
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

	if (new_state <= NM_DEVICE_STATE_UNAVAILABLE) {
		/* Clean up the supplicant interface because in these states the
		 * device cannot be used.
		 */
		if (priv->sup_iface)
			supplicant_interface_release (self);

		if (priv->periodic_source_id) {
			g_source_remove (priv->periodic_source_id);
			priv->periodic_source_id = 0;
		}

		cleanup_association_attempt (self, TRUE);
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
		nm_platform_wifi_indicate_addressing_running (NM_PLATFORM_GET, nm_device_get_ifindex (device), FALSE);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		activation_success_handler (device);
		break;
	case NM_DEVICE_STATE_FAILED:
		activation_failure_handler (device);
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		/* Kick off a scan to get latest results */
		priv->scan_interval = SCAN_INTERVAL_MIN;
		cancel_pending_scan (self);
		request_wireless_scan (self, NULL);
		break;
	default:
		break;
	}

	if (clear_aps)
		remove_all_aps (self);
}

static void
set_enabled (NMDevice *device, gboolean enabled)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMDeviceState state;

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

/********************************************************************/

NMDevice *
nm_device_wifi_new (const char *iface)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_WIFI,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "802.11 WiFi",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_WIFI,
	                                  NM_DEVICE_RFKILL_TYPE, RFKILL_TYPE_WLAN,
	                                  NULL);
}

static void
nm_device_wifi_init (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	priv->mode = NM_802_11_MODE_INFRA;
	priv->aps = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);
}

static void
dispose (GObject *object)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (object);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->periodic_source_id) {
		g_source_remove (priv->periodic_source_id);
		priv->periodic_source_id = 0;
	}

	cleanup_association_attempt (self, TRUE);
	supplicant_interface_release (self);

	g_clear_object (&priv->sup_mgr);

	remove_all_aps (self);

	G_OBJECT_CLASS (nm_device_wifi_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	g_clear_pointer (&NM_DEVICE_WIFI_GET_PRIVATE (object)->aps, g_hash_table_unref);

	G_OBJECT_CLASS (nm_device_wifi_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceWifi *device = NM_DEVICE_WIFI (object);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	GHashTableIter iter;
	const char *dbus_path;
	GPtrArray *array;

	switch (prop_id) {
	case PROP_PERM_HW_ADDRESS:
		g_value_set_string (value, nm_device_get_permanent_hw_address (NM_DEVICE (device)));
		break;
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
		array = g_ptr_array_sized_new (g_hash_table_size (priv->aps) + 1);
		g_hash_table_iter_init (&iter, priv->aps);
		while (g_hash_table_iter_next (&iter, (gpointer) &dbus_path, NULL))
			g_ptr_array_add (array, g_strdup (dbus_path));
		g_ptr_array_add (array, NULL);
		g_value_take_boxed (value, (char **) g_ptr_array_free (array, FALSE));
		break;
	case PROP_ACTIVE_ACCESS_POINT:
		nm_utils_g_value_set_object_path (value, priv->current_ap);
		break;
	case PROP_SCANNING:
		g_value_set_boolean (value, nm_supplicant_interface_get_scanning (priv->sup_iface));
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
	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
}


static void
nm_device_wifi_class_init (NMDeviceWifiClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceWifiPrivate));

	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	parent_class->setup = setup;
	parent_class->bring_up = bring_up;
	parent_class->can_auto_connect = can_auto_connect;
	parent_class->is_available = is_available;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->check_connection_available = check_connection_available;
	parent_class->complete_connection = complete_connection;
	parent_class->set_enabled = set_enabled;

	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->act_stage2_config = act_stage2_config;
	parent_class->ip4_config_pre_commit = ip4_config_pre_commit;
	parent_class->act_stage3_ip4_config_start = act_stage3_ip4_config_start;
	parent_class->act_stage3_ip6_config_start = act_stage3_ip6_config_start;
	parent_class->act_stage4_ip4_config_timeout = act_stage4_ip4_config_timeout;
	parent_class->act_stage4_ip6_config_timeout = act_stage4_ip6_config_timeout;
	parent_class->deactivate = deactivate;

	parent_class->state_changed = device_state_changed;

	klass->scanning_allowed = scanning_allowed;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_PERM_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_uint (NM_DEVICE_WIFI_MODE, "", "",
		                    NM_802_11_MODE_UNKNOWN,
		                    NM_802_11_MODE_AP,
		                    NM_802_11_MODE_INFRA,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_BITRATE,
		 g_param_spec_uint (NM_DEVICE_WIFI_BITRATE, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_ACCESS_POINTS,
		 g_param_spec_boxed (NM_DEVICE_WIFI_ACCESS_POINTS, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_ACTIVE_ACCESS_POINT,
		 g_param_spec_string (NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_WIFI_CAPABILITIES, "", "",
		                    0, G_MAXUINT32, NM_WIFI_DEVICE_CAP_NONE,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_SCANNING,
		 g_param_spec_boolean (NM_DEVICE_WIFI_SCANNING, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/* Signals */
	signals[ACCESS_POINT_ADDED] =
		g_signal_new ("access-point-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, access_point_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              NM_TYPE_AP);

	signals[ACCESS_POINT_REMOVED] =
		g_signal_new ("access-point-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0,
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              NM_TYPE_AP);

	signals[SCANNING_ALLOWED] =
		g_signal_new ("scanning-allowed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, scanning_allowed),
		              scanning_allowed_accumulator, NULL, NULL,
		              G_TYPE_BOOLEAN, 0);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_WIFI_SKELETON,
	                                        "GetAccessPoints", impl_device_wifi_get_access_points,
	                                        "GetAllAccessPoints", impl_device_wifi_get_all_access_points,
	                                        "RequestScan", impl_device_wifi_request_scan,
	                                        NULL);
}


