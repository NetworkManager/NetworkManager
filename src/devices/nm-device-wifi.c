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

#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <netinet/in.h>
#include <string.h>
#include <net/ethernet.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <errno.h>

#include "nm-glib-compat.h"
#include "nm-dbus-manager.h"
#include "nm-device.h"
#include "nm-device-wifi.h"
#include "nm-device-private.h"
#include "nm-utils.h"
#include "nm-logging.h"
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
#include "nm-setting-ip6-config.h"
#include "nm-platform.h"
#include "nm-system.h"
#include "nm-manager-auth.h"
#include "nm-settings-connection.h"
#include "nm-enum-types.h"
#include "wifi-utils.h"

static gboolean impl_device_get_access_points (NMDeviceWifi *device,
                                               GPtrArray **aps,
                                               GError **err);

static void impl_device_request_scan (NMDeviceWifi *device,
                                      GHashTable *options,
                                      DBusGMethodInvocation *context);

#include "nm-device-wifi-glue.h"


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
	PROP_ACTIVE_ACCESS_POINT,
	PROP_CAPABILITIES,
	PROP_SCANNING,
	PROP_IPW_RFKILL_STATE,

	LAST_PROP
};

enum {
	ACCESS_POINT_ADDED,
	ACCESS_POINT_REMOVED,
	HIDDEN_AP_FOUND,
	SCANNING_ALLOWED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

#define SUP_SIG_ID_LEN 6

typedef struct Supplicant {
	NMSupplicantManager *mgr;
	NMSupplicantInterface *iface;

	guint sig_ids[SUP_SIG_ID_LEN];
	guint iface_error_id;

	/* Timeouts and idles */
	guint iface_con_error_cb_id;
	guint con_timeout_id;
} Supplicant;

struct _NMDeviceWifiPrivate {
	gboolean          disposed;

	guint8            perm_hw_addr[ETH_ALEN];    /* Permanent MAC address */
	guint8            initial_hw_addr[ETH_ALEN]; /* Initial MAC address (as seen when NM starts) */

	/* Legacy rfkill for ipw2x00; will be fixed with 2.6.33 kernel */
	char *            ipw_rfkill_path;
	guint             ipw_rfkill_id;
	RfKillState       ipw_rfkill_state;

	gint8             invalid_strength_counter;

	GSList *          ap_list;
	NMAccessPoint *   current_ap;
	guint32           rate;
	gboolean          enabled; /* rfkilled or not */
	
	time_t            scheduled_scan_time;
	guint8            scan_interval; /* seconds */
	guint             pending_scan_id;
	guint             scanlist_cull_id;

	Supplicant        supplicant;
	WifiData *        wifi_data;
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

static void remove_supplicant_timeouts (NMDeviceWifi *self);

static void supplicant_iface_state_cb (NMSupplicantInterface *iface,
                                       guint32 new_state,
                                       guint32 old_state,
                                       int disconnect_reason,
                                       gpointer user_data);

static void supplicant_iface_new_bss_cb (NMSupplicantInterface * iface,
                                         const char *object_path,
                                         GHashTable *properties,
                                         NMDeviceWifi * self);

static void supplicant_iface_bss_updated_cb (NMSupplicantInterface *iface,
                                             const char *object_path,
                                             GHashTable *properties,
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

static void schedule_scanlist_cull (NMDeviceWifi *self);

static gboolean request_wireless_scan (gpointer user_data);

/*****************************************************************/

#define NM_WIFI_ERROR (nm_wifi_error_quark ())

static GQuark
nm_wifi_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-wifi-error");
	return quark;
}

/*****************************************************************/

/* IPW rfkill handling (until 2.6.33) */
RfKillState
nm_device_wifi_get_ipw_rfkill_state (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	char *contents = NULL;
	RfKillState state = RFKILL_UNBLOCKED;
	const char *str_state = NULL;

	if (   priv->ipw_rfkill_path
	    && g_file_get_contents (priv->ipw_rfkill_path, &contents, NULL, NULL)) {
		contents = g_strstrip (contents);

		/* 0 - RF kill not enabled
		 * 1 - SW based RF kill active (sysfs)
		 * 2 - HW based RF kill active
		 * 3 - Both HW and SW baed RF kill active
		 */
		switch (contents[0]) {
		case '1':
			state = RFKILL_SOFT_BLOCKED;
			str_state = "soft-blocked";
			break;
		case '2':
		case '3':
			state = RFKILL_HARD_BLOCKED;
			str_state = "hard-blocked";
			break;
		case '0':
			str_state = "unblocked";
		default:
			break;
		}
		g_free (contents);

		nm_log_dbg (LOGD_RFKILL, "(%s): ipw rfkill state '%s'",
		            nm_device_get_iface (NM_DEVICE (self)),
		            str_state ? str_state : "(unknown)");
	}

	return state;
}

static gboolean
ipw_rfkill_state_work (gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	RfKillState old_state;

	old_state = priv->ipw_rfkill_state;
	priv->ipw_rfkill_state = nm_device_wifi_get_ipw_rfkill_state (self);
	if (priv->ipw_rfkill_state != old_state)
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_IPW_RFKILL_STATE);

	return TRUE;
}

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

	nm_log_dbg (LOGD_HW | LOGD_WIFI, "(%s): kernel ifindex %d",
	            nm_device_get_iface (NM_DEVICE (self)),
	            nm_device_get_ifindex (NM_DEVICE (self)));

	priv->wifi_data = wifi_utils_init (nm_device_get_iface (NM_DEVICE (self)),
	                                   nm_device_get_ifindex (NM_DEVICE (self)),
	                                   TRUE);
	if (priv->wifi_data == NULL) {
		nm_log_warn (LOGD_HW | LOGD_WIFI, "(%s): failed to initialize WiFi driver",
		             nm_device_get_iface (NM_DEVICE (self)));
		g_object_unref (object);
		return NULL;
	}
	priv->capabilities = wifi_utils_get_caps (priv->wifi_data);

	if (priv->capabilities & NM_WIFI_DEVICE_CAP_AP) {
		nm_log_info (LOGD_HW | LOGD_WIFI, "(%s): driver supports Access Point (AP) mode",
		             nm_device_get_iface (NM_DEVICE (self)));
	}

	/* Connect to the supplicant manager */
	priv->supplicant.mgr = nm_supplicant_manager_get ();
	g_assert (priv->supplicant.mgr);

	/* The ipw2x00 drivers don't integrate with the kernel rfkill subsystem until
	 * 2.6.33.  Thus all our nice libgudev magic is useless.  So we get to poll.
	 *
	 * FIXME: when 2.6.33 comes lands, we can do some sysfs parkour to figure out
	 * if we need to poll or not by matching /sys/class/net/ethX/device to one
	 * of the /sys/class/rfkill/rfkillX/device links.  If there's a match, we
	 * don't have to poll.
	 */
	priv->ipw_rfkill_path = g_strdup_printf ("/sys/class/net/%s/device/rf_kill",
	                                         nm_device_get_iface (NM_DEVICE (self)));
	if (!g_file_test (priv->ipw_rfkill_path, G_FILE_TEST_IS_REGULAR)) {
		g_free (priv->ipw_rfkill_path);
		priv->ipw_rfkill_path = NULL;
	}
	priv->ipw_rfkill_state = nm_device_wifi_get_ipw_rfkill_state (self);

	return object;
}

static gboolean
supplicant_interface_acquire (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	guint id, i = 0;

	g_return_val_if_fail (self != NULL, FALSE);
	/* interface already acquired? */
	g_return_val_if_fail (priv->supplicant.iface == NULL, TRUE);

	priv->supplicant.iface = nm_supplicant_manager_iface_get (priv->supplicant.mgr,
	                                                          nm_device_get_iface (NM_DEVICE (self)),
	                                                          TRUE);
	if (priv->supplicant.iface == NULL) {
		nm_log_err (LOGD_WIFI, "Couldn't initialize supplicant interface for %s.",
		            nm_device_get_iface (NM_DEVICE (self)));
		return FALSE;
	}

	memset (priv->supplicant.sig_ids, 0, sizeof (priv->supplicant.sig_ids));

	id = g_signal_connect (priv->supplicant.iface,
	                       NM_SUPPLICANT_INTERFACE_STATE,
	                       G_CALLBACK (supplicant_iface_state_cb),
	                       self);
	priv->supplicant.sig_ids[i++] = id;

	id = g_signal_connect (priv->supplicant.iface,
	                       NM_SUPPLICANT_INTERFACE_NEW_BSS,
	                       G_CALLBACK (supplicant_iface_new_bss_cb),
	                       self);
	priv->supplicant.sig_ids[i++] = id;

	id = g_signal_connect (priv->supplicant.iface,
	                       NM_SUPPLICANT_INTERFACE_BSS_UPDATED,
	                       G_CALLBACK (supplicant_iface_bss_updated_cb),
	                       self);
	priv->supplicant.sig_ids[i++] = id;

	id = g_signal_connect (priv->supplicant.iface,
	                       NM_SUPPLICANT_INTERFACE_BSS_REMOVED,
	                       G_CALLBACK (supplicant_iface_bss_removed_cb),
	                       self);
	priv->supplicant.sig_ids[i++] = id;

	id = g_signal_connect (priv->supplicant.iface,
	                       NM_SUPPLICANT_INTERFACE_SCAN_DONE,
	                       G_CALLBACK (supplicant_iface_scan_done_cb),
	                       self);
	priv->supplicant.sig_ids[i++] = id;

	id = g_signal_connect (priv->supplicant.iface,
	                       "notify::scanning",
	                       G_CALLBACK (supplicant_iface_notify_scanning_cb),
	                       self);
	priv->supplicant.sig_ids[i++] = id;

	return TRUE;
}

static void
remove_supplicant_interface_error_handler (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (!priv->supplicant.iface)
		return;

	if (priv->supplicant.iface_error_id > 0) {
		g_signal_handler_disconnect (priv->supplicant.iface, priv->supplicant.iface_error_id);
		priv->supplicant.iface_error_id = 0;
	}

	if (priv->supplicant.iface_con_error_cb_id > 0) {
		g_source_remove (priv->supplicant.iface_con_error_cb_id);
		priv->supplicant.iface_con_error_cb_id = 0;
	}
}

static void
supplicant_interface_release (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;
	guint i;

	g_return_if_fail (self != NULL);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	cancel_pending_scan (self);

	/* Reset the scan interval to be pretty frequent when disconnected */
	priv->scan_interval = SCAN_INTERVAL_MIN + SCAN_INTERVAL_STEP;
	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): reset scanning interval to %d seconds",
	            nm_device_get_iface (NM_DEVICE (self)),
	            priv->scan_interval);

	remove_supplicant_interface_error_handler (self);

	/* Clear supplicant interface signal handlers */
	for (i = 0; i < SUP_SIG_ID_LEN; i++) {
		if (priv->supplicant.sig_ids[i] > 0)
			g_signal_handler_disconnect (priv->supplicant.iface, priv->supplicant.sig_ids[i]);
	}
	memset (priv->supplicant.sig_ids, 0, sizeof (priv->supplicant.sig_ids));

	if (priv->scanlist_cull_id) {
		g_source_remove (priv->scanlist_cull_id);
		priv->scanlist_cull_id = 0;
	}

	if (priv->supplicant.iface) {
		/* Tell the supplicant to disconnect from the current AP */
		nm_supplicant_interface_disconnect (priv->supplicant.iface);

		nm_supplicant_manager_iface_release (priv->supplicant.mgr, priv->supplicant.iface);
		priv->supplicant.iface = NULL;
	}
}

static NMAccessPoint *
get_ap_by_path (NMDeviceWifi *self, const char *path)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->ap_list; iter; iter = g_slist_next (iter)) {
		if (g_strcmp0 (path, nm_ap_get_dbus_path (NM_AP (iter->data))) == 0)
			return NM_AP (iter->data);
	}
	return NULL;
}

static NMAccessPoint *
get_ap_by_supplicant_path (NMDeviceWifi *self, const char *path)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->ap_list; iter && path; iter = g_slist_next (iter)) {
		if (g_strcmp0 (path, nm_ap_get_supplicant_path (NM_AP (iter->data))) == 0)
			return NM_AP (iter->data);
	}
	return NULL;
}

static NMAccessPoint *
get_active_ap (NMDeviceWifi *self,
               NMAccessPoint *ignore_ap,
               gboolean match_hidden)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	const char *iface = nm_device_get_iface (NM_DEVICE (self));
	struct ether_addr bssid;
	GByteArray *ssid;
	GSList *iter;
	int i = 0;
	NMAccessPoint *match_nofreq = NULL, *active_ap = NULL;
	gboolean found_a_band = FALSE;
	gboolean found_bg_band = FALSE;
	NM80211Mode devmode;
	guint32 devfreq;

	wifi_utils_get_bssid (priv->wifi_data, &bssid);
	nm_log_dbg (LOGD_WIFI, "(%s): active BSSID: %02x:%02x:%02x:%02x:%02x:%02x",
	            iface,
	            bssid.ether_addr_octet[0], bssid.ether_addr_octet[1],
	            bssid.ether_addr_octet[2], bssid.ether_addr_octet[3],
	            bssid.ether_addr_octet[4], bssid.ether_addr_octet[5]);

	if (!nm_ethernet_address_is_valid (&bssid))
		return NULL;

	ssid = wifi_utils_get_ssid (priv->wifi_data);
	nm_log_dbg (LOGD_WIFI, "(%s): active SSID: %s%s%s",
	            iface,
	            ssid ? "'" : "",
	            ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)",
	            ssid ? "'" : "");

	devmode = wifi_utils_get_mode (priv->wifi_data);
	devfreq = wifi_utils_get_freq (priv->wifi_data);

	/* When matching hidden APs, do a second pass that ignores the SSID check,
	 * because NM might not yet know the SSID of the hidden AP in the scan list
	 * and therefore it won't get matched the first time around.
	 */
	while (i++ < (match_hidden ? 2 : 1)) {
		nm_log_dbg (LOGD_WIFI, "  Pass #%d %s", i, i > 1 ? "(ignoring SSID)" : "");

		/* Find this SSID + BSSID in the device's AP list */
		for (iter = priv->ap_list; iter; iter = g_slist_next (iter)) {
			NMAccessPoint *ap = NM_AP (iter->data);
			const struct ether_addr	*ap_bssid = nm_ap_get_address (ap);
			const GByteArray *ap_ssid = nm_ap_get_ssid (ap);
			NM80211Mode apmode;
			guint32 apfreq;

			nm_log_dbg (LOGD_WIFI, "    AP: %s%s%s  %02x:%02x:%02x:%02x:%02x:%02x",
			            ap_ssid ? "'" : "",
			            ap_ssid ? nm_utils_escape_ssid (ap_ssid->data, ap_ssid->len) : "(none)",
			            ap_ssid ? "'" : "",
			            ap_bssid->ether_addr_octet[0], ap_bssid->ether_addr_octet[1],
			            ap_bssid->ether_addr_octet[2], ap_bssid->ether_addr_octet[3],
			            ap_bssid->ether_addr_octet[4], ap_bssid->ether_addr_octet[5]);

			if (ignore_ap && (ap == ignore_ap)) {
				nm_log_dbg (LOGD_WIFI, "      ignored");
				continue;
			}

			if (memcmp (bssid.ether_addr_octet, ap_bssid->ether_addr_octet, ETH_ALEN)) {
				nm_log_dbg (LOGD_WIFI, "      BSSID mismatch");
				continue;
			}

			if ((i == 0) && !nm_utils_same_ssid (ssid, ap_ssid, TRUE)) {
				nm_log_dbg (LOGD_WIFI, "      SSID mismatch");
				continue;
			}

			apmode = nm_ap_get_mode (ap);
			if (devmode != apmode) {
				nm_log_dbg (LOGD_WIFI, "      mode mismatch (device %d, ap %d)",
				            devmode, apmode);
				continue;
			}

			apfreq = nm_ap_get_freq (ap);
			if (devfreq != apfreq) {
				nm_log_dbg (LOGD_WIFI, "      frequency mismatch (device %u, ap %u)",
				            devfreq, apfreq);

				if (match_nofreq == NULL)
					match_nofreq = ap;

				if (apfreq > 4000)
					found_a_band = TRUE;
				else if (apfreq > 2000)
					found_bg_band = TRUE;
				continue;
			}

			// FIXME: handle security settings here too
			nm_log_dbg (LOGD_WIFI, "      matched");
			active_ap = ap;
			goto done;
		}
	}

	/* Some proprietary drivers (wl.o) report tuned frequency (like when
	 * scanning) instead of the associated AP's frequency.  This is a great
	 * example of how WEXT is underspecified.  We use frequency to find the
	 * active AP in the scan list because some configurations use the same
	 * SSID/BSSID on the 2GHz and 5GHz bands simultaneously, and we need to
	 * make sure we get the right AP in the right band.  This configuration
	 * is uncommon though, and the frequency check penalizes closed drivers we
	 * can't fix.  Because we're not total dicks, ignore the frequency condition
	 * if the associated BSSID/SSID exists only in one band since that's most
	 * likely the AP we want.  Sometimes wl.o returns a frequency of 0, so if
	 * we can't match the AP based on frequency at all, just give up.
	 */
	if (match_nofreq && ((found_a_band != found_bg_band) || (devfreq == 0))) {
		const struct ether_addr	*ap_bssid = nm_ap_get_address (match_nofreq);
		const GByteArray *ap_ssid = nm_ap_get_ssid (match_nofreq);

		nm_log_dbg (LOGD_WIFI, "    matched %s%s%s  %02x:%02x:%02x:%02x:%02x:%02x",
		            ap_ssid ? "'" : "",
		            ap_ssid ? nm_utils_escape_ssid (ap_ssid->data, ap_ssid->len) : "(none)",
		            ap_ssid ? "'" : "",
		            ap_bssid->ether_addr_octet[0], ap_bssid->ether_addr_octet[1],
		            ap_bssid->ether_addr_octet[2], ap_bssid->ether_addr_octet[3],
		            ap_bssid->ether_addr_octet[4], ap_bssid->ether_addr_octet[5]);

		active_ap = match_nofreq;
	}

	nm_log_dbg (LOGD_WIFI, "  No matching AP found.");

done:
	if (ssid)
		g_byte_array_free (ssid, TRUE);
	return active_ap;
}

static void
update_seen_bssids_cache (NMDeviceWifi *self, NMAccessPoint *ap)
{
	NMActRequest *req;
	NMConnection *connection;

	g_return_if_fail (NM_IS_DEVICE_WIFI (self));
	
	if (ap == NULL)
		return;

	/* Don't cache the BSSID for Ad-Hoc APs */
	if (nm_ap_get_mode (ap) != NM_802_11_MODE_INFRA)
		return;

	if (nm_device_get_state (NM_DEVICE (self)) == NM_DEVICE_STATE_ACTIVATED) {
		req = nm_device_get_act_request (NM_DEVICE (self));
		if (req) {
			connection = nm_act_request_get_connection (req);
			nm_settings_connection_add_seen_bssid (NM_SETTINGS_CONNECTION (connection),
			                                       nm_ap_get_address (ap));
		}
	}
}

static void
set_active_ap (NMDeviceWifi *self, NMAccessPoint *new_ap)
{
	NMDeviceWifiPrivate *priv;
	char *old_path = NULL;
	NMAccessPoint *old_ap;

	g_return_if_fail (NM_IS_DEVICE_WIFI (self));

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	old_ap = priv->current_ap;

	if (old_ap) {
		old_path = g_strdup (nm_ap_get_dbus_path (old_ap));
		priv->current_ap = NULL;
	}

	if (new_ap) {
		priv->current_ap = g_object_ref (new_ap);

		/* Move the current AP to the front of the scan list.  Since we
		 * do a lot of searches looking for the current AP, it saves
		 * time to have it in front.
		 */
		priv->ap_list = g_slist_remove (priv->ap_list, new_ap);
		priv->ap_list = g_slist_prepend (priv->ap_list, new_ap);

		/* Update seen BSSIDs cache */
		update_seen_bssids_cache (self, priv->current_ap);
	}

	/* Unref old AP here to ensure object lives if new_ap == old_ap */
	if (old_ap)
		g_object_unref (old_ap);

	/* Only notify if it's really changed */
	if (   (!old_path && new_ap)
	    || (old_path && !new_ap)
	    || (old_path && new_ap && strcmp (old_path, nm_ap_get_dbus_path (new_ap))))
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT);

	g_free (old_path);
}

/* Called both as a GSourceFunc and standalone */
static gboolean
periodic_update (gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *new_ap;
	guint32 new_rate, percent;
	NMDeviceState state;
	guint32 supplicant_state;

	/* BSSID and signal strength have meaningful values only if the device
	 * is activated and not scanning.
	 */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state != NM_DEVICE_STATE_ACTIVATED)
		return TRUE;

	/* Only update current AP if we're actually talking to something, otherwise
	 * assume the old one (if any) is still valid until we're told otherwise or
	 * the connection fails.
	 */
	supplicant_state = nm_supplicant_interface_get_state (priv->supplicant.iface);
	if (   supplicant_state < NM_SUPPLICANT_INTERFACE_STATE_AUTHENTICATING
	    || supplicant_state > NM_SUPPLICANT_INTERFACE_STATE_COMPLETED
	    || nm_supplicant_interface_get_scanning (priv->supplicant.iface))
		return TRUE;

	/* In AP mode we currently have nothing to do. */
	if (priv->mode == NM_802_11_MODE_AP)
		return TRUE;

	/* In IBSS mode, most newer firmware/drivers do "BSS coalescing" where
	 * multiple IBSS stations using the same SSID will eventually switch to
	 * using the same BSSID to avoid network segmentation.  When this happens,
	 * the card's reported BSSID will change, but the the new BSS may not
	 * be in the scan list, since scanning isn't done in ad-hoc mode for
	 * various reasons.  So pull the BSSID from the card and update the
	 * current AP with it, if the current AP is adhoc.
	 */
	if (priv->current_ap && (nm_ap_get_mode (priv->current_ap) == NM_802_11_MODE_ADHOC)) {
		struct ether_addr bssid = { {0x0, 0x0, 0x0, 0x0, 0x0, 0x0} };

		wifi_utils_get_bssid (priv->wifi_data, &bssid);
		/* 0x02 means "locally administered" and should be OR-ed into
		 * the first byte of IBSS BSSIDs.
		 */
		if (   (bssid.ether_addr_octet[0] & 0x02)
		    && nm_ethernet_address_is_valid (&bssid))
			nm_ap_set_address (priv->current_ap, &bssid);
	}

	new_ap = get_active_ap (self, NULL, FALSE);
	if (new_ap) {
		/* Try to smooth out the strength.  Atmel cards, for example, will give no strength
		 * one second and normal strength the next.
		 */
		percent = wifi_utils_get_qual (priv->wifi_data);
		if (percent >= 0 || ++priv->invalid_strength_counter > 3) {
			nm_ap_set_strength (new_ap, (gint8) percent);
			priv->invalid_strength_counter = 0;
		}
	}

	if ((new_ap || priv->current_ap) && (new_ap != priv->current_ap)) {
		const struct ether_addr *new_bssid = NULL;
		const GByteArray *new_ssid = NULL;
		const struct ether_addr *old_bssid = NULL;
		const GByteArray *old_ssid = NULL;
		char *old_addr = NULL, *new_addr = NULL;

		if (new_ap) {
			new_bssid = nm_ap_get_address (new_ap);
			new_addr = nm_utils_hwaddr_ntoa (new_bssid, ARPHRD_ETHER);
			new_ssid = nm_ap_get_ssid (new_ap);
		}

		if (priv->current_ap) {
			old_bssid = nm_ap_get_address (priv->current_ap);
			old_addr = nm_utils_hwaddr_ntoa (old_bssid, ARPHRD_ETHER);
			old_ssid = nm_ap_get_ssid (priv->current_ap);
		}

		nm_log_info (LOGD_WIFI, "(%s): roamed from BSSID %s (%s) to %s (%s)",
		             nm_device_get_iface (NM_DEVICE (self)),
		             old_addr ? old_addr : "(none)",
		             old_ssid ? nm_utils_escape_ssid (old_ssid->data, old_ssid->len) : "(none)",
		             new_addr ? new_addr : "(none)",
		             new_ssid ? nm_utils_escape_ssid (new_ssid->data, new_ssid->len) : "(none)");
		g_free (old_addr);
		g_free (new_addr);

		set_active_ap (self, new_ap);
	}

	new_rate = wifi_utils_get_rate (priv->wifi_data);
	if (new_rate != priv->rate) {
		priv->rate = new_rate;
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_BITRATE);
	}

	return TRUE;
}

static gboolean
bring_up (NMDevice *device, gboolean *no_firmware)
{
	if (!NM_DEVICE_WIFI_GET_PRIVATE (device)->enabled)
		return FALSE;

	return NM_DEVICE_CLASS (nm_device_wifi_parent_class)->bring_up (device, no_firmware);
}

static gboolean
_set_hw_addr (NMDeviceWifi *self, const guint8 *addr, const char *detail)
{
	NMDevice *dev = NM_DEVICE (self);
	const char *iface;
	char *mac_str = NULL;
	gboolean success = FALSE;
	const guint8 *cur_addr = nm_device_get_hw_address (dev, NULL);

	g_return_val_if_fail (addr != NULL, FALSE);

	iface = nm_device_get_iface (dev);

	mac_str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
	                           addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	/* Do nothing if current MAC is same */
	if (cur_addr && !memcmp (cur_addr, addr, ETH_ALEN)) {
		nm_log_dbg (LOGD_DEVICE | LOGD_ETHER, "(%s): no MAC address change needed", iface);
		g_free (mac_str);
		return TRUE;
	}

	/* Can't change MAC address while device is up */
	nm_device_take_down (dev, FALSE);

	success = nm_platform_link_set_address (nm_device_get_ip_ifindex (dev), addr, ETH_ALEN);
	if (success) {
		/* MAC address succesfully changed; update the current MAC to match */
		nm_device_update_hw_address (dev);
		nm_log_info (LOGD_DEVICE | LOGD_ETHER, "(%s): %s MAC address to %s",
		             iface, detail, mac_str);
	} else {
		nm_log_warn (LOGD_DEVICE | LOGD_ETHER, "(%s): failed to %s MAC address to %s",
		             iface, detail, mac_str);
	}
	bring_up (dev, NULL);
	g_free (mac_str);

	return success;
}

static void
remove_access_point (NMDeviceWifi *device,
                     NMAccessPoint *ap,
                     gboolean recheck_available_connections)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);

	g_signal_emit (device, signals[ACCESS_POINT_REMOVED], 0, ap);
	priv->ap_list = g_slist_remove (priv->ap_list, ap);
	g_object_unref (ap);

	if (recheck_available_connections)
		nm_device_recheck_available_connections (NM_DEVICE (device));
}

static void
remove_all_aps (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	/* Remove outdated APs */
	while (g_slist_length (priv->ap_list)) {
		NMAccessPoint *ap = NM_AP (priv->ap_list->data);
		remove_access_point (self, ap, FALSE);
	}
	g_slist_free (priv->ap_list);
	priv->ap_list = NULL;

	nm_device_recheck_available_connections (NM_DEVICE (self));
}

static void
deactivate (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *orig_ap = nm_device_wifi_get_activation_ap (self);
	NMActRequest *req;
	NMConnection *connection;
	NM80211Mode old_mode = priv->mode;

	req = nm_device_get_act_request (dev);
	if (req) {
		connection = nm_act_request_get_connection (req);
		/* Clear wireless secrets tries when deactivating */
		g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, NULL);
	}

	if (priv->periodic_source_id) {
		g_source_remove (priv->periodic_source_id);
		priv->periodic_source_id = 0;
	}

	cleanup_association_attempt (self, TRUE);

	set_active_ap (self, NULL);
	priv->rate = 0;

	/* If the AP is 'fake', i.e. it wasn't actually found from
	 * a scan but the user tried to connect to it manually (maybe it
	 * was non-broadcasting or something) get rid of it, because 'fake'
	 * APs should only live for as long as we're connected to them.  Fixes
	 * a bug where user-created Ad-Hoc APs are never removed from the scan
	 * list, because scanning is disabled while in Ad-Hoc mode (for stability),
	 * and thus the AP culling never happens. (bgo #569241)
	 */
	if (orig_ap && nm_ap_get_fake (orig_ap))
	    remove_access_point (self, orig_ap, TRUE);

	/* Reset MAC address back to initial address */
	_set_hw_addr (self, priv->initial_hw_addr, "reset");

	/* Ensure we're in infrastructure mode after deactivation; some devices
	 * (usually older ones) don't scan well in adhoc mode.
	 */
	if (wifi_utils_get_mode (priv->wifi_data) != NM_802_11_MODE_INFRA) {
		nm_device_take_down (NM_DEVICE (self), TRUE);
		wifi_utils_set_mode (priv->wifi_data, NM_802_11_MODE_INFRA);
		nm_device_bring_up (NM_DEVICE (self), TRUE, NULL);
	}

	if (priv->mode != NM_802_11_MODE_INFRA) {
		priv->mode = NM_802_11_MODE_INFRA;
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_MODE);
	}

	/* Ensure we trigger a scan after deactivating a Hotspot */
	if (old_mode == NM_802_11_MODE_AP) {
		cancel_pending_scan (self);
		request_wireless_scan (self);
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
check_connection_compatible (NMDevice *device,
                             NMConnection *connection,
                             GError **error)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	const GByteArray *mac;
	const GSList *mac_blacklist, *mac_blacklist_iter;
	const char *mode;

	if (!NM_DEVICE_CLASS (nm_device_wifi_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_WIRELESS_SETTING_NAME)) {
		g_set_error (error,
		             NM_WIFI_ERROR, NM_WIFI_ERROR_CONNECTION_NOT_WIRELESS,
		             "The connection was not a WiFi connection.");
		return FALSE;
	}

	s_wireless = nm_connection_get_setting_wireless (connection);
	if (!s_wireless) {
		g_set_error (error,
		             NM_WIFI_ERROR, NM_WIFI_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid WiFi connection.");
		return FALSE;
	}


	mac = nm_setting_wireless_get_mac_address (s_wireless);
	if (mac && memcmp (mac->data, &priv->perm_hw_addr, ETH_ALEN)) {
		g_set_error (error,
		             NM_WIFI_ERROR, NM_WIFI_ERROR_CONNECTION_INCOMPATIBLE,
		             "The connection's MAC address did not match this device.");
		return FALSE;
	}

	/* Check for MAC address blacklist */
	mac_blacklist = nm_setting_wireless_get_mac_address_blacklist (s_wireless);
	for (mac_blacklist_iter = mac_blacklist; mac_blacklist_iter;
	     mac_blacklist_iter = g_slist_next (mac_blacklist_iter)) {
		struct ether_addr addr;

		if (!ether_aton_r (mac_blacklist_iter->data, &addr)) {
			g_warn_if_reached ();
			continue;
		}
		if (memcmp (&addr, &priv->perm_hw_addr, ETH_ALEN) == 0) {
			g_set_error (error,
			             NM_WIFI_ERROR, NM_WIFI_ERROR_CONNECTION_INCOMPATIBLE,
			             "The connection's MAC address (%s) is blacklisted in %s.",
			             (char *) mac_blacklist_iter->data, NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST);
			return FALSE;
		}
	}

	if (is_adhoc_wpa (connection)) {
		g_set_error_literal (error,
		                     NM_WIFI_ERROR,
		                     NM_WIFI_ERROR_CONNECTION_INCOMPATIBLE,
		                     "WPA Ad-Hoc disabled due to kernel bugs");
		return FALSE;
	}

	/* Early exit if supplicant or device doesn't support requested mode */
	mode = nm_setting_wireless_get_mode (s_wireless);
	if (g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_ADHOC) == 0) {
		if (!(priv->capabilities & NM_WIFI_DEVICE_CAP_ADHOC)) {
			g_set_error_literal (error,
			                     NM_WIFI_ERROR,
			                     NM_WIFI_ERROR_ADHOC_MODE_UNSUPPORTED,
			                     "Ad-Hoc mode is not supported by this device.");
			return FALSE;
		}
	} else if (g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_AP) == 0) {
		if (!(priv->capabilities & NM_WIFI_DEVICE_CAP_AP)) {
			g_set_error_literal (error,
			                     NM_WIFI_ERROR,
			                     NM_WIFI_ERROR_AP_MODE_UNSUPPORTED,
			                     "Access Point (AP) mode is not supported by this device.");
			return FALSE;
		}

		if (priv->supplicant.iface) {
			switch (nm_supplicant_interface_get_ap_support (priv->supplicant.iface)) {
			case AP_SUPPORT_NO:
				g_set_error_literal (error,
				                     NM_WIFI_ERROR,
				                     NM_WIFI_ERROR_AP_MODE_UNSUPPORTED,
				                     "Access Point (AP) mode is not supported by the supplicant.");
				return FALSE;
			case AP_SUPPORT_YES:
			case AP_SUPPORT_UNKNOWN:
			default:
				break;
			}
		}
	}

	// FIXME: check channel/freq/band against bands the hardware supports
	// FIXME: check encryption against device capabilities
	// FIXME: check bitrate against device capabilities

	return TRUE;
}


static gboolean
check_connection_available (NMDevice *device, NMConnection *connection)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	NMSettingWireless *s_wifi;
	const char *mode;
	GSList *ap_iter = NULL;

	s_wifi = nm_connection_get_setting_wireless (connection);

	/* Ad-Hoc and AP connections are always available because they may be
	 * started at any time.
	 */
	mode = nm_setting_wireless_get_mode (s_wifi);
	if (g_strcmp0 (mode, "adhoc") == 0 || g_strcmp0 (mode, "ap") == 0)
		return TRUE;

	/* Hidden SSIDs obviously don't always appear in the scan list either */
	if (nm_setting_wireless_get_hidden (s_wifi))
		return TRUE;

	/* check if its visible */
	for (ap_iter = priv->ap_list; ap_iter; ap_iter = g_slist_next (ap_iter)) {
		if (nm_ap_check_compatible (NM_AP (ap_iter->data), connection))
			return TRUE;
	}

	return FALSE;
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
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSetting8021x *s_8021x;
	const GByteArray *setting_mac;
	char *format, *str_ssid = NULL;
	NMAccessPoint *ap = NULL;
	const GByteArray *ssid = NULL;
	GSList *iter;

	s_wifi = nm_connection_get_setting_wireless (connection);
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	s_8021x = nm_connection_get_setting_802_1x (connection);

	if (!specific_object) {
		/* If not given a specific object, we need at minimum an SSID */
		if (!s_wifi) {
			g_set_error_literal (error,
			                     NM_WIFI_ERROR,
			                     NM_WIFI_ERROR_CONNECTION_INVALID,
			                     "A 'wireless' setting is required if no AP path was given.");
			return FALSE;
		}

		ssid = nm_setting_wireless_get_ssid (s_wifi);
		if (!ssid || !ssid->len) {
			g_set_error_literal (error,
			                     NM_WIFI_ERROR,
			                     NM_WIFI_ERROR_CONNECTION_INVALID,
			                     "A 'wireless' setting with a valid SSID is required if no AP path was given.");
			return FALSE;
		}

		/* Find a compatible AP in the scan list */
		for (iter = priv->ap_list; iter; iter = g_slist_next (iter)) {
			if (nm_ap_check_compatible (NM_AP (iter->data), connection)) {
				ap = NM_AP (iter->data);
				break;
			}
		}

		/* If we still don't have an AP, then the WiFI settings needs to be
		 * fully specified by the client.  Might not be able to find an AP
		 * if the network isn't broadcasting the SSID for example.
		 */
		if (!ap) {
			GSList *settings = NULL;
			gboolean valid;

			settings = g_slist_prepend (settings, s_wifi);
			if (s_wsec)
				settings = g_slist_prepend (settings, s_wsec);
			if (s_8021x)
				settings = g_slist_prepend (settings, s_8021x);
			valid = nm_setting_verify (NM_SETTING (s_wifi), settings, error);
			g_slist_free (settings);
			if (!valid)
				return FALSE;
		}
	} else {
		ap = get_ap_by_path (self, specific_object);
		if (!ap) {
			g_set_error (error,
			             NM_WIFI_ERROR,
			             NM_WIFI_ERROR_ACCESS_POINT_NOT_FOUND,
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

	if (ap) {
		ssid = nm_ap_get_ssid (ap);

		if (ssid == NULL) {
			/* The AP must be hidden.  Connecting to a WiFi AP requires the SSID
			 * as part of the initial handshake, so check the connection details
			 * for the SSID.  The AP object will still be used for encryption
			 * settings and such.
			 */
			ssid = nm_setting_wireless_get_ssid (s_wifi);
		}

		if (ssid == NULL) {
			/* If there's no SSID on the AP itself, and no SSID in the
			 * connection data, then we cannot connect at all.  Return an error.
			 */
			g_set_error_literal (error,
			                     NM_WIFI_ERROR,
			                     NM_WIFI_ERROR_CONNECTION_INVALID,
			                     "A 'wireless' setting with a valid SSID is required for hidden access points.");
			return FALSE;
		}

		/* If the SSID is a well-known SSID, lock the connection to the AP's
		 * specific BSSID so NM doesn't autoconnect to some random wifi net.
		 */
		if (!nm_ap_complete_connection (ap,
		                                connection,
		                                is_manf_default_ssid (ssid),
		                                error))
			return FALSE;
	}

	/* The kernel doesn't support Ad-Hoc WPA connections well at this time,
	 * and turns them into open networks.  It's been this way since at least
	 * 2.6.30 or so; until that's fixed, disable WPA-protected Ad-Hoc networks.
	 */
	if (is_adhoc_wpa (connection)) {
		g_set_error_literal (error,
		                     NM_SETTING_WIRELESS_ERROR,
		                     NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
		                     "WPA Ad-Hoc disabled due to kernel bugs");
		return FALSE;
	}

	g_assert (ssid);
	str_ssid = nm_utils_ssid_to_utf8 (ssid);
	format = g_strdup_printf ("%s %%d", str_ssid);

	nm_utils_complete_generic (connection,
	                           NM_SETTING_WIRELESS_SETTING_NAME,
	                           existing_connections,
	                           format,
	                           str_ssid,
	                           TRUE);
	g_free (str_ssid);
	g_free (format);

	setting_mac = nm_setting_wireless_get_mac_address (s_wifi);
	if (setting_mac) {
		/* Make sure the setting MAC (if any) matches the device's permanent MAC */
		if (memcmp (setting_mac->data, priv->perm_hw_addr, ETH_ALEN)) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_ERROR,
			             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
			             NM_SETTING_WIRELESS_MAC_ADDRESS);
			return FALSE;
		}
	} else {
		GByteArray *mac;
		const guint8 null_mac[ETH_ALEN] = { 0, 0, 0, 0, 0, 0 };

		/* Lock the connection to this device by default if it uses a
		 * permanent MAC address (ie not a 'locally administered' one)
		 */
		if (   !(priv->perm_hw_addr[0] & 0x02)
		    && memcmp (priv->perm_hw_addr, null_mac, ETH_ALEN)) {
			mac = g_byte_array_sized_new (ETH_ALEN);
			g_byte_array_append (mac, priv->perm_hw_addr, ETH_ALEN);
			g_object_set (G_OBJECT (s_wifi), NM_SETTING_WIRELESS_MAC_ADDRESS, mac, NULL);
			g_byte_array_free (mac, TRUE);
		}
	}

	return TRUE;
}

static gboolean
is_available (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSupplicantInterface *sup_iface;
	guint32 state;

	if (!priv->enabled) {
		nm_log_dbg (LOGD_WIFI, "(%s): not available because not enabled",
		            nm_device_get_iface (dev));
		return FALSE;
	}

	sup_iface = priv->supplicant.iface;
	if (!sup_iface) {
		nm_log_dbg (LOGD_WIFI, "(%s): not available because supplicant not running",
		            nm_device_get_iface (dev));
		return FALSE;
	}

	state = nm_supplicant_interface_get_state (sup_iface);
	if (   state < NM_SUPPLICANT_INTERFACE_STATE_READY
	    || state > NM_SUPPLICANT_INTERFACE_STATE_COMPLETED) {
		nm_log_dbg (LOGD_WIFI, "(%s): not available because supplicant interface not ready",
		            nm_device_get_iface (dev));
		return FALSE;
	}

	return TRUE;
}

static gboolean
can_auto_connect (NMDevice *dev,
                  NMConnection *connection,
                  char **specific_object)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	GSList *ap_iter;
	NMSettingIP4Config *s_ip4;
	const char *method = NULL;
	guint64 timestamp = 0;

	if (!NM_DEVICE_CLASS (nm_device_wifi_parent_class)->can_auto_connect (dev, connection, specific_object))
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
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (s_ip4) {
		method = nm_setting_ip4_config_get_method (s_ip4);
		if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
			return TRUE;
	}

	for (ap_iter = priv->ap_list; ap_iter; ap_iter = g_slist_next (ap_iter)) {
		NMAccessPoint *ap = NM_AP (ap_iter->data);

		if (nm_ap_check_compatible (ap, connection)) {
			/* All good; connection is usable */
			*specific_object = (char *) nm_ap_get_dbus_path (ap);
			return TRUE;
		}
	}

	return FALSE;
}

static void
ap_list_dump (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	GSList * elt;
	int i = 0;

	g_return_if_fail (NM_IS_DEVICE_WIFI (self));

	nm_log_dbg (LOGD_WIFI_SCAN, "Current AP list:");
	for (elt = priv->ap_list; elt; elt = g_slist_next (elt), i++) {
		NMAccessPoint * ap = NM_AP (elt->data);
		nm_ap_dump (ap, "List AP: ");
	}
	nm_log_dbg (LOGD_WIFI_SCAN, "Current AP list: done");
}

static gboolean
impl_device_get_access_points (NMDeviceWifi *self,
                               GPtrArray **aps,
                               GError **err)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	GSList *elt;

	*aps = g_ptr_array_new ();

	for (elt = priv->ap_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint * ap = NM_AP (elt->data);

		if (nm_ap_get_ssid (ap))
			g_ptr_array_add (*aps, g_strdup (nm_ap_get_dbus_path (ap)));
	}
	return TRUE;
}

static void
request_scan_cb (NMDevice *device,
                 DBusGMethodInvocation *context,
                 GError *error,
                 gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);

	if (error) {
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
	} else if (!check_scanning_allowed (self)) {
		error = g_error_new_literal (NM_WIFI_ERROR,
		                             NM_WIFI_ERROR_SCAN_NOT_ALLOWED,
		                             "Scanning not allowed at this time");
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	} else {
		cancel_pending_scan (self);
		request_wireless_scan (self);
		dbus_g_method_return (context);
	}
}

static void
impl_device_request_scan (NMDeviceWifi *self,
                          GHashTable *options,
                          DBusGMethodInvocation *context)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	time_t last_scan;
	GError *error;

	if (   !priv->enabled
	    || !priv->supplicant.iface
	    || nm_device_get_state (device) < NM_DEVICE_STATE_DISCONNECTED
	    || nm_device_is_activating (device)) {
		error = g_error_new_literal (NM_WIFI_ERROR,
		                             NM_WIFI_ERROR_SCAN_NOT_ALLOWED,
		                             "Scanning not allowed while unavailable or activating");
		goto error;
	}

	if (nm_supplicant_interface_get_scanning (priv->supplicant.iface)) {
		error = g_error_new_literal (NM_WIFI_ERROR,
		                             NM_WIFI_ERROR_SCAN_NOT_ALLOWED,
		                             "Scanning not allowed while already scanning");
		goto error;
	}

	last_scan = nm_supplicant_interface_get_last_scan_time (priv->supplicant.iface);
	if ((time (NULL) - last_scan) < 10) {
		error = g_error_new_literal (NM_WIFI_ERROR,
		                             NM_WIFI_ERROR_SCAN_NOT_ALLOWED,
		                             "Scanning not allowed immediately following previous scan");
		goto error;
	}

	/* Ask the manager to authenticate this request for us */
	g_signal_emit_by_name (device,
	                       NM_DEVICE_AUTH_REQUEST,
	                       context,
	                       NM_AUTH_PERMISSION_NETWORK_CONTROL,
	                       TRUE,
	                       request_scan_cb,
	                       NULL);
	return;

error:
	dbus_g_method_return_error (context, error);
	g_error_free (error);
}

static gboolean
scanning_allowed (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	guint32 sup_state;
	NMActRequest *req;

	g_return_val_if_fail (priv->supplicant.iface != NULL, FALSE);

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
	sup_state = nm_supplicant_interface_get_state (priv->supplicant.iface);
	if (   sup_state == NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING
	    || sup_state == NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED
	    || sup_state == NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE
	    || sup_state == NM_SUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE
	    || nm_supplicant_interface_get_scanning (priv->supplicant.iface))
		return FALSE;

	req = nm_device_get_act_request (NM_DEVICE (self));
	if (req) {
		NMConnection *connection;
		NMSettingIP4Config *s_ip4;
		NMSettingWireless *s_wifi;
		const char *ip4_method = NULL;
		const GByteArray *bssid;

		/* Don't scan when a shared connection is active; it makes drivers mad */
		connection = nm_act_request_get_connection (req);
		s_ip4 = nm_connection_get_setting_ip4_config (connection);
		if (s_ip4)
			ip4_method = nm_setting_ip4_config_get_method (s_ip4);

		if (s_ip4 && !strcmp (ip4_method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
			return FALSE;

		/* Don't scan when the connection is locked to a specifc AP, since
		 * intra-ESS roaming (which requires periodic scanning) isn't being
		 * used due to the specific AP lock. (bgo #513820)
		 */
		s_wifi = nm_connection_get_setting_wireless (connection);
		g_assert (s_wifi);
		bssid = nm_setting_wireless_get_bssid (s_wifi);
		if (bssid && bssid->len == ETH_ALEN)
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
	guint max_scan_ssids = nm_supplicant_interface_get_max_scan_ssids (priv->supplicant.iface);
	NMConnectionProvider *provider = nm_device_get_connection_provider (NM_DEVICE (self));
	GSList *connections, *iter;
	GPtrArray *ssids = NULL;
	static GByteArray *nullssid = NULL;

	/* Need at least two: wildcard SSID and one or more hidden SSIDs */
	if (max_scan_ssids < 2)
		return NULL;

	/* Static wildcard SSID used for every scan */
	if (G_UNLIKELY (nullssid == NULL))
		nullssid = g_byte_array_new ();

	connections = nm_connection_provider_get_best_connections (provider,
	                                                           max_scan_ssids - 1,
	                                                           NM_SETTING_WIRELESS_SETTING_NAME,
	                                                           NULL,
	                                                           hidden_filter_func,
	                                                           NULL);
	if (connections && connections->data) {
		ssids = g_ptr_array_sized_new (max_scan_ssids - 1);
		g_ptr_array_add (ssids, nullssid);  /* Add wildcard SSID */
	}

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = iter->data;
		NMSettingWireless *s_wifi;
		const GByteArray *ssid;

		s_wifi = (NMSettingWireless *) nm_connection_get_setting_wireless (connection);
		g_assert (s_wifi);
		ssid = nm_setting_wireless_get_ssid (s_wifi);
		g_assert (ssid);
		g_ptr_array_add (ssids, (gpointer) ssid);
	}
	g_slist_free (connections);

	return ssids;
}

static gboolean
request_wireless_scan (gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	gboolean backoff = FALSE;
	GPtrArray *ssids = NULL;

	if (check_scanning_allowed (self)) {
		nm_log_dbg (LOGD_WIFI_SCAN, "(%s): scanning requested",
		            nm_device_get_iface (NM_DEVICE (self)));

		ssids = build_hidden_probe_list (self);

		if (nm_logging_level_enabled (LOGL_DEBUG)) {
			if (ssids) {
				guint i;
				char *foo;

				for (i = 0; i < ssids->len; i++) {
					foo = nm_utils_ssid_to_utf8 (g_ptr_array_index (ssids, i));
					nm_log_dbg (LOGD_WIFI_SCAN, "(%s): (%d) probe scanning SSID '%s'",
					            nm_device_get_iface (NM_DEVICE (self)),
					            i, foo ? foo : "<hidden>");
					g_free (foo);
				}
			} else {
				nm_log_dbg (LOGD_WIFI_SCAN, "(%s): no SSIDs to probe scan",
				            nm_device_get_iface (NM_DEVICE (self)));
			}
		}

		if (nm_supplicant_interface_request_scan (priv->supplicant.iface, ssids)) {
			/* success */
			backoff = TRUE;
		}

		if (ssids) {
			/* Elements owned by the connections, so we don't free them here */
			g_ptr_array_free (ssids, TRUE);
		}
	} else {
		nm_log_dbg (LOGD_WIFI_SCAN, "(%s): scan requested but not allowed at this time",
		            nm_device_get_iface (NM_DEVICE (self)));
	}

	priv->pending_scan_id = 0;
	schedule_scan (self, backoff);
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
	time_t now = time (NULL);

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
		                                               request_wireless_scan,
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

		nm_log_dbg (LOGD_WIFI_SCAN, "(%s): scheduled scan in %d seconds (interval now %d seconds)",
		            nm_device_get_iface (NM_DEVICE (self)),
		            next_scan,
		            priv->scan_interval);

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
	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): scan %s",
	            nm_device_get_iface (NM_DEVICE (self)),
	            success ? "successful" : "failed");

	schedule_scan (self, success);

	/* Ensure that old APs get removed, which otherwise only
	 * happens when there are new BSSes.
	 */
	schedule_scanlist_cull (self);
}


/****************************************************************************
 * WPA Supplicant control stuff
 *
 */

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((guint8*)(x))[0],((guint8*)(x))[1],((guint8*)(x))[2],((guint8*)(x))[3],((guint8*)(x))[4],((guint8*)(x))[5]

/*
 * merge_scanned_ap
 *
 * If there is already an entry that matches the BSSID and ESSID of the
 * AP to merge, replace that entry with the scanned AP.  Otherwise, add
 * the scanned AP to the list.
 *
 * TODO: possibly need to differentiate entries based on security too; i.e. if
 * there are two scan results with the same BSSID and SSID but different
 * security options?
 *
 */
static void
merge_scanned_ap (NMDeviceWifi *self,
                  NMAccessPoint *merge_ap)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *found_ap = NULL;
	const GByteArray *ssid;
	const struct ether_addr *bssid;
	gboolean strict_match = TRUE;
	NMAccessPoint *current_ap = NULL;

	/* Let the manager try to fill in the SSID from seen-bssids lists */
	bssid = nm_ap_get_address (merge_ap);
	ssid = nm_ap_get_ssid (merge_ap);
	if (!ssid || nm_utils_is_empty_ssid (ssid->data, ssid->len)) {
		/* Let the manager try to fill the AP's SSID from the database */
		g_signal_emit (self, signals[HIDDEN_AP_FOUND], 0, merge_ap);

		ssid = nm_ap_get_ssid (merge_ap);
		if (ssid && (nm_utils_is_empty_ssid (ssid->data, ssid->len) == FALSE)) {
			/* Yay, matched it, no longer treat as hidden */
			nm_log_dbg (LOGD_WIFI_SCAN, "(%s): matched hidden AP " MAC_FMT " => '%s'",
			            nm_device_get_iface (NM_DEVICE (self)),
			            MAC_ARG (bssid->ether_addr_octet),
			            nm_utils_escape_ssid (ssid->data, ssid->len));
			nm_ap_set_broadcast (merge_ap, FALSE);
		} else {
			/* Didn't have an entry for this AP in the database */
			nm_log_dbg (LOGD_WIFI_SCAN, "(%s): failed to match hidden AP " MAC_FMT,
			            nm_device_get_iface (NM_DEVICE (self)),
			            MAC_ARG (bssid->ether_addr_octet));
		}
	}

	/* If the incoming scan result matches the hidden AP that NM is currently
	 * connected to but hasn't been seen in the scan list yet, don't use
	 * strict matching.  Because the capabilities of the fake AP have to be
	 * constructed from the NMConnection of the activation request, they won't
	 * always be the same as the capabilities of the real AP from the scan.
	 */
	current_ap = nm_device_wifi_get_activation_ap (self);
	if (current_ap && nm_ap_get_fake (current_ap))
		strict_match = FALSE;

	found_ap = get_ap_by_supplicant_path (self, nm_ap_get_supplicant_path (merge_ap));
	if (!found_ap)
		found_ap = nm_ap_match_in_list (merge_ap, priv->ap_list, strict_match);
	if (found_ap) {
		nm_log_dbg (LOGD_WIFI_SCAN, "(%s): merging AP '%s' " MAC_FMT " (%p) with existing (%p)",
		            nm_device_get_iface (NM_DEVICE (self)),
		            ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)",
		            MAC_ARG (bssid->ether_addr_octet),
		            merge_ap,
		            found_ap);

		nm_ap_set_supplicant_path (found_ap, nm_ap_get_supplicant_path (merge_ap));
		nm_ap_set_flags (found_ap, nm_ap_get_flags (merge_ap));
		nm_ap_set_wpa_flags (found_ap, nm_ap_get_wpa_flags (merge_ap));
		nm_ap_set_rsn_flags (found_ap, nm_ap_get_rsn_flags (merge_ap));
		nm_ap_set_strength (found_ap, nm_ap_get_strength (merge_ap));
		nm_ap_set_last_seen (found_ap, nm_ap_get_last_seen (merge_ap));
		nm_ap_set_broadcast (found_ap, nm_ap_get_broadcast (merge_ap));
		nm_ap_set_freq (found_ap, nm_ap_get_freq (merge_ap));
		nm_ap_set_max_bitrate (found_ap, nm_ap_get_max_bitrate (merge_ap));

		/* If the AP is noticed in a scan, it's automatically no longer
		 * fake, since it clearly exists somewhere.
		 */
		nm_ap_set_fake (found_ap, FALSE);
	} else {
		/* New entry in the list */
		nm_log_dbg (LOGD_WIFI_SCAN, "(%s): adding new AP '%s' " MAC_FMT " (%p)",
		            nm_device_get_iface (NM_DEVICE (self)),
		            ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)",
		            MAC_ARG (bssid->ether_addr_octet),
		            merge_ap);

		g_object_ref (merge_ap);
		priv->ap_list = g_slist_prepend (priv->ap_list, merge_ap);
		nm_ap_export_to_dbus (merge_ap);
		g_signal_emit (self, signals[ACCESS_POINT_ADDED], 0, merge_ap);
		nm_device_recheck_available_connections (NM_DEVICE (self));
	}
}

#define WPAS_REMOVED_TAG "supplicant-removed"

static gboolean
cull_scan_list (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	time_t now = time (NULL);
	GSList *outdated_list = NULL;
	GSList *elt;
	guint32 removed = 0, total = 0;

	priv->scanlist_cull_id = 0;

	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): checking scan list for outdated APs",
	            nm_device_get_iface (NM_DEVICE (self)));

	/* Walk the access point list and remove any access points older than
	 * three times the inactive scan interval.
	 */
	for (elt = priv->ap_list; elt; elt = g_slist_next (elt), total++) {
		NMAccessPoint *ap = elt->data;
		const guint prune_interval_s = SCAN_INTERVAL_MAX * 3;

		/* Don't cull the associated AP or manually created APs */
		if (ap == priv->current_ap || nm_ap_get_fake (ap))
			continue;

		/* Don't cull APs still known to the supplicant.  Since the supplicant
		 * doesn't yet emit property updates for "last seen" we have to rely
		 * on changing signal strength for updating "last seen".  But if the
		 * AP's strength doesn't change we won't get any updates for the AP,
		 * and we'll end up here even if the AP was still found by the
		 * supplicant in the last scan.
		 */
		if (   nm_ap_get_supplicant_path (ap)
		    && g_object_get_data (G_OBJECT (ap), WPAS_REMOVED_TAG) == NULL)
			continue;

		if (nm_ap_get_last_seen (ap) + prune_interval_s < now)
			outdated_list = g_slist_append (outdated_list, ap);
	}

	/* Remove outdated APs */
	for (elt = outdated_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint *outdated_ap = NM_AP (elt->data);
		const struct ether_addr *bssid;
		const GByteArray *ssid;

		bssid = nm_ap_get_address (outdated_ap);
		ssid = nm_ap_get_ssid (outdated_ap);
		nm_log_dbg (LOGD_WIFI_SCAN,
		            "   removing %02x:%02x:%02x:%02x:%02x:%02x (%s%s%s)",
		            bssid->ether_addr_octet[0], bssid->ether_addr_octet[1],
		            bssid->ether_addr_octet[2], bssid->ether_addr_octet[3],
		            bssid->ether_addr_octet[4], bssid->ether_addr_octet[5],
		            ssid ? "'" : "",
		            ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)",
		            ssid ? "'" : "");

		remove_access_point (self, outdated_ap, TRUE);
		removed++;
	}
	g_slist_free (outdated_list);

	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): removed %d APs (of %d)",
	            nm_device_get_iface (NM_DEVICE (self)),
	            removed, total);

	ap_list_dump (self);

	if(removed > 0)
	    nm_device_recheck_available_connections (NM_DEVICE (self));

	return FALSE;
}

static void
schedule_scanlist_cull (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	/* Cull the scan list after the last request for it has come in */
	if (priv->scanlist_cull_id)
		g_source_remove (priv->scanlist_cull_id);
	priv->scanlist_cull_id = g_timeout_add_seconds (4, (GSourceFunc) cull_scan_list, self);
}

static void
supplicant_iface_new_bss_cb (NMSupplicantInterface *iface,
                             const char *object_path,
                             GHashTable *properties,
                             NMDeviceWifi *self)
{
	NMDeviceState state;
	NMAccessPoint *ap;

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
	if (ap) {
		nm_ap_dump (ap, "New AP: ");

		/* Add the AP to the device's AP list */
		merge_scanned_ap (self, ap);
		g_object_unref (ap);
	} else {
		nm_log_warn (LOGD_WIFI_SCAN, "(%s): invalid AP properties received",
		             nm_device_get_iface (NM_DEVICE (self)));
	}

	/* Remove outdated access points */
	schedule_scanlist_cull (self);
}

static void
supplicant_iface_bss_updated_cb (NMSupplicantInterface *iface,
                                 const char *object_path,
                                 GHashTable *properties,
                                 NMDeviceWifi *self)
{
	NMDeviceState state;
	NMAccessPoint *ap;

	g_return_if_fail (self != NULL);
	g_return_if_fail (object_path != NULL);
	g_return_if_fail (properties != NULL);

	/* Ignore new APs when unavailable or unamnaged */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state <= NM_DEVICE_STATE_UNAVAILABLE)
		return;

	/* Update the AP's last-seen property */
	ap = get_ap_by_supplicant_path (self, object_path);
	if (ap)
		nm_ap_set_last_seen (ap, (guint32) time (NULL));

	/* Remove outdated access points */
	schedule_scanlist_cull (self);
}

static void
supplicant_iface_bss_removed_cb (NMSupplicantInterface *iface,
                                 const char *object_path,
                                 NMDeviceWifi *self)
{
	NMAccessPoint *ap;

	g_return_if_fail (self != NULL);
	g_return_if_fail (object_path != NULL);

	ap = get_ap_by_supplicant_path (self, object_path);
	if (ap)
		g_object_set_data (G_OBJECT (ap), WPAS_REMOVED_TAG, GUINT_TO_POINTER (TRUE));
}


static void
cleanup_association_attempt (NMDeviceWifi *self, gboolean disconnect)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	remove_supplicant_interface_error_handler (self);
	remove_supplicant_timeouts (self);
	if (disconnect && priv->supplicant.iface)
		nm_supplicant_interface_disconnect (priv->supplicant.iface);
}

static void
wifi_secrets_cb (NMActRequest *req,
                 guint32 call_id,
                 NMConnection *connection,
                 GError *error,
                 gpointer user_data)
{
	NMDevice *dev = NM_DEVICE (user_data);

	g_return_if_fail (req == nm_device_get_act_request (dev));
	g_return_if_fail (nm_device_get_state (dev) == NM_DEVICE_STATE_NEED_AUTH);
	g_return_if_fail (nm_act_request_get_connection (req) == connection);

	if (error) {
		nm_log_warn (LOGD_WIFI, "%s", error->message);
		nm_device_state_changed (dev,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_NO_SECRETS);
	} else
		nm_device_activate_schedule_stage1_device_prepare (dev);
}

static void
remove_link_timeout (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;

	g_return_if_fail (self != NULL);
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->link_timeout_id) {
		g_source_remove (priv->link_timeout_id);
		priv->link_timeout_id = 0;
	}
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
	NMDevice *dev = NM_DEVICE (user_data);
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *ap;

	nm_log_warn (LOGD_WIFI, "(%s): link timed out.", nm_device_get_iface (dev));

	priv->link_timeout_id = 0;

	/* Disconnect event while activated; the supplicant hasn't been able
	 * to reassociate within the timeout period, so the connection must
	 * fail.
	 */
	if (nm_device_get_state (dev) != NM_DEVICE_STATE_ACTIVATED)
		return FALSE;

	/* If the access point failed, and wasn't found by the supplicant when it
	 * attempted to reconnect, then it's probably out of range or turned off.
	 * Remove it from the list and if it's actually still present, it'll be
	 * found in the next scan.
	 */
	if (priv->ssid_found == FALSE) {
		if (priv->current_ap) {
			ap = priv->current_ap;
			priv->current_ap = NULL;
		} else
			ap = nm_device_wifi_get_activation_ap (self);

		if (ap)
			remove_access_point (self, ap, TRUE);
	}

	nm_device_state_changed (dev,
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
		nm_setting_get_secret_flags (NM_SETTING (s_8021x),
		                             NM_SETTING_802_1X_PASSWORD,
		                             &secret_flags,
		                             NULL);
		if (secret_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
			*setting_name = NM_SETTING_802_1X_SETTING_NAME;
		return *setting_name ? TRUE : FALSE;
	}

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (s_wsec) {
		nm_setting_get_secret_flags (NM_SETTING (s_wsec),
		                             NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
		                             &secret_flags,
		                             NULL);
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

		nm_log_info (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): disconnected during association,"
		             " asking for new key.", nm_device_get_iface (device));

		cleanup_association_attempt (self, TRUE);
		nm_device_state_changed (device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
		nm_act_request_get_secrets (req,
		                            setting_name,
		                            NM_SETTINGS_GET_SECRETS_FLAG_ALLOW_INTERACTION
		                              | NM_SETTINGS_GET_SECRETS_FLAG_REQUEST_NEW,
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

	if (new_state == old_state)
		return;

	nm_log_info (LOGD_DEVICE | LOGD_WIFI,
	             "(%s): supplicant interface state: %s -> %s",
	             nm_device_get_iface (device),
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
		priv->scan_interval = SCAN_INTERVAL_MIN;

		/* If the interface can now be activated because the supplicant is now
		 * available, transition to DISCONNECTED.
		 */
		if ((devstate == NM_DEVICE_STATE_UNAVAILABLE) && nm_device_is_available (device)) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_DISCONNECTED,
			                         NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE);
		}

		nm_log_dbg (LOGD_WIFI_SCAN,
		            "(%s): supplicant ready, requesting initial scan",
		            nm_device_get_iface (device));

		/* Request a scan to get latest results */
		cancel_pending_scan (self);
		request_wireless_scan (self);
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_COMPLETED:
		remove_supplicant_interface_error_handler (self);
		remove_supplicant_timeouts (self);

		/* If this is the initial association during device activation,
		 * schedule the next activation stage.
		 */
		if (devstate == NM_DEVICE_STATE_CONFIG) {
			NMAccessPoint *ap = nm_device_wifi_get_activation_ap (self);
			const GByteArray *ssid = nm_ap_get_ssid (ap);

			nm_log_info (LOGD_DEVICE | LOGD_WIFI,
			             "Activation (%s/wireless) Stage 2 of 5 (Device Configure) "
			             "successful.  %s '%s'.",
			             nm_device_get_iface (device),
			             priv->mode == NM_802_11_MODE_AP ? "Started Wi-Fi Hotspot" :
			                 "Connected to wireless network",
			             ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");
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
		cleanup_association_attempt (self, FALSE);

		/* If the device is already in UNAVAILABLE state then the state change
		 * is a NOP and the interface won't be re-acquired in the device state
		 * change handler.  So ensure we have a new one here so that we're
		 * ready if the supplicant comes back.
		 */
		supplicant_interface_release (self);
		supplicant_interface_acquire (self);

		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_UNAVAILABLE,
		                         NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		break;
	default:
		break;
	}

	/* Signal scanning state changes */
	if (   new_state == NM_SUPPLICANT_INTERFACE_STATE_SCANNING
	    || old_state == NM_SUPPLICANT_INTERFACE_STATE_SCANNING)
		g_object_notify (G_OBJECT (self), "scanning");
}

struct iface_con_error_cb_data {
	NMDeviceWifi *self;
	char *name;
	char *message;
};

static gboolean
supplicant_iface_connection_error_cb_handler (gpointer user_data)
{
	NMDeviceWifi *self;
	NMDeviceWifiPrivate *priv;
	struct iface_con_error_cb_data * cb_data = (struct iface_con_error_cb_data *) user_data;

	g_return_val_if_fail (cb_data != NULL, FALSE);

	self = cb_data->self;
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (!nm_device_is_activating (NM_DEVICE (self)))
		goto out;

	nm_log_info (LOGD_DEVICE | LOGD_WIFI,
	             "Activation (%s/wireless): association request to the supplicant "
	             "failed: %s - %s",
	             nm_device_get_iface (NM_DEVICE (self)),
	             cb_data->name,
	             cb_data->message);

	cleanup_association_attempt (self, TRUE);
	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);

out:
	priv->supplicant.iface_con_error_cb_id = 0;
	g_free (cb_data->name);
	g_free (cb_data->message);
	g_slice_free (struct iface_con_error_cb_data, cb_data);
	return FALSE;
}


static void
supplicant_iface_connection_error_cb (NMSupplicantInterface * iface,
                                      const char * name,
                                      const char * message,
                                      NMDeviceWifi * self)
{
	NMDeviceWifiPrivate *priv;
	struct iface_con_error_cb_data *cb_data;
	guint id;

	g_return_if_fail (self != NULL);
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	cb_data = g_slice_new0 (struct iface_con_error_cb_data);
	cb_data->self = self;
	cb_data->name = g_strdup (name);
	cb_data->message = g_strdup (message);

	if (priv->supplicant.iface_con_error_cb_id)
		g_source_remove (priv->supplicant.iface_con_error_cb_id);

	id = g_idle_add (supplicant_iface_connection_error_cb_handler, cb_data);
	priv->supplicant.iface_con_error_cb_id = id;
}

static void
supplicant_iface_notify_scanning_cb (NMSupplicantInterface *iface,
                                     GParamSpec *pspec,
                                     NMDeviceWifi *self)
{
	NMDeviceState state;
	gboolean scanning;

	scanning = nm_supplicant_interface_get_scanning (iface);
	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): now %s",
	            nm_device_get_iface (NM_DEVICE (self)),
	            scanning ? "scanning" : "idle");

	g_object_notify (G_OBJECT (self), "scanning");

	/* Run a quick update of current AP when coming out of a scan */
	state = nm_device_get_state (NM_DEVICE (self));
	if (!scanning && state == NM_DEVICE_STATE_ACTIVATED)
		periodic_update (self);
}

static void
remove_supplicant_connection_timeout (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;

	g_return_if_fail (self != NULL);
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	/* Remove any pending timeouts on the request */
	if (priv->supplicant.con_timeout_id) {
		g_source_remove (priv->supplicant.con_timeout_id);
		priv->supplicant.con_timeout_id = 0;
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
		NMSettingsGetSecretsFlags flags = NM_SETTINGS_GET_SECRETS_FLAG_ALLOW_INTERACTION;

		if (new_secrets)
			flags |= NM_SETTINGS_GET_SECRETS_FLAG_REQUEST_NEW;
		nm_act_request_get_secrets (req, setting_name, flags, NULL, wifi_secrets_cb, self);

		g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, GUINT_TO_POINTER (++tries));
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else
		nm_log_warn (LOGD_DEVICE, "Cleared secrets, but setting didn't need any secrets.");

	return ret;
}

static gboolean
is_encrypted (NMAccessPoint *ap, NMConnection *connection)
{
	NM80211ApFlags flags;
	NM80211ApSecurityFlags wpa_flags, rsn_flags;

	g_return_val_if_fail (ap != NULL, FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);

	flags = nm_ap_get_flags (ap);
	wpa_flags = nm_ap_get_wpa_flags (ap);
	rsn_flags = nm_ap_get_rsn_flags (ap);

	if (flags & NM_802_11_AP_FLAGS_PRIVACY)
		return TRUE;
	if (wpa_flags & (NM_802_11_AP_SEC_KEY_MGMT_PSK | NM_802_11_AP_SEC_KEY_MGMT_802_1X))
		return TRUE;
	if (rsn_flags & (NM_802_11_AP_SEC_KEY_MGMT_PSK | NM_802_11_AP_SEC_KEY_MGMT_802_1X))
		return TRUE;

	return FALSE;
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
	NMDevice *dev = NM_DEVICE (user_data);
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *ap;
	NMActRequest *req;
	NMConnection *connection;

	cleanup_association_attempt (self, TRUE);

	if (!nm_device_is_activating (dev))
		return FALSE;

	/* Timed out waiting for a successful connection to the AP; if the AP's
	 * security requires network-side authentication (like WPA or 802.1x)
	 * and the connection attempt timed out then it's likely the authentication
	 * information (passwords, pin codes, etc) are wrong.
	 */

	req = nm_device_get_act_request (dev);
	g_assert (req);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	if (   priv->mode == NM_802_11_MODE_ADHOC
	    || priv->mode == NM_802_11_MODE_AP) {
		/* In Ad-Hoc and AP modes there's nothing to check the encryption key
		 * (if any), so supplicant timeouts here are almost certainly the wifi
		 * driver being really stupid.
		 */
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): %s network creation took "
		             "too long, failing activation.",
		             nm_device_get_iface (dev),
		             priv->mode == NM_802_11_MODE_ADHOC ? "Ad-Hoc" : "Hotspot");
		nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT);
		return FALSE;
	}

	g_assert (priv->mode == NM_802_11_MODE_INFRA);
	ap = nm_device_wifi_get_activation_ap (self);
	g_assert (ap);

	if (priv->ssid_found && is_encrypted (ap, connection)) {
		guint64 timestamp = 0;
		gboolean new_secrets = TRUE;

		/* Connection failed; either driver problems, the encryption key is
		 * wrong, or the passwords or certificates were wrong.
		 */
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): association took too long.",
		             nm_device_get_iface (dev));

		/* Ask for new secrets only if we've never activated this connection
		 * before.  If we've connected before, don't bother the user with
		 * dialogs, just retry or fail, and if we never connect the user can
		 * fix the password somewhere else.
		 */
		if (nm_settings_connection_get_timestamp (NM_SETTINGS_CONNECTION (connection), &timestamp))
			new_secrets = !timestamp;

		if (handle_auth_or_fail (self, req, new_secrets) == NM_ACT_STAGE_RETURN_POSTPONE) {
			nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
			             "Activation (%s/wireless): asking for new secrets",
			             nm_device_get_iface (dev));
		} else {
			nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_NO_SECRETS);
		}
	} else {
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): association took too long, "
		             "failing activation.",
		             nm_device_get_iface (dev));
		nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED,
		                         priv->ssid_found ? NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT :
		                                            NM_DEVICE_STATE_REASON_SSID_NOT_FOUND);
	}

	return FALSE;
}


static gboolean
start_supplicant_connection_timeout (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;
	guint id;

	g_return_val_if_fail (self != NULL, FALSE);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	/* Set up a timeout on the connection attempt to fail it after 25 seconds */
	id = g_timeout_add_seconds (25, supplicant_connection_timeout_cb, self);
	if (id == 0) {
		nm_log_err (LOGD_DEVICE | LOGD_WIFI,
		            "Activation (%s/wireless): couldn't start supplicant "
		            "timeout timer.",
		            nm_device_get_iface (NM_DEVICE (self)));
		return FALSE;
	}
	priv->supplicant.con_timeout_id = id;
	return TRUE;
}


static void
remove_supplicant_timeouts (NMDeviceWifi *self)
{
	g_return_if_fail (self != NULL);

	remove_supplicant_connection_timeout (self);
	remove_link_timeout (self);
}

static NMSupplicantConfig *
build_supplicant_config (NMDeviceWifi *self,
                         NMConnection *connection,
                         NMAccessPoint *ap)
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
	    && nm_supplicant_interface_get_ap_support (priv->supplicant.iface) == AP_SUPPORT_UNKNOWN) {
		nm_log_warn (LOGD_WIFI, "Supplicant may not support AP mode; connection may time out.");
	}

	if (!nm_supplicant_config_add_setting_wireless (config,
	                                                s_wireless,
	                                                nm_ap_get_broadcast (ap),
	                                                nm_ap_get_freq (ap),
	                                                wifi_utils_can_scan_ssid (priv->wifi_data))) {
		nm_log_err (LOGD_WIFI, "Couldn't add 802-11-wireless setting to supplicant config.");
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
			nm_log_err (LOGD_WIFI, "Couldn't add 802-11-wireless-security setting to "
			            "supplicant config.");
			goto error;
		}
	} else {
		if (!nm_supplicant_config_add_no_security (config)) {
			nm_log_err (LOGD_WIFI, "Couldn't add unsecured option to supplicant config.");
			goto error;
		}
	}

	return config;

error:
	g_object_unref (config);
	return NULL;
}

/****************************************************************************/

static void
update_permanent_hw_address (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	struct ifreq req;
	struct ethtool_perm_addr *epaddr = NULL;
	int fd, ret;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_err (LOGD_HW, "could not open control socket.");
		return;
	}

	/* Get permanent MAC address */
	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), IFNAMSIZ);

	epaddr = g_malloc0 (sizeof (struct ethtool_perm_addr) + ETH_ALEN);
	epaddr->cmd = ETHTOOL_GPERMADDR;
	epaddr->size = ETH_ALEN;
	req.ifr_data = (void *) epaddr;

	errno = 0;
	ret = ioctl (fd, SIOCETHTOOL, &req);
	if ((ret < 0) || !nm_ethernet_address_is_valid ((struct ether_addr *) epaddr->data)) {
		nm_log_dbg (LOGD_HW | LOGD_ETHER, "(%s): unable to read permanent MAC address (error %d)",
		            nm_device_get_iface (dev), errno);
		/* Fall back to current address */
		memcpy (epaddr->data, nm_device_get_hw_address (dev, NULL), ETH_ALEN);
	}

	if (memcmp (&priv->perm_hw_addr, epaddr->data, ETH_ALEN)) {
		memcpy (&priv->perm_hw_addr, epaddr->data, ETH_ALEN);
		g_object_notify (G_OBJECT (dev), NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS);
	}

	g_free (epaddr);
	close (fd);
}

static void
update_initial_hw_address (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	char *mac_str;

	/* This sets initial MAC address from current MAC address. It should only
	 * be called from NMDevice constructor() to really get the initial address.
	 */
	memcpy (priv->initial_hw_addr, nm_device_get_hw_address (dev, NULL), ETH_ALEN);
 
	mac_str = nm_utils_hwaddr_ntoa (priv->initial_hw_addr, ARPHRD_ETHER);
	nm_log_dbg (LOGD_DEVICE | LOGD_ETHER, "(%s): read initial MAC address %s",
	            nm_device_get_iface (dev), mac_str);
	g_free (mac_str);
}

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *ap = NULL;
	NMActRequest *req;
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	const GByteArray *cloned_mac;
	GSList *iter;
	const char *mode;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_val_if_fail (req != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_act_request_get_connection (req);
	g_return_val_if_fail (connection != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (g_strcmp0 (mode, "infra") == 0)
		priv->mode = NM_802_11_MODE_INFRA;
	else if (g_strcmp0 (mode, "adhoc") == 0)
		priv->mode = NM_802_11_MODE_ADHOC;
	else if (g_strcmp0 (mode, "ap") == 0) {
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
		nm_log_warn (LOGD_WIFI, "Ad-Hoc WPA disabled due to kernel bugs");
		*reason = NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	/* Set spoof MAC to the interface */
	cloned_mac = nm_setting_wireless_get_cloned_mac_address (s_wireless);
	if (cloned_mac && (cloned_mac->len == ETH_ALEN))
		_set_hw_addr (self, (const guint8 *) cloned_mac->data, "set");

	/* AP mode never uses a specific object or existing scanned AP */
	if (priv->mode != NM_802_11_MODE_AP) {
		ap = nm_device_wifi_get_activation_ap (self);
		if (ap)
			goto done;

		/* Find a compatible AP in the scan list */
		for (iter = priv->ap_list; iter; iter = g_slist_next (iter)) {
			NMAccessPoint *candidate = NM_AP (iter->data);

			if (nm_ap_check_compatible (candidate, connection)) {
				ap = candidate;
				break;
			}
		}
	}

	/* If the user is trying to connect to an AP that NM doesn't yet know about
	 * (hidden network or something) or starting a Hotspot, create an fake AP
	 * from the security settings in the connection.  This "fake" AP gets used
	 * until the real one is found in the scan list (Ad-Hoc or Hidden), or until
	 * the device is deactivated (Hotspot).
	 */
	if (!ap) {
		ap = nm_ap_new_fake_from_connection (connection);
		g_return_val_if_fail (ap != NULL, NM_ACT_STAGE_RETURN_FAILURE);

		if (nm_ap_get_mode (ap) == NM_802_11_MODE_INFRA)
			nm_ap_set_broadcast (ap, FALSE);
		else if (nm_ap_is_hotspot (ap))
			nm_ap_set_address (ap, (const struct ether_addr *) nm_device_get_hw_address (dev, NULL));

		priv->ap_list = g_slist_prepend (priv->ap_list, ap);
		nm_ap_export_to_dbus (ap);
		g_signal_emit (self, signals[ACCESS_POINT_ADDED], 0, ap);
		nm_device_recheck_available_connections (NM_DEVICE (self));
	}

	nm_active_connection_set_specific_object (NM_ACTIVE_CONNECTION (req), nm_ap_get_dbus_path (ap));

done:
	set_active_ap (self, ap);
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
ensure_hotspot_frequency (NMDeviceWifi *self,
                          NMSettingWireless *s_wifi,
                          NMAccessPoint *ap)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	const char *band = nm_setting_wireless_get_band (s_wifi);
	const guint32 a_freqs[] = { 5180, 5200, 5220, 5745, 5765, 5785, 5805, 0 };
	const guint32 bg_freqs[] = { 2412, 2437, 2462, 2472, 0 };
	guint32 freq = 0;

	g_assert (ap);

	if (nm_ap_get_freq (ap))
		return;

	if (g_strcmp0 (band, "a") == 0)
		freq = wifi_utils_find_freq (priv->wifi_data, a_freqs);
	else
		freq = wifi_utils_find_freq (priv->wifi_data, bg_freqs);

	if (!freq)
		freq = (g_strcmp0 (band, "a") == 0) ? 5180 : 2462;

	nm_ap_set_freq (ap, freq);
}

static NMActStageReturn
act_stage2_config (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	const char *iface = nm_device_get_iface (dev);
	NMSupplicantConfig *config = NULL;
	gulong id = 0;
	NMActRequest *req;
	NMAccessPoint *ap;
	NMConnection *connection;
	const char *setting_name;
	NMSettingWireless *s_wireless;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	remove_supplicant_timeouts (self);

	req = nm_device_get_act_request (dev);
	g_assert (req);

	ap = nm_device_wifi_get_activation_ap (self);
	g_assert (ap);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* If we need secrets, get them */
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		nm_log_info (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): access point '%s' has security,"
		             " but secrets are required.",
		             iface, nm_connection_get_id (connection));

		ret = handle_auth_or_fail (self, req, FALSE);
		if (ret == NM_ACT_STAGE_RETURN_FAILURE)
			*reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
		goto out;
	}

	/* have secrets, or no secrets required */
	if (nm_setting_wireless_get_security (s_wireless)) {
		nm_log_info (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): connection '%s' has security"
		             ", and secrets exist.  No new secrets needed.",
		             iface, nm_connection_get_id (connection));
	} else {
		nm_log_info (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): connection '%s' requires no "
		             "security.  No secrets needed.",
		             iface, nm_connection_get_id (connection));
	}

	priv->ssid_found = FALSE;

	/* Supplicant requires an initial frequency for Ad-Hoc and Hotspot; if the user
	 * didn't specify one and we didn't find an AP that matched the connection,
	 * just pick a frequency the device supports.
	 */
	if ((nm_ap_get_mode (ap) == NM_802_11_MODE_ADHOC) || nm_ap_is_hotspot (ap))
		ensure_hotspot_frequency (self, s_wireless, ap);

	/* Build up the supplicant configuration */
	config = build_supplicant_config (self, connection, ap);
	if (config == NULL) {
		nm_log_err (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): couldn't build wireless configuration.",
		             iface);
		*reason = NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED;
		goto out;
	}

	/* Hook up error signal handler to capture association errors */
	id = g_signal_connect (priv->supplicant.iface,
	                       NM_SUPPLICANT_INTERFACE_CONNECTION_ERROR,
	                       G_CALLBACK (supplicant_iface_connection_error_cb),
	                       self);
	priv->supplicant.iface_error_id = id;

	if (!nm_supplicant_interface_set_config (priv->supplicant.iface, config)) {
		nm_log_err (LOGD_DEVICE | LOGD_WIFI,
		            "Activation (%s/wireless): couldn't send wireless "
		            "configuration to the supplicant.", iface);
		*reason = NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED;
		goto out;
	}

	if (!start_supplicant_connection_timeout (self)) {
		*reason = NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED;
		goto out;
	}

	if (!priv->periodic_source_id)
		priv->periodic_source_id = g_timeout_add_seconds (6, periodic_update, self);

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
		nm_ip4_config_set_mtu (config, mtu);
}

static gboolean
is_static_wep (NMAccessPoint *ap, NMConnection *connection)
{
	NM80211ApFlags flags;
	NM80211ApSecurityFlags wpa_flags, rsn_flags;
	NMSettingWirelessSecurity *s_wsec;
	const char *key_mgmt;

	g_return_val_if_fail (ap != NULL, FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);

	flags = nm_ap_get_flags (ap);
	wpa_flags = nm_ap_get_wpa_flags (ap);
	rsn_flags = nm_ap_get_rsn_flags (ap);

	if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
	    && (wpa_flags == NM_802_11_AP_SEC_NONE)
	    && (rsn_flags == NM_802_11_AP_SEC_NONE)) {
		s_wsec = nm_connection_get_setting_wireless_security (connection);
		if (s_wsec) {
			key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
			if (g_strcmp0 (key_mgmt, "none") == 0)
				return TRUE;
		}
	}

	return FALSE;
}

static NMActStageReturn
handle_ip_config_timeout (NMDeviceWifi *self,
                          NMConnection *connection,
                          gboolean may_fail,
                          gboolean *chain_up,
                          NMDeviceStateReason *reason)
{
	NMAccessPoint *ap;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	g_return_val_if_fail (connection != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	if (NM_DEVICE_WIFI_GET_PRIVATE (self)->mode == NM_802_11_MODE_AP) {
		*chain_up = TRUE;
		return ret;
	}

	ap = nm_device_wifi_get_activation_ap (self);
	g_assert (ap);

	/* If IP configuration times out and it's a static WEP connection, that
	 * usually means the WEP key is wrong.  WEP's Open System auth mode has
	 * no provision for figuring out if the WEP key is wrong, so you just have
	 * to wait for DHCP to fail to figure it out.  For all other WiFi security
	 * types (open, WPA, 802.1x, etc) if the secrets/certs were wrong the
	 * connection would have failed before IP configuration.
	 */
	if (is_static_wep (ap, connection) && (may_fail == FALSE)) {
		/* Activation failed, we must have bad encryption key */
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): could not get IP configuration for "
		             "connection '%s'.",
		             nm_device_get_iface (NM_DEVICE (self)),
		             nm_connection_get_id (connection));

		ret = handle_auth_or_fail (self, NULL, TRUE);
		if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
			nm_log_info (LOGD_DEVICE | LOGD_WIFI,
			             "Activation (%s/wireless): asking for new secrets",
			             nm_device_get_iface (NM_DEVICE (self)));
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
act_stage4_ip4_config_timeout (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;
	gboolean may_fail = FALSE, chain_up = FALSE;
	NMActStageReturn ret;

	connection = nm_device_get_connection (dev);
	g_assert (connection);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (s_ip4)
		may_fail = nm_setting_ip4_config_get_may_fail (s_ip4);

	ret = handle_ip_config_timeout (NM_DEVICE_WIFI (dev), connection, may_fail, &chain_up, reason);
	if (chain_up)
		ret = NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage4_ip4_config_timeout (dev, reason);

	return ret;
}

static NMActStageReturn
act_stage4_ip6_config_timeout (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMConnection *connection;
	NMSettingIP6Config *s_ip6;
	gboolean may_fail = FALSE, chain_up = FALSE;
	NMActStageReturn ret;

	connection = nm_device_get_connection (dev);
	g_assert (connection);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (s_ip6)
		may_fail = nm_setting_ip6_config_get_may_fail (s_ip6);

	ret = handle_ip_config_timeout (NM_DEVICE_WIFI (dev), connection, may_fail, &chain_up, reason);
	if (chain_up)
		ret = NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage4_ip6_config_timeout (dev, reason);

	return ret;
}

static void
activation_success_handler (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *ap;
	struct ether_addr bssid = { {0x0, 0x0, 0x0, 0x0, 0x0, 0x0} };
	NMAccessPoint *tmp_ap;
	NMActRequest *req;
	NMConnection *connection;

	req = nm_device_get_act_request (dev);
	g_assert (req);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	/* Clear wireless secrets tries on success */
	g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, NULL);

	ap = nm_device_wifi_get_activation_ap (self);

	/* If the AP isn't fake, it was found in the scan list and all its
	 * details are known.
	 */
	if (!nm_ap_get_fake (ap))
		goto done;

	/* If the activate AP was fake, it probably won't have a BSSID at all.
	 * But if activation was successful, the card will know the BSSID.  Grab
	 * the BSSID off the card and fill in the BSSID of the activation AP.
	 */
	wifi_utils_get_bssid (priv->wifi_data, &bssid);
	if (!nm_ethernet_address_is_valid (nm_ap_get_address (ap)))
		nm_ap_set_address (ap, &bssid);
	if (!nm_ap_get_freq (ap))
		nm_ap_set_freq (ap, wifi_utils_get_freq (priv->wifi_data));
	if (!nm_ap_get_max_bitrate (ap))
		nm_ap_set_max_bitrate (ap, wifi_utils_get_rate (priv->wifi_data));

	tmp_ap = get_active_ap (self, ap, TRUE);
	if (tmp_ap) {
		const GByteArray *ssid = nm_ap_get_ssid (tmp_ap);

		/* Found a better match in the scan list than the fake AP.  Use it
		 * instead.
		 */

		/* If the better match was a hidden AP, update it's SSID */
		if (!ssid || nm_utils_is_empty_ssid (ssid->data, ssid->len))
			nm_ap_set_ssid (tmp_ap, nm_ap_get_ssid (ap));

		nm_active_connection_set_specific_object (NM_ACTIVE_CONNECTION (req),
		                                          nm_ap_get_dbus_path (tmp_ap));

		priv->ap_list = g_slist_remove (priv->ap_list, ap);
		g_object_unref (ap);
	}

done:
	periodic_update (self);

	/* Update seen BSSIDs cache with the connected AP */
	update_seen_bssids_cache (self, priv->current_ap);

	/* Reset scan interval to something reasonable */
	priv->scan_interval = SCAN_INTERVAL_MIN + (SCAN_INTERVAL_STEP * 2);
}

static void
activation_failure_handler (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMAccessPoint *ap;
	NMConnection *connection;

	connection = nm_device_get_connection (dev);
	g_assert (connection);

	/* Clear wireless secrets tries on failure */
	g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, NULL);

	if ((ap = nm_device_wifi_get_activation_ap (self))) {
		if (nm_ap_get_fake (ap)) {
			/* Fake APs are ones that don't show up in scans,
			 * but which the user explicitly attempted to connect to.
			 * However, if we fail on one of these, remove it from the
			 * list because we don't have any scan or capability info
			 * for it, and they are pretty much useless.
			 */
			remove_access_point (self, ap, TRUE);
		}
	}
}

static gboolean
can_interrupt_activation (NMDevice *dev)
{
	if (nm_device_get_state (dev) == NM_DEVICE_STATE_NEED_AUTH)
		return TRUE;

	return FALSE;
}

static const GByteArray *
get_connection_hw_address (NMDevice *device,
                           NMConnection *connection)
{
	NMSettingWireless *s_wifi;

	s_wifi = nm_connection_get_setting_wireless (connection);
	return s_wifi ? nm_setting_wireless_get_mac_address (s_wifi) : NULL;
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
		if (priv->supplicant.iface)
			supplicant_interface_release (self);

		if (priv->periodic_source_id) {
			g_source_remove (priv->periodic_source_id);
			priv->periodic_source_id = 0;
		}

		cleanup_association_attempt (self, TRUE);
		set_active_ap (self, NULL);
		remove_all_aps (self);
	}

	/* Start or stop the rfkill poll worker for ipw cards */
	if (priv->ipw_rfkill_path) {
		if (new_state > NM_DEVICE_STATE_UNMANAGED) {
			if (!priv->ipw_rfkill_id)
				priv->ipw_rfkill_id = g_timeout_add_seconds (3, ipw_rfkill_state_work, self);
		} else if (new_state <= NM_DEVICE_STATE_UNMANAGED) {
			if (priv->ipw_rfkill_id) {
				g_source_remove (priv->ipw_rfkill_id);
				priv->ipw_rfkill_id = 0;
			}
		}
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
			if (!priv->supplicant.iface)
				supplicant_interface_acquire (self);
		}
		clear_aps = TRUE;
		break;
	case NM_DEVICE_STATE_NEED_AUTH:
		if (priv->supplicant.iface)
			nm_supplicant_interface_disconnect (priv->supplicant.iface);
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
		request_wireless_scan (self);
		break;
	default:
		break;
	}

	if (clear_aps)
		remove_all_aps (self);
}

NMAccessPoint *
nm_device_wifi_get_activation_ap (NMDeviceWifi *self)
{
	NMActRequest *req;
	const char *ap_path;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (self), NULL);

	req = nm_device_get_act_request (NM_DEVICE (self));
	if (!req)
		return NULL;

	ap_path = nm_active_connection_get_specific_object (NM_ACTIVE_CONNECTION (req));

	return ap_path ? get_ap_by_path (self, ap_path) : NULL;
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

	nm_log_dbg (LOGD_WIFI, "(%s): device now %s",
	            nm_device_get_iface (NM_DEVICE (device)),
	            enabled ? "enabled" : "disabled");

	state = nm_device_get_state (NM_DEVICE (self));
	if (state < NM_DEVICE_STATE_UNAVAILABLE) {
		nm_log_dbg (LOGD_WIFI, "(%s): %s blocked by UNMANAGED state",
		            enabled ? "enable" : "disable",
		            nm_device_get_iface (NM_DEVICE (device)));
		return;
	}

	if (enabled) {
		gboolean no_firmware = FALSE;

		if (state != NM_DEVICE_STATE_UNAVAILABLE)
			nm_log_warn (LOGD_CORE, "not in expected unavailable state!");

		if (!nm_device_bring_up (NM_DEVICE (self), TRUE, &no_firmware)) {
			nm_log_dbg (LOGD_WIFI, "(%s): enable blocked by failure to bring device up",
			            nm_device_get_iface (NM_DEVICE (device)));

			if (no_firmware)
				nm_device_set_firmware_missing (NM_DEVICE (device), TRUE);
			else {
				/* The device sucks, or the kernel was lying to us about the killswitch state */
				priv->enabled = FALSE;
			}
			return;
		}

		/* Re-initialize the supplicant interface and wait for it to be ready */
		if (priv->supplicant.iface)
			supplicant_interface_release (self);
		supplicant_interface_acquire (self);

		nm_log_dbg (LOGD_WIFI, "(%s): enable waiting on supplicant state",
		            nm_device_get_iface (NM_DEVICE (device)));
	} else {
		nm_device_state_changed (NM_DEVICE (self),
		                         NM_DEVICE_STATE_UNAVAILABLE,
		                         NM_DEVICE_STATE_REASON_NONE);
		nm_device_take_down (NM_DEVICE (self), TRUE);
	}
}

/********************************************************************/

NMDevice *
nm_device_wifi_new (NMPlatformLink *platform_device)
{
	g_return_val_if_fail (platform_device != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_WIFI,
	                                  NM_DEVICE_PLATFORM_DEVICE, platform_device,
	                                  NM_DEVICE_TYPE_DESC, "802.11 WiFi",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_WIFI,
	                                  NM_DEVICE_RFKILL_TYPE, RFKILL_TYPE_WLAN,
	                                  NULL);
}

static void
nm_device_wifi_init (NMDeviceWifi *self)
{
	NM_DEVICE_WIFI_GET_PRIVATE (self)->mode = NM_802_11_MODE_INFRA;
}

static void
dispose (GObject *object)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (object);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_wifi_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	if (priv->periodic_source_id) {
		g_source_remove (priv->periodic_source_id);
		priv->periodic_source_id = 0;
	}

	cleanup_association_attempt (self, TRUE);
	supplicant_interface_release (self);

	if (priv->supplicant.mgr) {
		g_object_unref (priv->supplicant.mgr);
		priv->supplicant.mgr = NULL;
	}

	set_active_ap (self, NULL);
	remove_all_aps (self);

	if (priv->wifi_data)
		wifi_utils_deinit (priv->wifi_data);

	g_free (priv->ipw_rfkill_path);
	if (priv->ipw_rfkill_id) {
		g_source_remove (priv->ipw_rfkill_id);
		priv->ipw_rfkill_id = 0;
	}

	G_OBJECT_CLASS (nm_device_wifi_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceWifi *device = NM_DEVICE_WIFI (object);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);

	switch (prop_id) {
	case PROP_PERM_HW_ADDRESS:
		g_value_take_string (value, nm_utils_hwaddr_ntoa (&priv->perm_hw_addr, ARPHRD_ETHER));
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
	case PROP_ACTIVE_ACCESS_POINT:
		if (priv->current_ap)
			g_value_set_boxed (value, nm_ap_get_dbus_path (priv->current_ap));
		else
			g_value_set_boxed (value, "/");
		break;
	case PROP_SCANNING:
		g_value_set_boolean (value, nm_supplicant_interface_get_scanning (priv->supplicant.iface));
		break;
	case PROP_IPW_RFKILL_STATE:
		g_value_set_uint (value, nm_device_wifi_get_ipw_rfkill_state (device));
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
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_IPW_RFKILL_STATE:
		/* construct only */
		priv->ipw_rfkill_state = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
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

	parent_class->bring_up = bring_up;
	parent_class->update_permanent_hw_address = update_permanent_hw_address;
	parent_class->update_initial_hw_address = update_initial_hw_address;
	parent_class->can_auto_connect = can_auto_connect;
	parent_class->is_available = is_available;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->check_connection_available = check_connection_available;
	parent_class->complete_connection = complete_connection;
	parent_class->set_enabled = set_enabled;

	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->act_stage2_config = act_stage2_config;
	parent_class->ip4_config_pre_commit = ip4_config_pre_commit;
	parent_class->act_stage4_ip4_config_timeout = act_stage4_ip4_config_timeout;
	parent_class->act_stage4_ip6_config_timeout = act_stage4_ip6_config_timeout;
	parent_class->deactivate = deactivate;
	parent_class->can_interrupt_activation = can_interrupt_activation;
	parent_class->get_connection_hw_address = get_connection_hw_address;

	parent_class->state_changed = device_state_changed;

	klass->scanning_allowed = scanning_allowed;

	/* Properties */
	g_object_class_install_property (object_class, PROP_PERM_HW_ADDRESS,
		g_param_spec_string (NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS,
		                     "Permanent MAC Address",
		                     "Permanent hardware MAC address",
		                     NULL,
		                     G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_MODE,
		g_param_spec_uint (NM_DEVICE_WIFI_MODE,
		                   "Mode",
		                   "Mode",
		                   NM_802_11_MODE_UNKNOWN,
		                   NM_802_11_MODE_AP,
		                   NM_802_11_MODE_INFRA,
		                   G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_BITRATE,
		g_param_spec_uint (NM_DEVICE_WIFI_BITRATE,
		                   "Bitrate",
		                   "Bitrate",
		                   0, G_MAXUINT32, 0,
		                   G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_ACTIVE_ACCESS_POINT,
		g_param_spec_boxed (NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT,
		                    "Active access point",
		                    "Currently active access point",
		                    DBUS_TYPE_G_OBJECT_PATH,
		                    G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_CAPABILITIES,
		g_param_spec_uint (NM_DEVICE_WIFI_CAPABILITIES,
		                   "Wireless Capabilities",
		                   "Wireless Capabilities",
		                   0, G_MAXUINT32, NM_WIFI_DEVICE_CAP_NONE,
		                   G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_SCANNING,
		g_param_spec_boolean (NM_DEVICE_WIFI_SCANNING,
		                   "Scanning",
		                   "Scanning",
		                   FALSE,
		                   G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_IPW_RFKILL_STATE,
		g_param_spec_uint (NM_DEVICE_WIFI_IPW_RFKILL_STATE,
		                   "IpwRfkillState",
		                   "ipw rf-kill state",
		                   RFKILL_UNBLOCKED, RFKILL_HARD_BLOCKED, RFKILL_UNBLOCKED,
		                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* Signals */
	signals[ACCESS_POINT_ADDED] =
		g_signal_new ("access-point-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, access_point_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	signals[ACCESS_POINT_REMOVED] =
		g_signal_new ("access-point-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0,
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	signals[HIDDEN_AP_FOUND] =
		g_signal_new ("hidden-ap-found",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, hidden_ap_found),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	signals[SCANNING_ALLOWED] =
		g_signal_new ("scanning-allowed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, scanning_allowed),
		              scanning_allowed_accumulator, NULL, NULL,
		              G_TYPE_BOOLEAN, 0);

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_device_wifi_object_info);

	dbus_g_error_domain_register (NM_WIFI_ERROR, NULL, NM_TYPE_WIFI_ERROR);
}


