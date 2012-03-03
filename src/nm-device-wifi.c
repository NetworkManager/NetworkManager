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
#include <net/if.h>
#include <errno.h>

#include "nm-glib-compat.h"
#include "nm-device.h"
#include "nm-device-wifi.h"
#include "nm-device-private.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-marshal.h"
#include "NetworkManagerUtils.h"
#include "nm-activation-request.h"
#include "nm-supplicant-manager.h"
#include "nm-supplicant-interface.h"
#include "nm-supplicant-config.h"
#include "nm-properties-changed-signal.h"
#include "nm-setting-connection.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-system.h"
#include "nm-settings-connection.h"
#include "nm-enum-types.h"
#include "wifi-utils.h"

static gboolean impl_device_get_access_points (NMDeviceWifi *device,
                                               GPtrArray **aps,
                                               GError **err);

#include "nm-device-wifi-glue.h"


/* All of these are in seconds */
#define SCAN_INTERVAL_MIN 0
#define SCAN_INTERVAL_STEP 20
#define SCAN_INTERVAL_MAX 120

#define WIRELESS_SECRETS_TRIES "wireless-secrets-tries"

G_DEFINE_TYPE (NMDeviceWifi, nm_device_wifi, NM_TYPE_DEVICE)

#define NM_DEVICE_WIFI_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_WIFI, NMDeviceWifiPrivate))


enum {
	PROP_0,
	PROP_HW_ADDRESS,
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
	PROPERTIES_CHANGED,
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

	guint8            hw_addr[ETH_ALEN];         /* Currently set MAC address */
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
	
	glong             scheduled_scan_time;
	guint8            scan_interval; /* seconds */
	guint             pending_scan_id;
	guint             scanlist_cull_id;

	Supplicant        supplicant;
	WifiData *        wifi_data;

	guint32           failed_link_count;
	guint             periodic_source_id;
	guint             link_timeout_id;

	NMDeviceWifiCapabilities capabilities;
};

static gboolean request_wireless_scan (gpointer user_data);

static void schedule_scan (NMDeviceWifi *self, gboolean backoff);

static void cancel_pending_scan (NMDeviceWifi *self);

static void cleanup_association_attempt (NMDeviceWifi * self,
                                         gboolean disconnect);

static void remove_supplicant_timeouts (NMDeviceWifi *self);

static void supplicant_iface_state_cb (NMSupplicantInterface *iface,
                                       guint32 new_state,
                                       guint32 old_state,
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

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_NM_SUPPORTED;
}

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
		nm_log_warn (LOGD_HW | LOGD_WIFI, "(%s): driver supports Access Point (AP) mode",
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
	 * likely the AP we want.
	 */
	if (match_nofreq && (found_a_band != found_bg_band)) {
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
set_current_ap (NMDeviceWifi *self, NMAccessPoint *new_ap)
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

static void
periodic_update (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *new_ap;
	guint32 new_rate, percent;

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

		set_current_ap (self, new_ap);
	}

	new_rate = wifi_utils_get_rate (priv->wifi_data);
	if (new_rate != priv->rate) {
		priv->rate = new_rate;
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_BITRATE);
	}
}

/*
 * nm_device_wifi_periodic_update
 *
 * Periodically update device statistics.
 *
 */
static gboolean
nm_device_wifi_periodic_update (gpointer data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMDeviceState state;

	/* BSSID and signal strength have meaningful values only if the device
	   is activated and not scanning */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state != NM_DEVICE_STATE_ACTIVATED)
		goto out;

	if (nm_supplicant_interface_get_scanning (priv->supplicant.iface))
		goto out;

	periodic_update (self);

out:
	return TRUE;
}

static gboolean
real_hw_is_up (NMDevice *device)
{
	return nm_system_iface_is_up (nm_device_get_ip_ifindex (device));
}

static gboolean
real_hw_bring_up (NMDevice *device, gboolean *no_firmware)
{
	if (!NM_DEVICE_WIFI_GET_PRIVATE (device)->enabled)
		return FALSE;

	return nm_system_iface_set_up (nm_device_get_ip_ifindex (device), TRUE, no_firmware);
}

static void
real_hw_take_down (NMDevice *device)
{
	nm_system_iface_set_up (nm_device_get_ip_ifindex (device), FALSE, NULL);
}

static gboolean
real_is_up (NMDevice *device)
{
	if (!NM_DEVICE_WIFI_GET_PRIVATE (device)->periodic_source_id)
		return FALSE;

	return TRUE;
}

static gboolean
real_bring_up (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	priv->periodic_source_id = g_timeout_add_seconds (6, nm_device_wifi_periodic_update, self);
	return TRUE;
}

static void
_update_hw_addr (NMDeviceWifi *self, const guint8 *addr)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	g_return_if_fail (addr != NULL);

	if (memcmp (&priv->hw_addr, addr, ETH_ALEN)) {
		memcpy (&priv->hw_addr, addr, ETH_ALEN);
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_HW_ADDRESS);
	}
}

static gboolean
_set_hw_addr (NMDeviceWifi *self, const guint8 *addr, const char *detail)
{
	NMDevice *dev = NM_DEVICE (self);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	const char *iface;
	char *mac_str = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (addr != NULL, FALSE);

	iface = nm_device_get_iface (dev);

	mac_str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
	                           addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	/* Do nothing if current MAC is same */
	if (!memcmp (&priv->hw_addr, addr, ETH_ALEN)) {
		nm_log_dbg (LOGD_DEVICE | LOGD_ETHER, "(%s): no MAC address change needed", iface);
		g_free (mac_str);
		return TRUE;
	}

	/* Can't change MAC address while device is up */
	real_hw_take_down (dev);

	success = nm_system_iface_set_mac (nm_device_get_ip_ifindex (dev), (struct ether_addr *) addr);
	if (success) {
		/* MAC address succesfully changed; update the current MAC to match */
		_update_hw_addr (self, addr);
		nm_log_info (LOGD_DEVICE | LOGD_ETHER, "(%s): %s MAC address to %s",
		             iface, detail, mac_str);
	} else {
		nm_log_warn (LOGD_DEVICE | LOGD_ETHER, "(%s): failed to %s MAC address to %s",
		             iface, detail, mac_str);
	}
	real_hw_bring_up (dev, NULL);
	g_free (mac_str);

	return success;
}

static void
access_point_removed (NMDeviceWifi *device, NMAccessPoint *ap)
{
	g_signal_emit (device, signals[ACCESS_POINT_REMOVED], 0, ap);
}

static void
remove_all_aps (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	/* Remove outdated APs */
	while (g_slist_length (priv->ap_list)) {
		NMAccessPoint *ap = NM_AP (priv->ap_list->data);

		access_point_removed (self, ap);
		priv->ap_list = g_slist_remove (priv->ap_list, ap);
		g_object_unref (ap);
	}
	g_slist_free (priv->ap_list);
	priv->ap_list = NULL;
}

static void
real_take_down (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->periodic_source_id) {
		g_source_remove (priv->periodic_source_id);
		priv->periodic_source_id = 0;
	}

	cleanup_association_attempt (self, TRUE);
	set_current_ap (self, NULL);
	remove_all_aps (self);
}

static void
real_deactivate (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *orig_ap = nm_device_wifi_get_activation_ap (self);
	NMActRequest *req;
	NMConnection *connection;

	req = nm_device_get_act_request (dev);
	if (req) {
		connection = nm_act_request_get_connection (req);
		/* Clear wireless secrets tries when deactivating */
		g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, NULL);
	}

	cleanup_association_attempt (self, TRUE);

	set_current_ap (self, NULL);
	priv->rate = 0;

	/* If the AP is 'fake', i.e. it wasn't actually found from
	 * a scan but the user tried to connect to it manually (maybe it
	 * was non-broadcasting or something) get rid of it, because 'fake'
	 * APs should only live for as long as we're connected to them.  Fixes
	 * a bug where user-created Ad-Hoc APs are never removed from the scan
	 * list, because scanning is disabled while in Ad-Hoc mode (for stability),
	 * and thus the AP culling never happens. (bgo #569241)
	 */
	if (orig_ap && nm_ap_get_fake (orig_ap)) {
		access_point_removed (self, orig_ap);
		priv->ap_list = g_slist_remove (priv->ap_list, orig_ap);
		g_object_unref (orig_ap);
	}

	/* Reset MAC address back to initial address */
	_set_hw_addr (self, priv->initial_hw_addr, "reset");

	/* Ensure we're in infrastructure mode after deactivation; some devices
	 * (usually older ones) don't scan well in adhoc mode.
	 */
	wifi_utils_set_mode (priv->wifi_data, NM_802_11_MODE_INFRA);
}

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	const GByteArray *mac;
	const GSList *mac_blacklist, *mac_blacklist_iter;

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

	// FIXME: check channel/freq/band against bands the hardware supports
	// FIXME: check encryption against device capabilities
	// FIXME: check bitrate against device capabilities

	return TRUE;
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
real_complete_connection (NMDevice *device,
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
real_is_available (NMDevice *dev)
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
	if (state != NM_SUPPLICANT_INTERFACE_STATE_READY) {
		nm_log_dbg (LOGD_WIFI, "(%s): not available because supplicant interface not ready",
		            nm_device_get_iface (dev));
		return FALSE;
	}

	return TRUE;
}

static NMConnection *
real_get_best_auto_connection (NMDevice *dev,
                               GSList *connections,
                               char **specific_object)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	GSList *iter, *ap_iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;
		NMSettingWireless *s_wireless;
		const GByteArray *mac;
		const GSList *mac_blacklist, *mac_blacklist_iter;
		gboolean mac_blacklist_found = FALSE;
		NMSettingIP4Config *s_ip4;
		const char *method = NULL;

		s_con = nm_connection_get_setting_connection (connection);
		if (s_con == NULL)
			continue;
		if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_WIRELESS_SETTING_NAME))
			continue;
		if (!nm_setting_connection_get_autoconnect (s_con))
			continue;

		s_wireless = nm_connection_get_setting_wireless (connection);
		if (!s_wireless)
			continue;

		mac = nm_setting_wireless_get_mac_address (s_wireless);
		if (mac && memcmp (mac->data, &priv->perm_hw_addr, ETH_ALEN))
			continue;

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
				mac_blacklist_found = TRUE;
				break;
			}
		}
		/* Found device MAC address in the blacklist - do not use this connection */
		if (mac_blacklist_found)
			continue;

		/* Use the connection if it's a shared connection */
		s_ip4 = nm_connection_get_setting_ip4_config (connection);
		if (s_ip4)
			method = nm_setting_ip4_config_get_method (s_ip4);

		if (s_ip4 && !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
			return connection;

		for (ap_iter = priv->ap_list; ap_iter; ap_iter = g_slist_next (ap_iter)) {
			NMAccessPoint *ap = NM_AP (ap_iter->data);

			if (nm_ap_check_compatible (ap, connection)) {
				/* All good; connection is usable */
				*specific_object = (char *) nm_ap_get_dbus_path (ap);
				return connection;
			}
		}
	}
	return NULL;
}

/*
 * nm_device_wifi_get_address
 *
 * Get a device's hardware address
 *
 */
void
nm_device_wifi_get_address (NMDeviceWifi *self,
                            struct ether_addr *addr)
{
	NMDeviceWifiPrivate *priv;

	g_return_if_fail (self != NULL);
	g_return_if_fail (addr != NULL);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	memcpy (addr, &priv->hw_addr, sizeof (struct ether_addr));
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

static gboolean
scanning_allowed (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	guint32 sup_state;
	NMActRequest *req;

	g_return_val_if_fail (priv->supplicant.iface != NULL, FALSE);

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
	GValue instance = { 0, };
	GValue retval = { 0, };

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
request_wireless_scan (gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	gboolean backoff = FALSE;

	if (check_scanning_allowed (self)) {
		nm_log_dbg (LOGD_WIFI_SCAN, "(%s): scanning requested",
		            nm_device_get_iface (NM_DEVICE (self)));

		if (nm_supplicant_interface_request_scan (priv->supplicant.iface)) {
			/* success */
			backoff = TRUE;
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
	GTimeVal now;

	g_get_current_time (&now);

	/* Cancel the pending scan if it would happen later than (now + the scan_interval) */
	if (priv->pending_scan_id) {
		if (now.tv_sec + priv->scan_interval < priv->scheduled_scan_time)
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

		priv->scheduled_scan_time = now.tv_sec + priv->scan_interval;
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

	if (check_scanning_allowed (self))
		schedule_scan (self, TRUE);

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
	}
}

#define WPAS_REMOVED_TAG "supplicant-removed"

static gboolean
cull_scan_list (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	GTimeVal now;
	GSList *outdated_list = NULL;
	GSList *elt;
	guint32 removed = 0, total = 0;

	priv->scanlist_cull_id = 0;

	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): checking scan list for outdated APs",
	            nm_device_get_iface (NM_DEVICE (self)));

	/* Walk the access point list and remove any access points older than
	 * three times the inactive scan interval.
	 */
	g_get_current_time (&now);
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

		if (nm_ap_get_last_seen (ap) + prune_interval_s < now.tv_sec)
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

		access_point_removed (self, outdated_ap);
		priv->ap_list = g_slist_remove (priv->ap_list, outdated_ap);
		g_object_unref (outdated_ap);
		removed++;
	}
	g_slist_free (outdated_list);

	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): removed %d APs (of %d)",
	            nm_device_get_iface (NM_DEVICE (self)),
	            removed, total);

	ap_list_dump (self);

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

	/* Ignore new APs when unavailable or unamnaged */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state <= NM_DEVICE_STATE_UNAVAILABLE)
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
	GTimeVal now;

	g_return_if_fail (self != NULL);
	g_return_if_fail (object_path != NULL);
	g_return_if_fail (properties != NULL);

	/* Ignore new APs when unavailable or unamnaged */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state <= NM_DEVICE_STATE_UNAVAILABLE)
		return;

	/* Update the AP's last-seen property */
	ap = get_ap_by_supplicant_path (self, object_path);
	if (ap) {
		g_get_current_time (&now);
		nm_ap_set_last_seen (ap, now.tv_sec);
	}

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

	nm_log_warn (LOGD_WIFI, "(%s): link timed out.", nm_device_get_iface (dev));

	NM_DEVICE_WIFI_GET_PRIVATE (dev)->link_timeout_id = 0;

	/* Disconnect event while activated; the supplicant hasn't been able
	 * to reassociate within the timeout period, so the connection must
	 * fail.
	 */
	if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED)
		nm_device_state_changed (dev, NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT);

	return FALSE;
}

static gboolean
handle_8021x_auth_fail (NMDeviceWifi *self, guint32 new_state, guint32 old_state)
{
	NMDevice *device = NM_DEVICE (self);
	NMSetting8021x *s_8021x;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;
	NMActRequest *req;
	NMConnection *connection;
	const char *setting_name = NULL;
	gboolean handled = FALSE;

	g_return_val_if_fail (new_state == NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED, FALSE);

	/* Only care about ASSOCIATED -> DISCONNECTED transitions since 802.1x stuff
	 * happens between the ASSOCIATED and AUTHENTICATED states.
	 */
	if (old_state != NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED)
		return FALSE;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_val_if_fail (req != NULL, FALSE);

	connection = nm_act_request_get_connection (req);
	g_return_val_if_fail (connection != NULL, FALSE);

	/* If it's an 802.1x or LEAP connection with "always ask"/unsaved secrets
	 * then we need to ask again because it might be an OTP token and the PIN
	 * may have changed.
	 */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	s_wsec = nm_connection_get_setting_wireless_security (connection);

	if (s_8021x) {
		nm_setting_get_secret_flags (NM_SETTING (s_8021x),
		                             NM_SETTING_802_1X_PASSWORD,
		                             &secret_flags,
		                             NULL);
		setting_name = NM_SETTING_802_1X_SETTING_NAME;
	} else if (s_wsec) {
		nm_setting_get_secret_flags (NM_SETTING (s_wsec),
		                             NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
		                             &secret_flags,
		                             NULL);
		setting_name = NM_SETTING_WIRELESS_SECURITY_SETTING_NAME;
	}

	if (setting_name && (secret_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
		NMSettingsGetSecretsFlags flags =   NM_SETTINGS_GET_SECRETS_FLAG_ALLOW_INTERACTION
		                                  | NM_SETTINGS_GET_SECRETS_FLAG_REQUEST_NEW;

		nm_connection_clear_secrets (connection);

		nm_log_info (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): disconnected during association,"
		             " asking for new key.", nm_device_get_iface (device));

		cleanup_association_attempt (self, TRUE);
		nm_device_state_changed (device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
		nm_act_request_get_secrets (req, setting_name, flags, NULL, wifi_secrets_cb, self);
		handled = TRUE;
	}

	return handled;
}

static void
supplicant_iface_state_cb (NMSupplicantInterface *iface,
                           guint32 new_state,
                           guint32 old_state,
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
			             "successful.  Connected to wireless network '%s'.",
			             nm_device_get_iface (device),
			             ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");
			nm_device_activate_schedule_stage3_ip_config_start (device);
		}
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED:
		if ((devstate == NM_DEVICE_STATE_ACTIVATED) || nm_device_is_activating (device)) {
			/* Disconnect of an 802.1x/LEAP connection during authentication
			 * means secrets might be wrong. Not always the case, but until we
			 * have more information from wpa_supplicant about why the
			 * disconnect happened this is the best we can do.
			 */
			if (handle_8021x_auth_fail (self, new_state, old_state))
				break;
		}

		/* Otherwise it might be a stupid driver or some transient error, so
		 * let the supplicant try to reconnect a few more times.  Give it more
		 * time if a scan is in progress since the link might be dropped during
		 * the scan but will be re-established when the scan is done.
		 */
		if (devstate == NM_DEVICE_STATE_ACTIVATED) {
			if (priv->link_timeout_id == 0)
				priv->link_timeout_id = g_timeout_add_seconds (scanning ? 30 : 15, link_timeout_cb, self);
		}
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_DOWN:
		cleanup_association_attempt (self, FALSE);
		supplicant_interface_release (self);
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
	if (cb_data == NULL) {
		nm_log_err (LOGD_WIFI, "Not enough memory to process supplicant connection error.");
		return;
	}

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
	gboolean scanning;

	scanning = nm_supplicant_interface_get_scanning (iface);
	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): now %s",
	            nm_device_get_iface (NM_DEVICE (self)),
	            scanning ? "scanning" : "idle");

	g_object_notify (G_OBJECT (self), "scanning");
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
	NMAccessPoint *ap;
	NMConnection *connection;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (self), NM_ACT_STAGE_RETURN_FAILURE);

	if (!req) {
		req = nm_device_get_act_request (NM_DEVICE (self));
		g_assert (req);
	}

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	ap = nm_device_wifi_get_activation_ap (self);
	g_assert (ap);

	tries = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES));
	if (tries > 3)
		return NM_ACT_STAGE_RETURN_FAILURE;

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);

	nm_connection_clear_secrets (connection);
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		NMSettingsGetSecretsFlags flags = NM_SETTINGS_GET_SECRETS_FLAG_ALLOW_INTERACTION;

		/* If the caller doesn't necessarily want completely new secrets,
		 * only ask for new secrets after the first failure.
		 */
		if (new_secrets || tries)
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

	ap = nm_device_wifi_get_activation_ap (self);
	g_assert (ap);

	if (nm_ap_get_mode (ap) == NM_802_11_MODE_ADHOC) {
		/* In Ad-Hoc mode there's nothing to check the encryption key (if any)
		 * so supplicant timeouts here are almost certainly the wifi driver
		 * being really stupid.
		 */
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): Ad-Hoc network creation took "
		             "too long, failing activation.",
		             nm_device_get_iface (dev));
		nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT);
		return FALSE;
	}

	if (is_encrypted (ap, connection)) {
		/* Connection failed; either driver problems, the encryption key is
		 * wrong, or the passwords or certificates were wrong.
		 */
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): association took too long.",
		             nm_device_get_iface (dev));

		if (handle_auth_or_fail (self, req, TRUE) == NM_ACT_STAGE_RETURN_POSTPONE) {
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
		                         NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT);
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
	guint32 adhoc_freq = 0;

	g_return_val_if_fail (self != NULL, NULL);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wireless != NULL, NULL);

	config = nm_supplicant_config_new ();
	if (!config)
		return NULL;

	/* Supplicant requires an initial frequency for Ad-Hoc networks; if the user
	 * didn't specify one and we didn't find an AP that matched the connection,
	 * just pick a frequency the device supports.
	 */
	if (nm_ap_get_mode (ap) == NM_802_11_MODE_ADHOC) {
		const char *band = nm_setting_wireless_get_band (s_wireless);
		const guint32 a_freqs[] = { 5180, 5200, 5220, 5745, 5765, 5785, 5805, 0 };
		const guint32 bg_freqs[] = { 2412, 2437, 2462, 2472, 0 };

		adhoc_freq = nm_ap_get_freq (ap);
		if (!adhoc_freq) {
			if (g_strcmp0 (band, "a") == 0)
				adhoc_freq = wifi_utils_find_freq (priv->wifi_data, a_freqs);
			else
				adhoc_freq = wifi_utils_find_freq (priv->wifi_data, bg_freqs);
		}

		if (!adhoc_freq) {
			if (g_strcmp0 (band, "a") == 0)
				adhoc_freq = 5180;
			else
				adhoc_freq = 2462;
		}
	}

	if (!nm_supplicant_config_add_setting_wireless (config,
	                                                s_wireless,
	                                                nm_ap_get_broadcast (ap),
	                                                adhoc_freq,
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
real_update_hw_address (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	struct ifreq req;
	int fd;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_err (LOGD_HW, "could not open control socket.");
		return;
	}

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), IFNAMSIZ);
	errno = 0;
	if (ioctl (fd, SIOCGIFHWADDR, &req) < 0) {
		nm_log_err (LOGD_HW | LOGD_WIFI, "(%s): unable to read hardware address (error %d)",
		            nm_device_get_iface (dev), errno);
	} else
		_update_hw_addr (self, (const guint8 *) &req.ifr_hwaddr.sa_data);

	close (fd);
}

static void
real_update_permanent_hw_address (NMDevice *dev)
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
		nm_log_err (LOGD_HW | LOGD_ETHER, "(%s): unable to read permanent MAC address (error %d)",
		            nm_device_get_iface (dev), errno);
		/* Fall back to current address */
		memcpy (epaddr->data, &priv->hw_addr, ETH_ALEN);
	}

	if (memcmp (&priv->perm_hw_addr, epaddr->data, ETH_ALEN)) {
		memcpy (&priv->perm_hw_addr, epaddr->data, ETH_ALEN);
		g_object_notify (G_OBJECT (dev), NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS);
	}

	g_free (epaddr);
	close (fd);
}

static void
real_update_initial_hw_address (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	char *mac_str = NULL;
	guint8 *addr = priv->initial_hw_addr;
	guint8 zero[ETH_ALEN] = {0,0,0,0,0,0};

	/* This sets initial MAC address from current MAC address. It should only
	 * be called from NMDevice constructor() to really get the initial address.
	 */
	if (!memcmp (&priv->hw_addr, &zero, ETH_ALEN))
		real_update_hw_address (dev);

	if (memcmp (&priv->initial_hw_addr, &priv->hw_addr, ETH_ALEN))
		memcpy (&priv->initial_hw_addr, &priv->hw_addr, ETH_ALEN);

	mac_str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
	                           addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	nm_log_dbg (LOGD_DEVICE | LOGD_ETHER, "(%s): read initial MAC address %s",
	            nm_device_get_iface (dev), mac_str);

	g_free (mac_str);
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *ap = NULL;
	NMActRequest *req;
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	const GByteArray *cloned_mac;
	GSList *iter;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_val_if_fail (req != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_act_request_get_connection (req);
	g_return_val_if_fail (connection != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	/* Set spoof MAC to the interface */
	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	cloned_mac = nm_setting_wireless_get_cloned_mac_address (s_wireless);
	if (cloned_mac && (cloned_mac->len == ETH_ALEN))
		_set_hw_addr (self, (const guint8 *) cloned_mac->data, "set");

	/* If the user is trying to connect to an AP that NM doesn't yet know about
	 * (hidden network or something), create an fake AP from the security
	 * settings in the connection to use until the AP is recognized from the
	 * scan list, which should show up when the connection is successful.
	 */
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

	/* If no compatible AP was found, create a fake AP (network is likely
	 * hidden) and try to use that.
	 */
	if (!ap) {
		ap = nm_ap_new_fake_from_connection (connection);
		g_return_val_if_fail (ap != NULL, NM_ACT_STAGE_RETURN_FAILURE);

		if (nm_ap_get_mode (ap) == NM_802_11_MODE_INFRA)
			nm_ap_set_broadcast (ap, FALSE);

		priv->ap_list = g_slist_prepend (priv->ap_list, ap);
		nm_ap_export_to_dbus (ap);
		g_signal_emit (self, signals[ACCESS_POINT_ADDED], 0, ap);
	}

	nm_active_connection_set_specific_object (NM_ACTIVE_CONNECTION (req), nm_ap_get_dbus_path (ap));

done:
	set_current_ap (self, ap);
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
real_act_stage2_config (NMDevice *dev, NMDeviceStateReason *reason)
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
real_ip4_config_pre_commit (NMDevice *device, NMIP4Config *config)
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
real_act_stage4_ip4_config_timeout (NMDevice *dev, NMDeviceStateReason *reason)
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
real_act_stage4_ip6_config_timeout (NMDevice *dev, NMDeviceStateReason *reason)
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
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *ap;
	const GByteArray * ssid;
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
			access_point_removed (self, ap);
			priv->ap_list = g_slist_remove (priv->ap_list, ap);
			g_object_unref (ap);
		}
	}

	ssid = nm_ap_get_ssid (ap);
	nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
	             "Activation (%s) failed for access point (%s)",
	             nm_device_get_iface (dev),
	             ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");
}

static gboolean
real_can_interrupt_activation (NMDevice *dev)
{
	if (nm_device_get_state (dev) == NM_DEVICE_STATE_NEED_AUTH)
		return TRUE;

	return FALSE;
}


static guint32
real_get_type_capabilities (NMDevice *dev)
{
	return NM_DEVICE_WIFI_GET_PRIVATE (dev)->capabilities;
}


static gboolean
spec_match_list (NMDevice *device, const GSList *specs)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	char *hwaddr;
	gboolean matched;

	hwaddr = nm_utils_hwaddr_ntoa (&priv->perm_hw_addr, ARPHRD_ETHER);
	matched = nm_match_spec_hwaddr (specs, hwaddr);
	g_free (hwaddr);

	return matched;
}

static gboolean
hwaddr_matches (NMDevice *device,
                NMConnection *connection,
                const guint8 *other_hwaddr,
                guint other_hwaddr_len,
                gboolean fail_if_no_hwaddr)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	NMSettingWireless *s_wifi;
	const GByteArray *mac = NULL;

	s_wifi = nm_connection_get_setting_wireless (connection);
	if (s_wifi)
		mac = nm_setting_wireless_get_mac_address (s_wifi);

	if (mac) {
		g_return_val_if_fail (mac->len == ETH_ALEN, FALSE);
		if (other_hwaddr) {
			g_return_val_if_fail (other_hwaddr_len == ETH_ALEN, FALSE);
			if (memcmp (mac->data, other_hwaddr, mac->len) == 0)
				return TRUE;
		} else if (memcmp (mac->data, priv->hw_addr, mac->len) == 0)
			return TRUE;
	} else if (fail_if_no_hwaddr == FALSE)
		return TRUE;

	return FALSE;
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
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
		// FIXME: ensure that the activation request is destroyed
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
real_set_enabled (NMDevice *device, gboolean enabled)
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

		if (!nm_device_hw_bring_up (NM_DEVICE (self), TRUE, &no_firmware)) {
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
		nm_device_hw_take_down (NM_DEVICE (self), TRUE);
	}
}

/********************************************************************/

NMDevice *
nm_device_wifi_new (const char *udi,
                    const char *iface,
                    const char *driver)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_WIFI,
	                                  NM_DEVICE_UDI, udi,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, driver,
	                                  NM_DEVICE_TYPE_DESC, "802.11 WiFi",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_WIFI,
	                                  NM_DEVICE_RFKILL_TYPE, RFKILL_TYPE_WLAN,
	                                  NULL);
}

static void
nm_device_wifi_init (NMDeviceWifi * self)
{
	g_signal_connect (self, "state-changed", G_CALLBACK (device_state_changed), NULL);
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

	set_current_ap (self, NULL);
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
	case PROP_HW_ADDRESS:
		g_value_take_string (value, nm_utils_hwaddr_ntoa (&priv->hw_addr, ARPHRD_ETHER));
		break;
	case PROP_PERM_HW_ADDRESS:
		g_value_take_string (value, nm_utils_hwaddr_ntoa (&priv->perm_hw_addr, ARPHRD_ETHER));
		break;
	case PROP_MODE:
		g_value_set_uint (value, wifi_utils_get_mode (priv->wifi_data));
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

	parent_class->get_type_capabilities = real_get_type_capabilities;
	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->hw_is_up = real_hw_is_up;
	parent_class->hw_bring_up = real_hw_bring_up;
	parent_class->hw_take_down = real_hw_take_down;
	parent_class->is_up = real_is_up;
	parent_class->bring_up = real_bring_up;
	parent_class->take_down = real_take_down;
	parent_class->update_hw_address = real_update_hw_address;
	parent_class->update_permanent_hw_address = real_update_permanent_hw_address;
	parent_class->update_initial_hw_address = real_update_initial_hw_address;
	parent_class->get_best_auto_connection = real_get_best_auto_connection;
	parent_class->is_available = real_is_available;
	parent_class->check_connection_compatible = real_check_connection_compatible;
	parent_class->complete_connection = real_complete_connection;
    parent_class->set_enabled = real_set_enabled;

	parent_class->act_stage1_prepare = real_act_stage1_prepare;
	parent_class->act_stage2_config = real_act_stage2_config;
	parent_class->ip4_config_pre_commit = real_ip4_config_pre_commit;
	parent_class->act_stage4_ip4_config_timeout = real_act_stage4_ip4_config_timeout;
	parent_class->act_stage4_ip6_config_timeout = real_act_stage4_ip6_config_timeout;
	parent_class->deactivate = real_deactivate;
	parent_class->can_interrupt_activation = real_can_interrupt_activation;
	parent_class->spec_match_list = spec_match_list;
	parent_class->hwaddr_matches = hwaddr_matches;

	klass->scanning_allowed = scanning_allowed;

	/* Properties */
	g_object_class_install_property (object_class, PROP_HW_ADDRESS,
		g_param_spec_string (NM_DEVICE_WIFI_HW_ADDRESS,
		                     "Active MAC Address",
		                     "Currently set hardware MAC address",
		                     NULL,
		                     G_PARAM_READABLE));

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
		                   NM_802_11_MODE_INFRA,
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
		                   G_PARAM_READABLE | NM_PROPERTY_PARAM_NO_EXPORT));

	g_object_class_install_property (object_class, PROP_IPW_RFKILL_STATE,
		g_param_spec_uint (NM_DEVICE_WIFI_IPW_RFKILL_STATE,
		                   "IpwRfkillState",
		                   "ipw rf-kill state",
		                   RFKILL_UNBLOCKED, RFKILL_HARD_BLOCKED, RFKILL_UNBLOCKED,
		                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | NM_PROPERTY_PARAM_NO_EXPORT));

	/* Signals */
	signals[ACCESS_POINT_ADDED] =
		g_signal_new ("access-point-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, access_point_added),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	signals[ACCESS_POINT_REMOVED] =
		g_signal_new ("access-point-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, access_point_removed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	signals[HIDDEN_AP_FOUND] =
		g_signal_new ("hidden-ap-found",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, hidden_ap_found),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	signals[PROPERTIES_CHANGED] =
		nm_properties_changed_signal_new (object_class,
		                                  G_STRUCT_OFFSET (NMDeviceWifiClass, properties_changed));

	signals[SCANNING_ALLOWED] =
		g_signal_new ("scanning-allowed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, scanning_allowed),
		              scanning_allowed_accumulator, NULL,
		              _nm_marshal_BOOLEAN__VOID,
		              G_TYPE_BOOLEAN, 0);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass), &dbus_glib_nm_device_wifi_object_info);

	dbus_g_error_domain_register (NM_WIFI_ERROR, NULL, NM_TYPE_WIFI_ERROR);
}


