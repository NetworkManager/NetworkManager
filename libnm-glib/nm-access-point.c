/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2011 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>
#include <netinet/ether.h>

#include <nm-connection.h>
#include <nm-setting-connection.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>
#include <nm-utils.h>

#include "nm-default.h"
#include "nm-access-point.h"
#include "NetworkManager.h"
#include "nm-types-private.h"
#include "nm-object-private.h"

G_DEFINE_TYPE (NMAccessPoint, nm_access_point, NM_TYPE_OBJECT)

#define NM_ACCESS_POINT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ACCESS_POINT, NMAccessPointPrivate))

typedef struct {
	DBusGProxy *proxy;

	NM80211ApFlags flags;
	NM80211ApSecurityFlags wpa_flags;
	NM80211ApSecurityFlags rsn_flags;
	GByteArray *ssid;
	guint32 frequency;
	char *bssid;
	NM80211Mode mode;
	guint32 max_bitrate;
	guint8 strength;
	gint last_seen;
} NMAccessPointPrivate;

enum {
	PROP_0,
	PROP_FLAGS,
	PROP_WPA_FLAGS,
	PROP_RSN_FLAGS,
	PROP_SSID,
	PROP_FREQUENCY,
	PROP_HW_ADDRESS,
	PROP_MODE,
	PROP_MAX_BITRATE,
	PROP_STRENGTH,
	PROP_BSSID,
	PROP_LAST_SEEN,

	LAST_PROP
};

/**
 * nm_access_point_new:
 * @connection: the #DBusGConnection
 * @path: the DBusobject path of the access point
 *
 * Creates a new #NMAccessPoint.
 *
 * Returns: (transfer full): a new access point
 **/
GObject *
nm_access_point_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return (GObject *) g_object_new (NM_TYPE_ACCESS_POINT,
	                                 NM_OBJECT_DBUS_CONNECTION, connection,
	                                 NM_OBJECT_DBUS_PATH, path,
	                                 NULL);
}

/**
 * nm_access_point_get_flags:
 * @ap: a #NMAccessPoint
 *
 * Gets the flags of the access point.
 *
 * Returns: the flags
 **/
NM80211ApFlags
nm_access_point_get_flags (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NM_802_11_AP_FLAGS_NONE);

	_nm_object_ensure_inited (NM_OBJECT (ap));
	return NM_ACCESS_POINT_GET_PRIVATE (ap)->flags;
}

/**
 * nm_access_point_get_wpa_flags:
 * @ap: a #NMAccessPoint
 *
 * Gets the WPA (version 1) flags of the access point.
 *
 * Returns: the WPA flags
 **/
NM80211ApSecurityFlags
nm_access_point_get_wpa_flags (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NM_802_11_AP_SEC_NONE);

	_nm_object_ensure_inited (NM_OBJECT (ap));
	return NM_ACCESS_POINT_GET_PRIVATE (ap)->wpa_flags;
}

/**
 * nm_access_point_get_rsn_flags:
 * @ap: a #NMAccessPoint
 *
 * Gets the RSN (Robust Secure Network, ie WPA version 2) flags of the access
 * point.
 *
 * Returns: the RSN flags
 **/
NM80211ApSecurityFlags
nm_access_point_get_rsn_flags (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NM_802_11_AP_SEC_NONE);

	_nm_object_ensure_inited (NM_OBJECT (ap));
	return NM_ACCESS_POINT_GET_PRIVATE (ap)->rsn_flags;
}

/**
 * nm_access_point_get_ssid:
 * @ap: a #NMAccessPoint
 *
 * Gets the SSID of the access point.
 *
 * Returns: the #GByteArray containing the SSID. This is the internal copy used by the
 * access point, and must not be modified.
 **/
const GByteArray *
nm_access_point_get_ssid (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NULL);

	_nm_object_ensure_inited (NM_OBJECT (ap));
	return NM_ACCESS_POINT_GET_PRIVATE (ap)->ssid;
}

/**
 * nm_access_point_get_frequency:
 * @ap: a #NMAccessPoint
 *
 * Gets the frequency of the access point.
 *
 * Returns: the frequency
 **/
guint32
nm_access_point_get_frequency (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	_nm_object_ensure_inited (NM_OBJECT (ap));
	return NM_ACCESS_POINT_GET_PRIVATE (ap)->frequency;
}

/**
 * nm_access_point_get_bssid:
 * @ap: a #NMAccessPoint
 *
 * Gets the Basic Service Set ID (BSSID) of the Wi-Fi access point.
 *
 * Returns: the BSSID of the access point. This is an internal string and must
 * not be modified or freed.
 **/
const char *
nm_access_point_get_bssid (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NULL);

	_nm_object_ensure_inited (NM_OBJECT (ap));
	return NM_ACCESS_POINT_GET_PRIVATE (ap)->bssid;
}

/**
 * nm_access_point_get_hw_address:
 * @ap: a #NMAccessPoint
 *
 * Gets the hardware (MAC) address of the access point.
 *
 * Returns: the hardware address of the access point. This is the internal string used by the
 * access point and must not be modified.
 *
 * Deprecated: 0.9: Use nm_access_point_get_bssid() instead.
 **/
const char *
nm_access_point_get_hw_address (NMAccessPoint *ap)
{
	return nm_access_point_get_bssid (ap);
}

/**
 * nm_access_point_get_mode:
 * @ap: a #NMAccessPoint
 *
 * Gets the mode of the access point.
 *
 * Returns: the mode
 **/
NM80211Mode
nm_access_point_get_mode (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	_nm_object_ensure_inited (NM_OBJECT (ap));
	return NM_ACCESS_POINT_GET_PRIVATE (ap)->mode;
}

/**
 * nm_access_point_get_max_bitrate:
 * @ap: a #NMAccessPoint
 *
 * Gets the maximum bit rate of the access point in kbit/s.
 *
 * Returns: the maximum bit rate (kbit/s)
 **/
guint32
nm_access_point_get_max_bitrate (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	_nm_object_ensure_inited (NM_OBJECT (ap));
	return NM_ACCESS_POINT_GET_PRIVATE (ap)->max_bitrate;
}

/**
 * nm_access_point_get_strength:
 * @ap: a #NMAccessPoint
 *
 * Gets the current signal strength of the access point.
 *
 * Returns: the signal strength
 **/
guint8
nm_access_point_get_strength (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	_nm_object_ensure_inited (NM_OBJECT (ap));
	return NM_ACCESS_POINT_GET_PRIVATE (ap)->strength;
}

/**
 * nm_access_point_get_last_seen:
 * @ap: a #NMAccessPoint
 *
 * Returns the timestamp (in CLOCK_BOOTTIME seconds) for the last time the
 * access point was found in scan results.  A value of -1 means the access
 * point has not been found in a scan.
 *
 * Returns: the last seen time in seconds
 *
 * Since: 1.2
 **/
gint
nm_access_point_get_last_seen (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), -1);

	_nm_object_ensure_inited (NM_OBJECT (ap));
	return NM_ACCESS_POINT_GET_PRIVATE (ap)->last_seen;
}

/**
 * nm_access_point_connection_valid:
 * @ap: an #NMAccessPoint to validate @connection against
 * @connection: an #NMConnection to validate against @ap
 *
 * Validates a given connection against a given Wi-Fi access point to ensure that
 * the connection may be activated with that AP.  The connection must match the
 * @ap's SSID, (if given) BSSID, and other attributes like security settings,
 * channel, band, etc.
 *
 * Returns: %TRUE if the connection may be activated with this Wi-Fi AP,
 * %FALSE if it cannot be.
 **/
gboolean
nm_access_point_connection_valid (NMAccessPoint *ap, NMConnection *connection)
{
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	const char *ctype, *ap_bssid_str;
	const GByteArray *setting_ssid;
	const GByteArray *ap_ssid;
	const GByteArray *setting_bssid;
	struct ether_addr *ap_bssid;
	const char *setting_mode;
	NM80211Mode ap_mode;
	const char *setting_band;
	guint32 ap_freq, setting_chan, ap_chan;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	ctype = nm_setting_connection_get_connection_type (s_con);
	if (strcmp (ctype, NM_SETTING_WIRELESS_SETTING_NAME) != 0)
		return FALSE;

	s_wifi = nm_connection_get_setting_wireless (connection);
	if (!s_wifi)
		return FALSE;

	/* SSID checks */
	ap_ssid = nm_access_point_get_ssid (ap);
	g_warn_if_fail (ap_ssid != NULL);
	setting_ssid = nm_setting_wireless_get_ssid (s_wifi);
	if (!setting_ssid || !ap_ssid || (setting_ssid->len != ap_ssid->len))
		return FALSE;
	if (memcmp (setting_ssid->data, ap_ssid->data, ap_ssid->len) != 0)
		return FALSE;

	/* BSSID checks */
	ap_bssid_str = nm_access_point_get_bssid (ap);
	g_warn_if_fail (ap_bssid_str);
	setting_bssid = nm_setting_wireless_get_bssid (s_wifi);
	if (setting_bssid && ap_bssid_str) {
		g_assert (setting_bssid->len == ETH_ALEN);
		ap_bssid = ether_aton (ap_bssid_str);
		g_warn_if_fail (ap_bssid);
		if (ap_bssid) {
			if (memcmp (ap_bssid->ether_addr_octet, setting_bssid->data, ETH_ALEN) != 0)
				return FALSE;
		}
	}

	/* Mode */
	ap_mode = nm_access_point_get_mode (ap);
	g_warn_if_fail (ap_mode != NM_802_11_MODE_UNKNOWN);
	setting_mode = nm_setting_wireless_get_mode (s_wifi);
	if (setting_mode && ap_mode) {
		if (!strcmp (setting_mode, "infrastructure") && (ap_mode != NM_802_11_MODE_INFRA))
			return FALSE;
		if (!strcmp (setting_mode, "adhoc") && (ap_mode != NM_802_11_MODE_ADHOC))
			return FALSE;
		/* Hotspot never matches against APs as it's a device-specific mode. */
		if (!strcmp (setting_mode, "ap"))
			return FALSE;
	}

	/* Band and Channel/Frequency */
	ap_freq = nm_access_point_get_frequency (ap);
	if (ap_freq) {
		setting_band = nm_setting_wireless_get_band (s_wifi);
		if (g_strcmp0 (setting_band, "a") == 0) {
			if (ap_freq < 4915 || ap_freq > 5825)
				return FALSE;
		} else if (g_strcmp0 (setting_band, "bg") == 0) {
			if (ap_freq < 2412 || ap_freq > 2484)
				return FALSE;
		}

		setting_chan = nm_setting_wireless_get_channel (s_wifi);
		if (setting_chan) {
			ap_chan = nm_utils_wifi_freq_to_channel (ap_freq);
			if (setting_chan != ap_chan)
				return FALSE;
		}
	}

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (!nm_setting_wireless_ap_security_compatible (s_wifi,
	                                                 s_wsec,
	                                                 nm_access_point_get_flags (ap),
	                                                 nm_access_point_get_wpa_flags (ap),
	                                                 nm_access_point_get_rsn_flags (ap),
	                                                 ap_mode))
		return FALSE;

	return TRUE;
}

/**
 * nm_access_point_filter_connections:
 * @ap: an #NMAccessPoint to filter connections for
 * @connections: (element-type NMConnection): a list of
 * #NMConnection objects to filter
 *
 * Filters a given list of connections for a given #NMAccessPoint object and
 * return connections which may be activated with the access point.  Any
 * returned connections will match the @ap's SSID and (if given) BSSID and
 * other attributes like security settings, channel, etc.
 *
 * To obtain the list of connections that are compatible with this access point,
 * use nm_remote_settings_list_connections() and then filter the returned list
 * for a given #NMDevice using nm_device_filter_connections() and finally
 * filter that list with this function.
 *
 * Returns: (transfer container) (element-type NMConnection): a
 * list of #NMConnection objects that could be activated with the given @ap.
 * The elements of the list are owned by their creator and should not be freed
 * by the caller, but the returned list itself is owned by the caller and should
 * be freed with g_slist_free() when it is no longer required.
 **/
GSList *
nm_access_point_filter_connections (NMAccessPoint *ap, const GSList *connections)
{
	GSList *filtered = NULL;
	const GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		if (nm_access_point_connection_valid (ap, candidate))
			filtered = g_slist_prepend (filtered, candidate);
	}

	return g_slist_reverse (filtered);
}

/************************************************************/

static void
nm_access_point_init (NMAccessPoint *ap)
{
	NM_ACCESS_POINT_GET_PRIVATE (ap)->last_seen = -1;
}

static void
dispose (GObject *object)
{
	NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE (object);

	g_clear_object (&priv->proxy);

	G_OBJECT_CLASS (nm_access_point_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE (object);

	if (priv->ssid)
		g_byte_array_free (priv->ssid, TRUE);

	g_free (priv->bssid);

	G_OBJECT_CLASS (nm_access_point_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMAccessPoint *ap = NM_ACCESS_POINT (object);

	_nm_object_ensure_inited (NM_OBJECT (object));

	switch (prop_id) {
	case PROP_FLAGS:
		g_value_set_uint (value, nm_access_point_get_flags (ap));
		break;
	case PROP_WPA_FLAGS:
		g_value_set_uint (value, nm_access_point_get_wpa_flags (ap));
		break;
	case PROP_RSN_FLAGS:
		g_value_set_uint (value, nm_access_point_get_rsn_flags (ap));
		break;
	case PROP_SSID:
		g_value_set_boxed (value, nm_access_point_get_ssid (ap));
		break;
	case PROP_FREQUENCY:
		g_value_set_uint (value, nm_access_point_get_frequency (ap));
		break;
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_access_point_get_bssid (ap));
		break;
	case PROP_BSSID:
		g_value_set_string (value, nm_access_point_get_bssid (ap));
		break;
	case PROP_MODE:
		g_value_set_uint (value, nm_access_point_get_mode (ap));
		break;
	case PROP_MAX_BITRATE:
		g_value_set_uint (value, nm_access_point_get_max_bitrate (ap));
		break;
	case PROP_STRENGTH:
		g_value_set_uchar (value, nm_access_point_get_strength (ap));
		break;
	case PROP_LAST_SEEN:
		g_value_set_int (value, nm_access_point_get_last_seen (ap));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static gboolean
demarshal_ssid (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	if (!_nm_ssid_demarshal (value, (GByteArray **) field))
		return FALSE;

	_nm_object_queue_notify (object, NM_ACCESS_POINT_SSID);
	return TRUE;
}

static void
register_properties (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	const NMPropertiesInfo property_info[] = {
		{ NM_ACCESS_POINT_FLAGS,       &priv->flags },
		{ NM_ACCESS_POINT_WPA_FLAGS,   &priv->wpa_flags },
		{ NM_ACCESS_POINT_RSN_FLAGS,   &priv->rsn_flags },
		{ NM_ACCESS_POINT_SSID,        &priv->ssid, demarshal_ssid },
		{ NM_ACCESS_POINT_FREQUENCY,   &priv->frequency },
		{ NM_ACCESS_POINT_HW_ADDRESS,  &priv->bssid },
		{ NM_ACCESS_POINT_MODE,        &priv->mode },
		{ NM_ACCESS_POINT_MAX_BITRATE, &priv->max_bitrate },
		{ NM_ACCESS_POINT_STRENGTH,    &priv->strength },
		{ NM_ACCESS_POINT_LAST_SEEN,   &priv->last_seen },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (ap),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMAccessPointPrivate *priv;

	G_OBJECT_CLASS (nm_access_point_parent_class)->constructed (object);

	priv = NM_ACCESS_POINT_GET_PRIVATE (object);
	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_ACCESS_POINT);
	register_properties (NM_ACCESS_POINT (object));
}


static void
nm_access_point_class_init (NMAccessPointClass *ap_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ap_class);

	g_type_class_add_private (ap_class, sizeof (NMAccessPointPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */

	/**
	 * NMAccessPoint:flags:
	 *
	 * The flags of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_FLAGS,
		 g_param_spec_uint (NM_ACCESS_POINT_FLAGS, "", "",
		                    NM_802_11_AP_FLAGS_NONE,
		                    NM_802_11_AP_FLAGS_PRIVACY,
		                    NM_802_11_AP_FLAGS_NONE,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMAccessPoint:wpa-flags:
	 *
	 * The WPA flags of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_WPA_FLAGS,
		 g_param_spec_uint (NM_ACCESS_POINT_WPA_FLAGS, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMAccessPoint:rsn-flags:
	 *
	 * The RSN flags of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_RSN_FLAGS,
		 g_param_spec_uint (NM_ACCESS_POINT_RSN_FLAGS, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMAccessPoint:ssid:
	 *
	 * The SSID of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_SSID,
		 g_param_spec_boxed (NM_ACCESS_POINT_SSID, "", "",
		                     NM_TYPE_SSID,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMAccessPoint:frequency:
	 *
	 * The frequency of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_FREQUENCY,
		 g_param_spec_uint (NM_ACCESS_POINT_FREQUENCY, "", "",
		                    0, 10000, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMAccessPoint:bssid:
	 *
	 * The BSSID of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_BSSID,
		 g_param_spec_string (NM_ACCESS_POINT_BSSID, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMAccessPoint:hw-address:
	 *
	 * The hardware address of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_ACCESS_POINT_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
	
	/**
	 * NMAccessPoint:mode:
	 *
	 * The mode of the access point; either "infrastructure" (a central
	 * coordinator of the wireless network allowing clients to connect) or
	 * "ad-hoc" (a network with no central controller).
	 **/
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_uint (NM_ACCESS_POINT_MODE, "", "",
		                    NM_802_11_MODE_ADHOC, NM_802_11_MODE_INFRA, NM_802_11_MODE_INFRA,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMAccessPoint:max-bitrate:
	 *
	 * The maximum bit rate of the access point in kbit/s.
	 **/
	g_object_class_install_property
		(object_class, PROP_MAX_BITRATE,
		 g_param_spec_uint (NM_ACCESS_POINT_MAX_BITRATE, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMAccessPoint:strength:
	 *
	 * The current signal strength of the access point.
	 **/
	g_object_class_install_property
		(object_class, PROP_STRENGTH,
		 g_param_spec_uchar (NM_ACCESS_POINT_STRENGTH, "", "",
		                     0, G_MAXUINT8, 0,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMAccessPoint:last-seen:
	 *
	 * The timestamp (in CLOCK_BOOTTIME seconds) for the last time the
	 * access point was found in scan results.  A value of -1 means the
	 * access point has not been found in a scan.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_LAST_SEEN,
		 g_param_spec_int (NM_ACCESS_POINT_LAST_SEEN, "", "",
		                   -1, G_MAXINT, -1,
		                   G_PARAM_READABLE |
		                   G_PARAM_STATIC_STRINGS));
}
