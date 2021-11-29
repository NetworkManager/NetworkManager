/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#include "libnm-client-impl/nm-default-libnm.h"

#include "nm-access-point.h"

#include <linux/if_ether.h>

#include "nm-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-utils.h"

#include "nm-dbus-interface.h"
#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMAccessPoint,
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
                             PROP_LAST_SEEN, );

typedef struct {
    GBytes *ssid;
    char   *bssid;
    guint32 flags;
    guint32 wpa_flags;
    guint32 rsn_flags;
    guint32 frequency;
    guint32 mode;
    guint32 max_bitrate;
    gint32  last_seen;
    guint8  strength;
} NMAccessPointPrivate;

struct _NMAccessPoint {
    NMObject             parent;
    NMAccessPointPrivate _priv;
};

struct _NMAccessPointClass {
    NMObjectClass parent;
};

G_DEFINE_TYPE(NMAccessPoint, nm_access_point, NM_TYPE_OBJECT)

#define NM_ACCESS_POINT_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMAccessPoint, NM_IS_ACCESS_POINT, NMObject)

/*****************************************************************************/

/**
 * nm_access_point_get_flags:
 * @ap: a #NMAccessPoint
 *
 * Gets the flags of the access point.
 *
 * Returns: the flags
 **/
NM80211ApFlags
nm_access_point_get_flags(NMAccessPoint *ap)
{
    g_return_val_if_fail(NM_IS_ACCESS_POINT(ap), NM_802_11_AP_FLAGS_NONE);

    return NM_ACCESS_POINT_GET_PRIVATE(ap)->flags;
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
nm_access_point_get_wpa_flags(NMAccessPoint *ap)
{
    g_return_val_if_fail(NM_IS_ACCESS_POINT(ap), NM_802_11_AP_SEC_NONE);

    return NM_ACCESS_POINT_GET_PRIVATE(ap)->wpa_flags;
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
nm_access_point_get_rsn_flags(NMAccessPoint *ap)
{
    g_return_val_if_fail(NM_IS_ACCESS_POINT(ap), NM_802_11_AP_SEC_NONE);

    return NM_ACCESS_POINT_GET_PRIVATE(ap)->rsn_flags;
}

/**
 * nm_access_point_get_ssid:
 * @ap: a #NMAccessPoint
 *
 * Gets the SSID of the access point.
 *
 * Returns: (transfer none): the #GBytes containing the SSID, or %NULL if the
 *   SSID is unknown.
 **/
GBytes *
nm_access_point_get_ssid(NMAccessPoint *ap)
{
    NMAccessPointPrivate *priv;

    g_return_val_if_fail(NM_IS_ACCESS_POINT(ap), NULL);

    priv = NM_ACCESS_POINT_GET_PRIVATE(ap);
    nm_assert(!priv->ssid || g_bytes_get_size(priv->ssid) > 0);
    return priv->ssid;
}

/**
 * nm_access_point_get_frequency:
 * @ap: a #NMAccessPoint
 *
 * Gets the frequency of the access point in MHz.
 *
 * Returns: the frequency in MHz
 **/
guint32
nm_access_point_get_frequency(NMAccessPoint *ap)
{
    g_return_val_if_fail(NM_IS_ACCESS_POINT(ap), 0);

    return NM_ACCESS_POINT_GET_PRIVATE(ap)->frequency;
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
nm_access_point_get_bssid(NMAccessPoint *ap)
{
    g_return_val_if_fail(NM_IS_ACCESS_POINT(ap), NULL);

    return _nml_coerce_property_str_not_empty(NM_ACCESS_POINT_GET_PRIVATE(ap)->bssid);
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
nm_access_point_get_mode(NMAccessPoint *ap)
{
    g_return_val_if_fail(NM_IS_ACCESS_POINT(ap), 0);

    return NM_ACCESS_POINT_GET_PRIVATE(ap)->mode;
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
nm_access_point_get_max_bitrate(NMAccessPoint *ap)
{
    g_return_val_if_fail(NM_IS_ACCESS_POINT(ap), 0);

    return NM_ACCESS_POINT_GET_PRIVATE(ap)->max_bitrate;
}

/**
 * nm_access_point_get_strength:
 * @ap: a #NMAccessPoint
 *
 * Gets the current signal strength of the access point as a percentage.
 *
 * Returns: the signal strength (0 to 100)
 **/
guint8
nm_access_point_get_strength(NMAccessPoint *ap)
{
    g_return_val_if_fail(NM_IS_ACCESS_POINT(ap), 0);

    return NM_ACCESS_POINT_GET_PRIVATE(ap)->strength;
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
int
nm_access_point_get_last_seen(NMAccessPoint *ap)
{
    g_return_val_if_fail(NM_IS_ACCESS_POINT(ap), -1);

    return NM_ACCESS_POINT_GET_PRIVATE(ap)->last_seen;
}
NM_BACKPORT_SYMBOL(libnm_1_0_6, int, nm_access_point_get_last_seen, (NMAccessPoint * ap), (ap));

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
nm_access_point_connection_valid(NMAccessPoint *ap, NMConnection *connection)
{
    NMSettingConnection       *s_con;
    NMSettingWireless         *s_wifi;
    NMSettingWirelessSecurity *s_wsec;
    const char                *ctype, *ap_bssid;
    GBytes                    *setting_ssid;
    GBytes                    *ap_ssid;
    const char                *setting_bssid;
    const char                *setting_mode;
    NM80211Mode                ap_mode;
    const char                *setting_band;
    guint32                    ap_freq, setting_chan, ap_chan;

    g_return_val_if_fail(NM_IS_ACCESS_POINT(ap), FALSE);
    g_return_val_if_fail(NM_IS_CONNECTION(connection), FALSE);

    s_con = nm_connection_get_setting_connection(connection);
    if (!s_con)
        return FALSE;

    ctype = nm_setting_connection_get_connection_type(s_con);
    if (!ctype || !nm_streq(ctype, NM_SETTING_WIRELESS_SETTING_NAME))
        return FALSE;

    s_wifi = nm_connection_get_setting_wireless(connection);
    if (!s_wifi)
        return FALSE;

    /* SSID checks */
    ap_ssid = nm_access_point_get_ssid(ap);
    if (!ap_ssid)
        return FALSE;
    setting_ssid = nm_setting_wireless_get_ssid(s_wifi);
    if (!setting_ssid || !g_bytes_equal(ap_ssid, setting_ssid))
        return FALSE;

    /* BSSID checks */
    ap_bssid = nm_access_point_get_bssid(ap);
    if (!ap_bssid)
        return FALSE;
    setting_bssid = nm_setting_wireless_get_bssid(s_wifi);
    if (setting_bssid) {
        guint8 c[ETH_ALEN];

        if (!nm_utils_hwaddr_aton(ap_bssid, c, ETH_ALEN)
            || !nm_utils_hwaddr_matches(c, ETH_ALEN, setting_bssid, -1))
            return FALSE;
    }

    /* Mode */
    ap_mode = nm_access_point_get_mode(ap);
    if (ap_mode == NM_802_11_MODE_UNKNOWN)
        return FALSE;
    setting_mode = nm_setting_wireless_get_mode(s_wifi);
    if (setting_mode && ap_mode) {
        if (!strcmp(setting_mode, "infrastructure") && (ap_mode != NM_802_11_MODE_INFRA))
            return FALSE;
        if (!strcmp(setting_mode, "adhoc") && (ap_mode != NM_802_11_MODE_ADHOC))
            return FALSE;
        /* Hotspot never matches against APs as it's a device-specific mode. */
        if (!strcmp(setting_mode, "ap"))
            return FALSE;
    }

    /* Band and Channel/Frequency */
    ap_freq = nm_access_point_get_frequency(ap);
    if (ap_freq) {
        setting_band = nm_setting_wireless_get_band(s_wifi);
        if (g_strcmp0(setting_band, "a") == 0) {
            if (ap_freq < 4915 || ap_freq > 5825)
                return FALSE;
        } else if (g_strcmp0(setting_band, "bg") == 0) {
            if (ap_freq < 2412 || ap_freq > 2484)
                return FALSE;
        }

        setting_chan = nm_setting_wireless_get_channel(s_wifi);
        if (setting_chan) {
            ap_chan = nm_utils_wifi_freq_to_channel(ap_freq);
            if (setting_chan != ap_chan)
                return FALSE;
        }
    }

    s_wsec = nm_connection_get_setting_wireless_security(connection);
    if (!nm_setting_wireless_ap_security_compatible(s_wifi,
                                                    s_wsec,
                                                    nm_access_point_get_flags(ap),
                                                    nm_access_point_get_wpa_flags(ap),
                                                    nm_access_point_get_rsn_flags(ap),
                                                    ap_mode))
        return FALSE;

    return TRUE;
}

/**
 * nm_access_point_filter_connections:
 * @ap: an #NMAccessPoint to filter connections for
 * @connections: (element-type NMConnection): an array of #NMConnections to
 * filter
 *
 * Filters a given array of connections for a given #NMAccessPoint object and
 * returns connections which may be activated with the access point.  Any
 * returned connections will match the @ap's SSID and (if given) BSSID and
 * other attributes like security settings, channel, etc.
 *
 * To obtain the list of connections that are compatible with this access point,
 * use nm_client_get_connections() and then filter the returned list for a given
 * #NMDevice using nm_device_filter_connections() and finally filter that list
 * with this function.
 *
 * Returns: (transfer full) (element-type NMConnection): an array of
 * #NMConnections that could be activated with the given @ap.  The array should
 * be freed with g_ptr_array_unref() when it is no longer required.
 *
 * WARNING: the transfer annotation for this function may not work correctly
 *   with bindings. See https://gitlab.gnome.org/GNOME/gobject-introspection/-/issues/305.
 *   You can filter the list yourself with nm_access_point_connection_valid().
 **/
GPtrArray *
nm_access_point_filter_connections(NMAccessPoint *ap, const GPtrArray *connections)
{
    GPtrArray *filtered;
    guint      i;

    g_return_val_if_fail(NM_IS_ACCESS_POINT(ap), NULL);

    if (!connections)
        return NULL;

    filtered = g_ptr_array_new_with_free_func(g_object_unref);
    for (i = 0; i < connections->len; i++) {
        NMConnection *candidate = connections->pdata[i];

        if (nm_access_point_connection_valid(ap, candidate))
            g_ptr_array_add(filtered, g_object_ref(candidate));
    }

    return filtered;
}

/*****************************************************************************/

static NMLDBusNotifyUpdatePropFlags
_notify_update_prop_hw_address(NMClient               *client,
                               NMLDBusObject          *dbobj,
                               const NMLDBusMetaIface *meta_iface,
                               guint                   dbus_property_idx,
                               GVariant               *value)
{
    NMAccessPoint        *self = NM_ACCESS_POINT(dbobj->nmobj);
    NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE(self);

    g_free(priv->bssid);
    priv->bssid = value ? g_variant_dup_string(value, NULL) : 0u;
    _notify(self, PROP_HW_ADDRESS);
    return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NOTIFY;
}

/*****************************************************************************/

static void
nm_access_point_init(NMAccessPoint *ap)
{
    NM_ACCESS_POINT_GET_PRIVATE(ap)->last_seen = -1;
}

static void
finalize(GObject *object)
{
    NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE(object);

    if (priv->ssid)
        g_bytes_unref(priv->ssid);
    g_free(priv->bssid);

    G_OBJECT_CLASS(nm_access_point_parent_class)->finalize(object);
}

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMAccessPoint *ap = NM_ACCESS_POINT(object);

    switch (prop_id) {
    case PROP_FLAGS:
        g_value_set_flags(value, nm_access_point_get_flags(ap));
        break;
    case PROP_WPA_FLAGS:
        g_value_set_flags(value, nm_access_point_get_wpa_flags(ap));
        break;
    case PROP_RSN_FLAGS:
        g_value_set_flags(value, nm_access_point_get_rsn_flags(ap));
        break;
    case PROP_SSID:
        g_value_set_boxed(value, nm_access_point_get_ssid(ap));
        break;
    case PROP_FREQUENCY:
        g_value_set_uint(value, nm_access_point_get_frequency(ap));
        break;
    case PROP_HW_ADDRESS:
        g_value_set_string(value, nm_access_point_get_bssid(ap));
        break;
    case PROP_BSSID:
        g_value_set_string(value, nm_access_point_get_bssid(ap));
        break;
    case PROP_MODE:
        g_value_set_enum(value, nm_access_point_get_mode(ap));
        break;
    case PROP_MAX_BITRATE:
        g_value_set_uint(value, nm_access_point_get_max_bitrate(ap));
        break;
    case PROP_STRENGTH:
        g_value_set_uchar(value, nm_access_point_get_strength(ap));
        break;
    case PROP_LAST_SEEN:
        g_value_set_int(value, nm_access_point_get_last_seen(ap));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_accesspoint = NML_DBUS_META_IFACE_INIT_PROP(
    NM_DBUS_INTERFACE_ACCESS_POINT,
    nm_access_point_get_type,
    NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
    NML_DBUS_META_IFACE_DBUS_PROPERTIES(
        NML_DBUS_META_PROPERTY_INIT_U("Flags", PROP_FLAGS, NMAccessPoint, _priv.flags),
        NML_DBUS_META_PROPERTY_INIT_U("Frequency", PROP_FREQUENCY, NMAccessPoint, _priv.frequency),
        NML_DBUS_META_PROPERTY_INIT_FCN("HwAddress",
                                        PROP_BSSID,
                                        "s",
                                        _notify_update_prop_hw_address),
        NML_DBUS_META_PROPERTY_INIT_I("LastSeen", PROP_LAST_SEEN, NMAccessPoint, _priv.last_seen),
        NML_DBUS_META_PROPERTY_INIT_U("MaxBitrate",
                                      PROP_MAX_BITRATE,
                                      NMAccessPoint,
                                      _priv.max_bitrate),
        NML_DBUS_META_PROPERTY_INIT_U("Mode", PROP_MODE, NMAccessPoint, _priv.mode),
        NML_DBUS_META_PROPERTY_INIT_U("RsnFlags", PROP_RSN_FLAGS, NMAccessPoint, _priv.rsn_flags),
        NML_DBUS_META_PROPERTY_INIT_AY("Ssid", PROP_SSID, NMAccessPoint, _priv.ssid),
        NML_DBUS_META_PROPERTY_INIT_Y("Strength", PROP_STRENGTH, NMAccessPoint, _priv.strength),
        NML_DBUS_META_PROPERTY_INIT_U("WpaFlags",
                                      PROP_WPA_FLAGS,
                                      NMAccessPoint,
                                      _priv.wpa_flags), ), );

static void
nm_access_point_class_init(NMAccessPointClass *ap_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(ap_class);

    object_class->get_property = get_property;
    object_class->finalize     = finalize;

    /**
     * NMAccessPoint:flags:
     *
     * The flags of the access point.
     **/
    obj_properties[PROP_FLAGS] = g_param_spec_flags(NM_ACCESS_POINT_FLAGS,
                                                    "",
                                                    "",
                                                    NM_TYPE_802_11_AP_FLAGS,
                                                    NM_802_11_AP_FLAGS_NONE,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMAccessPoint:wpa-flags:
     *
     * The WPA flags of the access point.
     **/
    obj_properties[PROP_WPA_FLAGS] = g_param_spec_flags(NM_ACCESS_POINT_WPA_FLAGS,
                                                        "",
                                                        "",
                                                        NM_TYPE_802_11_AP_SECURITY_FLAGS,
                                                        NM_802_11_AP_SEC_NONE,
                                                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMAccessPoint:rsn-flags:
     *
     * The RSN flags of the access point.
     **/
    obj_properties[PROP_RSN_FLAGS] = g_param_spec_flags(NM_ACCESS_POINT_RSN_FLAGS,
                                                        "",
                                                        "",
                                                        NM_TYPE_802_11_AP_SECURITY_FLAGS,
                                                        NM_802_11_AP_SEC_NONE,
                                                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMAccessPoint:ssid:
     *
     * The SSID of the access point, or %NULL if it is not known.
     **/
    obj_properties[PROP_SSID] = g_param_spec_boxed(NM_ACCESS_POINT_SSID,
                                                   "",
                                                   "",
                                                   G_TYPE_BYTES,
                                                   G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMAccessPoint:frequency:
     *
     * The frequency of the access point.
     **/
    obj_properties[PROP_FREQUENCY] = g_param_spec_uint(NM_ACCESS_POINT_FREQUENCY,
                                                       "",
                                                       "",
                                                       0,
                                                       10000,
                                                       0,
                                                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMAccessPoint:bssid:
     *
     * The BSSID of the access point.
     **/
    obj_properties[PROP_BSSID] = g_param_spec_string(NM_ACCESS_POINT_BSSID,
                                                     "",
                                                     "",
                                                     NULL,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMAccessPoint:hw-address:
     *
     * Alias for #NMAccessPoint:bssid.
     *
     * Deprecated: 1.0: Use #NMAccessPoint:bssid.
     **/
    obj_properties[PROP_HW_ADDRESS] =
        g_param_spec_string(NM_ACCESS_POINT_HW_ADDRESS,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMAccessPoint:mode:
     *
     * The mode of the access point; either "infrastructure" (a central
     * coordinator of the wireless network allowing clients to connect) or
     * "ad-hoc" (a network with no central controller).
     **/
    obj_properties[PROP_MODE] = g_param_spec_enum(NM_ACCESS_POINT_MODE,
                                                  "",
                                                  "",
                                                  NM_TYPE_802_11_MODE,
                                                  NM_802_11_MODE_UNKNOWN,
                                                  G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMAccessPoint:max-bitrate:
     *
     * The maximum bit rate of the access point in kbit/s.
     **/
    obj_properties[PROP_MAX_BITRATE] = g_param_spec_uint(NM_ACCESS_POINT_MAX_BITRATE,
                                                         "",
                                                         "",
                                                         0,
                                                         G_MAXUINT32,
                                                         0,
                                                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMAccessPoint:strength:
     *
     * The current signal strength of the access point.
     **/
    obj_properties[PROP_STRENGTH] = g_param_spec_uchar(NM_ACCESS_POINT_STRENGTH,
                                                       "",
                                                       "",
                                                       0,
                                                       G_MAXUINT8,
                                                       0,
                                                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMAccessPoint:last-seen:
     *
     * The timestamp (in CLOCK_BOOTTIME seconds) for the last time the
     * access point was found in scan results.  A value of -1 means the
     * access point has not been found in a scan.
     *
     * Since: 1.2
     **/
    obj_properties[PROP_LAST_SEEN] = g_param_spec_int(NM_ACCESS_POINT_LAST_SEEN,
                                                      "",
                                                      "",
                                                      -1,
                                                      G_MAXINT,
                                                      -1,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    _nml_dbus_meta_class_init_with_properties(object_class, &_nml_dbus_meta_iface_nm_accesspoint);
}
