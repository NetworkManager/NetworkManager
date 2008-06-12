/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SETTING_WIRELESS_H
#define NM_SETTING_WIRELESS_H

#include <nm-setting.h>
#include <nm-setting-wireless-security.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_WIRELESS            (nm_setting_wireless_get_type ())
#define NM_SETTING_WIRELESS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_WIRELESS, NMSettingWireless))
#define NM_SETTING_WIRELESS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_WIRELESS, NMSettingWirelessClass))
#define NM_IS_SETTING_WIRELESS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_WIRELESS))
#define NM_IS_SETTING_WIRELESS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_WIRELESS))
#define NM_SETTING_WIRELESS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_WIRELESS, NMSettingWirelessClass))

#define NM_SETTING_WIRELESS_SETTING_NAME "802-11-wireless"

typedef enum
{
	NM_SETTING_WIRELESS_ERROR_UNKNOWN = 0,
	NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
	NM_SETTING_WIRELESS_ERROR_MISSING_PROPERTY,
	NM_SETTING_WIRELESS_ERROR_MISSING_SECURITY_SETTING,
	NM_SETTING_WIRELESS_ERROR_CHANNEL_REQUIRES_BAND
} NMSettingWirelessError;

#define NM_TYPE_SETTING_WIRELESS_ERROR (nm_setting_wireless_error_get_type ()) 
GType nm_setting_wireless_error_get_type (void);

#define NM_SETTING_WIRELESS_ERROR nm_setting_wireless_error_quark ()
GQuark nm_setting_wireless_error_quark (void);

#define NM_SETTING_WIRELESS_SSID        "ssid"
#define NM_SETTING_WIRELESS_MODE        "mode"
#define NM_SETTING_WIRELESS_BAND        "band"
#define NM_SETTING_WIRELESS_CHANNEL     "channel"
#define NM_SETTING_WIRELESS_BSSID       "bssid"
#define NM_SETTING_WIRELESS_RATE        "rate"
#define NM_SETTING_WIRELESS_TX_POWER    "tx-power"
#define NM_SETTING_WIRELESS_MAC_ADDRESS "mac-address"
#define NM_SETTING_WIRELESS_MTU         "mtu"
#define NM_SETTING_WIRELESS_SEEN_BSSIDS "seen-bssids"
#define NM_SETTING_WIRELESS_SEC         "security"

typedef struct {
	NMSetting parent;

	GByteArray *ssid;
	char *mode;
	char *band;
	guint32 channel;
	GByteArray *bssid;
	guint32 rate;
	guint32 tx_power;
	GByteArray *mac_address;
	guint32 mtu;
	GSList *seen_bssids;
	char *security;
} NMSettingWireless;

typedef struct {
	NMSettingClass parent;
} NMSettingWirelessClass;

GType nm_setting_wireless_get_type (void);

NMSetting *nm_setting_wireless_new (void);

gboolean   nm_setting_wireless_ap_security_compatible (NMSettingWireless *s_wireless,
											NMSettingWirelessSecurity *s_wireless_sec,
											guint32 ap_flags,
											guint32 ap_wpa,
											guint32 ap_rsn,
											guint32 ap_mode);

G_END_DECLS

#endif /* NM_SETTING_WIRELESS_H */
