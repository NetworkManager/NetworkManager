/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
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
 * (C) Copyright 2007 - 2010 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

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
#define NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS "cloned-mac-address"
#define NM_SETTING_WIRELESS_MTU         "mtu"
#define NM_SETTING_WIRELESS_SEEN_BSSIDS "seen-bssids"
#define NM_SETTING_WIRELESS_SEC         "security"

typedef struct {
	NMSetting parent;
} NMSettingWireless;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingWirelessClass;

GType nm_setting_wireless_get_type (void);

NMSetting *nm_setting_wireless_new (void);

const GByteArray *nm_setting_wireless_get_ssid               (NMSettingWireless *setting);
const char       *nm_setting_wireless_get_mode               (NMSettingWireless *setting);
const char       *nm_setting_wireless_get_band               (NMSettingWireless *setting);
guint32           nm_setting_wireless_get_channel            (NMSettingWireless *setting);
const GByteArray *nm_setting_wireless_get_bssid              (NMSettingWireless *setting);
guint32           nm_setting_wireless_get_rate               (NMSettingWireless *setting);
guint32           nm_setting_wireless_get_tx_power           (NMSettingWireless *setting);
const GByteArray *nm_setting_wireless_get_mac_address        (NMSettingWireless *setting);
const GByteArray *nm_setting_wireless_get_cloned_mac_address (NMSettingWireless *setting);
guint32           nm_setting_wireless_get_mtu                (NMSettingWireless *setting);
const char       *nm_setting_wireless_get_security           (NMSettingWireless *setting);

gboolean          nm_setting_wireless_add_seen_bssid         (NMSettingWireless *setting,
															  const char *bssid);

guint32           nm_setting_wireless_get_num_seen_bssids    (NMSettingWireless *setting);
const char       *nm_setting_wireless_get_seen_bssid         (NMSettingWireless *setting,
															  guint32 i);

gboolean          nm_setting_wireless_ap_security_compatible (NMSettingWireless *s_wireless,
															  NMSettingWirelessSecurity *s_wireless_sec,
															  guint32 ap_flags,
															  guint32 ap_wpa,
															  guint32 ap_rsn,
															  guint32 ap_mode);

G_END_DECLS

#endif /* NM_SETTING_WIRELESS_H */
