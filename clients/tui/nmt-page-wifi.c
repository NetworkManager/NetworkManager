/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-page-wifi
 * @short_description: The editor page for Wi-Fi connections
 *
 * #NmtPageWifi is the editor page for Wi-Fi connections, which
 * includes both #NMSettingWireless and #NMSettingWirelessSecurity
 * properties.
 */

#include "config.h"

#include <stdlib.h>

#include "nm-default.h"
#include "nmt-page-wifi.h"
#include "nmt-mac-entry.h"
#include "nmt-mtu-entry.h"
#include "nmt-password-fields.h"

#include "nm-editor-bindings.h"

G_DEFINE_TYPE (NmtPageWifi, nmt_page_wifi, NMT_TYPE_EDITOR_PAGE_DEVICE)

#define NMT_PAGE_WIFI_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_PAGE_WIFI, NmtPageWifiPrivate))

typedef struct {
	NMSettingWirelessSecurity *s_wsec;

} NmtPageWifiPrivate;

NmtEditorPage *
nmt_page_wifi_new (NMConnection   *conn,
                   NmtDeviceEntry *deventry)
{
	return g_object_new (NMT_TYPE_PAGE_WIFI,
	                     "connection", conn,
	                     "device-entry", deventry,
	                     NULL);
}

static void
nmt_page_wifi_init (NmtPageWifi *wifi)
{
}

static NmtNewtPopupEntry wifi_mode[] = {
	{ NC_("Wi-Fi", "Client"), NM_SETTING_WIRELESS_MODE_INFRA },
	{ N_("Access Point"),     NM_SETTING_WIRELESS_MODE_AP },
	{ N_("Ad-Hoc Network"),   NM_SETTING_WIRELESS_MODE_ADHOC },
	{ NULL, NULL }
};

static NmtNewtPopupEntry wifi_band[] = {
	{ NC_("Wi-Fi", "Automatic"), NULL },
	/* 802.11a Wi-Fi network */
	{ N_("A (5 GHz)"),           "a" },
	/* 802.11b / 802.11g Wi-Fi network */
	{ N_("B/G (2.4 GHz)"),       "bg" },
	{ NULL, NULL }
};

static NmtNewtPopupEntry wifi_security[] = {
	{ NC_("Wi-Fi security", "None"),           "none" },
	{ N_("WPA & WPA2 Personal"),               "wpa-personal" },
	{ N_("WPA & WPA2 Enterprise"),             "wpa-enterprise" },
	{ N_("WEP 40/128-bit Key (Hex or ASCII)"), "wep-key" },
	{ N_("WEP 128-bit Passphrase"),            "wep-passphrase" },
	{ N_("Dynamic WEP (802.1x)"),              "dynamic-wep" },
	{ N_("LEAP"),                              "leap" },
	{ NULL, NULL }
};

static NmtNewtPopupEntry wep_index[] = {
	{ NC_("WEP key index", "1 (Default)"), "1" },
	{ NC_("WEP key index", "2"),           "2" },
	{ NC_("WEP key index", "3"),           "3" },
	{ NC_("WEP key index", "4"),           "4" },
	{ NULL, NULL }
};

static NmtNewtPopupEntry wep_auth[] = {
	{ N_("Open System"), "open" },
	{ N_("Shared Key"),  "shared" },
	{ NULL, NULL }
};

static gboolean
mode_transform_to_band_visibility (GBinding     *binding,
                                   const GValue *source_value,
                                   GValue       *target_value,
                                   gpointer      user_data)
{
	if (!g_strcmp0 (g_value_get_string (source_value), NM_SETTING_WIRELESS_MODE_INFRA))
		g_value_set_boolean (target_value, FALSE);
	else
		g_value_set_boolean (target_value, TRUE);
	return TRUE;
}

static gboolean
band_transform_to_channel_visibility (GBinding     *binding,
                                      const GValue *source_value,
                                      GValue       *target_value,
                                      gpointer      user_data)
{
	g_value_set_boolean (target_value, g_value_get_string (source_value) != NULL);
	return TRUE;
}

static gboolean
ssid_transform_to_entry (GBinding     *binding,
                         const GValue *source_value,
                         GValue       *target_value,
                         gpointer      user_data)
{
	GBytes *ssid;
	char *utf8;

	ssid = g_value_get_boxed (source_value);
	if (ssid)
		utf8 = nm_utils_ssid_to_utf8 (g_bytes_get_data (ssid, NULL),
		                              g_bytes_get_size (ssid));
	else
		utf8 = g_strdup ("");
	g_value_take_string (target_value, utf8);
	return TRUE;
}

static gboolean
ssid_transform_from_entry (GBinding     *binding,
                           const GValue *source_value,
                           GValue       *target_value,
                           gpointer      user_data)
{
	NMSettingWireless *s_wireless = user_data;
	const char *text;
	GBytes *old_ssid, *ssid;
	char *utf8;

	text = g_value_get_string (source_value);

	old_ssid = nm_setting_wireless_get_ssid (s_wireless);
	if (old_ssid)
		utf8 = nm_utils_ssid_to_utf8 (g_bytes_get_data (old_ssid, NULL),
		                              g_bytes_get_size (old_ssid));
	else
		utf8 = g_strdup ("");

	if (!g_strcmp0 (text, utf8)) {
		g_free (utf8);
		return FALSE;
	}
	g_free (utf8);

	ssid = g_bytes_new (text, strlen (text));
	g_value_take_boxed (target_value, ssid);
	return TRUE;
}

static void
nmt_page_wifi_constructed (GObject *object)
{
	NmtPageWifiPrivate *priv = NMT_PAGE_WIFI_GET_PRIVATE (object);
	NmtPageWifi *wifi = NMT_PAGE_WIFI (object);
	NmtDeviceEntry *deventry;
	NmtEditorSection *section;
	NmtEditorGrid *grid;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NmtNewtWidget *widget, *hbox, *subgrid;
	NmtNewtWidget *mode, *band, *security, *entry;
	NmtNewtStack *stack;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (wifi));
	s_wireless = nm_connection_get_setting_wireless (conn);
	if (!s_wireless) {
		nm_connection_add_setting (conn, nm_setting_wireless_new ());
		s_wireless = nm_connection_get_setting_wireless (conn);
	}

	s_wsec = nm_connection_get_setting_wireless_security (conn);
	if (!s_wsec) {
		/* It makes things simpler if we always have a
		 * NMSettingWirelessSecurity; we'll hold a ref on one, and add
		 * it to and remove it from the connection as needed.
		 */
		s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());
	}
	priv->s_wsec = g_object_ref_sink (s_wsec);

	deventry = nmt_editor_page_device_get_device_entry (NMT_EDITOR_PAGE_DEVICE (object));
	g_object_bind_property (s_wireless, NM_SETTING_WIRELESS_MAC_ADDRESS,
	                        deventry, "mac-address",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

	section = nmt_editor_section_new (_("WI-FI"), NULL, TRUE);
	grid = nmt_editor_section_get_body (section);

	widget = nmt_newt_entry_new (40, NMT_NEWT_ENTRY_NONEMPTY);
	g_object_bind_property_full (s_wireless, NM_SETTING_WIRELESS_SSID,
	                             widget, "text",
	                             G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE,
	                             ssid_transform_to_entry,
	                             ssid_transform_from_entry,
	                             s_wireless, NULL);
	nmt_editor_grid_append (grid, _("SSID"), widget, NULL);

	widget = nmt_newt_popup_new (wifi_mode);
	g_object_bind_property (s_wireless, NM_SETTING_WIRELESS_MODE,
	                        widget, "active-id",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Mode"), widget, NULL);
	mode = widget;

	hbox = nmt_newt_grid_new ();
	widget = nmt_newt_popup_new (wifi_band);
	g_object_bind_property (s_wireless, NM_SETTING_WIRELESS_BAND,
	                        widget, "active-id",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_newt_grid_add (NMT_NEWT_GRID (hbox), widget, 0, 0);
	band = widget;

	widget = nmt_newt_entry_numeric_new (10, 0, 255);
	g_object_bind_property (s_wireless, NM_SETTING_WIRELESS_CHANNEL,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_newt_grid_add (NMT_NEWT_GRID (hbox), widget, 1, 0);
	nmt_newt_widget_set_padding (widget, 1, 0, 0, 0);

	g_object_bind_property_full (band, "active-id", widget, "visible",
	                             G_BINDING_SYNC_CREATE,
	                             band_transform_to_channel_visibility,
	                             NULL, NULL, NULL);
	g_object_bind_property_full (mode, "active-id", hbox, "visible",
	                             G_BINDING_SYNC_CREATE,
	                             mode_transform_to_band_visibility,
	                             NULL, NULL, NULL);
	nmt_editor_grid_append (grid, _("Channel"), hbox, NULL);

	nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	widget = nmt_newt_popup_new (wifi_security);
	nmt_editor_grid_append (grid, _("Security"), widget, NULL);
	security = widget;

	widget = nmt_newt_stack_new ();
	stack = NMT_NEWT_STACK (widget);

	/* none */
	subgrid = nmt_editor_grid_new ();
	nmt_newt_stack_add (stack, "none", subgrid);

	/* wpa-personal */
	subgrid = nmt_editor_grid_new ();
	widget = nmt_password_fields_new (40, NMT_PASSWORD_FIELDS_SHOW_PASSWORD);
	g_object_bind_property (s_wsec, NM_SETTING_WIRELESS_SECURITY_PSK,
	                        widget, "password",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
	nmt_editor_grid_append (NMT_EDITOR_GRID (subgrid), _("Password"), widget, NULL);
	nmt_newt_stack_add (stack, "wpa-personal", subgrid);

	/* "wpa-enterprise" */
	// FIXME
	widget = nmt_newt_label_new (_("(No support for wpa-enterprise yet...)"));
	nmt_newt_stack_add (stack, "wpa-enterprise", widget);

	/* wep-key */
	subgrid = nmt_editor_grid_new ();

	widget = entry = nmt_password_fields_new (40, NMT_PASSWORD_FIELDS_SHOW_PASSWORD);
	nmt_editor_grid_append (NMT_EDITOR_GRID (subgrid), _("Key"), widget, NULL);

	widget = nmt_newt_popup_new (wep_index);
	nmt_editor_grid_append (NMT_EDITOR_GRID (subgrid), _("WEP index"), widget, NULL);

	nm_editor_bind_wireless_security_wep_key (s_wsec,
	                                          entry, "password",
	                                          widget, "active",
	                                          G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

	widget = nmt_newt_popup_new (wep_auth);
	nmt_editor_grid_append (NMT_EDITOR_GRID (subgrid), _("Authentication"), widget, NULL);

	nmt_newt_stack_add (stack, "wep-key", subgrid);

	/* wep-passphrase */
	subgrid = nmt_editor_grid_new ();

	widget = entry = nmt_password_fields_new (40, NMT_PASSWORD_FIELDS_SHOW_PASSWORD);
	nmt_editor_grid_append (NMT_EDITOR_GRID (subgrid), _("Password"), widget, NULL);

	widget = nmt_newt_popup_new (wep_index);
	nmt_editor_grid_append (NMT_EDITOR_GRID (subgrid), _("WEP index"), widget, NULL);

	nm_editor_bind_wireless_security_wep_key (s_wsec,
	                                          entry, "password",
	                                          widget, "active",
	                                          G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

	widget = nmt_newt_popup_new (wep_auth);
	nmt_editor_grid_append (NMT_EDITOR_GRID (subgrid), _("Authentication"), widget, NULL);

	nmt_newt_stack_add (stack, "wep-passphrase", subgrid);

	/* "dynamic-wep" */
	// FIXME
	widget = nmt_newt_label_new (_("(No support for dynamic-wep yet...)"));
	nmt_newt_stack_add (stack, "dynamic-wep", widget);

	/* leap */
	subgrid = nmt_editor_grid_new ();

	widget = nmt_newt_entry_new (40, NMT_NEWT_ENTRY_NONEMPTY);
	nmt_editor_grid_append (NMT_EDITOR_GRID (subgrid), _("Username"), widget, NULL);
	g_object_bind_property (s_wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME,
	                        widget, "text",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

	widget = nmt_password_fields_new (40, NMT_PASSWORD_FIELDS_SHOW_PASSWORD);
	g_object_bind_property (s_wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
	                        widget, "password",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
	nmt_editor_grid_append (NMT_EDITOR_GRID (subgrid), _("Password"), widget, NULL);

	nmt_newt_stack_add (stack, "leap", subgrid);

	nmt_editor_grid_append (grid, NULL, NMT_NEWT_WIDGET (stack), NULL);
	g_object_bind_property (security, "active-id",
	                        stack, "active-id",
	                        G_BINDING_SYNC_CREATE);
	nm_editor_bind_wireless_security_method (conn, s_wsec, security, "active-id",
	                                         G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

	nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	widget = nmt_mac_entry_new (40, ETH_ALEN);
	g_object_bind_property (s_wireless, NM_SETTING_WIRELESS_BSSID,
	                        widget, "mac-address",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("BSSID"), widget, NULL);

	widget = nmt_mac_entry_new (40, ETH_ALEN);
	g_object_bind_property (s_wireless, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS,
	                        widget, "mac-address",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Cloned MAC address"), widget, NULL);

	widget = nmt_mtu_entry_new ();
	g_object_bind_property (s_wireless, NM_SETTING_WIRELESS_MTU,
	                        widget, "mtu",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("MTU"), widget, NULL);

	nmt_editor_page_add_section (NMT_EDITOR_PAGE (wifi), section);

	G_OBJECT_CLASS (nmt_page_wifi_parent_class)->constructed (object);
}

static void
nmt_page_wifi_finalize (GObject *object)
{
	NmtPageWifiPrivate *priv = NMT_PAGE_WIFI_GET_PRIVATE (object);

	g_clear_object (&priv->s_wsec);

	G_OBJECT_CLASS (nmt_page_wifi_parent_class)->finalize (object);
}


static void
nmt_page_wifi_class_init (NmtPageWifiClass *wifi_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (wifi_class);

	g_type_class_add_private (wifi_class, sizeof (NmtPageWifiPrivate));

	object_class->constructed = nmt_page_wifi_constructed;
	object_class->finalize    = nmt_page_wifi_finalize;
}
