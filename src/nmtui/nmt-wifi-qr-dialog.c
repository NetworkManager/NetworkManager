/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2026 Red Hat, Inc.
 */

/**
 * SECTION:nmt-wifi-qr-dialog
 * @short_description: A dialog that shares a Wi-Fi connection as a QR code
 *
 * Shows the "WIFI:" provisioning URI of a saved Wi-Fi connection as a
 * scannable QR code, along with the SSID and password. If the password is a
 * passphrase that cannot be read, it shows a warning instead of a QR code.
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmt-wifi-qr-dialog.h"

#include "libnm-glib-aux/nm-secret-utils.h"
#include "libnmc-base/nm-client-utils.h"
#include "nmt-utils.h"

static NMConnection *
clone_with_secrets(NMConnection *connection)
{
    NMConnection              *clone   = nm_simple_connection_new_clone(connection);
    gs_unref_variant GVariant *secrets = NULL;

    if (!NM_IS_REMOTE_CONNECTION(connection))
        return clone;

    secrets = nmt_sync_get_secrets(NM_REMOTE_CONNECTION(connection),
                                   NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                                   NULL);
    if (secrets)
        nm_connection_update_secrets(clone,
                                     NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                                     secrets,
                                     NULL);

    return clone;
}

static gboolean
qr_fits_screen(const char *qr)
{
    gs_strfreev char **lines = NULL;
    int                screen_w;
    int                screen_h;
    int                qr_rows;
    int                qr_cols;

    newtGetScreenSize(&screen_w, &screen_h);

    lines   = g_strsplit(qr, "\n", -1);
    qr_rows = g_strv_length(lines);
    qr_cols = lines[0] ? (int) g_utf8_strlen(lines[0], -1) : 0;

    /* Reserve room for the form border, title, the SSID/password labels and
     * the button row. */
    return qr_cols + 4 <= screen_w && qr_rows + 8 <= screen_h;
}

/**
 * nmt_wifi_qr_dialog_run:
 * @connection: a Wi-Fi #NMConnection
 *
 * Fetches @connection's secrets and shows a modal dialog with a QR code that
 * encodes its Wi-Fi credentials, or a warning if the password cannot be read.
 * Returns when the user closes the dialog.
 */
void
nmt_wifi_qr_dialog_run(NMConnection *connection)
{
    gs_unref_object NMConnection *clone = NULL;
    gs_unref_object NmtNewtForm  *form  = NULL;
    NMSettingWireless            *s_wireless;
    NMSettingWirelessSecurity    *s_wsec;
    NmtNewtGrid                  *grid;
    NmtNewtWidget                *widget;
    NmtNewtButtonBox             *bbox;
    GBytes                       *ssid_bytes;
    gs_free char                 *ssid     = NULL;
    nm_auto_free_secret char     *uri      = NULL;
    nm_auto_free_secret char     *qr       = NULL;
    const char                   *key_mgmt = NULL;
    const char                   *psk      = NULL;
    gboolean                      no_password;
    int                           row = 0;

    g_return_if_fail(NM_IS_CONNECTION(connection));

    if (!nm_connection_get_setting_wireless(connection))
        return;

    clone      = clone_with_secrets(connection);
    s_wireless = nm_connection_get_setting_wireless(clone);

    ssid_bytes = nm_setting_wireless_get_ssid(s_wireless);
    if (ssid_bytes)
        ssid =
            nm_utils_ssid_to_utf8(g_bytes_get_data(ssid_bytes, NULL), g_bytes_get_size(ssid_bytes));

    s_wsec = nm_connection_get_setting_wireless_security(clone);
    if (s_wsec) {
        key_mgmt = nm_setting_wireless_security_get_key_mgmt(s_wsec);
        psk      = nm_setting_wireless_security_get_psk(s_wsec);
    }

    /* A QR code for a secured network without its password connects to nothing,
     * so don't render one; show a warning instead. */
    no_password = nmc_wifi_key_mgmt_uses_psk(key_mgmt) && (!psk || !psk[0]);

    if (!no_password) {
        uri = nmc_wifi_qr_uri_new(ssid, key_mgmt, psk, nm_setting_wireless_get_hidden(s_wireless));
        qr  = nmc_wifi_qr_render_string(uri);
    }

    form = nmt_newt_form_new(_("Share Wi-Fi"));

    widget = nmt_newt_grid_new();
    nmt_newt_form_set_content(form, widget);
    grid = NMT_NEWT_GRID(widget);

    if (no_password) {
        widget = nmt_newt_textbox_new(0, 50);
        nmt_newt_textbox_set_text(
            NMT_NEWT_TEXTBOX(widget),
            _("Warning: cannot read the Wi-Fi password due to insufficient privileges."));
    } else if (qr && qr_fits_screen(qr)) {
        widget = nmt_newt_textbox_new(NMT_NEWT_TEXTBOX_SET_BACKGROUND, 0);
        nmt_newt_textbox_set_text(NMT_NEWT_TEXTBOX(widget), qr);
    } else {
        widget = nmt_newt_textbox_new(0, 50);
        nmt_newt_textbox_set_text(NMT_NEWT_TEXTBOX(widget),
                                  qr ? _("The terminal is too small to display the QR code.")
                                     : _("The Wi-Fi credentials could not be encoded."));
    }
    nmt_newt_grid_add(grid, widget, 0, row++);
    nmt_newt_widget_set_padding(widget, 0, 0, 0, 1);

    if (ssid) {
        gs_free char *label = g_strdup_printf("%s: %s", _("SSID"), ssid);

        widget = nmt_newt_label_new(label);
        nmt_newt_grid_add(grid, widget, 0, row++);
    }

    if (psk) {
        nm_auto_free_secret char *label = g_strdup_printf("%s: %s", _("Password"), psk);

        widget = nmt_newt_label_new(label);
        nmt_newt_grid_add(grid, widget, 0, row++);
    }

    widget = nmt_newt_button_box_new(NMT_NEWT_BUTTON_BOX_HORIZONTAL);
    nmt_newt_grid_add(grid, widget, 0, row++);
    nmt_newt_widget_set_padding(widget, 0, 1, 0, 0);
    bbox = NMT_NEWT_BUTTON_BOX(widget);

    widget = nmt_newt_button_box_add_end(bbox, _("Close"));
    nmt_newt_widget_set_exit_on_activate(widget, TRUE);

    nmt_newt_form_run_sync(form);
}
