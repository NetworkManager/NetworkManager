/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2023 Javier Sánchez Parra, javsanpar@riseup.net
 */

/**
 * SECTION:nmtui-radio
 * @short_description: radio-setting functionality
 *
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "libnmt-newt/nmt-newt-toggle-button.h"
#include "libnmt-newt/nmt-newt-types.h"
#include "libnmt-newt/nmt-newt.h"

#include "nmtui.h"
#include "nmtui-radio.h"
#include "nmt-utils.h"

static void
nmtui_radio_toggle_wifi(GObject *object, gpointer radio_type)
{
    NmtNewtToggleButton *button = NMT_NEWT_TOGGLE_BUTTON(object);
    gboolean             enable_flag;

    enable_flag = nmt_newt_toggle_button_get_active(button);
    nm_client_wireless_set_enabled(nm_client, enable_flag);
}

static void
nmtui_radio_toggle_wwan(GObject *object, gpointer radio_type)
{
    NmtNewtToggleButton *button = NMT_NEWT_TOGGLE_BUTTON(object);
    gboolean             enable_flag;

    enable_flag = nmt_newt_toggle_button_get_active(button);
    nm_client_wwan_set_enabled(nm_client, enable_flag);
}

static void
nmtui_radio_run_dialog(void)
{
    gs_unref_object NmtNewtForm *form = NULL;
    NmtNewtToggleButton         *toggle_wifi, *toggle_wwan;
    NmtNewtButtonBox            *bbox;
    NmtNewtWidget               *widget;
    NmtNewtGrid                 *grid;
    gboolean                     enable_flag;

    form = g_object_new(NMT_TYPE_NEWT_FORM, "title", _("Set the radio switches status"), NULL);

    widget = nmt_newt_grid_new();
    nmt_newt_form_set_content(form, widget);
    grid = NMT_NEWT_GRID(widget);

    widget = nmt_newt_label_new(_("Wi-Fi"));
    nmt_newt_grid_add(grid, widget, 0, 0);

    widget = nmt_newt_label_new(_("Hardware:"));
    nmt_newt_grid_add(grid, widget, 0, 1);

    if (!(nm_client_get_radio_flags(nm_client) & NM_RADIO_FLAG_WLAN_AVAILABLE)) {
        widget = nmt_newt_label_new(_("Missing"));
    } else {
        enable_flag = nm_client_wireless_hardware_get_enabled(nm_client);
        widget      = nmt_newt_label_new(enable_flag ? _("Enabled") : _("Disabled"));
    }
    nmt_newt_grid_add(grid, widget, 1, 1);
    nmt_newt_widget_set_padding(widget, 1, 0, 0, 0);

    widget = nmt_newt_label_new(_("Software:"));
    nmt_newt_grid_add(grid, widget, 2, 1);
    nmt_newt_widget_set_padding(widget, 3, 0, 0, 0);

    widget = nmt_newt_toggle_button_new(_("Enabled"), _("Disabled"));
    nmt_newt_grid_add(grid, widget, 3, 1);
    nmt_newt_widget_set_padding(widget, 1, 0, 0, 0);
    toggle_wifi = NMT_NEWT_TOGGLE_BUTTON(widget);
    enable_flag = nm_client_wireless_get_enabled(nm_client);
    nmt_newt_toggle_button_set_active(toggle_wifi, enable_flag);
    g_signal_connect(widget, "activated", G_CALLBACK(nmtui_radio_toggle_wifi), NULL);

    widget = nmt_newt_label_new(_("WWAN"));
    nmt_newt_grid_add(grid, widget, 0, 2);
    nmt_newt_widget_set_padding(widget, 0, 1, 0, 0);

    widget = nmt_newt_label_new(_("Hardware:"));
    nmt_newt_grid_add(grid, widget, 0, 3);

    if (!(nm_client_get_radio_flags(nm_client) & NM_RADIO_FLAG_WWAN_AVAILABLE)) {
        widget = nmt_newt_label_new(_("Missing"));
    } else {
        enable_flag = nm_client_wwan_hardware_get_enabled(nm_client);
        widget      = nmt_newt_label_new(enable_flag ? _("Enabled") : _("Disabled"));
    }
    nmt_newt_grid_add(grid, widget, 1, 3);
    nmt_newt_widget_set_padding(widget, 1, 0, 0, 0);

    widget = nmt_newt_label_new(_("Software:"));
    nmt_newt_grid_add(grid, widget, 2, 3);
    nmt_newt_widget_set_padding(widget, 3, 0, 0, 0);

    widget = nmt_newt_toggle_button_new(_("Enabled"), _("Disabled"));
    nmt_newt_grid_add(grid, widget, 3, 3);
    nmt_newt_widget_set_padding(widget, 1, 0, 0, 0);
    toggle_wwan = NMT_NEWT_TOGGLE_BUTTON(widget);
    enable_flag = nm_client_wwan_get_enabled(nm_client);
    nmt_newt_toggle_button_set_active(toggle_wwan, enable_flag);
    g_signal_connect(widget, "activated", G_CALLBACK(nmtui_radio_toggle_wwan), NULL);

    widget = nmt_newt_button_box_new(NMT_NEWT_BUTTON_BOX_HORIZONTAL);
    nmt_newt_grid_add(grid, widget, 3, 4);
    nmt_newt_widget_set_padding(widget, 0, 1, 0, 0);
    bbox = NMT_NEWT_BUTTON_BOX(widget);

    widget = nmt_newt_button_box_add_end(bbox, _("Back"));
    nmt_newt_widget_set_exit_on_activate(widget, TRUE);

    nmt_newt_form_run_sync(form);
}

NmtNewtForm *
nmtui_radio(gboolean is_top, int argc, char **argv)
{
    nmtui_radio_run_dialog();

    return NULL;
}
