/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmtui-connect
 * @short_description: nm-applet-like functionality
 *
 * nmtui-connect implements activating and deactivating #NMConnections,
 * including presenting a password dialog if necessary.
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include <stdlib.h>

#include "libnmt-newt/nmt-newt.h"

#include "nmtui.h"
#include "nmtui-connect.h"
#include "nmt-connect-connection-list.h"
#include "nmt-password-dialog.h"
#include "libnmc-base/nm-secret-agent-simple.h"
#include "libnmc-base/nm-vpn-helpers.h"
#include "libnmc-base/nm-client-utils.h"
#include "nmt-utils.h"

static void
secrets_requested(NMSecretAgentSimple *agent,
                  const char          *request_id,
                  const char          *title,
                  const char          *msg,
                  GPtrArray           *secrets,
                  gpointer             user_data)
{
    NMConnection *connection = NM_CONNECTION(user_data);
    gboolean      success    = FALSE;

    /* Get secrets for OpenConnect VPN */
    if (connection && nm_connection_is_type(connection, NM_SETTING_VPN_SETTING_NAME)) {
        NMSettingVpn *s_vpn = nm_connection_get_setting_vpn(connection);

        if (nm_streq0(nm_setting_vpn_get_service_type(s_vpn),
                      NM_SECRET_AGENT_VPN_TYPE_OPENCONNECT)) {
            gs_free_error GError *error = NULL;

            nmt_newt_message_dialog(_("openconnect will be run to authenticate.\nIt will return to "
                                      "nmtui when completed."));

            newtSuspend();

            success = nm_vpn_openconnect_authenticate_helper(s_vpn, secrets, &error);

            newtResume();

            if (!success)
                nmt_newt_message_dialog(_("Error: openconnect failed: %s"), error->message);
        }
    }

    if (!success) {
        gs_unref_object NmtNewtForm *form = NULL;

        form = nmt_password_dialog_new(request_id, title, msg, secrets);
        nmt_newt_form_run_sync(form);

        success = nmt_password_dialog_succeeded(NMT_PASSWORD_DIALOG(form));
    }

    nm_secret_agent_simple_response(agent, request_id, success ? secrets : NULL);
}

typedef struct {
    NMDevice           *device;
    NMActiveConnection *active;
    NmtSyncOp          *op;
} ActivateConnectionInfo;

static void
connect_cancelled(NmtNewtForm *form, gpointer user_data)
{
    ActivateConnectionInfo *info  = user_data;
    GError                 *error = NULL;

    error = g_error_new_literal(G_IO_ERROR, G_IO_ERROR_CANCELLED, "Cancelled");
    nmt_sync_op_complete_boolean(info->op, FALSE, error);
    g_clear_error(&error);
}

static void
check_activated(ActivateConnectionInfo *info)
{
    NMActiveConnectionState ac_state;
    const char             *reason = NULL;
    gs_free_error GError   *error  = NULL;

    ac_state = nmc_activation_get_effective_state(info->active, info->device, &reason);
    if (!NM_IN_SET(ac_state,
                   NM_ACTIVE_CONNECTION_STATE_ACTIVATED,
                   NM_ACTIVE_CONNECTION_STATE_DEACTIVATED))
        return;

    if (ac_state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
        nm_assert(reason);
        error = g_error_new(NM_CLIENT_ERROR,
                            NM_CLIENT_ERROR_FAILED,
                            _("Activation failed: %s"),
                            reason);
    }

    nmt_sync_op_complete_boolean(info->op, error == NULL, error);
}

static void
activate_ac_state_changed(GObject *object, GParamSpec *pspec, gpointer user_data)
{
    check_activated(user_data);
}

static void
activate_device_state_changed(GObject *object, GParamSpec *pspec, gpointer user_data)
{
    check_activated(user_data);
}

static void
activate_callback(GObject *client, GAsyncResult *result, gpointer user_data)
{
    NmtSyncOp          *op = user_data;
    NMActiveConnection *ac;
    GError             *error = NULL;

    ac = nm_client_activate_connection_finish(NM_CLIENT(client), result, &error);
    if (error)
        nmt_sync_op_complete_pointer(op, NULL, error);
    else
        nmt_sync_op_complete_pointer(op, ac, NULL);
}

static void
add_and_activate_callback(GObject *client, GAsyncResult *result, gpointer user_data)
{
    NmtSyncOp          *op = user_data;
    NMActiveConnection *ac;
    GError             *error = NULL;

    ac = nm_client_add_and_activate_connection_finish(NM_CLIENT(client), result, &error);
    if (error)
        nmt_sync_op_complete_pointer(op, NULL, error);
    else
        nmt_sync_op_complete_pointer(op, ac, NULL);
}

static void
deactivate_connection(NMActiveConnection *ac)
{
    GError *error = NULL;

    if (!nm_client_deactivate_connection(nm_client, ac, NULL, &error)) {
        nmt_newt_message_dialog(_("Could not deactivate connection: %s"), error->message);
        g_clear_error(&error);
    }
}

static void
activate_connection(NMConnection *connection, NMDevice *device, NMObject *specific_object)
{
    NmtNewtForm                         *form;
    gs_unref_object NMSecretAgentSimple *agent = NULL;
    NmtNewtWidget                       *label;
    NmtSyncOp                            op;
    const char                          *specific_object_path;
    NMActiveConnection                  *ac;
    GError                              *error = NULL;
    ActivateConnectionInfo               info  = {};

    form  = g_object_new(NMT_TYPE_NEWT_FORM, NULL);
    label = nmt_newt_label_new(_("Connecting..."));
    nmt_newt_form_set_content(form, label);

    agent = nm_secret_agent_simple_new("nmtui");
    if (agent) {
        if (connection) {
            nm_secret_agent_simple_enable(agent, nm_object_get_path(NM_OBJECT(connection)));
        }
        g_signal_connect(agent,
                         NM_SECRET_AGENT_SIMPLE_REQUEST_SECRETS,
                         G_CALLBACK(secrets_requested),
                         connection);
    }

    specific_object_path = specific_object ? nm_object_get_path(specific_object) : NULL;

    /* There's no way to cancel an nm_client_activate_connection() /
     * nm_client_add_and_activate_connection() call, so we always let them
     * complete, even if the user hits Esc; they shouldn't normally take long
     * to complete anyway.
     */

    nmt_sync_op_init(&op);
    if (connection) {
        nm_client_activate_connection_async(nm_client,
                                            connection,
                                            device,
                                            specific_object_path,
                                            NULL,
                                            activate_callback,
                                            &op);
    } else {
        nm_client_add_and_activate_connection_async(nm_client,
                                                    NULL,
                                                    device,
                                                    specific_object_path,
                                                    NULL,
                                                    add_and_activate_callback,
                                                    &op);
    }

    nmt_newt_form_show(form);

    ac = nmt_sync_op_wait_pointer(&op, &error);
    if (!ac) {
        nmt_newt_message_dialog(_("Could not activate connection: %s"), error->message);
        g_clear_error(&error);
        goto done;
    } else if (nm_active_connection_get_state(ac) == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
        /* Already active */
        goto done;
    } else if (!nmt_newt_widget_get_realized(NMT_NEWT_WIDGET(form))) {
        /* User already hit Esc */
        goto done;
    }

    if (agent && !connection) {
        connection = NM_CONNECTION(nm_active_connection_get_connection(ac));
        if (connection) {
            nm_secret_agent_simple_enable(agent, nm_object_get_path(NM_OBJECT(connection)));
        }
    }

    /* Now wait for the connection to actually reach the ACTIVATED state,
     * allowing the user to cancel if it takes too long.
     */
    nmt_sync_op_init(&op);
    info.active = ac;
    info.device = device;
    info.op     = &op;

    g_signal_connect(form, "quit", G_CALLBACK(connect_cancelled), &info);
    g_signal_connect(ac,
                     "notify::" NM_ACTIVE_CONNECTION_STATE,
                     G_CALLBACK(activate_ac_state_changed),
                     &info);
    if (device) {
        g_signal_connect(device,
                         "notify::" NM_DEVICE_STATE,
                         G_CALLBACK(activate_device_state_changed),
                         &info);
    }

    if (!nmt_sync_op_wait_boolean(&op, &error)) {
        if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
            nmt_newt_message_dialog(_("Could not activate connection: %s"), error->message);
        g_clear_error(&error);
    }

    g_signal_handlers_disconnect_by_func(form, G_CALLBACK(connect_cancelled), &info);
    g_signal_handlers_disconnect_by_func(ac, G_CALLBACK(activate_ac_state_changed), &info);
    if (device)
        g_signal_handlers_disconnect_by_func(device,
                                             G_CALLBACK(activate_device_state_changed),
                                             &info);

done:
    if (nmt_newt_widget_get_realized(NMT_NEWT_WIDGET(form)))
        nmt_newt_form_quit(form);
    g_object_unref(form);

    if (agent)
        nm_secret_agent_old_unregister(NM_SECRET_AGENT_OLD(agent), NULL, NULL);
}

static void
listbox_activated(NmtNewtListbox *listbox, gpointer user_data)
{
    NmtConnectConnectionList *list = NMT_CONNECT_CONNECTION_LIST(listbox);
    NMConnection             *connection;
    NMDevice                 *device;
    NMObject                 *specific_object;
    NMActiveConnection       *ac;

    if (!nmt_connect_connection_list_get_selection(list,
                                                   &connection,
                                                   &device,
                                                   &specific_object,
                                                   &ac))
        return;

    if (ac)
        deactivate_connection(ac);
    else
        activate_connection(connection, device, specific_object);
}

static void
activate_clicked(NmtNewtButton *button, gpointer listbox)
{
    listbox_activated(listbox, NULL);
}

static void
listbox_active_changed(GObject *object, GParamSpec *pspec, gpointer button)
{
    NmtConnectConnectionList *list = NMT_CONNECT_CONNECTION_LIST(object);
    static const char        *activate, *deactivate;
    static int                deactivate_padding, activate_padding;
    NMActiveConnection       *ac;
    gboolean                  has_selection;

    if (G_UNLIKELY(activate == NULL)) {
        int activate_width, deactivate_width;

        activate         = _("Activate");
        activate_width   = nmt_newt_text_width(activate);
        deactivate       = _("Deactivate");
        deactivate_width = nmt_newt_text_width(deactivate);

        activate_padding   = NM_MAX(0, deactivate_width - activate_width);
        deactivate_padding = NM_MAX(0, activate_width - deactivate_width);
    }

    has_selection = nmt_connect_connection_list_get_selection(list, NULL, NULL, NULL, &ac);

    nmt_newt_component_set_sensitive(button, has_selection);
    if (has_selection && ac) {
        nmt_newt_button_set_label(button, deactivate);
        nmt_newt_widget_set_padding(button, 0, 0, deactivate_padding, 0);
    } else {
        nmt_newt_button_set_label(button, activate);
        nmt_newt_widget_set_padding(button, 0, 0, activate_padding, 0);
    }
}

/* Contains both the UI and batch data for wifi-rescans */
typedef struct {
    NmtNewtWidget *activate_button;
    NmtNewtWidget *listbox;
    NmtNewtForm   *rescan_form;
    NmtNewtWidget *rescan_button;
    int            pending;
    GCancellable  *cancellable;
    gboolean       cancelled;
    gboolean       has_error;
    gboolean       timeout_occurred;
} RescanBatch;

typedef struct {
    NMDeviceWifi *wifi_device;
    GSource      *timeout_id;
    gulong        signal_id;
    RescanBatch  *batch;
} RescanData;

static GPtrArray *
active_wifi_devices(void)
{
    const GPtrArray *devices;
    GPtrArray       *active_wifi_devices;

    devices = nm_client_get_devices(nm_client);

    if (!devices)
        return NULL;

    active_wifi_devices = g_ptr_array_new_with_free_func(g_object_unref);

    for (guint i = 0; i < devices->len; i++) {
        NMDevice              *dev      = g_ptr_array_index((GPtrArray *) devices, i);
        NMDeviceInterfaceFlags devflags = nm_device_get_interface_flags(dev);

        if ((devflags & NM_DEVICE_INTERFACE_FLAG_UP) == 0)
            continue;

        if (NM_IS_DEVICE_WIFI(dev)
            && !NM_IN_SET(nm_device_get_state(dev),
                          NM_DEVICE_STATE_UNAVAILABLE,
                          NM_DEVICE_STATE_UNMANAGED,
                          NM_DEVICE_STATE_FAILED)) {
            g_ptr_array_add(active_wifi_devices, g_object_ref(dev));
        }
    }
    return active_wifi_devices;
}

static void
on_rescan_cancel(NmtNewtForm *form, gpointer user_data)
{
    RescanBatch *batch_data = user_data;

    if (!batch_data || batch_data->cancelled)
        return;

    batch_data->cancelled = TRUE;

    /* Cancel the async operations using nm_clear_g_cancellable */
    if (batch_data->cancellable)
        nm_clear_g_cancellable(&batch_data->cancellable);

    g_object_unref(batch_data->rescan_form);
    batch_data->rescan_form = NULL;
}

/* creates the wifi-rescan form and manages other ui properties while rescanning */
static void
wifi_rescan_form(RescanBatch *batch_data)
{
    NmtNewtForm   *rescan_form;
    NmtNewtWidget *label;

    nmt_newt_component_set_sensitive(NMT_NEWT_COMPONENT(batch_data->listbox), FALSE);
    nmt_newt_component_set_sensitive(NMT_NEWT_COMPONENT(batch_data->rescan_button), FALSE);
    nmt_newt_component_set_sensitive(NMT_NEWT_COMPONENT(batch_data->activate_button), FALSE);

    /* open the scanning form*/
    rescan_form = g_object_new(NMT_TYPE_NEWT_FORM, NULL);
    label       = nmt_newt_label_new(_("Rescanning Wi-Fi devices..."));
    nmt_newt_form_set_content(rescan_form, label);

    /* connect the quit signal to rescan cancel */
    g_signal_connect(rescan_form, "quit", G_CALLBACK(on_rescan_cancel), batch_data);

    nmt_newt_form_show(rescan_form);
    batch_data->rescan_form = rescan_form;
}

/* rebuilds the connection list and changes back the
 * state for various UI components which were
 * changed during rescanning */
static void
on_rescan_complete(gpointer data)
{
    NmtConnectConnectionList *list;
    RescanData               *rescan_data;
    RescanBatch              *batch_data;
    NMDeviceWifi             *wifi_device;

    rescan_data = data;
    batch_data  = rescan_data->batch;
    wifi_device = rescan_data->wifi_device;

    g_free(rescan_data);
    rescan_data = NULL;

    if (batch_data->has_error) {
        nmt_newt_message_dialog(_("Wi-Fi scan failed for device : %s"),
                                nm_device_get_iface(NM_DEVICE(wifi_device)));
        batch_data->has_error = FALSE;
    }

    if (batch_data->timeout_occurred) {
        nmt_newt_message_dialog(_("Wi-Fi scan timed out for device : %s"),
                                nm_device_get_iface(NM_DEVICE(wifi_device)));
        batch_data->timeout_occurred = FALSE;
    }

    /* If the scans are not complete then simply wait for them to complete
     * This also ensures that UI is only enabled either after all
     * scans complete (Either complete or cancel ). Preventing any
     * overlapping scans caused due to the user pressing rescan multiple times
     */

    if (--batch_data->pending > 0)
        return;

    /* If the scan is not cancelled quit normally */
    if (!batch_data->cancelled) {
        if (nmt_newt_widget_get_realized(NMT_NEWT_WIDGET(batch_data->rescan_form))) {
            nmt_newt_form_quit(batch_data->rescan_form);
            nm_clear_g_object(&batch_data->rescan_form);
            batch_data->rescan_form = NULL;
        }
        list = NMT_CONNECT_CONNECTION_LIST(batch_data->listbox);
        nmt_newt_listbox_clear(NMT_NEWT_LISTBOX(list));

        g_object_notify(G_OBJECT(nm_client), NM_CLIENT_CONNECTIONS);
    }

    /* The following cleanup  is required regardless of any cancellation */
    nmt_newt_component_set_sensitive(NMT_NEWT_COMPONENT(batch_data->listbox), TRUE);
    nmt_newt_component_set_sensitive(NMT_NEWT_COMPONENT(batch_data->rescan_button), TRUE);
    nmt_newt_component_set_sensitive(NMT_NEWT_COMPONENT(batch_data->activate_button), TRUE);

    g_clear_object(&batch_data->cancellable);
}

static gboolean
scan_timeout_callback(gpointer user_data)
{
    RescanData *data = user_data;

    nm_clear_g_source_inst(&data->timeout_id);

    /* Timeout reached - scan took too long */
    if (data->signal_id) {
        g_signal_handler_disconnect(data->wifi_device, data->signal_id);
        data->signal_id = 0;
    }

    data->batch->timeout_occurred = TRUE;

    on_rescan_complete(data);
    return G_SOURCE_REMOVE;
}

static void
on_last_scan_changed(GObject *object, GParamSpec *pspec, gpointer user_data)
{
    RescanData *data = user_data;

    /* Scan completed successfully */
    nm_clear_g_source_inst(&data->timeout_id);
    if (data->signal_id) {
        g_signal_handler_disconnect(data->wifi_device, data->signal_id);
        data->signal_id = 0;
    }

    on_rescan_complete(data);
}

static void
wifi_rescan_callback(GObject *source_object, GAsyncResult *result, gpointer rescan_data)
{
    RescanData *data = rescan_data;

    if (!nm_device_wifi_request_scan_finish(data->wifi_device, result, NULL)) {
        data->batch->has_error = TRUE;
        on_rescan_complete(data);
        return;
    }

    /* Listen for last-scan property changes */
    data->signal_id = g_signal_connect(data->wifi_device,
                                       "notify::last-scan",
                                       G_CALLBACK(on_last_scan_changed),
                                       data);

    /* Set a 10-second timeout in case scan doesn't complete */
    data->timeout_id = nm_g_timeout_add_source(RESCAN_TIMEOUT_MS, scan_timeout_callback, data);
}

static void
wifi_rescan(NmtNewtButton *button, gpointer data_batch)
{
    gs_unref_ptrarray GPtrArray *devices = active_wifi_devices();
    RescanData                  *data;
    RescanBatch                 *batch_data = data_batch;

    if (!devices || devices->len == 0) {
        nmt_newt_message_dialog(_("No active Wi-Fi devices found"));
        return;
    }

    /* create a shared batch for all the devices*/
    batch_data->pending     = devices->len;
    batch_data->cancelled   = FALSE;
    batch_data->cancellable = g_cancellable_new();

    wifi_rescan_form(batch_data);

    for (guint i = 0; i < devices->len; i++) {
        NMDevice *dev = g_ptr_array_index(devices, i);

        /* per-device data */
        data              = g_new0(RescanData, 1);
        data->wifi_device = NM_DEVICE_WIFI(dev);
        data->batch       = batch_data;

        nm_device_wifi_request_scan_async(NM_DEVICE_WIFI(dev),
                                          batch_data->cancellable,
                                          wifi_rescan_callback,
                                          data);
    }
}

static NmtNewtForm *
nmt_connect_connection_list(gboolean is_top)
{
    int                          screen_width, screen_height;
    NmtNewtForm                 *form;
    NmtNewtWidget               *list, *activate, *quit, *bbox, *grid, *rescan;
    RescanBatch                 *batch_data;
    gs_unref_ptrarray GPtrArray *all_active_wifi_devices = NULL;

    newtGetScreenSize(&screen_width, &screen_height);

    form = g_object_new(NMT_TYPE_NEWT_FORM, "y", 2, "height", screen_height - 4, NULL);

    grid = nmt_newt_grid_new();

    list = nmt_connect_connection_list_new();
    nmt_newt_grid_add(NMT_NEWT_GRID(grid), list, 0, 0);
    nmt_newt_grid_set_flags(NMT_NEWT_GRID(grid),
                            list,
                            NMT_NEWT_GRID_FILL_X | NMT_NEWT_GRID_FILL_Y | NMT_NEWT_GRID_EXPAND_X
                                | NMT_NEWT_GRID_EXPAND_Y);
    g_signal_connect(list, "activated", G_CALLBACK(listbox_activated), NULL);

    bbox = nmt_newt_button_box_new(NMT_NEWT_BUTTON_BOX_VERTICAL);
    nmt_newt_grid_add(NMT_NEWT_GRID(grid), bbox, 1, 0);
    nmt_newt_widget_set_padding(bbox, 1, 1, 0, 1);

    activate = nmt_newt_button_box_add_start(NMT_NEWT_BUTTON_BOX(bbox), _("Activate"));
    g_signal_connect(list, "notify::active", G_CALLBACK(listbox_active_changed), activate);
    listbox_active_changed(G_OBJECT(list), NULL, activate);
    g_signal_connect(activate, "clicked", G_CALLBACK(activate_clicked), list);

    all_active_wifi_devices = active_wifi_devices();
    if (all_active_wifi_devices && all_active_wifi_devices->len > 0) {
        rescan = nmt_newt_button_box_add_start(NMT_NEWT_BUTTON_BOX(bbox), _("Rescan Wi-Fi"));

        batch_data                  = g_new0(RescanBatch, 1);
        batch_data->activate_button = activate;
        batch_data->listbox         = list;
        batch_data->rescan_button   = rescan;

        /* Bind the lifecycle of batch_data to the rescan button.
         * The data will be freed automatically when the button is destroyed i.e form quits. */
        g_object_set_data_full(G_OBJECT(rescan), "rescan-batch-data", batch_data, g_free);

        g_signal_connect(rescan, "clicked", G_CALLBACK(wifi_rescan), batch_data);
    }

    quit = nmt_newt_button_box_add_end(NMT_NEWT_BUTTON_BOX(bbox), is_top ? _("Quit") : _("Back"));
    nmt_newt_widget_set_exit_on_activate(quit, TRUE);

    nmt_newt_form_set_content(form, grid);
    return form;
}

static NmtNewtForm *
nmt_connect_connection(const char *identifier)
{
    NmtNewtWidget      *list;
    NMConnection       *connection;
    NMDevice           *device;
    NMObject           *specific_object;
    NMActiveConnection *ac;

    list = nmt_connect_connection_list_new();
    if (!nmt_connect_connection_list_get_connection(NMT_CONNECT_CONNECTION_LIST(list),
                                                    identifier,
                                                    &connection,
                                                    &device,
                                                    &specific_object,
                                                    &ac))
        nmt_newt_message_dialog(_("No such connection '%s'"), identifier);
    else if (ac)
        nmt_newt_message_dialog(_("Connection is already active"));
    else
        activate_connection(connection, device, specific_object);
    g_object_unref(list);

    return NULL;
}

NmtNewtForm *
nmtui_connect(gboolean is_top, int argc, char **argv)
{
    if (argc == 2)
        return nmt_connect_connection(argv[1]);
    else
        return nmt_connect_connection_list(is_top);
}
