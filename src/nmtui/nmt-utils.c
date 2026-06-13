/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-utils
 * @short_description: Miscellaneous nmtui-specific utilities
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmt-utils.h"

#include "libnmt-newt/nmt-newt.h"

/**
 * NmtSyncOp:
 *
 * A helper object used when synchronously waiting for an asynchronous
 * operation to complete.
 *
 * The caller first does:
 *
 * |[
 *     NmtSyncOp op;
 *
 *     nmt_sync_op_init (&op);
 * ]|
 *
 * It then passes the op as the user_data to the async operation's
 * callback function, and then calls nmt_sync_op_wait_boolean() or
 * nmt_sync_op_wait_pointer() to wait for the result.
 *
 * When the async callback is invoked, it should call
 * nmt_sync_op_complete_boolean() or nmt_sync_op_complete_pointer() to
 * return a result or an error to the caller.
 *
 * There is no free/clear function; any memory that needs to be freed
 * will have been returned to the caller from
 * nmt_sync_op_wait_boolean() or nmt_sync_op_wait_pointer(), so there
 * is nothing left that needs to be freed.
 */

typedef struct {
    gpointer result;
    GError  *error;
    gpointer complete;
} NmtSyncOpReal;

/**
 * nmt_sync_op_init:
 * @op: pointer to a stack-allocated #NmtSyncOp
 *
 * Initializes @op before use.
 */
void
nmt_sync_op_init(NmtSyncOp *op)
{
    memset(op, 0, sizeof(*op));
}

/**
 * nmt_sync_op_wait_boolean:
 * @op: the #NmtSyncOp
 * @error: return location for a #GError
 *
 * This runs the main loop until @op's operation returns, and then
 * returns the result or error.
 *
 * Returns: the result of the operation.
 */
gboolean
nmt_sync_op_wait_boolean(NmtSyncOp *op, GError **error)
{
    return GPOINTER_TO_UINT(nmt_sync_op_wait_pointer(op, error));
}

/**
 * nmt_sync_op_complete_boolean:
 * @op: the #NmtSyncOp
 * @result: the result of the operation
 * @error: (nullable): the error, or %NULL
 *
 * Completes @op and returns @result and/or @error to the caller.
 */
void
nmt_sync_op_complete_boolean(NmtSyncOp *op, gboolean result, GError *error)
{
    nmt_sync_op_complete_pointer(op, GUINT_TO_POINTER(result), error);
}

/**
 * nmt_sync_op_wait_pointer:
 * @op: the #NmtSyncOp
 * @error: return location for a #GError
 *
 * This runs the main loop until @op's operation returns, and then
 * returns the result or error.
 *
 * Returns: the result of the operation.
 */
gpointer
nmt_sync_op_wait_pointer(NmtSyncOp *op, GError **error)
{
    NmtSyncOpReal *real = (NmtSyncOpReal *) op;

    while (!real->complete)
        g_main_context_iteration(NULL, TRUE);

    if (real->error)
        g_propagate_error(error, real->error);
    return real->result;
}

/**
 * nmt_sync_op_complete_pointer:
 * @op: the #NmtSyncOp
 * @result: the result of the operation
 * @error: (nullable): the error, or %NULL
 *
 * Completes @op and returns @result and/or @error to the caller.
 */
void
nmt_sync_op_complete_pointer(NmtSyncOp *op, gpointer result, GError *error)
{
    NmtSyncOpReal *real = (NmtSyncOpReal *) op;

    real->result   = result;
    real->error    = error ? g_error_copy(error) : NULL;
    real->complete = GUINT_TO_POINTER(TRUE);
}

/**
 * nmt_utils_filter_match:
 * @haystack: (nullable): the string to search in
 * @needle: (nullable): the search term
 *
 * Case-insensitive UTF-8 substring test. An empty or %NULL @needle matches
 * anything; a %NULL @haystack matches only an empty @needle.
 *
 * Returns: %TRUE if @haystack contains @needle.
 */
gboolean
nmt_utils_filter_match(const char *haystack, const char *needle)
{
    gs_free char *h = NULL;
    gs_free char *n = NULL;

    if (!needle || !needle[0])
        return TRUE;
    if (!haystack)
        return FALSE;

    h = g_utf8_casefold(haystack, -1);
    n = g_utf8_casefold(needle, -1);
    return strstr(h, n) != NULL;
}

/*
 * Renders the search state into @label: "Search:" while typing,
 * "Matching '...' (N)" once a filter is applied with the entry hidden, or
 * empty when idle.
 *
 * When the entry is hidden the text is padded to the width the row occupies
 * while searching ("Search:" plus the entry), so revealing or hiding the entry
 * never changes the form's width.
 */
static void
set_search_label(NmtNewtLabel *label, const char *filter_text, int match_count, gboolean searching)
{
    gs_free char *body = NULL;
    int           reserve, body_width;

    if (searching) {
        nmt_newt_label_set_text(label, _("Search:"));
        return;
    }

    reserve = nmt_newt_text_width(_("Search:")) + 1 + NMT_SEARCH_ENTRY_WIDTH;

    if (!nm_str_is_empty(filter_text)) {
        gs_free char *shown = NULL;
        int           overhead;

        /* Echo the filter, but elide it so the confirmed label never exceeds
         * the reserved width; otherwise the form grows when a long search is
         * confirmed with Enter. */
        body     = g_strdup_printf(_("Matching '%s' (%d)"), "", match_count);
        overhead = nmt_newt_text_width(body);
        nm_clear_g_free(&body);

        shown = nmt_newt_text_truncate(filter_text, reserve - overhead);
        body  = g_strdup_printf(_("Matching '%s' (%d)"), shown, match_count);
    } else
        body = g_strdup("");

    body_width = nmt_newt_text_width(body);
    if (body_width < reserve) {
        gs_free char *padded = NULL;

        padded = g_strdup_printf("%s%*s", body, reserve - body_width, "");
        nmt_newt_label_set_text(label, padded);
    } else
        nmt_newt_label_set_text(label, body);
}

struct _NmtSearch {
    NmtNewtEntry      *entry;
    NmtNewtLabel      *label;
    NmtNewtWidget     *focus;
    NmtSearchApplyFunc apply;
    NmtSearchCountFunc count;
    gpointer           user_data;
};

void
nmt_search_update_label(NmtSearch *search)
{
    set_search_label(search->label,
                     nmt_newt_entry_get_text(search->entry),
                     search->count(search->user_data),
                     nmt_newt_widget_get_visible(NMT_NEWT_WIDGET(search->entry)));
}

static void
search_text_changed(GObject *entry, GParamSpec *pspec, gpointer user_data)
{
    NmtSearch *search = user_data;

    search->apply(search->user_data, nmt_newt_entry_get_text(search->entry));
    nmt_search_update_label(search);
}

static void
search_activated(NmtNewtWidget *entry, gpointer user_data)
{
    NmtSearch   *search = user_data;
    NmtNewtForm *form   = nmt_newt_widget_get_form(search->focus);

    /* Enter: hide the entry but keep the filter; the label now reports it. */
    nmt_newt_widget_set_visible(NMT_NEWT_WIDGET(search->entry), FALSE);
    nmt_search_update_label(search);
    if (form)
        nmt_newt_form_set_focus(form, search->focus);
}

static gboolean
search_hotkey(NmtNewtForm *form, int key, gpointer user_data)
{
    NmtSearch  *search = user_data;
    const char *filter = nmt_newt_entry_get_text(search->entry);

    if (key == '/') {
        nmt_newt_widget_set_visible(NMT_NEWT_WIDGET(search->entry), TRUE);
        nmt_search_update_label(search);
        nmt_newt_form_set_focus(form, NMT_NEWT_WIDGET(search->entry));
        return TRUE;
    }
    if (key == NEWT_KEY_ESCAPE
        && (nmt_newt_widget_get_visible(NMT_NEWT_WIDGET(search->entry))
            || !nm_str_is_empty(filter))) {
        /* Esc: clear the filter (via notify::text) and return to the list. */
        nmt_newt_entry_set_text(search->entry, "");
        nmt_newt_widget_set_visible(NMT_NEWT_WIDGET(search->entry), FALSE);
        nmt_search_update_label(search);
        nmt_newt_form_set_focus(form, search->focus);
        return TRUE;
    }
    return FALSE;
}

NmtSearch *
nmt_search_new(NmtNewtEntry      *entry,
               NmtNewtLabel      *label,
               NmtNewtWidget     *focus,
               NmtSearchApplyFunc apply,
               NmtSearchCountFunc count,
               gpointer           user_data)
{
    NmtSearch *search = g_new0(NmtSearch, 1);

    search->entry     = entry;
    search->label     = label;
    search->focus     = focus;
    search->apply     = apply;
    search->count     = count;
    search->user_data = user_data;

    nmt_newt_widget_set_visible(NMT_NEWT_WIDGET(entry), FALSE);
    g_signal_connect(entry, "notify::text", G_CALLBACK(search_text_changed), search);
    g_signal_connect(entry, "activated", G_CALLBACK(search_activated), search);

    return search;
}

void
nmt_search_bind_form(NmtSearch *search, NmtNewtForm *form)
{
    g_signal_connect(form, "hotkey", G_CALLBACK(search_hotkey), search);
    nmt_newt_form_add_hotkey(form, '/');
    nmt_newt_form_set_stable_width(form);

    /* Reserve the search row's width up front so the form does not grow when
     * the entry is first revealed. */
    nmt_search_update_label(search);
}

static void
get_secrets_cb(GObject *object, GAsyncResult *result, gpointer op)
{
    GVariant *secrets;
    GError   *error = NULL;

    secrets = nm_remote_connection_get_secrets_finish(NM_REMOTE_CONNECTION(object), result, &error);
    nmt_sync_op_complete_pointer(op, secrets, error);
    g_clear_error(&error);
}

/**
 * nmt_sync_get_secrets:
 * @connection: the #NMRemoteConnection to fetch secrets from
 * @setting_name: the setting to fetch secrets for
 * @error: return location for a #GError
 *
 * Synchronously requests @setting_name's secrets for @connection, running the
 * main loop until the request completes.
 *
 * Returns: (transfer full): the secrets variant, or %NULL on error.
 */
GVariant *
nmt_sync_get_secrets(NMRemoteConnection *connection, const char *setting_name, GError **error)
{
    NmtSyncOp op;

    nmt_sync_op_init(&op);
    nm_remote_connection_get_secrets_async(connection, setting_name, NULL, get_secrets_cb, &op);
    return nmt_sync_op_wait_pointer(&op, error);
}
