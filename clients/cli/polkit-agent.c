/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "libnm/nm-default-client.h"

#include "polkit-agent.h"

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "nm-polkit-listener.h"
#include "common.h"

static char *
polkit_read_passwd(gpointer    instance,
                   const char *action_id,
                   const char *message,
                   const char *user,
                   gpointer    user_data)
{
    NmCli *nmc = user_data;

    g_print("%s\n", message);
    g_print("(action_id: %s)\n", action_id);

    /* Ask user for polkit authorization password */
    if (user) {
        return nmc_readline_echo(&nmc->nmc_config, FALSE, "password (%s): ", user);
    }
    return nmc_readline_echo(&nmc->nmc_config, FALSE, "password: ");
}

static void
polkit_error(gpointer instance, const char *error, gpointer user_data)
{
    g_printerr(_("Error: polkit agent failed: %s\n"), error);
}

gboolean
nmc_polkit_agent_init(NmCli *nmc, gboolean for_session, GError **error)
{
    NMPolkitListener *listener;
    GDBusConnection * dbus_connection = NULL;

    g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

    if (nmc->client && nm_client_get_dbus_connection(nmc->client)) {
        dbus_connection = nm_client_get_dbus_connection(nmc->client);
        listener        = nm_polkit_listener_new(dbus_connection, for_session);
    } else {
        dbus_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, error);

        if (!dbus_connection) {
            return FALSE;
        }

        listener = nm_polkit_listener_new(dbus_connection, for_session);
        g_object_unref(dbus_connection);
    }

    g_signal_connect(listener,
                     NM_POLKIT_LISTENER_SIGNAL_REQUEST_SYNC,
                     G_CALLBACK(polkit_read_passwd),
                     nmc);
    g_signal_connect(listener, NM_POLKIT_LISTENER_SIGNAL_ERROR, G_CALLBACK(polkit_error), NULL);

    nmc->pk_listener = listener;
    return TRUE;
}

void
nmc_polkit_agent_fini(NmCli *nmc)
{
    if (nmc->pk_listener) {
        g_clear_object(&nmc->pk_listener);
    }
}

gboolean
nmc_start_polkit_agent_start_try(NmCli *nmc)
{
    gs_free_error GError *error = NULL;

    /* We don't register polkit agent at all when running non-interactively */
    if (!nmc->ask)
        return TRUE;

    if (!nmc_polkit_agent_init(nmc, FALSE, &error)) {
        g_printerr(_("Warning: polkit agent initialization failed: %s\n"), error->message);
        return FALSE;
    }
    return TRUE;
}
