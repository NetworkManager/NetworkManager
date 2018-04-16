/* nmcli - command-line tool to control NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "polkit-agent.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "nm-polkit-listener.h"
#include "common.h"

#if WITH_POLKIT_AGENT
static char *
polkit_request (NMPolkitListener *listener,
                const char *request,
                const char *action_id,
                const char *message,
                const char *icon_name,
                const char *user,
                gboolean echo_on,
                gpointer user_data)
{
	char *response, *tmp, *p;

	g_print ("%s\n", message);
	g_print ("(action_id: %s)\n", action_id);

	/* Ask user for polkit authorization password */
	if (user) {
		/* chop of ": " if present */
		tmp = g_strdup (request);
		p = strrchr (tmp, ':');
		if (p && !strcmp (p, ": "))
			*p = '\0';
		response = nmc_readline_echo (echo_on, "%s (%s): ", tmp, user);
		g_free (tmp);
	} else
		response = nmc_readline_echo (echo_on, "%s", request);

	return response;
}

static void
polkit_show_info (NMPolkitListener *listener,
                  const char *text,
                  gpointer user_data)
{
	g_print (_("Authentication message: %s\n"), text);
}

static void
polkit_show_error (NMPolkitListener *listener,
                   const char *text,
                   gpointer user_data)
{
	g_print (_("Authentication error: %s\n"), text);
}

static void
polkit_completed (NMPolkitListener *listener,
                  gboolean gained_authorization,
                  gpointer user_data)
{
	/* We don't print anything here. The outcome will be evident from
	 * the operation result anyway. */
}
#endif

gboolean
nmc_polkit_agent_init (NmCli* nmc, gboolean for_session, GError **error)
{
#if WITH_POLKIT_AGENT
	static const NMPolkitListenVtable vtable = {
		.on_request = polkit_request,
		.on_show_info = polkit_show_info,
		.on_show_error = polkit_show_error,
		.on_completed = polkit_completed,
	};
	NMPolkitListener *listener;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	listener = nm_polkit_listener_new (for_session, error);
	if (!listener)
		return FALSE;

	nm_polkit_listener_set_vtable (listener, &vtable, nmc);

	nmc->pk_listener = listener;
#endif
	return TRUE;
}

void
nmc_polkit_agent_fini (NmCli* nmc)
{
#if WITH_POLKIT_AGENT
	if (nmc->pk_listener) {
		nm_polkit_listener_set_vtable (nmc->pk_listener, NULL, NULL);
		g_clear_object (&nmc->pk_listener);
	}
#endif
}

gboolean
nmc_start_polkit_agent_start_try (NmCli *nmc)
{
#if WITH_POLKIT_AGENT
	GError *error = NULL;

	/* We don't register polkit agent at all when running non-interactively */
	if (!nmc->ask)
		return TRUE;

	if (!nmc_polkit_agent_init (nmc, FALSE, &error)) {
		g_printerr (_("Warning: polkit agent initialization failed: %s\n"),
		            error->message);
		g_error_free (error);
		return FALSE;
	}
#endif
	return TRUE;
}
