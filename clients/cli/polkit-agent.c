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

#include "config.h"

#if WITH_POLKIT_AGENT

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <termios.h>

#include <glib/gi18n-lib.h>

#include "nm-glib.h"
#include "polkit-agent.h"
#include "nm-polkit-listener.h"
#include "common.h"

static char *
polkit_request (const char *request,
                const char *action_id,
                const char *message,
                const char *icon_name,
                const char *user,
                gboolean echo_on,
		gpointer user_data)
{
	char *response, *tmp, *p;
	struct termios termios_orig, termios_new;

	g_print ("%s\n", message);
	g_print ("(action_id: %s)\n", action_id);

	if (!echo_on) {
		tcgetattr (STDIN_FILENO, &termios_orig);
		termios_new = termios_orig;
		termios_new.c_lflag &= ~(ECHO);
		tcsetattr (STDIN_FILENO, TCSADRAIN, &termios_new);
	}

	/* Ask user for polkit authorization password */
	if (user) {
		/* chop of ": " if present */
		tmp = g_strdup (request);
		p = strrchr (tmp, ':');
		if (p && !strcmp (p, ": "))
			*p = '\0';
		response = nmc_readline ("%s (%s): ", tmp, user);
		g_free (tmp);
	} else
		response = nmc_readline ("%s", request);
	g_print ("\n");

	/* Restore original terminal settings */
	if (!echo_on)
		tcsetattr (STDIN_FILENO, TCSADRAIN, &termios_orig);

	return response;
}

static void
polkit_show_info (const char *text)
{
	g_print (_("Authentication message: %s\n"), text);
}

static void
polkit_show_error (const char *text)
{
	g_print (_("Authentication error: %s\n"), text);
}

static void
polkit_completed (gboolean gained_authorization)
{
	/* We don't print anything here. The outcome will be evident from
	 * the operation result anyway. */
}

gboolean
nmc_polkit_agent_init (NmCli* nmc, gboolean for_session, GError **error)
{
	PolkitAgentListener *listener;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	listener = nm_polkit_listener_new (for_session, error);
	if (!listener)
		return FALSE;

	nm_polkit_listener_set_request_callback (NM_POLKIT_LISTENER (listener), polkit_request, nmc);
	nm_polkit_listener_set_show_info_callback (NM_POLKIT_LISTENER (listener), polkit_show_info);
	nm_polkit_listener_set_show_error_callback (NM_POLKIT_LISTENER (listener), polkit_show_error);
	nm_polkit_listener_set_completed_callback (NM_POLKIT_LISTENER (listener), polkit_completed);

	nmc->pk_listener = NM_POLKIT_LISTENER (listener);
	return TRUE;
}

void
nmc_polkit_agent_fini (NmCli* nmc)
{
	g_clear_object (&nmc->pk_listener);
}

gboolean
nmc_start_polkit_agent_start_try (NmCli *nmc)
{
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
	return TRUE;
}

#else
/* polkit agent is not avalable; implement stub functions. */

#include "nm-glib.h"
#include "nmcli.h"
#include "polkit-agent.h"

gboolean
nmc_polkit_agent_init (NmCli* nmc, gboolean for_session, GError **error)
{
	return TRUE;
}

void
nmc_polkit_agent_fini (NmCli* nmc)
{
}

gboolean
nmc_start_polkit_agent_start_try (NmCli *nmc)
{
	return TRUE;
}

#endif /* #if WITH_POLKIT_AGENT */
