/*
 *  nmcli - command-line tool for controlling NetworkManager
 *  Functions for running NM secret agent.
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "nm-default.h"
#include "common.h"
#include "utils.h"
#include "nm-secret-agent-simple.h"
#include "polkit-agent.h"
#include "agent.h"

static void
usage (void)
{
	g_printerr (_("Usage: nmcli agent { COMMAND | help }\n\n"
	              "COMMAND := { secret | polkit | all }\n\n"
	           ));
}

static void
usage_agent_secret (void)
{
	g_printerr (_("Usage: nmcli agent secret { help }\n"
	              "\n"
	              "Runs nmcli as NetworkManager secret agent. When NetworkManager requires\n"
	              "a password it asks registered agents for it. This command keeps nmcli running\n"
	              "and if a password is required asks the user for it.\n\n"));
}

static void
usage_agent_polkit (void)
{
	g_printerr (_("Usage: nmcli agent polkit { help }\n"
	              "\n"
	              "Registers nmcli as a polkit action for the user session.\n"
	              "When a polkit daemon requires an authorization, nmcli asks the user and gives\n"
	              "the response back to polkit.\n\n"));
}

static void
usage_agent_all (void)
{
	g_printerr (_("Usage: nmcli agent all { help }\n"
	              "\n"
	              "Runs nmcli as both NetworkManager secret and a polkit agent.\n\n"));
}

/* for pre-filling a string to readline prompt */
static char *pre_input_deftext;
static int
set_deftext (void)
{
	if (pre_input_deftext && rl_startup_hook) {
		rl_insert_text (pre_input_deftext);
		g_free (pre_input_deftext);
		pre_input_deftext = NULL;
		rl_startup_hook = NULL;
	}
	return 0;
}

static gboolean
get_secrets_from_user (const char *request_id,
                       const char *title,
                       const char *msg,
                       GPtrArray *secrets)
{
	int i;

	for (i = 0; i < secrets->len; i++) {
		NMSecretAgentSimpleSecret *secret = secrets->pdata[i];
		char *pwd = NULL;

		/* Ask user for the password */
		g_print ("%s\n", msg);
		if (secret->value) {
			/* Prefill the password if we have it. */
			rl_startup_hook = set_deftext;
			pre_input_deftext = g_strdup (secret->value);
		}
		pwd = nmc_readline ("%s (%s): ", secret->name, secret->prop_name);

		/* No password provided, cancel the secrets. */
		if (!pwd)
			return FALSE;
		g_free (secret->value);
		secret->value = pwd;
	}
	return TRUE;
}

static void
secrets_requested (NMSecretAgentSimple *agent,
                   const char          *request_id,
                   const char          *title,
                   const char          *msg,
                   GPtrArray           *secrets,
                   gpointer             user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	gboolean success = FALSE;

	if (nmc->print_output == NMC_PRINT_PRETTY)
		nmc_terminal_erase_line ();

	success = get_secrets_from_user (request_id, title, msg, secrets);
	if (success)
		nm_secret_agent_simple_response (agent, request_id, secrets);
	else
		nm_secret_agent_simple_response (agent, request_id, NULL);
}


static NMCResultCode
do_agent_secret (NmCli *nmc, int argc, char **argv)
{
	/* Create secret agent */
	nmc->secret_agent = nm_secret_agent_simple_new ("nmcli-agent");
	if (nmc->secret_agent) {
		/* We keep running */
		nmc->should_wait = TRUE;

		nm_secret_agent_simple_enable (NM_SECRET_AGENT_SIMPLE (nmc->secret_agent), NULL);
		g_signal_connect (nmc->secret_agent, "request-secrets", G_CALLBACK (secrets_requested), nmc);
		g_print (_("nmcli successfully registered as a NetworkManager's secret agent.\n"));
	} else {
		g_string_printf (nmc->return_text, _("Error: secret agent initialization failed"));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
	}

	return nmc->return_value;
}

static NMCResultCode
do_agent_polkit (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;

	/* Initialize polkit agent */
	if (!nmc_polkit_agent_init (nmc, TRUE, &error)) {
		g_dbus_error_strip_remote_error (error);
		g_string_printf (nmc->return_text, _("Error: polkit agent initialization failed: %s"),
		                 error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		g_error_free (error);
	} else {
		/* We keep running */
		nmc->should_wait = TRUE;

		g_print (_("nmcli successfully registered as a polkit agent.\n"));
	}

	return nmc->return_value;
}

static NMCResultCode
do_agent_all (NmCli *nmc, int argc, char **argv)
{
	NMCResultCode secret_res;

	/* Run both secret and polkit agent */
	secret_res = do_agent_secret (nmc, argc, argv);
	if (secret_res != NMC_RESULT_SUCCESS)
		g_printerr ("%s\n", nmc->return_text->str);

	nmc->return_value = do_agent_polkit (nmc, argc, argv);

	if (nmc->return_value == NMC_RESULT_SUCCESS && secret_res != NMC_RESULT_SUCCESS)
		nmc->return_value = secret_res;

	return nmc->return_value;
}

NMCResultCode
do_agent (NmCli *nmc, int argc, char **argv)
{
	/* Get NMClient object */
	nmc->get_client (nmc);

	/* Check whether NetworkManager is running */
	if (!nm_client_get_nm_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		return nmc->return_value;
	}
	/* Compare NM and nmcli versions */
	if (!nmc_versions_match (nmc))
		return nmc->return_value;

	if (argc == 0) {
		nmc->return_value = do_agent_all (nmc, 0, NULL);
	}

	if (argc > 0) {
		if (nmc_arg_is_help (*argv)) {
			usage ();
			goto usage_exit;
		} else if (matches (*argv, "secret") == 0) {
			if (nmc_arg_is_help (*(argv+1))) {
				usage_agent_secret ();
				goto usage_exit;
			}
			nmc->return_value = do_agent_secret (nmc, argc-1, argv+1);
		} else if (matches (*argv, "polkit") == 0) {
			if (nmc_arg_is_help (*(argv+1))) {
				usage_agent_polkit ();
				goto usage_exit;
			}
			nmc->return_value = do_agent_polkit (nmc, argc-1, argv+1);
		} else if (matches (*argv, "all") == 0) {
			if (nmc_arg_is_help (*(argv+1))) {
				usage_agent_all ();
				goto usage_exit;
			}
			nmc->return_value = do_agent_all (nmc, argc-1, argv+1);
		} else {
			usage ();
			g_string_printf (nmc->return_text, _("Error: 'agent' command '%s' is not valid."), *argv);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		}
	}

usage_exit:
	return nmc->return_value;
}
