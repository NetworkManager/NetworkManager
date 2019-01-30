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

#include "nm-default.h"

#include "agent.h"

#include <stdio.h>
#include <stdlib.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "common.h"
#include "utils.h"
#include "nm-secret-agent-simple.h"
#include "polkit-agent.h"

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
get_secrets_from_user (const NmcConfig *nmc_config,
                       const char *request_id,
                       const char *title,
                       const char *msg,
                       GPtrArray *secrets)
{
	int i;

	for (i = 0; i < secrets->len; i++) {
		NMSecretAgentSimpleSecret *secret = secrets->pdata[i];
		char *pwd = NULL;

		/* Ask user for the password */
		if (msg)
			g_print ("%s\n", msg);
		if (secret->value) {
			/* Prefill the password if we have it. */
			rl_startup_hook = set_deftext;
			pre_input_deftext = g_strdup (secret->value);
		}
		if (secret->no_prompt_entry_id)
			pwd = nmc_readline (nmc_config, "%s: ", secret->pretty_name);
		else
			pwd = nmc_readline (nmc_config, "%s (%s): ", secret->pretty_name, secret->entry_id);

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
	NmCli *nmc = user_data;
	gboolean success;

	if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY)
		nmc_terminal_erase_line ();

	success = get_secrets_from_user (&nmc->nmc_config, request_id, title, msg, secrets);
	nm_secret_agent_simple_response (agent,
	                                 request_id,
	                                 success ? secrets : NULL);
}

static NMCResultCode
do_agent_secret (NmCli *nmc, int argc, char **argv)
{
	next_arg (nmc, &argc, &argv, NULL);
	if (nmc->complete)
		return nmc->return_value;

	/* Create secret agent */
	nmc->secret_agent = nm_secret_agent_simple_new ("nmcli-agent");
	if (nmc->secret_agent) {
		/* We keep running */
		nmc->should_wait++;

		nm_secret_agent_simple_enable (nmc->secret_agent, NULL);
		g_signal_connect (nmc->secret_agent,
		                  NM_SECRET_AGENT_SIMPLE_REQUEST_SECRETS,
		                  G_CALLBACK (secrets_requested),
		                  nmc);
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

	next_arg (nmc, &argc, &argv, NULL);
	if (nmc->complete)
		return nmc->return_value;

	/* Initialize polkit agent */
	if (!nmc_polkit_agent_init (nmc, TRUE, &error)) {
		g_dbus_error_strip_remote_error (error);
		g_string_printf (nmc->return_text, _("Error: polkit agent initialization failed: %s"),
		                 error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		g_error_free (error);
	} else {
		/* We keep running */
		nmc->should_wait++;

		g_print (_("nmcli successfully registered as a polkit agent.\n"));
	}

	return nmc->return_value;
}

static NMCResultCode
do_agent_all (NmCli *nmc, int argc, char **argv)
{
	NMCResultCode secret_res;

	next_arg (nmc, &argc, &argv, NULL);
	if (nmc->complete)
		return nmc->return_value;

	/* Run both secret and polkit agent */
	secret_res = do_agent_secret (nmc, argc, argv);
	if (secret_res != NMC_RESULT_SUCCESS) {
		g_printerr ("%s\n", nmc->return_text->str);
		g_string_truncate (nmc->return_text, 0);
	}

	nmc->return_value = do_agent_polkit (nmc, argc, argv);
	if (nmc->return_value != NMC_RESULT_SUCCESS) {
		g_printerr ("%s\n", nmc->return_text->str);
		g_string_truncate (nmc->return_text, 0);
	}

	if (nmc->return_value == NMC_RESULT_SUCCESS && secret_res != NMC_RESULT_SUCCESS)
		nmc->return_value = secret_res;

	return nmc->return_value;
}

static const NMCCommand agent_cmds[] = {
	{ "secret",  do_agent_secret,  usage_agent_secret,  TRUE,   TRUE },
	{ "polkit",  do_agent_polkit,  usage_agent_polkit,  TRUE,   TRUE },
	{ "all",     do_agent_all,     usage_agent_all,     TRUE,   TRUE },
	{ NULL,      do_agent_all,     usage,               TRUE,   TRUE },
};

NMCResultCode
do_agent (NmCli *nmc, int argc, char **argv)
{
	next_arg (nmc, &argc, &argv, NULL);
	nmc_do_cmd (nmc, agent_cmds, *argv, argc, argv);

	return nmc->return_value;
}
