/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "nm-default.h"
#include "nm-dnsmasq-manager.h"
#include "nm-dnsmasq-utils.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"

typedef struct {
	char *iface;
	char *pidfile;
	GPid pid;
	guint32 dm_watch_id;
} NMDnsMasqManagerPrivate;

#define NM_DNSMASQ_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DNSMASQ_MANAGER, NMDnsMasqManagerPrivate))

G_DEFINE_TYPE (NMDnsMasqManager, nm_dnsmasq_manager, G_TYPE_OBJECT)

enum {
	STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
nm_dnsmasq_manager_init (NMDnsMasqManager *manager)
{
}

static void
finalize (GObject *object)
{
	NMDnsMasqManagerPrivate *priv = NM_DNSMASQ_MANAGER_GET_PRIVATE (object);

	nm_dnsmasq_manager_stop (NM_DNSMASQ_MANAGER (object));

	g_free (priv->iface);
	g_free (priv->pidfile);

	G_OBJECT_CLASS (nm_dnsmasq_manager_parent_class)->finalize (object);
}

static void
nm_dnsmasq_manager_class_init (NMDnsMasqManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMDnsMasqManagerPrivate));

	object_class->finalize = finalize;

	/* signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMDnsMasqManagerClass, state_changed),
				    NULL, NULL,
				    g_cclosure_marshal_VOID__UINT,
				    G_TYPE_NONE, 1,
				    G_TYPE_UINT);
}

NMDnsMasqManager *
nm_dnsmasq_manager_new (const char *iface)
{
	NMDnsMasqManager *manager;
	NMDnsMasqManagerPrivate *priv;

	manager = (NMDnsMasqManager *) g_object_new (NM_TYPE_DNSMASQ_MANAGER, NULL);

	priv = NM_DNSMASQ_MANAGER_GET_PRIVATE (manager);
	priv->iface = g_strdup (iface);
	priv->pidfile = g_strdup_printf (RUNSTATEDIR "/nm-dnsmasq-%s.pid", iface);

	return manager;
}

typedef struct {
	GPtrArray *array;
	GStringChunk *chunk;
} NMCmdLine;

static NMCmdLine *
nm_cmd_line_new (void)
{
	NMCmdLine *cmd;

	cmd = g_slice_new (NMCmdLine);
	cmd->array = g_ptr_array_new ();
	cmd->chunk = g_string_chunk_new (1024);

	return cmd;
}

static void
nm_cmd_line_destroy (NMCmdLine *cmd)
{
	g_ptr_array_free (cmd->array, TRUE);
	g_string_chunk_free (cmd->chunk);
	g_slice_free (NMCmdLine, cmd);
}

static char *
nm_cmd_line_to_str (NMCmdLine *cmd)
{
	char *str;

	g_ptr_array_add (cmd->array, NULL);
	str = g_strjoinv (" ", (gchar **) cmd->array->pdata);
	g_ptr_array_remove_index (cmd->array, cmd->array->len - 1);

	return str;
}

static void
nm_cmd_line_add_string (NMCmdLine *cmd, const char *str)
{
	g_ptr_array_add (cmd->array, g_string_chunk_insert (cmd->chunk, str));
}

/*******************************************/

static void
dm_exit_code (guint dm_exit_status)
{
	char *msg = "Unknown error";

	switch (dm_exit_status) {
	case 1:
		msg = "Configuration problem";
		break;
	case 2:
		msg = "Network access problem (address in use; permissions; etc)";
		break;
	case 3:
		msg = "Filesystem problem (missing file/directory; permissions; etc)";
		break;
	case 4:
		msg = "Memory allocation failure";
		break;
	case 5: 
		msg = "Other problem";
		break;
	default:
		if (dm_exit_status >= 11)
			msg = "Lease-script 'init' process failure";
		break;
	}

	nm_log_warn (LOGD_SHARING, "dnsmasq exited with error: %s (%d)", msg, dm_exit_status);
}

static void
dm_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMDnsMasqManager *manager = NM_DNSMASQ_MANAGER (user_data);
	NMDnsMasqManagerPrivate *priv = NM_DNSMASQ_MANAGER_GET_PRIVATE (manager);
	guint err;

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
		if (err != 0)
			dm_exit_code (err);
	} else if (WIFSTOPPED (status)) {
		nm_log_warn (LOGD_SHARING, "dnsmasq stopped unexpectedly with signal %d", WSTOPSIG (status));
	} else if (WIFSIGNALED (status)) {
		nm_log_warn (LOGD_SHARING, "dnsmasq died with signal %d", WTERMSIG (status));
	} else {
		nm_log_warn (LOGD_SHARING, "dnsmasq died from an unknown cause");
	}
  
	priv->pid = 0;
	priv->dm_watch_id = 0;

	g_signal_emit (manager, signals[STATE_CHANGED], 0, NM_DNSMASQ_STATUS_DEAD);
}

static NMCmdLine *
create_dm_cmd_line (const char *iface,
                    NMIP4Config *ip4_config,
                    const char *pidfile,
                    GError **error)
{
	NMCmdLine *cmd;
	GString *s;
	const NMPlatformIP4Address *tmp;
	char first[INET_ADDRSTRLEN];
	char last[INET_ADDRSTRLEN];
	char localaddr[INET_ADDRSTRLEN];
	char *error_desc = NULL;
	const char *dm_binary;

	dm_binary = nm_utils_find_helper ("dnsmasq", DNSMASQ_PATH, error);
	if (!dm_binary)
		return NULL;

	/* Create dnsmasq command line */
	cmd = nm_cmd_line_new ();
	nm_cmd_line_add_string (cmd, dm_binary);

	if (getenv ("NM_DNSMASQ_DEBUG")) {
		nm_cmd_line_add_string (cmd, "--log-dhcp");
		nm_cmd_line_add_string (cmd, "--log-queries");
	}

	/* dnsmasq may read from it's default config file location, which if that
	 * location is a valid config file, it will combine with the options here
	 * and cause undesirable side-effects.  Like sending bogus IP addresses
	 * as the gateway or whatever.  So tell dnsmasq not to use any config file
	 * at all.
	 */
	nm_cmd_line_add_string (cmd, "--conf-file");

	nm_cmd_line_add_string (cmd, "--no-hosts");
	nm_cmd_line_add_string (cmd, "--keep-in-foreground");
	nm_cmd_line_add_string (cmd, "--bind-interfaces");
	nm_cmd_line_add_string (cmd, "--except-interface=lo");
	nm_cmd_line_add_string (cmd, "--clear-on-reload");

	/* Use strict order since in the case of VPN connections, the VPN's
	 * nameservers will be first in resolv.conf, and those need to be tried
	 * first by dnsmasq to successfully resolve names from the VPN.
	 */
	nm_cmd_line_add_string (cmd, "--strict-order");

	/* Find the IP4 address to use */
	tmp = nm_ip4_config_get_address (ip4_config, 0);

	s = g_string_new ("--listen-address=");
	nm_utils_inet4_ntop (tmp->address, localaddr);
	g_string_append (s, localaddr);
	nm_cmd_line_add_string (cmd, s->str);
	g_string_free (s, TRUE);

	if (!nm_dnsmasq_utils_get_range (tmp, first, last, &error_desc)) {
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_FAILED,
		                     error_desc);
		nm_log_warn (LOGD_SHARING, "Failed to find DHCP address ranges: %s", error_desc);
		g_free (error_desc);
		nm_cmd_line_destroy (cmd);
		return NULL;
	}

	s = g_string_new ("--dhcp-range=");
	g_string_append_printf (s, "%s,%s,60m", first, last);
	nm_cmd_line_add_string (cmd, s->str);
	g_string_free (s, TRUE);

	s = g_string_new ("--dhcp-option=option:router,");
	g_string_append (s, localaddr);
	nm_cmd_line_add_string (cmd, s->str);
	g_string_free (s, TRUE);

	nm_cmd_line_add_string (cmd, "--dhcp-lease-max=50");

	s = g_string_new ("--pid-file=");
	g_string_append (s, pidfile);
	nm_cmd_line_add_string (cmd, s->str);
	g_string_free (s, TRUE);

	return cmd;
}

static void
kill_existing_for_iface (const char *iface, const char *pidfile)
{
	char *contents = NULL;
	glong pid;
	char *proc_path = NULL;
	char *cmdline_contents = NULL;

	if (!g_file_get_contents (pidfile, &contents, NULL, NULL))
		goto out;

	pid = strtol (contents, NULL, 10);
	if (pid < 1 || pid > INT_MAX)
		goto out;

	proc_path = g_strdup_printf ("/proc/%ld/cmdline", pid);
	if (!g_file_get_contents (proc_path, &cmdline_contents, NULL, NULL))
		goto out;

	if (strstr (cmdline_contents, "bin/dnsmasq")) {
		if (kill (pid, 0) == 0) {
			nm_log_dbg (LOGD_SHARING, "Killing stale dnsmasq process %ld", pid);
			kill (pid, SIGKILL);
		}
		unlink (pidfile);
	}

out:
	g_free (cmdline_contents);
	g_free (proc_path);
	g_free (contents);
}

gboolean
nm_dnsmasq_manager_start (NMDnsMasqManager *manager,
                          NMIP4Config *ip4_config,
                          GError **error)
{
	NMDnsMasqManagerPrivate *priv;
	NMCmdLine *dm_cmd;
	char *cmd_str;

	g_return_val_if_fail (NM_IS_DNSMASQ_MANAGER (manager), FALSE);
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	priv = NM_DNSMASQ_MANAGER_GET_PRIVATE (manager);

	kill_existing_for_iface (priv->iface, priv->pidfile);

	dm_cmd = create_dm_cmd_line (priv->iface, ip4_config, priv->pidfile, error);
	if (!dm_cmd)
		return FALSE;

	g_ptr_array_add (dm_cmd->array, NULL);

	nm_log_info (LOGD_SHARING, "Starting dnsmasq...");

	cmd_str = nm_cmd_line_to_str (dm_cmd);
	nm_log_dbg (LOGD_SHARING, "Command line: %s", cmd_str);
	g_free (cmd_str);

	priv->pid = 0;
	if (!g_spawn_async (NULL, (char **) dm_cmd->array->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD,
	                    nm_utils_setpgid, NULL,
	                    &priv->pid, error)) {
		goto out;
	}

	nm_log_dbg (LOGD_SHARING, "dnsmasq started with pid %d", priv->pid);

	priv->dm_watch_id = g_child_watch_add (priv->pid, (GChildWatchFunc) dm_watch_cb, manager);

 out:
	if (dm_cmd)
		nm_cmd_line_destroy (dm_cmd);

	return priv->pid > 0;
}

void
nm_dnsmasq_manager_stop (NMDnsMasqManager *manager)
{
	NMDnsMasqManagerPrivate *priv;

	g_return_if_fail (NM_IS_DNSMASQ_MANAGER (manager));

	priv = NM_DNSMASQ_MANAGER_GET_PRIVATE (manager);

	if (priv->dm_watch_id) {
		g_source_remove (priv->dm_watch_id);
		priv->dm_watch_id = 0;
	}

	if (priv->pid) {
		nm_utils_kill_child_async (priv->pid, SIGTERM, LOGD_SHARING, "dnsmasq", 2000, NULL, NULL);
		priv->pid = 0;
	}

	unlink (priv->pidfile);
}
