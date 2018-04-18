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

#include "nm-default.h"

#include "nm-dnsmasq-manager.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "nm-dnsmasq-utils.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"

#define CONFDIR NMCONFDIR "/dnsmasq-shared.d"

/*****************************************************************************/

enum {
	STATE_CHANGED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	char *iface;
	char *pidfile;
	GPid pid;
	guint dm_watch_id;
} NMDnsMasqManagerPrivate;

struct _NMDnsMasqManager {
	GObject parent;
	NMDnsMasqManagerPrivate _priv;
};

struct _NMDnsMasqManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMDnsMasqManager, nm_dnsmasq_manager, G_TYPE_OBJECT)

#define NM_DNSMASQ_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDnsMasqManager, NM_IS_DNSMASQ_MANAGER)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_SHARING
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "dnsmasq-manager", __VA_ARGS__)

/*****************************************************************************/

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

/*****************************************************************************/

static void
dm_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMDnsMasqManager *manager = NM_DNSMASQ_MANAGER (user_data);
	NMDnsMasqManagerPrivate *priv = NM_DNSMASQ_MANAGER_GET_PRIVATE (manager);
	guint err;

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
		if (err != 0) {
			_LOGW ("dnsmasq exited with error: %s",
			       nm_utils_dnsmasq_status_to_string (err, NULL, 0));
		}
	} else if (WIFSTOPPED (status)) {
		_LOGW ("dnsmasq stopped unexpectedly with signal %d", WSTOPSIG (status));
	} else if (WIFSIGNALED (status)) {
		_LOGW ("dnsmasq died with signal %d", WTERMSIG (status));
	} else {
		_LOGW ("dnsmasq died from an unknown cause");
	}

	priv->pid = 0;
	priv->dm_watch_id = 0;

	g_signal_emit (manager, signals[STATE_CHANGED], 0, NM_DNSMASQ_STATUS_DEAD);
}

static NMCmdLine *
create_dm_cmd_line (const char *iface,
                    const NMIP4Config *ip4_config,
                    const char *pidfile,
                    GError **error)
{
	NMCmdLine *cmd;
	nm_auto_free_gstring GString *s = NULL;
	char first[INET_ADDRSTRLEN];
	char last[INET_ADDRSTRLEN];
	char localaddr[INET_ADDRSTRLEN];
	char tmpaddr[INET_ADDRSTRLEN];
	char *error_desc = NULL;
	const char *dm_binary;
	const NMPlatformIP4Address *listen_address;
	guint i, n;

	listen_address = nm_ip4_config_get_first_address (ip4_config);
	g_return_val_if_fail (listen_address, NULL);

	dm_binary = nm_utils_find_helper ("dnsmasq", DNSMASQ_PATH, error);
	if (!dm_binary)
		return NULL;

	s = g_string_sized_new (100);

	/* Create dnsmasq command line */
	cmd = nm_cmd_line_new ();
	nm_cmd_line_add_string (cmd, dm_binary);

	if (   nm_logging_enabled (LOGL_TRACE, LOGD_SHARING)
	    || getenv ("NM_DNSMASQ_DEBUG")) {
		nm_cmd_line_add_string (cmd, "--log-dhcp");
		nm_cmd_line_add_string (cmd, "--log-queries");
	}

	/* dnsmasq may read from its default config file location, which if that
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

	nm_utils_inet4_ntop (listen_address->address, localaddr);
	g_string_append (s, "--listen-address=");
	g_string_append (s, localaddr);
	nm_cmd_line_add_string (cmd, s->str);
	g_string_truncate (s, 0);

	if (!nm_dnsmasq_utils_get_range (listen_address, first, last, &error_desc)) {
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_FAILED,
		                     error_desc);
		_LOGW ("failed to find DHCP address ranges: %s", error_desc);
		g_free (error_desc);
		nm_cmd_line_destroy (cmd);
		return NULL;
	}

	g_string_append_printf (s, "--dhcp-range=%s,%s,60m", first, last);
	nm_cmd_line_add_string (cmd, s->str);
	g_string_truncate (s, 0);

	if (nm_ip4_config_best_default_route_get (ip4_config)) {
		g_string_append (s, "--dhcp-option=option:router,");
		g_string_append (s, localaddr);
		nm_cmd_line_add_string (cmd, s->str);
		g_string_truncate (s, 0);
	}

	if ((n = nm_ip4_config_get_num_nameservers (ip4_config))) {
		g_string_append (s, "--dhcp-option=option:dns-server");
		for (i = 0; i < n; i++) {
			g_string_append_c (s, ',');
			g_string_append (s, nm_utils_inet4_ntop (nm_ip4_config_get_nameserver (ip4_config, i), tmpaddr));
		}
		g_string_truncate (s, 0);
	}

	if ((n = nm_ip4_config_get_num_searches (ip4_config))) {
		g_string_append (s, "--dhcp-option=option:domain-search");
		for (i = 0; i < n; i++) {
			g_string_append_c (s, ',');
			g_string_append (s, nm_ip4_config_get_search (ip4_config, i));
		}
		g_string_truncate (s, 0);
	}

	nm_cmd_line_add_string (cmd, "--dhcp-lease-max=50");

	g_string_append (s, "--pid-file=");
	g_string_append (s, pidfile);
	nm_cmd_line_add_string (cmd, s->str);
	g_string_truncate (s, 0);

	/* dnsmasq exits if the conf dir is not present */
	if (g_file_test (CONFDIR, G_FILE_TEST_IS_DIR))
		nm_cmd_line_add_string (cmd, "--conf-dir=" CONFDIR);

	return cmd;
}

static void
kill_existing_by_pidfile (const char *pidfile)
{
	char *contents = NULL;
	pid_t pid;
	char proc_path[250];
	char *cmdline_contents = NULL;
	guint64 start_time;
	const char *exe;

	if (   !pidfile
	    || !g_file_get_contents (pidfile, &contents, NULL, NULL))
		return;

	pid = _nm_utils_ascii_str_to_int64 (contents, 10, 1, G_MAXUINT64, 0);
	if (pid == 0)
		goto out;

	start_time = nm_utils_get_start_time_for_pid (pid, NULL, NULL);
	if (start_time == 0)
		goto out;

	nm_sprintf_buf (proc_path, "/proc/%lld/cmdline", (long long) pid);
	if (!g_file_get_contents (proc_path, &cmdline_contents, NULL, NULL))
		goto out;

	exe = strrchr (cmdline_contents, '/');
	if (   (exe && strcmp (&exe[1], "dnsmasq") == 0)
	    || (strcmp (cmdline_contents, DNSMASQ_PATH) == 0)) {
		nm_utils_kill_process_sync (pid, start_time, SIGKILL, LOGD_SHARING,
		                            "dnsmasq", 0, 0, 500);
	}

out:
	unlink (pidfile);
	g_free (cmdline_contents);
	g_free (contents);
}

gboolean
nm_dnsmasq_manager_start (NMDnsMasqManager *manager,
                          NMIP4Config *ip4_config,
                          GError **error)
{
	NMDnsMasqManagerPrivate *priv;
	NMCmdLine *dm_cmd;
	gs_free char *cmd_str = NULL;

	g_return_val_if_fail (NM_IS_DNSMASQ_MANAGER (manager), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	g_return_val_if_fail (nm_ip4_config_get_num_addresses (ip4_config) > 0, FALSE);

	priv = NM_DNSMASQ_MANAGER_GET_PRIVATE (manager);

	kill_existing_by_pidfile (priv->pidfile);

	dm_cmd = create_dm_cmd_line (priv->iface, ip4_config, priv->pidfile, error);
	if (!dm_cmd)
		return FALSE;

	g_ptr_array_add (dm_cmd->array, NULL);

	_LOGI ("starting dnsmasq...");
	_LOGD ("command line: %s", (cmd_str = nm_cmd_line_to_str (dm_cmd)));

	priv->pid = 0;
	if (!g_spawn_async (NULL, (char **) dm_cmd->array->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD,
	                    nm_utils_setpgid, NULL,
	                    &priv->pid, error)) {
		goto out;
	}

	_LOGD ("dnsmasq started with pid %d", priv->pid);

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

	nm_clear_g_source (&priv->dm_watch_id);

	if (priv->pid) {
		nm_utils_kill_child_async (priv->pid, SIGTERM, LOGD_SHARING, "dnsmasq", 2000, NULL, NULL);
		priv->pid = 0;
	}

	unlink (priv->pidfile);
}

/*****************************************************************************/

static void
nm_dnsmasq_manager_init (NMDnsMasqManager *manager)
{
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

static void
finalize (GObject *object)
{
	NMDnsMasqManagerPrivate *priv = NM_DNSMASQ_MANAGER_GET_PRIVATE ((NMDnsMasqManager *) object);

	nm_dnsmasq_manager_stop (NM_DNSMASQ_MANAGER (object));

	g_free (priv->iface);
	g_free (priv->pidfile);

	G_OBJECT_CLASS (nm_dnsmasq_manager_parent_class)->finalize (object);
}

static void
nm_dnsmasq_manager_class_init (NMDnsMasqManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	object_class->finalize = finalize;

	signals[STATE_CHANGED] =
	     g_signal_new (NM_DNS_MASQ_MANAGER_STATE_CHANGED,
	                   G_OBJECT_CLASS_TYPE (object_class),
	                   G_SIGNAL_RUN_FIRST,
	                   0, NULL, NULL,
	                   g_cclosure_marshal_VOID__UINT,
	                   G_TYPE_NONE, 1,
	                   G_TYPE_UINT);
}
