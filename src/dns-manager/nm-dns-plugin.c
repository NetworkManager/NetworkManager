/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2010 - 2012 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "nm-core-internal.h"

#include "nm-dns-plugin.h"
#include "NetworkManagerUtils.h"

typedef struct {
	GPid pid;
	guint watch_id;
	char *progname;
	char *pidfile;
} NMDnsPluginPrivate;

#define NM_DNS_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DNS_PLUGIN, NMDnsPluginPrivate))

G_DEFINE_TYPE_EXTENDED (NMDnsPlugin, nm_dns_plugin, G_TYPE_OBJECT, G_TYPE_FLAG_ABSTRACT, {})

enum {
	FAILED,
	CHILD_QUIT,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

/********************************************/

gboolean
nm_dns_plugin_update (NMDnsPlugin *self,
                      const GSList *vpn_configs,
                      const GSList *dev_configs,
                      const GSList *other_configs,
                      const NMGlobalDnsConfig *global_config,
                      const char *hostname)
{
	g_return_val_if_fail (NM_DNS_PLUGIN_GET_CLASS (self)->update != NULL, FALSE);

	return NM_DNS_PLUGIN_GET_CLASS (self)->update (self,
	                                               vpn_configs,
	                                               dev_configs,
	                                               other_configs,
	                                               global_config,
	                                               hostname);
}

static gboolean
is_caching (NMDnsPlugin *self)
{
	return FALSE;
}

gboolean
nm_dns_plugin_is_caching (NMDnsPlugin *self)
{
	return NM_DNS_PLUGIN_GET_CLASS (self)->is_caching (self);
}

const char *
nm_dns_plugin_get_name (NMDnsPlugin *self)
{
	g_assert (NM_DNS_PLUGIN_GET_CLASS (self)->get_name);
	return NM_DNS_PLUGIN_GET_CLASS (self)->get_name (self);
}

/********************************************/

static void
_clear_pidfile (NMDnsPlugin *self)
{
	NMDnsPluginPrivate *priv = NM_DNS_PLUGIN_GET_PRIVATE (self);

	if (priv->pidfile) {
		unlink (priv->pidfile);
		g_free (priv->pidfile);
		priv->pidfile = NULL;
	}
}

static void
kill_existing (const char *progname, const char *pidfile, const char *kill_match)
{
	glong pid;
	gs_free char *contents = NULL;
	gs_free char *cmdline_contents = NULL;
	guint64 start_time;
	char proc_path[256];
	gs_free_error GError *error = NULL;

	if (!pidfile)
		return;

	if (!kill_match)
		g_return_if_reached ();

	if (!g_file_get_contents (pidfile, &contents, NULL, &error)) {
		if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			return;
		goto out;
	}

	pid = _nm_utils_ascii_str_to_int64 (contents, 10, 2, INT_MAX, -1);
	if (pid == -1)
		goto out;

	start_time = nm_utils_get_start_time_for_pid (pid, NULL, NULL);
	if (start_time == 0)
		goto out;

	nm_sprintf_buf (proc_path, "/proc/%ld/cmdline", pid);
	if (!g_file_get_contents (proc_path, &cmdline_contents, NULL, NULL))
		goto out;

	if (!strstr (cmdline_contents, kill_match))
		goto out;

	nm_utils_kill_process_sync (pid, start_time, SIGKILL, LOGD_DNS,
	                            progname ?: "<dns-process>",
	                            0, 0, 1000);

out:
	unlink (pidfile);
}

static void
watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMDnsPlugin *self = NM_DNS_PLUGIN (user_data);
	NMDnsPluginPrivate *priv = NM_DNS_PLUGIN_GET_PRIVATE (self);

	priv->pid = 0;
	priv->watch_id = 0;
	g_free (priv->progname);
	priv->progname = NULL;

	_clear_pidfile (self);

	g_signal_emit (self, signals[CHILD_QUIT], 0, status);
}

GPid
nm_dns_plugin_child_spawn (NMDnsPlugin *self,
                           const char **argv,
                           const char *pidfile,
                           const char *kill_match)
{
	NMDnsPluginPrivate *priv = NM_DNS_PLUGIN_GET_PRIVATE (self);
	GError *error = NULL;
	char *cmdline;

	g_return_val_if_fail (argv != NULL, 0);
	g_return_val_if_fail (argv[0] != NULL, 0);

	g_warn_if_fail (priv->progname == NULL);
	g_free (priv->progname);
	priv->progname = g_path_get_basename (argv[0]);

	kill_existing (priv->progname, pidfile, kill_match);

	g_warn_if_fail (priv->pidfile == NULL);
	g_clear_pointer (&priv->pidfile, g_free);
	priv->pidfile = g_strdup (pidfile);

	nm_log_info (LOGD_DNS, "DNS: starting %s...", priv->progname);
	cmdline = g_strjoinv (" ", (char **) argv);
	nm_log_dbg (LOGD_DNS, "DNS: command line: %s", cmdline);
	g_free (cmdline);

	priv->pid = 0;
	if (g_spawn_async (NULL, (char **) argv, NULL,
	                   G_SPAWN_DO_NOT_REAP_CHILD,
	                   nm_utils_setpgid, NULL,
	                   &priv->pid,
	                   &error)) {
		nm_log_dbg (LOGD_DNS, "%s started with pid %d", priv->progname, priv->pid);
		priv->watch_id = g_child_watch_add (priv->pid, (GChildWatchFunc) watch_cb, self);
	} else {
		nm_log_warn (LOGD_DNS, "Failed to spawn %s: %s",
		             priv->progname, error->message);
		g_clear_error (&error);
	}

	return priv->pid;
}

gboolean
nm_dns_plugin_child_kill (NMDnsPlugin *self)
{
	NMDnsPluginPrivate *priv = NM_DNS_PLUGIN_GET_PRIVATE (self);

	nm_clear_g_source (&priv->watch_id);

	if (priv->pid) {
		nm_utils_kill_child_sync (priv->pid, SIGTERM, LOGD_DNS, priv->progname, NULL, 1000, 0);
		priv->pid = 0;
		g_free (priv->progname);
		priv->progname = NULL;
	}

	_clear_pidfile (self);

	return TRUE;
}

/********************************************/

static void
nm_dns_plugin_init (NMDnsPlugin *self)
{
}

static void
dispose (GObject *object)
{
	NMDnsPlugin *self = NM_DNS_PLUGIN (object);

	nm_dns_plugin_child_kill (self);

	G_OBJECT_CLASS (nm_dns_plugin_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDnsPlugin *self = NM_DNS_PLUGIN (object);
	NMDnsPluginPrivate *priv = NM_DNS_PLUGIN_GET_PRIVATE (self);

	g_free (priv->progname);
	g_free (priv->pidfile);

	G_OBJECT_CLASS (nm_dns_plugin_parent_class)->finalize (object);
}

static void
nm_dns_plugin_class_init (NMDnsPluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);

	g_type_class_add_private (plugin_class, sizeof (NMDnsPluginPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	plugin_class->is_caching = is_caching;

	/* signals */
	signals[FAILED] =
	    g_signal_new (NM_DNS_PLUGIN_FAILED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  G_STRUCT_OFFSET (NMDnsPluginClass, failed),
	                  NULL, NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);

	signals[CHILD_QUIT] =
	    g_signal_new (NM_DNS_PLUGIN_CHILD_QUIT,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  G_STRUCT_OFFSET (NMDnsPluginClass, child_quit),
	                  NULL, NULL,
	                  g_cclosure_marshal_VOID__INT,
	                  G_TYPE_NONE, 1, G_TYPE_INT);
}

