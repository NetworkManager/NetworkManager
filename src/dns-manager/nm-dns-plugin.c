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

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "nm-default.h"
#include "nm-dns-plugin.h"
#include "NetworkManagerUtils.h"

typedef struct {
	gboolean disposed;

	GPid pid;
	guint32 watch_id;
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
                      const char *hostname)
{
	g_return_val_if_fail (NM_DNS_PLUGIN_GET_CLASS (self)->update != NULL, FALSE);

	return NM_DNS_PLUGIN_GET_CLASS (self)->update (self,
	                                               vpn_configs,
	                                               dev_configs,
	                                               other_configs,
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
kill_existing (const char *progname, const char *pidfile, const char *kill_match)
{
	char *contents = NULL;
	glong pid;
	char *proc_path = NULL;
	char *cmdline_contents = NULL;

	if (!g_file_get_contents (pidfile, &contents, NULL, NULL))
		return;

	pid = strtol (contents, NULL, 10);
	if (pid < 1 || pid > INT_MAX)
		goto out;

	proc_path = g_strdup_printf ("/proc/%ld/cmdline", pid);
	if (!g_file_get_contents (proc_path, &cmdline_contents, NULL, NULL))
		goto out;

	if (strstr (cmdline_contents, kill_match)) {
		if (kill (pid, 0) == 0) {
			nm_log_dbg (LOGD_DNS, "Killing stale %s child process %ld", progname, pid);
			kill (pid, SIGKILL);
		}
		unlink (pidfile);
	}

out:
	g_free (cmdline_contents);
	g_free (proc_path);
	g_free (contents);
}

static void
watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMDnsPlugin *self = NM_DNS_PLUGIN (user_data);
	NMDnsPluginPrivate *priv = NM_DNS_PLUGIN_GET_PRIVATE (self);

	priv->pid = 0;
	g_free (priv->progname);
	priv->progname = NULL;

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

	if (pidfile) {
		g_return_val_if_fail (kill_match != NULL, 0);
		kill_existing (priv->progname, pidfile, kill_match);

		g_free (priv->pidfile);
		priv->pidfile = g_strdup (pidfile);
	}

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
		nm_log_warn (LOGD_DNS, "Failed to spawn %s: (%d) %s",
		             priv->progname, error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	return priv->pid;
}

gboolean
nm_dns_plugin_child_kill (NMDnsPlugin *self)
{
	NMDnsPluginPrivate *priv = NM_DNS_PLUGIN_GET_PRIVATE (self);

	if (priv->watch_id) {
		g_source_remove (priv->watch_id);
		priv->watch_id = 0;
	}

	if (priv->pid) {
		nm_utils_kill_child_sync (priv->pid, SIGTERM, LOGD_DNS, priv->progname, NULL, 1000, 0);
		priv->pid = 0;
		g_free (priv->progname);
		priv->progname = NULL;
	}

	if (priv->pidfile) {
		unlink (priv->pidfile);
		g_free (priv->pidfile);
		priv->pidfile = NULL;
	}

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
	NMDnsPluginPrivate *priv = NM_DNS_PLUGIN_GET_PRIVATE (self);

	if (!priv->disposed) {
		priv->disposed = TRUE;

		nm_dns_plugin_child_kill (self);
	}

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

