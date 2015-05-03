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

#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <arpa/inet.h>

#include <glib.h>
#include <glib-unix.h>


#include "nm-dispatcher-api.h"
#include "nm-dispatcher-utils.h"
#include "nm-glib-compat.h"

#include "nmdbus-dispatcher.h"

static GMainLoop *loop = NULL;
static gboolean debug = FALSE;
static gboolean persist = FALSE;
static guint quit_id;

typedef struct Request Request;

typedef struct {
	GObject parent;

	/* Private data */
	NMDBusDispatcher *dbus_dispatcher;

	Request *current_request;
	GQueue *pending_requests;
} Handler;

typedef struct {
  GObjectClass parent;
} HandlerClass;

GType handler_get_type (void);

#define HANDLER_TYPE         (handler_get_type ())
#define HANDLER(object)      (G_TYPE_CHECK_INSTANCE_CAST ((object), HANDLER_TYPE, Handler))
#define HANDLER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), HANDLER_TYPE, HandlerClass))

G_DEFINE_TYPE(Handler, handler, G_TYPE_OBJECT)

static gboolean
handle_action (NMDBusDispatcher *dbus_dispatcher,
               GDBusMethodInvocation *context,
               const char *str_action,
               GVariant *connection_dict,
               GVariant *connection_props,
               GVariant *device_props,
               GVariant *device_ip4_props,
               GVariant *device_ip6_props,
               GVariant *device_dhcp4_props,
               GVariant *device_dhcp6_props,
               const char *vpn_ip_iface,
               GVariant *vpn_ip4_props,
               GVariant *vpn_ip6_props,
               gboolean request_debug,
               gpointer user_data);

static void
handler_init (Handler *h)
{
	h->pending_requests = g_queue_new ();
	h->dbus_dispatcher = nmdbus_dispatcher_skeleton_new ();
	g_signal_connect (h->dbus_dispatcher, "handle-action",
	                  G_CALLBACK (handle_action), h);
}

static void
handler_class_init (HandlerClass *h_class)
{
}

static void dispatch_one_script (Request *request);

typedef struct {
	Request *request;

	char *script;
	GPid pid;
	DispatchResult result;
	char *error;
} ScriptInfo;

struct Request {
	Handler *handler;

	GDBusMethodInvocation *context;
	char *action;
	char *iface;
	char **envp;
	gboolean debug;

	GPtrArray *scripts;  /* list of ScriptInfo */
	guint idx;

	guint script_watch_id;
	guint script_timeout_id;
};

static void
script_info_free (gpointer ptr)
{
	ScriptInfo *info = ptr;

	g_free (info->script);
	g_free (info->error);
	g_free (info);
}

static void
request_free (Request *request)
{
	g_free (request->action);
	g_free (request->iface);
	g_strfreev (request->envp);
	if (request->scripts)
		g_ptr_array_free (request->scripts, TRUE);
}

static gboolean
quit_timeout_cb (gpointer user_data)
{
	g_main_loop_quit (loop);
	return FALSE;
}

static void
quit_timeout_cancel (void)
{
	if (quit_id) {
		g_source_remove (quit_id);
		quit_id = 0;
	}
}

static void
quit_timeout_reschedule (void)
{
	quit_timeout_cancel ();
	if (!persist)
		quit_id = g_timeout_add_seconds (10, quit_timeout_cb, NULL);
}

static void
start_request (Request *request)
{
	if (request->iface)
		g_message ("Dispatching action '%s' for %s", request->action, request->iface);
	else
		g_message ("Dispatching action '%s'", request->action);

	request->handler->current_request = request;
	dispatch_one_script (request);
}

static void
next_request (Handler *h)
{
	Request *request = g_queue_pop_head (h->pending_requests);

	if (request) {
		start_request (request);
		return;
	}

	h->current_request = NULL;
	quit_timeout_reschedule ();
}

static gboolean
next_script (gpointer user_data)
{
	Request *request = user_data;
	Handler *h = request->handler;
	GVariantBuilder results;
	GVariant *ret;
	guint i;

	request->idx++;
	if (request->idx < request->scripts->len) {
		dispatch_one_script (request);
		return FALSE;
	}

	/* All done */
	g_variant_builder_init (&results, G_VARIANT_TYPE ("a(sus)"));
	for (i = 0; i < request->scripts->len; i++) {
		ScriptInfo *script = g_ptr_array_index (request->scripts, i);

		g_variant_builder_add (&results, "(sus)",
		                       script->script,
		                       script->result,
		                       script->error ? script->error : "");
	}

	ret = g_variant_new ("(a(sus))", &results);
	g_dbus_method_invocation_return_value (request->context, ret);

	if (request->debug) {
		if (request->iface)
			g_message ("Dispatch '%s' on %s complete", request->action, request->iface);
		else
			g_message ("Dispatch '%s' complete", request->action);
	}
	request_free (request);

	next_request (h);
	return FALSE;
}

static void
script_watch_cb (GPid pid, gint status, gpointer user_data)
{
	ScriptInfo *script = user_data;
	guint err;

	g_assert (pid == script->pid);

	script->request->script_watch_id = 0;
	g_source_remove (script->request->script_timeout_id);
	script->request->script_timeout_id = 0;

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
		if (err == 0)
			script->result = DISPATCH_RESULT_SUCCESS;
		else {
			script->error = g_strdup_printf ("Script '%s' exited with error status %d.",
			                                 script->script, err);
		}
	} else if (WIFSTOPPED (status)) {
		script->error = g_strdup_printf ("Script '%s' stopped unexpectedly with signal %d.",
		                                 script->script, WSTOPSIG (status));
	} else if (WIFSIGNALED (status)) {
		script->error = g_strdup_printf ("Script '%s' died with signal %d",
		                                 script->script, WTERMSIG (status));
	} else {
		script->error = g_strdup_printf ("Script '%s' died from an unknown cause",
		                                 script->script);
	}

	if (script->result == DISPATCH_RESULT_SUCCESS) {
		if (script->request->debug)
			g_message ("Script '%s' complete", script->script);
	} else {
		script->result = DISPATCH_RESULT_FAILED;
		g_warning ("%s", script->error);
	}

	g_spawn_close_pid (script->pid);
	next_script (script->request);
}

static gboolean
script_timeout_cb (gpointer user_data)
{
	ScriptInfo *script = user_data;

	g_source_remove (script->request->script_watch_id);
	script->request->script_watch_id = 0;
	script->request->script_timeout_id = 0;

	g_warning ("Script '%s' took too long; killing it.", script->script);

	kill (script->pid, SIGKILL);
again:
	if (waitpid (script->pid, NULL, 0) == -1) {
		if (errno == EINTR)
			goto again;
	}

	script->error = g_strdup_printf ("Script '%s' timed out.", script->script);
	script->result = DISPATCH_RESULT_TIMEOUT;

	g_spawn_close_pid (script->pid);
	g_idle_add (next_script, script->request);
	return FALSE;
}

static inline gboolean
check_permissions (struct stat *s, const char **out_error_msg)
{
	g_return_val_if_fail (s != NULL, FALSE);
	g_return_val_if_fail (out_error_msg != NULL, FALSE);
	g_return_val_if_fail (*out_error_msg == NULL, FALSE);

	/* Only accept regular files */
	if (!S_ISREG (s->st_mode)) {
		*out_error_msg = "not a regular file.";
		return FALSE;
	}

	/* Only accept files owned by root */
	if (s->st_uid != 0) {
		*out_error_msg = "not owned by root.";
		return FALSE;
	}

	/* Only accept files not writable by group or other, and not SUID */
	if (s->st_mode & (S_IWGRP | S_IWOTH | S_ISUID)) {
		*out_error_msg = "writable by group or other, or set-UID.";
		return FALSE;
	}

	/* Only accept files executable by the owner */
	if (!(s->st_mode & S_IXUSR)) {
		*out_error_msg = "not executable by owner.";
		return FALSE;
	}

	return TRUE;
}

static gboolean
check_filename (const char *file_name)
{
	char *bad_suffixes[] = { "~", ".rpmsave", ".rpmorig", ".rpmnew", NULL };
	char *tmp;
	guint i;

	/* File must not be a backup file, package management file, or start with '.' */

	if (file_name[0] == '.')
		return FALSE;
	for (i = 0; bad_suffixes[i]; i++) {
		if (g_str_has_suffix (file_name, bad_suffixes[i]))
			return FALSE;
	}
	tmp = g_strrstr (file_name, ".dpkg-");
	if (tmp && (tmp == strrchr (file_name, '.')))
		return FALSE;
	return TRUE;
}

#define SCRIPT_TIMEOUT 600  /* 10 minutes */

static void
dispatch_one_script (Request *request)
{
	GError *error = NULL;
	gchar *argv[4];
	ScriptInfo *script = g_ptr_array_index (request->scripts, request->idx);

	argv[0] = script->script;
	argv[1] = request->iface ? request->iface : "none";
	argv[2] = request->action;
	argv[3] = NULL;

	if (request->debug)
		g_message ("Running script '%s'", script->script);

	if (g_spawn_async ("/", argv, request->envp, G_SPAWN_DO_NOT_REAP_CHILD, NULL, request, &script->pid, &error)) {
		request->script_watch_id = g_child_watch_add (script->pid, (GChildWatchFunc) script_watch_cb, script);
		request->script_timeout_id = g_timeout_add_seconds (SCRIPT_TIMEOUT, script_timeout_cb, script);
	} else {
		g_warning ("Failed to execute script '%s': (%d) %s",
		           script->script, error->code, error->message);
		script->result = DISPATCH_RESULT_EXEC_FAILED;
		script->error = g_strdup (error->message);
		g_clear_error (&error);

		/* Try the next script */
		g_idle_add (next_script, request);
	}
}

static GSList *
find_scripts (const char *str_action)
{
	GDir *dir;
	const char *filename;
	GSList *sorted = NULL;
	GError *error = NULL;
	const char *dirname;

	if (   strcmp (str_action, NMD_ACTION_PRE_UP) == 0
	    || strcmp (str_action, NMD_ACTION_VPN_PRE_UP) == 0)
		dirname = NMD_SCRIPT_DIR_PRE_UP;
	else if (   strcmp (str_action, NMD_ACTION_PRE_DOWN) == 0
	         || strcmp (str_action, NMD_ACTION_VPN_PRE_DOWN) == 0)
		dirname = NMD_SCRIPT_DIR_PRE_DOWN;
	else
		dirname = NMD_SCRIPT_DIR_DEFAULT;

	if (!(dir = g_dir_open (dirname, 0, &error))) {
		g_message ("Failed to open dispatcher directory '%s': (%d) %s",
		           dirname, error->code, error->message);
		g_error_free (error);
		return NULL;
	}

	while ((filename = g_dir_read_name (dir))) {
		char *path;
		struct stat	st;
		int err;
		const char *err_msg = NULL;

		if (!check_filename (filename))
			continue;

		path = g_build_filename (dirname, filename, NULL);

		err = stat (path, &st);
		if (err)
			g_warning ("Failed to stat '%s': %d", path, err);
		else if (S_ISDIR (st.st_mode))
			; /* silently skip. */
		else if (!check_permissions (&st, &err_msg))
			g_warning ("Cannot execute '%s': %s", path, err_msg);
		else {
			/* success */
			sorted = g_slist_insert_sorted (sorted, path, (GCompareFunc) g_strcmp0);
			path = NULL;
		}
		g_free (path);
	}
	g_dir_close (dir);

	return sorted;
}

static gboolean
handle_action (NMDBusDispatcher *dbus_dispatcher,
               GDBusMethodInvocation *context,
               const char *str_action,
               GVariant *connection_dict,
               GVariant *connection_props,
               GVariant *device_props,
               GVariant *device_ip4_props,
               GVariant *device_ip6_props,
               GVariant *device_dhcp4_props,
               GVariant *device_dhcp6_props,
               const char *vpn_ip_iface,
               GVariant *vpn_ip4_props,
               GVariant *vpn_ip6_props,
               gboolean request_debug,
               gpointer user_data)
{
	Handler *h = user_data;
	GSList *sorted_scripts = NULL;
	GSList *iter;
	Request *request;
	char **p;
	char *iface = NULL;

	sorted_scripts = find_scripts (str_action);

	if (!sorted_scripts) {
		GVariant *results;

		results = g_variant_new_array (G_VARIANT_TYPE ("(sus)"), NULL, 0);
		g_dbus_method_invocation_return_value (context, g_variant_new ("(@a(sus))", results));
		return TRUE;
	}

	quit_timeout_cancel ();

	request = g_malloc0 (sizeof (*request));
	request->handler = h;
	request->debug = request_debug || debug;
	request->context = context;
	request->action = g_strdup (str_action);

	request->envp = nm_dispatcher_utils_construct_envp (str_action,
	                                                    connection_dict,
	                                                    connection_props,
	                                                    device_props,
	                                                    device_ip4_props,
	                                                    device_ip6_props,
	                                                    device_dhcp4_props,
	                                                    device_dhcp6_props,
	                                                    vpn_ip_iface,
	                                                    vpn_ip4_props,
	                                                    vpn_ip6_props,
	                                                    &iface);

	if (request->debug) {
		g_message ("------------ Action ID %p '%s' Interface %s Environment ------------",
		           context, str_action, iface ? iface : "(none)");
		for (p = request->envp; *p; p++)
			g_message ("  %s", *p);
		g_message ("\n");
	}

	request->iface = g_strdup (iface);

	request->scripts = g_ptr_array_new_full (5, script_info_free);
	for (iter = sorted_scripts; iter; iter = g_slist_next (iter)) {
		ScriptInfo *s = g_malloc0 (sizeof (*s));
		s->request = request;
		s->script = iter->data;
		g_ptr_array_add (request->scripts, s);
	}
	g_slist_free (sorted_scripts);

	if (h->current_request)
		g_queue_push_tail (h->pending_requests, request);
	else
		start_request (request);

	return TRUE;
}

static gboolean ever_acquired_name = FALSE;

static void
on_name_acquired (GDBusConnection *connection,
                  const char      *name,
                  gpointer         user_data)
{
	ever_acquired_name = TRUE;
}

static void
on_name_lost (GDBusConnection *connection,
              const char      *name,
              gpointer         user_data)
{
	if (!connection) {
		g_warning ("Could not get the system bus.  Make sure the message bus daemon is running!");
		exit (1);
	} else if (!ever_acquired_name) {
		g_warning ("Could not acquire the " NM_DISPATCHER_DBUS_SERVICE " service.");
		exit (1);
	} else {
		g_message ("Lost the " NM_DISPATCHER_DBUS_SERVICE " name. Exiting");
		exit (0);
	}
}

static void
log_handler (const gchar *log_domain,
             GLogLevelFlags log_level,
             const gchar *message,
             gpointer ignored)
{
	int syslog_priority;	

	switch (log_level) {
	case G_LOG_LEVEL_ERROR:
		syslog_priority = LOG_CRIT;
		break;
	case G_LOG_LEVEL_CRITICAL:
		syslog_priority = LOG_ERR;
		break;
	case G_LOG_LEVEL_WARNING:
		syslog_priority = LOG_WARNING;
		break;
	case G_LOG_LEVEL_MESSAGE:
		syslog_priority = LOG_NOTICE;
		break;
	case G_LOG_LEVEL_DEBUG:
		syslog_priority = LOG_DEBUG;
		break;
	case G_LOG_LEVEL_INFO:
	default:
		syslog_priority = LOG_INFO;
		break;
	}

	syslog (syslog_priority, "%s", message);
}


static void
logging_setup (void)
{
	openlog (G_LOG_DOMAIN, LOG_CONS, LOG_DAEMON);
	g_log_set_handler (G_LOG_DOMAIN, 
	                   G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
	                   log_handler,
	                   NULL);
}

static void
logging_shutdown (void)
{
	closelog ();
}

static gboolean
signal_handler (gpointer user_data)
{
	int signo = GPOINTER_TO_INT (user_data);

	g_message ("Caught signal %d, shutting down...", signo);
	g_main_loop_quit (loop);

	return G_SOURCE_REMOVE;
}

int
main (int argc, char **argv)
{
	GOptionContext *opt_ctx;
	GError *error = NULL;
	GDBusConnection *bus;
	Handler *handler;

	GOptionEntry entries[] = {
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &debug, "Output to console rather than syslog", NULL },
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, "Don't quit after a short timeout", NULL },
		{ NULL }
	};

	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_summary (opt_ctx, "Executes scripts upon actions by NetworkManager.");
	g_option_context_add_main_entries (opt_ctx, entries, NULL);

	if (!g_option_context_parse (opt_ctx, &argc, &argv, &error)) {
		g_warning ("%s\n", error->message);
		g_error_free (error);
		return 1;
	}

	g_option_context_free (opt_ctx);

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	g_unix_signal_add (SIGTERM, signal_handler, GINT_TO_POINTER (SIGTERM));
	g_unix_signal_add (SIGINT, signal_handler, GINT_TO_POINTER (SIGINT));

	if (!debug)
		logging_setup ();

	loop = g_main_loop_new (NULL, FALSE);

	bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
	if (!bus) {
		g_warning ("Could not get the system bus (%s).  Make sure the message bus daemon is running!",
		           error->message);
		g_error_free (error);
		return 1;
	}

	handler = g_object_new (HANDLER_TYPE, NULL);
	g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (handler->dbus_dispatcher),
	                                  bus,
	                                  NM_DISPATCHER_DBUS_PATH,
	                                  &error);
	if (error) {
		g_warning ("Could not export Dispatcher D-Bus interface: %s", error->message);
		g_error_free (error);
		return 1;
	}

	g_bus_own_name_on_connection (bus,
	                              NM_DISPATCHER_DBUS_SERVICE,
	                              G_BUS_NAME_OWNER_FLAGS_NONE,
	                              on_name_acquired,
	                              on_name_lost,
	                              NULL, NULL);
	g_object_unref (bus);

	if (!persist)
		quit_id = g_timeout_add_seconds (10, quit_timeout_cb, NULL);

	g_main_loop_run (loop);

	g_queue_free (handler->pending_requests);
	g_object_unref (handler);

	if (!debug)
		logging_shutdown ();

	return 0;
}

