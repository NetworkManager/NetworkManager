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
#include <glib-unix.h>

#include "nm-dispatcher-api.h"
#include "nm-dispatcher-utils.h"

#include "nmdbus-dispatcher.h"

static GMainLoop *loop = NULL;
static gboolean debug = FALSE;
static gboolean persist = FALSE;
static guint quit_id;
static guint request_id_counter = 0;

typedef struct Request Request;

typedef struct {
	GObject parent;

	/* Private data */
	NMDBusDispatcher *dbus_dispatcher;

	Request *current_request;
	GQueue *requests_waiting;
	gint num_requests_pending;
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
               GVariant *device_proxy_props,
               GVariant *device_ip4_props,
               GVariant *device_ip6_props,
               GVariant *device_dhcp4_props,
               GVariant *device_dhcp6_props,
               const char *connectivity_state,
               const char *vpn_ip_iface,
               GVariant *vpn_proxy_props,
               GVariant *vpn_ip4_props,
               GVariant *vpn_ip6_props,
               gboolean request_debug,
               gpointer user_data);

static void
handler_init (Handler *h)
{
	h->requests_waiting = g_queue_new ();
	h->dbus_dispatcher = nmdbus_dispatcher_skeleton_new ();
	g_signal_connect (h->dbus_dispatcher, "handle-action",
	                  G_CALLBACK (handle_action), h);
}

static void
handler_class_init (HandlerClass *h_class)
{
}

static gboolean dispatch_one_script (Request *request);

typedef struct {
	Request *request;

	char *script;
	GPid pid;
	DispatchResult result;
	char *error;
	gboolean wait;
	gboolean dispatched;
	guint watch_id;
	guint timeout_id;
} ScriptInfo;

struct Request {
	Handler *handler;

	guint request_id;

	GDBusMethodInvocation *context;
	char *action;
	char *iface;
	char **envp;
	gboolean debug;

	GPtrArray *scripts;  /* list of ScriptInfo */
	guint idx;
	gint num_scripts_done;
	gint num_scripts_nowait;
};

/*****************************************************************************/

#define __LOG_print(print_cmd, _request, _script, ...) \
	G_STMT_START { \
		nm_assert ((_request) && (!(_script) || (_script)->request == (_request))); \
		print_cmd ("req:%u '%s'%s%s%s%s%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
		           (_request)->request_id, \
		           (_request)->action, \
		           (_request)->iface ? " [" : "", \
		           (_request)->iface ? (_request)->iface : "", \
		           (_request)->iface ? "]" : "", \
		           (_script) ? ", \"" : "", \
		           (_script) ? (_script)->script : "", \
		           (_script) ? "\"" : "" \
		           _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
	} G_STMT_END

#define _LOG(_request, _script, log_always, print_cmd, ...) \
	G_STMT_START { \
		const Request *__request = (_request); \
		const ScriptInfo *__script = (_script); \
		\
		if (!__request) \
			__request = __script->request; \
		nm_assert (__request && (!__script || __script->request == __request)); \
		if ((log_always) || _LOG_R_D_enabled (__request)) { \
			if (FALSE) { \
				/* g_message() alone does not warn about invalid format. Add a dummy printf() statement to
				 * get a compiler warning about wrong format. */ \
				__LOG_print (printf, __request, __script, __VA_ARGS__); \
			} \
			__LOG_print (print_cmd, __request, __script, __VA_ARGS__); \
		} \
	} G_STMT_END

static gboolean
_LOG_R_D_enabled (const Request *request)
{
	return request->debug;
}

#define _LOG_R_D(_request, ...) _LOG(_request, NULL, FALSE, g_debug,   __VA_ARGS__)
#define _LOG_R_I(_request, ...) _LOG(_request, NULL, TRUE,  g_info,    __VA_ARGS__)
#define _LOG_R_W(_request, ...) _LOG(_request, NULL, TRUE,  g_warning, __VA_ARGS__)

#define _LOG_S_D(_script, ...)  _LOG(NULL, _script,  FALSE, g_debug,   __VA_ARGS__)
#define _LOG_S_I(_script, ...)  _LOG(NULL, _script,  TRUE,  g_info,    __VA_ARGS__)
#define _LOG_S_W(_script, ...)  _LOG(NULL, _script,  TRUE,  g_warning, __VA_ARGS__)

/*****************************************************************************/

static void
script_info_free (gpointer ptr)
{
	ScriptInfo *info = ptr;

	g_free (info->script);
	g_free (info->error);
	g_slice_free (ScriptInfo, info);
}

static void
request_free (Request *request)
{
	g_assert_cmpuint (request->num_scripts_done, ==, request->scripts->len);
	g_assert_cmpuint (request->num_scripts_nowait, ==, 0);

	g_free (request->action);
	g_free (request->iface);
	g_strfreev (request->envp);
	g_ptr_array_free (request->scripts, TRUE);

	g_slice_free (Request, request);
}

static gboolean
quit_timeout_cb (gpointer user_data)
{
	g_main_loop_quit (loop);
	return FALSE;
}

static void
quit_timeout_reschedule (void)
{
	if (!persist) {
		nm_clear_g_source (&quit_id);
		quit_id = g_timeout_add_seconds (10, quit_timeout_cb, NULL);
	}
}

/**
 * next_request:
 *
 * @h: the handler
 * @request: (allow-none): the request to set as next. If %NULL, dequeue the next
 * waiting request. Otherwise, try to set the given request.
 *
 * Sets the currently active request (@current_request). The current request
 * is a request that has at least on "wait" script, because requests that only
 * consist of "no-wait" scripts are handled right away and not enqueued to
 * @requests_waiting nor set as @current_request.
 *
 * Returns: %TRUE, if there was currently not request in process and it set
 * a new request as current.
 */
static gboolean
next_request (Handler *h, Request *request)
{
	if (request) {
		if (h->current_request) {
			g_queue_push_tail (h->requests_waiting, request);
			return FALSE;
		}
	} else {
		/* when calling next_request() without explicit @request, we always
		 * forcefully clear @current_request. That one is certainly
		 * handled already. */
		h->current_request = NULL;

		request = g_queue_pop_head (h->requests_waiting);
		if (!request)
			return FALSE;
	}

	_LOG_R_I (request, "start running ordered scripts...");

	h->current_request = request;

	return TRUE;
}

/**
 * complete_request:
 * @request: the request
 *
 * Checks if all the scripts for the request have terminated and in such case
 * it sends the D-Bus response and releases the request resources.
 *
 * It also decreases @num_requests_pending and possibly does quit_timeout_reschedule().
 */
static void
complete_request (Request *request)
{
	GVariantBuilder results;
	GVariant *ret;
	guint i;
	Handler *handler = request->handler;

	nm_assert (request);

	/* Are there still pending scripts? Then do nothing (for now). */
	if (request->num_scripts_done < request->scripts->len)
		return;

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

	_LOG_R_D (request, "completed (%u scripts)", request->scripts->len);

	if (handler->current_request == request)
		handler->current_request = NULL;

	request_free (request);

	g_assert_cmpuint (handler->num_requests_pending, >, 0);
	if (--handler->num_requests_pending <= 0) {
		nm_assert (!handler->current_request && !g_queue_peek_head (handler->requests_waiting));
		quit_timeout_reschedule ();
	}
}

static void
complete_script (ScriptInfo *script)
{
	Handler *handler;
	Request *request;
	gboolean wait = script->wait;

	request = script->request;

	if (wait) {
		/* for "wait" scripts, try to schedule the next blocking script.
		 * If that is successful, return (as we must wait for its completion). */
		if (dispatch_one_script (request))
			return;
	}

	handler = request->handler;

	nm_assert (!wait || handler->current_request == request);

	/* Try to complete the request. @request will be possibly free'd,
	 * making @script and @request a dangling pointer. */
	complete_request (request);

	if (!wait) {
		/* this was a "no-wait" script. We either completed the request,
		 * or there is nothing to do. Especially, there is no need to
		 * queue the next_request() -- because no-wait scripts don't block
		 * requests. However, if this was the last "no-wait" script and
		 * there are "wait" scripts ready to run, launch them.
		 */
		if (   handler->current_request == request
		    && handler->current_request->num_scripts_nowait == 0) {

			if (dispatch_one_script (handler->current_request))
				return;

			complete_request (handler->current_request);
		} else
			return;
	} else {
		/* if the script is a "wait" script, we already tried above to
		 * dispatch the next script. As we didn't do that, it means we
		 * just completed the last script of @request and we can continue
		 * with the next request...
		 *
		 * Also, it cannot be that there is another request currently being
		 * processed because only requests with "wait" scripts can become
		 * @current_request. As there can only be one "wait" script running
		 * at any time, it means complete_request() above completed @request. */
		nm_assert (!handler->current_request);
	}

	while (next_request (handler, NULL)) {
		request = handler->current_request;

		if (dispatch_one_script (request))
			return;

		/* Try to complete the request. It will be either completed
		 * now, or when all pending "no-wait" scripts return. */
		complete_request (request);

		/* We can immediately start next_request(), because our current
		 * @request has obviously no more "wait" scripts either.
		 * Repeat... */
	}
}

static void
script_watch_cb (GPid pid, gint status, gpointer user_data)
{
	ScriptInfo *script = user_data;
	guint err;

	g_assert (pid == script->pid);

	script->watch_id = 0;
	nm_clear_g_source (&script->timeout_id);
	script->request->num_scripts_done++;
	if (!script->wait)
		script->request->num_scripts_nowait--;

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
		_LOG_S_D (script, "complete");
	} else {
		script->result = DISPATCH_RESULT_FAILED;
		_LOG_S_W (script, "complete: failed with %s", script->error);
	}

	g_spawn_close_pid (script->pid);

	complete_script (script);
}

static gboolean
script_timeout_cb (gpointer user_data)
{
	ScriptInfo *script = user_data;

	script->timeout_id = 0;
	nm_clear_g_source (&script->watch_id);
	script->request->num_scripts_done++;
	if (!script->wait)
		script->request->num_scripts_nowait--;

	_LOG_S_W (script, "complete: timeout (kill script)");

	kill (script->pid, SIGKILL);
again:
	if (waitpid (script->pid, NULL, 0) == -1) {
		if (errno == EINTR)
			goto again;
	}

	script->error = g_strdup_printf ("Script '%s' timed out.", script->script);
	script->result = DISPATCH_RESULT_TIMEOUT;

	g_spawn_close_pid (script->pid);

	complete_script (script);

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
	static const char *bad_suffixes[] = {
		"~",
		".rpmsave",
		".rpmorig",
		".rpmnew",
		".swp",
	};
	char *tmp;
	guint i;

	/* File must not be a backup file, package management file, or start with '.' */

	if (file_name[0] == '.')
		return FALSE;
	for (i = 0; i < G_N_ELEMENTS (bad_suffixes); i++) {
		if (g_str_has_suffix (file_name, bad_suffixes[i]))
			return FALSE;
	}
	tmp = g_strrstr (file_name, ".dpkg-");
	if (tmp && !strchr (&tmp[1], '.'))
		return FALSE;
	return TRUE;
}

#define SCRIPT_TIMEOUT 600  /* 10 minutes */

static gboolean
script_dispatch (ScriptInfo *script)
{
	GError *error = NULL;
	gchar *argv[4];
	Request *request = script->request;

	if (script->dispatched)
		return FALSE;

	script->dispatched = TRUE;

	argv[0] = script->script;
	argv[1] = request->iface
	          ? request->iface
	          : (!strcmp (request->action, NMD_ACTION_HOSTNAME) ? "none" : "");
	argv[2] = request->action;
	argv[3] = NULL;

	_LOG_S_D (script, "run script%s", script->wait ? "" : " (no-wait)");

	if (g_spawn_async ("/", argv, request->envp, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &script->pid, &error)) {
		script->watch_id = g_child_watch_add (script->pid, (GChildWatchFunc) script_watch_cb, script);
		script->timeout_id = g_timeout_add_seconds (SCRIPT_TIMEOUT, script_timeout_cb, script);
		if (!script->wait)
			request->num_scripts_nowait++;
		return TRUE;
	} else {
		_LOG_S_W (script, "complete: failed to execute script: %s", error->message);
		script->result = DISPATCH_RESULT_EXEC_FAILED;
		script->error = g_strdup (error->message);
		request->num_scripts_done++;
		g_clear_error (&error);
		return FALSE;
	}
}

static gboolean
dispatch_one_script (Request *request)
{
	if (request->num_scripts_nowait > 0)
		return TRUE;

	while (request->idx < request->scripts->len) {
		ScriptInfo *script;

		script = g_ptr_array_index (request->scripts, request->idx++);
		if (script_dispatch (script))
			return TRUE;
	}
	return FALSE;
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
		g_message ("find-scripts: Failed to open dispatcher directory '%s': %s",
		           dirname, error->message);
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
			g_warning ("find-scripts: Failed to stat '%s': %d", path, err);
		else if (S_ISDIR (st.st_mode))
			; /* silently skip. */
		else if (!check_permissions (&st, &err_msg))
			g_warning ("find-scripts: Cannot execute '%s': %s", path, err_msg);
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
script_must_wait (const char *path)
{
	gs_free char *link = NULL;
	gs_free char *dir = NULL;
	gs_free char *real = NULL;
	char *tmp;

	link = g_file_read_link (path, NULL);
	if (link) {
		if (!g_path_is_absolute (link)) {
			dir = g_path_get_dirname (path);
			tmp = g_build_path ("/", dir, link, NULL);
			g_free (link);
			g_free (dir);
			link = tmp;
		}

		dir = g_path_get_dirname (link);
		real = realpath (dir, NULL);

		if (real && !strcmp (real, NMD_SCRIPT_DIR_NO_WAIT))
			return FALSE;
	}

	return TRUE;
}

static gboolean
handle_action (NMDBusDispatcher *dbus_dispatcher,
               GDBusMethodInvocation *context,
               const char *str_action,
               GVariant *connection_dict,
               GVariant *connection_props,
               GVariant *device_props,
               GVariant *device_proxy_props,
               GVariant *device_ip4_props,
               GVariant *device_ip6_props,
               GVariant *device_dhcp4_props,
               GVariant *device_dhcp6_props,
               const char *connectivity_state,
               const char *vpn_ip_iface,
               GVariant *vpn_proxy_props,
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
	guint i, num_nowait = 0;
	const char *error_message = NULL;

	sorted_scripts = find_scripts (str_action);

	request = g_slice_new0 (Request);
	request->request_id = ++request_id_counter;
	request->handler = h;
	request->debug = request_debug || debug;
	request->context = context;
	request->action = g_strdup (str_action);

	request->envp = nm_dispatcher_utils_construct_envp (str_action,
	                                                    connection_dict,
	                                                    connection_props,
	                                                    device_props,
	                                                    device_proxy_props,
	                                                    device_ip4_props,
	                                                    device_ip6_props,
	                                                    device_dhcp4_props,
	                                                    device_dhcp6_props,
	                                                    connectivity_state,
	                                                    vpn_ip_iface,
	                                                    vpn_proxy_props,
	                                                    vpn_ip4_props,
	                                                    vpn_ip6_props,
	                                                    &request->iface,
	                                                    &error_message);

	request->scripts = g_ptr_array_new_full (5, script_info_free);
	for (iter = sorted_scripts; iter; iter = g_slist_next (iter)) {
		ScriptInfo *s;

		s = g_slice_new0 (ScriptInfo);
		s->request = request;
		s->script = iter->data;
		s->wait = script_must_wait (s->script);
		g_ptr_array_add (request->scripts, s);
	}
	g_slist_free (sorted_scripts);

	_LOG_R_I (request, "new request (%u scripts)", request->scripts->len);
	if (   _LOG_R_D_enabled (request)
	    && request->envp) {
		for (p = request->envp; *p; p++)
			_LOG_R_D (request, "environment: %s", *p);
	}

	if (error_message || request->scripts->len == 0) {
		GVariant *results;

		if (error_message)
			_LOG_R_W (request, "completed: invalid request: %s", error_message);
		else
			_LOG_R_I (request, "completed: no scripts");

		results = g_variant_new_array (G_VARIANT_TYPE ("(sus)"), NULL, 0);
		g_dbus_method_invocation_return_value (context, g_variant_new ("(@a(sus))", results));
		request->num_scripts_done = request->scripts->len;
		request_free (request);
		return TRUE;
	}

	nm_clear_g_source (&quit_id);

	h->num_requests_pending++;

	for (i = 0; i < request->scripts->len; i++) {
		ScriptInfo *s = g_ptr_array_index (request->scripts, i);

		if (!s->wait) {
			script_dispatch (s);
			num_nowait++;
		}
	}

	if (num_nowait < request->scripts->len) {
		/* The request has at least one wait script.
		 * Try next_request() to schedule the request for
		 * execution. This either enqueues the request or
		 * sets it as h->current_request. */
		if (next_request (h, request)) {
			/* @request is now @current_request. Go ahead and
			 * schedule the first wait script. */
			if (!dispatch_one_script (request)) {
				/* If that fails, we might be already finished with the
				 * request. Try complete_request(). */
				complete_request (request);

				if (next_request (h, NULL)) {
					/* As @request was successfully scheduled as next_request(), there is no
					 * other request in queue that can be scheduled afterwards. Assert against
					 * that, but call next_request() to clear current_request. */
					g_assert_not_reached ();
				}
			}
		}
	} else {
		/* The request contains only no-wait scripts. Try to complete
		 * the request right away (we might have failed to schedule any
		 * of the scripts). It will be either completed now, or later
		 * when the pending scripts return.
		 * We don't enqueue it to h->requests_waiting.
		 * There is no need to handle next_request(), because @request is
		 * not the current request anyway and does not interfere with requests
		 * that have any "wait" scripts. */
		complete_request (request);
	}

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
		if (!ever_acquired_name) {
			g_warning ("Could not get the system bus.  Make sure the message bus daemon is running!");
			exit (1);
		} else {
			g_message ("System bus stopped. Exiting");
			exit (0);
		}
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
		g_warning ("Error parsing command line arguments: %s", error->message);
		g_error_free (error);
		return 1;
	}

	g_option_context_free (opt_ctx);

	nm_g_type_init ();

	g_unix_signal_add (SIGTERM, signal_handler, GINT_TO_POINTER (SIGTERM));
	g_unix_signal_add (SIGINT, signal_handler, GINT_TO_POINTER (SIGINT));


	if (debug) {
		if (!g_getenv ("G_MESSAGES_DEBUG")) {
			/* we log our regular messages using g_debug() and g_info().
			 * When we redirect glib logging to syslog, there is no problem.
			 * But in "debug" mode, glib will no print these messages unless
			 * we set G_MESSAGES_DEBUG. */
			g_setenv ("G_MESSAGES_DEBUG", "all", TRUE);
		}
	} else
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

	quit_timeout_reschedule ();

	g_main_loop_run (loop);

	g_queue_free (handler->requests_waiting);
	g_object_unref (handler);

	if (!debug)
		logging_shutdown ();

	return 0;
}

