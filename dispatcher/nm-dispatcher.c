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
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <glib-unix.h>

#include "nm-libnm-core-aux/nm-dispatcher-api.h"
#include "nm-dispatcher-utils.h"

/*****************************************************************************/

typedef struct Request Request;

static struct {
	GDBusConnection *dbus_connection;
	GMainLoop *loop;
	gboolean debug;
	gboolean persist;
	guint quit_id;
	guint request_id_counter;
	gboolean ever_acquired_name;
	bool exit_with_failure;

	Request *current_request;
	GQueue *requests_waiting;
	int num_requests_pending;
} gl;

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
	guint request_id;

	GDBusMethodInvocation *context;
	char *action;
	char *iface;
	char **envp;
	gboolean debug;

	GPtrArray *scripts;  /* list of ScriptInfo */
	guint idx;
	int num_scripts_done;
	int num_scripts_nowait;
};

/*****************************************************************************/

#define __LOG_print(print_cmd, ...) \
	G_STMT_START { \
		if (FALSE) { \
			/* g_message() alone does not warn about invalid format. Add a dummy printf() statement to
			 * get a compiler warning about wrong format. */ \
			printf (__VA_ARGS__); \
		} \
		print_cmd (__VA_ARGS__); \
	} G_STMT_END

#define __LOG_print_R(print_cmd, _request, ...) \
	G_STMT_START { \
		__LOG_print (print_cmd, \
		             "req:%u '%s'%s%s%s" _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
		             (_request)->request_id, \
		             (_request)->action, \
		             (_request)->iface ? " [" : "", \
		             (_request)->iface ?: "", \
		             (_request)->iface ? "]" : "" \
		             _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
	} G_STMT_END

#define __LOG_print_S(print_cmd, _request, _script, ...) \
	G_STMT_START { \
		__LOG_print_R (print_cmd, \
		               (_request), \
		               "%s%s%s" _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
		               (_script) ? ", \"" : "", \
		               (_script) ? (_script)->script : "", \
		               (_script) ? "\"" : "" \
		               _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
	} G_STMT_END

#define _LOG_X_(enabled_cmd, print_cmd, ...) \
	G_STMT_START { \
		if (enabled_cmd) \
			__LOG_print (print_cmd, __VA_ARGS__); \
	} G_STMT_END

#define _LOG_R_(enabled_cmd, x_request, print_cmd, ...) \
	G_STMT_START { \
		const Request *const _request = (x_request); \
		\
		nm_assert (_request); \
		if (enabled_cmd) \
			__LOG_print_R (print_cmd, _request, ": "__VA_ARGS__); \
	} G_STMT_END

#define _LOG_S_(enabled_cmd, x_script, print_cmd, ...) \
	G_STMT_START { \
		const ScriptInfo *const _script = (x_script); \
		const Request *const _request = _script ? _script->request : NULL; \
		\
		nm_assert (_script && _request); \
		if (enabled_cmd) \
			__LOG_print_S (print_cmd, _request, _script, ": "__VA_ARGS__); \
	} G_STMT_END

#define _LOG_X_D_enabled() (gl.debug)
#define _LOG_X_T_enabled() _LOG_X_D_enabled ()

#define _LOG_R_D_enabled(request) (_NM_ENSURE_TYPE_CONST (Request *, request)->debug)
#define _LOG_R_T_enabled(request) _LOG_R_D_enabled (request)

#define _LOG_X_T(...)          _LOG_X_ (_LOG_X_T_enabled (),                  g_debug,   __VA_ARGS__)
#define _LOG_X_D(...)          _LOG_X_ (_LOG_X_D_enabled (),                  g_info,    __VA_ARGS__)
#define _LOG_X_I(...)          _LOG_X_ (TRUE,                                 g_message, __VA_ARGS__)
#define _LOG_X_W(...)          _LOG_X_ (TRUE,                                 g_warning, __VA_ARGS__)

#define _LOG_R_T(request, ...) _LOG_R_ (_LOG_R_T_enabled (_request), request, g_debug,   __VA_ARGS__)
#define _LOG_R_D(request, ...) _LOG_R_ (_LOG_R_D_enabled (_request), request, g_info,    __VA_ARGS__)
#define _LOG_R_W(request, ...) _LOG_R_ (TRUE,                        request, g_warning, __VA_ARGS__)

#define _LOG_S_T(script, ...)  _LOG_S_ (_LOG_R_T_enabled (_request), script,  g_debug,   __VA_ARGS__)
#define _LOG_S_D(script, ...)  _LOG_S_ (_LOG_R_D_enabled (_request), script,  g_info,    __VA_ARGS__)
#define _LOG_S_W(script, ...)  _LOG_S_ (TRUE,                        script,  g_warning, __VA_ARGS__)

/*****************************************************************************/

static gboolean dispatch_one_script (Request *request);

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
	gl.quit_id = 0;
	g_main_loop_quit (gl.loop);
	return G_SOURCE_REMOVE;
}

static void
quit_timeout_reschedule (void)
{
	if (!gl.persist) {
		nm_clear_g_source (&gl.quit_id);
		gl.quit_id = g_timeout_add_seconds (10, quit_timeout_cb, NULL);
	}
}

/**
 * next_request:
 *
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
next_request (Request *request)
{
	if (request) {
		if (gl.current_request) {
			g_queue_push_tail (gl.requests_waiting, request);
			return FALSE;
		}
	} else {
		/* when calling next_request() without explicit @request, we always
		 * forcefully clear @current_request. That one is certainly
		 * handled already. */
		gl.current_request = NULL;

		request = g_queue_pop_head (gl.requests_waiting);
		if (!request)
			return FALSE;
	}

	_LOG_R_D (request, "start running ordered scripts...");

	gl.current_request = request;

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
		                       script->error ?: "");
	}

	ret = g_variant_new ("(a(sus))", &results);
	g_dbus_method_invocation_return_value (request->context, ret);

	_LOG_R_T (request, "completed (%u scripts)", request->scripts->len);

	if (gl.current_request == request)
		gl.current_request = NULL;

	request_free (request);

	g_assert_cmpuint (gl.num_requests_pending, >, 0);
	if (--gl.num_requests_pending <= 0) {
		nm_assert (!gl.current_request && !g_queue_peek_head (gl.requests_waiting));
		quit_timeout_reschedule ();
	}
}

static void
complete_script (ScriptInfo *script)
{
	Request *request;
	gboolean wait = script->wait;

	request = script->request;

	if (wait) {
		/* for "wait" scripts, try to schedule the next blocking script.
		 * If that is successful, return (as we must wait for its completion). */
		if (dispatch_one_script (request))
			return;
	}

	nm_assert (!wait || gl.current_request == request);

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
		if (   gl.current_request == request
		    && gl.current_request->num_scripts_nowait == 0) {

			if (dispatch_one_script (gl.current_request))
				return;

			complete_request (gl.current_request);
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
		nm_assert (!gl.current_request);
	}

	while (next_request (NULL)) {
		request = gl.current_request;

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
script_watch_cb (GPid pid, int status, gpointer user_data)
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
		_LOG_S_T (script, "complete");
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

static gboolean
check_permissions (struct stat *s, const char **out_error_msg)
{
	g_return_val_if_fail (s != NULL, FALSE);
	g_return_val_if_fail (out_error_msg != NULL, FALSE);
	g_return_val_if_fail (*out_error_msg == NULL, FALSE);

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
	char *argv[4];
	Request *request = script->request;

	if (script->dispatched)
		return FALSE;

	script->dispatched = TRUE;

	argv[0] = script->script;
	argv[1] = request->iface ?: (!strcmp(request->action, NMD_ACTION_HOSTNAME) ? "none" : "");
	argv[2] = request->action;
	argv[3] = NULL;

	_LOG_S_T (script, "run script%s", script->wait ? "" : " (no-wait)");

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

static int
_compare_basenames (gconstpointer a, gconstpointer b)
{
	const char *basename_a = strrchr (a, '/');
	const char *basename_b = strrchr (b, '/');
	int ret;

	nm_assert (basename_a);
	nm_assert (basename_b);

	ret = strcmp (++basename_a, ++basename_b);
	if (ret)
		return ret;

	nm_assert_not_reached ();
	return 0;
}

static void
_find_scripts (Request *request, GHashTable *scripts, const char *base, const char *subdir)
{
	const char *filename;
	gs_free char *dirname = NULL;
	GError *error = NULL;
	GDir *dir;

	dirname = g_build_filename (base, "dispatcher.d", subdir, NULL);

	if (!(dir = g_dir_open (dirname, 0, &error))) {
		if (!g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			_LOG_R_W (request, "find-scripts: Failed to open dispatcher directory '%s': %s",
			          dirname, error->message);
		}
		g_error_free (error);
		return;
	}

	while ((filename = g_dir_read_name (dir))) {
		if (!check_filename (filename))
			continue;

		g_hash_table_insert (scripts,
		                     g_strdup (filename),
		                     g_build_filename (dirname, filename, NULL));
	}

	g_dir_close (dir);
}

static GSList *
find_scripts (Request *request)
{
	gs_unref_hashtable GHashTable *scripts = NULL;
	GSList *script_list = NULL;
	GHashTableIter iter;
	const char *subdir;
	char *path;
	char *filename;

	if (NM_IN_STRSET (request->action, NMD_ACTION_PRE_UP,
	                                   NMD_ACTION_VPN_PRE_UP))
		subdir = "pre-up.d";
	else if (NM_IN_STRSET (request->action, NMD_ACTION_PRE_DOWN,
	                                        NMD_ACTION_VPN_PRE_DOWN))
		subdir = "pre-down.d";
	else
		subdir = NULL;

	scripts = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	_find_scripts (request, scripts, NMLIBDIR, subdir);
	_find_scripts (request, scripts, NMCONFDIR, subdir);

	g_hash_table_iter_init (&iter, scripts);
	while (g_hash_table_iter_next (&iter, (gpointer *) &filename, (gpointer *) &path)) {
		struct stat st;
		char *link_target;
		int err;
		const char *err_msg = NULL;

		link_target = g_file_read_link (path, NULL);
		if (g_strcmp0 (link_target, "/dev/null") == 0) {
			g_free (link_target);
			continue;
		}
		g_free (link_target);

		err = stat (path, &st);
		if (err)
			_LOG_R_W (request, "find-scripts: Failed to stat '%s': %d", path, err);
		else if (!S_ISREG (st.st_mode))
			; /* silently skip. */
		else if (!check_permissions (&st, &err_msg))
			_LOG_R_W (request, "find-scripts: Cannot execute '%s': %s", path, err_msg);
		else {
			/* success */
			script_list = g_slist_prepend (script_list, g_strdup (path));
			continue;
		}
	}

	return g_slist_sort (script_list, _compare_basenames);
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
		if (real && !g_str_has_suffix (real, "/no-wait.d"))
			return FALSE;
	}

	return TRUE;
}

static void
_method_call_action (GDBusMethodInvocation *invocation,
                     GVariant *parameters)
{
	const char *action;
	gs_unref_variant GVariant *connection = NULL;
	gs_unref_variant GVariant *connection_properties = NULL;
	gs_unref_variant GVariant *device_properties = NULL;
	gs_unref_variant GVariant *device_proxy_properties = NULL;
	gs_unref_variant GVariant *device_ip4_config = NULL;
	gs_unref_variant GVariant *device_ip6_config = NULL;
	gs_unref_variant GVariant *device_dhcp4_config = NULL;
	gs_unref_variant GVariant *device_dhcp6_config = NULL;
	const char *connectivity_state;
	const char *vpn_ip_iface;
	gs_unref_variant GVariant *vpn_proxy_properties = NULL;
	gs_unref_variant GVariant *vpn_ip4_config = NULL;
	gs_unref_variant GVariant *vpn_ip6_config = NULL;
	gboolean debug;
	GSList *sorted_scripts = NULL;
	GSList *iter;
	Request *request;
	char **p;
	guint i, num_nowait = 0;
	const char *error_message = NULL;

	g_variant_get (parameters, "("
	               "&s"         /* action */
	               "@a{sa{sv}}" /* connection */
	               "@a{sv}"     /* connection_properties */
	               "@a{sv}"     /* device_properties */
	               "@a{sv}"     /* device_proxy_properties */
	               "@a{sv}"     /* device_ip4_config */
	               "@a{sv}"     /* device_ip6_config */
	               "@a{sv}"     /* device_dhcp4_config */
	               "@a{sv}"     /* device_dhcp6_config */
	               "&s"         /* connectivity_state */
	               "&s"         /* vpn_ip_iface */
	               "@a{sv}"     /* vpn_proxy_properties */
	               "@a{sv}"     /* vpn_ip4_config */
	               "@a{sv}"     /* vpn_ip6_config */
	               "b"          /* debug */
	               ")",
	               &action,
	               &connection,
	               &connection_properties,
	               &device_properties,
	               &device_proxy_properties,
	               &device_ip4_config,
	               &device_ip6_config,
	               &device_dhcp4_config,
	               &device_dhcp6_config,
	               &connectivity_state,
	               &vpn_ip_iface,
	               &vpn_proxy_properties,
	               &vpn_ip4_config,
	               &vpn_ip6_config,
	               &debug);

	request = g_slice_new0 (Request);
	request->request_id = ++gl.request_id_counter;
	request->debug = debug || gl.debug;
	request->context = invocation;
	request->action = g_strdup (action);

	request->envp = nm_dispatcher_utils_construct_envp (action,
	                                                    connection,
	                                                    connection_properties,
	                                                    device_properties,
	                                                    device_proxy_properties,
	                                                    device_ip4_config,
	                                                    device_ip6_config,
	                                                    device_dhcp4_config,
	                                                    device_dhcp6_config,
	                                                    connectivity_state,
	                                                    vpn_ip_iface,
	                                                    vpn_proxy_properties,
	                                                    vpn_ip4_config,
	                                                    vpn_ip6_config,
	                                                    &request->iface,
	                                                    &error_message);

	request->scripts = g_ptr_array_new_full (5, script_info_free);

	sorted_scripts = find_scripts (request);
	for (iter = sorted_scripts; iter; iter = g_slist_next (iter)) {
		ScriptInfo *s;

		s = g_slice_new0 (ScriptInfo);
		s->request = request;
		s->script = iter->data;
		s->wait = script_must_wait (s->script);
		g_ptr_array_add (request->scripts, s);
	}
	g_slist_free (sorted_scripts);

	_LOG_R_D (request, "new request (%u scripts)", request->scripts->len);
	if (   _LOG_R_T_enabled (request)
	    && request->envp) {
		for (p = request->envp; *p; p++)
			_LOG_R_T (request, "environment: %s", *p);
	}

	if (error_message || request->scripts->len == 0) {
		GVariant *results;

		if (error_message)
			_LOG_R_W (request, "completed: invalid request: %s", error_message);
		else
			_LOG_R_D (request, "completed: no scripts");

		results = g_variant_new_array (G_VARIANT_TYPE ("(sus)"), NULL, 0);
		g_dbus_method_invocation_return_value (invocation, g_variant_new ("(@a(sus))", results));
		request->num_scripts_done = request->scripts->len;
		request_free (request);
		return;
	}

	nm_clear_g_source (&gl.quit_id);

	gl.num_requests_pending++;

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
		 * sets it as gl.current_request. */
		if (next_request (request)) {
			/* @request is now @current_request. Go ahead and
			 * schedule the first wait script. */
			if (!dispatch_one_script (request)) {
				/* If that fails, we might be already finished with the
				 * request. Try complete_request(). */
				complete_request (request);

				if (next_request (NULL)) {
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
		 * We don't enqueue it to gl.requests_waiting.
		 * There is no need to handle next_request(), because @request is
		 * not the current request anyway and does not interfere with requests
		 * that have any "wait" scripts. */
		complete_request (request);
	}
}

static void
on_name_acquired (GDBusConnection *connection,
                  const char      *name,
                  gpointer         user_data)
{
	gl.ever_acquired_name = TRUE;
}

static void
on_name_lost (GDBusConnection *connection,
              const char      *name,
              gpointer         user_data)
{
	if (!connection) {
		if (!gl.ever_acquired_name) {
			_LOG_X_W ("Could not get the system bus.  Make sure the message bus daemon is running!");
			gl.exit_with_failure = TRUE;
		} else {
			_LOG_X_I ("System bus stopped. Exiting");
		}
	} else if (!gl.ever_acquired_name) {
		_LOG_X_W ("Could not acquire the " NM_DISPATCHER_DBUS_SERVICE " service.");
		gl.exit_with_failure = TRUE;
	} else
		_LOG_X_I ("Lost the " NM_DISPATCHER_DBUS_SERVICE " name. Exiting");

	g_main_loop_quit (gl.loop);
}

static void
_method_call (GDBusConnection *connection,
              const char *sender,
              const char *object_path,
              const char *interface_name,
              const char *method_name,
              GVariant *parameters,
              GDBusMethodInvocation *invocation,
              gpointer user_data)
{
	if (nm_streq (interface_name, NM_DISPATCHER_DBUS_INTERFACE)) {
		if (nm_streq (method_name, "Action")) {
			_method_call_action (invocation, parameters);
			return;
		}
	}
	g_dbus_method_invocation_return_error (invocation,
	                                       G_DBUS_ERROR,
	                                       G_DBUS_ERROR_UNKNOWN_METHOD,
	                                       "Unknown method %s",
	                                       method_name);
}

static GDBusInterfaceInfo *const interface_info = NM_DEFINE_GDBUS_INTERFACE_INFO (
	NM_DISPATCHER_DBUS_INTERFACE,
	.methods = NM_DEFINE_GDBUS_METHOD_INFOS (
		NM_DEFINE_GDBUS_METHOD_INFO (
			"Action",
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("action", "s"),
				NM_DEFINE_GDBUS_ARG_INFO ("connection", "a{sa{sv}}"),
				NM_DEFINE_GDBUS_ARG_INFO ("connection_properties", "a{sv}"),
				NM_DEFINE_GDBUS_ARG_INFO ("device_properties", "a{sv}"),
				NM_DEFINE_GDBUS_ARG_INFO ("device_proxy_properties", "a{sv}"),
				NM_DEFINE_GDBUS_ARG_INFO ("device_ip4_config", "a{sv}"),
				NM_DEFINE_GDBUS_ARG_INFO ("device_ip6_config", "a{sv}"),
				NM_DEFINE_GDBUS_ARG_INFO ("device_dhcp4_config", "a{sv}"),
				NM_DEFINE_GDBUS_ARG_INFO ("device_dhcp6_config", "a{sv}"),
				NM_DEFINE_GDBUS_ARG_INFO ("connectivity_state", "s"),
				NM_DEFINE_GDBUS_ARG_INFO ("vpn_ip_iface", "s"),
				NM_DEFINE_GDBUS_ARG_INFO ("vpn_proxy_properties", "a{sv}"),
				NM_DEFINE_GDBUS_ARG_INFO ("vpn_ip4_config", "a{sv}"),
				NM_DEFINE_GDBUS_ARG_INFO ("vpn_ip6_config", "a{sv}"),
				NM_DEFINE_GDBUS_ARG_INFO ("debug", "b"),
			),
			.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("results", "a(sus)"),
			),
		),
	),
);

static const GDBusInterfaceVTable interface_vtable = {
	.method_call = _method_call,
};

/*****************************************************************************/

static void
log_handler (const char *log_domain,
             GLogLevelFlags log_level,
             const char *message,
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

	_LOG_X_I ("Caught signal %d, shutting down...", signo);
	g_main_loop_quit (gl.loop);

	return G_SOURCE_CONTINUE;
}

static gboolean
parse_command_line (int *p_argc,
                    char ***p_argv,
                    GError **error)
{
	GOptionContext *opt_ctx;
	GOptionEntry entries[] = {
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &gl.debug, "Output to console rather than syslog", NULL },
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &gl.persist, "Don't quit after a short timeout", NULL },
		{ NULL }
	};
	gboolean success;

	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_summary (opt_ctx, "Executes scripts upon actions by NetworkManager.");
	g_option_context_add_main_entries (opt_ctx, entries, NULL);

	success = g_option_context_parse (opt_ctx, p_argc, p_argv, error);

	g_option_context_free (opt_ctx);

	return success;
}

int
main (int argc, char **argv)
{
	gs_free_error GError *error = NULL;
	guint signal_id_term = 0;
	guint signal_id_int = 0;
	guint dbus_regist_id = 0;
	guint dbus_own_name_id = 0;

	if (!parse_command_line (&argc, &argv, &error)) {
		_LOG_X_W ("Error parsing command line arguments: %s", error->message);
		gl.exit_with_failure = TRUE;
		goto done;
	}

	signal_id_term = g_unix_signal_add (SIGTERM, signal_handler, GINT_TO_POINTER (SIGTERM));
	signal_id_int  = g_unix_signal_add (SIGINT,  signal_handler, GINT_TO_POINTER (SIGINT));

	if (gl.debug) {
		if (!g_getenv ("G_MESSAGES_DEBUG")) {
			/* we log our regular messages using g_debug() and g_info().
			 * When we redirect glib logging to syslog, there is no problem.
			 * But in "debug" mode, glib will no print these messages unless
			 * we set G_MESSAGES_DEBUG. */
			g_setenv ("G_MESSAGES_DEBUG", "all", TRUE);
		}
	} else
		logging_setup ();

	gl.loop = g_main_loop_new (NULL, FALSE);

	gl.dbus_connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
	if (!gl.dbus_connection) {
		_LOG_X_W ("Could not get the system bus (%s).  Make sure the message bus daemon is running!",
		          error->message);
		gl.exit_with_failure = TRUE;
		goto done;
	}

	gl.requests_waiting = g_queue_new ();

	dbus_regist_id = g_dbus_connection_register_object (gl.dbus_connection,
	                                                    NM_DISPATCHER_DBUS_PATH,
	                                                    interface_info,
	                                                    NM_UNCONST_PTR (GDBusInterfaceVTable, &interface_vtable),
	                                                    NULL,
	                                                    NULL,
	                                                    &error);
	if (dbus_regist_id == 0) {
		_LOG_X_W ("Could not export Dispatcher D-Bus interface: %s", error->message);
		gl.exit_with_failure = 1;
		goto done;
	}

	dbus_own_name_id = g_bus_own_name_on_connection (gl.dbus_connection,
	                                                 NM_DISPATCHER_DBUS_SERVICE,
	                                                 G_BUS_NAME_OWNER_FLAGS_NONE,
	                                                 on_name_acquired,
	                                                 on_name_lost,
	                                                 NULL, NULL);

	quit_timeout_reschedule ();

	g_main_loop_run (gl.loop);

done:

	if (gl.num_requests_pending > 0) {
		/* this only happens when we quit due to SIGTERM (not due to the idle timer).
		 *
		 * Log a warning about pending scripts.
		 *
		 * Maybe we should notify NetworkManager that these scripts are left in an unknown state.
		 * But this is either a bug of a dispatcher script (not terminating in time).
		 *
		 * FIXME(shutdown): Also, currently NetworkManager behaves wrongly on shutdown.
		 * Note that systemd would not terminate NetworkManager-dispatcher before NetworkManager.
		 * It's NetworkManager's responsibility to keep running long enough so that all requests
		 * can complete (with a watchdog timer, and a warning that user provided scripts hang). */
		_LOG_X_W ("exiting but there are still %u requests pending", gl.num_requests_pending);
	}

	if (dbus_own_name_id != 0)
		g_bus_unown_name (nm_steal_int (&dbus_own_name_id));

	if (dbus_regist_id != 0)
		g_dbus_connection_unregister_object (gl.dbus_connection, nm_steal_int (&dbus_regist_id));

	nm_clear_pointer (&gl.requests_waiting, g_queue_free);

	nm_clear_g_source (&signal_id_term);
	nm_clear_g_source (&signal_id_int);
	nm_clear_g_source (&gl.quit_id);
	g_clear_pointer (&gl.loop, g_main_loop_unref);
	g_clear_object (&gl.dbus_connection);

	if (!gl.debug)
		logging_shutdown ();

	return gl.exit_with_failure ? 1 : 0;
}
