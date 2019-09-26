// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2010 Dan Williams <dcbw@redhat.com>
 *
 */

#include "nm-default.h"

#include "nm-dns-dnsmasq.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <linux/if.h>

#include "nm-glib-aux/nm-dbus-aux.h"
#include "nm-core-internal.h"
#include "platform/nm-platform.h"
#include "nm-utils.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-dbus-manager.h"
#include "NetworkManagerUtils.h"

#define PIDFILE    NMRUNDIR "/dnsmasq.pid"
#define CONFDIR    NMCONFDIR "/dnsmasq.d"

#define DNSMASQ_DBUS_SERVICE "org.freedesktop.NetworkManager.dnsmasq"
#define DNSMASQ_DBUS_PATH    "/uk/org/thekelleys/dnsmasq"

#define RATELIMIT_INTERVAL_MSEC    30000
#define RATELIMIT_BURST            5

#define _NMLOG_DOMAIN      LOGD_DNS

/*****************************************************************************/

#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "dnsmasq", __VA_ARGS__)

#define WAIT_MSEC_AFTER_SIGTERM 1000
G_STATIC_ASSERT (WAIT_MSEC_AFTER_SIGTERM <= NM_SHUTDOWN_TIMEOUT_MS);

#define WAIT_MSEC_AFTER_SIGKILL 400
G_STATIC_ASSERT (WAIT_MSEC_AFTER_SIGKILL + 100 <= NM_SHUTDOWN_TIMEOUT_MS_WATCHDOG);

typedef void (*GlPidSpawnAsyncNotify) (GCancellable *cancellable,
                                       GPid pid,
                                       const int *p_exit_code,
                                       GError *error,
                                       gpointer notify_user_data);

typedef struct {
	NMShutdownWaitObjHandle *shutdown_wait_handle;
	guint64 p_start_time;
	gint64 started_at;
	GPid pid;
	bool sigkilled:1;
} GlPidKillExternalData;

typedef struct {
	const char *dm_binary;
	GlPidSpawnAsyncNotify notify;
	gpointer notify_user_data;
	GCancellable *cancellable;
} GlPidSpawnAsyncData;

static struct {

	GlPidKillExternalData *kill_external_data;

	GlPidSpawnAsyncData *spawn_data;

	NMShutdownWaitObjHandle *terminate_handle;

	GPid pid;

	guint terminate_timeout_id;

	guint watch_id;

	/* whether the external process (with the pid from PIDFILE) was already killed.
	 * This only happens once, once we do that, we remember to not do it again.
	 * The reason is that later one, when we want to kill the process it's a
	 * child process. So, we wait for the exit code. */
	bool kill_external_done:1;

	bool terminate_sigkill:1;
} gl_pid;

/*****************************************************************************/

static void _gl_pid_spawn_next_step (void);
static void _gl_pid_spawn_cancelled_cb (GCancellable *cancellable,
                                        GlPidSpawnAsyncData *sdata);

/*****************************************************************************/

static gboolean
_gl_pid_unlink_pidfile (gboolean do_unlink)
{
	int errsv;

	if (do_unlink) {
		if (unlink (PIDFILE) == 0)
			_LOGD ("spawn: delete PID file %s", PIDFILE);
		else {
			errsv = errno;
			if (errsv != ENOENT)
				_LOGD ("spawn: delete PID file %s failed: %s (%d)", PIDFILE, nm_strerror_native (errsv), errsv);
		}
	}
	return TRUE;
}

static gboolean
_gl_pid_kill_external_timeout_cb (gpointer user_data)
{
	guint64 p_start_time;
	char p_state = '\0';
	gint64 now;

	p_start_time = nm_utils_get_start_time_for_pid (gl_pid.kill_external_data->pid, &p_state, NULL);
	if (   p_start_time == 0
	    || p_start_time != gl_pid.kill_external_data->p_start_time
	    || nm_utils_process_state_is_dead (p_state)) {
		_LOGD ("spawn: process %"G_PID_FORMAT" from pidfile %s is gone", gl_pid.kill_external_data->pid, PIDFILE);
		goto process_gone;
	}

	now = nm_utils_get_monotonic_timestamp_ms ();

	if (gl_pid.kill_external_data->started_at + WAIT_MSEC_AFTER_SIGTERM < now) {
		if (!gl_pid.kill_external_data->sigkilled) {
			_LOGD ("spawn: send SIGKILL to process %"G_PID_FORMAT" from pidfile %s", gl_pid.kill_external_data->pid, PIDFILE);
			gl_pid.kill_external_data->sigkilled = TRUE;
			kill (gl_pid.kill_external_data->pid, SIGKILL);
		} else if (gl_pid.kill_external_data->started_at + WAIT_MSEC_AFTER_SIGTERM + WAIT_MSEC_AFTER_SIGKILL < now) {
			_LOGW ("spawn: process %"G_PID_FORMAT" from pidfile %s is still here after trying to kill it. Wait no longer", gl_pid.kill_external_data->pid, PIDFILE);
			goto process_gone;
		}
	}

	return G_SOURCE_CONTINUE;

process_gone:
	nm_shutdown_wait_obj_unregister (gl_pid.kill_external_data->shutdown_wait_handle);
	g_slice_free (GlPidKillExternalData, g_steal_pointer (&gl_pid.kill_external_data));

	_gl_pid_unlink_pidfile (TRUE);

	_gl_pid_spawn_next_step ();

	return G_SOURCE_REMOVE;
}

static gboolean
_gl_pid_kill_external (void)
{
	gs_free char *contents = NULL;
	gs_free char *cmdline_contents = NULL;
	gs_free_error GError *error = NULL;
	gint64 pid64;
	GPid pid = 0;
	guint64 p_start_time = 0;
	char proc_path[256];
	gboolean do_kill = FALSE;
	char p_state = '\0';
	gboolean do_unlink = TRUE;
	int errsv;

	if (gl_pid.kill_external_done) {
		if (gl_pid.kill_external_data) {
			_LOGD ("spawn: waiting for external process %"G_PID_FORMAT" from pidfile %s quit", gl_pid.kill_external_data->pid, PIDFILE);
			return FALSE;
		}
		return TRUE;
	}

	if (!g_file_get_contents (PIDFILE, &contents, NULL, &error)) {
		if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			do_unlink = FALSE;
		_LOGD ("spawn: failure to read pidfile %s: %s", PIDFILE, error->message);
		g_clear_error (&error);
		goto handle_kill;
	}

	pid64 = _nm_utils_ascii_str_to_int64 (contents, 10, 2, G_MAXINT64, -1);
	if (   pid64 == -1
	    || (pid = (GPid) pid64) != pid64) {
		_LOGD ("spawn: pidfile %s does not contain a valid process identifier", PIDFILE);
		goto handle_kill;
	}

	G_STATIC_ASSERT_EXPR (sizeof (pid) == sizeof (pid_t));

	p_start_time = nm_utils_get_start_time_for_pid (pid, &p_state, NULL);
	if (p_start_time == 0) {
		_LOGD ("spawn: process %"G_PID_FORMAT" from pidfile %s seems to no longer exist", pid, PIDFILE);
		goto handle_kill;
	}

	nm_sprintf_buf (proc_path, "/proc/%"G_PID_FORMAT"/cmdline", pid);
	if (!g_file_get_contents (proc_path, &cmdline_contents, NULL, NULL)) {
		_LOGD ("spawn: process %"G_PID_FORMAT" from pidfile %s seems to no longer exist", pid, PIDFILE);
		goto handle_kill;
	}

	if (!strstr (cmdline_contents, "/dnsmasq")) {
		_LOGD ("spawn: process %"G_PID_FORMAT" from pidfile %s seems to no longer to be a dnsmasq process", pid, PIDFILE);
		goto handle_kill;
	}

	do_kill = TRUE;

handle_kill:

	gl_pid.kill_external_done = TRUE;

	if (!do_kill)
		return _gl_pid_unlink_pidfile (do_unlink);

	if (nm_utils_process_state_is_dead (p_state)) {
		_LOGD ("spawn: process %"G_PID_FORMAT" from pidfile %s is already a zombie", pid, PIDFILE);
		return _gl_pid_unlink_pidfile (do_unlink);
	}

	if (kill (pid, SIGTERM) != 0) {
		errsv = errno;
		if (errsv == ESRCH)
			_LOGD ("spawn: process %"G_PID_FORMAT" from pidfile %s no longer exists", pid, PIDFILE);
		else
			_LOGD ("spawn: process %"G_PID_FORMAT" from pidfile %s failed with \"%s\" (%d)", pid, PIDFILE, nm_strerror_native (errsv), errsv);
		return _gl_pid_unlink_pidfile (do_unlink);
	}

	_LOGD ("spawn: waiting for process %"G_PID_FORMAT" from pidfile %s to terminate after SIGTERM", pid, PIDFILE);

	gl_pid.kill_external_data = g_slice_new (GlPidKillExternalData);
	*gl_pid.kill_external_data = (GlPidKillExternalData) {
		.shutdown_wait_handle = nm_shutdown_wait_obj_register_handle_full (g_strdup_printf ("kill-external-dnsmasq-process-%"G_PID_FORMAT, pid), TRUE),
		.started_at           = nm_utils_get_monotonic_timestamp_ms (),
		.pid                  = pid,
		.p_start_time         = p_start_time,
	};
	g_timeout_add (50, _gl_pid_kill_external_timeout_cb, NULL);
	return FALSE;
}

/*****************************************************************************/

static gboolean
_gl_pid_spawn_clear_pid (void)
{
	gboolean was_stopping = !!gl_pid.terminate_handle;

	gl_pid.pid = 0;
	gl_pid.terminate_sigkill = FALSE;
	nm_clear_g_source (&gl_pid.watch_id);
	nm_clear_g_source (&gl_pid.terminate_timeout_id);
	nm_clear_pointer (&gl_pid.terminate_handle, nm_shutdown_wait_obj_unregister);
	return was_stopping;
}

static void
_gl_pid_spawn_register_for_termination (void)
{
	if (   gl_pid.pid > 0
	    && !gl_pid.terminate_handle) {
		/* Create a shtudown handle as a reminder that the currently running process must be terminated
		 * first. This also happens to block shutdown... */
		gl_pid.terminate_handle = nm_shutdown_wait_obj_register_handle_full (g_strdup_printf ("kill-dnsmasq-process-%"G_PID_FORMAT, gl_pid.pid), TRUE);
	}
}

/**
 * _gl_pid_spawn_notify:
 * @sdata: the notify data. @sdata might be destroyed by the function,
 *   depending on the other arguments (which indicate whether the
 *   task is complete).
 * @pid: the PID to notify (argument for GlPidSpawnAsyncNotify)
 * @p_exit_code: the exit code to notify (argument for GlPidSpawnAsyncNotify)
 * @error: error reason to notify (argument for GlPidSpawnAsyncNotify)
 *
 * The GlPidSpawnAsyncNotify callback passed to _gl_pid_spawn() is used
 * for two purposes:
 *
 *  - signal that the dnsmasq process was spawned (or failed to be spawned).
 *  - signal that the dnsmasq process quit (if it was spawned sucessfully before).
 *
 * Depending on the arguments, the callee can see what's the case.
 */
static void
_gl_pid_spawn_notify (GlPidSpawnAsyncData *sdata,
                      GPid pid,
                      const int *p_exit_code,
                      GError *error)
{
	gboolean destroy = TRUE;

	nm_assert (sdata);

	if (error) {
		nm_assert (pid == 0);
		nm_assert (!p_exit_code);
		if (!nm_utils_error_is_cancelled (error, FALSE))
			_LOGD ("spawn: dnsmasq failed: %s", error->message);
	} else if (p_exit_code) {
		/* the only caller already logged about this condition extensively. */
		nm_assert (pid > 0);
	} else {
		nm_assert (pid > 0);
		_LOGD ("spawn: dnsmasq started with pid %"G_PID_FORMAT, pid);
		destroy = FALSE;
	}

	nm_assert ((!!destroy) == (sdata != gl_pid.spawn_data));

	if (destroy)
		g_signal_handlers_disconnect_by_func (sdata->cancellable, _gl_pid_spawn_cancelled_cb, sdata);

	sdata->notify (sdata->cancellable,
	               pid,
	               p_exit_code,
	               error,
	               sdata->notify_user_data);

	if (destroy) {
		g_clear_object (&sdata->cancellable);
		nm_g_slice_free (sdata);
	}
}

static void
_gl_pid_spawn_cancelled_cb (GCancellable *cancellable,
                            GlPidSpawnAsyncData *sdata)
{
	gs_free_error GError *error = NULL;

	if (sdata == gl_pid.spawn_data) {
		gl_pid.spawn_data = NULL;

		/* When the cancellable gets cancelled, we terminate the current dnsmasq instance
		 * in the background. The only way for keeping dnsmasq running while unregistering
		 * the callback is by calling _gl_pid_spawn() without a new callback. */
		_gl_pid_spawn_register_for_termination ();
	} else
		nm_assert_not_reached ();

	if (!g_cancellable_set_error_if_cancelled (cancellable, &error))
		nm_assert_not_reached ();

	_gl_pid_spawn_notify (sdata, 0, NULL, error);

	_gl_pid_spawn_next_step ();
}

static gboolean
_gl_pid_spawn_terminate_timeout_cb (gpointer user_data)
{
	nm_assert (gl_pid.terminate_timeout_id != 0);
	nm_assert (gl_pid.pid > 0);
	nm_assert (gl_pid.terminate_handle);
	nm_assert (gl_pid.watch_id != 0);

	gl_pid.terminate_timeout_id = 0;

	if (!gl_pid.terminate_sigkill) {
		gl_pid.terminate_sigkill = TRUE;
		_LOGD ("spawn: send SIGKILL signal to dnsmasq process %"G_PID_FORMAT" as it did not exit yet", gl_pid.pid);
		kill (gl_pid.pid, SIGKILL);
		gl_pid.terminate_timeout_id = g_timeout_add (WAIT_MSEC_AFTER_SIGKILL, _gl_pid_spawn_terminate_timeout_cb, NULL);
	} else {
		_LOGE ("spawn: process %"G_PID_FORMAT" did not exit even after SIGTERM and SIGKILL", gl_pid.pid);

		/* we don't unregister the watch. Just forget about it. We still want to reap the child eventually. */
		gl_pid.watch_id = 0;

		_gl_pid_spawn_clear_pid ();
		_gl_pid_spawn_next_step ();
	}

	return G_SOURCE_REMOVE;
}

static void
_gl_pid_spawn_watch_cb (GPid pid,
                        int status,
                        gpointer user_data)
{
	int err;
	gboolean was_stopping;

	nm_assert (pid > 0);

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
		if (err) {
			char sbuf[100];

			_LOGW ("spawn: dnsmasq process %"G_PID_FORMAT" exited with error: %s",
			       pid, nm_utils_dnsmasq_status_to_string (err, sbuf, sizeof (sbuf)));
		} else
			_LOGD ("spawn: dnsmasq process %"G_PID_FORMAT" exited normally", pid);
	} else if (WIFSTOPPED (status))
		_LOGW ("spawn: dnsmasq process %"G_PID_FORMAT" stopped unexpectedly with signal %d", pid, WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		_LOGW ("spawn: dnsmasq process %"G_PID_FORMAT" died with signal %d", pid, WTERMSIG (status));
	else
		_LOGW ("spawn: dnsmasq process %"G_PID_FORMAT" died from an unknown cause (status %d)", pid, status);

	if (gl_pid.pid != pid) {
		/* this can only happen, if we timed out and no longer care about this PID.
		 * We still kept the watch-id active, to reap the process. Nothing to do. */
		return;
	}

	nm_assert (gl_pid.watch_id != 0);

	gl_pid.watch_id = 0;

	_gl_pid_unlink_pidfile (TRUE);

	was_stopping = _gl_pid_spawn_clear_pid ();

	if (gl_pid.spawn_data) {
		if (was_stopping) {
			/* The current process was scheduled to be terminated. That means the pending
			 * spawn_data is not for that former instance, but for starting a new one.
			 * This spawn-request is not yet complete, instead it's just about to start. */
		} else
			_gl_pid_spawn_notify (g_steal_pointer (&gl_pid.spawn_data), pid, &status, NULL);
	}

	_gl_pid_spawn_next_step ();
}

/**
 * _gl_pid_spawn_next_step:
 *
 * The state about a running dnsmasq process is tracked in @gl_pid. There are
 * various things that can happen
 *
 *   - user calls _gl_pid_spawn() -- which might terminate an existing run first.
 *   - user might cancel the GCancellable -- which would abort the spawning or
 *     kill the current instance.
 *   - the child process might exit.
 *
 * In all these cases, we call _gl_pid_spawn_next_step() to check what to do next.
 */
static void
_gl_pid_spawn_next_step (void)
{
	gs_free_error GError *error = NULL;
	const char *argv[15];
	GPid pid = 0;
	guint argv_idx;

	if (!_gl_pid_kill_external ()) {
		/* we need to wait to kill the instance from the PID file first. */
		return;
	}

	if (gl_pid.terminate_handle) {

		nm_assert (gl_pid.pid > 0);

		if (gl_pid.terminate_timeout_id == 0) {
			_LOGD ("spawn: send SIGTERM signal to process %"G_PID_FORMAT, gl_pid.pid);
			gl_pid.terminate_timeout_id = g_timeout_add (WAIT_MSEC_AFTER_SIGTERM, _gl_pid_spawn_terminate_timeout_cb, NULL);
			kill (gl_pid.pid, SIGTERM);
		}

		/* we can only wait for the process to exit. */
		return;
	}

	if (!gl_pid.spawn_data) {
		/* we are not requested to spawn another process. */
		nm_assert (gl_pid.pid == 0);
		return;
	}

	if (gl_pid.pid > 0) {
		/* the process we desire is already running. All good. */
		return;
	}

	argv_idx = 0;
	argv[argv_idx++] = gl_pid.spawn_data->dm_binary;
	argv[argv_idx++] = "--no-resolv";  /* Use only commandline */
	argv[argv_idx++] = "--keep-in-foreground";
	argv[argv_idx++] = "--no-hosts"; /* don't use /etc/hosts to resolve */
	argv[argv_idx++] = "--bind-interfaces";
	argv[argv_idx++] = "--pid-file=" PIDFILE;
	argv[argv_idx++] = "--listen-address=127.0.0.1"; /* Should work for both 4 and 6 */
	argv[argv_idx++] = "--cache-size=400";
	argv[argv_idx++] = "--clear-on-reload"; /* clear cache when dns server changes */
	argv[argv_idx++] = "--conf-file=/dev/null"; /* avoid loading /etc/dnsmasq.conf */
	argv[argv_idx++] = "--proxy-dnssec"; /* Allow DNSSEC to pass through */
	argv[argv_idx++] = "--enable-dbus=" DNSMASQ_DBUS_SERVICE;

	/* dnsmasq exits if the conf dir is not present */
	if (g_file_test (CONFDIR, G_FILE_TEST_IS_DIR))
		argv[argv_idx++] = "--conf-dir=" CONFDIR;

	argv[argv_idx++] = NULL;
	nm_assert (argv_idx <= G_N_ELEMENTS (argv));

	if (!_LOGD_ENABLED ())
		_LOGI ("starting %s", gl_pid.spawn_data->dm_binary);
	else {
		gs_free char *cmdline = NULL;

		_LOGD ("spawn: starting dnsmasq: %s",
		      (cmdline = g_strjoinv (" ", (char **) argv)));
	}

	if (!g_spawn_async (NULL,
	                    (char **) argv,
	                    NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD,
	                    nm_utils_setpgid,
	                    NULL,
	                    &pid,
	                    &error)) {
		_gl_pid_spawn_notify (g_steal_pointer (&gl_pid.spawn_data), 0, NULL, error);
		return;
	}

	gl_pid.pid = pid;
	gl_pid.watch_id = g_child_watch_add (pid, _gl_pid_spawn_watch_cb, NULL);

	_gl_pid_spawn_notify (gl_pid.spawn_data, pid, NULL, NULL);
}

/**
 * _gl_pid_spawn:
 * @dm_binary: the binary name for dnsmasq to spawn. We could
 *   detect it ad-hoc right when needing it. But that would be
 *   asynchronously, and if dnsmasq is not in $PATH, we want to
 *   fail right away (synchrounously). Hence, @dm_binary is
 *   an argument.
 * @cancellable: abort the operation. This will invoke the callback
 *   a last time. Also, if the dnsmasq process is currently running,
 *   it will be terminated in the background. To unregister a notify
 *   call without killing the dnsmasq process, call _gl_pid_spawn()
 *   again with all arguments %NULL.
 * @notify: the callback when the process is started successfully
 *   and when the process terminates.
 * @notify_user_data: user-data for callback.
 *
 * If a dnsmasq process is already running (from a previous call of
 * _gl_pid_spawn()), that one will be replaced. Meaning, the other notify
 * callback will be invoked with NM_UTILS_ERROR/NM_UTILS_ERROR_CANCELLED_DISPOSING.
 * If you the @dm_binary argument, the previously running process will
 * also be terminated first, before spawning a new instance.
 * However, you may also pass all arguments as %NULL. In that case, the
 * previous @notify will be completed (and forgotten), but the dnsmasq
 * process will be left running in the background.
 *
 * So, you can:
 *
 *   - call _gl_pid_spawn() with a @dm_binary argument. The previous
 *     notify() completes with NM_UTILS_ERROR_CANCELLED_DISPOSING and
 *     the dnsmasq process gets killed.
 *   - cancel the GCancellable, in this case the notify() completes
 *     with G_IO_ERROR_CANCELLED and the dnsmasq process gets killed.
 *   - call _gl_pid_spawn() with all arguments %NULL. In that case
 *     the previous notify() completes with NM_UTILS_ERROR_CANCELLED_DISPOSING
 *     but the dnsmasq process keeps running in the background.
 *
 * The callback is used in two cases.
 * - When spawning the process it will be invoked always exactly once.
 *   In this case the callback might be invoked synchronously or
 *   asynchronously.
 *   This either provides a PID or a failure reason. In case of a
 *   failure, that's the end and the process is not running.
 * - if the process could be spawned, the child process with the
 *   provided PID gets monitored. When the process exits, the callback
 *   will be invoked again, with a failure reason. This is always done
 *   asynchronously.
 */
static void
_gl_pid_spawn (const char *dm_binary,
               GCancellable *cancellable,
               GlPidSpawnAsyncNotify notify,
               gpointer notify_user_data)
{
	GlPidSpawnAsyncData *sdata_replace;

	sdata_replace = g_steal_pointer (&gl_pid.spawn_data);

	if (dm_binary) {
		nm_assert (notify);
		nm_assert (G_IS_CANCELLABLE (cancellable));
		gl_pid.spawn_data = g_slice_new (GlPidSpawnAsyncData);
		*gl_pid.spawn_data = (GlPidSpawnAsyncData) {
			.dm_binary        = dm_binary,
			.notify           = notify,
			.notify_user_data = notify_user_data,
			.cancellable      = g_object_ref (cancellable),
		};
		g_signal_connect (cancellable, "cancelled", G_CALLBACK (_gl_pid_spawn_cancelled_cb), gl_pid.spawn_data);

		/* If dnsmasq is running, we terminate it and start a new instance.
		 *
		 * If the user would not provide a new callback, this would mean to fail/abort
		 * the currently subscribed notification (below). But it would leave the dnsmasq
		 * instance running in the background.
		 * This allows the user to say to not care about the current instance
		 * anymore, but still leave it running.
		 *
		 * To kill the dnsmasq process without scheduling a new one, cancel the cancellable
		 * instead. */
		_gl_pid_spawn_register_for_termination ();
	} else {
		nm_assert (!notify);
		nm_assert (!cancellable);
		nm_assert (!notify_user_data);
	}

	if (sdata_replace) {
		gs_free_error GError *error = NULL;

		/* we don't mark the error as G_IO_ERROR/G_IO_ERROR_CANCELLED. That
		 * is reserved for cancelling the cancellable. However, the current
		 * request was obsoleted/replaced by a new one, so we fail it with
		 * NM_UTILS_ERROR/NM_UTILS_ERROR_CANCELLED_DISPOSING. */
		nm_utils_error_set_cancelled (&error, TRUE, NULL);
		_gl_pid_spawn_notify (sdata_replace, 0, NULL, error);
	}

	_gl_pid_spawn_next_step ();
}

/*****************************************************************************/

typedef struct {

	GDBusConnection *dbus_connection;

	GVariant *set_server_ex_args;

	GCancellable *update_cancellable;

	GCancellable *main_cancellable;

	char *name_owner;

	gint64 burst_start_at;

	GPid process_pid;

	guint name_owner_changed_id;
	guint main_timeout_id;

	guint burst_retry_timeout_id;

	guint8 burst_count;

	bool is_stopped:1;

} NMDnsDnsmasqPrivate;

struct _NMDnsDnsmasq {
	NMDnsPlugin parent;
	NMDnsDnsmasqPrivate _priv;
};

struct _NMDnsDnsmasqClass {
	NMDnsPluginClass parent;
};

G_DEFINE_TYPE (NMDnsDnsmasq, nm_dns_dnsmasq, NM_TYPE_DNS_PLUGIN)

#define NM_DNS_DNSMASQ_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDnsDnsmasq, NM_IS_DNS_DNSMASQ)

/*****************************************************************************/

#undef _NMLOG
#define _NMLOG(level, ...) __NMLOG_DEFAULT_WITH_ADDR (level, _NMLOG_DOMAIN, "dnsmasq", __VA_ARGS__)

/*****************************************************************************/

static gboolean start_dnsmasq (NMDnsDnsmasq *self, gboolean force_start, GError **error);

/*****************************************************************************/

static void
add_dnsmasq_nameserver (NMDnsDnsmasq *self,
                        GVariantBuilder *servers,
                        const char *ip,
                        const char *domain)
{
	g_return_if_fail (ip);

	_LOGD ("adding nameserver '%s'%s%s%s", ip,
	       NM_PRINT_FMT_QUOTED (domain, " for domain \"", domain, "\"", ""));

	g_variant_builder_open (servers, G_VARIANT_TYPE ("as"));

	g_variant_builder_add (servers, "s", ip);
	if (domain)
		g_variant_builder_add (servers, "s", domain);

	g_variant_builder_close (servers);
}

#define IP_ADDR_TO_STRING_BUFLEN (NM_UTILS_INET_ADDRSTRLEN + 1 + IFNAMSIZ)

static const char *
ip_addr_to_string (int addr_family, gconstpointer addr, const char *iface, char *out_buf)
{
	int n_written;
	char buf2[NM_UTILS_INET_ADDRSTRLEN];
	const char *separator;

	nm_assert_addr_family (addr_family);
	nm_assert (addr);
	nm_assert (out_buf);

	if (addr_family == AF_INET) {
		nm_utils_inet_ntop (addr_family, addr, buf2);
		separator = "@";
	} else {
		if (IN6_IS_ADDR_V4MAPPED (addr))
			nm_utils_inet4_ntop (((const struct in6_addr *) addr)->s6_addr32[3], buf2);
		else
			nm_utils_inet6_ntop (addr, buf2);
		/* Need to scope link-local addresses with %<zone-id>. Before dnsmasq 2.58,
		 * only '@' was supported as delimiter. Since 2.58, '@' and '%' are
		 * supported. Due to a bug, since 2.73 only '%' works properly as "server"
		 * address.
		 */
		separator = IN6_IS_ADDR_LINKLOCAL (addr) ? "%" : "@";
	}

	n_written = g_snprintf (out_buf,
	                        IP_ADDR_TO_STRING_BUFLEN,
	                        "%s%s%s",
	                        buf2,
	                        iface ? separator : "",
	                        iface ?: "");
	nm_assert (n_written < IP_ADDR_TO_STRING_BUFLEN);
	return out_buf;
}

static void
add_global_config (NMDnsDnsmasq *self, GVariantBuilder *dnsmasq_servers, const NMGlobalDnsConfig *config)
{
	guint i, j;

	g_return_if_fail (config);

	for (i = 0; i < nm_global_dns_config_get_num_domains (config); i++) {
		NMGlobalDnsDomain *domain = nm_global_dns_config_get_domain (config, i);
		const char *const *servers = nm_global_dns_domain_get_servers (domain);
		const char *name = nm_global_dns_domain_get_name (domain);

		g_return_if_fail (name);

		for (j = 0; servers && servers[j]; j++) {
			if (!strcmp (name, "*"))
				add_dnsmasq_nameserver (self, dnsmasq_servers, servers[j], NULL);
			else
				add_dnsmasq_nameserver (self, dnsmasq_servers, servers[j], name);
		}

	}
}

static void
add_ip_config (NMDnsDnsmasq *self, GVariantBuilder *servers, const NMDnsIPConfigData *ip_data)
{
	NMIPConfig *ip_config = ip_data->ip_config;
	gconstpointer addr;
	const char *iface, *domain;
	char ip_addr_to_string_buf[IP_ADDR_TO_STRING_BUFLEN];
	int addr_family;
	guint i, j, num;

	iface = nm_platform_link_get_name (NM_PLATFORM_GET, ip_data->data->ifindex);
	addr_family = nm_ip_config_get_addr_family (ip_config);

	num = nm_ip_config_get_num_nameservers (ip_config);
	for (i = 0; i < num; i++) {
		addr = nm_ip_config_get_nameserver (ip_config, i);
		ip_addr_to_string (addr_family, addr, iface, ip_addr_to_string_buf);
		for (j = 0; ip_data->domains.search[j]; j++) {
			domain = nm_utils_parse_dns_domain (ip_data->domains.search[j], NULL);
			add_dnsmasq_nameserver (self,
			                        servers,
			                        ip_addr_to_string_buf,
			                        domain[0] ? domain : NULL);
		}

		if (ip_data->domains.reverse) {
			for (j = 0; ip_data->domains.reverse[j]; j++) {
				add_dnsmasq_nameserver (self, servers,
				                        ip_addr_to_string_buf,
				                        ip_data->domains.reverse[j]);
			}
		}
	}
}

static GVariant *
create_update_args (NMDnsDnsmasq *self,
                    const NMGlobalDnsConfig *global_config,
                    const CList *ip_config_lst_head,
                    const char *hostname)
{
	GVariantBuilder servers;
	const NMDnsIPConfigData *ip_data;

	g_variant_builder_init (&servers, G_VARIANT_TYPE ("aas"));

	if (global_config)
		add_global_config (self, &servers, global_config);
	else {
		c_list_for_each_entry (ip_data, ip_config_lst_head, ip_config_lst)
			add_ip_config (self, &servers, ip_data);
	}

	return g_variant_new ("(aas)", &servers);
}

/*****************************************************************************/

static void
dnsmasq_update_done (GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	NMDnsDnsmasq *self;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *response = NULL;

	response = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source_object), res, &error);

	if (nm_utils_error_is_cancelled (error, FALSE))
		return;

	self = user_data;
	if (!response)
		_LOGW ("dnsmasq update failed: %s", error->message);
	else
		_LOGD ("dnsmasq update successful");
}

static void
send_dnsmasq_update (NMDnsDnsmasq *self)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	if (   !priv->name_owner
	    || !priv->set_server_ex_args)
	    return;

	_LOGD ("trying to update dnsmasq nameservers");

	nm_clear_g_cancellable (&priv->update_cancellable);
	priv->update_cancellable = g_cancellable_new ();

	g_dbus_connection_call (priv->dbus_connection,
	                        priv->name_owner,
	                        DNSMASQ_DBUS_PATH,
	                        DNSMASQ_DBUS_SERVICE,
	                        "SetServersEx",
	                        priv->set_server_ex_args,
	                        NULL,
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                        20000,
	                        priv->update_cancellable,
	                        dnsmasq_update_done,
	                        self);
}

/*****************************************************************************/

static void
_main_cleanup (NMDnsDnsmasq *self, gboolean emit_failed)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	if (!priv->main_cancellable)
		return;

	priv->process_pid = 0;
	nm_clear_g_free (&priv->name_owner);

	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->name_owner_changed_id);

	nm_clear_g_source (&priv->main_timeout_id);
	nm_clear_g_cancellable (&priv->update_cancellable);

	/* cancelling the main_cancellable will also cause _gl_pid_spawn*() to terminate the
	 * process in the background. */
	nm_clear_g_cancellable (&priv->main_cancellable);

	if (   !priv->is_stopped
	    && priv->burst_retry_timeout_id == 0) {
		start_dnsmasq (self, FALSE, NULL);
		send_dnsmasq_update (self);
	}
}

static void
name_owner_changed (NMDnsDnsmasq *self,
                    const char *name_owner)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	name_owner = nm_str_not_empty (name_owner);

	if (nm_streq0 (priv->name_owner, name_owner))
		return;

	g_free (priv->name_owner);
	priv->name_owner = g_strdup (name_owner);

	if (!name_owner) {
		_LOGT ("D-Bus name for dnsmasq disappeared");
		_main_cleanup (self, TRUE);
		return;
	}

	_LOGT ("D-Bus name for dnsmasq got owner %s", name_owner);
	nm_clear_g_source (&priv->main_timeout_id);
	send_dnsmasq_update (self);
}

static void
name_owner_changed_cb (GDBusConnection *connection,
                       const char *sender_name,
                       const char *object_path,
                       const char *interface_name,
                       const char *signal_name,
                       GVariant *parameters,
                       gpointer user_data)
{
	NMDnsDnsmasq *self = user_data;
	const char *new_owner;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sss)")))
		return;

	g_variant_get (parameters,
	               "(&s&s&s)",
	               NULL,
	               NULL,
	               &new_owner);

	name_owner_changed (self, new_owner);
}

static void
get_name_owner_cb (const char *name_owner,
                   GError *error,
                   gpointer user_data)
{
	if (   !name_owner
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	name_owner_changed (user_data, name_owner);
}

static gboolean
spawn_timeout_cb (gpointer user_data)
{
	NMDnsDnsmasq *self = user_data;

	_LOGW ("timeout waiting for dnsmasq to appear on D-Bus");
	_main_cleanup (self, TRUE);
	return G_SOURCE_REMOVE;
}

static void
spawn_notify (GCancellable *cancellable,
              GPid pid,
              const int *p_exit_code,
              GError *error,
              gpointer notify_user_data)
{
	NMDnsDnsmasq *self;
	NMDnsDnsmasqPrivate *priv;

	if (nm_utils_error_is_cancelled (error, FALSE))
		return;

	self = notify_user_data;
	priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	if (   error
	    || p_exit_code) {
		_main_cleanup (self, TRUE);
		return;
	}

	nm_assert (pid > 0);
	priv->process_pid = pid;

	priv->name_owner_changed_id = nm_dbus_connection_signal_subscribe_name_owner_changed (priv->dbus_connection,
	                                                                                      DNSMASQ_DBUS_SERVICE,
	                                                                                      name_owner_changed_cb,
	                                                                                      self,
	                                                                                      NULL);
	nm_dbus_connection_call_get_name_owner (priv->dbus_connection,
	                                        DNSMASQ_DBUS_SERVICE,
	                                        -1,
	                                        priv->main_cancellable,
	                                        get_name_owner_cb,
	                                        self);
}

static gboolean
_burst_retry_timeout_cb (gpointer user_data)
{
	NMDnsDnsmasq *self = user_data;
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	priv->burst_retry_timeout_id = 0;

	start_dnsmasq (self, TRUE, NULL);
	send_dnsmasq_update (self);
	return G_SOURCE_REMOVE;
}

static gboolean
start_dnsmasq (NMDnsDnsmasq *self, gboolean force_start, GError **error)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	const char *dm_binary;
	gint64 now;

	if (G_LIKELY (priv->main_cancellable)) {
		/* The process is already running or about to be started. Nothing to do. */
		return TRUE;
	}

	dm_binary = nm_utils_find_helper ("dnsmasq", DNSMASQ_PATH, NULL);
	if (!dm_binary) {
		/* We resolve the binary name before trying to start it asynchronously.
		 * The reason is, that if dnsmasq is not installed, we want to fail early,
		 * so that NMDnsManager can fallback to a non-caching implementation. */
		nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
		                    "could not find dnsmasq binary");
		return FALSE;
	}

	if (!priv->dbus_connection) {
		priv->dbus_connection = nm_g_object_ref (NM_MAIN_DBUS_CONNECTION_GET);
		if (!priv->dbus_connection) {
			nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
			                    "no D-Bus connection available to talk to dnsmasq");
			return FALSE;
		}
	}

	now = nm_utils_get_monotonic_timestamp_ms ();
	if (   force_start
	    || priv->burst_start_at == 0
	    || priv->burst_start_at + RATELIMIT_INTERVAL_MSEC <= now) {
		priv->burst_start_at = now;
		priv->burst_count = 1;
		nm_clear_g_source (&priv->burst_retry_timeout_id);
		_LOGT ("rate-limit: start burst interval of %d seconds %s",
		       RATELIMIT_INTERVAL_MSEC / 1000,
		       force_start ? " (force)" : "");
	} else if (priv->burst_count < RATELIMIT_BURST) {
		nm_assert (priv->burst_retry_timeout_id == 0);
		priv->burst_count++;
		_LOGT ("rate-limit: %u try within burst interval of %d seconds",
		       (guint) priv->burst_count,
		       RATELIMIT_INTERVAL_MSEC / 1000);
	} else {
		if (priv->burst_retry_timeout_id == 0) {
			_LOGW ("dnsmasq dies and gets respawned too quickly. Back off. Something is very wrong");
			priv->burst_retry_timeout_id = g_timeout_add_seconds ((2 * RATELIMIT_INTERVAL_MSEC) / 1000, _burst_retry_timeout_cb, self);
		} else
			_LOGT ("rate-limit: currently rate-limited from restart");
		return TRUE;
	}

	priv->main_timeout_id = g_timeout_add (10000,
	                                       spawn_timeout_cb,
	                                       self);

	priv->main_cancellable = g_cancellable_new ();

	_gl_pid_spawn (dm_binary,
	               priv->main_cancellable,
	               spawn_notify,
	               self);
	return TRUE;
}

static gboolean
update (NMDnsPlugin *plugin,
        const NMGlobalDnsConfig *global_config,
        const CList *ip_config_lst_head,
        const char *hostname,
        GError **error)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (plugin);
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	if (!start_dnsmasq (self, TRUE, error))
		return FALSE;

	nm_clear_pointer (&priv->set_server_ex_args, g_variant_unref);
	priv->set_server_ex_args = g_variant_ref_sink (create_update_args (self,
	                                                                   global_config,
	                                                                   ip_config_lst_head,
	                                                                   hostname));

	send_dnsmasq_update (self);
	return TRUE;
}

/*****************************************************************************/

static void
stop (NMDnsPlugin *plugin)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (plugin);
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	priv->is_stopped = TRUE;
	priv->burst_start_at = 0;
	nm_clear_g_source (&priv->burst_retry_timeout_id);

	/* Cancelling the cancellable will also terminate the
	 * process (in the background). */
	_main_cleanup (self, FALSE);
}

/*****************************************************************************/

static void
nm_dns_dnsmasq_init (NMDnsDnsmasq *self)
{
}

NMDnsPlugin *
nm_dns_dnsmasq_new (void)
{
	return g_object_new (NM_TYPE_DNS_DNSMASQ, NULL);
}

static void
dispose (GObject *object)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (object);
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	priv->is_stopped = TRUE;

	nm_clear_g_source (&priv->burst_retry_timeout_id);

	_main_cleanup (self, FALSE);

	g_clear_pointer (&priv->set_server_ex_args, g_variant_unref);

	G_OBJECT_CLASS (nm_dns_dnsmasq_parent_class)->dispose (object);

	g_clear_object (&priv->dbus_connection);
}

static void
nm_dns_dnsmasq_class_init (NMDnsDnsmasqClass *dns_class)
{
	NMDnsPluginClass *plugin_class = NM_DNS_PLUGIN_CLASS (dns_class);
	GObjectClass *object_class = G_OBJECT_CLASS (dns_class);

	object_class->dispose = dispose;

	plugin_class->plugin_name = "dnsmasq";
	plugin_class->is_caching  = TRUE;
	plugin_class->stop        = stop;
	plugin_class->update      = update;
}
