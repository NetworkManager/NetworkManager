// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nm-cloud-setup-utils.h"

#include "nm-glib-aux/nm-time-utils.h"
#include "nm-glib-aux/nm-logging-base.h"

/*****************************************************************************/

volatile NMLogLevel _nm_logging_configured_level = LOGL_TRACE;

void
_nm_logging_enabled_init (const char *level_str)
{
	NMLogLevel level;

	if (!_nm_log_parse_level (level_str, &level))
		level = LOGL_WARN;
	else if (level == _LOGL_KEEP)
		level = LOGL_WARN;

	_nm_logging_configured_level = level;
}

void
_nm_log_impl_cs (NMLogLevel level,
                 const char *fmt,
                 ...)
{
	gs_free char *msg = NULL;
	va_list ap;
	const char *level_str;
	gint64 ts;

	va_start (ap, fmt);
	msg = g_strdup_vprintf (fmt, ap);
	va_end (ap);

	switch (level) {
	case LOGL_TRACE: level_str = "<trace>"; break;
	case LOGL_DEBUG: level_str = "<debug>"; break;
	case LOGL_INFO:  level_str = "<info> "; break;
	case LOGL_WARN:  level_str = "<warn> "; break;
	default:
		nm_assert (level == LOGL_ERR);
		level_str = "<error>";
		break;
	}

	ts = nm_utils_clock_gettime_ns (CLOCK_BOOTTIME);

	g_print ("[%"G_GINT64_FORMAT".%05"G_GINT64_FORMAT"] %s %s\n",
	         ts / NM_UTILS_NS_PER_SECOND,
	         (ts / (NM_UTILS_NS_PER_SECOND / 10000)) % 10000,
	         level_str,
	         msg);
}

void
_nm_utils_monotonic_timestamp_initialized (const struct timespec *tp,
                                           gint64 offset_sec,
                                           gboolean is_boottime)
{
}

/*****************************************************************************/

G_LOCK_DEFINE_STATIC  (_wait_for_objects_lock);
static GSList *_wait_for_objects_list;
static GSList *_wait_for_objects_iterate_loops;

static void
_wait_for_objects_maybe_quit_mainloops_with_lock (void)
{
	GSList *iter;

	if (!_wait_for_objects_list) {
		for (iter = _wait_for_objects_iterate_loops; iter; iter = iter->next)
			g_main_loop_quit (iter->data);
	}
}

static void
_wait_for_objects_weak_cb (gpointer data,
                           GObject *where_the_object_was)
{
	G_LOCK (_wait_for_objects_lock);
	nm_assert (g_slist_find (_wait_for_objects_list, where_the_object_was));
	_wait_for_objects_list = g_slist_remove (_wait_for_objects_list, where_the_object_was);
	_wait_for_objects_maybe_quit_mainloops_with_lock ();
	G_UNLOCK (_wait_for_objects_lock);
}

/**
 * nmcs_wait_for_objects_register:
 * @target: a #GObject to wait for.
 *
 * Registers @target as a pointer to wait during shutdown. Using
 * nmcs_wait_for_objects_iterate_until_done() we keep waiting until
 * @target gets destroyed, which means that it gets completely unreferenced.
 */
gpointer
nmcs_wait_for_objects_register (gpointer target)
{
	g_return_val_if_fail (G_IS_OBJECT (target), NULL);

	G_LOCK (_wait_for_objects_lock);
	_wait_for_objects_list = g_slist_prepend (_wait_for_objects_list, target);
	G_UNLOCK (_wait_for_objects_lock);

	g_object_weak_ref (target,
	                   _wait_for_objects_weak_cb,
	                   NULL);
	return target;
}

typedef struct {
	GMainLoop *loop;
	gboolean got_timeout;
} WaitForObjectsData;

static gboolean
_wait_for_objects_iterate_until_done_timeout_cb (gpointer user_data)
{
	WaitForObjectsData *data = user_data;

	data->got_timeout = TRUE;
	g_main_loop_quit (data->loop);
	return G_SOURCE_CONTINUE;
}

static gboolean
_wait_for_objects_iterate_until_done_idle_cb (gpointer user_data)
{
	/* This avoids a race where:
	 *
	 *   - we check whether there are objects to wait for.
	 *   - the last object to wait for gets removed (issuing g_main_loop_quit()).
	 *   - we run the mainloop (and missed our signal).
	 *
	 * It's really a missing feature of GMainLoop where the "is-running" flag is always set to
	 * TRUE by g_main_loop_run(). That means, you cannot catch a g_main_loop_quit() in a race
	 * free way while not iterating the loop.
	 *
	 * Avoid this, by checking once again after we start running the mainloop.
	 */

	G_LOCK (_wait_for_objects_lock);
	_wait_for_objects_maybe_quit_mainloops_with_lock ();
	G_UNLOCK (_wait_for_objects_lock);
	return G_SOURCE_REMOVE;
}

/**
 * nmcs_wait_for_objects_iterate_until_done:
 * @context: the #GMainContext to iterate.
 * @timeout_msec: timeout or -1 for no timeout.
 *
 * Iterates the provided @context until all objects that we wait for
 * are destroyed.
 *
 * The purpose of this is to cleanup all objects that we have on exit. That
 * is especially because objects have asynchronous operations pending that
 * should be cancelled and properly completed during exit.
 *
 * Returns: %FALSE on timeout or %TRUE if all objects destroyed before timeout.
 */
gboolean
nmcs_wait_for_objects_iterate_until_done (GMainContext *context,
                                          int timeout_msec)
{
	nm_auto_unref_gmainloop GMainLoop *loop = g_main_loop_new (context, FALSE);
	nm_auto_destroy_and_unref_gsource GSource *timeout_source = NULL;
	WaitForObjectsData data;
	gboolean has_more_objects;

	G_LOCK (_wait_for_objects_lock);
	if (!_wait_for_objects_list) {
		G_UNLOCK (_wait_for_objects_lock);
		return TRUE;
	}
	_wait_for_objects_iterate_loops = g_slist_prepend (_wait_for_objects_iterate_loops, loop);
	G_UNLOCK (_wait_for_objects_lock);

	data = (WaitForObjectsData) {
		.loop        = loop,
		.got_timeout = FALSE,
	};

	if (timeout_msec >= 0) {
		timeout_source = nm_g_source_attach (nm_g_timeout_source_new (timeout_msec,
		                                                              G_PRIORITY_DEFAULT,
		                                                              _wait_for_objects_iterate_until_done_timeout_cb,
		                                                              &data,
		                                                              NULL),
		                                     context);
	}

	has_more_objects = TRUE;
	while (   has_more_objects
	       && !data.got_timeout) {
		nm_auto_destroy_and_unref_gsource GSource *idle_source = NULL;

		idle_source = nm_g_source_attach (nm_g_idle_source_new (G_PRIORITY_DEFAULT,
		                                                        _wait_for_objects_iterate_until_done_idle_cb,
		                                                        &data,
		                                                        NULL),
		                                  context);

		g_main_loop_run (loop);

		G_LOCK (_wait_for_objects_lock);
		has_more_objects = (!!_wait_for_objects_list);
		if (   data.got_timeout
			|| !has_more_objects)
			_wait_for_objects_iterate_loops = g_slist_remove (_wait_for_objects_iterate_loops, loop);
		G_UNLOCK (_wait_for_objects_lock);
	}

	return !data.got_timeout;
}

/*****************************************************************************/

typedef struct {
	GTask *task;
	GSource *source_timeout;
	GSource *source_next_poll;
	GMainContext *context;
	GCancellable *internal_cancellable;
	NMCSUtilsPollProbeStartFcn probe_start_fcn;
	NMCSUtilsPollProbeFinishFcn probe_finish_fcn;
	gpointer probe_user_data;
	gulong cancellable_id;
	gint64 last_poll_start_ms;
	int sleep_timeout_ms;
	int ratelimit_timeout_ms;
	bool completed:1;
} PollTaskData;

static void
_poll_task_data_free (gpointer data)
{
	PollTaskData *poll_task_data = data;

	nm_assert (G_IS_TASK (poll_task_data->task));
	nm_assert (!poll_task_data->source_next_poll);
	nm_assert (!poll_task_data->source_timeout);
	nm_assert (poll_task_data->cancellable_id == 0);

	g_main_context_unref (poll_task_data->context);

	nm_g_slice_free (poll_task_data);
}

static void
_poll_return (PollTaskData *poll_task_data,
              gboolean success,
              GError *error_take)
{
	nm_clear_g_source_inst (&poll_task_data->source_next_poll);
	nm_clear_g_source_inst (&poll_task_data->source_timeout);
	nm_clear_g_cancellable_disconnect (g_task_get_cancellable (poll_task_data->task),
	                                   &poll_task_data->cancellable_id);

	nm_clear_g_cancellable (&poll_task_data->internal_cancellable);

	if (error_take)
		g_task_return_error (poll_task_data->task, g_steal_pointer (&error_take));
	else
		g_task_return_boolean (poll_task_data->task, success);

	g_object_unref (poll_task_data->task);
}

static gboolean _poll_start_cb (gpointer user_data);

static void
_poll_done_cb (GObject *source,
               GAsyncResult *result,
               gpointer user_data)
{
	PollTaskData *poll_task_data = user_data;
	_nm_unused gs_unref_object GTask *task = poll_task_data->task; /* balance ref from _poll_start_cb() */
	gs_free_error GError *error = NULL;
	gint64 now_ms;
	gint64 wait_ms;
	gboolean is_finished;

	is_finished = poll_task_data->probe_finish_fcn (source,
	                                                result,
	                                                poll_task_data->probe_user_data,
	                                                &error);

	if (nm_utils_error_is_cancelled (error, FALSE)) {
		/* we already handle this differently. Nothing to do. */
		return;
	}

	if (   error
	    || is_finished) {
		_poll_return (poll_task_data, TRUE, g_steal_pointer (&error));
		return;
	}

	now_ms = nm_utils_get_monotonic_timestamp_ms ();
	if (poll_task_data->ratelimit_timeout_ms > 0)
		wait_ms = (poll_task_data->last_poll_start_ms + poll_task_data->ratelimit_timeout_ms) - now_ms;
	else
		wait_ms = 0;
	if (poll_task_data->sleep_timeout_ms > 0)
		wait_ms = MAX (wait_ms, poll_task_data->sleep_timeout_ms);

	poll_task_data->source_next_poll = nm_g_source_attach (nm_g_timeout_source_new (MAX (1, wait_ms),
	                                                                                G_PRIORITY_DEFAULT,
	                                                                                _poll_start_cb,
	                                                                                poll_task_data,
	                                                                                NULL),
	                                                       poll_task_data->context);
}

static gboolean
_poll_start_cb (gpointer user_data)
{
	PollTaskData *poll_task_data = user_data;

	nm_clear_g_source_inst (&poll_task_data->source_next_poll);

	poll_task_data->last_poll_start_ms = nm_utils_get_monotonic_timestamp_ms ();

	g_object_ref (poll_task_data->task); /* balanced by _poll_done_cb() */

	poll_task_data->probe_start_fcn (poll_task_data->internal_cancellable,
	                                 poll_task_data->probe_user_data,
	                                 _poll_done_cb,
	                                 poll_task_data);

	return G_SOURCE_CONTINUE;
}

static gboolean
_poll_timeout_cb (gpointer user_data)
{
	PollTaskData *poll_task_data = user_data;

	_poll_return (poll_task_data, FALSE, NULL);
	return G_SOURCE_CONTINUE;
}

static void
_poll_cancelled_cb (GObject *object, gpointer user_data)
{
	PollTaskData *poll_task_data = user_data;
	GError *error = NULL;

	_LOGD (">> poll cancelled");
	nm_clear_g_signal_handler (g_task_get_cancellable (poll_task_data->task),
	                           &poll_task_data->cancellable_id);
	nm_utils_error_set_cancelled (&error, FALSE, NULL);
	_poll_return (poll_task_data, FALSE, error);
}

/**
 * nmcs_utils_poll:
 * @poll_timeout_ms: if >= 0, then this is the overall timeout for how long we poll.
 *   When this timeout expires, the request completes with failure (but no error set).
 * @ratelimit_timeout_ms: if > 0, we ratelimit the starts from one prope_start_fcn
 *   call to the next.
 * @sleep_timeout_ms: if > 0, then we wait after a probe finished this timeout
 *   before the next. Together with @ratelimit_timeout_ms this determines how
 *   frequently we probe.
 * @probe_start_fcn: used to start a (asynchrnous) probe. A probe must be completed
 *   by calling the provided callback. While a probe is in progress, we will not
 *   start another. This function is already invoked the first time synchronously,
 *   during nmcs_utils_poll().
 * @probe_finish_fcn: will be called from the callback of @probe_start_fcn. If the
 *   function returns %TRUE (polling done) or an error, polling stops. Otherwise,
 *   another poll will be started.
 * @probe_user_data: user_data for the probe functions.
 * @cancellable: cancellable for polling.
 * @callback: when polling completes.
 * @user_data: for @callback.
 *
 * This uses the current g_main_context_get_thread_default() for scheduling
 * actions.
 */
void
nmcs_utils_poll (int poll_timeout_ms,
                 int sleep_timeout_ms,
                 int ratelimit_timeout_ms,
                 NMCSUtilsPollProbeStartFcn probe_start_fcn,
                 NMCSUtilsPollProbeFinishFcn probe_finish_fcn,
                 gpointer probe_user_data,
                 GCancellable *cancellable,
                 GAsyncReadyCallback callback,
                 gpointer user_data)
{
	PollTaskData *poll_task_data;

	poll_task_data = g_slice_new (PollTaskData);
	*poll_task_data = (PollTaskData) {
		.task                 = nm_g_task_new (NULL, cancellable, nmcs_utils_poll, callback, user_data),
		.probe_start_fcn      = probe_start_fcn,
		.probe_finish_fcn     = probe_finish_fcn,
		.probe_user_data      = probe_user_data,
		.completed            = FALSE,
		.context              = g_main_context_ref_thread_default (),
		.sleep_timeout_ms     = sleep_timeout_ms,
		.ratelimit_timeout_ms = ratelimit_timeout_ms,
		.internal_cancellable = g_cancellable_new (),
	};

	nmcs_wait_for_objects_register (poll_task_data->task);

	g_task_set_task_data (poll_task_data->task, poll_task_data, _poll_task_data_free);

	if (poll_timeout_ms >= 0) {
		poll_task_data->source_timeout = nm_g_source_attach (nm_g_timeout_source_new (poll_timeout_ms,
		                                                                              G_PRIORITY_DEFAULT,
		                                                                              _poll_timeout_cb,
		                                                                              poll_task_data,
		                                                                              NULL),
		                                                     poll_task_data->context);
	}

	poll_task_data->source_next_poll = nm_g_source_attach (nm_g_idle_source_new (G_PRIORITY_DEFAULT,
	                                                                             _poll_start_cb,
	                                                                             poll_task_data,
	                                                                             NULL),
	                                                       poll_task_data->context);

	if (cancellable) {
		gulong signal_id;

		signal_id = g_cancellable_connect (cancellable,
		                                   G_CALLBACK (_poll_cancelled_cb),
		                                   poll_task_data,
		                                   NULL);
		if (signal_id == 0) {
			/* the request is already cancelled. Return. */
			return;
		}
		poll_task_data->cancellable_id = signal_id;
	}
}

/**
 * nmcs_utils_poll_finish:
 * @result: the GAsyncResult from the GAsyncReadyCallback callback.
 * @probe_user_data: the user data provided to nmcs_utils_poll().
 * @error: the failure code.
 *
 * Returns: %TRUE if the polling completed with success. In that case,
 *   the error won't be set.
 *   If the request was cancelled, this is indicated by @error and
 *   %FALSE will be returned.
 *   If the probe returned a failure, this returns %FALSE and the error
 *   provided by @probe_finish_fcn.
 *   If the request times out, this returns %FALSE without error set.
 */
gboolean
nmcs_utils_poll_finish (GAsyncResult *result,
                        gpointer *probe_user_data,
                        GError **error)
{
	GTask *task;
	PollTaskData *poll_task_data;

	g_return_val_if_fail (nm_g_task_is_valid (result, NULL, nmcs_utils_poll), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	task = G_TASK (result);

	if (probe_user_data) {
		poll_task_data = g_task_get_task_data (task);
		NM_SET_OUT (probe_user_data, poll_task_data->probe_user_data);
	}

	return g_task_propagate_boolean (task, error);
}

/*****************************************************************************/

char *
nmcs_utils_hwaddr_normalize (const char *hwaddr, gssize len)
{
	gs_free char *hwaddr_clone = NULL;
	guint8 buf[ETH_ALEN];

	nm_assert (len >= -1);

	if (len < 0) {
		if (!hwaddr)
			return NULL;
	} else {
		if (len == 0)
			return NULL;
		nm_assert (hwaddr);
		hwaddr = nm_strndup_a (300, hwaddr, len, &hwaddr_clone);
	}

	if (!nm_utils_hwaddr_aton (hwaddr, buf, sizeof (buf)))
		return NULL;

	return nm_utils_hwaddr_ntoa (buf, sizeof (buf));
}

/*****************************************************************************/

const char *
nmcs_utils_parse_memmem (GBytes *mem, const char *needle)
{
	const char *mem_data;
	gsize mem_size;

	g_return_val_if_fail (mem, NULL);
	g_return_val_if_fail (needle, NULL);

	mem_data = g_bytes_get_data (mem, &mem_size);
	return memmem (mem_data, mem_size, needle, strlen (needle));
}

const char *
nmcs_utils_parse_get_full_line (GBytes *mem, const char *needle)
{
	const char *mem_data;
	gsize mem_size;
	gsize c;
	gsize l;

	const char *line;

	line = nmcs_utils_parse_memmem (mem, needle);
	if (!line)
		return NULL;

	mem_data = g_bytes_get_data (mem, &mem_size);

	if (   line != mem_data
	    && line[-1] != '\n') {
		/* the line must be preceeded either by the begin of the data or
		 * by a newline. */
		return NULL;
	}

	c = mem_size - (line - mem_data);
	l = strlen (needle);

	if (   c != l
	    && line[l] != '\n') {
		/* the end of the needle must be either a newline or the end of the buffer. */
		return NULL;
	}

	return line;
}

/*****************************************************************************/

char *
nmcs_utils_uri_build_concat_v (const char *base,
                               const char **components,
                               gsize n_components)
{
	GString *uri;

	nm_assert (base);
	nm_assert (base[0]);
	nm_assert (!NM_STR_HAS_SUFFIX (base, "/"));

	uri = g_string_sized_new (100);

	g_string_append (uri, base);

	if (   n_components > 0
	    && components[0]
	    && components[0][0] == '/') {
		/* the first component starts with a slash. We allow that, and don't add a duplicate
		 * slash. Otherwise, we add a separator after base.
		 *
		 * We only do that for the first component. */
	} else
		g_string_append_c (uri, '/');

	while (n_components > 0) {
		if (!components[0]) {
			/* we allow NULL, to indicate nothing to append*/
		} else
			g_string_append (uri, components[0]);
		components++;
		n_components--;
	}

	return g_string_free (uri, FALSE);
}

/*****************************************************************************/

gboolean
nmcs_setting_ip_replace_ipv4_addresses (NMSettingIPConfig *s_ip,
                                        NMIPAddress **entries_arr,
                                        guint entries_len)
{
	gboolean any_changes = FALSE;
	guint i_next;
	guint num;
	guint i;

	num = nm_setting_ip_config_get_num_addresses (s_ip);

	i_next = 0;

	for (i = 0; i < entries_len; i++) {
		NMIPAddress *entry = entries_arr[i];

		if (!any_changes) {
			if (i_next < num) {
				if (nm_ip_address_cmp_full (entry,
				                            nm_setting_ip_config_get_address (s_ip, i_next),
				                            NM_IP_ADDRESS_CMP_FLAGS_WITH_ATTRS) == 0) {
					i_next++;
					continue;
				}
			}
			while (i_next < num)
				nm_setting_ip_config_remove_address (s_ip, --num);
			any_changes = TRUE;
		}

		if (!nm_setting_ip_config_add_address (s_ip, entry))
			continue;

		i_next++;
	}
	if (any_changes) {
		while (i_next < num) {
			nm_setting_ip_config_remove_address (s_ip, --num);
			any_changes = TRUE;
		}
	}

	return any_changes;
}

gboolean
nmcs_setting_ip_replace_ipv4_routes (NMSettingIPConfig *s_ip,
                                     NMIPRoute **entries_arr,
                                     guint entries_len)
{
	gboolean any_changes = FALSE;
	guint i_next;
	guint num;
	guint i;

	num = nm_setting_ip_config_get_num_routes (s_ip);

	i_next = 0;

	for (i = 0; i < entries_len; i++) {
		NMIPRoute *entry = entries_arr[i];

		if (!any_changes) {
			if (i_next < num) {
				if (nm_ip_route_equal_full (entry,
				                            nm_setting_ip_config_get_route (s_ip, i_next),
				                            NM_IP_ROUTE_EQUAL_CMP_FLAGS_WITH_ATTRS)) {
					i_next++;
					continue;
				}
			}
			while (i_next < num)
				nm_setting_ip_config_remove_route (s_ip, --num);
			any_changes = TRUE;
		}

		if (!nm_setting_ip_config_add_route (s_ip, entry))
			continue;

		i_next++;
	}
	if (!any_changes) {
		while (i_next < num) {
			nm_setting_ip_config_remove_route (s_ip, --num);
			any_changes = TRUE;
		}
	}

	return any_changes;
}

gboolean
nmcs_setting_ip_replace_ipv4_rules (NMSettingIPConfig *s_ip,
                                    NMIPRoutingRule **entries_arr,
                                    guint entries_len)
{
	gboolean any_changes = FALSE;
	guint i_next;
	guint num;
	guint i;

	num = nm_setting_ip_config_get_num_routing_rules (s_ip);

	i_next = 0;

	for (i = 0; i < entries_len; i++) {
		NMIPRoutingRule *entry = entries_arr[i];

		if (!any_changes) {
			if (i_next < num) {
				if (nm_ip_routing_rule_cmp (entry,
				                            nm_setting_ip_config_get_routing_rule (s_ip, i_next)) == 0) {
					i_next++;
					continue;
				}
			}
			while (i_next < num)
				nm_setting_ip_config_remove_routing_rule (s_ip, --num);
			any_changes = TRUE;
		}

		nm_setting_ip_config_add_routing_rule (s_ip, entry);
		i_next++;
	}
	if (!any_changes) {
		while (i_next < num) {
			nm_setting_ip_config_remove_routing_rule (s_ip, --num);
			any_changes = TRUE;
		}
	}

	return any_changes;
}

/*****************************************************************************/

typedef struct {
	GMainLoop *main_loop;
	NMConnection *connection;
	GError *error;
	guint64 version_id;
} DeviceGetAppliedConnectionData;

static void
_nmcs_device_get_applied_connection_cb (GObject *source,
                                        GAsyncResult *result,
                                        gpointer user_data)
{
	DeviceGetAppliedConnectionData *data = user_data;

	data->connection = nm_device_get_applied_connection_finish (NM_DEVICE (source),
	                                                            result,
	                                                            &data->version_id,
	                                                            &data->error);
	g_main_loop_quit (data->main_loop);
}

NMConnection *
nmcs_device_get_applied_connection (NMDevice *device,
                                    GCancellable *cancellable,
                                    guint64 *version_id,
                                    GError **error)
{
	nm_auto_unref_gmainloop GMainLoop *main_loop = g_main_loop_new (NULL, FALSE);
	DeviceGetAppliedConnectionData data = {
		.main_loop = main_loop,
	};

	nm_device_get_applied_connection_async (device,
	                                        0,
	                                        cancellable,
	                                        _nmcs_device_get_applied_connection_cb,
	                                        &data);

	g_main_loop_run (main_loop);

	if (data.error)
		g_propagate_error (error, data.error);
	NM_SET_OUT (version_id, data.version_id);
	return data.connection;
}

/*****************************************************************************/

typedef struct {
	GMainLoop *main_loop;
	GError *error;
} DeviceReapplyData;

static void
_nmcs_device_reapply_cb (GObject *source,
                         GAsyncResult *result,
                         gpointer user_data)
{
	DeviceReapplyData *data = user_data;

	nm_device_reapply_finish (NM_DEVICE (source),
	                          result,
	                          &data->error);
	g_main_loop_quit (data->main_loop);
}

gboolean
nmcs_device_reapply (NMDevice *device,
                     GCancellable *sigterm_cancellable,
                     NMConnection *connection,
                     guint64 version_id,
                     gboolean *out_version_id_changed,
                     GError **error)
{
	nm_auto_unref_gmainloop GMainLoop *main_loop = g_main_loop_new (NULL, FALSE);
	DeviceReapplyData data = {
		.main_loop = main_loop,
	};

	nm_device_reapply_async (device,
	                         connection,
	                         version_id,
	                         0,
	                         sigterm_cancellable,
	                         _nmcs_device_reapply_cb,
	                         &data);

	g_main_loop_run (main_loop);

	if (data.error) {
		NM_SET_OUT (out_version_id_changed, g_error_matches (data.error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_VERSION_ID_MISMATCH));
		g_propagate_error (error, data.error);
		return FALSE;
	}

	NM_SET_OUT (out_version_id_changed, FALSE);
	return TRUE;
}
