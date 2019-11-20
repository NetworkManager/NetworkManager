// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include <glib-unix.h>

#include "devices/bluetooth/nm-bluez5-dun.h"

#include "nm-test-utils-core.h"

/*****************************************************************************/

#define _NMLOG_DOMAIN LOGD_BT
#define _NMLOG(level, ...) \
	nm_log ((level), _NMLOG_DOMAIN, \
	        NULL, NULL, \
	        "bt%s%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
	        NM_PRINT_FMT_QUOTED (gl.argv_cmd, "[", gl.argv_cmd, "]", "") \
	        _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

struct {
	int argc;
	const char *const*argv;
	const char *argv_cmd;
	GMainLoop *loop;
} gl;

typedef struct _MainCmdInfo {
	const char *name;
	int (*main_func) (const struct _MainCmdInfo *main_cmd_info);
} MainCmdInfo;

/*****************************************************************************/

#if WITH_BLUEZ5_DUN

typedef struct {
	NMBluez5DunContext *dun_context;
	GCancellable *cancellable;
	guint timeout_id;
	guint sig_term_id;
	guint sig_int_id;
} DunConnectData;

static void
_dun_connect_cb (NMBluez5DunContext *context,
                 const char *rfcomm_dev,
                 GError *error,
                 gpointer user_data)
{
	DunConnectData *dun_connect_data = user_data;

	g_assert (dun_connect_data);
	g_assert (!dun_connect_data->dun_context);
	g_assert ((!!error) != (!!rfcomm_dev));

	if (rfcomm_dev && !context) {
		_LOGI ("dun-connect notifies path \"%s\". Wait longer...", rfcomm_dev);
		return;
	}

	if (rfcomm_dev) {
		g_assert (context);
		_LOGI ("dun-connect completed with path \"%s\"", rfcomm_dev);
	} else {
		g_assert (!context);
		_LOGI ("dun-connect failed with error: %s", error->message);
	}

	dun_connect_data->dun_context = context;

	g_main_loop_quit (gl.loop);
}

static void
_dun_notify_tty_hangup_cb (NMBluez5DunContext *context,
                           gpointer user_data)
{
	_LOGI ("dun-connect: notified TTY hangup");
}

static gboolean
_timeout_cb (gpointer user_data)
{
	DunConnectData *dun_connect_data = user_data;

	_LOGI ("timeout");
	dun_connect_data->timeout_id = 0;
	if (dun_connect_data->cancellable)
		g_cancellable_cancel (dun_connect_data->cancellable);
	return G_SOURCE_REMOVE;
}

static gboolean
_sig_xxx_cb (DunConnectData *dun_connect_data, int sigid)
{
	_LOGI ("signal %s received", sigid == SIGTERM ? "SIGTERM" : "SIGINT");
	g_main_loop_quit (gl.loop);
	return G_SOURCE_CONTINUE;
}

static gboolean
_sig_term_cb (gpointer user_data)
{
	return _sig_xxx_cb (user_data, SIGTERM);
}

static gboolean
_sig_int_cb (gpointer user_data)
{
	return _sig_xxx_cb (user_data, SIGINT);
}
#endif

static int
do_dun_connect (const MainCmdInfo *main_cmd_info)
{
#if WITH_BLUEZ5_DUN
	gs_unref_object GCancellable *cancellable = NULL;
	gs_free_error GError *error = NULL;
	const char *adapter;
	const char *remote;
	DunConnectData dun_connect_data = { };

	if (gl.argc < 4) {
		_LOGE ("missing arguments \"adapter\" and \"remote\"");
		return -1;
	}

	adapter = gl.argv[2];
	remote = gl.argv[3];

	cancellable = g_cancellable_new ();
	dun_connect_data.cancellable = cancellable;

	if (!nm_bluez5_dun_connect (adapter,
	                            remote,
	                            cancellable,
	                            _dun_connect_cb,
	                            &dun_connect_data,
	                            _dun_notify_tty_hangup_cb,
	                            &dun_connect_data,
	                            &error)) {
		_LOGE ("connect failed to start: %s", error->message);
		return -1;
	}

	dun_connect_data.timeout_id = g_timeout_add (60000, _timeout_cb, &dun_connect_data);

	g_main_loop_run (gl.loop);

	nm_clear_g_source (&dun_connect_data.timeout_id);

	if (dun_connect_data.dun_context) {

		dun_connect_data.sig_term_id = g_unix_signal_add (SIGTERM, _sig_term_cb, &dun_connect_data);
		dun_connect_data.sig_int_id = g_unix_signal_add (SIGINT, _sig_int_cb, &dun_connect_data);

		g_main_loop_run (gl.loop);

		nm_clear_g_source (&dun_connect_data.sig_term_id);
		nm_clear_g_source (&dun_connect_data.sig_int_id);

		nm_bluez5_dun_disconnect (g_steal_pointer (&dun_connect_data.dun_context));
	}

	return 0;
#else
	_LOGE ("compiled without bluetooth DUN support");
	return 1;
#endif
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	static const MainCmdInfo main_cmd_infos[] = {
		{ .name = "dun-connect", .main_func = do_dun_connect, },
	};
	int exit_code = 0;
	guint i;

	if (!g_getenv ("G_MESSAGES_DEBUG"))
		g_setenv ("G_MESSAGES_DEBUG", "all", TRUE);

	nmtst_init_with_logging (&argc, &argv, "DEBUG", "ALL");

	nm_logging_init (NULL, TRUE);

	gl.argv = (const char *const*) argv;
	gl.argc = argc;
	gl.loop = g_main_loop_new (NULL, FALSE);

	_LOGI ("bluetooth test util start");

	gl.argv_cmd = argc >= 2 ? argv[1] : NULL;

	for (i = 0; i < G_N_ELEMENTS (main_cmd_infos); i++) {
		if (nm_streq0 (main_cmd_infos[i].name, gl.argv_cmd)) {
			_LOGD ("start \"%s\"", gl.argv_cmd);
			exit_code = main_cmd_infos[i].main_func (&main_cmd_infos[i]);
			_LOGD ("completed with %d", exit_code);
			break;
		}
	}
	if (gl.argv_cmd && i >= G_N_ELEMENTS (main_cmd_infos)) {
		nm_log_err (LOGD_BT, "invalid command \"%s\"", gl.argv_cmd);
		exit_code = -1;
	}

	nm_clear_pointer (&gl.loop, g_main_loop_unref);

	return exit_code;
}
