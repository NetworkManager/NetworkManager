/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "nm-supplicant.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "wpa_ctrl.h"


/****************************************************************************/
/* WPA Supplicant control stuff
 *
 * Originally from:
 *
 *	wpa_supplicant wrapper
 *
 *	Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

#define WPA_SUPPLICANT_GLOBAL_SOCKET		LOCALSTATEDIR"/run/wpa_supplicant-global"
#define WPA_SUPPLICANT_CONTROL_SOCKET		LOCALSTATEDIR"/run/wpa_supplicant"
#define WPA_SUPPLICANT_NUM_RETRIES		20
#define WPA_SUPPLICANT_RETRY_TIME_US		100*1000

G_DEFINE_TYPE (NMSupplicant, nm_supplicant, G_TYPE_OBJECT)

#define NM_SUPPLICANT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SUPPLICANT, NMSupplicantPrivate))

typedef struct {
	GPid pid;
	GSource *watch;
	GSource *status;
	GSource *timeout;
	struct wpa_ctrl *ctrl;

	char *socket_path;
	char *message;
} NMSupplicantPrivate;

enum {
	STATE_CHANGED,
	DOWN,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

NMSupplicant *
nm_supplicant_new (void)
{
	return (NMSupplicant *) g_object_new (NM_TYPE_SUPPLICANT, NULL);
}

void
nm_supplicant_remove_timeout (NMSupplicant *self)
{
	NMSupplicantPrivate *priv = NM_SUPPLICANT_GET_PRIVATE (self);

	/* Remove any pending timeouts on the request */
	if (priv->timeout != NULL) {
		g_source_destroy (priv->timeout);
		priv->timeout = NULL;
	}
}

void
nm_supplicant_down (NMSupplicant *self)
{
	NMSupplicantPrivate *priv;

	g_return_if_fail (NM_IS_SUPPLICANT (self));

	priv = NM_SUPPLICANT_GET_PRIVATE (self);

	if (priv->pid > 0) {
		kill (priv->pid, SIGTERM);
		priv->pid = -1;
	}

	if (priv->watch) {
		g_source_destroy (priv->watch);
		priv->watch = NULL;
	}

	if (priv->status) {
		g_source_destroy (priv->status);
		priv->status = NULL;
	}

	if (priv->ctrl) {
		wpa_ctrl_close (priv->ctrl);
		priv->ctrl = NULL;
	}

	nm_supplicant_remove_timeout (self);

	/* HACK: should be fixed in wpa_supplicant.  Will likely
	 * require accomodations for selinux.
	 */
	unlink (WPA_SUPPLICANT_GLOBAL_SOCKET);
	unlink (priv->socket_path);

	g_signal_emit (self, signals[DOWN], 0);
}

static void
supplicant_watch_done (gpointer user_data)
{
	NMSupplicantPrivate *priv = NM_SUPPLICANT_GET_PRIVATE (user_data);

	priv->watch = NULL;
}

static void
supplicant_watch_cb (GPid pid,
                     gint status,
                     gpointer user_data)
{
	NMSupplicant *self = NM_SUPPLICANT (user_data);

	if (WIFEXITED (status))
		nm_warning ("wpa_supplicant exited with error code %d", WEXITSTATUS (status));
	else if (WIFSTOPPED (status)) 
		nm_warning ("wpa_supplicant stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		nm_warning ("wpa_supplicant died with signal %d", WTERMSIG (status));
	else
		nm_warning ("wpa_supplicant died from an unknown cause");

	nm_supplicant_down (self);
}

/*
 * supplicant_child_setup
 *
 * Set the process group ID of the newly forked process
 *
 */
static void
supplicant_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);
}

gboolean
nm_supplicant_exec (NMSupplicant *self,
				GMainContext *ctx)
{
	gboolean success;
	char *argv[4];
	GPid pid;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_SUPPLICANT (self), FALSE);

	argv[0] = WPA_SUPPLICANT_BIN;
	argv[1] = "-g";
	argv[2] = WPA_SUPPLICANT_GLOBAL_SOCKET;
	argv[3] = NULL;

	success = g_spawn_async ("/", argv, NULL, 0, &supplicant_child_setup, NULL, &pid, &err);
	if (!success) {
		if (err) {
			nm_warning ("Couldn't start wpa_supplicant. Error: (%d) %s", err->code, err->message);
			g_error_free (err);
		} else
			nm_warning ("Couldn't start wpa_supplicant due to an unknown error.");
	} else {
		NMSupplicantPrivate *priv = NM_SUPPLICANT_GET_PRIVATE (self);

		/* Monitor the child process so we know when it stops */
		priv->pid = pid;
		if (priv->watch)
			g_source_destroy (priv->watch);

		priv->watch = g_child_watch_source_new (pid);
		g_source_set_callback (priv->watch,
						   (GSourceFunc) supplicant_watch_cb,
						   self,
						   supplicant_watch_done);
		g_source_attach (priv->watch, ctx);
		g_source_unref (priv->watch);
	}

	return success;
}

gboolean
nm_supplicant_interface_init (NMSupplicant *self, 
						const char *iface,
						const char *supplicant_driver)
{
	NMSupplicantPrivate *priv;
	struct wpa_ctrl *ctrl = NULL;
	int tries;

	g_return_val_if_fail (NM_IS_SUPPLICANT (self), FALSE);
	g_return_val_if_fail (iface != NULL, FALSE);

	/* Try to open wpa_supplicant's global control socket */
	for (tries = 0; tries < WPA_SUPPLICANT_NUM_RETRIES && !ctrl; tries++) {
		ctrl = wpa_ctrl_open (WPA_SUPPLICANT_GLOBAL_SOCKET, NM_RUN_DIR);
		g_usleep (WPA_SUPPLICANT_RETRY_TIME_US);
	}

	if (!ctrl) {
		nm_info ("Error opening supplicant global control interface.");
		return FALSE;
	}

	/* wpa_cli -g/var/run/wpa_supplicant-global interface_add eth1 "" wext /var/run/wpa_supplicant */
	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
										"INTERFACE_ADD %s\t\t%s\t" WPA_SUPPLICANT_CONTROL_SOCKET "\t",
										iface, supplicant_driver)) {
		wpa_ctrl_close (ctrl);
		return FALSE;
	}

	wpa_ctrl_close (ctrl);

	priv = NM_SUPPLICANT_GET_PRIVATE (self);

	/* Get a control socket to wpa_supplicant for this interface.
	 * Try a couple times to work around naive socket naming
	 * in wpa_ctrl that sometimes collides with stale ones.
	 */
	priv->socket_path = g_strdup_printf (WPA_SUPPLICANT_CONTROL_SOCKET "/%s", iface);

	while (!priv->ctrl && (tries++ < 10))
		priv->ctrl = wpa_ctrl_open (priv->socket_path, NM_RUN_DIR);

	if (!priv->ctrl)
		nm_info ("Error opening control interface to supplicant.");

	return priv->ctrl != NULL;
}

static void
supplicant_status_done (gpointer user_data)
{
	NMSupplicantPrivate *priv = NM_SUPPLICANT_GET_PRIVATE (user_data);

	priv->status = NULL;
}

static void
supplicant_state_changed (NMSupplicant *self, gboolean up)
{
	nm_info ("Supplicant state changed: %d", up);
	g_signal_emit (self, signals[STATE_CHANGED], 0, up);
}

#define MESSAGE_LEN	2048

static gboolean
supplicant_status_cb (GIOChannel *source,
                      GIOCondition condition,
                      gpointer user_data)
{
	NMSupplicant *self = NM_SUPPLICANT (user_data);
	NMSupplicantPrivate *priv = NM_SUPPLICANT_GET_PRIVATE (self);
	size_t len = MESSAGE_LEN;

	wpa_ctrl_recv (priv->ctrl, priv->message, &len);
	priv->message[len] = '\0';

	if (strstr (priv->message, WPA_EVENT_CONNECTED) != NULL)
		supplicant_state_changed (self, TRUE);
	else if (strstr (priv->message, WPA_EVENT_DISCONNECTED) != NULL)
		supplicant_state_changed (self, FALSE);

	return TRUE;
}

typedef struct {
	NMSupplicant *supplicant;
	GSourceFunc callback;
	gpointer user_data;
} TimeoutInfo;

static void
supplicant_timeout_done (gpointer user_data)
{
	TimeoutInfo *info = (TimeoutInfo *) user_data;

	NM_SUPPLICANT_GET_PRIVATE (info->supplicant)->timeout = NULL;

	g_free (info);
}

static void
supplicant_timeout_cb (gpointer user_data)
{
	TimeoutInfo *info = (TimeoutInfo *) user_data;

	info->callback (info->user_data);
}

gboolean
nm_supplicant_monitor_start (NMSupplicant *self,
					    GMainContext *context,
					    guint32 timeout,
					    GSourceFunc timeout_cb,
					    gpointer user_data)
{
	NMSupplicantPrivate *priv;
	int fd;
	GIOChannel *channel;

	g_return_val_if_fail (NM_IS_SUPPLICANT (self), FALSE);

	priv = NM_SUPPLICANT_GET_PRIVATE (self);

	/* register network event monitor */
	if (wpa_ctrl_attach (priv->ctrl) != 0)
		return FALSE;

	if ((fd = wpa_ctrl_get_fd (priv->ctrl)) < 0)
		return FALSE;

	channel = g_io_channel_unix_new (fd);
	priv->status = g_io_create_watch (channel, G_IO_IN);
	g_io_channel_unref (channel);
	g_source_set_callback (priv->status,
					   (GSourceFunc) supplicant_status_cb,
					   self,
					   supplicant_status_done);
	g_source_attach (priv->status, context);
	g_source_unref (priv->status);

	if (timeout_cb) {
		TimeoutInfo *info;

		info = g_new (TimeoutInfo, 1);
		info->supplicant = self;
		info->callback = timeout_cb;
		info->user_data = user_data;

		priv->timeout = g_timeout_source_new (timeout * 1000);
		g_source_set_callback (priv->timeout,
						   (GSourceFunc) supplicant_timeout_cb,
						   info,
						   supplicant_timeout_done);
		g_source_attach (priv->timeout, context);
		g_source_unref (priv->timeout);
	}

	return TRUE;
}

struct wpa_ctrl *
nm_supplicant_get_ctrl (NMSupplicant *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT (self), NULL);

	return NM_SUPPLICANT_GET_PRIVATE (self)->ctrl;
}

/*****************************************************************************/

static void
nm_supplicant_init (NMSupplicant *supplicant)
{
	NMSupplicantPrivate *priv = NM_SUPPLICANT_GET_PRIVATE (supplicant);

	priv->message = g_malloc (MESSAGE_LEN);
}

static void
finalize (GObject *object)
{
	NMSupplicantPrivate *priv = NM_SUPPLICANT_GET_PRIVATE (object);

	nm_supplicant_down (NM_SUPPLICANT (object));

	g_free (priv->socket_path);
	g_free (priv->message);

	G_OBJECT_CLASS (nm_supplicant_parent_class)->finalize (object);
}

static void
nm_supplicant_class_init (NMSupplicantClass *supplicant_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (supplicant_class);

	g_type_class_add_private (supplicant_class, sizeof (NMSupplicantPrivate));

	object_class->finalize = finalize;

	/* signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMSupplicantClass, state_changed),
				    NULL, NULL,
				    g_cclosure_marshal_VOID__BOOLEAN,
				    G_TYPE_NONE, 1,
				    G_TYPE_BOOLEAN);

	signals[DOWN] =
		g_signal_new ("down",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMSupplicantClass, down),
				    NULL, NULL,
				    g_cclosure_marshal_VOID__VOID,
				    G_TYPE_NONE, 0);
}
