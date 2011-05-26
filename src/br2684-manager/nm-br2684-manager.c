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
 * Author: Pantelis Koukousoulas <pktoss@gmail.com>
 */

#include <config.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

#include "nm-br2684-manager.h"
#include "nm-setting-adsl.h"
#include "nm-logging.h"

typedef struct {
	gboolean disposed;

	gboolean iface_up;
	guint32  iface_poll_id;
	guint32  br2684_watch_id;
	GPid     pid;
} NMBr2684ManagerPrivate;

#define NM_BR2684_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_BR2684_MANAGER, NMBr2684ManagerPrivate))

G_DEFINE_TYPE (NMBr2684Manager, nm_br2684_manager, G_TYPE_OBJECT)

enum {
	STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	LAST_PROP
};

typedef enum {
	NM_BR2684_MANAGER_ERROR_UNKOWN
} NMBr2684ManagerError;

GQuark
nm_br2684_manager_error_quark (void)
{
	static GQuark quark;

	if (!quark)
		quark = g_quark_from_static_string ("nm_br2684_manager_error");

	return quark;
}

static void
nm_br2684_manager_init (NMBr2684Manager *manager)
{
}

static gboolean
iface_update_cb (gpointer user_data)
{
	NMBr2684Manager *self = NM_BR2684_MANAGER (user_data);
	NMBr2684ManagerPrivate *priv = NM_BR2684_MANAGER_GET_PRIVATE (self);

	gchar *contents = NULL;
	GError *error = NULL;
	const gchar *path = "/sys/devices/virtual/net/nas0/ifindex";

	if (!g_file_get_contents(path, &contents, NULL, &error)) {
		g_clear_error (&error);
		if (priv->iface_up) {
			priv->iface_up = FALSE;
			g_signal_emit(self, signals[STATE_CHANGED], 0, 0);
		}

		return TRUE;
	}

	if (!priv->iface_up) {
		priv->iface_up = TRUE;
		g_signal_emit(self, signals[STATE_CHANGED], 0, 1);
	}

	return TRUE;
}

static GObject *
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	GObject *object;
	NMBr2684Manager *self;
	NMBr2684ManagerPrivate *priv;

	object = G_OBJECT_CLASS (nm_br2684_manager_parent_class)->constructor (type,
	                                                                       n_construct_params,
	                                                                       construct_params);

	if (!object)
		return NULL;

	self = NM_BR2684_MANAGER (object);
	priv = NM_BR2684_MANAGER_GET_PRIVATE (self);

	priv->iface_up = FALSE;
	priv->iface_poll_id = g_timeout_add_seconds(5, iface_update_cb, self);

	return object;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	/* ensure the child is reaped */
	nm_log_dbg (LOGD_BR2684, "waiting for br2684ctl pid %d to exit", pid);
	waitpid (pid, NULL, 0);
	nm_log_dbg (LOGD_BR2684, "br2684ctl pid %d cleaned up", pid);

	return FALSE;
}

static void br2684_cleanup (NMBr2684Manager *manager)
{
	NMBr2684ManagerPrivate *priv;

	g_return_if_fail (NM_IS_BR2684_MANAGER (manager));

	priv = NM_BR2684_MANAGER_GET_PRIVATE (manager);

	nm_log_dbg (LOGD_BR2684, "br2684ctl cleanup (pid: %d)", priv->pid);

	if (priv->br2684_watch_id) {
		g_source_remove (priv->br2684_watch_id);
		priv->br2684_watch_id = 0;
	}

	if (priv->pid) {
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add_seconds (2, ensure_killed, GINT_TO_POINTER (priv->pid));
		else {
			kill (priv->pid, SIGKILL);

			/* ensure the child is reaped */
			nm_log_dbg (LOGD_BR2684, "waiting for br2684ctl pid %d to exit", priv->pid);
			waitpid (priv->pid, NULL, 0);
			nm_log_dbg (LOGD_BR2684, "br2684ctl pid %d cleaned up", priv->pid);
		}

		priv->pid = 0;
	}
}

static void
dispose (GObject *object)
{
	NMBr2684ManagerPrivate *priv = NM_BR2684_MANAGER_GET_PRIVATE (object);

	nm_log_dbg (LOGD_BR2684, "in Br2684Manager::dispose()");

	if (priv->disposed == FALSE) {
		priv->disposed = TRUE;

		br2684_cleanup(NM_BR2684_MANAGER (object));

		if (priv->iface_poll_id) {
			g_source_remove(priv->iface_poll_id);
			priv->iface_poll_id = 0;
		}
	}

	G_OBJECT_CLASS (nm_br2684_manager_parent_class)->dispose (object);
}

static void
nm_br2684_manager_class_init (NMBr2684ManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMBr2684ManagerPrivate));

	object_class->constructor = constructor;
	object_class->dispose = dispose;

	/* signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMBr2684ManagerClass, state_changed),
				    NULL, NULL,
				    g_cclosure_marshal_VOID__UINT,
				    G_TYPE_NONE, 1,
				    G_TYPE_UINT);
}

/************************************************/

static inline const char *
nm_find_br2684ctl (void)
{
	static const char *br2684ctl_binary_paths[] = {
		"/usr/local/sbin/br2684ctl",
		"/usr/sbin/br2684ctl",
		"/sbin/br2684ctl",
	};

	const char  **br2684ctl_binary = br2684ctl_binary_paths;

	while (*br2684ctl_binary != NULL) {
		if (g_file_test (*br2684ctl_binary, G_FILE_TEST_EXISTS))
			break;
		br2684ctl_binary++;
	}

	return *br2684ctl_binary;
}

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

static void
nm_cmd_line_add_int (NMCmdLine *cmd, int i)
{
	char *str;

	str = g_strdup_printf ("%d", i);
	nm_cmd_line_add_string (cmd, str);
	g_free (str);
}

static NMCmdLine *
create_br2684ctl_cmd_line (NMBr2684Manager *manager,
                           NMSettingAdsl *s_adsl,
                           GError **err)
{
	const char *b2864_binary;
	const char *encapsulation, *protocol;
	guint32 vpi, vci;
	gchar *vpivci;
	gboolean is_llc, is_pppoe;
	NMCmdLine *cmd;

	b2864_binary = nm_find_br2684ctl ();
	if (!b2864_binary) {
		g_set_error (err, NM_BR2684_MANAGER_ERROR, NM_BR2684_MANAGER_ERROR,
		                               "Could not find br2684ctl binary.");
	}

	cmd = nm_cmd_line_new ();
	nm_cmd_line_add_string (cmd, b2864_binary);
	nm_cmd_line_add_string (cmd, "-c");
	nm_cmd_line_add_int (cmd, 0); // interface number (for now force nas0)

	encapsulation = nm_setting_adsl_get_encapsulation (s_adsl);
	is_llc = !strcmp (encapsulation, "llc");

	protocol = nm_setting_adsl_get_protocol (s_adsl);
	is_pppoe = !strcmp (protocol, "pppoe");

	vpi = nm_setting_adsl_get_vpi (s_adsl);
	vci = nm_setting_adsl_get_vci (s_adsl);
	vpivci = g_strdup_printf ("%d.%d", vpi, vci);

	nm_cmd_line_add_string (cmd, "-e");
	nm_cmd_line_add_int (cmd, is_llc ? 0 : 1);
	nm_cmd_line_add_string (cmd, "-p");
	nm_cmd_line_add_int (cmd, is_pppoe ? 1 : 0);
	nm_cmd_line_add_string (cmd, "-a");
	nm_cmd_line_add_string (cmd, vpivci);

	g_free (vpivci);

	return cmd;
}

static void
br2684_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);
}

static void
br2684_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMBr2684Manager *manager = NM_BR2684_MANAGER (user_data);
	NMBr2684ManagerPrivate *priv = NM_BR2684_MANAGER_GET_PRIVATE (manager);
	guint err;

	g_assert (pid == priv->pid);

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
	} else if (WIFSTOPPED (status)) {
		nm_log_info (LOGD_BR2684, "br2684ctl pid %d stopped unexpectedly with signal %d", priv->pid, WSTOPSIG (status));
	} else if (WIFSIGNALED (status)) {
		nm_log_info (LOGD_BR2684, "br2684ctl pid %d died with signal %d", priv->pid, WTERMSIG (status));
	} else
		nm_log_info (LOGD_BR2684, "br2684ctl pid %d died from an unknown cause", priv->pid);

	nm_log_dbg (LOGD_BR2684, "br2684ctl pid %d cleaned up", priv->pid);
	priv->pid = 0;
}


/* API Functions */

gboolean nm_br2684_manager_start (NMBr2684Manager *manager,
                                  NMActRequest *req,
                                  guint32 timeout_secs,
                                  GError **err)
{
	NMBr2684ManagerPrivate *priv;
	NMConnection *connection;
	NMSettingAdsl *adsl_setting;
	NMCmdLine *b2684_cmd;
	char *cmd_str;

	g_return_val_if_fail (NM_IS_BR2684_MANAGER (manager), FALSE);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), FALSE);

	priv = NM_BR2684_MANAGER_GET_PRIVATE (manager);
	priv->pid = 0;

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	adsl_setting = (NMSettingAdsl *) nm_connection_get_setting (connection, NM_TYPE_SETTING_ADSL);

	b2684_cmd = create_br2684ctl_cmd_line (manager, adsl_setting, err);
	if (!b2684_cmd)
		goto out;

	g_ptr_array_add (b2684_cmd->array, NULL);

	nm_log_info (LOGD_BR2684, "starting RFC 2684 Bridge");

	cmd_str = nm_cmd_line_to_str (b2684_cmd);
	nm_log_dbg (LOGD_BR2684, "command line: %s", cmd_str);
	g_free (cmd_str);

	priv->pid = 0;
	if (!g_spawn_async (NULL, (char **) b2684_cmd->array->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD,
	                    br2684_child_setup,
	                    NULL, &priv->pid, err))
		goto out;

	nm_log_info (LOGD_BR2684, "br2684ctl started with pid %d", priv->pid);

	priv->br2684_watch_id = g_child_watch_add (priv->pid, (GChildWatchFunc) br2684_watch_cb, manager);

out:
	if (b2684_cmd)
		nm_cmd_line_destroy (b2684_cmd);

	return (priv->pid > 0);
}

NMBr2684Manager *nm_br2684_manager_new ()
{
	return (NMBr2684Manager *) g_object_new (NM_TYPE_BR2684_MANAGER,
	                                         NULL);
}
