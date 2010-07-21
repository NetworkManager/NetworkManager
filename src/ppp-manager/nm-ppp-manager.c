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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2010 Red Hat, Inc.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <net/if.h>
#include <sys/stat.h>

#include <linux/ppp_defs.h>
#ifndef aligned_u64
#define aligned_u64 unsigned long long __attribute__((aligned(8)))
#endif
#include <linux/if_ppp.h>

#include "NetworkManager.h"
#include "nm-glib-compat.h"
#include "nm-ppp-manager.h"
#include "nm-setting-connection.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-gsm.h"
#include "nm-setting-cdma.h"
#include "nm-dbus-manager.h"
#include "nm-logging.h"
#include "nm-marshal.h"

static void impl_ppp_manager_need_secrets (NMPPPManager *manager,
                                           DBusGMethodInvocation *context);

static gboolean impl_ppp_manager_set_state (NMPPPManager *manager,
								    guint32 state,
								    GError **err);

static gboolean impl_ppp_manager_set_ip4_config (NMPPPManager *manager,
									    GHashTable *config,
									    GError **err);

#include "nm-ppp-manager-glue.h"

#define NM_PPPD_PLUGIN PLUGINDIR "/nm-pppd-plugin.so"
#define PPP_MANAGER_SECRET_TRIES "ppp-manager-secret-tries"

typedef struct {
	GPid pid;
	NMDBusManager *dbus_manager;
	char *dbus_path;

	char *parent_iface;

	NMActRequest *act_req;
	DBusGMethodInvocation *pending_secrets_context;

	guint32 ppp_watch_id;
	guint32 ppp_timeout_handler;

	/* Monitoring */
	char *ip_iface;
	int monitor_fd;
	guint monitor_id;
} NMPPPManagerPrivate;

#define NM_PPP_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_PPP_MANAGER, NMPPPManagerPrivate))

G_DEFINE_TYPE (NMPPPManager, nm_ppp_manager, G_TYPE_OBJECT)

enum {
	STATE_CHANGED,
	IP4_CONFIG,
	STATS,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_PARENT_IFACE,
	LAST_PROP
};

typedef enum {
	NM_PPP_MANAGER_ERROR_UNKOWN
} NMPPPManagerError;

GQuark
nm_ppp_manager_error_quark (void)
{
	static GQuark quark;

	if (!quark)
		quark = g_quark_from_static_string ("nm_ppp_manager_error");

	return quark;
}

static void
nm_ppp_manager_init (NMPPPManager *manager)
{
}

static GObject *
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	GObject *object;
	NMPPPManagerPrivate *priv;
	DBusGConnection *connection;
	static guint32 counter = 0;

	object = G_OBJECT_CLASS (nm_ppp_manager_parent_class)->constructor (type,
	                                                                    n_construct_params,
	                                                                    construct_params);
	if (!object)
		return NULL;

	priv = NM_PPP_MANAGER_GET_PRIVATE (object);
	priv->dbus_manager = nm_dbus_manager_get ();
	if (!priv->dbus_manager) {
		g_object_unref (object);
		return NULL;
	}

	connection = nm_dbus_manager_get_connection (priv->dbus_manager);
	priv->dbus_path = g_strdup_printf (NM_DBUS_PATH "/PPP/%d", counter++);
	dbus_g_connection_register_g_object (connection, priv->dbus_path, object);

	return object;
}

static void
dispose (GObject *object)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (object);

	nm_ppp_manager_stop (NM_PPP_MANAGER (object));

	g_object_unref (priv->act_req);
	g_object_unref (priv->dbus_manager);

	G_OBJECT_CLASS (nm_ppp_manager_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (object);

	g_free (priv->ip_iface);
	g_free (priv->parent_iface);

	G_OBJECT_CLASS (nm_ppp_manager_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PARENT_IFACE:
		if (priv->parent_iface)
			g_free (priv->parent_iface);
		priv->parent_iface = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PARENT_IFACE:
		g_value_set_string (value, priv->parent_iface);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ppp_manager_class_init (NMPPPManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMPPPManagerPrivate));

	object_class->constructor = constructor;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_PARENT_IFACE,
		 g_param_spec_string (NM_PPP_MANAGER_PARENT_IFACE,
							"ParentIface",
							"Parent interface",
							NULL,
							G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMPPPManagerClass, state_changed),
				    NULL, NULL,
				    g_cclosure_marshal_VOID__UINT,
				    G_TYPE_NONE, 1,
				    G_TYPE_UINT);

	signals[IP4_CONFIG] =
		g_signal_new ("ip4-config",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMPPPManagerClass, ip4_config),
				    NULL, NULL,
				    _nm_marshal_VOID__STRING_OBJECT,
				    G_TYPE_NONE, 2,
				    G_TYPE_STRING,
				    G_TYPE_OBJECT);

	signals[STATS] =
		g_signal_new ("stats",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMPPPManagerClass, stats),
				    NULL, NULL,
				    _nm_marshal_VOID__UINT_UINT,
				    G_TYPE_NONE, 2,
				    G_TYPE_UINT, G_TYPE_UINT);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (manager_class),
							   &dbus_glib_nm_ppp_manager_object_info);
}

NMPPPManager *
nm_ppp_manager_new (const char *iface)
{
	g_return_val_if_fail (iface != NULL, NULL);

	return (NMPPPManager *) g_object_new (NM_TYPE_PPP_MANAGER,
	                                      NM_PPP_MANAGER_PARENT_IFACE, iface,
	                                      NULL);
}

/*******************************************/

static gboolean
monitor_cb (gpointer user_data)
{
	NMPPPManager *manager = NM_PPP_MANAGER (user_data);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	struct ifpppstatsreq req;

	memset (&req, 0, sizeof (req));
	req.stats_ptr = (caddr_t) &req.stats;

	strncpy (req.ifr__name, priv->ip_iface, sizeof (req.ifr__name));
	if (ioctl (priv->monitor_fd, SIOCGPPPSTATS, &req) < 0) {
		nm_log_warn (LOGD_PPP, "could not read ppp stats: %s", strerror (errno));
	} else {
		g_signal_emit (manager, signals[STATS], 0, 
		               req.stats.p.ppp_ibytes,
		               req.stats.p.ppp_obytes);
	}

	return TRUE;
}

static void
monitor_stats (NMPPPManager *manager)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);

	priv->monitor_fd = socket (AF_INET, SOCK_DGRAM, 0);
	if (priv->monitor_fd > 0)
		priv->monitor_id = g_timeout_add_seconds (5, monitor_cb, manager);
	else
		nm_log_warn (LOGD_PPP, "could not monitor PPP stats: %s", strerror (errno));
}

/*******************************************/

static void
remove_timeout_handler (NMPPPManager *manager)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	
	if (priv->ppp_timeout_handler) {
		g_source_remove (priv->ppp_timeout_handler);
		priv->ppp_timeout_handler = 0;
	}
}

static void
impl_ppp_manager_need_secrets (NMPPPManager *manager,
                               DBusGMethodInvocation *context)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	NMConnection *connection;
	NMSettingConnection *s_con;
	const char *connection_type;
	const char *setting_name;
	guint32 tries;
	GPtrArray *hints = NULL;
	const char *hint1 = NULL, *hint2 = NULL;

	connection = nm_act_request_get_connection (priv->act_req);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	connection_type = nm_setting_connection_get_connection_type (s_con);
	g_assert (connection_type);

	nm_connection_clear_secrets (connection);
	setting_name = nm_connection_need_secrets (connection, &hints);
	if (!setting_name) {
		NMSetting *setting;

		setting = nm_connection_get_setting_by_name (connection, connection_type);
		if (setting) {
			const char *username = NULL;
			const char *password = NULL;

			/* FIXME: push this down to the settings and keep PPP manager generic */
			if (NM_IS_SETTING_PPPOE (setting)) {
				username = nm_setting_pppoe_get_username (NM_SETTING_PPPOE (setting));
				password = nm_setting_pppoe_get_password (NM_SETTING_PPPOE (setting));
			} else if (NM_IS_SETTING_GSM (setting)) {
				username = nm_setting_gsm_get_username (NM_SETTING_GSM (setting));
				password = nm_setting_gsm_get_password (NM_SETTING_GSM (setting));
			} else if (NM_IS_SETTING_CDMA (setting)) {
				username = nm_setting_cdma_get_username (NM_SETTING_CDMA (setting));
				password = nm_setting_cdma_get_password (NM_SETTING_CDMA (setting));
			}

			/* If secrets are not required, send the existing username and password
			 * back to the PPP plugin immediately.
			 */
			priv->pending_secrets_context = context;
			nm_ppp_manager_update_secrets (manager,
			                               priv->parent_iface,
			                               username ? username : "",
			                               password ? password : "",
			                               NULL);
		} else {
			GError *err = NULL;

			g_set_error (&err, NM_PPP_MANAGER_ERROR, NM_PPP_MANAGER_ERROR_UNKOWN,
			             "Missing type-specific setting; no secrets could be found.");
			nm_log_warn (LOGD_PPP, "%s", err->message);
			dbus_g_method_return_error (context, err);
		}
		return;
	}

	/* Extract hints */
	if (hints) {
		if (hints->len > 0)
			hint1 = g_ptr_array_index (hints, 0);
		if (hints->len > 1)
			hint2 = g_ptr_array_index (hints, 1);
	}

	tries = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), PPP_MANAGER_SECRET_TRIES));
	/* Only ask for completely new secrets after retrying them once; some PPP
	 * servers (T-Mobile USA) appear to ask a few times when they actually don't
	 * even care what you pass back.
	 */
	nm_act_request_get_secrets (priv->act_req,
	                            setting_name,
	                            tries > 1 ? TRUE : FALSE,
	                            SECRETS_CALLER_PPP,
	                            hint1,
	                            hint2);
	g_object_set_data (G_OBJECT (connection), PPP_MANAGER_SECRET_TRIES, GUINT_TO_POINTER (++tries));
	priv->pending_secrets_context = context;

	if (hints)
		g_ptr_array_free (hints, TRUE);
}

static gboolean impl_ppp_manager_set_state (NMPPPManager *manager,
								    guint32 state,
								    GError **err)
{
	g_signal_emit (manager, signals[STATE_CHANGED], 0, state);

	return TRUE;
}

static gboolean
impl_ppp_manager_set_ip4_config (NMPPPManager *manager,
						   GHashTable *config_hash,
						   GError **err)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	NMConnection *connection;
	NMSettingPPP *s_ppp;
	NMIP4Config *config;
	NMIP4Address *addr;
	GValue *val;
	int i;

	nm_log_info (LOGD_PPP, "PPP manager(IP Config Get) reply received.");

	remove_timeout_handler (manager);

	config = nm_ip4_config_new ();
	addr = nm_ip4_address_new ();
	nm_ip4_address_set_prefix (addr, 32);

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_GATEWAY);
	if (val) {
		nm_ip4_address_set_gateway (addr, g_value_get_uint (val));
		nm_ip4_config_set_ptp_address (config, g_value_get_uint (val));
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_ADDRESS);
	if (val)
		nm_ip4_address_set_address (addr, g_value_get_uint (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_PREFIX);
	if (val)
		nm_ip4_address_set_prefix (addr, g_value_get_uint (val));

	if (nm_ip4_address_get_address (addr) && nm_ip4_address_get_prefix (addr)) {
		nm_ip4_config_take_address (config, addr);
	} else {
		nm_log_err (LOGD_PPP, "invalid IPv4 address received!");
		nm_ip4_address_unref (addr);
		goto out;
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_DNS);
	if (val) {
		GArray *dns = (GArray *) g_value_get_boxed (val);

		for (i = 0; i < dns->len; i++)
			nm_ip4_config_add_nameserver (config, g_array_index (dns, guint, i));
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_WINS);
	if (val) {
		GArray *wins = (GArray *) g_value_get_boxed (val);

		for (i = 0; i < wins->len; i++)
			nm_ip4_config_add_wins (config, g_array_index (wins, guint, i));
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_INTERFACE);
	if (!val || !G_VALUE_HOLDS_STRING (val)) {
		nm_log_err (LOGD_PPP, "no interface received!");
		goto out;
	}
	priv->ip_iface = g_value_dup_string (val);

	/* Got successful IP4 config; obviously the secrets worked */
	connection = nm_act_request_get_connection (priv->act_req);
	g_assert (connection);
	g_object_set_data (G_OBJECT (connection), PPP_MANAGER_SECRET_TRIES, NULL);

	/* Merge in custom MTU */
	s_ppp = (NMSettingPPP *) nm_connection_get_setting (connection, NM_TYPE_SETTING_PPP);
	if (s_ppp) {
		guint32 mtu = nm_setting_ppp_get_mtu (s_ppp);

		if (mtu)
			nm_ip4_config_set_mtu (config, mtu);
	}

	/* Push the IP4 config up to the device */
	g_signal_emit (manager, signals[IP4_CONFIG], 0, priv->ip_iface, config);

	monitor_stats (manager);

 out:
	g_object_unref (config);

	return TRUE;
}

/*******************************************/



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

/*******************************************/

static inline const char *
nm_find_pppd (void)
{
	static const char *pppd_binary_paths[] = {
		"/usr/local/sbin/pppd",
		"/usr/sbin/pppd",
		"/sbin/pppd",
		NULL
	};

	const char  **pppd_binary = pppd_binary_paths;

	while (*pppd_binary != NULL) {
		if (g_file_test (*pppd_binary, G_FILE_TEST_EXISTS))
			break;
		pppd_binary++;
	}

	return *pppd_binary;
}

static void
ppp_exit_code (guint pppd_exit_status, GPid pid)
{
	const char *msg;

	switch (pppd_exit_status) {
	case  1: 
		msg = "Fatal pppd error"; 
		break;
	case  2: 
		msg = "pppd options error"; 
		break;
	case  3: 
		msg = "No root priv error"; 
		break;
	case  4: 
		msg = "No ppp module error"; 
		break;
	case  5: 
		msg = "pppd received a signal"; 
		break;
	case  6: 
		msg = "Serial port lock failed"; 
		break;
	case  7: 
		msg = "Serial port open failed"; 
		break;
	case  8: 
		msg = "Connect script failed"; 
		break;
	case  9: 
		msg = "Pty program error"; 
		break;
	case 10: 
		msg = "PPP negotiation failed"; 
		break;
	case 11: 
		msg = "Peer didn't authenticatie itself"; 
		break;
	case 12: 
		msg = "Link idle: Idle Seconds reached."; 
		break;
	case 13: 
		msg = "Connect time limit reached."; 
		break;
	case 14: 
		msg = "Callback negotiated, call should come back.";
		break;
	case 15: 
		msg = "Lack of LCP echo responses"; 
		break;
	case 16: 
		msg = "A modem hung up the phone"; 
		break;
	case 17: 
		msg = "Loopback detected"; 
		break;
	case 18: 
		msg = "The init script failed"; 
		break;
	case 19: 
		msg = "Authentication error.\n"
			"We failed to authenticate ourselves to the peer.\n"
			"Maybe bad account or password?";
		break;
	default:
		msg = "Unknown error";
	}

	nm_log_warn (LOGD_PPP, "pppd pid %d exited with error: %s", pid, msg);
}

static void
ppp_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMPPPManager *manager = NM_PPP_MANAGER (user_data);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	guint err;

	g_assert (pid == priv->pid);

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
		if (err != 0)
			ppp_exit_code (err, priv->pid);
	} else if (WIFSTOPPED (status)) {
		nm_log_info (LOGD_PPP, "pppd pid %d stopped unexpectedly with signal %d", priv->pid, WSTOPSIG (status));
	} else if (WIFSIGNALED (status)) {
		nm_log_info (LOGD_PPP, "pppd pid %d died with signal %d", priv->pid, WTERMSIG (status));
	} else
		nm_log_info (LOGD_PPP, "pppd pid %d died from an unknown cause", priv->pid);

	nm_log_dbg (LOGD_PPP, "pppd pid %d cleaned up", priv->pid);
	priv->pid = 0;
	g_signal_emit (manager, signals[STATE_CHANGED], 0, NM_PPP_STATUS_DEAD);
}

static gboolean
pppd_timed_out (gpointer data)
{
	NMPPPManager *manager = NM_PPP_MANAGER (data);

	nm_log_warn (LOGD_PPP, "pppd timed out or didn't initialize our dbus module");
	nm_ppp_manager_stop (manager);

	g_signal_emit (manager, signals[STATE_CHANGED], 0, NM_PPP_STATUS_DEAD);

	return FALSE;
}

static NMCmdLine *
create_pppd_cmd_line (NMPPPManager *self,
                      NMSettingPPP *setting, 
                      NMSettingPPPOE *pppoe,
                      const char *ppp_name,
                      GError **err)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	const char *ppp_binary;
	NMCmdLine *cmd;
	const char *ppp_debug;

	ppp_binary = nm_find_pppd ();
	if (!ppp_binary) {
		g_set_error (err, NM_PPP_MANAGER_ERROR, NM_PPP_MANAGER_ERROR,
				   "Could not find ppp binary.");
		return NULL;
	}

	/* Create pppd command line */
	cmd = nm_cmd_line_new ();
	nm_cmd_line_add_string (cmd, ppp_binary);

	nm_cmd_line_add_string (cmd, "nodetach");
	nm_cmd_line_add_string (cmd, "lock");

	/* NM handles setting the default route */
	nm_cmd_line_add_string (cmd, "nodefaultroute");

	ppp_debug = getenv ("NM_PPP_DEBUG");
	if (ppp_debug)
		nm_cmd_line_add_string (cmd, "debug");

	if (ppp_name) {
		nm_cmd_line_add_string (cmd, "user");
		nm_cmd_line_add_string (cmd, ppp_name);
	}

	if (pppoe) {
		char *dev_str;
		const char *pppoe_service;

		nm_cmd_line_add_string (cmd, "plugin");
		nm_cmd_line_add_string (cmd, "rp-pppoe.so");

		dev_str = g_strdup_printf ("nic-%s", priv->parent_iface);
		nm_cmd_line_add_string (cmd, dev_str);
		g_free (dev_str);

		pppoe_service = nm_setting_pppoe_get_service (pppoe);
		if (pppoe_service) {
			nm_cmd_line_add_string (cmd, "rp_pppoe_service");
			nm_cmd_line_add_string (cmd, pppoe_service);
		}
	} else {
		nm_cmd_line_add_string (cmd, priv->parent_iface);
		/* Don't send some random address as the local address */
		nm_cmd_line_add_string (cmd, "noipdefault");
	}

	if (nm_setting_ppp_get_baud (setting))
		nm_cmd_line_add_int (cmd, nm_setting_ppp_get_baud (setting));

	/* noauth by default, because we certainly don't have any information
	 * with which to verify anything the peer gives us if we ask it to
	 * authenticate itself, which is what 'auth' really means.
	 */
	nm_cmd_line_add_string (cmd, "noauth");

	if (nm_setting_ppp_get_refuse_eap (setting))
		nm_cmd_line_add_string (cmd, "refuse-eap");
	if (nm_setting_ppp_get_refuse_pap (setting))
		nm_cmd_line_add_string (cmd, "refuse-pap");
	if (nm_setting_ppp_get_refuse_chap (setting))
		nm_cmd_line_add_string (cmd, "refuse-chap");
	if (nm_setting_ppp_get_refuse_mschap (setting))
		nm_cmd_line_add_string (cmd, "refuse-mschap");
	if (nm_setting_ppp_get_refuse_mschapv2 (setting))
		nm_cmd_line_add_string (cmd, "refuse-mschap-v2");
	if (nm_setting_ppp_get_nobsdcomp (setting))
		nm_cmd_line_add_string (cmd, "nobsdcomp");
	if (nm_setting_ppp_get_nodeflate (setting))
		nm_cmd_line_add_string (cmd, "nodeflate");
	if (nm_setting_ppp_get_require_mppe (setting))
		nm_cmd_line_add_string (cmd, "require-mppe");
	if (nm_setting_ppp_get_require_mppe_128 (setting))
		nm_cmd_line_add_string (cmd, "require-mppe-128");
	if (nm_setting_ppp_get_mppe_stateful (setting))
		nm_cmd_line_add_string (cmd, "mppe-stateful");
	if (nm_setting_ppp_get_crtscts (setting))
		nm_cmd_line_add_string (cmd, "crtscts");

	/* Always ask for DNS, we don't have to use them if the connection
	 * overrides the returned servers.
	 */
	nm_cmd_line_add_string (cmd, "usepeerdns");

	if (nm_setting_ppp_get_mru (setting)) {
		nm_cmd_line_add_string (cmd, "mru");
		nm_cmd_line_add_int (cmd, nm_setting_ppp_get_mru (setting));
	}

	if (nm_setting_ppp_get_mtu (setting)) {
		nm_cmd_line_add_string (cmd, "mtu");
		nm_cmd_line_add_int (cmd, nm_setting_ppp_get_mtu (setting));
	}

	nm_cmd_line_add_string (cmd, "lcp-echo-failure");
	nm_cmd_line_add_int (cmd, nm_setting_ppp_get_lcp_echo_failure (setting));

	nm_cmd_line_add_string (cmd, "lcp-echo-interval");
	nm_cmd_line_add_int (cmd, nm_setting_ppp_get_lcp_echo_interval (setting));

	nm_cmd_line_add_string (cmd, "ipparam");
	nm_cmd_line_add_string (cmd, priv->dbus_path);

	nm_cmd_line_add_string (cmd, "plugin");
	nm_cmd_line_add_string (cmd, NM_PPPD_PLUGIN);

	return cmd;
}

static void
pppd_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);
}

static void
pppoe_fill_defaults (NMSettingPPP *setting)
{
	if (!nm_setting_ppp_get_mtu (setting))
		g_object_set (setting, NM_SETTING_PPP_MTU, (guint32) 1492, NULL);

	if (!nm_setting_ppp_get_mru (setting))
		g_object_set (setting, NM_SETTING_PPP_MRU, (guint32) 1492, NULL);

	if (!nm_setting_ppp_get_lcp_echo_interval (setting))
		g_object_set (setting, NM_SETTING_PPP_LCP_ECHO_INTERVAL, (guint32) 20, NULL);

	if (!nm_setting_ppp_get_lcp_echo_failure (setting))
		g_object_set (setting, NM_SETTING_PPP_LCP_ECHO_FAILURE, (guint32) 3, NULL);

	g_object_set (setting,
			    NM_SETTING_PPP_NOAUTH, TRUE,
			    NM_SETTING_PPP_NODEFLATE, TRUE,
			    NULL);

	/* FIXME: These commented settings should be set as well, update NMSettingPPP first. */
#if 0
	setting->noipdefault = TRUE;
	setting->default_asyncmap = TRUE;
	setting->defaultroute = TRUE;
	setting->hide_password = TRUE;
	setting->noaccomp = TRUE;
	setting->nopcomp = TRUE;
	setting->novj = TRUE;
	setting->novjccomp = TRUE;
#endif
}

gboolean
nm_ppp_manager_start (NMPPPManager *manager,
                      NMActRequest *req,
                      const char *ppp_name,
                      guint32 timeout_secs,
                      GError **err)
{
	NMPPPManagerPrivate *priv;
	NMConnection *connection;
	NMSettingPPP *s_ppp;
	gboolean s_ppp_created = FALSE;
	NMSettingPPPOE *pppoe_setting;
	NMCmdLine *ppp_cmd;
	char *cmd_str;
	struct stat st;
	int ignored;

	g_return_val_if_fail (NM_IS_PPP_MANAGER (manager), FALSE);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), FALSE);

	priv = NM_PPP_MANAGER_GET_PRIVATE (manager);

	priv->pid = 0;

	/* Make sure /dev/ppp exists (bgo #533064) */
	if (stat ("/dev/ppp", &st) || !S_ISCHR (st.st_mode))
		ignored = system ("/sbin/modprobe ppp_generic");

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	s_ppp = (NMSettingPPP *) nm_connection_get_setting (connection, NM_TYPE_SETTING_PPP);
	if (!s_ppp) {
		/* If the PPP settings are all default we may not have a PPP setting yet,
		 * so just make a default one here.
		 */
		s_ppp = NM_SETTING_PPP (nm_setting_ppp_new ());
		s_ppp_created = TRUE;
	}
	
	pppoe_setting = (NMSettingPPPOE *) nm_connection_get_setting (connection, NM_TYPE_SETTING_PPPOE);
	if (pppoe_setting)
		pppoe_fill_defaults (s_ppp);

	ppp_cmd = create_pppd_cmd_line (manager, s_ppp, pppoe_setting, ppp_name, err);
	if (!ppp_cmd)
		goto out;

	g_ptr_array_add (ppp_cmd->array, NULL);

	nm_log_info (LOGD_PPP, "starting PPP connection");

	cmd_str = nm_cmd_line_to_str (ppp_cmd);
	nm_log_dbg (LOGD_PPP, "command line: %s", cmd_str);
	g_free (cmd_str);

	priv->pid = 0;
	if (!g_spawn_async (NULL, (char **) ppp_cmd->array->pdata, NULL,
					G_SPAWN_DO_NOT_REAP_CHILD,
					pppd_child_setup,
					NULL, &priv->pid, err)) {
		goto out;
	}

	nm_log_info (LOGD_PPP, "pppd started with pid %d", priv->pid);

	priv->ppp_watch_id = g_child_watch_add (priv->pid, (GChildWatchFunc) ppp_watch_cb, manager);
	priv->ppp_timeout_handler = g_timeout_add_seconds (timeout_secs, pppd_timed_out, manager);
	priv->act_req = g_object_ref (req);

 out:
	if (s_ppp_created)
		g_object_unref (s_ppp);

	if (ppp_cmd)
		nm_cmd_line_destroy (ppp_cmd);

	return priv->pid > 0;
}

void
nm_ppp_manager_update_secrets (NMPPPManager *manager,
                               const char *device,
                               const char *username,
                               const char *password,
                               const char *error_message)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);

	g_return_if_fail (NM_IS_PPP_MANAGER (manager));
	g_return_if_fail (device != NULL);
	g_return_if_fail (priv->pending_secrets_context != NULL);

	if (error_message) {
		g_return_if_fail (username == NULL);
		g_return_if_fail (password == NULL);
	} else {
		g_return_if_fail (username != NULL);
		g_return_if_fail (password != NULL);
	}

	if (error_message) {
		GError *err = NULL;

		g_set_error (&err, NM_PPP_MANAGER_ERROR, NM_PPP_MANAGER_ERROR_UNKOWN, "%s", error_message);
		nm_log_warn (LOGD_PPP, "%s", error_message);
		dbus_g_method_return_error (priv->pending_secrets_context, err);
		g_error_free (err);
	} else {
		/* This is sort of a hack but...
		   pppd plugin only ever needs username and password.
		   Passing the full connection there would mean some bloat:
		   the plugin would need to link against libnm-util just to parse this.
		   So instead, let's just send what it needs */

		dbus_g_method_return (priv->pending_secrets_context, username, password);
	}
	priv->pending_secrets_context = NULL;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	/* ensure the child is reaped */
	nm_log_dbg (LOGD_PPP, "waiting for pppd pid %d to exit", pid);
	waitpid (pid, NULL, 0);
	nm_log_dbg (LOGD_PPP, "pppd pid %d cleaned up", pid);

	return FALSE;
}

void
nm_ppp_manager_stop (NMPPPManager *manager)
{
	NMPPPManagerPrivate *priv;

	g_return_if_fail (NM_IS_PPP_MANAGER (manager));

	priv = NM_PPP_MANAGER_GET_PRIVATE (manager);

	if (priv->monitor_id) {
		g_source_remove (priv->monitor_id);
		priv->monitor_id = 0;
	}

	if (priv->monitor_fd) {
		/* Get the stats one last time */
		monitor_cb (manager);
		close (priv->monitor_fd);
		priv->monitor_fd = 0;
	}

	if (priv->ppp_timeout_handler) {
		g_source_remove (priv->ppp_timeout_handler);
		priv->ppp_timeout_handler = 0;
	}

	if (priv->ppp_watch_id) {
		g_source_remove (priv->ppp_watch_id);
		priv->ppp_watch_id = 0;
	}

	if (priv->pid) {
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add_seconds (2, ensure_killed, GINT_TO_POINTER (priv->pid));
		else {
			kill (priv->pid, SIGKILL);

			/* ensure the child is reaped */
			nm_log_dbg (LOGD_PPP, "waiting for pppd pid %d to exit", priv->pid);
			waitpid (priv->pid, NULL, 0);
			nm_log_dbg (LOGD_PPP, "pppd pid %d cleaned up", priv->pid);
		}

		priv->pid = 0;
	}
}
