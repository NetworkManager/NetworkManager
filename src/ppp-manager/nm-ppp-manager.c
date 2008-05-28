/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "nm-ppp-manager.h"
#include "nm-setting-connection.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-dbus-manager.h"
#include "nm-utils.h"
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
#define NM_PPP_WAIT_PPPD 10000 /* 10 seconds */
#define PPP_MANAGER_SECRET_TRIES "ppp-manager-secret-tries"

typedef struct {
	GPid pid;
	NMDBusManager *dbus_manager;

	NMActRequest *act_req;
	DBusGMethodInvocation *pending_secrets_context;

	guint32 ppp_watch_id;
	guint32 ppp_timeout_handler;
} NMPPPManagerPrivate;

#define NM_PPP_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_PPP_MANAGER, NMPPPManagerPrivate))

G_DEFINE_TYPE (NMPPPManager, nm_ppp_manager, G_TYPE_OBJECT)

enum {
	STATE_CHANGED,
	IP4_CONFIG,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

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
	DBusGProxy *proxy;
	guint request_name_result;
	GError *err = NULL;

	object = G_OBJECT_CLASS (nm_ppp_manager_parent_class)->constructor (type,
														   n_construct_params,
														   construct_params);
	if (!object)
		return NULL;

	priv = NM_PPP_MANAGER_GET_PRIVATE (object);
	priv->dbus_manager = nm_dbus_manager_get ();
	connection = nm_dbus_manager_get_connection (priv->dbus_manager);

	proxy = dbus_g_proxy_new_for_name (connection,
								"org.freedesktop.DBus",
								"/org/freedesktop/DBus",
								"org.freedesktop.DBus");

	if (dbus_g_proxy_call (proxy, "RequestName", &err,
					   G_TYPE_STRING, NM_DBUS_SERVICE_PPP,
					   G_TYPE_UINT, 0,
					   G_TYPE_INVALID,
					   G_TYPE_UINT, &request_name_result,
					   G_TYPE_INVALID))
		dbus_g_connection_register_g_object (connection, NM_DBUS_PATH_PPP, object);

	g_object_unref (proxy);

	return object;
}

static void
finalize (GObject *object)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (object);

	nm_ppp_manager_stop (NM_PPP_MANAGER (object));

	g_object_unref (priv->act_req);
	g_object_unref (priv->dbus_manager);

	G_OBJECT_CLASS (nm_ppp_manager_parent_class)->finalize (object);
}

static void
nm_ppp_manager_class_init (NMPPPManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMPPPManagerPrivate));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (manager_class),
							   &dbus_glib_nm_ppp_manager_object_info);

	object_class->constructor = constructor;
	object_class->finalize = finalize;

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
				    nm_marshal_VOID__STRING_OBJECT,
				    G_TYPE_NONE, 2,
				    G_TYPE_STRING,
				    G_TYPE_OBJECT);
}

NMPPPManager *
nm_ppp_manager_new (void)
{
	return (NMPPPManager *) g_object_new (NM_TYPE_PPP_MANAGER, NULL);
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
	const char *setting_name;

	remove_timeout_handler (manager);

	connection = nm_act_request_get_connection (priv->act_req);

	nm_connection_clear_secrets (connection);
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		guint32 tries;

		tries = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), PPP_MANAGER_SECRET_TRIES));
		nm_act_request_request_connection_secrets (priv->act_req, setting_name, tries == 0 ? TRUE : FALSE);
		g_object_set_data (G_OBJECT (connection), PPP_MANAGER_SECRET_TRIES, GUINT_TO_POINTER (++tries));
		priv->pending_secrets_context = context;
	} else {
		GError *err = NULL;

		g_set_error (&err, NM_PPP_MANAGER_ERROR, NM_PPP_MANAGER_ERROR_UNKOWN,
				   "Cleared secrets, but setting didn't need any secrets.");

		nm_warning ("%s", err->message);
		dbus_g_method_return_error (context, err);
	}
}

static gboolean impl_ppp_manager_set_state (NMPPPManager *manager,
								    guint32 state,
								    GError **err)
{
	remove_timeout_handler (manager);
	g_signal_emit (manager, signals[STATE_CHANGED], 0, state);

	return TRUE;
}

static gboolean
impl_ppp_manager_set_ip4_config (NMPPPManager *manager,
						   GHashTable *config_hash,
						   GError **err)
{
	NMIP4Config *config;
	NMSettingIP4Address *addr;
	GValue *val;
	const char *iface;
	int i;

	nm_info ("PPP manager(IP Config Get) reply received.");

	remove_timeout_handler (manager);

	/* FIXME */
/* 	g_source_remove (priv->ipconfig_timeout); */
/* 	priv->ipconfig_timeout = 0; */

	config = nm_ip4_config_new ();
	addr = g_malloc0 (sizeof (NMSettingIP4Address));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_GATEWAY);
	if (val) {
		addr->gateway = g_value_get_uint (val);
		nm_ip4_config_set_ptp_address (config, g_value_get_uint (val));
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_ADDRESS);
	if (val)
		addr->address = g_value_get_uint (val);

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_NETMASK);
	if (val)
		addr->netmask = g_value_get_uint (val);
	else {
		/* If no netmask, default to Class C address */
		addr->netmask = htonl (0x000000FF);
	}

	if (addr->netmask && addr->address) {
		nm_ip4_config_take_address (config, addr);
	} else {
		nm_warning ("%s: invalid IPv4 address or netmask received!", __func__);
		g_free (addr);
		goto out;
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_DNS);
	if (val) {
		GArray *dns = (GArray *) g_value_get_boxed (val);

		for (i = 0; i < dns->len; i++)
			nm_ip4_config_add_nameserver (config, g_array_index (dns, guint, i));
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_INTERFACE);
	if (val)
		iface = g_value_get_string (val);
	else {
		nm_warning ("No interface");
		goto out;
	}

	g_signal_emit (manager, signals[IP4_CONFIG], 0, iface, config);

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
	static const char *pppd_binary_paths[] =
		{
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
ppp_exit_code (guint pppd_exit_status)
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

	g_warning ("pppd exited with error: %s", msg);
}

static void
ppp_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMPPPManager *manager = NM_PPP_MANAGER (user_data);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	guint err;

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
		if (err != 0)
			ppp_exit_code (err);
	} else if (WIFSTOPPED (status))
		g_warning ("ppp stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		g_warning ("ppp died with signal %d", WTERMSIG (status));
	else
		g_warning ("ppp died from an unknown cause");
  
	/* Reap child if needed. */
	waitpid (pid, NULL, WNOHANG);

	priv->pid = 0;

	g_signal_emit (manager, signals[STATE_CHANGED], 0, NM_PPP_STATUS_DEAD);
}

static gboolean
pppd_timed_out (gpointer data)
{
	NMPPPManager *manager = NM_PPP_MANAGER (data);

	nm_warning ("Looks like pppd didn't initialize our dbus module");
	nm_ppp_manager_stop (manager);

	return FALSE;
}

static NMCmdLine *
create_pppd_cmd_line (NMSettingPPP *setting, 
				  NMSettingPPPOE *pppoe,
				  const char *device,
				  GError **err)
{
	const char *ppp_binary;
	NMCmdLine *cmd;

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

	if (pppoe) {
		char *dev_str;

		nm_cmd_line_add_string (cmd, "plugin");
		nm_cmd_line_add_string (cmd, "rp-pppoe.so");

		dev_str = g_strdup_printf ("nic-%s", device);
		nm_cmd_line_add_string (cmd, dev_str);
		g_free (dev_str);

		if (pppoe->service) {
			nm_cmd_line_add_string (cmd, "rp_pppoe_service");
			nm_cmd_line_add_string (cmd, pppoe->service);
		}

		nm_cmd_line_add_string (cmd, "user");
		nm_cmd_line_add_string (cmd, pppoe->username);
	} else {
		nm_cmd_line_add_string (cmd, device);
	}

	if (setting->baud)
		nm_cmd_line_add_int (cmd, setting->baud);

	if (setting->noauth)
		nm_cmd_line_add_string (cmd, "noauth");
	if (setting->refuse_eap)
		nm_cmd_line_add_string (cmd, "refuse-eap");
	if (setting->refuse_pap)
		nm_cmd_line_add_string (cmd, "refuse-pap");
	if (setting->refuse_chap)
		nm_cmd_line_add_string (cmd, "refuse-chap");
	if (setting->refuse_mschap)
		nm_cmd_line_add_string (cmd, "refuse-mschap");
	if (setting->refuse_mschapv2)
		nm_cmd_line_add_string (cmd, "refuse-mschap-v2");
	if (setting->nobsdcomp)
		nm_cmd_line_add_string (cmd, "nobsdcomp");
	if (setting->nodeflate)
		nm_cmd_line_add_string (cmd, "nodeflate");
	if (setting->require_mppe)
		nm_cmd_line_add_string (cmd, "require-mppe");
	if (setting->require_mppe_128)
		nm_cmd_line_add_string (cmd, "require-mppe-128");
	if (setting->mppe_stateful)
		nm_cmd_line_add_string (cmd, "mppe-stateful");
	if (setting->crtscts)
		nm_cmd_line_add_string (cmd, "crtscts");

	/* Always ask for DNS, we don't have to use them if the connection
	 * overrides the returned servers.
	 */
	nm_cmd_line_add_string (cmd, "usepeerdns");

	if (setting->mru) {
		nm_cmd_line_add_string (cmd, "mru");
		nm_cmd_line_add_int (cmd, setting->mru);
	}

	if (setting->mtu) {
		nm_cmd_line_add_string (cmd, "mtu");
		nm_cmd_line_add_int (cmd, setting->mtu);
	}

	if (setting->lcp_echo_failure) {
		nm_cmd_line_add_string (cmd, "lcp-echo-failure");
		nm_cmd_line_add_int (cmd, setting->lcp_echo_failure);
	}

	if (setting->lcp_echo_interval) {
		nm_cmd_line_add_string (cmd, "lcp-echo-interval");
		nm_cmd_line_add_int (cmd, setting->lcp_echo_interval);
	}

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
	if (!setting->mtu)
		setting->mtu = 1492;

	if (!setting->mru)
		setting->mru = 1492;

	if (!setting->lcp_echo_interval)
		setting->lcp_echo_interval = 20;

	if (!setting->lcp_echo_failure)
		setting->lcp_echo_failure = 3;

	setting->noauth = TRUE;
	setting->nodeflate = TRUE;

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
				  const char *device,
				  NMActRequest *req,
				  GError **err)
{
	NMPPPManagerPrivate *priv;
	NMConnection *connection;
	NMSettingPPP *ppp_setting;
	NMSettingPPPOE *pppoe_setting;
	NMCmdLine *ppp_cmd;
	char *cmd_str;
	GSource *ppp_watch;

	g_return_val_if_fail (NM_IS_PPP_MANAGER (manager), FALSE);
	g_return_val_if_fail (device != NULL, FALSE);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), FALSE);

	connection = nm_act_request_get_connection (req);
	ppp_setting = NM_SETTING_PPP (nm_connection_get_setting (connection, NM_TYPE_SETTING_PPP));
	g_return_val_if_fail (ppp_setting != NULL, FALSE);
	
	pppoe_setting = (NMSettingPPPOE *) nm_connection_get_setting (connection, NM_TYPE_SETTING_PPPOE);
	if (pppoe_setting)
		pppoe_fill_defaults (ppp_setting);

	ppp_cmd = create_pppd_cmd_line (ppp_setting, pppoe_setting, device, err);
	if (!ppp_cmd)
		return FALSE;

	g_ptr_array_add (ppp_cmd->array, NULL);

	priv = NM_PPP_MANAGER_GET_PRIVATE (manager);

	nm_info ("Starting pppd connection");

	cmd_str = nm_cmd_line_to_str (ppp_cmd);
	nm_debug ("Command line: %s", cmd_str);
	g_free (cmd_str);

	priv->pid = 0;
	if (!g_spawn_async (NULL, (char **) ppp_cmd->array->pdata, NULL,
					G_SPAWN_DO_NOT_REAP_CHILD,
					pppd_child_setup,
					NULL, &priv->pid, err)) {
		goto out;
	}

	nm_debug ("ppp started with pid %d", priv->pid);

	ppp_watch = g_child_watch_source_new (priv->pid);
	g_source_set_callback (ppp_watch, (GSourceFunc) ppp_watch_cb, manager, NULL);
	g_source_attach (ppp_watch, NULL);
	priv->ppp_watch_id = g_source_get_id (ppp_watch);
	g_source_unref (ppp_watch);

	priv->ppp_timeout_handler = g_timeout_add (NM_PPP_WAIT_PPPD, pppd_timed_out, manager);
	priv->act_req = g_object_ref (req);

 out:
	if (ppp_cmd)
		nm_cmd_line_destroy (ppp_cmd);

	return priv->pid > 0;
}

void
nm_ppp_manager_update_secrets (NMPPPManager *manager,
						 const char *device,
						 NMConnection *connection)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	NMSettingConnection *s_connection;
	NMSettingPPPOE *pppoe_setting;

	g_return_if_fail (NM_IS_PPP_MANAGER (manager));
	g_return_if_fail (device != NULL);
	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (priv->pending_secrets_context != NULL);

	s_connection = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_connection);

	if (strcmp (s_connection->type, NM_SETTING_PPPOE_SETTING_NAME))
		/* Not for us */
		return;

	/* This is sort of a hack but...
	   pppd plugin only ever needs username and password.
	   Passing the full connection there would mean some bloat:
	   the plugin would need to link against libnm-util just to parse this.
	   So instead, let's just send what it needs */

	pppoe_setting = NM_SETTING_PPPOE (nm_connection_get_setting (connection, NM_TYPE_SETTING_PPPOE));
	g_assert (pppoe_setting);

	/* FIXME: Do we have to strdup the values here? */
	dbus_g_method_return (priv->pending_secrets_context, 
					  g_strdup (pppoe_setting->username),
					  g_strdup (pppoe_setting->password));
	priv->pending_secrets_context = NULL;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	return FALSE;
}

void
nm_ppp_manager_stop (NMPPPManager *manager)
{
	NMPPPManagerPrivate *priv;

	g_return_if_fail (NM_IS_PPP_MANAGER (manager));

	priv = NM_PPP_MANAGER_GET_PRIVATE (manager);

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
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
		else
			kill (priv->pid, SIGKILL);

		priv->pid = 0;
	}
}
