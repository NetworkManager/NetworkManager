/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-pptp-service - PPTP VPN integration with NetworkManager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctype.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#include <linux/ppp_defs.h>
#ifndef aligned_u64
#define aligned_u64 unsigned long long __attribute__((aligned(8)))
#endif
#include <linux/if_ppp.h>

#include <nm-setting-vpn.h>
#include <nm-utils.h>

#include "nm-pptp-service.h"
#include "nm-ppp-status.h"

/********************************************************/
/* ppp plugin <-> pptp-service object                   */
/********************************************************/

/* Have to have a separate objec to handle ppp plugin requests since
 * dbus-glib doesn't allow multiple interfaces registed on one GObject.
 */

#define NM_TYPE_PPTP_PPP_SERVICE            (nm_pptp_ppp_service_get_type ())
#define NM_PPTP_PPP_SERVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PPTP_PPP_SERVICE, NMPptpPppService))
#define NM_PPTP_PPP_SERVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PPTP_PPP_SERVICE, NMPptpPppServiceClass))
#define NM_IS_PPTP_PPP_SERVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PPTP_PPP_SERVICE))
#define NM_IS_PPTP_PPP_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_PPTP_PPP_SERVICE))
#define NM_PPTP_PPP_SERVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PPTP_PPP_SERVICE, NMPptpPppServiceClass))

typedef struct {
	GObject parent;
} NMPptpPppService;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*plugin_alive) (NMPptpPppService *self);
	void (*ppp_state) (NMPptpPppService *self, guint32 state);
	void (*ip4_config) (NMPptpPppService *self, GHashTable *config_hash);
} NMPptpPppServiceClass;

GType nm_pptp_ppp_service_get_type (void);

G_DEFINE_TYPE (NMPptpPppService, nm_pptp_ppp_service, G_TYPE_OBJECT)

static gboolean impl_pptp_service_need_secrets (NMPptpPppService *self,
                                                char **out_username,
                                                char **out_password,
                                                GError **err);

static gboolean impl_pptp_service_set_state (NMPptpPppService *self,
                                             guint32 state,
                                             GError **err);

static gboolean impl_pptp_service_set_ip4_config (NMPptpPppService *self,
                                                  GHashTable *config,
                                                  GError **err);

#include "nm-pptp-pppd-service-glue.h"


#define NM_PPTP_PPP_SERVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_PPTP_PPP_SERVICE, NMPptpPppServicePrivate))

typedef struct {
	char username[100];
	char domain[100];
	char password[100];
} NMPptpPppServicePrivate;

enum {
	PLUGIN_ALIVE,
	PPP_STATE,
	IP4_CONFIG,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

NMPptpPppService *
nm_pptp_ppp_service_new (void)
{
	DBusGConnection *connection;
	DBusGProxy *proxy;
	GError *error = NULL;
	gboolean success = FALSE;
	guint request_name_result;
	GObject *object;

	object = g_object_new (NM_TYPE_PPTP_PPP_SERVICE, NULL);

	dbus_connection_set_change_sigpipe (TRUE);

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
	if (!connection) {
		nm_warning ("Could not get the system bus.  Make sure "
		            "the message bus daemon is running!  Message: %s",
		            error->message);
		g_error_free (error);
		g_object_unref (object);
		return NULL;
	}

	proxy = dbus_g_proxy_new_for_name (connection,
								"org.freedesktop.DBus",
								"/org/freedesktop/DBus",
								"org.freedesktop.DBus");

	if (dbus_g_proxy_call (proxy, "RequestName", &error,
					   G_TYPE_STRING, NM_DBUS_SERVICE_PPTP_PPP,
					   G_TYPE_UINT, 0,
					   G_TYPE_INVALID,
					   G_TYPE_UINT, &request_name_result,
					   G_TYPE_INVALID)) {
		dbus_g_connection_register_g_object (connection, NM_DBUS_PATH_PPTP_PPP, object);
		success = TRUE;
	} else {
		nm_warning ("Could not register D-Bus service name.  Message: %s", error->message);
		g_error_free (error);
		g_object_unref (object);
		object = NULL;
	}

	g_object_unref (proxy);
	return (NMPptpPppService *) object;
}

static void
nm_pptp_ppp_service_init (NMPptpPppService *self)
{
}

static void
finalize (GObject *object)
{
	NMPptpPppServicePrivate *priv = NM_PPTP_PPP_SERVICE_GET_PRIVATE (object);

	/* Get rid of the cached username and password */
	memset (priv->username, 0, sizeof (priv->username));
	memset (priv->domain, 0, sizeof (priv->domain));
	memset (priv->password, 0, sizeof (priv->password));
}

static void
nm_pptp_ppp_service_class_init (NMPptpPppServiceClass *service_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (service_class);

	g_type_class_add_private (service_class, sizeof (NMPptpPppServicePrivate));

	/* virtual methods */
	object_class->finalize = finalize;

	/* Signals */
	signals[PLUGIN_ALIVE] = 
		g_signal_new ("plugin-alive", 
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMPptpPppServiceClass, plugin_alive),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	signals[PPP_STATE] = 
		g_signal_new ("ppp-state", 
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMPptpPppServiceClass, ppp_state),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__UINT,
		              G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[IP4_CONFIG] = 
		g_signal_new ("ip4-config", 
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMPptpPppServiceClass, ip4_config),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__POINTER,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (service_class),
									 &dbus_glib_nm_pptp_pppd_service_object_info);
}

static gboolean
nm_pptp_ppp_service_cache_credentials (NMPptpPppService *self,
                                       NMConnection *connection,
                                       GError **error)
{
	NMPptpPppServicePrivate *priv = NM_PPTP_PPP_SERVICE_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	const char *username, *password, *domain;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);

	memset (priv->username, 0, sizeof (priv->username));
	memset (priv->domain, 0, sizeof (priv->domain));
	memset (priv->password, 0, sizeof (priv->password));

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	if (!s_vpn) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             "Could not find secrets (connection invalid, no vpn setting).");
		return FALSE;
	}

	/* Username; try PPTP specific username first, then generic username */
	username = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_USER);
	if (username && strlen (username)) {
		/* FIXME: This check makes about 0 sense. */
		if (!username || !strlen (username)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
			             "%s",
			             "Invalid VPN username.");
			return FALSE;
		}
	} else {
		username = nm_setting_vpn_get_user_name (s_vpn);
		if (!username || !strlen (username)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
			             "%s",
			             "Missing VPN username.");
			return FALSE;
		}
	}

	password = nm_setting_vpn_get_secret (s_vpn, NM_PPTP_KEY_PASSWORD);
	if (!password || !strlen (password)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             "Missing or invalid VPN password.");
		return FALSE;
	}

	domain = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_DOMAIN);
	if (domain && strlen (domain))
		memcpy (priv->domain, domain, strlen (domain));

	memcpy (priv->username, username, strlen (username));
	memcpy (priv->password, password, strlen (password));
	return TRUE;
}

static gboolean
impl_pptp_service_need_secrets (NMPptpPppService *self,
                                char **out_username,
                                char **out_password,
                                GError **error)
{
	NMPptpPppServicePrivate *priv = NM_PPTP_PPP_SERVICE_GET_PRIVATE (self);

	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);

	if (!strlen (priv->username) || !strlen (priv->password)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             "No cached credentials.");
		goto error;
	}

	/* Success */
	if (strlen (priv->domain))
		*out_username = g_strdup_printf ("%s\\\\%s", priv->domain, priv->username);
	else
		*out_username = g_strdup (priv->username);
	*out_password = g_strdup (priv->password);
	return TRUE;

error:
	return FALSE;
}

static gboolean
impl_pptp_service_set_state (NMPptpPppService *self,
                             guint32 pppd_state,
                             GError **err)
{
	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);
	g_signal_emit (G_OBJECT (self), signals[PPP_STATE], 0, pppd_state);
	return TRUE;
}

static gboolean
impl_pptp_service_set_ip4_config (NMPptpPppService *self,
                                  GHashTable *config_hash,
                                  GError **err)
{
	nm_info ("PPTP service (IP Config Get) reply received.");
	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);

	/* Just forward the pppd plugin config up to our superclass; no need to modify it */
	g_signal_emit (G_OBJECT (self), signals[IP4_CONFIG], 0, config_hash);

	return TRUE;
}


/********************************************************/
/* The VPN plugin service                               */
/********************************************************/

G_DEFINE_TYPE (NMPptpPlugin, nm_pptp_plugin, NM_TYPE_VPN_PLUGIN)

typedef struct {
	GPid pid;
	guint32 ppp_timeout_handler;
	NMPptpPppService *service;
	NMConnection *connection;
} NMPptpPluginPrivate;

#define NM_PPTP_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_PPTP_PLUGIN, NMPptpPluginPrivate))

#define NM_PPTP_PPPD_PLUGIN PLUGINDIR "/nm-pptp-pppd-plugin.so"
#define NM_PPTP_WAIT_PPPD 10000 /* 10 seconds */
#define PPTP_SERVICE_SECRET_TRIES "pptp-service-secret-tries"

typedef struct {
	const char *name;
	GType type;
	gboolean required;
} ValidProperty;

static ValidProperty valid_properties[] = {
	{ NM_PPTP_KEY_GATEWAY,           G_TYPE_STRING, TRUE },
	{ NM_PPTP_KEY_USER,              G_TYPE_STRING, FALSE },
	{ NM_PPTP_KEY_DOMAIN,            G_TYPE_STRING, FALSE },
	{ NM_PPTP_KEY_REFUSE_EAP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REFUSE_PAP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REFUSE_CHAP,       G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REFUSE_MSCHAP,     G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REFUSE_MSCHAPV2,   G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REQUIRE_MPPE,      G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REQUIRE_MPPE_40,   G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REQUIRE_MPPE_128,  G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_MPPE_STATEFUL,     G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_NOBSDCOMP,         G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_NODEFLATE,         G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_NO_VJ_COMP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_LCP_ECHO_FAILURE,  G_TYPE_UINT, FALSE },
	{ NM_PPTP_KEY_LCP_ECHO_INTERVAL, G_TYPE_UINT, FALSE },
	{ NULL,                          G_TYPE_NONE,   FALSE }
};

static ValidProperty valid_secrets[] = {
	{ NM_PPTP_KEY_PASSWORD,          G_TYPE_STRING, FALSE },
	{ NULL,                          G_TYPE_NONE,   FALSE }
};

static gboolean
validate_gateway (const char *gateway)
{
	const char *p = gateway;

	if (!gateway || !strlen (gateway))
		return FALSE;

	/* Ensure it's a valid DNS name or IP address */
	p = gateway;
	while (*p) {
		if (!isalnum (*p) && (*p != '-') && (*p != '.'))
			return FALSE;
		p++;
	}
	return TRUE;
}

typedef struct ValidateInfo {
	ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		ValidProperty prop = info->table[i];
		long int tmp;

		if (strcmp (prop.name, key))
			continue;

		switch (prop.type) {
		case G_TYPE_STRING:
			if (   !strcmp (prop.name, NM_PPTP_KEY_GATEWAY)
			    && !validate_gateway (value)) {
				g_set_error (info->error,
				             NM_VPN_PLUGIN_ERROR,
				             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				             "invalid gateway '%s'",
				             key);
				return;
			}
			return; /* valid */
		case G_TYPE_UINT:
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0)
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "invalid integer property '%s'",
			             key);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "invalid boolean property '%s' (not yes or no)",
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "unhandled property '%s' type %s",
			             key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "property '%s' invalid or not supported",
		             key);
	}
}

static gboolean
nm_pptp_properties_validate (NMSettingVPN *s_vpn,
                             GError **error)
{
	ValidateInfo info = { &valid_properties[0], error, FALSE };
	int i;

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "No VPN configuration options.");
		return FALSE;
	}

	if (*error)
		return FALSE;

	/* Ensure required properties exist */
	for (i = 0; valid_properties[i].name; i++) {
		ValidProperty prop = valid_properties[i];
		const char *value;

		if (!prop.required)
			continue;

		value = nm_setting_vpn_get_data_item (s_vpn, prop.name);
		if (!value || !strlen (value)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "Missing required option '%s'.",
			             prop.name);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
nm_pptp_secrets_validate (NMSettingVPN *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_secrets[0], error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "No VPN secrets!");
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

static void
pppd_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMPptpPlugin *plugin = NM_PPTP_PLUGIN (user_data);
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	guint error = 0;

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			nm_warning ("pppd exited with error code %d", error);
	}
	else if (WIFSTOPPED (status))
		nm_warning ("pppd stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		nm_warning ("pppd died with signal %d", WTERMSIG (status));
	else
		nm_warning ("pppd died from an unknown cause");

	/* Reap child if needed. */
	waitpid (priv->pid, NULL, WNOHANG);
	priv->pid = 0;

	/* Must be after data->state is set since signals use data->state */
	switch (error) {
	case 16:
		/* hangup */
		// FIXME: better failure reason
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	case 2:
		/* Couldn't log in due to bad user/pass */
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
		break;
	case 1:
		/* Other error (couldn't bind to address, etc) */
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		break;
	}

	nm_vpn_plugin_set_state (NM_VPN_PLUGIN (plugin), NM_VPN_SERVICE_STATE_STOPPED);
}

static inline const char *
nm_find_pppd (void)
{
	static const char *pppd_binary_paths[] =
		{
			"/sbin/pppd",
			"/usr/sbin/pppd",
			"/usr/local/sbin/pppd",
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

static inline const char *
nm_find_pptp (void)
{
	static const char *pptp_binary_paths[] =
		{
			"/sbin/pptp",
			"/usr/sbin/pptp",
			"/usr/local/sbin/pptp",
			NULL
		};

	const char  **pptp_binary = pptp_binary_paths;

	while (*pptp_binary != NULL) {
		if (g_file_test (*pptp_binary, G_FILE_TEST_EXISTS))
			break;
		pptp_binary++;
	}

	return *pptp_binary;
}

static gboolean
pppd_timed_out (gpointer user_data)
{
	NMPptpPlugin *plugin = NM_PPTP_PLUGIN (user_data);

	nm_warning ("Looks like pppd didn't initialize our dbus module");
	nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT);

	return FALSE;
}

static void
free_pppd_args (GPtrArray *args)
{
	int i;

	if (!args)
		return;

	for (i = 0; i < args->len; i++)
		g_free (g_ptr_array_index (args, i));
	g_ptr_array_free (args, TRUE);
}

static GPtrArray *
construct_pppd_args (NMPptpPlugin *plugin,
                     NMSettingVPN *s_vpn,
                     const char *pppd,
                     GError **error)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	NMPptpPppServicePrivate *service_priv = NULL;
	GPtrArray *args = NULL;
	const char *value, *pptp_binary;
	char *ipparam, *tmp;

	pptp_binary = nm_find_pptp ();
	if (!pptp_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             "Could not find pptp client binary.");
		return FALSE;
	}

	args = g_ptr_array_new ();
	g_ptr_array_add (args, (gpointer) g_strdup (pppd));

	/* PPTP options */
	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_GATEWAY);
	if (!value || !strlen (value)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             "Missing VPN gateway.");
		goto error;
	}

	ipparam = g_strdup_printf ("nm-pptp-service-%d", getpid ());

	g_ptr_array_add (args, (gpointer) g_strdup ("pty"));
	tmp = g_strdup_printf ("%s %s --nolaunchpppd --logstring %s", pptp_binary, value, ipparam);
	g_ptr_array_add (args, (gpointer) tmp);

	if (getenv ("NM_PPP_DEBUG"))
		g_ptr_array_add (args, (gpointer) g_strdup ("debug"));

	/* PPP options */
	g_ptr_array_add (args, (gpointer) g_strdup ("ipparam"));
	g_ptr_array_add (args, (gpointer) ipparam);

	g_ptr_array_add (args, (gpointer) g_strdup ("nodetach"));
	g_ptr_array_add (args, (gpointer) g_strdup ("lock"));
	g_ptr_array_add (args, (gpointer) g_strdup ("usepeerdns"));
	g_ptr_array_add (args, (gpointer) g_strdup ("noipdefault"));
	g_ptr_array_add (args, (gpointer) g_strdup ("nodefaultroute"));

	if (priv->service)
		service_priv = NM_PPTP_PPP_SERVICE_GET_PRIVATE (priv->service);
	if (service_priv && strlen (service_priv->username)) {
		g_ptr_array_add (args, (gpointer) g_strdup ("user"));
		g_ptr_array_add (args, (gpointer) g_strdup (service_priv->username));
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_EAP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-eap"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_PAP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-pap"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_CHAP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-chap"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_MSCHAP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-mschap"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_MSCHAPV2);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-mschap-v2"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REQUIRE_MPPE);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("require-mppe"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REQUIRE_MPPE_40);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("require-mppe-40"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REQUIRE_MPPE_128);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("require-mppe-128"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_MPPE_STATEFUL);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("mppe-stateful"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_NOBSDCOMP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("nobsdcomp"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_NODEFLATE);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("nodeflate"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_NO_VJ_COMP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("novj"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_LCP_ECHO_FAILURE);
	if (value && strlen (value)) {
		long int tmp_int;

		/* Convert to integer and then back to string for security's sake
		 * because strtol ignores some leading and trailing characters.
		 */
		errno = 0;
		tmp_int = strtol (value, NULL, 10);
		if (errno == 0) {
			g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-failure"));
			g_ptr_array_add (args, (gpointer) g_strdup_printf ("%ld", tmp_int));
		} else {
			nm_warning ("failed to convert lcp-echo-failure value '%s'", value);
		}
	} else {
		g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-failure"));
		g_ptr_array_add (args, (gpointer) g_strdup ("0"));
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_LCP_ECHO_INTERVAL);
	if (value && strlen (value)) {
		long int tmp_int;

		/* Convert to integer and then back to string for security's sake
		 * because strtol ignores some leading and trailing characters.
		 */
		errno = 0;
		tmp_int = strtol (value, NULL, 10);
		if (errno == 0) {
			g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-interval"));
			g_ptr_array_add (args, (gpointer) g_strdup_printf ("%ld", tmp_int));
		} else {
			nm_warning ("failed to convert lcp-echo-interval value '%s'", value);
		}
	} else {
		g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-interval"));
		g_ptr_array_add (args, (gpointer) g_strdup ("0"));
	}

	g_ptr_array_add (args, (gpointer) g_strdup ("plugin"));
	g_ptr_array_add (args, (gpointer) g_strdup (NM_PPTP_PPPD_PLUGIN));

	g_ptr_array_add (args, NULL);

	return args;

error:
	free_pppd_args (args);
	return FALSE;
}

static gboolean
nm_pptp_start_pppd_binary (NMPptpPlugin *plugin,
                           NMSettingVPN *s_vpn,
                           GError **error)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	GPid pid;
	const char *pppd_binary;
	GPtrArray *pppd_argv;

	pppd_binary = nm_find_pppd ();
	if (!pppd_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             "Could not find the pppd binary.");
		return FALSE;
	}

	pppd_argv = construct_pppd_args (plugin, s_vpn, pppd_binary, error);
	if (!pppd_argv)
		return FALSE;

	if (!g_spawn_async (NULL, (char **) pppd_argv->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, error)) {
		g_ptr_array_free (pppd_argv, TRUE);
		return FALSE;
	}
	free_pppd_args (pppd_argv);

	nm_info ("pppd started with pid %d", pid);

	NM_PPTP_PLUGIN_GET_PRIVATE (plugin)->pid = pid;
	g_child_watch_add (pid, pppd_watch_cb, plugin);

	priv->ppp_timeout_handler = g_timeout_add (NM_PPTP_WAIT_PPPD, pppd_timed_out, plugin);

	return TRUE;
}

static void
remove_timeout_handler (NMPptpPlugin *plugin)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	
	if (priv->ppp_timeout_handler) {
		g_source_remove (priv->ppp_timeout_handler);
		priv->ppp_timeout_handler = 0;
	}
}

static void
service_plugin_alive_cb (NMPptpPppService *service,
                         NMPptpPlugin *plugin)
{
	remove_timeout_handler (plugin);
}

static void
service_ppp_state_cb (NMPptpPppService *service,
                      guint32 ppp_state,
                      NMPptpPlugin *plugin)
{
	NMVPNServiceState plugin_state = nm_vpn_plugin_get_state (NM_VPN_PLUGIN (plugin));

	switch (ppp_state) {
	case NM_PPP_STATUS_DEAD:
	case NM_PPP_STATUS_DISCONNECT:
		if (plugin_state == NM_VPN_SERVICE_STATE_STARTED)
			nm_vpn_plugin_disconnect (NM_VPN_PLUGIN (plugin), NULL);
		else if (plugin_state == NM_VPN_SERVICE_STATE_STARTING)
			nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		break;
	}
}

static void
nm_gvalue_destroy (gpointer data)
{
	g_value_unset ((GValue *) data);
	g_slice_free (GValue, data);
}

static GValue *
nm_gvalue_dup (const GValue *value)
{
	GValue *dup;

	dup = g_slice_new0 (GValue);
	g_value_init (dup, G_VALUE_TYPE (value));
	g_value_copy (value, dup);

	return dup;
}

static void
copy_hash (gpointer key, gpointer value, gpointer user_data)
{
	g_hash_table_insert ((GHashTable *) user_data, g_strdup (key), nm_gvalue_dup ((GValue *) value));
}

static GValue *
get_pptp_gw_address_as_gvalue (NMConnection *connection)
{
	NMSettingVPN *s_vpn;
	const char *tmp;
	GValue *value;
	struct in_addr addr;

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	if (!s_vpn) {
		nm_warning ("couldn't get VPN setting");
		return NULL;
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_GATEWAY);
	if (!tmp || !strlen (tmp)) {
		nm_warning ("couldn't get PPTP VPN gateway IP address");
		return NULL;
	}
	
	errno = 0;
	if (inet_pton (AF_INET, tmp, &addr) <= 0) {
		nm_warning ("couldn't convert PPTP VPN gateway IP address '%s' (%d)", tmp, errno);
		return NULL;
	}
	
	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_UINT);
	g_value_set_uint (value, (guint32) addr.s_addr);

	return value;
}

static void
service_ip4_config_cb (NMPptpPppService *service,
                       GHashTable *config_hash,
                       NMPptpPlugin *plugin)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	GHashTable *hash;
	GValue *value;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, nm_gvalue_destroy);
	g_hash_table_foreach (config_hash, copy_hash, hash);

	/* Insert the external VPN gateway into the table, which the pppd plugin
	 * simply doesn't know about.
	 */
	value = get_pptp_gw_address_as_gvalue (priv->connection);
	if (value)
		g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_GATEWAY), value);

	nm_vpn_plugin_set_ip4_config (NM_VPN_PLUGIN (plugin), hash);

	g_hash_table_destroy (hash);
}

static gboolean
real_connect (NMVPNPlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	NMSettingVPN *s_vpn;

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	g_assert (s_vpn);

	if (!nm_pptp_properties_validate (s_vpn, error))
		return FALSE;

	if (!nm_pptp_secrets_validate (s_vpn, error))
		return FALSE;

	/* Start our pppd plugin helper service */
	if (priv->service)
		g_object_unref (priv->service);
	if (priv->connection) {
		g_object_unref (priv->connection);
		priv->connection = NULL;
	}

	priv->service = nm_pptp_ppp_service_new ();
	if (!priv->service) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             "Could not start pppd plugin helper service.");
		return FALSE;
	}

	priv->connection = g_object_ref (connection);

	g_signal_connect (G_OBJECT (priv->service), "plugin-alive", G_CALLBACK (service_plugin_alive_cb), plugin);
	g_signal_connect (G_OBJECT (priv->service), "ppp-state", G_CALLBACK (service_ppp_state_cb), plugin);
	g_signal_connect (G_OBJECT (priv->service), "ip4-config", G_CALLBACK (service_ip4_config_cb), plugin);

	/* Cache the username and password so we can relay the secrets to the pppd
	 * plugin when it asks for them.
	 */
	if (!nm_pptp_ppp_service_cache_credentials (priv->service, connection, error))
		return FALSE;

	if (!nm_pptp_start_pppd_binary (NM_PPTP_PLUGIN (plugin), s_vpn, error))
		return FALSE;

	return TRUE;
}

static gboolean
real_need_secrets (NMVPNPlugin *plugin,
                   NMConnection *connection,
                   char **setting_name,
                   GError **error)
{
	NMSettingVPN *s_vpn;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));

	if (!nm_setting_vpn_get_secret (s_vpn, NM_PPTP_KEY_PASSWORD)) {
		*setting_name = NM_SETTING_VPN_SETTING_NAME;
		return TRUE;
	}

	return FALSE;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	return FALSE;
}

static gboolean
real_disconnect (NMVPNPlugin   *plugin,
			  GError       **err)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid) {
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
		else
			kill (priv->pid, SIGKILL);

		nm_info ("Terminated ppp daemon with PID %d.", priv->pid);
		priv->pid = 0;
	}

	if (priv->connection) {
		g_object_unref (priv->connection);
		priv->connection = NULL;
	}

	if (priv->service) {
		g_object_unref (priv->service);
		priv->service = NULL;
	}

	return TRUE;
}

static void
state_changed_cb (GObject *object, NMVPNServiceState state, gpointer user_data)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (object);

	switch (state) {
	case NM_VPN_SERVICE_STATE_STARTED:
		remove_timeout_handler (NM_PPTP_PLUGIN (object));
		break;
	case NM_VPN_SERVICE_STATE_UNKNOWN:
	case NM_VPN_SERVICE_STATE_INIT:
	case NM_VPN_SERVICE_STATE_SHUTDOWN:
	case NM_VPN_SERVICE_STATE_STOPPING:
	case NM_VPN_SERVICE_STATE_STOPPED:
		remove_timeout_handler (NM_PPTP_PLUGIN (object));
		if (priv->connection) {
			g_object_unref (priv->connection);
			priv->connection = NULL;
		}
		if (priv->service) {
			g_object_unref (priv->service);
			priv->service = NULL;
		}
		break;
	default:
		break;
	}
}

static void
dispose (GObject *object)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (object);

	if (priv->connection)
		g_object_unref (priv->connection);

	if (priv->service)
		g_object_unref (priv->service);

	G_OBJECT_CLASS (nm_pptp_plugin_parent_class)->dispose (object);
}

static void
nm_pptp_plugin_init (NMPptpPlugin *plugin)
{
}

static void
nm_pptp_plugin_class_init (NMPptpPluginClass *pptp_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (pptp_class);
	NMVPNPluginClass *parent_class = NM_VPN_PLUGIN_CLASS (pptp_class);

	g_type_class_add_private (object_class, sizeof (NMPptpPluginPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	parent_class->connect    = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect = real_disconnect;
}

NMPptpPlugin *
nm_pptp_plugin_new (void)
{
	NMPptpPlugin *plugin;

	plugin = g_object_new (NM_TYPE_PPTP_PLUGIN,
	                       NM_VPN_PLUGIN_DBUS_SERVICE_NAME,
	                       NM_DBUS_SERVICE_PPTP,
	                       NULL);
	if (plugin)
		g_signal_connect (G_OBJECT (plugin), "state-changed", G_CALLBACK (state_changed_cb), NULL);
	return plugin;
}

static void
quit_mainloop (NMPptpPlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	NMPptpPlugin *plugin;
	GMainLoop *main_loop;

	g_type_init ();

	plugin = nm_pptp_plugin_new ();
	if (!plugin)
		exit (EXIT_FAILURE);

	main_loop = g_main_loop_new (NULL, FALSE);

	g_signal_connect (plugin, "quit",
				   G_CALLBACK (quit_mainloop),
				   main_loop);

	g_main_loop_run (main_loop);

	g_main_loop_unref (main_loop);
	g_object_unref (plugin);

	exit (EXIT_SUCCESS);
}
