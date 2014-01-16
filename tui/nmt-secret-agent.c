/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2011-2013 Red Hat, Inc.
 * Copyright 2011 Giovanni Campagna <scampa.giovanni@gmail.com>
 */

/**
 * SECTION:nmt-secret-agent
 * @short_description: A secret agent
 *
 * #NmtSecretAgent is the secret agent used by nmtui-connect.
 *
 * This is a stripped-down version of gnome-shell's ShellNetworkAgent,
 * with bits of the corresponding JavaScript code squished down into
 * it. It is intended to eventually be generic enough that it could
 * replace ShellNetworkAgent.
 */

#include "config.h"

#include <string.h>
#include <dbus/dbus-glib.h>
#include <glib/gi18n-lib.h>

#include <nm-utils.h>

#include "nmt-secret-agent.h"
#include "nmt-newt.h"

G_DEFINE_TYPE (NmtSecretAgent, nmt_secret_agent, NM_TYPE_SECRET_AGENT)

#define NMT_SECRET_AGENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_SECRET_AGENT, NmtSecretAgentPrivate))

enum {
	REQUEST_SECRETS,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	NmtSecretAgent                *self;

	gchar                         *request_id;
	NMConnection                  *connection;
	gchar                        **hints;
	NMSecretAgentGetSecretsFunc    callback;
	gpointer                       callback_data;
} NmtSecretAgentRequest;

typedef struct {
	/* <char *request_id, NmtSecretAgentRequest *request> */
	GHashTable *requests;
} NmtSecretAgentPrivate;

static void
nmt_secret_agent_request_free (gpointer data)
{
	NmtSecretAgentRequest *request = data;

	g_object_unref (request->self);
	g_object_unref (request->connection);
	g_strfreev (request->hints);

	g_slice_free (NmtSecretAgentRequest, request);
}

static void
nmt_secret_agent_init (NmtSecretAgent *agent)
{
	NmtSecretAgentPrivate *priv = NMT_SECRET_AGENT_GET_PRIVATE (agent);

	priv->requests = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                        g_free, nmt_secret_agent_request_free);
}

static void
nmt_secret_agent_finalize (GObject *object)
{
	NmtSecretAgentPrivate *priv = NMT_SECRET_AGENT_GET_PRIVATE (object);
	GError *error;
	GHashTableIter iter;
	gpointer key;
	gpointer value;

	error = g_error_new (NM_SECRET_AGENT_ERROR,
	                     NM_SECRET_AGENT_ERROR_AGENT_CANCELED,
	                     "The secret agent is going away");

	g_hash_table_iter_init (&iter, priv->requests);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		NmtSecretAgentRequest *request = value;

		request->callback (NM_SECRET_AGENT (object),
		                   request->connection,
		                   NULL, error,
		                   request->callback_data);
	}

	g_hash_table_destroy (priv->requests);
	g_error_free (error);

	G_OBJECT_CLASS (nmt_secret_agent_parent_class)->finalize (object);
}

static gboolean
strv_has (gchar **haystack,
          gchar  *needle)
{
	gchar *iter;

	for (iter = *haystack; iter; iter++) {
		if (g_strcmp0 (iter, needle) == 0)
			return TRUE;
	}

	return FALSE;
}

/**
 * NmtSecretAgentSecret:
 * @name: the user-visible name of the secret. Eg, "WEP Passphrase".
 * @value: the value of the secret
 * @password: %TRUE if this secret represents a password, %FALSE
 *   if it represents non-secret data.
 *
 * A single "secret" being requested.
 */

typedef struct {
	NmtSecretAgentSecret base;

	NMSetting *setting;
	char *property;

	NmtNewtEntryValidator validator;
	gpointer validator_data;
} NmtSecretAgentSecretReal;

static void
nmt_secret_agent_secret_free (NmtSecretAgentSecret *secret)
{
	NmtSecretAgentSecretReal *real = (NmtSecretAgentSecretReal *)secret;

	g_free (secret->name);
	g_free (secret->value);
	g_free (real->property);
	g_clear_object (&real->setting);

	g_slice_free (NmtSecretAgentSecretReal, real);
}

static NmtSecretAgentSecret *
nmt_secret_agent_secret_new (const char *name,
                             NMSetting  *setting,
                             const char *property,
                             gboolean    password)
{
	NmtSecretAgentSecretReal *real;

	real = g_slice_new0 (NmtSecretAgentSecretReal);
	real->base.name = g_strdup (name);
	real->base.password = password;

	if (setting) {
		real->setting = g_object_ref (setting);
		real->property = g_strdup (property);

		g_object_get (setting, property, &real->base.value, NULL);
	}

	return &real->base;
}

static gboolean
add_8021x_secrets (NmtSecretAgentRequest *request,
                   GPtrArray             *secrets)
{
	NMSetting8021x *s_8021x = nm_connection_get_setting_802_1x (request->connection);
	const char *eap_method;
	NmtSecretAgentSecret *secret;

	eap_method = nm_setting_802_1x_get_eap_method (s_8021x, 0);
	if (!eap_method)
		return FALSE;

	if (   !strcmp (eap_method, "md5")
	    || !strcmp (eap_method, "leap")
	    || !strcmp (eap_method, "ttls")
	    || !strcmp (eap_method, "peap")) {
		/* TTLS and PEAP are actually much more complicated, but this complication
		 * is not visible here since we only care about phase2 authentication
		 * (and don't even care of which one)
		 */
		secret = nmt_secret_agent_secret_new (_("Username"),
		                                      NM_SETTING (s_8021x),
		                                      NM_SETTING_802_1X_IDENTITY,
		                                      FALSE);
		g_ptr_array_add (secrets, secret);
		secret = nmt_secret_agent_secret_new (_("Password"),
		                                      NM_SETTING (s_8021x),
		                                      NM_SETTING_802_1X_PASSWORD,
		                                      TRUE);
		g_ptr_array_add (secrets, secret);
		return TRUE;
	}

	if (!strcmp (eap_method, "tls")) {
		secret = nmt_secret_agent_secret_new (_("Identity"),
		                                      NM_SETTING (s_8021x),
		                                      NM_SETTING_802_1X_IDENTITY,
		                                      FALSE);
		g_ptr_array_add (secrets, secret);
		secret = nmt_secret_agent_secret_new (_("Private key password"),
		                                      NM_SETTING (s_8021x),
		                                      NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD,
		                                      TRUE);
		g_ptr_array_add (secrets, secret);
		return TRUE;
	}

	return FALSE;
}

static gboolean
add_wireless_secrets (NmtSecretAgentRequest *request,
                      GPtrArray             *secrets)
{
	NMSettingWirelessSecurity *s_wsec = nm_connection_get_setting_wireless_security (request->connection);
	const char *key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	NmtSecretAgentSecret *secret;

	if (!key_mgmt)
		return FALSE;

	if (!strcmp (key_mgmt, "wpa-none") || !strcmp (key_mgmt, "wpa-psk")) {
		secret = nmt_secret_agent_secret_new (_("Password"),
		                                      NM_SETTING (s_wsec),
		                                      NM_SETTING_WIRELESS_SECURITY_PSK,
		                                      TRUE);
		g_ptr_array_add (secrets, secret);
		return TRUE;
	}

	if (!strcmp (key_mgmt, "none")) {
		int index;
		char *key;

		index = nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec);
		key = g_strdup_printf ("wep-key%d", index);
		secret = nmt_secret_agent_secret_new (_("Key"),
		                                      NM_SETTING (s_wsec),
		                                      key,
		                                      TRUE);
		g_free (key);

#if 0
		nmt_secret_agent_secret_set_validator (secret, static_wep_key_validate,
		                                       nm_setting_wireless_security_get_wep_key_type (s_wsec));
#endif
		g_ptr_array_add (secrets, secret);
		return TRUE;
	}

	if (!strcmp (key_mgmt, "iee8021x")) {
		if (!g_strcmp0 (nm_setting_wireless_security_get_auth_alg (s_wsec), "leap")) {
			secret = nmt_secret_agent_secret_new (_("Password"),
			                                      NM_SETTING (s_wsec),
			                                      NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
			                                      TRUE);
			g_ptr_array_add (secrets, secret);
			return TRUE;
		} else
			return add_8021x_secrets (request, secrets);
	}

	if (!strcmp (key_mgmt, "wpa-eap"))
		return add_8021x_secrets (request, secrets);

	return FALSE;
}

static gboolean
add_pppoe_secrets (NmtSecretAgentRequest *request,
                   GPtrArray             *secrets)
{
	NMSettingPPPOE *s_pppoe = nm_connection_get_setting_pppoe (request->connection);
	NmtSecretAgentSecret *secret;

	secret = nmt_secret_agent_secret_new (_("Username"),
	                                      NM_SETTING (s_pppoe),
	                                      NM_SETTING_PPPOE_USERNAME,
	                                      FALSE);
	g_ptr_array_add (secrets, secret);
	secret = nmt_secret_agent_secret_new (_("Service"),
	                                      NM_SETTING (s_pppoe),
	                                      NM_SETTING_PPPOE_SERVICE,
	                                      FALSE);
	g_ptr_array_add (secrets, secret);
	secret = nmt_secret_agent_secret_new (_("Password"),
	                                      NM_SETTING (s_pppoe),
	                                      NM_SETTING_PPPOE_PASSWORD,
	                                      TRUE);
	g_ptr_array_add (secrets, secret);
	return TRUE;
}

static void
request_secrets_from_ui (NmtSecretAgentRequest *request)
{
	GPtrArray *secrets;
	NmtSecretAgentSecret *secret;
	const char *title;
	char *msg;
	gboolean ok = TRUE;

	secrets = g_ptr_array_new_with_free_func ((GDestroyNotify) nmt_secret_agent_secret_free);

	if (nm_connection_is_type (request->connection, NM_SETTING_WIRELESS_SETTING_NAME)) {
		NMSettingWireless *s_wireless;
		char *ssid;

		s_wireless = nm_connection_get_setting_wireless (request->connection);
		ssid = nm_utils_ssid_to_utf8 (nm_setting_wireless_get_ssid (s_wireless));

		title = _("Authentication required by wireless network");
		msg = g_strdup_printf (_("Passwords or encryption keys are required to access the wireless network '%s'."), ssid);

		ok = add_wireless_secrets (request, secrets);
	} else if (nm_connection_is_type (request->connection, NM_SETTING_WIRED_SETTING_NAME)) {
		NMSettingConnection *s_con;

		s_con = nm_connection_get_setting_connection (request->connection);

		title = _("Wired 802.1X authentication");
		msg = NULL;

		secret = nmt_secret_agent_secret_new (_("Network name"),
		                                      NM_SETTING (s_con),
		                                      NM_SETTING_CONNECTION_ID,
		                                      FALSE);
		g_ptr_array_add (secrets, secret);
		ok = add_8021x_secrets (request, secrets);
	} else if (nm_connection_is_type (request->connection, NM_SETTING_PPPOE_SETTING_NAME)) {
		title = _("DSL authentication");
		msg = NULL;

		ok = add_pppoe_secrets (request, secrets);
	} else if (nm_connection_is_type (request->connection, NM_SETTING_GSM_SETTING_NAME)) {
		NMSettingGsm *s_gsm = nm_connection_get_setting_gsm (request->connection);

		if (strv_has (request->hints, "pin")) {
			title = _("PIN code required");
			msg = g_strdup (_("PIN code is needed for the mobile broadband device"));

			secret = nmt_secret_agent_secret_new (_("PIN"),
			                                      NM_SETTING (s_gsm),
			                                      NM_SETTING_GSM_PIN,
			                                      FALSE);
			g_ptr_array_add (secrets, secret);
		} else {
			title = _("Mobile broadband network password");
			msg = g_strdup_printf (_("A password is required to connect to '%s'."),
			                       nm_connection_get_id (request->connection));

			secret = nmt_secret_agent_secret_new (_("Password"),
			                                      NM_SETTING (s_gsm),
			                                      NM_SETTING_GSM_PASSWORD,
			                                      TRUE);
			g_ptr_array_add (secrets, secret);
		}
	} else if (nm_connection_is_type (request->connection, NM_SETTING_CDMA_SETTING_NAME)) {
		NMSettingCdma *s_cdma = nm_connection_get_setting_cdma (request->connection);

		title = _("Mobile broadband network password");
		msg = g_strdup_printf (_("A password is required to connect to '%s'."),
		                       nm_connection_get_id (request->connection));

		secret = nmt_secret_agent_secret_new (_("Password"),
		                                      NM_SETTING (s_cdma),
		                                      NM_SETTING_CDMA_PASSWORD,
		                                      TRUE);
		g_ptr_array_add (secrets, secret);
	} else if (nm_connection_is_type (request->connection, NM_SETTING_BLUETOOTH_SETTING_NAME)) {
		NMSetting *setting;

		setting = nm_connection_get_setting_by_name (request->connection, NM_SETTING_GSM_SETTING_NAME);
		if (!setting)
			setting = nm_connection_get_setting_by_name (request->connection, NM_SETTING_CDMA_SETTING_NAME);

		title = _("Mobile broadband network password");
		msg = g_strdup_printf (_("A password is required to connect to '%s'."),
		                       nm_connection_get_id (request->connection));

		secret = nmt_secret_agent_secret_new (_("Password"),
		                                      setting,
		                                      "password",
		                                      TRUE);
		g_ptr_array_add (secrets, secret);
	} else
		ok = FALSE;

	if (!ok) {
		g_ptr_array_unref (secrets);
		return;
	}

	g_signal_emit (request->self, signals[REQUEST_SECRETS], 0,
	               request->request_id, title, msg, secrets);
}

static void
nmt_secret_agent_get_secrets (NMSecretAgent                 *agent,
                              NMConnection                  *connection,
                              const gchar                   *connection_path,
                              const gchar                   *setting_name,
                              const gchar                  **hints,
                              NMSecretAgentGetSecretsFlags   flags,
                              NMSecretAgentGetSecretsFunc    callback,
                              gpointer                       callback_data)
{
	NmtSecretAgent *self = NMT_SECRET_AGENT (agent);
	NmtSecretAgentPrivate *priv = NMT_SECRET_AGENT_GET_PRIVATE (self);
	NmtSecretAgentRequest *request;
	NMSettingConnection *s_con;
	const char *connection_type;
	char *request_id;
	GError *error;

	request_id = g_strdup_printf ("%s/%s", connection_path, setting_name);
	if (g_hash_table_lookup (priv->requests, request_id) != NULL) {
		/* We already have a request pending for this (connection, setting) */
		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_INTERNAL_ERROR,
		                     "Request for %s secrets already pending", request_id);
	nope:
		callback (agent, connection, NULL, error, callback_data);
		g_error_free (error);
		g_free (request_id);
		return;
	}

	s_con = nm_connection_get_setting_connection (connection);
	connection_type = nm_setting_connection_get_connection_type (s_con);

	if (!strcmp (connection_type, NM_SETTING_VPN_SETTING_NAME)) {
		/* We don't support VPN secrets yet */
		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_NO_SECRETS,
		                     "VPN secrets not supported");
		goto nope;
	}

	if (!(flags & NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION)) {
		/* We don't do stored passwords */
		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_NO_SECRETS,
		                     "Stored passwords not supported");
		goto nope;
	}

	request = g_slice_new (NmtSecretAgentRequest);
	request->self = g_object_ref (self);
	request->connection = g_object_ref (connection);
	request->hints = g_strdupv ((gchar **)hints);
	request->callback = callback;
	request->callback_data = callback_data;
	request->request_id = request_id;
	g_hash_table_replace (priv->requests, request->request_id, request);

	request_secrets_from_ui (request);
}

static void
gvalue_destroy_notify (gpointer data)
{
	GValue *value = data;
	g_value_unset (value);
	g_slice_free (GValue, value);
}

/**
 * nmt_secret_agent_response:
 * @self: the #NmtSecretAgent
 * @request_id: the request ID being responded to
 * @secrets: (allow-none): the array of secrets, or %NULL
 *
 * Response to a #NmtSecretAgent::get-secrets signal.
 *
 * If the user provided secrets, the caller should set the
 * corresponding <literal>value</literal> fields in the
 * #NmtSecretAgentSecrets (freeing any initial values they had), and
 * pass the array to nmt_secret_agent_response(). If the user
 * cancelled the request, @secrets should be NULL.
 */
void
nmt_secret_agent_response (NmtSecretAgent *self,
                           const char     *request_id,
                           GPtrArray      *secrets)
{
	NmtSecretAgentPrivate *priv;
	NmtSecretAgentRequest *request;
	GHashTable *hash = NULL, *setting_hash;
	GValue *value;
	GError *error = NULL;
	int i;

	g_return_if_fail (NMT_IS_SECRET_AGENT (self));

	priv = NMT_SECRET_AGENT_GET_PRIVATE (self);
	request = g_hash_table_lookup (priv->requests, request_id);
	g_return_if_fail (request != NULL);

	if (secrets) {
		hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, (GDestroyNotify) g_hash_table_unref);
		for (i = 0; i < secrets->len; i++) {
			NmtSecretAgentSecretReal *secret = secrets->pdata[i];

			setting_hash = g_hash_table_lookup (hash, nm_setting_get_name (secret->setting));
			if (!setting_hash) {
				setting_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
				                                      g_free, gvalue_destroy_notify);
				g_hash_table_insert (hash, (char *)nm_setting_get_name (secret->setting),
				                     setting_hash);
			}

			value = g_slice_new0 (GValue);
			g_value_init (value, G_TYPE_STRING);
			g_value_set_string (value, secret->base.value);

			g_hash_table_insert (setting_hash, g_strdup (secret->property), value);
		}
	} else {
		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_USER_CANCELED,
		                     "User cancelled");
	}

	request->callback (NM_SECRET_AGENT (self), request->connection, hash, error, request->callback_data);

	g_clear_pointer (&hash, g_hash_table_unref);
	g_clear_error (&error);
	g_hash_table_remove (priv->requests, request_id);
}

static void
nmt_secret_agent_cancel_get_secrets (NMSecretAgent *agent,
                                     const gchar   *connection_path,
                                     const gchar   *setting_name)
{
	/* We don't support cancellation. Sorry! */
}

static void
nmt_secret_agent_save_secrets (NMSecretAgent                *agent,
                               NMConnection                 *connection,
                               const gchar                  *connection_path,
                               NMSecretAgentSaveSecretsFunc  callback,
                               gpointer                      callback_data)
{
	/* We don't support secret storage */
	callback (agent, connection, NULL, callback_data);}

static void
nmt_secret_agent_delete_secrets (NMSecretAgent                  *agent,
                                 NMConnection                   *connection,
                                 const gchar                    *connection_path,
                                 NMSecretAgentDeleteSecretsFunc  callback,
                                 gpointer                        callback_data)
{
	/* We don't support secret storage, so there's nothing to delete. */
	callback (agent, connection, NULL, callback_data);
}

void
nmt_secret_agent_class_init (NmtSecretAgentClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	NMSecretAgentClass *agent_class = NM_SECRET_AGENT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NmtSecretAgentPrivate));

	gobject_class->finalize = nmt_secret_agent_finalize;

	agent_class->get_secrets = nmt_secret_agent_get_secrets;
	agent_class->cancel_get_secrets = nmt_secret_agent_cancel_get_secrets;
	agent_class->save_secrets = nmt_secret_agent_save_secrets;
	agent_class->delete_secrets = nmt_secret_agent_delete_secrets;

	/**
	 * NmtSecretAgent::request-secrets:
	 * @agent: the #NmtSecretAgent
	 * @request_id: request ID, to eventually pass to
	 *   nmt_secret_agent_response().
	 * @title: a title for the password dialog
	 * @prompt: a prompt message for the password dialog
	 * @secrets: (element-type #NmtSecretAgentSecret): array of secrets
	 *   being requested.
	 *
	 * Emitted when the agent requires secrets from the user.
	 *
	 * The application should create a password dialog (eg,
	 * #NmtPasswordDialog) with the given title and prompt, and an
	 * entry for each element of @secrets. If any of the secrets
	 * already have a <literal>value</literal> filled in, the
	 * corresponding entry should be initialized to that value.
	 *
	 * When the dialog is complete, the app must call
	 * nmt_secret_agent_response() with the results.
	 */
	signals[REQUEST_SECRETS] = g_signal_new ("request-secrets",
	                                         G_TYPE_FROM_CLASS (klass),
	                                         0, 0, NULL, NULL, NULL,
	                                         G_TYPE_NONE,
	                                         4,
	                                         G_TYPE_STRING, /* request_id */
	                                         G_TYPE_STRING, /* title */
	                                         G_TYPE_STRING, /* prompt */
	                                         G_TYPE_PTR_ARRAY);
}

/**
 * nmt_secret_agent_new:
 *
 * Creates a new #NmtSecretAgent.
 *
 * Returns: a new #NmtSecretAgent
 */
NMSecretAgent *
nmt_secret_agent_new (void)
{
	return g_object_new (NMT_TYPE_SECRET_AGENT,
	                     NM_SECRET_AGENT_IDENTIFIER, "nmtui",
	                     NM_SECRET_AGENT_AUTO_REGISTER, FALSE,
	                     NULL);
}
