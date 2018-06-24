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
 * Copyright 2011-2015 Red Hat, Inc.
 * Copyright 2011 Giovanni Campagna <scampa.giovanni@gmail.com>
 */

/**
 * SECTION:nm-secret-agent-simple
 * @short_description: A simple secret agent for NetworkManager
 *
 * #NMSecretAgentSimple is the secret agent used by nmtui-connect and nmcli.
 *
 * This is a stripped-down version of gnome-shell's ShellNetworkAgent,
 * with bits of the corresponding JavaScript code squished down into
 * it. It is intended to eventually be generic enough that it could
 * replace ShellNetworkAgent.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-vpn-service-plugin.h"

#include "nm-vpn-helpers.h"
#include "nm-secret-agent-simple.h"

G_DEFINE_TYPE (NMSecretAgentSimple, nm_secret_agent_simple, NM_TYPE_SECRET_AGENT_OLD)

#define NM_SECRET_AGENT_SIMPLE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SECRET_AGENT_SIMPLE, NMSecretAgentSimplePrivate))

enum {
	REQUEST_SECRETS,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	NMSecretAgentSimple           *self;

	gchar                         *request_id;
	NMConnection                  *connection;
	gchar                        **hints;
	NMSecretAgentOldGetSecretsFunc callback;
	gpointer                       callback_data;
} NMSecretAgentSimpleRequest;

typedef struct {
	/* <char *request_id, NMSecretAgentSimpleRequest *request> */
	GHashTable *requests;

	char *path;
	gboolean enabled;
} NMSecretAgentSimplePrivate;

static void
nm_secret_agent_simple_request_free (gpointer data)
{
	NMSecretAgentSimpleRequest *request = data;

	g_object_unref (request->self);
	g_object_unref (request->connection);
	g_strfreev (request->hints);

	g_slice_free (NMSecretAgentSimpleRequest, request);
}

static void
nm_secret_agent_simple_init (NMSecretAgentSimple *agent)
{
	NMSecretAgentSimplePrivate *priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (agent);

	priv->requests = g_hash_table_new_full (nm_str_hash, g_str_equal,
	                                        g_free, nm_secret_agent_simple_request_free);
}

static void
nm_secret_agent_simple_finalize (GObject *object)
{
	NMSecretAgentSimplePrivate *priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (object);
	GError *error;
	GHashTableIter iter;
	gpointer key;
	gpointer value;

	error = g_error_new (NM_SECRET_AGENT_ERROR,
	                     NM_SECRET_AGENT_ERROR_AGENT_CANCELED,
	                     "The secret agent is going away");

	g_hash_table_iter_init (&iter, priv->requests);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		NMSecretAgentSimpleRequest *request = value;

		request->callback (NM_SECRET_AGENT_OLD (object),
		                   request->connection,
		                   NULL, error,
		                   request->callback_data);
	}

	g_hash_table_destroy (priv->requests);
	g_error_free (error);

	g_free (priv->path);

	G_OBJECT_CLASS (nm_secret_agent_simple_parent_class)->finalize (object);
}

static gboolean
strv_has (gchar **haystack,
          gchar  *needle)
{
	gchar **iter;

	for (iter = haystack; iter && *iter; iter++) {
		if (g_strcmp0 (*iter, needle) == 0)
			return TRUE;
	}

	return FALSE;
}

/**
 * NMSecretAgentSimpleSecret:
 * @name: the user-visible name of the secret. Eg, "WEP Passphrase".
 * @value: the value of the secret
 * @password: %TRUE if this secret represents a password, %FALSE
 *   if it represents non-secret data.
 *
 * A single "secret" being requested.
 */

typedef struct {
	NMSecretAgentSimpleSecret base;
	NMSetting *setting;
	char *property;
} NMSecretAgentSimpleSecretReal;

static void
nm_secret_agent_simple_secret_free (NMSecretAgentSimpleSecret *secret)
{
	NMSecretAgentSimpleSecretReal *real = (NMSecretAgentSimpleSecretReal *)secret;

	g_free ((char *) secret->pretty_name);
	g_free ((char *) secret->entry_id);
	g_free (secret->value);
	g_free ((char *) secret->vpn_type);
	g_free (real->property);
	g_clear_object (&real->setting);

	g_slice_free (NMSecretAgentSimpleSecretReal, real);
}

static NMSecretAgentSimpleSecret *
nm_secret_agent_simple_secret_new (NMSecretAgentSecretType secret_type,
                                   const char *pretty_name,
                                   NMSetting  *setting,
                                   const char *property,
                                   const char *vpn_type)
{
	NMSecretAgentSimpleSecretReal *real;
	const char *vpn_prefix;
	const char *value;

	nm_assert (property);
	nm_assert (NM_IS_SETTING (setting));

	real = g_slice_new0 (NMSecretAgentSimpleSecretReal);
	*((NMSecretAgentSecretType *) &real->base.secret_type) = secret_type;
	real->setting = g_object_ref (setting);
	real->base.pretty_name = g_strdup (pretty_name);
	real->property = g_strdup (property);
	switch (secret_type) {
	case NM_SECRET_AGENT_SECRET_TYPE_PROPERTY:
	case NM_SECRET_AGENT_SECRET_TYPE_SECRET:
		nm_assert (!vpn_type);
		nm_assert (g_object_class_find_property (G_OBJECT_GET_CLASS (setting), property));
		nm_assert ((secret_type == NM_SECRET_AGENT_SECRET_TYPE_SECRET) == nm_setting_get_secret_flags (setting, property, NULL, NULL));
		real->base.entry_id = g_strdup_printf ("%s.%s", nm_setting_get_name (setting), property);
		g_object_get (setting, property, &real->base.value, NULL);
		real->base.is_secret = (secret_type != NM_SECRET_AGENT_SECRET_TYPE_PROPERTY);
		break;
	case NM_SECRET_AGENT_SECRET_TYPE_VPN_SECRET:
		vpn_prefix = NM_SECRET_AGENT_ENTRY_ID_PREFX_VPN_SECRET;
		value = nm_setting_vpn_get_secret (NM_SETTING_VPN (setting), property);
		real->base.entry_id = g_strdup_printf ("%s%s", vpn_prefix, property);
		nm_assert (vpn_type);
		real->base.vpn_type = g_strdup (vpn_type);
		real->base.value = g_strdup (value);
		real->base.is_secret = TRUE;
		break;
	}
	nm_assert (real->base.entry_id);

	return &real->base;
}

static gboolean
add_8021x_secrets (NMSecretAgentSimpleRequest *request,
                   GPtrArray                  *secrets)
{
	NMSetting8021x *s_8021x = nm_connection_get_setting_802_1x (request->connection);
	const char *eap_method;
	NMSecretAgentSimpleSecret *secret;

	/* If hints are given, then always ask for what the hints require */
	if (request->hints && request->hints[0]) {
		char **iter;

		for (iter = request->hints; *iter; iter++) {
			secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
			                                            _(*iter),
			                                            NM_SETTING (s_8021x),
			                                            *iter,
			                                            NULL);
			g_ptr_array_add (secrets, secret);
		}

		return TRUE;
	}

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
		secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_PROPERTY,
		                                            _("Username"),
		                                            NM_SETTING (s_8021x),
		                                            NM_SETTING_802_1X_IDENTITY,
		                                            NULL);
		g_ptr_array_add (secrets, secret);
		secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
		                                            _("Password"),
		                                            NM_SETTING (s_8021x),
		                                            NM_SETTING_802_1X_PASSWORD,
		                                            NULL);
		g_ptr_array_add (secrets, secret);
		return TRUE;
	}

	if (!strcmp (eap_method, "tls")) {
		secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_PROPERTY,
		                                            _("Identity"),
		                                            NM_SETTING (s_8021x),
		                                            NM_SETTING_802_1X_IDENTITY,
		                                            NULL);
		g_ptr_array_add (secrets, secret);
		secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
		                                            _("Private key password"),
		                                            NM_SETTING (s_8021x),
		                                            NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD,
		                                            NULL);
		g_ptr_array_add (secrets, secret);
		return TRUE;
	}

	return FALSE;
}

static gboolean
add_wireless_secrets (NMSecretAgentSimpleRequest *request,
                      GPtrArray                  *secrets)
{
	NMSettingWirelessSecurity *s_wsec = nm_connection_get_setting_wireless_security (request->connection);
	const char *key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	NMSecretAgentSimpleSecret *secret;

	if (!key_mgmt)
		return FALSE;

	if (!strcmp (key_mgmt, "wpa-none") || !strcmp (key_mgmt, "wpa-psk")) {
		secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
		                                            _("Password"),
		                                            NM_SETTING (s_wsec),
		                                            NM_SETTING_WIRELESS_SECURITY_PSK,
		                                            NULL);
		g_ptr_array_add (secrets, secret);
		return TRUE;
	}

	if (!strcmp (key_mgmt, "none")) {
		int index;
		char *key;

		index = nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec);
		key = g_strdup_printf ("wep-key%d", index);
		secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
		                                            _("Key"),
		                                            NM_SETTING (s_wsec),
		                                            key,
		                                            NULL);
		g_free (key);

		g_ptr_array_add (secrets, secret);
		return TRUE;
	}

	if (!strcmp (key_mgmt, "iee8021x")) {
		if (!g_strcmp0 (nm_setting_wireless_security_get_auth_alg (s_wsec), "leap")) {
			secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
			                                            _("Password"),
			                                            NM_SETTING (s_wsec),
			                                            NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
			                                            NULL);
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
add_pppoe_secrets (NMSecretAgentSimpleRequest *request,
                   GPtrArray                  *secrets)
{
	NMSettingPppoe *s_pppoe = nm_connection_get_setting_pppoe (request->connection);
	NMSecretAgentSimpleSecret *secret;

	secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_PROPERTY,
	                                            _("Username"),
	                                            NM_SETTING (s_pppoe),
	                                            NM_SETTING_PPPOE_USERNAME,
	                                            NULL);
	g_ptr_array_add (secrets, secret);
	secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_PROPERTY,
	                                            _("Service"),
	                                            NM_SETTING (s_pppoe),
	                                            NM_SETTING_PPPOE_SERVICE,
	                                            NULL);
	g_ptr_array_add (secrets, secret);
	secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
	                                            _("Password"),
	                                            NM_SETTING (s_pppoe),
	                                            NM_SETTING_PPPOE_PASSWORD,
	                                            NULL);
	g_ptr_array_add (secrets, secret);
	return TRUE;
}

static NMSettingSecretFlags
get_vpn_secret_flags (NMSettingVpn *s_vpn, const char *secret_name)
{
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;
	GHashTable *vpn_data;

	g_object_get (s_vpn, NM_SETTING_VPN_DATA, &vpn_data, NULL);
	nm_vpn_service_plugin_get_secret_flags (vpn_data, secret_name, &flags);
	g_hash_table_unref (vpn_data);

	return flags;
}

static void
add_vpn_secret_helper (GPtrArray *secrets, NMSettingVpn *s_vpn, const char *name, const char *ui_name)
{
	NMSecretAgentSimpleSecret *secret;
	NMSettingSecretFlags flags;
	int i;

	flags = get_vpn_secret_flags (s_vpn, name);
	if (   flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED
	    || flags & NM_SETTING_SECRET_FLAG_NOT_SAVED) {
		secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_VPN_SECRET,
		                                            ui_name,
		                                            NM_SETTING (s_vpn),
		                                            name,
		                                            nm_setting_vpn_get_service_type (s_vpn));

		/* Check for duplicates */
		for (i = 0; i < secrets->len; i++) {
			NMSecretAgentSimpleSecret *s = secrets->pdata[i];

			if (   s->secret_type == secret->secret_type
			    && nm_streq0 (s->vpn_type, secret->vpn_type)
			    && nm_streq0 (s->entry_id, secret->entry_id)) {
				nm_secret_agent_simple_secret_free (secret);
				return;
			}
		}

		g_ptr_array_add (secrets, secret);
	}
}

#define VPN_MSG_TAG "x-vpn-message:"

static gboolean
add_vpn_secrets (NMSecretAgentSimpleRequest *request,
                 GPtrArray                  *secrets,
                 char                       **msg)
{
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (request->connection);
	const VpnPasswordName *secret_names, *p;
	const char *vpn_msg = NULL;
	char **iter;

	/* If hints are given, then always ask for what the hints require */
	if (request->hints) {
		for (iter = request->hints; *iter; iter++) {
			if (!vpn_msg && g_str_has_prefix (*iter, VPN_MSG_TAG))
				vpn_msg = &(*iter)[NM_STRLEN (VPN_MSG_TAG)];
			else
				add_vpn_secret_helper (secrets, s_vpn, *iter, *iter);
		}
	}

	NM_SET_OUT (msg, g_strdup (vpn_msg));

	/* Now add what client thinks might be required, because hints may be empty or incomplete */
	p = secret_names = nm_vpn_get_secret_names (nm_setting_vpn_get_service_type (s_vpn));
	while (p && p->name) {
		add_vpn_secret_helper (secrets, s_vpn, p->name, _(p->ui_name));
		p++;
	}

	return TRUE;
}

static void
request_secrets_from_ui (NMSecretAgentSimpleRequest *request)
{
	GPtrArray *secrets;
	NMSecretAgentSimplePrivate *priv;
	NMSecretAgentSimpleSecret *secret;
	const char *title;
	char *msg;
	gboolean ok = TRUE;

	priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (request->self);
	g_return_if_fail (priv->enabled);

	/* We only handle requests for connection with @path if set. */
	if (priv->path && !g_str_has_prefix (request->request_id, priv->path)) {
		gs_free_error GError *error = NULL;

		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_FAILED,
		                     "Request for %s secrets doesn't match path %s",
		                     request->request_id, priv->path);
		request->callback (NM_SECRET_AGENT_OLD (request->self), request->connection,
		                   NULL, error, request->callback_data);
		g_hash_table_remove (priv->requests, request->request_id);
		return;
	}

	secrets = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_secret_agent_simple_secret_free);

	if (nm_connection_is_type (request->connection, NM_SETTING_WIRELESS_SETTING_NAME)) {
		NMSettingWireless *s_wireless;
		GBytes *ssid;
		char *ssid_utf8;

		s_wireless = nm_connection_get_setting_wireless (request->connection);
		ssid = nm_setting_wireless_get_ssid (s_wireless);
		ssid_utf8 = nm_utils_ssid_to_utf8 (g_bytes_get_data (ssid, NULL),
		                                   g_bytes_get_size (ssid));

		title = _("Authentication required by wireless network");
		msg = g_strdup_printf (_("Passwords or encryption keys are required to access the wireless network '%s'."), ssid_utf8);

		ok = add_wireless_secrets (request, secrets);
	} else if (nm_connection_is_type (request->connection, NM_SETTING_WIRED_SETTING_NAME)) {
		title = _("Wired 802.1X authentication");
		msg = g_strdup_printf (_("Secrets are required to access the wired network '%s'"),
		                       nm_connection_get_id (request->connection));

		ok = add_8021x_secrets (request, secrets);
	} else if (nm_connection_is_type (request->connection, NM_SETTING_PPPOE_SETTING_NAME)) {
		title = _("DSL authentication");
		msg = g_strdup_printf (_("Secrets are required for the DSL connection '%s'"),
		                       nm_connection_get_id (request->connection));

		ok = add_pppoe_secrets (request, secrets);
	} else if (nm_connection_is_type (request->connection, NM_SETTING_GSM_SETTING_NAME)) {
		NMSettingGsm *s_gsm = nm_connection_get_setting_gsm (request->connection);

		if (strv_has (request->hints, "pin")) {
			title = _("PIN code required");
			msg = g_strdup (_("PIN code is needed for the mobile broadband device"));

			secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_PROPERTY,
			                                            _("PIN"),
			                                            NM_SETTING (s_gsm),
			                                            NM_SETTING_GSM_PIN,
			                                            NULL);
			g_ptr_array_add (secrets, secret);
		} else {
			title = _("Mobile broadband network password");
			msg = g_strdup_printf (_("A password is required to connect to '%s'."),
			                       nm_connection_get_id (request->connection));

			secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
			                                            _("Password"),
			                                            NM_SETTING (s_gsm),
			                                            NM_SETTING_GSM_PASSWORD,
			                                            NULL);
			g_ptr_array_add (secrets, secret);
		}
	} else if (nm_connection_is_type (request->connection, NM_SETTING_MACSEC_SETTING_NAME)) {
		NMSettingMacsec *s_macsec = nm_connection_get_setting_macsec (request->connection);

		msg = g_strdup_printf (_("Secrets are required to access the MACsec network '%s'"),
		                       nm_connection_get_id (request->connection));

		if (nm_setting_macsec_get_mode (s_macsec) == NM_SETTING_MACSEC_MODE_PSK) {
			title = _("MACsec PSK authentication");
			secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
			                                            _("MKA CAK"),
			                                            NM_SETTING (s_macsec),
			                                            NM_SETTING_MACSEC_MKA_CAK,
			                                            NULL);
			g_ptr_array_add (secrets, secret);
		} else {
			title = _("MACsec EAP authentication");
			ok = add_8021x_secrets (request, secrets);
		}
	} else if (nm_connection_is_type (request->connection, NM_SETTING_CDMA_SETTING_NAME)) {
		NMSettingCdma *s_cdma = nm_connection_get_setting_cdma (request->connection);

		title = _("Mobile broadband network password");
		msg = g_strdup_printf (_("A password is required to connect to '%s'."),
		                       nm_connection_get_id (request->connection));

		secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
		                                            _("Password"),
		                                            NM_SETTING (s_cdma),
		                                            NM_SETTING_CDMA_PASSWORD,
		                                            NULL);
		g_ptr_array_add (secrets, secret);
	} else if (nm_connection_is_type (request->connection, NM_SETTING_BLUETOOTH_SETTING_NAME)) {
		NMSetting *setting = NULL;

		setting = nm_connection_get_setting_by_name (request->connection, NM_SETTING_BLUETOOTH_SETTING_NAME);
		if (   setting
		    && !nm_streq0 (nm_setting_bluetooth_get_connection_type (NM_SETTING_BLUETOOTH (setting)), NM_SETTING_BLUETOOTH_TYPE_NAP)) {
			setting = nm_connection_get_setting_by_name (request->connection, NM_SETTING_GSM_SETTING_NAME);
			if (!setting)
				setting = nm_connection_get_setting_by_name (request->connection, NM_SETTING_CDMA_SETTING_NAME);
		}

		if (setting) {
			title = _("Mobile broadband network password");
			msg = g_strdup_printf (_("A password is required to connect to '%s'."),
			                       nm_connection_get_id (request->connection));

			secret = nm_secret_agent_simple_secret_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
			                                            _("Password"),
			                                            setting,
			                                            "password",
			                                            NULL);
			g_ptr_array_add (secrets, secret);
		} else
			ok = FALSE;
	} else if (nm_connection_is_type (request->connection, NM_SETTING_VPN_SETTING_NAME)) {
		title = _("VPN password required");
		msg = NULL;

		ok = add_vpn_secrets (request, secrets, &msg);
		if (!msg)
			msg = g_strdup_printf (_("A password is required to connect to '%s'."),
			                       nm_connection_get_id (request->connection));
	} else
		ok = FALSE;

	if (!ok) {
		gs_free_error GError *error = NULL;

		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_FAILED,
		                     "Cannot service a secrets request %s for a %s connection",
		                     request->request_id,
		                     nm_connection_get_connection_type (request->connection));
		request->callback (NM_SECRET_AGENT_OLD (request->self), request->connection,
		                   NULL, error, request->callback_data);
		g_hash_table_remove (priv->requests, request->request_id);
		g_ptr_array_unref (secrets);
		return;
	}

	g_signal_emit (request->self, signals[REQUEST_SECRETS], 0,
	               request->request_id, title, msg, secrets);
}

static void
nm_secret_agent_simple_get_secrets (NMSecretAgentOld                 *agent,
                                    NMConnection                     *connection,
                                    const gchar                      *connection_path,
                                    const gchar                      *setting_name,
                                    const gchar                     **hints,
                                    NMSecretAgentGetSecretsFlags      flags,
                                    NMSecretAgentOldGetSecretsFunc    callback,
                                    gpointer                          callback_data)
{
	NMSecretAgentSimple *self = NM_SECRET_AGENT_SIMPLE (agent);
	NMSecretAgentSimplePrivate *priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (self);
	NMSecretAgentSimpleRequest *request;
	char *request_id;
	GError *error;

	request_id = g_strdup_printf ("%s/%s", connection_path, setting_name);
	if (g_hash_table_lookup (priv->requests, request_id) != NULL) {
		/* We already have a request pending for this (connection, setting) */
		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_FAILED,
		                     "Request for %s secrets already pending", request_id);
	nope:
		callback (agent, connection, NULL, error, callback_data);
		g_error_free (error);
		g_free (request_id);
		return;
	}

	if (!(flags & NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION)) {
		/* We don't do stored passwords */
		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_NO_SECRETS,
		                     "Stored passwords not supported");
		goto nope;
	}

	request = g_slice_new (NMSecretAgentSimpleRequest);
	request->self = g_object_ref (self);
	request->connection = g_object_ref (connection);
	request->hints = g_strdupv ((gchar **)hints);
	request->callback = callback;
	request->callback_data = callback_data;
	request->request_id = request_id;
	g_hash_table_replace (priv->requests, request->request_id, request);

	if (priv->enabled)
		request_secrets_from_ui (request);
}

/**
 * nm_secret_agent_simple_response:
 * @self: the #NMSecretAgentSimple
 * @request_id: the request ID being responded to
 * @secrets: (allow-none): the array of secrets, or %NULL
 *
 * Response to a #NMSecretAgentSimple::get-secrets signal.
 *
 * If the user provided secrets, the caller should set the
 * corresponding <literal>value</literal> fields in the
 * #NMSecretAgentSimpleSecrets (freeing any initial values they had), and
 * pass the array to nm_secret_agent_simple_response(). If the user
 * cancelled the request, @secrets should be NULL.
 */
void
nm_secret_agent_simple_response (NMSecretAgentSimple *self,
                                 const char          *request_id,
                                 GPtrArray           *secrets)
{
	NMSecretAgentSimplePrivate *priv;
	NMSecretAgentSimpleRequest *request;
	GVariant *dict = NULL;
	GError *error = NULL;
	int i;

	g_return_if_fail (NM_IS_SECRET_AGENT_SIMPLE (self));

	priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (self);
	request = g_hash_table_lookup (priv->requests, request_id);
	g_return_if_fail (request != NULL);

	if (secrets) {
		GVariantBuilder conn_builder, *setting_builder;
		GVariantBuilder vpn_secrets_builder;
		GHashTable *settings;
		GHashTableIter iter;
		const char *name;
		gboolean has_vpn = FALSE;

		settings = g_hash_table_new (nm_str_hash, g_str_equal);
		for (i = 0; i < secrets->len; i++) {
			NMSecretAgentSimpleSecretReal *secret = secrets->pdata[i];

			setting_builder = g_hash_table_lookup (settings, nm_setting_get_name (secret->setting));
			if (!setting_builder) {
				setting_builder = g_variant_builder_new (NM_VARIANT_TYPE_SETTING);
				g_hash_table_insert (settings, (char *) nm_setting_get_name (secret->setting),
				                     setting_builder);
			}

			switch (secret->base.secret_type) {
			case NM_SECRET_AGENT_SECRET_TYPE_PROPERTY:
			case NM_SECRET_AGENT_SECRET_TYPE_SECRET:
				g_variant_builder_add (setting_builder, "{sv}",
				                       secret->property,
				                       g_variant_new_string (secret->base.value));
				break;
			case NM_SECRET_AGENT_SECRET_TYPE_VPN_SECRET:
				if (!has_vpn) {
					g_variant_builder_init (&vpn_secrets_builder, G_VARIANT_TYPE ("a{ss}"));
					has_vpn = TRUE;
				}
				g_variant_builder_add (&vpn_secrets_builder, "{ss}",
				                       secret->property, secret->base.value);
				break;
			}
		}

		if (has_vpn) {
			g_variant_builder_add (setting_builder, "{sv}",
			                       "secrets",
			                       g_variant_builder_end (&vpn_secrets_builder));
		}

		g_variant_builder_init (&conn_builder, NM_VARIANT_TYPE_CONNECTION);
		g_hash_table_iter_init (&iter, settings);
		while (g_hash_table_iter_next (&iter, (gpointer *) &name, (gpointer *) &setting_builder))
			g_variant_builder_add (&conn_builder, "{sa{sv}}", name, setting_builder);
		dict = g_variant_builder_end (&conn_builder);
		g_hash_table_destroy (settings);
	} else {
		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_USER_CANCELED,
		                     "User cancelled");
	}

	request->callback (NM_SECRET_AGENT_OLD (self), request->connection, dict, error, request->callback_data);

	g_clear_error (&error);
	g_hash_table_remove (priv->requests, request_id);
}

static void
nm_secret_agent_simple_cancel_get_secrets (NMSecretAgentOld *agent,
                                           const gchar      *connection_path,
                                           const gchar      *setting_name)
{
	NMSecretAgentSimple *self = NM_SECRET_AGENT_SIMPLE (agent);
	NMSecretAgentSimplePrivate *priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (self);
	gs_free char *request_id = NULL;

	request_id = g_strdup_printf ("%s/%s", connection_path, setting_name);
	g_hash_table_remove (priv->requests, request_id);
}

static void
nm_secret_agent_simple_save_secrets (NMSecretAgentOld                *agent,
                                     NMConnection                    *connection,
                                     const gchar                     *connection_path,
                                     NMSecretAgentOldSaveSecretsFunc  callback,
                                     gpointer                         callback_data)
{
	/* We don't support secret storage */
	callback (agent, connection, NULL, callback_data);
}

static void
nm_secret_agent_simple_delete_secrets (NMSecretAgentOld                  *agent,
                                       NMConnection                      *connection,
                                       const gchar                       *connection_path,
                                       NMSecretAgentOldDeleteSecretsFunc  callback,
                                       gpointer                           callback_data)
{
	/* We don't support secret storage, so there's nothing to delete. */
	callback (agent, connection, NULL, callback_data);
}

/**
 * nm_secret_agent_simple_enable:
 * @self: the #NMSecretAgentSimple
 * @path: (allow-none): the path of the connection (if any) to handle secrets
 *        for.  If %NULL, secrets for any connection will be handled.
 *
 * Enables servicing the requests including the already queued ones.  If @path
 * is given, the agent will only handle requests for connections that match
 * @path.
 */
void
nm_secret_agent_simple_enable (NMSecretAgentSimple *self, const char *path)
{
	NMSecretAgentSimplePrivate *priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (self);
	GList *requests, *iter;
	gs_free char *path_full = NULL;

	/* The path is only used to match a request_id with the current
	 * connection. Since the request_id is "${CONNECTION_PATH}/${SETTING}",
	 * add a trailing '/' to the path to match the full connection path.
	 */
	path_full = path ? g_strdup_printf ("%s/", path) : NULL;

	if (g_strcmp0 (path_full, priv->path) != 0) {
		g_free (priv->path);
		priv->path = path_full;
		path_full = NULL;
	}

	if (priv->enabled)
		return;
	priv->enabled = TRUE;

	/* Service pending secret requests. */
	requests = g_hash_table_get_values (priv->requests);
	for (iter = requests; iter; iter = g_list_next (iter))
		request_secrets_from_ui (iter->data);

	g_list_free (requests);
}

void
nm_secret_agent_simple_class_init (NMSecretAgentSimpleClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	NMSecretAgentOldClass *agent_class = NM_SECRET_AGENT_OLD_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMSecretAgentSimplePrivate));

	gobject_class->finalize = nm_secret_agent_simple_finalize;

	agent_class->get_secrets = nm_secret_agent_simple_get_secrets;
	agent_class->cancel_get_secrets = nm_secret_agent_simple_cancel_get_secrets;
	agent_class->save_secrets = nm_secret_agent_simple_save_secrets;
	agent_class->delete_secrets = nm_secret_agent_simple_delete_secrets;

	/**
	 * NMSecretAgentSimple::request-secrets:
	 * @agent: the #NMSecretAgentSimple
	 * @request_id: request ID, to eventually pass to
	 *   nm_secret_agent_simple_response().
	 * @title: a title for the password dialog
	 * @prompt: a prompt message for the password dialog
	 * @secrets: (element-type #NMSecretAgentSimpleSecret): array of secrets
	 *   being requested.
	 *
	 * Emitted when the agent requires secrets from the user.
	 *
	 * The application should ask user for the secrets. For example,
	 * nmtui should create a password dialog (#NmtPasswordDialog)
	 * with the given title and prompt, and an entry for each
	 * element of @secrets. If any of the secrets already have a
	 * <literal>value</literal> filled in, the corresponding entry
	 * should be initialized to that value.
	 *
	 * When the dialog is complete, the app must call
	 * nm_secret_agent_simple_response() with the results.
	 */
	signals[REQUEST_SECRETS] = g_signal_new (NM_SECRET_AGENT_SIMPLE_REQUEST_SECRETS,
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
 * nm_secret_agent_simple_new:
 * @name: the identifier of secret agent
 *
 * Creates a new #NMSecretAgentSimple. It does not serve any requests until
 * nm_secret_agent_simple_enable() is called.
 *
 * Returns: a new #NMSecretAgentSimple if the agent creation is successful
 * or %NULL in case of a failure.
 */
NMSecretAgentOld *
nm_secret_agent_simple_new (const char *name)
{
	return g_initable_new (NM_TYPE_SECRET_AGENT_SIMPLE, NULL, NULL,
	                       NM_SECRET_AGENT_OLD_IDENTIFIER, name,
	                       NM_SECRET_AGENT_OLD_CAPABILITIES, NM_SECRET_AGENT_CAPABILITY_VPN_HINTS,
	                       NULL);
}
