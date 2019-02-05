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

#include "nm-secret-agent-simple.h"

#include <gio/gunixoutputstream.h>
#include <gio/gunixinputstream.h>
#include <string.h>

#include "nm-vpn-service-plugin.h"
#include "nm-vpn-helpers.h"

/*****************************************************************************/

typedef struct {
	char                          *request_id;

	NMSecretAgentSimple           *self;

	NMConnection                  *connection;
	char                         **hints;
	NMSecretAgentOldGetSecretsFunc callback;
	gpointer                       callback_data;
	GCancellable                  *cancellable;
	NMSecretAgentGetSecretsFlags   flags;
} RequestData;

enum {
	REQUEST_SECRETS,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	GHashTable *requests;

	char *path;
	gboolean enabled;
} NMSecretAgentSimplePrivate;

struct _NMSecretAgentSimple {
	NMSecretAgentOld parent;
	NMSecretAgentSimplePrivate _priv;
};

struct _NMSecretAgentSimpleClass {
	NMSecretAgentOldClass parent;
};

G_DEFINE_TYPE (NMSecretAgentSimple, nm_secret_agent_simple, NM_TYPE_SECRET_AGENT_OLD)

#define NM_SECRET_AGENT_SIMPLE_GET_PRIVATE(self)  _NM_GET_PRIVATE (self, NMSecretAgentSimple, NM_IS_SECRET_AGENT_SIMPLE, NMSecretAgentOld)

/*****************************************************************************/

static void
_request_data_free (gpointer data)
{
	RequestData *request = data;

	g_free (request->request_id);
	nm_clear_g_cancellable (&request->cancellable);
	g_object_unref (request->connection);
	g_strfreev (request->hints);

	g_slice_free (RequestData, request);
}

static void
_request_data_complete (RequestData *request,
                        GVariant *secrets,
                        GError *error,
                        GHashTableIter *iter_to_remove)
{
	NMSecretAgentSimple *self = request->self;
	NMSecretAgentSimplePrivate *priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (self);

	nm_assert ((secrets != NULL) != (error != NULL));

	request->callback (NM_SECRET_AGENT_OLD (request->self),
	                   request->connection,
	                   secrets,
	                   error,
	                   request->callback_data);

	if (iter_to_remove)
		g_hash_table_iter_remove (iter_to_remove);
	else
		g_hash_table_remove (priv->requests, request);
}

/*****************************************************************************/

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
} SecretReal;

static void
_secret_real_free (NMSecretAgentSimpleSecret *secret)
{
	SecretReal *real = (SecretReal *)secret;

	g_free ((char *) secret->pretty_name);
	g_free ((char *) secret->entry_id);
	g_free (secret->value);
	g_free ((char *) secret->vpn_type);
	g_free (real->property);
	g_clear_object (&real->setting);

	g_slice_free (SecretReal, real);
}

static NMSecretAgentSimpleSecret *
_secret_real_new (NMSecretAgentSecretType secret_type,
                  const char *pretty_name,
                  NMSetting  *setting,
                  const char *property,
                  const char *vpn_type)
{
	SecretReal *real;
	const char *vpn_prefix;
	const char *value;

	nm_assert (property);
	nm_assert (NM_IS_SETTING (setting));

	real = g_slice_new0 (SecretReal);
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
		vpn_prefix = NM_SECRET_AGENT_ENTRY_ID_PREFX_VPN_SECRETS;
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

/*****************************************************************************/

static gboolean
add_8021x_secrets (RequestData *request,
                   GPtrArray *secrets)
{
	NMSetting8021x *s_8021x = nm_connection_get_setting_802_1x (request->connection);
	const char *eap_method;
	NMSecretAgentSimpleSecret *secret;

	/* If hints are given, then always ask for what the hints require */
	if (request->hints && request->hints[0]) {
		char **iter;

		for (iter = request->hints; *iter; iter++) {
			secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
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

	if (NM_IN_STRSET (eap_method, "md5",
	                              "leap",
	                              "ttls",
	                              "peap")) {
		/* TTLS and PEAP are actually much more complicated, but this complication
		 * is not visible here since we only care about phase2 authentication
		 * (and don't even care of which one)
		 */
		secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_PROPERTY,
		                           _("Username"),
		                           NM_SETTING (s_8021x),
		                           NM_SETTING_802_1X_IDENTITY,
		                           NULL);
		g_ptr_array_add (secrets, secret);
		secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
		                           _("Password"),
		                           NM_SETTING (s_8021x),
		                           NM_SETTING_802_1X_PASSWORD,
		                           NULL);
		g_ptr_array_add (secrets, secret);
		return TRUE;
	}

	if (nm_streq (eap_method, "tls")) {
		secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_PROPERTY,
		                           _("Identity"),
		                           NM_SETTING (s_8021x),
		                           NM_SETTING_802_1X_IDENTITY,
		                           NULL);
		g_ptr_array_add (secrets, secret);
		secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
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
add_wireless_secrets (RequestData *request,
                      GPtrArray                  *secrets)
{
	NMSettingWirelessSecurity *s_wsec = nm_connection_get_setting_wireless_security (request->connection);
	const char *key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	NMSecretAgentSimpleSecret *secret;

	if (!key_mgmt)
		return FALSE;

	if (NM_IN_STRSET (key_mgmt, "wpa-none",
	                            "wpa-psk")) {
		secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
		                           _("Password"),
		                           NM_SETTING (s_wsec),
		                           NM_SETTING_WIRELESS_SECURITY_PSK,
		                           NULL);
		g_ptr_array_add (secrets, secret);
		return TRUE;
	}

	if (nm_streq (key_mgmt, "none")) {
		guint32 index;
		char key[100];

		index = nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec);
		secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
		                           _("Key"),
		                           NM_SETTING (s_wsec),
		                           nm_sprintf_buf (key, "wep-key%u", (guint) index),
		                           NULL);
		g_ptr_array_add (secrets, secret);
		return TRUE;
	}

	if (nm_streq (key_mgmt, "iee8021x")) {
		if (nm_streq0 (nm_setting_wireless_security_get_auth_alg (s_wsec), "leap")) {
			secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
			                           _("Password"),
			                           NM_SETTING (s_wsec),
			                           NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
			                           NULL);
			g_ptr_array_add (secrets, secret);
			return TRUE;
		} else
			return add_8021x_secrets (request, secrets);
	}

	if (nm_streq (key_mgmt, "wpa-eap"))
		return add_8021x_secrets (request, secrets);

	return FALSE;
}

static gboolean
add_pppoe_secrets (RequestData *request,
                   GPtrArray                  *secrets)
{
	NMSettingPppoe *s_pppoe = nm_connection_get_setting_pppoe (request->connection);
	NMSecretAgentSimpleSecret *secret;

	secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_PROPERTY,
	                           _("Username"),
	                           NM_SETTING (s_pppoe),
	                           NM_SETTING_PPPOE_USERNAME,
	                           NULL);
	g_ptr_array_add (secrets, secret);
	secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_PROPERTY,
	                           _("Service"),
	                           NM_SETTING (s_pppoe),
	                           NM_SETTING_PPPOE_SERVICE,
	                           NULL);
	g_ptr_array_add (secrets, secret);
	secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
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
		secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_VPN_SECRET,
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
				_secret_real_free (secret);
				return;
			}
		}

		g_ptr_array_add (secrets, secret);
	}
}

#define VPN_MSG_TAG "x-vpn-message:"

static gboolean
add_vpn_secrets (RequestData *request,
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

typedef struct {
	GPid auth_dialog_pid;
	GString *auth_dialog_response;
	RequestData *request;
	GPtrArray *secrets;
	GCancellable *cancellable;
	gulong cancellable_id;
	guint child_watch_id;
	char read_buf[5];
} AuthDialogData;

static void
_auth_dialog_data_free (AuthDialogData *data)
{
	nm_clear_g_signal_handler (data->cancellable, &data->cancellable_id);
	g_clear_object (&data->cancellable);
	nm_clear_g_source (&data->child_watch_id);
	g_ptr_array_unref (data->secrets);
	g_spawn_close_pid (data->auth_dialog_pid);
	g_string_free (data->auth_dialog_response, TRUE);
	g_slice_free (AuthDialogData, data);
}

static void
_auth_dialog_exited (GPid pid, int status, gpointer user_data)
{
	AuthDialogData *data = user_data;
	RequestData *request = data->request;
	GPtrArray *secrets = data->secrets;
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (request->connection);
	gs_unref_keyfile GKeyFile *keyfile = NULL;
	gs_strfreev char **groups = NULL;
	gs_free char *title = NULL;
	gs_free char *message = NULL;
	int i;
	gs_free_error GError *error = NULL;

	data->child_watch_id = 0;

	nm_clear_g_cancellable_disconnect (data->cancellable, &data->cancellable_id);

	if (status != 0) {
		g_set_error (&error, NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_FAILED,
		             "Auth dialog failed with error code %d\n", status);
		goto out;
	}

	keyfile = g_key_file_new ();
	if (!g_key_file_load_from_data (keyfile,
	                                data->auth_dialog_response->str,
	                                data->auth_dialog_response->len, G_KEY_FILE_NONE,
	                                &error)) {
		goto out;
	}

	groups = g_key_file_get_groups (keyfile, NULL);
	if (!nm_streq0 (groups[0], "VPN Plugin UI")) {
		g_set_error (&error, NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_FAILED,
		             "Expected [VPN Plugin UI] in auth dialog response");
		goto out;
	}

	title = g_key_file_get_string (keyfile, "VPN Plugin UI", "Title", &error);
	if (!title)
		goto out;

	message = g_key_file_get_string (keyfile, "VPN Plugin UI", "Description", &error);
	if (!message)
		goto out;

	for (i = 1; groups[i]; i++) {
		if (!g_key_file_get_boolean (keyfile, groups[i], "IsSecret", NULL))
			continue;
		if (!g_key_file_get_boolean (keyfile, groups[i], "ShouldAsk", NULL))
			continue;

		g_ptr_array_add (secrets, _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_VPN_SECRET,
		                                            g_key_file_get_string (keyfile, groups[i], "Label", NULL),
		                                            NM_SETTING (s_vpn),
		                                            groups[i],
		                                            nm_setting_vpn_get_service_type (s_vpn)));
	}

out:
	/* Try to fall back to the hardwired VPN support if the auth dialog fails.
	 * We may eventually get rid of the whole hardwired secrets handling at some point,
	 * when the auth helpers are goode enough.. */
	if (error && add_vpn_secrets (request, secrets, &message)) {
		g_clear_error (&error);
		if (!message) {
			message = g_strdup_printf (_("A password is required to connect to '%s'."),
			                           nm_connection_get_id (request->connection));
		}
	}

	if (error)
		_request_data_complete (request, NULL, error, NULL);
	else {
		g_signal_emit (request->self, signals[REQUEST_SECRETS], 0,
		               request->request_id, title, message, secrets);
	}

	_auth_dialog_data_free (data);
}

static void
_request_cancelled (GObject *object, gpointer user_data)
{
	_auth_dialog_data_free (user_data);
}

static void
_auth_dialog_read_done (GObject *source_object,
                        GAsyncResult *res,
                        gpointer user_data)
{
	GInputStream *auth_dialog_out = G_INPUT_STREAM (source_object);
	AuthDialogData *data = user_data;
	gssize read_size;
	gs_free_error GError *error = NULL;

	read_size = g_input_stream_read_finish (auth_dialog_out, res, &error);
	switch (read_size) {
	case -1:
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			_request_data_complete (data->request, NULL, error, NULL);
		_auth_dialog_data_free (data);
		break;
	case 0:
		/* Done reading. Let's wait for the auth dialog to exit so that we're able to collect the status.
		 * Remember we can be cancelled in between. */
		data->child_watch_id = g_child_watch_add (data->auth_dialog_pid, _auth_dialog_exited, data);
		data->cancellable = g_object_ref (data->request->cancellable);
		data->cancellable_id = g_cancellable_connect (data->cancellable,
		                                              G_CALLBACK (_request_cancelled), data, NULL);
		break;
	default:
		g_string_append_len (data->auth_dialog_response, data->read_buf, read_size);
		g_input_stream_read_async (auth_dialog_out,
		                           data->read_buf,
		                           sizeof (data->read_buf),
		                           G_PRIORITY_DEFAULT,
		                           NULL,
		                           _auth_dialog_read_done,
		                           data);
		return;
	}

	g_input_stream_close (auth_dialog_out, NULL, NULL);
}

static void
_auth_dialog_write_done (GObject *source_object,
                        GAsyncResult *res,
                        gpointer user_data)
{
	GOutputStream *auth_dialog_out = G_OUTPUT_STREAM (source_object);
	_nm_unused gs_free char *auth_dialog_request_free = user_data;

	/* We don't care about write errors. If there are any problems, the
	 * reader shall notice. */
	g_output_stream_write_finish (auth_dialog_out, res, NULL);
	g_output_stream_close (auth_dialog_out, NULL, NULL);
}

static void
_add_to_string (GString *string, const char *key, const char *value)
{
	gs_strfreev char **lines = NULL;
	int i;

	lines = g_strsplit (value, "\n", -1);

	g_string_append (string, key);
	for (i = 0; lines[i]; i++) {
		g_string_append_c (string, '=');
		g_string_append (string, lines[i]);
		g_string_append_c (string, '\n');
	}
}

static void
_add_data_item_to_string (const char *key, const char *value, gpointer user_data)
{
	GString *string = user_data;

	_add_to_string (string, "DATA_KEY", key);
	_add_to_string (string, "DATA_VAL", value);
	g_string_append_c (string, '\n');
}

static void
_add_secret_to_string (const char *key, const char *value, gpointer user_data)
{
	GString *string = user_data;

	_add_to_string (string, "SECRET_KEY", key);
	_add_to_string (string, "SECRET_VAL", value);
	g_string_append_c (string, '\n');
}

static gboolean
try_spawn_vpn_auth_helper (RequestData *request,
                           GPtrArray *secrets)
{
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (request->connection);
        NMVpnPluginInfo *plugin_info;
	gboolean supports_external;
	const char *auth_dialog_argv[] = { NULL,
		"-u", nm_connection_get_uuid (request->connection),
		"-n", nm_connection_get_id (request->connection),
		"-s", nm_setting_vpn_get_service_type (s_vpn),
		"--external-ui-mode",
		"-i",
		NULL, /* [9], slot for "-r" */
		NULL };
	const char *s;
	GPid auth_dialog_pid;
	int auth_dialog_in_fd;
	int auth_dialog_out_fd;
	GOutputStream *auth_dialog_in;
	GInputStream *auth_dialog_out;
	GError *error = NULL;
	GString *auth_dialog_request;
	char *auth_dialog_request_str;
	gsize auth_dialog_request_len;
	AuthDialogData *data;

	plugin_info = nm_vpn_plugin_info_list_find_by_service (nm_vpn_get_plugin_infos (),
	                                                       nm_setting_vpn_get_service_type (s_vpn));
	if (!plugin_info)
		return FALSE;

	s = nm_vpn_plugin_info_lookup_property (plugin_info, "GNOME", "supports-external-ui-mode");
	supports_external = _nm_utils_ascii_str_to_bool (s, FALSE);
	if (!supports_external)
		return FALSE;

	auth_dialog_argv[0] = nm_vpn_plugin_info_lookup_property (plugin_info, "GNOME", "auth-dialog");
	g_return_val_if_fail (auth_dialog_argv[0], FALSE);

	if (request->flags & NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW)
		auth_dialog_argv[9] = "-r";

	if (!g_spawn_async_with_pipes (NULL, (char **)auth_dialog_argv, NULL,
	                               G_SPAWN_DO_NOT_REAP_CHILD,
	                               NULL, NULL,
	                               &auth_dialog_pid,
	                               &auth_dialog_in_fd,
	                               &auth_dialog_out_fd,
	                               NULL,
	                               &error)) {
		g_warning ("Failed to spawn the auth dialog%s\n", error->message);
		return FALSE;
	}

	auth_dialog_in = g_unix_output_stream_new (auth_dialog_in_fd, TRUE);
	auth_dialog_out =  g_unix_input_stream_new (auth_dialog_out_fd, TRUE);

	auth_dialog_request = g_string_new_len (NULL, 1024);
	nm_setting_vpn_foreach_data_item (s_vpn, _add_data_item_to_string, auth_dialog_request);
	nm_setting_vpn_foreach_secret (s_vpn, _add_secret_to_string, auth_dialog_request);
	g_string_append (auth_dialog_request, "DONE\nQUIT\n");
	auth_dialog_request_len = auth_dialog_request->len;
	auth_dialog_request_str = g_string_free (auth_dialog_request, FALSE);

	data = g_slice_new (AuthDialogData);
	*data = (AuthDialogData) {
		.auth_dialog_response = g_string_new_len (NULL, sizeof (data->read_buf)),
		.auth_dialog_pid = auth_dialog_pid,
		.request = request,
		.secrets = secrets,
	};

	g_output_stream_write_async (auth_dialog_in,
	                             auth_dialog_request_str,
	                             auth_dialog_request_len,
	                             G_PRIORITY_DEFAULT,
	                             request->cancellable,
	                             _auth_dialog_write_done,
	                             auth_dialog_request_str);

	g_input_stream_read_async (auth_dialog_out,
	                           data->read_buf,
	                           sizeof (data->read_buf),
	                            G_PRIORITY_DEFAULT,
	                           request->cancellable,
	                           _auth_dialog_read_done,
	                           data);

	return TRUE;
}

static void
request_secrets_from_ui (RequestData *request)
{
	gs_unref_ptrarray GPtrArray *secrets = NULL;
	gs_free_error GError *error = NULL;
	NMSecretAgentSimplePrivate *priv;
	NMSecretAgentSimpleSecret *secret;
	const char *title;
	gs_free char *msg = NULL;

	priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (request->self);
	g_return_if_fail (priv->enabled);

	/* We only handle requests for connection with @path if set. */
	if (priv->path && !g_str_has_prefix (request->request_id, priv->path)) {
		g_set_error (&error, NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_FAILED,
		             "Request for %s secrets doesn't match path %s",
		             request->request_id, priv->path);
		goto out_fail_error;
	}

	secrets = g_ptr_array_new_with_free_func ((GDestroyNotify) _secret_real_free);

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

		if (!add_wireless_secrets (request, secrets))
			goto out_fail;
	} else if (nm_connection_is_type (request->connection, NM_SETTING_WIRED_SETTING_NAME)) {
		title = _("Wired 802.1X authentication");
		msg = g_strdup_printf (_("Secrets are required to access the wired network '%s'"),
		                       nm_connection_get_id (request->connection));

		if (!add_8021x_secrets (request, secrets))
			goto out_fail;
	} else if (nm_connection_is_type (request->connection, NM_SETTING_PPPOE_SETTING_NAME)) {
		title = _("DSL authentication");
		msg = g_strdup_printf (_("Secrets are required for the DSL connection '%s'"),
		                       nm_connection_get_id (request->connection));

		if (!add_pppoe_secrets (request, secrets))
			goto out_fail;
	} else if (nm_connection_is_type (request->connection, NM_SETTING_GSM_SETTING_NAME)) {
		NMSettingGsm *s_gsm = nm_connection_get_setting_gsm (request->connection);

		if (g_strv_contains (NM_CAST_STRV_CC (request->hints), NM_SETTING_GSM_PIN)) {
			title = _("PIN code required");
			msg = g_strdup (_("PIN code is needed for the mobile broadband device"));

			secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_PROPERTY,
			                           _("PIN"),
			                           NM_SETTING (s_gsm),
			                           NM_SETTING_GSM_PIN,
			                           NULL);
			g_ptr_array_add (secrets, secret);
		} else {
			title = _("Mobile broadband network password");
			msg = g_strdup_printf (_("A password is required to connect to '%s'."),
			                       nm_connection_get_id (request->connection));

			secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
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
			secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
			                           _("MKA CAK"),
			                           NM_SETTING (s_macsec),
			                           NM_SETTING_MACSEC_MKA_CAK,
			                           NULL);
			g_ptr_array_add (secrets, secret);
		} else {
			title = _("MACsec EAP authentication");
			if (!add_8021x_secrets (request, secrets))
				goto out_fail;
		}
	} else if (nm_connection_is_type (request->connection, NM_SETTING_CDMA_SETTING_NAME)) {
		NMSettingCdma *s_cdma = nm_connection_get_setting_cdma (request->connection);

		title = _("Mobile broadband network password");
		msg = g_strdup_printf (_("A password is required to connect to '%s'."),
		                       nm_connection_get_id (request->connection));

		secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
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

		if (!setting)
			goto out_fail;

		title = _("Mobile broadband network password");
		msg = g_strdup_printf (_("A password is required to connect to '%s'."),
		                       nm_connection_get_id (request->connection));

		secret = _secret_real_new (NM_SECRET_AGENT_SECRET_TYPE_SECRET,
		                           _("Password"),
		                           setting,
		                           "password",
		                           NULL);
		g_ptr_array_add (secrets, secret);
	} else if (nm_connection_is_type (request->connection, NM_SETTING_VPN_SETTING_NAME)) {
		title = _("VPN password required");

		if (try_spawn_vpn_auth_helper (request, secrets)) {
			/* This will emit REQUEST_SECRETS when ready */
			return;
		}

		if (!add_vpn_secrets (request, secrets, &msg))
			goto out_fail;
		if (!msg) {
			msg = g_strdup_printf (_("A password is required to connect to '%s'."),
			                       nm_connection_get_id (request->connection));
		}
	} else
		goto out_fail;

	g_signal_emit (request->self, signals[REQUEST_SECRETS], 0,
	               request->request_id, title, msg, secrets);
	return;

out_fail:
	g_set_error (&error, NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_FAILED,
	             "Cannot service a secrets request %s for a %s connection",
	             request->request_id,
	             nm_connection_get_connection_type (request->connection));
out_fail_error:
	_request_data_complete (request, NULL, error, NULL);

}

static void
get_secrets (NMSecretAgentOld                 *agent,
             NMConnection                     *connection,
             const char                       *connection_path,
             const char                       *setting_name,
             const char                      **hints,
             NMSecretAgentGetSecretsFlags      flags,
             NMSecretAgentOldGetSecretsFunc    callback,
             gpointer                          callback_data)
{
	NMSecretAgentSimple *self = NM_SECRET_AGENT_SIMPLE (agent);
	NMSecretAgentSimplePrivate *priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (self);
	RequestData *request;
	gs_free_error GError *error = NULL;
	gs_free char *request_id = NULL;

	request_id = g_strdup_printf ("%s/%s", connection_path, setting_name);

	if (g_hash_table_contains (priv->requests, &request_id)) {
		/* We already have a request pending for this (connection, setting) */
		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_FAILED,
		                     "Request for %s secrets already pending", request_id);
		callback (agent, connection, NULL, error, callback_data);
		return;
	}

	if (!(flags & NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION)) {
		/* We don't do stored passwords */
		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_NO_SECRETS,
		                     "Stored passwords not supported");
		callback (agent, connection, NULL, error, callback_data);
		return;
	}

	request = g_slice_new (RequestData);
	*request = (RequestData) {
		.self = self,
		.connection = g_object_ref (connection),
		.hints = g_strdupv ((char **) hints),
		.callback = callback,
		.callback_data = callback_data,
		.request_id = g_steal_pointer (&request_id),
		.flags = flags,
		.cancellable = g_cancellable_new (),
	};
	g_hash_table_add (priv->requests, request);

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
	RequestData *request;
	gs_unref_variant GVariant *secrets_dict = NULL;
	gs_free_error GError *error = NULL;
	int i;

	g_return_if_fail (NM_IS_SECRET_AGENT_SIMPLE (self));

	priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (self);
	request = g_hash_table_lookup (priv->requests, &request_id);
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
			SecretReal *secret = secrets->pdata[i];

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
		secrets_dict = g_variant_ref_sink (g_variant_builder_end (&conn_builder));
		g_hash_table_destroy (settings);
	} else {
		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_USER_CANCELED,
		                     "User cancelled");
	}

	_request_data_complete (request, secrets_dict, error, NULL);
}

static void
cancel_get_secrets (NMSecretAgentOld *agent,
                    const char       *connection_path,
                    const char       *setting_name)
{
	NMSecretAgentSimple *self = NM_SECRET_AGENT_SIMPLE (agent);
	NMSecretAgentSimplePrivate *priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;
	gs_free char *request_id = NULL;
	RequestData *request;

	request_id = g_strdup_printf ("%s/%s", connection_path, setting_name);
	request = g_hash_table_lookup (priv->requests, &request_id);
	if (!request) {
		/* this is really a bug of the caller (or us?). We cannot invoke a callback,
		 * hence the caller cannot cleanup the request. */
		g_return_if_reached ();
	}

	g_set_error (&error,
	             NM_SECRET_AGENT_ERROR,
	             NM_SECRET_AGENT_ERROR_AGENT_CANCELED,
	             "The secret agent is going away");
	_request_data_complete (request, NULL, error, NULL);
}

static void
save_secrets (NMSecretAgentOld                *agent,
              NMConnection                    *connection,
              const char                      *connection_path,
              NMSecretAgentOldSaveSecretsFunc  callback,
              gpointer                         callback_data)
{
	/* We don't support secret storage */
	callback (agent, connection, NULL, callback_data);
}

static void
delete_secrets (NMSecretAgentOld                  *agent,
                NMConnection                      *connection,
                const char                        *connection_path,
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
	gs_free RequestData **requests = NULL;
	gsize i;
	gs_free char *path_full = NULL;

	/* The path is only used to match a request_id with the current
	 * connection. Since the request_id is "${CONNECTION_PATH}/${SETTING}",
	 * add a trailing '/' to the path to match the full connection path.
	 */
	path_full = path ? g_strdup_printf ("%s/", path) : NULL;

	if (!nm_streq0 (path_full, priv->path)) {
		g_free (priv->path);
		priv->path = g_steal_pointer (&path_full);
	}

	if (priv->enabled)
		return;
	priv->enabled = TRUE;

	/* Service pending secret requests. */
	requests = (RequestData **) g_hash_table_get_keys_as_array (priv->requests, NULL);
	for (i = 0; requests[i]; i++)
		request_secrets_from_ui (requests[i]);
}

/*****************************************************************************/

static void
nm_secret_agent_simple_init (NMSecretAgentSimple *agent)
{
	NMSecretAgentSimplePrivate *priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (agent);

	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (RequestData, request_id) == 0);
	priv->requests = g_hash_table_new_full (nm_pstr_hash, nm_pstr_equal,
	                                        NULL, _request_data_free);
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
NMSecretAgentSimple *
nm_secret_agent_simple_new (const char *name)
{
	return g_initable_new (NM_TYPE_SECRET_AGENT_SIMPLE, NULL, NULL,
	                       NM_SECRET_AGENT_OLD_IDENTIFIER, name,
	                       NM_SECRET_AGENT_OLD_CAPABILITIES, NM_SECRET_AGENT_CAPABILITY_VPN_HINTS,
	                       NULL);
}

static void
dispose (GObject *object)
{
	NMSecretAgentSimplePrivate *priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (object);
	gs_free_error GError *error = NULL;
	GHashTableIter iter;
	RequestData *request;

	g_hash_table_iter_init (&iter, priv->requests);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &request)) {
		if (!error)
			nm_utils_error_set_cancelled (&error, TRUE, "NMSecretAgentSimple");
		_request_data_complete (request, NULL, error, &iter);
	}

	G_OBJECT_CLASS (nm_secret_agent_simple_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMSecretAgentSimplePrivate *priv = NM_SECRET_AGENT_SIMPLE_GET_PRIVATE (object);

	g_hash_table_destroy (priv->requests);

	g_free (priv->path);

	G_OBJECT_CLASS (nm_secret_agent_simple_parent_class)->finalize (object);
}

void
nm_secret_agent_simple_class_init (NMSecretAgentSimpleClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSecretAgentOldClass *agent_class = NM_SECRET_AGENT_OLD_CLASS (klass);

	object_class->dispose = dispose;
	object_class->finalize = finalize;

	agent_class->get_secrets        = get_secrets;
	agent_class->cancel_get_secrets = cancel_get_secrets;
	agent_class->save_secrets       = save_secrets;
	agent_class->delete_secrets     = delete_secrets;

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
