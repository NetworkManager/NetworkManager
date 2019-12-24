// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2010 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include <sys/types.h>
#include <signal.h>

#include "nm-secret-agent-old.h"

#include "nm-test-libnm-utils.h"

/*****************************************************************************/

enum {
	SECRET_REQUESTED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef NMSecretAgentOld      TestSecretAgent;
typedef NMSecretAgentOldClass TestSecretAgentClass;

GType test_secret_agent_get_type (void);

G_DEFINE_TYPE (TestSecretAgent, test_secret_agent, NM_TYPE_SECRET_AGENT_OLD)

static void
test_secret_agent_get_secrets (NMSecretAgentOld                 *agent,
                               NMConnection                     *connection,
                               const char                       *connection_path,
                               const char                       *setting_name,
                               const char                      **hints,
                               NMSecretAgentGetSecretsFlags      flags,
                               NMSecretAgentOldGetSecretsFunc    callback,
                               gpointer                          callback_data)
{
	NMSettingWirelessSecurity *s_wsec;
	GVariant *secrets = NULL;
	GVariantBuilder secrets_builder, setting_builder;
	char *secret = NULL;
	GError *error = NULL;

	g_assert_cmpstr (setting_name, ==, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "wpa-psk");
	g_assert_cmpstr (nm_setting_wireless_security_get_psk (s_wsec), ==, NULL);

	g_signal_emit (agent, signals[SECRET_REQUESTED], 0,
	               connection,
	               connection_path,
	               NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	               NM_SETTING_WIRELESS_SECURITY_PSK,
	               &secret);

	if (!secret) {
		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_NO_SECRETS,
		                     "No secrets");
		goto done;
	}

	if (!strcmp (secret, "CANCEL")) {
		error = g_error_new (NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_USER_CANCELED,
		                     "User canceled");
		goto done;
	}

	g_variant_builder_init (&setting_builder, NM_VARIANT_TYPE_SETTING);
	g_variant_builder_add (&setting_builder, "{sv}",
	                       NM_SETTING_WIRELESS_SECURITY_PSK,
	                       g_variant_new_string (secret));

	g_variant_builder_init (&secrets_builder, NM_VARIANT_TYPE_CONNECTION);
	g_variant_builder_add (&secrets_builder, "{sa{sv}}",
	                       setting_name,
	                       &setting_builder);
	secrets = g_variant_ref_sink (g_variant_builder_end (&secrets_builder));

done:
	callback (agent, connection, secrets, error, callback_data);
	g_clear_error (&error);
	g_clear_pointer (&secrets, g_variant_unref);
	g_free (secret);
}

static void
test_secret_agent_cancel_get_secrets (NMSecretAgentOld *agent,
                                      const char       *connection_path,
                                      const char       *setting_name)
{
	g_assert_not_reached ();
}

static void
test_secret_agent_save_secrets (NMSecretAgentOld                *agent,
                                NMConnection                    *connection,
                                const char                      *connection_path,
                                NMSecretAgentOldSaveSecretsFunc  callback,
                                gpointer                         callback_data)
{
	g_assert_not_reached ();
}

static void
test_secret_agent_delete_secrets (NMSecretAgentOld                  *agent,
                                  NMConnection                      *connection,
                                  const char                        *connection_path,
                                  NMSecretAgentOldDeleteSecretsFunc  callback,
                                  gpointer                           callback_data)
{
	g_assert_not_reached ();
}

static void
test_secret_agent_init (TestSecretAgent *agent)
{
}

static NMSecretAgentOld *
test_secret_agent_new (gboolean auto_register)
{
	return nmtstc_context_object_new (test_secret_agent_get_type (),
	                                  TRUE,
	                                  NM_SECRET_AGENT_OLD_IDENTIFIER, "test-secret-agent",
	                                  NM_SECRET_AGENT_OLD_AUTO_REGISTER, auto_register,
	                                  NULL);
}

static void
test_secret_agent_class_init (TestSecretAgentClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSecretAgentOldClass *agent_class = NM_SECRET_AGENT_OLD_CLASS (klass);

	agent_class->get_secrets =        test_secret_agent_get_secrets;
	agent_class->cancel_get_secrets = test_secret_agent_cancel_get_secrets;
	agent_class->save_secrets =       test_secret_agent_save_secrets;
	agent_class->delete_secrets =     test_secret_agent_delete_secrets;

	signals[SECRET_REQUESTED] =
	    g_signal_new ("secret-requested",
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_STRING, 4,
	                  NM_TYPE_CONNECTION,
	                  G_TYPE_STRING,
	                  G_TYPE_STRING,
	                  G_TYPE_STRING);
}

/*****************************************************************************/

typedef struct {
	NMTstcServiceInfo *sinfo;
	NMClient *client;

	NMSecretAgentOld *agent;
	NMDevice *device;
	NMConnection *connection;

	GMainLoop *loop;
	GSource *timeout_source;

	char *ifname;
	char *con_id;

	int secrets_requested;
} TestSecretAgentData;

static void
connection_added_cb (GObject *s,
                     GAsyncResult *result,
                     gpointer user_data)
{
	TestSecretAgentData *sadata = user_data;
	NMRemoteConnection *connection;
	GError *error = NULL;

	connection = nm_client_add_connection_finish (sadata->client, result, &error);

	g_assert_no_error (error);
	g_assert_cmpstr (nm_connection_get_id (NM_CONNECTION (connection)), ==, sadata->con_id);

	sadata->connection = NM_CONNECTION (connection);
	g_main_loop_quit (sadata->loop);
}

static void
register_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	TestSecretAgentData *sadata = user_data;
	GError *error = NULL;

	nm_secret_agent_old_register_finish (sadata->agent, result, &error);
	g_assert_no_error (error);
	g_assert (nm_secret_agent_old_get_registered (sadata->agent));

	g_main_loop_quit (sadata->loop);
}

#define TEST_CON_ID_PREFIX "test-secret-agent"

static void
test_setup (TestSecretAgentData *sadata, gconstpointer test_data)
{
	static int static_counter = 0;
	const int counter = static_counter++;
	const char *create_agent = test_data;
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	GBytes *ssid;
	NMSetting *s_wsec;
	gs_free_error GError *error = NULL;

	sadata->sinfo = nmtstc_service_init ();
	if (!sadata->sinfo)
		return;

	g_assert (g_main_context_get_thread_default () == NULL);

	sadata->client = nmtstc_client_new (TRUE);

	sadata->loop = g_main_loop_new (NULL, FALSE);

	sadata->timeout_source = g_timeout_source_new_seconds (5);
	g_source_set_callback (sadata->timeout_source, nmtst_g_source_assert_not_called, NULL, NULL);
	g_source_attach (sadata->timeout_source, NULL);

	sadata->ifname = g_strdup_printf ("wlan%d", counter);
	sadata->con_id = g_strdup_printf ("%s-%d", TEST_CON_ID_PREFIX, counter);

	sadata->device = nmtstc_service_add_device (sadata->sinfo,
	                                            sadata->client,
	                                            "AddWifiDevice",
	                                            sadata->ifname);

	/* Create the connection */
	connection = nmtst_create_minimal_connection (sadata->con_id, NULL, NM_SETTING_WIRELESS_SETTING_NAME, &s_con);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, sadata->ifname,
	              NULL);

	s_wireless = nm_connection_get_setting_wireless (connection);
	ssid = g_bytes_new ("foo", 3);
	g_object_set (s_wireless,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NULL);
	g_bytes_unref (ssid);

	s_wsec = g_object_new (NM_TYPE_SETTING_WIRELESS_SECURITY,
	                       NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	                       NULL);
	nm_connection_add_setting (connection, s_wsec);

	nm_client_add_connection_async (sadata->client,
	                                connection,
	                                TRUE,
	                                NULL,
	                                connection_added_cb,
	                                sadata);
	g_object_unref (connection);

	g_main_loop_run (sadata->loop);
	g_assert (sadata->connection);

	if (nm_streq (create_agent, "1")) {
		gboolean auto_register = nmtst_get_rand_bool ();

		sadata->agent = test_secret_agent_new (auto_register);

		if (auto_register) {
			g_assert (nm_secret_agent_old_get_registered (sadata->agent));
			nm_secret_agent_old_register (sadata->agent, NULL, &error);
			g_assert_no_error (error);
		} else {
			g_assert (!nm_secret_agent_old_get_registered (sadata->agent));
			nm_secret_agent_old_register_async (sadata->agent,
			                                    NULL,
			                                    register_cb,
			                                    sadata);
			g_main_loop_run (sadata->loop);
		}

		g_assert (nm_secret_agent_old_get_registered (sadata->agent));
	}
}

static void
test_cleanup (TestSecretAgentData *sadata, gconstpointer test_data)
{
	GVariant *ret;
	GError *error = NULL;
	NMTstContextBusyWatcherData watcher_data = { };

	g_assert (nm_g_main_context_is_thread_default (NULL));

	if (!sadata->sinfo)
		return;

	nmtst_context_busy_watcher_add (&watcher_data,
	                                nm_client_get_context_busy_watcher (sadata->client));

	if (sadata->agent) {
		nmtst_context_busy_watcher_add (&watcher_data,
		                                nm_secret_agent_old_get_context_busy_watcher (sadata->agent));

		if (nm_secret_agent_old_get_registered (sadata->agent)) {
			nm_secret_agent_old_unregister (sadata->agent, NULL, &error);
			g_assert_no_error (error);
		}
		g_object_unref (sadata->agent);
	}

	ret = g_dbus_proxy_call_sync (sadata->sinfo->proxy,
	                              "RemoveDevice",
	                              g_variant_new ("(s)", nm_object_get_path (NM_OBJECT (sadata->device))),
	                              G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                              3000,
	                              NULL,
	                              &error);
	g_assert_no_error (error);
	g_variant_unref (ret);

	g_object_unref (sadata->connection);
	g_object_unref (sadata->client);

	nmtstc_service_cleanup (sadata->sinfo);

	nm_clear_g_source_inst (&sadata->timeout_source);

	g_main_loop_unref (sadata->loop);

	g_free (sadata->ifname);
	g_free (sadata->con_id);

	*sadata = (TestSecretAgentData) { };

	nmtst_context_busy_watcher_wait (&watcher_data);

	while (g_main_context_iteration (NULL, FALSE)) {
	}

	nmtst_main_context_assert_no_dispatch (NULL, nmtst_get_rand_uint32 () % 500);
}

/*****************************************************************************/

static void
connection_activated_none_cb (GObject *c,
                              GAsyncResult *result,
                              gpointer user_data)
{
	TestSecretAgentData *sadata = user_data;
	gs_free_error GError *error = NULL;

	nm_client_activate_connection_finish (sadata->client, result, &error);
	g_assert_error (error, NM_AGENT_MANAGER_ERROR, NM_AGENT_MANAGER_ERROR_NO_SECRETS);

	g_main_loop_quit (sadata->loop);
}

static void
test_secret_agent_none (TestSecretAgentData *sadata, gconstpointer test_data)
{
	if (!nmtstc_service_available (sadata->sinfo))
		return;

	nm_client_activate_connection_async (sadata->client,
	                                     sadata->connection,
	                                     sadata->device,
	                                     NULL,
	                                     NULL,
	                                     connection_activated_none_cb,
	                                     sadata);
	g_main_loop_run (sadata->loop);
}

/*****************************************************************************/

static char *
secrets_requested_no_secrets_cb (TestSecretAgent *agent,
                                 NMConnection *connection,
                                 const char *connection_path,
                                 const char *setting_name,
                                 const char *secret_name,
                                 gpointer user_data)
{
	TestSecretAgentData *sadata = user_data;

	g_assert_cmpstr (connection_path, ==, nm_connection_get_path (sadata->connection));
	sadata->secrets_requested++;

	return NULL;
}

static void
connection_activated_no_secrets_cb (GObject *c,
                                    GAsyncResult *result,
                                    gpointer user_data)
{
	TestSecretAgentData *sadata = user_data;
	gs_unref_object NMActiveConnection *ac = NULL;
	gs_free_error GError *error = NULL;

	ac = nm_client_activate_connection_finish (sadata->client, result, &error);
	g_assert_error (error, NM_AGENT_MANAGER_ERROR, NM_AGENT_MANAGER_ERROR_NO_SECRETS);
	g_main_loop_quit (sadata->loop);
}

static void
test_secret_agent_no_secrets (TestSecretAgentData *sadata, gconstpointer test_data)
{
	if (!nmtstc_service_available (sadata->sinfo))
		return;

	g_signal_connect (sadata->agent, "secret-requested",
	                  G_CALLBACK (secrets_requested_no_secrets_cb),
	                  sadata);

	nm_client_activate_connection_async (sadata->client,
	                                     sadata->connection,
	                                     sadata->device,
	                                     NULL,
	                                     NULL,
	                                     connection_activated_no_secrets_cb,
	                                     sadata);
	g_main_loop_run (sadata->loop);

	g_assert_cmpint (sadata->secrets_requested, ==, 1);
}

/*****************************************************************************/

static void
connection_activated_cancel_cb (GObject *c,
                                GAsyncResult *result,
                                gpointer user_data)
{
	TestSecretAgentData *sadata = user_data;
	gs_unref_object NMActiveConnection *ac = NULL;
	gs_free_error GError *error = NULL;

	ac = nm_client_activate_connection_finish (sadata->client, result, &error);
	g_assert_error (error, NM_AGENT_MANAGER_ERROR, NM_AGENT_MANAGER_ERROR_USER_CANCELED);
	g_main_loop_quit (sadata->loop);
}

static char *
secrets_requested_cancel_cb (TestSecretAgent *agent,
                             NMConnection *connection,
                             const char *connection_path,
                             const char *setting_name,
                             const char *secret_name,
                             gpointer user_data)
{
	TestSecretAgentData *sadata = user_data;

	g_assert_cmpstr (connection_path, ==, nm_connection_get_path (sadata->connection));
	sadata->secrets_requested++;

	return g_strdup ("CANCEL");
}

static void
test_secret_agent_cancel (TestSecretAgentData *sadata, gconstpointer test_data)
{
	if (!nmtstc_service_available (sadata->sinfo))
		return;

	g_signal_connect (sadata->agent, "secret-requested",
	                  G_CALLBACK (secrets_requested_cancel_cb),
	                  sadata);

	nm_client_activate_connection_async (sadata->client,
	                                     sadata->connection,
	                                     sadata->device,
	                                     NULL,
	                                     NULL,
	                                     connection_activated_cancel_cb,
	                                     sadata);
	g_main_loop_run (sadata->loop);

	g_assert_cmpint (sadata->secrets_requested, ==, 1);
}

/*****************************************************************************/

static void
connection_activated_good_cb (GObject *c,
                              GAsyncResult *result,
                              gpointer user_data)
{
	TestSecretAgentData *sadata = user_data;
	NMActiveConnection *ac;
	GError *error = NULL;

	ac = nm_client_activate_connection_finish (sadata->client, result, &error);
	g_assert_no_error (error);

	g_object_unref (ac);

	g_main_loop_quit (sadata->loop);
}

static char *
secrets_requested_good_cb (TestSecretAgent *agent,
                           NMConnection *connection,
                           const char *connection_path,
                           const char *setting_name,
                           const char *secret_name,
                           gpointer user_data)
{
	TestSecretAgentData *sadata = user_data;

	g_assert_cmpstr (connection_path, ==, nm_connection_get_path (sadata->connection));
	sadata->secrets_requested++;

	return g_strdup ("password");
}

static void
test_secret_agent_good (TestSecretAgentData *sadata, gconstpointer test_data)
{
	if (!nmtstc_service_available (sadata->sinfo))
		return;

	g_signal_connect (sadata->agent, "secret-requested",
	                  G_CALLBACK (secrets_requested_good_cb),
	                  sadata);

	nm_client_activate_connection_async (sadata->client,
	                                     sadata->connection,
	                                     sadata->device,
	                                     NULL,
	                                     NULL,
	                                     connection_activated_good_cb,
	                                     sadata);
	g_main_loop_run (sadata->loop);

	g_assert_cmpint (sadata->secrets_requested, ==, 1);
}

/*****************************************************************************/

static void
async_init_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	GMainLoop *loop = user_data;
	gs_free_error GError *error = NULL;
	gs_unref_object GObject *agent = NULL;

	agent = g_async_initable_new_finish (G_ASYNC_INITABLE (object), result, &error);
	nmtst_assert_success (NM_IS_SECRET_AGENT_OLD (agent), error);
	g_assert (!nm_secret_agent_old_get_registered (NM_SECRET_AGENT_OLD (agent)));

	g_main_loop_quit (loop);
}

static void
test_secret_agent_nm_not_running (void)
{
	gs_unref_object NMSecretAgentOld *agent = NULL;
	nm_auto_unref_gmainloop GMainLoop *loop = NULL;
	GError *error = NULL;

	agent = g_initable_new (test_secret_agent_get_type (),
	                        NULL,
	                        &error,
	                        NM_SECRET_AGENT_OLD_IDENTIFIER, "test-secret-agent",
	                        NULL);
	nmtst_assert_success (NM_IS_SECRET_AGENT_OLD (agent), error);
	g_assert (!nm_secret_agent_old_get_registered (agent));
	g_clear_object (&agent);

	loop = g_main_loop_new (NULL, FALSE);
	g_async_initable_new_async (test_secret_agent_get_type (),
	                            G_PRIORITY_DEFAULT,
	                            NULL,
	                            async_init_cb,
	                            loop,
	                            NM_SECRET_AGENT_OLD_IDENTIFIER, "test-secret-agent",
	                            NULL);
	g_main_loop_run (loop);
}

/*****************************************************************************/

typedef struct {
	int step;
	int invoke_count;
} AutoRegisterData;

static void
registered_changed (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMSecretAgentOld *agent = NM_SECRET_AGENT_OLD (object);
	AutoRegisterData *data = user_data;

	g_assert (data);
	g_assert (NM_IS_SECRET_AGENT_OLD (agent));

	data->invoke_count++;
	g_assert_cmpint (data->invoke_count, ==, data->step);

	switch (data->step) {
	case 1:
	case 3:
		g_assert (nm_secret_agent_old_get_registered (agent));
		break;
	case 2:
	case 4:
		g_assert (!nm_secret_agent_old_get_registered (agent));
		break;
	default:
		g_assert_not_reached ();
	}
}

static void
test_secret_agent_auto_register (void)
{
	NMTstcServiceInfo *sinfo;
	gs_unref_object NMSecretAgentOld *agent = NULL;
	GError *error = NULL;
	AutoRegisterData auto_register_data = {
		.step         = 0,
		.invoke_count = 0,
	};
	gulong signal_id;

	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	agent = test_secret_agent_new (FALSE);
	g_assert (!nm_secret_agent_old_get_registered (agent));

	signal_id = g_signal_connect (agent, "notify::" NM_SECRET_AGENT_OLD_REGISTERED,
	                              G_CALLBACK (registered_changed), &auto_register_data);

	if (nmtst_get_rand_bool ()) {
		g_object_set (agent,
		              NM_SECRET_AGENT_OLD_AUTO_REGISTER, TRUE,
		              NULL);
	} else
		nm_secret_agent_old_enable (agent, TRUE);
	g_assert (!nm_secret_agent_old_get_registered (agent));

	nm_secret_agent_old_register (agent, NULL, &error);
	g_assert_no_error (error);
	g_assert (!nm_secret_agent_old_get_registered (agent));

	auto_register_data.step = 1;
	nmtst_main_context_iterate_until (NULL,
	                                  1000,
	                                  nm_secret_agent_old_get_registered (agent));

	nmtstc_service_cleanup (sinfo);

	g_assert (nm_secret_agent_old_get_registered (agent));

	auto_register_data.step = 2;
	nmtst_main_context_iterate_until (NULL,
	                                  1000,
	                                  !nm_secret_agent_old_get_registered (agent));

	sinfo = nmtstc_service_init ();
	g_assert (nmtstc_service_available (sinfo));

	auto_register_data.step = 3;
	nmtst_main_context_iterate_until (NULL,
	                                  1000,
	                                  nm_secret_agent_old_get_registered (agent));

	nmtstc_service_cleanup (sinfo);

	auto_register_data.step = 4;
	nmtst_main_context_iterate_until (NULL,
	                                  1000,
	                                  !nm_secret_agent_old_get_registered (agent));

	nm_clear_g_signal_handler (agent, &signal_id);

	g_clear_object (&agent);
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	g_setenv ("LIBNM_USE_SESSION_BUS", "1", TRUE);

	nmtst_init (&argc, &argv, TRUE);

	g_test_add ("/libnm/secret-agent/none",       TestSecretAgentData, "0", test_setup, test_secret_agent_none,       test_cleanup);
	g_test_add ("/libnm/secret-agent/no-secrets", TestSecretAgentData, "1", test_setup, test_secret_agent_no_secrets, test_cleanup);
	g_test_add ("/libnm/secret-agent/cancel",     TestSecretAgentData, "1", test_setup, test_secret_agent_cancel,     test_cleanup);
	g_test_add ("/libnm/secret-agent/good",       TestSecretAgentData, "1", test_setup, test_secret_agent_good,       test_cleanup);
	g_test_add_func ("/libnm/secret-agent/nm-not-running", test_secret_agent_nm_not_running);
	g_test_add_func ("/libnm/secret-agent/auto-register", test_secret_agent_auto_register);

	return g_test_run ();
}
