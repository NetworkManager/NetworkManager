/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2010 - 2011 Red Hat, Inc.
 */

#ifndef __NM_SECRET_AGENT_OLD_H__
#define __NM_SECRET_AGENT_OLD_H__

#include "nm-types.h"

G_BEGIN_DECLS

#define NM_TYPE_SECRET_AGENT_OLD            (nm_secret_agent_old_get_type ())
#define NM_SECRET_AGENT_OLD(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SECRET_AGENT_OLD, NMSecretAgentOld))
#define NM_SECRET_AGENT_OLD_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SECRET_AGENT_OLD, NMSecretAgentOldClass))
#define NM_IS_SECRET_AGENT_OLD(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SECRET_AGENT_OLD))
#define NM_IS_SECRET_AGENT_OLD_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SECRET_AGENT_OLD))
#define NM_SECRET_AGENT_OLD_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SECRET_AGENT_OLD, NMSecretAgentOldClass))

#define NM_SECRET_AGENT_OLD_IDENTIFIER          "identifier"
#define NM_SECRET_AGENT_OLD_AUTO_REGISTER       "auto-register"
#define NM_SECRET_AGENT_OLD_REGISTERED          "registered"
#define NM_SECRET_AGENT_OLD_CAPABILITIES        "capabilities"

/**
 * NMSecretAgentOld:
 */
typedef struct {
	GObject parent;
} NMSecretAgentOld;

/**
 * NMSecretAgentOldGetSecretsFunc:
 * @agent: the secret agent object
 * @connection: (transfer none): the connection for which secrets were requested,
 * note that this object will be unrefed after the callback has returned, use
 * g_object_ref()/g_object_unref() if you want to use this object after the callback
 * has returned
 * @secrets: the #GVariant of type %NM_VARIANT_TYPE_CONNECTION containing the requested
 * secrets (as created by nm_connection_to_dbus() for example).  Each key in @secrets
 * should be the name of a #NMSetting object (like "802-11-wireless-security")
 * and each value should be an %NM_VARIANT_TYPE_SETTING variant.  The sub-dicts
 * map string:value, where the string is the setting property name (like "psk")
 * and the value is the secret
 * @error: if the secrets request failed, give a descriptive error here
 * @user_data: caller-specific data to be passed to the function
 *
 * Called as a result of a request by NM to retrieve secrets.  When the
 * #NMSecretAgentOld subclass has finished retrieving secrets and is ready to
 * return them, or to return an error, this function should be called with
 * those secrets or the error.
 *
 * To easily create the dictionary to return the Wi-Fi PSK, you could do
 * something like this:
 * <example>
 *  <title>Creating a secrets dictionary</title>
 *  <programlisting>
 *   NMConnection *secrets;
 *   NMSettingWirelessSecurity *s_wsec;
 *   GVariant *secrets_dict;
 *
 *   secrets = nm_simple_connection_new ();
 *   s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
 *   g_object_set (G_OBJECT (s_wsec),
 *                 NM_SETTING_WIRELESS_SECURITY_PSK, "my really cool PSK",
 *                 NULL);
 *   nm_connection_add_setting (secrets, NM_SETTING (s_wsec));
 *   secrets_dict = nm_connection_to_dbus (secrets, NM_CONNECTION_SERIALIZE_ALL);
 *
 *   (call the NMSecretAgentOldGetSecretsFunc with secrets_dict)
 *
 *   g_object_unref (secrets);
 *   g_variant_unref (secrets_dict);
 *  </programlisting>
 * </example>
 */
typedef void (*NMSecretAgentOldGetSecretsFunc) (NMSecretAgentOld *agent,
                                                NMConnection *connection,
                                                GVariant *secrets,
                                                GError *error,
                                                gpointer user_data);

/**
 * NMSecretAgentOldSaveSecretsFunc:
 * @agent: the secret agent object
 * @connection: (transfer none): the connection for which secrets were to be saved,
 * note that this object will be unrefed after the callback has returned, use
 * g_object_ref()/g_object_unref() if you want to use this object after the callback
 * has returned
 * @error: if the saving secrets failed, give a descriptive error here
 * @user_data: caller-specific data to be passed to the function
 *
 * Called as a result of a request by NM to save secrets.  When the
 * #NMSecretAgentOld subclass has finished saving the secrets, this function
 * should be called.
 */
typedef void (*NMSecretAgentOldSaveSecretsFunc) (NMSecretAgentOld *agent,
                                                 NMConnection *connection,
                                                 GError *error,
                                                 gpointer user_data);

/**
 * NMSecretAgentOldDeleteSecretsFunc:
 * @agent: the secret agent object
 * @connection: (transfer none): the connection for which secrets were to be deleted,
 * note that this object will be unrefed after the callback has returned, use
 * g_object_ref()/g_object_unref() if you want to use this object after the callback
 * has returned
 * @error: if the deleting secrets failed, give a descriptive error here
 * @user_data: caller-specific data to be passed to the function
 *
 * Called as a result of a request by NM to delete secrets.  When the
 * #NMSecretAgentOld subclass has finished deleting the secrets, this function
 * should be called.
 */
typedef void (*NMSecretAgentOldDeleteSecretsFunc) (NMSecretAgentOld *agent,
                                                   NMConnection *connection,
                                                   GError *error,
                                                   gpointer user_data);

typedef struct {
	GObjectClass parent;

	/* Virtual methods for subclasses */

	/* Called when the subclass should retrieve and return secrets.  Subclass
	 * must copy or reference any arguments it may require after returning from
	 * this method, as the arguments will freed (except for 'self', 'callback',
	 * and 'user_data' of course).  If the request is canceled, the callback
	 * should still be called, but with the
	 * NM_SECRET_AGENT_OLD_ERROR_AGENT_CANCELED error.
	 */
	void (*get_secrets) (NMSecretAgentOld *self,
	                     NMConnection *connection,
	                     const char *connection_path,
	                     const char *setting_name,
	                     const char **hints,
	                     NMSecretAgentGetSecretsFlags flags,
	                     NMSecretAgentOldGetSecretsFunc callback,
	                     gpointer user_data);

	/* Called when the subclass should cancel an outstanding request to
	 * get secrets for a given connection.  Canceling the request MUST
	 * call the callback that was passed along with the initial get_secrets
	 * call, sending the NM_SECRET_AGENT_OLD_ERROR/
	 * NM_SECRET_AGENT_OLD_ERROR_AGENT_CANCELED error to that callback.
	 */
	void (*cancel_get_secrets) (NMSecretAgentOld *self,
	                            const char *connection_path,
	                            const char *setting_name);

	/* Called when the subclass should save the secrets contained in the
	 * connection to backing storage.  Subclass must copy or reference any
	 * arguments it may require after returning from this method, as the
	 * arguments will freed (except for 'self', 'callback', and 'user_data'
	 * of course).
	 */
	void (*save_secrets) (NMSecretAgentOld *self,
	                      NMConnection *connection,
	                      const char *connection_path,
	                      NMSecretAgentOldSaveSecretsFunc callback,
	                      gpointer user_data);

	/* Called when the subclass should delete the secrets contained in the
	 * connection from backing storage.  Subclass must copy or reference any
	 * arguments it may require after returning from this method, as the
	 * arguments will freed (except for 'self', 'callback', and 'user_data'
	 * of course).
	 */
	void (*delete_secrets) (NMSecretAgentOld *self,
	                        NMConnection *connection,
	                        const char *connection_path,
	                        NMSecretAgentOldDeleteSecretsFunc callback,
	                        gpointer user_data);

	/*< private >*/
	gpointer padding[8];
} NMSecretAgentOldClass;

GType nm_secret_agent_old_get_type (void);

gboolean nm_secret_agent_old_register        (NMSecretAgentOld *self,
                                              GCancellable *cancellable,
                                              GError **error);
void     nm_secret_agent_old_register_async  (NMSecretAgentOld *self,
                                              GCancellable *cancellable,
                                              GAsyncReadyCallback callback,
                                              gpointer user_data);
gboolean nm_secret_agent_old_register_finish (NMSecretAgentOld *self,
                                              GAsyncResult *result,
                                              GError **error);

gboolean nm_secret_agent_old_unregister        (NMSecretAgentOld *self,
                                                GCancellable *cancellable,
                                                GError **error);
void     nm_secret_agent_old_unregister_async  (NMSecretAgentOld *self,
                                                GCancellable *cancellable,
                                                GAsyncReadyCallback callback,
                                                gpointer user_data);
gboolean nm_secret_agent_old_unregister_finish (NMSecretAgentOld *self,
                                                GAsyncResult *result,
                                                GError **error);

gboolean nm_secret_agent_old_get_registered (NMSecretAgentOld *self);

void nm_secret_agent_old_get_secrets (NMSecretAgentOld *self,
                                      NMConnection *connection,
                                      const char *setting_name,
                                      const char **hints,
                                      NMSecretAgentGetSecretsFlags flags,
                                      NMSecretAgentOldGetSecretsFunc callback,
                                      gpointer user_data);

void nm_secret_agent_old_save_secrets (NMSecretAgentOld *self,
                                       NMConnection *connection,
                                       NMSecretAgentOldSaveSecretsFunc callback,
                                       gpointer user_data);

void nm_secret_agent_old_delete_secrets (NMSecretAgentOld *self,
                                         NMConnection *connection,
                                         NMSecretAgentOldDeleteSecretsFunc callback,
                                         gpointer user_data);

G_END_DECLS

#endif /* __NM_SECRET_AGENT_OLD_H__ */
