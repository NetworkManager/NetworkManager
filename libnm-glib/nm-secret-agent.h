/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * (C) Copyright 2010 Red Hat, Inc.
 */

#ifndef NM_SECRET_AGENT_H
#define NM_SECRET_AGENT_H

#include <nm-connection.h>

G_BEGIN_DECLS

#define NM_SECRET_AGENT_ERROR         (nm_secret_agent_error_quark ())
#define NM_TYPE_SECRET_AGENT_ERROR    (nm_secret_agent_error_get_type ())

GQuark nm_secret_agent_error_quark (void);
GType nm_secret_agent_error_get_type (void);

typedef enum {
	NM_SECRET_AGENT_ERROR_NOT_AUTHORIZED = 0,
	NM_SECRET_AGENT_ERROR_INVALID_CONNECTION,
	NM_SECRET_AGENT_ERROR_USER_CANCELED,
	NM_SECRET_AGENT_ERROR_AGENT_CANCELED,
	NM_SECRET_AGENT_ERROR_INTERNAL_ERROR,
	NM_SECRET_AGENT_ERROR_NO_SECRETS,
} NMSecretAgentError;


#define NM_TYPE_SECRET_AGENT            (nm_secret_agent_get_type ())
#define NM_SECRET_AGENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SECRET_AGENT, NMSecretAgent))
#define NM_SECRET_AGENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SECRET_AGENT, NMSecretAgentClass))
#define NM_IS_SECRET_AGENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SECRET_AGENT))
#define NM_IS_SECRET_AGENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SECRET_AGENT))
#define NM_SECRET_AGENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SECRET_AGENT, NMSecretAgentClass))

#define NM_SECRET_AGENT_IDENTIFIER          "identifier"

#define NM_SECRET_AGENT_REGISTRATION_RESULT "registration-result"

typedef struct {
	GObject parent;
} NMSecretAgent;

typedef void (*NMSecretAgentGetSecretsFunc) (NMSecretAgent *agent,
                                             NMConnection *connection,
                                             GHashTable *secrets,
                                             GError *error,
                                             gpointer user_data);

typedef void (*NMSecretAgentSaveSecretsFunc) (NMSecretAgent *agent,
                                              NMConnection *connection,
                                              GError *error,
                                              gpointer user_data);

typedef void (*NMSecretAgentDeleteSecretsFunc) (NMSecretAgent *agent,
                                                NMConnection *connection,
                                                GError *error,
                                                gpointer user_data);

typedef struct {
	GObjectClass parent;

	/* Virtual methods for subclasses */

	/* Called when the subclass should retrieve and return secrets.  Subclass
	 * must copy or reference any arguments it may require after returning from
	 * this method, as the arguments will freed (except for 'agent', 'callback',
	 * and 'callback_data' of course).
	 */
	void (*get_secrets) (NMSecretAgent *agent,
	                     NMConnection *connection,
	                     const char *connection_path,
	                     const char *setting_name,
	                     const char **hints,
	                     gboolean request_new,
	                     NMSecretAgentGetSecretsFunc callback,
	                     gpointer callback_data);

	/* Called when the subclass should save the secrets contained in the
	 * connection to backing storage.  Subclass must copy or reference any
	 * arguments it may require after returning from this method, as the
	 * arguments will freed (except for 'agent', 'callback', and 'callback_data'
	 * of course).
	 */
	void (*save_secrets) (NMSecretAgent *agent,
	                      NMConnection *connection,
	                      const char *connection_path,
	                      NMSecretAgentSaveSecretsFunc callback,
	                      gpointer callback_data);

	/* Called when the subclass should delete the secrets contained in the
	 * connection from backing storage.  Subclass must copy or reference any
	 * arguments it may require after returning from this method, as the
	 * arguments will freed (except for 'agent', 'callback', and 'callback_data'
	 * of course).
	 */
	void (*delete_secrets) (NMSecretAgent *agent,
	                        NMConnection *connection,
	                        const char *connection_path,
	                        NMSecretAgentDeleteSecretsFunc callback,
	                        gpointer callback_data);

	/* Signals */
	void (*registration_result) (NMSecretAgent *agent, GError *error);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMSecretAgentClass;

GType nm_secret_agent_get_type (void);

NMSecretAgent *nm_secret_agent_new (const char *identifier);

gboolean nm_secret_agent_register (NMSecretAgent *self);

gboolean nm_secret_agent_unregister (NMSecretAgent *self);

void nm_secret_agent_get_secrets (NMSecretAgent *self,
                                  NMConnection *connection,
                                  const char *setting_name,
                                  const char **hints,
                                  gboolean request_new,
                                  NMSecretAgentGetSecretsFunc callback,
                                  gpointer callback_data);

void nm_secret_agent_save_secrets (NMSecretAgent *self,
                                   NMConnection *connection,
                                   NMSecretAgentSaveSecretsFunc callback,
                                   gpointer callback_data);

void nm_secret_agent_delete_secrets (NMSecretAgent *self,
                                     NMConnection *connection,
                                     NMSecretAgentDeleteSecretsFunc callback,
                                     gpointer callback_data);

G_END_DECLS

#endif /* NM_SECRET_AGENT_H */
