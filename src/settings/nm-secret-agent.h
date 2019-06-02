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
 * Copyright (C) 2010 - 2011 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_SECRET_AGENT_H__
#define __NETWORKMANAGER_SECRET_AGENT_H__

#include "nm-connection.h"

#define NM_TYPE_SECRET_AGENT            (nm_secret_agent_get_type ())
#define NM_SECRET_AGENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SECRET_AGENT, NMSecretAgent))
#define NM_SECRET_AGENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SECRET_AGENT, NMSecretAgentClass))
#define NM_IS_SECRET_AGENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SECRET_AGENT))
#define NM_IS_SECRET_AGENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SECRET_AGENT))
#define NM_SECRET_AGENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SECRET_AGENT, NMSecretAgentClass))

#define NM_SECRET_AGENT_DISCONNECTED "disconnected"

typedef struct _NMSecretAgentClass NMSecretAgentClass;
typedef struct _NMSecretAgentCallId NMSecretAgentCallId;

GType nm_secret_agent_get_type (void);

NMSecretAgent *nm_secret_agent_new (GDBusMethodInvocation *context,
                                    NMAuthSubject *subject,
                                    const char *identifier,
                                    NMSecretAgentCapabilities capabilities);

const char *nm_secret_agent_get_description (NMSecretAgent *agent);

const char *nm_secret_agent_get_dbus_owner (NMSecretAgent *agent);

const char *nm_secret_agent_get_identifier (NMSecretAgent *agent);

gulong      nm_secret_agent_get_owner_uid  (NMSecretAgent *agent);

const char *nm_secret_agent_get_owner_username (NMSecretAgent *agent);

gulong      nm_secret_agent_get_pid        (NMSecretAgent *agent);

NMSecretAgentCapabilities nm_secret_agent_get_capabilities (NMSecretAgent *agent);

NMAuthSubject *nm_secret_agent_get_subject (NMSecretAgent *agent);

void        nm_secret_agent_add_permission (NMSecretAgent *agent,
                                            const char *permission,
                                            gboolean allowed);

gboolean    nm_secret_agent_has_permission (NMSecretAgent *agent,
                                            const char *permission);

typedef void (*NMSecretAgentCallback) (NMSecretAgent *agent,
                                       NMSecretAgentCallId *call_id,
                                       GVariant *new_secrets, /* NULL for save & delete */
                                       GError *error,
                                       gpointer user_data);

NMSecretAgentCallId *nm_secret_agent_get_secrets (NMSecretAgent *agent,
                                                  const char *path,
                                                  NMConnection *connection,
                                                  const char *setting_name,
                                                  const char **hints,
                                                  NMSecretAgentGetSecretsFlags flags,
                                                  NMSecretAgentCallback callback,
                                                  gpointer callback_data);

void        nm_secret_agent_cancel_secrets (NMSecretAgent *agent,
                                            NMSecretAgentCallId *call_id);

NMSecretAgentCallId *nm_secret_agent_save_secrets (NMSecretAgent *agent,
                                                   const char *path,
                                                   NMConnection *connection,
                                                   NMSecretAgentCallback callback,
                                                   gpointer callback_data);

NMSecretAgentCallId *nm_secret_agent_delete_secrets (NMSecretAgent *agent,
                                                     const char *path,
                                                     NMConnection *connection,
                                                     NMSecretAgentCallback callback,
                                                     gpointer callback_data);

#endif /* __NETWORKMANAGER_SECRET_AGENT_H__ */
