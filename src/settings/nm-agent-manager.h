// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2010 - 2011 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_AGENT_MANAGER_H__
#define __NETWORKMANAGER_AGENT_MANAGER_H__

#include "nm-connection.h"

#include "nm-dbus-object.h"
#include "nm-secret-agent.h"

#define NM_TYPE_AGENT_MANAGER            (nm_agent_manager_get_type ())
#define NM_AGENT_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_AGENT_MANAGER, NMAgentManager))
#define NM_AGENT_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_AGENT_MANAGER, NMAgentManagerClass))
#define NM_IS_AGENT_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_AGENT_MANAGER))
#define NM_IS_AGENT_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_AGENT_MANAGER))
#define NM_AGENT_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_AGENT_MANAGER, NMAgentManagerClass))

#define NM_AGENT_MANAGER_AGENT_REGISTERED "agent-registered"

typedef struct _NMAgentManagerCallId *NMAgentManagerCallId;

typedef struct _NMAgentManagerClass NMAgentManagerClass;

GType nm_agent_manager_get_type (void);

NMAgentManager *nm_agent_manager_get (void);

guint64 nm_agent_manager_get_agent_version_id (NMAgentManager *self);

/* If no agent fulfilled the secrets request, agent_dbus_owner will be NULL */
typedef void (*NMAgentSecretsResultFunc) (NMAgentManager *manager,
                                          NMAgentManagerCallId call_id,
                                          const char *agent_dbus_owner,
                                          const char *agent_uname,
                                          gboolean agent_has_modify,
                                          const char *setting_name,
                                          NMSecretAgentGetSecretsFlags flags,
                                          GVariant *secrets,
                                          GError *error,
                                          gpointer user_data);

NMAgentManagerCallId nm_agent_manager_get_secrets (NMAgentManager *manager,
                                                   const char *path,
                                                   NMConnection *connection,
                                                   NMAuthSubject *subject,
                                                   GVariant *existing_secrets,
                                                   const char *setting_name,
                                                   NMSecretAgentGetSecretsFlags flags,
                                                   const char *const*hints,
                                                   NMAgentSecretsResultFunc callback,
                                                   gpointer callback_data);

void nm_agent_manager_cancel_secrets (NMAgentManager *manager,
                                      NMAgentManagerCallId request_id);

void nm_agent_manager_save_secrets (NMAgentManager *manager,
                                    const char *path,
                                    NMConnection *connection,
                                    NMAuthSubject *subject);

void nm_agent_manager_delete_secrets (NMAgentManager *manager,
                                      const char *path,
                                      NMConnection *connection);

NMSecretAgent *nm_agent_manager_get_agent_by_user (NMAgentManager *manager,
                                                   const char *username);

gboolean nm_agent_manager_all_agents_have_capability (NMAgentManager *manager,
                                                      NMAuthSubject *subject,
                                                      NMSecretAgentCapabilities capability);

#endif /* __NETWORKMANAGER_AGENT_MANAGER_H__ */
