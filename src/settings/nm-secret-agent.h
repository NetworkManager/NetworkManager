// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2010 - 2011 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_SECRET_AGENT_H__
#define __NETWORKMANAGER_SECRET_AGENT_H__

#include "nm-connection.h"

#include "c-list/src/c-list.h"

#define NM_TYPE_SECRET_AGENT            (nm_secret_agent_get_type ())
#define NM_SECRET_AGENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SECRET_AGENT, NMSecretAgent))
#define NM_SECRET_AGENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SECRET_AGENT, NMSecretAgentClass))
#define NM_IS_SECRET_AGENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SECRET_AGENT))
#define NM_IS_SECRET_AGENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SECRET_AGENT))
#define NM_SECRET_AGENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SECRET_AGENT, NMSecretAgentClass))

#define NM_SECRET_AGENT_DISCONNECTED "disconnected"

typedef struct _NMSecretAgentClass NMSecretAgentClass;
typedef struct _NMSecretAgentCallId NMSecretAgentCallId;

struct _NMSecretAgentPrivate;

struct _NMSecretAgent {
	GObject parent;
	CList agent_lst;
	struct _NMSecretAgentPrivate *_priv;
};

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

void nm_secret_agent_cancel_call (NMSecretAgent *self,
                                  NMSecretAgentCallId *call_id);

#endif /* __NETWORKMANAGER_SECRET_AGENT_H__ */
