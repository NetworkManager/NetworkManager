/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#ifndef __NETWORKMANAGER_AGENT_MANAGER_H__
#define __NETWORKMANAGER_AGENT_MANAGER_H__

#include <nm-connection.h>
#include "nm-glib.h"
#include "nm-secret-agent.h"
#include "nm-types.h"

#define NM_TYPE_AGENT_MANAGER            (nm_agent_manager_get_type ())
#define NM_AGENT_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_AGENT_MANAGER, NMAgentManager))
#define NM_AGENT_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_AGENT_MANAGER, NMAgentManagerClass))
#define NM_IS_AGENT_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_AGENT_MANAGER))
#define NM_IS_AGENT_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_AGENT_MANAGER))
#define NM_AGENT_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_AGENT_MANAGER, NMAgentManagerClass))

struct _NMAgentManager {
	GObject parent;
};

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*agent_registered)   (NMAgentManager *agent_mgr, NMSecretAgent *agent);
} NMAgentManagerClass;

GType nm_agent_manager_get_type (void);

NMAgentManager *nm_agent_manager_get (void);

/* If no agent fulfilled the secrets request, agent_dbus_owner will be NULL */
typedef void (*NMAgentSecretsResultFunc) (NMAgentManager *manager,
                                          guint32 call_id,
                                          const char *agent_dbus_owner,
                                          const char *agent_uname,
                                          gboolean agent_has_modify,
                                          const char *setting_name,
                                          NMSecretAgentGetSecretsFlags flags,
                                          GHashTable *secrets,
                                          GError *error,
                                          gpointer user_data,
                                          gpointer other_data2,
                                          gpointer other_data3);

guint32 nm_agent_manager_get_secrets (NMAgentManager *manager,
                                      NMConnection *connection,
                                      NMAuthSubject *subject,
                                      GHashTable *existing_secrets,
                                      const char *setting_name,
                                      NMSecretAgentGetSecretsFlags flags,
                                      const char **hints,
                                      NMAgentSecretsResultFunc callback,
                                      gpointer callback_data,
                                      gpointer other_data2,
                                      gpointer other_data3);

void nm_agent_manager_cancel_secrets (NMAgentManager *manager,
                                      guint32 request_id);

guint32 nm_agent_manager_save_secrets (NMAgentManager *manager,
                                       NMConnection *connection,
                                       NMAuthSubject *subject);

guint32 nm_agent_manager_delete_secrets (NMAgentManager *manager,
                                         NMConnection *connection);

NMSecretAgent *nm_agent_manager_get_agent_by_user (NMAgentManager *manager,
                                                   const char *username);

gboolean nm_agent_manager_all_agents_have_capability (NMAgentManager *manager,
                                                      NMAuthSubject *subject,
                                                      NMSecretAgentCapabilities capability);

#endif /* __NETWORKMANAGER_AGENT_MANAGER_H__ */
