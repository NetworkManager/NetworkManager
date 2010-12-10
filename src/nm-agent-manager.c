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
 * Copyright (C) 2010 Red Hat, Inc.
 */

#include <config.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "NetworkManager.h"
#include "nm-logging.h"
#include "nm-agent-manager.h"
#include "nm-secret-agent.h"
#include "nm-manager-auth.h"

G_DEFINE_TYPE (NMAgentManager, nm_agent_manager, G_TYPE_OBJECT)

#define NM_AGENT_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                         NM_TYPE_AGENT_MANAGER, \
                                         NMAgentManagerPrivate))

typedef struct {
	gboolean disposed;

	NMDBusManager *dbus_mgr;
	NMSessionMonitor *session_monitor;

	/* Hashed by owner name, not identifier, since two agents in different
	 * sessions can use the same identifier.
	 */
	GHashTable *agents;
} NMAgentManagerPrivate;


static void impl_agent_manager_register (NMAgentManager *self,
                                         const char *identifier,
                                         DBusGMethodInvocation *context);

static void impl_agent_manager_unregister (NMAgentManager *self,
                                           DBusGMethodInvocation *context);

#include "nm-agent-manager-glue.h"

/********************************************************************/

#define NM_AGENT_MANAGER_ERROR         (nm_agent_manager_error_quark ())
#define NM_TYPE_AGENT_MANAGER_ERROR    (nm_agent_manager_error_get_type ())

typedef enum {
	NM_AGENT_MANAGER_ERROR_SENDER_UNKNOWN = 0,
	NM_AGENT_MANAGER_ERROR_PERMISSION_DENIED,
	NM_AGENT_MANAGER_ERROR_SESSION_NOT_FOUND,
	NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER,
	NM_AGENT_MANAGER_ERROR_NOT_REGISTERED,
	NM_AGENT_MANAGER_ERROR_INTERNAL_ERROR
} NMAgentManagerError;

static GQuark
nm_agent_manager_error_quark (void)
{
	static GQuark ret = 0;

	if (G_UNLIKELY (ret == 0))
		ret = g_quark_from_static_string ("nm-agent-manager-error");
	return ret;
}

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_agent_manager_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unable to determine caller's sender or UID */
			ENUM_ENTRY (NM_AGENT_MANAGER_ERROR_SENDER_UNKNOWN, "SenderUnknown"),
			/* Permission for some operation was denied */
			ENUM_ENTRY (NM_AGENT_MANAGER_ERROR_PERMISSION_DENIED, "PermissionDenied"),
			/* The caller's session could not be determined */
			ENUM_ENTRY (NM_AGENT_MANAGER_ERROR_SESSION_NOT_FOUND, "SessionNotFound"),
			/* The identifier was invalid */
			ENUM_ENTRY (NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER, "InvalidIdentifier"),
			/* Request was not from a registered agent */
			ENUM_ENTRY (NM_AGENT_MANAGER_ERROR_NOT_REGISTERED, "NotRegistered"),
			/* Some internal error occurred */
			ENUM_ENTRY (NM_AGENT_MANAGER_ERROR_INTERNAL_ERROR, "InternalError"),
			{ 0, 0, 0 }
		};

		etype = g_enum_register_static ("NMAgentManagerError", values);
	}
	return etype;
}

/*************************************************************/

static gboolean
remove_agent (NMAgentManager *self, const char *owner)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	NMSecretAgent *agent;

	g_return_val_if_fail (owner != NULL, FALSE);

	agent = g_hash_table_lookup (priv->agents, owner);
	if (!agent)
		return FALSE;

	/* FIXME: signal agent removal */

	nm_log_dbg (LOGD_AGENTS, "(%s/%s) agent unregistered for UID %ld",
	            nm_secret_agent_get_dbus_owner (agent),
	            nm_secret_agent_get_identifier (agent),
	            nm_secret_agent_get_owner_uid (agent));

	g_hash_table_remove (priv->agents, owner);
	return TRUE;
}

/*************************************************************/

static gboolean
validate_identifier (const char *identifier, GError **error)
{
	const char *p = identifier;
	size_t id_len;

	if (!identifier) {
		g_set_error_literal (error,
		                     NM_AGENT_MANAGER_ERROR,
		                     NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER,
		                     "No identifier was given");
		return FALSE;
	}

	/* Length between 3 and 255 characters inclusive */
	id_len = strlen (identifier);
	if (id_len < 3 || id_len > 255) {
		g_set_error_literal (error,
		                     NM_AGENT_MANAGER_ERROR,
		                     NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER,
		                     "Identifier length not between 3 and 255 characters (inclusive)");
		return FALSE;
	}

	if ((identifier[0] == '.') || (identifier[id_len - 1] == '.')) {
		g_set_error_literal (error,
		                     NM_AGENT_MANAGER_ERROR,
		                     NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER,
		                     "Identifier must not start or end with '.'");
		return FALSE;
	}

	/* FIXME: do complete validation here */
	while (p && *p) {
		if (!isalnum (*p) && (*p != '_') && (*p != '-')) {
			g_set_error (error,
			             NM_AGENT_MANAGER_ERROR,
				         NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER,
				         "Identifier contains invalid character '%c'", *p);
			return FALSE;
		}

		if ((*p == '.') && (*(p + 1) == '.')) {
			g_set_error_literal (error,
			                     NM_AGENT_MANAGER_ERROR,
				                 NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER,
				                 "Identifier contains two '.' characters in sequence");
			return FALSE;
		}
	}

	return TRUE;
}

static void
impl_agent_manager_register (NMAgentManager *self,
                             const char *identifier,
                             DBusGMethodInvocation *context)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	char *error_desc = NULL, *sender = NULL;
	gulong sender_uid = G_MAXULONG;
	GError *error = NULL, *local = NULL;
	NMSecretAgent *agent;

	if (!nm_auth_get_caller_uid (context, 
		                         priv->dbus_mgr,
	                             &sender_uid,
	                             &error_desc)) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_SENDER_UNKNOWN,
		                             error_desc);
		g_free (error_desc);
		goto done;
	}

	if (!nm_session_monitor_uid_has_session (priv->session_monitor,
                                             sender_uid,
                                             NULL,
                                             &local)) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_SESSION_NOT_FOUND,
		                             local && local->message ? local->message : "Session not found");
		goto done;
	}

	sender = dbus_g_method_get_sender (context);
	if (!sender) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_SENDER_UNKNOWN,
		                             "Failed to get D-Bus request sender");
		goto done;
	}

	/* Validate the identifier */
	if (!validate_identifier (identifier, &error))
		goto done;

	/* Success, add the new agent */
	agent = nm_secret_agent_new (sender, identifier, sender_uid);
	if (!agent) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_INTERNAL_ERROR,
		                             "Failed to initialize the agent");
		goto done;
	}

	g_hash_table_insert (priv->agents, g_strdup (sender), agent);
	nm_log_dbg (LOGD_AGENTS, "(%s/%s) agent registered for UID %ld",
	            nm_secret_agent_get_dbus_owner (agent),
	            nm_secret_agent_get_identifier (agent),
	            nm_secret_agent_get_owner_uid (agent));
	dbus_g_method_return (context);

done:
	if (error)
		dbus_g_method_return_error (context, error);
	g_clear_error (&error);
	g_clear_error (&local);
	g_free (sender);
}

static void
impl_agent_manager_unregister (NMAgentManager *self,
                               DBusGMethodInvocation *context)
{
	GError *error = NULL;
	char *sender = NULL;

	sender = dbus_g_method_get_sender (context);
	if (!sender) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_SENDER_UNKNOWN,
		                             "Failed to get D-Bus request sender");
		goto done;
	}

	/* Found the agent, unregister and remove it */
	if (!remove_agent (self, sender)) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_NOT_REGISTERED,
		                             "Caller is not registered as an Agent");
		goto done;
	}

	dbus_g_method_return (context);

done:
	if (error)
		dbus_g_method_return_error (context, error);
	g_clear_error (&error);
	g_free (sender);
}

/*************************************************************/

static void
name_owner_changed_cb (NMDBusManager *dbus_mgr,
                       const char *name,
                       const char *old_owner,
                       const char *new_owner,
                       gpointer user_data)
{
	if (old_owner) {
		/* The agent quit, so remove it and let interested clients know */
		remove_agent (NM_AGENT_MANAGER (user_data), old_owner);
	}
}

/*************************************************************/

NMAgentManager *
nm_agent_manager_new (NMDBusManager *dbus_mgr, NMSessionMonitor *session_monitor)
{
	NMAgentManager *self;
	NMAgentManagerPrivate *priv;
	DBusGConnection *connection;

	g_return_val_if_fail (dbus_mgr != NULL, NULL);

	self = (NMAgentManager *) g_object_new (NM_TYPE_AGENT_MANAGER, NULL);
	if (self) {
		priv = NM_AGENT_MANAGER_GET_PRIVATE (self);

		priv->session_monitor = g_object_ref (session_monitor);
		priv->dbus_mgr = g_object_ref (dbus_mgr);
		connection = nm_dbus_manager_get_connection (dbus_mgr);
		dbus_g_connection_register_g_object (connection, NM_DBUS_PATH_AGENT_MANAGER, G_OBJECT (self));

		g_signal_connect (priv->dbus_mgr,
		                  NM_DBUS_MANAGER_NAME_OWNER_CHANGED,
		                  G_CALLBACK (name_owner_changed_cb),
		                  self);
	}

	return self;
}

static void
nm_agent_manager_init (NMAgentManager *self)
{
}

static void
dispose (GObject *object)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (object);

	if (priv->disposed)
		return;
	priv->disposed = TRUE;

	g_object_unref (priv->session_monitor);
	g_object_unref (priv->dbus_mgr);

	g_hash_table_destroy (priv->agents);

	G_OBJECT_CLASS (nm_agent_manager_parent_class)->dispose (object);
}

static void
nm_agent_manager_class_init (NMAgentManagerClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMAgentManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	dbus_g_error_domain_register (NM_AGENT_MANAGER_ERROR,
	                              NM_DBUS_INTERFACE_AGENT_MANAGER,
	                              NM_TYPE_AGENT_MANAGER_ERROR);
}
