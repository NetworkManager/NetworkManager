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

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "nm-secret-agent.h"

G_DEFINE_TYPE (NMSecretAgent, nm_secret_agent, G_TYPE_OBJECT)

#define NM_SECRET_AGENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                        NM_TYPE_SECRET_AGENT, \
                                        NMSecretAgentPrivate))

typedef struct {
	gboolean disposed;

	char *owner;
	char *identifier;
	uid_t owner_uid;
} NMSecretAgentPrivate;

/*************************************************************/

const char *
nm_secret_agent_get_dbus_owner (NMSecretAgent *agent)
{
	g_return_val_if_fail (agent != NULL, NULL);
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->owner;
}

const char *
nm_secret_agent_get_identifier (NMSecretAgent *agent)
{
	g_return_val_if_fail (agent != NULL, NULL);
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->identifier;
}

uid_t
nm_secret_agent_get_owner_uid  (NMSecretAgent *agent)
{
	g_return_val_if_fail (agent != NULL, G_MAXUINT);
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), G_MAXUINT);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->owner_uid;
}

/*************************************************************/

NMSecretAgent *
nm_secret_agent_new (const char *owner,
                     const char *identifier,
                     uid_t owner_uid)
{
	NMSecretAgent *self;
	NMSecretAgentPrivate *priv;

	g_return_val_if_fail (owner != NULL, NULL);
	g_return_val_if_fail (identifier != NULL, NULL);

	self = (NMSecretAgent *) g_object_new (NM_TYPE_SECRET_AGENT, NULL);
	if (self) {
		priv = NM_SECRET_AGENT_GET_PRIVATE (self);

		priv->owner = g_strdup (owner);
		priv->identifier = g_strdup (identifier);
		priv->owner_uid = owner_uid;
	}

	return self;
}

static void
nm_secret_agent_init (NMSecretAgent *self)
{
}

static void
dispose (GObject *object)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (object);

	if (priv->disposed)
		return;
	priv->disposed = TRUE;

	g_free (priv->owner);
	g_free (priv->identifier);

	G_OBJECT_CLASS (nm_secret_agent_parent_class)->dispose (object);
}

static void
nm_secret_agent_class_init (NMSecretAgentClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMSecretAgentPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
}

