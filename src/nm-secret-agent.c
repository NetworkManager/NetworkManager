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
} NMSecretAgentPrivate;

/*************************************************************/

NMSecretAgent *
nm_secret_agent_new (const char *owner, const char *identifier)
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

