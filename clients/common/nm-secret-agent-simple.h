/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 - 2015 Red Hat, Inc.
 */

#ifndef __NM_SECRET_AGENT_SIMPLE_H__
#define __NM_SECRET_AGENT_SIMPLE_H__

#include <NetworkManager.h>
#include <nm-secret-agent-old.h>

G_BEGIN_DECLS

#define NM_TYPE_SECRET_AGENT_SIMPLE            (nm_secret_agent_simple_get_type ())
#define NM_SECRET_AGENT_SIMPLE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SECRET_AGENT_SIMPLE, NMSecretAgentSimple))
#define NM_SECRET_AGENT_SIMPLE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SECRET_AGENT_SIMPLE, NMSecretAgentSimpleClass))
#define NM_IS_SECRET_AGENT_SIMPLE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SECRET_AGENT_SIMPLE))
#define NM_IS_SECRET_AGENT_SIMPLE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SECRET_AGENT_SIMPLE))
#define NM_SECRET_AGENT_SIMPLE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SECRET_AGENT_SIMPLE, NMSecretAgentSimpleClass))

typedef struct {
	NMSecretAgentOld parent;

} NMSecretAgentSimple;

typedef struct {
	NMSecretAgentOldClass parent;

} NMSecretAgentSimpleClass;

typedef struct {
	char *name, *prop_name, *value;
	char *vpn_property;
	char *vpn_type;
	gboolean password;
} NMSecretAgentSimpleSecret;

GType nm_secret_agent_simple_get_type (void);

NMSecretAgentOld *nm_secret_agent_simple_new                 (const char          *name);

void              nm_secret_agent_simple_response            (NMSecretAgentSimple *self,
                                                              const char          *request_id,
                                                              GPtrArray           *secrets);

void              nm_secret_agent_simple_enable              (NMSecretAgentSimple *self,
                                                              const char          *path);

G_END_DECLS

#endif /* __NM_SECRET_AGENT_SIMPLE_H__ */
