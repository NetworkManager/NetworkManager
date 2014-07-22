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
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_SECRET_AGENT_H
#define NMT_SECRET_AGENT_H

#include <nm-secret-agent.h>

G_BEGIN_DECLS

#define NMT_TYPE_SECRET_AGENT            (nmt_secret_agent_get_type ())
#define NMT_SECRET_AGENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_SECRET_AGENT, NmtSecretAgent))
#define NMT_SECRET_AGENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_SECRET_AGENT, NmtSecretAgentClass))
#define NMT_IS_SECRET_AGENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_SECRET_AGENT))
#define NMT_IS_SECRET_AGENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_SECRET_AGENT))
#define NMT_SECRET_AGENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_SECRET_AGENT, NmtSecretAgentClass))

typedef struct {
	NMSecretAgent parent;

} NmtSecretAgent;

typedef struct {
	NMSecretAgentClass parent;

} NmtSecretAgentClass;

typedef struct {
	char *name, *value;
	gboolean password;
} NmtSecretAgentSecret;

GType nmt_secret_agent_get_type (void);

NMSecretAgent *nmt_secret_agent_new      (void);
void           nmt_secret_agent_response (NmtSecretAgent *self,
                                          const char     *request_id,
                                          GPtrArray      *secrets);

G_END_DECLS

#endif /* NMT_SECRET_AGENT_H */
