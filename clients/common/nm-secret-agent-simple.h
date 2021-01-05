/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 - 2015 Red Hat, Inc.
 */

#ifndef __NM_SECRET_AGENT_SIMPLE_H__
#define __NM_SECRET_AGENT_SIMPLE_H__

#include "nm-secret-agent-old.h"

typedef enum {
    NM_SECRET_AGENT_SECRET_TYPE_PROPERTY,
    NM_SECRET_AGENT_SECRET_TYPE_SECRET,
    NM_SECRET_AGENT_SECRET_TYPE_VPN_SECRET,
    NM_SECRET_AGENT_SECRET_TYPE_WIREGUARD_PEER_PSK,
} NMSecretAgentSecretType;

typedef struct {
    NMSecretAgentSecretType secret_type;
    const char *            pretty_name;
    const char *            entry_id;
    char *                  value;
    const char *            vpn_type;
    bool                    is_secret : 1;
    bool                    no_prompt_entry_id : 1;
} NMSecretAgentSimpleSecret;

#define NM_SECRET_AGENT_ENTRY_ID_PREFX_VPN_SECRETS "vpn.secrets."

#define NM_SECRET_AGENT_VPN_TYPE_OPENCONNECT NM_DBUS_INTERFACE ".openconnect"

/*****************************************************************************/

#define NM_TYPE_SECRET_AGENT_SIMPLE (nm_secret_agent_simple_get_type())
#define NM_SECRET_AGENT_SIMPLE(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SECRET_AGENT_SIMPLE, NMSecretAgentSimple))
#define NM_SECRET_AGENT_SIMPLE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SECRET_AGENT_SIMPLE, NMSecretAgentSimpleClass))
#define NM_IS_SECRET_AGENT_SIMPLE(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SECRET_AGENT_SIMPLE))
#define NM_IS_SECRET_AGENT_SIMPLE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SECRET_AGENT_SIMPLE))
#define NM_SECRET_AGENT_SIMPLE_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SECRET_AGENT_SIMPLE, NMSecretAgentSimpleClass))

#define NM_SECRET_AGENT_SIMPLE_REQUEST_SECRETS "request-secrets"

typedef struct _NMSecretAgentSimple      NMSecretAgentSimple;
typedef struct _NMSecretAgentSimpleClass NMSecretAgentSimpleClass;

GType nm_secret_agent_simple_get_type(void);

NMSecretAgentSimple *nm_secret_agent_simple_new(const char *name);

void nm_secret_agent_simple_response(NMSecretAgentSimple *self,
                                     const char *         request_id,
                                     GPtrArray *          secrets);

void nm_secret_agent_simple_enable(NMSecretAgentSimple *self, const char *path);

#endif /* __NM_SECRET_AGENT_SIMPLE_H__ */
