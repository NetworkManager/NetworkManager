/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2008 - 2014 Red Hat, Inc.
 */

#ifndef __NM_IP_CONFIG_H__
#define __NM_IP_CONFIG_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_IP_CONFIG (nm_ip_config_get_type())
#define NM_IP_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_IP_CONFIG, NMIPConfig))
#define NM_IP_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_IP_CONFIG, NMIPConfigClass))
#define NM_IS_IP_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_IP_CONFIG))
#define NM_IS_IP_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_IP_CONFIG))
#define NM_IP_CONFIG_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_IP_CONFIG, NMIPConfigClass))

/**
 * NMIPConfig:
 */
typedef struct _NMIPConfigClass NMIPConfigClass;

#define NM_IP_CONFIG_FAMILY       "family"
#define NM_IP_CONFIG_GATEWAY      "gateway"
#define NM_IP_CONFIG_ADDRESSES    "addresses"
#define NM_IP_CONFIG_ROUTES       "routes"
#define NM_IP_CONFIG_NAMESERVERS  "nameservers"
#define NM_IP_CONFIG_DOMAINS      "domains"
#define NM_IP_CONFIG_SEARCHES     "searches"
#define NM_IP_CONFIG_WINS_SERVERS "wins-servers"

GType nm_ip_config_get_type(void);

int                nm_ip_config_get_family(NMIPConfig *config);
const char        *nm_ip_config_get_gateway(NMIPConfig *config);
GPtrArray         *nm_ip_config_get_addresses(NMIPConfig *config);
GPtrArray         *nm_ip_config_get_routes(NMIPConfig *config);
const char *const *nm_ip_config_get_nameservers(NMIPConfig *config);
const char *const *nm_ip_config_get_domains(NMIPConfig *config);
const char *const *nm_ip_config_get_searches(NMIPConfig *config);
const char *const *nm_ip_config_get_wins_servers(NMIPConfig *config);

G_END_DECLS

#endif /* __NM_IP_CONFIG_H__ */
