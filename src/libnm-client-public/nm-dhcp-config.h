/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#ifndef __NM_DHCP_CONFIG_H__
#define __NM_DHCP_CONFIG_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_DHCP_CONFIG (nm_dhcp_config_get_type())
#define NM_DHCP_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DHCP_CONFIG, NMDhcpConfig))
#define NM_DHCP_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DHCP_CONFIG, NMDhcpConfigClass))
#define NM_IS_DHCP_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DHCP_CONFIG))
#define NM_IS_DHCP_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DHCP_CONFIG))

/**
 * NMDhcpConfig:
 */
typedef struct _NMDhcpConfigClass NMDhcpConfigClass;

#define NM_DHCP_CONFIG_FAMILY  "family"
#define NM_DHCP_CONFIG_OPTIONS "options"

GType nm_dhcp_config_get_type(void);

int nm_dhcp_config_get_family(NMDhcpConfig *config);

GHashTable *nm_dhcp_config_get_options(NMDhcpConfig *config);
const char *nm_dhcp_config_get_one_option(NMDhcpConfig *config, const char *option);

G_END_DECLS

#endif /* __NM_DHCP_CONFIG_H__ */
