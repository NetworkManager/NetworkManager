// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef __NM_DHCP6_CONFIG_H__
#define __NM_DHCP6_CONFIG_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_PRIVATE)
#error Cannot use this header.
#endif

#include "nm-dhcp-config.h"

#define NM_TYPE_DHCP6_CONFIG            (nm_dhcp6_config_get_type ())
#define NM_DHCP6_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP6_CONFIG, NMDhcp6Config))
#define NM_DHCP6_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP6_CONFIG, NMDhcp6ConfigClass))
#define NM_IS_DHCP6_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP6_CONFIG))
#define NM_IS_DHCP6_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP6_CONFIG))

/**
 * NMDhcp6Config:
 */
typedef struct {
	NMDhcpConfig parent;
} NMDhcp6Config;

typedef struct {
	NMDhcpConfigClass parent;
} NMDhcp6ConfigClass;

GType nm_dhcp6_config_get_type (void);

#endif /* __NM_DHCP6_CONFIG_H__ */
