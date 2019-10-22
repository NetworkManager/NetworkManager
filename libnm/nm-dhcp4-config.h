// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NM_DHCP4_CONFIG_H__
#define __NM_DHCP4_CONFIG_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_PRIVATE)
#error Cannot use this header.
#endif

#include "nm-dhcp-config.h"

#define NM_TYPE_DHCP4_CONFIG            (nm_dhcp4_config_get_type ())
#define NM_DHCP4_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP4_CONFIG, NMDhcp4Config))
#define NM_DHCP4_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP4_CONFIG, NMDhcp4ConfigClass))
#define NM_IS_DHCP4_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP4_CONFIG))
#define NM_IS_DHCP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP4_CONFIG))
#define NM_DHCP4_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP4_CONFIG, NMDhcp4ConfigClass))

/**
 * NMDhcp4Config:
 */
typedef struct _NMDhcp4Config NMDhcp4Config;
typedef struct _NMDhcp4ConfigClass NMDhcp4ConfigClass;

GType nm_dhcp4_config_get_type (void);

#endif /* __NM_DHCP4_CONFIG_H__ */
