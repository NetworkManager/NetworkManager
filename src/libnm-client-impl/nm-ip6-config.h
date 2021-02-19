/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2008 - 2014 Red Hat, Inc.
 */

#ifndef __NM_IP6_CONFIG_H__
#define __NM_IP6_CONFIG_H__

#if !((NETWORKMANAGER_COMPILATION) &NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_PRIVATE)
    #error Cannot use this header.
#endif

#include "nm-ip-config.h"

#define NM_TYPE_IP6_CONFIG (nm_ip6_config_get_type())
#define NM_IP6_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_IP6_CONFIG, NMIP6Config))
#define NM_IP6_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_IP6_CONFIG, NMIP6ConfigClass))
#define NM_IS_IP6_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_IP6_CONFIG))
#define NM_IS_IP6_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_IP6_CONFIG))
#define NM_IP6_CONFIG_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_IP6_CONFIG, NMIP6ConfigClass))

/**
 * NMIP6Config:
 */
typedef struct _NMIP6Config      NMIP6Config;
typedef struct _NMIP6ConfigClass NMIP6ConfigClass;

GType nm_ip6_config_get_type(void);

#endif /* __NM_IP6_CONFIG_H__ */
