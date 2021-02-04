/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "libnm/nm-default-libnm.h"

#include "nm-ip6-config.h"

/*****************************************************************************/

struct _NMIP6Config {
    NMIPConfig parent;
};

struct _NMIP6ConfigClass {
    NMIPConfigClass parent;
};

G_DEFINE_TYPE(NMIP6Config, nm_ip6_config, NM_TYPE_IP_CONFIG)

/*****************************************************************************/

static void
nm_ip6_config_init(NMIP6Config *config)
{}

static void
nm_ip6_config_class_init(NMIP6ConfigClass *config_class)
{}
