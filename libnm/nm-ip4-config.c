/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "libnm/nm-default-libnm.h"

#include "nm-ip4-config.h"

/*****************************************************************************/

struct _NMIP4Config {
    NMIPConfig parent;
};

struct _NMIP4ConfigClass {
    NMIPConfigClass parent;
};

G_DEFINE_TYPE(NMIP4Config, nm_ip4_config, NM_TYPE_IP_CONFIG)

/*****************************************************************************/

static void
nm_ip4_config_init(NMIP4Config *config)
{}

static void
nm_ip4_config_class_init(NMIP4ConfigClass *config_class)
{}
