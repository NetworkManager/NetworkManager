/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "libnm-client-impl/nm-default-libnm.h"

#include "nm-dhcp4-config.h"

/*****************************************************************************/

struct _NMDhcp4Config {
    NMDhcpConfig parent;
};

struct _NMDhcp4ConfigClass {
    NMDhcpConfigClass parent;
};

G_DEFINE_TYPE(NMDhcp4Config, nm_dhcp4_config, NM_TYPE_DHCP_CONFIG)

/*****************************************************************************/

static void
nm_dhcp4_config_init(NMDhcp4Config *config)
{}

static void
nm_dhcp4_config_class_init(NMDhcp4ConfigClass *config_class)
{}
