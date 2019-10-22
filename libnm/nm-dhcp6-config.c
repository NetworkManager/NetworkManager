// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-dhcp6-config.h"

/*****************************************************************************/

struct _NMDhcp6Config {
	NMDhcpConfig parent;
};

struct _NMDhcp6ConfigClass{
	NMDhcpConfigClass parent;
};

G_DEFINE_TYPE (NMDhcp6Config, nm_dhcp6_config, NM_TYPE_DHCP_CONFIG)

/*****************************************************************************/

static void
nm_dhcp6_config_init (NMDhcp6Config *config)
{
}

static void
nm_dhcp6_config_class_init (NMDhcp6ConfigClass *config_class)
{
}
