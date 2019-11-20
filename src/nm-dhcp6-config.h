// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP6_CONFIG_H__
#define __NETWORKMANAGER_DHCP6_CONFIG_H__

#define NM_TYPE_DHCP6_CONFIG            (nm_dhcp6_config_get_type ())
#define NM_DHCP6_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP6_CONFIG, NMDhcp6Config))
#define NM_DHCP6_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP6_CONFIG, NMDhcp6ConfigClass))
#define NM_IS_DHCP6_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP6_CONFIG))
#define NM_IS_DHCP6_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP6_CONFIG))
#define NM_DHCP6_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP6_CONFIG, NMDhcp6ConfigClass))

#define NM_DHCP6_CONFIG_OPTIONS "options"

typedef struct _NMDhcp6ConfigClass NMDhcp6ConfigClass;

GType nm_dhcp6_config_get_type (void);

NMDhcp6Config *nm_dhcp6_config_new (void);

void nm_dhcp6_config_set_options (NMDhcp6Config *config,
                                  GHashTable *options);

const char *nm_dhcp6_config_get_option (NMDhcp6Config *config, const char *option);

GVariant *nm_dhcp6_config_get_options (NMDhcp6Config *self);

#endif /* __NETWORKMANAGER_DHCP6_CONFIG_H__ */
