// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP4_CONFIG_H__
#define __NETWORKMANAGER_DHCP4_CONFIG_H__

#define NM_TYPE_DHCP4_CONFIG            (nm_dhcp4_config_get_type ())
#define NM_DHCP4_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP4_CONFIG, NMDhcp4Config))
#define NM_DHCP4_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP4_CONFIG, NMDhcp4ConfigClass))
#define NM_IS_DHCP4_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP4_CONFIG))
#define NM_IS_DHCP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP4_CONFIG))
#define NM_DHCP4_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP4_CONFIG, NMDhcp4ConfigClass))

#define NM_DHCP4_CONFIG_OPTIONS "options"

typedef struct _NMDhcp4ConfigClass NMDhcp4ConfigClass;

GType nm_dhcp4_config_get_type (void);

NMDhcp4Config *nm_dhcp4_config_new (void);

void nm_dhcp4_config_set_options (NMDhcp4Config *config,
                                  GHashTable *options);

const char *nm_dhcp4_config_get_option (NMDhcp4Config *config, const char *option);

GVariant *nm_dhcp4_config_get_options (NMDhcp4Config *config);

#endif /* __NETWORKMANAGER_DHCP4_CONFIG_H__ */
