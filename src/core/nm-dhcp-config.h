/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef __NM_DHCP_CONFIG_H__
#define __NM_DHCP_CONFIG_H__

/*****************************************************************************/

#define NM_TYPE_DHCP_CONFIG (nm_dhcp_config_get_type())
#define NM_DHCP_CONFIG(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DHCP_CONFIG, NMDhcpConfig))
#define NM_DHCP_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DHCP_CONFIG, NMDhcpConfigClass))
#define NM_IS_DHCP_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DHCP_CONFIG))
#define NM_IS_DHCP_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DHCP_CONFIG))
#define NM_DHCP_CONFIG_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DHCP_CONFIG, NMDhcpConfigClass))

#define NM_DHCP_CONFIG_OPTIONS "options"
#define NM_DHCP_CONFIG_L3CD    "l3cd"

typedef struct _NMDhcpConfigClass NMDhcpConfigClass;

GType nm_dhcp_config_get_type(void);

NMDhcpConfig *nm_dhcp_config_new(int addr_family, const NML3ConfigData *l3cd);

int nm_dhcp_config_get_addr_family(NMDhcpConfig *self);

void nm_dhcp_config_set_lease(NMDhcpConfig *self, const NML3ConfigData *l3cd);

NMUtilsNamedValue *nm_dhcp_config_get_option_values(NMDhcpConfig *self, guint *num);
const char        *nm_dhcp_config_get_option(NMDhcpConfig *self, const char *option);

GVariant *nm_dhcp_config_get_options(NMDhcpConfig *self);

#endif /* __NM_DHCP_CONFIG_H__ */
