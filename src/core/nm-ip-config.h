/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2008 - 2013 Red Hat, Inc.
 */

#ifndef __NM_IP_CONFIG_H__
#define __NM_IP_CONFIG_H__

#include "nm-dbus-object.h"

/*****************************************************************************/

#define NM_TYPE_IP_CONFIG (nm_ip_config_get_type())
#define NM_IP_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_IP_CONFIG, NMIPConfig))
#define NM_IP_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_IP_CONFIG, NMIPConfigClass))
#define NM_IS_IP_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_IP_CONFIG))
#define NM_IS_IP_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_IP_CONFIG))
#define NM_IP_CONFIG_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_IP_CONFIG, NMIPConfigClass))

#define NM_IP_CONFIG_L3CFG  "l3cfg"
#define NM_IP_CONFIG_IS_VPN "is-vpn"

struct _NMIPConfigPrivate;

struct _NMIPConfig {
    NMDBusObject               parent;
    struct _NMIPConfigPrivate *_priv;
};

typedef struct {
    NMDBusObjectClass parent;
    gboolean          is_ipv4;
    int               addr_family;
} NMIPConfigClass;

GType nm_ip_config_get_type(void);
GType nm_ip4_config_get_type(void);
GType nm_ip6_config_get_type(void);

NMIPConfig *nm_ip_config_new(int addr_family, NML3Cfg *l3cfg, gboolean is_vpn);

#endif /* __NM_IP_CONFIG_H__ */
