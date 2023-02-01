/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2008 - 2013 Red Hat, Inc.
 */

#ifndef __NM_IP_CONFIG_H__
#define __NM_IP_CONFIG_H__

#include "nm-dbus-object.h"
#include "nm-l3cfg.h"

/*****************************************************************************/

#define NM_TYPE_IP_CONFIG (nm_ip_config_get_type())
#define NM_IP_CONFIG(obj) (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_IP_CONFIG, NMIPConfig))
#define NM_IP_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_IP_CONFIG, NMIPConfigClass))
#define NM_IS_IP_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_IP_CONFIG))
#define NM_IS_IP_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_IP_CONFIG))
#define NM_IP_CONFIG_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_IP_CONFIG, NMIPConfigClass))

#define NM_IP_CONFIG_L3CFG "l3cfg"

struct _NMIPConfigPrivate {
    NML3Cfg              *l3cfg;
    const NML3ConfigData *l3cd;
    GVariant             *v_address_data;
    GVariant             *v_addresses;
    GVariant             *v_route_data;
    GVariant             *v_routes;
    struct {
        const NMPObject *best_default_route;
    } v_gateway;
    gulong l3cfg_notify_id;
};

struct _NMIPConfig {
    NMDBusObject              parent;
    struct _NMIPConfigPrivate _priv;
};

typedef struct {
    NMDBusObjectClass parent;
    int               addr_family;
} NMIPConfigClass;

GType nm_ip_config_get_type(void);

NMIPConfig *nm_ip_config_new(int addr_family, NML3Cfg *l3cfg);

void nm_ip_config_take_and_unexport_on_idle(NMIPConfig *self_take);

/*****************************************************************************/

static inline NML3Cfg *
nm_ip_config_get_l3cfg(NMIPConfig *self)
{
    g_return_val_if_fail(NM_IS_IP_CONFIG(self), NULL);

    return self->_priv.l3cfg;
}

static inline struct _NMDedupMultiIndex *
nm_ip_config_get_multi_index(NMIPConfig *self)
{
    return nm_l3cfg_get_multi_idx(nm_ip_config_get_l3cfg(self));
}

static inline int
nm_ip_config_get_ifindex(NMIPConfig *self)
{
    return nm_l3cfg_get_ifindex(nm_ip_config_get_l3cfg(self));
}

static inline int
nm_ip_config_get_addr_family(NMIPConfig *self)
{
    g_return_val_if_fail(NM_IS_IP_CONFIG(self), AF_UNSPEC);

    return NM_IP_CONFIG_GET_CLASS(self)->addr_family;
}

#endif /* __NM_IP_CONFIG_H__ */
