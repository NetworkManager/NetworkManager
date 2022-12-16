/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifndef __NM_DNS_PLUGIN_H__
#define __NM_DNS_PLUGIN_H__

#include "c-list/src/c-list.h"

#include "nm-config-data.h"

#define NM_TYPE_DNS_PLUGIN (nm_dns_plugin_get_type())
#define NM_DNS_PLUGIN(obj) (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DNS_PLUGIN, NMDnsPlugin))
#define NM_DNS_PLUGIN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DNS_PLUGIN, NMDnsPluginClass))
#define NM_IS_DNS_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DNS_PLUGIN))
#define NM_IS_DNS_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DNS_PLUGIN))
#define NM_DNS_PLUGIN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DNS_PLUGIN, NMDnsPluginClass))

#define NM_DNS_PLUGIN_UPDATE_PENDING_CHANGED "update-pending-changed"

struct _NMDnsPluginPrivate;

typedef struct {
    GObject                     parent;
    struct _NMDnsPluginPrivate *_priv;
} NMDnsPlugin;

typedef struct {
    GObjectClass parent;

    /* Called when DNS information is changed.  'configs' is an array
     * of pointers to NMDnsConfigIPData sorted by priority.
     * 'global_config' is the optional global DNS
     * configuration.
     */
    gboolean (*update)(NMDnsPlugin             *self,
                       const NMGlobalDnsConfig *global_config,
                       const CList             *ip_config_lst_head,
                       const char              *hostdomain,
                       GError                 **error);

    void (*stop)(NMDnsPlugin *self);

    gboolean (*get_update_pending)(NMDnsPlugin *self);

    const char *plugin_name;

    /* Types should set to TRUE if they start a local caching nameserver
     * that listens on localhost and would block any other local caching
     * nameserver from operating.
     */
    bool is_caching : 1;

} NMDnsPluginClass;

GType nm_dns_plugin_get_type(void);

gboolean nm_dns_plugin_is_caching(NMDnsPlugin *self);

const char *nm_dns_plugin_get_name(NMDnsPlugin *self);

gboolean nm_dns_plugin_update(NMDnsPlugin             *self,
                              const NMGlobalDnsConfig *global_config,
                              const CList             *ip_config_lst_head,
                              const char              *hostname,
                              GError                 **error);

void nm_dns_plugin_stop(NMDnsPlugin *self);

gboolean nm_dns_plugin_get_update_pending(NMDnsPlugin *self);

void _nm_dns_plugin_update_pending_maybe_changed(NMDnsPlugin *self);

#endif /* __NM_DNS_PLUGIN_H__ */
