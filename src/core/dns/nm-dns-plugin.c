/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2010 - 2012 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-dns-plugin.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

typedef struct _NMDnsPluginPrivate {
    GPid  pid;
    guint watch_id;
    char *progname;
    char *pidfile;
} NMDnsPluginPrivate;

G_DEFINE_ABSTRACT_TYPE(NMDnsPlugin, nm_dns_plugin, G_TYPE_OBJECT)

#define NM_DNS_PLUGIN_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMDnsPlugin, NM_IS_DNS_PLUGIN)

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME "dns-plugin"
#define _NMLOG_DOMAIN      LOGD_DNS
#define _NMLOG(level, ...)                                                    \
    G_STMT_START                                                              \
    {                                                                         \
        const NMLogLevel __level = (level);                                   \
                                                                              \
        if (nm_logging_enabled(__level, _NMLOG_DOMAIN)) {                     \
            char                     __prefix[20];                            \
            const NMDnsPlugin *const __self = (self);                         \
                                                                              \
            _nm_log(__level,                                                  \
                    _NMLOG_DOMAIN,                                            \
                    0,                                                        \
                    NULL,                                                     \
                    NULL,                                                     \
                    "%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),              \
                    _NMLOG_PREFIX_NAME,                                       \
                    (!__self ? "" : nm_sprintf_buf(__prefix, "[%p]", __self)) \
                        _NM_UTILS_MACRO_REST(__VA_ARGS__));                   \
        }                                                                     \
    }                                                                         \
    G_STMT_END

/*****************************************************************************/

gboolean
nm_dns_plugin_update(NMDnsPlugin *            self,
                     const NMGlobalDnsConfig *global_config,
                     const CList *            ip_config_lst_head,
                     const char *             hostname,
                     GError **                error)
{
    g_return_val_if_fail(NM_DNS_PLUGIN_GET_CLASS(self)->update != NULL, FALSE);

    return NM_DNS_PLUGIN_GET_CLASS(self)->update(self,
                                                 global_config,
                                                 ip_config_lst_head,
                                                 hostname,
                                                 error);
}

gboolean
nm_dns_plugin_is_caching(NMDnsPlugin *self)
{
    return NM_DNS_PLUGIN_GET_CLASS(self)->is_caching;
}

const char *
nm_dns_plugin_get_name(NMDnsPlugin *self)
{
    NMDnsPluginClass *klass;

    g_return_val_if_fail(NM_IS_DNS_PLUGIN(self), NULL);

    klass = NM_DNS_PLUGIN_GET_CLASS(self);
    nm_assert(klass->plugin_name);
    return klass->plugin_name;
}

void
nm_dns_plugin_stop(NMDnsPlugin *self)
{
    NMDnsPluginClass *klass;

    g_return_if_fail(NM_IS_DNS_PLUGIN(self));

    klass = NM_DNS_PLUGIN_GET_CLASS(self);
    if (klass->stop)
        klass->stop(self);
}

/*****************************************************************************/

static void
nm_dns_plugin_init(NMDnsPlugin *self)
{}

static void
nm_dns_plugin_class_init(NMDnsPluginClass *plugin_class)
{}
