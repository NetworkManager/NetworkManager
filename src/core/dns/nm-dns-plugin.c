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

#include "libnm-core-intern/nm-core-internal.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

enum {
    UPDATE_PENDING_CHANGED,
    LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

typedef struct _NMDnsPluginPrivate {
    bool update_pending_inited : 1;
    bool update_pending : 1;
} NMDnsPluginPrivate;

G_DEFINE_ABSTRACT_TYPE(NMDnsPlugin, nm_dns_plugin, G_TYPE_OBJECT)

#define NM_DNS_PLUGIN_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMDnsPlugin, NM_IS_DNS_PLUGIN)

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME "dns-plugin"
#define _NMLOG_DOMAIN      LOGD_DNS
#define _NMLOG(level, ...)                                                                      \
    G_STMT_START                                                                                \
    {                                                                                           \
        const NMLogLevel __level = (level);                                                     \
                                                                                                \
        if (nm_logging_enabled(__level, _NMLOG_DOMAIN)) {                                       \
            char                     __prefix[20];                                              \
            const NMDnsPlugin *const __self = (self);                                           \
                                                                                                \
            _nm_log(__level,                                                                    \
                    _NMLOG_DOMAIN,                                                              \
                    0,                                                                          \
                    NULL,                                                                       \
                    NULL,                                                                       \
                    "%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                                \
                    _NMLOG_PREFIX_NAME,                                                         \
                    (!__self ? ""                                                               \
                             : nm_sprintf_buf(__prefix,                                         \
                                              "[" NM_HASH_OBFUSCATE_PTR_FMT "]",                \
                                              NM_HASH_OBFUSCATE_PTR(                            \
                                                  __self))) _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        }                                                                                       \
    }                                                                                           \
    G_STMT_END

/*****************************************************************************/

gboolean
nm_dns_plugin_update(NMDnsPlugin             *self,
                     const NMGlobalDnsConfig *global_config,
                     const CList             *ip_config_lst_head,
                     const char              *hostdomain,
                     GError                 **error)
{
    g_return_val_if_fail(NM_DNS_PLUGIN_GET_CLASS(self)->update != NULL, FALSE);

    return NM_DNS_PLUGIN_GET_CLASS(self)->update(self,
                                                 global_config,
                                                 ip_config_lst_head,
                                                 hostdomain,
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

static gboolean
_get_update_pending(NMDnsPlugin *self)
{
    NMDnsPluginClass *klass;

    nm_assert(NM_IS_DNS_PLUGIN(self));

    klass = NM_DNS_PLUGIN_GET_CLASS(self);
    if (klass->get_update_pending) {
        if (klass->get_update_pending(self))
            return TRUE;
    }
    return FALSE;
}

gboolean
nm_dns_plugin_get_update_pending(NMDnsPlugin *self)
{
    NMDnsPluginPrivate *priv;

    g_return_val_if_fail(NM_IS_DNS_PLUGIN(self), FALSE);

    priv = NM_DNS_PLUGIN_GET_PRIVATE(self);

    /* We cache the boolean and rely on the subclass to call
     * _nm_dns_plugin_update_pending_maybe_changed(). The subclass
     * anyway must get it right to notify us when the value (maybe)
     * changes. By caching the value, the subclass is free to notify
     * even if the value did not actually change.
     *
     * Also, this allows the base implementation to combine multiple
     * sources/reasons (if we need that in the future). */

    if (!priv->update_pending_inited) {
        priv->update_pending_inited = TRUE;
        priv->update_pending        = _get_update_pending(self);
        _LOGD("[%s] update-pending changed (%spending)",
              nm_dns_plugin_get_name(self),
              priv->update_pending ? "" : "not ");
    } else
        nm_assert(priv->update_pending == _get_update_pending(self));

    return priv->update_pending;
}

void
_nm_dns_plugin_update_pending_maybe_changed(NMDnsPlugin *self)
{
    NMDnsPluginPrivate *priv;
    gboolean            v;

    g_return_if_fail(NM_IS_DNS_PLUGIN(self));

    priv = NM_DNS_PLUGIN_GET_PRIVATE(self);

    v = _get_update_pending(self);

    if (!priv->update_pending_inited)
        priv->update_pending_inited = TRUE;
    else if (priv->update_pending == v)
        return;

    priv->update_pending = v;

    _LOGD("[%s] update-pending changed (%spending)",
          nm_dns_plugin_get_name(self),
          priv->update_pending ? "" : "not ");

    g_signal_emit(self, signals[UPDATE_PENDING_CHANGED], 0, (gboolean) priv->update_pending);
}

/*****************************************************************************/

static void
nm_dns_plugin_init(NMDnsPlugin *self)
{
    NMDnsPluginPrivate *priv;

    priv = G_TYPE_INSTANCE_GET_PRIVATE(self, NM_TYPE_DNS_PLUGIN, NMDnsPluginPrivate);

    self->_priv = priv;

    nm_assert(priv->update_pending_inited == FALSE);
    nm_assert(priv->update_pending == FALSE);

    nm_shutdown_wait_obj_register_object(self, "dns-plugin");
}

static void
nm_dns_plugin_class_init(NMDnsPluginClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    g_type_class_add_private(object_class, sizeof(NMDnsPluginPrivate));

    signals[UPDATE_PENDING_CHANGED] = g_signal_new(NM_DNS_PLUGIN_UPDATE_PENDING_CHANGED,
                                                   G_OBJECT_CLASS_TYPE(klass),
                                                   G_SIGNAL_RUN_FIRST,
                                                   0,
                                                   NULL,
                                                   NULL,
                                                   NULL,
                                                   G_TYPE_NONE,
                                                   1,
                                                   G_TYPE_BOOLEAN);
}
