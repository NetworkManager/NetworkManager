/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2016 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-ppp-manager-call.h"

#include <sys/types.h>
#include <sys/stat.h>

#include "nm-manager.h"
#include "nm-core-utils.h"
#include "nm-ppp-plugin-api.h"

#define PPP_PLUGIN_PATH NMPLUGINDIR "/libnm-ppp-plugin.so"

/*****************************************************************************/

static const NMPPPOps *_ppp_ops = NULL;

#define ppp_ops_get() ((const NMPPPOps *) g_atomic_pointer_get(&_ppp_ops))

NMPPPManager *
nm_ppp_manager_create(const char *iface, GError **error)
{
    NMPPPManager   *ret;
    GModule        *plugin;
    GError         *error_local = NULL;
    struct stat     st;
    const NMPPPOps *ppp_ops;

again:
    ppp_ops = ppp_ops_get();
    if (G_UNLIKELY(!ppp_ops)) {
        if (stat(PPP_PLUGIN_PATH, &st) != 0) {
            g_set_error_literal(error,
                                NM_MANAGER_ERROR,
                                NM_MANAGER_ERROR_MISSING_PLUGIN,
                                "the PPP plugin " PPP_PLUGIN_PATH " is not installed");
            return NULL;
        }

        if (!nm_utils_validate_plugin(PPP_PLUGIN_PATH, &st, &error_local)) {
            g_set_error(error,
                        NM_MANAGER_ERROR,
                        NM_MANAGER_ERROR_MISSING_PLUGIN,
                        "could not load the PPP plugin " PPP_PLUGIN_PATH ": %s",
                        error_local->message);
            g_clear_error(&error_local);
            return NULL;
        }

        plugin = g_module_open(PPP_PLUGIN_PATH, G_MODULE_BIND_LOCAL);
        if (!plugin) {
            g_set_error(error,
                        NM_MANAGER_ERROR,
                        NM_MANAGER_ERROR_MISSING_PLUGIN,
                        "could not load the PPP plugin " PPP_PLUGIN_PATH ": %s",
                        g_module_error());
            return NULL;
        }

        if (!g_module_symbol(plugin, "ppp_ops", (gpointer *) &ppp_ops)) {
            g_set_error(error,
                        NM_MANAGER_ERROR,
                        NM_MANAGER_ERROR_MISSING_PLUGIN,
                        "error loading the PPP plugin: %s",
                        g_module_error());
            return NULL;
        }

        nm_assert(ppp_ops);
        nm_assert(ppp_ops->create);
        nm_assert(ppp_ops->start);
        nm_assert(ppp_ops->stop);
        nm_assert(ppp_ops->stop_cancel);

        if (!g_atomic_pointer_compare_and_exchange(&_ppp_ops, NULL, ppp_ops)) {
            g_module_close(plugin);
            goto again;
        }

        /* after loading glib types from the plugin, we cannot unload the library anymore.
         * Make it resident. */
        g_module_make_resident(plugin);

        nm_log_info(LOGD_CORE | LOGD_PPP, "loaded PPP plugin " PPP_PLUGIN_PATH);
    }

    ret = ppp_ops->create(iface);
    g_return_val_if_fail(ret, NULL);
    return ret;
}

gboolean
nm_ppp_manager_start(NMPPPManager *self,
                     NMActRequest *req,
                     const char   *ppp_name,
                     guint32       timeout_secs,
                     guint         baud_override,
                     GError      **err)
{
    const NMPPPOps *ppp_ops = ppp_ops_get();

    g_return_val_if_fail(ppp_ops, FALSE);

    return ppp_ops->start(self, req, ppp_name, timeout_secs, baud_override, err);
}

NMPPPManagerStopHandle *
nm_ppp_manager_stop(NMPPPManager            *self,
                    GCancellable            *cancellable,
                    NMPPPManagerStopCallback callback,
                    gpointer                 user_data)
{
    const NMPPPOps *ppp_ops = ppp_ops_get();

    g_return_val_if_fail(ppp_ops, NULL);

    return ppp_ops->stop(self, cancellable, callback, user_data);
}

void
nm_ppp_manager_stop_cancel(NMPPPManagerStopHandle *handle)
{
    const NMPPPOps *ppp_ops = ppp_ops_get();

    g_return_if_fail(ppp_ops);
    g_return_if_fail(handle);

    ppp_ops->stop_cancel(handle);
}
