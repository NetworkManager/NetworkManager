/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2016 Atul Anand <atulhjp@gmail.com>.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-proxy-config.h"

#include <stdlib.h>

#include "nm-core-internal.h"

/*****************************************************************************/

typedef struct {
    NMProxyConfigMethod method;
    gboolean            browser_only;
    char *              pac_url;
    char *              pac_script;
} NMProxyConfigPrivate;

struct _NMProxyConfig {
    GObject              parent;
    NMProxyConfigPrivate _priv;
};

struct _NMProxyConfigClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NMProxyConfig, nm_proxy_config, G_TYPE_OBJECT)

#define NM_PROXY_CONFIG_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMProxyConfig, NM_IS_PROXY_CONFIG)

/*****************************************************************************/

void
nm_proxy_config_set_method(NMProxyConfig *config, NMProxyConfigMethod method)
{
    NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE(config);

    priv->method = method;
}

NMProxyConfigMethod
nm_proxy_config_get_method(const NMProxyConfig *config)
{
    const NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE(config);

    return priv->method;
}

void
nm_proxy_config_merge_setting(NMProxyConfig *config, NMSettingProxy *setting)
{
    const char *          tmp = NULL;
    NMProxyConfigPrivate *priv;
    NMSettingProxyMethod  method;

    if (!setting)
        return;

    g_return_if_fail(NM_IS_SETTING_PROXY(setting));

    priv = NM_PROXY_CONFIG_GET_PRIVATE(config);

    nm_clear_g_free(&priv->pac_script);

    method = nm_setting_proxy_get_method(setting);
    switch (method) {
    case NM_SETTING_PROXY_METHOD_AUTO:
        priv->method = NM_PROXY_CONFIG_METHOD_AUTO;

        /* Free DHCP Obtained PAC Url (i.e Option 252)
         * only when libnm overrides it.
         */
        tmp = nm_setting_proxy_get_pac_url(setting);
        if (tmp) {
            g_free(priv->pac_url);
            priv->pac_url = g_strdup(tmp);
        }

        tmp              = nm_setting_proxy_get_pac_script(setting);
        priv->pac_script = g_strdup(tmp);

        break;
    case NM_SETTING_PROXY_METHOD_NONE:
        priv->method = NM_PROXY_CONFIG_METHOD_NONE;
        break;
    }

    priv->browser_only = nm_setting_proxy_get_browser_only(setting);
}

gboolean
nm_proxy_config_get_browser_only(const NMProxyConfig *config)
{
    const NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE(config);

    return priv->browser_only;
}

void
nm_proxy_config_set_pac_url(NMProxyConfig *config, const char *url)
{
    NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE(config);

    g_free(priv->pac_url);
    priv->pac_url = g_strdup(url);
}

const char *
nm_proxy_config_get_pac_url(const NMProxyConfig *config)
{
    const NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE(config);

    return priv->pac_url;
}

void
nm_proxy_config_set_pac_script(NMProxyConfig *config, const char *script)
{
    NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE(config);

    g_free(priv->pac_script);
    priv->pac_script = g_strdup(script);
}

const char *
nm_proxy_config_get_pac_script(const NMProxyConfig *config)
{
    const NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE(config);

    return priv->pac_script;
}

/*****************************************************************************/

static void
nm_proxy_config_init(NMProxyConfig *config)
{
    NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE(config);

    priv->method = NM_PROXY_CONFIG_METHOD_NONE;
}

NMProxyConfig *
nm_proxy_config_new(void)
{
    return g_object_new(NM_TYPE_PROXY_CONFIG, NULL);
}

static void
finalize(GObject *object)
{
    NMProxyConfig *       self = NM_PROXY_CONFIG(object);
    NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE(self);

    g_free(priv->pac_url);
    g_free(priv->pac_script);

    G_OBJECT_CLASS(nm_proxy_config_parent_class)->finalize(object);
}

static void
nm_proxy_config_class_init(NMProxyConfigClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->finalize = finalize;
}
