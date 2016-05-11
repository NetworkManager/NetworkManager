/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include "nm-proxy-config.h"

#define NM_PROXY_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_PROXY_CONFIG, NMProxyConfigPrivate))

G_DEFINE_TYPE (NMProxyConfig, nm_proxy_config, G_TYPE_OBJECT)

typedef struct {
	NMProxyConfigMethod method;
	GArray *proxies;
	char *pac_url;
	char *pac_script;
} NMProxyConfigPrivate;

NM_GOBJECT_PROPERTIES_DEFINE (NMProxyConfig,
	PROP_METHOD,
	PROP_PROXIES,
	PROP_PAC_URL,
	PROP_PAC_SCRIPT
);

NMProxyConfig *
nm_proxy_config_new (void)
{
	return NM_PROXY_CONFIG (g_object_new (NM_PROXY_CONFIG, NULL));
}

void
nm_proxy_config_merge_setting (NMProxyConfig *config, NMSettingProxyConfig *setting)
{
	NMProxyConfigPrivate *priv;
	guint nproxies;
	int i;
	char *pac_url, *pac_script;

	if (!setting)
		return;

	g_return_if_fail (NM_IS_SETTING_PROXY_CONFIG (setting));

	priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	g_free (priv->method);
	priv->method = NM_PROXY_CONFIG_METHOD_MANUAL;
	_notify (config, PROP_METHOD);

	nproxies = nm_setting_proxy_config_get_num_proxies (setting);
	for (i = 0; i < nproxies; i++)
		nm_proxy_config_add_proxy (config, nm_setting_proxy_config_get_proxy (setting, i));
	_notify (config, PROP_PROXIES);

	pac_url = nm_setting_proxy_config_get_pac_url (setting);
	if (!nm_streq0 (pac_url, priv->pac_url)) {
		g_free (priv->pac_url);
		priv->pac_url = g_strdup (pac_url);
		_notify (config, PROP_PAC_URL);
	}

	pac_script = nm_setting_proxy_config_get_pac_script (setting);
	if (!nm_streq0 (pac_script, priv->pac_script)) {
		g_free (priv->pac_script);
		priv->pac_script = g_strdup (pac_script);
		_notify (config, PROP_PAC_SCRIPT);
	}
}
