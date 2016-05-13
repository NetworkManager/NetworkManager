/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include "nm-default.h"

#include "nm-proxy-config.h"

#include <string.h>

#include "nm-utils.h"
#include "NetworkManagerUtils.h"

#define NM_PROXY_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_PROXY_CONFIG, NMProxyConfigPrivate))

G_DEFINE_TYPE (NMProxyConfig, nm_proxy_config, G_TYPE_OBJECT)

typedef struct {
	NMProxyConfigMethod method;
	GPtrArray *proxies;
	char *pac_url;
	char *pac_script;
} NMProxyConfigPrivate;

NM_GOBJECT_PROPERTIES_DEFINE (NMProxyConfig,
	PROP_METHOD,
	PROP_PROXIES,
	PROP_PAC_URL,
	PROP_PAC_SCRIPT,
);

NMProxyConfig *
nm_proxy_config_new (void)
{
	return NM_PROXY_CONFIG (g_object_new (NM_TYPE_PROXY_CONFIG, NULL));
}

void
nm_proxy_config_merge_setting (NMProxyConfig *config, NMSettingProxy *setting)
{
	NMProxyConfigPrivate *priv;
	guint nproxies;
	int i;
	char *pac_url, *pac_script;

	if (!setting)
		return;

	g_return_if_fail (NM_IS_SETTING_PROXY (setting));

	priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	g_free (priv->method);
	priv->method = NM_PROXY_CONFIG_METHOD_MANUAL;
	_notify (config, PROP_METHOD);

	nproxies = nm_setting_proxy_get_num_proxies (setting);
	for (i = 0; i < nproxies; i++)
		nm_proxy_config_add_proxy (config, nm_setting_proxy_get_proxy (setting, i));
	_notify (config, PROP_PROXIES);

	pac_url = nm_setting_proxy_get_pac_url (setting);
	if (!nm_streq0 (pac_url, priv->pac_url)) {
		g_free (priv->pac_url);
		priv->pac_url = g_strdup (pac_url);
		_notify (config, PROP_PAC_URL);
	}

	pac_script = nm_setting_proxy_get_pac_script (setting);
	if (!nm_streq0 (pac_script, priv->pac_script)) {
		g_free (priv->pac_script);
		priv->pac_script = g_strdup (pac_script);
		_notify (config, PROP_PAC_SCRIPT);
	}
}

NMSetting
nm_proxy_config_create_setting (const NMProxyConfig *config)
{
	NMSettingProxy *s_p;
	guint nproxies;
	int i;

	s_p = NM_SETTING_PROXY (nm_setting_proxy_new ());

	if (!config)
		return NM_SETTING (s_p);
	
	nproxies = nm_proxy_config_get_num_proxies (config);
	for (i = 0; i < nproxies; i++) {
		const char *proxy = nm_proxy_config_get_proxy (config, i);
	
		nm_setting_proxy_add_proxy (s_p, proxy);
	}

	nm_setting_proxy_set_pac_url (s_p, nm_proxy_config_get_pac_url (config));
	nm_setting_proxy_set_pac_script (s_p, nm_proxy_config_get_pac_script (config));

	return NM_SETTING (s_p);
}

void
nm_proxy_config_set_method (NMProxyConfig *config, NMProxyConfigMethod method)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	priv->method = method;
}

NMProxyConfigMethod
nm_proxy_config_get_method (const NMProxyConfig *config)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	return priv->method;
}

void
nm_proxy_config_reset_proxies (NMProxyConfig *config)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	if (priv->proxies->len !=0) {
		g_ptr_array_set_size (priv->proxies, 0);
		_notify (config, PROP_PROXIES);
	}
}

void
nm_proxy_config_add_proxy (NMProxyConfig *config, const char *proxy)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);
	int i;

	g_return_if_fail (proxy != NULL);
	g_return_if_fail (proxy[0] != '\0');

	for (i = 0; i < priv->proxies->len; i++)
		if (!g_strcmp0 (g_ptr_array_index (priv->proxies, i), proxy))
			return;

	g_ptr_array_add (priv->proxies, g_strdup (proxy));
	_notify (config, PROP_PROXIES);
}

void
nm_proxy_config_del_proxy (NMProxyConfig *config, guint i)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->proxies->len);

	g_ptr_array_remove_index (priv->proxies, i);
	_notify (config, PROP_PROXIES);
}

guint32
nm_proxy_config_get_num_proxies (const NMProxyConfig *config)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	return priv->proxies->len;
}

const char *
nm_proxy_config_get_proxy (const NMProxyConfig *config, guint i)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	return g_ptr_array_index (priv->proxies, i);
}

void
nm_proxy_config_set_pac_url (NMProxyConfig *config, const char *url)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	g_free (priv->pac_url);
	priv->pac_url = g_strdup (url);
}

const char *
nm_proxy_config_get_pac_url (const NMProxyConfig *config)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	return priv->pac_url;
}

void
nm_proxy_config_set_pac_script (NMProxyConfig *config, const char *script)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	g_free (priv->pac_script);
	priv->pac_script = g_strdup (script);
}

const char *
nm_proxy_config_get_pac_script (const NMProxyConfig *config)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	return priv->pac_script;
}

static void
nm_proxy_config_init (NMProxyConfig *config)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	priv->method = NM_PROXY_CONFIG_METHOD_NONE;
	priv->proxies = g_ptr_array_new_with_free_func (g_free);
}

static void
finalize (GObject *object)
{
	NMProxyConfig *self = NM_PROXY_CONFIG (object);
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (self);

	g_ptr_array_unref (priv->proxies);
	g_free (priv->pac_url);
	g_free (priv->pac_script);

	G_OBJECT_CLASS (nm_proxy_config_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
    NMProxyConfig *config = NM_PROXY_CONFIG (object);
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_int (value, priv->method);
		break;
	case PROP_PROXIES:
		nm_utils_g_value_set_strv (value, priv->proxies);
		break;
	case PROP_PAC_URL:
		g_value_set_string (value, priv->pac_url);
		break;
	case PROP_PAC_SCRIPT:
		g_value_set_string (value, priv->pac_script);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_proxy_config_class_init (NMProxyConfigClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMProxyConfigPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	obj_properties[PROP_METHOD] =
		g_param_spec_int (NM_PROXY_CONFIG_METHOD, "", "",
                          0, G_MAXINT, 0,
                          G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT_ONLY |
                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_PROXIES] =
		g_param_spec_boxed (NM_PROXY_CONFIG_PROXIES, "", "",
                            G_TYPE_STRV,
                            G_PARAM_READABLE |
                            G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_PAC_URL] =
		g_param_spec_string (NM_PROXY_CONFIG_PAC_URL, "", "",
                             NULL,
                             G_PARAM_READABLE |
                             G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_PAC_SCRIPT] =
		g_param_spec_string (NM_PROXY_CONFIG_PAC_SCRIPT, "", "",
                             NULL,
                             G_PARAM_READABLE |
                             G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
