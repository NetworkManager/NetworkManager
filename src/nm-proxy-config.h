/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#ifndef __NETWORKMANAGER_PROXY_CONFIG_H__
#define __NETWORKMANAGER_PROXY_CONFIG_H__

#include "nm-setting-proxy.h"

typedef enum {
	NM_PROXY_CONFIG_METHOD_NONE = 0,
	NM_PROXY_CONFIG_METHOD_AUTO,
	NM_PROXY_CONFIG_METHOD_MANUAL
} NMProxyConfigMethod;

#define NM_TYPE_PROXY_CONFIG (nm_proxy_config_get_type ())
#define NM_PROXY_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PROXY_CONFIG, NMProxyConfig))
#define NM_PROXY_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PROXY_CONFIG, NMProxyConfigClass))
#define NM_IS_PROXY_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PROXY_CONFIG))
#define NM_IS_PROXY_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_PROXY_CONFIG))
#define NM_PROXY_CONFIG_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PROXY_CONFIG, NMProxyConfigClass))

struct _NMProxyConfig {
	GObject parent;
};

typedef struct {
	GObjectClass parent;
} NMProxyConfigClass;

#define NM_PROXY_CONFIG_METHOD "method"
#define NM_PROXY_CONFIG_PROXIES "proxies"
#define NM_PROXY_CONFIG_PAC_URL "pac-url"
#define NM_PROXY_CONFIG_PAC_SCRIPT "pac-script"

GType nm_proxy_config_get_type (void);

NMProxyConfig * nm_proxy_config_new (void);

void nm_proxy_config_merge_setting (NMProxyConfig *config, NMSettingProxy *setting);
NMSetting nm_proxy_config_create_setting (const NMProxyConfig *config);

void nm_proxy_config_set_method (NMProxyConfig *config, NMProxyConfigMethod method);
NMProxyConfigMethod nm_proxy_config_get_method (const NMProxyConfig *config);

void nm_proxy_config_reset_proxies (NMProxyConfig *config);
void nm_proxy_config_add_proxy (NMProxyConfig *config, const char *proxy);
void nm_proxy_config_del_proxy (NMProxyConfig *config, guint i);
guint32 nm_proxy_config_get_num_proxies (const NMProxyConfig *config);
const char * nm_proxy_config_get_proxy (const NMProxyConfig *config, guint i);

void nm_proxy_config_set_pac_url (NMProxyConfig *config, const char *url);
const char * nm_proxy_config_get_pac_url (const NMProxyConfig *config);

void nm_proxy_config_set_pac_script (NMProxyConfig *config, const char *script);
const char * nm_proxy_config_get_pac_script (const NMProxyConfig *config);

#endif /* __NETWORKMANAGER_PROXY_CONFIG_H__ */
