// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager
 *
 * (C) Copyright 2016 Atul Anand <atulhjp@gmail.com>.
 */

#ifndef __NETWORKMANAGER_PROXY_CONFIG_H__
#define __NETWORKMANAGER_PROXY_CONFIG_H__

#include "nm-setting-proxy.h"

typedef enum {
	NM_PROXY_CONFIG_METHOD_AUTO = 0,
	NM_PROXY_CONFIG_METHOD_NONE
} NMProxyConfigMethod;

#define NM_TYPE_PROXY_CONFIG (nm_proxy_config_get_type ())
#define NM_PROXY_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PROXY_CONFIG, NMProxyConfig))
#define NM_PROXY_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PROXY_CONFIG, NMProxyConfigClass))
#define NM_IS_PROXY_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PROXY_CONFIG))
#define NM_IS_PROXY_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_PROXY_CONFIG))
#define NM_PROXY_CONFIG_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PROXY_CONFIG, NMProxyConfigClass))

typedef struct _NMProxyConfigClass NMProxyConfigClass;

GType nm_proxy_config_get_type (void);

NMProxyConfig * nm_proxy_config_new (void);

void nm_proxy_config_set_method (NMProxyConfig *config, NMProxyConfigMethod method);
NMProxyConfigMethod nm_proxy_config_get_method (const NMProxyConfig *config);

void nm_proxy_config_merge_setting (NMProxyConfig *config, NMSettingProxy *setting);

gboolean nm_proxy_config_get_browser_only (const NMProxyConfig *config);

void nm_proxy_config_set_pac_url (NMProxyConfig *config, const char *url);
const char * nm_proxy_config_get_pac_url (const NMProxyConfig *config);

void nm_proxy_config_set_pac_script (NMProxyConfig *config, const char *script);
const char * nm_proxy_config_get_pac_script (const NMProxyConfig *config);

#endif /* __NETWORKMANAGER_PROXY_CONFIG_H__ */
