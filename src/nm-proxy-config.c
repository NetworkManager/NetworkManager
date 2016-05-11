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

