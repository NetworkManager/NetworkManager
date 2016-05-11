/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#ifndef __NETWORKMANAGER_PROXY_CONFIG_H__
#define __NETWORKMANAGER_PROXY_CONFIG_H__

#include "nm-setting-proxy-config.h"

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



