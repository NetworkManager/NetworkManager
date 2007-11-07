/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SETTING_IP4_CONFIG_H
#define NM_SETTING_IP4_CONFIG_H

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_IP4_CONFIG            (nm_setting_ip4_config_get_type ())
#define NM_SETTING_IP4_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_IP4_CONFIG, NMSettingIP4Config))
#define NM_SETTING_IP4_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_IP4CONFIG, NMSettingIP4ConfigClass))
#define NM_IS_SETTING_IP4_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_IP4_CONFIG))
#define NM_IS_SETTING_IP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_IP4_CONFIG))
#define NM_SETTING_IP4_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_IP4_CONFIG, NMSettingIP4ConfigClass))

#define NM_SETTING_IP4_CONFIG_SETTING_NAME "ipv4"

#define NM_SETTING_IP4_CONFIG_MANUAL     "manual"
#define NM_SETTING_IP4_CONFIG_DNS        "dns"
#define NM_SETTING_IP4_CONFIG_DNS_SEARCH "dns-search"
#define NM_SETTING_IP4_CONFIG_ADDRESSES  "addresses"

typedef struct {
	guint32 address;
	guint32 netmask;
	guint32 gateway;
} NMSettingIP4Address;

typedef struct {
	NMSetting parent;

	gboolean manual;
	GArray *dns;        /* array of guint32 */
	GSList *dns_search; /* list of strings */
	GSList *addresses;  /* array of NMSettingIP4Address */
} NMSettingIP4Config;

typedef struct {
	NMSettingClass parent;
} NMSettingIP4ConfigClass;

GType nm_setting_ip4_config_get_type (void);

NMSetting *nm_setting_ip4_config_new (void);

G_END_DECLS

#endif /* NM_SETTING_IP4_CONFIG_H */
