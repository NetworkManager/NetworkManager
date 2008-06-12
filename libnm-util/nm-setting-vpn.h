/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SETTING_VPN_H
#define NM_SETTING_VPN_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_VPN            (nm_setting_vpn_get_type ())
#define NM_SETTING_VPN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_VPN, NMSettingVPN))
#define NM_SETTING_VPN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_VPN, NMSettingVPNClass))
#define NM_IS_SETTING_VPN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_VPN))
#define NM_IS_SETTING_VPN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_VPN))
#define NM_SETTING_VPN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_VPN, NMSettingVPNClass))

#define NM_SETTING_VPN_SETTING_NAME "vpn"

typedef enum
{
	NM_SETTING_VPN_ERROR_UNKNOWN = 0,
	NM_SETTING_VPN_ERROR_INVALID_PROPERTY,
	NM_SETTING_VPN_ERROR_MISSING_PROPERTY,
} NMSettingVpnError;

#define NM_TYPE_SETTING_VPN_ERROR (nm_setting_vpn_error_get_type ()) 
GType nm_setting_vpn_error_get_type (void);

#define NM_SETTING_VPN_ERROR nm_setting_vpn_error_quark ()
GQuark nm_setting_vpn_error_quark (void);

#define NM_SETTING_VPN_SERVICE_TYPE "service-type"
#define NM_SETTING_VPN_USER_NAME    "user-name"
#define NM_SETTING_VPN_ROUTES       "routes"

typedef struct {
	NMSetting parent;

	char *service_type;
	char *user_name;
	GSList *routes;
} NMSettingVPN;

typedef struct {
	NMSettingClass parent;
} NMSettingVPNClass;

GType nm_setting_vpn_get_type (void);

NMSetting *nm_setting_vpn_new (void);

G_END_DECLS

#endif /* NM_SETTING_VPN_H */
