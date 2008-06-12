/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SETTING_PPPOE_H
#define NM_SETTING_PPPOE_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_PPPOE            (nm_setting_pppoe_get_type ())
#define NM_SETTING_PPPOE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_PPPOE, NMSettingPPPOE))
#define NM_SETTING_PPPOE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_PPPOE, NMSettingPPPOEClass))
#define NM_IS_SETTING_PPPOE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_PPPOE))
#define NM_IS_SETTING_PPPOE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_PPPOE))
#define NM_SETTING_PPPOE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_PPPOE, NMSettingPPPOEClass))

#define NM_SETTING_PPPOE_SETTING_NAME "pppoe"

typedef enum
{
	NM_SETTING_PPPOE_ERROR_UNKNOWN = 0,
	NM_SETTING_PPPOE_ERROR_INVALID_PROPERTY,
	NM_SETTING_PPPOE_ERROR_MISSING_PROPERTY,
	NM_SETTING_PPPOE_ERROR_MISSING_PPP_SETTING
} NMSettingPPPOEError;

#define NM_TYPE_SETTING_PPPOE_ERROR (nm_setting_pppoe_error_get_type ()) 
GType nm_setting_pppoe_error_get_type (void);

#define NM_SETTING_PPPOE_ERROR nm_setting_pppoe_error_quark ()
GQuark nm_setting_pppoe_error_quark (void);

#define NM_SETTING_PPPOE_SERVICE  "service"
#define NM_SETTING_PPPOE_USERNAME "username"
#define NM_SETTING_PPPOE_PASSWORD "password"

typedef struct {
	NMSetting parent;

	char *service;
	char *username;
	char *password;
} NMSettingPPPOE;

typedef struct {
	NMSettingClass parent;
} NMSettingPPPOEClass;

GType nm_setting_pppoe_get_type (void);

NMSetting *nm_setting_pppoe_new (void);

G_END_DECLS

#endif /* NM_SETTING_PPPOE_H */
