/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#ifndef NM_SETTING_CDMA_H
#define NM_SETTING_CDMA_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_CDMA            (nm_setting_cdma_get_type ())
#define NM_SETTING_CDMA(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_CDMA, NMSettingCdma))
#define NM_SETTING_CDMA_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_CDMA, NMSettingCdmaClass))
#define NM_IS_SETTING_CDMA(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_CDMA))
#define NM_IS_SETTING_CDMA_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_CDMA))
#define NM_SETTING_CDMA_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_CDMA, NMSettingCdmaClass))

#define NM_SETTING_CDMA_SETTING_NAME "cdma"

#define NM_SETTING_CDMA_NUMBER       "number"
#define NM_SETTING_CDMA_USERNAME     "username"
#define NM_SETTING_CDMA_PASSWORD     "password"

typedef struct {
	NMSetting parent;

	char *number; /* For dialing, duh */
	char *username;
	char *password;
} NMSettingCdma;

typedef struct {
	NMSettingClass parent;
} NMSettingCdmaClass;

GType nm_setting_cdma_get_type (void);

NMSetting *nm_setting_cdma_new (void);

G_END_DECLS

#endif /* NM_SETTING_CDMA_H */
