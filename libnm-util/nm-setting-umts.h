/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SETTING_UMTS_H
#define NM_SETTING_UMTS_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_UMTS            (nm_setting_umts_get_type ())
#define NM_SETTING_UMTS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_UMTS, NMSettingUmts))
#define NM_SETTING_UMTS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_UMTS, NMSettingUmtsClass))
#define NM_IS_SETTING_UMTS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_UMTS))
#define NM_IS_SETTING_UMTS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_UMTS))
#define NM_SETTING_UMTS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_UMTS, NMSettingUmtsClass))

#define NM_SETTING_UMTS_SETTING_NAME "umts"

#define NM_SETTING_UMTS_NUMBER       "number"
#define NM_SETTING_UMTS_USERNAME     "username"
#define NM_SETTING_UMTS_PASSWORD     "password"
#define NM_SETTING_UMTS_APN          "apn"
#define NM_SETTING_UMTS_NETWORK_ID   "network-id"
#define NM_SETTING_UMTS_NETWORK_TYPE "network-type"
#define NM_SETTING_UMTS_BAND         "band"
#define NM_SETTING_UMTS_PIN          "pin"
#define NM_SETTING_UMTS_PUK          "puk"

enum {
	NM_UMTS_NETWORK_ANY = -1,
	NM_UMTS_NETWORK_GPRS = 0,
	NM_UMTS_NETWORK_UMTS = 1,
	NM_UMTS_NETWORK_PREFER_GPRS = 2,
	NM_UMTS_NETWORK_PREFER_UMTS = 3,
};

typedef struct {
	NMSetting parent;

	char *number; /* For dialing, duh */
	char *username;
	char *password;

	char *apn; /* NULL for dynamic */
	char *network_id; /* for manual registration or NULL for automatic */
	int network_type; /* One of the NM_UMTS_NETWORK_* */
	int band;

	char *pin;
	char *puk;
} NMSettingUmts;

typedef struct {
	NMSettingClass parent;
} NMSettingUmtsClass;

GType nm_setting_umts_get_type (void);

NMSetting *nm_setting_umts_new (void);

G_END_DECLS

#endif /* NM_SETTING_UMTS_H */
