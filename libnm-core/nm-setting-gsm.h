// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_GSM_H__
#define __NM_SETTING_GSM_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_GSM            (nm_setting_gsm_get_type ())
#define NM_SETTING_GSM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_GSM, NMSettingGsm))
#define NM_SETTING_GSM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_GSM, NMSettingGsmClass))
#define NM_IS_SETTING_GSM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_GSM))
#define NM_IS_SETTING_GSM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_GSM))
#define NM_SETTING_GSM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_GSM, NMSettingGsmClass))

#define NM_SETTING_GSM_SETTING_NAME "gsm"

#define NM_SETTING_GSM_AUTO_CONFIG     "auto-config"
#define NM_SETTING_GSM_USERNAME        "username"
#define NM_SETTING_GSM_PASSWORD        "password"
#define NM_SETTING_GSM_PASSWORD_FLAGS  "password-flags"
#define NM_SETTING_GSM_APN             "apn"
#define NM_SETTING_GSM_NETWORK_ID      "network-id"
#define NM_SETTING_GSM_PIN             "pin"
#define NM_SETTING_GSM_PIN_FLAGS       "pin-flags"
#define NM_SETTING_GSM_HOME_ONLY       "home-only"
#define NM_SETTING_GSM_DEVICE_ID       "device-id"
#define NM_SETTING_GSM_SIM_ID          "sim-id"
#define NM_SETTING_GSM_SIM_OPERATOR_ID "sim-operator-id"
#define NM_SETTING_GSM_MTU             "mtu"

/* Deprecated */
#define NM_SETTING_GSM_NUMBER          "number"

/**
 * NMSettingGsm:
 *
 * GSM-based Mobile Broadband Settings
 */
struct _NMSettingGsm {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingGsmClass;

GType nm_setting_gsm_get_type (void);

NMSetting *nm_setting_gsm_new                  (void);

NM_AVAILABLE_IN_1_22
gboolean    nm_setting_gsm_get_auto_config     (NMSettingGsm *setting);

const char *nm_setting_gsm_get_username        (NMSettingGsm *setting);
const char *nm_setting_gsm_get_password        (NMSettingGsm *setting);
const char *nm_setting_gsm_get_apn             (NMSettingGsm *setting);
const char *nm_setting_gsm_get_network_id      (NMSettingGsm *setting);
const char *nm_setting_gsm_get_pin             (NMSettingGsm *setting);
gboolean    nm_setting_gsm_get_home_only       (NMSettingGsm *setting);

NM_AVAILABLE_IN_1_2
const char *nm_setting_gsm_get_device_id       (NMSettingGsm *setting);
NM_AVAILABLE_IN_1_2
const char *nm_setting_gsm_get_sim_id          (NMSettingGsm *setting);
NM_AVAILABLE_IN_1_2
const char *nm_setting_gsm_get_sim_operator_id (NMSettingGsm *setting);
NM_AVAILABLE_IN_1_8
guint32 nm_setting_gsm_get_mtu                 (NMSettingGsm *setting);

NM_DEPRECATED_IN_1_16
const char *nm_setting_gsm_get_number          (NMSettingGsm *setting);

NMSettingSecretFlags nm_setting_gsm_get_pin_flags      (NMSettingGsm *setting);
NMSettingSecretFlags nm_setting_gsm_get_password_flags (NMSettingGsm *setting);

G_END_DECLS

#endif /* __NM_SETTING_GSM_H__ */
