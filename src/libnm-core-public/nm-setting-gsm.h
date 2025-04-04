/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_GSM_H__
#define __NM_SETTING_GSM_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_GSM (nm_setting_gsm_get_type())
#define NM_SETTING_GSM(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_GSM, NMSettingGsm))
#define NM_SETTING_GSM_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_GSM, NMSettingGsmClass))
#define NM_IS_SETTING_GSM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_GSM))
#define NM_IS_SETTING_GSM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_GSM))
#define NM_SETTING_GSM_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_GSM, NMSettingGsmClass))

#define NM_SETTING_GSM_SETTING_NAME "gsm"

#define NM_SETTING_GSM_AUTO_CONFIG                        "auto-config"
#define NM_SETTING_GSM_USERNAME                           "username"
#define NM_SETTING_GSM_PASSWORD                           "password"
#define NM_SETTING_GSM_PASSWORD_FLAGS                     "password-flags"
#define NM_SETTING_GSM_APN                                "apn"
#define NM_SETTING_GSM_NETWORK_ID                         "network-id"
#define NM_SETTING_GSM_PIN                                "pin"
#define NM_SETTING_GSM_PIN_FLAGS                          "pin-flags"
#define NM_SETTING_GSM_HOME_ONLY                          "home-only"
#define NM_SETTING_GSM_DEVICE_ID                          "device-id"
#define NM_SETTING_GSM_SIM_ID                             "sim-id"
#define NM_SETTING_GSM_SIM_OPERATOR_ID                    "sim-operator-id"
#define NM_SETTING_GSM_MTU                                "mtu"
#define NM_SETTING_GSM_INITIAL_EPS_BEARER_CONFIGURE       "initial-eps-bearer-configure"
#define NM_SETTING_GSM_INITIAL_EPS_BEARER_APN             "initial-eps-bearer-apn"
#define NM_SETTING_GSM_INITIAL_EPS_BEARER_USERNAME        "initial-eps-bearer-username"
#define NM_SETTING_GSM_INITIAL_EPS_BEARER_PASSWORD        "initial-eps-bearer-password"
#define NM_SETTING_GSM_INITIAL_EPS_BEARER_PASSWORD_FLAGS  "initial-eps-bearer-password-flags"
#define NM_SETTING_GSM_INITIAL_EPS_BEARER_NOAUTH          "initial-eps-bearer-noauth"
#define NM_SETTING_GSM_INITIAL_EPS_BEARER_REFUSE_EAP      "initial-eps-bearer-refuse-eap"
#define NM_SETTING_GSM_INITIAL_EPS_BEARER_REFUSE_PAP      "initial-eps-bearer-refuse-pap"
#define NM_SETTING_GSM_INITIAL_EPS_BEARER_REFUSE_CHAP     "initial-eps-bearer-refuse-chap"
#define NM_SETTING_GSM_INITIAL_EPS_BEARER_REFUSE_MSCHAP   "initial-eps-bearer-refuse-mschap"
#define NM_SETTING_GSM_INITIAL_EPS_BEARER_REFUSE_MSCHAPV2 "initial-eps-bearer-refuse-mschapv2"

/* Deprecated */
#define NM_SETTING_GSM_NUMBER "number"

typedef struct _NMSettingGsmClass NMSettingGsmClass;

GType nm_setting_gsm_get_type(void);

NMSetting *nm_setting_gsm_new(void);

NM_AVAILABLE_IN_1_22
gboolean nm_setting_gsm_get_auto_config(NMSettingGsm *setting);

const char *nm_setting_gsm_get_username(NMSettingGsm *setting);
const char *nm_setting_gsm_get_password(NMSettingGsm *setting);
const char *nm_setting_gsm_get_apn(NMSettingGsm *setting);
const char *nm_setting_gsm_get_network_id(NMSettingGsm *setting);
const char *nm_setting_gsm_get_pin(NMSettingGsm *setting);
gboolean    nm_setting_gsm_get_home_only(NMSettingGsm *setting);

NM_AVAILABLE_IN_1_2
const char *nm_setting_gsm_get_device_id(NMSettingGsm *setting);
NM_AVAILABLE_IN_1_2
const char *nm_setting_gsm_get_sim_id(NMSettingGsm *setting);
NM_AVAILABLE_IN_1_2
const char *nm_setting_gsm_get_sim_operator_id(NMSettingGsm *setting);
NM_AVAILABLE_IN_1_8
guint32 nm_setting_gsm_get_mtu(NMSettingGsm *setting);
NM_AVAILABLE_IN_1_44
gboolean nm_setting_gsm_get_initial_eps_config(NMSettingGsm *setting);
NM_AVAILABLE_IN_1_44
const char *nm_setting_gsm_get_initial_eps_apn(NMSettingGsm *setting);
NM_AVAILABLE_IN_1_52
const char *nm_setting_gsm_get_initial_eps_username(NMSettingGsm *setting);
NM_AVAILABLE_IN_1_52
const char *nm_setting_gsm_get_initial_eps_password(NMSettingGsm *setting);
NM_AVAILABLE_IN_1_52
gboolean nm_setting_gsm_get_initial_eps_noauth(NMSettingGsm *setting);
NM_AVAILABLE_IN_1_52
gboolean nm_setting_gsm_get_initial_eps_refuse_eap(NMSettingGsm *setting);
NM_AVAILABLE_IN_1_52
gboolean nm_setting_gsm_get_initial_eps_refuse_pap(NMSettingGsm *setting);
NM_AVAILABLE_IN_1_52
gboolean nm_setting_gsm_get_initial_eps_refuse_chap(NMSettingGsm *setting);
NM_AVAILABLE_IN_1_52
gboolean nm_setting_gsm_get_initial_eps_refuse_mschap(NMSettingGsm *setting);
NM_AVAILABLE_IN_1_52
gboolean nm_setting_gsm_get_initial_eps_refuse_mschapv2(NMSettingGsm *setting);

NM_DEPRECATED_IN_1_16
const char *nm_setting_gsm_get_number(NMSettingGsm *setting);

NMSettingSecretFlags nm_setting_gsm_get_pin_flags(NMSettingGsm *setting);
NMSettingSecretFlags nm_setting_gsm_get_password_flags(NMSettingGsm *setting);

G_END_DECLS

#endif /* __NM_SETTING_GSM_H__ */
