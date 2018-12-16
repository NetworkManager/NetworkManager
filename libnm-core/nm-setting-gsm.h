/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2011 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
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
