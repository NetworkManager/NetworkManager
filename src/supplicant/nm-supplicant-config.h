// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2006 - 2012 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_SUPPLICANT_CONFIG_H__
#define __NETWORKMANAGER_SUPPLICANT_CONFIG_H__

#include "nm-setting-macsec.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"

#include "nm-supplicant-types.h"

#define NM_TYPE_SUPPLICANT_CONFIG            (nm_supplicant_config_get_type ())
#define NM_SUPPLICANT_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SUPPLICANT_CONFIG, NMSupplicantConfig))
#define NM_SUPPLICANT_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SUPPLICANT_CONFIG, NMSupplicantConfigClass))
#define NM_IS_SUPPLICANT_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SUPPLICANT_CONFIG))
#define NM_IS_SUPPLICANT_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SUPPLICANT_CONFIG))
#define NM_SUPPLICANT_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SUPPLICANT_CONFIG, NMSupplicantConfigClass))

typedef struct _NMSupplicantConfigClass NMSupplicantConfigClass;

GType nm_supplicant_config_get_type (void);

NMSupplicantConfig *nm_supplicant_config_new (NMSupplCapMask capabilities);

guint32 nm_supplicant_config_get_ap_scan (NMSupplicantConfig *self);

gboolean nm_supplicant_config_fast_required (NMSupplicantConfig *self);

GVariant *nm_supplicant_config_to_variant (NMSupplicantConfig *self);

GHashTable *nm_supplicant_config_get_blobs (NMSupplicantConfig *self);

gboolean nm_supplicant_config_add_setting_wireless (NMSupplicantConfig *self,
                                                    NMSettingWireless *setting,
                                                    guint32 fixed_freq,
                                                    GError **error);

gboolean nm_supplicant_config_add_bgscan           (NMSupplicantConfig *self,
                                                    NMConnection *connection,
                                                    GError **error);

gboolean nm_supplicant_config_add_setting_wireless_security (NMSupplicantConfig *self,
                                                             NMSettingWirelessSecurity *setting,
                                                             NMSetting8021x *setting_8021x,
                                                             const char *con_uuid,
                                                             guint32 mtu,
                                                             NMSettingWirelessSecurityPmf pmf,
                                                             NMSettingWirelessSecurityFils fils,
                                                             GError **error);

gboolean nm_supplicant_config_add_no_security (NMSupplicantConfig *self,
                                               GError **error);

gboolean nm_supplicant_config_add_setting_8021x (NMSupplicantConfig *self,
                                                 NMSetting8021x *setting,
                                                 const char *con_uuid,
                                                 guint32 mtu,
                                                 gboolean wired,
                                                 GError **error);

gboolean nm_supplicant_config_add_setting_macsec (NMSupplicantConfig *self,
                                                  NMSettingMacsec *setting,
                                                  GError **error);

gboolean nm_supplicant_config_enable_pmf_akm (NMSupplicantConfig *self,
                                              GError **error);
#endif /* __NETWORKMANAGER_SUPPLICANT_CONFIG_H__ */
