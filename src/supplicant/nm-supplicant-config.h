/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2006 - 2012 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_SUPPLICANT_CONFIG_H__
#define __NETWORKMANAGER_SUPPLICANT_CONFIG_H__

#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>
#include <nm-setting-8021x.h>

#include "nm-supplicant-types.h"

#define NM_TYPE_SUPPLICANT_CONFIG            (nm_supplicant_config_get_type ())
#define NM_SUPPLICANT_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SUPPLICANT_CONFIG, NMSupplicantConfig))
#define NM_SUPPLICANT_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SUPPLICANT_CONFIG, NMSupplicantConfigClass))
#define NM_IS_SUPPLICANT_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SUPPLICANT_CONFIG))
#define NM_IS_SUPPLICANT_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SUPPLICANT_CONFIG))
#define NM_SUPPLICANT_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SUPPLICANT_CONFIG, NMSupplicantConfigClass))

typedef struct _NMSupplicantConfigClass NMSupplicantConfigClass;

GType nm_supplicant_config_get_type (void);

NMSupplicantConfig *nm_supplicant_config_new (void);

guint32 nm_supplicant_config_get_ap_scan (NMSupplicantConfig *self);

gboolean nm_supplicant_config_fast_required (NMSupplicantConfig *self);

GVariant *nm_supplicant_config_to_variant (NMSupplicantConfig *self);

GHashTable *nm_supplicant_config_get_blobs (NMSupplicantConfig *self);

gboolean nm_supplicant_config_add_setting_wireless (NMSupplicantConfig *self,
                                                    NMSettingWireless *setting,
                                                    guint32 fixed_freq,
                                                    GError **error);

gboolean nm_supplicant_config_add_setting_wireless_security (NMSupplicantConfig *self,
                                                             NMSettingWirelessSecurity *setting,
                                                             NMSetting8021x *setting_8021x,
                                                             const char *con_uuid,
                                                             guint32 mtu,
                                                             GError **error);

gboolean nm_supplicant_config_add_no_security (NMSupplicantConfig *self,
                                               GError **error);

gboolean nm_supplicant_config_add_setting_8021x (NMSupplicantConfig *self,
                                                 NMSetting8021x *setting,
                                                 const char *con_uuid,
                                                 guint32 mtu,
                                                 gboolean wired,
                                                 GError **error);

#endif /* __NETWORKMANAGER_SUPPLICANT_CONFIG_H__ */
