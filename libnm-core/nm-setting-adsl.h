/* -*- mode: c; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

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
 * Copyright 2007 - 2008 Red Hat, Inc.
 */

#ifndef __NM_SETTING_ADSL_H__
#define __NM_SETTING_ADSL_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_ADSL            (nm_setting_adsl_get_type ())
#define NM_SETTING_ADSL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_ADSL, NMSettingAdsl))
#define NM_SETTING_ADSL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_ADSL, NMSettingAdslClass))
#define NM_IS_SETTING_ADSL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_ADSL))
#define NM_IS_SETTING_ADSL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_ADSL))
#define NM_SETTING_ADSL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_ADSL, NMSettingAdslClass))

#define NM_SETTING_ADSL_SETTING_NAME "adsl"

#define NM_SETTING_ADSL_USERNAME            "username"
#define NM_SETTING_ADSL_PASSWORD            "password"
#define NM_SETTING_ADSL_PASSWORD_FLAGS      "password-flags"
#define NM_SETTING_ADSL_PROTOCOL            "protocol"
#define NM_SETTING_ADSL_ENCAPSULATION       "encapsulation"
#define NM_SETTING_ADSL_VPI                 "vpi"
#define NM_SETTING_ADSL_VCI                 "vci"

#define NM_SETTING_ADSL_PROTOCOL_PPPOA      "pppoa"
#define NM_SETTING_ADSL_PROTOCOL_PPPOE      "pppoe"
#define NM_SETTING_ADSL_PROTOCOL_IPOATM     "ipoatm"

#define NM_SETTING_ADSL_ENCAPSULATION_VCMUX "vcmux"
#define NM_SETTING_ADSL_ENCAPSULATION_LLC   "llc"

/**
 * NMSettingAdsl:
 */
struct _NMSettingAdsl {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingAdslClass;

GType nm_setting_adsl_get_type (void);

NMSetting  *nm_setting_adsl_new               (void);
const char *nm_setting_adsl_get_username      (NMSettingAdsl *setting);
const char *nm_setting_adsl_get_password      (NMSettingAdsl *setting);
const char *nm_setting_adsl_get_protocol      (NMSettingAdsl *setting);
const char *nm_setting_adsl_get_encapsulation (NMSettingAdsl *setting);
guint32     nm_setting_adsl_get_vpi           (NMSettingAdsl *setting);
guint32     nm_setting_adsl_get_vci           (NMSettingAdsl *setting);
NMSettingSecretFlags nm_setting_adsl_get_password_flags (NMSettingAdsl *setting);

G_END_DECLS

#endif /* __NM_SETTING_ADSL_H__ */
