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

#ifndef __NM_SETTING_PPPOE_H__
#define __NM_SETTING_PPPOE_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_PPPOE            (nm_setting_pppoe_get_type ())
#define NM_SETTING_PPPOE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_PPPOE, NMSettingPppoe))
#define NM_SETTING_PPPOE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_PPPOE, NMSettingPppoeClass))
#define NM_IS_SETTING_PPPOE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_PPPOE))
#define NM_IS_SETTING_PPPOE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_PPPOE))
#define NM_SETTING_PPPOE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_PPPOE, NMSettingPppoeClass))

#define NM_SETTING_PPPOE_SETTING_NAME "pppoe"

#define NM_SETTING_PPPOE_SERVICE        "service"
#define NM_SETTING_PPPOE_USERNAME       "username"
#define NM_SETTING_PPPOE_PASSWORD       "password"
#define NM_SETTING_PPPOE_PASSWORD_FLAGS "password-flags"

/**
 * NMSettingPppoe:
 */
struct _NMSettingPppoe {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingPppoeClass;

GType nm_setting_pppoe_get_type (void);

NMSetting  *nm_setting_pppoe_new          (void);
const char *nm_setting_pppoe_get_service  (NMSettingPppoe *setting);
const char *nm_setting_pppoe_get_username (NMSettingPppoe *setting);
const char *nm_setting_pppoe_get_password (NMSettingPppoe *setting);
NMSettingSecretFlags nm_setting_pppoe_get_password_flags (NMSettingPppoe *setting);

G_END_DECLS

#endif /* __NM_SETTING_PPPOE_H__ */
