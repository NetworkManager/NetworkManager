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

#ifndef __NM_SETTING_CDMA_H__
#define __NM_SETTING_CDMA_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_CDMA            (nm_setting_cdma_get_type ())
#define NM_SETTING_CDMA(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_CDMA, NMSettingCdma))
#define NM_SETTING_CDMA_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_CDMA, NMSettingCdmaClass))
#define NM_IS_SETTING_CDMA(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_CDMA))
#define NM_IS_SETTING_CDMA_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_CDMA))
#define NM_SETTING_CDMA_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_CDMA, NMSettingCdmaClass))

#define NM_SETTING_CDMA_SETTING_NAME "cdma"

#define NM_SETTING_CDMA_NUMBER         "number"
#define NM_SETTING_CDMA_USERNAME       "username"
#define NM_SETTING_CDMA_PASSWORD       "password"
#define NM_SETTING_CDMA_PASSWORD_FLAGS "password-flags"

/**
 * NMSettingCdma:
 */
struct _NMSettingCdma {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingCdmaClass;

GType nm_setting_cdma_get_type (void);

NMSetting  *nm_setting_cdma_new          (void);
const char *nm_setting_cdma_get_number   (NMSettingCdma *setting);
const char *nm_setting_cdma_get_username (NMSettingCdma *setting);
const char *nm_setting_cdma_get_password (NMSettingCdma *setting);
NMSettingSecretFlags nm_setting_cdma_get_password_flags (NMSettingCdma *setting);

G_END_DECLS

#endif /* __NM_SETTING_CDMA_H__ */
