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
 * Copyright 2017 Red Hat, Inc.
 */

#ifndef __NM_SETTING_METADATA_H__
#define __NM_SETTING_METADATA_H__

#include "nm-setting-8021x.h"

/*****************************************************************************/

typedef struct {
	const char *setting_key;
	NMSetting8021xCKScheme (*scheme_func) (NMSetting8021x *setting);
	NMSetting8021xCKFormat (*format_func) (NMSetting8021x *setting);
	const char *           (*path_func)   (NMSetting8021x *setting);
	GBytes *               (*blob_func)   (NMSetting8021x *setting);
	const char *           (*uri_func)    (NMSetting8021x *setting);
	const char *           (*passwd_func) (NMSetting8021x *setting);
	NMSettingSecretFlags   (*pwflag_func) (NMSetting8021x *setting);
	const char *file_suffix;
} NMSetting8021xSchemeVtable;

enum {
	NM_SETTING_802_1X_SCHEME_TYPE_CA_CERT,
	NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CA_CERT,
	NM_SETTING_802_1X_SCHEME_TYPE_CLIENT_CERT,
	NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CLIENT_CERT,
	NM_SETTING_802_1X_SCHEME_TYPE_PRIVATE_KEY,
	NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_PRIVATE_KEY,

	NM_SETTING_802_1X_SCHEME_TYPE_UNKNOWN,
};

extern const NMSetting8021xSchemeVtable nm_setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_UNKNOWN + 1];

/*****************************************************************************/

#endif /* __NM_SETTING_METADATA_H__ */
