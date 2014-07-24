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
 * Copyright 2011 Red Hat, Inc.
 */

#ifndef NM_SETTING_INFINIBAND_H
#define NM_SETTING_INFINIBAND_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_INFINIBAND            (nm_setting_infiniband_get_type ())
#define NM_SETTING_INFINIBAND(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_INFINIBAND, NMSettingInfiniband))
#define NM_SETTING_INFINIBAND_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_INFINIBAND, NMSettingInfinibandClass))
#define NM_IS_SETTING_INFINIBAND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_INFINIBAND))
#define NM_IS_SETTING_INFINIBAND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_INFINIBAND))
#define NM_SETTING_INFINIBAND_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_INFINIBAND, NMSettingInfinibandClass))

#define NM_SETTING_INFINIBAND_SETTING_NAME "infiniband"

/**
 * NMSettingInfinibandError:
 * @NM_SETTING_INFINIBAND_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_INFINIBAND_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_INFINIBAND_ERROR_MISSING_PROPERTY: the property was missing and is
 * required
 */
typedef enum {
	NM_SETTING_INFINIBAND_ERROR_UNKNOWN = 0,      /*< nick=UnknownError >*/
	NM_SETTING_INFINIBAND_ERROR_INVALID_PROPERTY, /*< nick=InvalidProperty >*/
	NM_SETTING_INFINIBAND_ERROR_MISSING_PROPERTY  /*< nick=MissingProperty >*/
} NMSettingInfinibandError;

#define NM_SETTING_INFINIBAND_ERROR nm_setting_infiniband_error_quark ()
GQuark nm_setting_infiniband_error_quark (void);

#define NM_SETTING_INFINIBAND_MAC_ADDRESS    "mac-address"
#define NM_SETTING_INFINIBAND_MTU            "mtu"
#define NM_SETTING_INFINIBAND_TRANSPORT_MODE "transport-mode"
#define NM_SETTING_INFINIBAND_P_KEY          "p-key"
#define NM_SETTING_INFINIBAND_PARENT         "parent"

typedef struct {
	NMSetting parent;
} NMSettingInfiniband;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingInfinibandClass;

GType nm_setting_infiniband_get_type (void);

NMSetting *       nm_setting_infiniband_new                (void);
const GByteArray *nm_setting_infiniband_get_mac_address    (NMSettingInfiniband *setting);
guint32           nm_setting_infiniband_get_mtu            (NMSettingInfiniband *setting);
const char *      nm_setting_infiniband_get_transport_mode (NMSettingInfiniband *setting);
int               nm_setting_infiniband_get_p_key          (NMSettingInfiniband *setting);
const char *      nm_setting_infiniband_get_parent         (NMSettingInfiniband *setting);

G_END_DECLS

#endif /* NM_SETTING_INFINIBAND_H */
