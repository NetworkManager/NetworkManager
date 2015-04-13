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
 * Copyright 2009 Novell, Inc.
 */

#ifndef NM_SETTING_WIMAX_H
#define NM_SETTING_WIMAX_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_WIMAX            (nm_setting_wimax_get_type ())
#define NM_SETTING_WIMAX(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_WIMAX, NMSettingWimax))
#define NM_SETTING_WIMAX_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_WIMAX, NMSettingWimaxClass))
#define NM_IS_SETTING_WIMAX(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_WIMAX))
#define NM_IS_SETTING_WIMAX_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_WIMAX))
#define NM_SETTING_WIMAX_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_WIMAX, NMSettingWimaxClass))

#define NM_SETTING_WIMAX_SETTING_NAME "wimax"

/**
 * NMSettingWimaxError:
 * @NM_SETTING_WIMAX_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_WIMAX_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_WIMAX_ERROR_MISSING_PROPERTY: the property was missing and is
 * required
 */
typedef enum {
	NM_SETTING_WIMAX_ERROR_UNKNOWN = 0,      /*< nick=UnknownError >*/
	NM_SETTING_WIMAX_ERROR_INVALID_PROPERTY, /*< nick=InvalidProperty >*/
	NM_SETTING_WIMAX_ERROR_MISSING_PROPERTY  /*< nick=MissingProperty >*/
} NMSettingWimaxError;

#define NM_SETTING_WIMAX_ERROR nm_setting_wimax_error_quark ()
NM_DEPRECATED_IN_1_2
GQuark nm_setting_wimax_error_quark (void);

#define NM_SETTING_WIMAX_NETWORK_NAME "network-name"
#define NM_SETTING_WIMAX_MAC_ADDRESS  "mac-address"

typedef struct {
	NMSetting parent;
} NMSettingWimax;

typedef struct {
	NMSettingClass parent;
} NMSettingWimaxClass;

NM_DEPRECATED_IN_1_2
GType nm_setting_wimax_get_type (void);

NM_DEPRECATED_IN_1_2
NMSetting        *nm_setting_wimax_new              (void);
NM_DEPRECATED_IN_1_2
const char       *nm_setting_wimax_get_network_name (NMSettingWimax *setting);
NM_DEPRECATED_IN_1_2
const GByteArray *nm_setting_wimax_get_mac_address  (NMSettingWimax *setting);

G_END_DECLS

#endif /* NM_SETTING_WIMAX_H */
