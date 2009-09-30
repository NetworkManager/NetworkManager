/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_PPPOE_H
#define NM_SETTING_PPPOE_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_PPPOE            (nm_setting_pppoe_get_type ())
#define NM_SETTING_PPPOE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_PPPOE, NMSettingPPPOE))
#define NM_SETTING_PPPOE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_PPPOE, NMSettingPPPOEClass))
#define NM_IS_SETTING_PPPOE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_PPPOE))
#define NM_IS_SETTING_PPPOE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_PPPOE))
#define NM_SETTING_PPPOE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_PPPOE, NMSettingPPPOEClass))

#define NM_SETTING_PPPOE_SETTING_NAME "pppoe"

typedef enum
{
	NM_SETTING_PPPOE_ERROR_UNKNOWN = 0,
	NM_SETTING_PPPOE_ERROR_INVALID_PROPERTY,
	NM_SETTING_PPPOE_ERROR_MISSING_PROPERTY,
	NM_SETTING_PPPOE_ERROR_MISSING_PPP_SETTING
} NMSettingPPPOEError;

#define NM_TYPE_SETTING_PPPOE_ERROR (nm_setting_pppoe_error_get_type ()) 
GType nm_setting_pppoe_error_get_type (void);

#define NM_SETTING_PPPOE_ERROR nm_setting_pppoe_error_quark ()
GQuark nm_setting_pppoe_error_quark (void);

#define NM_SETTING_PPPOE_SERVICE  "service"
#define NM_SETTING_PPPOE_USERNAME "username"
#define NM_SETTING_PPPOE_PASSWORD "password"

typedef struct {
	NMSetting parent;
} NMSettingPPPOE;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingPPPOEClass;

GType nm_setting_pppoe_get_type (void);

NMSetting  *nm_setting_pppoe_new          (void);
const char *nm_setting_pppoe_get_service  (NMSettingPPPOE *setting);
const char *nm_setting_pppoe_get_username (NMSettingPPPOE *setting);
const char *nm_setting_pppoe_get_password (NMSettingPPPOE *setting);

G_END_DECLS

#endif /* NM_SETTING_PPPOE_H */
