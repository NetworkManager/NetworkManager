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
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NM_SETTING_GENERIC_H
#define NM_SETTING_GENERIC_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_GENERIC            (nm_setting_generic_get_type ())
#define NM_SETTING_GENERIC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_GENERIC, NMSettingGeneric))
#define NM_SETTING_GENERIC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_GENERIC, NMSettingGenericClass))
#define NM_IS_SETTING_GENERIC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_GENERIC))
#define NM_IS_SETTING_GENERIC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_GENERIC))
#define NM_SETTING_GENERIC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_GENERIC, NMSettingGenericClass))

#define NM_SETTING_GENERIC_SETTING_NAME "generic"

/**
 * NMSettingGenericError:
 * @NM_SETTING_GENERIC_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_GENERIC_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_GENERIC_ERROR_MISSING_PROPERTY: the property was missing and
 * is required
 *
 * Since: 0.9.10
 */
typedef enum {
	NM_SETTING_GENERIC_ERROR_UNKNOWN = 0,      /*< nick=UnknownError >*/
	NM_SETTING_GENERIC_ERROR_INVALID_PROPERTY, /*< nick=InvalidProperty >*/
	NM_SETTING_GENERIC_ERROR_MISSING_PROPERTY, /*< nick=MissingProperty >*/
} NMSettingGenericError;

#define NM_SETTING_GENERIC_ERROR nm_setting_generic_error_quark ()
GQuark nm_setting_generic_error_quark (void);

typedef struct {
	NMSetting parent;
} NMSettingGeneric;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingGenericClass;

NM_AVAILABLE_IN_0_9_10
GType nm_setting_generic_get_type (void);

NM_AVAILABLE_IN_0_9_10
NMSetting * nm_setting_generic_new              (void);

G_END_DECLS

#endif /* NM_SETTING_GENERIC_H */
