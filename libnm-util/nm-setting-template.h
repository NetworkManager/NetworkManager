/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
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
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

/* This file is just a template - it's not built nor included in the tarball.
   It's sole purpose is to make the process of creating new settings easier.
   Just replace 'template' with new setting name (preserving the case),
   remove this comment, and you're almost done.
*/

#ifndef NM_SETTING_TEMPLATE_H
#define NM_SETTING_TEMPLATE_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_TEMPLATE            (nm_setting_template_get_type ())
#define NM_SETTING_TEMPLATE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_TEMPLATE, NMSettingTemplate))
#define NM_SETTING_TEMPLATE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_TEMPLATE, NMSettingTemplateClass))
#define NM_IS_SETTING_TEMPLATE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_TEMPLATE))
#define NM_IS_SETTING_TEMPLATE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_TEMPLATE))
#define NM_SETTING_TEMPLATE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_TEMPLATE, NMSettingTemplateClass))

#define NM_SETTING_TEMPLATE_SETTING_NAME "template"

typedef struct {
	NMSetting parent;
} NMSettingTemplate;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingTemplateClass;

GType nm_setting_template_get_type (void);

NMSetting *nm_setting_template_new (void);

G_END_DECLS

#endif /* NM_SETTING_TEMPLATE_H */
