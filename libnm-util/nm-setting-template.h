/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

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
} NMSettingTemplateClass;

GType nm_setting_template_get_type (void);

NMSetting *nm_setting_template_new (void);

G_END_DECLS

#endif /* NM_SETTING_TEMPLATE_H */
