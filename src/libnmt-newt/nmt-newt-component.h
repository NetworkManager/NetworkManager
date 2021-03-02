/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_COMPONENT_H
#define NMT_NEWT_COMPONENT_H

#include "nmt-newt-widget.h"

#define NMT_TYPE_NEWT_COMPONENT (nmt_newt_component_get_type())
#define NMT_NEWT_COMPONENT(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_NEWT_COMPONENT, NmtNewtComponent))
#define NMT_NEWT_COMPONENT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_NEWT_COMPONENT, NmtNewtComponentClass))
#define NMT_IS_NEWT_COMPONENT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_NEWT_COMPONENT))
#define NMT_IS_NEWT_COMPONENT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_NEWT_COMPONENT))
#define NMT_NEWT_COMPONENT_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_NEWT_COMPONENT, NmtNewtComponentClass))

struct _NmtNewtComponent {
    NmtNewtWidget parent;
};

typedef struct {
    NmtNewtWidgetClass parent;

    /* methods */
    newtComponent (*build_component)(NmtNewtComponent *component, gboolean sensitive);

} NmtNewtComponentClass;

GType nmt_newt_component_get_type(void);

newtComponent nmt_newt_component_get_component(NmtNewtComponent *component);

gboolean nmt_newt_component_get_sensitive(NmtNewtComponent *component);
void     nmt_newt_component_set_sensitive(NmtNewtComponent *component, gboolean sensitive);

#endif /* NMT_NEWT_COMPONENT_H */
