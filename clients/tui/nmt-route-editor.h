// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_ROUTE_EDITOR_H
#define NMT_ROUTE_EDITOR_H

#include "nmt-newt.h"

#define NMT_TYPE_ROUTE_EDITOR            (nmt_route_editor_get_type ())
#define NMT_ROUTE_EDITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_ROUTE_EDITOR, NmtRouteEditor))
#define NMT_ROUTE_EDITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_ROUTE_EDITOR, NmtRouteEditorClass))
#define NMT_IS_ROUTE_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_ROUTE_EDITOR))
#define NMT_IS_ROUTE_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_ROUTE_EDITOR))
#define NMT_ROUTE_EDITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_ROUTE_EDITOR, NmtRouteEditorClass))

typedef struct {
	NmtNewtForm parent;

} NmtRouteEditor;

typedef struct {
	NmtNewtFormClass parent;

} NmtRouteEditorClass;

GType nmt_route_editor_get_type (void);

NmtNewtForm *nmt_route_editor_new (NMSetting *setting);

#endif /* NMT_ROUTE_EDITOR_H */
