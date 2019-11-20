// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_EDITOR_H
#define NMT_EDITOR_H

#include "nmt-newt.h"

#define NMT_TYPE_EDITOR            (nmt_editor_get_type ())
#define NMT_EDITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_EDITOR, NmtEditor))
#define NMT_EDITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_EDITOR, NmtEditorClass))
#define NMT_IS_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_EDITOR))
#define NMT_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_EDITOR))
#define NMT_EDITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_EDITOR, NmtEditorClass))

typedef struct {
	NmtNewtForm parent;

} NmtEditor;

typedef struct {
	NmtNewtFormClass parent;

} NmtEditorClass;

GType nmt_editor_get_type (void);

NmtNewtForm *nmt_editor_new (NMConnection *connection);

#endif /* NMT_EDITOR_H */
