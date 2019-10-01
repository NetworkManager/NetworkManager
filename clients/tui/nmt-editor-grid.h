// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_EDITOR_GRID_H
#define NMT_EDITOR_GRID_H

#include "nmt-newt.h"

#define NMT_TYPE_EDITOR_GRID            (nmt_editor_grid_get_type ())
#define NMT_EDITOR_GRID(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_EDITOR_GRID, NmtEditorGrid))
#define NMT_EDITOR_GRID_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_EDITOR_GRID, NmtEditorGridClass))
#define NMT_IS_EDITOR_GRID(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_EDITOR_GRID))
#define NMT_IS_EDITOR_GRID_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_EDITOR_GRID))
#define NMT_EDITOR_GRID_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_EDITOR_GRID, NmtEditorGridClass))

typedef struct {
	NmtNewtContainer parent;

} NmtEditorGrid;

typedef struct {
	NmtNewtContainerClass parent;

} NmtEditorGridClass;

GType nmt_editor_grid_get_type (void);

typedef enum {
	NMT_EDITOR_GRID_ROW_LABEL_ALIGN_LEFT = (1 << 0),
	NMT_EDITOR_GRID_ROW_EXTRA_ALIGN_RIGHT = (1 << 1)
} NmtEditorGridRowFlags;

NmtNewtWidget *nmt_editor_grid_new              (void);

void           nmt_editor_grid_append           (NmtEditorGrid         *grid,
                                               const char          *label,
                                               NmtNewtWidget       *widget,
                                               NmtNewtWidget       *extra);
void           nmt_editor_grid_set_row_flags    (NmtEditorGrid         *grid,
                                               NmtNewtWidget       *widget,
                                               NmtEditorGridRowFlags  flags);

#endif /* NMT_EDITOR_GRID_H */
