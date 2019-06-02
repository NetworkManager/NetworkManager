/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_GRID_H
#define NMT_NEWT_GRID_H

#include "nmt-newt-container.h"

#define NMT_TYPE_NEWT_GRID            (nmt_newt_grid_get_type ())
#define NMT_NEWT_GRID(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_GRID, NmtNewtGrid))
#define NMT_NEWT_GRID_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_GRID, NmtNewtGridClass))
#define NMT_IS_NEWT_GRID(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_GRID))
#define NMT_IS_NEWT_GRID_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_GRID))
#define NMT_NEWT_GRID_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_GRID, NmtNewtGridClass))

struct _NmtNewtGrid {
	NmtNewtContainer parent;

};

typedef struct {
	NmtNewtContainerClass parent;

} NmtNewtGridClass;

GType nmt_newt_grid_get_type (void);

typedef enum {
	NMT_NEWT_GRID_EXPAND_X      = (1 << 0),
	NMT_NEWT_GRID_EXPAND_Y      = (1 << 1),
	NMT_NEWT_GRID_ANCHOR_LEFT   = (1 << 2),
	NMT_NEWT_GRID_ANCHOR_RIGHT  = (1 << 3),
	NMT_NEWT_GRID_FILL_X        = NMT_NEWT_GRID_ANCHOR_LEFT | NMT_NEWT_GRID_ANCHOR_RIGHT,
	NMT_NEWT_GRID_ANCHOR_TOP    = (1 << 4),
	NMT_NEWT_GRID_ANCHOR_BOTTOM = (1 << 5),
	NMT_NEWT_GRID_FILL_Y        = NMT_NEWT_GRID_ANCHOR_TOP | NMT_NEWT_GRID_ANCHOR_BOTTOM,
} NmtNewtGridFlags;

NmtNewtWidget *nmt_newt_grid_new         (void);

void           nmt_newt_grid_add         (NmtNewtGrid      *grid,
                                          NmtNewtWidget    *widget,
                                          int               x,
                                          int               y);
void           nmt_newt_grid_move        (NmtNewtGrid      *grid,
                                          NmtNewtWidget    *widget,
                                          int               x,
                                          int               y);
void           nmt_newt_grid_set_flags   (NmtNewtGrid      *grid,
                                          NmtNewtWidget    *widget,
                                          NmtNewtGridFlags  flags);

#endif /* NMT_NEWT_GRID_H */
