/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#ifndef NMT_NEWT_CONTAINER_H
#define NMT_NEWT_CONTAINER_H

#include "nmt-newt-widget.h"

G_BEGIN_DECLS

#define NMT_TYPE_NEWT_CONTAINER            (nmt_newt_container_get_type ())
#define NMT_NEWT_CONTAINER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_CONTAINER, NmtNewtContainer))
#define NMT_NEWT_CONTAINER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_CONTAINER, NmtNewtContainerClass))
#define NMT_IS_NEWT_CONTAINER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_CONTAINER))
#define NMT_IS_NEWT_CONTAINER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_CONTAINER))
#define NMT_NEWT_CONTAINER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_CONTAINER, NmtNewtContainerClass))

struct _NmtNewtContainer {
	NmtNewtWidget parent;

};

typedef struct {
	NmtNewtWidgetClass parent;

	/* methods */
	void (*add)                    (NmtNewtContainer *container,
	                                NmtNewtWidget    *child);
	void (*remove)                 (NmtNewtContainer *container,
	                                NmtNewtWidget    *child);

	void (*child_validity_changed) (NmtNewtContainer *container,
	                                NmtNewtWidget    *child);

} NmtNewtContainerClass;

GType nmt_newt_container_get_type (void);

void           nmt_newt_container_remove       (NmtNewtContainer *container,
                                                NmtNewtWidget    *widget);

GSList        *nmt_newt_container_get_children (NmtNewtContainer *container);

G_END_DECLS

#endif /* NMT_NEWT_CONTAINER_H */
