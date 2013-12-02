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

#ifndef NMT_NEWT_COMPONENT_H
#define NMT_NEWT_COMPONENT_H

#include "nmt-newt-widget.h"

G_BEGIN_DECLS

#define NMT_TYPE_NEWT_COMPONENT            (nmt_newt_component_get_type ())
#define NMT_NEWT_COMPONENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_COMPONENT, NmtNewtComponent))
#define NMT_NEWT_COMPONENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_COMPONENT, NmtNewtComponentClass))
#define NMT_IS_NEWT_COMPONENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_COMPONENT))
#define NMT_IS_NEWT_COMPONENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_COMPONENT))
#define NMT_NEWT_COMPONENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_COMPONENT, NmtNewtComponentClass))

struct _NmtNewtComponent {
	NmtNewtWidget parent;

};

typedef struct {
	NmtNewtWidgetClass parent;

	/* methods */
	newtComponent (*build_component)    (NmtNewtComponent *component,
	                                     gboolean          sensitive);

} NmtNewtComponentClass;

GType nmt_newt_component_get_type (void);

newtComponent nmt_newt_component_get_component (NmtNewtComponent *component);

gboolean      nmt_newt_component_get_sensitive (NmtNewtComponent *component);
void          nmt_newt_component_set_sensitive (NmtNewtComponent *component,
                                                gboolean          sensitive);

G_END_DECLS

#endif /* NMT_NEWT_COMPONENT_H */
