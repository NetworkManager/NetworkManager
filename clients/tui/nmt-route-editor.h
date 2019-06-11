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
