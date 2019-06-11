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
