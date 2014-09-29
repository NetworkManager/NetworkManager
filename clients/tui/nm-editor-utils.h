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
 * Copyright 2012, 2013 Red Hat, Inc.
 */

#ifndef NM_EDITOR_UTILS_H
#define NM_EDITOR_UTILS_H

#include <NetworkManager.h>

G_BEGIN_DECLS

typedef struct {
	const char *name;
	GType setting_type;
	GType slave_setting_type;
	GType device_type;
	gboolean virtual;
} NMEditorConnectionTypeData;

NMEditorConnectionTypeData **nm_editor_utils_get_connection_type_list (void);
NMEditorConnectionTypeData  *nm_editor_utils_get_connection_type_data (NMConnection *conn);

NMConnection *nm_editor_utils_create_connection (GType         type,
                                                 NMConnection *master,
                                                 NMClient     *client);

G_END_DECLS

#endif /* NM_EDITOR_UTILS_H */
