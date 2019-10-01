// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2012, 2013 Red Hat, Inc.
 */

#ifndef NM_EDITOR_UTILS_H
#define NM_EDITOR_UTILS_H

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

#endif /* NM_EDITOR_UTILS_H */
