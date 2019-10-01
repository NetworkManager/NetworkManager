// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMTUI_EDIT_H
#define NMTUI_EDIT_H

#include "nmt-newt.h"

typedef gboolean (*NmtAddConnectionTypeFilter) (GType    connection_type,
                                                gpointer user_data);

NmtNewtForm *nmtui_edit (gboolean is_top, int argc, char **argv);

void nmt_add_connection      (void);
void nmt_add_connection_full (const char                 *primary_text,
                              const char                 *secondary_text,
                              NMConnection               *master,
                              NmtAddConnectionTypeFilter  type_filter,
                              gpointer                    type_filter_data);

void nmt_edit_connection     (NMConnection               *connection);

void nmt_remove_connection   (NMRemoteConnection         *connection);

#endif /* NMTUI_EDIT_H */
