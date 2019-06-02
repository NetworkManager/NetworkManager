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
