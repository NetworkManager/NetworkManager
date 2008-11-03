/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2007 Novell, Inc.
 */

#ifndef NM_CALLBACK_STORE_H
#define NM_CALLBACK_STORE_H

#include <glib-object.h>

typedef GHashTable NMCallStore;

typedef gboolean (*NMCallStoreFunc) (GObject *object, gpointer call_id, gpointer user_data);

NMCallStore *nm_call_store_new     (void);
void         nm_call_store_add     (NMCallStore *store,
									GObject *object,
									gpointer *call_id);

void         nm_call_store_remove  (NMCallStore *store,
									GObject *object,
									gpointer call_id);

int          nm_call_store_foreach (NMCallStore *store,
									GObject *object,
									NMCallStoreFunc callback,
									gpointer user_data);

void         nm_call_store_clear   (NMCallStore *store);
void         nm_call_store_destroy (NMCallStore *store);

#endif /* NM_CALLBACK_STORE_H */
