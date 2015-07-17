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

#ifndef NMT_MAC_ENTRY_H
#define NMT_MAC_ENTRY_H

#include "nm-default.h"
#include "nm-utils.h"
#include "nmt-newt.h"

G_BEGIN_DECLS

#define NMT_TYPE_MAC_ENTRY            (nmt_mac_entry_get_type ())
#define NMT_MAC_ENTRY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_MAC_ENTRY, NmtMacEntry))
#define NMT_MAC_ENTRY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_MAC_ENTRY, NmtMacEntryClass))
#define NMT_IS_MAC_ENTRY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_MAC_ENTRY))
#define NMT_IS_MAC_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_MAC_ENTRY))
#define NMT_MAC_ENTRY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_MAC_ENTRY, NmtMacEntryClass))

typedef struct {
	NmtNewtEntry parent;

} NmtMacEntry;

typedef struct {
	NmtNewtEntryClass parent;

} NmtMacEntryClass;

GType nmt_mac_entry_get_type (void);

NmtNewtWidget *nmt_mac_entry_new (int width,
                                  int mac_length);

G_END_DECLS

#endif /* NMT_MAC_ENTRY_H */
