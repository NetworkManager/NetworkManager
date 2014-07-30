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

#ifndef NMT_NEWT_POPUP_H
#define NMT_NEWT_POPUP_H

#include "nmt-newt-button.h"

G_BEGIN_DECLS

#define NMT_TYPE_NEWT_POPUP            (nmt_newt_popup_get_type ())
#define NMT_NEWT_POPUP(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_POPUP, NmtNewtPopup))
#define NMT_NEWT_POPUP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_POPUP, NmtNewtPopupClass))
#define NMT_IS_NEWT_POPUP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_POPUP))
#define NMT_IS_NEWT_POPUP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_POPUP))
#define NMT_NEWT_POPUP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_POPUP, NmtNewtPopupClass))

struct _NmtNewtPopup {
	NmtNewtButton parent;

};

typedef struct {
	NmtNewtButtonClass parent;

} NmtNewtPopupClass;

GType nmt_newt_popup_get_type (void);

typedef struct {
	char *label;
	char *id;
} NmtNewtPopupEntry;

NmtNewtWidget *nmt_newt_popup_new           (NmtNewtPopupEntry *entries);

int            nmt_newt_popup_get_active    (NmtNewtPopup      *popup);
void           nmt_newt_popup_set_active    (NmtNewtPopup      *popup,
                                             int                active);

const char    *nmt_newt_popup_get_active_id (NmtNewtPopup      *popup);
void           nmt_newt_popup_set_active_id (NmtNewtPopup      *popup,
                                             const char        *active_id);

G_END_DECLS

#endif /* NMT_NEWT_POPUP_H */
