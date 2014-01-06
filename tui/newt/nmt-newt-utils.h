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

#ifndef NMT_NEWT_UTILS_H
#define NMT_NEWT_UTILS_H

#include <newt.h>
#include <glib.h>

G_BEGIN_DECLS

void nmt_newt_init     (void);
void nmt_newt_finished (void);

typedef enum {
	NMT_NEWT_COLORSET_BAD_LABEL = NEWT_COLORSET_CUSTOM (0),
	NMT_NEWT_COLORSET_PLAIN_LABEL,
	NMT_NEWT_COLORSET_DISABLED_BUTTON,
	NMT_NEWT_COLORSET_TEXTBOX_WITH_BACKGROUND
} NmtNewtColorsets;

char *nmt_newt_locale_to_utf8   (const char *str_lc);
char *nmt_newt_locale_from_utf8 (const char *str_utf8);

int   nmt_newt_text_width       (const char *str);

void nmt_newt_message_dialog  (const char *message,
                               ...);
int  nmt_newt_choice_dialog (const char *button1,
                             const char *button2,
                             const char *message,
                             ...);

char *nmt_newt_edit_string (const char *data);

G_END_DECLS

#endif /* NMT_NEWT_UTILS_H */
