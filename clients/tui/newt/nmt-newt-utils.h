/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_UTILS_H
#define NMT_NEWT_UTILS_H

#include <newt.h>

void nmt_newt_init(void);
void nmt_newt_finished(void);

typedef enum {
    NMT_NEWT_COLORSET_BAD_LABEL = NEWT_COLORSET_CUSTOM(0),
    NMT_NEWT_COLORSET_PLAIN_LABEL,
    NMT_NEWT_COLORSET_DISABLED_BUTTON,
    NMT_NEWT_COLORSET_TEXTBOX_WITH_BACKGROUND
} NmtNewtColorsets;

char *nmt_newt_locale_to_utf8(const char *str_lc);
char *nmt_newt_locale_from_utf8(const char *str_utf8);

int nmt_newt_text_width(const char *str);

void nmt_newt_message_dialog(const char *message, ...) _nm_printf(1, 2);
int  nmt_newt_choice_dialog(const char *button1, const char *button2, const char *message, ...)
    _nm_printf(3, 4);

char *nmt_newt_edit_string(const char *data);

#endif /* NMT_NEWT_UTILS_H */
