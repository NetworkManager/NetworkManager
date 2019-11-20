// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_HACKS_H
#define NMT_NEWT_HACKS_H

#include <newt.h>

#ifndef HAVE_NEWTCOMPONENTGETSIZE
void newtComponentGetSize     (newtComponent  component,
                               int           *width,
                               int           *height);

void newtComponentGetPosition (newtComponent  component,
                               int           *left,
                               int           *top);
#endif

#ifndef HAVE_NEWTENTRYGETCURSORPOSITION
int  newtEntryGetCursorPosition (newtComponent component);
void newtEntrySetCursorPosition (newtComponent component,
                                 int           position);
#endif

#endif /* NMT_NEWT_HACKS_H */
