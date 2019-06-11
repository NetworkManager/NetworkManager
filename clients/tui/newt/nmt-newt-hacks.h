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
