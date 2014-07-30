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

/**
 * SECTION:nmt-newt-hacks
 * @short_description: Hacks!
 *
 * This contains hacky cheating implementations of certain newt
 * functions that were added after 0.52.15.
 */

#include "config.h"

#include "nmt-newt-hacks.h"

#if !defined (HAVE_NEWTCOMPONENTGETSIZE) || !defined (HAVE_NEWTENTRYGETCURSORPOSITION)
struct newtComponent_0_52_15_struct_hack {
	int height, width;
	int top, left;
	int takesFocus;
	int isMapped;

	struct componentOps *ops;

	newtCallback callback;
	void *callbackData;

	newtCallback destroyCallback;
	void *destroyCallbackData;

	void *data;
};
#endif

#ifndef HAVE_NEWTCOMPONENTGETSIZE
void
newtComponentGetSize (newtComponent  component,
                      int           *width,
                      int           *height)
{
	struct newtComponent_0_52_15_struct_hack *hack = (void *) component;

	*width = hack->width;
	*height = hack->height;
}

void
newtComponentGetPosition (newtComponent  component,
                          int           *left,
                          int           *top)
{
	struct newtComponent_0_52_15_struct_hack *hack = (void *) component;

	*left = hack->left;
	*top = hack->top;
}
#endif

#ifndef HAVE_NEWTENTRYGETCURSORPOSITION
struct newtEntry_0_52_15_struct_hack {
	int flags;
	char *buf;
	const char **resultPtr;
	int bufAlloced;
	int bufUsed;
	int cursorPosition;
	/* ... */
};

int
newtEntryGetCursorPosition (newtComponent component)
{
	struct newtComponent_0_52_15_struct_hack *co_hack = (void *) component;
	struct newtEntry_0_52_15_struct_hack *entry_hack = co_hack->data;

	return entry_hack->cursorPosition;
}

void
newtEntrySetCursorPosition (newtComponent component,
                            int           position)
{
	struct newtComponent_0_52_15_struct_hack *co_hack = (void *) component;
	struct newtEntry_0_52_15_struct_hack *entry_hack = co_hack->data;

	entry_hack->cursorPosition = position;
}
#endif
