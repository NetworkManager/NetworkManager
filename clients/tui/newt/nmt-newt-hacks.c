/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-newt-hacks
 * @short_description: Hacks!
 *
 * This contains hacky cheating implementations of certain newt
 * functions that were added after 0.52.15.
 */

#include "libnm/nm-default-client.h"

#include "nmt-newt-hacks.h"

#if !defined(HAVE_NEWTCOMPONENTGETSIZE) || !defined(HAVE_NEWTENTRYGETCURSORPOSITION)
struct newtComponent_0_52_15_struct_hack {
    int height, width;
    int top, left;
    int takesFocus;
    int isMapped;

    struct componentOps *ops;

    newtCallback callback;
    void *       callbackData;

    newtCallback destroyCallback;
    void *       destroyCallbackData;

    void *data;
};
#endif

#ifndef HAVE_NEWTCOMPONENTGETSIZE
void
newtComponentGetSize(newtComponent component, int *width, int *height)
{
    struct newtComponent_0_52_15_struct_hack *hack = (void *) component;

    *width  = hack->width;
    *height = hack->height;
}

void
newtComponentGetPosition(newtComponent component, int *left, int *top)
{
    struct newtComponent_0_52_15_struct_hack *hack = (void *) component;

    *left = hack->left;
    *top  = hack->top;
}
#endif

#ifndef HAVE_NEWTENTRYGETCURSORPOSITION
struct newtEntry_0_52_15_struct_hack {
    int          flags;
    char *       buf;
    const char **resultPtr;
    int          bufAlloced;
    int          bufUsed;
    int          cursorPosition;
    /* ... */
};

int
newtEntryGetCursorPosition(newtComponent component)
{
    struct newtComponent_0_52_15_struct_hack *co_hack    = (void *) component;
    struct newtEntry_0_52_15_struct_hack *    entry_hack = co_hack->data;

    return entry_hack->cursorPosition;
}

void
newtEntrySetCursorPosition(newtComponent component, int position)
{
    struct newtComponent_0_52_15_struct_hack *co_hack    = (void *) component;
    struct newtEntry_0_52_15_struct_hack *    entry_hack = co_hack->data;

    entry_hack->cursorPosition = position;
}
#endif
